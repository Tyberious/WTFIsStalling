//! Real-time kernel ETW session: DPC/ISR, hard faults, disk I/O, thread map and CPU samples.
//!
//! The session uses the QPC clock (ClientContext = 1) and the consumer asks for raw
//! timestamps, so every event time is directly comparable to QueryPerformanceCounter
//! values taken by the latency probes.

use std::ffi::c_void;
use std::mem::{size_of, zeroed};
use std::ptr::{null, null_mut};
use std::sync::Arc;
use std::thread::JoinHandle;

use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, LUID};
use windows_sys::Win32::Security::{
    AdjustTokenPrivileges, LookupPrivilegeValueW, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES,
    TOKEN_QUERY,
};
use windows_sys::Win32::System::Diagnostics::Etw::{
    CloseTrace, ControlTraceW, OpenTraceW, ProcessTrace, StartTraceW, CONTROLTRACE_HANDLE, EVENT_RECORD, EVENT_TRACE_FLAG_DISK_IO,
    EVENT_TRACE_FLAG_DPC, EVENT_TRACE_FLAG_INTERRUPT, EVENT_TRACE_FLAG_MEMORY_HARD_FAULTS, EVENT_TRACE_FLAG_PROCESS,
    EVENT_TRACE_FLAG_PROFILE, EVENT_TRACE_FLAG_THREAD, EVENT_TRACE_LOGFILEW, EVENT_TRACE_PROPERTIES,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use crate::state::*;
use crate::util::wide;

const SESSION_NAME: &str = "WTFIsStallingSession";
const SESSION_GUID: GUID = GUID::from_u128(0x5b1e4c0a_7d3f_4a86_9c21_57f1a0d3e9b4);

const EVENT_TRACE_REAL_TIME_MODE: u32 = 0x0000_0100;
const EVENT_TRACE_SYSTEM_LOGGER_MODE: u32 = 0x0200_0000;
const WNODE_FLAG_TRACED_GUID: u32 = 0x0002_0000;
const EVENT_TRACE_CONTROL_STOP: u32 = 1;

const PROCESS_TRACE_MODE_REAL_TIME: u32 = 0x0000_0100;
const PROCESS_TRACE_MODE_RAW_TIMESTAMP: u32 = 0x0000_1000;
const PROCESS_TRACE_MODE_EVENT_RECORD: u32 = 0x1000_0000;

const ERROR_ALREADY_EXISTS: u32 = 183;

// First field of the classic kernel provider GUIDs is enough to tell them apart.
const GUID_PERFINFO: u32 = 0xce1d_bfb4;
const GUID_DISKIO: u32 = 0x3d6f_a8d4;
const GUID_PAGEFAULT: u32 = 0x3d6f_a8d3;
const GUID_THREAD: u32 = 0x3d6f_a8d1;

pub struct Session {
    handle: CONTROLTRACE_HANDLE,
    pub profile: bool,
}

/// EVENT_TRACE_PROPERTIES followed by room for the session name, 8-byte aligned.
fn props_buffer() -> (Vec<u64>, usize) {
    let total = size_of::<EVENT_TRACE_PROPERTIES>() + 2 * 260;
    (vec![0u64; total.div_ceil(8)], total)
}

pub fn enable_privilege(name: &str) -> bool {
    unsafe {
        let mut token: HANDLE = null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut luid: LUID = zeroed();
        let ok = LookupPrivilegeValueW(null(), wide(name).as_ptr(), &mut luid) != 0 && {
            let tp =
                TOKEN_PRIVILEGES { PrivilegeCount: 1, Privileges: [LUID_AND_ATTRIBUTES { Luid: luid, Attributes: SE_PRIVILEGE_ENABLED }] };
            AdjustTokenPrivileges(token, 0, &tp, 0, null_mut(), null_mut()) != 0 && windows_sys::Win32::Foundation::GetLastError() == 0
        };
        CloseHandle(token);
        ok
    }
}

fn stop_by_name() {
    let (mut buf, total) = props_buffer();
    let p = buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
    unsafe {
        (*p).Wnode.BufferSize = total as u32;
        (*p).LoggerNameOffset = size_of::<EVENT_TRACE_PROPERTIES>() as u32;
        ControlTraceW(CONTROLTRACE_HANDLE { Value: 0 }, wide(SESSION_NAME).as_ptr(), p, EVENT_TRACE_CONTROL_STOP);
    }
}

fn try_start(flags: u32) -> Result<CONTROLTRACE_HANDLE, u32> {
    let (mut buf, total) = props_buffer();
    let p = buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
    let mut handle = CONTROLTRACE_HANDLE { Value: 0 };
    let rc = unsafe {
        (*p).Wnode.BufferSize = total as u32;
        (*p).Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        (*p).Wnode.ClientContext = 1; // QPC clock
        (*p).Wnode.Guid = SESSION_GUID;
        (*p).LogFileMode = EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_SYSTEM_LOGGER_MODE;
        (*p).EnableFlags = flags;
        (*p).BufferSize = 256; // KB
        (*p).MinimumBuffers = 64;
        (*p).MaximumBuffers = 320;
        (*p).FlushTimer = 1;
        (*p).LoggerNameOffset = size_of::<EVENT_TRACE_PROPERTIES>() as u32;
        StartTraceW(&mut handle, wide(SESSION_NAME).as_ptr(), p)
    };
    if rc == 0 {
        Ok(handle)
    } else {
        Err(rc)
    }
}

impl Session {
    pub fn start(want_profile: bool) -> Result<Session, String> {
        let base = EVENT_TRACE_FLAG_PROCESS
            | EVENT_TRACE_FLAG_THREAD
            | EVENT_TRACE_FLAG_DISK_IO
            | EVENT_TRACE_FLAG_MEMORY_HARD_FAULTS
            | EVENT_TRACE_FLAG_DPC
            | EVENT_TRACE_FLAG_INTERRUPT;
        let profile = want_profile && enable_privilege("SeSystemProfilePrivilege");
        let mut attempts = vec![(base, false)];
        if profile {
            attempts.insert(0, (base | EVENT_TRACE_FLAG_PROFILE, true));
        }
        let mut last = 0;
        for (flags, with_profile) in attempts {
            let mut r = try_start(flags);
            if matches!(r, Err(ERROR_ALREADY_EXISTS)) {
                // Left over from a previous run that was killed; take it over.
                stop_by_name();
                r = try_start(flags);
            }
            match r {
                Ok(handle) => return Ok(Session { handle, profile: with_profile }),
                Err(rc) => last = rc,
            }
        }
        Err(match last {
            5 => "access denied starting the kernel trace (must run as Administrator)".into(),
            1450 => "Windows is out of kernel trace sessions (max 8). Close other profilers \
                     (xperf, WPR, Process Monitor, LatencyMon...) and retry"
                .into(),
            rc => format!("StartTrace failed with Win32 error {rc}"),
        })
    }

    /// Stops the session (which also makes ProcessTrace return). Returns events lost.
    pub fn stop(&self) -> u32 {
        let (mut buf, total) = props_buffer();
        let p = buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
        unsafe {
            (*p).Wnode.BufferSize = total as u32;
            (*p).LoggerNameOffset = size_of::<EVENT_TRACE_PROPERTIES>() as u32;
            ControlTraceW(self.handle, null(), p, EVENT_TRACE_CONTROL_STOP);
            (*p).EventsLost + (*p).RealTimeBuffersLost
        }
    }
}

/// Spawns the thread that pumps events into `shared` until the session is stopped.
pub fn spawn_consumer(shared: Arc<Shared>) -> JoinHandle<Result<(), String>> {
    std::thread::Builder::new()
        .name("etw-consumer".into())
        .spawn(move || unsafe {
            let mut name = wide(SESSION_NAME);
            let mut lf: EVENT_TRACE_LOGFILEW = zeroed();
            lf.LoggerName = name.as_mut_ptr();
            lf.Anonymous1.ProcessTraceMode =
                PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_RAW_TIMESTAMP;
            lf.Anonymous2.EventRecordCallback = Some(on_event);
            lf.Context = Arc::as_ptr(&shared) as *mut c_void;
            let h = OpenTraceW(&mut lf);
            if h.Value == u64::MAX {
                return Err(format!("OpenTrace failed with Win32 error {}", windows_sys::Win32::Foundation::GetLastError()));
            }
            let rc = ProcessTrace(&h, 1, null(), null());
            CloseTrace(h);
            if rc != 0 {
                return Err(format!("ProcessTrace failed with Win32 error {rc}"));
            }
            Ok(())
        })
        .expect("spawn etw thread")
}

fn rd_u32(d: &[u8], off: usize) -> Option<u32> {
    d.get(off..off + 4).map(|b| u32::from_le_bytes(b.try_into().unwrap()))
}

fn rd_u64(d: &[u8], off: usize) -> Option<u64> {
    d.get(off..off + 8).map(|b| u64::from_le_bytes(b.try_into().unwrap()))
}

unsafe extern "system" fn on_event(rec: *mut EVENT_RECORD) {
    let rec = &*rec;
    let shared = &*(rec.UserContext as *const Shared);
    let hdr = &rec.EventHeader;
    let data: &[u8] =
        if rec.UserData.is_null() { &[] } else { std::slice::from_raw_parts(rec.UserData as *const u8, rec.UserDataLength as usize) };
    let cpu = rec.BufferContext.Anonymous.ProcessorIndex;
    let mut inner = shared.inner.lock().unwrap();
    handle_event(shared, &mut inner, hdr.ProviderId.data1, hdr.EventDescriptor.Opcode, hdr.TimeStamp, cpu, data);
}

/// Layouts below are the 64-bit MOF layouts of the classic NT kernel logger events.
fn handle_event(shared: &Shared, inner: &mut Inner, guid: u32, opcode: u8, ts: i64, cpu: u16, d: &[u8]) -> Option<()> {
    inner.events += 1;
    if shared.debug {
        *inner.debug_counts.entry((guid, opcode)).or_default() += 1;
    }
    if ts > inner.latest_ts {
        inner.latest_ts = ts;
        if ts - inner.last_prune > shared.keep / 8 {
            inner.prune(shared.keep);
        }
    }
    // Some bookkeeping DPC events carry InitialTime = 0, which would read as a DPC as long
    // as the system's uptime. No real DPC/ISR runs for seconds (the watchdog bugchecks first).
    let max_exec = shared.keep;
    const MAX_SANE: i64 = i64::MAX / 4;
    match (guid, opcode) {
        // SampledProfile: InstructionPointer, ThreadId, Count
        (GUID_PERFINFO, 46) => {
            let ip = rd_u64(d, 0)?;
            let tid = rd_u32(d, 8)?;
            inner.samples.push_back(SampleRec { ts, cpu, tid, ip });
        }
        // ISR-MSI (50), ThreadedDPC / ISR / DPC / TimerDPC (66-69): InitialTime, Routine, ...
        (GUID_PERFINFO, 50 | 66..=69) => {
            let start = rd_u64(d, 0)? as i64;
            let routine = rd_u64(d, 8)?;
            let dur = ts - start;
            if start <= 0 || !(0..max_exec).contains(&dur) {
                if shared.debug && inner.debug_rejected.len() < 5 {
                    inner.debug_rejected.push((ts, start));
                }
                return None;
            }
            let kind = match opcode {
                66 => KIND_THREADED_DPC,
                50 | 67 => KIND_ISR,
                68 => KIND_DPC,
                _ => KIND_TIMER_DPC,
            };
            let r = ExecRec { cpu, kind, start, end: ts, routine };
            inner.execs.push_back(r);
            let st = inner.routines.entry((routine, kind)).or_default();
            st.count += 1;
            st.total += dur;
            st.max = st.max.max(dur);
            if dur >= shared.exec_warn {
                st.over_warn += 1;
                push_notable(inner, Notable::LongExec(r));
            }
        }
        // HardFault: InitialTime, ReadOffset, VirtualAddress, FileObject, TThreadId, ByteCount
        (GUID_PAGEFAULT, 32) => {
            let start = rd_u64(d, 0)? as i64;
            let tid = rd_u32(d, 32)?;
            let bytes = rd_u32(d, 36).unwrap_or(0);
            let dur = ts - start;
            if !(0..MAX_SANE).contains(&dur) {
                return None;
            }
            let pid = inner.tid_pid.get(&tid).copied().unwrap_or(PID_UNKNOWN);
            let r = FaultRec { start, end: ts, tid, pid, bytes };
            inner.faults.push_back(r);
            let st = inner.faults_by_pid.entry(pid).or_default();
            st.count += 1;
            st.total += dur;
            st.max = st.max.max(dur);
            if dur >= shared.fault_warn {
                st.slow += 1;
                push_notable(inner, Notable::SlowFault(r));
            }
        }
        // Read / Write / Flush completion
        (GUID_DISKIO, 10 | 11 | 14) => {
            let disk = rd_u32(d, 0)?;
            let (size, dur, tid, op) = if opcode == 14 {
                (0, rd_u64(d, 8)? as i64, rd_u32(d, 24)?, b'F')
            } else {
                (rd_u32(d, 8)?, rd_u64(d, 40)? as i64, rd_u32(d, 48)?, if opcode == 10 { b'R' } else { b'W' })
            };
            if !(0..MAX_SANE).contains(&dur) {
                return None;
            }
            let pid = inner.tid_pid.get(&tid).copied().unwrap_or(PID_UNKNOWN);
            let r = IoRec { end: ts, dur, disk, tid, pid, size, op };
            inner.ios.push_back(r);
            let st = inner.disks.entry(disk).or_default();
            st.count += 1;
            st.total += dur;
            st.max = st.max.max(dur);
            if dur >= shared.io_warn {
                st.slow += 1;
                push_notable(inner, Notable::SlowIo(r));
            }
        }
        // Thread Start / DCStart (rundown): ProcessId, TThreadId
        (GUID_THREAD, 1 | 3) => {
            let pid = rd_u32(d, 0)?;
            let tid = rd_u32(d, 4)?;
            inner.tid_pid.insert(tid, pid);
        }
        _ => {}
    }
    Some(())
}

fn push_notable(inner: &mut Inner, n: Notable) {
    if inner.notable.len() < 2000 {
        inner.notable.push(n);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn shared() -> Shared {
        Shared {
            inner: Mutex::new(Inner::default()),
            exec_warn: 1_000,
            fault_warn: 50_000,
            io_warn: 200_000,
            keep: 20_000_000,
            debug: false,
        }
    }

    fn exec_payload(initial_time: u64, routine: u64) -> Vec<u8> {
        let mut d = initial_time.to_le_bytes().to_vec();
        d.extend(routine.to_le_bytes());
        d
    }

    #[test]
    fn dpc_duration_is_event_time_minus_initial_time() {
        let sh = shared();
        let mut inner = sh.inner.lock().unwrap();
        handle_event(&sh, &mut inner, GUID_PERFINFO, 68, 5_000_500, 3, &exec_payload(5_000_000, 0xFFFF_F800_1234_5678));
        let rec = inner.execs.back().expect("DPC recorded");
        assert_eq!((rec.cpu, rec.kind, rec.end - rec.start), (3, KIND_DPC, 500));
        assert_eq!(inner.routines[&(0xFFFF_F800_1234_5678, KIND_DPC)].max, 500);
        assert!(inner.notable.is_empty(), "500 ticks is under the warn threshold");
    }

    #[test]
    fn long_isr_is_flagged_and_msi_variant_counts_as_isr() {
        let sh = shared();
        let mut inner = sh.inner.lock().unwrap();
        handle_event(&sh, &mut inner, GUID_PERFINFO, 50, 9_002_000, 0, &exec_payload(9_000_000, 0xFFFF_F800_0000_1000));
        assert_eq!(inner.execs.back().unwrap().kind, KIND_ISR);
        assert!(matches!(inner.notable.as_slice(), [Notable::LongExec(_)]));
    }

    #[test]
    fn zero_initial_time_is_not_an_uptime_long_dpc() {
        let sh = shared();
        let mut inner = sh.inner.lock().unwrap();
        handle_event(&sh, &mut inner, GUID_PERFINFO, 68, 446_000_000_000, 0, &exec_payload(0, 0xFFFF_F800_0000_1000));
        assert!(inner.execs.is_empty() && inner.routines.is_empty());
    }

    #[test]
    fn hard_fault_is_attributed_through_the_thread_map() {
        let sh = shared();
        let mut inner = sh.inner.lock().unwrap();
        let mut thread = 4242u32.to_le_bytes().to_vec(); // ProcessId
        thread.extend(77u32.to_le_bytes()); // TThreadId
        handle_event(&sh, &mut inner, GUID_THREAD, 3, 1_000, 0, &thread);

        let mut fault = vec![0u8; 40];
        fault[0..8].copy_from_slice(&2_000_000u64.to_le_bytes()); // InitialTime
        fault[32..36].copy_from_slice(&77u32.to_le_bytes()); // TThreadId
        fault[36..40].copy_from_slice(&4096u32.to_le_bytes()); // ByteCount
        handle_event(&sh, &mut inner, GUID_PAGEFAULT, 32, 2_060_000, 0, &fault);

        let f = inner.faults.back().expect("fault recorded");
        assert_eq!((f.pid, f.end - f.start), (4242, 60_000));
        assert_eq!(inner.faults_by_pid[&4242].slow, 1);
    }

    #[test]
    fn truncated_payloads_are_ignored() {
        let sh = shared();
        let mut inner = sh.inner.lock().unwrap();
        handle_event(&sh, &mut inner, GUID_PERFINFO, 68, 10, 0, &[1, 2, 3]);
        handle_event(&sh, &mut inner, GUID_DISKIO, 10, 10, 0, &[0; 20]);
        assert!(inner.execs.is_empty() && inner.ios.is_empty());
    }
}
