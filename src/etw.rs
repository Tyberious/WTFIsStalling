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
    CloseTrace, ControlTraceW, OpenTraceW, ProcessTrace, StartTraceW, CONTROLTRACE_HANDLE, EVENT_HEADER_FLAG_PROCESSOR_INDEX, EVENT_RECORD,
    EVENT_TRACE_FLAG_DISK_FILE_IO, EVENT_TRACE_FLAG_DISK_IO, EVENT_TRACE_FLAG_DPC, EVENT_TRACE_FLAG_INTERRUPT,
    EVENT_TRACE_FLAG_MEMORY_HARD_FAULTS, EVENT_TRACE_FLAG_PROCESS, EVENT_TRACE_FLAG_PROFILE, EVENT_TRACE_FLAG_THREAD, EVENT_TRACE_LOGFILEW,
    EVENT_TRACE_PROPERTIES,
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
/// FileIoGuid = 90cbdc39-4a3e-11d1-84f4-0000f80464e3.
/// https://learn.microsoft.com/en-us/windows/win32/etw/nt-kernel-logger-constants
const GUID_FILEIO: u32 = 0x90cb_dc39;

pub struct Session {
    handle: CONTROLTRACE_HANDLE,
    pub profile: bool,
    stopped: std::sync::atomic::AtomicBool,
}

/// A kernel logger session outlives the process that started it. Whatever goes wrong after the
/// trace starts (a panic while summarizing included), unwinding must still take the session down.
impl Drop for Session {
    fn drop(&mut self) {
        if !self.stopped.load(std::sync::atomic::Ordering::Relaxed) {
            self.stop();
        }
    }
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
        let core = EVENT_TRACE_FLAG_PROCESS
            | EVENT_TRACE_FLAG_THREAD
            | EVENT_TRACE_FLAG_DISK_IO
            | EVENT_TRACE_FLAG_MEMORY_HARD_FAULTS
            | EVENT_TRACE_FLAG_DPC
            | EVENT_TRACE_FLAG_INTERRUPT;
        // DISK_FILE_IO (0x200, "requires disk IO" - evntrace.h) adds only the FileIo_Name class:
        // one small event per file object, not one per file operation. The per-operation classes
        // live behind FILE_IO_INIT (FileIo_ReadWrite, FileIo_Create, ...) and FILE_IO
        // (FileIo_OpEnd), which this tool must not enable: those fire for every read and write on
        // the machine. https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties
        let base = core | EVENT_TRACE_FLAG_DISK_FILE_IO;
        let profile = want_profile && enable_privilege("SeSystemProfilePrivilege");
        // Last resort: a session with no file names at all still reports everything else.
        let mut attempts = vec![(base, false), (core, false)];
        if profile {
            attempts.insert(0, (core | EVENT_TRACE_FLAG_PROFILE, true));
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
                Ok(handle) => return Ok(Session { handle, profile: with_profile, stopped: std::sync::atomic::AtomicBool::new(false) }),
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
        self.stopped.store(true, std::sync::atomic::Ordering::Relaxed);
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

/// Longest file path the kernel can hand us that is worth keeping (NTFS allows 32767 with the
/// \\?\ prefix, but nothing that long belongs in a report).
const MAX_PATH_CHARS: usize = 320;

/// A UTF-16, null-terminated MOF string at `off`. Returns None for a truncated or empty one.
/// An odd trailing byte is ignored rather than read past the end of the payload.
fn rd_wstr(d: &[u8], off: usize) -> Option<String> {
    let tail = d.get(off..)?;
    let mut units: Vec<u16> = Vec::new();
    for pair in tail.chunks(2) {
        if pair.len() < 2 {
            break;
        }
        let u = u16::from_le_bytes([pair[0], pair[1]]);
        if u == 0 || units.len() >= MAX_PATH_CHARS {
            break;
        }
        units.push(u);
    }
    (!units.is_empty()).then(|| String::from_utf16_lossy(&units))
}

/// Which CPU an event was logged on. `ETW_BUFFER_CONTEXT` holds a u16 `ProcessorIndex` in a
/// union with an older `{ u8 ProcessorNumber; u8 Alignment; }`, and the flag says which one is
/// filled in. This is exactly what the SDK's own inline `GetEventProcessorIndex` does
/// (evntcons.h, Windows Kits 10.0.26100.0):
///     if (Flags & EVENT_HEADER_FLAG_PROCESSOR_INDEX) return BufferContext.ProcessorIndex;
///     else return BufferContext.ProcessorNumber;
/// Reading the u16 unconditionally (what this used to do) would return
/// `ProcessorNumber + 256 * Alignment` on a buffer written the old way.
///
/// `ProcessorIndex` is the system-wide index, the numbering `topology` maps probe threads onto.
/// `ProcessorNumber` is only a group-relative number, so on a machine with several processor
/// groups an old-style buffer cannot be placed at all; taking it as-is is right for every
/// machine of 64 CPUs or fewer, which is every machine with a single group.
fn processor_index(flags: u16, index: u16, number: u8) -> u16 {
    if flags as u32 & EVENT_HEADER_FLAG_PROCESSOR_INDEX != 0 {
        index
    } else {
        number as u16
    }
}

unsafe extern "system" fn on_event(rec: *mut EVENT_RECORD) {
    let rec = &*rec;
    let shared = &*(rec.UserContext as *const Shared);
    let hdr = &rec.EventHeader;
    let data: &[u8] =
        if rec.UserData.is_null() { &[] } else { std::slice::from_raw_parts(rec.UserData as *const u8, rec.UserDataLength as usize) };
    let ctx = rec.BufferContext.Anonymous;
    let cpu = processor_index(hdr.Flags, ctx.ProcessorIndex, ctx.Anonymous.ProcessorNumber);
    // This runs on ETW's thread behind a foreign frame: a panic must not unwind out of it (that
    // aborts the process, which would leave the kernel session running and lose the report).
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // A poisoned lock only means some other thread panicked; the event data is still sound.
        let mut inner = shared.inner.lock().unwrap_or_else(|e| e.into_inner());
        handle_event(shared, &mut inner, hdr.ProviderId.data1, hdr.EventDescriptor.Opcode, hdr.TimeStamp, cpu, data);
    }));
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
            let dur = ts.wrapping_sub(start);
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
        // HardFault (64-bit): InitialTime u64 @0, ReadOffset u64 @8, VirtualAddress ptr @16,
        // FileObject ptr @24, TThreadId u32 @32, ByteCount u32 @36. FileObject: "Match the value
        // of this pointer to the FileObject pointer value in a FileIo_Name event to determine the
        // name of the file." https://learn.microsoft.com/en-us/windows/win32/etw/pagefault-hardfault
        (GUID_PAGEFAULT, 32) => {
            let start = rd_u64(d, 0)? as i64;
            let file = rd_u64(d, 24).unwrap_or(0);
            let tid = rd_u32(d, 32)?;
            let bytes = rd_u32(d, 36).unwrap_or(0);
            let dur = ts.wrapping_sub(start);
            if !(0..MAX_SANE).contains(&dur) {
                return None;
            }
            let pid = inner.tid_pid.get(&tid).copied().unwrap_or(PID_UNKNOWN);
            let r = FaultRec { start, end: ts, tid, pid, bytes, file };
            inner.faults.push_back(r);
            let st = inner.faults_by_pid.entry(pid).or_default();
            st.count += 1;
            st.total += dur;
            st.max = st.max.max(dur);
            if file != 0 {
                add_wait(&mut inner.fault_file, (pid, file), 0, dur);
                cap_by_wait(&mut inner.fault_file, FILE_WAIT_CAP);
            }
            if dur >= shared.fault_warn {
                st.slow += 1;
                push_notable(inner, Notable::SlowFault(r));
            }
        }
        // Read / Write (DiskIo_TypeGroup1, 64-bit): DiskNumber u32 @0, IrpFlags u32 @4,
        // TransferSize u32 @8, Reserved u32 @12, ByteOffset i64 @16, FileObject ptr @24,
        // Irp ptr @32, HighResResponseTime u64 @40, IssuingThreadId u32 @48.
        // Flush (DiskIo_TypeGroup3): DiskNumber @0, IrpFlags @4, HighResResponseTime u64 @8,
        // Irp ptr @16, IssuingThreadId u32 @24 - no file object at all, so flushes stay unnamed.
        // https://learn.microsoft.com/en-us/windows/win32/etw/diskio-typegroup1
        // https://learn.microsoft.com/en-us/windows/win32/etw/diskio-typegroup3
        (GUID_DISKIO, 10 | 11 | 14) => {
            let disk = rd_u32(d, 0)?;
            let (size, dur, tid, op, file) = if opcode == 14 {
                (0, rd_u64(d, 8)? as i64, rd_u32(d, 24)?, b'F', 0)
            } else {
                let file = rd_u64(d, 24).unwrap_or(0);
                (rd_u32(d, 8)?, rd_u64(d, 40)? as i64, rd_u32(d, 48)?, if opcode == 10 { b'R' } else { b'W' }, file)
            };
            if !(0..MAX_SANE).contains(&dur) {
                return None;
            }
            let pid = inner.tid_pid.get(&tid).copied().unwrap_or(PID_UNKNOWN);
            let r = IoRec { end: ts, dur, disk, tid, pid, size, op, file };
            inner.ios.push_back(r);
            let st = inner.disks.entry(disk).or_default();
            st.count += 1;
            st.total += dur;
            st.max = st.max.max(dur);
            if file != 0 {
                add_wait(&mut inner.file_wait, file, disk, dur);
                cap_by_wait(&mut inner.file_wait, FILE_WAIT_CAP);
            }
            if dur >= shared.io_warn {
                st.slow += 1;
                push_notable(inner, Notable::SlowIo(r));
            }
        }
        // FileIo_Name / FileCreate / FileDelete / FileRundown, all one MOF class (64-bit):
        // FileObject ptr @0, FileName UTF-16 null-terminated @8.
        // https://learn.microsoft.com/en-us/windows/win32/etw/fileio-name
        // https://learn.microsoft.com/en-us/windows/win32/etw/fileio  (event types 0, 32, 35, 36)
        //
        // The field is documented as the FileObject, but in the rundown (36) it is really the
        // FileKey (the FILE_OBJECT's FsContext), which is what DiskIo and HardFault carry for a
        // mapped file - a long-known discrepancy, see
        // https://lowleveldesign.wordpress.com/2020/08/15/fixing-empty-paths-in-fileio-events-etw/
        // Both are pointers into one kernel address space, so keying every name event by the
        // value it carries and looking up whatever the I/O event carries resolves either kind
        // without having to know which is which.
        //
        // FileDelete still inserts: the file is gone, but requests already recorded for it are
        // not, and they still deserve a name. Eviction is what bounds this map, not deletion.
        (GUID_FILEIO, 0 | 32 | 35 | 36) => {
            let key = rd_u64(d, 0)?;
            // The rundown (36) arrives when the session stops and names EVERY open file on the PC:
            // about 130,000 on the development machine, against a map capped at 40,000. Only files
            // that waited on a disk during this run are of any use by then, so once the map is
            // half full the rest are skipped instead of pushing useful names out. (Measured live;
            // Microsoft documents the timing, "at the end of the trace session", not the count.)
            if opcode == 36 && inner.file_names.len() >= crate::state::FILE_NAME_CAP / 2 && !inner.file_wait.contains_key(&key) {
                return Some(());
            }
            let name = rd_wstr(d, 8)?;
            // The kernel recycles FILE_OBJECT addresses, so one key can name a different file
            // later in the run. Seeing the key change name means the old tally belongs to a file
            // we can no longer name: drop it rather than add it to the new file's waiting, which
            // would put someone else's seconds against this one's name.
            if inner.file_names.get(key).is_some_and(|had| had != name) {
                inner.file_wait.remove(&key);
            }
            inner.file_names.insert(key, &name);
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

fn add_wait<K: Copy + Eq + std::hash::Hash>(m: &mut std::collections::HashMap<K, FileWait>, key: K, disk: u32, dur: i64) {
    let e = m.entry(key).or_insert(FileWait { disk, ..FileWait::default() });
    e.count += 1;
    e.total += dur;
    e.max = e.max.max(dur);
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

        handle_event(&sh, &mut inner, GUID_PAGEFAULT, 32, 2_060_000, 0, &fault_payload(2_000_000, 0, 77, 4096));

        let f = inner.faults.back().expect("fault recorded");
        assert_eq!((f.pid, f.end - f.start), (4242, 60_000));
        assert_eq!(inner.faults_by_pid[&4242].slow, 1);
    }

    fn fault_payload(initial_time: u64, file: u64, tid: u32, bytes: u32) -> Vec<u8> {
        let mut d = vec![0u8; 40];
        d[0..8].copy_from_slice(&initial_time.to_le_bytes()); // InitialTime
        d[24..32].copy_from_slice(&file.to_le_bytes()); // FileObject
        d[32..36].copy_from_slice(&tid.to_le_bytes()); // TThreadId
        d[36..40].copy_from_slice(&bytes.to_le_bytes()); // ByteCount
        d
    }

    fn io_payload(disk: u32, size: u32, file: u64, response: u64, tid: u32) -> Vec<u8> {
        let mut d = vec![0u8; 52];
        d[0..4].copy_from_slice(&disk.to_le_bytes()); // DiskNumber
        d[8..12].copy_from_slice(&size.to_le_bytes()); // TransferSize
        d[24..32].copy_from_slice(&file.to_le_bytes()); // FileObject
        d[40..48].copy_from_slice(&response.to_le_bytes()); // HighResResponseTime
        d[48..52].copy_from_slice(&tid.to_le_bytes()); // IssuingThreadId
        d
    }

    /// The end-of-session rundown names every open file on the PC; only the ones that waited on
    /// a disk may take up room once the map is filling.
    #[test]
    fn the_rundown_cannot_push_out_the_names_that_matter() {
        let sh = shared();
        let mut inner = sh.inner.lock().unwrap();
        const BUSY: u64 = 0xffff_aaaa_0000_0010;
        // A file does slow I/O during the run; its name is not known yet.
        handle_event(&sh, &mut inner, GUID_DISKIO, 11, 5_000, 0, &io_payload(1, 65536, BUSY, 300_000, 9));
        assert!(inner.file_wait.contains_key(&BUSY));
        // Rundown: far more files than the cap, the busy one in the middle of them.
        let total = crate::state::FILE_NAME_CAP as u64 * 3;
        for k in 1..=total {
            let key = if k == total / 2 { BUSY } else { 0xffff_bbbb_0000_0000 + k * 16 };
            handle_event(&sh, &mut inner, GUID_FILEIO, 36, 9_000_000, 0, &name_payload(key, r"\Device\HarddiskVolume3\x.bin"));
        }
        assert_eq!(inner.file_names.get(BUSY), Some(r"\Device\HarddiskVolume3\x.bin"), "the file that waited keeps its name");
        assert!(inner.file_names.len() <= crate::state::FILE_NAME_CAP / 2 + 1, "idle files stop being stored: {}", inner.file_names.len());
    }

    fn name_payload(key: u64, name: &str) -> Vec<u8> {
        let mut d = key.to_le_bytes().to_vec();
        d.extend(name.encode_utf16().flat_map(u16::to_le_bytes));
        d.extend([0, 0]); // NUL terminator
        d
    }

    const FILE_KEY: u64 = 0xFFFF_8E01_2345_6780;

    #[test]
    fn a_name_event_names_the_disk_requests_that_carry_the_same_key() {
        let sh = shared();
        let mut inner = sh.inner.lock().unwrap();
        handle_event(&sh, &mut inner, GUID_FILEIO, 0, 100, 0, &name_payload(FILE_KEY, "\\Device\\HarddiskVolume3\\pagefile.sys"));
        handle_event(&sh, &mut inner, GUID_DISKIO, 10, 5_000, 0, &io_payload(1, 65536, FILE_KEY, 300_000, 9));

        let io = inner.ios.back().expect("request recorded");
        assert_eq!((io.file, io.disk, io.op), (FILE_KEY, 1, b'R'));
        assert_eq!(inner.file_names.get(FILE_KEY), Some("\\Device\\HarddiskVolume3\\pagefile.sys"));
        let w = inner.file_wait[&FILE_KEY];
        assert_eq!((w.disk, w.count, w.total), (1, 1, 300_000));
        // The rundown at the end of the trace carries the same shape and a FileKey instead.
        handle_event(&sh, &mut inner, GUID_FILEIO, 36, 200, 0, &name_payload(7, "\\Device\\HarddiskVolume3\\$Mft"));
        assert_eq!(inner.file_names.get(7), Some("\\Device\\HarddiskVolume3\\$Mft"));
        // Repeating the same name (which the kernel does) must not throw the tally away.
        handle_event(&sh, &mut inner, GUID_FILEIO, 0, 300, 0, &name_payload(FILE_KEY, "\\Device\\HarddiskVolume3\\pagefile.sys"));
        assert_eq!(inner.file_wait[&FILE_KEY].count, 1);
    }

    /// Windows recycles FILE_OBJECT addresses. When a key comes back as a different file, the
    /// waiting recorded under it must not be handed to the new file.
    #[test]
    fn a_recycled_file_object_does_not_inherit_the_old_files_waiting() {
        let sh = shared();
        let mut inner = sh.inner.lock().unwrap();
        handle_event(&sh, &mut inner, GUID_FILEIO, 32, 100, 0, &name_payload(FILE_KEY, "\\Device\\HarddiskVolume3\\big.log"));
        handle_event(&sh, &mut inner, GUID_DISKIO, 11, 5_000, 0, &io_payload(1, 4096, FILE_KEY, 900_000, 9));
        assert_eq!(inner.file_wait[&FILE_KEY].total, 900_000);

        handle_event(&sh, &mut inner, GUID_FILEIO, 32, 6_000, 0, &name_payload(FILE_KEY, "\\Device\\HarddiskVolume3\\other.dat"));
        assert!(!inner.file_wait.contains_key(&FILE_KEY), "the old tally went with the old name");
        handle_event(&sh, &mut inner, GUID_DISKIO, 11, 7_000, 0, &io_payload(1, 4096, FILE_KEY, 10, 9));
        assert_eq!(inner.file_wait[&FILE_KEY].total, 10, "the new file starts from zero");
        assert_eq!(inner.file_names.get(FILE_KEY), Some("\\Device\\HarddiskVolume3\\other.dat"));
    }

    #[test]
    fn hard_faults_are_totaled_per_process_and_file() {
        let sh = shared();
        let mut inner = sh.inner.lock().unwrap();
        let mut thread = 42u32.to_le_bytes().to_vec();
        thread.extend(7u32.to_le_bytes());
        handle_event(&sh, &mut inner, GUID_THREAD, 3, 10, 0, &thread);
        for i in 0..3 {
            handle_event(&sh, &mut inner, GUID_PAGEFAULT, 32, 1_000 + i * 100, 0, &fault_payload(1_000, FILE_KEY, 7, 4096));
        }
        let w = inner.fault_file[&(42, FILE_KEY)];
        assert_eq!((w.count, w.max), (3, 200));
        assert_eq!(inner.faults.back().unwrap().file, FILE_KEY);
    }

    /// Flush events (DiskIo_TypeGroup3) have no FileObject field; nothing may be invented.
    #[test]
    fn flushes_and_nameless_requests_are_left_unnamed() {
        let sh = shared();
        let mut inner = sh.inner.lock().unwrap();
        let mut flush = vec![0u8; 28];
        flush[8..16].copy_from_slice(&400_000u64.to_le_bytes());
        handle_event(&sh, &mut inner, GUID_DISKIO, 14, 9_000, 0, &flush);
        assert_eq!(inner.ios.back().unwrap().file, 0);
        assert!(inner.file_wait.is_empty(), "a zero file object is never a map key");
    }

    #[test]
    fn garbage_and_truncated_name_events_are_ignored() {
        let sh = shared();
        let mut inner = sh.inner.lock().unwrap();
        handle_event(&sh, &mut inner, GUID_FILEIO, 0, 1, 0, &[]);
        handle_event(&sh, &mut inner, GUID_FILEIO, 0, 1, 0, &[0xFF; 7]); // no room for the key
        handle_event(&sh, &mut inner, GUID_FILEIO, 0, 1, 0, &1u64.to_le_bytes()); // key, no name
        assert!(inner.file_names.is_empty(), "nothing usable in any of those");
        // A payload that ends mid-character: keep the characters that are whole, read no further.
        let mut odd = 2u64.to_le_bytes().to_vec();
        odd.extend([b'a', 0, b'b', 0, b'c']);
        handle_event(&sh, &mut inner, GUID_FILEIO, 0, 1, 0, &odd);
        assert_eq!(inner.file_names.get(2), Some("ab"));
        // A name longer than any real path is cut, not stored whole.
        let mut huge = 3u64.to_le_bytes().to_vec();
        huge.extend("x".repeat(5000).encode_utf16().flat_map(u16::to_le_bytes));
        handle_event(&sh, &mut inner, GUID_FILEIO, 0, 1, 0, &huge);
        assert_eq!(inner.file_names.get(3).map(str::len), Some(MAX_PATH_CHARS));
        // A payload cut short after the file object still yields the request, just unnamed.
        handle_event(&sh, &mut inner, GUID_DISKIO, 10, 5_000, 0, &io_payload(0, 0, 5, 1, 0)[..20]);
        assert!(inner.ios.is_empty());
    }

    #[test]
    fn the_name_map_is_capped_and_evicts_the_oldest() {
        let mut names = FileNames::default();
        for i in 1..=(FILE_NAME_CAP as u64 + 100) {
            names.insert(i, &format!("\\Device\\HarddiskVolume1\\f{i}"));
        }
        assert_eq!(names.len(), FILE_NAME_CAP);
        assert_eq!(names.get(1), None, "the oldest went first");
        assert!(names.get(FILE_NAME_CAP as u64 + 100).is_some());
        // Re-inserting a known key must not grow the eviction queue.
        let before = names.len();
        names.insert(FILE_NAME_CAP as u64 + 100, "\\Device\\HarddiskVolume1\\renamed");
        assert_eq!((names.len(), names.get(FILE_NAME_CAP as u64 + 100)), (before, Some("\\Device\\HarddiskVolume1\\renamed")));
        names.insert(0, "ignored");
        names.insert(999_999, "");
        assert_eq!(names.len(), before);
    }

    #[test]
    fn the_per_file_tally_is_capped_by_dropping_the_files_that_waited_least() {
        let mut m: std::collections::HashMap<u64, FileWait> = std::collections::HashMap::new();
        for i in 1..=(FILE_WAIT_CAP as u64 + 500) {
            m.insert(i, FileWait { disk: 0, count: 1, total: i as i64, max: i as i64 });
        }
        let biggest = (FILE_WAIT_CAP as u64 + 500) as i64;
        cap_by_wait(&mut m, FILE_WAIT_CAP);
        assert!(m.len() <= FILE_WAIT_CAP / 2, "{} left", m.len());
        assert!(m.values().all(|v| v.total > biggest / 3), "only the longest waits survive");
        // Under the cap nothing is touched, and all-equal totals still terminate.
        let mut small: std::collections::HashMap<u64, FileWait> = (0..10).map(|i| (i, FileWait::default())).collect();
        cap_by_wait(&mut small, FILE_WAIT_CAP);
        assert_eq!(small.len(), 10);
        let mut tied: std::collections::HashMap<u64, FileWait> =
            (0..FILE_WAIT_CAP as u64 + 10).map(|i| (i, FileWait { total: 5, ..FileWait::default() })).collect();
        cap_by_wait(&mut tied, FILE_WAIT_CAP);
        assert!(tied.is_empty(), "all tied: the whole tally is dropped rather than grown");
    }

    /// The flag decides which half of the union is real; without it the u16 is
    /// ProcessorNumber + 256 * Alignment and must not be used.
    #[test]
    fn processor_index_follows_the_event_header_flag() {
        let flag = EVENT_HEADER_FLAG_PROCESSOR_INDEX as u16;
        assert_eq!(processor_index(flag, 300, 44), 300, "past 255 CPUs only the u16 is right");
        assert_eq!(processor_index(flag | 0x40, 7, 7), 7);
        // Old-style buffer: Alignment 8 makes the u16 read 2051, the real CPU is 3.
        assert_eq!(processor_index(0x40, 3 + 8 * 256, 3), 3);
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
