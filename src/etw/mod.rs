//! Real-time kernel ETW session: DPC/ISR, hard faults, disk I/O, thread map and CPU samples.
//!
//! This file starts, stops and pumps the session; `events.rs` next to it turns the raw event
//! records into the shared state. The session uses the QPC clock (ClientContext = 1) and the
//! consumer asks for raw timestamps, so every event time is directly comparable to
//! QueryPerformanceCounter values taken by the latency probes.

mod events;

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
    CloseTrace, ControlTraceW, OpenTraceW, ProcessTrace, StartTraceW, CONTROLTRACE_HANDLE, EVENT_TRACE_FLAG_CSWITCH,
    EVENT_TRACE_FLAG_DISK_FILE_IO, EVENT_TRACE_FLAG_DISK_IO, EVENT_TRACE_FLAG_DISPATCHER, EVENT_TRACE_FLAG_DPC, EVENT_TRACE_FLAG_INTERRUPT,
    EVENT_TRACE_FLAG_MEMORY_HARD_FAULTS, EVENT_TRACE_FLAG_PROCESS, EVENT_TRACE_FLAG_PROFILE, EVENT_TRACE_FLAG_THREAD, EVENT_TRACE_LOGFILEW,
    EVENT_TRACE_PROPERTIES,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use crate::state::Shared;
use crate::util::wide;

use events::on_event;

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

pub struct Session {
    handle: CONTROLTRACE_HANDLE,
    pub profile: bool,
    /// Whether context switches and thread wake-ups are actually being traced.
    pub switches: bool,
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
        // Buffer settings, all from
        // learn.microsoft.com/windows/win32/api/evntrace/ns-evntrace-event_trace_properties:
        // * BufferSize is in KB, 4 to 16384 (1024 before Windows 8). 256 KB is the documented
        //   size for "a diagnostic trace with hundreds of megabytes of data per second", where
        //   "a huge buffer size ... can reduce CPU overhead" - which is what this session is once
        //   context switches are on.
        // * "Beyond this limit, the session discards incoming events": MaximumBuffers is the one
        //   lever against losing events at a peak, and 320 x 256 KB = 80 MB is already far above
        //   the ~5 MB/s a busy 8-CPU machine produces with CSwitch and ReadyThread enabled. Left
        //   as it is deliberately: the fix for a run that still loses events is the run saying so
        //   (it does, in the tool's own cost block) and --no-switches, not reserving more of the
        //   user's memory by default.
        // * FlushTimer is in seconds and 1 is its documented minimum. Higher "will reduce CPU
        //   overhead", but the analyzer holds every incident until the trace has caught up past
        //   its end, so a higher value would delay every verdict by that many seconds.
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
    pub fn start(want_profile: bool, want_switches: bool) -> Result<Session, String> {
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
        // CSWITCH (0x10) turns on the Thread provider's CSwitch events and DISPATCHER (0x800) its
        // ReadyThread events; both are EnableFlags of this same system logger, so they need no
        // second session. Microsoft's own warning about them is on the CSwitch class page: "These
        // events produce a high volume of events" - which is why they are off in light mode and
        // behind --no-switches.
        // https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties
        // https://learn.microsoft.com/en-us/windows/win32/etw/cswitch
        let sched = EVENT_TRACE_FLAG_CSWITCH | EVENT_TRACE_FLAG_DISPATCHER;
        let mut attempts: Vec<(u32, bool, bool)> = attempts.into_iter().map(|(f, p)| (f, p, false)).collect();
        if want_switches {
            // Tried first with the scheduler flags on; the same list without them is the fallback,
            // so a Windows that refuses them still yields everything else.
            let mut with: Vec<(u32, bool, bool)> = attempts.iter().map(|(f, p, _)| (f | sched, *p, true)).collect();
            with.append(&mut attempts);
            attempts = with;
        }
        let mut last = 0;
        for (flags, with_profile, with_switches) in attempts {
            let mut r = try_start(flags);
            if matches!(r, Err(ERROR_ALREADY_EXISTS)) {
                // Left over from a previous run that was killed; take it over.
                stop_by_name();
                r = try_start(flags);
            }
            match r {
                Ok(handle) => {
                    return Ok(Session {
                        handle,
                        profile: with_profile,
                        switches: with_switches,
                        stopped: std::sync::atomic::AtomicBool::new(false),
                    })
                }
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
