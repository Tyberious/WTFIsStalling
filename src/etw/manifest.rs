//! A real-time ETW session of its own for one manifest provider, on the same QPC clock as the
//! kernel session.
//!
//! The kernel logger in `etw` is a system logger and cannot carry a manifest provider, so each one
//! this tool reads (the graphics kernel in `gputrace`, the storage port driver in `storport`) gets
//! its own named session with the provider enabled through `EnableTraceEx2`. They share one set of
//! lifetime rules, which live here so that they cannot drift apart:
//! * the session is stopped on `Drop`, so unwinding takes it down;
//! * a stale session with the same name, left by a run that was killed, is stopped and taken over;
//! * only the event ids asked for are delivered (an `EVENT_FILTER_TYPE_EVENT_ID` scope filter);
//! * the consumer runs on its own thread and the callback is the caller's, which must wrap its
//!   work in `catch_unwind`;
//! * field offsets are worked out once per (event id, version) with TDH (`layout`), never per event
//!   and never hand-typed.
//!
//! Everything about such a session is optional: a caller that cannot start one carries on and
//! says so in one line.

use std::collections::HashMap;
use std::ffi::c_void;
use std::mem::{size_of, zeroed};
use std::ptr::null;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;

use windows_sys::core::GUID;
use windows_sys::Win32::System::Diagnostics::Etw::{
    CloseTrace, ControlTraceW, EnableTraceEx2, OpenTraceW, ProcessTrace, StartTraceW, CONTROLTRACE_HANDLE, ENABLE_TRACE_PARAMETERS,
    EVENT_CONTROL_CODE_ENABLE_PROVIDER, EVENT_FILTER_DESCRIPTOR, EVENT_FILTER_TYPE_EVENT_ID, EVENT_RECORD, EVENT_TRACE_LOGFILEW,
    EVENT_TRACE_PROPERTIES, PEVENT_RECORD_CALLBACK,
};

use super::layout;
use crate::util::wide;

const EVENT_TRACE_REAL_TIME_MODE: u32 = 0x0000_0100;
const WNODE_FLAG_TRACED_GUID: u32 = 0x0002_0000;
const EVENT_TRACE_CONTROL_STOP: u32 = 1;
const PROCESS_TRACE_MODE_REAL_TIME: u32 = 0x0000_0100;
const PROCESS_TRACE_MODE_RAW_TIMESTAMP: u32 = 0x0000_1000;
const PROCESS_TRACE_MODE_EVENT_RECORD: u32 = 0x1000_0000;
const ERROR_ALREADY_EXISTS: u32 = 183;

/// What to start: which provider, which of its events, and how much buffer to give the session.
pub struct Spec<'a> {
    /// The session's name. One per provider, so a stale one can be found and taken over.
    pub session: &'a str,
    pub provider: GUID,
    /// The provider in words, for the one-line error: "the graphics provider".
    pub what: &'a str,
    /// `TRACE_LEVEL_*`: every event at this level or more severe.
    pub level: u8,
    /// MatchAnyKeyword.
    pub keywords: u64,
    /// The event ids delivered; everything else the keywords enable is dropped by the session.
    pub ids: &'a [u16],
    /// `EVENT_TRACE_PROPERTIES` buffer settings: size in KB, and the minimum and maximum count.
    pub buffer_kb: u32,
    pub min_buffers: u32,
    pub max_buffers: u32,
}

/// Maps a `(event id, version)` to where its wanted fields are, or `None` when that version's
/// layout could not be worked out (its events are then skipped, never guessed at).
pub type LayoutCache = HashMap<(u16, u8), Option<layout::Fields>>;

pub struct Session {
    handle: CONTROLTRACE_HANDLE,
    stopped: AtomicBool,
}

/// A trace session outlives the process that started it, so unwinding must still take it down.
impl Drop for Session {
    fn drop(&mut self) {
        if !self.stopped.load(Ordering::Relaxed) {
            self.stop();
        }
    }
}

impl Session {
    /// Stops the session, which also disables the provider and makes `ProcessTrace` return.
    /// Returns how many events and real-time buffers the session had to drop.
    pub fn stop(&self) -> u32 {
        self.stopped.store(true, Ordering::Relaxed);
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

fn props_buffer() -> (Vec<u64>, usize) {
    let total = size_of::<EVENT_TRACE_PROPERTIES>() + 2 * 260;
    (vec![0u64; total.div_ceil(8)], total)
}

fn stop_by_name(name: &str) {
    let (mut buf, total) = props_buffer();
    let p = buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
    unsafe {
        (*p).Wnode.BufferSize = total as u32;
        (*p).LoggerNameOffset = size_of::<EVENT_TRACE_PROPERTIES>() as u32;
        ControlTraceW(CONTROLTRACE_HANDLE { Value: 0 }, wide(name).as_ptr(), p, EVENT_TRACE_CONTROL_STOP);
    }
}

fn try_start(spec: &Spec) -> Result<CONTROLTRACE_HANDLE, u32> {
    let (mut buf, total) = props_buffer();
    let p = buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
    let mut handle = CONTROLTRACE_HANDLE { Value: 0 };
    let rc = unsafe {
        (*p).Wnode.BufferSize = total as u32;
        (*p).Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        // 1 = QueryPerformanceCounter, the same clock the kernel session and the probes use, so
        // every timestamp in this report is directly comparable.
        // https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties
        (*p).Wnode.ClientContext = 1;
        (*p).LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        (*p).BufferSize = spec.buffer_kb;
        (*p).MinimumBuffers = spec.min_buffers;
        (*p).MaximumBuffers = spec.max_buffers;
        (*p).FlushTimer = 1; // seconds; the documented minimum
        (*p).LoggerNameOffset = size_of::<EVENT_TRACE_PROPERTIES>() as u32;
        StartTraceW(&mut handle, wide(spec.session).as_ptr(), p)
    };
    if rc == 0 {
        Ok(handle)
    } else {
        Err(rc)
    }
}

/// The event-id scope filter: an `EVENT_FILTER_EVENT_ID` with `FilterIn` set, followed by the
/// ids. The struct declares `Events[ANYSIZE_ARRAY]`, so the real thing is the header plus one
/// `USHORT` per id. At most `MAX_EVENT_FILTER_EVENT_ID_COUNT` (64) ids are allowed.
/// https://learn.microsoft.com/en-us/windows/win32/api/evntprov/ns-evntprov-event_filter_event_id
pub fn event_id_filter(ids: &[u16]) -> Vec<u16> {
    // [FilterIn | Reserved << 8, Count, ids...] as u16 words: FilterIn and Reserved are one byte
    // each and Count is a USHORT, which is the same 4-byte header on every Windows ABI.
    let mut words = vec![1u16, ids.len() as u16];
    words.extend_from_slice(ids);
    words
}

/// Starts the session and enables the provider on it with the event-id filter.
///
/// Microsoft's note on `EnableTraceEx2` is why callers still pick their keywords with care:
/// filtering by event id "is only effective in reducing trace data volume and is not as effective
/// for reducing trace CPU overhead", i.e. the provider still builds every event its keywords
/// enable, and the session throws away the ones not asked for.
/// https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-enabletraceex2
pub fn start(spec: &Spec) -> Result<Session, String> {
    let mut r = try_start(spec);
    if matches!(r, Err(ERROR_ALREADY_EXISTS)) {
        // Left over from a run that was killed; take it over.
        stop_by_name(spec.session);
        r = try_start(spec);
    }
    let handle = r.map_err(|rc| match rc {
        5 => "access denied".to_string(),
        1450 => "Windows is out of trace sessions".to_string(),
        rc => format!("StartTrace failed with Win32 error {rc}"),
    })?;
    let session = Session { handle, stopped: AtomicBool::new(false) };

    let filter = event_id_filter(spec.ids);
    let mut desc = EVENT_FILTER_DESCRIPTOR {
        Ptr: filter.as_ptr() as u64,
        Size: std::mem::size_of_val(&filter[..]) as u32,
        Type: EVENT_FILTER_TYPE_EVENT_ID,
    };
    let mut params: ENABLE_TRACE_PARAMETERS = unsafe { zeroed() };
    params.Version = 2; // ENABLE_TRACE_PARAMETERS_VERSION_2
    params.EnableFilterDesc = &mut desc;
    params.FilterDescCount = 1;
    let rc =
        unsafe { EnableTraceEx2(handle, &spec.provider, EVENT_CONTROL_CODE_ENABLE_PROVIDER, spec.level, spec.keywords, 0, 0, &params) };
    if rc != 0 {
        // The session is stopped by `session` going out of scope here.
        return Err(match rc {
            5 => format!("access denied enabling {}", spec.what),
            rc => format!("EnableTraceEx2 failed with Win32 error {rc}"),
        });
    }
    Ok(session)
}

/// Spawns the consumer thread for session `name`. `callback` receives every event record with
/// `UserContext` pointing at `ctx`, which the thread keeps alive until `ProcessTrace` returns.
pub fn spawn_consumer<T: Send + Sync + 'static>(name: &str, thread: &str, callback: PEVENT_RECORD_CALLBACK, ctx: Arc<T>) -> JoinHandle<()> {
    let name = name.to_string();
    std::thread::Builder::new()
        .name(thread.into())
        .spawn(move || unsafe {
            let mut name = wide(&name);
            let mut lf: EVENT_TRACE_LOGFILEW = zeroed();
            lf.LoggerName = name.as_mut_ptr();
            lf.Anonymous1.ProcessTraceMode =
                PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_RAW_TIMESTAMP;
            lf.Anonymous2.EventRecordCallback = callback;
            lf.Context = Arc::as_ptr(&ctx) as *mut c_void;
            let h = OpenTraceW(&mut lf);
            if h.Value == u64::MAX {
                return;
            }
            ProcessTrace(&h, 1, null(), null());
            CloseTrace(h);
        })
        .expect("spawn manifest etw thread")
}

/// Where `wanted` sits in this event's payload, from the cache or worked out now with TDH and
/// cached. `None` when there is nothing to read (`wanted` is empty) or the layout could not be
/// worked out, which is also cached so TDH is asked once per (event id, version).
///
/// # Safety
/// `rec` must be the event record ETW handed to the callback.
pub unsafe fn resolve(
    cache: &mut LayoutCache,
    rec: *const EVENT_RECORD,
    key: (u16, u8),
    wanted: &[&str],
    ptr_size: usize,
) -> Option<layout::Fields> {
    if wanted.is_empty() {
        return None;
    }
    if let Some(cached) = cache.get(&key) {
        return cached.clone();
    }
    let mut buf = Vec::new();
    let resolved = layout::describe(rec, &mut buf)
        .map(|props| layout::field_offsets(&props, wanted, ptr_size))
        .filter(|f| f.iter().all(Option::is_some));
    cache.insert(key, resolved.clone());
    resolved
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_event_id_filter_is_a_filter_in_list_of_the_ids_asked_for() {
        let ids = [201u16, 209, 1, 2, 4];
        let f = event_id_filter(&ids);
        assert_eq!(f[0], 1, "FilterIn = TRUE, Reserved = 0");
        assert_eq!(f[1] as usize, ids.len());
        assert_eq!(&f[2..], &ids);
        assert_eq!(std::mem::size_of_val(&f[..]), 4 + 2 * ids.len(), "the 4-byte header plus one USHORT per id");
    }
}
