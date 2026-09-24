//! One raw DxgKrnl event record into the shared GPU state.
//!
//! Every field is read at an offset worked out once per (event id, version) by `layout`, never
//! at a hand-typed offset and never by calling TDH per event. A version whose layout cannot be
//! worked out is skipped and counted, not guessed at.
//!
//! A panic must never unwind out of `on_event`, which Windows calls: it is wrapped.

use windows_sys::Win32::System::Diagnostics::Etw::EVENT_RECORD;

use crate::etw::{layout, manifest};

use super::{GpuInner, GpuTrace, PresentRec, ResidentRec};
use super::{EV_HSYNC_MULTIPLANE, EV_PRESENT, EV_RESIDENT_START, EV_RESIDENT_STOP, EV_VSYNC, EV_VSYNC_MULTIPLANE};

/// The fields each event is read for, by name. Names come from the provider's own manifest
/// template, so a later version that keeps the name keeps working and one that drops it is
/// skipped rather than misread.
fn wanted_fields(id: u16) -> &'static [&'static str] {
    match id {
        EV_PRESENT => &["VidPnSourceId"],
        EV_RESIDENT_START => &["NumAllocations"],
        EV_RESIDENT_STOP => &["Status", "NumBytesToTrim"],
        _ => &[],
    }
}

/// An NTSTATUS whose severity is Error (the top two bits set, i.e. 0xC0000000 and up).
/// Success (0), Informational (0x4...) and Warning (0x8...) are not failures.
/// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/87fba13e-bf06-450e-83b1-9241dc81e781
fn is_error(status: u64) -> bool {
    (status as u32) >= 0xC000_0000
}

/// No residency operation takes seconds; anything that long is a start event that belonged to a
/// different operation on the same thread, so the duration is dropped rather than reported.
const MAX_RESIDENT_MS: f64 = 2000.0;

pub(super) unsafe extern "system" fn on_event(rec: *mut EVENT_RECORD) {
    let record = &*rec;
    let trace = &*(record.UserContext as *const GpuTrace);
    let hdr = &record.EventHeader;
    let data: &[u8] = if record.UserData.is_null() {
        &[]
    } else {
        std::slice::from_raw_parts(record.UserData as *const u8, record.UserDataLength as usize)
    };
    // ETW's thread, behind a foreign frame: a panic here would abort the process and leave the
    // session running. A poisoned lock only means some other thread panicked; the data is sound.
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut inner = trace.inner.lock().unwrap_or_else(|e| e.into_inner());
        let at = At {
            id: hdr.EventDescriptor.Id,
            version: hdr.EventDescriptor.Version,
            ts: hdr.TimeStamp,
            pid: hdr.ProcessId,
            tid: hdr.ThreadId,
            ptr_size: layout::pointer_size(hdr.Flags),
        };
        // Resolving a layout needs the record itself, so it happens here rather than in the
        // pure handler below.
        let fields = manifest::resolve(&mut inner.layouts, rec, (at.id, at.version), wanted_fields(at.id), at.ptr_size);
        handle(trace, &mut inner, at, fields.as_deref(), data);
    }));
}

/// Which event this is and where it came from.
#[derive(Clone, Copy)]
pub(super) struct At {
    pub id: u16,
    pub version: u8,
    pub ts: i64,
    /// The process the event was logged in. For a present that is the program that drew the
    /// frame; for a residency operation, the program whose textures were being moved.
    pub pid: u32,
    pub tid: u32,
    pub ptr_size: usize,
}

pub(super) fn handle(trace: &GpuTrace, inner: &mut GpuInner, at: At, fields: Option<&[Option<layout::Field>]>, data: &[u8]) {
    inner.events += 1;
    super::maybe_prune(inner, at.ts);
    if trace.debug {
        *inner.debug_counts.entry((at.id, at.version)).or_default() += 1;
    }
    let field = |i: usize| fields.and_then(|f| f.get(i).copied()).flatten();
    match at.id {
        // The vertical-blank (and hardware-flip-queue) DPCs: one per refresh of a display, per
        // path. Only the timestamps are read; see the note on `GpuInner::refresh`.
        EV_VSYNC | EV_VSYNC_MULTIPLANE | EV_HSYNC_MULTIPLANE => inner.on_refresh(at.ts),
        EV_PRESENT => {
            if fields.is_none() {
                return unknown(trace, inner, at);
            }
            let source = layout::read_uint(data, field(0)).unwrap_or(u64::MAX) as u32;
            inner.push_present(PresentRec { ts: at.ts, pid: at.pid, source });
        }
        EV_RESIDENT_START => {
            if fields.is_none() {
                return unknown(trace, inner, at);
            }
            let allocations = layout::read_uint(data, field(0)).unwrap_or(0) as u32;
            inner.starts.insert(at.tid, (at.ts, allocations));
        }
        EV_RESIDENT_STOP => {
            if fields.is_none() {
                return unknown(trace, inner, at);
            }
            let Some(status) = layout::read_uint(data, field(0)) else { return };
            let trim = layout::read_uint(data, field(1)).unwrap_or(0);
            let dur = match inner.starts.remove(&at.tid) {
                Some((start, _)) if (0..crate::util::ms_to_ticks(MAX_RESIDENT_MS)).contains(&(at.ts - start)) => at.ts - start,
                _ => 0,
            };
            inner.push_residency(ResidentRec { ts: at.ts, dur, trim, pid: at.pid, failed: is_error(status) });
        }
        _ => unknown(trace, inner, at),
    }
}

/// An event this build does not understand: counted under `--debug` so one elevated run says
/// exactly which (id, version) pairs a Windows build produces, and otherwise ignored.
fn unknown(trace: &GpuTrace, inner: &mut GpuInner, at: At) {
    if trace.debug {
        *inner.debug_unknown.entry((at.id, at.version)).or_default() += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gputrace::{caps, GpuTraceTotals};
    use crate::util::ms_to_ticks;
    use std::sync::Mutex;

    fn trace(debug: bool) -> GpuTrace {
        let (refresh_cap, present_cap, residency_cap) = caps(60);
        GpuTrace { inner: Mutex::new(GpuInner { refresh_cap, present_cap, residency_cap, ..GpuInner::default() }), debug }
    }

    fn at(id: u16, version: u8, ts: i64, pid: u32, tid: u32) -> At {
        At { id, version, ts, pid, tid, ptr_size: 8 }
    }

    /// The real Present v1 payload, built from the manifest declaration: hContext, hWindow,
    /// VidPnSourceId, FlipInterval, Flags, ReturnStatus, hSrcAllocHandle, hDstAllocHandle.
    fn present_payload(source: u32) -> Vec<u8> {
        let mut d = vec![0u8; 44];
        d[0..4].copy_from_slice(&7u32.to_le_bytes());
        d[12..16].copy_from_slice(&source.to_le_bytes());
        d
    }

    fn resident_stop_payload(status: u32, trim: u64) -> Vec<u8> {
        let mut d = vec![0u8; 20];
        d[0..4].copy_from_slice(&status.to_le_bytes());
        d[4..12].copy_from_slice(&trim.to_le_bytes());
        d
    }

    #[test]
    fn refresh_events_need_no_payload_at_all() {
        let tr = trace(false);
        let mut inner = tr.inner.lock().unwrap();
        for (i, id) in [EV_VSYNC, EV_VSYNC_MULTIPLANE, EV_HSYNC_MULTIPLANE].into_iter().enumerate() {
            // A refresh apart: two events closer than half a millisecond are one refresh.
            handle(&tr, &mut inner, at(id, 0, 100 + i as i64 * crate::util::ms_to_ticks(16.7), 0, 0), None, &[]);
        }
        assert_eq!(inner.refresh.len(), 3);
        assert_eq!(inner.totals.refresh_ticks, 3);
        assert_eq!(inner.events, 3);
    }

    #[test]
    fn a_present_is_credited_to_the_process_it_was_logged_in() {
        let tr = trace(false);
        let mut inner = tr.inner.lock().unwrap();
        let fields = [Some((12usize, 4usize))];
        handle(&tr, &mut inner, at(EV_PRESENT, 1, 5_000, 4242, 77), Some(&fields), &present_payload(1));
        assert_eq!(inner.presents.back(), Some(&PresentRec { ts: 5_000, pid: 4242, source: 1 }));
        // A payload cut short before the field still counts as a present, just without a display.
        handle(&tr, &mut inner, at(EV_PRESENT, 1, 5_100, 4242, 77), Some(&fields), &present_payload(1)[..8]);
        assert_eq!(inner.presents.back().unwrap().source, u32::MAX);
        assert_eq!(inner.totals.presents, 2);
    }

    #[test]
    fn a_residency_operation_gets_its_duration_from_the_matching_start_on_the_same_thread() {
        let tr = trace(false);
        let mut inner = tr.inner.lock().unwrap();
        let start_fields = [Some((16usize, 4usize))];
        let stop_fields = [Some((0usize, 4usize)), Some((4usize, 8usize))];
        let mut start_payload = vec![0u8; 24];
        start_payload[16..20].copy_from_slice(&3u32.to_le_bytes());

        handle(&tr, &mut inner, at(EV_RESIDENT_START, 0, 1_000, 900, 55), Some(&start_fields), &start_payload);
        handle(
            &tr,
            &mut inner,
            at(EV_RESIDENT_STOP, 0, 1_000 + ms_to_ticks(8.0), 900, 55),
            Some(&stop_fields),
            &resident_stop_payload(0, 0),
        );
        let r = *inner.residency.back().unwrap();
        assert_eq!((r.pid, r.trim, r.failed), (900, 0, false));
        assert!((crate::util::ticks_to_ms(r.dur) - 8.0).abs() < 0.1);
        assert!(inner.starts.is_empty(), "the pairing consumes the start");

        // Over budget, and a failure: both are facts the report can use.
        handle(
            &tr,
            &mut inner,
            at(EV_RESIDENT_STOP, 0, 2_000, 900, 56),
            Some(&stop_fields),
            &resident_stop_payload(0xC000_0017, 512_000_000),
        );
        let r = *inner.residency.back().unwrap();
        assert_eq!((r.dur, r.trim, r.failed), (0, 512_000_000, true), "no start on that thread: no invented duration");
        assert_eq!(inner.totals.trim_events, 1);
        assert_eq!(inner.totals.trim_max_bytes, 512_000_000);
        assert_eq!(inner.totals.residency_failed, 1);

        // A start left behind by an earlier operation must not become a several-second duration.
        handle(&tr, &mut inner, at(EV_RESIDENT_START, 0, 0, 900, 57), Some(&start_fields), &start_payload);
        handle(&tr, &mut inner, at(EV_RESIDENT_STOP, 0, ms_to_ticks(9_000.0), 900, 57), Some(&stop_fields), &resident_stop_payload(0, 0));
        assert_eq!(inner.residency.back().unwrap().dur, 0);
    }

    #[test]
    fn a_version_whose_layout_is_unknown_is_counted_and_skipped_rather_than_guessed() {
        let tr = trace(true);
        let mut inner = tr.inner.lock().unwrap();
        handle(&tr, &mut inner, at(EV_PRESENT, 99, 10, 1, 1), None, &present_payload(0));
        handle(&tr, &mut inner, at(EV_RESIDENT_STOP, 99, 11, 1, 1), None, &resident_stop_payload(0, 1));
        handle(&tr, &mut inner, at(4242, 0, 12, 1, 1), None, &[]);
        assert!(inner.presents.is_empty() && inner.residency.is_empty(), "nothing was invented");
        assert_eq!(inner.debug_unknown.get(&(EV_PRESENT, 99)), Some(&1));
        assert_eq!(inner.debug_unknown.get(&(4242, 0)), Some(&1), "an event the filter should have excluded is still reported");
        assert_eq!(inner.debug_counts.len(), 3, "and everything seen is counted");
        assert_eq!(inner.totals, GpuTraceTotals::default());
    }

    #[test]
    fn only_error_statuses_count_as_a_failure() {
        assert!(!is_error(0), "STATUS_SUCCESS");
        assert!(!is_error(0x0000_0103), "STATUS_PENDING is not a failure");
        assert!(!is_error(0x8000_000A), "a warning is not a failure");
        assert!(is_error(0xC000_0017), "STATUS_NO_MEMORY");
        assert!(is_error(0xC000_009A));
    }
}
