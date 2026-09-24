//! One raw StorPort event record into the shared storage-port state.
//!
//! Every field is read at an offset worked out once per (event id, version) by `etw::layout`,
//! never at a hand-typed offset and never by calling TDH per event. A version whose layout cannot
//! be worked out is skipped and counted under --debug, not guessed at.
//!
//! A panic must never unwind out of `on_event`, which Windows calls: it is wrapped.

use windows_sys::Win32::System::Diagnostics::Etw::EVENT_RECORD;

use crate::etw::{layout, manifest};

use super::{ReqRec, ResetKind, ResetRec, ScsiAddr, StorInner, StorTrace};
use super::{EV_LU_RESET, EV_REQUEST, EV_RESET_DETECTED, EV_RETRY, EV_TARGET_RESET};

/// The fields each event is read for, by name, from the manifest templates quoted in `mod.rs`. A
/// later version that keeps the names keeps working; one that drops one is skipped, not misread.
pub(super) fn wanted_fields(id: u16) -> &'static [&'static str] {
    match id {
        EV_REQUEST => &[
            "RequestDuration_100ns",
            "Irp",
            "Command",
            "SrbStatus",
            "OriginalIrp",
            "Port",
            "Bus",
            "Target",
            "LUN",
            "ScsiStatus",
            "ByteLengthOfTransfer",
        ],
        EV_RETRY => &["Irp", "CurrentRetryCount"],
        EV_LU_RESET => &["PortNumber", "PathID", "TargetID", "LUN"],
        EV_TARGET_RESET => &["PortNumber", "PathID", "TargetID"],
        EV_RESET_DETECTED => &["PortNumber"],
        _ => &[],
    }
}

pub(super) unsafe extern "system" fn on_event(rec: *mut EVENT_RECORD) {
    let record = &*rec;
    let trace = &*(record.UserContext as *const StorTrace);
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
            ptr_size: layout::pointer_size(hdr.Flags),
        };
        let fields = manifest::resolve(&mut inner.layouts, rec, (at.id, at.version), wanted_fields(at.id), at.ptr_size);
        handle(trace, &mut inner, at, fields.as_deref(), data);
    }));
}

/// Which event this is and when.
#[derive(Clone, Copy)]
pub(super) struct At {
    pub id: u16,
    pub version: u8,
    pub ts: i64,
    pub ptr_size: usize,
}

pub(super) fn handle(trace: &StorTrace, inner: &mut StorInner, at: At, fields: Option<&[Option<layout::Field>]>, data: &[u8]) {
    inner.events += 1;
    super::maybe_prune(inner, at.ts);
    if trace.debug {
        *inner.debug_counts.entry((at.id, at.version)).or_default() += 1;
    }
    let Some(fields) = fields else { return unknown(trace, inner, at) };
    let get = |i: usize| layout::read_uint(data, fields.get(i).copied().flatten());
    let byte = |i: usize| get(i).map(|v| v as u8);
    match at.id {
        EV_REQUEST => {
            let (Some(dur), Some(irp)) = (get(0), get(1)) else { return unknown(trace, inner, at) };
            let r = ReqRec {
                ts: at.ts,
                dur: super::ticks_from_100ns(dur),
                irp,
                orig: get(4).unwrap_or(0),
                bytes: get(10).unwrap_or(0) as u32,
                addr: ScsiAddr {
                    port: byte(5).unwrap_or(0),
                    bus: byte(6).unwrap_or(0),
                    target: byte(7).unwrap_or(0),
                    lun: byte(8).unwrap_or(0),
                },
                srb: byte(3).unwrap_or(0),
                scsi: byte(9).unwrap_or(0),
                cmd: byte(2).unwrap_or(0),
                retries: 0,
            };
            if trace.debug {
                *inner.debug_status.entry((r.srb, r.scsi)).or_default() += 1;
                *inner.debug_commands.entry(r.cmd).or_default() += 1;
            }
            inner.push_req(r);
        }
        EV_RETRY => match get(0) {
            Some(irp) => inner.on_retry(at.ts, irp),
            None => unknown(trace, inner, at),
        },
        EV_LU_RESET | EV_TARGET_RESET | EV_RESET_DETECTED => {
            let Some(port) = get(0) else { return unknown(trace, inner, at) };
            let kind = match at.id {
                EV_LU_RESET => ResetKind::LogicalUnit,
                EV_TARGET_RESET => ResetKind::Target,
                _ => ResetKind::Detected,
            };
            // Only the fields this kind of reset names; `wanted_fields` asks for no more.
            inner.on_reset(ResetRec { ts: at.ts, kind, port: port as u32, bus: byte(1), target: byte(2), lun: byte(3) });
        }
        _ => unknown(trace, inner, at),
    }
}

/// An event this build does not understand: counted under `--debug` so one elevated run says
/// exactly which (id, version) pairs a Windows build produces, and otherwise ignored.
fn unknown(trace: &StorTrace, inner: &mut StorInner, at: At) {
    if trace.debug {
        *inner.debug_unknown.entry((at.id, at.version)).or_default() += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::etw::layout::{field_offsets, Prop};
    use crate::util::{ms_to_ticks, ticks_to_ms};
    use std::sync::Mutex;
    use windows_sys::Win32::System::Diagnostics::Etw::{TDH_INTYPE_POINTER, TDH_INTYPE_UINT32, TDH_INTYPE_UINT64, TDH_INTYPE_UINT8};

    fn trace(debug: bool) -> StorTrace {
        StorTrace { inner: Mutex::new(StorInner::new(super::super::REQ_CAP, 0)), debug }
    }

    fn p(name: &str, in_type: i32, length: u16) -> Prop {
        Prop { name: name.into(), in_type: in_type as u16, length, variable: false }
    }

    /// Event 201 version 2, exactly as the provider manifest on this machine declares it.
    fn template_201() -> Vec<Prop> {
        vec![
            p("RequestDuration_100ns", TDH_INTYPE_UINT64, 8),
            p("Irp", TDH_INTYPE_POINTER, 8),
            p("Command", TDH_INTYPE_UINT8, 1),
            p("SrbStatus", TDH_INTYPE_UINT8, 1),
            p("OriginalIrp", TDH_INTYPE_POINTER, 8),
            p("Port", TDH_INTYPE_UINT8, 1),
            p("Bus", TDH_INTYPE_UINT8, 1),
            p("Target", TDH_INTYPE_UINT8, 1),
            p("LUN", TDH_INTYPE_UINT8, 1),
            p("ScsiStatus", TDH_INTYPE_UINT8, 1),
            p("ByteLengthOfTransfer", TDH_INTYPE_UINT32, 4),
            p("BuildIoDuration_100ns", TDH_INTYPE_UINT64, 8),
            p("StartIoDuration_100ns", TDH_INTYPE_UINT64, 8),
        ]
    }

    /// A packed payload of `template` with the given values, pointers `ptr` bytes wide: built the
    /// way the provider writes it, independently of `field_offsets`.
    fn payload(template: &[Prop], values: &[u64], ptr: usize) -> Vec<u8> {
        let mut d = Vec::new();
        for (prop, v) in template.iter().zip(values.iter().chain(std::iter::repeat(&0))) {
            let size = if prop.in_type == TDH_INTYPE_POINTER as u16 { ptr } else { prop.length as usize };
            d.extend_from_slice(&v.to_le_bytes()[..size]);
        }
        d
    }

    fn at(id: u16, ts: i64, ptr_size: usize) -> At {
        At { id, version: if id == EV_REQUEST { 2 } else { 1 }, ts, ptr_size }
    }

    /// Both pointer widths: a 32-bit provider halves both pointers, which moves every field after
    /// the first one. The parse has to land on the same values either way.
    #[test]
    fn a_request_event_is_read_from_its_manifest_template_on_64_and_32_bit() {
        for ptr in [8usize, 4] {
            let tr = trace(true);
            let mut inner = tr.inner.lock().unwrap();
            let fields = field_offsets(&template_201(), wanted_fields(EV_REQUEST), ptr);
            assert!(fields.iter().all(Option::is_some), "{fields:?}");
            let (irp, orig) = if ptr == 8 { (0xFFFF_A08F_1234_5670u64, 0xFFFF_A08F_9999_0000u64) } else { (0x8123_4560, 0x8999_0000) };
            // 1.9 s, READ(10), success, port 6 bus 0 target 1 lun 2, GOOD, 256 KB.
            let values = [19_000_000, irp, 0x28, 0x01, orig, 6, 0, 1, 2, 0x00, 262_144, 11, 12];
            let data = payload(&template_201(), &values, ptr);
            assert_eq!(data.len(), 8 + ptr + 2 + ptr + 5 + 4 + 16);
            handle(&tr, &mut inner, at(EV_REQUEST, ms_to_ticks(5000.0), ptr), Some(&fields), &data);
            let r = *inner.reqs.back().expect("a request");
            assert_eq!((r.irp, r.orig, r.bytes), (irp, orig, 262_144), "ptr {ptr}");
            assert_eq!(r.addr, ScsiAddr { port: 6, bus: 0, target: 1, lun: 2 });
            assert_eq!((r.srb, r.scsi, r.failed()), (0x01, 0x00, false));
            assert!((ticks_to_ms(r.dur) - 1900.0).abs() < 0.01, "{}", ticks_to_ms(r.dur));
            assert_eq!(inner.debug_commands.get(&0x28), Some(&1));
            assert_eq!(inner.debug_status.get(&(0x01, 0x00)), Some(&1));
        }
    }

    #[test]
    fn retries_and_resets_are_read_from_their_templates() {
        let tr = trace(false);
        let mut inner = tr.inner.lock().unwrap();
        let retry = vec![p("Irp", TDH_INTYPE_POINTER, 8), p("CurrentRetryCount", TDH_INTYPE_UINT32, 4)];
        let f = field_offsets(&retry, wanted_fields(EV_RETRY), 8);
        handle(&tr, &mut inner, at(EV_RETRY, 10, 8), Some(&f), &payload(&retry, &[0xAB, 1], 8));
        let f201 = field_offsets(&template_201(), wanted_fields(EV_REQUEST), 8);
        let done = payload(&template_201(), &[100, 0xAB, 0x2A, 0x01, 0, 2, 0, 0, 0, 0, 4096], 8);
        handle(&tr, &mut inner, at(EV_REQUEST, 20, 8), Some(&f201), &done);
        assert_eq!(inner.reqs.back().unwrap().retries, 1, "the retry went to its request");

        let lu = vec![
            p("PortNumber", TDH_INTYPE_UINT32, 4),
            p("PathID", TDH_INTYPE_UINT8, 1),
            p("TargetID", TDH_INTYPE_UINT8, 1),
            p("LUN", TDH_INTYPE_UINT8, 1),
        ];
        let f = field_offsets(&lu, wanted_fields(EV_LU_RESET), 8);
        handle(&tr, &mut inner, at(EV_LU_RESET, 30, 8), Some(&f), &payload(&lu, &[2, 0, 1, 0], 8));
        let detected = vec![
            p("MiniportExtension", TDH_INTYPE_POINTER, 8),
            p("PortNumber", TDH_INTYPE_UINT32, 4),
            p("PauseTime", TDH_INTYPE_UINT32, 4),
        ];
        for ptr in [8usize, 4] {
            let f = field_offsets(&detected, wanted_fields(EV_RESET_DETECTED), ptr);
            handle(&tr, &mut inner, at(EV_RESET_DETECTED, 40, ptr), Some(&f), &payload(&detected, &[0xFFFF_0000, 5, 99], ptr));
        }
        assert_eq!(
            inner.resets[0],
            ResetRec { ts: 30, kind: ResetKind::LogicalUnit, port: 2, bus: Some(0), target: Some(1), lun: Some(0) }
        );
        assert_eq!(inner.resets[1], ResetRec { ts: 40, kind: ResetKind::Detected, port: 5, bus: None, target: None, lun: None });
        assert_eq!(inner.resets[2], inner.resets[1], "the same whatever the pointer width in front");
    }

    #[test]
    fn a_version_whose_layout_is_unknown_is_counted_and_skipped_rather_than_guessed() {
        let tr = trace(true);
        let mut inner = tr.inner.lock().unwrap();
        handle(&tr, &mut inner, At { id: EV_REQUEST, version: 9, ts: 1, ptr_size: 8 }, None, &[0u8; 64]);
        handle(&tr, &mut inner, at(202, 2, 8), None, &[]);
        // A payload cut short of the fields that matter yields nothing rather than zeros.
        let f201 = field_offsets(&template_201(), wanted_fields(EV_REQUEST), 8);
        handle(&tr, &mut inner, at(EV_REQUEST, 3, 8), Some(&f201), &[0u8; 6]);
        assert!(inner.reqs.is_empty(), "nothing was invented");
        assert_eq!(inner.debug_unknown.get(&(EV_REQUEST, 9)), Some(&1));
        assert_eq!(inner.debug_unknown.get(&(202, 1)), Some(&1), "an event the filter should have excluded is still reported");
        assert_eq!(inner.events, 3);
    }
}
