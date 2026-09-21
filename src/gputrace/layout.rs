//! Where each field of a manifest event sits in its payload, worked out once per (event id,
//! version) and then reused.
//!
//! A manifest event's payload is the fields written one after another with no padding, so the
//! offset of a field is the sum of the sizes of the fields in front of it. `TdhGetEventInformation`
//! is what says what those fields are; calling it per event would be far too expensive in an ETW
//! callback, so it is called once per (event id, version) and only the offsets are kept.
//!
//! Nothing here guesses. A field whose size depends on the payload (a string, an array, a
//! structure) ends the walk, and any event whose wanted fields could not all be placed is skipped
//! and counted under `--debug` instead.
//!
//! https://learn.microsoft.com/en-us/windows/win32/api/tdh/nf-tdh-tdhgeteventinformation
//! https://learn.microsoft.com/en-us/windows/win32/api/tdh/ns-tdh-event_property_info

use std::mem::size_of;

use windows_sys::Win32::System::Diagnostics::Etw::{
    PropertyParamCount, PropertyParamLength, PropertyStruct, TdhGetEventInformation, EVENT_HEADER_FLAG_32_BIT_HEADER, EVENT_RECORD,
    TDH_INTYPE_POINTER, TRACE_EVENT_INFO,
};

/// Where one wanted field is and how wide it is.
pub type Field = (usize, usize);
/// One entry per name asked for, in the order asked for.
pub type Fields = Vec<Option<Field>>;

/// One top-level property of an event, as TDH describes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Prop {
    pub name: String,
    /// `EVENT_PROPERTY_INFO::InType`, a `TDH_INTYPE_*` value.
    pub in_type: u16,
    /// `EVENT_PROPERTY_INFO::length`: the size in bytes of a fixed-size property, 0 otherwise.
    pub length: u16,
    /// Set when the property's size depends on the payload: a structure, an array, or a length
    /// taken from another property. Nothing after such a property has a fixed offset.
    pub variable: bool,
}

/// Offsets of `wanted` within the payload, or `None` for any that could not be placed.
/// `ptr_size` is the pointer width of the machine the event was logged on.
pub fn field_offsets(props: &[Prop], wanted: &[&str], ptr_size: usize) -> Fields {
    let mut out: Fields = vec![None; wanted.len()];
    let mut offset = 0usize;
    for p in props {
        if p.variable {
            break; // everything after this moves with the payload
        }
        // A pointer is as wide as the machine that logged the event, which the event header says.
        // Every other fixed-size type states its own width.
        let size = if p.in_type == TDH_INTYPE_POINTER as u16 { ptr_size } else { p.length as usize };
        if size == 0 {
            break;
        }
        if let Some(i) = wanted.iter().position(|w| *w == p.name) {
            out[i] = Some((offset, size));
        }
        offset += size;
        if out.iter().all(Option::is_some) {
            break;
        }
    }
    out
}

/// Reads `TRACE_EVENT_INFO` for one event and turns its top-level properties into `Prop`s.
/// `None` when TDH has no schema for the event, which is what happens on a Windows whose
/// dxgkrnl.sys manifest does not describe this version.
///
/// # Safety
/// `rec` must be the event record ETW handed to the callback.
pub unsafe fn describe(rec: *const EVENT_RECORD, buf: &mut Vec<u8>) -> Option<Vec<Prop>> {
    let mut size = buf.len() as u32;
    if size == 0 {
        buf.resize(4096, 0);
        size = buf.len() as u32;
    }
    let mut rc = TdhGetEventInformation(rec, 0, std::ptr::null(), buf.as_mut_ptr() as *mut TRACE_EVENT_INFO, &mut size);
    if rc == 122 {
        // ERROR_INSUFFICIENT_BUFFER: `size` now holds what is needed.
        buf.resize(size as usize, 0);
        rc = TdhGetEventInformation(rec, 0, std::ptr::null(), buf.as_mut_ptr() as *mut TRACE_EVENT_INFO, &mut size);
    }
    if rc != 0 {
        return None;
    }
    let info = &*(buf.as_ptr() as *const TRACE_EVENT_INFO);
    let count = info.TopLevelPropertyCount as usize;
    // Sanity: the array has to fit inside the buffer TDH just filled in.
    let base = buf.as_ptr();
    let array = info.EventPropertyInfoArray.as_ptr();
    let elem = size_of::<windows_sys::Win32::System::Diagnostics::Etw::EVENT_PROPERTY_INFO>();
    let used = (array as usize - base as usize) + count * elem;
    if count == 0 || used > size as usize {
        return None;
    }
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let p = &*array.add(i);
        // The name is a null-terminated UTF-16 string at NameOffset from the start of the struct.
        let name = wide_at(buf, p.NameOffset as usize, size as usize)?;
        let variable = p.Flags & (PropertyStruct | PropertyParamLength | PropertyParamCount) != 0 || p.Anonymous2.count != 1;
        out.push(Prop { name, in_type: p.Anonymous1.nonStructType.InType, length: p.Anonymous3.length, variable });
    }
    Some(out)
}

/// A null-terminated UTF-16 string at `offset` inside the TDH buffer.
fn wide_at(buf: &[u8], offset: usize, limit: usize) -> Option<String> {
    let tail = buf.get(offset..limit.min(buf.len()))?;
    let mut units = Vec::new();
    for pair in tail.chunks(2) {
        if pair.len() < 2 {
            break;
        }
        let u = u16::from_le_bytes([pair[0], pair[1]]);
        if u == 0 || units.len() >= 128 {
            break;
        }
        units.push(u);
    }
    Some(String::from_utf16_lossy(&units))
}

/// Pointer width, in bytes, of the machine that logged an event.
/// `EVENT_HEADER_FLAG_32_BIT_HEADER` means "the provider is running on a 32-bit computer or is a
/// 32-bit process"; the 64-bit flag is its counterpart.
/// https://learn.microsoft.com/en-us/windows/win32/api/evntcons/ns-evntcons-event_header
pub fn pointer_size(flags: u16) -> usize {
    if flags as u32 & EVENT_HEADER_FLAG_32_BIT_HEADER != 0 {
        4
    } else {
        8
    }
}

/// An unsigned integer of 1, 2, 4 or 8 bytes at `field`, or `None` if the payload is too short.
pub fn read_uint(data: &[u8], field: Option<Field>) -> Option<u64> {
    let (off, size) = field?;
    let b = data.get(off..off + size)?;
    Some(match size {
        1 => b[0] as u64,
        2 => u16::from_le_bytes(b.try_into().ok()?) as u64,
        4 => u32::from_le_bytes(b.try_into().ok()?) as u64,
        8 => u64::from_le_bytes(b.try_into().ok()?),
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::System::Diagnostics::Etw::{TDH_INTYPE_BOOLEAN, TDH_INTYPE_UINT32, TDH_INTYPE_UINT64};

    fn p(name: &str, in_type: i32, length: u16) -> Prop {
        Prop { name: name.into(), in_type: in_type as u16, length, variable: false }
    }

    fn ptr(name: &str) -> Prop {
        Prop { name: name.into(), in_type: TDH_INTYPE_POINTER as u16, length: 8, variable: false }
    }

    /// Microsoft-Windows-DxgKrnl event 184 (Present) version 1, exactly as the provider manifest
    /// on this machine declares it.
    fn present_v1() -> Vec<Prop> {
        vec![
            p("hContext", TDH_INTYPE_UINT32, 4),
            ptr("hWindow"),
            p("VidPnSourceId", TDH_INTYPE_UINT32, 4),
            p("FlipInterval", TDH_INTYPE_UINT32, 4),
            p("Flags", TDH_INTYPE_UINT32, 4),
            p("ReturnStatus", TDH_INTYPE_UINT32, 4),
            ptr("hSrcAllocHandle"),
            ptr("hDstAllocHandle"),
        ]
    }

    #[test]
    fn offsets_follow_the_packed_layout_and_the_machines_pointer_width() {
        let want = ["VidPnSourceId", "ReturnStatus"];
        assert_eq!(field_offsets(&present_v1(), &want, 8), vec![Some((12, 4)), Some((24, 4))]);
        // The same event logged by a 32-bit provider: every pointer in front of it is half as wide.
        assert_eq!(field_offsets(&present_v1(), &want, 4), vec![Some((8, 4)), Some((20, 4))]);
    }

    /// Event 339 (MakeResident stop) version 0 and event 338 (start) version 0.
    #[test]
    fn residency_fields_are_placed_from_the_manifest_declaration() {
        let stop =
            vec![p("Status", TDH_INTYPE_UINT32, 4), p("NumBytesToTrim", TDH_INTYPE_UINT64, 8), p("PagingFenceValue", TDH_INTYPE_UINT64, 8)];
        assert_eq!(field_offsets(&stop, &["Status", "NumBytesToTrim"], 8), vec![Some((0, 4)), Some((4, 8))]);
        let start =
            vec![ptr("pPagingQueue"), ptr("pSyncObject"), p("NumAllocations", TDH_INTYPE_UINT32, 4), p("Flags", TDH_INTYPE_UINT32, 4)];
        assert_eq!(field_offsets(&start, &["NumAllocations"], 8), vec![Some((16, 4))]);
        assert_eq!(field_offsets(&start, &["NumAllocations"], 4), vec![Some((8, 4))]);
    }

    /// Event 273 (VSyncDPCMultiPlane) version 4 puts a counted array second, so nothing after it
    /// has a fixed offset. The answer has to be "cannot place it", never a guess.
    #[test]
    fn a_counted_array_ends_the_walk_rather_than_being_guessed_past() {
        let props = vec![
            ptr("pDxgAdapter"),
            p("PlaneCount", TDH_INTYPE_UINT32, 4),
            Prop { name: "PresentIdOrPhysicalAddress".into(), in_type: TDH_INTYPE_UINT64 as u16, length: 8, variable: true },
            p("VidPnSourceId", TDH_INTYPE_UINT32, 4),
            p("FrameNumber", TDH_INTYPE_UINT32, 4),
        ];
        let got = field_offsets(&props, &["PlaneCount", "VidPnSourceId", "FrameNumber"], 8);
        assert_eq!(got, vec![Some((8, 4)), None, None]);
        // A field of unknown width does the same.
        let unknown = vec![p("Name", TDH_INTYPE_UINT32, 0), p("After", TDH_INTYPE_UINT32, 4)];
        assert_eq!(field_offsets(&unknown, &["After"], 8), vec![None]);
        // A name that is not in this version at all is simply not found.
        assert_eq!(field_offsets(&present_v1(), &["NoSuchField"], 8), vec![None]);
    }

    #[test]
    fn values_are_read_at_the_resolved_offsets_and_short_payloads_are_refused() {
        let mut payload = vec![0u8; 32];
        payload[0..4].copy_from_slice(&0xC000_0017u32.to_le_bytes()); // Status
        payload[4..12].copy_from_slice(&600_000_000u64.to_le_bytes()); // NumBytesToTrim
        assert_eq!(read_uint(&payload, Some((0, 4))), Some(0xC000_0017));
        assert_eq!(read_uint(&payload, Some((4, 8))), Some(600_000_000));
        assert_eq!(read_uint(&payload, None), None);
        assert_eq!(read_uint(&payload[..6], Some((4, 8))), None, "a truncated payload yields nothing, never a panic");
        assert_eq!(read_uint(&payload, Some((0, 3))), None, "an odd width is refused rather than pieced together");
        // A one-byte boolean-looking field still reads.
        let one = [7u8];
        assert_eq!(read_uint(&one, Some((0, 1))), Some(7));
        let _ = TDH_INTYPE_BOOLEAN;
    }

    #[test]
    fn the_pointer_width_comes_from_the_event_header_flag() {
        assert_eq!(pointer_size(EVENT_HEADER_FLAG_32_BIT_HEADER as u16), 4);
        assert_eq!(pointer_size(0x40), 8, "the 64-bit flag");
        assert_eq!(pointer_size(0), 8, "and 64-bit is the assumption when neither is set");
    }
}
