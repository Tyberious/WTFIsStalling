//! Trouble Windows itself has written to the System event log. Storage: device resets, retried
//! I/O, bad blocks (the closest thing to seeing the disk protocol go wrong). Hardware (WHEA):
//! corrected memory, CPU and PCI Express errors, which are handled in firmware while the rest of
//! the PC waits, and fatal ones that crashed it.

use std::ffi::c_void;
use std::ptr::null_mut;

use windows_sys::Win32::Foundation::{GetLastError, ERROR_INSUFFICIENT_BUFFER};
use windows_sys::Win32::System::EventLog::{
    EvtClose, EvtNext, EvtQuery, EvtQueryChannelPath, EvtQueryReverseDirection, EvtRender, EvtRenderEventXml, EVT_HANDLE,
};

use crate::util::wide;

/// One storage-related error or warning from the System log.
#[derive(Clone, Debug, PartialEq)]
pub struct StorageEvent {
    /// Seconds since the Unix epoch (UTC).
    pub unix_time: i64,
    pub id: u32,
    /// "disk", "stornvme", "storahci", ...
    pub provider: String,
    /// From `\Device\HarddiskN\...` in the event data; None for controller-level events (129).
    pub disk: Option<u32>,
}

/// Short, plain-English gloss for the event ID, meant for someone who has never seen an event log.
pub fn meaning(id: u32) -> &'static str {
    match id {
        129 => "Windows had to reset the drive's controller because the drive stopped answering",
        153 => "a read or write had to be retried",
        7 => "the drive reported a bad block",
        51 => "an error occurred while paging to or from the drive",
        11 => "the drive's controller reported an error",
        157 => "the drive disconnected unexpectedly",
        _ => "storage error",
    }
}

/// Closes an event or query handle when dropped; 0 is "no handle", never passed to EvtClose.
struct EvtHandleGuard(EVT_HANDLE);

impl Drop for EvtHandleGuard {
    fn drop(&mut self) {
        if self.0 != 0 {
            unsafe { EvtClose(self.0) };
        }
    }
}

/// Storage events from the last `days` days, oldest first. Empty on any failure.
pub fn storage_events(days: u32) -> Vec<StorageEvent> {
    // The ID list is shared with unrelated providers (Time-Service logs a 129 too); parse_event
    // keeps only the storage ones.
    let filter = "(EventID=129 or EventID=153 or EventID=7 or EventID=51 or EventID=11 or EventID=157)";
    query_system(filter, days).iter().filter_map(|xml| parse_event(xml)).collect()
}

/// Hardware errors (WHEA) from the last `days` days, oldest first. Empty on any failure.
pub fn hardware_events(days: u32) -> Vec<HardwareEvent> {
    query_system("Provider[@Name='Microsoft-Windows-WHEA-Logger']", days).iter().filter_map(|xml| parse_whea(xml)).collect()
}

/// XML of the newest (at most 500) System-log events matching `filter` (an XPath condition on the
/// System element), returned oldest first. The time filter runs server-side, so the channel is
/// not walked end to end.
fn query_system(filter: &str, days: u32) -> Vec<String> {
    let ms = days as u64 * 86_400_000;
    let xpath = format!("*[System[{filter} and TimeCreated[timediff(@SystemTime) <= {ms}]]]");
    let channel = wide("System");
    let query = wide(&xpath);
    // Newest first, so that when a device floods the log the cap drops the oldest entries.
    let h = unsafe { EvtQuery(0, channel.as_ptr(), query.as_ptr(), EvtQueryChannelPath | EvtQueryReverseDirection) };
    if h == 0 {
        return Vec::new();
    }
    let query_handle = EvtHandleGuard(h);

    let mut out = Vec::new();
    let mut batch: [EVT_HANDLE; 16] = [0; 16];
    'outer: loop {
        let mut returned = 0u32;
        let ok = unsafe { EvtNext(query_handle.0, batch.len() as u32, batch.as_mut_ptr(), 1000, 0, &mut returned) };
        if ok == 0 || returned == 0 {
            break;
        }
        // Every handle in the batch must be closed, so wrap them all before any early exit.
        let events: Vec<EvtHandleGuard> = batch[..returned as usize].iter().map(|&raw| EvtHandleGuard(raw)).collect();
        for event in &events {
            if let Some(xml) = render_event(event.0) {
                out.push(xml);
            }
            if out.len() >= 500 {
                break 'outer;
            }
        }
    }
    out.reverse();
    out
}

/// Renders one event as XML. Two-call dance: first asks for the size, then fills a buffer of it.
fn render_event(h: EVT_HANDLE) -> Option<String> {
    let mut used = 0u32;
    let mut count = 0u32;
    let ok = unsafe { EvtRender(0, h, EvtRenderEventXml, 0, null_mut(), &mut used, &mut count) };
    if ok != 0 || used == 0 {
        return None;
    }
    if unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER {
        return None;
    }
    // `used` is a byte count; the buffer is UTF-16, so it holds used/2 u16 code units (rounded up).
    let mut buf = vec![0u16; used as usize / 2 + 1];
    let bufsize = (buf.len() * 2) as u32;
    let ok = unsafe { EvtRender(0, h, EvtRenderEventXml, bufsize, buf.as_mut_ptr() as *mut c_void, &mut used, &mut count) };
    if ok == 0 {
        return None;
    }
    let len = (used as usize / 2).min(buf.len());
    Some(String::from_utf16_lossy(&buf[..len]).trim_end_matches('\0').to_string())
}

/// Byte offset of the first case-insensitive match of `needle` in `haystack`, or None.
/// ASCII-only comparison, so byte offsets from the original (mixed-case) string stay valid.
fn find_ci(haystack: &str, needle: &str) -> Option<usize> {
    let h = haystack.as_bytes();
    let n = needle.as_bytes();
    if n.is_empty() || n.len() > h.len() {
        return None;
    }
    (0..=h.len() - n.len()).find(|&i| h[i..i + n.len()].eq_ignore_ascii_case(n))
}

/// Value of `name='...'` or `name="..."` inside `s` (meant to be called on a short slice, e.g.
/// one element's opening tag, so it cannot wander into an unrelated attribute of the same name).
fn attr(s: &str, name: &str) -> Option<String> {
    let idx = find_ci(s, &format!("{name}="))?;
    let after = idx + name.len() + 1;
    let quote = *s.as_bytes().get(after)?;
    if quote != b'\'' && quote != b'"' {
        return None;
    }
    let start = after + 1;
    let end_rel = s[start..].find(quote as char)?;
    Some(s[start..start + end_rel].to_string())
}

/// Attribute of the first `<tag ...>` (or `<tag/>`) found anywhere in `xml`.
fn tag_attr(xml: &str, tag: &str, attr_name: &str) -> Option<String> {
    let open = find_ci(xml, &format!("<{tag}"))?;
    let rest = &xml[open..];
    let end = rest.find('>').unwrap_or(rest.len());
    attr(&rest[..end], attr_name)
}

/// Text between `<tag ...>` and the matching `</tag>`.
fn tag_text(xml: &str, tag: &str) -> Option<String> {
    let open = find_ci(xml, &format!("<{tag}"))?;
    let gt_rel = xml[open..].find('>')?;
    let content_start = open + gt_rel + 1;
    let close_rel = find_ci(&xml[content_start..], &format!("</{tag}>"))?;
    Some(xml[content_start..content_start + close_rel].to_string())
}

/// Disk number following the first `\Device\HarddiskN` anywhere in the XML.
fn disk_number(xml: &str) -> Option<u32> {
    let idx = find_ci(xml, r"\Device\Harddisk")?;
    let start = idx + r"\Device\Harddisk".len();
    let digits: String = xml[start..].chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().ok()
}

/// Days since 1970-01-01 for a proleptic Gregorian civil date (Howard Hinnant's algorithm).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let mp = (m + 9) % 12; // [0, 11]: Mar=0 .. Feb=11
    let doy = (153 * mp + 2) / 5 + d - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146097 + doe - 719468
}

/// Parses `YYYY-MM-DDTHH:MM:SS[.fraction]Z` (what EvtRender emits for TimeCreated) to Unix seconds.
fn parse_iso(s: &str) -> Option<i64> {
    if s.len() < 19 {
        return None;
    }
    let year: i64 = s.get(0..4)?.parse().ok()?;
    let month: i64 = s.get(5..7)?.parse().ok()?;
    let day: i64 = s.get(8..10)?.parse().ok()?;
    let hour: i64 = s.get(11..13)?.parse().ok()?;
    let min: i64 = s.get(14..16)?.parse().ok()?;
    let sec: i64 = s.get(17..19)?.parse().ok()?;
    let days = days_from_civil(year, month, day);
    Some(days * 86_400 + hour * 3600 + min * 60 + sec)
}

/// Parses one EvtRender EventXml document into a `StorageEvent`, filtering out providers that
/// reuse the same event IDs for unrelated things (e.g. Time-Service also logs a 129).
fn parse_event(xml: &str) -> Option<StorageEvent> {
    let provider = tag_attr(xml, "Provider", "Name")?;
    let id: u32 = tag_text(xml, "EventID")?.trim().parse().ok()?;
    let time_str = tag_attr(xml, "TimeCreated", "SystemTime")?;
    let unix_time = parse_iso(&time_str)?;
    let disk = disk_number(xml);

    let is_disk_provider = provider.eq_ignore_ascii_case("disk");
    let is_storage_controller_129 =
        id == 129 && [r"\Device\RaidPort", r"\Device\Scsi", r"\Device\Ide"].iter().any(|n| find_ci(xml, n).is_some());
    if !is_disk_provider && !is_storage_controller_129 {
        return None;
    }
    Some(StorageEvent { unix_time, id, provider, disk })
}

/// What kind of hardware a WHEA event is about.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HardwareKind {
    /// The PC crashed or reset because of a hardware error (events 1, 18, 20, 46).
    Fatal,
    /// Corrected memory error (47).
    Memory,
    /// Corrected machine check: CPU cache, bus or interconnect (19).
    Processor,
    /// Corrected PCI Express error (17).
    PciExpress,
    Other,
}

/// Where on the PCI bus an event 17 points.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PciRef {
    pub bus: u32,
    pub device: u32,
    pub function: u32,
    /// For a bridge or root port: the bus behind it, where the actual card sits.
    pub secondary_bus: Option<u32>,
    /// `PCI\VEN_10DE&DEV_2684...` when Windows recorded it.
    pub hardware_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct HardwareEvent {
    pub unix_time: i64,
    pub id: u32,
    pub kind: HardwareKind,
    /// Logical processor (APIC ID) that reported a machine check.
    pub apic_id: Option<u32>,
    pub pci: Option<PciRef>,
}

/// Text of `<Data Name='name'>...</Data>`, name matched case-insensitively.
fn data_named(xml: &str, name: &str) -> Option<String> {
    let mut from = 0;
    while let Some(rel) = find_ci(&xml[from..], "<Data ") {
        let open = from + rel;
        let gt = open + xml[open..].find('>')?;
        let tag = &xml[open..gt];
        if attr(tag, "Name").is_some_and(|n| n.eq_ignore_ascii_case(name)) {
            if tag.ends_with('/') {
                return None;
            }
            let close = find_ci(&xml[gt + 1..], "</Data>")?;
            return Some(xml[gt + 1..gt + 1 + close].trim().to_string());
        }
        from = gt + 1;
    }
    None
}

/// "0x1f", "0X1F" or "31".
fn number(s: &str) -> Option<u32> {
    let s = s.trim();
    match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(hex) => u32::from_str_radix(hex, 16).ok(),
        None => s.parse().ok(),
    }
}

/// Field names differ between Windows builds, so each value is looked up under every name seen.
fn parse_whea(xml: &str) -> Option<HardwareEvent> {
    let provider = tag_attr(xml, "Provider", "Name")?;
    if !provider.eq_ignore_ascii_case("Microsoft-Windows-WHEA-Logger") {
        return None;
    }
    let id: u32 = tag_text(xml, "EventID")?.trim().parse().ok()?;
    let unix_time = parse_iso(&tag_attr(xml, "TimeCreated", "SystemTime")?)?;
    let kind = match id {
        1 | 18 | 20 | 46 => HardwareKind::Fatal,
        47 => HardwareKind::Memory,
        19 => HardwareKind::Processor,
        17 => HardwareKind::PciExpress,
        _ => HardwareKind::Other,
    };
    let first = |names: &[&str]| names.iter().find_map(|n| data_named(xml, n));
    let num = |names: &[&str]| first(names).and_then(|v| number(&v));
    let pci = (kind == HardwareKind::PciExpress)
        .then(|| {
            Some(PciRef {
                bus: num(&["PrimaryBusNumber", "Bus", "BusNumber"])?,
                device: num(&["PrimaryDeviceNumber", "Device", "DeviceNumber"])?,
                function: num(&["PrimaryFunctionNumber", "Function", "FunctionNumber"])?,
                secondary_bus: num(&["SecondaryBusNumber", "SecondaryBus"]).filter(|b| *b != 0),
                hardware_id: first(&["PrimaryDeviceName", "DeviceName"]).map(|v| v.replace("&amp;", "&")).filter(|v| !v.is_empty()),
            })
        })
        .flatten();
    let apic_id = if matches!(kind, HardwareKind::Processor | HardwareKind::Fatal) { num(&["ApicId", "ProcessorApicId"]) } else { None };
    Some(HardwareEvent { unix_time, id, kind, apic_id, pci })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn whea(id: u32, data: &str) -> String {
        format!(
            "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-WHEA-Logger' \
             Guid='{{c26c4f3c-3f66-4e99-8f8a-39405cfed220}}'/><EventID>{id}</EventID><TimeCreated \
             SystemTime='2026-09-18T03:12:45.1234567Z'/><Channel>System</Channel></System><EventData>{data}</EventData></Event>"
        )
    }

    #[test]
    fn whea_pcie_event_yields_the_bus_address_and_hardware_id() {
        let xml = whea(
            17,
            "<Data Name='ErrorSource'>4</Data><Data Name='FRUText'/><Data Name='PrimaryBusNumber'>0x0</Data><Data \
             Name='PrimaryDeviceNumber'>0x1</Data><Data Name='PrimaryFunctionNumber'>0x1</Data><Data \
             Name='SecondaryBusNumber'>0x1</Data><Data Name='PrimaryDeviceName'>PCI\\VEN_1022&amp;DEV_14DB&amp;SUBSYS_1</Data>",
        );
        let ev = parse_whea(&xml).unwrap();
        assert_eq!((ev.id, ev.kind, ev.unix_time), (17, HardwareKind::PciExpress, 1_789_701_165));
        let pci = ev.pci.unwrap();
        assert_eq!((pci.bus, pci.device, pci.function, pci.secondary_bus), (0, 1, 1, Some(1)));
        assert_eq!(pci.hardware_id.as_deref(), Some(r"PCI\VEN_1022&DEV_14DB&SUBSYS_1"));
    }

    #[test]
    fn whea_kinds_and_processor_ids() {
        let cpu = parse_whea(&whea(19, "<Data Name=\"ErrorSource\">1</Data><Data Name=\"ApicId\">0xb</Data>")).unwrap();
        assert_eq!((cpu.kind, cpu.apic_id, cpu.pci), (HardwareKind::Processor, Some(11), None));
        assert_eq!(parse_whea(&whea(47, "")).unwrap().kind, HardwareKind::Memory);
        assert_eq!(parse_whea(&whea(18, "<Data Name='ApicId'>4</Data>")).unwrap().kind, HardwareKind::Fatal);
        assert_eq!(parse_whea(&whea(1, "")).unwrap().kind, HardwareKind::Fatal);
        // A PCIe event without an address is still counted.
        assert_eq!(parse_whea(&whea(17, "")).unwrap().pci, None);
        // Not WHEA: ignored even with a matching ID.
        assert!(parse_whea(DISK_153_SINGLE).is_none());
        assert_eq!((number("0x1F"), number("31"), number("zz")), (Some(31), Some(31), None));
    }

    #[test]
    fn hardware_events_live_query_does_not_panic() {
        println!("hardware_events(7): {} events", hardware_events(7).len());
    }

    const DISK_153_SINGLE: &str = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='disk'/><EventID Qualifiers='32772'>153</EventID><Version>0</Version><Level>3</Level><Task>0</Task><Opcode>0</Opcode><Keywords>0x8080000000000000</Keywords><TimeCreated SystemTime='2026-09-18T03:12:45.1234567Z'/><EventRecordID>12345</EventRecordID><Correlation/><Execution ProcessID='4' ThreadID='8'/><Channel>System</Channel><Computer>DESKTOP-TEST</Computer><Security/></System><EventData><Data>\Device\Harddisk2\DR2</Data></EventData></Event>"#;

    #[test]
    fn parses_disk_153_with_single_quotes() {
        let ev = parse_event(DISK_153_SINGLE).unwrap();
        assert_eq!(ev, StorageEvent { unix_time: 1_789_701_165, id: 153, provider: "disk".into(), disk: Some(2) });
    }

    #[test]
    fn parses_disk_153_with_double_quotes() {
        let xml = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="disk"/><EventID Qualifiers="32772">153</EventID><TimeCreated SystemTime="2026-09-18T03:12:45.1234567Z"/><Channel>System</Channel></System><EventData><Data>\Device\Harddisk2\DR2</Data></EventData></Event>"#;
        let ev = parse_event(xml).unwrap();
        assert_eq!(ev, StorageEvent { unix_time: 1_789_701_165, id: 153, provider: "disk".into(), disk: Some(2) });
    }

    #[test]
    fn keeps_stornvme_129_with_raidport() {
        let xml = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='stornvme'/><EventID Qualifiers='16384'>129</EventID><TimeCreated SystemTime='2026-09-18T03:12:45.0000000Z'/><Channel>System</Channel></System><EventData><Data>\Device\RaidPort1</Data></EventData></Event>"#;
        let ev = parse_event(xml).unwrap();
        assert_eq!(ev.provider, "stornvme");
        assert_eq!(ev.id, 129);
        assert_eq!(ev.disk, None);
    }

    #[test]
    fn drops_time_service_129() {
        let xml = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Time-Service'/><EventID Qualifiers='0'>129</EventID><TimeCreated SystemTime='2026-09-18T03:12:45.0000000Z'/><Channel>System</Channel></System><EventData></EventData></Event>"#;
        assert!(parse_event(xml).is_none());
    }

    #[test]
    fn garbage_does_not_panic() {
        assert!(parse_event("not xml at all").is_none());
        assert!(parse_event("").is_none());
    }

    #[test]
    fn days_from_civil_epoch_and_leap_year() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2024, 2, 29), 19782); // 2024 is a leap year
    }

    #[test]
    fn meaning_covers_known_and_unknown_ids() {
        assert!(meaning(129).contains("controller"));
        assert_eq!(meaning(999), "storage error");
    }

    #[test]
    fn live_storage_events_do_not_panic() {
        // Live read; works without admin (EvtQuery on the System channel is readable by everyone).
        let events = storage_events(7);
        println!("storage_events(7): {} event(s)", events.len());
        for ev in &events {
            println!("  id={} provider={}", ev.id, ev.provider);
        }
    }
}
