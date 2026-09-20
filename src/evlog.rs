//! Storage trouble Windows itself has written to the System event log: device resets,
//! retried I/O, bad blocks. These are the closest thing to seeing the disk protocol go wrong.

use std::ffi::c_void;
use std::ptr::null_mut;

use windows_sys::Win32::Foundation::{GetLastError, ERROR_INSUFFICIENT_BUFFER};
use windows_sys::Win32::System::EventLog::{
    EvtClose, EvtNext, EvtQuery, EvtQueryChannelPath, EvtQueryForwardDirection, EvtRender, EvtRenderEventXml, EVT_HANDLE,
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
    let ms = days as u64 * 86_400_000;
    // (EventID list) picked for disk/storport/stornvme/NTFS-visible transport trouble; TimeCreated
    // filter is done server-side so we do not have to walk the whole channel.
    let xpath = format!(
        "*[System[(EventID=129 or EventID=153 or EventID=7 or EventID=51 or EventID=11 or EventID=157) and TimeCreated[timediff(@SystemTime) <= {ms}]]]"
    );
    let channel = wide("System");
    let query = wide(&xpath);
    let h = unsafe { EvtQuery(0, channel.as_ptr(), query.as_ptr(), EvtQueryChannelPath | EvtQueryForwardDirection) };
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
        for &raw in &batch[..returned as usize] {
            let event = EvtHandleGuard(raw);
            if let Some(xml) = render_event(event.0) {
                if let Some(ev) = parse_event(&xml) {
                    out.push(ev);
                }
            }
            if out.len() >= 500 {
                break 'outer;
            }
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

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
