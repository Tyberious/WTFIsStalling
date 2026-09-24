//! A second real-time ETW session on the graphics kernel, for the one thing a CPU-side trace
//! cannot otherwise see: whether the picture actually stopped updating, and whether video memory
//! was over budget at that moment.
//!
//! The kernel logger in `etw` is a system logger and cannot carry a manifest provider, so this is
//! its own session ("WTFIsStallingGpuSession") on the same QPC clock, with
//! Microsoft-Windows-DxgKrnl enabled through `EnableTraceEx2`. The session itself (lifetime,
//! stale-session takeover, event-id filter, consumer thread) is `etw::manifest`, shared with the
//! storage-port trace; the callback is wrapped in `catch_unwind` and a poisoned lock tolerated.
//!
//! Everything here is optional. If the session cannot start the run carries on and the report
//! says in one line that GPU evidence was not available.

mod events;

use std::collections::{HashMap, VecDeque};
use std::mem::{size_of, zeroed};
use std::ptr::null;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use windows_sys::core::GUID;
use windows_sys::Win32::System::Diagnostics::Etw::TRACE_LEVEL_INFORMATION;

use crate::etw::manifest;
pub use crate::etw::manifest::Session;
use crate::util::{ms_to_ticks, qpc, ticks_to_ms};

const SESSION_NAME: &str = "WTFIsStallingGpuSession";

/// Microsoft-Windows-DxgKrnl, the graphics kernel (dxgkrnl.sys). The GUID is the one the live
/// system reports for it (`logman query providers Microsoft-Windows-DxgKrnl`) and the one
/// PresentMon uses: https://github.com/GameTechDev/PresentMon (PresentData/ETW/Microsoft_Windows_DxgKrnl.h)
const DXGKRNL_GUID: GUID = GUID::from_u128(0x802ec45a_1e99_4b83_9920_87c98277ba9d);

/// The provider's `Present` keyword, from this machine's own manifest
/// (`logman query providers Microsoft-Windows-DxgKrnl` lists `0x0000000008000000  Present`) and
/// from PresentMon's generated header, which gives `Keyword::Present = 0x8000000`.
///
/// This is the ONLY keyword asked for, and that is deliberate. The events below that are not
/// under `Present` live under `Base`, which dxgkrnl also uses for every DMA packet and every
/// queue packet on the machine - thousands of events a second in a game. Microsoft's own note on
/// `EnableTraceEx2` is why that matters: filtering by event id "is only effective in reducing
/// trace data volume and is not as effective for reducing trace CPU overhead", i.e. the provider
/// would still build every one of those events even though this session throws them away.
/// https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-enabletraceex2
///
/// The cost of that choice: PresentMon's `PatchPreWin11Keyword` records that Windows 11 ADDED the
/// `Present` keyword to VSyncDPC, VSyncDPCMultiPlane and HSyncDPCMultiPlane, so on Windows 10
/// those three arrive only under `Base` and this session sees no display-refresh ticks at all.
/// The report says so rather than concluding anything from an empty stream.
const KEYWORD_PRESENT: u64 = 0x0800_0000;

// ---- the events this session asks for. Every id, version and field below was read from this
// machine's own copy of the provider manifest:
//     (Get-WinEvent -ListProvider Microsoft-Windows-DxgKrnl).Events
// which gives each event's id, version, task, keywords and its template (field names and types).
// The ids and versions are corroborated by PresentMon's generated header
// https://github.com/GameTechDev/PresentMon/blob/main/PresentData/ETW/Microsoft_Windows_DxgKrnl.h
// (VSyncDPC_Info 0x0011 v0, VSyncDPCMultiPlane_Info 0x0111 v4, HSyncDPCMultiPlane_Info 0x017e v2,
// Present_Info 0x00b8 v1), which is MIT-licensed and was read, not copied.

/// VSyncDPC: the graphics driver's vertical-blank DPC, one per refresh of a display.
const EV_VSYNC: u16 = 17;
/// VSyncDPCMultiPlane: the same thing on the multi-plane-overlay path, which is what a
/// full-screen game on Windows 10/11 normally uses.
const EV_VSYNC_MULTIPLANE: u16 = 273;
/// HSyncDPCMultiPlane: the hardware-flip-queue path, used with variable refresh rate.
const EV_HSYNC_MULTIPLANE: u16 = 382;
/// Present: one per present submitted to the graphics kernel, logged in the calling process.
const EV_PRESENT: u16 = 184;
/// MakeResident start/stop: bringing allocations back into video memory. The stop event carries
/// `NumBytesToTrim`, which is how much Windows wants freed because the card is over budget.
const EV_RESIDENT_START: u16 = 338;
const EV_RESIDENT_STOP: u16 = 339;

/// The event-id scope filter handed to `EnableTraceEx2`. At most
/// `MAX_EVENT_FILTER_EVENT_ID_COUNT` (64) ids are allowed; this uses six.
/// https://learn.microsoft.com/en-us/windows/win32/api/evntprov/ns-evntprov-event_filter_event_id
const WANTED: [u16; 6] = [EV_VSYNC, EV_VSYNC_MULTIPLANE, EV_HSYNC_MULTIPLANE, EV_PRESENT, EV_RESIDENT_START, EV_RESIDENT_STOP];

/// How much history the rings keep, in ms of trace time. A flagged moment looks 3 s back and
/// 0.3 s forward and is analyzed once the trace has caught up past its end, so 3.3 s has to
/// still be there; 10 s is that with headroom, and no more, because presents are the one class
/// here that a fast game produces in bulk.
pub const GPU_KEEP_MS: f64 = 10_000.0;

/// One present submitted to the graphics kernel. 16 bytes: this is the ring that grows fastest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PresentRec {
    pub ts: i64,
    /// The process the event was logged in, i.e. the program that asked for the frame.
    pub pid: u32,
    /// `VidPnSourceId`: which display output the frame is for.
    pub source: u32,
}

/// One "make these allocations resident in video memory" operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResidentRec {
    pub ts: i64,
    /// Start to stop, in QPC ticks; 0 when the start was not seen.
    pub dur: i64,
    /// `NumBytesToTrim`: how much video memory Windows wants freed. Non-zero means over budget.
    pub trim: u64,
    pub pid: u32,
    /// `Status` was not STATUS_SUCCESS: the allocations could not be made resident.
    pub failed: bool,
}

/// What the GPU trace saw over a whole run. Plain numbers, so the summary and its tests need no
/// live session.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct GpuTraceTotals {
    /// False when the session never ran; every other field is then meaningless.
    pub available: bool,
    pub events: u64,
    pub refresh_ticks: u64,
    pub presents: u64,
    pub residency_ops: u64,
    pub residency_ms: f64,
    /// Residency operations that came back with video memory over budget.
    pub trim_events: u64,
    pub trim_max_bytes: u64,
    pub residency_failed: u64,
}

/// Everything the GPU trace hands the summary once a run is over. Plain owned data, so the
/// summary and its tests never need a live session.
#[derive(Clone, Debug, Default)]
pub struct GpuTraceReport {
    pub totals: GpuTraceTotals,
    /// Why there is no GPU evidence, in one line for DETAILS. `None` when there is.
    pub note: Option<String>,
    /// --debug only: how many of each (event id, version) arrived...
    pub debug_counts: Vec<((u16, u8), u64)>,
    /// ...and which ones this build could not read, which is what an elevated run has to check.
    pub debug_unknown: Vec<((u16, u8), u64)>,
}

#[derive(Default)]
pub struct GpuInner {
    pub events: u64,
    pub latest_ts: i64,
    last_prune: i64,

    /// Display refresh DPCs, timestamps only: which display and which frame is not needed to see
    /// that the picture stopped, and the multi-plane versions put arrays in front of every other
    /// field, so nothing past the first one can be read at a fixed offset anyway.
    pub refresh: VecDeque<i64>,
    pub presents: VecDeque<PresentRec>,
    pub residency: VecDeque<ResidentRec>,

    /// Trace time of the newest record each count cap threw away. Everything after it is whole,
    /// so an overflow only disqualifies windows that reach back into it (the lesson from the
    /// thread-switch rings, which used one fixed cap and lost the whole run on a 32-CPU PC).
    pub refresh_lost_until: Option<i64>,
    pub present_lost_until: Option<i64>,
    pub residency_lost_until: Option<i64>,

    pub refresh_cap: usize,
    pub present_cap: usize,
    pub residency_cap: usize,

    pub totals: GpuTraceTotals,

    /// Open MakeResident operations by thread, so the stop event can be given a duration.
    starts: HashMap<u32, (i64, u32)>,

    /// Property offsets worked out once per (event id, version) and then reused; `None` means
    /// that version's layout could not be worked out and its events are skipped, never guessed.
    layouts: manifest::LayoutCache,

    /// --debug only: every (event id, version) seen, and the ones not understood.
    pub debug_counts: HashMap<(u16, u8), u64>,
    pub debug_unknown: HashMap<(u16, u8), u64>,
}

pub struct GpuTrace {
    pub inner: Mutex<GpuInner>,
    pub debug: bool,
}

// ---- ring sizes -----------------------------------------------------------------------------
//
// The thread-switch rings were once sized from an assumed per-second rate and overflowed
// instantly on a bigger machine than the one they were sized on. Two of the three rates here
// CAN be bounded from something real, and the third is given a bound plus a ceiling; whatever
// happens, an overflow only costs the windows it actually reaches into.

/// Refresh ticks come at the display's refresh rate, which is readable without administrator
/// rights, so this ring is sized from the displays actually attached. Three times the measured
/// rate leaves room for the multi-plane and hardware-flip-queue paths firing alongside the plain
/// vertical-blank DPC.
const REFRESH_HEADROOM: usize = 3;
/// ...with a floor for the case where no refresh rate could be read at all.
const REFRESH_HZ_FLOOR: usize = 500;
const REFRESH_CAP_MAX: usize = 500_000;

/// Presents cannot be measured before the session starts. This is a bound, not a measurement: a
/// game presenting with no frame-rate cap, the desktop compositor, a video player and a browser
/// together are nowhere near 8,000 frames a second.
const PRESENTS_PER_SECOND: usize = 8_000;
const PRESENT_CAP_MAX: usize = 600_000;
/// Residency operations are bursty rather than steady; this is the same kind of bound.
const RESIDENT_PER_SECOND: usize = 4_000;
const RESIDENT_CAP_MAX: usize = 300_000;

/// Ring count caps for a PC whose displays add up to `refresh_hz` refreshes a second.
/// Worst case at the ceilings: 4 MB + 9.6 MB + 9.6 MB.
pub fn caps(refresh_hz: usize) -> (usize, usize, usize) {
    let secs = (GPU_KEEP_MS / 1000.0).ceil() as usize;
    let refresh = (refresh_hz * REFRESH_HEADROOM).max(REFRESH_HZ_FLOOR) * secs;
    (refresh.min(REFRESH_CAP_MAX), (PRESENTS_PER_SECOND * secs).min(PRESENT_CAP_MAX), (RESIDENT_PER_SECOND * secs).min(RESIDENT_CAP_MAX))
}

/// Refreshes a second across every display attached to the desktop, or 0 when Windows will not
/// say. `DEVMODEW.dmDisplayFrequency` is "the frequency, in hertz (cycles per second)"; 0 and 1
/// mean the hardware default rather than a real number.
/// https://learn.microsoft.com/en-us/windows/win32/api/wingdi/ns-wingdi-devmodew
/// https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-enumdisplaysettingsw
pub fn display_refresh_hz() -> usize {
    use windows_sys::Win32::Graphics::Gdi::{
        EnumDisplayDevicesW, EnumDisplaySettingsW, DEVMODEW, DISPLAY_DEVICEW, DISPLAY_DEVICE_ATTACHED_TO_DESKTOP, ENUM_CURRENT_SETTINGS,
    };
    let mut total = 0usize;
    unsafe {
        for i in 0..16u32 {
            let mut dev: DISPLAY_DEVICEW = zeroed();
            dev.cb = size_of::<DISPLAY_DEVICEW>() as u32;
            if EnumDisplayDevicesW(null(), i, &mut dev, 0) == 0 {
                break;
            }
            if dev.StateFlags & DISPLAY_DEVICE_ATTACHED_TO_DESKTOP == 0 {
                continue;
            }
            let mut mode: DEVMODEW = zeroed();
            mode.dmSize = size_of::<DEVMODEW>() as u16;
            if EnumDisplaySettingsW(dev.DeviceName.as_ptr(), ENUM_CURRENT_SETTINGS, &mut mode) != 0 && mode.dmDisplayFrequency > 1 {
                total += mode.dmDisplayFrequency as usize;
            }
        }
    }
    total
}

impl GpuInner {
    /// One refresh event from the provider. MEASURED on Windows 11 25H2: `VSyncDPC` (17) and
    /// `VSyncDPCMultiPlane` (273) BOTH fire for the same refresh (15,426 of each in one run), so
    /// taking every event doubles the count and makes the typical gap between ticks ~0. Two
    /// ticks closer than half a millisecond are one refresh (or two displays refreshing together,
    /// which is the same thing to a search for gaps of 50 ms and more).
    pub(super) fn on_refresh(&mut self, ts: i64) {
        if self.refresh.back().is_some_and(|last| ts - *last < crate::util::ms_to_ticks(0.5)) {
            return;
        }
        self.push_refresh(ts);
    }

    fn push_refresh(&mut self, ts: i64) {
        self.totals.refresh_ticks += 1;
        self.refresh.push_back(ts);
        if self.refresh.len() > self.refresh_cap {
            self.refresh_lost_until = self.refresh_lost_until.max(self.refresh.pop_front());
        }
    }

    fn push_present(&mut self, r: PresentRec) {
        self.totals.presents += 1;
        self.presents.push_back(r);
        if self.presents.len() > self.present_cap {
            self.present_lost_until = self.present_lost_until.max(self.presents.pop_front().map(|r| r.ts));
        }
    }

    fn push_residency(&mut self, r: ResidentRec) {
        self.totals.residency_ops += 1;
        self.totals.residency_ms += ticks_to_ms(r.dur);
        if r.trim > 0 {
            self.totals.trim_events += 1;
            self.totals.trim_max_bytes = self.totals.trim_max_bytes.max(r.trim);
        }
        if r.failed {
            self.totals.residency_failed += 1;
        }
        self.residency.push_back(r);
        if self.residency.len() > self.residency_cap {
            self.residency_lost_until = self.residency_lost_until.max(self.residency.pop_front().map(|r| r.ts));
        }
    }

    fn prune(&mut self, keep: i64) {
        let cutoff = self.latest_ts - keep;
        while self.refresh.front().is_some_and(|ts| *ts < cutoff) {
            self.refresh.pop_front();
        }
        while self.presents.front().is_some_and(|r| r.ts < cutoff) {
            self.presents.pop_front();
        }
        while self.residency.front().is_some_and(|r| r.ts < cutoff) {
            self.residency.pop_front();
        }
        // An open MakeResident that never got its stop event is a leak otherwise.
        self.starts.retain(|_, (ts, _)| *ts >= cutoff);
        self.last_prune = self.latest_ts;
    }

    /// Do the rings honestly cover `[from, to]`? Only if nothing inside the window was thrown
    /// away by a count cap and the (short) history still reaches back to `from`. Checked per
    /// ring, so a burst of presents cannot silence the refresh ticks.
    fn covers(from: i64, lost_until: Option<i64>, oldest: Option<i64>) -> bool {
        lost_until.is_none_or(|lost| lost < from) && oldest.is_some_and(|ts| ts <= from)
    }

    /// Everything the GPU trace has to say about one window of time.
    pub fn window(&self, from: i64, to: i64) -> GpuWindow {
        let refresh: Vec<i64> = self.refresh.iter().copied().filter(|ts| *ts >= from && *ts <= to).collect();
        let refresh_covered = Self::covers(from, self.refresh_lost_until, self.refresh.front().copied());
        let present_covered = Self::covers(from, self.present_lost_until, self.presents.front().map(|r| r.ts));

        let mut by_pid: HashMap<u32, Vec<i64>> = HashMap::new();
        for r in self.presents.iter().filter(|r| r.ts >= from && r.ts <= to) {
            by_pid.entry(r.pid).or_default().push(r.ts);
        }
        // The program drawing the MOST frames in the window: the game or video the person is
        // looking at. Not the one with the longest gap: a browser or a chat window paints in
        // bursts with long pauses between them, and would win that contest every time without
        // anything having stopped. Ties are broken by pid so the answer is stable.
        let mut program: Option<(u32, Cadence)> = None;
        if present_covered {
            for (pid, times) in by_pid {
                let Some(c) = cadence(&times) else { continue };
                if program.as_ref().is_none_or(|(p, best)| c.count > best.count || (c.count == best.count && pid < *p)) {
                    program = Some((pid, c));
                }
            }
        }

        let mut w = GpuWindow {
            refresh_covered,
            present_covered,
            display: refresh_covered.then(|| cadence(&refresh)).flatten(),
            program,
            ..GpuWindow::default()
        };
        for r in self.residency.iter().filter(|r| r.ts >= from && r.ts <= to) {
            w.residency_ops += 1;
            w.residency_ms += ticks_to_ms(r.dur);
            w.trim_bytes = w.trim_bytes.max(r.trim);
            w.residency_failed += usize::from(r.failed);
        }
        w
    }
}

impl GpuTrace {
    /// Everything the summary needs, read out once at the end of the run.
    pub fn report(&self) -> GpuTraceReport {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let sorted = |m: &HashMap<(u16, u8), u64>| {
            let mut v: Vec<((u16, u8), u64)> = m.iter().map(|(k, n)| (*k, *n)).collect();
            v.sort();
            v
        };
        GpuTraceReport {
            totals: GpuTraceTotals { available: true, events: inner.events, ..inner.totals },
            note: None,
            debug_counts: sorted(&inner.debug_counts),
            debug_unknown: sorted(&inner.debug_unknown),
        }
    }
}

// ---- cadence --------------------------------------------------------------------------------

/// How regularly something happened, and the longest it stopped.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Cadence {
    pub count: usize,
    /// The middle gap between consecutive events, in ms. The median, not the mean: one long gap
    /// is exactly what is being looked for and must not drag the "normal" up with it.
    pub typical_ms: f64,
    pub worst_ms: f64,
    /// When the longest gap ended.
    pub worst_at: i64,
}

/// A gap a person can see: three refreshes missed on a 60 Hz display.
pub const GAP_MIN_MS: f64 = 50.0;
/// ...and it has to be several times the stream's own normal gap, so a video player drawing 24
/// frames a second is not accused of stopping.
pub const GAP_FACTOR: f64 = 3.0;

impl Cadence {
    /// Did this stream stop for long enough to be felt?
    pub fn stalled(&self) -> bool {
        self.worst_ms >= GAP_MIN_MS.max(self.typical_ms * GAP_FACTOR)
    }
}

/// The cadence of a sorted list of timestamps. `None` under three of them: two gaps is the least
/// that can say what "normal" was and whether one of them stands out.
pub fn cadence(times: &[i64]) -> Option<Cadence> {
    if times.len() < 3 {
        return None;
    }
    let mut gaps: Vec<i64> = times.windows(2).map(|w| w[1] - w[0]).collect();
    let (worst_at, worst) =
        times.windows(2).map(|w| (w[1], w[1] - w[0])).fold((0i64, i64::MIN), |best, cur| if cur.1 > best.1 { cur } else { best });
    gaps.sort_unstable();
    Some(Cadence { count: times.len(), typical_ms: ticks_to_ms(gaps[gaps.len() / 2]), worst_ms: ticks_to_ms(worst), worst_at })
}

/// What the GPU trace has to say about one window of time.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct GpuWindow {
    /// The refresh ring really reaches over this window; nothing may be read from it otherwise.
    pub refresh_covered: bool,
    pub present_covered: bool,
    /// How steadily the displays were refreshing.
    pub display: Option<Cadence>,
    /// The program drawing the most frames in the window, by process id.
    pub program: Option<(u32, Cadence)>,
    pub residency_ops: usize,
    pub residency_ms: f64,
    /// The most video memory Windows asked to have freed in this window; 0 means never.
    pub trim_bytes: u64,
    pub residency_failed: usize,
}

impl GpuWindow {
    /// Nothing at all to say: no stream covered, nothing measured.
    pub fn empty(&self) -> bool {
        self.display.is_none() && self.program.is_none() && self.residency_ops == 0
    }
}

/// One flagged moment, as the GPU trace saw it. Kept by the analyzer when the moment is examined,
/// because the rings only hold a few seconds and the summary runs minutes later.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct MarkGpu {
    /// At least one of the streams covered the moment.
    pub covered: bool,
    /// Longest gap in the display refresh, ms, and whether that counts as stopped.
    pub display_gap_ms: f64,
    pub display_stalled: bool,
    /// (program name, longest gap between its frames in ms, whether that counts as stopped).
    pub program: Option<(String, f64, bool)>,
    pub trim_bytes: u64,
    pub residency_ms: f64,
}

// ---- the session ----------------------------------------------------------------------------

/// Starts the session, enables DxgKrnl on it and spawns the consumer thread.
/// The handle must be kept alive for the run; dropping it stops the session.
pub fn start(debug: bool) -> Result<(Session, Arc<GpuTrace>, JoinHandle<()>), String> {
    let session = manifest::start(&manifest::Spec {
        session: SESSION_NAME,
        provider: DXGKRNL_GUID,
        what: "the graphics provider",
        level: TRACE_LEVEL_INFORMATION as u8,
        keywords: KEYWORD_PRESENT,
        ids: &WANTED,
        // Far smaller than the kernel session's: with the event-id filter this session carries
        // a few hundred small events a second, not hundreds of megabytes.
        buffer_kb: 64,
        min_buffers: 8,
        max_buffers: 64,
    })?;
    let (refresh_cap, present_cap, residency_cap) = caps(display_refresh_hz());
    let trace = Arc::new(GpuTrace {
        inner: Mutex::new(GpuInner { refresh_cap, present_cap, residency_cap, last_prune: qpc(), ..GpuInner::default() }),
        debug,
    });
    let consumer = manifest::spawn_consumer(SESSION_NAME, "gpu-etw", Some(events::on_event), trace.clone());
    Ok((session, trace, consumer))
}

/// Pruning is driven by the newest timestamp seen, like the kernel session's rings.
pub(crate) fn maybe_prune(inner: &mut GpuInner, ts: i64) {
    if ts > inner.latest_ts {
        inner.latest_ts = ts;
        let keep = ms_to_ticks(GPU_KEEP_MS);
        if ts - inner.last_prune > keep / 8 {
            inner.prune(keep);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(ms: f64) -> i64 {
        ms_to_ticks(ms)
    }

    #[test]
    fn cadence_needs_two_gaps_and_reports_the_middle_one_as_normal() {
        assert_eq!(cadence(&[]), None);
        assert_eq!(cadence(&[at(0.0), at(16.7)]), None, "one gap says nothing about what is normal");
        let steady: Vec<i64> = (0..10).map(|i| at(i as f64 * 16.7)).collect();
        let c = cadence(&steady).unwrap();
        assert_eq!(c.count, 10);
        assert!((c.typical_ms - 16.7).abs() < 0.1, "{c:?}");
        assert!((c.worst_ms - 16.7).abs() < 0.1, "{c:?}");
        assert!(!c.stalled(), "a steady 60 Hz stream never stopped");
    }

    #[test]
    fn one_long_gap_stands_out_without_dragging_the_normal_up() {
        // 60 Hz, then 200 ms of nothing, then 60 Hz again.
        let mut times: Vec<i64> = (0..8).map(|i| at(i as f64 * 16.7)).collect();
        let after = 8.0 * 16.7 + 200.0;
        times.extend((0..8).map(|i| at(after + i as f64 * 16.7)));
        let c = cadence(&times).unwrap();
        assert!((c.typical_ms - 16.7).abs() < 0.2, "the median ignores the outlier: {c:?}");
        assert!((c.worst_ms - 216.7).abs() < 0.5, "{c:?}");
        assert_eq!(c.worst_at, at(after));
        assert!(c.stalled());

        // A 24 fps video player is not stalling just because 41 ms is more than 50/3.
        let film: Vec<i64> = (0..20).map(|i| at(i as f64 * 41.7)).collect();
        assert!(!cadence(&film).unwrap().stalled(), "a slow but steady stream is not a stall");
        // ...but a missed beat three times its own normal is.
        let mut skipped = film.clone();
        skipped.retain(|t| !(10..=13).contains(&((ticks_to_ms(*t) / 41.7).round() as i32)));
        assert!(cadence(&skipped).unwrap().stalled());
    }

    fn inner() -> GpuInner {
        let (refresh_cap, present_cap, residency_cap) = caps(60);
        GpuInner { refresh_cap, present_cap, residency_cap, ..GpuInner::default() }
    }

    #[test]
    fn caps_follow_the_displays_actually_attached() {
        let secs = (GPU_KEEP_MS / 1000.0).ceil() as usize;
        assert_eq!(caps(240).0, 240 * REFRESH_HEADROOM * secs, "a 240 Hz display gets room for a 240 Hz stream");
        assert_eq!(caps(0).0, REFRESH_HZ_FLOOR * secs, "no readable refresh rate still leaves a usable floor");
        assert_eq!(caps(1_000_000).0, REFRESH_CAP_MAX, "and there is a ceiling");
        // The stated memory bound only holds if the records stay this size.
        assert_eq!(std::mem::size_of::<PresentRec>(), 16);
        assert_eq!(std::mem::size_of::<ResidentRec>(), 32);
        const {
            assert!(REFRESH_CAP_MAX * 8 + PRESENT_CAP_MAX * 16 + RESIDENT_CAP_MAX * 32 <= 24 << 20, "the rings must stay under 24 MB");
        };
    }

    #[test]
    fn two_events_for_one_refresh_count_once() {
        let mut inner = inner();
        for i in 0..10 {
            inner.on_refresh(at(i as f64 * 16.7));
            inner.on_refresh(at(i as f64 * 16.7 + 0.02));
        }
        assert_eq!(inner.totals.refresh_ticks, 10);
        let c = cadence(&inner.refresh.iter().copied().collect::<Vec<_>>()).unwrap();
        assert!((c.typical_ms - 16.7).abs() < 0.1, "{c:?}");
    }

    #[test]
    fn a_ring_that_overflowed_only_disqualifies_the_windows_it_reaches_into() {
        let mut inner = inner();
        inner.refresh_cap = 4;
        for i in 0..7 {
            inner.push_refresh(i);
        }
        assert_eq!(inner.refresh.len(), 4);
        assert_eq!(inner.refresh_lost_until, Some(2), "the oldest went first");
        assert_eq!(inner.totals.refresh_ticks, 7, "the count is of everything that arrived");
        assert!(GpuInner::covers(3, inner.refresh_lost_until, inner.refresh.front().copied()));
        assert!(!GpuInner::covers(2, inner.refresh_lost_until, inner.refresh.front().copied()), "a record from inside the window went");
        assert!(!GpuInner::covers(0, inner.refresh_lost_until, inner.refresh.front().copied()));
        // ...and the presents ring is judged on its own, not on the refresh ring's overflow.
        inner.push_present(PresentRec { ts: 1, pid: 7, source: 0 });
        assert!(GpuInner::covers(3, inner.present_lost_until, inner.presents.front().map(|r| r.ts)));
    }

    #[test]
    fn a_window_judges_the_program_drawing_the_most_frames() {
        let mut inner = inner();
        for i in 0..40 {
            inner.push_refresh(at(i as f64 * 16.7));
        }
        // A game that stops for a quarter of a second, and a chat window that paints in bursts
        // with longer pauses than that between them. The game is what the person is looking at:
        // it draws the most, so it is the one judged, although the other has the longer gap.
        for i in 0..40 {
            let ms = if i < 20 { i as f64 * 16.7 } else { 250.0 + i as f64 * 16.7 };
            inner.push_present(PresentRec { ts: at(ms), pid: 100, source: 0 });
        }
        for i in 0..10 {
            let ms = if i < 5 { i as f64 * 16.7 } else { 600.0 + i as f64 * 16.7 };
            inner.push_present(PresentRec { ts: at(ms), pid: 200, source: 0 });
        }
        inner.push_residency(ResidentRec { ts: at(100.0), dur: at(12.0), trim: 600_000_000, pid: 200, failed: false });
        inner.push_residency(ResidentRec { ts: at(120.0), dur: at(3.0), trim: 0, pid: 200, failed: true });

        let w = inner.window(0, at(1000.0));
        assert!(w.refresh_covered && w.present_covered);
        assert!(!w.display.unwrap().stalled(), "the displays kept refreshing");
        let (pid, c) = w.program.expect("a program stopped");
        assert_eq!(pid, 100);
        assert!(c.stalled() && c.worst_ms > 200.0 && c.worst_ms < 300.0, "{c:?}");
        assert_eq!(w.residency_ops, 2);
        assert_eq!(w.trim_bytes, 600_000_000);
        assert_eq!(w.residency_failed, 1);
        assert!((w.residency_ms - 15.0).abs() < 0.5, "{}", w.residency_ms);
        assert!(!w.empty());

        // A window with nothing in it says nothing rather than something reassuring.
        let far = inner.window(at(5000.0), at(6000.0));
        assert!(far.empty() && far.display.is_none() && far.program.is_none());
    }

    #[test]
    fn pruning_drops_only_what_is_older_than_the_window() {
        let mut inner = inner();
        inner.push_refresh(at(0.0));
        inner.push_refresh(at(GPU_KEEP_MS - 100.0));
        inner.push_present(PresentRec { ts: at(0.0), pid: 1, source: 0 });
        inner.starts.insert(9, (at(0.0), 1));
        inner.latest_ts = at(GPU_KEEP_MS + 10.0);
        inner.prune(ms_to_ticks(GPU_KEEP_MS));
        assert_eq!(inner.refresh.len(), 1, "only the record past the window went");
        assert!(inner.presents.is_empty());
        assert!(inner.starts.is_empty(), "an operation that never finished must not leak");
    }

    /// Non-asserting: CI runners have no display, and a developer's PC has one or more.
    #[test]
    fn reading_this_pcs_refresh_rate_does_not_panic() {
        let hz = display_refresh_hz();
        println!("displays add up to {hz} Hz; caps {:?}", caps(hz));
    }

    #[test]
    fn the_event_id_filter_is_a_filter_in_list_of_the_wanted_ids() {
        let f = manifest::event_id_filter(&WANTED);
        assert_eq!(f[0], 1, "FilterIn = TRUE, Reserved = 0");
        assert_eq!(f[1] as usize, WANTED.len());
        assert_eq!(&f[2..], &WANTED);
        assert!(WANTED.len() <= 64, "MAX_EVENT_FILTER_EVENT_ID_COUNT is 64");
    }
}
