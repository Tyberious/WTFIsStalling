//! Turns a finished run into an answer: a one-line verdict, ranked findings (what, evidence,
//! what to try) and the supporting tables. Front ends decide how to present it.

use std::collections::HashMap;
use std::mem::{size_of, zeroed};
use std::sync::atomic::Ordering;

use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};

use crate::analyze::Analyzer;
use crate::cpuclock::ClockSample;
use crate::devices::{self, DeviceMap};
use crate::disks::{fmt_size, DiskInfo};
use crate::diskwhy::{known_worker, Cause, DiskWhy};
use crate::evlog::{self, HardwareEvent, HardwareKind, UnexpectedShutdown};
use crate::gpu::GpuLog;
use crate::health::{self, DriveHealth};
use crate::modules::knowledge;
use crate::pci::{self, PciDevice};
use crate::period;
use crate::probe::{ProbeStats, StallKind};
use crate::state::*;
use crate::topology::Topology;
use crate::util::{fmt_dur, ms_to_ticks, qpc, qpc_freq};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Severity {
    /// Worth knowing, not a cause of hitches by itself.
    Low,
    /// Can cause audio crackle or micro-stutter; a suspect.
    Medium,
    /// Repeatedly or badly stalled the machine.
    High,
}

impl Severity {
    fn label(self) -> &'static str {
        match self {
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Health {
    Ok,
    Warning,
    Problem,
    /// The kernel trace delivered nothing, so there is no basis for a verdict.
    NoData,
}

pub struct Finding {
    pub severity: Severity,
    pub title: String,
    pub evidence: Vec<String>,
    pub advice: String,
    /// Ticks of harm attributed to this subject; orders findings of equal severity.
    impact: i64,
}

pub struct Summary {
    pub health: Health,
    pub headline: String,
    /// One sentence backing the headline (the top finding's evidence, or reassurance).
    pub subline: String,
    /// Short "label: value" lines: duration, stall counts, worst delays.
    pub overview: Vec<String>,
    pub findings: Vec<Finding>,
    /// Supporting tables, already formatted.
    pub details: Vec<String>,
}

const WIDTH: usize = 100;

/// Word-wraps `text`; the first line starts with `first`, the rest align under its text.
fn wrap(text: &str, first: &str, out: &mut Vec<String>) {
    let hang = " ".repeat(first.len());
    let mut indent = first;
    let mut line = String::new();
    for word in text.split_whitespace() {
        if !line.is_empty() && indent.len() + line.len() + 1 + word.len() > WIDTH {
            out.push(format!("{indent}{line}"));
            indent = &hang;
            line.clear();
        }
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(word);
    }
    if !line.is_empty() {
        out.push(format!("{indent}{line}"));
    }
}

impl Summary {
    /// The answer block: verdict first, then each finding with evidence and what to try.
    pub fn result_lines(&self) -> Vec<String> {
        let bar = "=".repeat(WIDTH);
        let mut out = vec![bar.clone(), "RESULT".into(), String::new()];
        let tag = match self.health {
            Health::Problem => "PROBLEM FOUND",
            Health::Warning => "SUSPECT FOUND",
            Health::Ok => "ALL CLEAR",
            Health::NoData => "NO DATA",
        };
        out.push(format!("  >>> {tag}: {}", self.headline));
        wrap(&self.subline, "      ", &mut out);
        out.push(String::new());
        out.extend(self.overview.iter().map(|l| format!("  {l}")));
        for (i, f) in self.findings.iter().enumerate() {
            out.push(String::new());
            out.push(format!("  {}. [{}] {}", i + 1, f.severity.label(), f.title));
            for e in &f.evidence {
                wrap(e, "       - ", &mut out);
            }
            out.push("     What to try:".into());
            wrap(&f.advice, "       ", &mut out);
        }
        out.push(bar);
        out
    }

    pub fn detail_lines(&self) -> Vec<String> {
        let mut out = vec!["DETAILS".to_string()];
        out.extend(self.details.iter().cloned());
        out
    }
}

impl Summary {
    /// Canned results for working on the front ends without admin rights or a sick PC.
    pub fn demo(health: Health) -> Summary {
        let finding = |severity, title: &str, evidence: &str, advice: &str| Finding {
            severity,
            title: title.into(),
            evidence: vec![evidence.into()],
            advice: advice.into(),
            impact: 0,
        };
        let findings = match health {
            Health::Problem => vec![
                finding(
                    Severity::High,
                    "rtwlane.sys  -  Wi-Fi adapter driver",
                    "Blamed for 14 stalls (worst 11.80 ms, 121 ms in total).",
                    knowledge("rtwlane.sys").map_or("", |k| k.advice),
                ),
                finding(
                    Severity::Medium,
                    "Disk 1 (D:), WDC WD40EZAZ-00SF3B0  -  responding slowly",
                    "3 requests took longer than 200 ms (worst 840 ms). SATA hard drive, 4.0 TB, firmware 80.00A80. D: 93% full.",
                    "Check its health (SMART), free up space on D:, and reseat or replace its cable.",
                ),
            ],
            Health::Warning => vec![finding(
                Severity::Medium,
                "nvlddmkm.sys  -  NVIDIA GPU driver",
                "Its interrupt handling ran for up to 1.84 ms at a time (6 times over 1.00 ms).",
                knowledge("nvlddmkm.sys").map_or("", |k| k.advice),
            )],
            _ => Vec::new(),
        };
        let (headline, subline) = match findings.first() {
            Some(f) => (f.title.clone(), f.evidence[0].clone()),
            None => (
                "Nothing stalled this PC while monitoring".to_string(),
                "No driver, program, disk or firmware problem showed up.".to_string(),
            ),
        };
        Summary {
            health,
            headline,
            subline,
            overview: vec!["Monitored:        05:12".into(), "Note:             demo data, not a real measurement".into()],
            findings,
            details: vec![String::new(), "(demo: no details)".into()],
        }
    }
}

/// Findings keyed by subject so that e.g. a driver blamed for stalls *and* seen running long
/// DPCs becomes one entry with both pieces of evidence.
#[derive(Default)]
struct Findings(Vec<(String, Finding)>);

impl Findings {
    fn add(&mut self, key: &str, severity: Severity, title: String, evidence: String, advice: String, impact: i64) {
        match self.0.iter_mut().find(|(k, _)| k == key) {
            Some((_, f)) => {
                f.severity = f.severity.max(severity);
                f.evidence.push(evidence);
                f.impact += impact;
            }
            None => self.0.push((key.to_string(), Finding { severity, title, evidence: vec![evidence], advice, impact })),
        }
    }

    fn raise(&mut self, key: &str, severity: Severity) {
        if let Some((_, f)) = self.0.iter_mut().find(|(k, _)| k == key) {
            f.severity = f.severity.max(severity);
        }
    }

    /// More to try for a subject that is already a finding.
    fn advise(&mut self, key: &str, advice: &str) {
        if let Some((_, f)) = self.0.iter_mut().find(|(k, _)| k == key) {
            if !f.advice.contains(advice) {
                f.advice = format!("{} {advice}", f.advice.trim_end());
            }
        }
    }

    /// Extra evidence for a subject that is already a finding. Returns whether it was.
    fn note(&mut self, key: &str, evidence: String) -> bool {
        match self.0.iter_mut().find(|(k, _)| k == key) {
            Some((_, f)) => {
                f.evidence.push(evidence);
                true
            }
            None => false,
        }
    }
}

const CONTROLLER_RESET_ADVICE: &str = "Every program waits, often for many seconds, while Windows resets a drive. Usual causes: a \
    loose or bad SATA/M.2 connection, drive firmware, or link power saving. Reseat or replace cables, update SSD firmware and the \
    chipset/storage driver, and set Power Options > PCI Express > Link State Power Management to Off. Event Viewer > Windows Logs > \
    System (event 129) shows which controller.";

const GENERIC_DRIVER_ADVICE: &str = "Update this driver from the device maker's site, or roll it back if the problem started after an \
    update. To confirm, temporarily disable the device (or close the software it belongs to) and monitor again.";

const POLLING_ADVICE: &str = "Something runs on a timer. The usual suspects poll hardware sensors: RGB and fan utilities (iCUE, Armoury \
    Crate, Aura, RGB Fusion, MSI Center, NZXT CAM), monitoring tools (HWiNFO, Afterburner/RTSS, Ryzen Master), vendor 'control \
    center' and battery utilities. Fully exit them one at a time (not just close the window) and monitor again.";

const THROTTLE_ADVICE: &str = "The CPU is being held back by heat or a power limit. Watch temperatures under load (HWiNFO or the \
    vendor's tool): clean dust, check the cooler is seated and the fans spin, renew thermal paste on older machines. On laptops \
    plug in the charger and pick the 'Best performance' power mode. In the BIOS check that power limits, ECO mode or an undervolt \
    are not set too aggressively.";

fn secs(ticks: &[i64]) -> Vec<f64> {
    ticks.iter().map(|t| *t as f64 / qpc_freq() as f64).collect()
}

const DARK_ADVICE: &str = "Windows itself was frozen out, which points below the operating system. Update the BIOS/UEFI, load BIOS \
    defaults (undo overclocks and memory tweaks), disable 'Legacy USB support' and unused onboard devices as a test, check for \
    thermal throttling, and if Hyper-V / Core Isolation (VBS) is enabled, test with it off. If it persists, suspect hardware.";

fn memory_load() -> u32 {
    let mut mem: MEMORYSTATUSEX = unsafe { zeroed() };
    mem.dwLength = size_of::<MEMORYSTATUSEX>() as u32;
    unsafe { GlobalMemoryStatusEx(&mut mem) };
    mem.dwMemoryLoad
}

#[derive(Default)]
struct DriverAgg {
    dpc_n: u64,
    dpc_max: i64,
    isr_n: u64,
    isr_max: i64,
    total: i64,
    over: u64,
}

/// What to try for a slow disk, based on why it seemed slow and what kind of disk it is.
fn disk_advice(disk: &DiskInfo, why: Option<&DiskWhy>, logged_errors: bool) -> String {
    let mut advice = String::from("Anything that touches this disk freezes while it answers. ");
    let main = if logged_errors { None } else { why.and_then(|w| w.main_cause()) };
    match main {
        Some(Cause::Busy) => {
            let who = why.and_then(|w| w.top_movers(1).into_iter().next()).map(|m| m.0);
            advice.push_str("It was slow because it was busy, so deal with the traffic first. ");
            match (&who, who.as_deref().and_then(known_worker)) {
                // Part of Windows: there is nothing to close or pause, only a setting or patience.
                (Some(who), Some(w)) if w.windows => {
                    advice.push_str(&format!("{who} is part of Windows ({}), not something you can close. {} ", w.what, w.tip))
                }
                (Some(who), Some(w)) => advice.push_str(&format!("{who}: {} ", w.tip)),
                (Some(who), None) => {
                    advice.push_str(&format!("Let {who} finish, pause it, or schedule it for when you are not using the PC. "))
                }
                (None, _) => {}
            }
            advice.push_str("Keeping heavy disk work and your game on different drives also fixes it. ");
        }
        Some(Cause::WokeUp) => advice.push_str(
            "It had gone to sleep and needed time to wake up. Stop it from sleeping: Control Panel > Power Options > Change plan \
             settings > Advanced > Hard disk > 'Turn off hard disk after' = 0 (never), and for a USB drive also set 'USB selective \
             suspend' to Disabled there. Or keep files you use while gaming off this drive. ",
        ),
        Some(Cause::Flush) => advice.push_str(
            "A program kept forcing its writes out to the drive, which budget SSDs without their own memory handle badly. See which \
             program issued the slow flushes in the event log below. ",
        ),
        _ => {}
    }
    let full = disk.nearly_full();
    if !full.is_empty() {
        let letters = full.iter().map(|l| format!("{l}:")).collect::<Vec<_>>().join(" and ");
        advice.push_str(&format!("{letters} is nearly full, which by itself makes drives slow: free up space. "));
    }
    if logged_errors {
        advice.push_str(
            "Windows logged errors for this drive, which is not normal: back up what matters now. Then reseat or replace its cable \
             (or move an M.2 drive to another slot), update its firmware, and check its health (SMART) with the maker's tool or \
             CrystalDiskInfo.",
        );
    } else if matches!(main, Some(Cause::Busy | Cause::WokeUp)) {
        advice.push_str("If it stays slow without that, check its health (SMART) with the maker's tool or CrystalDiskInfo.");
    } else {
        advice.push_str("Check its health (SMART) with the maker's tool or CrystalDiskInfo");
        advice.push_str(match (disk.bus, disk.spinning) {
            ("USB", _) => ", and try another USB port or cable, plugged straight into the PC rather than a hub.",
            (_, Some(true)) => {
                ". A hard drive that takes this long with little to do is often failing: back up what matters, reseat or replace its \
                 cable, and move games and programs to an SSD."
            }
            ("NVMe", _) => ", update its firmware, and make sure it isn't overheating (a heatsink helps).",
            ("SATA" | "ATA", _) => ", update its firmware, and reseat or replace its SATA cable.",
            _ => ", update SSD firmware, and reseat or replace the cable on SATA drives.",
        });
    }
    if disk.model.is_empty() && disk.volumes.is_empty() {
        advice.push_str(&format!(" Disk {} is the number shown in Windows Disk Management.", disk.number));
    }
    advice
}

/// One sentence per reason the disk's slow requests were slow, most common first.
fn why_sentences(why: &DiskWhy) -> Vec<String> {
    let mut causes = [Cause::Busy, Cause::WokeUp, Cause::IdleSlow, Cause::Flush].map(|c| (c, why.count(c)));
    causes.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
    let of = |n: u32| if n == why.total() { "every time".to_string() } else { format!("{n} of {} times", why.total()) };
    let mut out = Vec::new();
    for (cause, n) in causes.into_iter().filter(|(_, n)| *n > 0) {
        out.push(match cause {
            Cause::Busy => {
                let movers: Vec<String> = why
                    .top_movers(2)
                    .into_iter()
                    .filter(|m| m.2 >= 0.15)
                    .map(|(name, bytes, share)| {
                        let what = known_worker(&name).map_or(String::new(), |w| format!(": {}", w.what));
                        format!("{name} ({}, {:.0}% of the traffic{what})", fmt_size(bytes), share * 100.0)
                    })
                    .collect();
                let who = if movers.is_empty() { String::new() } else { format!(" The traffic came from {}.", movers.join(" and ")) };
                format!("Why: the disk was busy moving a lot of data ({}).{who}", of(n))
            }
            Cause::WokeUp => format!(
                "Why: the drive had gone to sleep ({}). The slow request was the first after up to {:.0} s of silence.",
                of(n),
                why.longest_sleep_ms / 1000.0
            ),
            Cause::IdleSlow => format!(
                "Why: not traffic. The disk had little else to do and still took that long ({}), which points at the drive itself, \
                 its cable or its firmware.",
                of(n)
            ),
            Cause::Flush => format!("Why: a program forced its writes out to the drive and the drive took its time ({}).", of(n)),
        });
    }
    out
}

const DRIVE_FAILING_ADVICE: &str = "The drive itself reports damage. Back up everything on it now, before doing anything else, then \
    replace it; drives in this state fail without further warning, and every retry on a bad spot is a freeze.";

const DRIVE_HOT_ADVICE: &str = "The drive is hot enough to slow itself down, which shows up as hitches during loading and saving. Fit \
    an M.2 heatsink (many motherboards ship one that is easy to leave off), improve case airflow, and if it sits directly under the \
    graphics card consider another M.2 slot.";

const DRIVE_CABLE_ADVICE: &str = "CRC errors mean data was damaged between the drive and the motherboard, not on the drive: replace \
    the SATA cable (they do go bad), make sure both ends click in, and try another SATA port.";

/// What a drive's own health data says, as (severity, sentence, what to try).
fn health_findings(spinning: bool, start: Option<&DriveHealth>, end: &DriveHealth) -> Vec<(Severity, String, &'static str)> {
    let mut out = Vec::new();
    if let Some(n) = &end.nvme {
        let before = start.and_then(|s| s.nvme.as_ref());
        let problems: Vec<&str> = [
            (1, "its spare capacity is running out"),
            (2, "it is over (or under) its temperature limit"),
            (4, "its reliability is degraded by media errors"),
            (8, "it has switched to read-only mode"),
            (16, "its power-loss protection has failed"),
        ]
        .iter()
        .filter(|(bit, _)| n.critical_warning & bit != 0)
        .map(|(_, text)| *text)
        .collect();
        if !problems.is_empty() {
            let advice = if n.critical_warning & !2 != 0 { DRIVE_FAILING_ADVICE } else { DRIVE_HOT_ADVICE };
            out.push((
                Severity::High,
                format!("Drive health: the drive has raised its own critical warning: {}.", problems.join("; ")),
                advice,
            ));
        }
        if n.media_errors > 0 {
            out.push((
                Severity::Medium,
                format!("Drive health: {} unrecoverable media error(s) recorded over its life.", n.media_errors),
                DRIVE_FAILING_ADVICE,
            ));
        }
        if n.percent_used >= 100 {
            out.push((
                Severity::Medium,
                format!("Drive health: it has used {}% of its rated write endurance, so it is past its designed life.", n.percent_used),
                DRIVE_FAILING_ADVICE,
            ));
        }
        let throttled = before.map_or(0, |b| n.throttle_seconds.saturating_sub(b.throttle_seconds));
        let over_temp = before.map_or(0, |b| n.warning_temp_minutes.saturating_sub(b.warning_temp_minutes));
        if throttled > 0 || over_temp > 0 {
            let what = if throttled > 0 {
                format!("spent {throttled} s slowed down by heat")
            } else {
                "was over its warning temperature".to_string()
            };
            out.push((Severity::High, format!("Drive health: it {what} while monitoring (now {} °C).", n.temperature_c), DRIVE_HOT_ADVICE));
        } else if n.temperature_c >= 70 {
            out.push((
                Severity::Medium,
                format!("Drive health: it is at {} °C. NVMe drives slow themselves down from roughly 70-80 °C.", n.temperature_c),
                DRIVE_HOT_ADVICE,
            ));
        } else if n.warning_temp_minutes > 0 || n.throttle_seconds >= 600 {
            out.push((
                Severity::Low,
                format!(
                    "Drive health: over its life it has spent {} min above its warning temperature and {} min slowed down by heat (now {} °C).",
                    n.warning_temp_minutes,
                    n.throttle_seconds / 60,
                    n.temperature_c
                ),
                DRIVE_HOT_ADVICE,
            ));
        }
    }
    if let Some(sata) = &end.sata {
        let before = start.and_then(|s| s.sata.as_ref());
        let damaged: Vec<String> =
            [(sata.reallocated, "reallocated"), (sata.pending, "pending (unreadable)"), (sata.uncorrectable, "uncorrectable")]
                .iter()
                .filter_map(|(v, name)| v.filter(|v| *v > 0).map(|v| format!("{v} {name}")))
                .collect();
        if !damaged.is_empty() {
            let total: u64 = [sata.reallocated, sata.pending, sata.uncorrectable].iter().flatten().sum();
            let sev = if total >= 50 || sata.pending.unwrap_or(0) > 0 { Severity::High } else { Severity::Medium };
            out.push((sev, format!("Drive health (SMART): bad sectors: {}.", damaged.join(", ")), DRIVE_FAILING_ADVICE));
        }
        if let Some(crc) = sata.crc_errors.filter(|c| *c > 0) {
            let new = before.and_then(|b| b.crc_errors).map_or(0, |b| crc.saturating_sub(b));
            if new > 0 {
                out.push((
                    Severity::High,
                    format!("Drive health (SMART): {new} new CRC error(s) while monitoring ({crc} in total)."),
                    DRIVE_CABLE_ADVICE,
                ));
            } else {
                out.push((
                    Severity::Low,
                    format!("Drive health (SMART): {crc} CRC error(s) over its life; none while monitoring. Only a problem if the number keeps rising."),
                    DRIVE_CABLE_ADVICE,
                ));
            }
        }
    }
    if end.nvme.is_none() {
        let limit = if spinning { 55 } else { 70 };
        if let Some(t) = end.temperature().filter(|t| *t >= limit) {
            out.push((Severity::Medium, format!("Drive health: it is at {t} °C, which is hot for this kind of drive."), DRIVE_HOT_ADVICE));
        }
    }
    out
}

const DISPLAY_RESET_ADVICE: &str = "The graphics driver stopped answering for about two seconds, so Windows restarted it: that is a \
    freeze of several seconds, often with a black flash, and sometimes the game crashes. In order of likelihood: remove any GPU \
    overclock or undervolt (including factory-overclock tuning in Afterburner or the vendor app); clean-install the graphics driver \
    (use DDU, then the current or the previous driver version); check GPU temperatures and that every PCIe power plug is fully \
    seated, using separate cables rather than one daisy-chained cable; lower in-game settings that fill the VRAM. If it happens at \
    stock settings in every game, suspect the power supply or the card.";

/// Third-party drivers older than this get "update it" put first.
const OLD_DRIVER_YEARS: i32 = 2;

/// Retitles "driver <file>" findings with the device the driver serves and adds the driver's
/// version, date and age. Drivers without a device (filters, antivirus, the kernel) stay as they are.
fn name_devices(found: &mut Findings, map: &DeviceMap, today: (i32, u32, u32)) {
    for (key, f) in found.0.iter_mut() {
        let Some(file) = key.strip_prefix("driver ") else { continue };
        let (Some(title), Some(first)) = (map.device_title(file), map.get(file).first()) else { continue };
        // Keep whatever followed the description, e.g. ": it hung and was reset".
        let suffix =
            f.title.split_once("  -  ").and_then(|(_, rest)| rest.split_once(": ")).map_or(String::new(), |(_, tail)| format!(": {tail}"));
        f.title = format!("{file}  -  {title}{suffix}");
        let about = first.describe(today);
        if !about.is_empty() {
            f.evidence.push(about);
        }
        if let Some(years) = first.age_years(today).filter(|y| *y >= OLD_DRIVER_YEARS) {
            let provider =
                if first.provider.is_empty() { "the device maker".to_string() } else { first.provider.trim_end_matches('.').to_string() };
            f.advice = format!(
                "Start here: this driver is {years} years old. Install the current one from {provider} or from the support page of your \
                 PC or motherboard model (Windows Update rarely offers the newest). {}",
                f.advice
            );
        }
    }
}

/// Video memory counts as full from here: Windows keeps part of it back, so a game is already
/// being pushed out to system RAM before the counter reaches 100%.
const VRAM_FULL: f64 = 0.92;
/// Adapters with less dedicated memory than this are integrated graphics, whose small carve-out
/// is always "full" by design.
const VRAM_MIN_BYTES: u64 = 3_000_000_000;
/// A GPU this busy is the limit; one below GPU_WAITING was waiting for something else.
const GPU_BOUND: f64 = 95.0;
const GPU_WAITING: f64 = 70.0;
/// "It had spare capacity" only means something if the GPU was given real work at some point in
/// the run; a desktop idling at 30% is not a game waiting for the CPU.
const GPU_WORKED: f64 = 80.0;

const VRAM_ADVICE: &str = "When video memory runs out, Windows moves textures to ordinary RAM across the PCIe bus, and every time \
    the game needs one back there is a hitch. Lower texture quality first (it is the biggest consumer and costs almost no frame \
    rate), then resolution, ray tracing and frame generation. Close other things that hold video memory: browsers with many tabs, \
    a second game launcher, recording and overlay tools.";

const GPU_BOUND_ADVICE: &str = "At the moments you flagged, the graphics card was working flat out, so the hitch is the GPU running \
    out of time for a frame rather than something interrupting the PC. Lower the settings that load the GPU (resolution or render \
    scale, ray tracing, shadows), turn on DLSS / FSR / XeSS, or cap the frame rate a little below what the card averages so it has \
    headroom for heavy scenes.";

const GPU_WAITING_ADVICE: &str = "At the moments you flagged, the graphics card had spare capacity, so it was waiting for the rest \
    of the PC: the game's own CPU work (one overloaded thread is enough), loading or shader compilation, or one of the other \
    findings in this report. Lowering graphics settings will not help with this kind of hitch.";

#[derive(Default)]
struct GpuReport {
    findings: Vec<GpuFinding>,
    /// Lines for the details section.
    lines: Vec<String>,
    /// Set when video memory can be ruled out: "NVIDIA ... peaked at 2.7 GB of 33.8 GB (8%)".
    vram_clear: Option<String>,
}

struct GpuFinding {
    key: String,
    severity: Severity,
    title: String,
    evidence: String,
    advice: &'static str,
}

/// Findings and detail lines from the once-a-second GPU samples. `marks` are the moments the user
/// flagged (QPC); `name_of` turns a pid into a program name.
fn gpu_findings(log: &GpuLog, marks: &[i64], name_of: &mut dyn FnMut(u32) -> String) -> GpuReport {
    let (mut findings, mut lines) = (Vec::new(), Vec::new());
    let mut vram_clear: Option<(u64, String)> = None;
    let gb = |bytes: u64| format!("{:.1} GB", bytes as f64 / 1e9);
    for adapter in &log.adapters {
        let samples: Vec<(i64, &crate::gpu::AdapterSample)> =
            log.samples.iter().filter_map(|s| s.adapters.iter().find(|a| a.luid == adapter.luid).map(|a| (s.ts, a))).collect();
        if samples.is_empty() {
            continue;
        }
        let peak_busy = samples.iter().map(|(_, a)| a.busy).fold(0.0, f64::max);
        let avg_busy = samples.iter().map(|(_, a)| a.busy).sum::<f64>() / samples.len() as f64;
        let peak_mem = samples.iter().map(|(_, a)| a.dedicated).max().unwrap_or(0);
        let mut line = format!("  {}: busy {avg_busy:.0}% on average, {peak_busy:.0}% at most", adapter.name);
        if adapter.vram >= VRAM_MIN_BYTES {
            line.push_str(&format!(
                "; video memory peaked at {} of {} ({:.0}%)",
                gb(peak_mem),
                gb(adapter.vram),
                100.0 * peak_mem as f64 / adapter.vram as f64
            ));
        }
        lines.push(line);
        // The card with the most memory is the one games run on; its headroom is what clears VRAM.
        if adapter.vram >= VRAM_MIN_BYTES
            && (peak_mem as f64) < 0.8 * adapter.vram as f64
            && vram_clear.as_ref().is_none_or(|(v, _)| adapter.vram > *v)
        {
            let text = format!(
                "{} peaked at {} of {} ({:.0}%)",
                adapter.name,
                gb(peak_mem),
                gb(adapter.vram),
                100.0 * peak_mem as f64 / adapter.vram as f64
            );
            vram_clear = Some((adapter.vram, text));
        }

        // ---- video memory full
        if adapter.vram >= VRAM_MIN_BYTES {
            let full: Vec<&(i64, &crate::gpu::AdapterSample)> =
                samples.iter().filter(|(_, a)| a.dedicated as f64 >= VRAM_FULL * adapter.vram as f64).collect();
            if full.len() >= 3.max(samples.len() / 20) {
                let worst = full.iter().max_by_key(|(_, a)| a.dedicated).unwrap().1;
                let mut evidence = format!(
                    "Its video memory was full ({} of {}) in {} of {} seconds.",
                    gb(worst.dedicated),
                    gb(adapter.vram),
                    full.len(),
                    samples.len()
                );
                let mut spilled = 0;
                if let Some((pid, dedicated, shared)) = worst.top_memory {
                    spilled = shared;
                    evidence.push_str(&format!(" {} held {} of it", name_of(pid), gb(dedicated)));
                    evidence.push_str(&if shared >= 500_000_000 {
                        format!(", and another {} of its graphics data had been pushed out to system RAM.", gb(shared))
                    } else {
                        ".".to_string()
                    });
                }
                let near = ms_to_ticks(1500.0);
                let hits = marks.iter().filter(|m| full.iter().any(|(ts, _)| (*ts - **m).abs() <= near)).count();
                if hits > 0 {
                    evidence.push_str(&format!(" {hits} of the {} moments you flagged happened while it was full.", marks.len()));
                }
                findings.push(GpuFinding {
                    key: format!("gpu vram {}", adapter.luid),
                    severity: if hits > 0 || spilled >= 1_000_000_000 { Severity::High } else { Severity::Medium },
                    title: format!("{}  -  video memory is full", adapter.name),
                    evidence,
                    advice: VRAM_ADVICE,
                });
            }
        }
    }

    // ---- what the GPU was doing at the flagged moments: only the adapter doing the work counts
    if !marks.is_empty() {
        let near = ms_to_ticks(1500.0);
        let peak_of = |adapter: &crate::gpu::Adapter| {
            log.samples.iter().filter_map(|s| s.adapters.iter().find(|a| a.luid == adapter.luid)).map(|a| a.busy).fold(0.0, f64::max)
        };
        let mut best: Option<(&crate::gpu::Adapter, Vec<f64>)> = None;
        for adapter in &log.adapters {
            let at_marks: Vec<f64> = marks
                .iter()
                .filter_map(|m| {
                    log.samples
                        .iter()
                        .filter(|s| (s.ts - *m).abs() <= near)
                        .filter_map(|s| s.adapters.iter().find(|a| a.luid == adapter.luid))
                        .map(|a| a.busy)
                        .reduce(f64::max)
                })
                .collect();
            let total: f64 = at_marks.iter().sum();
            if !at_marks.is_empty() && best.as_ref().is_none_or(|(_, b)| total > b.iter().sum::<f64>()) {
                best = Some((adapter, at_marks));
            }
        }
        if let Some((adapter, at_marks)) = best {
            let bound = at_marks.iter().filter(|b| **b >= GPU_BOUND).count();
            let waiting = at_marks.iter().filter(|b| **b < GPU_WAITING).count();
            let typical = at_marks.iter().sum::<f64>() / at_marks.len() as f64;
            lines.push(format!("  at the {} moment(s) you flagged, {} was {typical:.0}% busy on average", at_marks.len(), adapter.name));
            if bound * 2 > at_marks.len() {
                findings.push(GpuFinding {
                    key: "gpu bound".into(),
                    severity: Severity::Medium,
                    title: format!("{}  -  working flat out when you felt the hitches", adapter.name),
                    evidence: format!("It was {GPU_BOUND:.0}% busy or more at {bound} of the {} moments you flagged.", at_marks.len()),
                    advice: GPU_BOUND_ADVICE,
                });
            } else if waiting * 2 > at_marks.len() && peak_of(adapter) >= GPU_WORKED {
                findings.push(GpuFinding {
                    key: "gpu waiting".into(),
                    severity: Severity::Low,
                    title: format!("{}  -  not the bottleneck when you felt the hitches", adapter.name),
                    evidence: format!(
                        "It was under {GPU_WAITING:.0}% busy at {waiting} of the {} moments you flagged ({typical:.0}% on average).",
                        at_marks.len()
                    ),
                    advice: GPU_WAITING_ADVICE,
                });
            }
        }
    }
    let vram_clear = if findings.iter().any(|f| f.key.starts_with("gpu vram")) { None } else { vram_clear.map(|(_, text)| text) };
    GpuReport { findings, lines, vram_clear }
}

/// Title for a process blamed for CPU time. Parts of Windows are named as such: nobody can close
/// "System", and calling it a program sends people looking for something that does not exist.
fn process_title(label: &str) -> String {
    let name = process_name_only(label);
    if name.starts_with("System") {
        return "Windows kernel (the System process)  -  a driver, or Windows itself".to_string();
    }
    match known_worker(&name) {
        Some(w) if w.windows => format!("{name}  -  part of Windows: {}", w.what),
        Some(w) => format!("{name}  -  {}", w.what),
        None => format!("{name}  -  program"),
    }
}

/// What to try for a process blamed for CPU time; never "close it" for something that is Windows.
fn process_advice(label: &str) -> String {
    let name = process_name_only(label);
    if name.starts_with("System") {
        return "This is not a program you can close: it is where Windows runs the work of drivers and of the kernel itself. The \
                driver behind it is usually named under 'Kernel-mode time by module' for that stall in the event log below: update \
                or roll back that driver. If only ntoskrnl.exe appears there, suspect storage, memory pressure or power management: \
                check the disk and drive-health findings in this report, update the chipset driver and the BIOS."
            .to_string();
    }
    match known_worker(&name) {
        Some(w) if w.windows => format!(
            "{name} is part of Windows ({}), not something you can close. {} If it keeps showing up, the driver it leans on is \
             listed under 'Kernel-mode time by module' for that stall in the event log.",
            w.what, w.tip
        ),
        Some(w) => format!("{} Then monitor again; if the stalls are gone, that was it.", w.tip),
        None => "Close this program and monitor again. If the stalls disappear, update or replace it, or look at the driver it \
                 leans on (listed under 'Kernel-mode time by module' in the event log)."
            .to_string(),
    }
}

const MEMORY_ERROR_ADVICE: &str = "The PC corrected these errors, but each one pauses everything briefly and they are a warning sign: \
    uncorrected ones crash programs and corrupt files. The usual cause is a memory overclock profile that is not quite stable: in the \
    BIOS turn XMP / EXPO / DOCP off (or lower the memory speed one step) and monitor again. Update the BIOS. If errors continue at \
    default settings, reseat the memory sticks and test them one at a time with MemTest86 or Windows Memory Diagnostic; replace the \
    one that fails.";

const PROCESSOR_ERROR_ADVICE: &str = "The processor reported errors it could correct; each one pauses everything briefly, and the \
    uncorrected kind crashes the PC. The usual cause is settings pushed past stable: in the BIOS remove any undervolt, Curve Optimizer \
    / PBO tuning or overclock (loading 'optimized defaults' does all of that), then monitor again. Update the BIOS and check CPU \
    temperatures under load. If errors continue at default settings the CPU or motherboard may be faulty: use the warranty.";

const PCIE_ERROR_ADVICE: &str = "Data on this PCI Express link arrived damaged and had to be sent again, which stalls the device and \
    everything waiting on it. Reseat the card or M.2 drive; if a riser or extension cable is used, that is the prime suspect: test \
    without it, or set that slot to a lower PCIe generation (Gen 4 -> Gen 3) in the BIOS. Also try Power Options > PCI Express > \
    Link State Power Management = Off, update the BIOS and chipset driver, and try another slot.";

const FATAL_ERROR_ADVICE: &str = "The PC crashed, froze or restarted because of a hardware error, not because of software. Load \
    'optimized defaults' in the BIOS to remove every overclock, undervolt and memory profile (XMP / EXPO), update the BIOS, and check \
    temperatures and that all power cables are firmly seated. If it still happens at default settings, test the memory (MemTest86) \
    and suspect the power supply, CPU or motherboard.";

/// Fewest stalls worth reading a pattern into, and the share of them that has to be on
/// efficiency cores before it is one.
const ECORE_MIN_STALLS: usize = 3;
const ECORE_SHARE: f64 = 0.8;

/// Were the stalls concentrated on the slow (efficiency) cores of a hybrid CPU?
///
/// `hit` is the CPUs each stall or flagged moment held up. It counts as an E-core stall only
/// when every CPU it hit was an efficiency core. The rule deliberately stays narrow: at least
/// 3 stalls, at least 80% of them on E-cores, and only where the E-cores are at most half of
/// the logical CPUs -- otherwise most stalls land on an E-core on any machine, simply because
/// most cores are E-cores, and that says nothing.
///
/// Returns (stalls on E-cores, stalls that named a CPU, the cores involved).
fn e_core_concentration(topo: &Topology, hit: &[Vec<u16>]) -> Option<(usize, usize, Vec<u16>)> {
    if !topo.hybrid() || topo.efficiency_cpus() * 2 > topo.total() {
        return None;
    }
    let named: Vec<&Vec<u16>> = hit.iter().filter(|c| !c.is_empty()).collect();
    let on_e: Vec<&&Vec<u16>> = named.iter().filter(|c| c.iter().all(|cpu| topo.is_efficiency(*cpu))).collect();
    if named.len() < ECORE_MIN_STALLS || (on_e.len() as f64) < named.len() as f64 * ECORE_SHARE {
        return None;
    }
    let mut cores: Vec<u16> = on_e.iter().flat_map(|c| c.iter().copied()).collect();
    cores.sort_unstable();
    cores.dedup();
    Some((on_e.len(), named.len(), cores))
}

/// What this finding may claim is limited to what the probes measure and what Microsoft documents.
/// The probes are pinned one per core, so a stall on an E-core means a driver or interrupt held
/// THAT core; it does not show what program was running there. Microsoft's Quality of Service page
/// (<https://learn.microsoft.com/windows/win32/procthread/quality-of-service>) documents which work
/// is sent to efficient cores: Eco QoS (Task Manager's "Efficiency mode") "always ... schedules to
/// efficient cores", and on battery so do windows that are not visible (Low) and background
/// services (Utility). It does not say that foreground work stays off E-cores, so that is not
/// claimed. Efficiency mode is toggled per process by right-clicking it on Task Manager's
/// Processes tab; a green leaf marks it.
const ECORE_ADVICE: &str = "This is a lead, not a verdict: it tells you where the stalls were, not who was waiting there. Two things \
    Windows documents as sending a program to the efficiency cores are worth ruling out. Open Task Manager, and on the Processes tab \
    check that the game or app you care about does not have 'Efficiency mode' switched on (a small green leaf next to its name): \
    right-click it to turn that off. On a laptop, plug in the charger: on battery, Windows moves background work and windows that \
    are not in view to the efficiency cores. The findings above say what caused the stalls themselves.";

/// (bus, device, function)
type PciAddress = (u32, u32, u32);

/// A hardware error and a stall this close together are treated as one event. Event log times are
/// whole seconds and logging lags the error slightly.
const COINCIDE_S: i64 = 2;

/// How many of `stalls` fall within COINCIDE_S of any of `events` (Unix seconds).
fn coinciding(stalls: &[i64], events: &[i64]) -> usize {
    stalls.iter().filter(|s| events.iter().any(|e| (*e - **s).abs() <= COINCIDE_S)).count()
}

const SHUTDOWN_ADVICE: &str = "A blue screen names its stop code: search for that code together with your PC or motherboard model, and \
    update the driver it points at. A sudden restart or power-off with no blue screen is usually power or heat: check CPU and GPU \
    temperatures under load, reseat the power cables, remove any overclock, undervolt or memory profile (XMP / EXPO) in the BIOS, \
    and suspect the power supply if it happens under load.";

/// One finding for the times Windows came back up without a clean shutdown.
fn shutdown_finding(events: &[UnexpectedShutdown], now: i64) -> Option<(Severity, String)> {
    // Someone holding the power button is a symptom (it had frozen), but not a crash by itself.
    let crashes: Vec<&UnexpectedShutdown> = events.iter().filter(|e| e.bugcheck != 0 || !e.power_button).collect();
    if crashes.is_empty() {
        return None;
    }
    let mut codes: Vec<u32> = crashes.iter().map(|e| e.bugcheck).filter(|c| *c != 0).collect();
    codes.sort();
    codes.dedup();
    let blue = crashes.iter().filter(|e| e.bugcheck != 0).count();
    let silent = crashes.len() - blue;
    let mut parts = Vec::new();
    if blue > 0 {
        let names: Vec<String> = codes
            .iter()
            .map(|c| match evlog::bugcheck_name(*c) {
                "" => format!("0x{c:X}"),
                name => format!("0x{c:X} {name}"),
            })
            .collect();
        parts.push(format!("{blue} blue screen{} (stop code {})", if blue == 1 { "" } else { "s" }, names.join(", ")));
    }
    if silent > 0 {
        parts.push(format!("{silent} sudden restart{} or power loss with no blue screen", if silent == 1 { "" } else { "s" }));
    }
    let times: Vec<i64> = crashes.iter().map(|e| e.unix_time).collect();
    let text = format!(
        "Windows event log: this PC went down without shutting down {}: {}.",
        when_text(&times, now, i64::MAX),
        parts.join(" and ")
    );
    Some((if crashes.len() >= 2 { Severity::Medium } else { Severity::Low }, text))
}

struct HardwareFinding {
    key: String,
    severity: Severity,
    title: String,
    evidence: String,
    advice: &'static str,
}

/// One finding per failing component from the WHEA events Windows logged.
/// `stalls` are the wall-clock times (Unix seconds) of this run's stalls and flagged moments.
fn hardware_findings(events: &[HardwareEvent], devices: &[PciDevice], stalls: &[i64], now: i64, run_start: i64) -> Vec<HardwareFinding> {
    // PCIe errors are grouped per bus address; everything else per kind.
    let mut groups: Vec<(HardwareKind, Option<PciAddress>)> = events
        .iter()
        .filter(|e| e.kind != HardwareKind::Other)
        .map(|e| (e.kind, e.pci.as_ref().map(|p| (p.bus, p.device, p.function))))
        .collect();
    groups.sort();
    groups.dedup();
    let mut out = Vec::new();
    for (kind, address) in groups {
        let members: Vec<&HardwareEvent> =
            events.iter().filter(|e| e.kind == kind && e.pci.as_ref().map(|p| (p.bus, p.device, p.function)) == address).collect();
        let times: Vec<i64> = members.iter().map(|e| e.unix_time).collect();
        let during = times.iter().any(|t| *t >= run_start);
        let when = when_text(&times, now, run_start);
        let ids = {
            let mut ids: Vec<u32> = members.iter().map(|e| e.id).collect();
            ids.sort();
            ids.dedup();
            ids.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(", ")
        };
        let source = format!("Windows event log, WHEA-Logger event {ids}");
        let (key, title, evidence, advice, floor) = match kind {
            HardwareKind::Memory => (
                "whea memory".to_string(),
                "Memory (RAM)  -  errors were detected and corrected".to_string(),
                format!("Corrected memory errors {when}. ({source}.)"),
                MEMORY_ERROR_ADVICE,
                Severity::Medium,
            ),
            HardwareKind::Processor => {
                let mut cpus: Vec<u32> = members.iter().filter_map(|e| e.apic_id).collect();
                cpus.sort();
                cpus.dedup();
                let on = match cpus.len() {
                    0 => String::new(),
                    1..=4 => {
                        format!(" Reported by logical processor {}.", cpus.iter().map(|c| c.to_string()).collect::<Vec<_>>().join(", "))
                    }
                    n => format!(" Reported by {n} different logical processors."),
                };
                (
                    "whea processor".to_string(),
                    "Processor  -  hardware errors were detected and corrected".to_string(),
                    format!("Corrected processor errors (cache, bus or interconnect) {when}.{on} ({source}.)"),
                    PROCESSOR_ERROR_ADVICE,
                    Severity::Medium,
                )
            }
            HardwareKind::PciExpress => {
                let pci = members.iter().find_map(|e| e.pci.as_ref());
                let name = pci.and_then(|p| pci::describe(devices, p.bus, p.device, p.function, p.secondary_bus));
                let place = match (pci, &name) {
                    (Some(p), Some(n)) => format!("{n} (PCI bus {}, device {}, function {})", p.bus, p.device, p.function),
                    (Some(p), None) => format!(
                        "the device at PCI bus {}, device {}, function {}{}",
                        p.bus,
                        p.device,
                        p.function,
                        p.hardware_id.as_ref().map_or(String::new(), |h| format!(" [{h}]"))
                    ),
                    (None, _) => "a PCI Express device Windows did not identify".to_string(),
                };
                (
                    format!("whea pcie {address:?}"),
                    format!("{}  -  PCI Express link errors", name.unwrap_or_else(|| "PCI Express device".to_string())),
                    format!("Corrected PCI Express errors on {place}, {when}. ({source}.)"),
                    PCIE_ERROR_ADVICE,
                    // A handful per week is common and harmless; a stream of them is not.
                    if times.len() >= 3 { Severity::Medium } else { Severity::Low },
                )
            }
            HardwareKind::Fatal => (
                "whea fatal".to_string(),
                "Hardware error  -  it crashed or restarted this PC".to_string(),
                format!("A fatal hardware error was recorded {when}. ({source}.)"),
                FATAL_ERROR_ADVICE,
                Severity::Medium,
            ),
            HardwareKind::Other => continue,
        };
        // An error is handled in firmware while the rest of the PC waits, so a stall at the same
        // moment is cause and effect, not coincidence.
        let hits = coinciding(stalls, &times);
        let evidence = if hits > 0 {
            format!("{evidence} {hits} of this run's stalls / flagged moments happened within {COINCIDE_S} seconds of one of these errors.")
        } else {
            evidence
        };
        out.push(HardwareFinding { key, severity: if during { Severity::High } else { floor }, title, evidence, advice });
    }
    out
}

/// "56 °C  |  1% of rated life used  |  spare 100%  |  0 media errors  |  16169 h powered on"
fn health_line(h: &DriveHealth) -> String {
    let mut parts = Vec::new();
    if let Some(t) = h.temperature() {
        parts.push(format!("{t} °C"));
    }
    if let Some(n) = &h.nvme {
        parts.push(format!("{}% of rated life used", n.percent_used));
        parts.push(format!("spare {}%", n.spare_percent));
        parts.push(format!("{} media errors", n.media_errors));
        parts.push(format!("{} min over temperature", n.warning_temp_minutes + n.critical_temp_minutes));
        parts.push(format!("{} h powered on", n.power_on_hours));
    }
    if let Some(s) = &h.sata {
        let show = |v: Option<u64>| v.map_or("n/a".to_string(), |v| v.to_string());
        parts.push(format!("reallocated {}", show(s.reallocated)));
        parts.push(format!("pending {}", show(s.pending)));
        parts.push(format!("uncorrectable {}", show(s.uncorrectable)));
        parts.push(format!("CRC errors {}", show(s.crc_errors)));
    }
    parts.join("  |  ")
}

/// "game.exe (1234)" -> "game.exe"
fn process_name_only(label: &str) -> String {
    match label.rsplit_once(" (") {
        Some((name, rest)) if rest.trim_end_matches(')').chars().all(|c| c.is_ascii_digit()) => name.to_string(),
        _ => label.to_string(),
    }
}

/// "3 times in the last 7 days (1 while monitoring), most recently 2 day(s) ago"
fn when_text(times: &[i64], now: i64, run_start: i64) -> String {
    let during = times.iter().filter(|t| **t >= run_start).count();
    let last = times.iter().copied().max().unwrap_or(now);
    let ago = match (now - last).max(0) {
        s if s < 3600 => "within the last hour".to_string(),
        s if s < 86_400 => format!("{} hour(s) ago", s / 3600),
        s => format!("{} day(s) ago", s / 86_400),
    };
    let during_txt = if during > 0 { format!(" ({during} while monitoring)") } else { String::new() };
    let plural = if times.len() == 1 { "" } else { "s" };
    format!("{} time{plural} in the last {EVENT_LOG_DAYS} days{during_txt}, most recently {ago}", times.len())
}

const EVENT_LOG_DAYS: u32 = 7;

/// Everything a finished run hands to the summary besides the analyzer's own state.
pub struct RunData<'a> {
    pub elapsed_s: f64,
    pub events_lost: u32,
    pub stats: &'a ProbeStats,
    pub exec_warn: i64,
    pub io_warn: i64,
    pub clock: &'a [ClockSample],
    pub gpu: &'a GpuLog,
}

impl Analyzer {
    pub fn summarize(&mut self, run: RunData) -> Summary {
        let RunData { elapsed_s, events_lost, stats, exec_warn, io_warn, clock, gpu } = run;
        let inner = self.shared.inner.lock().unwrap();
        let routines = inner.routines.clone();
        let faults = inner.faults_by_pid.clone();
        let disks = inner.disks.clone();
        let events = inner.events;
        let mut debug_counts: Vec<_> = inner.debug_counts.iter().map(|(k, v)| (*k, *v)).collect();
        let debug_rejected = inner.debug_rejected.clone();
        drop(inner);

        let now_unix = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64);
        let run_start_unix = now_unix - elapsed_s as i64 - 2;
        let storage_log = evlog::storage_events(EVENT_LOG_DAYS);

        let mut found = Findings::default();
        let mut details: Vec<String> = Vec::new();
        macro_rules! d {
            ($($a:tt)*) => { details.push(format!($($a)*)) };
        }

        // ---- Stalls, by who was blamed -------------------------------------------------
        let mut tally: HashMap<String, (u32, i64, i64)> = HashMap::new();
        for i in self.incidents.iter().filter(|i| !i.marked) {
            let t = tally.entry(i.culprit.clone()).or_default();
            t.0 += 1;
            t.1 += i.dur;
            t.2 = t.2.max(i.dur);
        }
        let mut tally: Vec<_> = tally.into_iter().collect();
        tally.sort_by_key(|(_, t)| std::cmp::Reverse(t.1));

        for (culprit, (n, total, worst)) in &tally {
            let sev = if *n >= 3 || *worst >= ms_to_ticks(15.0) { Severity::High } else { Severity::Medium };
            let stalls = format!("{n} stall{} (worst {}, {} in total)", if *n == 1 { "" } else { "s" }, fmt_dur(*worst), fmt_dur(*total));
            if let Some(m) = culprit.strip_prefix("driver ") {
                let what = self.modules.describe_short(m);
                let advice = knowledge(m).map(|k| k.advice).unwrap_or(GENERIC_DRIVER_ADVICE);
                found.add(culprit, sev, format!("{m}  -  {what}"), format!("Blamed for {stalls}."), advice.into(), *total);
            } else if culprit.starts_with("CPU went dark") {
                found.add(
                    culprit,
                    sev,
                    "Firmware / BIOS (SMI), a hypervisor, or a driver running with interrupts disabled".into(),
                    format!("The CPU vanished from Windows' view during {stalls}: no DPC/ISR ran and profiler interrupts went missing."),
                    DARK_ADVICE.into(),
                    *total,
                );
            } else if let Some(p) = culprit.strip_prefix("process ") {
                found.add(culprit, sev, process_title(p), format!("Was occupying the CPU during {stalls}."), process_advice(p), *total);
            } else if culprit == "unexplained" {
                let sev = if *n >= 3 { Severity::Medium } else { Severity::Low };
                found.add(
                    culprit,
                    sev,
                    "Stalls without an identifiable cause".into(),
                    format!("{stalls} where neither DPC/ISR activity nor CPU samples pointed at anything."),
                    "Monitor for longer while reproducing the problem so a pattern can emerge, and check the per-stall entries in \
                     the event log for a module or program that keeps appearing."
                        .into(),
                    *total,
                );
            } else if culprit.starts_with("CPU starvation") {
                found.add(
                    culprit,
                    Severity::Medium,
                    "All CPU cores were busy".into(),
                    format!("An ordinary thread could not get a core during {stalls}, and CPU sampling was unavailable to say who."),
                    "Check Task Manager for programs using a lot of CPU while the problem happens.".into(),
                    *total,
                );
            } else if *n >= 5 {
                found.add(
                    culprit,
                    Severity::Low,
                    "Scheduling delays while CPUs were idle".into(),
                    format!("{stalls}."),
                    "Usually harmless. If hitches persist, test the 'High performance' power plan (core parking can cause this).".into(),
                    *total,
                );
            }
        }

        // ---- Moments the user flagged ("I felt it") ----------------------------------------
        let mut marked: HashMap<String, (u32, i64)> = HashMap::new();
        for i in self.incidents.iter().filter(|i| i.marked) {
            let m = marked.entry(i.culprit.clone()).or_default();
            m.0 += 1;
            m.1 = m.1.max(i.dur);
        }
        let marks_total = self.marks_total;
        for (culprit, (n, worst)) in &marked {
            let sev = match *n {
                1 => Severity::Low,
                2 => Severity::Medium,
                _ => Severity::High,
            };
            let evidence = format!(
                "Was interrupting a CPU core (for up to {}) at {n} of the {marks_total} moment{} you flagged with 'I felt it'.",
                fmt_dur(*worst),
                if marks_total == 1 { "" } else { "s" }
            );
            if let Some(m) = culprit.strip_prefix("driver ") {
                let what = self.modules.describe_short(m);
                let advice = knowledge(m).map(|k| k.advice).unwrap_or(GENERIC_DRIVER_ADVICE);
                found.add(culprit, sev, format!("{m}  -  {what}"), evidence, advice.into(), *worst * *n as i64);
            } else if let Some(p) = culprit.strip_prefix("process ") {
                found.add(culprit, sev, process_title(p), evidence, process_advice(p), *worst * *n as i64);
            } else if culprit.starts_with("CPU went dark") {
                // Same key as the unmarked stalls of this kind, so both land in one finding.
                found.add(
                    culprit,
                    sev,
                    "Firmware / BIOS (SMI), a hypervisor, or a driver running with interrupts disabled".into(),
                    format!(
                        "At {n} of the {marks_total} moment{} you flagged, a CPU core vanished from Windows' view (for up to {}): no \
                         DPC/ISR ran and profiler interrupts went missing.",
                        if marks_total == 1 { "" } else { "s" },
                        fmt_dur(*worst)
                    ),
                    DARK_ADVICE.into(),
                    *worst * *n as i64,
                );
            } else {
                // A core was held up, but the trace cannot say by what. Still owed to the user:
                // every flagged moment has to show up somewhere in the result.
                found.add(
                    "unexplained",
                    if *n >= 3 { Severity::Medium } else { Severity::Low },
                    "Stalls without an identifiable cause".into(),
                    format!(
                        "At {n} of the {marks_total} moment{} you flagged, a CPU core was held up (for up to {}), but neither DPC/ISR \
                         activity nor CPU samples pointed at anything.",
                        if marks_total == 1 { "" } else { "s" },
                        fmt_dur(*worst)
                    ),
                    "Monitor for longer while reproducing the problem so a pattern can emerge, and check the flagged entries in the \
                     event log for a module or program that keeps appearing."
                        .into(),
                    *worst * *n as i64,
                );
            }
        }
        if self.marks_clean > 0 {
            found.add(
                "clean marks",
                Severity::Low,
                "Hitches you flagged that left no trace on the CPU side".into(),
                format!(
                    "At {} of the {marks_total} moment{} you flagged, no CPU core was held up long enough to feel (3 ms) and nothing else stood out.",
                    self.marks_clean,
                    if marks_total == 1 { "" } else { "s" }
                ),
                "That rules out drivers, interrupts and firmware for those hitches. Look inside the app or at the GPU: shader \
                 compilation, VRAM running out (lower texture quality), frame pacing / V-Sync settings, overlays, or the game's own \
                 asset streaming."
                    .into(),
                0,
            );
        }

        // ---- Hybrid CPUs: work that kept landing on the efficiency cores -------------------
        let hit: Vec<Vec<u16>> = self.incidents.iter().map(|i| i.cpus.clone()).collect();
        if let Some((on_e, named, cores)) = e_core_concentration(&self.topo, &hit) {
            let list = cores.iter().map(|c| c.to_string()).collect::<Vec<_>>().join(", ");
            found.add(
                "e-core stalls",
                Severity::Low,
                "Most stalls were on the processor's efficiency cores (E-cores)".into(),
                format!(
                    "{on_e} of the {named} stalls held up an efficiency core (CPU {list}). This processor pairs those with faster \
                     performance cores (P-cores). Only programs running on the stalled cores were held up by these."
                ),
                ECORE_ADVICE.into(),
                0,
            );
        }

        // ---- Drivers: DPC/ISR execution times ---------------------------------------------
        let mut mods: HashMap<String, DriverAgg> = HashMap::new();
        for ((routine, kind), st) in &routines {
            let a = mods.entry(self.modules.name(*routine)).or_default();
            if *kind == KIND_ISR {
                a.isr_n += st.count;
                a.isr_max = a.isr_max.max(st.max);
            } else {
                a.dpc_n += st.count;
                a.dpc_max = a.dpc_max.max(st.max);
            }
            a.total += st.total;
            a.over += st.over_warn;
        }
        let mut drivers: Vec<_> = mods.into_iter().collect();
        drivers.sort_by_key(|(_, a)| std::cmp::Reverse(a.dpc_max.max(a.isr_max)));

        for (name, a) in &drivers {
            let worst = a.dpc_max.max(a.isr_max);
            if worst < exec_warn {
                continue;
            }
            let sev = if worst >= ms_to_ticks(4.0) && a.over >= 3 { Severity::High } else { Severity::Medium };
            let what = self.modules.describe_short(name);
            let advice = knowledge(name).map(|k| k.advice).unwrap_or(GENERIC_DRIVER_ADVICE);
            found.add(
                &format!("driver {name}"),
                sev,
                format!("{name}  -  {what}"),
                format!(
                    "Its interrupt handling ran for up to {} at a time ({} time{} over {}). Healthy drivers stay under 0.5 ms; \
                     longer runs block everything else on that CPU core and cause audio crackle and micro-stutter.",
                    fmt_dur(worst),
                    a.over,
                    if a.over == 1 { "" } else { "s" },
                    fmt_dur(exec_warn)
                ),
                advice.into(),
                worst * a.over.max(1) as i64,
            );
        }

        // ---- Paging ------------------------------------------------------------------
        let mut faults_named: HashMap<String, LatStat> = HashMap::new();
        for (pid, st) in faults {
            let e = faults_named.entry(self.procs.label(pid, 0)).or_default();
            e.count += st.count;
            e.total += st.total;
            e.max = e.max.max(st.max);
        }
        let mut faults_named: Vec<_> = faults_named.into_iter().collect();
        faults_named.sort_by_key(|(_, s)| std::cmp::Reverse(s.total));
        let mem = memory_load();
        for (name, s) in &faults_named {
            if s.total < ms_to_ticks(1000.0) && s.max < ms_to_ticks(200.0) {
                continue;
            }
            let sev = if s.total >= ms_to_ticks(5000.0) { Severity::High } else { Severity::Medium };
            let advice = if mem >= 85 {
                format!(
                    "Memory is {mem}% full, so Windows keeps pushing programs out to disk. Close memory-hungry programs \
                     (browsers with many tabs are the usual one) or add RAM."
                )
            } else {
                format!(
                    "Memory is only {mem}% full, so this is more likely the program starting up or loading data than a RAM \
                     shortage. It matters only if this is the program that hitches; if so, move it to a faster drive (SSD)."
                )
            };
            found.add(
                &format!("paging {name}"),
                sev,
                format!("{name}  -  waiting for memory to be read back from disk"),
                format!("Frozen by {} hard page faults for {} in total (longest {}).", s.count, fmt_dur(s.total), fmt_dur(s.max)),
                advice,
                s.total,
            );
        }

        // ---- Disks -------------------------------------------------------------------
        let mut disks: Vec<_> = disks.into_iter().collect();
        disks.sort_by_key(|(n, _)| *n);
        for (n, s) in &disks {
            if s.slow == 0 {
                continue;
            }
            let sev = if s.max >= ms_to_ticks(1000.0) || s.slow >= 10 { Severity::High } else { Severity::Medium };
            let disk = self.disks.get(*n).clone();
            let mut evidence = format!(
                "{} request{} took longer than {} (worst {}).",
                s.slow,
                if s.slow == 1 { "" } else { "s" },
                fmt_dur(io_warn),
                fmt_dur(s.max)
            );
            for extra in [disk.hardware(), disk.fullness()] {
                if !extra.is_empty() {
                    evidence.push_str(&format!(" {}{}.", extra[..1].to_uppercase(), &extra[1..]));
                }
            }
            let key = format!("disk {n}");
            let why = self.disk_why.get(n);
            let logged = storage_log.iter().any(|e| e.disk == Some(*n));
            let advice = disk_advice(&disk, why, logged);
            found.add(&key, sev, format!("{}  -  responding slowly", disk.title()), evidence, advice, s.max * s.slow as i64);
            for sentence in why.map(why_sentences).unwrap_or_default() {
                found.note(&key, sentence);
            }
        }

        // ---- What Windows itself logged about storage ---------------------------------------
        // Per disk where the event names one; controller resets (129) only name the adapter.
        let mut logged: Vec<(Option<u32>, u32)> = storage_log.iter().map(|e| (e.disk, e.id)).collect();
        logged.sort();
        logged.dedup();
        for (disk_n, id) in logged {
            let times: Vec<i64> = storage_log.iter().filter(|e| e.disk == disk_n && e.id == id).map(|e| e.unix_time).collect();
            let during = times.iter().any(|t| *t >= run_start_unix);
            let text = format!("Windows event log: {} (event {id}), {}.", evlog::meaning(id), when_text(&times, now_unix, run_start_unix));
            let (key, title, advice) = match disk_n {
                Some(n) => {
                    let disk = self.disks.get(n).clone();
                    (format!("disk {n}"), format!("{}  -  errors in the Windows event log", disk.title()), disk_advice(&disk, None, true))
                }
                None => (
                    "storage controller".to_string(),
                    "Storage controller  -  a drive stopped answering and was reset".to_string(),
                    CONTROLLER_RESET_ADVICE.to_string(),
                ),
            };
            if !found.note(&key, text.clone()) {
                // Old entries alone are a lead, not a verdict.
                let sev = if during {
                    Severity::High
                } else if times.len() >= 3 {
                    Severity::Medium
                } else {
                    Severity::Low
                };
                found.add(&key, sev, title, text, advice, 0);
            }
        }

        // ---- What the drives say about themselves ------------------------------------------------
        let mut health_lines: Vec<String> = Vec::new();
        for n in self.disks.present() {
            let disk = self.disks.get(n).clone();
            let now = health::read(n, disk.bus);
            if now.is_empty() {
                health_lines.push(format!(
                    "  disk {n:<3} not readable ({})",
                    if disk.bus == "USB" { "USB enclosures usually block it" } else { "driver refused" }
                ));
                continue;
            }
            health_lines.push(format!("  disk {n:<3} {}", health_line(&now)));
            let key = format!("disk {n}");
            for (sev, text, advice) in health_findings(disk.spinning == Some(true), self.health_at_start.get(&n), &now) {
                if found.note(&key, text.clone()) {
                    found.raise(&key, sev);
                    found.advise(&key, advice);
                } else {
                    found.add(&key, sev, format!("{}  -  drive health warning", disk.title()), text, advice.to_string(), 0);
                }
            }
        }

        // ---- Graphics driver resets (TDR) ---------------------------------------------------------
        let display_log = evlog::display_resets(EVENT_LOG_DAYS);
        let mut reset_drivers: Vec<String> = display_log.iter().map(|e| e.driver.to_lowercase()).collect();
        reset_drivers.sort();
        reset_drivers.dedup();
        for driver in reset_drivers {
            let times: Vec<i64> = display_log.iter().filter(|e| e.driver.eq_ignore_ascii_case(&driver)).map(|e| e.unix_time).collect();
            let file = format!("{driver}.sys");
            let what = knowledge(&file).map_or("graphics driver", |k| k.what);
            let text = format!(
                "Windows event log: the graphics driver stopped responding and was reset (event 4101), {}.",
                when_text(&times, now_unix, run_start_unix)
            );
            let sev = if times.iter().any(|t| *t >= run_start_unix) { Severity::High } else { Severity::Medium };
            // Same subject as a driver blamed for stalls, so both land in one finding.
            let wanted = format!("driver {file}");
            let key = found.0.iter().map(|(k, _)| k.clone()).find(|k| k.eq_ignore_ascii_case(&wanted)).unwrap_or(wanted);
            if found.note(&key, text.clone()) {
                found.raise(&key, sev);
                found.advise(&key, DISPLAY_RESET_ADVICE);
            } else {
                found.add(&key, sev, format!("{file}  -  {what}: it hung and was reset"), text, DISPLAY_RESET_ADVICE.to_string(), 0);
            }
        }

        // ---- Graphics card: video memory and load ---------------------------------------------------
        let mark_times = self.mark_times.clone();
        let gpu_report = gpu_findings(gpu, &mark_times, &mut |pid| process_name_only(&self.procs.label(pid, 0)));
        let gpu_lines = gpu_report.lines;
        for f in gpu_report.findings {
            found.add(&f.key, f.severity, f.title, f.evidence, f.advice.to_string(), 0);
        }
        // "Look at the GPU: VRAM running out..." is a guess the measurements can now retire.
        if let Some(clear) = &gpu_report.vram_clear {
            if found.note("clean marks", format!("Video memory was not the problem: {clear}.")) {
                // ...so stop suggesting it.
                if let Some((_, f)) = found.0.iter_mut().find(|(k, _)| k == "clean marks") {
                    f.advice = f.advice.replace("VRAM running out (lower texture quality), ", "");
                }
            }
        }

        // ---- Hardware errors Windows logged (WHEA) ----------------------------------------------
        let hardware_log = evlog::hardware_events(EVENT_LOG_DAYS);
        if !hardware_log.is_empty() {
            // QPC -> wall clock, anchored at "now"; good to well under the 2 s matching window.
            let (qpc_now, freq) = (qpc(), qpc_freq());
            let wall = |ticks: i64| now_unix - (qpc_now - ticks) / freq;
            let stall_times: Vec<i64> = self.incidents.iter().map(|i| wall(i.start)).collect();
            let whea_times: Vec<i64> = hardware_log.iter().filter(|e| e.kind != HardwareKind::Other).map(|e| e.unix_time).collect();
            for f in hardware_findings(&hardware_log, &pci::devices(), &stall_times, now_unix, run_start_unix) {
                found.add(&f.key, f.severity, f.title, f.evidence, f.advice.to_string(), 0);
            }
            // "The CPU went dark" is exactly what firmware handling a hardware error looks like.
            let dark: Vec<i64> = self.incidents.iter().filter(|i| i.culprit.starts_with("CPU went dark")).map(|i| wall(i.start)).collect();
            let explained = coinciding(&dark, &whea_times);
            if explained > 0 {
                let keys: Vec<String> = found.0.iter().map(|(k, _)| k.clone()).filter(|k| k.starts_with("CPU went dark")).collect();
                for key in keys {
                    found.note(
                        &key,
                        format!(
                            "{explained} of these happened within {COINCIDE_S} seconds of a hardware error Windows logged (see the hardware \
                             finding): the firmware was busy handling that error."
                        ),
                    );
                }
            }
        }

        // ---- Crashes and sudden power loss ----------------------------------------------------------
        let shutdown_log = evlog::unexpected_shutdowns(EVENT_LOG_DAYS);
        if let Some((sev, text)) = shutdown_finding(&shutdown_log, now_unix) {
            // A fatal hardware error already explains a crash; otherwise it stands alone.
            if !found.note("whea fatal", text.clone()) {
                found.add(
                    "unexpected shutdowns",
                    sev,
                    "This PC crashed or lost power unexpectedly".into(),
                    text,
                    SHUTDOWN_ADVICE.into(),
                    0,
                );
            }
        }

        // ---- Does it keep time? ------------------------------------------------------------
        let mut periodic_noted = false;
        let culprits: Vec<String> = tally.iter().map(|(c, _)| c.clone()).collect();
        for culprit in culprits {
            let times: Vec<i64> = self.incidents.iter().filter(|i| !i.marked && i.culprit == culprit).map(|i| i.start).collect();
            if let Some(p) = period::detect(&secs(&times)) {
                periodic_noted |= found.note(&culprit, format!("The stalls keep time. {}", p.describe()));
            }
        }
        for (module, times) in &self.long_exec_times {
            if let Some(p) = period::detect(&secs(times)) {
                periodic_noted |= found.note(&format!("driver {module}"), format!("Its long interrupt runs keep time. {}", p.describe()));
            }
        }
        if !periodic_noted {
            let all: Vec<i64> = self.incidents.iter().filter(|i| !i.marked).map(|i| i.start).collect();
            if let Some(p) = period::detect(&secs(&all)) {
                found.add("periodic", Severity::Medium, "Stalls repeat on a timer".into(), p.describe(), POLLING_ADVICE.into(), 0);
            }
        } else {
            for (_, f) in found.0.iter_mut().filter(|(_, f)| f.evidence.iter().any(|e| e.contains("keep time"))) {
                f.advice = format!(
                    "{} Because it repeats on a timer: {}",
                    f.advice,
                    POLLING_ADVICE.to_lowercase().replacen("something", "something software-driven", 1)
                );
            }
        }

        // ---- CPU throttling ----------------------------------------------------------------
        let throttled: Vec<&ClockSample> = clock.iter().filter(|c| c.throttled()).collect();
        if throttled.len() >= 3.max(clock.len() / 20) {
            let near = ms_to_ticks(1500.0);
            let hits = self.incidents.iter().filter(|i| throttled.iter().any(|c| (c.ts - i.start).abs() <= near)).count();
            let share = throttled.len() as f64 / clock.len() as f64;
            let sev = if share >= 0.3 || (hits >= 2 && hits * 2 >= self.incidents.len()) { Severity::High } else { Severity::Medium };
            let slowest = throttled.iter().map(|c| c.min_busy_perf).fold(100.0, f64::min);
            let cap = throttled.iter().map(|c| c.limit).fold(100.0, f64::min);
            let mut evidence = format!(
                "In {} of {} seconds, cores that were busy ran at as little as {slowest:.0}% of their rated speed.",
                throttled.len(),
                clock.len()
            );
            if cap < 99.5 {
                evidence.push_str(&format!(" Windows reported an active performance cap down to {cap:.0}% (thermal or power limit)."));
            }
            if hits > 0 {
                evidence
                    .push_str(&format!(" {hits} of {} stalls / flagged moments happened while it was throttled.", self.incidents.len()));
            }
            found.add(
                "throttling",
                sev,
                "CPU throttling  -  the processor is being slowed down".into(),
                evidence,
                THROTTLE_ADVICE.into(),
                ms_to_ticks(1000.0) * throttled.len() as i64,
            );
        }

        // Windows logs when firmware (not the OS) caps the processor. Some PCs log it at every boot,
        // so older entries only back up a throttling finding; one during the run stands by itself.
        let firmware_caps = evlog::firmware_throttle_times(EVENT_LOG_DAYS);
        let caps_during = firmware_caps.iter().filter(|t| **t >= run_start_unix).count();
        if !firmware_caps.is_empty() {
            let text = format!(
                "Windows event log: firmware limited the processor's speed (Kernel-Processor-Power event 37), {}.",
                when_text(&firmware_caps, now_unix, run_start_unix)
            );
            if found.note("throttling", text.clone()) {
                if caps_during > 0 {
                    found.raise("throttling", Severity::High);
                }
            } else if caps_during > 0 {
                found.add(
                    "throttling",
                    Severity::Medium,
                    "CPU throttling  -  firmware is limiting the processor's speed".into(),
                    text,
                    THROTTLE_ADVICE.into(),
                    0,
                );
            }
        }

        // ---- Say which device each blamed driver belongs to, and how old the driver is ----------
        let device_map = DeviceMap::load();
        let today = devices::today();
        name_devices(&mut found, &device_map, today);

        let mut findings: Vec<Finding> = found.0.into_iter().map(|(_, f)| f).collect();
        findings.sort_by_key(|f| (std::cmp::Reverse(f.severity), std::cmp::Reverse(f.impact)));

        // ---- Verdict -----------------------------------------------------------------
        let kernel_stalls = self.incidents.iter().filter(|i| !i.marked && i.kind == StallKind::Kernel).count();
        let sched_stalls = self.incidents.iter().filter(|i| !i.marked).count() - kernel_stalls;
        let secs = elapsed_s as u64;
        let mut overview = vec![
            format!("Monitored:        {:02}:{:02}", secs / 60, secs % 60),
            format!("Stalls detected:  {kernel_stalls} kernel-level, {sched_stalls} CPU-starvation"),
        ];
        if marks_total > 0 {
            overview.push(format!("Flagged by you:   {marks_total} moment(s), {} with nothing on the system side", self.marks_clean));
        }
        overview.push(format!(
            "Worst wake-up:    {} real-time thread, {} normal thread",
            fmt_dur(stats.max_kernel.load(Ordering::Relaxed)),
            fmt_dur(stats.max_sched.load(Ordering::Relaxed))
        ));

        let more =
            |n: usize| if n > 1 { format!("  (+{} more finding{} below)", n - 1, if n == 2 { "" } else { "s" }) } else { String::new() };
        let top = findings.first();
        let (health, mut headline, mut subline) = if events == 0 {
            (
                Health::NoData,
                "Windows delivered no kernel trace data".to_string(),
                "Nothing can be concluded from this run. Another profiler may be holding the kernel trace, or security software \
                 blocked it. Close tools like LatencyMon, WPR/xperf or Process Monitor and try again."
                    .to_string(),
            )
        } else {
            match top.map(|f| f.severity) {
                Some(Severity::High) => {
                    let f = top.unwrap();
                    (Health::Problem, f.title.clone(), format!("{}{}", f.evidence[0], more(findings.len())))
                }
                Some(Severity::Medium) => {
                    let f = top.unwrap();
                    (Health::Warning, f.title.clone(), format!("{}{}", f.evidence[0], more(findings.len())))
                }
                _ => {
                    let short = if secs < 60 { " This was a short run; a few minutes gives a more reliable answer." } else { "" };
                    (
                        Health::Ok,
                        "Nothing stalled this PC while monitoring".to_string(),
                        format!(
                            "No driver, program, disk or firmware problem showed up.{short} If the hitch DID happen during this run, \
                             its cause is inside the app or on the GPU (shader compilation, VRAM overflow, frame pacing), which a \
                             CPU-side trace cannot see. If it did not happen, monitor again and reproduce it."
                        ),
                    )
                }
            }
        };

        if health == Health::Ok && self.marks_clean > 0 {
            headline = "The hitches you flagged did not come from drivers, interrupts or the CPU".to_string();
            subline = format!(
                "At {} of the {marks_total} moment(s) you flagged, no CPU core was held up long enough to feel and no disk, paging or \
                 throttling problem showed up. That clears the system side: look inside the app or at the GPU (shader compilation, \
                 VRAM running out, frame pacing, overlays).",
                self.marks_clean
            );
        }

        // ---- Supporting tables ---------------------------------------------------------
        d!("");
        d!("{events} kernel events processed, {events_lost} lost.");
        if self.notable_suppressed > 0 {
            d!("{} of {} individual slow-event lines were suppressed in the event log.", self.notable_suppressed, self.notable_total);
        }
        if !tally.is_empty() {
            d!("");
            d!("WHO CAUSED THE STALLS");
            d!("  {:<58} {:>6} {:>11} {:>11}", "culprit", "stalls", "total", "worst");
            for (name, (n, total, worst)) in &tally {
                d!("  {:<58} {:>6} {:>11} {:>11}", name, n, fmt_dur(*total), fmt_dur(*worst));
            }
        }
        if !drivers.is_empty() {
            d!("");
            d!("DRIVERS BY WORST DPC/ISR EXECUTION TIME  (healthy: DPC < 0.5 ms, ISR < 0.1 ms)");
            d!("  {:<24} {:>9} {:>10} {:>9} {:>10} {:>11} {:>7}", "driver", "DPCs", "worst DPC", "ISRs", "worst ISR", "total time", "slow");
            for (name, a) in drivers.iter().take(12) {
                d!(
                    "  {:<24} {:>9} {:>10} {:>9} {:>10} {:>11} {:>7}",
                    name,
                    a.dpc_n,
                    fmt_dur(a.dpc_max),
                    a.isr_n,
                    fmt_dur(a.isr_max),
                    fmt_dur(a.total),
                    a.over
                );
            }
            // Which device each third-party driver belongs to; Windows' own drivers need no legend.
            for (name, _) in drivers.iter().take(12) {
                if let (Some(title), Some(first)) = (device_map.device_title(name), device_map.get(name).first()) {
                    if !first.from_microsoft() {
                        d!("  {name} = {title}  |  {}", first.describe(today));
                    }
                }
            }
        }
        if !faults_named.is_empty() {
            d!("");
            d!("HARD PAGE FAULTS  (program frozen while memory is read back from disk; RAM {mem}% in use)");
            d!("  {:<40} {:>8} {:>12} {:>10}", "process", "faults", "total wait", "worst");
            for (name, s) in faults_named.iter().take(6) {
                d!("  {:<40} {:>8} {:>12} {:>10}", name, s.count, fmt_dur(s.total), fmt_dur(s.max));
            }
        }
        if !disks.is_empty() {
            d!("");
            d!("DISK LATENCY");
            d!("  {:<8} {:>10} {:>10} {:>10} {:>7}", "disk", "requests", "average", "worst", "slow");
            for (n, s) in &disks {
                d!("  {:<8} {:>10} {:>10} {:>10} {:>7}", n, s.count, fmt_dur(s.total / s.count.max(1) as i64), fmt_dur(s.max), s.slow);
            }
            for (n, _) in &disks {
                let disk = self.disks.get(*n);
                let about: Vec<String> =
                    [disk.letters(), disk.model.clone(), disk.hardware(), disk.fullness()].into_iter().filter(|s| !s.is_empty()).collect();
                if !about.is_empty() {
                    d!("  disk {n} = {}", about.join("  |  "));
                }
            }
        }
        if !gpu_lines.is_empty() {
            d!("");
            d!("GRAPHICS  (sampled once a second)");
            details.extend(gpu_lines);
        }
        if !health_lines.is_empty() {
            d!("");
            d!("DRIVE HEALTH  (what each drive reports about itself)");
            details.extend(health_lines);
        }
        d!("");
        d!("WINDOWS EVENT LOG  (last {EVENT_LOG_DAYS} days)");
        d!("  storage errors (resets, retries, bad blocks): {}", storage_log.len());
        d!("  graphics driver resets: {}", display_log.len());
        d!("  crashes / sudden power loss: {}", shutdown_log.iter().filter(|e| e.bugcheck != 0 || !e.power_button).count());
        d!("  firmware limited the processor's speed: {}", firmware_caps.len());
        d!(
            "  hardware errors (WHEA: memory, processor, PCI Express): {}",
            hardware_log.iter().filter(|e| e.kind != HardwareKind::Other).count()
        );
        if !clock.is_empty() {
            let busy: Vec<f64> = clock.iter().filter(|c| c.busy_cores > 0).map(|c| c.min_busy_perf).collect();
            d!("");
            d!("CPU CLOCK  (slowest busy core each second, % of rated speed; 100+ is normal)");
            if busy.is_empty() {
                d!("  no core was busy enough to judge in {} samples", clock.len());
            } else {
                d!(
                    "  lowest {:.0}%   typical {:.0}%   throttled in {} of {} seconds",
                    busy.iter().copied().fold(f64::MAX, f64::min),
                    busy.iter().sum::<f64>() / busy.len() as f64,
                    throttled.len(),
                    clock.len()
                );
            }
        }
        if !debug_counts.is_empty() {
            debug_counts.sort();
            d!("");
            d!("debug: events by (provider, opcode):");
            for ((guid, op), n) in debug_counts {
                d!("  {guid:08x} op {op:>3}: {n}");
            }
            for (ts, initial) in debug_rejected {
                d!("  rejected DPC/ISR: event ts {ts}, InitialTime {initial}, now {}", qpc());
            }
        }

        Summary { health, headline, subline, overview, findings, details }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn usb_hdd() -> DiskInfo {
        DiskInfo { number: 4, model: "Seagate FireCuda Dock".into(), bus: "USB", spinning: Some(true), ..Default::default() }
    }

    #[test]
    fn a_busy_disk_names_the_program_and_does_not_blame_the_drive() {
        let mut why = DiskWhy::default();
        why.causes.insert(Cause::Busy, 9);
        why.causes.insert(Cause::IdleSlow, 1);
        why.movers.insert("steam.exe".into(), 3_000_000_000);
        why.movers.insert("chrome.exe".into(), 100_000_000);
        let s = why_sentences(&why);
        assert!(
            s[0].contains("busy") && s[0].contains("9 of 10 times") && s[0].contains("steam.exe (3 GB, 97% of the traffic: Steam"),
            "{s:?}"
        );
        assert!(!s[0].contains("chrome"), "minor movers stay out: {s:?}");
        assert!(s[1].contains("not traffic"), "{s:?}");
        let advice = disk_advice(&usb_hdd(), Some(&why), false);
        assert!(advice.contains("steam.exe: Pause the download") && !advice.contains("failing"), "{advice}");

        // Windows' own work cannot be paused or closed, so the advice must not say so.
        let mut win = DiskWhy::default();
        win.causes.insert(Cause::Busy, 3);
        win.movers.insert("backgroundTaskHost.exe".into(), 50_000_000);
        let advice = disk_advice(&usb_hdd(), Some(&win), false);
        assert!(advice.contains("part of Windows") && advice.contains("run in background"), "{advice}");
        assert!(!advice.contains("pause it") && !advice.contains("Let backgroundTaskHost"), "{advice}");
    }

    #[test]
    fn a_sleeping_drive_gets_power_settings_and_logged_errors_override_everything() {
        let mut why = DiskWhy { longest_sleep_ms: 42_000.0, ..Default::default() };
        why.causes.insert(Cause::WokeUp, 2);
        assert!(why_sentences(&why)[0].contains("every time") && why_sentences(&why)[0].contains("42 s"));
        assert!(disk_advice(&usb_hdd(), Some(&why), false).contains("Turn off hard disk after"));
        let logged = disk_advice(&usb_hdd(), Some(&why), true);
        assert!(logged.contains("back up what matters now") && !logged.contains("Turn off hard disk"), "{logged}");
    }

    #[test]
    fn hardware_errors_become_one_finding_per_component() {
        use crate::evlog::PciRef;
        let now = 2_000_000;
        let ev = |unix_time, id, kind, apic_id, pci| HardwareEvent { unix_time, id, kind, apic_id, pci };
        let port = PciRef { bus: 0, device: 1, function: 1, secondary_bus: Some(1), hardware_id: None };
        let events = vec![
            ev(now - 90_000, 47, HardwareKind::Memory, None, None),
            ev(now - 50, 47, HardwareKind::Memory, None, None),
            ev(now - 80_000, 19, HardwareKind::Processor, Some(11), None),
            ev(now - 70_000, 17, HardwareKind::PciExpress, None, Some(port.clone())),
            ev(now - 60_000, 17, HardwareKind::PciExpress, None, Some(port)),
            ev(now - 60_000, 5, HardwareKind::Other, None, None),
        ];
        let devices = vec![PciDevice { bus: 1, device: 0, function: 0, name: "NVIDIA GeForce RTX 4090".into() }];
        let f = hardware_findings(&events, &devices, &[now - 49, now - 300], now, now - 600);
        assert_eq!(f.len(), 3, "memory, processor, one PCIe address; 'other' ignored");

        let mem = f.iter().find(|f| f.key == "whea memory").unwrap();
        assert_eq!(mem.severity, Severity::High, "it fired while monitoring");
        assert!(
            mem.evidence.contains("2 times") && mem.evidence.contains("1 while monitoring") && mem.advice.contains("XMP"),
            "{}",
            mem.evidence
        );

        let cpu = f.iter().find(|f| f.key == "whea processor").unwrap();
        assert_eq!(cpu.severity, Severity::Medium);
        assert!(cpu.evidence.contains("logical processor 11"), "{}", cpu.evidence);

        let gpu = f.iter().find(|f| f.key.starts_with("whea pcie")).unwrap();
        assert_eq!(gpu.severity, Severity::Low, "two corrected link errors in a week is only a lead");
        assert!(
            gpu.title.starts_with("NVIDIA GeForce RTX 4090") && gpu.evidence.contains("PCI bus 0, device 1, function 1"),
            "{}",
            gpu.evidence
        );
        assert!(mem.evidence.contains("1 of this run's stalls / flagged moments happened within 2 seconds"), "{}", mem.evidence);
        assert!(!cpu.evidence.contains("within 2 seconds"), "no stall near the processor error");
        assert!(hardware_findings(&[], &devices, &[], now, now - 600).is_empty());
    }

    #[test]
    fn drive_health_separates_what_happened_now_from_lifetime_totals() {
        use crate::health::{NvmeHealth, SataSmart};
        let nvme = |temperature_c, throttle_seconds, media_errors| DriveHealth {
            nvme: Some(NvmeHealth { temperature_c, throttle_seconds, media_errors, spare_percent: 100, ..Default::default() }),
            ..Default::default()
        };
        assert!(health_findings(false, Some(&nvme(45, 0, 0)), &nvme(48, 0, 0)).is_empty(), "a healthy drive says nothing");

        let f = health_findings(false, Some(&nvme(60, 100, 0)), &nvme(78, 130, 0));
        assert_eq!(f.len(), 1);
        assert!(f[0].0 == Severity::High && f[0].1.contains("30 s slowed down by heat while monitoring"), "{}", f[0].1);

        let f = health_findings(false, None, &nvme(74, 5000, 2));
        assert!(f.iter().any(|x| x.0 == Severity::Medium && x.1.contains("2 unrecoverable media error")));
        assert!(f.iter().any(|x| x.1.contains("74 °C") && x.2 == DRIVE_HOT_ADVICE), "hot now, no baseline to compare");

        let sata = |crc, pending| DriveHealth {
            sata: Some(SataSmart { crc_errors: Some(crc), pending: Some(pending), reallocated: Some(0), ..Default::default() }),
            ..Default::default()
        };
        let f = health_findings(true, Some(&sata(10, 0)), &sata(10, 0));
        assert!(f.len() == 1 && f[0].0 == Severity::Low && f[0].1.contains("none while monitoring"), "old CRC errors are only a lead");
        let f = health_findings(true, Some(&sata(10, 0)), &sata(14, 3));
        assert!(f.iter().any(|x| x.0 == Severity::High && x.1.contains("4 new CRC") && x.2 == DRIVE_CABLE_ADVICE));
        assert!(f.iter().any(|x| x.0 == Severity::High && x.1.contains("3 pending") && x.2 == DRIVE_FAILING_ADVICE));
    }

    #[test]
    fn blamed_drivers_are_named_after_their_device_and_old_ones_say_so() {
        use crate::devices::DeviceDriver;
        let mut found = Findings::default();
        found.add(
            "driver rtwlane.sys",
            Severity::High,
            "rtwlane.sys  -  Wi-Fi adapter driver".into(),
            "Blamed for 3 stalls.".into(),
            "Disable power saving.".into(),
            0,
        );
        found.add(
            "driver nvlddmkm.sys",
            Severity::High,
            "nvlddmkm.sys  -  NVIDIA GPU driver: it hung and was reset".into(),
            "e".into(),
            "a".into(),
            0,
        );
        found.add("driver wdfilter.sys", Severity::Medium, "wdfilter.sys  -  Microsoft Defender filter".into(), "e".into(), "a".into(), 0);
        found.add("disk 1", Severity::Medium, "Disk 1  -  responding slowly".into(), "e".into(), "a".into(), 0);
        let mut map = DeviceMap::default();
        let dev = |device: &str, provider: &str, date| DeviceDriver {
            device: device.into(),
            provider: provider.into(),
            version: "1.2".into(),
            date: Some(date),
        };
        map.insert_for_test(
            "rtwlane.sys",
            vec![dev("Realtek 8822CE Wireless LAN 802.11ac PCI-E NIC", "Realtek Semiconductor Corp.", (2021, 3, 4))],
        );
        map.insert_for_test("nvlddmkm.sys", vec![dev("NVIDIA GeForce RTX 5090", "NVIDIA", (2026, 9, 4))]);
        name_devices(&mut found, &map, (2026, 9, 20));

        let f = |key: &str| &found.0.iter().find(|(k, _)| k == key).unwrap().1;
        let wifi = f("driver rtwlane.sys");
        assert_eq!(wifi.title, "rtwlane.sys  -  Realtek 8822CE Wireless LAN 802.11ac PCI-E NIC");
        assert!(
            wifi.evidence.iter().any(|e| e.contains("dated 2021-03-04 (5 years old), from Realtek Semiconductor Corp.")),
            "{:?}",
            wifi.evidence
        );
        assert!(
            wifi.advice.starts_with("Start here: this driver is 5 years old") && wifi.advice.ends_with("Disable power saving."),
            "{}",
            wifi.advice
        );

        let gpu = f("driver nvlddmkm.sys");
        assert_eq!(gpu.title, "nvlddmkm.sys  -  NVIDIA GeForce RTX 5090: it hung and was reset");
        assert_eq!(gpu.advice, "a", "a current driver gets no 'update it' advice");
        assert_eq!(f("driver wdfilter.sys").title, "wdfilter.sys  -  Microsoft Defender filter", "no device: unchanged");
        assert_eq!(f("disk 1").title, "Disk 1  -  responding slowly");
    }

    #[test]
    fn crashes_are_summarized_and_forced_power_offs_alone_are_not() {
        let now = 3_000_000;
        let ev = |ago, bugcheck, power_button| UnexpectedShutdown { unix_time: now - ago, bugcheck, power_button };
        let (sev, text) = shutdown_finding(&[ev(90_000, 0x9F, false), ev(200_000, 0, false), ev(300_000, 0, true)], now).unwrap();
        assert_eq!(sev, Severity::Medium);
        assert!(
            text.contains("2 times in the last 7 days") && text.contains("1 blue screen (stop code 0x9F DRIVER_POWER_STATE_FAILURE)"),
            "{text}"
        );
        assert!(text.contains("1 sudden restart or power loss with no blue screen") && !text.contains("while monitoring"), "{text}");
        assert_eq!(shutdown_finding(&[ev(100, 0x999, false)], now).unwrap().0, Severity::Low);
        assert!(shutdown_finding(&[ev(100, 0x999, false)], now).unwrap().1.contains("stop code 0x999)"));
        assert!(shutdown_finding(&[ev(100, 0, true)], now).is_none(), "held power button only");
        assert_eq!(coinciding(&[100, 200, 300], &[102, 297, 1000]), 1, "3 s apart is outside the window");
        assert_eq!(coinciding(&[100, 200, 300], &[102, 298, 1000]), 2);
    }

    fn gpu_log(vram: u64, samples: &[(f64, f64, u64, u64)]) -> GpuLog {
        use crate::gpu::{Adapter, AdapterSample, GpuSample};
        let luid = "0x0_0x1".to_string();
        GpuLog {
            adapters: vec![Adapter { luid: luid.clone(), name: "NVIDIA GeForce RTX 4070".into(), vram }],
            samples: samples
                .iter()
                .map(|(t_s, busy, dedicated, shared)| GpuSample {
                    ts: ms_to_ticks(t_s * 1000.0),
                    adapters: vec![AdapterSample {
                        luid: luid.clone(),
                        busy: *busy,
                        busiest_engine: "3d".into(),
                        top_pid: Some(7),
                        dedicated: *dedicated,
                        shared: *shared,
                        top_memory: Some((7, *dedicated - 500_000_000, *shared)),
                    }],
                })
                .collect(),
        }
    }

    #[test]
    fn full_video_memory_is_a_finding_and_names_the_program() {
        const GB: u64 = 1_000_000_000;
        let samples: Vec<(f64, f64, u64, u64)> =
            (0..20).map(|i| (i as f64, 80.0, if i >= 10 { 11_600_000_000 } else { 6 * GB }, 2 * GB)).collect();
        let report = gpu_findings(&gpu_log(12 * GB, &samples), &[ms_to_ticks(15_000.0)], &mut |_| "game.exe".into());
        assert!(report.vram_clear.is_none(), "full memory must not also be declared fine");
        let vram = report.findings.iter().find(|f| f.key.starts_with("gpu vram")).expect("vram finding");
        assert_eq!(vram.severity, Severity::High);
        assert!(vram.title.starts_with("NVIDIA GeForce RTX 4070"), "{}", vram.title);
        assert!(vram.evidence.contains("full (11.6 GB of 12.0 GB) in 10 of 20 seconds"), "{}", vram.evidence);
        assert!(vram.evidence.contains("game.exe held 11.1 GB"), "{}", vram.evidence);
        assert!(vram.evidence.contains("2.0 GB of its graphics data had been pushed out"), "{}", vram.evidence);
        assert!(vram.evidence.contains("1 of the 1 moments you flagged happened while it was full"), "{}", vram.evidence);
        assert!(report.lines[0].contains("video memory peaked at 11.6 GB of 12.0 GB (97%)"), "{:?}", report.lines);

        // Half-empty memory is no finding, and it lets the report rule video memory out.
        let calm: Vec<(f64, f64, u64, u64)> = (0..20).map(|i| (i as f64, 30.0, 6 * GB, 0)).collect();
        let report = gpu_findings(&gpu_log(12 * GB, &calm), &[], &mut |_| String::new());
        assert!(report.findings.is_empty());
        assert_eq!(report.vram_clear.as_deref(), Some("NVIDIA GeForce RTX 4070 peaked at 6.0 GB of 12.0 GB (50%)"));

        // An integrated GPU's tiny carve-out is always "full" by design and is never judged.
        let igpu: Vec<(f64, f64, u64, u64)> = (0..20).map(|i| (i as f64, 30.0, 510_000_000, 0)).collect();
        let report = gpu_findings(&gpu_log(512_000_000, &igpu), &[], &mut |_| String::new());
        assert!(report.findings.is_empty() && report.vram_clear.is_none());
    }

    #[test]
    fn gpu_load_at_flagged_moments_says_which_side_to_look_at() {
        const GB: u64 = 1_000_000_000;
        let marks = [ms_to_ticks(5_000.0), ms_to_ticks(12_000.0), ms_to_ticks(18_000.0)];
        let keys = |r: &GpuReport| r.findings.iter().map(|f| f.key.clone()).collect::<Vec<_>>();

        let busy: Vec<(f64, f64, u64, u64)> = (0..20).map(|i| (i as f64, 99.0, 4 * GB, 0)).collect();
        let report = gpu_findings(&gpu_log(12 * GB, &busy), &marks, &mut |_| String::new());
        assert_eq!(keys(&report), ["gpu bound"]);
        assert!(report.findings[0].evidence.contains("3 of the 3"));

        // A game that loads the GPU most of the time, but not around the flagged moments.
        let dips: Vec<(f64, f64, u64, u64)> =
            (0..20).map(|i| (i as f64, if [4, 5, 6, 11, 12, 13, 17, 18, 19].contains(&i) { 45.0 } else { 97.0 }, 4 * GB, 0)).collect();
        let report = gpu_findings(&gpu_log(12 * GB, &dips), &marks, &mut |_| String::new());
        assert_eq!(keys(&report), ["gpu waiting"]);
        assert_eq!(report.findings[0].severity, Severity::Low);
        assert!(report.lines.iter().any(|l| l.contains("45% busy on average")), "{:?}", report.lines);

        // A desktop idling at 30% all along is not "a game waiting for the CPU".
        let desktop: Vec<(f64, f64, u64, u64)> = (0..20).map(|i| (i as f64, 30.0, 4 * GB, 0)).collect();
        assert!(gpu_findings(&gpu_log(12 * GB, &desktop), &marks, &mut |_| String::new()).findings.is_empty());

        // No flagged moments: load alone is never a finding. A busy GPU is what a game should look like.
        assert!(gpu_findings(&gpu_log(12 * GB, &busy), &[], &mut |_| String::new()).findings.is_empty());
    }

    // --- hybrid CPUs: stalls landing on the efficiency cores --------------------------------

    /// `p` performance cores then `e` efficiency cores, one group, no SMT.
    fn hybrid_topo(p: u8, e: u8) -> Topology {
        let sets: Vec<crate::topology::CpuSet> =
            (0..p + e).map(|i| crate::topology::CpuSet { group: 0, index: i, class: u8::from(i < p), core: i }).collect();
        Topology::build(&[(p + e) as u32], &sets)
    }

    #[test]
    fn stalls_concentrated_on_efficiency_cores_are_reported() {
        let topo = hybrid_topo(4, 4);
        let hit = vec![vec![5u16], vec![6], vec![7]];
        assert_eq!(e_core_concentration(&topo, &hit), Some((3, 3, vec![5, 6, 7])));
        // One in four on a P-core is 75%: under the 80% rule.
        let mixed = vec![vec![5u16], vec![6], vec![7], vec![1]];
        assert_eq!(e_core_concentration(&topo, &mixed), None);
        // A stall that hit a P-core as well as an E-core does not count as an E-core stall.
        assert_eq!(e_core_concentration(&topo, &[vec![5, 1], vec![6], vec![7]]), None);
    }

    #[test]
    fn too_few_stalls_or_no_cpu_is_not_a_pattern() {
        let topo = hybrid_topo(4, 4);
        assert_eq!(e_core_concentration(&topo, &[vec![5u16], vec![6]]), None);
        // CPU-starvation stalls name no CPU at all.
        assert_eq!(e_core_concentration(&topo, &[vec![], vec![], vec![]]), None);
    }

    #[test]
    fn nothing_is_said_about_cores_on_a_uniform_cpu() {
        let topo = Topology::build(&[8], &[]);
        assert_eq!(e_core_concentration(&topo, &[vec![5u16], vec![6], vec![7]]), None);
        assert_eq!(e_core_concentration(&Topology::default(), &[vec![0u16], vec![0], vec![0]]), None);
    }

    /// With 2 P-cores and 6 E-cores, stalls land on an E-core simply because most cores are.
    #[test]
    fn e_cores_in_the_majority_prove_nothing() {
        let topo = hybrid_topo(2, 6);
        assert_eq!(e_core_concentration(&topo, &[vec![3u16], vec![4], vec![5], vec![6]]), None);
    }

    #[test]
    fn every_flagged_moment_shows_up_in_the_result_whatever_the_verdict() {
        use crate::analyze::IncidentSummary;
        use crate::modules::ModuleMap;
        use crate::procs::ProcNames;
        use std::sync::atomic::{AtomicBool, AtomicI64};
        use std::sync::Arc;

        let mut az = Analyzer::for_test(ModuleMap::for_test(&[]), ProcNames::for_test(&[]), true);
        let flagged = |culprit: &str| IncidentSummary {
            kind: StallKind::Kernel,
            start: qpc(),
            dur: ms_to_ticks(6.0),
            culprit: culprit.to_string(),
            marked: true,
            cpus: vec![0],
        };
        az.incidents.push(flagged("CPU went dark (firmware SMI / hypervisor / interrupts off)"));
        az.incidents.push(flagged("unexplained"));
        az.incidents.push(flagged("driver nvlddmkm.sys"));
        az.marks_total = 3;
        let stats =
            ProbeStats { max_kernel: Arc::new(AtomicI64::new(0)), max_sched: Arc::new(AtomicI64::new(0)), realtime: AtomicBool::new(true) };
        let summary = az.summarize(RunData {
            elapsed_s: 60.0,
            events_lost: 0,
            stats: &stats,
            exec_warn: ms_to_ticks(1.0),
            io_warn: ms_to_ticks(200.0),
            clock: &[],
            gpu: &GpuLog::default(),
        });
        let flagged_findings: Vec<&Finding> =
            summary.findings.iter().filter(|f| f.evidence.iter().any(|e| e.contains("of the 3 moments you flagged"))).collect();
        let titles: Vec<&str> = flagged_findings.iter().map(|f| f.title.as_str()).collect();
        assert_eq!(flagged_findings.len(), 3, "one finding per verdict, none dropped: {titles:?}");
        assert!(titles.iter().any(|t| t.starts_with("Firmware / BIOS (SMI)")), "{titles:?}");
        assert!(titles.contains(&"Stalls without an identifiable cause"), "{titles:?}");
        assert!(titles.iter().any(|t| t.starts_with("nvlddmkm.sys")), "{titles:?}");
    }

    #[test]
    fn windows_processes_are_never_called_programs_you_can_close() {
        for label in [
            "System (kernel threads)",
            "System (4)",
            "svchost.exe (1234)",
            "MsMpEng.exe (99)",
            "dwm.exe (1500)",
            "backgroundTaskHost.exe (7)",
        ] {
            let (title, advice) = (process_title(label), process_advice(label));
            assert!(!title.ends_with("-  program"), "{label}: {title}");
            assert!(!advice.starts_with("Close this program") && !advice.contains("pause it"), "{label}: {advice}");
            assert!(
                advice.contains("not") && (advice.contains("you can close") || advice.contains("something you can close")),
                "{label}: {advice}"
            );
        }
        assert!(process_title("System (kernel threads)").starts_with("Windows kernel"));
        assert!(process_advice("System (kernel threads)").contains("Kernel-mode time by module"));
        // A real program still gets the plain advice, and a known app its own tip.
        assert_eq!(process_title("game.exe (4242)"), "game.exe  -  program");
        assert!(process_advice("game.exe (4242)").starts_with("Close this program"));
        assert!(process_advice("steam.exe (77)").contains("Pause the download"));
    }

    #[test]
    fn event_log_timing_reads_naturally() {
        let now = 1_000_000;
        assert_eq!(
            when_text(&[now - 3 * 86_400, now - 100], now, now - 600),
            "2 times in the last 7 days (1 while monitoring), most recently within the last hour"
        );
        assert_eq!(when_text(&[now - 2 * 86_400 - 5], now, now - 600), "1 time in the last 7 days, most recently 2 day(s) ago");
    }

    #[test]
    fn result_block_leads_with_the_verdict_and_stays_within_width() {
        let lines = Summary::demo(Health::Problem).result_lines();
        let verdict = lines.iter().find(|l| l.contains(">>>")).expect("verdict line");
        assert!(verdict.contains("PROBLEM FOUND") && verdict.contains("rtwlane.sys"));
        assert!(lines.iter().any(|l| l.contains("What to try:")));
        assert!(lines.iter().all(|l| l.chars().count() <= WIDTH), "advice text must be wrapped");
    }

    #[test]
    fn evidence_for_the_same_subject_merges_and_keeps_the_worst_severity() {
        let mut f = Findings::default();
        f.add("driver x.sys", Severity::Medium, "x.sys".into(), "long DPCs".into(), "advice".into(), 10);
        f.add("driver x.sys", Severity::High, "ignored".into(), "blamed for stalls".into(), "ignored".into(), 5);
        assert_eq!(f.0.len(), 1);
        let finding = &f.0[0].1;
        assert_eq!((finding.severity, finding.evidence.len(), finding.impact), (Severity::High, 2, 15));
    }
}
