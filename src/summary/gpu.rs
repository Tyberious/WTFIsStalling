//! The graphics card: how full its video memory got, what it was doing at the moments the user
//! flagged, and the times Windows had to reset the graphics driver.

use crate::evlog;
use crate::gpu::GpuLog;
use crate::gputrace::{GpuTraceReport, MarkGpu};
use crate::modules::knowledge;
use crate::procs::process_name;
use crate::util::ms_to_ticks;

use super::ctx::{when_text, Ctx, EVENT_LOG_DAYS};
use super::wording::process_title;
use super::{Metric, Severity};

const DISPLAY_RESET_ADVICE: &str = "The graphics driver stopped answering for about two seconds, so Windows restarted it: that is a \
    freeze of several seconds, often with a black flash, and sometimes the game crashes. In order of likelihood: remove any GPU \
    overclock or undervolt (including factory-overclock tuning in Afterburner or the vendor app); clean-install the graphics driver \
    (use DDU, then the current or the previous driver version); check GPU temperatures and that every PCIe power plug is fully \
    seated, using separate cables rather than one daisy-chained cable; lower in-game settings that fill the VRAM. If it happens at \
    stock settings in every game, suspect the power supply or the card.";

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

/// The picture stopping is the symptom, not the cause, so this must not read as blame on whatever
/// program happened to be drawing (it is often the desktop compositor, which is part of Windows).
pub(super) const FRAMES_ADVICE: &str = "This is the hitch itself rather than its cause: the graphics kernel had no new picture to put on \
    screen. If anything else in this report names a driver, a disk or video memory, change that one thing first and run this again. \
    If nothing else shows up, the cause is inside the program drawing the picture or on the graphics card: install the current \
    graphics driver from the card maker's site, turn off in-game overlays and recording tools (Discord, GeForce Experience, Xbox Game \
    Bar, streaming software), and lower the settings that load the card the most (resolution or render scale, ray tracing, frame \
    generation).";

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
    /// What a next run compares this against.
    metric: Metric,
}

/// Findings and detail lines from the once-a-second GPU samples and the graphics-kernel trace.
/// `marks` are the moments the user flagged (QPC); `name_of` turns a pid into a program name;
/// `trace` and `gpu_marks` are what the second ETW session saw over the run and at each of those
/// moments (both empty when there was no such session).
fn gpu_findings(
    log: &GpuLog,
    marks: &[i64],
    name_of: &mut dyn FnMut(u32) -> String,
    trace: &GpuTraceReport,
    gpu_marks: &[MarkGpu],
) -> GpuReport {
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
                    // Keyed by name: the LUID is reassigned at every boot, and runs are compared across boots.
                    key: format!("gpu vram {}", adapter.name),
                    severity: if hits > 0 || spilled >= 1_000_000_000 { Severity::High } else { Severity::Medium },
                    title: format!("{}  -  video memory is full", adapter.name),
                    evidence,
                    advice: VRAM_ADVICE,
                    metric: Metric::secs("seconds video memory was full", full.len() as u32),
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
                    metric: Metric::flat("flagged moments with the GPU flat out", bound as u32),
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
                    metric: Metric::flat("flagged moments with the GPU waiting", waiting as u32),
                });
            }
        }
    }
    // ---- what the graphics-kernel trace saw: frame cadence and video memory pressure
    let totals = &trace.totals;
    if let Some(note) = &trace.note {
        lines.push(format!("  frame timing and video memory pressure were not measured: {note}"));
    }
    if totals.available {
        lines.push(format!(
            "  graphics kernel trace: {} display refreshes, {} frames handed to the graphics card",
            totals.refresh_ticks, totals.presents
        ));
        if totals.residency_ops > 0 {
            let budget = if totals.trim_events == 0 {
                "never over budget".to_string()
            } else {
                format!("over budget {} time(s), up to {} asked to be freed", totals.trim_events, gb(totals.trim_max_bytes))
            };
            lines.push(format!(
                "  video memory moves: {} transfer(s) taking {:.0} ms in total; {budget}",
                totals.residency_ops, totals.residency_ms
            ));
        }
    }

    // Windows asking for video memory to be freed is the card's own answer to "is it full",
    // which is worth more than the once-a-second counter and is attributed the same way: to the
    // adapter with the most video memory, the one games run on.
    if totals.trim_events > 0 {
        let biggest = log.adapters.iter().max_by_key(|a| a.vram);
        let at_mark = gpu_marks.iter().filter(|m| m.trim_bytes > 0).count();
        let mut evidence = format!(
            "The graphics card ran out of room {} time(s) while monitoring: Windows asked for up to {} of video memory to be freed.",
            totals.trim_events,
            gb(totals.trim_max_bytes)
        );
        if totals.residency_failed > 0 {
            evidence.push_str(&format!(" {} of those attempts could not be satisfied at all.", totals.residency_failed));
        }
        if at_mark > 0 {
            evidence.push_str(&format!(" {at_mark} of the {} moments you flagged happened while that was going on.", gpu_marks.len()));
        }
        findings.push(GpuFinding {
            // The same subject as the counter-based finding above, so the two become one entry.
            key: biggest.map_or_else(|| "gpu vram".to_string(), |a| format!("gpu vram {}", a.name)),
            severity: if at_mark > 0 || totals.residency_failed > 0 { Severity::High } else { Severity::Medium },
            title: biggest.map_or_else(|| "Video memory ran out".to_string(), |a| format!("{}  -  video memory ran out", a.name)),
            evidence,
            advice: VRAM_ADVICE,
            metric: Metric::count("times video memory ran out", totals.trim_events as u32),
        });
    }

    // ---- the picture stopping at a flagged moment
    let covered = gpu_marks.iter().filter(|m| m.covered).count();
    let stopped: Vec<&MarkGpu> =
        gpu_marks.iter().filter(|m| m.covered && (m.display_stalled || m.program.as_ref().is_some_and(|(_, _, s)| *s))).collect();
    if covered > 0 {
        lines.push(format!(
            "  at the {} moment(s) you flagged: {covered} with frame-timing evidence, {} where the picture stopped updating",
            gpu_marks.len(),
            stopped.len()
        ));
    }
    if !stopped.is_empty() {
        let worst = stopped.iter().map(|m| m.display_gap_ms.max(m.program.as_ref().map_or(0.0, |(_, gap, _)| *gap))).fold(0.0, f64::max);
        let who = stopped
            .iter()
            .filter_map(|m| m.program.as_ref())
            .filter(|(_, _, s)| *s)
            .max_by(|a, b| a.1.total_cmp(&b.1))
            .map(|(name, ..)| name.clone());
        let mut evidence = format!(
            "At {} of the {} moment(s) you flagged, the graphics kernel put no new picture on screen for up to {worst:.0} ms.",
            stopped.len(),
            gpu_marks.len()
        );
        if let Some(name) = &who {
            evidence.push_str(&format!(" The program whose frames stopped was {}.", process_title(name)));
        }
        findings.push(GpuFinding {
            key: "gpu frames".into(),
            // A symptom with no named cause must not set the banner on a single sighting.
            severity: if stopped.len() * 2 > covered { Severity::Medium } else { Severity::Low },
            title: "The picture stopped updating when you felt the hitch".into(),
            evidence,
            advice: FRAMES_ADVICE,
            metric: Metric::ms("longest moment with no new picture", worst),
        });
    }

    // Video memory cannot be ruled out while the card was asking for room.
    let ruled_out = !findings.iter().any(|f| f.key.starts_with("gpu vram")) && totals.trim_events == 0;
    let vram_clear = if ruled_out { vram_clear.map(|(_, text)| text) } else { None };
    GpuReport { findings, lines, vram_clear }
}

/// Times Windows reset the graphics driver because it stopped answering (TDR).
pub(super) fn driver_resets(cx: &mut Ctx) {
    let (now_unix, run_start_unix) = (cx.now_unix, cx.run_start_unix);
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
        let key = cx.found.0.iter().map(|(k, _)| k.clone()).find(|k| k.eq_ignore_ascii_case(&wanted)).unwrap_or(wanted);
        if cx.found.note(&key, text.clone()) {
            cx.found.raise(&key, sev);
            cx.found.advise(&key, DISPLAY_RESET_ADVICE);
        } else {
            cx.found.add(&key, sev, format!("{file}  -  {what}: it hung and was reset"), text, DISPLAY_RESET_ADVICE.to_string(), 0);
        }
        cx.found.measure(&key, Metric::flat("resets while monitoring", times.iter().filter(|t| **t >= run_start_unix).count() as u32));
        cx.found.measure(&key, Metric::logged(&format!("in the last {EVENT_LOG_DAYS} days"), times.len() as u32));
    }
    cx.display_log = display_log;
}

/// Video memory and GPU load.
pub(super) fn graphics(cx: &mut Ctx) {
    let gpu = cx.run.gpu;
    let mark_times = cx.az.mark_times.clone();
    let trace = cx.run.gpu_trace.clone();
    let gpu_marks = cx.az.gpu_marks.clone();
    let gpu_report = gpu_findings(gpu, &mark_times, &mut |pid| process_name(&cx.az.procs.label(pid, 0)), &trace, &gpu_marks);
    let gpu_lines = gpu_report.lines;
    for f in gpu_report.findings {
        cx.found.add(&f.key, f.severity, f.title, f.evidence, f.advice.to_string(), 0);
        cx.found.measure(&f.key, f.metric);
    }
    // "Look at the GPU: VRAM running out..." is a guess the measurements can now retire.
    if let Some(clear) = &gpu_report.vram_clear {
        if cx.found.note("clean marks", format!("Video memory was not the problem: {clear}.")) {
            // ...so stop suggesting it.
            if let Some((_, f)) = cx.found.0.iter_mut().find(|(k, _)| k == "clean marks") {
                f.advice = f.advice.replace("VRAM running out (lower texture quality), ", "");
            }
        }
    }
    cx.gpu_lines = gpu_lines;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gputrace::GpuTraceTotals;

    /// A run in which the graphics-kernel session did work.
    fn trace(trim_events: u64, trim_max: u64, failed: u64) -> GpuTraceReport {
        GpuTraceReport {
            totals: GpuTraceTotals {
                available: true,
                events: 1_000,
                refresh_ticks: 600,
                presents: 400,
                residency_ops: 50,
                residency_ms: 120.0,
                trim_events,
                trim_max_bytes: trim_max,
                residency_failed: failed,
            },
            ..GpuTraceReport::default()
        }
    }

    fn mark(stalled: bool, who: &str, gap_ms: f64) -> MarkGpu {
        MarkGpu {
            covered: true,
            display_gap_ms: if stalled { gap_ms } else { 8.0 },
            display_stalled: stalled,
            program: Some((who.to_string(), gap_ms, stalled)),
            trim_bytes: 0,
            residency_ms: 0.0,
        }
    }

    /// The card telling Windows to free video memory is the card's own answer to "is it full?",
    /// and it has to land on the same subject as the once-a-second counter, not beside it.
    #[test]
    fn video_memory_running_out_is_the_same_subject_as_full_video_memory() {
        const GB: u64 = 1_000_000_000;
        let calm: Vec<(f64, f64, u64, u64)> = (0..20).map(|i| (i as f64, 30.0, 6 * GB, 0)).collect();
        let report = gpu_findings(&gpu_log(12 * GB, &calm), &[], &mut |_| String::new(), &trace(47, 512_000_000, 0), &[]);
        assert!(report.vram_clear.is_none(), "the card asked for room, so video memory cannot be ruled out");
        let f = report.findings.iter().find(|f| f.key.starts_with("gpu vram")).expect("a video memory finding");
        assert_eq!(f.key, "gpu vram NVIDIA GeForce RTX 4070", "the same key the counters use, so the two merge into one entry");
        assert_eq!(f.severity, Severity::Medium);
        assert!(f.evidence.contains("ran out of room 47 time(s)"), "{}", f.evidence);
        assert!(f.evidence.contains("up to 0.5 GB"), "{}", f.evidence);
        assert!(report.lines.iter().any(|l| l.contains("600 display refreshes")), "{:?}", report.lines);
        assert!(report.lines.iter().any(|l| l.contains("over budget 47 time(s)")), "{:?}", report.lines);

        // Full counters AND the card asking for room: one subject, two pieces of evidence.
        let full: Vec<(f64, f64, u64, u64)> = (0..20).map(|i| (i as f64, 80.0, 11_600_000_000, 0)).collect();
        let report = gpu_findings(&gpu_log(12 * GB, &full), &[], &mut |_| "game.exe".into(), &trace(3, GB, 0), &[]);
        let keys: Vec<&str> = report.findings.iter().map(|f| f.key.as_str()).collect();
        assert_eq!(keys, ["gpu vram NVIDIA GeForce RTX 4070", "gpu vram NVIDIA GeForce RTX 4070"]);

        // An attempt that failed outright, or one at a flagged moment, is the worse case.
        let at_mark = [MarkGpu { covered: true, trim_bytes: GB, ..MarkGpu::default() }];
        let report = gpu_findings(&gpu_log(12 * GB, &calm), &[], &mut |_| String::new(), &trace(9, GB, 2), &at_mark);
        let f = &report.findings[0];
        assert_eq!(f.severity, Severity::High);
        assert!(f.evidence.contains("2 of those attempts could not be satisfied"), "{}", f.evidence);
        assert!(f.evidence.contains("1 of the 1 moments you flagged"), "{}", f.evidence);

        // No trace at all: nothing is said about any of it, and the counters still rule VRAM out.
        let report = gpu_findings(&gpu_log(12 * GB, &calm), &[], &mut |_| String::new(), &GpuTraceReport::default(), &[]);
        assert!(report.findings.is_empty() && report.vram_clear.is_some());
        assert!(!report.lines.iter().any(|l| l.contains("graphics kernel")), "{:?}", report.lines);
    }

    /// The program whose frames stopped is the victim, never the culprit - and it is very often
    /// the desktop compositor, which nobody can close.
    #[test]
    fn the_picture_stopping_is_reported_without_telling_anyone_to_close_windows() {
        let marks = [mark(true, "dwm.exe", 180.0), mark(true, "dwm.exe", 240.0), mark(false, "dwm.exe", 7.0)];
        let report = gpu_findings(&GpuLog::default(), &[], &mut |_| String::new(), &trace(0, 0, 0), &marks);
        let f = report.findings.iter().find(|f| f.key == "gpu frames").expect("a frames finding");
        assert_eq!(f.severity, Severity::Medium);
        assert!(f.title.starts_with("The picture stopped updating"), "{}", f.title);
        assert!(f.evidence.contains("At 2 of the 3 moment(s) you flagged"), "{}", f.evidence);
        assert!(f.evidence.contains("up to 240 ms"), "{}", f.evidence);
        assert!(f.evidence.contains("part of Windows"), "the compositor is named as what it is: {}", f.evidence);
        let text = format!("{} {} {}", f.title, f.evidence, f.advice).to_lowercase();
        for forbidden in ["close dwm", "close this program", "end task", "uninstall"] {
            assert!(!text.contains(forbidden), "says '{forbidden}': {text}");
        }
        assert!(report.lines.iter().any(|l| l.contains("3 with frame-timing evidence, 2 where the picture stopped")), "{:?}", report.lines);

        // One moment out of three is a lead, not a suspect.
        let one = [mark(true, "game.exe", 90.0), mark(false, "game.exe", 7.0), mark(false, "game.exe", 7.0)];
        let report = gpu_findings(&GpuLog::default(), &[], &mut |_| String::new(), &trace(0, 0, 0), &one);
        assert_eq!(report.findings.iter().find(|f| f.key == "gpu frames").unwrap().severity, Severity::Low);

        // A moment the rings did not reach back over says nothing at all.
        let uncovered = [MarkGpu { covered: false, display_stalled: true, display_gap_ms: 900.0, ..MarkGpu::default() }];
        let report = gpu_findings(&GpuLog::default(), &[], &mut |_| String::new(), &trace(0, 0, 0), &uncovered);
        assert!(!report.findings.iter().any(|f| f.key == "gpu frames"), "an uncovered moment is not evidence");
        assert!(!report.lines.iter().any(|l| l.contains("where the picture stopped")), "{:?}", report.lines);
    }

    /// A run with no GPU evidence has to say so in one line, not go quiet.
    #[test]
    fn a_run_without_the_second_session_says_why() {
        let report = gpu_findings(
            &GpuLog::default(),
            &[],
            &mut |_| String::new(),
            &GpuTraceReport { note: Some("light mode leaves the second trace session off".into()), ..GpuTraceReport::default() },
            &[],
        );
        assert!(report.findings.is_empty());
        assert_eq!(report.lines.len(), 1);
        assert!(report.lines[0].contains("were not measured: light mode"), "{:?}", report.lines);
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
        let report = gpu_findings(
            &gpu_log(12 * GB, &samples),
            &[ms_to_ticks(15_000.0)],
            &mut |_| "game.exe".into(),
            &GpuTraceReport::default(),
            &[],
        );
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
        let report = gpu_findings(&gpu_log(12 * GB, &calm), &[], &mut |_| String::new(), &GpuTraceReport::default(), &[]);
        assert!(report.findings.is_empty());
        assert_eq!(report.vram_clear.as_deref(), Some("NVIDIA GeForce RTX 4070 peaked at 6.0 GB of 12.0 GB (50%)"));

        // An integrated GPU's tiny carve-out is always "full" by design and is never judged.
        let igpu: Vec<(f64, f64, u64, u64)> = (0..20).map(|i| (i as f64, 30.0, 510_000_000, 0)).collect();
        let report = gpu_findings(&gpu_log(512_000_000, &igpu), &[], &mut |_| String::new(), &GpuTraceReport::default(), &[]);
        assert!(report.findings.is_empty() && report.vram_clear.is_none());
    }

    #[test]
    fn gpu_load_at_flagged_moments_says_which_side_to_look_at() {
        const GB: u64 = 1_000_000_000;
        let marks = [ms_to_ticks(5_000.0), ms_to_ticks(12_000.0), ms_to_ticks(18_000.0)];
        let keys = |r: &GpuReport| r.findings.iter().map(|f| f.key.clone()).collect::<Vec<_>>();

        let busy: Vec<(f64, f64, u64, u64)> = (0..20).map(|i| (i as f64, 99.0, 4 * GB, 0)).collect();
        let report = gpu_findings(&gpu_log(12 * GB, &busy), &marks, &mut |_| String::new(), &GpuTraceReport::default(), &[]);
        assert_eq!(keys(&report), ["gpu bound"]);
        assert!(report.findings[0].evidence.contains("3 of the 3"));

        // A game that loads the GPU most of the time, but not around the flagged moments.
        let dips: Vec<(f64, f64, u64, u64)> =
            (0..20).map(|i| (i as f64, if [4, 5, 6, 11, 12, 13, 17, 18, 19].contains(&i) { 45.0 } else { 97.0 }, 4 * GB, 0)).collect();
        let report = gpu_findings(&gpu_log(12 * GB, &dips), &marks, &mut |_| String::new(), &GpuTraceReport::default(), &[]);
        assert_eq!(keys(&report), ["gpu waiting"]);
        assert_eq!(report.findings[0].severity, Severity::Low);
        assert!(report.lines.iter().any(|l| l.contains("45% busy on average")), "{:?}", report.lines);

        // A desktop idling at 30% all along is not "a game waiting for the CPU".
        let desktop: Vec<(f64, f64, u64, u64)> = (0..20).map(|i| (i as f64, 30.0, 4 * GB, 0)).collect();
        assert!(gpu_findings(&gpu_log(12 * GB, &desktop), &marks, &mut |_| String::new(), &GpuTraceReport::default(), &[])
            .findings
            .is_empty());

        // No flagged moments: load alone is never a finding. A busy GPU is what a game should look like.
        assert!(gpu_findings(&gpu_log(12 * GB, &busy), &[], &mut |_| String::new(), &GpuTraceReport::default(), &[]).findings.is_empty());
    }
}
