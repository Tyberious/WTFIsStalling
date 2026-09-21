//! Turns a finished run into an answer: a one-line verdict, ranked findings (what, evidence,
//! what to try) and the supporting tables. Front ends decide how to present it.
//!
//! `Analyzer::summarize` at the bottom is the table of contents: one call per section of the
//! report, in the order the report is built. Each section lives in its own file next to this one.

mod ctx;
mod details;
mod gpu;
mod hardware;
mod stalls;
mod storage;
mod wording;

use std::sync::atomic::Ordering;

use crate::analyze::Analyzer;
use crate::baseline::{self, Metric, RunFacts, RunRecord, MAX_METRICS};
use crate::cpuclock::ClockSample;
use crate::gpu::GpuLog;
use crate::modules::knowledge;
use crate::overhead::Overhead;
use crate::probe::{ProbeStats, StallKind};
use crate::util::{plural, ticks_to_ms};

use ctx::Ctx;

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
    /// The subject this finding is about ("driver rtwlane.sys", "disk 1"); the same subject in
    /// another run carries the same key, which is how two runs are compared.
    pub key: String,
    pub severity: Severity,
    pub title: String,
    pub evidence: Vec<String>,
    pub advice: String,
    /// The one or two numbers that measure this finding, for comparing runs. Never printed as
    /// prose: the evidence above says it in words already.
    pub metrics: Vec<Metric>,
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
    /// "Compared with your last run": empty when there is no previous run to compare with.
    pub comparison: Vec<String>,
    pub findings: Vec<Finding>,
    /// Supporting tables, already formatted.
    pub details: Vec<String>,
    /// This run's numbers, for the next run to compare itself against.
    pub record: RunRecord,
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
        // Right after the overview and before the findings: what changed since the last run.
        if !self.comparison.is_empty() {
            out.push(String::new());
            for line in &self.comparison {
                match line.strip_prefix("- ") {
                    Some(bullet) => wrap(bullet, "    - ", &mut out),
                    None => wrap(line, "  ", &mut out),
                }
            }
        }
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
        let finding = |severity, key: &str, title: &str, evidence: &str, advice: &str, metrics| Finding {
            key: key.into(),
            severity,
            title: title.into(),
            evidence: vec![evidence.into()],
            advice: advice.into(),
            metrics,
            impact: 0,
        };
        let findings = match health {
            Health::Problem => vec![
                finding(
                    Severity::High,
                    "driver rtwlane.sys",
                    "rtwlane.sys  -  Wi-Fi adapter driver",
                    "Blamed for 14 stalls (worst 11.80 ms, 121 ms in total).",
                    knowledge("rtwlane.sys").map_or("", |k| k.advice),
                    vec![Metric::count("stalls blamed", 14), Metric::ms("worst stall", 11.8)],
                ),
                finding(
                    Severity::Medium,
                    "disk 1",
                    "Disk 1 (D:), WDC WD40EZAZ-00SF3B0  -  responding slowly",
                    "3 requests took longer than 200 ms (worst 840 ms). SATA hard drive, 4.0 TB, firmware 80.00A80. D: 93% full.",
                    "Check its health (SMART), free up space on D:, and reseat or replace its cable.",
                    vec![Metric::count("slow requests", 3), Metric::ms("worst wait", 840.0)],
                ),
            ],
            Health::Warning => vec![finding(
                Severity::Medium,
                "driver nvlddmkm.sys",
                "nvlddmkm.sys  -  NVIDIA GPU driver",
                "Its interrupt handling ran for up to 1.84 ms at a time (6 times over 1.00 ms).",
                knowledge("nvlddmkm.sys").map_or("", |k| k.advice),
                vec![Metric::ms("worst DPC/ISR", 1.84), Metric::count("long runs", 6)],
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
        let facts = RunFacts {
            seconds: 312.0,
            light: false,
            stalls_kernel: match health {
                Health::Problem => 14,
                Health::Warning => 2,
                _ => 0,
            },
            stalls_starve: 0,
            worst_kernel_ms: if health == Health::Problem { 11.8 } else { 1.84 },
            worst_sched_ms: 1.59,
            marks: 0,
            marks_clean: 0,
        };
        let record = baseline::record_of(&facts, health, &findings);
        // A canned previous run, so the comparison block can be seen without admin rights: last
        // time this PC was blamed on the Wi-Fi driver.
        let previous = RunRecord {
            unix_time: record.unix_time - 3 * 86_400,
            machine: record.machine.clone(),
            seconds: 300.0,
            stalls_kernel: 14,
            worst_kernel_ms: 11.8,
            health: Health::Problem,
            findings: vec![baseline::FindingRecord {
                key: "driver rtwlane.sys".into(),
                severity: Severity::High,
                title: "rtwlane.sys  -  Wi-Fi adapter driver".into(),
                metrics: vec![Metric::count("stalls blamed", 14), Metric::ms("worst stall", 11.8)],
            }],
            ..RunRecord::default()
        };
        Summary {
            health,
            headline,
            subline,
            overview: vec!["Monitored:        05:12".into(), "Note:             demo data, not a real measurement".into()],
            comparison: baseline::compare(&previous, &record),
            findings,
            details: vec![String::new(), "(demo: no details)".into()],
            record,
        }
    }
}

/// Findings keyed by subject so that e.g. a driver blamed for stalls *and* seen running long
/// DPCs becomes one entry with both pieces of evidence.
#[derive(Default)]
pub(super) struct Findings(pub(super) Vec<(String, Finding)>);

impl Findings {
    pub(super) fn add(&mut self, key: &str, severity: Severity, title: String, evidence: String, advice: String, impact: i64) {
        match self.0.iter_mut().find(|(k, _)| k == key) {
            Some((_, f)) => {
                f.severity = f.severity.max(severity);
                f.evidence.push(evidence);
                f.impact += impact;
            }
            None => self.0.push((
                key.to_string(),
                Finding { key: key.to_string(), severity, title, evidence: vec![evidence], advice, metrics: Vec::new(), impact },
            )),
        }
    }

    /// Attaches the number this finding is measured by when two runs are compared. The first one
    /// attached is the one it is judged by, so the most telling number goes on first; the same
    /// label twice keeps the larger value, and anything past the second is dropped.
    pub(super) fn measure(&mut self, key: &str, metric: Metric) {
        let Some((_, f)) = self.0.iter_mut().find(|(k, _)| k == key) else { return };
        match f.metrics.iter().position(|m| m.label == metric.label) {
            Some(at) => f.metrics[at].value = f.metrics[at].value.max(metric.value),
            None if f.metrics.len() < MAX_METRICS => f.metrics.push(metric),
            None => {}
        }
    }

    pub(super) fn raise(&mut self, key: &str, severity: Severity) {
        if let Some((_, f)) = self.0.iter_mut().find(|(k, _)| k == key) {
            f.severity = f.severity.max(severity);
        }
    }

    /// More to try for a subject that is already a finding.
    pub(super) fn advise(&mut self, key: &str, advice: &str) {
        if let Some((_, f)) = self.0.iter_mut().find(|(k, _)| k == key) {
            if !f.advice.contains(advice) {
                f.advice = format!("{} {advice}", f.advice.trim_end());
            }
        }
    }

    /// Extra evidence for a subject that is already a finding. Returns whether it was.
    pub(super) fn note(&mut self, key: &str, evidence: String) -> bool {
        match self.0.iter_mut().find(|(k, _)| k == key) {
            Some((_, f)) => {
                f.evidence.push(evidence);
                true
            }
            None => false,
        }
    }
}

/// Everything a finished run hands to the summary besides the analyzer's own state.
pub struct RunData<'a> {
    pub elapsed_s: f64,
    pub events_lost: u32,
    /// What the measuring itself cost this PC.
    pub overhead: Overhead,
    /// Why the run used the lighter settings, if it did.
    pub light: Option<&'static str>,
    pub stats: &'a ProbeStats,
    pub exec_warn: i64,
    pub io_warn: i64,
    pub clock: &'a [ClockSample],
    pub gpu: &'a GpuLog,
}

impl Analyzer {
    /// The report, section by section, in the order it is built.
    ///
    /// THE ORDER IS PART OF THE MEANING. Every section writes into one list of findings keyed by
    /// subject: `Findings::add` keeps the FIRST title and advice for a key (raising the severity
    /// and appending the evidence), while `note`, `raise`, `advise` and `measure` do nothing at
    /// all unless that key already exists. So whichever section runs first decides how a subject
    /// is introduced, and everything after it can only add to that. The constraints found in the
    /// code, and why each one holds:
    ///
    /// * `stalls::tally` runs first of all, so a driver, process or "CPU went dark" that actually
    ///   stalled the PC is introduced as such ("Blamed for N stalls"), with that culprit's advice.
    ///   `stalls::flagged_moments`, `stalls::long_dpc_isr`, `gpu::driver_resets` and
    ///   `hardware::whea` all add to those same keys afterwards.
    /// * `stalls::flagged_moments` creates "clean marks"; `gpu::graphics` notes on it that video
    ///   memory can be ruled out and edits its advice, so it has to come later.
    /// * `storage::slow_disks` introduces "disk <n>" as a slow disk. `storage::event_log` and
    ///   `storage::drive_health` note on that key and only fall back to creating it (with a
    ///   different title) when the disk was not slow, so they must run after it.
    /// * `hardware::whea` notes on the "CPU went dark ..." keys, which only exist if the two
    ///   stall sections have run.
    /// * `hardware::unexpected_shutdowns` notes on "whea fatal", so `hardware::whea` goes first:
    ///   a fatal hardware error already explains the crash and must not be reported twice.
    /// * `hardware::cpu_throttling` introduces "throttling" from what was measured;
    ///   `hardware::firmware_throttle` backs it up from the event log and only stands alone when
    ///   nothing was measured.
    /// * `stalls::periodicity` notes "the stalls keep time" on findings that already exist and
    ///   then rewrites the advice of every finding whose evidence says so, which means it has to
    ///   run after every section that sets an advice it may append to.
    /// * `wording::devices_behind_drivers` runs last of the finding sections: it rewrites every
    ///   "driver <file>" title and puts "Start here: this driver is N years old" in FRONT of the
    ///   advice, so anything added after it would end up behind that sentence.
    /// * `details::tables` runs after everything, because it prints the totals the sections above
    ///   worked out (the tally, the driver table, paging, disks, GPU and drive-health lines, the
    ///   event-log counts and the seconds spent throttled).
    pub fn summarize(&mut self, run: RunData) -> Summary {
        let mut cx = Ctx::new(self, run);

        stalls::tally(&mut cx);
        stalls::flagged_moments(&mut cx);
        hardware::e_cores(&mut cx);
        stalls::long_dpc_isr(&mut cx);
        storage::paging(&mut cx);
        storage::slow_disks(&mut cx);
        storage::event_log(&mut cx);
        storage::drive_health(&mut cx);
        gpu::driver_resets(&mut cx);
        gpu::graphics(&mut cx);
        hardware::whea(&mut cx);
        hardware::unexpected_shutdowns(&mut cx);
        stalls::periodicity(&mut cx);
        hardware::cpu_throttling(&mut cx);
        hardware::firmware_throttle(&mut cx);
        details::tool_cost(&mut cx);
        wording::devices_behind_drivers(&mut cx);

        let mut findings: Vec<Finding> = std::mem::take(&mut cx.found.0).into_iter().map(|(_, f)| f).collect();
        findings.sort_by_key(|f| (std::cmp::Reverse(f.severity), std::cmp::Reverse(f.impact)));

        // ---- Verdict -----------------------------------------------------------------
        let kernel_stalls = cx.az.incidents.iter().filter(|i| !i.marked && i.kind == StallKind::Kernel).count();
        let sched_stalls = cx.az.incidents.iter().filter(|i| !i.marked).count() - kernel_stalls;
        let overview = details::overview(&cx, kernel_stalls, sched_stalls);
        let (events, secs, marks_total) = (cx.events, cx.run.elapsed_s as u64, cx.az.marks_total);
        let more = |n: usize| if n > 1 { format!("  (+{} more finding{} below)", n - 1, plural(n as u64 - 1)) } else { String::new() };
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

        if health == Health::Ok && cx.az.marks_clean > 0 {
            headline = "The hitches you flagged did not come from drivers, interrupts or the CPU".to_string();
            subline = format!(
                "At {} of the {marks_total} moment(s) you flagged, no CPU core was held up long enough to feel and no disk, paging or \
                 throttling problem showed up. That clears the system side: look inside the app or at the GPU (shader compilation, \
                 VRAM running out, frame pacing, overlays).",
                cx.az.marks_clean
            );
        }

        details::tables(&mut cx);

        let (elapsed_s, light, stats) = (cx.run.elapsed_s, cx.run.light, cx.run.stats);

        // The numbers this run leaves behind for the next one. The comparison itself is added by
        // `baseline::attach` once the engine knows where the report was written.
        let record = baseline::record_of(
            &RunFacts {
                seconds: elapsed_s,
                light: light.is_some(),
                stalls_kernel: kernel_stalls as u32,
                stalls_starve: sched_stalls as u32,
                worst_kernel_ms: ticks_to_ms(stats.max_kernel.load(Ordering::Relaxed)),
                worst_sched_ms: ticks_to_ms(stats.max_sched.load(Ordering::Relaxed)),
                marks: marks_total,
                marks_clean: cx.az.marks_clean,
            },
            health,
            &findings,
        );
        Summary { health, headline, subline, overview, comparison: Vec::new(), findings, details: cx.details, record }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::{ms_to_ticks, qpc};

    /// Prints the three demo reports exactly as rendered. `cargo test golden -- --ignored --nocapture`
    /// before and after a restructuring shows whether anything user-visible moved.
    #[test]
    #[ignore]
    fn golden_demo_reports() {
        for health in [Health::Problem, Health::Warning, Health::Ok] {
            let s = Summary::demo(health);
            println!("GOLDEN {health:?} headline={} | {}", s.headline, s.subline);
            for line in s.result_lines().iter().chain(s.detail_lines().iter()) {
                println!("GOLDEN {line}");
            }
        }
    }

    /// The tool's own cost is reported, but it is never allowed to become the verdict.
    #[test]
    fn the_tools_own_cost_is_reported_and_never_flips_the_banner() {
        use crate::modules::ModuleMap;
        use crate::procs::ProcNames;
        use std::sync::atomic::{AtomicBool, AtomicI64};
        use std::sync::Arc;

        let stats =
            ProbeStats { max_kernel: Arc::new(AtomicI64::new(0)), max_sched: Arc::new(AtomicI64::new(0)), realtime: AtomicBool::new(true) };
        let run = |overhead, light, lost| {
            let mut az = Analyzer::for_test(ModuleMap::for_test(&[]), ProcNames::for_test(&[]), true);
            az.shared.inner.lock().unwrap().events = 90_000;
            az.summarize(RunData {
                elapsed_s: 60.0,
                events_lost: lost,
                overhead,
                light,
                stats: &stats,
                exec_warn: ms_to_ticks(1.0),
                io_warn: ms_to_ticks(200.0),
                clock: &[],
                gpu: &GpuLog::default(),
            })
        };

        // 30 s + 120 s of CPU over a 60 s run on 4 CPUs, plus 10% of the events lost.
        let heavy = Overhead { monitor_100ns: 300_000_000, probes_100ns: Some(1_200_000_000), elapsed_s: 60.0, ncpu: 4 };
        let s = run(heavy, Some("this PC has few processor cores"), 10_000);
        let f = s.findings.iter().find(|f| f.title.starts_with("Measuring cost")).expect("the cost is a finding");
        assert_eq!(f.severity, Severity::Low, "an observation about the measuring must never be High or Medium");
        assert_eq!(s.health, Health::Ok, "and must not turn the banner into a problem");
        assert!(f.evidence.iter().any(|e| e.contains("total processor capacity")), "{:?}", f.evidence);
        assert!(f.evidence.iter().any(|e| e.contains("200% of one processor core")), "{:?}", f.evidence);
        assert!(f.evidence.iter().any(|e| e.contains("10000 of the 100000 kernel events")), "{:?}", f.evidence);
        assert!(f.advice.contains("already used the lighter settings"), "{}", f.advice);
        assert!(s.overview.iter().any(|l| l.starts_with("Light mode:") && l.contains("few processor cores")), "{:?}", s.overview);
        assert!(s.details.iter().any(|l| l.contains("THIS TOOL'S OWN COST")), "the cost block is in DETAILS");
        assert!(s.details.iter().any(|l| l.contains("1500 per second")), "{:?}", s.details);

        // A cheap run on a normal machine says nothing beyond the DETAILS block.
        let cheap = Overhead { monitor_100ns: 10_000_000, probes_100ns: Some(20_000_000), elapsed_s: 60.0, ncpu: 16 };
        let s = run(cheap, None, 0);
        assert!(!s.findings.iter().any(|f| f.title.starts_with("Measuring cost")), "1% of one core is not worth a finding");
        assert!(!s.overview.iter().any(|l| l.starts_with("Light mode:")), "no light-mode line when it is off");
        assert!(s.details.iter().any(|l| l.contains("Monitoring program:")), "{:?}", s.details);
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
            overhead: Overhead::default(),
            light: None,
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
    fn result_block_leads_with_the_verdict_and_stays_within_width() {
        let lines = Summary::demo(Health::Problem).result_lines();
        let verdict = lines.iter().find(|l| l.contains(">>>")).expect("verdict line");
        assert!(verdict.contains("PROBLEM FOUND") && verdict.contains("rtwlane.sys"));
        assert!(lines.iter().any(|l| l.contains("What to try:")));
        assert!(lines.iter().all(|l| l.chars().count() <= WIDTH), "advice text must be wrapped");
    }

    /// The demo carries a canned previous run, so the block can be seen (and checked) without
    /// admin rights: it sits between the overview and the findings and obeys the report width.
    #[test]
    fn the_comparison_sits_under_the_overview_and_stays_within_width() {
        for health in [Health::Ok, Health::Warning, Health::Problem] {
            let summary = Summary::demo(health);
            assert!(!summary.comparison.is_empty(), "{health:?}: the demo shows a comparison");
            let lines = summary.result_lines();
            let at = |needle: &str| lines.iter().position(|l| l.contains(needle));
            assert!(at("Monitored:") < at("COMPARED WITH YOUR LAST RUN"), "{lines:?}");
            if health != Health::Ok {
                assert!(at("COMPARED WITH YOUR LAST RUN") < at("What to try:"), "{lines:?}");
            }
            assert!(lines.iter().all(|l| l.chars().count() <= WIDTH), "the comparison must be wrapped too: {lines:?}");
            assert!(lines.iter().any(|l| l.trim_start().starts_with("- rtwlane.sys")), "bullets keep their indent: {lines:?}");
        }
        // The one thing the block must never do is claim a fix after a single short run.
        let ok = Summary::demo(Health::Ok).result_lines().join("\n");
        assert!(ok.contains("did not show up this time") && !ok.contains("fixed"), "{ok}");
    }

    #[test]
    fn every_finding_carries_a_number_to_compare_it_by() {
        // Whatever the demo shows, a next run can measure it: no finding is prose only.
        for health in [Health::Warning, Health::Problem] {
            for f in &Summary::demo(health).findings {
                assert!(!f.metrics.is_empty(), "{}: no metric", f.title);
                assert!(f.metrics.len() <= MAX_METRICS);
            }
        }
        // The first metric attached is the one the finding is judged by, and repeats keep the
        // larger value rather than piling up.
        let mut f = Findings::default();
        f.add("disk 1", Severity::High, "Disk 1".into(), "e".into(), "a".into(), 0);
        f.measure("disk 1", Metric::count("slow requests", 3.0));
        f.measure("disk 1", Metric::count("slow requests", 9.0));
        f.measure("disk 1", Metric::ms("worst wait", 840.0));
        f.measure("disk 1", Metric::secs("dropped", 1.0));
        f.measure("nothing here", Metric::count("ignored", 1.0));
        let m = &f.0[0].1.metrics;
        assert_eq!(m.len(), MAX_METRICS);
        assert_eq!((m[0].label.as_str(), m[0].value), ("slow requests", 9.0));
        assert_eq!(m[1].label, "worst wait");
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
