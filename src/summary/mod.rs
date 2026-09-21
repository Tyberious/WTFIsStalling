//! Turns a finished run into an answer: a one-line verdict, ranked findings (what, evidence,
//! what to try) and the supporting tables. Front ends decide how to present it.
//!
//! `Analyzer::summarize` at the bottom is the table of contents: one call per section of the
//! report, in the order the report is built. Each section lives in its own file next to this one.

mod ctx;
mod details;
mod freezes;
mod gpu;
mod hardware;
mod platform;
mod stalls;
mod storage;
mod wording;

use std::sync::atomic::Ordering;

use crate::analyze::{Analyzer, IncidentClass};
use crate::baseline::{self, Metric, RunFacts, RunRecord, MAX_METRICS};
use crate::cpuclock::ClockSample;
use crate::gpu::GpuLog;
use crate::modules::knowledge;
use crate::overhead::Overhead;
use crate::probe::ProbeStats;
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

/// What a person would FEEL from a finding. Real PCs have several problems at once, and a list
/// ranked only by severity cannot say which layer to attack first; grouping by symptom can.
/// The order of the variants is the order the report presents them in.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Group {
    /// The whole PC stops: cursor and sound included.
    WholePc,
    /// Short interruptions: audio crackle, micro-stutter, a core held by a driver.
    Interruptions,
    /// One program waits: disk, paging, GPU limits. The rest of the PC carries on.
    OneProgram,
    /// Worth knowing, not a hitch yet: drive errors, hardware errors, old drivers, health.
    Health,
}

impl Group {
    pub fn title(self) -> &'static str {
        match self {
            Group::WholePc => "THE WHOLE PC STOPS",
            Group::Interruptions => "SHORT INTERRUPTIONS  (audio crackle, micro-stutter)",
            Group::OneProgram => "ONE PROGRAM WAITS  (disk, memory, graphics)",
            Group::Health => "WORTH KNOWING  (not causing hitches yet)",
        }
    }

    /// The short form used in the plan at the top of the report.
    pub fn short(self) -> &'static str {
        match self {
            Group::WholePc => "the whole PC stops",
            Group::Interruptions => "short interruptions",
            Group::OneProgram => "one program waits",
            Group::Health => "worth knowing, not a hitch yet",
        }
    }

    pub fn all() -> [Group; 4] {
        [Group::WholePc, Group::Interruptions, Group::OneProgram, Group::Health]
    }
}

pub struct Finding {
    /// The subject this finding is about ("driver rtwlane.sys", "disk 1"); the same subject in
    /// another run carries the same key, which is how two runs are compared.
    pub key: String,
    /// Which symptom this finding produces; see `Group`.
    pub group: Group,
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
/// The DETAILS tables are printed as-is and are allowed to be wider than the RESULT block.
const DETAIL_WIDTH: usize = 118;

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

/// Findings shown in full before the rest are folded into one line per group. The plan at the
/// top (verdict, overview, the group headlines, the order of attack) is about twenty lines and a
/// finding is four to six, so five full ones is what fits a console window before a reader has
/// to scroll. Nothing is lost: the folded ones are listed in DETAILS.
const SHOWN_IN_FULL: usize = 5;
/// ...and this is the ceiling once every group's own worst finding has been given a place.
const SHOWN_MAX: usize = 8;

/// Which findings are shown in full: the worst ones overall, plus the worst of every group that
/// has something a person can feel, so that a long tail of Low notes can never push a real
/// problem off the first screen. `findings` is already worst-first.
fn shown_in_full(findings: &[Finding]) -> Vec<usize> {
    let real: Vec<usize> = (0..findings.len()).filter(|i| findings[*i].severity > Severity::Low).collect();
    let pool: Vec<usize> = if real.is_empty() { (0..findings.len()).collect() } else { real };
    let mut shown: Vec<usize> = pool.iter().copied().take(SHOWN_IN_FULL).collect();
    // Then the worst of every group that has nothing shown yet, so a group never appears as a
    // heading with only a "and 3 more" line under it. Low findings can reach the list this way
    // but never before the five above, so they cannot push a real problem off the first screen.
    for g in Group::all() {
        if shown.iter().any(|i| findings[*i].group == g) {
            continue;
        }
        if let Some(i) = (0..findings.len()).find(|i| findings[*i].group == g) {
            if shown.len() < SHOWN_MAX {
                shown.push(i);
            }
        }
    }
    shown.sort_unstable();
    shown
}

impl Summary {
    /// The answer block: the verdict, then a plan (what the layers are, which to attack first),
    /// then the findings grouped by the symptom they produce.
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

        let shown = shown_in_full(&self.findings);
        self.plan(&shown, &mut out);
        let mut n = 0;
        for group in Group::all() {
            let in_group: Vec<&Finding> = self.findings.iter().filter(|f| f.group == group).collect();
            if in_group.is_empty() {
                continue;
            }
            out.push(String::new());
            out.push(format!("  {}", group.title()));
            let mut folded: Vec<&str> = Vec::new();
            for (i, f) in self.findings.iter().enumerate().filter(|(_, f)| f.group == group) {
                if !shown.contains(&i) {
                    folded.push(&f.title);
                    continue;
                }
                n += 1;
                out.push(String::new());
                out.push(format!("  {n}. [{}] {}", f.severity.label(), f.title));
                for e in &f.evidence {
                    wrap(e, "       - ", &mut out);
                }
                out.push("     What to try:".into());
                wrap(&f.advice, "       ", &mut out);
            }
            if !folded.is_empty() {
                out.push(String::new());
                wrap(
                    &format!("+ {} more in this group, with the full tables under DETAILS below: {}", folded.len(), folded.join("; ")),
                    "     ",
                    &mut out,
                );
            }
        }
        out.push(bar);
        out
    }

    /// The first screen has to read as a plan: how many problems of each kind there are, and
    /// which one to change first. One change at a time, because the next run's comparison can
    /// then say which layer moved.
    fn plan(&self, shown: &[usize], out: &mut Vec<String>) {
        if self.findings.is_empty() {
            return;
        }
        out.push(String::new());
        out.push("  WHAT THIS RUN FOUND".into());
        for group in Group::all() {
            let n = self.findings.iter().filter(|f| f.group == group).count();
            if n > 0 {
                out.push(format!("    {:<34} {n} finding{}", group.short(), plural(n as u64)));
            }
        }
        // The cheapest useful order: the worst thing a person can feel first, then the worst of
        // a different kind, and the warnings that are not hitches last.
        let first = shown.first().map(|i| &self.findings[*i]);
        let Some(first) = first else { return };
        // Background notes are not something to attack; a clean PC gets one line instead of a plan.
        if first.severity == Severity::Low {
            out.push(String::new());
            out.push("  Nothing here needs fixing. The notes below are background about this PC.".into());
            return;
        }
        out.push(String::new());
        out.push("  ORDER OF ATTACK  (change ONE thing, run this again, and the comparison above will say what moved)".into());
        wrap(&format!("Start here:  {}", first.title), "    ", out);
        if let Some(next) = shown.iter().map(|i| &self.findings[*i]).find(|f| f.group != first.group && f.severity > Severity::Low) {
            wrap(&format!("Then:        {}", next.title), "    ", out);
        }
        let later = self.findings.iter().filter(|f| f.group == Group::Health).count();
        if later > 0 {
            wrap(
                &format!(
                    "Later:       the {later} warning{} under '{}'. They are not causing hitches yet.",
                    plural(later as u64),
                    Group::Health.short()
                ),
                "    ",
                out,
            );
        }
    }

    pub fn detail_lines(&self) -> Vec<String> {
        let mut out = vec!["DETAILS".to_string()];
        if !self.findings.is_empty() {
            out.push(String::new());
            out.push("ALL FINDINGS  (including the ones folded away above)".into());
            for group in Group::all() {
                for f in self.findings.iter().filter(|f| f.group == group) {
                    let mut line = format!("  [{:<6}] {:<32} {}", f.severity.label(), group.short(), f.title);
                    line.truncate(DETAIL_WIDTH);
                    out.push(line);
                    if let Some(first) = f.evidence.first() {
                        let mut line = format!("            {first}");
                        line.truncate(DETAIL_WIDTH);
                        out.push(line);
                    }
                }
            }
        }
        out.extend(self.details.iter().cloned());
        out
    }
}

impl Summary {
    /// Canned results for working on the front ends without admin rights or a sick PC.
    pub fn demo(health: Health) -> Summary {
        let finding = |severity, group, key: &str, title: &str, evidence: Vec<&str>, advice: &str, metrics| Finding {
            key: key.into(),
            group,
            severity,
            title: title.into(),
            evidence: evidence.into_iter().map(String::from).collect(),
            advice: advice.into(),
            metrics,
            impact: 0,
        };
        let findings = match health {
            // Several layers at once, which is what a real PC looks like: a whole-PC freeze, a
            // driver holding one core, a slow drive, and a warning that is not a hitch yet.
            Health::Problem => vec![
                finding(
                    Severity::High,
                    Group::WholePc,
                    "whole-PC freeze",
                    "The whole PC stopped responding, 12 times",
                    vec![
                        "12 freezes in 59 minutes (12 per hour), typically 950 ms and at worst 1000 ms. All 8 processors stopped at \
                         the same instant each time, so no program that happened to be running can be the cause.",
                        "Device interrupts did not all stop together: Wdf01000.sys stopped completely in 8 of the 12 while \
                         dxgkrnl.sys kept arriving; in 3 it was the other way round. Which device goes quiet differs from freeze to \
                         freeze, which points below the drivers, at the board, its firmware or a bus.",
                        "8 of the 12 coincided with a slow write to disk 6 (I:), a drive that had been asleep; 4 coincided with \
                         nothing this tool can see.",
                        "What is NOT explained: no driver's interrupt handling was long enough to do this, no single processor was \
                         held, and the cause of the freezes is not visible in this trace.",
                    ],
                    "Nothing in this trace names a cause, so test one layer at a time and run this tool again after each change: \
                     the comparison at the top of the next report will say whether the freezes moved. 1) Fully exit (not just close) \
                     any utility that talks to the hardware directly - RGB, fan, lighting and monitoring tools - one at a time. 2) \
                     Unplug external drives, especially any this report mentions. 3) Update the motherboard BIOS/UEFI and load its \
                     defaults.",
                    vec![Metric::flat("freezes per hour", 12), Metric::ms("worst freeze", 1000.0)],
                ),
                finding(
                    Severity::Medium,
                    Group::Interruptions,
                    "driver rtwlane.sys",
                    "rtwlane.sys  -  Wi-Fi adapter driver",
                    vec!["Blamed for 14 stalls (worst 11.80 ms, 121 ms in total), about 14 per hour."],
                    knowledge("rtwlane.sys").map_or("", |k| k.advice),
                    vec![Metric::count("stalls blamed", 14), Metric::ms("worst stall", 11.8)],
                ),
                finding(
                    Severity::Medium,
                    Group::OneProgram,
                    "disk 1",
                    "Disk 1 (D:), WDC WD40EZAZ-00SF3B0  -  responding slowly",
                    vec!["3 requests took longer than 200 ms (worst 840 ms). SATA hard drive, 4.0 TB, firmware 80.00A80. D: 93% full."],
                    "Check its health (SMART), free up space on D:, and reseat or replace its cable.",
                    vec![Metric::count("slow requests", 3), Metric::ms("worst wait", 840.0)],
                ),
                finding(
                    Severity::Low,
                    Group::Health,
                    "disk 0",
                    "Disk 0 (C:), Samsung SSD 990 PRO  -  drive health warning",
                    vec!["Drive health: 2 CRC error(s) over its life; none while monitoring. Only a problem if the number keeps rising."],
                    "CRC errors mean data was damaged between the drive and the motherboard, not on the drive. Only act if the number \
                     grows between runs.",
                    vec![Metric::flat("errors while monitoring", 0)],
                ),
            ],
            Health::Warning => vec![finding(
                Severity::Medium,
                Group::Interruptions,
                "driver nvlddmkm.sys",
                "nvlddmkm.sys  -  NVIDIA GPU driver",
                vec!["Its interrupt handling ran for up to 1.84 ms at a time (6 times over 1.00 ms)."],
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
            seconds: if health == Health::Problem { 3561.0 } else { 312.0 },
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
            overview: vec![
                match health {
                    Health::Problem => "Monitored:        59:21".to_string(),
                    _ => "Monitored:        05:12".to_string(),
                },
                match health {
                    Health::Problem => "Stalls detected:  12 whole-PC freezes, 14 short kernel-level stalls".to_string(),
                    _ => "Stalls detected:  2 short kernel-level stalls".to_string(),
                },
                "Note:             demo data, not a real measurement".into(),
            ],
            comparison: baseline::compare(&previous, &record),
            findings,
            details: vec![String::new(), "(demo: no details)".into()],
            record,
        }
    }
}

/// Findings keyed by subject so that e.g. a driver blamed for stalls *and* seen running long
/// DPCs becomes one entry with both pieces of evidence.
pub(super) struct Findings(pub(super) Vec<(String, Finding)>, Group);

impl Default for Findings {
    fn default() -> Findings {
        Findings(Vec::new(), Group::Interruptions)
    }
}

impl Findings {
    /// Which group the sections that follow put their NEW findings in. Like the title and the
    /// advice, the group is decided by whichever section introduces a subject first: a disk that
    /// actually responded slowly this run belongs under "one program waits", the same disk known
    /// only from the event log belongs under "worth knowing".
    pub(super) fn in_group(&mut self, group: Group) {
        self.1 = group;
    }

    pub(super) fn add(&mut self, key: &str, severity: Severity, title: String, evidence: String, advice: String, impact: i64) {
        let group = self.1;
        match self.0.iter_mut().find(|(k, _)| k == key) {
            Some((_, f)) => {
                f.severity = f.severity.max(severity);
                f.evidence.push(evidence);
                f.impact += impact;
            }
            None => self.0.push((
                key.to_string(),
                Finding { key: key.to_string(), group, severity, title, evidence: vec![evidence], advice, metrics: Vec::new(), impact },
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
    /// Each section also declares which `Group` its NEW findings belong to, and `add` keeps the
    /// group of whichever section introduced a subject first, exactly as it keeps the title and
    /// the advice. That is what puts a disk which really responded slowly this run under "one
    /// program waits" and a disk known only from the event log under "worth knowing".
    ///
    /// * `freezes::whole_pc` runs before everything, so that whole-PC freezes are one finding at
    ///   the top of the report instead of a dozen bystanders; `stalls::tally` then never sees
    ///   those incidents.
    /// * `stalls::tally` runs next, so a driver, process or "CPU went dark" that actually
    ///   stalled the PC is introduced as such ("Blamed for N stalls"), with that culprit's advice.
    ///   `stalls::flagged_moments`, `stalls::long_dpc_isr`, `gpu::driver_resets` and
    ///   `hardware::whea` all add to those same keys afterwards.
    /// * `stalls::flagged_moments` creates "clean marks"; `gpu::graphics` notes on it that video
    ///   memory can be ruled out and edits its advice, so it has to come later.
    /// * `storage::slow_disks` introduces "disk <n>" as a slow disk. `storage::event_log` and
    ///   `storage::drive_health` note on that key and only fall back to creating it (with a
    ///   different title) when the disk was not slow, so they must run after it.
    /// * `stalls::one_program_waits` introduces its own "waiting <program>" keys and notes on
    ///   nothing, so its only constraint is the group it runs under.
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
    /// * `stalls::on_whose_behalf` and `stalls::periodicity` only note on findings that already
    ///   exist, so both go after every section that can create a "driver <file>" key.
    /// * `stalls::quiet_polling` goes after `stalls::long_dpc_isr`, which leaves it the per-driver
    ///   totals, and after everything that creates a driver finding: a driver that already has one
    ///   has been said more about than "it wakes on a timer" could add.
    /// * `wording::devices_behind_drivers` rewrites every "driver <file>" title and puts "Start
    ///   here: this driver is N years old" in FRONT of the advice, so anything that REPLACES an
    ///   advice must come before it. The `platform` sections below only append.
    /// * `platform::*` run last of the finding sections. They attach context to the freeze, the
    ///   "CPU went dark" and the periodic findings and to `driver <file>` findings, so everything
    ///   that creates those has to have run; `platform::legacy_interrupts` also reads the device
    ///   map that `wording::devices_behind_drivers` loads.
    /// * `details::tables` runs after everything, because it prints the totals the sections above
    ///   worked out (the tally, the driver table, paging, disks, GPU and drive-health lines, the
    ///   event-log counts and the seconds spent throttled).
    pub fn summarize(&mut self, run: RunData) -> Summary {
        let mut cx = Ctx::new(self, run);

        cx.found.in_group(Group::WholePc);
        freezes::whole_pc(&mut cx);
        cx.found.in_group(Group::Interruptions);
        stalls::tally(&mut cx);
        stalls::flagged_moments(&mut cx);
        hardware::e_cores(&mut cx);
        stalls::long_dpc_isr(&mut cx);
        cx.found.in_group(Group::OneProgram);
        storage::paging(&mut cx);
        storage::slow_disks(&mut cx);
        cx.found.in_group(Group::Health);
        storage::event_log(&mut cx);
        storage::drive_health(&mut cx);
        cx.found.in_group(Group::OneProgram);
        gpu::driver_resets(&mut cx);
        gpu::graphics(&mut cx);
        stalls::one_program_waits(&mut cx);
        cx.found.in_group(Group::Health);
        hardware::whea(&mut cx);
        hardware::unexpected_shutdowns(&mut cx);
        cx.found.in_group(Group::Interruptions);
        stalls::on_whose_behalf(&mut cx);
        stalls::periodicity(&mut cx);
        cx.found.in_group(Group::Health);
        stalls::quiet_polling(&mut cx);
        hardware::cpu_throttling(&mut cx);
        hardware::firmware_throttle(&mut cx);
        details::tool_cost(&mut cx);
        wording::devices_behind_drivers(&mut cx);
        platform::hardware_access(&mut cx);
        platform::network_filters(&mut cx);
        platform::legacy_interrupts(&mut cx);

        let mut findings: Vec<Finding> = std::mem::take(&mut cx.found.0).into_iter().map(|(_, f)| f).collect();
        findings.sort_by_key(|f| (std::cmp::Reverse(f.severity), std::cmp::Reverse(f.impact)));

        // ---- Verdict -----------------------------------------------------------------
        let count = |class| cx.az.incidents.iter().filter(|i| !i.marked && i.class == class).count();
        let (freezes, short_kernel, sched_stalls) =
            (count(IncidentClass::Freeze), count(IncidentClass::Kernel), count(IncidentClass::Starvation));
        let kernel_stalls = freezes + short_kernel;
        let overview = details::overview(&cx, freezes, short_kernel, sched_stalls);
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
        use std::sync::atomic::AtomicBool;

        let stats = ProbeStats { realtime: AtomicBool::new(true), ..ProbeStats::default() };
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
        // Compared with a cheap run on the SAME machine rather than with `Health::Ok`: summarize()
        // also reads this PC's real event log and drives, and a CI runner or a developer's PC may
        // have something genuine to report there. The point is that the cost changes nothing.
        let calm = Overhead { monitor_100ns: 10_000_000, probes_100ns: Some(20_000_000), elapsed_s: 60.0, ncpu: 16 };
        assert_eq!(s.health, run(calm, None, 0).health, "and must not change the banner");
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
        use std::sync::atomic::AtomicBool;

        let mut az = Analyzer::for_test(ModuleMap::for_test(&[]), ProcNames::for_test(&[]), true);
        let flagged = |culprit: &str| IncidentSummary {
            class: IncidentClass::Kernel,
            start: qpc(),
            dur: ms_to_ticks(6.0),
            culprit: culprit.to_string(),
            marked: true,
            cpus: vec![0],
            on_cpu: None,
            freeze: None,
        };
        az.incidents.push(flagged("CPU went dark (firmware SMI / hypervisor / interrupts off)"));
        az.incidents.push(flagged("unexplained"));
        az.incidents.push(flagged("driver nvlddmkm.sys"));
        az.marks_total = 3;
        let stats = ProbeStats { realtime: AtomicBool::new(true), ..ProbeStats::default() };
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

    /// From a field report: four "msedge.exe" findings (one per process ID), and periodic-stall
    /// advice that came out as "icue, armoury crate, hwinfo".
    #[test]
    fn one_program_is_one_finding_and_product_names_keep_their_case() {
        use crate::analyze::IncidentSummary;
        use crate::modules::ModuleMap;
        use crate::procs::ProcNames;
        use std::sync::atomic::AtomicBool;

        let mut az = Analyzer::for_test(ModuleMap::for_test(&[]), ProcNames::for_test(&[]), true);
        let freq = crate::util::qpc_freq();
        let t0 = qpc() - 400 * freq;
        let stall = |culprit: &str, at_s: i64| IncidentSummary {
            class: IncidentClass::Starvation,
            start: t0 + at_s * freq,
            dur: ms_to_ticks(30.0),
            culprit: culprit.to_string(),
            marked: false,
            cpus: Vec::new(),
            on_cpu: None,
            freeze: None,
        };
        for (i, pid) in [42216, 42980, 2308, 18996].into_iter().enumerate() {
            az.incidents.push(stall(&format!("process msedge.exe ({pid})"), 300 + i as i64));
        }
        // A driver blamed every 60 s exactly, so the periodic advice is appended to its finding.
        for k in 0..6 {
            az.incidents.push(stall("driver NETIO.SYS", 60 * k));
        }
        let stats = ProbeStats { realtime: AtomicBool::new(true), ..ProbeStats::default() };
        let summary = az.summarize(RunData {
            elapsed_s: 400.0,
            events_lost: 0,
            overhead: Overhead::default(),
            light: None,
            stats: &stats,
            exec_warn: ms_to_ticks(1.0),
            io_warn: ms_to_ticks(200.0),
            clock: &[],
            gpu: &GpuLog::default(),
        });
        let edge: Vec<&Finding> = summary.findings.iter().filter(|f| f.title.starts_with("msedge.exe")).collect();
        assert_eq!(edge.len(), 1, "one finding for the program, not one per process");
        assert!(edge[0].evidence[0].contains("4 stalls"), "{:?}", edge[0].evidence);

        let netio = summary.findings.iter().find(|f| f.title.starts_with("NETIO.SYS")).expect("driver finding");
        assert!(netio.evidence.iter().any(|e| e.contains("keep time")), "{:?}", netio.evidence);
        assert!(netio.advice.contains("something software-driven runs on a timer"), "{}", netio.advice);
        assert!(netio.advice.contains("iCUE") && netio.advice.contains("HWiNFO"), "product names keep their case: {}", netio.advice);
    }

    /// Deliverable 2: at the moments the user flagged, who was kept waiting, by what, and who
    /// woke them - said without ever naming a cause, and without telling anyone to close Windows.
    #[test]
    fn programs_kept_waiting_are_reported_without_naming_a_culprit() {
        use crate::analyze::ProgramWait;
        use crate::modules::ModuleMap;
        use crate::procs::ProcNames;
        use std::sync::atomic::AtomicBool;

        let mut az = Analyzer::for_test(ModuleMap::for_test(&[]), ProcNames::for_test(&[]), true);
        az.wait_moments = 3;
        // A game queued behind an RGB utility; the advice has to be about the RGB utility.
        az.program_waits.insert(
            "game.exe".into(),
            ProgramWait { ready: ms_to_ticks(180.0), instead: Some("iCUE.exe".into()), moments: 3, ..ProgramWait::default() },
        );
        // Part of Windows, blocked and woken by another part of Windows.
        az.program_waits.insert(
            "svchost.exe".into(),
            ProgramWait {
                blocked: ms_to_ticks(300.0),
                blocked_reason: 13, // WrUserRequest
                woken_by: Some("audiodg.exe".into()),
                moments: 2,
                ..ProgramWait::default()
            },
        );
        // Ready and waiting on a processor with nothing else to do: not contention at all.
        az.program_waits
            .insert("dwm.exe".into(), ProgramWait { ready: ms_to_ticks(120.0), instead_idle: true, moments: 1, ..ProgramWait::default() });
        // Just over the "you can feel it" floor: a lead, not a suspect.
        az.program_waits.insert("notepad.exe".into(), ProgramWait { ready: ms_to_ticks(30.0), moments: 1, ..ProgramWait::default() });

        let stats = ProbeStats { realtime: AtomicBool::new(true), ..ProbeStats::default() };
        let summary = az.summarize(RunData {
            elapsed_s: 400.0,
            events_lost: 0,
            overhead: Overhead::default(),
            light: None,
            stats: &stats,
            exec_warn: ms_to_ticks(1.0),
            io_warn: ms_to_ticks(200.0),
            clock: &[],
            gpu: &GpuLog::default(),
        });
        let f = |key: &str| summary.findings.iter().find(|f| f.key == key).unwrap_or_else(|| panic!("no finding for {key}"));

        let game = f("waiting game.exe");
        assert_eq!((game.group, game.severity), (Group::OneProgram, Severity::Medium));
        assert!(game.evidence[0].contains("ready to run and got no processor for 180"), "{:?}", game.evidence);
        assert!(game.evidence[0].contains("at 3 of the 3 moments"), "{:?}", game.evidence);
        assert!(game.evidence[0].contains("while iCUE.exe held that processor"), "{:?}", game.evidence);
        assert!(game.metrics.iter().any(|m| m.label == "longest wait for a processor"), "{:?}", game.metrics);

        let sv = f("waiting svchost.exe");
        assert!(sv.evidence[0].contains("blocked for 300"), "{:?}", sv.evidence);
        assert!(sv.evidence[0].contains("woken by a thread in audiodg.exe"), "{:?}", sv.evidence);
        assert!(sv.evidence[0].contains("not in this trace"), "it says how long, never why: {:?}", sv.evidence);

        let dwm = f("waiting dwm.exe");
        assert!(dwm.evidence[0].contains("nothing else to do at all"), "{:?}", dwm.evidence);
        assert!(dwm.advice.contains("closing programs will not help"), "{}", dwm.advice);

        assert_eq!(f("waiting notepad.exe").severity, Severity::Low, "30 ms is a lead, not a suspect");

        for key in ["waiting game.exe", "waiting svchost.exe", "waiting dwm.exe", "waiting notepad.exe"] {
            let f = f(key);
            assert!(f.severity < Severity::High, "{key}: a symptom with no culprit must never set the banner");
            // The audience rule: nothing here may read as blame, or as "close this bit of Windows".
            let text = format!("{} {} {}", f.title, f.evidence.join(" "), f.advice);
            for forbidden in ["blame", "culprit", "caused by", "responsible for"] {
                assert!(!text.to_lowercase().contains(forbidden), "{key} says '{forbidden}': {text}");
            }
        }
        // svchost and dwm are Windows; neither may be described as a program to close, and the
        // report says as much where a reader will see it.
        for key in ["waiting svchost.exe", "waiting dwm.exe"] {
            let f = f(key);
            assert!(!f.advice.to_lowercase().contains("close this program"), "{}", f.advice);
            assert!(f.evidence.iter().any(|e| e.contains("part of Windows")), "{:?}", f.evidence);
        }
        assert!(!f("waiting game.exe").evidence.iter().any(|e| e.starts_with("What game.exe is")), "nothing to say about a plain app");
        assert!(summary.result_lines().iter().all(|l| l.chars().count() <= WIDTH), "{:?}", summary.result_lines());
    }

    /// Everything read from the thread-switch trace is a chain, so a gap in it can flip a
    /// conclusion rather than blur it. When events were lost, or switches were never traced at
    /// all, none of it may reach the report.
    #[test]
    fn a_trace_with_gaps_produces_no_scheduler_findings_at_all() {
        use crate::analyze::{FreezeFacts, IncidentSummary, ProgramWait};
        use crate::modules::ModuleMap;
        use crate::procs::ProcNames;
        use crate::switches::ProbeVerdict;
        use std::sync::atomic::AtomicBool;

        // `lost` events, and whether switches were traced at all.
        let report = |lost: u32, traced: bool| {
            let mut az = Analyzer::for_test(ModuleMap::for_test(&[]), ProcNames::for_test(&[]), true);
            az.shared = std::sync::Arc::new(crate::state::Shared {
                inner: std::sync::Mutex::new(crate::state::Inner::default()),
                exec_warn: ms_to_ticks(1.0),
                fault_warn: ms_to_ticks(50.0),
                io_warn: ms_to_ticks(200.0),
                keep: ms_to_ticks(20_000.0),
                switches: traced,
                debug: false,
            });
            az.wait_moments = 1;
            az.program_waits.insert("game.exe".into(), ProgramWait { ready: ms_to_ticks(180.0), moments: 1, ..ProgramWait::default() });
            az.incidents.push(IncidentSummary {
                class: IncidentClass::Freeze,
                start: qpc() - 60 * crate::util::qpc_freq(),
                dur: ms_to_ticks(900.0),
                culprit: "whole-PC freeze".into(),
                marked: false,
                cpus: (0..8).collect(),
                on_cpu: None,
                freeze: Some(FreezeFacts {
                    cpus: 8,
                    ncpu: 8,
                    probes: ProbeVerdict { late: 8, ..ProbeVerdict::default() },
                    ..FreezeFacts::default()
                }),
            });
            // A short stall whose verdict came out of the switch trace.
            az.incidents.push(IncidentSummary {
                class: IncidentClass::Kernel,
                start: qpc() - 30 * crate::util::qpc_freq(),
                dur: ms_to_ticks(20.0),
                culprit: "not woken (nothing woke the thread)".into(),
                marked: false,
                cpus: vec![1],
                on_cpu: None,
                freeze: None,
            });
            let stats = ProbeStats { realtime: AtomicBool::new(true), ..ProbeStats::default() };
            az.summarize(RunData {
                elapsed_s: 300.0,
                events_lost: lost,
                overhead: Overhead::default(),
                light: None,
                stats: &stats,
                exec_warn: ms_to_ticks(1.0),
                io_warn: ms_to_ticks(200.0),
                clock: &[],
                gpu: &GpuLog::default(),
            })
        };

        // Everything arrived: the scheduler has its say.
        let good = report(0, true);
        let freeze_said = |s: &Summary| s.findings.iter().find(|f| f.key == "whole-PC freeze").unwrap().evidence.join(" ");
        assert!(freeze_said(&good).contains("never made runnable"), "{}", freeze_said(&good));
        assert!(good.findings.iter().any(|f| f.key == "waiting game.exe"));
        assert!(good.findings.iter().any(|f| f.key == "not woken (nothing woke the thread)"), "{:?}", keys(&good));

        // Events lost, or switches never traced: the same data, and none of it is used.
        for summary in [report(17, true), report(0, false)] {
            assert!(!freeze_said(&summary).contains("never made runnable"), "{}", freeze_said(&summary));
            assert!(!freeze_said(&summary).contains("measuring threads"), "{}", freeze_said(&summary));
            assert!(!summary.findings.iter().any(|f| f.key.starts_with("waiting ")), "{:?}", keys(&summary));
            // The stall still counts, under the vaguer verdict it would have had without the trace.
            assert!(!summary.findings.iter().any(|f| f.key.contains("nothing woke the thread")), "{:?}", keys(&summary));
            let generic = summary.findings.iter().find(|f| f.key == "not woken (timers or scheduling)").expect("still counted");
            assert!(generic.evidence[0].contains("1 stall"), "{:?}", generic.evidence);
        }
        // ...and a run that lost events says so where its own cost is reported.
        assert!(
            report(17, true).detail_lines().iter().any(|l| l.contains("nothing in this report rests on the thread-switch trace")),
            "a suppressed measurement has to be admitted"
        );
    }

    fn keys(s: &Summary) -> Vec<&str> {
        s.findings.iter().map(|f| f.key.as_str()).collect()
    }

    /// The first screen has to read as a plan: the verdict, then how many problems of each kind
    /// there are, then what to change first - and the whole-PC freeze above everything else.
    #[test]
    fn result_block_leads_with_the_verdict_and_stays_within_width() {
        let lines = Summary::demo(Health::Problem).result_lines();
        let verdict = lines.iter().find(|l| l.contains(">>>")).expect("verdict line");
        assert!(verdict.contains("PROBLEM FOUND") && verdict.contains("The whole PC stopped"), "{verdict}");
        let at = |needle: &str| lines.iter().position(|l| l.contains(needle));
        assert!(at("WHAT THIS RUN FOUND") < at("ORDER OF ATTACK"), "{lines:?}");
        assert!(at("ORDER OF ATTACK") < at("THE WHOLE PC STOPS"), "the plan comes before the findings: {lines:?}");
        assert!(at("THE WHOLE PC STOPS") < at("SHORT INTERRUPTIONS"), "groups in felt-impact order: {lines:?}");
        assert!(at("SHORT INTERRUPTIONS") < at("ONE PROGRAM WAITS"), "{lines:?}");
        assert!(at("ONE PROGRAM WAITS") < at("WORTH KNOWING"), "{lines:?}");
        assert!(lines.iter().any(|l| l.contains("Start here:")), "{lines:?}");
        assert!(lines.iter().any(|l| l.contains("What to try:")));
        assert!(lines.iter().all(|l| l.chars().count() <= WIDTH), "advice text must be wrapped");
        // Correlation language, never causation, and the gaps are named.
        let text = lines.join(" ");
        assert!(text.contains("coincided with") && text.contains("coincided with nothing"), "{text}");
        assert!(text.contains("What is NOT explained"), "{text}");
    }

    /// A healthy PC with a couple of background notes (RGB tools present, an old-style interrupt)
    /// must not be told to "start here": there is nothing to attack.
    #[test]
    fn background_notes_alone_do_not_get_an_order_of_attack() {
        let mut summary = Summary::demo(Health::Ok);
        summary.findings.push(Finding {
            key: "hardware tools".into(),
            group: Group::Health,
            severity: Severity::Low,
            title: "6 programs that talk to the hardware directly are running".into(),
            evidence: vec!["e".into()],
            advice: "a".into(),
            metrics: Vec::new(),
            impact: 0,
        });
        let lines = summary.result_lines();
        assert!(!lines.iter().any(|l| l.contains("ORDER OF ATTACK") || l.contains("Start here")), "{lines:?}");
        assert!(lines.iter().any(|l| l.contains("Nothing here needs fixing")), "{lines:?}");
        // One real finding brings the plan back.
        summary.findings.insert(
            0,
            Finding {
                key: "driver x.sys".into(),
                group: Group::Interruptions,
                severity: Severity::Medium,
                title: "x.sys  -  something".into(),
                evidence: vec!["e".into()],
                advice: "a".into(),
                metrics: Vec::new(),
                impact: 0,
            },
        );
        assert!(summary.result_lines().iter().any(|l| l.contains("Start here: x.sys")));
    }

    /// A long tail of findings must not bury the answer, and nothing may be silently dropped.
    #[test]
    fn only_the_top_findings_are_shown_in_full_and_the_rest_are_folded_into_details() {
        let mut summary = Summary::demo(Health::Problem);
        let noise = |i: usize, group: Group, severity| Finding {
            key: format!("driver noise{i}.sys"),
            group,
            severity,
            title: format!("noise{i}.sys  -  something"),
            evidence: vec!["e".into()],
            advice: "a".into(),
            metrics: Vec::new(),
            impact: 0,
        };
        for i in 0..10 {
            summary.findings.push(noise(i, Group::Interruptions, Severity::Medium));
            summary.findings.push(noise(100 + i, Group::Health, Severity::Low));
        }
        let lines = summary.result_lines();
        let shown = lines.iter().filter(|l| l.contains("] ") && l.contains("  -  ")).count();
        assert!(shown <= SHOWN_MAX, "{shown} findings shown in full");
        assert!(lines.iter().any(|l| l.contains("more in this group")), "the rest are folded: {lines:?}");
        assert!(lines.iter().all(|l| l.chars().count() <= WIDTH), "{lines:?}");
        // The freeze is still first, and every finding is still listed under DETAILS.
        assert!(lines.iter().position(|l| l.contains("The whole PC stopped")) < lines.iter().position(|l| l.contains("noise")));
        let details = summary.detail_lines();
        assert!(details.iter().any(|l| l.contains("ALL FINDINGS")), "{details:?}");
        for f in &summary.findings {
            assert!(details.iter().any(|l| l.contains(f.title.split("  -  ").next().unwrap())), "{} missing from DETAILS", f.title);
        }
        assert!(details.iter().all(|l| l.chars().count() <= DETAIL_WIDTH), "{details:?}");
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

    /// The 59-minute field report from issue #15, rebuilt from synthetic incidents: one
    /// recurring whole-PC freeze plus three background problems. What used to come out as 34
    /// findings, 23 of them HIGH, blaming a dozen bystanders.
    #[test]
    fn the_field_report_becomes_one_freeze_finding_and_a_plan() {
        use crate::analyze::{Coincided, FreezeFacts, IncidentClass, IncidentSummary};
        use crate::diskwait::Role;
        use crate::intr::Flow;
        use crate::modules::ModuleMap;
        use crate::procs::ProcNames;
        use crate::switches::ProbeVerdict;
        use std::sync::atomic::AtomicBool;

        let mut az = Analyzer::for_test(ModuleMap::for_test(&[]), ProcNames::for_test(&[(32468, "SignalRgb.exe")]), true);
        let freq = crate::util::qpc_freq();
        let t0 = qpc() - 3561 * freq;
        // Twelve freezes; eight of them coincide with a slow request to a drive that had been
        // asleep, four with nothing at all. Every one of them has a different program on the
        // CPUs, which is exactly how the old report produced a dozen accusations.
        for i in 0..12i64 {
            let coincided = (i < 8).then(|| Coincided { disk: Some(6), role: Role::Trigger, waited: ms_to_ticks(2173.0), woke: true });
            az.incidents.push(IncidentSummary {
                class: IncidentClass::Freeze,
                start: t0 + i * 290 * freq,
                dur: ms_to_ticks(900.0 + i as f64 * 8.0),
                culprit: "whole-PC freeze".into(),
                marked: false,
                cpus: (0..8).collect(),
                on_cpu: None,
                freeze: Some(FreezeFacts {
                    cpus: 8,
                    ncpu: 8,
                    idle_share: if i % 2 == 0 { 0.86 } else { 0.02 },
                    samples: 120,
                    on_cpu: vec!["SignalRgb.exe (32468)".into(), "explorer.exe (23584)".into()],
                    silent: if i < 8 { vec![("Wdf01000.sys".into(), 0.0)] } else { vec![("dxgkrnl.sys".into(), 0.05)] },
                    continued: if i < 8 { vec![("dxgkrnl.sys".into(), 0.68)] } else { vec![("Wdf01000.sys".into(), 1.37)] },
                    timer: Some(Flow::Silent),
                    dpcs_kept_running: true,
                    holding: None,
                    coincided,
                    // The answer the field logs could not give: in nine of the twelve, all eight
                    // measuring threads were never made runnable (nothing woke them); in three
                    // they were made runnable on time and left on an idle processor.
                    probes: if i < 9 {
                        ProbeVerdict { late: 8, worst_delay: ms_to_ticks(890.0), ..ProbeVerdict::default() }
                    } else {
                        ProbeVerdict { queued: 8, on_idle_cpu: 8, ..ProbeVerdict::default() }
                    },
                }),
            });
        }
        // The background layer: a network filter stalling one core every 60 s.
        for i in 0..55i64 {
            az.incidents.push(IncidentSummary {
                class: IncidentClass::Kernel,
                start: t0 + i * 60 * freq,
                dur: ms_to_ticks(13.52),
                culprit: "driver NETIO.SYS".into(),
                marked: false,
                cpus: vec![5],
                on_cpu: Some("iCUE.exe (4242)".into()),
                freeze: None,
            });
        }
        // ...and a single 31 ms starvation stall, which used to be reported as HIGH.
        az.incidents.push(IncidentSummary {
            class: IncidentClass::Starvation,
            start: t0 + 900 * freq,
            dur: ms_to_ticks(31.6),
            culprit: "process consent.exe (18812)".into(),
            marked: false,
            cpus: Vec::new(),
            on_cpu: None,
            freeze: None,
        });

        let stats = ProbeStats { realtime: AtomicBool::new(true), ..ProbeStats::default() };
        az.shared.inner.lock().unwrap().events = 37_917_537;
        let summary = az.summarize(RunData {
            elapsed_s: 3561.0,
            events_lost: 0,
            overhead: Overhead::default(),
            light: None,
            stats: &stats,
            exec_warn: ms_to_ticks(1.0),
            io_warn: ms_to_ticks(200.0),
            clock: &[],
            gpu: &GpuLog::default(),
        });

        let freeze = summary.findings.iter().find(|f| f.key == "whole-PC freeze").expect("one freeze finding");
        assert_eq!(freeze.group, Group::WholePc);
        assert_eq!(summary.findings.iter().filter(|f| f.key == "whole-PC freeze").count(), 1, "one finding, not twelve");
        assert_eq!(summary.findings[0].key, "whole-PC freeze", "and it is the first thing the report says");
        let said = freeze.evidence.join(" ");
        assert!(said.contains("12 freezes"), "{said}");
        assert!(said.contains("8 of the 12 freezes coincided with a slow request"), "{said}");
        assert!(said.contains("4 of the 12 freezes coincided with nothing at all"), "both numbers: {said}");
        assert!(said.contains("Wdf01000.sys stopped completely in 8 of 12"), "{said}");
        // The one thing the field logs in issue #15 could not say, now said, with both shapes and
        // both counts, and in words that name a layer rather than a bystander.
        assert!(said.contains("measuring threads were never made runnable"), "{said}");
        assert!(said.contains("in 9 of them") && said.contains("in 3 of them"), "both numbers: {said}");
        assert!(said.contains("the timer that wakes sleeping threads failing to fire"), "{said}");
        assert!(said.contains("nothing else to do"), "the idle-processor half: {said}");
        assert!(freeze.advice.contains("C-states"), "the order of attack narrows: {}", freeze.advice);
        assert!(said.contains("What is NOT explained"), "{said}");
        assert!(said.contains("Context, not blame") && said.contains("SignalRgb.exe"), "named, never blamed: {said}");
        // No bystander is a finding of its own, and nothing anywhere claims raised IRQL.
        for f in &summary.findings {
            assert!(!f.title.starts_with("SignalRgb.exe"), "a bystander became a finding: {}", f.title);
            assert!(!f.title.starts_with("explorer.exe"), "{}", f.title);
        }
        assert!(!summary.findings.iter().any(|f| f.evidence.iter().any(|e| e.contains("raised IRQL"))));

        // The background layers are still reported, at a severity that matches how often they
        // happen rather than how long the run was.
        let netio = summary.findings.iter().find(|f| f.key == "driver NETIO.SYS").expect("the network filter");
        assert_eq!((netio.severity, netio.group), (Severity::Medium, Group::Interruptions), "{:?}", netio.evidence);
        // ...and the report says which program it was working for. All 55 stalls had iCUE.exe on
        // the processor, which is what turns "update your network driver" into something to do.
        assert!(
            netio.evidence.iter().any(|e| e.contains("while iCUE.exe was on the processor, in 55 of the 55 of them")),
            "{:?}",
            netio.evidence
        );
        assert!(netio.evidence.iter().any(|e| e.contains("the program to try closing first")), "{:?}", netio.evidence);
        let consent = summary.findings.iter().find(|f| f.key.contains("consent.exe")).expect("the one starvation stall");
        assert_eq!(consent.severity, Severity::Low, "one 31 ms stall in an hour is a lead, not a HIGH");

        // The first screen reads as a plan and every line fits the report.
        let lines = summary.result_lines();
        let at = |needle: &str| lines.iter().position(|l| l.contains(needle));
        assert!(at("WHAT THIS RUN FOUND") < at("ORDER OF ATTACK"));
        assert!(at("ORDER OF ATTACK") < at("THE WHOLE PC STOPS"));
        assert!(lines.iter().any(|l| l.contains("Start here:") && l.contains("whole PC")), "{lines:?}");
        assert!(lines.iter().any(|l| l.contains("12 whole-PC freezes")), "the counts are honest: {:?}", summary.overview);
        assert!(lines.iter().any(|l| l.contains("55 short kernel-level")), "{:?}", summary.overview);
        let full = lines.iter().filter(|l| l.contains("] ") && l.contains("  -  ")).count();
        assert!(full <= SHOWN_MAX, "{full} findings shown in full");
        assert!(lines.iter().all(|l| l.chars().count() <= WIDTH), "{lines:?}");
        // The block this section adds to DETAILS. (The DRIVE HEALTH table below it can
        // already run past the width on a PC with several NVMe drives; that is issue #13's
        // table, not this one.)
        let details = summary.detail_lines();
        let all_findings = details.iter().skip_while(|l| !l.contains("ALL FINDINGS")).take_while(|l| !l.is_empty());
        for l in all_findings {
            assert!(l.chars().count() <= DETAIL_WIDTH, "{} chars: {l}", l.chars().count());
        }

        // The freeze can be compared with the next run without a process ID or a timestamp in
        // the key, and by a number that does not grow with the length of the run.
        assert_eq!(crate::baseline::stable_key(&freeze.key), "whole-PC freeze");
        assert_eq!(freeze.metrics[0].label, "freezes per hour");
        assert!((freeze.metrics[0].value - 12.13).abs() < 0.1, "{:?}", freeze.metrics);
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
