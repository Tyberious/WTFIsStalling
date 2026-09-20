//! Turns a finished run into an answer: a one-line verdict, ranked findings (what, evidence,
//! what to try) and the supporting tables. Front ends decide how to present it.

use std::collections::HashMap;
use std::mem::{size_of, zeroed};
use std::sync::atomic::Ordering;

use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};

use crate::analyze::Analyzer;
use crate::modules::knowledge;
use crate::probe::{ProbeStats, StallKind};
use crate::state::*;
use crate::util::{fmt_dur, ms_to_ticks, qpc};

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
    pub overview: String,
    pub findings: Vec<Finding>,
    /// Supporting tables, already formatted.
    pub details: Vec<String>,
}

const WIDTH: usize = 100;

fn wrap(text: &str, indent: &str, out: &mut Vec<String>) {
    let mut line = String::new();
    for word in text.split_whitespace() {
        if !line.is_empty() && indent.len() + line.len() + 1 + word.len() > WIDTH {
            out.push(format!("{indent}{line}"));
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
        out.push(format!("  {}", self.overview));
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
                    "Disk 1  -  responding slowly",
                    "3 requests took longer than 200 ms (worst 840 ms).",
                    "Check its health (SMART), make sure it isn't nearly full, update SSD firmware.",
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
            overview: "Monitored 05:12  |  demo data, not a real measurement".into(),
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
}

const GENERIC_DRIVER_ADVICE: &str = "Update this driver from the device maker's site, or roll it back if the problem started after an \
    update. To confirm, temporarily disable the device (or close the software it belongs to) and monitor again.";

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

impl Analyzer {
    pub fn summarize(&mut self, elapsed_s: f64, events_lost: u32, stats: &ProbeStats, exec_warn: i64, io_warn: i64) -> Summary {
        let inner = self.shared.inner.lock().unwrap();
        let routines = inner.routines.clone();
        let faults = inner.faults_by_pid.clone();
        let disks = inner.disks.clone();
        let events = inner.events;
        let mut debug_counts: Vec<_> = inner.debug_counts.iter().map(|(k, v)| (*k, *v)).collect();
        let debug_rejected = inner.debug_rejected.clone();
        drop(inner);

        let mut found = Findings::default();
        let mut details: Vec<String> = Vec::new();
        macro_rules! d {
            ($($a:tt)*) => { details.push(format!($($a)*)) };
        }

        // ---- Stalls, by who was blamed -------------------------------------------------
        let mut tally: HashMap<String, (u32, i64, i64)> = HashMap::new();
        for i in &self.incidents {
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
                let what = self.modules.describe(m);
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
                found.add(
                    culprit,
                    sev,
                    format!("{p}  -  program"),
                    format!("Was occupying the CPU during {stalls}."),
                    "Close this program and monitor again. If the stalls disappear, update or replace it, or look at the driver it \
                     leans on (listed under 'Kernel-mode time by module' in the event log)."
                        .into(),
                    *total,
                );
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
            let what = self.modules.describe(name);
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
            found.add(
                &format!("disk {n}"),
                sev,
                format!("Disk {n}  -  responding slowly"),
                format!(
                    "{} request{} took longer than {} (worst {}).",
                    s.slow,
                    if s.slow == 1 { "" } else { "s" },
                    fmt_dur(io_warn),
                    fmt_dur(s.max)
                ),
                format!(
                    "Anything that touches this disk freezes while it answers. Check its health (SMART) with the maker's tool or \
                     CrystalDiskInfo, make sure it isn't nearly full, update SSD firmware, and reseat or replace the cable on SATA \
                     drives. Disk {n} is the number shown in Windows Disk Management."
                ),
                s.max * s.slow as i64,
            );
        }

        let mut findings: Vec<Finding> = found.0.into_iter().map(|(_, f)| f).collect();
        findings.sort_by_key(|f| (std::cmp::Reverse(f.severity), std::cmp::Reverse(f.impact)));

        // ---- Verdict -----------------------------------------------------------------
        let kernel_stalls = self.incidents.iter().filter(|i| i.kind == StallKind::Kernel).count();
        let sched_stalls = self.incidents.len() - kernel_stalls;
        let secs = elapsed_s as u64;
        let overview = format!(
            "Monitored {:02}:{:02}  |  {kernel_stalls} kernel-level stall(s), {sched_stalls} CPU-starvation stall(s)  |  worst wake-up delay {} (real-time thread), {} (normal thread)",
            secs / 60,
            secs % 60,
            fmt_dur(stats.max_kernel.load(Ordering::Relaxed)),
            fmt_dur(stats.max_sched.load(Ordering::Relaxed))
        );

        let more =
            |n: usize| if n > 1 { format!("  (+{} more finding{} below)", n - 1, if n == 2 { "" } else { "s" }) } else { String::new() };
        let top = findings.first();
        let (health, headline, subline) = if events == 0 {
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
