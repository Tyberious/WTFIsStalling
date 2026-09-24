//! Who or what stalled the machine: the tally of blamed culprits, the moments the user flagged,
//! drivers whose DPC/ISR runs went long, and whether any of it keeps time.

use crate::baseline::stable_key;
use std::collections::HashMap;

use crate::analyze::{CoreHolder, IncidentClass};
use crate::modules::knowledge;
use crate::period;
use crate::state::{is_isr, Beats, BEAT_MS, KIND_ISR_MSI};
use crate::util::{fmt_dur, ms_to_ticks, plural, qpc_freq, ticks_to_ms};

use super::ctx::Ctx;
use super::wording::{on_behalf_of, process_advice, process_title, GENERIC_DRIVER_ADVICE, POLLING_ADVICE};
use super::{Group, Metric, Severity};

const DARK_ADVICE: &str = "Windows itself was frozen out, which points below the operating system. Update the BIOS/UEFI, load BIOS \
    defaults (undo overclocks and memory tweaks), disable 'Legacy USB support' and unused onboard devices as a test, check for \
    thermal throttling, and if Hyper-V / Core Isolation (VBS) is enabled, test with it off. If it persists, suspect hardware.";

#[derive(Default)]
pub(super) struct DriverAgg {
    pub dpc_n: u64,
    pub dpc_max: i64,
    /// Both ISR kinds together, and then apart: `isr_line_n` from the documented ISR event (67),
    /// `isr_msi_n` from the message-signaled one (50). See `etw::events` for the sources.
    pub isr_n: u64,
    pub isr_line_n: u64,
    pub isr_msi_n: u64,
    pub isr_max: i64,
    pub total: i64,
    pub over: u64,
}

impl DriverAgg {
    /// Which kind of interrupt its handler actually ran for, when it ran one at all.
    pub fn isr_seen(&self) -> Option<crate::interrupts::Observed> {
        crate::interrupts::Observed::from_counts(self.isr_line_n, self.isr_msi_n)
    }
}

/// QPC ticks -> seconds, which is what the periodicity detector works in.
fn secs(ticks: &[i64]) -> Vec<f64> {
    ticks.iter().map(|t| *t as f64 / qpc_freq() as f64).collect()
}

/// How bad a run of stalls blamed on one subject is, relative to the length of the run and to
/// what a person can feel.
///
/// Counting alone inflated everything on a long run: "1 stall, 31 ms" came out HIGH because a
/// separate rule said "worst >= 15 ms". So:
/// * 100 ms is the classic limit above which an interruption stops feeling instantaneous
///   (nngroup.com/articles/response-times-3-important-limits), so one of those is serious on its
///   own, whenever it happened.
/// * Under that, what makes a short stall matter is how OFTEN it comes back. Once every ten
///   seconds (360 per hour) at 5 ms or more is continuous audio crackle; that is High.
/// * So is anything that adds up to half a percent of the whole run, however it is distributed.
/// * A couple an hour is a lead worth knowing (Low). Between the two, a suspect (Medium).
///
/// How many processors a stall held matters too (issue #19): a kernel-level stall on 1 of 32
/// leaves 31 carrying on, so the PC as a whole kept responding. The two rules that stand for "the
/// PC stopped responding" - one felt stall of 100 ms, half a percent of the run - therefore count
/// each stall in proportion to its breadth (`breadth`), with a quarter of the processors or more
/// counting in full. Rule of thumb, not a measurement. The crackle rule keeps the raw length:
/// audio breaks up when the one core its work is on is held, however many others are free. And
/// the raw length still makes a 50 ms hold at least a suspect, however narrow.
fn stall_severity(t: &Tally, run_s: f64) -> Severity {
    let per_hour = f64::from(t.n) * 3600.0 / run_s.max(1.0);
    let share = ticks_to_ms(t.felt_total) / (run_s.max(1.0) * 1000.0);
    if t.felt_worst >= ms_to_ticks(100.0) || (per_hour >= 360.0 && t.worst >= ms_to_ticks(5.0)) || share >= 0.005 {
        Severity::High
    } else if per_hour >= 2.0 || t.worst >= ms_to_ticks(50.0) {
        Severity::Medium
    } else {
        Severity::Low
    }
}

/// Stalls blamed on one subject, with their lengths as measured and as weighted by `breadth`.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
struct Tally {
    n: u32,
    worst: i64,
    total: i64,
    /// Longest and total after weighting each stall by how many processors it held.
    felt_worst: i64,
    felt_total: i64,
}

impl Tally {
    fn add(&mut self, dur: i64, breadth: f64) {
        let felt = (dur as f64 * breadth) as i64;
        self.n += 1;
        self.total += dur;
        self.worst = self.worst.max(dur);
        self.felt_total += felt;
        self.felt_worst = self.felt_worst.max(felt);
    }
}

/// How much of "the PC" one stall held, 0-1: its processors against a quarter of this PC's. A
/// CPU-starvation stall is PC-wide by definition (no core at all for a normal thread), and when
/// the processor count is unknown the stall counts in full, which is how it was always judged.
fn breadth(class: IncidentClass, held: usize, ncpu: usize) -> f64 {
    if class == IncidentClass::Starvation || ncpu == 0 || held == 0 {
        return 1.0;
    }
    let quarter = (ncpu as f64 / 4.0).max(1.0);
    (held as f64 / quarter).min(1.0)
}

/// "14 stalls (worst 11.80 ms, 121 ms in total), about 14 per hour"
fn how_often(n: u32, worst: i64, total: i64, run_s: f64) -> String {
    let per_hour = f64::from(n) * 3600.0 / run_s.max(1.0);
    let rate = if n > 1 {
        format!(", about {} per hour", if per_hour >= 10.0 { format!("{per_hour:.0}") } else { format!("{per_hour:.1}") })
    } else {
        String::new()
    };
    format!("{n} stall{} (worst {}, {} in total){rate}", plural(u64::from(n)), fmt_dur(worst), fmt_dur(total))
}

/// Stalls grouped by who was blamed, worst total first. Whole-PC freezes are not here: they are
/// one incident class with one finding of their own (`freezes`), because everything the samples
/// inside them landed in was a bystander.
pub(super) fn tally(cx: &mut Ctx) {
    let run_s = cx.run.elapsed_s;
    let ncpu = cx.az.ncpu();
    let mut tally: HashMap<String, Tally> = HashMap::new();
    // One or a few cores busy while the rest idled, per subject: (how many stalls, what held it).
    let mut busy_cores: HashMap<String, (u32, Vec<String>)> = HashMap::new();
    // A verdict that rests on the context-switch trace has to fall back to the vaguer one when
    // that trace cannot be trusted; see `Ctx::scheduler_usable`.
    let usable = cx.scheduler_usable();
    for i in cx.az.incidents.iter().filter(|i| !i.marked && i.class != IncidentClass::Freeze) {
        let culprit = match i.culprit.as_str() {
            "not woken (nothing woke the thread)" | "not woken (ready, but given no processor)" if !usable => {
                "not woken (timers or scheduling)"
            }
            other => other,
        };
        // Keyed without the process ID: a browser runs a dozen processes, and four findings for
        // "msedge.exe" are one finding said four times.
        let key = stable_key(culprit);
        tally.entry(key.clone()).or_default().add(i.dur, breadth(i.class, i.cpus.len(), ncpu));
        if let Some(holder) = &i.busy_core {
            let e = busy_cores.entry(key).or_default();
            e.0 += 1;
            if let Some(name) = holder_name(holder) {
                if !e.1.contains(&name) {
                    e.1.push(name);
                }
            }
        }
    }
    let mut tally: Vec<(String, Tally)> = tally.into_iter().collect();
    tally.sort_by_key(|(_, t)| std::cmp::Reverse(t.total));

    for (culprit, t) in &tally {
        let (n, total, worst) = (&t.n, &t.total, &t.worst);
        let sev = stall_severity(t, run_s);
        let stalls = how_often(*n, *worst, *total, run_s);
        if let Some(m) = culprit.strip_prefix("driver ") {
            let what = cx.az.modules.describe_short(m);
            let advice = knowledge(m).map(|k| k.advice).unwrap_or(GENERIC_DRIVER_ADVICE);
            cx.found.add(culprit, sev, format!("{m}  -  {what}"), format!("Blamed for {stalls}."), advice.into(), *total);
        } else if culprit.starts_with("CPU went dark") {
            cx.found.add(
                culprit,
                sev,
                "Firmware / BIOS (SMI), a hypervisor, or a driver running with interrupts disabled".into(),
                format!("The CPU vanished from Windows' view during {stalls}: no DPC/ISR ran and profiler interrupts went missing."),
                DARK_ADVICE.into(),
                *total,
            );
        } else if let Some(p) = culprit.strip_prefix("process ") {
            cx.found.add(culprit, sev, process_title(p), format!("Was occupying the CPU during {stalls}."), process_advice(p), *total);
        } else if let Some(n_disk) = culprit.strip_prefix("disk ").and_then(|n| n.parse::<u32>().ok()) {
            // A normal thread that could not run while the CPUs were idle was blocked, and the
            // trace says on which drive. Same subject as the storage section's "disk N", so it
            // belongs in the same finding and in the same group.
            let disk = cx.az.disks.get(n_disk).clone();
            cx.found.in_group(Group::OneProgram);
            cx.found.add(
                culprit,
                sev,
                format!("{}  -  froze what was waiting on it", disk.title()),
                format!(
                    "A normal program thread could not run during {stalls} while the processors were idle, because it was \
                         waiting for this drive to answer."
                ),
                "Anything that touches this drive waits with it. Check its health (SMART) with the maker's tool or \
                 CrystalDiskInfo, stop it from sleeping (Power Options > Hard disk > 'Turn off hard disk after' = 0), and keep \
                 files you use while playing or working off it."
                    .into(),
                *total,
            );
            cx.found.in_group(Group::Interruptions);
        } else if culprit == "waiting on paging" {
            cx.found.add(
                culprit,
                sev,
                "Threads were held up waiting for memory to come back from disk".into(),
                format!(
                    "During {stalls} nothing was holding the processors: this tool's own measuring thread was waiting for \
                         memory to be read back from disk, which is what any program in the same position would be doing."
                ),
                "See the paging findings in this report: close memory-hungry programs (a browser with many tabs is the usual \
                 one), or move the paging file to your fastest drive."
                    .into(),
                *total,
            );
        } else if culprit.starts_with("not woken") {
            // Three flavors of the same shape, told apart by the context-switch trace: nothing
            // woke the thread at all, it was woken and left without a processor, or the trace
            // could not say which. The remedies overlap but the first sentence must not.
            let (title, what) = match culprit.as_str() {
                "not woken (nothing woke the thread)" => (
                    "Sleeping threads were not woken on time",
                    "and nothing made the measuring thread runnable until it was over: the timer that wakes sleeping threads did \
                     not fire. That is below Windows' scheduling and below every driver.",
                ),
                "not woken (ready, but given no processor)" => (
                    "Threads were ready to run and got no processor",
                    "and the measuring thread WAS made runnable on time and then was not given a processor. No thread outranks it \
                     and no processor was held at interrupt level, so this points at the scheduler or the platform rather than \
                     another program.",
                ),
                _ => (
                    "Threads were not woken on time, with no processor held",
                    "so nothing was blocking the processors: threads simply were not woken, by timer delivery or by scheduling.",
                ),
            };
            cx.found.add(
                culprit,
                sev,
                title.into(),
                format!(
                    "During {stalls} ordinary interrupt work kept running on the affected processors, which cannot happen while a \
                     driver holds one, {what}"
                ),
                "This is a timing problem below the programs; power management and the system clock are the places to look. Test with the 'High \
                 performance' power plan, update the BIOS/UEFI and the chipset driver, and undo any 'latency tweak' that changed \
                 the timer (bcdedit settings such as useplatformclock or disabledynamictick)."
                    .into(),
                *total,
            );
        } else if culprit == "unexplained" {
            // Nothing to act on, so it takes a lot of them before this outranks a real finding.
            let sev = if *n >= 3 { sev } else { sev.min(Severity::Medium) };
            cx.found.add(
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
            cx.found.add(
                culprit,
                Severity::Medium,
                "All CPU cores were busy".into(),
                format!("An ordinary thread could not get a core during {stalls}, and CPU sampling was unavailable to say who."),
                "Check Task Manager for programs using a lot of CPU while the problem happens.".into(),
                *total,
            );
        } else if culprit == "scheduling delay with idle CPUs" {
            cx.found.add(
                culprit,
                sev.min(Severity::Medium),
                "Delays with idle processors and no visible cause".into(),
                format!(
                    "{stalls}. A normal program thread could not run even though the processors had nothing to do, and neither \
                     disk activity nor paging lines up with it, so what held it up is not visible in this trace."
                ),
                "Test the 'High performance' power plan (processor core parking can do this), and run again for longer while \
                 reproducing the problem so a pattern can appear."
                    .into(),
                *total,
            );
        }
        // The two numbers a next run is judged by: how often, and how bad at worst.
        cx.found.measure(culprit, Metric::count("stalls blamed", *n));
        cx.found.measure(culprit, Metric::ms("worst stall", ticks_to_ms(*worst)));
        // Context only: a busy core next to idle ones does not say the waiting thread needed THAT
        // core, and nothing in the trace shows it was limited to it, so no more is claimed.
        if let Some((k, names)) = busy_cores.get(culprit) {
            let with = if names.is_empty() { String::new() } else { format!(", busy with {}", names.join(" / ")) };
            cx.found.note(
                culprit,
                format!(
                    "In {k} of these, one core (or a few) was busy while the others idled{with}. An average over all of them hid that."
                ),
            );
        }
    }
    cx.tally = tally.into_iter().map(|(k, t)| (k, (t.n, t.total, t.worst))).collect();
}

/// How a busy core's holder is named in a finding: Windows' own parts marked as such, nothing
/// said for "System", which is where every driver's work runs (see `wording::on_behalf_of`).
fn holder_name(holder: &CoreHolder) -> Option<String> {
    match holder {
        CoreHolder::Program(label) => on_behalf_of(label),
        CoreHolder::Driver(module) => Some(format!("interrupt handling in {module}")),
        CoreHolder::Unnamed => None,
    }
}

/// The moments the user flagged with "I felt it".
pub(super) fn flagged_moments(cx: &mut Ctx) {
    let mut marked: HashMap<String, (u32, i64)> = HashMap::new();
    for i in cx.az.incidents.iter().filter(|i| i.marked) {
        let m = marked.entry(stable_key(&i.culprit)).or_default();
        m.0 += 1;
        m.1 = m.1.max(i.dur);
    }
    let marks_total = cx.az.marks_total;
    for (culprit, (n, worst)) in &marked {
        let sev = match *n {
            1 => Severity::Low,
            2 => Severity::Medium,
            _ => Severity::High,
        };
        let evidence = format!(
            "Was interrupting a CPU core (for up to {}) at {n} of the {marks_total} moment{} you flagged with 'I felt it'.",
            fmt_dur(*worst),
            plural(marks_total as u64)
        );
        if let Some(m) = culprit.strip_prefix("driver ") {
            let what = cx.az.modules.describe_short(m);
            let advice = knowledge(m).map(|k| k.advice).unwrap_or(GENERIC_DRIVER_ADVICE);
            cx.found.add(culprit, sev, format!("{m}  -  {what}"), evidence, advice.into(), *worst * *n as i64);
        } else if let Some(p) = culprit.strip_prefix("process ") {
            cx.found.add(culprit, sev, process_title(p), evidence, process_advice(p), *worst * *n as i64);
        } else if culprit.starts_with("CPU went dark") {
            // Same key as the unmarked stalls of this kind, so both land in one finding.
            cx.found.add(
                culprit,
                sev,
                "Firmware / BIOS (SMI), a hypervisor, or a driver running with interrupts disabled".into(),
                format!(
                    "At {n} of the {marks_total} moment{} you flagged, a CPU core vanished from Windows' view (for up to {}): no \
                     DPC/ISR ran and profiler interrupts went missing.",
                    plural(marks_total as u64),
                    fmt_dur(*worst)
                ),
                DARK_ADVICE.into(),
                *worst * *n as i64,
            );
        } else {
            // A core was held up, but the trace cannot say by what. Still owed to the user:
            // every flagged moment has to show up somewhere in the result.
            cx.found.add(
                "unexplained",
                if *n >= 3 { Severity::Medium } else { Severity::Low },
                "Stalls without an identifiable cause".into(),
                format!(
                    "At {n} of the {marks_total} moment{} you flagged, a CPU core was held up (for up to {}), but neither DPC/ISR \
                     activity nor CPU samples pointed at anything.",
                    plural(marks_total as u64),
                    fmt_dur(*worst)
                ),
                "Monitor for longer while reproducing the problem so a pattern can emerge, and check the flagged entries in the \
                 event log for a module or program that keeps appearing."
                    .into(),
                *worst * *n as i64,
            );
        }
        // Flagged moments are the person's own doing, so they never scale with run length.
        let key = if culprit.starts_with("driver ") || culprit.starts_with("process ") || culprit.starts_with("CPU went dark") {
            culprit.as_str()
        } else {
            "unexplained"
        };
        cx.found.measure(key, Metric::flat("moments you flagged", *n));
    }
    if cx.az.marks_clean > 0 {
        cx.found.add(
            "clean marks",
            Severity::Low,
            "Hitches you flagged that left no trace on the CPU side".into(),
            format!(
                "At {} of the {marks_total} moment{} you flagged, no CPU core was held up long enough to feel (3 ms) and nothing else stood out.",
                cx.az.marks_clean,
                plural(marks_total as u64)
            ),
            "That rules out drivers, interrupts and firmware for those hitches. Look inside the app or at the GPU: shader \
             compilation, VRAM running out (lower texture quality), frame pacing / V-Sync settings, overlays, or the game's own \
             asset streaming."
                .into(),
            0,
        );
        cx.found.measure("clean marks", Metric::flat("moments you flagged", cx.az.marks_clean));
    }
}

/// A wait this long is what turns a hitch into something you see: at 60 frames a second it is
/// six frames, and it is well past the point where a click feels like it landed late.
const BAD_READY_MS: f64 = 100.0;
/// The same idea for a thread that was blocked, where waiting is normal and only a long one
/// stands out.
const BAD_BLOCKED_MS: f64 = 250.0;

/// Programs that were kept waiting at the moments the user flagged, and when a normal-priority
/// thread could not get a processor.
///
/// This section never names a cause. It says what happened to a program: it was ready to run and
/// did not get a processor (and what held that processor instead), or it was blocked and which
/// program's thread eventually woke it. Which lock, and why, is not in these events and is not
/// claimed. Severity is capped at Medium for exactly that reason: a symptom with no culprit must
/// not set the banner for the whole report.
pub(super) fn one_program_waits(cx: &mut Ctx) {
    if cx.az.wait_moments == 0 || !cx.scheduler_usable() {
        return;
    }
    let moments = cx.az.wait_moments;
    let mut rows: Vec<(String, crate::analyze::ProgramWait)> =
        cx.az.program_waits.iter().map(|(name, w)| (name.clone(), w.clone())).collect();
    // A program the person was looking at when it was kept waiting goes first, whatever waited
    // longer in the background: that is the one they felt (issue #19).
    rows.sort_by_key(|(name, w)| (w.in_front == 0, std::cmp::Reverse(w.ready.max(w.blocked)), name.clone()));
    // A report that lists twenty waiting programs says nothing; the worst few say it all.
    for (name, w) in rows.iter().take(4) {
        let key = format!("waiting {name}");
        let front =
            if w.in_front > 0 { format!(" (at {} of them it was {})", w.in_front, crate::foreground::role(name)) } else { String::new() };
        let when = format!("at {} of the {moments} moment{} this report examined closely{front}", w.moments, plural(u64::from(moments)));
        let severity =
            if w.ready >= ms_to_ticks(BAD_READY_MS) || w.blocked >= ms_to_ticks(BAD_BLOCKED_MS) { Severity::Medium } else { Severity::Low };
        let (evidence, advice) = if w.ready >= w.blocked {
            let (because, advice) = match (&w.instead, w.instead_idle) {
                (_, true) => (
                    " while the processor it was waiting for had nothing else to do at all. That is not other programs competing \
                     for it: something was not handing the processor over."
                        .to_string(),
                    "Nothing was competing for the processor, so closing programs will not help. Set Control Panel > Power Options \
                     to High performance, update the BIOS/UEFI and load its defaults, and if Core Isolation (Memory integrity) or \
                     Hyper-V is on, test once with it off. Then monitor again and compare."
                        .to_string(),
                ),
                (Some(other), _) => (format!(" while {} held that processor.", crate::procs::process_name(other)), process_advice(other)),
                (None, _) => (
                    " while something this trace could not name held that processor.".to_string(),
                    "Monitor again for longer while reproducing the hitch: with more of these moments the report can name what \
                     keeps taking the processor."
                        .to_string(),
                ),
            };
            (format!("One of its threads was ready to run and got no processor for {} {when}{because}", fmt_dur(w.ready),), advice)
        } else {
            let why = crate::switches::wait_reason_name(w.blocked_reason).map(|r| format!(" ({r})")).unwrap_or_default();
            let by = match &w.woken_by {
                Some(other) => format!(" It was eventually woken by a thread in {}.", crate::procs::process_name(other)),
                None => String::new(),
            };
            (
                format!(
                    "One of its threads was blocked for {} {when}{why}.{by} What it was waiting for is not in this trace: this says \
                     how long, not why.",
                    fmt_dur(w.blocked)
                ),
                "Look at the other findings in this report for something that fits: a drive responding slowly, paging, or a driver \
                 holding a processor. If none of them do, monitor for longer while reproducing the hitch."
                    .to_string(),
            )
        };
        // The title stays short (some `process_title` descriptions are a line on their own, and
        // the RESULT block does not wrap titles); what the program IS goes in the evidence
        // underneath, which is also where the audience rule is honored for Windows components.
        cx.found.add(&key, severity, format!("{name}  -  was held up"), evidence, advice, w.ready.max(w.blocked));
        let what = process_title(name);
        if !what.ends_with("-  program") {
            cx.found.note(&key, format!("What {name} is: {}.", what.replacen("  -  ", "", 1)));
        }
        // Both numbers when both were measured, so the next run can say which one moved.
        if w.ready > 0 {
            cx.found.measure(&key, Metric::ms("longest wait for a processor", ticks_to_ms(w.ready)));
        }
        if w.blocked > 0 {
            cx.found.measure(&key, Metric::ms("longest block", ticks_to_ms(w.blocked)));
        }
    }
    if rows.len() > 4 {
        cx.details.push(format!("  ({} more program(s) were kept waiting; the four worst are in the result above)", rows.len() - 4));
    }
}

/// How bad a driver's over-long interrupt handling is.
///
/// "3 times over the threshold" was a count, so an hour-long run reached it for almost anything.
/// What matters is how often it happens: once a minute of a 4 ms hold is a machine that crackles
/// continuously, once an hour is a note. (A DPC is expected to finish well inside 100 us; see
/// learn.microsoft.com/windows-hardware/drivers/kernel/guidelines-for-writing-dpc-routines.)
fn exec_severity(worst: i64, over: u64, run_s: f64) -> Severity {
    let over_per_hour = over as f64 * 3600.0 / run_s.max(1.0);
    if worst >= ms_to_ticks(4.0) && over_per_hour >= 60.0 {
        Severity::High
    } else if over_per_hour >= 2.0 || worst >= ms_to_ticks(2.0) {
        Severity::Medium
    } else {
        Severity::Low
    }
}

/// Drivers whose DPC or ISR runs went over the warning threshold.
pub(super) fn long_dpc_isr(cx: &mut Ctx) {
    let exec_warn = cx.run.exec_warn;
    let routines = std::mem::take(&mut cx.routines);
    let mut mods: HashMap<String, DriverAgg> = HashMap::new();
    for ((routine, kind), st) in &routines {
        let a = mods.entry(cx.az.modules.name(*routine)).or_default();
        if is_isr(*kind) {
            a.isr_n += st.count;
            a.isr_max = a.isr_max.max(st.max);
            if *kind == KIND_ISR_MSI {
                a.isr_msi_n += st.count;
            } else {
                a.isr_line_n += st.count;
            }
        } else {
            a.dpc_n += st.count;
            a.dpc_max = a.dpc_max.max(st.max);
        }
        a.total += st.total;
        a.over += st.over_warn;
    }
    let mut drivers: Vec<_> = mods.into_iter().collect();
    drivers.sort_by_key(|(_, a)| std::cmp::Reverse(a.dpc_max.max(a.isr_max)));

    let run_s = cx.run.elapsed_s.max(1.0);
    for (name, a) in &drivers {
        let worst = a.dpc_max.max(a.isr_max);
        if worst < exec_warn {
            continue;
        }
        let sev = exec_severity(worst, a.over, run_s);
        let what = cx.az.modules.describe_short(name);
        let advice = knowledge(name).map(|k| k.advice).unwrap_or(GENERIC_DRIVER_ADVICE);
        cx.found.add(
            &format!("driver {name}"),
            sev,
            format!("{name}  -  {what}"),
            format!(
                "Its interrupt handling ran for up to {} at a time ({} time{} over {}). Healthy drivers stay under 0.5 ms; \
                 longer runs block everything else on that CPU core and cause audio crackle and micro-stutter.",
                fmt_dur(worst),
                a.over,
                plural(a.over),
                fmt_dur(exec_warn)
            ),
            advice.into(),
            worst * a.over.max(1) as i64,
        );
        let key = format!("driver {name}");
        cx.found.measure(&key, Metric::ms("worst DPC/ISR", ticks_to_ms(worst)));
        cx.found.measure(&key, Metric::count("long runs", a.over as f64));
    }
    cx.drivers = drivers;
}

/// Fewest stalls blamed on one driver before the program it was working for is worth a sentence.
/// Under this it is as likely to be whatever happened to be on the processor: the periodicity
/// detector wants 5 events before it calls a pattern a pattern, and this is the same kind of claim.
const MIN_ON_BEHALF_STALLS: usize = 4;
/// ...and the share of THOSE stalls the same program has to hold. A plain majority would let
/// "5 of 9" through, which is not a pattern anyone should act on; 60% is.
const ON_BEHALF_SHARE: f64 = 0.6;

/// The one program a driver was working for in most of its stalls, with how many that was.
///
/// `names` is one entry per stall blamed on the driver: the program that held the processor, or
/// `None` where no single one did (or where naming it would say nothing - see
/// `wording::on_behalf_of`). The denominator stays ALL of that driver's stalls, so the sentence
/// the report prints uses the same number a reader can count in the table.
fn worked_for(names: &[Option<String>]) -> Option<(String, usize, usize)> {
    let total = names.len();
    if total < MIN_ON_BEHALF_STALLS {
        return None;
    }
    let mut counts: HashMap<&str, usize> = HashMap::new();
    for name in names.iter().flatten() {
        *counts.entry(name.as_str()).or_default() += 1;
    }
    let (name, n) = counts.into_iter().max_by_key(|(name, n)| (*n, std::cmp::Reverse(*name)))?;
    ((n as f64) >= total as f64 * ON_BEHALF_SHARE).then(|| (name.to_string(), n, total))
}

/// A driver does not decide to run: it runs because something asked it to. The CPU samples inside
/// a stall say who that was, which turns "update your storage driver" into "this happens while
/// iCUE.exe is running".
pub(super) fn on_whose_behalf(cx: &mut Ctx) {
    let mut per_driver: HashMap<String, Vec<Option<String>>> = HashMap::new();
    for i in cx.az.incidents.iter().filter(|i| !i.marked && i.class == IncidentClass::Kernel) {
        let key = stable_key(&i.culprit);
        if !key.starts_with("driver ") {
            continue;
        }
        per_driver.entry(key).or_default().push(i.on_cpu.as_deref().and_then(on_behalf_of));
    }
    let mut drivers: Vec<(String, Vec<Option<String>>)> = per_driver.into_iter().collect();
    drivers.sort_by(|a, b| a.0.cmp(&b.0));
    for (key, names) in &drivers {
        let Some((who, n, total)) = worked_for(names) else { continue };
        let windows = who.ends_with("(part of Windows)");
        let tail = if windows {
            " That is part of Windows rather than a program to close, so the thing to change is whatever asked it to do that work."
        } else {
            " A driver runs because something asked it to, so this is the program to try closing first."
        };
        cx.found.note(key, format!("Its stalls happened while {who} was on the processor, in {n} of the {total} of them.{tail}"));
    }
}

/// Drivers that wake on a steady beat without ever stalling anything.
///
/// The stall-based periodicity below can only see a driver whose bursts crossed a threshold. A
/// sensor poll that takes 300 microseconds every five seconds crosses nothing, yet it is the same
/// fingerprint and the same answer. So the ETW callback records, per DPC/ISR routine, which
/// quarter-second bucket of the run it was active in (`state::Beats`: one bit per bucket, a fixed
/// number of routines, so the memory is bounded and the callback stays O(1)), and this rolls those
/// bits up per driver and runs the same detector over them.
///
/// Third-party drivers only, and only ones whose own version resource says who wrote them: Windows
/// polls its own hardware on timers all day and saying so would be noise. A driver with no readable
/// version resource is skipped rather than guessed at.
/// Whether one driver's bucket map is a steady beat worth a note.
///
/// `is_microsoft` is what the file's own version resource says, or `None` when it has no readable
/// one. Only a driver someone else wrote is reported: Windows polls its own hardware on timers all
/// day, and an unknown author is not evidence of anything, so both are skipped rather than guessed.
///
/// The buckets are quarter-seconds, which is also `period::detect`'s own burst window, so a driver
/// that is simply always busy produces gaps of one bucket and is rejected by the detector's
/// one-second floor rather than by a rule of this function's own.
fn steady_beat(is_microsoft: Option<bool>, buckets: &[usize]) -> Option<period::Period> {
    if is_microsoft != Some(false) {
        return None;
    }
    let times: Vec<f64> = buckets.iter().map(|i| *i as f64 * BEAT_MS / 1000.0).collect();
    period::detect(&times)
}

pub(super) fn quiet_polling(cx: &mut Ctx) {
    let beats = std::mem::take(&mut cx.beats);
    let mut by_module: HashMap<String, Beats> = HashMap::new();
    for (routine, b) in &beats {
        let name = cx.az.modules.name(*routine);
        by_module.entry(name).or_default().merge(b);
    }
    let mut modules: Vec<(String, Beats)> = by_module.into_iter().collect();
    modules.sort_by(|a, b| b.1.count().cmp(&a.1.count()).then_with(|| a.0.cmp(&b.0)));

    let mut said = 0;
    for (module, b) in &modules {
        // A driver that already has a finding has been said more about than this could add.
        if cx.found.0.iter().any(|(k, _)| k == &format!("driver {module}")) || said >= MAX_QUIET_POLLERS {
            continue;
        }
        let Some(p) = steady_beat(cx.az.modules.is_microsoft(module), &b.buckets()) else { continue };
        let what = cx.az.modules.describe_short(module);
        let key = format!("timer {module}");
        cx.found.add(
            &key,
            Severity::Low,
            format!("{module}  -  {what}: wakes on a steady timer"),
            format!(
                "Its interrupt handling ran in {} separate quarter-second slices of the run, spread evenly: {} Nothing it did was \
                 long enough to stall this PC, so this is a lead rather than a problem.",
                b.count(),
                p.describe()
            ),
            format!(
                "Nothing to change unless the hitches you are chasing keep the same time. If they do: {}",
                knowledge(module).map(|k| k.advice).unwrap_or(POLLING_ADVICE)
            ),
            0,
        );
        // Both numbers a next run can compare: how often it wakes, and how much of the run it was
        // awake for. Neither grows just because the run was longer.
        cx.found.measure(&key, Metric::secs("wakes every", p.seconds));
        if let Some((_, agg)) = cx.drivers.iter().find(|(name, _)| name == module) {
            let total = agg.dpc_n + agg.isr_n;
            cx.found.note(
                &key,
                format!(
                    "Over the whole run that was {total} interrupt run{}, {} in total, at worst {}.",
                    plural(total),
                    fmt_dur(agg.total),
                    fmt_dur(agg.dpc_max.max(agg.isr_max))
                ),
            );
            cx.found.measure(&key, Metric::ms("worst DPC/ISR", ticks_to_ms(agg.dpc_max.max(agg.isr_max))));
        }
        said += 1;
    }
}

/// At most this many "wakes on a timer" notes. They are Low and informational; a long tail of them
/// would push real findings off the first screen for nothing.
const MAX_QUIET_POLLERS: usize = 3;

/// Stalls that repeat on a timer point at software polling rather than at hardware.
pub(super) fn periodicity(cx: &mut Ctx) {
    let tally = &cx.tally;
    let mut periodic_noted = false;
    let culprits: Vec<String> = tally.iter().map(|(c, _)| c.clone()).collect();
    for culprit in culprits {
        let times: Vec<i64> = cx.az.incidents.iter().filter(|i| !i.marked && stable_key(&i.culprit) == culprit).map(|i| i.start).collect();
        if let Some(p) = period::detect(&secs(&times)) {
            periodic_noted |= cx.found.note(&culprit, format!("The stalls keep time. {}", p.describe()));
        }
    }
    for (module, times) in &cx.az.long_exec_times {
        if let Some(p) = period::detect(&secs(times)) {
            periodic_noted |= cx.found.note(&format!("driver {module}"), format!("Its long interrupt runs keep time. {}", p.describe()));
        }
    }
    if !periodic_noted {
        let all: Vec<i64> = cx.az.incidents.iter().filter(|i| !i.marked).map(|i| i.start).collect();
        if let Some(p) = period::detect(&secs(&all)) {
            cx.found.add("periodic", Severity::Medium, "Stalls repeat on a timer".into(), p.describe(), POLLING_ADVICE.into(), 0);
        }
    } else {
        for (_, f) in cx.found.0.iter_mut().filter(|(_, f)| f.evidence.iter().any(|e| e.contains("keep time"))) {
            f.advice = format!(
                "{} Because it repeats on a timer: {}",
                f.advice,
                // Only the first word changes; lowercasing the lot turned "iCUE, HWiNFO" into "icue, hwinfo".
                POLLING_ADVICE.replacen("Something", "something software-driven", 1)
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The numbers from the two field reports in issue #15, judged against the length of the run
    /// they came from and against the same numbers in a five-minute run.
    #[test]
    fn stall_severity_is_relative_to_the_run_and_to_what_a_person_can_feel() {
        let hour = 3561.0; // the 59-minute field run
        let short = 300.0; // five minutes
        let ms = ms_to_ticks;

        // "[HIGH] consent.exe - 1 stall, 31 ms" was the worst of the old rules: a single blip
        // nobody felt, promoted because 31 ms is over a fixed 15 ms line.
        assert_eq!(full(1, ms(31.6), ms(31.6), hour), Severity::Low);
        // The same one stall inside five minutes is twelve an hour, which is a suspect. That is
        // the rate changing, not the rule.
        assert_eq!(full(1, ms(31.6), ms(31.6), short), Severity::Medium);

        // 55 network-filter stalls of 5-13 ms in 59 minutes: once a minute. Real, worth acting
        // on, but not a machine that is repeatedly or badly stalled.
        assert_eq!(full(55, ms(13.52), ms(415.0), hour), Severity::Medium);
        // The same 55 in five minutes is one every five seconds: continuous audio crackle.
        assert_eq!(full(55, ms(13.52), ms(415.0), short), Severity::High);

        // One hold long enough to be seen is serious however rarely it happens...
        assert_eq!(full(1, ms(900.0), ms(900.0), hour), Severity::High);
        // ...and so is anything that adds up to half a percent of the run.
        assert_eq!(full(300, ms(60.0), ms(18_000.0), hour), Severity::High);
    }

    /// Severity for stalls that held every processor they could (breadth 1), which is how every
    /// stall used to be judged: the expectations above are unchanged by the breadth rule.
    fn full(n: u32, worst: i64, total: i64, run_s: f64) -> Severity {
        stall_severity(&Tally { n, worst, total, felt_worst: worst, felt_total: total }, run_s)
    }

    /// Issue #19: a kernel-level stall on 1 of 32 processors and one on 30 of 32 must not rate the
    /// same, while a starvation stall, a small PC and an unknown processor count keep full weight.
    #[test]
    fn a_stall_that_held_few_of_many_processors_counts_for_less() {
        let ms = ms_to_ticks;
        let hour = 3561.0;
        let rate = |class, held, ncpu, dur_ms: f64, n: u32| {
            let mut t = Tally::default();
            for _ in 0..n {
                t.add(ms(dur_ms), breadth(class, held, ncpu));
            }
            stall_severity(&t, hour)
        };
        // One 150 ms stall: on 30 of 32 processors it is the PC not responding...
        assert_eq!(rate(IncidentClass::Kernel, 30, 32, 150.0, 1), Severity::High);
        // ...on 1 of 32 the other 31 kept working: a suspect, never below one at that length.
        assert_eq!(rate(IncidentClass::Kernel, 1, 32, 150.0, 1), Severity::Medium);
        // A quarter of the processors counts in full; on a 4-thread laptop one core is a quarter.
        assert_eq!(rate(IncidentClass::Kernel, 8, 32, 150.0, 1), Severity::High);
        assert_eq!(rate(IncidentClass::Kernel, 1, 4, 150.0, 1), Severity::High);
        // The share-of-run rule weighs breadth too: 300 x 60 ms on 1 of 32 is not half a percent.
        assert_eq!(rate(IncidentClass::Kernel, 1, 32, 60.0, 300), Severity::Medium);
        assert_eq!(rate(IncidentClass::Kernel, 16, 32, 60.0, 300), Severity::High);
        // The crackle rule is about the one core audio runs on, so breadth does not soften it.
        assert_eq!(rate(IncidentClass::Kernel, 1, 32, 6.0, 400), Severity::High);
        // No core at all for a normal thread is PC-wide by definition; unknown counts stay whole.
        assert_eq!(breadth(IncidentClass::Starvation, 0, 32), 1.0);
        assert_eq!(breadth(IncidentClass::Kernel, 1, 0), 1.0);
        assert_eq!(breadth(IncidentClass::Kernel, 1, 8), 0.5);
    }

    #[test]
    fn a_driver_is_judged_by_how_often_its_interrupt_handling_runs_long_not_how_long_you_watched() {
        let hour = 3561.0;
        let ms = ms_to_ticks;
        // The field case: 3.64 ms at worst, four times in an hour. A suspect, not a HIGH.
        assert_eq!(exec_severity(ms(3.64), 4, hour), Severity::Medium);
        // One 1.01 ms run in an hour is a note, not a suspect: the old rule made it MEDIUM.
        assert_eq!(exec_severity(ms(1.01), 1, hour), Severity::Low);
        // 4 ms or more, once a minute or more often: that is what a person hears.
        assert_eq!(exec_severity(ms(4.2), 60, hour), Severity::High);
        assert_eq!(exec_severity(ms(4.2), 4, hour), Severity::Medium, "the same driver, four times an hour");
    }

    /// The rule for "running for iCUE.exe in 9 of 11 stalls": enough stalls to be a pattern, and a
    /// clear majority of them.
    #[test]
    fn the_program_behind_a_driver_needs_both_enough_stalls_and_a_majority() {
        let some = |names: &[&str]| -> Vec<Option<String>> { names.iter().map(|n| (!n.is_empty()).then(|| n.to_string())).collect() };

        // 9 of 11: what the issue asks for.
        let mut names = some(&["iCUE.exe"; 9]);
        names.extend(some(&["", "explorer.exe"]));
        assert_eq!(worked_for(&names), Some(("iCUE.exe".to_string(), 9, 11)));

        // Three stalls all pointing the same way is still a coincidence, not a pattern.
        assert_eq!(worked_for(&some(&["iCUE.exe"; 3])), None);
        assert_eq!(worked_for(&[]), None);

        // A bare majority of NAMED stalls is not enough when most stalls named nobody: the
        // denominator is every stall blamed on the driver, which is what the sentence says too.
        let mut thin = some(&["iCUE.exe", "iCUE.exe"]);
        thin.extend(some(&["", "", "", "", ""]));
        assert_eq!(worked_for(&thin), None);

        // Split between two programs: neither reaches the bar, so nothing is said.
        let split = some(&["iCUE.exe", "iCUE.exe", "chrome.exe", "chrome.exe", "explorer.exe"]);
        assert_eq!(worked_for(&split), None);

        // Exactly at the bar: 6 of 10.
        let mut edge = some(&["iCUE.exe"; 6]);
        edge.extend(some(&["chrome.exe"; 4]));
        assert_eq!(worked_for(&edge).map(|(n, ..)| n), Some("iCUE.exe".to_string()));
    }

    /// The sub-threshold beat: a driver that wakes every 5 s for a moment, seen only through the
    /// quarter-second bucket map, with nothing long enough to have stalled anything.
    #[test]
    fn a_driver_that_wakes_on_a_timer_is_seen_through_the_bucket_map() {
        let third_party = Some(false);
        // Every 5 s = every 20 buckets, for two minutes.
        let every_5s: Vec<usize> = (0..24).map(|i| i * 20).collect();
        let p = steady_beat(third_party, &every_5s).expect("a steady beat");
        assert!((p.seconds - 5.0).abs() < 0.01, "period {}", p.seconds);

        // Windows' own drivers, and drivers whose author cannot be read, are left alone.
        assert!(steady_beat(Some(true), &every_5s).is_none(), "Windows polls its own hardware all day");
        assert!(steady_beat(None, &every_5s).is_none(), "an unreadable version resource is not evidence of anything");

        // A driver that is simply always busy fills every bucket: gaps of 0.25 s, under the
        // detector's one-second floor, so it is a storm and not a timer.
        let always: Vec<usize> = (0..400).collect();
        assert!(steady_beat(third_party, &always).is_none());
        // ...and neither too few wakes nor irregular ones are a pattern.
        assert!(steady_beat(third_party, &[0, 20, 40]).is_none());
        assert!(steady_beat(third_party, &[0, 12, 18, 44, 49, 120, 124]).is_none());
        assert!(steady_beat(third_party, &[]).is_none());
    }

    #[test]
    fn how_often_says_the_rate_only_when_there_is_a_rate_to_say() {
        let text = how_often(55, ms_to_ticks(13.52), ms_to_ticks(415.0), 3561.0);
        assert!(text.contains("55 stalls") && text.contains("about 56 per hour"), "{text}");
        assert!(!how_often(1, ms_to_ticks(31.6), ms_to_ticks(31.6), 3561.0).contains("per hour"), "one stall has no rate");
    }
}
