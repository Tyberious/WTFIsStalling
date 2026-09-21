//! Who or what stalled the machine: the tally of blamed culprits, the moments the user flagged,
//! drivers whose DPC/ISR runs went long, and whether any of it keeps time.

use std::collections::HashMap;

use crate::modules::knowledge;
use crate::period;
use crate::state::KIND_ISR;
use crate::util::{fmt_dur, ms_to_ticks, plural, qpc_freq, ticks_to_ms};

use super::ctx::Ctx;
use super::wording::{process_advice, process_title, GENERIC_DRIVER_ADVICE, POLLING_ADVICE};
use super::{Metric, Severity};

const DARK_ADVICE: &str = "Windows itself was frozen out, which points below the operating system. Update the BIOS/UEFI, load BIOS \
    defaults (undo overclocks and memory tweaks), disable 'Legacy USB support' and unused onboard devices as a test, check for \
    thermal throttling, and if Hyper-V / Core Isolation (VBS) is enabled, test with it off. If it persists, suspect hardware.";

#[derive(Default)]
pub(super) struct DriverAgg {
    pub dpc_n: u64,
    pub dpc_max: i64,
    pub isr_n: u64,
    pub isr_max: i64,
    pub total: i64,
    pub over: u64,
}

/// QPC ticks -> seconds, which is what the periodicity detector works in.
fn secs(ticks: &[i64]) -> Vec<f64> {
    ticks.iter().map(|t| *t as f64 / qpc_freq() as f64).collect()
}

/// Stalls grouped by who was blamed, worst total first.
pub(super) fn tally(cx: &mut Ctx) {
    let mut tally: HashMap<String, (u32, i64, i64)> = HashMap::new();
    for i in cx.az.incidents.iter().filter(|i| !i.marked) {
        let t = tally.entry(i.culprit.clone()).or_default();
        t.0 += 1;
        t.1 += i.dur;
        t.2 = t.2.max(i.dur);
    }
    let mut tally: Vec<_> = tally.into_iter().collect();
    tally.sort_by_key(|(_, t)| std::cmp::Reverse(t.1));

    for (culprit, (n, total, worst)) in &tally {
        let sev = if *n >= 3 || *worst >= ms_to_ticks(15.0) { Severity::High } else { Severity::Medium };
        let stalls = format!("{n} stall{} (worst {}, {} in total)", plural(*n as u64), fmt_dur(*worst), fmt_dur(*total));
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
        } else if culprit == "unexplained" {
            let sev = if *n >= 3 { Severity::Medium } else { Severity::Low };
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
        } else if *n >= 5 {
            cx.found.add(
                culprit,
                Severity::Low,
                "Scheduling delays while CPUs were idle".into(),
                format!("{stalls}."),
                "Usually harmless. If hitches persist, test the 'High performance' power plan (core parking can cause this).".into(),
                *total,
            );
        }
        // The two numbers a next run is judged by: how often, and how bad at worst.
        cx.found.measure(culprit, Metric::count("stalls blamed", *n));
        cx.found.measure(culprit, Metric::ms("worst stall", ticks_to_ms(*worst)));
    }
    cx.tally = tally;
}

/// The moments the user flagged with "I felt it".
pub(super) fn flagged_moments(cx: &mut Ctx) {
    let mut marked: HashMap<String, (u32, i64)> = HashMap::new();
    for i in cx.az.incidents.iter().filter(|i| i.marked) {
        let m = marked.entry(i.culprit.clone()).or_default();
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

/// Drivers whose DPC or ISR runs went over the warning threshold.
pub(super) fn long_dpc_isr(cx: &mut Ctx) {
    let exec_warn = cx.run.exec_warn;
    let routines = std::mem::take(&mut cx.routines);
    let mut mods: HashMap<String, DriverAgg> = HashMap::new();
    for ((routine, kind), st) in &routines {
        let a = mods.entry(cx.az.modules.name(*routine)).or_default();
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

/// Stalls that repeat on a timer point at software polling rather than at hardware.
pub(super) fn periodicity(cx: &mut Ctx) {
    let tally = &cx.tally;
    let mut periodic_noted = false;
    let culprits: Vec<String> = tally.iter().map(|(c, _)| c.clone()).collect();
    for culprit in culprits {
        let times: Vec<i64> = cx.az.incidents.iter().filter(|i| !i.marked && i.culprit == culprit).map(|i| i.start).collect();
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
                POLLING_ADVICE.to_lowercase().replacen("something", "something software-driven", 1)
            );
        }
    }
}
