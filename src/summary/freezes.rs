//! The whole PC stopping is one problem, however many times it happened.
//!
//! A freeze holds every processor at once, so the CPU samples inside it land in whatever
//! happened to be running - a file manager, an RGB utility, a VPN client, "System" - and every
//! one of those is a bystander that was stopped along with everything else. The field reports in
//! issue #15 turned one recurring freeze into a dozen accusations that way. So this section
//! takes all the freeze incidents together and says what is actually known about them: how often,
//! how long, what the processors were doing, which interrupt sources stopped, what coincided,
//! and - explicitly - what is not explained.

use std::collections::HashMap;

use crate::analyze::{FreezeFacts, IncidentClass};
use crate::diskwait::Role;
use crate::intr::Flow;
use crate::switches::Verdict;
use crate::util::{fmt_dur, plural, ticks_to_ms};

use super::ctx::Ctx;
use super::{Metric, Severity};

pub(super) const FREEZE_KEY: &str = "whole-PC freeze";

/// The order of attack for a machine that stops dead. Cheapest and most reversible test first.
const FREEZE_ADVICE: &str = "Nothing in this trace names a cause, so test one layer at a time and run this tool again after each \
    change: the comparison at the top of the next report will say whether the freezes moved. 1) Fully exit (not just close) any \
    utility that talks to the hardware directly - RGB, fan, lighting and monitoring tools - one at a time. 2) Unplug external \
    drives, especially any this report mentions. 3) Update the motherboard BIOS/UEFI and load its defaults, which undoes overclocks \
    and memory tuning. 4) If Core Isolation (Memory integrity) or Hyper-V is switched on, test once with it off: a hypervisor sits \
    between Windows and the processors. If none of that changes anything, the next step is a hardware one: different memory \
    settings, and the power supply.";

/// One finding for every whole-PC freeze in the run.
pub(super) fn whole_pc(cx: &mut Ctx) {
    let run_s = cx.run.elapsed_s.max(1.0);
    let facts: Vec<(i64, &FreezeFacts)> = cx
        .az
        .incidents
        .iter()
        .filter(|i| !i.marked && i.class == IncidentClass::Freeze)
        .filter_map(|i| i.freeze.as_ref().map(|f| (i.dur, f)))
        .collect();
    let n = facts.len();
    if n == 0 {
        return;
    }
    let mut lengths: Vec<i64> = facts.iter().map(|(d, _)| *d).collect();
    lengths.sort_unstable();
    let worst = *lengths.last().unwrap();
    let typical = lengths[lengths.len() / 2];
    let per_hour = n as f64 * 3600.0 / run_s;
    let cpus = facts.iter().map(|(_, f)| f.cpus).max().unwrap_or(0);
    let ncpu = facts.iter().map(|(_, f)| f.ncpu).max().unwrap_or(0);

    let mut evidence = vec![format!(
        "{n} freeze{} in {}, about {per_hour:.0} per hour. Typically {}, at worst {}. Each one held {cpus} of this PC's {ncpu} \
         processors at the same instant, so no program or driver that the CPU samples landed in can be the cause: those were \
         stopped too.",
        plural(n as u64),
        fmt_run(run_s),
        fmt_dur(typical),
        fmt_dur(worst)
    )];

    // What the processors were doing, in plain words.
    let measured: Vec<f64> = facts.iter().filter(|(_, f)| f.samples > 0).map(|(_, f)| f.idle_share).collect();
    if !measured.is_empty() {
        let lo = measured.iter().copied().fold(f64::MAX, f64::min);
        let hi = measured.iter().copied().fold(0.0, f64::max);
        let mostly_idle = measured.iter().filter(|s| **s >= 0.5).count();
        let judged = measured.len();
        // Say only what was seen. The field logs had both kinds in one run: freezes with the
        // processors 94% idle, and freezes with them 99% busy inside Windows itself.
        evidence.push(if mostly_idle == judged {
            format!(
                "The processors were not busy: they were {:.0}-{:.0}% idle during the freezes. A PC that stops while its \
                 processors are idle is not short of processing power.",
                lo * 100.0,
                hi * 100.0
            )
        } else if mostly_idle == 0 {
            format!(
                "The processors were busy during the freezes ({:.0}-{:.0}% idle), mostly inside Windows itself and not in any one \
                 program's own code.",
                lo * 100.0,
                hi * 100.0
            )
        } else {
            format!(
                "What the processors were doing differed: in {mostly_idle} of {judged} freezes they were mostly idle, in {} they \
                 were busy, mostly inside Windows itself ({:.0}-{:.0}% idle overall). One symptom with more than one look usually \
                 means more than one thing is going on.",
                judged - mostly_idle,
                lo * 100.0,
                hi * 100.0
            )
        });
    }
    // The one measurement that says whether the threads were held up or simply never woken. This
    // is what the field logs in issue #15 could not answer: every probe on every processor waking
    // late by the same amount is the same picture either way, and only the scheduler trace
    // separates them.
    // ...and only when every event arrived; see `Ctx::scheduler_usable`.
    let judged: Vec<Verdict> =
        if cx.scheduler_usable() { facts.iter().filter_map(|(_, f)| f.probes.overall()).collect() } else { Vec::new() };
    let count = |v: Verdict| judged.iter().filter(|j| **j == v).count();
    let (not_woken, queued, blocked) = (count(Verdict::NotWoken), count(Verdict::Queued), count(Verdict::Blocked));
    let on_idle = facts.iter().map(|(_, f)| f.probes.on_idle_cpu).sum::<usize>();
    if !judged.is_empty() {
        let j = judged.len();
        let mut said = Vec::new();
        if not_woken > 0 {
            said.push(format!(
                "in {not_woken} of them the measuring threads were never made runnable at all until the freeze ended: nothing woke \
                 them. That looks like the timer that wakes sleeping threads failing to fire, which points at the clock, the firmware or power \
                 management - below Windows' own scheduling, and below every driver"
            ));
        }
        if queued > 0 {
            let idle = if on_idle > 0 { ", on a processor that had nothing else to do at all" } else { "" };
            // A DPC or ISR runs on top of whatever thread is there and no thread switch records
            // it, so "woken and not run" only points below the drivers when none was seen holding.
            let held = facts.iter().filter(|(_, f)| f.probes.overall() == Some(Verdict::Queued) && f.holding.is_some()).count();
            let means = if held >= queued {
                "No thread outranks them, so interrupt-level work kept them off, which fits the driver seen holding the processors"
            } else if held > 0 {
                "No thread outranks them, so interrupt-level work or the platform kept them off: in some of these a driver was \
                 seen holding the processors, in the others nothing was"
            } else {
                "No thread outranks them and no driver was seen holding the processors, so that points at the platform (firmware, \
                 power management) or at interrupt-level work this trace cannot see, rather than at another program"
            };
            said.push(format!(
                "in {queued} of them the measuring threads WERE made runnable on time and were then left waiting{idle}. {means}"
            ));
        }
        if blocked > 0 {
            said.push(format!(
                "in {blocked} of them the measuring threads were woken on time, ran, and then had to wait for something else, so \
                 that wait is the freeze"
            ));
        }
        evidence.push(format!(
            "What happened to this tool's own measuring threads, from the context-switch trace ({j} of the {n} freeze{} could be \
             judged): {}.",
            plural(n as u64),
            said.join("; ")
        ));
    }

    let kept_running = facts.iter().filter(|(_, f)| f.dpcs_kept_running).count();
    if kept_running > 0 {
        evidence.push(format!(
            "In {kept_running} of {n}, ordinary interrupt work carried on running on the frozen processors throughout, which cannot \
             happen while a processor is held by a driver. The processors were awake; nothing was waking up threads."
        ));
    }
    if let Some((module, on)) = facts.iter().filter_map(|(_, f)| f.holding.clone()).next() {
        evidence.push(format!(
            "One exception: {module}'s own interrupt handling did cover most of the freeze on {on} of the processors. That is worth \
             following up on its own."
        ));
    }

    // Which interrupt sources stopped, and which kept going. The one measurement here that comes
    // close to watching a bus or a controller stall.
    let mut silent: HashMap<&str, usize> = HashMap::new();
    let mut continued: HashMap<&str, usize> = HashMap::new();
    for (_, f) in &facts {
        for (name, _) in &f.silent {
            *silent.entry(name.as_str()).or_default() += 1;
        }
        for (name, _) in &f.continued {
            *continued.entry(name.as_str()).or_default() += 1;
        }
    }
    if !silent.is_empty() {
        // "It varies" is only said when it did: a source that went quiet in some freezes and kept
        // going in others, or different sources going quiet in different freezes.
        let varies = silent.len() > 1 || silent.keys().any(|k| continued.contains_key(k)) || silent.values().any(|c| *c < n);
        let reading = if varies {
            " Which device goes quiet differs from freeze to freeze. No single driver explains that; it points below the drivers, at \
             the board, its firmware or a bus."
        } else {
            " A device that stops interrupting while others carry on is the closest this tool gets to seeing one controller or bus \
             stall."
        };
        evidence.push(format!(
            "Device interrupts did not all stop together: {}. Meanwhile {}.{reading}",
            list(&silent, n, "stopped completely in"),
            if continued.is_empty() { "others carried on".to_string() } else { list(&continued, n, "kept arriving in") }
        ));
    }
    let timers_stopped = facts.iter().filter(|(_, f)| f.timer == Some(Flow::Silent)).count();
    let timers_judged = facts.iter().filter(|(_, f)| f.timer.is_some()).count();
    if timers_judged > 0 {
        evidence.push(if timers_stopped > 0 {
            format!(
                "The timer interrupts that wake sleeping threads stopped in {timers_stopped} of the {timers_judged} freezes this \
                 could be judged for. That is the clock the whole system runs on."
            )
        } else {
            format!(
                "The timer interrupts that wake sleeping threads kept running in all {timers_judged} freezes this could be judged \
                 for, so the clock itself did not stop."
            )
        });
    }

    // What coincided, in correlation language and with both numbers.
    let mut by_disk: HashMap<u32, (usize, bool, i64)> = HashMap::new();
    let mut alone = 0usize;
    for (_, f) in &facts {
        match f.coincided.as_ref().filter(|c| c.role != Role::Victim) {
            Some(c) => match c.disk {
                Some(d) => {
                    let e = by_disk.entry(d).or_insert((0, false, 0));
                    e.0 += 1;
                    e.1 |= c.woke;
                    e.2 = e.2.max(c.waited);
                }
                None => alone += 1,
            },
            None => alone += 1,
        }
    }
    let mut disks: Vec<(u32, (usize, bool, i64))> = by_disk.into_iter().collect();
    disks.sort_by_key(|(d, (count, _, _))| (std::cmp::Reverse(*count), *d));
    for (disk, (count, woke, waited)) in &disks {
        let asleep = if *woke { ", a drive that had been asleep" } else { "" };
        evidence.push(format!(
            "{count} of the {n} freezes coincided with a slow request to {}{asleep}, taking up to {}. 'Coincided' is all this \
             says: the freeze and the slow request happened together, and this tool cannot tell which caused which.",
            cx.az.disks.get(*disk).short(),
            fmt_dur(*waited)
        ));
    }
    if alone > 0 {
        evidence.push(format!("{alone} of the {n} freezes coincided with nothing at all that this tool can see."));
    }

    // Context that is relevant but proves nothing.
    let mut seen: HashMap<String, usize> = HashMap::new();
    for (_, f) in &facts {
        for p in &f.on_cpu {
            *seen.entry(crate::procs::process_name(p)).or_default() += 1;
        }
    }
    let mut programs: Vec<(String, usize)> = seen.into_iter().collect();
    programs.sort_by_key(|(name, n)| (std::cmp::Reverse(*n), name.clone()));
    if !programs.is_empty() {
        let names: Vec<&str> = programs.iter().take(4).map(|(name, _)| name.as_str()).collect();
        evidence.push(format!(
            "Context, not blame: the programs the processors were interrupted in were {}. They were frozen along with everything \
             else. They are worth trying one at a time only because a program that talks to the hardware directly is one of the few \
             things software can do that stops every processor.",
            names.join(", ")
        ));
    }
    evidence.push(
        "What is NOT explained: no driver's interrupt handling was long enough to do this, no single processor was held, and the \
         cause of the freezes is not visible in this trace. Everything above is what happened, not why."
            .to_string(),
    );

    // The whole machine stopping for a second at a time is the worst thing this tool measures,
    // and unlike every other rule here it does not need a rate to justify itself: one is enough.
    cx.found.add(
        FREEZE_KEY,
        Severity::High,
        format!("The whole PC stopped responding, {n} time{}", plural(n as u64)),
        evidence.remove(0),
        FREEZE_ADVICE.to_string(),
        lengths.iter().sum(),
    );
    for more in evidence {
        cx.found.note(FREEZE_KEY, more);
    }
    // When it is the wake-ups that are failing, the order of attack narrows: the layers that own
    // the clock come first. Appended rather than replacing, so the general plan still follows.
    if not_woken > queued + blocked {
        cx.found.advise(
            FREEZE_KEY,
            "Because nothing was waking sleeping threads, start with the layers that own the clock: in the BIOS/UEFI update it, load \
             defaults, and try switching off C-states / 'global C-state control' / ErP; in Windows, Control Panel > Power Options > \
             High performance. Those are also the settings a 'latency tweak' guide most often changes.",
        );
    }
    // Per hour rather than a raw count, so a 5-minute run and an hour-long one compare. How many
    // freezes had no wake-up stays in the evidence above: it is a share of these, not a number a
    // fix would be judged by.
    cx.found.measure(FREEZE_KEY, Metric::flat("freezes per hour", per_hour));
    cx.found.measure(FREEZE_KEY, Metric::ms("worst freeze", ticks_to_ms(worst)));
}

fn fmt_run(seconds: f64) -> String {
    if seconds >= 90.0 {
        format!("{:.0} minutes", seconds / 60.0)
    } else {
        format!("{seconds:.0} seconds")
    }
}

/// "Wdf01000.sys stopped completely in 8 of 12, ACPI.sys in 2 of 12"
fn list(counts: &HashMap<&str, usize>, total: usize, what: &str) -> String {
    let mut rows: Vec<(&str, usize)> = counts.iter().map(|(k, v)| (*k, *v)).collect();
    rows.sort_by_key(|(name, n)| (std::cmp::Reverse(*n), *name));
    rows.iter()
        .take(3)
        .enumerate()
        .map(|(i, (name, n))| if i == 0 { format!("{name} {what} {n} of {total}") } else { format!("{name} in {n} of {total}") })
        .collect::<Vec<_>>()
        .join(", ")
}
