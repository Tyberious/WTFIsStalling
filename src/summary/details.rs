//! What goes under the answer: the short overview lines, the cost of the measuring itself, the
//! supporting tables, and the --debug dump.

use std::sync::atomic::Ordering;

use crate::evlog::HardwareKind;
use crate::files;
use crate::util::{fmt_dur, qpc};

use super::ctx::{Ctx, EVENT_LOG_DAYS};
use super::Severity;

/// --debug only: the first field of each classic kernel provider GUID, so the event counts can
/// be read without a lookup table. https://learn.microsoft.com/en-us/windows/win32/etw/nt-kernel-logger-constants
fn provider_name(guid: u32) -> &'static str {
    match guid {
        0xce1d_bfb4 => "PerfInfo",
        0x3d6f_a8d4 => "DiskIo",
        0x3d6f_a8d3 => "PageFault",
        0x3d6f_a8d1 => "Thread",
        0x3d6f_a8d0 => "Process",
        0x90cb_dc39 => "FileIo",
        0x0185_3a65 => "Config",
        _ => "",
    }
}

/// What the measuring itself cost this PC.
///
/// Always Low: this is about the measurement, not about the PC, so it must never decide the
/// banner. The first evidence line becomes the headline only if nothing else exists, and a Low
/// finding never does that.
pub(super) fn tool_cost(cx: &mut Ctx) {
    let (overhead, light) = (&cx.run.overhead, cx.run.light);
    let (events, events_lost) = (cx.events, cx.run.events_lost);
    let mut concerns = overhead.concerns(events, events_lost).into_iter();
    if let Some(first) = concerns.next() {
        let lighter = match light {
            Some(_) => "This run already used the lighter settings.",
            None => "Run from a command prompt, 'wtfis-cli --light' checks half as often, which roughly halves what it costs.",
        };
        cx.found.add(
            "tool overhead",
            Severity::Low,
            "Measuring cost this PC enough to be part of the picture".into(),
            first,
            format!(
                "Close other heavy programs (a browser with many tabs, a game, a video export) and measure again: with less going \
                 on, measuring costs less and the answer is cleaner. {lighter}"
            ),
            0,
        );
        for more in concerns {
            cx.found.note("tool overhead", more);
        }
    }
}

/// The "label: value" lines under the verdict.
pub(super) fn overview(cx: &Ctx, freezes: usize, kernel_stalls: usize, sched_stalls: usize) -> Vec<String> {
    let (elapsed_s, light, stats) = (cx.run.elapsed_s, cx.run.light, cx.run.stats);
    let marks_total = cx.az.marks_total;
    let secs = elapsed_s as u64;
    // Counted once each. A whole-PC freeze is reported by both probes and used to appear twice,
    // as a kernel-level stall AND as a CPU-starvation stall; it is one event.
    let mut counts = Vec::new();
    if freezes > 0 {
        counts.push(format!("{freezes} whole-PC freeze{}", crate::util::plural(freezes as u64)));
    }
    counts.push(format!("{kernel_stalls} short kernel-level"));
    counts.push(format!("{sched_stalls} CPU-starvation"));
    let mut overview =
        vec![format!("Monitored:        {:02}:{:02}", secs / 60, secs % 60), format!("Stalls detected:  {}", counts.join(", "))];
    // Near the top on purpose: two runs measured differently must never be compared unaware.
    if let Some(why) = light {
        overview.push(format!(
            "Light mode:       on, because {why}; stalls shorter than about {:.0} ms can be missed",
            crate::overhead::PROBE_MS_LIGHT
        ));
    }
    if marks_total > 0 {
        overview.push(format!("Flagged by you:   {marks_total} moment(s), {} with nothing on the system side", cx.az.marks_clean));
    }
    overview.push(format!(
        "Worst wake-up:    {} real-time thread, {} normal thread",
        fmt_dur(stats.max_kernel.load(Ordering::Relaxed)),
        fmt_dur(stats.max_sched.load(Ordering::Relaxed))
    ));
    overview
}

/// The DETAILS tables, in the order the report prints them.
pub(super) fn tables(cx: &mut Ctx) {
    let (overhead, clock) = (&cx.run.overhead, cx.run.clock);
    let (events, events_lost) = (cx.events, cx.run.events_lost);
    let (mem, named_files, throttled_secs) = (cx.mem, cx.named_files, cx.throttled_secs);
    let (crashes, today) = (cx.crashes, cx.today);
    let tally = std::mem::take(&mut cx.tally);
    let disks = std::mem::take(&mut cx.disk_stats);
    let mut debug_counts = std::mem::take(&mut cx.debug_counts);
    let debug_rejected = std::mem::take(&mut cx.debug_rejected);
    let gpu_lines = std::mem::take(&mut cx.gpu_lines);
    let health_lines = std::mem::take(&mut cx.health_lines);
    let (drivers, faults_named) = (&cx.drivers, &cx.faults_named);
    let (file_waits, device_map) = (&cx.file_waits, &cx.device_map);
    let (storage_log, display_log) = (&cx.storage_log, &cx.display_log);
    let (firmware_caps, hardware_log) = (&cx.firmware_caps, &cx.hardware_log);
    let mut details: Vec<String> = Vec::new();
    macro_rules! d {
        ($($a:tt)*) => { details.push(format!($($a)*)) };
    }
    d!("");
    d!("THIS TOOL'S OWN COST  (what the measuring itself used)");
    for line in overhead.detail_lines(events, events_lost) {
        d!("{line}");
    }
    if cx.az.notable_folded > 0 {
        d!(
            "{} of {} individual slow events were folded into roll-up lines in the event log (repeats from the same disk, driver or program).",
            cx.az.notable_folded,
            cx.az.notable_total
        );
    }
    if cx.az.notable_suppressed > 0 {
        d!("{} of {} individual slow-event lines were suppressed in the event log.", cx.az.notable_suppressed, cx.az.notable_total);
    }
    let dropped = cx.az.shared.inner.lock().unwrap_or_else(|e| e.into_inner()).notable_dropped;
    if dropped > 0 {
        d!("{dropped} more slow events arrived while this tool itself was held up and are missing from the event log (the totals above include them).");
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
            let disk = cx.az.disks.get(*n);
            let about: Vec<String> =
                [disk.letters(), disk.model.clone(), disk.hardware(), disk.fullness()].into_iter().filter(|s| !s.is_empty()).collect();
            if !about.is_empty() {
                d!("  disk {n} = {}", about.join("  |  "));
            }
        }
    }
    let top_files = files::rank(file_waits, 8);
    if !top_files.is_empty() {
        d!("");
        d!("FILES THAT WAITED LONGEST ON DISK  (file names are shortened; see the privacy note in the README)");
        d!("  {:<64} {:>5} {:>9} {:>12} {:>10}", "file", "disk", "requests", "total wait", "worst");
        for (name, disk, count, total, max) in &top_files {
            d!("  {name:<64} {disk:>5} {count:>9} {:>12} {:>10}", fmt_dur(*total), fmt_dur(*max));
        }
        // Plain words for the ones nobody recognizes, once each.
        let mut explained: Vec<&str> = Vec::new();
        for (name, ..) in &top_files {
            if let Some(what) = files::explain(name) {
                if !explained.contains(&what) {
                    explained.push(what);
                    d!("  {name} = {what}");
                }
            }
        }
    }
    details.extend(std::mem::take(&mut cx.platform_lines));
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
    d!("  crashes / sudden power loss: {crashes}");
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
                throttled_secs,
                clock.len()
            );
        }
    }
    if !debug_counts.is_empty() {
        debug_counts.sort();
        d!("");
        d!("debug: events by (provider, opcode):");
        for ((guid, op), n) in debug_counts {
            d!("  {guid:08x} {:<9} op {op:>3}: {n}", provider_name(guid));
        }
        d!("  file names learned: {named_files}; files with a wait total: {}", file_waits.len());
        for (ts, initial) in debug_rejected {
            d!("  rejected DPC/ISR: event ts {ts}, InitialTime {initial}, now {}", qpc());
        }
    }
    cx.details = details;
}
