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
    let gpu_events = cx.run.gpu_trace.totals.available.then_some(cx.run.gpu_trace.totals.events);
    let storage = &cx.run.storage_trace;
    for line in overhead.detail_lines(events, events_lost, cx.switch_events, gpu_events, storage.available.then_some(storage.events)) {
        d!("{line}");
    }
    if let Some(why) = &storage.note {
        d!("  The storage trace did not run: {why}. How slow disk time split between the drive and Windows is not measured.");
    } else if storage.lost > 0 {
        d!("  The storage trace lost {} events, so some slow requests could not be followed into the drive.", storage.lost);
    }
    if cx.switch_events.is_some() && !cx.scheduler_usable() {
        d!("Because some kernel events were lost, nothing in this report rests on the thread-switch trace: what it says about \
             whether a stalled thread was woken, and about which programs were kept waiting, is left out rather than guessed at.");
    }
    let uncovered = cx.az.switch_uncovered.load(std::sync::atomic::Ordering::Relaxed);
    if uncovered > 0 && cx.scheduler_usable() {
        let of = cx.az.switch_gathers.load(std::sync::atomic::Ordering::Relaxed);
        d!("For {uncovered} of the {of} moments looked at, the thread-switch history did not reach back far enough (it holds a few              seconds, less on a PC switching threads very fast, and nothing from before the run began), so those say nothing about              whether a stalled thread was woken or which programs were kept waiting.");
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
        // "Not measured", never an empty or zero split, for a drive the storage driver trace does
        // not see (a USB 'BOT' drive, an older controller).
        let numbers: Vec<u32> = disks.iter().map(|(n, _)| *n).collect();
        for n in super::storage::not_on_storport(cx.az, &cx.run.storage_trace, &numbers) {
            d!("  disk {n}: time inside the drive vs waiting in Windows not measured (the storage driver trace reports nothing for it)");
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
    // The IrpFlags values actually seen, to check the bits `diskstuck` reads (0x2 paging, 0x40
    // synchronous paging, 0x1 no-cache) against a live run: a paging read should show 0x2 set.
    let irp_flags = std::mem::take(&mut cx.debug_irp_flags);
    if !irp_flags.is_empty() {
        d!("");
        d!("debug: disk requests by (read/write/flush, IrpFlags):");
        for ((op, flags), n) in irp_flags {
            let paging = if flags & 0x2 != 0 && op != b'F' { "  paging" } else { "" };
            d!("  {} 0x{flags:08x}: {n}{paging}", op as char);
        }
    }
    // The graphics provider is a manifest provider, so its events are counted by (id, version)
    // rather than by opcode. The second list is the one an elevated live run has to check: an
    // (id, version) whose payload layout this build could not work out is skipped, never guessed.
    let gpu_debug = (&cx.run.gpu_trace.debug_counts, &cx.run.gpu_trace.debug_unknown);
    if !gpu_debug.0.is_empty() || !gpu_debug.1.is_empty() {
        d!("");
        d!("debug: DxgKrnl events by (event id, version):");
        for ((id, version), n) in gpu_debug.0 {
            d!(
                "  id {id:>4} v{version}: {n}{}",
                if gpu_debug.1.iter().any(|(k, _)| k == &(*id, *version)) { "  NOT UNDERSTOOD" } else { "" }
            );
        }
        for ((id, version), n) in gpu_debug.1 {
            d!("  not understood: id {id:>4} v{version}: {n} event(s) skipped");
        }
    }
    // The storage port driver's trace: what an elevated run has to check is which pointer (if
    // any) ties its records to the kernel's DiskIo records, and whether the status rule and the
    // opcodes match what the drives really send.
    let st = &cx.run.storage_trace;
    if !st.debug_counts.is_empty() || !st.debug_unknown.is_empty() {
        d!("");
        d!("debug: StorPort events by (event id, version):");
        for ((id, version), n) in &st.debug_counts {
            let bad = st.debug_unknown.iter().any(|(k, _)| k == &(*id, *version));
            d!("  id {id:>4} v{version}: {n}{}", if bad { "  NOT UNDERSTOOD" } else { "" });
        }
        let mut t = crate::storport::split::SplitTotals::default();
        let mut per_disk: Vec<_> = cx.az.disk_split.iter().collect();
        per_disk.sort_by_key(|(n, _)| **n);
        for (_, s) in &per_disk {
            t.merge(s);
        }
        d!(
            "  slow requests matched by Irp {}, by OriginalIrp {}, by fallback {}; ambiguous {}, unmatched {}, not covered {}",
            t.by_irp,
            t.by_orig,
            t.by_fallback,
            t.ambiguous,
            t.unmatched,
            t.not_covered
        );
        d!("  matched in several pieces {}; clipped (port-driver time outside the request) {}", t.multi_piece, t.clipped);
        for (n, s) in per_disk {
            d!(
                "  disk {n}: Irp {} OriginalIrp {} fallback {} unmatched {} ambiguous {} not covered {}; inside {} waiting {}",
                s.by_irp,
                s.by_orig,
                s.by_fallback,
                s.unmatched,
                s.ambiguous,
                s.not_covered,
                fmt_dur(s.inside),
                fmt_dur(s.waiting)
            );
        }
        d!("  retries attached by Irp {}, by OriginalIrp {}, never attached {}", st.retry_by[0], st.retry_by[1], st.retry_by[2]);
        let status: Vec<String> = st.debug_status.iter().map(|((srb, scsi), n)| format!("{srb:#04x}/{scsi:#04x}: {n}")).collect();
        d!("  (SrbStatus/ScsiStatus): {}", status.join(", "));
        let cmds: Vec<String> = st.debug_commands.iter().map(|(c, n)| format!("{c:#04x}: {n}")).collect();
        d!("  commands: {}", cmds.join(", "));
        for (a, t) in &st.per_addr {
            d!(
                "  port {} bus {} target {} lun {}: {} requests, {} failed, {} retried ({} retries)",
                a.port,
                a.bus,
                a.target,
                a.lun,
                t.requests,
                t.failed,
                t.retried,
                t.retries
            );
        }
        for n in cx.az.disks.present() {
            match cx.az.scsi_addr(n) {
                Some(a) => d!("  disk {n} = port {} bus {} target {} lun {}", a.port, a.bus, a.target, a.lun),
                None => d!("  disk {n}: no storage port address (IOCTL_SCSI_GET_ADDRESS refused)"),
            }
        }
        for r in &st.resets {
            d!(
                "  reset {:?} at {}: port {} bus {:?} target {:?} lun {:?}",
                r.kind,
                crate::util::clock().fmt(r.ts),
                r.port,
                r.bus,
                r.target,
                r.lun
            );
        }
    }
    cx.details = details;
}
