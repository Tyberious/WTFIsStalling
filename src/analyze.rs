//! Correlates probe stalls with what ETW saw on the affected CPUs, prints incident
//! reports as they happen and the final summary.

use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::mpsc::Receiver;
use std::sync::Arc;

use crate::modules::{knowledge, ModuleMap, KERNEL_SPACE};
use crate::probe::{ProbeStats, Stall, StallKind};
use crate::procs::ProcNames;
use crate::say;
use crate::state::*;
use crate::util::{clock, fmt_dur, ms_to_ticks, qpc, ticks_to_ms};

struct IncidentSummary {
    kind: StallKind,
    dur: i64,
    culprit: String,
}

pub struct Analyzer {
    shared: Arc<Shared>,
    rx: Receiver<Stall>,
    pending: Vec<Stall>,
    pub modules: ModuleMap,
    pub procs: ProcNames,
    profile: bool,
    incidents: Vec<IncidentSummary>,
    notable_window_start: i64,
    notable_in_window: u32,
    notable_suppressed: u64,
    notable_total: u64,
}

/// Everything ETW recorded around one incident, copied out so the lock is held briefly.
struct Evidence {
    execs: Vec<ExecRec>,
    faults: Vec<FaultRec>,
    ios: Vec<IoRec>,
    /// (sample, pid)
    samples: Vec<(SampleRec, u32)>,
    /// Samples per CPU in the 500 ms before the incident: the "normal" sampling rate.
    baseline: HashMap<u16, u32>,
    etw_caught_up: bool,
}

const BASELINE_MS: f64 = 500.0;

/// (name, fraction of samples), biggest first.
type Shares = Vec<(String, f64)>;

impl Analyzer {
    pub fn new(shared: Arc<Shared>, rx: Receiver<Stall>, modules: ModuleMap, profile: bool) -> Analyzer {
        Analyzer {
            shared,
            rx,
            pending: Vec::new(),
            modules,
            procs: ProcNames::new(),
            profile,
            incidents: Vec::new(),
            notable_window_start: 0,
            notable_in_window: 0,
            notable_suppressed: 0,
            notable_total: 0,
        }
    }

    /// Called ~10x per second. `force` analyzes everything pending (shutdown).
    pub fn tick(&mut self, force: bool) {
        self.procs.refresh_if_older_than(2);
        self.pending.extend(self.rx.try_iter());
        self.report_notables();
        if self.pending.is_empty() {
            return;
        }

        // Cluster stalls of the same kind that overlap in time: one hitch usually trips
        // the probes on several CPUs at once.
        self.pending.sort_by_key(|s| (s.kind as u8, s.start));
        let mut clusters: Vec<Vec<Stall>> = Vec::new();
        let gap = ms_to_ticks(2.0);
        for s in self.pending.drain(..) {
            match clusters.last_mut() {
                Some(c) if c[0].kind == s.kind && s.start <= c.iter().map(|x| x.end).max().unwrap() + gap => c.push(s),
                _ => clusters.push(vec![s]),
            }
        }

        // ETW delivers in ~1 s batches. A cluster is ripe once the trace has caught up past
        // its end, or we've waited long enough that it isn't going to.
        let now = qpc();
        let latest = self.shared.inner.lock().unwrap().latest_ts;
        for c in clusters {
            let end = c.iter().map(|s| s.end).max().unwrap();
            let age = now - end;
            let caught_up = latest > end + ms_to_ticks(50.0);
            if force || (caught_up && age > ms_to_ticks(300.0)) || age > ms_to_ticks(4000.0) {
                self.analyze(&c, caught_up);
            } else {
                self.pending.extend(c);
            }
        }
    }

    fn gather(&self, from: i64, to: i64, wide_from: i64, caught_up: bool) -> Evidence {
        let inner = self.shared.inner.lock().unwrap();
        let base_from = from - ms_to_ticks(BASELINE_MS);
        let mut baseline = HashMap::new();
        let mut samples = Vec::new();
        for s in inner.samples.iter() {
            if s.ts >= from && s.ts <= to {
                let pid = if s.tid == 0 { 0 } else { inner.tid_pid.get(&s.tid).copied().unwrap_or(PID_UNKNOWN) };
                samples.push((*s, pid));
            } else if s.ts >= base_from && s.ts < from {
                *baseline.entry(s.cpu).or_insert(0) += 1;
            }
        }
        Evidence {
            execs: inner.execs.iter().filter(|e| e.end >= from && e.start <= to).copied().collect(),
            faults: inner.faults.iter().filter(|f| f.end >= wide_from && f.start <= to).copied().collect(),
            ios: inner.ios.iter().filter(|i| i.end >= wide_from && i.end - i.dur <= to).copied().collect(),
            samples,
            baseline,
            etw_caught_up: caught_up,
        }
    }

    fn analyze(&mut self, stalls: &[Stall], caught_up: bool) {
        let kind = stalls[0].kind;
        let start = stalls.iter().map(|s| s.start).min().unwrap();
        let end = stalls.iter().map(|s| s.end).max().unwrap();
        let worst = stalls.iter().map(|s| s.end - s.start).max().unwrap();
        let lead = ms_to_ticks(if kind == StallKind::Kernel { 0.5 } else { 4.0 });
        let ev = self.gather(start - lead, end, start - ms_to_ticks(100.0), caught_up);

        let id = self.incidents.len() + 1;
        let mut cpus: Vec<u16> = stalls.iter().filter_map(|s| s.cpu).collect();
        cpus.sort_unstable();
        cpus.dedup();
        let cpu_list = cpus.iter().map(|c| c.to_string()).collect::<Vec<_>>().join(",");

        say!("");
        match kind {
            StallKind::Kernel => {
                say!("[{}] STALL #{id}  kernel-level (DPC/ISR/firmware)  {}  on CPU {cpu_list}", clock().fmt(start), fmt_dur(worst))
            }
            StallKind::Scheduler => say!(
                "[{}] STALL #{id}  CPU starvation (normal-priority thread couldn't get a core)  {}",
                clock().fmt(start),
                fmt_dur(worst)
            ),
        }

        let culprit = match kind {
            StallKind::Kernel => self.verdict_kernel(stalls, &ev),
            StallKind::Scheduler => self.verdict_sched(&ev),
        };
        self.print_io_context(&ev);
        if !ev.etw_caught_up {
            say!("    note: kernel trace data for this window was incomplete (trace lagging or events lost)");
        }
        self.incidents.push(IncidentSummary { kind, dur: worst, culprit });
    }

    fn verdict_kernel(&mut self, stalls: &[Stall], ev: &Evidence) -> String {
        // How much of each probe's blocked window was covered by DPC/ISR execution on its CPU.
        let mut by_routine: HashMap<(u64, u8), (i64, i64, u32)> = HashMap::new(); // overlap, longest, count
        let mut stalled = 0i64;
        let mut covered = 0i64;
        let (mut seen_samples, mut expected_samples) = (0f64, 0f64);
        let mut window_samples: Vec<&(SampleRec, u32)> = Vec::new();
        for s in stalls {
            let cpu = s.cpu.unwrap_or(0);
            stalled += s.end - s.start;
            for e in ev.execs.iter().filter(|e| e.cpu == cpu) {
                let overlap = e.end.min(s.end) - e.start.max(s.start);
                if overlap > 0 {
                    covered += overlap;
                    let r = by_routine.entry((e.routine, e.kind)).or_default();
                    r.0 += overlap;
                    r.1 = r.1.max(e.end - e.start);
                    r.2 += 1;
                }
            }
            let in_window: Vec<_> = ev.samples.iter().filter(|(x, _)| x.cpu == cpu && x.ts >= s.start && x.ts <= s.end).collect();
            let rate = *ev.baseline.get(&cpu).unwrap_or(&0) as f64 / BASELINE_MS;
            seen_samples += in_window.len() as f64;
            expected_samples += rate * ticks_to_ms(s.end - s.start);
            window_samples.extend(in_window);
        }

        let mut routines: Vec<_> = by_routine.into_iter().collect();
        routines.sort_by_key(|(_, v)| std::cmp::Reverse(v.0));
        let mut by_module: HashMap<String, i64> = HashMap::new();
        for ((routine, _), (overlap, _, _)) in &routines {
            *by_module.entry(self.modules.name(*routine)).or_default() += overlap;
        }
        let top_module = by_module.iter().max_by_key(|(_, v)| **v).map(|(k, v)| (k.clone(), *v));
        let coverage = covered as f64 / stalled.max(1) as f64;

        let (on_cpu_procs, on_cpu_mods) = self.sample_breakdown(&window_samples);

        let culprit = if let (true, Some((module, _))) = (coverage >= 0.35, &top_module) {
            let what = self.modules.describe(module);
            say!("    VERDICT: {module} [{what}] kept the CPU in DPC/ISR code for {:.0}% of the stall", coverage * 100.0);
            format!("driver {module}")
        } else if self.profile && expected_samples >= 3.0 && seen_samples < expected_samples * 0.3 {
            say!(
                "    VERDICT: the CPU went dark: only {seen_samples:.0} of ~{expected_samples:.0} expected profiler interrupts arrived and no DPC/ISR explains it."
            );
            say!("             Windows itself was frozen out -> firmware SMI (BIOS, USB legacy, thermal/EC), a hypervisor, or a driver");
            say!("             running with interrupts disabled. Think BIOS update/settings and failing or misbehaving hardware.");
            "CPU went dark (firmware SMI / hypervisor / interrupts off)".to_string()
        } else if let Some((m, share)) = on_cpu_mods.first().filter(|(_, share)| *share >= 0.4) {
            let what = self.modules.describe(m);
            say!("    VERDICT: {m} [{what}] was executing for {:.0}% of the stall at raised IRQL (not as a DPC/ISR,", share * 100.0);
            say!("             e.g. holding a spinlock or inside a long driver call), which blocks every thread on that CPU");
            format!("driver {m}")
        } else if let Some((p, share)) = on_cpu_procs.first().filter(|(p, share)| *share >= 0.4 && !p.starts_with("Idle")) {
            say!("    VERDICT: {p} was on the CPU for {:.0}% of the stall. Nothing can outrank the probe thread, so it was", share * 100.0);
            say!("             inside kernel/driver code at raised IRQL on this process's behalf (see kernel modules below)");
            format!("process {p}")
        } else {
            say!("    VERDICT: no clear culprit in the trace (DPC/ISR covered only {:.0}% of the stall)", coverage * 100.0);
            "unexplained".to_string()
        };

        if !routines.is_empty() {
            say!("    DPC/ISR activity on the stalled CPU(s):");
            for ((routine, k), (overlap, longest, count)) in routines.iter().take(6) {
                say!(
                    "      {:<42} {:<12} x{count:<4} in-stall {:>9}   longest {:>9}",
                    self.modules.symbolish(*routine),
                    kind_name(*k),
                    fmt_dur(*overlap),
                    fmt_dur(*longest)
                );
            }
        }
        self.print_on_cpu(&on_cpu_procs, &on_cpu_mods);
        culprit
    }

    fn verdict_sched(&mut self, ev: &Evidence) -> String {
        let all: Vec<&(SampleRec, u32)> = ev.samples.iter().collect();
        let (procs, mods) = self.sample_breakdown(&all);
        let idle = procs.iter().find(|(p, _)| p == "Idle").map(|(_, s)| *s).unwrap_or(0.0);
        let busy: Vec<_> = procs.iter().filter(|(p, _)| p != "Idle").cloned().collect();
        let culprit = if !self.profile || all.is_empty() {
            say!("    VERDICT: all CPUs were busy, but CPU sampling is unavailable so the process can't be named");
            "CPU starvation (unattributed)".to_string()
        } else if idle < 0.25 {
            let (top, share) = busy.first().cloned().unwrap_or(("?".into(), 0.0));
            say!(
                "    VERDICT: CPUs were saturated ({:.0}% busy). Biggest consumer: {top} with {:.0}% of all CPU time",
                (1.0 - idle) * 100.0,
                share * 100.0
            );
            format!("process {top}")
        } else {
            say!("    VERDICT: inconclusive, CPUs were {:.0}% idle during this delay (likely a one-off scheduling quirk; ignore unless frequent)", idle * 100.0);
            "scheduling delay with idle CPUs".to_string()
        };
        self.print_on_cpu(&busy, &mods);
        culprit
    }

    /// Returns (share by process, share of kernel-mode samples by module), biggest first.
    fn sample_breakdown(&mut self, samples: &[&(SampleRec, u32)]) -> (Shares, Shares) {
        let total = samples.len().max(1) as f64;
        let mut procs: HashMap<(u32, u32), u32> = HashMap::new();
        let mut mods: HashMap<String, u32> = HashMap::new();
        for (s, pid) in samples {
            // Unknown pids are keyed by tid so they can still be resolved individually.
            *procs.entry((*pid, if *pid == PID_UNKNOWN { s.tid } else { 0 })).or_default() += 1;
            if s.ip >= KERNEL_SPACE && s.tid != 0 {
                *mods.entry(self.modules.name(s.ip)).or_default() += 1;
            }
        }
        let mut named: HashMap<String, u32> = HashMap::new();
        for ((pid, tid), n) in procs {
            *named.entry(self.procs.label(pid, tid)).or_default() += n;
        }
        let to_sorted = |m: HashMap<String, u32>| {
            let mut v: Vec<_> = m.into_iter().map(|(k, n)| (k, n as f64 / total)).collect();
            v.sort_by(|a, b| b.1.total_cmp(&a.1));
            v
        };
        (to_sorted(named), to_sorted(mods))
    }

    fn print_on_cpu(&self, procs: &[(String, f64)], mods: &[(String, f64)]) {
        let fmt = |v: &[(String, f64)]| v.iter().take(5).map(|(n, s)| format!("{n} {:.0}%", s * 100.0)).collect::<Vec<_>>().join(", ");
        if !procs.is_empty() {
            say!("    On-CPU by process:       {}", fmt(procs));
        }
        if !mods.is_empty() {
            say!("    Kernel-mode time by module: {}", fmt(mods));
        }
    }

    /// Paging and slow disk I/O near the incident. Not what blocks a time-critical thread,
    /// but exactly what makes a game or app hitch at the same moment.
    fn print_io_context(&mut self, ev: &Evidence) {
        if !ev.faults.is_empty() {
            let mut by_proc: HashMap<String, (u32, i64)> = HashMap::new();
            for f in &ev.faults {
                let e = by_proc.entry(self.procs.label(f.pid, f.tid)).or_default();
                e.0 += 1;
                e.1 += f.end - f.start;
            }
            // Sub-millisecond totals are background noise on any system.
            let mut v: Vec<_> = by_proc.into_iter().filter(|(_, (_, t))| *t >= ms_to_ticks(1.0)).collect();
            v.sort_by_key(|(_, (_, t))| std::cmp::Reverse(*t));
            if v.is_empty() {
                return self.print_slow_io(ev);
            }
            let txt = v.iter().take(4).map(|(p, (n, t))| format!("{p} x{n} waiting {}", fmt_dur(*t))).collect::<Vec<_>>().join(", ");
            say!("    Hard page faults nearby: {txt}");
        }
        self.print_slow_io(ev);
    }

    fn print_slow_io(&mut self, ev: &Evidence) {
        let slow_io: Vec<_> = ev.ios.iter().filter(|i| i.dur >= ms_to_ticks(20.0)).collect();
        if let Some(worst) = slow_io.iter().max_by_key(|i| i.dur) {
            say!(
                "    Slow disk I/O nearby:    {} slow request(s), worst {} on disk {} ({}, issued by {})",
                slow_io.len(),
                fmt_dur(worst.dur),
                worst.disk,
                op_name(worst.op),
                self.procs.label(worst.pid, worst.tid)
            );
        }
    }

    /// One-liners for individually bad events, even when no probe stalled.
    fn report_notables(&mut self) {
        let notables = std::mem::take(&mut self.shared.inner.lock().unwrap().notable);
        for n in notables {
            self.notable_total += 1;
            let now = qpc();
            if now - self.notable_window_start > ms_to_ticks(1000.0) {
                self.notable_window_start = now;
                self.notable_in_window = 0;
            }
            self.notable_in_window += 1;
            if self.notable_in_window > 6 {
                self.notable_suppressed += 1;
                continue;
            }
            match n {
                Notable::LongExec(e) => say!(
                    "[{}] long {:<12} {:>9}  {}  (CPU {})",
                    clock().fmt(e.start),
                    kind_name(e.kind),
                    fmt_dur(e.end - e.start),
                    self.modules.symbolish(e.routine),
                    e.cpu
                ),
                Notable::SlowFault(f) => say!(
                    "[{}] slow hard page fault {:>9}  {} waited on disk for paged-out memory ({} KB)",
                    clock().fmt(f.start),
                    fmt_dur(f.end - f.start),
                    self.procs.label(f.pid, f.tid),
                    f.bytes / 1024
                ),
                Notable::SlowIo(i) => say!(
                    "[{}] slow disk {:<5} {:>9}  disk {}  {} KB  issued by {}",
                    clock().fmt(i.end - i.dur),
                    op_name(i.op),
                    fmt_dur(i.dur),
                    i.disk,
                    i.size / 1024,
                    self.procs.label(i.pid, i.tid)
                ),
            }
        }
    }

    /// "02:15 monitored | 0 stalls | worst DPC 686 us (nvlddmkm.sys)"
    pub fn status_line(&mut self, elapsed_s: u64) -> String {
        let inner = self.shared.inner.lock().unwrap();
        let worst = inner.routines.iter().max_by_key(|(_, s)| s.max).map(|((r, k), s)| (*r, *k, s.max));
        let events = inner.events;
        drop(inner);
        let worst_txt = match worst {
            Some((r, k, max)) => format!("worst {} {} ({})", kind_name(k), fmt_dur(max), self.modules.name(r)),
            None if events == 0 => "waiting for kernel events".into(),
            None => "no DPC/ISR seen yet".into(),
        };
        format!("{:02}:{:02} monitored  |  {} stall(s)  |  {worst_txt}", elapsed_s / 60, elapsed_s % 60, self.incidents.len())
    }

    pub fn summary(&mut self, elapsed_s: f64, events_lost: u32, stats: &ProbeStats, exec_warn: i64) {
        let inner = self.shared.inner.lock().unwrap();
        let routines = inner.routines.clone();
        let faults = inner.faults_by_pid.clone();
        let disks = inner.disks.clone();
        let events = inner.events;
        let mut debug_counts: Vec<_> = inner.debug_counts.iter().map(|(k, v)| (*k, *v)).collect();
        let debug_rejected = inner.debug_rejected.clone();
        drop(inner);

        say!("");
        say!("==================================== SUMMARY ====================================");
        say!("Monitored {elapsed_s:.0} s, {events} kernel events processed, {events_lost} lost.");
        if events == 0 {
            say!("!! No kernel events were received, so nothing below is meaningful. Another tool may be");
            say!("!! holding the kernel trace, or security software blocked it.");
        }
        say!(
            "Worst wake-up latency: time-critical thread {}, normal-priority thread {}",
            fmt_dur(stats.max_kernel.load(Ordering::Relaxed)),
            fmt_dur(stats.max_sched.load(Ordering::Relaxed))
        );

        let kernel = self.incidents.iter().filter(|i| i.kind == StallKind::Kernel).count();
        say!("Stalls detected: {} kernel-level, {} CPU-starvation", kernel, self.incidents.len() - kernel);
        if self.notable_suppressed > 0 {
            say!(
                "({} of {} individual slow-event lines were suppressed to keep the log readable)",
                self.notable_suppressed,
                self.notable_total
            );
        }

        if !self.incidents.is_empty() {
            let mut tally: HashMap<&str, (u32, i64, i64)> = HashMap::new();
            for i in &self.incidents {
                let t = tally.entry(i.culprit.as_str()).or_default();
                t.0 += 1;
                t.1 += i.dur;
                t.2 = t.2.max(i.dur);
            }
            let mut v: Vec<_> = tally.into_iter().collect();
            v.sort_by_key(|(_, t)| std::cmp::Reverse(t.1));
            say!("");
            say!("WHO CAUSED THE STALLS");
            say!("  {:<58} {:>6} {:>11} {:>11}", "culprit", "stalls", "total", "worst");
            for (name, (n, total, worst)) in v {
                say!("  {:<58} {:>6} {:>11} {:>11}", name, n, fmt_dur(total), fmt_dur(worst));
            }
        }

        // Per-driver DPC/ISR statistics.
        #[derive(Default)]
        struct Agg {
            dpc_n: u64,
            dpc_max: i64,
            isr_n: u64,
            isr_max: i64,
            total: i64,
            over: u64,
        }
        let mut mods: HashMap<String, Agg> = HashMap::new();
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
        let mut v: Vec<_> = mods.into_iter().collect();
        v.sort_by_key(|(_, a)| std::cmp::Reverse(a.dpc_max.max(a.isr_max)));
        if !v.is_empty() {
            say!("");
            say!("DRIVERS BY WORST DPC/ISR EXECUTION TIME  (healthy: DPC < 0.5 ms, ISR < 0.1 ms)");
            say!(
                "  {:<24} {:>9} {:>10} {:>9} {:>10} {:>11} {:>7}",
                "driver",
                "DPCs",
                "worst DPC",
                "ISRs",
                "worst ISR",
                "total time",
                "slow"
            );
            for (name, a) in v.iter().take(12) {
                say!(
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

        if !faults.is_empty() {
            let mut by_name: HashMap<String, LatStat> = HashMap::new();
            for (pid, st) in faults {
                let e = by_name.entry(self.procs.label(pid, 0)).or_default();
                e.count += st.count;
                e.total += st.total;
                e.max = e.max.max(st.max);
            }
            let mut f: Vec<_> = by_name.into_iter().collect();
            f.sort_by_key(|(_, s)| std::cmp::Reverse(s.total));
            say!("");
            say!("HARD PAGE FAULTS  (process frozen while memory is read back from disk)");
            say!("  {:<40} {:>8} {:>12} {:>10}", "process", "faults", "total wait", "worst");
            for (name, s) in f.iter().take(6) {
                say!("  {:<40} {:>8} {:>12} {:>10}", name, s.count, fmt_dur(s.total), fmt_dur(s.max));
            }
        }

        if !disks.is_empty() {
            let mut d: Vec<_> = disks.into_iter().collect();
            d.sort_by_key(|(n, _)| *n);
            say!("");
            say!("DISK LATENCY");
            say!("  {:<8} {:>10} {:>10} {:>10} {:>7}", "disk", "requests", "average", "worst", "slow");
            for (n, s) in d {
                say!("  {:<8} {:>10} {:>10} {:>10} {:>7}", n, s.count, fmt_dur(s.total / s.count.max(1) as i64), fmt_dur(s.max), s.slow);
            }
        }

        // Plain-language conclusion.
        say!("");
        say!("WHAT TO DO");
        let mut advised = 0;
        let mut suspects: Vec<String> = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for i in &self.incidents {
            if let Some(m) = i.culprit.strip_prefix("driver ") {
                if seen.insert(m.to_string()) {
                    suspects.push(m.to_string());
                }
            }
        }
        for (name, a) in v.iter().take(12) {
            if a.dpc_max.max(a.isr_max) >= exec_warn && seen.insert(name.clone()) {
                suspects.push(name.clone());
            }
        }
        for m in suspects.iter().take(5) {
            let what = self.modules.describe(m);
            say!("  * {m}: {what}");
            if let Some(k) = knowledge(m) {
                say!("      {}", k.advice);
            } else {
                say!("      Update, roll back or temporarily disable the device/software this driver belongs to and retest.");
            }
            advised += 1;
        }
        if self.incidents.iter().any(|i| i.culprit.starts_with("CPU went dark")) {
            say!("  * CPU went dark: update the BIOS/UEFI, disable 'Legacy USB support' and unused onboard devices as a test,");
            say!("      check temperatures/throttling, and if Hyper-V/VBS (Core Isolation) is on, test with it off.");
            advised += 1;
        }
        let mut procs_blamed: Vec<&str> = self.incidents.iter().filter_map(|i| i.culprit.strip_prefix("process ")).collect();
        procs_blamed.sort_unstable();
        procs_blamed.dedup();
        for p in procs_blamed.iter().take(4) {
            say!("  * {p}: was on the CPU during stalls. Close it and retest; if the stalls vanish, the app or a driver it leans on is at fault.");
            advised += 1;
        }
        if advised == 0 {
            if self.incidents.is_empty() {
                say!("  Nothing stalled while this was running and no driver misbehaved. Reproduce the hitch while");
                say!("  monitoring (run it during the game/app that hitches), and let it run longer.");
                say!("  If the hitch happened and nothing was flagged, the cause is likely inside the app or on the GPU");
                say!("  (shader compilation, VRAM overflow, frame pacing), which a CPU-side trace can't see.");
            } else {
                say!("  Stalls happened but no single culprit stood out. Run longer to gather more incidents, and check the");
                say!("  per-incident details above for a pattern.");
            }
        }
        say!("=================================================================================");

        if !debug_counts.is_empty() {
            debug_counts.sort();
            say!("debug: events by (provider, opcode):");
            for ((guid, op), n) in debug_counts {
                say!("  {guid:08x} op {op:>3}: {n}");
            }
            for (ts, initial) in debug_rejected {
                say!("  rejected DPC/ISR: event ts {ts}, InitialTime {initial}, now {}", qpc());
            }
        }
    }
}

fn op_name(op: u8) -> &'static str {
    match op {
        b'R' => "read",
        b'W' => "write",
        _ => "flush",
    }
}
