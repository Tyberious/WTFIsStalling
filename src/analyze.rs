//! Correlates probe stalls with what ETW saw on the affected CPUs, prints incident
//! reports as they happen and the final summary.

use std::collections::{HashMap, VecDeque};
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex};

use crate::disks::DiskMap;
use crate::diskwhy::{self, Cause, DiskWhy};
use crate::health::{self, DriveHealth};
use crate::modules::{ModuleMap, KERNEL_SPACE};
use crate::probe::{Stall, StallKind};
use crate::procs::ProcNames;
use crate::say;
use crate::state::*;
use crate::util::{clock, fmt_dur, ms_to_ticks, qpc, ticks_to_ms};

pub(crate) struct IncidentSummary {
    pub(crate) kind: StallKind,
    pub(crate) start: i64,
    pub(crate) dur: i64,
    pub(crate) culprit: String,
    /// Below the stall threshold; only examined because the user flagged that moment.
    pub(crate) marked: bool,
}

/// Moments the user flagged with "I felt it" (QPC), waiting for the analyzer to pick them up.
static MARKS: Mutex<Vec<i64>> = Mutex::new(Vec::new());

/// Called from a front end (button, hotkey, Enter key) the instant the user feels a hitch.
pub fn mark_now() {
    MARKS.lock().unwrap().push(qpc());
}

/// A person reacts a good while after the hitch; look this far back from the mark...
const MARK_BEFORE_MS: f64 = 3000.0;
/// ...and a little past it, in case they anticipated a periodic one.
const MARK_AFTER_MS: f64 = 300.0;
/// Every healthy PC shows 1-2 ms wake-up blips all day; nobody feels those. A flagged moment
/// is only pinned on an interruption at least this long (or the stall threshold, if lower).
const MARK_MIN_MS: f64 = 3.0;
/// How long sub-threshold wake-up delays are kept for marks to draw on.
const MINOR_KEEP_MS: f64 = 30_000.0;

pub struct Analyzer {
    pub(crate) shared: Arc<Shared>,
    rx: Receiver<Stall>,
    pending: Vec<Stall>,
    pub modules: ModuleMap,
    pub procs: ProcNames,
    pub disks: DiskMap,
    /// Why each disk's slow requests were slow, as far as the traffic around them can tell.
    pub(crate) disk_why: HashMap<u32, DiskWhy>,
    /// Each drive's own health counters when monitoring began; the summary compares against them.
    pub(crate) health_at_start: HashMap<u32, DriveHealth>,
    started: i64,
    profile: bool,
    pub(crate) incidents: Vec<IncidentSummary>,
    /// Recent wake-up delays under the stall threshold, newest last.
    minor: VecDeque<Stall>,
    marks_pending: Vec<i64>,
    pub(crate) marks_total: u32,
    /// When each "I felt it" was pressed (QPC), for anything that wants to look at those moments.
    pub(crate) mark_times: Vec<i64>,
    /// Marks where nothing at all disturbed the CPUs.
    pub(crate) marks_clean: u32,
    /// Start times of over-threshold DPC/ISR runs per driver, for periodicity detection.
    pub(crate) long_exec_times: HashMap<String, Vec<i64>>,
    notable_window_start: i64,
    notable_in_window: u32,
    pub(crate) notable_suppressed: u64,
    pub(crate) notable_total: u64,
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
        MARKS.lock().unwrap().clear(); // anything flagged before this run started is not about this run
        let mut disks = DiskMap::new();
        let health_at_start = disks.present().into_iter().map(|n| (n, health::read(n, disks.get(n).bus))).collect();
        Analyzer {
            shared,
            rx,
            pending: Vec::new(),
            modules,
            procs: ProcNames::new(),
            disks,
            disk_why: HashMap::new(),
            health_at_start,
            started: qpc(),
            profile,
            incidents: Vec::new(),
            minor: VecDeque::new(),
            marks_pending: Vec::new(),
            marks_total: 0,
            mark_times: Vec::new(),
            marks_clean: 0,
            long_exec_times: HashMap::new(),
            notable_window_start: 0,
            notable_in_window: 0,
            notable_suppressed: 0,
            notable_total: 0,
        }
    }

    /// Builds an `Analyzer` from synthetic data only: no live disk health, process
    /// snapshot or module list. For tests of `verdict_kernel`/`verdict_sched`, which only
    /// need `self.modules`/`self.procs` and hand-built `Evidence` values.
    #[cfg(test)]
    pub fn for_test(modules: ModuleMap, procs: ProcNames, profile: bool) -> Analyzer {
        let (_tx, rx) = std::sync::mpsc::channel();
        let shared = Arc::new(Shared {
            inner: Mutex::new(Inner::default()),
            exec_warn: ms_to_ticks(1.0),
            fault_warn: ms_to_ticks(50.0),
            io_warn: ms_to_ticks(200.0),
            keep: ms_to_ticks(20_000.0),
            debug: false,
        });
        Analyzer {
            shared,
            rx,
            pending: Vec::new(),
            modules,
            procs,
            disks: DiskMap::new(),
            disk_why: HashMap::new(),
            health_at_start: HashMap::new(),
            started: qpc(),
            profile,
            incidents: Vec::new(),
            minor: VecDeque::new(),
            marks_pending: Vec::new(),
            marks_total: 0,
            mark_times: Vec::new(),
            marks_clean: 0,
            long_exec_times: HashMap::new(),
            notable_window_start: 0,
            notable_in_window: 0,
            notable_suppressed: 0,
            notable_total: 0,
        }
    }

    /// Called ~10x per second. `force` analyzes everything pending (shutdown).
    pub fn tick(&mut self, force: bool) {
        self.procs.refresh_if_older_than(2);
        for s in self.rx.try_iter() {
            if s.minor {
                self.minor.push_back(s);
            } else {
                self.pending.push(s);
            }
        }
        let now = qpc();
        while self.minor.front().is_some_and(|s| s.end < now - ms_to_ticks(MINOR_KEEP_MS)) {
            self.minor.pop_front();
        }
        self.report_notables();
        self.process_marks(force);
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
        self.incidents.push(IncidentSummary { kind, start, dur: worst, culprit, marked: false });
    }

    /// Marks wait for the trace to catch up just like stalls do.
    fn process_marks(&mut self, force: bool) {
        self.marks_pending.append(&mut MARKS.lock().unwrap());
        if self.marks_pending.is_empty() {
            return;
        }
        let now = qpc();
        let latest = self.shared.inner.lock().unwrap().latest_ts;
        let after = ms_to_ticks(MARK_AFTER_MS);
        let (ripe, waiting): (Vec<i64>, Vec<i64>) = std::mem::take(&mut self.marks_pending).into_iter().partition(|&t| {
            let caught_up = latest > t + after + ms_to_ticks(50.0);
            force || (caught_up && now - t > ms_to_ticks(1000.0)) || now - t > ms_to_ticks(5000.0)
        });
        self.marks_pending = waiting;
        for t in ripe {
            self.analyze_mark(t, latest > t + after);
        }
    }

    /// The user felt something at `t`. Look at the seconds before it with no threshold at all.
    fn analyze_mark(&mut self, t: i64, caught_up: bool) {
        self.marks_total += 1;
        self.mark_times.push(t);
        let (from, to) = (t - ms_to_ticks(MARK_BEFORE_MS), t + ms_to_ticks(MARK_AFTER_MS));
        say!("");
        say!(
            "[{}] MARK #{}  you flagged a hitch; examining the {:.0} s before it",
            clock().fmt(t),
            self.marks_total,
            MARK_BEFORE_MS / 1000.0
        );

        // A full stall in the window already has (or will get) its own entry and verdict.
        let full = self.incidents.iter().filter(|i| !i.marked && i.start >= from && i.start <= to).count()
            + self.pending.iter().filter(|s| s.start >= from && s.start <= to).count();
        if full > 0 {
            say!("    A full stall was detected at this moment; see the STALL entries around this time.");
            return;
        }

        let blips: Vec<Stall> =
            self.minor.iter().filter(|s| s.kind == StallKind::Kernel && s.end >= from && s.start <= to).copied().collect();
        let noise = blips.iter().map(|s| s.end - s.start).max().unwrap_or(0);
        let in_window: Vec<Stall> = blips.into_iter().filter(|s| s.end - s.start >= ms_to_ticks(MARK_MIN_MS)).collect();
        let Some(worst) = in_window.iter().max_by_key(|s| s.end - s.start).copied() else {
            let ev = self.gather(from, to, from, caught_up);
            say!(
                "    No CPU core was held up for {MARK_MIN_MS:.0} ms or more in that window (longest blip: {}, normal background noise),",
                fmt_dur(noise)
            );
            say!("    so drivers, interrupts and firmware are in the clear for this one.");
            self.print_longest_execs(&ev);
            self.print_io_context(&ev);
            let all: Vec<&(SampleRec, u32)> = ev.samples.iter().collect();
            let (procs, _) = self.sample_breakdown(&all);
            let busy: Vec<_> = procs.into_iter().filter(|(p, _)| p != "Idle").collect();
            self.print_on_cpu(&busy, &[]);
            say!("    -> If the hitch was real, look inside the app or at the GPU (frame pacing, shader compilation, VRAM).");
            self.marks_clean += 1;
            return;
        };

        // Examine the worst interruption (with whatever hit other CPUs at the same instant)
        // exactly like a full stall, just without the threshold.
        let gap = ms_to_ticks(2.0);
        let cluster: Vec<Stall> = in_window.iter().filter(|s| s.start <= worst.end + gap && s.end >= worst.start - gap).copied().collect();
        let start = cluster.iter().map(|s| s.start).min().unwrap();
        let end = cluster.iter().map(|s| s.end).max().unwrap();
        let dur = worst.end - worst.start;
        let offset_s = ticks_to_ms(t - worst.start) / 1000.0;
        say!(
            "    {} CPU interruption(s) in that window; the worst held CPU {} for {} at {} ({:.1} s {} your mark)",
            in_window.len(),
            worst.cpu.unwrap_or(0),
            fmt_dur(dur),
            clock().fmt(worst.start),
            offset_s.abs(),
            if offset_s >= 0.0 { "before" } else { "after" }
        );
        let ev = self.gather(start - ms_to_ticks(0.5), end, from, caught_up);
        let culprit = self.verdict_kernel(&cluster, &ev);
        self.print_io_context(&ev);
        self.incidents.push(IncidentSummary { kind: StallKind::Kernel, start, dur, culprit, marked: true });
    }

    fn print_longest_execs(&mut self, ev: &Evidence) {
        let mut execs: Vec<&ExecRec> = ev.execs.iter().collect();
        execs.sort_by_key(|e| std::cmp::Reverse(e.end - e.start));
        let txt: Vec<String> = execs
            .iter()
            .take(3)
            .map(|e| format!("{} {} {}", self.modules.name(e.routine), kind_name(e.kind), fmt_dur(e.end - e.start)))
            .collect();
        if !txt.is_empty() {
            say!("    Longest DPC/ISR runs then: {}", txt.join(", "));
        }
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
            let mut spans: Vec<(i64, i64)> = Vec::new();
            for e in ev.execs.iter().filter(|e| e.cpu == cpu) {
                let overlap = e.end.min(s.end) - e.start.max(s.start);
                if overlap > 0 {
                    spans.push((e.start.max(s.start), e.end.min(s.end)));
                    let r = by_routine.entry((e.routine, e.kind)).or_default();
                    r.0 += overlap;
                    r.1 = r.1.max(e.end - e.start);
                    r.2 += 1;
                }
            }
            covered += union_len(&mut spans);
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
            let what = self.modules.describe_short(module);
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
            let what = self.modules.describe_short(m);
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
        // Our own probe threads are, by design, what gets interrupted; they are never the cause.
        let own = std::env::current_exe().ok().and_then(|p| p.file_name().map(|f| f.to_string_lossy().to_lowercase()));
        if let Some(own) = own {
            named.retain(|name, _| !name.to_lowercase().starts_with(&own));
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
                "    Slow disk I/O nearby:    {} slow request(s), worst {} on {} ({}, issued by {})",
                slow_io.len(),
                fmt_dur(worst.dur),
                self.disks.get(worst.disk).short(),
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
            // Every slow request is explained, including the ones the log below leaves out.
            let why = if let Notable::SlowIo(i) = &n { self.explain_io(i) } else { String::new() };
            if let Notable::LongExec(e) = &n {
                let times = self.long_exec_times.entry(self.modules.name(e.routine)).or_default();
                if times.len() < 5000 {
                    times.push(e.start);
                }
            }
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
                    "[{}] slow disk {:<5} {:>9}  {}  {} KB  issued by {}  ({why})",
                    clock().fmt(i.end - i.dur),
                    op_name(i.op),
                    fmt_dur(i.dur),
                    self.disks.get(i.disk).short(),
                    i.size / 1024,
                    self.procs.label(i.pid, i.tid)
                ),
            }
        }
    }

    /// Works out what the disk was doing while `slow` was outstanding, adds it to the disk's
    /// totals and returns a few words for the log line.
    fn explain_io(&mut self, slow: &IoRec) -> String {
        let ios: Vec<IoRec> = self.shared.inner.lock().unwrap().ios.iter().filter(|i| i.disk == slow.disk).copied().collect();
        let spinning = self.disks.get(slow.disk).spinning == Some(true);
        let ctx = diskwhy::explain(slow, &ios, spinning, self.started);
        let movers: Vec<(String, u64)> =
            ctx.movers.iter().map(|(pid, tid, bytes)| (process_name(&self.procs.label(*pid, *tid)), *bytes)).collect();
        let why = self.disk_why.entry(slow.disk).or_default();
        *why.causes.entry(ctx.cause).or_default() += 1;
        match ctx.cause {
            Cause::Busy => {
                for (name, bytes) in &movers {
                    *why.movers.entry(name.clone()).or_default() += bytes;
                }
                let top = movers.first().map_or(String::new(), |(n, _)| format!(", mostly {n}"));
                format!("disk busy: {:.0} MB/s{top}", ctx.mb_per_s)
            }
            Cause::WokeUp => {
                let idle = ctx.idle_before_ms.unwrap_or(0.0);
                why.longest_sleep_ms = why.longest_sleep_ms.max(idle);
                format!("first request after {:.0} s of silence: the drive was asleep", idle / 1000.0)
            }
            Cause::Flush => "a program forced its writes out to the drive".to_string(),
            Cause::IdleSlow => "disk had little else to do".to_string(),
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
}

/// Total length covered by possibly overlapping intervals. ISRs interrupt DPCs, so their
/// intervals nest; summing them would count the same instant twice.
fn union_len(spans: &mut [(i64, i64)]) -> i64 {
    spans.sort_unstable();
    let (mut covered, mut reach) = (0, i64::MIN);
    for &(from, to) in spans.iter() {
        covered += (to - from.max(reach)).max(0);
        reach = reach.max(to);
    }
    covered
}

fn op_name(op: u8) -> &'static str {
    match op {
        b'R' => "read",
        b'W' => "write",
        _ => "flush",
    }
}

/// "steam.exe (1234)" -> "steam.exe", so several processes of one program add up.
fn process_name(label: &str) -> String {
    match label.rsplit_once(" (") {
        Some((name, rest)) if rest.trim_end_matches(')').chars().all(|c| c.is_ascii_digit()) => name.to_string(),
        _ => label.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nested_and_overlapping_intervals_are_counted_once() {
        // A 100-tick DPC with two ISRs inside it, a partial overlap, and a separate run.
        let mut spans = vec![(0, 100), (10, 20), (50, 60), (90, 130), (200, 250)];
        assert_eq!(union_len(&mut spans), 130 + 50);
        assert_eq!(union_len(&mut []), 0);
    }

    // --- verdict_kernel / verdict_sched, on synthetic evidence -----------------------------

    fn ms(v: f64) -> i64 {
        ms_to_ticks(v)
    }

    fn stall(cpu: u16, start_ms: f64, dur_ms: f64) -> Stall {
        Stall { kind: StallKind::Kernel, cpu: Some(cpu), start: ms(start_ms), end: ms(start_ms + dur_ms), minor: false }
    }

    fn exec_rec(cpu: u16, kind: u8, start_ms: f64, dur_ms: f64, routine: u64) -> ExecRec {
        ExecRec { cpu, kind, start: ms(start_ms), end: ms(start_ms + dur_ms), routine }
    }

    fn dpc(cpu: u16, start_ms: f64, dur_ms: f64, routine: u64) -> ExecRec {
        exec_rec(cpu, KIND_DPC, start_ms, dur_ms, routine)
    }

    fn isr(cpu: u16, start_ms: f64, dur_ms: f64, routine: u64) -> ExecRec {
        exec_rec(cpu, KIND_ISR, start_ms, dur_ms, routine)
    }

    /// `pid == 0` is Idle and gets `tid == 0` to match; any other pid gets a nonzero tid so
    /// it counts toward kernel-mode module attribution when `ip` is in kernel space.
    fn sample(cpu: u16, t_ms: f64, ip: u64, pid: u32) -> (SampleRec, u32) {
        let tid = if pid == 0 { 0 } else { pid.max(1) };
        (SampleRec { ts: ms(t_ms), cpu, tid, ip }, pid)
    }

    fn evidence(execs: Vec<ExecRec>, samples: Vec<(SampleRec, u32)>, baseline: HashMap<u16, u32>) -> Evidence {
        Evidence { execs, faults: Vec::new(), ios: Vec::new(), samples, baseline, etw_caught_up: true }
    }

    const MOD_A: u64 = KERNEL_SPACE + 0x1_0000;
    const MOD_B: u64 = KERNEL_SPACE + 0x5_0000;
    const USER_IP: u64 = 0x0000_7ff6_0000_0000;

    #[test]
    fn dpc_coverage_over_threshold_blames_the_driver_on_the_stalled_cpu() {
        let modules = ModuleMap::for_test(&[("nvlddmkm.sys", MOD_A, 0x1000)]);
        let mut az = Analyzer::for_test(modules, ProcNames::for_test(&[]), false);
        let s = stall(0, 0.0, 100.0);
        let ev = evidence(vec![dpc(0, 0.0, 40.0, MOD_A + 0x10)], vec![], HashMap::new());
        assert_eq!(az.verdict_kernel(&[s], &ev), "driver nvlddmkm.sys");
    }

    #[test]
    fn dpc_on_a_different_cpu_is_not_blamed() {
        let modules = ModuleMap::for_test(&[("nvlddmkm.sys", MOD_A, 0x1000)]);
        let mut az = Analyzer::for_test(modules, ProcNames::for_test(&[]), false);
        let s = stall(0, 0.0, 100.0);
        // Same DPC, same size, but it ran on CPU 1 while the probe stalled on CPU 0.
        let ev = evidence(vec![dpc(1, 0.0, 40.0, MOD_A + 0x10)], vec![], HashMap::new());
        assert_eq!(az.verdict_kernel(&[s], &ev), "unexplained");
    }

    #[test]
    fn dpc_coverage_just_under_threshold_is_not_blamed() {
        let modules = ModuleMap::for_test(&[("nvlddmkm.sys", MOD_A, 0x1000)]);
        let mut az = Analyzer::for_test(modules, ProcNames::for_test(&[]), false);
        let s = stall(0, 0.0, 100.0);
        // 34% covered: just below the 35% rule-1 threshold.
        let ev = evidence(vec![dpc(0, 0.0, 34.0, MOD_A + 0x10)], vec![], HashMap::new());
        assert_eq!(az.verdict_kernel(&[s], &ev), "unexplained");
    }

    #[test]
    fn overlapping_dpc_and_isr_are_not_double_counted_toward_coverage() {
        let modules = ModuleMap::for_test(&[("nvlddmkm.sys", MOD_A, 0x1000), ("rtwlane.sys", MOD_B, 0x1000)]);
        let mut az = Analyzer::for_test(modules, ProcNames::for_test(&[]), false);
        let s = stall(0, 0.0, 100.0);
        // A DPC and an ISR from two different drivers, both covering the exact same 0-20ms
        // window. Naive summing would give 20+20=40ms => 40% of the 100ms stall, clearing the
        // 35% rule-1 threshold; the real (unioned) coverage is only 20ms => 20%, which doesn't.
        let ev = evidence(vec![dpc(0, 0.0, 20.0, MOD_A + 0x10), isr(0, 0.0, 20.0, MOD_B + 0x10)], vec![], HashMap::new());
        assert_eq!(az.verdict_kernel(&[s], &ev), "unexplained");
    }

    #[test]
    fn cpu_going_dark_is_reported_only_when_profiling() {
        let mut baseline = HashMap::new();
        baseline.insert(0u16, 500u32); // 500 samples in the 500ms baseline window: ~1/ms
        let s = stall(0, 0.0, 100.0);
        let ev = evidence(vec![], vec![], baseline);

        let mut profiled = Analyzer::for_test(ModuleMap::for_test(&[]), ProcNames::for_test(&[]), true);
        let v = profiled.verdict_kernel(&[s], &ev);
        assert!(v.starts_with("CPU went dark"), "expected 'CPU went dark...', got {v:?}");

        // Same evidence, but sampling wasn't enabled: it must not claim the CPU went dark.
        let mut unprofiled = Analyzer::for_test(ModuleMap::for_test(&[]), ProcNames::for_test(&[]), false);
        assert_eq!(unprofiled.verdict_kernel(&[s], &ev), "unexplained");
    }

    #[test]
    fn very_short_stalls_do_not_trigger_went_dark() {
        let mut baseline = HashMap::new();
        baseline.insert(0u16, 500u32); // ~1 sample/ms
                                       // 2ms stall => ~2 expected samples, under the "expected >= 3" floor.
        let s = stall(0, 0.0, 2.0);
        let ev = evidence(vec![], vec![], baseline);
        let mut az = Analyzer::for_test(ModuleMap::for_test(&[]), ProcNames::for_test(&[]), true);
        assert_eq!(az.verdict_kernel(&[s], &ev), "unexplained");
    }

    #[test]
    fn kernel_module_holding_most_samples_is_blamed() {
        let modules = ModuleMap::for_test(&[("rtwlane.sys", MOD_B, 0x1000)]);
        let procs = ProcNames::for_test(&[(777, "driverhost.exe"), (300, "explorer.exe")]);
        let mut az = Analyzer::for_test(modules, procs, false);
        let s = stall(0, 0.0, 100.0);
        let samples = vec![
            sample(0, 10.0, MOD_B + 0x10, 777),
            sample(0, 20.0, MOD_B + 0x10, 777),
            sample(0, 30.0, MOD_B + 0x10, 777),
            sample(0, 40.0, USER_IP, 300),
            sample(0, 50.0, USER_IP, 300),
        ];
        let ev = evidence(vec![], samples, HashMap::new());
        assert_eq!(az.verdict_kernel(&[s], &ev), "driver rtwlane.sys");
    }

    #[test]
    fn user_process_holding_most_samples_is_blamed() {
        let procs = ProcNames::for_test(&[(200, "game.exe"), (300, "other.exe")]);
        let mut az = Analyzer::for_test(ModuleMap::for_test(&[]), procs, false);
        let s = stall(0, 0.0, 100.0);
        let samples = vec![
            sample(0, 10.0, USER_IP, 200),
            sample(0, 20.0, USER_IP, 200),
            sample(0, 30.0, USER_IP, 200),
            sample(0, 40.0, USER_IP, 300),
            sample(0, 50.0, USER_IP, 300),
        ];
        let ev = evidence(vec![], samples, HashMap::new());
        assert_eq!(az.verdict_kernel(&[s], &ev), "process game.exe (200)");
    }

    #[test]
    fn nothing_conclusive_is_unexplained() {
        let mut az = Analyzer::for_test(ModuleMap::for_test(&[]), ProcNames::for_test(&[]), false);
        let s = stall(0, 0.0, 100.0);
        let ev = evidence(vec![], vec![], HashMap::new());
        assert_eq!(az.verdict_kernel(&[s], &ev), "unexplained");
    }

    #[test]
    fn sample_breakdown_filters_out_the_tools_own_process() {
        // sample_breakdown() excludes whatever process name starts with our own exe's file
        // name; under `cargo test` that's the test binary itself, so we can mirror the same
        // lookup here instead of touching a live process list.
        let own = std::env::current_exe().unwrap().file_name().unwrap().to_string_lossy().to_lowercase();
        let procs = ProcNames::for_test(&[(999, &own), (111, "notme.exe")]);
        let mut az = Analyzer::for_test(ModuleMap::for_test(&[]), procs, false);
        let samples = [sample(0, 1.0, USER_IP, 999), sample(0, 2.0, USER_IP, 111)];
        let refs: Vec<&(SampleRec, u32)> = samples.iter().collect();
        let (procs_shares, _mods) = az.sample_breakdown(&refs);
        assert!(!procs_shares.iter().any(|(name, _)| name.to_lowercase().starts_with(&own)), "{procs_shares:?}");
        assert!(procs_shares.iter().any(|(name, _)| name == "notme.exe (111)"), "{procs_shares:?}");
    }

    #[test]
    fn sched_without_profiling_is_unattributed() {
        let mut az = Analyzer::for_test(ModuleMap::for_test(&[]), ProcNames::for_test(&[(500, "app.exe")]), false);
        let ev = evidence(vec![], vec![sample(0, 1.0, USER_IP, 500)], HashMap::new());
        assert_eq!(az.verdict_sched(&ev), "CPU starvation (unattributed)");
    }

    #[test]
    fn sched_with_no_samples_is_unattributed() {
        let mut az = Analyzer::for_test(ModuleMap::for_test(&[]), ProcNames::for_test(&[]), true);
        let ev = evidence(vec![], vec![], HashMap::new());
        assert_eq!(az.verdict_sched(&ev), "CPU starvation (unattributed)");
    }

    #[test]
    fn sched_blames_top_consumer_when_idle_is_low() {
        let procs = ProcNames::for_test(&[(500, "app.exe")]);
        let mut az = Analyzer::for_test(ModuleMap::for_test(&[]), procs, true);
        let mut samples: Vec<(SampleRec, u32)> = (0..8).map(|i| sample(0, i as f64, USER_IP, 500)).collect();
        samples.extend((0..2).map(|i| sample(0, i as f64, USER_IP, 0))); // Idle: 2/10 = 20% < 25%
        let ev = evidence(vec![], samples, HashMap::new());
        assert_eq!(az.verdict_sched(&ev), "process app.exe (500)");
    }

    #[test]
    fn sched_reports_idle_cpus_when_idle_share_is_high() {
        let procs = ProcNames::for_test(&[(500, "app.exe"), (600, "other.exe")]);
        let mut az = Analyzer::for_test(ModuleMap::for_test(&[]), procs, true);
        let mut samples: Vec<(SampleRec, u32)> = (0..3).map(|i| sample(0, i as f64, USER_IP, 0)).collect(); // Idle: 30%
        samples.extend((0..4).map(|i| sample(0, i as f64, USER_IP, 500)));
        samples.extend((0..3).map(|i| sample(0, i as f64, USER_IP, 600)));
        let ev = evidence(vec![], samples, HashMap::new());
        assert_eq!(az.verdict_sched(&ev), "scheduling delay with idle CPUs");
    }
}
