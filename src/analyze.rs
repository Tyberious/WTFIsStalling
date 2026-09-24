//! Correlates probe stalls with what ETW saw on the affected CPUs, prints incident
//! reports as they happen and the final summary.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex};

use crate::disks::DiskMap;
use crate::diskstuck::{self, DiskBehind};
use crate::diskwait::{self, DiskWait, Role};
use crate::diskwhy::{self, Cause, DiskWhy};
use crate::files::{self, DosMap};
use crate::gputrace::{GpuTrace, GpuWindow, MarkGpu};
use crate::health::{self, DriveHealth};
use crate::intr::{self, Flow, Reference};
use crate::modules::{ModuleMap, KERNEL_SPACE};
use crate::probe::{ProbeTids, Stall, StallKind};
use crate::procs::{process_name, ProcNames};
use crate::quiet::Quieter;
use crate::say;
use crate::stacks::{self, IoStack, Kind as StackKind};
use crate::state::*;
use crate::storport::split::{self as storsplit, Outcome, SplitTotals};
use crate::storport::{ScsiAddr, StorTrace};
use crate::switches::{self, ProbeVerdict, ProbeWindow, RanInstead};
use crate::topology::{topology, Topology};
use crate::util::{clock, fmt_dur, ms_to_ticks, plural, qpc, ticks_to_ms};

/// What kind of event an incident was. A stall that holds one core is a different animal from
/// one that stops the whole machine, and the report has to count and word them separately.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum IncidentClass {
    /// Every (or nearly every) logical CPU held at once, for long enough to feel.
    Freeze,
    /// One or a few cores held at kernel level.
    Kernel,
    /// A normal-priority thread could not get a core.
    Starvation,
}

/// A whole-PC freeze has to last at least this long. 0.1 s is the classic limit below which a
/// person perceives a system as reacting instantly (Miller 1968; Card, Robertson & Mackinlay
/// 1991, as summarized in nngroup.com/articles/response-times-3-important-limits), so a gap
/// shorter than this is a latency problem, not "the PC stopped". Deliberately well under the
/// 750-1300 ms of the field reports in issue #15: those must not be what defines the class.
pub const FREEZE_MS: f64 = 100.0;

/// How many logical CPUs have to be held at once for "the whole PC stopped".
///
/// Requiring literally all of them is right on a 4-thread laptop and wrong on a 64-thread
/// workstation, where a single probe that is itself descheduled, or one CPU parked by the power
/// manager, would hide every freeze. So: all of them up to 4 CPUs, and three quarters (never
/// fewer than 4) above that.
pub fn freeze_cpu_floor(ncpu: usize) -> usize {
    if ncpu <= 4 {
        ncpu
    } else {
        (ncpu * 3).div_ceil(4).max(4)
    }
}

/// Two probes with different priorities, in two processes, see the same freeze a few ms apart.
/// They are matched by their edges rather than merged blindly, so an unrelated starvation stall
/// that happens to be nearby stays its own incident.
const TWIN_SLACK_MS: f64 = 25.0;
/// How long a ripe cluster is held waiting for its twin from the other probe. Bounded on
/// purpose: past this the sibling is not coming, and the incident is reported alone.
const TWIN_WAIT_MS: f64 = 500.0;

/// How far back the reference window for interrupt rates reaches. The ring buffers keep 20 s, and
/// a single 500 ms slice is far too short for a source that comes in bursts.
const REF_MS: f64 = 8000.0;
/// Below this much usable reference, the continuity check says nothing at all.
const REF_MIN_MS: f64 = 2000.0;
/// A DPC/ISR share of one CPU's stall this high is the driver executing, not a sample landing.
const COVER_RULE: f64 = 0.35;
/// A share of the samples this high points at whatever was on the CPU...
const SHARE_RULE: f64 = 0.4;
/// ...but never on fewer samples than this, and the count is printed when it is thin.
const MIN_SAMPLES: usize = 4;
const THIN_SAMPLES: usize = 10;

/// Which interrupt sources kept going through a freeze, and what coincided with it.
#[derive(Clone, Debug, Default)]
pub(crate) struct FreezeFacts {
    pub(crate) cpus: usize,
    pub(crate) ncpu: usize,
    /// Share of the CPU samples inside the freeze that were the Idle process.
    pub(crate) idle_share: f64,
    pub(crate) samples: usize,
    /// Programs seen on the CPUs. Context only: in a whole-PC freeze they are stopped too.
    pub(crate) on_cpu: Vec<String>,
    /// Steady interrupt sources that stopped, and ones that carried on, with the share of their
    /// usual rate seen inside the freeze.
    pub(crate) silent: Vec<(String, f64)>,
    pub(crate) continued: Vec<(String, f64)>,
    /// Whether timer DPCs (the clock that wakes threads) stopped, when it could be judged.
    pub(crate) timer: Option<Flow>,
    /// Ordinary DPCs kept executing right through it, so no CPU was held at raised IRQL.
    pub(crate) dpcs_kept_running: bool,
    /// A driver whose own DPC/ISR code really did cover the stall on most CPUs, if any.
    pub(crate) holding: Option<(String, usize)>,
    pub(crate) coincided: Option<Coincided>,
    /// What the scheduler did to the measuring threads: were they woken at all? See `switches`.
    pub(crate) probes: ProbeVerdict,
}

/// One program that was kept waiting at a moment that mattered, merged over every such moment.
///
/// Nothing here says WHY. A wait reason is a kind of wait and a waker is the thread that
/// signalled: neither names a lock or a culprit, and the report must not either.
#[derive(Clone, Debug, Default)]
pub struct ProgramWait {
    /// The process label of whatever held the processor during the longest ready-wait.
    pub instead: Option<String>,
    /// That processor had nothing else to do, which is a different problem entirely.
    pub instead_idle: bool,
    /// Longest stretch one of this program's threads was runnable and did not get a processor.
    pub ready: i64,
    /// Longest stretch one of them was blocked, start and end both inside the window.
    pub blocked: i64,
    pub blocked_reason: i8,
    /// The program whose thread ended that block.
    pub woken_by: Option<String>,
    /// How many of the examined moments this program was kept waiting at.
    pub moments: u32,
}

/// A storage event that overlapped a freeze. Never a cause, only a coincidence.
#[derive(Clone, Debug)]
pub(crate) struct Coincided {
    pub(crate) disk: Option<u32>,
    pub(crate) role: Role,
    pub(crate) waited: i64,
    /// That drive had been asleep before this run's slow requests.
    pub(crate) woke: bool,
}

pub(crate) struct IncidentSummary {
    pub(crate) class: IncidentClass,
    pub(crate) start: i64,
    pub(crate) dur: i64,
    pub(crate) culprit: String,
    /// Below the stall threshold; only examined because the user flagged that moment.
    pub(crate) marked: bool,
    /// The CPUs whose probes were held up (system-wide indexes); empty for CPU starvation.
    pub(crate) cpus: Vec<u16>,
    /// The process that held most of the CPU samples inside this stall, when one clearly did.
    ///
    /// A driver runs on behalf of whoever asked it to work, so for a stall blamed on a driver this
    /// is the program that set it off ("running for iCUE.exe"). Never a culprit by itself, and
    /// never set for a whole-PC freeze, where everything on the CPUs was stopped too.
    pub(crate) on_cpu: Option<String>,
    /// Set on a `Freeze`; what the interrupt records say about it.
    pub(crate) freeze: Option<FreezeFacts>,
    /// Set on a CPU-starvation stall where one or a few cores were busy while the others idled:
    /// what held the (first) busy one. Context, never the culprit; see `pegged_cores`.
    pub(crate) busy_core: Option<CoreHolder>,
}

/// What kept one busy core busy, as far as its CPU samples say.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CoreHolder {
    /// A process label ("SignalRgb.exe (32468)"), which held most of that core's samples.
    Program(String),
    /// A driver whose DPC/ISR code the samples on that core mostly landed in.
    Driver(String),
    /// Busy, but no single program or driver held most of it.
    Unnamed,
}

/// Share of a stall's CPU samples one process must hold before the report will say the driver was
/// running for it. Above `SHARE_RULE` (0.4, the bar for blaming a process outright) on purpose: a
/// plain majority is the least that can honestly be called "this program was on the processor".
const ON_BEHALF_SHARE: f64 = 0.5;

/// One slow request seen on a disk, and whether a whole-PC freeze explains it.
#[derive(Clone, Copy)]
pub(crate) struct SlowSeen {
    pub(crate) end: i64,
    pub(crate) dur: i64,
    pub(crate) victim: bool,
}

/// The System process: Windows' own kernel threads.
const SYSTEM_PID: u32 = 4;

/// What `explain_io` has to say about one slow request.
struct IoWhy {
    /// Why the disk was slow, for the end of the slow-disk line.
    why: String,
    /// "    Request: ..." - what the request was.
    request: Option<String>,
    /// "    Stuck behind it: ..." - who waited for it.
    stuck: Option<String>,
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
    /// Drive letters, for turning the kernel's `\Device\HarddiskVolume3\...` into `C:\...`.
    pub(crate) dos: DosMap,
    /// What this PC's CPUs are: processor groups, and P-cores vs E-cores on a hybrid chip.
    pub(crate) topo: Topology,
    /// Why each disk's slow requests were slow, as far as the traffic around them can tell.
    pub(crate) disk_why: HashMap<u32, DiskWhy>,
    /// Every slow request seen per disk, and whether a freeze explains it (see `diskwait`).
    pub(crate) disk_slow: HashMap<u32, Vec<SlowSeen>>,
    /// What each disk's slow requests were and who was stuck behind them (see `diskstuck`).
    pub(crate) disk_behind: HashMap<u32, DiskBehind>,
    /// Slow-request events waiting for the trace to reach past them, so the threads woken as
    /// they completed are in the rings before anyone looks. Everything after the first such
    /// event waits with it, so the event log stays in order.
    held_notables: Vec<Notable>,
    /// Each drive's own health counters when monitoring began; the summary compares against them.
    pub(crate) health_at_start: HashMap<u32, DriveHealth>,
    started: i64,
    profile: bool,
    /// The threads doing the measuring, so the switch trace can be read against them.
    probe_tids: Arc<ProbeTids>,
    /// Programs kept waiting at flagged moments and CPU-starvation stalls, by program name.
    pub(crate) program_waits: HashMap<String, ProgramWait>,
    /// How many moments the program waits above were gathered from, so shares can be stated.
    pub(crate) wait_moments: u32,
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
    /// Folds repeats from one disk, driver or program into roll-up lines in the event log.
    quiet: Quieter,
    notable_window_start: i64,
    notable_in_window: u32,
    pub(crate) notable_suppressed: u64,
    /// Events folded into roll-up lines rather than shown one by one.
    pub(crate) notable_folded: u64,
    pub(crate) notable_total: u64,
    /// Flagged moments the thread-switch rings did not reach back far enough to explain.
    pub(crate) switch_uncovered: std::sync::atomic::AtomicU32,
    pub(crate) switch_gathers: std::sync::atomic::AtomicU32,
    /// The graphics-kernel trace, when a second session could be started for it.
    pub(crate) gputrace: Option<Arc<GpuTrace>>,
    /// What it saw at each flagged moment. Kept as the moment is examined: its rings only hold a
    /// few seconds and the summary runs minutes later.
    pub(crate) gpu_marks: Vec<MarkGpu>,
    /// The storage port driver's trace, when a session could be started for it (see `storport`).
    pub(crate) storport: Option<Arc<StorTrace>>,
    /// Where each disk's slow requests' time went, per disk; worked out as each is examined.
    pub(crate) disk_split: HashMap<u32, SplitTotals>,
    /// Each disk's address on its storage port, read once (see `disks::scsi_address`).
    scsi_addrs: HashMap<u32, Option<ScsiAddr>>,
    /// The once-a-second CPU clock samples, for "the processor was throttled at the time".
    clock: Option<crate::cpuclock::Samples>,
    /// Memory in use right now, %; `None` where it must not be read (tests).
    mem_load: fn() -> Option<u32>,
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
    /// DPC/ISR runs in the reference window before the incident, and how long that window was.
    /// Empty when there was no usable stretch (the previous incident was too close).
    ref_execs: Vec<ExecRec>,
    ref_seconds: f64,
    etw_caught_up: bool,
    /// Context switches and wake-ups covering the window, in timestamp order. Empty when the
    /// session is not tracing them (light mode, `--no-switches`, or Windows refusing).
    switches: Vec<SwitchRec>,
    readies: Vec<ReadyRec>,
    /// The switch rings really do cover this window: they are being recorded, they were not
    /// overflowed, and their (short) history still reaches back past `from`. When this is false
    /// nothing may be concluded from them.
    switches_cover: bool,
}

const BASELINE_MS: f64 = 500.0;

/// (name, fraction of samples), biggest first.
type Shares = Vec<(String, f64)>;

/// One DPC/ISR routine's activity inside a stall: ((routine, kind), (overlap, longest, count)).
type RoutineRow = ((u64, u8), (i64, i64, u32));

/// What the DPC/ISR and sample records say about one cluster of stalls.
struct Look {
    routines: Vec<RoutineRow>,
    /// Per stalled CPU: its own DPC/ISR coverage, and whether DPCs kept running through it.
    per_cpu: Vec<CpuStall>,
    /// A module whose own DPC/ISR code covered `COVER_RULE` of the stall on at least half of the
    /// stalled CPUs, with how many CPUs that was.
    blame: Option<(String, usize)>,
    /// Best single-CPU coverage in the cluster, for the "nothing explains it" sentence.
    best_coverage: f64,
    /// Share of the stalled CPUs on which ordinary DPCs were NOT running through the stall.
    held_share: f64,
    seen_samples: f64,
    expected_samples: f64,
    on_cpu_procs: Shares,
    on_cpu_mods: Shares,
    samples: usize,
}

struct CpuStall {
    coverage: f64,
    held: bool,
}

impl Analyzer {
    pub fn new(shared: Arc<Shared>, rx: Receiver<Stall>, modules: ModuleMap, profile: bool, probe_tids: Arc<ProbeTids>) -> Analyzer {
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
            dos: DosMap::live(),
            topo: topology().clone(),
            disk_why: HashMap::new(),
            disk_slow: HashMap::new(),
            disk_behind: HashMap::new(),
            held_notables: Vec::new(),
            health_at_start,
            started: qpc(),
            profile,
            probe_tids,
            program_waits: HashMap::new(),
            wait_moments: 0,
            incidents: Vec::new(),
            minor: VecDeque::new(),
            marks_pending: Vec::new(),
            marks_total: 0,
            mark_times: Vec::new(),
            marks_clean: 0,
            long_exec_times: HashMap::new(),
            quiet: Quieter::default(),
            notable_window_start: 0,
            notable_in_window: 0,
            notable_suppressed: 0,
            notable_folded: 0,
            notable_total: 0,
            switch_uncovered: Default::default(),
            switch_gathers: Default::default(),
            gputrace: None,
            gpu_marks: Vec::new(),
            storport: None,
            disk_split: HashMap::new(),
            scsi_addrs: HashMap::new(),
            clock: None,
            mem_load: || Some(crate::util::memory_load()),
        }
    }

    /// Builds an `Analyzer` from synthetic data only: no live disk health, process
    /// snapshot or module list. For tests of `verdict_kernel`/`verdict_sched`, which only
    /// need `self.modules`/`self.procs` and hand-built `Evidence` values.
    #[cfg(test)]
    pub fn for_test(modules: ModuleMap, procs: ProcNames, profile: bool) -> Analyzer {
        let probe_tids = Arc::new(ProbeTids::default());
        let (_tx, rx) = std::sync::mpsc::channel();
        let shared = Arc::new(Shared {
            inner: Mutex::new(Inner::default()),
            exec_warn: ms_to_ticks(1.0),
            fault_warn: ms_to_ticks(50.0),
            io_warn: ms_to_ticks(200.0),
            keep: ms_to_ticks(20_000.0),
            switches: true,
            debug: false,
        });
        Analyzer {
            shared,
            rx,
            pending: Vec::new(),
            modules,
            procs,
            disks: DiskMap::new(),
            dos: DosMap::default(),
            topo: Topology::default(),
            disk_why: HashMap::new(),
            disk_slow: HashMap::new(),
            disk_behind: HashMap::new(),
            held_notables: Vec::new(),
            health_at_start: HashMap::new(),
            started: qpc(),
            profile,
            probe_tids,
            program_waits: HashMap::new(),
            wait_moments: 0,
            incidents: Vec::new(),
            minor: VecDeque::new(),
            marks_pending: Vec::new(),
            marks_total: 0,
            mark_times: Vec::new(),
            marks_clean: 0,
            long_exec_times: HashMap::new(),
            quiet: Quieter::default(),
            notable_window_start: 0,
            notable_in_window: 0,
            notable_suppressed: 0,
            notable_folded: 0,
            notable_total: 0,
            switch_uncovered: Default::default(),
            switch_gathers: Default::default(),
            gputrace: None,
            gpu_marks: Vec::new(),
            storport: None,
            disk_split: HashMap::new(),
            scsi_addrs: HashMap::new(),
            clock: None,
            mem_load: || None,
        }
    }

    /// Logical CPUs on this PC, or 0 when the topology was never read (tests).
    pub(crate) fn ncpu(&self) -> usize {
        self.topo.total()
    }

    /// Hands stalls to the clustering in `tick` without a probe process behind them.
    #[cfg(test)]
    pub(crate) fn feed(&mut self, stalls: &[Stall]) {
        self.pending.extend_from_slice(stalls);
    }

    #[cfg(test)]
    pub(crate) fn waiting(&self) -> usize {
        self.pending.len()
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
        self.report_notables(force);
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

        // One freeze is reported twice: by the pinned real-time probes in the child process and,
        // a few ms later and through a different path, by the normal-priority probe here. Pair
        // them up so it becomes one incident with one verdict and one tally row.
        let (kernel, sched): (Vec<Vec<Stall>>, Vec<Vec<Stall>>) = clusters.into_iter().partition(|c| c[0].kind == StallKind::Kernel);
        let mut sched: Vec<Option<Vec<Stall>>> = sched.into_iter().map(Some).collect();
        let mut groups: Vec<(Vec<Stall>, Vec<Stall>)> = Vec::new();
        for k in kernel {
            let span = span_of(&k);
            let twin = sched.iter_mut().find(|c| c.as_ref().is_some_and(|c| is_twin(span, span_of(c))));
            let twin = twin.and_then(|t| t.take()).unwrap_or_default();
            groups.push((k, twin));
        }
        groups.extend(sched.into_iter().flatten().map(|s| (Vec::new(), s)));

        // ETW delivers in ~1 s batches. A cluster is ripe once the trace has caught up past
        // its end, or we've waited long enough that it isn't going to.
        let latest = self.shared.inner.lock().unwrap().latest_ts;
        for (kernel, sched) in groups {
            let end = kernel.iter().chain(sched.iter()).map(|s| s.end).max().unwrap();
            let age = now - end;
            let caught_up = latest > end + ms_to_ticks(50.0);
            let ripe = force || (caught_up && age > ms_to_ticks(300.0)) || age > ms_to_ticks(4000.0);
            // Both halves in hand, or long enough that the other one is not coming. Time-based,
            // so nothing can be held forever and nothing waits on a message that never arrives.
            let paired = !kernel.is_empty() && !sched.is_empty();
            if force || (ripe && (paired || age > ms_to_ticks(TWIN_WAIT_MS))) {
                self.analyze(&kernel, &sched, caught_up);
            } else {
                self.pending.extend(kernel);
                self.pending.extend(sched);
            }
        }
    }

    fn gather(&self, from: i64, to: i64, wide_from: i64, ref_from: i64, caught_up: bool) -> Evidence {
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
        let usable_ref = from - ref_from >= ms_to_ticks(REF_MIN_MS);
        // The switch rings hold only a few seconds. They cover this window when they are being
        // filled at all, nothing was thrown away by the count cap, and the oldest record still
        // held is no newer than the start of what is being asked about. `wide_from` is the
        // earliest instant any caller looks at.
        //
        // The extra lead is so that "which thread was already on this processor when the wait
        // began" can be answered: that needs the last switch AT OR BEFORE the window, which on an
        // idle processor could be much older. It does not need to be long, because this tool's own
        // probe threads switch in on every processor every 1-2 ms for as long as a run lasts, so
        // no processor goes a quarter of a second without a switch record while it is measuring.
        let switch_from = wide_from.min(from) - ms_to_ticks(250.0);
        let switches_cover = self.shared.switches && inner.switches_cover(switch_from);
        if self.shared.switches {
            use std::sync::atomic::Ordering::Relaxed;
            self.switch_gathers.fetch_add(1, Relaxed);
            if !switches_cover {
                self.switch_uncovered.fetch_add(1, Relaxed);
            }
        }
        let (switches, readies) = if switches_cover { inner.switch_window(switch_from, to) } else { (Vec::new(), Vec::new()) };
        Evidence {
            switches,
            readies,
            switches_cover,
            execs: inner.execs.iter().filter(|e| e.end >= from && e.start <= to).copied().collect(),
            faults: inner.faults.iter().filter(|f| f.end >= wide_from && f.start <= to).copied().collect(),
            ios: inner.ios.iter().filter(|i| i.end >= wide_from && i.end - i.dur <= to).copied().collect(),
            samples,
            baseline,
            ref_execs: if usable_ref {
                inner.execs.iter().filter(|e| e.start >= ref_from && e.start < from).copied().collect()
            } else {
                Vec::new()
            },
            ref_seconds: if usable_ref { ticks_to_ms(from - ref_from) / 1000.0 } else { 0.0 },
            etw_caught_up: caught_up,
        }
    }

    fn analyze(&mut self, kernel: &[Stall], sched: &[Stall], caught_up: bool) {
        let all: Vec<Stall> = kernel.iter().chain(sched.iter()).copied().collect();
        let start = all.iter().map(|s| s.start).min().unwrap();
        let end = all.iter().map(|s| s.end).max().unwrap();
        let worst = all.iter().map(|s| s.end - s.start).max().unwrap();
        let lead = ms_to_ticks(if kernel.is_empty() { 4.0 } else { 0.5 });
        // The reference window for interrupt rates never reaches back into the previous incident:
        // comparing a freeze with the tail of the last freeze would flatten exactly the signal
        // this is looking for.
        let prev_end = self.incidents.last().map_or(i64::MIN / 2, |i| i.start + i.dur);
        let ref_to = start - lead;
        let ref_from = (ref_to - ms_to_ticks(REF_MS)).max(prev_end + ms_to_ticks(200.0));
        let ev = self.gather(ref_to, end, start - ms_to_ticks(100.0), ref_from, caught_up);

        let id = self.incidents.len() + 1;
        let mut cpus: Vec<u16> = kernel.iter().filter_map(|s| s.cpu).collect();
        cpus.sort_unstable();
        cpus.dedup();
        // "4,5" as always; on a hybrid CPU "4 (P-core), 5 (E-core)", which needs the wider gap.
        let sep = if self.topo.hybrid() { ", " } else { "," };
        let cpu_list = cpus.iter().map(|c| self.cpu_label(*c)).collect::<Vec<_>>().join(sep);

        let ncpu = self.ncpu();
        let class = if kernel.is_empty() {
            IncidentClass::Starvation
        } else if ncpu > 0 && cpus.len() >= freeze_cpu_floor(ncpu) && worst >= ms_to_ticks(FREEZE_MS) {
            IncidentClass::Freeze
        } else {
            IncidentClass::Kernel
        };

        say!("");
        match class {
            IncidentClass::Freeze => say!(
                "[{}] FREEZE #{id}  the whole PC stopped  {}  ({} of {ncpu} CPUs held at once)",
                clock().fmt(start),
                fmt_dur(worst),
                cpus.len()
            ),
            IncidentClass::Kernel => {
                say!("[{}] STALL #{id}  kernel-level (DPC/ISR/firmware)  {}  on CPU {cpu_list}", clock().fmt(start), fmt_dur(worst))
            }
            IncidentClass::Starvation => say!(
                "[{}] STALL #{id}  CPU starvation (normal-priority thread couldn't get a core)  {}",
                clock().fmt(start),
                fmt_dur(worst)
            ),
        }
        if !kernel.is_empty() && !sched.is_empty() {
            let sched_worst = sched.iter().map(|s| s.end - s.start).max().unwrap();
            say!(
                "    The normal-priority probe in this tool's other process was late by {} at the same instant: the same",
                fmt_dur(sched_worst)
            );
            say!("    event seen twice, counted once.");
        }

        // What the scheduler did to the measuring threads themselves. This is the one thing that
        // separates "nothing woke them" (a timer/clock/platform problem) from "they were woken
        // and not given a processor" (a scheduler or platform one), which the field logs in
        // issue #15 could not tell apart.
        let probes = self.judge_probes(&all, &ev);
        self.print_probes(&probes, class);

        let mut freeze = None;
        let mut on_cpu = None;
        let mut busy_core = None;
        let culprit = match class {
            IncidentClass::Freeze => {
                let (culprit, mut facts) = self.verdict_freeze(kernel, &ev, ncpu, start, end);
                facts.probes = probes.clone();
                freeze = Some(facts);
                culprit
            }
            IncidentClass::Kernel => {
                let (culprit, who) = self.verdict_kernel(kernel, &ev, &probes);
                on_cpu = who;
                culprit
            }
            IncidentClass::Starvation => {
                let (culprit, core) = self.verdict_sched(&ev, start, end, &probes);
                busy_core = core;
                culprit
            }
        };
        self.print_io_context(&ev);
        self.print_context(start, end);
        if let Some(w) = self.gpu_window(start - ms_to_ticks(100.0), end) {
            self.print_gpu(&w);
        }
        if !ev.etw_caught_up {
            say!("    note: kernel trace data for this window was incomplete (trace lagging or events lost)");
        }
        // A normal-priority thread that could not get a processor is exactly the position an app
        // or a game is in, so the same window is worth asking who else was kept waiting.
        if class == IncidentClass::Starvation {
            self.collect_waits(start - ms_to_ticks(100.0), end);
        }
        self.incidents.push(IncidentSummary { class, start, dur: worst, culprit, marked: false, cpus, on_cpu, freeze, busy_core });
    }

    /// One `ProbeWindow` per late wake-up in this cluster, and the outcome of each.
    ///
    /// A stall record says which processor was late and when; the probe thread on that processor
    /// is looked up in the list the probes registered themselves in. A stall whose thread is not
    /// known (the scheduler probe before it has registered, a processor the child never started a
    /// probe for) is left out rather than guessed at.
    fn judge_probes(&self, stalls: &[Stall], ev: &Evidence) -> ProbeVerdict {
        if !ev.switches_cover {
            return ProbeVerdict::default();
        }
        let threads = self.probe_tids.all();
        let mut windows = Vec::new();
        for s in stalls {
            let found = match s.cpu {
                Some(cpu) => threads.iter().find(|t| t.cpu == Some(cpu)),
                // The unpinned scheduler probe is the only probe thread with no processor.
                None => threads.iter().find(|t| t.cpu.is_none()),
            };
            if let Some(t) = found {
                windows.push(ProbeWindow { tid: t.tid, cpu: t.cpu, start: s.start, end: s.end });
            }
        }
        switches::judge_probes(&ev.switches, &ev.readies, &windows)
    }

    /// The three-way answer, in the event log, in plain words.
    fn print_probes(&mut self, v: &ProbeVerdict, class: IncidentClass) {
        if v.empty() {
            return;
        }
        let n = v.judged();
        // "1 of the 8 measuring threads was" / "7 of the 8 measuring threads were".
        let threads = |k: usize| format!("{k} of the {n} measuring thread{} {}", plural(n as u64), if k == 1 { "was" } else { "were" });
        if v.late > 0 {
            say!(
                "    SCHEDULER: {} never made runnable until {} into it: nothing woke {}.",
                threads(v.late),
                fmt_dur(v.worst_delay),
                if v.late == 1 { "it" } else { "them" }
            );
            say!("               The timer that wakes them fired late, which points at the clock, the firmware or power management,");
            say!("               below the scheduler, unless the verdict below shows interrupt-level work holding the timer's processor.");
        }
        if v.queued > 0 {
            let idle = v.on_idle_cpu;
            say!("    SCHEDULER: {} made runnable on time and then did not get a processor.", threads(v.queued));
            // Facts only. What kept the thread off its processor is the VERDICT's business: a DPC
            // or ISR runs on top of whatever thread was there (the idle thread included) and no
            // context switch records it, so this block alone cannot tell a driver from the platform.
            if idle > 0 {
                say!("               On {idle} of those no other thread took the processor: its record shows only the idle thread.");
            }
            for (tid, prio, held) in v.instead.iter().take(3) {
                let who = self.procs.label(self.pid_of(*tid), *tid);
                // The number stays; the band is added only where the documented ranges make it
                // unambiguous (see `switches::priority_band`).
                let band = switches::priority_band(*prio).map(|b| format!(": {b}")).unwrap_or_default();
                say!("               Thread on that processor meanwhile: {who} (priority {prio}{band}) for {}", fmt_dur(*held));
            }
            if class != IncidentClass::Starvation {
                say!("               No thread outranks a measuring thread, so what kept it off is interrupt-level work (a DPC or");
                say!("               ISR, which no thread switch records) or the platform. The verdict below says which, if it can.");
            }
        }
        if v.blocked > 0 {
            let reasons: Vec<&str> = v.reasons.iter().filter_map(|r| switches::wait_reason_name(*r)).collect();
            let why = if reasons.is_empty() { String::new() } else { format!(" ({})", reasons.join("; ")) };
            say!(
                "    SCHEDULER: {} woken on time, ran, and then had to wait again{why}, so this is that wait, not a held processor.",
                threads(v.blocked)
            );
        }
        if class == IncidentClass::Freeze && v.late == n && n > 0 {
            say!("               No measuring thread anywhere on this PC was woken: whatever stopped is common to every processor.");
        }
    }

    /// The switch and wake-up records covering `[from, to]`, or `None` when the rings cannot
    /// honestly cover that window (not being recorded, or the count cap threw records away).
    /// Same test as `gather`, and the same 250 ms lead for "who was already on this processor".
    fn gather_switches(&self, from: i64, to: i64) -> Option<(Vec<SwitchRec>, Vec<ReadyRec>)> {
        if !self.shared.switches {
            return None;
        }
        let inner = self.shared.inner.lock().unwrap();
        let start = from - ms_to_ticks(250.0);
        if !inner.switches_cover(start) {
            return None;
        }
        Some(inner.switch_window(start, to))
    }

    fn pid_of(&self, tid: u32) -> u32 {
        self.shared.inner.lock().unwrap().tid_pid.get(&tid).copied().unwrap_or(PID_UNKNOWN)
    }

    /// Who else was kept waiting in this window, merged into `program_waits` by program name.
    ///
    /// Only waits long enough for a person to notice, and only for programs: the idle thread and
    /// this tool's own two processes are dropped. Nothing here is a culprit.
    /// The window is its own, not the one the DPC/sample evidence was gathered over: a flagged
    /// moment reaches three seconds back and a little past the mark, while the evidence around it
    /// is cut to the worst interruption inside that. Both are right for what they answer.
    fn collect_waits(&mut self, from: i64, to: i64) {
        let Some((sw, rd)) = self.gather_switches(from, to) else { return };
        self.wait_moments += 1;
        let rows = switches::waits(&sw, &rd, from, to);
        let ready_floor = ms_to_ticks(switches::FELT_READY_MS);
        let blocked_floor = ms_to_ticks(switches::FELT_BLOCKED_MS);
        let blocked_ceiling = ms_to_ticks(switches::MAX_BLOCKED_MS);
        let own = std::env::current_exe().ok().and_then(|p| p.file_name().map(|f| f.to_string_lossy().to_lowercase()));
        // Every program named in one window is counted once, however many of its threads waited.
        let mut seen: HashSet<String> = HashSet::new();
        for w in rows {
            let ready = if w.ready >= ready_floor { w.ready } else { 0 };
            let long_enough = w.blocked >= blocked_floor && w.blocked <= blocked_ceiling;
            let blocked = if long_enough && !switches::voluntary_wait(w.blocked_reason) { w.blocked } else { 0 };
            if ready == 0 && blocked == 0 {
                continue;
            }
            let pid = self.pid_of(w.tid);
            if pid == 0 || pid == PID_UNKNOWN {
                continue; // the idle thread, or a thread that ended before it could be named
            }
            let label = self.procs.label(pid, w.tid);
            let name = process_name(&label);
            if own.as_ref().is_some_and(|own| name.to_lowercase().starts_with(own)) {
                continue; // the tool measuring itself
            }
            let instead =
                if ready > 0 { switches::held_by(&sw, w.ready_cpu, w.ready_from, w.ready_to, w.tid) } else { RanInstead::Unknown };
            let (instead_name, instead_idle) = match instead {
                RanInstead::Idle => (None, true),
                RanInstead::Thread { tid, .. } => {
                    let pid = self.pid_of(tid);
                    ((pid != PID_UNKNOWN).then(|| process_name(&self.procs.label(pid, tid))), false)
                }
                RanInstead::Unknown => (None, false),
            };
            let woken_by = w.woken_by.and_then(|tid| {
                let pid = self.pid_of(tid);
                (pid != PID_UNKNOWN && pid != 0).then(|| process_name(&self.procs.label(pid, tid)))
            });
            let fresh = seen.insert(name.clone());
            let e = self.program_waits.entry(name).or_default();
            if fresh {
                e.moments += 1;
            }
            if ready > e.ready {
                e.ready = ready;
                e.instead = instead_name;
                e.instead_idle = instead_idle;
            }
            if blocked > e.blocked {
                e.blocked = blocked;
                e.blocked_reason = w.blocked_reason;
                e.woken_by = woken_by;
            }
        }
    }

    /// "4" on an ordinary PC; "4 (E-core)" where the cores are not all the same. Nothing is
    /// added on a uniform CPU, where a core number says all there is to say.
    fn cpu_label(&self, cpu: u16) -> String {
        match self.topo.core_type(cpu) {
            Some(what) => format!("{cpu} ({what})"),
            None => cpu.to_string(),
        }
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

        // The whole flagged window, whatever the CPUs did in it: "the picture stopped updating"
        // is exactly the kind of hitch that leaves no trace on the processor side.
        if let Some(w) = self.gpu_window(from, to) {
            self.print_gpu(&w);
            self.note_gpu_mark(&w);
        }

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
            let ev = self.gather(from, to, from, from, caught_up);
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
            self.cpu_label(worst.cpu.unwrap_or(0)),
            fmt_dur(dur),
            clock().fmt(worst.start),
            offset_s.abs(),
            if offset_s >= 0.0 { "before" } else { "after" }
        );
        let lead = start - ms_to_ticks(0.5);
        let ev = self.gather(lead, end, from, lead - ms_to_ticks(REF_MS), caught_up);
        let probes = self.judge_probes(&cluster, &ev);
        self.print_probes(&probes, IncidentClass::Kernel);
        let (culprit, on_cpu) = self.verdict_kernel(&cluster, &ev, &probes);
        self.print_io_context(&ev);
        self.print_context(start, end);
        // The whole window the person flagged, not just the worst interruption in it: a hitch
        // someone feels is usually a program waiting, not a processor being held.
        self.collect_waits(from, to);
        self.print_waits();
        let mut cpus: Vec<u16> = cluster.iter().filter_map(|s| s.cpu).collect();
        cpus.sort_unstable();
        cpus.dedup();
        self.incidents.push(IncidentSummary {
            class: IncidentClass::Kernel,
            start,
            dur,
            culprit,
            marked: true,
            cpus,
            on_cpu,
            freeze: None,
            busy_core: None,
        });
    }

    /// Throttling and memory pressure at the time of an incident, as one "Context:" line, and
    /// only when either was present. Facts: coinciding is not causing.
    fn print_context(&self, start: i64, end: i64) {
        let throttled = self.clock.as_ref().and_then(|c| {
            let samples = c.lock().unwrap_or_else(|e| e.into_inner());
            crate::cpuclock::throttled_clause(&samples, start, end)
        });
        if let Some(line) = context_line(throttled, (self.mem_load)()) {
            say!("{line}");
        }
    }

    /// The three worst programs kept waiting, for the event-log entry of a flagged moment.
    fn print_waits(&mut self) {
        let mut rows: Vec<(String, ProgramWait)> = self.program_waits.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        rows.sort_by_key(|(name, w)| (std::cmp::Reverse(w.ready.max(w.blocked)), name.clone()));
        for (name, w) in rows.iter().take(3) {
            if w.ready > 0 {
                let instead = if w.instead_idle {
                    " while the processor had nothing else to do".to_string()
                } else {
                    w.instead.as_ref().map(|i| format!(" while {i} held the processor")).unwrap_or_default()
                };
                say!("    Kept waiting: {name} was ready to run but got no processor for {}{instead}", fmt_dur(w.ready));
            }
            if w.blocked > 0 {
                let why = switches::wait_reason_name(w.blocked_reason).map(|r| format!(" ({r})")).unwrap_or_default();
                let by = w.woken_by.as_ref().map(|b| format!(", woken by {b}")).unwrap_or_default();
                say!("    Kept waiting: {name} was blocked for {}{why}{by}", fmt_dur(w.blocked));
            }
        }
    }

    /// Records the graphics-kernel trace to read alongside the kernel one.
    pub fn set_gpu_trace(&mut self, trace: Arc<GpuTrace>) {
        self.gputrace = Some(trace);
    }

    /// The CPU clock samples, so an incident can say whether the processor was throttled then.
    pub fn set_cpu_clock(&mut self, samples: crate::cpuclock::Samples) {
        self.clock = Some(samples);
    }

    /// Records the storage port driver's trace to read alongside the kernel one.
    pub fn set_storage_trace(&mut self, trace: Arc<StorTrace>) {
        self.storport = Some(trace);
    }

    /// A disk's address on its storage port, read once per disk with a zero-access handle.
    pub(crate) fn scsi_addr(&mut self, disk: u32) -> Option<ScsiAddr> {
        *self.scsi_addrs.entry(disk).or_insert_with(|| crate::disks::scsi_address(disk))
    }

    /// Where one slow request's time went, from the storage port driver's trace, or `None` when
    /// there is no such trace. The totals per disk are kept as it goes.
    fn storage_split(&mut self, slow: &IoRec) -> Option<Outcome> {
        let trace = self.storport.clone()?;
        let addr = self.scsi_addr(slow.disk);
        let (start, end) = (slow.end - slow.dur, slow.end);
        let slop = ms_to_ticks(storsplit::MATCH_SLOP_MS);
        let window = {
            let inner = trace.inner.lock().unwrap_or_else(|e| e.into_inner());
            // Not reaching back to the start, or not yet past the end: say nothing either way.
            (inner.covers(start - slop) && inner.caught_up(end + slop, qpc())).then(|| inner.window(start - slop, end + slop))
        };
        let outcome = match window {
            Some(w) => storsplit::correlate(slow, &w, addr),
            None => Outcome::NotCovered,
        };
        self.disk_split.entry(slow.disk).or_default().add(&outcome);
        Some(outcome)
    }

    /// What the graphics-kernel trace saw in one window, or `None` when there is no such trace.
    fn gpu_window(&self, from: i64, to: i64) -> Option<GpuWindow> {
        let trace = self.gputrace.as_ref()?;
        let w = trace.inner.lock().unwrap_or_else(|e| e.into_inner()).window(from, to);
        Some(w)
    }

    /// One compact line of GPU facts for the event log. Facts only: whether any of this had
    /// anything to do with the hitch is the verdict's and the findings' business, and "at the
    /// same moment" is as far as either may go without a mechanism.
    fn print_gpu(&mut self, w: &GpuWindow) {
        let mut facts: Vec<String> = Vec::new();
        if let Some(c) = w.display.filter(|c| c.stalled()) {
            facts.push(format!("the displays stopped refreshing for {:.0} ms (normally every {:.1} ms)", c.worst_ms, c.typical_ms));
        }
        if let Some((pid, c)) = w.program.as_ref().filter(|(_, c)| c.stalled()) {
            let who = process_name(&self.procs.label(*pid, 0));
            facts.push(format!("{who} put up no new frame for {:.0} ms (normally every {:.1} ms)", c.worst_ms, c.typical_ms));
        }
        if w.trim_bytes > 0 {
            facts.push(format!("video memory was over budget; Windows asked for {:.0} MB to be freed", w.trim_bytes as f64 / 1e6));
        }
        if w.residency_ops > 0 && w.residency_ms >= 1.0 {
            facts.push(format!("{} video memory transfer(s) took {:.0} ms in total", w.residency_ops, w.residency_ms));
        }
        if !facts.is_empty() {
            say!("    GPU: {}.", facts.join("; "));
        }
    }

    /// Keeps what the GPU trace saw at a flagged moment, for the summary to count later.
    fn note_gpu_mark(&mut self, w: &GpuWindow) {
        let program = w.program.as_ref().map(|(pid, c)| (process_name(&self.procs.label(*pid, 0)), c.worst_ms, c.stalled()));
        self.gpu_marks.push(MarkGpu {
            covered: w.refresh_covered || w.present_covered,
            display_gap_ms: w.display.map_or(0.0, |c| c.worst_ms),
            display_stalled: w.display.is_some_and(|c| c.stalled()),
            program,
            trim_bytes: w.trim_bytes,
            residency_ms: w.residency_ms,
        });
    }

    /// The one place a file path turns into report text: NT device path -> drive letter, then
    /// the privacy rule in `files`. `None` when the trace never named that file; the report then
    /// says nothing rather than printing "(file name not available)" hundreds of times.
    ///
    /// Names for files already open when the trace started only arrive with the rundown at the
    /// end of the session, so during the run this resolves the files opened since it began. By
    /// the time the summary is built, the rundown has been consumed and nearly everything
    /// resolves.
    pub(crate) fn file_label(&self, key: u64) -> Option<String> {
        if key == 0 {
            return None;
        }
        let inner = self.shared.inner.lock().unwrap();
        let raw = inner.file_names.get(key)?.to_string();
        drop(inner);
        let shown = files::public_path(&self.dos.to_dos(&raw));
        (!shown.is_empty()).then_some(shown)
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

    /// Everything both kernel-side verdicts rest on, worked out once.
    fn look(&mut self, stalls: &[Stall], ev: &Evidence) -> Look {
        let mut by_routine: HashMap<(u64, u8), (i64, i64, u32)> = HashMap::new(); // overlap, longest, count
                                                                                  // Per (module, CPU): the spans that module's own DPC/ISR code held, so coverage can be
                                                                                  // judged per processor instead of being diluted across a cluster.
        let mut per_module: HashMap<(String, u16), Vec<(i64, i64)>> = HashMap::new();
        let mut per_cpu = Vec::new();
        let (mut seen_samples, mut expected_samples) = (0f64, 0f64);
        let mut window_samples: Vec<&(SampleRec, u32)> = Vec::new();
        for s in stalls {
            let cpu = s.cpu.unwrap_or(0);
            let len = (s.end - s.start).max(1);
            let mut spans: Vec<(i64, i64)> = Vec::new();
            let mut dpc_starts: Vec<i64> = Vec::new();
            for e in ev.execs.iter().filter(|e| e.cpu == cpu) {
                let overlap = e.end.min(s.end) - e.start.max(s.start);
                if overlap > 0 {
                    spans.push((e.start.max(s.start), e.end.min(s.end)));
                    per_module.entry((self.modules.name(e.routine), cpu)).or_default().push((e.start.max(s.start), e.end.min(s.end)));
                    let r = by_routine.entry((e.routine, e.kind)).or_default();
                    r.0 += overlap;
                    r.1 = r.1.max(e.end - e.start);
                    r.2 += 1;
                    if e.kind != KIND_ISR {
                        dpc_starts.push(e.start.max(s.start));
                    }
                }
            }
            // A DPC cannot run on a processor that is already at DISPATCH_LEVEL or above, so
            // DPCs spread right through the stall prove this CPU was never held.
            let covered_slices = intr::slices_covered(s.start, s.end, dpc_starts.iter().copied());
            let kept = intr::dpcs_kept_running(covered_slices, dpc_starts.len());
            per_cpu.push(CpuStall { coverage: union_len(&mut spans) as f64 / len as f64, held: !kept });

            let in_window: Vec<_> = ev.samples.iter().filter(|(x, _)| x.cpu == cpu && x.ts >= s.start && x.ts <= s.end).collect();
            let rate = *ev.baseline.get(&cpu).unwrap_or(&0) as f64 / BASELINE_MS;
            seen_samples += in_window.len() as f64;
            expected_samples += rate * ticks_to_ms(len);
            window_samples.extend(in_window);
        }

        // A driver is blamed when ITS code covered the stall on at least half the stalled CPUs.
        // Summing coverage over a cluster (what this used to do) gave a driver saturating one
        // core 1/N of an N-core event, so no whole-machine stall could ever reach the bar.
        let need = stalls.len().div_ceil(2);
        let mut by_module: HashMap<String, (usize, i64)> = HashMap::new();
        for ((module, cpu), spans) in per_module.iter_mut() {
            let Some(s) = stalls.iter().find(|s| s.cpu.unwrap_or(0) == *cpu) else { continue };
            let covered = union_len(spans);
            let e = by_module.entry(module.clone()).or_default();
            e.1 += covered;
            if covered as f64 / (s.end - s.start).max(1) as f64 >= COVER_RULE {
                e.0 += 1;
            }
        }
        let blame = by_module
            .iter()
            .filter(|(_, (cpus, _))| *cpus >= need && *cpus > 0)
            .max_by_key(|(_, (cpus, total))| (*cpus, *total))
            .map(|(m, (cpus, _))| (m.clone(), *cpus));

        let mut routines: Vec<_> = by_routine.into_iter().collect();
        routines.sort_by_key(|(_, v)| std::cmp::Reverse(v.0));
        let held = per_cpu.iter().filter(|c| c.held).count();
        let held_share = held as f64 / per_cpu.len().max(1) as f64;
        let best_coverage = per_cpu.iter().map(|c| c.coverage).fold(0.0, f64::max);
        let samples = window_samples.len();
        let (on_cpu_procs, on_cpu_mods) = self.sample_breakdown(&window_samples);
        Look { routines, per_cpu, blame, best_coverage, held_share, seen_samples, expected_samples, on_cpu_procs, on_cpu_mods, samples }
    }

    /// "(on 6 of 8 CPUs)" / "" for a single-CPU stall, and "based on only 6 samples" when thin.
    fn thin(samples: usize) -> String {
        if samples < THIN_SAMPLES {
            format!(" (based on only {samples} CPU sample{})", plural(samples as u64))
        } else {
            String::new()
        }
    }

    /// Returns the culprit, and the program that held the CPU through the stall when one clearly
    /// did. See `IncidentSummary::on_cpu`.
    ///
    /// A kernel-level stall gets the same three checks a whole-PC freeze always had (issue #19):
    /// whether a slow disk request or the measuring thread's own hard page fault covered it
    /// (`diskwait`), which interrupt sources kept arriving and which went silent, and whether the
    /// timer DPCs that wake sleeping threads kept their usual rate (`continuity`). They add facts
    /// to the event log. The verdict only changes where one of them changes the conclusion: the
    /// measuring thread was itself waiting on a page fault, or no processor was held AND the timer
    /// DPCs stopped.
    fn verdict_kernel(&mut self, stalls: &[Stall], ev: &Evidence, probes: &ProbeVerdict) -> (String, Option<String>) {
        let look = self.look(stalls, ev);
        let cpus = look.per_cpu.len();
        let (start, end) = span_of(stalls);
        // Ordinary DPCs running right through the stall on most of the stalled CPUs means no CPU
        // was held at raised IRQL. Nothing below may then blame what a sample happened to land in.
        let could_be_held = look.held_share >= 0.5;
        let enough_samples = look.samples >= MIN_SAMPLES;
        let (silent, continued, timer) = self.continuity(ev, start, end);
        let own = self.probe_paging(stalls, ev);
        // Only requests slow enough to be findings of their own: a 3 ms read that happens to overlap
        // a 5 ms stall is ordinary traffic, not a coincidence worth a line.
        let slow_ios: Vec<IoRec> = ev.ios.iter().filter(|i| i.dur >= self.shared.io_warn).copied().collect();
        let wait = diskwait::explain(start, end, &slow_ios, &own.faults, own.pid);
        // The measuring thread was not runnable at all: it was waiting for its own code or data to
        // come back from disk. On at least half the stalled CPUs, like the driver rule in `look`.
        let paging = own.cpus > 0 && own.cpus >= stalls.len().div_ceil(2);

        let culprit = if paging {
            let where_ = if cpus > 1 { format!(" on {} of the {cpus} stalled CPUs", own.cpus) } else { String::new() };
            say!("    VERDICT: the measuring thread itself was waiting for its own memory to be read back from disk (a hard page");
            say!("             fault) for most of this{where_}, so nothing held the processor. That is paging, and any");
            say!("             program in the same position waits the same way.");
            "waiting on paging".to_string()
        } else if let Some((module, on)) = &look.blame {
            let what = self.modules.describe_short(module);
            let where_ = if cpus > 1 { format!(" on {on} of the {cpus} stalled CPUs") } else { String::new() };
            say!("    VERDICT: {module} [{what}] kept the CPU in DPC/ISR code for most of the stall{where_}");
            format!("driver {module}")
        } else if self.profile && could_be_held && look.expected_samples >= 3.0 && look.seen_samples < look.expected_samples * 0.3 {
            say!(
                "    VERDICT: the CPU went dark: only {:.0} of ~{:.0} expected profiler interrupts arrived, no DPC/ISR explains it,",
                look.seen_samples,
                look.expected_samples
            );
            say!("             and ordinary DPCs stopped too -> firmware SMI (BIOS, USB legacy, thermal/EC), a hypervisor, or a");
            say!("             driver running with interrupts disabled. Think BIOS update/settings and failing hardware.");
            "CPU went dark (firmware SMI / hypervisor / interrupts off)".to_string()
        } else if let Some((m, share)) = look.on_cpu_mods.first().filter(|(_, s)| *s >= SHARE_RULE && could_be_held && enough_samples) {
            let what = self.modules.describe_short(m);
            say!(
                "    VERDICT: {m} [{what}] was executing for {:.0}% of the stall{}, and no DPC ran on the stalled CPU(s) while it",
                share * 100.0,
                Self::thin(look.samples)
            );
            say!("             did, so it was at raised IRQL (a spinlock or a long driver call), which blocks every thread there");
            format!("driver {m}")
        } else if let Some((p, share)) =
            look.on_cpu_procs.first().filter(|(p, s)| *s >= SHARE_RULE && !p.starts_with("Idle") && could_be_held && enough_samples)
        {
            say!(
                "    VERDICT: {p} was on the CPU for {:.0}% of the stall{}. Nothing can outrank the probe thread and no DPC ran,",
                share * 100.0,
                Self::thin(look.samples)
            );
            say!("             so it was inside kernel/driver code at raised IRQL on this process's behalf (modules below)");
            format!("process {p}")
        } else if !could_be_held {
            say!("    VERDICT: no CPU was held. Ordinary DPCs kept executing on the stalled CPU(s) right through this, which cannot");
            say!("             happen at raised IRQL, so the measuring thread was simply not woken: timer delivery or scheduling.");
            say!("             Whatever the CPU samples landed in was interrupted too, and is not the cause.");
            // The one check that narrows "timer delivery or scheduling" down: the clock's own
            // DPCs stopping everywhere. Kept going proves nothing about this thread's timer, so
            // that case leaves the verdict alone and is only listed with the facts below.
            if timer == Some(Flow::Silent) {
                say!("             Timer DPCs (how the clock wakes sleeping threads) stopped across the PC during it, which points at");
                say!("             timer delivery rather than scheduling.");
            }
            // The scheduler trace says which of the two it was, when it can.
            not_woken_culprit(probes, "not woken (timers or scheduling)")
        } else {
            // "covered at most 99%" next to "no clear culprit" reads as a contradiction unless it
            // says the rest: one processor was covered and most of the stalled ones were not.
            let covered = look.per_cpu.iter().filter(|c| c.coverage >= COVER_RULE).count();
            if covered > 0 && look.per_cpu.len() > 1 {
                say!(
                    "    VERDICT: no clear culprit in the trace (DPC/ISR code explains {covered} of the {} stalled CPUs, up to {:.0}% of \
                     the stall there, and not the rest)",
                    look.per_cpu.len(),
                    look.best_coverage * 100.0
                );
            } else {
                say!(
                    "    VERDICT: no clear culprit in the trace (DPC/ISR covered at most {:.0}% of the stall)",
                    look.best_coverage * 100.0
                );
            }
            "unexplained".to_string()
        };

        for line in flow_lines("stall", &silent, &continued, timer) {
            say!("{line}");
        }
        // The page fault is already the verdict; saying it again as a coincidence adds nothing.
        if let Some(w) = wait.filter(|w| !(paging && w.disk.is_none())) {
            let disk = w.disk.map(|d| self.disks.get(d).short());
            for line in coincided_lines("stall", false, &w, disk.as_deref(), start) {
                say!("{line}");
            }
        }

        // Who the CPU was actually running, whatever the verdict was. "Idle" is the processor
        // having nothing to do, and the tool's own process is already filtered out upstream.
        let on_cpu = look
            .on_cpu_procs
            .first()
            .filter(|(p, s)| *s >= ON_BEHALF_SHARE && !p.starts_with("Idle") && look.samples >= MIN_SAMPLES)
            .map(|(p, _)| p.clone());

        self.print_routines(&look);
        self.print_on_cpu(&look.on_cpu_procs, &look.on_cpu_mods);
        (culprit, on_cpu)
    }

    /// Hard page faults taken by the measuring threads of the stalled CPUs, and on how many of
    /// those CPUs such a fault covered at least half the stall (`diskwait`'s own bar).
    fn probe_paging(&self, stalls: &[Stall], ev: &Evidence) -> ProbePaging {
        let threads = self.probe_tids.all();
        let (mut faults, mut cpus) = (Vec::new(), 0);
        for s in stalls {
            let Some(t) = s.cpu.and_then(|c| threads.iter().find(|t| t.cpu == Some(c))) else { continue };
            let mine: Vec<FaultRec> = ev.faults.iter().filter(|f| f.tid == t.tid).copied().collect();
            let mut spans: Vec<(i64, i64)> =
                mine.iter().map(|f| (f.start.max(s.start), f.end.min(s.end))).filter(|(from, to)| to > from).collect();
            if union_len(&mut spans) as f64 >= (s.end - s.start).max(1) as f64 * PAGING_COVER {
                cpus += 1;
            }
            faults.extend(mine);
        }
        // Every fault here is a measuring thread's, so their process is the probes' own.
        let pid = faults.first().map_or(0, |f| f.pid);
        ProbePaging { faults, pid, cpus }
    }

    /// The whole machine stopped. Whatever the CPU samples landed in was stopped with it, so
    /// nothing here may name a program or a module from a sample: they are bystanders.
    fn verdict_freeze(&mut self, stalls: &[Stall], ev: &Evidence, ncpu: usize, start: i64, end: i64) -> (String, FreezeFacts) {
        let look = self.look(stalls, ev);
        let cpus = look.per_cpu.len();
        let dur = fmt_dur(end - start);
        say!("    VERDICT: the whole PC stopped. {cpus} of this PC's {ncpu} processors were held for {dur} at the same instant,");
        say!("             so no program or driver that the CPU samples landed in can be the cause: they were stopped too.");

        let idle = look.on_cpu_procs.iter().find(|(p, _)| p == "Idle").map(|(_, s)| *s).unwrap_or(0.0);
        let on_cpu: Vec<String> = look.on_cpu_procs.iter().filter(|(p, _)| p != "Idle").take(3).map(|(p, _)| p.clone()).collect();

        let mut facts = FreezeFacts {
            cpus,
            ncpu,
            idle_share: idle,
            samples: look.samples,
            on_cpu,
            dpcs_kept_running: look.held_share < 0.5,
            holding: look.blame.clone(),
            ..FreezeFacts::default()
        };

        if let Some((module, on)) = &look.blame {
            let what = self.modules.describe_short(module);
            say!("             {module} [{what}] did hold {on} of the {cpus} CPUs in its own DPC/ISR code for most of it.");
        }
        if facts.dpcs_kept_running {
            say!("             Ordinary DPCs kept executing throughout, so no CPU was held at raised IRQL: the processors were");
            say!("             running, nothing was waking threads.");
        }

        // Which interrupt sources stopped and which carried on. This is the closest a CPU-side
        // trace gets to watching a bus or a controller stall.
        let (silent, continued, timer) = self.continuity(ev, start, end);
        for line in flow_lines("freeze", &silent, &continued, timer) {
            say!("{line}");
        }
        facts.silent = silent;
        facts.continued = continued;
        facts.timer = timer;

        // What coincided, and which way round. A request that only started once the machine had
        // already stopped is a victim of the freeze, not a lead.
        // Any slow request that sits inside the freeze is explained by it, whichever one turns out
        // to be the most informative below; it must not also become "this drive responds slowly".
        self.mark_victims(&ev.ios, start, end);
        let own = std::process::id();
        if let Some(w) = diskwait::explain(start, end, &ev.ios, &ev.faults, own) {
            let woke = w.disk.is_some_and(|d| self.disk_why.get(&d).is_some_and(|why| why.count(Cause::WokeUp) > 0));
            let disk = w.disk.map(|d| self.disks.get(d).short());
            for line in coincided_lines("freeze", true, &w, disk.as_deref(), start) {
                say!("{line}");
            }
            facts.coincided = Some(Coincided { disk: w.disk, role: w.role, waited: w.waited, woke });
        }

        self.print_routines(&look);
        self.print_on_cpu(&look.on_cpu_procs, &look.on_cpu_mods);
        ("whole-PC freeze".to_string(), facts)
    }

    /// Records every slow request that sits entirely inside this freeze as explained by it.
    fn mark_victims(&mut self, ios: &[IoRec], start: i64, end: i64) {
        let warn = self.shared.io_warn;
        for io in ios.iter().filter(|i| i.dur >= warn) {
            if diskwait::role_of(start, end, io.end - io.dur, io.end) == Role::Victim {
                if let Some(seen) = self.disk_slow.get_mut(&io.disk) {
                    for s in seen.iter_mut().filter(|s| s.end == io.end && s.dur == io.dur) {
                        s.victim = true;
                    }
                }
            }
        }
    }

    /// Per interrupt source: did it keep going, or stop? Only sources that were STEADY before the
    /// stall can say anything, so a driver that naturally fires in bursts raises no alarm.
    #[allow(clippy::type_complexity)]
    fn continuity(&mut self, ev: &Evidence, start: i64, end: i64) -> (Vec<(String, f64)>, Vec<(String, f64)>, Option<Flow>) {
        if ev.ref_seconds <= 0.0 {
            return (Vec::new(), Vec::new(), None);
        }
        let slices = (ev.ref_seconds.round() as u32).max(2);
        let slice_len = ms_to_ticks(ev.ref_seconds * 1000.0 / f64::from(slices));
        let ref_start = ev.ref_execs.iter().map(|e| e.start).min().unwrap_or(start);
        let mut refs: HashMap<String, (u32, HashSet<u32>)> = HashMap::new();
        let mut timer_ref = (0u32, HashSet::new());
        for e in &ev.ref_execs {
            let slot = (((e.start - ref_start).max(0) / slice_len.max(1)) as u32).min(slices - 1);
            let r = refs.entry(self.modules.name(e.routine)).or_default();
            r.0 += 1;
            r.1.insert(slot);
            if e.kind == KIND_TIMER_DPC {
                timer_ref.0 += 1;
                timer_ref.1.insert(slot);
            }
        }
        let mut inside: HashMap<String, u32> = HashMap::new();
        let mut timer_in = 0u32;
        for e in ev.execs.iter().filter(|e| e.start >= start && e.start <= end) {
            *inside.entry(self.modules.name(e.routine)).or_default() += 1;
            if e.kind == KIND_TIMER_DPC {
                timer_in += 1;
            }
        }
        let stall_s = ticks_to_ms(end - start) / 1000.0;
        let (mut silent, mut continued) = (Vec::new(), Vec::new());
        let mut rows: Vec<(String, u32, HashSet<u32>)> = refs.into_iter().map(|(k, (n, s))| (k, n, s)).collect();
        rows.sort_by_key(|(name, n, _)| (std::cmp::Reverse(*n), name.clone()));
        for (name, events, seen) in rows {
            let reference = Reference { events, slices_seen: seen.len() as u32, slices, seconds: ev.ref_seconds };
            let Some((flow, share)) = intr::flow(&reference, inside.get(&name).copied().unwrap_or(0), stall_s) else { continue };
            match flow {
                Flow::Silent => silent.push((name, share)),
                Flow::Continued => continued.push((name, share)),
                Flow::Reduced => {}
            }
        }
        let timer_reference = Reference { events: timer_ref.0, slices_seen: timer_ref.1.len() as u32, slices, seconds: ev.ref_seconds };
        (silent, continued, intr::flow(&timer_reference, timer_in, stall_s).map(|(f, _)| f))
    }

    /// Returns the culprit, and what held the busy core when one or a few cores were busy while
    /// the rest idled (see `pegged_cores`).
    fn verdict_sched(&mut self, ev: &Evidence, start: i64, end: i64, probes: &ProbeVerdict) -> (String, Option<CoreHolder>) {
        let all: Vec<&(SampleRec, u32)> = ev.samples.iter().collect();
        let (procs, mods) = self.sample_breakdown(&all);
        // Idle with interrupt-level time taken out. A DPC or ISR that runs on an idle processor
        // interrupts the idle thread, so the profiler used to count that time as idle (issue #19).
        let loads = core_loads(&ev.samples, &ev.execs);
        let idle = idle_share(&loads);
        let busy: Vec<_> = procs.iter().filter(|(p, _)| p != "Idle").cloned().collect();
        let saturated = idle < 0.25;
        let culprit = if !self.profile || all.is_empty() {
            say!("    VERDICT: all CPUs were busy, but CPU sampling is unavailable so the process can't be named");
            "CPU starvation (unattributed)".to_string()
        } else if saturated {
            let (top, share) = busy.first().cloned().unwrap_or(("?".into(), 0.0));
            say!(
                "    VERDICT: CPUs were saturated ({:.0}% busy). Biggest consumer: {top} with {:.0}% of all CPU time",
                (1.0 - idle) * 100.0,
                share * 100.0
            );
            format!("process {top}")
        } else if let Some(w) = diskwait::explain(start, end, &ev.ios, &ev.faults, std::process::id()) {
            // Idle CPUs and a thread that did not run means it was blocked, not starved. When a
            // disk covers the delay, say so; "a one-off scheduling quirk, ignore it" was wrong.
            match w.disk {
                Some(d) => {
                    say!(
                        "    VERDICT: not a CPU shortage ({:.0}% idle): the thread was blocked on storage. A {} {} request to {}",
                        idle * 100.0,
                        fmt_dur(w.waited),
                        op_name(w.op),
                        self.disks.get(d).short()
                    );
                    say!("             covered this delay. Everything that touches that drive waits with it.");
                    format!("disk {d}")
                }
                None => {
                    say!(
                        "    VERDICT: not a CPU shortage ({:.0}% idle): this tool's own thread waited {} for memory to be read back",
                        idle * 100.0,
                        fmt_dur(w.waited)
                    );
                    say!("             from disk, which is what any program in the same position would do.");
                    "waiting on paging".to_string()
                }
            }
        } else {
            say!(
                "    VERDICT: the CPUs were {:.0}% idle. It is not CPU load, and no disk request or page fault lines up with it.",
                idle * 100.0
            );
            not_woken_culprit(probes, "scheduling delay with idle CPUs")
        };
        // An average over every CPU hides one core pegged on an otherwise idle PC. Said as a fact:
        // nothing in this trace shows whether the waiting thread was limited to that core, so the
        // report does not suggest it was.
        let mut holder = None;
        if self.profile && !saturated {
            if let Some(p) = pegged_cores(&loads) {
                let (line, first) = self.pegged_line(&p, ev);
                say!("{line}");
                holder = Some(first);
            }
        }
        self.print_on_cpu(&busy, &mods);
        (culprit, holder)
    }

    /// "    One core was busy while the others idled: CPU 3 was 97% busy (mostly X); the other 7
    /// were 91% idle.", and what held the first of the busy cores.
    fn pegged_line(&mut self, p: &Pegged, ev: &Evidence) -> (String, CoreHolder) {
        let mut parts = Vec::new();
        let mut first = None;
        for (cpu, busy) in &p.cores {
            let holder = self.core_holder(*cpu, ev);
            let mostly = match &holder {
                CoreHolder::Program(label) => format!(" (mostly {label})"),
                CoreHolder::Driver(module) => format!(" (mostly DPC/ISR code in {module})"),
                CoreHolder::Unnamed => String::new(),
            };
            parts.push(format!("CPU {} was {:.0}% busy{mostly}", self.cpu_label(*cpu), busy * 100.0));
            first.get_or_insert(holder);
        }
        let head = if p.cores.len() == 1 {
            "One core was busy while the others idled".to_string()
        } else {
            format!("{} cores were busy while the others idled", p.cores.len())
        };
        let line = format!("    {head}: {}; the other {} were {:.0}% idle.", parts.join(", "), p.others, p.others_idle * 100.0);
        (line, first.unwrap_or(CoreHolder::Unnamed))
    }

    /// What one core's samples in this window mostly landed in: a driver's DPC/ISR code, a
    /// program, or nothing in particular. Same bar as the verdicts (`SHARE_RULE`).
    fn core_holder(&mut self, cpu: u16, ev: &Evidence) -> CoreHolder {
        let on: Vec<&(SampleRec, u32)> = ev.samples.iter().filter(|(s, _)| s.cpu == cpu).collect();
        let (Some(from), Some(to)) = (on.iter().map(|(s, _)| s.ts).min(), on.iter().map(|(s, _)| s.ts).max()) else {
            return CoreHolder::Unnamed;
        };
        let spans = merged_spans(&ev.execs, cpu);
        let n = on.len() as f64;
        let mut interrupt = 0usize;
        let mut by_thread: HashMap<(u32, u32), usize> = HashMap::new();
        for (s, pid) in &on {
            if in_spans(&spans, s.ts) {
                interrupt += 1;
            } else if s.tid != 0 {
                *by_thread.entry((*pid, if *pid == PID_UNKNOWN { s.tid } else { 0 })).or_default() += 1;
            }
        }
        if interrupt as f64 >= n * SHARE_RULE {
            let mut by_module: HashMap<String, i64> = HashMap::new();
            for e in ev.execs.iter().filter(|e| e.cpu == cpu) {
                let overlap = e.end.min(to) - e.start.max(from);
                if overlap > 0 {
                    *by_module.entry(self.modules.name(e.routine)).or_default() += overlap;
                }
            }
            return by_module
                .into_iter()
                .max_by(|a, b| a.1.cmp(&b.1).then_with(|| b.0.cmp(&a.0)))
                .map_or(CoreHolder::Unnamed, |(m, _)| CoreHolder::Driver(m));
        }
        let mut named: HashMap<String, usize> = HashMap::new();
        for ((pid, tid), k) in by_thread {
            *named.entry(self.procs.label(pid, tid)).or_default() += k;
        }
        let own = own_exe();
        named
            .into_iter()
            .filter(|(label, k)| *k as f64 >= n * SHARE_RULE && !own.as_ref().is_some_and(|o| label.to_lowercase().starts_with(o)))
            .max_by(|a, b| a.1.cmp(&b.1).then_with(|| b.0.cmp(&a.0)))
            .map_or(CoreHolder::Unnamed, |(label, _)| CoreHolder::Program(label))
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

    fn print_routines(&mut self, look: &Look) {
        if look.routines.is_empty() {
            return;
        }
        say!("    DPC/ISR activity on the stalled CPU(s):");
        for ((routine, k), (overlap, longest, count)) in look.routines.iter().take(6) {
            say!(
                "      {:<42} {:<12} x{count:<4} in-stall {:>9}   longest {:>9}",
                self.modules.symbolish(*routine),
                kind_name(*k),
                fmt_dur(*overlap),
                fmt_dur(*longest)
            );
        }
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
            let file = self.file_label(worst.file).map(|f| format!(", on {f}")).unwrap_or_default();
            say!(
                "    Slow disk I/O nearby:    {} slow request(s), worst {} on {} ({}, issued by {}{file})",
                slow_io.len(),
                fmt_dur(worst.dur),
                self.disks.get(worst.disk).short(),
                op_name(worst.op),
                self.procs.label(worst.pid, worst.tid)
            );
        }
    }

    /// One-liners for individually bad events, even when no probe stalled.
    fn report_notables(&mut self, last_call: bool) {
        let mut notables = std::mem::take(&mut self.held_notables);
        let latest = {
            let mut inner = self.shared.inner.lock().unwrap();
            notables.append(&mut inner.notable);
            inner.latest_ts
        };
        // A slow request is examined only once the trace has reached far enough past its end for
        // the wake-ups it caused to be in the rings; see `diskstuck::LOOK_AFTER_MS`. Held for at
        // most a few seconds, like a stall, and never at the end of the run. The storage port
        // driver's trace is a separate session with its own buffers, so it is waited for too
        // (see `StorInner::caught_up`), light mode included.
        if !last_call {
            let (need, give_up, now) = (ms_to_ticks(diskstuck::LOOK_AFTER_MS + 50.0), ms_to_ticks(4000.0), qpc());
            let stor_need = ms_to_ticks(storsplit::MATCH_SLOP_MS);
            let stor = self.storport.as_ref().map(|t| t.inner.lock().unwrap_or_else(|e| e.into_inner()));
            let switches = self.shared.switches;
            let waiting = |i: &IoRec| {
                let kernel = switches && latest < i.end + need;
                let storage = stor.as_ref().is_some_and(|s| !s.caught_up(i.end + stor_need, now));
                (kernel || storage) && now - i.end < give_up
            };
            if let Some(at) = notables.iter().position(|n| matches!(n, Notable::SlowIo(i) if waiting(i))) {
                self.held_notables = notables.split_off(at);
            }
        }
        for n in notables {
            self.notable_total += 1;
            // Every slow request is explained, including the ones the log below leaves out.
            let io_why = if let Notable::SlowIo(i) = &n { Some(self.explain_io(i)) } else { None };
            let why = io_why.as_ref().map(|w| w.why.clone()).unwrap_or_default();
            if let Notable::LongExec(e) = &n {
                let times = self.long_exec_times.entry(self.modules.name(e.routine)).or_default();
                if times.len() < 5000 {
                    times.push(e.start);
                }
            }
            let now = qpc();
            // The file this event touched, if the trace has named it by now.
            let file = match &n {
                Notable::SlowFault(f) => self.file_label(f.file),
                Notable::SlowIo(i) => self.file_label(i.file),
                Notable::LongExec(_) => None,
            };
            // One disk, driver or program that keeps doing the same thing gets a few full lines
            // and then a roll-up; see `quiet`. The summary still counts every event. The file is
            // deliberately NOT part of the subject: a download writing a thousand files would
            // then be a thousand subjects and nothing would ever fold. It rides along in the
            // note instead, where the roll-up reports it for the worst event it folded away.
            let named = file.clone().unwrap_or_default();
            let (subject, duration, note) = match &n {
                Notable::LongExec(e) => {
                    (format!("driver {}", self.modules.name(e.routine)), e.end - e.start, kind_name(e.kind).to_string())
                }
                Notable::SlowFault(f) => {
                    let note = if named.is_empty() { String::new() } else { format!("from {named}") };
                    (format!("paging {}", process_name(&self.procs.label(f.pid, f.tid))), f.end - f.start, note)
                }
                Notable::SlowIo(i) => {
                    let note = if named.is_empty() { why.clone() } else { format!("{why}, on {named}") };
                    (format!("disk {}", i.disk), i.dur, note)
                }
            };
            if !self.quiet.offer(&subject, duration, &note, now) {
                self.notable_folded += 1;
                continue;
            }
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
                    self.cpu_label(e.cpu)
                ),
                Notable::SlowFault(f) => say!(
                    "[{}] slow hard page fault {:>9}  {} waited on disk for paged-out memory ({} KB){}",
                    clock().fmt(f.start),
                    fmt_dur(f.end - f.start),
                    self.procs.label(f.pid, f.tid),
                    f.bytes / 1024,
                    file.map(|f| format!("  from {f}")).unwrap_or_default()
                ),
                Notable::SlowIo(i) => {
                    say!(
                        "[{}] slow disk {:<5} {:>9}  {}{}  {} KB  issued by {}  ({why})",
                        clock().fmt(i.end - i.dur),
                        op_name(i.op),
                        fmt_dur(i.dur),
                        self.disks.get(i.disk).short(),
                        file.map(|f| format!("  {f}")).unwrap_or_default(),
                        i.size / 1024,
                        self.procs.label(i.pid, i.tid)
                    );
                    // At most two more lines, and only for requests that get a line of their own:
                    // folded and suppressed ones are counted in the finding instead.
                    for line in io_why.iter().flat_map(|w| [&w.request, &w.stuck]).flatten() {
                        say!("{line}");
                    }
                }
            }
        }
        let every = ms_to_ticks(Quieter::rollup_period_ms());
        let rollups = if last_call { self.quiet.flush() } else { self.quiet.due(qpc(), every) };
        for r in rollups {
            let what = match r.subject.split_once(' ') {
                Some(("disk", n)) => {
                    let disk = n.parse().map(|n| self.disks.get(n).short()).unwrap_or_else(|_| r.subject.clone());
                    format!("{disk}: {} more slow request{}", r.count, plural(r.count as u64))
                }
                Some(("driver", module)) => format!("{module}: {} more long DPC/ISR run{}", r.count, plural(r.count as u64)),
                Some(("paging", program)) => {
                    format!("{program}: {} more slow hard page fault{}", r.count, plural(r.count as u64))
                }
                _ => format!("{}: {} more", r.subject, r.count),
            };
            let note = if r.note.is_empty() { String::new() } else { format!("  ({})", r.note) };
            say!("[{}] ... {what} since {}, worst {}{note}", clock().fmt(qpc()), clock().fmt(r.since), fmt_dur(r.worst));
        }
    }

    /// Works out what the disk was doing while `slow` was outstanding, what the request was and
    /// who was stuck behind it, adds all of it to the disk's totals, and returns the words for
    /// the log line and the (at most two) lines under it.
    fn explain_io(&mut self, slow: &IoRec) -> IoWhy {
        let start = slow.end - slow.dur;
        let (ios, near, recs, (issue, (switch_ins, fault_stacks))) = {
            let inner = self.shared.inner.lock().unwrap();
            let ios: Vec<IoRec> = inner.ios.iter().filter(|i| i.disk == slow.disk).copied().collect();
            // Every disk: a thread woken as this one completed may have been waiting on another.
            let hi = slow.end + ms_to_ticks(diskstuck::READY_AFTER_MS);
            let near: Vec<IoRec> = inner.ios.iter().filter(|i| i.end >= start && i.end <= hi).copied().collect();
            let recs = self.shared.switches.then(|| {
                let (before, after) = (ms_to_ticks(diskstuck::READY_BEFORE_MS), ms_to_ticks(diskstuck::LOOK_AFTER_MS));
                inner.stuck_records(start, slow.end, before, after)
            });
            // Call stacks (see `stacks`): the request's own issuing stack, and the wait stacks of the
            // threads woken around its completion, any of which may turn out to be stuck behind it.
            let st = &inner.stacks;
            let issue = st.set.has(StackKind::DiskInit).then(|| st.slow_io_stack(slow.end, slow.irp));
            let waits = match &recs {
                Some(Some((_, rd))) if st.set.has(StackKind::CSwitch) || st.set.has(StackKind::Fault) => {
                    let mut tids: Vec<u32> = rd.iter().map(|r| r.tid).collect();
                    tids.sort_unstable();
                    tids.dedup();
                    let to = slow.end + ms_to_ticks(diskstuck::LOOK_AFTER_MS + stacks::FAULT_LATE_MS);
                    st.wait_stacks(&tids, start, to)
                }
                _ => (Vec::new(), Vec::new()),
            };
            (ios, near, recs, (issue, waits))
        };
        let why = self.explain_cause(slow, &ios);
        let disk = self.disks.get(slow.disk).clone();

        // What the request was. The path is only ever looked at after the privacy rule.
        let path = self.file_label(slow.file);
        let kind = diskstuck::classify(slow.op, slow.irp_flags, path.as_deref());

        // Several programs fighting over a hard drive's head at the time.
        let mut thrashers: Vec<String> = Vec::new();
        if disk.spinning == Some(true) {
            // Keyed by process, not by name: two copies of the same program fight over the head
            // just as hard as two different ones (seen live with two readers of one kind).
            let mut names: HashMap<(u32, u32), String> = HashMap::new();
            let mut reqs: Vec<(i64, i64, (String, u32))> = Vec::new();
            // Thrashing is what the drive has been doing lately, not a property of one request: a
            // hard drive completes only ~5 requests during a 60 ms one, too few to see a pattern
            // (measured live). So the last half second up to this completion is looked at, or the
            // request's own lifetime when that is longer. Rule of thumb, not a specification.
            let from = slow.end - slow.dur.max(ms_to_ticks(diskstuck::THRASH_LOOK_MS));
            for i in ios.iter().filter(|i| i.op != b'F' && i.end > from && i.end <= slow.end) {
                let key = if i.pid == PID_UNKNOWN { (i.pid, i.tid) } else { (i.pid, 0) };
                let name = names.entry(key).or_insert_with(|| process_name(&self.procs.label(i.pid, i.tid))).clone();
                reqs.push((i.end, i.offset, (name, key.0 ^ key.1)));
            }
            if let Some(t) = diskstuck::thrash(&reqs, true) {
                thrashers = diskstuck::copies(t.into_iter().map(|((name, _), _)| name));
            }
        }
        // Where its time went, when the storage port driver's trace could follow it; appended to
        // the same line rather than adding a third one.
        let timing = match self.storage_split(slow) {
            Some(Outcome::Split(s)) => Some(storsplit::event_words(&s)),
            _ => None,
        };
        // Which drivers the request went through on its way down, from its issuing call stack.
        let issue_path: Option<Vec<String>> = match &issue {
            Some(Some(IoStack::Found(st))) => Some(self.stack_path(st)),
            _ => None,
        };
        let via = issue_path.as_deref().map(stacks::via_variants).unwrap_or_default();
        let request = diskstuck::request_line_via(kind, slow.op, path.as_deref(), &thrashers, timing.as_deref(), &via);

        // Who was stuck behind it. Nothing at all is said when the rings could not tell.
        let mut stuck_line = None;
        let mut victims: Vec<diskstuck::Victim> = Vec::new();
        let mut chains: Vec<diskstuck::ChainText> = Vec::new();
        let mut wait_paths: Vec<(String, String)> = Vec::new();
        if let Some(Some((sw, rd))) = &recs {
            let stuck = diskstuck::stuck_behind(slow, &near, sw, rd);
            let found = diskstuck::lock_chains(slow, &stuck, sw, rd);
            let own = std::env::current_exe().ok().and_then(|p| p.file_name().map(|f| f.to_string_lossy().to_lowercase()));
            let is_own = |n: &str| own.as_ref().is_some_and(|own| n.to_lowercase().starts_with(own));
            let mut named: Vec<diskstuck::StuckThread> = Vec::new();
            for s in &stuck {
                // Windows' own kernel threads (the file cache's workers, mostly) are the machinery
                // doing the waiting on everyone's behalf, not a program anyone is waiting for:
                // measured live, they were all that "stuck behind it" named for a cached read.
                if self.pid_of(s.tid) == SYSTEM_PID {
                    continue;
                }
                let Some(name) = self.thread_program(s.tid).filter(|n| !is_own(n)) else { continue };
                // Where it was blocked, when a call stack for exactly this wait exists.
                let off = s.woke_at - s.waited;
                let at = match stacks::wait_stack(s.tid, off, s.woke_at, &switch_ins, &fault_stacks) {
                    Some((st, _)) => {
                        let path = self.stack_path(st);
                        wait_paths.push((name.clone(), stacks::path_text(None, &path)));
                        Some(stacks::waited_in(&path))
                    }
                    None => None,
                };
                named.push((name, s.waited, at));
            }
            victims = diskstuck::by_program(&named);
            for c in &found {
                if self.pid_of(c.waiter) == SYSTEM_PID {
                    continue;
                }
                let (Some(w), Some(h)) = (self.thread_program(c.waiter), self.thread_program(c.holder)) else { continue };
                if is_own(&w) {
                    continue;
                }
                // A lock wait is never a page fault: only the switch-in stack can say where it was.
                let at = stacks::wait_stack(c.waiter, c.woke_at - c.waited, c.woke_at, &switch_ins, &[]).map(|(st, _)| {
                    let path = self.stack_path(st);
                    stacks::waited_in(&path)
                });
                chains.push((w, c.waited, h, at));
            }
            stuck_line = diskstuck::stuck_line(&victims, &chains, &disk.short());
        }

        let behind = self.disk_behind.entry(slow.disk).or_default();
        *behind.kinds.entry(kind).or_default() += 1;
        if !thrashers.is_empty() {
            behind.thrash += 1;
            for name in &thrashers {
                *behind.thrash_programs.entry(name.clone()).or_default() += 1;
            }
        }
        match &recs {
            Some(Some(_)) => behind.checked += 1,
            Some(None) => behind.uncovered += 1,
            None => {} // not traced at all: nothing to count
        }
        for v in &victims {
            let e = behind.stuck.entry(v.name.clone()).or_default();
            e.0 += 1;
            e.1 += v.longest;
        }
        for (w, t, h, _) in &chains {
            let e = behind.chains.entry((w.clone(), h.clone())).or_default();
            e.0 += 1;
            e.1 = e.1.max(*t);
        }
        // Call stacks: which drivers the request went through, and where its victims waited.
        match (&issue, &issue_path) {
            (_, Some(path)) => {
                behind.stack_found += 1;
                let mut seen: Vec<&String> = Vec::new();
                for m in path {
                    if !seen.contains(&m) {
                        seen.push(m);
                        diskstuck::bump(&mut behind.in_path, m.clone());
                    }
                }
                diskstuck::bump(&mut behind.issue_paths, stacks::path_text(None, path));
            }
            (Some(_), None) => behind.stack_missing += 1,
            (None, None) => {} // not asked for
        }
        for v in &victims {
            if let Some(at) = &v.waited_in {
                behind.wait_stacks += 1;
                diskstuck::bump(&mut behind.waited_in, at.clone());
            }
        }
        for key in wait_paths {
            diskstuck::bump(&mut behind.wait_paths, key);
        }
        IoWhy { why, request, stuck: stuck_line }
    }

    /// The drivers on a call stack, caller first (see `stacks::module_path`).
    fn stack_path(&mut self, st: &stacks::Stack) -> Vec<String> {
        let modules = &mut self.modules;
        stacks::module_path(&st.frames, &mut |a| modules.owner(a))
    }

    /// The program a thread belongs to, or `None` for the idle thread and threads that can no
    /// longer be named.
    fn thread_program(&mut self, tid: u32) -> Option<String> {
        let pid = self.pid_of(tid);
        if pid == 0 {
            return None;
        }
        let label = self.procs.label(pid, tid);
        (!label.starts_with("unknown") && !label.starts_with("pid ")).then(|| process_name(&label))
    }

    /// Why the disk was slow, from the traffic around the request; adds it to the disk's totals.
    fn explain_cause(&mut self, slow: &IoRec, ios: &[IoRec]) -> String {
        let disk = self.disks.get(slow.disk);
        let class = match (disk.spinning, disk.bus) {
            (Some(true), _) => diskwhy::DriveClass::Spinning,
            (_, "NVMe") => diskwhy::DriveClass::Nvme,
            _ => diskwhy::DriveClass::Flash,
        };
        let ctx = diskwhy::explain(slow, ios, class, self.started);
        // Remembered so a freeze can later say "this one was a victim of the freeze, not a
        // problem of its own". Capped: a sick drive can produce thousands over a long run.
        let seen = self.disk_slow.entry(slow.disk).or_default();
        if seen.len() < 4096 {
            seen.push(SlowSeen { end: slow.end, dur: slow.dur, victim: false });
        }
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

/// The culprit for a stall where no processor was held, sharpened by the scheduler trace.
///
/// Without context switches all that can be said is "the thread was not woken, for one of two
/// reasons"; with them the two are told apart, and they lead to different places. `fallback` is
/// what the caller would have said on its own, and is what comes back when the measuring threads
/// disagree or nothing could be reconstructed.
pub(crate) fn not_woken_culprit(probes: &ProbeVerdict, fallback: &str) -> String {
    match probes.overall() {
        Some(switches::Verdict::NotWoken) => "not woken (nothing woke the thread)".to_string(),
        Some(switches::Verdict::Queued) => "not woken (ready, but given no processor)".to_string(),
        _ => fallback.to_string(),
    }
}

fn span_of(stalls: &[Stall]) -> (i64, i64) {
    (stalls.iter().map(|s| s.start).min().unwrap_or(0), stalls.iter().map(|s| s.end).max().unwrap_or(0))
}

/// Two probes reporting the same event: same start and same end, to within a few ms. Matching on
/// both edges keeps an unrelated starvation stall that merely happens to be nearby separate.
fn is_twin(a: (i64, i64), b: (i64, i64)) -> bool {
    let slack = ms_to_ticks(TWIN_SLACK_MS);
    (a.0 - b.0).abs() <= slack && (a.1 - b.1).abs() <= slack
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

/// A measuring thread's own hard page fault has to cover this much of its stall before the stall
/// is put down to paging: the same bar `diskwait` uses for a disk request.
const PAGING_COVER: f64 = 0.5;

/// The measuring threads' own hard page faults around a kernel-level stall; see `probe_paging`.
struct ProbePaging {
    faults: Vec<FaultRec>,
    /// Their process (the probes' own), or 0 when there were none.
    pid: u32,
    /// Stalled CPUs whose measuring thread spent at least `PAGING_COVER` of the stall in a fault.
    cpus: usize,
}

/// The event-log lines saying which interrupt sources stopped and which kept going during a
/// stall or freeze, and what the timer DPCs did. `what` is "freeze" or "stall"; the freeze's
/// lines are exactly what they always were.
fn flow_lines(what: &str, silent: &[(String, f64)], continued: &[(String, f64)], timer: Option<Flow>) -> Vec<String> {
    let say_list =
        |v: &[(String, f64)]| v.iter().map(|(n, s)| format!("{n} ({:.0}% of its usual rate)", s * 100.0)).collect::<Vec<_>>().join(", ");
    let stopped = format!("    Interrupt sources that STOPPED during the {what}: ");
    let mut out = Vec::new();
    if !silent.is_empty() {
        out.push(format!("{stopped}{}", say_list(silent)));
    }
    if !continued.is_empty() {
        out.push(format!("{:<width$}{}", "    Interrupt sources that kept going:", say_list(continued), width = stopped.len()));
    }
    if let Some(flow) = timer {
        let said = match flow {
            Flow::Silent => "stopped",
            Flow::Reduced => "well down",
            Flow::Continued => "unchanged",
        };
        out.push(format!("    Timer DPCs (the clock that wakes threads): {said}"));
    }
    out
}

/// The "Coincided with:" lines for a slow disk request (or the measuring thread's own page
/// fault) overlapping a stall. `disk` is the drive's short name. Only a whole-PC freeze may say a
/// request inside it was MADE slow by it: that stops every processor its answer could arrive on,
/// while a stall on some of them does not.
fn coincided_lines(what: &str, whole_pc: bool, w: &DiskWait, disk: Option<&str>, start: i64) -> Vec<String> {
    let Some(disk) = disk.filter(|_| w.disk.is_some()) else {
        return vec![format!("    Coincided with: this tool's own thread waiting {} for memory from disk", fmt_dur(w.waited))];
    };
    let (waited, op) = (fmt_dur(w.waited), op_name(w.op));
    match w.role {
        Role::Trigger => vec![
            format!(
                "    Coincided with: a {op} request to {disk} that was already outstanding {} before the {what} began and ended",
                fmt_dur((start - (w.io_end - w.waited)).max(0))
            ),
            format!("                    with it ({waited} in all). Correlation, not proof."),
        ],
        Role::Victim if whole_pc => vec![
            format!("    Coincided with: a {waited} {op} request to {disk}, which began after the {what} had already started,"),
            format!("                    so the {what} is what made it slow, not the other way round."),
        ],
        Role::Victim => vec![
            format!("    Coincided with: a {waited} {op} request to {disk}, which began after the {what} had already started and"),
            "                    ended with it. Correlation, not proof.".to_string(),
        ],
        Role::Overlap => vec![format!("    Coincided with: a {waited} {op} request to {disk} that overlapped it. Correlation, not proof.")],
    }
}

/// "    Context: ..." for one incident: throttling (see `cpuclock::throttled_clause`) and memory
/// pressure, one short clause each and only when present. Memory is read when the incident is
/// examined, a fraction of a second to a few seconds after it, and the line says so.
fn context_line(throttled: Option<String>, mem_load: Option<u32>) -> Option<String> {
    let mut parts: Vec<String> = throttled.into_iter().collect();
    if let Some(load) = mem_load.filter(|l| *l >= crate::util::MEMORY_TIGHT_PCT) {
        parts.push(format!("memory was {load}% in use when this was examined"));
    }
    (!parts.is_empty()).then(|| format!("    Context: {}.", parts.join("; ")))
}

/// This executable's file name, lowercased: its own threads are what gets interrupted, never a
/// cause.
fn own_exe() -> Option<String> {
    std::env::current_exe().ok().and_then(|p| p.file_name().map(|f| f.to_string_lossy().to_lowercase()))
}

/// One logical CPU's profiler samples in a window, split three ways.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct CoreLoad {
    cpu: u16,
    samples: u32,
    /// The idle thread with no DPC or ISR running: the processor really had nothing to do.
    idle: u32,
    /// Inside a DPC or ISR on that processor, whichever thread it interrupted.
    interrupt: u32,
}

impl CoreLoad {
    fn busy(&self) -> f64 {
        if self.samples == 0 {
            0.0
        } else {
            1.0 - f64::from(self.idle) / f64::from(self.samples)
        }
    }
}

/// One CPU's DPC/ISR spans, merged into sorted, disjoint intervals (ISRs nest inside DPCs).
fn merged_spans(execs: &[ExecRec], cpu: u16) -> Vec<(i64, i64)> {
    let mut spans: Vec<(i64, i64)> = execs.iter().filter(|e| e.cpu == cpu).map(|e| (e.start, e.end)).collect();
    spans.sort_unstable();
    let mut out: Vec<(i64, i64)> = Vec::new();
    for (from, to) in spans {
        match out.last_mut() {
            Some(last) if from <= last.1 => last.1 = last.1.max(to),
            _ => out.push((from, to)),
        }
    }
    out
}

fn in_spans(spans: &[(i64, i64)], ts: i64) -> bool {
    let i = spans.partition_point(|s| s.0 <= ts);
    i > 0 && spans[i - 1].1 >= ts
}

/// Per CPU: how many samples, how many were really idle, how many landed in interrupt-level code.
/// The profiler attributes a sample to whatever thread was current, so a DPC running on an idle
/// processor shows up as the idle thread; the DPC/ISR records say when that was.
fn core_loads(samples: &[(SampleRec, u32)], execs: &[ExecRec]) -> Vec<CoreLoad> {
    let mut by_cpu: HashMap<u16, (Vec<(i64, i64)>, CoreLoad)> = HashMap::new();
    for (s, _) in samples {
        let (spans, load) =
            by_cpu.entry(s.cpu).or_insert_with(|| (merged_spans(execs, s.cpu), CoreLoad { cpu: s.cpu, ..CoreLoad::default() }));
        load.samples += 1;
        if in_spans(spans, s.ts) {
            load.interrupt += 1;
        } else if s.tid == 0 {
            load.idle += 1;
        }
    }
    let mut out: Vec<CoreLoad> = by_cpu.into_values().map(|(_, l)| l).collect();
    out.sort_by_key(|l| l.cpu);
    out
}

/// Share of all samples in which the processor really had nothing to do.
fn idle_share(loads: &[CoreLoad]) -> f64 {
    let samples: u32 = loads.iter().map(|l| l.samples).sum();
    if samples == 0 {
        return 0.0;
    }
    f64::from(loads.iter().map(|l| l.idle).sum::<u32>()) / f64::from(samples)
}

/// A core this busy in the window was pegged: at most one sample in ten found it idle.
const PEGGED_BUSY: f64 = 0.9;
/// ...and the cores that were not have to have been idle at least this much on average, or it is
/// a busy PC rather than one busy core.
const OTHERS_IDLE: f64 = 0.5;

/// One or a few cores pegged while the rest idled.
#[derive(Clone, Debug, PartialEq)]
struct Pegged {
    /// (CPU, busy share), busiest first.
    cores: Vec<(u16, f64)>,
    /// How many other CPUs were judged, and their idle share together.
    others: usize,
    others_idle: f64,
}

/// "One or a few" is at most a quarter of the CPUs that could be judged (at least one), so a PC
/// with most of its cores busy is not described as having one busy core. Only CPUs with at
/// least `MIN_SAMPLES` samples are judged at all; a CPU with none (parked, or not sampled) is left
/// out rather than counted as idle. Rules of thumb, stated in the README.
fn pegged_cores(loads: &[CoreLoad]) -> Option<Pegged> {
    let judged: Vec<&CoreLoad> = loads.iter().filter(|l| l.samples as usize >= MIN_SAMPLES).collect();
    let (hot, rest): (Vec<&CoreLoad>, Vec<&CoreLoad>) = judged.iter().partition(|l| l.busy() >= PEGGED_BUSY);
    if hot.is_empty() || rest.is_empty() || hot.len() > (judged.len() / 4).max(1) {
        return None;
    }
    let (samples, idle) = rest.iter().fold((0u32, 0u32), |(s, i), l| (s + l.samples, i + l.idle));
    let others_idle = f64::from(idle) / f64::from(samples.max(1));
    if others_idle < OTHERS_IDLE {
        return None;
    }
    let mut cores: Vec<(u16, f64)> = hot.iter().map(|l| (l.cpu, l.busy())).collect();
    cores.sort_by(|a, b| b.1.total_cmp(&a.1).then(a.0.cmp(&b.0)));
    Some(Pegged { cores, others: rest.len(), others_idle })
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

    /// The CPU number in a stall line is bare on an ordinary PC, and labeled only where the
    /// cores differ. Nothing about core types may appear on a uniform machine.
    #[test]
    fn cpu_numbers_are_only_labeled_on_a_hybrid_cpu() {
        let mut az = Analyzer::for_test(ModuleMap::for_test(&[]), ProcNames::for_test(&[]), false);
        az.topo = crate::topology::Topology::build(&[8], &[]);
        assert_eq!(az.cpu_label(5), "5");

        let sets: Vec<crate::topology::CpuSet> =
            (0..8u8).map(|i| crate::topology::CpuSet { group: 0, index: i, class: u8::from(i < 4), core: i }).collect();
        az.topo = crate::topology::Topology::build(&[8], &sets);
        assert_eq!(az.cpu_label(1), "1 (P-core)");
        assert_eq!(az.cpu_label(5), "5 (E-core)");
    }

    /// Every file name in the report goes through this one function: drive letter first, then
    /// the privacy rule. A file the trace never named must produce nothing at all.
    #[test]
    fn file_names_are_converted_and_redacted_before_they_can_be_printed() {
        let mut az = Analyzer::for_test(ModuleMap::for_test(&[]), ProcNames::for_test(&[]), false);
        az.dos = DosMap::from_pairs(&[("\\Device\\HarddiskVolume3", "C:")]);
        {
            let mut inner = az.shared.inner.lock().unwrap();
            inner.file_names.insert(10, "\\Device\\HarddiskVolume3\\pagefile.sys");
            inner.file_names.insert(11, "\\Device\\HarddiskVolume3\\Users\\Jennifer\\Documents\\secret.docx");
            inner.file_names.insert(12, "\\Device\\HarddiskVolume9\\Stuff\\thing.bin");
        }
        assert_eq!(az.file_label(10).as_deref(), Some("C:\\pagefile.sys"));
        assert_eq!(az.file_label(11).as_deref(), Some("C:\\Users\\...\\(a .docx file)"));
        assert_eq!(az.file_label(12).as_deref(), Some("\\Device\\HarddiskVolume9\\...\\(a .bin file)"));
        assert_eq!(az.file_label(0), None, "no file object: nothing to say");
        assert_eq!(az.file_label(999), None, "the trace never named it: nothing to say");
    }

    /// The whole-PC rule has to work on a 4-thread laptop and on a 64-thread workstation, where
    /// one parked or descheduled CPU must not hide a machine-wide freeze.
    #[test]
    fn the_whole_pc_rule_scales_from_a_laptop_to_a_workstation() {
        assert_eq!(freeze_cpu_floor(1), 1);
        assert_eq!(freeze_cpu_floor(4), 4, "a 4-thread PC: all of them");
        assert_eq!(freeze_cpu_floor(6), 5);
        assert_eq!(freeze_cpu_floor(8), 6);
        assert_eq!(freeze_cpu_floor(64), 48);
        assert_eq!(freeze_cpu_floor(192), 144);
    }

    #[test]
    fn twin_stalls_are_matched_on_both_edges() {
        let ms = ms_to_ticks;
        // The field pair: kernel 888 ms at t, scheduler 885 ms 3 ms later.
        assert!(is_twin((ms(0.0), ms(888.0)), (ms(3.0), ms(888.0))));
        assert!(is_twin((ms(0.0), ms(1324.0)), (ms(2.0), ms(1331.0))));
        // Same start, very different length: two different events.
        assert!(!is_twin((ms(0.0), ms(888.0)), (ms(0.0), ms(30.0))));
        // Same length, far apart in time.
        assert!(!is_twin((ms(0.0), ms(888.0)), (ms(900.0), ms(1788.0))));
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
        Evidence {
            execs,
            faults: Vec::new(),
            ios: Vec::new(),
            samples,
            baseline,
            ref_execs: Vec::new(),
            ref_seconds: 0.0,
            etw_caught_up: true,
            switches: Vec::new(),
            readies: Vec::new(),
            switches_cover: false,
        }
    }

    /// No context-switch trace, so the scheduler can say nothing: the verdicts below are the
    /// ones this tool reaches from DPC/ISR and CPU samples alone.
    fn no_probes() -> ProbeVerdict {
        ProbeVerdict::default()
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
        assert_eq!(az.verdict_kernel(&[s], &ev, &no_probes()).0, "driver nvlddmkm.sys");
    }

    #[test]
    fn dpc_on_a_different_cpu_is_not_blamed() {
        let modules = ModuleMap::for_test(&[("nvlddmkm.sys", MOD_A, 0x1000)]);
        let mut az = Analyzer::for_test(modules, ProcNames::for_test(&[]), false);
        let s = stall(0, 0.0, 100.0);
        // Same DPC, same size, but it ran on CPU 1 while the probe stalled on CPU 0.
        let ev = evidence(vec![dpc(1, 0.0, 40.0, MOD_A + 0x10)], vec![], HashMap::new());
        assert_eq!(az.verdict_kernel(&[s], &ev, &no_probes()).0, "unexplained");
    }

    #[test]
    fn dpc_coverage_just_under_threshold_is_not_blamed() {
        let modules = ModuleMap::for_test(&[("nvlddmkm.sys", MOD_A, 0x1000)]);
        let mut az = Analyzer::for_test(modules, ProcNames::for_test(&[]), false);
        let s = stall(0, 0.0, 100.0);
        // 34% covered: just below the 35% rule-1 threshold.
        let ev = evidence(vec![dpc(0, 0.0, 34.0, MOD_A + 0x10)], vec![], HashMap::new());
        assert_eq!(az.verdict_kernel(&[s], &ev, &no_probes()).0, "unexplained");
    }

    #[test]
    fn overlapping_dpc_and_isr_are_not_double_counted_toward_coverage() {
        let modules = ModuleMap::for_test(&[("nvlddmkm.sys", MOD_A, 0x1000), ("rtwlane.sys", MOD_B, 0x1000)]);
        let mut az = Analyzer::for_test(modules, ProcNames::for_test(&[]), false);
        let s = stall(0, 0.0, 100.0);
        // A DPC and an ISR from two different drivers, both covering the exact same 0-20ms
        // window. Neither driver's own code reaches the 35% bar, and the two must not be added
        // together into one: the honest answer is that nothing explains the stall.
        let ev = evidence(vec![dpc(0, 0.0, 20.0, MOD_A + 0x10), isr(0, 0.0, 20.0, MOD_B + 0x10)], vec![], HashMap::new());
        assert_eq!(az.verdict_kernel(&[s], &ev, &no_probes()).0, "unexplained");
    }

    /// The dilution bug from the verdict audit: on a multi-CPU cluster, coverage used to be
    /// summed over every per-CPU stall, so a driver holding one core scored 1/N.
    #[test]
    fn a_driver_holding_its_own_cpu_is_judged_per_cpu_not_across_the_cluster() {
        let modules = ModuleMap::for_test(&[("nvlddmkm.sys", MOD_A, 0x1000)]);
        let mut az = Analyzer::for_test(modules, ProcNames::for_test(&[]), false);
        // Two CPUs stalled; the driver's DPCs cover 90% of BOTH, which used to work out to 45%
        // of the cluster and now correctly reads as "it held both of them".
        let stalls = [stall(0, 0.0, 10.0), stall(1, 0.0, 10.0)];
        let ev = evidence(vec![dpc(0, 0.0, 9.0, MOD_A + 0x10), dpc(1, 0.0, 9.0, MOD_A + 0x10)], vec![], HashMap::new());
        assert_eq!(az.verdict_kernel(&stalls, &ev, &no_probes()).0, "driver nvlddmkm.sys");

        // Holding ONE of eight CPUs is not an explanation for an eight-CPU event.
        let stalls: Vec<Stall> = (0..8).map(|c| stall(c, 0.0, 10.0)).collect();
        let ev = evidence(vec![dpc(3, 0.0, 9.0, MOD_A + 0x10)], vec![], HashMap::new());
        assert_eq!(az.verdict_kernel(&stalls, &ev, &no_probes()).0, "unexplained");
    }

    #[test]
    fn cpu_going_dark_is_reported_only_when_profiling() {
        let mut baseline = HashMap::new();
        baseline.insert(0u16, 500u32); // 500 samples in the 500ms baseline window: ~1/ms
        let s = stall(0, 0.0, 100.0);
        let ev = evidence(vec![], vec![], baseline);

        let mut profiled = Analyzer::for_test(ModuleMap::for_test(&[]), ProcNames::for_test(&[]), true);
        let v = profiled.verdict_kernel(&[s], &ev, &no_probes());
        assert!(v.0.starts_with("CPU went dark"), "expected 'CPU went dark...', got {v:?}");

        // Same evidence, but sampling wasn't enabled: it must not claim the CPU went dark.
        let mut unprofiled = Analyzer::for_test(ModuleMap::for_test(&[]), ProcNames::for_test(&[]), false);
        assert_eq!(unprofiled.verdict_kernel(&[s], &ev, &no_probes()).0, "unexplained");
    }

    /// From the field logs: "the CPU went dark, Windows itself was frozen out" printed for a
    /// window that also contained hundreds of DPC/ISR executions. A DPC cannot run on a frozen
    /// processor, so the claim is not allowed to be made.
    #[test]
    fn the_cpu_did_not_go_dark_while_dpcs_were_still_running_on_it() {
        let modules = ModuleMap::for_test(&[("Wdf01000.sys", MOD_A, 0x1000)]);
        let mut baseline = HashMap::new();
        baseline.insert(0u16, 500u32);
        let s = stall(0, 0.0, 800.0);
        // 800 DPCs, one per millisecond, right through the stall: the CPU was alive.
        let execs: Vec<ExecRec> = (0..800).map(|i| dpc(0, i as f64, 0.01, MOD_A + 0x10)).collect();
        let ev = evidence(execs, vec![], baseline);
        let mut az = Analyzer::for_test(modules, ProcNames::for_test(&[]), true);
        assert_eq!(az.verdict_kernel(&[s], &ev, &no_probes()).0, "not woken (timers or scheduling)");
    }

    #[test]
    fn very_short_stalls_do_not_trigger_went_dark() {
        let mut baseline = HashMap::new();
        baseline.insert(0u16, 500u32); // ~1 sample/ms
                                       // 2ms stall => ~2 expected samples, under the "expected >= 3" floor.
        let s = stall(0, 0.0, 2.0);
        let ev = evidence(vec![], vec![], baseline);
        let mut az = Analyzer::for_test(ModuleMap::for_test(&[]), ProcNames::for_test(&[]), true);
        assert_eq!(az.verdict_kernel(&[s], &ev, &no_probes()).0, "unexplained");
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
        assert_eq!(az.verdict_kernel(&[s], &ev, &no_probes()).0, "driver rtwlane.sys");
    }

    /// The behavior that was right and has to survive: one core held for 8 ms with a network
    /// filter in 90% of the samples and NOT ONE DPC on that core while it happened.
    #[test]
    fn a_driver_holding_one_core_with_no_dpcs_running_is_still_blamed() {
        let modules = ModuleMap::for_test(&[("NETIO.SYS", MOD_B, 0x1000)]);
        let procs = ProcNames::for_test(&[(4, "System (kernel threads)")]);
        let mut az = Analyzer::for_test(modules, procs, false);
        let s = stall(5, 0.0, 8.0);
        let mut samples: Vec<(SampleRec, u32)> = (0..9).map(|i| sample(5, i as f64, MOD_B + 0x10, 4)).collect();
        samples.push(sample(5, 9.0, USER_IP, 4));
        let ev = evidence(vec![], samples, HashMap::new());
        assert_eq!(az.verdict_kernel(&[s], &ev, &no_probes()).0, "driver NETIO.SYS");
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
        assert_eq!(az.verdict_kernel(&[s], &ev, &no_probes()).0, "process game.exe (200)");
    }

    /// A share of nearly nothing is not evidence. Two samples in a stall cannot name a culprit.
    #[test]
    fn a_share_of_two_samples_names_nobody() {
        let procs = ProcNames::for_test(&[(200, "game.exe")]);
        let mut az = Analyzer::for_test(ModuleMap::for_test(&[]), procs, false);
        let s = stall(0, 0.0, 100.0);
        let ev = evidence(vec![], vec![sample(0, 10.0, USER_IP, 200), sample(0, 20.0, USER_IP, 200)], HashMap::new());
        assert_eq!(az.verdict_kernel(&[s], &ev, &no_probes()).0, "unexplained");
    }

    #[test]
    fn nothing_conclusive_is_unexplained() {
        let mut az = Analyzer::for_test(ModuleMap::for_test(&[]), ProcNames::for_test(&[]), false);
        let s = stall(0, 0.0, 100.0);
        let ev = evidence(vec![], vec![], HashMap::new());
        assert_eq!(az.verdict_kernel(&[s], &ev, &no_probes()).0, "unexplained");
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
        assert_eq!(az.verdict_sched(&ev, 0, ms(30.0), &no_probes()).0, "CPU starvation (unattributed)");
    }

    #[test]
    fn sched_with_no_samples_is_unattributed() {
        let mut az = Analyzer::for_test(ModuleMap::for_test(&[]), ProcNames::for_test(&[]), true);
        let ev = evidence(vec![], vec![], HashMap::new());
        assert_eq!(az.verdict_sched(&ev, 0, ms(30.0), &no_probes()).0, "CPU starvation (unattributed)");
    }

    #[test]
    fn sched_blames_top_consumer_when_idle_is_low() {
        let procs = ProcNames::for_test(&[(500, "app.exe")]);
        let mut az = Analyzer::for_test(ModuleMap::for_test(&[]), procs, true);
        let mut samples: Vec<(SampleRec, u32)> = (0..8).map(|i| sample(0, i as f64, USER_IP, 500)).collect();
        samples.extend((0..2).map(|i| sample(0, i as f64, USER_IP, 0))); // Idle: 2/10 = 20% < 25%
        let ev = evidence(vec![], samples, HashMap::new());
        assert_eq!(az.verdict_sched(&ev, 0, ms(30.0), &no_probes()).0, "process app.exe (500)");
    }

    /// A late wake-up with idle CPUs is not "a scheduling quirk, ignore it": when a disk request
    /// covers the delay, the thread was blocked on that disk, and when nothing does, the honest
    /// answer is that the cause is not visible.
    #[test]
    fn a_scheduler_delay_with_idle_cpus_names_the_disk_or_admits_it_cannot() {
        let procs = ProcNames::for_test(&[(500, "app.exe"), (600, "other.exe")]);
        let mut az = Analyzer::for_test(ModuleMap::for_test(&[]), procs, true);
        let idle_samples = || -> Vec<(SampleRec, u32)> {
            let mut s: Vec<(SampleRec, u32)> = (0..7).map(|i| sample(0, i as f64, USER_IP, 0)).collect();
            s.extend((0..3).map(|i| sample(0, i as f64, USER_IP, 500)));
            s
        };
        let mut ev = evidence(vec![], idle_samples(), HashMap::new());
        assert_eq!(az.verdict_sched(&ev, ms(1000.0), ms(1887.0), &no_probes()).0, "scheduling delay with idle CPUs");

        ev.ios = vec![IoRec {
            end: ms(1883.0),
            dur: ms(878.0),
            disk: 5,
            tid: 1,
            pid: 4,
            size: 4096,
            op: b'W',
            file: 0,
            irp: 0,
            offset: 0,
            irp_flags: 0,
        }];
        assert_eq!(az.verdict_sched(&ev, ms(1000.0), ms(1887.0), &no_probes()).0, "disk 5");
    }

    // --- the twin merge --------------------------------------------------------------------

    fn freeze_probes(start: i64, dur: i64) -> Vec<Stall> {
        (0..8).map(|c| Stall { kind: StallKind::Kernel, cpu: Some(c), start, end: start + dur, minor: false }).collect()
    }

    fn sched_probe(start: i64, dur: i64) -> Stall {
        Stall { kind: StallKind::Scheduler, cpu: None, start, end: start + dur, minor: false }
    }

    /// Who was stuck behind a slow request is said only when the switch rings cover it; otherwise
    /// nothing is said about it at all (not "nobody waited"), and the request is counted as unchecked.
    #[test]
    fn a_slow_request_names_who_waited_only_when_the_rings_cover_it() {
        let slow = IoRec {
            end: ms(1800.0),
            dur: ms(800.0),
            disk: 99,
            tid: 7,
            pid: 100,
            size: 4096,
            op: b'R',
            file: 0,
            irp: 0,
            offset: 0,
            irp_flags: 0x2,
        };
        let waiter = |ts: f64| SwitchRec {
            ts: ms(ts),
            new_tid: 0,
            old_tid: 51,
            cpu: 0,
            new_prio: 0,
            old_prio: 8,
            old_wait_reason: 9,
            old_wait_mode: 0,
            old_state: switches::STATE_WAITING,
        };
        let build = |first_switch_ms: f64, traced: bool| {
            let mut az = Analyzer::for_test(ModuleMap::for_test(&[]), ProcNames::for_test(&[(100, "explorer.exe")]), false);
            Arc::get_mut(&mut az.shared).unwrap().switches = traced;
            {
                let mut inner = az.shared.inner.lock().unwrap();
                inner.push_switch(SwitchRec { old_tid: 90, ..waiter(first_switch_ms) });
                inner.push_switch(waiter(1100.0));
                inner.push_ready(ReadyRec { ts: ms(1800.1), tid: 51, by_tid: 0, cpu: 0, flag: READY_FROM_DPC });
                inner.tid_pid.insert(51, 100);
                inner.tid_pid.insert(7, 100);
                inner.ios.push_back(slow);
                inner.latest_ts = ms(5000.0);
            }
            az
        };

        let mut az = build(0.0, true);
        let w = az.explain_io(&slow);
        assert_eq!(w.stuck.as_deref(), Some("    Stuck behind it: explorer.exe (1 thread, up to 700 ms)"));
        assert!(w.request.as_deref().is_some_and(|r| r.contains("through the file cache")), "{:?}", w.request);
        let b = &az.disk_behind[&99];
        assert_eq!((b.checked, b.uncovered, b.stuck["explorer.exe"].0), (1, 0, 1));

        // The rings start after the request did: nothing is said, and it is counted as unchecked.
        let mut az = build(1050.0, true);
        let w = az.explain_io(&slow);
        assert!(w.stuck.is_none());
        let b = &az.disk_behind[&99];
        assert_eq!((b.checked, b.uncovered), (0, 1));
        assert!(b.stuck.is_empty());

        // Not traced at all (light mode, --no-switches): nothing said, nothing counted either way.
        let mut az = build(0.0, false);
        assert!(az.explain_io(&slow).stuck.is_none());
        assert_eq!((az.disk_behind[&99].checked, az.disk_behind[&99].uncovered), (0, 0));
        assert_eq!(az.disk_behind[&99].kinds[&diskstuck::Kind::PagedFile], 1, "what the request was is still known");
    }

    /// With the storage port driver's trace, the "Request:" line says where the time went, and
    /// the disk's totals count how the request was matched. A trace that did not cover the request
    /// says nothing on the line and counts it as not covered, never as "not matched".
    #[test]
    fn a_slow_request_says_where_its_time_went_when_the_storage_trace_follows_it() {
        use crate::storport::{ReqRec, StorInner, StorTrace};
        let slow = IoRec {
            end: ms(1800.0),
            dur: ms(800.0),
            disk: 99,
            tid: 7,
            pid: 100,
            size: 4096,
            op: b'R',
            file: 0,
            irp: 0xFFFF_A000_0000_ABC0,
            offset: 0,
            irp_flags: 0,
        };
        let build = |session_started_ms: f64| {
            let mut az = Analyzer::for_test(ModuleMap::for_test(&[]), ProcNames::for_test(&[(100, "explorer.exe")]), false);
            Arc::get_mut(&mut az.shared).unwrap().switches = false;
            az.scsi_addrs.insert(99, None); // no live IOCTL from a test
            let mut inner = StorInner::new(1000, ms(session_started_ms));
            let piece = ReqRec {
                ts: ms(1799.9),
                dur: ms(760.0),
                irp: slow.irp,
                bytes: 4096,
                srb: 0x01,
                cmd: 0x28,
                retries: 2,
                ..ReqRec::default()
            };
            inner.reqs.push_back(piece);
            inner.latest_ts = ms(5000.0);
            az.set_storage_trace(Arc::new(StorTrace { inner: Mutex::new(inner), debug: false }));
            az
        };

        let mut az = build(0.0);
        let w = az.explain_io(&slow);
        let line = w.request.expect("a request line");
        assert!(line.contains("760 ms inside the drive, 40.00 ms waiting in Windows; retried 2 times"), "{line}");
        assert!(line.chars().count() <= diskstuck::LINE_WIDTH, "{line}");
        let t = az.disk_split[&99];
        assert_eq!((t.by_irp, t.retries, t.not_covered), (1, 2, 0));

        let mut az = build(1500.0);
        let w = az.explain_io(&slow);
        assert!(!w.request.unwrap().contains("inside the drive"), "the session began after the request did");
        assert_eq!((az.disk_split[&99].not_covered, az.disk_split[&99].unmatched), (1, 0));

        let mut az = Analyzer::for_test(ModuleMap::for_test(&[]), ProcNames::for_test(&[]), false);
        az.explain_io(&slow);
        assert!(az.disk_split.is_empty(), "no storage trace, nothing counted");
    }

    fn eight_cpu_analyzer() -> Analyzer {
        let mut az = Analyzer::for_test(ModuleMap::for_test(&[]), ProcNames::for_test(&[]), true);
        az.topo = crate::topology::Topology::build(&[8], &[]);
        az
    }

    /// The field shape: eight real-time probes and the normal-priority probe in the other
    /// process report the same ~900 ms gap a few ms apart. That is ONE event.
    #[test]
    fn a_freeze_and_its_starvation_twin_become_one_incident() {
        let mut az = eight_cpu_analyzer();
        let start = qpc() - ms(6000.0);
        let mut stalls = freeze_probes(start, ms(900.0));
        stalls.push(sched_probe(start + ms(2.0), ms(903.0)));
        az.feed(&stalls);
        az.tick(false);
        assert_eq!(az.incidents.len(), 1, "one freeze, not a freeze plus a starvation stall");
        assert_eq!(az.incidents[0].class, IncidentClass::Freeze);
        assert_eq!(az.incidents[0].culprit, "whole-PC freeze");
        assert_eq!(az.waiting(), 0);
    }

    #[test]
    fn a_scheduler_stall_with_no_kernel_twin_stays_a_scheduler_incident() {
        let mut az = eight_cpu_analyzer();
        az.feed(&[sched_probe(qpc() - ms(6000.0), ms(30.0))]);
        az.tick(false);
        assert_eq!(az.incidents.len(), 1);
        assert_eq!(az.incidents[0].class, IncidentClass::Starvation);
    }

    /// A ripe cluster waits a little for its sibling, and then gives up. Nothing is held for
    /// ever, and shutting down flushes whatever is still waiting.
    #[test]
    fn an_unpaired_cluster_is_held_briefly_and_then_reported_alone() {
        let mut az = eight_cpu_analyzer();
        let end = qpc() - ms(380.0);
        let stalls = freeze_probes(end - ms(900.0), ms(900.0));
        az.shared.inner.lock().unwrap().latest_ts = end + ms(100.0);
        az.feed(&stalls);
        az.tick(false);
        assert_eq!(az.incidents.len(), 0, "ripe, but its twin could still arrive");
        assert_eq!(az.waiting(), 8, "and it is kept, not dropped");
        // Shutdown analyzes everything pending, whatever the clock says.
        az.tick(true);
        assert_eq!(az.incidents.len(), 1);
        assert_eq!(az.waiting(), 0);

        // Past the wait, an unpaired cluster is reported on its own rather than held for ever.
        let mut az = eight_cpu_analyzer();
        az.shared.inner.lock().unwrap().latest_ts = qpc();
        az.feed(&freeze_probes(qpc() - ms(1500.0), ms(900.0)));
        az.tick(false);
        assert_eq!(az.incidents.len(), 1);
    }

    /// Two events that merely happen near each other are not twins.
    #[test]
    fn an_unrelated_starvation_stall_is_not_swallowed_by_a_freeze() {
        let mut az = eight_cpu_analyzer();
        let start = qpc() - ms(6000.0);
        let mut stalls = freeze_probes(start, ms(900.0));
        stalls.push(sched_probe(start + ms(1200.0), ms(40.0)));
        az.feed(&stalls);
        az.tick(false);
        assert_eq!(az.incidents.len(), 2);
        assert_eq!(az.incidents[0].class, IncidentClass::Freeze);
        assert_eq!(az.incidents[1].class, IncidentClass::Starvation);
    }

    /// A short all-CPU stall is not a freeze: the field logs are full of 5-13 ms stalls that hit
    /// every core, and calling those "the whole PC stopped" would be as wrong in the other
    /// direction.
    #[test]
    fn a_short_all_cpu_stall_is_not_a_whole_pc_freeze() {
        let mut az = eight_cpu_analyzer();
        az.feed(&freeze_probes(qpc() - ms(6000.0), ms(6.0)));
        az.tick(false);
        assert_eq!(az.incidents[0].class, IncidentClass::Kernel);
    }

    // --- whole-PC freezes ------------------------------------------------------------------

    fn eight_cpu_freeze(dur_ms: f64) -> Vec<Stall> {
        (0..8).map(|c| stall(c, 0.0, dur_ms)).collect()
    }

    /// The shape of the field reports: eight CPUs held for 900 ms, DPCs flowing as usual, the
    /// CPUs mostly idle. No program, no module, and not one word about raised IRQL.
    #[test]
    fn an_all_cpu_freeze_with_dpcs_flowing_blames_nobody() {
        let modules = ModuleMap::for_test(&[("Wdf01000.sys", MOD_A, 0x1000)]);
        let procs = ProcNames::for_test(&[(300, "explorer.exe")]);
        let mut az = Analyzer::for_test(modules, procs, true);
        az.topo = crate::topology::Topology::build(&[8], &[]);
        let stalls = eight_cpu_freeze(900.0);
        // ~100 DPCs per CPU, evenly spread: the machine's interrupts never stopped.
        let mut execs = Vec::new();
        for cpu in 0..8u16 {
            execs.extend((0..100).map(|i| dpc(cpu, i as f64 * 9.0, 0.02, MOD_A + 0x10)));
        }
        let mut samples: Vec<(SampleRec, u32)> = (0..70).map(|i| sample(0, i as f64, USER_IP, 0)).collect();
        samples.extend((0..30).map(|i| sample(1, i as f64, USER_IP, 300)));
        let ev = evidence(execs, samples, HashMap::new());
        let (culprit, facts) = az.verdict_freeze(&stalls, &ev, 8, 0, ms(900.0));
        assert_eq!(culprit, "whole-PC freeze");
        assert!(facts.dpcs_kept_running, "DPCs ran throughout, so no CPU was held");
        assert_eq!(facts.holding, None, "no driver held a majority of the CPUs");
        assert!(facts.idle_share > 0.6, "{}", facts.idle_share);
    }

    /// The other flavor in the field logs: one program in 91% of the samples, all of it inside
    /// ntoskrnl. It is still a freeze and it is still not that program's fault.
    #[test]
    fn a_freeze_with_one_program_all_over_the_samples_still_blames_nobody() {
        let modules = ModuleMap::for_test(&[("ntoskrnl.exe", MOD_A, 0x1000)]);
        let procs = ProcNames::for_test(&[(32468, "SignalRgb.exe")]);
        let mut az = Analyzer::for_test(modules, procs, true);
        az.topo = crate::topology::Topology::build(&[8], &[]);
        let stalls = eight_cpu_freeze(924.0);
        let samples: Vec<(SampleRec, u32)> = (0..91).map(|i| sample((i % 8) as u16, i as f64 * 10.0, MOD_A + 0x10, 32468)).collect();
        let ev = evidence(vec![], samples, HashMap::new());
        let (culprit, facts) = az.verdict_freeze(&stalls, &ev, 8, 0, ms(924.0));
        assert_eq!(culprit, "whole-PC freeze");
        assert_eq!(facts.holding, None);
        assert!(facts.on_cpu.contains(&"SignalRgb.exe (32468)".to_string()), "named as context only: {:?}", facts.on_cpu);
    }

    /// A slow request that only began once the machine had already stopped is a victim of the
    /// freeze; it must not also be counted against its drive.
    #[test]
    fn a_slow_request_inside_a_freeze_is_marked_as_the_freezes_victim() {
        let mut az = Analyzer::for_test(ModuleMap::for_test(&[]), ProcNames::for_test(&[]), true);
        az.topo = crate::topology::Topology::build(&[8], &[]);
        let (start, end) = (ms(1000.0), ms(1886.0));
        let victim = IoRec {
            end: ms(1887.0),
            dur: ms(878.0),
            disk: 5,
            tid: 1,
            pid: 4,
            size: 4096,
            op: b'W',
            file: 0,
            irp: 0,
            offset: 0,
            irp_flags: 0,
        };
        az.disk_slow.insert(5, vec![SlowSeen { end: victim.end, dur: victim.dur, victim: false }]);
        let stalls: Vec<Stall> = (0..8).map(|c| Stall { kind: StallKind::Kernel, cpu: Some(c), start, end, minor: false }).collect();
        let mut ev = evidence(vec![], vec![], HashMap::new());
        ev.ios = vec![victim];
        let (_, facts) = az.verdict_freeze(&stalls, &ev, 8, start, end);
        assert_eq!(facts.coincided.as_ref().map(|c| c.role), Some(Role::Victim));
        assert!(az.disk_slow[&5][0].victim, "the request is explained by the freeze");
    }

    /// One source stops dead while another carries on: the signal issue #15 asks for.
    #[test]
    fn a_freeze_says_which_interrupt_sources_stopped_and_which_kept_going() {
        let modules = ModuleMap::for_test(&[("Wdf01000.sys", MOD_A, 0x1000), ("dxgkrnl.sys", MOD_B, 0x1000)]);
        let mut az = Analyzer::for_test(modules, ProcNames::for_test(&[]), true);
        az.topo = crate::topology::Topology::build(&[8], &[]);
        // 5 s of reference: both sources at ~500/s, firing in every second.
        let mut ref_execs = Vec::new();
        for i in 0..2500 {
            ref_execs.push(dpc(0, -5000.0 + i as f64 * 2.0, 0.01, MOD_A + 0x10));
            ref_execs.push(isr(0, -5000.0 + i as f64 * 2.0, 0.01, MOD_B + 0x10));
        }
        // Inside the 900 ms freeze: the USB side stops, the graphics side keeps coming.
        let execs: Vec<ExecRec> = (0..450).map(|i| isr(0, i as f64 * 2.0, 0.01, MOD_B + 0x10)).collect();
        let mut ev = evidence(execs, vec![], HashMap::new());
        ev.ref_execs = ref_execs;
        ev.ref_seconds = 5.0;
        let stalls = eight_cpu_freeze(900.0);
        let (_, facts) = az.verdict_freeze(&stalls, &ev, 8, 0, ms(900.0));
        assert!(facts.silent.iter().any(|(s, _)| s == "Wdf01000.sys"), "{:?}", facts.silent);
        assert!(facts.continued.iter().any(|(s, _)| s == "dxgkrnl.sys"), "{:?}", facts.continued);
    }

    // --- issue #19: the freeze checks on kernel-level stalls ---------------------------------

    /// The freeze's event-log lines are built by the helpers now shared with kernel-level stalls.
    /// These are the exact strings the freeze printed before the helpers existed.
    #[test]
    fn the_freeze_lines_are_unchanged_by_the_shared_helpers() {
        let silent = vec![("Wdf01000.sys".to_string(), 0.0)];
        let continued = vec![("dxgkrnl.sys".to_string(), 0.68)];
        assert_eq!(
            flow_lines("freeze", &silent, &continued, Some(Flow::Silent)),
            vec![
                "    Interrupt sources that STOPPED during the freeze: Wdf01000.sys (0% of its usual rate)",
                "    Interrupt sources that kept going:                dxgkrnl.sys (68% of its usual rate)",
                "    Timer DPCs (the clock that wakes threads): stopped",
            ]
        );
        assert!(flow_lines("freeze", &[], &[], None).is_empty());
        let w = |disk, role, waited: f64, io_end: f64, op| DiskWait {
            disk,
            waited: ms(waited),
            op,
            own_fault: false,
            role,
            io_end: ms(io_end),
        };
        let start = ms(1000.0);
        assert_eq!(
            coincided_lines("freeze", true, &w(Some(6), Role::Trigger, 2100.0, 1900.0, b'W'), Some("disk 6 (I:)"), start),
            vec![
                "    Coincided with: a write request to disk 6 (I:) that was already outstanding 1200 ms before the freeze began and ended",
                "                    with it (2100 ms in all). Correlation, not proof.",
            ]
        );
        assert_eq!(
            coincided_lines("freeze", true, &w(Some(5), Role::Victim, 878.0, 1887.0, b'W'), Some("disk 5"), start),
            vec![
                "    Coincided with: a 878 ms write request to disk 5, which began after the freeze had already started,",
                "                    so the freeze is what made it slow, not the other way round.",
            ]
        );
        assert_eq!(
            coincided_lines("freeze", true, &w(Some(1), Role::Overlap, 900.0, 2500.0, b'R'), Some("disk 1"), start),
            vec!["    Coincided with: a 900 ms read request to disk 1 that overlapped it. Correlation, not proof."]
        );
        assert_eq!(
            coincided_lines("freeze", true, &w(None, Role::Victim, 880.0, 1882.0, b'R'), None, start),
            vec!["    Coincided with: this tool's own thread waiting 880 ms for memory from disk"]
        );
        // A stall on some of the processors does not stop every path a request's answer could take,
        // so it never says it made the request slow.
        let kernel = coincided_lines("stall", false, &w(Some(5), Role::Victim, 878.0, 1887.0, b'W'), Some("disk 5"), start);
        assert!(kernel.iter().all(|l| !l.contains("made it slow")), "{kernel:?}");
        assert!(kernel.join(" ").contains("Correlation, not proof"), "{kernel:?}");
    }

    /// Steady Wdf01000 DPCs and timer DPCs for 5 s before, as in the field logs.
    fn steady_reference() -> Vec<ExecRec> {
        let mut r = Vec::new();
        for i in 0..2500 {
            r.push(dpc(0, -5000.0 + i as f64 * 2.0, 0.01, MOD_A + 0x10));
            r.push(exec_rec(1, KIND_TIMER_DPC, -5000.0 + i as f64 * 2.0, 0.01, MOD_B + 0x10));
        }
        r
    }

    /// The field shape on a kernel-level stall that is not a whole-PC freeze: DPCs kept flowing on
    /// the stalled CPU, the USB controller went quiet and so did the timer DPCs. The DPC-flow guard
    /// still holds (no raised-IRQL claim) and the culprit is unchanged, so the tally is too; the
    /// timer check only narrows the verdict's wording.
    #[test]
    fn a_kernel_stall_with_dpcs_flowing_gets_the_interrupt_and_timer_checks() {
        let modules = ModuleMap::for_test(&[("Wdf01000.sys", MOD_A, 0x1000), ("ntoskrnl.exe", MOD_B, 0x1000)]);
        let mut az = Analyzer::for_test(modules, ProcNames::for_test(&[]), true);
        let s = stall(3, 0.0, 400.0);
        // Ordinary DPCs of another driver right through the stall on CPU 3; no Wdf01000, no timers.
        let execs: Vec<ExecRec> = (0..400).map(|i| dpc(3, i as f64, 0.01, MOD_B + 0x20)).collect();
        let mut ev = evidence(execs, vec![], HashMap::new());
        ev.ref_execs = steady_reference();
        ev.ref_seconds = 5.0;
        assert_eq!(az.verdict_kernel(&[s], &ev, &no_probes()).0, "not woken (timers or scheduling)");
        let (silent, _, timer) = az.continuity(&ev, s.start, s.end);
        assert!(silent.iter().any(|(n, _)| n == "Wdf01000.sys"), "{silent:?}");
        assert_eq!(timer, Some(Flow::Silent));
    }

    /// A slow request that began after a kernel-level stall had started is reported as a
    /// coincidence, but only a whole-PC freeze takes it off its drive's slow count.
    #[test]
    fn a_kernel_stall_never_marks_a_disk_request_as_its_victim() {
        let mut az = Analyzer::for_test(ModuleMap::for_test(&[]), ProcNames::for_test(&[]), false);
        let victim = IoRec {
            end: ms(887.0),
            dur: ms(878.0),
            disk: 5,
            tid: 1,
            pid: 4,
            size: 4096,
            op: b'W',
            file: 0,
            irp: 0,
            offset: 0,
            irp_flags: 0,
        };
        az.disk_slow.insert(5, vec![SlowSeen { end: victim.end, dur: victim.dur, victim: false }]);
        let mut ev = evidence(vec![], vec![], HashMap::new());
        ev.ios = vec![victim];
        let stalls = [stall(0, 0.0, 886.0), stall(1, 0.0, 886.0)];
        assert_eq!(az.verdict_kernel(&stalls, &ev, &no_probes()).0, "unexplained", "a coincidence is not a culprit");
        assert!(!az.disk_slow[&5][0].victim, "still counted against its drive");
    }

    /// The measuring thread itself took a hard page fault for most of the stall: nothing held the
    /// processor, whatever the samples landed in.
    #[test]
    fn a_kernel_stall_where_the_measuring_thread_was_paging_is_put_down_to_paging() {
        let modules = ModuleMap::for_test(&[("ntoskrnl.exe", MOD_A, 0x1000)]);
        let mut az = Analyzer::for_test(modules, ProcNames::for_test(&[(4, "System (kernel threads)")]), false);
        az.probe_tids.add(700, Some(2));
        let s = stall(2, 0.0, 60.0);
        // Samples that would otherwise read as "ntoskrnl.exe at raised IRQL".
        let samples: Vec<(SampleRec, u32)> = (0..10).map(|i| sample(2, i as f64 * 5.0, MOD_A + 0x10, 4)).collect();
        let mut ev = evidence(vec![], samples.clone(), HashMap::new());
        assert_eq!(az.verdict_kernel(&[s], &ev, &no_probes()).0, "driver ntoskrnl.exe");
        ev.faults = vec![FaultRec { start: ms(1.0), end: ms(55.0), tid: 700, pid: 9000, bytes: 4096, file: 0 }];
        assert_eq!(az.verdict_kernel(&[s], &ev, &no_probes()).0, "waiting on paging");
        // Another thread's fault, even in the same process, says nothing about this one.
        ev.faults[0].tid = 701;
        assert_eq!(az.verdict_kernel(&[s], &ev, &no_probes()).0, "driver ntoskrnl.exe");
    }

    // --- issue #19: one saturated core ------------------------------------------------------

    /// A DPC running on an idle processor interrupts the idle thread; that time is not idle.
    #[test]
    fn interrupt_time_on_an_idle_core_is_not_counted_as_idle() {
        let samples: Vec<(SampleRec, u32)> = (0..10).map(|i| sample(0, i as f64, KERNEL_SPACE + 0x10, 0)).collect();
        let execs = vec![dpc(0, 0.0, 3.5, MOD_A), isr(0, 1.0, 0.5, MOD_B), dpc(0, 8.0, 0.5, MOD_A)];
        let loads = core_loads(&samples, &execs);
        assert_eq!(loads, vec![CoreLoad { cpu: 0, samples: 10, idle: 5, interrupt: 5 }]);
        assert!((idle_share(&loads) - 0.5).abs() < 1e-9);
        assert_eq!(merged_spans(&execs, 0), vec![(0, ms(3.5)), (ms(8.0), ms(8.5))], "nested spans merge");
        assert_eq!(idle_share(&[]), 0.0);
    }

    fn load(cpu: u16, samples: u32, idle: u32) -> CoreLoad {
        CoreLoad { cpu, samples, idle, interrupt: 0 }
    }

    #[test]
    fn one_or_a_few_pegged_cores_are_told_from_a_busy_pc() {
        // One of eight pegged, the rest ~90% idle.
        let mut loads: Vec<CoreLoad> = (0..8).map(|c| load(c, 30, 27)).collect();
        loads[3] = load(3, 30, 1);
        let p = pegged_cores(&loads).expect("one pegged core");
        assert_eq!((p.cores.len(), p.cores[0].0, p.others), (1, 3, 7));
        assert!((p.others_idle - 0.9).abs() < 1e-9);
        // Three of eight is more than "a few" (a quarter), and a PC where the rest are busy too
        // is simply busy.
        let mut three = loads.clone();
        three[4] = load(4, 30, 0);
        three[5] = load(5, 30, 0);
        assert_eq!(pegged_cores(&three), None);
        let busy: Vec<CoreLoad> = (0..8).map(|c| if c == 3 { load(c, 30, 0) } else { load(c, 30, 12) }).collect();
        assert_eq!(pegged_cores(&busy), None);
        // A core with too few samples is not judged at all, in either direction.
        let mut thin = loads.clone();
        thin[3] = load(3, 3, 0);
        assert_eq!(pegged_cores(&thin), None);
        // Exactly the bar: 9 of 10 busy is pegged.
        let edge: Vec<CoreLoad> = vec![load(0, 10, 1), load(1, 10, 9)];
        assert_eq!(pegged_cores(&edge).map(|p| p.cores[0].0), Some(0));
        assert_eq!(pegged_cores(&[load(0, 30, 0)]), None, "one CPU has no others to idle");
    }

    /// A starvation stall on an otherwise idle 8-CPU PC with one core pegged by one program:
    /// the average said "idle", and the report now also says which core was busy with what.
    #[test]
    fn a_starvation_stall_names_the_one_busy_core_and_what_held_it() {
        let procs = ProcNames::for_test(&[(32468, "SignalRgb.exe")]);
        let mut az = Analyzer::for_test(ModuleMap::for_test(&[("nvlddmkm.sys", MOD_A, 0x1000)]), procs, true);
        az.topo = crate::topology::Topology::build(&[8], &[]);
        let mut samples = Vec::new();
        for cpu in 0..8u16 {
            for i in 0..30 {
                let pid = if cpu == 3 || i % 10 == 0 { 32468 } else { 0 };
                samples.push(sample(cpu, i as f64, USER_IP, pid));
            }
        }
        let ev = evidence(vec![], samples.clone(), HashMap::new());
        let (culprit, holder) = az.verdict_sched(&ev, 0, ms(30.0), &no_probes());
        assert_eq!(culprit, "scheduling delay with idle CPUs", "the culprit stays what the evidence supports");
        assert_eq!(holder, Some(CoreHolder::Program("SignalRgb.exe (32468)".into())));

        // The same core held by a driver's interrupt handling instead: the samples land in the idle
        // thread, which the DPC records turn into "busy".
        let idle_samples: Vec<(SampleRec, u32)> = samples.iter().map(|(s, _)| (SampleRec { tid: 0, ..*s }, 0)).collect();
        let mut ev = evidence((0..30).map(|i| dpc(3, i as f64 - 0.1, 0.9, MOD_A + 0x10)).collect(), idle_samples, HashMap::new());
        ev.execs.push(dpc(3, 29.0, 2.0, MOD_A + 0x10));
        let (_, holder) = az.verdict_sched(&ev, 0, ms(30.0), &no_probes());
        assert_eq!(holder, Some(CoreHolder::Driver("nvlddmkm.sys".into())));
    }

    // --- issue #19: per-incident context --------------------------------------------------------

    #[test]
    fn an_incident_states_throttling_and_memory_pressure_only_when_present() {
        assert_eq!(context_line(None, Some(60)), None, "an ordinary amount of memory in use is not worth a line");
        assert_eq!(context_line(None, None), None);
        assert_eq!(context_line(None, Some(91)).as_deref(), Some("    Context: memory was 91% in use when this was examined."));
        assert_eq!(
            context_line(Some("the processor was being slowed down at the time".into()), Some(85)).as_deref(),
            Some("    Context: the processor was being slowed down at the time; memory was 85% in use when this was examined.")
        );
    }
}
