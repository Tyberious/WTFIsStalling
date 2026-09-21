//! Latency probes: threads that ask to be woken on a fixed interval and measure how late
//! the wake-up actually was.
//!
//! * Kernel probes: one per CPU, pinned, priority 31 (REALTIME class + TIME_CRITICAL). No
//!   thread can outrank them, so only DPCs, ISRs, code at raised IRQL, SMIs/firmware or a
//!   hypervisor can delay them. They live in a child process (`--probe-child`) so the
//!   real-time priority class doesn't also lift the parent's analysis threads; the child
//!   reports over its stdout. QPC is system-wide, so timestamps line up across processes. In
//!   light mode they wake every 2 ms instead, which costs the PC about half as much.
//! * Scheduler probe: a single unpinned normal-priority thread in the parent. It is delayed
//!   when every CPU is busy with equal-or-higher priority work, i.e. what an ordinary app
//!   or game feels.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::windows::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::Arc;
use std::time::Duration;

use windows_sys::Win32::Media::timeBeginPeriod;
use windows_sys::Win32::System::Console::SetConsoleCtrlHandler;
use windows_sys::Win32::System::SystemInformation::GROUP_AFFINITY;
use windows_sys::Win32::System::Threading::{
    CreateWaitableTimerExW, CreateWaitableTimerW, GetCurrentProcess, GetCurrentThread, GetCurrentThreadId, GetPriorityClass,
    SetPriorityClass, SetThreadGroupAffinity, SetThreadPriority, SetWaitableTimer, WaitForSingleObject, REALTIME_PRIORITY_CLASS,
    THREAD_PRIORITY_IDLE, THREAD_PRIORITY_NORMAL, THREAD_PRIORITY_TIME_CRITICAL,
};

use crate::overhead::PROBE_MS_NORMAL;
use crate::topology::{self, Slot};
use crate::util::{ms_to_ticks, qpc};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StallKind {
    Kernel,
    Scheduler,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Stall {
    pub kind: StallKind,
    /// System-wide processor index, the same numbering ETW uses (see `topology`).
    pub cpu: Option<u16>,
    /// When the thread should have run.
    pub start: i64,
    /// When it actually ran.
    pub end: i64,
    /// Below the stall threshold: not reported by itself, but kept briefly so that a moment
    /// the user flags ("I felt it") can be examined at finer grain.
    pub minor: bool,
}

/// Lateness from which wake-ups are kept as minor, per probe kind (ms).
const MINOR_KERNEL_MS: f64 = 1.0;
const MINOR_SCHED_MS: f64 = 8.0;

#[derive(Default)]
pub struct ProbeStats {
    pub max_kernel: Arc<AtomicI64>,
    pub max_sched: Arc<AtomicI64>,
    /// Set once the child confirms it got the real-time priority class.
    pub realtime: AtomicBool,
    /// Which threads are doing the measuring; see `ProbeTids`.
    pub tids: Arc<ProbeTids>,
}

/// The thread ids of the measuring threads, and the processor each is pinned to.
///
/// The analysis needs these to reconstruct, from the context-switch trace, what the scheduler did
/// to a probe during a stall: a thread that was never made runnable was never woken. The parent's
/// own scheduler-probe thread registers here directly; the real-time probes live in a child
/// process and report theirs over the existing stdout protocol.
///
/// Bounded by construction: one entry per logical processor plus one, added once at start-up.
#[derive(Default)]
pub struct ProbeTids(std::sync::Mutex<Vec<ProbeThread>>);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ProbeThread {
    pub tid: u32,
    /// The system-wide processor index it is pinned to; `None` for the unpinned parent probe.
    pub cpu: Option<u16>,
}

/// More probe threads than any machine has, so a garbled or hostile stdout stream cannot grow
/// this list. 1024 logical processors is past what Windows itself supports in one system.
const MAX_PROBE_THREADS: usize = 1100;

impl ProbeTids {
    pub fn add(&self, tid: u32, cpu: Option<u16>) {
        if tid == 0 {
            return;
        }
        let mut v = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if v.len() < MAX_PROBE_THREADS && !v.iter().any(|t| t.tid == tid) {
            v.push(ProbeThread { tid, cpu });
        }
    }

    pub fn all(&self) -> Vec<ProbeThread> {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Entries added since `from`, for the child's reporting loop.
    fn since(&self, from: usize) -> Vec<ProbeThread> {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).get(from..).unwrap_or_default().to_vec()
    }
}

/// First argument that turns either binary into the probe helper process.
pub const CHILD_ARG: &str = "--probe-child";

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const CREATE_WAITABLE_TIMER_HIGH_RESOLUTION: u32 = 2;
const TIMER_ALL_ACCESS: u32 = 0x1F_0003;
const INFINITE: u32 = u32::MAX;
const WAIT_OBJECT_0: u32 = 0;

/// Everything one probe thread needs. A struct rather than seven-plus arguments.
struct ProbeCfg {
    kind: StallKind,
    pin: Option<Slot>,
    interval_ms: f64,
    threshold_ms: f64,
    tx: Sender<Stall>,
    stop: Arc<AtomicBool>,
    max_slot: Arc<AtomicI64>,
    /// Where this thread registers its own id, so the scheduler trace can be read against it.
    tids: Arc<ProbeTids>,
}

fn run(cfg: ProbeCfg) {
    let ProbeCfg { kind, pin, interval_ms, threshold_ms, tx, stop, max_slot, tids } = cfg;
    let cpu = pin.map(|s| s.cpu);
    tids.add(unsafe { GetCurrentThreadId() }, cpu);
    unsafe {
        let me = GetCurrentThread();
        if let Some(slot) = pin {
            // The mask is group-relative: index is always < 64, however many CPUs the PC has.
            // Pinning outside our own group is allowed on every supported Windows: since
            // Windows 11 threads span all groups by default, and before that "if a thread is
            // assigned to a different group than the process, the process's affinity is updated
            // to include the thread's affinity and the process becomes a multi-group process"
            // (learn.microsoft.com/windows/win32/procthread/processor-groups).
            let ga = GROUP_AFFINITY { Mask: 1usize << slot.index, Group: slot.group, Reserved: [0; 3] };
            SetThreadGroupAffinity(me, &ga, null_mut());
        }
        SetThreadPriority(me, if kind == StallKind::Kernel { THREAD_PRIORITY_TIME_CRITICAL } else { THREAD_PRIORITY_NORMAL });

        let mut timer = CreateWaitableTimerExW(null(), null(), CREATE_WAITABLE_TIMER_HIGH_RESOLUTION, TIMER_ALL_ACCESS);
        if timer.is_null() {
            // Pre-1803 Windows 10: regular timer, relies on timeBeginPeriod(1).
            timer = CreateWaitableTimerW(null(), 1, null());
        }
        if timer.is_null() {
            return;
        }

        let interval = ms_to_ticks(interval_ms);
        let threshold = ms_to_ticks(threshold_ms);
        let minor_threshold = ms_to_ticks(threshold_ms.min(if kind == StallKind::Kernel { MINOR_KERNEL_MS } else { MINOR_SCHED_MS }));
        let due: i64 = -((interval_ms * 10_000.0) as i64); // relative, 100 ns units
        let warmup_until = qpc() + ms_to_ticks(500.0);
        let mut early_wakes = 0;

        while !stop.load(Ordering::Relaxed) {
            let t0 = qpc();
            if SetWaitableTimer(timer, &due, 0, None, null(), 0) == 0 || WaitForSingleObject(timer, INFINITE) != WAIT_OBJECT_0 {
                break;
            }
            let t1 = qpc();
            // A wait that returns immediately would turn this into a priority-31 busy loop
            // on every CPU, i.e. a frozen machine. Bail out long before that matters.
            if t1 - t0 < interval / 4 {
                early_wakes += 1;
                if early_wakes > 50 {
                    break;
                }
                continue;
            }
            early_wakes = 0;
            let late = (t1 - t0) - interval;
            // > 10 s is a sleep/resume or a debugger, not a hitch.
            if t0 < warmup_until || late > ms_to_ticks(10_000.0) {
                continue;
            }
            max_slot.fetch_max(late, Ordering::Relaxed);
            if late >= minor_threshold {
                let _ = tx.send(Stall { kind, cpu, start: t0 + interval, end: t1, minor: late < threshold });
            }
        }
    }
}

/// Parent side: the normal-priority probe thread. Its thread id is local, so it registers itself
/// in the shared stats directly rather than going through the child protocol.
pub fn spawn_scheduler_probe(threshold_ms: f64, tx: Sender<Stall>, stop: Arc<AtomicBool>, stats: Arc<ProbeStats>) {
    // The parent's own `ProbeStats::tids` is what the analyzer reads, so this probe writes
    // straight into it; the reader thread below fills in the child's from its stdout.
    let cfg = ProbeCfg {
        kind: StallKind::Scheduler,
        pin: None,
        interval_ms: 4.0,
        threshold_ms,
        tx,
        stop,
        max_slot: stats.max_sched.clone(),
        tids: stats.tids.clone(),
    };
    std::thread::Builder::new().name("probe-scheduler".into()).spawn(move || run(cfg)).expect("spawn scheduler probe");
}

/// The wake-up interval the child is asked for, kept inside sane bounds. A tiny interval would
/// turn a priority-31 thread on every CPU into a busy loop, i.e. a frozen machine, so a garbage
/// command line must not be able to produce one.
pub fn sane_interval_ms(ms: f64) -> f64 {
    if ms.is_finite() {
        ms.clamp(0.5, 10.0)
    } else {
        PROBE_MS_NORMAL
    }
}

/// One line of the child's stdout protocol (see `child_main`).
#[derive(Clone, Copy, PartialEq, Debug)]
enum ChildMsg {
    Stall(Stall),
    /// Keep-alive carrying the worst lateness so far.
    Max(i64),
    /// The priority class the child actually got.
    Class(u32),
    Thread(ProbeThread),
}

/// Parses one line of the child's stdout. `None` for anything not understood: the pipe carries
/// whatever the child wrote, and a line that does not match exactly is dropped rather than
/// guessed at. A tid is a Windows thread id (a u32) and a processor index a u16, so a number
/// outside those ranges is a garbled line, not a probe on processor 0.
fn parse_child_line(line: &str) -> Option<ChildMsg> {
    let mut it = line.split(' ');
    let tag = it.next()?;
    let mut nums: Vec<i64> = Vec::new();
    for word in it {
        // Every field of every message is a number; one that is not means the line is not one of
        // ours, and must not be silently skipped over to make the rest line up.
        nums.push(word.parse().ok()?);
    }
    Some(match (tag, nums.as_slice()) {
        ("S" | "L", [cpu, start, end]) => ChildMsg::Stall(Stall {
            kind: StallKind::Kernel,
            cpu: Some(u16::try_from(*cpu).ok()?),
            start: *start,
            end: *end,
            minor: tag == "L",
        }),
        ("M", [max]) => ChildMsg::Max(*max),
        ("C", [class]) => ChildMsg::Class(u32::try_from(*class).ok()?),
        ("T", [tid, -1]) => ChildMsg::Thread(ProbeThread { tid: u32::try_from(*tid).ok()?, cpu: None }),
        ("T", [tid, cpu]) => ChildMsg::Thread(ProbeThread { tid: u32::try_from(*tid).ok()?, cpu: Some(u16::try_from(*cpu).ok()?) }),
        _ => return None,
    })
}

/// Parent side: start the real-time child and forward what it reports.
pub fn spawn_kernel_probes(threshold_ms: f64, interval_ms: f64, tx: Sender<Stall>, stats: Arc<ProbeStats>) -> std::io::Result<Child> {
    let mut child = Command::new(std::env::current_exe()?)
        .arg(CHILD_ARG)
        .arg(threshold_ms.to_string())
        .arg(sane_interval_ms(interval_ms).to_string())
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let out = child.stdout.take().expect("piped stdout");
    std::thread::Builder::new()
        .name("probe-reader".into())
        .spawn(move || {
            for line in BufReader::new(out).lines().map_while(Result::ok) {
                match parse_child_line(&line) {
                    Some(ChildMsg::Stall(s)) => {
                        stats.max_kernel.fetch_max(s.end - s.start, Ordering::Relaxed);
                        let _ = tx.send(s);
                    }
                    Some(ChildMsg::Max(max)) => {
                        stats.max_kernel.fetch_max(max, Ordering::Relaxed);
                    }
                    Some(ChildMsg::Class(class)) => stats.realtime.store(class == REALTIME_PRIORITY_CLASS, Ordering::Relaxed),
                    Some(ChildMsg::Thread(t)) => stats.tids.add(t.tid, t.cpu),
                    None => {}
                }
            }
        })
        .expect("spawn probe reader");
    Ok(child)
}

/// Child side. Exits when the parent closes our stdin (or dies).
///
/// Protocol on stdout, one line each: `C <priority class>` once at the start, `T <tid> <cpu>`
/// once per probe thread as it starts (`<cpu>` = -1 for an unpinned one), `S`/`L <cpu> <start>
/// <end>` for a stall / a sub-threshold blip, `M <max>` as a keep-alive. `<cpu>` is the
/// system-wide processor index, the same numbering ETW reports.
///
/// The parent matches on the tag and the shape of the numbers and ignores anything else, so a
/// line it does not understand costs nothing. Parent and child are always the same binary (the
/// child is this exe re-run with `--probe-child`), so there is no older child to be compatible
/// with; the tolerance is against a garbled pipe, not against a version skew.
///
/// `interval_ms` is how often each probe asks to be woken (2 ms in light mode instead of 1 ms).
/// A stall is still measured as lateness beyond the requested wake-up, so its length means the
/// same either way; what a longer interval costs is resolution, because a blockage that fits
/// between two wake-ups is not seen at all and a measured length can fall short of the real one
/// by up to one interval.
pub fn child_main(threshold_ms: f64, interval_ms: f64) -> ! {
    crate::etw::enable_privilege("SeIncreaseBasePriorityPrivilege");
    unsafe {
        SetConsoleCtrlHandler(None, 1); // Ctrl+C is the parent's business
        SetPriorityClass(GetCurrentProcess(), REALTIME_PRIORITY_CLASS);
        timeBeginPeriod(1);
    }
    // One probe per logical CPU, across every processor group: past 64 CPUs Windows splits the
    // machine into groups and a thread pinned in group 0 would never see the rest.
    let slots = topology::processor_slots(&topology::active_groups());
    let interval_ms = sane_interval_ms(interval_ms);

    std::thread::spawn(|| {
        let mut sink = Vec::new();
        let _ = std::io::stdin().read_to_end(&mut sink);
        std::process::exit(0);
    });

    let (tx, rx) = mpsc::channel::<Stall>();
    let stop = Arc::new(AtomicBool::new(false));
    let max = Arc::new(AtomicI64::new(0));
    let tids = Arc::new(ProbeTids::default());
    for slot in slots {
        let cfg = ProbeCfg {
            kind: StallKind::Kernel,
            pin: Some(slot),
            interval_ms,
            threshold_ms,
            tx: tx.clone(),
            stop: stop.clone(),
            max_slot: max.clone(),
            tids: tids.clone(),
        };
        std::thread::spawn(move || run(cfg));
    }

    // Reporting is the only non-probe work in this process; keep it at the bottom of the
    // real-time range.
    unsafe { SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_IDLE) };
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "C {}", unsafe { GetPriorityClass(GetCurrentProcess()) });
    // Each probe thread registers itself as it starts; this loop forwards whatever is new. The
    // wait below is at most a second, so every probe is announced within a second of start-up,
    // which is inside the probes' own 500 ms warm-up plus the first tick of analysis.
    let mut announced = 0usize;
    loop {
        for t in tids.since(announced) {
            announced += 1;
            if writeln!(out, "T {} {}", t.tid, t.cpu.map_or(-1i32, i32::from)).is_err() {
                std::process::exit(0);
            }
        }
        let msg = match rx.recv_timeout(Duration::from_secs(1)) {
            Ok(s) => format!("{} {} {} {}", if s.minor { "L" } else { "S" }, s.cpu.unwrap_or(0), s.start, s.end),
            Err(_) => format!("M {}", max.load(Ordering::Relaxed)),
        };
        if writeln!(out, "{msg}").and_then(|_| out.flush()).is_err() {
            std::process::exit(0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::overhead::PROBE_MS_LIGHT;

    /// Priority-31 threads on every CPU: whatever reaches the child's command line, the wait
    /// between wake-ups must stay a real wait.
    #[test]
    fn the_probe_interval_can_never_become_a_spin() {
        assert_eq!(sane_interval_ms(PROBE_MS_NORMAL), 1.0);
        assert_eq!(sane_interval_ms(PROBE_MS_LIGHT), 2.0);
        assert_eq!(sane_interval_ms(0.0), 0.5);
        assert_eq!(sane_interval_ms(-5.0), 0.5);
        assert_eq!(sane_interval_ms(1e9), 10.0);
        assert_eq!(sane_interval_ms(f64::NAN), PROBE_MS_NORMAL);
        assert_eq!(sane_interval_ms(f64::INFINITY), PROBE_MS_NORMAL);
    }

    #[test]
    fn the_child_protocol_round_trips_every_message_it_can_send() {
        assert_eq!(parse_child_line("C 256"), Some(ChildMsg::Class(REALTIME_PRIORITY_CLASS)));
        assert_eq!(parse_child_line("M 12345"), Some(ChildMsg::Max(12_345)));
        assert_eq!(parse_child_line("T 4242 3"), Some(ChildMsg::Thread(ProbeThread { tid: 4242, cpu: Some(3) })));
        assert_eq!(parse_child_line("T 77 -1"), Some(ChildMsg::Thread(ProbeThread { tid: 77, cpu: None })));
        // Exactly the line the child writes, for a machine past 255 processors.
        let t = ProbeThread { tid: 4_294_967_295, cpu: Some(300) };
        assert_eq!(parse_child_line(&format!("T {} {}", t.tid, t.cpu.map_or(-1i32, i32::from))), Some(ChildMsg::Thread(t)));
        match parse_child_line("S 5 1000 2000") {
            Some(ChildMsg::Stall(s)) => {
                assert_eq!((s.kind, s.cpu, s.start, s.end, s.minor), (StallKind::Kernel, Some(5), 1000, 2000, false))
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(parse_child_line("L 0 1 2"), Some(ChildMsg::Stall(s)) if s.minor));
    }

    /// The pipe carries bytes, not promises: nothing a garbled line can say may become a probe
    /// thread, a processor number or a stall.
    #[test]
    fn garbage_lines_are_ignored_rather_than_guessed_at() {
        for line in [
            "",
            "T",
            "T 4242",
            "T 4242 3 9",
            "T -5 3",             // a negative thread id
            "T 4242 -2",          // -1 is the only negative processor
            "T 4242 99999",       // past any processor index
            "T 99999999999999 3", // past a thread id
            "T abc 3",
            "T 4242 three",
            "Tid 4242 3",
            "t 4242 3",
            "S 5 1000",
            "S -1 1000 2000",
            "C -3",
            "X 1 2 3",
            "  T 4242 3",
            "hello world",
            "\u{1}\u{2}\u{3}",
        ] {
            assert_eq!(parse_child_line(line), None, "{line:?} must be ignored");
        }
    }

    #[test]
    fn the_probe_thread_list_is_deduplicated_and_bounded() {
        let tids = ProbeTids::default();
        tids.add(0, Some(1)); // thread id 0 is not a thread
        tids.add(10, Some(0));
        tids.add(10, Some(7)); // the same thread twice: the first registration wins
        tids.add(11, None);
        assert_eq!(tids.all(), vec![ProbeThread { tid: 10, cpu: Some(0) }, ProbeThread { tid: 11, cpu: None }]);
        assert_eq!(tids.since(1), vec![ProbeThread { tid: 11, cpu: None }]);
        assert!(tids.since(9).is_empty(), "asking past the end is empty, not a panic");
        for tid in 100..100_000 {
            tids.add(tid, Some(0));
        }
        assert_eq!(tids.all().len(), MAX_PROBE_THREADS);
    }
}
