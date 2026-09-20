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
    CreateWaitableTimerExW, CreateWaitableTimerW, GetCurrentProcess, GetCurrentThread, GetPriorityClass, SetPriorityClass,
    SetThreadGroupAffinity, SetThreadPriority, SetWaitableTimer, WaitForSingleObject, REALTIME_PRIORITY_CLASS, THREAD_PRIORITY_IDLE,
    THREAD_PRIORITY_NORMAL, THREAD_PRIORITY_TIME_CRITICAL,
};

use crate::overhead::PROBE_MS_NORMAL;
use crate::topology::{self, Slot};
use crate::util::{ms_to_ticks, qpc};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StallKind {
    Kernel,
    Scheduler,
}

#[derive(Clone, Copy, Debug)]
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
}

/// First argument that turns either binary into the probe helper process.
pub const CHILD_ARG: &str = "--probe-child";

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const CREATE_WAITABLE_TIMER_HIGH_RESOLUTION: u32 = 2;
const TIMER_ALL_ACCESS: u32 = 0x1F_0003;
const INFINITE: u32 = u32::MAX;
const WAIT_OBJECT_0: u32 = 0;

fn run(
    kind: StallKind,
    pin: Option<Slot>,
    interval_ms: f64,
    threshold_ms: f64,
    tx: Sender<Stall>,
    stop: Arc<AtomicBool>,
    max_slot: Arc<AtomicI64>,
) {
    let cpu = pin.map(|s| s.cpu);
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

/// Parent side: the normal-priority probe thread.
pub fn spawn_scheduler_probe(threshold_ms: f64, tx: Sender<Stall>, stop: Arc<AtomicBool>, stats: Arc<ProbeStats>) {
    std::thread::Builder::new()
        .name("probe-scheduler".into())
        .spawn(move || run(StallKind::Scheduler, None, 4.0, threshold_ms, tx, stop, stats.max_sched.clone()))
        .expect("spawn scheduler probe");
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
                let mut it = line.split(' ');
                let tag = it.next().unwrap_or("");
                let nums: Vec<i64> = it.filter_map(|x| x.parse().ok()).collect();
                match (tag, nums.as_slice()) {
                    ("S" | "L", [cpu, start, end]) => {
                        stats.max_kernel.fetch_max(end - start, Ordering::Relaxed);
                        let _ =
                            tx.send(Stall { kind: StallKind::Kernel, cpu: Some(*cpu as u16), start: *start, end: *end, minor: tag == "L" });
                    }
                    ("M", [max]) => {
                        stats.max_kernel.fetch_max(*max, Ordering::Relaxed);
                    }
                    ("C", [class]) => stats.realtime.store(*class as u32 == REALTIME_PRIORITY_CLASS, Ordering::Relaxed),
                    _ => {}
                }
            }
        })
        .expect("spawn probe reader");
    Ok(child)
}

/// Child side. Exits when the parent closes our stdin (or dies).
///
/// Protocol on stdout, one line each: `C <priority class>` once at the start, `S`/`L <cpu>
/// <start> <end>` for a stall / a sub-threshold blip, `M <max>` as a keep-alive. `<cpu>` is the
/// system-wide processor index, the same numbering ETW reports.
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
    for slot in slots {
        let (tx, stop, max) = (tx.clone(), stop.clone(), max.clone());
        std::thread::spawn(move || run(StallKind::Kernel, Some(slot), interval_ms, threshold_ms, tx, stop, max));
    }

    // Reporting is the only non-probe work in this process; keep it at the bottom of the
    // real-time range.
    unsafe { SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_IDLE) };
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "C {}", unsafe { GetPriorityClass(GetCurrentProcess()) });
    loop {
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
}
