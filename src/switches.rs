//! What the scheduler actually did: who was made runnable, who got a processor, who did not, and
//! who was blocked waiting for something.
//!
//! Everything here is a pure function over a slice of `CSwitch` and `ReadyThread` records, so all
//! of it is tested from synthetic streams. Two questions are asked:
//!
//! 1. **Why was a measuring thread late?** (`classify_probe`) The field logs behind issue #15
//!    showed every real-time probe on every processor, and the normal-priority probe in a
//!    different process, waking late by the same amount at the same instant, while ordinary DPCs
//!    kept running. That rules out "a processor was held", but it cannot tell apart "nothing woke
//!    them" from "they were woken and not run". These two event classes can: a thread that was
//!    never made READY was never woken, and that is a timer / clock / firmware problem below the
//!    scheduler. A thread made READY on time and left in the queue is a scheduler or platform
//!    anomaly - and if the processor was idle throughout, a plain one.
//!
//! 2. **Who was kept waiting?** (`waits`) At a moment the user flagged, which threads spent the
//!    longest runnable-but-not-running and the longest blocked, what held the processor instead,
//!    and which thread woke them.
//!
//! What this file never claims: WHICH lock, and WHY. A wait reason names a kind of wait, not a
//! culprit, and a readying thread is the thread that signalled - not necessarily the one at fault.

use std::collections::HashMap;

use crate::state::{ReadyRec, SwitchRec};
use crate::util::ms_to_ticks;

/// `OldThreadState` values, documented on the CSwitch class page:
/// 0 Initialized, 1 Ready, 2 Running, 3 Standby, 4 Terminated, 5 Waiting, 6 Transition,
/// 7 DeferredReady. https://learn.microsoft.com/en-us/windows/win32/etw/cswitch
pub const STATE_READY: i8 = 1;
pub const STATE_STANDBY: i8 = 3;
pub const STATE_TERMINATED: i8 = 4;
pub const STATE_WAITING: i8 = 5;
pub const STATE_DEFERRED_READY: i8 = 7;

/// `NewThreadId` / `OldThreadId` of the idle thread, i.e. the processor having nothing to do.
pub const IDLE_TID: u32 = 0;

/// A thread runnable but not running for this long is something a person can feel: one frame at
/// 60 per second is 16.7 ms, so a thread that has been ready and waiting for 25 ms has already
/// missed a frame and is about to miss another, and 25 ms is an audible gap in sound.
pub const FELT_READY_MS: f64 = 25.0;
/// Threads wait for things all day, so being blocked has to last much longer before it is worth
/// a word at all...
pub const FELT_BLOCKED_MS: f64 = 50.0;
/// ...and past this a thread was parked for the duration rather than held up by a hitch.
pub const MAX_BLOCKED_MS: f64 = 2000.0;

/// Distinct threads tracked by `waits` in one window. A window is a few seconds and a busy PC has
/// a few thousand threads; past this the rest are ignored rather than letting the map grow.
const MAX_THREADS: usize = 20_000;
/// Rows returned, worst first. Far more than any report shows, and enough to add up per process.
const MAX_ROWS: usize = 512;

/// Plain words for which band a thread priority (0-31, as `CSwitch` reports it) sits in.
///
/// Microsoft's base-priority table ("Scheduling Priorities",
/// https://learn.microsoft.com/en-us/windows/win32/procthread/scheduling-priorities) puts every
/// priority class at 1-15 except REALTIME_PRIORITY_CLASS, which is 16-31; "Only the zero-page
/// thread can have a priority of zero". "The system does not boost the priority of threads with a
/// base priority level between 16 and 31" (".../procthread/priority-boosts").
///
/// Only the BAND is said, never the process's class: the number in a switch record is the dynamic
/// priority, a 13 can be a HIGH_PRIORITY_CLASS thread or a boosted normal one, and the Multimedia
/// Class Scheduler puts ordinary programs' audio and game threads at 16-26
/// (".../procthread/multimedia-class-scheduler-service", "Thread Priorities"). So "the real-time
/// range" is unambiguous and "a real-time program" would not be.
pub fn priority_band(prio: i8) -> Option<&'static str> {
    match prio {
        16..=31 => Some("the real-time range, 16-31, above every ordinary thread"),
        1..=15 => Some("the ordinary range, 1-15"),
        _ => None,
    }
}

/// Plain words for a `OldThreadWaitReason` (a KWAIT_REASON). The value table is Microsoft's, on
/// the CSwitch class page; the wording is this tool's. `None` means "nothing worth saying": the
/// report then gives the duration without naming a kind of wait, which is better than jargon.
///
/// These are kinds of wait, never causes. "Waiting for a lock another thread holds" does not say
/// which lock, and nothing here may be read as saying so.
pub fn wait_reason_name(reason: i8) -> Option<&'static str> {
    Some(match reason {
        1 | 8 => "waiting for free memory",                                  // FreePage, WrFreePage
        2 | 9 => "waiting for memory to be read back from disk",             // PageIn, WrPageIn
        3 | 10 => "waiting for Windows to free up kernel memory",            // PoolAllocation
        4 | 11 => "sleeping on purpose",                                     // DelayExecution
        5 | 12 => "suspended by something else",                             // Suspended
        6 | 13 => "waiting on a lock, an event or a message",                // UserRequest
        0 | 7 => "waiting inside Windows",                                   // Executive, WrExecutive
        15 => "idle, waiting for work to arrive",                            // WrQueue
        16 | 17 => "waiting for another program to answer",                  // WrLpcReceive, WrLpcReply
        18 => "waiting on memory management",                                // WrVirtualMemory
        19 => "waiting for memory to be written out to disk",                // WrPageOut
        24 => "held back by a processor usage limit",                        // WrCpuRateControl
        21 | 26..=29 | 34 | 35 => "waiting for a lock another thread holds", // WrKeyedEvent, WrKernel, WrResource, WrPushLock, WrMutex, Wr(Fast|Guarded)Mutex
        _ => return None,
    })
}

/// The lock-like kinds of wait: exactly the reasons `wait_reason_name` calls "waiting for a lock
/// another thread holds" (WrKeyedEvent 21, WrKernel 26, WrResource 27, WrPushLock 28, WrMutex 29,
/// WrFastMutex 34, WrGuardedMutex 35; values from the CSwitch page). Which lock is never known.
pub fn lock_wait(reason: i8) -> bool {
    matches!(reason, 21 | 26..=29 | 34 | 35)
}

/// Is this a thread that chose to stop, rather than one held up by something?
///
/// A program with a timer loop sleeps thousands of times a run, and a thread-pool worker sits on
/// its queue whenever there is nothing to do. Reporting either as "waiting" would flag every
/// program on the PC, so those reasons are dropped before anything is ranked.
pub fn voluntary_wait(reason: i8) -> bool {
    matches!(reason, 4 | 11 | 5 | 12 | 15 | 22) // DelayExecution, Suspended, WrQueue, WrTerminated
}

/// Can a long wait of this kind count as a program being HELD UP?
///
/// Not a voluntary one, and not UserRequest / WrUserRequest (6 / 13): that is what every window's
/// message loop and every event wait in a program sits in when there is nothing to do, and the
/// trace cannot tell "idle" from "stuck" for it. Measured live (2026-09-24): at one flagged moment
/// msedge.exe, a CEF helper, RustRover and Claude each "waited" ~1,996 ms in it, which is idle
/// loops waking on their own 2 s timeouts, and the report made the first of them its top suspect.
/// A real lock has its own reasons (WrResource, WrPushLock, the mutexes) and disk and paging
/// waits theirs, so those still count.
pub fn held_up_wait(reason: i8) -> bool {
    !voluntary_wait(reason) && !matches!(reason, 6 | 13)
}

/// What held a processor while some other thread was waiting for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RanInstead {
    /// The processor had nothing at all to do for (almost) the whole wait. A thread that is ready
    /// and is not run on an idle processor is the scheduler or the platform, not contention.
    Idle,
    /// One thread held it longest.
    Thread { tid: u32, prio: i8, held: i64 },
    /// No switch records for that processor in the window: nothing can be said.
    Unknown,
}

/// Idle has to hold at least this share of the wait before the report will call the processor
/// idle: a processor that was busy for a third of it was not "doing nothing".
const IDLE_SHARE: f64 = 0.9;

/// What occupied `cpu` between `from` and `to`, ignoring `exclude` (the waiting thread itself).
///
/// The thread running on a processor at any instant is the `NewThreadId` of the last switch on
/// that processor at or before it, so this replays the switches in order and adds up how long
/// each one held it.
pub fn held_by(sw: &[SwitchRec], cpu: u16, from: i64, to: i64, exclude: u32) -> RanInstead {
    if to <= from {
        return RanInstead::Unknown;
    }
    // Who was on the processor when the wait began: the newest switch at or before `from`.
    let mut current = sw.iter().rfind(|s| s.cpu == cpu && s.ts <= from).map(|s| (s.new_tid, s.new_prio));
    let inside: Vec<&SwitchRec> = sw.iter().filter(|s| s.cpu == cpu && s.ts > from && s.ts <= to).collect();
    if current.is_none() && inside.is_empty() {
        return RanInstead::Unknown;
    }
    let mut held: HashMap<u32, (i64, i8)> = HashMap::new();
    let mut prev = from;
    for s in inside {
        if let Some((tid, prio)) = current {
            let e = held.entry(tid).or_insert((0, prio));
            e.0 += s.ts - prev;
            e.1 = prio;
        }
        current = Some((s.new_tid, s.new_prio));
        prev = s.ts;
    }
    if let Some((tid, prio)) = current {
        let e = held.entry(tid).or_insert((0, prio));
        e.0 += to - prev;
        e.1 = prio;
    }
    let span = (to - from) as f64;
    let idle = held.get(&IDLE_TID).map_or(0, |(t, _)| *t) as f64;
    if idle / span >= IDLE_SHARE {
        return RanInstead::Idle;
    }
    match held.iter().filter(|(tid, _)| **tid != IDLE_TID && **tid != exclude).max_by_key(|(_, (t, _))| *t) {
        Some((tid, (t, prio))) if *t > 0 => RanInstead::Thread { tid: *tid, prio: *prio, held: *t },
        // Everything that ran was the waiting thread itself, or nothing measurable ran: the
        // records contradict the premise, so nothing is claimed.
        _ => RanInstead::Unknown,
    }
}

// ---------------------------------------------------------------------------------------------
// 1. Why was a measuring thread late?
// ---------------------------------------------------------------------------------------------

/// One late wake-up of one measuring thread, as the probe itself measured it.
#[derive(Clone, Copy, Debug)]
pub struct ProbeWindow {
    pub tid: u32,
    /// The processor the probe is pinned to. `None` for the unpinned normal-priority probe, whose
    /// processor is taken from the switch that finally ran it.
    pub cpu: Option<u16>,
    /// When it asked to be woken.
    pub start: i64,
    /// When it actually ran.
    pub end: i64,
}

/// What happened to a measuring thread between asking to be woken and running.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProbeOutcome {
    /// Nothing made it runnable until `delay` after it was due. The timer that should have woken
    /// it fired late, or not at all until the end: a clock / firmware / power-management problem
    /// below the scheduler, not a busy processor.
    ReadiedLate { delay: i64 },
    /// It was made runnable on time and then sat in the queue for `waited`.
    ReadyNotRun { waited: i64, instead: RanInstead },
    /// It was woken on time, ran, and then blocked again (a page fault, a disk wait, a lock).
    RanThenBlocked { reason: i8 },
    /// Not enough records to say, with why in plain words.
    Unknown(&'static str),
}

/// How late a wake-up can be and still count as on time: a millisecond, or a twentieth of the
/// stall, whichever is longer. The probes ask to be woken every 1 ms (2 ms in light mode), so
/// anything inside that is the wake-up itself rather than lateness; and on a one-second freeze,
/// arguing about five milliseconds would be false precision.
pub fn on_time_slack(len: i64) -> i64 {
    ms_to_ticks(1.0).max(len / 20)
}

/// Reconstructs one late wake-up. `sw` and `rd` must be in timestamp order, which is the order
/// the ring buffers hold them in.
pub fn classify_probe(sw: &[SwitchRec], rd: &[ReadyRec], w: ProbeWindow) -> ProbeOutcome {
    if w.end <= w.start {
        return ProbeOutcome::Unknown("the stall had no length");
    }
    let slack = on_time_slack(w.end - w.start);

    // The switch that finally ran it, which also says which processor it ran on.
    let ran = sw.iter().rfind(|s| s.new_tid == w.tid && s.ts > w.start - slack && s.ts <= w.end + slack);
    let cpu = w.cpu.or(ran.map(|s| s.cpu));

    // The first thing that made it runnable at or after it was due. Anything before that belongs
    // to the previous wake-up.
    let ready = rd.iter().find(|r| r.tid == w.tid && r.ts >= w.start - slack && r.ts <= w.end + slack);

    let Some(ready) = ready else {
        // No wake-up record at all. If it clearly did run, the ReadyThread events for this window
        // are simply missing; if nothing at all is recorded for this thread, so is everything.
        return ProbeOutcome::Unknown(if ran.is_some() {
            "no wake-up record for the measuring thread (events lost, or the window has been overwritten)"
        } else {
            "no scheduler records at all for the measuring thread"
        });
    };

    if ready.ts > w.start + slack {
        return ProbeOutcome::ReadiedLate { delay: ready.ts - w.start };
    }

    // Woken on time. Did it run and then block again? Being switched off into a wait anywhere
    // inside the window can only have happened after it ran: it went into this wait before the
    // window began.
    if let Some(off) = sw.iter().rfind(|s| s.old_tid == w.tid && s.old_state == STATE_WAITING && s.ts > ready.ts && s.ts < w.end) {
        return ProbeOutcome::RanThenBlocked { reason: off.old_wait_reason };
    }

    let ran_at = ran.map_or(w.end, |s| s.ts);
    let instead = match cpu {
        Some(cpu) => held_by(sw, cpu, ready.ts, ran_at, w.tid),
        None => RanInstead::Unknown,
    };
    ProbeOutcome::ReadyNotRun { waited: (ran_at - ready.ts).max(0), instead }
}

/// How one cluster of late wake-ups came out: the three outcomes counted, which is what a verdict
/// and the freeze finding are written from.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ProbeVerdict {
    /// Made runnable late: nothing woke them.
    pub late: usize,
    /// Made runnable on time and left in the queue.
    pub queued: usize,
    /// Woken on time, ran, blocked again.
    pub blocked: usize,
    /// Too few records to say.
    pub unknown: usize,
    /// Of the `queued` ones, how many were left waiting on a processor that had nothing to do.
    pub on_idle_cpu: usize,
    /// Worst lateness of a wake-up among the `late` ones.
    pub worst_delay: i64,
    /// Threads that held a processor while a measuring thread was ready and waiting, worst first.
    pub instead: Vec<(u32, i8, i64)>,
    /// Wait reasons seen among the `blocked` ones.
    pub reasons: Vec<i8>,
}

/// What one incident was, once every measuring thread that could be judged has been.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Verdict {
    /// Nothing woke them: below the scheduler.
    NotWoken,
    /// Woken on time, left in the queue: the scheduler or the platform.
    Queued,
    /// Woken on time, ran, waited again: that wait is the stall.
    Blocked,
    /// The measuring threads did not agree, so neither may the report.
    Mixed,
}

impl ProbeVerdict {
    pub fn judged(&self) -> usize {
        self.late + self.queued + self.blocked
    }

    /// The one thing that happened, when the measuring threads all say the same. Deliberately
    /// strict: a freeze where seven processors were never woken and one was woken and queued is
    /// not "the timer did not fire", it is two things, and the report says so.
    pub fn overall(&self) -> Option<Verdict> {
        Some(match (self.late, self.queued, self.blocked) {
            (0, 0, 0) => return None,
            (_, 0, 0) => Verdict::NotWoken,
            (0, _, 0) => Verdict::Queued,
            (0, 0, _) => Verdict::Blocked,
            _ => Verdict::Mixed,
        })
    }

    /// Nothing at all could be reconstructed, so the report must say nothing rather than guess.
    pub fn empty(&self) -> bool {
        self.judged() == 0
    }

    fn push(&mut self, outcome: ProbeOutcome) {
        match outcome {
            ProbeOutcome::ReadiedLate { delay } => {
                self.late += 1;
                self.worst_delay = self.worst_delay.max(delay);
            }
            ProbeOutcome::ReadyNotRun { instead, .. } => {
                self.queued += 1;
                match instead {
                    RanInstead::Idle => self.on_idle_cpu += 1,
                    RanInstead::Thread { tid, prio, held } => self.instead.push((tid, prio, held)),
                    RanInstead::Unknown => {}
                }
            }
            ProbeOutcome::RanThenBlocked { reason } => {
                self.blocked += 1;
                if !self.reasons.contains(&reason) {
                    self.reasons.push(reason);
                }
            }
            ProbeOutcome::Unknown(_) => self.unknown += 1,
        }
    }
}

/// Classifies every measuring thread that was late in one incident and adds the outcomes up.
pub fn judge_probes(sw: &[SwitchRec], rd: &[ReadyRec], windows: &[ProbeWindow]) -> ProbeVerdict {
    let mut v = ProbeVerdict::default();
    for w in windows {
        v.push(classify_probe(sw, rd, *w));
    }
    v.instead.sort_by_key(|(_, _, held)| std::cmp::Reverse(*held));
    v.instead.truncate(8);
    v
}

// ---------------------------------------------------------------------------------------------
// 2. Who was kept waiting?
// ---------------------------------------------------------------------------------------------

/// The worst wait one thread had inside a window.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ThreadWait {
    pub tid: u32,
    /// Longest single stretch it was runnable and did not get a processor.
    pub ready: i64,
    /// The processor it was waiting for (the one it eventually ran on), and when that stretch ran.
    pub ready_cpu: u16,
    pub ready_from: i64,
    pub ready_to: i64,
    /// Longest single stretch it was blocked, counting only stretches that both began and ended
    /// inside the window: a thread already parked when the window opened was not held up by
    /// anything in it.
    pub blocked: i64,
    pub blocked_reason: i8,
    /// The thread that ended that longest block, when one can be named (see `ReadyRec::waker`).
    pub woken_by: Option<u32>,
}

impl ThreadWait {
    fn worst(&self) -> i64 {
        self.ready.max(self.blocked)
    }
}

/// What the scheduler was doing to one thread when the window last said something about it.
#[derive(Clone, Copy, Default)]
struct Live {
    /// Runnable since, and not yet given a processor.
    ready_since: Option<i64>,
    /// Blocked since, with the reason it was switched off for.
    blocked_since: Option<(i64, i8)>,
    /// The processor it was last seen running on.
    cpu: u16,
}

/// One entry of the merged switch/ready stream.
enum Step<'a> {
    Switch(&'a SwitchRec),
    Ready(&'a ReadyRec),
}

/// Walks the two streams in timestamp order.
fn merged<'a>(sw: &'a [SwitchRec], rd: &'a [ReadyRec], from: i64, to: i64) -> Vec<Step<'a>> {
    let mut out: Vec<Step> = Vec::with_capacity(sw.len() + rd.len());
    let (mut i, mut j) = (0, 0);
    let sw: Vec<&SwitchRec> = sw.iter().filter(|s| s.ts >= from && s.ts <= to).collect();
    let rd: Vec<&ReadyRec> = rd.iter().filter(|r| r.ts >= from && r.ts <= to).collect();
    while i < sw.len() || j < rd.len() {
        // A tie goes to the ready event: a thread is made runnable before it can be switched in.
        let take_ready = j < rd.len() && (i >= sw.len() || rd[j].ts <= sw[i].ts);
        if take_ready {
            out.push(Step::Ready(rd[j]));
            j += 1;
        } else {
            out.push(Step::Switch(sw[i]));
            i += 1;
        }
    }
    out
}

/// Per thread, the longest stretch it spent runnable-but-not-running and the longest it spent
/// blocked, inside `[from, to]`. Worst first; capped, so a machine with thousands of threads
/// cannot produce an unbounded result.
///
/// `sw` and `rd` must be in timestamp order, which is the order the ring buffers hold them in.
///
/// Thread ids are recycled by Windows. A `Terminated` switch clears everything known about an id,
/// so an id handed straight back out starts from nothing; a reuse with no terminate event inside
/// the window would mix two threads' waits, which over a window of a few seconds is rare enough
/// to accept and impossible to detect from these events alone.
pub fn waits(sw: &[SwitchRec], rd: &[ReadyRec], from: i64, to: i64) -> Vec<ThreadWait> {
    let mut live: HashMap<u32, Live> = HashMap::new();
    let mut worst: HashMap<u32, ThreadWait> = HashMap::new();
    /// The tracked state for one thread, added only while there is room in the map.
    fn track(live: &mut HashMap<u32, Live>, tid: u32) -> Option<&mut Live> {
        if live.len() >= MAX_THREADS && !live.contains_key(&tid) {
            return None;
        }
        Some(live.entry(tid).or_default())
    }
    fn row(worst: &mut HashMap<u32, ThreadWait>, tid: u32) -> &mut ThreadWait {
        worst.entry(tid).or_insert(ThreadWait { tid, ..ThreadWait::default() })
    }

    for step in merged(sw, rd, from, to) {
        match step {
            Step::Ready(r) => {
                if r.tid == IDLE_TID {
                    continue;
                }
                let Some(state) = track(&mut live, r.tid) else { continue };
                let was_blocked = state.blocked_since.take();
                state.ready_since.get_or_insert(r.ts);
                if let Some((since, reason)) = was_blocked {
                    let span = r.ts - since;
                    let w = row(&mut worst, r.tid);
                    if span > 0 && span > w.blocked {
                        w.blocked = span;
                        w.blocked_reason = reason;
                        w.woken_by = r.waker();
                    }
                }
            }
            Step::Switch(s) => {
                if s.new_tid != IDLE_TID {
                    if let Some(state) = track(&mut live, s.new_tid) {
                        let was_ready = state.ready_since.take();
                        state.blocked_since = None;
                        state.cpu = s.cpu;
                        if let Some(since) = was_ready {
                            let span = s.ts - since;
                            let w = row(&mut worst, s.new_tid);
                            if span > 0 && span > w.ready {
                                w.ready = span;
                                w.ready_cpu = s.cpu;
                                w.ready_from = since;
                                w.ready_to = s.ts;
                            }
                        }
                    }
                }
                if s.old_tid == IDLE_TID {
                    continue;
                }
                if s.old_state == STATE_TERMINATED {
                    // The id is free to be handed to a new thread, so nothing the scheduler was
                    // doing to the old one carries over. What was already measured stays: it
                    // happened, and this is the only place a reuse can be seen at all.
                    live.remove(&s.old_tid);
                    continue;
                }
                let Some(state) = track(&mut live, s.old_tid) else { continue };
                state.cpu = s.cpu;
                match s.old_state {
                    STATE_WAITING => {
                        state.blocked_since = Some((s.ts, s.old_wait_reason));
                        state.ready_since = None;
                    }
                    // Still runnable, just not on a processor: preempted, or queued behind others.
                    STATE_READY | STATE_STANDBY | STATE_DEFERRED_READY => {
                        state.blocked_since = None;
                        state.ready_since = Some(s.ts);
                    }
                    _ => {
                        state.blocked_since = None;
                        state.ready_since = None;
                    }
                }
            }
        }
    }

    let mut rows: Vec<ThreadWait> = worst.into_values().filter(|w| w.worst() > 0).collect();
    rows.sort_by_key(|w| (std::cmp::Reverse(w.worst()), w.tid));
    rows.truncate(MAX_ROWS);
    rows
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The band changes exactly where Microsoft's table does, between 15 and 16, and nothing is
    /// said for values no documented class produces.
    #[test]
    fn a_priority_is_named_by_its_documented_band_at_the_15_16_boundary() {
        assert_eq!(priority_band(15), Some("the ordinary range, 1-15"));
        assert_eq!(priority_band(16), Some("the real-time range, 16-31, above every ordinary thread"));
        assert_eq!(priority_band(1), Some("the ordinary range, 1-15"));
        assert_eq!(priority_band(31), priority_band(16));
        assert_eq!(priority_band(0), None, "the zero-page thread only");
        assert_eq!(priority_band(-1), None, "a garbled record");
        assert_eq!(priority_band(32), None);
    }

    fn sw(ts: i64, cpu: u16, new_tid: u32, old_tid: u32, old_state: i8) -> SwitchRec {
        SwitchRec { ts, new_tid, old_tid, cpu, new_prio: 8, old_prio: 8, old_wait_reason: 0, old_wait_mode: 0, old_state }
    }

    fn sw_prio(ts: i64, cpu: u16, new_tid: u32, prio: i8, old_tid: u32, old_state: i8) -> SwitchRec {
        SwitchRec { new_prio: prio, ..sw(ts, cpu, new_tid, old_tid, old_state) }
    }

    fn blocked_out(ts: i64, cpu: u16, tid: u32, reason: i8) -> SwitchRec {
        SwitchRec { old_wait_reason: reason, ..sw(ts, cpu, IDLE_TID, tid, STATE_WAITING) }
    }

    fn rdy(ts: i64, tid: u32) -> ReadyRec {
        ReadyRec { ts, tid, by_tid: 0, cpu: 0, flag: 0 }
    }

    fn rdy_by(ts: i64, tid: u32, by: u32) -> ReadyRec {
        ReadyRec { ts, tid, by_tid: by, cpu: 0, flag: 0 }
    }

    const MS: f64 = 1.0;
    fn ms(x: f64) -> i64 {
        ms_to_ticks(x)
    }

    const PROBE: u32 = 4242;

    fn probe(start: f64, end: f64) -> ProbeWindow {
        ProbeWindow { tid: PROBE, cpu: Some(3), start: ms(start), end: ms(end) }
    }

    // ---- 1. the probe-thread classifier -------------------------------------------------

    /// (a) The freeze shape from issue #15: nothing readied the probe until the end. That is the
    /// answer the field logs could not give - the timer did not fire.
    #[test]
    fn a_probe_that_was_never_woken_is_reported_as_the_timer_not_firing() {
        // Due at 1000 ms, readied and run only at 1900 ms. Ordinary work carried on meanwhile.
        let mut s = vec![sw(ms(500.0), 3, IDLE_TID, PROBE, STATE_WAITING)];
        s.push(sw(ms(1899.0), 3, PROBE, IDLE_TID, STATE_READY));
        let r = vec![rdy(ms(1898.0), PROBE)];
        match classify_probe(&s, &r, probe(1000.0, 1900.0)) {
            ProbeOutcome::ReadiedLate { delay } => assert_eq!(delay, ms(898.0)),
            other => panic!("{other:?}"),
        }
        // No ready event at all in the window is not the same claim: it is missing data.
        assert!(matches!(classify_probe(&s, &[], probe(1000.0, 1900.0)), ProbeOutcome::Unknown(_)));
    }

    /// (b) Readied on time, left in the queue, and the processor had nothing else to do. A ready
    /// priority-31 thread not run on an idle processor is worth stating plainly.
    #[test]
    fn a_probe_ready_on_time_on_an_idle_processor_is_called_exactly_that() {
        let s = vec![
            sw(ms(500.0), 3, IDLE_TID, PROBE, STATE_WAITING), // the processor goes idle
            sw(ms(1899.0), 3, PROBE, IDLE_TID, STATE_READY),  // ...and stays idle until the end
        ];
        let r = vec![rdy(ms(1000.2), PROBE)];
        match classify_probe(&s, &r, probe(1000.0, 1900.0)) {
            ProbeOutcome::ReadyNotRun { waited, instead } => {
                assert!(waited > ms(890.0) && waited < ms(900.0), "{waited}");
                assert_eq!(instead, RanInstead::Idle);
            }
            other => panic!("{other:?}"),
        }
    }

    /// (b) again, with something actually holding the processor: name it and its priority.
    #[test]
    fn a_probe_queued_behind_another_thread_names_that_thread() {
        let s = vec![
            sw(ms(500.0), 3, IDLE_TID, PROBE, STATE_WAITING),
            sw_prio(ms(900.0), 3, 77, 24, IDLE_TID, STATE_READY), // a priority-24 thread takes it
            sw(ms(1090.0), 3, PROBE, 77, STATE_READY),
        ];
        let r = vec![rdy(ms(1000.0), PROBE)];
        match classify_probe(&s, &r, probe(1000.0, 1090.0)) {
            ProbeOutcome::ReadyNotRun { instead: RanInstead::Thread { tid, prio, held }, .. } => {
                assert_eq!((tid, prio), (77, 24));
                assert_eq!(held, ms(90.0), "it held the processor for the whole wait");
            }
            other => panic!("{other:?}"),
        }
    }

    /// (c) Woken on time, ran, and blocked again on a page fault.
    #[test]
    fn a_probe_that_ran_and_blocked_again_reports_the_wait_it_went_into() {
        let s = vec![
            sw(ms(500.0), 3, IDLE_TID, PROBE, STATE_WAITING),
            sw(ms(1000.1), 3, PROBE, IDLE_TID, STATE_READY),
            blocked_out(ms(1000.3), 3, PROBE, 9), // WrPageIn
            sw(ms(1089.0), 3, PROBE, IDLE_TID, STATE_READY),
        ];
        let r = vec![rdy(ms(1000.0), PROBE), rdy(ms(1088.0), PROBE)];
        assert_eq!(classify_probe(&s, &r, probe(1000.0, 1090.0)), ProbeOutcome::RanThenBlocked { reason: 9 });
        assert_eq!(wait_reason_name(9), Some("waiting for memory to be read back from disk"));
    }

    /// Whatever is missing - lost events, a pruned ring, a zero-length window - the classifier
    /// says it does not know rather than inventing an outcome.
    #[test]
    fn missing_data_is_never_turned_into_an_answer() {
        assert!(matches!(classify_probe(&[], &[], probe(1000.0, 1900.0)), ProbeOutcome::Unknown(_)));
        assert!(matches!(classify_probe(&[], &[], probe(1000.0, 1000.0)), ProbeOutcome::Unknown(_)));
        assert!(matches!(classify_probe(&[], &[], probe(1900.0, 1000.0)), ProbeOutcome::Unknown(_)));
        // Ready records for some other thread say nothing about this one.
        let r = vec![rdy(ms(1000.0), 99)];
        assert!(matches!(classify_probe(&[], &r, probe(1000.0, 1900.0)), ProbeOutcome::Unknown(_)));
        // Ready on time, but no switch records for that processor: the wait is known, not the cause.
        let r = vec![rdy(ms(1000.0), PROBE)];
        assert!(matches!(classify_probe(&[], &r, probe(1000.0, 1900.0)), ProbeOutcome::ReadyNotRun { instead: RanInstead::Unknown, .. }));
    }

    /// A thread id that came back as a different thread must not make the wake-up look on time:
    /// only records inside this wake-up's own window are considered.
    #[test]
    fn records_from_before_the_wake_up_do_not_count_as_this_wake_up() {
        let s = vec![sw(ms(1899.0), 3, PROBE, IDLE_TID, STATE_READY)];
        // A ready event a full second before it was due belongs to the previous wake-up.
        let r = vec![rdy(ms(0.0), PROBE), rdy(ms(1898.0), PROBE)];
        assert!(matches!(classify_probe(&s, &r, probe(1000.0, 1900.0)), ProbeOutcome::ReadiedLate { .. }));
    }

    /// A wake-up a hair late is a wake-up, not lateness: the probes ask every millisecond, and on
    /// a one-second freeze five milliseconds of argument would be false precision.
    #[test]
    fn the_on_time_window_scales_with_the_length_of_the_stall() {
        assert_eq!(on_time_slack(ms(6.0)), ms(MS), "a short stall gets the flat 1 ms");
        assert_eq!(on_time_slack(ms(900.0)), ms(45.0), "a 900 ms freeze gets a twentieth of it");
        let s = vec![sw(ms(1089.0), 3, PROBE, IDLE_TID, STATE_READY)];
        let r = vec![rdy(ms(1000.5), PROBE)];
        assert!(matches!(classify_probe(&s, &r, probe(1000.0, 1090.0)), ProbeOutcome::ReadyNotRun { .. }));
        let r = vec![rdy(ms(1020.0), PROBE)];
        assert!(matches!(classify_probe(&s, &r, probe(1000.0, 1090.0)), ProbeOutcome::ReadiedLate { .. }));
    }

    /// The unpinned normal-priority probe has no processor of its own; it is taken from the
    /// switch that ran it.
    #[test]
    fn the_unpinned_probe_takes_its_processor_from_the_switch_that_ran_it() {
        let s = vec![sw(ms(900.0), 6, 77, IDLE_TID, STATE_READY), sw(ms(1089.0), 6, PROBE, 77, STATE_READY)];
        let r = vec![rdy(ms(1000.0), PROBE)];
        let w = ProbeWindow { tid: PROBE, cpu: None, start: ms(1000.0), end: ms(1090.0) };
        match classify_probe(&s, &r, w) {
            ProbeOutcome::ReadyNotRun { instead: RanInstead::Thread { tid, .. }, .. } => assert_eq!(tid, 77),
            other => panic!("{other:?}"),
        }
    }

    /// The whole point of deliverable 1: 9 freezes where nothing woke the threads and 3 where
    /// they were ready and not run have to come out as two different sentences.
    #[test]
    fn a_run_of_freezes_adds_up_to_the_sentence_the_report_needs() {
        let s = vec![sw(ms(1899.0), 3, PROBE, IDLE_TID, STATE_READY)];
        let late = ProbeWindow { tid: PROBE, cpu: Some(3), start: ms(1000.0), end: ms(1900.0) };
        let mut windows = Vec::new();
        for cpu in 0..8u16 {
            windows.push(ProbeWindow { cpu: Some(cpu), ..late });
        }
        let r = vec![rdy(ms(1898.0), PROBE)];
        let v = judge_probes(&s, &r, &windows);
        assert_eq!((v.late, v.queued, v.blocked, v.unknown), (8, 0, 0, 0));
        assert_eq!(v.worst_delay, ms(898.0));
        assert_eq!(v.judged(), 8);
        assert!(!v.empty());
        assert_eq!(v.overall(), Some(Verdict::NotWoken));
        assert!(ProbeVerdict::default().empty());
        assert_eq!(ProbeVerdict::default().overall(), None);

        // The other shape: ready on time, idle processors.
        let s = vec![sw(ms(500.0), 3, IDLE_TID, PROBE, STATE_WAITING), sw(ms(1899.0), 3, PROBE, IDLE_TID, STATE_READY)];
        let r = vec![rdy(ms(1000.0), PROBE)];
        let v = judge_probes(&s, &r, &[probe(1000.0, 1900.0)]);
        assert_eq!((v.late, v.queued, v.on_idle_cpu), (0, 1, 1));
        assert_eq!(v.overall(), Some(Verdict::Queued));

        // Threads that disagree are not summarized into one claim.
        let mixed = ProbeVerdict { late: 7, queued: 1, ..ProbeVerdict::default() };
        assert_eq!(mixed.overall(), Some(Verdict::Mixed));
        assert_eq!(ProbeVerdict { blocked: 2, ..ProbeVerdict::default() }.overall(), Some(Verdict::Blocked));
        // Threads nothing could be said about never turn into an answer on their own.
        assert_eq!(ProbeVerdict { unknown: 8, ..ProbeVerdict::default() }.overall(), None);
    }

    // ---- held_by --------------------------------------------------------------------------

    #[test]
    fn what_held_a_processor_is_added_up_across_switches_and_the_waiter_left_out() {
        let s = vec![
            sw_prio(ms(100.0), 1, 10, 9, IDLE_TID, STATE_READY),
            sw_prio(ms(140.0), 1, 20, 15, 10, STATE_READY),
            sw_prio(ms(150.0), 1, 10, 9, 20, STATE_READY),
            sw_prio(ms(180.0), 1, 99, 8, 10, STATE_READY), // the waiter finally gets it
        ];
        // tid 10 held 40 + 30 = 70 ms, tid 20 held 10 ms.
        match held_by(&s, 1, ms(100.0), ms(180.0), 99) {
            RanInstead::Thread { tid, prio, held } => assert_eq!((tid, prio, held), (10, 9, ms(70.0))),
            other => panic!("{other:?}"),
        }
        // Another processor entirely: nothing known.
        assert_eq!(held_by(&s, 7, ms(100.0), ms(180.0), 99), RanInstead::Unknown);
        assert_eq!(held_by(&s, 1, ms(180.0), ms(100.0), 99), RanInstead::Unknown, "a backwards window");
        // Only the waiting thread ran: the records contradict the premise, so nothing is claimed.
        let mine = vec![sw(ms(100.0), 1, 99, IDLE_TID, STATE_READY)];
        assert_eq!(held_by(&mine, 1, ms(100.0), ms(180.0), 99), RanInstead::Unknown);
        // Idle for nine tenths of it counts as idle; less does not.
        let mostly = vec![sw(ms(0.0), 1, IDLE_TID, 5, STATE_WAITING), sw(ms(95.0), 1, 10, IDLE_TID, STATE_READY)];
        assert_eq!(held_by(&mostly, 1, ms(0.0), ms(100.0), 99), RanInstead::Idle);
        let busy = vec![sw(ms(0.0), 1, IDLE_TID, 5, STATE_WAITING), sw(ms(50.0), 1, 10, IDLE_TID, STATE_READY)];
        assert!(matches!(held_by(&busy, 1, ms(0.0), ms(100.0), 99), RanInstead::Thread { tid: 10, .. }));
    }

    // ---- 2. who was kept waiting -----------------------------------------------------------

    /// A multi-processor stream: one thread queued behind another, one thread blocked and woken.
    #[test]
    fn ready_waiting_and_blocked_are_measured_separately_per_thread() {
        // In timestamp order across both processors, which is the order the ring buffer holds.
        let s = vec![
            // CPU 0: thread 10 runs the whole time. Thread 11 is readied and waits for it.
            sw_prio(ms(0.0), 0, 10, 9, IDLE_TID, STATE_READY),
            // CPU 1: thread 20 blocks on a lock at 50 ms and is woken by thread 21 at 170 ms.
            sw(ms(10.0), 1, 20, IDLE_TID, STATE_READY),
            blocked_out(ms(50.0), 1, 20, 13), // WrUserRequest
            sw(ms(171.0), 1, 20, IDLE_TID, STATE_READY),
            sw(ms(200.0), 0, 11, 10, STATE_READY),
        ];
        let r = vec![rdy(ms(120.0), 11), rdy_by(ms(170.0), 20, 21)];
        let rows = waits(&s, &r, 0, ms(300.0));

        let get = |tid: u32| *rows.iter().find(|w| w.tid == tid).unwrap_or_else(|| panic!("no row for {tid}"));
        let waiter = get(11);
        assert_eq!(waiter.ready, ms(80.0), "readied at 120, ran at 200");
        assert_eq!((waiter.ready_cpu, waiter.blocked), (0, 0));
        assert!(matches!(held_by(&s, waiter.ready_cpu, waiter.ready_from, waiter.ready_to, 11), RanInstead::Thread { tid: 10, .. }));

        let blocked = get(20);
        assert_eq!((blocked.blocked, blocked.blocked_reason, blocked.woken_by), (ms(120.0), 13, Some(21)));
        assert_eq!(blocked.ready, ms(1.0), "readied at 170, ran at 171");
        assert_eq!(rows.first().map(|w| w.tid), Some(20), "worst first");
        assert!(!rows.iter().any(|w| w.tid == IDLE_TID), "the idle thread is never a waiter");
    }

    /// A thread already parked when the window opened, or still parked when it closed, was not
    /// held up by anything inside it: only complete waits count.
    #[test]
    fn only_waits_that_both_began_and_ended_inside_the_window_are_counted() {
        // Blocked long before the window; woken inside it. The block did not start here.
        let s = vec![sw(ms(150.0), 0, 30, IDLE_TID, STATE_READY)];
        let r = vec![rdy(ms(149.0), 30)];
        let rows = waits(&s, &r, ms(100.0), ms(200.0));
        assert_eq!(rows.iter().find(|w| w.tid == 30).map(|w| w.blocked), Some(0));

        // Blocked inside the window and never woken: still nothing to report.
        let s = vec![sw(ms(110.0), 0, 30, IDLE_TID, STATE_READY), blocked_out(ms(120.0), 0, 30, 13)];
        assert!(waits(&s, &[], ms(100.0), ms(200.0)).iter().all(|w| w.blocked == 0));
    }

    /// Windows hands thread ids straight back out. A terminate clears everything known about one.
    #[test]
    fn a_recycled_thread_id_does_not_inherit_the_old_threads_wait() {
        let s = vec![
            sw(ms(10.0), 0, 40, IDLE_TID, STATE_READY),
            blocked_out(ms(20.0), 0, 40, 13),
            // The thread ends while blocked (it is switched off Terminated on its last run).
            sw(ms(30.0), 0, 40, IDLE_TID, STATE_READY),
            sw(ms(31.0), 0, IDLE_TID, 40, STATE_TERMINATED),
            // A new thread gets the same id and is readied; the old block must not be charged here.
            sw(ms(200.0), 0, 40, IDLE_TID, STATE_READY),
        ];
        let r = vec![rdy(ms(29.0), 40), rdy(ms(199.0), 40)];
        let rows = waits(&s, &r, 0, ms(300.0));
        let row = rows.iter().find(|w| w.tid == 40).unwrap();
        assert_eq!(row.blocked, ms(9.0), "only the first thread's own block, not 20 ms to 199 ms");
    }

    /// Being preempted leaves a thread runnable, so the clock on "ready and not running" keeps
    /// going; being switched off into a wait stops it.
    #[test]
    fn preemption_keeps_a_thread_runnable_and_a_wait_does_not() {
        let preempted = vec![
            sw(ms(0.0), 0, 50, IDLE_TID, STATE_READY),
            sw(ms(10.0), 0, 51, 50, STATE_READY), // 50 is preempted, still runnable
            sw(ms(90.0), 0, 50, 51, STATE_READY),
        ];
        let rows = waits(&preempted, &[], 0, ms(200.0));
        assert_eq!(rows.iter().find(|w| w.tid == 50).map(|w| w.ready), Some(ms(80.0)));

        let waited = vec![sw(ms(0.0), 0, 50, IDLE_TID, STATE_READY), blocked_out(ms(10.0), 0, 50, 13), sw(ms(90.0), 0, 50, IDLE_TID, 1)];
        // No ready record, so nothing closes the block and nothing starts a ready-wait.
        assert!(waits(&waited, &[], 0, ms(200.0)).iter().all(|w| w.tid != 50 || (w.ready == 0 && w.blocked == 0)));
    }

    #[test]
    fn an_empty_or_backwards_window_yields_nothing_and_never_panics() {
        assert!(waits(&[], &[], 0, ms(100.0)).is_empty());
        let s = vec![sw(ms(50.0), 0, 10, 11, STATE_READY)];
        assert!(waits(&s, &[], ms(100.0), ms(0.0)).is_empty());
        assert!(waits(&s, &[], ms(500.0), ms(600.0)).is_empty(), "nothing in range");
    }

    /// A busy machine must not be able to make this grow without limit.
    #[test]
    fn the_result_is_capped_however_many_threads_were_waiting() {
        let mut s = Vec::new();
        let mut r = Vec::new();
        for i in 0..(MAX_ROWS as u32 + 500) {
            let tid = i + 1000;
            r.push(rdy(ms(1.0), tid));
            s.push(sw(ms(2.0) + i as i64, (i % 8) as u16, tid, IDLE_TID, STATE_READY));
        }
        let rows = waits(&s, &r, 0, ms(1000.0));
        assert_eq!(rows.len(), MAX_ROWS);
        assert!(rows.windows(2).all(|p| p[0].worst() >= p[1].worst()), "worst first");
    }

    /// Sleeping and sitting on a work queue are not being held up by anything.
    #[test]
    fn a_thread_that_chose_to_stop_is_not_reported_as_waiting() {
        for reason in [4i8, 11, 5, 12, 15, 22] {
            assert!(voluntary_wait(reason), "{reason}");
        }
        for reason in [0i8, 2, 6, 13, 21, 29] {
            assert!(!voluntary_wait(reason), "{reason}");
        }
    }

    /// An idle message loop or event wait (UserRequest) looks exactly like a stuck one in this
    /// trace, so it can never make a program "held up"; locks, disk and paging waits still do.
    #[test]
    fn a_message_or_event_wait_is_never_a_program_held_up() {
        for reason in [6i8, 13, 4, 11, 15] {
            assert!(!held_up_wait(reason), "{reason}");
        }
        // Executive, PageIn, WrPageIn, WrResource, WrPushLock, WrGuardedMutex.
        for reason in [0i8, 2, 9, 27, 28, 35] {
            assert!(held_up_wait(reason), "{reason}");
        }
    }

    /// Every wait reason the report can print has to read as plain English, and none of them may
    /// name a culprit: these say what kind of wait it was, never whose fault it was.
    #[test]
    fn wait_reasons_read_as_plain_words_and_blame_nobody() {
        for reason in 0i8..=37 {
            let Some(text) = wait_reason_name(reason) else { continue };
            assert!(text.is_ascii() && text.chars().next().unwrap().is_lowercase(), "{reason}: {text}");
            for jargon in ["mutex", "pushlock", "lpc", "irql", "dispatcher", "kwait", "quantum"] {
                assert!(!text.to_lowercase().contains(jargon), "{reason}: {text} says {jargon}");
            }
        }
        assert_eq!(wait_reason_name(-1), None, "a garbage payload names no wait");
        assert_eq!(wait_reason_name(99), None);
        assert_eq!(wait_reason_name(30), None, "WrQuantumEnd is not a wait anyone can feel");
        // "A lock" in a disk finding means exactly what the plain words call a lock.
        for reason in -1i8..=40 {
            assert_eq!(lock_wait(reason), wait_reason_name(reason) == Some("waiting for a lock another thread holds"), "{reason}");
        }
    }
}
