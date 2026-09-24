//! Data shared between the ETW consumer thread (writer) and the analyzer (reader).
//! All timestamps and durations are raw QPC ticks.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

pub const KIND_DPC: u8 = 0;
pub const KIND_TIMER_DPC: u8 = 1;
pub const KIND_THREADED_DPC: u8 = 2;
/// PerfInfo event type 67, the documented ISR event. Called "line-based" only by elimination;
/// see the comment on the ISR opcodes in `etw::events`.
pub const KIND_ISR: u8 = 3;
/// PerfInfo event type 50, undocumented on Learn; the message-signaled interrupt hook by the
/// sources cited in `etw::events`. Kept apart from `KIND_ISR` so the report can say which kind of
/// interrupt a driver's handler actually ran for.
pub const KIND_ISR_MSI: u8 = 4;

/// Both ISR kinds. Anything that tells a DPC from an ISR must ask this, not compare with one kind.
pub fn is_isr(k: u8) -> bool {
    k == KIND_ISR || k == KIND_ISR_MSI
}

pub fn kind_name(k: u8) -> &'static str {
    match k {
        KIND_DPC => "DPC",
        KIND_TIMER_DPC => "timer DPC",
        KIND_THREADED_DPC => "threaded DPC",
        KIND_ISR_MSI => "ISR (MSI)",
        _ => "ISR",
    }
}

pub const PID_UNKNOWN: u32 = u32::MAX;

/// One DPC or ISR execution.
#[derive(Clone, Copy)]
pub struct ExecRec {
    pub cpu: u16,
    pub kind: u8,
    pub start: i64,
    pub end: i64,
    pub routine: u64,
}

#[derive(Clone, Copy)]
pub struct FaultRec {
    pub start: i64,
    pub end: i64,
    pub tid: u32,
    pub pid: u32,
    pub bytes: u32,
    /// FileObject/FileKey of the file the page came from; 0 when the event did not carry one.
    /// Look it up in `Inner::file_names`.
    pub file: u64,
}

/// One completed disk request. 64 bytes (see the size test): the ring is pruned by time
/// (`Shared::keep`, 20 s), not by count, so its memory is the drives' request rate x 20 s x 64.
/// At the ~1,750 requests a second measured under heavy disk load (2026-09-23) that is 2.2 MB.
#[derive(Clone, Copy)]
pub struct IoRec {
    pub end: i64,
    pub dur: i64,
    /// FileObject of the file, or 0 (flush events carry none). See `Inner::file_names`.
    pub file: u64,
    /// `Irp`: the request's I/O request packet, a kernel pointer. Kept only so that the storage
    /// port driver's record of the same request can be found (see `storport`); never printed.
    /// https://learn.microsoft.com/en-us/windows/win32/etw/diskio-typegroup1
    pub irp: u64,
    /// `ByteOffset`: "Byte offset from the beginning of the physical disk". 0 for a flush, which
    /// carries none. https://learn.microsoft.com/en-us/windows/win32/etw/diskio-typegroup1
    pub offset: i64,
    pub disk: u32,
    pub tid: u32,
    pub pid: u32,
    pub size: u32,
    /// `IrpFlags` of the request; see `diskstuck` for the bits that are read.
    pub irp_flags: u32,
    /// b'R', b'W' or b'F'
    pub op: u8,
}

#[derive(Clone, Copy)]
pub struct SampleRec {
    pub ts: i64,
    pub cpu: u16,
    pub tid: u32,
    pub ip: u64,
}

/// One context switch (Thread provider, event type 36, `CSwitch`). Only the fields the analysis
/// uses are kept, so the record stays 24 bytes: this is the highest-volume class in the kernel
/// logger and the ring holds hundreds of thousands of them.
///
/// `NewThreadWaitTime` is deliberately NOT stored: Microsoft documents it only as "Wait time for
/// the new thread" and gives no unit, and a number whose unit is unknown cannot be reported.
/// https://learn.microsoft.com/en-us/windows/win32/etw/cswitch
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SwitchRec {
    pub ts: i64,
    /// Thread switched ON to this processor (0 is the idle thread).
    pub new_tid: u32,
    /// Thread switched OFF it.
    pub old_tid: u32,
    pub cpu: u16,
    pub new_prio: i8,
    pub old_prio: i8,
    /// `OldThreadWaitReason`, a KWAIT_REASON; see `switches::wait_reason_name`.
    pub old_wait_reason: i8,
    /// `OldThreadWaitMode`: 0 KernelMode, 1 UserMode.
    pub old_wait_mode: i8,
    /// `OldThreadState`: 0 Initialized, 1 Ready, 2 Running, 3 Standby, 4 Terminated, 5 Waiting,
    /// 6 Transition, 7 DeferredReady.
    pub old_state: i8,
}

/// One "this thread has been made runnable" event (Thread provider, event type 50,
/// `ReadyThread`). https://learn.microsoft.com/en-us/windows/win32/etw/readythread
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadyRec {
    pub ts: i64,
    /// `TThreadId`: "The thread identifier of the thread being readied for execution."
    pub tid: u32,
    /// The event header's thread, i.e. whoever was running when the readying happened. Only
    /// meaningful when `Flag & 1` is clear; see `ReadyRec::waker`.
    pub by_tid: u32,
    pub cpu: u16,
    /// `Flag`: 0x1 readied from a DPC, 0x2 kernel stack swapped out, 0x4 address space swapped out.
    pub flag: i8,
}

/// `Flag` bit 0x1: "The thread has been readied from DPC (deferred procedure call)."
pub const READY_FROM_DPC: i8 = 0x1;

impl ReadyRec {
    /// The thread that woke this one, when that can be said at all.
    ///
    /// The readying thread is not a documented field of the MOF class: it is the thread the event
    /// was logged in the context of, which is what Windows Performance Analyzer shows as
    /// "ReadyingThreadId". When the thread was readied from a DPC the processor was not running
    /// that thread on anyone's behalf, and Microsoft's own `Flag` documentation is why this is
    /// checked rather than guessed.
    pub fn waker(&self) -> Option<u32> {
        (self.flag & READY_FROM_DPC == 0 && self.by_tid != 0 && self.by_tid != self.tid).then_some(self.by_tid)
    }
}

#[derive(Default, Clone, Copy)]
pub struct RoutineStat {
    pub count: u64,
    pub total: i64,
    pub max: i64,
    pub over_warn: u64,
}

/// How long requests to one file waited over the whole run.
#[derive(Default, Clone, Copy, Debug)]
pub struct FileWait {
    pub disk: u32,
    pub count: u64,
    pub total: i64,
    pub max: i64,
}

/// One process's share of the waiting on one file.
#[derive(Default, Clone, Copy, Debug, PartialEq, Eq)]
pub struct PidWait {
    pub pid: u32,
    pub count: u32,
    pub total: i64,
}

/// How long disk requests to one file waited over the whole run, and which processes issued them.
///
/// Keyed by file, not by (process, file), so that the rundown check and a recycled file object
/// stay one hash lookup each inside the ETW callback. The processes are a short list inside:
/// at most `FILE_WAIT_PIDS` of them, and requests from any further process still count toward
/// the file's totals, just unattributed. Memory: 56 bytes plus 16 per process listed, so at the
/// `FILE_WAIT_CAP` of 8,192 files at most ~1.6 MB with hash-table overhead, typically a tenth of
/// that (most files are read by one process). Process IDs, not names: naming happens once, in the
/// summary, the way `fault_file` is named.
#[derive(Default, Clone, Debug)]
pub struct DiskFileWait {
    pub wait: FileWait,
    pub by_pid: Vec<PidWait>,
}

/// Processes listed per file; see `DiskFileWait`.
pub const FILE_WAIT_PIDS: usize = 8;

impl DiskFileWait {
    pub fn add(&mut self, pid: u32, dur: i64) {
        self.wait.count += 1;
        self.wait.total += dur;
        self.wait.max = self.wait.max.max(dur);
        if let Some(p) = self.by_pid.iter_mut().find(|p| p.pid == pid) {
            p.count += 1;
            p.total += dur;
        } else if self.by_pid.len() < FILE_WAIT_PIDS {
            self.by_pid.push(PidWait { pid, count: 1, total: dur });
        }
    }
}

/// Anything whose waiting can be totaled, so one capping rule serves every per-file tally.
pub trait Waited {
    fn waited(&self) -> i64;
}

impl Waited for FileWait {
    fn waited(&self) -> i64 {
        self.total
    }
}

impl Waited for DiskFileWait {
    fn waited(&self) -> i64 {
        self.wait.total
    }
}

/// FileObject/FileKey -> NT path, filled from the kernel's FileIo name events.
///
/// A PC can have tens of thousands of files open, and a multi-hour run opens many more, so this
/// map is hard-capped and evicts oldest-first. Nothing here is ever printed as-is: every path
/// leaves through `files::public_path`.
#[derive(Default)]
pub struct FileNames {
    map: HashMap<u64, Box<str>>,
    /// Insertion order, for eviction. Cheaper than any kind of LRU inside the ETW callback.
    order: VecDeque<u64>,
}

/// Roughly 4 MB of paths at the cap, which is the worst case, not the normal one.
pub const FILE_NAME_CAP: usize = 40_000;
/// Distinct files whose waiting is totaled. Over this the smallest halves are dropped.
pub const FILE_WAIT_CAP: usize = 8_192;

impl FileNames {
    pub fn insert(&mut self, key: u64, name: &str) {
        if key == 0 || name.is_empty() {
            return;
        }
        if self.map.insert(key, name.into()).is_none() {
            self.order.push_back(key);
            while self.order.len() > FILE_NAME_CAP {
                if let Some(old) = self.order.pop_front() {
                    self.map.remove(&old);
                }
            }
        }
    }

    pub fn get(&self, key: u64) -> Option<&str> {
        self.map.get(&key).map(|s| &**s)
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

/// Keeps a per-file tally from growing without limit over a long run: when it goes over `cap`,
/// only the half that waited longest is kept. Rare and bounded, so the ETW callback stays cheap.
pub fn cap_by_wait<K: Copy + Eq + std::hash::Hash, V: Waited>(m: &mut HashMap<K, V>, cap: usize) {
    if m.len() <= cap {
        return;
    }
    let mut totals: Vec<i64> = m.values().map(|v| v.waited()).collect();
    totals.sort_unstable();
    let cut = totals[totals.len() / 2];
    let mut room = cap / 2;
    m.retain(|_, v| {
        if v.waited() <= cut || room == 0 {
            return false;
        }
        room -= 1;
        true
    });
}

#[derive(Default, Clone, Copy)]
pub struct LatStat {
    pub count: u64,
    pub total: i64,
    pub max: i64,
    pub slow: u64,
}

pub enum Notable {
    LongExec(ExecRec),
    SlowFault(FaultRec),
    SlowIo(IoRec),
}

/// How wide one bucket of the per-routine activity map is. Small enough that a 1 s beat is still
/// four buckets apart, and it matches `period::BURST_S`, so a burst of DPCs lands in one bucket
/// exactly as the periodicity detector would have collapsed it anyway.
pub const BEAT_MS: f64 = 250.0;
/// One hour of buckets. Past that, a beat that is going to be visible has been visible for a while.
pub const BEAT_BUCKETS: usize = 14_400;
const BEAT_WORDS: usize = BEAT_BUCKETS / 64;
/// Distinct routines tracked, first come first served. 1.8 KB each, so this is the memory bound:
/// under 350 KB however long the run is and however many drivers the PC has.
pub const BEAT_ROUTINES: usize = 192;

/// Which buckets one DPC/ISR routine was active in, one bit each.
pub struct Beats(Box<[u64; BEAT_WORDS]>);

impl Beats {
    fn new() -> Beats {
        Beats(Box::new([0u64; BEAT_WORDS]))
    }

    pub fn set(&mut self, bucket: usize) {
        if let Some(word) = self.0.get_mut(bucket / 64) {
            *word |= 1 << (bucket % 64);
        }
    }

    /// The bucket indexes that were active, in order.
    pub fn buckets(&self) -> Vec<usize> {
        let mut out = Vec::new();
        for (i, word) in self.0.iter().enumerate() {
            let mut bits = *word;
            while bits != 0 {
                let b = bits.trailing_zeros() as usize;
                out.push(i * 64 + b);
                bits &= bits - 1;
            }
        }
        out
    }

    pub fn count(&self) -> usize {
        self.0.iter().map(|w| w.count_ones() as usize).sum()
    }

    /// Merges another routine's buckets in, for rolling several routines up into one driver.
    pub fn merge(&mut self, other: &Beats) {
        for (a, b) in self.0.iter_mut().zip(other.0.iter()) {
            *a |= *b;
        }
    }
}

impl Default for Beats {
    fn default() -> Beats {
        Beats::new()
    }
}

#[derive(Default)]
pub struct Inner {
    /// Newest ETW timestamp seen; tells the analyzer how far the (buffered) trace has caught up.
    pub latest_ts: i64,
    pub last_prune: i64,
    pub events: u64,

    pub execs: VecDeque<ExecRec>,
    pub faults: VecDeque<FaultRec>,
    pub ios: VecDeque<IoRec>,
    pub samples: VecDeque<SampleRec>,
    pub tid_pid: HashMap<u32, u32>,

    /// Context switches and thread wake-ups, kept only for `SWITCH_KEEP_MS` (see there).
    pub switches: VecDeque<SwitchRec>,
    pub readies: VecDeque<ReadyRec>,
    /// How many of each arrived over the whole run, so the report can price them.
    pub switch_events: u64,
    pub ready_events: u64,
    /// Set when the hard count cap threw records away, i.e. the ring no longer covers the window
    /// it is supposed to. The analysis then says so instead of drawing a conclusion.
    pub switches_overflowed: bool,
    /// Trace time of the newest record the count cap threw away, from either ring.
    pub ring_lost_until: Option<i64>,
    /// Count caps for the two rings, from `switch_caps`; 0 means "use the floor".
    pub switch_cap: usize,
    pub ready_cap: usize,

    pub routines: HashMap<(u64, u8), RoutineStat>,
    /// Whole-run activity per DPC/ISR routine in `BEAT_MS` buckets, so a driver that wakes every
    /// few seconds for a moment can be seen even though the ring buffers above only reach 20 s
    /// back and nothing it does is long enough to stall anything. One bit per bucket: the ETW
    /// callback does a hash lookup and sets a bit, and the memory is capped by `BEAT_ROUTINES`.
    pub beats: HashMap<u64, Beats>,
    /// ETW timestamp of the first DPC/ISR seen, which bucket 0 starts at.
    pub beat_t0: i64,
    pub faults_by_pid: HashMap<u32, LatStat>,
    pub disks: HashMap<u32, LatStat>,
    pub notable: Vec<Notable>,
    /// Notable events that arrived while `notable` was full: the analyzer was itself held up,
    /// which is exactly when there is most to report. Counted so the report can say so.
    pub notable_dropped: u64,

    /// File names, and the whole run's waiting totaled per file. The ring buffers above only
    /// reach 20 s back, so these are what the summary's file tables are built from.
    pub file_names: FileNames,
    pub file_wait: HashMap<u64, DiskFileWait>,
    /// Hard-fault waiting per (process, file), for "mostly reading back <file>".
    pub fault_file: HashMap<(u32, u64), FileWait>,

    /// --debug only: event counts by (provider GUID data1, opcode), and a few DPC/ISR
    /// events whose computed duration was rejected as (event time, InitialTime).
    pub debug_counts: HashMap<(u32, u8), u64>,
    pub debug_rejected: Vec<(i64, i64)>,
    /// --debug only: DiskIo requests by (op, IrpFlags), so the flag values can be checked live.
    pub debug_irp_flags: HashMap<(u8, u32), u64>,

    /// Module-level call stacks, when the session asks for them (see `stacks`).
    pub stacks: crate::stacks::StackState,
}

pub struct Shared {
    pub inner: Mutex<Inner>,
    pub exec_warn: i64,
    pub fault_warn: i64,
    pub io_warn: i64,
    /// How much history the ring buffers keep.
    pub keep: i64,
    /// Whether context switches and thread wake-ups are being recorded at all. Off in light mode
    /// and under `--no-switches`; when off the session never asks for the events, so this only
    /// guards the bookkeeping.
    pub switches: bool,
    pub debug: bool,
}

/// How far back the context-switch rings reach, in ms of TRACE time.
///
/// What has to fit: a flagged moment looks 3 s back and 0.3 s forward, and is only analyzed once
/// the trace has caught up past its end, so 3.3 s of history has to still be there at that point.
/// A whole-PC freeze is ~1 s and is analyzed within ~0.4 s of its end. 6 s is that worst case
/// with most of it again as headroom, and no more: this is the highest-volume class in the
/// kernel logger and every extra second is megabytes.
pub const SWITCH_KEEP_MS: f64 = 6000.0;

/// Hard count caps, so a machine switching far faster than expected cannot grow the rings without
/// limit before the time-based pruning next runs. These are the floor; `switch_caps` scales them
/// with the processor count, because the rate does.
pub const SWITCH_CAP: usize = 300_000;
pub const READY_CAP: usize = 300_000;

/// Records per logical CPU the rings may hold. MEASURED, not estimated: a 32-thread desktop doing
/// ordinary work produced 141,000 context switches and 75,000 wake-ups per second (the tool's own
/// 1 kHz probes on every CPU are about half of that), i.e. 4,400 and 2,400 per CPU per second, or
/// 26,000 and 14,000 per CPU over the 6 s window. With the fixed 300,000 cap that machine kept 2 s
/// of history and no flagged moment could ever be analyzed. 40,000 / 24,000 leaves headroom.
const SWITCHES_PER_CPU: usize = 40_000;
const READIES_PER_CPU: usize = 24_000;
/// ...and a ceiling, so a 256-CPU server cannot ask for a quarter of a gigabyte: 2.5 M + 1.5 M
/// records of 24 bytes is 96 MB worst case. Past this the window is simply shorter, and
/// `switches_cover` says so per incident.
const SWITCH_CAP_MAX: usize = 2_500_000;
const READY_CAP_MAX: usize = 1_500_000;

/// (switch cap, ready cap) for a machine with `ncpu` logical CPUs.
pub fn switch_caps(ncpu: usize) -> (usize, usize) {
    ((ncpu * SWITCHES_PER_CPU).clamp(SWITCH_CAP, SWITCH_CAP_MAX), (ncpu * READIES_PER_CPU).clamp(READY_CAP, READY_CAP_MAX))
}

impl Inner {
    /// O(1) per event: push, then drop from the front if the cap is exceeded.
    pub fn push_switch(&mut self, r: SwitchRec) {
        self.switch_events += 1;
        self.switches.push_back(r);
        if self.switches.len() > self.switch_cap.max(SWITCH_CAP) {
            let lost = self.switches.pop_front().map(|r| r.ts);
            self.ring_lost_until = self.ring_lost_until.max(lost);
            self.switches_overflowed = true;
        }
    }

    pub fn push_ready(&mut self, r: ReadyRec) {
        self.ready_events += 1;
        self.readies.push_back(r);
        if self.readies.len() > self.ready_cap.max(READY_CAP) {
            let lost = self.readies.pop_front().map(|r| r.ts);
            self.ring_lost_until = self.ring_lost_until.max(lost);
            self.switches_overflowed = true;
        }
    }

    /// Do the switch rings honestly reach back to `from`? Not if they were never filled, if the
    /// count cap threw away a record from `from` or later, or if their (short) history no longer
    /// covers it. Nothing may be read out of them otherwise: a missing wake-up record reverses a
    /// conclusion.
    ///
    /// The cap only ever drops the OLDEST record, so everything after `ring_lost_until` is whole.
    /// (Any overflow used to disqualify the rest of the run, which on a 32-CPU PC was all of it.)
    pub fn switches_cover(&self, from: i64) -> bool {
        self.ring_lost_until.is_none_or(|lost| lost < from)
            && self.switches.front().is_some_and(|r| r.ts <= from)
            && !self.readies.is_empty()
    }

    /// The switch and wake-up records in `[from, to]`.
    ///
    /// This runs under the lock the ETW callback needs for every event, and the rings hold up to
    /// millions of records, so it must not walk them: a binary search finds the window's edges.
    /// ETW delivers a session's events in timestamp order, but to be safe against neighbors that
    /// are slightly out of order the search is widened by a millisecond each side and the exact
    /// bounds are applied to what is left.
    pub fn switch_window(&self, from: i64, to: i64) -> (Vec<SwitchRec>, Vec<ReadyRec>) {
        let slop = crate::util::ms_to_ticks(1.0);
        let (lo, hi) = (from - slop, to + slop);
        let a = self.switches.partition_point(|r| r.ts < lo);
        let b = self.switches.partition_point(|r| r.ts <= hi);
        let switches = self.switches.range(a..b.max(a)).filter(|r| r.ts >= from && r.ts <= to).copied().collect();
        let a = self.readies.partition_point(|r| r.ts < lo);
        let b = self.readies.partition_point(|r| r.ts <= hi);
        let readies = self.readies.range(a..b.max(a)).filter(|r| r.ts >= from && r.ts <= to).copied().collect();
        (switches, readies)
    }

    /// What `diskstuck` needs to say who was stuck behind a slow request `[start, end]`, or `None`
    /// when the rings cannot honestly answer: they do not reach back to `start`, or the trace has
    /// not yet reached `after` past `end`. Returns the wake-ups from just before `end` to `after`
    /// past it, and only the switches that took one of THOSE threads off a processor since
    /// `start`.
    ///
    /// This runs under the lock the ETW callback needs for every event, and a long request on a
    /// busy PC spans hundreds of thousands of switch records, so it copies only what matches
    /// instead of the whole window.
    pub fn stuck_records(&self, start: i64, end: i64, before: i64, after: i64) -> Option<(Vec<SwitchRec>, Vec<ReadyRec>)> {
        if !self.switches_cover(start) || self.latest_ts < end + after {
            return None;
        }
        let (from, to) = (end - before, end + after);
        let a = self.readies.partition_point(|r| r.ts < from);
        let b = self.readies.partition_point(|r| r.ts <= to);
        let readies: Vec<ReadyRec> = self.readies.range(a..b.max(a)).copied().collect();
        let tids: std::collections::HashSet<u32> = readies.iter().map(|r| r.tid).collect();
        let a = self.switches.partition_point(|r| r.ts < start);
        let b = self.switches.partition_point(|r| r.ts <= to);
        let switches = self.switches.range(a..b.max(a)).filter(|s| tids.contains(&s.old_tid)).copied().collect();
        Some((switches, readies))
    }

    pub fn prune(&mut self, keep: i64) {
        let cutoff = self.latest_ts - keep;
        let switch_cutoff = self.latest_ts - crate::util::ms_to_ticks(SWITCH_KEEP_MS);
        while self.switches.front().is_some_and(|r| r.ts < switch_cutoff) {
            self.switches.pop_front();
        }
        while self.readies.front().is_some_and(|r| r.ts < switch_cutoff) {
            self.readies.pop_front();
        }
        while self.execs.front().is_some_and(|r| r.end < cutoff) {
            self.execs.pop_front();
        }
        while self.faults.front().is_some_and(|r| r.end < cutoff) {
            self.faults.pop_front();
        }
        while self.ios.front().is_some_and(|r| r.end < cutoff) {
            self.ios.pop_front();
        }
        while self.samples.front().is_some_and(|r| r.ts < cutoff) {
            self.samples.pop_front();
        }
        self.stacks.prune(self.latest_ts, keep, crate::util::ms_to_ticks(SWITCH_KEEP_MS));
        self.last_prune = self.latest_ts;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn beats_record_buckets_and_merge() {
        let mut a = Beats::default();
        for b in [0usize, 63, 64, 4000, BEAT_BUCKETS - 1] {
            a.set(b);
        }
        a.set(BEAT_BUCKETS); // out of range: dropped, never a panic
        a.set(BEAT_BUCKETS * 9);
        assert_eq!(a.buckets(), vec![0, 63, 64, 4000, BEAT_BUCKETS - 1]);
        assert_eq!(a.count(), 5);

        let mut b = Beats::default();
        b.set(1);
        b.set(64);
        a.merge(&b);
        assert_eq!(a.buckets(), vec![0, 1, 63, 64, 4000, BEAT_BUCKETS - 1], "merging is a union, not a sum");
        assert_eq!(Beats::default().buckets(), Vec::<usize>::new());
    }

    fn sw(ts: i64, new_tid: u32) -> SwitchRec {
        SwitchRec { ts, new_tid, old_tid: 0, cpu: 0, new_prio: 8, old_prio: 8, old_wait_reason: 0, old_wait_mode: 0, old_state: 5 }
    }

    /// The memory bounds stated next to the caps are only true if the records are this size.
    #[test]
    fn switch_records_stay_small_enough_for_the_stated_memory_bound() {
        assert_eq!(std::mem::size_of::<SwitchRec>(), 24);
        assert_eq!(std::mem::size_of::<ReadyRec>(), 24);
        const { assert!((SWITCH_CAP_MAX + READY_CAP_MAX) * 24 <= 96 << 20, "the two rings must stay under 96 MB") };
        // Was 48 before IrpFlags and ByteOffset were kept and 56 before Irp was (issue #20); the
        // comment on IoRec states the bound in these terms.
        assert_eq!(std::mem::size_of::<IoRec>(), 64);
    }

    /// Nothing may be read about who was stuck behind a request unless the rings reach back to
    /// its start AND the trace has caught up past its end.
    #[test]
    fn stuck_records_are_only_handed_out_for_windows_the_rings_cover() {
        let mut inner = Inner::default();
        for i in 0..100i64 {
            inner.push_switch(SwitchRec { old_tid: (i % 5) as u32 + 10, ..sw(i * 10, 0) });
            inner.push_ready(ReadyRec { ts: i * 10 + 5, tid: (i % 5) as u32 + 10, by_tid: 0, cpu: 0, flag: 0 });
        }
        inner.latest_ts = 995;
        assert!(inner.stuck_records(-5, 500, 1, 20).is_none(), "starts before the oldest record");
        assert!(inner.stuck_records(100, 980, 1, 20).is_none(), "the trace has not reached past the end yet");
        let (s, r) = inner.stuck_records(100, 500, 1, 20).expect("covered");
        assert_eq!(r.iter().map(|r| r.ts).collect::<Vec<_>>(), vec![505, 515]);
        assert!(s.iter().all(|s| s.ts >= 100 && s.ts <= 520 && (s.old_tid == 10 || s.old_tid == 11)), "only those threads' switches");
        assert!(!s.is_empty());
        inner.ring_lost_until = Some(200);
        assert!(inner.stuck_records(100, 500, 1, 20).is_none(), "records from inside the window were thrown away");
    }

    #[test]
    fn the_caps_follow_the_processor_count_between_a_floor_and_a_ceiling() {
        assert_eq!(switch_caps(4), (SWITCH_CAP, READY_CAP), "a small PC keeps the floor");
        assert_eq!(switch_caps(32), (1_280_000, 768_000));
        // The rate measured on that 32-thread PC, over the whole 6 s window, has to fit.
        assert!(switch_caps(32).0 >= 141_000 * 6 && switch_caps(32).1 >= 75_000 * 6);
        assert_eq!(switch_caps(1024), (SWITCH_CAP_MAX, READY_CAP_MAX));
        let mut inner = Inner { switch_cap: SWITCH_CAP + 5, ..Inner::default() };
        for i in 0..(SWITCH_CAP as i64 + 5) {
            inner.push_switch(sw(i, 1));
        }
        assert!(!inner.switches_overflowed, "the configured cap is the one that counts");
    }

    #[test]
    fn the_switch_rings_wrap_keep_order_and_admit_when_they_dropped_something() {
        let mut inner = Inner::default();
        for i in 0..(SWITCH_CAP as i64 + 10) {
            inner.push_switch(sw(i, i as u32));
        }
        assert_eq!(inner.switches.len(), SWITCH_CAP);
        assert_eq!(inner.switch_events, SWITCH_CAP as u64 + 10);
        assert_eq!(inner.switches.front().unwrap().ts, 10, "the oldest went first");
        assert_eq!(inner.switches.back().unwrap().ts, SWITCH_CAP as i64 + 9);
        assert!(inner.switches.iter().zip(inner.switches.iter().skip(1)).all(|(a, b)| a.ts < b.ts), "still in order");
        assert!(inner.switches_overflowed, "dropping records has to be admitted, not hidden");
        assert_eq!(inner.ring_lost_until, Some(9));

        let mut small = Inner::default();
        small.push_switch(sw(1, 7));
        small.push_ready(ReadyRec { ts: 2, tid: 7, by_tid: 9, cpu: 0, flag: 0 });
        assert!(!small.switches_overflowed);
        assert_eq!((small.switch_events, small.ready_events), (1, 1));
    }

    /// The switch rings keep far less history than the other ring buffers, and pruning must not
    /// touch the longer-lived ones early (or leave the short ones long).
    #[test]
    fn pruning_uses_the_short_window_for_switches_and_the_long_one_for_everything_else() {
        let mut inner = Inner::default();
        let long_ago = -crate::util::ms_to_ticks(10_000.0);
        inner.push_switch(sw(long_ago, 1));
        inner.push_switch(sw(-crate::util::ms_to_ticks(1000.0), 2));
        inner.push_ready(ReadyRec { ts: long_ago, tid: 1, by_tid: 0, cpu: 0, flag: 0 });
        inner.samples.push_back(SampleRec { ts: long_ago, cpu: 0, tid: 1, ip: 0 });
        inner.latest_ts = 0;
        inner.prune(crate::util::ms_to_ticks(20_000.0));
        assert_eq!(inner.switches.len(), 1, "only the record older than 6 s went");
        assert_eq!(inner.switches.front().unwrap().new_tid, 2);
        assert!(inner.readies.is_empty());
        assert_eq!(inner.samples.len(), 1, "20 s of samples are still kept");
    }

    #[test]
    fn a_window_of_switches_is_found_without_walking_the_ring() {
        let mut inner = Inner::default();
        let ms = crate::util::ms_to_ticks;
        for i in 0..1000 {
            inner.push_switch(sw(ms(i as f64), i as u32));
            inner.push_ready(ReadyRec { ts: ms(i as f64), tid: i as u32, by_tid: 0, cpu: 0, flag: 0 });
        }
        let (s, r) = inner.switch_window(ms(100.0), ms(200.0));
        assert_eq!((s.len(), r.len()), (101, 101), "both ends are inclusive");
        assert_eq!((s.first().unwrap().new_tid, s.last().unwrap().new_tid), (100, 200));
        assert_eq!(inner.switch_window(ms(5000.0), ms(6000.0)).0.len(), 0);
        assert_eq!(inner.switch_window(ms(-50.0), ms(2.0)).0.len(), 3);
    }

    /// The rings only reach a few seconds back, so whether they cover a window has to be asked
    /// before anything is read out of them.
    #[test]
    fn the_rings_admit_when_they_do_not_cover_a_window() {
        let mut inner = Inner::default();
        assert!(!inner.switches_cover(0), "nothing recorded covers nothing");
        inner.push_switch(sw(100, 7));
        assert!(!inner.switches_cover(100), "switches without wake-ups cannot answer anything");
        inner.push_ready(ReadyRec { ts: 110, tid: 7, by_tid: 0, cpu: 0, flag: 0 });
        assert!(inner.switches_cover(100) && inner.switches_cover(500));
        assert!(!inner.switches_cover(99), "one tick before the oldest record is not covered");
        // The cap drops the oldest record only, so a window that starts after the last dropped
        // record is whole, and one that starts at or before it is not.
        inner.ring_lost_until = Some(99);
        assert!(inner.switches_cover(100));
        inner.ring_lost_until = Some(100);
        assert!(!inner.switches_cover(100), "a record from inside the window was thrown away");
    }

    /// A DPC readies threads on nobody's behalf; Microsoft documents `Flag` 0x1 for exactly that.
    #[test]
    fn a_waker_is_only_named_when_there_really_was_one() {
        let r = |by_tid, flag| ReadyRec { ts: 0, tid: 100, by_tid, cpu: 0, flag };
        assert_eq!(r(55, 0).waker(), Some(55));
        assert_eq!(r(55, READY_FROM_DPC).waker(), None, "readied from a DPC: no waking thread");
        assert_eq!(r(55, 0x2).waker(), Some(55), "a swapped-out kernel stack says nothing about the waker");
        assert_eq!(r(0, 0).waker(), None);
        assert_eq!(r(100, 0).waker(), None, "a thread does not wake itself");
    }
}
