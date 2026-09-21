//! Data shared between the ETW consumer thread (writer) and the analyzer (reader).
//! All timestamps and durations are raw QPC ticks.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

pub const KIND_DPC: u8 = 0;
pub const KIND_TIMER_DPC: u8 = 1;
pub const KIND_THREADED_DPC: u8 = 2;
pub const KIND_ISR: u8 = 3;

pub fn kind_name(k: u8) -> &'static str {
    match k {
        KIND_DPC => "DPC",
        KIND_TIMER_DPC => "timer DPC",
        KIND_THREADED_DPC => "threaded DPC",
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

#[derive(Clone, Copy)]
pub struct IoRec {
    pub end: i64,
    pub dur: i64,
    pub disk: u32,
    pub tid: u32,
    pub pid: u32,
    pub size: u32,
    /// b'R', b'W' or b'F'
    pub op: u8,
    /// FileObject of the file, or 0 (flush events carry none). See `Inner::file_names`.
    pub file: u64,
}

#[derive(Clone, Copy)]
pub struct SampleRec {
    pub ts: i64,
    pub cpu: u16,
    pub tid: u32,
    pub ip: u64,
}

#[derive(Default, Clone, Copy)]
pub struct RoutineStat {
    pub count: u64,
    pub total: i64,
    pub max: i64,
    pub over_warn: u64,
}

/// How long requests to one file waited over the whole run.
#[derive(Default, Clone, Copy)]
pub struct FileWait {
    pub disk: u32,
    pub count: u64,
    pub total: i64,
    pub max: i64,
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
pub fn cap_by_wait<K: Copy + Eq + std::hash::Hash>(m: &mut HashMap<K, FileWait>, cap: usize) {
    if m.len() <= cap {
        return;
    }
    let mut totals: Vec<i64> = m.values().map(|v| v.total).collect();
    totals.sort_unstable();
    let cut = totals[totals.len() / 2];
    let mut room = cap / 2;
    m.retain(|_, v| {
        if v.total <= cut || room == 0 {
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
    pub file_wait: HashMap<u64, FileWait>,
    /// Hard-fault waiting per (process, file), for "mostly reading back <file>".
    pub fault_file: HashMap<(u32, u64), FileWait>,

    /// --debug only: event counts by (provider GUID data1, opcode), and a few DPC/ISR
    /// events whose computed duration was rejected as (event time, InitialTime).
    pub debug_counts: HashMap<(u32, u8), u64>,
    pub debug_rejected: Vec<(i64, i64)>,
}

pub struct Shared {
    pub inner: Mutex<Inner>,
    pub exec_warn: i64,
    pub fault_warn: i64,
    pub io_warn: i64,
    /// How much history the ring buffers keep.
    pub keep: i64,
    pub debug: bool,
}

impl Inner {
    pub fn prune(&mut self, keep: i64) {
        let cutoff = self.latest_ts - keep;
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
}
