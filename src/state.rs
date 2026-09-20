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
    pub faults_by_pid: HashMap<u32, LatStat>,
    pub disks: HashMap<u32, LatStat>,
    pub notable: Vec<Notable>,

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
