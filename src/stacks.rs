//! Module-level call stacks (issue #20 step 3, the "deep mode" of #19): which DRIVERS were on the
//! call stack of a thread that waited, or of a disk request that was slow. Never function names:
//! those need Microsoft's symbol files, i.e. network access, which this tool does not have.
//!
//! HOW STACKS ARE ASKED FOR. `TraceSetInformation(session, TraceStackTracingInfo, CLASSIC_EVENT_ID[],
//! len)`: "calling this function enables stack tracing of the specified kernel events", called
//! "after calling StartTrace"; a `CLASSIC_EVENT_ID` is the kernel event class GUID plus the event
//! type, and the list "is limited to 256 elements".
//!   https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-tracesetinformation
//!   https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-classic_event_id
//!   https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ne-evntrace-trace_query_info_class
//! Microsoft's own sample does exactly this on a session started with
//! EVENT_TRACE_SYSTEM_LOGGER_MODE, the kind `etw::Session` starts:
//!   https://github.com/microsoft/Windows-driver-samples/blob/main/general/tracing/SystemTraceControl/SystemTraceControl.cpp
//! The setting belongs to the session whose handle is passed (Geoff Chappell: it "specifies which
//! NT Kernel Logger events are to have call-stack tracing information added whenever the event is
//! sent to the given trace session" - reverse engineering, not a primary source:
//! https://www.geoffchappell.com/studies/windows/win32/advapi32/api/etw/logapi/set.htm), so it dies
//! with the session. Nothing system-wide is changed. In particular the tool does NOT set
//! `DisablePagingExecutive`, which the same Microsoft page suggests for complete x64 kernel stacks:
//! that is a registry change that outlives the run. Some kernel stacks may therefore be missing, and
//! the report says so rather than guessing.
//!
//! WHAT A STACK EVENT LOOKS LIKE. Class StackWalk, GUID {def2fe46-7bd6-4b80-bd94-f57fe20d0ce3},
//! event type 32 (StackWalk_Event): EventTimeStamp u64 @0 ("Original event time stamp from the
//! event header. Use this time stamp to match the stack to an event"), StackProcess u32 @8,
//! StackThread u32 @12 ("The thread identifier of the original event"), then Stack1..Stack192, each
//! a pointer ("Use the size of the event to determine how many Stackn properties contain valid
//! addresses"). Pointer size comes from the event header flags (EVENT_HEADER_FLAG_32_BIT_HEADER /
//! _64_BIT_HEADER).
//!   https://learn.microsoft.com/en-us/windows/win32/etw/stackwalk
//!   https://learn.microsoft.com/en-us/windows/win32/etw/stackwalk-event
//! UNVERIFIED: that Stack1 is the innermost frame (the most recent call) and the last one the
//! outermost. The docs only say "Address of the call". `--debug` prints a few raw stacks in
//! Stack1-first order so an elevated run can confirm it (ntoskrnl should come first, the user-mode
//! frames last).
//!
//! WHOSE STACK EACH EVENT CARRIES.
//! * CSwitch: the thread switched IN. Windows Performance Analyzer calls it "NewThreadStack: The
//!   stack of the new thread when it is switched in. Usually indicates what the thread was blocked
//!   or waiting on." That is where it waited. (Microsoft Learn, WPT exercise 3:
//!   https://learn.microsoft.com/en-us/windows-hardware/test/wpt/optimizing-performance-and-responsiveness-exercise-3)
//! * ReadyThread: the READYING thread ("ReadyThreadStack: The stack of the readying thread", same
//!   page) - the waker, not the waiter. Collected for the cost check; the report does not word
//!   anything from it.
//! * DiskIo ReadInit / WriteInit / FlushInit (12, 13, 15; needs EVENT_TRACE_FLAG_DISK_IO_INIT): the
//!   start of a request, with Irp and IssuingThreadId.
//!   https://learn.microsoft.com/en-us/windows/win32/etw/diskio-typegroup2
//!   UNVERIFIED which thread's context it is logged in; `--debug` counts whether each stack's
//!   StackThread was the event header's thread or the IssuingThreadId.
//! * PageFault HardFault (32): logged when the fault's read completes (it carries InitialTime).
//!   UNVERIFIED whether in the faulting thread's context; `--debug` counts StackThread against the
//!   payload's TThreadId the same way.
//!
//! USER-MODE FRAMES. The session has no image-load events, so a user-mode address cannot be tied
//! to a DLL; and a user's DLL paths are exactly what a public report must not carry. User-mode
//! frames are counted and collapsed into the program's name.

use std::collections::{HashMap, VecDeque};

use windows_sys::core::GUID;
use windows_sys::Win32::System::Diagnostics::Etw::{DiskIoGuid, PageFaultGuid, ThreadGuid, CLASSIC_EVENT_ID};

use crate::modules::KERNEL_SPACE;
use crate::util::ms_to_ticks;

/// StackWalk class GUID, first field (enough to tell the classic kernel classes apart, as in
/// `etw::events`). https://learn.microsoft.com/en-us/windows/win32/etw/stackwalk
pub const GUID_STACKWALK: u32 = 0xdef2_fe46;
/// "Event type value, 32 | Stack tracing event."
pub const OPCODE_STACK: u8 = 32;

/// Kernel frames kept per stack. Deeper kernel stacks exist, but the drivers that matter here sit
/// well inside this many frames of the wait, and the bound is what the memory figures below use.
pub const MAX_KERNEL_FRAMES: usize = 40;
/// Stack1..Stack192.
const MAX_FRAMES: usize = 192;

/// Which kinds of event get a stack.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub enum Kind {
    CSwitch = 0,
    Ready = 1,
    DiskInit = 2,
    Fault = 3,
}

impl Kind {
    pub const ALL: [Kind; 4] = [Kind::CSwitch, Kind::Ready, Kind::DiskInit, Kind::Fault];

    pub fn name(self) -> &'static str {
        match self {
            Kind::CSwitch => "cswitch",
            Kind::Ready => "ready",
            Kind::DiskInit => "diskinit",
            Kind::Fault => "fault",
        }
    }

    fn bit(self) -> u8 {
        1 << self as u8
    }
}

/// A set of `Kind`s.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct StackSet(u8);

impl StackSet {
    pub const NONE: StackSet = StackSet(0);
    /// PROVISIONAL default, to be set from a measured cost: one stack per disk request and one per
    /// hard page fault. Both classes arrive at hundreds to a few thousand a second under heavy
    /// load (the storage trace measured ~1,750 disk requests a second), against the ~141,000 context
    /// switches a second measured on a 32-thread PC, and they are the two that answer "which
    /// drivers were in the path of a slow disk request" and "where was a thread stuck on paging".
    pub const DEFAULT: StackSet = StackSet(1 << Kind::DiskInit as u8 | 1 << Kind::Fault as u8);

    pub fn of(kinds: &[Kind]) -> StackSet {
        StackSet(kinds.iter().fold(0, |a, k| a | k.bit()))
    }

    pub fn has(self, k: Kind) -> bool {
        self.0 & k.bit() != 0
    }

    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub fn without(self, k: Kind) -> StackSet {
        StackSet(self.0 & !k.bit())
    }

    pub fn kinds(self) -> Vec<Kind> {
        Kind::ALL.into_iter().filter(|k| self.has(*k)).collect()
    }

    /// "diskinit,fault", or "none".
    pub fn names(self) -> String {
        let v: Vec<&str> = self.kinds().into_iter().map(Kind::name).collect();
        if v.is_empty() {
            "none".into()
        } else {
            v.join(",")
        }
    }

    /// "disk requests and hard page faults", for the line at the top of the report.
    pub fn plain(self) -> String {
        let words: Vec<String> = self
            .kinds()
            .into_iter()
            .map(|k| {
                match k {
                    Kind::CSwitch => "thread switches",
                    Kind::Ready => "thread wake-ups",
                    Kind::DiskInit => "disk requests",
                    Kind::Fault => "hard page faults",
                }
                .to_string()
            })
            .collect();
        match words.split_last() {
            Some((last, rest)) if !rest.is_empty() => format!("{} and {last}", rest.join(", ")),
            _ => words.join(""),
        }
    }

    /// `--stacks cswitch,ready,diskinit,fault` (also "none" and "default").
    pub fn parse(s: &str) -> Result<StackSet, String> {
        let mut set = StackSet::NONE;
        for word in s.split(',').map(|w| w.trim().to_ascii_lowercase()).filter(|w| !w.is_empty()) {
            match word.as_str() {
                "none" => {}
                "default" => set = StackSet(set.0 | StackSet::DEFAULT.0),
                "all" => set = StackSet::of(&Kind::ALL),
                w => match Kind::ALL.into_iter().find(|k| k.name() == w) {
                    Some(k) => set = StackSet(set.0 | k.bit()),
                    None => return Err(format!("unknown stack event '{w}' (use cswitch, ready, diskinit, fault, all or none)")),
                },
            }
        }
        Ok(set)
    }

    /// The `CLASSIC_EVENT_ID`s for `TraceSetInformation`. Types from the class pages:
    /// CSwitch = Thread type 36 (https://learn.microsoft.com/en-us/windows/win32/etw/cswitch),
    /// ReadyThread = Thread type 50 (https://learn.microsoft.com/en-us/windows/win32/etw/readythread),
    /// ReadInit 12 / WriteInit 13 / FlushInit 15 (https://learn.microsoft.com/en-us/windows/win32/etw/diskio),
    /// HardFault = PageFault type 32 (https://learn.microsoft.com/en-us/windows/win32/etw/pagefault-hardfault).
    pub fn classic_ids(self) -> Vec<CLASSIC_EVENT_ID> {
        let id = |guid: GUID, ty: u8| CLASSIC_EVENT_ID { EventGuid: guid, Type: ty, Reserved: [0; 7] };
        let mut out = Vec::new();
        if self.has(Kind::CSwitch) {
            out.push(id(ThreadGuid, 36));
        }
        if self.has(Kind::Ready) {
            out.push(id(ThreadGuid, 50));
        }
        if self.has(Kind::DiskInit) {
            out.extend([id(DiskIoGuid, 12), id(DiskIoGuid, 13), id(DiskIoGuid, 15)]);
        }
        if self.has(Kind::Fault) {
            out.push(id(PageFaultGuid, 32));
        }
        out
    }
}

// ---------------------------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------------------------

/// One StackWalk event, user-mode frames already reduced to a count.
#[derive(Clone, Debug, PartialEq)]
pub struct RawStack {
    /// EventTimeStamp: the original event's header time stamp.
    pub ts: i64,
    pub pid: u32,
    /// StackThread: the original event's thread.
    pub tid: u32,
    /// Kernel-mode addresses in the order the event carries them (Stack1 first), capped at
    /// `MAX_KERNEL_FRAMES`.
    pub kernel: Vec<u64>,
    /// Every frame the event carried, and how many of them were user-mode addresses.
    pub frames: u32,
    pub user_frames: u32,
    /// The payload ended part-way through an address.
    pub ragged: bool,
}

/// Is `addr` a kernel-mode address? x64 kernel space starts at 0xFFFF8000'00000000 (the same bound
/// `modules` uses); a 32-bit kernel's at 0x80000000, which is only true of the default 2 GB split
/// (UNVERIFIED for /3GB systems, which this 64-bit-only tool never runs on).
pub fn is_kernel(addr: u64, ptr64: bool) -> bool {
    if ptr64 {
        addr >= KERNEL_SPACE
    } else {
        (0x8000_0000..=0xFFFF_FFFF).contains(&addr)
    }
}

fn rd_u32(d: &[u8], off: usize) -> Option<u32> {
    d.get(off..off + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn rd_u64(d: &[u8], off: usize) -> Option<u64> {
    d.get(off..off + 8).map(|b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
}

/// StackWalk_Event: EventTimeStamp u64 @0, StackProcess u32 @8, StackThread u32 @12, Stack1.. @16.
/// `None` when even the fixed part is missing. A stack with no frames at all is still returned:
/// it is a stack that arrived and could not be walked, which is worth counting.
pub fn parse(d: &[u8], ptr64: bool) -> Option<RawStack> {
    let ts = rd_u64(d, 0)? as i64;
    let pid = rd_u32(d, 8)?;
    let tid = rd_u32(d, 12)?;
    let width = if ptr64 { 8 } else { 4 };
    let body = d.get(16..)?;
    let n = (body.len() / width).min(MAX_FRAMES);
    let mut out = RawStack { ts, pid, tid, kernel: Vec::new(), frames: n as u32, user_frames: 0, ragged: body.len() % width != 0 };
    for i in 0..n {
        let off = 16 + i * width;
        let addr = if ptr64 { rd_u64(d, off)? } else { rd_u32(d, off)? as u64 };
        if is_kernel(addr, ptr64) {
            if out.kernel.len() < MAX_KERNEL_FRAMES {
                out.kernel.push(addr);
            }
        } else {
            out.user_frames += 1;
        }
    }
    Some(out)
}

// ---------------------------------------------------------------------------------------------
// Keeping the stacks that matter
// ---------------------------------------------------------------------------------------------

/// A kept stack: kernel addresses, Stack1 first, and whether it went on into user mode.
#[derive(Clone, Debug, PartialEq)]
pub struct Stack {
    pub pid: u32,
    pub frames: Box<[u64]>,
    pub user: bool,
}

impl Stack {
    fn from_raw(r: &RawStack) -> Stack {
        Stack { pid: r.pid, frames: r.kernel.clone().into_boxed_slice(), user: r.user_frames > 0 }
    }
}

/// The stack a thread was switched back in with after a wait: where it had been waiting.
#[derive(Clone, Debug, PartialEq)]
pub struct SwitchInStack {
    pub ts: i64,
    pub tid: u32,
    /// When it was switched OUT into that wait: the exact `SwitchRec::ts`, which is what ties this
    /// stack to one wait and not the thread's next one.
    pub since: i64,
    pub stack: Stack,
}

/// A hard page fault's stack. `tid` is the payload's TThreadId.
#[derive(Clone, Debug, PartialEq)]
pub struct FaultStack {
    pub start: i64,
    pub end: i64,
    pub tid: u32,
    pub stack: Stack,
}

/// The readying thread's stack when `tid` was woken from a wait that began at `since`.
#[derive(Clone, Debug, PartialEq)]
pub struct ReadyStack {
    pub ts: i64,
    pub tid: u32,
    pub since: i64,
    pub stack: Stack,
}

/// What is known about the issuing stack of one slow disk request.
#[derive(Clone, Debug, PartialEq)]
pub enum IoStack {
    Found(Stack),
    /// The start of the request was seen, but its stack never arrived (Windows could not walk it).
    NoStack,
    /// No start event was seen for it (it began before the trace did, or the Irp did not match).
    NoInit,
}

/// What the next stack event on a processor belongs to. The stack walk is written right after the
/// event it belongs to by the processor that logged it, so a few per processor are enough; if the
/// stack turns up on another processor anyway, every slot is searched (and `--debug` counts it).
#[derive(Clone, Copy, Debug)]
enum Want {
    /// Counted for the cost, not kept.
    Ignore,
    DiskInit {
        irp: u64,
    },
    Fault {
        start: i64,
        tid: u32,
    },
    SwitchIn {
        tid: u32,
        since: i64,
    },
    Readied {
        tid: u32,
        since: i64,
    },
}

#[derive(Clone, Copy, Debug)]
struct Pending {
    ts: i64,
    /// The event header's thread, and the thread the payload names (0 when none).
    tids: [u32; 2],
    kind: Kind,
    want: Want,
}

const PENDING_PER_CPU: usize = 4;

/// Per-kind price, for the cost line and `--debug`.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct KindCount {
    pub stacks: u64,
    pub bytes: u64,
    pub frames: u64,
    pub kernel_frames: u64,
    pub max_frames: u32,
    /// Stacks whose StackThread was the event header's thread, and ones where it was the thread
    /// the payload names instead: this is how an elevated run tells whose stack each event carries.
    pub by_header_tid: u64,
    pub by_payload_tid: u64,
    /// Stacks that were kept because they belong to something the report can use.
    pub kept: u64,
    /// Stacks with no kernel frame at all.
    pub empty: u64,
}

impl KindCount {
    fn add(&mut self, r: &RawStack, bytes: usize) {
        self.stacks += 1;
        self.bytes += bytes as u64;
        self.frames += r.frames as u64;
        self.kernel_frames += r.kernel.len() as u64;
        self.max_frames = self.max_frames.max(r.frames);
        if r.kernel.is_empty() {
            self.empty += 1;
        }
    }
}

#[derive(Clone, Default, Debug)]
pub struct Counts {
    pub kinds: [KindCount; 4],
    /// Stacks that matched no event this tool asked for.
    pub unmatched: KindCount,
    /// Matched, but only by searching the other processors' slots.
    pub other_cpu: u64,
    /// Events whose stack never arrived before a newer event took its slot.
    pub overwritten: u64,
    pub ragged: u64,
    /// Disk request completions whose start event was seen (by Irp), and ones whose was not.
    pub io_with_init: u64,
    pub io_without_init: u64,
    /// Slow requests: with an issuing stack, start seen but no stack, no start seen.
    pub slow_found: u64,
    pub slow_no_stack: u64,
    pub slow_no_init: u64,
    /// Start events not tracked because too many requests were outstanding at once.
    pub init_dropped: u64,
}

impl Counts {
    /// Every stack event that arrived.
    pub fn total(&self) -> u64 {
        self.kinds.iter().map(|k| k.stacks).sum::<u64>() + self.unmatched.stacks
    }

    pub fn total_bytes(&self) -> u64 {
        self.kinds.iter().map(|k| k.bytes).sum::<u64>() + self.unmatched.bytes
    }
}

/// Outstanding disk requests whose start was seen. A queue is tens to hundreds deep; this bound is
/// only there so a start whose completion never arrives cannot grow the map for ever.
pub const IO_INIT_CAP: usize = 65_536;
/// Slow requests' issuing stacks. One per request over the warn threshold (200 ms by default);
/// 4,096 of them is minutes of a failing drive, and the pruning by time normally keeps far fewer.
pub const SLOW_IO_CAP: usize = 4_096;
/// Hard faults of `KEEP_WAIT_MS` or more.
pub const FAULT_CAP: usize = 8_192;
/// Switch-ins after a disk-type or lock-like wait of `KEEP_WAIT_MS` or more (only with the CSwitch
/// stacks on). Scaled with the processor count like the switch rings (`state::switch_caps`),
/// because the rate is: see `stack_caps`.
const SWITCH_INS_PER_CPU: usize = 1_000;
const SWITCH_IN_FLOOR: usize = 20_000;
/// 100,000 stacks of at most `MAX_KERNEL_FRAMES` addresses is ~36 MB at the very worst, on a PC
/// with 100 CPUs or more that is also waiting on disks and locks non-stop.
const SWITCH_IN_CEILING: usize = 100_000;

/// (switch-in cap, ready cap) for `ncpu` logical CPUs.
pub fn stack_caps(ncpu: usize) -> (usize, usize) {
    let n = (ncpu * SWITCH_INS_PER_CPU).clamp(SWITCH_IN_FLOOR, SWITCH_IN_CEILING);
    (n, n)
}

/// Only waits at least this long are worth a stack: the same bar `diskstuck` sets for being stuck
/// behind a request at all.
pub const KEEP_WAIT_MS: f64 = crate::diskstuck::STUCK_MIN_MS;

/// Everything the ETW callback keeps about stacks. Lives in `state::Inner`, under its lock.
#[derive(Default)]
pub struct StackState {
    /// What the session was really asked for (empty: stacks are off).
    pub set: StackSet,
    /// Why `TraceSetInformation` refused, when it did (a Win32 error code).
    pub enable_error: Option<u32>,
    pub switch_cap: usize,
    pub ready_cap: usize,
    per_cpu: Vec<VecDeque<Pending>>,
    io_init: HashMap<u64, (i64, Option<Stack>)>,
    pub slow_io: VecDeque<(i64, u64, IoStack)>,
    pub faults: VecDeque<FaultStack>,
    pub switch_ins: VecDeque<SwitchInStack>,
    pub readies: VecDeque<ReadyStack>,
    /// Threads currently in a wait: when they went in and why. Only kept with CSwitch or Ready
    /// stacks on, and only so that the stacks worth keeping can be picked in the callback.
    off_at: HashMap<u32, (i64, i8)>,
    /// Trace time of the newest record a count cap threw away, per ring: [slow_io, faults,
    /// switch_ins, readies]. Everything after it is whole (see `state::Inner::switches_cover`).
    pub lost_until: [Option<i64>; 4],
    pub counts: Counts,
    /// A couple of raw stacks per kind (kernel addresses, Stack1 first, and the user frame count)
    /// for `--debug` to show the frame order.
    pub samples: Vec<(Kind, Vec<u64>, u32)>,
}

fn push_capped<T>(q: &mut VecDeque<T>, item: T, cap: usize, ts: impl Fn(&T) -> i64, lost: &mut Option<i64>) {
    q.push_back(item);
    while q.len() > cap.max(1) {
        if let Some(old) = q.pop_front() {
            *lost = (*lost).max(Some(ts(&old)));
        }
    }
}

/// A wait worth a stack: one that can be a thread waiting on the disk or on a lock.
fn worth(reason: i8) -> bool {
    crate::diskstuck::disk_wait(reason) || crate::switches::lock_wait(reason)
}

impl StackState {
    pub fn new(set: StackSet, ncpu: usize) -> StackState {
        let (switch_cap, ready_cap) = stack_caps(ncpu);
        StackState { set, switch_cap, ready_cap, ..StackState::default() }
    }

    fn pend(&mut self, cpu: u16, p: Pending) {
        let cpu = cpu as usize;
        if self.per_cpu.len() <= cpu {
            self.per_cpu.resize_with(cpu + 1, VecDeque::new);
        }
        let slots = &mut self.per_cpu[cpu];
        slots.push_back(p);
        if slots.len() > PENDING_PER_CPU {
            if let Some(old) = slots.pop_front() {
                if !matches!(old.want, Want::Ignore) {
                    self.counts.overwritten += 1;
                }
            }
        }
    }

    fn take(&mut self, cpu: u16, ts: i64, tid: u32) -> Option<(Pending, bool)> {
        let hit = |p: &Pending| p.ts == ts && (p.tids[0] == tid || p.tids[1] == tid && tid != 0);
        if let Some(slots) = self.per_cpu.get_mut(cpu as usize) {
            if let Some(i) = slots.iter().position(hit) {
                return slots.remove(i).map(|p| (p, false));
            }
        }
        for slots in self.per_cpu.iter_mut() {
            if let Some(i) = slots.iter().position(hit) {
                return slots.remove(i).map(|p| (p, true));
            }
        }
        None
    }

    /// DiskIo ReadInit / WriteInit / FlushInit.
    pub fn on_disk_init(&mut self, ts: i64, cpu: u16, header_tid: u32, irp: u64, issuer: u32) {
        if !self.set.has(Kind::DiskInit) {
            return;
        }
        let want = if irp == 0 {
            Want::Ignore
        } else if self.io_init.len() >= IO_INIT_CAP && !self.io_init.contains_key(&irp) {
            self.counts.init_dropped += 1;
            Want::Ignore
        } else {
            self.io_init.insert(irp, (ts, None));
            Want::DiskInit { irp }
        };
        self.pend(cpu, Pending { ts, tids: [header_tid, issuer], kind: Kind::DiskInit, want });
    }

    /// A disk request completed. Its issuing stack is kept only if it was slow.
    pub fn on_disk_done(&mut self, end: i64, irp: u64, slow: bool) {
        if !self.set.has(Kind::DiskInit) || irp == 0 {
            return;
        }
        let found = self.io_init.remove(&irp);
        if found.is_some() {
            self.counts.io_with_init += 1;
        } else {
            self.counts.io_without_init += 1;
        }
        if !slow {
            return;
        }
        let what = match found {
            Some((_, Some(stack))) => {
                self.counts.slow_found += 1;
                IoStack::Found(stack)
            }
            Some((_, None)) => {
                self.counts.slow_no_stack += 1;
                IoStack::NoStack
            }
            None => {
                self.counts.slow_no_init += 1;
                IoStack::NoInit
            }
        };
        push_capped(&mut self.slow_io, (end, irp, what), SLOW_IO_CAP, |r| r.0, &mut self.lost_until[0]);
    }

    /// A hard page fault completed at `ts`.
    pub fn on_fault(&mut self, ts: i64, cpu: u16, header_tid: u32, start: i64, tid: u32) {
        if !self.set.has(Kind::Fault) {
            return;
        }
        let want = if ts - start >= ms_to_ticks(KEEP_WAIT_MS) { Want::Fault { start, tid } } else { Want::Ignore };
        self.pend(cpu, Pending { ts, tids: [header_tid, tid], kind: Kind::Fault, want });
    }

    /// A context switch. Keeps track of who is waiting on what whenever CSwitch or Ready stacks
    /// are on, and asks for the stack of a thread coming back from a wait worth explaining.
    pub fn on_switch(&mut self, ts: i64, cpu: u16, header_tid: u32, sw: &crate::state::SwitchRec) {
        let (cs, rd) = (self.set.has(Kind::CSwitch), self.set.has(Kind::Ready));
        if !cs && !rd {
            return;
        }
        let back = self.off_at.remove(&sw.new_tid);
        if cs {
            let want = match back {
                Some((since, reason)) if sw.new_tid != 0 && ts - since >= ms_to_ticks(KEEP_WAIT_MS) && worth(reason) => {
                    Want::SwitchIn { tid: sw.new_tid, since }
                }
                _ => Want::Ignore,
            };
            self.pend(cpu, Pending { ts, tids: [header_tid, sw.new_tid], kind: Kind::CSwitch, want });
        }
        if sw.old_state == crate::switches::STATE_WAITING && sw.old_tid != 0 {
            self.off_at.insert(sw.old_tid, (ts, sw.old_wait_reason));
        }
    }

    /// A thread was readied; the stack that follows is the readying thread's.
    pub fn on_ready(&mut self, ts: i64, cpu: u16, header_tid: u32, tid: u32) {
        if !self.set.has(Kind::Ready) {
            return;
        }
        let want = match self.off_at.get(&tid) {
            Some(&(since, reason)) if ts - since >= ms_to_ticks(KEEP_WAIT_MS) && worth(reason) => Want::Readied { tid, since },
            _ => Want::Ignore,
        };
        self.pend(cpu, Pending { ts, tids: [header_tid, tid], kind: Kind::Ready, want });
    }

    /// A StackWalk event, already parsed. `bytes` is its payload size.
    pub fn on_stack(&mut self, cpu: u16, raw: RawStack, bytes: usize) {
        if raw.ragged {
            self.counts.ragged += 1;
        }
        let Some((p, elsewhere)) = self.take(cpu, raw.ts, raw.tid) else {
            self.counts.unmatched.add(&raw, bytes);
            return;
        };
        if elsewhere {
            self.counts.other_cpu += 1;
        }
        let c = &mut self.counts.kinds[p.kind as usize];
        c.add(&raw, bytes);
        if raw.tid == p.tids[0] {
            c.by_header_tid += 1;
        } else {
            c.by_payload_tid += 1;
        }
        if self.samples.iter().filter(|s| s.0 == p.kind).count() < 2 && !raw.kernel.is_empty() {
            self.samples.push((p.kind, raw.kernel.clone(), raw.user_frames));
        }
        let kept = match p.want {
            Want::Ignore => false,
            Want::DiskInit { irp } => match self.io_init.get_mut(&irp) {
                Some(e) if e.0 == p.ts => {
                    e.1 = Some(Stack::from_raw(&raw));
                    true
                }
                _ => false,
            },
            Want::Fault { start, tid } => {
                let r = FaultStack { start, end: p.ts, tid, stack: Stack::from_raw(&raw) };
                push_capped(&mut self.faults, r, FAULT_CAP, |r| r.end, &mut self.lost_until[1]);
                true
            }
            Want::SwitchIn { tid, since } => {
                let r = SwitchInStack { ts: p.ts, tid, since, stack: Stack::from_raw(&raw) };
                push_capped(&mut self.switch_ins, r, self.switch_cap, |r| r.ts, &mut self.lost_until[2]);
                true
            }
            Want::Readied { tid, since } => {
                let r = ReadyStack { ts: p.ts, tid, since, stack: Stack::from_raw(&raw) };
                push_capped(&mut self.readies, r, self.ready_cap, |r| r.ts, &mut self.lost_until[3]);
                true
            }
        };
        if kept {
            self.counts.kinds[p.kind as usize].kept += 1;
        }
    }

    /// Drops what is older than the rings' windows: `keep` (the long rings' 20 s) for disk and
    /// fault stacks, `switch_keep` for the switch-in and wake-up stacks.
    pub fn prune(&mut self, latest: i64, keep: i64, switch_keep: i64) {
        let (cut, switch_cut) = (latest - keep, latest - switch_keep);
        while self.slow_io.front().is_some_and(|r| r.0 < cut) {
            self.slow_io.pop_front();
        }
        while self.faults.front().is_some_and(|r| r.end < cut) {
            self.faults.pop_front();
        }
        while self.switch_ins.front().is_some_and(|r| r.ts < switch_cut) {
            self.switch_ins.pop_front();
        }
        while self.readies.front().is_some_and(|r| r.ts < switch_cut) {
            self.readies.pop_front();
        }
        self.io_init.retain(|_, v| v.0 >= cut);
        self.off_at.retain(|_, v| v.0 >= switch_cut);
    }

    /// The issuing stack of the slow request that completed at `end` with this Irp. `None` when
    /// the ring no longer has it (pruned, or thrown away by the cap).
    pub fn slow_io_stack(&self, end: i64, irp: u64) -> Option<IoStack> {
        self.slow_io.iter().rev().find(|r| r.0 == end && r.1 == irp).map(|r| r.2.clone())
    }

    /// Switch-in and fault stacks of `tids` from `[from, to]`, for working out where those
    /// threads waited. Copies only what matches: this runs under the ETW callback's lock.
    pub fn wait_stacks(&self, tids: &[u32], from: i64, to: i64) -> (Vec<SwitchInStack>, Vec<FaultStack>) {
        let sw = self.switch_ins.iter().filter(|s| s.ts >= from && s.ts <= to && tids.contains(&s.tid)).cloned().collect();
        let f = self.faults.iter().filter(|f| f.end >= from && f.end <= to && tids.contains(&f.tid)).cloned().collect();
        (sw, f)
    }

    /// Do the switch-in stacks honestly cover a wait that began at `since`? Not if the cap threw
    /// away a record from then on.
    pub fn switch_ins_cover(&self, since: i64) -> bool {
        self.set.has(Kind::CSwitch) && self.lost_until[2].is_none_or(|l| l < since)
    }

    pub fn report(&self) -> StackReport {
        StackReport { set: self.set, enable_error: self.enable_error, counts: self.counts.clone(), samples: self.samples.clone() }
    }
}

/// What the summary needs about stacks, copied out once.
#[derive(Clone, Default, Debug)]
pub struct StackReport {
    pub set: StackSet,
    pub enable_error: Option<u32>,
    pub counts: Counts,
    pub samples: Vec<(Kind, Vec<u64>, u32)>,
}

// ---------------------------------------------------------------------------------------------
// Which stack says where a thread waited
// ---------------------------------------------------------------------------------------------

/// Where a stuck thread's wait stack came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WaitSource {
    /// The stack it was switched back in with after THIS wait (CSwitch stacks).
    SwitchIn,
    /// A hard page fault of that thread spanning the wait.
    Fault,
}

/// The stack that says where thread `tid` waited, for a wait that began when it was switched out
/// at `off_ts` and ended when it was readied at `woke_at`.
///
/// A switch-in stack must name exactly that wait (`since == off_ts`), so the thread's next wait,
/// however close, is never taken for this one. A fault stack must span it: started no later than
/// the thread went to sleep, completed no earlier than a millisecond before it was woken, and not
/// long after (the closest completion wins).
pub fn wait_stack<'a>(
    tid: u32,
    off_ts: i64,
    woke_at: i64,
    switch_ins: &'a [SwitchInStack],
    faults: &'a [FaultStack],
) -> Option<(&'a Stack, WaitSource)> {
    if let Some(s) = switch_ins.iter().find(|s| s.tid == tid && s.since == off_ts && s.ts >= woke_at) {
        return Some((&s.stack, WaitSource::SwitchIn));
    }
    let slack = ms_to_ticks(1.0);
    let late = ms_to_ticks(FAULT_LATE_MS);
    faults
        .iter()
        .filter(|f| f.tid == tid && f.start <= off_ts + slack && f.end >= woke_at - slack && f.end <= woke_at + late)
        .min_by_key(|f| (f.end - woke_at).abs())
        .map(|f| (&f.stack, WaitSource::Fault))
}

/// How long after the wake-up a hard fault's completion event may still be tied to that wait. The
/// event's exact moment relative to the wake-up is not documented; rule of thumb.
pub const FAULT_LATE_MS: f64 = 50.0;

// ---------------------------------------------------------------------------------------------
// Addresses to module names, and words
// ---------------------------------------------------------------------------------------------

/// The Windows kernel image and the HAL: on every stack, and naming them says nothing.
pub fn is_kernel_core(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l.starts_with("ntoskrnl") || l.starts_with("ntkrnl") || l.starts_with("ntkrpamp") || l == "hal.dll"
}

/// The drivers on a stack in CALL order (outermost caller first, innermost last), with the kernel
/// image left out and repeats collapsed: ntoskrnl -> Ntfs -> ntoskrnl -> Ntfs -> FLTMGR is
/// "Ntfs.sys -> FLTMGR.SYS". Addresses `resolve` cannot place are skipped. Assumes Stack1 is the
/// innermost frame (UNVERIFIED, see the module comment).
pub fn module_path(frames: &[u64], resolve: &mut dyn FnMut(u64) -> Option<String>) -> Vec<String> {
    let mut v: Vec<String> = frames.iter().rev().filter_map(|a| resolve(*a)).filter(|n| !is_kernel_core(n)).collect();
    v.dedup_by(|a, b| a.eq_ignore_ascii_case(b));
    v
}

/// "explorer.exe -> FLTMGR.SYS -> WdFilter.sys", or "... -> the Windows kernel only" when no
/// driver but the kernel itself was on the stack.
pub fn path_text(program: Option<&str>, modules: &[String]) -> String {
    let mut parts: Vec<&str> = program.into_iter().collect();
    if modules.is_empty() {
        parts.push("the Windows kernel only");
    }
    parts.extend(modules.iter().map(String::as_str));
    parts.join(" -> ")
}

/// Where a thread was blocked: the innermost driver on its wait stack, or the kernel itself.
pub fn waited_in(modules: &[String]) -> String {
    modules.last().cloned().unwrap_or_else(|| "the Windows kernel".to_string())
}

/// Windows' own drivers below the file system that every request to a local disk goes through.
/// DISPLAY ONLY: they are left out of the shortened "via" list in the event log, because naming
/// them on every line says nothing. Nothing is concluded from this list.
const STORAGE_STACK: &[&str] = &[
    "volsnap.sys",
    "volmgr.sys",
    "volmgrx.sys",
    "volume.sys",
    "partmgr.sys",
    "disk.sys",
    "classpnp.sys",
    "storport.sys",
    "stornvme.sys",
    "storahci.sys",
    "iorate.sys",
    "fvevol.sys",
    "ehstorclass.sys",
    "spaceport.sys",
    "rdyboost.sys",
    "uaspstor.sys",
    "usbstor.sys",
    "ataport.sys",
];

/// The "via" variants for the event log, most detailed first: every driver, then without Windows'
/// storage stack below the file system. Empty when there is nothing to say.
pub fn via_variants(modules: &[String]) -> Vec<String> {
    if modules.is_empty() {
        return Vec::new();
    }
    let full = format!("via {}", modules.join(" -> "));
    let upper: Vec<&str> =
        modules.iter().map(String::as_str).filter(|m| !STORAGE_STACK.contains(&m.to_ascii_lowercase().as_str())).collect();
    let mut out = vec![full];
    if !upper.is_empty() && upper.len() < modules.len() {
        out.push(format!("via {}", upper.join(" -> ")));
    }
    out
}

// ---------------------------------------------------------------------------------------------
// File-system filters
// ---------------------------------------------------------------------------------------------

/// Plain words for a minifilter load order group. The groups, their altitude ranges and what each
/// is for are Microsoft's: https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/load-order-groups-and-altitudes-for-minifilter-drivers
/// (e.g. "FSFilter Anti-Virus ... Includes filter drivers that detect and disinfect viruses during
/// file I/O"). `None` for the groups whose description says nothing a reader could use.
pub fn group_role(group: &str) -> Option<&'static str> {
    Some(match group.to_ascii_lowercase().trim() {
        "fsfilter activity monitor" => "watches file activity",
        "fsfilter undelete" => "recovers deleted files",
        "fsfilter anti-virus" => "antivirus scanning",
        "fsfilter replication" => "copies files to other servers",
        "fsfilter continuous backup" => "continuous backup",
        "fsfilter content screener" => "blocks certain files",
        "fsfilter quota management" | "fsfilter physical quota management" => "disk quotas",
        "fsfilter system recovery" => "system recovery",
        "fsfilter cluster file system" => "cluster file system",
        "fsfilter hsm" => "hierarchical storage management",
        "fsfilter imaging" => "virtual file namespace",
        "fsfilter compression" => "compression",
        "fsfilter encryption" => "encryption",
        "fsfilter virtualization" => "file virtualization",
        "fsfilter open file" => "snapshots of open files",
        "fsfilter security enhancer" => "access control",
        "fsfilter copy protection" => "copy protection",
        _ => return None,
    })
}

/// Filters whose product the report names in plain words, each with its source. Everything else is
/// named from the file's own version resource (`modules::describe`), which is read live.
pub fn known_filter(file: &str) -> Option<&'static str> {
    match file.to_ascii_lowercase().as_str() {
        // Service "WdFilter", display name "Microsoft Defender Antivirus Mini-Filter Driver":
        // https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-service-startup-problems
        // and "WdFilter.sys 328010 Microsoft", FSFilter Anti-Virus:
        // https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/allocated-altitudes
        "wdfilter.sys" => Some("Microsoft Defender Antivirus"),
        _ => None,
    }
}

/// Is this the Filter Manager itself? It hosts every minifilter and is on the path of every file
/// operation on a volume that has one, so it is never counted as a filter: "FltMgr is installed
/// with Windows, but it becomes active only when a minifilter driver is loaded ... A minifilter
/// driver attaches to the file system stack indirectly, by registering with FltMgr".
/// https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/filter-manager-concepts
pub fn is_filter_manager(file: &str) -> bool {
    file.eq_ignore_ascii_case("fltmgr.sys")
}

/// Driver file (lower case) -> minifilter load order group, for every service installed in an
/// "FSFilter ..." group. Read from the registry, no elevation needed: the INF's `LoadOrderGroup`
/// becomes the service's `Group` value (verified live on Windows 11 26200: WdFilter is in
/// "FSFilter Anti-Virus", CldFlt in "FSFilter HSM"; the value name itself is not stated on the
/// AddService page, https://learn.microsoft.com/en-us/windows-hardware/drivers/install/inf-addservice-directive).
/// The binary is `ImagePath`'s file name, or the service name + ".sys" when there is none.
pub fn filesystem_filters() -> HashMap<String, String> {
    const SERVICES: &str = r"SYSTEM\CurrentControlSet\Services";
    let mut out = HashMap::new();
    for svc in crate::reg::subkeys(SERVICES) {
        let key = format!(r"{SERVICES}\{svc}");
        let Some(group) = crate::reg::hklm_str(&key, "Group") else { continue };
        if !group.to_ascii_lowercase().starts_with("fsfilter") {
            continue;
        }
        let file = crate::reg::hklm_path(&key, "ImagePath")
            .and_then(|p| p.trim().trim_matches('"').rsplit(['\\', '/']).next().map(str::to_string))
            .filter(|f| f.to_ascii_lowercase().ends_with(".sys"))
            .unwrap_or_else(|| format!("{svc}.sys"));
        out.insert(file.to_ascii_lowercase(), group);
    }
    out
}

/// Is `file` a file-system filter by the registry map (the Filter Manager excluded)?
pub fn is_filter(filters: &HashMap<String, String>, file: &str) -> bool {
    !is_filter_manager(file) && filters.contains_key(&file.to_ascii_lowercase())
}

/// "WdFilter.sys (Microsoft Defender Antivirus, antivirus scanning)". `describe` is the file's own
/// version-resource description, used when the file is not in `known_filter`.
pub fn filter_label(file: &str, group: Option<&str>, describe: Option<&str>) -> String {
    let what = known_filter(file).map(str::to_string).or_else(|| describe.filter(|d| !d.is_empty()).map(str::to_string));
    let role = group.and_then(group_role);
    match (what, role) {
        (Some(w), Some(r)) => format!("{file} ({w}, {r})"),
        (Some(w), None) => format!("{file} ({w})"),
        (None, Some(r)) => format!("{file} ({r} filter)"),
        (None, None) => file.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::SwitchRec;

    const K: u64 = 0xFFFF_F800_0000_0000;

    fn payload64(ts: u64, pid: u32, tid: u32, frames: &[u64]) -> Vec<u8> {
        let mut d = ts.to_le_bytes().to_vec();
        d.extend(pid.to_le_bytes());
        d.extend(tid.to_le_bytes());
        for f in frames {
            d.extend(f.to_le_bytes());
        }
        d
    }

    #[test]
    fn a_64_bit_stack_splits_kernel_from_user_frames() {
        let d = payload64(123_456, 4242, 77, &[K + 0x10, K + 0x20, 0x7FF6_0000_1000, 0x7FF6_0000_2000]);
        let r = parse(&d, true).unwrap();
        assert_eq!((r.ts, r.pid, r.tid, r.frames, r.user_frames, r.ragged), (123_456, 4242, 77, 4, 2, false));
        assert_eq!(r.kernel, vec![K + 0x10, K + 0x20]);
    }

    #[test]
    fn a_32_bit_stack_reads_four_byte_addresses() {
        let mut d = 9u64.to_le_bytes().to_vec();
        d.extend(1u32.to_le_bytes());
        d.extend(2u32.to_le_bytes());
        for a in [0x8123_4567u32, 0x0040_1000, 0xFFFF_0000] {
            d.extend(a.to_le_bytes());
        }
        let r = parse(&d, false).unwrap();
        assert_eq!(r.kernel, vec![0x8123_4567, 0xFFFF_0000]);
        assert_eq!((r.frames, r.user_frames), (3, 1));
        // The same bytes read as 64-bit are one whole address and a ragged tail, not garbage frames.
        let r64 = parse(&d, true).unwrap();
        assert_eq!((r64.frames, r64.ragged), (1, true));
    }

    #[test]
    fn truncated_stacks_are_refused_or_counted_never_a_panic() {
        let d = payload64(1, 2, 3, &[K]);
        for cut in 0..16 {
            assert!(parse(&d[..cut], true).is_none(), "{cut} bytes has no room for the header");
        }
        let empty = parse(&d[..16], true).unwrap();
        assert_eq!((empty.frames, empty.kernel.len()), (0, 0), "a stack that could not be walked still counts");
        let ragged = parse(&d[..21], true).unwrap();
        assert!(ragged.ragged && ragged.frames == 0);
        // More frames than the event can hold, and more kernel frames than are kept.
        let many: Vec<u64> = (0..300).map(|i| K + i).collect();
        let r = parse(&payload64(1, 2, 3, &many), true).unwrap();
        assert_eq!((r.frames as usize, r.kernel.len()), (MAX_FRAMES, MAX_KERNEL_FRAMES));
    }

    #[test]
    fn the_set_parses_the_hidden_flag_and_lists_the_right_events() {
        assert_eq!(StackSet::parse("cswitch,ready").unwrap(), StackSet::of(&[Kind::CSwitch, Kind::Ready]));
        assert_eq!(StackSet::parse(" DiskInit , fault ").unwrap(), StackSet::DEFAULT);
        assert_eq!(StackSet::parse("none").unwrap(), StackSet::NONE);
        assert_eq!(StackSet::parse("all").unwrap().names(), "cswitch,ready,diskinit,fault");
        assert!(StackSet::parse("cswitch,bogus").is_err());
        let ids = StackSet::DEFAULT.classic_ids();
        let types: Vec<u8> = ids.iter().map(|i| i.Type).collect();
        assert_eq!(types, vec![12, 13, 15, 32]);
        assert_eq!(ids[0].EventGuid.data1, 0x3d6f_a8d4, "DiskIo");
        assert_eq!(ids[3].EventGuid.data1, 0x3d6f_a8d3, "PageFault");
        let all = StackSet::of(&Kind::ALL).classic_ids();
        assert_eq!((all[0].EventGuid.data1, all[0].Type, all[1].Type), (0x3d6f_a8d1, 36, 50));
        assert!(all.len() <= 256, "TraceStackTracingInfo takes at most 256 entries");
        assert!(StackSet::DEFAULT.without(Kind::DiskInit).without(Kind::Fault).is_empty());
    }

    fn raw(ts: i64, tid: u32, frames: &[u64]) -> RawStack {
        parse(&payload64(ts as u64, 100, tid, frames), true).unwrap()
    }

    fn state(set: StackSet) -> StackState {
        StackState::new(set, 8)
    }

    /// The stack that follows the start of a slow request is its issuing stack; a fast request's
    /// is dropped at completion, and a request whose start was never seen says so.
    #[test]
    fn a_slow_requests_issuing_stack_is_kept_and_a_fast_ones_is_not() {
        let mut s = state(StackSet::DEFAULT);
        s.on_disk_init(1_000, 2, 55, 0xAAA0, 55);
        s.on_stack(2, raw(1_000, 55, &[K + 1, K + 2]), 32);
        s.on_disk_init(1_100, 3, 56, 0xBBB0, 56);
        s.on_stack(3, raw(1_100, 56, &[K + 3]), 24);
        s.on_disk_done(9_000, 0xAAA0, true);
        s.on_disk_done(9_100, 0xBBB0, false);
        s.on_disk_done(9_200, 0xCCC0, true);
        assert!(matches!(s.slow_io_stack(9_000, 0xAAA0), Some(IoStack::Found(st)) if st.frames[..] == [K + 1, K + 2]));
        assert_eq!(s.slow_io_stack(9_100, 0xBBB0), None, "fast: nothing kept");
        assert_eq!(s.slow_io_stack(9_200, 0xCCC0), Some(IoStack::NoInit));
        assert_eq!(s.slow_io_stack(9_000, 0xBBB0), None, "the Irp has to match too");
        let c = &s.counts;
        assert_eq!((c.io_with_init, c.io_without_init, c.slow_found, c.slow_no_init), (2, 1, 1, 1));
        assert_eq!((c.kinds[Kind::DiskInit as usize].stacks, c.kinds[Kind::DiskInit as usize].kept), (2, 2));
        // A start whose stack never came.
        s.on_disk_init(10_000, 1, 57, 0xDDD0, 57);
        s.on_disk_done(12_000, 0xDDD0, true);
        assert_eq!(s.slow_io_stack(12_000, 0xDDD0), Some(IoStack::NoStack));
    }

    /// A stack is tied to its event by time stamp AND thread: the neighbor logged at the same
    /// instant by another thread, or a moment later by the same one, does not get it.
    #[test]
    fn a_stack_goes_to_its_own_event_and_not_to_a_neighbor() {
        let mut s = state(StackSet::DEFAULT);
        s.on_disk_init(5_000, 0, 10, 0x100, 10);
        s.on_disk_init(5_000, 1, 11, 0x200, 11); // same instant, other CPU, other thread
        s.on_disk_init(5_001, 0, 10, 0x300, 10); // same thread, a tick later
        s.on_stack(0, raw(5_000, 11, &[K + 7]), 24); // arrives on CPU 0 but is thread 11's
        s.on_disk_done(6_000, 0x100, true);
        s.on_disk_done(6_001, 0x200, true);
        s.on_disk_done(6_002, 0x300, true);
        assert_eq!(s.slow_io_stack(6_000, 0x100), Some(IoStack::NoStack));
        assert!(matches!(s.slow_io_stack(6_001, 0x200), Some(IoStack::Found(_))));
        assert_eq!(s.slow_io_stack(6_002, 0x300), Some(IoStack::NoStack));
        assert_eq!(s.counts.other_cpu, 1, "found by searching the other processors, and counted");
        // A stack for nothing this tool asked for is counted as unmatched.
        s.on_stack(0, raw(77, 99, &[K]), 24);
        assert_eq!(s.counts.unmatched.stacks, 1);
        assert_eq!(s.counts.total(), 2);
    }

    #[test]
    fn whose_stack_it_was_is_counted_by_thread() {
        let mut s = state(StackSet::DEFAULT);
        let ms = ms_to_ticks;
        // A 30 ms fault logged in thread 5's context naming thread 9 as the faulting thread.
        s.on_fault(ms(100.0), 0, 5, ms(70.0), 9);
        s.on_stack(0, raw(ms(100.0), 9, &[K]), 24);
        s.on_fault(ms(200.0), 0, 5, ms(170.0), 9);
        s.on_stack(0, raw(ms(200.0), 5, &[K]), 24);
        let f = s.counts.kinds[Kind::Fault as usize];
        assert_eq!((f.by_header_tid, f.by_payload_tid, f.kept), (1, 1, 2));
        assert_eq!(s.faults.len(), 2);
        // A 1 ms fault is priced but not kept.
        s.on_fault(ms(300.0), 0, 9, ms(299.0), 9);
        s.on_stack(0, raw(ms(300.0), 9, &[K]), 24);
        assert_eq!((s.faults.len(), s.counts.kinds[Kind::Fault as usize].stacks), (2, 3));
    }

    fn sw(ts: i64, new_tid: u32, old_tid: u32, reason: i8) -> SwitchRec {
        SwitchRec { ts, new_tid, old_tid, cpu: 0, new_prio: 8, old_prio: 8, old_wait_reason: reason, old_wait_mode: 0, old_state: 5 }
    }

    /// Only the switch-in that ends a long disk or lock wait is kept, and it remembers which wait.
    #[test]
    fn switch_in_stacks_are_kept_only_after_a_wait_worth_explaining() {
        let ms = ms_to_ticks;
        let mut s = state(StackSet::of(&[Kind::CSwitch, Kind::Ready]));
        s.on_switch(ms(0.0), 0, 0, &sw(ms(0.0), 0, 40, 9)); // 40 goes into WrPageIn
        s.on_switch(ms(0.0), 0, 0, &sw(ms(0.0), 0, 41, 13)); // 41 waits for a message (UserRequest)
        s.on_switch(ms(0.0), 0, 0, &sw(ms(0.0), 0, 42, 27)); // 42 on a lock, but only briefly
        s.on_ready(ms(30.0), 1, 7, 40);
        s.on_stack(1, raw(ms(30.0), 7, &[K + 9]), 24);
        s.on_switch(ms(31.0), 0, 0, &sw(ms(31.0), 40, 0, 0));
        s.on_stack(0, raw(ms(31.0), 40, &[K + 1]), 24);
        s.on_switch(ms(32.0), 0, 0, &sw(ms(32.0), 41, 0, 0));
        s.on_stack(0, raw(ms(32.0), 41, &[K + 2]), 24);
        s.on_switch(ms(2.0), 2, 0, &sw(ms(2.0), 42, 0, 0));
        s.on_stack(2, raw(ms(2.0), 42, &[K + 3]), 24);
        assert_eq!(s.switch_ins.len(), 1);
        assert_eq!((s.switch_ins[0].tid, s.switch_ins[0].since), (40, 0));
        assert_eq!((s.readies.len(), s.readies[0].tid), (1, 40));
        assert_eq!(s.counts.kinds[Kind::CSwitch as usize].stacks, 3, "every stack is priced");
        assert_eq!(s.counts.kinds[Kind::CSwitch as usize].by_payload_tid, 3, "matched by the new thread");
    }

    #[test]
    fn the_wait_stack_is_the_one_for_that_wait_and_not_the_threads_next_one() {
        let ms = ms_to_ticks;
        let st = |a: u64| Stack { pid: 1, frames: vec![K + a].into_boxed_slice(), user: true };
        let ins = vec![
            SwitchInStack { ts: ms(1801.0), tid: 7, since: ms(1100.0), stack: st(1) },
            SwitchInStack { ts: ms(1850.0), tid: 7, since: ms(1820.0), stack: st(2) }, // its next wait
            SwitchInStack { ts: ms(1801.0), tid: 8, since: ms(1100.0), stack: st(3) }, // another thread
        ];
        let (s, src) = wait_stack(7, ms(1100.0), ms(1800.5), &ins, &[]).unwrap();
        assert_eq!((s.frames[0], src), (K + 1, WaitSource::SwitchIn));
        assert!(wait_stack(7, ms(1100.0), ms(1805.0), &ins, &[]).is_none(), "a switch-in before the wake-up is not it");
        assert!(wait_stack(9, ms(1100.0), ms(1800.5), &ins, &[]).is_none());
        // Faults: the one spanning the wait, not one that ended before it or much later.
        let faults = vec![
            FaultStack { start: ms(1000.0), end: ms(1050.0), tid: 7, stack: st(4) }, // over before the wait
            FaultStack { start: ms(1099.0), end: ms(1800.6), tid: 7, stack: st(5) },
            FaultStack { start: ms(1099.0), end: ms(1800.6), tid: 6, stack: st(6) },
            FaultStack { start: ms(1099.0), end: ms(2500.0), tid: 7, stack: st(7) }, // much later
        ];
        let (s, src) = wait_stack(7, ms(1100.0), ms(1800.5), &[], &faults).unwrap();
        assert_eq!((s.frames[0], src), (K + 5, WaitSource::Fault));
        // A fault that began after the thread went to sleep is some other fault.
        let later = [FaultStack { start: ms(1200.0), end: ms(1800.6), tid: 7, stack: st(8) }];
        assert!(wait_stack(7, ms(1100.0), ms(1800.5), &[], &later).is_none());
    }

    #[test]
    fn frames_become_drivers_in_call_order_with_repeats_and_the_kernel_collapsed() {
        let map = crate::modules::ModuleMap::for_test(&[
            ("ntoskrnl.exe", K, 0x100_0000),
            ("Ntfs.sys", K + 0x200_0000, 0x10_0000),
            ("FLTMGR.SYS", K + 0x300_0000, 0x10_0000),
            ("WdFilter.sys", K + 0x400_0000, 0x10_0000),
        ]);
        // Stack1 (innermost) first: kernel wait code, WdFilter, FltMgr, kernel, Ntfs, Ntfs, kernel,
        // FltMgr, kernel syscall entry, and one address nobody owns.
        let frames = [
            K + 0x10,
            K + 0x400_0010,
            K + 0x300_0010,
            K + 0x20,
            K + 0x200_0010,
            K + 0x200_0020,
            K + 0x30,
            K + 0x300_0020,
            K + 0x40,
            K + 0x900_0000,
        ];
        let mut resolve = |a: u64| map.module_at(a).map(str::to_string);
        let path = module_path(&frames, &mut resolve);
        assert_eq!(path, vec!["FLTMGR.SYS", "Ntfs.sys", "FLTMGR.SYS", "WdFilter.sys"]);
        assert_eq!(path_text(Some("explorer.exe"), &path), "explorer.exe -> FLTMGR.SYS -> Ntfs.sys -> FLTMGR.SYS -> WdFilter.sys");
        assert_eq!(waited_in(&path), "WdFilter.sys");
        let kernel_only = module_path(&[K + 1, K + 2], &mut resolve);
        assert!(kernel_only.is_empty());
        assert_eq!(path_text(Some("game.exe"), &kernel_only), "game.exe -> the Windows kernel only");
        assert_eq!(waited_in(&kernel_only), "the Windows kernel");
    }

    #[test]
    fn via_drops_the_storage_stack_only_as_a_shorter_variant() {
        let m: Vec<String> =
            ["FLTMGR.SYS", "Ntfs.sys", "volsnap.sys", "disk.sys", "CLASSPNP.SYS", "storport.sys"].iter().map(|s| s.to_string()).collect();
        let v = via_variants(&m);
        assert_eq!(v[0], "via FLTMGR.SYS -> Ntfs.sys -> volsnap.sys -> disk.sys -> CLASSPNP.SYS -> storport.sys");
        assert_eq!(v[1], "via FLTMGR.SYS -> Ntfs.sys");
        assert!(via_variants(&[]).is_empty());
        assert_eq!(via_variants(&["WdFilter.sys".to_string()]).len(), 1);
    }

    #[test]
    fn filters_are_named_from_sourced_facts_only() {
        assert_eq!(
            filter_label("WdFilter.sys", Some("FSFilter Anti-Virus"), None),
            "WdFilter.sys (Microsoft Defender Antivirus, antivirus scanning)"
        );
        assert_eq!(
            filter_label("cldflt.sys", Some("FSFilter HSM"), Some("Cloud Files Mini Filter Driver")),
            "cldflt.sys (Cloud Files Mini Filter Driver, hierarchical storage management)"
        );
        assert_eq!(filter_label("x.sys", Some("FSFilter Encryption"), None), "x.sys (encryption filter)");
        assert_eq!(filter_label("y.sys", Some("FSFilter Top"), None), "y.sys");
        let mut map = HashMap::new();
        map.insert("wdfilter.sys".to_string(), "FSFilter Anti-Virus".to_string());
        map.insert("fltmgr.sys".to_string(), "FSFilter Infrastructure".to_string());
        assert!(is_filter(&map, "WdFilter.sys"));
        assert!(!is_filter(&map, "FLTMGR.SYS"), "the Filter Manager hosts filters; it is not one");
        assert!(!is_filter(&map, "Ntfs.sys"));
    }

    /// The caps bound memory and admit what they threw away.
    #[test]
    fn the_rings_are_capped_and_say_so() {
        assert_eq!(stack_caps(4), (SWITCH_IN_FLOOR, SWITCH_IN_FLOOR));
        assert_eq!(stack_caps(64), (64_000, 64_000));
        assert_eq!(stack_caps(1024), (SWITCH_IN_CEILING, SWITCH_IN_CEILING));
        let mut s = state(StackSet::DEFAULT);
        for i in 0..(SLOW_IO_CAP as i64 + 3) {
            s.on_disk_done(i, 0x10 + i as u64, true);
        }
        assert_eq!(s.slow_io.len(), SLOW_IO_CAP);
        assert_eq!(s.lost_until[0], Some(2), "the three oldest went");
        s.prune(SLOW_IO_CAP as i64 + 3, 10, 5);
        assert!(s.slow_io.len() <= 11);
        assert!(!s.switch_ins_cover(0), "no CSwitch stacks, nothing covered");
    }

    /// Prints this PC's registered file-system filters. No count asserted: a CI runner has few.
    #[test]
    fn listing_this_pcs_filesystem_filters_does_not_panic() {
        let f = filesystem_filters();
        let mut v: Vec<_> = f.iter().collect();
        v.sort();
        for (file, group) in v {
            println!("  {file:<24} {group:<28} {:?}", group_role(group));
        }
    }
}
