//! Where a slow disk request's time went: inside the drive, or waiting in Windows before it got
//! there (issue #20, step 2).
//!
//! The kernel's DiskIo event says how long a request took from the moment the disk driver got it
//! (`HighResResponseTime`), which includes any time spent queued inside Windows. The storage port
//! driver (storport.sys, which runs NVMe, SATA/AHCI and UAS USB drives) logs, for every request it
//! passes down, how long the layers below it took: the miniport driver, the controller and the
//! drive. Subtracting one from the other splits "the drive took 1.9 s" from "the request sat in
//! Windows' queue". The same session also sees the port driver retrying requests and resetting
//! drives, live, with the time it happened.
//!
//! Provider: Microsoft-Windows-StorPort. Every id, version, field and keyword below was read from
//! this machine's own copy of the provider manifest:
//!     (Get-WinEvent -ListProvider Microsoft-Windows-StorPort).Events
//! and the rates were MEASURED on Windows 11 25H2 (32 CPUs, 4 NVMe + 1 USB hard drive, 2026-09-23).
//!
//! It is its own real-time session ("WTFIsStallingStorageSession"), the shared `etw::manifest`
//! machinery, so it has the kernel session's lifetime rules. Everything here is optional: a session
//! that cannot start never fails the run, and the report says in one line that it did not run.
//!
//! ON in light mode too, unlike thread switches and the GPU trace, and that is a measured choice:
//! it is one event per disk request (about 1,750 a second under heavy disk load, 0 lost) against
//! about 370,000 a second for the kernel trace with thread switches, and the kernel trace already
//! records one DiskIo event per request, so this at most doubles the disk share of it.

mod events;
pub mod split;

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use windows_sys::core::GUID;
use windows_sys::Win32::System::Diagnostics::Etw::TRACE_LEVEL_INFORMATION;

use crate::etw::manifest;
pub use crate::etw::manifest::Session;
use crate::util::{ms_to_ticks, qpc, qpc_freq};

const SESSION_NAME: &str = "WTFIsStallingStorageSession";

/// Microsoft-Windows-StorPort, {C4636A1E-7986-4646-BF10-7BC3B4A76E8E}, as the live system reports
/// it (`Get-WinEvent -ListProvider Microsoft-Windows-StorPort` / `logman query providers`).
const STORPORT_GUID: GUID = GUID::from_u128(0xc4636a1e_7986_4646_bf10_7bc3b4a76e8e);

// ---- keywords, from the provider manifest's keyword list ------------------------------------
/// Unnamed in the manifest. Gates event 1 (Logical Unit reset) and 2 (Target reset); also 501,
/// 550 and 589, which the id filter drops.
const KW_RESET: u64 = 0x1;
/// Unnamed in the manifest. Gates event 4 (Reset detected notification); also 5, 6, 7, 12, 25 and
/// several 5xx events, which the id filter drops.
const KW_NOTIFY: u64 = 0x2;
/// "IO Performance measurement": event 201, one per request. MEASURED alone at level 4: 78,960
/// events in 45 s under heavy load (~1,750 a second), 0 lost, every one of them id 201.
const KW_IO_PERFORMANCE: u64 = 0x10_0000;
/// Read, Write, Paging Read, Paging Write, Low memory Read, Low memory write: the keywords event
/// 209 (retry) is logged under. It is NOT under the "Retry handling" keyword (0x40000000000).
///
/// The price, and why it is paid: these keywords also enable the per-request command trace
/// (events 202, 203 and 208). MEASURED with them on: ~3,500 events a second in total. The id
/// filter keeps those out of this session, but Microsoft is explicit that filtering by event id
/// "is only effective in reducing trace data volume and is not as effective for reducing trace
/// CPU overhead", so storport.sys still builds them.
/// https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-enabletraceex2
const KW_READ_WRITE: u64 = 0x20_0000 | 0x40_0000 | 0x80_0000 | 0x100_0000 | 0x200_0000 | 0x400_0000;
const KEYWORDS: u64 = KW_RESET | KW_NOTIFY | KW_IO_PERFORMANCE | KW_READ_WRITE;

// ---- the events this session asks for ------------------------------------------------------
/// "Logical Unit reset" v1, level Error: PortNumber UInt32, PathID UInt8, TargetID UInt8, LUN UInt8.
pub(crate) const EV_LU_RESET: u16 = 1;
/// "Target reset" v1, level Error: PortNumber UInt32, PathID UInt8, TargetID UInt8.
pub(crate) const EV_TARGET_RESET: u16 = 2;
/// "Reset detected notification" v1: MiniportExtension Pointer, PortNumber UInt32, PauseTime
/// UInt32. PauseTime's unit is not documented anywhere found, so it is not read.
pub(crate) const EV_RESET_DETECTED: u16 = 4;
/// "Request servicing time taken by lower driver stack(s)" v2: RequestDuration_100ns UInt64, Irp
/// Pointer, Command UInt8, SrbStatus UInt8, OriginalIrp Pointer, Port UInt8, Bus UInt8, Target
/// UInt8, LUN UInt8, ScsiStatus UInt8, ByteLengthOfTransfer UInt32, BuildIoDuration_100ns UInt64,
/// StartIoDuration_100ns UInt64. Event 200 ("...taken by target device") has the same template
/// but never fired in 45 s of measuring, so it is not asked for.
pub(crate) const EV_REQUEST: u16 = 201;
/// "Retrying an IO (read/write) request" v1: Irp Pointer, CurrentRetryCount UInt32.
pub(crate) const EV_RETRY: u16 = 209;

const WANTED: [u16; 5] = [EV_REQUEST, EV_RETRY, EV_LU_RESET, EV_TARGET_RESET, EV_RESET_DETECTED];

// ---- status values -----------------------------------------------------------------------------
// From Microsoft's own table (support article 244780, "Information about Event ID 51", which lists
// srb.h and scsi.h): 0x01 = SRB_STATUS_SUCCESS; 0x80 = SRB_STATUS_AUTOSENSE_VALID and 0x40 =
// SRB_STATUS_QUEUE_FROZEN are masks "combined with the SRB status codes"; 0x00 = SCSISTAT_GOOD.
// https://learn.microsoft.com/en-us/troubleshoot/windows-server/backup-and-storage/event-id-51-information
const SRB_STATUS_SUCCESS: u8 = 0x01;
const SRB_STATUS_FLAGS: u8 = 0x80 | 0x40;
const SCSISTAT_GOOD: u8 = 0x00;

/// Did the request come back with anything but success? The two flag bits are masked off first:
/// "autosense valid" and "queue frozen" say something about the request, not whether it worked.
pub fn failed(srb: u8, scsi: u8) -> bool {
    srb & !SRB_STATUS_FLAGS != SRB_STATUS_SUCCESS || scsi != SCSISTAT_GOOD
}

/// Is `Command` (the SCSI operation code; NVMe drives show up translated to SCSI by stornvme,
/// MEASURED) a read, a write or a flush? Only those count as a drive failing a request: the port
/// driver also passes down inquiries and health queries (this tool makes some itself), which a
/// drive or a USB bridge may reject without anything being wrong.
/// 0x08 READ6, 0x0A WRITE6, 0x28 READ, 0x2A WRITE, 0x35 SYNCHRONIZE_CACHE: Microsoft's scsi.h table
/// in the Event ID 51 article above. 0x88 READ16 and 0x8A WRITE16: the SDK's scsi.h
/// (https://github.com/tpn/winsdk-10/blob/master/Include/10.0.16299.0/shared/scsi.h, a mirror of
/// the Windows 10 SDK), and seen live on this PC's NVMe drives.
pub fn is_data_command(cmd: u8) -> bool {
    matches!(cmd, 0x08 | 0x0A | 0x28 | 0x2A | 0x35 | 0x88 | 0x8A)
}

// ---- memory bounds -----------------------------------------------------------------------------
/// How much history the request ring keeps, in ms of trace time: the same 20 s as the kernel
/// session's disk ring, so every slow request the analyzer can still see can be looked up here.
pub const KEEP_MS: f64 = 20_000.0;
/// ...and a count cap, so a benchmark doing hundreds of thousands of requests a second cannot grow
/// it without limit before pruning runs: 500,000 x 48 bytes is 24 MB worst case. At the measured
/// 1,750 a second the ring holds 35,000 records (1.7 MB). An overflow only disqualifies the slow
/// requests that reach back into what was thrown away.
pub const REQ_CAP: usize = 500_000;
/// Resets are rare; this only bounds a drive resetting in a loop.
const RESET_CAP: usize = 1_000;
/// How long the analyzer may wait for this session's buffers after the kernel session has caught
/// up: the session flushes at least once a second (`FlushTimer` = 1), plus delivery. Rule of thumb.
pub const FLUSH_WAIT_MS: f64 = 2_000.0;

/// A drive's address on its storage port: which adapter (`Port`), bus, target and logical unit.
/// The same four numbers `IOCTL_SCSI_GET_ADDRESS` returns for a disk, which is how an event is
/// tied to a disk number (see `disks::scsi_address`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ScsiAddr {
    pub port: u8,
    pub bus: u8,
    pub target: u8,
    pub lun: u8,
}

/// One request the port driver passed down and got back (event 201). 48 bytes: see the size test.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReqRec {
    /// When it completed (the event's timestamp), QPC.
    pub ts: i64,
    /// `RequestDuration_100ns`, converted to QPC ticks: the time below the port driver.
    pub dur: i64,
    /// `Irp` and `OriginalIrp`: kernel pointers, used only to find the DiskIo record of the same
    /// request. Which of the two equals DiskIo's `Irp` is exactly what --debug counts.
    pub irp: u64,
    pub orig: u64,
    pub bytes: u32,
    pub addr: ScsiAddr,
    pub srb: u8,
    pub scsi: u8,
    /// `Command`: the SCSI operation code; see `is_data_command`.
    pub cmd: u8,
    /// Retries (event 209) the port driver logged for this request before it completed.
    pub retries: u8,
}

impl ReqRec {
    pub fn start(&self) -> i64 {
        self.ts - self.dur
    }

    /// A read, write or flush that came back with anything but success.
    pub fn failed(&self) -> bool {
        is_data_command(self.cmd) && failed(self.srb, self.scsi)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResetKind {
    LogicalUnit,
    Target,
    /// The miniport told the port driver the whole adapter port was reset.
    Detected,
}

/// One reset seen live. The narrower the reset, the more of the address it names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResetRec {
    pub ts: i64,
    pub kind: ResetKind,
    pub port: u32,
    pub bus: Option<u8>,
    pub target: Option<u8>,
    pub lun: Option<u8>,
}

impl ResetRec {
    /// Did this reset take the drive at `a` down with it? A logical-unit reset hits one drive, a
    /// target reset every unit of that target, a reset notification the whole port.
    pub fn hits(&self, a: ScsiAddr) -> bool {
        self.port == a.port as u32
            && self.bus.is_none_or(|b| b == a.bus)
            && self.target.is_none_or(|t| t == a.target)
            && self.lun.is_none_or(|l| l == a.lun)
    }
}

/// Everything one drive address did over the whole run.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AddrTotals {
    pub requests: u64,
    /// Reads, writes and flushes that came back with a status other than success.
    pub failed: u64,
    /// Requests that were retried at least once, and the retries in all.
    pub retried: u64,
    pub retries: u64,
}

#[derive(Default)]
pub struct StorInner {
    pub events: u64,
    pub latest_ts: i64,
    last_prune: i64,
    /// When the session started (QPC): a request that began before it cannot be followed.
    pub started: i64,
    /// Records that completed before this were pruned by time.
    pub pruned_until: i64,
    /// Set once the session is stopped and its consumer has drained: nothing more is coming.
    pub finished: bool,

    pub reqs: VecDeque<ReqRec>,
    pub req_cap: usize,
    /// Trace time of the newest record the count cap threw away; see `covers`.
    pub reqs_lost_until: Option<i64>,

    /// Retries waiting for their request to complete: Irp -> (first retry, retries so far).
    pending: HashMap<u64, (i64, u32)>,
    /// Retries attached to their request by `Irp`, by `OriginalIrp`, and never attached (the
    /// request's completion was not seen within `KEEP_MS`).
    pub retry_by: [u64; 3],

    pub resets: Vec<ResetRec>,
    pub per_addr: HashMap<ScsiAddr, AddrTotals>,

    /// See `etw::manifest::resolve`.
    layouts: manifest::LayoutCache,

    /// --debug only: every (event id, version) seen, and the ones not understood...
    pub debug_counts: HashMap<(u16, u8), u64>,
    pub debug_unknown: HashMap<(u16, u8), u64>,
    /// ...(SrbStatus, ScsiStatus) and the SCSI command opcode of every request, to check the
    /// status rule and the opcodes against a live run.
    pub debug_status: HashMap<(u8, u8), u64>,
    pub debug_commands: HashMap<u8, u64>,
}

pub struct StorTrace {
    pub inner: Mutex<StorInner>,
    pub debug: bool,
}

/// `RequestDuration_100ns` in QPC ticks. Integer arithmetic, so short requests are not rounded
/// away, and saturating, so a nonsense value cannot overflow.
pub fn ticks_from_100ns(d: u64) -> i64 {
    let t = d as i128 * qpc_freq() as i128 / 10_000_000;
    t.min(i64::MAX as i128) as i64
}

impl StorInner {
    pub fn new(req_cap: usize, started: i64) -> StorInner {
        StorInner { req_cap, started, last_prune: started, ..StorInner::default() }
    }

    fn push_req(&mut self, mut r: ReqRec) {
        // Retries logged before this completion, looked up by either pointer; see `retry_by`.
        for (i, key) in [r.irp, r.orig].into_iter().enumerate() {
            if key == 0 {
                continue;
            }
            if let Some((_, n)) = self.pending.remove(&key) {
                r.retries = r.retries.saturating_add(n.min(255) as u8);
                self.retry_by[i] += n as u64;
            }
        }
        let t = self.per_addr.entry(r.addr).or_default();
        t.requests += 1;
        t.failed += u64::from(r.failed());
        if r.retries > 0 {
            t.retried += 1;
            t.retries += r.retries as u64;
        }
        self.reqs.push_back(r);
        if self.reqs.len() > self.req_cap.max(1) {
            self.reqs_lost_until = self.reqs_lost_until.max(self.reqs.pop_front().map(|r| r.ts));
        }
    }

    fn on_retry(&mut self, ts: i64, irp: u64) {
        if irp == 0 {
            return;
        }
        let e = self.pending.entry(irp).or_insert((ts, 0));
        e.1 += 1;
    }

    fn on_reset(&mut self, r: ResetRec) {
        if self.resets.len() < RESET_CAP {
            self.resets.push(r);
        }
    }

    fn prune(&mut self, keep: i64) {
        let cutoff = self.latest_ts - keep;
        while self.reqs.front().is_some_and(|r| r.ts < cutoff) {
            self.reqs.pop_front();
        }
        self.pruned_until = self.pruned_until.max(cutoff);
        let mut dropped = 0u64;
        self.pending.retain(|_, (ts, n)| {
            let keep = *ts >= cutoff;
            if !keep {
                dropped += *n as u64;
            }
            keep
        });
        self.retry_by[2] += dropped;
        self.last_prune = self.latest_ts;
    }

    /// Does the ring still hold every record that completed from `from` on? Not if the session
    /// started after it, pruning has passed it, or the count cap threw a record from it away.
    pub fn covers(&self, from: i64) -> bool {
        self.started <= from && self.pruned_until < from && self.reqs_lost_until.is_none_or(|l| l < from)
    }

    /// Has this session's trace reached `to`, or has enough real time passed since then that
    /// anything before it would have been delivered? `now` is QPC.
    pub fn caught_up(&self, to: i64, now: i64) -> bool {
        self.finished || self.latest_ts >= to || now - to > ms_to_ticks(FLUSH_WAIT_MS)
    }

    /// The requests that completed in `[from, to]`. Runs under the lock the callback needs, so
    /// it finds the edges by binary search instead of walking the ring; the search is widened by
    /// a millisecond each side against neighbors slightly out of order (as `Inner::switch_window`).
    pub fn window(&self, from: i64, to: i64) -> Vec<ReqRec> {
        let slop = ms_to_ticks(1.0);
        let a = self.reqs.partition_point(|r| r.ts < from - slop);
        let b = self.reqs.partition_point(|r| r.ts <= to + slop);
        self.reqs.range(a..b.max(a)).filter(|r| r.ts >= from && r.ts <= to).copied().collect()
    }
}

/// Pruning is driven by the newest timestamp seen, like the kernel session's rings.
fn maybe_prune(inner: &mut StorInner, ts: i64) {
    if ts > inner.latest_ts {
        inner.latest_ts = ts;
        let keep = ms_to_ticks(KEEP_MS);
        if ts - inner.last_prune > keep / 8 {
            inner.prune(keep);
        }
    }
}

/// What the storage-port trace hands the summary once a run is over. Plain owned data, so the
/// summary and its tests never need a live session.
#[derive(Clone, Debug, Default)]
pub struct StorageReport {
    /// False when the session never ran; nothing else here means anything then.
    pub available: bool,
    pub events: u64,
    /// Events and buffers the session itself had to drop, from stopping it.
    pub lost: u32,
    /// Why there is no storage-port evidence, in one line for DETAILS. `None` when there is.
    pub note: Option<String>,
    pub resets: Vec<ResetRec>,
    pub per_addr: Vec<(ScsiAddr, AddrTotals)>,
    /// See `StorInner::retry_by`.
    pub retry_by: [u64; 3],
    pub debug_counts: Vec<((u16, u8), u64)>,
    pub debug_unknown: Vec<((u16, u8), u64)>,
    pub debug_status: Vec<((u8, u8), u64)>,
    pub debug_commands: Vec<(u8, u64)>,
}

impl StorageReport {
    pub fn totals(&self, a: ScsiAddr) -> AddrTotals {
        self.per_addr.iter().find(|(k, _)| *k == a).map(|(_, t)| *t).unwrap_or_default()
    }

    /// Resets that hit the drive at `a`, oldest first.
    pub fn resets_of(&self, a: ScsiAddr) -> Vec<ResetRec> {
        let mut v: Vec<ResetRec> = self.resets.iter().filter(|r| r.hits(a)).copied().collect();
        v.sort_by_key(|r| r.ts);
        v
    }

    /// Was the drive at `a` (when its address is known) seen by the port driver at all?
    /// `matched` is how many of its slow requests were matched to a port-driver record, which
    /// proves it is on StorPort even when its address could not be read.
    /// `None` when nothing can be said either way.
    pub fn on_storport(&self, a: Option<ScsiAddr>, matched: u32, unmatched: u32) -> Option<bool> {
        if !self.available {
            return None;
        }
        if matched > 0 {
            return Some(true);
        }
        match a {
            Some(a) => Some(self.totals(a).requests > 0),
            None if unmatched > 0 => Some(false),
            None => None,
        }
    }
}

impl StorTrace {
    /// Everything the summary needs, read out once at the end of the run.
    pub fn report(&self) -> StorageReport {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        fn sorted<K: Ord + Copy, V: Copy>(m: &HashMap<K, V>) -> Vec<(K, V)> {
            let mut v: Vec<(K, V)> = m.iter().map(|(k, n)| (*k, *n)).collect();
            v.sort_by_key(|(k, _)| *k);
            v
        }
        // Retries still waiting for their request count as never attached.
        let mut retry_by = inner.retry_by;
        retry_by[2] += inner.pending.values().map(|(_, n)| *n as u64).sum::<u64>();
        StorageReport {
            available: true,
            events: inner.events,
            lost: 0,
            note: None,
            resets: inner.resets.clone(),
            per_addr: sorted(&inner.per_addr),
            retry_by,
            debug_counts: sorted(&inner.debug_counts),
            debug_unknown: sorted(&inner.debug_unknown),
            debug_status: sorted(&inner.debug_status),
            debug_commands: sorted(&inner.debug_commands),
        }
    }
}

/// Starts the session, enables StorPort on it and spawns the consumer thread.
/// The handle must be kept alive for the run; dropping it stops the session.
pub fn start(debug: bool) -> Result<(Session, Arc<StorTrace>, JoinHandle<()>), String> {
    let session = manifest::start(&manifest::Spec {
        session: SESSION_NAME,
        provider: STORPORT_GUID,
        what: "the storage port provider",
        level: TRACE_LEVEL_INFORMATION as u8,
        keywords: KEYWORDS,
        ids: &WANTED,
        // ~1,750 events a second of ~130 bytes each is ~230 KB/s; 128 x 64 KB leaves room for a
        // burst many times that between the once-a-second flushes. Rule of thumb; the session's
        // own lost count is reported.
        buffer_kb: 64,
        min_buffers: 16,
        max_buffers: 128,
    })?;
    let trace = Arc::new(StorTrace { inner: Mutex::new(StorInner::new(REQ_CAP, qpc())), debug });
    let consumer = manifest::spawn_consumer(SESSION_NAME, "storport-etw", Some(events::on_event), trace.clone());
    Ok((session, trace, consumer))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(ms: f64) -> i64 {
        ms_to_ticks(ms)
    }

    fn req(ts_ms: f64, dur_ms: f64, irp: u64) -> ReqRec {
        ReqRec { ts: at(ts_ms), dur: at(dur_ms), irp, srb: SRB_STATUS_SUCCESS, cmd: 0x28, ..ReqRec::default() }
    }

    #[test]
    fn records_stay_small_enough_for_the_stated_memory_bound() {
        assert_eq!(std::mem::size_of::<ReqRec>(), 48);
        const { assert!(REQ_CAP * 48 <= 24 << 20, "the request ring must stay under 24 MB") };
    }

    #[test]
    fn only_success_with_good_scsi_status_counts_as_success() {
        assert!(!failed(0x01, 0x00), "SRB_STATUS_SUCCESS, SCSISTAT_GOOD");
        assert!(!failed(0x41, 0x00), "the queue-frozen flag is not a failure by itself");
        assert!(!failed(0x81, 0x00), "nor is valid sense data");
        assert!(failed(0x04, 0x02), "SRB_STATUS_ERROR with CHECK CONDITION");
        assert!(failed(0x84, 0x02), "the same with sense data (the Event ID 51 example)");
        assert!(failed(0x09, 0x00), "SRB_STATUS_TIMEOUT");
        assert!(failed(0x01, 0x08), "success from the port but SCSISTAT_BUSY from the drive");
        assert!(failed(0x00, 0x00), "still pending is not success");
        // A rejected inquiry or health query is not the drive failing a read or a write.
        let rejected = ReqRec { srb: 0x06, scsi: 0x02, cmd: 0x12, ..ReqRec::default() };
        assert!(!rejected.failed());
        for cmd in [0x08, 0x0A, 0x28, 0x2A, 0x35, 0x88, 0x8A] {
            assert!(ReqRec { cmd, ..rejected }.failed(), "{cmd:#x}");
        }
    }

    #[test]
    fn durations_convert_from_100ns_units_without_losing_short_ones() {
        assert_eq!(ticks_from_100ns(10_000_000), qpc_freq(), "one second");
        assert!((crate::util::ticks_to_ms(ticks_from_100ns(19_000_000)) - 1900.0).abs() < 0.01);
        assert!(ticks_from_100ns(1) <= 1);
        assert!(ticks_from_100ns(u64::MAX) > 0, "a nonsense value saturates rather than wrapping negative");
    }

    #[test]
    fn a_retry_is_attached_to_its_request_by_either_pointer_and_totaled_per_drive() {
        let mut inner = StorInner::new(100, 0);
        let a = ScsiAddr { port: 6, bus: 0, target: 0, lun: 0 };
        inner.on_retry(at(5.0), 0xAAAA);
        inner.on_retry(at(6.0), 0xAAAA);
        inner.on_retry(at(7.0), 0xBBBB);
        inner.push_req(ReqRec { addr: a, ..req(10.0, 9.0, 0xAAAA) });
        inner.push_req(ReqRec { addr: a, orig: 0xBBBB, ..req(11.0, 9.0, 0xCCCC) });
        inner.push_req(ReqRec { addr: a, srb: 0x04, scsi: 0x02, ..req(12.0, 1.0, 0xDDDD) });
        assert_eq!(inner.reqs[0].retries, 2);
        assert_eq!(inner.reqs[1].retries, 1);
        assert_eq!(inner.retry_by, [2, 1, 0]);
        assert_eq!(inner.per_addr[&a], AddrTotals { requests: 3, failed: 1, retried: 2, retries: 3 });
        // A retry whose request is never seen completing is counted, not lost silently.
        inner.on_retry(at(13.0), 0xEEEE);
        inner.latest_ts = at(13.0 + KEEP_MS + 1.0);
        inner.prune(at(KEEP_MS));
        assert_eq!(inner.retry_by[2], 1);
        assert!(inner.reqs.is_empty());
    }

    #[test]
    fn the_ring_admits_what_it_no_longer_covers() {
        let mut inner = StorInner::new(3, at(100.0));
        assert!(!inner.covers(at(50.0)), "before the session started");
        assert!(inner.covers(at(150.0)));
        for i in 0..5 {
            inner.push_req(req(200.0 + i as f64, 0.1, i + 1));
        }
        assert_eq!(inner.reqs.len(), 3);
        assert_eq!(inner.reqs_lost_until, Some(at(201.0)));
        assert!(!inner.covers(at(201.0)) && inner.covers(at(201.5)), "only windows reaching into the overflow are lost");
        inner.latest_ts = at(300.0);
        assert!(inner.caught_up(at(299.0), at(299.0)));
        assert!(!inner.caught_up(at(301.0), at(302.0)), "not there yet and no time to have been delivered");
        assert!(inner.caught_up(at(301.0), at(301.0 + FLUSH_WAIT_MS + 1.0)), "long enough since: whatever was there arrived");
        let w = inner.window(at(202.5), at(204.0));
        assert_eq!(w.iter().map(|r| r.irp).collect::<Vec<_>>(), vec![4, 5]);
    }

    #[test]
    fn a_reset_hits_the_drives_its_address_covers() {
        let d = |port, target, lun| ScsiAddr { port, bus: 0, target, lun };
        let lu = ResetRec { ts: 0, kind: ResetKind::LogicalUnit, port: 2, bus: Some(0), target: Some(1), lun: Some(0) };
        assert!(lu.hits(d(2, 1, 0)) && !lu.hits(d(2, 1, 1)) && !lu.hits(d(3, 1, 0)));
        let target = ResetRec { lun: None, kind: ResetKind::Target, ..lu };
        assert!(target.hits(d(2, 1, 0)) && target.hits(d(2, 1, 1)) && !target.hits(d(2, 0, 0)));
        let port = ResetRec { bus: None, target: None, lun: None, kind: ResetKind::Detected, ..lu };
        assert!(port.hits(d(2, 7, 3)) && !port.hits(d(6, 0, 0)));
    }

    #[test]
    fn a_drive_is_only_called_off_storport_on_evidence() {
        let mut r = StorageReport { available: true, ..StorageReport::default() };
        let usb = ScsiAddr { port: 6, ..ScsiAddr::default() };
        let nvme = ScsiAddr { port: 2, ..ScsiAddr::default() };
        r.per_addr = vec![(nvme, AddrTotals { requests: 10, ..AddrTotals::default() })];
        assert_eq!(r.on_storport(Some(nvme), 0, 0), Some(true));
        assert_eq!(r.on_storport(Some(usb), 0, 3), Some(false), "an address that never showed up");
        assert_eq!(r.on_storport(None, 2, 1), Some(true), "a matched request proves it");
        assert_eq!(r.on_storport(None, 0, 0), None, "no address and nothing tried: nothing to say");
        assert_eq!(StorageReport::default().on_storport(Some(nvme), 0, 3), None, "no session, no verdict");
    }
}
