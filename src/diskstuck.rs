//! When a disk request is slow: WHAT it was, WHO was stuck behind it, and whether several programs
//! were fighting over a hard drive's head at the time (issue #20, step 1).
//!
//! Everything here reads data the trace already records: the request's `IrpFlags` and
//! `ByteOffset` (DiskIo read/write events), the file-name map, and the context-switch / wake-up
//! rings. No new trace flags, no extra events.
//!
//! What this never claims: WHICH lock, or which kernel function anyone was in. A wait reason is a
//! kind of wait and a readying thread is the thread that signaled; "held by" below means exactly
//! "the thread that woke it", and is only said when the trace names such a thread at all.

use std::collections::{HashMap, HashSet};
use std::hash::Hash;

use windows_sys::Wdk::System::SystemServices::{IRP_NOCACHE, IRP_PAGING_IO, IRP_SYNCHRONOUS_PAGING_IO};

use crate::files;
use crate::state::{IoRec, ReadyRec, SwitchRec};
use crate::switches::{self, IDLE_TID, STATE_WAITING};
use crate::util::{fmt_dur, ms_to_ticks};

// IRP flag values, from windows-sys (generated from Microsoft's metadata for wdm.h) and confirmed
// against Microsoft's own sample header, which defines exactly these four for display:
//   #define IRP_NOCACHE 0x00000001 / IRP_PAGING_IO 0x00000002 / IRP_SYNCHRONOUS_API 0x00000004 /
//   IRP_SYNCHRONOUS_PAGING_IO 0x00000040
// https://github.com/microsoft/Windows-driver-samples/blob/main/filesys/miniFilter/minispy/user/mspyLog.h
// The DiskIo event lists these names without values:
// https://learn.microsoft.com/en-us/windows/win32/etw/diskio-typegroup1
//
// IRP_MOUNT_COMPLETION has the SAME value as IRP_PAGING_IO (0x2; windows-sys, and phnt as a second
// source: https://ntdoc.m417z.com/irp_mount_completion). It means "mount completion" only on a file
// system's mount request (IRP_MN_MOUNT_VOLUME), never on a read or a write, and DiskIo events 10/11
// are reads and writes. So 0x2 on them is read as paging I/O - but that is an inference from the
// names, not something Microsoft states, and the --debug histogram exists to check it.
const _: () = assert!(IRP_PAGING_IO == 0x2 && IRP_NOCACHE == 0x1 && IRP_SYNCHRONOUS_PAGING_IO == 0x40);

/// What one slow request was.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Kind {
    /// Paging I/O to or from pagefile.sys / swapfile.sys: a program's memory.
    PagingFile,
    /// A paging read of an .exe / .dll / .sys: a program's code being loaded.
    ProgramCode,
    /// Any other paging I/O: Windows' memory manager moving one file's pages (a mapped file, or a
    /// file named nowhere at all).
    PagedFile,
    /// NTFS's own metadata ($Mft, $LogFile, $Bitmap, directory indexes...).
    Bookkeeping,
    /// A read or write that was not paging I/O: a file's contents.
    FileData,
    Flush,
}

impl Kind {
    pub fn is_paging(self) -> bool {
        // Not `PagedFile`: measured live, most paging I/O to an ordinary file is the file cache
        // reading ahead for a program or writing its saved changes out, not memory pressure.
        matches!(self, Kind::PagingFile | Kind::ProgramCode)
    }
}

/// Is this file the file system's own bookkeeping? NTFS's metadata files all have names that start
/// with '$' in the volume root (`$Mft`, `$LogFile`, `$Bitmap`, `$Extend\$UsnJrnl`...). A directory's
/// index is the `$I30` stream of the directory; whether the kernel names a directory read that way
/// in FileIo_Name is NOT verified, so it only counts when the name says so.
/// https://learn.microsoft.com/en-us/archive/blogs/askcore/ntfs-metafiles (Microsoft support blog)
pub fn is_bookkeeping(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    // Deleted files in the Recycle Bin are renamed $R... / $I...: somebody's data, not metadata.
    if lower.contains("$recycle.bin") {
        return false;
    }
    files::base_name(&lower).starts_with('$') || lower.contains("\\$extend\\") || lower.contains(":$i30")
}

/// `path` must already have been through `files::public_path` (it only ever reads the file name
/// and extension, and those survive the privacy rule whenever they matter here).
pub fn classify(op: u8, irp_flags: u32, path: Option<&str>) -> Kind {
    if op == b'F' {
        return Kind::Flush;
    }
    if path.is_some_and(is_bookkeeping) {
        return Kind::Bookkeeping;
    }
    if irp_flags & IRP_PAGING_IO == 0 {
        return Kind::FileData;
    }
    match path {
        Some(p) if files::is_paging_file(p) => Kind::PagingFile,
        Some(p) if op == b'R' && is_code(p) => Kind::ProgramCode,
        _ => Kind::PagedFile,
    }
}

fn is_code(path: &str) -> bool {
    let lower = files::base_name(path).to_ascii_lowercase();
    [".exe", ".dll", ".sys"].iter().any(|e| lower.ends_with(e))
}

/// The "Request:" line's words, or `None` for a flush (the slow line already says "flush").
pub fn request_text(kind: Kind, op: u8, path: Option<&str>) -> Option<String> {
    let read = op == b'R';
    Some(match kind {
        Kind::Flush => return None,
        Kind::PagingFile if read => "paging read from the paging file: a program's memory coming back from disk".into(),
        Kind::PagingFile => "paging write to the paging file: memory being moved out to disk to make room".into(),
        Kind::ProgramCode => "paging read of program code: Windows loading part of a program from disk".into(),
        // Measured live (issue #20): a program reading a big file through the normal file cache
        // shows up as paging reads (read-ahead on Windows' own threads, cache misses on its own), not memory
        // running out. The words must not suggest a memory problem.
        Kind::PagedFile if read => "through the file cache: Windows fetching part of a file for whichever program is reading it".into(),
        Kind::PagedFile => "the file cache writing out: a program's saved changes going to the drive".into(),
        Kind::Bookkeeping => {
            let name = path.map(files::base_name).unwrap_or("metadata");
            format!("file-system bookkeeping ({name}): the file system's own records, not anyone's data")
        }
        Kind::FileData if read => "ordinary read of a file's contents".into(),
        Kind::FileData => "ordinary write of a file's contents".into(),
    })
}

// ---------------------------------------------------------------------------------------------
// Who was stuck behind it
// ---------------------------------------------------------------------------------------------

/// A thread counts as stuck behind a request when it was made runnable within this window around
/// the request's completion. The completion path itself readies the threads waiting on it, so
/// this is normally microseconds; 1 ms leaves room for completion work delayed behind other
/// interrupt-level work, and is still short next to what one hard-drive request takes. Rule of
/// thumb, not a specification.
pub const READY_AFTER_MS: f64 = 1.0;
/// The least a thread must have waited to count as stuck behind a request: about one frame at
/// 100 Hz. Shorter waits are not felt, and at that length a wake-up at the same instant as the
/// completion is as likely a coincidence as a consequence. Rule of thumb, not a specification.
pub const STUCK_MIN_MS: f64 = 10.0;
/// ...and this much BEFORE it: the completion event and the wake-up are stamped on different
/// processors, and which of the two is logged first is not documented.
pub const READY_BEFORE_MS: f64 = 0.1;
/// A lock waiter is only tied to a stuck thread when that thread woke it within this long of
/// getting going again itself: time to finish what it needed the disk for and let go. Rule of
/// thumb; any longer and "it held the lock because it was waiting on the drive" is a guess.
pub const LOCK_AFTER_MS: f64 = 20.0;
/// How far past a request's completion the rings have to reach before it can be examined.
pub const LOOK_AFTER_MS: f64 = READY_AFTER_MS + LOCK_AFTER_MS;

/// Kinds of wait that can be a thread waiting on I/O. Values from the KWAIT_REASON table on the
/// CSwitch page: 0 Executive / 7 WrExecutive, 2 PageIn / 9 WrPageIn, 19 WrPageOut.
/// https://learn.microsoft.com/en-us/windows/win32/etw/cswitch
/// Executive is what Microsoft tells kernel code to wait with ("A driver should set this value to
/// Executive, unless it is doing work on behalf of a user..."):
/// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kewaitforsingleobject
/// Which reason Windows' own synchronous file I/O waits with is not documented, so this is a
/// filter, not a proof; the timing rules in `stuck_behind` do the real work.
/// UserRequest (6/13) is left out on purpose: it is every GUI thread waiting for a message, and on a
/// busy PC dozens of those are woken inside any millisecond. Only the thread that issued the
/// request is allowed any (non-voluntary) reason, because its link to the request is known.
pub fn disk_wait(reason: i8) -> bool {
    matches!(reason, 0 | 7 | 2 | 9 | 19)
}

/// One thread stuck behind a slow request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stuck {
    pub tid: u32,
    /// How long it waited, from being switched off into its wait until it was made runnable.
    pub waited: i64,
    pub reason: i8,
    pub woke_at: i64,
}

/// A thread that waited on a lock-like wait and was woken by a stuck thread.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LockChain {
    pub waiter: u32,
    pub holder: u32,
    pub waited: i64,
}

/// The newest switch that took `tid` off a processor at or before `at`, if that was into a wait.
/// Because a thread that has been readied has to run before it can wait again, this is the wait
/// that the ready at `at` ended.
fn wait_before(sw: &[SwitchRec], tid: u32, at: i64) -> Option<&SwitchRec> {
    sw.iter().rfind(|s| s.old_tid == tid && s.ts <= at).filter(|s| s.old_state == STATE_WAITING)
}

/// Threads that went to sleep while `slow` was outstanding and were made runnable as it completed.
/// `others` is every other recent request, on any disk: when one of them started before the
/// thread's wait and completed at least as close to its wake-up, the thread could have been
/// waiting on that one instead, and it is left out rather than guessed at.
pub fn stuck_behind(slow: &IoRec, others: &[IoRec], sw: &[SwitchRec], rd: &[ReadyRec]) -> Vec<Stuck> {
    let start = slow.end - slow.dur;
    let (lo, hi) = (slow.end - ms_to_ticks(READY_BEFORE_MS), slow.end + ms_to_ticks(READY_AFTER_MS));
    let mut out: Vec<Stuck> = Vec::new();
    for r in rd.iter().filter(|r| r.ts >= lo && r.ts <= hi && r.tid != IDLE_TID) {
        if out.iter().any(|s| s.tid == r.tid) {
            continue;
        }
        let Some(off) = wait_before(sw, r.tid, r.ts) else { continue };
        // The wait began while the request was outstanding, not before it (then it was waiting
        // for something else first) and not after it completed.
        if off.ts < start || off.ts >= slow.end {
            continue;
        }
        let reason = off.old_wait_reason;
        let issuer = r.tid == slow.tid;
        if !(disk_wait(reason) || issuer && !switches::voluntary_wait(reason)) {
            continue;
        }
        let ours = (slow.end - r.ts).abs();
        let rival = others.iter().any(|o| {
            let same = o.end == slow.end && o.dur == slow.dur && o.tid == slow.tid && o.disk == slow.disk;
            !same && o.end - o.dur <= off.ts && o.end <= hi && (o.end - r.ts).abs() <= ours && o.end > off.ts
        });
        if rival && !issuer {
            continue;
        }
        // A thread that only joined the wait at the very end was not held up by this request in
        // any way a person feels, and is more likely woken by something else at the same instant:
        // measured live, a 91 ms flush "had" a sync service stuck behind it for 0.4 ms.
        if r.ts - off.ts < ms_to_ticks(STUCK_MIN_MS) {
            continue;
        }
        out.push(Stuck { tid: r.tid, waited: r.ts - off.ts, reason, woke_at: r.ts });
    }
    out.sort_by_key(|s| (std::cmp::Reverse(s.waited), s.tid));
    out
}

/// Depth-2 lock chains: a thread in a lock-like wait that was woken by one of `stuck` shortly after
/// that thread got going again. Only when the wake-up names a real waking thread (not a DPC): see
/// `ReadyRec::waker`. The waiter's wait has to have begun while the request was outstanding.
pub fn lock_chains(slow: &IoRec, stuck: &[Stuck], sw: &[SwitchRec], rd: &[ReadyRec]) -> Vec<LockChain> {
    let start = slow.end - slow.dur;
    let window = ms_to_ticks(LOCK_AFTER_MS);
    let mut out: Vec<LockChain> = Vec::new();
    for r in rd {
        let Some(by) = r.waker() else { continue };
        let Some(holder) = stuck.iter().find(|s| s.tid == by) else { continue };
        if r.ts < holder.woke_at || r.ts > holder.woke_at + window || stuck.iter().any(|s| s.tid == r.tid) {
            continue;
        }
        if out.iter().any(|c| c.waiter == r.tid) {
            continue;
        }
        let Some(off) = wait_before(sw, r.tid, r.ts) else { continue };
        // Already waiting while the holder was stuck, and on something lock-like.
        if off.ts < start || off.ts >= holder.woke_at || !switches::lock_wait(off.old_wait_reason) {
            continue;
        }
        if r.ts - off.ts < ms_to_ticks(STUCK_MIN_MS) {
            continue;
        }
        out.push(LockChain { waiter: r.tid, holder: by, waited: r.ts - off.ts });
    }
    out.sort_by_key(|c| (std::cmp::Reverse(c.waited), c.waiter));
    out
}

// ---------------------------------------------------------------------------------------------
// Head thrashing
// ---------------------------------------------------------------------------------------------

/// Two requests this far apart on the disk cost a real seek on a hard drive, never a read that
/// just carries on down the track. Rule of thumb, not a specification: any jump past a few
/// megabytes already moves the head.
pub const FAR_BYTES: i64 = 128 << 20;
/// How far back from a slow request's completion the drive's recent requests are looked at.
pub const THRASH_LOOK_MS: f64 = 500.0;
/// A program has to have this many requests in the window to count as one of the "several".
const MIN_EACH: usize = 4;
/// ...and the drive has to have jumped between programs, far apart, at least this often...
const MIN_FAR_SWITCHES: usize = 6;
/// ...and for at least this share of all its consecutive requests. Two programs taking turns in
/// long runs is not thrashing; alternating every request or two is. Both rules of thumb.
const MIN_FAR_SHARE: f64 = 0.25;

/// Did a hard drive keep jumping between several programs working far-apart regions while `slow`
/// was outstanding? `reqs` is (completion time, byte offset, program) of every read and write the
/// drive completed in that window; they are taken in completion order, which is the order the
/// drive served them. Returns the programs involved, most requests first. Never on an SSD, where
/// there is no head and distance costs nothing.
pub fn thrash<K: Eq + Hash + Clone + Ord>(reqs: &[(i64, i64, K)], spinning: bool) -> Option<Vec<(K, usize)>> {
    if !spinning || reqs.len() < 2 * MIN_EACH {
        return None;
    }
    let mut v: Vec<&(i64, i64, K)> = reqs.iter().collect();
    v.sort_by_key(|r| r.0);
    let mut counts: HashMap<&K, usize> = HashMap::new();
    for r in &v {
        *counts.entry(&r.2).or_default() += 1;
    }
    let big: HashSet<&K> = counts.iter().filter(|(_, n)| **n >= MIN_EACH).map(|(k, _)| *k).collect();
    if big.len() < 2 {
        return None;
    }
    let far = v.windows(2).filter(|p| p[0].2 != p[1].2 && (p[0].1 - p[1].1).abs() >= FAR_BYTES).count();
    let share = far as f64 / (v.len() - 1) as f64;
    if far < MIN_FAR_SWITCHES || share < MIN_FAR_SHARE {
        return None;
    }
    let mut out: Vec<(K, usize)> = big.into_iter().map(|k| (k.clone(), counts[k])).collect();
    out.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    Some(out)
}

/// Program names with repeats folded: ["a", "b", "a"] -> ["a (2 copies)", "b"], first seen first.
pub fn copies(names: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut order: Vec<(String, usize)> = Vec::new();
    for n in names {
        match order.iter_mut().find(|(o, _)| *o == n) {
            Some(e) => e.1 += 1,
            None => order.push((n, 1)),
        }
    }
    order.into_iter().map(|(n, k)| if k > 1 { format!("{n} ({k} copies)") } else { n }).collect()
}

// ---------------------------------------------------------------------------------------------
// The event-log line
// ---------------------------------------------------------------------------------------------

/// Same as the rest of the report.
pub const LINE_WIDTH: usize = 118;
/// Longest program name the line will print whole.
const NAME_MAX: usize = 32;

fn clip(name: &str) -> String {
    if name.chars().count() <= NAME_MAX {
        return name.to_string();
    }
    let head: String = name.chars().take(NAME_MAX - 3).collect();
    format!("{head}...")
}

/// One program stuck behind a request: its name, how many of its threads, the longest wait.
#[derive(Clone, Debug, PartialEq)]
pub struct Victim {
    pub name: String,
    pub threads: usize,
    pub longest: i64,
}

/// Threads grouped into programs, longest wait first.
pub fn by_program(stuck: &[(String, i64)]) -> Vec<Victim> {
    let mut v: Vec<Victim> = Vec::new();
    for (name, waited) in stuck {
        match v.iter_mut().find(|p| &p.name == name) {
            Some(p) => {
                p.threads += 1;
                p.longest = p.longest.max(*waited);
            }
            None => v.push(Victim { name: name.clone(), threads: 1, longest: *waited }),
        }
    }
    v.sort_by(|a, b| b.longest.cmp(&a.longest).then_with(|| a.name.cmp(&b.name)));
    v
}

/// "    Stuck behind it: explorer.exe (3 threads, up to 2100 ms), Discord.exe (1); explorer.exe
/// waited 1200 ms on a lock held by System, which was waiting on disk 1 (D:)"
///
/// Never wider than `LINE_WIDTH`: programs are dropped (the lock chain is the rarer and more
/// telling fact, so it goes last), then the chain, until it fits. `chains` is (waiter, waited,
/// holder); only the longest is shown here, the finding totals them all.
pub fn stuck_line(victims: &[Victim], chains: &[(String, i64, String)], drive: &str) -> Option<String> {
    if victims.is_empty() && chains.is_empty() {
        return None;
    }
    // "disk 1 (D:)", and "disk 1" when that is what it takes to fit (the line above names the drive).
    let bare = drive.split(" (").next().unwrap_or(drive);
    let chain_to = |drive: &str| {
        chains.first().map(|(w, t, h)| {
            format!("{} waited {} on a lock held by {}, which was waiting on {}", clip(w), fmt_dur(*t), clip(h), clip(drive))
        })
    };
    // The worst program in full, the next ones as "name (threads)".
    let programs = |n: usize| {
        let mut parts: Vec<String> = Vec::new();
        for (i, p) in victims.iter().take(n).enumerate() {
            parts.push(if i == 0 {
                let t = if p.threads == 1 { "1 thread".to_string() } else { format!("{} threads", p.threads) };
                format!("{} ({t}, up to {})", clip(&p.name), fmt_dur(p.longest))
            } else {
                format!("{} ({})", clip(&p.name), p.threads)
            });
        }
        if victims.len() > n {
            parts.push(format!("{} more", victims.len() - n));
        }
        parts.join(", ")
    };
    let counted = format!("{} program{}", victims.len(), if victims.len() == 1 { "" } else { "s" });
    let mut candidates: Vec<String> = Vec::new();
    let ns: Vec<usize> = (1..=victims.len().min(4)).rev().collect();
    for c in [chain_to(drive), chain_to(bare)].into_iter().flatten() {
        candidates.extend(ns.iter().map(|&n| format!("{}; {c}", programs(n))));
        candidates.push(if victims.is_empty() { c.clone() } else { format!("{counted}; {c}") });
    }
    candidates.extend(ns.iter().map(|&n| programs(n)));
    let lines: Vec<String> = candidates.into_iter().map(|c| format!("    Stuck behind it: {c}")).collect();
    // The last resort is only reachable with absurd names: cut rather than overflow.
    lines.iter().find(|l| l.chars().count() <= LINE_WIDTH).cloned().or_else(|| lines.first().map(|l| l.chars().take(LINE_WIDTH).collect()))
}

/// "the drive kept jumping between A and B", when there was a fight over the head at all.
fn fight(thrash_with: &[String]) -> Option<String> {
    // Two copies of one program are one name here, and still two things fighting over the head.
    (thrash_with.len() >= 2 || thrash_with.iter().any(|n| n.ends_with(" copies)"))).then(|| {
        let names: Vec<String> = thrash_with.iter().take(3).map(|n| clip(n)).collect();
        format!("the drive kept jumping between {}", names.join(" and "))
    })
}

/// "    Request: <text>", plus who the drive was jumping between when it fits.
pub fn request_line(text: &str, thrash_with: &[String]) -> String {
    let base = format!("    Request: {text}");
    if let Some(f) = fight(thrash_with) {
        let with = format!("{base}; {f}");
        if with.chars().count() <= LINE_WIDTH {
            return with;
        }
    }
    base.chars().take(LINE_WIDTH).collect()
}

/// A few words for what the request was, for when the full sentence does not leave room.
pub fn request_short(kind: Kind, op: u8) -> &'static str {
    let read = op == b'R';
    match kind {
        Kind::Flush => "flush",
        Kind::PagingFile if read => "paging-file read",
        Kind::PagingFile => "paging-file write",
        Kind::ProgramCode => "loading program code",
        Kind::PagedFile if read => "read through the file cache",
        Kind::PagedFile => "file cache writing out",
        Kind::Bookkeeping => "file-system bookkeeping",
        Kind::FileData if read => "ordinary read",
        Kind::FileData => "ordinary write",
    }
}

/// The "Request:" line with where the time went appended (`timing`, from the storage port
/// driver's trace), or the plain `request_line` without it. `None` only for a flush with nothing
/// to add, as before. Never wider than `LINE_WIDTH`: the full description gives way to the short
/// one before the thrashing or the timing is dropped, and the timing, the one new measured fact,
/// goes last.
pub fn request_line_timed(kind: Kind, op: u8, path: Option<&str>, thrash_with: &[String], timing: Option<&str>) -> Option<String> {
    let long = request_text(kind, op, path);
    let Some(timing) = timing else { return long.map(|t| request_line(&t, thrash_with)) };
    let short = request_short(kind, op);
    let long = long.unwrap_or_else(|| short.to_string());
    let mut candidates: Vec<String> = Vec::new();
    if let Some(f) = fight(thrash_with) {
        // The same fact in fewer words before it is given up; the finding totals it either way.
        let brief = f.replacen("the drive kept jumping", "head jumping", 1);
        candidates.extend([format!("{long}; {f}; {timing}"), format!("{short}; {f}; {timing}"), format!("{short}; {brief}; {timing}")]);
    }
    candidates.extend([format!("{long}; {timing}"), format!("{short}; {timing}"), timing.to_string()]);
    let lines: Vec<String> = candidates.into_iter().map(|c| format!("    Request: {c}")).collect();
    lines.iter().find(|l| l.chars().count() <= LINE_WIDTH).cloned().or_else(|| lines.last().map(|l| l.chars().take(LINE_WIDTH).collect()))
}

// ---------------------------------------------------------------------------------------------
// Totals over the run, for the disk finding
// ---------------------------------------------------------------------------------------------

/// Everything the slow requests of one disk said about themselves over a run.
#[derive(Clone, Debug, Default)]
pub struct DiskBehind {
    pub kinds: HashMap<Kind, u32>,
    /// Slow requests whose waiters could be looked for, and ones the switch rings could not cover.
    pub checked: u32,
    pub uncovered: u32,
    /// Program -> (slow requests it was stuck behind, total wait).
    pub stuck: HashMap<String, (u32, i64)>,
    /// (waiter, holder) -> (times, longest wait).
    pub chains: HashMap<(String, String), (u32, i64)>,
    /// Slow requests during which the drive was thrashing, and program -> how often it was involved.
    pub thrash: u32,
    pub thrash_programs: HashMap<String, u32>,
}

impl DiskBehind {
    pub fn count(&self, pred: impl Fn(Kind) -> bool) -> u32 {
        self.kinds.iter().filter(|(k, _)| pred(**k)).map(|(_, n)| *n).sum()
    }

    /// Programs stuck behind this disk, most total waiting first.
    pub fn top_stuck(&self, n: usize) -> Vec<(String, u32, i64)> {
        let mut v: Vec<(String, u32, i64)> = self.stuck.iter().map(|(k, (c, t))| (k.clone(), *c, *t)).collect();
        v.sort_by(|a, b| b.2.cmp(&a.2).then_with(|| a.0.cmp(&b.0)));
        v.truncate(n);
        v
    }

    pub fn top_chains(&self, n: usize) -> Vec<(String, String, u32, i64)> {
        let mut v: Vec<_> = self.chains.iter().map(|((w, h), (c, t))| (w.clone(), h.clone(), *c, *t)).collect();
        v.sort_by(|a, b| b.3.cmp(&a.3).then_with(|| a.0.cmp(&b.0)));
        v.truncate(n);
        v
    }

    pub fn top_thrashers(&self, n: usize) -> Vec<(String, u32)> {
        let mut v: Vec<(String, u32)> = self.thrash_programs.iter().map(|(k, c)| (k.clone(), *c)).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        v.truncate(n);
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::READY_FROM_DPC;

    fn ms(x: f64) -> i64 {
        ms_to_ticks(x)
    }

    fn io(start_ms: f64, dur_ms: f64, tid: u32) -> IoRec {
        let dur = ms(dur_ms);
        IoRec { end: ms(start_ms) + dur, dur, disk: 1, tid, pid: 100, size: 4096, op: b'R', file: 0, irp: 0, offset: 0, irp_flags: 0 }
    }

    fn off(ts: f64, tid: u32, reason: i8) -> SwitchRec {
        SwitchRec {
            ts: ms(ts),
            new_tid: IDLE_TID,
            old_tid: tid,
            cpu: 0,
            new_prio: 0,
            old_prio: 8,
            old_wait_reason: reason,
            old_wait_mode: 0,
            old_state: STATE_WAITING,
        }
    }

    fn rdy(ts: f64, tid: u32, by: u32, flag: i8) -> ReadyRec {
        ReadyRec { ts: ms(ts), tid, by_tid: by, cpu: 0, flag }
    }

    #[test]
    fn requests_are_classified_by_their_flags_and_file() {
        let pf = Some(r"C:\pagefile.sys");
        assert_eq!(classify(b'R', 0x2, pf), Kind::PagingFile);
        assert_eq!(classify(b'W', 0x2 | 0x1, pf), Kind::PagingFile);
        assert_eq!(classify(b'R', 0x43, Some(r"C:\Windows\explorer.exe")), Kind::ProgramCode, "synchronous paging read");
        assert_eq!(classify(b'W', 0x2, Some(r"C:\Windows\x.dll")), Kind::PagedFile, "code is read, not written");
        assert_eq!(classify(b'R', 0x2, None), Kind::PagedFile, "an unnamed paging read is still paging");
        assert_eq!(classify(b'R', 0x2, Some(r"D:\...\(a .mp4 file)")), Kind::PagedFile);
        // Bookkeeping wins over the flags: NTFS reads its metadata through paging I/O too.
        assert_eq!(classify(b'R', 0x2, Some(r"C:\$Mft")), Kind::Bookkeeping);
        assert_eq!(classify(b'W', 0x0, Some(r"\Device\HarddiskVolume3\$LogFile")), Kind::Bookkeeping);
        assert_eq!(classify(b'R', 0, Some(r"C:\$Extend\$UsnJrnl:$J")), Kind::Bookkeeping);
        assert_eq!(classify(b'R', 0, Some(r"C:\$Recycle.Bin\S-1-5-21\$RAB12CD.jpg")), Kind::FileData, "a deleted file is data");
        assert_eq!(classify(b'R', 0x1, Some(r"D:\...\(a .mp4 file)")), Kind::FileData, "no-cache is not paging");
        assert_eq!(classify(b'R', 0x0, Some(r"C:\Windows\explorer.exe")), Kind::FileData, "copying an .exe is file data");
        assert_eq!(classify(b'F', 0x2, None), Kind::Flush);
        assert!(Kind::PagingFile.is_paging() && !Kind::Bookkeeping.is_paging());
        assert!(request_text(Kind::Flush, b'F', None).is_none());
        assert!(request_text(Kind::Bookkeeping, b'R', Some(r"C:\$Mft")).unwrap().contains("($Mft)"));
        assert!(request_text(Kind::PagingFile, b'W', pf).unwrap().contains("make room"));
    }

    /// The core case: a thread goes to sleep on a page-in after the request started and is woken
    /// as it completes. A thread woken before the request began, or seconds later, is not stuck
    /// behind it.
    #[test]
    fn threads_woken_as_the_request_completed_are_stuck_behind_it_and_no_others() {
        let slow = io(1000.0, 800.0, 7); // 1000 -> 1800 ms
        let sw = vec![
            off(900.0, 50, 9),   // waited before the request began
            off(1100.0, 51, 9),  // WrPageIn, inside
            off(1200.0, 52, 0),  // Executive, inside
            off(1300.0, 53, 13), // WrUserRequest: a GUI thread waiting for a message
            off(1400.0, 54, 9),  // woken seconds later
            off(1500.0, 7, 13),  // the issuer itself: any non-voluntary reason
            off(1600.0, 55, 4),  // sleeping on purpose
            off(1799.6, 56, 9),  // joined 0.4 ms before the end: not held up by it (seen live)
        ];
        let rd = vec![
            rdy(1800.05, 50, 0, READY_FROM_DPC),
            rdy(1800.1, 51, 0, READY_FROM_DPC),
            rdy(1800.3, 52, 0, READY_FROM_DPC),
            rdy(1800.3, 53, 0, READY_FROM_DPC),
            rdy(4000.0, 54, 0, READY_FROM_DPC),
            rdy(1800.2, 7, 0, READY_FROM_DPC),
            rdy(1800.2, 55, 0, READY_FROM_DPC),
            rdy(1800.0, 56, 0, READY_FROM_DPC),
        ];
        let got: Vec<u32> = stuck_behind(&slow, &[], &sw, &rd).iter().map(|s| s.tid).collect();
        assert_eq!(got, vec![51, 52, 7], "longest wait first");
        let s = stuck_behind(&slow, &[], &sw, &rd);
        assert_eq!(s[0].waited, ms(1800.1) - ms(1100.0));

        // Readied before the request even started: never matched, whatever the reason.
        let early = vec![rdy(950.0, 51, 0, 0)];
        assert!(stuck_behind(&slow, &[], &sw, &early).is_empty());
    }

    /// When another request that was already outstanding completed at least as close to the
    /// wake-up, the thread may have been waiting on that one: say nothing about it.
    #[test]
    fn a_thread_that_could_have_been_waiting_on_another_request_is_left_out() {
        let slow = io(1000.0, 800.0, 7);
        let sw = vec![off(1100.0, 51, 9), off(1100.0, 60, 9)];
        let rd = vec![rdy(1800.5, 51, 0, READY_FROM_DPC)];
        let rival = io(1050.0, 750.4, 99); // started before the wait, ended at 1800.4
        assert!(stuck_behind(&slow, &[slow, rival], &sw, &rd).is_empty());
        // A rival that began only after the thread went to sleep cannot be what it waited on.
        let late_rival = io(1150.0, 650.4, 99);
        assert_eq!(stuck_behind(&slow, &[slow, late_rival], &sw, &rd).len(), 1);
    }

    #[test]
    fn a_lock_chain_needs_a_real_waking_thread() {
        let slow = io(1000.0, 800.0, 7);
        let stuck = vec![Stuck { tid: 51, waited: ms(700.0), reason: 9, woke_at: ms(1800.1) }];
        let sw = vec![off(1200.0, 80, 27), off(1300.0, 81, 28), off(1250.0, 82, 13)];
        // 80 (WrResource) woken by 51 shortly after 51 got going: a chain.
        let rd = vec![rdy(1802.0, 80, 51, 0)];
        let c = lock_chains(&slow, &stuck, &sw, &rd);
        assert_eq!(c, vec![LockChain { waiter: 80, holder: 51, waited: ms(1802.0) - ms(1200.0) }]);
        // The same wake-up done from a DPC names nobody.
        assert!(lock_chains(&slow, &stuck, &sw, &[rdy(1802.0, 80, 51, READY_FROM_DPC)]).is_empty());
        // Woken by someone who was not stuck: nothing.
        assert!(lock_chains(&slow, &stuck, &sw, &[rdy(1802.0, 80, 99, 0)]).is_empty());
        // Not a lock-like wait.
        assert!(lock_chains(&slow, &stuck, &sw, &[rdy(1802.0, 82, 51, 0)]).is_empty());
        // Much later than the holder got going: not tied to it.
        assert!(lock_chains(&slow, &stuck, &sw, &[rdy(1900.0, 81, 51, 0)]).is_empty());
    }

    fn reqs(pattern: &[(u32, i64)]) -> Vec<(i64, i64, u32)> {
        pattern.iter().enumerate().map(|(i, (p, off))| (i as i64 * 10, *off, *p)).collect()
    }

    #[test]
    fn two_copies_of_one_program_are_named_as_copies_and_still_count_as_thrashing() {
        assert_eq!(copies(["a".to_string(), "b".into(), "a".into()]), vec!["a (2 copies)".to_string(), "b".into()]);
        let line = request_line("x", &copies(["powershell.exe".to_string(), "powershell.exe".into()]));
        assert!(line.contains("jumping between powershell.exe (2 copies)"), "{line}");
        assert!(!request_line("x", &["solo.exe".to_string()]).contains("jumping"), "one program alone is not a fight");
    }

    #[test]
    fn thrashing_is_two_programs_interleaved_far_apart_on_a_hard_drive_only() {
        let gb = 1i64 << 30;
        // A and B alternate, 100 GB apart.
        let pattern: Vec<(u32, i64)> = (0..20).map(|i| if i % 2 == 0 { (1, i * 65536) } else { (2, 100 * gb + i * 65536) }).collect();
        let r = reqs(&pattern);
        let got = thrash(&r, true).expect("thrashing");
        assert_eq!(got.iter().map(|g| g.0).collect::<Vec<_>>(), vec![1, 2]);
        assert!(thrash(&r, false).is_none(), "an SSD has no head to thrash");

        // One sequential stream is not thrashing.
        let one: Vec<(u32, i64)> = (0..30).map(|i| (1, i * 65536)).collect();
        assert!(thrash(&reqs(&one), true).is_none());
        // Two programs taking turns in long runs is not thrashing either.
        let runs: Vec<(u32, i64)> = (0..20).map(|i| if i < 10 { (1, i) } else { (2, 100 * gb + i) }).collect();
        assert!(thrash(&reqs(&runs), true).is_none());
        // Interleaved but next to each other on the disk: no seek, no thrashing.
        let near: Vec<(u32, i64)> = (0..20).map(|i| ((i % 2) as u32 + 1, i * 65536)).collect();
        assert!(thrash(&reqs(&near), true).is_none());
    }

    #[test]
    fn stuck_lines_never_exceed_the_report_width() {
        let v = |name: &str, threads, ms_: f64| Victim { name: name.into(), threads, longest: ms(ms_) };
        let victims = vec![v("explorer.exe", 3, 2100.0), v("Discord.exe", 1, 900.0), v("steam.exe", 2, 40.0)];
        let chains = vec![("explorer.exe".to_string(), ms(1200.0), "System".to_string())];
        let line = stuck_line(&victims, &chains, "disk 1 (D:)").unwrap();
        assert!(line.chars().count() <= LINE_WIDTH, "{line}");
        assert!(line.contains("lock held by System, which was waiting on disk 1"), "{line}");
        println!("{line}");
        let long = "a".repeat(300);
        let many: Vec<Victim> = (0..20).map(|i| v(&format!("{long}{i}.exe"), i + 1, 5.0)).collect();
        let chains = [(long.clone(), ms(1.0), long.clone())];
        for (vs, cs) in [(&many[..], &chains[..]), (&many[..], &[][..]), (&[][..], &chains[..]), (&victims[..], &[][..])] {
            let line = stuck_line(vs, cs, &long).unwrap();
            assert!(line.chars().count() <= LINE_WIDTH, "{} chars: {line}", line.chars().count());
        }
        assert!(stuck_line(&[], &[], "disk 1").is_none(), "nothing to say says nothing");
        let r = request_line(&"x".repeat(200), &["a".into(), "b".into()]);
        assert!(r.chars().count() <= LINE_WIDTH);
        let r = request_line("ordinary read of a file's contents", &["steam.exe".into(), "chrome.exe".into()]);
        assert!(r.ends_with("jumping between steam.exe and chrome.exe") && r.chars().count() <= LINE_WIDTH, "{r}");
    }

    /// Where the time went rides on the "Request:" line; every combination still fits the width,
    /// and the timing is the last thing to go.
    #[test]
    fn the_timed_request_line_fits_and_keeps_the_timing() {
        let timing = "1955 ms inside the drive, 45.00 ms waiting in Windows; retried 12 times";
        let kinds = [Kind::PagingFile, Kind::ProgramCode, Kind::PagedFile, Kind::Bookkeeping, Kind::FileData, Kind::Flush];
        let fighters = [vec![], vec!["steam.exe".to_string(), "qbittorrent.exe".to_string()], vec!["x".repeat(300), "y".repeat(300)]];
        for kind in kinds {
            for op in [b'R', b'W', b'F'] {
                for thrash in &fighters {
                    let line = request_line_timed(kind, op, Some(r"C:\$Mft"), thrash, Some(timing)).expect("a line with timing");
                    assert!(line.chars().count() <= LINE_WIDTH, "{} chars: {line}", line.chars().count());
                    assert!(line.ends_with(timing), "{line}");
                }
            }
        }
        // Short names: the fight stays, in fewer words; long ones give way to the timing.
        let short_timing = "200 ms inside the drive, 5.00 ms waiting in Windows";
        let ab = ["a.exe".to_string(), "b.exe".to_string()];
        let line = request_line_timed(Kind::FileData, b'R', None, &ab, Some(short_timing)).unwrap();
        assert_eq!(line, format!("    Request: ordinary read; head jumping between a.exe and b.exe; {short_timing}"));
        let line = request_line_timed(Kind::FileData, b'R', None, &fighters[1], Some(short_timing)).unwrap();
        assert_eq!(line, format!("    Request: ordinary read of a file's contents; {short_timing}"));
        // Without timing it is exactly the old line, and a flush still has none.
        assert_eq!(
            request_line_timed(Kind::FileData, b'R', None, &[], None),
            Some(request_line("ordinary read of a file's contents", &[]))
        );
        assert_eq!(request_line_timed(Kind::Flush, b'F', None, &[], None), None);
        assert_eq!(
            request_line_timed(Kind::Flush, b'F', None, &[], Some("9 ms inside the drive, 1 ms waiting in Windows")).unwrap(),
            "    Request: flush; 9 ms inside the drive, 1 ms waiting in Windows"
        );
        println!("{}", request_line_timed(Kind::PagedFile, b'R', None, &fighters[1], Some(timing)).unwrap());
    }

    #[test]
    fn threads_add_up_per_program() {
        let p = by_program(&[("a.exe".into(), 5), ("b.exe".into(), 50), ("a.exe".into(), 70)]);
        assert_eq!(p[0], Victim { name: "a.exe".into(), threads: 2, longest: 70 });
        assert_eq!(p[1].name, "b.exe");
    }
}
