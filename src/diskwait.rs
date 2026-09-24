//! What coincided with a stall on the storage side, and in which direction the arrow points.
//!
//! A thread that wakes up late while the CPUs are mostly idle was not starved of CPU: it was
//! blocked on something. When the delay lines up with a slow disk request or a slow hard page
//! fault, that something is usually the disk, and the honest verdict is "waiting on disk N", not
//! "a one-off scheduling quirk".
//!
//! For a whole-PC freeze the arrow can point the other way, so this module also says which way.
//! A request that was ALREADY outstanding well before the machine stopped, and only completed as
//! the machine came back, is a `Trigger` candidate: the drive was not answering before anything
//! froze. A request that starts after the freeze began and finishes inside it is a `Victim`: the
//! whole machine was stopped, so of course its request took that long, and counting it against
//! its drive invents a second problem out of the first one. Neither is a proof of cause; the
//! report only ever says "coincided with".

use crate::state::{FaultRec, IoRec};
use crate::util::ms_to_ticks;

/// A disk request has to cover this much of the delay before the delay is blamed on it.
const COVER: f64 = 0.5;
/// A request outstanding at least this long before the stall began was not started by it. The
/// field case that motivated this is a 2.1 s write that began 1.2 s before a 0.9 s freeze; the
/// victims began 9-20 ms after their freeze started, so a few tens of ms separates the two.
const TRIGGER_LEAD_MS: f64 = 50.0;
/// The probe's idea of when a stall ended and the kernel's idea of when a request completed come
/// from different paths; allow this much slop before calling a request "longer than the freeze".
const EDGE_SLACK_MS: f64 = 50.0;

/// Which way the arrow between a stall and an overlapping disk request may point.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// Already outstanding before the stall began: the drive was not answering first.
    Trigger,
    /// Began after the stall began and ended inside it: the stall explains the request.
    Victim,
    /// Overlaps, but neither containment holds. Correlation only.
    Overlap,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DiskWait {
    /// The disk the overlapping slow request was on; None when only a page fault was seen (hard
    /// fault events do not say which disk).
    pub disk: Option<u32>,
    /// The longest overlapping wait, in ticks, and whether it was a write, read or flush.
    pub waited: i64,
    pub op: u8,
    /// This process took a hard page fault during the delay: the probe thread itself was frozen.
    pub own_fault: bool,
    pub role: Role,
    /// When that request completed, so the caller can mark exactly this one as a victim.
    pub io_end: i64,
}

fn overlap(a0: i64, a1: i64, b0: i64, b1: i64) -> i64 {
    (a1.min(b1) - a0.max(b0)).max(0)
}

/// Where a request sits relative to a stall. See the module comment for why this matters.
pub fn role_of(start: i64, end: i64, io_start: i64, io_end: i64) -> Role {
    let lead = ms_to_ticks(TRIGGER_LEAD_MS);
    let slack = ms_to_ticks(EDGE_SLACK_MS);
    if io_start <= start - lead && io_end >= end - slack {
        Role::Trigger
    } else if io_start >= start - lead && io_end <= end + slack {
        Role::Victim
    } else {
        Role::Overlap
    }
}

/// Does a disk explain the delay `[start, end]`, or did the delay explain the disk? `own_pid` is
/// this process. The longest overlapping request wins; a `Trigger` beats a longer `Victim`,
/// because a drive that was already not answering is the more informative of the two.
pub fn explain(start: i64, end: i64, ios: &[IoRec], faults: &[FaultRec], own_pid: u32) -> Option<DiskWait> {
    let length = (end - start).max(1);
    let needed = (length as f64 * COVER) as i64;
    let own_fault = faults.iter().any(|f| f.pid == own_pid && overlap(start, end, f.start, f.end) >= needed);
    let io = ios
        .iter()
        .filter(|i| overlap(start, end, i.end - i.dur, i.end) >= needed)
        .max_by_key(|i| (role_of(start, end, i.end - i.dur, i.end) == Role::Trigger, i.dur));
    match (io, own_fault) {
        (Some(i), _) => Some(DiskWait {
            disk: Some(i.disk),
            waited: i.dur,
            op: i.op,
            own_fault,
            role: role_of(start, end, i.end - i.dur, i.end),
            io_end: i.end,
        }),
        (None, true) => {
            let f = faults.iter().filter(|f| f.pid == own_pid).max_by_key(|f| overlap(start, end, f.start, f.end))?;
            Some(DiskWait {
                disk: None,
                waited: f.end - f.start,
                op: b'R',
                own_fault: true,
                role: role_of(start, end, f.start, f.end),
                io_end: f.end,
            })
        }
        (None, false) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn io(disk: u32, start: i64, dur: i64, op: u8) -> IoRec {
        IoRec { end: start + dur, dur, disk, tid: 1, pid: 4, size: 4096, op, file: 0, offset: 0, irp_flags: 0 }
    }

    fn fault(pid: u32, start: i64, dur: i64) -> FaultRec {
        FaultRec { start, end: start + dur, tid: 9, pid, bytes: 4096, file: 0 }
    }

    fn ms(v: f64) -> i64 {
        ms_to_ticks(v)
    }

    #[test]
    fn a_delay_that_matches_a_slow_request_is_a_disk_wait() {
        // The reported case: 887 ms late with idle CPUs, and an 878 ms write on disk 5 alongside.
        let (start, end) = (ms(1000.0), ms(1887.0));
        let w = explain(start, end, &[io(5, ms(1005.0), ms(878.0), b'W'), io(0, ms(1100.0), ms(2.0), b'R')], &[], 77).unwrap();
        assert_eq!((w.disk, w.op, w.own_fault), (Some(5), b'W', false));
        assert_eq!(w.waited, ms(878.0));
    }

    #[test]
    fn short_or_unrelated_requests_do_not_explain_a_long_delay() {
        let (start, end) = (ms(1000.0), ms(1887.0));
        assert_eq!(explain(start, end, &[io(5, ms(1005.0), ms(100.0), b'W')], &[], 77), None, "covers 11% of the delay");
        assert_eq!(explain(start, end, &[io(5, 0, ms(900.0), b'W')], &[], 77), None, "ended before the delay began");
        assert_eq!(explain(start, end, &[], &[fault(12, ms(1000.0), ms(880.0))], 77), None, "another program's page fault");
    }

    #[test]
    fn the_tools_own_page_fault_is_recognized_with_or_without_a_matching_request() {
        let (start, end) = (ms(1000.0), ms(1887.0));
        let w = explain(start, end, &[io(5, ms(1005.0), ms(878.0), b'R')], &[fault(77, ms(1002.0), ms(880.0))], 77).unwrap();
        assert!(w.own_fault && w.disk == Some(5));
        let w = explain(start, end, &[], &[fault(77, ms(1002.0), ms(880.0))], 77).unwrap();
        assert_eq!((w.disk, w.own_fault, w.waited), (None, true, ms(880.0)));
    }

    #[test]
    fn a_zero_length_delay_does_not_divide_by_zero_or_match_everything() {
        assert_eq!(explain(1000, 1000, &[], &[], 77), None);
    }

    /// Both field cases, with the numbers from the logs in issue #15. The 2.1 s write to the
    /// sleeping drive was outstanding 1.2 s before the freeze and finished with it: a trigger
    /// candidate. The 878 ms write that began 9 ms INTO an 886 ms freeze is a victim, and must
    /// not become a second "this drive responds slowly" problem.
    #[test]
    fn a_request_that_outlasted_the_freeze_is_a_trigger_and_one_inside_it_is_a_victim() {
        let (start, end) = (ms(1000.0), ms(1886.0)); // an 886 ms freeze
        let trigger = io(6, ms(-200.0), ms(2100.0), b'W'); // began 1.2 s early, ends 14 ms after
        let victim = io(5, ms(1009.0), ms(878.0), b'W'); // began 9 ms in, ends 1 ms after
        assert_eq!(role_of(start, end, trigger.end - trigger.dur, trigger.end), Role::Trigger);
        assert_eq!(role_of(start, end, victim.end - victim.dur, victim.end), Role::Victim);
        // A request that started inside and was still running long after the machine came back
        // is neither: it says nothing either way.
        let after = io(1, ms(1100.0), ms(2000.0), b'R');
        assert_eq!(role_of(start, end, after.end - after.dur, after.end), Role::Overlap);

        // With both present the trigger is reported, even though the victim is not much shorter.
        let w = explain(start, end, &[victim, trigger], &[], 77).unwrap();
        assert_eq!((w.disk, w.role), (Some(6), Role::Trigger));
        // Alone, the victim is still reported: the caller decides what to do with the role.
        let w = explain(start, end, &[victim], &[], 77).unwrap();
        assert_eq!((w.disk, w.role, w.io_end), (Some(5), Role::Victim, victim.end));
    }
}
