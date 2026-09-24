//! Matching a slow DiskIo request to the storage port driver's record of it, and splitting its
//! time into "inside the drive" and "waiting in Windows". Pure functions over plain records, so
//! all of it is tested without a live session.
//!
//! How the two are matched, in order:
//! 1. by pointer: a port-driver record whose `Irp` or `OriginalIrp` equals DiskIo's `Irp`, and
//!    that completed while the DiskIo request was outstanding. IRP addresses are reused, but not
//!    while the request that owns one is still outstanding, and the time window rules out an
//!    earlier or later owner.
//! 2. only when no pointer matches: same drive (by address), completion within `FALLBACK_MS` of
//!    DiskIo's, same byte count, and exactly one such record. Two candidates are ambiguous and
//!    nothing is claimed.
//!
//! Which of these actually works on a real PC is not documented anywhere found; --debug counts
//! each, so one elevated run settles it.
//!
//! A large transfer may reach the port driver as several requests. Their time "inside the drive"
//! is the UNION of their intervals, clipped to the DiskIo request's own lifetime: pieces sent one
//! after another add up (the same as a sum), pieces in flight together are not counted twice
//! (which a sum would), and a slow piece among fast ones is not lost (which a max would do to the
//! rest). The remainder of the DiskIo time is "waiting in Windows". Neither can go negative:
//! anything that does not fit is clipped and counted as an anomaly.

use crate::state::IoRec;
use crate::util::{fmt_dur, ms_to_ticks, plural};

use super::{ReqRec, ScsiAddr};

/// How far outside the DiskIo request's lifetime a port-driver completion may be stamped and still
/// be taken as part of it. Both sessions stamp with the same QPC clock, but on different
/// processors, and which of the two layers logs first is not documented. Rule of thumb.
pub const MATCH_SLOP_MS: f64 = 1.0;
/// The fallback match: completions this close together, on the same drive, same size. Rule of
/// thumb: the port driver completes a request and the disk driver above it completes it next,
/// normally microseconds apart.
pub const FALLBACK_MS: f64 = 1.0;

/// How a slow request was matched to the port driver's record of it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum How {
    Irp,
    OriginalIrp,
    Fallback,
}

/// Where one slow request's time went.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Split {
    pub how: How,
    /// Port-driver requests it was made of.
    pub pieces: u32,
    /// QPC ticks below the port driver (the driver, the controller and the drive)...
    pub inside: i64,
    /// ...and the rest of the DiskIo time: in Windows, above the port driver.
    pub waiting: i64,
    /// A piece reached outside the DiskIo request's lifetime and was clipped.
    pub clipped: bool,
    pub retries: u32,
    /// Pieces that came back with a status other than success.
    pub failed: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Split(Split),
    /// No record matched. On a drive that is not run by the port driver, that is every request.
    Unmatched,
    /// No pointer matched and more than one record fits the fallback.
    Ambiguous,
    /// The ring did not cover the request (the session started later, it overflowed, or the trace
    /// had not caught up): nothing may be concluded, either way.
    NotCovered,
}

/// The union length of `[a, b]` intervals, and nothing negative.
fn union_len(mut spans: Vec<(i64, i64)>) -> i64 {
    spans.retain(|(a, b)| b > a);
    spans.sort_unstable();
    let mut total = 0i64;
    let mut cur: Option<(i64, i64)> = None;
    for (a, b) in spans {
        cur = match cur {
            Some((ca, cb)) if a <= cb => Some((ca, cb.max(b))),
            Some((ca, cb)) => {
                total += cb - ca;
                Some((a, b))
            }
            None => Some((a, b)),
        };
    }
    total + cur.map_or(0, |(a, b)| b - a)
}

/// The split of `slow` over the port-driver `pieces` that make it up.
pub fn split_of(slow: &IoRec, pieces: &[ReqRec], how: How) -> Split {
    let (start, end) = (slow.end - slow.dur, slow.end);
    let slop = ms_to_ticks(MATCH_SLOP_MS);
    let spans: Vec<(i64, i64)> = pieces.iter().map(|r| (r.start().max(start), r.ts.min(end))).collect();
    let inside = union_len(spans).clamp(0, slow.dur.max(0));
    Split {
        how,
        pieces: pieces.len() as u32,
        inside,
        waiting: (slow.dur - inside).max(0),
        clipped: pieces.iter().any(|r| r.start() < start - slop || r.ts > end + slop || r.dur < 0),
        retries: pieces.iter().map(|r| r.retries as u32).sum(),
        failed: pieces.iter().filter(|r| r.failed()).count() as u32,
    }
}

/// Matches `slow` against `window` (the port-driver records that completed around it) and splits
/// its time. `addr` is the drive's address when it is known; without it only pointers can match.
/// The caller decides `NotCovered` before calling.
pub fn correlate(slow: &IoRec, window: &[ReqRec], addr: Option<ScsiAddr>) -> Outcome {
    let (start, end) = (slow.end - slow.dur, slow.end);
    let slop = ms_to_ticks(MATCH_SLOP_MS);
    let during = |r: &&ReqRec| r.ts >= start - slop && r.ts <= end + slop;
    if slow.irp != 0 {
        let pieces: Vec<ReqRec> = window.iter().filter(during).filter(|r| r.irp == slow.irp || r.orig == slow.irp).copied().collect();
        if !pieces.is_empty() {
            let how = if pieces.iter().any(|r| r.irp == slow.irp) { How::Irp } else { How::OriginalIrp };
            return Outcome::Split(split_of(slow, &pieces, how));
        }
    }
    let Some(addr) = addr else { return Outcome::Unmatched };
    let near = ms_to_ticks(FALLBACK_MS);
    let fits: Vec<ReqRec> =
        window.iter().filter(|r| r.addr == addr && (r.ts - end).abs() <= near && r.bytes == slow.size).copied().collect();
    match fits.len() {
        0 => Outcome::Unmatched,
        1 => Outcome::Split(split_of(slow, &fits, How::Fallback)),
        _ => Outcome::Ambiguous,
    }
}

/// Everything the port driver said about one disk's slow requests over a run.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SplitTotals {
    pub by_irp: u32,
    pub by_orig: u32,
    pub by_fallback: u32,
    pub unmatched: u32,
    pub ambiguous: u32,
    pub not_covered: u32,
    /// Matched requests that were made of more than one port-driver request.
    pub multi_piece: u32,
    pub clipped: u32,
    pub inside: i64,
    pub waiting: i64,
    /// Matched requests that were retried, and the retries in all.
    pub retried: u32,
    pub retries: u32,
    pub failed: u32,
}

impl SplitTotals {
    pub fn add(&mut self, o: &Outcome) {
        match o {
            Outcome::Split(s) => {
                match s.how {
                    How::Irp => self.by_irp += 1,
                    How::OriginalIrp => self.by_orig += 1,
                    How::Fallback => self.by_fallback += 1,
                }
                self.multi_piece += u32::from(s.pieces > 1);
                self.clipped += u32::from(s.clipped);
                self.inside += s.inside;
                self.waiting += s.waiting;
                self.retried += u32::from(s.retries > 0);
                self.retries += s.retries;
                self.failed += s.failed;
            }
            Outcome::Unmatched => self.unmatched += 1,
            Outcome::Ambiguous => self.ambiguous += 1,
            Outcome::NotCovered => self.not_covered += 1,
        }
    }

    pub fn matched(&self) -> u32 {
        self.by_irp + self.by_orig + self.by_fallback
    }

    /// Everything tried, for "N of M".
    pub fn tried(&self) -> u32 {
        self.matched() + self.unmatched + self.ambiguous
    }

    pub fn merge(&mut self, o: &SplitTotals) {
        self.by_irp += o.by_irp;
        self.by_orig += o.by_orig;
        self.by_fallback += o.by_fallback;
        self.unmatched += o.unmatched;
        self.ambiguous += o.ambiguous;
        self.not_covered += o.not_covered;
        self.multi_piece += o.multi_piece;
        self.clipped += o.clipped;
        self.inside += o.inside;
        self.waiting += o.waiting;
        self.retried += o.retried;
        self.retries += o.retries;
        self.failed += o.failed;
    }
}

/// "1900 ms inside the drive, 40.00 ms waiting in Windows; retried 2 times" for the event log.
pub fn event_words(s: &Split) -> String {
    let mut out = format!("{} inside the drive, {} waiting in Windows", fmt_dur(s.inside), fmt_dur(s.waiting));
    if s.retries > 0 {
        out.push_str(&format!("; retried {} time{}", s.retries, plural(s.retries as u64)));
    }
    out
}

/// Above this share of the time inside the drive, the drive is what took it; below the mirror
/// image, Windows' queue did. Between the two both played a part. Rule of thumb.
const MOSTLY: f64 = 0.75;

/// The disk finding's line on where the slow time went, or `None` when nothing was matched.
/// `busy` is whether the traffic around the requests already made the drive "busy": then time
/// inside the drive includes waiting in the drive's own queue behind that traffic, which is said.
pub fn finding_sentence(t: &SplitTotals, busy: bool) -> Option<String> {
    let matched = t.matched();
    let total = t.inside + t.waiting;
    if matched == 0 || total <= 0 {
        return None;
    }
    let share = t.inside as f64 / total as f64;
    let of = if matched == t.tried() { format!("all {matched}") } else { format!("{matched} of {}", t.tried()) };
    let mut s = format!(
        "Where the time went ({of} slow requests the storage driver could follow): {} inside the drive, {} waiting in Windows \
         before reaching it.",
        fmt_dur(t.inside),
        fmt_dur(t.waiting)
    );
    if share >= MOSTLY {
        // Measured live: a hard drive kept seeking by two programs showed 95% of the slow time
        // "inside the drive". That is the drive working through its own queue, and blaming the
        // drive, cable or firmware for it sends people to the wrong fix.
        s.push_str(if busy {
            " Mostly inside the drive, working through the requests it had been handed: the traffic named above is the cause,              not the drive."
        } else {
            " Mostly inside the drive, with little else asked of it: the drive itself, its cable or its firmware was slow to answer."
        });
    } else if share <= 1.0 - MOSTLY {
        s.push_str(" Mostly waiting in Windows: more was asked of the drive at once than it could take, which points back at the programs using it.");
    } else {
        s.push_str(" Both played a part.");
    }
    Some(s)
}

/// The disk finding's line for a drive the port driver never reported on.
pub const NOT_MEASURED: &str = "How the slow time split between the drive and Windows was not measured for this drive: Windows' \
    storage driver trace reports nothing for it (USB drives using the older 'BOT' protocol and older controllers do not go \
    through it).";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::ticks_to_ms;

    fn ms(x: f64) -> i64 {
        ms_to_ticks(x)
    }

    /// A slow DiskIo request from `start_ms` for `dur_ms`, IRP 0x1000, disk 4, 256 KB.
    fn slow(start_ms: f64, dur_ms: f64) -> IoRec {
        IoRec {
            end: ms(start_ms + dur_ms),
            dur: ms(dur_ms),
            disk: 4,
            tid: 1,
            pid: 2,
            size: 262_144,
            op: b'R',
            file: 0,
            irp: 0x1000,
            offset: 0,
            irp_flags: 0,
        }
    }

    fn piece(start_ms: f64, end_ms: f64, irp: u64, orig: u64) -> ReqRec {
        ReqRec { ts: ms(end_ms), dur: ms(end_ms - start_ms), irp, orig, bytes: 262_144, srb: 0x01, cmd: 0x28, ..ReqRec::default() }
    }

    const USB: ScsiAddr = ScsiAddr { port: 6, bus: 0, target: 0, lun: 0 };

    fn close(a: i64, b_ms: f64) -> bool {
        (ticks_to_ms(a) - b_ms).abs() < 0.01
    }

    #[test]
    fn matched_by_irp_the_time_splits_into_drive_and_windows() {
        let s = slow(1000.0, 2000.0);
        let window = [piece(1040.0, 2995.0, 0x1000, 0), piece(1500.0, 1600.0, 0x2000, 0)];
        let Outcome::Split(sp) = correlate(&s, &window, None) else { panic!() };
        assert_eq!((sp.how, sp.pieces, sp.clipped), (How::Irp, 1, false));
        assert!(close(sp.inside, 1955.0) && close(sp.waiting, 45.0), "{sp:?}");
        assert_eq!(event_words(&sp), "1955 ms inside the drive, 45.00 ms waiting in Windows");
    }

    #[test]
    fn original_irp_matches_when_the_port_driver_has_its_own() {
        let s = slow(1000.0, 500.0);
        let Outcome::Split(sp) = correlate(&s, &[piece(1400.0, 1499.5, 0x7777, 0x1000)], None) else { panic!() };
        assert_eq!(sp.how, How::OriginalIrp);
        assert!(close(sp.inside, 99.5) && close(sp.waiting, 400.5));
    }

    /// A reused IRP address belongs to another request when it completed outside this one's life.
    #[test]
    fn a_reused_pointer_outside_the_requests_lifetime_is_not_it() {
        let s = slow(1000.0, 500.0);
        let window = [piece(900.0, 950.0, 0x1000, 0), piece(1600.0, 1700.0, 0x1000, 0)];
        assert_eq!(correlate(&s, &window, None), Outcome::Unmatched);
    }

    #[test]
    fn the_fallback_needs_one_candidate_on_the_same_drive_of_the_same_size() {
        let mut s = slow(1000.0, 500.0);
        s.irp = 0x5555; // matches nothing by pointer
        let on = |r: ReqRec, addr| ReqRec { addr, ..r };
        let one = [on(piece(1300.0, 1499.8, 1, 2), USB)];
        let Outcome::Split(sp) = correlate(&s, &one, Some(USB)) else { panic!() };
        assert_eq!(sp.how, How::Fallback);
        assert!(close(sp.inside, 199.8));
        assert_eq!(correlate(&s, &one, None), Outcome::Unmatched, "no address, no fallback");
        let other_drive = [on(piece(1300.0, 1499.8, 1, 2), ScsiAddr { port: 2, ..USB })];
        assert_eq!(correlate(&s, &other_drive, Some(USB)), Outcome::Unmatched);
        let other_size = [ReqRec { bytes: 4096, ..one[0] }];
        assert_eq!(correlate(&s, &other_size, Some(USB)), Outcome::Unmatched);
        let too_early = [on(piece(1300.0, 1480.0, 1, 2), USB)];
        assert_eq!(correlate(&s, &too_early, Some(USB)), Outcome::Unmatched, "completed 20 ms before: another request");
        let two = [one[0], on(piece(1350.0, 1500.2, 3, 4), USB)];
        assert_eq!(correlate(&s, &two, Some(USB)), Outcome::Ambiguous, "two fit: nothing is claimed");
    }

    /// One transfer in several pieces: back to back they add up, overlapping they are not
    /// counted twice, and the gap between them is Windows' time.
    #[test]
    fn several_pieces_count_as_the_union_of_their_times() {
        let s = slow(0.0, 1000.0);
        let serial = [piece(10.0, 300.0, 0x1000, 0), piece(300.0, 600.0, 0x9, 0x1000), piece(700.0, 990.0, 0xA, 0x1000)];
        let Outcome::Split(sp) = correlate(&s, &serial, None) else { panic!() };
        assert_eq!((sp.pieces, sp.how), (3, How::Irp));
        assert!(close(sp.inside, 880.0) && close(sp.waiting, 120.0), "{sp:?}");
        let parallel = [piece(100.0, 900.0, 0x1000, 0), piece(150.0, 850.0, 0x9, 0x1000)];
        let Outcome::Split(sp) = correlate(&s, &parallel, None) else { panic!() };
        assert!(close(sp.inside, 800.0), "overlap is not counted twice: {sp:?}");
    }

    #[test]
    fn the_split_never_goes_negative_and_says_when_it_clipped() {
        let s = slow(1000.0, 100.0);
        // A port-driver time longer than the whole request: clipped to it, and flagged.
        let Outcome::Split(sp) = correlate(&s, &[piece(500.0, 1100.0, 0x1000, 0)], None) else { panic!() };
        assert!(close(sp.inside, 100.0) && sp.waiting == 0 && sp.clipped, "{sp:?}");
        // A nonsense negative duration is clipped too.
        let neg = ReqRec { dur: -ms(50.0), ..piece(1000.0, 1050.0, 0x1000, 0) };
        let sp = split_of(&s, &[neg], How::Irp);
        assert!(sp.inside == 0 && close(sp.waiting, 100.0) && sp.clipped, "{sp:?}");
        assert_eq!(union_len(vec![(5, 3), (1, 2), (0, 4)]), 4);
    }

    #[test]
    fn retries_and_failures_add_up_per_request_and_per_disk() {
        let s = slow(0.0, 1000.0);
        let window = [
            ReqRec { retries: 2, ..piece(10.0, 500.0, 0x1000, 0) },
            ReqRec { retries: 1, srb: 0x04, scsi: 0x02, ..piece(500.0, 990.0, 0x9, 0x1000) },
        ];
        let o = correlate(&s, &window, None);
        let Outcome::Split(sp) = o else { panic!() };
        assert_eq!((sp.retries, sp.failed), (3, 1));
        assert!(event_words(&sp).ends_with("; retried 3 times"), "{}", event_words(&sp));
        let mut t = SplitTotals::default();
        t.add(&o);
        t.add(&Outcome::Unmatched);
        t.add(&Outcome::NotCovered);
        t.add(&Outcome::Split(Split { how: How::Fallback, pieces: 1, inside: 5, waiting: 5, clipped: false, retries: 0, failed: 0 }));
        assert_eq!((t.by_irp, t.by_fallback, t.unmatched, t.not_covered, t.multi_piece), (1, 1, 1, 1, 1));
        assert_eq!((t.retried, t.retries, t.failed, t.matched(), t.tried()), (1, 3, 1, 2, 3));
        let mut sum = SplitTotals::default();
        sum.merge(&t);
        sum.merge(&t);
        assert_eq!((sum.matched(), sum.retries, sum.inside), (4, 6, 2 * t.inside));
    }

    #[test]
    fn the_finding_says_which_side_the_time_was_on_in_plain_words() {
        let t = |inside, waiting, irp, unmatched| SplitTotals {
            inside: ms(inside),
            waiting: ms(waiting),
            by_irp: irp,
            unmatched,
            ..SplitTotals::default()
        };
        let drive = finding_sentence(&t(19_000.0, 400.0, 14, 2), false).unwrap();
        assert!(
            drive.contains("14 of 16 slow requests") && drive.contains("with little else asked of it: the drive itself, its cable"),
            "{drive}"
        );
        assert!(finding_sentence(&t(19_000.0, 400.0, 14, 0), true).unwrap().contains("all 14"));
        let busy = finding_sentence(&t(19_000.0, 400.0, 14, 0), true).unwrap();
        assert!(busy.contains("the traffic named above is the cause") && !busy.contains("cable"), "{busy}");
        let queue = finding_sentence(&t(300.0, 9_000.0, 5, 0), false).unwrap();
        assert!(queue.contains("Mostly waiting in Windows") && queue.contains("programs using it"), "{queue}");
        assert!(finding_sentence(&t(500.0, 500.0, 5, 0), false).unwrap().ends_with("Both played a part."));
        assert!(finding_sentence(&t(0.0, 0.0, 0, 9), false).is_none(), "nothing matched says nothing");
        // The audience rule: nothing here tells anyone to close or stop anything.
        for s in [drive, queue, NOT_MEASURED.to_string()] {
            let l = s.to_lowercase();
            for bad in ["close", "end task", "uninstall", "pause", "stop"] {
                assert!(!l.contains(bad), "{bad}: {s}");
            }
        }
    }
}
