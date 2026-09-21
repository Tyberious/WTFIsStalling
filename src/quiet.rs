//! Keeps the live event log readable when one thing keeps going wrong. A long download to a hard
//! drive can produce a slow write every few milliseconds for an hour; hundreds of near-identical
//! lines bury everything else and tell the reader nothing the first three did not. So per subject
//! (one disk, one driver, one program) the first few events are shown in full, then they are
//! folded into one roll-up line every so often. An event far worse than anything shown for that
//! subject still gets its own line: outliers are the point of an event log.
//!
//! Nothing is lost to the analysis: every event is still counted and explained in the summary.

use std::collections::HashMap;

/// Events shown in full per subject before folding starts.
const SHOW_FIRST: u32 = 3;
/// At most one roll-up line per subject this often (ms).
const ROLLUP_EVERY_MS: f64 = 30_000.0;
/// A held event is shown in full after all when it is this many times worse than the worst one
/// already shown for its subject.
const OUTLIER_FACTOR: i64 = 3;

/// What was folded away for one subject since its last roll-up.
#[derive(Clone, Debug, PartialEq)]
pub struct Rollup {
    pub subject: String,
    pub count: u32,
    /// Duration of the worst folded event (ticks) and the note that came with it.
    pub worst: i64,
    pub note: String,
    /// When the first folded event of this roll-up happened (ticks).
    pub since: i64,
}

#[derive(Default)]
struct Subject {
    shown: u32,
    worst_shown: i64,
    held: Option<Rollup>,
    last_rollup: i64,
}

#[derive(Default)]
pub struct Quieter {
    subjects: HashMap<String, Subject>,
}

impl Quieter {
    /// Should this event get a line of its own? If not it is folded into the subject's roll-up.
    /// `note` is whatever would help explain the worst folded event ("disk busy: 80 MB/s, mostly
    /// steam.exe", a routine name); `now` and `duration` are in ticks.
    pub fn offer(&mut self, subject: &str, duration: i64, note: &str, now: i64) -> bool {
        let s = self.subjects.entry(subject.to_string()).or_default();
        let outlier = s.shown >= SHOW_FIRST && duration >= s.worst_shown.saturating_mul(OUTLIER_FACTOR);
        if s.shown < SHOW_FIRST || outlier {
            if s.shown == 0 {
                s.last_rollup = now; // the first roll-up is due one period after the subject appears
            }
            s.shown += 1;
            s.worst_shown = s.worst_shown.max(duration);
            return true;
        }
        let held =
            s.held.get_or_insert_with(|| Rollup { subject: subject.to_string(), count: 0, worst: 0, note: String::new(), since: now });
        held.count += 1;
        if duration > held.worst {
            held.worst = duration;
            held.note = note.to_string();
        }
        false
    }

    /// Roll-ups that are due. `every` is the roll-up period in ticks.
    pub fn due(&mut self, now: i64, every: i64) -> Vec<Rollup> {
        let mut out = Vec::new();
        for s in self.subjects.values_mut() {
            if s.held.is_some() && now - s.last_rollup >= every {
                s.last_rollup = now;
                out.extend(s.held.take());
            }
        }
        out.sort_by(|a, b| a.since.cmp(&b.since).then_with(|| a.subject.cmp(&b.subject)));
        out
    }

    /// Everything still held, for the end of the run.
    pub fn flush(&mut self) -> Vec<Rollup> {
        self.due(i64::MAX, 0)
    }

    pub fn rollup_period_ms() -> f64 {
        ROLLUP_EVERY_MS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EVERY: i64 = 30_000;

    #[test]
    fn the_first_few_are_shown_then_the_rest_are_folded_into_one_line() {
        let mut q = Quieter::default();
        let shown: Vec<bool> = (0..500).map(|i| q.offer("disk 4", 250 + (i % 7), "disk busy", i * 10)).collect();
        assert_eq!(shown.iter().filter(|s| **s).count(), 3, "three lines, not five hundred");
        assert!(shown[..3].iter().all(|s| *s));
        assert!(q.due(10_000, EVERY).is_empty(), "not due yet");
        let r = q.due(30_000, EVERY);
        assert_eq!(r.len(), 1);
        assert_eq!((r[0].subject.as_str(), r[0].count, r[0].worst, r[0].note.as_str()), ("disk 4", 497, 256, "disk busy"));
        assert!(q.due(31_000, EVERY).is_empty(), "nothing new held since");
    }

    #[test]
    fn an_event_far_worse_than_anything_shown_still_gets_its_own_line() {
        let mut q = Quieter::default();
        for i in 0..10 {
            q.offer("disk 4", 200, "", i);
        }
        assert!(!q.offer("disk 4", 500, "", 20), "2.5x is more of the same");
        assert!(q.offer("disk 4", 900, "", 21), "4.5x the worst shown is news");
        assert!(!q.offer("disk 4", 900, "", 22), "and now 900 is the bar");
    }

    #[test]
    fn subjects_are_independent_and_the_end_of_the_run_flushes_what_is_left() {
        let mut q = Quieter::default();
        for i in 0..6 {
            q.offer("disk 4", 200, "a", i);
            q.offer("driver x.sys", 50, "b", i);
        }
        assert!(q.offer("disk 1", 200, "", 7), "a new subject starts with full lines again");
        let left = q.flush();
        assert_eq!(left.iter().map(|r| (r.subject.as_str(), r.count)).collect::<Vec<_>>(), [("disk 4", 3), ("driver x.sys", 3)]);
        assert!(q.flush().is_empty());
    }
}
