//! Detects events that recur on a timer. "It hitches every ten seconds" almost always means
//! something is polling: RGB and monitoring utilities, battery/EC checks, scheduled scans.

pub struct Period {
    pub seconds: f64,
    /// Intervals that matched the period (or exactly one missed beat), out of `intervals`.
    pub regular: usize,
    pub intervals: usize,
}

impl Period {
    pub fn describe(&self) -> String {
        format!(
            "Repeats about every {:.1} s ({} of {} intervals), the signature of something polling on a timer.",
            self.seconds, self.regular, self.intervals
        )
    }
}

const MIN_EVENTS: usize = 5;
const MIN_PERIOD_S: f64 = 1.0;
/// Events closer together than this are one burst, not separate beats.
const BURST_S: f64 = 0.25;
const TOLERANCE: f64 = 0.12;
const MIN_REGULAR_SHARE: f64 = 0.7;

/// `times` are event times in seconds, in any order.
pub fn detect(times: &[f64]) -> Option<Period> {
    let mut sorted = times.to_vec();
    sorted.sort_by(f64::total_cmp);
    let mut beats: Vec<f64> = Vec::new();
    for t in sorted {
        if beats.last().is_none_or(|last| t - last > BURST_S) {
            beats.push(t);
        }
    }
    if beats.len() < MIN_EVENTS {
        return None;
    }
    let mut gaps: Vec<f64> = beats.windows(2).map(|w| w[1] - w[0]).collect();
    let intervals = gaps.len();
    gaps.sort_by(f64::total_cmp);
    let median = gaps[intervals / 2];
    if median < MIN_PERIOD_S {
        return None;
    }
    let near = |gap: f64, target: f64| (gap - target).abs() <= target * TOLERANCE;
    // A single missed beat (gap of two periods) still counts as keeping time.
    let regular = gaps.iter().filter(|g| near(**g, median) || near(**g, 2.0 * median)).count();
    (regular as f64 >= intervals as f64 * MIN_REGULAR_SHARE).then_some(Period { seconds: median, regular, intervals })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn steady_timer_with_jitter_and_a_missed_beat_is_periodic() {
        let times = [0.0, 10.1, 19.9, 30.0, 50.2, 60.0, 70.1]; // beat at 40 s missing
        let p = detect(&times).expect("periodic");
        assert!((p.seconds - 10.0).abs() < 0.3, "period {}", p.seconds);
        assert_eq!((p.regular, p.intervals), (6, 6));
    }

    #[test]
    fn bursts_collapse_into_single_beats() {
        let times = [0.0, 0.01, 0.02, 5.0, 5.01, 10.0, 15.0, 15.02, 20.0];
        assert!((detect(&times).expect("periodic").seconds - 5.0).abs() < 0.1);
    }

    #[test]
    fn irregular_or_sparse_events_are_not_periodic() {
        assert!(detect(&[0.0, 3.0, 4.5, 11.0, 12.2, 30.0, 31.0]).is_none());
        assert!(detect(&[0.0, 10.0, 20.0]).is_none(), "too few events to call it a pattern");
        assert!(detect(&[0.0, 0.3, 0.6, 0.9, 1.2, 1.5]).is_none(), "sub-second repetition is a storm, not a timer");
    }
}
