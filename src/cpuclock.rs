//! Once-a-second view of how fast the busy CPU cores are actually running, to catch thermal
//! and power throttling: it feels exactly like stalling, and no kernel trace event shows it.
//!
//! Uses the "Processor Information" performance counters. Only cores that are doing work are
//! judged: an idle core clocking down is normal, a busy core at half speed is not.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::pdh;
use crate::util::qpc;

/// A core counts as busy at this load (%), and as slow below this share of its rated speed (%).
const BUSY_LOAD: f64 = 50.0;
const SLOW_PERF: f64 = 70.0;

#[derive(Clone, Copy, Debug)]
pub struct ClockSample {
    pub ts: i64,
    pub busy_cores: u32,
    /// Busy cores running below SLOW_PERF % of rated speed.
    pub slow_cores: u32,
    /// Slowest busy core, % of rated speed; above 100 when boosting (100 when no core is busy).
    pub min_busy_perf: f64,
    /// Lowest OS-imposed performance cap across cores, % (100 = none).
    pub limit: f64,
}

impl ClockSample {
    /// Busy cores were held back: either Windows reports a cap, or at least half of the
    /// cores doing work are running well under their rated speed.
    pub fn throttled(&self) -> bool {
        self.limit < 99.5 || (self.busy_cores > 0 && self.slow_cores * 2 >= self.busy_cores)
    }
}

/// A stall counts as happening "while throttled" when a throttled sample was taken this close to
/// it. The clock is sampled once a second, so this is one sample either side with some slack.
pub const NEAR_MS: f64 = 1500.0;

/// What the clock samples around `[start, end]` say, as one short clause for the event log, or
/// `None` when no sample that close was throttled. Facts only: throttling at the same moment is
/// not a cause of the stall.
pub fn throttled_clause(samples: &[ClockSample], start: i64, end: i64) -> Option<String> {
    let near = crate::util::ms_to_ticks(NEAR_MS);
    let hits: Vec<&ClockSample> = samples.iter().filter(|c| c.ts >= start - near && c.ts <= end + near && c.throttled()).collect();
    if hits.is_empty() {
        return None;
    }
    let busy: Vec<f64> = hits.iter().filter(|c| c.busy_cores > 0).map(|c| c.min_busy_perf).collect();
    let cap = hits.iter().map(|c| c.limit).fold(100.0, f64::min);
    let mut clause = "the processor was being slowed down at the time".to_string();
    if !busy.is_empty() {
        let slowest = busy.iter().copied().fold(f64::MAX, f64::min);
        clause.push_str(&format!(" (busy cores at as little as {slowest:.0}% of rated speed"));
        clause.push_str(&if cap < 99.5 { format!(", Windows capping it at {cap:.0}%)") } else { ")".to_string() });
    } else if cap < 99.5 {
        clause.push_str(&format!(" (Windows capping it at {cap:.0}%)"));
    }
    Some(clause)
}

pub type Samples = Arc<Mutex<Vec<ClockSample>>>;

struct Counters {
    query: pdh::Query,
    perf: pdh::Counter,
    load: pdh::Counter,
    limit: pdh::Counter,
}

impl Counters {
    fn open() -> Option<Counters> {
        let query = pdh::Query::open()?;
        let add = |name: &str| query.add(&format!("\\Processor Information(*)\\{name}"));
        match (add("% Processor Performance"), add("% Processor Time"), add("% Performance Limit")) {
            (Some(perf), Some(load), Some(limit)) => {
                query.collect(); // rate counters need a first reading to diff against
                Some(Counters { query, perf, load, limit })
            }
            _ => None,
        }
    }

    /// Per-core values, keyed by instance name ("0,3"); the "_Total" rows are dropped.
    fn read(counter: &pdh::Counter) -> HashMap<String, f64> {
        counter.read().into_iter().filter(|(name, _)| !name.contains("_Total")).collect()
    }

    fn sample(&self) -> Option<ClockSample> {
        if !self.query.collect() {
            return None;
        }
        let (perf, load, limit) = (Self::read(&self.perf), Self::read(&self.load), Self::read(&self.limit));
        if perf.is_empty() {
            return None;
        }
        let busy: Vec<f64> = perf.iter().filter(|(core, _)| load.get(*core).is_some_and(|l| *l >= BUSY_LOAD)).map(|(_, p)| *p).collect();
        Some(ClockSample {
            ts: qpc(),
            busy_cores: busy.len() as u32,
            slow_cores: busy.iter().filter(|p| **p < SLOW_PERF).count() as u32,
            min_busy_perf: busy.iter().copied().reduce(f64::min).unwrap_or(100.0),
            limit: limit.values().copied().fold(100.0, f64::min),
        })
    }
}

/// Samples until `stop` is set. If the counters are unavailable the list simply stays empty.
pub fn spawn(stop: Arc<AtomicBool>) -> Samples {
    let samples: Samples = Arc::default();
    let out = samples.clone();
    let _ = std::thread::Builder::new().name("cpu-clock".into()).spawn(move || {
        let Some(counters) = Counters::open() else { return };
        while !stop.load(Ordering::Relaxed) {
            std::thread::sleep(Duration::from_millis(1000));
            if let Some(s) = counters.sample() {
                out.lock().unwrap().push(s);
            }
        }
    });
    samples
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn throttling_needs_a_cap_or_slow_busy_cores() {
        let s = |busy_cores, slow_cores, limit| ClockSample { ts: 0, busy_cores, slow_cores, min_busy_perf: 50.0, limit };
        assert!(!s(0, 0, 100.0).throttled(), "an idle machine clocking down is normal");
        assert!(!s(4, 1, 100.0).throttled());
        assert!(s(4, 2, 100.0).throttled());
        assert!(s(0, 0, 80.0).throttled(), "an explicit OS performance cap always counts");
    }

    /// Per incident: said only when a sample that close to the stall was throttled, with the
    /// numbers the sample carries.
    #[test]
    fn a_stall_says_it_was_throttled_only_when_a_nearby_sample_was() {
        let ms = crate::util::ms_to_ticks;
        let s = |ts, busy_cores, slow_cores, min_busy_perf, limit| ClockSample { ts, busy_cores, slow_cores, min_busy_perf, limit };
        let (start, end) = (ms(10_000.0), ms(10_900.0));
        let far = [s(ms(5_000.0), 4, 4, 40.0, 100.0), s(ms(10_500.0), 4, 0, 110.0, 100.0)];
        assert_eq!(throttled_clause(&far, start, end), None, "throttled, but four seconds earlier");
        let near = [s(ms(9_000.0), 4, 3, 45.0, 100.0)];
        assert_eq!(
            throttled_clause(&near, start, end).as_deref(),
            Some("the processor was being slowed down at the time (busy cores at as little as 45% of rated speed)")
        );
        let capped = [s(ms(12_000.0), 0, 0, 100.0, 80.0)];
        assert_eq!(
            throttled_clause(&capped, start, end).as_deref(),
            Some("the processor was being slowed down at the time (Windows capping it at 80%)")
        );
        assert_eq!(throttled_clause(&[], start, end), None);
    }

    /// The counters exist on every supported Windows; tolerate their absence (containers).
    #[test]
    fn live_counters_report_plausible_values() {
        let Some(counters) = Counters::open() else { return };
        std::thread::sleep(Duration::from_millis(300));
        if let Some(sample) = counters.sample() {
            println!("{sample:?}");
            assert!(sample.busy_cores >= sample.slow_cores);
            assert!((0.0..=100.0).contains(&sample.limit));
            assert!(sample.min_busy_perf > 0.0);
        }
    }
}
