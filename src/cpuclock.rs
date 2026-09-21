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
