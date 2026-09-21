//! Two checks on interrupt activity that the verdicts are not allowed to skip.
//!
//! 1. **Were the CPUs actually held?** A DPC runs at DISPATCH_LEVEL and cannot preempt code that
//!    is already at DISPATCH_LEVEL or above on the same processor, so ordinary DPCs executing
//!    right through a stall are direct evidence that the processor was NOT held at raised IRQL
//!    (learn.microsoft.com/windows-hardware/drivers/kernel/managing-hardware-priorities and
//!    .../introduction-to-dpc-objects). Counting them is not enough - a driver could be held for
//!    900 ms and then drain a queue of DPCs in 2 ms - so the stall is cut into slices and what
//!    matters is in how many of them a DPC ran.
//!
//! 2. **Which interrupt sources kept going?** For each driver routine with a STEADY rate before
//!    the stall, its rate inside the stall as a share of that. "The USB controller's interrupts
//!    stopped for 0.9 s while the graphics card's kept coming" is the closest a CPU-side trace
//!    gets to seeing a bus or a controller stall, and in the field logs behind issue #15 it is
//!    the only thing that separates one freeze from another.
//!
//! Both are pure arithmetic on counts so they can be tested without a live system.

/// A stall is cut into this many slices for the "did DPCs keep running" check.
pub const SLICES: usize = 10;
/// ...and DPCs must have run in at least this share of them.
const SLICE_SHARE: f64 = 0.6;
/// Below this many DPCs the slice count is noise, whatever share it works out to.
const MIN_DPCS: usize = 10;

/// In how many of `SLICES` equal slices of `[start, end]` did at least one of `starts` fall?
pub fn slices_covered(start: i64, end: i64, starts: impl IntoIterator<Item = i64>) -> usize {
    let len = (end - start).max(1);
    let mut hit = [false; SLICES];
    for t in starts {
        if t >= start && t <= end {
            let slot = (((t - start) as i128 * SLICES as i128) / len as i128) as usize;
            hit[slot.min(SLICES - 1)] = true;
        }
    }
    hit.iter().filter(|h| **h).count()
}

/// Did ordinary DPCs keep running right through the stall on this CPU? When they did, nothing may
/// claim that the CPU was held at raised IRQL, or that Windows was frozen out of it.
pub fn dpcs_kept_running(covered_slices: usize, total_dpcs: usize) -> bool {
    total_dpcs >= MIN_DPCS && covered_slices as f64 >= SLICES as f64 * SLICE_SHARE
}

/// What one interrupt source did before the stall, as counted from the ring buffer.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Reference {
    pub events: u32,
    /// One-second slices of the reference window in which this source fired at all...
    pub slices_seen: u32,
    /// ...out of this many.
    pub slices: u32,
    pub seconds: f64,
}

/// A source has to fire this often, and this evenly, before its silence means anything: a
/// source that naturally comes in bursts is quiet for most windows and would cry wolf.
const MIN_REF_EVENTS: u32 = 50;
const MIN_STEADY_SHARE: f64 = 0.8;
/// ...and enough of it has to fall inside the stall for a ratio to mean anything.
const MIN_EXPECTED: f64 = 10.0;

impl Reference {
    pub fn steady(&self) -> bool {
        self.slices >= 2
            && self.events >= MIN_REF_EVENTS
            && self.seconds > 0.0
            && f64::from(self.slices_seen) >= f64::from(self.slices) * MIN_STEADY_SHARE
    }

    pub fn per_s(&self) -> f64 {
        if self.seconds > 0.0 {
            f64::from(self.events) / self.seconds
        } else {
            0.0
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flow {
    /// Stopped almost completely.
    Silent,
    /// Well down, but not gone.
    Reduced,
    /// Carried on much as before.
    Continued,
}

/// The stall's share of this source's usual rate, and what to call it. `None` when the source was
/// not steady enough before the stall, or when too little of it was due inside the stall, for the
/// comparison to say anything.
pub fn flow(reference: &Reference, in_stall: u32, stall_s: f64) -> Option<(Flow, f64)> {
    if !reference.steady() || stall_s <= 0.0 {
        return None;
    }
    let expected = reference.per_s() * stall_s;
    if expected < MIN_EXPECTED {
        return None;
    }
    let share = f64::from(in_stall) / expected;
    let what = if share < 0.10 {
        Flow::Silent
    } else if share < 0.50 {
        Flow::Reduced
    } else {
        Flow::Continued
    };
    Some((what, share))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dpcs_spread_through_a_stall_are_told_from_a_burst_at_one_end() {
        // 479 DPCs spread evenly through a 924 ms freeze: the CPUs were never held.
        let spread: Vec<i64> = (0..479).map(|i| i * 924_000 / 479).collect();
        let covered = slices_covered(0, 924_000, spread);
        assert_eq!(covered, SLICES);
        assert!(dpcs_kept_running(covered, 479));

        // The same 479 DPCs draining in the last 2 ms, as a released queue would: not running.
        let burst: Vec<i64> = (0..479).map(|i| 922_000 + i * 4).collect();
        let covered = slices_covered(0, 924_000, burst);
        assert_eq!(covered, 1);
        assert!(!dpcs_kept_running(covered, 479));

        // A 6 ms stall with the two DPCs the field log shows: far too few to conclude anything,
        // so the driver verdict that rests on the samples is left alone.
        assert!(!dpcs_kept_running(slices_covered(0, 6_440, [1_000i64, 5_000]), 2));
        assert_eq!(slices_covered(0, 0, [0i64]), 1, "a zero-length window must not divide by zero");
        assert_eq!(slices_covered(100, 200, [50i64, 250]), 0, "events outside the window do not count");
    }

    #[test]
    fn a_source_that_went_silent_is_told_from_one_that_was_already_quiet_or_bursty() {
        // 1900/s for 5 s, firing in every slice: steady. 2 events in a 900 ms freeze is silence.
        let usb = Reference { events: 9500, slices_seen: 5, slices: 5, seconds: 5.0 };
        assert_eq!(flow(&usb, 2, 0.9).map(|f| f.0), Some(Flow::Silent));
        // Half its usual rate is "continued": the controller was answering.
        assert_eq!(flow(&usb, 900, 0.9).map(|f| f.0), Some(Flow::Continued));
        assert_eq!(flow(&usb, 400, 0.9).map(|f| f.0), Some(Flow::Reduced));

        // A source that only fires in one second out of five is bursty: no alarm either way.
        let bursty = Reference { events: 9500, slices_seen: 1, slices: 5, seconds: 5.0 };
        assert_eq!(flow(&bursty, 0, 0.9), None);
        // A source that was barely there to begin with says nothing by stopping.
        let quiet = Reference { events: 20, slices_seen: 5, slices: 5, seconds: 5.0 };
        assert_eq!(flow(&quiet, 0, 0.9), None);
        // Steady and busy, but the stall is too short for the comparison to mean anything:
        // 1900/s x 2 ms is 3.8 expected events, and seeing none of them is luck, not evidence.
        assert_eq!(flow(&usb, 0, 0.002), None);
        assert_eq!(flow(&Reference::default(), 0, 1.0), None);
    }
}
