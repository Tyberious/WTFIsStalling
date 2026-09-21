//! Educated guesses at WHY a disk request was slow, from nothing but the completed requests
//! around it. A completion carries its duration, so its start is known too; what else the disk
//! finished while the slow request was outstanding separates "the disk was flat out" from
//! "the disk had nothing else to do and still took that long".

use std::collections::HashMap;

use crate::state::IoRec;
use crate::util::{ms_to_ticks, ticks_to_ms};

/// A disk quiet for this long may have powered down (HDD spin-down, USB suspend, NVMe deep idle).
const SLEEP_GAP_MS: f64 = 5000.0;
/// ...and a request that then takes at least this long looks like a wake-up.
const WAKE_MIN_MS: f64 = 400.0;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Cause {
    /// The disk was moving a lot of data for someone at the time.
    Busy,
    /// First request after a long silence: the drive was asleep.
    WokeUp,
    /// A program forced cached writes out (FlushFileBuffers) and the drive took its time.
    Flush,
    /// Nearly idle and still slow: the drive, its cable or its firmware.
    IdleSlow,
}

/// What the disk was doing while one slow request was outstanding.
#[derive(Clone, Debug, PartialEq)]
pub struct Context {
    pub cause: Cause,
    /// Other requests the disk completed during the slow one.
    pub others: u32,
    pub mb_per_s: f64,
    /// How long the disk had been silent before the slow request was issued.
    pub idle_before_ms: Option<f64>,
    /// (pid, tid of one request, bytes) moved during the slow request, biggest first.
    pub movers: Vec<(u32, u32, u64)>,
}

/// How much traffic it takes before "the drive was busy" explains a slow request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DriveClass {
    Spinning,
    /// SATA and USB flash: one queue, a few hundred MB/s at best.
    Flash,
    Nvme,
}

impl DriveClass {
    /// (MB per second, requests per second) at which the drive counts as busy. Rules of thumb,
    /// not specifications, set an order of magnitude under what each class sustains: a hard drive
    /// manages roughly 100-200 random requests a second, a SATA SSD is capped near 550 MB/s by
    /// the link, and an NVMe drive moves gigabytes a second. The old single flash threshold
    /// called an NVMe drive "busy" at 33 MB/s (field report, issue #15), about 1% of what it can
    /// do, which hid that the drive was slow with next to nothing asked of it.
    fn busy_at(self) -> (f64, f64) {
        match self {
            DriveClass::Spinning => (10.0, 50.0),
            DriveClass::Flash => (30.0, 300.0),
            DriveClass::Nvme => (200.0, 3000.0),
        }
    }
}

/// `ios` is the recent history (any disk, any order); `history_start` is the oldest moment that
/// history can vouch for, so silence is never assumed for a time nobody was watching.
pub fn explain(slow: &IoRec, ios: &[IoRec], class: DriveClass, history_start: i64) -> Context {
    let start = slow.end - slow.dur;
    let mut others = 0u32;
    let mut bytes = 0u64;
    let mut by_pid: HashMap<u32, (u32, u64)> = HashMap::new();
    let mut last_before: Option<i64> = None;
    let mut in_flight_at_start = 0u32;
    for io in ios.iter().filter(|io| io.disk == slow.disk) {
        let same = io.end == slow.end && io.dur == slow.dur && io.tid == slow.tid && io.size == slow.size;
        if same {
            continue;
        }
        let io_start = io.end - io.dur;
        if io.end > start && io.end <= slow.end {
            others += 1;
            bytes += io.size as u64;
            let e = by_pid.entry(io.pid).or_insert((io.tid, 0));
            e.1 += io.size as u64;
        }
        if io.end <= start {
            last_before = Some(last_before.map_or(io.end, |l| l.max(io.end)));
        }
        if io_start < start && io.end > start {
            in_flight_at_start += 1;
        }
    }
    let secs = (ticks_to_ms(slow.dur) / 1000.0).max(0.001);
    let mb_per_s = bytes as f64 / 1e6 / secs;
    let per_s = others as f64 / secs;
    // A hard drive is saturated by a fraction of what an SSD shrugs off.
    let (busy_mb, busy_per_s) = class.busy_at();
    let fast = mb_per_s >= busy_mb || per_s >= busy_per_s;
    // Rates over a few milliseconds mean little: one neighboring request is not a busy disk.
    let busy = fast && (bytes >= 4_000_000 || others >= 32);

    let quiet_since = last_before.unwrap_or(history_start).max(history_start);
    let idle_before_ms = (in_flight_at_start == 0 && start > quiet_since).then(|| ticks_to_ms(start - quiet_since));
    let woke = idle_before_ms.is_some_and(|g| g >= SLEEP_GAP_MS) && slow.dur >= ms_to_ticks(WAKE_MIN_MS);

    // A sleeping drive completes nothing until it is awake, so real traffic rules a wake-up out.
    let cause = if busy {
        Cause::Busy
    } else if woke {
        Cause::WokeUp
    } else if slow.op == b'F' {
        Cause::Flush
    } else {
        Cause::IdleSlow
    };
    let mut movers: Vec<(u32, u32, u64)> = by_pid.into_iter().map(|(pid, (tid, b))| (pid, tid, b)).collect();
    movers.sort_by_key(|m| std::cmp::Reverse(m.2));
    Context { cause, others, mb_per_s, idle_before_ms, movers }
}

/// Everything learned about one disk's slow requests over a run.
#[derive(Clone, Debug, Default)]
pub struct DiskWhy {
    pub causes: HashMap<Cause, u32>,
    /// Process label -> bytes it moved while slow requests were outstanding on a busy disk.
    pub movers: HashMap<String, u64>,
    pub longest_sleep_ms: f64,
}

impl DiskWhy {
    pub fn count(&self, c: Cause) -> u32 {
        self.causes.get(&c).copied().unwrap_or(0)
    }

    pub fn total(&self) -> u32 {
        self.causes.values().sum()
    }

    /// The cause behind most slow requests, if any were explained.
    pub fn main_cause(&self) -> Option<Cause> {
        // Fixed order so ties resolve the same way every run. `max_by_key` keeps the LAST of equal
        // maxima, so the drive-side causes go last: they are the ones worth acting on.
        [Cause::Flush, Cause::Busy, Cause::WokeUp, Cause::IdleSlow]
            .into_iter()
            .filter(|c| self.count(*c) > 0)
            .max_by_key(|c| self.count(*c))
    }

    /// Biggest data movers, with their share of the bytes.
    pub fn top_movers(&self, n: usize) -> Vec<(String, u64, f64)> {
        let total: u64 = self.movers.values().sum();
        let mut v: Vec<_> = self.movers.iter().map(|(k, b)| (k.clone(), *b, *b as f64 / total.max(1) as f64)).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        v.truncate(n);
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::procs::known_worker;

    fn io(disk: u32, start_ms: f64, dur_ms: f64, size: u32, pid: u32, op: u8) -> IoRec {
        let dur = ms_to_ticks(dur_ms);
        IoRec { end: ms_to_ticks(10_000.0 + start_ms) + dur, dur, disk, tid: pid * 10, pid, size, op, file: 0 }
    }

    /// Monitoring began just before the requests the tests issue, unless a test says otherwise.
    const T0: i64 = 0;
    fn recent() -> i64 {
        ms_to_ticks(10_000.0 + 500.0)
    }

    #[test]
    fn heavy_traffic_from_one_program_means_busy_and_names_it() {
        let slow = io(2, 1000.0, 500.0, 4096, 7, b'R');
        let mut ios = vec![slow];
        // 100 x 1 MB finished by pid 42 during the slow request = 200 MB/s.
        ios.extend((0..100).map(|i| io(2, 1000.0 + i as f64 * 5.0, 4.0, 1_000_000, 42, b'W')));
        ios.push(io(2, 1100.0, 3.0, 8192, 9, b'R'));
        ios.push(io(5, 1100.0, 3.0, 900_000_000, 99, b'W')); // another disk: irrelevant
        let c = explain(&slow, &ios, DriveClass::Flash, T0);
        assert_eq!(c.cause, Cause::Busy);
        assert_eq!(c.others, 101);
        assert!((c.mb_per_s - 200.0).abs() < 1.0, "{}", c.mb_per_s);
        assert_eq!(c.movers[0].0, 42);
    }

    #[test]
    fn first_request_after_long_silence_is_a_wake_up() {
        let slow = io(4, 9000.0, 3200.0, 4096, 7, b'R');
        let ios = vec![io(4, 100.0, 5.0, 4096, 7, b'R'), slow];
        let c = explain(&slow, &ios, DriveClass::Spinning, T0);
        assert_eq!(c.cause, Cause::WokeUp);
        assert!(c.idle_before_ms.unwrap() > 8000.0);
    }

    #[test]
    fn silence_is_not_assumed_before_the_history_began() {
        // Nothing earlier in the ring, but monitoring started only 1 s before the request.
        let slow = io(4, 9000.0, 3200.0, 4096, 7, b'R');
        let c = explain(&slow, &[slow], DriveClass::Spinning, ms_to_ticks(10_000.0 + 8000.0));
        assert_eq!(c.cause, Cause::IdleSlow);
    }

    #[test]
    fn quiet_disk_that_is_still_slow_points_at_the_drive() {
        let slow = io(1, 1000.0, 800.0, 65536, 7, b'R');
        let ios = vec![io(1, 900.0, 2.0, 4096, 7, b'R'), slow, io(1, 1200.0, 1.0, 4096, 8, b'R')];
        assert_eq!(explain(&slow, &ios, DriveClass::Flash, T0).cause, Cause::IdleSlow);
        let flush = io(1, 1000.0, 800.0, 0, 7, b'F');
        assert_eq!(explain(&flush, &[flush], DriveClass::Flash, recent()).cause, Cause::Flush);
    }

    #[test]
    fn a_hard_drive_counts_as_busy_much_sooner_than_an_ssd() {
        let slow = io(3, 1000.0, 1000.0, 4096, 7, b'R');
        let mut ios = vec![slow];
        ios.extend((0..15).map(|i| io(3, 1000.0 + i as f64 * 60.0, 50.0, 1_000_000, 42, b'R'))); // 15 MB/s
        assert_eq!(explain(&slow, &ios, DriveClass::Spinning, T0).cause, Cause::Busy);
        assert_eq!(explain(&slow, &ios, DriveClass::Flash, recent()).cause, Cause::IdleSlow);
    }

    /// The field report in issue #15: an NVMe drive took most of a second with 33 MB/s going
    /// through it and was called "busy", which blamed the programs instead of the drive.
    #[test]
    fn thirty_megabytes_a_second_does_not_make_an_nvme_drive_busy() {
        let slow = io(6, 1000.0, 1000.0, 4096, 7, b'W');
        let mut ios = vec![slow];
        ios.extend((0..33).map(|i| io(6, 1000.0 + i as f64 * 30.0, 5.0, 1_000_000, 42, b'W'))); // 33 MB/s
        assert_eq!(explain(&slow, &ios, DriveClass::Flash, T0).cause, Cause::Busy);
        assert_eq!(explain(&slow, &ios, DriveClass::Nvme, recent()).cause, Cause::IdleSlow);
    }

    #[test]
    fn one_neighbor_during_a_short_request_is_not_a_busy_disk() {
        let slow = io(0, 1000.0, 16.0, 16384, 7, b'R');
        let ios = vec![io(0, 990.0, 1.0, 4096, 7, b'R'), slow, io(0, 1002.0, 3.0, 2_000_000, 42, b'W')];
        let c = explain(&slow, &ios, DriveClass::Flash, T0);
        assert!(c.mb_per_s > 100.0);
        assert_eq!(c.cause, Cause::IdleSlow);
    }

    #[test]
    fn totals_pick_the_main_cause_and_rank_movers() {
        let mut w = DiskWhy::default();
        *w.causes.entry(Cause::Busy).or_default() += 5;
        *w.causes.entry(Cause::IdleSlow).or_default() += 2;
        w.movers.insert("steam.exe (1234)".into(), 3_000_000_000);
        w.movers.insert("chrome.exe (99)".into(), 1_000_000_000);
        assert_eq!(w.main_cause(), Some(Cause::Busy));
        // A tie goes to the drive-side cause: it is the one worth acting on.
        let mut tie = DiskWhy::default();
        tie.causes.insert(Cause::Busy, 3);
        tie.causes.insert(Cause::IdleSlow, 3);
        assert_eq!(tie.main_cause(), Some(Cause::IdleSlow));
        tie.causes.insert(Cause::Flush, 3);
        tie.causes.insert(Cause::WokeUp, 3);
        assert_eq!(tie.main_cause(), Some(Cause::IdleSlow));
        tie.causes.remove(&Cause::IdleSlow);
        assert_eq!(tie.main_cause(), Some(Cause::WokeUp));
        let top = w.top_movers(1);
        assert_eq!(top[0].0, "steam.exe (1234)");
        assert!((top[0].2 - 0.75).abs() < 1e-9);
        assert!(known_worker("MsMpEng.exe (4321)").is_some_and(|w| w.windows));
        assert!(known_worker("steam.exe").is_some_and(|w| !w.windows));
        assert!(known_worker("game.exe").is_none());
    }
}
