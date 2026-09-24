//! The context every section of the summary works on: the finished run's data, the findings
//! collected so far, the detail lines, and the handful of numbers one section works out that a
//! later section (or the DETAILS tables) needs.

use std::collections::HashMap;

use crate::analyze::Analyzer;
use crate::devices::DeviceMap;
use crate::evlog::{self, DisplayReset, HardwareEvent, StorageEvent};
use crate::files;
use crate::state::{Beats, LatStat, RoutineStat};
use crate::util::{plural, unix_now};

use super::stalls::DriverAgg;
use super::storage::FileRow;
use super::{Findings, RunData};

/// How far back the Windows event log is read, everywhere in the report.
pub(super) const EVENT_LOG_DAYS: u32 = 7;

/// "3 times in the last 7 days (1 while monitoring), most recently 2 day(s) ago"
pub(super) fn when_text(times: &[i64], now: i64, run_start: i64) -> String {
    let during = times.iter().filter(|t| **t >= run_start).count();
    let last = times.iter().copied().max().unwrap_or(now);
    let ago = match (now - last).max(0) {
        s if s < 3600 => "within the last hour".to_string(),
        s if s < 86_400 => format!("{} hour(s) ago", s / 3600),
        s => format!("{} day(s) ago", s / 86_400),
    };
    let during_txt = if during > 0 { format!(" ({during} while monitoring)") } else { String::new() };
    let plural = plural(times.len() as u64);
    format!("{} time{plural} in the last {EVENT_LOG_DAYS} days{during_txt}, most recently {ago}", times.len())
}

pub(super) struct Ctx<'a> {
    pub az: &'a mut Analyzer,
    pub run: RunData<'a>,
    pub found: Findings,
    pub details: Vec<String>,

    // ---- copied out of the shared ETW state once, while the lock is held
    pub routines: HashMap<(u64, u8), RoutineStat>,
    /// Whole-run activity per DPC/ISR routine, in quarter-second buckets. See `state::Beats`.
    pub beats: HashMap<u64, Beats>,
    pub faults: HashMap<u32, LatStat>,
    /// Per-disk latency totals, by disk number.
    pub disk_stats: Vec<(u32, LatStat)>,
    pub events: u64,
    /// Context switches plus thread wake-ups over the whole run; `None` when they were not being
    /// traced (light mode, `--no-switches`, or Windows refusing the flags).
    pub switch_events: Option<u64>,
    pub debug_counts: Vec<((u32, u8), u64)>,
    pub debug_rejected: Vec<(i64, i64)>,
    /// --debug only: DiskIo requests by (op, IrpFlags).
    pub debug_irp_flags: Vec<((u8, u32), u64)>,
    /// What the call stacks cost and what became of them (see `stacks`).
    pub stacks: crate::stacks::StackReport,
    pub named_files: usize,
    /// Every path already in drive-letter form and past the privacy rule.
    pub file_waits: Vec<FileRow>,
    pub fault_files: HashMap<String, Vec<(String, u64, i64)>>,

    // ---- this run in wall-clock terms
    pub now_unix: i64,
    /// QPC at the instant `now_unix` was read: the anchor for turning a stall's QPC time into wall-clock
    /// time. Read together, because the sections in between can block for seconds (a sleeping drive).
    pub now_qpc: i64,
    pub run_start_unix: i64,
    pub storage_log: Vec<StorageEvent>,

    // ---- worked out by one section, read by later ones and by the DETAILS tables
    pub tally: Vec<(String, (u32, i64, i64))>,
    pub drivers: Vec<(String, DriverAgg)>,
    pub faults_named: Vec<(String, LatStat)>,
    /// Memory in use, %, as the paging section read it.
    pub mem: u32,
    pub gpu_lines: Vec<String>,
    pub health_lines: Vec<String>,
    pub display_log: Vec<DisplayReset>,
    pub hardware_log: Vec<HardwareEvent>,
    pub firmware_caps: Vec<i64>,
    pub crashes: usize,
    /// Seconds in which busy cores were held back (the clock is sampled once a second).
    pub throttled_secs: usize,
    pub device_map: DeviceMap,
    pub today: (i32, u32, u32),
    /// DETAILS tables built by the `platform` section (hardware-access drivers, network filters,
    /// devices on legacy interrupts), printed by `details::tables`.
    pub platform_lines: Vec<String>,
    /// The "where the waiting happened" block, built by `storage::slow_disks` from call stacks.
    pub stack_lines: Vec<String>,
}

impl Ctx<'_> {
    /// May anything be concluded from the context-switch trace?
    ///
    /// Only if it was recorded at all AND Windows handed over every event. Everything read from
    /// these two classes is a chain - readied, then switched in, then switched out - and one
    /// missing `ReadyThread` turns "woken on time" into "never woken", which is the opposite
    /// conclusion. Unlike counting DPCs, there is no safe way to be approximately right here, so
    /// any loss at all disqualifies the run's scheduler findings rather than shading them.
    pub fn scheduler_usable(&self) -> bool {
        self.switch_events.is_some() && self.run.events_lost == 0
    }
}

impl<'a> Ctx<'a> {
    pub fn new(az: &'a mut Analyzer, run: RunData<'a>) -> Ctx<'a> {
        let elapsed_s = run.elapsed_s;
        let mut inner = az.shared.inner.lock().unwrap();
        let routines = inner.routines.clone();
        // Taken rather than cloned: the run is over, and the bitmaps are the one thing here big
        // enough (a few hundred KB) to be worth not copying.
        let beats = std::mem::take(&mut inner.beats);
        let faults = inner.faults_by_pid.clone();
        let disks = inner.disks.clone();
        let events = inner.events;
        // Priced together: they are enabled by one decision and arrive at comparable rates.
        let switch_events = az.shared.switches.then(|| inner.switch_events + inner.ready_events);
        let debug_counts: Vec<_> = inner.debug_counts.iter().map(|(k, v)| (*k, *v)).collect();
        let debug_rejected = inner.debug_rejected.clone();
        let mut debug_irp_flags: Vec<_> = inner.debug_irp_flags.iter().map(|(k, v)| (*k, *v)).collect();
        debug_irp_flags.sort();
        let stacks = inner.stacks.report();
        // Files the trace named. Anything it never named is dropped here rather than carried
        // around as an unnamed row: "(file name not available)" repeated is noise, not evidence.
        let named_files = inner.file_names.len();
        let raw_waits: Vec<(String, u32, u64, i64, i64)> = inner
            .file_wait
            .iter()
            .filter_map(|(key, w)| inner.file_names.get(*key).map(|p| (p.to_string(), w.disk, w.count, w.total, w.max)))
            .collect();
        let raw_fault_files: Vec<(u32, String, u64, i64)> = inner
            .fault_file
            .iter()
            .filter_map(|((pid, key), w)| inner.file_names.get(*key).map(|p| (*pid, p.to_string(), w.count, w.total)))
            .collect();
        drop(inner);

        // Every path becomes drive-letter form and passes the privacy rule ONCE, here, before any
        // section of the summary can see it. Nothing past this point ever touches a raw NT path.
        let file_waits: Vec<FileRow> =
            raw_waits.into_iter().map(|(p, d, c, t, m)| (files::public_path(&az.dos.to_dos(&p)), d, c, t, m)).collect();
        let mut fault_files: HashMap<String, Vec<(String, u64, i64)>> = HashMap::new();
        for (pid, path, count, total) in raw_fault_files {
            let shown = files::public_path(&az.dos.to_dos(&path));
            if !shown.is_empty() {
                fault_files.entry(az.procs.label(pid, 0)).or_default().push((shown, count, total));
            }
        }

        let (now_unix, now_qpc) = (unix_now(), crate::util::qpc());
        let run_start_unix = now_unix - elapsed_s as i64 - 2;
        let storage_log = evlog::storage_events(EVENT_LOG_DAYS);
        let mut disk_stats: Vec<(u32, LatStat)> = disks.into_iter().collect();
        disk_stats.sort_by_key(|(n, _)| *n);
        Ctx {
            az,
            run,
            found: Findings::default(),
            details: Vec::new(),
            routines,
            beats,
            faults,
            disk_stats,
            events,
            switch_events,
            debug_counts,
            debug_rejected,
            debug_irp_flags,
            stacks,
            named_files,
            file_waits,
            fault_files,
            now_unix,
            now_qpc,
            run_start_unix,
            storage_log,
            tally: Vec::new(),
            drivers: Vec::new(),
            faults_named: Vec::new(),
            mem: 0,
            gpu_lines: Vec::new(),
            health_lines: Vec::new(),
            display_log: Vec::new(),
            hardware_log: Vec::new(),
            firmware_caps: Vec::new(),
            crashes: 0,
            throttled_secs: 0,
            device_map: DeviceMap::default(),
            today: (0, 0, 0),
            platform_lines: Vec::new(),
            stack_lines: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_log_timing_reads_naturally() {
        let now = 1_000_000;
        assert_eq!(
            when_text(&[now - 3 * 86_400, now - 100], now, now - 600),
            "2 times in the last 7 days (1 while monitoring), most recently within the last hour"
        );
        assert_eq!(when_text(&[now - 2 * 86_400 - 5], now, now - 600), "1 time in the last 7 days, most recently 2 day(s) ago");
    }
}
