//! What the measuring itself costs the PC, and the lighter mode for weak machines.
//!
//! Two processes do the work: this one (the kernel trace consumer and the analysis) and the
//! real-time probe child. Both are measured with `GetProcessTimes`, whose kernel and user
//! FILETIMEs are *durations* in 100 ns units ("if a process has spent one second in kernel
//! mode, this function will fill the FILETIME ... with a 64-bit value of ten million"),
//! summed over every thread of the process
//! (learn.microsoft.com/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocesstimes).
//!
//! Light mode halves how often the probes wake up and how often the CPU is sampled. It is
//! decided once, before the run, so everything in one report is measured the same way.

use std::mem::zeroed;

use windows_sys::Win32::Foundation::{FILETIME, HANDLE};
use windows_sys::Win32::System::Power::{GetSystemPowerStatus, SYSTEM_POWER_STATUS};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetProcessTimes};

/// How often each real-time probe thread asks to be woken, in ms.
pub const PROBE_MS_NORMAL: f64 = 1.0;
pub const PROBE_MS_LIGHT: f64 = 2.0;
/// A PC with this many logical CPUs or fewer is measured in light mode: one real-time probe
/// thread per CPU is a much bigger share of a 4-CPU machine than of a 16-CPU one.
pub const LIGHT_CPU_MAX: u32 = 4;

/// Above this share of the whole processor, the tool's own two processes are enough to change
/// what they are measuring. 5% is roughly "one core in twenty busy with measuring".
const TOTAL_SHARE_WARN: f64 = 5.0;
/// A single process holding half a core has a real chance of being scheduled against the very
/// work whose hitches are being investigated.
const ONE_CORE_WARN: f64 = 50.0;
/// Losing this share of the kernel events means gaps big enough to miss a stall's cause.
const LOST_SHARE_WARN: f64 = 0.01;

/// 100 ns units in one second (FILETIME durations).
const PER_SECOND: f64 = 10_000_000.0;

/// CPU time used by the tool's own processes during one run.
#[derive(Clone, Copy, Default, Debug)]
pub struct Overhead {
    /// Kernel + user time of the monitoring process, 100 ns units.
    pub monitor_100ns: u64,
    /// Same for the real-time probe child; `None` when it never started or could not be read.
    pub probes_100ns: Option<u64>,
    pub elapsed_s: f64,
    /// Logical CPUs across every processor group.
    pub ncpu: u32,
}

/// (share of one core, share of the whole processor), both in percent.
fn shares(cpu_100ns: u64, elapsed_s: f64, ncpu: u32) -> (f64, f64) {
    if elapsed_s <= 0.0 || !elapsed_s.is_finite() {
        return (0.0, 0.0);
    }
    let one_core = 100.0 * (cpu_100ns as f64 / PER_SECOND) / elapsed_s;
    (one_core, one_core / ncpu.max(1) as f64)
}

impl Overhead {
    pub fn monitor_shares(&self) -> (f64, f64) {
        shares(self.monitor_100ns, self.elapsed_s, self.ncpu)
    }

    /// `None` when the probe child's time could not be read; it is then left out of every total.
    pub fn probe_shares(&self) -> Option<(f64, f64)> {
        self.probes_100ns.map(|t| shares(t, self.elapsed_s, self.ncpu))
    }

    /// Share of the whole processor used by both processes together, in percent.
    pub fn total_share(&self) -> f64 {
        self.monitor_shares().1 + self.probe_shares().map_or(0.0, |s| s.1)
    }

    /// The plain-lines block for DETAILS. `events` is how many kernel events were processed;
    /// `switch_events` is how many of those were context switches and thread wake-ups, which is
    /// the one class expensive enough that its price should be visible (`None` when they were not
    /// being traced at all). `gpu_events` is the second session's own count, priced separately
    /// because it is a separate session with its own switch.
    pub fn detail_lines(&self, events: u64, lost: u32, switch_events: Option<u64>, gpu_events: Option<u64>) -> Vec<String> {
        let secs = |t: u64| t as f64 / PER_SECOND;
        let line = |what: &str, t: u64| {
            let (core, machine) = shares(t, self.elapsed_s, self.ncpu);
            format!("  {what:<20}{:.1} s of processor time  -  {core:.0}% of one core, {machine:.1}% of the whole processor", secs(t))
        };
        let mut out = vec![line("Monitoring program:", self.monitor_100ns)];
        out.push(match self.probes_100ns {
            Some(t) => line("Latency probes:", t),
            None => "  Latency probes:     not measured (the probe process did not run)".to_string(),
        });
        let per_s = |n: u64| if self.elapsed_s > 0.0 { n as f64 / self.elapsed_s } else { 0.0 };
        out.push(format!("  Kernel events:      {events} processed ({:.0} per second), {lost} lost", per_s(events)));
        out.push(match switch_events {
            Some(n) => {
                format!("  Thread switches:    {n} of those ({:.0} per second) - the costliest thing measured (--no-switches)", per_s(n))
            }
            None => "  Thread switches:    not traced (light mode, or --no-switches)".to_string(),
        });
        out.push(match gpu_events {
            Some(n) => format!(
                "  GPU trace:          {n} graphics events ({:.0} per second) - frame timing and video memory (--no-gpu-trace)",
                per_s(n)
            ),
            None => {
                "  GPU trace:          not traced (light mode, --no-gpu-trace, or Windows would not start a second session)".to_string()
            }
        });
        out
    }

    /// Plain-words reasons this run's own cost may have disturbed what it measured. Empty means
    /// the cost was low enough to ignore.
    pub fn concerns(&self, events: u64, lost: u32) -> Vec<String> {
        let mut out = Vec::new();
        let total = self.total_share();
        if total >= TOTAL_SHARE_WARN {
            out.push(format!(
                "Measuring used {total:.1}% of this PC's total processor capacity, enough that the tool is part of what it measured.",
            ));
        }
        for (what, (core, _)) in
            [("The monitoring program", self.monitor_shares())].into_iter().chain(self.probe_shares().map(|s| ("The latency probes", s)))
        {
            if core >= ONE_CORE_WARN {
                out.push(format!("{what} kept {core:.0}% of one processor core busy for the whole run."));
            }
        }
        let offered = events + lost as u64;
        if lost > 0 && offered > 0 && lost as f64 / offered as f64 >= LOST_SHARE_WARN {
            out.push(format!(
                "Windows could not hand over {lost} of the {offered} kernel events ({:.0}%), so parts of the run were not seen and a \
                 cause may have been missed.",
                100.0 * lost as f64 / offered as f64
            ));
        }
        out
    }
}

/// Kernel + user CPU time of a process, in 100 ns units. The handle needs
/// PROCESS_QUERY_INFORMATION or PROCESS_QUERY_LIMITED_INFORMATION, which a handle to our own
/// process and one to a child we created both have.
///
/// # Safety
/// `process` must be a live process handle (or a pseudo-handle) that the caller keeps open for
/// the duration of the call.
pub unsafe fn process_cpu_100ns(process: HANDLE) -> Option<u64> {
    let ft = |f: FILETIME| ((f.dwHighDateTime as u64) << 32) | f.dwLowDateTime as u64;
    let (mut created, mut exited, mut kernel, mut user): (FILETIME, FILETIME, FILETIME, FILETIME) =
        (zeroed(), zeroed(), zeroed(), zeroed());
    (GetProcessTimes(process, &mut created, &mut exited, &mut kernel, &mut user) != 0).then(|| ft(kernel) + ft(user))
}

pub fn current_process_cpu_100ns() -> Option<u64> {
    // GetCurrentProcess returns a pseudo-handle that is always valid for this process.
    unsafe { process_cpu_100ns(GetCurrentProcess()) }
}

/// Whether the PC is running off its battery. `None` when Windows will not say, which includes
/// every desktop without a battery (they report AC online).
///
/// SYSTEM_POWER_STATUS.ACLineStatus is 0 offline, 1 online, 255 unknown
/// (learn.microsoft.com/windows/win32/api/winbase/ns-winbase-system_power_status).
pub fn on_battery() -> Option<bool> {
    unsafe {
        let mut status: SYSTEM_POWER_STATUS = zeroed();
        if GetSystemPowerStatus(&mut status) == 0 {
            return None;
        }
        match status.ACLineStatus {
            0 => Some(true),
            1 => Some(false),
            _ => None,
        }
    }
}

/// Should this run measure in light mode without being asked? Decided from facts that need no
/// administrator rights, before anything starts, and never changed mid-run: two halves of one
/// run measured differently could not be compared.
pub fn auto_light_reason(ncpu: u32, on_battery: Option<bool>) -> Option<&'static str> {
    if ncpu > 0 && ncpu <= LIGHT_CPU_MAX {
        Some("this PC has few processor cores")
    } else if on_battery == Some(true) {
        Some("this PC is running on battery")
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One second of CPU time in FILETIME units.
    const SEC: u64 = 10_000_000;

    #[test]
    fn shares_are_of_one_core_and_of_the_whole_processor() {
        // 3 s of CPU over a 60 s run on 8 CPUs: 5% of one core, 0.625% of the machine.
        let o = Overhead { monitor_100ns: 3 * SEC, probes_100ns: Some(6 * SEC), elapsed_s: 60.0, ncpu: 8 };
        let (core, machine) = o.monitor_shares();
        assert!((core - 5.0).abs() < 1e-9 && (machine - 0.625).abs() < 1e-9, "{core} {machine}");
        let (core, machine) = o.probe_shares().unwrap();
        assert!((core - 10.0).abs() < 1e-9 && (machine - 1.25).abs() < 1e-9, "{core} {machine}");
        assert!((o.total_share() - 1.875).abs() < 1e-9);
    }

    #[test]
    fn missing_numbers_never_panic_or_divide_by_zero() {
        let zero = Overhead::default();
        assert_eq!(zero.monitor_shares(), (0.0, 0.0));
        assert!(zero.probe_shares().is_none());
        assert_eq!(zero.total_share(), 0.0);
        assert!(zero.concerns(0, 0).is_empty());
        assert_eq!(zero.detail_lines(0, 0, None, None).len(), 5);
        // Elapsed but no CPU count reported: fall back to "one core" rather than dividing by 0.
        let no_cpus = Overhead { monitor_100ns: SEC, probes_100ns: None, elapsed_s: 10.0, ncpu: 0 };
        assert_eq!(no_cpus.monitor_shares(), (10.0, 10.0));
        assert!(no_cpus.detail_lines(5, 0, None, None)[1].contains("not measured"));
    }

    #[test]
    fn a_cheap_run_raises_nothing_and_an_expensive_one_says_why() {
        // 2 s + 4 s of CPU over 300 s on 16 CPUs is a fraction of a percent.
        let cheap = Overhead { monitor_100ns: 2 * SEC, probes_100ns: Some(4 * SEC), elapsed_s: 300.0, ncpu: 16 };
        assert!(cheap.concerns(1_000_000, 0).is_empty(), "{:?}", cheap.concerns(1_000_000, 0));

        // 4 CPUs, probes busy on 60% of a core each: over both thresholds.
        let heavy = Overhead { monitor_100ns: 6 * SEC, probes_100ns: Some(60 * SEC), elapsed_s: 100.0, ncpu: 4 };
        let c = heavy.concerns(1_000_000, 0);
        assert_eq!(c.len(), 2, "{c:?}");
        assert!(c[0].contains("total processor capacity"), "{c:?}");
        assert!(c[1].starts_with("The latency probes") && c[1].contains("60%"), "{c:?}");
    }

    #[test]
    fn lost_events_are_called_out_only_when_they_are_a_real_share() {
        let o = Overhead { monitor_100ns: SEC, probes_100ns: Some(SEC), elapsed_s: 300.0, ncpu: 16 };
        assert!(o.concerns(1_000_000, 10).is_empty(), "a handful out of a million is noise");
        let c = o.concerns(100_000, 5_000);
        assert_eq!(c.len(), 1, "{c:?}");
        assert!(c[0].contains("5000 of the 105000 kernel events (5%)"), "{c:?}");
    }

    #[test]
    fn light_mode_is_chosen_for_small_or_unplugged_machines() {
        assert_eq!(auto_light_reason(4, Some(false)), Some("this PC has few processor cores"));
        assert_eq!(auto_light_reason(2, None), Some("this PC has few processor cores"));
        assert_eq!(auto_light_reason(16, Some(true)), Some("this PC is running on battery"));
        assert_eq!(auto_light_reason(16, Some(false)), None);
        assert_eq!(auto_light_reason(16, None), None, "unknown power status is not a reason");
        assert_eq!(auto_light_reason(0, None), None, "a CPU count of 0 means we could not count");
    }

    /// Non-asserting: prints what this machine actually reports, so a live run can be sanity-checked.
    #[test]
    fn live_own_cpu_time_and_power_status() {
        let cpu = current_process_cpu_100ns();
        println!("this process has used {:?} 100 ns units of CPU so far", cpu);
        println!("on battery: {:?}", on_battery());
        assert!(cpu.is_some(), "GetProcessTimes on our own process must work everywhere");
    }
}
