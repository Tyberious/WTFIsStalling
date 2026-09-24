//! One monitoring run, start to summary. Shared by the GUI and the CLI; all output goes
//! through `say!` / `util::status`, so the front end decides where it lands.

use std::mem::{size_of, zeroed};
use std::os::windows::io::AsRawHandle;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, ERROR_ALREADY_EXISTS, HANDLE};
use windows_sys::Win32::Media::{timeBeginPeriod, timeEndPeriod};
use windows_sys::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
use windows_sys::Win32::System::Threading::{
    CreateMutexW, GetCurrentProcess, GetCurrentThread, OpenProcessToken, SetThreadPriority, THREAD_PRIORITY_HIGHEST,
};
use windows_sys::Win32::UI::Shell::ShellExecuteW;
use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

use crate::baseline::CompareMode;
use crate::overhead::Overhead;
use crate::reg::hklm_str;
use crate::summary::{RunData, Summary};
use crate::topology::topology;
use crate::util::{self, ms_to_ticks, wide};
use crate::{analyze, baseline, cpuclock, etw, foreground, gpu, gputrace, modules, overhead, probe, say, state, storport};

pub use crate::analyze::mark_now;

pub enum LogTarget {
    /// WTFIsStalling-<timestamp>.txt in the current directory, else in %TEMP%.
    Auto,
    Path(String),
    None,
}

pub struct Config {
    /// Stop on its own after this many seconds.
    pub duration: Option<u64>,
    pub stall_ms: f64,
    pub sched_stall_ms: f64,
    pub dpc_warn_us: f64,
    pub fault_warn_ms: f64,
    pub io_warn_ms: f64,
    pub profile: bool,
    /// Trace context switches and thread wake-ups, which is what says whether a stalled thread
    /// was never woken or was woken and not run. This is the highest-volume class the kernel
    /// logger has, so it is off in light mode whatever this says.
    pub switches: bool,
    /// Trace the graphics kernel in a second ETW session: frame cadence and video memory
    /// pressure, which a CPU-side trace cannot see at all. Off in light mode whatever this says.
    pub gpu_trace: bool,
    /// Trace the storage port driver in its own session: where a slow disk request's time went
    /// (inside the drive or waiting in Windows), retries and resets. ON in light mode too: it is
    /// one small event per disk request, a tiny fraction of the kernel trace (see `storport`).
    pub storage_trace: bool,
    /// Which kernel events carry a module-level call stack (see `stacks`). Off in light mode
    /// whatever this says. Hidden CLI flags `--stacks` / `--no-stacks` set it, for measuring what
    /// each kind costs before the default is final.
    pub stacks: crate::stacks::StackSet,
    /// Measure with the lighter settings (2 ms probes, slower CPU sampling). `None` lets the
    /// tool decide before the run from the CPU count and whether the PC is on battery, which is
    /// what the GUI always uses; `Some` overrides that either way.
    pub light: Option<bool>,
    pub log: LogTarget,
    /// Which earlier run this one compares itself with (by default: the newest one from this PC
    /// saved next to the report).
    pub compare: CompareMode,
    pub debug: bool,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            duration: None,
            stall_ms: 5.0,
            sched_stall_ms: 25.0,
            dpc_warn_us: 1000.0,
            fault_warn_ms: 50.0,
            io_warn_ms: 200.0,
            profile: true,
            switches: true,
            gpu_trace: true,
            storage_trace: true,
            stacks: crate::stacks::StackSet::DEFAULT,
            light: None,
            log: LogTarget::Auto,
            compare: CompareMode::Auto,
            debug: false,
        }
    }
}

/// Both binaries call this first: when started as `<exe> --probe-child <threshold_ms>
/// <interval_ms>` the process is the real-time latency probe helper and never returns.
pub fn run_probe_child_if_requested() {
    let mut args = std::env::args().skip(1);
    if args.next().as_deref() == Some(probe::CHILD_ARG) {
        let threshold = args.next().and_then(|a| a.parse().ok()).unwrap_or(5.0);
        let interval = args.next().and_then(|a| a.parse().ok()).unwrap_or(overhead::PROBE_MS_NORMAL);
        probe::child_main(threshold, interval);
    }
}

pub fn is_elevated() -> bool {
    unsafe {
        let mut token: HANDLE = null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut elev: TOKEN_ELEVATION = zeroed();
        let mut ret = 0u32;
        let ok = GetTokenInformation(token, TokenElevation, &mut elev as *mut _ as _, size_of::<TOKEN_ELEVATION>() as u32, &mut ret);
        CloseHandle(token);
        ok != 0 && elev.TokenIsElevated != 0
    }
}

/// Re-runs this exe through the UAC prompt with the same arguments plus `extra`.
/// Returns false when the user declined.
pub fn relaunch_elevated(extra: &[&str]) -> bool {
    let Ok(exe) = std::env::current_exe() else { return false };
    let params: Vec<String> = std::env::args()
        .skip(1)
        .chain(extra.iter().map(|s| s.to_string()))
        .map(|a| if a.contains(' ') { format!("\"{a}\"") } else { a })
        .collect();
    let cwd = std::env::current_dir().map(|p| p.display().to_string()).unwrap_or_default();
    let rc = unsafe {
        ShellExecuteW(
            null_mut(),
            wide("runas").as_ptr(),
            wide(&exe.display().to_string()).as_ptr(),
            wide(&params.join(" ")).as_ptr(),
            wide(&cwd).as_ptr(),
            SW_SHOWNORMAL,
        )
    };
    rc as usize > 32
}

fn print_system_info(ncpu: u32) {
    let cv = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
    let bios_key = "HARDWARE\\DESCRIPTION\\System\\BIOS";
    let cpu = hklm_str("HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", "ProcessorNameString");
    let mut mem: MEMORYSTATUSEX = unsafe { zeroed() };
    mem.dwLength = size_of::<MEMORYSTATUSEX>() as u32;
    unsafe { GlobalMemoryStatusEx(&mut mem) };
    let u = |s: Option<String>| s.unwrap_or_else(|| "?".into());
    say!(
        "System : {} ({ncpu} logical CPUs), {:.1} GB RAM ({}% in use)",
        u(cpu),
        mem.ullTotalPhys as f64 / (1u64 << 30) as f64,
        mem.dwMemoryLoad
    );
    say!(
        "Board  : {} {}, BIOS {} ({})",
        u(hklm_str(bios_key, "BaseBoardManufacturer")),
        u(hklm_str(bios_key, "BaseBoardProduct")),
        u(hklm_str(bios_key, "BIOSVersion")),
        u(hklm_str(bios_key, "BIOSReleaseDate"))
    );
    // Only worth a line when there is something unusual about the layout: a hybrid chip
    // (P-cores and E-cores) or more than one processor group.
    if let Some(note) = topology().note() {
        say!("CPUs   : {note}");
    }
    say!("Windows: build {} ({})", u(hklm_str(cv, "CurrentBuild")), u(hklm_str(cv, "DisplayVersion")));
}

fn open_log(target: &LogTarget) -> Option<String> {
    let name = format!("WTFIsStalling-{}.txt", util::file_timestamp());
    let candidates = match target {
        LogTarget::None => return None,
        LogTarget::Path(p) => vec![std::path::PathBuf::from(p)],
        LogTarget::Auto => vec![std::path::PathBuf::from(&name), std::env::temp_dir().join(&name)],
    };
    for path in candidates {
        if let Ok(f) = std::fs::File::create(&path) {
            util::set_log(Some(f));
            let full = std::fs::canonicalize(&path).unwrap_or(path);
            return Some(full.display().to_string().trim_start_matches("\\\\?\\").to_string());
        }
    }
    None
}

pub struct RunOutput {
    /// Where the report was saved, if anywhere.
    pub log_path: Option<String>,
    /// The full report with the result first: system info, RESULT, DETAILS, event log.
    pub report: String,
    pub summary: Summary,
}

/// Monitors until `stop` is set (or `cfg.duration` elapses), then prints the summary.
/// Returns the path of the report file, if one was written. Must be elevated.
pub fn run(cfg: &Config, stop: &AtomicBool) -> Result<RunOutput, String> {
    // Starting a second trace would take over (and so kill) the first one's session.
    let guard = unsafe { CreateMutexW(null_mut(), 0, wide(r"Global\WTFIsStalling.Monitor").as_ptr()) };
    if guard.is_null() || unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
        let e = "another WTFIsStalling is already monitoring on this PC".to_string();
        say!("ERROR: {e}");
        if !guard.is_null() {
            unsafe { CloseHandle(guard) };
        }
        return Err(e);
    }
    let result = run_guarded(cfg, stop);
    unsafe { CloseHandle(guard) };
    result
}

/// Longest line the report may contain; longer event-log lines are wrapped so the GUI needs
/// no horizontal scrolling at its default size.
const REPORT_WIDTH: usize = 118;

/// The answer-first report: system info, RESULT, DETAILS, then the chronological event log.
/// Lines end in CRLF: the GUI's edit control only breaks on that, and so does classic Notepad.
pub fn compose_report(header: &[String], summary: &Summary, events: &[String]) -> String {
    let mut report: Vec<String> = header.to_vec();
    report.extend(summary.result_lines());
    // Table rows fit by construction; the legends and notes under them (a drive's health line, what
    // a file is, which device a driver belongs to) are prose and get wrapped like the event log,
    // so the window never needs a horizontal scroll bar.
    for line in summary.detail_lines() {
        wrap_line(&line, &mut report);
    }
    report.push(String::new());
    report.push("EVENT LOG (chronological)".into());
    let events: Vec<&String> = events.iter().skip_while(|l| l.trim().is_empty()).collect();
    if events.is_empty() {
        report.push("  (nothing noteworthy happened)".into());
    }
    for line in events {
        wrap_line(line, &mut report);
    }
    report.join("\r\n") + "\r\n"
}

/// Wraps at spaces, continuing under the text with a hanging indent.
fn wrap_line(line: &str, out: &mut Vec<String>) {
    if line.chars().count() <= REPORT_WIDTH {
        return out.push(line.to_string());
    }
    let indent = line.len() - line.trim_start().len();
    let hang = " ".repeat(indent + 8);
    let mut current = " ".repeat(indent);
    for word in line.split_whitespace() {
        let fresh = current.trim().is_empty();
        if !fresh && current.chars().count() + 1 + word.chars().count() > REPORT_WIDTH {
            out.push(std::mem::replace(&mut current, hang.clone()));
        } else if !fresh {
            current.push(' ');
        }
        current.push_str(word);
    }
    out.push(current);
}

fn run_guarded(cfg: &Config, stop: &AtomicBool) -> Result<RunOutput, String> {
    util::clock();
    let log_path = open_log(&cfg.log);
    util::start_capture();
    let result = run_inner(cfg, stop, log_path.as_deref());
    if let Err(e) = &result {
        say!("ERROR: {e}");
    }
    util::set_log(None);
    let lines = util::take_capture();
    let (summary, header_len) = result?;

    // The file was streamed chronologically (so a crash still leaves a log). Now that the
    // answer is known, rewrite it answer-first.
    let streamed = lines.len() - summary.detail_lines().len() - summary.result_lines().len();
    let (header, events) = lines[..streamed].split_at(header_len.min(streamed));
    let report = compose_report(header, &summary, events);
    if let Some(path) = &log_path {
        let _ = std::fs::write(path, &report);
    }
    Ok(RunOutput { log_path, report, summary })
}

/// Returns the summary and how many captured lines make up the system-info header.
/// 1 ms system timer resolution for as long as a run lasts, and not a moment longer: the request is
/// system-wide, and "changes nothing on the system" has to stay true once monitoring stops. Released
/// on every way out of the run, early returns and panics included.
struct TimerResolution;

impl TimerResolution {
    fn raise() -> TimerResolution {
        unsafe { timeBeginPeriod(1) };
        TimerResolution
    }
}

impl Drop for TimerResolution {
    fn drop(&mut self) {
        unsafe { timeEndPeriod(1) };
    }
}

fn run_inner(cfg: &Config, stop: &AtomicBool, log_path: Option<&str>) -> Result<(Summary, usize), String> {
    // Every group, not just group 0: past 64 logical CPUs Windows splits the machine up.
    let ncpu = topology().total() as u32;
    say!("WTFIsStalling {} - what is stalling this PC?", env!("CARGO_PKG_VERSION"));
    print_system_info(ncpu);

    // Decided once, before anything starts: mid-run switching would make the two halves of one
    // report incomparable. Both facts are readable without administrator rights.
    let light_reason = match cfg.light {
        Some(false) => None,
        Some(true) => overhead::auto_light_reason(ncpu, overhead::on_battery()).or(Some("you asked for it")),
        None => overhead::auto_light_reason(ncpu, overhead::on_battery()),
    };
    let probe_ms = if light_reason.is_some() { overhead::PROBE_MS_LIGHT } else { overhead::PROBE_MS_NORMAL };

    // Since Windows 11 24H2 kernel module addresses are hidden without SeDebugPrivilege.
    etw::enable_privilege("SeDebugPrivilege");
    let modules = modules::ModuleMap::load();
    if modules.is_empty() {
        say!("warning: Windows would not reveal kernel module addresses; drivers will show as raw addresses.");
    }

    util::status("Starting kernel trace...");
    // Context switches cost far more than everything else in this session put together, and light
    // mode exists to cost the PC less; asking for them there would undo the point of it.
    let want_switches = cfg.switches && light_reason.is_none();
    // Call stacks cost one stack walk per event they are attached to; light mode leaves them off
    // for the same reason it leaves the switches off.
    let want_stacks = if light_reason.is_some() { crate::stacks::StackSet::NONE } else { cfg.stacks };
    let session = etw::Session::start(cfg.profile, want_switches, want_stacks)?;
    if !session.profile && cfg.profile {
        say!("warning: CPU sampling could not be enabled; process attribution and firmware/SMI detection are off.");
    }
    if want_switches && !session.switches {
        say!("warning: Windows would not trace context switches; the report cannot say whether a stalled thread was woken.");
    }
    let _timer_resolution = TimerResolution::raise();
    // Light mode deliberately leaves CPU sampling alone: its interval is a system-wide Windows
    // setting, a hard kill would leave it changed until reboot, and other profilers would see it.
    // The probes are the real cost, and those are ours to slow down.
    if let Some(why) = light_reason {
        say!("Light mode: on, because {why}. The probes check every {probe_ms:.0} ms instead of 1 ms, so measuring costs this PC");
        say!("            less. Stalls shorter than about {probe_ms:.0} ms can be missed.");
    }
    if let Some(rc) = session.stack_error {
        say!("warning: Windows refused call stacks (Win32 error {rc}); the report cannot say which drivers were in the path.");
    } else if !session.stacks.is_empty() {
        say!("Stacks  : recording which drivers {} went through", session.stacks.plain());
        say!("          (driver names only, never function names).");
    }
    if session.switches {
        say!("Switches: tracing every thread switch, which is what tells 'nothing woke it' apart from 'it was woken and not run'.");
        say!("          It is the most expensive thing this tool records: tens of thousands of events a second on a busy PC. The");
        say!("          DETAILS block reports what it actually cost; 'wtfis-cli --no-switches' turns it off.");
    } else if cfg.switches && light_reason.is_some() {
        say!("Switches: not traced in light mode (it is the most expensive thing this tool records), so the report cannot say");
        say!("          whether a stalled thread was never woken or was woken and not given a processor.");
    }

    let shared = Arc::new(state::Shared {
        inner: Mutex::new({
            let (switch_cap, ready_cap) = state::switch_caps(ncpu as usize);
            let mut stacks = crate::stacks::StackState::new(session.stacks, ncpu as usize);
            stacks.enable_error = session.stack_error;
            state::Inner { switch_cap, ready_cap, stacks, ..Default::default() }
        }),
        exec_warn: ms_to_ticks(cfg.dpc_warn_us / 1000.0),
        fault_warn: ms_to_ticks(cfg.fault_warn_ms),
        io_warn: ms_to_ticks(cfg.io_warn_ms),
        keep: ms_to_ticks(20_000.0),
        switches: session.switches,
        debug: cfg.debug,
    });
    let consumer = etw::spawn_consumer(shared.clone());

    // The graphics kernel is a manifest provider and cannot ride on the system logger above, so
    // it gets its own real-time session on the same clock. Everything about it is optional: if
    // it will not start, the run carries on and DETAILS says in one line why there is no GPU
    // evidence. Off in light mode for the same reason thread switches are.
    let want_gpu = cfg.gpu_trace && light_reason.is_none();
    let (mut gpu_session, mut gpu_trace, mut gpu_consumer) = (None, None, None);
    let mut gpu_note = match (cfg.gpu_trace, light_reason.is_some()) {
        (false, _) => Some("you asked for it with --no-gpu-trace".to_string()),
        (_, true) => Some("light mode leaves the second trace session off".to_string()),
        _ => None,
    };
    if want_gpu {
        match gputrace::start(cfg.debug) {
            Ok((session, trace, consumer)) => {
                gpu_session = Some(session);
                gpu_trace = Some(trace);
                gpu_consumer = Some(consumer);
            }
            Err(e) => {
                say!("warning: the graphics-kernel trace could not be started ({e}); frame timing and video memory pressure are off.");
                gpu_note = Some(e);
            }
        }
    }

    // The storage port driver, likewise its own session, and likewise optional. ON in light mode:
    // measured at ~1,750 events a second under heavy disk load against ~370,000 for the kernel
    // trace, it costs next to nothing next to what light mode leaves off.
    let (mut stor_session, mut stor_trace, mut stor_consumer) = (None, None, None);
    let mut stor_note = (!cfg.storage_trace).then(|| "you asked for it with --no-storage-trace".to_string());
    if cfg.storage_trace {
        match storport::start(cfg.debug) {
            Ok((session, trace, consumer)) => {
                stor_session = Some(session);
                stor_trace = Some(trace);
                stor_consumer = Some(consumer);
            }
            Err(e) => {
                say!("warning: the storage driver trace could not be started ({e}); where slow disk time went is not measured.");
                stor_note = Some(e);
            }
        }
    }

    let (tx, rx) = mpsc::channel();
    let probe_stop = Arc::new(AtomicBool::new(false));
    let probe_stats = Arc::new(probe::ProbeStats::default());
    probe::spawn_scheduler_probe(cfg.sched_stall_ms, tx.clone(), probe_stop.clone(), probe_stats.clone());
    let cpu_clock = cpuclock::spawn(probe_stop.clone());
    let gpu_log = gpu::spawn(probe_stop.clone());
    // Which program is in front, once a second: process ID only, never a window title.
    let foreground = foreground::spawn(probe_stop.clone());
    let mut probe_child = match probe::spawn_kernel_probes(cfg.stall_ms, probe_ms, tx, probe_stats.clone()) {
        Ok(c) => Some(c),
        Err(e) => {
            say!("warning: could not start the latency probe process ({e}); only individual slow events will be reported.");
            None
        }
    };

    // Keep the analysis thread ahead of ordinary apps so reports aren't delayed by the
    // very CPU starvation they describe.
    unsafe { SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST) };

    let mut analyzer = analyze::Analyzer::new(shared.clone(), rx, modules, session.profile, probe_stats.tids.clone());
    if let Some(trace) = &gpu_trace {
        analyzer.set_gpu_trace(trace.clone());
    }
    if let Some(trace) = &stor_trace {
        analyzer.set_storage_trace(trace.clone());
    }
    analyzer.set_cpu_clock(cpu_clock.clone());
    analyzer.set_foreground(foreground);
    say!(
        "Monitoring {} kernel modules; stall thresholds {} ms kernel-level / {} ms CPU-starvation. Reproduce the hitch now.",
        analyzer.modules.len(),
        cfg.stall_ms,
        cfg.sched_stall_ms
    );
    let header_len = util::capture_len();
    say!("");

    let started = Instant::now();
    let mut last_status = u64::MAX;
    let mut checked_realtime = probe_child.is_none();
    while !stop.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(100));
        analyzer.tick(false);
        let elapsed = started.elapsed().as_secs();
        if consumer.is_finished() {
            say!("ERROR: the kernel trace ended unexpectedly.");
            break;
        }
        if cfg.duration.is_some_and(|d| elapsed >= d) {
            break;
        }
        if !checked_realtime && elapsed >= 2 {
            checked_realtime = true;
            if !probe_stats.realtime.load(Ordering::Relaxed) {
                say!("warning: probes could not get real-time priority; busy high-priority apps may show up as kernel-level stalls.");
            }
        }
        if elapsed != last_status {
            last_status = elapsed;
            let line = analyzer.status_line(elapsed);
            util::status(&line);
            if elapsed > 0 && elapsed.is_multiple_of(60) {
                say!("    ... {line}");
            }
        }
    }

    util::status("Stopping: collecting the last trace buffers and analyzing...");
    probe_stop.store(true, Ordering::SeqCst);
    let mut probes_cpu = None;
    if let Some(mut c) = probe_child.take() {
        drop(c.stdin.take()); // EOF on stdin tells the child to exit
        let _ = c.wait();
        // `Child` keeps the process handle open until it is dropped, and a process's CPU time
        // stays readable after it exits, so this is the child's final total.
        probes_cpu = unsafe { overhead::process_cpu_100ns(c.as_raw_handle() as HANDLE) };
    }
    // ETW flushes once a second; let the tail arrive before the final analysis.
    std::thread::sleep(Duration::from_millis(1200));
    analyzer.tick(true);
    // Read out before the session is stopped: stopping it is what makes its consumer exit.
    let gpu_report = match &gpu_trace {
        Some(trace) => {
            let mut r = trace.report();
            r.note = gpu_note.take();
            r
        }
        None => crate::gputrace::GpuTraceReport { note: gpu_note.take(), ..Default::default() },
    };
    if let Some(s) = &gpu_session {
        s.stop();
    }
    if let Some(h) = gpu_consumer {
        let _ = h.join();
    }
    // Stopped first and read out after its consumer has drained, so the count and the lost count
    // cover everything it delivered; the ring stays readable for the last analysis below.
    let stor_lost = stor_session.take().map_or(0, |s| s.stop());
    if let Some(h) = stor_consumer {
        let _ = h.join();
    }
    let storage_report = match &stor_trace {
        Some(trace) => {
            trace.inner.lock().unwrap_or_else(|e| e.into_inner()).finished = true;
            storport::StorageReport { lost: stor_lost, note: stor_note.take(), ..trace.report() }
        }
        None => storport::StorageReport { note: stor_note.take(), ..Default::default() },
    };
    let lost = session.stop();
    match consumer.join() {
        Ok(Err(e)) => say!("ERROR: {e}"),
        Err(_) => say!("ERROR: trace consumer thread panicked"),
        Ok(Ok(())) => {}
    }
    analyzer.tick(true);
    let clock_samples = cpu_clock.lock().unwrap().clone();
    let gpu_log = gpu_log.lock().unwrap().clone();
    let elapsed_s = started.elapsed().as_secs_f64();
    let mut summary = analyzer.summarize(RunData {
        elapsed_s,
        events_lost: lost,
        overhead: Overhead { monitor_100ns: overhead::current_process_cpu_100ns().unwrap_or(0), probes_100ns: probes_cpu, elapsed_s, ncpu },
        light: light_reason,
        stats: &probe_stats,
        exec_warn: shared.exec_warn,
        io_warn: shared.io_warn,
        clock: &clock_samples,
        gpu: &gpu_log,
        gpu_trace: gpu_report,
        storage_trace: storage_report,
    });
    // Compare with the previous run and leave this run's numbers for the next one. Must happen
    // before the result is printed, so "what changed" is part of the result everywhere.
    baseline::attach(&mut summary, &cfg.compare, log_path);
    // Streamed order ends with the result, because on a console the bottom is what you see.
    say!("");
    for line in summary.detail_lines().iter().chain(summary.result_lines().iter()) {
        say!("{line}");
    }
    Ok((summary, header_len))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::summary::Health;

    #[test]
    fn report_is_crlf_answer_first_and_needs_no_horizontal_scrolling() {
        let header = vec!["WTFIsStalling test".to_string()];
        let long = format!("    VERDICT: {}", "word ".repeat(60));
        let events = vec![String::new(), "[12:00:00.000] STALL #1".to_string(), long];
        // A real run's DETAILS carry prose wider than any table: a drive-health line, what a file is.
        let mut summary = Summary::demo(Health::Problem);
        summary.details.push(format!("  disk 0   59 °C  |  {}", "6% of rated life used  |  ".repeat(8)));
        let report = compose_report(&header, &summary, &events);

        assert!(!report.replace("\r\n", "").contains('\n'), "every line break must be CRLF or the GUI shows one endless line");
        let lines: Vec<&str> = report.split("\r\n").collect();
        assert!(lines.iter().all(|l| l.chars().count() <= REPORT_WIDTH), "long lines must be wrapped");
        let at = |needle: &str| lines.iter().position(|l| l.contains(needle)).unwrap_or_else(|| panic!("missing {needle}"));
        assert!(at("WTFIsStalling test") < at("RESULT") && at("RESULT") < at("DETAILS") && at("DETAILS") < at("EVENT LOG"));
        assert!(at("EVENT LOG") < at("STALL #1"));
        assert!(lines[at("VERDICT:") + 1].starts_with("            word"), "continuation lines hang under the text");
    }
}
