//! One monitoring run, start to summary. Shared by the GUI and the CLI; all output goes
//! through `say!` / `util::status`, so the front end decides where it lands.

use std::mem::{size_of, zeroed};
use std::ptr::null_mut;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, ERROR_ALREADY_EXISTS, HANDLE};
use windows_sys::Win32::Media::timeBeginPeriod;
use windows_sys::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
use windows_sys::Win32::System::Registry::{RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ};
use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
use windows_sys::Win32::System::Threading::{
    CreateMutexW, GetActiveProcessorCount, GetCurrentProcess, GetCurrentThread, OpenProcessToken, SetThreadPriority,
    THREAD_PRIORITY_HIGHEST,
};
use windows_sys::Win32::UI::Shell::ShellExecuteW;
use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

use crate::summary::Summary;
use crate::util::{self, from_wide, ms_to_ticks, wide};
use crate::{analyze, cpuclock, etw, modules, probe, say, state};

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
    pub log: LogTarget,
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
            log: LogTarget::Auto,
            debug: false,
        }
    }
}

/// Both binaries call this first: when started as `<exe> --probe-child <threshold_ms>` the
/// process is the real-time latency probe helper and never returns.
pub fn run_probe_child_if_requested() {
    let mut args = std::env::args().skip(1);
    if args.next().as_deref() == Some(probe::CHILD_ARG) {
        let threshold = args.next().and_then(|a| a.parse().ok()).unwrap_or(5.0);
        probe::child_main(threshold);
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

fn reg_str(subkey: &str, value: &str) -> Option<String> {
    let mut buf = [0u16; 256];
    let mut size = (buf.len() * 2) as u32;
    let rc = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            wide(subkey).as_ptr(),
            wide(value).as_ptr(),
            RRF_RT_REG_SZ,
            null_mut(),
            buf.as_mut_ptr() as _,
            &mut size,
        )
    };
    (rc == 0).then(|| from_wide(&buf).trim().to_string())
}

fn print_system_info(ncpu: u32) {
    let cv = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
    let bios_key = "HARDWARE\\DESCRIPTION\\System\\BIOS";
    let cpu = reg_str("HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", "ProcessorNameString");
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
        u(reg_str(bios_key, "BaseBoardManufacturer")),
        u(reg_str(bios_key, "BaseBoardProduct")),
        u(reg_str(bios_key, "BIOSVersion")),
        u(reg_str(bios_key, "BIOSReleaseDate"))
    );
    say!("Windows: build {} ({})", u(reg_str(cv, "CurrentBuild")), u(reg_str(cv, "DisplayVersion")));
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
    report.extend(summary.detail_lines());
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
    let result = run_inner(cfg, stop);
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
fn run_inner(cfg: &Config, stop: &AtomicBool) -> Result<(Summary, usize), String> {
    let ncpu = unsafe { GetActiveProcessorCount(0) };
    say!("WTFIsStalling {} - what is stalling this PC?", env!("CARGO_PKG_VERSION"));
    print_system_info(ncpu);

    // Since Windows 11 24H2 kernel module addresses are hidden without SeDebugPrivilege.
    etw::enable_privilege("SeDebugPrivilege");
    let modules = modules::ModuleMap::load();
    if modules.is_empty() {
        say!("warning: Windows would not reveal kernel module addresses; drivers will show as raw addresses.");
    }

    util::status("Starting kernel trace...");
    let session = etw::Session::start(cfg.profile)?;
    if !session.profile && cfg.profile {
        say!("warning: CPU sampling could not be enabled; process attribution and firmware/SMI detection are off.");
    }
    unsafe { timeBeginPeriod(1) };

    let shared = Arc::new(state::Shared {
        inner: Mutex::new(state::Inner::default()),
        exec_warn: ms_to_ticks(cfg.dpc_warn_us / 1000.0),
        fault_warn: ms_to_ticks(cfg.fault_warn_ms),
        io_warn: ms_to_ticks(cfg.io_warn_ms),
        keep: ms_to_ticks(20_000.0),
        debug: cfg.debug,
    });
    let consumer = etw::spawn_consumer(shared.clone());

    let (tx, rx) = mpsc::channel();
    let probe_stop = Arc::new(AtomicBool::new(false));
    let probe_stats = Arc::new(probe::ProbeStats::default());
    probe::spawn_scheduler_probe(cfg.sched_stall_ms, tx.clone(), probe_stop.clone(), probe_stats.clone());
    let cpu_clock = cpuclock::spawn(probe_stop.clone());
    let mut probe_child = match probe::spawn_kernel_probes(cfg.stall_ms, tx, probe_stats.clone()) {
        Ok(c) => Some(c),
        Err(e) => {
            say!("warning: could not start the latency probe process ({e}); only individual slow events will be reported.");
            None
        }
    };

    // Keep the analysis thread ahead of ordinary apps so reports aren't delayed by the
    // very CPU starvation they describe.
    unsafe { SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST) };

    let mut analyzer = analyze::Analyzer::new(shared.clone(), rx, modules, session.profile);
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
    if let Some(mut c) = probe_child.take() {
        drop(c.stdin.take()); // EOF on stdin tells the child to exit
        let _ = c.wait();
    }
    // ETW flushes once a second; let the tail arrive before the final analysis.
    std::thread::sleep(Duration::from_millis(1200));
    analyzer.tick(true);
    let lost = session.stop();
    match consumer.join() {
        Ok(Err(e)) => say!("ERROR: {e}"),
        Err(_) => say!("ERROR: trace consumer thread panicked"),
        Ok(Ok(())) => {}
    }
    analyzer.tick(true);
    let clock_samples = cpu_clock.lock().unwrap().clone();
    let summary = analyzer.summarize(started.elapsed().as_secs_f64(), lost, &probe_stats, shared.exec_warn, shared.io_warn, &clock_samples);
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
        let report = compose_report(&header, &Summary::demo(Health::Problem), &events);

        assert!(!report.replace("\r\n", "").contains('\n'), "every line break must be CRLF or the GUI shows one endless line");
        let lines: Vec<&str> = report.split("\r\n").collect();
        assert!(lines.iter().all(|l| l.chars().count() <= REPORT_WIDTH), "long lines must be wrapped");
        let at = |needle: &str| lines.iter().position(|l| l.contains(needle)).unwrap_or_else(|| panic!("missing {needle}"));
        assert!(at("WTFIsStalling test") < at("RESULT") && at("RESULT") < at("DETAILS") && at("DETAILS") < at("EVENT LOG"));
        assert!(at("EVENT LOG") < at("STALL #1"));
        assert!(lines[at("VERDICT:") + 1].starts_with("            word"), "continuation lines hang under the text");
    }
}
