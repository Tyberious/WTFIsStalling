//! Console front end: monitor until Ctrl+C (or --duration), then print the summary.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use clap::Parser;
use windows_sys::Win32::System::Console::SetConsoleCtrlHandler;
use wtfis::engine::{self, Config, LogTarget};

#[derive(Parser)]
#[command(
    name = "wtfis-cli",
    version,
    about = "Finds the driver, app or hardware behind hitches and micro-stalls. Run it, reproduce the hitch, press Ctrl+C."
)]
struct Args {
    /// Stop automatically after this many seconds (default: run until Ctrl+C)
    #[arg(short, long)]
    duration: Option<u64>,
    /// Report a kernel-level stall when a real-time thread wakes this many ms late
    #[arg(long, default_value_t = 5.0)]
    stall_ms: f64,
    /// Report CPU starvation when a normal-priority thread wakes this many ms late
    #[arg(long, default_value_t = 25.0)]
    sched_stall_ms: f64,
    /// Log individual DPCs/ISRs that run longer than this many microseconds
    #[arg(long, default_value_t = 1000.0)]
    dpc_warn_us: f64,
    /// Log individual hard page faults slower than this many ms
    #[arg(long, default_value_t = 50.0)]
    fault_warn_ms: f64,
    /// Log individual disk requests slower than this many ms
    #[arg(long, default_value_t = 200.0)]
    io_warn_ms: f64,
    /// Don't sample the CPU (loses process attribution and firmware/SMI detection)
    #[arg(long)]
    no_profile: bool,
    /// Report file path (default: WTFIsStalling-<date>.txt in the current directory)
    #[arg(long)]
    log: Option<String>,
    /// Don't write a report file
    #[arg(long)]
    no_log: bool,
    /// Fail instead of asking for elevation when not running as Administrator
    #[arg(long)]
    no_elevate: bool,
    /// Set when relaunched elevated in a new console, so the window doesn't vanish
    #[arg(long, hide = true)]
    pause_on_exit: bool,
    /// Print kernel event counts by type after the summary
    #[arg(long, hide = true)]
    debug: bool,
    /// Flag a hitch automatically this many seconds in (for unattended testing of marks)
    #[arg(long, hide = true)]
    mark_at: Option<u64>,
}

static STOP: AtomicBool = AtomicBool::new(false);
static DONE: AtomicBool = AtomicBool::new(false);

unsafe extern "system" fn ctrl_handler(ctrl_type: u32) -> i32 {
    STOP.store(true, Ordering::SeqCst);
    // For close/logoff/shutdown Windows kills us as soon as this returns; hold on long
    // enough for the main thread to stop the kernel trace session.
    if ctrl_type >= 2 {
        for _ in 0..40 {
            if DONE.load(Ordering::SeqCst) {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
    1
}

fn main() {
    engine::run_probe_child_if_requested();
    let args = Args::parse();

    if !engine::is_elevated() {
        if !args.no_elevate && engine::relaunch_elevated(&["--pause-on-exit"]) {
            println!("Administrator rights are needed to trace the kernel; continuing in the elevated window.");
            return;
        }
        eprintln!("wtfis-cli must run as Administrator (kernel tracing requires it).");
        eprintln!("Right-click your terminal and choose 'Run as administrator'.");
        std::process::exit(1);
    }

    unsafe { SetConsoleCtrlHandler(Some(ctrl_handler), 1) };

    // A background thread reads stdin so pressing Enter marks a hitch while `engine::run`
    // (below) blocks the main thread. After the run finishes it instead forwards Enter presses
    // through this channel, since `--pause-on-exit`'s final "press Enter to close" wait would
    // otherwise race the same stdin against this thread.
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    std::thread::spawn(move || loop {
        let mut buf = String::new();
        match std::io::stdin().read_line(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(_) => {
                if DONE.load(Ordering::SeqCst) {
                    if tx.send(()).is_err() {
                        break;
                    }
                } else {
                    engine::mark_now();
                    println!("  marked - the report will show what happened just before this moment");
                }
            }
        }
    });

    if let Some(secs) = args.mark_at {
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(secs));
            engine::mark_now();
        });
    }

    let cfg = Config {
        duration: args.duration,
        stall_ms: args.stall_ms,
        sched_stall_ms: args.sched_stall_ms,
        dpc_warn_us: args.dpc_warn_us,
        fault_warn_ms: args.fault_warn_ms,
        io_warn_ms: args.io_warn_ms,
        profile: !args.no_profile,
        log: match (args.no_log, args.log) {
            (true, _) => LogTarget::None,
            (false, Some(p)) => LogTarget::Path(p),
            (false, None) => LogTarget::Auto,
        },
        debug: args.debug,
    };
    println!("Press Enter whenever you feel a hitch to mark that moment. Press Ctrl+C to stop and see the summary.");
    let result = engine::run(&cfg, &STOP);
    DONE.store(true, Ordering::SeqCst);
    if let Some(path) = result.as_ref().ok().and_then(|out| out.log_path.as_ref()) {
        println!("\nReport saved to {path} (result first, then details and the event log)");
    }
    if args.pause_on_exit {
        println!("\nPress Enter to close...");
        let _ = rx.recv();
    }
    std::process::exit(if result.is_ok() { 0 } else { 2 });
}
