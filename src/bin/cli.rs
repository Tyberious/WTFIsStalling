//! Console front end: monitor until Ctrl+C (or --duration), then print the summary.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use clap::Parser;
use windows_sys::Win32::System::Console::SetConsoleCtrlHandler;
use wtfis::baseline::CompareMode;
use wtfis::engine::{self, Config, LogTarget};
use wtfis::stacks::StackSet;

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
    /// Don't trace thread switches. They are the most expensive thing this tool records (tens of
    /// thousands of events a second on a busy PC), and without them the report cannot say whether
    /// a stalled thread was never woken or was woken and given no processor. Already off in
    /// --light mode
    #[arg(long)]
    no_switches: bool,
    /// Don't trace the graphics kernel. A second, small trace session records when the picture
    /// actually stopped updating and when the graphics card ran out of video memory - the part of
    /// a hitch a processor-side trace cannot see. Already off in --light mode
    #[arg(long)]
    no_gpu_trace: bool,
    /// Don't trace the storage driver. A small trace session records how long each disk request
    /// spent inside the drive versus waiting in Windows, and any retries and resets. One event per
    /// disk request, so it stays on in --light mode
    #[arg(long)]
    no_storage_trace: bool,
    /// Which kernel events get a module-level call stack: any of cswitch, ready, diskinit, fault
    /// (comma-separated), or all / none. Default: diskinit,fault. For measuring the cost
    #[arg(long, hide = true, value_name = "LIST", conflicts_with = "no_stacks")]
    stacks: Option<String>,
    /// Collect no call stacks at all
    #[arg(long, hide = true)]
    no_stacks: bool,
    /// Also record WHERE every waiting thread was blocked (which drivers were on its call stack),
    /// not only which drivers slow disk requests went through. Costs more: on a busy 32-thread PC,
    /// ~120,000 extra stack events a second and about twice this tool's own processor use. Not in
    /// --light mode
    #[arg(long, conflicts_with_all = ["stacks", "no_stacks"])]
    deep: bool,
    /// Measure more gently: probe every 2 ms and leave thread-switch, GPU and call-stack tracing off, so the tool costs
    /// the PC about half as much. Stalls shorter than ~2 ms can then be missed. On by itself on a
    /// PC with 4 logical CPUs or fewer, or one running on battery
    #[arg(long)]
    light: bool,
    /// Keep full measuring even on a small or unplugged PC (the opposite of --light)
    #[arg(long, conflicts_with = "light")]
    no_light: bool,
    /// Report file path (default: WTFIsStalling-<date>.txt in the current directory)
    #[arg(long)]
    log: Option<String>,
    /// Don't write a report file
    #[arg(long)]
    no_log: bool,
    /// Compare this run with a particular earlier one: the .wtfis file saved next to its report
    /// (default: the newest run from this PC in the report's folder, up to 30 days old)
    #[arg(long, value_name = "FILE")]
    compare: Option<String>,
    /// Don't compare this run with an earlier one
    #[arg(long, conflicts_with = "compare")]
    no_compare: bool,
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
    // Checked before anything else, so a mistyped list fails here and not after an elevation prompt.
    let stacks = match (args.no_stacks, args.stacks.as_deref()) {
        (true, _) => StackSet::NONE,
        // Measured 2026-09-24 (32 threads, disk load): disk starts + hard faults ~1,000 stacks a
        // second and no measurable cost; switch stacks ~122,000 a second, monitor 5% -> 9% of a
        // core. So switch stacks are opt-in. Wake-up stacks are not used by the report at all.
        (false, None) if args.deep => StackSet::parse("default,cswitch").expect("a fixed list"),
        (false, Some(list)) => match StackSet::parse(list) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("--stacks: {e}");
                std::process::exit(1);
            }
        },
        (false, None) => StackSet::DEFAULT,
    };

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
        switches: !args.no_switches,
        gpu_trace: !args.no_gpu_trace,
        storage_trace: !args.no_storage_trace,
        stacks,
        // Neither flag: decide from the machine itself, exactly as the GUI does.
        light: match (args.light, args.no_light) {
            (true, _) => Some(true),
            (_, true) => Some(false),
            _ => None,
        },
        log: match (args.no_log, args.log) {
            (true, _) => LogTarget::None,
            (false, Some(p)) => LogTarget::Path(p),
            (false, None) => LogTarget::Auto,
        },
        compare: match (args.no_compare, args.compare) {
            (true, _) => CompareMode::Off,
            (false, Some(p)) => CompareMode::Path(p),
            (false, None) => CompareMode::Auto,
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
