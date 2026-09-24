//! Which program the person was looking at: the owner of the foreground window, once a second.
//!
//! The waiters the report lists at a hitch are ranked by how long they waited, which is not the
//! same as mattering: a background updater that waited 300 ms is noise next to the game that
//! waited 40. So once a second this records WHICH PROCESS owns the foreground window - the process
//! ID and nothing else. Window titles and class names are never read: a title is whatever the
//! program chose to show (a document name, a web page, a chat), and reports get posted in public.
//!
//! Sources:
//! * `GetForegroundWindow`: "Retrieves a handle to the foreground window (the window with which
//!   the user is currently working)" and "The foreground window can be NULL in certain
//!   circumstances, such as when a window is losing activation."
//!   <https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getforegroundwindow>
//! * `GetWindowThreadProcessId`: returns the creating thread's id, "If the window handle is
//!   invalid, the return value is zero", and "If the function fails, the value of the variable is
//!   unchanged" - so the process id starts at 0 and is only trusted when the call succeeded.
//!   <https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getwindowthreadprocessid>
//!
//! NOT documented, and so never assumed: what `GetForegroundWindow` returns while the screen is
//! locked or a UAC prompt is on the secure desktop, and whether an elevated process (this tool
//! runs elevated) sees a non-elevated foreground window. A null window, a failed call, a process
//! id of 0 or the lock screen's own process is recorded as UNKNOWN, and unknown is never turned
//! into a name.
//!
//! Cost: one thread asleep 999 ms of every second, two user32 calls per wake-up and a 16-byte
//! record. That is below anything the cost block can resolve, so the cost block does not list it.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use windows_sys::Win32::System::Console::GetConsoleWindow;
use windows_sys::Win32::UI::WindowsAndMessaging::{GetForegroundWindow, GetWindowThreadProcessId};

use crate::procs::windows_part;
use crate::util::{ms_to_ticks, qpc};

/// What was in front at one sample.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Front {
    /// The process that owns the foreground window.
    Pid(u32),
    /// This tool's own window (or console). The person looking at the tool is not "the program
    /// they were using" at the hitch: they came here to press "I felt it".
    Own,
    /// No foreground window, or none that could be attributed. Never guessed.
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sample {
    /// QPC, the clock the kernel trace is on.
    pub ts: i64,
    pub front: Front,
}

pub type Log = Arc<Mutex<Vec<Sample>>>;

/// How often the foreground is sampled.
pub const SAMPLE_MS: u64 = 1000;
/// Samples kept: 55 hours at one a second, 3.2 MB. Past that the oldest half goes.
const MAX_SAMPLES: usize = 200_000;
/// A sample older than this before the moment asked about says nothing about that moment: one
/// period plus half of one for a late wake-up.
pub const STALE_MS: f64 = 1500.0;

/// Starts the sampler thread. It exits within a second of `stop` being set.
pub fn spawn(stop: Arc<AtomicBool>) -> Log {
    let log: Log = Arc::default();
    let out = log.clone();
    let own = std::process::id();
    let _ = std::thread::Builder::new().name("foreground".into()).spawn(move || {
        while !stop.load(Ordering::Relaxed) {
            let s = Sample { ts: qpc(), front: sample_now(own) };
            let mut v = out.lock().unwrap_or_else(|e| e.into_inner());
            if v.len() >= MAX_SAMPLES {
                v.drain(..MAX_SAMPLES / 2);
            }
            v.push(s);
            drop(v);
            std::thread::sleep(Duration::from_millis(SAMPLE_MS));
        }
    });
    log
}

/// The process that owns the foreground window right now. Process id only.
pub fn sample_now(own_pid: u32) -> Front {
    let hwnd = unsafe { GetForegroundWindow() };
    if hwnd.is_null() {
        return Front::Unknown;
    }
    // This process's console, when it has one (wtfis-cli in a classic console window). A console
    // hosted by Windows Terminal is that program's window and is named as such.
    // https://learn.microsoft.com/en-us/windows/console/getconsolewindow
    let console = unsafe { GetConsoleWindow() };
    if !console.is_null() && console == hwnd {
        return Front::Own;
    }
    let mut pid = 0u32;
    let tid = unsafe { GetWindowThreadProcessId(hwnd, &mut pid) };
    classify(tid, pid, own_pid)
}

/// The two numbers `GetWindowThreadProcessId` hands back, read honestly.
fn classify(tid: u32, pid: u32, own_pid: u32) -> Front {
    match (tid, pid) {
        (0, _) | (_, 0) => Front::Unknown,
        (_, p) if p == own_pid => Front::Own,
        (_, p) => Front::Pid(p),
    }
}

/// The process that was in front at `at`, looking back no further than `from` (and never more
/// than `STALE_MS` before whichever is earlier). `samples` in time order.
///
/// This tool's own window is skipped: someone who clicked "I felt it!" brought the tool to the
/// front to do so, and what they were using is the sample before. An unknown sample is NOT
/// skipped: if the newest thing known before the moment is "nothing could be attributed", the
/// answer is `None`, not whatever was in front before that.
pub fn in_front(samples: &[Sample], from: i64, at: i64) -> Option<u32> {
    let floor = from.min(at) - ms_to_ticks(STALE_MS);
    let upto = samples.partition_point(|s| s.ts <= at);
    for s in samples[..upto].iter().rev() {
        if s.ts < floor {
            break;
        }
        match s.front {
            Front::Own => continue,
            Front::Pid(p) => return Some(p),
            Front::Unknown => return None,
        }
    }
    None
}

/// Programs that are in front without being a program someone is using. The lock screen's own
/// process is one: when it is in front, the person was not using anything. It is only described
/// by Microsoft in community answers, not in documentation, so this is kept to that one name.
/// <https://learn.microsoft.com/en-us/answers/questions/4261566/lockapp-exe-is-suspended>
const NOT_IN_USE: &[&str] = &["lockapp.exe"];

/// Whether a program name can stand for "what the person was using" at all.
pub fn usable(name: &str) -> bool {
    let lower = name.to_lowercase();
    !(NOT_IN_USE.contains(&lower.as_str())
        || lower.starts_with("system")
        || lower.starts_with("idle")
        || lower.starts_with("unknown")
        || lower.starts_with("pid "))
}

/// What the foreground program is, for the wording below.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Program,
    /// explorer.exe: the desktop, the taskbar or a File Explorer window.
    Shell,
    /// Some other part of Windows (see `procs::windows_part`).
    Windows,
}

fn kind(name: &str) -> Kind {
    if name.eq_ignore_ascii_case("explorer.exe") {
        Kind::Shell
    } else if windows_part(name) {
        Kind::Windows
    } else {
        Kind::Program
    }
}

/// "the program you were using, game.exe", for the start of a sentence about it. Never words a
/// part of Windows as a program: explorer.exe in front means the desktop or File Explorer.
pub fn subject(name: &str) -> String {
    match kind(name) {
        Kind::Program => format!("the program you were using, {name}"),
        Kind::Shell => format!("what you were using, the Windows desktop or File Explorer ({name})"),
        Kind::Windows => format!("what you were using, {name} (part of Windows)"),
    }
}

/// "the program you were using", for "(..., at 2 of them)" after a name that is already shown
/// with "(part of Windows)" where that applies, so this never repeats it in brackets.
pub fn role(name: &str) -> &'static str {
    match kind(name) {
        Kind::Program => "the program you were using",
        Kind::Shell => "what you were using: the Windows desktop or File Explorer",
        Kind::Windows => "what you were using",
    }
}

/// `subject` with a capital letter, to open a sentence.
pub fn subject_capitalized(name: &str) -> String {
    let s = subject(name);
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
        None => s,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(x: f64) -> i64 {
        ms_to_ticks(x)
    }

    fn at(t_ms: f64, front: Front) -> Sample {
        Sample { ts: ms(t_ms), front }
    }

    #[test]
    fn a_failed_or_empty_answer_is_unknown_and_our_own_window_is_ours() {
        assert_eq!(classify(0, 1234, 99), Front::Unknown, "invalid window: the pid variable was left alone");
        assert_eq!(classify(55, 0, 99), Front::Unknown, "no process");
        assert_eq!(classify(55, 99, 99), Front::Own);
        assert_eq!(classify(55, 1234, 99), Front::Pid(1234));
    }

    /// One sample a second: the moment asked about is answered by the newest sample before it,
    /// never by one after it, and never by one so old it says nothing.
    #[test]
    fn the_program_in_front_is_the_newest_sample_before_the_moment() {
        let s = [at(1000.0, Front::Pid(10)), at(2000.0, Front::Pid(20)), at(3000.0, Front::Pid(30))];
        assert_eq!(in_front(&s, ms(2500.0), ms(2500.0)), Some(20));
        assert_eq!(in_front(&s, ms(2000.0), ms(2000.0)), Some(20), "a sample at the instant counts");
        assert_eq!(in_front(&s, ms(900.0), ms(900.0)), None, "nothing recorded yet");
        assert_eq!(in_front(&s, ms(9000.0), ms(9000.0)), None, "the sampler stopped: stale, not guessed");
        assert_eq!(in_front(&[], 0, ms(1.0)), None);
    }

    /// Clicking "I felt it!" brings this tool to the front; the program before it is the answer.
    #[test]
    fn this_tools_own_window_is_skipped_back_to_what_was_in_front_before_it() {
        let s = [at(1000.0, Front::Pid(4242)), at(2000.0, Front::Own), at(3000.0, Front::Own)];
        assert_eq!(in_front(&s, ms(0.0), ms(3000.0)), Some(4242));
        // ...but only within the window asked about.
        assert_eq!(in_front(&s, ms(3000.0), ms(3000.0)), None, "only this tool in the last 1.5 s");
    }

    /// A locked screen or a UAC prompt reads as unknown, and unknown is never papered over with
    /// whatever happened to be in front before it.
    #[test]
    fn an_unknown_sample_is_an_answer_and_is_never_replaced_by_an_older_name() {
        let s = [at(1000.0, Front::Pid(4242)), at(2000.0, Front::Unknown)];
        assert_eq!(in_front(&s, ms(0.0), ms(2500.0)), None);
        let s = [at(1000.0, Front::Unknown), at(2000.0, Front::Own)];
        assert_eq!(in_front(&s, ms(0.0), ms(2500.0)), None);
    }

    #[test]
    fn windows_components_in_front_are_never_worded_as_a_program() {
        assert_eq!(subject("game.exe"), "the program you were using, game.exe");
        assert_eq!(subject("explorer.exe"), "what you were using, the Windows desktop or File Explorer (explorer.exe)");
        assert_eq!(subject("Explorer.EXE"), "what you were using, the Windows desktop or File Explorer (Explorer.EXE)");
        assert_eq!(subject("svchost.exe"), "what you were using, svchost.exe (part of Windows)");
        assert_eq!(subject_capitalized("game.exe"), "The program you were using, game.exe");
        for name in ["explorer.exe", "svchost.exe", "dwm.exe", "System"] {
            assert!(!subject(name).contains("program"), "{name}: {}", subject(name));
            assert!(!role(name).contains("program"), "{name}: {}", role(name));
        }
        assert_eq!(role("game.exe"), "the program you were using");
    }

    #[test]
    fn the_lock_screen_and_unnamed_processes_are_not_what_anyone_was_using() {
        assert!(usable("game.exe") && usable("explorer.exe"));
        for name in ["LockApp.exe", "System (kernel threads)", "Idle", "unknown (exited thread)", "pid 1234 (exited)"] {
            assert!(!usable(name), "{name}");
        }
    }

    /// Reads this PC's foreground once. Nothing is asserted: a CI runner has no desktop at all,
    /// and what a test process sees depends on who launched it.
    #[test]
    fn sampling_the_foreground_here_does_not_panic() {
        println!("foreground now: {:?} (this process is {})", sample_now(std::process::id()), std::process::id());
    }
}
