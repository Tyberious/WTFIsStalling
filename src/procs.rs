//! PID -> process name, and what the tool knows about the processes people do not recognize.
//! Snapshots are cumulative so processes that already exited by the time an incident is
//! analyzed can still be named.

use std::collections::HashMap;
use std::mem::{size_of, zeroed};
use std::time::Instant;

use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Threading::{GetProcessIdOfThread, OpenThread, THREAD_QUERY_LIMITED_INFORMATION};

use crate::state::PID_UNKNOWN;
use crate::util::from_wide;

pub struct ProcNames {
    names: HashMap<u32, String>,
    last_refresh: Instant,
}

impl Default for ProcNames {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcNames {
    pub fn new() -> ProcNames {
        let mut p = ProcNames { names: HashMap::new(), last_refresh: Instant::now() };
        p.refresh();
        p
    }

    /// Synthetic pid -> name table for tests: no live process snapshot, ever. `label()`
    /// only refreshes for a pid missing from the map, so tests must stick to pids listed here.
    #[cfg(test)]
    pub fn for_test(names: &[(u32, &str)]) -> ProcNames {
        ProcNames { names: names.iter().map(|(pid, name)| (*pid, name.to_string())).collect(), last_refresh: Instant::now() }
    }

    pub fn refresh(&mut self) {
        self.last_refresh = Instant::now();
        unsafe {
            let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if snap == INVALID_HANDLE_VALUE {
                return;
            }
            let mut pe: PROCESSENTRY32W = zeroed();
            pe.dwSize = size_of::<PROCESSENTRY32W>() as u32;
            let mut ok = Process32FirstW(snap, &mut pe);
            while ok != 0 {
                self.names.insert(pe.th32ProcessID, from_wide(&pe.szExeFile));
                ok = Process32NextW(snap, &mut pe);
            }
            CloseHandle(snap);
        }
    }

    pub fn refresh_if_older_than(&mut self, secs: u64) {
        if self.last_refresh.elapsed().as_secs() >= secs {
            self.refresh();
        }
    }

    /// `pid` may be PID_UNKNOWN, in which case the thread id is tried.
    pub fn label(&mut self, pid: u32, tid: u32) -> String {
        let pid = if pid == PID_UNKNOWN { pid_of_thread(tid).unwrap_or(PID_UNKNOWN) } else { pid };
        match pid {
            0 => "Idle".into(),
            4 => "System (kernel threads)".into(),
            PID_UNKNOWN => "unknown (exited thread)".into(),
            _ => {
                if !self.names.contains_key(&pid) {
                    self.refresh_if_older_than(1);
                }
                match self.names.get(&pid) {
                    Some(n) => format!("{n} ({pid})"),
                    None => format!("pid {pid} (exited)"),
                }
            }
        }
    }
}

/// Strips a well-formed trailing " (<digits>)" from a label, e.g. "steam.exe (1234)" ->
/// "steam.exe". Requires a closing parenthesis with at least one ASCII digit inside; a label
/// that happens to end in "()" or in an unclosed "(" is returned unchanged rather than silently
/// shortened.
pub fn strip_pid(label: &str) -> &str {
    match label.rsplit_once(" (") {
        Some((head, tail)) if tail.ends_with(')') && tail.len() > 1 && tail[..tail.len() - 1].bytes().all(|b| b.is_ascii_digit()) => head,
        _ => label,
    }
}

/// "steam.exe (1234)" -> "steam.exe", so several processes of one program add up, and so the
/// report never prints a process ID it does not need.
pub fn process_name(label: &str) -> String {
    strip_pid(label).to_string()
}

/// A process people do not recognize by file name: what it is doing, and the one thing that
/// actually controls it. `windows` = part of Windows, so "close it" or "pause it" is not advice.
pub struct Worker {
    pub what: &'static str,
    pub tip: &'static str,
    pub windows: bool,
}

const IDLE_TIP: &str = "Windows saves this work for when the PC is idle, so a PC that is switched off right after use never gets \
    it done: leave it on and untouched for an hour, then monitor again.";

pub fn known_worker(process: &str) -> Option<Worker> {
    let p = process.to_lowercase();
    let w = |what, tip, windows| Worker { what, tip, windows };
    let table: &[(&str, Worker)] = &[
        (
            "msmpeng",
            w(
                "Microsoft Defender antivirus scanning",
                "Let the scan finish. To keep it away from games: Windows Security > Virus & threat protection > Manage settings > \
                 Exclusions, add your game library folder.",
                true,
            ),
        ),
        (
            "searchindexer",
            w(
                "Windows Search indexing files",
                "It stops when the index is complete. To keep it off this drive: Settings > Privacy & security > Searching Windows, \
                 add the folder under 'Exclude folders'.",
                true,
            ),
        ),
        ("searchprotocolhost", w("Windows Search indexing files", IDLE_TIP, true)),
        ("tiworker", w("Windows Update installing", "Let the update finish, restart the PC, then monitor again.", true)),
        ("trustedinstaller", w("Windows Update installing", "Let the update finish, restart the PC, then monitor again.", true)),
        ("wuauclt", w("Windows Update", "Let the update finish, restart the PC, then monitor again.", true)),
        ("mousocoreworker", w("Windows Update", "Let the update finish, restart the PC, then monitor again.", true)),
        ("defrag", w("Windows drive optimization (defrag / TRIM)", IDLE_TIP, true)),
        ("compattelrunner", w("Windows telemetry", IDLE_TIP, true)),
        (
            "backgroundtaskhost",
            w(
                "Windows running a background task for a Store app or a Windows feature",
                "It normally finishes within minutes. If it keeps coming back: Settings > Apps > Installed apps > (the app) > Advanced \
                 options > 'Let this app run in background' = Never, for apps you do not need updating themselves.",
                true,
            ),
        ),
        (
            "vssvc",
            w("a backup or restore point being made", "Let it finish; move scheduled backups to a time you are not using the PC.", true),
        ),
        ("memcompression", w("Windows paging memory out", "The PC is short of memory: close memory-hungry programs or add RAM.", true)),
        ("system", w("Windows itself (file cache, paging or a driver)", IDLE_TIP, true)),
        (
            "dwm",
            w(
                "the desktop compositor that draws every window",
                "It is driven by the graphics driver: update or clean-reinstall that, and close overlays and screen recorders.",
                true,
            ),
        ),
        (
            "audiodg",
            w(
                "the Windows audio engine",
                "Update the audio driver and turn off audio enhancements (Sound settings > device > Enhancements).",
                true,
            ),
        ),
        (
            "wmiprvse",
            w(
                "a hardware-information service that monitoring tools query",
                "Something is polling it hard: fully exit RGB, fan-control and hardware-monitoring utilities one at a time.",
                true,
            ),
        ),
        ("csrss", w("a core Windows process", IDLE_TIP, true)),
        ("registry", w("a core Windows process", IDLE_TIP, true)),
        ("svchost", w("a Windows service", IDLE_TIP, true)),
        ("onedrive", w("OneDrive syncing", "Pause syncing from the OneDrive tray icon while you play.", false)),
        (
            "steam",
            w(
                "Steam downloading, updating or verifying a game",
                "Pause the download, or in Steam > Settings > Downloads turn off downloads during gameplay.",
                false,
            ),
        ),
        ("epicgameslauncher", w("Epic Games Launcher downloading or updating", "Pause the download while you play.", false)),
        ("battle.net", w("Battle.net downloading or updating", "Pause the download while you play.", false)),
    ];
    table.iter().find(|(k, _)| p.starts_with(k)).map(|(_, v)| Worker { ..*v })
}

/// Parts of Windows that can turn up doing disk work or in front of the person, beyond
/// `known_worker`'s table: none of them is something a person can close or run "one at a time".
const WINDOWS_PARTS: &[&str] = &[
    "explorer.exe",
    "lsass.exe",
    "services.exe",
    "wininit.exe",
    "winlogon.exe",
    "smss.exe",
    "sihost.exe",
    "runtimebroker.exe",
    "searchhost.exe",
    "fontdrvhost.exe",
    "ctfmon.exe",
    "taskhostw.exe",
    "spoolsv.exe",
    "memory compression",
];

/// Is this program name a part of Windows (never to be worded as something to close)?
pub fn windows_part(name: &str) -> bool {
    let lower = name.to_lowercase();
    name.starts_with("System") || known_worker(name).is_some_and(|w| w.windows) || WINDOWS_PARTS.contains(&lower.as_str())
}

pub fn pid_of_thread(tid: u32) -> Option<u32> {
    if tid == 0 {
        return Some(0);
    }
    unsafe {
        let h = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, 0, tid);
        if h.is_null() {
            return None;
        }
        let pid = GetProcessIdOfThread(h);
        CloseHandle(h);
        (pid != 0).then_some(pid)
    }
}

#[cfg(test)]
mod strip_pid_tests {
    use super::strip_pid;

    #[test]
    fn strips_only_well_formed_trailing_pid() {
        assert_eq!(strip_pid("chrome.exe (1234)"), "chrome.exe");
        assert_eq!(strip_pid("odd ()"), "odd ()");
        assert_eq!(strip_pid("a (12"), "a (12");
        assert_eq!(strip_pid("App (x86) (77)"), "App (x86)");
        assert_eq!(strip_pid("plain"), "plain");
    }
}
