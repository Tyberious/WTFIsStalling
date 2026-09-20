//! PID -> process name. Snapshots are cumulative so processes that already exited by the
//! time an incident is analyzed can still be named.

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
