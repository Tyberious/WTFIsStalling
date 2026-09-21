use std::fs::File;
use std::io::Write;
use std::mem::{size_of, zeroed};
use std::sync::{Mutex, OnceLock};

use windows_sys::Win32::System::Performance::{QueryPerformanceCounter, QueryPerformanceFrequency};
use windows_sys::Win32::System::SystemInformation::{GetLocalTime, GlobalMemoryStatusEx, MEMORYSTATUSEX};

static LOG: Mutex<Option<File>> = Mutex::new(None);

type Sink = Box<dyn Fn(&str) + Send>;
static LINE_SINK: Mutex<Option<Sink>> = Mutex::new(None);
static STATUS_SINK: Mutex<Option<Sink>> = Mutex::new(None);

/// While set, every emitted line is also kept so the final report can be recomposed.
static CAPTURE: Mutex<Option<Vec<String>>> = Mutex::new(None);

pub fn start_capture() {
    *CAPTURE.lock().unwrap() = Some(Vec::new());
}

pub fn capture_len() -> usize {
    CAPTURE.lock().unwrap().as_ref().map_or(0, Vec::len)
}

pub fn take_capture() -> Vec<String> {
    CAPTURE.lock().unwrap().take().unwrap_or_default()
}

pub fn set_log(f: Option<File>) {
    *LOG.lock().unwrap() = f;
}

/// Where report lines go instead of stdout (the GUI's log box).
pub fn set_line_sink(sink: Sink) {
    *LINE_SINK.lock().unwrap() = Some(sink);
}

/// Receives the once-a-second progress text. Without a sink it is dropped.
pub fn set_status_sink(sink: Sink) {
    *STATUS_SINK.lock().unwrap() = Some(sink);
}

/// Write a report line to the console or GUI and, if enabled, to the report file.
pub fn emit(s: &str) {
    match LINE_SINK.lock().unwrap().as_ref() {
        Some(sink) => sink(s),
        None => println!("{s}"),
    }
    if let Some(f) = LOG.lock().unwrap().as_mut() {
        let _ = writeln!(f, "{s}");
    }
    if let Some(lines) = CAPTURE.lock().unwrap().as_mut() {
        lines.push(s.to_string());
    }
}

pub fn status(s: &str) {
    if let Some(sink) = STATUS_SINK.lock().unwrap().as_ref() {
        sink(s);
    }
}

/// The local date and time, as Windows reports it.
pub fn local_time() -> windows_sys::Win32::Foundation::SYSTEMTIME {
    unsafe {
        let mut st = zeroed();
        GetLocalTime(&mut st);
        st
    }
}

/// Seconds since the Unix epoch, 0 if the clock is somehow before it. The Windows event log
/// timestamps are in these terms, so everything compared against them is too.
pub fn unix_now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64)
}

/// "" or "s": the suffix that makes a word agree with a count.
pub fn plural(n: u64) -> &'static str {
    if n == 1 {
        ""
    } else {
        "s"
    }
}

/// "20260920-001530", for report file names.
pub fn file_timestamp() -> String {
    let st = local_time();
    format!("{:04}{:02}{:02}-{:02}{:02}{:02}", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond)
}

/// "2026-09-20 00:15" (local), for showing when a saved run was made.
pub fn local_stamp() -> String {
    let st = local_time();
    format!("{:04}-{:02}-{:02} {:02}:{:02}", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute)
}

pub fn total_ram_bytes() -> u64 {
    let mut mem: MEMORYSTATUSEX = unsafe { zeroed() };
    mem.dwLength = size_of::<MEMORYSTATUSEX>() as u32;
    unsafe { GlobalMemoryStatusEx(&mut mem) };
    mem.ullTotalPhys
}

#[macro_export]
macro_rules! say {
    ($($a:tt)*) => { $crate::util::emit(&format!($($a)*)) };
}

pub fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

pub fn from_wide(w: &[u16]) -> String {
    let len = w.iter().position(|&c| c == 0).unwrap_or(w.len());
    String::from_utf16_lossy(&w[..len])
}

pub fn qpc() -> i64 {
    let mut v = 0i64;
    unsafe { QueryPerformanceCounter(&mut v) };
    v
}

pub fn qpc_freq() -> i64 {
    static FREQ: OnceLock<i64> = OnceLock::new();
    *FREQ.get_or_init(|| {
        let mut f = 0i64;
        unsafe { QueryPerformanceFrequency(&mut f) };
        f.max(1)
    })
}

pub fn ticks_to_ms(t: i64) -> f64 {
    t as f64 * 1000.0 / qpc_freq() as f64
}

pub fn ms_to_ticks(ms: f64) -> i64 {
    (ms * qpc_freq() as f64 / 1000.0) as i64
}

/// Human friendly duration from QPC ticks.
pub fn fmt_dur(t: i64) -> String {
    let ms = ticks_to_ms(t);
    if ms < 1.0 {
        format!("{:.0} µs", ms * 1000.0)
    } else if ms < 100.0 {
        format!("{ms:.2} ms")
    } else {
        format!("{ms:.0} ms")
    }
}

/// Maps QPC timestamps (which ETW and the probes share) to local wall-clock time.
pub struct WallClock {
    qpc0: i64,
    ms_of_day0: i64,
}

static CLOCK: OnceLock<WallClock> = OnceLock::new();

pub fn clock() -> &'static WallClock {
    CLOCK.get_or_init(|| {
        let st = local_time();
        WallClock {
            qpc0: qpc(),
            ms_of_day0: ((st.wHour as i64 * 60 + st.wMinute as i64) * 60 + st.wSecond as i64) * 1000 + st.wMilliseconds as i64,
        }
    })
}

impl WallClock {
    pub fn fmt(&self, ts: i64) -> String {
        let ms = (self.ms_of_day0 + ticks_to_ms(ts - self.qpc0) as i64).rem_euclid(86_400_000);
        format!("{:02}:{:02}:{:02}.{:03}", ms / 3_600_000, ms / 60_000 % 60, ms / 1000 % 60, ms % 1000)
    }
}
