use std::fs::File;
use std::io::Write;
use std::sync::{Mutex, OnceLock};

use windows_sys::Win32::System::Performance::{QueryPerformanceCounter, QueryPerformanceFrequency};
use windows_sys::Win32::System::SystemInformation::GetLocalTime;

static LOG: Mutex<Option<File>> = Mutex::new(None);

type Sink = Box<dyn Fn(&str) + Send>;
static LINE_SINK: Mutex<Option<Sink>> = Mutex::new(None);
static STATUS_SINK: Mutex<Option<Sink>> = Mutex::new(None);

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
}

pub fn status(s: &str) {
    if let Some(sink) = STATUS_SINK.lock().unwrap().as_ref() {
        sink(s);
    }
}

/// "20260920-001530", for report file names.
pub fn file_timestamp() -> String {
    let st = unsafe {
        let mut st = std::mem::zeroed();
        GetLocalTime(&mut st);
        st
    };
    format!("{:04}{:02}{:02}-{:02}{:02}{:02}", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond)
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
        let st = unsafe {
            let mut st = std::mem::zeroed();
            GetLocalTime(&mut st);
            st
        };
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
