//! Window front end: one Start/Stop button, a result banner, and the report.
//!
//! Deliberately plain Win32 controls: no GPU rendering and no repaint loop, so the tool
//! doesn't disturb the very latencies it measures. Follows the system light/dark app theme.
//!
//! While monitoring, the "I felt it!" button (or the Ctrl+Shift+F9 global hotkey) marks the
//! moment a hitch was felt so the report can zoom in on it.
//!
//! Environment switches for working on the UI without admin rights:
//! * `WTFIS_SKIP_ELEVATION=1`  don't ask for elevation (real monitoring then fails)
//! * `WTFIS_DEMO=problem|warning|ok`  Start/Stop shows a canned result instead of monitoring
//! * `WTFIS_THEME=dark|light`  override the system theme
#![windows_subsystem = "windows"]

use std::ffi::c_void;
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};

use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, RECT, WPARAM};
use windows_sys::Win32::Graphics::Dwm::DwmSetWindowAttribute;
use windows_sys::Win32::Graphics::Gdi::{
    BeginPaint, CreateFontW, CreateSolidBrush, DeleteObject, DrawTextW, EndPaint, FillRect, InvalidateRect, RedrawWindow, SelectObject,
    SetBkColor, SetBkMode, SetTextColor, UpdateWindow, DT_END_ELLIPSIS, DT_LEFT, DT_NOPREFIX, DT_SINGLELINE, DT_WORDBREAK, HBRUSH, HDC,
    PAINTSTRUCT, RDW_ALLCHILDREN, RDW_ERASE, RDW_FRAME, RDW_INVALIDATE, TRANSPARENT,
};
use windows_sys::Win32::System::DataExchange::{CloseClipboard, EmptyClipboard, OpenClipboard, SetClipboardData};
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress, LoadLibraryW};
use windows_sys::Win32::System::Memory::{GlobalAlloc, GlobalLock, GlobalUnlock, GMEM_MOVEABLE};
use windows_sys::Win32::System::Registry::{RegGetValueW, HKEY_CURRENT_USER, RRF_RT_REG_DWORD};
use windows_sys::Win32::UI::Controls::{
    InitCommonControlsEx, SetWindowTheme, EM_REPLACESEL, EM_SCROLLCARET, EM_SETLIMITTEXT, EM_SETSEL, ICC_STANDARD_CLASSES,
    INITCOMMONCONTROLSEX,
};
use windows_sys::Win32::UI::HiDpi::{GetDpiForSystem, GetDpiForWindow, GetSystemMetricsForDpi};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
    EnableWindow, RegisterHotKey, SetFocus, UnregisterHotKey, MOD_CONTROL, MOD_NOREPEAT, MOD_SHIFT, VK_F9,
};
use windows_sys::Win32::UI::Shell::ShellExecuteW;
use windows_sys::Win32::UI::WindowsAndMessaging::*;

use wtfis::engine::{self, Config};
use wtfis::summary::{Health, Summary};
use wtfis::util::{self, wide};

const ID_TOGGLE: usize = 1;
const ID_COPY: usize = 2;
const ID_SHOW: usize = 3;
const ID_MARK: usize = 4;

const HOTKEY_MARK: i32 = 1;

const WM_APP_LINES: u32 = WM_APP + 1;
const WM_APP_STATUS: u32 = WM_APP + 2;
const WM_APP_DONE: u32 = WM_APP + 3;

const CF_UNICODETEXT: u32 = 13;

const INTRO: &str = "How to use\r\n\
    \r\n\
    \x20 1. Click \"Start monitoring\".\r\n\
    \x20 2. Use the PC normally until the hitch / stall / audio crackle happens, ideally a few times.\r\n\
    \x20    (Run the game or app that has the problem. A few minutes is usually enough.)\r\n\
    \x20    Felt one? Press Ctrl+Shift+F9 (works inside games) or click \"I felt it!\" so the report can\r\n\
    \x20    zoom in on that exact moment.\r\n\
    \x20 3. Click \"Stop\". The colored bar above names the driver, program or hardware responsible,\r\n\
    \x20    and the report below says what to do about it.\r\n\
    \r\n\
    \x20 \"Copy report\" puts the whole report on the clipboard so it can be pasted to whoever is helping you.\r\n\
    \r\n\
    This tool only observes. It changes nothing on the system.";

// ---- Theme -----------------------------------------------------------------------------

const fn rgb(r: u32, g: u32, b: u32) -> u32 {
    r | (g << 8) | (b << 16)
}

#[derive(Clone, Copy, PartialEq)]
enum Tone {
    Neutral,
    Info,
    Ok,
    Warning,
    Problem,
}

struct Palette {
    window: u32,
    text: u32,
    subtext: u32,
    field: u32,
    /// Scroll bar track, for the square where the report's two scroll bars meet.
    track: u32,
}

const LIGHT: Palette = Palette {
    window: rgb(243, 243, 243),
    text: rgb(26, 26, 26),
    subtext: rgb(70, 70, 70),
    field: rgb(255, 255, 255),
    track: rgb(240, 240, 240),
};
const DARK: Palette = Palette {
    window: rgb(32, 32, 32),
    text: rgb(236, 236, 236),
    subtext: rgb(190, 190, 190),
    field: rgb(24, 24, 24),
    track: rgb(23, 23, 23),
};

/// (banner background, accent) per tone.
fn tone_colors(tone: Tone, dark: bool) -> (u32, u32) {
    match (tone, dark) {
        (Tone::Neutral, false) => (rgb(232, 232, 232), rgb(120, 120, 120)),
        (Tone::Neutral, true) => (rgb(44, 44, 44), rgb(150, 150, 150)),
        (Tone::Info, false) => (rgb(222, 236, 252), rgb(0, 95, 184)),
        (Tone::Info, true) => (rgb(18, 40, 64), rgb(96, 205, 255)),
        (Tone::Ok, false) => (rgb(223, 246, 221), rgb(15, 110, 15)),
        (Tone::Ok, true) => (rgb(20, 48, 26), rgb(108, 203, 95)),
        (Tone::Warning, false) => (rgb(255, 244, 206), rgb(150, 85, 0)),
        (Tone::Warning, true) => (rgb(60, 46, 10), rgb(252, 205, 90)),
        (Tone::Problem, false) => (rgb(253, 231, 233), rgb(190, 35, 25)),
        (Tone::Problem, true) => (rgb(66, 22, 26), rgb(255, 140, 150)),
    }
}

static DARK_MODE: AtomicBool = AtomicBool::new(false);
/// Brushes handed back from WM_CTLCOLOR*; they must outlive the message.
static WINDOW_BRUSH: AtomicIsize = AtomicIsize::new(0);
static FIELD_BRUSH: AtomicIsize = AtomicIsize::new(0);
static TRACK_BRUSH: AtomicIsize = AtomicIsize::new(0);

fn palette() -> &'static Palette {
    if DARK_MODE.load(Ordering::Relaxed) {
        &DARK
    } else {
        &LIGHT
    }
}

fn system_wants_dark() -> bool {
    match std::env::var("WTFIS_THEME").as_deref() {
        Ok("dark") => return true,
        Ok("light") => return false,
        _ => {}
    }
    let mut value = 1u32;
    let mut size = 4u32;
    let rc = unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            wide(r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize").as_ptr(),
            wide("AppsUseLightTheme").as_ptr(),
            RRF_RT_REG_DWORD,
            null_mut(),
            &mut value as *mut u32 as *mut c_void,
            &mut size,
        )
    };
    rc == 0 && value == 0
}

/// Lets common controls (buttons, scroll bars) pick up their dark visual styles. This is
/// uxtheme's SetPreferredAppMode, exported by ordinal only; every dark-mode Win32 app relies
/// on it. Absent (pre-1903) the controls simply stay light.
fn allow_dark_controls() {
    unsafe {
        let lib = LoadLibraryW(wide("uxtheme.dll").as_ptr());
        if lib.is_null() {
            return;
        }
        if let Some(f) = GetProcAddress(lib, 135 as *const u8) {
            let set_preferred_app_mode: unsafe extern "system" fn(i32) -> i32 = std::mem::transmute(f);
            // ForceDark/ForceLight when overridden for UI work, otherwise AllowDark (follow system).
            set_preferred_app_mode(match std::env::var("WTFIS_THEME").as_deref() {
                Ok("dark") => 2,
                Ok("light") => 3,
                _ => 1,
            });
        }
    }
}

unsafe fn apply_theme(hwnd: HWND) {
    let dark = system_wants_dark();
    DARK_MODE.store(dark, Ordering::Relaxed);
    let p = palette();
    for (slot, color) in [(&WINDOW_BRUSH, p.window), (&FIELD_BRUSH, p.field), (&TRACK_BRUSH, p.track)] {
        let old = slot.swap(CreateSolidBrush(color) as isize, Ordering::Relaxed);
        if old != 0 {
            DeleteObject(old as _);
        }
    }
    const DWMWA_USE_IMMERSIVE_DARK_MODE: u32 = 20;
    let flag = dark as i32;
    DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, &flag as *const i32 as *const c_void, 4);
    if let Some(ui) = UI.get() {
        let theme = wide(if dark { "DarkMode_Explorer" } else { "Explorer" });
        for h in [ui.toggle, ui.copy, ui.show, ui.mark, ui.log] {
            SetWindowTheme(h as HWND, theme.as_ptr(), null());
        }
    }
    RedrawWindow(hwnd, null(), null_mut(), RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN | RDW_FRAME);
}

// ---- State -----------------------------------------------------------------------------

/// Window and font handles, stored as integers so they can live in a static.
struct Ui {
    toggle: usize,
    copy: usize,
    show: usize,
    mark: usize,
    status: usize,
    log: usize,
    /// Covers the square between the report's scroll bars, which Windows leaves light in dark mode.
    corner: usize,
    headline_font: isize,
    sub_font: isize,
}

struct Banner {
    tone: Tone,
    headline: String,
    sub: String,
}

static UI: OnceLock<Ui> = OnceLock::new();
static MAIN: AtomicUsize = AtomicUsize::new(0);
static STOP: AtomicBool = AtomicBool::new(false);
static RUNNING: AtomicBool = AtomicBool::new(false);
static CLOSING: AtomicBool = AtomicBool::new(false);
static HOTKEY_OK: AtomicBool = AtomicBool::new(false);
static MARKS: AtomicUsize = AtomicUsize::new(0);

static BANNER: Mutex<Banner> = Mutex::new(Banner { tone: Tone::Neutral, headline: String::new(), sub: String::new() });
/// Lines from the engine thread waiting to be appended by the UI thread.
static PENDING: Mutex<Vec<String>> = Mutex::new(Vec::new());
static STATUS: Mutex<String> = Mutex::new(String::new());
/// What "Copy report" copies: the live log while running, the answer-first report afterwards.
static REPORT: Mutex<String> = Mutex::new(String::new());
static OUTCOME: Mutex<Option<Result<engine::RunOutput, String>>> = Mutex::new(None);
static REPORT_PATH: Mutex<Option<String>> = Mutex::new(None);

fn post(msg: u32) {
    let hwnd = MAIN.load(Ordering::SeqCst) as HWND;
    if !hwnd.is_null() {
        unsafe { PostMessageW(hwnd, msg, 0, 0) };
    }
}

fn set_text(hwnd: usize, text: &str) {
    unsafe { SetWindowTextW(hwnd as HWND, wide(text).as_ptr()) };
}

fn set_banner(hwnd: HWND, tone: Tone, headline: &str, sub: &str) {
    *BANNER.lock().unwrap() = Banner { tone, headline: headline.into(), sub: sub.into() };
    unsafe { InvalidateRect(hwnd, &banner_rect(hwnd), 0) };
}

fn append_log(ui: &Ui, text: &str) {
    let log = ui.log as HWND;
    unsafe {
        SendMessageW(log, EM_SETSEL, usize::MAX, -1);
        SendMessageW(log, EM_REPLACESEL, 0, wide(text).as_ptr() as LPARAM);
        SendMessageW(log, EM_SCROLLCARET, 0, 0);
    }
}

fn demo_health() -> Option<Health> {
    match std::env::var("WTFIS_DEMO").as_deref() {
        Ok("problem") => Some(Health::Problem),
        Ok("warning") => Some(Health::Warning),
        Ok("ok") => Some(Health::Ok),
        _ => None,
    }
}

fn start_monitoring(hwnd: HWND, ui: &Ui) {
    STOP.store(false, Ordering::SeqCst);
    RUNNING.store(true, Ordering::SeqCst);
    MARKS.store(0, Ordering::SeqCst);
    REPORT.lock().unwrap().clear();
    *REPORT_PATH.lock().unwrap() = None;
    set_text(ui.log, "");
    set_text(ui.toggle, "Stop && show result");
    unsafe {
        EnableWindow(ui.copy as HWND, 0);
        EnableWindow(ui.show as HWND, 0);
        EnableWindow(ui.mark as HWND, 1);
        let ok = RegisterHotKey(hwnd, HOTKEY_MARK, MOD_CONTROL | MOD_SHIFT | MOD_NOREPEAT, VK_F9 as u32) != 0;
        HOTKEY_OK.store(ok, Ordering::SeqCst);
    }
    set_text(
        ui.status,
        if HOTKEY_OK.load(Ordering::SeqCst) {
            "Felt a hitch? Press Ctrl+Shift+F9, even in a game."
        } else {
            "Felt a hitch? Click \"I felt it!\" right away."
        },
    );
    set_banner(hwnd, Tone::Info, "Monitoring - reproduce the hitch now", "Starting...");
    std::thread::spawn(|| {
        let outcome = match demo_health() {
            Some(health) => {
                while !STOP.load(Ordering::SeqCst) {
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                let summary = Summary::demo(health);
                // Same composer as a real run, so what is tested here is what users see.
                let header = [format!("WTFIsStalling {} - demo data", env!("CARGO_PKG_VERSION"))];
                let events = ["[21:14:07.412] STALL #1  kernel-level (DPC/ISR/firmware)  11.80 ms  on CPU 4".to_string()];
                let report = engine::compose_report(&header, &summary, &events);
                Ok(engine::RunOutput { log_path: None, report, summary })
            }
            None => engine::run(&Config::default(), &STOP),
        };
        *OUTCOME.lock().unwrap() = Some(outcome);
        post(WM_APP_DONE);
    });
}

fn request_stop(ui: &Ui) {
    STOP.store(true, Ordering::SeqCst);
    set_text(ui.toggle, "Stopping...");
    unsafe {
        EnableWindow(ui.toggle as HWND, 0);
        EnableWindow(ui.mark as HWND, 0);
    }
}

/// Record that the user felt a hitch right now, while monitoring is actually running.
fn mark(ui: &Ui) {
    if RUNNING.load(Ordering::SeqCst) && !STOP.load(Ordering::SeqCst) {
        engine::mark_now();
        let n = MARKS.fetch_add(1, Ordering::SeqCst) + 1;
        set_text(ui.status, &format!("Marked ({n}). The report will show what happened just before each mark."));
    }
}

/// Replace the live log with the answer-first report and light up the banner.
fn show_outcome(hwnd: HWND, ui: &Ui) {
    // Whatever is still queued belongs to the run that just ended.
    unsafe { SendMessageW(hwnd, WM_APP_LINES, 0, 0) };
    set_text(ui.toggle, "Start monitoring");
    unsafe {
        UnregisterHotKey(hwnd, HOTKEY_MARK);
        EnableWindow(ui.toggle as HWND, 1);
        EnableWindow(ui.copy as HWND, 1);
        EnableWindow(ui.mark as HWND, 0);
    }
    match OUTCOME.lock().unwrap().take() {
        Some(Ok(out)) => {
            let s = &out.summary;
            let (tone, headline) = match s.health {
                Health::Problem => (Tone::Problem, format!("Cause found:  {}", s.headline)),
                Health::Warning => (Tone::Warning, format!("Suspect:  {}", s.headline)),
                Health::Ok => (Tone::Ok, s.headline.clone()),
                Health::NoData => (Tone::Warning, s.headline.clone()),
            };
            set_banner(hwnd, tone, &headline, &s.subline);
            set_text(ui.log, &out.report);
            *REPORT.lock().unwrap() = out.report;
            if let Some(path) = out.log_path {
                unsafe { EnableWindow(ui.show as HWND, 1) };
                set_text(ui.status, &format!("Saved to {path}"));
                *REPORT_PATH.lock().unwrap() = Some(path);
            }
        }
        Some(Err(e)) => set_banner(hwnd, Tone::Problem, "Monitoring could not run", &e),
        None => {}
    }
}

fn copy_report(hwnd: HWND) {
    let text = wide(&REPORT.lock().unwrap());
    unsafe {
        if OpenClipboard(hwnd) == 0 {
            return;
        }
        EmptyClipboard();
        let mem = GlobalAlloc(GMEM_MOVEABLE, text.len() * 2);
        if !mem.is_null() {
            let dst = GlobalLock(mem) as *mut u16;
            if !dst.is_null() {
                std::ptr::copy_nonoverlapping(text.as_ptr(), dst, text.len());
                GlobalUnlock(mem);
                SetClipboardData(CF_UNICODETEXT, mem);
            }
        }
        CloseClipboard();
    }
}

fn show_report_file() {
    if let Some(path) = REPORT_PATH.lock().unwrap().as_ref() {
        unsafe {
            ShellExecuteW(
                null_mut(),
                wide("open").as_ptr(),
                wide("explorer.exe").as_ptr(),
                wide(&format!("/select,\"{path}\"")).as_ptr(),
                null(),
                SW_SHOWNORMAL,
            );
        }
    }
}

// ---- Window ----------------------------------------------------------------------------

unsafe fn make_font(face: &str, points: i32, weight: i32, dpi: u32) -> isize {
    const CLEARTYPE_QUALITY: u32 = 5;
    CreateFontW(-(points * dpi as i32 / 72), 0, 0, 0, weight, 0, 0, 0, 1, 0, 0, CLEARTYPE_QUALITY, 0, wide(face).as_ptr()) as isize
}

unsafe fn create_controls(hwnd: HWND) {
    let dpi = GetDpiForWindow(hwnd);
    let ui_font = make_font("Segoe UI", 9, 400, dpi);
    let button_font = make_font("Segoe UI", 11, 600, dpi);
    let mono_font = make_font("Consolas", 10, 400, dpi);
    let hinst = GetModuleHandleW(null());

    let child = |class: &str, text: &str, style: u32, ex: u32, id: usize, font: isize| -> usize {
        let h = CreateWindowExW(
            ex,
            wide(class).as_ptr(),
            wide(text).as_ptr(),
            WS_CHILD | WS_VISIBLE | style,
            0,
            0,
            10,
            10,
            hwnd,
            id as HMENU,
            hinst,
            null(),
        );
        SendMessageW(h, WM_SETFONT, font as WPARAM, 1);
        h as usize
    };

    const BS_DEFPUSHBUTTON: u32 = 0x1;
    const ES_MULTILINE: u32 = 0x4;
    const ES_AUTOVSCROLL: u32 = 0x40;
    const ES_AUTOHSCROLL: u32 = 0x80;
    const ES_READONLY: u32 = 0x800;
    const SS_ENDELLIPSIS: u32 = 0x4000;
    const SS_RIGHT: u32 = 0x2;

    let ui = Ui {
        toggle: child("BUTTON", "Start monitoring", WS_TABSTOP | BS_DEFPUSHBUTTON, 0, ID_TOGGLE, button_font),
        copy: child("BUTTON", "Copy report", WS_TABSTOP | WS_DISABLED, 0, ID_COPY, ui_font),
        show: child("BUTTON", "Show report file", WS_TABSTOP | WS_DISABLED, 0, ID_SHOW, ui_font),
        mark: child("BUTTON", "I felt it!", WS_TABSTOP | WS_DISABLED, 0, ID_MARK, button_font),
        status: child("STATIC", "", SS_ENDELLIPSIS | SS_RIGHT, 0, 0, ui_font),
        log: child(
            "EDIT",
            INTRO,
            WS_TABSTOP | WS_CLIPSIBLINGS | WS_VSCROLL | WS_HSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_AUTOHSCROLL | ES_READONLY,
            0,
            0,
            mono_font,
        ),
        corner: child("STATIC", "", WS_CLIPSIBLINGS, 0, 0, ui_font),
        headline_font: make_font("Segoe UI", 15, 600, dpi),
        sub_font: make_font("Segoe UI", 10, 400, dpi),
    };
    SendMessageW(ui.log as HWND, EM_SETLIMITTEXT, 64 << 20, 0);
    SetWindowPos(ui.corner as HWND, HWND_TOP, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
    SetFocus(ui.toggle as HWND);
    let _ = UI.set(ui);
    set_banner(hwnd, Tone::Neutral, "Ready", "Press Start monitoring, then reproduce the problem.");
}

fn scale(hwnd: HWND, v: i32) -> i32 {
    v * unsafe { GetDpiForWindow(hwnd) } as i32 / 96
}

fn banner_rect(hwnd: HWND) -> RECT {
    let mut rc: RECT = unsafe { std::mem::zeroed() };
    unsafe { GetClientRect(hwnd, &mut rc) };
    let m = scale(hwnd, 12);
    let top = m + scale(hwnd, 40) + m;
    RECT { left: m, top, right: rc.right - m, bottom: top + scale(hwnd, 86) }
}

unsafe fn layout(hwnd: HWND, ui: &Ui) {
    let mut rc: RECT = std::mem::zeroed();
    GetClientRect(hwnd, &mut rc);
    let s = |v: i32| scale(hwnd, v);
    let (w, h, m) = (rc.right, rc.bottom, s(12));
    let (toggle_w, side_w, row_h) = (s(230), s(130), s(40));
    MoveWindow(ui.toggle as HWND, m, m, toggle_w, row_h, 1);
    let show_x = w - m - side_w;
    let copy_x = show_x - s(8) - side_w;
    MoveWindow(ui.show as HWND, show_x, m + s(6), side_w, row_h - s(12), 1);
    MoveWindow(ui.copy as HWND, copy_x, m + s(6), side_w, row_h - s(12), 1);
    let mark_x = m + toggle_w + s(8);
    let mark_w = s(150);
    MoveWindow(ui.mark as HWND, mark_x, m, mark_w, row_h, 1);
    let status_x = mark_x + mark_w + m;
    MoveWindow(ui.status as HWND, status_x, m + s(12), (copy_x - m - status_x).max(0), s(20), 1);
    let top = banner_rect(hwnd).bottom + m;
    MoveWindow(ui.log as HWND, m, top, (w - 2 * m).max(0), (h - top - m).max(0), 1);
    let dpi = GetDpiForWindow(hwnd);
    let (bar_w, bar_h) = (GetSystemMetricsForDpi(SM_CXVSCROLL, dpi), GetSystemMetricsForDpi(SM_CYHSCROLL, dpi));
    MoveWindow(ui.corner as HWND, w - m - bar_w, h - m - bar_h, bar_w, bar_h, 1);
    InvalidateRect(hwnd, null(), 1);
}

unsafe fn fill(hdc: HDC, rc: &RECT, color: u32) {
    let brush = CreateSolidBrush(color);
    FillRect(hdc, rc, brush);
    DeleteObject(brush as _);
}

unsafe fn paint(hwnd: HWND, ui: &Ui) {
    let mut ps: PAINTSTRUCT = std::mem::zeroed();
    let hdc = BeginPaint(hwnd, &mut ps);
    let p = palette();
    let mut client: RECT = std::mem::zeroed();
    GetClientRect(hwnd, &mut client);
    fill(hdc, &client, p.window);

    let banner = BANNER.lock().unwrap();
    let (bg, accent) = tone_colors(banner.tone, DARK_MODE.load(Ordering::Relaxed));
    let rc = banner_rect(hwnd);
    fill(hdc, &rc, bg);
    fill(hdc, &RECT { right: rc.left + scale(hwnd, 6), ..rc }, accent);

    SetBkMode(hdc, TRANSPARENT as _);
    let pad = scale(hwnd, 18);
    let mut head =
        RECT { left: rc.left + pad, top: rc.top + scale(hwnd, 9), right: rc.right - scale(hwnd, 10), bottom: rc.top + scale(hwnd, 40) };
    let old = SelectObject(hdc, ui.headline_font as _);
    SetTextColor(hdc, accent);
    DrawTextW(hdc, wide(&banner.headline).as_ptr(), -1, &mut head, DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX);
    let mut sub = RECT { top: head.bottom + scale(hwnd, 2), bottom: rc.bottom - scale(hwnd, 6), ..head };
    SelectObject(hdc, ui.sub_font as _);
    SetTextColor(hdc, p.text);
    DrawTextW(hdc, wide(&banner.sub).as_ptr(), -1, &mut sub, DT_LEFT | DT_WORDBREAK | DT_END_ELLIPSIS | DT_NOPREFIX);
    SelectObject(hdc, old);
    EndPaint(hwnd, &ps);
}

unsafe fn is_theme_change(lp: LPARAM) -> bool {
    const NAME: &str = "ImmersiveColorSet";
    lp != 0 && util::from_wide(std::slice::from_raw_parts(lp as *const u16, NAME.len() + 1)) == NAME
}

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    let ui = UI.get();
    match (msg, ui) {
        (WM_CREATE, _) => {
            MAIN.store(hwnd as usize, Ordering::SeqCst);
            create_controls(hwnd);
            apply_theme(hwnd);
        }
        (WM_SIZE, Some(ui)) => layout(hwnd, ui),
        (WM_GETMINMAXINFO, _) => {
            let mmi = &mut *(lp as *mut MINMAXINFO);
            mmi.ptMinTrackSize.x = scale(hwnd, 780);
            mmi.ptMinTrackSize.y = scale(hwnd, 420);
        }
        (WM_DPICHANGED, _) => {
            let r = &*(lp as *const RECT);
            SetWindowPos(hwnd, null_mut(), r.left, r.top, r.right - r.left, r.bottom - r.top, SWP_NOZORDER | SWP_NOACTIVATE);
        }
        // Windows broadcasts this when the user flips light/dark mode.
        (WM_SETTINGCHANGE, _) if is_theme_change(lp) => apply_theme(hwnd),
        (WM_ERASEBKGND, _) => return 1, // WM_PAINT covers the whole client area
        (WM_PAINT, Some(ui)) => paint(hwnd, ui),
        // The read-only report box and the status label.
        (WM_CTLCOLORSTATIC | WM_CTLCOLOREDIT, Some(ui)) => {
            if lp as usize == ui.corner {
                return TRACK_BRUSH.load(Ordering::Relaxed) as HBRUSH as LRESULT;
            }
            let p = palette();
            let is_log = lp as usize == ui.log;
            SetTextColor(wp as HDC, if is_log { p.text } else { p.subtext });
            SetBkColor(wp as HDC, if is_log { p.field } else { p.window });
            return if is_log { &FIELD_BRUSH } else { &WINDOW_BRUSH }.load(Ordering::Relaxed) as HBRUSH as LRESULT;
        }
        (WM_COMMAND, Some(ui)) => match wp & 0xFFFF {
            ID_TOGGLE if RUNNING.load(Ordering::SeqCst) => request_stop(ui),
            ID_TOGGLE => start_monitoring(hwnd, ui),
            ID_COPY => {
                copy_report(hwnd);
                set_text(ui.status, "Report copied to the clipboard.");
            }
            ID_SHOW => show_report_file(),
            ID_MARK => mark(ui),
            _ => {}
        },
        (WM_HOTKEY, Some(ui)) if wp as i32 == HOTKEY_MARK => mark(ui),
        (WM_APP_LINES, Some(ui)) => {
            let lines = std::mem::take(&mut *PENDING.lock().unwrap());
            if !lines.is_empty() {
                let mut text = lines.join("\r\n");
                text.push_str("\r\n");
                REPORT.lock().unwrap().push_str(&text);
                append_log(ui, &text);
            }
        }
        (WM_APP_STATUS, _) if RUNNING.load(Ordering::SeqCst) => {
            BANNER.lock().unwrap().sub = STATUS.lock().unwrap().clone();
            InvalidateRect(hwnd, &banner_rect(hwnd), 0);
        }
        (WM_APP_DONE, Some(ui)) => {
            RUNNING.store(false, Ordering::SeqCst);
            if CLOSING.load(Ordering::SeqCst) {
                DestroyWindow(hwnd);
                return 0;
            }
            show_outcome(hwnd, ui);
        }
        (WM_CLOSE, Some(ui)) if RUNNING.load(Ordering::SeqCst) => {
            // The kernel trace session must be shut down first; WM_APP_DONE finishes the close.
            CLOSING.store(true, Ordering::SeqCst);
            request_stop(ui);
        }
        (WM_DESTROY, _) => PostQuitMessage(0),
        _ => return DefWindowProcW(hwnd, msg, wp, lp),
    }
    0
}

fn message_box(text: &str, flags: u32) {
    unsafe { MessageBoxW(null_mut(), wide(text).as_ptr(), wide("WTFIsStalling").as_ptr(), flags) };
}

fn main() {
    engine::run_probe_child_if_requested();

    let skip_elevation = std::env::var_os("WTFIS_SKIP_ELEVATION").is_some() || demo_health().is_some();
    if !engine::is_elevated() && !skip_elevation {
        if !engine::relaunch_elevated(&[]) {
            message_box(
                "WTFIsStalling needs administrator rights to trace the Windows kernel (that is how it sees drivers \
                 and interrupts).\n\nStart it again and choose Yes at the permission prompt.",
                MB_OK | MB_ICONINFORMATION,
            );
        }
        return;
    }

    util::set_line_sink(Box::new(|line| {
        PENDING.lock().unwrap().push(line.to_string());
        post(WM_APP_LINES);
    }));
    util::set_status_sink(Box::new(|text| {
        *STATUS.lock().unwrap() = text.to_string();
        post(WM_APP_STATUS);
    }));

    allow_dark_controls();
    unsafe {
        let icc = INITCOMMONCONTROLSEX { dwSize: std::mem::size_of::<INITCOMMONCONTROLSEX>() as u32, dwICC: ICC_STANDARD_CLASSES };
        InitCommonControlsEx(&icc);

        let hinst = GetModuleHandleW(null());
        let class = wide("WTFIsStallingMain");
        let wc = WNDCLASSW {
            style: CS_HREDRAW | CS_VREDRAW,
            lpfnWndProc: Some(wndproc),
            cbClsExtra: 0,
            cbWndExtra: 0,
            hInstance: hinst,
            hIcon: LoadIconW(null_mut(), IDI_APPLICATION),
            hCursor: LoadCursorW(null_mut(), IDC_ARROW),
            hbrBackground: null_mut(),
            lpszMenuName: null(),
            lpszClassName: class.as_ptr(),
        };
        RegisterClassW(&wc);

        let dpi = GetDpiForSystem() as i32;
        let hwnd = CreateWindowExW(
            0,
            class.as_ptr(),
            wide(&format!("WTFIsStalling {} - what is stalling this PC?", env!("CARGO_PKG_VERSION"))).as_ptr(),
            WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            1080 * dpi / 96,
            760 * dpi / 96,
            null_mut(),
            null_mut(),
            hinst,
            null(),
        );
        if hwnd.is_null() {
            message_box("Could not create the main window.", MB_OK | MB_ICONERROR);
            return;
        }
        ShowWindow(hwnd, SW_SHOWNORMAL);
        UpdateWindow(hwnd);

        let mut msg: MSG = std::mem::zeroed();
        while GetMessageW(&mut msg, null_mut(), 0, 0) > 0 {
            if IsDialogMessageW(hwnd, &msg) == 0 {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
    }
}
