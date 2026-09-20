//! Window front end: one Start/Stop button, a live log, and the summary when stopped.
//!
//! Deliberately plain Win32 controls: no GPU rendering and no repaint loop, so the tool
//! doesn't disturb the very latencies it measures.
#![windows_subsystem = "windows"]

use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};

use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, RECT, WPARAM};
use windows_sys::Win32::Graphics::Gdi::{
    CreateFontW, GetSysColor, GetSysColorBrush, SetBkColor, UpdateWindow, COLOR_BTNFACE, COLOR_WINDOW, HDC,
};
use windows_sys::Win32::System::DataExchange::{CloseClipboard, EmptyClipboard, OpenClipboard, SetClipboardData};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::Memory::{GlobalAlloc, GlobalLock, GlobalUnlock, GMEM_MOVEABLE};
use windows_sys::Win32::UI::Controls::{
    InitCommonControlsEx, EM_REPLACESEL, EM_SCROLLCARET, EM_SETLIMITTEXT, EM_SETSEL, ICC_STANDARD_CLASSES, INITCOMMONCONTROLSEX,
};
use windows_sys::Win32::UI::HiDpi::{GetDpiForSystem, GetDpiForWindow};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{EnableWindow, SetFocus};
use windows_sys::Win32::UI::Shell::ShellExecuteW;
use windows_sys::Win32::UI::WindowsAndMessaging::*;

use wtfis::engine::{self, Config};
use wtfis::util::{self, wide};

const ID_TOGGLE: usize = 1;
const ID_COPY: usize = 2;
const ID_SHOW: usize = 3;

const WM_APP_LINES: u32 = WM_APP + 1;
const WM_APP_STATUS: u32 = WM_APP + 2;
const WM_APP_DONE: u32 = WM_APP + 3;

const CF_UNICODETEXT: u32 = 13;

const INTRO: &str = "How to use\r\n\
    \r\n\
    \x20 1. Click \"Start monitoring\".\r\n\
    \x20 2. Use the PC normally until the hitch / stall / audio crackle happens, ideally a few times.\r\n\
    \x20    (Run the game or app that has the problem. A few minutes is usually enough.)\r\n\
    \x20 3. Click \"Stop\". The summary names the driver, program or hardware responsible\r\n\
    \x20    and suggests what to do about it.\r\n\
    \r\n\
    \x20 \"Copy report\" puts the whole report on the clipboard so it can be pasted to whoever is helping you.\r\n\
    \r\n\
    This tool only observes. It changes nothing on the system.";

/// Window handles, stored as integers so they can live in a static.
struct Ui {
    toggle: usize,
    copy: usize,
    show: usize,
    status: usize,
    log: usize,
}

static UI: OnceLock<Ui> = OnceLock::new();
static MAIN: AtomicUsize = AtomicUsize::new(0);
static STOP: AtomicBool = AtomicBool::new(false);
static RUNNING: AtomicBool = AtomicBool::new(false);
static CLOSING: AtomicBool = AtomicBool::new(false);
static FAILED: AtomicBool = AtomicBool::new(false);

/// Lines from the engine thread waiting to be appended by the UI thread.
static PENDING: Mutex<Vec<String>> = Mutex::new(Vec::new());
static STATUS: Mutex<String> = Mutex::new(String::new());
/// Everything shown in the log box for the current run (what "Copy report" copies).
static REPORT: Mutex<String> = Mutex::new(String::new());
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

fn append_log(ui: &Ui, text: &str) {
    let log = ui.log as HWND;
    unsafe {
        SendMessageW(log, EM_SETSEL, usize::MAX, -1);
        SendMessageW(log, EM_REPLACESEL, 0, wide(text).as_ptr() as LPARAM);
        SendMessageW(log, EM_SCROLLCARET, 0, 0);
    }
}

fn start_monitoring(ui: &Ui) {
    STOP.store(false, Ordering::SeqCst);
    FAILED.store(false, Ordering::SeqCst);
    RUNNING.store(true, Ordering::SeqCst);
    REPORT.lock().unwrap().clear();
    *REPORT_PATH.lock().unwrap() = None;
    set_text(ui.log, "");
    set_text(ui.toggle, "Stop && show summary");
    set_text(ui.status, "Starting...");
    unsafe {
        EnableWindow(ui.copy as HWND, 0);
        EnableWindow(ui.show as HWND, 0);
    }
    std::thread::spawn(|| {
        match engine::run(&Config::default(), &STOP) {
            Ok(path) => *REPORT_PATH.lock().unwrap() = path,
            Err(_) => FAILED.store(true, Ordering::SeqCst),
        }
        post(WM_APP_DONE);
    });
}

fn request_stop(ui: &Ui) {
    STOP.store(true, Ordering::SeqCst);
    set_text(ui.toggle, "Stopping...");
    unsafe { EnableWindow(ui.toggle as HWND, 0) };
}

fn copy_report(hwnd: HWND) {
    let text = wide(&REPORT.lock().unwrap());
    unsafe {
        if OpenClipboard(hwnd) == 0 {
            return;
        }
        EmptyClipboard();
        let bytes = text.len() * 2;
        let mem = GlobalAlloc(GMEM_MOVEABLE, bytes);
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

    let ui = Ui {
        toggle: child("BUTTON", "Start monitoring", WS_TABSTOP | BS_DEFPUSHBUTTON, 0, ID_TOGGLE, button_font),
        copy: child("BUTTON", "Copy report", WS_TABSTOP | WS_DISABLED, 0, ID_COPY, ui_font),
        show: child("BUTTON", "Show report file", WS_TABSTOP | WS_DISABLED, 0, ID_SHOW, ui_font),
        status: child("STATIC", "Ready. Nothing is being monitored.", 0, 0, 0, ui_font),
        log: child(
            "EDIT",
            INTRO,
            WS_TABSTOP | WS_VSCROLL | WS_HSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_AUTOHSCROLL | ES_READONLY,
            WS_EX_CLIENTEDGE,
            0,
            mono_font,
        ),
    };
    SendMessageW(ui.log as HWND, EM_SETLIMITTEXT, 64 << 20, 0);
    SetFocus(ui.toggle as HWND);
    let _ = UI.set(ui);
}

unsafe fn layout(hwnd: HWND, ui: &Ui) {
    let mut rc: RECT = std::mem::zeroed();
    GetClientRect(hwnd, &mut rc);
    let s = |v: i32| v * GetDpiForWindow(hwnd) as i32 / 96;
    let (w, h, m) = (rc.right, rc.bottom, s(12));
    let (toggle_w, side_w, row_h) = (s(230), s(130), s(40));
    MoveWindow(ui.toggle as HWND, m, m, toggle_w, row_h, 1);
    MoveWindow(ui.show as HWND, w - m - side_w, m + s(6), side_w, row_h - s(12), 1);
    MoveWindow(ui.copy as HWND, w - 2 * (m + side_w) + m - s(4), m + s(6), side_w, row_h - s(12), 1);
    let status_x = m + toggle_w + m;
    MoveWindow(ui.status as HWND, status_x, m + s(11), (w - 2 * (m + side_w) - status_x).max(0), s(20), 1);
    let top = m + row_h + m;
    MoveWindow(ui.log as HWND, m, top, (w - 2 * m).max(0), (h - top - m).max(0), 1);
}

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    let ui = UI.get();
    match (msg, ui) {
        (WM_CREATE, _) => {
            MAIN.store(hwnd as usize, Ordering::SeqCst);
            create_controls(hwnd);
        }
        (WM_SIZE, Some(ui)) => layout(hwnd, ui),
        (WM_GETMINMAXINFO, _) => {
            let mmi = &mut *(lp as *mut MINMAXINFO);
            let dpi = GetDpiForWindow(hwnd) as i32;
            mmi.ptMinTrackSize.x = 760 * dpi / 96;
            mmi.ptMinTrackSize.y = 360 * dpi / 96;
        }
        (WM_DPICHANGED, _) => {
            let r = &*(lp as *const RECT);
            SetWindowPos(hwnd, null_mut(), r.left, r.top, r.right - r.left, r.bottom - r.top, SWP_NOZORDER | SWP_NOACTIVATE);
        }
        // Read-only edits paint grey by default; a report reads better on white.
        (WM_CTLCOLORSTATIC, Some(ui)) if lp as usize == ui.log => {
            SetBkColor(wp as HDC, GetSysColor(COLOR_WINDOW));
            return GetSysColorBrush(COLOR_WINDOW) as LRESULT;
        }
        (WM_COMMAND, Some(ui)) => match wp & 0xFFFF {
            ID_TOGGLE if RUNNING.load(Ordering::SeqCst) => request_stop(ui),
            ID_TOGGLE => start_monitoring(ui),
            ID_COPY => {
                copy_report(hwnd);
                set_text(ui.status, "Report copied to the clipboard.");
            }
            ID_SHOW => show_report_file(),
            _ => {}
        },
        (WM_APP_LINES, Some(ui)) => {
            let lines = std::mem::take(&mut *PENDING.lock().unwrap());
            if !lines.is_empty() {
                let mut text = lines.join("\r\n");
                text.push_str("\r\n");
                REPORT.lock().unwrap().push_str(&text);
                append_log(ui, &text);
            }
        }
        (WM_APP_STATUS, Some(ui)) => set_text(ui.status, &STATUS.lock().unwrap()),
        (WM_APP_DONE, Some(ui)) => {
            RUNNING.store(false, Ordering::SeqCst);
            if CLOSING.load(Ordering::SeqCst) {
                DestroyWindow(hwnd);
                return 0;
            }
            // Flush anything still queued so the summary is complete before we say "done".
            SendMessageW(hwnd, WM_APP_LINES, 0, 0);
            set_text(ui.toggle, "Start monitoring");
            EnableWindow(ui.toggle as HWND, 1);
            EnableWindow(ui.copy as HWND, 1);
            match REPORT_PATH.lock().unwrap().as_ref() {
                _ if FAILED.load(Ordering::SeqCst) => set_text(ui.status, "Monitoring could not run. See the error below."),
                Some(path) => {
                    EnableWindow(ui.show as HWND, 1);
                    set_text(ui.status, &format!("Done. Report saved to {path}"));
                }
                None => set_text(ui.status, "Done."),
            }
        }
        (WM_CLOSE, Some(ui)) if RUNNING.load(Ordering::SeqCst) => {
            // The kernel trace session must be shut down first; WM_APP_DONE finishes the close.
            CLOSING.store(true, Ordering::SeqCst);
            request_stop(ui);
            set_text(ui.status, "Stopping the kernel trace before closing...");
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

    // WTFIS_SKIP_ELEVATION is for working on the UI itself; monitoring will fail without admin.
    if !engine::is_elevated() && std::env::var_os("WTFIS_SKIP_ELEVATION").is_none() {
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
            hbrBackground: GetSysColorBrush(COLOR_BTNFACE),
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
            1040 * dpi / 96,
            700 * dpi / 96,
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
