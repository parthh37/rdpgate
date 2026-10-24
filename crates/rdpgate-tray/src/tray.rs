//! The icon in the notification area. It runs as the signed-in person,
//! without Administrator rights: asking the service manager for the
//! service's state needs none, and RDP Gate Server asks for them itself when
//! it opens.

use crate::icon::{self, Level};
use crate::watch::{Note, Watch};
use rdpgate_server::service::{self, Status};
use rdpgate_server::updater::WINDOW_EXE;
use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::{Duration, Instant, SystemTime};
use windows_sys::Win32::Foundation::{CloseHandle, ERROR_ALREADY_EXISTS, GetLastError, HWND, LPARAM, LRESULT, WPARAM};
use windows_sys::Win32::Graphics::Gdi::{
    BI_RGB, BITMAPINFO, BITMAPINFOHEADER, CreateBitmap, CreateDIBSection, DIB_RGB_COLORS, DeleteObject, GetDC, ReleaseDC,
};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows_sys::Win32::System::Threading::{
    CreateMutexW, GetCurrentProcessId, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
};
use windows_sys::Win32::UI::Shell::{
    NIF_ICON, NIF_INFO, NIF_MESSAGE, NIF_SHOWTIP, NIF_TIP, NIIF_INFO, NIIF_WARNING, NIM_ADD, NIM_DELETE, NIM_MODIFY,
    NIM_SETVERSION, NIN_SELECT, NOTIFYICON_VERSION_4, NOTIFYICONDATAW, ShellExecuteW, Shell_NotifyIconW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    AppendMenuW, CreateIconIndirect, CreatePopupMenu, CreateWindowExW, DefWindowProcW, DestroyIcon, DestroyMenu,
    DestroyWindow, DispatchMessageW, EnumWindows, KillTimer, GetMessageW, GetSystemMetrics, GetWindowThreadProcessId, HICON,
    ICONINFO, IsIconic, IsWindowVisible, MB_ICONERROR, MB_OK, MF_DISABLED, MF_SEPARATOR, MF_STRING, MSG, MessageBoxW,
    PostMessageW, PostQuitMessage, RegisterClassW, RegisterWindowMessageW, SM_CXSMICON, SM_MENUDROPALIGNMENT, SW_HIDE,
    SW_RESTORE, SW_SHOWNORMAL, SetForegroundWindow, SetMenuDefaultItem, SetTimer, ShowWindow, TPM_BOTTOMALIGN,
    TPM_LEFTALIGN, TPM_NONOTIFY, TPM_RETURNCMD, TPM_RIGHTALIGN, TPM_RIGHTBUTTON, TrackPopupMenu, TranslateMessage,
    WM_APP, WM_CONTEXTMENU, WM_DESTROY, WM_NULL, WM_TIMER, WNDCLASSW, WS_OVERLAPPED,
};

/// How often the service's state is checked, like the window's refresh.
const POLL: Duration = Duration::from_secs(3);
/// The shell's messages about the icon (clicks, the menu key).
const WM_TRAY: u32 = WM_APP + 1;
/// Enter or Space on the icon (NIN_SELECT | NINF_KEY).
const NIN_KEYSELECT: u32 = NIN_SELECT | 1;
/// RDP Gate Server asks for Administrator rights as it opens; don't stack
/// up several of those prompts from a double-click.
const OPEN_AGAIN_AFTER: Duration = Duration::from_secs(3);
const ID_OPEN: usize = 1;
const ID_START: usize = 2;
const ID_EXIT: usize = 3;

/// The shell's "TaskbarCreated" broadcast: Explorer restarted, so the icon
/// has to be added again.
static TASKBAR_CREATED: AtomicU32 = AtomicU32::new(0);
/// Set when this program was updated: start the new copy once this one has gone.
static RELAUNCH: AtomicBool = AtomicBool::new(false);

thread_local! {
    static TRAY: RefCell<Option<Tray>> = const { RefCell::new(None) };
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain([0]).collect()
}

fn wide_path(p: &Path) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    p.as_os_str().encode_wide().chain([0]).collect()
}

/// Copies `s` into a fixed-size, zero-filled field, keeping its terminator.
fn fill(field: &mut [u16], s: &str) {
    let room = field.len() - 1;
    for (d, c) in field[..room].iter_mut().zip(s.encode_utf16()) {
        *d = c;
    }
}

fn message_box(text: &str) {
    let (text, title) = (wide(text), wide("RDP Gate"));
    unsafe { MessageBoxW(null_mut(), text.as_ptr(), title.as_ptr(), MB_OK | MB_ICONERROR) };
}

fn level(s: Status) -> Level {
    match s {
        Status::Running => Level::Good,
        Status::Starting | Status::Stopping => Level::Busy,
        Status::Stopped | Status::NotInstalled => Level::Bad,
        Status::Unknown => Level::Unknown,
    }
}

/// The service's state, as the first line of the menu.
fn describe(s: Status) -> &'static str {
    match s {
        Status::Running => "RDP Gate service is running",
        Status::Starting => "RDP Gate service is starting…",
        Status::Stopping => "RDP Gate service is stopping…",
        Status::Stopped => "RDP Gate service is stopped: nobody can sign in",
        Status::NotInstalled => "RDP Gate service isn't installed",
        Status::Unknown => "RDP Gate service: state unknown",
    }
}

/// Makes the icon for `level` at the size the taskbar uses.
fn make_icon(level: Level) -> HICON {
    let size = unsafe { GetSystemMetrics(SM_CXSMICON) }.clamp(16, 256);
    let pixels = icon::render(size as usize, level);
    let mut info: BITMAPINFO = unsafe { std::mem::zeroed() };
    info.bmiHeader = BITMAPINFOHEADER {
        biSize: size_of::<BITMAPINFOHEADER>() as u32,
        biWidth: size,
        biHeight: -size, // top row first
        biPlanes: 1,
        biBitCount: 32,
        biCompression: BI_RGB,
        ..unsafe { std::mem::zeroed() }
    };
    unsafe {
        let mut bits = null_mut();
        let dc = GetDC(null_mut());
        let color = CreateDIBSection(dc, &info, DIB_RGB_COLORS, &mut bits, null_mut(), 0);
        ReleaseDC(null_mut(), dc);
        if color.is_null() || bits.is_null() {
            return null_mut();
        }
        std::ptr::copy_nonoverlapping(pixels.as_ptr(), bits.cast::<u8>(), pixels.len());
        // The alpha channel says what's see-through; the mask only has to exist.
        let mask_row = (size as usize).div_ceil(16) * 2;
        let mask_bits = vec![0u8; mask_row * size as usize];
        let mask = CreateBitmap(size, size, 1, 1, mask_bits.as_ptr().cast());
        let icon = CreateIconIndirect(&ICONINFO { fIcon: 1, xHotspot: 0, yHotspot: 0, hbmMask: mask, hbmColor: color });
        DeleteObject(color);
        DeleteObject(mask);
        icon
    }
}

struct Tray {
    hwnd: HWND,
    /// This program, to notice when an update replaces it.
    exe: PathBuf,
    built: Option<SystemTime>,
    status: Option<Status>,
    icon: HICON,
    icon_level: Option<Level>,
    added: bool,
    watch: Watch,
    opened: Option<Instant>,
}

impl Tray {
    fn data(&self) -> NOTIFYICONDATAW {
        let mut n: NOTIFYICONDATAW = unsafe { std::mem::zeroed() };
        n.cbSize = size_of::<NOTIFYICONDATAW>() as u32;
        n.hWnd = self.hwnd;
        n.uID = 1;
        n
    }

    /// Adds the icon, or brings it up to date.
    fn show(&mut self) {
        let mut n = self.data();
        n.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP | NIF_SHOWTIP;
        n.uCallbackMessage = WM_TRAY;
        n.hIcon = self.icon;
        let state = self.status.map_or("RDP Gate service: checking…", describe);
        fill(&mut n.szTip, &format!("RDP Gate Server\n{}", state.trim_start_matches("RDP Gate service ")));
        if self.added {
            // Fails if Explorer went away without telling: add it again next time.
            self.added = unsafe { Shell_NotifyIconW(NIM_MODIFY, &n) } != 0;
        } else if unsafe { Shell_NotifyIconW(NIM_ADD, &n) } != 0 {
            n.Anonymous.uVersion = NOTIFYICON_VERSION_4;
            unsafe { Shell_NotifyIconW(NIM_SETVERSION, &n) };
            self.added = true;
        }
    }

    fn remove(&mut self) {
        if self.added {
            unsafe { Shell_NotifyIconW(NIM_DELETE, &self.data()) };
            self.added = false;
        }
    }

    fn notify(&self, title: &str, body: &str, warning: bool) {
        let mut n = self.data();
        n.uFlags = NIF_INFO;
        fill(&mut n.szInfoTitle, title);
        fill(&mut n.szInfo, body);
        n.dwInfoFlags = if warning { NIIF_WARNING } else { NIIF_INFO };
        unsafe { Shell_NotifyIconW(NIM_MODIFY, &n) };
    }

    /// True when an update has put a new copy of this program in place.
    fn replaced(&self) -> bool {
        let now = std::fs::metadata(&self.exe).and_then(|m| m.modified()).ok();
        self.built.is_some() && now.is_some() && now != self.built
    }

    /// Checks the service and updates the icon. Returns true to quit (so the
    /// updated copy can start).
    fn poll(&mut self) -> bool {
        if self.replaced() {
            return true;
        }
        let status = service::status();
        let level = level(status);
        let changed = self.status != Some(status);
        self.status = Some(status);
        if self.icon_level != Some(level) || self.icon.is_null() {
            let old = std::mem::replace(&mut self.icon, make_icon(level));
            self.icon_level = Some(level);
            self.show();
            if !old.is_null() {
                unsafe { DestroyIcon(old) };
            }
        } else if changed || !self.added {
            self.show();
        }
        match self.watch.update(level, Instant::now()) {
            Some(Note::Down) if status == Status::NotInstalled => self.notify(
                "RDP Gate service isn't installed",
                "Nobody can sign in to this PC. Run RDP Gate Server Setup again to install it.",
                true,
            ),
            Some(Note::Down) => self.notify(
                "RDP Gate service stopped",
                "Nobody can sign in to this PC until it runs again. Windows normally restarts it within a few minutes; to start it now, right-click the RDP Gate icon.",
                true,
            ),
            Some(Note::Up) => self.notify("RDP Gate service is running again", "Your computers can sign in again.", false),
            None => {}
        }
        false
    }
}

/// Runs `f` on the tray's state. Skipped (None) if the state is already in
/// use further up: the shell can call back while a call to it is waiting.
fn with<R>(f: impl FnOnce(&mut Tray) -> R) -> Option<R> {
    TRAY.with(|t| t.try_borrow_mut().ok().and_then(|mut t| t.as_mut().map(f)))
}

fn server_dir() -> PathBuf {
    std::env::current_exe().ok().and_then(|p| p.parent().map(Path::to_path_buf)).unwrap_or_default()
}

/// The RDP Gate Server window that's already open, if there is one.
fn find_window() -> Option<HWND> {
    unsafe extern "system" fn each(hwnd: HWND, found: LPARAM) -> windows_sys::core::BOOL {
        unsafe {
            if IsWindowVisible(hwnd) == 0 {
                return 1;
            }
            let mut pid = 0;
            GetWindowThreadProcessId(hwnd, &mut pid);
            let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if process.is_null() {
                return 1;
            }
            let mut name = [0u16; 1024];
            let mut len = name.len() as u32;
            let ok = QueryFullProcessImageNameW(process, 0, name.as_mut_ptr(), &mut len) != 0;
            CloseHandle(process);
            let path = String::from_utf16_lossy(&name[..len as usize]);
            let file = path.rsplit('\\').next().unwrap_or_default();
            if ok && file.eq_ignore_ascii_case(WINDOW_EXE) {
                *(found as *mut HWND) = hwnd;
                return 0;
            }
            1
        }
    }
    let mut found: HWND = null_mut();
    unsafe { EnumWindows(Some(each), &mut found as *mut HWND as LPARAM) };
    (!found.is_null()).then_some(found)
}

fn open_window(hwnd: HWND) {
    let now = Instant::now();
    let go = with(|t| {
        let again = t.opened.is_none_or(|at| now.duration_since(at) >= OPEN_AGAIN_AFTER);
        if again {
            t.opened = Some(now);
        }
        again
    });
    if go != Some(true) {
        return;
    }
    if let Some(w) = find_window() {
        unsafe {
            if IsIconic(w) != 0 {
                ShowWindow(w, SW_RESTORE);
            }
            SetForegroundWindow(w);
        }
        return;
    }
    let dir = server_dir();
    let (file, dir_w, verb) = (wide_path(&dir.join(WINDOW_EXE)), wide_path(&dir), wide("open"));
    let r = unsafe { ShellExecuteW(hwnd, verb.as_ptr(), file.as_ptr(), null(), dir_w.as_ptr(), SW_SHOWNORMAL) } as isize;
    // 2 and 3: file or folder not found. Other failures include saying No
    // to the Administrator prompt, which needs no message.
    if r == 2 || r == 3 {
        message_box(&format!("{WINDOW_EXE} is missing from {}. Run RDP Gate Server Setup again to repair it.", dir.display()));
    }
}

/// Starts the service through rdpgate-server, which asks for Administrator rights.
fn start_service(hwnd: HWND) {
    let dir = server_dir();
    let (file, dir_w) = (wide_path(&dir.join("rdpgate-server.exe")), wide_path(&dir));
    let (verb, args) = (wide("runas"), wide("service-start"));
    unsafe { ShellExecuteW(hwnd, verb.as_ptr(), file.as_ptr(), args.as_ptr(), dir_w.as_ptr(), SW_HIDE) };
    // Show "starting…" soon rather than at the next regular check.
    unsafe { SetTimer(hwnd, 2, 1500, None) };
}

fn menu(hwnd: HWND, x: i32, y: i32) {
    let Some(status) = with(|t| t.status) else { return };
    let status = status.unwrap_or(Status::Unknown);
    unsafe {
        let m = CreatePopupMenu();
        let header = wide(describe(status));
        AppendMenuW(m, MF_STRING | MF_DISABLED, 0, header.as_ptr());
        AppendMenuW(m, MF_SEPARATOR, 0, null());
        let open = wide("Open RDP Gate Server");
        AppendMenuW(m, MF_STRING, ID_OPEN, open.as_ptr());
        SetMenuDefaultItem(m, ID_OPEN as u32, 0);
        let start = wide("Start the service");
        if status == Status::Stopped {
            AppendMenuW(m, MF_STRING, ID_START, start.as_ptr());
        }
        AppendMenuW(m, MF_SEPARATOR, 0, null());
        let exit = wide("Hide this icon until next sign-in");
        AppendMenuW(m, MF_STRING, ID_EXIT, exit.as_ptr());

        // Without this the menu stays open after clicking elsewhere.
        SetForegroundWindow(hwnd);
        let align = if GetSystemMetrics(SM_MENUDROPALIGNMENT) != 0 { TPM_RIGHTALIGN } else { TPM_LEFTALIGN };
        let flags = TPM_RETURNCMD | TPM_NONOTIFY | TPM_RIGHTBUTTON | TPM_BOTTOMALIGN | align;
        let picked = TrackPopupMenu(m, flags, x, y, 0, hwnd, null()) as usize;
        PostMessageW(hwnd, WM_NULL, 0, 0);
        DestroyMenu(m);
        match picked {
            ID_OPEN => open_window(hwnd),
            ID_START => start_service(hwnd),
            ID_EXIT => {
                DestroyWindow(hwnd);
            }
            _ => {}
        }
    }
}

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    match msg {
        WM_TIMER => {
            if wparam == 2 {
                unsafe { KillTimer(hwnd, 2) };
            }
            if with(Tray::poll) == Some(true) {
                RELAUNCH.store(true, Ordering::Relaxed);
                unsafe { DestroyWindow(hwnd) };
            }
            0
        }
        WM_TRAY => {
            // Version 4: the event in the low word of lparam, and where to put
            // a menu in wparam (signed x and y).
            match (lparam & 0xffff) as u32 {
                NIN_SELECT | NIN_KEYSELECT => open_window(hwnd),
                WM_CONTEXTMENU => menu(hwnd, (wparam & 0xffff) as i16 as i32, ((wparam >> 16) & 0xffff) as i16 as i32),
                _ => {}
            }
            0
        }
        WM_DESTROY => {
            with(Tray::remove);
            unsafe { PostQuitMessage(0) };
            0
        }
        m if m != 0 && m == TASKBAR_CREATED.load(Ordering::Relaxed) => {
            with(|t| {
                t.added = false;
                // The taskbar may have a new icon size.
                t.icon_level = None;
                t.poll()
            });
            0
        }
        _ => unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) },
    }
}

pub fn main() {
    rdpgate_core::update::cleanup_previous();
    // Session 0 has no desktop to show an icon on (Setup run as SYSTEM, say).
    let mut session = 0;
    if unsafe { ProcessIdToSessionId(GetCurrentProcessId(), &mut session) } != 0 && session == 0 {
        return;
    }
    // One icon per signed-in person.
    let name = wide("Local\\RDPGate.Tray");
    let mutex = unsafe { CreateMutexW(null(), 0, name.as_ptr()) };
    if mutex.is_null() || unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
        return;
    }

    let class = wide("RDPGate.Tray");
    let hwnd = unsafe {
        let instance = GetModuleHandleW(null());
        let mut wc: WNDCLASSW = std::mem::zeroed();
        wc.lpfnWndProc = Some(wndproc);
        wc.hInstance = instance;
        wc.lpszClassName = class.as_ptr();
        RegisterClassW(&wc);
        // Never shown: it only receives the shell's messages about the icon.
        let title = wide("RDP Gate");
        CreateWindowExW(0, class.as_ptr(), title.as_ptr(), WS_OVERLAPPED, 0, 0, 0, 0, null_mut(), null_mut(), instance, null())
    };
    if hwnd.is_null() {
        unsafe { CloseHandle(mutex) };
        return;
    }
    let taskbar = wide("TaskbarCreated");
    TASKBAR_CREATED.store(unsafe { RegisterWindowMessageW(taskbar.as_ptr()) }, Ordering::Relaxed);

    let exe = std::env::current_exe().unwrap_or_default();
    let built = std::fs::metadata(&exe).and_then(|m| m.modified()).ok();
    TRAY.with(|t| {
        *t.borrow_mut() = Some(Tray {
            hwnd,
            exe: exe.clone(),
            built,
            status: None,
            icon: null_mut(),
            icon_level: None,
            added: false,
            watch: Watch::default(),
            opened: None,
        })
    });
    // At sign-in the taskbar may not be ready yet; each check retries adding the icon.
    if with(Tray::poll) == Some(true) {
        RELAUNCH.store(true, Ordering::Relaxed);
        unsafe { DestroyWindow(hwnd) };
    }
    unsafe { SetTimer(hwnd, 1, POLL.as_millis() as u32, None) };

    unsafe {
        let mut msg: MSG = std::mem::zeroed();
        while GetMessageW(&mut msg, null_mut(), 0, 0) > 0 {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        CloseHandle(mutex);
    }
    if RELAUNCH.load(Ordering::Relaxed) {
        let _ = std::process::Command::new(exe).spawn();
    }
}
