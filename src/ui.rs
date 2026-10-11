//! Native Win32 GUI (native-windows-gui)
use std::cell::{Cell, RefCell};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use native_windows_gui as nwg;
use nwg::{ControlHandle, Event};

use crate::pgp_ops;
use crate::secure_store::{self, Credentials};
use crate::shell_ext;
use crate::window_state;

const TITLE: &str = "MyPgpDecrypt";
const KEY_FILE_PLACEHOLDER: &str = "[바이너리 키 파일을 불러왔습니다]";
/// First line of the (non-secret) text shown in the key box while a key is already saved.
const SAVED_KEY_MARK: &str = "[저장된 개인 키 사용 중]";

/// What the settings window knows about the stored credentials (never the secrets themselves).
enum SavedState {
    None,
    Unreadable,
    Saved { info: String },
}

fn saved_state() -> SavedState {
    match secure_store::load() {
        Ok(None) => SavedState::None,
        Err(_) => SavedState::Unreadable,
        Ok(Some(creds)) => {
            let info = match pgp_ops::parse_secret_key(&creds.key) {
                Ok(key) => {
                    let users = pgp_ops::key_user_ids(&key);
                    format!(
                        "{SAVED_KEY_MARK}\r\n\r\nFingerprint: {}\r\n사용자: {}\r\n암호: 저장됨\r\n\r\n다른 키로 바꾸려면 이 내용을 지우고 새 키를 붙여넣거나 [키 파일 선택] 버튼을 누르세요.\r\n암호만 바꾸려면 아래 암호 칸에 새 암호를 입력하고 저장하세요.",
                        pgp_ops::key_summary(&key),
                        if users.is_empty() { "(없음)".to_string() } else { users.join(", ") },
                    )
                }
                Err(_) => format!("{SAVED_KEY_MARK}\r\n\r\n(키 정보를 읽을 수 없습니다. 새 키를 입력해 다시 저장하세요.)"),
            };
            SavedState::Saved { info }
        }
    }
}

/// Initialise NWG (idempotent enough for our single call path); needed before any window/dialog.
pub fn init() -> bool {
    if nwg::init().is_err() {
        return false;
    }
    nwg::enable_visual_styles();
    let mut font = nwg::Font::default();
    if nwg::Font::builder().family("Segoe UI").size(18).build(&mut font).is_ok() {
        nwg::Font::set_global_default(Some(font));
    }
    true
}

/// GUI entry: main window (drag & drop) without files, otherwise decrypt the given files.
pub fn run(files: Vec<PathBuf>) {
    if !init() {
        return;
    }
    if files.is_empty() {
        run_main_window();
    } else {
        process_files(files, None);
    }
}

pub fn show_info(msg: &str) {
    info(msg);
}

pub fn show_error(msg: &str) {
    error(msg);
}

/// `size` in `WindowBuilder` is the *outer* size (title bar and borders included), so controls placed near the bottom would be cut off on a real Windows desktop.
/// Resize so that the usable client area is exactly `client` (in the same logical units as the control positions).
fn fit_client_area(window: &nwg::Window, client: (i32, i32)) {
    use windows::Win32::Foundation::{HWND, RECT};
    use windows::Win32::UI::WindowsAndMessaging::{
        GetClientRect, GetWindowRect, SetWindowPos, SWP_NOACTIVATE, SWP_NOMOVE, SWP_NOZORDER,
    };

    let Some(hwnd) = window.handle.hwnd() else { return };
    let hwnd = HWND(hwnd as _);
    let (mut outer, mut inner) = (RECT::default(), RECT::default());
    unsafe {
        if GetWindowRect(hwnd, &mut outer).is_err() || GetClientRect(hwnd, &mut inner).is_err() {
            return;
        }
        let scale = nwg::scale_factor();
        let frame_w = (outer.right - outer.left) - (inner.right - inner.left);
        let frame_h = (outer.bottom - outer.top) - (inner.bottom - inner.top);
        let w = (client.0 as f64 * scale).round() as i32 + frame_w;
        let h = (client.1 as f64 * scale).round() as i32 + frame_h;
        let _ = SetWindowPos(hwnd, None, 0, 0, w, h, SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);
    }
}

/// Message loop for our windows, replacing `nwg::dispatch_thread_events()`.
/// `esc_closes`: pressing Esc anywhere in that window ends the loop, like its close button.
/// Tab inside a multi-line edit box (the key box of the settings window) moves to the next control instead of typing a tab character, Shift+Tab to the previous one.
fn run_event_loop(esc_closes: Option<&nwg::Window>) {
    use windows::Win32::Foundation::HWND;
    use windows::Win32::UI::Input::KeyboardAndMouse::{GetKeyState, SetFocus, VK_SHIFT, VK_TAB};
    use windows::Win32::UI::WindowsAndMessaging::{
        DispatchMessageW, GetAncestor, GetClassNameW, GetMessageW, GetNextDlgTabItem, GetWindowLongW,
        IsDialogMessageW, TranslateMessage, GA_ROOT, GWL_STYLE, MSG, WM_KEYDOWN, WM_SYSCHAR,
    };
    const VK_ESCAPE: usize = 0x1B;
    const ES_MULTILINE: i32 = 0x0004;
    let is_multiline_edit = |hwnd: HWND| unsafe {
        let mut class = [0u16; 16];
        let len = GetClassNameW(hwnd, &mut class).max(0) as usize;
        String::from_utf16_lossy(&class[..len]).eq_ignore_ascii_case("edit")
            && GetWindowLongW(hwnd, GWL_STYLE) & ES_MULTILINE != 0
    };
    let esc_hwnd = esc_closes.and_then(|w| w.handle.hwnd()).map(|h| h as isize);
    let mut msg = MSG::default();
    unsafe {
        while GetMessageW(&mut msg, None, 0, 0).0 > 0 {
            let root: HWND = GetAncestor(msg.hwnd, GA_ROOT);
            if msg.message == WM_KEYDOWN && msg.wParam.0 == VK_ESCAPE && Some(root.0 as isize) == esc_hwnd {
                break;
            }
            if msg.message == WM_KEYDOWN && msg.wParam.0 == VK_TAB.0 as usize && is_multiline_edit(msg.hwnd) {
                let backwards = GetKeyState(VK_SHIFT.0 as i32) < 0;
                if let Ok(next) = GetNextDlgTabItem(root, Some(msg.hwnd), backwards) {
                    let _ = SetFocus(Some(next));
                }
                continue;
            }
            if msg.message != WM_SYSCHAR && IsDialogMessageW(root, &msg).as_bool() {
                continue;
            }
            let _ = TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
}

/// Apply the exe's embedded icon (resource id 1) to the title bar (small) and taskbar/Alt-Tab (big).
fn set_window_icon(window: &nwg::Window) {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{HWND, LPARAM, WPARAM};
    use windows::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows::Win32::UI::WindowsAndMessaging::{
        GetSystemMetrics, LoadImageW, SendMessageW, ICON_BIG, ICON_SMALL, IMAGE_ICON, LR_DEFAULTCOLOR,
        SM_CXICON, SM_CXSMICON, SM_CYICON, SM_CYSMICON, WM_SETICON,
    };

    let Some(hwnd) = window.handle.hwnd() else { return };
    unsafe {
        let Ok(module) = GetModuleHandleW(None) else { return };
        for (kind, cx, cy) in [(ICON_SMALL, SM_CXSMICON, SM_CYSMICON), (ICON_BIG, SM_CXICON, SM_CYICON)] {
            let icon = LoadImageW(
                Some(module.into()),
                PCWSTR(std::ptr::without_provenance(1)), // MAKEINTRESOURCE(1), see assets/app.rc
                IMAGE_ICON,
                GetSystemMetrics(cx),
                GetSystemMetrics(cy),
                LR_DEFAULTCOLOR,
            );
            if let Ok(icon) = icon {
                SendMessageW(HWND(hwnd as _), WM_SETICON, Some(WPARAM(kind as usize)), Some(LPARAM(icon.0 as isize)));
            }
        }
    }
}

fn info(msg: &str) {
    nwg::simple_message(TITLE, msg);
}

fn error(msg: &str) {
    nwg::error_message(TITLE, msg);
}

/// Yes/No question.
/// With an `owner` the box is blocked-on and centred over that window (Windows itself would centre it on the screen); without one it is centred on the screen.
fn confirm(msg: &str, owner: Option<Owner>) -> bool {
    use windows::Win32::UI::WindowsAndMessaging::{IDYES, MB_ICONQUESTION, MB_YESNO};
    message_box(owner.and_then(|o| o.handle.hwnd()).map(|h| h as isize), msg, MB_YESNO | MB_ICONQUESTION) == IDYES
}

/// Information / error popups owned by `window` and centred over it.
fn popup_info(window: &nwg::Window, msg: &str) {
    use windows::Win32::UI::WindowsAndMessaging::{MB_ICONINFORMATION, MB_OK};
    message_box(window.handle.hwnd().map(|h| h as isize), msg, MB_OK | MB_ICONINFORMATION);
}

fn popup_error(window: &nwg::Window, msg: &str) {
    use windows::Win32::UI::WindowsAndMessaging::{MB_ICONERROR, MB_OK};
    message_box(window.handle.hwnd().map(|h| h as isize), msg, MB_OK | MB_ICONERROR);
}

/// Error popup centred over `owner` when there is one.
fn popup_error_owned(owner: Option<Owner>, msg: &str) {
    match owner {
        Some(o) => {
            use windows::Win32::UI::WindowsAndMessaging::{MB_ICONERROR, MB_OK};
            message_box(o.handle.hwnd().map(|h| h as isize), msg, MB_OK | MB_ICONERROR);
        }
        None => error(msg),
    }
}

static CENTER_OWNER: AtomicIsize = AtomicIsize::new(0);
static CENTER_HOOK: AtomicIsize = AtomicIsize::new(0);

/// CBT hook: when the message box is activated, move it to the centre of its owner (one shot).
unsafe extern "system" fn center_over_owner(
    code: i32,
    wparam: windows::Win32::Foundation::WPARAM,
    lparam: windows::Win32::Foundation::LPARAM,
) -> windows::Win32::Foundation::LRESULT {
    use windows::Win32::Foundation::{HWND, RECT};
    use windows::Win32::UI::WindowsAndMessaging::{
        CallNextHookEx, GetWindowRect, SetWindowPos, UnhookWindowsHookEx, HCBT_ACTIVATE, HHOOK, SWP_NOACTIVATE,
        SWP_NOSIZE, SWP_NOZORDER,
    };
    if code == HCBT_ACTIVATE as i32 {
        let dialog = HWND(wparam.0 as *mut _);
        let owner = HWND(CENTER_OWNER.load(Ordering::Relaxed) as *mut _);
        let (mut o, mut d) = (RECT::default(), RECT::default());
        unsafe {
            if GetWindowRect(owner, &mut o).is_ok() && GetWindowRect(dialog, &mut d).is_ok() {
                let x = o.left + ((o.right - o.left) - (d.right - d.left)) / 2;
                let y = o.top + ((o.bottom - o.top) - (d.bottom - d.top)) / 2;
                let _ = SetWindowPos(dialog, None, x.max(0), y.max(0), 0, 0, SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
            }
            let hook = CENTER_HOOK.swap(0, Ordering::Relaxed);
            if hook != 0 {
                let _ = UnhookWindowsHookEx(HHOOK(hook as *mut _));
            }
        }
    }
    unsafe { CallNextHookEx(None, code, wparam, lparam) }
}

/// Native message box. With an owner it is owned by that window and centred over it.
fn message_box(
    owner_hwnd: Option<isize>,
    msg: &str,
    style: windows::Win32::UI::WindowsAndMessaging::MESSAGEBOX_STYLE,
) -> windows::Win32::UI::WindowsAndMessaging::MESSAGEBOX_RESULT {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::HWND;
    use windows::Win32::System::Threading::GetCurrentThreadId;
    use windows::Win32::UI::WindowsAndMessaging::{
        MessageBoxW, SetWindowsHookExW, UnhookWindowsHookEx, HHOOK, WH_CBT,
    };
    let wide = |t: &str| -> Vec<u16> { t.encode_utf16().chain(Some(0)).collect() };
    let (text, title) = (wide(msg), wide(TITLE));
    unsafe {
        if let Some(owner) = owner_hwnd {
            CENTER_OWNER.store(owner, Ordering::Relaxed);
            if let Ok(hook) = SetWindowsHookExW(WH_CBT, Some(center_over_owner), None, GetCurrentThreadId()) {
                CENTER_HOOK.store(hook.0 as isize, Ordering::Relaxed);
            }
        }
        let answer = MessageBoxW(
            owner_hwnd.map(|h| HWND(h as *mut _)),
            PCWSTR(text.as_ptr()),
            PCWSTR(title.as_ptr()),
            style,
        );
        // Normally removed by the hook itself; make sure it never outlives the box.
        let hook = CENTER_HOOK.swap(0, Ordering::Relaxed);
        if hook != 0 {
            let _ = UnhookWindowsHookEx(HHOOK(hook as *mut _));
        }
        answer
    }
}

/// Load stored credentials, running the settings window first if none exist.
/// Returns `None` when the user gives up.
fn ensure_credentials(owner: Option<Owner>) -> Option<Credentials> {
    match secure_store::load() {
        Ok(Some(c)) => return Some(c),
        Ok(None) => {}
        Err(e) => {
            if !confirm(&format!("저장된 설정을 읽을 수 없습니다.\n{}\n\n키/암호를 다시 입력하시겠습니까?", pgp_ops::error_text(&e)), owner) {
                return None;
            }
        }
    }
    if !run_settings(owner) {
        return None;
    }
    secure_store::load().ok().flatten()
}

/// The window our dialogs/windows belong to (stay on top of it and are centred over it).
#[derive(Clone, Copy)]
struct Owner {
    handle: ControlHandle,
    pos: (i32, i32),
    size: (u32, u32),
}

impl Owner {
    fn of(window: &nwg::Window) -> Self {
        Owner { handle: window.handle, pos: window.position(), size: window.size() }
    }
}

/// Where to open a window of `size`: centred over its owner, else where it was last closed.
fn child_position(owner: Option<Owner>, size: (i32, i32), saved_key: &str) -> (i32, i32) {
    if let Some(o) = owner {
        // Taller than the owner: keep the title bar on screen instead of centring it off the top.
        let pos = (
            o.pos.0 + (o.size.0 as i32 - size.0) / 2,
            (o.pos.1 + (o.size.1 as i32 - size.1) / 2).max(0),
        );
        if window_state::is_on_screen(pos) {
            return pos;
        }
    }
    window_state::load(saved_key).unwrap_or((300, 200))
}

/// Decrypt one or more files in a single window (per-file list and overall progress).
/// Each output goes next to its source file; the user is never asked for a folder.
/// `owner`: the window that stays blocked (modal) while our windows are open.
fn process_files(files: Vec<PathBuf>, owner: Option<Owner>) {
    let (files, skipped_invalid): (Vec<_>, Vec<_>) = files.into_iter().partition(|f| f.is_file());
    if !skipped_invalid.is_empty() {
        let list: Vec<String> = skipped_invalid.iter().map(|f| f.display().to_string()).collect();
        popup_error_owned(owner, &format!("파일이 아니어서 건너뜁니다:\n{}", list.join("\n")));
    }
    if files.is_empty() {
        return;
    }
    let Some(creds) = ensure_credentials(owner) else { return };
    let creds = Arc::new(creds);

    // Confirm overwrites up front so the batch can then run unattended.
    // Files whose overwrite the user declines are left out of the batch altogether.
    let jobs: Vec<Job> = files
        .iter()
        .filter_map(|file| {
            let output = file.with_file_name(pgp_ops::output_name(file));
            let overwrite = output.exists();
            if overwrite
                && !confirm(&format!("이미 파일이 있습니다. 덮어쓰시겠습니까?\n\n{}", output.display()), owner)
            {
                return None;
            }
            let size = std::fs::metadata(file).map(|m| m.len()).unwrap_or(0).max(1);
            Some(Job { file: file.clone(), output, overwrite, size })
        })
        .collect();
    if jobs.is_empty() {
        return;
    }
    run_batch_window(jobs, creds, owner);
}

// ---------------------------------------------------------------------------------------------
// Main window (GUI launch): drag & drop target
// ---------------------------------------------------------------------------------------------

struct MainUi {
    window: nwg::Window,
    hint: nwg::Label,
    drop_label: nwg::Label,
    pick_btn: nwg::Button,
    settings_btn: nwg::Button,
    exit_btn: nwg::Button,
    menu_file: nwg::Menu,
    menu_pick: nwg::MenuItem,
    menu_settings: nwg::MenuItem,
    menu_sep: nwg::MenuSeparator,
    menu_exit: nwg::MenuItem,
    busy: Cell<bool>,
}

fn run_main_window() {
    let mut ui = MainUi {
        window: Default::default(),
        hint: Default::default(),
        drop_label: Default::default(),
        pick_btn: Default::default(),
        settings_btn: Default::default(),
        exit_btn: Default::default(),
        menu_file: Default::default(),
        menu_pick: Default::default(),
        menu_settings: Default::default(),
        menu_sep: Default::default(),
        menu_exit: Default::default(),
        busy: Cell::new(false),
    };
    let mut build = || -> Result<(), nwg::NwgError> {
        nwg::Window::builder()
            .size((480, 280))
            .position(window_state::load("main").unwrap_or((300, 250)))
            .title("MyPgpDecrypt")
            .accept_files(true)
            .flags(nwg::WindowFlags::WINDOW | nwg::WindowFlags::VISIBLE)
            .build(&mut ui.window)?;
        set_window_icon(&ui.window);
        nwg::Menu::builder().text("메뉴(&M)").parent(&ui.window).build(&mut ui.menu_file)?;
        nwg::MenuItem::builder().text("PGP 파일 선택(&F)").parent(&ui.menu_file).build(&mut ui.menu_pick)?;
        nwg::MenuItem::builder().text("설정(&C)").parent(&ui.menu_file).build(&mut ui.menu_settings)?;
        nwg::MenuSeparator::builder().parent(&ui.menu_file).build(&mut ui.menu_sep)?;
        nwg::MenuItem::builder().text("종료(&X)").parent(&ui.menu_file).build(&mut ui.menu_exit)?;
        // After the menu bar exists, so its height is part of the measured window frame.
        fit_client_area(&ui.window, (480, 280));
        // Both texts are disabled (grey) so drops over them fall through to the window.
        nwg::Label::builder()
            .text("PGP 파일을 이 창에 끌어다 놓으면 자동으로 복호화합니다.")
            .position((15, 92))
            .size((450, 24))
            .h_align(nwg::HTextAlign::Center)
            .parent(&ui.window)
            .build(&mut ui.hint)?;
        ui.hint.set_enabled(false);
        nwg::Label::builder()
            .text("여기에 파일을 놓으세요.")
            .position((15, 120))
            .size((450, 24))
            .h_align(nwg::HTextAlign::Center)
            .parent(&ui.window)
            .build(&mut ui.drop_label)?;
        ui.drop_label.set_enabled(false);
        nwg::Button::builder()
            .text("PGP 파일 선택")
            .position((15, 232))
            .size((120, 32))
            .parent(&ui.window)
            .build(&mut ui.pick_btn)?;
        nwg::Button::builder()
            .text("설정")
            .position((180, 232))
            .size((120, 32))
            .parent(&ui.window)
            .build(&mut ui.settings_btn)?;
        nwg::Button::builder()
            .text("종료")
            .position((345, 232))
            .size((120, 32))
            .parent(&ui.window)
            .build(&mut ui.exit_btn)?;
        Ok(())
    };
    if let Err(e) = build() {
        error(&format!("창을 만들 수 없습니다: {}", pgp_ops::capitalize(&e.to_string())));
        return;
    }

    let ui = Rc::new(ui);
    let ui2 = ui.clone();
    let handler = nwg::full_bind_event_handler(&ui.window.handle, move |evt, data, h| {
        let ui = &ui2;
        match evt {
            Event::OnWindowClose if h == ui.window.handle => nwg::stop_thread_dispatch(),
            Event::OnFileDrop => {
                let files: Vec<PathBuf> = data.on_file_drop().files().into_iter().map(PathBuf::from).collect();
                main_process(ui, files);
            }
            Event::OnButtonClick if h == ui.pick_btn.handle => main_pick_files(ui),
            Event::OnMenuItemSelected if h == ui.menu_pick.handle => main_pick_files(ui),
            Event::OnButtonClick if h == ui.settings_btn.handle => main_open_settings(ui),
            Event::OnMenuItemSelected if h == ui.menu_settings.handle => main_open_settings(ui),
            Event::OnButtonClick if h == ui.exit_btn.handle => main_exit(ui),
            Event::OnMenuItemSelected if h == ui.menu_exit.handle => main_exit(ui),
            _ => {}
        }
    });
    run_event_loop(None);
    nwg::unbind_event_handler(&handler);
    window_state::save("main", ui.window.position());
}

/// Main window actions, shared by the buttons and the "메뉴" menu.
fn main_pick_files(ui: &MainUi) {
    let mut dialog = nwg::FileDialog::default();
    let built = nwg::FileDialog::builder()
        .title("복호화할 PGP 파일 선택")
        .action(nwg::FileDialogAction::Open)
        .multiselect(true)
        .filters("PGP files(*.pgp;*.gpg)|All files(*.*)")
        .build(&mut dialog);
    if let (true, Ok(items)) = (built.is_ok() && dialog.run(Some(&ui.window)), dialog.get_selected_items()) {
        main_process(ui, items.into_iter().map(PathBuf::from).collect());
    }
}

fn main_open_settings(ui: &MainUi) {
    if ui.busy.replace(true) {
        return;
    }
    ui.window.set_enabled(false);
    run_settings(Some(Owner::of(&ui.window)));
    ui.window.set_enabled(true);
    ui.window.set_focus();
    ui.busy.set(false);
}

/// Ignored while a batch/settings window is open (its nested loop would be stopped instead).
fn main_exit(ui: &MainUi) {
    if !ui.busy.get() {
        nwg::stop_thread_dispatch();
    }
}

/// The main window is disabled while a batch runs (no clicks or drops); `busy` also guards re-entry.
fn main_process(ui: &MainUi, files: Vec<PathBuf>) {
    if ui.busy.replace(true) {
        return;
    }
    ui.window.set_enabled(false);
    process_files(files, Some(Owner::of(&ui.window)));
    ui.window.set_enabled(true);
    ui.window.set_focus();
    ui.busy.set(false);
}

// ---------------------------------------------------------------------------------------------
// Settings window
// ---------------------------------------------------------------------------------------------

struct SettingsUi {
    window: nwg::Window,
    key_label: nwg::Label,
    key_btn: nwg::Button,
    key_text: nwg::TextBox,
    pass_label: nwg::Label,
    pass_input: nwg::TextInput,
    status: nwg::Label,
    reg_btn: nwg::Button,
    unreg_btn: nwg::Button,
    save_btn: nwg::Button,
    cancel_btn: nwg::Button,
    binary_key: RefCell<Option<Vec<u8>>>,
    saved: Cell<bool>,
}

/// Returns true if credentials were saved.
fn run_settings(owner: Option<Owner>) -> bool {
    let state = saved_state();
    let mut ui = SettingsUi {
        window: Default::default(),
        key_label: Default::default(),
        key_btn: Default::default(),
        key_text: Default::default(),
        pass_label: Default::default(),
        pass_input: Default::default(),
        status: Default::default(),
        reg_btn: Default::default(),
        unreg_btn: Default::default(),
        save_btn: Default::default(),
        cancel_btn: Default::default(),
        binary_key: RefCell::new(None),
        saved: Cell::new(false),
    };

    let mut build = || -> Result<(), nwg::NwgError> {
        nwg::Window::builder()
            .size((540, 450))
            .position(child_position(owner, (540, 450), "settings"))
            .title(match state {
                SavedState::Saved { .. } => "MyPgpDecrypt 설정 — 키/암호 저장됨",
                _ => "MyPgpDecrypt 설정 — 키/암호 없음",
            })
            .parent(owner.map(|o| o.handle))
            .flags(nwg::WindowFlags::WINDOW | nwg::WindowFlags::VISIBLE)
            .build(&mut ui.window)?;
        set_window_icon(&ui.window);
        fit_client_area(&ui.window, (540, 418));
        nwg::Label::builder()
            .text("개인(Private) PGP 키 (파일 선택 또는 붙여넣기)")
            .position((15, 15))
            .size((380, 24))
            .parent(&ui.window)
            .build(&mut ui.key_label)?;
        nwg::Button::builder()
            .text("키 파일 선택")
            .position((405, 10))
            .size((120, 30))
            .parent(&ui.window)
            .build(&mut ui.key_btn)?;
        nwg::TextBox::builder()
            .text(match &state {
                SavedState::Saved { info } => info,
                _ => "",
            })
            .position((15, 46))
            .size((510, 190))
            .flags(nwg::TextBoxFlags::VISIBLE | nwg::TextBoxFlags::TAB_STOP | nwg::TextBoxFlags::VSCROLL)
            .parent(&ui.window)
            .build(&mut ui.key_text)?;
        nwg::Label::builder()
            .text("키 암호(Passphrase)")
            .position((15, 248))
            .size((300, 24))
            .parent(&ui.window)
            .build(&mut ui.pass_label)?;
        nwg::TextInput::builder()
            .position((15, 274))
            .size((510, 28))
            .password(Some('*'))
            .placeholder_text(Some(match state {
                SavedState::Saved { .. } => "저장됨 (바꾸려면 새 암호 입력)",
                _ => "키 암호 입력",
            }))
            .parent(&ui.window)
            .build(&mut ui.pass_input)?;
        let status = match state {
            SavedState::Saved { .. } => "[저장됨] 개인 키와 암호가 저장되어 있습니다.",
            SavedState::None => "[없음] 저장된 개인 키/암호가 없습니다. 입력 후 저장하세요.",
            SavedState::Unreadable => "[오류] 저장된 설정을 읽을 수 없습니다. 다시 입력하세요.",
        };
        nwg::Label::builder()
            .text(&format!("{status}\n(Windows 계정에 묶여 암호화되어 저장되며, 보안상 화면에는 표시하지 않습니다)"))
            .position((15, 312))
            .size((510, 44))
            .parent(&ui.window)
            .build(&mut ui.status)?;
        nwg::Button::builder()
            .text("우클릭 메뉴 등록")
            .position((15, 370))
            .size((150, 32))
            .parent(&ui.window)
            .build(&mut ui.reg_btn)?;
        nwg::Button::builder()
            .text("우클릭 메뉴 해제")
            .position((172, 370))
            .size((150, 32))
            .parent(&ui.window)
            .build(&mut ui.unreg_btn)?;
        nwg::Button::builder()
            .text("키/암호 저장")
            .position((330, 370))
            .size((110, 32))
            .parent(&ui.window)
            .build(&mut ui.save_btn)?;
        nwg::Button::builder()
            .text("닫기")
            .position((448, 370))
            .size((77, 32))
            .parent(&ui.window)
            .build(&mut ui.cancel_btn)?;
        Ok(())
    };
    if let Err(e) = build() {
        error(&format!("창을 만들 수 없습니다: {}", pgp_ops::capitalize(&e.to_string())));
        return false;
    }

    let ui = Rc::new(ui);
    let ui2 = ui.clone();
    let handler = nwg::full_bind_event_handler(&ui.window.handle, move |evt, _, h| {
        let ui = &ui2;
        match evt {
            Event::OnWindowClose if h == ui.window.handle => nwg::stop_thread_dispatch(),
            Event::OnButtonClick => {
                if h == ui.cancel_btn.handle {
                    nwg::stop_thread_dispatch();
                } else if h == ui.key_btn.handle {
                    settings_pick_key(ui);
                } else if h == ui.save_btn.handle {
                    settings_save(ui);
                } else if h == ui.reg_btn.handle {
                    match shell_ext::register() {
                        Ok(()) => popup_info(&ui.window, "우클릭 메뉴를 등록했습니다."),
                        Err(e) => popup_error(&ui.window, &format!("등록 실패: {}", pgp_ops::error_text(&e))),
                    };
                } else if h == ui.unreg_btn.handle {
                    match shell_ext::unregister() {
                        Ok(()) => popup_info(&ui.window, "우클릭 메뉴를 해제했습니다."),
                        Err(e) => popup_error(&ui.window, &format!("해제 실패: {}", pgp_ops::error_text(&e))),
                    };
                }
            }
            _ => {}
        }
    });
    run_event_loop(Some(&ui.window));
    nwg::unbind_event_handler(&handler);
    if owner.is_none() {
        window_state::save("settings", ui.window.position());
    }
    ui.saved.get()
}

fn settings_pick_key(ui: &SettingsUi) {
    let mut dialog = nwg::FileDialog::default();
    let built = nwg::FileDialog::builder()
        .title("개인 키 파일 선택")
        .action(nwg::FileDialogAction::Open)
        .filters("Key files(*.asc;*.key)|All files(*.*)")
        .build(&mut dialog);
    if built.is_err() || !dialog.run(Some(&ui.window)) {
        return;
    }
    let Ok(path) = dialog.get_selected_item() else { return };
    match std::fs::read(&path) {
        Ok(bytes) => match std::str::from_utf8(&bytes) {
            Ok(text) => {
                *ui.binary_key.borrow_mut() = None;
                ui.key_text.set_text(&text.replace("\r\n", "\n").replace('\n', "\r\n"));
            }
            Err(_) => {
                *ui.binary_key.borrow_mut() = Some(bytes);
                ui.key_text.set_text(KEY_FILE_PLACEHOLDER);
            }
        },
        Err(e) => {
            popup_error(&ui.window, &format!("파일을 읽을 수 없습니다: {}", pgp_ops::capitalize(&e.to_string())));
        }
    }
}

fn settings_save(ui: &SettingsUi) {
    let text = ui.key_text.text();
    let passphrase = ui.pass_input.text();
    let keep_saved_key = text.trim_start().starts_with(SAVED_KEY_MARK);

    let key_bytes = if keep_saved_key {
        if passphrase.is_empty() {
            popup_info(&ui.window, "변경 사항이 없습니다.\n(저장된 키/암호를 계속 사용합니다)");
            return;
        }
        match secure_store::load() {
            Ok(Some(c)) => c.key.clone(),
            _ => {
                popup_error(&ui.window, "저장된 키를 읽을 수 없습니다. 키를 다시 입력하세요.");
                return;
            }
        }
    } else {
        match ui.binary_key.borrow().as_ref() {
            Some(b) if text.trim() == KEY_FILE_PLACEHOLDER => b.clone(),
            _ => text.replace("\r\n", "\n").trim().as_bytes().to_vec(),
        }
    };
    if key_bytes.is_empty() {
        popup_error(&ui.window, "개인 키를 입력하세요.");
        return;
    }

    let key = match pgp_ops::parse_secret_key(&key_bytes) {
        Ok(k) => k,
        Err(e) => {
            popup_error(&ui.window, &format!("키를 읽을 수 없습니다.\n(개인 키가 맞는지 확인하세요)\n\n{}", pgp_ops::error_text(&e)));
            return;
        }
    };
    if let Err(e) = pgp_ops::verify_passphrase(&key, &passphrase) {
        popup_error(&ui.window, &format!("암호가 맞지 않습니다.\n\n{}", pgp_ops::error_text(&e)));
        return;
    }
    let creds = Credentials { key: key_bytes, passphrase };
    match secure_store::save(&creds) {
        Ok(()) => {
            ui.saved.set(true);
            ui.pass_input.set_text("");
            popup_info(&ui.window, &format!("저장했습니다.\nFingerprint: {}", pgp_ops::key_summary(&key)),
            );
            nwg::stop_thread_dispatch();
        }
        Err(e) => {
            popup_error(&ui.window, &format!("저장 실패: {}", pgp_ops::error_text(&e)));
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Batch decrypt window: file list + per-file status + overall progress
// ---------------------------------------------------------------------------------------------

struct Job {
    file: PathBuf,
    output: PathBuf,
    overwrite: bool,
    size: u64,
}

#[derive(Clone, PartialEq)]
enum Status {
    Pending,
    Running,
    Done(u64),
    Failed(String),
}

struct BatchShared {
    status: Mutex<Vec<Status>>,
    current: AtomicUsize,
    consumed: AtomicU64,
    cancel: AtomicBool,
    finished: AtomicBool,
}

struct BatchUi {
    window: nwg::Window,
    summary: nwg::Label,
    list: nwg::ListView,
    bar: nwg::ProgressBar,
    open_btn: nwg::Button,
    close_btn: nwg::Button,
    notice: nwg::Notice,
    /// Text currently shown in the status column, so only changed rows are redrawn.
    shown: RefCell<Vec<String>>,
}

const BAR_MAX: u32 = 1000;

fn status_text(st: &Status, pct: u64) -> String {
    match st {
        Status::Pending => "대기".into(),
        Status::Running => format!("복호화 중 {pct}%"),
        Status::Done(n) => format!("완료 ({} 바이트)", pgp_ops::with_commas(*n)),
        Status::Failed(m) => format!("실패: {m}"),
    }
}

fn run_batch_window(jobs: Vec<Job>, creds: Arc<Credentials>, owner: Option<Owner>) {
    let mut ui = BatchUi {
        window: Default::default(),
        summary: Default::default(),
        list: Default::default(),
        bar: Default::default(),
        open_btn: Default::default(),
        close_btn: Default::default(),
        notice: Default::default(),
        shown: RefCell::new(Vec::new()),
    };
    let mut build = || -> Result<(), nwg::NwgError> {
        nwg::Window::builder()
            .size((660, 420))
            .position(child_position(owner, (660, 420), "batch"))
            .title("MyPgpDecrypt")
            .parent(owner.map(|o| o.handle))
            .flags(nwg::WindowFlags::WINDOW | nwg::WindowFlags::VISIBLE)
            .build(&mut ui.window)?;
        set_window_icon(&ui.window);
        fit_client_area(&ui.window, (660, 414));
        nwg::Label::builder()
            .text("")
            .position((15, 12))
            .size((630, 24))
            .parent(&ui.window)
            .build(&mut ui.summary)?;
        nwg::ListView::builder()
            .position((15, 42))
            .size((630, 270))
            .list_style(nwg::ListViewStyle::Detailed)
            .ex_flags(nwg::ListViewExFlags::FULL_ROW_SELECT | nwg::ListViewExFlags::GRID)
            .parent(&ui.window)
            .build(&mut ui.list)?;
        nwg::ProgressBar::builder()
            .range(0..BAR_MAX)
            .position((15, 324))
            .size((630, 22))
            .parent(&ui.window)
            .build(&mut ui.bar)?;
        nwg::Button::builder()
            .text("폴더 열기")
            .position((415, 366))
            .size((110, 32))
            .enabled(false)
            .parent(&ui.window)
            .build(&mut ui.open_btn)?;
        nwg::Button::builder()
            .text("취소")
            .position((535, 366))
            .size((110, 32))
            .parent(&ui.window)
            .build(&mut ui.close_btn)?;
        nwg::Notice::builder().parent(&ui.window).build(&mut ui.notice)?;
        Ok(())
    };
    if let Err(e) = build() {
        error(&format!("창을 만들 수 없습니다: {}", pgp_ops::capitalize(&e.to_string())));
        return;
    }

    ui.list.set_headers_enabled(true);
    ui.list.insert_column(nwg::InsertListViewColumn {
        index: Some(0),
        fmt: None,
        width: Some(300),
        text: Some("파일".into()),
    });
    ui.list.insert_column(nwg::InsertListViewColumn {
        index: Some(1),
        fmt: None,
        width: Some(310),
        text: Some("상태".into()),
    });
    let initial: Vec<Status> = jobs.iter().map(|_| Status::Pending).collect();
    for (job, st) in jobs.iter().zip(&initial) {
        let name = job.file.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let text = status_text(st, 0);
        ui.list.insert_items_row(None, &[name.as_str(), text.as_str()]);
        ui.shown.borrow_mut().push(text);
    }

    let jobs = Arc::new(jobs);
    let shared = Arc::new(BatchShared {
        status: Mutex::new(initial),
        current: AtomicUsize::new(0),
        consumed: AtomicU64::new(0),
        cancel: AtomicBool::new(false),
        finished: AtomicBool::new(false),
    });
    let sender = ui.notice.sender();

    let worker = {
        let (shared, jobs) = (shared.clone(), jobs.clone());
        std::thread::spawn(move || {
            let set = |i: usize, st: Status| shared.status.lock().unwrap()[i] = st;
            let key = pgp_ops::parse_secret_key(&creds.key);
            for (i, job) in jobs.iter().enumerate() {
                if shared.cancel.load(Ordering::Relaxed) {
                    break;
                }
                shared.consumed.store(0, Ordering::Relaxed);
                shared.current.store(i, Ordering::Relaxed);
                set(i, Status::Running);
                sender.notice();
                let mut last = Instant::now();
                let result = match &key {
                    Ok(key) => pgp_ops::decrypt_file(
                        &job.file,
                        &job.output,
                        key,
                        &creds.passphrase,
                        job.overwrite,
                        |n| {
                            shared.consumed.store(n, Ordering::Relaxed);
                            if last.elapsed() >= Duration::from_millis(50) {
                                last = Instant::now();
                                sender.notice();
                            }
                            !shared.cancel.load(Ordering::Relaxed)
                        },
                    ),
                    Err(e) => Err(anyhow::anyhow!(pgp_ops::error_text(e))),
                };
                match result {
                    Ok(n) => set(i, Status::Done(n)),
                    // Cancelled: the window is closing, nothing more to show.
                    Err(_) if shared.cancel.load(Ordering::Relaxed) => break,
                    Err(e) => set(i, Status::Failed(pgp_ops::error_text(&e))),
                }
                sender.notice();
            }
            shared.finished.store(true, Ordering::Relaxed);
            sender.notice();
        })
    };

    let ui = Rc::new(ui);
    let ui2 = ui.clone();
    let (shared2, jobs2) = (shared.clone(), jobs.clone());
    let total_bytes: u64 = jobs.iter().map(|j| j.size).sum();
    let handler = nwg::full_bind_event_handler(&ui.window.handle, move |evt, _, h| {
        let ui = &ui2;
        match evt {
            Event::OnNotice => batch_refresh(ui, &jobs2, &shared2, total_bytes),
            Event::OnButtonClick if h == ui.close_btn.handle => {
                if shared2.finished.load(Ordering::Relaxed) {
                    nwg::stop_thread_dispatch();
                } else {
                    // "취소": stop right away and close the window.
                    shared2.cancel.store(true, Ordering::Relaxed);
                    nwg::stop_thread_dispatch();
                }
            }
            Event::OnButtonClick if h == ui.open_btn.handle => {
                let st = shared2.status.lock().unwrap();
                if let Some(job) = jobs2.iter().zip(st.iter()).find(|(_, s)| matches!(s, Status::Done(_))).map(|(j, _)| j) {
                    open_in_explorer(&job.output);
                }
            }
            Event::OnWindowClose if h == ui.window.handle => {
                shared2.cancel.store(true, Ordering::Relaxed);
                nwg::stop_thread_dispatch();
            }
            _ => {}
        }
    });
    batch_refresh(&ui, &jobs, &shared, total_bytes);
    run_event_loop(None);
    nwg::unbind_event_handler(&handler);
    if owner.is_none() {
        window_state::save("batch", ui.window.position());
    }
    // Stop a still-running worker so it removes its `.part` file before we exit
    ui.window.set_visible(false);
    shared.cancel.store(true, Ordering::Relaxed);
    let _ = worker.join();
}

fn batch_refresh(ui: &BatchUi, jobs: &[Job], shared: &BatchShared, total_bytes: u64) {
    let statuses = shared.status.lock().unwrap().clone();
    let current = shared.current.load(Ordering::Relaxed);
    let consumed = shared.consumed.load(Ordering::Relaxed);

    let mut shown = ui.shown.borrow_mut();
    let (mut done_bytes, mut ok, mut failed, mut finished_n) = (0u64, 0, 0, 0);
    for (i, (st, job)) in statuses.iter().zip(jobs).enumerate() {
        let pct = if i == current { (consumed.min(job.size) * 100 / job.size).min(100) } else { 0 };
        match st {
            Status::Running => done_bytes += consumed.min(job.size),
            Status::Pending => {}
            Status::Done(_) => { ok += 1; done_bytes += job.size; finished_n += 1; }
            Status::Failed(_) => { failed += 1; done_bytes += job.size; finished_n += 1; }
        }
        let text = status_text(st, pct);
        if shown[i] != text {
            ui.list.update_item(
                i,
                nwg::InsertListViewItem {
                    index: Some(i as i32),
                    column_index: 1,
                    text: Some(text.clone()),
                    ..Default::default()
                },
            );
            shown[i] = text;
        }
    }
    ui.bar.set_pos((done_bytes.min(total_bytes) * BAR_MAX as u64 / total_bytes.max(1)) as u32);

    if shared.finished.load(Ordering::Relaxed) {
        ui.summary.set_text(&format!("완료 {ok}개, 실패 {failed}개"));
        ui.close_btn.set_text("닫기");
        ui.close_btn.set_enabled(true);
        ui.open_btn.set_enabled(ok > 0);
        if failed == 0 {
            ui.bar.set_pos(BAR_MAX);
        }
    } else {
        ui.summary.set_text(&format!("복호화 중… ({}/{})", finished_n.min(jobs.len()), jobs.len()));
    }
}

fn open_in_explorer(path: &Path) {
    use std::os::windows::process::CommandExt;
    let _ = std::process::Command::new("explorer")
        .raw_arg(format!("/select,\"{}\"", path.display()))
        .spawn();
}
