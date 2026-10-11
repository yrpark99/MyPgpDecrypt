//! Entry logic: CLI (when started from a terminal) vs GUI (Explorer, double click).
use std::ffi::OsString;
use std::os::windows::io::IntoRawHandle;

use windows::Win32::Foundation::HANDLE;
use windows::Win32::Storage::FileSystem::{GetFileType, FILE_TYPE_UNKNOWN};
use windows::Win32::System::Console::{
    AttachConsole, GetStdHandle, SetStdHandle, ATTACH_PARENT_PROCESS, STD_ERROR_HANDLE, STD_HANDLE,
    STD_OUTPUT_HANDLE,
};

use crate::cli::{self, Action, Args};
use crate::{secure_store, ui};

/// True if the standard handle exists and refers to something usable (console, pipe or file).
fn std_handle_usable(which: STD_HANDLE) -> bool {
    unsafe {
        match GetStdHandle(which) {
            Ok(h) if !h.is_invalid() && !h.0.is_null() => GetFileType(h) != FILE_TYPE_UNKNOWN,
            _ => false,
        }
    }
}

/// This is a GUI-subsystem exe, so it has no console of its own. If it was started from a terminal,
/// attach to that console and make stdout/stderr usable.
/// Returns false when there is nowhere to print (Explorer, shortcut, ...).
/// Redirected output (`> file`, pipes) also counts.
fn attach_parent_console() -> bool {
    let attached = unsafe { AttachConsole(ATTACH_PARENT_PROCESS).is_ok() };
    if attached {
        // Keep redirections; only fix up handles that are missing.
        for which in [STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
            if let (false, Ok(con)) = (std_handle_usable(which), std::fs::OpenOptions::new().write(true).open("CONOUT$")) {
                let _ = unsafe { SetStdHandle(which, HANDLE(con.into_raw_handle() as _)) };
            }
        }
    }
    attached || std_handle_usable(STD_OUTPUT_HANDLE) || std_handle_usable(STD_ERROR_HANDLE)
}

/// Print to the console if there is one, otherwise show a message box.
fn emit(console: bool, text: &str, is_error: bool) {
    if console {
        if is_error {
            eprint!("{text}");
        } else {
            print!("{text}");
        }
    } else {
        ui::init();
        let text = text.trim_end();
        if is_error {
            ui::show_error(text);
        } else {
            ui::show_info(text);
        }
    }
}

pub fn run(argv: Vec<OsString>) -> i32 {
    let console = attach_parent_console();
    let args = match cli::parse(&argv) {
        Ok(a) => a,
        Err(e) => {
            emit(console, &format!("오류: {e}\n\n{}", cli::HELP), true);
            return 2;
        }
    };
    match args.action {
        Action::Help => {
            emit(console, cli::HELP, false);
            0
        }
        Action::Run if console && !args.files.is_empty() => run_cli(&args),
        Action::Run => {
            ui::run(args.files);
            0
        }
    }
}

fn run_cli(args: &Args) -> i32 {
    let creds = match secure_store::load() {
        Ok(Some(c)) => c,
        Ok(None) => {
            eprintln!("오류: 저장된 개인 키/암호가 없습니다. MyPgpDecrypt.exe를 인자 없이 실행해 [설정]에서 먼저 입력하세요.");
            return 1;
        }
        Err(e) => {
            eprintln!("오류: 저장된 설정을 읽을 수 없습니다: {}", crate::pgp_ops::error_text(&e));
            return 1;
        }
    };
    cli::decrypt_files(args, &creds, &mut std::io::stdout(), &mut std::io::stderr())
}
