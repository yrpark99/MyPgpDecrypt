//! Remembers where each window was when the program last closed (`%APPDATA%\MyPgpDecrypt\window.ini`).
//! Format: one `name=x,y` line per window.

pub type Pos = (i32, i32);

pub fn parse(text: &str, name: &str) -> Option<Pos> {
    text.lines().find_map(|line| {
        let (key, val) = line.split_once('=')?;
        if key.trim() != name {
            return None;
        }
        let (x, y) = val.split_once(',')?;
        Some((x.trim().parse().ok()?, y.trim().parse().ok()?))
    })
}

/// Returns `text` with the entry for `name` replaced (or appended).
pub fn update(text: &str, name: &str, (x, y): Pos) -> String {
    let mut out: String = text
        .lines()
        .filter(|l| l.split_once('=').map(|(k, _)| k.trim() != name).unwrap_or(false))
        .map(|l| format!("{l}\n"))
        .collect();
    out.push_str(&format!("{name}={x},{y}\n"));
    out
}

/// Is a window whose top-left corner is at `pos` reachable on a desktop of this size?
/// (Guards against restoring onto a monitor that is no longer connected.)
pub fn is_reachable(pos: Pos, desktop: (i32, i32, i32, i32)) -> bool {
    let (dx, dy, dw, dh) = desktop;
    let (x, y) = pos;
    x > dx - 100 && x < dx + dw - 150 && y >= dy && y < dy + dh - 80
}

#[cfg(windows)]
mod io {
    use super::*;
    use windows::Win32::UI::WindowsAndMessaging::{
        GetSystemMetrics, SM_CXVIRTUALSCREEN, SM_CYVIRTUALSCREEN, SM_XVIRTUALSCREEN, SM_YVIRTUALSCREEN,
    };

    fn path() -> Option<std::path::PathBuf> {
        Some(crate::secure_store::key_path().ok()?.with_file_name("window.ini"))
    }

    /// Is a window whose top-left corner is at `pos` reachable on the current desktop?
    pub fn is_on_screen(pos: Pos) -> bool {
        let desktop = unsafe {
            (
                GetSystemMetrics(SM_XVIRTUALSCREEN),
                GetSystemMetrics(SM_YVIRTUALSCREEN),
                GetSystemMetrics(SM_CXVIRTUALSCREEN),
                GetSystemMetrics(SM_CYVIRTUALSCREEN),
            )
        };
        is_reachable(pos, desktop)
    }

    /// Saved position for `name`, if any and still on screen.
    pub fn load(name: &str) -> Option<Pos> {
        let pos = parse(&std::fs::read_to_string(path()?).ok()?, name)?;
        is_on_screen(pos).then_some(pos)
    }

    /// Best effort; failures are ignored (position memory is a convenience only).
    pub fn save(name: &str, pos: Pos) {
        let Some(path) = path() else { return };
        if pos.0 < -10_000 || pos.1 < -10_000 {
            return; // minimized windows report
        }
        let old = std::fs::read_to_string(&path).unwrap_or_default();
        let _ = std::fs::create_dir_all(path.parent().unwrap());
        let _ = std::fs::write(&path, update(&old, name, pos));
    }
}

#[cfg(windows)]
pub use io::{is_on_screen, load, save};
