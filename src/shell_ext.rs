//! Explorer right-click menu registration (per-user, HKCU; no admin rights needed).
use anyhow::{Context, Result};
use winreg::enums::*;
use winreg::RegKey;

const EXTENSIONS: [&str; 2] = [".pgp", ".gpg"];
const VERB: &str = "MyPgpDecrypt";
const MENU_TEXT: &str = "내 PGP key로 복호화";

fn verb_path(ext: &str) -> String {
    format!(r"Software\Classes\SystemFileAssociations\{ext}\shell\{VERB}")
}

pub fn register() -> Result<()> {
    let exe = std::env::current_exe().context("cannot determine exe path")?;
    let exe = exe.display().to_string();
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    for ext in EXTENSIONS {
        let (key, _) = hkcu.create_subkey(verb_path(ext))?;
        key.set_value("", &MENU_TEXT)?;
        key.set_value("Icon", &format!("\"{exe}\",0"))?;
        let (cmd, _) = key.create_subkey("command")?;
        cmd.set_value("", &format!("\"{exe}\" \"%1\""))?;
    }
    Ok(())
}

pub fn unregister() -> Result<()> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    for ext in EXTENSIONS {
        match hkcu.delete_subkey_all(verb_path(ext)) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

pub fn is_registered() -> bool {
    RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey(format!(r"{}\command", verb_path(EXTENSIONS[0])))
        .is_ok()
}
