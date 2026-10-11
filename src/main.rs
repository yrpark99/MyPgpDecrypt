#![cfg_attr(windows, windows_subsystem = "windows")]
#![allow(non_snake_case)]

#[cfg(windows)]
fn main() {
    let argv: Vec<_> = std::env::args_os().skip(1).collect();
    let code = my_pgp_decrypt::app::run(argv);

    std::process::exit(code);
}

#[cfg(not(windows))]
fn main() {
    eprintln!("MyPgpDecrypt is a Windows-only GUI tool.");
}
