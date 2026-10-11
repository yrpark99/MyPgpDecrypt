//! Command-line handling: argument parsing and the console decrypt runner (platform independent).
use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::pgp_ops;
use crate::secure_store::Credentials;

pub const HELP: &str = "\
MyPgpDecrypt - PGP 파일 복호화 도구

사용법:
  MyPgpDecrypt.exe                      GUI 실행: PGP 파일을 선택하거나 끌어다 놓으면 복호화
  MyPgpDecrypt.exe [옵션] <파일>...     터미널에서 실행: CLI로 복호화하고 결과를 출력
  탐색기에서 마우스 우클릭:             탐색기에서 PGP 파일을 마우스 우클릭으로 실행: GUI로 복호화

옵션:
  -h, --help          이 도움말을 출력
  -f, --force         이미 있는 출력 파일을 덮어씀 (CLI)

복호화한 파일은 입력 PGP 파일과 같은 폴더에 저장되며, 이름은 원본에서 .pgp/.gpg 확장자를 뺀 이름입니다.
개인 키와 암호는 GUI의 [설정]에서 먼저 저장해야 합니다.
";

#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    Run,
    Help,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Args {
    pub action: Action,
    pub files: Vec<PathBuf>,
    pub force: bool,
}

pub fn parse(args: &[OsString]) -> Result<Args, String> {
    let mut a = Args { action: Action::Run, files: Vec::new(), force: false };
    let mut only_files = false;
    for arg in args {
        let s = arg.to_string_lossy();
        if only_files || !s.starts_with('-') || s == "-" {
            a.files.push(PathBuf::from(arg));
            continue;
        }
        match s.as_ref() {
            "--" => only_files = true,
            "-h" | "--help" => a.action = Action::Help,
            "-f" | "--force" => a.force = true,
            _ => return Err(format!("알 수 없는 옵션: {s}")),
        }
    }
    Ok(a)
}

/// Decrypt every file, print one result line per file, return the process exit code.
/// Each output goes into the same folder as its input file.
pub fn decrypt_files(
    args: &Args,
    creds: &Credentials,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> i32 {
    let key = match pgp_ops::parse_secret_key(&creds.key) {
        Ok(k) => k,
        Err(e) => {
            let _ = writeln!(err, "오류: 저장된 키를 읽을 수 없습니다: {}", pgp_ops::error_text(&e));
            return 1;
        }
    };

    let (mut ok, mut failed) = (0, 0);
    for file in &args.files {
        match decrypt_one(file, args, &key, &creds.passphrase) {
            Ok((output, bytes)) => {
                ok += 1;
                let _ = writeln!(out, "성공  {} -> {} ({} 바이트)", file.display(), output.display(), pgp_ops::with_commas(bytes));
            }
            Err(e) => {
                failed += 1;
                let _ = writeln!(err, "실패  {}: {}", file.display(), pgp_ops::error_text(&e));
            }
        }
    }
    let _ = writeln!(out, "완료 {ok}개, 실패 {failed}개");
    i32::from(failed > 0)
}

fn decrypt_one(
    file: &Path,
    args: &Args,
    key: &pgp::composed::SignedSecretKey,
    passphrase: &str,
) -> anyhow::Result<(PathBuf, u64)> {
    use anyhow::bail;
    if !file.is_file() {
        bail!("파일을 찾을 수 없습니다");
    }
    let output = file.with_file_name(pgp_ops::output_name(file));
    if output.exists() && !args.force {
        bail!("출력 파일이 이미 있습니다 (덮어쓰려면 -f)");
    }
    let n = pgp_ops::decrypt_file(file, &output, key, passphrase, args.force, |_| true)?;
    Ok((output, n))
}
