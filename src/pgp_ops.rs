use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use pgp::composed::{DecryptionOptions, Deserializable, Message, SignedSecretKey, TheRing};
use pgp::types::{Password, Seipdv1ReadMode};

const ARMOR_PREFIX: &[u8] = b"-----BEGIN";
const CHUNK: usize = 1 << 20;

/// Parse a private key from armored text or binary bytes.
pub fn parse_secret_key(data: &[u8]) -> Result<SignedSecretKey> {
    let key = if is_armored(data) {
        SignedSecretKey::from_armor_single(data)
            .map(|(k, _)| k)
            .context("failed to parse armored private key")?
    } else {
        SignedSecretKey::from_bytes(data).context("failed to parse binary private key")?
    };
    Ok(key)
}

/// Check that `passphrase` unlocks the key (primary key and all subkeys).
pub fn verify_passphrase(key: &SignedSecretKey, passphrase: &str) -> Result<()> {
    let pw = Password::from(passphrase);
    key.primary_key
        .unlock(&pw, |_, _| Ok(()))
        .context("wrong passphrase or unsupported key")?
        .context("failed to unlock primary key")?;
    for sub in &key.secret_subkeys {
        sub.key
            .unlock(&pw, |_, _| Ok(()))
            .context("wrong passphrase or unsupported subkey")?
            .context("failed to unlock subkey")?;
    }
    Ok(())
}

/// Counts input bytes consumed, so progress can be shown against the input file size.
#[derive(Debug)]
struct CountingReader<R> {
    inner: R,
    count: Arc<AtomicU64>,
}

impl<R: Read> Read for CountingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.count.fetch_add(n as u64, Ordering::Relaxed);
        Ok(n)
    }
}

impl<R: BufRead> BufRead for CountingReader<R> {
    fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
        self.inner.fill_buf()
    }
    fn consume(&mut self, amt: usize) {
        self.count.fetch_add(amt as u64, Ordering::Relaxed);
        self.inner.consume(amt)
    }
}

/// `1234567` -> `1,234,567` (thousands separators for display).
pub fn with_commas(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// Uppercase the first letter (English messages from our code and libraries start lowercase).
pub fn capitalize(text: &str) -> String {
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

/// Error chain for display: every context/cause message starts with a capital letter,
/// joined as `Outer: Inner: Cause`.
pub fn error_text(err: &anyhow::Error) -> String {
    err.chain().map(|e| capitalize(&e.to_string())).collect::<Vec<_>>().join(": ")
}

/// Short human-readable description of a key (fingerprint) for confirmation in the UI.
pub fn key_summary(key: &SignedSecretKey) -> String {
    use pgp::types::KeyDetails;
    key.fingerprint().to_string().to_uppercase()
}

/// User IDs (name/e-mail) of a key, for display.
pub fn key_user_ids(key: &SignedSecretKey) -> Vec<String> {
    key.details
        .users
        .iter()
        .map(|u| String::from_utf8_lossy(u.id.id()).into_owned())
        .collect()
}

/// Stream-decrypt `input` into `output`.
/// `progress(input_bytes_consumed)` is called per chunk; return `false` to cancel.
/// Returns total plaintext bytes.
/// Output is written to `<output>.part` and renamed only after the full message verified; on failure or cancel nothing is left behind.
/// An existing `output` is only replaced when `overwrite` is true.
pub fn decrypt_file(
    input: &Path,
    output: &Path,
    key: &SignedSecretKey,
    passphrase: &str,
    overwrite: bool,
    mut progress: impl FnMut(u64) -> bool,
) -> Result<u64> {
    decrypt_inner(input, output, key, passphrase, overwrite, &mut progress)
}

fn decrypt_inner(
    input: &Path,
    output: &Path,
    key: &SignedSecretKey,
    passphrase: &str,
    overwrite: bool,
    progress: &mut dyn FnMut(u64) -> bool,
) -> Result<u64> {
    let count = Arc::new(AtomicU64::new(0));
    let mut reader = CountingReader {
        inner: BufReader::new(File::open(input).context("cannot open input file")?),
        count: count.clone(),
    };
    let armored = is_armored(reader.fill_buf()?);

    let msg = if armored {
        Message::from_armor(reader)
            .map(|(m, _)| m)
            .context("not a valid armored PGP message")?
    } else {
        Message::from_bytes(reader).context("not a valid PGP message")?
    };
    if !msg.is_encrypted() {
        bail!("file is not encrypted");
    }

    let pw = Password::from(passphrase);
    // Streaming keeps memory flat for ~GB files. Unauthenticated plaintext only ever goes to a
    // temp file that is renamed to the final name after the integrity check passes at EOF.
    let ring = TheRing {
        secret_keys: vec![key],
        key_passwords: vec![&pw],
        decrypt_options: DecryptionOptions::new()
            .enable_gnupg_aead()
            .set_seipdv1_read_mode(Seipdv1ReadMode::Streaming),
        ..Default::default()
    };
    let (mut msg, _) = msg
        .decrypt_the_ring(ring, true)
        .context("decryption failed (key mismatch or wrong passphrase)")?;
    if msg.is_compressed() {
        msg = msg.decompress().context("decompression failed")?;
    }

    if !overwrite && output.exists() {
        bail!("output file already exists: {}", output.display());
    }
    let mut tmp_name = output.as_os_str().to_owned();
    tmp_name.push(".part");
    let tmp = std::path::PathBuf::from(tmp_name);
    let r = write_stream(&mut msg, &tmp, &count, progress);
    if r.is_err() {
        let _ = std::fs::remove_file(&tmp);
        return r;
    }
    if !overwrite && output.exists() {
        let _ = std::fs::remove_file(&tmp);
        bail!("output file already exists: {}", output.display());
    }
    std::fs::rename(&tmp, output).context("cannot move output into place")?;
    r
}

fn write_stream(
    msg: &mut Message<'_>,
    tmp: &Path,
    count: &AtomicU64,
    progress: &mut dyn FnMut(u64) -> bool,
) -> Result<u64> {
    let mut out = BufWriter::new(File::create(tmp).context("cannot create output file")?);
    let mut buf = vec![0u8; CHUNK];
    let mut total = 0u64;
    loop {
        let n = msg.read(&mut buf).context("error while decrypting data")?;
        if n == 0 {
            break;
        }
        out.write_all(&buf[..n])?;
        total += n as u64;
        if !progress(count.load(Ordering::Relaxed)) {
            bail!("cancelled");
        }
    }
    out.flush()?;
    Ok(total)
}

fn is_armored(data: &[u8]) -> bool {
    let data = data.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(data);
    let start = data.iter().position(|b| !b.is_ascii_whitespace()).unwrap_or(0);
    data[start..].starts_with(ARMOR_PREFIX)
}

/// `a.txt.pgp` -> `a.txt`; names without a PGP extension get `.decrypted` appended.
pub fn output_name(input: &Path) -> std::ffi::OsString {
    let name = input.file_name().map(|n| n.to_os_string()).unwrap_or_else(|| "output".into());
    let path = Path::new(&name);
    let is_pgp_ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| matches!(e.to_ascii_lowercase().as_str(), "pgp" | "gpg"))
        .unwrap_or(false);
    match (is_pgp_ext, path.file_stem()) {
        (true, Some(stem)) if !stem.is_empty() => stem.to_os_string(),
        _ => {
            let mut n = name;
            n.push(".decrypted");
            n
        }
    }
}
