//! Persists the private key and passphrase in `%APPDATA%\MyPgpDecrypt\key.bin`,
//! encrypted with Windows DPAPI (bound to the current Windows user).
use anyhow::{bail, Result};
use zeroize::{Zeroize, ZeroizeOnDrop};

const MAGIC: &[u8; 4] = b"MPD1";

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Credentials {
    pub key: Vec<u8>,
    pub passphrase: String,
}

impl Credentials {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(12 + self.key.len() + self.passphrase.len());
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&(self.key.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.key);
        out.extend_from_slice(&(self.passphrase.len() as u32).to_le_bytes());
        out.extend_from_slice(self.passphrase.as_bytes());
        out
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        fn take<'a>(data: &mut &'a [u8], n: usize) -> Result<&'a [u8]> {
            if data.len() < n {
                bail!("Key file is corrupted");
            }
            let (head, rest) = data.split_at(n);
            *data = rest;
            Ok(head)
        }
        let mut rest = data;
        if take(&mut rest, 4)? != MAGIC {
            bail!("Key file has an unknown format");
        }
        let klen = u32::from_le_bytes(take(&mut rest, 4)?.try_into()?) as usize;
        let key = take(&mut rest, klen)?.to_vec();
        let plen = u32::from_le_bytes(take(&mut rest, 4)?.try_into()?) as usize;
        let passphrase = String::from_utf8(take(&mut rest, plen)?.to_vec())?;
        Ok(Self { key, passphrase })
    }
}

#[cfg(windows)]
pub use dpapi_store::{key_path, load, save};

#[cfg(windows)]
mod dpapi_store {
    use std::path::PathBuf;

    use anyhow::{anyhow, Context, Result};
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    use super::Credentials;

    /// App-specific extra secret mixed into DPAPI.
    const ENTROPY: &[u8] = b"MyPgpDecrypt/mykey/v1";

    /// `%APPDATA%\MyPgpDecrypt\key.bin`
    pub fn key_path() -> Result<PathBuf> {
        let appdata = std::env::var_os("APPDATA").ok_or_else(|| anyhow!("APPDATA is not set"))?;
        Ok(PathBuf::from(appdata).join("MyPgpDecrypt").join("key.bin"))
    }


    fn blob(data: &[u8]) -> CRYPT_INTEGER_BLOB {
        CRYPT_INTEGER_BLOB { cbData: data.len() as u32, pbData: data.as_ptr() as *mut u8 }
    }

    /// Copy a DPAPI output blob into a Vec and free the system buffer.
    unsafe fn take_blob(out: CRYPT_INTEGER_BLOB, wipe: bool) -> Vec<u8> {
        unsafe {
            let slice = std::slice::from_raw_parts_mut(out.pbData, out.cbData as usize);
            let v = slice.to_vec();
            if wipe {
                slice.fill(0);
            }
            let _ = LocalFree(Some(HLOCAL(out.pbData as *mut _)));
            v
        }
    }

    fn protect(plain: &[u8]) -> Result<Vec<u8>> {
        let input = blob(plain);
        let entropy = blob(ENTROPY);
        let mut out = CRYPT_INTEGER_BLOB::default();
        unsafe {
            CryptProtectData(
                &input,
                PCWSTR::null(),
                Some(&entropy),
                None,
                None,
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            )
            .context("DPAPI encryption failed")?;
            Ok(take_blob(out, false))
        }
    }

    fn unprotect(cipher: &[u8]) -> Result<Vec<u8>> {
        let input = blob(cipher);
        let entropy = blob(ENTROPY);
        let mut out = CRYPT_INTEGER_BLOB::default();
        unsafe {
            CryptUnprotectData(
                &input,
                None,
                Some(&entropy),
                None,
                None,
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            )
            .context("DPAPI decryption failed (key file was saved by another Windows user?)")?;
            Ok(take_blob(out, true))
        }
    }

    pub fn save(creds: &Credentials) -> Result<()> {
        let path = key_path()?;
        let dir = path.parent().unwrap();
        std::fs::create_dir_all(dir).context("Cannot create key directory")?;
        let mut plain = creds.encode();
        let protected = protect(&plain);
        zeroize::Zeroize::zeroize(&mut plain);
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, protected?).context("Cannot write key file")?;
        std::fs::rename(&tmp, &path).context("Cannot replace key file")?;
        Ok(())
    }

    /// Returns `Ok(None)` when nothing has been saved yet.
    pub fn load() -> Result<Option<Credentials>> {
        let path = key_path()?;
        let data = match std::fs::read(&path) {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e).context("Cannot read key file"),
        };
        let mut plain = unprotect(&data)?;
        let creds = Credentials::decode(&plain);
        zeroize::Zeroize::zeroize(&mut plain);
        Ok(Some(creds?))
    }
}
