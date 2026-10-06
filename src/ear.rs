//! FileMaker Encryption At Rest (EAR): detect, derive, decrypt, and verify.
//!
//! Protocol (see docs/EAR.md): magic "HBAMe" at 0x0F (plain is "HBAM7"); 4096-byte
//! sectors; sector 0 is plaintext and holds the salt at offset 0xFA. The AES-256 key
//! is PBKDF2-HMAC-SHA1(password UTF-16LE, salt, 18000). Each body sector s>=1 is
//! AES-256-CBC(ct=[0:4064], iv=[4064:4080]); the trailer [4080:4096] is an unreversed
//! MAC. EAR stores no password verifier, so a guess is confirmed by decrypting a
//! sector and recognising structured plaintext.

use std::fs;
use std::path::{Path, PathBuf};

use aes::Aes256;
use aes::cipher::{BlockDecryptMut, KeyIvInit, block_padding::NoPadding};
use regex::bytes::Regex;
use std::sync::OnceLock;

type Aes256CbcDec = cbc::Decryptor<Aes256>;

pub const SECTOR: usize = 4096;
pub const BODY: usize = 4064;
pub const SALT_OFF: usize = 0xFA;
pub const SALT_LEN: usize = 16;
pub const KDF_ITER: u32 = 18000;
pub const CHECK_SECTORS: usize = 48;
pub const GATE_SECTORS: usize = 2;
pub const GATE_BYTES: usize = 256;
pub const GATE_MIN_MAXBIN: u32 = 32;

#[derive(Debug)]
pub struct WrongPassword(pub String);
impl std::fmt::Display for WrongPassword {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "EAR password appears incorrect: {}", self.0)
    }
}
impl std::error::Error for WrongPassword {}

fn verpat() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?:Pro|Server|Go|Advanced|FileMaker) ?\d{1,2}\.\d").unwrap())
}

pub fn is_encrypted(data: &[u8]) -> bool {
    data.len() >= 0x14 && &data[0x0F..0x14] == b"HBAMe"
}

pub fn read_salt(data: &[u8]) -> [u8; SALT_LEN] {
    let mut s = [0u8; SALT_LEN];
    s.copy_from_slice(&data[SALT_OFF..SALT_OFF + SALT_LEN]);
    s
}

pub fn read_hint(data: &[u8]) -> String {
    let head = &data[..SALT_OFF.min(data.len())];
    let mut best = String::new();
    let mut start = 0x10;
    while start + 1 < head.len() {
        let mut run = String::new();
        let mut i = start;
        while i + 1 < head.len() && head[i + 1] == 0 && (0x20..0x7F).contains(&head[i]) {
            run.push(head[i] as char);
            i += 2;
        }
        if run.len() >= 3 && run.len() > best.len() {
            best = run;
        }
        start += 2;
    }
    best
}

pub fn derive_key(password: &str, salt: &[u8]) -> [u8; 32] {
    let pw: Vec<u8> = password.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    let mut key = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<sha1::Sha1>(&pw, salt, KDF_ITER, &mut key);
    key
}

fn cbc_decrypt(ct: &[u8], key: &[u8; 32], iv: &[u8]) -> Vec<u8> {
    let mut buf = ct.to_vec();
    Aes256CbcDec::new(key.into(), iv.into())
        .decrypt_padded_mut::<NoPadding>(&mut buf)
        .unwrap();
    buf
}

fn sector_pt(data: &[u8], s: usize, key: &[u8; 32]) -> Vec<u8> {
    let sec = &data[s * SECTOR..(s + 1) * SECTOR];
    cbc_decrypt(&sec[..BODY], key, &sec[BODY..BODY + 16])
}

fn max_bin(buf: &[u8]) -> u32 {
    let mut h = [0u32; 256];
    for &b in buf {
        h[b as usize] += 1;
    }
    *h.iter().max().unwrap_or(&0)
}

fn has_version(pt: &[u8]) -> bool {
    let dx: Vec<u8> = pt.iter().map(|b| b ^ 0x5A).collect();
    verpat().is_match(&dx)
}

pub fn looks_right(data: &[u8], key: &[u8; 32]) -> bool {
    let total = data.len() / SECTOR;
    if total < 2 {
        return false;
    }
    let mut gated = false;
    for s in 1..=GATE_SECTORS.min(total - 1) {
        let pt = sector_pt(data, s, key);
        if max_bin(&pt[..GATE_BYTES.min(pt.len())]) >= GATE_MIN_MAXBIN {
            gated = true;
            if has_version(&pt) {
                return true;
            }
        }
    }
    if !gated {
        return false;
    }
    for s in 1..=CHECK_SECTORS.min(total - 1) {
        if has_version(&sector_pt(data, s, key)) {
            return true;
        }
    }
    false
}

/// Fast gate for a candidate key: decrypt only the first GATE_BYTES of body
/// sector 1 and test the max byte-frequency. A wrong key is near-uniform (low),
/// a correct key is structured (high). Confirm a pass with `looks_right`.
pub fn gate_ok(data: &[u8], key: &[u8; 32]) -> bool {
    if data.len() / SECTOR < 2 {
        return false;
    }
    let sec = &data[SECTOR..2 * SECTOR];
    let n = GATE_BYTES.min(BODY);
    let pt = cbc_decrypt(&sec[..n], key, &sec[BODY..BODY + 16]);
    max_bin(&pt) >= GATE_MIN_MAXBIN
}

pub fn check_password(data: &[u8], salt: &[u8], password: &str) -> bool {
    looks_right(data, &derive_key(password, salt))
}

pub fn new_path(out: &Path) -> PathBuf {
    if !out.exists() {
        return out.to_path_buf();
    }
    let stem = out.file_stem().unwrap_or_default().to_string_lossy().to_string();
    let ext = out.extension().map(|e| e.to_string_lossy().to_string());
    let dir = out.parent().unwrap_or_else(|| Path::new("."));
    let mut n = 2;
    loop {
        let name = match &ext {
            Some(e) => format!("{stem}_v{n}.{e}"),
            None => format!("{stem}_v{n}"),
        };
        let cand = dir.join(name);
        if !cand.exists() {
            return cand;
        }
        n += 1;
    }
}

pub fn decrypt_file(
    path: &Path,
    password: &str,
    out: Option<&Path>,
    verify: bool,
) -> anyhow::Result<(PathBuf, [u8; 32])> {
    let data = fs::read(path)?;
    if !is_encrypted(&data) {
        anyhow::bail!("not an EAR file (magic is not HBAMe): {}", path.display());
    }
    if data.len() % SECTOR != 0 {
        anyhow::bail!("file size is not a multiple of {SECTOR}");
    }
    let salt = read_salt(&data);
    let key = derive_key(password, &salt);
    if verify && !looks_right(&data, &key) {
        return Err(WrongPassword(
            path.file_name().unwrap_or_default().to_string_lossy().to_string(),
        )
        .into());
    }

    let mut out_buf = Vec::with_capacity(data.len());
    for s in 0..(data.len() / SECTOR) {
        let sec = &data[s * SECTOR..(s + 1) * SECTOR];
        if s == 0 {
            let mut h = sec.to_vec();
            if &h[0x0F..0x14] == b"HBAMe" {
                h[0x13] = b'7';
            }
            out_buf.extend_from_slice(&h);
        } else {
            let pt = cbc_decrypt(&sec[..BODY], &key, &sec[BODY..BODY + 16]);
            out_buf.extend_from_slice(&pt);
            out_buf.extend_from_slice(&sec[BODY..SECTOR]);
        }
    }

    let default_out = {
        let stem = path.file_stem().unwrap_or_default().to_string_lossy().to_string();
        let ext = path.extension().map(|e| e.to_string_lossy().to_string()).unwrap_or_else(|| "fmp12".into());
        let mut p = path.to_path_buf();
        p.set_file_name(format!("{stem}_DECRYPTED.{ext}"));
        p
    };
    let target = new_path(out.unwrap_or(&default_out));
    fs::write(&target, &out_buf)?;
    Ok((target, key))
}
