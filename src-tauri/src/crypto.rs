//! Credential encryption at rest.
//!
//! Passwords stored in the local SQLite database (`connections.password` and
//! `db_credentials.password`) are encrypted with AES-256-GCM. The symmetric key is
//! obtained from the OS keychain (macOS Keychain / Windows Credential Manager /
//! Linux secret-service) via the `keyring` crate, with a best-effort fallback to a
//! `0600` key file when no keychain backend is available.
//!
//! Ciphertext format: `"enc::" + base64(nonce[12] || ciphertext)`.
//! Values without the `enc::` prefix are returned unchanged so that existing
//! plaintext rows remain readable (transparent migration on first rewrite).

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use std::sync::OnceLock;

const SERVICE: &str = "MPanel";
const KEY_ENTRY: &str = "db-encryption-key";
const PREFIX: &str = "enc::";

fn master_key() -> &'static [u8] {
    static KEY: OnceLock<Vec<u8>> = OnceLock::new();
    KEY.get_or_init(load_or_create_key)
}

fn load_or_create_key() -> Vec<u8> {
    // 1) Prefer the OS keychain.
    if let Ok(entry) = keyring::Entry::new(SERVICE, KEY_ENTRY) {
        if let Ok(b64) = entry.get_password() {
            if let Ok(k) = B64.decode(b64.trim()) {
                if k.len() == 32 {
                    return k;
                }
            }
        }
        let key = Aes256Gcm::generate_key(OsRng);
        let kb = key.as_slice().to_vec();
        // Best-effort: store the key; if this fails we still use it for this run.
        let _ = entry.set_password(&B64.encode(&kb));
        return kb;
    }
    // 2) Fallback: a key file in the app data dir.
    fallback_key()
}

#[cfg(unix)]
fn write_key_file(path: &std::path::Path, contents: &str) {
    let _ = std::fs::write(path, contents);
    let _ = std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o600));
}

#[cfg(not(unix))]
fn write_key_file(path: &std::path::Path, contents: &str) {
    let _ = std::fs::write(path, contents);
}

fn fallback_key() -> Vec<u8> {
    let dir = crate::db::db_dir();
    let path = dir.join("mpanel.key");
    if let Ok(s) = std::fs::read_to_string(&path) {
        if let Ok(k) = B64.decode(s.trim()) {
            if k.len() == 32 {
                return k;
            }
        }
    }
    let key = Aes256Gcm::generate_key(OsRng);
    let kb = key.as_slice().to_vec();
    write_key_file(&path, &B64.encode(&kb));
    kb
}

/// Encrypt a plaintext secret. Empty input stays empty.
pub fn encrypt(plaintext: &str) -> String {
    if plaintext.is_empty() {
        return String::new();
    }
    let key = Key::<Aes256Gcm>::from_slice(master_key());
    let cipher = Aes256Gcm::new(key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    match cipher.encrypt(&nonce, plaintext.as_bytes()) {
        Ok(ct) => {
            let mut combined = nonce.as_slice().to_vec();
            combined.extend_from_slice(&ct);
            format!("{}{}", PREFIX, B64.encode(combined))
        }
        Err(_) => plaintext.to_string(),
    }
}

/// Decrypt a stored value. Values without the `enc::` prefix are returned unchanged
/// (transparent migration from legacy plaintext rows).
pub fn decrypt(stored: &str) -> String {
    let Some(b64) = stored.strip_prefix(PREFIX) else {
        return stored.to_string();
    };
    let Ok(combined) = B64.decode(b64) else {
        return String::new();
    };
    if combined.len() <= 12 {
        return String::new();
    }
    let (nonce_b, ct) = combined.split_at(12);
    let nonce = Nonce::from_slice(nonce_b);
    let key = Key::<Aes256Gcm>::from_slice(master_key());
    let cipher = Aes256Gcm::new(key);
    match cipher.decrypt(nonce, ct) {
        Ok(pt) => String::from_utf8_lossy(&pt).to_string(),
        Err(_) => String::new(),
    }
}
