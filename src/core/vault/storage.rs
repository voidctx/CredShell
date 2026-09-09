use super::json::{vault_from_json, vault_to_json};
use super::model::Vault;
use crate::core::crypto::gcm::Aes256Gcm;
use crate::core::crypto::pbkdf2::derive_key_32;
use crate::core::crypto::rng::{random_12, random_32};
use crate::core::crypto::zeroize::zeroize;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

pub const MAGIC: &[u8; 8] = b"KERNVAUL";
pub const CURRENT_VERSION: u32 = 1;
pub const DEFAULT_ITERATIONS: u32 = 100_000;

pub const MIN_ITERATIONS: u32 = 10_000;
pub const MAX_ITERATIONS: u32 = 5_000_000;

pub fn default_vault_path() -> PathBuf {
    let local_dir = Path::new(".credshell");
    if !local_dir.exists() {
        let _ = fs::create_dir_all(local_dir);
    }
    local_dir.join("vault.kdb")
}

pub fn encrypt_vault(vault: &Vault, passphrase: &str) -> Result<Vec<u8>, String> {
    let mut json_data = vault_to_json(vault);
    let salt = random_32()?;
    let nonce = random_12()?;
    let iterations = DEFAULT_ITERATIONS;

    let mut key = derive_key_32(passphrase.as_bytes(), &salt, iterations);
    let gcm = Aes256Gcm::new(&key);
    zeroize(&mut key);

    let mut aad = Vec::with_capacity(60);
    aad.extend_from_slice(MAGIC);
    aad.extend_from_slice(&CURRENT_VERSION.to_be_bytes());
    aad.extend_from_slice(&salt);
    aad.extend_from_slice(&nonce);
    aad.extend_from_slice(&iterations.to_be_bytes());

    let (ciphertext, tag) = gcm.encrypt(&nonce, &aad, json_data.as_bytes());
    unsafe {
        zeroize(json_data.as_bytes_mut());
    }

    let mut out = Vec::with_capacity(aad.len() + tag.len() + ciphertext.len());
    out.extend_from_slice(&aad);
    out.extend_from_slice(&tag);
    out.extend_from_slice(&ciphertext);

    Ok(out)
}

pub fn decrypt_vault(data: &[u8], passphrase: &str) -> Result<Vault, String> {
    const MIN_LEN: usize = 8 + 4 + 32 + 12 + 4 + 16;
    if data.len() < MIN_LEN {
        return Err("Invalid vault data: file is corrupted or too short".to_string());
    }

    if &data[0..8] != MAGIC {
        return Err("Invalid vault file: incorrect magic header".to_string());
    }

    let version = u32::from_be_bytes(data[8..12].try_into().unwrap());
    if version != CURRENT_VERSION {
        return Err(format!("Unsupported vault version: {}", version));
    }

    let salt: [u8; 32] = data[12..44].try_into().unwrap();
    let nonce: [u8; 12] = data[44..56].try_into().unwrap();
    let iterations = u32::from_be_bytes(data[56..60].try_into().unwrap());
    if iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS {
        return Err(format!(
            "Vault iterations {} out of safe bounds ({}..={})",
            iterations, MIN_ITERATIONS, MAX_ITERATIONS
        ));
    }
    let tag: [u8; 16] = data[60..76].try_into().unwrap();
    let ciphertext = &data[76..];

    let aad = &data[0..60];

    let mut key = derive_key_32(passphrase.as_bytes(), &salt, iterations);
    let gcm = Aes256Gcm::new(&key);
    zeroize(&mut key);

    let mut plaintext_bytes = gcm.decrypt(&nonce, aad, ciphertext, &tag)?;
    let mut json_str = String::from_utf8(plaintext_bytes.clone())
        .map_err(|e| {
            zeroize(&mut plaintext_bytes);
            format!("Corrupted vault plaintext: invalid UTF-8 ({})", e)
        })?;
    zeroize(&mut plaintext_bytes);

    let vault = vault_from_json(&json_str)?;
    unsafe {
        zeroize(json_str.as_bytes_mut());
    }
    Ok(vault)
}

pub fn save_vault_atomic(path: &Path, vault: &Vault, passphrase: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create directory {:?}: {}", parent, e))?;
        }
    }

    let encrypted_data = encrypt_vault(vault, passphrase)?;
    let tmp_path = path.with_extension("tmp");

    {
        let mut f = File::create(&tmp_path)
            .map_err(|e| format!("Failed to create temporary file {:?}: {}", tmp_path, e))?;
        f.write_all(&encrypted_data)
            .map_err(|e| format!("Failed to write encrypted data: {}", e))?;
        f.sync_all()
            .map_err(|e| format!("Failed to sync temporary file: {}", e))?;
    }

    fs::rename(&tmp_path, path)
        .map_err(|e| format!("Failed to atomically replace vault file {:?}: {}", path, e))?;

    Ok(())
}

pub fn load_vault(path: &Path, passphrase: &str) -> Result<Vault, String> {
    let mut file = File::open(path)
        .map_err(|e| format!("Failed to open vault file {:?}: {}", path, e))?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)
        .map_err(|e| format!("Failed to read vault file: {}", e))?;

    let mut vault = decrypt_vault(&data, passphrase)?;

    const SEVEN_DAYS_SECS: u64 = 7 * 86400;
    let expired_count = vault.passkeys.iter().filter(|p| {
        if let Some(ts) = Vault::parse_bak_timestamp(&p.id) {
            let now = crate::core::vault::model::now_secs();
            now >= ts && (now - ts) > SEVEN_DAYS_SECS
        } else {
            false
        }
    }).count();

    if expired_count > 0 {
        let snapshot_path = path.with_extension("kdb.pruned_bak");
        let _ = save_vault_atomic(&snapshot_path, &vault, passphrase);
        eprintln!("[CredShell Audit] Pruning {} expired backup passkey(s) (>7 days old). Safety snapshot archived at {:?}", expired_count, snapshot_path);
        if vault.prune_expired_backups(SEVEN_DAYS_SECS) {
            let _ = save_vault_atomic(path, &vault, passphrase);
        }
    }

    Ok(vault)
}
