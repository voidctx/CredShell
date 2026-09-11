use crate::core::crypto::gcm::Aes256Gcm;
use crate::core::crypto::pbkdf2::derive_key_32;
use crate::core::crypto::rng::{random_12, random_32};
use crate::core::crypto::zeroize::zeroize;
use crate::core::vault::diff::VaultDiff;
use crate::core::vault::json::{vault_from_json, vault_to_json};
use crate::core::vault::model::Vault;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

pub const KXB_MAGIC: &[u8; 8] = b"KXBLOB01";
pub const KXB_ITERATIONS: u32 = 100_000;
pub const MIN_ITERATIONS: u32 = 10_000;
pub const MAX_ITERATIONS: u32 = 2_000_000;

pub fn export_blob(vault: &Vault, passphrase: &str, output_path: &Path) -> Result<(), String> {
    let json_data = vault_to_json(vault);
    let salt = random_32()?;
    let nonce = random_12()?;
    let iterations = KXB_ITERATIONS;

    let mut key = derive_key_32(passphrase.as_bytes(), &salt, iterations);
    let gcm = Aes256Gcm::new(&key);
    zeroize(&mut key);

    let mut aad = Vec::with_capacity(56);
    aad.extend_from_slice(KXB_MAGIC);
    aad.extend_from_slice(&salt);
    aad.extend_from_slice(&nonce);
    aad.extend_from_slice(&iterations.to_be_bytes());

    let (ciphertext, tag) = gcm.encrypt(&nonce, &aad, json_data.as_bytes());

    let mut file_data = Vec::with_capacity(aad.len() + tag.len() + ciphertext.len());
    file_data.extend_from_slice(&aad);
    file_data.extend_from_slice(&tag);
    file_data.extend_from_slice(&ciphertext);

    let mut f = File::create(output_path)
        .map_err(|e| format!("Failed to create export blob {:?}: {}", output_path, e))?;
    f.write_all(&file_data)
        .map_err(|e| format!("Failed to write export blob: {}", e))?;
    f.sync_all()
        .map_err(|e| format!("Failed to sync export blob: {}", e))?;

    Ok(())
}

pub fn read_blob(blob_path: &Path, passphrase: &str) -> Result<Vault, String> {
    let mut f = File::open(blob_path)
        .map_err(|e| format!("Failed to open blob file {:?}: {}", blob_path, e))?;
    let mut data = Vec::new();
    f.read_to_end(&mut data)
        .map_err(|e| format!("Failed to read blob file: {}", e))?;

    const HEADER_LEN: usize = 8 + 32 + 12 + 4 + 16;
    if data.len() < HEADER_LEN {
        return Err("Corrupted .kxb blob: file is too short".to_string());
    }

    if &data[0..8] != KXB_MAGIC {
        return Err("Invalid .kxb file: magic header mismatch".to_string());
    }

    let salt: [u8; 32] = data[8..40].try_into().unwrap();
    let nonce: [u8; 12] = data[40..52].try_into().unwrap();
    let iterations = u32::from_be_bytes(data[52..56].try_into().unwrap());
    if iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS {
        return Err(format!("Blob iterations {} out of safe bounds", iterations));
    }
    let tag: [u8; 16] = data[56..72].try_into().unwrap();
    let ciphertext = &data[72..];

    let aad = &data[0..56];

    let mut key = derive_key_32(passphrase.as_bytes(), &salt, iterations);
    let gcm = Aes256Gcm::new(&key);
    zeroize(&mut key);

    let plaintext = gcm.decrypt(&nonce, aad, ciphertext, &tag)
        .map_err(|_| "Decryption failed: incorrect passphrase or corrupted file".to_string())?;

    let json_str = String::from_utf8(plaintext)
        .map_err(|e| format!("Invalid UTF-8 payload in blob: {}", e))?;

    vault_from_json(&json_str)
}

pub fn stage_blob_import(
    blob_path: &Path,
    blob_passphrase: &str,
    local_vault: &Vault,
) -> Result<(Vault, VaultDiff), String> {
    let incoming_vault = read_blob(blob_path, blob_passphrase)?;
    let diff = VaultDiff::compute(local_vault, &incoming_vault);
    Ok((incoming_vault, diff))
}
