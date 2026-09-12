use super::args::PasskeyAction;
use super::output::{print_totp_json, print_totp_result};
use crate::core::sync::blob::{export_blob, stage_blob_import};
use crate::core::sync::transport::{run_receiver, run_transmitter};
use crate::core::totp::base32::decode_base32;
use crate::core::totp::{generate_totp_now, HmacAlgorithm};
use crate::core::vault::model::Vault;
use crate::core::vault::storage::{load_vault, save_vault_atomic};
use crate::platform::{get_default_device_name, prompt_passphrase};
use std::env;
use std::io::{self, Write};
use std::path::Path;

pub fn get_or_unlock_vault(
    path: &Path,
    password_opt: Option<&str>,
) -> Result<(Vault, String), String> {
    let resolved_pass = if let Some(p) = password_opt {
        if p.is_empty() {
            return Err("Supplied password cannot be empty".to_string());
        }
        p.to_string()
    } else if let Ok(pass) = env::var("CREDSHELL_PASSWORD").or_else(|_| env::var("CREDSHELL_PASSPHRASE")) {
        if !pass.trim().is_empty() {
            eprintln!("\x1b[33m[Warning]\x1b[0m Master password supplied via environment variable. Ensure this variable is not exposed in shared shell environments.");
            pass.trim().to_string()
        } else {
            prompt_passphrase("Enter vault master password: ")?
        }
    } else {
        prompt_passphrase("Enter vault master password: ")?
    };

    if !path.exists() {
        println!("Initializing new encrypted vault at {:?}...", path);
        let device_name = get_default_device_name();
        let vault = Vault::new(device_name)?;
        save_vault_atomic(path, &vault, &resolved_pass)?;
        println!("✓ New vault created and encrypted with AES-256-GCM (PBKDF2-SHA-512) at {:?}", path);
        return Ok((vault, resolved_pass));
    }

    let vault = load_vault(path, &resolved_pass)?;
    Ok((vault, resolved_pass))
}

pub fn handle_totp_get(
    vault_path: &Path,
    name: &str,
    json: bool,
) -> Result<(), String> {
    let (vault, _) = get_or_unlock_vault(vault_path, None)?;

    let entry = vault.get_totp(name)
        .ok_or_else(|| format!("TOTP entry '{}' not found in vault {:?}", name, vault_path))?;

    let secret_bytes = decode_base32(&entry.secret_base32)?;
    let algo = HmacAlgorithm::from_str(&entry.algorithm)?;
    let result = generate_totp_now(&secret_bytes, entry.period, entry.digits, algo)?;

    if json {
        print_totp_json(&result);
    } else {
        print_totp_result(&entry.issuer, &result);
    }

    Ok(())
}

pub fn handle_totp_add(
    vault_path: &Path,
    id_opt: Option<String>,
    secret_or_uri: &str,
    issuer_opt: Option<String>,
    account_opt: Option<String>,
    algo_opt: Option<String>,
) -> Result<(), String> {
    let (secret, final_issuer, final_account, final_algo, suggested_id) =
        if secret_or_uri.trim().starts_with("otpauth://") {
            let parsed = crate::core::totp::uri::parse_otpauth_uri(secret_or_uri)?;
            let sug = parsed.suggested_id();
            let iss = issuer_opt.or(parsed.issuer);
            let acc = account_opt.or(parsed.account);
            let alg = algo_opt.or(parsed.algorithm);
            (parsed.secret, iss, acc, alg, sug)
        } else {
            let clean = crate::core::totp::base32::clean_base32(secret_or_uri);
            decode_base32(&clean)
                .map_err(|e| format!("Invalid Base32 secret: {}", e))?;
            let sug = issuer_opt.clone()
                .or_else(|| account_opt.clone())
                .unwrap_or_else(|| "totp-entry".to_string());
            (clean, issuer_opt, account_opt, algo_opt, sug)
        };

    let (mut vault, passphrase) = get_or_unlock_vault(vault_path, None)?;

    let chosen_id = match id_opt {
        Some(id) => {
            if vault.totp_entries.iter().any(|e| e.id.eq_ignore_ascii_case(&id)) {
                return Err(format!("A TOTP entry with ID '{}' already exists in the vault", id));
            }
            id
        }
        None => {
            let default_id = vault.generate_unique_totp_id(&suggested_id);
            loop {
                print!("Enter unique ID for this TOTP entry [default: {}]: ", default_id);
                io::stdout().flush().map_err(|e| e.to_string())?;
                let mut input = String::new();
                io::stdin().read_line(&mut input).map_err(|e| e.to_string())?;
                let trimmed = input.trim();
                let candidate = if trimmed.is_empty() {
                    default_id.clone()
                } else {
                    trimmed.to_string()
                };

                if vault.totp_entries.iter().any(|e| e.id.eq_ignore_ascii_case(&candidate)) {
                    println!("\x1b[31mError:\x1b[0m ID '{}' already exists in the vault. Please choose a different ID.", candidate);
                    continue;
                }
                break candidate;
            }
        }
    };

    let iss_str = final_issuer.as_deref().unwrap_or(&chosen_id);
    let entry = vault.add_totp_with_id(
        &chosen_id,
        iss_str,
        &secret,
        Some(iss_str),
        final_account.as_deref(),
        final_algo.as_deref(),
    )?;

    save_vault_atomic(vault_path, &vault, &passphrase)?;
    println!("✓ Successfully added TOTP entry with ID '{}' ({}) to {:?}", entry.id, entry.issuer, vault_path);
    Ok(())
}

pub fn handle_totp_list(
    vault_path: &Path,
    json: bool,
) -> Result<(), String> {
    let (vault, _) = get_or_unlock_vault(vault_path, None)?;

    if json {
        println!("[");
        for (i, e) in vault.totp_entries.iter().enumerate() {
            println!("  {{");
            println!("    \"id\": \"{}\",", e.id);
            println!("    \"name\": \"{}\",", e.name);
            println!("    \"issuer\": \"{}\",", e.issuer);
            println!("    \"account\": \"{}\",", e.account);
            println!("    \"algorithm\": \"{}\",", e.algorithm);
            println!("    \"period\": {}", e.period);
            if i + 1 < vault.totp_entries.len() {
                println!("  }},");
            } else {
                println!("  }}");
            }
        }
        println!("]");
        return Ok(());
    }

    println!("CredShell Vault {:?} ({} TOTP items):\n", vault_path, vault.totp_entries.len());
    if vault.totp_entries.is_empty() {
        println!("  (No TOTP entries found. Use 'credshell totp add' to create one.)");
        return Ok(());
    }

    for e in &vault.totp_entries {
        println!("• ID: {:<20} Issuer: {:<16} Account: {}", e.id, e.issuer, e.account);
    }
    Ok(())
}

pub fn handle_totp_delete(
    vault_path: &Path,
    id: &str,
) -> Result<(), String> {
    let (mut vault, passphrase) = get_or_unlock_vault(vault_path, None)?;
    if !vault.delete_totp(id) {
        return Err(format!("Entry with ID '{}' not found in vault {:?}", id, vault_path));
    }
    save_vault_atomic(vault_path, &vault, &passphrase)?;
    println!("✓ Successfully deleted TOTP entry '{}'", id);
    Ok(())
}

pub fn handle_passkey(
    vault_path: &Path,
    action: Option<PasskeyAction>,
) -> Result<(), String> {
    let (mut vault, passphrase) = get_or_unlock_vault(vault_path, None)?;

    match action {
        None => {
            let listener = crate::core::passkey::PasskeyListener::new(
                crate::core::passkey::DEFAULT_PASSKEY_PORT,
                vault_path,
                &passphrase,
                false,
            );
            listener.run(&mut vault)?;
        }
        Some(PasskeyAction::Listen { port, auto_approve }) => {
            let listener = crate::core::passkey::PasskeyListener::new(
                port,
                vault_path,
                &passphrase,
                auto_approve,
            );
            listener.run(&mut vault)?;
        }
        Some(PasskeyAction::List) => {
            let active_keys: Vec<&crate::core::vault::PasskeyCredential> = vault
                .passkeys
                .iter()
                .filter(|p| !Vault::is_bak_passkey(&p.id))
                .collect();
            println!("CredShell Vault {:?} ({} Active Passkeys):\n", vault_path, active_keys.len());
            if active_keys.is_empty() {
                println!("  (No active passkeys stored in vault)");
                return Ok(());
            }
            for p in &active_keys {
                let alg_name = if p.alg == -8 { "EdDSA (Ed25519)" } else { "ES256 (P-256)" };
                println!("• ID: {:<28} RP: {:<20} User: {:<16} Alg: {:<16} Signs: {}", p.id, p.rp_id, p.user_name, alg_name, p.sign_count);
            }
        }
        Some(PasskeyAction::ListBak) => {
            let bak_keys: Vec<&crate::core::vault::PasskeyCredential> = vault
                .passkeys
                .iter()
                .filter(|p| Vault::is_bak_passkey(&p.id))
                .collect();
            println!("CredShell Vault {:?} ({} Backup Passkeys):\n", vault_path, bak_keys.len());
            if bak_keys.is_empty() {
                println!("  (No backup passkeys found in vault)");
                return Ok(());
            }
            for p in &bak_keys {
                let ts = Vault::parse_bak_timestamp(&p.id).unwrap_or(0);
                let base_id = Vault::get_bak_base_id(&p.id);
                let restore_id = format!("{}-bak", base_id);
                println!("• Restore ID: {:<30} (Stored: {}) | Unix Time: {} | Signs: {}", restore_id, p.id, ts, p.sign_count);
            }
        }
        Some(PasskeyAction::Restore { id }) => {
            let (restored_id, moved_bak_id) = vault.restore_backup_passkey(&id)?;
            save_vault_atomic(vault_path, &vault, &passphrase)?;
            println!("✓ Successfully restored passkey '{}'", restored_id);
            if !moved_bak_id.is_empty() {
                println!("  Previous active passkey moved to backup: '{}'", moved_bak_id);
            }
        }
        Some(PasskeyAction::Delete { id_or_rp }) => {
            if !vault.delete_passkey(&id_or_rp) {
                return Err(format!("No passkey found matching ID/RP '{}'", id_or_rp));
            }
            save_vault_atomic(vault_path, &vault, &passphrase)?;
            println!("✓ Successfully deleted passkey '{}'", id_or_rp);
        }
        Some(PasskeyAction::InstallManifest) => {
            install_browser_native_manifest()?;
        }
    }

    Ok(())
}

pub fn handle_vault_status(
    vault_path: &Path,
) -> Result<(), String> {
    let (vault, _) = get_or_unlock_vault(vault_path, None)?;
    println!("╭──────────────────────────────────────────────╮");
    println!("│             CREDSHELL VAULT STATUS              │");
    println!("├──────────────────────────────────────────────┤");
    println!("│ Path:            {:<28}│", vault_path.to_string_lossy());
    println!("│ Version:         {:<28}│", vault.version);
    println!("│ Device:          {:<28}│", vault.device_name);
    println!("│ TOTP Entries:    {:<28}│", vault.totp_entries.len());
    println!("│ Passkeys:        {:<28}│", vault.passkeys.len());
    println!("│ Trusted Devices: {:<28}│", vault.trusted_devices.len());
    println!("╰──────────────────────────────────────────────╯");
    Ok(())
}

pub fn handle_vault_change_password(
    vault_path: &Path,
    new_password_opt: Option<String>,
) -> Result<(), String> {
    let (vault, _old_pass) = get_or_unlock_vault(vault_path, None)?;

    let new_pass = match new_password_opt {
        Some(p) => p,
        None => {
            prompt_passphrase("Enter new master password: ")?
        }
    };

    save_vault_atomic(vault_path, &vault, &new_pass)?;
    println!("✓ Master passphrase updated and vault re-encrypted at {:?}", vault_path);
    Ok(())
}

fn install_browser_native_manifest() -> Result<(), String> {
    let exe_path = env::current_exe().map_err(|e| e.to_string())?;
    let manifest_dir = env::var("LOCALAPPDATA")
        .map(|p| std::path::PathBuf::from(p).join("CredShell"))
        .unwrap_or_else(|_| std::path::PathBuf::from(".credshell"));

    std::fs::create_dir_all(&manifest_dir).map_err(|e| e.to_string())?;
    let manifest_path = manifest_dir.join("com.credshell.passkey.json");

    let exe_str = exe_path.to_string_lossy().replace('\\', "\\\\");
    let manifest_content = format!(
        "{{\n  \"name\": \"com.credshell.passkey\",\n  \"description\": \"CredShell Native Passkey Authenticator\",\n  \"path\": \"{}\",\n  \"type\": \"stdio\",\n  \"allowed_origins\": [\"chrome-extension://*/\"]\n}}\n",
        exe_str
    );

    std::fs::write(&manifest_path, manifest_content).map_err(|e| e.to_string())?;
    println!("✓ Native messaging manifest written to {:?}", manifest_path);
    println!("✓ Registry registration commands for Chrome and Edge:");
    println!("  reg add \"HKCU\\Software\\Google\\Chrome\\NativeMessagingHosts\\com.credshell.passkey\" /ve /t REG_SZ /d \"{}\" /f", manifest_path.to_string_lossy());
    println!("  reg add \"HKCU\\Software\\Microsoft\\Edge\\NativeMessagingHosts\\com.credshell.passkey\" /ve /t REG_SZ /d \"{}\" /f", manifest_path.to_string_lossy());
    Ok(())
}

pub fn handle_sync_rx(
    vault_path: &Path,
    port: u16,
) -> Result<(), String> {
    let (vault, passphrase) = get_or_unlock_vault(vault_path, None)?;
    run_receiver(port, vault_path, &passphrase, vault)
}

pub fn handle_sync_tx(
    vault_path: &Path,
    target: &str,
) -> Result<(), String> {
    let (vault, _) = get_or_unlock_vault(vault_path, None)?;
    run_transmitter(target, &vault)
}

pub fn handle_export(
    vault_path: &Path,
    output_path: &str,
) -> Result<(), String> {
    let (vault, vault_pass) = get_or_unlock_vault(vault_path, None)?;
    export_blob(&vault, &vault_pass, Path::new(output_path))?;
    println!("✓ Encrypted blob exported successfully to {:?}", output_path);
    println!("  Encryption: AES-256-GCM + PBKDF2-SHA-512 (100,000 iterations)");
    Ok(())
}

pub fn handle_import(
    vault_path: &Path,
    input_path: &str,
) -> Result<(), String> {
    let (mut vault, passphrase) = get_or_unlock_vault(vault_path, None)?;
    let path = Path::new(input_path);
    println!("Reading and authenticating blob {:?}...", input_path);

    let (incoming_vault, diff) = stage_blob_import(path, &passphrase, &vault)?;
    let preview = diff.format_preview(&incoming_vault.device_name, &vault.device_name);
    print!("{}", preview);

    if diff.is_empty() {
        println!("No changes to import.");
        return Ok(());
    }

    println!("\nApplying authenticated transaction...\n");
    diff.apply(&mut vault);
    save_vault_atomic(vault_path, &vault, &passphrase)?;

    println!("[████████████████████] 100%");
    println!("✓ Transaction authenticated");
    println!("✓ Integrity verified");
    println!("✓ Vault committed");

    Ok(())
}
