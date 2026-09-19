use super::protocol::{
    read_frame, rx_handshake, send_frame, tx_handshake, MSG_SYNC_ACK, MSG_SYNC_PAYLOAD,
};
use crate::core::crypto::gcm::Aes256Gcm;
use crate::core::crypto::rng::random_12;
use crate::core::vault::diff::VaultDiff;
use crate::core::vault::json::{vault_from_json, vault_to_json};
use crate::core::vault::model::Vault;
use crate::core::vault::storage::save_vault_atomic;
use std::net::{IpAddr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::path::Path;

pub const DEFAULT_SYNC_PORT: u16 = 7443;

pub fn run_receiver(
    port: u16,
    vault_path: &Path,
    passphrase: &str,
    mut local_vault: Vault,
) -> Result<(), String> {
    println!("CredShell Synchronization Receiver\n");
    println!("Listening for incoming connections on port {}...\n", port);
    println!("IPv6 addresses:");
    println!("  [1] ::1 (Loopback)");
    println!("  [2] [::] (All IPv6 Interfaces)");
    println!("\nWaiting for transmitter...");

    let bind_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port);
    let listener = TcpListener::bind(bind_addr).or_else(|_| {
        TcpListener::bind(format!("0.0.0.0:{}", port))
    }).map_err(|e| format!("Failed to bind to port {}: {}", port, e))?;

    let (mut stream, peer_addr) = listener.accept()
        .map_err(|e| format!("Failed to accept incoming connection: {}", e))?;

    println!("\nConnection established from: {}\nPerforming cryptographic device handshake...", peer_addr);

    let (peer_info, session_key) = rx_handshake(&mut stream, &local_vault)?;
    println!("✓ Authenticated device identity: {}", peer_info.device_name);

    let (msg_type, enc_payload) = read_frame(&mut stream)?;
    if msg_type != MSG_SYNC_PAYLOAD || enc_payload.len() < 12 + 16 {
        return Err("Invalid sync payload frame".to_string());
    }

    let nonce: [u8; 12] = enc_payload[..12].try_into().unwrap();
    let tag: [u8; 16] = enc_payload[12..28].try_into().unwrap();
    let ciphertext = &enc_payload[28..];

    let gcm = Aes256Gcm::new(&session_key);
    let decrypted_bytes = gcm.decrypt(&nonce, b"CREDSHELL_SYNC_DATA", ciphertext, &tag)?;
    let incoming_json = String::from_utf8(decrypted_bytes)
        .map_err(|e| format!("Invalid UTF-8 in sync payload: {}", e))?;

    let incoming_vault = vault_from_json(&incoming_json)?;

    let diff = VaultDiff::compute(&local_vault, &incoming_vault);
    let preview = diff.format_preview(&peer_info.device_name, &local_vault.device_name);
    print!("{}", preview);

    if diff.is_empty() {
        println!("No changes to apply.");
        send_frame(&mut stream, MSG_SYNC_ACK, &[0x01])?;
        return Ok(());
    }

    println!("Requesting native platform authorization...");
    let approved = crate::platform::native_gui_confirm(
        "CredShell Vault Synchronization",
        &format!(
            "Incoming vault synchronization from authenticated peer '{}'.\n\nApply incoming changes to local vault?",
            peer_info.device_name
        ),
    );

    if approved {
        println!("\nApplying transaction...\n");
        diff.apply(&mut local_vault);
        save_vault_atomic(vault_path, &local_vault, passphrase)?;

        println!("[████████████████████] 100%");
        println!("✓ Transaction authenticated");
        println!("✓ Integrity verified");
        println!("✓ Vault committed");

        send_frame(&mut stream, MSG_SYNC_ACK, &[0x01])?;
    } else {
        println!("Synchronization aborted by user.");
        send_frame(&mut stream, MSG_SYNC_ACK, &[0x00])?;
    }

    Ok(())
}

pub fn run_transmitter(
    target_addr: &str,
    vault: &Vault,
) -> Result<(), String> {
    println!("CredShell Synchronization Transmitter\n");
    println!("Connecting to {}...", target_addr);

    let mut stream = TcpStream::connect(target_addr)
        .map_err(|e| format!("Failed to connect to recipient at {}: {}", target_addr, e))?;

    println!("Performing cryptographic device authentication...");
    let (peer_info, session_key) = tx_handshake(&mut stream, vault)?;
    println!("✓ Authenticated recipient: {}", peer_info.device_name);

    let is_trusted = vault.trusted_devices.iter().any(|d| d.public_key == peer_info.public_key && d.trusted);
    if !is_trusted {
        let hex_key: String = peer_info.public_key.iter().map(|b| format!("{:02x}", b)).collect();
        let prompt_msg = format!(
            "Recipient device '{}' is not pinned in trusted devices.\nKey: {}\n\nAuthorize vault transmission to this device?",
            peer_info.device_name, hex_key
        );
        let confirmed = crate::platform::native_gui_confirm("CredShell Device Verification", &prompt_msg);
        if !confirmed {
            return Err(format!("Device trust verification declined for peer '{}'", peer_info.device_name));
        }
    }

    let nonce = random_12()?;
    let gcm = Aes256Gcm::new(&session_key);
    let json_data = vault_to_json(vault);
    let (ciphertext, tag) = gcm.encrypt(&nonce, b"CREDSHELL_SYNC_DATA", json_data.as_bytes());

    let mut payload = Vec::with_capacity(12 + 16 + ciphertext.len());
    payload.extend_from_slice(&nonce);
    payload.extend_from_slice(&tag);
    payload.extend_from_slice(&ciphertext);

    println!("Transmitting encrypted vault delta...");
    send_frame(&mut stream, MSG_SYNC_PAYLOAD, &payload)?;

    println!("Waiting for recipient approval...");
    let (msg_type, ack_payload) = read_frame(&mut stream)?;
    if msg_type == MSG_SYNC_ACK && !ack_payload.is_empty() && ack_payload[0] == 0x01 {
        println!("\n[████████████████████] 100%");
        println!("✓ Recipient verified and committed synchronization transaction.");
    } else {
        println!("\n✗ Recipient declined or failed to apply transaction.");
    }

    Ok(())
}
