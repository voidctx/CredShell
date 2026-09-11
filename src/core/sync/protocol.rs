use crate::core::crypto::ed25519::{sign, verify, x25519, X25519_BASE_POINT};
use crate::core::crypto::pbkdf2::derive_key_32;
use crate::core::crypto::rng::random_32;
use crate::core::crypto::zeroize::zeroize;
use crate::core::vault::model::Vault;
use std::io::{Read, Write};
use std::net::TcpStream;

pub const MSG_HANDSHAKE_INIT: u8 = 0x01;
pub const MSG_HANDSHAKE_RESP: u8 = 0x02;
pub const MSG_HANDSHAKE_ACK: u8 = 0x03;
pub const MSG_SYNC_PAYLOAD: u8 = 0x04;
pub const MSG_SYNC_ACK: u8 = 0x05;

pub struct PeerInfo {
    pub device_name: String,
    pub public_key: [u8; 32],
}

pub fn send_frame(stream: &mut TcpStream, msg_type: u8, payload: &[u8]) -> Result<(), String> {
    let mut header = [0u8; 5];
    header[0] = msg_type;
    header[1..5].copy_from_slice(&(payload.len() as u32).to_be_bytes());

    stream.write_all(&header)
        .map_err(|e| format!("Failed to send frame header: {}", e))?;
    stream.write_all(payload)
        .map_err(|e| format!("Failed to send frame payload: {}", e))?;
    stream.flush()
        .map_err(|e| format!("Failed to flush frame: {}", e))?;
    Ok(())
}

pub fn read_frame(stream: &mut TcpStream) -> Result<(u8, Vec<u8>), String> {
    let mut header = [0u8; 5];
    stream.read_exact(&mut header)
        .map_err(|e| format!("Failed to read frame header: {}", e))?;

    let msg_type = header[0];
    let len = u32::from_be_bytes(header[1..5].try_into().unwrap()) as usize;

    if len > 32 * 1024 * 1024 {
        return Err(format!("Frame payload too large: {} bytes", len));
    }

    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload)
        .map_err(|e| format!("Failed to read frame payload: {}", e))?;

    Ok((msg_type, payload))
}

pub fn tx_handshake(
    stream: &mut TcpStream,
    local_vault: &Vault,
) -> Result<(PeerInfo, [u8; 32]), String> {
    let mut local_eph_priv = random_32()?;
    let local_eph_pub = x25519(&local_eph_priv, &X25519_BASE_POINT);
    let local_challenge = random_32()?;

    let name_bytes = local_vault.device_name.as_bytes();
    let mut init_payload = Vec::with_capacity(1 + name_bytes.len() + 32 + 32 + 32);
    init_payload.push(name_bytes.len() as u8);
    init_payload.extend_from_slice(name_bytes);
    init_payload.extend_from_slice(&local_vault.device_public_key);
    init_payload.extend_from_slice(&local_challenge);
    init_payload.extend_from_slice(&local_eph_pub);

    send_frame(stream, MSG_HANDSHAKE_INIT, &init_payload)?;

    let (msg_type, resp_payload) = read_frame(stream)?;
    if msg_type != MSG_HANDSHAKE_RESP {
        return Err(format!("Expected MSG_HANDSHAKE_RESP, got {:#04x}", msg_type));
    }

    if resp_payload.is_empty() {
        return Err("Empty HandshakeResp payload".to_string());
    }

    let rx_name_len = resp_payload[0] as usize;
    if resp_payload.len() < 1 + rx_name_len + 32 + 64 + 32 + 32 {
        return Err("Malformed HandshakeResp payload: buffer too short for peer identity".to_string());
    }

    let rx_name = String::from_utf8_lossy(&resp_payload[1..1 + rx_name_len]).to_string();
    let offset = 1 + rx_name_len;

    let rx_pubkey: [u8; 32] = resp_payload[offset..offset + 32].try_into().unwrap();
    let rx_sig: [u8; 64] = resp_payload[offset + 32..offset + 96].try_into().unwrap();
    let peer_challenge: [u8; 32] = resp_payload[offset + 96..offset + 128].try_into().unwrap();
    let peer_eph_pub: [u8; 32] = resp_payload[offset + 128..offset + 160].try_into().unwrap();

    let mut signed_msg = Vec::with_capacity(128);
    signed_msg.extend_from_slice(&local_challenge);
    signed_msg.extend_from_slice(&rx_pubkey);
    signed_msg.extend_from_slice(&local_eph_pub);
    signed_msg.extend_from_slice(&peer_eph_pub);

    if !verify(&rx_pubkey, &signed_msg, &rx_sig) {
        return Err("Peer cryptographic authentication failed: invalid signature".to_string());
    }

    let mut ack_msg = Vec::with_capacity(128);
    ack_msg.extend_from_slice(&peer_challenge);
    ack_msg.extend_from_slice(&local_vault.device_public_key);
    ack_msg.extend_from_slice(&peer_eph_pub);
    ack_msg.extend_from_slice(&local_eph_pub);
    let local_sig = sign(&local_vault.device_seed, &ack_msg);

    send_frame(stream, MSG_HANDSHAKE_ACK, &local_sig)?;

    let mut shared_secret = x25519(&local_eph_priv, &peer_eph_pub);
    zeroize(&mut local_eph_priv);

    let mut session_salt = [0u8; 64];
    session_salt[..32].copy_from_slice(&local_challenge);
    session_salt[32..].copy_from_slice(&peer_challenge);
    let session_key = derive_key_32(&shared_secret, &session_salt, 1000);
    zeroize(&mut shared_secret);

    Ok((
        PeerInfo {
            device_name: rx_name,
            public_key: rx_pubkey,
        },
        session_key,
    ))
}

pub fn rx_handshake(
    stream: &mut TcpStream,
    local_vault: &Vault,
) -> Result<(PeerInfo, [u8; 32]), String> {
    let (msg_type, init_payload) = read_frame(stream)?;
    if msg_type != MSG_HANDSHAKE_INIT {
        return Err(format!("Expected MSG_HANDSHAKE_INIT, got {:#04x}", msg_type));
    }

    if init_payload.is_empty() {
        return Err("Empty HandshakeInit payload".to_string());
    }

    let tx_name_len = init_payload[0] as usize;
    if init_payload.len() < 1 + tx_name_len + 32 + 32 + 32 {
        return Err("Malformed HandshakeInit payload: buffer too short for peer identity".to_string());
    }

    let tx_name = String::from_utf8_lossy(&init_payload[1..1 + tx_name_len]).to_string();
    let offset = 1 + tx_name_len;

    let tx_pubkey: [u8; 32] = init_payload[offset..offset + 32].try_into().unwrap();
    let tx_challenge: [u8; 32] = init_payload[offset + 32..offset + 64].try_into().unwrap();
    let tx_eph_pub: [u8; 32] = init_payload[offset + 64..offset + 96].try_into().unwrap();

    let mut my_eph_priv = random_32()?;
    let my_eph_pub = x25519(&my_eph_priv, &X25519_BASE_POINT);

    let my_challenge = random_32()?;
    let mut signed_msg = Vec::with_capacity(128);
    signed_msg.extend_from_slice(&tx_challenge);
    signed_msg.extend_from_slice(&local_vault.device_public_key);
    signed_msg.extend_from_slice(&tx_eph_pub);
    signed_msg.extend_from_slice(&my_eph_pub);
    let rx_sig = sign(&local_vault.device_seed, &signed_msg);

    let my_name_bytes = local_vault.device_name.as_bytes();
    let mut resp_payload = Vec::with_capacity(1 + my_name_bytes.len() + 32 + 64 + 32 + 32);
    resp_payload.push(my_name_bytes.len() as u8);
    resp_payload.extend_from_slice(my_name_bytes);
    resp_payload.extend_from_slice(&local_vault.device_public_key);
    resp_payload.extend_from_slice(&rx_sig);
    resp_payload.extend_from_slice(&my_challenge);
    resp_payload.extend_from_slice(&my_eph_pub);

    send_frame(stream, MSG_HANDSHAKE_RESP, &resp_payload)?;

    let (msg_type, ack_payload) = read_frame(stream)?;
    if msg_type != MSG_HANDSHAKE_ACK || ack_payload.len() != 64 {
        return Err("Malformed HandshakeAck payload".to_string());
    }

    let tx_sig: [u8; 64] = ack_payload[..64].try_into().unwrap();
    let mut expected_ack = Vec::with_capacity(128);
    expected_ack.extend_from_slice(&my_challenge);
    expected_ack.extend_from_slice(&tx_pubkey);
    expected_ack.extend_from_slice(&my_eph_pub);
    expected_ack.extend_from_slice(&tx_eph_pub);

    if !verify(&tx_pubkey, &expected_ack, &tx_sig) {
        return Err("Transmitter signature verification failed".to_string());
    }

    let mut shared_secret = x25519(&my_eph_priv, &tx_eph_pub);
    zeroize(&mut my_eph_priv);

    let mut session_salt = [0u8; 64];
    session_salt[..32].copy_from_slice(&tx_challenge);
    session_salt[32..].copy_from_slice(&my_challenge);
    let session_key = derive_key_32(&shared_secret, &session_salt, 1000);
    zeroize(&mut shared_secret);

    Ok((
        PeerInfo {
            device_name: tx_name,
            public_key: tx_pubkey,
        },
        session_key,
    ))
}
