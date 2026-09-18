use super::cbor::{encode_ed25519_cose_key, encode_p256_cose_key, CborValue};
use crate::core::crypto::ed25519::sign as ed25519_sign;
use crate::core::crypto::p256::sign_p256;
use crate::core::crypto::sha256::sha256;

pub const FLAG_USER_PRESENT: u8 = 0x01;
pub const FLAG_USER_VERIFIED: u8 = 0x04;
pub const FLAG_BACKUP_ELIGIBILITY: u8 = 0x08;
pub const FLAG_BACKUP_STATE: u8 = 0x10;
pub const FLAG_ATTESTED_CREDENTIAL_DATA: u8 = 0x40;

pub const CREDSHELL_AAGUID: [u8; 16] = [0u8; 16];

pub fn make_registration_auth_data(
    rp_id: &str,
    sign_count: u32,
    credential_id: &[u8],
    public_key: &[u8],
    alg: i32,
) -> Vec<u8> {
    let rp_id_hash = sha256(rp_id.as_bytes());
    let flags = FLAG_USER_PRESENT
        | FLAG_USER_VERIFIED
        | FLAG_BACKUP_ELIGIBILITY
        | FLAG_BACKUP_STATE
        | FLAG_ATTESTED_CREDENTIAL_DATA;

    let mut auth_data = Vec::new();
    auth_data.extend_from_slice(&rp_id_hash);
    auth_data.push(flags);
    auth_data.extend_from_slice(&sign_count.to_be_bytes());
    auth_data.extend_from_slice(&CREDSHELL_AAGUID);
    auth_data.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
    auth_data.extend_from_slice(credential_id);
    let cose_key = if alg == -8 {
        encode_ed25519_cose_key(public_key)
    } else {
        encode_p256_cose_key(public_key)
    };
    auth_data.extend_from_slice(&cose_key);

    auth_data
}

pub fn make_assertion_auth_data(rp_id: &str, sign_count: u32) -> Vec<u8> {
    let rp_id_hash = sha256(rp_id.as_bytes());
    let flags = FLAG_USER_PRESENT | FLAG_USER_VERIFIED | FLAG_BACKUP_ELIGIBILITY | FLAG_BACKUP_STATE;

    let mut auth_data = Vec::new();
    auth_data.extend_from_slice(&rp_id_hash);
    auth_data.push(flags);
    auth_data.extend_from_slice(&sign_count.to_be_bytes());

    auth_data
}

pub fn make_attestation_object(auth_data: &[u8]) -> Vec<u8> {
    let map = CborValue::Map(vec![
        (
            CborValue::TextString("fmt".to_string()),
            CborValue::TextString("none".to_string()),
        ),
        (
            CborValue::TextString("attStmt".to_string()),
            CborValue::Map(vec![]),
        ),
        (
            CborValue::TextString("authData".to_string()),
            CborValue::ByteString(auth_data.to_vec()),
        ),
    ]);
    map.encode()
}

pub fn p256_sig_to_der(raw_sig: &[u8; 64]) -> Vec<u8> {
    fn encode_der_int(bytes: &[u8]) -> Vec<u8> {
        let mut start = 0;
        while start < bytes.len() - 1 && bytes[start] == 0 {
            start += 1;
        }
        let slice = &bytes[start..];
        let mut out = Vec::new();
        out.push(0x02);
        if (slice[0] & 0x80) != 0 {
            out.push((slice.len() + 1) as u8);
            out.push(0x00);
        } else {
            out.push(slice.len() as u8);
        }
        out.extend_from_slice(slice);
        out
    }

    let r_enc = encode_der_int(&raw_sig[0..32]);
    let s_enc = encode_der_int(&raw_sig[32..64]);

    let total_len = r_enc.len() + s_enc.len();
    let mut der = Vec::with_capacity(2 + total_len);
    der.push(0x30);
    der.push(total_len as u8);
    der.extend_from_slice(&r_enc);
    der.extend_from_slice(&s_enc);
    der
}

pub fn p256_der_to_sig(der: &[u8]) -> Result<[u8; 64], String> {
    if der.len() < 8 || der[0] != 0x30 {
        return Err("Invalid DER: missing SEQUENCE tag".to_string());
    }

    let mut idx = 2;

    if idx >= der.len() || der[idx] != 0x02 {
        return Err("Invalid DER: missing INTEGER r tag".to_string());
    }
    let r_len = der[idx + 1] as usize;
    idx += 2;
    if idx + r_len > der.len() {
        return Err("Invalid DER: r length exceeds buffer".to_string());
    }
    let mut r_slice = &der[idx..idx + r_len];
    if r_slice.len() > 32 && r_slice[0] == 0x00 {
        r_slice = &r_slice[1..];
    }
    if r_slice.len() > 32 {
        return Err("Invalid DER: r exceeds 32 bytes".to_string());
    }
    idx += r_len;

    if idx >= der.len() || der[idx] != 0x02 {
        return Err("Invalid DER: missing INTEGER s tag".to_string());
    }
    let s_len = der[idx + 1] as usize;
    idx += 2;
    if idx + s_len > der.len() {
        return Err("Invalid DER: s length exceeds buffer".to_string());
    }
    let mut s_slice = &der[idx..idx + s_len];
    if s_slice.len() > 32 && s_slice[0] == 0x00 {
        s_slice = &s_slice[1..];
    }
    if s_slice.len() > 32 {
        return Err("Invalid DER: s exceeds 32 bytes".to_string());
    }

    let mut raw = [0u8; 64];
    let r_offset = 32 - r_slice.len();
    raw[r_offset..32].copy_from_slice(r_slice);

    let s_offset = 64 - s_slice.len();
    raw[s_offset..64].copy_from_slice(s_slice);

    Ok(raw)
}

pub fn p256_pubkey_to_spki(pub_key_64: &[u8]) -> Vec<u8> {
    let mut spki = Vec::with_capacity(91);
    spki.extend_from_slice(&[
        0x30, 0x59,
        0x30, 0x13,
        0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
        0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
        0x03, 0x42, 0x00,
        0x04,
    ]);
    if pub_key_64.len() >= 64 {
        spki.extend_from_slice(&pub_key_64[0..64]);
    } else {
        spki.extend_from_slice(pub_key_64);
        while spki.len() < 91 {
            spki.push(0);
        }
    }
    spki
}

pub fn ed25519_pubkey_to_spki(pub_key_32: &[u8]) -> Vec<u8> {
    let mut spki = Vec::with_capacity(44);
    spki.extend_from_slice(&[
        0x30, 0x2a,
        0x30, 0x05,
        0x06, 0x03, 0x2b, 0x65, 0x70,
        0x03, 0x21, 0x00,
    ]);
    if pub_key_32.len() >= 32 {
        spki.extend_from_slice(&pub_key_32[0..32]);
    } else {
        spki.extend_from_slice(pub_key_32);
        while spki.len() < 44 {
            spki.push(0);
        }
    }
    spki
}

pub fn sign_assertion(
    alg: i32,
    private_seed: &[u8; 32],
    public_key: &[u8],
    auth_data: &[u8],
    client_data_hash: &[u8; 32],
) -> Result<Vec<u8>, String> {
    let mut data_to_sign = Vec::with_capacity(auth_data.len() + 32);
    data_to_sign.extend_from_slice(auth_data);
    data_to_sign.extend_from_slice(client_data_hash);

    if alg == -8 {
        Ok(ed25519_sign(private_seed, &data_to_sign).to_vec())
    } else {
        let digest = sha256(&data_to_sign);
        let raw_sig = sign_p256(private_seed, public_key, &digest)?;
        Ok(p256_sig_to_der(&raw_sig))
    }
}
