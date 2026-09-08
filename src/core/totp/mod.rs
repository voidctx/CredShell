pub mod base32;
pub mod uri;

use super::crypto::hmac::{hmac_sha1, hmac_sha256, hmac_sha512};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HmacAlgorithm {
    Sha1,
    Sha256,
    Sha512,
}

impl HmacAlgorithm {
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s.to_lowercase().as_str() {
            "sha1" | "sha-1" => Ok(Self::Sha1),
            "sha256" | "sha-256" => Ok(Self::Sha256),
            "sha512" | "sha-512" => Ok(Self::Sha512),
            _ => Err(format!("Unsupported algorithm '{}'. Use sha1, sha256, or sha512.", s)),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Sha1 => "SHA-1",
            Self::Sha256 => "SHA-256",
            Self::Sha512 => "SHA-512",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TotpResult {
    pub current: String,
    pub current_formatted: String,
    pub next: String,
    pub next_formatted: String,
    pub expires_in: u64,
    pub period: u32,
}

pub fn hotp(secret: &[u8], counter: u64, digits: u32, algo: HmacAlgorithm) -> String {
    let counter_bytes = counter.to_be_bytes();

    let (hash_bytes, hash_len): (Vec<u8>, usize) = match algo {
        HmacAlgorithm::Sha1 => (hmac_sha1(secret, &counter_bytes).to_vec(), 20),
        HmacAlgorithm::Sha256 => (hmac_sha256(secret, &counter_bytes).to_vec(), 32),
        HmacAlgorithm::Sha512 => (hmac_sha512(secret, &counter_bytes).to_vec(), 64),
    };

    let offset = (hash_bytes[hash_len - 1] & 0x0f) as usize;
    let binary = (((hash_bytes[offset] & 0x7f) as u32) << 24)
        | ((hash_bytes[offset + 1] as u32) << 16)
        | ((hash_bytes[offset + 2] as u32) << 8)
        | (hash_bytes[offset + 3] as u32);

    let safe_digits = if digits == 0 || digits > 9 { 6 } else { digits };
    let divisor = 10u32.pow(safe_digits);
    let code_num = binary % divisor;

    format!("{:0width$}", code_num, width = safe_digits as usize)
}

pub fn format_totp_code(code: &str) -> String {
    if code.len() == 6 {
        format!("{} {}", &code[..3], &code[3..])
    } else if code.len() == 8 {
        format!("{} {}", &code[..4], &code[4..])
    } else {
        code.to_string()
    }
}

pub fn generate_totp(
    secret: &[u8],
    timestamp: u64,
    period: u32,
    digits: u32,
    algo: HmacAlgorithm,
) -> TotpResult {
    let safe_period = if period == 0 { 30 } else { period };
    let safe_digits = if digits == 0 || digits > 9 { 6 } else { digits };

    let counter = timestamp / (safe_period as u64);
    let next_counter = counter + 1;
    let expires_in = (safe_period as u64) - (timestamp % (safe_period as u64));

    let current = hotp(secret, counter, safe_digits, algo);
    let next = hotp(secret, next_counter, safe_digits, algo);

    TotpResult {
        current_formatted: format_totp_code(&current),
        current,
        next_formatted: format_totp_code(&next),
        next,
        expires_in,
        period: safe_period,
    }
}

pub fn generate_totp_now(
    secret: &[u8],
    period: u32,
    digits: u32,
    algo: HmacAlgorithm,
) -> Result<TotpResult, String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("System time before UNIX epoch: {}", e))?
        .as_secs();

    Ok(generate_totp(secret, now, period, digits, algo))
}
