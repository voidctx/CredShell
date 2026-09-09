use crate::core::crypto::ed25519::public_key_from_seed;
use crate::core::crypto::rng::random_32;
use crate::core::crypto::zeroize::zeroize;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TotpEntry {
    pub id: String,
    pub name: String,
    pub issuer: String,
    pub account: String,
    pub secret_base32: String,
    pub algorithm: String,
    pub digits: u32,
    pub period: u32,
    pub created_at: u64,
    pub updated_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PasskeyCredential {
    pub id: String,
    pub rp_id: String,
    pub rp_name: String,
    pub user_name: String,
    pub user_id: Vec<u8>,
    pub credential_id: Vec<u8>,
    pub private_seed: [u8; 32],
    pub public_key: Vec<u8>,
    pub alg: i32,
    pub sign_count: u32,
    pub created_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceIdentity {
    pub device_id: String,
    pub device_name: String,
    pub public_key: [u8; 32],
    pub trusted: bool,
    pub last_sync: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Vault {
    pub version: u32,
    pub device_name: String,
    pub device_seed: [u8; 32],
    pub device_public_key: [u8; 32],
    pub totp_entries: Vec<TotpEntry>,
    pub passkeys: Vec<PasskeyCredential>,
    pub trusted_devices: Vec<DeviceIdentity>,
    pub created_at: u64,
    pub updated_at: u64,
}

impl Drop for TotpEntry {
    fn drop(&mut self) {
        unsafe {
            zeroize(self.secret_base32.as_bytes_mut());
        }
    }
}

impl Drop for PasskeyCredential {
    fn drop(&mut self) {
        zeroize(&mut self.private_seed);
    }
}

impl Drop for Vault {
    fn drop(&mut self) {
        zeroize(&mut self.device_seed);
    }
}

impl Vault {
    pub fn new(device_name: String) -> Result<Self, String> {
        let device_seed = random_32()?;
        let device_public_key = public_key_from_seed(&device_seed);
        let now = now_secs();

        Ok(Self {
            version: 1,
            device_name,
            device_seed,
            device_public_key,
            totp_entries: Vec::new(),
            passkeys: Vec::new(),
            trusted_devices: Vec::new(),
            created_at: now,
            updated_at: now,
        })
    }

    pub fn add_totp_with_id(
        &mut self,
        id: &str,
        name: &str,
        secret_base32: &str,
        issuer: Option<&str>,
        account: Option<&str>,
        algo: Option<&str>,
    ) -> Result<TotpEntry, String> {
        if self.totp_entries.iter().any(|e| e.id.eq_ignore_ascii_case(id)) {
            return Err(format!("A TOTP entry with ID '{}' already exists in the vault", id));
        }

        let now = now_secs();
        let entry = TotpEntry {
            id: id.to_string(),
            name: name.to_string(),
            issuer: issuer.unwrap_or(name).to_string(),
            account: account.unwrap_or("user").to_string(),
            secret_base32: secret_base32.to_string(),
            algorithm: algo.unwrap_or("SHA-1").to_string(),
            digits: 6,
            period: 30,
            created_at: now,
            updated_at: now,
        };

        self.totp_entries.push(entry.clone());
        self.updated_at = now;
        Ok(entry)
    }

    pub fn add_totp(
        &mut self,
        name: &str,
        secret_base32: &str,
        issuer: Option<&str>,
        account: Option<&str>,
        algo: Option<&str>,
    ) -> Result<TotpEntry, String> {
        let id = self.generate_unique_totp_id(name);
        self.add_totp_with_id(&id, name, secret_base32, issuer, account, algo)
    }

    pub fn generate_unique_totp_id(&self, base_name: &str) -> String {
        if !self.totp_entries.iter().any(|e| e.id.eq_ignore_ascii_case(base_name)) {
            return base_name.to_string();
        }
        let mut idx = 1;
        loop {
            let candidate = format!("{}-{}", base_name, idx);
            if !self.totp_entries.iter().any(|e| e.id.eq_ignore_ascii_case(&candidate)) {
                return candidate;
            }
            idx += 1;
        }
    }

    pub fn get_totp(&self, id_or_name: &str) -> Option<&TotpEntry> {
        self.totp_entries.iter().find(|e| {
            e.id.eq_ignore_ascii_case(id_or_name) || e.name.eq_ignore_ascii_case(id_or_name)
        })
    }

    pub fn delete_totp(&mut self, id_or_name: &str) -> bool {
        let before = self.totp_entries.len();
        self.totp_entries.retain(|e| {
            !e.id.eq_ignore_ascii_case(id_or_name) && !e.name.eq_ignore_ascii_case(id_or_name)
        });
        let deleted = self.totp_entries.len() < before;
        if deleted {
            self.updated_at = now_secs();
        }
        deleted
    }

    pub fn generate_unique_passkey_id(&self, rp_id: &str, user_name: &str) -> String {
        let user = if user_name.trim().is_empty() { "user" } else { user_name.trim() };
        format!("{}#{}", user, rp_id.trim())
    }

    pub fn is_bak_passkey(id: &str) -> bool {
        id.contains("-bak-")
    }

    pub fn parse_bak_timestamp(id: &str) -> Option<u64> {
        if let Some(idx) = id.rfind("-bak-") {
            let ts_str = &id[idx + 5..];
            ts_str.parse::<u64>().ok()
        } else {
            None
        }
    }

    pub fn get_bak_base_id(id: &str) -> &str {
        if let Some(idx) = id.rfind("-bak-") {
            &id[..idx]
        } else if let Some(stripped) = id.strip_suffix("-bak") {
            stripped
        } else {
            id
        }
    }

    pub fn prune_expired_backups(&mut self, max_age_secs: u64) -> bool {
        let now = now_secs();
        let before = self.passkeys.len();
        self.passkeys.retain(|p| {
            if let Some(ts) = Self::parse_bak_timestamp(&p.id) {
                if now >= ts && (now - ts) > max_age_secs {
                    return false;
                }
            }
            true
        });
        let pruned = self.passkeys.len() < before;
        if pruned {
            self.updated_at = now;
        }
        pruned
    }

    pub fn backup_and_overwrite_passkey(
        &mut self,
        id: &str,
        rp_id: &str,
        rp_name: &str,
        user_name: &str,
        user_id: &[u8],
        alg: i32,
    ) -> Result<PasskeyCredential, String> {
        let now = now_secs();
        if let Some(pos) = self.passkeys.iter().position(|p| p.id.eq_ignore_ascii_case(id)) {
            let bak_id = format!("{}-bak-{}", id, now);
            self.passkeys[pos].id = bak_id;
        }

        let (public_key, private_seed) = if alg == -8 {
            let seed = random_32()?;
            let pk = public_key_from_seed(&seed);
            (pk.to_vec(), seed)
        } else {
            crate::core::crypto::p256::generate_p256_keypair()?
        };

        let credential_id = random_32()?.to_vec();
        let cred = PasskeyCredential {
            id: id.to_string(),
            rp_id: rp_id.to_string(),
            rp_name: rp_name.to_string(),
            user_name: user_name.to_string(),
            user_id: user_id.to_vec(),
            credential_id,
            private_seed,
            public_key,
            alg,
            sign_count: 0,
            created_at: now,
        };

        self.passkeys.push(cred.clone());
        self.updated_at = now;
        Ok(cred)
    }

    pub fn overwrite_passkey_with_id(
        &mut self,
        id: &str,
        rp_id: &str,
        rp_name: &str,
        user_name: &str,
        user_id: &[u8],
        alg: i32,
    ) -> Result<PasskeyCredential, String> {
        let now = now_secs();
        self.passkeys.retain(|p| !p.id.eq_ignore_ascii_case(id));

        let (public_key, private_seed) = if alg == -8 {
            let seed = random_32()?;
            let pk = public_key_from_seed(&seed);
            (pk.to_vec(), seed)
        } else {
            crate::core::crypto::p256::generate_p256_keypair()?
        };

        let credential_id = random_32()?.to_vec();
        let cred = PasskeyCredential {
            id: id.to_string(),
            rp_id: rp_id.to_string(),
            rp_name: rp_name.to_string(),
            user_name: user_name.to_string(),
            user_id: user_id.to_vec(),
            credential_id,
            private_seed,
            public_key,
            alg,
            sign_count: 0,
            created_at: now,
        };

        self.passkeys.push(cred.clone());
        self.updated_at = now;
        Ok(cred)
    }

    pub fn restore_backup_passkey(&mut self, input_id: &str) -> Result<(String, String), String> {
        let clean = input_id.trim();
        let base_id = if clean.ends_with("-bak") {
            &clean[..clean.len() - 4]
        } else if Self::is_bak_passkey(clean) {
            Self::get_bak_base_id(clean)
        } else {
            clean
        };

        let bak_prefix = format!("{}-bak-", base_id);

        let mut candidates: Vec<(usize, u64)> = Vec::new();
        for (i, p) in self.passkeys.iter().enumerate() {
            if p.id.eq_ignore_ascii_case(clean) {
                candidates.push((i, Self::parse_bak_timestamp(&p.id).unwrap_or(0)));
            } else if p.id.starts_with(&bak_prefix) {
                candidates.push((i, Self::parse_bak_timestamp(&p.id).unwrap_or(0)));
            }
        }

        if candidates.is_empty() {
            return Err(format!("No backup passkey found matching '{}' (expected format: '<id>-bak')", input_id));
        }

        candidates.sort_by_key(|c| c.1);
        let (bak_idx, _) = candidates.last().unwrap();
        let bak_idx = *bak_idx;

        let now = now_secs();
        let target_id = base_id.to_string();

        let mut moved_active_bak_id = String::new();
        if let Some(active_idx) = self.passkeys.iter().position(|p| p.id.eq_ignore_ascii_case(&target_id)) {
            moved_active_bak_id = format!("{}-bak-{}", target_id, now);
            self.passkeys[active_idx].id = moved_active_bak_id.clone();
        }

        self.passkeys[bak_idx].id = target_id.clone();
        self.updated_at = now;

        Ok((target_id, moved_active_bak_id))
    }

    pub fn add_passkey_with_id(
        &mut self,
        id: &str,
        rp_id: &str,
        rp_name: &str,
        user_name: &str,
        user_id: &[u8],
        alg: i32,
    ) -> Result<PasskeyCredential, String> {
        if self.passkeys.iter().any(|p| p.id.eq_ignore_ascii_case(id)) {
            return Err(format!("A passkey with ID '{}' already exists in the vault", id));
        }

        let (public_key, private_seed) = if alg == -8 {
            let seed = random_32()?;
            let pk = public_key_from_seed(&seed);
            (pk.to_vec(), seed)
        } else {
            crate::core::crypto::p256::generate_p256_keypair()?
        };

        let credential_id = random_32()?.to_vec();
        let now = now_secs();

        let cred = PasskeyCredential {
            id: id.to_string(),
            rp_id: rp_id.to_string(),
            rp_name: rp_name.to_string(),
            user_name: user_name.to_string(),
            user_id: user_id.to_vec(),
            credential_id,
            private_seed,
            public_key,
            alg,
            sign_count: 0,
            created_at: now,
        };

        self.passkeys.push(cred.clone());
        self.updated_at = now;
        Ok(cred)
    }

    pub fn add_passkey(
        &mut self,
        rp_id: &str,
        rp_name: &str,
        user_name: &str,
    ) -> Result<PasskeyCredential, String> {
        let id = self.generate_unique_passkey_id(rp_id, user_name);
        self.add_passkey_with_id(&id, rp_id, rp_name, user_name, &[], -7)
    }

    pub fn add_passkey_with_alg(
        &mut self,
        rp_id: &str,
        rp_name: &str,
        user_name: &str,
        alg: i32,
    ) -> Result<PasskeyCredential, String> {
        let id = self.generate_unique_passkey_id(rp_id, user_name);
        self.add_passkey_with_id(&id, rp_id, rp_name, user_name, &[], alg)
    }

    pub fn find_passkey(&self, id_or_rp: &str) -> Option<&PasskeyCredential> {
        self.passkeys.iter().find(|p| {
            if Self::is_bak_passkey(&p.id) {
                return false;
            }
            p.id.eq_ignore_ascii_case(id_or_rp) || rp_matches_requested(id_or_rp, &p.rp_id)
        })
    }

    pub fn find_passkeys_for_rp(&self, rp_id: &str) -> Vec<&PasskeyCredential> {
        self.passkeys.iter().filter(|p| {
            if Self::is_bak_passkey(&p.id) {
                return false;
            }
            p.id.eq_ignore_ascii_case(rp_id) || rp_matches_requested(rp_id, &p.rp_id)
        }).collect()
    }

    pub fn find_passkey_by_id(&self, credential_id: &[u8]) -> Option<&PasskeyCredential> {
        self.passkeys.iter().find(|p| p.credential_id == credential_id)
    }

    pub fn find_passkey_by_custom_id(&self, id: &str) -> Option<&PasskeyCredential> {
        self.passkeys.iter().find(|p| p.id.eq_ignore_ascii_case(id))
    }

    pub fn delete_passkey(&mut self, id_or_rp: &str) -> bool {
        let before = self.passkeys.len();
        self.passkeys.retain(|p| {
            !p.id.eq_ignore_ascii_case(id_or_rp) && !p.rp_id.eq_ignore_ascii_case(id_or_rp)
        });
        let deleted = self.passkeys.len() < before;
        if deleted {
            self.updated_at = now_secs();
        }
        deleted
    }

    pub fn increment_passkey_sign_count(&mut self, id_or_rp: &str) -> Option<u32> {
        if let Some(p) = self.passkeys.iter_mut().find(|p| {
            p.id.eq_ignore_ascii_case(id_or_rp)
                || p.rp_id.eq_ignore_ascii_case(id_or_rp)
                || id_or_rp.ends_with(&format!(".{}", p.rp_id))
                || p.rp_id.ends_with(&format!(".{}", id_or_rp))
        }) {
            p.sign_count += 1;
            self.updated_at = now_secs();
            Some(p.sign_count)
        } else {
            None
        }
    }

    pub fn increment_passkey_sign_count_by_id(&mut self, credential_id: &[u8]) -> Option<u32> {
        if let Some(p) = self.passkeys.iter_mut().find(|p| p.credential_id == credential_id) {
            p.sign_count += 1;
            self.updated_at = now_secs();
            Some(p.sign_count)
        } else {
            None
        }
    }
}

pub fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

pub fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("Hex string must have even length".to_string());
    }
    let mut bytes = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        let byte = u8::from_str_radix(&s[i..i + 2], 16)
            .map_err(|e| format!("Invalid hex digit: {}", e))?;
        bytes.push(byte);
    }
    Ok(bytes)
}

pub const MULTI_TENANT_SUFFIXES: &[&str] = &[
    "github.io", "gitlab.io", "pages.dev", "workers.dev", "vercel.app", "now.sh",
    "netlify.app", "herokuapp.com", "herokussl.com", "firebaseapp.com", "web.app",
    "azurewebsites.net", "cloudapp.net", "azurestaticapps.net", "s3.amazonaws.com",
    "s3-website.amazonaws.com", "cloudfront.net", "elasticbeanstalk.com", "appspot.com",
    "000webhostapp.com", "fly.dev", "render.com", "onrender.com", "glitch.me", "repl.co",
    "replit.dev", "surge.sh", "myshopify.com", "wordpress.com", "blogspot.com", "wixsite.com",
    "weebly.com", "squarespace.com", "carrd.co", "ghost.io", "pantheonsite.io", "kinsta.cloud",
    "ngrok.io", "ngrok-free.app", "loca.lt", "nip.io", "sslip.io",
];

pub fn is_public_suffix(domain: &str) -> bool {
    let d = domain.trim().trim_matches('.').to_lowercase();
    if d.is_empty() {
        return false;
    }

    let parts: Vec<&str> = d.split('.').collect();
    if parts.len() <= 1 {
        return true;
    }

    for &s in MULTI_TENANT_SUFFIXES {
        if d == s {
            return true;
        }
    }

    if parts.len() == 2 {
        let second_last = parts[0];
        let last = parts[1];
        if last.len() == 2 && matches!(second_last, "co" | "com" | "org" | "net" | "edu" | "gov" | "ac" | "or" | "ne" | "gen" | "ind" | "firm" | "nic" | "muni" | "k12" | "nom" | "mil" | "sch" | "ltd" | "plc") {
            return true;
        }
    }

    false
}

pub fn extract_base_domain(domain: &str) -> &str {
    let d = domain.trim().trim_matches('.');
    if d.is_empty() {
        return domain;
    }

    let parts: Vec<&str> = d.split('.').collect();
    if parts.len() <= 1 {
        return d;
    }

    let d_lower = d.to_lowercase();
    for &suffix in MULTI_TENANT_SUFFIXES {
        if d_lower == suffix {
            return d;
        }
        if d_lower.ends_with(&format!(".{}", suffix)) {
            let suffix_labels = suffix.split('.').count();
            let needed_labels = suffix_labels + 1;
            if parts.len() <= needed_labels {
                return d;
            }
            let skip_count = parts.len() - needed_labels;
            let offset = parts[..skip_count].iter().map(|p| p.len() + 1).sum::<usize>();
            return &d[offset..];
        }
    }

    if parts.len() >= 3 {
        let second_last = parts[parts.len() - 2].to_lowercase();
        let last = parts[parts.len() - 1].to_lowercase();
        if last.len() == 2 && matches!(second_last.as_str(), "co" | "com" | "org" | "net" | "edu" | "gov" | "ac" | "or" | "ne" | "gen" | "ind" | "firm" | "nic" | "muni" | "k12" | "nom" | "mil" | "sch" | "ltd" | "plc") {
            let needed_labels = 3;
            if parts.len() <= needed_labels {
                return d;
            }
            let skip_count = parts.len() - needed_labels;
            let offset = parts[..skip_count].iter().map(|p| p.len() + 1).sum::<usize>();
            return &d[offset..];
        }
    }

    let needed_labels = 2;
    if parts.len() <= needed_labels {
        return d;
    }
    let skip_count = parts.len() - needed_labels;
    let offset = parts[..skip_count].iter().map(|p| p.len() + 1).sum::<usize>();
    &d[offset..]
}

pub fn rp_matches_requested(requested_rp: &str, cred_rp: &str) -> bool {
    let req = requested_rp.trim().trim_matches('.').to_lowercase();
    let cred = cred_rp.trim().trim_matches('.').to_lowercase();

    if req.is_empty() || cred.is_empty() {
        return false;
    }

    if is_public_suffix(&req) || is_public_suffix(&cred) {
        return false;
    }

    if req == cred {
        return true;
    }

    if cred.ends_with(&format!(".{}", req)) {
        return true;
    }

    if req.ends_with(&format!(".{}", cred)) {
        return true;
    }

    let base_req = extract_base_domain(&req);
    let base_cred = extract_base_domain(&cred);
    if !base_req.is_empty() && !is_public_suffix(base_req) && base_req == base_cred {
        return true;
    }

    false
}


