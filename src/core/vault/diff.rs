use super::model::{PasskeyCredential, TotpEntry, Vault};

#[derive(Clone, Debug, PartialEq)]
pub enum DiffItem {
    AddTotp(TotpEntry),
    ModifyTotp { old: TotpEntry, new: TotpEntry },
    DeleteTotp(TotpEntry),
    AddPasskey(PasskeyCredential),
    ModifyPasskey { old: PasskeyCredential, new: PasskeyCredential },
    DeletePasskey(PasskeyCredential),
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct VaultDiff {
    pub items: Vec<DiffItem>,
}

impl VaultDiff {
    pub fn compute(local: &Vault, incoming: &Vault) -> Self {
        let mut items = Vec::new();

        for inc in &incoming.totp_entries {
            if let Some(loc) = local.totp_entries.iter().find(|e| e.name.eq_ignore_ascii_case(&inc.name)) {
                if loc.secret_base32 != inc.secret_base32
                    || loc.issuer != inc.issuer
                    || loc.account != inc.account
                    || loc.algorithm != inc.algorithm
                {
                    items.push(DiffItem::ModifyTotp {
                        old: loc.clone(),
                        new: inc.clone(),
                    });
                }
            } else {
                items.push(DiffItem::AddTotp(inc.clone()));
            }
        }

        for inc_p in &incoming.passkeys {
            if let Some(loc_p) = local.passkeys.iter().find(|p| p.id.eq_ignore_ascii_case(&inc_p.id)) {
                if loc_p.public_key != inc_p.public_key || loc_p.sign_count < inc_p.sign_count {
                    items.push(DiffItem::ModifyPasskey {
                        old: loc_p.clone(),
                        new: inc_p.clone(),
                    });
                }
            } else {
                items.push(DiffItem::AddPasskey(inc_p.clone()));
            }
        }

        Self { items }
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub fn format_preview(&self, source: &str, destination: &str) -> String {
        let mut out = String::new();
        out.push_str("Synchronization Preview\n\n");
        out.push_str(&format!("Source:\n  {}\n\n", source));
        out.push_str(&format!("Destination:\n  {}\n\n", destination));
        out.push_str("Changes:\n\n");

        if self.items.is_empty() {
            out.push_str("  (No changes detected. Vaults are already identical.)\n\n");
            return out;
        }

        for item in &self.items {
            match item {
                DiffItem::AddTotp(t) => {
                    out.push_str(&format!("  + TOTP\n    {} / {}\n\n", t.issuer, t.account));
                }
                DiffItem::ModifyTotp { new, .. } => {
                    out.push_str(&format!("  ~ TOTP\n    {} / {}\n\n", new.issuer, new.account));
                }
                DiffItem::DeleteTotp(t) => {
                    out.push_str(&format!("  - TOTP\n    {} / {}\n\n", t.issuer, t.account));
                }
                DiffItem::AddPasskey(p) => {
                    out.push_str(&format!("  + Passkey\n    {} / {}\n\n", p.rp_id, p.user_name));
                }
                DiffItem::ModifyPasskey { new, .. } => {
                    out.push_str(&format!("  ~ Passkey\n    {} / {}\n\n", new.rp_id, new.user_name));
                }
                DiffItem::DeletePasskey(p) => {
                    out.push_str(&format!("  - Passkey\n    {} / {}\n\n", p.rp_id, p.user_name));
                }
            }
        }

        out
    }

    pub fn apply(&self, vault: &mut Vault) {
        for item in &self.items {
            match item {
                DiffItem::AddTotp(t) => {
                    if let Some(pos) = vault.totp_entries.iter().position(|e| e.name.eq_ignore_ascii_case(&t.name)) {
                        vault.totp_entries[pos] = t.clone();
                    } else {
                        vault.totp_entries.push(t.clone());
                    }
                }
                DiffItem::ModifyTotp { new, .. } => {
                    if let Some(pos) = vault.totp_entries.iter().position(|e| e.name.eq_ignore_ascii_case(&new.name)) {
                        vault.totp_entries[pos] = new.clone();
                    } else {
                        vault.totp_entries.push(new.clone());
                    }
                }
                DiffItem::DeleteTotp(t) => {
                    vault.totp_entries.retain(|e| !e.name.eq_ignore_ascii_case(&t.name));
                }
                DiffItem::AddPasskey(p) => {
                    if let Some(pos) = vault.passkeys.iter().position(|pk| pk.id.eq_ignore_ascii_case(&p.id)) {
                        vault.passkeys[pos] = p.clone();
                    } else {
                        vault.passkeys.push(p.clone());
                    }
                }
                DiffItem::ModifyPasskey { new, .. } => {
                    if let Some(pos) = vault.passkeys.iter().position(|pk| pk.id.eq_ignore_ascii_case(&new.id)) {
                        vault.passkeys[pos] = new.clone();
                    } else {
                        vault.passkeys.push(new.clone());
                    }
                }
                DiffItem::DeletePasskey(p) => {
                    vault.passkeys.retain(|pk| !pk.id.eq_ignore_ascii_case(&p.id));
                }
            }
        }
    }
}
