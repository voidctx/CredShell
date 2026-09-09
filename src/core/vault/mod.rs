pub mod diff;
pub mod json;
pub mod model;
pub mod storage;

pub use diff::{DiffItem, VaultDiff};
pub use json::{vault_from_json, vault_to_json};
pub use model::{DeviceIdentity, PasskeyCredential, TotpEntry, Vault};
pub use storage::{
    decrypt_vault, default_vault_path, encrypt_vault, load_vault, save_vault_atomic,
};
