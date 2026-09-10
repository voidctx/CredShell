pub mod base64url;
pub mod cbor;
pub mod server;
pub mod webauthn;

pub use base64url::{decode_base64url, encode_base64url};
pub use cbor::{encode_ed25519_cose_key, CborValue};
pub use server::{PasskeyListener, DEFAULT_PASSKEY_PORT};
pub use webauthn::{
    make_assertion_auth_data, make_attestation_object, make_registration_auth_data, sign_assertion,
};
