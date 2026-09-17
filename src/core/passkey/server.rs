use super::base64url::{decode_base64url, encode_base64url};
use super::webauthn::{
    ed25519_pubkey_to_spki, make_assertion_auth_data, make_attestation_object,
    make_registration_auth_data, p256_pubkey_to_spki, sign_assertion,
};
use crate::cli::output::{print_passkey_reg_box, print_passkey_request_box};
use crate::core::crypto::sha256::sha256;
use crate::core::vault::json::{escape_json, JsonParser, JsonVal};
use crate::core::vault::model::Vault;
use crate::core::vault::storage::save_vault_atomic;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;

pub const DEFAULT_PASSKEY_PORT: u16 = 5209;


fn is_allowed_origin(origin: &str) -> bool {
    let clean = origin.trim_end_matches('/');
    if clean.starts_with("chrome-extension://") || clean.starts_with("moz-extension://") {
        return true;
    }
    clean == "http://127.0.0.1"
        || clean.starts_with("http://127.0.0.1:")
        || clean == "http://localhost"
        || clean.starts_with("http://localhost:")
        || clean == "https://localhost"
        || clean.starts_with("https://localhost:")
}

use crate::platform::native_gui_confirm;
use std::sync::{Arc, RwLock};
use std::thread;

#[derive(Clone)]
pub struct PasskeyListener {
    port: u16,
    vault_path: std::path::PathBuf,
    passphrase: String,
    auto_approve: bool,
}

impl PasskeyListener {
    pub fn new(
        port: u16,
        vault_path: &Path,
        passphrase: &str,
        auto_approve: bool,
    ) -> Self {
        Self {
            port,
            vault_path: vault_path.to_path_buf(),
            passphrase: passphrase.to_string(),
            auto_approve,
        }
    }

    pub fn run(&self, vault: &mut Vault) -> Result<(), String> {
        let listener = TcpListener::bind(format!("127.0.0.1:{}", self.port))
            .map_err(|e| format!("Failed to bind passkey listener on 127.0.0.1:{}: {}", self.port, e))?;

        println!("\x1b[1;36m╭──────────────────────────────────────╮\x1b[0m");
        println!("\x1b[1;36m│              \x1b[1mCREDSHELL\x1b[0m               \x1b[1;36m│\x1b[0m");
        println!("\x1b[1;36m│                                      │\x1b[0m");
        println!("\x1b[1;36m│ \x1b[32m●\x1b[0m \x1b[1mPasskey authenticator active\x1b[0m       \x1b[1;36m│\x1b[0m");
        println!("\x1b[1;36m│                                      │\x1b[0m");
        println!("\x1b[1;36m│\x1b[0m Listening for WebAuthn requests...   \x1b[1;36m│\x1b[0m");
        println!("\x1b[1;36m│\x1b[0m   Loopback: \x1b[1;33mhttp://127.0.0.1:{}\x1b[0m  \x1b[1;36m│\x1b[0m", self.port);
        println!("\x1b[1;36m│                                      │\x1b[0m");
        println!("\x1b[1;36m│\x1b[0m Waiting for browser / app requests.  \x1b[1;36m│\x1b[0m");
        println!("\x1b[1;36m│                                      │\x1b[0m");
        println!("\x1b[1;36m│\x1b[0m Ctrl+C to exit                       \x1b[1;36m│\x1b[0m");
        println!("\x1b[1;36m╰──────────────────────────────────────╯\x1b[0m\n");

        let vault_shared = Arc::new(RwLock::new(vault.clone()));
        let server_arc = Arc::new(self.clone());

        for stream_res in listener.incoming() {
            match stream_res {
                Ok(mut stream) => {
                    let v_clone = Arc::clone(&vault_shared);
                    let s_clone = Arc::clone(&server_arc);
                    thread::spawn(move || {
                        let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(30)));
                        let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(30)));
                        if let Err(err) = s_clone.handle_http_connection(&mut stream, &v_clone) {
                            eprintln!("\x1b[33m[Listener error]\x1b[0m {}", err);
                        }
                    });
                }
                Err(e) => {
                    eprintln!("Listener connection error: {}", e);
                }
            }
        }

        *vault = vault_shared.read().unwrap().clone();
        Ok(())
    }

    fn handle_http_connection(
        &self,
        stream: &mut TcpStream,
        vault_arc: &Arc<RwLock<Vault>>,
    ) -> Result<(), String> {
        let mut buffer = vec![0u8; 16384];
        let bytes_read = stream.read(&mut buffer).map_err(|e| e.to_string())?;
        if bytes_read == 0 {
            return Ok(());
        }

        let data = &buffer[..bytes_read];
        let (header_bytes, body_initial_offset) = if let Some(pos) = data.windows(4).position(|w| w == b"\r\n\r\n") {
            (&data[..pos], pos + 4)
        } else if let Some(pos) = data.windows(2).position(|w| w == b"\n\n") {
            (&data[..pos], pos + 2)
        } else {
            (data, data.len())
        };

        let header_str = String::from_utf8_lossy(header_bytes);
        let mut lines = header_str.lines();
        let request_line = lines.next().unwrap_or("");
        let parts: Vec<&str> = request_line.split_whitespace().collect();
        if parts.is_empty() {
            return Ok(());
        }

        let method = parts[0];
        let path = if parts.len() > 1 { parts[1] } else { "/" };

        println!("\x1b[35m[HTTP]\x1b[0m Incoming {} {}", method, path);

        let mut content_length = 0usize;
        let mut request_origin: Option<String> = None;
        let mut tab_origin: Option<String> = None;
        let mut ext_confirmed = false;
        for line in lines {
            let lower = line.to_lowercase();
            if let Some(val) = lower.strip_prefix("content-length:") {
                content_length = val.trim().parse::<usize>().unwrap_or(0);
            } else if let Some(val) = lower.strip_prefix("origin:") {
                request_origin = Some(val.trim().to_string());
            } else if let Some(val) = lower.strip_prefix("x-credshell-tab-origin:") {
                tab_origin = Some(val.trim().to_string());
            } else if let Some(val) = lower.strip_prefix("x-credshell-confirmed:") {
                ext_confirmed = val.trim().eq_ignore_ascii_case("true");
            }
        }

        const MAX_CONTENT_LENGTH: usize = 65536;
        if content_length > MAX_CONTENT_LENGTH {
            return Self::send_json_cors(stream, 413, "{\"error\":\"Payload Too Large\"}", request_origin.as_deref());
        }

        if let Some(ref origin) = request_origin {
            if !is_allowed_origin(origin) {
                let forbidden = "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nForbidden: Untrusted Origin\r\n";
                stream.write_all(forbidden.as_bytes()).map_err(|e| e.to_string())?;
                stream.flush().map_err(|e| e.to_string())?;
                let _ = stream.shutdown(std::net::Shutdown::Both);
                return Ok(());
            }
        }

        if method == "OPTIONS" {
            let cors_origin = request_origin.as_deref().unwrap_or("http://127.0.0.1");
            if is_allowed_origin(cors_origin) {
                let cors_response = format!(
                    "HTTP/1.1 204 No Content\r\n\
Access-Control-Allow-Origin: {}\r\n\
Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n\
Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With, X-CredShell-Tab-Origin, X-CredShell-Confirmed\r\n\
Access-Control-Allow-Private-Network: true\r\n\
Connection: close\r\n\r\n",
                    cors_origin
                );
                stream.write_all(cors_response.as_bytes()).map_err(|e| e.to_string())?;
                stream.flush().map_err(|e| e.to_string())?;
            } else {
                let forbidden = "HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n";
                stream.write_all(forbidden.as_bytes()).map_err(|e| e.to_string())?;
                stream.flush().map_err(|e| e.to_string())?;
            }
            let _ = stream.shutdown(std::net::Shutdown::Both);
            return Ok(());
        }

        if method == "GET" && (path == "/status" || path == "/") {
            println!("\x1b[32m[HTTP 200]\x1b[0m Status ping successful (companion app connected)");
            let passkeys_len = vault_arc.read().unwrap().passkeys.len();
            let body = format!(
                "{{\"status\":\"active\",\"name\":\"CredShell\",\"passkeys\":{}}}",
                passkeys_len
            );
            Self::send_json_cors(stream, 200, &body, request_origin.as_deref())?;
            return Ok(());
        }

        let mut body_bytes = data[body_initial_offset..].to_vec();
        while body_bytes.len() < content_length {
            let mut chunk = vec![0u8; content_length - body_bytes.len()];
            let n = stream.read(&mut chunk).map_err(|e| e.to_string())?;
            if n == 0 { break; }
            body_bytes.extend_from_slice(&chunk[..n]);
        }

        let body_str = String::from_utf8_lossy(&body_bytes);
        let parsed_json = JsonParser::parse(&body_str).unwrap_or(JsonVal::Null);

        if method == "POST" && path == "/webauthn/create" {
            let mut vault = vault_arc.write().unwrap();
            self.handle_webauthn_create(stream, &mut vault, &parsed_json, request_origin.as_deref(), tab_origin.as_deref(), ext_confirmed)
        } else if method == "POST" && path == "/webauthn/get" {
            let mut vault = vault_arc.write().unwrap();
            self.handle_webauthn_get(stream, &mut vault, &parsed_json, request_origin.as_deref(), tab_origin.as_deref(), ext_confirmed)
        } else if method == "POST" && path == "/webauthn/query" {
            let vault = vault_arc.read().unwrap();
            self.handle_webauthn_query(stream, &vault, &parsed_json, request_origin.as_deref(), tab_origin.as_deref())
        } else {
            Self::send_json_cors(stream, 404, "{\"error\":\"Not Found\"}", request_origin.as_deref())
        }
    }

    fn handle_webauthn_create(
        &self,
        stream: &mut TcpStream,
        vault: &mut Vault,
        json: &JsonVal,
        request_origin: Option<&str>,
        tab_origin: Option<&str>,
        ext_confirmed: bool,
    ) -> Result<(), String> {
        let root = json.get("publicKey").or_else(|| json.get("options")).unwrap_or(json);

        let rp_id = root.get_str("rp_id")
            .or_else(|| root.get_str("rpId"))
            .or_else(|| root.get("rp").and_then(|r| r.get_str("id")))
            .or_else(|| json.get_str("rp_id"))
            .or_else(|| json.get_str("rpId"))
            .or_else(|| json.get("rp").and_then(|r| r.get_str("id")))
            .unwrap_or("unknown-rp");

        let rp_name = root.get_str("rp_name")
            .or_else(|| root.get_str("rpName"))
            .or_else(|| root.get("rp").and_then(|r| r.get_str("name")))
            .or_else(|| json.get_str("rp_name"))
            .or_else(|| json.get_str("rpName"))
            .or_else(|| json.get("rp").and_then(|r| r.get_str("name")))
            .unwrap_or(rp_id);

        let user_name = root.get_str("user_name")
            .or_else(|| root.get_str("userName"))
            .or_else(|| root.get("user").and_then(|u| u.get_str("name")))
            .or_else(|| root.get("user").and_then(|u| u.get_str("displayName")))
            .or_else(|| json.get_str("user_name"))
            .or_else(|| json.get_str("userName"))
            .or_else(|| json.get("user").and_then(|u| u.get_str("name")))
            .or_else(|| json.get("user").and_then(|u| u.get_str("displayName")))
            .unwrap_or("user");

        let challenge = root.get_str("challenge")
            .or_else(|| json.get_str("challenge"))
            .unwrap_or("ephemeral-challenge");

        let package_name = json.get_str("package_name")
            .or_else(|| json.get_str("packageName"))
            .or_else(|| root.get_str("package_name"))
            .or_else(|| root.get_str("packageName"));

        let default_origin = if rp_id == "localhost" || rp_id.starts_with("127.0.0.1") {
            "https://localhost".to_string()
        } else if rp_id.starts_with("android:apk-key-hash:") || rp_id.starts_with("https://") || rp_id.starts_with("http://") {
            rp_id.to_string()
        } else {
            format!("https://{}", rp_id)
        };
        let origin = json.get_str("origin")
            .or_else(|| root.get_str("origin"))
            .unwrap_or(&default_origin);

        let mut alg = -7;
        let params_opt = root.get("pubKeyCredParams")
            .or_else(|| json.get("pubKeyCredParams"))
            .and_then(|v| v.as_array());

        if let Some(params) = params_opt {
            let mut has_es256 = false;
            let mut has_eddsa = false;
            for p in params {
                if let Some(a) = p.get("alg").and_then(|v| v.as_i64()) {
                    if a == -7 {
                        has_es256 = true;
                    } else if a == -8 {
                        has_eddsa = true;
                    }
                }
            }
            if has_es256 {
                alg = -7;
            } else if has_eddsa {
                alg = -8;
            }
        } else if let Some(a) = root.get("alg").or_else(|| json.get("alg")).and_then(|v| v.as_i64()) {
            alg = a as i32;
        }

        print_passkey_reg_box(rp_id, user_name);

        let is_extension = request_origin
            .map(|o| o.starts_with("chrome-extension://") || o.starts_with("moz-extension://"))
            .unwrap_or(false);

        let is_android = origin.starts_with("android:apk-key-hash:")
            && request_origin.map(|o| !o.starts_with("http://") && !o.starts_with("https://")).unwrap_or(true);

        let is_extension_valid = is_extension && ext_confirmed && {
            if let Some(tab_host) = tab_origin {
                crate::core::vault::model::rp_matches_requested(tab_host, rp_id)
            } else {
                false
            }
        };

        let approved = if self.auto_approve {
            println!("Auto-approving registration (-y flag)...");
            true
        } else if is_extension_valid {
            println!("Registration authorized by Browser Extension.");
            true
        } else {
            let msg = format!("Create new Passkey for '{}'?\nUser: {}", rp_id, user_name);
            native_gui_confirm("CredShell Passkey Registration", &msg)
        };

        if !approved {
            println!("Registration declined.\nWaiting for requests...\n");
            return Self::send_json_cors(stream, 403, "{\"error\":\"Passkey registration declined by user\"}", request_origin);
        }

        let chosen_id = vault.generate_unique_passkey_id(rp_id, user_name);

        let user_id_str = root.get_str("user_id")
            .or_else(|| root.get_str("userId"))
            .or_else(|| root.get("user").and_then(|u| u.get_str("id")))
            .or_else(|| json.get_str("user_id"))
            .or_else(|| json.get_str("userId"))
            .or_else(|| json.get("user").and_then(|u| u.get_str("id")));

        let user_id = user_id_str
            .and_then(|s| decode_base64url(s).ok().or_else(|| Some(s.as_bytes().to_vec())))
            .unwrap_or_default();

        let overwrite = root.get("overwrite")
            .or_else(|| json.get("overwrite"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let already_exists = vault.passkeys.iter().any(|p| p.id.eq_ignore_ascii_case(&chosen_id));

        let cred = if already_exists {
            if is_android {
                println!("Renaming existing key to backup (-bak-timestamp) for Android Credential Manager...");
                vault.backup_and_overwrite_passkey(&chosen_id, rp_id, rp_name, user_name, &user_id, alg)?
            } else {
                let can_overwrite = overwrite || self.auto_approve || {
                    if is_extension_valid {
                        false
                    } else {
                        let confirm_msg = format!("Passkey with ID '{}' already exists.\nDo you want to overwrite it?", chosen_id);
                        native_gui_confirm("Overwrite Passkey?", &confirm_msg)
                    }
                };
                if !can_overwrite {
                    println!("Passkey overwrite declined.\nWaiting for requests...\n");
                    return Self::send_json_cors(stream, 403, "{\"error\":\"Passkey overwrite declined by user\"}", request_origin);
                }
                println!("Overwriting existing passkey '{}'...", chosen_id);
                vault.overwrite_passkey_with_id(&chosen_id, rp_id, rp_name, user_name, &user_id, alg)?
            }
        } else {
            println!("Storing private key for ID '{}'...", chosen_id);
            vault.add_passkey_with_id(&chosen_id, rp_id, rp_name, user_name, &user_id, alg)?
        };

        save_vault_atomic(&self.vault_path, vault, &self.passphrase)?;
        println!("✓ Passkey registered with ID '{}' for {} ({})\nWaiting for requests...\n", cred.id, cred.rp_id, cred.user_name);

        let auth_data = make_registration_auth_data(
            rp_id,
            cred.sign_count,
            &cred.credential_id,
            &cred.public_key,
            cred.alg,
        );
        let attestation_obj = make_attestation_object(&auth_data);
        let spki = if cred.alg == -8 {
            ed25519_pubkey_to_spki(&cred.public_key)
        } else {
            p256_pubkey_to_spki(&cred.public_key)
        };

        let client_data_json = if let Some(pkg) = package_name {
            format!(
                "{{\"type\":\"webauthn.create\",\"challenge\":\"{}\",\"origin\":\"{}\",\"androidPackageName\":\"{}\"}}",
                challenge, origin, pkg
            )
        } else {
            format!(
                "{{\"type\":\"webauthn.create\",\"challenge\":\"{}\",\"origin\":\"{}\",\"crossOrigin\":false}}",
                challenge, origin
            )
        };

        let cred_id_b64 = encode_base64url(&cred.credential_id);
        let client_data_b64 = encode_base64url(client_data_json.as_bytes());
        let attestation_b64 = encode_base64url(&attestation_obj);
        let auth_data_b64 = encode_base64url(&auth_data);
        let spki_b64 = encode_base64url(&spki);

        let response_body = format!(
            "{{\"id\":\"{}\",\"rawId\":\"{}\",\"type\":\"public-key\",\"authenticatorAttachment\":\"platform\",\"clientExtensionResults\":{{}},\"response\":{{\"clientDataJSON\":\"{}\",\"attestationObject\":\"{}\",\"authenticatorData\":\"{}\",\"transports\":[\"internal\"],\"publicKey\":\"{}\",\"publicKeyAlgorithm\":{}}}}}",
            cred_id_b64, cred_id_b64, client_data_b64, attestation_b64, auth_data_b64, spki_b64, cred.alg
        );

        Self::send_json_cors(stream, 200, &response_body, request_origin)
    }

    fn handle_webauthn_get(
        &self,
        stream: &mut TcpStream,
        vault: &mut Vault,
        json: &JsonVal,
        request_origin: Option<&str>,
        tab_origin: Option<&str>,
        ext_confirmed: bool,
    ) -> Result<(), String> {
        let root = json.get("publicKey").or_else(|| json.get("options")).unwrap_or(json);

        let rp_id = root.get_str("rp_id")
            .or_else(|| root.get_str("rpId"))
            .or_else(|| root.get("rp").and_then(|r| r.get_str("id")))
            .or_else(|| json.get_str("rp_id"))
            .or_else(|| json.get_str("rpId"))
            .or_else(|| json.get("rp").and_then(|r| r.get_str("id")))
            .unwrap_or("unknown-rp");

        let challenge = root.get_str("challenge")
            .or_else(|| json.get_str("challenge"))
            .unwrap_or("ephemeral-challenge");

        let package_name = json.get_str("package_name")
            .or_else(|| json.get_str("packageName"))
            .or_else(|| root.get_str("package_name"))
            .or_else(|| root.get_str("packageName"));

        let default_origin = if rp_id == "localhost" || rp_id.starts_with("127.0.0.1") {
            "https://localhost".to_string()
        } else if rp_id.starts_with("android:apk-key-hash:") || rp_id.starts_with("https://") || rp_id.starts_with("http://") {
            rp_id.to_string()
        } else {
            format!("https://{}", rp_id)
        };
        let origin = json.get_str("origin")
            .or_else(|| root.get_str("origin"))
            .unwrap_or(&default_origin);

        let mut matched_creds: Vec<&crate::core::vault::PasskeyCredential> = Vec::new();
        let allow_arr = root.get("allow_credentials")
            .or_else(|| root.get("allowCredentials"))
            .or_else(|| json.get("allow_credentials"))
            .or_else(|| json.get("allowCredentials"))
            .and_then(|v| v.as_array());

        if let Some(arr) = allow_arr {
            for item in arr {
                let id_b64_opt = item.as_str().or_else(|| item.get_str("id"));
                if let Some(id_b64) = id_b64_opt {
                    if let Ok(id_bytes) = decode_base64url(id_b64) {
                        if let Some(c) = vault.find_passkey_by_id(&id_bytes) {
                            if !Vault::is_bak_passkey(&c.id) && !matched_creds.iter().any(|m| m.credential_id == c.credential_id) {
                                matched_creds.push(c);
                            }
                        }
                    }
                }
            }
        }

        if matched_creds.is_empty() {
            matched_creds = vault.find_passkeys_for_rp(rp_id);
        }

        let selected_id = json.get_str("selected_credential_id")
            .or_else(|| json.get_str("selectedCredentialId"))
            .or_else(|| json.get_str("credential_id"))
            .or_else(|| json.get_str("credentialId"))
            .or_else(|| root.get_str("selected_credential_id"))
            .or_else(|| root.get_str("selectedCredentialId"))
            .or_else(|| root.get_str("credential_id"))
            .or_else(|| root.get_str("credentialId"));

        let chosen_cred = if let Some(sel_b64) = selected_id {
            let found = if let Ok(id_bytes) = decode_base64url(sel_b64) {
                vault.find_passkey_by_id(&id_bytes)
            } else {
                vault.find_passkey_by_custom_id(sel_b64)
            };
            if let Some(c) = found {
                if !Vault::is_bak_passkey(&c.id) {
                    Some(c)
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };

        let cred = if let Some(c) = chosen_cred {
            c.clone()
        } else if !matched_creds.is_empty() {
            matched_creds[0].clone()
        } else {
            println!("\x1b[33m[Passkey request]\x1b[0m No registered passkey found for RP '{}' ({} passkeys in vault).\n", rp_id, vault.passkeys.len());
            return Self::send_json_cors(stream, 404, "{\"error\":\"No passkey found for Relying Party\"}", request_origin);
        };

        let user_name = cred.user_name.clone();
        let cred_id = cred.credential_id.clone();
        let private_seed = cred.private_seed;
        let public_key = cred.public_key.clone();
        let cred_alg = cred.alg;

        print_passkey_request_box(rp_id, &user_name);

        let is_extension = request_origin
            .map(|o| o.starts_with("chrome-extension://") || o.starts_with("moz-extension://"))
            .unwrap_or(false);

        let is_extension_valid = is_extension && ext_confirmed && {
            if let Some(tab_host) = tab_origin {
                crate::core::vault::model::rp_matches_requested(tab_host, rp_id)
            } else {
                false
            }
        };

        let approved = if self.auto_approve {
            println!("Auto-approving authentication (-y flag)...");
            true
        } else if is_extension_valid {
            println!("Registration authorized by Browser Extension.");
            true
        } else {
            let msg = format!("Allow Passkey sign-in to '{}'?\nUser: {}", rp_id, user_name);
            native_gui_confirm("CredShell Passkey Authentication", &msg)
        };

        if !approved {
            println!("Authentication declined.\nWaiting for requests...\n");
            return Self::send_json_cors(stream, 403, "{\"error\":\"Authentication declined by user\"}", request_origin);
        }

        let new_count = vault.increment_passkey_sign_count_by_id(&cred_id).unwrap_or(1);
        save_vault_atomic(&self.vault_path, vault, &self.passphrase)?;

        let effective_rp_id = if rp_id != "unknown-rp" { rp_id } else { &cred.rp_id };
        let auth_data = make_assertion_auth_data(effective_rp_id, new_count);

        let client_data_json = if let Some(pkg) = package_name {
            format!(
                "{{\"type\":\"webauthn.get\",\"challenge\":\"{}\",\"origin\":\"{}\",\"androidPackageName\":\"{}\"}}",
                challenge, origin, pkg
            )
        } else {
            format!(
                "{{\"type\":\"webauthn.get\",\"challenge\":\"{}\",\"origin\":\"{}\",\"crossOrigin\":false}}",
                challenge, origin
            )
        };
        let client_data_hash = sha256(client_data_json.as_bytes());
        let signature = sign_assertion(cred_alg, &private_seed, &public_key, &auth_data, &client_data_hash)?;

        println!("✓ Authentication successful\nWaiting for requests...\n");

        let cred_id_b64 = encode_base64url(&cred_id);
        let auth_data_b64 = encode_base64url(&auth_data);
        let client_data_b64 = encode_base64url(client_data_json.as_bytes());
        let sig_b64 = encode_base64url(&signature);
        let user_handle_json = if !cred.user_id.is_empty() {
            format!("\"{}\"", encode_base64url(&cred.user_id))
        } else {
            "null".to_string()
        };

        let response_body = format!(
            "{{\"id\":\"{}\",\"rawId\":\"{}\",\"type\":\"public-key\",\"authenticatorAttachment\":\"platform\",\"clientExtensionResults\":{{}},\"response\":{{\"authenticatorData\":\"{}\",\"clientDataJSON\":\"{}\",\"signature\":\"{}\",\"userHandle\":{}}}}}",
            cred_id_b64, cred_id_b64, auth_data_b64, client_data_b64, sig_b64, user_handle_json
        );

        Self::send_json_cors(stream, 200, &response_body, request_origin)
    }

    fn handle_webauthn_query(
        &self,
        stream: &mut TcpStream,
        vault: &Vault,
        json: &JsonVal,
        request_origin: Option<&str>,
        tab_origin: Option<&str>,
    ) -> Result<(), String> {
        let root = json.get("publicKey").or_else(|| json.get("options")).unwrap_or(json);

        let rp_id = root.get_str("rp_id")
            .or_else(|| root.get_str("rpId"))
            .or_else(|| root.get("rp").and_then(|r| r.get_str("id")))
            .or_else(|| json.get_str("rp_id"))
            .or_else(|| json.get_str("rpId"))
            .unwrap_or("unknown-rp");

        let is_extension = request_origin
            .map(|o| o.starts_with("chrome-extension://") || o.starts_with("moz-extension://"))
            .unwrap_or(false);
        if is_extension {
            if let Some(tab_host) = tab_origin {
                if !crate::core::vault::model::rp_matches_requested(tab_host, rp_id) {
                    return Self::send_json_cors(stream, 403, "{\"error\":\"RP mismatch for active tab\"}", request_origin);
                }
            }
        }

        let allow_arr = root.get("allow_credentials")
            .or_else(|| root.get("allowCredentials"))
            .or_else(|| json.get("allow_credentials"))
            .or_else(|| json.get("allowCredentials"))
            .and_then(|v| v.as_array());

        let mut matched_creds: Vec<&crate::core::vault::PasskeyCredential> = Vec::new();

        if let Some(arr) = allow_arr {
            for item in arr {
                let id_b64_opt = item.as_str().or_else(|| item.get_str("id"));
                if let Some(id_b64) = id_b64_opt {
                    if let Ok(id_bytes) = decode_base64url(id_b64) {
                        if let Some(c) = vault.find_passkey_by_id(&id_bytes) {
                            if !Vault::is_bak_passkey(&c.id) && !matched_creds.iter().any(|m| m.credential_id == c.credential_id) {
                                matched_creds.push(c);
                            }
                        }
                    }
                }
            }
        }

        if matched_creds.is_empty() {
            matched_creds = vault.find_passkeys_for_rp(rp_id);
        }

        let mut accounts_json = Vec::new();
        for c in &matched_creds {
            let id_b64 = encode_base64url(&c.credential_id);
            accounts_json.push(format!(
                "{{\"id\":\"{}\",\"custom_id\":\"{}\",\"user_name\":\"{}\",\"rp_id\":\"{}\",\"rp_name\":\"{}\",\"sign_count\":{}}}",
                id_b64,
                escape_json(&c.id),
                escape_json(&c.user_name),
                escape_json(&c.rp_id),
                escape_json(&c.rp_name),
                c.sign_count
            ));
        }

        let check_user = root.get_str("user_name")
            .or_else(|| root.get_str("userName"))
            .or_else(|| json.get_str("user_name"))
            .or_else(|| json.get_str("userName"));

        let check_id = if let Some(u) = check_user {
            format!("{}#{}", u.trim(), rp_id.trim())
        } else {
            String::new()
        };

        let exists = if !check_id.is_empty() {
            vault.passkeys.iter().any(|p| p.id.eq_ignore_ascii_case(&check_id))
        } else {
            false
        };

        let has_passkeys = !matched_creds.is_empty();
        let body = format!(
            "{{\"has_passkeys\":{},\"exists\":{},\"accounts\":[{}]}}",
            has_passkeys,
            exists,
            accounts_json.join(",")
        );

        Self::send_json_cors(stream, 200, &body, request_origin)
    }

    fn send_json_cors(
        stream: &mut TcpStream,
        status_code: u16,
        body: &str,
        origin_opt: Option<&str>,
    ) -> Result<(), String> {
        let status_text = match status_code {
            200 => "OK",
            204 => "No Content",
            400 => "Bad Request",
            403 => "Forbidden",
            404 => "Not Found",
            413 => "Payload Too Large",
            _ => "Internal Server Error",
        };

        let cors_header = if let Some(origin) = origin_opt {
            if is_allowed_origin(origin) {
                format!(
                    "Access-Control-Allow-Origin: {}\r\n\
Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n\
Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With\r\n\
Access-Control-Allow-Private-Network: true\r\n",
                    origin
                )
            } else {
                String::new()
            }
        } else {
            String::new()
        };

        let response = format!(
            "HTTP/1.1 {} {}\r\n\
Content-Type: application/json; charset=utf-8\r\n\
{}Content-Length: {}\r\n\
Connection: close\r\n\r\n{}",
            status_code,
            status_text,
            cors_header,
            body.len(),
            body
        );

        stream.write_all(response.as_bytes()).map_err(|e| e.to_string())?;
        stream.flush().map_err(|e| e.to_string())?;
        let _ = stream.shutdown(std::net::Shutdown::Both);
        Ok(())
    }

    #[allow(dead_code)]
    fn send_json(stream: &mut TcpStream, status_code: u16, body: &str) -> Result<(), String> {
        Self::send_json_cors(stream, status_code, body, None)
    }
}
