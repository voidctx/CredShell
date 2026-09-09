use super::model::{hex_decode, hex_encode, DeviceIdentity, PasskeyCredential, TotpEntry, Vault};

pub fn escape_json(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

pub fn vault_to_json(vault: &Vault) -> String {
    let mut out = String::new();
    out.push_str("{\n");
    out.push_str(&format!("  \"version\": {},\n", vault.version));
    out.push_str(&format!("  \"device_name\": \"{}\",\n", escape_json(&vault.device_name)));
    out.push_str(&format!("  \"device_seed\": \"{}\",\n", hex_encode(&vault.device_seed)));
    out.push_str(&format!("  \"device_public_key\": \"{}\",\n", hex_encode(&vault.device_public_key)));
    out.push_str(&format!("  \"created_at\": {},\n", vault.created_at));
    out.push_str(&format!("  \"updated_at\": {},\n", vault.updated_at));

    out.push_str("  \"totp_entries\": [\n");
    for (i, t) in vault.totp_entries.iter().enumerate() {
        out.push_str("    {\n");
        out.push_str(&format!("      \"id\": \"{}\",\n", escape_json(&t.id)));
        out.push_str(&format!("      \"name\": \"{}\",\n", escape_json(&t.name)));
        out.push_str(&format!("      \"issuer\": \"{}\",\n", escape_json(&t.issuer)));
        out.push_str(&format!("      \"account\": \"{}\",\n", escape_json(&t.account)));
        out.push_str(&format!("      \"secret_base32\": \"{}\",\n", escape_json(&t.secret_base32)));
        out.push_str(&format!("      \"algorithm\": \"{}\",\n", escape_json(&t.algorithm)));
        out.push_str(&format!("      \"digits\": {},\n", t.digits));
        out.push_str(&format!("      \"period\": {},\n", t.period));
        out.push_str(&format!("      \"created_at\": {},\n", t.created_at));
        out.push_str(&format!("      \"updated_at\": {}\n", t.updated_at));
        if i + 1 < vault.totp_entries.len() {
            out.push_str("    },\n");
        } else {
            out.push_str("    }\n");
        }
    }
    out.push_str("  ],\n");

    out.push_str("  \"passkeys\": [\n");
    for (i, p) in vault.passkeys.iter().enumerate() {
        out.push_str("    {\n");
        out.push_str(&format!("      \"id\": \"{}\",\n", escape_json(&p.id)));
        out.push_str(&format!("      \"rp_id\": \"{}\",\n", escape_json(&p.rp_id)));
        out.push_str(&format!("      \"rp_name\": \"{}\",\n", escape_json(&p.rp_name)));
        out.push_str(&format!("      \"user_name\": \"{}\",\n", escape_json(&p.user_name)));
        out.push_str(&format!("      \"user_id\": \"{}\",\n", hex_encode(&p.user_id)));
        out.push_str(&format!("      \"credential_id\": \"{}\",\n", hex_encode(&p.credential_id)));
        out.push_str(&format!("      \"private_seed\": \"{}\",\n", hex_encode(&p.private_seed)));
        out.push_str(&format!("      \"public_key\": \"{}\",\n", hex_encode(&p.public_key)));
        out.push_str(&format!("      \"alg\": {},\n", p.alg));
        out.push_str(&format!("      \"sign_count\": {},\n", p.sign_count));
        out.push_str(&format!("      \"created_at\": {}\n", p.created_at));
        if i + 1 < vault.passkeys.len() {
            out.push_str("    },\n");
        } else {
            out.push_str("    }\n");
        }
    }
    out.push_str("  ],\n");

    out.push_str("  \"trusted_devices\": [\n");
    for (i, d) in vault.trusted_devices.iter().enumerate() {
        out.push_str("    {\n");
        out.push_str(&format!("      \"device_id\": \"{}\",\n", escape_json(&d.device_id)));
        out.push_str(&format!("      \"device_name\": \"{}\",\n", escape_json(&d.device_name)));
        out.push_str(&format!("      \"public_key\": \"{}\",\n", hex_encode(&d.public_key)));
        out.push_str(&format!("      \"trusted\": {},\n", d.trusted));
        out.push_str(&format!("      \"last_sync\": {}\n", d.last_sync));
        if i + 1 < vault.trusted_devices.len() {
            out.push_str("    },\n");
        } else {
            out.push_str("    }\n");
        }
    }
    out.push_str("  ]\n");
    out.push_str("}\n");
    out
}

#[derive(Clone, Debug, PartialEq)]
pub enum JsonVal {
    Null,
    Bool(bool),
    Number(f64),
    Str(String),
    Array(Vec<JsonVal>),
    Object(Vec<(String, JsonVal)>),
}

impl JsonVal {
    pub fn get(&self, key: &str) -> Option<&JsonVal> {
        if let JsonVal::Object(map) = self {
            map.iter().find(|(k, _)| k == key).map(|(_, v)| v)
        } else {
            None
        }
    }

    pub fn get_str(&self, key: &str) -> Option<&str> {
        self.get(key).and_then(|v| v.as_str())
    }

    pub fn get_bool(&self, key: &str) -> Option<bool> {
        self.get(key).and_then(|v| v.as_bool())
    }

    pub fn as_str(&self) -> Option<&str> {
        if let JsonVal::Str(s) = self {
            Some(s)
        } else {
            None
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        if let JsonVal::Number(n) = self {
            Some(*n as u64)
        } else {
            None
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        if let JsonVal::Number(n) = self {
            Some(*n as i64)
        } else {
            None
        }
    }

    pub fn as_u32(&self) -> Option<u32> {
        self.as_u64().map(|v| v as u32)
    }

    pub fn as_bool(&self) -> Option<bool> {
        if let JsonVal::Bool(b) = self {
            Some(*b)
        } else {
            None
        }
    }

    pub fn as_array(&self) -> Option<&[JsonVal]> {
        if let JsonVal::Array(arr) = self {
            Some(arr)
        } else {
            None
        }
    }
}

pub struct JsonParser<'a> {
    chars: Vec<char>,
    pos: usize,
    depth: usize,
    _marker: std::marker::PhantomData<&'a ()>,
}

impl<'a> JsonParser<'a> {
    const MAX_DEPTH: usize = 32;

    pub fn parse(input: &str) -> Result<JsonVal, String> {
        let mut p = Self {
            chars: input.chars().collect(),
            pos: 0,
            depth: 0,
            _marker: std::marker::PhantomData,
        };
        p.skip_whitespace();
        let val = p.parse_value()?;
        p.skip_whitespace();
        if p.pos < p.chars.len() {
            return Err(format!("Unexpected trailing characters at index {}", p.pos));
        }
        Ok(val)
    }

    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<char> {
        let ch = self.peek();
        if ch.is_some() {
            self.pos += 1;
        }
        ch
    }

    fn skip_whitespace(&mut self) {
        while let Some(ch) = self.peek() {
            if ch.is_whitespace() {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    fn parse_value(&mut self) -> Result<JsonVal, String> {
        self.skip_whitespace();
        match self.peek() {
            Some('{') => self.parse_object(),
            Some('[') => self.parse_array(),
            Some('"') => self.parse_string().map(JsonVal::Str),
            Some('t') | Some('f') => self.parse_bool(),
            Some('n') => self.parse_null(),
            Some(c) if c.is_ascii_digit() || c == '-' => self.parse_number(),
            Some(c) => Err(format!("Unexpected character '{}' at pos {}", c, self.pos)),
            None => Err("Unexpected end of input".to_string()),
        }
    }

    fn parse_object(&mut self) -> Result<JsonVal, String> {
        self.depth += 1;
        if self.depth > Self::MAX_DEPTH {
            return Err("JSON recursion depth limit exceeded".to_string());
        }
        self.bump();
        self.skip_whitespace();
        let mut entries = Vec::new();

        if let Some('}') = self.peek() {
            self.bump();
            self.depth -= 1;
            return Ok(JsonVal::Object(entries));
        }

        loop {
            self.skip_whitespace();
            let key = match self.peek() {
                Some('"') => self.parse_string()?,
                Some(c) => return Err(format!("Expected string key, found '{}' at {}", c, self.pos)),
                None => return Err("Unexpected EOF in object key".to_string()),
            };

            self.skip_whitespace();
            if self.bump() != Some(':') {
                return Err(format!("Expected ':' after key at pos {}", self.pos));
            }

            let val = self.parse_value()?;
            entries.push((key, val));

            self.skip_whitespace();
            match self.bump() {
                Some(',') => continue,
                Some('}') => break,
                Some(c) => return Err(format!("Expected ',' or '}}', found '{}' at {}", c, self.pos)),
                None => return Err("Unexpected EOF in object".to_string()),
            }
        }

        self.depth -= 1;
        Ok(JsonVal::Object(entries))
    }

    fn parse_array(&mut self) -> Result<JsonVal, String> {
        self.depth += 1;
        if self.depth > Self::MAX_DEPTH {
            return Err("JSON recursion depth limit exceeded".to_string());
        }
        self.bump();
        self.skip_whitespace();
        let mut items = Vec::new();

        if let Some(']') = self.peek() {
            self.bump();
            self.depth -= 1;
            return Ok(JsonVal::Array(items));
        }

        loop {
            let val = self.parse_value()?;
            items.push(val);

            self.skip_whitespace();
            match self.bump() {
                Some(',') => continue,
                Some(']') => break,
                Some(c) => return Err(format!("Expected ',' or ']', found '{}' at {}", c, self.pos)),
                None => return Err("Unexpected EOF in array".to_string()),
            }
        }

        self.depth -= 1;
        Ok(JsonVal::Array(items))
    }

    fn parse_string(&mut self) -> Result<String, String> {
        self.bump();
        let mut s = String::new();

        while let Some(ch) = self.bump() {
            match ch {
                '"' => return Ok(s),
                '\\' => match self.bump() {
                    Some('"') => s.push('"'),
                    Some('\\') => s.push('\\'),
                    Some('/') => s.push('/'),
                    Some('b') => s.push('\x08'),
                    Some('f') => s.push('\x0c'),
                    Some('n') => s.push('\n'),
                    Some('r') => s.push('\r'),
                    Some('t') => s.push('\t'),
                    Some('u') => {
                        let mut hex = String::new();
                        for _ in 0..4 {
                            if let Some(h) = self.bump() {
                                hex.push(h);
                            }
                        }
                        if let Ok(codepoint) = u32::from_str_radix(&hex, 16) {
                            if let Some(c) = char::from_u32(codepoint) {
                                s.push(c);
                            }
                        }
                    }
                    _ => s.push('\\'),
                },
                c => s.push(c),
            }
        }
        Err("Unterminated string in JSON".to_string())
    }

    fn parse_number(&mut self) -> Result<JsonVal, String> {
        let mut num_str = String::new();
        while let Some(ch) = self.peek() {
            if ch.is_ascii_digit() || ch == '-' || ch == '+' || ch == '.' || ch == 'e' || ch == 'E' {
                num_str.push(ch);
                self.pos += 1;
            } else {
                break;
            }
        }
        let num: f64 = num_str.parse().map_err(|e| format!("Invalid number: {}", e))?;
        Ok(JsonVal::Number(num))
    }

    fn parse_bool(&mut self) -> Result<JsonVal, String> {
        if self.pos < self.chars.len() && self.chars[self.pos..].starts_with(&['t', 'r', 'u', 'e']) {
            self.pos += 4;
            Ok(JsonVal::Bool(true))
        } else if self.pos < self.chars.len() && self.chars[self.pos..].starts_with(&['f', 'a', 'l', 's', 'e']) {
            self.pos += 5;
            Ok(JsonVal::Bool(false))
        } else {
            Err(format!("Invalid boolean literal at pos {}", self.pos))
        }
    }

    fn parse_null(&mut self) -> Result<JsonVal, String> {
        if self.pos < self.chars.len() && self.chars[self.pos..].starts_with(&['n', 'u', 'l', 'l']) {
            self.pos += 4;
            Ok(JsonVal::Null)
        } else {
            Err(format!("Invalid null literal at pos {}", self.pos))
        }
    }
}

pub fn vault_from_json(s: &str) -> Result<Vault, String> {
    let root = JsonParser::parse(s)?;

    let version = root.get("version").and_then(|v| v.as_u32()).unwrap_or(1);
    let device_name = root.get("device_name").and_then(|v| v.as_str()).unwrap_or("credshell-node").to_string();

    let device_seed_hex = root.get("device_seed").and_then(|v| v.as_str()).unwrap_or("");
    let device_seed_vec = hex_decode(device_seed_hex).unwrap_or_else(|_| vec![0u8; 32]);
    let mut device_seed = [0u8; 32];
    if device_seed_vec.len() == 32 {
        device_seed.copy_from_slice(&device_seed_vec);
    }

    let device_pk_hex = root.get("device_public_key").and_then(|v| v.as_str()).unwrap_or("");
    let device_pk_vec = hex_decode(device_pk_hex).unwrap_or_else(|_| vec![0u8; 32]);
    let mut device_public_key = [0u8; 32];
    if device_pk_vec.len() == 32 {
        device_public_key.copy_from_slice(&device_pk_vec);
    }

    let created_at = root.get("created_at").and_then(|v| v.as_u64()).unwrap_or(0);
    let updated_at = root.get("updated_at").and_then(|v| v.as_u64()).unwrap_or(0);

    let mut totp_entries = Vec::new();
    if let Some(arr) = root.get("totp_entries").and_then(|v| v.as_array()) {
        for item in arr {
            let id = item.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let name = item.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let issuer = item.get("issuer").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let account = item.get("account").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let secret_base32 = item.get("secret_base32").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let algorithm = item.get("algorithm").and_then(|v| v.as_str()).unwrap_or("SHA-1").to_string();
            let digits = item.get("digits").and_then(|v| v.as_u32()).unwrap_or(6);
            let period = item.get("period").and_then(|v| v.as_u32()).unwrap_or(30);
            let c_at = item.get("created_at").and_then(|v| v.as_u64()).unwrap_or(0);
            let u_at = item.get("updated_at").and_then(|v| v.as_u64()).unwrap_or(0);

            totp_entries.push(TotpEntry {
                id,
                name,
                issuer,
                account,
                secret_base32,
                algorithm,
                digits,
                period,
                created_at: c_at,
                updated_at: u_at,
            });
        }
    }

    let mut passkeys = Vec::new();
    if let Some(arr) = root.get("passkeys").and_then(|v| v.as_array()) {
        for item in arr {
            let id = item.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let rp_id = item.get("rp_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let rp_name = item.get("rp_name").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let user_name = item.get("user_name").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let uid_hex = item.get("user_id").and_then(|v| v.as_str()).unwrap_or("");
            let user_id = hex_decode(uid_hex).unwrap_or_default();
            let cred_id_hex = item.get("credential_id").and_then(|v| v.as_str()).unwrap_or("");
            let credential_id = hex_decode(cred_id_hex).unwrap_or_default();

            let seed_hex = item.get("private_seed").and_then(|v| v.as_str()).unwrap_or("");
            let seed_vec = hex_decode(seed_hex).unwrap_or_else(|_| vec![0u8; 32]);
            let mut private_seed = [0u8; 32];
            if seed_vec.len() == 32 {
                private_seed.copy_from_slice(&seed_vec);
            }

            let pk_hex = item.get("public_key").and_then(|v| v.as_str()).unwrap_or("");
            let public_key = hex_decode(pk_hex).unwrap_or_default();

            let alg = item
                .get("alg")
                .and_then(|v| v.as_i64())
                .map(|v| v as i32)
                .unwrap_or_else(|| if public_key.len() == 32 { -8 } else { -7 });

            let sign_count = item.get("sign_count").and_then(|v| v.as_u32()).unwrap_or(0);
            let c_at = item.get("created_at").and_then(|v| v.as_u64()).unwrap_or(0);

            passkeys.push(PasskeyCredential {
                id,
                rp_id,
                rp_name,
                user_name,
                user_id,
                credential_id,
                private_seed,
                public_key,
                alg,
                sign_count,
                created_at: c_at,
            });
        }
    }

    let mut trusted_devices = Vec::new();
    if let Some(arr) = root.get("trusted_devices").and_then(|v| v.as_array()) {
        for item in arr {
            let device_id = item.get("device_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let device_name = item.get("device_name").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let pk_hex = item.get("public_key").and_then(|v| v.as_str()).unwrap_or("");
            let pk_vec = hex_decode(pk_hex).unwrap_or_else(|_| vec![0u8; 32]);
            let mut public_key = [0u8; 32];
            if pk_vec.len() == 32 {
                public_key.copy_from_slice(&pk_vec);
            }
            let trusted = item.get("trusted").and_then(|v| v.as_bool()).unwrap_or(false);
            let last_sync = item.get("last_sync").and_then(|v| v.as_u64()).unwrap_or(0);

            trusted_devices.push(DeviceIdentity {
                device_id,
                device_name,
                public_key,
                trusted,
                last_sync,
            });
        }
    }

    Ok(Vault {
        version,
        device_name,
        device_seed,
        device_public_key,
        totp_entries,
        passkeys,
        trusted_devices,
        created_at,
        updated_at,
    })
}
