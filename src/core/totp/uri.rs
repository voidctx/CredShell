use crate::core::totp::base32::decode_base32;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OtpAuthUri {
    pub secret: String,
    pub issuer: Option<String>,
    pub account: Option<String>,
    pub algorithm: Option<String>,
    pub digits: Option<u32>,
    pub period: Option<u32>,
    pub label: String,
}

impl OtpAuthUri {
    pub fn suggested_id(&self) -> String {
        match (&self.issuer, &self.account) {
            (Some(iss), Some(acc)) if !acc.is_empty() => format!("{}:{}", iss, acc),
            (Some(iss), _) => iss.clone(),
            (None, Some(acc)) if !acc.is_empty() => acc.clone(),
            _ => self.label.clone(),
        }
    }
}

pub fn url_decode(s: &str) -> String {
    let mut raw = Vec::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(val) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                raw.push(val);
                i += 3;
                continue;
            }
        } else if bytes[i] == b'+' {
            raw.push(b' ');
            i += 1;
            continue;
        }
        raw.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&raw).to_string()
}

pub fn parse_otpauth_uri(uri_str: &str) -> Result<OtpAuthUri, String> {
    let trimmed = uri_str.trim();
    if !trimmed.starts_with("otpauth://") {
        return Err("URI must begin with 'otpauth://'".to_string());
    }

    let rest = &trimmed["otpauth://".len()..];
    let (auth_type_and_label, query) = match rest.split_once('?') {
        Some((path, q)) => (path, q),
        None => return Err("Invalid otpauth URI: missing '?' query separator".to_string()),
    };

    let (_auth_type, raw_label) = match auth_type_and_label.split_once('/') {
        Some((t, l)) => (t, l),
        None => ("totp", auth_type_and_label),
    };

    let full_label = url_decode(raw_label);
    let (mut label_issuer, mut label_account) = match full_label.split_once(':') {
        Some((iss, acc)) => (Some(iss.trim().to_string()), Some(acc.trim().to_string())),
        None => (None, Some(full_label.trim().to_string())),
    };

    let mut secret = None;
    let mut query_issuer = None;
    let mut algorithm = None;
    let mut digits = None;
    let mut period = None;

    for param in query.split('&') {
        if param.is_empty() {
            continue;
        }
        let (k, v) = match param.split_once('=') {
            Some((k, v)) => (k.trim().to_lowercase(), url_decode(v.trim())),
            None => (param.trim().to_lowercase(), String::new()),
        };

        match k.as_str() {
            "secret" => {
                let clean_secret = crate::core::totp::base32::clean_base32(&v);
                decode_base32(&clean_secret)
                    .map_err(|e| format!("Invalid Base32 secret in URI: {}", e))?;
                secret = Some(clean_secret);
            }
            "issuer" => {
                if !v.is_empty() {
                    query_issuer = Some(v);
                }
            }
            "algorithm" => {
                let alg_upper = v.to_uppercase();
                if alg_upper.contains("512") {
                    algorithm = Some("SHA-512".to_string());
                } else if alg_upper.contains("256") {
                    algorithm = Some("SHA-256".to_string());
                } else {
                    algorithm = Some("SHA-1".to_string());
                }
            }
            "digits" => {
                if let Ok(d) = v.parse::<u32>() {
                    digits = Some(d);
                }
            }
            "period" => {
                if let Ok(p) = v.parse::<u32>() {
                    period = Some(p);
                }
            }
            _ => {}
        }
    }

    let secret = secret.ok_or_else(|| "Missing required 'secret' parameter in otpauth URI".to_string())?;
    let final_issuer = query_issuer.or_else(|| label_issuer.take());

    Ok(OtpAuthUri {
        secret,
        issuer: final_issuer,
        account: label_account.take(),
        algorithm,
        digits,
        period,
        label: full_label,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_otpauth_uri() {
        let uri = "otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA1&digits=6&period=30";
        let parsed = parse_otpauth_uri(uri).unwrap();
        assert_eq!(parsed.secret, "JBSWY3DPEHPK3PXP");
        assert_eq!(parsed.issuer, Some("GitHub".to_string()));
        assert_eq!(parsed.account, Some("alice".to_string()));
        assert_eq!(parsed.algorithm, Some("SHA-1".to_string()));
        assert_eq!(parsed.digits, Some(6));
        assert_eq!(parsed.period, Some(30));
        assert_eq!(parsed.suggested_id(), "GitHub:alice");
    }

    #[test]
    fn test_parse_otpauth_uri_encoded() {
        let uri = "otpauth://totp/Google%20Workspace:bob%40company.com?secret=JBSWY3DPEHPK3PXP";
        let parsed = parse_otpauth_uri(uri).unwrap();
        assert_eq!(parsed.secret, "JBSWY3DPEHPK3PXP");
        assert_eq!(parsed.issuer, Some("Google Workspace".to_string()));
        assert_eq!(parsed.account, Some("bob@company.com".to_string()));
        assert_eq!(parsed.suggested_id(), "Google Workspace:bob@company.com");
    }

    #[test]
    fn test_url_decode_utf8_multibyte() {
        assert_eq!(url_decode("Soci%C3%A9t%C3%A9%20G%C3%A9n%C3%A9rale"), "Société Générale");
        assert_eq!(url_decode("%E4%BD%A0%E5%A5%BD%E4%B8%96%E7%95%8C"), "你好世界");
    }
}
