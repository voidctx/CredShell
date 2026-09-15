const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

pub fn is_ignorable_base32_char(ch: char) -> bool {
    if ch.is_whitespace() || ch.is_control() {
        return true;
    }
    match ch {
        '-' | '=' | '_' | ':' | '.' | ',' | '\'' | '"' | '`'
        | '‘' | '’' | '“' | '”'
        | '\u{200B}'..='\u{200F}'
        | '\u{202A}'..='\u{202E}'
        | '\u{2060}'
        | '\u{FEFF}'
        | '\u{00A0}'
        | '\u{00AD}'
        | '\u{2010}'..='\u{2015}'
        => true,
        _ => false,
    }
}

pub fn clean_base32(input: &str) -> String {
    input
        .chars()
        .filter(|&c| !is_ignorable_base32_char(c))
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

pub fn decode_base32(input: &str) -> Result<Vec<u8>, String> {
    let mut buffer = 0u64;
    let mut bits_in_buf = 0usize;
    let mut output = Vec::new();

    for ch in input.chars() {
        if is_ignorable_base32_char(ch) {
            continue;
        }

        let val = match ch {
            'A'..='Z' => (ch as u8 - b'A') as u64,
            'a'..='z' => (ch as u8 - b'a') as u64,
            '2'..='7' => (ch as u8 - b'2' + 26) as u64,
            _ => {
                if ch.is_control() || (ch as u32) > 127 {
                    return Err(format!("Invalid character in Base32 string: U+{:04X}", ch as u32));
                } else {
                    return Err(format!("Invalid character in Base32 string: '{}'", ch));
                }
            }
        };

        buffer = (buffer << 5) | val;
        bits_in_buf += 5;

        if bits_in_buf >= 8 {
            bits_in_buf -= 8;
            let byte = ((buffer >> bits_in_buf) & 0xff) as u8;
            output.push(byte);
        }
    }

    Ok(output)
}

pub fn encode_base32(data: &[u8]) -> String {
    let mut buffer = 0u64;
    let mut bits_in_buf = 0usize;
    let mut output = String::new();

    for &byte in data {
        buffer = (buffer << 8) | (byte as u64);
        bits_in_buf += 8;

        while bits_in_buf >= 5 {
            bits_in_buf -= 5;
            let idx = ((buffer >> bits_in_buf) & 0x1f) as usize;
            output.push(ALPHABET[idx] as char);
        }
    }

    if bits_in_buf > 0 {
        let idx = ((buffer << (5 - bits_in_buf)) & 0x1f) as usize;
        output.push(ALPHABET[idx] as char);
    }

    output
}
