#[derive(Clone, Debug, PartialEq)]
pub enum CborValue {
    Unsigned(u64),
    Negative(u64),
    ByteString(Vec<u8>),
    TextString(String),
    Array(Vec<CborValue>),
    Map(Vec<(CborValue, CborValue)>),
    Boolean(bool),
    Null,
}

impl CborValue {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.encode_into(&mut buf);
        buf
    }

    fn encode_header(major: u8, val: u64, buf: &mut Vec<u8>) {
        let major_bits = major << 5;
        if val < 24 {
            buf.push(major_bits | (val as u8));
        } else if val <= 0xff {
            buf.push(major_bits | 24);
            buf.push(val as u8);
        } else if val <= 0xffff {
            buf.push(major_bits | 25);
            buf.extend_from_slice(&(val as u16).to_be_bytes());
        } else if val <= 0xffffffff {
            buf.push(major_bits | 26);
            buf.extend_from_slice(&(val as u32).to_be_bytes());
        } else {
            buf.push(major_bits | 27);
            buf.extend_from_slice(&val.to_be_bytes());
        }
    }

    fn encode_into(&self, buf: &mut Vec<u8>) {
        match self {
            CborValue::Unsigned(n) => Self::encode_header(0, *n, buf),
            CborValue::Negative(n) => Self::encode_header(1, *n, buf),
            CborValue::ByteString(bytes) => {
                Self::encode_header(2, bytes.len() as u64, buf);
                buf.extend_from_slice(bytes);
            }
            CborValue::TextString(s) => {
                let bytes = s.as_bytes();
                Self::encode_header(3, bytes.len() as u64, buf);
                buf.extend_from_slice(bytes);
            }
            CborValue::Array(items) => {
                Self::encode_header(4, items.len() as u64, buf);
                for item in items {
                    item.encode_into(buf);
                }
            }
            CborValue::Map(entries) => {
                Self::encode_header(5, entries.len() as u64, buf);
                for (k, v) in entries {
                    k.encode_into(buf);
                    v.encode_into(buf);
                }
            }
            CborValue::Boolean(b) => {
                buf.push(if *b { 0xf5 } else { 0xf4 });
            }
            CborValue::Null => {
                buf.push(0xf6);
            }
        }
    }
}

pub fn encode_ed25519_cose_key(public_key: &[u8]) -> Vec<u8> {
    let map = CborValue::Map(vec![
        (CborValue::Unsigned(1), CborValue::Unsigned(1)),
        (CborValue::Unsigned(3), CborValue::Negative(7)),
        (CborValue::Negative(0), CborValue::Unsigned(6)),
        (
            CborValue::Negative(1),
            CborValue::ByteString(public_key.to_vec()),
        ),
    ]);
    map.encode()
}

pub fn encode_p256_cose_key(public_key_xy: &[u8]) -> Vec<u8> {
    let x = if public_key_xy.len() >= 32 {
        public_key_xy[0..32].to_vec()
    } else {
        vec![0u8; 32]
    };
    let y = if public_key_xy.len() >= 64 {
        public_key_xy[32..64].to_vec()
    } else {
        vec![0u8; 32]
    };

    let map = CborValue::Map(vec![
        (CborValue::Unsigned(1), CborValue::Unsigned(2)),
        (CborValue::Unsigned(3), CborValue::Negative(6)),
        (CborValue::Negative(0), CborValue::Unsigned(1)),
        (CborValue::Negative(1), CborValue::ByteString(x)),
        (CborValue::Negative(2), CborValue::ByteString(y)),
    ]);
    map.encode()
}
