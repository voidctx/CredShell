use super::hmac::hmac_sha512;
use super::zeroize::zeroize;

pub fn pbkdf2_hmac_sha512(
    passphrase: &[u8],
    salt: &[u8],
    iterations: u32,
    output: &mut [u8],
) {
    if iterations == 0 || output.is_empty() {
        return;
    }

    const HASH_LEN: usize = 64;
    let mut block_idx: u32 = 1;
    let mut out_offset = 0;

    let mut salt_with_idx = Vec::with_capacity(salt.len() + 4);
    salt_with_idx.extend_from_slice(salt);
    salt_with_idx.extend_from_slice(&[0, 0, 0, 0]);

    while out_offset < output.len() {
        let idx_bytes = block_idx.to_be_bytes();
        let salt_len = salt.len();
        salt_with_idx[salt_len..salt_len + 4].copy_from_slice(&idx_bytes);

        let mut u = hmac_sha512(passphrase, &salt_with_idx);
        let mut t = u;

        for _ in 1..iterations {
            u = hmac_sha512(passphrase, &u);
            for k in 0..HASH_LEN {
                t[k] ^= u[k];
            }
        }

        let to_copy = (output.len() - out_offset).min(HASH_LEN);
        output[out_offset..out_offset + to_copy].copy_from_slice(&t[..to_copy]);
        out_offset += to_copy;
        block_idx += 1;

        zeroize(&mut u);
        zeroize(&mut t);
    }

    zeroize(&mut salt_with_idx);
}

pub fn derive_key_32(passphrase: &[u8], salt: &[u8], iterations: u32) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2_hmac_sha512(passphrase, salt, iterations, &mut key);
    key
}
