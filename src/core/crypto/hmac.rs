use super::sha1::{sha1, Sha1};
use super::sha256::{sha256, Sha256};
use super::sha512::{sha512, Sha512};
use super::zeroize::zeroize;

pub fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64] {
    const BLOCK_SIZE: usize = 128;
    let mut k = [0u8; BLOCK_SIZE];

    if key.len() > BLOCK_SIZE {
        let digest = sha512(key);
        k[..64].copy_from_slice(&digest);
    } else {
        k[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0u8; BLOCK_SIZE];
    let mut opad = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5c;
    }

    let mut inner_hasher = Sha512::new();
    inner_hasher.update(&ipad);
    inner_hasher.update(data);
    let inner_hash = inner_hasher.finalize();

    let mut outer_hasher = Sha512::new();
    outer_hasher.update(&opad);
    outer_hasher.update(&inner_hash);
    let out = outer_hasher.finalize();

    zeroize(&mut k);
    zeroize(&mut ipad);
    zeroize(&mut opad);
    out
}

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    const BLOCK_SIZE: usize = 64;
    let mut k = [0u8; BLOCK_SIZE];

    if key.len() > BLOCK_SIZE {
        let digest = sha256(key);
        k[..32].copy_from_slice(&digest);
    } else {
        k[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0u8; BLOCK_SIZE];
    let mut opad = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5c;
    }

    let mut inner_hasher = Sha256::new();
    inner_hasher.update(&ipad);
    inner_hasher.update(data);
    let inner_hash = inner_hasher.finalize();

    let mut outer_hasher = Sha256::new();
    outer_hasher.update(&opad);
    outer_hasher.update(&inner_hash);
    let out = outer_hasher.finalize();

    zeroize(&mut k);
    zeroize(&mut ipad);
    zeroize(&mut opad);
    out
}

pub fn hmac_sha1(key: &[u8], data: &[u8]) -> [u8; 20] {
    const BLOCK_SIZE: usize = 64;
    let mut k = [0u8; BLOCK_SIZE];

    if key.len() > BLOCK_SIZE {
        let digest = sha1(key);
        k[..20].copy_from_slice(&digest);
    } else {
        k[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0u8; BLOCK_SIZE];
    let mut opad = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5c;
    }

    let mut inner_hasher = Sha1::new();
    inner_hasher.update(&ipad);
    inner_hasher.update(data);
    let inner_hash = inner_hasher.finalize();

    let mut outer_hasher = Sha1::new();
    outer_hasher.update(&opad);
    outer_hasher.update(&inner_hash);
    let out = outer_hasher.finalize();

    zeroize(&mut k);
    zeroize(&mut ipad);
    zeroize(&mut opad);
    out
}
