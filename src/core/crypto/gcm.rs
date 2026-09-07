use super::aes::Aes256;
use super::zeroize::{subtle_eq, zeroize};

struct GhashTable {
    table: [[u8; 16]; 16],
}

impl GhashTable {
    fn new(h: &[u8; 16]) -> Self {
        let mut table = [[0u8; 16]; 16];
        table[8] = *h;

        for i in (1..8).rev() {
            table[i] = ghash_mul_x(&table[i * 2]);
        }
        for i in 2..16 {
            if i & (i - 1) != 0 {
                let mut sum = [0u8; 16];
                for bit in 0..4 {
                    if (i >> (3 - bit)) & 1 == 1 {
                        let p = 1 << (3 - bit);
                        for k in 0..16 {
                            sum[k] ^= table[p][k];
                        }
                    }
                }
                table[i] = sum;
            }
        }

        Self { table }
    }

    #[inline(always)]
    fn ct_select_row(&self, idx: usize) -> [u8; 16] {
        let mut row = [0u8; 16];
        for i in 0..16 {
            let mask = ((i == idx) as u8).wrapping_neg();
            for k in 0..16 {
                row[k] |= self.table[i][k] & mask;
            }
        }
        row
    }

    fn mul(&self, x: &mut [u8; 16]) {
        let mut z = [0u8; 16];
        for i in 0..16 {
            let byte = x[i];
            let hi = (byte >> 4) as usize;
            let lo = (byte & 0x0f) as usize;

            let hi_row = self.ct_select_row(hi);
            for k in 0..16 {
                z[k] ^= hi_row[k];
            }
            shift_right_4(&mut z);

            let lo_row = self.ct_select_row(lo);
            for k in 0..16 {
                z[k] ^= lo_row[k];
            }
            if i < 15 {
                shift_right_4(&mut z);
            }
        }
        *x = z;
    }
}

fn ghash_mul_x(v: &[u8; 16]) -> [u8; 16] {
    let mut out = *v;
    let lsb = out[15] & 1;
    let mut carry = 0u8;
    for k in 0..16 {
        let next_carry = out[k] & 1;
        out[k] = (out[k] >> 1) | (carry << 7);
        carry = next_carry;
    }
    if lsb != 0 {
        out[0] ^= 0xe1;
    }
    out
}

#[inline(always)]
fn shift_right_4(z: &mut [u8; 16]) {
    for _ in 0..4 {
        let lsb = z[15] & 1;
        let mut carry = 0u8;
        for k in 0..16 {
            let next_carry = z[k] & 1;
            z[k] = (z[k] >> 1) | (carry << 7);
            carry = next_carry;
        }
        if lsb != 0 {
            z[0] ^= 0xe1;
        }
    }
}

pub struct Aes256Gcm {
    cipher: Aes256,
    h_table: GhashTable,
    h: [u8; 16],
}

impl Aes256Gcm {
    pub fn new(key: &[u8; 32]) -> Self {
        let cipher = Aes256::new(key);
        let mut h = [0u8; 16];
        cipher.encrypt_block(&mut h);
        let h_table = GhashTable::new(&h);
        Self { cipher, h_table, h }
    }

    fn ghash(&self, aad: &[u8], ciphertext: &[u8]) -> [u8; 16] {
        let mut y = [0u8; 16];
        let mut chunks = aad.chunks_exact(16);
        for chunk in &mut chunks {
            for k in 0..16 {
                y[k] ^= chunk[k];
            }
            self.h_table.mul(&mut y);
        }
        let rem_aad = chunks.remainder();
        if !rem_aad.is_empty() {
            for (k, b) in rem_aad.iter().enumerate() {
                y[k] ^= *b;
            }
            self.h_table.mul(&mut y);
        }
        let mut c_chunks = ciphertext.chunks_exact(16);
        for chunk in &mut c_chunks {
            for k in 0..16 {
                y[k] ^= chunk[k];
            }
            self.h_table.mul(&mut y);
        }
        let rem_c = c_chunks.remainder();
        if !rem_c.is_empty() {
            for (k, b) in rem_c.iter().enumerate() {
                y[k] ^= *b;
            }
            self.h_table.mul(&mut y);
        }

        let mut len_block = [0u8; 16];
        let aad_bits = (aad.len() as u64) * 8;
        let c_bits = (ciphertext.len() as u64) * 8;
        len_block[..8].copy_from_slice(&aad_bits.to_be_bytes());
        len_block[8..16].copy_from_slice(&c_bits.to_be_bytes());

        for k in 0..16 {
            y[k] ^= len_block[k];
        }
        self.h_table.mul(&mut y);

        y
    }
    #[inline(always)]
    fn get_j0(iv: &[u8; 12]) -> [u8; 16] {
        let mut j0 = [0u8; 16];
        j0[..12].copy_from_slice(iv);
        j0[15] = 1;
        j0
    }

    pub fn encrypt(&self, iv: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> (Vec<u8>, [u8; 16]) {
        let j0 = Self::get_j0(iv);

        let mut ej0 = j0;
        self.cipher.encrypt_block(&mut ej0);

        let mut counter = j0;
        let mut ctr_val = 1u32;

        let mut ciphertext = vec![0u8; plaintext.len()];
        let mut p_chunks = plaintext.chunks_exact(16);
        let mut c_chunks = ciphertext.chunks_exact_mut(16);

        for (p, c) in p_chunks.by_ref().zip(c_chunks.by_ref()) {
            ctr_val = ctr_val.wrapping_add(1);
            counter[12..16].copy_from_slice(&ctr_val.to_be_bytes());

            let mut mask = counter;
            self.cipher.encrypt_block(&mut mask);
            for k in 0..16 {
                c[k] = p[k] ^ mask[k];
            }
        }

        let p_rem = p_chunks.remainder();
        if !p_rem.is_empty() {
            ctr_val = ctr_val.wrapping_add(1);
            counter[12..16].copy_from_slice(&ctr_val.to_be_bytes());

            let mut mask = counter;
            self.cipher.encrypt_block(&mut mask);
            let c_rem = c_chunks.into_remainder();
            for (k, b) in p_rem.iter().enumerate() {
                c_rem[k] = *b ^ mask[k];
            }
        }

        let s = self.ghash(aad, &ciphertext);

        let mut tag = [0u8; 16];
        for k in 0..16 {
            tag[k] = ej0[k] ^ s[k];
        }

        (ciphertext, tag)
    }

    pub fn decrypt(
        &self,
        iv: &[u8; 12],
        aad: &[u8],
        ciphertext: &[u8],
        expected_tag: &[u8; 16],
    ) -> Result<Vec<u8>, String> {
        let j0 = Self::get_j0(iv);
        let mut ej0 = j0;
        self.cipher.encrypt_block(&mut ej0);

        let s = self.ghash(aad, ciphertext);

        let mut tag = [0u8; 16];
        for k in 0..16 {
            tag[k] = ej0[k] ^ s[k];
        }

        if !subtle_eq(&tag, expected_tag) {
            return Err("AES-256-GCM authentication failed: invalid tag".to_string());
        }

        let mut counter = j0;
        let mut ctr_val = 1u32;

        let mut plaintext = vec![0u8; ciphertext.len()];
        let mut c_chunks = ciphertext.chunks_exact(16);
        let mut p_chunks = plaintext.chunks_exact_mut(16);

        for (c, p) in c_chunks.by_ref().zip(p_chunks.by_ref()) {
            ctr_val = ctr_val.wrapping_add(1);
            counter[12..16].copy_from_slice(&ctr_val.to_be_bytes());

            let mut mask = counter;
            self.cipher.encrypt_block(&mut mask);
            for k in 0..16 {
                p[k] = c[k] ^ mask[k];
            }
        }

        let c_rem = c_chunks.remainder();
        if !c_rem.is_empty() {
            ctr_val = ctr_val.wrapping_add(1);
            counter[12..16].copy_from_slice(&ctr_val.to_be_bytes());

            let mut mask = counter;
            self.cipher.encrypt_block(&mut mask);
            let p_rem = p_chunks.into_remainder();
            for (k, b) in c_rem.iter().enumerate() {
                p_rem[k] = *b ^ mask[k];
            }
        }

        Ok(plaintext)
    }
}

impl Drop for Aes256Gcm {
    fn drop(&mut self) {
        zeroize(&mut self.h);
        for row in self.h_table.table.iter_mut() {
            zeroize(row);
        }
    }
}
