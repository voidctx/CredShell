#[cfg(target_os = "windows")]
mod windows {
    #[link(name = "bcrypt")]
    extern "system" {
        fn BCryptOpenAlgorithmProvider(
            phAlgorithm: *mut usize,
            pszAlgId: *const u16,
            pszImplementation: *const u16,
            dwFlags: u32,
        ) -> i32;

        fn BCryptCloseAlgorithmProvider(hAlgorithm: usize, dwFlags: u32) -> i32;

        fn BCryptGenerateKeyPair(
            hAlgorithm: usize,
            phKey: *mut usize,
            dwLength: u32,
            dwFlags: u32,
        ) -> i32;

        fn BCryptFinalizeKeyPair(hKey: usize, dwFlags: u32) -> i32;

        fn BCryptDestroyKey(hKey: usize) -> i32;

        fn BCryptExportKey(
            hKey: usize,
            hExportKey: usize,
            pszBlobType: *const u16,
            pbOutput: *mut u8,
            cbOutput: u32,
            pcbResult: *mut u32,
            dwFlags: u32,
        ) -> i32;

        fn BCryptImportKeyPair(
            hAlgorithm: usize,
            hImportKey: usize,
            pszBlobType: *const u16,
            phKey: *mut usize,
            pbInput: *const u8,
            cbInput: u32,
            dwFlags: u32,
        ) -> i32;

        fn BCryptSignHash(
            hKey: usize,
            pPaddingInfo: *const u8,
            pbInput: *const u8,
            cbInput: u32,
            pbOutput: *mut u8,
            cbOutput: u32,
            pcbResult: *mut u32,
            dwFlags: u32,
        ) -> i32;

        fn BCryptVerifySignature(
            hKey: usize,
            pPaddingInfo: *const u8,
            pbHash: *const u8,
            cbHash: u32,
            pbSignature: *const u8,
            cbSignature: u32,
            dwFlags: u32,
        ) -> i32;
    }

    pub fn generate_p256_keypair() -> Result<(Vec<u8>, [u8; 32]), String> {
        let mut h_alg = 0usize;
        let alg_name: Vec<u16> = "ECDSA_P256\0".encode_utf16().collect();
        let status = unsafe {
            BCryptOpenAlgorithmProvider(&mut h_alg, alg_name.as_ptr(), std::ptr::null(), 0)
        };
        if status != 0 {
            return Err(format!("BCryptOpenAlgorithmProvider failed: 0x{:x}", status));
        }

        let mut h_key = 0usize;
        let status = unsafe { BCryptGenerateKeyPair(h_alg, &mut h_key, 256, 0) };
        if status != 0 {
            unsafe { BCryptCloseAlgorithmProvider(h_alg, 0); }
            return Err(format!("BCryptGenerateKeyPair failed: 0x{:x}", status));
        }

        let status = unsafe { BCryptFinalizeKeyPair(h_key, 0) };
        if status != 0 {
            unsafe {
                BCryptDestroyKey(h_key);
                BCryptCloseAlgorithmProvider(h_alg, 0);
            }
            return Err(format!("BCryptFinalizeKeyPair failed: 0x{:x}", status));
        }

        let priv_blob_type: Vec<u16> = "ECCPRIVATEBLOB\0".encode_utf16().collect();
        let mut priv_len = 0u32;
        unsafe {
            BCryptExportKey(h_key, 0, priv_blob_type.as_ptr(), std::ptr::null_mut(), 0, &mut priv_len, 0);
        }

        let mut priv_blob = vec![0u8; priv_len as usize];
        let status = unsafe {
            BCryptExportKey(h_key, 0, priv_blob_type.as_ptr(), priv_blob.as_mut_ptr(), priv_len, &mut priv_len, 0)
        };

        unsafe {
            BCryptDestroyKey(h_key);
            BCryptCloseAlgorithmProvider(h_alg, 0);
        }

        if status != 0 || priv_blob.len() < 104 {
            return Err(format!("BCryptExportKey failed: 0x{:x}", status));
        }
        let mut pub_key = Vec::with_capacity(64);
        pub_key.extend_from_slice(&priv_blob[8..72]);

        let mut priv_scalar = [0u8; 32];
        priv_scalar.copy_from_slice(&priv_blob[72..104]);

        Ok((pub_key, priv_scalar))
    }

    pub fn sign_p256(
        priv_scalar: &[u8; 32],
        pub_key: &[u8],
        hash: &[u8; 32],
    ) -> Result<[u8; 64], String> {
        let mut h_alg = 0usize;
        let alg_name: Vec<u16> = "ECDSA_P256\0".encode_utf16().collect();
        let status = unsafe {
            BCryptOpenAlgorithmProvider(&mut h_alg, alg_name.as_ptr(), std::ptr::null(), 0)
        };
        if status != 0 {
            return Err(format!("BCryptOpenAlgorithmProvider failed: 0x{:x}", status));
        }

        let mut reimport_blob = Vec::with_capacity(104);
        reimport_blob.extend_from_slice(&0x32534345u32.to_le_bytes());
        reimport_blob.extend_from_slice(&32u32.to_le_bytes());
        if pub_key.len() >= 64 {
            reimport_blob.extend_from_slice(&pub_key[0..64]);
        } else {
            reimport_blob.extend_from_slice(&[0u8; 64]);
        }
        reimport_blob.extend_from_slice(priv_scalar);

        let priv_blob_type: Vec<u16> = "ECCPRIVATEBLOB\0".encode_utf16().collect();
        let mut h_key = 0usize;
        let status = unsafe {
            BCryptImportKeyPair(
                h_alg,
                0,
                priv_blob_type.as_ptr(),
                &mut h_key,
                reimport_blob.as_ptr(),
                reimport_blob.len() as u32,
                0,
            )
        };

        if status != 0 {
            unsafe { BCryptCloseAlgorithmProvider(h_alg, 0); }
            return Err(format!("BCryptImportKeyPair failed: 0x{:x}", status));
        }

        let mut sig = [0u8; 64];
        let mut sig_len = 64u32;
        let status = unsafe {
            BCryptSignHash(
                h_key,
                std::ptr::null(),
                hash.as_ptr(),
                32,
                sig.as_mut_ptr(),
                64,
                &mut sig_len,
                0,
            )
        };

        unsafe {
            BCryptDestroyKey(h_key);
            BCryptCloseAlgorithmProvider(h_alg, 0);
        }

        if status != 0 {
            return Err(format!("BCryptSignHash failed: 0x{:x}", status));
        }

        Ok(sig)
    }

    pub fn verify_p256(pub_key: &[u8], hash: &[u8; 32], sig: &[u8; 64]) -> bool {
        if pub_key.len() < 64 {
            return false;
        }

        let mut h_alg = 0usize;
        let alg_name: Vec<u16> = "ECDSA_P256\0".encode_utf16().collect();
        let status = unsafe {
            BCryptOpenAlgorithmProvider(&mut h_alg, alg_name.as_ptr(), std::ptr::null(), 0)
        };
        if status != 0 {
            return false;
        }

        let mut pub_blob = Vec::with_capacity(72);
        pub_blob.extend_from_slice(&0x31534345u32.to_le_bytes());
        pub_blob.extend_from_slice(&32u32.to_le_bytes());
        pub_blob.extend_from_slice(&pub_key[0..64]);

        let pub_blob_type: Vec<u16> = "ECCPUBLICBLOB\0".encode_utf16().collect();
        let mut h_key = 0usize;
        let status = unsafe {
            BCryptImportKeyPair(
                h_alg,
                0,
                pub_blob_type.as_ptr(),
                &mut h_key,
                pub_blob.as_ptr(),
                pub_blob.len() as u32,
                0,
            )
        };

        if status != 0 {
            unsafe { BCryptCloseAlgorithmProvider(h_alg, 0); }
            return false;
        }

        let status = unsafe {
            BCryptVerifySignature(
                h_key,
                std::ptr::null(),
                hash.as_ptr(),
                32,
                sig.as_ptr(),
                64,
                0,
            )
        };

        unsafe {
            BCryptDestroyKey(h_key);
            BCryptCloseAlgorithmProvider(h_alg, 0);
        }

        status == 0
    }
}

pub mod pure_p256 {
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub struct U256(pub [u64; 4]);

    impl U256 {
        pub const ZERO: Self = U256([0, 0, 0, 0]);
        pub const ONE: Self = U256([1, 0, 0, 0]);

        pub const P: Self = U256([
            0xFFFFFFFFFFFFFFFF,
            0x00000000FFFFFFFF,
            0x0000000000000000,
            0xFFFFFFFF00000001,
        ]);

        pub const N: Self = U256([
            0xF3B9CAC2FC632551,
            0xBCE6FAADA7179E84,
            0xFFFFFFFFFFFFFFFF,
            0xFFFFFFFF00000000,
        ]);

        pub const B: Self = U256([
            0x3BCE3C3E27D2604B,
            0x651D06B0CC53B0F6,
            0xB3EBBD55769886BC,
            0x5AC635D8AA3A93E7,
        ]);

        pub const G_X: Self = U256([
            0xF4A13945D898C296,
            0x77037D812DEB33A0,
            0xF8BCE6E563A440F2,
            0x6B17D1F2E12C4247,
        ]);

        pub const G_Y: Self = U256([
            0xCBB6406837BF51F5,
            0x2BCE33576B315ECE,
            0x8EE7EB4A7C0F9E16,
            0x4FE342E2FE1A7F9B,
        ]);

        pub fn from_be_bytes(bytes: &[u8; 32]) -> Self {
            let mut limbs = [0u64; 4];
            limbs[3] = u64::from_be_bytes(bytes[0..8].try_into().unwrap());
            limbs[2] = u64::from_be_bytes(bytes[8..16].try_into().unwrap());
            limbs[1] = u64::from_be_bytes(bytes[16..24].try_into().unwrap());
            limbs[0] = u64::from_be_bytes(bytes[24..32].try_into().unwrap());
            Self(limbs)
        }

        pub fn to_be_bytes(&self) -> [u8; 32] {
            let mut out = [0u8; 32];
            out[0..8].copy_from_slice(&self.0[3].to_be_bytes());
            out[8..16].copy_from_slice(&self.0[2].to_be_bytes());
            out[16..24].copy_from_slice(&self.0[1].to_be_bytes());
            out[24..32].copy_from_slice(&self.0[0].to_be_bytes());
            out
        }

        pub fn is_zero(&self) -> bool {
            self.0 == [0, 0, 0, 0]
        }

        pub fn cmp(&self, rhs: &Self) -> core::cmp::Ordering {
            for i in (0..4).rev() {
                if self.0[i] < rhs.0[i] {
                    return core::cmp::Ordering::Less;
                } else if self.0[i] > rhs.0[i] {
                    return core::cmp::Ordering::Greater;
                }
            }
            core::cmp::Ordering::Equal
        }

        pub fn add(&self, rhs: &Self) -> (Self, u64) {
            let mut out = [0u64; 4];
            let mut carry = 0u128;
            for i in 0..4 {
                let sum = (self.0[i] as u128) + (rhs.0[i] as u128) + carry;
                out[i] = sum as u64;
                carry = sum >> 64;
            }
            (Self(out), carry as u64)
        }

        pub fn sub(&self, rhs: &Self) -> (Self, u64) {
            let mut out = [0u64; 4];
            let mut borrow = 0i128;
            for i in 0..4 {
                let diff = (self.0[i] as i128) - (rhs.0[i] as i128) - borrow;
                if diff < 0 {
                    out[i] = (diff + (1i128 << 64)) as u64;
                    borrow = 1;
                } else {
                    out[i] = diff as u64;
                    borrow = 0;
                }
            }
            (Self(out), borrow as u64)
        }

        pub fn add_mod(&self, rhs: &Self, m: &Self) -> Self {
            let (sum, carry) = self.add(rhs);
            if carry != 0 || sum.cmp(m) != core::cmp::Ordering::Less {
                sum.sub(m).0
            } else {
                sum
            }
        }

        pub fn sub_mod(&self, rhs: &Self, m: &Self) -> Self {
            if self.cmp(rhs) == core::cmp::Ordering::Less {
                let (adj, _) = self.add(m);
                adj.sub(rhs).0
            } else {
                self.sub(rhs).0
            }
        }

        pub fn mul_wide(&self, rhs: &Self) -> [u64; 8] {
            let mut res = [0u64; 8];
            for i in 0..4 {
                let mut carry = 0u128;
                for j in 0..4 {
                    let prod = (self.0[i] as u128) * (rhs.0[j] as u128) + (res[i + j] as u128) + carry;
                    res[i + j] = prod as u64;
                    carry = prod >> 64;
                }
                res[i + 4] = carry as u64;
            }
            res
        }

        pub fn mod_reduce(wide: &[u64; 8], m: &Self) -> Self {
            let mut rem = [0u64; 5];
            for i in (0..512).rev() {
                let limb_idx = i / 64;
                let bit_idx = i % 64;
                let bit = (wide[limb_idx] >> bit_idx) & 1;

                let mut carry = bit;
                for k in 0..5 {
                    let next_carry = (rem[k] >> 63) & 1;
                    rem[k] = (rem[k] << 1) | carry;
                    carry = next_carry;
                }

                while rem[4] > 0 || Self::cmp_5_4(&rem, &m.0) != core::cmp::Ordering::Less {
                    Self::sub_5_4(&mut rem, &m.0);
                }
            }
            Self([rem[0], rem[1], rem[2], rem[3]])
        }

        fn cmp_5_4(a: &[u64; 5], b: &[u64; 4]) -> core::cmp::Ordering {
            if a[4] > 0 {
                return core::cmp::Ordering::Greater;
            }
            for i in (0..4).rev() {
                if a[i] < b[i] {
                    return core::cmp::Ordering::Less;
                } else if a[i] > b[i] {
                    return core::cmp::Ordering::Greater;
                }
            }
            core::cmp::Ordering::Equal
        }

        fn sub_5_4(a: &mut [u64; 5], b: &[u64; 4]) {
            let mut borrow = 0i128;
            for k in 0..4 {
                let diff = (a[k] as i128) - (b[k] as i128) - borrow;
                if diff < 0 {
                    a[k] = (diff + (1i128 << 64)) as u64;
                    borrow = 1;
                } else {
                    a[k] = diff as u64;
                    borrow = 0;
                }
            }
            a[4] = (a[4] as i128 - borrow) as u64;
        }

        pub fn mul_mod(&self, rhs: &Self, m: &Self) -> Self {
            let wide = self.mul_wide(rhs);
            Self::mod_reduce(&wide, m)
        }

        pub fn pow_mod(&self, exp: &Self, m: &Self) -> Self {
            let mut res = Self::ONE;
            let mut base = *self;
            for i in 0..256 {
                let limb = i / 64;
                let bit = (exp.0[limb] >> (i % 64)) & 1;
                if bit == 1 {
                    res = res.mul_mod(&base, m);
                }
                base = base.mul_mod(&base, m);
            }
            res
        }

        pub fn inv_mod(&self, m: &Self) -> Self {
            let (two, _) = Self::from_be_bytes(&[
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
            ]).sub(&Self::ZERO);
            let exp = m.sub(&two).0;
            self.pow_mod(&exp, m)
        }

        pub fn shift_right_1(&self) -> Self {
            let mut out = [0u64; 4];
            out[0] = (self.0[0] >> 1) | ((self.0[1] & 1) << 63);
            out[1] = (self.0[1] >> 1) | ((self.0[2] & 1) << 63);
            out[2] = (self.0[2] >> 1) | ((self.0[3] & 1) << 63);
            out[3] = self.0[3] >> 1;
            Self(out)
        }
    }

    #[derive(Clone, Copy, Debug)]
    pub struct PointJacobian {
        pub x: U256,
        pub y: U256,
        pub z: U256,
    }

    impl PointJacobian {
        pub const INFINITY: Self = Self {
            x: U256::ZERO,
            y: U256::ONE,
            z: U256::ZERO,
        };

        pub fn from_affine(x: &U256, y: &U256) -> Self {
            Self {
                x: *x,
                y: *y,
                z: U256::ONE,
            }
        }

        pub fn to_affine(&self) -> Option<(U256, U256)> {
            if self.z.is_zero() {
                return None;
            }
            let z_inv = self.z.inv_mod(&U256::P);
            let z_inv2 = z_inv.mul_mod(&z_inv, &U256::P);
            let z_inv3 = z_inv2.mul_mod(&z_inv, &U256::P);
            let x = self.x.mul_mod(&z_inv2, &U256::P);
            let y = self.y.mul_mod(&z_inv3, &U256::P);
            Some((x, y))
        }

        pub fn double(&self) -> Self {
            if self.z.is_zero() || self.y.is_zero() {
                return Self::INFINITY;
            }
            let p = &U256::P;
            let delta = self.z.mul_mod(&self.z, p);
            let gamma = self.y.mul_mod(&self.y, p);
            let beta = self.x.mul_mod(&gamma, p);

            let t1 = self.x.sub_mod(&delta, p);
            let t2 = self.x.add_mod(&delta, p);
            let t3 = t1.mul_mod(&t2, p);
            let alpha = t3.add_mod(&t3, p).add_mod(&t3, p);

            let alpha2 = alpha.mul_mod(&alpha, p);
            let beta2 = beta.add_mod(&beta, p);
            let beta4 = beta2.add_mod(&beta2, p);
            let beta8 = beta4.add_mod(&beta4, p);
            let x3 = alpha2.sub_mod(&beta8, p);

            let yz = self.y.mul_mod(&self.z, p);
            let z3 = yz.add_mod(&yz, p);

            let gamma2 = gamma.mul_mod(&gamma, p);
            let gamma_x2 = gamma2.add_mod(&gamma2, p);
            let gamma_x4 = gamma_x2.add_mod(&gamma_x2, p);
            let gamma_x8 = gamma_x4.add_mod(&gamma_x4, p);

            let y3 = alpha.mul_mod(&beta4.sub_mod(&x3, p), p).sub_mod(&gamma_x8, p);

            Self { x: x3, y: y3, z: z3 }
        }

        pub fn add(&self, rhs: &Self) -> Self {
            if self.z.is_zero() {
                return *rhs;
            }
            if rhs.z.is_zero() {
                return *self;
            }
            let p = &U256::P;
            let z1_2 = self.z.mul_mod(&self.z, p);
            let z2_2 = rhs.z.mul_mod(&rhs.z, p);
            let u1 = self.x.mul_mod(&z2_2, p);
            let u2 = rhs.x.mul_mod(&z1_2, p);

            let s1 = self.y.mul_mod(&rhs.z.mul_mod(&z2_2, p), p);
            let s2 = rhs.y.mul_mod(&self.z.mul_mod(&z1_2, p), p);

            if u1 == u2 {
                if s1 == s2 {
                    return self.double();
                } else {
                    return Self::INFINITY;
                }
            }

            let h = u2.sub_mod(&u1, p);
            let r = s2.sub_mod(&s1, p);
            let h2 = h.mul_mod(&h, p);
            let h3 = h2.mul_mod(&h, p);
            let v = u1.mul_mod(&h2, p);

            let r2 = r.mul_mod(&r, p);
            let v2 = v.add_mod(&v, p);
            let x3 = r2.sub_mod(&h3, p).sub_mod(&v2, p);

            let y3 = r.mul_mod(&v.sub_mod(&x3, p), p).sub_mod(&s1.mul_mod(&h3, p), p);
            let z3 = self.z.mul_mod(&rhs.z, p).mul_mod(&h, p);

            Self { x: x3, y: y3, z: z3 }
        }

        pub fn ct_select(a: &Self, b: &Self, choice: u64) -> Self {
            let mask = 0u64.wrapping_sub(choice & 1);
            let select_u256 = |u1: &U256, u2: &U256| -> U256 {
                let mut out = [0u64; 4];
                for i in 0..4 {
                    out[i] = (u1.0[i] & !mask) | (u2.0[i] & mask);
                }
                U256(out)
            };
            Self {
                x: select_u256(&a.x, &b.x),
                y: select_u256(&a.y, &b.y),
                z: select_u256(&a.z, &b.z),
            }
        }

        pub fn scalar_mul(&self, k: &U256) -> Self {
            let mut r = Self::INFINITY;
            let mut base = *self;
            for i in 0..256 {
                let limb = i / 64;
                let bit = (k.0[limb] >> (i % 64)) & 1;
                let sum = r.add(&base);
                r = Self::ct_select(&r, &sum, bit);
                base = base.double();
            }
            r
        }
    }

    pub fn generate_p256_keypair() -> Result<(Vec<u8>, [u8; 32]), String> {
        let mut d_bytes = [0u8; 32];
        loop {
            crate::core::crypto::rng::random_bytes(&mut d_bytes)?;
            let d = U256::from_be_bytes(&d_bytes);
            if !d.is_zero() && d.cmp(&U256::N) == core::cmp::Ordering::Less {
                break;
            }
        }

        let d = U256::from_be_bytes(&d_bytes);
        let g = PointJacobian::from_affine(&U256::G_X, &U256::G_Y);
        let q = g
            .scalar_mul(&d)
            .to_affine()
            .ok_or_else(|| "Failed to compute public key".to_string())?;

        let x_bytes = q.0.to_be_bytes();
        let y_bytes = q.1.to_be_bytes();
        let mut pub_key = Vec::with_capacity(64);
        pub_key.extend_from_slice(&x_bytes);
        pub_key.extend_from_slice(&y_bytes);
        Ok((pub_key, d_bytes))
    }

    pub fn sign_p256(
        priv_scalar: &[u8; 32],
        _pub_key: &[u8],
        hash: &[u8; 32],
    ) -> Result<[u8; 64], String> {
        let d = U256::from_be_bytes(priv_scalar);
        if d.is_zero() || d.cmp(&U256::N) != core::cmp::Ordering::Less {
            return Err("Invalid private key".to_string());
        }
        let z = U256::from_be_bytes(hash);
        let g = PointJacobian::from_affine(&U256::G_X, &U256::G_Y);

        let mut sig_out = [0u8; 64];
        let mut k_bytes = [0u8; 32];
        loop {
            crate::core::crypto::rng::random_bytes(&mut k_bytes)?;
            let k = U256::from_be_bytes(&k_bytes);
            if k.is_zero() || k.cmp(&U256::N) != core::cmp::Ordering::Less {
                continue;
            }

            let k_pt = match g.scalar_mul(&k).to_affine() {
                Some(pt) => pt,
                None => continue,
            };

            let r = k_pt.0.sub_mod(&U256::ZERO, &U256::N);
            if r.is_zero() {
                continue;
            }

            let k_inv = k.inv_mod(&U256::N);
            let rd = r.mul_mod(&d, &U256::N);
            let z_plus_rd = z.add_mod(&rd, &U256::N);
            let mut s = k_inv.mul_mod(&z_plus_rd, &U256::N);
            if s.is_zero() {
                continue;
            }

            let half_n = U256::N.shift_right_1();
            if s.cmp(&half_n) == core::cmp::Ordering::Greater {
                s = U256::N.sub(&s).0;
            }

            let r_bytes = r.to_be_bytes();
            let s_bytes = s.to_be_bytes();
            sig_out[0..32].copy_from_slice(&r_bytes);
            sig_out[32..64].copy_from_slice(&s_bytes);
            break;
        }
        Ok(sig_out)
    }

    pub fn verify_p256(pub_key: &[u8], hash: &[u8; 32], sig: &[u8; 64]) -> bool {
        let (qx, qy) = if pub_key.len() == 65 && pub_key[0] == 0x04 {
            let x: [u8; 32] = match pub_key[1..33].try_into() {
                Ok(b) => b,
                Err(_) => return false,
            };
            let y: [u8; 32] = match pub_key[33..65].try_into() {
                Ok(b) => b,
                Err(_) => return false,
            };
            (U256::from_be_bytes(&x), U256::from_be_bytes(&y))
        } else if pub_key.len() == 64 {
            let x: [u8; 32] = match pub_key[0..32].try_into() {
                Ok(b) => b,
                Err(_) => return false,
            };
            let y: [u8; 32] = match pub_key[32..64].try_into() {
                Ok(b) => b,
                Err(_) => return false,
            };
            (U256::from_be_bytes(&x), U256::from_be_bytes(&y))
        } else {
            return false;
        };

        let p = &U256::P;
        if qx.cmp(p) != core::cmp::Ordering::Less || qy.cmp(p) != core::cmp::Ordering::Less {
            return false;
        }
        let y2 = qy.mul_mod(&qy, p);
        let x2 = qx.mul_mod(&qx, p);
        let x3 = x2.mul_mod(&qx, p);
        let three_x = qx.add_mod(&qx, p).add_mod(&qx, p);
        let right = x3.sub_mod(&three_x, p).add_mod(&U256::B, p);
        if y2 != right {
            return false;
        }

        let r_bytes: [u8; 32] = match sig[0..32].try_into() {
            Ok(b) => b,
            Err(_) => return false,
        };
        let s_bytes: [u8; 32] = match sig[32..64].try_into() {
            Ok(b) => b,
            Err(_) => return false,
        };
        let r = U256::from_be_bytes(&r_bytes);
        let s = U256::from_be_bytes(&s_bytes);

        if r.is_zero() || r.cmp(&U256::N) != core::cmp::Ordering::Less {
            return false;
        }
        if s.is_zero() || s.cmp(&U256::N) != core::cmp::Ordering::Less {
            return false;
        }

        let z = U256::from_be_bytes(hash);
        let w = s.inv_mod(&U256::N);
        let u1 = z.mul_mod(&w, &U256::N);
        let u2 = r.mul_mod(&w, &U256::N);

        let g = PointJacobian::from_affine(&U256::G_X, &U256::G_Y);
        let q = PointJacobian::from_affine(&qx, &qy);

        let p1 = g.scalar_mul(&u1);
        let p2 = q.scalar_mul(&u2);
        let pt = match p1.add(&p2).to_affine() {
            Some(pt) => pt,
            None => return false,
        };

        let v = pt.0.sub_mod(&U256::ZERO, &U256::N);
        v == r
    }
}

#[cfg(target_os = "windows")]
pub use windows::{generate_p256_keypair, sign_p256, verify_p256};

#[cfg(not(target_os = "windows"))]
pub use pure_p256::{generate_p256_keypair, sign_p256, verify_p256};
