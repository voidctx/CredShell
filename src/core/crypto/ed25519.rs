use super::sha512::sha512;
use super::zeroize::zeroize;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FieldElement(pub [u64; 5]);

const MASK_51: u64 = (1 << 51) - 1;

impl FieldElement {
    pub const ZERO: Self = FieldElement([0, 0, 0, 0, 0]);
    pub const ONE: Self = FieldElement([1, 0, 0, 0, 0]);

    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        let load64 = |idx: usize| -> u64 {
            let chunk: [u8; 8] = bytes[idx..idx + 8].try_into().unwrap();
            u64::from_le_bytes(chunk)
        };

        let mut limbs = [0u64; 5];
        limbs[0] = load64(0) & MASK_51;
        limbs[1] = (load64(6) >> 3) & MASK_51;
        limbs[2] = (load64(12) >> 6) & MASK_51;
        limbs[3] = (load64(19) >> 1) & MASK_51;
        limbs[4] = (load64(24) >> 12) & 0x7ffffffffffff;

        Self(limbs)
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        let mut t = *self;
        t.carry();
        t.carry();

        let mut q = (t.0[0] + 19) >> 51;
        q = (t.0[1] + q) >> 51;
        q = (t.0[2] + q) >> 51;
        q = (t.0[3] + q) >> 51;
        q = (t.0[4] + q) >> 51;

        t.0[0] += 19 * q;

        let c0 = t.0[0] >> 51;
        t.0[0] &= MASK_51;
        t.0[1] += c0;

        let c1 = t.0[1] >> 51;
        t.0[1] &= MASK_51;
        t.0[2] += c1;

        let c2 = t.0[2] >> 51;
        t.0[2] &= MASK_51;
        t.0[3] += c2;

        let c3 = t.0[3] >> 51;
        t.0[3] &= MASK_51;
        t.0[4] += c3;

        t.0[4] &= MASK_51;

        let mut out = [0u8; 32];
        let mut b = [0u64; 4];
        b[0] = t.0[0] | (t.0[1] << 51);
        b[1] = (t.0[1] >> 13) | (t.0[2] << 38);
        b[2] = (t.0[2] >> 26) | (t.0[3] << 25);
        b[3] = (t.0[3] >> 39) | (t.0[4] << 12);

        for (i, val) in b.iter().enumerate() {
            out[i * 8..(i + 1) * 8].copy_from_slice(&val.to_le_bytes());
        }
        out
    }

    pub fn carry(&mut self) {
        let c0 = self.0[0] >> 51;
        self.0[0] &= MASK_51;
        self.0[1] += c0;

        let c1 = self.0[1] >> 51;
        self.0[1] &= MASK_51;
        self.0[2] += c1;

        let c2 = self.0[2] >> 51;
        self.0[2] &= MASK_51;
        self.0[3] += c2;

        let c3 = self.0[3] >> 51;
        self.0[3] &= MASK_51;
        self.0[4] += c3;

        let c4 = self.0[4] >> 51;
        self.0[4] &= MASK_51;
        self.0[0] += c4 * 19;

        let c0 = self.0[0] >> 51;
        self.0[0] &= MASK_51;
        self.0[1] += c0;
    }

    pub fn add(&self, rhs: &Self) -> Self {
        let mut res = Self([
            self.0[0] + rhs.0[0],
            self.0[1] + rhs.0[1],
            self.0[2] + rhs.0[2],
            self.0[3] + rhs.0[3],
            self.0[4] + rhs.0[4],
        ]);
        res.carry();
        res
    }

    pub fn sub(&self, rhs: &Self) -> Self {
        const BIAS: [u64; 5] = [
            (1u64 << 53) - 76,
            (1u64 << 53) - 4,
            (1u64 << 53) - 4,
            (1u64 << 53) - 4,
            (1u64 << 53) - 4,
        ];
        let mut res = Self([
            (self.0[0] + BIAS[0]) - rhs.0[0],
            (self.0[1] + BIAS[1]) - rhs.0[1],
            (self.0[2] + BIAS[2]) - rhs.0[2],
            (self.0[3] + BIAS[3]) - rhs.0[3],
            (self.0[4] + BIAS[4]) - rhs.0[4],
        ]);
        res.carry();
        res
    }

    pub fn mul(&self, rhs: &Self) -> Self {
        let a = self.0;
        let b = rhs.0;

        let mut r = [0u128; 5];
        r[0] = (a[0] as u128) * (b[0] as u128)
            + 19 * ((a[1] as u128) * (b[4] as u128)
                + (a[2] as u128) * (b[3] as u128)
                + (a[3] as u128) * (b[2] as u128)
                + (a[4] as u128) * (b[1] as u128));

        r[1] = (a[0] as u128) * (b[1] as u128)
            + (a[1] as u128) * (b[0] as u128)
            + 19 * ((a[2] as u128) * (b[4] as u128)
                + (a[3] as u128) * (b[3] as u128)
                + (a[4] as u128) * (b[2] as u128));

        r[2] = (a[0] as u128) * (b[2] as u128)
            + (a[1] as u128) * (b[1] as u128)
            + (a[2] as u128) * (b[0] as u128)
            + 19 * ((a[3] as u128) * (b[4] as u128)
                + (a[4] as u128) * (b[3] as u128));

        r[3] = (a[0] as u128) * (b[3] as u128)
            + (a[1] as u128) * (b[2] as u128)
            + (a[2] as u128) * (b[1] as u128)
            + (a[3] as u128) * (b[0] as u128)
            + 19 * ((a[4] as u128) * (b[4] as u128));

        r[4] = (a[0] as u128) * (b[4] as u128)
            + (a[1] as u128) * (b[3] as u128)
            + (a[2] as u128) * (b[2] as u128)
            + (a[3] as u128) * (b[1] as u128)
            + (a[4] as u128) * (b[0] as u128);

        let c0 = (r[0] >> 51) as u64;
        let mut l0 = (r[0] as u64) & MASK_51;
        r[1] += c0 as u128;

        let c1 = (r[1] >> 51) as u64;
        let l1 = (r[1] as u64) & MASK_51;
        r[2] += c1 as u128;

        let c2 = (r[2] >> 51) as u64;
        let l2 = (r[2] as u64) & MASK_51;
        r[3] += c2 as u128;

        let c3 = (r[3] >> 51) as u64;
        let l3 = (r[3] as u64) & MASK_51;
        r[4] += c3 as u128;

        let c4 = (r[4] >> 51) as u64;
        let l4 = (r[4] as u64) & MASK_51;
        l0 += c4 * 19;

        let mut res = Self([l0, l1, l2, l3, l4]);
        res.carry();
        res
    }

    pub fn square(&self) -> Self {
        self.mul(self)
    }

    pub fn invert(&self) -> Self {
        let t0 = self.square();
        let t1 = t0.square().square();
        let t2 = self.mul(&t1);
        let t3 = t0.mul(&t2);
        let t4 = t3.square();
        let t5 = t2.mul(&t4);
        let mut t6 = t5;
        for _ in 0..5 {
            t6 = t6.square();
        }
        let t7 = t6.mul(&t5);
        let mut t8 = t7;
        for _ in 0..10 {
            t8 = t8.square();
        }
        let t9 = t8.mul(&t7);
        let mut t10 = t9;
        for _ in 0..20 {
            t10 = t10.square();
        }
        let t11 = t10.mul(&t9);
        let mut t12 = t11;
        for _ in 0..10 {
            t12 = t12.square();
        }
        let t13 = t12.mul(&t7);
        let mut t14 = t13;
        for _ in 0..50 {
            t14 = t14.square();
        }
        let t15 = t14.mul(&t13);
        let mut t16 = t15;
        for _ in 0..100 {
            t16 = t16.square();
        }
        let t17 = t16.mul(&t15);
        let mut t18 = t17;
        for _ in 0..50 {
            t18 = t18.square();
        }
        let t19 = t18.mul(&t13);
        let mut t20 = t19;
        for _ in 0..5 {
            t20 = t20.square();
        }
        t20.mul(&t3)
    }

    pub fn pow_p58(&self) -> Self {
        let t0 = self.square();
        let t1 = t0.square().square();
        let t2 = self.mul(&t1);
        let t3 = t0.mul(&t2);
        let t4 = t3.square();
        let t5 = t2.mul(&t4);
        let mut t6 = t5;
        for _ in 0..5 {
            t6 = t6.square();
        }
        let t7 = t6.mul(&t5);
        let mut t8 = t7;
        for _ in 0..10 {
            t8 = t8.square();
        }
        let t9 = t8.mul(&t7);
        let mut t10 = t9;
        for _ in 0..20 {
            t10 = t10.square();
        }
        let t11 = t10.mul(&t9);
        let mut t12 = t11;
        for _ in 0..10 {
            t12 = t12.square();
        }
        let t13 = t12.mul(&t7);
        let mut t14 = t13;
        for _ in 0..50 {
            t14 = t14.square();
        }
        let t15 = t14.mul(&t13);
        let mut t16 = t15;
        for _ in 0..100 {
            t16 = t16.square();
        }
        let t17 = t16.mul(&t15);
        let mut t18 = t17;
        for _ in 0..50 {
            t18 = t18.square();
        }
        let t19 = t18.mul(&t13);
        t19.square().square().mul(self)
    }

    pub fn ct_select(a: &Self, b: &Self, choice: u8) -> Self {
        let mask = 0u64.wrapping_sub(choice as u64);
        let mut r = [0u64; 5];
        for i in 0..5 {
            r[i] = a.0[i] ^ (mask & (a.0[i] ^ b.0[i]));
        }
        FieldElement(r)
    }

    pub fn cswap(swap: u8, a: &mut Self, b: &mut Self) {
        let mask = 0u64.wrapping_sub(swap as u64);
        for i in 0..5 {
            let dummy = mask & (a.0[i] ^ b.0[i]);
            a.0[i] ^= dummy;
            b.0[i] ^= dummy;
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EdwardsPoint {
    pub x: FieldElement,
    pub y: FieldElement,
    pub z: FieldElement,
    pub t: FieldElement,
}

const ED_D: FieldElement = FieldElement([
    0x00034dca135978a3,
    0x0001a8283b156ebd,
    0x0005e7a26001c029,
    0x000739c663a03cbb,
    0x00052036cee2b6ff,
]);

const BASE_X_BYTES: [u8; 32] = [
    0x1a, 0xd5, 0x25, 0x8f, 0x60, 0x2d, 0x56, 0xc9,
    0xb2, 0xa7, 0x25, 0x95, 0x60, 0xc7, 0x2c, 0x69,
    0x5c, 0xdc, 0xd6, 0xfd, 0x31, 0xe2, 0xa4, 0xc0,
    0xfe, 0x53, 0x6e, 0xcd, 0xd3, 0x36, 0x69, 0x21,
];

const BASE_Y_BYTES: [u8; 32] = [
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
];

impl EdwardsPoint {
    pub const IDENTITY: Self = Self {
        x: FieldElement::ZERO,
        y: FieldElement::ONE,
        z: FieldElement::ONE,
        t: FieldElement::ZERO,
    };

    pub fn base() -> Self {
        let x = FieldElement::from_bytes(&BASE_X_BYTES);
        let y = FieldElement::from_bytes(&BASE_Y_BYTES);
        Self {
            x,
            y,
            z: FieldElement::ONE,
            t: x.mul(&y),
        }
    }

    pub fn add(&self, rhs: &Self) -> Self {
        let a = self.y.sub(&self.x).mul(&rhs.y.sub(&rhs.x));
        let b = self.y.add(&self.x).mul(&rhs.y.add(&rhs.x));
        let c = self.t.mul(&rhs.t).mul(&ED_D).add(&self.t.mul(&rhs.t).mul(&ED_D));
        let d = self.z.mul(&rhs.z).add(&self.z.mul(&rhs.z));

        let e = b.sub(&a);
        let f = d.sub(&c);
        let g = d.add(&c);
        let h = b.add(&a);

        Self {
            x: e.mul(&f),
            y: g.mul(&h),
            z: f.mul(&g),
            t: e.mul(&h),
        }
    }

    pub fn double(&self) -> Self {
        self.add(self)
    }

    pub fn ct_select(a: &Self, b: &Self, choice: u8) -> Self {
        Self {
            x: FieldElement::ct_select(&a.x, &b.x, choice),
            y: FieldElement::ct_select(&a.y, &b.y, choice),
            z: FieldElement::ct_select(&a.z, &b.z, choice),
            t: FieldElement::ct_select(&a.t, &b.t, choice),
        }
    }

    pub fn scalar_mul(&self, scalar: &[u8; 32]) -> Self {
        let mut res = Self::IDENTITY;
        let mut cur = *self;

        for byte in scalar.iter() {
            for bit in 0..8 {
                let bit_val = ((byte >> bit) & 1) as u8;
                let added = res.add(&cur);
                res = Self::ct_select(&res, &added, bit_val);
                cur = cur.double();
            }
        }
        res
    }

    pub fn compress(&self) -> [u8; 32] {
        let z_inv = self.z.invert();
        let x = self.x.mul(&z_inv);
        let y = self.y.mul(&z_inv);

        let mut s = y.to_bytes();
        let x_bytes = x.to_bytes();
        s[31] |= (x_bytes[0] & 1) << 7;
        s
    }

    pub fn decompress(bytes: &[u8; 32]) -> Option<Self> {
        let sign_x = (bytes[31] >> 7) & 1;
        let mut y_bytes = *bytes;
        y_bytes[31] &= 0x7f;

        let y = FieldElement::from_bytes(&y_bytes);
        let y2 = y.square();
        let u = y2.sub(&FieldElement::ONE);
        let v = ED_D.mul(&y2).add(&FieldElement::ONE);

        let v_inv = v.invert();
        let x2 = u.mul(&v_inv);

        let x2_bytes = x2.to_bytes();
        let is_zero = x2_bytes.iter().all(|&b| b == 0);
        if is_zero {
            if sign_x == 1 {
                return None;
            }
            return Some(Self {
                x: FieldElement::ZERO,
                y,
                z: FieldElement::ONE,
                t: FieldElement::ZERO,
            });
        }

        let v3 = v.square().mul(&v);
        let v7 = v3.square().mul(&v);
        let uv7 = u.mul(&v7);
        let cand = u.mul(&v3).mul(&uv7.pow_p58());

        let cand2_v = cand.square().mul(&v);
        let sqrt_m1 = FieldElement::from_bytes(&SQRT_M1_BYTES);
        let cand2_v_b = cand2_v.to_bytes();
        let u_b = u.to_bytes();
        let neg_u_b = FieldElement::ZERO.sub(&u).to_bytes();
        let mut x = if cand2_v_b == u_b {
            cand
        } else if cand2_v_b == neg_u_b {
            cand.mul(&sqrt_m1)
        } else {
            return None;
        };

        let x_bytes = x.to_bytes();
        if (x_bytes[0] & 1) != sign_x {
            x = FieldElement::ZERO.sub(&x);
        }

        Some(Self {
            x,
            y,
            z: FieldElement::ONE,
            t: x.mul(&y),
        })
    }
}

const SQRT_M1_BYTES: [u8; 32] = [
    0xb0, 0xa0, 0x0e, 0x4a, 0x27, 0x1b, 0xee, 0xc4,
    0x78, 0xe4, 0x2f, 0xad, 0x06, 0x18, 0x43, 0x2f,
    0xa7, 0xd7, 0xfb, 0x3d, 0x99, 0x00, 0x4d, 0x2b,
    0x0b, 0xdf, 0xc1, 0x4f, 0x80, 0x24, 0x83, 0x2b,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BigInt10([u64; 10]);

impl BigInt10 {
    #[allow(dead_code)]
    fn zero() -> Self {
        BigInt10([0; 10])
    }

    fn from_bytes_le(b: &[u8]) -> Self {
        let mut limbs = [0u64; 10];
        for (i, chunk) in b.chunks(8).enumerate() {
            if i < 10 {
                let mut buf = [0u8; 8];
                buf[..chunk.len()].copy_from_slice(chunk);
                limbs[i] = u64::from_le_bytes(buf);
            }
        }
        Self(limbs)
    }

    fn to_bytes_32(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..4 {
            out[i * 8..(i + 1) * 8].copy_from_slice(&self.0[i].to_le_bytes());
        }
        out
    }

    fn shl1(&mut self) {
        let mut carry = 0u64;
        for limb in self.0.iter_mut() {
            let next_carry = *limb >> 63;
            *limb = (*limb << 1) | carry;
            carry = next_carry;
        }
    }

    fn gte(&self, other: &Self) -> bool {
        for i in (0..10).rev() {
            if self.0[i] > other.0[i] {
                return true;
            }
            if self.0[i] < other.0[i] {
                return false;
            }
        }
        true
    }

    fn sub(&mut self, other: &Self) {
        let mut borrow = 0u128;
        for i in 0..10 {
            let diff = (self.0[i] as u128).wrapping_sub(other.0[i] as u128).wrapping_sub(borrow);
            self.0[i] = diff as u64;
            borrow = if diff >> 64 != 0 { 1 } else { 0 };
        }
    }
}

fn scalar_mod_l(input: &[u8]) -> [u8; 32] {
    let mut a = BigInt10::from_bytes_le(input);
    let l = BigInt10([
        0x5812631a5cf5d3ed,
        0x14def9dea2f79cd6,
        0x0000000000000000,
        0x1000000000000000,
        0, 0, 0, 0, 0, 0,
    ]);

    let mut high_bit = 0usize;
    for i in (0..10).rev() {
        if a.0[i] != 0 {
            high_bit = i * 64 + (64 - a.0[i].leading_zeros() as usize);
            break;
        }
    }

    if high_bit < 253 {
        return a.to_bytes_32();
    }

    let shift = high_bit - 253;
    let mut shifted_l = l;
    for _ in 0..shift {
        shifted_l.shl1();
    }

    for _ in 0..=shift {
        if a.gte(&shifted_l) {
            a.sub(&shifted_l);
        }
        let mut carry = 0u64;
        for limb in shifted_l.0.iter_mut().rev() {
            let next_carry = *limb & 1;
            *limb = (*limb >> 1) | (carry << 63);
            carry = next_carry;
        }
    }

    a.to_bytes_32()
}

fn mul_add_mod_l(k: &[u8; 32], s: &[u8; 32], r: &[u8; 64]) -> [u8; 32] {
    let k_limbs = [
        u64::from_le_bytes(k[0..8].try_into().unwrap()),
        u64::from_le_bytes(k[8..16].try_into().unwrap()),
        u64::from_le_bytes(k[16..24].try_into().unwrap()),
        u64::from_le_bytes(k[24..32].try_into().unwrap()),
    ];
    let s_limbs = [
        u64::from_le_bytes(s[0..8].try_into().unwrap()),
        u64::from_le_bytes(s[8..16].try_into().unwrap()),
        u64::from_le_bytes(s[16..24].try_into().unwrap()),
        u64::from_le_bytes(s[24..32].try_into().unwrap()),
    ];

    let mut out = BigInt10::from_bytes_le(r);

    for i in 0..4 {
        let mut carry = 0u128;
        for j in 0..4 {
            let prod = (k_limbs[i] as u128) * (s_limbs[j] as u128)
                + (out.0[i + j] as u128)
                + carry;
            out.0[i + j] = prod as u64;
            carry = prod >> 64;
        }
        let mut idx = i + 4;
        while carry > 0 && idx < 10 {
            let sum = (out.0[idx] as u128) + carry;
            out.0[idx] = sum as u64;
            carry = sum >> 64;
            idx += 1;
        }
    }

    let mut out_bytes = [0u8; 80];
    for i in 0..10 {
        out_bytes[i * 8..(i + 1) * 8].copy_from_slice(&out.0[i].to_le_bytes());
    }
    scalar_mod_l(&out_bytes)
}

pub fn scalar_from_sha512(hash: &[u8; 64]) -> [u8; 32] {
    scalar_mod_l(hash)
}

pub fn public_key_from_seed(seed: &[u8; 32]) -> [u8; 32] {
    let mut h = sha512(seed);
    h[0] &= 248;
    h[31] &= 127;
    h[31] |= 64;

    let mut scalar = [0u8; 32];
    scalar.copy_from_slice(&h[..32]);

    let p = EdwardsPoint::base().scalar_mul(&scalar);
    zeroize(&mut h);
    zeroize(&mut scalar);
    p.compress()
}

pub fn sign(seed: &[u8; 32], message: &[u8]) -> [u8; 64] {
    let mut h = sha512(seed);
    let pubkey = public_key_from_seed(seed);
    h[0] &= 248;
    h[31] &= 127;
    h[31] |= 64;

    let mut s = [0u8; 32];
    s.copy_from_slice(&h[..32]);

    let mut r_input = Vec::with_capacity(32 + message.len());
    r_input.extend_from_slice(&h[32..64]);
    r_input.extend_from_slice(message);
    let r_hash = sha512(&r_input);

    let r_scalar = scalar_mod_l(&r_hash);
    let r_point = EdwardsPoint::base().scalar_mul(&r_scalar);
    let r_bytes = r_point.compress();

    let mut k_input = Vec::with_capacity(64 + message.len());
    k_input.extend_from_slice(&r_bytes);
    k_input.extend_from_slice(&pubkey);
    k_input.extend_from_slice(message);
    let k_hash = sha512(&k_input);
    let k_scalar = scalar_mod_l(&k_hash);

    let s_scalar = mul_add_mod_l(&k_scalar, &s, &r_hash);

    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&r_bytes);
    sig[32..].copy_from_slice(&s_scalar);

    zeroize(&mut h);
    zeroize(&mut s);
    sig
}

pub fn verify(pubkey: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&signature[32..64]);

    let s_big = BigInt10::from_bytes_le(&s_bytes);
    let l = BigInt10([
        0x5812631a5cf5d3ed,
        0x14def9dea2f79cd6,
        0x0000000000000000,
        0x1000000000000000,
        0, 0, 0, 0, 0, 0,
    ]);
    if s_big.gte(&l) {
        return false;
    }

    let mut r_bytes = [0u8; 32];
    r_bytes.copy_from_slice(&signature[..32]);

    let point_r = match EdwardsPoint::decompress(&r_bytes) {
        Some(p) => p,
        None => return false,
    };

    let point_a = match EdwardsPoint::decompress(pubkey) {
        Some(p) => p,
        None => return false,
    };

    let mut k_input = Vec::with_capacity(64 + message.len());
    k_input.extend_from_slice(&r_bytes);
    k_input.extend_from_slice(pubkey);
    k_input.extend_from_slice(message);
    let k_hash = sha512(&k_input);
    let k_scalar = scalar_mod_l(&k_hash);

    let sb = EdwardsPoint::base().scalar_mul(&s_bytes);
    let ka = point_a.scalar_mul(&k_scalar);
    let r_plus_ka = point_r.add(&ka);

    sb.compress() == r_plus_ka.compress()
}

pub const X25519_BASE_POINT: [u8; 32] = [
    9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

pub fn x25519(scalar: &[u8; 32], point_u: &[u8; 32]) -> [u8; 32] {
    let mut clamped = *scalar;
    clamped[0] &= 248;
    clamped[31] &= 127;
    clamped[31] |= 64;

    let x1 = FieldElement::from_bytes(point_u);
    let mut x2 = FieldElement::ONE;
    let mut z2 = FieldElement::ZERO;
    let mut x3 = x1;
    let mut z3 = FieldElement::ONE;

    let a24 = FieldElement([121665, 0, 0, 0, 0]);

    let mut swap = 0u8;

    for i in (0..255).rev() {
        let byte_idx = i / 8;
        let bit_idx = i % 8;
        let bit = ((clamped[byte_idx] >> bit_idx) & 1) as u8;

        let swap_now = swap ^ bit;
        FieldElement::cswap(swap_now, &mut x2, &mut x3);
        FieldElement::cswap(swap_now, &mut z2, &mut z3);
        swap = bit;

        let a = x2.add(&z2);
        let aa = a.square();
        let b = x2.sub(&z2);
        let bb = b.square();
        let e = aa.sub(&bb);
        let c = x3.add(&z3);
        let d = x3.sub(&z3);
        let da = d.mul(&a);
        let cb = c.mul(&b);

        x3 = da.add(&cb).square();
        z3 = x1.mul(&da.sub(&cb).square());
        x2 = aa.mul(&bb);
        z2 = e.mul(&aa.add(&a24.mul(&e)));
    }

    FieldElement::cswap(swap, &mut x2, &mut x3);
    FieldElement::cswap(swap, &mut z2, &mut z3);

    x2.mul(&z2.invert()).to_bytes()
}
