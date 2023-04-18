use crate::{fips202, ntt, params, reduce, rounding};
const N: usize = params::N as usize;
const UNIFORM_NBLOCKS: usize = (767 + fips202::SHAKE128_RATE) / fips202::SHAKE128_RATE;
const D_SHL: i32 = 1 << (params::D - 1);

/// Represents a polynomial
#[derive(Clone, Copy, Debug)]
pub struct Poly {
    pub coeffs: [i32; N]
}

/// For some reason can't simply derive the Default trait
impl Default for Poly {
    fn default() -> Self {
        Poly {
            coeffs: [0i32; N]
        }
    }
}

/// Inplace reduction of all coefficients of polynomial to representative in [-6283009,6283007].
pub fn reduce(a: &mut Poly) {
    // Bad C style
    // for i in 0..N {
    //     a.coeffs[i] = reduce::reduce32(a.coeffs[i]);
    // }
    // Nice Rust style
    for coeff in a.coeffs.iter_mut() {
        *coeff = reduce::reduce32(*coeff);
    }
}

/// For all coefficients of in/out polynomial add Q if coefficient is negative.
pub fn caddq(a: &mut Poly) {
    // Bad C style
    // for i in 0..N {
    //     a.coeffs[i] = reduce::caddq(a.coeffs[i]);
    // }
    // Nice Rust style
    for coeff in a.coeffs.iter_mut() {
        *coeff = reduce::caddq(*coeff);
    }
}

/// Add polynomials. No modular reduction is performed.
/// 
/// # Arguments
/// 
/// * 'a' - 1st input polynomial
/// * 'b' - 2nd input polynomial
/// 
/// Returns coefficient wise a + b
pub fn add(a: &Poly, b: &Poly) -> Poly {
    let mut c = Poly::default();
    for i in 0..N {
        c.coeffs[i] = a.coeffs[i] + b.coeffs[i];
    }
    c
}

/// Add polynomials in place. No modular reduction is performed.
/// 
/// # Arguments
/// 
/// * 'a' - polynomial to add to
/// * 'b' - added polynomial
pub fn add_ip(a: &mut Poly, b: &Poly) {
    for i in 0..N {
        a.coeffs[i] += b.coeffs[i];
    }
}

/// Subtract polynomials. No modular reduction is performed.
/// 
/// # Arguments
/// 
/// * 'a' - 1st input polynomial
/// * 'b' - 2nd input polynomial
/// 
/// Returns coefficient wise a - b
pub fn sub(a: &Poly, b: &Poly) -> Poly {
    let mut c = Poly::default();
    for i in 0..N {
        c.coeffs[i] = a.coeffs[i] - b.coeffs[i];
    }
    c
}

/// Subtract polynomials in place. No modular reduction is performed.
/// 
/// # Arguments
/// 
/// * 'a' - polynomial to subtract from
/// * 'b' - subtracted polynomial
pub fn sub_ip(a: &mut Poly, b: &Poly) {
    for i in 0..N {
        a.coeffs[i] -= b.coeffs[i];
    }
}

/// Multiply polynomial by 2^D without modular reduction.
/// Assumes input coefficients to be less than 2^{31-D} in absolute value.
pub fn shiftl(a: &mut Poly) {
    for coeff in a.coeffs.iter_mut() {
        *coeff <<= params::D;
    }
}

/// Inplace forward NTT. Coefficients can grow by 8*Q in absolute value.
pub fn ntt(a: &mut Poly) {
    ntt::ntt(&mut a.coeffs);
}

/// Inplace inverse NTT and multiplication by 2^{32}.
/// Input coefficients need to be less than Q in absolute value and output coefficients are again bounded by Q.
pub fn invntt_tomont(a: &mut Poly) {
    ntt::invntt_tomont(&mut a.coeffs);
}

/// Pointwise multiplication of polynomials in NTT domain representation and multiplication of resulting polynomial by 2^{-32}.
/// 
/// # Arguments
/// 
/// * 'a' - 1st input polynomial
/// * 'b' - 2nd input polynomial
/// 
/// Returns resulting polynomial
pub fn pointwise_montgomery(c: &mut Poly, a: &Poly, b: &Poly) {
    for i in 0..N {
        c.coeffs[i] = reduce::montgomery_reduce(a.coeffs[i] as i64 * b.coeffs[i] as i64);
    }
}

/// For all coefficients c of the input polynomial, compute c0, c1 such that c mod Q = c1*2^D + c0 with -2^{D-1} < c0 <= 2^{D-1}.
/// Assumes coefficients to be standard representatives.
/// 
/// # Arguments
/// 
/// * 'a' - input polynomial
/// 
/// Returns a touple of polynomials with coefficients c0, c1
pub fn power2round(a1: &mut Poly, a0: &mut Poly) {
    for i in 0..N {
        (a0.coeffs[i], a1.coeffs[i]) = rounding::power2round(a1.coeffs[i]);
    }
}

/// Check infinity norm of polynomial against given bound.
/// Assumes input coefficients were reduced by reduce32().
/// 
/// # Arguments
/// 
/// * 'a' - input polynomial
/// * 'b' - norm bound
/// 
/// Returns 0 if norm is strictly smaller than B and B <= (Q-1)/8, 1 otherwise.
pub fn chknorm(a: &Poly, b: i32) -> i32 {
    if b > (params::Q - 1)/ 8 {
        return 1;
    }
    // for i in a.coeffs.iter() {
    //     let mut t = *i >> 31;
    //     t = *i - (t & 2 * *i);
    //     if t.ge(&b) {
    //         return 1;
    //     }
    // }
    for i in 0..N {
        let mut t = a.coeffs[i] >> 31;
        t = a.coeffs[i] - (t & 2 * a.coeffs[i]);
        if t >= b {
            return 1;
        }
    }
    0
}

/// Sample uniformly random coefficients in [0, Q-1] by performing rejection sampling on array of random bytes.
/// 
/// # Arguments
/// 
/// * 'a' - output array (allocated)
/// * 'b' - array of random bytes
/// 
/// Returns number of sampled coefficients. Can be smaller than a.len() if not enough random bytes were given.
pub fn rej_uniform(a: &mut [i32], alen: usize, buf: &[u8], buflen: usize) -> usize {
    let mut ctr: usize = 0;
    let mut pos: usize = 0;
    while ctr < alen && pos + 3 <= buflen {
        let mut t = buf[pos] as u32;
        t |= (buf[pos + 1] as u32) << 8;
        t |= (buf[pos + 2] as u32) << 16;
        t &= 0x7FFFFF;
        pos += 3;
        let t = t as i32;
        if t < params::Q {
            a[ctr] = t;
            ctr += 1;
        }
    }
    ctr
}

/// Sample polynomial with uniformly random coefficients in [0, Q-1] by performing rejection sampling using the output stream of SHAKE128(seed|nonce).
pub fn uniform(a: &mut Poly, seed: &[u8], nonce: u16) {
    let mut state = fips202::KeccakState::default();
    fips202::shake128_stream_init(&mut state, seed, nonce);

    let mut buf = [0u8; UNIFORM_NBLOCKS * fips202::SHAKE128_RATE + 2];
    fips202::shake128_squeezeblocks(&mut buf, UNIFORM_NBLOCKS, &mut state);

    let mut buflen: usize = UNIFORM_NBLOCKS * fips202::SHAKE128_RATE;
    let mut ctr = rej_uniform(&mut a.coeffs, N, &mut buf, buflen);

    while ctr < N {
        let off = buflen % 3;
        for i in 0..off {
            buf[i] = buf[buflen - off + i];
        }           
        buflen = fips202::SHAKE128_RATE + off;
        fips202::shake128_squeezeblocks(&mut buf[off..], 1, &mut state);
        ctr += rej_uniform(&mut a.coeffs[ctr..], N - ctr, &buf, buflen);
    }
}

/// Bit-pack polynomial t1 with coefficients fitting in 10 bits.
/// Input coefficients are assumed to be standard representatives.
pub fn t1_pack(r: &mut [u8], a: &Poly) {
    for i in 0..N / 4 {
        r[5 * i + 0] = (a.coeffs[4 * i + 0] >> 0) as u8;
        r[5 * i + 1] = ((a.coeffs[4 * i + 0] >> 8) | (a.coeffs[4 * i + 1] << 2)) as u8;
        r[5 * i + 2] = ((a.coeffs[4 * i + 1] >> 6) | (a.coeffs[4 * i + 2] << 4)) as u8;
        r[5 * i + 3] = ((a.coeffs[4 * i + 2] >> 4) | (a.coeffs[4 * i + 3] << 6)) as u8;
        r[5 * i + 4] = (a.coeffs[4 * i + 3] >> 2) as u8;
    }
}

/// Unpack polynomial t1 with 9-bit coefficients.
/// Output coefficients are standard representatives.
pub fn t1_unpack(r: &mut Poly, a: &[u8]) {
    for i in 0..N / 4 {
        r.coeffs[4 * i + 0] = (((a[5 * i + 0] >> 0) as u32 | (a[5 * i + 1] as u32) << 8) & 0x3FF) as i32;
        r.coeffs[4 * i + 1] = (((a[5 * i + 1] >> 2) as u32 | (a[5 * i + 2] as u32) << 6) & 0x3FF) as i32;
        r.coeffs[4 * i + 2] = (((a[5 * i + 2] >> 4) as u32 | (a[5 * i + 3] as u32) << 4) & 0x3FF) as i32;
        r.coeffs[4 * i + 3] = (((a[5 * i + 3] >> 6) as u32 | (a[5 * i + 4] as u32) << 2) & 0x3FF) as i32;
    }
}

/// Bit-pack polynomial t0 with coefficients in [-2^{D-1}, 2^{D-1}].
pub fn t0_pack(r: &mut [u8], a: &Poly) {
    let mut t = [0i32; 8];

    for i in 0..N / 8 {
        t[0] = D_SHL - a.coeffs[8 * i + 0];
        t[1] = D_SHL - a.coeffs[8 * i + 1];
        t[2] = D_SHL - a.coeffs[8 * i + 2];
        t[3] = D_SHL - a.coeffs[8 * i + 3];
        t[4] = D_SHL - a.coeffs[8 * i + 4];
        t[5] = D_SHL - a.coeffs[8 * i + 5];
        t[6] = D_SHL - a.coeffs[8 * i + 6];
        t[7] = D_SHL - a.coeffs[8 * i + 7];

        r[13 * i + 0] = (t[0]) as u8;
        r[13 * i + 1] = (t[0] >> 8) as u8;
        r[13 * i + 1] |= (t[1] << 5) as u8;
        r[13 * i + 2] = (t[1] >> 3) as u8;
        r[13 * i + 3] = (t[1] >> 11) as u8;
        r[13 * i + 3] |= (t[2] << 2) as u8;
        r[13 * i + 4] = (t[2] >> 6) as u8;
        r[13 * i + 4] |= (t[3] << 7) as u8;
        r[13 * i + 5] = (t[3] >> 1) as u8;
        r[13 * i + 6] = (t[3] >> 9) as u8;
        r[13 * i + 6] |= (t[4] << 4) as u8;
        r[13 * i + 7] = (t[4] >> 4) as u8;
        r[13 * i + 8] = (t[4] >> 12) as u8;
        r[13 * i + 8] |= (t[5] << 1) as u8;
        r[13 * i + 9] = (t[5] >> 7) as u8;
        r[13 * i + 9] |= (t[6] << 6) as u8;
        r[13 * i + 10] = (t[6] >> 2) as u8;
        r[13 * i + 11] = (t[6] >> 10) as u8;
        r[13 * i + 11] |= (t[7] << 3) as u8;
        r[13 * i + 12] = (t[7] >> 5) as u8;
    }
}

/// Unpack polynomial t0 with coefficients in ]-2^{D-1}, 2^{D-1}].
/// Output coefficients lie in ]Q-2^{D-1},Q+2^{D-1}].
pub fn t0_unpack(r: &mut Poly, a: &[u8]) {
    for i in 0..N / 8 {
        r.coeffs[8 * i + 0] = a[13 * i + 0] as i32;
        r.coeffs[8 * i + 0] |= (a[13 * i + 1] as i32) << 8;
        r.coeffs[8 * i + 0] &= 0x1FFF;

        r.coeffs[8 * i + 1] = (a[13 * i + 1] as i32) >> 5;
        r.coeffs[8 * i + 1] |= (a[13 * i + 2] as i32) << 3;
        r.coeffs[8 * i + 1] |= (a[13 * i + 3] as i32) << 11;
        r.coeffs[8 * i + 1] &= 0x1FFF;

        r.coeffs[8 * i + 2] = (a[13 * i + 3] as i32) >> 2;
        r.coeffs[8 * i + 2] |= (a[13 * i + 4] as i32) << 6;
        r.coeffs[8 * i + 2] &= 0x1FFF;

        r.coeffs[8 * i + 3] = (a[13 * i + 4] as i32) >> 7;
        r.coeffs[8 * i + 3] |= (a[13 * i + 5] as i32) << 1;
        r.coeffs[8 * i + 3] |= (a[13 * i + 6] as i32) << 9;
        r.coeffs[8 * i + 3] &= 0x1FFF;

        r.coeffs[8 * i + 4] = (a[13 * i + 6] as i32) >> 4;
        r.coeffs[8 * i + 4] |= (a[13 * i + 7] as i32) << 4;
        r.coeffs[8 * i + 4] |= (a[13 * i + 8] as i32) << 12;
        r.coeffs[8 * i + 4] &= 0x1FFF;

        r.coeffs[8 * i + 5] = (a[13 * i + 8] as i32) >> 1;
        r.coeffs[8 * i + 5] |= (a[13 * i + 9] as i32) << 7;
        r.coeffs[8 * i + 5] &= 0x1FFF;

        r.coeffs[8 * i + 6] = (a[13 * i + 9] as i32) >> 6;
        r.coeffs[8 * i + 6] |= (a[13 * i + 10] as i32) << 2;
        r.coeffs[8 * i + 6] |= (a[13 * i + 11] as i32) << 10;
        r.coeffs[8 * i + 6] &= 0x1FFF;

        r.coeffs[8 * i + 7] = (a[13 * i + 11] as i32) >> 3;
        r.coeffs[8 * i + 7] |= (a[13 * i + 12] as i32) << 5;
        r.coeffs[8 * i + 7] &= 0x1FFF;

        r.coeffs[8 * i + 0] = D_SHL - r.coeffs[8 * i + 0];
        r.coeffs[8 * i + 1] = D_SHL - r.coeffs[8 * i + 1];
        r.coeffs[8 * i + 2] = D_SHL - r.coeffs[8 * i + 2];
        r.coeffs[8 * i + 3] = D_SHL - r.coeffs[8 * i + 3];
        r.coeffs[8 * i + 4] = D_SHL - r.coeffs[8 * i + 4];
        r.coeffs[8 * i + 5] = D_SHL - r.coeffs[8 * i + 5];
        r.coeffs[8 * i + 6] = D_SHL - r.coeffs[8 * i + 6];
        r.coeffs[8 * i + 7] = D_SHL - r.coeffs[8 * i + 7];
    }
}

pub mod lvl2;
pub mod lvl3;
pub mod lvl5;