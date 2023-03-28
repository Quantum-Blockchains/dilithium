use super::{Poly, N};
use crate::{fips202, params, rounding};

const UNIFORM_ETA_NBLOCKS: usize = (135 + fips202::SHAKE256_RATE) / fips202::SHAKE256_RATE;
const UNIFORM_GAMMA1_NBLOCKS: usize = (params::lvl3::POLYZ_PACKEDBYTES + fips202::SHAKE256_RATE - 1) / fips202::SHAKE256_RATE;

/// For all coefficients c of the input polynomial, compute high and low bits c0, c1 such c mod Q = c1*ALPHA + c0 with -ALPHA/2 < c0 <= ALPHA/2 except c1 = (Q-1)/ALPHA where we set c1 = 0 and -ALPHA/2 <= c0 = c mod Q - Q < 0.
/// Assumes coefficients to be standard representatives.
///
/// # Arguments
///
/// * 'a' - input polynomial
///
/// Returns a touple of polynomials with coefficients c0, c1
pub fn decompose(a: &Poly) -> (Poly, Poly) {
    let mut a0 = Poly::default();
    let mut a1 = Poly::default();
    for i in 0..N {
        (a0.coeffs[i], a1.coeffs[i]) = rounding::lvl3::decompose(a.coeffs[i]);
    }
    (a0, a1)
}

/// Compute hint polynomial, the coefficients of which indicate whether the low bits of the corresponding coefficient of the input polynomial overflow into the high bits.
///
/// # Arguments
///
/// * 'a0' - low part of input polynomial
/// * 'a1' - low part of input polynomial
///
/// Returns the hint polynomial and the number of 1s
pub fn make_hint(a0: &Poly, a1: &Poly) -> (Poly, i32) {
    let mut hint = Poly::default();
    let mut s: i32 = 0;
    for i in 0..N {
        hint.coeffs[i] = rounding::lvl3::make_hint(a0.coeffs[i], a1.coeffs[i]);
        s += hint.coeffs[i];
    }
    (hint, s)
}

/// Use hint polynomial to correct the high bits of a polynomial.
///
/// # Arguments
///
/// * 'a' - input polynomial
/// * 'hint' - hint polynomial
///
/// Returns polynomial with corrected high bits
pub fn use_hint(a: &Poly, hint: &Poly) -> Poly {
    let mut result = Poly::default();
    for i in 0..N {
        result.coeffs[i] = rounding::lvl3::use_hint(a.coeffs[i], hint.coeffs[i]);
    }
    result
}

/// Use hint polynomial to correct the high bits of a polynomial in place.
///
/// # Arguments
///
/// * 'a' - input polynomial to have high bits corrected
/// * 'hint' - hint polynomial
pub fn use_hint_ip(a: &mut Poly, hint: &Poly) {
    for i in 0..N {
        a.coeffs[i] = rounding::lvl3::use_hint(a.coeffs[i], hint.coeffs[i]);
    }
}

/// Sample uniformly random coefficients in [-ETA, ETA] by performing rejection sampling using array of random bytes.
///
/// Returns number of sampled coefficients. Can be smaller than len if not enough random bytes were given
pub fn rej_eta(a: &mut [i32], alen: usize, buf: &[u8], buflen: usize) -> usize {
    let mut ctr = 0usize;
    let mut pos = 0usize;
    while ctr < alen && pos < buflen {
        let t0 = (buf[pos] & 0x0F) as u32;
        let t1 = (buf[pos] >> 4) as u32;
        pos += 1;

        if t0 < 9 {
            a[ctr] = 4 - t0 as i32;
            ctr += 1;
        }
        if t1 < 9 && ctr < alen {
            a[ctr] = 4 - t1 as i32;
            ctr += 1;
        }
    }
    ctr
}

/// Sample polynomial with uniformly random coefficients in [-ETA,ETA] by performing rejection sampling using the output stream from SHAKE256(seed|nonce).
pub fn uniform_eta(a: &mut Poly, seed: &[u8], nonce: u16) {
    let mut state = fips202::KeccakState::default();
    fips202::shake256_stream_init(&mut state, seed, nonce);

    let mut buf = [0u8; UNIFORM_ETA_NBLOCKS * fips202::SHAKE256_RATE];
    fips202::shake256_squeezeblocks(&mut buf, UNIFORM_ETA_NBLOCKS, &mut state);

    let buflen = UNIFORM_ETA_NBLOCKS * fips202::SHAKE256_RATE;
    let mut ctr = rej_eta(&mut a.coeffs, N, &buf, buflen);
    while ctr < N {
        fips202::shake256_squeezeblocks(&mut buf, 1, &mut state);
        ctr += rej_eta(&mut a.coeffs[ctr..], N - ctr, &buf, fips202::SHAKE256_RATE);
    }
}

/// Sample polynomial with uniformly random coefficients in [-(GAMMA1 - 1), GAMMA1 - 1] by performing rejection sampling on output stream of SHAKE256(seed|nonce).
pub fn uniform_gamma1(a: &mut Poly, seed: &[u8], nonce: u16) {
    let mut state = fips202::KeccakState::default();
    fips202::shake256_stream_init(&mut state, seed, nonce);

    let mut buf = [0u8; UNIFORM_GAMMA1_NBLOCKS * fips202::SHAKE256_RATE];
    fips202::shake256_squeezeblocks(&mut buf, UNIFORM_GAMMA1_NBLOCKS, &mut state);
    z_unpack(a, &mut buf);
}

/// Implementation of H. Samples polynomial with TAU nonzero coefficients in {-1,1} using the output stream of SHAKE256(seed).
pub fn challenge(c: &mut Poly, seed: &[u8]) {
    let mut state = fips202::KeccakState::default();
    fips202::shake256_absorb(&mut state, seed, params::SEEDBYTES);
    fips202::shake128_finalize(&mut state);

    let mut buf = [0u8; fips202::SHAKE256_RATE];
    fips202::shake256_squeezeblocks(&mut buf, 1, &mut state);

    let mut signs: u64 = 0;
    for i in 0..8 {
        signs |= (buf[i] as u64) << 8 * i;
    }

    let mut pos: usize = 8;
    c.coeffs.fill(0);
    for i in (N - params::lvl3::TAU)..N {
        let mut b: usize;
        loop {
            if pos >= fips202::SHAKE256_RATE {
                fips202::shake256_squeezeblocks(&mut buf, 1, &mut state);
                pos = 0;
            }
            b = buf[pos] as usize;
            pos += 1;
            if b <= i {
                break;
            }
        }
        c.coeffs[i] = c.coeffs[b];
        c.coeffs[b] = 1 - 2 * ((signs & 1) as i32);
        signs >>= 1;
    }
}

/// Bit-pack polynomial with coefficients in [-ETA,ETA]. Input coefficients are assumed to lie in [Q-ETA,Q+ETA].
pub fn eta_pack(r: &mut [u8], a: &Poly) {
    let mut t = [0u8; 2];
    for i in 0..N / 2 {
        t[0] = (params::lvl3::ETA as i32 - a.coeffs[2 * i + 0]) as u8;
        t[1] = (params::lvl3::ETA as i32 - a.coeffs[2 * i + 1]) as u8;
        r[i] = t[0] | (t[1] << 4);
    }
}

/// Unpack polynomial with coefficients in [-ETA,ETA].
pub fn eta_unpack(r: &mut Poly, a: &[u8]) {
    for i in 0..N / 2 {
        r.coeffs[2 * i + 0] = (a[i] & 0x0F) as i32;
        r.coeffs[2 * i + 1] = (a[i] >> 4) as i32;
        r.coeffs[2 * i + 0] = params::lvl3::ETA as i32 - r.coeffs[2 * i + 0];
        r.coeffs[2 * i + 1] = params::lvl3::ETA as i32 - r.coeffs[2 * i + 1];
    }
}


/// Bit-pack polynomial z with coefficients in [-(GAMMA1 - 1), GAMMA1 - 1].
/// Input coefficients are assumed to be standard representatives.*
pub fn z_pack(r: &mut [u8], a: &Poly) {
    let mut t = [0i32; 2];

    for i in 0..N / 2 {
        t[0] = params::lvl3::GAMMA1 as i32 - a.coeffs[2 * i + 0];
        t[1] = params::lvl3::GAMMA1 as i32 - a.coeffs[2 * i + 1];
  
        r[5 * i + 0] = (t[0]) as u8;
        r[5 * i + 1] = (t[0] >> 8) as u8;
        r[5 * i + 2] = (t[0] >> 16) as u8;
        r[5 * i + 2] |= (t[1] << 4) as u8;
        r[5 * i + 3] = (t[1] >> 4) as u8;
        r[5 * i + 4] = (t[1] >> 12) as u8;
    }
}

/// Unpack polynomial z with coefficients in [-(GAMMA1 - 1), GAMMA1 - 1].
/// Output coefficients are standard representatives.
pub fn z_unpack(r: &mut Poly, a: &[u8]) {
    for i in 0..N / 2 {
        r.coeffs[2 * i + 0] = a[5 * i + 0] as i32;
        r.coeffs[2 * i + 0] |= (a[5 * i + 1] as i32) << 8;
        r.coeffs[2 * i + 0] |= (a[5 * i + 2] as i32) << 16;
        r.coeffs[2 * i + 0] &= 0xFFFFF;
  
        r.coeffs[2 * i + 1] = (a[5 * i + 2] as i32) >> 4;
        r.coeffs[2 * i + 1] |= (a[5 * i + 3] as i32) << 4;
        r.coeffs[2 * i + 1] |= (a[5 * i + 4] as i32) << 12;
        r.coeffs[2 * i + 0] &= 0xFFFFF;
  
        r.coeffs[2 * i + 0] = params::lvl3::GAMMA1 as i32 - r.coeffs[2 * i + 0];
        r.coeffs[2 * i + 1] = params::lvl3::GAMMA1 as i32 - r.coeffs[2 * i + 1];
    }
}

/// Bit-pack polynomial w1 with coefficients in [0, 15].
/// Input coefficients are assumed to be standard representatives.
pub fn w1_pack(r: &mut [u8], a: &Poly) {
    for i in 0..N / 2 {
        r[i] = (a.coeffs[2 * i + 0] | (a.coeffs[2 * i + 1] << 4)) as u8;
    }
}