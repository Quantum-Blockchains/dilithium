use crate::{params, poly, poly::Poly};

const L: usize = params::lvl2::L;
const K: usize = params::lvl2::K;

#[derive(Clone, Copy)]
pub struct Polyveck {
    pub vec: [Poly; K]
}

impl Default for Polyveck {
    fn default() -> Self {
        Polyveck {
            vec: [Poly::default(); K]
        }
    }
}

#[derive(Clone, Copy)]
pub struct Polyvecl {
    pub vec: [Poly; L]
}

impl Default for Polyvecl {
    fn default() -> Self {
        Polyvecl {
            vec: [Poly::default(); L]
        }
    }
}

/// Implementation of ExpandA. Generates matrix A with uniformly random coefficients a_{i,j} by performing rejection sampling on the output stream of SHAKE128(rho|j|i).
pub fn matrix_expand(mat: &mut [Polyvecl], rho: &[u8]) {
    for i in 0..K {
        for j in 0..L {
            poly::uniform(&mut mat[i].vec[j], rho, ((i << 8) + j) as u16);
        }
    }
}

/// Pointwise multiply vectors of polynomials of length L, multiply resulting vector by 2^{-32} and add (accumulate) polynomials in it.
/// Input/output vectors are in NTT domain representation. Input coefficients are assumed to be less than 22*Q. Output coeffcient are less than 2*L*Q.
pub fn l_pointwise_acc_montgomery(w: &mut Poly, u: &Polyvecl, v: &Polyvecl) {
    *w = poly::pointwise_montgomery(&u.vec[0], &v.vec[0]);
    for i in 1..L {
        let t = poly::pointwise_montgomery(&u.vec[i], &v.vec[i]);
        poly::add_ip(w, &t);
    }
}

pub fn matrix_pointwise_montgomery(t: &mut Polyveck, mat: &[Polyvecl], v: &Polyvecl) {
    for i in 0..K {
        l_pointwise_acc_montgomery(&mut t.vec[i], &mat[i], v);
    }
}

pub fn l_uniform_eta(v: &mut Polyvecl, seed: &[u8], mut nonce: u16) {
    for i in 0..L {
        poly::lvl2::uniform_eta(&mut v.vec[i], seed, nonce);
        nonce += 1;
    }
}

pub fn l_uniform_gamma1(v: &mut Polyvecl, seed: &[u8], nonce: u16) {
    for i in 0..L {
        poly::lvl2::uniform_gamma1(&mut v.vec[i], seed, L as u16 * nonce + i as u16);
    }
}
pub fn l_reduce(v: &mut Polyvecl) {
    for i in 0..L {
        poly::reduce(&mut v.vec[i]);
    }
}

/// Add vectors of polynomials of length L.
/// No modular reduction is performed.
pub fn l_add(w: &mut Polyvecl, v: &Polyvecl) {
    for i in 0..L {
        poly::add_ip(&mut w.vec[i], &v.vec[i]);
    }
}

/// Forward NTT of all polynomials in vector of length L. Output coefficients can be up to 16*Q larger than input coefficients.
pub fn l_ntt(v: &mut Polyvecl) {
    for i in 0..L {
        poly::ntt(&mut v.vec[i]);
    }
}

pub fn l_invntt_tomont(v: &mut Polyvecl) {
    for i in 0..L {
        poly::invntt_tomont(&mut v.vec[i]);
    }
}

pub fn l_pointwise_poly_montgomery(r: &mut Polyvecl, a: &Poly, v: &Polyvecl) {
    for i in 0..L {
        r.vec[i] = poly::pointwise_montgomery(a, &v.vec[i]);
    }
}

//---------------------------------

pub fn k_uniform_eta(v: &mut Polyveck, seed: &[u8], mut nonce: u16) {
    for i in 0..K {
        poly::lvl2::uniform_eta(&mut v.vec[i], seed, nonce);
        nonce += 1
    }
}

/// Reduce coefficients of polynomials in vector of length K
/// to representatives in [0,2*Q].
pub fn k_reduce(v: &mut Polyveck)
{
  for i in 0..K {
    poly::reduce(&mut v.vec[i]);
  }
}

/// For all coefficients of polynomials in vector of length K
/// add Q if coefficient is negative.
pub fn k_caddq(v: &mut Polyveck)
{
  for i in 0..K {
    poly::caddq(&mut v.vec[i]);
  }
}

/// Add vectors of polynomials of length K.
/// No modular reduction is performed.
pub fn k_add(w: &mut Polyveck, v: &Polyveck)
{
  for i in 0..K {
    poly::add_ip(&mut w.vec[i], &v.vec[i]);
  }
}

/// Subtract vectors of polynomials of length K.
/// Assumes coefficients of polynomials in second input vector
/// to be less than 2*Q. No modular reduction is performed.
pub fn k_sub(w: &mut Polyveck, v: &Polyveck) {
    for i in 0..K {
        poly::sub_ip(&mut w.vec[i], &v.vec[i]);
    }
}

/// Multiply vector of polynomials of Length K by 2^D without modular
/// reduction. Assumes input coefficients to be less than 2^{32-D}.
pub fn k_shiftl(v: &mut Polyveck) {
    for i in 0..K {
        poly::shiftl(&mut v.vec[i]);
    }
}

/// Forward NTT of all polynomials in vector of length K. Output
/// coefficients can be up to 16*Q larger than input coefficients.
pub fn k_ntt(v: &mut Polyveck) {
    for i in 0..K {
        poly::ntt(&mut v.vec[i]);
    }
}

/// Inverse NTT and multiplication by 2^{32} of polynomials
/// in vector of length K. Input coefficients need to be less
/// than 2*Q.
pub fn k_invntt_tomont(v: &mut Polyveck) {
    for i in 0..K {
        poly::invntt_tomont(&mut v.vec[i]);
    }
}

pub fn k_pointwise_poly_montgomery(r: &mut Polyveck, a: &Poly, v: &Polyveck) {
    for i in 0..K {
        r.vec[i] = poly::pointwise_montgomery(a, &v.vec[i]);
    }
}

/// Check infinity norm of polynomials in vector of length K.
/// Assumes input coefficients to be standard representatives.
//
/// Returns 0 if norm of all polynomials are strictly smaller than B and 1 otherwise.
pub fn k_chknorm(v: &Polyveck, bound: i32) -> u8 {
    for i in 0..K {
        if poly::chknorm(&v.vec[i], bound) == 1 {
            return 1;
        }
    }
    0
}

/// For all coefficients a of polynomials in vector of length K, compute a0, a1 such that a mod Q = a1*2^D + a0 with -2^{D-1} < a0 <= 2^{D-1}.
/// Assumes coefficients to be standard representatives.
pub fn k_power2round(v: &Polyveck) -> (Polyveck, Polyveck) {
    let mut v0 = Polyveck::default();
    let mut v1 = Polyveck::default();
    for i in 0..K {
        (v0.vec[i], v1.vec[i]) = poly::power2round(&v.vec[i]);
    }
    (v0, v1)
}

pub fn k_decompose(v: &Polyveck) -> (Polyveck, Polyveck) {
    let mut v0 = Polyveck::default();
    let mut v1 = Polyveck::default();
    for i in 0..K {
        (v0.vec[i], v1.vec[i]) = poly::lvl2::decompose(&v.vec[i]);
    }
    (v0, v1)
}

pub fn k_make_hint(v0: &Polyveck, v1: &Polyveck) -> (Polyveck, i32) {
    let mut v = Polyveck::default();
    let mut s: i32 = 0;
    let mut tmp: i32;
    for i in 0..K {
        (v.vec[i], tmp) = poly::lvl2::make_hint(&v0.vec[i], &v1.vec[i]);
        s += tmp;
    }
    (v, s)
}

pub fn k_use_hint(a: &Polyveck, hint: &Polyveck) -> Polyveck {
    let mut v = Polyveck::default();
    for i in 0..K {
        v.vec[i] = poly::lvl2::use_hint(&a.vec[i], &hint.vec[i]);
    }
    v
}

pub fn k_pack_w1(r: &mut [u8], a: &Polyveck) {
    for i in 0..K {
        poly::lvl2::w1_pack(&mut r[i * params::lvl2::POLYW1_PACKEDBYTES..], &a.vec[i]);
    }
}