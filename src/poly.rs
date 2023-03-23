use crate::{ntt, params, reduce, rounding};
const N: usize = params::N as usize;

/// Represents a polynomial
#[derive(Clone, Copy)]
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
pub fn pointwise_montgomery(a: &Poly, b: &Poly) -> Poly {
    let mut c = Poly::default();
    for i in 0..N {
        c.coeffs[i] = reduce::montgomery_reduce(a.coeffs[i] as i64 * b.coeffs[i] as i64);
    }
    c
}

/// For all coefficients c of the input polynomial, compute c0, c1 such that c mod Q = c1*2^D + c0 with -2^{D-1} < c0 <= 2^{D-1}.
/// Assumes coefficients to be standard representatives.
/// 
/// # Arguments
/// 
/// * 'a' - input polynomial
/// 
/// Returns a touple of polynomials with coefficients c0, c1
pub fn power2round(a: &Poly) -> (Poly, Poly) {
    let mut a0 = Poly::default();
    let mut a1 = Poly::default();
    for i in 0..N {
        (a0.coeffs[i], a1.coeffs[i]) = rounding::power2round(a.coeffs[i]);
    }
    (a0, a1)
}
