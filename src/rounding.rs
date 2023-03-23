/// For finite field element a, compute high and low bits a0, a1 such that a mod^+ Q = a1*2^D + a0 with -2^{D-1} < a0 <= 2^{D-1}.
/// Assumes a to be standard representative.
/// # Arguments
///
/// * 'a' - input element
/// 
/// Returns a touple (a0, a1).
pub fn power2round(a: i32) -> (i32, i32) {
    use crate::params::D;
    let a1: i32 = (a + (1 << (D - 1)) - 1) >> D;
    let a0: i32 = a - (a1 << D);
    (a0, a1)
}

pub mod lvl2;
pub mod lvl3;
pub mod lvl5;
