use crate::params::{Q, lvl3};
const GAMMA2: i32 = lvl3::GAMMA2 as i32;

/// For finite field element a, compute high and low bits a0, a1 such that a mod^+ Q = a1*ALPHA + a0 with -ALPHA/2 < a0 <= ALPHA/2 except if a1 = (Q-1)/ALPHA where we set a1 = 0 and -ALPHA/2 <= a0 = a mod^+ Q - Q < 0. Assumes a to be standard
/// representative.
/// # Arguments
///
/// * 'a' - input element
///
/// Returns a touple (a0, a1).
pub fn decompose(a: i32) -> (i32, i32) {
    let mut a1: i32 = (a + 127) >> 7;
    a1 = (a1 * 1025 + (1 << 21)) >> 22;
    a1 &= 15;
    let mut a0: i32 = a - a1 * 2 * GAMMA2;
    a0 -= (((Q - 1) / 2 - a0) >> 31) & Q;
    (a0, a1)
}

/// Compute hint bit indicating whether the low bits of the input element overflow into the high bits.
///
/// Returns 1 if overflow.
pub fn make_hint(a0: i32, a1: i32) -> i32 {
  if a0 > GAMMA2 || a0 < -GAMMA2 || (a0 == -GAMMA2 && a1 != 0) {
    return 1;
  }
  0
}

/// Correct high bits according to hint.
///
/// Returns corrected high bits.
pub fn use_hint(a: i32, hint: i32) -> i32
{
    let (a0, a1) = decompose(a);
    if hint == 0 {
        return a1;
    }
    if a0 > 0 {
      return (a1 + 1) & 15;
    } else {
      return (a1 - 1) & 15;
    }
}