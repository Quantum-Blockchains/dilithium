pub mod dilithium2;
pub mod dilithium3;
pub mod dilithium5;
pub mod fips202;
pub mod ml_dsa_44;
pub mod ml_dsa_65;
pub mod ml_dsa_87;
pub mod ntt;
pub mod packing;
pub mod params;
pub mod poly;
pub mod polyvec;
pub mod prehash;
pub mod reduce;
pub mod rounding;
pub mod sign;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    InvalidSeedLength {
        expected: usize,
        actual: usize,
    },
    InvalidKeyLength {
        kind: &'static str,
        expected: usize,
        actual: usize,
    },
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::InvalidSeedLength { expected, actual } => {
                write!(
                    f,
                    "invalid seed length: expected {expected} bytes, got {actual}"
                )
            }
            Error::InvalidKeyLength {
                kind,
                expected,
                actual,
            } => write!(
                f,
                "invalid {kind} length: expected {expected} bytes, got {actual}"
            ),
        }
    }
}

impl std::error::Error for Error {}

pub enum RandomMode {
    /// Deterministyczny podpis (ACVP: deterministic=true)
    Deterministic,
    /// Hedged – implementacja sama pobiera entropię (np. z RNG)
    Hedged,
    /// Z góry podany strumień bajtów RNG (ACVP: pole `rnd`)
    #[cfg(feature = "acvp-internal")]
    Fixed(Vec<u8>),
}

use rand::RngCore;
/// Generate random bytes.
///
/// # Arguments
///
/// * 'bytes' - an array to fill with random data
/// * 'n' - number of bytes to generate
fn random_bytes(bytes: &mut [u8], n: usize) {
    rand::prelude::thread_rng()
        .try_fill_bytes(&mut bytes[..n])
        .unwrap();
}

fn build_mprime(msg: &[u8], ctx: Option<&[u8]>, ph: bool) -> Option<Vec<u8>> {
    let ctx = ctx.unwrap_or(&[]);
    if ctx.len() > 255 {
        return None;
    }
    let ctx_len = u8::try_from(ctx.len()).unwrap();
    let mut m = Vec::with_capacity(2 + ctx.len() + msg.len());
    if ph {
        m.push(0x01);
    } else {
        m.push(0x00);
    }
    m.push(ctx_len);
    m.extend_from_slice(ctx);
    m.extend_from_slice(msg);
    Some(m)
}

#[cfg(test)]
mod tests {
    #[test]
    fn params() {
        assert_eq!(crate::params::Q, 8380417);
        assert_eq!(crate::params::N, 256);
        assert_eq!(crate::params::R, 1753);
        assert_eq!(crate::params::D, 13);
    }
    #[test]
    fn params_lvl2() {
        assert_eq!(crate::params::lvl2::TAU, 39);
        assert_eq!(crate::params::lvl2::CHALLENGE_ENTROPY, 192);
        assert_eq!(crate::params::lvl2::GAMMA1, 131072);
        assert_eq!(crate::params::lvl2::GAMMA2, 95232);
        assert_eq!(crate::params::lvl2::K, 4);
        assert_eq!(crate::params::lvl2::L, 4);
        assert_eq!(crate::params::lvl2::ETA, 2);
        assert_eq!(crate::params::lvl2::BETA, 78);
        assert_eq!(crate::params::lvl2::OMEGA, 80);
    }
    #[test]
    fn params_lvl3() {
        assert_eq!(crate::params::lvl3::TAU, 49);
        assert_eq!(crate::params::lvl3::CHALLENGE_ENTROPY, 225);
        assert_eq!(crate::params::lvl3::GAMMA1, 524288);
        assert_eq!(crate::params::lvl3::GAMMA2, 261888);
        assert_eq!(crate::params::lvl3::K, 6);
        assert_eq!(crate::params::lvl3::L, 5);
        assert_eq!(crate::params::lvl3::ETA, 4);
        assert_eq!(crate::params::lvl3::BETA, 196);
        assert_eq!(crate::params::lvl3::OMEGA, 55);
    }
    #[test]
    fn params_lvl5() {
        assert_eq!(crate::params::lvl5::TAU, 60);
        assert_eq!(crate::params::lvl5::CHALLENGE_ENTROPY, 257);
        assert_eq!(crate::params::lvl5::GAMMA1, 524288);
        assert_eq!(crate::params::lvl5::GAMMA2, 261888);
        assert_eq!(crate::params::lvl5::K, 8);
        assert_eq!(crate::params::lvl5::L, 7);
        assert_eq!(crate::params::lvl5::ETA, 2);
        assert_eq!(crate::params::lvl5::BETA, 120);
        assert_eq!(crate::params::lvl5::OMEGA, 75);
    }
}
