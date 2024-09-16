pub mod ml_dsa_44;
pub mod ml_dsa_65;
pub mod ml_dsa_87;
pub mod dilithium2;
pub mod dilithium3;
pub mod dilithium5;
pub mod fips202;
pub mod ntt;
pub mod packing;
pub mod params;
pub mod poly;
pub mod polyvec;
pub mod rounding;
pub mod reduce;
pub mod sign;

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
