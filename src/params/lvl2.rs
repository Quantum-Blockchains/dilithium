// Specification defined constans
pub const TAU: usize = 39; //number of +-1s in c
pub const CHALLENGE_ENTROPY: usize = 192;
pub const GAMMA1: usize = 1 << 17; //y coefficient range
pub const GAMMA2: usize = (crate::params::Q as usize - 1) / 88; //low-order rounding range
pub const K: usize = 4; //rows in A
pub const L: usize = 4; //columns in A
pub const ETA: usize = 2;
pub const BETA: usize = TAU * ETA;
pub const OMEGA: usize = 80;

// Implementation specific values
pub const POLYZ_PACKEDBYTES: usize = 576;
pub const POLYW1_PACKEDBYTES: usize = 192;
pub const POLYETA_PACKEDBYTES: usize = 96;
pub const POLYVECH_PACKEDBYTES: usize = OMEGA + K;
pub const PUBLICKEYBYTES: usize = super::SEEDBYTES + K * super::POLYT1_PACKEDBYTES;
pub const SECRETKEYBYTES: usize = 3 * super::SEEDBYTES + (K + L) * POLYETA_PACKEDBYTES + K * super::POLYT0_PACKEDBYTES;
pub const SIGNBYTES: usize = super::SEEDBYTES + L * POLYZ_PACKEDBYTES + POLYVECH_PACKEDBYTES;