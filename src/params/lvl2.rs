// Specification defined constans
pub const TAU: i32 = 39; //number of +-1s in c
pub const CHALLENGE_ENTROPY: i32 = 192;
pub const GAMMA1: i32 = 1 << 17; //y coefficient range
pub const GAMMA2: i32 = (crate::params::Q - 1) / 88; //low-order rounding range
pub const K: i32 = 4; //rows in A
pub const L: i32 = 4; //columns in A
pub const ETA: i32 = 2;
pub const BETA: i32 = TAU * ETA;
pub const OMEGA: i32 = 80;

// Implementation specific values
pub const POLYZ_PACKEDBYTES: i32 = 576;
pub const POLYW1_PACKEDBYTES: i32 = 192;
pub const POLYETA_PACKEDBYTES: i32 = 128;
pub const POLYVECH_PACKEDBYTES: i32 = OMEGA + K;
pub const PUBLICKEYBYTES: i32 = super::SEEDBYTES + K * super::POLYT1_PACKEDBYTES;
pub const SECRETKEYBYTES: i32 = 3 * super::SEEDBYTES + (K + L) * POLYETA_PACKEDBYTES + K * super::POLYT0_PACKEDBYTES;
pub const SIGNBYTES: i32 = super::SEEDBYTES + L * POLYZ_PACKEDBYTES + POLYVECH_PACKEDBYTES;