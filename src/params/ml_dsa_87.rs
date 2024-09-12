// Specification defined constans
pub const TAU: usize = 60; //number of +-1s in c
pub const CHALLENGE_ENTROPY: usize = 257;
pub const GAMMA1: usize = 1 << 19; //y coefficient range
pub const GAMMA2: usize = (crate::params::Q as usize - 1) / 32; //low-order rounding range
pub const K: usize = 8; //rows in A
pub const L: usize = 7; //columns in A
pub const ETA: usize = 2;
pub const BETA: usize = TAU * ETA;
pub const OMEGA: usize = 75;
pub const COLLISION_STRENGTH: usize = 256;

// Implementation specific values
pub const C_DASH_BYTES: usize = (COLLISION_STRENGTH * 2) / 8;
pub const POLYZ_PACKEDBYTES: usize = 640;
pub const POLYW1_PACKEDBYTES: usize = 128;
pub const POLYETA_PACKEDBYTES: usize = 96;
pub const POLYVECH_PACKEDBYTES: usize = OMEGA + K;
pub const PUBLICKEYBYTES: usize = super::SEEDBYTES + K * super::POLYT1_PACKEDBYTES;
pub const SECRETKEYBYTES: usize = 2 * super::SEEDBYTES + super::TR_BYTES + (K + L) * POLYETA_PACKEDBYTES + K * super::POLYT0_PACKEDBYTES;
pub const SIGNBYTES: usize = C_DASH_BYTES + L * POLYZ_PACKEDBYTES + POLYVECH_PACKEDBYTES;
