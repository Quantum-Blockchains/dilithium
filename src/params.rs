// Specification defined constans
pub const Q: i32 = (1 << 23) - (1 << 13) + 1; //prime defining the field
pub const N: i32 = 256; //ring defining polynomial degree
pub const R: i32 = 1753; //2Nth root of unity mod Q
pub const D: i32 = 13; //dropped bits

// Implementation specific values
pub const SEEDBYTES: i32 = 32;
pub const CRHBYTES: i32 = 64;
pub const POLYT1_PACKEDBYTES: i32 = 320;
pub const POLYT0_PACKEDBYTES: i32 = 416;

// Specific security levels parameters
pub mod lvl2;
pub mod lvl3;
pub mod lvl5;