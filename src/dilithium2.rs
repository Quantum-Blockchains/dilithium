pub const SECRETKEYBYTES: usize = crate::params::lvl2::SECRETKEYBYTES as usize;
pub const PUBLICKEYBYTES: usize = crate::params::lvl2::PUBLICKEYBYTES as usize;
pub const SIGNBYTES: usize = crate::params::lvl2::SIGNBYTES as usize;
pub const KEYPAIRBYTES: usize = SECRETKEYBYTES + PUBLICKEYBYTES;

pub type  Signature = [u8; SIGNBYTES];

pub struct Keypair {
    pub secret: [u8; SECRETKEYBYTES],
    pub public: [u8; PUBLICKEYBYTES],
}

impl Keypair {
    pub fn generate(entropy: Option<&[u8]>) -> Keypair {
        //TODO
        let mut bytes = [0u8; KEYPAIRBYTES];
        if let Some(x) = entropy {
            bytes[..x.len()].copy_from_slice(&x);
        }
        Keypair::from_bytes(&bytes)
    }

    pub fn to_bytes(&self) -> [u8; KEYPAIRBYTES] {
        let mut result = [0u8; KEYPAIRBYTES];
        result[..SECRETKEYBYTES].copy_from_slice(&self.secret);
        result[SECRETKEYBYTES..].copy_from_slice(&self.public);
        result
    }

    pub fn from_bytes(bytes: &[u8]) -> Keypair {
        Keypair{
            secret: bytes[..SECRETKEYBYTES].try_into().expect(""),
            public: bytes[SECRETKEYBYTES..].try_into().expect("")
        }
    }

    pub fn sign(&self, _msg: &[u8]) -> Signature {
        //TODO
        [0u8; SIGNBYTES]
    }

    pub fn verify(&self, _msg: &[u8], sig: &[u8], _pk: &[u8]) -> bool {
        if sig.len() != SIGNBYTES {
            return false;
        }
        //TODO
        return true;
    }
}