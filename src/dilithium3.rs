pub const SECRETKEYBYTES: usize = crate::params::lvl3::SECRETKEYBYTES;
pub const PUBLICKEYBYTES: usize = crate::params::lvl3::PUBLICKEYBYTES;
pub const SIGNBYTES: usize = crate::params::lvl3::SIGNBYTES;
pub const KEYPAIRBYTES: usize = SECRETKEYBYTES + PUBLICKEYBYTES;

pub type  Signature = [u8; SIGNBYTES];

pub struct Keypair {
    pub secret: [u8; SECRETKEYBYTES],
    pub public: [u8; PUBLICKEYBYTES],
}

impl Keypair {
    pub fn generate(entropy: Option<&[u8]>) -> Keypair {
        let mut pk = [0u8; PUBLICKEYBYTES];
        let mut sk = [0u8; SECRETKEYBYTES];
        crate::sign::lvl3::keypair(&mut pk, &mut sk, entropy);
        Keypair{
            secret: sk,
            public: pk
        }
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

    pub fn sign(&self, msg: &[u8]) -> Signature {
        let mut sig: Signature = [0u8; SIGNBYTES];
        crate::sign::lvl3::signature(&mut sig, msg, &self.secret, false);
        sig
    }

    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        if sig.len() != SIGNBYTES {
            return false;
        }
        return crate::sign::lvl3::verify(sig, msg, &self.public);
    }
}