pub const SECRETKEYBYTES: usize = crate::params::lvl2::SECRETKEYBYTES;
pub const PUBLICKEYBYTES: usize = crate::params::lvl2::PUBLICKEYBYTES;
pub const SIGNBYTES: usize = crate::params::lvl2::SIGNBYTES;
pub const KEYPAIRBYTES: usize = SECRETKEYBYTES + PUBLICKEYBYTES;

pub type Signature = [u8; SIGNBYTES];

/// A pair of private and public keys.
pub struct Keypair {
    pub secret: [u8; SECRETKEYBYTES],
    pub public: [u8; PUBLICKEYBYTES],
}

impl Keypair {
    /// Generate a Keypair instance.
    /// 
    /// # Arguments
    /// 
    /// * 'entropy' - optional bytes for determining the generation process
    /// 
    /// Returns an instance of Keypair
    pub fn generate(entropy: Option<&[u8]>) -> Keypair {
        let mut pk = [0u8; PUBLICKEYBYTES];
        let mut sk = [0u8; SECRETKEYBYTES];
        crate::sign::lvl2::keypair(&mut pk, &mut sk, entropy);
        Keypair{
            secret: sk,
            public: pk
        }
    }

    /// Convert a Keypair to a bytes array.
    /// 
    /// Returns an array containing private and public keys bytes
    pub fn to_bytes(&self) -> [u8; KEYPAIRBYTES] {
        let mut result = [0u8; KEYPAIRBYTES];
        result[..SECRETKEYBYTES].copy_from_slice(&self.secret);
        result[SECRETKEYBYTES..].copy_from_slice(&self.public);
        result
    }

    /// Create a Keypair from bytes.
    /// 
    /// # Arguments
    /// 
    /// * 'bytes' - private and public keys bytes
    /// 
    /// Returns a Keypair
    pub fn from_bytes(bytes: &[u8]) -> Keypair {
        Keypair{
            secret: bytes[..SECRETKEYBYTES].try_into().expect(""),
            public: bytes[SECRETKEYBYTES..].try_into().expect("")
        }
    }

    /// Compute a signature for a given message.
    ///
    /// # Arguments
    ///
    /// * 'msg' - message to sign
    /// 
    /// Returns a Signature
    pub fn sign(&self, msg: &[u8]) -> Signature {
        let mut sig: Signature = [0u8; SIGNBYTES];
        crate::sign::lvl2::signature(&mut sig, msg, &self.secret, false);
        sig
    }

    /// Verify a signature for a given message with a public key.
    /// 
    /// # Arguments
    /// 
    /// * 'msg' - message that is claimed to be signed
    /// * 'sig' - signature to verify
    /// 
    /// Returns 'true' if the verification process was successful, 'false' otherwise
    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        if sig.len() != SIGNBYTES {
            return false;
        }
        return crate::sign::lvl2::verify(sig, msg, &self.public);
    }
}