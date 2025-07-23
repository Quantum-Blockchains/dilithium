use sha2::{Sha256, Sha512, Digest};

pub const SECRETKEYBYTES: usize = crate::params::ml_dsa_44::SECRETKEYBYTES;
pub const PUBLICKEYBYTES: usize = crate::params::ml_dsa_44::PUBLICKEYBYTES;
pub const SIGNBYTES: usize = crate::params::ml_dsa_44::SIGNBYTES;
pub const KEYPAIRBYTES: usize = SECRETKEYBYTES + PUBLICKEYBYTES;

pub type Signature = [u8; SIGNBYTES];

/// A pair of private and public keys.
pub struct Keypair {
    pub secret: SecretKey,
    pub public: PublicKey
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
        crate::sign::ml_dsa_44::keypair(&mut pk, &mut sk, entropy);
        Keypair {
            secret: SecretKey::from_bytes(&sk),
            public: PublicKey::from_bytes(&pk)
        }
    }

    /// Convert a Keypair to a bytes array.
    /// 
    /// Returns an array containing private and public keys bytes
    pub fn to_bytes(&self) -> [u8; KEYPAIRBYTES] {
        let mut result = [0u8; KEYPAIRBYTES];
        result[..SECRETKEYBYTES].copy_from_slice(&self.secret.to_bytes());
        result[SECRETKEYBYTES..].copy_from_slice(&self.public.to_bytes());
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
        Keypair {
            secret: SecretKey::from_bytes(&bytes[..SECRETKEYBYTES]),
            public: PublicKey::from_bytes(&bytes[SECRETKEYBYTES..])
        }
    }

    /// Compute a signature for a given message.
    ///
    /// # Arguments
    ///
    /// * 'msg' - message to sign
    /// 
    /// Returns Option<Signature>
    pub fn sign(&self, msg: &[u8], ctx: Option<&[u8]>, hedged: bool) -> Option<Signature> {
        self.secret.sign(msg, ctx, hedged)
    }

    /// Verify a signature for a given message with a public key.
    /// 
    /// # Arguments
    /// 
    /// * 'msg' - message that is claimed to be signed
    /// * 'sig' - signature to verify
    /// 
    /// Returns 'true' if the verification process was successful, 'false' otherwise
    pub fn verify(&self, msg: &[u8], sig: &[u8], ctx: Option<&[u8]>) -> bool {
        self.public.verify(msg, sig, ctx)
    }

    /// Compute a signature for a given message.
    ///
    /// # Arguments
    ///
    /// * 'msg' - message to sign
    /// 
    /// Returns Option<Signature>
    pub fn prehash_sign(&self, msg: &[u8], ctx: Option<&[u8]>, hedged: bool, ph:crate::PH) -> Option<Signature> {
        self.secret.prehash_sign(msg, ctx, hedged, ph)
    }

    /// Verify a signature for a given message with a public key.
    /// 
    /// # Arguments
    /// 
    /// * 'msg' - message that is claimed to be signed
    /// * 'sig' - signature to verify
    /// 
    /// Returns 'true' if the verification process was successful, 'false' otherwise
    pub fn prehash_verify(&self, msg: &[u8], sig: &[u8], ctx: Option<&[u8]>, ph:crate::PH) -> bool {
        self.public.prehash_verify(msg, sig, ctx, ph)
    }
}

/// Private key.
pub struct SecretKey {
    pub bytes: [u8; SECRETKEYBYTES]
}

impl SecretKey {
    /// Returns a copy of underlying bytes.
    pub fn to_bytes(&self) -> [u8; SECRETKEYBYTES] {
       self.bytes.clone() 
    }

    /// Create a SecretKey from bytes.
    /// 
    /// # Arguments
    /// 
    /// * 'bytes' - private key bytes
    /// 
    /// Returns a SecretKey
    pub fn from_bytes(bytes: &[u8]) -> SecretKey {
        SecretKey {
            bytes: bytes.try_into().expect("")
        }
    }

    /// Compute a signature for a given message.
    ///
    /// # Arguments
    ///
    /// * 'msg' - message to sign
    /// * 'ctx' - context string
    /// * 'hedged' - wether to use RNG or not
    /// 
    /// Returns Option<Signature>
    pub fn sign(&self, msg: &[u8], ctx: Option<&[u8]>, hedged: bool) -> Option<Signature> {
        match ctx {
            Some(x) => {
                if x.len() > 255 {
                    return None;
                }
                let x_len = x.len();
                let msg_len = msg.len();
                let mut m = vec![0; msg_len + 2 + x_len];
                m[1] = x_len as u8;
                m[2..2+x_len].copy_from_slice(x);
                m[2+x_len..].copy_from_slice(msg);
                let mut sig: Signature = [0u8; SIGNBYTES];
                crate::sign::ml_dsa_44::signature(&mut sig, m.as_slice(), &self.bytes, hedged);
                Some(sig)
            },
            None => {
                let msg_len = msg.len();
                let mut m = vec![0; msg_len + 2];
                m[2..].copy_from_slice(msg);
                let mut sig: Signature = [0u8; SIGNBYTES];
                crate::sign::ml_dsa_44::signature(&mut sig, m.as_slice(), &self.bytes, hedged);
                Some(sig)
            }
        }
    }
    
    /// Compute a signature for a given message.
    /// 
    /// # Arguments
    /// 
    /// * 'msg' - message to sign
    /// * 'ctx' - context string
    /// * 'hedged' - wether to use RNG or not
    /// * 'ph' - pre-hash function
    /// 
    /// Returns Option<Signature>
    pub fn prehash_sign(&self, msg: &[u8], ctx: Option<&[u8]>, hedged: bool, ph:crate::PH) -> Option<Signature>  {
        let mut oid = [0u8; 11];
        let mut phm: Vec<u8> = Vec::new();
        match ph {
           crate::PH::SHA256 => {
                oid.copy_from_slice(&[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]);
                phm.extend_from_slice(Sha256::digest(msg).as_slice());
            },
           crate::PH::SHA512 => {
                oid.copy_from_slice(&[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03]);
                phm.extend_from_slice(Sha512::digest(msg).as_slice());
            },
        }
        match ctx {
            Some(x) => {
                if x.len() > 255 {
                    return None;
                }
                let x_len = x.len();
                let phm_len = phm.len();
                let mut m = vec![0; 2 + x_len + 11 + phm_len];
                m[0] = 1;
                m[1] = x_len as u8;
                m[2..2+x_len].copy_from_slice(x);
                m[2+x_len..2+x_len+11].copy_from_slice(&oid);
                m[2+x_len+11..].copy_from_slice(phm.as_slice());
                let mut sig: Signature = [0u8; SIGNBYTES];
                crate::sign::ml_dsa_44::signature(&mut sig, m.as_slice(), &self.bytes, hedged);
                Some(sig)
            },
            None => {
                let phm_len = phm.len();
                let mut m = vec![0; 2 + 11 + phm_len];
                m[0] = 1;
                m[2..2+11].copy_from_slice(&oid);
                m[2+11..].copy_from_slice(phm.as_slice());
                let mut sig: Signature = [0u8; SIGNBYTES];
                crate::sign::ml_dsa_44::signature(&mut sig, m.as_slice(), &self.bytes, hedged);
                Some(sig)
            }
        }
    }
}

pub struct PublicKey {
    pub bytes: [u8; PUBLICKEYBYTES]
}

impl PublicKey {
    /// Returns a copy of underlying bytes.
    pub fn to_bytes(&self) -> [u8; PUBLICKEYBYTES] {
        self.bytes.clone()
    }

    /// Create a PublicKey from bytes.
    /// 
    /// # Arguments
    /// 
    /// * 'bytes' - public key bytes
    /// 
    /// Returns a PublicKey
    pub fn from_bytes(bytes: &[u8]) -> PublicKey {
        PublicKey {
            bytes: bytes.try_into().expect("")
        }
    }

    /// Verify a signature for a given message with a public key.
    /// 
    /// # Arguments
    /// 
    /// * 'msg' - message that is claimed to be signed
    /// * 'sig' - signature to verify
    /// * 'ctx' - context string
    /// 
    /// Returns 'true' if the verification process was successful, 'false' otherwise
    pub fn verify(&self, msg: &[u8], sig: &[u8], ctx: Option<&[u8]>) -> bool {
        if sig.len() != SIGNBYTES {
            return false;
        }
        match ctx {
            Some(x) => {
                if x.len() > 255 {
                    return false;
                }
                let x_len = x.len();
                let msg_len = msg.len();
                let mut m = vec![0; msg_len + 2 + x_len];
                m[1] = x_len as u8;
                m[2..2+x_len].copy_from_slice(x);
                m[2+x_len..].copy_from_slice(msg);
                crate::sign::ml_dsa_44::verify(sig, m.as_slice(), &self.bytes)
            },
            None => {
                let msg_len = msg.len();
                let mut m = vec![0; msg_len + 2];
                m[2..].copy_from_slice(msg);
                crate::sign::ml_dsa_44::verify(sig, m.as_slice(), &self.bytes)
            }
        }
    }

    /// Verify a signature for a given message with a public key.
    /// 
    /// # Arguments
    /// 
    /// * 'msg' - message that is claimed to be signed
    /// * 'sig' - signature to verify
    /// * 'ctx' - context string
    /// * 'ph' - pre-hash function
    /// 
    /// Returns 'true' if the verification process was successful, 'false' otherwise
    pub fn prehash_verify(&self, msg: &[u8], sig: &[u8], ctx: Option<&[u8]>, ph:crate::PH) -> bool {
        if sig.len() != SIGNBYTES {
            return false;
        }
        let mut oid = [0u8; 11];
        let mut phm: Vec<u8> = Vec::new();
        match ph {
           crate::PH::SHA256 => {
                oid.copy_from_slice(&[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]);
                phm.extend_from_slice(Sha256::digest(msg).as_slice());
            },
           crate::PH::SHA512 => {
                oid.copy_from_slice(&[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03]);
                phm.extend_from_slice(Sha512::digest(msg).as_slice());
            },
        }
        match ctx {
            Some(x) => {
                if x.len() > 255 {
                    return false;
                }
                let x_len = x.len();
                let phm_len = phm.len();
                let mut m = vec![0; 2 + x_len + 11 + phm_len];
                m[0] = 1;
                m[1] = x_len as u8;
                m[2..2+x_len].copy_from_slice(x);
                m[2+x_len..2+x_len+11].copy_from_slice(&oid);
                m[2+x_len+11..].copy_from_slice(phm.as_slice());
                crate::sign::ml_dsa_44::verify(sig, m.as_slice(), &self.bytes)
            },
            None => {
                let phm_len = phm.len();
                let mut m = vec![0; 2 + 11 + phm_len];
                m[0] = 1;
                m[2..2+11].copy_from_slice(&oid);
                m[2+11..].copy_from_slice(phm.as_slice());
                crate::sign::ml_dsa_44::verify(sig, m.as_slice(), &self.bytes)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Keypair;
    #[test]
    fn self_verify_hedged() {
        const MSG_BYTES: usize = 94;
        let mut msg = [0u8; MSG_BYTES];
        crate::random_bytes(&mut msg, MSG_BYTES);
        let keys = Keypair::generate(None);
        let sig = keys.sign(&msg, None, true);
        assert!(keys.verify(&msg, &sig.unwrap(), None));
    }
    #[test]
    fn self_verify() {
        const MSG_BYTES: usize = 94;
        let mut msg = [0u8; MSG_BYTES];
        crate::random_bytes(&mut msg, MSG_BYTES);
        let keys = Keypair::generate(None);
        let sig = keys.sign(&msg, None, false);
        assert!(keys.verify(&msg, &sig.unwrap(), None));
    }
    #[test]
    fn self_verify_prehash_hedged() {
        const MSG_BYTES: usize = 94;
        let mut msg = [0u8; MSG_BYTES];
        crate::random_bytes(&mut msg, MSG_BYTES);
        let keys = Keypair::generate(None);
        let sig = keys.prehash_sign(&msg, None, true, crate::PH::SHA256);
        assert!(keys.prehash_verify(&msg, &sig.unwrap(), None, crate::PH::SHA256));
    }
    #[test]
    fn self_verify_prehash() {
        const MSG_BYTES: usize = 94;
        let mut msg = [0u8; MSG_BYTES];
        crate::random_bytes(&mut msg, MSG_BYTES);
        let keys = Keypair::generate(None);
        let sig = keys.prehash_sign(&msg, None, false, crate::PH::SHA256);
        assert!(keys.prehash_verify(&msg, &sig.unwrap(), None, crate::PH::SHA256));
    }
}