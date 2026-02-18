use crate::prehash::{prehash_bytes, PH};
use zeroize::ZeroizeOnDrop;

pub const SECRETKEYBYTES: usize = crate::params::ml_dsa_65::SECRETKEYBYTES;
pub const PUBLICKEYBYTES: usize = crate::params::ml_dsa_65::PUBLICKEYBYTES;
pub const SIGNBYTES: usize = crate::params::ml_dsa_65::SIGNBYTES;
pub const KEYPAIRBYTES: usize = SECRETKEYBYTES + PUBLICKEYBYTES;

pub type Signature = [u8; SIGNBYTES];

/// A pair of private and public keys.
pub struct Keypair {
    pub secret: SecretKey,
    pub public: PublicKey,
}

impl Keypair {
    /// Generate a Keypair instance.
    ///
    /// # Arguments
    ///
    /// * 'entropy' - optional bytes for determining the generation process
    ///
    /// Returns an instance of Keypair
    pub fn generate(entropy: Option<&[u8]>) -> Result<Keypair, crate::Error> {
        let mut pk = [0u8; PUBLICKEYBYTES];
        let mut sk = [0u8; SECRETKEYBYTES];
        crate::sign::ml_dsa_65::keypair(&mut pk, &mut sk, entropy)?;
        Ok(Keypair {
            secret: SecretKey::from_bytes(&sk)?,
            public: PublicKey::from_bytes(&pk)?,
        })
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
    pub fn from_bytes(bytes: &[u8]) -> Result<Keypair, crate::Error> {
        if bytes.len() != KEYPAIRBYTES {
            return Err(crate::Error::InvalidKeyLength {
                kind: "ml_dsa_65 keypair",
                expected: KEYPAIRBYTES,
                actual: bytes.len(),
            });
        }
        Ok(Keypair {
            secret: SecretKey::from_bytes(&bytes[..SECRETKEYBYTES])?,
            public: PublicKey::from_bytes(&bytes[SECRETKEYBYTES..])?,
        })
    }

    /// Compute a signature for a given message.
    ///
    /// # Arguments
    ///
    /// * 'msg' - message to sign
    ///
    /// Returns Option<Signature>
    pub fn sign(
        &self,
        msg: &[u8],
        ctx: Option<&[u8]>,
        rand: crate::RandomMode,
    ) -> Option<Signature> {
        self.secret.sign(msg, ctx, rand)
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
    pub fn prehash_sign(
        &self,
        msg: &[u8],
        ctx: Option<&[u8]>,
        rand: crate::RandomMode,
        ph: PH,
    ) -> Option<Signature> {
        self.secret.prehash_sign(msg, ctx, rand, ph)
    }

    /// Verify a signature for a given message with a public key.
    ///
    /// # Arguments
    ///
    /// * 'msg' - message that is claimed to be signed
    /// * 'sig' - signature to verify
    ///
    /// Returns 'true' if the verification process was successful, 'false' otherwise
    pub fn prehash_verify(&self, msg: &[u8], sig: &[u8], ctx: Option<&[u8]>, ph: PH) -> bool {
        self.public.prehash_verify(msg, sig, ctx, ph)
    }
}

/// Private key.
#[derive(ZeroizeOnDrop)]
pub struct SecretKey {
    bytes: [u8; SECRETKEYBYTES],
}

impl SecretKey {
    /// Returns a copy of underlying bytes.
    pub fn to_bytes(&self) -> [u8; SECRETKEYBYTES] {
        self.bytes
    }

    /// Create a SecretKey from bytes.
    ///
    /// # Arguments
    ///
    /// * 'bytes' - private key bytes
    ///
    /// Returns a SecretKey
    pub fn from_bytes(bytes: &[u8]) -> Result<SecretKey, crate::Error> {
        let bytes = bytes
            .try_into()
            .map_err(|_| crate::Error::InvalidKeyLength {
                kind: "ml_dsa_65 secret key",
                expected: SECRETKEYBYTES,
                actual: bytes.len(),
            })?;
        Ok(SecretKey { bytes })
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
    pub fn sign(
        &self,
        msg: &[u8],
        ctx: Option<&[u8]>,
        rand: crate::RandomMode,
    ) -> Option<Signature> {
        let m = crate::build_mprime(msg, ctx, false)?;
        let mut sig: Signature = [0u8; SIGNBYTES];
        crate::sign::ml_dsa_65::signature(&mut sig, m.as_slice(), &self.bytes, rand);
        Some(sig)
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
    pub fn prehash_sign(
        &self,
        msg: &[u8],
        ctx: Option<&[u8]>,
        rand: crate::RandomMode,
        ph: PH,
    ) -> Option<Signature> {
        let phm = prehash_bytes(ph, msg);
        let m = crate::build_mprime(phm.as_slice(), ctx, true)?;
        let mut sig: Signature = [0u8; SIGNBYTES];
        crate::sign::ml_dsa_65::signature(&mut sig, m.as_slice(), &self.bytes, rand);
        Some(sig)
    }

    #[cfg(feature = "acvp-internal")]
    pub fn sign_internal(&self, msg: &[u8], rand: crate::RandomMode) -> Option<Signature> {
        let mut sig: Signature = [0u8; SIGNBYTES];
        crate::sign::ml_dsa_65::signature(&mut sig, msg, &self.bytes, rand);
        Some(sig)
    }

    #[cfg(feature = "acvp-internal")]
    pub fn sign_mu(&self, mu: &[u8], rand: crate::RandomMode) -> Option<Signature> {
        let mut sig: Signature = [0u8; SIGNBYTES];
        crate::sign::ml_dsa_65::signature_mu(&mut sig, mu, &self.bytes, rand);
        Some(sig)
    }
}

pub struct PublicKey {
    bytes: [u8; PUBLICKEYBYTES],
}

impl PublicKey {
    /// Returns a copy of underlying bytes.
    pub fn to_bytes(&self) -> [u8; PUBLICKEYBYTES] {
        self.bytes
    }

    /// Create a PublicKey from bytes.
    ///
    /// # Arguments
    ///
    /// * 'bytes' - public key bytes
    ///
    /// Returns a PublicKey
    pub fn from_bytes(bytes: &[u8]) -> Result<PublicKey, crate::Error> {
        let bytes = bytes
            .try_into()
            .map_err(|_| crate::Error::InvalidKeyLength {
                kind: "ml_dsa_65 public key",
                expected: PUBLICKEYBYTES,
                actual: bytes.len(),
            })?;
        Ok(PublicKey { bytes })
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
        let Some(m) = crate::build_mprime(msg, ctx, false) else {
            return false;
        };
        crate::sign::ml_dsa_65::verify(sig, m.as_slice(), &self.bytes)
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
    pub fn prehash_verify(&self, msg: &[u8], sig: &[u8], ctx: Option<&[u8]>, ph: PH) -> bool {
        if sig.len() != SIGNBYTES {
            return false;
        }
        let phm = prehash_bytes(ph, msg);
        let Some(m) = crate::build_mprime(&phm, ctx, true) else {
            return false;
        };
        crate::sign::ml_dsa_65::verify(sig, m.as_slice(), &self.bytes)
    }

    #[cfg(feature = "acvp-internal")]
    pub fn verify_internal(&self, msg: &[u8], sig: &[u8]) -> bool {
        crate::sign::ml_dsa_65::verify(sig, msg, &self.bytes)
    }

    #[cfg(feature = "acvp-internal")]
    pub fn verify_mu(&self, mu: &[u8], sig: &[u8]) -> bool {
        crate::sign::ml_dsa_65::verify_mu(sig, mu, &self.bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::Keypair;
    use crate::prehash::PH;
    #[test]
    fn self_verify_hedged() {
        const MSG_BYTES: usize = 94;
        let mut msg = [0u8; MSG_BYTES];
        crate::random_bytes(&mut msg, MSG_BYTES);
        let keys = Keypair::generate(None).unwrap();
        let sig = keys.sign(&msg, None, crate::RandomMode::Hedged);
        assert!(keys.verify(&msg, &sig.unwrap(), None));
    }
    #[test]
    fn self_verify() {
        const MSG_BYTES: usize = 94;
        let mut msg = [0u8; MSG_BYTES];
        crate::random_bytes(&mut msg, MSG_BYTES);
        let keys = Keypair::generate(None).unwrap();
        let sig = keys.sign(&msg, None, crate::RandomMode::Deterministic);
        assert!(keys.verify(&msg, &sig.unwrap(), None));
    }
    #[test]
    fn self_verify_prehash_hedged() {
        const MSG_BYTES: usize = 94;
        let mut msg = [0u8; MSG_BYTES];
        crate::random_bytes(&mut msg, MSG_BYTES);
        let keys = Keypair::generate(None).unwrap();
        let sig = keys.prehash_sign(&msg, None, crate::RandomMode::Hedged, PH::SHA256);
        assert!(keys.prehash_verify(&msg, &sig.unwrap(), None, PH::SHA256));
    }
    #[test]
    fn self_verify_prehash() {
        const MSG_BYTES: usize = 94;
        let mut msg = [0u8; MSG_BYTES];
        crate::random_bytes(&mut msg, MSG_BYTES);
        let keys = Keypair::generate(None).unwrap();
        let sig = keys.prehash_sign(&msg, None, crate::RandomMode::Deterministic, PH::SHA256);
        assert!(keys.prehash_verify(&msg, &sig.unwrap(), None, PH::SHA256));
    }
}
