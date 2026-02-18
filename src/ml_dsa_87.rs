//! High-level ML-DSA-87 API.
//!
//! # Modes
//! - Pure mode: [`Keypair::sign`] / [`Keypair::verify`]
//! - Pre-hash mode: [`Keypair::prehash_sign`] / [`Keypair::prehash_verify`]
//! - Internal mode (`acvp-internal`): `sign_internal`, `sign_mu`,
//!   `verify_internal`, `verify_mu`
//!
//! Use [`crate::RandomMode`] to control deterministic vs hedged signing.
//!
use crate::prehash::{prehash_bytes, PH};
use zeroize::ZeroizeOnDrop;

pub const SECRETKEYBYTES: usize = crate::params::ml_dsa_87::SECRETKEYBYTES;
pub const PUBLICKEYBYTES: usize = crate::params::ml_dsa_87::PUBLICKEYBYTES;
pub const SIGNBYTES: usize = crate::params::ml_dsa_87::SIGNBYTES;
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
    /// * `entropy` - optional bytes for determining the generation process
    ///
    /// # Returns
    /// A new [`Keypair`].
    ///
    /// # Errors
    /// Returns [`crate::Error::InvalidSeedLength`] if `entropy` is provided and has an invalid length.
    pub fn generate(entropy: Option<&[u8]>) -> Result<Keypair, crate::Error> {
        let mut pk = [0u8; PUBLICKEYBYTES];
        let mut sk = [0u8; SECRETKEYBYTES];
        crate::sign::ml_dsa_87::keypair(&mut pk, &mut sk, entropy)?;
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
    /// * `bytes` - private and public keys bytes
    ///
    /// # Returns
    /// A parsed [`Keypair`].
    ///
    /// # Errors
    /// Returns [`crate::Error::InvalidKeyLength`] if `bytes` has an invalid keypair length.
    pub fn from_bytes(bytes: &[u8]) -> Result<Keypair, crate::Error> {
        if bytes.len() != KEYPAIRBYTES {
            return Err(crate::Error::InvalidKeyLength {
                kind: "ml_dsa_87 keypair",
                expected: KEYPAIRBYTES,
                actual: bytes.len(),
            });
        }
        Ok(Keypair {
            secret: SecretKey::from_bytes(&bytes[..SECRETKEYBYTES])?,
            public: PublicKey::from_bytes(&bytes[SECRETKEYBYTES..])?,
        })
    }

    /// Compute a pure-mode ML-DSA signature over `msg`.
    ///
    /// # Arguments
    ///
    /// * `msg` - message to sign
    ///
    /// # Returns
    /// `Some(signature)` on success, or `None` when input validation fails
    /// (for example, if `ctx` is longer than 255 bytes).
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
    /// * `msg` - message that is claimed to be signed
    /// * `sig` - signature to verify
    ///
    /// Returns `true` if verification succeeds, and `false` otherwise
    pub fn verify(&self, msg: &[u8], sig: &[u8], ctx: Option<&[u8]>) -> bool {
        self.public.verify(msg, sig, ctx)
    }

    /// Compute a pre-hash-mode ML-DSA signature over `msg`.
    ///
    /// # Arguments
    ///
    /// * `msg` - message to sign
    ///
    /// # Returns
    /// `Some(signature)` on success, or `None` when input validation fails
    /// (for example, if `ctx` is longer than 255 bytes).
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
    /// * `msg` - message that is claimed to be signed
    /// * `sig` - signature to verify
    ///
    /// Returns `true` if verification succeeds, and `false` otherwise
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
    /// * `bytes` - private key bytes
    ///
    /// # Returns
    /// A parsed [`SecretKey`].
    ///
    /// # Errors
    /// Returns [`crate::Error::InvalidKeyLength`] if `bytes` has an invalid secret-key length.
    ///
    /// # Examples
    /// See [`crate::ml_dsa_44::SecretKey::from_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> Result<SecretKey, crate::Error> {
        let bytes = bytes
            .try_into()
            .map_err(|_| crate::Error::InvalidKeyLength {
                kind: "ml_dsa_87 secret key",
                expected: SECRETKEYBYTES,
                actual: bytes.len(),
            })?;
        Ok(SecretKey { bytes })
    }

    /// Compute a signature for a given message.
    ///
    /// # Arguments
    ///
    /// * `msg` - message to sign
    /// * `ctx` - context string
    /// * `rand` - randomness mode used for signing
    ///
    /// # Returns
    /// `Some(signature)` on success, or `None` when input validation fails.
    pub fn sign(
        &self,
        msg: &[u8],
        ctx: Option<&[u8]>,
        rand: crate::RandomMode,
    ) -> Option<Signature> {
        let m = crate::build_mprime(msg, ctx, false)?;
        let mut sig: Signature = [0u8; SIGNBYTES];
        crate::sign::ml_dsa_87::signature(&mut sig, m.as_slice(), &self.bytes, rand);
        Some(sig)
    }

    /// Compute a signature for a given message.
    ///
    /// # Arguments
    ///
    /// * `msg` - message to sign
    /// * `ctx` - context string
    /// * `rand` - randomness mode used for signing
    /// * `ph` - pre-hash function
    ///
    /// # Returns
    /// `Some(signature)` on success, or `None` when input validation fails.
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
        crate::sign::ml_dsa_87::signature(&mut sig, m.as_slice(), &self.bytes, rand);
        Some(sig)
    }

    #[cfg(feature = "acvp-internal")]
    /// Compute an internal-mode signature over already prepared input.
    ///
    /// This API is intended for ACVP/internal testing workflows.
    pub fn sign_internal(&self, msg: &[u8], rand: crate::RandomMode) -> Option<Signature> {
        let mut sig: Signature = [0u8; SIGNBYTES];
        crate::sign::ml_dsa_87::signature(&mut sig, msg, &self.bytes, rand);
        Some(sig)
    }

    #[cfg(feature = "acvp-internal")]
    /// Compute an internal-mode signature over a precomputed `mu` digest.
    ///
    /// This API is intended for ACVP/internal testing workflows.
    pub fn sign_mu(&self, mu: &[u8], rand: crate::RandomMode) -> Option<Signature> {
        let mut sig: Signature = [0u8; SIGNBYTES];
        crate::sign::ml_dsa_87::signature_mu(&mut sig, mu, &self.bytes, rand);
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
    /// * `bytes` - public key bytes
    ///
    /// # Returns
    /// A parsed [`PublicKey`].
    ///
    /// # Errors
    /// Returns [`crate::Error::InvalidKeyLength`] if `bytes` has an invalid public-key length.
    pub fn from_bytes(bytes: &[u8]) -> Result<PublicKey, crate::Error> {
        let bytes = bytes
            .try_into()
            .map_err(|_| crate::Error::InvalidKeyLength {
                kind: "ml_dsa_87 public key",
                expected: PUBLICKEYBYTES,
                actual: bytes.len(),
            })?;
        Ok(PublicKey { bytes })
    }

    /// Verify a signature for a given message with a public key.
    ///
    /// # Arguments
    ///
    /// * `msg` - message that is claimed to be signed
    /// * `sig` - signature to verify
    /// * `ctx` - context string
    ///
    /// Returns `true` if verification succeeds, and `false` otherwise
    pub fn verify(&self, msg: &[u8], sig: &[u8], ctx: Option<&[u8]>) -> bool {
        if sig.len() != SIGNBYTES {
            return false;
        }
        let Some(m) = crate::build_mprime(msg, ctx, false) else {
            return false;
        };
        crate::sign::ml_dsa_87::verify(sig, m.as_slice(), &self.bytes)
    }

    /// Verify a signature for a given message with a public key.
    ///
    /// # Arguments
    ///
    /// * `msg` - message that is claimed to be signed
    /// * `sig` - signature to verify
    /// * `ctx` - context string
    /// * `ph` - pre-hash function
    ///
    /// Returns `true` if verification succeeds, and `false` otherwise
    pub fn prehash_verify(&self, msg: &[u8], sig: &[u8], ctx: Option<&[u8]>, ph: PH) -> bool {
        if sig.len() != SIGNBYTES {
            return false;
        }
        let phm = prehash_bytes(ph, msg);
        let Some(m) = crate::build_mprime(&phm, ctx, true) else {
            return false;
        };
        crate::sign::ml_dsa_87::verify(sig, m.as_slice(), &self.bytes)
    }

    #[cfg(feature = "acvp-internal")]
    /// Verify an internal-mode signature over already prepared input.
    ///
    /// This API is intended for ACVP/internal testing workflows.
    pub fn verify_internal(&self, msg: &[u8], sig: &[u8]) -> bool {
        crate::sign::ml_dsa_87::verify(sig, msg, &self.bytes)
    }

    #[cfg(feature = "acvp-internal")]
    /// Verify an internal-mode signature over a precomputed `mu` digest.
    ///
    /// This API is intended for ACVP/internal testing workflows.
    pub fn verify_mu(&self, mu: &[u8], sig: &[u8]) -> bool {
        crate::sign::ml_dsa_87::verify_mu(sig, mu, &self.bytes)
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
