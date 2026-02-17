use sha2::{Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256, Digest as _};
use sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512, Shake128, 
    Shake256, Digest as _, digest::{Update, ExtendableOutput, XofReader},};

const OID_SHA224:   &[u8] = &[0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x04];
const OID_SHA256:   &[u8] = &[0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01];
const OID_SHA384:   &[u8] = &[0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x02];
const OID_SHA512:   &[u8] = &[0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x03];
const OID_SHA512_224: &[u8] = &[0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x05];
const OID_SHA512_256: &[u8] = &[0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x06];
const OID_SHA3_224: &[u8] = &[0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x07];
const OID_SHA3_256: &[u8] = &[0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x08];
const OID_SHA3_384: &[u8] = &[0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x09];
const OID_SHA3_512: &[u8] = &[0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x0A];
const OID_SHAKE128: &[u8] = &[0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x0B];
const OID_SHAKE256: &[u8] = &[0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x0C];

pub enum PH {
    SHA224,
    SHA256,
    SHA384,
    SHA512,
    SHA512_224,
    SHA512_256,
    SHA3_224,
    SHA3_256,
    SHA3_384,
    SHA3_512,
    SHAKE128,
    SHAKE256,
}

#[inline]
pub fn oid_bytes(ph: PH) -> &'static [u8] {
    match ph {
        PH::SHA224     => OID_SHA224,
        PH::SHA256     => OID_SHA256,
        PH::SHA384     => OID_SHA384,
        PH::SHA512     => OID_SHA512,
        PH::SHA512_224 => OID_SHA512_224,
        PH::SHA512_256 => OID_SHA512_256,
        PH::SHA3_224   => OID_SHA3_224,
        PH::SHA3_256   => OID_SHA3_256,
        PH::SHA3_384   => OID_SHA3_384,
        PH::SHA3_512   => OID_SHA3_512,
        PH::SHAKE128   => OID_SHAKE128,
        PH::SHAKE256   => OID_SHAKE256,
    }
}

pub fn prehash_bytes(ph: PH, msg: &[u8]) -> Vec<u8> {
    let hash: Vec<u8> = match ph {
        PH::SHA224 => { Sha224::digest(msg).to_vec() },
        PH::SHA256 => { Sha256::digest(msg).to_vec() },
        PH::SHA384 => { Sha384::digest(msg).to_vec() },
        PH::SHA512 => { Sha512::digest(msg).to_vec() },
        PH::SHA512_224 => { Sha512_224::digest(msg).to_vec() },
        PH::SHA512_256 => { Sha512_256::digest(msg).to_vec() },
        PH::SHA3_224 => { Sha3_224::digest(msg).to_vec() },
        PH::SHA3_256 => { Sha3_256::digest(msg).to_vec() },
        PH::SHA3_384 => { Sha3_384::digest(msg).to_vec() },
        PH::SHA3_512 => { Sha3_512::digest(msg).to_vec() },
        PH::SHAKE128 => {
            let mut h = Shake128::default();
            h.update(msg);
            let mut x = h.finalize_xof();
            let mut out = vec![0u8; 32];
            x.read(&mut out);
            out
        },  
        PH::SHAKE256 => {
            let mut h = Shake256::default();
            h.update(msg);
            let mut r = h.finalize_xof();
            let mut out = [0u8; 64];
            r.read(&mut out);
            out.to_vec()
        }
    };

    let oid = oid_bytes(ph);

    let mut phm = Vec::with_capacity(oid.len() + hash.len());
    phm.extend_from_slice(oid);      // najpierw OID
    phm.extend_from_slice(&hash);  // potem digest
    phm
}