use rand::RngCore;

use crate::{fips202, packing, params, poly, poly::Poly, polyvec, polyvec::lvl5::{Polyveck, Polyvecl}};
const K: usize = params::ml_dsa_87::K;
const L: usize = params::ml_dsa_87::L;

/// Generate random bytes.
/// 
/// # Arguments
/// 
/// * 'bytes' - an array to fill with random data
/// * 'n' - number of bytes to generate
fn random_bytes(bytes: &mut [u8], n: usize) {
    rand::prelude::thread_rng().try_fill_bytes(&mut bytes[..n]).unwrap();
}

/// Generate public and private key.
/// 
/// # Arguments
/// 
/// * 'pk' - preallocated buffer for public key
/// * 'sk' - preallocated buffer for private key
/// * 'seed' - optional seed; if None [random_bytes()] is used for randomness generation
pub fn keypair(pk: &mut [u8], sk: &mut [u8], seed: Option<&[u8]>) {
    let mut init_seed = [0u8; params::SEEDBYTES];
    match seed {
        Some(x) => init_seed.copy_from_slice(x),
        None => random_bytes(&mut init_seed, params::SEEDBYTES)
    };

    const SEEDBUF_LEN: usize = 2 * params::SEEDBYTES + params::CRHBYTES;
    let mut seedbuf = [0u8; SEEDBUF_LEN];
    fips202::shake256(&mut seedbuf, SEEDBUF_LEN, &init_seed, params::SEEDBYTES);

    let mut rho = [0u8; params::SEEDBYTES];
    rho.copy_from_slice(&seedbuf[..params::SEEDBYTES]);

    let mut rhoprime = [0u8; params::CRHBYTES];
    rhoprime.copy_from_slice(&seedbuf[params::SEEDBYTES..params::SEEDBYTES + params::CRHBYTES]);

    let mut key = [0u8; params::SEEDBYTES];
    key.copy_from_slice(&seedbuf[params::SEEDBYTES + params::CRHBYTES..]);

    let mut mat = [Polyvecl::default(); K];
    polyvec::lvl5::matrix_expand(&mut mat, &rho);

    let mut s1 = Polyvecl::default();
    polyvec::lvl5::l_uniform_eta(&mut s1, &rhoprime, 0);

    let mut s2 = Polyveck::default();
    polyvec::lvl5::k_uniform_eta(&mut s2, &rhoprime, L as u16);

    let mut s1hat = s1;
    polyvec::lvl5::l_ntt(&mut s1hat);

    let mut t1 = Polyveck::default();
    polyvec::lvl5::matrix_pointwise_montgomery(&mut t1, &mat, &s1hat);
    polyvec::lvl5::k_reduce(&mut t1);
    polyvec::lvl5::k_invntt_tomont(&mut t1);
    polyvec::lvl5::k_add(&mut t1, &s2);
    polyvec::lvl5::k_caddq(&mut t1);

    let mut t0 = Polyveck::default();
    polyvec::lvl5::k_power2round(&mut t1, &mut t0);

    packing::ml_dsa_87::pack_pk(pk, &rho, &t1);

    let mut tr = [0u8; params::TR_BYTES];
    fips202::shake256(&mut tr, params::TR_BYTES, pk, params::ml_dsa_87::PUBLICKEYBYTES);

    packing::ml_dsa_87::pack_sk(sk, &rho, &tr, &key, &t0, &s1, &s2);
}

/// Compute a signature for a given message from a private (secret) key.
///
/// # Arguments
///
/// * 'sig' - preallocated with at least SIGNBYTES buffer
/// * 'msg' - message to sign
/// * 'sk' - private key to use
/// * 'hedged' - indicates wether to randomize the signature or to act deterministicly
pub fn signature(sig: &mut [u8], msg: &[u8], sk: &[u8], hedged: bool) {
    let mut rho = [0u8; params::SEEDBYTES];
    let mut tr = [0u8; params::TR_BYTES];
    let mut keymu = [0u8; params::SEEDBYTES + params::CRHBYTES];
    let mut t0 = Polyveck::default();
    let mut s1 = Polyvecl::default();
    let mut s2 = Polyveck::default();

    packing::ml_dsa_87::unpack_sk(&mut rho, &mut tr, &mut keymu[..params::SEEDBYTES], &mut t0, &mut s1, &mut s2, &sk);

    let mut state = fips202::KeccakState::default();
    fips202::shake256_absorb(&mut state, &tr, params::TR_BYTES);
    fips202::shake256_absorb(&mut state, &msg, msg.len());
    fips202::shake256_finalize(&mut state);
    fips202::shake256_squeeze(&mut keymu[params::SEEDBYTES..], params::CRHBYTES, &mut state);

    let mut rnd = [0u8; params::SEEDBYTES];
    if hedged {
        random_bytes(&mut rnd, params::SEEDBYTES);
    }
    state = fips202::KeccakState::default();
    fips202::shake256_absorb(&mut state, &keymu[..params::SEEDBYTES], params::SEEDBYTES);
    fips202::shake256_absorb(&mut state, &rnd, params::SEEDBYTES);
    fips202::shake256_absorb(&mut state, &keymu[params::SEEDBYTES..], params::CRHBYTES);
    fips202::shake256_finalize(&mut state);
    let mut rhoprime = [0u8; params::CRHBYTES];
    fips202::shake256_squeeze(&mut rhoprime, params::CRHBYTES, &mut state);

    let mut mat = [Polyvecl::default(); K];
    polyvec::lvl5::matrix_expand(&mut mat, &rho);
    polyvec::lvl5::l_ntt(&mut s1);
    polyvec::lvl5::k_ntt(&mut s2);
    polyvec::lvl5::k_ntt(&mut t0);

    let mut nonce: u16 = 0;
    let mut y = Polyvecl::default();
    let mut w1 = Polyveck::default();
    let mut w0 = Polyveck::default();
    let mut cp = Poly::default();
    let mut h = Polyveck::default();
    loop {
        polyvec::lvl5::l_uniform_gamma1(&mut y, &rhoprime, nonce);
        nonce += 1;

        let mut z = y;
        polyvec::lvl5::l_ntt(&mut z);
        polyvec::lvl5::matrix_pointwise_montgomery(&mut w1, &mat, &z);
        polyvec::lvl5::k_reduce(&mut w1);
        polyvec::lvl5::k_invntt_tomont(&mut w1);
        polyvec::lvl5::k_caddq(&mut w1);

        polyvec::lvl5::k_decompose(&mut w1, &mut w0);
        polyvec::lvl5::k_pack_w1(sig, &w1);

        state.init();
        fips202::shake256_absorb(&mut state, &keymu[params::SEEDBYTES..], params::CRHBYTES);
        fips202::shake256_absorb(&mut state, &sig, K * params::ml_dsa_87::POLYW1_PACKEDBYTES);
        fips202::shake256_finalize(&mut state);
        fips202::shake256_squeeze(sig, params::SEEDBYTES, &mut state);

        poly::lvl5::challenge(&mut cp, sig);
        poly::ntt(&mut cp);

        polyvec::lvl5::l_pointwise_poly_montgomery(&mut z, &cp, &s1);
        polyvec::lvl5::l_invntt_tomont(&mut z);
        polyvec::lvl5::l_add(&mut z, &y);
        polyvec::lvl5::l_reduce(&mut z);

        if polyvec::lvl5::l_chknorm(&z, (params::ml_dsa_87::GAMMA1 - params::ml_dsa_87::BETA) as i32) > 0 {
            continue;
        }

        polyvec::lvl5::k_pointwise_poly_montgomery(&mut h, &cp, &s2);
        polyvec::lvl5::k_invntt_tomont(&mut h);
        polyvec::lvl5::k_sub(&mut w0, &h);
        polyvec::lvl5::k_reduce(&mut w0);

        if polyvec::lvl5::k_chknorm(&w0, (params::ml_dsa_87::GAMMA2 - params::ml_dsa_87::BETA) as i32) > 0 {
            continue;
        }

        polyvec::lvl5::k_pointwise_poly_montgomery(&mut h, &cp, &t0);
        polyvec::lvl5::k_invntt_tomont(&mut h);
        polyvec::lvl5::k_reduce(&mut h);

        if polyvec::lvl5::k_chknorm(&h, params::ml_dsa_87::GAMMA2 as i32) > 0 {
            continue;
        }

        polyvec::lvl5::k_add(&mut w0, &h);

        let n = polyvec::lvl5::k_make_hint(&mut h, &w0, &w1);

        if n > params::ml_dsa_87::OMEGA as i32 {
            continue;
        }

        packing::ml_dsa_87::pack_sig(sig, None, &z, &h);

        return;
    }
}

/// Verify a signature for a given message with a public key.
/// 
/// # Arguments
/// 
/// * 'sig' - signature to verify
/// * 'm' - message that is claimed to be signed
/// * 'pk' - public key
/// 
/// Returns 'true' if the verification process was successful, 'false' otherwise
pub fn verify(sig: &[u8], m: &[u8], pk: &[u8]) -> bool {
    let mut buf = [0u8; K * crate::params::ml_dsa_87::POLYW1_PACKEDBYTES];
    let mut rho = [0u8; params::SEEDBYTES];
    let mut mu = [0u8; params::CRHBYTES];
    let mut c = [0u8; params::SEEDBYTES];
    let mut c2 = [0u8; params::SEEDBYTES];
    let mut cp = Poly::default();
    let (mut mat, mut z) = ([Polyvecl::default(); K], Polyvecl::default());
    let (mut t1, mut w1, mut h) = (
        Polyveck::default(),
        Polyveck::default(),
        Polyveck::default(),
    );
    let mut state = fips202::KeccakState::default(); // shake256_init()

    if sig.len() != crate::params::ml_dsa_87::SIGNBYTES {
        return false;
    }

    packing::ml_dsa_87::unpack_pk(&mut rho, &mut t1, pk);
    if !packing::ml_dsa_87::unpack_sig(&mut c, &mut z, &mut h, sig) {
        return false;
    }
    if polyvec::lvl5::l_chknorm(
        &z,
        (crate::params::ml_dsa_87::GAMMA1 - crate::params::ml_dsa_87::BETA) as i32,
    ) > 0
    {
        return false;
    }

    // Compute CRH(CRH(rho, t1), msg)
    fips202::shake256(
        &mut mu,
        params::SEEDBYTES,
        pk,
        crate::params::ml_dsa_87::PUBLICKEYBYTES,
    );
    fips202::shake256_absorb(&mut state, &mu, params::SEEDBYTES);
    fips202::shake256_absorb(&mut state, m, m.len());
    fips202::shake256_finalize(&mut state);
    fips202::shake256_squeeze(&mut mu, params::CRHBYTES, &mut state);

    // Matrix-vector multiplication; compute Az - c2^dt1
    poly::lvl5::challenge(&mut cp, &c);
    polyvec::lvl5::matrix_expand(&mut mat, &rho);

    polyvec::lvl5::l_ntt(&mut z);
    polyvec::lvl5::matrix_pointwise_montgomery(&mut w1, &mat, &z);

    poly::ntt(&mut cp);
    polyvec::lvl5::k_shiftl(&mut t1);
    polyvec::lvl5::k_ntt(&mut t1);
    let t1_2 = t1.clone();
    polyvec::lvl5::k_pointwise_poly_montgomery(&mut t1, &cp, &t1_2);

    polyvec::lvl5::k_sub(&mut w1, &t1);
    polyvec::lvl5::k_reduce(&mut w1);
    polyvec::lvl5::k_invntt_tomont(&mut w1);

    // Reconstruct w1
    polyvec::lvl5::k_caddq(&mut w1);
    polyvec::lvl5::k_use_hint(&mut w1, &h);
    polyvec::lvl5::k_pack_w1(&mut buf, &w1);

    // Call random oracle and verify challenge
    state.init();
    fips202::shake256_absorb(&mut state, &mu, params::CRHBYTES);
    fips202::shake256_absorb(
        &mut state,
        &buf,
        K * crate::params::ml_dsa_87::POLYW1_PACKEDBYTES,
    );
    fips202::shake256_finalize(&mut state);
    fips202::shake256_squeeze(&mut c2, params::SEEDBYTES, &mut state);
    // Doesn't require constant time equality check
    if c != c2 {
        return false;
    }
    true
}

//#[cfg(test)]
//mod tests {
//    #[test]
//    fn keypair() {
//        let seed: [u8; crate::params::SEEDBYTES] = [];
//        let mut pk = [0u8; crate::params::ml_dsa_87::PUBLICKEYBYTES];
//        let mut sk = [0u8; crate::params::ml_dsa_87::SECRETKEYBYTES];
//        super::keypair(&mut pk, &mut sk, Some(&seed));
//
//        let test_pk: [u8; crate::params::ml_dsa_87::PUBLICKEYBYTES] = [];
//        let test_sk: [u8; crate::params::ml_dsa_87::SECRETKEYBYTES] = [];
//        assert_eq!(test_pk, pk);
//        assert_eq!(test_sk, sk);
//        assert_eq!(pk[..crate::params::SEEDBYTES], sk[..crate::params::SEEDBYTES]);
//    }
//
//    #[test]
//    fn signature() {
//        let msg: [u8; 33] = [];
//        let sk: [u8; crate::params::ml_dsa_87::SECRETKEYBYTES] = [];
//        let mut sig = [0u8; crate::params::ml_dsa_87::SIGNBYTES];
//        super::signature(&mut sig, &msg, &sk, false);
//
//        let test_sig: [u8; crate::params::ml_dsa_87::SIGNBYTES + 33] =  [];
//        assert!(test_sig[..crate::params::ml_dsa_87::SIGNBYTES] == sig);
//    }
//
//    #[test]
//    fn verify() {
//        let msg: [u8; 33] = [];
//        let sig: [u8; crate::params::ml_dsa_87::SIGNBYTES + 33] = [];
//        let pk: [u8; crate::params::ml_dsa_87::PUBLICKEYBYTES] = [];
//        assert!(super::verify(&sig[..crate::params::ml_dsa_87::SIGNBYTES], &msg, &pk));
//    }
//}
