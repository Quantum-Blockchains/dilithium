use std::fs::File;
use std::path::Path;
use crystals_dilithium::{prehash::PH, RandomMode};
use serde_json::Value;

#[test]
fn acvp_key_gen() {
    let tv_file = File::open(Path::new("tests/json-files/ML-DSA-keyGen-FIPS204/internalProjection.json")).expect("failed to open prompt.json");
    
    let tv: acvp::KeyGenTests = serde_json::from_reader(tv_file).unwrap();
  
    for tg in tv.test_groups {
        for tc in tg.tests {
            match tg.parameter_set {
                acvp::ParameterSet::MLDSA44 => {
                    let kp = crystals_dilithium::ml_dsa_44::Keypair::generate(Some(&tc.seed));
                    assert_eq!(kp.secret.to_bytes(), tc.sk.as_slice(), "secret key mismatch");
                    assert_eq!(kp.public.to_bytes(), tc.pk.as_slice(), "public key mismatch");
                },
                acvp::ParameterSet::MLDSA65 => {
                    let kp = crystals_dilithium::ml_dsa_65::Keypair::generate(Some(&tc.seed));
                    assert_eq!(kp.secret.to_bytes(), tc.sk.as_slice(), "secret key mismatch");
                    assert_eq!(kp.public.to_bytes(), tc.pk.as_slice(), "public key mismatch");
                },
                acvp::ParameterSet::MLDSA87 => {
                    let kp = crystals_dilithium::ml_dsa_87::Keypair::generate(Some(&tc.seed));
                    assert_eq!(kp.secret.to_bytes(), tc.sk.as_slice(), "secret key mismatch");
                    assert_eq!(kp.public.to_bytes(), tc.pk.as_slice(), "public key mismatch");
                }
            }
        }
    }
}

#[test]
fn acvp_sig_gen() {
    let tv_file = File::open(Path::new("tests/json-files/ML-DSA-sigGen-FIPS204/internalProjection.json")).expect("failed to open prompt.json");
    
    let tv: acvp::SigGenTests = serde_json::from_reader(tv_file).unwrap();
  
    for tg in tv.test_groups {
        for tc in tg.tests {
            let rand = match (tg.deterministic, tc.rnd.is_empty()) {
                (true,  _)    => RandomMode::Deterministic,
                (false, false) => RandomMode::Fixed(tc.rnd.to_vec()), // ← referencja, nie move
                (false, true)  => RandomMode::Hedged,
            };

            let ph = if tg.pre_hash == acvp::PreHash::PreHash {
                match tc.hash_alg.as_str() {
                    "SHA2-224" => PH::SHA224,
                    "SHA2-256" => PH::SHA256,
                    "SHA2-384" => PH::SHA384,
                    "SHA2-512" => PH::SHA512,
                    "SHA2-512/224" => PH::SHA512_224,
                    "SHA2-512/256" => PH::SHA512_256,
                    "SHA3-224" => PH::SHA3_224,
                    "SHA3-256" => PH::SHA3_256,
                    "SHA3-384" => PH::SHA3_384,
                    "SHA3-512" => PH::SHA3_512,
                    "SHAKE-128" => PH::SHAKE128,
                    "SHAKE-256" => PH::SHAKE256,
                    _ => {
                        continue;
                    },
                }
            } else {
                PH::SHA256
            };
            
            
            if tg.external_mu {
                match &tg.parameter_set {
                    acvp::ParameterSet::MLDSA44 => {
                        let sk = crystals_dilithium::ml_dsa_44::SecretKey::from_bytes(&tc.sk);
                        let sig = sk.sign_mu(&tc.mu, rand).unwrap();
                        assert_eq!(sig.as_slice(), tc.signature.as_slice(), "signature mismatch");
                    },
                    acvp::ParameterSet::MLDSA65 => {
                        let sk = crystals_dilithium::ml_dsa_65::SecretKey::from_bytes(&tc.sk);
                        let sig = sk.sign_mu(&tc.mu, rand).unwrap();
                        assert_eq!(sig.as_slice(), tc.signature.as_slice(), "signature mismatch");
                    },
                    acvp::ParameterSet::MLDSA87 => {
                        let sk = crystals_dilithium::ml_dsa_87::SecretKey::from_bytes(&tc.sk);
                        let sig = sk.sign_mu(&tc.mu, rand).unwrap();
                        assert_eq!(sig.as_slice(), tc.signature.as_slice(), "signature mismatch");
                    },
                }
            } else {
                match (&tg.parameter_set, &tg.pre_hash) {
                    (acvp::ParameterSet::MLDSA44, acvp::PreHash::Pure) => {
                        let sk = crystals_dilithium::ml_dsa_44::SecretKey::from_bytes(&tc.sk);
                        let sig = sk.sign(&tc.message, Some(&tc.context), rand).unwrap();
                        assert_eq!(sig.as_slice(), tc.signature.as_slice(), "signature mismatch");
                    },
                    (acvp::ParameterSet::MLDSA44, acvp::PreHash::None) => {
                        let sk = crystals_dilithium::ml_dsa_44::SecretKey::from_bytes(&tc.sk);
                        let sig = sk.sign_internal(&tc.message, rand).unwrap();
                        assert_eq!(sig.as_slice(), tc.signature.as_slice(), "signature mismatch");
                    },
                    (acvp::ParameterSet::MLDSA44, acvp::PreHash::PreHash) => {
                        let sk = crystals_dilithium::ml_dsa_44::SecretKey::from_bytes(&tc.sk);
                        let sig = sk.prehash_sign(&tc.message, Some(&tc.context), rand, ph).unwrap();
                        assert_eq!(sig.as_slice(), tc.signature.as_slice(), "signature mismatch");
                    },
                    (acvp::ParameterSet::MLDSA65, acvp::PreHash::Pure) => {
                        let sk = crystals_dilithium::ml_dsa_65::SecretKey::from_bytes(&tc.sk);
                        let sig = sk.sign(&tc.message, Some(&tc.context), rand).unwrap();
                        assert_eq!(sig.as_slice(), tc.signature.as_slice(), "signature mismatch");
                    },
                    (acvp::ParameterSet::MLDSA65, acvp::PreHash::None) => {
                        let sk = crystals_dilithium::ml_dsa_65::SecretKey::from_bytes(&tc.sk);
                        let sig = sk.sign_internal(&tc.message, rand).unwrap();
                        assert_eq!(sig.as_slice(), tc.signature.as_slice(), "signature mismatch");
                    },
                    (acvp::ParameterSet::MLDSA65, acvp::PreHash::PreHash) => {
                        let sk = crystals_dilithium::ml_dsa_65::SecretKey::from_bytes(&tc.sk);
                        let sig = sk.prehash_sign(&tc.message, Some(&tc.context), rand, ph).unwrap();
                        assert_eq!(sig.as_slice(), tc.signature.as_slice(), "signature mismatch");
                    },
                    (acvp::ParameterSet::MLDSA87, acvp::PreHash::Pure) => {
                        let sk = crystals_dilithium::ml_dsa_87::SecretKey::from_bytes(&tc.sk);
                        let sig = sk.sign(&tc.message, Some(&tc.context), rand).unwrap();
                        assert_eq!(sig.as_slice(), tc.signature.as_slice(), "signature mismatch");
                    },
                    (acvp::ParameterSet::MLDSA87, acvp::PreHash::None) => {
                        let sk = crystals_dilithium::ml_dsa_87::SecretKey::from_bytes(&tc.sk);
                        let sig = sk.sign_internal(&tc.message, rand).unwrap();
                        assert_eq!(sig.as_slice(), tc.signature.as_slice(), "signature mismatch");
                    },
                    (acvp::ParameterSet::MLDSA87, acvp::PreHash::PreHash) => {
                        let sk = crystals_dilithium::ml_dsa_87::SecretKey::from_bytes(&tc.sk);
                        let sig = sk.prehash_sign(&tc.message, Some(&tc.context), rand, ph).unwrap();
                        assert_eq!(sig.as_slice(), tc.signature.as_slice(), "signature mismatch");
                    },
                }
            }
        }
    }
}

#[test]
fn acvp_sig_ver() {
    let tv_file = File::open(Path::new("tests/json-files/ML-DSA-sigVer-FIPS204/internalProjection.json")).expect("failed to open prompt.json");
    
    let tv: acvp::SigVerTests = serde_json::from_reader(tv_file).unwrap();
  
    for tg in tv.test_groups {
        for tc in tg.tests {
            let ph = if tg.pre_hash == acvp::PreHash::PreHash {
                match tc.hash_alg.as_str() {
                    "SHA2-224" => PH::SHA224,
                    "SHA2-256" => PH::SHA256,
                    "SHA2-384" => PH::SHA384,
                    "SHA2-512" => PH::SHA512,
                    "SHA2-512/224" => PH::SHA512_224,
                    "SHA2-512/256" => PH::SHA512_256,
                    "SHA3-224" => PH::SHA3_224,
                    "SHA3-256" => PH::SHA3_256,
                    "SHA3-384" => PH::SHA3_384,
                    "SHA3-512" => PH::SHA3_512,
                    "SHAKE-128" => PH::SHAKE128,
                    "SHAKE-256" => PH::SHAKE256,
                    _ => {
                        continue;
                    },
                }
            } else {
                PH::SHA256
            };
            
            if tg.external_mu {
                match &tg.parameter_set {
                    acvp::ParameterSet::MLDSA44 => {
                        let pk = crystals_dilithium::ml_dsa_44::PublicKey::from_bytes(&tc.pk);
                        assert_eq!(pk.verify_mu(&tc.mu, &tc.signature), tc.test_passed, "signature mismatch");
                    },
                    acvp::ParameterSet::MLDSA65 => {
                        let pk = crystals_dilithium::ml_dsa_65::PublicKey::from_bytes(&tc.pk);
                        assert_eq!(pk.verify_mu(&tc.mu, &tc.signature), tc.test_passed, "signature mismatch");
                    },
                    acvp::ParameterSet::MLDSA87 => {
                        let pk = crystals_dilithium::ml_dsa_87::PublicKey::from_bytes(&tc.pk);
                        assert_eq!(pk.verify_mu(&tc.mu, &tc.signature), tc.test_passed, "signature mismatch");
                    },
                }
            } else {
                match (&tg.parameter_set, &tg.pre_hash) {
                    (acvp::ParameterSet::MLDSA44, acvp::PreHash::Pure) => {
                        let pk = crystals_dilithium::ml_dsa_44::PublicKey::from_bytes(&tc.pk);
                        assert_eq!(pk.verify(&tc.message, &tc.signature, Some(&tc.context)), tc.test_passed, "signature mismatch");
                    },
                    (acvp::ParameterSet::MLDSA44, acvp::PreHash::None) => {
                        let pk = crystals_dilithium::ml_dsa_44::PublicKey::from_bytes(&tc.pk);
                        assert_eq!(pk.verify_internal(&tc.message, &tc.signature), tc.test_passed, "signature mismatch");
                    },
                    (acvp::ParameterSet::MLDSA44, acvp::PreHash::PreHash) => {
                        let pk = crystals_dilithium::ml_dsa_44::PublicKey::from_bytes(&tc.pk);
                        assert_eq!(pk.prehash_verify(&tc.message, &tc.signature, Some(&tc.context), ph), tc.test_passed, "signature mismatch");
                    },
                    (acvp::ParameterSet::MLDSA65, acvp::PreHash::Pure) => {
                        let pk = crystals_dilithium::ml_dsa_65::PublicKey::from_bytes(&tc.pk);
                        assert_eq!(pk.verify(&tc.message, &tc.signature, Some(&tc.context)), tc.test_passed, "signature mismatch");
                    },
                    (acvp::ParameterSet::MLDSA65, acvp::PreHash::None) => {
                        let pk = crystals_dilithium::ml_dsa_65::PublicKey::from_bytes(&tc.pk);
                        assert_eq!(pk.verify_internal(&tc.message, &tc.signature), tc.test_passed, "signature mismatch");
                    },
                    (acvp::ParameterSet::MLDSA65, acvp::PreHash::PreHash) => {
                        let pk = crystals_dilithium::ml_dsa_65::PublicKey::from_bytes(&tc.pk);
                        assert_eq!(pk.prehash_verify(&tc.message, &tc.signature, Some(&tc.context), ph), tc.test_passed, "signature mismatch");
                    },
                    (acvp::ParameterSet::MLDSA87, acvp::PreHash::Pure) => {
                        let pk = crystals_dilithium::ml_dsa_87::PublicKey::from_bytes(&tc.pk);
                        assert_eq!(pk.verify(&tc.message, &tc.signature, Some(&tc.context)), tc.test_passed, "signature mismatch");
                    },
                    (acvp::ParameterSet::MLDSA87, acvp::PreHash::None) => {
                        let pk = crystals_dilithium::ml_dsa_87::PublicKey::from_bytes(&tc.pk);
                        assert_eq!(pk.verify_internal(&tc.message, &tc.signature), tc.test_passed, "signature mismatch");
                    },
                    (acvp::ParameterSet::MLDSA87, acvp::PreHash::PreHash) => {
                        let pk = crystals_dilithium::ml_dsa_87::PublicKey::from_bytes(&tc.pk);
                        assert_eq!(pk.prehash_verify(&tc.message, &tc.signature, Some(&tc.context), ph), tc.test_passed, "signature mismatch");
                    },
                }
            }
        }
    }
}

mod acvp {
    use serde::{Deserialize, Serialize};

    #[derive(Deserialize, Serialize)]
    pub enum ParameterSet {
        #[serde(rename = "ML-DSA-44")]
        MLDSA44,

        #[serde(rename = "ML-DSA-65")]
        MLDSA65,

        #[serde(rename = "ML-DSA-87")]
        MLDSA87,
    }

    #[derive(Deserialize, Serialize)]
    pub enum SignatureInterface {
        #[serde(rename = "external")]
        External,

        #[serde(rename = "internal")]
        Internal,
    }

    #[derive(Deserialize, Serialize, PartialEq)]
    pub enum PreHash {
        #[serde(rename = "pure")]
        Pure,

        #[serde(rename = "preHash")]
        PreHash,

        #[serde(rename = "none")]
        None,
    }

    #[derive(Deserialize, Serialize)]
    pub struct KeyGenTests {
        #[serde(rename = "testGroups")]
        pub test_groups: Vec<KeyGenGroup>,
    }

    #[derive(Deserialize, Serialize)]
    pub struct KeyGenGroup {
        #[serde(rename = "tgId")]
        pub id: usize,

        #[serde(rename = "parameterSet")]
        pub parameter_set: ParameterSet,

        pub tests: Vec<KeyGenCase>,
    }

    #[derive(Deserialize, Serialize)]
    pub struct KeyGenCase {
        #[serde(rename = "tcId")]
        pub id: usize,

        #[serde(with = "hex::serde")]
        pub seed: Vec<u8>,

        #[serde(with = "hex::serde")]
        pub pk: Vec<u8>,

        #[serde(with = "hex::serde")]
        pub sk: Vec<u8>,
    }

    #[derive(Deserialize, Serialize)]
    pub struct SigGenTests {
        #[serde(rename = "testGroups")]
        pub test_groups: Vec<SigGenGroup>,
    }

    #[derive(Deserialize, Serialize)]
    pub struct SigGenGroup {
        #[serde(rename = "tgId")]
        pub id: usize,

        #[serde(rename = "parameterSet")]
        pub parameter_set: ParameterSet,

        #[serde(rename = "deterministic")]
        pub deterministic: bool,

        #[serde(rename = "signatureInterface")]
        pub signature_interface: SignatureInterface,

        #[serde(rename = "preHash")]
        pub pre_hash: PreHash,

        #[serde(rename = "externalMu")]
        pub external_mu: bool,

        pub tests: Vec<SigGenCase>,
    }

    #[derive(Deserialize, Serialize)]
    pub struct SigGenCase {
        #[serde(rename = "tcId")]
        pub id: usize,

        #[serde(default, with = "hex::serde")]
        pub message: Vec<u8>,

        #[serde(default, with = "hex::serde")]
        pub mu: Vec<u8>,

        #[serde(default, with = "hex::serde")]
        pub rnd: Vec<u8>,

        #[serde(with = "hex::serde")]
        pub pk: Vec<u8>,

        #[serde(with = "hex::serde")]
        pub sk: Vec<u8>,

        #[serde(default, with = "hex::serde")]
        pub context: Vec<u8>,

        #[serde(rename = "hashAlg")]
        pub hash_alg: String,

        #[serde(with = "hex::serde")]
        pub signature: Vec<u8>,
    }

    #[derive(Deserialize, Serialize)]
    pub struct SigVerTests {
        #[serde(rename = "testGroups")]
        pub test_groups: Vec<SigVerGroup>,
    }

    #[derive(Deserialize, Serialize)]
    pub struct SigVerGroup {
        #[serde(rename = "tgId")]
        pub id: usize,

        #[serde(rename = "parameterSet")]
        pub parameter_set: ParameterSet,

        #[serde(rename = "signatureInterface")]
        pub signature_interface: SignatureInterface,

        #[serde(rename = "preHash")]
        pub pre_hash: PreHash,

        #[serde(rename = "externalMu")]
        pub external_mu: bool,

        pub tests: Vec<SigVerCase>,
    }
    
    #[derive(Deserialize, Serialize)]
    pub struct SigVerCase {
        #[serde(rename = "tcId")]
        pub id: usize,

        #[serde(rename = "testPassed")]
        pub test_passed: bool,

        #[serde(default, with = "hex::serde")]
        pub message: Vec<u8>,

        #[serde(default, with = "hex::serde")]
        pub mu: Vec<u8>,

        #[serde(with = "hex::serde")]
        pub pk: Vec<u8>,

        #[serde(with = "hex::serde")]
        pub sk: Vec<u8>,

        #[serde(default, with = "hex::serde")]
        pub context: Vec<u8>,

        #[serde(rename = "hashAlg")]
        pub hash_alg: String,

        #[serde(with = "hex::serde")]
        pub signature: Vec<u8>,
    }

}

