# crystals-dilithium

Pure Rust implementation of:
- CRYSTALS-Dilithium (`dilithium2`, `dilithium3`, `dilithium5`)
- ML-DSA (`ml_dsa_44`, `ml_dsa_65`, `ml_dsa_87`)

The codebase is based on the reference implementation and includes test coverage against internal vectors and ACVP-style datasets.

## Security note
This project has not undergone a formal third-party security audit. Use in production should include your own security review.

## Build
```bash
cargo build --release
```

## Quick start (Dilithium)
```rust
use crystals_dilithium::dilithium2::Keypair;

let seed = [42u8; 32];
let msg = b"hello world";

let keypair = Keypair::generate(Some(&seed)).unwrap();
let signature = keypair.sign(msg);
let is_verified = keypair.verify(msg, &signature);

assert!(is_verified);
```

## Quick start (ML-DSA)
```rust
use crystals_dilithium::ml_dsa_44::Keypair;
use crystals_dilithium::RandomMode;

let seed = [7u8; 32];
let msg = b"hello world";

let keypair = Keypair::generate(Some(&seed)).unwrap();
let sig = keypair.sign(msg, None, RandomMode::Deterministic).unwrap();
assert!(keypair.verify(msg, &sig, None));
```

## Error handling (recommended)
Key generation and key deserialization now return `Result` to avoid panics on malformed input.

```rust
use crystals_dilithium::dilithium2::PublicKey;

fn parse_public_key(bytes: &[u8]) -> Result<PublicKey, crystals_dilithium::Error> {
    PublicKey::from_bytes(bytes)
}
```

The same applies to:
- `Keypair::generate(...)`
- `Keypair::from_bytes(...)`
- `SecretKey::from_bytes(...)`
- `PublicKey::from_bytes(...)`

## Testing
```bash
cargo test --all-targets --all-features
```

ACVP internal test vectors are feature-gated:
```bash
cargo test --test acvp_internal --features acvp-internal
```

## Benchmarks
Criterion benchmarks:
```bash
cargo bench
```

## Docs
```bash
cargo doc --open
```

## License
GPL-3.0-only. See [LICENSE](LICENSE).
