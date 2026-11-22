//! Shared serialization/signing vectors (issue #130).
//!
//! [`testdata/vectors.json`](../testdata/vectors.json) is checked in and is
//! consumed by both this crate's unit tests and the generated TypeScript
//! client's tests. Agreement on these vectors proves the two clients derive
//! the same Ed25519 signatures, public keys and domain-separated hashes, so a
//! transaction signed in the browser is interpreted identically by Rust.
use workstream_core::hash::Hash;

/// Domain-separated hash used for stable request/correlation identifiers.
/// The separator prevents cross-protocol reuse of a digest.
pub fn domain_hash(domain: &str, payload: &str) -> workstream_core::H256 {
    Hash::sha256_concat(&[b"WS:v1:api:", domain.as_bytes(), b":", payload.as_bytes()])
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn vectors() -> serde_json::Value {
        serde_json::from_str(include_str!("../testdata/vectors.json")).unwrap()
    }

    #[test]
    fn rust_matches_shared_ed25519_vectors() {
        let v = vectors();
        let seed = hex(v["seed"].as_str().unwrap());
        let key = SigningKey::from_bytes(&seed.try_into().unwrap());
        assert_eq!(
            key.verifying_key().to_bytes().to_vec(),
            hex(v["public_key"].as_str().unwrap()),
            "public key must match the shared vector"
        );
        let message = hex(v["message"].as_str().unwrap());
        let sig = key.sign(&message);
        assert_eq!(
            sig.to_bytes().to_vec(),
            hex(v["signature"].as_str().unwrap()),
            "Ed25519 signature must be deterministic and match the vector"
        );
        // Verify as well, mirroring the TypeScript verification path.
        let verifying =
            VerifyingKey::from_bytes(&hex(v["public_key"].as_str().unwrap()).try_into().unwrap())
                .unwrap();
        let parsed =
            Signature::from_bytes(&hex(v["signature"].as_str().unwrap()).try_into().unwrap());
        assert!(verifying.verify(&message, &parsed).is_ok());
    }

    #[test]
    fn rust_matches_shared_domain_hash() {
        let v = vectors();
        let got = domain_hash(
            v["domain"].as_str().unwrap(),
            v["payload"].as_str().unwrap(),
        );
        assert_eq!(
            got.as_bytes().to_vec(),
            hex(v["domain_hash"].as_str().unwrap())
        );
    }
}
