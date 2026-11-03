//! Signature verification for WorkStream (issue #19)
//!
//! Supports multiple signature schemes for flexibility:
//!
//! - **secp256k1 (ECDSA)**: Ethereum-compatible signatures
//! - **Ed25519**: Fast, modern signatures (Solana, etc.)
//!
//! All verification is deterministic and zkVM-compatible.

use ed25519_dalek::{Signature as Ed25519Sig, Verifier, VerifyingKey as Ed25519Key};
use k256::ecdsa::{Signature as EcdsaSig, VerifyingKey as Secp256k1Key};
use serde::{Deserialize, Serialize};
use workstream_core::{Error, Result};

/// Supported signature algorithms.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignatureAlgorithm {
    /// ECDSA over secp256k1 (Ethereum-compatible)
    Secp256k1,
    /// Ed25519 (Solana, etc.)
    Ed25519,
}

/// A signature with its algorithm tag.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Signature {
    /// The signature algorithm used.
    pub algorithm: SignatureAlgorithm,
    /// Raw signature bytes.
    pub bytes: Vec<u8>,
}

impl Signature {
    /// Create a new signature with the given algorithm and bytes.
    pub fn new(algorithm: SignatureAlgorithm, bytes: Vec<u8>) -> Self {
        Self { algorithm, bytes }
    }

    /// Create a secp256k1 ECDSA signature from raw bytes.
    pub fn secp256k1(bytes: Vec<u8>) -> Self {
        Self::new(SignatureAlgorithm::Secp256k1, bytes)
    }

    /// Create an Ed25519 signature from raw bytes.
    pub fn ed25519(bytes: Vec<u8>) -> Self {
        Self::new(SignatureAlgorithm::Ed25519, bytes)
    }
}

/// A public key with its algorithm tag.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicKey {
    /// The signature algorithm this key is for.
    pub algorithm: SignatureAlgorithm,
    /// Raw public key bytes.
    pub bytes: Vec<u8>,
}

impl PublicKey {
    /// Create a new public key with the given algorithm and bytes.
    pub fn new(algorithm: SignatureAlgorithm, bytes: Vec<u8>) -> Self {
        Self { algorithm, bytes }
    }

    /// Create a secp256k1 public key from raw bytes (33 or 65 bytes).
    pub fn secp256k1(bytes: Vec<u8>) -> Self {
        Self::new(SignatureAlgorithm::Secp256k1, bytes)
    }

    /// Create an Ed25519 public key from raw bytes (32 bytes).
    pub fn ed25519(bytes: Vec<u8>) -> Self {
        Self::new(SignatureAlgorithm::Ed25519, bytes)
    }
}

/// Verify a signature against a message and public key.
///
/// Returns `true` if the signature is valid, `false` otherwise.
/// Returns an error only for malformed inputs (wrong sizes, invalid encoding).
pub fn verify(message: &[u8], signature: &Signature, public_key: &PublicKey) -> Result<bool> {
    // Algorithms must match
    if signature.algorithm != public_key.algorithm {
        return Err(Error::Crypto(
            "signature and public key algorithm mismatch".to_string(),
        ));
    }

    match signature.algorithm {
        SignatureAlgorithm::Secp256k1 => {
            verify_secp256k1(message, &signature.bytes, &public_key.bytes)
        }
        SignatureAlgorithm::Ed25519 => verify_ed25519(message, &signature.bytes, &public_key.bytes),
    }
}

/// Verify a secp256k1 ECDSA signature.
fn verify_secp256k1(message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool> {
    // Parse the public key
    let key = Secp256k1Key::from_sec1_bytes(public_key)
        .map_err(|e| Error::Crypto(format!("invalid secp256k1 public key: {}", e)))?;

    // Parse the signature
    let sig = EcdsaSig::from_slice(signature)
        .map_err(|e| Error::Crypto(format!("invalid secp256k1 signature: {}", e)))?;

    // Verify (note: message should already be hashed for ECDSA)
    match key.verify(message, &sig) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Verify an Ed25519 signature.
fn verify_ed25519(message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool> {
    // Parse the public key (32 bytes)
    let key_bytes: [u8; 32] = public_key
        .try_into()
        .map_err(|_| Error::Crypto("ed25519 public key must be 32 bytes".to_string()))?;

    let key = Ed25519Key::from_bytes(&key_bytes)
        .map_err(|e| Error::Crypto(format!("invalid ed25519 public key: {}", e)))?;

    // Parse the signature (64 bytes)
    let sig_bytes: [u8; 64] = signature
        .try_into()
        .map_err(|_| Error::Crypto("ed25519 signature must be 64 bytes".to_string()))?;

    let sig = Ed25519Sig::from_bytes(&sig_bytes);

    // Verify
    match key.verify(message, &sig) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Legacy verification function for backward compatibility.
///
/// Requires an explicit algorithm to prevent cross-algorithm attacks.
/// For new code, use the typed `verify()` function with Signature/PublicKey structs.
#[deprecated(note = "use verify() with typed Signature and PublicKey")]
pub fn verify_raw(
    message: &[u8],
    algorithm: SignatureAlgorithm,
    signature: &[u8],
    public_key: &[u8],
) -> Result<bool> {
    match algorithm {
        SignatureAlgorithm::Secp256k1 => verify_secp256k1(message, signature, public_key),
        SignatureAlgorithm::Ed25519 => verify_ed25519(message, signature, public_key),
    }
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey as Ed25519SigningKey;
    use k256::ecdsa::{signature::Signer, SigningKey as Secp256k1SigningKey};

    #[test]
    fn secp256k1_sign_verify() {
        let signing_key = Secp256k1SigningKey::random(&mut rand::rng());
        let verifying_key = signing_key.verifying_key();

        let message = b"test message for secp256k1";
        let sig: EcdsaSig = signing_key.sign(message);

        let signature = Signature::secp256k1(sig.to_bytes().to_vec());
        let public_key = PublicKey::secp256k1(verifying_key.to_sec1_bytes().to_vec());

        let result = verify(message, &signature, &public_key).unwrap();
        assert!(result, "valid signature should verify");
    }

    #[test]
    fn secp256k1_invalid_signature() {
        let signing_key = Secp256k1SigningKey::random(&mut rand::rng());
        let verifying_key = signing_key.verifying_key();

        let message = b"test message";
        let sig: EcdsaSig = signing_key.sign(message);

        let signature = Signature::secp256k1(sig.to_bytes().to_vec());
        let public_key = PublicKey::secp256k1(verifying_key.to_sec1_bytes().to_vec());

        // Verify against wrong message
        let wrong_message = b"wrong message";
        let result = verify(wrong_message, &signature, &public_key).unwrap();
        assert!(!result, "signature should not verify for wrong message");
    }

    #[test]
    fn ed25519_sign_verify() {
        let signing_key = Ed25519SigningKey::generate(&mut rand::rng());
        let verifying_key = signing_key.verifying_key();

        let message = b"test message for ed25519";
        let sig = signing_key.sign(message);

        let signature = Signature::ed25519(sig.to_bytes().to_vec());
        let public_key = PublicKey::ed25519(verifying_key.to_bytes().to_vec());

        let result = verify(message, &signature, &public_key).unwrap();
        assert!(result, "valid signature should verify");
    }

    #[test]
    fn ed25519_invalid_signature() {
        let signing_key = Ed25519SigningKey::generate(&mut rand::rng());
        let verifying_key = signing_key.verifying_key();

        let message = b"test message";
        let sig = signing_key.sign(message);

        let signature = Signature::ed25519(sig.to_bytes().to_vec());
        let public_key = PublicKey::ed25519(verifying_key.to_bytes().to_vec());

        // Verify against wrong message
        let wrong_message = b"wrong message";
        let result = verify(wrong_message, &signature, &public_key).unwrap();
        assert!(!result, "signature should not verify for wrong message");
    }

    #[test]
    fn algorithm_mismatch_error() {
        let signing_key = Ed25519SigningKey::generate(&mut rand::rng());
        let verifying_key = signing_key.verifying_key();

        let message = b"test message";
        let sig = signing_key.sign(message);

        // Create signature with wrong algorithm tag
        let signature = Signature::secp256k1(sig.to_bytes().to_vec());
        let public_key = PublicKey::ed25519(verifying_key.to_bytes().to_vec());

        let result = verify(message, &signature, &public_key);
        assert!(result.is_err(), "algorithm mismatch should error");
    }

    #[test]
    fn invalid_public_key_format() {
        let message = b"test";
        let signature = Signature::ed25519(vec![0u8; 64]);
        let public_key = PublicKey::ed25519(vec![0u8; 16]); // Wrong size

        let result = verify(message, &signature, &public_key);
        assert!(result.is_err(), "invalid key size should error");
    }

    #[test]
    fn invalid_signature_format() {
        let signing_key = Ed25519SigningKey::generate(&mut rand::rng());
        let verifying_key = signing_key.verifying_key();

        let message = b"test";
        let signature = Signature::ed25519(vec![0u8; 32]); // Wrong size
        let public_key = PublicKey::ed25519(verifying_key.to_bytes().to_vec());

        let result = verify(message, &signature, &public_key);
        assert!(result.is_err(), "invalid signature size should error");
    }

    #[test]
    fn secp256k1_compressed_and_uncompressed_keys() {
        let signing_key = Secp256k1SigningKey::random(&mut rand::rng());
        let verifying_key = signing_key.verifying_key();

        let message = b"test message";
        let sig: EcdsaSig = signing_key.sign(message);

        // Test with compressed key (33 bytes)
        let compressed = verifying_key.to_sec1_bytes();
        assert_eq!(compressed.len(), 33);

        let signature = Signature::secp256k1(sig.to_bytes().to_vec());
        let public_key = PublicKey::secp256k1(compressed.to_vec());

        let result = verify(message, &signature, &public_key).unwrap();
        assert!(result, "compressed key should work");

        // Test with uncompressed key (65 bytes)
        let uncompressed = verifying_key.to_sec1_point(false);
        let signature2 = Signature::secp256k1(sig.to_bytes().to_vec());
        let public_key2 = PublicKey::secp256k1(uncompressed.as_bytes().to_vec());

        let result2 = verify(message, &signature2, &public_key2).unwrap();
        assert!(result2, "uncompressed key should work");
    }

    #[test]
    fn different_signers_produce_invalid_verification() {
        let signer1 = Ed25519SigningKey::generate(&mut rand::rng());
        let signer2 = Ed25519SigningKey::generate(&mut rand::rng());

        let message = b"test message";
        let sig = signer1.sign(message);

        // Verify with signer2's public key
        let signature = Signature::ed25519(sig.to_bytes().to_vec());
        let public_key = PublicKey::ed25519(signer2.verifying_key().to_bytes().to_vec());

        let result = verify(message, &signature, &public_key).unwrap();
        assert!(!result, "signature from different signer should not verify");
    }

    #[test]
    fn empty_message() {
        let signing_key = Ed25519SigningKey::generate(&mut rand::rng());
        let verifying_key = signing_key.verifying_key();

        let message = b"";
        let sig = signing_key.sign(message);

        let signature = Signature::ed25519(sig.to_bytes().to_vec());
        let public_key = PublicKey::ed25519(verifying_key.to_bytes().to_vec());

        let result = verify(message, &signature, &public_key).unwrap();
        assert!(result, "empty message should work");
    }

    #[test]
    fn large_message() {
        let signing_key = Ed25519SigningKey::generate(&mut rand::rng());
        let verifying_key = signing_key.verifying_key();

        // 1MB message
        let message = vec![0xAB; 1024 * 1024];
        let sig = signing_key.sign(&message);

        let signature = Signature::ed25519(sig.to_bytes().to_vec());
        let public_key = PublicKey::ed25519(verifying_key.to_bytes().to_vec());

        let result = verify(&message, &signature, &public_key).unwrap();
        assert!(result, "large message should work");
    }
}
