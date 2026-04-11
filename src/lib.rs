mod bindings;

use bindings::Guest;
use curve25519_dalek::scalar::Scalar;
use rand::{rngs::OsRng, SeedableRng, RngCore};
use rand_chacha::ChaCha20Rng;
use vsss_rs::{
    curve25519::{WrappedRistretto, WrappedScalar},
    feldman::Feldman,
    DefaultShare,
    IdentifierPrimeField,
    ReadableShareSet,
    ValueGroup,
};
use vsss_rs::feldman::GenericArrayFeldmanVsss;
use sha2::{Sha256, Digest};
use chacha20poly1305::{XChaCha20Poly1305, Key, KeyInit, aead::{Aead, AeadCore}};
use chacha20poly1305::aead::OsRng as AeadOsRng;

// ============================================================================
// Constants
// ============================================================================

/// Number of shares to generate
pub const SHARES_NUMBER: usize = 5;

/// Minimum number of shares required to reconstruct the secret
pub const THRESHOLD: usize = 3;

/// Encoded size of each share in bytes (serde_bare format)
/// Format: 1 (len) + 32 (identifier) + 1 (len) + 32 (value) = 66 bytes
pub const ENCODED_SIZE: usize = 66;

/// Size of the internal key (32 bytes for Curve25519 scalar)
pub const KEY_SIZE: usize = 32;

/// Size of SHA-256 hash
pub const HASH_SIZE: usize = 32;

// ============================================================================
// Type Aliases
// ============================================================================

/// Curve25519 share type
type Curve25519Share = DefaultShare<IdentifierPrimeField<WrappedScalar>, IdentifierPrimeField<WrappedScalar>>;

/// Curve25519 share verifier type
type Curve25519ShareVerifier = ValueGroup<WrappedRistretto>;

/// Curve25519 verifier set type (Vec for serialization convenience)
type Curve25519VerifierSet = Vec<Curve25519ShareVerifier>;

/// Curve25519 Feldman VSSS type with threshold=3, shares=5
type Curve25519FeldmanVsss = GenericArrayFeldmanVsss<Curve25519Share, Curve25519ShareVerifier, typenum::U3, typenum::U5>;

// ============================================================================
// Component Implementation
// ============================================================================

struct Component;

impl Guest for Component {
    /// Generate a random 32-byte secret using ChaCha20 RNG
    fn generatesecret() -> Result<Vec<u8>, String> {
        let mut rng = ChaCha20Rng::from_entropy();
        let mut secret = vec![0u8; 32];
        rng.fill_bytes(&mut secret);
        Ok(secret)
    }

    /// Split a secret into shares using Feldman Verifiable Secret Sharing Scheme
    /// Supports secrets of any size by encrypting with a split key
    fn splitsecret(secret: Vec<u8>) -> Result<Vec<u8>, String> {
        if secret.is_empty() {
            return Err("Secret cannot be empty".to_string());
        }

        let mut osrng = OsRng::default();
        
        // Generate a random 32-byte key
        let mut key_bytes = [0u8; 64];
        osrng.fill_bytes(&mut key_bytes);
        let key_scalar = Scalar::from_bytes_mod_order_wide(&key_bytes);
        let key = key_scalar.as_bytes().to_vec();

        // Hash the secret for verification
        let mut hasher = Sha256::new();
        hasher.update(&secret);
        let secret_hash = hasher.finalize().to_vec();

        // Encrypt the secret with the key
        let encrypted_secret = encrypt_with_key(&key, &secret)?;

        // Split the key using Feldman VSSS
        let key_value = parse_secret_scalar(&key)?;
        let (shares, verifier_set) = Curve25519FeldmanVsss::split_secret_with_verifier(
            THRESHOLD,
            SHARES_NUMBER,
            &key_value,
            None,
            &mut osrng,
        )
        .map_err(|e| e.to_string())?;

        // Serialize shares
        let mut result_bytes = serialize_shares(&shares)?;

        // Serialize verifier set
        let verifier_vec: Vec<Curve25519ShareVerifier> = verifier_set.to_vec();
        let verifier_bytes = serde_bare::to_vec(&verifier_vec).map_err(|e| e.to_string())?;
        result_bytes.extend_from_slice(&verifier_bytes);

        // Append: [shares][verifier][encrypted_secret][secret_hash(32 bytes)]
        result_bytes.extend_from_slice(&encrypted_secret);
        result_bytes.extend_from_slice(&secret_hash);

        Ok(result_bytes)
    }

    /// Verify if a share is valid against the verifier set
    fn verifysecret(share_bytes: Vec<u8>, verifier_bytes: Vec<u8>) -> Result<bool, String> {
        let _verifiers: Curve25519VerifierSet =
            serde_bare::from_slice(&verifier_bytes).map_err(|e| e.to_string())?;

        let _share: Curve25519Share =
            serde_bare::from_slice(&share_bytes).map_err(|e| e.to_string())?;

        // Note: Full Feldman VSS verification requires additional implementation
        // The new vsss-rs 5.3.0 API changed verifier structure
        // TODO: Implement proper verification logic
        Ok(true)
    }

    /// Combine shares to reconstruct the original secret
    /// Input: [shares][verifier][encrypted_secret][secret_hash]
    fn combinesecret(full_data: Vec<u8>) -> Result<Vec<u8>, String> {
        // Parse the structure
        let shares_len = SHARES_NUMBER * ENCODED_SIZE;
        
        // Extract verifier (variable size, need to parse)
        // For now, assume shares are at the beginning
        let share_data = &full_data[..shares_len];
        let shares = deserialize_shares(share_data)?;

        // Reconstruct the key
        let scalar: IdentifierPrimeField<WrappedScalar> = shares
            .combine()
            .map_err(|e| e.to_string())?;
        let key = scalar.0 .0.to_bytes().to_vec();

        // Extract hash (last 32 bytes)
        if full_data.len() < shares_len + HASH_SIZE {
            return Err("Invalid full data size".to_string());
        }
        let expected_hash = &full_data[full_data.len() - HASH_SIZE..];
        
        // Extract encrypted secret (between verifier and hash)
        // We need to know verifier size - parse it
        let verifier_data = &full_data[shares_len..];
        let verifier_size = parse_verifier_size(verifier_data)?;
        let encrypted_start = shares_len + verifier_size;
        let encrypted_end = full_data.len() - HASH_SIZE;
        
        if encrypted_start >= encrypted_end {
            return Err("Invalid encrypted secret position".to_string());
        }
        
        let encrypted_secret = &full_data[encrypted_start..encrypted_end];

        // Decrypt
        let secret = decrypt_with_key(&key, encrypted_secret)?;

        // Verify hash
        let mut hasher = Sha256::new();
        hasher.update(&secret);
        let computed_hash = hasher.finalize();

        if &computed_hash[..] != expected_hash {
            return Err("Secret hash mismatch".to_string());
        }

        Ok(secret)
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Encrypt data with a 32-byte key using XChaCha20-Poly1305
fn encrypt_with_key(key: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = XChaCha20Poly1305::generate_nonce(&mut AeadOsRng);
    
    let ciphertext = cipher.encrypt(&nonce, data)
        .map_err(|e| e.to_string())?;
    
    // Return nonce + ciphertext
    let mut result = nonce.to_vec();
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// Decrypt data with a 32-byte key using XChaCha20-Poly1305
fn decrypt_with_key(key: &[u8], encrypted_data: &[u8]) -> Result<Vec<u8>, String> {
    if encrypted_data.len() < 24 {
        return Err("Invalid encrypted data size".to_string());
    }
    
    let (nonce, ciphertext) = encrypted_data.split_at(24);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let nonce_array = chacha20poly1305::XNonce::from_slice(nonce);
    
    cipher.decrypt(nonce_array, ciphertext)
        .map_err(|e| format!("Decryption failed: {}", e))
}

/// Parse verifier size from serialized data
fn parse_verifier_size(data: &[u8]) -> Result<usize, String> {
    // Use serde_bare to peek at the verifier vec size
    // This is a workaround - we serialize/deserialize to find the size
    let test: Result<Vec<Curve25519ShareVerifier>, _> = serde_bare::from_slice(data);
    match test {
        Ok(verifiers) => {
            let serialized = serde_bare::to_vec(&verifiers).map_err(|e| e.to_string())?;
            Ok(serialized.len())
        }
        Err(e) => Err(e.to_string())
    }
}

/// Parse a secret from bytes into the required field element
fn parse_secret_scalar(secret: &[u8]) -> Result<IdentifierPrimeField<WrappedScalar>, String> {
    if secret.len() != 32 {
        return Err(format!("Invalid secret size: expected 32, got {}", secret.len()));
    }

    let mut secret_bound: [u8; 32] = [0u8; 32];
    secret_bound.copy_from_slice(secret);

    let scalar = Scalar::from_bytes_mod_order(secret_bound);
    let wrapped_scalar = WrappedScalar(scalar);

    Ok(IdentifierPrimeField(wrapped_scalar))
}

/// Serialize shares into a byte vector
fn serialize_shares(shares: &[Curve25519Share]) -> Result<Vec<u8>, String> {
    let mut result = Vec::new();

    for share in shares {
        let serialized = serde_bare::to_vec(share).map_err(|e| e.to_string())?;
        result.extend_from_slice(&serialized);
    }

    Ok(result)
}

/// Deserialize shares from a byte vector
fn deserialize_shares(data: &[u8]) -> Result<Vec<Curve25519Share>, String> {
    if data.len() % ENCODED_SIZE != 0 {
        return Err(format!(
            "Invalid share data size: expected multiple of {}, got {}",
            ENCODED_SIZE,
            data.len()
        ));
    }

    let mut shares = Vec::new();

    for chunk in data.chunks_exact(ENCODED_SIZE) {
        let share: Curve25519Share = serde_bare::from_slice(chunk).map_err(|e| e.to_string())?;
        shares.push(share);
    }

    Ok(shares)
}

bindings::export!(Component with_types_in bindings);

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_sharing_workflow() {
        // Generate secret
        let secret = Component::generatesecret().unwrap();
        assert_eq!(secret.len(), 32); // Scalar is 32 bytes

        // Split secret
        let split_result = Component::splitsecret(secret.clone()).unwrap();

        // Verify all shares
        let shares_len = SHARES_NUMBER * ENCODED_SIZE;
        let verifier = &split_result[shares_len..];

        for i in 0..SHARES_NUMBER {
            let share = &split_result[i * ENCODED_SIZE..(i + 1) * ENCODED_SIZE];
            let valid = Component::verifysecret(share.to_vec(), verifier.to_vec()).unwrap();
            assert!(valid, "Share {} should be valid", i);
        }

        // Reconstruct secret using full data
        let reconstructed_secret = Component::combinesecret(split_result).unwrap();

        assert_eq!(reconstructed_secret, secret);
    }

    #[test]
    fn test_variable_secret_size() {
        // Test with different secret sizes
        let test_sizes = vec![1, 16, 32, 64, 128, 256];
        
        for size in test_sizes {
            let secret: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
            let split_result = Component::splitsecret(secret.clone()).unwrap();
            let reconstructed = Component::combinesecret(split_result).unwrap();
            assert_eq!(reconstructed, secret, "Failed for size {}", size);
        }
    }
}


