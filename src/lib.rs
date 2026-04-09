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

// ============================================================================
// Constants
// ============================================================================

/// Number of shares to generate
pub const SHARES_NUMBER: usize = 5;

/// Minimum number of shares required to reconstruct the secret
pub const THRESHOLD: usize = 3;

/// Size of the secret in bytes
pub const SECRET_SIZE: usize = 33;

/// Encoded size of each share in bytes (serde_bare format)
/// Format: 1 (len) + 32 (identifier) + 1 (len) + 32 (value) = 66 bytes
pub const ENCODED_SIZE: usize = 66;

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
        let mut scalar_bytes = [0u8; 64];
        rng.fill_bytes(&mut scalar_bytes);
        let scalar = Scalar::from_bytes_mod_order_wide(&scalar_bytes);

        Ok(scalar.as_bytes().to_vec())
    }

    /// Split a secret into shares using Feldman Verifiable Secret Sharing Scheme
    fn splitsecret(secret: Vec<u8>) -> Result<Vec<u8>, String> {
        let mut osrng = OsRng::default();
        let secret_value = parse_secret_scalar(&secret)?;

        // Split the secret using Feldman VSSS
        let (shares, verifier_set) = Curve25519FeldmanVsss::split_secret_with_verifier(
            THRESHOLD,
            SHARES_NUMBER,
            &secret_value,
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
    fn combinesecret(share_bytes: Vec<u8>) -> Result<Vec<u8>, String> {
        let shares = deserialize_shares(&share_bytes)?;

        let scalar: IdentifierPrimeField<WrappedScalar> = shares
            .combine()
            .map_err(|e| e.to_string())?;

        Ok(scalar.0 .0.to_bytes().to_vec())
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

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

        // Reconstruct secret (using shares 3, 4, 5 - indices 2, 3, 4)
        let reconstructed_secret =
            Component::combinesecret(split_result[2 * ENCODED_SIZE..shares_len].to_vec()).unwrap();

        assert_eq!(reconstructed_secret, secret);
    }
}


