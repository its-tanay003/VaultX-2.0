//! Cryptographic hashing and Ed25519 digital signatures for audit records.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::error::AuditError;

/// Computes SHA-256 hash of arbitrary byte payload formatted as lowercase hex string.
pub fn compute_payload_hash(payload: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(payload);
    hex::encode(hasher.finalize())
}

/// Computes canonical SHA-256 entry hash over audit event metadata.
///
/// Format: `id|run_id|event_type|actor_id|payload_hash|created_at|prev_hash`
pub fn compute_entry_hash(
    id: i64,
    run_id: Option<&str>,
    event_type: &str,
    actor_id: &str,
    payload_hash: &str,
    created_at: &str,
    prev_hash: &str,
) -> String {
    let canonical = format!(
        "{}|{}|{}|{}|{}|{}|{}",
        id,
        run_id.unwrap_or(""),
        event_type,
        actor_id,
        payload_hash,
        created_at,
        prev_hash
    );

    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    hex::encode(hasher.finalize())
}

/// Runtime cryptographic signer managing the dedicated Ed25519 audit keypair.
///
/// Crucial security invariant: The secret key is stored securely and never leaked
/// in debug formatting or error output.
#[derive(Clone)]
pub struct AuditSigner {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

impl AuditSigner {
    /// Generates a fresh random Ed25519 keypair using OS entropy.
    pub fn generate() -> Self {
        use rand::rngs::OsRng;
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
        }
    }

    /// Reconstructs signer from 32-byte raw secret key.
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(bytes);
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
        }
    }

    /// Loads the signing key from the specified path or generates a new one on first run.
    ///
    /// Persisted outside sandbox mounts with restrictive OS permissions.
    pub fn load_or_generate_from_file(path: &std::path::Path) -> Result<Self, AuditError> {
        if path.exists() {
            let bytes = std::fs::read(path)?;
            if bytes.len() != 32 {
                return Err(AuditError::Crypto(format!(
                    "Invalid key file length: expected 32 bytes, got {}",
                    bytes.len()
                )));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            Ok(Self::from_bytes(&arr))
        } else {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let signer = Self::generate();
            let key_bytes = signer.to_bytes();

            #[cfg(unix)]
            {
                use std::fs::OpenOptions;
                use std::io::Write;
                use std::os::unix::fs::OpenOptionsExt;
                let mut file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(path)?;
                file.write_all(&key_bytes)?;
            }

            #[cfg(not(unix))]
            {
                std::fs::write(path, key_bytes)?;
            }

            Ok(signer)
        }
    }

    /// Exports raw 32-byte secret key for secure keychain persistence.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    /// Returns the hex-encoded 32-byte public verifying key.
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.verifying_key.to_bytes())
    }

    /// Signs an entry_hash string and returns the 64-byte hex-encoded Ed25519 signature.
    pub fn sign_entry_hash(&self, entry_hash: &str) -> String {
        let sig: Signature = self.signing_key.sign(entry_hash.as_bytes());
        hex::encode(sig.to_bytes())
    }

    /// Verifies that an entry_hash was signed by this runtime's verifying key.
    pub fn verify_entry_signature(
        &self,
        entry_hash: &str,
        signature_hex: &str,
    ) -> Result<(), AuditError> {
        let sig_bytes = hex::decode(signature_hex)
            .map_err(|e| AuditError::Crypto(format!("Invalid signature hex encoding: {}", e)))?;

        if sig_bytes.len() != 64 {
            return Err(AuditError::Crypto(format!(
                "Invalid signature length: expected 64 bytes, got {}",
                sig_bytes.len()
            )));
        }

        let mut arr = [0u8; 64];
        arr.copy_from_slice(&sig_bytes);
        let signature = Signature::from_bytes(&arr);

        self.verifying_key
            .verify(entry_hash.as_bytes(), &signature)
            .map_err(|e| AuditError::Crypto(format!("Signature verification failed: {}", e)))
    }
}

impl std::fmt::Debug for AuditSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditSigner")
            .field("verifying_key", &self.public_key_hex())
            .field("signing_key", &"[REDACTED]")
            .finish()
    }
}
