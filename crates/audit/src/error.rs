//! Structured audit and verification error definitions.

use thiserror::Error;

/// Specific integrity violation detected during audit log verification.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum VerificationError {
    /// The audit database contains zero events.
    #[error("Audit log is empty")]
    EmptyLog,

    /// A gap or disorder was found in the sequential ID chain.
    #[error("Broken sequence: expected event ID {expected}, got {actual} (at record ID {id})")]
    BrokenSequence {
        /// Record ID where violation was encountered.
        id: i64,
        /// Expected sequential ID.
        expected: i64,
        /// Actual sequential ID found.
        actual: i64,
    },

    /// The prev_hash field does not match the predecessor's entry_hash.
    #[error(
        "Hash linkage broken at event ID {id}: expected prev_hash '{expected}', got '{actual}'"
    )]
    PrevHashMismatch {
        /// Record ID where mismatch occurred.
        id: i64,
        /// Expected previous hash.
        expected: String,
        /// Actual previous hash found in record.
        actual: String,
    },

    /// Recomputed entry_hash does not match the stored entry_hash.
    #[error("Entry hash mismatch at event ID {id}: computed '{expected}', record has '{actual}'")]
    HashMismatch {
        /// Record ID with tampered content.
        id: i64,
        /// Recomputed hash from record fields.
        expected: String,
        /// Stored entry_hash in record.
        actual: String,
    },

    /// Digital signature verification failed for this record.
    #[error("Cryptographic signature invalid at event ID {id}: {reason}")]
    SignatureInvalid {
        /// Record ID with invalid signature.
        id: i64,
        /// Detailed cryptographic reason.
        reason: String,
    },
}

/// Errors originating from the audit logging subsystem.
#[derive(Debug, Error)]
pub enum AuditError {
    /// SQLite storage error.
    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    /// Filesystem / IO error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Cryptographic signing or key operation error.
    #[error("Cryptographic error: {0}")]
    Crypto(String),

    /// Verification / integrity violation.
    #[error("Audit log verification failure: {0}")]
    Verification(#[from] VerificationError),
}
