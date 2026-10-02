//! valutx-audit
//!
//! Tamper-evident, hash-chained audit logging created server-side by the runtime.
//! Enforces Ed25519 digital signatures, SQLite WAL append-only persistence,
//! and content-addressed storage for large evidence payloads.

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod artifacts;
pub mod crypto;
pub mod error;
pub mod models;
pub mod storage;

pub use artifacts::ArtifactStore;
pub use crypto::{compute_entry_hash, compute_payload_hash, AuditSigner};
pub use error::{AuditError, VerificationError};
pub use models::{AuditEventRecord, VerificationReport, GENESIS_HASH};
pub use storage::AuditLog;

use std::path::PathBuf;

/// Returns the user-private audit directory outside any sandbox-visible mounts.
///
/// On Windows: `%LOCALAPPDATA%\valutx\audit` (or `~/.valutx/audit` fallback)
/// On Linux/macOS: `~/.valutx/audit`
pub fn default_audit_dir() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
            return PathBuf::from(local_app_data).join("valutx").join("audit");
        }
    }
    if let Ok(home) = std::env::var("USERPROFILE").or_else(|_| std::env::var("HOME")) {
        return PathBuf::from(home).join(".valutx").join("audit");
    }
    PathBuf::from(".valutx").join("audit")
}

/// Returns the default path to the audit database SQLite file.
pub fn default_db_path() -> PathBuf {
    default_audit_dir().join("audit.db")
}

/// Returns the default path to the Ed25519 signing key.
pub fn default_key_path() -> PathBuf {
    default_audit_dir().join("audit_signer.key")
}

/// Returns the default path to the content-addressed artifact store.
pub fn default_artifacts_dir() -> PathBuf {
    default_audit_dir().join("artifacts")
}

/// Legacy lightweight audit event for link validation tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEvent {
    /// Sequence identifier.
    pub sequence: u64,
    /// Action capability executed.
    pub capability: String,
    /// Actor identity (user, agent, admin).
    pub actor: String,
    /// Sha256 hash of previous audit record in chain.
    pub prev_hash: String,
}

impl AuditEvent {
    /// Verifies continuity between two consecutive audit events.
    pub fn verify_link(prev: &AuditEvent, curr: &AuditEvent) -> bool {
        curr.sequence == prev.sequence + 1 && !curr.prev_hash.is_empty()
    }
}
