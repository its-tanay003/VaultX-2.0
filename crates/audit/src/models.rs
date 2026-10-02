//! Audit record data structures and verification reports.

use serde::{Deserialize, Serialize};

/// Canonical genesis hash representing the null predecessor (64 zeros).
pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Persistent audit event record stored in SQLite.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEventRecord {
    /// Monotonically increasing sequence ID (1-indexed).
    pub id: i64,
    /// Associated agent run ID if event occurred within a task run.
    pub run_id: Option<String>,
    /// Classification of action or lifecycle transition.
    pub event_type: String,
    /// Principal or component responsible for initiating action.
    pub actor_id: String,
    /// SHA-256 hash of operation payload or artifact evidence.
    pub payload_hash: String,
    /// ISO-8601 UTC timestamp of creation.
    pub created_at: String,
    /// SHA-256 entry_hash of the immediate predecessor in the chain.
    pub prev_hash: String,
    /// SHA-256 hash of this record's canonical representation.
    pub entry_hash: String,
    /// Ed25519 digital signature of entry_hash by runtime key.
    pub signature: String,
}

/// Summary report produced by chain verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationReport {
    /// Whether the evaluated chain is completely valid and untampered.
    pub valid: bool,
    /// Total count of successfully verified events in the range.
    pub verified_events: usize,
    /// ID of the first event verified.
    pub first_id: i64,
    /// ID of the last event verified.
    pub last_id: i64,
    /// Head entry hash of the verified chain segment.
    pub head_hash: String,
}
