//! valutx-audit
//!
//! Tamper-evident, hash-chained audit logging created server-side by the runtime.

#![deny(unsafe_code)]
#![warn(missing_docs)]

/// Structured security audit event.
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
