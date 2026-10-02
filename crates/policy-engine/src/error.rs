//! Policy engine error definitions.

use thiserror::Error;

/// Structured errors emitted during policy evaluation and pre-execution validation.
#[derive(Debug, Error)]
pub enum PolicyError {
    /// Cedar policy evaluation failure.
    #[error("Cedar evaluation error: {0}")]
    CedarEval(String),

    /// Cedar policy or schema parsing failure.
    #[error("Cedar parse error: {0}")]
    CedarParse(String),

    /// Security scope has expired.
    #[error("Security scope '{scope_id}' expired at {expired_at}")]
    ScopeExpired {
        /// Identifier of expired scope.
        scope_id: String,
        /// Expiration timestamp.
        expired_at: String,
    },

    /// Target destination is outside the authorized security scope.
    #[error("Target '{target}' denied by security scope: {reason}")]
    ScopeTargetDenied {
        /// Denied target.
        target: String,
        /// Reason for scope denial.
        reason: String,
    },

    /// Time-of-Check to Time-of-Use (TOCTOU) tamper detected.
    #[error("TOCTOU vulnerability detected: action hash altered between authorization ({original_hash}) and execution ({current_hash}) for path '{path}'")]
    ToctouDetected {
        /// Hash computed during policy evaluation.
        original_hash: String,
        /// Hash recomputed at execution time.
        current_hash: String,
        /// Path that underwent modification.
        path: String,
    },

    /// Approval token has expired.
    #[error("Approval token '{approval_id}' expired at {expired_at}")]
    ApprovalExpired {
        /// Identifier of expired approval.
        approval_id: String,
        /// Expiration timestamp.
        expired_at: String,
    },

    /// Approval token was issued for a different action hash.
    #[error("Approval hash mismatch: approval is bound to '{expected}', request has '{actual}'")]
    ApprovalHashMismatch {
        /// Hash recorded in approval token.
        expected: String,
        /// Hash of the current action.
        actual: String,
    },

    /// Pre-execution audit logging failed.
    #[error("Audit logging error: {0}")]
    Audit(#[from] valutx_audit::AuditError),

    /// Underlying filesystem I/O error during canonicalization.
    #[error("Filesystem I/O error: {0}")]
    Io(#[from] std::io::Error),
}
