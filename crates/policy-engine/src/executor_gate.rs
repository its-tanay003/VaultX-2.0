//! Pre-execution audit logging, TOCTOU symlink protection, and approval verification.

use chrono::{DateTime, Utc};
use valutx_audit::{crypto::compute_payload_hash, AuditError, AuditLog};

use crate::canonical::{canonicalize_parameters, canonicalize_target, compute_action_hash};
use crate::error::PolicyError;
use crate::models::{ActionRequest, ApprovalToken, Decision, RiskClass};

/// Records an authorization decision in the tamper-evident audit log before execution begins.
pub fn record_pre_execution_decision(
    audit_log: &AuditLog,
    req: &ActionRequest,
    decision: &Decision,
) -> Result<valutx_audit::AuditEventRecord, AuditError> {
    let serialized_decision = serde_json::to_string(decision).unwrap_or_default();
    let payload_hash = compute_payload_hash(serialized_decision.as_bytes());

    audit_log.append(
        req.run_id.as_deref(),
        "policy.decision",
        &req.actor_id,
        &payload_hash,
    )
}

/// Re-evaluates action parameters at execution time to prevent Time-of-Check to Time-of-Use (TOCTOU) attacks.
///
/// Invariant: If a symlink was swapped or arguments altered between decision and execution,
/// this check will fail immediately and abort execution.
pub fn verify_execution_integrity(
    decision: &Decision,
    current_target: &str,
    current_parameters: &serde_json::Value,
    capability: &str,
    actor_id: &str,
    risk_class: RiskClass,
    scope_id: Option<&str>,
) -> Result<(), PolicyError> {
    let canonical_target = canonicalize_target(current_target);
    let canonical_params = canonicalize_parameters(current_parameters);

    let current_hash = compute_action_hash(
        capability,
        actor_id,
        &canonical_target,
        &canonical_params,
        risk_class.as_str(),
        scope_id,
    );

    if current_hash != decision.action_hash {
        return Err(PolicyError::ToctouDetected {
            original_hash: decision.action_hash.clone(),
            current_hash,
            path: current_target.to_string(),
        });
    }

    Ok(())
}

/// Validates that an approval token is unexpired and bound to the exact requested action hash.
pub fn validate_approval(
    approval: &ApprovalToken,
    expected_action_hash: &str,
    now: DateTime<Utc>,
) -> Result<(), PolicyError> {
    if let Ok(exp) = DateTime::parse_from_rfc3339(&approval.expires_at) {
        if now >= exp.with_timezone(&Utc) {
            return Err(PolicyError::ApprovalExpired {
                approval_id: approval.approval_id.clone(),
                expired_at: approval.expires_at.clone(),
            });
        }
    }

    if approval.action_hash != expected_action_hash {
        return Err(PolicyError::ApprovalHashMismatch {
            expected: expected_action_hash.to_string(),
            actual: approval.action_hash.clone(),
        });
    }

    Ok(())
}
