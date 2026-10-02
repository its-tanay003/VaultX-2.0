//! Approval token binding and pre-execution audit persistence tests.

use chrono::Utc;
use tempfile::tempdir;
use valutx_audit::{crypto::AuditSigner, storage::AuditLog};
use valutx_policy_engine::{
    capabilities, ActionRequest, ApprovalToken, DecisionEffect, PolicyEngine, Role,
};

#[test]
fn test_expired_approval_token_rejected() {
    let engine = PolicyEngine::new();

    let expired_token = ApprovalToken {
        approval_id: "expired-appr-01".to_string(),
        action_hash: "dummy_action_hash".to_string(),
        approved_by: "sec_officer".to_string(),
        approved_at: "2020-01-01T00:00:00Z".to_string(),
        expires_at: "2020-01-02T00:00:00Z".to_string(), // Expired
    };

    let req = ActionRequest {
        run_id: Some("expired-approval-run".to_string()),
        actor_id: "agent_worker".to_string(),
        role: Role::Developer,
        capability: capabilities::PLUGIN_INSTALL.to_string(),
        target: "plugin-xyz".to_string(),
        parameters: serde_json::json!({}),
        scope: None,
        environment: "local".to_string(),
        trust_state: "trusted".to_string(),
        approval: Some(expired_token),
    };

    let decision = engine
        .evaluate_action(&req)
        .expect("evaluate expired approval");
    assert_eq!(
        decision.effect,
        DecisionEffect::RequireApproval,
        "Expired approval token must require fresh approval"
    );
    assert!(decision.reasons.iter().any(|r| r.contains("expired")));
}

#[test]
fn test_wrong_action_hash_approval_rejected() {
    let engine = PolicyEngine::new();

    let mismatched_token = ApprovalToken {
        approval_id: "mismatch-appr-01".to_string(),
        action_hash: "hash_for_completely_different_action_12345".to_string(),
        approved_by: "sec_officer".to_string(),
        approved_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: "2099-01-01T00:00:00Z".to_string(),
    };

    let req = ActionRequest {
        run_id: Some("wrong-hash-run".to_string()),
        actor_id: "agent_worker".to_string(),
        role: Role::Developer,
        capability: capabilities::PLUGIN_INSTALL.to_string(),
        target: "plugin-xyz".to_string(),
        parameters: serde_json::json!({}),
        scope: None,
        environment: "local".to_string(),
        trust_state: "trusted".to_string(),
        approval: Some(mismatched_token),
    };

    let decision = engine
        .evaluate_action(&req)
        .expect("evaluate mismatched hash");
    assert_eq!(
        decision.effect,
        DecisionEffect::RequireApproval,
        "Mismatched action hash approval must be rejected"
    );
    assert!(decision.reasons.iter().any(|r| r.contains("mismatch")));
}

#[test]
fn test_valid_approval_grants_authorization() {
    let engine = PolicyEngine::new();

    let mut req = ActionRequest {
        run_id: Some("valid-approval-run".to_string()),
        actor_id: "developer_01".to_string(),
        role: Role::Developer,
        capability: capabilities::PLUGIN_INSTALL.to_string(),
        target: "plugin-xyz".to_string(),
        parameters: serde_json::json!({ "version": "1.0.0" }),
        scope: None,
        environment: "local".to_string(),
        trust_state: "trusted".to_string(),
        approval: None,
    };

    // 1. Without approval -> RequireApproval
    let initial_decision = engine.evaluate_action(&req).expect("evaluate unapproved");
    assert_eq!(initial_decision.effect, DecisionEffect::RequireApproval);

    // 2. Attach valid approval bound to initial_decision.action_hash
    req.approval = Some(ApprovalToken {
        approval_id: "valid-appr-01".to_string(),
        action_hash: initial_decision.action_hash.clone(),
        approved_by: "security_admin".to_string(),
        approved_at: Utc::now().to_rfc3339(),
        expires_at: "2099-01-01T00:00:00Z".to_string(),
    });

    let approved_decision = engine.evaluate_action(&req).expect("evaluate approved");
    assert_eq!(
        approved_decision.effect,
        DecisionEffect::Allow,
        "Valid cryptographic approval must permit plugin installation"
    );
}

#[test]
fn test_pre_execution_audit_persistence_stored_before_execution() {
    let temp_dir = tempdir().expect("create temp dir");
    let db_path = temp_dir.path().join("audit_pre_exec.db");
    let signer = AuditSigner::generate();
    let audit_log = AuditLog::open(&db_path, signer).expect("open audit log");

    let engine = PolicyEngine::new();
    let req = ActionRequest {
        run_id: Some("run-audit-persist".to_string()),
        actor_id: "agent_executor".to_string(),
        role: Role::Developer,
        capability: capabilities::PROJECT_READ.to_string(),
        target: "workspace/src/lib.rs".to_string(),
        parameters: serde_json::json!({}),
        scope: None,
        environment: "local".to_string(),
        trust_state: "trusted".to_string(),
        approval: None,
    };

    // Evaluate and record in tamper-evident audit trail BEFORE execution
    let decision = engine
        .evaluate_and_record(&req, &audit_log)
        .expect("evaluate and record");
    assert_eq!(decision.effect, DecisionEffect::Allow);

    // Verify audit log has exactly 1 event and verifies
    assert_eq!(audit_log.count().expect("count events"), 1);
    let verify_report = audit_log.verify(None).expect("verify audit trail");
    assert!(verify_report.valid);
    assert_eq!(verify_report.verified_events, 1);
}
