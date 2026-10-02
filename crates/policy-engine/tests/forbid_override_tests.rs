//! Property Test: Invariant that a Cedar `forbid` policy ALWAYS overrides any `permit`.

use valutx_policy_engine::{
    capabilities, ActionRequest, CedarPolicyEngine, DecisionEffect, RiskClass, Role,
};

#[test]
fn test_adding_forbid_always_overrides_permit() {
    // 1. Base policy: Admin has full permit
    let base_policy = r#"
        permit (
            principal in ValutX::Role::"Admin",
            action,
            resource
        );
    "#;
    let engine_allow =
        CedarPolicyEngine::from_policy_text(base_policy).expect("Parse base allow policy");

    let req = ActionRequest {
        run_id: Some("run-forbid-test".to_string()),
        actor_id: "admin_user".to_string(),
        role: Role::Admin,
        capability: capabilities::PROJECT_WRITE.to_string(),
        target: "workspace/src/lib.rs".to_string(),
        parameters: serde_json::json!({}),
        scope: None,
        environment: "local".to_string(),
        trust_state: "trusted".to_string(),
        approval: None,
    };

    let decision_allow = engine_allow
        .evaluate_request(
            &req,
            "workspace/src/lib.rs",
            "hash_001",
            RiskClass::L1,
            false,
        )
        .expect("Evaluate allow");
    assert_eq!(decision_allow.effect, DecisionEffect::Allow);

    // 2. Add an explicit `forbid` policy targeting the capability
    let policy_with_forbid = r#"
        permit (
            principal in ValutX::Role::"Admin",
            action,
            resource
        );

        forbid (
            principal,
            action == ValutX::Action::"project.write",
            resource
        );
    "#;
    let engine_forbid =
        CedarPolicyEngine::from_policy_text(policy_with_forbid).expect("Parse forbid policy");

    let decision_forbid = engine_forbid
        .evaluate_request(
            &req,
            "workspace/src/lib.rs",
            "hash_001",
            RiskClass::L1,
            false,
        )
        .expect("Evaluate forbid");

    assert_eq!(
        decision_forbid.effect,
        DecisionEffect::Deny,
        "Cedar forbid rule MUST unconditionally override any permit"
    );
}

#[test]
fn test_quarantine_forbid_overrides_all_capabilities() {
    let engine = valutx_policy_engine::PolicyEngine::new();

    // Even Admin attempting benign read is forbidden when trust_state is quarantined
    let req = ActionRequest {
        run_id: Some("quarantine-run".to_string()),
        actor_id: "admin_compromised".to_string(),
        role: Role::Admin,
        capability: capabilities::PROJECT_READ.to_string(),
        target: "workspace".to_string(),
        parameters: serde_json::json!({}),
        scope: None,
        environment: "local".to_string(),
        trust_state: "quarantined".to_string(),
        approval: None,
    };

    let decision = engine.evaluate_action(&req).expect("evaluate quarantine");
    assert_eq!(
        decision.effect,
        DecisionEffect::Deny,
        "Quarantined trust state must unconditionally deny via forbid rule"
    );
}
