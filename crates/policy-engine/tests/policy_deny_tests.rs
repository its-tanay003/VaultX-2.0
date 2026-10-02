use valutx_policy_engine::{EvaluationContext, PolicyDecision, PolicyEngine};

#[test]
fn test_unknown_capability_denied_by_default() {
    let ctx = EvaluationContext {
        role: "Developer".into(),
        capability: "unknown.exploit".into(),
        risk_class: "L2".into(),
    };
    assert_eq!(PolicyEngine::evaluate(&ctx), PolicyDecision::Deny);
}

#[test]
fn test_empty_capability_denied() {
    let ctx = EvaluationContext {
        role: "Admin".into(),
        capability: "".into(),
        risk_class: "L0".into(),
    };
    assert_eq!(PolicyEngine::evaluate(&ctx), PolicyDecision::Deny);
}

#[test]
fn test_l4_destructive_requires_approval() {
    let ctx = EvaluationContext {
        role: "Security Analyst".into(),
        capability: "cyber.active_scan".into(),
        risk_class: "L4".into(),
    };
    assert_eq!(
        PolicyEngine::evaluate(&ctx),
        PolicyDecision::ApprovalRequired
    );
}
