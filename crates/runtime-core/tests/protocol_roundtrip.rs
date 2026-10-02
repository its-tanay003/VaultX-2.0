use std::fs;
use std::path::PathBuf;
use valutx_runtime_core::protocol::*;

fn fixtures_dir() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("packages")
        .join("test-fixtures")
        .join("protocol")
}

#[test]
fn test_roundtrip_agent_run() {
    let path = fixtures_dir().join("valid").join("agent_run.json");
    let content = fs::read_to_string(&path).expect("read agent_run.json");
    let parsed: AgentRun = serde_json::from_str(&content).expect("parse AgentRun");
    assert_eq!(parsed.status, RunStatus::RUNNING);

    let serialized = serde_json::to_string(&parsed).expect("serialize AgentRun");
    let reparsed: AgentRun = serde_json::from_str(&serialized).expect("reparse AgentRun");
    assert_eq!(parsed, reparsed);
}

#[test]
fn test_roundtrip_action_request() {
    let path = fixtures_dir().join("valid").join("action_request.json");
    let content = fs::read_to_string(&path).expect("read action_request.json");
    let parsed: ActionRequest = serde_json::from_str(&content).expect("parse ActionRequest");
    assert_eq!(parsed.capability, Capability::ProjectWrite);

    let serialized = serde_json::to_string(&parsed).expect("serialize ActionRequest");
    let reparsed: ActionRequest = serde_json::from_str(&serialized).expect("reparse ActionRequest");
    assert_eq!(parsed, reparsed);
}

#[test]
fn test_roundtrip_decision_allow() {
    let path = fixtures_dir().join("valid").join("decision_allow.json");
    let content = fs::read_to_string(&path).expect("read decision_allow.json");
    let parsed: Decision = serde_json::from_str(&content).expect("parse Decision");
    assert_eq!(parsed.effect, DecisionEffect::ALLOW);

    let serialized = serde_json::to_string(&parsed).expect("serialize Decision");
    let reparsed: Decision = serde_json::from_str(&serialized).expect("reparse Decision");
    assert_eq!(parsed, reparsed);
}

#[test]
fn test_roundtrip_decision_deny() {
    let path = fixtures_dir().join("valid").join("decision_deny.json");
    let content = fs::read_to_string(&path).expect("read decision_deny.json");
    let parsed: Decision = serde_json::from_str(&content).expect("parse Decision");
    assert_eq!(parsed.effect, DecisionEffect::DENY);

    let serialized = serde_json::to_string(&parsed).expect("serialize Decision");
    let reparsed: Decision = serde_json::from_str(&serialized).expect("reparse Decision");
    assert_eq!(parsed, reparsed);
}

#[test]
fn test_roundtrip_approval() {
    let path = fixtures_dir().join("valid").join("approval.json");
    let content = fs::read_to_string(&path).expect("read approval.json");
    let parsed: Approval = serde_json::from_str(&content).expect("parse Approval");
    assert_eq!(parsed.approver_role, ApproverRole::SecurityAdmin);

    let serialized = serde_json::to_string(&parsed).expect("serialize Approval");
    let reparsed: Approval = serde_json::from_str(&serialized).expect("reparse Approval");
    assert_eq!(parsed, reparsed);
}

#[test]
fn test_roundtrip_security_scope() {
    let path = fixtures_dir().join("valid").join("security_scope.json");
    let content = fs::read_to_string(&path).expect("read security_scope.json");
    let parsed: SecurityScope = serde_json::from_str(&content).expect("parse SecurityScope");
    assert_eq!(parsed.max_depth, 3);
    assert_eq!(parsed.allowed_ports, vec![80, 443, 8080]);

    let serialized = serde_json::to_string(&parsed).expect("serialize SecurityScope");
    let reparsed: SecurityScope = serde_json::from_str(&serialized).expect("reparse SecurityScope");
    assert_eq!(parsed, reparsed);
}

#[test]
fn test_roundtrip_tool_passport() {
    let path = fixtures_dir().join("valid").join("tool_passport.json");
    let content = fs::read_to_string(&path).expect("read tool_passport.json");
    let parsed: ToolPassport = serde_json::from_str(&content).expect("parse ToolPassport");
    assert_eq!(parsed.runtime_type, RuntimeType::Container);
    assert!(parsed.capabilities.contains(&Capability::CyberScan));

    let serialized = serde_json::to_string(&parsed).expect("serialize ToolPassport");
    let reparsed: ToolPassport = serde_json::from_str(&serialized).expect("reparse ToolPassport");
    assert_eq!(parsed, reparsed);
}

#[test]
fn test_roundtrip_verification_result() {
    let path = fixtures_dir()
        .join("valid")
        .join("verification_result.json");
    let content = fs::read_to_string(&path).expect("read verification_result.json");
    let parsed: VerificationResult =
        serde_json::from_str(&content).expect("parse VerificationResult");
    assert_eq!(parsed.status, VerificationStatus::PASSED);
    assert_eq!(parsed.checks.len(), 2);

    let serialized = serde_json::to_string(&parsed).expect("serialize VerificationResult");
    let reparsed: VerificationResult =
        serde_json::from_str(&serialized).expect("reparse VerificationResult");
    assert_eq!(parsed, reparsed);
}

#[test]
fn test_roundtrip_evidence() {
    let path = fixtures_dir().join("valid").join("evidence.json");
    let content = fs::read_to_string(&path).expect("read evidence.json");
    let parsed: Evidence = serde_json::from_str(&content).expect("parse Evidence");
    assert_eq!(parsed.artifacts.len(), 1);

    let serialized = serde_json::to_string(&parsed).expect("serialize Evidence");
    let reparsed: Evidence = serde_json::from_str(&serialized).expect("reparse Evidence");
    assert_eq!(parsed, reparsed);
}

#[test]
fn test_roundtrip_audit_event() {
    let path = fixtures_dir().join("valid").join("audit_event.json");
    let content = fs::read_to_string(&path).expect("read audit_event.json");
    let parsed: AuditEvent = serde_json::from_str(&content).expect("parse AuditEvent");
    assert_eq!(parsed.sequence, 42);

    let serialized = serde_json::to_string(&parsed).expect("serialize AuditEvent");
    let reparsed: AuditEvent = serde_json::from_str(&serialized).expect("reparse AuditEvent");
    assert_eq!(parsed, reparsed);
}

#[test]
fn test_roundtrip_checkpoint() {
    let path = fixtures_dir().join("valid").join("checkpoint.json");
    let content = fs::read_to_string(&path).expect("read checkpoint.json");
    let parsed: Checkpoint = serde_json::from_str(&content).expect("parse Checkpoint");
    assert!(parsed.rollback_point);

    let serialized = serde_json::to_string(&parsed).expect("serialize Checkpoint");
    let reparsed: Checkpoint = serde_json::from_str(&serialized).expect("reparse Checkpoint");
    assert_eq!(parsed, reparsed);
}

#[test]
fn test_roundtrip_finding() {
    let path = fixtures_dir().join("valid").join("finding.json");
    let content = fs::read_to_string(&path).expect("read finding.json");
    let parsed: Finding = serde_json::from_str(&content).expect("parse Finding");
    assert_eq!(parsed.severity, FindingSeverity::CRITICAL);

    let serialized = serde_json::to_string(&parsed).expect("serialize Finding");
    let reparsed: Finding = serde_json::from_str(&serialized).expect("reparse Finding");
    assert_eq!(parsed, reparsed);
}

#[test]
fn test_roundtrip_protocol_error() {
    let path = fixtures_dir()
        .join("valid")
        .join("error_policy_denied.json");
    let content = fs::read_to_string(&path).expect("read error_policy_denied.json");
    let parsed: ProtocolError = serde_json::from_str(&content).expect("parse ProtocolError");
    assert_eq!(parsed.code, ErrorCode::POLICY_DENIED);

    let serialized = serde_json::to_string(&parsed).expect("serialize ProtocolError");
    let reparsed: ProtocolError = serde_json::from_str(&serialized).expect("reparse ProtocolError");
    assert_eq!(parsed, reparsed);
}

#[test]
fn test_roundtrip_protocol_event() {
    let path = fixtures_dir().join("valid").join("protocol_event.json");
    let content = fs::read_to_string(&path).expect("read protocol_event.json");
    let parsed: ProtocolEvent = serde_json::from_str(&content).expect("parse ProtocolEvent");
    assert_eq!(parsed.event_type, EventType::ToolStarted);

    let serialized = serde_json::to_string(&parsed).expect("serialize ProtocolEvent");
    let reparsed: ProtocolEvent = serde_json::from_str(&serialized).expect("reparse ProtocolEvent");
    assert_eq!(parsed, reparsed);
}

#[test]
fn test_roundtrip_protocol_envelope() {
    let path = fixtures_dir().join("valid").join("protocol_envelope.json");
    let content = fs::read_to_string(&path).expect("read protocol_envelope.json");
    let parsed: ProtocolEnvelope = serde_json::from_str(&content).expect("parse ProtocolEnvelope");
    assert_eq!(parsed.protocol_version, "1.0.0");
    assert_eq!(parsed.message_type, MessageType::ActionRequest);
    assert_eq!(
        parsed.negotiation.as_ref().unwrap().status,
        NegotiationStatus::ACCEPTED
    );

    let serialized = serde_json::to_string(&parsed).expect("serialize ProtocolEnvelope");
    let reparsed: ProtocolEnvelope =
        serde_json::from_str(&serialized).expect("reparse ProtocolEnvelope");
    assert_eq!(parsed, reparsed);
}

// -----------------------------------------------------------------------------
// Deny-Path Tests
// -----------------------------------------------------------------------------

#[test]
fn test_deny_invalid_capability() {
    let path = fixtures_dir()
        .join("invalid")
        .join("invalid_capability.json");
    let content = fs::read_to_string(&path).expect("read invalid_capability.json");
    let result: Result<ActionRequest, _> = serde_json::from_str(&content);
    assert!(
        result.is_err(),
        "Expected deserialization failure on unauthorized capability"
    );
}

#[test]
fn test_deny_unknown_property() {
    let path = fixtures_dir().join("invalid").join("unknown_property.json");
    let content = fs::read_to_string(&path).expect("read unknown_property.json");
    let result: Result<SecurityScope, _> = serde_json::from_str(&content);
    assert!(
        result.is_err(),
        "Expected failure due to deny_unknown_fields on unknown property"
    );
}

#[test]
fn test_deny_unrecognized_error_code() {
    let path = fixtures_dir()
        .join("invalid")
        .join("unrecognized_error_code.json");
    let content = fs::read_to_string(&path).expect("read unrecognized_error_code.json");
    let result: Result<ProtocolError, _> = serde_json::from_str(&content);
    assert!(
        result.is_err(),
        "Expected failure on unrecognized error code"
    );
}
