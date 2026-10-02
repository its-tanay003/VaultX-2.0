//! Deny-Path Integration Tests for Local IPC Daemon
//!
//! Non-negotiable invariant: Every security-sensitive function has tests for BOTH
//! allow and deny paths. Write deny-path tests first.
//!
//! Required deny paths:
//! 1. Wrong token -> UNAUTHENTICATED
//! 2. Other-user peer -> PEER_CREDENTIAL_MISMATCH
//! 3. Forged caller identity -> CALLER_IDENTITY_MISMATCH
//! 4. Oversized frame -> RESOURCE_LIMIT
//! 5. Unknown capability -> SCOPE_DENIED
//! 6. Unknown JSON fields -> INVALID_REQUEST
//! 7. Conflicting replayed idempotency key -> IDEMPOTENCY_CONFLICT

use serde_json::json;
use valutx_runtime_core::ipc::{
    envelope::{IpcErrorCode, IpcMessageEnvelope},
    idempotency::IdempotencyStore,
    peer::PeerIdentity,
    server::IpcSecurityContext,
    transport::{read_frame, MAX_FRAME_SIZE_BYTES},
};

#[tokio::test]
async fn test_deny_wrong_session_token() {
    let ctx = IpcSecurityContext::new(
        "expected-secret-token-123".to_string(),
        PeerIdentity::new(1000, 1000, 5001),
        "caller:desktop-user".to_string(),
    );

    let envelope = IpcMessageEnvelope {
        token: "wrong-fake-token-999".to_string(),
        caller_identity: "caller:desktop-user".to_string(),
        project_id: "proj_demo".to_string(),
        task_id: "task_001".to_string(),
        requested_capability: "fs:read".to_string(),
        policy_context: json!({}),
        idempotency_key: None,
        payload: json!({"path": "src/lib.rs"}),
    };

    let result = ctx.validate_envelope(&envelope);
    assert!(result.is_err(), "Must deny request with wrong token");
    let err = result.unwrap_err();
    assert_eq!(err.code, IpcErrorCode::Unauthenticated);
    assert_eq!(err.error_code(), "UNAUTHENTICATED");
}

#[tokio::test]
async fn test_deny_other_user_peer() {
    // Daemon runs as UID 1000
    let daemon_peer = PeerIdentity::new(1000, 1000, 5000);
    // Attacker client connects as UID 1001
    let attacker_peer = PeerIdentity::new(1001, 1001, 9999);

    let result = daemon_peer.verify_peer_credentials(&attacker_peer);
    assert!(result.is_err(), "Must deny connection from different UID");
    let err = result.unwrap_err();
    assert_eq!(err.code, IpcErrorCode::PeerCredentialMismatch);
    assert_eq!(err.error_code(), "PEER_CREDENTIAL_MISMATCH");
}

#[tokio::test]
async fn test_deny_forged_caller_identity() {
    let ctx = IpcSecurityContext::new(
        "valid-token-xyz".to_string(),
        PeerIdentity::new(1000, 1000, 5001),
        "caller:desktop-user".to_string(),
    );

    let envelope = IpcMessageEnvelope {
        token: "valid-token-xyz".to_string(),
        caller_identity: "caller:forged-admin".to_string(),
        project_id: "proj_demo".to_string(),
        task_id: "task_001".to_string(),
        requested_capability: "fs:read".to_string(),
        policy_context: json!({}),
        idempotency_key: None,
        payload: json!({}),
    };

    let result = ctx.validate_envelope(&envelope);
    assert!(result.is_err(), "Must deny forged caller identity");
    let err = result.unwrap_err();
    assert_eq!(err.code, IpcErrorCode::CallerIdentityMismatch);
    assert_eq!(err.error_code(), "CALLER_IDENTITY_MISMATCH");
}

#[tokio::test]
async fn test_deny_oversized_frame() {
    let (mut client_stream, mut server_stream) = tokio::io::duplex(64);

    // Spawn a writer sending an explicit length header exceeding 1 MiB limit
    let oversized_len: u32 = (MAX_FRAME_SIZE_BYTES + 1024) as u32;
    tokio::spawn(async move {
        use tokio::io::AsyncWriteExt;
        let _ = client_stream.write_all(&oversized_len.to_be_bytes()).await;
    });

    let result = read_frame(&mut server_stream).await;
    assert!(result.is_err(), "Must reject frame exceeding max size");
    let err = result.unwrap_err();
    assert_eq!(err.code, IpcErrorCode::ResourceLimit);
    assert_eq!(err.error_code(), "RESOURCE_LIMIT");
}

#[tokio::test]
async fn test_deny_unknown_capability() {
    let ctx = IpcSecurityContext::new(
        "valid-token-xyz".to_string(),
        PeerIdentity::new(1000, 1000, 5001),
        "caller:desktop-user".to_string(),
    );

    let envelope = IpcMessageEnvelope {
        token: "valid-token-xyz".to_string(),
        caller_identity: "caller:desktop-user".to_string(),
        project_id: "proj_demo".to_string(),
        task_id: "task_001".to_string(),
        requested_capability: "root:host_takeover".to_string(),
        policy_context: json!({}),
        idempotency_key: None,
        payload: json!({}),
    };

    let result = ctx.validate_envelope(&envelope);
    assert!(result.is_err(), "Must deny unknown capability");
    let err = result.unwrap_err();
    assert_eq!(err.code, IpcErrorCode::ScopeDenied);
    assert_eq!(err.error_code(), "SCOPE_DENIED");
}

#[tokio::test]
async fn test_deny_unknown_fields_in_envelope() {
    // Malicious payload with injected extraneous fields
    let raw_json = json!({
        "token": "valid-token-xyz",
        "caller_identity": "caller:desktop-user",
        "project_id": "proj_demo",
        "task_id": "task_001",
        "requested_capability": "fs:read",
        "policy_context": {},
        "payload": {},
        "injected_privilege_override": true // Disallowed unknown field
    });

    let result = serde_json::from_value::<IpcMessageEnvelope>(raw_json);
    assert!(
        result.is_err(),
        "Must reject unknown fields due to deny_unknown_fields"
    );
}

#[tokio::test]
async fn test_deny_conflicting_replayed_idempotency_key() {
    let mut store = IdempotencyStore::new();

    let key = "idem-key-12345";
    let initial_payload = json!({"action": "create_file", "path": "test.txt"});
    let conflicting_payload = json!({"action": "create_file", "path": "different_file.txt"});

    // First execution: store the key and result
    let first_check = store.check_or_record(key, &initial_payload);
    assert!(matches!(first_check, Ok(None)), "First request proceeds");

    // Attacker or client sends identical key with a conflicting payload
    let second_check = store.check_or_record(key, &conflicting_payload);
    assert!(
        second_check.is_err(),
        "Must reject duplicate key with altered payload"
    );
    let err = second_check.unwrap_err();
    assert_eq!(err.code, IpcErrorCode::IdempotencyConflict);
    assert_eq!(err.error_code(), "IDEMPOTENCY_CONFLICT");
}
