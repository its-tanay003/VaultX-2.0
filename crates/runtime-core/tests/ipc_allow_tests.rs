//! Allow-Path Integration Tests for Local IPC Daemon
//!
//! Non-negotiable invariant: Every security-sensitive function has tests for BOTH
//! allow and deny paths.

use serde_json::json;
use valutx_runtime_core::ipc::{
    envelope::IpcMessageEnvelope,
    idempotency::IdempotencyStore,
    peer::PeerIdentity,
    server::{IpcSecurityContext, IpcServer},
    transport::{read_frame, write_frame},
};

#[tokio::test]
async fn test_allow_valid_authenticated_request() {
    let token = "valid-secret-token-abcdef123456".to_string();
    let peer = PeerIdentity::new(1000, 1000, 5001);
    let caller = "caller:desktop-user".to_string();

    let ctx = IpcSecurityContext::new(token.clone(), peer, caller.clone());

    let envelope = IpcMessageEnvelope {
        token,
        caller_identity: caller,
        project_id: "project-alpha".to_string(),
        task_id: "task-001".to_string(),
        requested_capability: "fs:read".to_string(),
        policy_context: json!({"sandbox": "restricted"}),
        idempotency_key: None,
        payload: json!({"path": "src/main.rs"}),
    };

    let result = ctx.validate_envelope(&envelope);
    assert!(
        result.is_ok(),
        "Must allow valid authenticated request: {:?}",
        result.err()
    );
}

#[tokio::test]
async fn test_allow_matching_peer_credentials() {
    let daemon_peer = PeerIdentity::new(1000, 1000, 5000);
    let client_peer = PeerIdentity::new(1000, 1000, 5002);

    let result = daemon_peer.verify_peer_credentials(&client_peer);
    assert!(result.is_ok(), "Must allow connection when UIDs match");
}

#[tokio::test]
async fn test_allow_framing_roundtrip() {
    let (mut client_stream, mut server_stream) = tokio::io::duplex(1024);

    let original_payload = b"{\"action\":\"ping\",\"timestamp\":1727913600}";

    tokio::spawn(async move {
        write_frame(&mut client_stream, original_payload)
            .await
            .expect("write_frame must succeed");
    });

    let received_payload = read_frame(&mut server_stream)
        .await
        .expect("read_frame must succeed");

    assert_eq!(
        received_payload, original_payload,
        "Received payload must match transmitted payload byte-for-byte"
    );
}

#[tokio::test]
async fn test_allow_idempotency_caching() {
    let mut store = IdempotencyStore::new();

    let key = "mutating-task-step-99";
    let payload = json!({"action": "apply_patch", "file": "README.md"});

    // Initial execution: not yet cached
    let check1 = store
        .check_or_record(key, &payload)
        .expect("check_or_record succeeds");
    assert!(
        check1.is_none(),
        "New idempotency key must not have cached response"
    );

    // Save executed response
    let execution_result = json!({"status": "APPLIED", "lines_changed": 4});
    store.save_response(key, execution_result.clone());

    // Replay with exact same payload
    let check2 = store
        .check_or_record(key, &payload)
        .expect("replay succeeds");
    assert_eq!(
        check2,
        Some(execution_result),
        "Replayed request with identical payload must return cached response"
    );
}

#[tokio::test]
async fn test_allow_handle_raw_frame_end_to_end() {
    let server = IpcServer::new("/tmp/test_valutx_ipc.sock", "caller:desktop-user");
    let client_peer = PeerIdentity::current();

    let valid_envelope = IpcMessageEnvelope {
        token: server.session_token.clone(),
        caller_identity: "caller:desktop-user".to_string(),
        project_id: "test-project".to_string(),
        task_id: "test-task-1".to_string(),
        requested_capability: "proc:exec".to_string(),
        policy_context: json!({}),
        idempotency_key: Some("idem-step-1".to_string()),
        payload: json!({"command": "cargo test"}),
    };

    let raw_frame = serde_json::to_vec(&valid_envelope).expect("Serialize envelope");

    // 1. Initial request execution
    let response1 = server.handle_raw_frame(&raw_frame, &client_peer).await;
    assert!(
        response1.success,
        "Response 1 must succeed: {:?}",
        response1.error
    );
    assert!(!response1.idempotent_cached, "Response 1 is not cached");
    assert_eq!(response1.data.unwrap()["status"], "DISPATCHED");

    // 2. Replayed request returns cached response
    let response2 = server.handle_raw_frame(&raw_frame, &client_peer).await;
    assert!(
        response2.success,
        "Response 2 must succeed: {:?}",
        response2.error
    );
    assert!(
        response2.idempotent_cached,
        "Response 2 must be served from cache"
    );
}
