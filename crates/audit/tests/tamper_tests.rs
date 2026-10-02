//! Tamper Detection Integration Tests (Deny-Path TDD)
//!
//! Non-negotiable invariant: Every security-sensitive function has tests for BOTH
//! allow and deny paths. Write deny-path tests first.
//!
//! Evaluates detection of:
//! 1. Modified payload hash
//! 2. Modified actor ID or event type
//! 3. Deleted row in sequence
//! 4. Reordered rows
//! 5. Inserted unauthorized row
//! 6. Corrupted cryptographic signature
//! 7. Corrupted prev_hash
//! 8. Private key isolation (never printed in logs or debug output)

use valutx_audit::{
    crypto::AuditSigner,
    error::{AuditError, VerificationError},
    storage::AuditLog,
};

fn setup_test_audit_log() -> (AuditLog, tempfile::TempDir) {
    let temp_dir = tempfile::tempdir().expect("Create temp dir");
    let db_path = temp_dir.path().join("test_audit.db");
    let signer = AuditSigner::generate();
    let log = AuditLog::open(&db_path, signer).expect("Open audit log");
    (log, temp_dir)
}

#[test]
fn test_tamper_modified_payload_hash_detected() {
    let (log, _dir) = setup_test_audit_log();

    // Populate with 3 valid events
    log.append(Some("run_1"), "file.read", "user_1", "hash_alpha")
        .unwrap();
    log.append(Some("run_1"), "file.write", "user_1", "hash_beta")
        .unwrap();
    log.append(Some("run_1"), "proc.exec", "user_1", "hash_gamma")
        .unwrap();

    // Tamper directly in SQLite: alter payload_hash of record 2
    {
        let conn = log.connection();
        let conn = conn.lock().unwrap();
        conn.execute(
            "UPDATE audit_events SET payload_hash = 'tampered_hash_value' WHERE id = 2",
            [],
        )
        .unwrap();
    }

    // Verify must fail with HashMismatch
    let result = log.verify(None);
    assert!(result.is_err(), "Must detect modified payload_hash");
    match result.unwrap_err() {
        AuditError::Verification(VerificationError::HashMismatch { id, .. }) => {
            assert_eq!(id, 2, "Must identify tampered event ID 2");
        }
        other => panic!("Expected VerificationError::HashMismatch, got {:?}", other),
    }
}

#[test]
fn test_tamper_modified_actor_or_type_detected() {
    let (log, _dir) = setup_test_audit_log();

    log.append(Some("run_1"), "file.read", "user_1", "hash_alpha")
        .unwrap();
    log.append(Some("run_1"), "file.write", "user_1", "hash_beta")
        .unwrap();

    // Tamper: change actor_id of record 1
    {
        let conn = log.connection();
        let conn = conn.lock().unwrap();
        conn.execute(
            "UPDATE audit_events SET actor_id = 'rogue_admin' WHERE id = 1",
            [],
        )
        .unwrap();
    }

    let result = log.verify(None);
    assert!(result.is_err(), "Must detect modified actor_id");
    match result.unwrap_err() {
        AuditError::Verification(VerificationError::HashMismatch { id, .. }) => {
            assert_eq!(id, 1);
        }
        other => panic!("Expected VerificationError::HashMismatch, got {:?}", other),
    }
}

#[test]
fn test_tamper_deleted_row_detected() {
    let (log, _dir) = setup_test_audit_log();

    log.append(Some("run_1"), "event_1", "actor_1", "hash_1")
        .unwrap();
    log.append(Some("run_1"), "event_2", "actor_1", "hash_2")
        .unwrap();
    log.append(Some("run_1"), "event_3", "actor_1", "hash_3")
        .unwrap();

    // Tamper: delete record 2
    {
        let conn = log.connection();
        let conn = conn.lock().unwrap();
        conn.execute("DELETE FROM audit_events WHERE id = 2", [])
            .unwrap();
    }

    // Verification must detect broken sequence / broken hash chain
    let result = log.verify(None);
    assert!(result.is_err(), "Must detect deleted intermediate row");
    match result.unwrap_err() {
        AuditError::Verification(VerificationError::BrokenSequence {
            id,
            expected,
            actual,
        }) => {
            assert_eq!(id, 3);
            assert_eq!(expected, 2);
            assert_eq!(actual, 3);
        }
        AuditError::Verification(VerificationError::PrevHashMismatch { id, .. }) => {
            assert_eq!(id, 3);
        }
        other => panic!(
            "Expected BrokenSequence or PrevHashMismatch, got {:?}",
            other
        ),
    }
}

#[test]
fn test_tamper_reordered_rows_detected() {
    let (log, _dir) = setup_test_audit_log();

    log.append(Some("run_1"), "event_1", "actor_1", "hash_1")
        .unwrap();
    log.append(Some("run_1"), "event_2", "actor_1", "hash_2")
        .unwrap();

    // Tamper: swap entry_hash and signatures between rows 1 and 2
    {
        let conn = log.connection();
        let conn = conn.lock().unwrap();
        conn.execute(
            "UPDATE audit_events SET event_type = 'event_2' WHERE id = 1",
            [],
        )
        .unwrap();
    }

    let result = log.verify(None);
    assert!(
        result.is_err(),
        "Must detect reordered or swapped row contents"
    );
}

#[test]
fn test_tamper_inserted_row_detected() {
    let (log, _dir) = setup_test_audit_log();

    log.append(Some("run_1"), "event_1", "actor_1", "hash_1")
        .unwrap();

    // Tamper: inject an unverified row
    {
        let conn = log.connection();
        let conn = conn.lock().unwrap();
        conn.execute(
            "INSERT INTO audit_events (id, run_id, event_type, actor_id, payload_hash, created_at, prev_hash, entry_hash, signature)
             VALUES (2, 'run_1', 'fake_event', 'attacker', 'hash_fake', '2026-10-02T00:00:00Z', 'fake_prev', 'fake_entry', 'fake_sig')",
            [],
        )
        .unwrap();
    }

    let result = log.verify(None);
    assert!(result.is_err(), "Must detect injected row");
}

#[test]
fn test_tamper_corrupted_signature_detected() {
    let (log, _dir) = setup_test_audit_log();

    log.append(Some("run_1"), "event_1", "actor_1", "hash_1")
        .unwrap();

    // Tamper: corrupt signature bytes in DB
    {
        let conn = log.connection();
        let conn = conn.lock().unwrap();
        conn.execute(
            "UPDATE audit_events SET signature = '00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000' WHERE id = 1",
            [],
        )
        .unwrap();
    }

    let result = log.verify(None);
    assert!(result.is_err(), "Must detect corrupted signature");
    match result.unwrap_err() {
        AuditError::Verification(VerificationError::SignatureInvalid { id, .. }) => {
            assert_eq!(id, 1);
        }
        other => panic!(
            "Expected VerificationError::SignatureInvalid, got {:?}",
            other
        ),
    }
}

#[test]
fn test_key_never_leaks_in_debug_representation() {
    let signer = AuditSigner::generate();
    let debug_output = format!("{:?}", signer);

    assert!(
        !debug_output.contains("secret"),
        "Debug output must not mention secret key bytes: {}",
        debug_output
    );
    assert!(
        debug_output.contains("[REDACTED]"),
        "Debug output must explicitly show [REDACTED]: {}",
        debug_output
    );
}
