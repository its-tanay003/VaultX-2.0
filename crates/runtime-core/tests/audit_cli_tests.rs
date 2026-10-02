use tempfile::tempdir;
use valutx_audit::{crypto::AuditSigner, storage::AuditLog};

#[test]
fn test_audit_verify_and_export_cli_flow() {
    let temp_dir = tempdir().expect("create temp dir");
    let db_path = temp_dir.path().join("cli_test_audit.db");
    let key_path = temp_dir.path().join("cli_test.key");

    let signer = AuditSigner::load_or_generate_from_file(&key_path).expect("generate signer");
    let log = AuditLog::open(&db_path, signer).expect("open audit log");

    // Append 5 clean events
    for i in 1..=5 {
        log.append(
            Some("run-cli-test"),
            "file.write",
            "agent_cli",
            &format!("hash_{}", i),
        )
        .expect("append event");
    }

    // 1. Verify clean chain directly
    let report = log.verify(None).expect("verify clean");
    assert!(report.valid);
    assert_eq!(report.verified_events, 5);

    // 2. Export preserving original order
    let exported = log.export(None).expect("export log");
    assert_eq!(exported.len(), 5);
    for (idx, record) in exported.iter().enumerate() {
        assert_eq!(record.id, (idx + 1) as i64);
        assert_eq!(record.payload_hash, format!("hash_{}", idx + 1));
    }

    // 3. Tamper with row 3 and assert verification fails
    {
        let conn = log.connection();
        let conn_guard = conn.lock().unwrap();
        conn_guard
            .execute(
                "UPDATE audit_events SET payload_hash = 'corrupted_hash' WHERE id = 3",
                [],
            )
            .expect("tamper row 3");
    }

    let tampered_result = log.verify(None);
    assert!(
        tampered_result.is_err(),
        "Tampered chain must fail verification"
    );
    let err = tampered_result.unwrap_err();
    assert!(
        err.to_string().to_lowercase().contains("hash mismatch"),
        "Error must specify hash mismatch: {}",
        err
    );
}

#[test]
fn test_audit_signer_persistence_and_regeneration() {
    let temp_dir = tempdir().expect("create temp dir");
    let key_path = temp_dir.path().join("persistent.key");

    // 1. First run generates new key
    let signer1 = AuditSigner::load_or_generate_from_file(&key_path).expect("first run keygen");
    assert!(key_path.exists());
    let pubkey1 = signer1.public_key_hex();

    // 2. Second run loads existing key
    let signer2 = AuditSigner::load_or_generate_from_file(&key_path).expect("second run load");
    let pubkey2 = signer2.public_key_hex();

    assert_eq!(
        pubkey1, pubkey2,
        "Signer loaded on subsequent runs must match original key"
    );

    // Sign and verify with loaded signer
    let signature = signer1.sign_entry_hash("test_entry_hash_data");
    assert!(signer2
        .verify_entry_signature("test_entry_hash_data", &signature)
        .is_ok());
}
