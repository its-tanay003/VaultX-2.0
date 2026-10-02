//! Scale & High-Throughput Verification Test (10,000 Events)
//!
//! Non-negotiable requirement ("DONE WHEN"):
//! "A clean chain of 10,000 events verifies."

use std::time::Instant;
use valutx_audit::{crypto::AuditSigner, storage::AuditLog};

#[test]
fn test_clean_chain_10000_events_verifies() {
    let temp_dir = tempfile::tempdir().expect("Create temp dir");
    let db_path = temp_dir.path().join("scale_audit_10k.db");
    let signer = AuditSigner::generate();
    let log = AuditLog::open(&db_path, signer).expect("Open audit log");

    println!("Appending 10,000 audit events...");
    let start_append = Instant::now();

    // Append in batches of 1,000 events for maximum transaction throughput
    for batch_idx in 0..10 {
        let mut batch = Vec::with_capacity(1000);
        let run_id_str = format!("scale_run_{}", batch_idx);
        for _ in 0..1000 {
            batch.push((
                Some(run_id_str.as_str()),
                "benchmark.action",
                "bench_worker",
                "sha256_mock_payload_hash_value_12345",
            ));
        }
        log.append_batch(&batch).expect("Batch append must succeed");
    }

    let append_duration = start_append.elapsed();
    println!("10,000 events appended in {:?}", append_duration);

    assert_eq!(log.count().expect("Count"), 10_000);

    // Verify all 10,000 events end-to-end
    println!("Verifying 10,000 events end-to-end...");
    let start_verify = Instant::now();
    let report = log.verify(None).expect("Chain verification must succeed");
    let verify_duration = start_verify.elapsed();
    println!("10,000 events verified in {:?}", verify_duration);

    assert!(report.valid, "Chain must be 100% valid");
    assert_eq!(report.verified_events, 10_000);
    assert_eq!(report.first_id, 1);
    assert_eq!(report.last_id, 10_000);
    assert!(!report.head_hash.is_empty());
}
