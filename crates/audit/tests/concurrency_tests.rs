//! Concurrency and Fork Prevention Tests for Audit Log
//!
//! Asserts that two concurrent writers cannot fork or interleave broken chains.

use std::sync::Arc;
use std::thread;

use valutx_audit::{crypto::AuditSigner, storage::AuditLog};

#[test]
fn test_concurrent_writers_cannot_fork_chain() {
    let temp_dir = tempfile::tempdir().expect("Create temp dir");
    let db_path = temp_dir.path().join("concurrent_audit.db");
    let signer = AuditSigner::generate();
    let log = Arc::new(AuditLog::open(&db_path, signer).expect("Open audit log"));

    let writer1_log = Arc::clone(&log);
    let writer2_log = Arc::clone(&log);

    let t1 = thread::spawn(move || {
        for i in 0..100 {
            writer1_log
                .append(
                    Some("run_concurrency"),
                    "thread1.action",
                    "worker_1",
                    &format!("hash_w1_{}", i),
                )
                .expect("Writer 1 append succeeds");
        }
    });

    let t2 = thread::spawn(move || {
        for i in 0..100 {
            writer2_log
                .append(
                    Some("run_concurrency"),
                    "thread2.action",
                    "worker_2",
                    &format!("hash_w2_{}", i),
                )
                .expect("Writer 2 append succeeds");
        }
    });

    t1.join().expect("Writer 1 finishes cleanly");
    t2.join().expect("Writer 2 finishes cleanly");

    // Total must be 200 events
    assert_eq!(log.count().unwrap(), 200);

    // Verify entire chain: must verify cleanly with NO forks
    let report = log.verify(None).expect("Verification must pass");
    assert!(report.valid, "Chain must remain valid and linear");
    assert_eq!(report.verified_events, 200);
    assert_eq!(report.first_id, 1);
    assert_eq!(report.last_id, 200);
}
