//! Content-Addressed Artifact Store Tests

use valutx_audit::artifacts::ArtifactStore;
use valutx_audit::crypto::compute_payload_hash;

#[test]
fn test_artifact_store_put_and_get_roundtrip() {
    let temp_dir = tempfile::tempdir().expect("Create temp dir");
    let store = ArtifactStore::new(temp_dir.path()).expect("Initialize artifact store");

    let payload = b"Evidence Payload: nmap scan results with 10 open ports on 127.0.0.1";
    let expected_hash = compute_payload_hash(payload);

    let stored_hash = store.put(payload).expect("Put artifact");
    assert_eq!(stored_hash, expected_hash);
    assert!(store.exists(&stored_hash));

    let retrieved = store
        .get(&stored_hash)
        .expect("Get artifact")
        .expect("Payload must exist");

    assert_eq!(retrieved, payload);
}

#[test]
fn test_artifact_store_nonexistent_and_invalid_hash() {
    let temp_dir = tempfile::tempdir().expect("Create temp dir");
    let store = ArtifactStore::new(temp_dir.path()).expect("Initialize artifact store");

    // Invalid hash length
    assert!(!store.exists("invalid_short_hash"));
    assert_eq!(store.get("invalid_short_hash").unwrap(), None);

    // Valid 64-char hex hash that doesn't exist
    let missing_hash = "1111111111111111111111111111111111111111111111111111111111111111";
    assert!(!store.exists(missing_hash));
    assert_eq!(store.get(missing_hash).unwrap(), None);
}
