use valutx_audit::AuditEvent;

#[test]
fn test_broken_sequence_rejected() {
    let e1 = AuditEvent {
        sequence: 1,
        capability: "project.read".into(),
        actor: "user".into(),
        prev_hash: "000".into(),
    };
    let e2 = AuditEvent {
        sequence: 3, // Skipped 2!
        capability: "project.write".into(),
        actor: "agent".into(),
        prev_hash: "abc".into(),
    };
    assert!(!AuditEvent::verify_link(&e1, &e2));
}
