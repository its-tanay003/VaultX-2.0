use valutx_sandbox::{IsolationLevel, SandboxConfig};

#[test]
fn test_sandbox_default_is_restricted() {
    let config = SandboxConfig::default();
    assert_eq!(config.level, IsolationLevel::Restricted);
    assert!(config.max_memory_bytes > 0);
    assert!(config.timeout_seconds > 0);
}
