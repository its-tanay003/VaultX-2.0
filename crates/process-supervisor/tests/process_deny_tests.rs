use valutx_process_supervisor::{ProcessSupervisor, SpawnOptions};

#[test]
fn test_rejects_empty_program() {
    let opts = SpawnOptions {
        program: "".into(),
        args: vec![],
        cwd: ".".into(),
        timeout_ms: 1000,
    };
    assert_eq!(
        ProcessSupervisor::validate_request(&opts),
        Err("EMPTY_PROGRAM")
    );
}

#[test]
fn test_rejects_zero_timeout() {
    let opts = SpawnOptions {
        program: "echo".into(),
        args: vec!["test".into()],
        cwd: ".".into(),
        timeout_ms: 0,
    };
    assert_eq!(
        ProcessSupervisor::validate_request(&opts),
        Err("ZERO_TIMEOUT")
    );
}
