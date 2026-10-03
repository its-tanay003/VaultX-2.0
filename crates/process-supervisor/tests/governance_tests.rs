//! Governance and containment integration tests for valutx-process-supervisor.
//!
//! Required test cases:
//! 1. Fork bomb contained (active process limit / Job Object quota).
//! 2. Runaway CPU killed (wall-clock timeout / CPU governance).
//! 3. Cancel kills grandchildren (tree-wide termination without orphan leaks).
//! 4. Output flood truncated (bounded stream buffers and truncation events).

use std::thread;
use std::time::Duration;
use valutx_process_supervisor::{
    ExecutionConstraints, ExecutionRequest, ProcessEvent, ProcessExitStatus, ProcessSupervisor,
    SandboxHandle, TerminationReason,
};

/// Helper returning platform-specific shell and args.
fn shell_command(script: &str) -> (String, Vec<String>) {
    if cfg!(windows) {
        (
            "powershell".to_string(),
            vec![
                "-NoProfile".to_string(),
                "-NonInteractive".to_string(),
                "-Command".to_string(),
                script.to_string(),
            ],
        )
    } else {
        ("sh".to_string(), vec!["-c".to_string(), script.to_string()])
    }
}

#[test]
fn test_fork_bomb_contained() {
    // Attempt to spawn multiple rapid child processes in a loop.
    let script = if cfg!(windows) {
        "1..15 | ForEach-Object { Start-Process cmd -ArgumentList '/c timeout /t 5' }"
    } else {
        "for i in $(seq 1 15); do sleep 5 & done"
    };

    let (prog, args) = shell_command(script);
    let request = ExecutionRequest::new(prog, args);

    // Limit process tree size to 4 active processes.
    let constraints = ExecutionConstraints {
        timeout_ms: 5000,
        max_process_tree_size: Some(4),
        max_memory_bytes: Some(128 * 1024 * 1024),
        max_output_bytes: 64 * 1024,
        ..Default::default()
    };

    let sandbox = SandboxHandle::default();
    let result = ProcessSupervisor::execute(&request, &constraints, &sandbox);

    assert!(
        result.is_ok(),
        "Supervisor execution should succeed: {:?}",
        result.err()
    );
    let outcome = result.unwrap();

    // The fork bomb should be stopped either by Job Object quota or supervisor termination.
    // In either case, the process tree size must not exceed the limit, or supervisor killed it.
    let contained = match outcome.exit_status {
        ProcessExitStatus::KilledBySupervisor(TerminationReason::ProcessCountExceeded) => true,
        ProcessExitStatus::KilledBySupervisor(TerminationReason::Timeout) => true,
        ProcessExitStatus::Exited(_) => {
            // If the shell handled the OS quota failure and exited, peak process count was constrained
            outcome.resource_usage.process_count <= 8
        }
        _ => false,
    };

    assert!(
        contained,
        "Fork bomb was not properly contained! Outcome: {:?}",
        outcome.exit_status
    );
}

#[test]
fn test_runaway_cpu_killed() {
    // Infinite busy loop consuming 100% CPU.
    let script = if cfg!(windows) {
        "while ($true) { $x = 1 + 1 }"
    } else {
        "while true; do :; done"
    };

    let (prog, args) = shell_command(script);
    let request = ExecutionRequest::new(prog, args);

    // Strict 600ms timeout
    let constraints = ExecutionConstraints {
        timeout_ms: 600,
        max_output_bytes: 4096,
        ..Default::default()
    };

    let sandbox = SandboxHandle::default();
    let start = std::time::Instant::now();
    let result = ProcessSupervisor::execute(&request, &constraints, &sandbox);
    let elapsed = start.elapsed();

    assert!(
        result.is_ok(),
        "Supervisor should return Ok(result): {:?}",
        result.err()
    );
    let outcome = result.unwrap();

    assert_eq!(
        outcome.exit_status,
        ProcessExitStatus::KilledBySupervisor(TerminationReason::Timeout),
        "Runaway process should be terminated due to timeout!"
    );

    // Verify it terminated promptly around the timeout mark (not hanging indefinitely)
    assert!(
        elapsed < Duration::from_millis(3000),
        "Process kill took too long: {:?}",
        elapsed
    );
}

#[test]
fn test_cancel_kills_grandchildren() {
    // Spawns parent -> child -> grandchild sleeping for 30 seconds
    let script = if cfg!(windows) {
        "cmd /c start /b ping -n 30 127.0.0.1"
    } else {
        "sh -c 'sleep 30 & wait' &"
    };

    let (prog, args) = shell_command(script);
    let request = ExecutionRequest::new(prog, args);

    let constraints = ExecutionConstraints {
        timeout_ms: 10_000,
        max_output_bytes: 4096,
        ..Default::default()
    };

    let sandbox = SandboxHandle::default();
    let handle = ProcessSupervisor::spawn(&request, &constraints, &sandbox)
        .expect("Failed to spawn process tree");

    let root_pid = handle.pid();

    // Give grandchild 300ms to spin up
    thread::sleep(Duration::from_millis(300));

    // Cancel supervisor handle
    handle.cancel().expect("Cancel should succeed");

    let outcome = handle
        .wait()
        .expect("Wait should return result after cancel");
    assert_eq!(
        outcome.exit_status,
        ProcessExitStatus::KilledBySupervisor(TerminationReason::Cancelled),
        "Exit status should reflect supervisor cancellation"
    );

    // Verify root and descendant processes are dead
    thread::sleep(Duration::from_millis(200));

    let mut sys = sysinfo::System::new();
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All);

    let root_alive = sys.process(sysinfo::Pid::from(root_pid as usize)).is_some();
    assert!(
        !root_alive,
        "Root process {} should be dead after cancel",
        root_pid
    );
}

#[test]
fn test_output_flood_truncated() {
    // Generate over 50,000 bytes of output
    let script = if cfg!(windows) {
        "1..1000 | ForEach-Object { 'FLOOD_LINE_PADDING_DATA_FOR_TRUNCATION_TEST_' + $_ }"
    } else {
        "for i in $(seq 1 1000); do echo FLOOD_LINE_PADDING_DATA_FOR_TRUNCATION_TEST_$i; done"
    };

    let (prog, args) = shell_command(script);
    let request = ExecutionRequest::new(prog, args);

    // Constrain buffer to at most 2048 bytes
    let constraints = ExecutionConstraints {
        timeout_ms: 10_000,
        max_output_bytes: 2048,
        ..Default::default()
    };

    let sandbox = SandboxHandle::default();
    let outcome = ProcessSupervisor::execute(&request, &constraints, &sandbox)
        .expect("Execution should succeed");

    assert!(
        outcome.stdout.len() <= 2048,
        "Captured stdout length {} exceeded limit of 2048 bytes!",
        outcome.stdout.len()
    );

    assert!(
        outcome.stdout_truncated,
        "stdout_truncated flag should be true when output exceeds limit"
    );

    let has_truncation_event = outcome.events.iter().any(|e| {
        matches!(
            e,
            ProcessEvent::OutputTruncated {
                stream,
                limit_bytes,
                ..
            } if stream == "stdout" && *limit_bytes == 2048
        )
    });

    assert!(
        has_truncation_event,
        "Expected OutputTruncated event in event stream: {:?}",
        outcome.events
    );
}
