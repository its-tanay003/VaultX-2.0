# valutx-process-supervisor

**Trust Level**: Sole Authority (Process Spawning)

## Purpose

Acts as the single, non-bypassable choke point for all process creation across the VaultX 2.0 ecosystem. Enforces process group tracking, Job Object containment, timeouts, resource quotas, output bounds, and tree-wide signal propagation.

## Architecture Invariants

- **CRITICAL**: This crate is the **ONLY** place in the entire codebase permitted to invoke process execution APIs (`std::process::Command`, `tokio::process::Command`, `async_process::Command`). Enforced continuously by CI architecture tests.
- **NEVER** spawn orphaned or unmonitored child processes.
- **NEVER** allow child processes to run without hard timeouts.
- **NEVER** buffer unbounded output from child processes; output streams are strictly capped by `max_output_bytes`.
- **FAIL CLOSED**: Cancellation and resource limit breaches immediately terminate the entire process tree (root, children, grandchildren, and orphans).

## Platform Governance Primitives

- **Windows (`cfg(windows)`)**: Employs kernel-level **Windows Job Objects** via `windows-sys`:
  - `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`: Prevents orphan leaks if supervisor terminates.
  - `JOB_OBJECT_LIMIT_ACTIVE_PROCESS`: Enforces `max_process_tree_size` directly at the OS kernel level, halting fork bombs with quota errors.
  - `JOB_OBJECT_LIMIT_JOB_MEMORY`: Bounds total physical/virtual memory across the process tree.
  - `TerminateJobObject`: Atomically terminates all processes in the job tree.
  - `QueryInformationJobObject`: Accurately queries total user+kernel CPU time and peak job memory.
- **Unix (`cfg(unix)`)**: Employs **Process Groups**:
  - `process_group(0)` creates a dedicated process group.
  - `libc::kill(-pgid, libc::SIGKILL)` dispatches atomic termination across parents, children, and grandchildren.

## Integration & Governance Tests

1. **Fork Bomb Contained**: Active process limit stops runaway process generation; child tree is terminated.
2. **Runaway CPU Killed**: Busy-loop processes pegging 100% CPU are promptly terminated when wall-clock timeout or CPU quota expires.
3. **Cancel Kills Grandchildren**: Cancelling the supervisor handle cleanly eliminates entire 3-tier process hierarchies without orphan leakage.
4. **Output Flood Truncated**: Processes emitting large streams are truncated at `max_output_bytes`, memory remains bounded, and an `OutputTruncated` structured event is recorded.
5. **Architecture Invariant Scanner**: Scans all crates, services, and apps for forbidden spawning tokens and deliberately catches simulated violations.
