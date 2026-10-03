# Implementation Plan - Task P1-T04: Process Supervisor Single Choke Point

## Context & Requirements
- **Spec Reference**: Spec §36 (Engineering Coding Standards - all process execution through Process Supervisor), §37 (Resource Governance - CPU, Memory, Process Tree limits, Wall-clock, Output bounds).
- **Core Invariant**: `crates/process-supervisor` is the **SOLE** authorized gateway in VaultX 2.0 permitted to spawn OS processes. Direct invocation of `std::process::Command` or `tokio::process::Command` outside this crate is strictly forbidden and verified by CI architecture tests.
- **Human Review**: This plan specifies the cross-platform execution architecture, resource limits, tree termination mechanics, and verification test cases for review before implementation.

---

## 1. Architecture & API Design

### 1.1 Core Types (`crates/process-supervisor/src/`)
1. **`ExecutionRequest`**:
   - `program: String` (executable binary path or name)
   - `args: Vec<String>` (command-line arguments)
   - `cwd: Option<PathBuf>` (working directory)
   - `env: HashMap<String, String>` (isolated environment variables)
   - `stdin: Option<Vec<u8>>` (optional input payload)
2. **`ExecutionConstraints`** (adapted from `DecisionConstraints` / `Decision`):
   - `timeout_ms: u64` (wall-clock timeout; default: 30,000ms)
   - `max_memory_bytes: Option<u64>` (job-wide memory ceiling)
   - `max_cpu_time_ms: Option<u64>` (total user+kernel CPU limit)
   - `max_process_tree_size: Option<u32>` (maximum concurrent active processes in tree, e.g. 10)
   - `max_output_bytes: usize` (bounded stdout/stderr buffer; default: 1 MiB)
   - `allowed_processes: Vec<String>` (optional allowlist constraint)
3. **`SandboxHandle`**:
   - Encapsulates isolation context (Restricted, Container, IsolatedLab) from `valutx-sandbox`.
4. **`ProcessEvent`**:
   - `Started { pid: u32, timestamp: DateTime<Utc> }`
   - `StdoutChunk { bytes: usize }`
   - `StderrChunk { bytes: usize }`
   - `OutputTruncated { stream: &'static str, total_bytes: usize, limit_bytes: usize }`
   - `ResourceLimitExceeded { resource: &'static str, details: String }`
   - `Cancelled { reason: String, timestamp: DateTime<Utc> }`
   - `Terminated { exit_code: Option<i32>, signal: Option<i32>, duration_ms: u64 }`
5. **`ExecutionHandle`**:
   - `cancel(&self) -> Result<(), SupervisorError>`: Immediately terminates root process and all children/grandchildren.
   - `wait(self) -> Result<ExecutionResult, SupervisorError>`: Awaits completion or termination.
   - `poll_events(&mut self) -> Vec<ProcessEvent>`: Returns structured events collected so far.
6. **`ExecutionResult`**:
   - `exit_status: ProcessExitStatus` (`Exited(i32)`, `Signaled(i32)`, `KilledBySupervisor(TerminationReason)`)
   - `stdout: Vec<u8>` (bounded)
   - `stderr: Vec<u8>` (bounded)
   - `stdout_truncated: bool`
   - `stderr_truncated: bool`
   - `resource_usage: ResourceUsage` (`peak_memory_bytes`, `cpu_time_ms`, `wall_clock_ms`, `process_count`)
   - `events: Vec<ProcessEvent>`

---

## 2. Cross-Platform Process Tree & Resource Governance

### 2.1 Windows Implementation (`cfg(windows)`)
- Uses Windows **Job Objects** via safe wrappers around Win32 APIs:
  - `CreateJobObjectW`
  - `JOBOBJECT_EXTENDED_LIMIT_INFORMATION`:
    - `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`: Ensures zero orphaned processes even if supervisor crashes.
    - `JOB_OBJECT_LIMIT_ACTIVE_PROCESS`: Sets `ActiveProcessLimit = max_process_tree_size`. If a process attempts to spawn more children (fork bomb), the OS refuses the spawn with quota exceeded.
    - `JOB_OBJECT_LIMIT_JOB_MEMORY`: Limits total memory allocated across the job.
  - `AssignProcessToJobObject`: Atomically binds spawned process tree to the Job Object.
  - `TerminateJobObject`: Instantly terminates all processes in the job (root, children, grandchildren, orphans) with exit code `STATUS_FATAL_APP_EXIT` or supervisor-defined code.
  - `QueryInformationJobObject` (`JobObjectBasicAccountingInformation`): Accurately queries total CPU time, active process count, and peak memory.

### 2.2 Unix Implementation (`cfg(unix)`)
- Process group isolation via `std::os::unix::process::CommandExt::process_group(0)` / `setpgid`.
- Tree termination via `libc::kill(-pgid, libc::SIGKILL)` killing the entire process group including grandchildren.
- Background monitoring thread tracking `/proc` or `sysinfo` to measure memory, process tree size, and CPU usage.

### 2.3 Bounded Output Capture
- Separate background reader threads for `stdout` and `stderr`.
- Enforces `max_output_bytes`:
  - Captures up to the limit.
  - Once reached, sets `truncated = true` and emits `OutputTruncated` event.
  - Drops subsequent bytes to prevent unbounded heap memory exhaustion.

### 2.4 Cancellation & Timeout Mechanics
- Watchdog monitors wall-clock time vs `timeout_ms`.
- Cancellation flag / token triggers immediate tree kill.
- Cleanup ensures no orphaned processes remain.

---

## 3. Four Core Test Suites (`crates/process-supervisor/tests/`)

1. **`test_fork_bomb_contained`**:
   - Executes a recursive process spawner (PowerShell/CMD on Windows, shell loop on Unix).
   - Constrained with `max_process_tree_size = 5`.
   - Verifies the process tree does not grow unbounded, completes or gets terminated, and leaves no rogue processes running.
2. **`test_runaway_cpu_killed`**:
   - Executes a busy-loop process pegging CPU at 100%.
   - Constrained with strict wall-clock timeout (e.g. 500ms) or CPU time limit.
   - Verifies the process is promptly killed by the supervisor with `KilledBySupervisor(Timeout)`.
3. **`test_cancel_kills_grandchildren`**:
   - Spawns Parent -> spawns Child -> spawns Grandchild (running a long sleep).
   - Captures grandchild PID or verifies via Job Object / process table.
   - Invokes `handle.cancel()`.
   - Asserts Parent, Child, and Grandchild are all terminated with zero lingering orphans.
4. **`test_output_flood_truncated`**:
   - Executes a command generating 2MB+ of output (e.g. infinite loop of text).
   - Constrained with `max_output_bytes = 4096`.
   - Verifies `stdout.len() <= 4096`, `stdout_truncated == true`, and `OutputTruncated` event was emitted.

---

## 4. Architecture Enforcement Test

- Extends `crates/process-supervisor/tests/no_external_process_spawning.rs`:
  - Scans all Rust source files in `crates/`, `services/`, `apps/` (excluding `crates/process-supervisor`).
  - Verifies no usage of `std::process::Command`, `tokio::process::Command`, or `async_process::Command`.
  - Includes a dedicated test verifying that a synthetic/deliberate violation is caught and reported with diagnostic path and forbidden token details.

---

## 5. Verification Checklist
- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] `cargo test -p valutx-process-supervisor` (all 4 integration tests pass)
- [ ] Architecture test catches deliberate violation and passes on clean tree
- [ ] Workspace-wide test suite passes
