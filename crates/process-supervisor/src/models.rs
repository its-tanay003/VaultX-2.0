//! Data models and execution types for valutx-process-supervisor.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use valutx_policy_engine::models::{Decision, DecisionConstraints};

/// Process execution request submitted to the supervisor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionRequest {
    /// Target binary path or command name.
    pub program: String,
    /// Arguments passed to the target binary.
    pub args: Vec<String>,
    /// Working directory.
    pub cwd: Option<PathBuf>,
    /// Environment variables (isolated from host unless explicitly forwarded).
    pub env: HashMap<String, String>,
    /// Standard input bytes to supply to the process.
    pub stdin: Option<Vec<u8>>,
}

impl ExecutionRequest {
    /// Constructs a basic execution request.
    pub fn new<P: Into<String>>(program: P, args: Vec<String>) -> Self {
        Self {
            program: program.into(),
            args,
            cwd: None,
            env: HashMap::new(),
            stdin: None,
        }
    }

    /// Sets working directory.
    pub fn with_cwd<P: Into<PathBuf>>(mut self, cwd: P) -> Self {
        self.cwd = Some(cwd.into());
        self
    }

    /// Sets an environment variable.
    pub fn with_env<K: Into<String>, V: Into<String>>(mut self, key: K, value: V) -> Self {
        self.env.insert(key.into(), value.into());
        self
    }

    /// Sets stdin payload.
    pub fn with_stdin(mut self, stdin: Vec<u8>) -> Self {
        self.stdin = Some(stdin);
        self
    }
}

/// Resource and execution constraints enforced by the supervisor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionConstraints {
    /// Wall-clock timeout in milliseconds.
    pub timeout_ms: u64,
    /// Maximum allowed memory bytes for the entire process tree.
    pub max_memory_bytes: Option<u64>,
    /// Maximum allowed CPU time in milliseconds across all child processes.
    pub max_cpu_time_ms: Option<u64>,
    /// Maximum number of active processes in the process tree (fork-bomb guard).
    pub max_process_tree_size: Option<u32>,
    /// Maximum captured stdout/stderr bytes before truncation.
    pub max_output_bytes: usize,
    /// Allowlist of permitted binary names or paths (empty = any program permitted by decision).
    pub allowed_processes: Vec<String>,
}

impl Default for ExecutionConstraints {
    fn default() -> Self {
        Self {
            timeout_ms: 30_000,
            max_memory_bytes: Some(512 * 1024 * 1024), // 512 MiB
            max_cpu_time_ms: None,
            max_process_tree_size: Some(16),
            max_output_bytes: 1024 * 1024, // 1 MiB
            allowed_processes: Vec::new(),
        }
    }
}

impl ExecutionConstraints {
    /// Constructs constraints from a policy engine Decision.
    pub fn from_decision(decision: &Decision) -> Self {
        Self::from_constraints(&decision.constraints)
    }

    /// Constructs constraints from policy engine DecisionConstraints.
    pub fn from_constraints(constraints: &DecisionConstraints) -> Self {
        let timeout_ms = constraints
            .max_runtime_seconds
            .map(|s| s.saturating_mul(1000))
            .unwrap_or(30_000);

        Self {
            timeout_ms: if timeout_ms == 0 { 30_000 } else { timeout_ms },
            max_memory_bytes: Some(512 * 1024 * 1024),
            max_cpu_time_ms: None,
            max_process_tree_size: Some(16),
            max_output_bytes: 1024 * 1024,
            allowed_processes: constraints.allowed_processes.clone(),
        }
    }
}

/// Sandbox handle encapsulating execution containment profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxHandle {
    /// Sandbox profile name (e.g., "restricted", "container", "isolated-lab").
    pub profile: String,
    /// Indicates whether filesystem/network sandboxing is active.
    pub isolated: bool,
}

impl Default for SandboxHandle {
    fn default() -> Self {
        Self {
            profile: "restricted".to_string(),
            isolated: true,
        }
    }
}

/// Cause of forced termination by the supervisor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TerminationReason {
    /// Wall-clock execution exceeded timeout_ms.
    Timeout,
    /// Execution cancelled by caller.
    Cancelled,
    /// Process tree exceeded memory limit.
    MemoryLimitExceeded,
    /// Process tree exceeded CPU time limit.
    CpuLimitExceeded,
    /// Process tree exceeded maximum active process limit.
    ProcessCountExceeded,
    /// Target executable not permitted by policy constraints.
    DisallowedProcess,
    /// Supervisor shutdown or error.
    SupervisorShutdown,
}

/// Final exit status of the supervised process tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProcessExitStatus {
    /// Process exited normally with exit code.
    Exited(i32),
    /// Process terminated by OS signal (Unix).
    Signaled(i32),
    /// Process tree killed by supervisor due to governance limits or cancellation.
    KilledBySupervisor(TerminationReason),
}

impl ProcessExitStatus {
    /// Returns true if process exited cleanly with code 0.
    pub fn success(&self) -> bool {
        matches!(self, Self::Exited(0))
    }

    /// Returns the exit code if exited normally.
    pub fn code(&self) -> Option<i32> {
        match self {
            Self::Exited(c) => Some(*c),
            _ => None,
        }
    }
}

/// Structured events emitted during execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProcessEvent {
    /// Process tree started with root PID.
    Started {
        /// OS Process ID of the root child.
        pid: u32,
        /// Timestamp when process started.
        timestamp: DateTime<Utc>,
    },
    /// Incremental chunk captured from stdout.
    StdoutChunk {
        /// Number of bytes captured in this chunk.
        bytes: usize,
    },
    /// Incremental chunk captured from stderr.
    StderrChunk {
        /// Number of bytes captured in this chunk.
        bytes: usize,
    },
    /// Output buffer reached max_output_bytes limit; subsequent output dropped.
    OutputTruncated {
        /// Stream name ("stdout" or "stderr").
        stream: String,
        /// Total bytes emitted before truncation.
        total_bytes: usize,
        /// Maximum limit enforced.
        limit_bytes: usize,
    },
    /// Resource limit exceeded warning or trigger.
    ResourceLimitExceeded {
        /// Name of the exceeded resource.
        resource: String,
        /// Diagnostic details.
        details: String,
    },
    /// Execution cancelled by caller.
    Cancelled {
        /// Reason for cancellation.
        reason: String,
        /// Timestamp of cancellation.
        timestamp: DateTime<Utc>,
    },
    /// Process tree terminated.
    Terminated {
        /// Final exit status.
        status: ProcessExitStatus,
        /// Total elapsed duration in milliseconds.
        duration_ms: u64,
    },
}

/// Cumulative resource usage metrics measured across the process tree.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResourceUsage {
    /// Peak memory consumed by the process tree in bytes.
    pub peak_memory_bytes: u64,
    /// Total CPU time consumed in milliseconds (user + kernel).
    pub cpu_time_ms: u64,
    /// Total wall-clock elapsed time in milliseconds.
    pub wall_clock_ms: u64,
    /// Peak number of active processes observed in the tree.
    pub process_count: u32,
}

/// Comprehensive outcome of a supervised execution run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionResult {
    /// Final exit status.
    pub exit_status: ProcessExitStatus,
    /// Captured standard output (bounded by max_output_bytes).
    pub stdout: Vec<u8>,
    /// Captured standard error (bounded by max_output_bytes).
    pub stderr: Vec<u8>,
    /// True if stdout exceeded max_output_bytes and was truncated.
    pub stdout_truncated: bool,
    /// True if stderr exceeded max_output_bytes and was truncated.
    pub stderr_truncated: bool,
    /// Monitored resource metrics.
    pub resource_usage: ResourceUsage,
    /// Complete chronological log of structured execution events.
    pub events: Vec<ProcessEvent>,
}

impl ExecutionResult {
    /// Returns stdout as UTF-8 string (lossy if invalid UTF-8).
    pub fn stdout_utf8(&self) -> String {
        String::from_utf8_lossy(&self.stdout).to_string()
    }

    /// Returns stderr as UTF-8 string (lossy if invalid UTF-8).
    pub fn stderr_utf8(&self) -> String {
        String::from_utf8_lossy(&self.stderr).to_string()
    }
}
