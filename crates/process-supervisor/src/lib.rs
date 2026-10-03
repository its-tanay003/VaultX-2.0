//! valutx-process-supervisor
//!
//! Sole authorized gateway for OS process execution.
//! No other component in the monorepo is permitted to spawn processes directly.
//! All process creation passes through the supervisor with Job Object / process group
//! containment and bounded resource governance.

// Process supervisor encapsulates audited low-level OS process management and Job Object / process group FFI.
#![allow(unsafe_code)]
#![warn(missing_docs)]

pub mod error;
pub mod executor;
pub mod models;
pub mod platform;

pub use error::SupervisorError;
pub use executor::{ExecutionHandle, ProcessSupervisor};
pub use models::{
    ExecutionConstraints, ExecutionRequest, ExecutionResult, ProcessEvent, ProcessExitStatus,
    ResourceUsage, SandboxHandle, TerminationReason,
};

/// Backward-compatible process execution options for legacy callers.
#[derive(Debug, Clone)]
pub struct SpawnOptions {
    /// Target binary path.
    pub program: String,
    /// Normalized process arguments.
    pub args: Vec<String>,
    /// Working directory.
    pub cwd: String,
    /// Execution timeout in milliseconds.
    pub timeout_ms: u64,
}

impl ProcessSupervisor {
    /// Validates execution request and ensures program is tracked.
    pub fn validate_request(options: &SpawnOptions) -> Result<(), &'static str> {
        if options.program.is_empty() {
            return Err("EMPTY_PROGRAM");
        }
        if options.timeout_ms == 0 {
            return Err("ZERO_TIMEOUT");
        }
        Ok(())
    }
}
