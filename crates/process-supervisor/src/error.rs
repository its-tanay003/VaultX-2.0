//! Error definitions for valutx-process-supervisor.

use thiserror::Error;

/// Errors arising during process validation, spawning, or supervision.
#[derive(Debug, Error)]
pub enum SupervisorError {
    /// Target program path is empty.
    #[error("EMPTY_PROGRAM: Target binary program cannot be empty")]
    EmptyProgram,

    /// Execution timeout cannot be zero.
    #[error("ZERO_TIMEOUT: Execution timeout must be greater than zero")]
    ZeroTimeout,

    /// Target program is not allowed by policy constraints.
    #[error("POLICY_DENIED: Target executable '{0}' is not in the allowed processes list")]
    DisallowedProcess(String),

    /// Standard I/O error during process creation or pipe communication.
    #[error("IO_ERROR: {0}")]
    Io(#[from] std::io::Error),

    /// Operating system platform error (Job Object or signal error).
    #[error("OS_ERROR: {0}")]
    OsError(String),

    /// Supervised process was already terminated or waited upon.
    #[error("ALREADY_TERMINATED: Process handle has already terminated")]
    AlreadyTerminated,
}
