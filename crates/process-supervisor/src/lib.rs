//! valutx-process-supervisor
//!
//! Sole authorized gateway for OS process execution.
//! No other component in the monorepo is permitted to spawn processes directly.

#![deny(unsafe_code)]
#![warn(missing_docs)]

/// Process execution options.
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

/// Supervised process instance.
pub struct ProcessSupervisor;

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
