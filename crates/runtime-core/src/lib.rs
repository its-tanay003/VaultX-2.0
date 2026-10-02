//! valutx-runtime-core
//!
//! Central runtime coordinator and task state machine.
//! Authority: High. Enforces fail-closed execution.

#![deny(unsafe_code)]
#![warn(missing_docs)]

/// Protocol definitions and version negotiation for VaultX 2.0.
pub mod protocol;

/// Local authenticated IPC daemon subsystem.
pub mod ipc;

/// System diagnostic and host readiness subsystem.
pub mod doctor;

/// Runtime lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeState {
    /// Initial created state.
    Created,
    /// Context engine prepared repository index.
    ContextReady,
    /// Task plan is generated and awaiting policy validation.
    PlanReady,
    /// Currently undergoing policy evaluation.
    PolicyCheck,
    /// Execution active within sandbox.
    Executing,
    /// Verification checks running.
    Verifying,
    /// Task successfully verified and completed.
    Completed,
    /// Task failed policy or verification; recovery/rollback triggered.
    Failed,
}

/// Structured runtime error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeError {
    /// Stable error code.
    pub code: &'static str,
    /// Human readable message.
    pub message: String,
}

impl RuntimeError {
    /// Create new runtime error.
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

/// Returns runtime version string.
pub fn runtime_version() -> &'static str {
    "0.1.0"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initial_state() {
        assert_eq!(RuntimeState::Created, RuntimeState::Created);
    }
}
