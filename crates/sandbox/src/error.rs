//! Error types for valutx-sandbox.
//!
//! All errors use stable code strings matching the error vocabulary defined in
//! the Engineering Master Specification (§ Structured Error Codes).

use thiserror::Error;

/// Stable error codes for sandbox failures, surfaced across the IPC boundary.
pub mod codes {
    /// The sandbox subsystem is not available on this platform or configuration.
    /// Execution MUST be refused — no fallback to raw exec is permitted.
    pub const SANDBOX_UNAVAILABLE: &str = "SANDBOX_UNAVAILABLE";
    /// The sandbox initialization succeeded but the requested capability is denied.
    pub const SCOPE_DENIED: &str = "SCOPE_DENIED";
    /// The Landlock ABI version is below the minimum required (< 1).
    pub const SANDBOX_ABI_TOO_OLD: &str = "SANDBOX_ABI_TOO_OLD";
}

/// Errors produced by the sandbox crate.
#[derive(Debug, Error)]
pub enum SandboxError {
    /// The sandbox cannot be initialized on this platform/kernel.
    /// Execution MUST be refused (fail-closed invariant).
    #[error("[{code}] {reason}")]
    Unavailable {
        /// Stable error code.
        code: &'static str,
        /// Human-readable reason.
        reason: String,
    },

    /// A requested filesystem capability was denied by the active policy.
    #[error("[{code}] capability denied: {detail}")]
    CapabilityDenied {
        /// Stable error code.
        code: &'static str,
        /// Detail of the denied capability.
        detail: String,
    },

    /// An OS-level I/O error occurred during sandbox setup.
    #[error("[SANDBOX_UNAVAILABLE] OS error during sandbox init: {0}")]
    Io(#[from] std::io::Error),
}

impl SandboxError {
    /// Construct a `SANDBOX_UNAVAILABLE` error with a static reason string.
    pub fn unavailable(reason: impl Into<String>) -> Self {
        Self::Unavailable {
            code: codes::SANDBOX_UNAVAILABLE,
            reason: reason.into(),
        }
    }

    /// Construct a `SANDBOX_ABI_TOO_OLD` error.
    pub fn abi_too_old(found: i64, required: i64) -> Self {
        Self::Unavailable {
            code: codes::SANDBOX_ABI_TOO_OLD,
            reason: format!(
                "Landlock ABI version {} found, minimum required is {}",
                found, required
            ),
        }
    }

    /// Returns the stable error code string for IPC serialization.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Unavailable { code, .. } => code,
            Self::CapabilityDenied { code, .. } => code,
            Self::Io(_) => codes::SANDBOX_UNAVAILABLE,
        }
    }
}
