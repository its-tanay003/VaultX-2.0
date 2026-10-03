//! Windows sandbox backend stub.
//!
//! On Windows, process isolation is enforced by `valutx-process-supervisor` via
//! Windows Job Objects and restricted security tokens (implemented in P1-T04).
//! This crate's Windows backend is a thin capability reporter that confirms the
//! Job Object path is active and defers all enforcement to process-supervisor.

use crate::error::SandboxError;

/// Windows capability snapshot.
#[derive(Debug, Clone)]
pub struct WindowsCapabilities {
    /// Always `true` on Windows — Job Objects are a native kernel primitive.
    pub job_objects: bool,
}

impl WindowsCapabilities {
    /// Probe Windows sandbox capabilities.
    pub fn probe() -> Self {
        Self { job_objects: true }
    }

    /// Returns `Ok(())` since Job Objects are always available on Windows.
    /// Enforcement is delegated to `valutx-process-supervisor`.
    pub fn select_backend(&self) -> Result<(), SandboxError> {
        // Windows sandbox is always available via Job Objects in process-supervisor.
        Ok(())
    }
}
