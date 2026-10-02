//! valutx-sandbox
//!
//! Sandboxing abstraction providing OS-level isolation (Landlock, Job Objects, containers).

#![deny(unsafe_code)]
#![warn(missing_docs)]

/// Isolation backend profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsolationLevel {
    /// Restricted local sandbox profile.
    Restricted,
    /// Ephemeral container/VM sandbox.
    Container,
    /// Network-isolated security range.
    IsolatedLab,
}

/// Sandbox configuration.
#[derive(Debug, Clone)]
pub struct SandboxConfig {
    /// Selected isolation level.
    pub level: IsolationLevel,
    /// Maximum memory limit in bytes.
    pub max_memory_bytes: u64,
    /// Maximum execution timeout in seconds.
    pub timeout_seconds: u32,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            level: IsolationLevel::Restricted,
            max_memory_bytes: 1024 * 1024 * 512, // 512 MB
            timeout_seconds: 60,
        }
    }
}
