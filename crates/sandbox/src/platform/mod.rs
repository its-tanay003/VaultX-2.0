//! Platform-specific sandbox backend implementations.
//!
//! This module routes to the correct OS implementation at compile time.
//! Each backend must implement `SandboxBackend` and return `SANDBOX_UNAVAILABLE`
//! (never fall back to raw unsandboxed execution) if initialization fails.

#[cfg(unix)]
pub mod linux;

#[cfg(windows)]
pub mod windows;

/// Minimum Landlock ABI version required by VaultX.
/// ABI 1 (kernel 5.13): path-beneath read/write/exec rules.
/// ABI 2 (kernel 5.19): adds LANDLOCK_ACCESS_FS_REFER.
/// ABI 3 (kernel 6.2): adds truncate control.
/// We require ABI >= 1; we probe actual version and adapt feature set.
pub const LANDLOCK_MIN_ABI: i64 = 1;
