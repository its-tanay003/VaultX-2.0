//! valutx-sandbox
//!
//! OS-level isolation adapter for VaultX 2.0.
//!
//! ## Backend selection (Linux/WSL2)
//!
//! 1. **Primary**: In-process Landlock LSM + seccomp-bpf + user namespaces.
//!    ABI detected via `LANDLOCK_CREATE_RULESET_VERSION` syscall flag —
//!    works on WSL2 where `/sys/kernel/security/landlock/abi` is not mounted.
//! 2. **Fallback**: `bubblewrap` (`bwrap`) command-line isolation.
//!    Not pre-installed on all distributions; fail-closed if absent.
//! 3. **Fail-closed**: If neither backend is available, `init_sandbox()` returns
//!    `SANDBOX_UNAVAILABLE`. The caller MUST refuse execution — no raw exec fallback.
//!
//! ## Backend selection (Windows)
//!
//! Job Objects + restricted security tokens, enforced by `valutx-process-supervisor`.
//! This crate reports the capability; enforcement is in the process supervisor.
//!
//! ## References
//!
//! - [ADR-003](../../../docs/architecture/adr/ADR-003-os-sandboxing-and-cyber-lab.md)
//! - [ADR-003 Addendum](../../../docs/architecture/adr/ADR-003-ADDENDUM-sandbox-spike-results.md)
//! - Conformance tests: SAND-01..SAND-22

// Allow unsafe in platform submodules that need raw libc syscall FFI.
// The top-level lib itself is safe.
#![warn(missing_docs)]

pub mod error;
pub mod platform;

pub use error::{codes as error_codes, SandboxError};

#[cfg(unix)]
pub use platform::linux::{
    bwrap_available, bwrap_path, landlock_abi_version, seccomp_available,
    user_namespaces_available, LinuxCapabilities, SandboxBackendKind,
};

// ─── Public Types ─────────────────────────────────────────────────────────────

/// Isolation backend profile — what level of isolation is requested.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum IsolationLevel {
    /// Standard restricted sandbox: Landlock filesystem rules + seccomp-bpf filter.
    Restricted,
    /// Mount-namespace projection via `bwrap` (used for Kali Lab and complex envs).
    Container,
    /// Network-isolated security range (Kali cyber-lab workloads).
    IsolatedLab,
}

/// Sandbox configuration passed to `init_sandbox()`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SandboxConfig {
    /// Requested isolation level.
    pub level: IsolationLevel,
    /// Maximum memory in bytes (propagated to process-supervisor constraints).
    pub max_memory_bytes: u64,
    /// Wall-clock timeout in seconds (propagated to process-supervisor).
    pub timeout_seconds: u32,
    /// Filesystem paths the sandboxed process may read (Landlock allowlist).
    pub readable_paths: Vec<std::path::PathBuf>,
    /// Filesystem paths the sandboxed process may read AND write.
    pub writable_paths: Vec<std::path::PathBuf>,
    /// Whether outbound network access is permitted.
    pub network_allowed: bool,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            level: IsolationLevel::Restricted,
            max_memory_bytes: 512 * 1024 * 1024, // 512 MiB
            timeout_seconds: 60,
            readable_paths: Vec::new(),
            writable_paths: Vec::new(),
            network_allowed: false, // default-deny network
        }
    }
}

/// An opaque handle to an initialized sandbox environment.
///
/// Returned by `init_sandbox()`. Pass this to `valutx-process-supervisor`
/// when spawning a process; the supervisor applies the constraints encoded here.
///
/// ## Invariant
///
/// A `SandboxHandle` can only be constructed via `init_sandbox()`.
/// Construction validates that a backend is available. If no backend is
/// available, `init_sandbox()` returns `Err(SANDBOX_UNAVAILABLE)` and
/// the caller MUST refuse execution.
#[derive(Debug)]
pub struct SandboxHandle {
    /// Selected backend, for audit logging.
    pub(crate) backend_name: &'static str,
    /// The validated configuration for this sandbox instance.
    pub(crate) config: SandboxConfig,
    /// ABI version of the Landlock backend (0 if using bwrap or Windows).
    pub(crate) landlock_abi: i64,
}

impl SandboxHandle {
    /// The name of the active sandbox backend (e.g. `"landlock+seccomp"`, `"bwrap"`).
    pub fn backend_name(&self) -> &'static str {
        self.backend_name
    }

    /// The Landlock ABI version, or 0 if Landlock is not the active backend.
    pub fn landlock_abi(&self) -> i64 {
        self.landlock_abi
    }

    /// The configuration that was used to initialize this sandbox.
    pub fn config(&self) -> &SandboxConfig {
        &self.config
    }
}

// ─── Public API ───────────────────────────────────────────────────────────────

/// Initialize the sandbox and return an opaque `SandboxHandle`.
///
/// This is the **only** way to obtain a `SandboxHandle`. The function probes
/// the current platform for available sandbox backends and selects the best one
/// per ADR-003 §5.3 platform gating.
///
/// ## Fail-closed semantics
///
/// If no backend is available (Landlock unsupported AND bwrap not installed),
/// this function returns `Err(SandboxError::Unavailable)` with code
/// `SANDBOX_UNAVAILABLE`. **The caller must not proceed with unsandboxed execution.**
///
/// ## Platform behavior
///
/// - **Linux / WSL2 (kernel >= 5.13)**: Probes Landlock ABI via syscall flag
///   (not sysfs, which is absent in WSL2). Falls back to `bwrap` if Landlock
///   ABI < 1. Returns `SANDBOX_UNAVAILABLE` if both are absent.
/// - **Windows**: Job Objects are always available; returns a handle immediately.
/// - **macOS**: Deferred to Phase 3 (ADR-003). Currently returns `SANDBOX_UNAVAILABLE`.
pub fn init_sandbox(config: SandboxConfig) -> Result<SandboxHandle, SandboxError> {
    #[cfg(unix)]
    {
        let caps = LinuxCapabilities::probe();
        let backend = caps.select_backend()?;
        Ok(SandboxHandle {
            backend_name: backend.name(),
            landlock_abi: match &backend {
                SandboxBackendKind::LandlockSeccomp { abi, .. } => *abi,
                SandboxBackendKind::Bwrap { .. } => 0,
            },
            config,
        })
    }

    #[cfg(windows)]
    {
        let _caps = platform::windows::WindowsCapabilities::probe();
        // Windows sandbox enforcement is in valutx-process-supervisor (Job Objects).
        Ok(SandboxHandle {
            backend_name: "job-objects",
            landlock_abi: 0,
            config,
        })
    }

    #[cfg(not(any(unix, windows)))]
    {
        Err(SandboxError::unavailable(
            "Sandbox not implemented on this platform (macOS deferred to Phase 3).",
        ))
    }
}

/// Returns a structured capability report for the current platform.
///
/// Suitable for logging, UI display, and audit records.
pub fn capability_report() -> PlatformCapabilities {
    #[cfg(unix)]
    {
        let caps = LinuxCapabilities::probe();
        PlatformCapabilities {
            platform: "linux",
            landlock_abi: caps.landlock_abi,
            seccomp: caps.seccomp,
            user_namespaces: caps.user_namespaces,
            bwrap_path: caps.bwrap.map(|p| p.to_string_lossy().into_owned()),
            job_objects: false,
        }
    }
    #[cfg(windows)]
    {
        PlatformCapabilities {
            platform: "windows",
            landlock_abi: 0,
            seccomp: false,
            user_namespaces: false,
            bwrap_path: None,
            job_objects: true,
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        PlatformCapabilities {
            platform: "unknown",
            landlock_abi: 0,
            seccomp: false,
            user_namespaces: false,
            bwrap_path: None,
            job_objects: false,
        }
    }
}

/// Structured capability report for the current platform.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PlatformCapabilities {
    /// OS platform string.
    pub platform: &'static str,
    /// Landlock ABI version (0 = not supported).
    pub landlock_abi: i64,
    /// Whether seccomp-bpf is available.
    pub seccomp: bool,
    /// Whether unprivileged user namespaces are available.
    pub user_namespaces: bool,
    /// Absolute path to `bwrap` binary, or `None` if not installed.
    pub bwrap_path: Option<String>,
    /// Whether Windows Job Objects are available (Windows only).
    pub job_objects: bool,
}
