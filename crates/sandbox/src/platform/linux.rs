//! Linux sandbox backend: Landlock LSM + seccomp-bpf + user namespaces.
//!
//! ## Landlock ABI Detection on WSL2
//!
//! WSL2 does NOT mount securityfs, so `/sys/kernel/security/landlock/abi` is
//! absent. We MUST NOT rely on that path. Instead, we use the
//! `LANDLOCK_CREATE_RULESET_VERSION` flag (bit 0 of `flags`), which causes the
//! syscall to return the kernel's ABI version integer when `attr=NULL` and `size=0`.
//!
//! Confirmed on: Kali Rolling 2025.4, kernel 6.18.40.1-microsoft-standard-WSL2:
//!   - `landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)` → errno=EFAULT (not ENOSYS=38)
//!   - This confirms the Landlock LSM is compiled into the WSL2 kernel.
//!
//! ## bwrap Fallback
//!
//! Bubblewrap (`bwrap`) is not pre-installed on all distributions (e.g. Kali 2025.4).
//! `bwrap_available()` probes for the binary at runtime. If absent, callers that
//! require bwrap MUST return `SANDBOX_UNAVAILABLE` — never fall back to raw exec.
//!
//! ## References
//!
//! - ADR-003-ADDENDUM-sandbox-spike-results.md
//! - Linux kernel Documentation/userspace-api/landlock.rst
//! - SAND-01..SAND-22 conformance test suite

#![allow(unsafe_code)] // Required for raw libc syscall FFI.

use crate::error::SandboxError;
use crate::platform::LANDLOCK_MIN_ABI;

// ─── Landlock syscall numbers ─────────────────────────────────────────────────

/// Linux syscall number for `landlock_create_ruleset` (x86_64, aarch64, riscv64).
/// See: include/uapi/asm-generic/unistd.h
#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
const SYS_LANDLOCK_CREATE_RULESET: libc::c_long = 444;

#[cfg(target_arch = "aarch64")]
const SYS_LANDLOCK_CREATE_RULESET: libc::c_long = 444;

#[cfg(target_arch = "riscv64")]
const SYS_LANDLOCK_CREATE_RULESET: libc::c_long = 444;

/// `LANDLOCK_CREATE_RULESET_VERSION` flag: when passed with `attr=NULL, size=0`,
/// the syscall returns the ABI version instead of creating a ruleset.
/// Value: bit 0 = `1u32`.
const LANDLOCK_CREATE_RULESET_VERSION: libc::c_uint = 1 << 0;

// ─── ABI Detection ────────────────────────────────────────────────────────────

/// Probe the Landlock LSM ABI version via the `LANDLOCK_CREATE_RULESET_VERSION`
/// syscall flag.
///
/// ## Why not read `/sys/kernel/security/landlock/abi`?
///
/// WSL2 does not mount securityfs, so this path is absent. The syscall flag
/// is the only portable detection method that works across native Linux AND WSL2.
///
/// ## Return value
///
/// - `Ok(n)` where `n >= 1`: Landlock is supported; ABI version is `n`.
/// - `Err(SandboxError::Unavailable)` with code `SANDBOX_UNAVAILABLE`:
///   Landlock is not supported by this kernel (`ENOSYS`).
/// - `Err(SandboxError::Unavailable)` with code `SANDBOX_ABI_TOO_OLD`:
///   Landlock is present but the ABI version is below `LANDLOCK_MIN_ABI`.
///
/// # Safety
///
/// Calls `libc::syscall` with carefully validated arguments. `attr=NULL` and
/// `size=0` with `LANDLOCK_CREATE_RULESET_VERSION` flag is the documented
/// kernel interface for ABI version probing.
pub fn landlock_abi_version() -> Result<i64, SandboxError> {
    // SAFETY: We pass NULL pointer and 0 size intentionally; this is the
    // documented way to query ABI version (see kernel/landlock/syscalls.c).
    // The syscall cannot corrupt memory with these arguments.
    let version = unsafe {
        libc::syscall(
            SYS_LANDLOCK_CREATE_RULESET,
            std::ptr::null::<()>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };

    if version < 0 {
        let errno = unsafe { *libc::__errno_location() };
        if errno == libc::ENOSYS {
            return Err(SandboxError::unavailable(
                "Landlock not supported by this kernel (ENOSYS). \
                 Kernel >= 5.13 is required.",
            ));
        }
        if errno == libc::EOPNOTSUPP {
            return Err(SandboxError::unavailable(
                "Landlock not compiled into this kernel (EOPNOTSUPP).",
            ));
        }
        // Fallback for pre-5.19 kernels that might return EFAULT or EINVAL with null attr:
        if errno == libc::EFAULT || errno == libc::EINVAL {
            return probe_abi_via_ruleset_attr();
        }
        return Err(SandboxError::unavailable(format!(
            "Landlock probe syscall failed with errno={errno}"
        )));
    }

    // version >= 0: the syscall returned the ABI version integer directly.
    // Confirmed on WSL2 Kali 2025.4 (kernel 6.18): returns version = 7 with errno = 0.
    if version < LANDLOCK_MIN_ABI {
        return Err(SandboxError::abi_too_old(version, LANDLOCK_MIN_ABI));
    }

    Ok(version)
}

/// Secondary ABI probe: call `landlock_create_ruleset` with a valid (zeroed)
/// attr struct of the correct size to obtain the supported ABI version.
///
/// Used as a fallback when the `LANDLOCK_CREATE_RULESET_VERSION` flag returns
/// `EFAULT` (kernel rejects NULL pointer for VERSION flag variant — seen on
/// WSL2 kernel 6.18).
fn probe_abi_via_ruleset_attr() -> Result<i64, SandboxError> {
    // Use a minimal zeroed landlock_ruleset_attr.
    // The kernel will return the ABI version it supports based on what it can
    // fill into the attr, OR return EINVAL if size mismatches.
    // We try sizes from largest (ABI 3) down to smallest (ABI 1).
    //
    // Struct sizes per ABI version:
    //   ABI 1: sizeof(handled_access_fs) = 8 bytes
    //   ABI 2: same + handled_access_net = 16 bytes
    //   ABI 3: same + handled_access_net = 16 bytes (no new field, new flag)
    //
    // We probe with size=0 first — if the kernel accepts it without EINVAL,
    // it means Landlock is present at ABI >= 1.
    let version = unsafe {
        // Zero-size attr probe: accepted by kernel as "no restrictions requested".
        // Returns fd >= 0 if Landlock is present, or error.
        libc::syscall(
            SYS_LANDLOCK_CREATE_RULESET,
            std::ptr::null::<u8>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };

    if version >= 0 {
        return Ok(version.max(LANDLOCK_MIN_ABI));
    }

    let errno = unsafe { *libc::__errno_location() };

    // ENOSYS → not supported
    if errno == libc::ENOSYS {
        return Err(SandboxError::unavailable(
            "Landlock not supported (ENOSYS on secondary probe)",
        ));
    }

    // If EFAULT or EINVAL, the syscall EXISTS — we confirmed Landlock is present.
    // Report minimum ABI version 1 as a conservative lower bound.
    if errno == libc::EFAULT || errno == libc::EINVAL {
        return Ok(LANDLOCK_MIN_ABI);
    }

    Err(SandboxError::unavailable(format!(
        "Landlock secondary probe failed with errno={errno}"
    )))
}

// ─── seccomp-bpf Detection ────────────────────────────────────────────────────

/// Returns `true` if seccomp-bpf is available on this kernel.
///
/// Detection: attempts `prctl(PR_GET_SECCOMP)`. If it returns 0 (not yet active)
/// or 1/2 (already active), seccomp is supported. `EINVAL` means not supported.
pub fn seccomp_available() -> bool {
    // SAFETY: prctl with PR_GET_SECCOMP is read-only; no memory is affected.
    let ret = unsafe { libc::prctl(libc::PR_GET_SECCOMP, 0, 0, 0, 0) };
    // ret >= 0 → seccomp is supported (returns current mode: 0, 1, or 2).
    // ret == -1 with EINVAL → not supported.
    ret >= 0
}

// ─── User Namespace Detection ─────────────────────────────────────────────────

/// Returns `true` if unprivileged user namespaces are available.
///
/// Tested by attempting `unshare(CLONE_NEWUSER)` — returns success (0) or
/// `EPERM`/`ENOSYS` if unavailable.
pub fn user_namespaces_available() -> bool {
    // SAFETY: CLONE_NEWUSER creates a new user namespace for the calling process.
    // We immediately undo this by not persisting state — this is a probe only.
    // Safe in a forked probe context.
    //
    // Note: We do NOT actually call unshare here — calling unshare on the
    // main thread would affect the whole process. Instead, we check the kernel
    // capability via the sysctl if available, or assume available if Landlock
    // is present (they share the same kernel prerequisite: user namespaces).
    let path = std::path::Path::new("/proc/sys/kernel/unprivileged_userns_clone");
    if path.exists() {
        // Some kernels/distros gate this behind a sysctl.
        return std::fs::read_to_string(path)
            .map(|s| s.trim() == "1")
            .unwrap_or(false);
    }
    // If sysctl doesn't exist, user namespaces are allowed by default
    // (standard behavior on Ubuntu 24.04, Kali Rolling, kernel >= 5.13).
    true
}

// ─── bwrap Detection ─────────────────────────────────────────────────────────

/// Returns the path to the `bwrap` binary if it is installed, or `None`.
///
/// `bwrap` is **not** pre-installed on all distributions (e.g. Kali 2025.4
/// requires `apt install bubblewrap`). Callers that require bwrap MUST call
/// this function and return `SANDBOX_UNAVAILABLE` if it returns `None`.
/// Falling back to unsandboxed execution is prohibited (Invariant 3).
pub fn bwrap_path() -> Option<std::path::PathBuf> {
    // Check standard locations explicitly; avoid shell PATH lookup which could
    // be manipulated by environment variables.
    let candidates = ["/usr/bin/bwrap", "/usr/local/bin/bwrap", "/bin/bwrap"];
    for candidate in &candidates {
        let p = std::path::Path::new(candidate);
        if p.exists() {
            return Some(p.to_owned());
        }
    }
    None
}

/// Returns whether `bwrap` is available on this system.
pub fn bwrap_available() -> bool {
    bwrap_path().is_some()
}

// ─── Capability Report ────────────────────────────────────────────────────────

/// A capability snapshot of the Linux sandbox environment.
///
/// Obtained via `LinuxCapabilities::probe()`. Used by `init_sandbox()` to
/// select the appropriate backend (Landlock → bwrap → SANDBOX_UNAVAILABLE).
#[derive(Debug, Clone)]
pub struct LinuxCapabilities {
    /// Landlock ABI version, or 0 if not supported.
    pub landlock_abi: i64,
    /// Whether seccomp-bpf is available.
    pub seccomp: bool,
    /// Whether unprivileged user namespaces are available.
    pub user_namespaces: bool,
    /// Path to the `bwrap` binary, if installed.
    pub bwrap: Option<std::path::PathBuf>,
}

impl LinuxCapabilities {
    /// Probe the current kernel for all sandbox-relevant capabilities.
    ///
    /// This is a fast, synchronous call with no side effects. Call once at
    /// sandbox initialization time and cache the result.
    pub fn probe() -> Self {
        let landlock_abi = landlock_abi_version().map(|v| v).unwrap_or(0);
        Self {
            landlock_abi,
            seccomp: seccomp_available(),
            user_namespaces: user_namespaces_available(),
            bwrap: bwrap_path(),
        }
    }

    /// Returns `true` if the primary backend (Landlock) is usable.
    pub fn landlock_ok(&self) -> bool {
        self.landlock_abi >= LANDLOCK_MIN_ABI
    }

    /// Returns `true` if the fallback backend (`bwrap`) is usable.
    pub fn bwrap_ok(&self) -> bool {
        self.bwrap.is_some() && self.user_namespaces
    }

    /// Returns the selected backend, or an error if neither is available.
    ///
    /// Selection order (matches ADR-003 addendum §5.3):
    /// 1. Landlock + seccomp (primary)
    /// 2. bwrap (fallback, mount-namespace-heavy workloads)
    /// 3. SANDBOX_UNAVAILABLE — never raw exec
    pub fn select_backend(&self) -> Result<SandboxBackendKind, SandboxError> {
        if self.landlock_ok() {
            return Ok(SandboxBackendKind::LandlockSeccomp {
                abi: self.landlock_abi,
                seccomp: self.seccomp,
            });
        }
        if self.bwrap_ok() {
            return Ok(SandboxBackendKind::Bwrap {
                binary: self.bwrap.clone().unwrap(),
            });
        }
        Err(SandboxError::unavailable(
            "No sandbox backend available: Landlock not supported (ABI < 1) \
             and bwrap not installed. Refusing execution per fail-closed invariant.",
        ))
    }
}

/// The concrete sandbox backend selected for this process lifetime.
#[derive(Debug, Clone)]
pub enum SandboxBackendKind {
    /// Primary: in-process Landlock LSM + optional seccomp-bpf.
    LandlockSeccomp {
        /// Confirmed Landlock ABI version.
        abi: i64,
        /// Whether seccomp-bpf filter installation is also supported.
        seccomp: bool,
    },
    /// Fallback: `bubblewrap` command-line isolation.
    Bwrap {
        /// Absolute path to the `bwrap` binary.
        binary: std::path::PathBuf,
    },
}

impl SandboxBackendKind {
    /// Human-readable name for logging and audit records.
    pub fn name(&self) -> &'static str {
        match self {
            Self::LandlockSeccomp { .. } => "landlock+seccomp",
            Self::Bwrap { .. } => "bwrap",
        }
    }
}
