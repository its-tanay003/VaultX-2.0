//! System Diagnostic Subsystem (`valutx doctor`)
//!
//! Evaluates host environment readiness for VaultX 2.0 sandboxing,
//! IPC, security capabilities, and hardware resources.

use serde::{Deserialize, Serialize};
use std::path::Path;
use sysinfo::{Disks, System};

/// Comprehensive report of host system readiness.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoctorReport {
    /// Operating system platform name.
    pub os: String,
    /// Operating system version or release.
    pub os_version: String,
    /// Kernel version string.
    pub kernel_version: String,
    /// Whether running within Windows Subsystem for Linux 2.
    pub is_wsl2: bool,
    /// Available Landlock ABI version (if supported on Linux/WSL2).
    pub landlock_abi_version: Option<u32>,
    /// Whether bubblewrap (`bwrap`) is installed and executable.
    pub bubblewrap_present: bool,
    /// Path to `bwrap` executable if found.
    pub bubblewrap_path: Option<String>,
    /// Unprivileged user namespaces availability.
    pub unprivileged_userns_available: bool,
    /// Whether Ubuntu 24.04 AppArmor restricts unprivileged userns.
    pub ubuntu_24_apparmor_restricted: bool,
    /// Whether an OS-native keychain / credential vault is available.
    pub keychain_available: bool,
    /// Name of the detected credential facility.
    pub keychain_provider: String,
    /// Total system physical memory in Megabytes.
    pub total_ram_mb: u64,
    /// Free system physical memory in Megabytes.
    pub free_ram_mb: u64,
    /// Available storage space in Gigabytes on the primary/runtime disk.
    pub free_disk_gb: u64,
    /// Whether an accelerator/GPU device was detected.
    pub gpu_present: bool,
    /// Details of detected GPU / display devices.
    pub gpu_details: Vec<String>,
    /// Hard blockers that prevent secure operation.
    pub blockers: Vec<String>,
    /// Operational warnings that may degrade performance or isolation.
    pub warnings: Vec<String>,
    /// Overall readiness: "READY" or "BLOCKED".
    pub overall_status: String,
}

impl DoctorReport {
    /// Inspects the local host environment and compiles a diagnostic report.
    pub fn probe() -> Self {
        let mut sys = System::new_all();
        sys.refresh_all();

        let os = std::env::consts::OS.to_string();
        let os_version = System::os_version().unwrap_or_else(|| "Unknown".to_string());
        let kernel_version = System::kernel_version().unwrap_or_else(|| "Unknown".to_string());

        let is_wsl2 = Self::probe_wsl2();
        let (landlock_abi_version, landlock_notes) = Self::probe_landlock();
        let (bubblewrap_present, bubblewrap_path) = Self::probe_bubblewrap();
        let (unprivileged_userns_available, ubuntu_24_apparmor_restricted) =
            Self::probe_user_namespaces();
        let (keychain_available, keychain_provider) = Self::probe_keychain();

        let total_ram_mb = sys.total_memory() / (1024 * 1024);
        let free_ram_mb = sys.available_memory() / (1024 * 1024);

        let disks = Disks::new_with_refreshed_list();
        let free_disk_gb =
            disks.iter().map(|d| d.available_space()).max().unwrap_or(0) / (1024 * 1024 * 1024);

        let (gpu_present, gpu_details) = Self::probe_gpu();

        let mut blockers = Vec::new();
        let mut warnings = Vec::new();

        // 1. Sandboxing readiness evaluation
        if os == "windows" {
            // On Windows, Linux container/sandbox tasks require WSL2
            if !Self::check_wsl_available_on_windows() {
                warnings.push(
                    "WSL2 is not detected in PATH. Linux-based sandboxing requires WSL2 with Ubuntu."
                        .to_string(),
                );
            }
        } else if os == "linux" {
            if !bubblewrap_present && landlock_abi_version.is_none() {
                blockers.push(
                    "Neither Bubblewrap (`bwrap`) nor Landlock ABI is available for Linux sandboxing."
                        .to_string(),
                );
            }
            if ubuntu_24_apparmor_restricted {
                warnings.push(
                    "Ubuntu 24.04 AppArmor restriction active on unprivileged user namespaces. Configure /etc/apparmor.d/bwrap or sysctl kernel.apparmor_restrict_unprivileged_userns=0."
                        .to_string(),
                );
            }
        }

        // Add landlock notes if any
        if let Some(note) = landlock_notes {
            warnings.push(note);
        }

        // 2. Resource evaluations
        if total_ram_mb < 4096 {
            warnings.push(format!(
                "Total system RAM ({} MB) is below the recommended 4096 MB baseline.",
                total_ram_mb
            ));
        }
        if free_disk_gb < 2 {
            blockers.push(format!(
                "Available disk space ({} GB) is critically low (< 2 GB).",
                free_disk_gb
            ));
        }

        let overall_status = if blockers.is_empty() {
            "READY".to_string()
        } else {
            "BLOCKED".to_string()
        };

        Self {
            os,
            os_version,
            kernel_version,
            is_wsl2,
            landlock_abi_version,
            bubblewrap_present,
            bubblewrap_path,
            unprivileged_userns_available,
            ubuntu_24_apparmor_restricted,
            keychain_available,
            keychain_provider,
            total_ram_mb,
            free_ram_mb,
            free_disk_gb,
            gpu_present,
            gpu_details,
            blockers,
            warnings,
            overall_status,
        }
    }

    /// Checks if running under WSL2.
    fn probe_wsl2() -> bool {
        if std::env::var("WSL_DISTRO_NAME").is_ok() || std::env::var("WSL_INTEROP").is_ok() {
            return true;
        }
        if let Ok(version_info) = std::fs::read_to_string("/proc/version") {
            if version_info.to_lowercase().contains("microsoft")
                || version_info.to_lowercase().contains("wsl")
            {
                return true;
            }
        }
        false
    }

    /// Probes whether Windows host has wsl.exe installed.
    fn check_wsl_available_on_windows() -> bool {
        if Path::new(r"C:\Windows\System32\wsl.exe").exists() {
            return true;
        }
        if let Ok(path_var) = std::env::var("PATH") {
            for dir in std::env::split_paths(&path_var) {
                if dir.join("wsl.exe").exists() {
                    return true;
                }
            }
        }
        false
    }

    /// Probes Linux Landlock LSM support.
    fn probe_landlock() -> (Option<u32>, Option<String>) {
        #[cfg(target_os = "linux")]
        {
            // Probe LSM list in /sys/kernel/security/lsm
            if let Ok(lsm) = std::fs::read_to_string("/sys/kernel/security/lsm") {
                if !lsm.contains("landlock") {
                    return (
                        None,
                        Some("Landlock is not listed in active security modules (/sys/kernel/security/lsm)".to_string()),
                    );
                }
            } else {
                return (
                    None,
                    Some("Unable to access /sys/kernel/security/lsm".to_string()),
                );
            }

            // Infer ABI version safely from kernel release if Landlock is active in LSM
            let kernel = System::kernel_version().unwrap_or_default();
            let abi = if kernel.starts_with("6.") {
                Some(4)
            } else if kernel.starts_with("5.1") {
                Some(1)
            } else {
                Some(1)
            };
            (abi, None)
        }
        #[cfg(not(target_os = "linux"))]
        {
            (None, None)
        }
    }

    /// Probes `bwrap` executable presence in PATH without spawning raw subprocesses.
    fn probe_bubblewrap() -> (bool, Option<String>) {
        if let Ok(path_var) = std::env::var("PATH") {
            for dir in std::env::split_paths(&path_var) {
                let candidate = dir.join("bwrap");
                let candidate_exe = dir.join("bwrap.exe");
                if candidate.is_file() {
                    return (true, Some(candidate.to_string_lossy().to_string()));
                }
                if candidate_exe.is_file() {
                    return (true, Some(candidate_exe.to_string_lossy().to_string()));
                }
            }
        }
        (false, None)
    }

    /// Probes unprivileged user namespace clone and Ubuntu 24.04 AppArmor restrictions.
    fn probe_user_namespaces() -> (bool, bool) {
        #[cfg(target_os = "linux")]
        {
            let mut available = true;
            let mut apparmor_restricted = false;

            if let Ok(val) = std::fs::read_to_string("/proc/sys/kernel/unprivileged_userns_clone") {
                if val.trim() == "0" {
                    available = false;
                }
            }
            if let Ok(val) = std::fs::read_to_string("/proc/sys/user/max_user_namespaces") {
                if val.trim() == "0" {
                    available = false;
                }
            }

            // Check Ubuntu 24.04 AppArmor restriction
            if let Ok(val) =
                std::fs::read_to_string("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
            {
                if val.trim() == "1" {
                    apparmor_restricted = true;
                }
            }

            (available, apparmor_restricted)
        }
        #[cfg(not(target_os = "linux"))]
        {
            // On Windows host, namespaces are delegated to WSL2
            (false, false)
        }
    }

    /// Probes keychain / OS credential store availability.
    fn probe_keychain() -> (bool, String) {
        #[cfg(target_os = "windows")]
        {
            (
                true,
                "Windows Credential Manager / DPAPI (Native)".to_string(),
            )
        }
        #[cfg(target_os = "macos")]
        {
            (true, "macOS Keychain Services (Native)".to_string())
        }
        #[cfg(target_os = "linux")]
        {
            // Check for Secret Service / libsecret or kernel keyring
            if Path::new("/proc/keys").exists() {
                (true, "Linux Kernel Keyring / Secret Service".to_string())
            } else {
                (true, "Local Encrypted SQLite Vault Fallback".to_string())
            }
        }
    }

    /// Probes GPU presence.
    fn probe_gpu() -> (bool, Vec<String>) {
        let mut devices = Vec::new();

        #[cfg(target_os = "windows")]
        {
            // Check common display adapter paths or NVIDIA SMI
            if Path::new(r"C:\Windows\System32\nvidia-smi.exe").exists()
                || Path::new(r"C:\Program Files\NVIDIA Corporation\NVSMI\nvidia-smi.exe").exists()
            {
                devices.push("NVIDIA GPU (nvidia-smi detected)".to_string());
            } else {
                devices.push("Windows DirectX/D3D Display Adapter".to_string());
            }
        }
        #[cfg(target_os = "linux")]
        {
            if Path::new("/dev/dri/card0").exists() || Path::new("/dev/dri/renderD128").exists() {
                devices.push("Linux Direct Rendering Device (/dev/dri)".to_string());
            }
            if Path::new("/proc/driver/nvidia/version").exists() {
                devices.push("NVIDIA Linux Driver".to_string());
            }
        }

        let present = !devices.is_empty();
        (present, devices)
    }

    /// Formats the report for human-readable terminal output.
    pub fn to_human_readable(&self) -> String {
        let mut out = String::new();
        out.push_str(
            "================================================================================\n",
        );
        out.push_str(" VaultX 2.0 Doctor - Host Readiness Diagnostic\n");
        out.push_str(
            "================================================================================\n\n",
        );

        out.push_str(&format!(
            "  Operating System:      {} ({})\n",
            self.os, self.os_version
        ));
        out.push_str(&format!(
            "  Kernel Version:        {}\n",
            self.kernel_version
        ));
        out.push_str(&format!(
            "  WSL2 Environment:      {}\n",
            if self.is_wsl2 {
                "YES (Active)"
            } else {
                "NO (Host/Bare)"
            }
        ));
        out.push_str(&format!(
            "  Keychain Facility:     {}\n",
            self.keychain_provider
        ));
        out.push_str(&format!(
            "  Physical RAM:          {} MB total ({} MB free)\n",
            self.total_ram_mb, self.free_ram_mb
        ));
        out.push_str(&format!(
            "  Primary Storage:       {} GB free\n",
            self.free_disk_gb
        ));
        out.push_str(&format!(
            "  GPU Acceleration:      {}\n",
            if self.gpu_present {
                self.gpu_details.join(", ")
            } else {
                "None detected".to_string()
            }
        ));

        out.push_str("\nSANDBOX & ISOLATION SUBSYSTEMS:\n");
        out.push_str(&format!(
            "  Bubblewrap (bwrap):    {}\n",
            if self.bubblewrap_present {
                format!(
                    "INSTALLED ({})",
                    self.bubblewrap_path.as_deref().unwrap_or("PATH")
                )
            } else {
                "NOT FOUND".to_string()
            }
        ));
        out.push_str(&format!(
            "  Landlock ABI Support:  {}\n",
            match self.landlock_abi_version {
                Some(v) => format!("ABI v{}", v),
                None => "UNAVAILABLE".to_string(),
            }
        ));
        out.push_str(&format!(
            "  Unprivileged UserNS:   {}\n",
            if self.unprivileged_userns_available {
                "AVAILABLE"
            } else {
                "RESTRICTED / DISABLED"
            }
        ));
        out.push_str(&format!(
            "  Ubuntu 24.04 AppArmor: {}\n",
            if self.ubuntu_24_apparmor_restricted {
                "RESTRICTION ACTIVE (Requires profile)"
            } else {
                "NOT RESTRICTED"
            }
        ));

        out.push_str("\nDIAGNOSTIC VERDICT:\n");
        out.push_str(&format!(
            "  Status:                {}\n",
            self.overall_status
        ));

        if !self.blockers.is_empty() {
            out.push_str("\n  BLOCKERS (Must be resolved before sandboxing):\n");
            for b in &self.blockers {
                out.push_str(&format!("    [!] {}\n", b));
            }
        }

        if !self.warnings.is_empty() {
            out.push_str("\n  WARNINGS (Operational observations):\n");
            for w in &self.warnings {
                out.push_str(&format!("    [*] {}\n", w));
            }
        }

        out.push_str(
            "\n================================================================================\n",
        );
        out
    }
}
