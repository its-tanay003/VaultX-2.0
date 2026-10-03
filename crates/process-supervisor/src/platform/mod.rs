//! Platform-specific process tree management and isolation.

#[cfg(windows)]
pub mod windows;
#[cfg(windows)]
pub use windows::PlatformProcessTree;

#[cfg(unix)]
pub mod unix;
#[cfg(unix)]
pub use unix::PlatformProcessTree;

/// Aggregated platform resource metrics.
#[derive(Debug, Clone, Default)]
pub struct PlatformUsage {
    /// Number of active processes currently running in the process tree.
    pub active_processes: u32,
    /// Peak memory consumed across the process tree in bytes.
    pub peak_memory_bytes: u64,
    /// Total CPU execution time consumed in milliseconds.
    pub total_cpu_time_ms: u64,
}
