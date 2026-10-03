//! Unix process group implementation for process tree governance.

use super::PlatformUsage;
use crate::error::SupervisorError;
use crate::models::ExecutionConstraints;
use std::sync::atomic::{AtomicU32, Ordering};

/// Unix process group controller providing whole-tree signal dispatch and containment.
pub struct PlatformProcessTree {
    root_pid: AtomicU32,
}

impl PlatformProcessTree {
    /// Creates a new Unix process group tracker.
    pub fn new(_constraints: &ExecutionConstraints) -> Result<Self, SupervisorError> {
        Ok(Self {
            root_pid: AtomicU32::new(0),
        })
    }

    /// Records the root child process PID (which acts as PGID).
    pub fn attach_pid(&self, pid: u32) {
        self.root_pid.store(pid, Ordering::SeqCst);
    }

    /// Terminates every process in the process group using SIGKILL on negative PGID.
    pub fn terminate(&self) -> Result<(), SupervisorError> {
        let pid = self.root_pid.load(Ordering::SeqCst);
        if pid > 0 {
            // SAFETY: Sending SIGKILL to negative PGID kills all child and descendant processes.
            let res = unsafe { libc::kill(-(pid as i32), libc::SIGKILL) };
            if res != 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() != Some(libc::ESRCH) {
                    return Err(SupervisorError::OsError(format!(
                        "Failed to kill process group {}: {}",
                        pid, err
                    )));
                }
            }
        }
        Ok(())
    }

    /// Queries resource usage across processes in the group via sysinfo.
    pub fn query_usage(&self) -> PlatformUsage {
        let mut usage = PlatformUsage::default();
        let root_pid = self.root_pid.load(Ordering::SeqCst);
        if root_pid == 0 {
            return usage;
        }

        let mut sys = sysinfo::System::new();
        sys.refresh_processes(sysinfo::ProcessesToUpdate::All);

        let target_pid = sysinfo::Pid::from(root_pid as usize);
        let mut active_count = 0;
        let mut total_mem = 0;

        for (pid, proc_) in sys.processes() {
            if *pid == target_pid || proc_.parent() == Some(target_pid) {
                active_count += 1;
                total_mem += proc_.memory();
            }
        }

        usage.active_processes = active_count;
        usage.peak_memory_bytes = total_mem;
        usage
    }
}
