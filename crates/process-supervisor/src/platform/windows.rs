//! Windows Job Object implementation for process tree governance.

use std::ffi::c_void;
use std::mem::size_of;
use std::os::windows::io::RawHandle;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectBasicAccountingInformation,
    JobObjectExtendedLimitInformation, QueryInformationJobObject, SetInformationJobObject,
    TerminateJobObject, JOBOBJECT_BASIC_ACCOUNTING_INFORMATION,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
    JOB_OBJECT_LIMIT_JOB_MEMORY, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};

use super::PlatformUsage;
use crate::error::SupervisorError;
use crate::models::ExecutionConstraints;

/// Wrapper around a Windows Job Object handle providing automatic resource limits,
/// process tree containment, and atomic whole-tree termination.
pub struct PlatformProcessTree {
    handle: HANDLE,
}

// SAFETY: Windows Job Object HANDLE can be safely sent and shared across threads.
unsafe impl Send for PlatformProcessTree {}
unsafe impl Sync for PlatformProcessTree {}

impl PlatformProcessTree {
    /// Creates a new Job Object configured with the provided execution constraints.
    pub fn new(constraints: &ExecutionConstraints) -> Result<Self, SupervisorError> {
        // SAFETY: Calling Win32 CreateJobObjectW with null security attributes and name.
        let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return Err(SupervisorError::OsError(format!(
                "Failed to create Job Object: Windows error {}",
                std::io::Error::last_os_error()
            )));
        }

        let tree = Self { handle };
        tree.apply_limits(constraints)?;
        Ok(tree)
    }

    /// Configures Job Object limits including process tree bounds and memory limits.
    fn apply_limits(&self, constraints: &ExecutionConstraints) -> Result<(), SupervisorError> {
        // SAFETY: Zero-initializing JOBOBJECT_EXTENDED_LIMIT_INFORMATION.
        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };

        // Always ensure that closing the job or killing it terminates the whole process tree.
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

        // Enforce maximum active processes limit (fork bomb mitigation).
        if let Some(max_procs) = constraints.max_process_tree_size {
            info.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
            info.BasicLimitInformation.ActiveProcessLimit = max_procs;
        }

        // Enforce memory limit if specified.
        if let Some(max_mem) = constraints.max_memory_bytes {
            info.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_JOB_MEMORY;
            info.JobMemoryLimit = max_mem as usize;
        }

        // SAFETY: Passing valid struct pointer and size to SetInformationJobObject.
        let ok = unsafe {
            SetInformationJobObject(
                self.handle,
                JobObjectExtendedLimitInformation,
                &info as *const _ as *const c_void,
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };

        if ok == 0 {
            return Err(SupervisorError::OsError(format!(
                "Failed to set Job Object limits: {}",
                std::io::Error::last_os_error()
            )));
        }

        Ok(())
    }

    /// Assigns a running process to this Job Object.
    pub fn attach_process(&self, raw_process_handle: RawHandle) -> Result<(), SupervisorError> {
        // SAFETY: Assigning child process to job object using valid HANDLE.
        let ok = unsafe { AssignProcessToJobObject(self.handle, raw_process_handle as HANDLE) };
        if ok == 0 {
            return Err(SupervisorError::OsError(format!(
                "Failed to assign process to Job Object: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(())
    }

    /// Terminates every process in the Job Object immediately (children, grandchildren, orphans).
    pub fn terminate(&self) -> Result<(), SupervisorError> {
        // Exit code 1 represents supervisor termination.
        // SAFETY: Terminating all processes in job object.
        let ok = unsafe { TerminateJobObject(self.handle, 1) };
        if ok == 0 {
            // If already terminated or no processes remain, ignore harmless errors.
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(5) {
                // ERROR_ACCESS_DENIED or already dead
                return Err(SupervisorError::OsError(format!(
                    "Failed to terminate Job Object: {}",
                    err
                )));
            }
        }
        Ok(())
    }

    /// Queries current resource usage and active process metrics from the Job Object.
    pub fn query_usage(&self) -> PlatformUsage {
        let mut usage = PlatformUsage::default();

        // Query active processes and CPU time.
        let mut accounting: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: Querying basic accounting information with valid buffer and size.
        let ok_acc = unsafe {
            QueryInformationJobObject(
                self.handle,
                JobObjectBasicAccountingInformation,
                &mut accounting as *mut _ as *mut c_void,
                size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                std::ptr::null_mut(),
            )
        };

        if ok_acc != 0 {
            usage.active_processes = accounting.ActiveProcesses;
            // TotalUserTime and TotalKernelTime are in 100-nanosecond intervals (1 ms = 10,000 intervals).
            let total_100ns =
                (accounting.TotalUserTime as u64).saturating_add(accounting.TotalKernelTime as u64);
            usage.total_cpu_time_ms = total_100ns / 10_000;
        }

        // Query peak memory usage.
        let mut ext: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: Querying extended limit information with valid buffer and size.
        let ok_ext = unsafe {
            QueryInformationJobObject(
                self.handle,
                JobObjectExtendedLimitInformation,
                &mut ext as *mut _ as *mut c_void,
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                std::ptr::null_mut(),
            )
        };

        if ok_ext != 0 {
            usage.peak_memory_bytes = ext.PeakJobMemoryUsed as u64;
        }

        usage
    }
}

impl Drop for PlatformProcessTree {
    fn drop(&mut self) {
        if !self.handle.is_null() && self.handle != INVALID_HANDLE_VALUE {
            // SAFETY: Closing Job Object handle on drop.
            unsafe {
                CloseHandle(self.handle);
            }
        }
    }
}
