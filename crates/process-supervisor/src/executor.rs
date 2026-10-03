//! Execution engine and process supervisor lifecycle management.

use chrono::Utc;
use std::io::Read;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::error::SupervisorError;
use crate::models::{
    ExecutionConstraints, ExecutionRequest, ExecutionResult, ProcessEvent, ProcessExitStatus,
    ResourceUsage, SandboxHandle, TerminationReason,
};
use crate::platform::PlatformProcessTree;

/// Active handle to a supervised process tree.
pub struct ExecutionHandle {
    child: Option<std::process::Child>,
    tree: Arc<PlatformProcessTree>,
    constraints: ExecutionConstraints,
    start_time: Instant,
    stdout_thread: Option<thread::JoinHandle<(Vec<u8>, bool, usize)>>,
    stderr_thread: Option<thread::JoinHandle<(Vec<u8>, bool, usize)>>,
    events: Arc<Mutex<Vec<ProcessEvent>>>,
    cancelled: Arc<AtomicBool>,
    pid: u32,
}

impl ExecutionHandle {
    /// Returns the OS process ID of the root child.
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Emits a cancellation request and immediately terminates the entire process tree.
    pub fn cancel(&self) -> Result<(), SupervisorError> {
        self.cancelled.store(true, Ordering::SeqCst);
        if let Ok(mut evs) = self.events.lock() {
            evs.push(ProcessEvent::Cancelled {
                reason: "Caller initiated cancellation".to_string(),
                timestamp: Utc::now(),
            });
        }
        self.tree.terminate()
    }

    /// Returns a snapshot of all structured events recorded so far.
    pub fn poll_events(&self) -> Vec<ProcessEvent> {
        self.events.lock().map(|e| e.clone()).unwrap_or_default()
    }

    /// Awaits process completion, enforcing timeout and governance limits.
    pub fn wait(mut self) -> Result<ExecutionResult, SupervisorError> {
        let mut child = self
            .child
            .take()
            .ok_or(SupervisorError::AlreadyTerminated)?;
        let mut termination_reason: Option<TerminationReason> = None;

        // Monitoring loop polling every 20ms
        loop {
            // Check caller cancellation
            if self.cancelled.load(Ordering::SeqCst) {
                termination_reason = Some(TerminationReason::Cancelled);
                let _ = self.tree.terminate();
                let _ = child.kill();
                break;
            }

            // Check wall-clock timeout
            let elapsed_ms = self.start_time.elapsed().as_millis() as u64;
            if elapsed_ms >= self.constraints.timeout_ms {
                termination_reason = Some(TerminationReason::Timeout);
                if let Ok(mut evs) = self.events.lock() {
                    evs.push(ProcessEvent::ResourceLimitExceeded {
                        resource: "wall_clock_timeout".to_string(),
                        details: format!(
                            "Execution exceeded timeout of {}ms",
                            self.constraints.timeout_ms
                        ),
                    });
                }
                let _ = self.tree.terminate();
                let _ = child.kill();
                break;
            }

            // Query resource metrics from platform process tree
            let usage = self.tree.query_usage();

            // Check active process count limit (fork bomb)
            if let Some(max_procs) = self.constraints.max_process_tree_size {
                if usage.active_processes > max_procs {
                    termination_reason = Some(TerminationReason::ProcessCountExceeded);
                    if let Ok(mut evs) = self.events.lock() {
                        evs.push(ProcessEvent::ResourceLimitExceeded {
                            resource: "process_tree_size".to_string(),
                            details: format!(
                                "Process tree active count {} exceeded limit of {}",
                                usage.active_processes, max_procs
                            ),
                        });
                    }
                    let _ = self.tree.terminate();
                    let _ = child.kill();
                    break;
                }
            }

            // Check memory limit
            if let Some(max_mem) = self.constraints.max_memory_bytes {
                if usage.peak_memory_bytes > max_mem {
                    termination_reason = Some(TerminationReason::MemoryLimitExceeded);
                    if let Ok(mut evs) = self.events.lock() {
                        evs.push(ProcessEvent::ResourceLimitExceeded {
                            resource: "memory".to_string(),
                            details: format!(
                                "Peak memory {} bytes exceeded limit of {} bytes",
                                usage.peak_memory_bytes, max_mem
                            ),
                        });
                    }
                    let _ = self.tree.terminate();
                    let _ = child.kill();
                    break;
                }
            }

            // Check CPU time limit
            if let Some(max_cpu) = self.constraints.max_cpu_time_ms {
                if usage.total_cpu_time_ms > max_cpu {
                    termination_reason = Some(TerminationReason::CpuLimitExceeded);
                    if let Ok(mut evs) = self.events.lock() {
                        evs.push(ProcessEvent::ResourceLimitExceeded {
                            resource: "cpu_time".to_string(),
                            details: format!(
                                "CPU time {}ms exceeded limit of {}ms",
                                usage.total_cpu_time_ms, max_cpu
                            ),
                        });
                    }
                    let _ = self.tree.terminate();
                    let _ = child.kill();
                    break;
                }
            }

            // Check if root process has exited
            match child.try_wait() {
                Ok(Some(_status)) => {
                    break;
                }
                Ok(None) => {
                    thread::sleep(Duration::from_millis(20));
                }
                Err(err) => {
                    return Err(SupervisorError::Io(err));
                }
            }
        }

        // Wait for root child process exit status
        let raw_exit = child.wait().ok();

        // Join stdout and stderr capture threads
        let (stdout, stdout_truncated, total_stdout) = self
            .stdout_thread
            .take()
            .and_then(|t| t.join().ok())
            .unwrap_or_default();

        let (stderr, stderr_truncated, total_stderr) = self
            .stderr_thread
            .take()
            .and_then(|t| t.join().ok())
            .unwrap_or_default();

        if stdout_truncated {
            if let Ok(mut evs) = self.events.lock() {
                evs.push(ProcessEvent::OutputTruncated {
                    stream: "stdout".to_string(),
                    total_bytes: total_stdout,
                    limit_bytes: self.constraints.max_output_bytes,
                });
            }
        }

        if stderr_truncated {
            if let Ok(mut evs) = self.events.lock() {
                evs.push(ProcessEvent::OutputTruncated {
                    stream: "stderr".to_string(),
                    total_bytes: total_stderr,
                    limit_bytes: self.constraints.max_output_bytes,
                });
            }
        }

        // Determine final exit status
        let exit_status = if let Some(reason) = termination_reason {
            ProcessExitStatus::KilledBySupervisor(reason)
        } else if let Some(exit) = raw_exit {
            #[cfg(unix)]
            {
                use std::os::unix::process::ExitStatusExt;
                if let Some(sig) = exit.signal() {
                    ProcessExitStatus::Signaled(sig)
                } else {
                    ProcessExitStatus::Exited(exit.code().unwrap_or(-1))
                }
            }
            #[cfg(not(unix))]
            {
                ProcessExitStatus::Exited(exit.code().unwrap_or(-1))
            }
        } else {
            ProcessExitStatus::KilledBySupervisor(TerminationReason::SupervisorShutdown)
        };

        let duration_ms = self.start_time.elapsed().as_millis() as u64;
        let final_usage = self.tree.query_usage();

        let resource_usage = ResourceUsage {
            peak_memory_bytes: final_usage.peak_memory_bytes,
            cpu_time_ms: final_usage.total_cpu_time_ms,
            wall_clock_ms: duration_ms,
            process_count: final_usage.active_processes,
        };

        if let Ok(mut evs) = self.events.lock() {
            evs.push(ProcessEvent::Terminated {
                status: exit_status.clone(),
                duration_ms,
            });
        }

        let events = self.events.lock().map(|e| e.clone()).unwrap_or_default();

        Ok(ExecutionResult {
            exit_status,
            stdout,
            stderr,
            stdout_truncated,
            stderr_truncated,
            resource_usage,
            events,
        })
    }
}

/// Sole authorized process supervisor implementation.
pub struct ProcessSupervisor;

impl ProcessSupervisor {
    /// Spawns a supervised process tree subject to strict resource constraints and containment.
    pub fn spawn(
        request: &ExecutionRequest,
        constraints: &ExecutionConstraints,
        _sandbox: &SandboxHandle,
    ) -> Result<ExecutionHandle, SupervisorError> {
        // Validate request
        if request.program.trim().is_empty() {
            return Err(SupervisorError::EmptyProgram);
        }
        if constraints.timeout_ms == 0 {
            return Err(SupervisorError::ZeroTimeout);
        }

        // Enforce process allowlist constraint if specified
        if !constraints.allowed_processes.is_empty() {
            let prog_name = std::path::Path::new(&request.program)
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| request.program.clone());

            let allowed = constraints.allowed_processes.iter().any(|allowed| {
                allowed == &request.program
                    || allowed == &prog_name
                    || allowed.ends_with(&prog_name)
                    || request.program.ends_with(allowed)
            });

            if !allowed {
                return Err(SupervisorError::DisallowedProcess(request.program.clone()));
            }
        }

        // Initialize platform process tree / Job Object
        let tree = Arc::new(PlatformProcessTree::new(constraints)?);

        // Build process command
        let mut cmd = std::process::Command::new(&request.program);
        cmd.args(&request.args);

        if let Some(ref cwd) = request.cwd {
            cmd.current_dir(cwd);
        }

        for (k, v) in &request.env {
            cmd.env(k, v);
        }

        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());

        if request.stdin.is_some() {
            cmd.stdin(std::process::Stdio::piped());
        } else {
            cmd.stdin(std::process::Stdio::null());
        }

        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            cmd.process_group(0);
        }

        // Sole authorized process spawn site in the codebase!
        let mut child = cmd.spawn()?;
        let pid = child.id();

        // Attach spawned process tree to the platform controller
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;
            tree.attach_process(child.as_raw_handle())?;
        }
        #[cfg(unix)]
        {
            tree.attach_pid(pid);
        }

        // Handle standard input
        if let Some(stdin_bytes) = request.stdin.clone() {
            if let Some(mut stdin) = child.stdin.take() {
                thread::spawn(move || {
                    use std::io::Write;
                    let _ = stdin.write_all(&stdin_bytes);
                });
            }
        }

        let events = Arc::new(Mutex::new(vec![ProcessEvent::Started {
            pid,
            timestamp: Utc::now(),
        }]));

        // Start bounded stdout reader thread
        let stdout_thread = child.stdout.take().map(|stdout| {
            spawn_bounded_reader(
                stdout,
                constraints.max_output_bytes,
                Arc::clone(&events),
                true,
            )
        });

        // Start bounded stderr reader thread
        let stderr_thread = child.stderr.take().map(|stderr| {
            spawn_bounded_reader(
                stderr,
                constraints.max_output_bytes,
                Arc::clone(&events),
                false,
            )
        });

        Ok(ExecutionHandle {
            child: Some(child),
            tree,
            constraints: constraints.clone(),
            start_time: Instant::now(),
            stdout_thread,
            stderr_thread,
            events,
            cancelled: Arc::new(AtomicBool::new(false)),
            pid,
        })
    }

    /// Spawns and synchronously executes a process to completion.
    pub fn execute(
        request: &ExecutionRequest,
        constraints: &ExecutionConstraints,
        sandbox: &SandboxHandle,
    ) -> Result<ExecutionResult, SupervisorError> {
        let handle = Self::spawn(request, constraints, sandbox)?;
        handle.wait()
    }
}

/// Spawns a background thread that continuously reads a pipe into a bounded buffer.
fn spawn_bounded_reader<R: Read + Send + 'static>(
    mut reader: R,
    max_bytes: usize,
    events: Arc<Mutex<Vec<ProcessEvent>>>,
    is_stdout: bool,
) -> thread::JoinHandle<(Vec<u8>, bool, usize)> {
    thread::spawn(move || {
        let mut buffer = Vec::new();
        let mut truncated = false;
        let mut total_bytes = 0;
        let mut chunk = [0u8; 8192];

        loop {
            match reader.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    total_bytes += n;
                    if buffer.len() < max_bytes {
                        let to_take = std::cmp::min(n, max_bytes - buffer.len());
                        buffer.extend_from_slice(&chunk[..to_take]);
                        if is_stdout {
                            if let Ok(mut evs) = events.lock() {
                                evs.push(ProcessEvent::StdoutChunk { bytes: to_take });
                            }
                        } else if let Ok(mut evs) = events.lock() {
                            evs.push(ProcessEvent::StderrChunk { bytes: to_take });
                        }
                    }
                    if total_bytes > max_bytes {
                        truncated = true;
                    }
                }
                Err(_) => break,
            }
        }
        (buffer, truncated, total_bytes)
    })
}
