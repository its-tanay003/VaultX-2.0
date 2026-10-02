//! Peer credential inspection and verification.

use crate::ipc::envelope::{IpcError, IpcErrorCode};

/// Identity details of a local process connecting over IPC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerIdentity {
    /// User ID of the process owner.
    pub uid: u32,
    /// Primary Group ID of the process owner.
    pub gid: u32,
    /// Process ID.
    pub pid: u32,
}

impl PeerIdentity {
    /// Creates a new peer identity record.
    pub fn new(uid: u32, gid: u32, pid: u32) -> Self {
        Self { uid, gid, pid }
    }

    /// Resolves the identity of the current daemon process.
    pub fn current() -> Self {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let uid = std::fs::metadata("/proc/self")
                .map(|m| m.uid())
                .unwrap_or(1000);
            let gid = std::fs::metadata("/proc/self")
                .map(|m| m.gid())
                .unwrap_or(1000);
            let pid = std::process::id();
            Self { uid, gid, pid }
        }
        #[cfg(not(unix))]
        {
            // On Windows / non-unix, simulate standard user profile context
            Self {
                uid: 1000,
                gid: 1000,
                pid: std::process::id(),
            }
        }
    }

    /// Verifies that the connecting peer UID matches the daemon process UID.
    ///
    /// Rejects unauthorized cross-user connections (e.g. from compromised daemons
    /// or other local users on a multi-user machine).
    pub fn verify_peer_credentials(&self, peer: &PeerIdentity) -> Result<(), IpcError> {
        if self.uid != peer.uid {
            return Err(IpcError::new(
                IpcErrorCode::PeerCredentialMismatch,
                format!(
                    "Peer UID {} does not match daemon UID {}. Connection rejected.",
                    peer.uid, self.uid
                ),
            ));
        }
        Ok(())
    }
}

#[cfg(unix)]
impl PeerIdentity {
    /// Extracts peer credentials from an active UnixStream.
    pub fn from_unix_stream(stream: &tokio::net::UnixStream) -> Result<Self, IpcError> {
        let cred = stream.peer_cred().map_err(|e| {
            IpcError::new(
                IpcErrorCode::PeerCredentialMismatch,
                format!("Failed to retrieve peer credentials: {}", e),
            )
        })?;

        let uid = cred.uid();
        let gid = cred.gid().unwrap_or(uid);
        let pid = cred.pid().unwrap_or(0) as u32;

        Ok(Self { uid, gid, pid })
    }
}
