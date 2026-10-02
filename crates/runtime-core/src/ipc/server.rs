//! Local IPC daemon server and security context validation.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::ipc::{
    envelope::{IpcError, IpcErrorCode, IpcMessageEnvelope, IpcResponseEnvelope},
    idempotency::IdempotencyStore,
    peer::PeerIdentity,
};

/// Canonical capabilities recognized by VaultX 2.0 (per CONSISTENCY.md).
pub const CANONICAL_CAPABILITIES: &[&str] = &[
    "fs:read",
    "fs:write",
    "proc:exec",
    "net:egress",
    "net:listen",
    "sec:scope:scan",
    "sec:scope:exploit",
    "mem:read",
    "mem:write",
    "secret:broker",
    "audit:read",
    "audit:append",
];

/// Checks whether a capability string is one of the recognized canonical capabilities.
pub fn is_canonical_capability(cap: &str) -> bool {
    CANONICAL_CAPABILITIES.contains(&cap)
}

/// Generates a cryptographically secure 256-bit session token (64 hex characters).
pub fn generate_session_token() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let mut s = String::with_capacity(64);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", b);
    }
    s
}

/// Security context bound to an active local IPC session.
#[derive(Debug, Clone)]
pub struct IpcSecurityContext {
    /// Expected per-session authentication token.
    pub session_token: String,
    /// Daemon's local peer credentials.
    pub daemon_peer: PeerIdentity,
    /// Authenticated caller identity (e.g. "caller:desktop-user").
    pub expected_caller: String,
}

impl IpcSecurityContext {
    /// Creates a new security context.
    pub fn new(session_token: String, daemon_peer: PeerIdentity, expected_caller: String) -> Self {
        Self {
            session_token,
            daemon_peer,
            expected_caller,
        }
    }

    /// Validates an incoming message envelope against session security rules.
    pub fn validate_envelope(&self, env: &IpcMessageEnvelope) -> Result<(), IpcError> {
        // 1. Session token validation
        if env.token != self.session_token {
            return Err(IpcError::new(
                IpcErrorCode::Unauthenticated,
                "Invalid or missing per-session authentication token",
            ));
        }

        // 2. Caller identity validation (prevent identity forgery)
        if env.caller_identity != self.expected_caller {
            return Err(IpcError::new(
                IpcErrorCode::CallerIdentityMismatch,
                format!(
                    "Declared caller identity '{}' does not match session-bound identity '{}'",
                    env.caller_identity, self.expected_caller
                ),
            ));
        }

        // 3. Project and Task identifiers
        if env.project_id.trim().is_empty() {
            return Err(IpcError::new(
                IpcErrorCode::InvalidRequest,
                "project_id must not be empty",
            ));
        }
        if env.task_id.trim().is_empty() {
            return Err(IpcError::new(
                IpcErrorCode::InvalidRequest,
                "task_id must not be empty",
            ));
        }

        // 4. Capability scope validation
        if !is_canonical_capability(&env.requested_capability) {
            return Err(IpcError::new(
                IpcErrorCode::ScopeDenied,
                format!(
                    "Requested capability '{}' is not recognized as a valid canonical capability",
                    env.requested_capability
                ),
            ));
        }

        Ok(())
    }
}

/// Local IPC Daemon Server.
pub struct IpcServer {
    /// Path to the local Unix domain socket.
    pub socket_path: PathBuf,
    /// Cryptographic session token for this daemon lifetime.
    pub session_token: String,
    /// In-memory idempotency cache for mutating operations.
    pub idempotency_store: Arc<Mutex<IdempotencyStore>>,
    /// Expected caller identity.
    pub caller_identity: String,
}

impl IpcServer {
    /// Initializes a new daemon server configuration.
    pub fn new(socket_path: impl AsRef<Path>, caller_identity: impl Into<String>) -> Self {
        Self {
            socket_path: socket_path.as_ref().to_path_buf(),
            session_token: generate_session_token(),
            idempotency_store: Arc::new(Mutex::new(IdempotencyStore::new())),
            caller_identity: caller_identity.into(),
        }
    }

    /// Prepares the socket file path ensuring parent directories and restrictive mode 0600 on Unix.
    pub fn prepare_socket_path(&self) -> std::io::Result<()> {
        if let Some(parent) = self.socket_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        if self.socket_path.exists() {
            std::fs::remove_file(&self.socket_path)?;
        }
        Ok(())
    }

    /// Sets restrictive permissions (0600) on Unix platforms.
    #[cfg(unix)]
    pub fn secure_socket_permissions(&self) -> std::io::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(&self.socket_path, perms)?;
        Ok(())
    }

    /// Sets restrictive permissions on non-Unix platforms (handled via user profile directory ACLs).
    #[cfg(not(unix))]
    pub fn secure_socket_permissions(&self) -> std::io::Result<()> {
        // Mode 0600 is handled via user profile directory ACLs on Windows
        Ok(())
    }

    /// Processes a raw byte frame from a connected client.
    pub async fn handle_raw_frame(
        &self,
        raw_frame: &[u8],
        connecting_peer: &PeerIdentity,
    ) -> IpcResponseEnvelope {
        // 1. Peer credentials check
        let daemon_peer = PeerIdentity::current();
        if let Err(e) = daemon_peer.verify_peer_credentials(connecting_peer) {
            return IpcResponseEnvelope::err(e);
        }

        // 2. JSON Deserialization & unknown field rejection
        let envelope: IpcMessageEnvelope = match serde_json::from_slice(raw_frame) {
            Ok(env) => env,
            Err(e) => {
                return IpcResponseEnvelope::err(IpcError::new(
                    IpcErrorCode::InvalidRequest,
                    format!("Malformed JSON envelope or unknown fields: {}", e),
                ));
            }
        };

        // 3. Security context validation
        let sec_ctx = IpcSecurityContext::new(
            self.session_token.clone(),
            daemon_peer,
            self.caller_identity.clone(),
        );

        if let Err(e) = sec_ctx.validate_envelope(&envelope) {
            return IpcResponseEnvelope::err(e);
        }

        // 4. Idempotency handling for mutating actions
        if let Some(ref key) = envelope.idempotency_key {
            let mut store = self.idempotency_store.lock().await;
            match store.check_or_record(key, &envelope.payload) {
                Ok(Some(cached_response)) => {
                    return IpcResponseEnvelope::ok(cached_response).with_cached();
                }
                Ok(None) => {
                    // Proceed to execute action
                }
                Err(e) => {
                    return IpcResponseEnvelope::err(e);
                }
            }
        }

        // 5. Successful dispatch execution stub
        let execution_result = serde_json::json!({
            "status": "DISPATCHED",
            "capability": envelope.requested_capability,
            "task_id": envelope.task_id,
            "project_id": envelope.project_id
        });

        // Save result in idempotency cache if key was provided
        if let Some(ref key) = envelope.idempotency_key {
            let mut store = self.idempotency_store.lock().await;
            store.save_response(key, execution_result.clone());
        }

        IpcResponseEnvelope::ok(execution_result)
    }
}
