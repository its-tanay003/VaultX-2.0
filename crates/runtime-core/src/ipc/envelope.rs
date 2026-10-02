//! IPC message and response envelopes with strict schema validation.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Stable, machine-readable IPC error codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IpcErrorCode {
    /// Request lacked valid session token or authentication.
    Unauthenticated,
    /// Connecting peer UID/PID does not match the daemon process owner.
    PeerCredentialMismatch,
    /// Stated caller identity does not match the session-bound caller.
    CallerIdentityMismatch,
    /// Requested capability is unknown or not permitted for this project/task.
    ScopeDenied,
    /// Denied by security policy.
    PolicyDenied,
    /// Operation frame size exceeded the strict limit.
    ResourceLimit,
    /// Malformed JSON or unknown envelope properties.
    InvalidRequest,
    /// Idempotency key replayed with conflicting operation payload.
    IdempotencyConflict,
    /// Sandbox subsystem is unavailable or failed to initialize.
    SandboxUnavailable,
    /// Required capability tool is not registered.
    ToolNotFound,
    /// Execution paused pending human operator approval.
    ApprovalRequired,
    /// Post-execution task verification check failed.
    VerificationFailed,
}

impl IpcErrorCode {
    /// Returns the static string representation of the error code.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Unauthenticated => "UNAUTHENTICATED",
            Self::PeerCredentialMismatch => "PEER_CREDENTIAL_MISMATCH",
            Self::CallerIdentityMismatch => "CALLER_IDENTITY_MISMATCH",
            Self::ScopeDenied => "SCOPE_DENIED",
            Self::PolicyDenied => "POLICY_DENIED",
            Self::ResourceLimit => "RESOURCE_LIMIT",
            Self::InvalidRequest => "INVALID_REQUEST",
            Self::IdempotencyConflict => "IDEMPOTENCY_CONFLICT",
            Self::SandboxUnavailable => "SANDBOX_UNAVAILABLE",
            Self::ToolNotFound => "TOOL_NOT_FOUND",
            Self::ApprovalRequired => "APPROVAL_REQUIRED",
            Self::VerificationFailed => "VERIFICATION_FAILED",
        }
    }
}

/// Structured protocol error returned to IPC clients.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpcError {
    /// Stable error classification.
    pub code: IpcErrorCode,
    /// Human-readable explanation.
    pub message: String,
    /// Additional context or violation details.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<Value>,
}

impl IpcError {
    /// Creates a new IPC error.
    pub fn new(code: IpcErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            details: None,
        }
    }

    /// Appends structured details.
    pub fn with_details(mut self, details: Value) -> Self {
        self.details = Some(details);
        self
    }

    /// Helper returning error code as string slice.
    pub fn error_code(&self) -> &'static str {
        self.code.as_str()
    }
}

impl std::fmt::Display for IpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.code.as_str(), self.message)
    }
}

impl std::error::Error for IpcError {}

/// Inbound message envelope for all IPC commands.
///
/// Disallows unknown properties to prevent smuggling unvalidated fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IpcMessageEnvelope {
    /// Cryptographically secure per-session token.
    pub token: String,
    /// Authenticated caller identity (e.g. "caller:desktop-user").
    pub caller_identity: String,
    /// Target project identifier.
    pub project_id: String,
    /// Unique task execution identifier.
    pub task_id: String,
    /// Requested capability (e.g. "fs:read", "proc:exec").
    pub requested_capability: String,
    /// Runtime policy context metadata.
    pub policy_context: Value,
    /// Optional idempotency key for mutating actions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    /// Command-specific operation payload.
    pub payload: Value,
}

/// Outbound response envelope returned by the daemon.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpcResponseEnvelope {
    /// Whether the operation succeeded.
    pub success: bool,
    /// Result payload if successful.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
    /// Structured error if failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<IpcError>,
    /// Whether this response was served from the idempotency cache.
    #[serde(default)]
    pub idempotent_cached: bool,
}

impl IpcResponseEnvelope {
    /// Creates a successful response.
    pub fn ok(data: Value) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
            idempotent_cached: false,
        }
    }

    /// Creates an error response.
    pub fn err(error: IpcError) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(error),
            idempotent_cached: false,
        }
    }

    /// Marks the response as served from idempotency cache.
    pub fn with_cached(mut self) -> Self {
        self.idempotent_cached = true;
        self
    }
}
