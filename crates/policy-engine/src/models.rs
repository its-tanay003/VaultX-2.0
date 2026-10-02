//! Domain models, capabilities, and decision structures for the policy engine.

use serde::{Deserialize, Serialize};

/// Canonical user and organizational roles defined in Spec §8.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Role {
    /// Read-only inspection role.
    Viewer,
    /// Educational / bounded student role.
    Student,
    /// Software engineering role with workspace execution capabilities.
    Developer,
    /// Authorized security auditor / penetration tester role.
    SecurityAnalyst,
    /// Administrative authority with policy editing access.
    Admin,
}

impl Role {
    /// Parses role from case-insensitive string identifier.
    pub fn from_str_loose(s: &str) -> Option<Self> {
        match s.to_lowercase().replace([' ', '_', '-'], "").as_str() {
            "viewer" => Some(Self::Viewer),
            "student" => Some(Self::Student),
            "developer" => Some(Self::Developer),
            "securityanalyst" | "secanalyst" | "analyst" => Some(Self::SecurityAnalyst),
            "admin" | "administrator" => Some(Self::Admin),
            _ => None,
        }
    }

    /// Returns canonical string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Viewer => "Viewer",
            Self::Student => "Student",
            Self::Developer => "Developer",
            Self::SecurityAnalyst => "SecurityAnalyst",
            Self::Admin => "Admin",
        }
    }
}

/// Canonical capabilities defined in Spec §8.
pub mod capabilities {
    /// Read files and inspect metadata within the project workspace.
    pub const PROJECT_READ: &str = "project.read";
    /// Write files, create branches, and modify code within the workspace.
    pub const PROJECT_WRITE: &str = "project.write";
    /// Execute process commands inside sandboxed execution workers.
    pub const TERMINAL_EXECUTE: &str = "terminal.execute";
    /// Egress network traffic to external endpoints.
    pub const NETWORK_EXTERNAL: &str = "network.external";
    /// Active cybersecurity scanning against targeted endpoints.
    pub const CYBER_ACTIVE_SCAN: &str = "cyber.active_scan";
    /// Access and inject governed credentials from the secret broker.
    pub const SECRETS_USE: &str = "secrets.use";
    /// Install community plugins or external tools.
    pub const PLUGIN_INSTALL: &str = "plugin.install";
    /// Modify organization or workspace security policies.
    pub const POLICY_EDIT: &str = "policy.edit";
    /// Export signed audit log records and forensic evidence.
    pub const AUDIT_EXPORT: &str = "audit.export";
    /// Launch background orchestrators or unattended subagents.
    pub const BACKGROUND_AGENT: &str = "background_agent";

    /// Complete list of canonical capabilities for baseline matrix validation.
    pub const ALL_CAPABILITIES: &[&str] = &[
        PROJECT_READ,
        PROJECT_WRITE,
        TERMINAL_EXECUTE,
        NETWORK_EXTERNAL,
        CYBER_ACTIVE_SCAN,
        SECRETS_USE,
        PLUGIN_INSTALL,
        POLICY_EDIT,
        AUDIT_EXPORT,
        BACKGROUND_AGENT,
    ];
}

/// Risk classes defined in Spec §9.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RiskClass {
    /// L0: Read-only / informational actions with zero side effects.
    L0,
    /// L1: Local, fully reversible file reads and minor writes.
    L1,
    /// L2: Active but bounded process execution (sandbox required).
    L2,
    /// L3: Credentialed, impactful, or state-mutating actions (explicit approval required).
    L3,
    /// L4: Exploitation, active network scans, or potentially destructive actions.
    L4,
    /// L5: Highly sensitive, irreversible, or policy modifications (restricted / deny by default).
    L5,
}

impl RiskClass {
    /// Returns canonical string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::L0 => "L0",
            Self::L1 => "L1",
            Self::L2 => "L2",
            Self::L3 => "L3",
            Self::L4 => "L4",
            Self::L5 => "L5",
        }
    }
}

/// Authorization decision effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DecisionEffect {
    /// Request is explicitly authorized to execute.
    Allow,
    /// Request is explicitly denied by policy.
    Deny,
    /// Request is gated pending cryptographic human approval.
    RequireApproval,
}

/// Execution constraints attached to an authorization decision.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct DecisionConstraints {
    /// Maximum execution duration permitted in seconds.
    pub max_runtime_seconds: Option<u64>,
    /// Allowed filesystem paths for read/write isolation.
    pub allowed_paths: Vec<String>,
    /// Allowed network target CIDRs or IP addresses.
    pub allowed_networks: Vec<String>,
    /// Allowed network target domain names.
    pub allowed_domains: Vec<String>,
    /// Allowed binary executables.
    pub allowed_processes: Vec<String>,
    /// Permitted secret identifiers.
    pub secret_refs: Vec<String>,
}

/// Traceable authorization decision emitted by the policy engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision {
    /// Authorization effect (ALLOW, DENY, REQUIRE_APPROVAL).
    pub effect: DecisionEffect,
    /// Evaluated policy identifier or rule source.
    pub policy_id: String,
    /// Explanatory diagnostic reasons.
    pub reasons: Vec<String>,
    /// Execution constraints to be enforced by the sandbox/process-supervisor.
    pub constraints: DecisionConstraints,
    /// Cryptographic SHA-256 hash of the canonical request.
    pub action_hash: String,
    /// Decision creation timestamp in RFC 3339 format.
    pub created_at: String,
}

/// Security Scope Lock object defined in Spec §11.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityScope {
    /// Unique scope UUID.
    pub scope_id: String,
    /// Scope owner / authorizing officer identity.
    pub owner: String,
    /// Human-readable authorization context.
    pub authorization_note: String,
    /// Permitted destination domain names.
    pub allowed_domains: Vec<String>,
    /// Permitted destination CIDRs (e.g. "10.10.20.0/24").
    pub allowed_cidrs: Vec<String>,
    /// Permitted URLs.
    pub allowed_urls: Vec<String>,
    /// Restricts execution strictly to isolated lab networks.
    pub lab_only: bool,
    /// Expiration timestamp in RFC 3339 format.
    pub expires_at: String,
    /// Maximum concurrent operations.
    pub max_concurrency: usize,
}

/// Incoming action request submitted for authorization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionRequest {
    /// Correlation run ID if part of an agent workflow.
    pub run_id: Option<String>,
    /// Identity of the calling agent or user.
    pub actor_id: String,
    /// Active organization or workspace role.
    pub role: Role,
    /// Requested capability (canonical identifier).
    pub capability: String,
    /// Target descriptor (file path, IP address, process command).
    pub target: String,
    /// Raw parameter payload.
    pub parameters: serde_json::Value,
    /// Active security scope for cyber/network operations.
    pub scope: Option<SecurityScope>,
    /// Target execution environment ("local", "sandbox", "lab", "cloud").
    pub environment: String,
    /// Project trust state ("trusted", "untrusted", "quarantined").
    pub trust_state: String,
    /// Attached cryptographic approval token if approved.
    pub approval: Option<ApprovalToken>,
}

/// Signed human approval token bound to an action hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalToken {
    /// Approval identifier.
    pub approval_id: String,
    /// SHA-256 action hash this approval authorizes.
    pub action_hash: String,
    /// Approving operator identity.
    pub approved_by: String,
    /// Approval creation timestamp (RFC 3339).
    pub approved_at: String,
    /// Expiration timestamp (RFC 3339).
    pub expires_at: String,
}
