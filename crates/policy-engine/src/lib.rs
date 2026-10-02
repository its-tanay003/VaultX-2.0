//! valutx-policy-engine
//!
//! Continuous capability and attribute-based authorization engine for VaultX 2.0.
//! Integrates AWS Cedar policy engine in Rust, a canonicalizing risk/scope pre-layer,
//! TOCTOU symlink protection, and pre-execution tamper-evident audit persistence.

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod canonical;
pub mod cedar_engine;
pub mod error;
pub mod executor_gate;
pub mod models;
pub mod risk;
pub mod scope;

pub use canonical::{canonicalize_parameters, canonicalize_target, compute_action_hash};
pub use cedar_engine::CedarPolicyEngine;
pub use error::PolicyError;
pub use executor_gate::{
    record_pre_execution_decision, validate_approval, verify_execution_integrity,
};
pub use models::{
    capabilities, ActionRequest, ApprovalToken, Decision, DecisionConstraints, DecisionEffect,
    RiskClass, Role, SecurityScope,
};
pub use risk::classify_risk;
pub use scope::validate_scope;

use chrono::Utc;
use valutx_audit::AuditLog;

/// Central policy engine orchestrating canonicalization, risk/scope evaluation, and Cedar.
pub struct PolicyEngine {
    cedar: CedarPolicyEngine,
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyEngine {
    /// Initializes PolicyEngine with the baseline Cedar policy set.
    pub fn new() -> Self {
        Self {
            cedar: CedarPolicyEngine::new(),
        }
    }

    /// Evaluates an ActionRequest through the full authorization pipeline:
    /// 1. Canonicalizes paths and arguments.
    /// 2. Classifies risk class (L0 to L5).
    /// 3. Validates SecurityScope if present.
    /// 4. Validates approval token if attached.
    /// 5. Evaluates Cedar policy.
    pub fn evaluate_action(&self, req: &ActionRequest) -> Result<Decision, PolicyError> {
        let now = Utc::now();
        let canonical_target = canonicalize_target(&req.target);
        let canonical_params = canonicalize_parameters(&req.parameters);
        let risk_class = classify_risk(&req.capability, &canonical_target, &req.parameters);

        let action_hash = compute_action_hash(
            &req.capability,
            &req.actor_id,
            &canonical_target,
            &canonical_params,
            risk_class.as_str(),
            req.scope.as_ref().map(|s| s.scope_id.as_str()),
        );

        let mut scope_valid = false;
        if let Some(ref sc) = req.scope {
            match validate_scope(sc, &canonical_target, now) {
                Ok(()) => {
                    scope_valid = true;
                }
                Err(e) => {
                    return Ok(Decision {
                        effect: DecisionEffect::Deny,
                        policy_id: "scope_denied".to_string(),
                        reasons: vec![e.to_string()],
                        constraints: DecisionConstraints::default(),
                        action_hash,
                        created_at: now.to_rfc3339(),
                    });
                }
            }
        }

        if let Some(ref approval) = req.approval {
            if let Err(e) = validate_approval(approval, &action_hash, now) {
                return Ok(Decision {
                    effect: DecisionEffect::RequireApproval,
                    policy_id: "approval_invalid".to_string(),
                    reasons: vec![e.to_string()],
                    constraints: DecisionConstraints::default(),
                    action_hash,
                    created_at: now.to_rfc3339(),
                });
            }
        }

        self.cedar.evaluate_request(
            req,
            &canonical_target,
            &action_hash,
            risk_class,
            scope_valid,
        )
    }

    /// Evaluates an action request and persists the decision in the tamper-evident audit log BEFORE execution.
    pub fn evaluate_and_record(
        &self,
        req: &ActionRequest,
        audit_log: &AuditLog,
    ) -> Result<Decision, PolicyError> {
        let decision = self.evaluate_action(req)?;
        record_pre_execution_decision(audit_log, req, &decision)?;
        Ok(decision)
    }

    /// Legacy evaluation entrypoint for backward compatibility with initial skeleton tests.
    pub fn evaluate(ctx: &EvaluationContext) -> PolicyDecision {
        if ctx.capability.is_empty() {
            return PolicyDecision::Deny;
        }

        if ctx.risk_class == "L4" || ctx.risk_class == "L5" {
            return PolicyDecision::ApprovalRequired;
        }

        let role = Role::from_str_loose(&ctx.role).unwrap_or(Role::Viewer);
        let engine = PolicyEngine::new();
        let req = ActionRequest {
            run_id: None,
            actor_id: "legacy_caller".to_string(),
            role,
            capability: ctx.capability.clone(),
            target: "workspace".to_string(),
            parameters: serde_json::json!({}),
            scope: None,
            environment: "sandbox".to_string(),
            trust_state: "trusted".to_string(),
            approval: None,
        };

        match engine.evaluate_action(&req) {
            Ok(decision) => match decision.effect {
                DecisionEffect::Allow => PolicyDecision::Allow,
                DecisionEffect::Deny => PolicyDecision::Deny,
                DecisionEffect::RequireApproval => PolicyDecision::ApprovalRequired,
            },
            Err(_) => PolicyDecision::Deny,
        }
    }
}

/// Legacy lightweight policy decision for backward compatibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyDecision {
    /// Action is explicitly authorized.
    Allow,
    /// Action is denied by policy.
    Deny,
    /// Action requires human approval before proceeding.
    ApprovalRequired,
}

/// Legacy evaluation context for backward compatibility.
#[derive(Debug, Clone)]
pub struct EvaluationContext {
    /// Active role (e.g. Developer, Security Analyst, Admin).
    pub role: String,
    /// Capability requested (e.g. project.read, terminal.execute).
    pub capability: String,
    /// Risk class (L0 to L5).
    pub risk_class: String,
}
