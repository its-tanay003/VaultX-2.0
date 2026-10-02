//! valutx-policy-engine
//!
//! Policy evaluator for privileged agent actions.
//! Evaluates actions against capabilities, roles, risk classes, and security scopes.

#![deny(unsafe_code)]
#![warn(missing_docs)]

/// Policy authorization decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyDecision {
    /// Action is explicitly authorized.
    Allow,
    /// Action is denied by policy.
    Deny,
    /// Action requires human approval before proceeding.
    ApprovalRequired,
}

/// Evaluation context carrying caller identity and target scope.
#[derive(Debug, Clone)]
pub struct EvaluationContext {
    /// Active role (e.g. Developer, Security Analyst, Admin).
    pub role: String,
    /// Capability requested (e.g. project.read, terminal.execute).
    pub capability: String,
    /// Risk class (L0 to L5).
    pub risk_class: String,
}

/// Evaluates action requests against security policies.
pub struct PolicyEngine;

impl PolicyEngine {
    /// Evaluate context and return authorization decision.
    /// Default behavior is fail-closed (Deny).
    pub fn evaluate(ctx: &EvaluationContext) -> PolicyDecision {
        if ctx.capability.is_empty() {
            return PolicyDecision::Deny;
        }

        // L0 read-only is generally allowed for authenticated roles
        if ctx.risk_class == "L0" && ctx.capability == "project.read" {
            return PolicyDecision::Allow;
        }

        // High risk L4/L5 actions require approval or are restricted
        if ctx.risk_class == "L4" || ctx.risk_class == "L5" {
            return PolicyDecision::ApprovalRequired;
        }

        // Fail-closed default
        PolicyDecision::Deny
    }
}
