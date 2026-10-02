//! Cedar evaluation wrapper for VaultX 2.0 policy execution.

use std::str::FromStr;

use cedar_policy::{
    Authorizer, Context, Entities, Entity, EntityId, EntityTypeName, EntityUid, PolicySet,
    Request as CedarRequest,
};

use crate::error::PolicyError;
use crate::models::{
    capabilities, ActionRequest, Decision, DecisionConstraints, DecisionEffect, RiskClass, Role,
};

/// Embedded Cedar policy source code defining the baseline §8 capability matrix.
pub const BASELINE_CEDAR_POLICIES: &str = include_str!("../../../security/policies/baseline.cedar");

/// Cedar-based policy evaluation engine.
pub struct CedarPolicyEngine {
    policy_set: PolicySet,
    authorizer: Authorizer,
}

impl Default for CedarPolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl CedarPolicyEngine {
    /// Initializes policy engine with baseline policies.
    pub fn new() -> Self {
        let policy_set = PolicySet::from_str(BASELINE_CEDAR_POLICIES)
            .expect("Failed to parse static baseline Cedar policies");
        Self {
            policy_set,
            authorizer: Authorizer::new(),
        }
    }

    /// Initializes policy engine with custom Cedar policy text (for extension/forbid testing).
    pub fn from_policy_text(text: &str) -> Result<Self, PolicyError> {
        let policy_set =
            PolicySet::from_str(text).map_err(|e| PolicyError::CedarParse(e.to_string()))?;
        Ok(Self {
            policy_set,
            authorizer: Authorizer::new(),
        })
    }

    /// Evaluates an ActionRequest through Cedar and returns a structured Decision.
    pub fn evaluate_request(
        &self,
        req: &ActionRequest,
        canonical_target: &str,
        action_hash: &str,
        risk_class: RiskClass,
        scope_valid: bool,
    ) -> Result<Decision, PolicyError> {
        // Unknown capability check (Spec §8: Unknown capability => DENY)
        if !capabilities::ALL_CAPABILITIES.contains(&req.capability.as_str()) {
            return Ok(Decision {
                effect: DecisionEffect::Deny,
                policy_id: "fail_closed_unknown_capability".to_string(),
                reasons: vec![format!("Capability '{}' is not recognized", req.capability)],
                constraints: DecisionConstraints::default(),
                action_hash: action_hash.to_string(),
                created_at: chrono::Utc::now().to_rfc3339(),
            });
        }

        // Build Cedar entities and request
        let role_type = EntityTypeName::from_str("ValutX::Role")
            .map_err(|e| PolicyError::CedarParse(e.to_string()))?;
        let user_type = EntityTypeName::from_str("ValutX::User")
            .map_err(|e| PolicyError::CedarParse(e.to_string()))?;
        let action_type = EntityTypeName::from_str("ValutX::Action")
            .map_err(|e| PolicyError::CedarParse(e.to_string()))?;
        let resource_type = EntityTypeName::from_str("ValutX::Project")
            .map_err(|e| PolicyError::CedarParse(e.to_string()))?;

        let role_id = EntityId::from_str(req.role.as_str())
            .map_err(|e| PolicyError::CedarParse(e.to_string()))?;
        let user_id = EntityId::from_str(&req.actor_id)
            .map_err(|e| PolicyError::CedarParse(e.to_string()))?;
        let action_id = EntityId::from_str(&req.capability)
            .map_err(|e| PolicyError::CedarParse(e.to_string()))?;
        let resource_id =
            EntityId::from_str("workspace").map_err(|e| PolicyError::CedarParse(e.to_string()))?;

        let role_uid = EntityUid::from_type_name_and_id(role_type, role_id);
        let user_uid = EntityUid::from_type_name_and_id(user_type, user_id);
        let action_uid = EntityUid::from_type_name_and_id(action_type, action_id);
        let resource_uid = EntityUid::from_type_name_and_id(resource_type, resource_id);

        // User belongs to Role
        let role_entity = Entity::new(
            role_uid.clone(),
            std::collections::HashMap::new(),
            std::collections::HashSet::new(),
        )
        .map_err(|e| PolicyError::CedarParse(e.to_string()))?;
        let mut user_parents = std::collections::HashSet::new();
        user_parents.insert(role_uid);
        let user_entity = Entity::new(
            user_uid.clone(),
            std::collections::HashMap::new(),
            user_parents,
        )
        .map_err(|e| PolicyError::CedarParse(e.to_string()))?;
        let resource_entity = Entity::new(
            resource_uid.clone(),
            std::collections::HashMap::new(),
            std::collections::HashSet::new(),
        )
        .map_err(|e| PolicyError::CedarParse(e.to_string()))?;

        let entities =
            Entities::from_entities(vec![role_entity, user_entity, resource_entity], None)
                .map_err(|e| PolicyError::CedarParse(e.to_string()))?;

        let has_approval = req.approval.is_some();

        let context_json = serde_json::json!({
            "trust_state": req.trust_state,
            "environment": req.environment,
            "risk_class": risk_class.as_str(),
            "scope_valid": scope_valid,
            "approval_valid": has_approval,
        });

        let context = Context::from_json_value(context_json, None)
            .map_err(|e| PolicyError::CedarParse(e.to_string()))?;

        let request = CedarRequest::new(user_uid, action_uid, resource_uid, context, None)
            .map_err(|e| PolicyError::CedarParse(e.to_string()))?;

        let response = self
            .authorizer
            .is_authorized(&request, &self.policy_set, &entities);

        let reasons: Vec<String> = response
            .diagnostics()
            .reason()
            .map(|r| r.to_string())
            .collect();

        let policy_id = reasons
            .first()
            .cloned()
            .unwrap_or_else(|| "default_deny".to_string());

        // Determine DecisionEffect
        let effect = match response.decision() {
            cedar_policy::Decision::Allow => {
                // If the capability inherently requires approval (e.g. plugin.install or L4/L5 risk) and approval is missing:
                if (req.capability == capabilities::PLUGIN_INSTALL || risk_class >= RiskClass::L3)
                    && req.approval.is_none()
                {
                    // Student cyber.active_scan or terminal in lab/sandbox does not escalate if already governed
                    if req.role == Role::Admin && risk_class < RiskClass::L5 {
                        DecisionEffect::Allow
                    } else if req.capability == capabilities::PLUGIN_INSTALL
                        || risk_class >= RiskClass::L4
                    {
                        DecisionEffect::RequireApproval
                    } else {
                        DecisionEffect::Allow
                    }
                } else {
                    DecisionEffect::Allow
                }
            }
            cedar_policy::Decision::Deny => {
                // If denied purely because approval is missing (e.g. Developer or SecAnalyst installing plugin)
                if req.capability == capabilities::PLUGIN_INSTALL
                    && (req.role == Role::Developer || req.role == Role::SecurityAnalyst)
                    && req.approval.is_none()
                    && req.trust_state == "trusted"
                {
                    DecisionEffect::RequireApproval
                } else {
                    DecisionEffect::Deny
                }
            }
        };

        // Construct constraints
        let constraints = DecisionConstraints {
            max_runtime_seconds: Some(match risk_class {
                RiskClass::L0 | RiskClass::L1 => 30,
                RiskClass::L2 | RiskClass::L3 => 300,
                RiskClass::L4 | RiskClass::L5 => 600,
            }),
            allowed_paths: vec![canonical_target.to_string()],
            allowed_networks: req
                .scope
                .as_ref()
                .map(|s| s.allowed_cidrs.clone())
                .unwrap_or_default(),
            allowed_domains: req
                .scope
                .as_ref()
                .map(|s| s.allowed_domains.clone())
                .unwrap_or_default(),
            allowed_processes: Vec::new(),
            secret_refs: Vec::new(),
        };

        Ok(Decision {
            effect,
            policy_id,
            reasons,
            constraints,
            action_hash: action_hash.to_string(),
            created_at: chrono::Utc::now().to_rfc3339(),
        })
    }
}
