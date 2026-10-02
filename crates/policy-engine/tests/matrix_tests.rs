//! Table-driven matrix tests over the entire Role x Capability matrix (Spec §8).

use valutx_policy_engine::{
    capabilities, ActionRequest, ApprovalToken, DecisionEffect, PolicyEngine, Role, SecurityScope,
};

fn create_test_request(
    role: Role,
    capability: &str,
    environment: &str,
    scope: Option<SecurityScope>,
    approval: Option<ApprovalToken>,
) -> ActionRequest {
    ActionRequest {
        run_id: Some("test-matrix-run".to_string()),
        actor_id: "matrix_tester".to_string(),
        role,
        capability: capability.to_string(),
        target: "workspace".to_string(),
        parameters: serde_json::json!({}),
        scope,
        environment: environment.to_string(),
        trust_state: "trusted".to_string(),
        approval,
    }
}

fn create_valid_scope() -> SecurityScope {
    SecurityScope {
        scope_id: "scope-matrix-01".to_string(),
        owner: "matrix_owner".to_string(),
        authorization_note: "Matrix authorization".to_string(),
        allowed_domains: vec!["authorized.internal".to_string()],
        allowed_cidrs: vec!["10.10.0.0/16".to_string()],
        allowed_urls: vec![],
        lab_only: false,
        expires_at: "2099-01-01T00:00:00Z".to_string(),
        max_concurrency: 5,
    }
}

#[test]
fn test_entire_role_capability_matrix_table_driven() {
    let engine = PolicyEngine::new();

    struct MatrixTestCase {
        role: Role,
        capability: &'static str,
        environment: &'static str,
        has_scope: bool,
        has_approval: bool,
        expected: DecisionEffect,
    }

    let cases = vec![
        // === 1. Viewer Role (10 capabilities) ===
        MatrixTestCase {
            role: Role::Viewer,
            capability: capabilities::PROJECT_READ,
            environment: "local",
            has_scope: false,
            has_approval: false,
            expected: DecisionEffect::Allow,
        },
        MatrixTestCase {
            role: Role::Viewer,
            capability: capabilities::PROJECT_WRITE,
            environment: "local",
            has_scope: false,
            has_approval: false,
            expected: DecisionEffect::Deny,
        },
        MatrixTestCase {
            role: Role::Viewer,
            capability: capabilities::TERMINAL_EXECUTE,
            environment: "sandbox",
            has_scope: false,
            has_approval: false,
            expected: DecisionEffect::Deny,
        },
        MatrixTestCase {
            role: Role::Viewer,
            capability: capabilities::NETWORK_EXTERNAL,
            environment: "local",
            has_scope: false,
            has_approval: false,
            expected: DecisionEffect::Deny,
        },
        MatrixTestCase {
            role: Role::Viewer,
            capability: capabilities::CYBER_ACTIVE_SCAN,
            environment: "lab",
            has_scope: true,
            has_approval: false,
            expected: DecisionEffect::Deny,
        },
        MatrixTestCase {
            role: Role::Viewer,
            capability: capabilities::SECRETS_USE,
            environment: "local",
            has_scope: true,
            has_approval: false,
            expected: DecisionEffect::Deny,
        },
        MatrixTestCase {
            role: Role::Viewer,
            capability: capabilities::PLUGIN_INSTALL,
            environment: "local",
            has_scope: false,
            has_approval: true,
            expected: DecisionEffect::Deny,
        },
        MatrixTestCase {
            role: Role::Viewer,
            capability: capabilities::POLICY_EDIT,
            environment: "local",
            has_scope: false,
            has_approval: false,
            expected: DecisionEffect::Deny,
        },
        MatrixTestCase {
            role: Role::Viewer,
            capability: capabilities::AUDIT_EXPORT,
            environment: "local",
            has_scope: false,
            has_approval: false,
            expected: DecisionEffect::Deny,
        },
        MatrixTestCase {
            role: Role::Viewer,
            capability: capabilities::BACKGROUND_AGENT,
            environment: "local",
            has_scope: false,
            has_approval: false,
            expected: DecisionEffect::Deny,
        },
        // === 2. Student Role (10 capabilities) ===
        MatrixTestCase {
            role: Role::Student,
            capability: capabilities::PROJECT_READ,
            environment: "local",
            has_scope: false,
            has_approval: false,
            expected: DecisionEffect::Allow,
        },
        MatrixTestCase {
            role: Role::Student,
            capability: capabilities::PROJECT_WRITE,
            environment: "local",
            has_scope: false,
            has_approval: false,
            expected: DecisionEffect::Allow,
        },
        MatrixTestCase {
            role: Role::Student,
            capability: capabilities::TERMINAL_EXECUTE,
            environment: "sandbox",
            has_scope: false,
            has_approval: false,
            expected: DecisionEffect::Allow,
        },
        MatrixTestCase {
            role: Role::Student,
            capability: capabilities::TERMINAL_EXECUTE,
            environment: "local",
            has_scope: false,
            has_approval: false,
            expected: DecisionEffect::Deny,
        },
        MatrixTestCase {
            role: Role::Student,
            capability: capabilities::NETWORK_EXTERNAL,
            environment: "local",
            has_scope: false,
            has_approval: false,
            expected: DecisionEffect::Deny,
        },
        MatrixTestCase {
            role: Role::Student,
            capability: capabilities::CYBER_ACTIVE_SCAN,
            environment: "lab",
            has_scope: true,
            has_approval: false,
            expected: DecisionEffect::Allow,
        },
        MatrixTestCase {
            role: Role::Student,
            capability: capabilities::CYBER_ACTIVE_SCAN,
            environment: "local",
            has_scope: false,
            has_approval: false,
            expected: DecisionEffect::Deny,
        },
        MatrixTestCase {
            role: Role::Student,
            capability: capabilities::SECRETS_USE,
            environment: "local",
            has_scope: true,
            has_approval: false,
            expected: DecisionEffect::Deny,
        },
        MatrixTestCase {
            role: Role::Student,
            capability: capabilities::PLUGIN_INSTALL,
            environment: "local",
            has_scope: false,
            has_approval: true,
            expected: DecisionEffect::Deny,
        },
        MatrixTestCase {
            role: Role::Student,
            capability: capabilities::POLICY_EDIT,
            environment: "local",
            has_scope: false,
            has_approval: false,
            expected: DecisionEffect::Deny,
        },
        MatrixTestCase {
            role: Role::Student,
            capability: capabilities::AUDIT_EXPORT,
            environment: "local",
            has_scope: false,
            has_approval: false,
            expected: DecisionEffect::Allow,
        },
        MatrixTestCase {
            role: Role::Student,
            capability: capabilities::BACKGROUND_AGENT,
            environment: "local",
            has_scope: false,
            has_approval: false,
            expected: DecisionEffect::Deny,
        },
        // === 3. Developer Role (10 capabilities) ===
        MatrixTestCase {
            role: Role::Developer,
            capability: capabilities::PROJECT_READ,
            environment: "local",
            has_scope: false,
            has_approval: false,
            expected: DecisionEffect::Allow,
        },
        MatrixTestCase {
            role: Role::Developer,
            capability: capabilities::PROJECT_WRITE,
            environment: "local",
            has_scope: false,
            has_approval: false,
            expected: DecisionEffect::Allow,
        },
        MatrixTestCase {
            role: Role::Developer,
            capability: capabilities::TERMINAL_EXECUTE,
            environment: "sandbox",
            has_scope: false,
            has_approval: false,
            expected: DecisionEffect::Allow,
        },
        MatrixTestCase {
            role: Role::Developer,
            capability: capabilities::TERMINAL_EXECUTE,
            environment: "local",
            has_scope: false,
            has_approval: false,
            expected: DecisionEffect::Deny,
        },
        MatrixTestCase {
            role: Role::Developer,
            capability: capabilities::NETWORK_EXTERNAL,
            environment: "sandbox",
            has_scope: false,
            has_approval: false,
            expected: DecisionEffect::Allow,
        },
        MatrixTestCase {
            role: Role::Developer,
            capability: capabilities::CYBER_ACTIVE_SCAN,
            environment: "lab",
            has_scope: true,
            has_approval: false,
            expected: DecisionEffect::Allow,
        },
        MatrixTestCase {
            role: Role::Developer,
            capability: capabilities::SECRETS_USE,
            environment: "local",
            has_scope: true,
            has_approval: false,
            expected: DecisionEffect::Allow,
        },
        MatrixTestCase {
            role: Role::Developer,
            capability: capabilities::SECRETS_USE,
            environment: "local",
            has_scope: false,
            has_approval: false,
            expected: DecisionEffect::Deny,
        },
        MatrixTestCase {
            role: Role::Developer,
            capability: capabilities::PLUGIN_INSTALL,
            environment: "local",
            has_scope: false,
            has_approval: false,
            expected: DecisionEffect::RequireApproval,
        },
        MatrixTestCase {
            role: Role::Developer,
            capability: capabilities::POLICY_EDIT,
            environment: "local",
            has_scope: false,
            has_approval: false,
            expected: DecisionEffect::Deny,
        },
        MatrixTestCase {
            role: Role::Developer,
            capability: capabilities::AUDIT_EXPORT,
            environment: "local",
            has_scope: false,
            has_approval: false,
            expected: DecisionEffect::Allow,
        },
        MatrixTestCase {
            role: Role::Developer,
            capability: capabilities::BACKGROUND_AGENT,
            environment: "local",
            has_scope: false,
            has_approval: false,
            expected: DecisionEffect::Allow,
        },
        // === 4. Security Analyst Role (10 capabilities) ===
        MatrixTestCase {
            role: Role::SecurityAnalyst,
            capability: capabilities::PROJECT_READ,
            environment: "local",
            has_scope: false,
            has_approval: false,
            expected: DecisionEffect::Allow,
        },
        MatrixTestCase {
            role: Role::SecurityAnalyst,
            capability: capabilities::PROJECT_WRITE,
            environment: "local",
            has_scope: false,
            has_approval: false,
            expected: DecisionEffect::Allow,
        },
        MatrixTestCase {
            role: Role::SecurityAnalyst,
            capability: capabilities::TERMINAL_EXECUTE,
            environment: "sandbox",
            has_scope: false,
            has_approval: false,
            expected: DecisionEffect::Allow,
        },
        MatrixTestCase {
            role: Role::SecurityAnalyst,
            capability: capabilities::NETWORK_EXTERNAL,
            environment: "local",
            has_scope: true,
            has_approval: false,
            expected: DecisionEffect::Allow,
        },
        MatrixTestCase {
            role: Role::SecurityAnalyst,
            capability: capabilities::NETWORK_EXTERNAL,
            environment: "local",
            has_scope: false,
            has_approval: false,
            expected: DecisionEffect::Deny,
        },
        MatrixTestCase {
            role: Role::SecurityAnalyst,
            capability: capabilities::CYBER_ACTIVE_SCAN,
            environment: "local",
            has_scope: true,
            has_approval: false,
            expected: DecisionEffect::Allow,
        },
        MatrixTestCase {
            role: Role::SecurityAnalyst,
            capability: capabilities::CYBER_ACTIVE_SCAN,
            environment: "local",
            has_scope: false,
            has_approval: false,
            expected: DecisionEffect::Deny,
        },
        MatrixTestCase {
            role: Role::SecurityAnalyst,
            capability: capabilities::SECRETS_USE,
            environment: "local",
            has_scope: true,
            has_approval: false,
            expected: DecisionEffect::Allow,
        },
        MatrixTestCase {
            role: Role::SecurityAnalyst,
            capability: capabilities::PLUGIN_INSTALL,
            environment: "local",
            has_scope: false,
            has_approval: false,
            expected: DecisionEffect::RequireApproval,
        },
        MatrixTestCase {
            role: Role::SecurityAnalyst,
            capability: capabilities::POLICY_EDIT,
            environment: "local",
            has_scope: false,
            has_approval: false,
            expected: DecisionEffect::Deny,
        },
        MatrixTestCase {
            role: Role::SecurityAnalyst,
            capability: capabilities::AUDIT_EXPORT,
            environment: "local",
            has_scope: true,
            has_approval: false,
            expected: DecisionEffect::Allow,
        },
        MatrixTestCase {
            role: Role::SecurityAnalyst,
            capability: capabilities::BACKGROUND_AGENT,
            environment: "local",
            has_scope: false,
            has_approval: false,
            expected: DecisionEffect::Allow,
        },
        // === 5. Admin Role (All capabilities permitted) ===
        MatrixTestCase {
            role: Role::Admin,
            capability: capabilities::PROJECT_READ,
            environment: "local",
            has_scope: false,
            has_approval: false,
            expected: DecisionEffect::Allow,
        },
        MatrixTestCase {
            role: Role::Admin,
            capability: capabilities::PROJECT_WRITE,
            environment: "local",
            has_scope: false,
            has_approval: false,
            expected: DecisionEffect::Allow,
        },
        MatrixTestCase {
            role: Role::Admin,
            capability: capabilities::TERMINAL_EXECUTE,
            environment: "local",
            has_scope: false,
            has_approval: false,
            expected: DecisionEffect::Allow,
        },
        MatrixTestCase {
            role: Role::Admin,
            capability: capabilities::NETWORK_EXTERNAL,
            environment: "local",
            has_scope: false,
            has_approval: false,
            expected: DecisionEffect::Allow,
        },
        MatrixTestCase {
            role: Role::Admin,
            capability: capabilities::CYBER_ACTIVE_SCAN,
            environment: "local",
            has_scope: false,
            has_approval: false,
            expected: DecisionEffect::Allow,
        },
        MatrixTestCase {
            role: Role::Admin,
            capability: capabilities::SECRETS_USE,
            environment: "local",
            has_scope: false,
            has_approval: false,
            expected: DecisionEffect::Allow,
        },
        MatrixTestCase {
            role: Role::Admin,
            capability: capabilities::PLUGIN_INSTALL,
            environment: "local",
            has_scope: false,
            has_approval: false,
            expected: DecisionEffect::Allow,
        },
        MatrixTestCase {
            role: Role::Admin,
            capability: capabilities::POLICY_EDIT,
            environment: "local",
            has_scope: false,
            has_approval: false,
            expected: DecisionEffect::Allow,
        },
        MatrixTestCase {
            role: Role::Admin,
            capability: capabilities::AUDIT_EXPORT,
            environment: "local",
            has_scope: false,
            has_approval: false,
            expected: DecisionEffect::Allow,
        },
        MatrixTestCase {
            role: Role::Admin,
            capability: capabilities::BACKGROUND_AGENT,
            environment: "local",
            has_scope: false,
            has_approval: false,
            expected: DecisionEffect::Allow,
        },
        // === 6. Unknown Capabilities (Fail-Closed Deny across all roles) ===
        MatrixTestCase {
            role: Role::Admin,
            capability: "arbitrary.exploit",
            environment: "local",
            has_scope: true,
            has_approval: true,
            expected: DecisionEffect::Deny,
        },
        MatrixTestCase {
            role: Role::Developer,
            capability: "unknown.tool",
            environment: "sandbox",
            has_scope: true,
            has_approval: true,
            expected: DecisionEffect::Deny,
        },
    ];

    for (idx, case) in cases.iter().enumerate() {
        let scope = if case.has_scope {
            Some(create_valid_scope())
        } else {
            None
        };
        let target = if case.has_scope {
            "10.10.20.1"
        } else {
            "workspace"
        };

        let mut req =
            create_test_request(case.role, case.capability, case.environment, scope, None);
        req.target = target.to_string();

        if case.has_approval {
            let risk =
                valutx_policy_engine::classify_risk(&req.capability, &req.target, &req.parameters);
            let action_hash = valutx_policy_engine::compute_action_hash(
                &req.capability,
                &req.actor_id,
                &req.target,
                &valutx_policy_engine::canonicalize_parameters(&req.parameters),
                risk.as_str(),
                req.scope.as_ref().map(|s| s.scope_id.as_str()),
            );
            req.approval = Some(ApprovalToken {
                approval_id: "appr-01".to_string(),
                action_hash,
                approved_by: "sec_officer".to_string(),
                approved_at: "2026-01-01T00:00:00Z".to_string(),
                expires_at: "2099-01-01T00:00:00Z".to_string(),
            });
        }

        let decision = engine.evaluate_action(&req).unwrap_or_else(|e| {
            panic!(
                "Case #{} ({:?}, {}) failed evaluation: {}",
                idx, case.role, case.capability, e
            )
        });

        assert_eq!(
            decision.effect, case.expected,
            "Case #{} failed: role={:?}, capability={}, env={}. Expected {:?}, got {:?}",
            idx, case.role, case.capability, case.environment, case.expected, decision.effect
        );
    }
}
