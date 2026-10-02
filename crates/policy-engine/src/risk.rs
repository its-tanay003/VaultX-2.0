//! Risk classification logic adhering to Spec §9.

use crate::models::{capabilities, RiskClass};

/// Classifies an action request into a canonical risk class (L0 to L5).
///
/// Invariant: Unknown capabilities automatically fail-closed into L5 (highest risk).
pub fn classify_risk(capability: &str, target: &str, parameters: &serde_json::Value) -> RiskClass {
    match capability {
        capabilities::PROJECT_READ => RiskClass::L0,

        capabilities::PROJECT_WRITE => {
            // Check if attempting to write outside workspace or modify sensitive config
            if target.contains(".valutx") || target.contains(".git") || target.contains("id_rsa") {
                RiskClass::L3
            } else {
                RiskClass::L1
            }
        }

        capabilities::TERMINAL_EXECUTE => {
            // Check if destructive command flags are supplied
            let cmd = parameters
                .get("command")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if cmd.contains("rm -rf")
                || cmd.contains("mkfs")
                || cmd.contains("dd if=")
                || cmd.contains(":(){ :|:& };:")
            {
                RiskClass::L4
            } else {
                RiskClass::L2
            }
        }

        capabilities::NETWORK_EXTERNAL => RiskClass::L2,

        capabilities::CYBER_ACTIVE_SCAN => {
            // Active exploits or credential brute forcing escalate to L4
            let scan_type = parameters
                .get("scan_type")
                .and_then(|v| v.as_str())
                .unwrap_or("discovery");
            if scan_type == "exploit" || scan_type == "bruteforce" {
                RiskClass::L4
            } else {
                RiskClass::L3
            }
        }

        capabilities::SECRETS_USE => RiskClass::L3,

        capabilities::PLUGIN_INSTALL => RiskClass::L3,

        capabilities::POLICY_EDIT => RiskClass::L4,

        capabilities::AUDIT_EXPORT => RiskClass::L1,

        capabilities::BACKGROUND_AGENT => RiskClass::L2,

        // Fail closed: Any unrecognized, blank, or undefined capability is classified L5
        _ => RiskClass::L5,
    }
}
