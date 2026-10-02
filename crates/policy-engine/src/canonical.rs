//! Path, argument, and request canonicalization routines.

use sha2::{Digest, Sha256};
use std::path::{Component, Path, PathBuf};

/// Resolves paths, symlinks, and network targets into unambiguous canonical forms.
pub fn canonicalize_target(target: &str) -> String {
    let trimmed = target.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    let p = Path::new(trimmed);

    // If the path exists on disk, resolve physical symlinks and normalize to real path
    if let Ok(canonical) = std::fs::canonicalize(p) {
        return canonical.to_string_lossy().to_string();
    }

    // Lexical normalization for nonexistent paths or hypothetical targets
    let mut normalized = PathBuf::new();
    for component in p.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            c => normalized.push(c.as_os_str()),
        }
    }

    let result = normalized.to_string_lossy().to_string();
    if result.is_empty() {
        trimmed.to_string()
    } else {
        result
    }
}

/// Recursively sorts keys in JSON values to guarantee deterministic canonical serialization.
pub fn canonicalize_parameters(val: &serde_json::Value) -> String {
    fn canonicalize_value(v: &serde_json::Value) -> serde_json::Value {
        match v {
            serde_json::Value::Object(map) => {
                let mut sorted: std::collections::BTreeMap<String, serde_json::Value> =
                    std::collections::BTreeMap::new();
                for (k, val) in map {
                    sorted.insert(k.clone(), canonicalize_value(val));
                }
                serde_json::to_value(sorted).unwrap()
            }
            serde_json::Value::Array(arr) => {
                let items: Vec<serde_json::Value> = arr.iter().map(canonicalize_value).collect();
                serde_json::Value::Array(items)
            }
            other => other.clone(),
        }
    }

    let canonical = canonicalize_value(val);
    serde_json::to_string(&canonical).unwrap_or_else(|_| "{}".to_string())
}

/// Computes a canonical SHA-256 action hash across all parameters of an action request.
pub fn compute_action_hash(
    capability: &str,
    actor_id: &str,
    canonical_target: &str,
    canonical_params: &str,
    risk_class: &str,
    scope_id: Option<&str>,
) -> String {
    let payload = format!(
        "{}|{}|{}|{}|{}|{}",
        capability,
        actor_id,
        canonical_target,
        canonical_params,
        risk_class,
        scope_id.unwrap_or("")
    );

    let mut hasher = Sha256::new();
    hasher.update(payload.as_bytes());
    hex::encode(hasher.finalize())
}
