//! Security Scope Lock evaluation and validation routines (Spec §11).

use chrono::{DateTime, Utc};
use std::net::IpAddr;
use std::str::FromStr;

use crate::error::PolicyError;
use crate::models::SecurityScope;

/// Validates whether an action target complies with the active SecurityScope.
pub fn validate_scope(
    scope: &SecurityScope,
    target: &str,
    now: DateTime<Utc>,
) -> Result<(), PolicyError> {
    // 1. Expiration check
    if let Ok(exp) = DateTime::parse_from_rfc3339(&scope.expires_at) {
        if now >= exp.with_timezone(&Utc) {
            return Err(PolicyError::ScopeExpired {
                scope_id: scope.scope_id.clone(),
                expired_at: scope.expires_at.clone(),
            });
        }
    }

    let trimmed = target.trim();
    if trimmed.is_empty() {
        return Ok(());
    }

    // 2. Domain check
    if !scope.allowed_domains.is_empty() {
        let domain_matched = scope
            .allowed_domains
            .iter()
            .any(|d| trimmed.eq_ignore_ascii_case(d) || trimmed.ends_with(&format!(".{}", d)));
        if domain_matched {
            return Ok(());
        }
    }

    // 3. IP / CIDR check
    let target_ip = extract_ip(trimmed);
    if let Some(ip) = target_ip {
        if scope.lab_only && !is_private_or_loopback(&ip) {
            return Err(PolicyError::ScopeTargetDenied {
                target: target.to_string(),
                reason: "Scope is restricted to lab-only private/loopback networks".to_string(),
            });
        }

        if !scope.allowed_cidrs.is_empty() {
            let in_cidr = scope.allowed_cidrs.iter().any(|cidr| ip_in_cidr(&ip, cidr));
            if !in_cidr {
                return Err(PolicyError::ScopeTargetDenied {
                    target: target.to_string(),
                    reason: format!("Target IP {} is not within allowed CIDRs", ip),
                });
            }
            return Ok(());
        }
    }

    // If scope has defined specific domains or CIDRs but target matched neither:
    if !scope.allowed_domains.is_empty() || !scope.allowed_cidrs.is_empty() {
        return Err(PolicyError::ScopeTargetDenied {
            target: target.to_string(),
            reason: "Target not present in scope allowed domains or CIDRs".to_string(),
        });
    }

    Ok(())
}

fn extract_ip(target: &str) -> Option<IpAddr> {
    // Strip port if present (e.g. "10.10.20.5:8080")
    let host = if let Some(idx) = target.rfind(':') {
        if !target.contains("::") {
            // IPv4:port
            &target[..idx]
        } else {
            target
        }
    } else {
        target
    };

    IpAddr::from_str(host).ok()
}

fn is_private_or_loopback(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_private(),
        IpAddr::V6(v6) => v6.is_loopback(),
    }
}

fn ip_in_cidr(ip: &IpAddr, cidr: &str) -> bool {
    // Parse CIDR notation (e.g., "10.10.20.0/24")
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        if let Ok(exact_ip) = IpAddr::from_str(cidr) {
            return ip == &exact_ip;
        }
        return false;
    }

    let network_ip = match IpAddr::from_str(parts[0]) {
        Ok(IpAddr::V4(v4)) => v4,
        _ => return false,
    };

    let prefix_len = match parts[1].parse::<u32>() {
        Ok(len) if len <= 32 => len,
        _ => return false,
    };

    let target_v4 = match ip {
        IpAddr::V4(v4) => *v4,
        _ => return false,
    };

    let mask = if prefix_len == 0 {
        0u32
    } else {
        !((1u32 << (32 - prefix_len)) - 1)
    };

    (u32::from(network_ip) & mask) == (u32::from(target_v4) & mask)
}
