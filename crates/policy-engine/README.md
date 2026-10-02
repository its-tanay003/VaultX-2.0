# valutx-policy-engine

**Trust Level**: High Authority (Security Boundary)

## Purpose
Continuous capability- and attribute-based policy evaluation engine for VaultX 2.0. Integrates the formally verified AWS Cedar authorization engine embedded directly in Rust, combined with a canonicalizing Rust pre-layer (path/argument canonicalization, risk classification L0–L5, SecurityScope validation, and TOCTOU protection) and pre-execution tamper-evident audit persistence.

## Architecture

```
ActionRequest
     │
     ▼
[Rust Pre-Layer]
  ├── Canonicalize Target Path (std::fs::canonicalize / lexical normalization)
  ├── Canonicalize Parameters (deterministic JSON key sorting)
  ├── Classify Risk Class L0-L5 (Spec §9; unknown => L5 fail-closed)
  ├── SecurityScope Validation (expiration, domain matching, CIDR IP math)
  ├── Approval Token Validation (expiry, signature, action_hash binding)
  └── Compute Cryptographic action_hash
     │
     ▼
[Cedar Policy Engine]
  ├── Evaluate Principal (User/Role) vs Action (Capability) vs Resource (Project)
  ├── Apply Universal Forbids (quarantined/untrusted state unconditionally denied)
  ├── Evaluate Spec §8 Baseline Matrix
  └── Emit Decision {effect ALLOW|DENY|REQUIRE_APPROVAL, constraints, action_hash}
     │
     ▼
[Pre-Execution Audit Log]
  └── Append Decision record to SQLite WAL audit trail BEFORE dispatching execution
     │
     ▼
[Execution-Time TOCTOU Verifier]
  └── Re-canonicalize target & args; abort execution if action_hash differs
```

## Cedar Expressiveness & Rust Pre-Layer Workarounds

While Cedar provides mathematical guarantees and sub-millisecond evaluation via formal verification, certain dynamic operating system and cybersecurity checks are handled by the Rust pre-layer:

1. **Filesystem Canonicalization & Symlink Resolution**:
   - *Limitation*: Cedar evaluates abstract string entity IDs and cannot directly inspect host filesystem inode links or perform physical path dereferencing.
   - *Workaround*: The Rust pre-layer canonicalizes target paths via `std::fs::canonicalize` and checks for directory traversal escapes before constructing Cedar entity attributes.
2. **CIDR & Subnet Range Matching**:
   - *Limitation*: Cedar's `ip()` extension supports IP comparisons, but dynamic enterprise security scopes can define arbitrary runtime CIDR lists (`SecurityScope.allowed_cidrs`).
   - *Workaround*: The Rust pre-layer validates target IPs against the active `SecurityScope` using standard network bitmask arithmetic, setting `context.scope_valid = true` only when authorized.
3. **Time-Boxed Scope Expiration**:
   - *Limitation*: Scope expiration requires comparison against current real-time clock timestamps.
   - *Workaround*: Evaluated pre-layer with `chrono::Utc::now()`. Expired scopes fail closed immediately.
4. **Fallback Strategy**:
   - If Cedar encounters schema corruption or parsing failures, it fails closed into `POLICY_DENIED`. Rego/OPA (via `regorus`) remains an evaluation benchmark fallback, but is not used in production.

## Invariants & Restrictions (What it must NEVER do)
- **NEVER** allow an action when policy is undefined, unavailable, or corrupted (MUST fail closed).
- **NEVER** permit an AI model or prompt instruction to edit, bypass, or override policy decisions.
- **NEVER** execute an action without first recording the decision in the tamper-evident audit log.
- **NEVER** proceed with execution if target paths or arguments mutated between check and use (TOCTOU protection).
