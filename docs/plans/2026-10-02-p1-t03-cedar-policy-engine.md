# TASK P1-T03 Implementation Plan: Policy Engine on Cedar with Rust Risk/Scope Layer

> **Goal:** Implement the VaultX 2.0 authorization engine using AWS Cedar policy engine embedded in Rust (`crates/policy-engine`), combined with a canonicalizing Rust risk/scope pre-layer, table-driven matrix verification, TOCTOU symlink protection, and pre-execution audit logging.

**Architecture:** 
The policy engine architecture follows a unified evaluation pipeline:
1. **Pre-Evaluation Layer**: Canonicalizes file paths, resolves symlinks, standardizes execution arguments, classifies action risk (L0–L5), checks security scope validity/expiration, and computes a cryptographic `action_hash`.
2. **Cedar Policy Evaluation**: Evaluates caller principal (`Role`/`User`), canonical capability (`Action`), resource, and runtime context against human-readable Cedar policies. Deny rules explicitly override allow rules.
3. **Audit & TOCTOU Gate**: Generates a structured `Decision` with execution constraints. Decisions are recorded in the append-only audit trail *before* execution. At execution time, the target is re-canonicalized and compared against `action_hash` to block Time-of-Check to Time-of-Use (TOCTOU) symlink swaps.

**Tech Stack:**
- `cedar-policy` v4.13 (Rust native embedded policy engine) with `datetime` and `ipaddr` features
- `valutx-audit` (for pre-execution decision logging)
- `sha2`, `hex`, `serde`, `serde_json`, `chrono`, `tempfile`

---

## Detailed Task Breakdown

### Task 1: Dependencies and Core Data Structures
**Files:**
- Modify: `crates/policy-engine/Cargo.toml`
- Create: `crates/policy-engine/src/models.rs`
- Create: `crates/policy-engine/src/error.rs`
- Modify: `crates/policy-engine/src/lib.rs`

- Add `cedar-policy = { version = "4.13", features = ["datetime", "ipaddr"] }`, `valutx-audit = { path = "../audit" }`, `sha2`, `hex`, `serde`, `serde_json`, `chrono`, `thiserror`.
- Define `Decision`, `DecisionEffect` (`Allow`, `Deny`, `RequireApproval`), `DecisionConstraints`, `RiskClass` (`L0` to `L5`), `Role` (`Viewer`, `Student`, `Developer`, `SecurityAnalyst`, `Admin`), `Capability` enum/constants, and `SecurityScope`.

### Task 2: Canonicalization, Risk Classification & Action Hash Pre-Layer
**Files:**
- Create: `crates/policy-engine/src/canonical.rs`
- Create: `crates/policy-engine/src/risk.rs`
- Create: `crates/policy-engine/src/scope.rs`

- Path and argument canonicalization:
  - Resolves symlinks using real filesystem checks (`canonicalize`).
  - Normalizes arguments into deterministic ordered sequences.
- Compute SHA-256 `action_hash`:
  - `hash(capability | actor | resolved_target | canonical_args | risk_class | scope_id)`
- Risk Classification:
  - Explicit rules for L0 to L5. Unknown capabilities automatically map to L5 (highest risk / fail closed).
- Scope validation:
  - Enforce expiration timestamps, CIDR membership, domain whitelisting, and `lab_only` restrictions.

### Task 3: Cedar Policy Schema & §8 Capability Matrix Policies
**Files:**
- Create: `security/policies/schema.cedarschema`
- Create: `security/policies/baseline.cedar`
- Create: `crates/policy-engine/src/cedar_engine.rs`

- Encode §8 matrix:
  - Viewer: `project.read` permitted; all mutating/executable capabilities forbidden.
  - Student: `project.read`, `project.write`, `terminal.execute` (in sandbox), `cyber.active_scan` (lab only).
  - Developer: `project.read`, `project.write`, `terminal.execute` (sandbox), `network.external` (policy/scoped), `cyber.active_scan` (lab/scoped), `secrets.use` (scoped), `plugin.install` (require approval).
  - Security Analyst: `project.read`, `project.write`, `terminal.execute` (sandbox), `network.external` (scoped), `cyber.active_scan` (scoped), `secrets.use` (scoped), `plugin.install` (require approval), `audit.export` (scoped).
  - Admin: All capabilities permitted; universal deny for quarantined or unauthenticated principals.
- Output `Decision` with `policy_id`, `reasons`, and execution `constraints`.

### Task 4: Pre-Execution Decision Audit Logging & TOCTOU Verifier
**Files:**
- Create: `crates/policy-engine/src/executor_gate.rs`

- `record_pre_execution_decision`:
  - Writes audit record to `crates/audit` before dispatching to supervisor.
- `verify_execution_integrity`:
  - Re-canonicalizes the target path/args immediately before process/tool execution.
  - Verifies current hash == stored `action_hash`.
  - Rejects execution if a symlink was swapped or args mutated (`TOCTOU_DETECTED`).
- Approval validation:
  - Checks approval token signature, `action_hash` match, and `expires_at > now`.

### Task 5: Comprehensive Test Suites
**Files:**
- Create: `crates/policy-engine/tests/matrix_tests.rs` (Table-driven 5 roles x 10 capabilities + unknown)
- Create: `crates/policy-engine/tests/forbid_override_tests.rs` (Property test: forbid always wins)
- Create: `crates/policy-engine/tests/toctou_tests.rs` (Symlink swap TOCTOU detection)
- Create: `crates/policy-engine/tests/approval_tests.rs` (Expired approval, hash mismatch)

### Task 6: Workspace CI, Formatting, Lints & Threat Model
- Run `cargo fmt --all -- --check`
- Run `cargo clippy --workspace --all-targets -- -D warnings`
- Run `cargo test --workspace`
- Run `pnpm -r test` and `pnpm run threat:coverage`
- Update `security/threat-models/threat-model.yaml` for policy engine and TOCTOU mitigations.
