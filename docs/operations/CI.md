# CI Pipeline & Spec §27 Verification Gates

This document defines the continuous integration architecture, branch protection standards, and automated verification gates for VaultX 2.0 (`valutx`) per Spec §27.

---

## 1. Security Posture & Non-Negotiables

The VaultX CI pipeline enforces the same security invariants as the production runtime:

1. **Least-Privilege Execution**:
   - The workflow uses explicit, minimal GitHub token permissions:

     ```yaml
     permissions:
       contents: read
       pull-requests: read
     ```

   - No ambient write permissions are granted to CI jobs.
2. **Pinned Action Dependencies**:
   - All third-party GitHub Actions are pinned to immutable **40-character commit SHAs** rather than mutable tags or branch names, protecting against upstream supply chain attacks.
3. **Zero Secrets in Logs**:
   - Secrets are never emitted to stdout or stderr. Gitleaks continuously audits git history and pull request diffs to block any credential leakage before merge.
4. **Offline & Local Reproducibility**:
   - Every single check executed in CI can be run locally using standard developer tooling prior to pushing.

---

## 2. GitHub Branch Protection Policy

The `main` branch must be configured with GitHub branch protection rules matching the following settings:

| Protection Rule | Value | Justification |
| --- | --- | --- |
| **Require pull request before merging** | Enabled | Prevents direct pushes to production branch |
| **Required approving reviews** | 1 | Ensures human code review per ADR-001 |
| **Dismiss stale pull request approvals** | Enabled | Invalidates approvals when new commits are added |
| **Require status checks to pass** | Enabled | Enforces mandatory automated Spec §27 gates |
| **Required Status Checks** | `TypeScript, Schemas & Security Gates`, `Rust Runtime & Security Gates` | Both jobs must report success |
| **Require branches to be up to date** | Enabled | Validates merged state against latest `main` |
| **Require linear history** | Enabled | Enforces clean rebase/squash commits |
| **Do not allow bypassing the above settings** | Enabled (Include Administrators) | No administrator bypass per fail-closed principle |

---

## 3. Spec §27 Gate Inventory

The CI pipeline runs across two parallel jobs:

### Job A: `TypeScript, Schemas & Security Gates`

- **Gate 1 - Gitleaks Secret Scanning**: Scans repo diff for tokens, private keys, and credentials using `.gitleaks.toml`.
- **Gate 2 - Threat Model CI Coverage**: Executes `pnpm run threat:coverage` to ensure every threat control has concrete automated tests.
- **Gate 3 - Protocol Codegen Freshness**: Executes `pnpm run codegen:check` to ensure committed TypeScript and Rust types are synchronized with `packages/schemas/v1/`.
- **Gate 4 - Protocol Schema Breaking Change Compatibility**: Executes `pnpm run schema:check-breaking` to prevent accidental backward-incompatible schema changes.
- **Gate 5 - TypeScript Lint & Format**: Executes `pnpm -r lint` (ESLint 9 flat config across all apps, packages, and services).
- **Gate 6 - TypeScript Build & Typecheck**: Executes `pnpm -r build` (`tsc -b` composite project compilation).
- **Gate 7 - TypeScript Unit & Integration Tests**: Executes `pnpm -r test` (Vitest & Node native test runners).
- **Gate 8 - Attack Fixtures Catalog & Canary Evaluation**: Executes `pnpm run attack:review` verifying all 8 inert attack fixtures pass canary isolation.
- **Gate 9 - pnpm Dependency Vulnerability Audit**: Executes `pnpm audit --audit-level=high`.

### Job B: `Rust Runtime & Security Gates`

- **Gate 10 - Rust Formatting Check**: Executes `cargo fmt --all -- --check`.
- **Gate 11 - Clippy Lint**: Executes `cargo clippy --workspace --all-targets -- -D warnings`.
- **Gate 12 - Rust Unit & Security Tests**: Executes `cargo test --workspace` (tests both allow and deny security paths).
- **Gate 13 - Architecture Invariant**: Executes `cargo test --test no_external_process_spawning` to verify that no crate spawns processes outside `process-supervisor`.
- **Gate 14 - Cargo Deny Dependency Governance**: Executes `cargo-deny check` against `deny.toml` (licenses, bans, advisories, sources).
- **Gate 15 - Cargo Audit Advisory Check**: Audits Rust crates against the RustSec Advisory Database.

### Future Gate Placeholders (Disabled)

- `PLACEHOLDER: Sandbox Conformance (Bubblewrap/Landlock/WSL2)`: TODO: @tanay Phase 1.
- `PLACEHOLDER: Adversarial Attack Fixtures (Runtime Verification)`: TODO: @tanay Phase 1.
- `PLACEHOLDER: Clean-Install Verification (Package Bundle)`: TODO: @tanay Phase 3.
- `PLACEHOLDER: Signed Artifacts & Provenance Verification`: TODO: @tanay Phase 3.

---

## 4. Local Pre-Flight Verification

Before pushing a branch or opening a PR, developers must run:

```bash
# 1. Full pre-commit check (runs lint, threat coverage, schema check, and gitleaks)
pnpm run threat:coverage
pnpm run codegen:check
pnpm run schema:check-breaking
pnpm -r lint
pnpm -r test

# 2. Rust checks
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace

# 3. Audit checks
cargo-deny check
pnpm audit --audit-level=high
```

---

## 5. Failure Remediation Guide

| Failure Mode | Diagnosis | Remediation |
| --- | --- | --- |
| **Lint / Format Error** | ESLint or rustfmt exit code 1 | Run `pnpm -r lint --fix` or `cargo fmt --all`. |
| **Codegen Stale** | `TypeScript codegen is out of date` | Run `pnpm run generate:ts` and commit generated files in `packages/protocol/src/generated/` and `crates/runtime-core/src/protocol/generated.rs`. |
| **Breaking Schema Change** | Property removed or required added | Revert breaking change or follow ADR-010 versioning guidelines (`/v2/`). |
| **Threat Coverage Gap** | Threat marked implemented lacks test | Add test ID to `security/threat-models/threat-model.yaml` and implement test. |
| **Architecture Violation** | `Command::new` found outside `process-supervisor` | Route all process execution through `valutx-process-supervisor`. |
| **Gitleaks Leak Detected** | Secret regex match | Remove secret from commit history using `git reset` / git-filter-repo. NEVER push real credentials. |
