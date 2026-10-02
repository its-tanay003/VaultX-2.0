# Implementation Plan - TASK P0-T07: CI Pipeline & Spec §27 Gates

**Date**: 2026-10-02  
**Task**: P0-T07  
**Risk Assessment**: **Low / Non-Destructive** (Adds CI workflow configuration, local/CI scripts, branch protection documentation, and verifies gate failures against isolated test cases).

---

## 1. Objectives & Scope

Implement the first slice of **Spec §27 CI Gates** in GitHub Actions adhering to all non-negotiable security invariants:

1. **Least-Privilege & Hardened Workflows**:
   - `permissions: { contents: read }` by default; no ambient write permissions.
   - All GitHub Actions pinned to full commit SHAs (with human-readable version comments).
   - Safe dependency caching (`actions/cache`, `swatinem/rust-cache`).
   - Zero secrets printed to logs.

2. **Active Gate Pipeline**:
   - **Lint, Format & Typecheck**: `pnpm -r lint`, `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`.
   - **Unit & Integration Tests**: `pnpm -r test` (schemas, protocol, test-fixtures), `cargo test --workspace`.
   - **Schema Freshness & Compatibility**: `pnpm run codegen:check` (verifies generated TS and Rust types are fresh), `pnpm run schema:check-breaking` (detects breaking JSON schema changes against baseline).
   - **Dependency Governance & Security**: `cargo deny check`, `cargo audit`, `pnpm audit --audit-level=high`.
   - **Threat Model Coverage**: `pnpm run threat:coverage` (fails if any implemented threat control lacks tests).
   - **Architecture Gate**: `cargo test --test no_external_process_spawning` (asserts no direct `std::process::Command` usage outside `process-supervisor`).
   - **Secret Detection**: Gitleaks scan (`gitleaks detect --verbose`).

3. **Disabled Future Gate Placeholders**:
   - `TODO: @tanay Phase 1` — Sandbox conformance (Bubblewrap / Landlock / WSL2 confinement & escape tests).
   - `TODO: @tanay Phase 1` — Adversarial attack fixtures (`security/attack-fixtures/` through live runtime).
   - `TODO: @tanay Phase 3` — Clean-install verification from packaged bundle.
   - `TODO: @tanay Phase 3` — Signed artifacts (Cosign / Sigstore provenance attestations).

4. **Documentation**:
   - `docs/operations/CI.md`: Complete specification of branch protection rules, required status checks, secret management, failure diagnosis, and offline validation.

5. **Failure Mode Verification ("DONE WHEN")**:
   - Deliberate lint error triggers CI failure with `ESLint/clippy` exit code.
   - Stale generated schema triggers CI failure with `codegen:check` exit code.
   - Fake leaked token triggers CI failure with `gitleaks` exit code.
   - Clean tree runs 100% green.

---

## 2. Step-by-Step Execution Plan

### Step 1: Create Hardened CI Workflow
- Create `.github/workflows/ci.yml` with:
  - Top-level `permissions: { contents: read }`.
  - SHA-pinned GitHub Actions:
    - `actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2`
    - `pnpm/action-setup@a3252b78c470c02df07e9d792dbd422789461f49 # v4.0.0`
    - `actions/setup-node@1e60f620b7ed1b0ad38b007393290720337e0073 # v4.0.2`
    - `dtolnay/rust-toolchain@7b7640457d930a38d3b36128028a422f7416744b # stable`
    - `swatinem/rust-cache@82a92a6e8fbeee08c6c4da52719b497042c93181 # v2.7.5`
    - `gitleaks/gitleaks-action@b706c64bc60285a8501ae7f4e9fa8211db492161 # v2.3.9`
  - Two parallel/interdependent jobs:
    - `quality-and-schemas`: Node/TS checks (lint, test, codegen:check, schema:check-breaking, threat:coverage, pnpm audit, gitleaks).
    - `rust-and-security`: Rust checks (fmt, clippy, cargo test, cargo deny, architecture test).
    - Future placeholders clearly annotated and disabled (`if: false`).

### Step 2: Document Branch Protection in `docs/operations/CI.md`
- Detail GitHub repository branch protection settings:
  - Required status checks: `quality-and-schemas`, `rust-and-security`.
  - Require branches to be up to date before merging.
  - Require linear commit history.
  - Require signed commits.
  - Enforce branch protections for administrators.

### Step 3: Verify All Steps Locally
- Run all commands locally to verify they exit cleanly on the current commit.
- Test failure simulations:
  - Simulate lint error -> verify detection.
  - Simulate stale schema -> verify detection.
  - Simulate leaked token -> verify Gitleaks detection.

### Step 4: Commit, Tag & Push
- Commit cleanly following conventional commits.
- Push upstream to `origin/main`.
