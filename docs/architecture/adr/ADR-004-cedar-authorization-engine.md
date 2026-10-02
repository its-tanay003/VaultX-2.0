# ADR-004: Cedar Authorization Engine and Unified Rust Scope Layer

- **Status**: Proposed
- **Deciders**: Product Owner, Security & Architecture Team
- **Date**: 2026-10-02
- **Technical Story**: Task P0-T03 — Write and ratify ADR-002 to ADR-009.
- **Governs**: `crates/policy-engine`, `packages/schemas`, `security/policies`.

---

## Context and Problem Statement

VaultX 2.0 enforces continuous policy evaluation before and at execution time. Authorization decisions evaluate:
1. Subject Identity & Organization Role (e.g. Developer, Security Analyst, Admin).
2. Action / Capability (e.g. `project.write`, `terminal.execute`, `cyber.active_scan`).
3. Resource / Target (repository file, external IP, process command).
4. Context & Risk Class (L0 to L5, `SecurityScope` validity, approval token).

We need an authorization engine that is fast (<1ms evaluation), embeddable directly in Rust (no external daemon), mathematically verifiable, and easily auditable.

---

## Decision

We adopt **Cedar** (AWS open-source policy engine) embedded in `crates/policy-engine`, complemented by a **Unified Rust Scope & Risk Evaluation Layer**:

1. **Cedar Policy Engine**:
   - Written in Rust, compiles directly into `valutx-policy-engine`.
   - Formal verification: Cedar semantics are mathematically verified in the Lean theorem prover.
   - Declarative policies (`permit(...)` / `forbid(...)`) govern capabilities and role matrices.
   - Fast in-memory evaluation (<50 microseconds).
2. **Unified Extension Layer**:
   - Dynamic cybersecurity constraints (e.g. checking whether a destination IP belongs to an authorized CIDR block in `SecurityScope`, or validating action risk tiers `risk_class <= L2`) are implemented as native Cedar custom extension functions or pre-evaluation context builders in Rust.
3. **Fallback Policy**:
   - If Cedar cannot be compiled on a niche platform or encounters fatal schema validation issues, the policy engine fails closed (`POLICY_DENIED`). OPA/regorus remains an evaluation benchmark fallback, but is not used in production.

---

## Architectural Critique & Challenges

- **Challenge**: The user proposed a "hand-written Rust risk/scope layer" operating *outside* Cedar. Splitting authorization into two independent engines (Cedar for roles/capabilities, hand-written Rust for risk/scope) introduces the risk of "split-brain" authorization, where one layer approves an action that the other rejects, or where policy changes in one do not reflect in the other.
- **Resolution**: Unify the evaluation pipeline. The Rust context builder constructs a single, comprehensive `CedarContext` containing all evaluated attributes (including `risk_class`, `is_in_authorized_cidr`, `approval_valid`). Cedar evaluates the final decision in one authoritative pass.

---

## Alternatives Considered

- **Open Policy Agent (OPA) / Rego (via `regorus` crate)**: Considered. OPA is standard in Kubernetes, but Rego is an expressive Turing-complete-adjacent query language with slower evaluation times, higher memory footprint, and complex formal verification compared to Cedar.
- **Hand-Written Custom RBAC in Rust**: Rejected. Difficult to audit, lacks declarative policy syntax, error-prone when organizations require custom role overlays, and lacks formal verification.

---

## Consequences

### Positive
- Sub-millisecond policy evaluation latency directly inside the Rust runtime.
- Auditable, human-readable policy files stored in `security/policies/`.
- Mathematically proven guarantees against authorization bypasses.

### Negative
- Developers must learn Cedar policy syntax (`permit(principal, action, resource) when { ... };`).
- CIDR parsing and mathematical range checks require structured context preparation before policy invocation.

---

## Security Impact

Directly enforces **Invariant 2** (continuous policy evaluation before and at execution) and **Invariant 3** (fail closed). Ensures that neither the model nor an external agent can escalate privileges without an explicit, verifiable permit.

---

## Revisit Trigger

**Revisit when**:
1. Cedar policy evaluation latency exceeds 5ms under complex organizational policy sets.
2. Enterprise customer requirements mandate strict Rego/OPA compatibility for integration with existing corporate policy repositories.
