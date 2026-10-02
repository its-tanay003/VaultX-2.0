# ADR-001: Naming Conventions, Document Hierarchy, and Single Roadmap Baseline

- **Status**: Accepted
- **Deciders**: Product Owner, Security & Architecture Team
- **Date**: 2026-10-02
- **Technical Story**: Task P0-T01 — Reconcile the VaultX documents into one consistent baseline.
- **Governs**: All crates, packages, schemas, documentation, and operational processes.

---

## Context and Problem Statement

During the initial architectural scoping of VaultX 2.0, two primary sets of planning documentation were created in `docs/source/`:
1. The **16-Document Master Documentation Suite** (`01_Project_Brief_Scope.docx` through `16_Developer_API.docx`).
2. The **Engineering Master Specification v0.1** (`VALUTX_2_0_Engineering_Master_Specification.docx` and `valutx-engineering-manifest.json`).

Multiple critical conflicts, ambiguities, and naming differences existed between these documents:
1. **Naming**: The draft documents ubiquitously use `VALUTX 2.0`, whereas the project repository, marketing, and developer prompt designate `VaultX 2.0`.
2. **Document Hierarchy**: Various documents claim authority without a unified, unambiguous precedence order.
3. **Roadmap Discrepancy**: Document 06 specifies an 11-sprint roadmap (0–10) that places agent execution before policy and sandboxing, whereas the Engineering Master Specification (§40) and manifest define a 20-sprint security-first roadmap (0–19).

A binding, authoritative decision is required to eliminate ambiguity, establish an immutable document hierarchy, and lock down the roadmap and naming rules.

---

## Decision Drivers

- **Security Invariant 1**: The AI model is an untrusted decision component; the runtime is the authority.
- **Security Invariant 3**: Fail closed: Policy and sandboxing must exist and be verified before autonomous or untrusted execution is allowed.
- **Consistency**: Eliminating divergent vocabularies across Rust crates, TypeScript packages, and documentation.
- **Maintainability**: Establishing clear rules so future contributors and agents do not edit frozen source specifications directly.

---

## Considered Options

1. **Option 1**: Allow documents to co-exist without strict precedence; resolve conflicts ad-hoc per sprint.
2. **Option 2**: Re-write all source docx files to match one another.
3. **Option 3**: Keep source documents frozen in `docs/source/`, establish an authoritative document hierarchy with ADRs at the top, standardize code naming to `valutx`, and adopt the 20-sprint security-first roadmap detailed in `docs/architecture/CONSISTENCY.md`.

---

## Decision Outcome

Chosen option: **Option 3**.

### 1. Naming Standards
- **Code Identifiers & Crate / Package Names**: Strictly lowercase `valutx` (e.g., `crates/valutx-runtime`, `crates/valutx-policy`, `crates/valutx-sandbox`, `@valutx/protocol`, CLI executable `valutx`).
- **Product & Display Branding**: Designated as `VaultX 2.0` across UI, user-facing documentation, and repository metadata. `VALUTX 2.0` is recognized as the legacy moniker found in baseline source drafts.

### 2. Document Hierarchy & Precedence
When any conflict, ambiguity, or gap arises, the following order of precedence strictly governs:

1. **Architecture Decision Records** (`docs/architecture/adr/`)
2. **Security & Access Control (Doc 04) + Technical Architecture Document (Doc 03)**
3. **Product Requirements Document (Doc 02)**
4. **Release Runbook (Doc 07)**
5. **Engineering Master Specification v0.1** (`VALUTX_2_0_Engineering_Master_Specification.docx`)
6. **Remaining Suite Documents** (`01`, `05`, `06`, `08`–`16`)

**Rule**: All source documents in `docs/source/` are frozen and read-only. All resolutions and reconciliations must be recorded in `docs/architecture/CONSISTENCY.md` and subsequent ADRs. If a conflict cannot be resolved by this hierarchy, stop and escalate to the Product Owner.

### 3. Canonical Roadmap
The project strictly follows the **20-Sprint Engineering Roadmap (Sprint 0 to Sprint 19)** from Master Specification §40:
- Sprints 0–6 establish the core security runtime, workspace shell, supervised terminal, agent protocol, policy engine, sandboxing, and verification engine before any unconstrained agent execution.
- Sprints 7–11 establish offline intelligence, tool governance, isolated cyber lab boundaries, evidence generation, and the Agent Firewall.
- Sprints 12–19 establish plugins, subagents, CLI parity, cloud control plane, adversarial hardening, and production packaging.

---

## Consequences

### Positive
- **Deterministic Authority**: Developers and agents have an unambiguous decision tree when interpreting requirements.
- **Fail-Closed Sequence**: Security guardrails (policy engine, sandbox, process supervisor) are developed and verified before autonomous task execution.
- **Clean Namespace**: Consistent `valutx` naming across all package manifests, Rust crates, schemas, and CLI commands.

### Negative
- Developers must consult `docs/architecture/CONSISTENCY.md` alongside any legacy source documents to avoid implementing deprecated or conflicting draft proposals.

---

## Links

- Baseline Reconciliation: [CONSISTENCY.md](file:///c:/New%20Volume%20%28D%29/ValutX%202.0/docs/architecture/CONSISTENCY.md)
- Master Context Prompt: [AGENTS.md](file:///c:/New%20Volume%20%28D%29/ValutX%202.0/AGENTS.md)
- Engineering Manifest: [valutx-engineering-manifest.json](file:///c:/New%20Volume%20%28D%29/ValutX%202.0/docs/source/valutx-engineering-manifest.json)
