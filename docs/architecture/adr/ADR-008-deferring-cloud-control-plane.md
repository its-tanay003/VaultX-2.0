# ADR-008: Deferral of Cloud Control Plane in Favor of Local-First MVP Architecture

- **Status**: Proposed
- **Deciders**: Product Owner, Security & Architecture Team
- **Date**: 2026-10-02
- **Technical Story**: Task P0-T03 — Write and ratify ADR-002 to ADR-009.
- **Governs**: `services/cloud-control-plane`, multi-tenant architecture.

---

## Context and Problem Statement

VaultX 2.0 documents discuss enterprise cloud features: centralized organization policy distribution, team audit log aggregation, shared cybersecurity scopes, and cloud-hosted background workers. 

However, building a multi-tenant cloud control plane in early sprints introduces massive architectural overhead: OAuth2/OIDC provider integrations, multi-tenant database isolation, remote secret synchronization, and cloud hosting infrastructure. The primary differentiator and highest technical risk for VaultX is **local host-level security, policy enforcement, sandboxing, and authorized cyber lab isolation**.

---

## Decision

We formally **defer the Cloud Control Plane until Sprint 16 (Phase 7)**:

1. **Local-First MVP Focus**: Sprints 0 through 15 focus entirely on the local runtime, desktop application, headless CLI, sandboxing, process supervisor, and Kali lab environment.
2. **Schema Preparation**: To avoid future refactoring debt, all database schemas and entity models in `packages/schemas` will include multi-tenant fields (`organization_id`, `project_id`, `owner_id`) from Day 1, defaulted to `local-org` and `local-user`.
3. **Local Storage Authority**: All policies, audit records, checkpoints, and tool passports are stored locally in embedded SQLite and Git.

---

## Architectural Critique & Challenges

- **Challenge**: If team collaboration features are deferred, how do multiple developers share policy rules and Tool Passports during alpha testing?
- **Resolution**: Policies and Tool Passports are stored as plain text/JSON files within the repository's `.vaultx/` or `security/` directory. Git serves as the distributed sync mechanism across developers without requiring a centralized cloud server.

---

## Alternatives Considered

- **Building Supabase / Cloud Sync in Sprint 1**: Rejected. Diverts engineering capacity away from the critical Rust security runtime and introduces cloud failure points early.
- **Omitting Multi-Tenant Fields from Schemas**: Rejected. Retrofitting multi-tenancy into database schemas later causes painful database migrations and breaking schema changes.

---

## Consequences

### Positive
- 100% of engineering bandwidth in Phases 0–3 focuses on runtime authority, policy enforcement, sandboxing, and verification.
- Guarantees true local-first execution (Invariant 8) from the start.

### Negative
- Enterprise multi-user synchronization, web dashboard, and centralized remote audit querying are unavailable until Sprint 16.

---

## Security Impact

Directly enforces **Invariant 8** (local-only mode never silently falls back to cloud) and drastically reduces the initial attack surface by eliminating remote cloud endpoints during alpha.

---

## Revisit Trigger

**Revisit when**:
1. Sprint 16 is reached per the 20-sprint engineering roadmap.
2. Enterprise pilot customer requirements mandate centralized SSO / audit aggregation before widespread workstation deployment.
