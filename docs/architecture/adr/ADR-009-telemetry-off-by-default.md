# ADR-009: Strict Opt-In Telemetry Policy (Disabled by Default)

- **Status**: Proposed
- **Deciders**: Product Owner, Security & Architecture Team
- **Date**: 2026-10-02
- **Technical Story**: Task P0-T03 — Write and ratify ADR-002 to ADR-009.
- **Governs**: `apps/desktop`, `apps/cli`, telemetry reporting.

---

## Context and Problem Statement

VaultX 2.0 is designed for secure software development and authorized cybersecurity operations. Users routinely process:
- Proprietary source code and unreleased intellectual property.
- Hardcoded secrets, private API endpoints, and internal infrastructure maps.
- Security vulnerability reports, exploit payloads, and zero-day findings.

Standard consumer software telemetry (which silently transmits crash dumps, stack traces, and usage patterns to third-party analytics servers) poses an existential security and confidentiality risk for VaultX users.

---

## Decision

We enforce a **Strict Opt-In Telemetry Policy**:

1. **Disabled by Default**: Telemetry is 100% disabled out of the box (`telemetry.enabled = false`). No network requests for analytics, crash reporting, or ping telemetry are emitted upon installation or startup.
2. **Explicit Opt-In Required**: Telemetry can only be enabled by explicit, voluntary user opt-in during settings setup or via environment variable (`VALUTX_TELEMETRY=1`).
3. **Data Collection Boundaries (Never Collected)**:
   - **NEVER** collect source code snippets, ASTs, file paths, or file names.
   - **NEVER** collect model prompts, completions, system instructions, or tool arguments.
   - **NEVER** collect secrets, tokens, credentials, or environment variables.
   - **NEVER** collect target domains, IP addresses, CIDR blocks, or vulnerability findings.
4. **Allowed Opt-In Telemetry**:
   - High-level platform metrics: OS version, Rust runtime version, crash stack traces (sanitized through `valutx-secret-broker` to strip paths and credentials), and anonymized aggregate error codes (e.g. `POLICY_DENIED` counts).

---

## Architectural Critique & Challenges

- **Challenge**: Complete absence of crash telemetry makes diagnosing rare hardware-specific crashes on Windows or Linux difficult during alpha testing.
- **Resolution**: Provide a local "Export Diagnostic Bundle" command that dumps sanitized local logs and system info to a local zip file on disk. The user can inspect the zip file before choosing to attach it to a GitHub issue or email.

---

## Alternatives Considered

- **Opt-Out Telemetry (Enabled by default with toggle)**: Strongly rejected. Catastrophic for security compliance in defense, enterprise, or red-team environments.
- **Anonymous Crash Dumps via Sentry**: Rejected for unmanaged crash reporting. Raw memory or stack traces frequently contain memory-mapped credentials or source code buffers.

---

## Consequences

### Positive
- Total user privacy and zero risk of proprietary source code or vulnerability leakage.
- Immediate compliance with GDPR, HIPAA, and defense enterprise procurement standards.

### Negative
- Engineering team relies on proactive user bug reports rather than automated global telemetry funnels.

---

## Security Impact

Directly enforces **Invariant 5** (secrets redacted everywhere) and **Invariant 8** (no unexpected outbound connections). Ensures VaultX can be operated safely in air-gapped and high-security defense networks.

---

## Revisit Trigger

**Revisit when**:
1. Enterprise fleet management requirements request a self-hosted telemetry receiver specification for internal corporate observability.
