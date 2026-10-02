# valutx-audit

**Trust Level**: High Authority (Compliance & Forensics)

## Purpose
Emits server-side, tamper-evident, cryptographically chained audit events for all privileged actions, policy decisions, and security events.

## Invariants & Restrictions (What it must NEVER do)
- **NEVER** permit an agent or model to write, alter, or delete audit records.
- **NEVER** use agent-controlled keys for audit signing.
- **NEVER** drop audit events even during high-load or recovery situations.
