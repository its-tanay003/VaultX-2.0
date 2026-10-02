# valutx-policy-engine

**Trust Level**: High Authority (Security Boundary)

## Purpose
Evaluates every privileged action before execution and re-evaluates at runtime against user identity, active role, risk class, and explicit security scopes.

## Invariants & Restrictions (What it must NEVER do)
- **NEVER** allow an action when policy is undefined, unavailable, or corrupted (MUST fail closed).
- **NEVER** permit an AI model or prompt instruction to edit, bypass, or override policy decisions.
- **NEVER** fall back to permissive default allowances.
