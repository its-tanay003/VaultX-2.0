# Security Policy

## Reporting Security Issues

VaultX 2.0 takes security vulnerabilities seriously. If you discover a vulnerability or security flaw in VaultX 2.0, please report it privately:

- **Email**: security@vaultx.dev (or contact repository owners privately)
- **PGP Key**: Available upon request
- **Response Window**: Initial response within 24 hours; status updates every 48 hours.

**Do NOT file public issues for suspected vulnerabilities, sandbox escapes, credential leaks, or policy bypasses.**

## Core Security Invariants

VaultX 2.0 enforces non-negotiable security guarantees:
1. The AI model is an untrusted decision component; the Rust runtime is the authority.
2. Every privileged action is evaluated by policy BEFORE execution and re-evaluated AT execution time.
3. Fail closed: If policy, sandboxing, or audit logging is unavailable, execution is refused.
4. Security operations require an explicit `SecurityScope` enforced at network and process layers.
5. Secrets are brokered by reference and masked everywhere.
6. Untrusted data (repositories, tools, MCP responses) are never treated as instructions.
7. Changes are checkpointed and reversible without agent repair.
8. Audit trails are created server-side, hash-chained, and tamper-evident.
