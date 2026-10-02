# Contributing to VaultX 2.0

Thank you for contributing to VaultX 2.0 (`valutx`). We enforce rigorous security and architectural invariants to ensure safe agentic execution.

## Non-Negotiable Invariants

All contributors must adhere to the core invariants documented in [AGENTS.md](AGENTS.md):
- **Rust** for runtime and security crates; **strict TypeScript** for agent services and UI. No Python in the MVP.
- **ALL process execution** goes through `crates/process-supervisor`. Direct `std::process::Command` or `child_process.spawn` is prohibited.
- **Schema-first**: Types derive from `packages/schemas`. Never hand-edit generated code.
- **Structured errors**: Use stable error codes (`POLICY_DENIED`, `SCOPE_DENIED`, `SANDBOX_UNAVAILABLE`, `TOOL_NOT_FOUND`, `APPROVAL_REQUIRED`, `VERIFICATION_FAILED`, `RESOURCE_LIMIT`).

## Workflow for Every Task

1. **Implementation Plan & Risk Assessment**:
   - Restate the task, list assumptions, assess risks, and list files to create/modify.
   - For **RISKY tasks** (security boundaries, policy, sandboxing, process execution, secrets, network scopes, architectural shifts), present the implementation plan and ask: *"Do you want to proceed with this implementation plan?"* WAIT for approval.
   - For **LOW-RISK / NO-RISK tasks** (non-breaking documentation, formatting, safe additions), proceed directly without blocking.
2. **Write failing tests first** (deny paths first).
3. **Implement the minimum** that passes. Keep changes small and reviewable.
4. **Run format, lint, type checks, and tests**; show output.
5. **Update threat model, ADRs, and docs** if attack surface changes. Add audit events for privileged actions.
6. **Finish with**: what changed, what is NOT done, new risks, and verification steps.

## Verification Checklist

Before submitting code:
```bash
cargo fmt --check
cargo clippy -- -D warnings
cargo test
pnpm -r lint
pnpm -r build
gitleaks detect --source . --verbose --no-git
```
