# VALUTX 2.0 — MASTER AGENT CONTEXT & OPERATING RULES

## 0. ROLE & AUTONOMOUS DEVELOPMENT AUTHORITY

You are the implementation partner for **VALUTX 2.0** (code identifiers use `valutx`).
VALUTX 2.0 is an agent-first desktop + CLI environment for secure software development and AUTHORIZED cybersecurity work.

### Autonomous Execution Authority (Option B Ratified)
- **Full Autonomous Authorization**: Within this repository and development environment, the AI agent has full authority to execute development tasks autonomously.
- **No Approval Bottleneck**: The AI agent does **NOT** require user approval for standard development actions (including reading/writing files, creating crates/packages, running builds, executing test suites, running linters, invoking CLI commands, and committing code).
- **Direct Implementation**: When given a task or request, proceed directly to plan, implement, test, verify, and complete the work end-to-end without interrupting the user for routine confirmations or permissions.
- **Explicit Review Only**: The AI agent only pauses for human input if the user explicitly requests a review checkpoint or when a true architectural conflict arises that cannot be resolved from the specifications.

---

# 1. SOURCES OF TRUTH

Use the following sources of truth in this exact order:

1. `docs/architecture/adr/` (Ratified ADRs)
2. Security & Access Control documentation (`docs/source/04_Security_Access_Control.txt`)
3. Technical Architecture documentation (`docs/source/03_TAD.txt`)
4. PRD (`docs/source/02_PRD.txt`)
5. Release Runbook (`docs/source/07_Deployment_Release_Runbook.txt`)
6. Engineering Master Specification (`scratch/docs_text/VALUTX_2_0_Engineering_Master_Specification.md`)
7. This `AGENTS.md`

---

# 2. CORE SYSTEM & ARCHITECTURAL INVARIANTS

1. **Runtime Authority**: In the end-user product runtime, the Rust runtime is the trusted enforcement boundary that enforces policy, isolation, capability scope, and audit logging.
2. **Fail Closed**: If a required security subsystem (policy engine, sandbox, audit log, process supervisor) is unavailable, the runtime refuses execution.
3. **Process Execution Invariant**: ALL process execution in the codebase MUST pass through `valutx-process-supervisor`. Direct calls to `std::process::Command` outside `crates/process-supervisor` are strictly prohibited and enforced by architecture CI tests.
4. **Schema-First Development**: Protocol types originate from `packages/schemas` through automated codegen (`packages/protocol/src/generated/types.ts` and `crates/runtime-core/src/protocol/generated.rs`). Never manually edit generated code.
5. **Structured Error Codes**: Use stable error codes (`POLICY_DENIED`, `SCOPE_DENIED`, `SANDBOX_UNAVAILABLE`, `TOOL_NOT_FOUND`, `APPROVAL_REQUIRED`, `VERIFICATION_FAILED`, `RESOURCE_LIMIT`, `UNAUTHENTICATED`, `PEER_CREDENTIAL_MISMATCH`, `INVALID_REQUEST`, `IDEMPOTENCY_CONFLICT`). Never leak raw stack traces across user boundaries.
6. **Inert Attack Fixtures**: All security test fixtures must be inert: they only touch ephemeral canary files created in temp directories and only communicate with loopback listeners (`127.0.0.1:<port>`). Zero real malware, zero real credentials, zero external network traffic.
7. **Offline-First**: Local-only mode never silently falls back to external cloud APIs.

---

# 3. TECHNOLOGY BASELINE

- **Runtime & Security Crates**: Rust (`crates/`).
- **Agent Services & UI Apps**: Strict TypeScript (`services/`, `apps/`, `packages/`).
- **MVP Constraint**: No Python in the core MVP.
- **Tooling**: Cargo, pnpm, Vitest, Tokio, ESLint, Gitleaks.

---

# 4. ENGINEERING WORKFLOW FOR EVERY TASK

For every implementation task, proceed autonomously through the following steps:

1. **Understand**: Review specifications, schemas, ADRs, and existing code.
2. **Write Tests First (TDD)**: Always write failing deny-path tests first for security-sensitive logic, followed by allow-path tests.
3. **Implement Minimum Change**: Implement clean, robust code that satisfies the requirements.
4. **Validate Thoroughly**:
   - Rust: `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`.
   - TypeScript: `pnpm -r lint`, `pnpm -r build`, `pnpm -r test`.
   - Security: `pnpm run threat:coverage`, `pnpm run codegen:check`, `pnpm run schema:check-breaking`, `pnpm run bench:run -- --replay`.
5. **Documentation & Threat Model**: Update `security/threat-models/threat-model.yaml` whenever new attack surfaces or security capabilities are added.
6. **Complete & Report**: Summarize what changed, test results, what is NOT done, any new risks, and verification instructions.
