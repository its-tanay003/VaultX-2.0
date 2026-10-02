# VaultX 2.0

> **Agent-first desktop + CLI environment for secure software development and authorized cybersecurity work.**  
> A hardened Rust runtime enforces policy, sandboxing, scope, evidence, and rollback around an **UNTRUSTED** AI model.

---

## Overview

VaultX 2.0 (`valutx`) is built around a foundational architectural principle: **The AI model is an untrusted decision component; the runtime is the authority.**

In conventional agentic platforms, models often possess ambient authority to run arbitrary shell commands, access the network, or read developer secrets. VaultX 2.0 places an unbypassable, policy-enforced perimeter around all model actions. Every privileged action carries user, project, task, and capability context, policy-evaluated **before** execution and re-evaluated **at** execution time.

### Non-Negotiable Core Invariants

1. **Untrusted Model, Authoritative Runtime**: No model output may grant itself permission, expand scope, read a secret, escape a sandbox, or touch the host.
2. **Fail-Closed Execution**: If the policy engine, sandbox, or audit logger is unavailable, execution is refused immediately. No unsandboxed fallback. No "disable sandbox" escape hatch.
3. **Explicit Security Scope**: Security and testing operations require an explicit `SecurityScope` enforced at the network and process layers. Public-Internet offensive actions are strictly blocked.
4. **Brokered & Redacted Secrets**: Secrets are brokered by reference and automatically redacted across prompts, logs, traces, fixtures, and source files.
5. **Untrusted Data Isolation**: Repository files, tool outputs, MCP responses, plugin manifests, and memory are treated strictly as untrusted data—never as direct instructions or authority.
6. **Deterministic Evidence & Rollback**: Every completed task provides cryptographic evidence of what ran and was verified; changes are checkpointed and reversible without relying on the agent to repair itself.
7. **Append-Only Tamper-Evident Audit Log**: Audit records are generated server-side by the runtime, hash-chained, and signed with a key inaccessible to the agent.
8. **Guaranteed Local-Only Operation**: Local execution mode never silently falls back to external cloud endpoints.

---

## Architecture & Monorepo Layout

The repository is organized into a Cargo + pnpm monorepo conforming to strict language boundaries (Rust for runtime/security crates; strict TypeScript for agent services, tooling, and UI):

```text
├── apps/
│   ├── cli/                   # Developer CLI interface
│   └── desktop/               # Desktop application (Tauri 2 isolation pattern)
├── crates/                    # Hardened Rust runtime crates
│   ├── audit/                 # Append-only hash-chained audit logging
│   ├── policy-engine/         # Cedar-based policy evaluation & scope gates
│   ├── process-supervisor/    # ALL process execution (no direct std::process::Command)
│   ├── runtime-core/          # Core runtime state machine & protocol dispatch
│   ├── sandbox/               # OS sandbox adapters (Landlock/Bubblewrap/WSL2)
│   └── secret-broker/         # In-memory secret brokering and regex redaction
├── services/                  # Strict TypeScript agent services
│   ├── agent-orchestrator/    # Task planning and agent step management
│   ├── context-engine/        # Context budgeting and working memory
│   ├── evidence/              # Evidence bundle creation and verification
│   ├── model-router/          # Provider-neutral model adapter
│   ├── tool-registry/         # Tool passports and capability bounds
│   └── verification/          # Independent step and task verification
├── packages/                  # Shared protocol & schemas
│   ├── protocol/              # TypeScript protocol bindings & serde validation
│   ├── schemas/               # JSON Schema (Draft 2020-12) + dual codegen (Rust/TS)
│   └── test-fixtures/         # Canary test harness & isolated mock execution
├── security/                  # Security engineering & machine-readable threat models
│   ├── attack-fixtures/       # Inert malicious repository & prompt-injection catalog
│   ├── policies/              # Default security policies & rule definitions
│   ├── sandbox-profiles/      # OS isolation profiles & capability maps
│   └── threat-models/         # Machine-readable YAML threat model mapped to OWASP
└── docs/                      # Architecture Decision Records (ADRs) & specifications
```

---

## Machine-Readable Threat Model & Safety Catalog

- **Threat Model Matrix** (`security/threat-models/threat-model.yaml`):  
  Documents 15 assets, 9 trust boundaries, 9 actors, and 14 formal threats mapped to STRIDE, OWASP Top 10 for Agentic Applications 2026 (ASI01–ASI10), OWASP LLM Top 10, and MCP risks. Continuous CI validation ensures every implemented control has concrete automated tests.
- **Inert Attack Fixtures Catalog** (`security/attack-fixtures/catalog/`):  
  Curated suite of inert attack fixtures (malicious `postinstall`, `Makefile`, `.git/hooks`, symlink traversal, fake MCP configs, CI workflow traps, and a 5-channel prompt injection corpus) designed to run against our canary harness with zero real malware, zero external network access, and zero credential leakage.

---

## Getting Started

### Prerequisites

- **Node.js**: `v22.6+` (or `v22+` with pnpm)
- **pnpm**: `v9.0+` or `v10.0+`
- **Rust Toolchain**: `1.75+` (stable)
- **Gitleaks**: (Recommended for pre-commit secret scanning)

### Installation

Clone the repository and install dependencies:

```bash
git clone https://github.com/its-tanay003/VaultX-2.0.git
cd VaultX-2.0
pnpm install
```

### Verification & Testing

Run the full verification suite across all TypeScript packages and Rust crates:

```bash
# 1. Typecheck and build all packages
pnpm -r build

# 2. Run TypeScript linter
pnpm -r lint

# 3. Run all unit & integration tests (53 tests across schemas, protocol, and test-fixtures)
pnpm -r test

# 4. Run Rust runtime & security deny-path test suite (28 tests)
cargo test

# 5. Run machine-readable threat model coverage audit
pnpm run threat:coverage

# 6. Verify protocol schema consistency & backward compatibility
pnpm run codegen:check
pnpm run schema:check-breaking

# 7. Run manual hand-inspection and stub evaluation of attack fixtures
pnpm run attack:review
```

---

## Available Scripts

| Script | Command | Purpose |
| --- | --- | --- |
| `build` | `pnpm -r build` | Compiles all TypeScript packages and projects |
| `lint` | `pnpm -r lint` | Enforces ESLint across all workspaces |
| `test` | `pnpm -r test` | Runs all Vitest and Node native test suites |
| `threat:coverage` | `node scripts/threat-coverage.ts` | Fails CI if any threat control lacks a corresponding automated test |
| `attack:review` | `node security/attack-fixtures/review.ts` | Prints file-by-file contents, safety guarantees, and evaluates stub executors |
| `generate:ts` | `pnpm --filter @valutx/schemas run generate:ts` | Generates TypeScript protocol types from JSON Schemas |
| `codegen:check` | `pnpm --filter @valutx/schemas run codegen:check` | Verifies committed generated types match schema source |
| `schema:check-breaking` | `pnpm --filter @valutx/schemas run check-breaking` | Detects breaking changes against schema baseline |

---

## Security & Contributing

- **Reporting Security Issues**: Review [SECURITY.md](SECURITY.md) for our vulnerability disclosure policy.
- **Workflow & Rules**: Review [CONTRIBUTING.md](CONTRIBUTING.md) and [AGENTS.md](AGENTS.md) for our mandatory deny-path-first TDD workflow and definition of done.
- **Architectural Decisions**: Review [docs/architecture/adr/](docs/architecture/adr/) for ratified ADRs (ADR-001 through ADR-010).

---

## License

This project is licensed under Apache-2.0 / MIT dual licensing. See individual crate and package manifests for details.