# ADR-006: Strict Rust and TypeScript Language Stack (Exclusion of Python in MVP)

- **Status**: Proposed
- **Deciders**: Product Owner, Security & Architecture Team
- **Date**: 2026-10-02
- **Technical Story**: Task P0-T03 — Write and ratify ADR-002 to ADR-009.
- **Governs**: All crates in `crates/`, all services in `services/`, all apps in `apps/`.

---

## Context and Problem Statement

Engineering Master Specification §3 suggested allowing Python for higher-level agent services alongside Rust and TypeScript. However, [AGENTS.md](file:///c:/New%20Volume%20%28D%29/ValutX%202.0/AGENTS.md) explicitly establishes: *"Rust for runtime/security crates; strict TypeScript for agent services and UI. No Python in the MVP."*

Including Python in core desktop applications introduces severe operational friction:
1. Requires bundling a 100MB+ Python interpreter runtime and virtual environments on Windows/macOS.
2. Inconsistent native compilation on Windows (MSVC vs MinGW wheel incompatibilities).
3. Large, unvetted PyPI dependency supply-chain attack surfaces.
4. Python cannot match Rust for fail-closed security boundary enforcement or deterministic memory management.

---

## Decision

We enforce a **Strict Dual-Language Stack**:

1. **Rust (System & Security Core)**:
   - Used for all security-critical crates: `runtime-core`, `policy-engine`, `sandbox`, `process-supervisor`, `secret-broker`, `audit`.
   - Compiles to native static binaries without garbage collection or external interpreter dependencies.
2. **Strict TypeScript (Coordination & Presentation)**:
   - Used for desktop UI (`apps/desktop`), developer CLI (`apps/cli`), orchestrator services (`services/*`), and shared protocols (`packages/*`).
   - Configured with maximum strictness: `strict: true`, `noImplicitAny: true`, `exactOptionalPropertyTypes: true`.
3. **Strict Exclusion of Python from Core**:
   - Python is strictly prohibited across all core repositories, services, packages, and binaries in the MVP.
   - **Target Exception**: Python scripts and tools (e.g., security scanners, PoC exploits, Scapy, Impacket) are permitted **only as untrusted guest payloads running inside the isolated Kali Linux container/VM** during security operations. They never touch host processes or the VaultX process tree.

---

## Architectural Critique & Challenges

- **Challenge**: The broader AI and data science ecosystem predominantly uses Python for local ML embeddings and RAG pipelines (e.g., PyTorch, HuggingFace transformers, LangChain).
- **Resolution**: For MVP local embeddings and local model execution, interface with standalone compiled binaries (e.g. `llama.cpp` server, `ollama`, or Rust-native ONNX runtime via `ort` crate). This provides 2x-5x faster inference speeds with zero Python dependency baggage.

---

## Alternatives Considered

- **Allowing Python for Agent Services**: Rejected. Drastically complicates desktop installer packaging (pyinstaller/briefcase instability), inflates binary size past 500MB, and makes sandboxing non-trivial.
- **Pure Rust for Everything (including UI)**: Considered (via Iced or Slint). Rejected because frontend web ecosystems (React, Monaco Editor, Tailwind, xterm.js) provide vastly superior developer productivity for complex IDE interfaces.

---

## Consequences

### Positive
- Compact, reliable installer distributions across Windows and Linux.
- Fast startup times and deterministic memory consumption.
- Eliminates Python dependency poisoning and virtual environment corruption bugs.

### Negative
- Developers contributing to agent services must write strict TypeScript rather than Python scripts.

---

## Security Impact

Directly reinforces **Invariant 1** and **Invariant 6**. Eliminates dynamic Python code injection (`eval()`, `exec()`, `pickle`) vulnerabilities from the host operating system.

---

## Revisit Trigger

**Revisit when**:
1. Post-MVP requirements demand running custom user-supplied Python data science agents locally on the host.
2. WebAssembly (Wasm) Python runtimes (e.g. Pyodide in Wasm sandbox) mature enough to run with zero host install footprint.
