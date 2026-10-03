# Implementation Plan - Task P1-T05: Sandbox Implementation Spike

## 1. Context & Objectives

- **Task**: P1-T05 — Time-boxed spike to choose the sandbox implementation for VaultX 2.0.
- **Relates to**: ADR-003 (*Multi-Platform OS Sandboxing Strategy and Cyber Lab Isolation*).
- **Core Invariant**: Fail closed. Unsandboxed execution is strictly forbidden. The chosen implementation must enforce read-only system files, project-dir read/write isolation, home & secret masking, scrubbed environment allowlists, and network denial by default.
- **Platform Under Test**: User real setup — **WSL2 Ubuntu 24.04 LTS (Noble Numbat)** and **WSL2 Kali Linux Rolling**, running kernel `6.18.40.1-microsoft-standard-WSL2`.

---

## 2. Candidate Options Evaluated

1. **Option (a)**: Wrap Anthropic's open-source `sandbox-runtime` (`srt`) from Rust.
2. **Option (b)**: Generate `bubblewrap` (`bwrap`) command lines directly from Rust.
3. **Option (c)**: In-process Landlock LSM + seccomp-bpf + Linux user/net namespaces via Rust FFI.

---

## 3. Evaluation Dimensions

- **Startup Latency**: Wall-clock overhead for `ls`, Python 3 one-liner, Node.js one-liner, and `npm --version`.
- **Default-Deny Reads Feasibility**: Can system paths outside the allowlist be hidden or rendered inaccessible?
- **Network Proxy Support**: Can network traffic be isolated, filtered, or routed to loopback proxies?
- **Maintenance Burden**: Upstream dependencies (Node, socat, external binaries) vs. self-contained syscalls.
- **License**: MIT / Apache-2.0 compatibility without GPL contamination.
- **Behavior Under WSL2**: Unprivileged user namespaces, AppArmor interaction on Ubuntu 24.04, and Landlock ABI detection without `/sys/kernel/security`.
- **Codex & Gemini CLI Architectural Study**: Review of industry isolation models.

---

## 4. Deliverables

1. [ADR-003-ADDENDUM-sandbox-spike-results.md](../architecture/adr/ADR-003-ADDENDUM-sandbox-spike-results.md): Comprehensive spike report with empirical benchmark table, failure/success evidence, and conformance test catalogue SAND-01..SAND-22 feeding P1-T07.
2. [ADR-003-os-sandboxing-and-cyber-lab.md](../architecture/adr/ADR-003-os-sandboxing-and-cyber-lab.md): Status updated Proposed → Accepted with addendum cross-reference.
3. [DECISIONS-LOG.md](../DECISIONS-LOG.md): Architectural decision recorded.
