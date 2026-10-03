# DECISIONS-LOG.md

This file records architectural conflicts, ambiguities, and choices made by the
implementation partner under the Autonomous Execution Authority defined in AGENTS.md.
Each entry identifies the conflict source, the chosen resolution, and the rationale.

---

## Entry 001 — 2026-10-03

**Task**: P1-T05 — Sandbox Implementation Spike

**Conflict / Ambiguity**:
ADR-003 §1 specified "Bubblewrap (`bwrap`) + Landlock LSM + seccomp-bpf" as the
primary Linux sandbox mechanism. After empirical testing on the production WSL2
environment (Kali Rolling 2025.4, kernel 6.18.40.1-microsoft-standard-WSL2), the
spike found:

1. `bwrap` is NOT pre-installed on the target distro (Kali 2025.4), requiring an
   explicit `apt install` step that introduces a binary dependency and setuid surface.
2. Landlock LSM is confirmed present via syscall (#444 returns EFAULT, not ENOSYS),
   but `/sys/kernel/security/landlock/abi` is absent in WSL2's stripped securityfs.
3. Startup latency with `bwrap` is ~12–18ms per sandbox; Landlock via direct syscall
   is ~0.1–0.8ms.

**Sources hierarchy consulted**:
- ADR-003 (ratified, Proposed) vs. empirical spike data (P1-T05).
- No conflict with higher-priority sources (ADR-003 is the governing ADR).

**Decision**:
- Revise ADR-003: demote `bwrap` from primary to **mount-namespace fallback**.
- Promote in-process **Landlock LSM + seccomp-bpf + user namespaces** (Rust FFI) as
  primary Linux/WSL2 sandbox mechanism.
- Startup latency target revised from < 15ms to **< 2ms**.
- ABI detection MUST use `LANDLOCK_CREATE_RULESET_VERSION` syscall flag (not sysfs).

**Evidence**: `docs/architecture/adr/ADR-003-ADDENDUM-sandbox-spike-results.md`

**ADR-003 updated**: Status Proposed → Accepted. Addendum linked inline.

**Follow-up Empirical Validation (2026-10-03 post-spike)**:
- `bwrap` v0.12.0 was installed in the WSL2 Kali environment and benchmarked directly:
  `bwrap true` startup: 7.70ms (min 6.83ms, max 9.62ms); `bwrap ls`: 6.90ms; `bwrap python`: 15.40ms.
- Landlock ABI probe via `LANDLOCK_CREATE_RULESET_VERSION` (flag `1u32`) was directly executed via syscall #444, returning ABI version `7` with `errno = 0` in `0.0008ms` (~0.8µs).
- Implemented and verified in `crates/sandbox` (`valutx-sandbox`): primary Landlock ABI probe with fail-closed fallback to `bwrap`, and SAND-01..22 conformance suite.

---

