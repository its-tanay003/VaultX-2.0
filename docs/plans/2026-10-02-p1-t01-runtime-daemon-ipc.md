# Implementation Plan - TASK P1-T01: Runtime Daemon Skeleton with Authenticated Local IPC

**Date**: 2026-10-02  
**Task**: P1-T01  
**Category**: Core Runtime / Security Architecture  
**Status**: PROPOSED FOR HUMAN REVIEW (Per Master Context Prompt & Human Review Requirement)  
**Risk Assessment**: **Medium-High (Security Authority Boundary)**. Implements the foundational IPC communication channel between untrusted UI/CLI clients and the authoritative Rust runtime daemon. Enforces peer credential verification, per-session authentication tokens, schema-strict message envelopes, frame size limits, and system diagnostics (`valutx doctor`).

---

## 1. Context & Architectural Grounding

- **Source of Truth**:
  - **Engineering Master Spec §2.1**: UI ↔ Runtime trust boundary. UI is an untrusted client; runtime is the authority. Local IPC must be authenticated, strictly validated, and enforce runtime-side authorization.
  - **TAD §5**: Privileged operations exposed through narrow typed APIs. IPC requests contain caller identity, project identity, task identity, requested capability, and policy context. The runtime validates all fields independently.
  - **ADR-002 & ADR-003**: Tauri 2 isolation pattern + OS sandbox boundary (Linux bubblewrap+Landlock+seccomp, Windows via WSL2).
  - **ADR-006**: Rust for security runtime crates; strict TypeScript for agent services and UI.

---

## 2. Invariants & Safety Guarantees

1. **Runtime Authority**: The local IPC endpoint is the sole gateway to runtime capabilities. No client (UI, CLI, model) can bypass policy evaluation.
2. **Fail Closed**: If socket creation fails, permissions cannot be set to `0600`, or peer credentials cannot be verified, the daemon shuts down immediately.
3. **Peer Credential Authentication**:
   - On Linux/WSL2: Socket uses Unix domain socket with file mode `0600` inside a user-private directory (`XDG_RUNTIME_DIR` or `~/.valutx/run`). Daemon inspects `SO_PEERCRED` / `UCred` to ensure connecting client UID matches runtime UID.
   - On Windows: Uses local AF_UNIX socket in user-private `%LOCALAPPDATA%\valutx\run` with restricted user ACLs and session token binding.
4. **Per-Session Random Token**: A 256-bit cryptographically secure random session token is generated upon daemon start / handshake; all subsequent requests on the session must supply this token.
5. **Frame & Schema Strictness**:
   - Max frame limit: 1 MiB (rejects oversized payloads before memory exhaustion).
   - Rejects unknown fields (`deny_unknown_fields` / `additionalProperties: false`).
   - Rejects malformed JSON with structured `INVALID_REQUEST` error.
   - Rejects replayed idempotency keys on mutating operations with `IDEMPOTENCY_CONFLICT`.
   - Rejects unknown or empty capabilities with `SCOPE_DENIED` / `POLICY_DENIED`.
6. **Zero Leaks**: Structured errors use stable protocol error codes. Raw internal stack traces are never exposed over IPC.

---

## 3. Detailed Component Design

### A. IPC Server & Protocol Envelope (`crates/runtime-core/src/ipc/`)
1. **`IpcConfig` & `IpcServer`**:
   - Configures socket path (in user-private runtime directory with mode `0600`).
   - Asynchronous listener using `tokio::net::UnixListener`.
   - Generates session token using `rand::rngs::OsRng` (32 bytes hex-encoded).
2. **`PeerCredentials` Verification**:
   - Reads `tokio::net::unix::UCred` on Unix/WSL2; verifies client PID/UID.
   - Rejects connections where client UID != server UID (`PEER_CREDENTIAL_MISMATCH`).
3. **`IpcMessageEnvelope`**:
   ```rust
   #[derive(Debug, Clone, Serialize, Deserialize)]
   #[serde(deny_unknown_fields)]
   pub struct IpcMessageEnvelope {
       pub token: String,
       pub caller_identity: String,
       pub project_id: String,
       pub task_id: String,
       pub requested_capability: String,
       pub policy_context: Value,
       #[serde(default, skip_serializing_if = "Option::is_none")]
       pub idempotency_key: Option<String>,
       pub payload: Value,
   }
   ```
4. **Idempotency Store**:
   - In-memory bounded cache tracking recently processed `idempotency_key`s per task.
   - Mutating calls check key; returns cached response or structured `IDEMPOTENCY_CONFLICT` on duplicate in-flight requests.
5. **Framing & Transport**:
   - Length-delimited framing: 4-byte big-endian payload length header + JSON payload.
   - Hard upper bound: 1 MiB (1,048,576 bytes). Frames exceeding this trigger instant connection reset and `RESOURCE_LIMIT` error.

### B. Structured Error Responses
Returns typed protocol errors matching `packages/schemas/v1/error.json`:
- `UNAUTHENTICATED`: Missing or invalid session token.
- `PEER_CREDENTIAL_MISMATCH`: Client UID does not match daemon process UID.
- `CALLER_IDENTITY_MISMATCH`: Forged caller identity.
- `SCOPE_DENIED`: Unknown or disallowed capability requested.
- `RESOURCE_LIMIT`: Frame size exceeded.
- `INVALID_REQUEST`: Malformed JSON or unexpected fields.
- `IDEMPOTENCY_CONFLICT`: Replayed mutating idempotency key.

### C. System Diagnostic Tool (`valutx doctor`)
Exposed as CLI command `valutx doctor` (`crates/runtime-core/src/bin/valutx.rs`):
Probes host environment and outputs machine-readable JSON (`--json`) and human-readable terminal diagnostic table:
1. **Platform & Kernel**:
   - OS name, release, architecture.
   - WSL2 detection: Probes `/proc/version`, `/proc/sys/fs/binfmt_misc/WSLInterop`, WSL environment variables.
2. **Sandboxing Readiness**:
   - **Landlock ABI**: Checks `/sys/kernel/security/lsm` or probes `landlock_create_ruleset` ABI version (v1-v4).
   - **Bubblewrap**: Checks presence of `bwrap` in PATH and verifies executable execution.
   - **Unprivileged User Namespaces**: Checks `/proc/sys/kernel/unprivileged_userns_clone`, `/proc/sys/user/max_user_namespaces`, and detects Ubuntu 24.04 AppArmor restrictions (`/etc/apparmor.d/`).
3. **Secret Storage & Keychain**:
   - Probes OS credential manager availability (Windows Credential Manager / DPAPI on Windows; Secret Service / Keyutils on Linux).
4. **Hardware Resources**:
   - Total & Available RAM.
   - Available disk space on runtime partition.
   - GPU presence (NVIDIA SMI, Direct3D/DXGI on Windows, `/dev/dri` on Linux).
5. **Exit Code Semantics**:
   - Exits `0` if all required capabilities for the active platform profile are met.
   - Exits non-zero (`1`) if critical sandbox/runtime blockers are detected (e.g., bare Windows without WSL2 when sandbox requires Linux container/bwrap).

---

## 4. Test Strategy (Deny Paths First)

1. **Deny-Path Unit & Integration Tests**:
   - `test_deny_wrong_session_token`: Request with invalid/missing token is rejected with `UNAUTHENTICATED`.
   - `test_deny_peer_credential_mismatch`: Simulated non-matching peer UID is rejected immediately.
   - `test_deny_forged_caller_identity`: Envelope claiming a caller identity mismatching session context is rejected.
   - `test_deny_oversized_frame`: Frame > 1 MiB rejected without buffering entire payload (`RESOURCE_LIMIT`).
   - `test_deny_unknown_fields`: Envelope containing extraneous fields rejected (`INVALID_REQUEST`).
   - `test_deny_unknown_capability`: Request with unregistered capability rejected with `SCOPE_DENIED`.
   - `test_deny_replayed_idempotency_key`: Duplicate mutating request with same key returns conflict / idempotent result.
2. **Allow-Path Tests**:
   - `test_allow_valid_authenticated_request`: Roundtrip handshake, valid token, valid envelope, successful response.
   - `test_idempotency_caching`: Mutating call with idempotency key succeeds and is cached.
3. **Doctor Verification**:
   - Run `valutx doctor` on the current machine and verify realistic detection of Windows 11 host environment, WSL2 status, resources, and sandbox prerequisites.

---

## 5. Verification & Review Checkpoints

Before implementation proceeds, this plan requires review and user confirmation.
Once approved, we will:
1. Add necessary dependencies to `crates/runtime-core/Cargo.toml` (`tokio`, `rand`, `thiserror`, `sysinfo` or platform probing utilities).
2. Implement IPC server, credential verifier, token issuer, and envelope validator.
3. Write deny-path tests first in `crates/runtime-core/tests/ipc_deny_tests.rs`.
4. Implement `valutx doctor` with JSON & human-readable output.
5. Validate all tests and run `valutx doctor` to demonstrate live findings.
