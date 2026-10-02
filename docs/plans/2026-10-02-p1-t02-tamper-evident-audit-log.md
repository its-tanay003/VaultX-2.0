# Implementation Plan - TASK P1-T02: Tamper-Evident Audit Log

**Date**: 2026-10-02  
**Task**: P1-T02  
**Category**: Security & Access Control / Audit Subsystem  
**Status**: PROPOSED FOR HUMAN REVIEW (Per explicit prompt instruction)  
**Risk Assessment**: **Medium (Cryptographic & Storage Boundary)**. Implements append-only hash-chained SQLite WAL logging, Ed25519 signing key lifecycle, content-addressed payload storage, and chain verification.

---

## 1. Context & Architectural Grounding

- **Source of Truth**:
  - **Engineering Master Spec §17.1**: `audit_events` schema: `id`, `run_id`, `event_type`, `actor_id`, `payload_hash`, `created_at`, `prev_hash`, `entry_hash`, `signature`.
  - **Doc 04 §10**: Tamper-evident audit logging. Every privileged action recorded server-side. Append-only, hash-chained, cryptographic integrity protection.
  - **OWASP ASI10**: Immutable signed logs; signing keys inaccessible to models and untrusted tools.
  - **AGENTS.md Invariants**: Audit records are created server-side by the runtime, hash-chained and signed with a key the agent cannot touch; fail closed if audit log is unavailable.

---

## 2. Invariants & Security Guarantees

1. **Server-Side Generation**: Audit events cannot be submitted, altered, or forged by clients over IPC or by models. The runtime signs every record directly before insertion.
2. **Cryptographic Integrity**:
   - `prev_hash`: SHA-256 of the immediate predecessor in the chain (Genesis block uses 64 zeros `000...000`).
   - `entry_hash`: SHA-256 of the canonical representation of `(id, run_id, event_type, actor_id, payload_hash, created_at, prev_hash)`.
   - `signature`: Ed25519 digital signature over `entry_hash` using the runtime's dedicated private signing key.
3. **Key Isolation**:
   - The Ed25519 private key is generated on first startup and persisted in the OS Credential Manager (DPAPI on Windows, Secret Service/keyring on Linux, or mode `0600` private key file outside any mount).
   - The private key is never transmitted over IPC, never exposed in debug logs, and never accessible inside any sandbox root.
4. **Storage Isolation**:
   - SQLite database path: `%LOCALAPPDATA%\valutx\audit\audit.db` (Windows) / `~/.valutx/audit/audit.db` (Linux/macOS).
   - Artifact store path: `%LOCALAPPDATA%\valutx\artifacts\` (Windows) / `~/.valutx/artifacts/` (Linux/macOS).
   - Both locations are outside any workspace or sandbox mount.
5. **Content-Addressed Artifacts**: Large evidence blobs, outputs, or tool payloads are stored in the content-addressed store keyed by SHA-256; the audit record stores only `payload_hash`.
6. **Concurrency Safety**: Database operations use SQLite Write-Ahead Logging (WAL) and exclusive transaction serialization to ensure concurrent writers cannot fork or interleave broken chains.

---

## 3. Detailed Component Architecture

### A. Dependencies in `crates/audit/Cargo.toml`
- `rusqlite = { version = "0.32", features = ["bundled"] }`: Embedded SQLite with WAL mode.
- `ed25519-dalek = { version = "2.1", features = ["rand_core"] }`: Fast, secure digital signatures.
- `sha2 = "0.10"`: SHA-256 cryptographic hashing.
- `hex = "0.4"`: Hexadecimal encoding/decoding.
- `serde = { version = "1.0", features = ["derive"] }` & `serde_json = "1.0"`.
- `chrono = { version = "0.4", features = ["serde"] }`.
- `thiserror = "1.0"`.

### B. Core Modules (`crates/audit/src/`)
1. **`schema.rs` & `models.rs`**:
   - `AuditEventRecord`:
     ```rust
     pub struct AuditEventRecord {
         pub id: i64,
         pub run_id: Option<String>,
         pub event_type: String,
         pub actor_id: String,
         pub payload_hash: String,
         pub created_at: String,
         pub prev_hash: String,
         pub entry_hash: String,
         pub signature: String,
     }
     ```
2. **`crypto.rs`**:
   - `AuditSigner`: Manages Ed25519 keypair generation, signing, and verification.
   - `compute_entry_hash(...) -> String`: Canonical SHA-256 calculation.
   - `verify_signature(public_key, entry_hash, signature) -> bool`.
3. **`storage.rs`**:
   - `AuditLog`: Opens SQLite with `PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;`.
   - `append_event(...)`: Atomic transaction reading the current head's `entry_hash`, generating the new record with monotonic ID, signing, and committing.
   - `verify(range)`: Scans chain verifying:
     - Monotonic ID sequence (`id == prev.id + 1`).
     - Matching `prev_hash` (`curr.prev_hash == prev.entry_hash`).
     - Recomputed `entry_hash == curr.entry_hash`.
     - Valid Ed25519 signature against stored `public_key`.
   - Detects all tampering: modified, deleted, inserted, or reordered rows.
4. **`artifacts.rs`**:
   - `ArtifactStore`: Content-addressed file store under `~/.valutx/artifacts/`.
   - `put(bytes) -> hash`: Writes content into `<store>/<first_2_chars>/<hash>`.
   - `get(hash) -> Option<Vec<u8>>`: Retrieves by hash.
5. **CLI Subcommand**:
   - `valutx audit verify [--db <path>]`
   - `valutx audit export [--db <path>] [--json]`

---

## 4. Test Strategy (Deny Paths First)

1. **Tamper Detection Tests (`crates/audit/tests/tamper_tests.rs`)**:
   - `test_detect_modified_payload_hash`: Altering an event's payload hash fails verification.
   - `test_detect_modified_actor_or_type`: Modifying actor ID or event type fails verification.
   - `test_detect_deleted_row`: Deleting an intermediate row breaks ID continuity and hash linkage.
   - `test_detect_inserted_row`: Inserting a rogue row breaks the hash chain and signature.
   - `test_detect_reordered_rows`: Swapping two consecutive rows breaks `prev_hash` linkage.
   - `test_detect_forged_signature`: Corrupting a signature fails signature verification.
   - `test_detect_broken_genesis`: Altering the initial genesis hash fails verification.
2. **Concurrency & Fork Prevention**:
   - `test_concurrent_writers_no_fork`: Multiple concurrent threads appending events maintain a single linear hash chain without split heads.
3. **Key Isolation & Privacy**:
   - `test_key_never_in_debug_output`: Asserts `format!("{:?}", signer)` redacts the private key bytes.
4. **Scale & Verification Benchmark**:
   - `test_clean_chain_10000_events`: Appends 10,000 events and verifies the entire chain end-to-end within milliseconds.

---

## 5. Definition of Done ("DONE WHEN")

1. Every tamper test fails verification with a descriptive reason.
2. Two concurrent writers cannot fork the chain.
3. The signing key never leaks in logs or formatted output.
4. A clean chain of 10,000 events verifies cleanly and efficiently.
5. `valutx audit verify` CLI command operates on live and test databases.
