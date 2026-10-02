# ADR-002: Tauri 2 Isolation Pattern and Strict Content Security Policy

- **Status**: Proposed
- **Deciders**: Product Owner, Security & Architecture Team
- **Date**: 2026-10-02
- **Technical Story**: Task P0-T03 — Write and ratify ADR-002 to ADR-009.
- **Governs**: `apps/desktop`, UI rendering layer, frontend-backend IPC boundary.

---

## Context and Problem Statement

VaultX 2.0 requires a cross-platform desktop shell providing a rich developer UI (Monaco editor, Git diffs, task trees, terminal emulation) while running alongside an untrusted AI model and untrusted workspace content. 

Traditional Electron shells expose massive attack surfaces: Node.js integration inside web views, large binary footprints (>150MB), high RAM usage, and common XSS-to-RCE vulnerabilities. Tauri 2 provides a native Rust core interfacing with system webviews. However, standard Tauri IPC can still be vulnerable if malicious code in the webview (e.g. from rendered markdown, poisoned repo dependencies, or third-party web content) attempts to invoke privileged backend commands directly.

---

## Decision

We adopt **Tauri v2** with the **Isolation Pattern** and a **Strict Content Security Policy (CSP)** for the desktop client:

1. **Tauri 2 Core**: The desktop shell is compiled with Tauri v2 (`apps/desktop`), connecting the native Rust runtime to the React/TypeScript frontend.
2. **Isolation Pattern**: Enable Tauri's isolation pattern. An isolated, sandboxed cryptographic iframe intercepts all frontend IPC messages before they reach the Rust backend. It signs or validates every command request with an ephemeral cryptographic key, preventing injected scripts from forging IPC messages.
3. **Strict Content Security Policy (CSP)**:
   - `default-src 'self';`
   - `script-src 'self';`
   - `style-src 'self' 'unsafe-inline';` (for Monaco editor dynamic tokens)
   - `connect-src 'self' ipc:;`
   - `img-src 'self' data: asset:;`
   - `font-src 'self';`
   - `object-src 'none';`
   - `frame-ancestors 'none';`
   - `base-uri 'self';`
   - `form-action 'none';`
4. **Principle of Least Privilege for IPC**: The frontend only receives capability tokens to invoke non-destructive UI queries. All privileged actions (file writes, process execution, policy modifications) require explicit action tickets verified by `valutx-policy-engine`.

---

## Architectural Critique & Challenges

- **Challenge**: The isolation pattern introduces a cryptographic framing layer for every IPC invoke call. For high-frequency streaming events (such as token-by-token LLM output or continuous stdout from terminal commands running at 60fps), per-message cryptographic iframe framing introduces measurable latency and CPU overhead.
- **Resolution**: High-throughput read streams (terminal output and LLM generation events) must use dedicated Tauri unidirectional event channels with chunked binary/text buffers, rather than bidirectional command invokes. Privileged mutating commands remain strictly behind the cryptographic isolation barrier.

---

## Alternatives Considered

- **Electron**: Rejected. Heavy resource footprint, bundled Chromium/Node.js attack surface, and history of remote code execution (RCE) via webview context exploitation.
- **Pure Web App (Browser only)**: Rejected. Cannot provide zero-trust local OS process supervision, local socket brokering, or offline hardware access required by Invariants 3 and 8.
- **Standard Tauri 2 without Isolation**: Rejected. In the event of an XSS vulnerability in Monaco or third-party UI dependencies, an attacker could invoke exposed Rust commands without cryptographic proof of origin.

---

## Consequences

### Positive
- Negligible binary size overhead (~15MB vs ~180MB for Electron).
- Memory footprint reduced by over 60%.
- Eliminates class of XSS-to-RCE attacks; even if an XSS exploit triggers in the frontend webview, it cannot forge IPC invocations without passing through the isolation frame.

### Negative
- UI development requires strict adherence to CSP (no external CDNs, inline scripts restricted).
- Testing requires headless WebDriver / Tauri test runners rather than standard browser-only suites.

---

## Security Impact

Directly reinforces **Invariant 1** (runtime authority) and **Invariant 6** (untrusted data). Untrusted repository text rendered in the Monaco editor or markdown previewer cannot escalate privileges to the host operating system.

---

## Revisit Trigger

**Revisit when**:
1. Tauri 3 introduces a revised IPC architecture that replaces the isolation iframe model.
2. Webview2 (Windows) or WebKitGTK (Linux) exhibits a zero-day isolation escape that invalidates iframe sandboxing.
3. IPC latency for streaming telemetry exceeds 16ms under standard load during Sprint 1 benchmarking.
