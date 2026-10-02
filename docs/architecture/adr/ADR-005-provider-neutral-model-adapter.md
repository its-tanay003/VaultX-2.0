# ADR-005: Provider-Neutral Model Adapter over OpenAI-Compatible Wire Protocols

- **Status**: Proposed
- **Deciders**: Product Owner, Security & Architecture Team
- **Date**: 2026-10-02
- **Technical Story**: Task P0-T03 — Write and ratify ADR-002 to ADR-009.
- **Governs**: `services/model-router`, `packages/protocol`.

---

## Context and Problem Statement

VaultX 2.0 requires seamless interoperability across both local offline models (Ollama, llama.cpp, vLLM, LM Studio) and external cloud providers (OpenAI, Azure OpenAI, Anthropic, Gemini, OpenRouter). Invariant 8 dictates: *"Local-only mode never silently falls back to cloud."* Invariant 5 dictates: *"Secrets are brokered by reference and redacted everywhere; never in prompts, logs, traces, fixtures or source."*

Tying the codebase to proprietary SDKs creates vendor lock-in, introduces dependency bloat, and complicates strict local-only routing enforcement.

---

## Decision

We adopt a **Provider-Neutral Model Adapter Architecture** standardized around the **OpenAI-Compatible REST wire format**:

1. **Internal Canonical Protocol**:
   - `services/model-router` defines a unified model interface (`ModelClient`) accepting canonical conversation messages, tool definitions, and temperature/seed parameters.
2. **OpenAI-Compatible Baseline**:
   - The primary wire transport communicates using standard HTTP/SSE streaming compatible with the `/v1/chat/completions` API. This natively supports Ollama, vLLM, llama.cpp server, OpenRouter, and OpenAI.
3. **Driver Extensions for Native Provider Features**:
   - While the wire transport defaults to OpenAI-compatible endpoints, dedicated driver adapters translate native features where required (e.g. Anthropic prompt caching, Gemini system instructions, Ollama local grammar constraints).
4. **Local-Only Hardware Enforcement**:
   - When a project or run is configured in `LocalOnly` mode, the router applies a network transport guard that blocks all outbound requests to non-loopback IP addresses (`127.0.0.1`, `::1`).

---

## Architectural Critique & Challenges

- **Challenge**: Relying purely on the OpenAI-compatible wire endpoint can degrade function-calling (Tool Calling) accuracy on smaller local models (e.g., 8B/14B parameter models like Qwen 2.5 or Llama 3.1). Local engines often perform significantly better when tool definitions are enforced via BNF grammars (such as llama.cpp GBNF or Ollama format flags) rather than standard JSON tool calling.
- **Resolution**: The `ModelRouter` must support a "Grammar-Enforced Local Driver" mode that compiles JSON Schemas from `packages/schemas` into GBNF grammars when dispatching to local runtimes, guaranteeing valid structured JSON tool calls from local models.

---

## Alternatives Considered

- **Proprietary Vendor SDKs (`@openai/sdk`, `@anthropic-ai/sdk`, `@google/genai`)**: Rejected for core routing. Increases dependency tree, introduces breaking API churn, and obscures network egress boundaries.
- **Direct LangChain / LlamaIndex Integration**: Rejected. Massive dependency bloat, opaque prompt templates, and violation of the schema-first architecture.

---

## Consequences

### Positive
- Zero vendor lock-in: users can switch between local Ollama instances, local GPUs, and cloud APIs with a single configuration flag.
- Enforces strict offline mode at the socket layer.
- Centralized point for credential redaction and token counting before prompt transmission.

### Negative
- Specialized vendor features (e.g. custom visual grounding or proprietary multi-agent protocols) require custom driver mapping.

---

## Security Impact

Directly enforces **Invariant 5** (secret redaction before prompt transmission) and **Invariant 8** (local-only mode never silently falls back to cloud). Ensures that prompts cannot leak proprietary code to external APIs without explicit user consent.

---

## Revisit Trigger

**Revisit when**:
1. Industry consensus establishes a superior unified standard (e.g. Model Context Protocol / MCP-based model streaming).
2. Local offline models require specialized binary drivers (e.g. direct ONNX / LibTorch runtime embedded in Rust) to meet performance targets on laptops without external daemons.
