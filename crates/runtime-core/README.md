# valutx-runtime-core

**Trust Level**: High Authority (Core Runtime)

## Purpose
Coordinates the agent execution pipeline, state machine transitions, and component communication across policy, sandboxing, and verification subsystems.

## Invariants & Restrictions (What it must NEVER do)
- **NEVER** treat LLM decision output as authority or permit the model to advance its own state.
- **NEVER** execute privileged operations or OS processes directly (must route through `valutx-process-supervisor`).
- **NEVER** transition to `Executing` without an approved policy decision.
- **NEVER** fall back to unsandboxed execution under any failure condition.
