# @valutx/agent-orchestrator

**Trust Level**: Untrusted Coordination

## Purpose
Coordinates agent planning, task graphs, and subagents. Must NEVER execute actions without policy evaluation.

## Invariants & Restrictions (What it must NEVER do)
- Must adhere to the strict TypeScript engineering standard.
- Must not perform OS process spawning directly.
- Must treat external data as untrusted.
