# valutx-process-supervisor

**Trust Level**: Sole Authority (Process Spawning)

## Purpose
Acts as the single, non-bypassable choke point for all process creation across the VaultX 2.0 ecosystem. Enforces process group tracking, timeouts, resource quotas, and signal propagation.

## Invariants & Restrictions (What it must NEVER do)
- **CRITICAL**: This crate is the **ONLY** place in the entire codebase permitted to invoke process execution APIs.
- **NEVER** spawn orphaned or unmonitored child processes.
- **NEVER** allow child processes to run without hard timeouts.
