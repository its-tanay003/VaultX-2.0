# @valutx/desktop

**Trust Level**: User Boundary Client

## Purpose
Tauri desktop interface for VaultX 2.0. Must NEVER bypass human approval dialogs or policy checks.

## Invariants & Restrictions (What it must NEVER do)
- All privileged actions must be policy-evaluated before execution.
- Must communicate with runtime-core via typed versioned schemas.
