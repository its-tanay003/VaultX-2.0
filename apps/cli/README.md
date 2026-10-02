# @valutx/cli

**Trust Level**: Headless Developer CLI

## Purpose
Headless developer CLI for VaultX 2.0. Must NEVER apply weaker policy enforcement than the desktop client.

## Invariants & Restrictions (What it must NEVER do)
- All privileged actions must be policy-evaluated before execution.
- Must communicate with runtime-core via typed versioned schemas.
