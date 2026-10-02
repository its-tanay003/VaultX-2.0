# @valutx/model-router

**Trust Level**: Untrusted Model Gateway

## Purpose
Dispatches prompts to local/cloud models. Must NEVER silently fall back to cloud when in local-only mode.

## Invariants & Restrictions (What it must NEVER do)
- Must adhere to the strict TypeScript engineering standard.
- Must not perform OS process spawning directly.
- Must treat external data as untrusted.
