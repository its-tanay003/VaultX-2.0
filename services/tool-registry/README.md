# @valutx/tool-registry

**Trust Level**: High Authority Tool Governance

## Purpose
Manages Tool Passports and capability declarations. Must NEVER register unsigned or unverified tools.

## Invariants & Restrictions (What it must NEVER do)
- Must adhere to the strict TypeScript engineering standard.
- Must not perform OS process spawning directly.
- Must treat external data as untrusted.
