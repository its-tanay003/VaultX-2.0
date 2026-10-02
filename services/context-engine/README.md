# @valutx/context-engine

**Trust Level**: Untrusted Data Processor

## Purpose
Builds AST, semantic search indices, and workspace context. Must NEVER treat retrieved repo data as instructions.

## Invariants & Restrictions (What it must NEVER do)
- Must adhere to the strict TypeScript engineering standard.
- Must not perform OS process spawning directly.
- Must treat external data as untrusted.
