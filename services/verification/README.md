# @valutx/verification

**Trust Level**: High Authority Verifier

## Purpose
Executes unit tests, lints, and build checks. Must NEVER rely on agent self-reporting for task success.

## Invariants & Restrictions (What it must NEVER do)
- Must adhere to the strict TypeScript engineering standard.
- Must not perform OS process spawning directly.
- Must treat external data as untrusted.
