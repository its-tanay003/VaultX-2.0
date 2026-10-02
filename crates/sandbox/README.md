# valutx-sandbox

**Trust Level**: High Authority (Isolation Boundary)

## Purpose
Enforces OS-level isolation, resource limits (CPU, memory, timeout), filesystem boundaries, and network filtering for tool and terminal execution.

## Invariants & Restrictions (What it must NEVER do)
- **NEVER** execute un-sandboxed code.
- **NEVER** provide a "disable sandbox" escape hatch.
- **NEVER** allow child processes to escape their assigned isolation boundary.
