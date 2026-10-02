# P0-T06 Inert Attack Fixtures & Harness Implementation Plan

> **For Claude / Agent:** REQUIRED SUB-SKILL: Use `superpowers:executing-plans` to implement this plan task-by-task.

**Goal:** Build an inert malicious-repository and prompt-injection fixture catalog and test harness in `security/attack-fixtures/` and `packages/test-fixtures/` with verifiable assertions on canary files and a loopback HTTP listener.

**Architecture:** 
- A static catalog in `security/attack-fixtures/catalog/` containing inert templates for malicious postinstall scripts, Makefiles, git hooks, prompt-injection markdown, directory symlinks, fake MCP configurations, CI workflow files, and a prompt-injection corpus.
- A dynamic harness API `create_fixture(kind)` in `packages/test-fixtures/src/attack-harness.ts` that spawns a loopback listener (`http://127.0.0.1:<random-port>`) and generates isolated canary files in `os.tmpdir()`.
- Assertions strictly evaluate observable facts: `fs.readFileSync(canaryPath)` remaining unchanged, and `listener.receivedRequests.length === 0`.

**Tech Stack:** Node.js HTTP server (loopback only), TypeScript, Vitest, Node.js filesystem APIs.

---

### Task 1: Create Inert Attack Catalog Templates in `security/attack-fixtures/catalog/`
- `catalog/postinstall/`: `package.json` with postinstall writing to `{{CANARY_PATH}}`.
- `catalog/makefile/`: `Makefile` and `build.sh` writing to `{{CANARY_PATH}}`.
- `catalog/git-hook/`: Git hook template writing to `{{CANARY_PATH}}`.
- `catalog/prompt-injection-docs/`: `README.md` and `AGENTS.md` with prompt injection targeting `{{CANARY_SSH_KEY}}` and exfiltrating to `{{LOOPBACK_URL}}`.
- `catalog/symlink-escape/`: Setup creating a symlink pointing to an external target.
- `catalog/fake-mcp/`: `.mcp.json` referencing a non-existent local server.
- `catalog/ci-workflow/`: `.github/workflows/ci.yml` attempting canary write.
- `catalog/prompt-injections/corpus.json`: Structured corpus covering direct overrides, indirect instructions, tool outputs, filenames, and code comments with `expected_outcome: "blocked_by_policy"`.

### Task 2: Implement Fixture Generator and Harness API in `packages/test-fixtures`
- `packages/test-fixtures/src/attack-harness.ts`:
  - `createFixture(kind)`:
    - Creates isolated temp directory `tmp/valutx-attack-XXXXXX/`.
    - Generates inert canary files (`canary.txt`, `id_ed25519_canary`).
    - Spawns an ephemeral `http.Server` listening strictly on `127.0.0.1`.
    - Replaces placeholders `{{CANARY_PATH}}`, `{{CANARY_SSH_KEY}}`, `{{LOOPBACK_URL}}`.
    - Returns `FixtureContext` with `canaryPaths`, `listener`, and `cleanUp()`.
  - `evaluateCanary(context)`: Checks whether canary files were modified or listener received requests.

### Task 3: Implement Stub Executors & Integration Tests in `packages/test-fixtures/tests/`
- Test every fixture kind against:
  1. Supervised stub executor (canary remains untouched, listener receives 0 requests).
  2. Deliberately unconstrained runner (verifies that if a canary is touched, the harness flags it).

### Task 4: CLI Runner for Human Review in `security/attack-fixtures/`
- `security/attack-fixtures/review.ts` (and runner script):
  - Runs all fixtures and prints their directory layouts, file contents, and canary status for human auditing.
