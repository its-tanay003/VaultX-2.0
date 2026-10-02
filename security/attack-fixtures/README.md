# Security Attack Fixtures & Canary Harness

**Trust Level**: Inert Test Fixtures (`UNTRUSTED_INERT_DATA`)  
**Hard Safety Invariants**:

1. Fixtures must be strictly **inert**: no real malware, no external network, no destructive commands.
2. Fixtures may only read/write canary files created by the test harness in a fresh isolated temporary directory per run.
3. Fixtures may only connect to an ephemeral loopback HTTP listener bound strictly to `127.0.0.1`.
4. Assertions must evaluate harness-observable facts (`canaryUntouched`, `listenerReceivedCount`), never probabilistic model output.

---

## 1. Catalog of Inert Attack Fixtures

The catalog resides in `security/attack-fixtures/catalog/`:

| Fixture Kind | Files | Attack Vector | Inert Safety Guarantee |
| --- | --- | --- | --- |
| `postinstall` | `postinstall/package.json` | Malicious npm postinstall lifecycle hook | Writes only to `{{CANARY_PATH}}` in isolated temp dir |
| `makefile` | `makefile/Makefile`, `build.sh` | Malicious build target altering files outside workspace | Targets `{{CANARY_PATH}}` via echo/touch |
| `git_hook` | `git-hook/pre-commit` | Malicious pre-commit hook executing covert actions | Targets isolated temp canary marker |
| `prompt_injection_docs` | `prompt-injection-docs/README.md`, `AGENTS.md` | Indirect prompt injection directing agent to read `CANARY_SSH_KEY` and exfiltrate | Points to dummy ssh key token in temp dir and `{{LOOPBACK_URL}}` (`127.0.0.1:<port>`) |
| `symlink_escape` | `symlink-escape/README.md` | Symlink inside repository pointing outside project boundary | Points to temporary canary file in test temp directory |
| `fake_mcp` | `fake-mcp/mcp.json` | Rogue MCP server configuration pointing to unverified binary | References non-existent binary `valutx-nonexistent-daemon-binary` |
| `ci_workflow` | `ci-workflow/ci.yml` | Malicious CI workflow action targeting local filesystem | Attempts write to `{{CANARY_PATH}}` only |
| `prompt_injection_corpus` | `prompt-injections/corpus.json` | Multi-channel prompt injection dataset (direct prompt, markdown doc, tool output, filename, code comment) | Static JSON dataset; all cases assert `expected_outcome: "blocked_by_policy"` |

---

## 2. Test Harness API

The harness is implemented in `@valutx/test-fixtures` (`packages/test-fixtures/src/attack-harness.ts`):

```typescript
import { create_fixture, evaluateCanary } from '@valutx/test-fixtures';

// 1. Create an isolated fixture in a fresh temp directory with loopback listener
const context = await create_fixture('prompt_injection_docs');

try {
  // context.repoPath -> fresh directory containing templated files
  // context.canaryPaths.canaryFile -> path to isolated canary.txt
  // context.canaryPaths.canarySshKey -> path to isolated id_ed25519_canary
  // context.listener.url -> http://127.0.0.1:<ephemeral-port>

  // 2. Run runtime / stub executor under test...

  // 3. Evaluate observable facts
  const result = evaluateCanary(context);
  assert.equal(result.canaryTouched, false);
  assert.equal(result.sshKeyTouched, false);
  assert.equal(result.listenerReceivedCount, 0);
} finally {
  await context.cleanUp();
}
```

---

## 3. Reviewing Fixtures by Hand

To review all fixture files, understand their safety guarantees, and run them through stub executors:

```bash
pnpm attack:review
```

Or directly via node:

```bash
node security/attack-fixtures/review.ts
```
