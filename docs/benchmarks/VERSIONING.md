# VaultX-Bench Versioning & Comparability Specification

Per Spec §26, benchmark evaluations must produce scientifically comparable metrics across both **model upgrades** and **runtime security policy updates**. This document defines the versioning scheme, cassette retention rules, and regression analysis standards.

---

## 1. Benchmark Suite Versioning (`MAJOR.MINOR.PATCH`)

The benchmark suite tracks a dedicated version identifier independent of the core application:

```text
VAULTX_BENCH_VERSION = "1.0.0"
```

### Version Increment Rules

1. **MAJOR Version (`X.0.0`)**:
   - Modified scoring rubric, changed result schema (`benchmark-result.json`), or altered verifier pass/fail thresholds.
   - Deprecation or structural redesign of existing tasks.
   - *Consequence*: Historical runs from prior MAJOR versions cannot be compared directly without running the migration adapter.
2. **MINOR Version (`1.X.0`)**:
   - Adding new benchmark tasks (e.g., adding `TASK-CODE-006` or new governance attack vectors).
   - Adding new diagnostic metrics to result objects (without modifying existing fields).
   - *Consequence*: Existing task scores remain strictly comparable; overall aggregated pass rate must be normalized by task set version.
3. **PATCH Version (`1.0.X`)**:
   - Typo fixes in instructions that do not alter task difficulty or model prompt semantics.
   - Test harness performance improvements and verifier bugfixes.
   - *Consequence*: Fully comparable across runs.

---

## 2. Comparing Runs Across Upgrades

When comparing benchmark results across changes, only one independent variable may vary per evaluation:

### Scenario A: Model Upgrades (Runtime Fixed)

- **Objective**: Evaluate whether a new model improves coding accuracy, prompt-injection resilience, or token efficiency.
- **Fixed Variables**:
  - Runtime policy engine version (`valutx-policy-engine`).
  - Security scope profile.
  - Benchmark task set version (`v1.0.0`).
- **Methodology**:
  1. Execute run in `record` mode against Model A -> capture `results-model-A.json`.
  2. Execute run in `record` mode against Model B -> capture `results-model-B.json`.
  3. Compare:
     $$\Delta \text{Accuracy} = \text{Verified}_B - \text{Verified}_A$$
     $$\Delta \text{Safety} = \text{PolicyDenials}_B - \text{PolicyDenials}_A$$
     $$\Delta \text{Cost} = \text{CostUsd}_B - \text{CostUsd}_A$$

### Scenario B: Runtime Policy & Sandbox Upgrades (Model Replayed)

- **Objective**: Verify that runtime security enhancements (e.g. stricter Cedar policies, tighter Landlock profiles) do not cause false-positive task blockages or regressions.
- **Fixed Variables**:
  - Model responses (fixed via deterministic replay cassette).
  - Benchmark task set version (`v1.0.0`).
- **Methodology**:
  1. Load golden cassette `benchmarks/cassettes/benchmark-seed-cassette.json`.
  2. Execute run in `replay` mode against Baseline Runtime -> assert 10/10 verified.
  3. Execute run in `replay` mode against Candidate Runtime -> assert 10/10 verified.
  4. If any task fails verification under identical model inputs, a **runtime policy regression** has occurred.

---

## 3. Cassette Storage & Invalidation Protocol

Model interaction tapes are stored in `benchmarks/cassettes/<dataset>.json`.

### Canonical Request Hashing

Requests are indexed by a SHA-256 hash computed over recursively key-sorted JSON:

$$\text{RequestHash} = \text{SHA256}(\text{canonicalizeJson}(\text{request}))$$

This guarantees that:

- Formatting variations, whitespace in metadata, or key ordering discrepancies do not invalidate cassettes.
- Any change to system prompts, user instructions, tools, or model IDs generates a distinct hash.

### Invalidation Triggers

A cassette entry is marked stale and must be re-recorded when:

1. The underlying `task.yaml` instruction is modified.
2. The agent prompt template in `services/agent-orchestrator` changes.
3. A new tool passport is added to the agent's capability bounds.

### CI Replay Enforcement

In pull request CI, benchmarks **must always run in `--replay` mode**. Any unrecorded request will immediately throw:

```text
MODEL_REPLAY_MISS: No recorded response found in cassette for request hash [hash]
```

This guarantees zero flaky CI runs, zero external API costs during PR verification, and zero test non-determinism.
