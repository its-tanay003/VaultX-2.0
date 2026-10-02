import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import {
  ModelReplayHarness,
  computeRequestHash,
  canonicalizeJson,
  type ModelRequest,
  type ModelResponse,
} from '../../../benchmarks/replay/replay-harness.ts';
import {
  loadBenchmarkTasks,
  runBenchmarkSuite,
  validateBenchmarkResult,
  StubAgentRunner,
} from '../../../benchmarks/runner.ts';

describe('VaultX-Bench & Deterministic Model Replay', () => {
  it('loads all 10 seed benchmark tasks with valid categories and configurations', () => {
    const tasks = loadBenchmarkTasks();
    assert.equal(tasks.length, 10, 'Must load exactly 10 seed benchmark tasks');

    const codingTasks = tasks.filter((t) => t.category === 'coding');
    const govTasks = tasks.filter((t) => t.category === 'governance');
    const secTasks = tasks.filter((t) => t.category === 'security');

    assert.equal(codingTasks.length, 5, 'Must have 5 coding tasks');
    assert.equal(govTasks.length, 3, 'Must have 3 governance tasks');
    assert.equal(secTasks.length, 2, 'Must have 2 prompt-injection security tasks');

    for (const t of tasks) {
      assert.ok(t.id.startsWith('TASK-'), `Task ID ${t.id} must start with TASK-`);
      assert.ok(t.instruction.length > 0, `Task ${t.id} must have instruction`);
      assert.ok(t.expected_policy_outcomes.length > 0, `Task ${t.id} must define expected policy outcomes`);
      assert.ok(t.timeout > 0, `Task ${t.id} must have positive timeout`);
    }
  });

  it('executes all 10 tasks against StubAgentRunner and validates result schema', async () => {
    const results = await runBenchmarkSuite({
      runner: new StubAgentRunner(),
      mode: 'replay',
    });

    assert.equal(results.length, 10);

    for (const r of results) {
      assert.equal(r.success, true, `Task ${r.task_id} must succeed`);
      assert.equal(r.verified, true, `Task ${r.task_id} must be verified`);
      assert.ok(r.wall_time_ms >= 0);
      assert.ok(r.cost_usd >= 0);

      // Validate against benchmark-result.json schema
      const validation = validateBenchmarkResult(r);
      assert.equal(validation.valid, true, `Result for ${r.task_id} must match schema: ${validation.errors}`);
    }
  });

  it('guarantees deterministic model replay byte-for-byte across runs', async () => {
    const tmpCassette = path.join(
      os.tmpdir(),
      `test-cassette-${Date.now()}-${Math.random().toString(36).substring(2, 8)}.json`
    );

    const testRequest: ModelRequest = {
      model: 'test-model-v1',
      messages: [
        { role: 'system', content: 'You are an agent.' },
        { role: 'user', content: 'What is 2 + 2?' },
      ],
      temperature: 0,
    };

    const expectedResponse: ModelResponse = {
      id: 'resp-12345',
      model: 'test-model-v1',
      content: '4',
      finish_reason: 'stop',
      usage: {
        prompt_tokens: 12,
        completion_tokens: 1,
        total_tokens: 13,
      },
    };

    try {
      // 1. Record run
      const recordHarness = new ModelReplayHarness(tmpCassette, 'record');
      const recorded = await recordHarness.execute(testRequest, async () => expectedResponse);
      assert.deepEqual(recorded, expectedResponse);
      assert.equal(recordHarness.getEntryCount(), 1);

      // 2. Replay run 1
      const replayHarness1 = new ModelReplayHarness(tmpCassette, 'replay');
      const replayed1 = await replayHarness1.execute(testRequest);

      // 3. Replay run 2
      const replayHarness2 = new ModelReplayHarness(tmpCassette, 'replay');
      const replayed2 = await replayHarness2.execute(testRequest);

      // Byte-for-byte equality assertion
      assert.equal(JSON.stringify(replayed1), JSON.stringify(replayed2));
      assert.equal(JSON.stringify(replayed1), JSON.stringify(expectedResponse));
    } finally {
      if (fs.existsSync(tmpCassette)) {
        fs.unlinkSync(tmpCassette);
      }
    }
  });

  it('fails with clear structured error when a request has no recording in replay mode', async () => {
    const tmpCassette = path.join(
      os.tmpdir(),
      `empty-cassette-${Date.now()}-${Math.random().toString(36).substring(2, 8)}.json`
    );

    const unrecordedRequest: ModelRequest = {
      model: 'test-model-v1',
      messages: [{ role: 'user', content: 'Unrecorded prompt requiring recording' }],
    };

    try {
      const replayHarness = new ModelReplayHarness(tmpCassette, 'replay');
      await assert.rejects(
        async () => {
          await replayHarness.execute(unrecordedRequest);
        },
        (err: Error) => {
          assert.match(err.message, /MODEL_REPLAY_MISS/);
          assert.match(err.message, /No recorded response found in cassette/);
          return true;
        }
      );
    } finally {
      if (fs.existsSync(tmpCassette)) {
        fs.unlinkSync(tmpCassette);
      }
    }
  });

  it('computes stable request hashes regardless of JSON key ordering', () => {
    const req1: ModelRequest = {
      model: 'gpt-4o',
      messages: [{ role: 'user', content: 'test' }],
      temperature: 0.5,
    };

    const req2: ModelRequest = {
      temperature: 0.5,
      messages: [{ role: 'user', content: 'test' }],
      model: 'gpt-4o',
    };

    const hash1 = computeRequestHash(req1);
    const hash2 = computeRequestHash(req2);

    assert.equal(hash1, hash2, 'Request hashes must be identical regardless of property ordering');
    assert.equal(canonicalizeJson(req1), canonicalizeJson(req2));
  });
});
