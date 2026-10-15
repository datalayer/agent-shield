/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

/**
 * Tests for orchestrationExtension.
 *
 * The claim under test is round-trip fidelity: what an orchestrator's
 * `buildDelegationMeta` writes is exactly what a worker's
 * `readDelegationMeta` reads back, and what a worker's `usageMeta` /
 * `pausedMeta` / `errorMeta` write is exactly what an orchestrator's
 * `readUsageMeta` reads back — over the plain object shape an A2A
 * message's `metadata` (or an ACP prompt's `_meta`) actually is.
 *
 * Mirrors `tests/test_a2a_orchestration_extension.py` in this same
 * package, field for field, case for case.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  BUDGET_FIELD,
  CHECKPOINT_FIELD,
  CREDENTIAL_FIELD,
  ENVELOPE_KEY,
  ERROR_FIELD,
  EXECUTION_FIELD,
  ORCHESTRATION_EXTENSION_URI,
  PAUSE_FIELD,
  PAUSED_FIELD,
  STEER_METHOD,
  USAGE_FIELD,
  agentExtension,
  buildDelegationMeta,
  errorMeta,
  isExtensionActive,
  pausedMeta,
  readDelegationMeta,
  readUsageMeta,
  steerNotification,
  usageMeta,
} from '../orchestrationExtension.js';

describe('constants', () => {
  test('uri', () => {
    assert.equal(ORCHESTRATION_EXTENSION_URI, 'https://datalayer.ai/extensions/orchestration/v1');
  });

  test('the envelope key is the one key the extension uses', () => {
    // One key, not nine, so a plain worker's message is untouched by it
    // and a proxy can strip the whole extension in one step.
    assert.equal(ENVELOPE_KEY, 'datalayer');
  });

  test('the steer method', () => {
    assert.equal(STEER_METHOD, '_datalayer/steer');
  });

  test('the field names are public, and match the Python package', () => {
    // Exported so a consumer with its own runtime-specific state around a
    // delegation imports these rather than re-declaring them
    // (ORCHESTRATOR.md O3-02, O3-03).
    assert.equal(EXECUTION_FIELD, 'execution');
    assert.equal(BUDGET_FIELD, 'budget');
    assert.equal(CREDENTIAL_FIELD, 'credential');
    assert.equal(CHECKPOINT_FIELD, 'checkpoint');
    assert.equal(PAUSE_FIELD, 'pause');
    assert.equal(USAGE_FIELD, 'usage');
    assert.equal(PAUSED_FIELD, 'paused');
    assert.equal(ERROR_FIELD, 'error');
  });
});

describe('buildDelegationMeta', () => {
  test('the execution is always present', () => {
    const meta = buildDelegationMeta({ executionId: 'exec_1', rootExecutionId: 'exec_1', depth: 0 });
    assert.deepEqual(meta[ENVELOPE_KEY].execution, {
      executionId: 'exec_1',
      rootExecutionId: 'exec_1',
      depth: 0,
    });
  });

  test('a child names its parent', () => {
    const written = buildDelegationMeta({
      executionId: 'exec_2',
      rootExecutionId: 'exec_1',
      depth: 1,
      parentExecutionId: 'exec_1',
      accountUid: 'acc_1',
    })[ENVELOPE_KEY].execution;
    assert.equal(written.parentExecutionId, 'exec_1');
    assert.equal(written.accountUid, 'acc_1');
  });

  test('a root execution names neither', () => {
    const written = buildDelegationMeta({ executionId: 'exec_1', rootExecutionId: 'exec_1', depth: 0 })[ENVELOPE_KEY]
      .execution;
    assert.ok(!('parentExecutionId' in written));
    assert.ok(!('accountUid' in written));
  });

  test('a budget writes the wire shape', () => {
    const budget = buildDelegationMeta(
      { executionId: 'exec_1', rootExecutionId: 'exec_1', depth: 0 },
      { budget: { outputTokens: 4000 } },
    )[ENVELOPE_KEY].budget;
    assert.deepEqual(budget, { outputTokens: 4000, currency: 'USD' });
  });

  test('no budget writes no budget field', () => {
    const envelope = buildDelegationMeta({ executionId: 'exec_1', rootExecutionId: 'exec_1', depth: 0 })[
      ENVELOPE_KEY
    ];
    assert.ok(!('budget' in envelope));
  });

  test('a credential is carried', () => {
    const meta = buildDelegationMeta(
      { executionId: 'exec_1', rootExecutionId: 'exec_1', depth: 0 },
      { credential: 'tok_secret' },
    );
    assert.equal(meta[ENVELOPE_KEY].credential, 'tok_secret');
  });

  test('no credential writes no credential field', () => {
    const envelope = buildDelegationMeta({ executionId: 'exec_1', rootExecutionId: 'exec_1', depth: 0 })[
      ENVELOPE_KEY
    ];
    assert.ok(!('credential' in envelope));
  });

  test('a checkpoint names where to resume from', () => {
    const meta = buildDelegationMeta(
      { executionId: 'exec_1', rootExecutionId: 'exec_1', depth: 0 },
      { checkpointId: 'ckpt_1' },
    );
    assert.deepEqual(meta[ENVELOPE_KEY].checkpoint, { checkpointId: 'ckpt_1' });
  });

  test('pause is present only when asked for', () => {
    const execution = { executionId: 'exec_1', rootExecutionId: 'exec_1', depth: 0 };
    assert.ok(!('pause' in buildDelegationMeta(execution)[ENVELOPE_KEY]));
    assert.equal(buildDelegationMeta(execution, { pause: true })[ENVELOPE_KEY].pause, true);
  });
});

describe('readDelegationMeta', () => {
  test('nothing sent reads as nothing', () => {
    const delegation = readDelegationMeta({});
    assert.equal(delegation.execution, undefined);
    assert.equal(delegation.budget, undefined);
    assert.equal(delegation.credential, undefined);
    assert.equal(delegation.checkpointId, undefined);
    assert.equal(delegation.pauseRequested, false);
  });

  test('a message with no metadata at all reads as nothing', () => {
    // `metadata` can be `null`/`undefined` on a real A2A message.
    assert.equal(readDelegationMeta(null).execution, undefined);
    assert.equal(readDelegationMeta(undefined).execution, undefined);
  });

  test('a plain worker message with unrelated metadata is untouched', () => {
    const delegation = readDelegationMeta({ 'some-other-key': 'value' });
    assert.equal(delegation.execution, undefined);
  });

  test('every field a delegation carries reads back', () => {
    const execution = {
      executionId: 'exec_2',
      rootExecutionId: 'exec_1',
      depth: 1,
      parentExecutionId: 'exec_1',
      accountUid: 'acc_1',
    };
    const meta = buildDelegationMeta(execution, {
      budget: { outputTokens: 4000, cost: 0.5 },
      credential: 'tok_secret',
      checkpointId: 'ckpt_1',
      pause: true,
    });
    const delegation = readDelegationMeta(meta);
    assert.deepEqual(delegation.execution, execution);
    assert.equal(delegation.budget?.outputTokens, 4000);
    assert.equal(delegation.budget?.cost, 0.5);
    assert.equal(delegation.credential, 'tok_secret');
    assert.equal(delegation.checkpointId, 'ckpt_1');
    assert.equal(delegation.pauseRequested, true);
  });

  test("a root execution's depth defaults when absent", () => {
    // A hand-built envelope from a third-party orchestrator that forgot
    // `depth` should not throw; it reads as a root.
    const delegation = readDelegationMeta({ [ENVELOPE_KEY]: { execution: { executionId: 'exec_1' } } });
    assert.equal(delegation.execution?.rootExecutionId, 'exec_1');
    assert.equal(delegation.execution?.depth, 0);
  });
});

describe('usage', () => {
  test('what a worker reports reads back', () => {
    const meta = usageMeta({ inputTokens: 812, outputTokens: 140, cost: 0.0031 });
    const usage = readUsageMeta(meta);
    assert.deepEqual(usage, { inputTokens: 812, outputTokens: 140, cost: 0.0031, currency: 'USD' });
  });

  test('a worker that could not price its model reports no cost', () => {
    const meta = usageMeta({ inputTokens: 812, outputTokens: 140 });
    const usage = readUsageMeta(meta);
    assert.equal(usage?.cost, undefined);
    assert.ok(!('cost' in meta[ENVELOPE_KEY].usage));
  });

  test('a worker that says nothing reports nothing', () => {
    assert.equal(readUsageMeta({}), undefined);
    assert.equal(readUsageMeta(null), undefined);
  });
});

describe('paused and error', () => {
  test('a paused worker names its own checkpoint', () => {
    const meta = pausedMeta('ckpt_1');
    assert.deepEqual(meta[ENVELOPE_KEY].paused, { checkpointId: 'ckpt_1' });
  });

  test('a budget refusal names the limit', () => {
    const meta = errorMeta({ code: 'budget_exhausted', limit: 'output_tokens' });
    assert.deepEqual(meta[ENVELOPE_KEY].error, { code: 'budget_exhausted', limit: 'output_tokens' });
  });

  test('a refusal with no limit names only the code', () => {
    const meta = errorMeta({ code: 'worker_unreachable' });
    assert.deepEqual(meta[ENVELOPE_KEY].error, { code: 'worker_unreachable' });
  });
});

describe('negotiation', () => {
  test('the extension is active when advertised', () => {
    assert.ok(isExtensionActive([ORCHESTRATION_EXTENSION_URI]));
    assert.ok(isExtensionActive(['a', ORCHESTRATION_EXTENSION_URI, 'b']));
  });

  test('the extension is not active by default', () => {
    assert.ok(!isExtensionActive(['some-other-extension']));
    assert.ok(!isExtensionActive([]));
    assert.ok(!isExtensionActive(null));
    assert.ok(!isExtensionActive(undefined));
  });

  test('the agent card entry names the uri', () => {
    const entry = agentExtension();
    assert.equal(entry.uri, ORCHESTRATION_EXTENSION_URI);
    assert.equal(entry.required, false);
  });

  test('a required extension can be declared', () => {
    assert.equal(agentExtension({ required: true }).required, true);
  });
});

describe('steer', () => {
  test('a steer notification carries no id', () => {
    // A notification, not a request: nothing answers it, so it has no
    // JSON-RPC `id` for an answer to correlate against.
    const notification = steerNotification('sess-1', 'check the assumptions');
    assert.ok(!('id' in notification));
    assert.equal(notification.method, STEER_METHOD);
    assert.deepEqual(notification.params, { sessionId: 'sess-1', instructions: 'check the assumptions' });
  });
});
