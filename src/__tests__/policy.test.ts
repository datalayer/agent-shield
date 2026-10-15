/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';

import {
  ACTION_CLASSES,
  KIND_CLASS,
  SCOPES,
  TOOL_KINDS,
  VERDICTS,
  VERDICT_WORDS,
  WHERE,
  classOf,
  describeDecision,
} from '../index.js';

const here = dirname(fileURLToPath(import.meta.url));
const schema = JSON.parse(readFileSync(join(here, '..', '..', 'schema', 'policy.schema.json'), 'utf8'));

test('the TypeScript constants are the schema’s enums', () => {
  assert.deepEqual(schema.properties.scope.enum, [...SCOPES]);
  assert.deepEqual(schema.$defs.Rule.properties.classes.items.enum, [...ACTION_CLASSES]);
  assert.deepEqual(schema.$defs.Rule.properties.decision.enum, [...VERDICTS]);
  assert.deepEqual(schema.$defs.Rule.properties.where.enum, [...WHERE]);
  assert.deepEqual(schema.$defs.Rule.properties.kinds.items.enum, [...TOOL_KINDS]);
});

test('the schema’s document and rule keys are the interfaces’ keys', () => {
  assert.deepEqual(Object.keys(schema.properties).sort(), ['expires', 'limits', 'mcp', 'network', 'rules', 'scope', 'version']);
  assert.deepEqual(Object.keys(schema.$defs.Rule.properties).sort(), ['classes', 'commands', 'decision', 'kinds', 'name', 'paths', 'reason', 'where']);
  assert.deepEqual(Object.keys(schema.$defs.Limits.properties).sort(), ['bytes_written', 'terminals_open', 'tool_calls']);
  assert.equal(schema.additionalProperties, false);
});

test('every ACP kind has a class, other fails closed to write', () => {
  assert.deepEqual(Object.keys(KIND_CLASS).sort(), [...TOOL_KINDS].sort());
  assert.equal(classOf('other'), 'write');
  assert.equal(classOf('think'), null);
  assert.throws(() => classOf('teleport'), /'teleport' is not a tool kind ACP names/);
});

test('the decisions’ sentences use the three words', () => {
  assert.deepEqual(VERDICT_WORDS, { allow: 'do it', ask: 'ask me first', deny: 'leave it to me' });
  assert.equal(
    describeDecision({ verdict: 'allow', sentence: '', scope: 'session', rule: 'read inside the workspace', decided_by: 'rule' }),
    "do it — session rule 'read inside the workspace'",
  );
  assert.equal(describeDecision({ verdict: 'ask', sentence: '', decided_by: 'default' }), 'ask me first — nothing names it');
  assert.equal(describeDecision({ verdict: 'deny', sentence: '', decided_by: 'network' }), 'leave it to me — network');
});
