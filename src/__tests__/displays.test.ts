/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';

import {
  DISPLAY_META_KEY,
  SHIELD_DIFF_TYPE,
  SHIELD_TERMINAL_TYPE,
  languageOf,
  readShieldDisplay,
  terminalText,
  unifiedDiffLines,
  unifiedDiffText,
} from '../index.js';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..', '..');

test('a diff reads strictly, its language from the path when the data names none', () => {
  const display = readShieldDisplay('c1', {
    type: SHIELD_DIFF_TYPE,
    version: '1',
    data: { path: 'src/app.py', old_text: 'a\nb\n', new_text: 'a\nc\n' },
    text: 'edited src/app.py',
  });
  assert.deepEqual(display, {
    kind: 'diff',
    id: 'c1',
    path: 'src/app.py',
    oldText: 'a\nb\n',
    newText: 'a\nc\n',
    language: 'python',
  });
  assert.equal(languageOf('Makefile'), 'text');
  assert.equal(languageOf('x.TS'), 'typescript');
  const created = readShieldDisplay('c2', { type: SHIELD_DIFF_TYPE, data: { path: 'new.md', new_text: 'hello\n' } });
  assert.equal(created.kind, 'diff');
  assert.equal((created as { oldText: unknown }).oldText, null);
  assert.equal(unifiedDiffText(created as never), '--- /dev/null\n+++ b/new.md\n+hello');
});

test('a terminal reads strictly: an exit code is an integer or null', () => {
  const running = readShieldDisplay('t1', {
    type: SHIELD_TERMINAL_TYPE,
    data: { terminal_id: 'term-1', command: 'pytest -q', output: '' },
  });
  assert.deepEqual(running, {
    kind: 'terminal',
    id: 't1',
    terminalId: 'term-1',
    command: 'pytest -q',
    output: '',
    exitCode: null,
    released: false,
  });
  assert.equal(terminalText(running as never), '$ pytest -q\n(running)');
  const done = readShieldDisplay('t2', {
    type: SHIELD_TERMINAL_TYPE,
    data: { terminal_id: 'term-2', command: 'ls', output: 'a\nb\n', exit_code: 0, released: true },
  });
  assert.equal(terminalText(done as never), '$ ls\na\nb\n(exit 0)');
  const odd = readShieldDisplay('t3', { type: SHIELD_TERMINAL_TYPE, data: { terminal_id: 'x', exit_code: 1.5 } });
  assert.equal(odd.kind, 'unknown');
});

test('anything else is unknown, with nothing drawn from its data', () => {
  const unknown = readShieldDisplay('u', { type: 'application/x-other', version: '2', data: { path: 'x' }, text: 'words' });
  assert.deepEqual(unknown, { kind: 'unknown', id: 'u', type: 'application/x-other', version: '2', text: 'words' });
  assert.equal(readShieldDisplay('u2', { type: SHIELD_DIFF_TYPE, data: { path: '', new_text: 'x' } }).kind, 'unknown');
  assert.equal(readShieldDisplay('u3', { type: SHIELD_DIFF_TYPE, data: [] }).kind, 'unknown');
  assert.equal(DISPLAY_META_KEY, 'reactor.ui/display');
});

test('the unified diff aligns by a longest common subsequence', () => {
  assert.deepEqual(unifiedDiffLines('a\nb\nc\n', 'a\nc\nd\n'), [
    { kind: 'context', text: 'a' },
    { kind: 'remove', text: 'b' },
    { kind: 'context', text: 'c' },
    { kind: 'add', text: 'd' },
  ]);
  assert.deepEqual(unifiedDiffLines(null, 'x\n'), [{ kind: 'add', text: 'x' }]);
  assert.deepEqual(unifiedDiffLines('', ''), []);
});

/**
 * The contracts are agent-runtimes' `portable/displays.ts` (SHIELD SH-53):
 * when that file is beside this package (the monorepo), the display types,
 * the diff and terminal shapes and the decoders' two cases are held equal,
 * whitespace aside.
 */
const sibling = join(root, '..', 'agent-runtimes', 'src', 'portable', 'displays.ts');

const between = (text: string, start: RegExp, end: RegExp, where: string): string => {
  const from = text.search(start);
  assert.notEqual(from, -1, `${where}: ${start} not found`);
  const rest = text.slice(from);
  const to = rest.search(end);
  assert.notEqual(to, -1, `${where}: ${end} not found after ${start}`);
  return rest.slice(0, to);
};
const flat = (text: string): string => text.replace(/\s+/g, ' ').replace(/\s*([{}();,:|])\s*/g, '$1').trim();

test('the diff and terminal contracts are agent-runtimes’ own', { skip: !existsSync(sibling) && 'agent-runtimes is not beside this package' }, () => {
  const ours = readFileSync(join(root, 'src', 'displays.ts'), 'utf8');
  const theirs = readFileSync(sibling, 'utf8');
  for (const name of ['SHIELD_DIFF_TYPE', 'SHIELD_TERMINAL_TYPE', 'DISPLAY_META_KEY']) {
    const value = new RegExp(`export const ${name} =\\s*'([^']+)'`);
    assert.equal(ours.match(value)?.[1], theirs.match(value)?.[1], name);
  }
  // The two decoded shapes: ours as interfaces, theirs as members of a union.
  for (const kind of ['diff', 'terminal']) {
    const mine = between(ours, new RegExp(`kind: '${kind}';`), /\n}/, `ours ${kind}`);
    const its = between(theirs, new RegExp(`kind: '${kind}';`), /\n {4}}/, `theirs ${kind}`);
    assert.equal(flat(mine), flat(its), `the ${kind} shape`);
  }
  // The two decoders' cases: the same keys read, the same refusals. (The diff
  // algorithm is the same longest common subsequence; its text differs by the
  // stricter indexing this package compiles with, so it is held by behaviour above.)
  for (const [start, end] of [
    [/case SHIELD_DIFF_TYPE: \{/, /\n {4}case SHIELD_TERMINAL_TYPE/],
    [/case SHIELD_TERMINAL_TYPE: \{/, /\n {4}(default:|\})/],
  ] as const) {
    assert.equal(flat(between(ours, start, end, 'ours')), flat(between(theirs, start, end, 'theirs')), String(start));
  }
});
