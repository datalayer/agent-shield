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

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..', '..');

test('the checked-in policy.generated.ts is what the schema gives now', async () => {
  // The generator is the script `npm run generate` runs; the comparison is byte for byte.
  const { generated } = (await import(join(root, 'scripts', 'generate.mjs'))) as {
    generated: () => Promise<string>;
  };
  const fresh = await generated();
  const kept = readFileSync(join(root, 'src', 'policy.generated.ts'), 'utf8');
  assert.equal(kept, fresh, 'src/policy.generated.ts drifted from schema/policy.schema.json: run `npm run generate`');
  assert.match(kept, /GENERATED from schema\/policy\.schema\.json/);
  for (const name of ['AgentShieldPolicy', 'Rule', 'Limits', 'Threshold', 'Harnesses', 'Network', 'Mcp']) {
    assert.match(kept, new RegExp(`export interface ${name} \\{`), name);
  }
});
