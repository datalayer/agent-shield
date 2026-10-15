/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

// Writes src/policy.generated.ts from schema/policy.schema.json (SHIELD SH-53).
// `node scripts/generate.mjs` writes it; `node scripts/generate.mjs --check`
// exits 1 when the checked-in file differs from what the schema gives now.

import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { compile } from 'json-schema-to-typescript';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const schemaPath = join(root, 'schema', 'policy.schema.json');
const target = join(root, 'src', 'policy.generated.ts');

export async function generated() {
  const schema = JSON.parse(readFileSync(schemaPath, 'utf8'));
  const body = await compile(schema, 'AgentShieldPolicy', {
    additionalProperties: false,
    bannerComment: '',
    style: { singleQuote: true, printWidth: 100 },
  });
  const banner = [
    '/*',
    ' * Copyright (c) 2025-2026 Datalayer, Inc.',
    ' *',
    ' * BSD 3-Clause License',
    ' */',
    '',
    '/* eslint-disable */',
    '/**',
    ' * GENERATED from schema/policy.schema.json by json-schema-to-typescript: do not edit.',
    ' * `npm run generate` writes it; `npm test` regenerates and refuses a drift (SHIELD SH-53).',
    ' */',
    '',
  ].join('\n');
  return banner + body;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const text = await generated();
  if (process.argv.includes('--check')) {
    const current = readFileSync(target, 'utf8');
    if (current !== text) {
      console.error(`${target} differs from what schema/policy.schema.json gives: run npm run generate`);
      process.exit(1);
    }
    console.log(`${target} is what the schema gives`);
  } else {
    writeFileSync(target, text);
    console.log(`wrote ${target}`);
  }
}
