/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

/**
 * The policy document's types and the decisions' sentences.
 *
 * The types come from `schema/policy.schema.json` — the one schema the Python
 * package publishes — through `policy.generated.ts`, written by
 * `npm run generate` (json-schema-to-typescript) and checked in; `npm test`
 * regenerates it and refuses a drift. The constants below are the schema's
 * enums as arrays, held equal to it by the same test. The decisions'
 * sentences live here and nowhere else (SHIELD SH-53): `VERDICT_WORDS` and
 * `describeDecision` are what every card, row and page says.
 */

import type {
  AgentShieldPolicy,
  Credentials,
  Decision as Verdict,
  Harnesses,
  Limits,
  Mcp,
  Network,
  Rule,
  Scope,
  Threshold,
  Where,
} from './policy.generated.js';

export type {
  AgentShieldPolicy,
  Credentials,
  Harnesses,
  Limits,
  Mcp,
  Network,
  Rule,
  Scope,
  Threshold,
  Verdict,
  Where,
};

/** One policy document, one scope: the generated type under the name the plan uses. */
export type Policy = AgentShieldPolicy;

export const SCOPES = ['organization', 'team', 'session'] as const satisfies readonly Scope[];

export const ACTION_CLASSES = ['read', 'write', 'send', 'buy', 'delete', 'execute'] as const;
export type ActionClass = (typeof ACTION_CLASSES)[number];

export const VERDICTS = ['allow', 'ask', 'deny'] as const satisfies readonly Verdict[];

export const WHERE = ['inside', 'outside', 'any'] as const satisfies readonly Where[];

export const TOOL_KINDS = [
  'read',
  'edit',
  'delete',
  'move',
  'search',
  'execute',
  'think',
  'fetch',
  'switch_mode',
  'other',
] as const;
export type ToolKind = (typeof TOOL_KINDS)[number];

/** What a decision says: do it, ask me first, leave it to me (R-05). */
export const VERDICT_WORDS: Record<Verdict, string> = {
  allow: 'do it',
  ask: 'ask me first',
  deny: 'leave it to me',
};

/** ACP kind → F-10 class; null means nothing to decide. */
export const KIND_CLASS: Record<ToolKind, ActionClass | null> = {
  read: 'read',
  search: 'read',
  fetch: 'read',
  edit: 'write',
  move: 'write',
  delete: 'delete',
  execute: 'execute',
  think: null,
  switch_mode: null,
  other: 'write',
};

export const LIMIT_NAMES = ['tool_calls', 'terminals_open', 'bytes_written', 'model_tokens', 'spend'] as const satisfies readonly (keyof Limits)[];
export type LimitName = (typeof LIMIT_NAMES)[number];

/** The limits' words, as the sentences say them. */
export const LIMIT_WORDS: Record<LimitName, string> = {
  tool_calls: 'tool calls',
  terminals_open: 'terminals open at once',
  bytes_written: 'bytes written',
  model_tokens: 'model tokens spent',
  spend: 'credits spent',
};

/** Whose key may run a harness. */
export const CREDENTIALS = ['account', 'platform', 'either'] as const satisfies readonly Credentials[];

export type DecidedBy = 'rule' | 'limit' | 'network' | 'default';

export interface Decision {
  verdict: Verdict;
  sentence: string;
  scope?: Scope | null;
  rule?: string | null;
  decided_by: DecidedBy;
  counted?: boolean;
}

/** The words of a decision, for a row or a card: the verdict's words and where it came from. */
export function describeDecision(decision: Decision): string {
  const words = VERDICT_WORDS[decision.verdict];
  if (decision.decided_by === 'default') {
    return `${words} — nothing names it`;
  }
  const from = decision.scope ? `${decision.scope} ${decision.decided_by}` : decision.decided_by;
  return decision.rule ? `${words} — ${from} '${decision.rule}'` : `${words} — ${from}`;
}

/** The class of an ACP kind, or null when there is nothing to decide. */
export function classOf(kind: string): ActionClass | null {
  if (!(kind in KIND_CLASS)) {
    throw new Error(`'${kind}' is not a tool kind ACP names, so it cannot be classed`);
  }
  return KIND_CLASS[kind as ToolKind];
}
