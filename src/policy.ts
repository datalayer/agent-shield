/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

/**
 * The policy document's types and the decisions' sentences, mirroring
 * `schema/policy.schema.json` (the one schema the Python package publishes).
 * `npm test` reads that schema and refuses a drift between the two.
 */

export const SCOPES = ['organization', 'team', 'session'] as const;
export type Scope = (typeof SCOPES)[number];

export const ACTION_CLASSES = ['read', 'write', 'send', 'buy', 'delete', 'execute'] as const;
export type ActionClass = (typeof ACTION_CLASSES)[number];

export const VERDICTS = ['allow', 'ask', 'deny'] as const;
export type Verdict = (typeof VERDICTS)[number];

export const WHERE = ['inside', 'outside', 'any'] as const;
export type Where = (typeof WHERE)[number];

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

/** ACP kind → F-10 class; null means nothing to decide (SHIELD §4.5). */
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

export interface Rule {
  name: string;
  decision: Verdict;
  classes?: ActionClass[];
  kinds?: ToolKind[];
  where?: Where;
  paths?: string[];
  commands?: string[];
  reason?: string | null;
}

export interface Threshold {
  soft: number;
  hard: number;
}

/**
 * The stateful limits of a session (SHIELD §6.3): three count the harness's
 * actions, two what its model costs — the model budget in tokens and the
 * spend in credits (100 a USD). Each has a soft threshold, where the next
 * call asks, and a hard one, where each further call is refused.
 */
export interface Limits {
  tool_calls?: Threshold | null;
  terminals_open?: Threshold | null;
  bytes_written?: Threshold | null;
  model_tokens?: Threshold | null;
  spend?: Threshold | null;
}

export const LIMIT_NAMES = ['tool_calls', 'terminals_open', 'bytes_written', 'model_tokens', 'spend'] as const;
export type LimitName = (typeof LIMIT_NAMES)[number];

/** The limits' words, as the sentences say them. */
export const LIMIT_WORDS: Record<LimitName, string> = {
  tool_calls: 'tool calls',
  terminals_open: 'terminals open at once',
  bytes_written: 'bytes written',
  model_tokens: 'model tokens spent',
  spend: 'credits spent',
};

/** Whose key may run a harness (SHIELD decision 3). */
export const CREDENTIALS = ['account', 'platform', 'either'] as const;
export type Credentials = (typeof CREDENTIALS)[number];

/** The harnesses an organization admits, and whose credentials run them (§6.7). */
export interface Harnesses {
  admit?: string[];
  credentials?: Credentials;
}

export interface Network {
  fetch?: string[];
}

export interface Mcp {
  allow?: string[];
}

export interface Policy {
  scope: Scope;
  version?: number;
  expires?: string | null;
  rules?: Rule[];
  limits?: Limits;
  network?: Network;
  mcp?: Mcp;
  harnesses?: Harnesses;
}

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
