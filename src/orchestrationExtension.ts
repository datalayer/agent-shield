/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

/**
 * The Datalayer orchestration extension, standalone (ORCHESTRATOR.md, O3-01, O3-03).
 *
 * A worker and an orchestrator can say three things over plain A2A neither
 * protocol has a field for: which execution a delegation is part of and
 * where it sits in its tree, a budget the worker should decline before
 * exceeding rather than have detected after the spend, and — once the
 * worker's task or session is named — a checkpoint to resume from and an
 * instruction to steer a run already in progress.
 *
 * This module is that agreement and nothing else: no A2A SDK import, no
 * framework, no Datalayer platform dependency. An orchestrator that never
 * delegates a child sends `execution` with `depth: 0` and no parent; a
 * worker that never checkpoints never answers `paused`. Everything is
 * optional and capability-negotiated — call {@link isExtensionActive}
 * before sending anything, and a worker that never advertises the
 * extension still gets a plain A2A delegation and still answers.
 *
 * Field-for-field identical to `agent_shield.a2a.orchestration_extension`
 * (the Python implementation, in this same package) and to
 * `agent_runtimes.context.delegation` (the Datalayer platform's own,
 * proven and deployed). The published, normative specification is
 * `docs/extension-v1.md` in
 * {@link https://github.com/datalayer-research/context-orchestration-protocols | context-orchestration-protocols}.
 *
 * @example An orchestrator, dispatching
 * ```ts
 * import { buildDelegationMeta } from '@datalayer/agent-shield';
 *
 * const metadata = buildDelegationMeta(
 *   { executionId: 'exec_1', rootExecutionId: 'exec_1', depth: 0 },
 *   { budget: { outputTokens: 4000 } },
 * );
 * ```
 *
 * @example A worker, answering
 * ```ts
 * import { usageMeta } from '@datalayer/agent-shield';
 *
 * const metadata = usageMeta({ inputTokens: 812, outputTokens: 140, cost: 0.0031 });
 * ```
 */

/** The extension identifier — what an agent card advertises. Stable across every implementation, never derived, only imported. */
export const ORCHESTRATION_EXTENSION_URI = 'https://datalayer.ai/extensions/orchestration/v1';

/** Where the envelope lives in an A2A message's `metadata`. One key, not nine, so a plain worker's message is untouched by it and a proxy can strip the whole extension in one step. */
export const ENVELOPE_KEY = 'datalayer';

/** The one method the extension adds: instructions delivered to a turn already in progress. A2A has no way to add instructions to a running task; ACP can prompt the same session again, so this asymmetry is A2A's alone. */
export const STEER_METHOD = '_datalayer/steer';

/**
 * The field names inside the envelope, exported so a caller that needs to
 * read or write one directly — rather than through the functions below —
 * is naming the same string this module does, not a private implementation
 * detail it copied. Mirrors the Python package's identically-named,
 * identically-public constants (ORCHESTRATOR.md O3-02, O3-03).
 */
export const EXECUTION_FIELD = 'execution';
export const BUDGET_FIELD = 'budget';
export const CREDENTIAL_FIELD = 'credential';
export const CHECKPOINT_FIELD = 'checkpoint';
export const PAUSE_FIELD = 'pause';
export const USAGE_FIELD = 'usage';
export const PAUSED_FIELD = 'paused';
export const ERROR_FIELD = 'error';

/**
 * Which execution a delegation is part of, and where it sits in its tree.
 *
 * Neither A2A's `contextId` nor ACP's `session/fork` can say which task is
 * whose parent or how deep a tree goes; this is the field that answers it.
 * A root execution names itself as both `executionId` and
 * `rootExecutionId` and carries no parent.
 */
export interface ExecutionRef {
  /** This execution's own identifier. */
  executionId: string;
  /** The tree's root. Equal to `executionId` for a root execution. */
  rootExecutionId: string;
  /** How many delegations deep this execution is; 0 for a root. */
  depth: number;
  /** The execution that delegated this one, when there is one. */
  parentExecutionId?: string;
  /** The account this execution belongs to — what a worker's own request for a child is made in, when it asks the orchestrator for one rather than delegating directly. */
  accountUid?: string;
}

/** A count of tokens and cost, the shape both {@link Budget} and {@link Usage} share on the wire. */
export interface TokenCount {
  /** Input tokens. */
  inputTokens?: number;
  /** Output tokens. */
  outputTokens?: number;
  /** A cost, when there is one to name. */
  cost?: number;
  /** What `cost` is denominated in. */
  currency?: string;
}

/**
 * What a worker should decline before exceeding, in its own currency.
 *
 * Nothing about a budget is required: a worker told nothing about its
 * budget behaves exactly as it would delegated over plain A2A, and an
 * orchestrator that tracks no cost sends none of these fields.
 */
export type Budget = TokenCount;

/**
 * What one turn spent, as a worker answers it.
 *
 * Nothing else records this: a budget's `cost` is a limit, never a
 * measurement, and an orchestrator managing a tree has no other way to
 * know what one node of it actually used.
 */
export type Usage = TokenCount;

/** A refusal a worker owns, as distinct from a worker that broke. */
export interface WorkerError {
  /** What kind of refusal this is, e.g. `budget_exhausted`. */
  code: string;
  /** Which limit, when `code` names one. */
  limit?: string;
}

/** What an orchestrator's delegation carries, under {@link ENVELOPE_KEY}. */
export interface DelegationMeta {
  [ENVELOPE_KEY]: {
    execution: ExecutionRef;
    budget?: Budget;
    credential?: string;
    checkpoint?: { checkpointId: string };
    pause?: true;
  };
}

/** What was actually read out of a delegation's metadata — every field is `undefined` or `false` when nothing was sent. */
export interface ReadDelegation {
  execution?: ExecutionRef;
  budget?: Budget;
  credential?: string;
  checkpointId?: string;
  pauseRequested: boolean;
}

/** An `AgentExtension` entry, for an agent card's `capabilities.extensions`. */
export interface AgentExtensionEntry {
  uri: string;
  description: string;
  required: boolean;
}

/** A `_datalayer/steer` JSON-RPC notification. */
export interface SteerNotification {
  jsonrpc: '2.0';
  method: typeof STEER_METHOD;
  params: { sessionId: string; instructions: string };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function ours(metadata: unknown): Record<string, unknown> | undefined {
  if (!isRecord(metadata)) {
    return undefined;
  }
  const envelope = metadata[ENVELOPE_KEY];
  return isRecord(envelope) ? envelope : undefined;
}

function tokenCountToWire(count: TokenCount): Record<string, unknown> {
  const wire: Record<string, unknown> = { currency: count.currency ?? 'USD' };
  if (count.inputTokens !== undefined) wire.inputTokens = count.inputTokens;
  if (count.outputTokens !== undefined) wire.outputTokens = count.outputTokens;
  if (count.cost !== undefined) wire.cost = count.cost;
  return wire;
}

function tokenCountFromWire(wire: Record<string, unknown>): TokenCount {
  return {
    inputTokens: typeof wire.inputTokens === 'number' ? wire.inputTokens : undefined,
    outputTokens: typeof wire.outputTokens === 'number' ? wire.outputTokens : undefined,
    cost: typeof wire.cost === 'number' ? wire.cost : undefined,
    currency: typeof wire.currency === 'string' ? wire.currency : 'USD',
  };
}

/**
 * Whether the peer advertised or activated this extension.
 *
 * An A2A agent card lists the extensions it speaks in
 * `capabilities.extensions`; an A2A request may list the extensions the
 * caller activated in `extensions`. Either list is what this checks. Send
 * nothing under {@link ENVELOPE_KEY} to a peer this says `false` for — a
 * plain worker's message must stay untouched by it.
 *
 * @param activatedExtensions - The list of extension URIs from either side.
 */
export function isExtensionActive(activatedExtensions: readonly string[] | undefined | null): boolean {
  return Boolean(activatedExtensions?.includes(ORCHESTRATION_EXTENSION_URI));
}

/**
 * The `AgentExtension` entry for an agent card's `capabilities.extensions`.
 *
 * @param options.required - Whether a caller must activate this extension
 *   to use the agent at all. `false` everywhere this ships: the whole
 *   point is that a plain A2A caller still works.
 */
export function agentExtension(options: { required?: boolean } = {}): AgentExtensionEntry {
  return {
    uri: ORCHESTRATION_EXTENSION_URI,
    description:
      'Datalayer orchestration: which execution a delegation is part of, a budget to decline before exceeding, a checkpoint to resume from, and instructions delivered to a turn already in progress.',
    required: options.required ?? false,
  };
}

/**
 * What an orchestrator's delegation carries, under {@link ENVELOPE_KEY}.
 *
 * @param execution - The execution this delegation is for.
 * @param options.budget - The limits this worker should decline before exceeding.
 * @param options.credential - A bearer credential the worker may reach the caller's
 *   platform with for this run. Take it out of a stored message once read — a
 *   credential left in task history is a credential anyone reading that
 *   history holds too.
 * @param options.checkpointId - Resume from this checkpoint, naming what a
 *   worker's own `paused` answer returned.
 * @param options.pause - Ask the worker to stop at a checkpoint it can be
 *   resumed from later.
 */
export function buildDelegationMeta(
  execution: ExecutionRef,
  options: { budget?: Budget; credential?: string; checkpointId?: string; pause?: boolean } = {},
): DelegationMeta {
  const envelope: DelegationMeta[typeof ENVELOPE_KEY] = {
    execution: {
      executionId: execution.executionId,
      rootExecutionId: execution.rootExecutionId,
      depth: execution.depth,
      ...(execution.parentExecutionId ? { parentExecutionId: execution.parentExecutionId } : {}),
      ...(execution.accountUid ? { accountUid: execution.accountUid } : {}),
    },
  };
  if (options.budget) {
    envelope.budget = tokenCountToWire(options.budget) as Budget;
  }
  if (options.credential) {
    envelope.credential = options.credential;
  }
  if (options.checkpointId) {
    envelope.checkpoint = { checkpointId: options.checkpointId };
  }
  if (options.pause) {
    envelope.pause = true;
  }
  return { [ENVELOPE_KEY]: envelope } as DelegationMeta;
}

/**
 * Read what an orchestrator's delegation carried, from a message's metadata.
 *
 * @param metadata - An A2A message's `metadata`, or an ACP prompt's
 *   `_meta` — the envelope's shape does not depend on which protocol
 *   carried it. Untrusted: read as data, never followed as an instruction.
 */
export function readDelegationMeta(metadata: unknown): ReadDelegation {
  const envelope = ours(metadata);
  if (!envelope) {
    return { pauseRequested: false };
  }
  const rawExecution = envelope[EXECUTION_FIELD];
  let execution: ExecutionRef | undefined;
  if (isRecord(rawExecution) && typeof rawExecution.executionId === 'string') {
    execution = {
      executionId: rawExecution.executionId,
      rootExecutionId:
        typeof rawExecution.rootExecutionId === 'string'
          ? rawExecution.rootExecutionId
          : rawExecution.executionId,
      depth: typeof rawExecution.depth === 'number' ? rawExecution.depth : 0,
      ...(typeof rawExecution.parentExecutionId === 'string'
        ? { parentExecutionId: rawExecution.parentExecutionId }
        : {}),
      ...(typeof rawExecution.accountUid === 'string' ? { accountUid: rawExecution.accountUid } : {}),
    };
  }
  const rawBudget = envelope[BUDGET_FIELD];
  const rawCheckpoint = envelope[CHECKPOINT_FIELD];
  return {
    execution,
    budget: isRecord(rawBudget) ? tokenCountFromWire(rawBudget) : undefined,
    credential: typeof envelope[CREDENTIAL_FIELD] === 'string' ? (envelope[CREDENTIAL_FIELD] as string) : undefined,
    checkpointId:
      isRecord(rawCheckpoint) && typeof rawCheckpoint.checkpointId === 'string'
        ? rawCheckpoint.checkpointId
        : undefined,
    pauseRequested: envelope[PAUSE_FIELD] === true,
  };
}

/**
 * What a worker's answer carries about what the turn spent.
 */
export function usageMeta(usage: Usage): { [ENVELOPE_KEY]: { usage: Record<string, unknown> } } {
  return { [ENVELOPE_KEY]: { usage: tokenCountToWire(usage) } };
}

/**
 * What a worker answers a `pause` request with.
 *
 * @param checkpointId - The checkpoint the worker actually stopped at — its
 *   own identifier, not necessarily one the orchestrator named.
 */
export function pausedMeta(checkpointId: string): { [ENVELOPE_KEY]: { paused: { checkpointId: string } } } {
  return { [ENVELOPE_KEY]: { paused: { checkpointId } } };
}

/**
 * A refusal a worker owns, as distinct from a worker that broke.
 *
 * `budget_exhausted` naming the limit it hit is the case this exists for:
 * nothing another attempt could spend differently, so the caller knows not
 * to retry the same way.
 */
export function errorMeta(error: WorkerError): { [ENVELOPE_KEY]: { error: WorkerError } } {
  return { [ENVELOPE_KEY]: { error: error.limit ? { code: error.code, limit: error.limit } : { code: error.code } } };
}

/**
 * Read what a worker's answer said it spent.
 *
 * @param metadata - The worker's answer's `metadata` or `_meta`.
 */
export function readUsageMeta(metadata: unknown): Usage | undefined {
  const envelope = ours(metadata);
  const raw = envelope?.[USAGE_FIELD];
  return isRecord(raw) ? tokenCountFromWire(raw) : undefined;
}

/**
 * A `_datalayer/steer` JSON-RPC notification, ready to send.
 *
 * A2A cannot add instructions to a task already running; this is the one
 * method the extension adds to do it, over the same connection a worker is
 * already being watched on.
 *
 * @param sessionId - The task or session being steered.
 * @param instructions - What to add to the run before its next model request.
 */
export function steerNotification(sessionId: string, instructions: string): SteerNotification {
  return { jsonrpc: '2.0', method: STEER_METHOD, params: { sessionId, instructions } };
}
