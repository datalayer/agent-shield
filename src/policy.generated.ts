/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

/* eslint-disable */
/**
 * GENERATED from schema/policy.schema.json by json-schema-to-typescript: do not edit.
 * `npm run generate` writes it; `npm test` regenerates and refuses a drift (SHIELD SH-53).
 */
/**
 * The classes that need an authorizer's allow beside the Rules: a deny wins over any Rule, an unreachable authorizer is a deny. Empty needs none (local-only); Datalayer's documents name read, write, execute, send and buy.
 */
export type Authorize = ('read' | 'write' | 'send' | 'buy' | 'delete' | 'execute')[];
export type Url = string;
/**
 * workspace:* /src/*, tool:earthdata/*, connection:acme.example
 */
export type Object = string;
/**
 * can_read, can_execute, can_call, can_act, or an action class
 */
export type Relation = string;
/**
 * user:alice, account:*, deployment:01…
 */
export type Subject = string;
export type Grants = Grant[];
/**
 * The Rego package answering decision and context.
 */
export type Package = string;
/**
 * OPA's address: http://opa:8181
 */
export type Url1 = string;
export type Model = string | null;
export type Store = string;
export type Url2 = string;
/**
 * When a pulled copy stops being honoured.
 */
export type Expires = string | null;
/**
 * Harness ids of the catalogue this scope admits; empty admits every registered harness.
 */
export type Admit = string[];
/**
 * Whose key runs a harness: the account's own declared secret, the platform's, or either.
 */
export type Credentials = 'account' | 'platform' | 'either';
export type Hard = number;
export type Soft = number;
export type Allow = string[];
/**
 * Hosts a fetch may reach (exact host, or *.example.com); empty refuses every fetch.
 */
export type Fetch = string[];
/**
 * The classes the rule names; empty names every class.
 */
export type Classes = ('read' | 'write' | 'send' | 'buy' | 'delete' | 'execute')[];
/**
 * Regular expressions on the whole command line; any matches.
 */
export type Commands = string[];
export type Decision = 'allow' | 'ask' | 'deny';
/**
 * The ACP tool kinds the rule names; empty names every kind.
 */
export type Kinds = (
  | 'read'
  | 'edit'
  | 'delete'
  | 'move'
  | 'search'
  | 'execute'
  | 'think'
  | 'fetch'
  | 'switch_mode'
  | 'other'
)[];
/**
 * A short name; every sentence quotes it.
 */
export type Name = string;
/**
 * Globs on the path relative to the workspace (fnmatch); any matches.
 */
export type Paths = string[];
/**
 * Why; shown in the sentence.
 */
export type Reason = string | null;
/**
 * inside: only a path inside the workspace; outside: only one outside; any: both, and actions with no path.
 */
export type Where = 'inside' | 'outside' | 'any';
export type Rules = Rule[];
export type Scope = 'organization' | 'team' | 'session';
export type Version = number;

/**
 * One policy document, one scope.
 */
export interface AgentShieldPolicy {
  authorize?: Authorize;
  /**
   * The decision point a standalone Shield asks: local (grants in this file), openfga {url, store, model} or authzen {url}. On Datalayer the authorizer is IAM's and a managed document names none.
   */
  authorizer?: AuthorizerConfig | null;
  expires?: Expires;
  harnesses?: Harnesses;
  limits?: Limits;
  mcp?: Mcp;
  network?: Network;
  rules?: Rules;
  scope: Scope;
  version?: Version;
}
/**
 * ``authorizer:`` in a policy document: exactly one decision point (standalone).
 */
export interface AuthorizerConfig {
  authzen?: AuthZenAuthorizerConfig | null;
  local?: LocalAuthorizerConfig | null;
  opa?: OpaAuthorizerConfig | null;
  openfga?: OpenFgaAuthorizerConfig | null;
}
export interface AuthZenAuthorizerConfig {
  headers?: Headers;
  url: Url;
}
export interface Headers {
  [k: string]: string;
}
export interface LocalAuthorizerConfig {
  grants?: Grants;
}
/**
 * One line of the ``local`` authorizer: who may do what to what, as patterns (fnmatch).
 */
export interface Grant {
  object: Object;
  relation: Relation;
  subject: Subject;
}
export interface OpaAuthorizerConfig {
  headers?: Headers1;
  package?: Package;
  url: Url1;
}
export interface Headers1 {
  [k: string]: string;
}
export interface OpenFgaAuthorizerConfig {
  model?: Model;
  store: Store;
  url: Url2;
}
/**
 * The harnesses an organization admits, and whose credentials run them.
 */
export interface Harnesses {
  admit?: Admit;
  credentials?: Credentials;
}
/**
 * The stateful limits of a session.
 *
 * Three count the harness's actions; two count what its model costs: the
 * **model budget** in tokens and the **spend** in credits (the deployment's
 * spend limit; 100 credits are one USD). Each has a soft threshold, where the
 * next call asks the person, and a hard one, where each further call is
 * refused and the sentence says what would let it go on.
 */
export interface Limits {
  /**
   * Bytes written to the workspace.
   */
  bytes_written?: Threshold | null;
  /**
   * The model budget: tokens the session's model requests spend, in and out.
   */
  model_tokens?: Threshold | null;
  /**
   * The spend limit: credits the session spends on models (100 credits a USD).
   */
  spend?: Threshold | null;
  /**
   * Terminals open at once.
   */
  terminals_open?: Threshold | null;
  /**
   * Classed actions per session.
   */
  tool_calls?: Threshold | null;
}
/**
 * A soft threshold asks once; a hard one refuses each call that would cross it.
 */
export interface Threshold {
  hard: Hard;
  soft: Soft;
}
/**
 * The MCP servers the agent is lent, by name; everything else is cut from session/new.
 */
export interface Mcp {
  allow?: Allow;
}
/**
 * What the agent may reach over the network, through the Shield.
 */
export interface Network {
  fetch?: Fetch;
}
/**
 * One line of a policy: what it matches and what it decides.
 */
export interface Rule {
  classes?: Classes;
  commands?: Commands;
  decision: Decision;
  kinds?: Kinds;
  name: Name;
  paths?: Paths;
  reason?: Reason;
  where?: Where;
}
