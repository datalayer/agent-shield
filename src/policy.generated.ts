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
 * A Cedar policy set, inline, or the path of a .cedar file.
 */
export type Policies = string;
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
 * enforce: what the set denies is refused; log_only: decided and recorded, then let through.
 */
export type Mode = 'enforce' | 'log_only';
/**
 * The policy set, as AgentCore Policy takes it: permit and forbid over Datalayer::User principals, Datalayer::Action::"<server>___<tool>" actions and the Datalayer::Runtime resource, with when temporal { formerly within | since within | count | sum } over the session's request, response and error events. Deny by default; a forbid overrides any permit.
 */
export type Policies1 = string;
/**
 * When a pulled copy stops being honoured.
 */
export type Expires = string | null;
/**
 * The most an agent's egress may be: '*' (any public address) alone, or exact hosts, host:port, IPv4 addresses, CIDRs, each with an optional :port. Left out bounds nothing; empty grants nothing beyond the platform's endpoints.
 */
export type Egress = (string[] | null) & string[];
/**
 * The most an agent's ingress may be: '*', or addresses and CIDRs with an optional :port. 'platform' is always kept. Left out bounds nothing; empty keeps 'platform' only.
 */
export type Ingress = (string[] | null) & string[];
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
 * second or minute.
 */
export type Per = 'second' | 'minute';
/**
 * How many, at most, in each period.
 */
export type Rate1 = number;
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
   * The decision point a standalone Shield asks: local (grants in this file), openfga {url, store, model}, authzen {url}, opa {url, package} or cedar {policies}. On Datalayer the authorizer is IAM's and a managed document names none.
   */
  authorizer?: AuthorizerConfig | null;
  /**
   * A Dogwood policy set deciding every classed action over the session's history (AgentCore Policy's language): a deny wins over any Rule, as the authorizer's does; an allow only lets the Rules decide.
   */
  dogwood?: Dogwood | null;
  expires?: Expires;
  /**
   * The organization's ceiling on its agents' firewall rules (policy.shield): the most any agent may be granted, egress and ingress, '*' allowing '*'. An organization document's alone.
   */
  firewall?: FirewallCeiling | null;
  harnesses?: Harnesses;
  limits?: Limits;
  mcp?: Mcp;
  network?: Network;
  /**
   * Per user, across tools, models and agents: the requests, tokens and connections each person may spend per second or per minute through the organization's AgentCore Gateways, pushed to them as Gateway rate limits. An organization document's alone.
   */
  rate_limits?: RateLimits | null;
  rules?: Rules;
  scope: Scope;
  version?: Version;
}
/**
 * ``authorizer:`` in a policy document: exactly one decision point (standalone).
 */
export interface AuthorizerConfig {
  authzen?: AuthZenAuthorizerConfig | null;
  cedar?: CedarAuthorizerConfig | null;
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
/**
 * ``cedar: {policies}``: a Cedar policy set inline, or the path of a ``.cedar`` file (AC-41).
 */
export interface CedarAuthorizerConfig {
  policies: Policies;
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
 * A Dogwood policy set (Cedar, and ``when temporal`` over the session's events), AC-42.
 *
 * Read as it is loaded: the temporal clauses parsed, AgentCore's quotas held
 * (20 temporal policies, 3 temporal operators in one, a 24-hour window at
 * most) and, when ``cedarpy`` is installed, the Cedar parsed too.
 */
export interface Dogwood {
  mode?: Mode;
  policies: Policies1;
}
/**
 * An organization's ``firewall``: the most any of its agents may be granted.
 *
 * The same grammar as :class:`FirewallRules`. A direction left out (``None``)
 * bounds nothing; an empty egress list grants nothing beyond the base layer,
 * an empty ingress list nothing beyond ``platform``. ``*`` allows ``*``.
 * :func:`agent_shield.firewall.bounds.bounded` holds an agent's rules to it.
 */
export interface FirewallCeiling {
  egress?: Egress;
  ingress?: Ingress;
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
 * What each person may spend through the organization's AgentCore Gateways (AC-45).
 *
 * Per user — the Gateway's OAuth subject, or its IAM principal — across its
 * tools, models and agents, as AgentCore's Gateway rate limits count them. The
 * Shield does not count these in process: they are pushed to the Gateways of an
 * organization that runs on AgentCore.
 */
export interface RateLimits {
  /**
   * Connections a person holds open to a Gateway.
   */
  connections?: Rate | null;
  /**
   * Requests a person makes through a Gateway.
   */
  requests?: Rate | null;
  /**
   * Tokens a person's requests process.
   */
  tokens?: Rate | null;
}
/**
 * A rate: at most ``rate`` per ``per``.
 */
export interface Rate {
  per: Per;
  rate: Rate1;
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
