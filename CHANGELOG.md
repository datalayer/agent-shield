<!--
  ~ Copyright (c) 2025-2026 Datalayer, Inc.
  ~
  ~ BSD 3-Clause License
-->

# Changelog

## 0.1.2

The policy side of SHIELD.md Phase 2 (SH-50, SH-31, SH-32, SH-54, SH-35).

- `agent_shield.policy`: the document grows `limits.model_tokens` (the model
  budget, in tokens) and `limits.spend` (the deployment's spend limit, in
  credits, 100 a USD), each soft then hard, and a `harnesses` section — the
  harnesses a scope admits and whose credentials run them (`account`,
  `platform`, `either`; decision 3). `decide_budget(context, policies,
  tokens=, cost=)` decides the next model request against the model limits
  alone; a hard limit's sentence says what would let the session go on (a
  cheaper model, a wider budget, a person's word). `LimitState.spent` counts
  what a model request cost.
- `agent_shield.policy.levels`: `widening(lower, above)` says, in sentences,
  every way a lower document would permit more than the one above — a rule
  that permits more than an overlapping rule above, a limit above, a fetch
  host, an MCP server or a harness the scope above does not list, a
  credentials rule not kept; `check_tightens` refuses with `PolicyWidens`
  (IAM refuses a team document with it, the runtime a session rule);
  `admits` and `credentials_rule` read the `harnesses` section strictest
  scope first. The engine's order is proved in every order the three levels
  are given.
- `agent_shield.saas` (§6.7, decisions 10 and 11): `ManagedPolicies` pulls
  the documents of an account from IAM (`GET
  /mcp-policies/shield/accounts/{account_uid}`, `IamPolicySource`), keeps
  them until their `expires`, takes one pushed over a socket, and polls while
  a watcher runs (30 s); **fail closed** — with IAM unreachable and no
  unexpired copy, `PolicyUnavailable` names IAM in a sentence.
- The proxy: `replace_policies` (a changed set in force at once in every open
  session, the session's own rules kept), `refuse_all` (decision 11 while
  running), `add_session_rule` / `remove_session_rule` / `rules_in_force`
  (a person tightening a running session; a rule that would permit more
  than the organization's documents refused with the sentences),
  `decide_budget`; a `policy` audit event.
- The conformance table (SH-35): the same action over MCP, A2A, ACP, AG-UI
  and the embed gets the same answer at the three levels.
- `agentspecs` is an extra (`[register]`, brought by each harness extra), no
  longer a dependency: IAM installs the policy engine without the
  catalogue's sandbox stack.
- `@datalayer/agent-shield`: `Limits.model_tokens`, `Limits.spend`,
  `LIMIT_NAMES`, `LIMIT_WORDS`, `Harnesses`, `CREDENTIALS`.

## 0.1.1

The package made real (SHIELD.md Phase 0: SH-07, SH-02, SH-08, SH-09, SH-04).

- `agent_shield.policy`: the policy document (one schema, published as
  `schema/policy.schema.json`), the six classes of STUDIO F-10, three scopes
  strictest first, *first decision wins*, stateful limits with soft and hard
  thresholds, `decide(action, context, policies) -> Decision` pure and tested;
  the default policy of decision 5.
- `agent_shield.register`: the harness register read from spec-shaped
  documents, with `claude-code`, `codex`, `gemini-cli`, `goose`, `opencode`
  and `openhands`, each with its terms, credential kind, pinned version and
  where it was checked; a harness without terms is not in the catalogue.
- `agent_shield.acp`: the stdio and WebSocket `ACPChannel` on the official
  SDK (protocol version 1), the normaliser of `session/update` into the
  package's neutral events (a malformed update ends the turn in a sentence),
  the workspace that answers `fs/*` and `terminal/*`, and the **proxy**:
  `agent-shield run -- <command>`, an ACP agent in front of the agent it
  launched, permissions decided by the policy, tool calls classed and
  limited, files and terminals confined to the workspace, `mcpServers`
  rewritten to the allow-list, every action in `~/.agent-shield/audit.jsonl`.
- `agent-shield setup | run | log | policy show | policy schema | policy init |
  harnesses | upgrade [--check] | uninstall`; `serve` says it is not built.
- `@datalayer/agent-shield`: the policy types and the decisions' sentences,
  checked against the same schema in `npm test`.
- The agent-teams scaffold's leftovers removed (the demo extra, the
  orchestration extension, the team CI step); the `datalayer.cli` and
  `datalayer.reactor.cli` entry points real and import-safe.

## 0.1.0

The name reservation: the Python distribution is **`datalayer-agent-shield`**
(PyPI refused `agent-shield` as too close to an existing project); the import
stays `agent_shield`, the npm package `@datalayer/agent-shield`, the repository
`datalayer/agent-shield`. Nothing but the version was in it.
