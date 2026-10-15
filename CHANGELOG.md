<!--
  ~ Copyright (c) 2025-2026 Datalayer, Inc.
  ~
  ~ BSD 3-Clause License
-->

# Changelog

## 0.1.6

0.1.3 to 0.1.5 were never published: a quote nested inside a quoted f-string in
`conformance/map.py` (a SyntaxError on Python 3.10 and 3.11, which the release's tests
caught), then the words moved out of it to a name that was not defined (a latent NameError
on a partially covered clause with no note, which no clause of the catalogue has — tested
now). 0.1.6 is the same release, compiled on 3.10, 17 tests.

The conformance side of SHIELD.md Phase 2 (SH-61, SH-62, SH-63, SH-65, SH-66; 15 October 2026):

- `agent_shield.conformance`: the evidence map for AIUC-1, control by control for
  all 55 at its 2026.4 version (agentspecs 0.0.104's `standards/` catalogue,
  SH-60), each with its collectors — the policy document in force and its
  versions by scope, the rules by class, the limits, the fetch and connection
  allow-lists; the record's rows by kind, behaviour and what decided them; the
  OTEL counts; SH-37's drills as a stored report; the Validate gate and the
  safety set; the benchmarks; the organization's signed documents; a third
  party's recorded reports; the facts the host asserts of its platform, each
  with where it was proved; the screens and notices — and the status rule.
  Five statuses honest by construction: *met by evidence* only when every piece
  the rule asks for was collected; *partly met* with what is missing named; *the
  organization's* until a person's document is signed, filled and in date, never
  auto-met; *a third party's* until a report recorded within the cadence says it
  passed; *not applicable* with why (the five controls retired in 2026.4). A
  policy written wider than the organization's (the application's own scope)
  drops D003 and B006 to partly met with the widening in the reason. Each
  control machine-readable: status, evidence with links and when collected,
  missing, crosswalks, the cadence clock. 14 of 14 by-hand mutants of the
  status rule killed.
- `agent_shield.report`: the conformance report per deployment and per
  organization (the weakest answer across deployments), every control with its
  status, evidence linked, the cadence clocks, the gaps, each control's
  crosswalk (the EU AI Act article, the NIST AI RMF function, the ISO/IEC 42001
  clause, the OWASP Agentic threat, and the rest the standard publishes); the
  Shield report of §6.5 as its Shield section (the policies in force at the
  three levels, the tests the Rules passed with the drills, the approvals and
  denials of the period with who decided, the limits reached, the coding
  agent's register entry); its first page says the Shield evidences and never
  certifies. Exported as Markdown, as a Lexical document (the Studio's), as
  JSON; for an assessor (SH-65) the evidence list in AIUC-1's own columns
  (*Requirement*, *Control activity*, *Evidence*, *Tags*, with the status and
  the Datalayer evidence beside), as rows and CSV, and an audit-hub JSON with
  the representative configurations attached.
- `agent_shield.conformance.continuous` (SH-63): `lapses` compares two
  assessments and raises a notice per lapse — a cadence clock run out, an
  application's rules permitting more than the organization's, the
  organization's rules permitting more than before (the snapshot keeps the
  documents it decided with), a drill that failed, a document past its review,
  a control that was met and no longer is — keyed once a day each;
  `Snapshot` and `Trend` for the line over time, one point a week.
- ISO/IEC 42001 through the crosswalk (SH-66): each clause answered from the
  AIUC-1 controls that cover it, the weakest of them, partly met at most where
  the crosswalk says partial, the organization's where nothing covers it; the
  same report from the same evidence.
- The `register` and `test` extras take agentspecs 0.0.104. 16 tests.

## 0.1.2

The policy side of SHIELD.md Phase 2 (SH-50, SH-31, SH-32, SH-54, SH-35).

The audit side of SHIELD.md Phase 2 (SH-34, SH-51, 15 October 2026):

- `agent_shield.tracing`: the Shield over OTEL (§6.8) — every audit row, after
  its redaction, a span event on the current span (`observe`, the safe
  vocabulary only, never a sentence's text beyond the row's fields) and a
  count: `shield.actions`, `shield.decisions`, `shield.refusals`,
  `shield.limits`, by harness and deployment (`set_labels`), filed under the
  account the host exports as; `turn_span` makes one prompt a span under
  whatever is current — the face's request — so the ACP session is one trace;
  `with_traceparent` hands the W3C context to the harness in the prompt's
  `_meta.traceparent`, the key ACP reserves, a caller's own winning;
  `continued` joins a trace a caller handed in; `trace_headers` for a lent
  MCP server. OpenTelemetry stays optional: without it nothing is done, and
  never a `traceparent` nobody opened.
- The audit: a `plan` event (how many steps, their statuses; never their
  text); `fs_read` written as a row of its own (the path, the bytes) beside
  `fs_write`; `redacted_row` for whoever keeps rows elsewhere (agent-runtimes'
  record); `AuditLog.write` observes each row it writes.
- The proxy's `prompt` carries the trace in `_meta.traceparent` (§6.8).

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
