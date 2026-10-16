<!--
  ~ Copyright (c) 2025-2026 Datalayer, Inc.
  ~
  ~ BSD 3-Clause License
-->

# Changelog

## 0.2.6

- The registered standalone proxy lends PAP (SHIELD §6.10, SH-73): `agent-shield run --pap <company> -- <agent>` lends the gateway's `pap` toolset at that company as the MCP server `pap_<domain>` (`?only=pap&pap-company=<domain>` on `$DATALAYER_MCP_SERVER_URL`, else `https://mcp.datalayer.run/mcp`), reached with the registered Shield's own token — made at each session, so a token near its end is exchanged first, and written nowhere. It is held to the policy's `mcp.allow` like any lent server, so a flag never lends what the policy does not; local-only, or not allowed, `run` refuses before the agent starts, in a sentence. The harness's own fetch to that company is refused. `ShieldProxy(own_servers=…)`, `registration.pap_servers`, `pap_server_name`; `test_pap_standalone.py` (5).
- The docs site's generated pages at the package's version, the register page listing the *listed* tier, and no *Not built* line naming a built part.

## 0.2.5

- The Shield section of the conformance report says **what changed since the last report** (SHIELD §6.5, SH-36): `build_report(..., previous=<the last report's JSON>)` — the policies by level (new, gone, its version, its rules, its limits), a scope newly permitting more than the organization, the Validate gate, each count that moved (decisions, decided by, answers, limits reached), the coding agent; *No earlier report to compare with* without one, *Nothing changed since the last report* when nothing did. In the JSON (`shield.changed`) and the Markdown and Lexical exports. Tests in `test_conformance_map.py`.
- `IamAuthorizer` held against a fake IAM over HTTP (SHIELD SH-75): the route and the bearer, read at each question; IAM's sentence on a deny; a 403 or a 503 a deny naming `openfga-through-iam`; an allow honoured through an outage until it expires. `test_iam_authorizer.py` (7).

## 0.2.4

- The audit's credential shapes start a token, never the middle of an identifier: a random id such as a PAP operation's (`…-sk-…`) was redacted now and then, losing the operation from the record (found by the v0.2.3 release run, whose tests failed on it; 0.2.3 was tagged and never published). Tests in `test_workspace_and_audit.py`.
- Everything listed under 0.2.3.

## 0.2.3 (tagged, not published)

- Authority across the chain (SHIELD SH-33): the execution credential a caller hands in `_meta.datalayer.credential` is withheld from the agent (`"credential": "withheld"` at `session/new` and every prompt), becomes the `Authorization` of every lent HTTP MCP server — so the gateway decides the agent's calls and every sub-agent's alike — a stdio server is refused with it, and a prompt under another credential than the session was lent with is refused in a sentence. The audit writes *lent*, never which. `agent_shield.acp.credential`; `test_credential_chain.py` (5).
- A terminal's output is pushed to the client while its command runs (SHIELD SH-13, SH-16): the terminal is the Shield's, so the client cannot ask it for its output; the proxy pushes it whole on its own row (`tool_call_update`, `in_progress`, the terminal's reference beside a text block) every 0.2 s while it grows, and once more `completed` when the command ended, before the agent's `terminal/wait_for_exit` or `terminal/release` is answered. `TerminalRun.received` counts every byte read. `test_terminal_stream.py` (2).

## 0.2.2

- A stdio agent that exits before answering fails the request at once, `ChannelRefused` naming its exit code (*the agent exited (code 3) before answering initialize*), where the SDK's request waited for ever and the caller its own timeout — found by SHIELD SH-45's drill (`agent-shield run` with no policy exits).

## 0.2.1

- `serve` reads a binary WebSocket frame as UTF-8 NDJSON, a message a line — what marimo's agents panel writes (use-acp's ndJsonStream): marimo's panel stayed on *Initializing agent…* against 0.2.0, and completes a shielded turn with this (SHIELD SH-49).
- The register refuses, at `setup` and `run`, a harness of agentspecs' listed tier in the sentence *listed, not drilled yet* (SHIELD SH-57: the long tail of the ACP agents page, registered with its documented command and its terms) and an organization's own `org-…` harness, which is served on Datalayer only, where its organization's catalogue holds it and its policy admits the reviewed command (SH-46). agentspecs 0.0.107.

## 0.2.0

External authorization and PAP through the Shield (SHIELD.md §6.10, §6.11; SH-74, SH-75's client
side, SH-78, SH-70, SH-71, SH-72, SH-73; 16 October 2026). **The schema changed** — the
document gains `authorize:` and `authorizer:` — so IAM and agentspecs follow (agentspecs
0.0.105 carries it):

- `agent_shield.policy.authorize`: the authorizer port — `authorize(subject, action, resource,
  context)` in the OpenID AuthZen evaluation shape; the contributions `local` (grants as
  patterns in `agent-shield.yaml`), `authzen` (any evaluation endpoint), `openfga` (an
  organization's own, at its check API) and `opa` (Open Policy Agent, the request as its
  `input`; proved against a real OPA 1.9.0); the port's rules: a deny wins over any Rule, an
  authorizer that cannot be reached is a deny naming it, allows cached until they expire and
  honoured through an outage, denies never cached, no authorizer configured is a deny for
  every class a policy lists — never a fail-open. A by-hand mutation pass killed 7 of 7
  mutants of the precedence.
- The policy's `authorize: [classes]` (empty for a local-only Shield; Datalayer's documents
  name the classes its relationships decide) and `authorizer: {local|openfga|authzen|opa}`;
  `decide` asks the context's hook first, for the strictest scope listing the class, an allow
  letting the rules decide and loosening nothing; the decision carries the authorizer, its
  answer and the model's version into the audit; a scope below drops no class the one above
  authorizes (`widening`).
- `agent_shield.saas.IamAuthorizer`: OpenFGA through IAM (`POST /api/iam/v1/authz/evaluate`
  with the token), the one authorizer on Datalayer and of the registered standalone Shield; a
  managed document naming an authorizer is refused.
- The gateway's `pap_*` tools classed by agentspecs' table (`PAP_TOOL_CLASSES`), a host's own
  table through `ShieldProxy(tool_class=…)` naming the company as the resource, so each PAP
  operation is decided by the Rules and the PAP grant is a decision input through the
  authorizer (`connection:<company>`); the harness's own fetch to a connected company refused
  (`ShieldProxy(companies=…)`): PAP is the only way to a company.
- `agent_shield.pap`: the company role in front of any agent on the PAP SDK's company points
  (`CompanyShield`, `ShieldedCompanyAgent`, `ShieldedOperationExecutor`, `ShieldCompanyPlugin`):
  an incoming operation classed (a term moving money is a `buy`, else a `write`; no terms, a
  `buy`) and decided by the company's policy, held for review when it says ask and released or
  refused by a person, refused in the sentence when it says deny, the answer signed
  (`Signer`), the audit in PAP's vocabulary (`operation`, `review`); the `pap` extra.
- Nothing of 0.1.x is removed; a document without `authorize:` decides as before.

## 0.1.7

The standalone side of SHIELD.md Phase 3 (SH-52, SH-56, SH-55, SH-53, SH-40, SH-47, SH-73,
SH-22; 15 October 2026):

- `agent-shield serve` (`agent_shield.acp.server.ShieldServer`): the proxy as a server, one
  harness per connection, over **WebSocket** (`GET /acp` upgraded; `/acp/ws` as ACP Remote
  has it; `/message` as marimo has it; one JSON-RPC message per text frame) and **ACP
  Streamable HTTP** (`POST /acp` in — `initialize` makes the connection, `200` with the
  result and `Acp-Connection-Id`, everything else `202` —, SSE streams out, connection- and
  session-scoped by `Acp-Session-Id`, `DELETE /acp` to end; batches `501`), as the ACP
  project's RFD and the ecosystem's bridges speak them. The token in the `Authorization`
  header or, over WebSocket, in the first message (`authenticate` with `methodId` `bearer`
  and `_meta.token`), never in the address (refused `400`); beyond the loopback a token is
  required. `--harness <id>` serves the register's at `/acp/<id>`; `--bridge` relays with no
  Shield (the sidecar); an idle HTTP connection is ended. `agent-shield connect <url>`
  mirrors a served Shield on stdio. The ACP TCK through `connect` against `serve`:
  `VERDICT: CONFORMANT`; ACP Remote's `acpremote mirror` drove a shielded turn with a
  permission through it. `ShieldProxy` takes `connect_url` (the agent over the WebSocket
  channel instead of a subprocess) for the sidecar. Extras `serve` (aiohttp) and `otel`.
- `agent-shield setup --register --org --agent` (`agent_shield.registration`): the service
  agent's key read from `$AGENT_SHIELD_SERVICE_KEY`, exchanged at IAM
  (`client_credentials`) and kept with the token in `credentials.yaml` (0600, a looser mode
  not read), exchanged again before it expires; the registered `serve` pulls its policies
  from IAM (fail closed; refuses to start when IAM serves no document), exports its spans
  and counts to Datalayer's observability with the token
  (`agent_shield.tracing.configure_export`, `refresh_export_token`, `flush_export`); what a
  standalone Shield cannot have said in one sentence (`cannot_have`), PAP's availability
  (`pap_sentence`) in `setup` and `policy show`. Proved against prod1's IAM with a throwaway
  service agent, revoked after.
- `@datalayer/agent-shield`: the policy types generated from `schema/policy.schema.json`
  (`policy.generated.ts`, `npm run generate`, held equal by `npm test`); the `diff` and
  `terminal` display contracts of agent-runtimes' `portable/displays` (`readShieldDisplay`,
  `unifiedDiffLines`, `unifiedDiffText`, `terminalText`), held equal to that file by a
  test when it is beside the package; the conformance report's renderer
  (`readConformanceReport`, `renderReportMarkdown`, `renderReportHtml`) on the JSON
  `agent_shield.conformance` writes.
- The documentation: `docs/scripts/generate.py` writes the policy reference from the schema,
  the register table from agentspecs and the Python API from the docstrings;
  `docs/scripts/check_pages.py` holds every page to a **Built** and a **Not built** line and
  to commands, options, modules and links that exist; the *serve and registration*, *works
  with*, *audit* and *conformance* pages; `docs.yaml` builds the site in CI; the Makefile's
  `deploy` refuses without the distribution id.
- 17 new tests (serve, registration), 14 TypeScript tests.

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
