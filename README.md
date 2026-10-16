<!--
  ~ Copyright (c) 2025-2026 Datalayer, Inc.
  ~
  ~ BSD 3-Clause License
-->

[![Datalayer](https://images.datalayer.io/legacy/datalayer-25.svg)](https://datalayer.ai)

[![Become a Sponsor](https://img.shields.io/static/v1?label=Become%20a%20Sponsor&message=%E2%9D%A4&logo=GitHub&style=flat&color=1ABC9C)](https://github.com/sponsors/datalayer)

# 🤖 🛡️ Agent Shield

[![PyPI - Version](https://img.shields.io/pypi/v/datalayer-agent-shield)](https://pypi.org/project/datalayer-agent-shield)
[![npm](https://img.shields.io/npm/v/%40datalayer%2Fagent-shield)](https://www.npmjs.com/package/@datalayer/agent-shield)

**A runtime firewall for every agent.** Deploy a shield with each agent. Enforce
permissions before actions execute, manage policies centrally, and retain an
audit trail.

The Shield stands between an agent and the world. Its first shippable is the
**proxy**: `agent-shield run -- <an ACP agent's command>` starts the agent as
its subprocess and stands as an [Agent Client Protocol](https://agentclientprotocol.com)
agent on its own stdio, so any ACP client — Zed, `vscode-acp`, Marimo,
Datalayer's runtimes — talks to the Shield and the Shield talks to the agent.
In between it decides:

- `session/request_permission` by the policy: *do it* is answered without the
  client, *ask me first* is forwarded with the same options and answered as
  the person chose, *leave it to me* is refused in a sentence the person sees;
- the agent's `tool_call` notifications are classed (ACP `kind` → `read`,
  `write`, `delete`, `execute`; `other` fails closed to `write`) and held to
  the session's limits; a refusal cancels the turn and says why;
- `fs/*` and `terminal/*` are answered by the Shield against the **workspace**
  — a path outside it is refused, a command runs with a trimmed environment
  — and every one is a tool row the client sees;
- `mcpServers` are rewritten so the agent gets only what the policy lends;
- every action and decision is a line of `~/.agent-shield/audit.jsonl`,
  credentials redacted, a file's content never in it.

## The first five minutes

```bash
pip install "datalayer-agent-shield[claude-code]"   # one extra per harness
agent-shield setup        # finds node, the vendor CLIs and the credentials present; installs the pinned adapter into ~/.agent-shield/harnesses/<id>@<version>; writes agent-shield.yaml beside the project
agent-shield run -- claude-agent-acp               # Claude Code behind the Shield, on this directory, with the default policy
```

Measured on 15 October 2026 from a clean prefix: `setup` took **27 s**
(the adapter `@agentclientprotocol/claude-agent-acp@0.91.0`, 325 MB, through
`npm install --prefix`, never a global `npx`); `run` initialized the adapter
and opened a session in **1.5 s**; the first decision followed the first tool
call. The whole, from `pip install` to a decision seen in the terminal, is
under a minute, five times under the five minutes of SHIELD §5.3.

`setup` asks for nothing it finds: it says which credentials are present by
name (never a value), which are missing and how to export them, and stores
no secret. It refuses, in a sentence, a credential the register forbids — a
Claude Code or ChatGPT subscription login where only an API key serves to
third parties, a Google login on Gemini's individuals tier.

Then:

```bash
agent-shield log                 # the audit, one line per action and decision
agent-shield policy show         # every line of the policy in force, and where it came from
agent-shield policy schema       # the document's JSON Schema
agent-shield harnesses           # the register: each harness, its terms, where they were read
agent-shield upgrade --check     # a newer Shield or adapter?
agent-shield upgrade             # move the adapters to the register's pinned versions
agent-shield uninstall           # previews; --yes removes the adapters and the config, keeps the audit and the policy
```

Zed, `settings.json`:

```json
"agent_servers": {
  "Claude Code behind the Shield": { "command": "agent-shield", "args": ["run", "--", "claude-agent-acp"] }
}
```

Every ACP client that starts a command takes the same line — VS Code's ACP
Client, agentic.nvim, agent-client-kernel, a Telegram bridge such as
acp-connector; the [works with](https://agent-shield.datalayer.tech/works-with/)
page says what was tried, with versions and dates.

## At an address: `serve`

```bash
export SHIELD_TOKEN=$(openssl rand -hex 24)
agent-shield serve --host 0.0.0.0 --port 8788 --token-env SHIELD_TOKEN -- claude-agent-acp   # one harness per connection
agent-shield connect ws://host:8788/acp --token-env SHIELD_TOKEN                               # a served Shield as a local stdio agent
```

`serve` is the same proxy as a server, over **WebSocket** and **ACP Streamable
HTTP** on `/acp` — the transports the ecosystem's bridges converge on (ACP
Remote, `acp_rpc_bridge`, the ACP project's RFD) — with the token in the
`Authorization` header or, over WebSocket, in the first message, never in the
address; `--harness <id>` serves the register's at `/acp/<id>`; `--bridge` is
the same server with no Shield in it, the sidecar of a Datalayer runtime pod.
The ACP TCK through `connect` against `serve`: `VERDICT: CONFORMANT`.

## Registered with Datalayer

```bash
export AGENT_SHIELD_SERVICE_KEY=...   # a service agent's key, made by the organization's administrator
agent-shield setup --register --org <organization uid> --agent <service agent uid>
```

The key is exchanged at IAM for a token (`client_credentials`) and kept with
it in `~/.agent-shield/credentials.yaml`, mode 0600, never shown; `serve` then
pulls its policies from IAM, fails closed without them, and exports its spans
and counts to Datalayer's observability with that token. What a standalone
Shield cannot have — the operator's network boundary and the companion's
mounts, a Datalayer runtime's — is said in a sentence by `setup` and
`policy show`; PAP is said unavailable while local-only, and once registered
`agent-shield run --pap <company> -- <agent>` lends the gateway's PAP toolset
at that company with the Shield's own token, when the policy's `mcp.allow`
names `pap_<company>`.

## The policy

One document per scope — `organization`, `team`, `session` — in
`agent-shield.yaml` beside the project (else `~/.agent-shield/agent-shield.yaml`),
with the schema in [`schema/policy.schema.json`](schema/policy.schema.json).
The strictest scope decides first and **the first decision wins**; a scope
that says nothing passes the action down; nothing a rule names falls to
*ask me first*, never to *do it*.

The default `setup` writes: read and search inside the workspace — do it;
edit and move inside it — do it, shown as diffs; delete, run a command, and
any path outside the workspace — ask me first; a command naming a credential,
`sudo`, a package install from the network, or `git push` — ask me first with
the command shown; a fetch — through `network.fetch`'s allow-list, which is
empty, so refused; send or buy — ask me first. Limits: 100 then 200 tool
calls, 4 then 8 terminals, 5 then 20 MiB written — a **soft** threshold asks
once, a **hard** one refuses each call that would cross it and says what would
let the session go on.

```yaml
scope: session
rules:
  - name: read inside the workspace
    decision: allow
    classes: [read]
    where: inside
  - name: git push
    decision: ask
    classes: [execute]
    commands: ['\bgit\b[^;&|]*\bpush\b']
limits:
  tool_calls: {soft: 100, hard: 200}
network:
  fetch: []
mcp:
  allow: []
```

`agent_shield.policy.decide(action, context, policies)` is pure: it answers
`allow | ask | deny`, the sentence, and the scope and rule that decided.

Three levels hold (SHIELD.md §6.3): on Datalayer the **organization's**
document comes from IAM, the **Appspec's** Rules are the team's, and the
**session's** is the default above plus what a person allows or tightens
while it runs. A lower document only tightens: `agent_shield.policy.widening`
says in sentences where it would permit more, IAM refuses a team document
with them, and the runtime refuses a session rule with them. Two more limits
hold the model: `model_tokens` (the budget) and `spend` (credits, 100 a USD),
soft then hard; `decide_budget` decides the next model request against them.
A `harnesses` section says which harnesses a scope admits and whose
credentials run them.

Managed from Datalayer (`agent_shield.saas`), the policy is pulled from IAM
at the agent's creation, kept until its `expires`, refreshed every 30 s or
when pushed, and **fails closed**: with IAM unreachable and no unexpired
copy, the harness is refused in a sentence naming IAM.

## What is built, and what is not

Built (0.1.2, SHIELD.md Phase 0 and the policy side of Phase 2): the policy
engine and its schema, the three levels with `widening`, the model limits and
`decide_budget`, the `harnesses` section, the SaaS client pulling from IAM
and failing closed; the
register read from [agentspecs](https://github.com/datalayer/agentspecs)
(`claude-code`, `codex`, `gemini-cli`, `goose`, `opencode`, `openhands`,
`fast-agent`); the stdio and WebSocket client channels on the official
`agent-client-protocol` SDK (protocol version 1); the proxy, which passes the
[ACP Test Compatibility Kit](https://github.com/agentclientprotocol/acp-tck)
in front of the test agent (`VERDICT: CONFORMANT`); the audit; the
`agent-shield` command; `@datalayer/agent-shield`'s policy types.

Built in 0.1.7 (SHIELD Phase 3's standalone side): `agent-shield serve` over
WebSocket and ACP Streamable HTTP, one harness per connection, the token in the
header or the first message (SH-52, SH-56); `agent-shield connect`; the bridge
of the `datalayer-harnesses` sidecar (SH-40); `setup --register` through a
service-agent key exchanged at IAM, the registered `serve` pulling its
policies and exporting over OTEL (SH-47, SH-73); the TypeScript types
generated from the schema, the `diff` and `terminal` displays, the report
renderer (SH-53); the documentation site built in CI, its policy reference
and register generated, every page held to what is built (SH-22).

Not built: the Shield report in Datalayer's Validate tab (SH-36); IAM serving
a service agent's organization documents, which a registered standalone
Shield waits on (it refuses to start with none); a driven turn in VS Code,
Neovim and marimo (each needs a window).

Claude Code has been run behind the proxy (`claude-agent-acp` 0.91.0:
initialize, session, modes); a turn needs a funded Anthropic API key.

## Development

```bash
pip install -e ".[test]"
pytest tests/ -q
npm install && npm test            # the TypeScript types against schema/policy.schema.json
make tck                            # the ACP TCK against the proxy (uv tool install acp-tck first)
```

## Documentation

[agent-shield.datalayer.tech](https://agent-shield.datalayer.tech)
