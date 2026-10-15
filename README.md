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

Not built: `agent-shield serve` (the proxy over WebSocket, SH-52);
registration of the standalone proxy with Datalayer (SH-47: the SaaS client
exists, `setup --register` does not use it yet); the OTEL export (SH-51); the
Shield report and conformance (SH-36, SH-60); the TypeScript renderers of
diffs and terminals (SH-53).

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
