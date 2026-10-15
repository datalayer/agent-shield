<!--
  ~ Copyright (c) 2025-2026 Datalayer, Inc.
  ~
  ~ BSD 3-Clause License
-->

# Changelog

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
