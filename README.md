<!--
  ~ Copyright (c) 2025-2026 Datalayer, Inc.
  ~
  ~ BSD 3-Clause License
-->

[![Datalayer](https://images.datalayer.io/legacy/datalayer-25.svg)](https://datalayer.ai)

[![Become a Sponsor](https://img.shields.io/static/v1?label=Become%20a%20Sponsor&message=%E2%9D%A4&logo=GitHub&style=flat&color=1ABC9C)](https://github.com/sponsors/datalayer)

# 🤖 🛡️ Agent Shield

[![PyPI - Version](https://img.shields.io/pypi/v/agent-shield)](https://pypi.org/project/agent-shield)
[![npm](https://img.shields.io/npm/v/%40datalayer%2Fagent-shield)](https://www.npmjs.com/package/@datalayer/agent-shield)

## The demo team

`datalayer agent-shield demo` deploys the landing's demo team on Datalayer,
under your own account: the members of the agentspecs team
`sales-and-accounting` that run in the cloud (Accounting) each get a runtime
of yours, serving their application over A2A, open to visitors.

```bash
pip install "agent-shield[demo]"
datalayer agent-shield demo deploy --dry-run   # what it would launch, and cost
datalayer agent-shield demo deploy             # prints demoTeam.accountingA2AUrl for the landing
datalayer agent-shield demo status
datalayer agent-shield demo url
datalayer agent-shield demo stop
```

With `DATALAYER_MAGIC_API_KEY` set (the platform's magic key, a secret), the
runtime is launched unmetered: no credits, and it never expires; `--dry-run`
says `unmetered: yes` and `status` shows `never` for the time left. See the
[CLI reference](docs/docs/cli/index.mdx#the-demo-team).

## The Datalayer orchestration extension

`agent_shield.a2a` (Python) and `@datalayer/agent-shield` (TypeScript)
implement the [Datalayer orchestration
extension](https://datalayer.ai/extensions/orchestration/v1) — an optional
A2A extension that lets a worker and an orchestrator say the things about
*delegated work* that A2A leaves unsaid: which execution a delegation is
part of and where it sits in its tree, a budget to decline before
exceeding, a checkpoint to resume from, and instructions delivered to a
turn already in progress.

```python
from agent_shield.a2a import ExecutionRef, build_delegation_meta

meta = build_delegation_meta(
    ExecutionRef(execution_id="exec_1", root_execution_id="exec_1", depth=0),
    budget={"outputTokens": 4000},
)
```

```typescript
import { buildDelegationMeta } from '@datalayer/agent-shield';

const meta = buildDelegationMeta(
  { executionId: 'exec_1', rootExecutionId: 'exec_1', depth: 0 },
  { budget: { outputTokens: 4000 } },
);
```

Nothing here requires the rest of this package, and nothing here imports
Datalayer's own platform — `agent_shield.a2a.orchestration_extension` and
`@datalayer/agent-shield`'s `src/orchestrationExtension.ts` are each a
standalone module (Python built on `fasta2a` alone; TypeScript with zero
runtime dependencies at all) implementing the identical wire shape, field
for field. A worker implementing none of it still runs; see the normative
specification and its JSON Schema at
[`docs/extension-v1.md`](https://github.com/datalayer-research/context-orchestration-protocols/blob/main/docs/extension-v1.md)
for the full field-by-field contract both modules implement.

This is distinct from `agent_shield.a2a.extensions`' own
**team-coordination** extension (`https://datalayer.io/ext/team-coordination/v1`)
— member assignment, task dependencies, health and reactions for a team's
*own* internal coordination. The two extensions are independent and
separately negotiated; a card may advertise either, both, or neither.

### A reference worker, and a public conformance suite

`agent_shield.a2a.reference_worker` is the smallest thing that speaks the
extension correctly: no model, no framework beyond `fasta2a`, no Datalayer
control plane. Run it standalone —

```bash
python -m agent_shield.a2a.reference_worker  # serves on :8000
```

— point any A2A client at it, and its card advertises the extension. It
answers a turn with what it "spent" (a character count, not a model call,
so this needs no API key), declines a delegation whose budget already
reads `outputTokens: 0` naming the limit, and answers a `pause` request by
ending the turn at a checkpoint it makes up on the spot.

`tests/test_reference_worker_conformance.py` drives it over real ASGI HTTP
(`httpx.ASGITransport`, no socket) with hand-built JSON-RPC requests
matching `docs/extension-v1.md`'s documented wire shapes — negotiation, a
declined budget, pause and resume — runnable by anyone against their own
worker, with no Datalayer service in the loop.
