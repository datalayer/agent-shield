# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""The workspace: where ``fs/*`` and ``terminal/*`` are answered (SHIELD §4.6).

A path is inside the workspace when, resolved (symlinks followed), it lies
under the workspace's root; everything else is *outside* and the policy says
what happens. A terminal runs with a trimmed environment — the SDK's
inherited set plus what the request names — so nothing of the Shield's own
environment (a provider key) leaks into a command the agent wrote.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import shlex
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping

from acp.transports import default_environment


class OutsideWorkspace(ValueError):
    """A path the workspace does not hold, said in a sentence."""


@dataclass
class Placed:
    """A path, placed against the workspace."""

    given: str
    resolved: Path
    inside: bool

    @property
    def shown(self) -> str:
        """The path as a sentence shows it: relative inside, absolute outside."""
        return self.given if not self.inside else str(self.resolved.relative_to(_root(self.resolved, self.given)))


def _root(resolved: Path, given: str) -> Path:  # pragma: no cover - replaced per workspace below
    return resolved


class Workspace:
    def __init__(self, root: str | Path) -> None:
        self.root = Path(root).resolve()
        if not self.root.is_dir():
            raise OutsideWorkspace(f"{self.root} is not a directory, so it cannot be the workspace")

    def place(self, path: str) -> Placed:
        """Where a path lies; a relative path is taken from the workspace's root."""
        candidate = Path(path)
        if not candidate.is_absolute():
            candidate = self.root / candidate
        resolved = candidate.resolve()
        inside = resolved == self.root or self.root in resolved.parents
        placed = Placed(given=path, resolved=resolved, inside=inside)
        if inside:
            placed.shown = str(resolved.relative_to(self.root)) or "."  # type: ignore[misc]
        else:
            placed.shown = str(resolved)  # type: ignore[misc]
        return placed

    def read_text(self, path: str, *, line: int | None = None, limit: int | None = None) -> str:
        placed = self.place(path)
        if not placed.inside:
            raise OutsideWorkspace(f"{placed.shown} is outside the workspace {self.root}")
        text = placed.resolved.read_text(encoding="utf-8")
        if line is None and limit is None:
            return text
        lines = text.splitlines(keepends=True)
        start = max((line or 1) - 1, 0)
        end = start + limit if limit is not None else None
        return "".join(lines[start:end])

    def write_text(self, path: str, content: str) -> int:
        placed = self.place(path)
        if not placed.inside:
            raise OutsideWorkspace(f"{placed.shown} is outside the workspace {self.root}")
        placed.resolved.parent.mkdir(parents=True, exist_ok=True)
        data = content.encode("utf-8")
        placed.resolved.write_bytes(data)
        return len(data)


# Placed.shown is assigned per instance above; drop the property so assignment works.
del Placed.shown
Placed = dataclass(Placed)  # type: ignore[misc]


@dataclass
class TerminalRun:
    terminal_id: str
    command: str
    args: list[str]
    cwd: Path
    process: asyncio.subprocess.Process
    output_byte_limit: int | None
    output: bytearray = field(default_factory=bytearray)
    truncated: bool = False
    exit_code: int | None = None
    signal: str | None = None
    reader: asyncio.Task[None] | None = None

    @property
    def shown(self) -> str:
        return " ".join([self.command, *map(shlex.quote, self.args)]) if self.args else self.command

    @property
    def exited(self) -> bool:
        return self.exit_code is not None or self.signal is not None


class Terminals:
    """The terminals a session opened, each a child process in the workspace."""

    def __init__(self, workspace: Workspace) -> None:
        self.workspace = workspace
        self._runs: dict[str, TerminalRun] = {}

    async def create(
        self,
        command: str,
        args: list[str] | None = None,
        cwd: str | None = None,
        env: Mapping[str, str] | None = None,
        output_byte_limit: int | None = None,
    ) -> TerminalRun:
        where = self.workspace.place(cwd) if cwd else self.workspace.place(".")
        if not where.inside:
            raise OutsideWorkspace(f"a terminal's cwd {where.shown} is outside the workspace {self.workspace.root}")
        environment = default_environment()
        environment.update(env or {})
        argv = [command, *(args or [])]
        if not args and any(ch.isspace() for ch in command):
            argv = ["/bin/sh", "-c", command]
        process = await asyncio.create_subprocess_exec(
            *argv,
            cwd=str(where.resolved),
            env=environment,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        run = TerminalRun(
            terminal_id=f"term_{uuid.uuid4().hex[:12]}",
            command=command,
            args=list(args or []),
            cwd=where.resolved,
            process=process,
            output_byte_limit=output_byte_limit,
        )
        run.reader = asyncio.create_task(self._read(run), name=f"agent-shield.{run.terminal_id}")
        self._runs[run.terminal_id] = run
        return run

    async def _read(self, run: TerminalRun) -> None:
        stream = run.process.stdout
        assert stream is not None
        while True:
            chunk = await stream.read(4096)
            if not chunk:
                break
            run.output.extend(chunk)
            limit = run.output_byte_limit
            if limit is not None and len(run.output) > limit:
                del run.output[: len(run.output) - limit]
                run.truncated = True
        code = await run.process.wait()
        if code < 0:
            run.signal = _signal_name(-code)
        else:
            run.exit_code = code

    def get(self, terminal_id: str) -> TerminalRun:
        try:
            return self._runs[terminal_id]
        except KeyError:
            raise KeyError(f"no terminal {terminal_id!r} is open in this session") from None

    async def wait(self, terminal_id: str) -> TerminalRun:
        run = self.get(terminal_id)
        if run.reader is not None:
            await run.reader
        return run

    async def kill(self, terminal_id: str) -> TerminalRun:
        run = self.get(terminal_id)
        if not run.exited:
            with contextlib.suppress(ProcessLookupError):
                run.process.kill()
        if run.reader is not None:
            await run.reader
        return run

    async def release(self, terminal_id: str) -> TerminalRun:
        run = await self.kill(terminal_id)
        self._runs.pop(terminal_id, None)
        return run

    async def release_all(self) -> None:
        for terminal_id in list(self._runs):
            await self.release(terminal_id)

    @property
    def open(self) -> int:
        return len(self._runs)


def _signal_name(number: int) -> str:
    import signal

    try:
        return signal.Signals(number).name
    except ValueError:
        return str(number)


def workspace_of(path: str | Path | None) -> Workspace:
    return Workspace(path or os.getcwd())


__all__ = ["OutsideWorkspace", "Placed", "TerminalRun", "Terminals", "Workspace", "workspace_of"]
