# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Hold the documentation to what is built (SHIELD SH-22, REVIEWS G-10).

For every page under ``docs/docs``:

- the page carries one **Built** line and one **Not built** line (a
  ``:::note[Built]`` admonition with both), so a reader is told on every page
  what exists and what does not;
- every ``agent-shield <command>`` the page names is a command of the CLI
  (read from ``agent_shield/cli.py``: ``@app.command`` and ``policy`` subcommands),
  and every ``--flag`` named right after it is an option of that command;
- every ``agent_shield.<module>`` the page names is a module or a public
  name of the package (read from the files, nothing imported);
- every relative link points at a page that exists;
- the generated pages are what the generator gives now (``generate.py --check``);
- the docs' ``package.json`` carries the package's version.

Run from the repository's root: ``python docs/scripts/check_pages.py``. Reads
files only; exits 1 naming each problem.
"""

from __future__ import annotations

import ast
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs" / "docs"
CLI = ROOT / "agent_shield" / "cli.py"
PACKAGE = ROOT / "agent_shield"

COMMAND = re.compile(r"`agent-shield ((?:[a-z-]+ )*[a-z-]+)((?: --?[a-zA-Z-]+)*)")
MODULE = re.compile(r"`agent_shield(?:\.[A-Za-z_][A-Za-z0-9_]*)+")
LINK = re.compile(r"\]\((?P<target>\.{1,2}/[^)#\s]+)(?:#[^)\s]*)?\)")
FENCE = re.compile(r"^```.*?^```", re.S | re.M)
BUILT = re.compile(r"\*\*Built:\*\* ")
NOT_BUILT = re.compile(r"\*\*Not built:\*\* ")


def cli_commands() -> dict[str, set[str]]:
    """Each command and the options it takes, from the Typer source."""
    tree = ast.parse(CLI.read_text(encoding="utf8"))
    groups: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            func = node.value.func
            if isinstance(func, ast.Attribute) and func.attr == "Typer":
                for keyword in node.value.keywords:
                    if keyword.arg == "name" and isinstance(keyword.value, ast.Constant) and node.targets:
                        target = node.targets[0]
                        if isinstance(target, ast.Name):
                            groups[target.id] = str(keyword.value.value)
    commands: dict[str, set[str]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        for decorator in node.decorator_list:
            call = decorator if isinstance(decorator, ast.Call) else None
            func = call.func if call else decorator
            if not (isinstance(func, ast.Attribute) and func.attr == "command" and isinstance(func.value, ast.Name)):
                continue
            group = groups.get(func.value.id, "agent-shield")
            name = node.name.replace("_", "-")
            if call and call.args and isinstance(call.args[0], ast.Constant):
                name = str(call.args[0].value)
            full = name if group == "agent-shield" else f"{group} {name}"
            options: set[str] = set()
            for argument in node.args.args + node.args.kwonlyargs:
                default = None
                defaults = node.args.defaults
                index = node.args.args.index(argument) - (len(node.args.args) - len(defaults)) if argument in node.args.args else -1
                if 0 <= index < len(defaults):
                    default = defaults[index]
                if isinstance(default, ast.Call):
                    for arg in default.args:
                        if isinstance(arg, ast.Constant) and isinstance(arg.value, str) and arg.value.startswith("-"):
                            for flag in arg.value.split("/"):
                                options.add(flag.strip())
            options.update({"--help", "-h"})
            commands[full] = options
    return commands


def package_names() -> set[str]:
    """Every module path and every public name, as ``agent_shield.x.y``."""
    names: set[str] = set()
    for path in PACKAGE.rglob("*.py"):
        relative = path.relative_to(ROOT).with_suffix("")
        parts = list(relative.parts)
        if parts[-1] == "__init__":
            parts = parts[:-1]
        module = ".".join(parts)
        names.add(module)
        tree = ast.parse(path.read_text(encoding="utf8"))
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                names.add(f"{module}.{node.name}")
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        names.add(f"{module}.{target.id}")
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                names.add(f"{module}.{node.target.id}")
            elif isinstance(node, (ast.ImportFrom,)):
                for alias in node.names:
                    names.add(f"{module}.{alias.asname or alias.name}")
    return names


def check_page(page: Path, commands: dict[str, set[str]], names: set[str]) -> list[str]:
    text = page.read_text(encoding="utf8")
    problems: list[str] = []
    where = page.relative_to(ROOT)
    if not BUILT.search(text):
        problems.append(f"{where}: no `**Built:**` line")
    if not NOT_BUILT.search(text):
        problems.append(f"{where}: no `**Not built:**` line")
    prose = FENCE.sub("", text)
    for found in COMMAND.finditer(text):
        words = found.group(1).split()
        candidates = [" ".join(words[:n]) for n in range(len(words), 0, -1)]
        command = next((c for c in candidates if c in commands), None)
        if command is None:
            problems.append(f"{where}: `agent-shield {found.group(1)}` is not a command the CLI has")
            continue
        for flag in found.group(2).split():
            if flag not in commands[command]:
                problems.append(f"{where}: `agent-shield {command}` has no option {flag}")
    for found in MODULE.finditer(prose):
        dotted = found.group(0)[1:]
        if dotted not in names and not any(dotted.startswith(name + ".") for name in names if name.count(".") >= 1 and dotted.count(".") > name.count(".") and name in names and dotted.rsplit(".", 1)[0] == name):
            problems.append(f"{where}: `{dotted}` is not a module or a public name of the package")
    for found in LINK.finditer(text):
        target = (page.parent / found.group("target")).resolve()
        if not (target.exists() or target.with_suffix(".mdx").exists() or (target / "index.mdx").exists()):
            problems.append(f"{where}: link to {found.group('target')} points at nothing")
    return problems


def main() -> int:
    commands = cli_commands()
    names = package_names()
    problems: list[str] = []
    pages = sorted(DOCS.rglob("*.mdx")) + sorted(DOCS.rglob("*.md"))
    if not pages:
        problems.append(f"no page under {DOCS}")
    for page in pages:
        problems.extend(check_page(page, commands, names))
    generated = subprocess.run(
        [sys.executable, str(Path(__file__).with_name("generate.py")), "--check"], capture_output=True, text=True
    )
    if generated.returncode != 0:
        problems.append(f"generated pages: {generated.stdout.strip()} {generated.stderr.strip()}".strip())
    docs_version = json.loads((ROOT / "docs" / "package.json").read_text(encoding="utf8")).get("version")
    version = re.search(r"__version__\s*=\s*[\"']([^\"']+)", (PACKAGE / "__version__.py").read_text(encoding="utf8"))
    if version is None or docs_version != version.group(1):
        problems.append(f"docs/package.json is version {docs_version}; the package is {version.group(1) if version else '?'}")
    for problem in problems:
        print(problem)
    print(f"{len(pages)} pages, {len(commands)} commands, {len(problems)} problems")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
