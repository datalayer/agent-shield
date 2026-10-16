/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

/**
 * The `diff` and `terminal` display contracts (SH-53): what a
 * tool result of a shielded harness carries for the page, read strictly for
 * any renderer, and the unified diff drawn from it.
 *
 * These are the same shapes agent-runtimes' `portable/displays.ts` reads —
 * the display types, the data keys, the decoded objects, the diff lines —
 * and `npm test` holds the two equal when that file is beside this package.
 * The landing and the phone draw from here; agent-runtimes consumes it.
 *
 * - **A diff** (`application/vnd.datalayer.shield.diff+json`): what a coding
 *   agent changed in one file — its path, what it held (`null` for a file
 *   that did not exist), what it holds now, the file's language.
 * - **A terminal** (`application/vnd.datalayer.shield.terminal+json`): what
 *   it ran — the command, the output kept after release, the exit code
 *   (`null` while it runs), whether it was released.
 *
 * Anything that does not read is `unknown`, with nothing drawn from its data.
 */

export const SHIELD_DIFF_TYPE = 'application/vnd.datalayer.shield.diff+json';
export const SHIELD_TERMINAL_TYPE = 'application/vnd.datalayer.shield.terminal+json';

/** Where a tool result carries its display for the page. */
export const DISPLAY_META_KEY = 'reactor.ui/display';

export interface DiffDisplay {
  kind: 'diff';
  id: string;
  /** The file, as the agent named it, relative to its workspace. */
  path: string;
  /** What it held; `null` for a file that did not exist. */
  oldText: string | null;
  newText: string;
  /** A highlighter's language name, from the file's suffix (`text` when none). */
  language: string;
}

export interface TerminalDisplay {
  kind: 'terminal';
  id: string;
  terminalId: string;
  /** What it ran, when known. */
  command: string;
  /** The output, kept after the terminal was released. */
  output: string;
  /** `null` while it runs. */
  exitCode: number | null;
  released: boolean;
}

export interface UnknownDisplay {
  kind: 'unknown';
  id: string;
  type: string;
  version: string;
  text: string;
}

export type ShieldDisplay = DiffDisplay | TerminalDisplay | UnknownDisplay;

/** A display as a tool result carries it: its type, its version, its data, its model-safe text. */
export interface CarriedDisplay {
  type?: unknown;
  version?: unknown;
  data?: unknown;
  text?: unknown;
}

const words = (value: unknown): string => (typeof value === 'string' ? value.trim() : '');
const text = (value: unknown): string => (typeof value === 'string' ? value : '');

/** A highlighter's language name from a path's suffix; `text` when none is known. */
export function languageOf(path: string): string {
  const suffix = path.includes('.') ? path.slice(path.lastIndexOf('.') + 1).toLowerCase() : '';
  return LANGUAGES[suffix] ?? 'text';
}

const LANGUAGES: Record<string, string> = {
  py: 'python',
  ts: 'typescript',
  tsx: 'tsx',
  js: 'javascript',
  jsx: 'jsx',
  mjs: 'javascript',
  cjs: 'javascript',
  json: 'json',
  md: 'markdown',
  mdx: 'markdown',
  yaml: 'yaml',
  yml: 'yaml',
  toml: 'toml',
  sh: 'bash',
  bash: 'bash',
  zsh: 'bash',
  html: 'html',
  css: 'css',
  scss: 'scss',
  sql: 'sql',
  go: 'go',
  rs: 'rust',
  java: 'java',
  kt: 'kotlin',
  rb: 'ruby',
  php: 'php',
  c: 'c',
  h: 'c',
  cpp: 'cpp',
  hpp: 'cpp',
  cs: 'csharp',
  swift: 'swift',
  xml: 'xml',
  txt: 'text',
};

/**
 * One display, read strictly: a `diff` or a `terminal` whose data reads, else
 * `unknown` with its type, version and text and nothing drawn from its data.
 */
export function readShieldDisplay(id: string, carried: CarriedDisplay): ShieldDisplay {
  const type = words(carried.type);
  const unknown: UnknownDisplay = {
    kind: 'unknown',
    id,
    type,
    version: words(carried.version),
    text: text(carried.text),
  };
  const data =
    carried.data && typeof carried.data === 'object' && !Array.isArray(carried.data)
      ? (carried.data as Record<string, unknown>)
      : null;
  if (!data) return unknown;
  switch (type) {
    case SHIELD_DIFF_TYPE: {
      const path = words(data.path);
      if (
        !path ||
        typeof data.new_text !== 'string' ||
        !(data.old_text === null || data.old_text === undefined || typeof data.old_text === 'string')
      ) {
        return unknown;
      }
      return {
        kind: 'diff',
        id,
        path,
        oldText: typeof data.old_text === 'string' ? data.old_text : null,
        newText: data.new_text,
        language: words(data.language) || languageOf(path),
      };
    }
    case SHIELD_TERMINAL_TYPE: {
      const terminalId = words(data.terminal_id);
      if (!terminalId) return unknown;
      const exitCode =
        typeof data.exit_code === 'number' && Number.isInteger(data.exit_code) ? data.exit_code : null;
      if (data.exit_code !== null && data.exit_code !== undefined && exitCode === null) {
        return unknown;
      }
      return {
        kind: 'terminal',
        id,
        terminalId,
        command: text(data.command),
        output: text(data.output),
        exitCode,
        released: data.released === true,
      };
    }
    default:
      return unknown;
  }
}

export type DiffLine = { kind: 'context' | 'add' | 'remove'; text: string };

/** A side longer than this is shown removed and added whole, not aligned. */
export const DIFF_LINES_LIMIT = 4000;

const lines = (value: string): string[] => (value === '' ? [] : value.replace(/\n$/, '').split('\n'));

/**
 * The lines of a unified diff between what a file held and what it holds,
 * by a longest common subsequence of lines; a file over `DIFF_LINES_LIMIT`
 * lines on a side is shown removed and added whole.
 */
export function unifiedDiffLines(oldText: string | null, newText: string): DiffLine[] {
  const before = oldText === null ? [] : lines(oldText);
  const after = lines(newText);
  if (before.length > DIFF_LINES_LIMIT || after.length > DIFF_LINES_LIMIT) {
    return [
      ...before.map(text => ({ kind: 'remove' as const, text })),
      ...after.map(text => ({ kind: 'add' as const, text })),
    ];
  }
  // The LCS table, one row per line of `before`.
  const width = after.length + 1;
  const table = new Uint32Array((before.length + 1) * width);
  const at = (i: number, j: number): number => table[i * width + j] as number;
  for (let i = before.length - 1; i >= 0; i--) {
    for (let j = after.length - 1; j >= 0; j--) {
      table[i * width + j] = before[i] === after[j] ? at(i + 1, j + 1) + 1 : Math.max(at(i + 1, j), at(i, j + 1));
    }
  }
  const out: DiffLine[] = [];
  let i = 0;
  let j = 0;
  while (i < before.length && j < after.length) {
    if (before[i] === after[j]) {
      out.push({ kind: 'context', text: before[i] as string });
      i++;
      j++;
    } else if (at(i + 1, j) >= at(i, j + 1)) {
      out.push({ kind: 'remove', text: before[i] as string });
      i++;
    } else {
      out.push({ kind: 'add', text: after[j] as string });
      j++;
    }
  }
  while (i < before.length) out.push({ kind: 'remove', text: before[i++] as string });
  while (j < after.length) out.push({ kind: 'add', text: after[j++] as string });
  return out;
}

/** The unified diff as text (`--- a/path`, `+++ b/path`, one sign per line), as a terminal shows it. */
export function unifiedDiffText(display: DiffDisplay): string {
  const from = display.oldText === null ? '/dev/null' : `a/${display.path}`;
  const signs = { context: ' ', add: '+', remove: '-' } as const;
  return [
    `--- ${from}`,
    `+++ b/${display.path}`,
    ...unifiedDiffLines(display.oldText, display.newText).map(line => `${signs[line.kind]}${line.text}`),
  ].join('\n');
}

/** A terminal as a terminal shows it: the command, its output, how it ended. */
export function terminalText(display: TerminalDisplay): string {
  const ended =
    display.exitCode === null ? (display.released ? '(released)' : '(running)') : `(exit ${display.exitCode})`;
  return [`$ ${display.command}`.trimEnd(), display.output.replace(/\n$/, ''), ended]
    .filter(part => part !== '')
    .join('\n');
}
