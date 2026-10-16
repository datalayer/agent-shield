/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

/**
 * The report document's renderer (SH-53): the conformance
 * report's JSON — what `agent_shield.conformance`'s `Assessment.to_json()`
 * writes: the standard, every control with its status, evidence, gaps,
 * crosswalks and cadence, and the disclaimer on the first page — rendered as
 * Markdown (`renderReportMarkdown`) or HTML (`renderReportHtml`) for the
 * Validate tab, Readiness, an assessor's export, or a page.
 *
 * The input type `ConformanceReport` is the typed seam: the Python side
 * defines the JSON, this side reads it strictly (`readConformanceReport`)
 * and refuses, in a sentence, a document that is not one.
 */

/** The five honest statuses a control can have, in the order a report lists them. */
export const STATUSES = ['partly', 'organizations', 'third_party', 'met', 'not_applicable'] as const;
export type ControlStatus = (typeof STATUSES)[number];

/** The statuses' words, as the report says them. */
export const STATUS_WORDS: Record<ControlStatus, string> = {
  partly: 'partly met',
  organizations: "the organization's",
  third_party: "a third party's",
  met: 'met by evidence',
  not_applicable: 'not applicable',
};

export const EVIDENCE_KINDS = ['documentation', 'config', 'logs', 'evals', 'report', 'demonstration'] as const;
export type EvidenceKind = (typeof EVIDENCE_KINDS)[number];

export interface ReportEvidence {
  kind: EvidenceKind;
  what: string;
  collected_at: string;
  link: string | null;
  item: string | null;
  detail: Record<string, unknown>;
}

export interface ReportCadence {
  months: number | null;
  last: string | null;
  next_due: string | null;
  overdue: boolean;
}

export interface ReportControl {
  control: string;
  title: string;
  domain: string;
  status: ControlStatus;
  status_words: string;
  reason: string;
  mandatory: boolean;
  retired: boolean;
  gap: boolean;
  evidence: ReportEvidence[];
  missing: string[];
  crosswalks: Record<string, string[]>;
  cadence: ReportCadence;
  collected_at: string;
  url: string;
}

/** `Assessment.to_json()`: the whole report. */
export interface ConformanceReport {
  standard: string;
  standard_name: string;
  version: string;
  assessed_at: string;
  version_notice: string | null;
  by_status: Record<ControlStatus, number>;
  gaps: string[];
  controls: ReportControl[];
  disclaimer: string;
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);
const str = (value: unknown): value is string => typeof value === 'string';
const strOrNull = (value: unknown): value is string | null => value === null || typeof value === 'string';
const strings = (value: unknown): value is string[] => Array.isArray(value) && value.every(str);

function readEvidence(value: unknown, where: string): ReportEvidence {
  if (!isRecord(value)) throw new Error(`${where}: an evidence is a mapping`);
  if (!EVIDENCE_KINDS.includes(value.kind as EvidenceKind)) {
    throw new Error(`${where}: evidence kind '${String(value.kind)}' is not one the report knows`);
  }
  if (!str(value.what) || !str(value.collected_at)) throw new Error(`${where}: an evidence says what and when`);
  return {
    kind: value.kind as EvidenceKind,
    what: value.what,
    collected_at: value.collected_at,
    link: strOrNull(value.link) ? value.link : null,
    item: strOrNull(value.item) ? value.item : null,
    detail: isRecord(value.detail) ? value.detail : {},
  };
}

function readControl(value: unknown, index: number): ReportControl {
  const where = `control ${index + 1}`;
  if (!isRecord(value)) throw new Error(`${where}: a control is a mapping`);
  if (!str(value.control) || !str(value.title) || !str(value.domain)) {
    throw new Error(`${where}: a control has an id, a title and a domain`);
  }
  if (!STATUSES.includes(value.status as ControlStatus)) {
    throw new Error(`${value.control}: status '${String(value.status)}' is not one of the five`);
  }
  const cadence = isRecord(value.cadence) ? value.cadence : {};
  const crosswalks: Record<string, string[]> = {};
  if (isRecord(value.crosswalks)) {
    for (const [name, refs] of Object.entries(value.crosswalks)) {
      if (!strings(refs)) throw new Error(`${value.control}: crosswalk '${name}' is a list of references`);
      crosswalks[name] = refs;
    }
  }
  const status = value.status as ControlStatus;
  return {
    control: value.control,
    title: value.title,
    domain: value.domain,
    status,
    status_words: str(value.status_words) ? value.status_words : STATUS_WORDS[status],
    reason: str(value.reason) ? value.reason : '',
    mandatory: value.mandatory === true,
    retired: value.retired === true,
    gap: value.gap === true,
    evidence: Array.isArray(value.evidence)
      ? value.evidence.map((item, i) => readEvidence(item, `${value.control} evidence ${i + 1}`))
      : [],
    missing: strings(value.missing) ? value.missing : [],
    crosswalks,
    cadence: {
      months: typeof cadence.months === 'number' ? cadence.months : null,
      last: str(cadence.last) ? cadence.last : null,
      next_due: str(cadence.next_due) ? cadence.next_due : null,
      overdue: cadence.overdue === true,
    },
    collected_at: str(value.collected_at) ? value.collected_at : '',
    url: str(value.url) ? value.url : '',
  };
}

/** The report read strictly from its JSON; a document that is not one is refused in a sentence. */
export function readConformanceReport(value: unknown): ConformanceReport {
  if (!isRecord(value)) throw new Error('a conformance report is a mapping');
  if (!str(value.standard) || !str(value.standard_name) || !str(value.version) || !str(value.assessed_at)) {
    throw new Error('a conformance report names its standard, its version and when it was assessed');
  }
  if (!Array.isArray(value.controls)) throw new Error('a conformance report lists its controls');
  if (!str(value.disclaimer) || !value.disclaimer) {
    throw new Error('a conformance report carries the disclaimer: the Shield evidences, it does not certify');
  }
  const controls = value.controls.map(readControl);
  const by_status = Object.fromEntries(STATUSES.map(s => [s, 0])) as Record<ControlStatus, number>;
  for (const control of controls) by_status[control.status] += 1;
  if (isRecord(value.by_status)) {
    for (const status of STATUSES) {
      const given = value.by_status[status];
      if (typeof given === 'number' && given !== by_status[status]) {
        throw new Error(`the report counts ${given} '${status}' controls and lists ${by_status[status]}`);
      }
    }
  }
  return {
    standard: value.standard,
    standard_name: value.standard_name,
    version: value.version,
    assessed_at: value.assessed_at,
    version_notice: strOrNull(value.version_notice) ? value.version_notice : null,
    by_status,
    gaps: strings(value.gaps) ? value.gaps : controls.filter(c => c.gap).map(c => c.control),
    controls,
    disclaimer: value.disclaimer,
  };
}

/** The controls of a report, status by status, in the order a report lists them. */
export function controlsByStatus(report: ConformanceReport): [ControlStatus, ReportControl[]][] {
  return STATUSES.map(status => [status, report.controls.filter(c => c.status === status)]);
}

const day = (value: string | null): string => (value ? value.slice(0, 10) : '—');

function cadenceWords(cadence: ReportCadence): string {
  if (cadence.months === null) return 'no cadence';
  const every = cadence.months === 12 ? 'yearly' : cadence.months === 3 ? 'quarterly' : `every ${cadence.months} months`;
  const next = cadence.next_due ? `next due ${day(cadence.next_due)}${cadence.overdue ? ' (overdue)' : ''}` : 'never run';
  return `${every}; last ${day(cadence.last)}; ${next}`;
}

/** The report as Markdown: the first page, the summary, the gaps, every control with its evidence. */
export function renderReportMarkdown(report: ConformanceReport): string {
  const out: string[] = [];
  out.push(`# ${report.standard_name} conformance report`);
  out.push('');
  out.push(`Standard ${report.standard} version ${report.version}, assessed ${day(report.assessed_at)}.`);
  if (report.version_notice) {
    out.push('');
    out.push(`> ${report.version_notice}`);
  }
  out.push('');
  out.push(`> ${report.disclaimer}`);
  out.push('');
  out.push('## Summary');
  out.push('');
  out.push('| Status | Controls |');
  out.push('|---|---|');
  for (const status of STATUSES) out.push(`| ${STATUS_WORDS[status]} | ${report.by_status[status]} |`);
  out.push('');
  out.push('## Gaps');
  out.push('');
  if (report.gaps.length === 0) {
    out.push('No mandatory control is short of evidence.');
  } else {
    for (const id of report.gaps) {
      const control = report.controls.find(c => c.control === id);
      out.push(`- **${id}** ${control ? `${control.title} — ${control.status_words}` : ''}`.trimEnd());
    }
  }
  for (const [status, controls] of controlsByStatus(report)) {
    if (controls.length === 0) continue;
    out.push('');
    const words = STATUS_WORDS[status];
    out.push(`## ${words.charAt(0).toUpperCase()}${words.slice(1)}`);
    for (const control of controls) {
      out.push('');
      out.push(`### ${control.control} ${control.title}`);
      out.push('');
      out.push(
        `${control.domain}; ${control.mandatory ? 'mandatory' : 'optional'}${control.retired ? '; retired' : ''}; ${cadenceWords(control.cadence)}.`,
      );
      if (control.reason) {
        out.push('');
        out.push(control.reason);
      }
      if (control.evidence.length > 0) {
        out.push('');
        out.push('Evidence:');
        for (const item of control.evidence) {
          const link = item.link ? ` ([link](${item.link}))` : '';
          const which = item.item ? ` (${item.item})` : '';
          out.push(`- ${item.kind}${which}: ${item.what}, ${day(item.collected_at)}${link}`);
        }
      }
      if (control.missing.length > 0) {
        out.push('');
        out.push('Missing:');
        for (const what of control.missing) out.push(`- ${what}`);
      }
      const walks = Object.entries(control.crosswalks).filter(([, refs]) => refs.length > 0);
      if (walks.length > 0) {
        out.push('');
        out.push(`Crosswalk: ${walks.map(([name, refs]) => `${name} ${refs.join(', ')}`).join('; ')}.`);
      }
    }
  }
  out.push('');
  return out.join('\n');
}

const escape = (value: string): string =>
  value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

/** The report as one HTML document, with no script and no style of its own beyond a class per status. */
export function renderReportHtml(report: ConformanceReport): string {
  const out: string[] = [];
  out.push('<!doctype html>');
  out.push('<html lang="en"><head><meta charset="utf-8">');
  out.push(`<title>${escape(report.standard_name)} conformance report</title>`);
  out.push('</head><body class="shield-report">');
  out.push(`<h1>${escape(report.standard_name)} conformance report</h1>`);
  out.push(
    `<p>Standard ${escape(report.standard)} version ${escape(report.version)}, assessed ${escape(day(report.assessed_at))}.</p>`,
  );
  if (report.version_notice) out.push(`<p class="notice">${escape(report.version_notice)}</p>`);
  out.push(`<blockquote class="disclaimer">${escape(report.disclaimer)}</blockquote>`);
  out.push('<h2>Summary</h2><table class="summary"><thead><tr><th>Status</th><th>Controls</th></tr></thead><tbody>');
  for (const status of STATUSES) {
    out.push(`<tr class="${status}"><td>${escape(STATUS_WORDS[status])}</td><td>${report.by_status[status]}</td></tr>`);
  }
  out.push('</tbody></table>');
  out.push('<h2>Gaps</h2>');
  if (report.gaps.length === 0) {
    out.push('<p>No mandatory control is short of evidence.</p>');
  } else {
    out.push('<ul class="gaps">');
    for (const id of report.gaps) {
      const control = report.controls.find(c => c.control === id);
      out.push(
        `<li><strong>${escape(id)}</strong>${control ? ` ${escape(control.title)} — ${escape(control.status_words)}` : ''}</li>`,
      );
    }
    out.push('</ul>');
  }
  for (const [status, controls] of controlsByStatus(report)) {
    if (controls.length === 0) continue;
    out.push(`<section class="status ${status}"><h2>${escape(STATUS_WORDS[status])}</h2>`);
    for (const control of controls) {
      out.push(`<article class="control" id="${escape(control.control)}">`);
      out.push(`<h3>${escape(control.control)} ${escape(control.title)}</h3>`);
      out.push(
        `<p class="facts">${escape(control.domain)}; ${control.mandatory ? 'mandatory' : 'optional'}${control.retired ? '; retired' : ''}; ${escape(cadenceWords(control.cadence))}.</p>`,
      );
      if (control.reason) out.push(`<p class="reason">${escape(control.reason)}</p>`);
      if (control.evidence.length > 0) {
        out.push('<ul class="evidence">');
        for (const item of control.evidence) {
          const which = item.item ? ` (${escape(item.item)})` : '';
          const what = item.link
            ? `<a href="${escape(item.link)}">${escape(item.what)}</a>`
            : escape(item.what);
          out.push(`<li>${escape(item.kind)}${which}: ${what}, ${escape(day(item.collected_at))}</li>`);
        }
        out.push('</ul>');
      }
      if (control.missing.length > 0) {
        out.push('<ul class="missing">');
        for (const what of control.missing) out.push(`<li>${escape(what)}</li>`);
        out.push('</ul>');
      }
      const walks = Object.entries(control.crosswalks).filter(([, refs]) => refs.length > 0);
      if (walks.length > 0) {
        out.push(
          `<p class="crosswalk">Crosswalk: ${walks.map(([name, refs]) => `${escape(name)} ${escape(refs.join(', '))}`).join('; ')}.</p>`,
        );
      }
      out.push('</article>');
    }
    out.push('</section>');
  }
  out.push('</body></html>');
  return out.join('\n');
}
