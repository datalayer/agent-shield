/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  STATUSES,
  STATUS_WORDS,
  controlsByStatus,
  readConformanceReport,
  renderReportHtml,
  renderReportMarkdown,
} from '../index.js';

const DISCLAIMER =
  'This report evidences: it collects, for each control of the standard, what Datalayer\'s Shield can show of this deployment. It does not certify.';

const report = {
  standard: 'aiuc-1',
  standard_name: 'AIUC-1',
  version: '2026-Q4',
  assessed_at: '2026-10-15T20:00:00+00:00',
  version_notice: null,
  by_status: { partly: 1, organizations: 1, third_party: 0, met: 1, not_applicable: 0 },
  gaps: ['A006', 'E010'],
  controls: [
    {
      control: 'D003',
      title: 'Restrict unsafe tool calls',
      domain: 'D Reliability',
      status: 'met',
      status_words: 'met by evidence',
      reason: 'The execution policy decides every tool call before it runs.',
      mandatory: true,
      retired: false,
      gap: false,
      evidence: [
        { kind: 'config', what: 'organization policy version 3', collected_at: '2026-10-15T19:00:00+00:00', link: 'https://datalayer.ai/policies/3', item: 'D003.1', detail: { version: 3 } },
        { kind: 'logs', what: '12 refusals in 90 days', collected_at: '2026-10-15T19:00:00+00:00', link: null, item: null, detail: {} },
      ],
      missing: [],
      crosswalks: { 'EU AI Act': ['Art. 9'], 'NIST AI RMF': ['MANAGE 2.2'] },
      cadence: { months: null, last: null, next_due: null, overdue: false },
      collected_at: '2026-10-15T19:00:00+00:00',
      url: 'https://standard.aiuc-1.com/D003',
    },
    {
      control: 'A006',
      title: 'Prevent PII leakage',
      domain: 'A Data & Privacy',
      status: 'partly',
      status_words: 'partly met',
      reason: 'The record is redacted; the model side is not shown.',
      mandatory: true,
      retired: false,
      gap: true,
      evidence: [],
      missing: ['an output filter on the model side'],
      crosswalks: {},
      cadence: { months: 3, last: '2026-07-01', next_due: '2026-10-01', overdue: true },
      collected_at: '2026-10-15T19:00:00+00:00',
      url: '',
    },
    {
      control: 'E010',
      title: 'Acceptable use policy',
      domain: 'E Accountability',
      status: 'organizations',
      status_words: "the organization's",
      reason: 'A document a person writes; none is signed.',
      mandatory: true,
      retired: false,
      gap: true,
      evidence: [],
      missing: ['the signed document'],
      crosswalks: { 'ISO 42001': ['A.2.2'] },
      cadence: { months: 12, last: null, next_due: null, overdue: false },
      collected_at: '2026-10-15T19:00:00+00:00',
      url: '',
    },
  ],
  disclaimer: DISCLAIMER,
};

test('the report reads strictly and keeps its counts', () => {
  const read = readConformanceReport(report);
  assert.equal(read.controls.length, 3);
  assert.deepEqual(read.by_status, { partly: 1, organizations: 1, third_party: 0, met: 1, not_applicable: 0 });
  assert.deepEqual(read.gaps, ['A006', 'E010']);
  assert.deepEqual(
    controlsByStatus(read).map(([status, controls]) => [status, controls.map(control => control.control)]),
    [['partly', ['A006']], ['organizations', ['E010']], ['third_party', []], ['met', ['D003']], ['not_applicable', []]],
  );
  assert.deepEqual([...STATUSES], Object.keys(STATUS_WORDS));
});

test('a document that is not a report is refused in a sentence', () => {
  assert.throws(() => readConformanceReport(null), /is a mapping/);
  assert.throws(() => readConformanceReport({ ...report, disclaimer: '' }), /does not certify/);
  assert.throws(() => readConformanceReport({ ...report, controls: [{ ...report.controls[0], status: 'done' }] }), /not one of the five/);
  assert.throws(() => readConformanceReport({ ...report, by_status: { ...report.by_status, met: 2 } }), /counts 2 'met' controls and lists 1/);
  assert.throws(
    () => readConformanceReport({ ...report, controls: [{ ...report.controls[0], evidence: [{ kind: 'rumour', what: 'x', collected_at: 'y' }] }] }),
    /evidence kind 'rumour'/,
  );
});

test('the Markdown says the disclaimer first, the summary, the gaps, every control', () => {
  const text = renderReportMarkdown(readConformanceReport(report));
  assert.ok(text.startsWith('# AIUC-1 conformance report\n'));
  assert.ok(text.indexOf(DISCLAIMER) < text.indexOf('## Summary'));
  assert.match(text, /\| met by evidence \| 1 \|/);
  assert.match(text, /## Gaps\n\n- \*\*A006\*\* Prevent PII leakage — partly met\n- \*\*E010\*\*/);
  assert.match(text, /### D003 Restrict unsafe tool calls/);
  assert.match(text, /- config \(D003\.1\): organization policy version 3, 2026-10-15 \(\[link\]\(https:\/\/datalayer\.ai\/policies\/3\)\)/);
  assert.match(text, /quarterly; last 2026-07-01; next due 2026-10-01 \(overdue\)/);
  assert.match(text, /Missing:\n- the signed document/);
  assert.match(text, /Crosswalk: EU AI Act Art\. 9; NIST AI RMF MANAGE 2\.2\./);
  // The statuses' sections come in the report's order: what needs attention first.
  assert.ok(text.indexOf('## Partly met') < text.indexOf("## The organization's"));
  assert.ok(text.indexOf("## The organization's") < text.indexOf('## Met by evidence'));
});

test('the HTML is one document, escaped, a class per status', () => {
  const html = renderReportHtml(readConformanceReport({ ...report, version_notice: 'Q4 2026 retired <two> controls' }));
  assert.ok(html.startsWith('<!doctype html>'));
  assert.match(html, /<blockquote class="disclaimer">This report evidences/);
  assert.match(html, /<p class="notice">Q4 2026 retired &lt;two&gt; controls<\/p>/);
  assert.match(html, /<section class="status partly">/);
  assert.match(html, /<article class="control" id="D003">/);
  assert.match(html, /<a href="https:\/\/datalayer\.ai\/policies\/3">organization policy version 3<\/a>/);
  assert.doesNotMatch(html, /<script/);
});
