#!/usr/bin/env node
// Tests for scripts/check-date-literals.mjs (#2001).
// Usage: node scripts/test-check-date-literals.mjs

import assert from "node:assert/strict";
import { test } from "node:test";

import { addedLines, findings, futureDates, isMarked } from "./check-date-literals.mjs";

const NOW = Date.parse("2026-11-02T12:00:00Z");
const entry = (text, extra = {}) => ({ file: "src/services/x/test/a.test.ts", line: 7, text, previous: "", ...extra });

test("an unmarked future date on an added line is reported, in every quoting and form", () => {
  for (const [text, value] of [
    ['expires_at: "2027-01-01T00:00:00Z",', "2027-01-01T00:00:00Z"],
    ["expires_at: '2027-06-01T00:00:00Z',", "2027-06-01T00:00:00Z"],
    ["const at = `2030-01-01T00:00:00Z`;", "2030-01-01T00:00:00Z"],
    ['not_after: "2027-12-31",', "2027-12-31"],
    ['ttl: "2027-01-01T00:00:00.000Z",', "2027-01-01T00:00:00.000Z"],
    ['body: \'{"expires_at":"2027-01-01T00:00:00Z"}\',', "2027-01-01T00:00:00Z"],
  ]) {
    assert.deepEqual(findings([entry(text)], NOW), [{ file: "src/services/x/test/a.test.ts", line: 7, value }], text);
  }
});

test("a zone offset is honored: the same wall time is past or future by its offset", () => {
  assert.deepEqual(futureDates('"2026-11-02T13:30:00+02:00"', NOW), []);
  assert.deepEqual(futureDates('"2026-11-02T11:30:00-02:00"', NOW), ["2026-11-02T11:30:00-02:00"]);
});

test("a marker on the line, or on the line before, is an explicit exception", () => {
  for (const marker of ["// date-literal: controlled-clock", "// date-literal: policy"]) {
    assert.equal(isMarked(`expires_at: "2027-01-01T00:00:00Z", ${marker}`), true, marker);
    assert.deepEqual(findings([entry('expires_at: "2027-01-01T00:00:00Z",', { previous: `  ${marker}` })], NOW), [], marker);
  }
  assert.equal(isMarked('expires_at: "2027-01-01T00:00:00Z", // date-literal: later'), false);
});

test("past dates, malformed dates and other strings are not reported", () => {
  for (const text of [
    'created_at: "2026-07-01T00:00:00Z",',
    'value: "2026-13-01T00:00:00Z",',
    'value: "2027-02-30T00:00:00Z",',
    'value: "2027-01-01T25:00:00Z",',
    'version: "2026-10-27",',
    'id: "msn_2027-01-01",',
    "const n = 20270101;",
  ]) {
    assert.deepEqual(findings([entry(text)], NOW), [], text);
  }
});

test("files under src/config/ hold declared policy dates and are not reported", () => {
  assert.deepEqual(findings([entry('"retained_until": "2027-10-27T00:00:00Z",', { file: "src/config/enforcement-scope.json" })], NOW), []);
  assert.equal(findings([entry('"retained_until": "2027-10-27T00:00:00Z",', { file: "src/demo/src/stack.ts" })], NOW).length, 1);
});

test("only the lines a diff adds are read: removed and unchanged lines are not", () => {
  const diff = [
    "diff --git a/src/a.test.ts b/src/a.test.ts",
    "--- a/src/a.test.ts",
    "+++ b/src/a.test.ts",
    "@@ -10,2 +10,3 @@ describe",
    '-  expires_at: "2027-01-01T00:00:00Z",',
    '+  expires_at: FIXTURE_EXPIRES_AT,',
    '+  approvedUntil: "2027-01-01T00:00:00Z",',
    "+  const x = 1;",
    "@@ -40 +41,0 @@",
    "-  removed",
    "diff --git a/src/gone.ts b/src/gone.ts",
    "--- a/src/gone.ts",
    "+++ /dev/null",
    "@@ -1 +0,0 @@",
    '-  expires_at: "2027-01-01T00:00:00Z",',
    "diff --git a/src/new.ts b/src/new.ts",
    "--- /dev/null",
    "+++ b/src/new.ts",
    "@@ -0,0 +1 @@",
    '+export const AT = "2028-01-01T00:00:00Z";',
  ].join("\n");
  assert.deepEqual(addedLines(diff), [
    { file: "src/a.test.ts", line: 10 },
    { file: "src/a.test.ts", line: 11 },
    { file: "src/a.test.ts", line: 12 },
    { file: "src/new.ts", line: 1 },
  ]);
});
