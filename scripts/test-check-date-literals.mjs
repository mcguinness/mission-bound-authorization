#!/usr/bin/env node
// Tests for scripts/check-date-literals.mjs (#2001, D1241).
// Usage: node scripts/test-check-date-literals.mjs

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

import { addedLineNumbers, findings, futureDates, inScope, isMarked, parseNameStatus } from "./check-date-literals.mjs";

const SCRIPT = path.join(path.dirname(fileURLToPath(import.meta.url)), "check-date-literals.mjs");
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

test("a zone offset is honored, and a malformed one names no date", () => {
  assert.deepEqual(futureDates('"2026-11-02T13:30:00+02:00"', NOW), []);
  assert.deepEqual(futureDates('"2026-11-02T11:30:00-02:00"', NOW), ["2026-11-02T11:30:00-02:00"]);
  assert.deepEqual(futureDates('"2027-01-01T00:00:00+23:59"', NOW), ["2027-01-01T00:00:00+23:59"]);
  for (const bad of ["+25:00", "+24:00", "+01:99", "-00:60"]) {
    assert.deepEqual(futureDates(`"2027-01-01T00:00:00${bad}"`, NOW), [], bad);
  }
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

test("the check reads only scanned kinds of file outside src/config/", () => {
  assert.equal(inScope("src/config/enforcement-scope.json"), false);
  assert.equal(inScope("src/demo/src/stack.ts"), true);
  assert.equal(inScope("src/x/blob.bin"), false);
  assert.deepEqual(findings([entry('"retained_until": "2027-10-27T00:00:00Z",', { file: "src/config/enforcement-scope.json" })], NOW), []);
});

test("one file's diff yields only its added line numbers, whatever its headers say", () => {
  const diff = [
    'diff --git "a/src/caf\\303\\251.ts" "b/src/caf\\303\\251.ts"',
    '--- "a/src/caf\\303\\251.ts"',
    '+++ "b/src/caf\\303\\251.ts"',
    "@@ -10,2 +10,3 @@ describe",
    '-  expires_at: "2027-01-01T00:00:00Z",',
    "+  expires_at: FIXTURE_EXPIRES_AT,",
    "+++ a line whose text starts with plus signs",
    "+  const x = 1;",
    "@@ -40 +41,0 @@",
    "-  removed",
  ].join("\n");
  assert.deepEqual(addedLineNumbers(diff), [10, 11, 12]);
});

test("NUL-delimited name status keeps every path verbatim, renames with their source", () => {
  const z = ["M", "src/café.ts", "R100", "src/old name.ts", "src/new\tname.ts", "A", "src/a\nb.ts", ""].join("\0");
  assert.deepEqual(parseNameStatus(z), [
    { status: "M", path: "src/café.ts" },
    { status: "R", from: "src/old name.ts", path: "src/new\tname.ts" },
    { status: "A", path: "src/a\nb.ts" },
  ]);
});

/** A repository with a base commit under src/, and the checker run inside it against that base. */
function repository(baseFiles = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "date-literals-"));
  const git = (...args) => {
    const r = spawnSync("git", ["-c", "user.email=t@example.test", "-c", "user.name=t", "-c", "commit.gpgsign=false", ...args], { cwd: dir, encoding: "utf8" });
    assert.equal(r.status, 0, `git ${args.join(" ")}: ${r.stderr}`);
    return r.stdout;
  };
  git("init", "-q");
  fs.mkdirSync(path.join(dir, "src"), { recursive: true });
  fs.writeFileSync(path.join(dir, "src", "base.ts"), "export const x = 1;\n");
  for (const [name, text] of Object.entries(baseFiles)) fs.writeFileSync(path.join(dir, "src", name), text);
  git("add", "-A");
  git("commit", "-q", "-m", "base");
  const base = git("rev-parse", "HEAD").trim();
  const run = () => spawnSync(process.execPath, [SCRIPT, base], { cwd: dir, encoding: "utf8" });
  return { dir, git, run, write: (name, text) => fs.writeFileSync(path.join(dir, "src", name), text) };
}

const FUTURE = 'export const AT = "2099-01-01T00:00:00Z";\n';

test("command line: a committed file with a non-ASCII name is read, and its future date reported", () => {
  const r = repository();
  r.write("café.test.ts", FUTURE);
  r.git("add", "-A");
  r.git("commit", "-q", "-m", "add");
  const out = r.run();
  assert.equal(out.status, 0, out.stderr);
  assert.match(out.stdout, /::warning file=src\/café\.test\.ts,line=1::2099-01-01T00:00:00Z/);
  assert.match(out.stdout, /complete\): 1 new fixed future date/);
});

test("command line: an untracked file with a non-ASCII name is read, and its future date reported", () => {
  const r = repository();
  r.write("naïve.test.ts", FUTURE);
  const out = r.run();
  assert.equal(out.status, 0, out.stderr);
  assert.match(out.stdout, /::warning file=src\/naïve\.test\.ts,line=1::2099-01-01T00:00:00Z/);
});

test("command line: a renamed file's unchanged lines are not added", () => {
  const r = repository({ "old name.ts": FUTURE });
  r.git("mv", "src/old name.ts", "src/new name.ts");
  r.git("commit", "-q", "-m", "move");
  const out = r.run();
  assert.equal(out.status, 0, out.stderr);
  assert.doesNotMatch(out.stdout, /::warning/);
  assert.match(out.stdout, /complete\): 0 new fixed future date/);
});

test("command line: an excluded dangling symlink is never read; one in scope leaves the scan incomplete, not crashed", () => {
  const r = repository();
  fs.symlinkSync("missing-target", path.join(r.dir, "src", "blob.bin"));
  let out = r.run();
  assert.equal(out.status, 0, out.stderr);
  assert.doesNotMatch(out.stdout, /blob\.bin/);
  assert.match(out.stdout, /complete\): 0 new/);
  fs.symlinkSync("missing-target", path.join(r.dir, "src", "dangling.ts"));
  out = r.run();
  assert.equal(out.status, 0, out.stderr);
  assert.match(out.stdout, /::warning file=src\/dangling\.ts::date-literal check incomplete: src\/dangling\.ts was not scanned, a symbolic link/);
  assert.match(out.stdout, /INCOMPLETE, 1 file\(s\) not scanned/);
});

test("command line: an unreadable file leaves the scan incomplete, never a clean scan", { skip: process.getuid?.() === 0 }, () => {
  const r = repository();
  r.write("locked.test.ts", FUTURE);
  fs.chmodSync(path.join(r.dir, "src", "locked.test.ts"), 0o000);
  try {
    const out = r.run();
    assert.equal(out.status, 0, out.stderr);
    assert.match(out.stdout, /src\/locked\.test\.ts was not scanned, unreadable/);
    assert.match(out.stdout, /INCOMPLETE, 1 file\(s\) not scanned/);
  } finally {
    fs.chmodSync(path.join(r.dir, "src", "locked.test.ts"), 0o644);
  }
});
