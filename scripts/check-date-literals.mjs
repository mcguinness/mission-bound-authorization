#!/usr/bin/env node
// Advisory date-literal check (#2001, D1159, D1241). Warns on a quoted future
// date that a change adds under src/: once the real clock reaches it, a fixture
// or default keyed to it fails (#1968, #1976). It reads only the lines the
// change adds, against the merge base with the base ref, and always exits 0.
//
// Skipped: dates already past, malformed dates and offsets, files outside the
// scanned kinds or under src/config/ (declared policy), never read at all, and
// lines marked `date-literal: controlled-clock` or `date-literal: policy`, on
// the line itself or the line before it. A file in scope that is not a regular
// file, or cannot be read, leaves the scan incomplete, and the summary says so.
//
// Paths come from Git NUL-delimited, so no quoted path is ever parsed.
//
// Usage: node scripts/check-date-literals.mjs [base-ref]
//   Run inside the repository. base-ref defaults to origin/$GITHUB_BASE_REF in
//   a pull request, else origin/main.

import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const SCRIPT_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
/** A quoted date, with an optional time and zone; the quote closes right after it. */
const DATE = /(["'`])(\d{4})-(\d{2})-(\d{2})(?:T(\d{2}):(\d{2})(?::(\d{2})(?:\.\d+)?)?(Z|[+-]\d{2}:\d{2})?)?\1/g;
const MARKER = /date-literal:\s*(controlled-clock|policy)\b/;
const POLICY_DIR = "src/config/";
const SCANNED = /\.(m?[jt]s|tsx?|json)$/;

/** The instant a matched literal names, or undefined when it names no real date or offset. */
function instantOf(m) {
  const [, , y, mo, d, h = "00", mi = "00", s = "00", zone] = m;
  const fields = [y, mo, d, h, mi, s].map(Number);
  const utc = Date.UTC(fields[0], fields[1] - 1, fields[2], fields[3], fields[4], fields[5]);
  const back = new Date(utc);
  if (
    back.getUTCFullYear() !== fields[0] || back.getUTCMonth() !== fields[1] - 1 || back.getUTCDate() !== fields[2] ||
    back.getUTCHours() !== fields[3] || back.getUTCMinutes() !== fields[4] || back.getUTCSeconds() !== fields[5]
  ) {
    return undefined;
  }
  if (!zone || zone === "Z") return utc;
  const [zh, zm] = zone.slice(1).split(":").map(Number);
  // RFC 3339 offsets: hours 00 to 23, minutes 00 to 59.
  if (zh > 23 || zm > 59) return undefined;
  const sign = zone[0] === "+" ? 1 : -1;
  return utc - sign * (zh * 60 + zm) * 60_000;
}

/** The quoted literals in `text` naming a real date later than `nowMs`. */
export function futureDates(text, nowMs) {
  const out = [];
  for (const m of text.matchAll(DATE)) {
    const at = instantOf(m);
    if (at !== undefined && at > nowMs) out.push(m[0].slice(1, -1));
  }
  return out;
}

/** Whether a line, or the line before it, carries an explicit exception marker. */
export function isMarked(line, previous = "") {
  return MARKER.test(line) || MARKER.test(previous);
}

/** Whether the check reads a path at all: a scanned kind of file, outside src/config/. */
export function inScope(file) {
  return SCANNED.test(file) && !file.startsWith(POLICY_DIR);
}

/**
 * The new line numbers one file's `git diff --unified=0` output adds. Only
 * hunk bodies are read, so no header, quoted or not, is parsed.
 */
export function addedLineNumbers(diff) {
  const out = [];
  let next = 0;
  let inHunk = false;
  for (const raw of diff.split("\n")) {
    const hunk = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/.exec(raw);
    if (hunk) {
      next = Number(hunk[1]);
      inHunk = true;
      continue;
    }
    if (inHunk && raw.startsWith("+")) out.push(next++);
  }
  return out;
}

/** `git diff -z --name-status` output: each changed path, with the path it was renamed from. */
export function parseNameStatus(z) {
  const parts = z.split("\0");
  const out = [];
  for (let i = 0; i < parts.length && parts[i]; ) {
    const status = parts[i];
    if (status.startsWith("R") || status.startsWith("C")) {
      out.push({ status: status[0], from: parts[i + 1], path: parts[i + 2] });
      i += 3;
    } else {
      out.push({ status: status[0], path: parts[i + 1] });
      i += 2;
    }
  }
  return out;
}

/**
 * The findings for added lines: each `{ file, line, text, previous }` entry's
 * unmarked future dates, in files the check reads.
 */
export function findings(entries, nowMs) {
  const out = [];
  for (const e of entries) {
    if (!inScope(e.file) || isMarked(e.text, e.previous)) continue;
    for (const value of futureDates(e.text, nowMs)) out.push({ file: e.file, line: e.line, value });
  }
  return out;
}

function git(root, args) {
  const r = spawnSync("git", args, {
    cwd: root,
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
    env: { ...process.env, GIT_LITERAL_PATHSPECS: "1" },
  });
  return r.status === 0 ? r.stdout : undefined;
}

/** A file's lines, or the reason it is not scanned: not a regular file, or unreadable. */
function readLines(root, file) {
  const full = path.join(root, file);
  try {
    const st = fs.lstatSync(full);
    if (!st.isFile()) return { reason: st.isSymbolicLink() ? "a symbolic link, not a regular file" : "not a regular file" };
    return { lines: fs.readFileSync(full, "utf8").split("\n") };
  } catch (e) {
    return { reason: `unreadable (${e.code ?? e.message})` };
  }
}

function main() {
  const root = spawnSync("git", ["rev-parse", "--show-toplevel"], { encoding: "utf8" }).stdout?.trim() || SCRIPT_ROOT;
  const base = process.argv[2] ?? (process.env.GITHUB_BASE_REF ? `origin/${process.env.GITHUB_BASE_REF}` : "origin/main");
  const mergeBase = git(root, ["merge-base", base, "HEAD"])?.trim();
  if (!mergeBase) {
    console.log(`date-literal check skipped: no merge base with ${base}.`);
    return;
  }
  // The merge base against the working tree: committed, staged and unstaged
  // changes, renames paired so a moved file's unchanged lines are not added;
  // untracked files under src/ count as wholly added.
  const changed = parseNameStatus(git(root, ["diff", "-z", "--name-status", "-M", "--diff-filter=ACMR", mergeBase, "--", "src"]) ?? "");
  const untracked = (git(root, ["ls-files", "-z", "--others", "--exclude-standard", "--", "src"]) ?? "").split("\0").filter(Boolean);
  const entries = [];
  const incomplete = [];
  const scan = (file, lineNumbers) => {
    const read = readLines(root, file);
    if (!read.lines) {
      incomplete.push({ file, reason: read.reason });
      return;
    }
    for (const line of lineNumbers(read.lines)) {
      entries.push({ file, line, text: read.lines[line - 1] ?? "", previous: read.lines[line - 2] ?? "" });
    }
  };
  for (const c of changed) {
    if (!inScope(c.path)) continue;
    const paths = c.from ? [c.from, c.path] : [c.path];
    const diff = git(root, ["diff", "--unified=0", "--no-color", "--no-ext-diff", "-M", mergeBase, "--", ...paths]);
    if (diff === undefined) {
      incomplete.push({ file: c.path, reason: "its diff could not be read" });
      continue;
    }
    const numbers = addedLineNumbers(diff);
    if (numbers.length > 0) scan(c.path, () => numbers);
  }
  for (const file of untracked) {
    if (inScope(file)) scan(file, (lines) => lines.map((_, i) => i + 1));
  }
  const found = findings(entries, Date.now());
  for (const f of found) {
    console.log(
      `::warning file=${f.file},line=${f.line}::${f.value} is a fixed future date: once the real clock reaches it, the code keyed to it fails (#1968). ` +
        "Derive it from the clock, or mark a deliberate one `// date-literal: controlled-clock` or `// date-literal: policy`.",
    );
  }
  for (const i of incomplete) console.log(`::warning file=${i.file}::date-literal check incomplete: ${i.file} was not scanned, ${i.reason}.`);
  const state = incomplete.length > 0 ? `INCOMPLETE, ${incomplete.length} file(s) not scanned` : "complete";
  console.log(`date-literal check (advisory, ${state}): ${found.length} new fixed future date(s) in ${entries.length} added line(s) under src/ since ${base}.`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch (e) {
    // Advisory: an unexpected failure is reported as an incomplete scan, never a failed build.
    console.log(`::warning::date-literal check incomplete: ${e instanceof Error ? e.message : String(e)}`);
  }
}
