#!/usr/bin/env node
// Advisory date-literal check (#2001, D1159). Warns on a quoted future date
// that a change adds under src/: once the real clock reaches it, a fixture or
// default keyed to it fails (#1968, #1976). It reads only the lines the change
// adds, against the merge base with the base ref, and always exits 0.
//
// Skipped: dates already past, malformed dates, files under src/config/
// (declared policy), and lines marked `date-literal: controlled-clock` or
// `date-literal: policy`, on the line itself or the line before it.
//
// Usage: node scripts/check-date-literals.mjs [base-ref]
//   base-ref defaults to origin/$GITHUB_BASE_REF in a pull request, else origin/main.

import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
/** A quoted date, with an optional time and zone; the quote closes right after it. */
const DATE = /(["'`])(\d{4})-(\d{2})-(\d{2})(?:T(\d{2}):(\d{2})(?::(\d{2})(?:\.\d+)?)?(Z|[+-]\d{2}:\d{2})?)?\1/g;
const MARKER = /date-literal:\s*(controlled-clock|policy)\b/;
const POLICY_DIR = "src/config/";

/** The instant a matched literal names, or undefined when it names no real date. */
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
  const sign = zone[0] === "+" ? 1 : -1;
  const [zh, zm] = zone.slice(1).split(":").map(Number);
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

/** The lines a `git diff --unified=0` output adds, by file and new line number. */
export function addedLines(diff) {
  const out = [];
  let file;
  let next = 0;
  for (const raw of diff.split("\n")) {
    if (raw.startsWith("+++ ")) {
      file = raw === "+++ /dev/null" ? undefined : raw.replace(/^\+\+\+ b\//, "");
      continue;
    }
    const hunk = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/.exec(raw);
    if (hunk) {
      next = Number(hunk[1]);
      continue;
    }
    if (file && raw.startsWith("+")) out.push({ file, line: next++ });
  }
  return out;
}

/**
 * The findings for added lines: each `{ file, line, text, previous }` entry's
 * unmarked future dates, outside `src/config/`.
 */
export function findings(entries, nowMs) {
  const out = [];
  for (const e of entries) {
    if (e.file.startsWith(POLICY_DIR) || isMarked(e.text, e.previous)) continue;
    for (const value of futureDates(e.text, nowMs)) out.push({ file: e.file, line: e.line, value });
  }
  return out;
}

function git(args) {
  const r = spawnSync("git", args, { cwd: ROOT, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
  return r.status === 0 ? r.stdout : undefined;
}

function main() {
  const base = process.argv[2] ?? (process.env.GITHUB_BASE_REF ? `origin/${process.env.GITHUB_BASE_REF}` : "origin/main");
  const mergeBase = git(["merge-base", base, "HEAD"])?.trim();
  if (!mergeBase) {
    console.log(`date-literal check skipped: no merge base with ${base}.`);
    return;
  }
  // The merge base against the working tree: committed, staged and unstaged
  // changes; untracked files under src/ count as wholly added.
  const diff = git(["diff", "--unified=0", "--no-color", "--no-ext-diff", mergeBase, "--", "src"]) ?? "";
  const added = addedLines(diff);
  for (const f of (git(["ls-files", "--others", "--exclude-standard", "--", "src"]) ?? "").split("\n").filter(Boolean)) {
    const count = fs.readFileSync(path.join(ROOT, f), "utf8").split("\n").length;
    for (let line = 1; line <= count; line++) added.push({ file: f, line });
  }
  const cache = new Map();
  const linesOf = (file) => {
    if (!cache.has(file)) cache.set(file, fs.existsSync(path.join(ROOT, file)) ? fs.readFileSync(path.join(ROOT, file), "utf8").split("\n") : []);
    return cache.get(file);
  };
  const entries = added
    .filter((a) => /\.(m?[jt]s|tsx?|json)$/.test(a.file))
    .map((a) => ({ ...a, text: linesOf(a.file)[a.line - 1] ?? "", previous: linesOf(a.file)[a.line - 2] ?? "" }));
  const found = findings(entries, Date.now());
  for (const f of found) {
    console.log(
      `::warning file=${f.file},line=${f.line}::${f.value} is a fixed future date: once the real clock reaches it, the code keyed to it fails (#1968). ` +
        "Derive it from the clock, or mark a deliberate one `// date-literal: controlled-clock` or `// date-literal: policy`.",
    );
  }
  console.log(`date-literal check (advisory): ${found.length} new fixed future date(s) in ${entries.length} added line(s) under src/ since ${base}.`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
