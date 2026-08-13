#!/usr/bin/env node
// Validates conformance-manifest.json (#245): the traceability record mapping
// normative clauses to observable conformance assertions and tests.
// Dependency-free (Node core only).
//
// Usage: node scripts/check-conformance-manifest.mjs [--collect]
//
// Exits 1 with a message per finding on any of:
//   (a) schema violation      - missing/invalid fields, unknown enum values
//   (b) duplicate ID          - two requirement rows share an id
//   (c) unknown anchor        - the named draft has no {#anchor}
//   (d) stale requirement     - the row's quoted clause text no longer appears
//                               (whitespace-normalized) in the named draft;
//                               an edited clause forces a manifest re-review
//   (e) missing test          - a named test file does not exist, or the test
//                               name string does not appear in it
//
// With --collect, additionally runs `pnpm -C src exec vitest list` and fails
// for any named test the runner does not collect (guards against renamed or
// skipped tests that still match by string).
//
// Rows with an empty tests[] (or a blocked_by) are the reverse-mapping TODO
// report: printed, never failing. Completeness is judged by that report, not
// by every test having a tag.

import fs from "node:fs";
import path from "node:path";
import { execSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..");
const MANIFEST_PATH = path.join(ROOT, "conformance-manifest.json");

const errors = [];
const fail = (check, msg) => errors.push(`[${check}] ${msg}`);
const normalize = (s) => s.replace(/\s+/g, " ").trim();

function readFile(p, label) {
  try {
    return fs.readFileSync(p, "utf8");
  } catch (e) {
    console.error(`Cannot read ${label} at ${p}: ${e.message}`);
    process.exit(1);
  }
}

const manifest = JSON.parse(readFile(MANIFEST_PATH, "conformance-manifest.json"));
const model = manifest.model ?? {};
const rows = manifest.requirements ?? [];

const REQUIRED_FIELDS = [
  "id", "spec", "anchor", "text", "role", "strength", "applicability",
  "surface", "assertion", "observation", "level", "tests",
];

const draftCache = new Map();
function draftContent(file) {
  if (!draftCache.has(file)) {
    const p = path.join(ROOT, file);
    if (!fs.existsSync(p)) return null;
    const raw = fs.readFileSync(p, "utf8");
    draftCache.set(file, { raw, normalized: normalize(raw) });
  }
  return draftCache.get(file);
}

const seenIds = new Set();
const todo = [];

for (const row of rows) {
  const id = row.id ?? "<missing id>";

  for (const f of REQUIRED_FIELDS) {
    if (row[f] === undefined) fail("schema", `${id}: missing field "${f}"`);
  }
  if (seenIds.has(id)) fail("duplicate-id", `${id} appears more than once`);
  seenIds.add(id);

  const enums = [
    ["role", model.roles],
    ["strength", model.strengths],
    ["assertion", model.assertions],
    ["surface", model.surfaces],
    ["level", model.levels],
  ];
  for (const [field, allowed] of enums) {
    if (Array.isArray(allowed) && row[field] !== undefined && !allowed.includes(row[field])) {
      fail("schema", `${id}: ${field} "${row[field]}" not in model.${field === "role" ? "roles" : field + "s"}`);
    }
  }
  if (row.observation && typeof row.observation.normative !== "string") {
    fail("schema", `${id}: observation.normative is required`);
  }

  const draft = row.spec ? draftContent(row.spec) : null;
  if (row.spec && !draft) {
    fail("unknown-anchor", `${id}: spec file ${row.spec} not found`);
  } else if (draft) {
    if (row.anchor && !draft.raw.includes(`{#${row.anchor}}`)) {
      fail("unknown-anchor", `${id}: ${row.spec} has no {#${row.anchor}}`);
    }
    if (row.text && !draft.normalized.includes(normalize(row.text))) {
      fail(
        "stale-requirement",
        `${id}: quoted clause not found in ${row.spec}; the clause changed or the row is wrong, re-review the requirement`
      );
    }
  }

  for (const entry of row.tests ?? []) {
    const [file, name] = entry.split(" :: ");
    if (!file || !name) {
      fail("missing-test", `${id}: test entry "${entry}" is not "path :: test name"`);
      continue;
    }
    const p = path.join(ROOT, file);
    if (!fs.existsSync(p)) {
      fail("missing-test", `${id}: test file ${file} not found`);
    } else if (!fs.readFileSync(p, "utf8").includes(name)) {
      fail("missing-test", `${id}: test name "${name}" not found in ${file}`);
    }
  }

  if ((row.tests ?? []).length === 0 || row.blocked_by) {
    todo.push(row);
  }
}

if (process.argv.includes("--collect")) {
  let listing = "";
  try {
    listing = execSync("pnpm -C src exec vitest list", {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      timeout: 300000,
    });
  } catch (e) {
    fail("collect", `vitest list failed: ${e.message}`);
  }
  if (listing) {
    for (const row of rows) {
      for (const entry of row.tests ?? []) {
        const name = entry.split(" :: ")[1];
        if (name && !listing.includes(name)) {
          fail("collect", `${row.id}: test "${name}" not collected by the runner`);
        }
      }
    }
  }
}

if (todo.length) {
  console.log(`TODO (${todo.length} requirement${todo.length === 1 ? "" : "s"} without adequate tests):`);
  for (const row of todo) {
    const blocked = row.blocked_by ? ` [blocked by ${row.blocked_by}]` : "";
    console.log(`  - ${row.id}${blocked}: ${row.observation?.normative ?? ""}`);
  }
}

if (errors.length) {
  for (const e of errors) console.error(e);
  console.error(`conformance-manifest check FAILED: ${errors.length} finding(s).`);
  process.exit(1);
}
console.log(
  `conformance-manifest check OK: ${rows.length} requirements, ` +
  `${rows.length - todo.length} tested, ${todo.length} TODO.`
);
