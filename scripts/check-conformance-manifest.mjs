#!/usr/bin/env node
// Validates conformance-manifest.json (#245): the traceability record mapping
// normative clauses to observable conformance assertions and tests.
// Dependency-free (Node core only).
//
// Usage: node scripts/check-conformance-manifest.mjs [--collect]
//
// Exits 1 with a message per finding on any of:
//   (a) schema violation      - missing/empty/mistyped fields, unknown enum
//                               values, unknown row or mapping members
//   (b) duplicate ID          - two requirement rows share an id
//   (c) unknown anchor        - the named draft has no {#anchor} heading
//   (d) stale requirement     - the row's quoted clause text no longer appears
//                               (whitespace-normalized) INSIDE the anchored
//                               section; an edited or relocated clause forces
//                               a manifest re-review
//   (e) missing test          - a mapped test file does not exist, or the full
//                               test name does not appear in it
//   (f) coverage inconsistency- the declared coverage state contradicts the
//                               mappings (see rules below)
//   (g) spec inventory drift  - source.specs is missing an entry for a spec
//                               referenced by a row, carries an entry for a
//                               spec no row references, or a spec's
//                               content_sha256 no longer matches its
//                               working-tree bytes: the spec changed since
//                               its rows were last audited against the
//                               recorded revision, and the entry needs
//                               deliberate re-review and a bump before this
//                               passes again
//
// source.specs replaces a single global source.revision with one entry per
// spec file named by a row's "spec": { revision, content_sha256 }. revision
// is the commit whose text that spec's rows were validated against;
// content_sha256 is a mechanical gate, recomputed here from the working-tree
// file and compared, proving the file is still byte-identical to the
// audited text. It intentionally does not shell out to git (CI checkouts are
// shallow): the digest is the whole check, not a lookup of what changed.
// Completeness provenance (whether the inventory covers every requirement in
// the spec) lives in the tracking issues, not in this manifest.
//
// Coverage states and their enforced consistency rules:
//   tested  - tests non-empty, and at least one mapping matches the row's
//             level (and surface, for endpoint-level rows). Semantic adequacy
//             is a human judgment; the checker enforces only that the declared
//             state and the mappings are internally consistent.
//   partial - tests non-empty (coverage exists but not at the required level,
//             surface, or breadth; say why in notes or observation.local).
//   todo    - tests empty.
//   blocked - blocked_by present (and only blocked rows carry blocked_by).
//
// Rows not "tested" are the outstanding reverse-mapping report: printed,
// never failing. Completeness is judged by that report, not by tag coverage.
//
// With --collect, additionally runs `pnpm -C src exec vitest list --json` over
// the unique mapped files and fails for any mapping whose (file, full name)
// pair the runner does not collect, so a renamed, relocated, or skipped test
// cannot pass on a string match.

import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { execSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..");
const MANIFEST_PATH = path.join(ROOT, "conformance-manifest.json");

const errors = [];
const fail = (check, msg) => errors.push(`[${check}] ${msg}`);
const normalize = (s) => s.replace(/\s+/g, " ").trim();
const nonEmptyString = (v) => typeof v === "string" && v.trim().length > 0;

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

// ---- model and source validation ------------------------------------------

const MODEL_LISTS = ["roles", "strengths", "assertions", "surfaces", "levels", "capabilities"];
for (const list of MODEL_LISTS) {
  if (!Array.isArray(model[list]) || model[list].length === 0 || !model[list].every(nonEmptyString)) {
    fail("schema", `model.${list} must be a non-empty array of non-empty strings`);
  }
}
const HEX40 = /^[0-9a-f]{40}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const SOURCE_SPEC_MEMBERS = new Set(["revision", "content_sha256"]);

if (!manifest.source || typeof manifest.source !== "object" || Array.isArray(manifest.source) ||
    !manifest.source.specs || typeof manifest.source.specs !== "object" || Array.isArray(manifest.source.specs)) {
  fail("schema", "manifest.source.specs (a per-spec {revision, content_sha256} map) is required");
} else {
  const specEntries = manifest.source.specs;
  const specsInRows = new Set(rows.map((r) => r.spec).filter(nonEmptyString));
  const specKeys = new Set(Object.keys(specEntries));

  for (const spec of specsInRows) {
    if (!specKeys.has(spec)) fail("spec-inventory-drift", `source.specs is missing an entry for ${spec}, which appears in requirements`);
  }
  for (const spec of specKeys) {
    if (!specsInRows.has(spec)) {
      fail("spec-inventory-drift", `source.specs has an entry for ${spec}, which no requirement row references`);
      continue;
    }
    const entry = specEntries[spec];
    if (entry === null || typeof entry !== "object" || Array.isArray(entry)) {
      fail("schema", `source.specs["${spec}"] must be an object`);
      continue;
    }
    for (const k of Object.keys(entry)) {
      if (!SOURCE_SPEC_MEMBERS.has(k)) fail("schema", `source.specs["${spec}"] has unknown member "${k}"`);
    }
    if (!nonEmptyString(entry.revision) || !HEX40.test(entry.revision)) {
      fail("schema", `source.specs["${spec}"].revision must be a full 40-hex commit SHA`);
    }
    if (!nonEmptyString(entry.content_sha256) || !HEX64.test(entry.content_sha256)) {
      fail("schema", `source.specs["${spec}"].content_sha256 must be a 64-hex sha256 digest`);
      continue;
    }
    const p = path.join(ROOT, spec);
    if (!fs.existsSync(p)) {
      fail("spec-inventory-drift", `source.specs["${spec}"] names a file that does not exist: ${spec}`);
      continue;
    }
    const actual = crypto.createHash("sha256").update(fs.readFileSync(p)).digest("hex");
    if (actual !== entry.content_sha256) {
      fail(
        "spec-inventory-drift",
        `${spec}: working-tree content_sha256 (${actual}) does not match source.specs's recorded digest (${entry.content_sha256}) for revision ${entry.revision}; the spec changed since its rows were last audited: re-review and bump both fields`
      );
    }
  }
}
if (!Array.isArray(manifest.profiles) || manifest.profiles.length === 0 || !manifest.profiles.every(nonEmptyString)) {
  fail("schema", "manifest.profiles (the published-baseline enum) must be a non-empty array of non-empty strings");
}

// ---- section extraction ----------------------------------------------------

const draftCache = new Map();
function draftSections(file) {
  if (!draftCache.has(file)) {
    const p = path.join(ROOT, file);
    if (!fs.existsSync(p)) {
      draftCache.set(file, null);
    } else {
      const lines = fs.readFileSync(p, "utf8").split("\n");
      const headings = [];
      for (let i = 0; i < lines.length; i++) {
        const m = lines[i].match(/^(#{1,6})\s+.*\{#([A-Za-z0-9._-]+)\}\s*$/);
        const plain = lines[i].match(/^(#{1,6})\s+/);
        if (m) headings.push({ line: i, level: m[1].length, anchor: m[2] });
        else if (plain) headings.push({ line: i, level: plain[1].length, anchor: null });
      }
      const sections = new Map();
      for (let h = 0; h < headings.length; h++) {
        const cur = headings[h];
        if (!cur.anchor) continue;
        let end = lines.length;
        for (let j = h + 1; j < headings.length; j++) {
          if (headings[j].level <= cur.level) { end = headings[j].line; break; }
        }
        sections.set(cur.anchor, normalize(lines.slice(cur.line, end).join("\n")));
      }
      draftCache.set(file, sections);
    }
  }
  return draftCache.get(file);
}

// ---- row validation ---------------------------------------------------------

const ROW_MEMBERS = new Set([
  "id", "spec", "anchor", "text", "facet", "role", "strength", "applicability",
  "profiles", "surface", "assertion", "observation", "level", "coverage", "tests",
  "blocked_by", "notes",
]);
const REQUIRED_MEMBERS = [
  "id", "spec", "anchor", "text", "role", "strength", "applicability",
  "profiles", "surface", "assertion", "observation", "level", "coverage", "tests",
];
const MAPPING_MEMBERS = new Set(["file", "name", "level", "surface"]);
const COVERAGES = ["tested", "partial", "todo", "blocked"];

const seenIds = new Set();
const outstanding = [];

for (const row of rows) {
  const id = nonEmptyString(row.id) ? row.id : "<missing id>";

  for (const k of Object.keys(row)) {
    if (!ROW_MEMBERS.has(k)) fail("schema", `${id}: unknown member "${k}"`);
  }
  for (const f of REQUIRED_MEMBERS) {
    if (row[f] === undefined || row[f] === null) fail("schema", `${id}: missing field "${f}"`);
  }
  for (const f of ["id", "spec", "anchor", "text"]) {
    if (row[f] !== undefined && !nonEmptyString(row[f])) fail("schema", `${id}: ${f} must be a non-empty string`);
  }
  for (const f of ["facet", "notes"]) {
    if (row[f] !== undefined && !nonEmptyString(row[f])) fail("schema", `${id}: ${f} must be a non-empty string when present`);
  }
  if (row.blocked_by !== undefined && !/^#\d+$/.test(row.blocked_by ?? "")) {
    fail("schema", `${id}: blocked_by must be "#<issue number>"`);
  }

  if (seenIds.has(id)) fail("duplicate-id", `${id} appears more than once`);
  seenIds.add(id);

  const enums = [
    ["role", model.roles], ["strength", model.strengths],
    ["assertion", model.assertions], ["surface", model.surfaces],
    ["level", model.levels],
  ];
  for (const [field, allowed] of enums) {
    if (Array.isArray(allowed) && nonEmptyString(row[field]) && !allowed.includes(row[field])) {
      fail("schema", `${id}: ${field} "${row[field]}" not in the model`);
    }
  }
  if (!COVERAGES.includes(row.coverage)) {
    fail("schema", `${id}: coverage must be one of ${COVERAGES.join(", ")}`);
  }

  // profiles: which published baseline(s) this row applies to (empty allowed:
  // a spec entirely outside both baselines)
  if (!Array.isArray(row.profiles)) {
    fail("schema", `${id}: profiles must be an array`);
  } else {
    for (const p of row.profiles) {
      if (!nonEmptyString(p) || (Array.isArray(manifest.profiles) && !manifest.profiles.includes(p))) {
        fail("schema", `${id}: profiles entry "${p}" not in manifest.profiles`);
      }
    }
  }

  // applicability: structured, machine-readable
  const app = row.applicability;
  if (app === undefined || app === null || typeof app !== "object" || Array.isArray(app)) {
    fail("schema", `${id}: applicability must be an object`);
  } else if (app.kind === "unconditional") {
    if (Object.keys(app).length !== 1) fail("schema", `${id}: unconditional applicability carries no other members`);
  } else if (app.kind === "capability") {
    const extra = Object.keys(app).filter((k) => k !== "kind" && k !== "capability");
    if (!nonEmptyString(app.capability) || extra.length) {
      fail("schema", `${id}: capability applicability is {kind, capability}`);
    } else if (Array.isArray(model.capabilities) && !model.capabilities.includes(app.capability)) {
      fail("schema", `${id}: capability "${app.capability}" not declared in model.capabilities`);
    }
  } else {
    fail("schema", `${id}: applicability.kind must be "unconditional" or "capability"`);
  }

  // observation: exact members, normative required
  const obs = row.observation;
  if (obs === null || typeof obs !== "object" || Array.isArray(obs)) {
    fail("schema", `${id}: observation must be an object`);
  } else {
    for (const k of Object.keys(obs)) {
      if (k !== "normative" && k !== "local") fail("schema", `${id}: observation has unknown member "${k}"`);
    }
    if (!nonEmptyString(obs.normative)) fail("schema", `${id}: observation.normative must be a non-empty string`);
    if (obs.local !== undefined && !nonEmptyString(obs.local)) fail("schema", `${id}: observation.local must be a non-empty string when present`);
  }

  // anchor-bound requirement text
  if (nonEmptyString(row.spec) && nonEmptyString(row.anchor) && nonEmptyString(row.text)) {
    const sections = draftSections(row.spec);
    if (!sections) {
      fail("unknown-anchor", `${id}: spec file ${row.spec} not found`);
    } else if (!sections.has(row.anchor)) {
      fail("unknown-anchor", `${id}: ${row.spec} has no heading with {#${row.anchor}}`);
    } else if (!sections.get(row.anchor).includes(normalize(row.text))) {
      fail(
        "stale-requirement",
        `${id}: quoted clause not found inside the {#${row.anchor}} section of ${row.spec}; the clause changed, moved, or the anchor is wrong: re-review the requirement`
      );
    }
  }

  // test mappings
  if (!Array.isArray(row.tests)) {
    fail("schema", `${id}: tests must be an array`);
    continue;
  }
  let levelMatched = false;
  for (const m of row.tests) {
    if (m === null || typeof m !== "object" || Array.isArray(m)) {
      fail("schema", `${id}: each test mapping must be an object {file, name, level, surface}`);
      continue;
    }
    for (const k of Object.keys(m)) {
      if (!MAPPING_MEMBERS.has(k)) fail("schema", `${id}: test mapping has unknown member "${k}"`);
    }
    if (!nonEmptyString(m.file) || !nonEmptyString(m.name)) {
      fail("schema", `${id}: test mapping needs non-empty file and name`);
      continue;
    }
    if (!model.levels?.includes(m.level)) fail("schema", `${id}: mapping level "${m.level}" not in the model`);
    if (!model.surfaces?.includes(m.surface)) fail("schema", `${id}: mapping surface "${m.surface}" not in the model`);
    const p = path.join(ROOT, m.file);
    if (!fs.existsSync(p)) {
      fail("missing-test", `${id}: test file ${m.file} not found`);
    } else {
      const leaf = m.name.includes(" > ") ? m.name.slice(m.name.lastIndexOf(" > ") + 3) : m.name;
      if (!fs.readFileSync(p, "utf8").includes(leaf)) {
        fail("missing-test", `${id}: test "${leaf}" not found in ${m.file}`);
      }
    }
    if (m.level === row.level && (row.level !== "endpoint" || m.surface === row.surface)) {
      levelMatched = true;
    }
  }

  // coverage consistency
  const n = row.tests.length;
  switch (row.coverage) {
    case "tested":
      if (n === 0) fail("coverage", `${id}: tested with no test mappings`);
      else if (!levelMatched) fail("coverage", `${id}: tested but no mapping matches the row's level${row.level === "endpoint" ? " and surface" : ""}`);
      break;
    case "partial":
      if (n === 0) fail("coverage", `${id}: partial requires at least one test mapping (else it is todo)`);
      break;
    case "todo":
      if (n > 0) fail("coverage", `${id}: todo with test mappings (declare tested or partial)`);
      break;
    case "blocked":
      break;
  }
  if (row.coverage === "blocked" && !row.blocked_by) fail("coverage", `${id}: blocked requires blocked_by`);
  if (row.coverage !== "blocked" && row.blocked_by) fail("coverage", `${id}: blocked_by requires coverage "blocked"`);

  if (row.coverage !== "tested") outstanding.push(row);
}

// ---- collection check (--collect) -------------------------------------------

if (process.argv.includes("--collect")) {
  const files = [...new Set(rows.flatMap((r) => (r.tests ?? []).map((m) => m.file)))].filter(nonEmptyString);
  if (files.length) {
    const rel = files.map((f) => path.relative("src", f));
    let collected = [];
    try {
      const out = execSync(`pnpm -C src exec vitest list ${rel.map((r) => JSON.stringify(r)).join(" ")} --json`, {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
        timeout: 600000,
      });
      collected = JSON.parse(out.slice(out.indexOf("[")));
    } catch (e) {
      fail("collect", `vitest list failed: ${e.message}`);
    }
    for (const row of rows) {
      for (const m of row.tests ?? []) {
        const hit = collected.some(
          (e) => e.name === m.name && typeof e.file === "string" && path.resolve(e.file) === path.resolve(ROOT, m.file)
        );
        if (!hit) fail("collect", `${row.id}: (${m.file}, "${m.name}") not collected by the runner`);
      }
    }
  }
}

// ---- report ------------------------------------------------------------------

if (outstanding.length) {
  console.log(`Outstanding (${outstanding.length} of ${rows.length} not fully tested):`);
  for (const row of outstanding) {
    const blocked = row.blocked_by ? ` [blocked by ${row.blocked_by}]` : "";
    console.log(`  - ${row.id} (${row.coverage})${blocked}: ${row.observation?.normative ?? ""}`);
  }
}

if (errors.length) {
  for (const e of errors) console.error(e);
  console.error(`conformance-manifest check FAILED: ${errors.length} finding(s).`);
  process.exit(1);
}
const counts = COVERAGES.map((c) => `${rows.filter((r) => r.coverage === c).length} ${c}`).join(", ");
console.log(`conformance-manifest check OK: ${rows.length} requirements (${counts}).`);
