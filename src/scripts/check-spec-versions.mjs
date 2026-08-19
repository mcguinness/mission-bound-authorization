#!/usr/bin/env node
// Validates SPEC_VERSIONS.md's "## Implemented" table (#601 author review,
// findings 1/3). For every row whose Surfaces column cites `<key>#<anchor>`
// `@spec` tags, this checks two directions between the row's Surfaces list
// and the `@spec <key>#` tags actually present (outside test/ and demo/
// code) in the row's Component files:
//
//   forward  - every anchor the row DECLARES in Surfaces must resolve to at
//              least one matching @spec tag in the row's Component files.
//   inverse  - every matching @spec tag actually found in the row's
//              Component files must be DECLARED in the row's Surfaces list.
//
// No script validated SPEC_VERSIONS.md before this one (searched src/scripts
// and scripts/; nothing referenced the file). Both directions are enforced
// (fail) only for STRICT_SPECS below -- the two specs this review round
// authored/restructured (cross-org-delegation, transaction-authorization),
// plus the txn-authorization#applicability row this round adds for
// services/pdp. Every other anchor-tagged row is computed and PRINTED as an
// outstanding-coverage report, never failing: those rows predate this
// checker, drift accumulated with nothing watching it (e.g. the
// child-delegation row cites `#request-processing`, which no @spec tag
// anywhere implements, and its listed files alone implement a dozen
// undeclared anchors -- #attenuation, #fanout, #child-evidence, ... --
// discovered while building this checker), and backfilling every
// pre-existing row is separate, disclosed follow-up, not this review round.
// This mirrors check-conformance-manifest.mjs's own precedent: "Rows not
// 'tested' are the outstanding reverse-mapping report: printed, never
// failing. Completeness is judged by that report, not by tag coverage."
//
// Also prints a global inverse-OMISSION report (#605 author review, finding
// 5): every `@spec <key>#<anchor>` tag found anywhere in implementation
// files repo-wide (excluding test/demo/dist), grouped by key, where that key
// never appears in ANY row's Surfaces column at all -- not merely an anchor
// missing from one row's already-matched Component files (the per-row
// inverse check above), but a whole spec key the matrix has no row for
// whatsoever. Print-only, never failing, the same outstanding-report
// pattern as the per-row checks: this closes the blind spot where an entire
// implemented spec could go untracked with nothing watching it.
//
// Usage: node scripts/check-spec-versions.mjs [--dump]
//   --dump  print every anchor-tagged row's resolved file set and matched
//           anchors (both directions), including non-strict rows; useful
//           for building/auditing a row's Surfaces list by hand.
//
// Exits 1 with a message per finding on any of (STRICT_SPECS rows only):
//   (a) unresolved-path   - a Component cell names a file/dir (a backtick
//                           span containing "/" or a source-file extension)
//                           that does not exist on disk
//   (b) unresolved-surface- a Surfaces anchor does not resolve to an @spec
//                           tag anywhere in the row's Component files
//                           (forward direction)
//   (c) undeclared-anchor - an @spec <key>#<anchor> tag in the row's
//                           Component files, matching the row's own key,
//                           is not in the row's Surfaces list (inverse
//                           direction)
//
// Dependency-free (Node core only).

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, ".."); // src/
const TABLE_PATH = path.join(ROOT, "SPEC_VERSIONS.md");

const STRICT_SPECS = new Set([
  "draft-mcguinness-oauth-mission-cross-org-delegation",
  "draft-mcguinness-oauth-mission-transaction-authorization",
]);

const errors = [];
const fail = (check, msg) => errors.push(`[${check}] ${msg}`);

function readFile(p, label) {
  try {
    return fs.readFileSync(p, "utf8");
  } catch (e) {
    console.error(`Cannot read ${label} at ${p}: ${e.message}`);
    process.exit(1);
  }
}

// ---- table extraction -------------------------------------------------

function implementedRows(text) {
  const lines = text.split("\n");
  const start = lines.findIndex((l) => l.startsWith("## Implemented"));
  const afterStart = lines.slice(start + 1);
  const end = afterStart.findIndex((l) => l.startsWith("## "));
  const section = end === -1 ? afterStart : afterStart.slice(0, end);
  const tableLines = section.filter((l) => l.trim().startsWith("|"));
  // tableLines[0] is the header, tableLines[1] the |---| separator.
  return tableLines.slice(2).map((l) => {
    const cells = l
      .split("|")
      .slice(1, -1)
      .map((c) => c.trim());
    return { spec: stripBackticks(cells[0]), component: cells[2], surfaces: cells[3], raw: l };
  });
}

function stripBackticks(s) {
  const m = s.match(/`([^`]+)`/);
  return m ? m[1] : s;
}

// ---- Surfaces column: `<key>#<anchor>` and abbreviated `#<anchor>` -----

function parseSurfaceAnchors(cell) {
  const spans = [...cell.matchAll(/`([^`]+)`/g)].map((m) => m[1]);
  const byKey = new Map(); // key -> Set<anchor>
  let lastKey = null;
  for (const span of spans) {
    let m = span.match(/^([A-Za-z][\w.-]*)#([\w-]+)$/);
    if (m) {
      lastKey = m[1];
      if (!byKey.has(lastKey)) byKey.set(lastKey, new Set());
      byKey.get(lastKey).add(m[2]);
      continue;
    }
    m = span.match(/^#([\w-]+)$/);
    if (m && lastKey) {
      byKey.get(lastKey).add(m[1]);
    }
  }
  return byKey;
}

// ---- Component column: resolve backtick spans to files/dirs on disk ---

function expandBraces(tok) {
  const m = tok.match(/^(.*)\{([^}]+)\}(.*)$/);
  if (!m) return [tok];
  const [, prefix, group, suffix] = m;
  return group.split(",").flatMap((alt) => expandBraces(`${prefix}${alt}${suffix}`));
}

const SOURCE_EXT = /\.(ts|tsx|js|mjs|json|sh)$/;

function resolveToken(tok) {
  for (const candidate of [tok, `services/${tok}`, `packages/${tok}`]) {
    const full = path.join(ROOT, candidate);
    if (fs.existsSync(full)) {
      return { full, isFile: fs.statSync(full).isFile() };
    }
  }
  return null;
}

function parseComponentPaths(cell) {
  const spans = [...cell.matchAll(/`([^`]+)`/g)].map((m) => m[1]);
  const files = new Set();
  const dirs = new Set();
  const problems = [];
  for (const span of spans) {
    if (span.includes("#") || span.includes(" ") || span.startsWith("/")) continue;
    if (!/^[\w.\-{},/]+$/.test(span)) continue;
    for (const tok of expandBraces(span)) {
      if (tok.startsWith("/")) continue; // an endpoint path (e.g. `/token`), not a repo path
      const looksLikePath = tok.includes("/") || SOURCE_EXT.test(tok);
      const resolved = resolveToken(tok);
      if (resolved) {
        (resolved.isFile ? files : dirs).add(resolved.full);
      } else if (looksLikePath) {
        problems.push(tok);
      }
      // else: a bare inline identifier (e.g. `cascadeChildren`), not a path -- ignore.
    }
  }
  return { files, dirs, problems };
}

// ---- @spec tag extraction from source, multi-line-aware ----------------

const EXCLUDED = /(^|\/)(test|demo)(\/|$)/;

function listFiles(dirFull) {
  const out = [];
  const stack = [dirFull];
  while (stack.length) {
    const d = stack.pop();
    for (const entry of fs.readdirSync(d, { withFileTypes: true })) {
      const p = path.join(d, entry.name);
      const rel = path.relative(ROOT, p);
      if (EXCLUDED.test(rel) || rel.includes("node_modules")) continue;
      if (entry.isDirectory()) stack.push(p);
      else if (/\.(ts|tsx)$/.test(entry.name) && !entry.name.endsWith(".test.ts")) out.push(p);
    }
  }
  return out;
}

function filesForRow({ files, dirs }) {
  const all = new Set(files);
  for (const d of dirs) for (const f of listFiles(d)) all.add(f);
  return [...all];
}

// ---- global file listing, for the inverse-omission report -------------
//
// Wider than listFiles: walks from repo root rather than a row's own
// Component dirs, so it additionally excludes "dist" (gitignored build
// output that copies doc-comments, including @spec tags, into .d.ts files)
// and any ".d.ts" file, neither of which the per-row scan ever encounters
// (Component cells name src/ paths, never a package's dist/ sibling).
const GLOBAL_EXCLUDED = /(^|\/)(test|demo|dist|node_modules)(\/|$)/;

function listAllSourceFiles(rootFull) {
  const out = [];
  const stack = [rootFull];
  while (stack.length) {
    const d = stack.pop();
    for (const entry of fs.readdirSync(d, { withFileTypes: true })) {
      const p = path.join(d, entry.name);
      const rel = path.relative(ROOT, p);
      if (GLOBAL_EXCLUDED.test(rel)) continue;
      if (entry.isDirectory()) stack.push(p);
      else if (
        /\.(ts|tsx)$/.test(entry.name) &&
        !entry.name.endsWith(".test.ts") &&
        !entry.name.endsWith(".d.ts")
      )
        out.push(p);
    }
  }
  return out;
}

// A trailing "," at a comment line's end, followed by a new comment line,
// joins with the next line so a wrapped `@spec key#a, key#b` list (or its
// prose that continues past the anchors) reads as one logical line.
function flatten(text) {
  return text.replace(/,(\s*\n\s*(?:\*|\/\/)\s*)/g, ", ");
}

function tagsInFile(fullPath, key) {
  const text = flatten(readFile(fullPath, fullPath));
  const anchors = new Set();
  for (const m of text.matchAll(/@spec\s+([^\n]*)/g)) {
    // Tag content ends at the first em dash, closing paren/quote, "*/", or
    // end of line -- whichever the prose boundary hits first.
    const boundary = m[1].search(/—|--|\)|"|\*\/|;/);
    const content = boundary === -1 ? m[1] : m[1].slice(0, boundary);
    let lastKey = null;
    for (const piece of content.split(",").map((s) => s.trim())) {
      let pm = piece.match(/^([A-Za-z][\w.-]*)#([\w-]+)/);
      if (pm) {
        lastKey = pm[1];
        if (lastKey === key) anchors.add(pm[2]);
        continue;
      }
      pm = piece.match(/^#([\w-]+)/);
      if (pm && lastKey === key) anchors.add(pm[1]);
    }
  }
  return anchors;
}

// Same parse as tagsInFile, but returns every key found (Map<key,
// Set<anchor>>) instead of filtering to one -- for the global
// inverse-omission scan, which does not know its keys in advance.
function allKeyAnchorsInFile(fullPath) {
  const text = flatten(readFile(fullPath, fullPath));
  const byKey = new Map();
  for (const m of text.matchAll(/@spec\s+([^\n]*)/g)) {
    const boundary = m[1].search(/—|--|\)|"|\*\/|;/);
    const content = boundary === -1 ? m[1] : m[1].slice(0, boundary);
    let lastKey = null;
    for (const piece of content.split(",").map((s) => s.trim())) {
      let pm = piece.match(/^([A-Za-z][\w.-]*)#([\w-]+)/);
      if (pm) {
        lastKey = pm[1];
        if (!byKey.has(lastKey)) byKey.set(lastKey, new Set());
        byKey.get(lastKey).add(pm[2]);
        continue;
      }
      pm = piece.match(/^#([\w-]+)/);
      if (pm && lastKey) byKey.get(lastKey).add(pm[1]);
    }
  }
  return byKey;
}

function tagsForFiles(fileList, key) {
  const anchors = new Set();
  const byAnchor = new Map(); // anchor -> [files]
  for (const f of fileList) {
    for (const a of tagsInFile(f, key)) {
      anchors.add(a);
      if (!byAnchor.has(a)) byAnchor.set(a, []);
      byAnchor.get(a).push(path.relative(ROOT, f));
    }
  }
  return { anchors, byAnchor };
}

// ---- main ---------------------------------------------------------------

const text = readFile(TABLE_PATH, "SPEC_VERSIONS.md");
const rows = implementedRows(text);
const dump = process.argv.includes("--dump");

const outstanding = [];

for (const row of rows) {
  const byKey = parseSurfaceAnchors(row.surfaces);
  if (byKey.size === 0) continue; // no `key#anchor` citations: not an anchor-checked row

  const { files, dirs, problems } = parseComponentPaths(row.component);
  const strict = STRICT_SPECS.has(row.spec);

  for (const p of problems) {
    const msg = `${row.spec}: Component cell names "${p}", not found on disk`;
    if (strict) fail("unresolved-path", msg);
    else if (dump) console.log(`  (non-strict unresolved-path, not enforced): ${msg}`);
  }

  const fileList = filesForRow({ files, dirs });

  for (const [key, declared] of byKey) {
    const { anchors: found, byAnchor } = tagsForFiles(fileList, key);

    const missingForward = [...declared].filter((a) => !found.has(a));
    const missingInverse = [...found].filter((a) => !declared.has(a));

    if (dump) {
      console.log(`\n${row.spec} :: ${key}`);
      console.log(`  files: ${fileList.map((f) => path.relative(ROOT, f)).join(", ")}`);
      console.log(`  declared: ${[...declared].sort().join(", ")}`);
      console.log(`  found:    ${[...found].sort().join(", ")}`);
      if (missingForward.length)
        console.log(`  MISSING FORWARD (declared, not found): ${missingForward.join(", ")}`);
      if (missingInverse.length) {
        for (const a of missingInverse)
          console.log(
            `  MISSING INVERSE (found, not declared): #${a} in ${byAnchor.get(a).join(", ")}`,
          );
      }
    }

    if (strict) {
      for (const a of missingForward) {
        fail(
          "unresolved-surface",
          `${row.spec} (${key}): Surfaces cites #${a}, not found as an @spec tag in any listed Component file`,
        );
      }
      for (const a of missingInverse) {
        fail(
          "undeclared-anchor",
          `${row.spec} (${key}): @spec ${key}#${a} found in ${byAnchor.get(a).join(", ")}, not declared in Surfaces`,
        );
      }
    } else if (missingForward.length || missingInverse.length) {
      outstanding.push({ spec: row.spec, key, missingForward, missingInverse, byAnchor });
    }
  }
}

if (outstanding.length && !dump) {
  console.log(
    `Outstanding anchor-coverage gaps (${outstanding.length} row/key pairs, pre-existing, not enforced):`,
  );
  for (const o of outstanding) {
    if (o.missingForward.length)
      console.log(
        `  - ${o.spec} (${o.key}): declared but unresolved: ${o.missingForward.map((a) => `#${a}`).join(", ")}`,
      );
    if (o.missingInverse.length)
      console.log(
        `  - ${o.spec} (${o.key}): implemented but undeclared: ${o.missingInverse.map((a) => `#${a}`).join(", ")}`,
      );
  }
}

// ---- global inverse-omission report -------------------------------------
//
// Every key any row declares anywhere in its Surfaces column (whether or
// not that row's own byKey.size check above skipped it, and regardless of
// strict/non-strict), versus every key actually tagged in implementation
// files repo-wide. A key tagged in code but declared by NO row at all is a
// whole spec the matrix never tracked, not merely one row's undercount.
const knownKeys = new Set();
for (const row of rows) {
  for (const key of parseSurfaceAnchors(row.surfaces).keys()) knownKeys.add(key);
}

const globalByKey = new Map(); // key -> Set<anchor>
const globalFilesByKey = new Map(); // key -> Set<relFile>
for (const f of listAllSourceFiles(ROOT)) {
  for (const [key, anchors] of allKeyAnchorsInFile(f)) {
    if (!globalByKey.has(key)) globalByKey.set(key, new Set());
    for (const a of anchors) globalByKey.get(key).add(a);
    if (!globalFilesByKey.has(key)) globalFilesByKey.set(key, new Set());
    globalFilesByKey.get(key).add(path.relative(ROOT, f));
  }
}

const omittedKeys = [...globalByKey.keys()].filter((k) => !knownKeys.has(k)).sort();

if (omittedKeys.length && !dump) {
  console.log(
    `Inverse-omission report (${omittedKeys.length} @spec key(s) tagged in implementation with NO matrix row at all, pre-existing, not enforced):`,
  );
  for (const k of omittedKeys) {
    const anchors = [...globalByKey.get(k)].sort();
    const files = [...globalFilesByKey.get(k)].sort();
    console.log(`  - ${k}: ${anchors.map((a) => `#${a}`).join(", ")} in ${files.join(", ")}`);
  }
}

if (errors.length) {
  for (const e of errors) console.error(e);
  console.error(`SPEC_VERSIONS check FAILED: ${errors.length} finding(s).`);
  process.exit(1);
}
console.log(
  `SPEC_VERSIONS check OK (${rows.length} rows, ${outstanding.length} outstanding gaps printed above, ${omittedKeys.length} omitted keys printed above, STRICT_SPECS clean).`,
);
