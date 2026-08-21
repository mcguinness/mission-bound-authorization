#!/usr/bin/env node
// Validates family-manifest.json against the drafts on disk, DRAFTS.md,
// README.md, and draft-mcguinness-mission-architecture.md. Dependency-free
// (Node core only).
//
// Usage: node scripts/check-family-manifest.mjs
//
// Exits 1 with a message per finding on any of:
//   (a) inventory drift       - a draft-*.md on disk not in the manifest, or vice versa
//   (b) category mismatch     - a draft's front-matter `category:` != manifest `category`
//   (c) drafts-catalog gap    - a draft not named under DRAFTS.md's "The documents" prose
//                                section (its presence in DRAFTS.md's generated index is
//                                covered by the freshness check (l), not repeated here)
//   (d) architecture map gap  - a draft not named in the architecture's Mission Document Map
//   (e) verbs                 - the manifest's top-level `verbs` enum is empty, non-string-valued,
//                                or has a duplicate entry; or a draft's `verbs` is not a
//                                non-empty, duplicate-free array drawn from that enum
//   (f) draft copy            - a draft's `summary` or `pull_when` is missing, empty, or not a
//                                string, or its `summary` is a bare maturity word
//   (g) packages              - the manifest's top-level `packages` object is missing or empty,
//                                or a package has an empty/duplicated `required` list, a
//                                `required` slug that is not a manifest draft, or no `summary`
//   (h) maintenance enum      - a draft's `maintenance` is not one of the manifest's declared
//                                `maintenance_classes`
//   (i) maintenance evidence  - a draft whose `maintenance` is "active-experimental" is missing
//                                a non-empty `maintenance_owner`, or its `maintenance_review_after`
//                                is not a YYYY-MM-DD date string
//   (j) external-pins shape   - notes/external-pins.json fails structural validation
//                                (see scripts/check-external-pins.mjs)
//   (k) bundle-manifest       - a notes/bundle-manifest.*.json file fails structural or
//                                registry cross-reference validation, including consuming
//                                a "pending" external pin (see scripts/check-bundle-manifest.mjs)
//   (l) drafts-index          - DRAFTS.md's generated index block is stale against the manifest
//                                (see scripts/generate-drafts-index.mjs --check), or a draft's
//                                `maturity` has no display word for that index
//   (m) readme-curated        - README.md does not link DRAFTS.md and DEPENDENCIES.md, or a
//                                backtick-quoted `draft-...` token in README.md is not a
//                                manifest slug. README's structure is otherwise unvalidated:
//                                it is curated prose, and the exhaustive inventory lives in
//                                DRAFTS.md.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { validateExternalPins } from "./check-external-pins.mjs";
import { validateBundleManifests } from "./check-bundle-manifest.mjs";
import { maturityDisplay, validateDraftsIndex } from "./generate-drafts-index.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..");

const MANIFEST_PATH = path.join(ROOT, "family-manifest.json");
const README_PATH = path.join(ROOT, "README.md");
const DRAFTS_PATH = path.join(ROOT, "DRAFTS.md");
const ARCHITECTURE_PATH = path.join(ROOT, "draft-mcguinness-mission-architecture.md");

// The architecture document does not list itself in its own document map.
const ARCHITECTURE_SLUG = "draft-mcguinness-mission-architecture";

// The curated README must hand the reader off to both moved files.
const README_REQUIRED_LINKS = ["DRAFTS.md", "DEPENDENCIES.md"];

// A `summary` that is only one of these says nothing: the maturity words (and
// the words the old catalog used as one-word stubs) carry no description.
const BARE_SUMMARY_WORDS = new Set([
  "stable",
  "experimental",
  "sketch",
  "informational",
  "guide",
  "optional",
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

function loadManifest() {
  const text = readFile(MANIFEST_PATH, "family-manifest.json");
  try {
    return JSON.parse(text);
  } catch (e) {
    console.error(`family-manifest.json is not valid JSON: ${e.message}`);
    process.exit(1);
  }
}

function parseFrontMatterCategory(text) {
  const m = text.match(/^---\n([\s\S]*?)\n---/);
  if (!m) return null;
  const km = m[1].match(/^category:\s*(.*)$/m);
  return km ? km[1].trim() : null;
}

// Returns the body text of a markdown section: from just after a heading line
// matched by `matchFn(headingText, level)` up to (but not including) the next
// heading of the same or shallower level. Anchor suffixes like " {#id}" are
// stripped from heading text before matching. Returns null if not found.
function extractSection(markdown, matchFn) {
  const lines = markdown.split("\n");
  const headings = [];
  for (let i = 0; i < lines.length; i++) {
    const m = lines[i].match(/^(#{1,6})\s+(.*)$/);
    if (!m) continue;
    const level = m[1].length;
    const text = m[2].replace(/\s*\{#[^}]*\}\s*$/, "").trim();
    headings.push({ level, text, line: i });
  }
  const startIdx = headings.findIndex((h) => matchFn(h.text, h.level));
  if (startIdx === -1) return null;
  const start = headings[startIdx];
  let endLine = lines.length;
  for (let j = startIdx + 1; j < headings.length; j++) {
    if (headings[j].level <= start.level) {
      endLine = headings[j].line;
      break;
    }
  }
  return lines.slice(start.line + 1, endLine).join("\n");
}

// Identifier-boundary containment check: true if `token` occurs in `text`
// without being a substring of a larger hyphenated/alnum identifier on
// either side (so "approval" doesn't match inside "approval-revision", and
// a short slug doesn't match inside a longer slug that extends it).
function containsToken(text, token) {
  const escaped = token.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const re = new RegExp(`(?<![A-Za-z0-9-])${escaped}(?![A-Za-z0-9-])`);
  return re.test(text);
}

function shortForm(slug) {
  return slug.replace(/^draft-mcguinness-/, "");
}

// Collects every backtick-quoted token (`` `token` ``, bare or inside a
// `[`token`](url)` link) out of a text blob. Backticks are exact delimiters,
// so this cannot mistake a short slug for a substring of a longer one the way
// plain containment matching could.
function extractBacktickedTokens(text) {
  const set = new Set();
  const re = /`([a-z0-9-]+)`/g;
  let m;
  while ((m = re.exec(text))) set.add(m[1]);
  return set;
}

// Validates a declared string enum on the manifest: non-empty, string-valued,
// duplicate-free. Findings are reported under `check`.
function validateEnumArray(check, name, arr) {
  if (!Array.isArray(arr) || arr.length === 0) {
    fail(check, `family-manifest.json's top-level "${name}" must be a non-empty array`);
    return false;
  }
  let ok = true;
  const seen = new Set();
  for (const v of arr) {
    if (typeof v !== "string" || v.length === 0) {
      fail(check, `family-manifest.json's "${name}" contains a non-string or empty entry: ${JSON.stringify(v)}`);
      ok = false;
      continue;
    }
    if (seen.has(v)) {
      fail(check, `family-manifest.json's "${name}" has a duplicate entry: "${v}"`);
      ok = false;
    }
    seen.add(v);
  }
  return ok;
}

function main() {
  const manifest = loadManifest();
  const drafts = manifest.drafts;
  if (!Array.isArray(drafts)) {
    console.error("family-manifest.json: `drafts` must be an array");
    process.exit(1);
  }

  const onDisk = fs
    .readdirSync(ROOT)
    .filter((f) => /^draft-.*\.md$/.test(f))
    .sort();
  const onDiskSet = new Set(onDisk);
  const manifestFiles = new Set(drafts.map((d) => d.file));
  const manifestSlugs = new Set(drafts.map((d) => d.slug));

  // (a) Inventory drift
  if (typeof manifest.count === "number" && manifest.count !== drafts.length) {
    fail("inventory", `family-manifest.json declares count ${manifest.count} but drafts[] has ${drafts.length} entries`);
  }
  for (const f of onDisk) {
    if (!manifestFiles.has(f)) fail("inventory", `${f} exists on disk but has no family-manifest.json entry`);
  }
  for (const d of drafts) {
    if (!onDiskSet.has(d.file)) fail("inventory", `family-manifest.json lists ${d.file}, which does not exist on disk`);
  }
  const publishedCore = drafts.filter((d) => d.is_published_core);
  if (publishedCore.length !== 1) {
    fail(
      "inventory",
      `expected exactly one draft flagged is_published_core, found ${publishedCore.length} (${publishedCore.map((d) => d.slug).join(", ") || "none"})`
    );
  }

  // (b) Category mismatch (only checked for drafts that exist on disk)
  for (const d of drafts) {
    if (!onDiskSet.has(d.file)) continue;
    const text = readFile(path.join(ROOT, d.file), d.file);
    const actual = parseFrontMatterCategory(text);
    if (actual !== d.category) {
      fail("category", `${d.file}: front-matter category is "${actual}", manifest says "${d.category}"`);
    }
  }

  // (c) Catalog coverage: every draft must be named under DRAFTS.md's "The
  // documents" prose section. DRAFTS.md, not README.md, is the exhaustive
  // catalog; the generated index above that section is validated for
  // freshness by (l) instead of for coverage here.
  const draftsDoc = readFile(DRAFTS_PATH, "DRAFTS.md");
  const catalogSection = extractSection(draftsDoc, (t, l) => l === 2 && t === "The documents");
  if (catalogSection === null) {
    fail("drafts-catalog", `could not find a "## The documents" section in DRAFTS.md`);
  } else {
    for (const d of drafts) {
      if (!containsToken(catalogSection, d.slug)) {
        fail("drafts-catalog", `${d.slug} is not named under DRAFTS.md's "The documents" section`);
      }
    }
  }

  // (d) Architecture document-map coverage: every draft (other than the
  // architecture document itself) must be named by its short form.
  const architecture = readFile(ARCHITECTURE_PATH, "draft-mcguinness-mission-architecture.md");
  const docMapSection = extractSection(architecture, (t, l) => l === 1 && t === "Mission Document Map");
  if (docMapSection === null) {
    fail("architecture-map", `could not find a "# Mission Document Map" section in draft-mcguinness-mission-architecture.md`);
  } else {
    for (const d of drafts) {
      if (d.slug === ARCHITECTURE_SLUG) continue;
      if (!containsToken(docMapSection, shortForm(d.slug))) {
        fail("architecture-map", `${d.slug} (short form "${shortForm(d.slug)}") is not named in the architecture's Mission Document Map`);
      }
    }
  }

  // (e) Verbs: the manifest declares the verb spine once, and every draft
  // claims at least one of those verbs.
  validateEnumArray("verbs", "verbs", manifest.verbs);
  const validVerbs = new Set(Array.isArray(manifest.verbs) ? manifest.verbs : []);
  for (const d of drafts) {
    if (!Array.isArray(d.verbs) || d.verbs.length === 0) {
      fail("verbs", `${d.slug}: "verbs" must be a non-empty array, got ${JSON.stringify(d.verbs)}`);
      continue;
    }
    const seen = new Set();
    for (const v of d.verbs) {
      if (!validVerbs.has(v)) {
        fail("verbs", `${d.slug}: verb ${JSON.stringify(v)} is not one of ${JSON.stringify([...validVerbs])}`);
      }
      if (seen.has(v)) fail("verbs", `${d.slug}: verb "${v}" is listed more than once`);
      seen.add(v);
    }
  }

  // (f) Draft copy: the one-sentence summary DRAFTS.md's index renders, and
  // the adoption trigger a reader chooses by. A summary that is only a
  // maturity word describes nothing.
  for (const d of drafts) {
    for (const field of ["summary", "pull_when"]) {
      const v = d[field];
      if (typeof v !== "string" || v.trim().length === 0) {
        fail("draft-copy", `${d.slug}: "${field}" must be a non-empty string, got ${JSON.stringify(v)}`);
      }
    }
    if (typeof d.summary === "string") {
      const bare = d.summary.trim().toLowerCase().replace(/\.$/, "");
      if (BARE_SUMMARY_WORDS.has(bare)) {
        fail("draft-copy", `${d.slug}: "summary" is the bare word "${d.summary.trim()}", which describes nothing`);
      }
    }
  }

  // (g) Packages: the document sets a deployment adopts together. Every
  // member must be a real draft, and a package with no members is not one.
  const packages = manifest.packages;
  if (typeof packages !== "object" || packages === null || Array.isArray(packages) || Object.keys(packages).length === 0) {
    fail("packages", `family-manifest.json's top-level "packages" must be a non-empty object`);
  } else {
    for (const [name, pkg] of Object.entries(packages)) {
      if (typeof pkg !== "object" || pkg === null || Array.isArray(pkg)) {
        fail("packages", `package "${name}" must be an object, got ${JSON.stringify(pkg)}`);
        continue;
      }
      if (!Array.isArray(pkg.required) || pkg.required.length === 0) {
        fail("packages", `package "${name}": "required" must be a non-empty array of manifest slugs`);
      } else {
        const seen = new Set();
        for (const slug of pkg.required) {
          if (!manifestSlugs.has(slug)) {
            fail("packages", `package "${name}" requires ${JSON.stringify(slug)}, which is not a manifest draft slug`);
          }
          if (seen.has(slug)) fail("packages", `package "${name}" lists "${slug}" more than once`);
          seen.add(slug);
        }
      }
      if (typeof pkg.summary !== "string" || pkg.summary.trim().length === 0) {
        fail("packages", `package "${name}": "summary" must be a non-empty string`);
      }
    }
  }

  // (h) maintenance enum: `maintenance` must be one of the manifest's own
  // declared `maintenance_classes`.
  const validMaintenance = new Set(manifest.maintenance_classes || []);
  if (validMaintenance.size === 0) {
    fail("maintenance-enum", `family-manifest.json is missing a non-empty top-level "maintenance_classes" array`);
  }
  for (const d of drafts) {
    if (!validMaintenance.has(d.maintenance)) {
      fail("maintenance-enum", `${d.slug}: maintenance "${d.maintenance}" is not one of ${JSON.stringify([...validMaintenance])}`);
    }
  }

  // (i) maintenance evidence: an "active-experimental" draft must name a
  // maintenance owner and carry a date-shaped review horizon.
  const DATE_SHAPED = /^\d{4}-\d{2}-\d{2}$/;
  for (const d of drafts) {
    if (d.maintenance !== "active-experimental") continue;
    if (typeof d.maintenance_owner !== "string" || d.maintenance_owner.length === 0) {
      fail("maintenance-evidence", `${d.slug}: maintenance "active-experimental" requires a non-empty "maintenance_owner"`);
    }
    if (typeof d.maintenance_review_after !== "string" || !DATE_SHAPED.test(d.maintenance_review_after)) {
      fail("maintenance-evidence", `${d.slug}: maintenance "active-experimental" requires a date-shaped (YYYY-MM-DD) "maintenance_review_after", got ${JSON.stringify(d.maintenance_review_after)}`);
    }
  }

  // (j) External pin registry: structural validation only (P2, review of
  // PR #595). Content verification against live source repos happens at
  // Ship 3, not here.
  for (const e of validateExternalPins(ROOT)) fail("external-pins", e);

  // (k) Bundle manifest(s): structural validation plus a cross-reference
  // against the external pin registry, chained the same way as (j). Rejects
  // the check if a bundle consumes a "pending" registry entry.
  for (const e of validateBundleManifests(ROOT)) fail("bundle-manifest", e);

  // (l) Generated index: DRAFTS.md's marker block must be what the manifest
  // renders today, and every maturity value must have a display word for
  // that block's Maturity column.
  for (const e of validateDraftsIndex(ROOT)) fail("drafts-index", e);
  for (const d of drafts) {
    if (maturityDisplay(d.maturity) === null) {
      fail("drafts-index", `${d.slug}: maturity "${d.maturity}" has no display word for DRAFTS.md's index`);
    }
  }

  // (m) Curated README: two hand-offs and one naming rule. README.md is
  // curated prose whose structure is deliberately not validated; what must
  // hold is that it points at the catalog and the dependency report, and
  // that any full draft name it quotes is a real family draft.
  const readme = readFile(README_PATH, "README.md");
  for (const target of README_REQUIRED_LINKS) {
    const escaped = target.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    if (!new RegExp(`\\]\\([^)]*${escaped}\\)`).test(readme)) {
      fail("readme-curated", `README.md does not link ${target}`);
    }
  }
  for (const token of extractBacktickedTokens(readme)) {
    if (!token.startsWith("draft-")) continue;
    if (!manifestSlugs.has(token)) {
      fail("readme-curated", `README.md quotes \`${token}\`, which is not a family-manifest.json draft slug`);
    }
  }

  if (errors.length > 0) {
    console.error(`family-manifest check FAILED with ${errors.length} finding(s):\n`);
    for (const e of errors) console.error(`  - ${e}`);
    console.error("");
    process.exit(1);
  }

  console.log(`family-manifest check OK: ${drafts.length} drafts, no drift detected.`);

  // Chained sub-check (#554): the Mission Substrate Statement structural
  // tripwire runs under this entry point so it rides the existing CI step;
  // its own findings and exit code stand on their own.
  const sub = spawnSync(process.execPath, [path.join(path.dirname(fileURLToPath(import.meta.url)), "check-substrate-statements.mjs")], { stdio: "inherit" });
  process.exit(sub.status ?? 1);
}

main();
