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
//   (f) draft copy            - a draft's `title`, `summary`, or `pull_when` is missing, empty,
//                                or not a string, or its `summary` is a bare maturity word
//   (g) reference stacks      - the manifest's top-level `reference_stacks` object (a transcription
//                                of the Architecture's four cumulative stacks in their OAuth
//                                realization) is missing a stack, has a malformed `contains` chain
//                                (self-reference, cycle, or not exactly one root), lacks the root's
//                                pinned `binding` or the Runtime-Enforced stack's `freshness_one_of`
//                                alternatives, lists an `adds`/`freshness_one_of` entry that is not
//                                a manifest slug (a `core:` freshness entry names a binding facility
//                                and is allowed), or names a stack whose `architecture_name` no
//                                longer appears in the architecture document (rename tripwire)
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
//   (m) readme-curated        - README.md does not link DRAFTS.md and DEPENDENCIES.md, a
//                                backtick-quoted `draft-...` token in README.md is not a
//                                manifest slug, or an editor's-copy link (#go.<slug>.html) in
//                                README.md or DRAFTS.md targets a slug that is not a manifest
//                                draft. README's structure is otherwise unvalidated: it is
//                                curated prose, and the exhaustive inventory lives in DRAFTS.md.
//   (n) typed edges           - a draft's edge sets are malformed or drift from the draft itself.
//                                `normative_references` (extracted: the front matter's normative
//                                in-family refs) and `references` (extracted: normative plus
//                                informative) are drift-checked bidirectionally against the draft's
//                                front matter and carry no adoption semantics. `adoption_requires`
//                                (authored: unconditional deployment dependencies; the only edges
//                                that close transitively for adoption) must be a subset of
//                                `normative_references`. `requires_when` (authored: conditional
//                                deployment edges) entries must be {when, requires} objects whose
//                                targets are cited in `references`.
//   (o) groups                - the manifest's `groups` enum is malformed, a draft's `group` is
//                                not in it, or the draft is not named under its group's "###"
//                                section in DRAFTS.md's catalog

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { validateExternalPins } from "./check-external-pins.mjs";
import { validateBundleManifests } from "./check-bundle-manifest.mjs";
import { maturityDisplay, validateDraftsIndex, GO_LINK_PATTERN } from "./generate-drafts-index.mjs";

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

// The in-family references a draft's own front matter declares, split by
// reference class: the ground truth the manifest's extracted edge sets must
// match. Only slugs that are family drafts count; external I-Ds are out of
// scope here.
function parseFamilyRefs(text, familySlugs) {
  const fmEnd = text.indexOf("\n--- abstract");
  const head = fmEnd > 0 ? text.slice(0, fmEnd) : text.slice(0, 8000);
  const collect = (block) => {
    const out = new Set();
    if (!block) return out;
    const re = /^  I-D\.(draft-mcguinness-[a-z0-9-]+):/gm;
    let m;
    while ((m = re.exec(block[1]))) {
      if (familySlugs.has(m[1])) out.add(m[1]);
    }
    return out;
  };
  return {
    normative: collect(head.match(/^normative:[ \t]*\r?\n([\s\S]*?)^(?:informative:|--- )/m)),
    informative: collect(head.match(/^informative:[ \t]*\r?\n([\s\S]*?)(?:^--- |$(?![\s\S]))/m)),
  };
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

  // Structural gate: every entry needs a string slug and file before any
  // other check can reason about it; a malformed entry would otherwise
  // crash later checks mid-run instead of producing one clean finding.
  const malformed = drafts.filter((d) => typeof d?.slug !== "string" || d.slug.length === 0 || typeof d?.file !== "string" || d.file.length === 0);
  if (malformed.length > 0) {
    console.error(`family-manifest check FAILED: ${malformed.length} drafts[] entr${malformed.length === 1 ? "y" : "ies"} missing a string slug/file:`);
    for (const d of malformed) console.error(`  - ${JSON.stringify({ slug: d?.slug, file: d?.file })}`);
    process.exit(1);
  }

  const onDisk = fs
    .readdirSync(ROOT)
    .filter((f) => /^draft-.*\.md$/.test(f))
    .sort();
  const onDiskSet = new Set(onDisk);
  const manifestFiles = new Set(drafts.map((d) => d.file));
  const manifestSlugs = new Set(drafts.map((d) => d.slug));

  // `slug` is the foreign key for requires/references/reference_stacks and
  // the go-link check; a duplicate would make every edge to it ambiguous
  // while the Sets above silently collapse it.
  for (const [field, set] of [["slug", manifestSlugs], ["file", manifestFiles]]) {
    if (set.size !== drafts.length) {
      const seen = new Set();
      for (const d of drafts) {
        if (seen.has(d[field])) fail("inventory", `drafts[] lists ${field} "${d[field]}" more than once`);
        seen.add(d[field]);
      }
    }
  }

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
  const publishedDrafts = drafts.filter((d) => d.is_published_draft);
  if (publishedDrafts.length !== 1) {
    fail(
      "inventory",
      `expected exactly one draft flagged is_published_draft, found ${publishedDrafts.length} (${publishedDrafts.map((d) => d.slug).join(", ") || "none"})`
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
    for (const field of ["title", "summary", "pull_when"]) {
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

  // (g) Reference stacks: a transcription of the Architecture's four
  // cumulative stacks ({#reference-architecture}), never a taxonomy of the
  // manifest's own. Structure is validated here; fidelity to the
  // Architecture's prose is an editorial obligation recorded in the object's
  // $comment.
  const stacks = manifest.reference_stacks;
  if (typeof stacks !== "object" || stacks === null || Array.isArray(stacks)) {
    fail("reference-stacks", `family-manifest.json's top-level "reference_stacks" must be an object`);
  } else {
    const stackNames = Object.keys(stacks).filter((k) => !k.startsWith("$"));
    const EXPECTED_STACKS = [
      "protocol-core",
      "reference-security-architecture",
      "recommended-agent-architecture",
      "high-assurance-architecture",
    ];
    for (const name of EXPECTED_STACKS) {
      if (!stackNames.includes(name)) {
        fail("reference-stacks", `reference_stacks is missing the Architecture's "${name}" stack`);
      }
    }
    for (const name of stackNames) {
      if (!EXPECTED_STACKS.includes(name)) {
        fail("reference-stacks", `reference_stacks names "${name}", which is not one of the Architecture's four stacks`);
      }
    }
    const checkSlugList = (name, field, arr, { allowEmpty, allowCore } = {}) => {
      if (arr === undefined) return;
      if (!Array.isArray(arr) || (!allowEmpty && arr.length === 0)) {
        fail("reference-stacks", `stack "${name}": "${field}" must be a non-empty array of manifest slugs`);
        return;
      }
      const seen = new Set();
      for (const slug of arr) {
        const isCoreFacility = allowCore && typeof slug === "string" && /^core:[a-z][a-z0-9-]*$/.test(slug);
        if (!isCoreFacility && !manifestSlugs.has(slug)) {
          fail("reference-stacks", `stack "${name}": "${field}" entry ${JSON.stringify(slug)} is not a manifest draft slug${allowCore ? ' or a "core:" binding facility' : ""}`);
        }
        if (seen.has(slug)) fail("reference-stacks", `stack "${name}": "${field}" lists "${slug}" more than once`);
        seen.add(slug);
      }
    };
    for (const name of stackNames) {
      const s = stacks[name];
      if (typeof s !== "object" || s === null || Array.isArray(s)) {
        fail("reference-stacks", `stack "${name}" must be an object, got ${JSON.stringify(s)}`);
        continue;
      }
      for (const field of ["level", "summary"]) {
        if (typeof s[field] !== "string" || s[field].trim().length === 0) {
          fail("reference-stacks", `stack "${name}": "${field}" must be a non-empty string`);
        }
      }
      if (s.contains !== null && !stackNames.includes(s.contains)) {
        fail("reference-stacks", `stack "${name}": "contains" must be null or another stack name, got ${JSON.stringify(s.contains)}`);
      }
      if (s.contains === name) {
        fail("reference-stacks", `stack "${name}": "contains" refers to itself`);
      }
      if (s.contains === null && !manifestSlugs.has(s.binding)) {
        fail("reference-stacks", `stack "${name}" is the root stack and must pin "binding" to a manifest slug (the stacks are the Architecture's OAuth realization), got ${JSON.stringify(s.binding)}`);
      }
      if (typeof s.architecture_name !== "string" || s.architecture_name.length === 0) {
        fail("reference-stacks", `stack "${name}": "architecture_name" (the Architecture's own name for this stack) is required`);
      } else if (!architecture.includes(s.architecture_name)) {
        fail("reference-stacks", `stack "${name}": architecture_name "${s.architecture_name}" no longer appears in draft-mcguinness-mission-architecture.md; the transcription must be re-checked against {#reference-architecture}`);
      }
      if (s.level === "Runtime-Enforced" && (!Array.isArray(s.freshness_one_of) || s.freshness_one_of.length === 0)) {
        fail("reference-stacks", `stack "${name}": the Runtime-Enforced level requires a non-empty "freshness_one_of" (the Architecture requires a freshness source, of which Status is only one realization)`);
      }
      checkSlugList(name, "adds", s.adds, { allowEmpty: true });
      checkSlugList(name, "freshness_one_of", s.freshness_one_of, { allowCore: true });
    }
    // The stacks are cumulative: exactly one root, and every `contains`
    // chain must reach it without a cycle.
    const roots = stackNames.filter((n) => stacks[n]?.contains === null);
    if (roots.length !== 1) {
      fail("reference-stacks", `expected exactly one root stack (contains: null), found ${roots.length} (${roots.join(", ") || "none"})`);
    }
    for (const name of stackNames) {
      const visited = new Set([name]);
      let cur = stacks[name]?.contains;
      while (typeof cur === "string" && stackNames.includes(cur)) {
        if (visited.has(cur)) {
          fail("reference-stacks", `stack "${name}": "contains" chain cycles at "${cur}"`);
          break;
        }
        visited.add(cur);
        cur = stacks[cur]?.contains;
      }
    }
  }

  // (h) maintenance enum: `maintenance` must be one of the manifest's own
  // declared `maintenance_classes`.
  validateEnumArray("maintenance-enum", "maintenance_classes", manifest.maintenance_classes);
  const validMaintenance = new Set(Array.isArray(manifest.maintenance_classes) ? manifest.maintenance_classes : []);
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
  // Editor's-copy links are the reader's actual navigation: a mistyped slug
  // renders fine and 404s at click time, so every #go.<slug>.html target in
  // the curated files must be a manifest draft.
  for (const [label, text] of [["README.md", readme], ["DRAFTS.md", draftsDoc]]) {
    const goRe = new RegExp(GO_LINK_PATTERN, "g");
    let gm;
    while ((gm = goRe.exec(text))) {
      if (!manifestSlugs.has(gm[1])) {
        fail("readme-curated", `${label} links the editor's copy of "${gm[1]}", which is not a family-manifest.json draft slug`);
      }
    }
  }

  // (n) Typed dependency edges: `requires` is the draft's normative in-family
  // reference set, extracted from and drift-checked against the draft's own
  // front matter, and the only edges adoption closure may follow;
  // `references` is the full in-family citation graph and pulls in nothing.
  for (const d of drafts) {
    // Shape validity is tracked per field so one malformed set never masks
    // an independent finding in another set on the same draft.
    const fieldOk = {};
    for (const field of ["normative_references", "references", "adoption_requires"]) {
      const arr = d[field];
      if (!Array.isArray(arr)) {
        fail("typed-edges", `${d.slug}: "${field}" must be an array of manifest slugs (empty allowed), got ${JSON.stringify(arr)}`);
        fieldOk[field] = false;
        continue;
      }
      fieldOk[field] = true;
      const seen = new Set();
      for (const slug of arr) {
        if (!manifestSlugs.has(slug)) {
          fail("typed-edges", `${d.slug}: "${field}" entry ${JSON.stringify(slug)} is not a manifest draft slug`);
          fieldOk[field] = false;
        }
        if (slug === d.slug) fail("typed-edges", `${d.slug}: "${field}" lists the draft itself`);
        if (seen.has(slug)) fail("typed-edges", `${d.slug}: "${field}" lists "${slug}" more than once`);
        seen.add(slug);
      }
    }
    if (fieldOk.normative_references && fieldOk.references) {
      const referenceSet = new Set(d.references);
      for (const slug of d.normative_references) {
        if (!referenceSet.has(slug)) {
          fail("typed-edges", `${d.slug}: "normative_references" entry "${slug}" is missing from "references"`);
        }
      }
    }
    // Adoption edges are authored, not extracted, but an unconditional
    // deployment dependency must at least be a normative reference.
    if (fieldOk.adoption_requires && fieldOk.normative_references) {
      const normSet = new Set(d.normative_references);
      for (const slug of d.adoption_requires) {
        if (!normSet.has(slug)) {
          fail("typed-edges", `${d.slug}: "adoption_requires" edge to "${slug}" is not among the draft's normative references; an unconditional deployment dependency must be normatively cited`);
        }
      }
    }
    // Conditional deployment edges: {when, requires}. Targets must at least
    // be cited by the draft.
    if (d.requires_when !== undefined) {
      if (!Array.isArray(d.requires_when)) {
        fail("typed-edges", `${d.slug}: "requires_when" must be an array of {when, requires} objects`);
      } else {
        const refSet = new Set(fieldOk.references ? d.references : []);
        for (const [i, entry] of d.requires_when.entries()) {
          if (typeof entry !== "object" || entry === null || Array.isArray(entry)) {
            fail("typed-edges", `${d.slug}: requires_when[${i}] must be an object, got ${JSON.stringify(entry)}`);
            continue;
          }
          if (typeof entry.when !== "string" || entry.when.trim().length === 0) {
            fail("typed-edges", `${d.slug}: requires_when[${i}].when must be a non-empty condition string`);
          }
          if (!Array.isArray(entry.requires) || entry.requires.length === 0) {
            fail("typed-edges", `${d.slug}: requires_when[${i}].requires must be a non-empty array of manifest slugs`);
            continue;
          }
          for (const slug of entry.requires) {
            if (!manifestSlugs.has(slug)) {
              fail("typed-edges", `${d.slug}: requires_when[${i}] targets ${JSON.stringify(slug)}, which is not a manifest draft slug`);
            } else if (fieldOk.references && !refSet.has(slug)) {
              fail("typed-edges", `${d.slug}: requires_when[${i}] targets "${slug}", which the draft does not cite (not in "references")`);
            }
            if (slug === d.slug) fail("typed-edges", `${d.slug}: requires_when[${i}] targets the draft itself`);
          }
        }
      }
    }
    // Drift: both extracted sets must match the draft's own front matter,
    // in both directions.
    if (!onDiskSet.has(d.file)) continue;
    const declared = parseFamilyRefs(readFile(path.join(ROOT, d.file), d.file), manifestSlugs);
    const declaredAll = new Set([...declared.normative, ...declared.informative]);
    const driftPairs = [
      ["normative_references", declared.normative, "normative"],
      ["references", declaredAll, "normative or informative"],
    ];
    for (const [field, truth, kind] of driftPairs) {
      if (!fieldOk[field]) continue;
      const recorded = new Set(d[field]);
      for (const slug of truth) {
        if (!recorded.has(slug)) {
          fail("typed-edges", `${d.slug}: front matter declares ${kind} I-D.${slug}, but manifest "${field}" omits it`);
        }
      }
      for (const slug of recorded) {
        if (!truth.has(slug)) {
          fail("typed-edges", `${d.slug}: manifest "${field}" lists "${slug}", but the draft's front matter has no ${kind} reference to it`);
        }
      }
    }
  }

  // (o) Groups: the enum is well-formed, every draft's `group` is in it, and
  // the draft is named under its group's "###" section in DRAFTS.md's
  // catalog — the placement semantics the retired README adoption map used
  // to carry.
  const GROUP_SECTION_TITLES = {
    "architecture": "Architecture",
    "approval-time": "Approval time",
    "lifecycle": "Lifecycle",
    "runtime-enforcement": "Runtime enforcement",
    "bindings-substrate": "The substrate and the bindings",
    "agent-runtime": "Agent runtime",
    "sub-agents": "Sub-agents",
    "cross-domain-projection": "Cross-domain projection",
    "proof-portability": "Proof and portability",
    "security-model": "Security model",
  };
  validateEnumArray("groups", "groups", manifest.groups);
  const validGroups = new Set(Array.isArray(manifest.groups) ? manifest.groups : []);
  for (const g of validGroups) {
    if (!(g in GROUP_SECTION_TITLES)) {
      fail("groups", `group "${g}" has no DRAFTS.md section title mapping in this checker; add it to GROUP_SECTION_TITLES`);
    }
  }
  const groupSections = {};
  for (const [g, title] of Object.entries(GROUP_SECTION_TITLES)) {
    if (!validGroups.has(g)) continue;
    const section = extractSection(draftsDoc, (t, l) => l === 3 && t === title);
    if (section === null) {
      fail("groups", `DRAFTS.md has no "### ${title}" section for group "${g}"`);
      continue;
    }
    groupSections[g] = section;
  }
  for (const d of drafts) {
    if (!validGroups.has(d.group)) {
      fail("groups", `${d.slug}: group ${JSON.stringify(d.group)} is not one of ${JSON.stringify([...validGroups])}`);
      continue;
    }
    const section = groupSections[d.group];
    if (section !== undefined && !containsToken(section, d.slug)) {
      fail("groups", `${d.slug}: not named under DRAFTS.md's "### ${GROUP_SECTION_TITLES[d.group]}" section, where its group "${d.group}" places it`);
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
