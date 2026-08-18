#!/usr/bin/env node
// Validates family-manifest.json against the drafts on disk, README.md, and
// draft-mcguinness-mission-architecture.md. Dependency-free (Node core only).
//
// Usage: node scripts/check-family-manifest.mjs
//
// Exits 1 with a message per finding on any of:
//   (a) inventory drift       - a draft-*.md on disk not in the manifest, or vice versa
//   (b) category mismatch     - a draft's front-matter `category:` != manifest `category`
//   (c) README catalog gap    - a draft not linked under README's "The documents" section
//   (d) architecture map gap  - a draft not named in the architecture's Mission Document Map
//   (e) adoption-order gap    - a draft with a real adoption_rung missing from README's
//                                Adoption order section (adoption_rung "outside-ordering" is exempt)
//   (f) external-pins shape   - notes/external-pins.json fails structural validation
//                                (see scripts/check-external-pins.mjs)

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { validateExternalPins } from "./check-external-pins.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..");

const MANIFEST_PATH = path.join(ROOT, "family-manifest.json");
const README_PATH = path.join(ROOT, "README.md");
const ARCHITECTURE_PATH = path.join(ROOT, "draft-mcguinness-mission-architecture.md");

// The architecture document does not list itself in its own document map.
const ARCHITECTURE_SLUG = "draft-mcguinness-mission-architecture";

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

// README's "Adoption order" list bolds every nickname (**status**,
// **core**, ...), and also uses several of those words in ordinary prose
// within the same section (e.g. "correctly sized status polling"). Require
// the bold form so a deleted bullet can't hide behind unrelated prose.
function containsBoldToken(text, token) {
  const escaped = token.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const re = new RegExp(`\\*\\*${escaped}\\*\\*`);
  return re.test(text);
}

function shortForm(slug) {
  return slug.replace(/^draft-mcguinness-/, "");
}

// The bare nickname README's "Adoption order" list uses: the short form with
// a further leading "oauth-mission-" or "mission-" stripped. A couple of
// drafts use a nickname the manifest can't derive this way; the manifest
// carries an explicit `adoption_alias` for those.
function adoptionNickname(draft) {
  if (draft.adoption_alias) return draft.adoption_alias;
  return shortForm(draft.slug).replace(/^oauth-mission-/, "").replace(/^mission-/, "");
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

  // (c) README catalog coverage: every draft must be linked under "The documents"
  const readme = readFile(README_PATH, "README.md");
  const catalogSection = extractSection(readme, (t, l) => l === 2 && t === "The documents");
  if (catalogSection === null) {
    fail("readme-catalog", `could not find a "## The documents" section in README.md`);
  } else {
    for (const d of drafts) {
      if (!containsToken(catalogSection, d.slug)) {
        fail("readme-catalog", `${d.slug} is not linked under README's "The documents" section`);
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

  // (e) Adoption-order coverage: every draft with a real adoption_rung must
  // appear in README's "Adoption order" section.
  const adoptionSection = extractSection(readme, (t, l) => l === 3 && t === "Adoption order");
  if (adoptionSection === null) {
    fail("adoption-order", `could not find a "### Adoption order" section in README.md`);
  } else {
    for (const d of drafts) {
      if (d.adoption_rung === "outside-ordering") continue;
      const nickname = adoptionNickname(d);
      if (!containsBoldToken(adoptionSection, nickname)) {
        fail(
          "adoption-order",
          `${d.slug} has adoption_rung "${d.adoption_rung}" but nickname "${nickname}" is not present in README's "Adoption order" section`
        );
      }
    }
  }

  // (f) External pin registry: structural validation only (P2, review of
  // PR #595). Content verification against live source repos happens at
  // Ship 3, not here.
  for (const e of validateExternalPins(ROOT)) fail("external-pins", e);

  if (errors.length > 0) {
    console.error(`family-manifest check FAILED with ${errors.length} finding(s):\n`);
    for (const e of errors) console.error(`  - ${e}`);
    console.error("");
    process.exit(1);
  }

  console.log(`family-manifest check OK: ${drafts.length} drafts, no drift detected.`);
  process.exit(0);
}

main();
