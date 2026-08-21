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
//   (f) presentation enum     - a draft's `presentation_zone`/`presentation_track` is not one of
//                                the manifest's declared `presentation_zones`/`presentation_tracks`,
//                                or either declared array is empty, non-string-valued, or has a
//                                duplicate entry
//   (g) adoption-map gap      - a draft not listed exactly once in README's "The adoption map"
//                                table, on a row whose Zone/Track/Group cells match the manifest's
//                                declared presentation_zone/presentation_track/group and whose
//                                "Pull this when..." cell is non-empty
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
//
// README's "The adoption map" section has two layers: a hand-authored ten-pick
// menu (from the heading down to the "<details>" line) and the machine-
// validated matrix (g) already covers. The menu's own prose claims are
// checked by (l)-(o):
//   (l) menu-coverage         - a draft not named at least once in the menu region as a
//                                backtick-quoted short slug
//   (m) menu-maturity         - the menu's display of a draft's maturity (an inline
//                                "(word)" suffix right after a slug link, or a table's
//                                trailing "Maturity" column) disagrees with the manifest,
//                                or a non-stable draft's maturity is not displayed anywhere
//                                in the menu region
//   (n) menu-picks            - a "pick N" / "picks N and M" cross-reference in the menu
//                                region names a pick number with no matching bolded
//                                "**N." pick heading in the region
//   (o) menu-floor-ref        - a "floor-referenced*" marker attached to a slug other than
//                                oauth-mission-containment/mission-metering, or either of
//                                those two missing the marker in the menu region or not
//                                carrying it exactly once in the matrix rows

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { validateExternalPins } from "./check-external-pins.mjs";
import { validateBundleManifests } from "./check-bundle-manifest.mjs";

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

// Parses the data rows of a "Document | Zone | Track | Group | Pull this
// when..." markdown table out of a section body. Tolerant of surrounding
// whitespace around cells; strict about shape: a row only counts as a
// document row when its first cell opens with a backtick-quoted slug,
// either bare (`` `slug` ``) or as a linked code label
// (`` [`slug`](url) ``), which also lets the header and separator rows
// fall out without special-casing them. Trailing text after the slug/link
// (e.g. a "floor-referenced*" marker) is ignored, wherever the marker sits.
function parseAdoptionMapRows(section) {
  const rows = [];
  for (const line of section.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed.startsWith("|") || !trimmed.endsWith("|")) continue;
    const inner = trimmed.slice(1, -1).split("|").map((c) => c.trim());
    if (inner.length < 5) continue;
    const linkMatch = inner[0].match(/^\[`([^`]+)`\]\([^)]+\)/);
    const bareMatch = inner[0].match(/^`([^`]+)`/);
    const slugMatch = linkMatch || bareMatch;
    if (!slugMatch) continue;
    rows.push({
      slug: slugMatch[1],
      zone: inner[1],
      track: inner[2],
      group: inner[3],
      trigger: inner.slice(4).join("|").trim(),
      line,
    });
  }
  return rows;
}

// Extracts README's hand-authored adoption-map menu: the text between the
// exact line "## The adoption map" and the first subsequent exact line
// "<details>" (the machine-validated matrix (g) validates lives past that
// point). Unlike extractSection, this is anchored on the literal "<details>"
// line rather than the next heading, since the menu and the matrix share one
// "## The adoption map" section. Returns null if either anchor is missing.
function extractMenuRegion(markdown) {
  const lines = markdown.split("\n");
  const headingIdx = lines.findIndex((l) => l === "## The adoption map");
  if (headingIdx === -1) return null;
  let detailsIdx = -1;
  for (let i = headingIdx + 1; i < lines.length; i++) {
    if (lines[i].trim() === "<details>") {
      detailsIdx = i;
      break;
    }
  }
  if (detailsIdx === -1) return null;
  return lines.slice(headingIdx + 1, detailsIdx).join("\n");
}

// The menu displays a manifest maturity value under one shared vocabulary:
// stable and experimental and sketch display verbatim; informational
// displays as "guide" (a document that explains rather than defines).
// Returns null for a maturity value with no defined display word.
function maturityDisplay(maturity) {
  if (maturity === "stable" || maturity === "experimental" || maturity === "sketch") return maturity;
  if (maturity === "informational") return "guide";
  return null;
}

// Collects every backtick-quoted token (`` `token` ``, bare or inside a
// `[`token`](url)` link) out of a text blob, e.g. the menu region. Backticks
// are exact delimiters, so this cannot mistake a short slug for a substring
// of a longer one the way plain containment matching could.
function extractBacktickedTokens(text) {
  const set = new Set();
  const re = /`([a-z0-9-]+)`/g;
  let m;
  while ((m = re.exec(text))) set.add(m[1]);
  return set;
}

// Parses every pipe-delimited markdown table out of a section, independent
// of column count (the menu's tables run 3 or 4 columns; the matrix table
// (g) parses runs 5). A table is a pipe row immediately followed by a
// separator row (cells of only "-", optionally colon-flanked) of the same
// width; every following pipe row is a data row until a non-pipe line ends
// the table.
function parseMarkdownTables(section) {
  const lines = section.split("\n");
  const isPipeRow = (l) => {
    const t = l.trim();
    return t.startsWith("|") && t.endsWith("|");
  };
  const splitRow = (l) => l.trim().slice(1, -1).split("|").map((c) => c.trim());
  const tables = [];
  let i = 0;
  while (i < lines.length) {
    if (isPipeRow(lines[i]) && i + 1 < lines.length && isPipeRow(lines[i + 1])) {
      const headerCells = splitRow(lines[i]);
      const sepCells = splitRow(lines[i + 1]);
      const isSeparator = sepCells.length === headerCells.length && sepCells.every((c) => /^:?-+:?$/.test(c));
      if (isSeparator) {
        const rows = [];
        let j = i + 2;
        while (j < lines.length && isPipeRow(lines[j])) {
          rows.push({ cells: splitRow(lines[j]), line: lines[j] });
          j++;
        }
        tables.push({ headerCells, rows });
        i = j;
        continue;
      }
    }
    i++;
  }
  return tables;
}

// Every backtick-quoted short slug linked anywhere in a table row (any
// cell), used both to find which manifest drafts a row names and to check
// (m)'s inline-badge and floor-referenced pairing patterns against a whole
// row rather than a single cell.
function slugsLinkedInRow(rowCells) {
  return extractBacktickedTokens(rowCells.join(" | "));
}

// Scans pipe-table-row lines only (never free-standing prose) for the
// literal marker "floor-referenced*", pairing each occurrence with whatever
// backtick-quoted slug's link immediately precedes it on that line. Prose
// glossary lines that merely discuss the marker (never inside a table row)
// are intentionally out of scope: (o) validates a display convention that
// only exists inside table cells.
function scanFloorReferencedMarkers(text) {
  const MARKER = "floor-referenced*";
  const pairRe = /\[`([a-z0-9-]+)`\]\([^)]*\)\s*floor-referenced\*/g;
  const paired = []; // { slug, line }
  const unpaired = []; // { line } - marker present but no slug link precedes it
  for (const line of text.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed.startsWith("|") || !trimmed.endsWith("|")) continue;
    const markerCount = line.split(MARKER).length - 1;
    if (markerCount === 0) continue;
    let pairedOnLine = 0;
    let m;
    pairRe.lastIndex = 0;
    while ((m = pairRe.exec(line))) {
      paired.push({ slug: m[1], line });
      pairedOnLine++;
    }
    for (let k = pairedOnLine; k < markerCount; k++) unpaired.push({ line });
  }
  return { paired, unpaired };
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

  // (f) presentation enum: presentation_zone/presentation_track must be one
  // of the manifest's own declared values, and those declared arrays
  // themselves must be non-empty, string-valued, and duplicate-free.
  function validateEnumArray(name, arr) {
    if (!Array.isArray(arr) || arr.length === 0) {
      fail("presentation-enum", `family-manifest.json's top-level "${name}" must be a non-empty array`);
      return;
    }
    const seen = new Set();
    for (const v of arr) {
      if (typeof v !== "string" || v.length === 0) {
        fail("presentation-enum", `family-manifest.json's "${name}" contains a non-string or empty entry: ${JSON.stringify(v)}`);
        continue;
      }
      if (seen.has(v)) {
        fail("presentation-enum", `family-manifest.json's "${name}" has a duplicate entry: "${v}"`);
      }
      seen.add(v);
    }
  }
  validateEnumArray("presentation_zones", manifest.presentation_zones);
  validateEnumArray("presentation_tracks", manifest.presentation_tracks);
  const validZones = new Set(manifest.presentation_zones || []);
  const validTracks = new Set(manifest.presentation_tracks || []);
  for (const d of drafts) {
    if (!validZones.has(d.presentation_zone)) {
      fail("presentation-enum", `${d.slug}: presentation_zone "${d.presentation_zone}" is not one of ${JSON.stringify([...validZones])}`);
    }
    if (!validTracks.has(d.presentation_track)) {
      fail("presentation-enum", `${d.slug}: presentation_track "${d.presentation_track}" is not one of ${JSON.stringify([...validTracks])}`);
    }
  }

  // (g) Adoption map coverage: every draft must appear exactly once in
  // README's "The adoption map" table, on a row whose Zone and Track cells
  // match the manifest's declared presentation_zone/presentation_track.
  const adoptionMapSection = extractSection(readme, (t, l) => l === 2 && t === "The adoption map");
  if (adoptionMapSection === null) {
    fail("adoption-map", `could not find a "## The adoption map" section in README.md`);
  } else {
    const rows = parseAdoptionMapRows(adoptionMapSection);
    if (rows.length !== drafts.length) {
      fail(
        "adoption-map",
        `README's "The adoption map" table has ${rows.length} document row(s) but family-manifest.json has ${drafts.length} drafts`
      );
    }
    for (const d of drafts) {
      const short = shortForm(d.slug);
      const matches = rows.filter((r) => r.slug === short);
      if (matches.length === 0) {
        fail("adoption-map", `${d.slug} (short form "${short}") is not listed in README's "The adoption map" table`);
        continue;
      }
      if (matches.length > 1) {
        fail("adoption-map", `${d.slug} (short form "${short}") appears ${matches.length} times in README's "The adoption map" table`);
      }
      const row = matches[0];
      if (row.zone !== d.presentation_zone) {
        fail(
          "adoption-map",
          `${d.slug}: adoption map row has Zone "${row.zone}" but manifest declares presentation_zone "${d.presentation_zone}"`
        );
      }
      if (row.track !== d.presentation_track) {
        fail(
          "adoption-map",
          `${d.slug}: adoption map row has Track "${row.track}" but manifest declares presentation_track "${d.presentation_track}"`
        );
      }
      if (row.group !== d.group) {
        fail(
          "adoption-map",
          `${d.slug}: adoption map row has Group "${row.group}" but manifest declares group "${d.group}"`
        );
      }
      if (row.trigger === "") {
        fail("adoption-map", `${d.slug}: adoption map row has an empty "Pull this when..." cell`);
      }
    }
  }

  // (l)-(o): the hand-authored adoption-map menu (the ten-pick prose above
  // the matrix table (g) validates). See extractMenuRegion for the exact
  // boundary: the "## The adoption map" heading line through the first
  // "<details>" line.
  const menuRegion = extractMenuRegion(readme);
  if (menuRegion === null) {
    fail("menu-coverage", `could not find README's adoption-map menu region (exact lines "## The adoption map" and "<details>")`);
  } else {
    // (l) Menu slug coverage: every draft must be named at least once in
    // the menu region as a backtick-quoted short slug.
    const menuSlugs = extractBacktickedTokens(menuRegion);
    for (const d of drafts) {
      const short = shortForm(d.slug);
      if (!menuSlugs.has(short)) {
        fail("menu-coverage", `${d.slug} (short form "${short}") does not appear as a backtick-quoted slug anywhere in README's adoption-map menu region`);
      }
    }

    // (m) Menu maturity display: the menu shows a manifest maturity as
    // "stable" (unmarked inline) or the literal word (table cells), and
    // "experimental"/"sketch" verbatim, or "guide" for informational. Checks,
    // in order: (m-a) inline "[`slug`](url) (word)" suffix badges;
    // (m-b) the trailing "Maturity" or "Family maturity" column of a menu table; (m-c) that
    // every non-stable draft is shown correctly by one of those two forms,
    // or, failing that, by the expected word appearing as a parenthetical
    // elsewhere in a table row that links the slug (how the Baseline
    // table's "Transaction assurance (experimental)" row marks a document
    // outside any "Maturity"-headed table).
    const shortToDraft = new Map(drafts.map((d) => [shortForm(d.slug), d]));
    const correctlyMarked = new Set();

    const INLINE_BADGE_RE = /\[`([a-z0-9-]+)`\]\([^)]*\)\s\((guide|experimental|sketch|stable)\)/g;
    let im;
    while ((im = INLINE_BADGE_RE.exec(menuRegion))) {
      const [, slug, badge] = im;
      const d = shortToDraft.get(slug);
      if (!d) continue;
      const expected = maturityDisplay(d.maturity);
      if (badge === expected) {
        correctlyMarked.add(slug);
      } else {
        fail(
          "menu-maturity",
          `${d.slug}: menu shows inline maturity badge "${badge}" but manifest maturity "${d.maturity}" displays as "${expected}"`
        );
      }
    }

    const menuTables = parseMarkdownTables(menuRegion);
    for (const table of menuTables) {
      const lastHeader = table.headerCells[table.headerCells.length - 1];
    if (lastHeader !== "Maturity" && lastHeader !== "Family maturity") continue;
      for (const row of table.rows) {
        const linked = slugsLinkedInRow(row.cells);
        if (linked.size === 0) continue;
        const cellValue = row.cells[row.cells.length - 1];
        for (const slug of linked) {
          const d = shortToDraft.get(slug);
          if (!d) continue;
          const expected = maturityDisplay(d.maturity);
          if (cellValue === expected) {
            correctlyMarked.add(slug);
          } else {
            fail(
              "menu-maturity",
              `${d.slug}: menu's Maturity column shows "${cellValue}" on the row linking it, but manifest maturity "${d.maturity}" displays as "${expected}"`
            );
          }
        }
      }
    }

    for (const d of drafts) {
      if (d.maturity === "stable") continue;
      const short = shortForm(d.slug);
      if (correctlyMarked.has(short)) continue;
      const expected = maturityDisplay(d.maturity);
      let markedByRowParenthetical = false;
      for (const table of menuTables) {
        for (const row of table.rows) {
          if (!slugsLinkedInRow(row.cells).has(short)) continue;
          if (row.cells.some((c) => c.includes(`(${expected})`))) {
            markedByRowParenthetical = true;
            break;
          }
        }
        if (markedByRowParenthetical) break;
      }
      if (!markedByRowParenthetical) {
        fail(
          "menu-maturity",
          `${d.slug}: manifest maturity "${d.maturity}" (displays as "${expected}") is not shown anywhere in README's adoption-map menu region (no inline badge, Maturity-column cell, or row parenthetical)`
        );
      }
    }

    // (n) Pick-reference resolution: every "pick N" / "picks N and M"
    // mention in the menu region must resolve to an existing bolded
    // "**N." pick heading in the region.
    const pickHeadings = new Set();
    const HEADING_RE = /\*\*(\d+)\./g;
    let hm;
    while ((hm = HEADING_RE.exec(menuRegion))) pickHeadings.add(hm[1]);

    const pickRefs = new Set();
    const PICK_WORD_RE = /pick[s]?(?=\s+\d)/gi;
    let pm;
    while ((pm = PICK_WORD_RE.exec(menuRegion))) {
      const start = pm.index + pm[0].length;
      const window = menuRegion.slice(start, start + 20);
      for (const n of window.match(/\d+/g) || []) pickRefs.add(n);
    }
    for (const n of pickRefs) {
      if (!pickHeadings.has(n)) {
        fail("menu-picks", `menu region references "pick ${n}" but no bolded "**${n}." pick heading exists in the region`);
      }
    }

    // (o) floor-referenced pairing: the literal marker "floor-referenced*"
    // may only follow the slug link for oauth-mission-containment or
    // mission-metering (the floor's conditional text names those two by
    // property). Scans pipe-table rows only in both the menu region and
    // the matrix rows (g) already isolated; the marker's two prose
    // glossary explanations sit outside any table row and are descriptive
    // text, not table-cell display, so they are out of scope by design.
    const FLOOR_REF_SLUGS = ["oauth-mission-containment", "mission-metering"];

    const menuFloorRef = scanFloorReferencedMarkers(menuRegion);
    for (const bad of menuFloorRef.unpaired) {
      fail("menu-floor-ref", `menu region has a "floor-referenced*" marker with no slug link immediately preceding it: ${bad.line.trim()}`);
    }
    for (const p of menuFloorRef.paired) {
      if (!FLOOR_REF_SLUGS.includes(p.slug)) {
        fail("menu-floor-ref", `menu region attaches "floor-referenced*" to ${p.slug}, but only ${FLOOR_REF_SLUGS.join(" and ")} may carry it`);
      }
    }
    const menuFloorRefCounts = new Map(FLOOR_REF_SLUGS.map((s) => [s, 0]));
    for (const p of menuFloorRef.paired) {
      if (menuFloorRefCounts.has(p.slug)) menuFloorRefCounts.set(p.slug, menuFloorRefCounts.get(p.slug) + 1);
    }
    for (const slug of FLOOR_REF_SLUGS) {
      if (menuFloorRefCounts.get(slug) === 0) {
        fail("menu-floor-ref", `${slug} must carry the "floor-referenced*" marker at least once in the menu region, but it does not`);
      }
    }

    if (adoptionMapSection !== null) {
      const matrixRowsForFloorRef = parseAdoptionMapRows(adoptionMapSection);
      const matrixText = matrixRowsForFloorRef.map((r) => r.line).join("\n");
      const matrixFloorRef = scanFloorReferencedMarkers(matrixText);
      for (const bad of matrixFloorRef.unpaired) {
        fail("menu-floor-ref", `matrix rows have a "floor-referenced*" marker with no slug link immediately preceding it: ${bad.line.trim()}`);
      }
      for (const p of matrixFloorRef.paired) {
        if (!FLOOR_REF_SLUGS.includes(p.slug)) {
          fail("menu-floor-ref", `matrix rows attach "floor-referenced*" to ${p.slug}, but only ${FLOOR_REF_SLUGS.join(" and ")} may carry it`);
        }
      }
      const matrixFloorRefCounts = new Map(FLOOR_REF_SLUGS.map((s) => [s, 0]));
      for (const p of matrixFloorRef.paired) {
        if (matrixFloorRefCounts.has(p.slug)) matrixFloorRefCounts.set(p.slug, matrixFloorRefCounts.get(p.slug) + 1);
      }
      for (const slug of FLOOR_REF_SLUGS) {
        const count = matrixFloorRefCounts.get(slug);
        if (count !== 1) {
          fail("menu-floor-ref", `${slug} must carry the "floor-referenced*" marker exactly once in the matrix rows, but it appears ${count} time(s)`);
        }
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
