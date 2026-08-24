#!/usr/bin/env node
// Generates two marker-delimited blocks from family-manifest.json: DRAFTS.md's
// index table, and README.md's per-binding minimum-package table (#709: verbs
// are the README's public front door, and the minimum document package a
// reader sees after choosing a binding is generated so its counts cannot
// drift from the manifest). Everything outside a file's markers is
// hand-authored and never touched here.
//
// Usage:
//   node scripts/generate-drafts-index.mjs           rewrite both blocks in place
//   node scripts/generate-drafts-index.mjs --check   exit 1 if either block is stale
//
// Dependency-free (Node core only). scripts/check-family-manifest.mjs chains
// --check, so a stale block fails the family-manifest CI step.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { REGISTRY as SUBSTRATE_STATEMENT_REGISTRY } from "./check-substrate-statements.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..");

export const MANIFEST_PATH = path.join(ROOT, "family-manifest.json");
export const DRAFTS_PATH = path.join(ROOT, "DRAFTS.md");
export const README_PATH = path.join(ROOT, "README.md");

export const START_MARKER = "<!-- generated:drafts-index:start -->";
export const END_MARKER = "<!-- generated:drafts-index:end -->";

export const BINDING_PACKAGES_START = "<!-- generated:binding-packages:start -->";
export const BINDING_PACKAGES_END = "<!-- generated:binding-packages:end -->";

// The family's peer bindings, in the README's display order: every manifest
// slug that has published a Mission Substrate Statement capability table
// (check-substrate-statements.mjs's REGISTRY). Publishing that table is what
// "binding" means architecturally, and that file's own tripwires already fail
// CI the moment a table appears anywhere in the corpus without a matching
// registry entry, so this derived list cannot go stale the way a second,
// independent hardcoded list could.
export const BINDING_SLUGS = SUBSTRATE_STATEMENT_REGISTRY.map((e) => e.slug);

const EDITORS_COPY_BASE = "https://mcguinness.github.io/mission-bound-authorization/#go.";

// The one editor's-copy link convention, shared with the family checker so
// the link-validation regex cannot drift from the URLs this file emits.
export const GO_LINK_PATTERN = "#go\\.(draft-[a-z0-9-]+)\\.html";

// A manifest maturity value under the family's one display vocabulary: stable,
// experimental, and sketch display verbatim; informational displays as "guide"
// (a document that explains rather than defines). Returns null for a value with
// no defined display word.
export function maturityDisplay(maturity) {
  if (maturity === "stable" || maturity === "experimental" || maturity === "sketch") return maturity;
  if (maturity === "informational") return "guide";
  return null;
}

export function editorsCopyUrl(slug) {
  return `${EDITORS_COPY_BASE}${slug}.html`;
}

// Manifest strings land inside a Markdown table: a literal pipe would open a
// phantom column and a newline would end the row, so both are neutralized
// here rather than banned in the manifest.
export function escapeCell(value) {
  return String(value).replace(/\|/g, "\\|").replace(/\s*\r?\n\s*/g, " ");
}

// The generated block, markers included, in manifest order.
export function renderIndex(manifest) {
  const lines = [
    START_MARKER,
    "",
    "| Document | Maturity | Verbs | Summary | Pull this in when |",
    "|---|---|---|---|---|",
  ];
  for (const d of manifest.drafts) {
    const maturity = maturityDisplay(d.maturity) ?? d.maturity;
    const verbs = (d.verbs || []).join(", ");
    lines.push(
      `| [${escapeCell(d.title)}](${editorsCopyUrl(d.slug)}) | ${maturity} | ${verbs} | ${escapeCell(d.summary)} | ${escapeCell(d.pull_when)} |`
    );
  }
  lines.push("", END_MARKER);
  return lines.join("\n");
}

// Splices a freshly rendered block into `text` between one marker pair.
// Throws when either marker is missing or out of order, so a mangled file
// fails loudly rather than getting a second block appended.
function spliceMarkedBlock(text, block, startMarker, endMarker, label) {
  const startIdx = text.indexOf(startMarker);
  const endIdx = text.indexOf(endMarker);
  if (startIdx === -1) throw new Error(`${label} is missing the marker ${startMarker}`);
  if (endIdx === -1) throw new Error(`${label} is missing the marker ${endMarker}`);
  if (endIdx < startIdx) throw new Error(`${label} has ${endMarker} before ${startMarker}`);
  // A duplicated block (bad merge, stray paste) must fail loudly: with only
  // first-occurrence splicing, the second, stale copy would ship while the
  // freshness check reports "current".
  if (text.indexOf(startMarker, startIdx + startMarker.length) !== -1) {
    throw new Error(`${label} contains ${startMarker} more than once`);
  }
  if (text.indexOf(endMarker, endIdx + endMarker.length) !== -1) {
    throw new Error(`${label} contains ${endMarker} more than once`);
  }
  return text.slice(0, startIdx) + block + text.slice(endIdx + endMarker.length);
}

// Splices a freshly rendered block into DRAFTS.md's text.
export function spliceIndex(text, block) {
  return spliceMarkedBlock(text, block, START_MARKER, END_MARKER, "DRAFTS.md");
}

// Returns [] when DRAFTS.md's generated block matches what the manifest would
// produce, or a one-entry findings array when it does not. Never writes.
export function validateDraftsIndex(root = ROOT) {
  const manifestPath = path.join(root, "family-manifest.json");
  const draftsPath = path.join(root, "DRAFTS.md");
  let manifest;
  try {
    manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  } catch (e) {
    return [`cannot read family-manifest.json: ${e.message}`];
  }
  let text;
  try {
    text = fs.readFileSync(draftsPath, "utf8");
  } catch (e) {
    return [`cannot read DRAFTS.md: ${e.message}`];
  }
  let expected;
  try {
    expected = spliceIndex(text, renderIndex(manifest));
  } catch (e) {
    return [e.message];
  }
  if (expected !== text) {
    return [
      "DRAFTS.md's generated index block is stale; run `node scripts/generate-drafts-index.mjs` to regenerate it",
    ];
  }
  return [];
}

// Transitive closure of a draft's `adoption_requires` edges: the only edges
// that close for adoption (scripts/check-family-manifest.mjs's typed-edges
// check keeps them a subset of the draft's normative references). Returns an
// array of slugs, dependencies before the draft itself, deduplicated. Throws
// on a cycle or an unknown slug so a malformed manifest fails loudly instead
// of looping or returning a silently incomplete package.
export function adoptionClosure(manifest, slug) {
  const bySlug = new Map(manifest.drafts.map((d) => [d.slug, d]));
  const order = [];
  const done = new Set();
  const visiting = new Set();
  function visit(s) {
    if (done.has(s)) return;
    if (visiting.has(s)) throw new Error(`adoption_requires cycle at "${s}"`);
    const d = bySlug.get(s);
    if (!d) throw new Error(`"${s}" is not a manifest draft slug`);
    visiting.add(s);
    for (const dep of d.adoption_requires || []) visit(dep);
    visiting.delete(s);
    done.add(s);
    order.push(s);
  }
  visit(slug);
  return order;
}

// The generated block, markers included: for each peer binding (BINDING_SLUGS,
// derived from the Mission Substrate Statement registry), its adoption
// closure as a document count and list, so a reader who has chosen a binding
// sees the minimum package without the prose restating a count that could
// drift from the manifest.
export function renderBindingPackages(manifest) {
  const bySlug = new Map(manifest.drafts.map((d) => [d.slug, d]));
  const lines = [
    BINDING_PACKAGES_START,
    "",
    "| Binding | Minimum package |",
    "|---|---|",
  ];
  for (const slug of BINDING_SLUGS) {
    const closure = adoptionClosure(manifest, slug);
    const bindingTitle = escapeCell(bySlug.get(slug).title);
    const count = closure.length;
    const noun = count === 1 ? "document" : "documents";
    const contents = count === 1 ? "itself alone" : closure.map((s) => escapeCell(bySlug.get(s).title)).join(" + ");
    lines.push(`| ${bindingTitle} | ${count} ${noun}: ${contents} |`);
  }
  lines.push("", BINDING_PACKAGES_END);
  return lines.join("\n");
}

// Splices a freshly rendered binding-packages block into README.md's text.
export function spliceBindingPackages(text, block) {
  return spliceMarkedBlock(text, block, BINDING_PACKAGES_START, BINDING_PACKAGES_END, "README.md");
}

// Returns [] when README.md's generated binding-packages block matches what
// the manifest would produce (and BINDING_SLUGS names only real manifest
// drafts), or a one-entry findings array when it does not. Never writes.
export function validateBindingPackages(root = ROOT) {
  const manifestPath = path.join(root, "family-manifest.json");
  const readmePath = path.join(root, "README.md");
  let manifest;
  try {
    manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  } catch (e) {
    return [`cannot read family-manifest.json: ${e.message}`];
  }
  const manifestSlugs = new Set(manifest.drafts.map((d) => d.slug));
  for (const slug of BINDING_SLUGS) {
    if (!manifestSlugs.has(slug)) {
      return [`BINDING_SLUGS (from check-substrate-statements.mjs's REGISTRY) names "${slug}", which is not a family-manifest.json draft slug`];
    }
  }
  let text;
  try {
    text = fs.readFileSync(readmePath, "utf8");
  } catch (e) {
    return [`cannot read README.md: ${e.message}`];
  }
  let block;
  try {
    block = renderBindingPackages(manifest);
  } catch (e) {
    return [e.message];
  }
  let expected;
  try {
    expected = spliceBindingPackages(text, block);
  } catch (e) {
    return [e.message];
  }
  if (expected !== text) {
    return [
      "README.md's generated binding-packages block is stale; run `node scripts/generate-drafts-index.mjs` to regenerate it",
    ];
  }
  return [];
}

function main() {
  const check = process.argv.includes("--check");
  if (check) {
    const findings = [...validateDraftsIndex(ROOT), ...validateBindingPackages(ROOT)];
    if (findings.length > 0) {
      for (const f of findings) console.error(`drafts-index check FAILED: ${f}`);
      process.exit(1);
    }
    console.log("drafts-index check OK: DRAFTS.md's and README.md's generated blocks are current.");
    process.exit(0);
  }

  const manifest = JSON.parse(fs.readFileSync(MANIFEST_PATH, "utf8"));

  const draftsText = fs.readFileSync(DRAFTS_PATH, "utf8");
  const updatedDrafts = spliceIndex(draftsText, renderIndex(manifest));
  if (updatedDrafts === draftsText) {
    console.log(`drafts-index: DRAFTS.md already current (${manifest.drafts.length} rows).`);
  } else {
    fs.writeFileSync(DRAFTS_PATH, updatedDrafts);
    console.log(`drafts-index: rewrote DRAFTS.md's generated block (${manifest.drafts.length} rows).`);
  }

  const readmeText = fs.readFileSync(README_PATH, "utf8");
  const updatedReadme = spliceBindingPackages(readmeText, renderBindingPackages(manifest));
  if (updatedReadme === readmeText) {
    console.log(`drafts-index: README.md's binding-packages block already current (${BINDING_SLUGS.length} bindings).`);
  } else {
    fs.writeFileSync(README_PATH, updatedReadme);
    console.log(`drafts-index: rewrote README.md's binding-packages block (${BINDING_SLUGS.length} bindings).`);
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main();
}
