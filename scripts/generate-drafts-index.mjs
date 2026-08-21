#!/usr/bin/env node
// Generates DRAFTS.md's index table from family-manifest.json.
//
// The block between the two marker comments in DRAFTS.md is generated; every
// other line of that file is hand-authored and never touched here.
//
// Usage:
//   node scripts/generate-drafts-index.mjs           rewrite the block in place
//   node scripts/generate-drafts-index.mjs --check   exit 1 if the block is stale
//
// Dependency-free (Node core only). scripts/check-family-manifest.mjs chains
// --check, so a stale block fails the family-manifest CI step.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..");

export const MANIFEST_PATH = path.join(ROOT, "family-manifest.json");
export const DRAFTS_PATH = path.join(ROOT, "DRAFTS.md");

export const START_MARKER = "<!-- generated:drafts-index:start -->";
export const END_MARKER = "<!-- generated:drafts-index:end -->";

const EDITORS_COPY_BASE = "https://mcguinness.github.io/mission-bound-authorization/#go.";

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
    lines.push(`| [${d.title}](${editorsCopyUrl(d.slug)}) | ${maturity} | ${verbs} | ${d.summary} | ${d.pull_when} |`);
  }
  lines.push("", END_MARKER);
  return lines.join("\n");
}

// Splices a freshly rendered block into DRAFTS.md's text. Throws when either
// marker is missing or out of order, so a mangled file fails loudly rather
// than getting a second block appended.
export function spliceIndex(text, block) {
  const startIdx = text.indexOf(START_MARKER);
  const endIdx = text.indexOf(END_MARKER);
  if (startIdx === -1) throw new Error(`DRAFTS.md is missing the marker ${START_MARKER}`);
  if (endIdx === -1) throw new Error(`DRAFTS.md is missing the marker ${END_MARKER}`);
  if (endIdx < startIdx) throw new Error(`DRAFTS.md has ${END_MARKER} before ${START_MARKER}`);
  return text.slice(0, startIdx) + block + text.slice(endIdx + END_MARKER.length);
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

function main() {
  const check = process.argv.includes("--check");
  if (check) {
    const findings = validateDraftsIndex(ROOT);
    if (findings.length > 0) {
      for (const f of findings) console.error(`drafts-index check FAILED: ${f}`);
      process.exit(1);
    }
    console.log("drafts-index check OK: DRAFTS.md's generated block is current.");
    process.exit(0);
  }

  const manifest = JSON.parse(fs.readFileSync(MANIFEST_PATH, "utf8"));
  const text = fs.readFileSync(DRAFTS_PATH, "utf8");
  const updated = spliceIndex(text, renderIndex(manifest));
  if (updated === text) {
    console.log(`drafts-index: DRAFTS.md already current (${manifest.drafts.length} rows).`);
    return;
  }
  fs.writeFileSync(DRAFTS_PATH, updated);
  console.log(`drafts-index: rewrote DRAFTS.md's generated block (${manifest.drafts.length} rows).`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main();
}
