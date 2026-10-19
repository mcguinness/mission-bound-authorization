#!/usr/bin/env node
// Canonical digest encoding check (#1188). Every `sha-256:<base64url>` value
// in draft-*.md must decode and re-encode to itself: a 43-character value for
// a 32-byte digest carries two padding bits in its last character that
// canonical encoding leaves zero (RFC 4648 Section 3.5).
//
// Usage: node scripts/check-canonical-digests.mjs

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const VALUE = /sha-256:([A-Za-z0-9_-]{43})(?![A-Za-z0-9_-])/g;

export function findNonCanonical(text) {
  const out = [];
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    for (const m of lines[i].matchAll(VALUE)) {
      const canon = Buffer.from(m[1], "base64url").toString("base64url");
      if (canon !== m[1]) out.push({ line: i + 1, value: m[1], canonical: canon });
    }
  }
  return out;
}

function main() {
  const files = fs.readdirSync(ROOT).filter((f) => /^draft-.*\.md$/.test(f)).sort();
  const errors = [];
  for (const f of files) {
    for (const r of findNonCanonical(fs.readFileSync(path.join(ROOT, f), "utf8"))) {
      errors.push(`${f}:${r.line}: sha-256:${r.value} is not canonical base64url (canonical: ${r.canonical})`);
    }
  }
  if (errors.length > 0) {
    console.error(`canonical-digests check FAILED with ${errors.length} finding(s):\n`);
    for (const e of errors) console.error(`  - ${e}`);
    process.exit(1);
  }
  console.log(`canonical-digests check OK: ${files.length} drafts, every sha-256 value is canonical.`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
