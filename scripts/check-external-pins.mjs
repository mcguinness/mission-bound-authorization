#!/usr/bin/env node
// Structural validation for notes/external-pins.json, the machine-readable
// registry of external planning pins. This checks shape only: unique ids,
// full-SHA commit + path + 64-hex sha256 on "established" entries, null pin
// fields on "pending" entries, status in the enum. It does NOT verify that
// a commit exists, that a blob lives at a path, or that a digest matches
// live content; that independent verification happens at Ship 3 against
// the source repositories (see the registry's own "description" field).
//
// Usage: node scripts/check-external-pins.mjs
// Also imported by scripts/check-family-manifest.mjs, which calls
// validateExternalPins() as part of its own check so CI needs no separate
// workflow step.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const STATUS_VALUES = new Set(["established", "pending"]);
const FULL_SHA_RE = /^[0-9a-f]{40}$/;
const SHA256_RE = /^[0-9a-f]{64}$/;

export function validateExternalPins(rootDir) {
  const pinsPath = path.join(rootDir, "notes", "external-pins.json");
  const errors = [];

  let raw;
  try {
    raw = fs.readFileSync(pinsPath, "utf8");
  } catch (e) {
    return [`cannot read ${pinsPath}: ${e.message}`];
  }

  let doc;
  try {
    doc = JSON.parse(raw);
  } catch (e) {
    return [`${pinsPath} is not valid JSON: ${e.message}`];
  }

  if (typeof doc.description !== "string" || doc.description.trim() === "") {
    errors.push(`${pinsPath}: missing a non-empty top-level "description"`);
  }

  if (!Array.isArray(doc.pins)) {
    errors.push(`${pinsPath}: missing a top-level "pins" array`);
    return errors;
  }

  const seenIds = new Set();

  doc.pins.forEach((entry, i) => {
    const label = entry && typeof entry.id === "string" && entry.id.trim() !== "" ? entry.id : `pins[${i}]`;

    if (!entry || typeof entry !== "object") {
      errors.push(`pins[${i}]: entry is not an object`);
      return;
    }

    if (typeof entry.id !== "string" || entry.id.trim() === "") {
      errors.push(`pins[${i}]: missing a non-empty string "id"`);
    } else if (seenIds.has(entry.id)) {
      errors.push(`${label}: duplicate id "${entry.id}"`);
    } else {
      seenIds.add(entry.id);
    }

    if (typeof entry.repo !== "string" || entry.repo.trim() === "") {
      errors.push(`${label}: missing a non-empty string "repo"`);
    }

    if (typeof entry.ref !== "string" || entry.ref.trim() === "") {
      errors.push(`${label}: missing a non-empty string "ref"`);
    }

    if (typeof entry.note !== "string" || entry.note.trim() === "") {
      errors.push(`${label}: missing a non-empty string "note"`);
    }

    if (!STATUS_VALUES.has(entry.status)) {
      errors.push(`${label}: "status" must be one of [${[...STATUS_VALUES].join(", ")}], got ${JSON.stringify(entry.status)}`);
      return;
    }

    if (entry.status === "established") {
      if (typeof entry.commit !== "string" || !FULL_SHA_RE.test(entry.commit)) {
        errors.push(`${label}: established entry needs a full 40-hex "commit", got ${JSON.stringify(entry.commit)}`);
      }
      if (typeof entry.path !== "string" || entry.path.trim() === "") {
        errors.push(`${label}: established entry needs a non-null "path"`);
      }
      if (typeof entry.sha256 !== "string" || !SHA256_RE.test(entry.sha256)) {
        errors.push(`${label}: established entry needs a 64-hex "sha256", got ${JSON.stringify(entry.sha256)}`);
      }
    } else {
      // pending
      if (entry.commit !== null) {
        errors.push(`${label}: pending entry must have "commit": null, got ${JSON.stringify(entry.commit)}`);
      }
      if (entry.path !== null) {
        errors.push(`${label}: pending entry must have "path": null, got ${JSON.stringify(entry.path)}`);
      }
      if (entry.sha256 !== null) {
        errors.push(`${label}: pending entry must have "sha256": null, got ${JSON.stringify(entry.sha256)}`);
      }
    }
  });

  return errors;
}

function main() {
  const rootDir = path.resolve(__dirname, "..");
  const errors = validateExternalPins(rootDir);

  if (errors.length > 0) {
    console.error(`external-pins check FAILED with ${errors.length} finding(s):\n`);
    for (const e of errors) console.error(`  - ${e}`);
    console.error("");
    process.exit(1);
  }

  console.log("external-pins check OK: structural validation passed.");
  process.exit(0);
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  main();
}
