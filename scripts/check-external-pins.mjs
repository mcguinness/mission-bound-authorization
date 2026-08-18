#!/usr/bin/env node
// Structural validation for notes/external-pins.json, the machine-readable
// registry of external planning pins. This checks shape only: unique ids,
// a "kind" in the enum with its kind-appropriate required fields, full-SHA
// commit + path + 64-hex sha256 on "established" git entries, doc + rev +
// url + 64-hex sha256 on "established" datatracker entries, publisher +
// edition on "established" standard entries (sha256 optional there), and
// null kind-specific fields on "pending" entries. It does NOT verify that
// a commit exists, that a blob lives at a path, or that a digest matches
// live content; that independent verification happens at Ship 3 against
// the source repositories (see the registry's own "description" field and
// scripts/check-bundle-manifest.mjs, which also enforces that no "pending"
// entry is consumed by a bundle build).
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
const KIND_VALUES = new Set(["git", "datatracker", "standard"]);
const FULL_SHA_RE = /^[0-9a-f]{40}$/;
const SHA256_RE = /^[0-9a-f]{64}$/;

function isNonEmptyString(v) {
  return typeof v === "string" && v.trim() !== "";
}

// Kind-specific field groups. `identityField` names what is being pinned
// (which repo, which datatracker document, which standard) and is always
// required, even while pending: it is the breadcrumb of what still needs
// establishing. `pinFields` are the specifics of the pin itself; they must
// be null while pending and are validated in kind-appropriate shape once
// established. `sha256Required` is false only for "standard", whose
// entries may cite a paywalled publication with no fetchable canonical
// file to hash (disclosed via the always-required "note" field instead).
const KIND_FIELDS = {
  git: { identityField: "repo", pinFields: ["commit", "path", "sha256"], sha256Required: true },
  datatracker: { identityField: "doc", pinFields: ["rev", "url", "sha256"], sha256Required: true },
  standard: { identityField: "publisher", pinFields: ["edition", "sha256"], sha256Required: false },
};

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

    if (!KIND_VALUES.has(entry.kind)) {
      errors.push(`${label}: "kind" must be one of [${[...KIND_VALUES].join(", ")}], got ${JSON.stringify(entry.kind)}`);
      return;
    }

    const { identityField, pinFields, sha256Required } = KIND_FIELDS[entry.kind];

    // The identity field (repo / doc / publisher) is always required,
    // regardless of status: it names what is being pinned even before the
    // pin itself is established.
    if (!isNonEmptyString(entry[identityField])) {
      errors.push(`${label}: ${entry.kind} entry needs a non-empty "${identityField}"`);
    }

    if (entry.status === "established") {
      for (const field of pinFields) {
        if (field === "sha256") continue; // handled below, kind-dependent requiredness
        if (field === "commit") {
          if (!FULL_SHA_RE.test(entry.commit ?? "")) {
            errors.push(`${label}: established ${entry.kind} entry needs a full 40-hex "commit", got ${JSON.stringify(entry.commit)}`);
          }
          continue;
        }
        if (!isNonEmptyString(entry[field])) {
          errors.push(`${label}: established ${entry.kind} entry needs a non-empty "${field}"`);
        }
      }

      if (sha256Required) {
        if (!SHA256_RE.test(entry.sha256 ?? "")) {
          errors.push(`${label}: established ${entry.kind} entry needs a 64-hex "sha256", got ${JSON.stringify(entry.sha256)}`);
        }
      } else if (entry.sha256 !== null && !SHA256_RE.test(entry.sha256)) {
        // kind "standard": sha256 is optional (null), but if present it must
        // be a real 64-hex digest, not a placeholder.
        errors.push(`${label}: established ${entry.kind} entry's "sha256" must be null or a 64-hex digest, got ${JSON.stringify(entry.sha256)}`);
      }
    } else {
      // pending: every pin-specific field (including sha256) must be null,
      // regardless of whether that kind requires sha256 once established.
      // The identity field, checked above, stays required.
      for (const field of pinFields) {
        if (entry[field] !== null) {
          errors.push(`${label}: pending ${entry.kind} entry must have "${field}": null, got ${JSON.stringify(entry[field])}`);
        }
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
