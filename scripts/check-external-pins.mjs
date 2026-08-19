#!/usr/bin/env node
// Structural validation for notes/external-pins.json, the machine-readable
// registry of external planning pins. This checks shape only: unique ids,
// a "kind" in the enum with its kind-appropriate required fields, full-SHA
// commit + path + 64-hex sha256 on "established" git entries, doc + rev +
// url + 64-hex sha256 on "established" datatracker entries, publisher +
// edition on "established" standard entries (sha256 optional there), null
// kind-specific fields on "pending" entries, a non-empty "reference_keys"
// array of non-empty strings on every entry, and an immutable "pin_id" on
// every established entry (absent on pending entries). "pin_id" is
// `<id>@<first 12 hex of sha256>` when a real sha256 is pinned, or
// `<id>@<normalized edition>` for a kind "standard" entry with sha256
// null. The top-level "archive" array holds superseded established
// entries (structurally identical to a "pins" entry); pin_id uniqueness
// is enforced across "pins" and "archive" together, since a bundle
// resolves a pin_id against both. It does NOT verify that a commit
// exists, that a blob lives at a path, or that a digest matches live
// content; that independent verification happens at Ship 3 against the
// source repositories (see the registry's own "description" field and
// scripts/check-bundle-manifest.mjs, which also enforces that no
// "pending" entry is consumed by a bundle build).
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
const PIN_ID_RE = /^[A-Za-z][A-Za-z0-9_-]*@[A-Za-z0-9][A-Za-z0-9.-]*$/;
// A "digits:4-digit-year" pattern found in a standard's free-text edition
// string (e.g. "ISO 4217:2015, Codes for ..." -> "4217:2015"), used to
// mechanically derive the normalized-edition half of a standard's pin_id
// ("4217-2015"). Not a general edition-string parser; entries whose
// edition does not carry this pattern only get a format check on pin_id,
// not a recomputed-value check.
const EDITION_YEAR_RE = /\d+:\d{4}/;

function isNonEmptyString(v) {
  return typeof v === "string" && v.trim() !== "";
}

function isNonEmptyStringArray(v) {
  return Array.isArray(v) && v.length > 0 && v.every((s) => isNonEmptyString(s));
}

function normalizedEditionToken(edition) {
  const m = typeof edition === "string" ? edition.match(EDITION_YEAR_RE) : null;
  return m ? m[0].replace(":", "-") : null;
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

// Validates one entry (from either "pins" or "archive"). `seenIds` is
// scoped to "pins" alone (ids are a "pins" concept; archive entries keep
// the id they had when superseded, and may repeat one, so archive ids are
// not checked for uniqueness against seenIds). `pinIdSet` is shared across
// both collections, since pin_id uniqueness spans "pins" and "archive"
// together. `requireEstablished`, when true (archive entries), rejects a
// "pending" status outright.
function validateEntry(entry, collectionLabel, i, errors, seenIds, pinIdSet, requireEstablished) {
  const label = entry && typeof entry.id === "string" && entry.id.trim() !== "" ? entry.id : `${collectionLabel}[${i}]`;

  if (!entry || typeof entry !== "object") {
    errors.push(`${collectionLabel}[${i}]: entry is not an object`);
    return;
  }

  if (typeof entry.id !== "string" || entry.id.trim() === "") {
    errors.push(`${collectionLabel}[${i}]: missing a non-empty string "id"`);
  } else if (seenIds && seenIds.has(entry.id)) {
    errors.push(`${label}: duplicate id "${entry.id}"`);
  } else if (seenIds) {
    seenIds.add(entry.id);
  }

  if (typeof entry.ref !== "string" || entry.ref.trim() === "") {
    errors.push(`${label}: missing a non-empty string "ref"`);
  }

  if (typeof entry.note !== "string" || entry.note.trim() === "") {
    errors.push(`${label}: missing a non-empty string "note"`);
  }

  if (!isNonEmptyStringArray(entry.reference_keys)) {
    errors.push(`${label}: missing a non-empty array of non-empty strings "reference_keys"`);
  }

  if (!STATUS_VALUES.has(entry.status)) {
    errors.push(`${label}: "status" must be one of [${[...STATUS_VALUES].join(", ")}], got ${JSON.stringify(entry.status)}`);
    return;
  }

  if (requireEstablished && entry.status !== "established") {
    errors.push(`${label}: ${collectionLabel} entries must be "established" (superseded pins are archived once established), got ${JSON.stringify(entry.status)}`);
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

    let sha256Valid = false;
    if (sha256Required) {
      if (!SHA256_RE.test(entry.sha256 ?? "")) {
        errors.push(`${label}: established ${entry.kind} entry needs a 64-hex "sha256", got ${JSON.stringify(entry.sha256)}`);
      } else {
        sha256Valid = true;
      }
    } else if (entry.sha256 !== null && !SHA256_RE.test(entry.sha256)) {
      // kind "standard": sha256 is optional (null), but if present it must
      // be a real 64-hex digest, not a placeholder.
      errors.push(`${label}: established ${entry.kind} entry's "sha256" must be null or a 64-hex digest, got ${JSON.stringify(entry.sha256)}`);
    } else if (entry.sha256 !== null) {
      sha256Valid = true;
    }

    // pin_id: immutable identity. Content-addressed (id@first-12-hex-sha256)
    // when a real sha256 is pinned; edition-addressed
    // (id@normalized-edition) for a paywalled "standard" entry with sha256
    // null. Never present on a "pending" entry (checked in the else branch
    // below).
    if (typeof entry.pin_id !== "string" || !PIN_ID_RE.test(entry.pin_id)) {
      errors.push(`${label}: established entry needs a "pin_id" matching <id>@<token>, got ${JSON.stringify(entry.pin_id)}`);
    } else {
      if (pinIdSet.has(entry.pin_id)) {
        errors.push(`${label}: duplicate "pin_id" "${entry.pin_id}" across pins and archive`);
      } else {
        pinIdSet.add(entry.pin_id);
      }
      const idPart = isNonEmptyString(entry.id) ? entry.id : null;
      if (idPart && !entry.pin_id.startsWith(`${idPart}@`)) {
        errors.push(`${label}: "pin_id" "${entry.pin_id}" does not start with "${idPart}@"`);
      }
      if (sha256Valid && SHA256_RE.test(entry.sha256)) {
        const expected = `${idPart}@${entry.sha256.slice(0, 12)}`;
        if (entry.pin_id !== expected) {
          errors.push(`${label}: "pin_id" "${entry.pin_id}" does not match the expected content-addressed form "${expected}"`);
        }
      } else if (entry.kind === "standard" && entry.sha256 === null) {
        const normalized = normalizedEditionToken(entry.edition);
        if (normalized) {
          const expected = `${idPart}@${normalized}`;
          if (entry.pin_id !== expected) {
            errors.push(`${label}: "pin_id" "${entry.pin_id}" does not match the edition-derived form "${expected}"`);
          }
        }
      }
    }
  } else {
    // pending: every pin-specific field (including sha256) must be null,
    // regardless of whether that kind requires sha256 once established.
    // The identity field, checked above, stays required. A pending entry
    // never carries a pin_id at all (there is no content yet to address).
    for (const field of pinFields) {
      if (entry[field] !== null) {
        errors.push(`${label}: pending ${entry.kind} entry must have "${field}": null, got ${JSON.stringify(entry[field])}`);
      }
    }
    if (Object.prototype.hasOwnProperty.call(entry, "pin_id")) {
      errors.push(`${label}: pending entries must never carry a "pin_id", got ${JSON.stringify(entry.pin_id)}`);
    }
  }
}

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

  if (!Array.isArray(doc.archive)) {
    errors.push(`${pinsPath}: missing a top-level "archive" array (empty until a pin is first superseded)`);
  }

  const seenIds = new Set();
  const pinIdSet = new Set();

  doc.pins.forEach((entry, i) => validateEntry(entry, "pins", i, errors, seenIds, pinIdSet, false));
  (doc.archive ?? []).forEach((entry, i) => validateEntry(entry, "archive", i, errors, null, pinIdSet, true));

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
