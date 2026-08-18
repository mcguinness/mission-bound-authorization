#!/usr/bin/env node
// Structural and cross-referential validation for
// notes/bundle-manifest.v0-preview.1.json (and any sibling
// notes/bundle-manifest.*.json this repository publishes later).
//
// This checks, per manifest file:
//   - version is a string matching vX or vX-preview.N (X, N non-negative
//     integers), and, when the filename encodes a version segment
//     (notes/bundle-manifest.<version>.json), that segment matches the
//     manifest's own "version" field exactly.
//   - source_repository_commit is a full 40-hex SHA.
//   - documents[] entries carry a non-empty slug and a full-SHA
//     last_modified_commit (informational only; never re-derived here).
//   - external_pins[] is non-empty, and every entry's "id" exists in
//     notes/external-pins.json with status "established" and an IDENTICAL
//     value (deep, key-for-key) to the registry entry. The build REJECTS
//     (fails) if a bundle-consumed registry entry has status "pending", or
//     if it does not exist in the registry at all.
//   - artifact_digests{}: every path that exists on disk is re-hashed
//     (sha256) and must match the recorded digest.
//   - disabled_capabilities[] entries carry a non-empty capability and
//     reason.
//
// This does NOT re-verify external_pins against live source repositories;
// that independent verification happens once, by hand, when a pin is
// established (see notes/external-pins.json's "description"). It also does
// NOT re-run notes/external-pins.json's own structural validation (see
// scripts/check-external-pins.mjs) to avoid reporting the same malformed
// registry entry twice when both scripts are chained from
// scripts/check-family-manifest.mjs. This script verifies internal
// consistency: the bundle manifest's pins are exactly what the registry
// currently says, and none of them is pending.
//
// Usage: node scripts/check-bundle-manifest.mjs
// Also imported by scripts/check-family-manifest.mjs, which calls
// validateBundleManifests() as part of its own check so CI needs no
// separate workflow step.

import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const FULL_SHA_RE = /^[0-9a-f]{40}$/;
const SHA256_RE = /^[0-9a-f]{64}$/;
const VERSION_RE = /^v[0-9]+(-preview\.[0-9]+)?$/;
const BUNDLE_MANIFEST_FILENAME_RE = /^bundle-manifest\.([^.]+(?:-preview\.[0-9]+)?)\.json$/;

function isNonEmptyString(v) {
  return typeof v === "string" && v.trim() !== "";
}

// Deep, key-order-independent equality. Used to confirm a bundle manifest's
// external_pins entry was copied verbatim from the registry (every key the
// registry has, with the same value; no extra or missing keys).
function deepEqual(a, b) {
  if (a === b) return true;
  if (typeof a !== typeof b) return false;
  if (a === null || b === null) return a === b;
  if (typeof a !== "object") return a === b;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  if (Array.isArray(a)) {
    if (a.length !== b.length) return false;
    return a.every((v, i) => deepEqual(v, b[i]));
  }
  const aKeys = Object.keys(a).sort();
  const bKeys = Object.keys(b).sort();
  if (aKeys.length !== bKeys.length) return false;
  if (!aKeys.every((k, i) => k === bKeys[i])) return false;
  return aKeys.every((k) => deepEqual(a[k], b[k]));
}

// This deliberately does not re-run validateExternalPins' structural checks:
// scripts/check-family-manifest.mjs already runs those once as its own (j)
// check, and re-running them here would report the same finding twice under
// two different check labels. A caller that runs this script standalone,
// without also running check-external-pins.mjs, gets read/parse errors here
// but not the finer-grained structural findings; run both for full coverage.
function loadRegistryPinsById(rootDir, errors) {
  const pinsPath = path.join(rootDir, "notes", "external-pins.json");
  let doc;
  try {
    doc = JSON.parse(fs.readFileSync(pinsPath, "utf8"));
  } catch (e) {
    errors.push(`cannot read/parse ${pinsPath}: ${e.message}`);
    return new Map();
  }
  const byId = new Map();
  for (const entry of doc.pins ?? []) {
    if (entry && typeof entry.id === "string") byId.set(entry.id, entry);
  }
  return byId;
}

function validateOneManifest(rootDir, manifestPath, registryById, errors) {
  const label = path.relative(rootDir, manifestPath);
  const filename = path.basename(manifestPath);

  let raw;
  try {
    raw = fs.readFileSync(manifestPath, "utf8");
  } catch (e) {
    errors.push(`${label}: cannot read: ${e.message}`);
    return;
  }

  let doc;
  try {
    doc = JSON.parse(raw);
  } catch (e) {
    errors.push(`${label}: not valid JSON: ${e.message}`);
    return;
  }

  if (typeof doc.bundle_id !== "string" || doc.bundle_id.trim() === "") {
    errors.push(`${label}: missing a non-empty string "bundle_id"`);
  }

  if (typeof doc.version !== "string" || !VERSION_RE.test(doc.version)) {
    errors.push(`${label}: "version" must match vX or vX-preview.N, got ${JSON.stringify(doc.version)}`);
  } else {
    const m = filename.match(BUNDLE_MANIFEST_FILENAME_RE);
    if (m && m[1] !== doc.version) {
      errors.push(`${label}: filename encodes version "${m[1]}" but manifest "version" field is "${doc.version}"`);
    }
  }

  if (typeof doc.source_repository_commit !== "string" || !FULL_SHA_RE.test(doc.source_repository_commit)) {
    errors.push(`${label}: "source_repository_commit" must be a full 40-hex SHA, got ${JSON.stringify(doc.source_repository_commit)}`);
  }

  if (!Array.isArray(doc.documents) || doc.documents.length === 0) {
    errors.push(`${label}: "documents" must be a non-empty array`);
  } else {
    doc.documents.forEach((d, i) => {
      const dl = `${label}: documents[${i}]${d && d.slug ? ` (${d.slug})` : ""}`;
      if (!d || typeof d !== "object") {
        errors.push(`${dl}: not an object`);
        return;
      }
      if (!isNonEmptyString(d.slug)) errors.push(`${dl}: missing a non-empty "slug"`);
      if (!isNonEmptyString(d.file)) errors.push(`${dl}: missing a non-empty "file"`);
      if (typeof d.last_modified_commit !== "string" || !FULL_SHA_RE.test(d.last_modified_commit)) {
        errors.push(`${dl}: "last_modified_commit" must be a full 40-hex SHA, got ${JSON.stringify(d.last_modified_commit)}`);
      }
      if (isNonEmptyString(d.file) && !fs.existsSync(path.join(rootDir, d.file))) {
        errors.push(`${dl}: file "${d.file}" does not exist on disk`);
      }
    });
  }

  if (!Array.isArray(doc.external_pins) || doc.external_pins.length === 0) {
    errors.push(`${label}: "external_pins" must be a non-empty array`);
  } else {
    const seenIds = new Set();
    doc.external_pins.forEach((entry, i) => {
      const el = `${label}: external_pins[${i}]${entry && entry.id ? ` (${entry.id})` : ""}`;
      if (!entry || typeof entry !== "object" || typeof entry.id !== "string" || entry.id.trim() === "") {
        errors.push(`${el}: missing a non-empty string "id"`);
        return;
      }
      if (seenIds.has(entry.id)) {
        errors.push(`${el}: duplicate id "${entry.id}" within this manifest's external_pins`);
      }
      seenIds.add(entry.id);

      const registryEntry = registryById.get(entry.id);
      if (!registryEntry) {
        errors.push(`${el}: id "${entry.id}" does not exist in notes/external-pins.json`);
        return;
      }

      // The build REJECTS if any registry entry a bundle consumes is
      // pending, regardless of what the bundle's own copy claims.
      if (registryEntry.status === "pending") {
        errors.push(`${el}: registry entry "${entry.id}" is "pending"; a bundle build MUST reject pending pins`);
        return;
      }

      if (entry.status !== "established") {
        errors.push(`${el}: bundle copy of "${entry.id}" has status "${entry.status}", expected "established"`);
      }

      if (!deepEqual(entry, registryEntry)) {
        errors.push(`${el}: bundle's copy of "${entry.id}" is not identical to the registry entry (must be copied verbatim)`);
      }
    });
  }

  if (doc.artifact_digests === null || typeof doc.artifact_digests !== "object" || Array.isArray(doc.artifact_digests)) {
    errors.push(`${label}: "artifact_digests" must be an object`);
  } else if (Object.keys(doc.artifact_digests).length === 0) {
    errors.push(`${label}: "artifact_digests" must not be empty`);
  } else {
    for (const [relPath, digest] of Object.entries(doc.artifact_digests)) {
      const dl = `${label}: artifact_digests["${relPath}"]`;
      if (typeof digest !== "string" || !SHA256_RE.test(digest)) {
        errors.push(`${dl}: must be a 64-hex sha256 digest, got ${JSON.stringify(digest)}`);
        continue;
      }
      const abs = path.join(rootDir, relPath);
      if (!fs.existsSync(abs)) {
        errors.push(`${dl}: file "${relPath}" does not exist on disk`);
        continue;
      }
      const actual = crypto.createHash("sha256").update(fs.readFileSync(abs)).digest("hex");
      if (actual !== digest) {
        errors.push(`${dl}: recorded digest ${digest} does not match live content digest ${actual}`);
      }
    }
  }

  if (!Array.isArray(doc.disabled_capabilities) || doc.disabled_capabilities.length === 0) {
    errors.push(`${label}: "disabled_capabilities" must be a non-empty array`);
  } else {
    doc.disabled_capabilities.forEach((entry, i) => {
      const dl = `${label}: disabled_capabilities[${i}]`;
      if (!entry || typeof entry !== "object") {
        errors.push(`${dl}: not an object`);
        return;
      }
      if (!isNonEmptyString(entry.capability)) errors.push(`${dl}: missing a non-empty "capability"`);
      if (!isNonEmptyString(entry.reason)) errors.push(`${dl}: missing a non-empty "reason"`);
    });
  }
}

export function validateBundleManifests(rootDir) {
  const errors = [];
  const registryById = loadRegistryPinsById(rootDir, errors);

  const notesDir = path.join(rootDir, "notes");
  let files = [];
  try {
    files = fs
      .readdirSync(notesDir)
      .filter((f) => /^bundle-manifest\..+\.json$/.test(f))
      .sort();
  } catch (e) {
    errors.push(`cannot read ${notesDir}: ${e.message}`);
    return errors;
  }

  if (files.length === 0) {
    errors.push(`no notes/bundle-manifest.*.json file found`);
    return errors;
  }

  for (const f of files) {
    validateOneManifest(rootDir, path.join(notesDir, f), registryById, errors);
  }

  return errors;
}

function main() {
  const rootDir = path.resolve(__dirname, "..");
  const errors = validateBundleManifests(rootDir);

  if (errors.length > 0) {
    console.error(`bundle-manifest check FAILED with ${errors.length} finding(s):\n`);
    for (const e of errors) console.error(`  - ${e}`);
    console.error("");
    process.exit(1);
  }

  console.log("bundle-manifest check OK: structural and registry cross-reference validation passed.");
  process.exit(0);
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  main();
}
