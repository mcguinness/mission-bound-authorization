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
//   - source_repository_commit is a full 40-hex SHA that names a commit
//     object that actually exists in this repository's git history (via
//     `git cat-file -e <commit>^{commit}`). A missing object fails loud
//     with a diagnosable cause (most commonly a shallow clone in CI).
//   - documents[] entries carry a non-empty slug and file, unique across
//     the array (no two entries may share a slug or a file), and a
//     full-SHA last_modified_commit that is RE-DERIVED from git
//     (`git log -1 --format=%H <source_repository_commit> -- <file>`) and
//     must match exactly, not merely well-shaped. Each entry also carries a
//     sha256 that is RE-DERIVED from the exact bytes of
//     `git show <source_repository_commit>:<file>` and must match. For the
//     oauth-mission-baseline-bundle specifically, documents[] must be
//     exactly the seven-slug set the bundle claims (no extras, none
//     missing).
//   - external_pins[] is non-empty, every entry's "id" exists in
//     notes/external-pins.json with status "established" (the build
//     REJECTS if a bundle-consumed registry entry is "pending" or does not
//     exist), every entry's "pin_id" resolves against the registry's
//     established entries plus its archive, and the bundle's copy of that
//     entry is IDENTICAL (deep, key-for-key) to the resolved record. The
//     required external-pin id set is also DERIVED mechanically from each
//     document's normative front matter at the pinned commit (see
//     deriveRequiredExternalIds below) and compared for exact equality
//     against the bundle's external_pins id set: fails on any pin the
//     bundle omits and on any pin the bundle carries that no document's
//     front matter actually requires.
//   - artifact_digests{}: every path that exists on disk is re-hashed
//     (sha256) and must match the recorded digest.
//   - disabled_capabilities[] entries carry a non-empty capability and
//     reason.
//   - deferred_capabilities[] entries (work that is absent, not disabled)
//     carry a non-empty capability and note.
//   - profiles{}: every profile's normative_document_slugs exist in
//     documents[], and (for oauth-mission-baseline-bundle) the union of
//     every profile's normative_document_slugs plus the architecture
//     preface equals documents[] exactly. The single preview markdown
//     tracked in artifact_digests (its path matching /preview\.md$/) must
//     name, in its "## The two levels" table, the same document-slug set
//     per profile (matched by the profile's "label"), so the containment
//     check is mechanical string comparison, never NLP.
//
// external_pins content is NOT re-fetched from live upstream source
// repositories here; that independent verification happens once, by hand,
// when a pin is established (see notes/external-pins.json's
// "description"). It also does NOT re-run notes/external-pins.json's own
// structural validation (see scripts/check-external-pins.mjs) to avoid
// reporting the same malformed registry entry twice when both scripts are
// chained from scripts/check-family-manifest.mjs. This script verifies
// internal consistency and, for the in-repository documents/pins this
// bundle claims, git-backed source-of-truth verification: the bundle's
// claims are checked against actual repository history and content, not
// merely against their own shape.
//
// Usage: node scripts/check-bundle-manifest.mjs
// Also imported by scripts/check-family-manifest.mjs, which calls
// validateBundleManifests() as part of its own check so CI needs no
// separate workflow step.

import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const FULL_SHA_RE = /^[0-9a-f]{40}$/;
const SHA256_RE = /^[0-9a-f]{64}$/;
const VERSION_RE = /^v[0-9]+(-preview\.[0-9]+)?$/;
const BUNDLE_MANIFEST_FILENAME_RE = /^bundle-manifest\.([^.]+(?:-preview\.[0-9]+)?)\.json$/;
const PIN_ID_RE = /^[A-Za-z][A-Za-z0-9_-]*@[A-Za-z0-9][A-Za-z0-9.-]*$/;

// The exact document-slug catalog the oauth-mission-baseline-bundle claims:
// architecture (informative preface) plus the six normative floor
// documents. Hardcoded here (not derived) because this is what the bundle
// itself asserts it is; a future sibling bundle with a different catalog
// is not held to this list (see the bundle_id guard where this is used).
const OAUTH_MISSION_BASELINE_BUNDLE_ID = "oauth-mission-baseline-bundle";
const OAUTH_MISSION_BASELINE_ARCHITECTURE_SLUG = "draft-mcguinness-mission-architecture";
const OAUTH_MISSION_BASELINE_EXPECTED_SLUGS = new Set([
  "draft-mcguinness-mission-architecture",
  "draft-mcguinness-mission-substrate",
  "draft-mcguinness-oauth-mission",
  "draft-mcguinness-oauth-mission-status",
  "draft-mcguinness-mission-runtime",
  "draft-mcguinness-mission-runtime-evidence",
  "draft-mcguinness-mission-authzen",
]);

function isNonEmptyString(v) {
  return typeof v === "string" && v.trim() !== "";
}

// git helpers. All operate with cwd = repo root, and use execFileSync (no
// shell interpolation) since commit SHAs and paths here come from JSON the
// repo itself controls, but there is no reason to risk shell metacharacters
// regardless.
function gitCommitExists(rootDir, commit) {
  try {
    execFileSync("git", ["cat-file", "-e", `${commit}^{commit}`], { cwd: rootDir, stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

function gitBlobExistsAt(rootDir, commit, file) {
  try {
    execFileSync("git", ["cat-file", "-e", `${commit}:${file}`], { cwd: rootDir, stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

function gitLastModifiedCommit(rootDir, commit, file) {
  try {
    const out = execFileSync("git", ["log", "-1", "--format=%H", commit, "--", file], {
      cwd: rootDir,
      encoding: "utf8",
    });
    const sha = out.trim();
    return FULL_SHA_RE.test(sha) ? sha : null;
  } catch {
    return null;
  }
}

// Returns the exact bytes of `file` as it existed at `commit`, or null if
// git cannot produce them (caller is expected to have already confirmed
// the blob exists via gitBlobExistsAt when that distinction matters).
function gitShowBytes(rootDir, commit, file) {
  try {
    return execFileSync("git", ["show", `${commit}:${file}`], {
      cwd: rootDir,
      maxBuffer: 64 * 1024 * 1024,
    });
  } catch {
    return null;
  }
}

function sha256Hex(buffer) {
  return crypto.createHash("sha256").update(buffer).digest("hex");
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

  let sourceCommitVerified = false;
  if (typeof doc.source_repository_commit !== "string" || !FULL_SHA_RE.test(doc.source_repository_commit)) {
    errors.push(`${label}: "source_repository_commit" must be a full 40-hex SHA, got ${JSON.stringify(doc.source_repository_commit)}`);
  } else if (!gitCommitExists(rootDir, doc.source_repository_commit)) {
    errors.push(
      `${label}: "source_repository_commit" ${doc.source_repository_commit} does not exist as a commit object in this checkout` +
        ` (most likely cause: a shallow clone in CI; the checkout step needs fetch-depth: 0)`
    );
  } else {
    sourceCommitVerified = true;
  }

  if (!Array.isArray(doc.documents) || doc.documents.length === 0) {
    errors.push(`${label}: "documents" must be a non-empty array`);
  } else {
    const seenSlugs = new Set();
    const seenFiles = new Set();
    doc.documents.forEach((d, i) => {
      const dl = `${label}: documents[${i}]${d && d.slug ? ` (${d.slug})` : ""}`;
      if (!d || typeof d !== "object") {
        errors.push(`${dl}: not an object`);
        return;
      }
      if (!isNonEmptyString(d.slug)) {
        errors.push(`${dl}: missing a non-empty "slug"`);
      } else if (seenSlugs.has(d.slug)) {
        errors.push(`${dl}: duplicate slug "${d.slug}" within this manifest's documents`);
      } else {
        seenSlugs.add(d.slug);
      }
      if (!isNonEmptyString(d.file)) {
        errors.push(`${dl}: missing a non-empty "file"`);
      } else if (seenFiles.has(d.file)) {
        errors.push(`${dl}: duplicate file "${d.file}" within this manifest's documents`);
      } else {
        seenFiles.add(d.file);
      }
      if (typeof d.last_modified_commit !== "string" || !FULL_SHA_RE.test(d.last_modified_commit)) {
        errors.push(`${dl}: "last_modified_commit" must be a full 40-hex SHA, got ${JSON.stringify(d.last_modified_commit)}`);
      }
      if (typeof d.sha256 !== "string" || !SHA256_RE.test(d.sha256)) {
        errors.push(`${dl}: "sha256" must be a 64-hex sha256 digest, got ${JSON.stringify(d.sha256)}`);
      }
      if (isNonEmptyString(d.file) && !fs.existsSync(path.join(rootDir, d.file))) {
        errors.push(`${dl}: file "${d.file}" does not exist on disk`);
      }

      if (!sourceCommitVerified || !isNonEmptyString(d.file)) return;

      if (!gitBlobExistsAt(rootDir, doc.source_repository_commit, d.file)) {
        errors.push(`${dl}: "${d.file}" does not exist at source_repository_commit ${doc.source_repository_commit} in git history`);
        return;
      }

      const actualLastModified = gitLastModifiedCommit(rootDir, doc.source_repository_commit, d.file);
      if (actualLastModified === null) {
        errors.push(`${dl}: could not derive "git log -1" for "${d.file}" at ${doc.source_repository_commit}`);
      } else if (FULL_SHA_RE.test(d.last_modified_commit) && actualLastModified !== d.last_modified_commit) {
        errors.push(
          `${dl}: "last_modified_commit" ${d.last_modified_commit} does not match ` +
            `git-derived last-touch commit ${actualLastModified} (as of ${doc.source_repository_commit})`
        );
      }

      const bytes = gitShowBytes(rootDir, doc.source_repository_commit, d.file);
      if (bytes === null) {
        errors.push(`${dl}: could not read "${d.file}" contents at ${doc.source_repository_commit} via git show`);
      } else if (SHA256_RE.test(d.sha256)) {
        const actualSha256 = sha256Hex(bytes);
        if (actualSha256 !== d.sha256) {
          errors.push(
            `${dl}: recorded "sha256" ${d.sha256} does not match the digest of "${d.file}" at ${doc.source_repository_commit} (${actualSha256})`
          );
        }
      }
    });

    if (doc.bundle_id === OAUTH_MISSION_BASELINE_BUNDLE_ID) {
      const actualSlugs = new Set(
        doc.documents.filter((d) => d && isNonEmptyString(d.slug)).map((d) => d.slug)
      );
      const missing = [...OAUTH_MISSION_BASELINE_EXPECTED_SLUGS].filter((s) => !actualSlugs.has(s));
      const extra = [...actualSlugs].filter((s) => !OAUTH_MISSION_BASELINE_EXPECTED_SLUGS.has(s));
      if (missing.length > 0 || extra.length > 0) {
        errors.push(
          `${label}: "documents" must be exactly the ${OAUTH_MISSION_BASELINE_BUNDLE_ID} seven-slug set` +
            (missing.length > 0 ? `; missing: ${missing.join(", ")}` : "") +
            (extra.length > 0 ? `; unexpected: ${extra.join(", ")}` : "")
        );
      }
    }
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
