#!/usr/bin/env node
// Fixture tests for the family-manifest tooling (#723 review response, P2:
// "the described mutation tests were manually injected and reverted; no
// test fixtures preserve them"). Dependency-free (Node core's node:assert
// and node:test), string/object fixtures rather than file mutation on the
// real repository. Covers role derivation, each candidate-gate criterion
// (including "a candidate with a Conformance heading but no requirement
// inventory fails"), the unstable-self-claim and hand-typed-count regex
// tripwires (both positive and negative cases, proving the external-
// dependency disclosure is distinguished from a self-contradiction), and
// generated-block drift detection.
//
// Usage: node scripts/test-family-manifest.mjs

import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import crypto from "node:crypto";
import assert from "node:assert/strict";
import { test } from "node:test";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import { roleFor, maturityDisplay, CORE_SLUG, BINDING_SLUGS, validateCandidateGate, loadConformanceCounts } from "./generate-drafts-index.mjs";
import { HAND_TYPED_COUNT, UNSTABLE_SELF_CLAIM } from "./check-family-manifest.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, "..");

// ---------------------------------------------------------------------
// Fixture repo builder: a throwaway git repository (candidate-gate's
// commit-existence check shells out to `git cat-file`, so a fixture needs
// real git history, not just files on disk) with a minimal
// family-manifest.json / conformance-manifest.json / candidate-gate.json
// and one draft file, patchable per test via overrides.
// ---------------------------------------------------------------------
// Fixed and exported so a test can reference it while BUILDING the
// arguments to makeFixtureRepo() (e.g. `conformanceRequirements: [{ spec:
// FIXTURE_FILE, ... }]`) without a circular reference to that call's own
// return value.
const FIXTURE_FILE = "draft-fixture-example.md";

// `gateOverrides` may be a plain object, or a function `(firstCommit) =>
// object` for the common case of a gate record that must cite a real,
// already-existing commit SHA (candidate-gate.json can never validly cite
// its own not-yet-made commit, so this makes an initial commit first, then
// lets the caller's function reference that commit's now-real SHA when
// building the record actually written to disk).
function makeFixtureRepo({ draftBody, familyOverrides = {}, conformanceRequirements = [], gateOverrides = {} } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "family-manifest-test-"));
  execFileSync("git", ["init", "-q"], { cwd: root });
  execFileSync("git", ["config", "user.email", "test@example.com"], { cwd: root });
  execFileSync("git", ["config", "user.name", "Test"], { cwd: root });

  const draftFile = FIXTURE_FILE;
  fs.writeFileSync(path.join(root, draftFile), draftBody);

  const family = {
    drafts: [
      {
        file: draftFile,
        slug: "draft-fixture-example",
        title: "Fixture Example",
        category: "std",
        role: "companion",
        spec_maturity: "candidate",
        maintenance: "active",
        group: "lifecycle",
        verbs: ["govern"],
        summary: "A fixture draft for candidate-gate testing.",
        pull_when: "Never; this is a test fixture.",
        adoption_alias: "fixture",
        normative_references: [],
        adoption_requires: [],
        references: [],
        ...familyOverrides,
      },
    ],
  };
  fs.writeFileSync(path.join(root, "family-manifest.json"), JSON.stringify(family, null, 1));

  const conformance = {
    requirements: conformanceRequirements,
    source: { specs: {} },
  };
  // Any requirement naming this draft's file implies an audited source.specs
  // entry, mirroring the real manifest's own invariant (checked elsewhere;
  // not re-validated by this fixture builder).
  for (const r of conformanceRequirements) {
    if (!conformance.source.specs[r.spec]) {
      conformance.source.specs[r.spec] = { revision: "0".repeat(40), content_sha256: "0".repeat(64) };
    }
  }
  fs.writeFileSync(path.join(root, "conformance-manifest.json"), JSON.stringify(conformance, null, 1));

  // First pass: an empty gate record, just to establish a real commit.
  fs.writeFileSync(path.join(root, "candidate-gate.json"), JSON.stringify({ decide_issue_scope: {}, documents: {} }, null, 1));
  execFileSync("git", ["add", "-A"], { cwd: root });
  execFileSync("git", ["commit", "-q", "-m", "fixture: initial"], { cwd: root });
  const firstCommit = execFileSync("git", ["rev-parse", "HEAD"], { cwd: root }).toString().trim();

  // Second pass: the caller's real gate record, now free to cite firstCommit.
  // A record identical to the first pass's placeholder (both empty) leaves
  // nothing to commit; that is a valid fixture (some tests want no gate
  // record at all), not an error, so the second commit is best-effort.
  const resolvedOverrides = typeof gateOverrides === "function" ? gateOverrides(firstCommit) : gateOverrides;
  const gate = { decide_issue_scope: {}, documents: {}, ...resolvedOverrides };
  fs.writeFileSync(path.join(root, "candidate-gate.json"), JSON.stringify(gate, null, 1));
  execFileSync("git", ["add", "-A"], { cwd: root });
  const status = execFileSync("git", ["status", "--porcelain"], { cwd: root }).toString();
  if (status.trim().length > 0) {
    execFileSync("git", ["commit", "-q", "-m", "fixture: gate record"], { cwd: root });
  }

  return { root, draftFile, commit: firstCommit };
}

function cleanup(root) {
  fs.rmSync(root, { recursive: true, force: true });
}

// Writes a fixture audit-report file at root/relPath and returns its
// sha256 hex digest, for building a requirement_inventory.report fixture
// (#727 review: an attestation must name a durable, versioned report, not
// only a commit SHA). Not committed to the fixture's git repo: report.path
// existence is a plain fs.existsSync check, independent of the
// commit-existence checks that need real git history.
function writeFixtureReport(root, relPath, content) {
  const p = path.join(root, relPath);
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, content);
  return crypto.createHash("sha256").update(content).digest("hex");
}
const FIXTURE_REPORT_PATH = "notes/audits/fixture-completeness-audit.md";

const CONFORMANT_BODY = [
  "# Fixture",
  "",
  "# Conformance {#conformance}",
  "",
  "A conforming implementation does whatever the fixture requires.",
  "",
  "~~~",
  "example: true",
  "~~~",
  "",
].join("\n");

// ---------------------------------------------------------------------
// roleFor()
// ---------------------------------------------------------------------

test("roleFor: the substrate kernel is core", () => {
  assert.equal(roleFor({ slug: CORE_SLUG, category: "std" }), "core");
});

test("roleFor: every BINDING_SLUGS entry is adapter-binding", () => {
  assert.ok(BINDING_SLUGS.length > 0, "BINDING_SLUGS must be non-empty for this test to mean anything");
  for (const slug of BINDING_SLUGS) {
    assert.equal(roleFor({ slug, category: "std" }), "adapter-binding");
  }
});

test("roleFor: a category:info document is guide", () => {
  assert.equal(roleFor({ slug: "draft-fixture-guide", category: "info" }), "guide");
});

test("roleFor: everything else is companion", () => {
  assert.equal(roleFor({ slug: "draft-fixture-companion", category: "std" }), "companion");
  assert.equal(roleFor({ slug: "draft-fixture-companion-exp", category: "exp" }), "companion");
});

// ---------------------------------------------------------------------
// maturityDisplay()
// ---------------------------------------------------------------------

test("maturityDisplay: candidate/experimental/sketch render verbatim", () => {
  assert.equal(maturityDisplay("candidate"), "candidate");
  assert.equal(maturityDisplay("experimental"), "experimental");
  assert.equal(maturityDisplay("sketch"), "sketch");
});

test("maturityDisplay: not_applicable renders as its own word, never folded into role's 'guide'", () => {
  // Regression test for the bug caught before the #723 submission: an
  // earlier draft of this function took a `role` argument and collapsed
  // not_applicable back into "guide", re-mixing the two axes in the one
  // place meant to keep them apart.
  assert.equal(maturityDisplay("not_applicable"), "not applicable");
  assert.equal(maturityDisplay.length, 1, "maturityDisplay must take spec_maturity alone, not a role argument");
});

test("maturityDisplay: an unknown value has no display word", () => {
  assert.equal(maturityDisplay("bogus"), null);
});

// ---------------------------------------------------------------------
// UNSTABLE_SELF_CLAIM (check (y)'s tripwire)
// ---------------------------------------------------------------------

test("UNSTABLE_SELF_CLAIM: fires on a self-referential interface-instability claim", () => {
  const text = "so this profile is not yet a stable interface and will track the substrate as it evolves.";
  assert.match(text, UNSTABLE_SELF_CLAIM);
});

test("UNSTABLE_SELF_CLAIM: does NOT fire on an external-dependency disclosure (criterion 5)", () => {
  // The exact discriminating case the review's P2 named: a valid disclosure
  // about a cited draft's instability must not read as this document
  // contradicting itself.
  const text = "It depends normatively on an early Internet-Draft that is not ratified and whose details may change.";
  assert.doesNotMatch(text, UNSTABLE_SELF_CLAIM);
});

test("UNSTABLE_SELF_CLAIM: does NOT fire on a deployment-experience disclosure", () => {
  // mission-mandate.md's actual sentence: subject is deployment/implementation
  // experience, not this document's own interface.
  const text = "The artifact itself is not yet exercised in deployment, so an implementer validates the verification steps and failure taxonomy against real cross-domain use before relying on them.";
  assert.doesNotMatch(text, UNSTABLE_SELF_CLAIM);
});

// ---------------------------------------------------------------------
// HAND_TYPED_COUNT (check (m)'s tripwire)
// ---------------------------------------------------------------------

test("HAND_TYPED_COUNT: fires on a hyphenated document count", () => {
  assert.match("not a request to standardize a 42-document suite", HAND_TYPED_COUNT);
});

test("HAND_TYPED_COUNT: fires on a spaced document count", () => {
  assert.match("Runtime-Enforced is 4 documents", HAND_TYPED_COUNT);
});

test("HAND_TYPED_COUNT: does NOT fire on a spelled-out count", () => {
  assert.doesNotMatch("the kernel contract first, then its five peer bindings", HAND_TYPED_COUNT);
});

// ---------------------------------------------------------------------
// validateCandidateGate(): each of the five criteria, isolated
// ---------------------------------------------------------------------

test("candidate-gate: passes when all five criteria are genuinely satisfied", () => {
  const { root } = makeFixtureRepo({
    draftBody: CONFORMANT_BODY,
    conformanceRequirements: [{ spec: FIXTURE_FILE, coverage: "tested" }],
    gateOverrides: (commit) => ({
      documents: {
        "draft-fixture-example": {
          requirement_inventory: {
            attested: true,
            audited_by: commit,
            report: { path: FIXTURE_REPORT_PATH, document_sha256: "0".repeat(64) },
          },
          decide_resolutions: [],
          examples_waiver: null,
        },
      },
    }),
  });
  try {
    writeFixtureReport(root, FIXTURE_REPORT_PATH, "fixture audit report body");
    assert.deepEqual(validateCandidateGate(root), []);
  } finally {
    cleanup(root);
  }
});

test("candidate-gate: attested without a report fails criterion 1 (#727 review: a SHA alone is not auditable)", () => {
  const { root } = makeFixtureRepo({
    draftBody: CONFORMANT_BODY,
    conformanceRequirements: [{ spec: FIXTURE_FILE, coverage: "tested" }],
    gateOverrides: (commit) => ({
      documents: {
        "draft-fixture-example": {
          requirement_inventory: { attested: true, audited_by: commit }, // no report field
          decide_resolutions: [],
          examples_waiver: null,
        },
      },
    }),
  });
  try {
    const findings = validateCandidateGate(root);
    assert.ok(findings.some((f) => f.includes("report")), `expected a report finding, got: ${JSON.stringify(findings)}`);
  } finally {
    cleanup(root);
  }
});

test("candidate-gate: a report with a malformed document_sha256 fails", () => {
  const { root } = makeFixtureRepo({
    draftBody: CONFORMANT_BODY,
    conformanceRequirements: [{ spec: FIXTURE_FILE, coverage: "tested" }],
    gateOverrides: (commit) => ({
      documents: {
        "draft-fixture-example": {
          requirement_inventory: {
            attested: true,
            audited_by: commit,
            report: { path: FIXTURE_REPORT_PATH, document_sha256: "not-a-hex-digest" },
          },
          decide_resolutions: [],
          examples_waiver: null,
        },
      },
    }),
  });
  try {
    writeFixtureReport(root, FIXTURE_REPORT_PATH, "fixture audit report body");
    const findings = validateCandidateGate(root);
    assert.ok(
      findings.some((f) => f.includes("document_sha256")),
      `expected a document_sha256 finding, got: ${JSON.stringify(findings)}`,
    );
  } finally {
    cleanup(root);
  }
});

test("candidate-gate: a report naming a missing path fails", () => {
  const { root } = makeFixtureRepo({
    draftBody: CONFORMANT_BODY,
    conformanceRequirements: [{ spec: FIXTURE_FILE, coverage: "tested" }],
    gateOverrides: (commit) => ({
      documents: {
        "draft-fixture-example": {
          requirement_inventory: {
            attested: true,
            audited_by: commit,
            report: { path: "notes/audits/does-not-exist.md", document_sha256: "0".repeat(64) },
          },
          decide_resolutions: [],
          examples_waiver: null,
        },
      },
    }),
  });
  // Deliberately never written to disk.
  try {
    const findings = validateCandidateGate(root);
    assert.ok(
      findings.some((f) => f.includes("report.path")),
      `expected a report.path finding, got: ${JSON.stringify(findings)}`,
    );
  } finally {
    cleanup(root);
  }
});

test("candidate-gate: a stale report document_sha256 warns but still passes", () => {
  const { root } = makeFixtureRepo({
    draftBody: CONFORMANT_BODY,
    conformanceRequirements: [{ spec: FIXTURE_FILE, coverage: "tested" }], // source.specs content_sha256 is "0".repeat(64)
    gateOverrides: (commit) => ({
      documents: {
        "draft-fixture-example": {
          requirement_inventory: {
            attested: true,
            audited_by: commit,
            // Well-formed, but deliberately does not equal the "0".repeat(64)
            // conformance-manifest.json records for FIXTURE_FILE: the
            // audited document has moved on since the report was written.
            report: { path: FIXTURE_REPORT_PATH, document_sha256: "1".repeat(64) },
          },
          decide_resolutions: [],
          examples_waiver: null,
        },
      },
    }),
  });
  const originalWarn = console.warn;
  let warned = false;
  console.warn = (...args) => {
    warned = true;
    originalWarn.apply(console, args);
  };
  try {
    writeFixtureReport(root, FIXTURE_REPORT_PATH, "fixture audit report body, now stale relative to the pin");
    assert.deepEqual(validateCandidateGate(root), [], "staleness must never fail the gate");
    assert.ok(warned, "expected a printed staleness warning");
  } finally {
    console.warn = originalWarn;
    cleanup(root);
  }
});

test("candidate-gate: a Conformance heading alone does not satisfy criterion 1 (the review's own resource-access counterexample)", () => {
  // This is the exact shape the review named: a real Conformance section
  // and real (if todo) conformance-manifest rows, but no recorded,
  // verified completeness attestation.
  const { root, draftFile } = makeFixtureRepo({
    draftBody: CONFORMANT_BODY,
    conformanceRequirements: [{ spec: FIXTURE_FILE, coverage: "todo" }],
    gateOverrides: { documents: {} }, // no requirement_inventory recorded at all
  });
  try {
    const findings = validateCandidateGate(root);
    assert.ok(findings.length > 0, "expected at least one finding");
    assert.ok(
      findings.some((f) => f.includes("criterion 1")),
      `expected a criterion 1 finding, got: ${JSON.stringify(findings)}`,
    );
  } finally {
    cleanup(root);
  }
});

test("candidate-gate: criterion 1 fails when the spec has no source.specs entry at all", () => {
  const { root } = makeFixtureRepo({
    draftBody: CONFORMANT_BODY,
    conformanceRequirements: [], // zero rows anywhere -> no source.specs entry
    gateOverrides: {
      documents: {
        "draft-fixture-example": {
          requirement_inventory: { attested: true, audited_by: "0".repeat(40) },
          decide_resolutions: [],
          examples_waiver: null,
        },
      },
    },
  });
  try {
    const findings = validateCandidateGate(root);
    assert.ok(findings.some((f) => f.includes("no source.specs entry")));
  } finally {
    cleanup(root);
  }
});

test("candidate-gate: criterion 1 fails when audited_by does not resolve to a real commit", () => {
  const { root, draftFile } = makeFixtureRepo({
    draftBody: CONFORMANT_BODY,
    conformanceRequirements: [{ spec: FIXTURE_FILE, coverage: "tested" }],
    gateOverrides: {
      documents: {
        "draft-fixture-example": {
          requirement_inventory: { attested: true, audited_by: "f".repeat(40) }, // well-formed, does not exist
          decide_resolutions: [],
          examples_waiver: null,
        },
      },
    },
  });
  try {
    const findings = validateCandidateGate(root);
    assert.ok(findings.some((f) => f.includes("does not resolve to a commit")));
  } finally {
    cleanup(root);
  }
});

test("candidate-gate: criterion 2 fails when a scoped decide issue has no resolution", () => {
  const { root } = makeFixtureRepo({
    draftBody: CONFORMANT_BODY,
    conformanceRequirements: [{ spec: FIXTURE_FILE, coverage: "tested" }],
    gateOverrides: (commit) => ({
      decide_issue_scope: { "999": { title: "Fixture decide issue", slugs: ["draft-fixture-example"] } },
      documents: {
        "draft-fixture-example": {
          requirement_inventory: { attested: true, audited_by: commit },
          decide_resolutions: [], // #999 is scoped to this slug but never resolved
          examples_waiver: null,
        },
      },
    }),
  });
  try {
    const findings = validateCandidateGate(root);
    assert.ok(findings.some((f) => f.includes("#999") && f.includes("criterion 2")));
  } finally {
    cleanup(root);
  }
});

test("candidate-gate: criterion 2 passes when the scoped issue is resolved_in_tree with a real commit", () => {
  const { root } = makeFixtureRepo({
    draftBody: CONFORMANT_BODY,
    conformanceRequirements: [{ spec: FIXTURE_FILE, coverage: "tested" }],
    gateOverrides: (commit) => ({
      decide_issue_scope: { "999": { title: "Fixture decide issue", slugs: ["draft-fixture-example"] } },
      documents: {
        "draft-fixture-example": {
          requirement_inventory: {
            attested: true,
            audited_by: commit,
            report: { path: FIXTURE_REPORT_PATH, document_sha256: "0".repeat(64) },
          },
          decide_resolutions: [{ issue: 999, status: "resolved_in_tree", commit }],
          examples_waiver: null,
        },
      },
    }),
  });
  try {
    writeFixtureReport(root, FIXTURE_REPORT_PATH, "fixture audit report body");
    assert.deepEqual(validateCandidateGate(root), []);
  } finally {
    cleanup(root);
  }
});

test("candidate-gate: criterion 3 fails without a Conformance-titled section", () => {
  const { root } = makeFixtureRepo({
    draftBody: "# Fixture\n\nNo conformance section at all.\n\n~~~\nexample: true\n~~~\n",
    conformanceRequirements: [{ spec: FIXTURE_FILE, coverage: "tested" }],
    gateOverrides: (commit) => ({
      documents: {
        "draft-fixture-example": {
          requirement_inventory: { attested: true, audited_by: commit },
          decide_resolutions: [],
          examples_waiver: null,
        },
      },
    }),
  });
  try {
    const findings = validateCandidateGate(root);
    assert.ok(findings.some((f) => f.includes("criterion 3")));
  } finally {
    cleanup(root);
  }
});

test("candidate-gate: criterion 4 fails with no examples and no waiver", () => {
  const { root } = makeFixtureRepo({
    draftBody: "# Fixture\n\n# Conformance {#conformance}\n\nNo artwork block here.\n",
    conformanceRequirements: [{ spec: FIXTURE_FILE, coverage: "tested" }],
    gateOverrides: (commit) => ({
      documents: {
        "draft-fixture-example": {
          requirement_inventory: { attested: true, audited_by: commit },
          decide_resolutions: [],
          examples_waiver: null,
        },
      },
    }),
  });
  try {
    const findings = validateCandidateGate(root);
    assert.ok(findings.some((f) => f.includes("criterion 4")));
  } finally {
    cleanup(root);
  }
});

test("candidate-gate: criterion 4 passes with no examples but a recorded, non-empty waiver (the aauth-mission-expiry case)", () => {
  const { root } = makeFixtureRepo({
    draftBody: "# Fixture\n\n# Conformance {#conformance}\n\nNo artwork block here.\n",
    conformanceRequirements: [{ spec: FIXTURE_FILE, coverage: "tested" }],
    gateOverrides: (commit) => ({
      documents: {
        "draft-fixture-example": {
          requirement_inventory: {
            attested: true,
            audited_by: commit,
            report: { path: FIXTURE_REPORT_PATH, document_sha256: "0".repeat(64) },
          },
          decide_resolutions: [],
          examples_waiver: { reason: "Single-member format profile; proportionality." },
        },
      },
    }),
  });
  try {
    writeFixtureReport(root, FIXTURE_REPORT_PATH, "fixture audit report body");
    assert.deepEqual(validateCandidateGate(root), []);
  } finally {
    cleanup(root);
  }
});

test("candidate-gate: an empty-string waiver reason does not count as a waiver", () => {
  const { root } = makeFixtureRepo({
    draftBody: "# Fixture\n\n# Conformance {#conformance}\n\nNo artwork block here.\n",
    conformanceRequirements: [{ spec: FIXTURE_FILE, coverage: "tested" }],
    gateOverrides: (commit) => ({
      documents: {
        "draft-fixture-example": {
          requirement_inventory: { attested: true, audited_by: commit },
          decide_resolutions: [],
          examples_waiver: { reason: "" },
        },
      },
    }),
  });
  try {
    const findings = validateCandidateGate(root);
    assert.ok(findings.some((f) => f.includes("criterion 4")));
  } finally {
    cleanup(root);
  }
});

test("candidate-gate: a non-candidate draft is never checked, however broken its gate record", () => {
  const { root } = makeFixtureRepo({
    draftBody: "# Fixture\n\nNothing here at all.\n",
    familyOverrides: { spec_maturity: "experimental" },
    conformanceRequirements: [],
    gateOverrides: { documents: {} },
  });
  try {
    assert.deepEqual(validateCandidateGate(root), []);
  } finally {
    cleanup(root);
  }
});

test("candidate-gate: decide_issue_scope naming an unknown slug is a structural finding, independent of any candidate", () => {
  const { root } = makeFixtureRepo({
    draftBody: "# Fixture\n\nNothing here at all.\n",
    familyOverrides: { spec_maturity: "experimental" },
    conformanceRequirements: [],
    gateOverrides: {
      decide_issue_scope: { "1": { title: "Bogus", slugs: ["draft-does-not-exist"] } },
      documents: {},
    },
  });
  try {
    const findings = validateCandidateGate(root);
    assert.ok(findings.some((f) => f.includes("draft-does-not-exist")));
  } finally {
    cleanup(root);
  }
});

// ---------------------------------------------------------------------
// The real repository: the candidate-gate check must also pass here
// (this is not a substitute for `node scripts/check-family-manifest.mjs`,
// but catches an obviously broken candidate-gate.json early).
// ---------------------------------------------------------------------

test("candidate-gate: the real repository's candidate-gate.json is currently gate-clean", () => {
  assert.deepEqual(validateCandidateGate(REPO_ROOT), []);
});

test("loadConformanceCounts: the real repository's ledger parses and is non-empty", () => {
  const counts = loadConformanceCounts(REPO_ROOT);
  assert.ok(counts.size > 0);
});
