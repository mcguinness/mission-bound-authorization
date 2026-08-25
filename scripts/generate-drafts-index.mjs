#!/usr/bin/env node
// Generates five marker-delimited blocks from family-manifest.json:
// DRAFTS.md's document index, DRAFTS.md's reference-stacks (assurance-level)
// table, DRAFTS.md's family-counts summary, README.md's per-binding
// minimum-package table (#709: verbs are the README's public front door, one
// link out to a catalog that itself exposes the family's other adoption axes
// as generated, not hand-typed, content), and every draft's own per-file
// family-status block (#707: role, spec maturity, and conformance-manifest
// coverage generated from the manifest, never hand-written). Everything
// outside a file's markers is hand-authored and never touched here.
//
// Usage:
//   node scripts/generate-drafts-index.mjs           rewrite all blocks in place
//   node scripts/generate-drafts-index.mjs --check   exit 1 if any block is stale
//
// Dependency-free (Node core only). scripts/check-family-manifest.mjs chains
// --check, so a stale block fails the family-manifest CI step.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { REGISTRY as SUBSTRATE_STATEMENT_REGISTRY } from "./check-substrate-statements.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..");

export const MANIFEST_PATH = path.join(ROOT, "family-manifest.json");
export const DRAFTS_PATH = path.join(ROOT, "DRAFTS.md");
export const README_PATH = path.join(ROOT, "README.md");
export const CANDIDATE_GATE_PATH = path.join(ROOT, "candidate-gate.json");

export const START_MARKER = "<!-- generated:drafts-index:start -->";
export const END_MARKER = "<!-- generated:drafts-index:end -->";

export const BINDING_PACKAGES_START = "<!-- generated:binding-packages:start -->";
export const BINDING_PACKAGES_END = "<!-- generated:binding-packages:end -->";

export const REFERENCE_STACKS_START = "<!-- generated:reference-stacks:start -->";
export const REFERENCE_STACKS_END = "<!-- generated:reference-stacks:end -->";

export const FAMILY_COUNTS_START = "<!-- generated:family-counts:start -->";
export const FAMILY_COUNTS_END = "<!-- generated:family-counts:end -->";

// The per-draft family-status block (#643, #707): every draft file except
// the published OAuth binding (see FAMILY_STATUS_EXEMPT_FILE below) carries
// one of these under its own top-level "# Status" heading.
export const FAMILY_STATUS_BEGIN = "<!-- family-status: BEGIN (generated from family-manifest.json; exact-matched by scripts/check-family-manifest.mjs) -->";
export const FAMILY_STATUS_END = "<!-- family-status: END -->";

// The published OAuth binding carries no per-file family-status block: its
// Status is the family's README (a published Internet-Draft on a fixed
// external track, not a manifest-driven adoption skeleton).
export const FAMILY_STATUS_EXEMPT_FILE = "draft-mcguinness-oauth-mission.md";

// The one document whose `role` is "core" (#707 ruling): the binding-neutral
// Mission Substrate Requirements kernel that every binding, including the
// OAuth binding itself, profiles. Not the OAuth binding: D122 retired "the
// core" as a name for that document (scripts/check-family-manifest.mjs's
// check (p)), and README's "The standards proposal" section already
// describes the substrate as the kernel that "publishes before or with any
// binding claiming conformance to it": structurally prior to its bindings,
// not one of them.
export const CORE_SLUG = "draft-mcguinness-mission-substrate";

// role enum (#707 ruling): core (CORE_SLUG alone), adapter-binding (every
// BINDING_SLUGS entry, defined below), guide (every category:info document),
// companion (everything else). Order matters: adapter-binding and core are
// checked before the category:info fallback so a future binding that is
// also, hypothetically, category:info still classifies as adapter-binding.
export function roleFor(draft) {
  if (draft.slug === CORE_SLUG) return "core";
  if (SUBSTRATE_STATEMENT_REGISTRY.some((e) => e.slug === draft.slug)) return "adapter-binding";
  if (draft.category === "info") return "guide";
  return "companion";
}

// spec_maturity (#707 ruling) is manifest data (family-manifest.json's own
// `spec_maturity` field: candidate, experimental, sketch, or not_applicable),
// gated by the five-criteria candidate test at migration or reclassification
// time, never recomputed from a formula here. maturityDisplay() below only
// renders it.

// DRAFTS.md's group section titles, in manifest `groups` order: the single
// source of truth for both the generated index's "Group" column (below) and
// scripts/check-family-manifest.mjs's check (o), which uses this same map to
// find each group's "###" section in DRAFTS.md. One map, so a renamed section
// cannot go stale in one file while the other still expects the old title.
export const GROUP_SECTION_TITLES = {
  "architecture": "Architecture",
  "approval-time": "Approval time",
  "lifecycle": "Lifecycle",
  "runtime-enforcement": "Runtime enforcement",
  "bindings-substrate": "The substrate and the bindings",
  "agent-runtime": "Agent runtime",
  "sub-agents": "Sub-agents",
  "cross-domain-projection": "Cross-domain projection",
  "proof-portability": "Proof and portability",
  "security-model": "Security model",
};

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

// A manifest spec_maturity value under the family's display vocabulary
// (#707): candidate, experimental, and sketch display verbatim; not_applicable
// displays as "not applicable" in its own right. Deliberately does NOT fold
// in `role`: collapsing "not_applicable" back into the word "guide" here
// would re-mix the role and spec_maturity axes in the one place (the Spec
// maturity column/line) that exists to keep them apart: the document's
// Role column/line already says "guide" beside it. Returns null for a value
// with no defined display word.
export function maturityDisplay(specMaturity) {
  if (specMaturity === "candidate" || specMaturity === "experimental" || specMaturity === "sketch") return specMaturity;
  if (specMaturity === "not_applicable") return "not applicable";
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

// The generated block, markers included, in manifest order. The Group column
// (#709 review, P2) is the same axis DRAFTS.md's "###" sections already
// organize the prose catalog by, rendered here as data so the grouping shows
// up in the generated table too, not only as an implicit heading structure.
export function renderIndex(manifest) {
  const lines = [
    START_MARKER,
    "",
    "| Document | Role | Spec maturity | Verbs | Group | Summary | Pull this in when |",
    "|---|---|---|---|---|---|---|",
  ];
  for (const d of manifest.drafts) {
    const maturity = maturityDisplay(d.spec_maturity) ?? d.spec_maturity;
    const verbs = (d.verbs || []).join(", ");
    const group = GROUP_SECTION_TITLES[d.group] ?? d.group;
    lines.push(
      `| [${escapeCell(d.title)}](${editorsCopyUrl(d.slug)}) | ${d.role} | ${maturity} | ${verbs} | ${escapeCell(group)} | ${escapeCell(d.summary)} | ${escapeCell(d.pull_when)} |`
    );
  }
  lines.push("", END_MARKER);
  return lines.join("\n");
}

// Splices a freshly rendered block into `text` between one marker pair.
// Throws when either marker is missing or out of order, so a mangled file
// fails loudly rather than getting a second block appended.
export function spliceMarkedBlock(text, block, startMarker, endMarker, label) {
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

// Cumulative document set for a reference stack: its own `binding` or its
// contained stack's cumulative set, plus its own `adds`, deduplicated in
// order. Mirrors the manifest's own cumulative design
// (scripts/check-family-manifest.mjs's check (g) validates the `contains`
// chain has exactly one root and no cycle, which this relies on).
function stackDocuments(manifest, stackName) {
  const stack = manifest.reference_stacks[stackName];
  const inherited = stack.contains ? stackDocuments(manifest, stack.contains) : [stack.binding];
  return [...new Set([...inherited, ...(stack.adds || [])])];
}

// The generated block, markers included: the Architecture's four cumulative
// reference stacks (#709 review, P2: the ruling's "assurance levels" axis),
// each as a level name, its cumulative document list, and its summary,
// generated from the manifest's `reference_stacks` object so the catalog
// carries this axis as data rather than the README restating it in prose.
export function renderReferenceStacks(manifest) {
  const bySlug = new Map(manifest.drafts.map((d) => [d.slug, d]));
  const stackNames = Object.keys(manifest.reference_stacks).filter((k) => !k.startsWith("$"));
  const lines = [
    REFERENCE_STACKS_START,
    "",
    "| Level | Cumulative documents | Summary |",
    "|---|---|---|",
  ];
  for (const name of stackNames) {
    const stack = manifest.reference_stacks[name];
    const docs = stackDocuments(manifest, name);
    const titles = docs.map((s) => escapeCell(bySlug.get(s).title)).join(" + ");
    lines.push(`| ${escapeCell(stack.level)} | ${docs.length} document${docs.length === 1 ? "" : "s"}: ${titles} | ${escapeCell(stack.summary)} |`);
  }
  lines.push("", REFERENCE_STACKS_END);
  return lines.join("\n");
}

// Splices a freshly rendered reference-stacks block into DRAFTS.md's text.
export function spliceReferenceStacks(text, block) {
  return spliceMarkedBlock(text, block, REFERENCE_STACKS_START, REFERENCE_STACKS_END, "DRAFTS.md");
}

// Returns [] when DRAFTS.md's generated reference-stacks block matches what
// the manifest would produce, or a one-entry findings array when it does
// not. Never writes.
export function validateReferenceStacks(root = ROOT) {
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
  let block;
  try {
    block = renderReferenceStacks(manifest);
  } catch (e) {
    return [e.message];
  }
  let expected;
  try {
    expected = spliceReferenceStacks(text, block);
  } catch (e) {
    return [e.message];
  }
  if (expected !== text) {
    return [
      "DRAFTS.md's generated reference-stacks block is stale; run `node scripts/generate-drafts-index.mjs` to regenerate it",
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

// #707: conformance-manifest.json's requirement rows, grouped by their own
// `spec` field, one pass. This is the sole reader of conformance-manifest.json
// this file needs: every consumer below asks it "how many rows, and what
// coverage, for this one draft file" and gets back that draft's slice, never
// a family-wide scan of its own.
export function loadConformanceCounts(root = ROOT) {
  const conf = JSON.parse(fs.readFileSync(path.join(root, "conformance-manifest.json"), "utf8"));
  const bySpec = new Map();
  for (const r of conf.requirements) {
    if (!bySpec.has(r.spec)) bySpec.set(r.spec, { total: 0, tested: 0, partial: 0, todo: 0, blocked: 0 });
    const c = bySpec.get(r.spec);
    c.total += 1;
    c[r.coverage] = (c[r.coverage] ?? 0) + 1;
  }
  return bySpec;
}

// The derived implementation/conformance line (#707 ruling: "displayed beside
// maturity, never encoded into it"). A draft with no rows in the audited
// ledger says so plainly rather than rendering as a wall of zeros that reads
// as failure: the ledger is a traceability record for what src/ has
// undertaken, not a maturity signal, so its absence is a fact, not a fault.
export function conformanceSummary(bySpec, file) {
  const c = bySpec.get(file);
  if (!c || c.total === 0) {
    return "not yet in the conformance ledger (conformance-manifest.json)";
  }
  const parts = [];
  if (c.tested) parts.push(`${c.tested} tested`);
  if (c.partial) parts.push(`${c.partial} partial`);
  if (c.todo) parts.push(`${c.todo} todo`);
  if (c.blocked) parts.push(`${c.blocked} blocked`);
  return `${c.total} conformance row${c.total === 1 ? "" : "s"} in conformance-manifest.json (${parts.join(", ")})`;
}

// The generated block, markers included, for one draft's own "# Status"
// section (#643 origin, #707 extension): role, spec maturity, and derived
// conformance coverage sit beside each other on their own lines, then
// maintenance, adoption trigger, and typed requires edges as before. Never
// encodes conformance into the maturity word itself (the #707 ruling's own
// text): a candidate with an empty ledger and a candidate with heavy
// coverage render the same spec_maturity, different Implementation lines.
export function renderFamilyStatusBlock(d, bySlug, confBySpec) {
  const lines = [
    FAMILY_STATUS_BEGIN,
    `Role: ${d.role}. Spec maturity: ${maturityDisplay(d.spec_maturity) ?? d.spec_maturity}. Maintenance: ${d.maintenance}.`,
    `Implementation: ${conformanceSummary(confBySpec, d.file)}.`,
    `Adopt when: ${d.pull_when}`,
  ];
  const ar = d.adoption_requires || [];
  lines.push(ar.length
    ? `Requires: ${ar.map((s) => bySlug.get(s).title).join("; ")}.`
    : "Requires: nothing beyond its listed references.");
  const rw = d.requires_when || [];
  if (rw.length) {
    lines.push(`Also requires, conditionally: ${rw.map((e) => e.requires.map((s) => bySlug.get(s).title).join(" and ") + " (when " + e.when + ")").join("; ")}.`);
  }
  lines.push(FAMILY_STATUS_END);
  return lines.join("\n");
}

// Locates a draft's top-level "# Status" section and returns the [start, end)
// byte offsets of everything between its heading and the next top-level
// heading (or end of file). Returns null when the heading is missing.
function findStatusSection(text) {
  const head = text.match(/^# Status[^\n]*$/m);
  if (!head) return null;
  const start = text.indexOf(head[0]) + head[0].length;
  const rest = text.slice(start);
  const nextHead = rest.search(/^# [^#\n]/m);
  const end = nextHead === -1 ? text.length : start + nextHead;
  return [start, end];
}

// Returns [] when every non-exempt draft's family-status block matches what
// the manifest and conformance ledger would produce, or one finding per
// stale/missing block. Never writes.
export function validateFamilyStatusBlocks(root = ROOT) {
  const manifest = JSON.parse(fs.readFileSync(path.join(root, "family-manifest.json"), "utf8"));
  const bySlug = new Map(manifest.drafts.map((d) => [d.slug, d]));
  const confBySpec = loadConformanceCounts(root);
  const findings = [];
  for (const d of manifest.drafts) {
    if (d.file === FAMILY_STATUS_EXEMPT_FILE) continue;
    let text;
    try {
      text = fs.readFileSync(path.join(root, d.file), "utf8");
    } catch (e) {
      findings.push(`${d.file}: cannot read (${e.message})`);
      continue;
    }
    const bounds = findStatusSection(text);
    if (!bounds) {
      findings.push(`${d.file}: missing the top-level "# Status" section (family skeleton)`);
      continue;
    }
    const section = text.slice(bounds[0], bounds[1]);
    const expectedBlock = renderFamilyStatusBlock(d, bySlug, confBySpec);
    const bm = section.match(/<!-- family-status: BEGIN[\s\S]*?END -->/);
    if (!bm) {
      findings.push(`${d.file}: family-status block missing from the Status section`);
    } else if (bm[0] !== expectedBlock) {
      findings.push(`${d.file}: family-status block does not match the manifest; regenerate it to:\n${expectedBlock}`);
    }
  }
  return findings;
}

// Rewrites every non-exempt draft's family-status block in place. Returns
// the count of files actually changed (a no-op write is skipped so mtimes
// and git diffs stay quiet when nothing drifted).
export function writeFamilyStatusBlocks(root = ROOT) {
  const manifest = JSON.parse(fs.readFileSync(path.join(root, "family-manifest.json"), "utf8"));
  const bySlug = new Map(manifest.drafts.map((d) => [d.slug, d]));
  const confBySpec = loadConformanceCounts(root);
  let changed = 0;
  for (const d of manifest.drafts) {
    if (d.file === FAMILY_STATUS_EXEMPT_FILE) continue;
    const filePath = path.join(root, d.file);
    const text = fs.readFileSync(filePath, "utf8");
    const bounds = findStatusSection(text);
    if (!bounds) throw new Error(`${d.file}: missing the top-level "# Status" section (family skeleton)`);
    const [start, end] = bounds;
    const block = renderFamilyStatusBlock(d, bySlug, confBySpec);
    const newSection = spliceMarkedBlock(text.slice(start, end), block, FAMILY_STATUS_BEGIN, FAMILY_STATUS_END, d.file);
    const newText = text.slice(0, start) + newSection + text.slice(end);
    if (newText !== text) {
      fs.writeFileSync(filePath, newText);
      changed += 1;
    }
  }
  return changed;
}

// The generated block, markers included: a family-wide summary so README and
// DRAFTS.md's prose never hand-type a count that the manifest and
// conformance ledger already know (#707 ruling item 3: "ALL counts in
// README/DRAFTS derived/generated, never hand-written").
export function renderFamilyCounts(manifest, confBySpec) {
  const roleCounts = { core: 0, "adapter-binding": 0, companion: 0, guide: 0 };
  const maturityCounts = { candidate: 0, experimental: 0, sketch: 0, not_applicable: 0 };
  for (const d of manifest.drafts) {
    roleCounts[d.role] = (roleCounts[d.role] ?? 0) + 1;
    maturityCounts[d.spec_maturity] = (maturityCounts[d.spec_maturity] ?? 0) + 1;
  }
  const confBySpecEntries = [...confBySpec.values()];
  const totals = confBySpecEntries.reduce(
    (acc, c) => ({
      total: acc.total + c.total,
      tested: acc.tested + c.tested,
      partial: acc.partial + c.partial,
      todo: acc.todo + c.todo,
      blocked: acc.blocked + c.blocked,
    }),
    { total: 0, tested: 0, partial: 0, todo: 0, blocked: 0 },
  );
  const specsAudited = confBySpec.size;
  const specsUnaudited = manifest.drafts.length - specsAudited;
  const lines = [
    FAMILY_COUNTS_START,
    "",
    `${manifest.drafts.length} documents: ${roleCounts.core} core, ${roleCounts["adapter-binding"]} adapter-binding, ${roleCounts.companion} companion, ${roleCounts.guide} guide.`,
    `Spec maturity: ${maturityCounts.candidate} candidate, ${maturityCounts.experimental} experimental, ${maturityCounts.sketch} sketch, ${maturityCounts.not_applicable} not applicable (guide documents; protocol maturity does not apply).`,
    `Conformance ledger (\`conformance-manifest.json\`): ${totals.total} requirement rows across ${specsAudited} audited specs (${totals.tested} tested, ${totals.partial} partial, ${totals.todo} todo${totals.blocked ? `, ${totals.blocked} blocked` : ""}); ${specsUnaudited} documents carry no rows in the audited set yet.`,
    "",
    FAMILY_COUNTS_END,
  ];
  return lines.join("\n");
}

export function spliceFamilyCounts(text, block) {
  return spliceMarkedBlock(text, block, FAMILY_COUNTS_START, FAMILY_COUNTS_END, "DRAFTS.md");
}

// Returns [] when DRAFTS.md's generated family-counts block matches what the
// manifest and conformance ledger would produce, or a one-entry findings
// array when it does not. Never writes.
export function validateFamilyCounts(root = ROOT) {
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
  const confBySpec = loadConformanceCounts(root);
  let expected;
  try {
    expected = spliceFamilyCounts(text, renderFamilyCounts(manifest, confBySpec));
  } catch (e) {
    return [e.message];
  }
  if (expected !== text) {
    return [
      "DRAFTS.md's generated family-counts block is stale; run `node scripts/generate-drafts-index.mjs` to regenerate it",
    ];
  }
  return [];
}

// #723 review response: the five-criterion candidate gate as structured,
// resolvable evidence (candidate-gate.json) rather than a checker inferring
// completeness from a "# Conformance" heading. That heading proves a named
// floor exists (criterion 3); it proves nothing about criterion 1
// (complete requirement inventory), which is why the review's own
// counterexample (oauth-mission-resource-access: a real Conformance
// section, real conformance-manifest.json rows, all "todo", entirely
// unaudited for completeness) slipped past the earlier version of this
// gate. Coverage/evidence stays a displayed fact (each draft's
// family-status Implementation: line), never a gate threshold, per the
// ruling's own text ("do not gate candidate status on a raw percentage").
export function loadCandidateGate(root = ROOT) {
  return JSON.parse(fs.readFileSync(path.join(root, "candidate-gate.json"), "utf8"));
}

// True only for a syntactically valid, 40-hex commit SHA that this
// repository's object database can actually resolve. Never throws: a
// malformed or unknown SHA is simply "not found," the same as any other
// gate failure. Requires full history (CI runs `fetch-depth: 0`); a
// shallow clone would make an otherwise-valid ancestor SHA look missing,
// which is a CI configuration concern, not this function's.
export function commitExists(sha, root = ROOT) {
  if (typeof sha !== "string" || !/^[0-9a-f]{40}$/.test(sha)) return false;
  const res = spawnSync("git", ["cat-file", "-e", `${sha}^{commit}`], { cwd: root, stdio: "ignore" });
  return res.status === 0;
}

// Returns [] when every spec_maturity: "candidate" draft resolves all five
// criteria against candidate-gate.json and conformance-manifest.json, or one
// finding per unresolved criterion. Also validates candidate-gate.json's own
// structural integrity (real slugs) regardless of how many drafts currently
// claim candidate, so the ledger cannot silently rot while unused.
export function validateCandidateGate(root = ROOT) {
  const findings = [];
  const manifest = JSON.parse(fs.readFileSync(path.join(root, "family-manifest.json"), "utf8"));
  let gate;
  try {
    gate = loadCandidateGate(root);
  } catch (e) {
    return [`cannot read candidate-gate.json: ${e.message}`];
  }
  const manifestSlugs = new Set(manifest.drafts.map((d) => d.slug));

  for (const [issue, entry] of Object.entries(gate.decide_issue_scope || {})) {
    for (const slug of entry.slugs || []) {
      if (!manifestSlugs.has(slug)) {
        findings.push(`candidate-gate.json: decide_issue_scope["${issue}"] names "${slug}", which is not a family-manifest.json draft slug`);
      }
    }
  }
  for (const slug of Object.keys(gate.documents || {})) {
    if (!manifestSlugs.has(slug)) {
      findings.push(`candidate-gate.json: documents["${slug}"] is not a family-manifest.json draft slug`);
    }
  }

  const confBySpec = loadConformanceCounts(root);
  for (const d of manifest.drafts) {
    if (d.spec_maturity !== "candidate") continue;
    const docGate = (gate.documents || {})[d.slug];

    // Criterion 1: mechanical (an audit has been recorded against this spec
    // at all) AND attested (a human-recorded, commit-verified claim that the
    // recorded audit was a complete requirement inventory).
    if (!confBySpec.has(d.file)) {
      findings.push(`${d.slug}: spec_maturity is "candidate" but ${d.file} has no source.specs entry in conformance-manifest.json (no inventory audit has ever been recorded against it)`);
    }
    const inv = docGate?.requirement_inventory;
    if (!inv || inv.attested !== true || typeof inv.audited_by !== "string" || inv.audited_by.length === 0) {
      findings.push(`${d.slug}: spec_maturity is "candidate" but candidate-gate.json records no attested requirement_inventory (criterion 1: complete requirement inventory)`);
    } else if (!commitExists(inv.audited_by, root)) {
      findings.push(`${d.slug}: requirement_inventory.audited_by "${inv.audited_by}" does not resolve to a commit in this repository's history`);
    }

    // Criterion 2: every decide issue scoped to this slug must be recorded
    // resolved_in_tree with a commit the checker can independently verify
    // exists, never inferred from GitHub's open/closed issue metadata.
    const resolutions = new Map((docGate?.decide_resolutions || []).map((r) => [r.issue, r]));
    for (const [issueStr, entry] of Object.entries(gate.decide_issue_scope || {})) {
      const issue = Number(issueStr);
      if (!(entry.slugs || []).includes(d.slug)) continue;
      const res = resolutions.get(issue);
      if (!res || res.status !== "resolved_in_tree" || !commitExists(res.commit, root)) {
        findings.push(`${d.slug}: spec_maturity is "candidate" but decide issue #${issue} ("${entry.title}") is not recorded resolved_in_tree with a verifiable commit (criterion 2: no unresolved issue affecting the interface)`);
      }
    }

    // Criterion 3: a named floor: the document has a real Conformance-
    // titled section. (Representative implementation evidence is displayed,
    // not gated: see the Implementation: line in the family-status block.)
    const text = fs.readFileSync(path.join(root, d.file), "utf8");
    if (!/^#{1,2}.*Conformance/m.test(text)) {
      findings.push(`${d.slug}: spec_maturity is "candidate" but ${d.file} has no Conformance-titled section (criterion 3: named interoperability floor)`);
    }

    // Criterion 4: examples/vectors, or an explicit, non-empty, recorded
    // proportionality waiver (never a silent default).
    const hasExamples = text.includes("~~~");
    const waiver = docGate?.examples_waiver;
    if (!hasExamples && (!waiver || typeof waiver.reason !== "string" || waiver.reason.length === 0)) {
      findings.push(`${d.slug}: spec_maturity is "candidate" but ${d.file} has no example/vector artwork block and candidate-gate.json records no examples_waiver.reason (criterion 4)`);
    }

    // Criterion 5 (disclosed unstable external normative dependencies) is
    // already enforced structurally by check (q)'s generated
    // external-normative-ids block in DEPENDENCIES.md; no independent
    // re-check is needed here.
  }
  return findings;
}

function main() {
  const check = process.argv.includes("--check");
  if (check) {
    const findings = [
      ...validateDraftsIndex(ROOT),
      ...validateReferenceStacks(ROOT),
      ...validateBindingPackages(ROOT),
      ...validateFamilyCounts(ROOT),
      ...validateFamilyStatusBlocks(ROOT),
      ...validateCandidateGate(ROOT),
    ];
    if (findings.length > 0) {
      for (const f of findings) console.error(`drafts-index check FAILED: ${f}`);
      process.exit(1);
    }
    console.log("drafts-index check OK: DRAFTS.md's index, reference-stacks, and family-counts blocks, README.md's binding-packages block, every draft's family-status block, and the candidate gate, are current.");
    process.exit(0);
  }

  const manifest = JSON.parse(fs.readFileSync(MANIFEST_PATH, "utf8"));
  const confBySpec = loadConformanceCounts(ROOT);

  let draftsText = fs.readFileSync(DRAFTS_PATH, "utf8");
  const updatedIndex = spliceIndex(draftsText, renderIndex(manifest));
  if (updatedIndex === draftsText) {
    console.log(`drafts-index: DRAFTS.md's index already current (${manifest.drafts.length} rows).`);
  } else {
    draftsText = updatedIndex;
    console.log(`drafts-index: rewrote DRAFTS.md's index block (${manifest.drafts.length} rows).`);
  }

  const stackCount = Object.keys(manifest.reference_stacks).filter((k) => !k.startsWith("$")).length;
  const updatedStacks = spliceReferenceStacks(draftsText, renderReferenceStacks(manifest));
  if (updatedStacks === draftsText) {
    console.log(`drafts-index: DRAFTS.md's reference-stacks block already current (${stackCount} stacks).`);
  } else {
    draftsText = updatedStacks;
    console.log(`drafts-index: rewrote DRAFTS.md's reference-stacks block (${stackCount} stacks).`);
  }

  const updatedCounts = spliceFamilyCounts(draftsText, renderFamilyCounts(manifest, confBySpec));
  if (updatedCounts === draftsText) {
    console.log("drafts-index: DRAFTS.md's family-counts block already current.");
  } else {
    draftsText = updatedCounts;
    console.log("drafts-index: rewrote DRAFTS.md's family-counts block.");
  }

  fs.writeFileSync(DRAFTS_PATH, draftsText);

  const readmeText = fs.readFileSync(README_PATH, "utf8");
  const updatedReadme = spliceBindingPackages(readmeText, renderBindingPackages(manifest));
  if (updatedReadme === readmeText) {
    console.log(`drafts-index: README.md's binding-packages block already current (${BINDING_SLUGS.length} bindings).`);
  } else {
    fs.writeFileSync(README_PATH, updatedReadme);
    console.log(`drafts-index: rewrote README.md's binding-packages block (${BINDING_SLUGS.length} bindings).`);
  }

  const changedStatusBlocks = writeFamilyStatusBlocks(ROOT);
  console.log(
    changedStatusBlocks === 0
      ? "drafts-index: every draft's family-status block already current."
      : `drafts-index: rewrote ${changedStatusBlocks} draft(s)' family-status block.`,
  );
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main();
}
