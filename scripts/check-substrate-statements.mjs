#!/usr/bin/env node
// Structural tripwire for Mission Substrate Statement AND Mapping
// Assessment capability lists (#554 review, item 6; kind-tagged per the
// #717 review on #708; list form per #1382). Three binding Statements
// retained the retired three-state vocabulary and omitted an entire
// capability without any validator noticing; this check makes both
// classes of drift fail CI.
//
// The registry covers two distinct kinds sharing one form (the substrate
// requires a Mapping Assessment to use "the Statement's form"): a
// Statement (kind "statement") is a conforming binding's own normative
// conformance result; an Assessment (kind "assessment") is a non-claiming
// specification's informative self-description, never a conformance
// result, and never implies the assessed specification takes a normative
// dependency on the substrate. The structural checks below apply
// identically to both kinds, and to the substrate's own non-normative
// skeleton (SKELETON, kept out of REGISTRY so the substrate never counts
// as a binding); only the summary line and any future kind-specific rule
// would differ.
//
// The form (#1382) is a kramdown definition list with one entry per
// capability, closed by an anchor attribute list that locates it:
//
//   Lifecycle-Gated Authorization:
//   : Claim: supplied
//
//     Activation: always
//
//     Scope and defining sections: ... ({{section}})
//
//     Limitations: ...
//
//   State-Observable:
//   : Claim: ...
//   ...
//   {: #<anchor> newline="true"}
//
// Each entry's term is a capability name with a trailing colon; its
// definition is exactly four paragraphs, each led by its label in this
// order: Claim, Activation, Scope and defining sections, Limitations.
// Wrapped lines are joined with single spaces before the checks below.
//
// Checks, per registered list (and the skeleton):
//   (a) exactly the canonical eight capabilities, in canonical order;
//   (b) the Claim member says only `supplied` or `not supplied`;
//   (c) every supplied entry states an activation condition (never
//       empty, never `--`) and carries non-empty Scope and Limitations
//       members, the members that hold its temporal and failure
//       elements; and
//   (d) every not-supplied entry uses `--` for Activation and Scope and
//       states its reason in Limitations.
// Plus repo-wide tripwires:
//   (e) the retired `supported`/`conditional`/`not supported` claim
//       vocabulary appears in no draft table cell and no Claim member;
//   (f) every capability entry anywhere in the corpus (a `: Claim:`
//       member, or a canonical capability term opening a definition)
//       lies inside a registered list or the skeleton, so a new
//       binding's Statement must register here; the retired five-column
//       table form, and any table titled "...substrate capabilities",
//       fail wherever they appear; and a "Mission Substrate Statement"
//       section must live in a file that registers a Statement; and
//   (g) every consumer capability-consumption table (any table with the
//       `| Capability | Consumption | Scope of consumption |` header,
//       found by the header itself rather than a filename allowlist, so
//       a new consumer table self-registers) uses only a legal
//       Consumption value (`required`, `required and produced`,
//       `required when <condition>`, `not consumed`, or `produced`),
//       names a canonical capability without repeating it, and carries a
//       non-empty Scope of consumption cell (#620; unlike Statements, a
//       consumer table legitimately omits untouched capabilities and
//       needs no fixed order).
//
// Semantic completeness of temporal/failure elements remains a review
// property; (c) is the structural proxy.

import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));

const CAPABILITIES = [
  "Lifecycle-Gated Authorization",
  "State-Observable",
  "Structured Authority",
  "Monotonic Derivation",
  "Credential-Bound",
  "Authorized Context Correlation",
  "Independently Verifiable",
  "Portable Evidence",
];

// Every registered Statement or Assessment is a Mission binding: publishing
// a capability list here is what "binding" means architecturally (the
// README says as much: new bindings are authored against the substrate and
// claim their capabilities through a Statement, or, for a non-claiming
// specification, are assessed through an Assessment). `slug` names the
// family-manifest.json draft the list is FOR, which is not always the
// file it lives in; `anchor` is the list's closing `{: #anchor}`.
// scripts/generate-drafts-index.mjs imports this array as the single
// source of truth for "which manifest slugs are bindings," so this list is
// exhaustive by construction: the tripwires below (statement-unregistered)
// already fail CI the moment a capability entry appears anywhere in the
// corpus outside a registered list.
export const REGISTRY = [
  { file: "draft-mcguinness-oauth-mission.md", anchor: "oauth-mission-binding-capabilities", slug: "draft-mcguinness-oauth-mission", kind: "assessment" },
  { file: "draft-mcguinness-mission-authority-server.md", anchor: "standalone-mas-mission-substrate-capabilities", slug: "draft-mcguinness-mission-authority-server", kind: "statement" },
  { file: "draft-mcguinness-mission-aauth.md", anchor: "aauth-mission-substrate-capabilities", slug: "draft-mcguinness-mission-aauth", kind: "statement" },
  { file: "draft-mcguinness-mission-uma.md", anchor: "uma-mission-substrate-capabilities", slug: "draft-mcguinness-mission-uma", kind: "statement" },
  { file: "draft-mcguinness-mission-gnap.md", anchor: "gnap-mission-substrate-capabilities", slug: "draft-mcguinness-mission-gnap", kind: "statement" },
];

// The substrate's own non-normative skeleton: validated in the same form,
// never a binding.
const SKELETON = { file: "draft-mcguinness-mission-substrate.md", anchor: "illustrative-statement-capabilities", kind: "skeleton" };

const LABELS = ["Claim", "Activation", "Scope and defining sections", "Limitations"];
const RETIRED_HEADER = "| Capability | Claim | Activation | Scope and defining sections | Limitations |";
const RETIRED = /\|\s*(supported|conditional|not supported)\s*\|/;
const RETIRED_CLAIM = /^(?::|\s)\s*Claim:\s*(supported|conditional|not supported)\s*$/;
const CLAIM_MEMBER = /^:\s+Claim:/;
const CONSUMER_HEADER = "| Capability | Consumption | Scope of consumption |";
const CONSUMER_SEPARATOR = "| --- | --- | --- |";
const CONSUMER_CLAIM = /^(required( and produced)?|required when .+|not consumed|produced)$/;

function cells(row) {
  return row.split("|").slice(1, -1).map((c) => c.trim());
}

function escapeRegExp(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// A definition-list term: an unindented, non-empty line whose next line
// opens a definition.
function isTerm(lines, i) {
  const line = lines[i];
  return line !== "" && !line.startsWith(" ") && !line.startsWith(":") && !line.startsWith("{:") && (lines[i + 1] ?? "").startsWith(": ");
}

// Locate a capability list by its closing anchor and parse its entries.
// Returns { start, end, entries, errors }: `start` is the first term's
// line index and `end` the anchor's; each entry is { name, line, members }
// with members keyed by label. `errors` lists format findings.
export function parseCapabilityList(lines, anchor) {
  const re = new RegExp(`^\\{:.*#${escapeRegExp(anchor)}(?=[\\s}])`);
  const end = lines.findIndex((l) => re.test(l));
  if (end === -1) return { missing: true };
  const errors = [];
  if (end === 0 || lines[end - 1] === "") {
    errors.push(`the {: #${anchor}} line must directly follow the list's last line`);
    return { start: end, end, entries: [], errors };
  }
  // Walk up from the anchor through the definition list it closes.
  let start = end;
  for (let i = end - 1; i >= 0; i--) {
    const line = lines[i];
    if (line === "" || line.startsWith("  ") || line.startsWith(": ") || isTerm(lines, i)) {
      start = i;
      continue;
    }
    break;
  }
  while (start < end && !isTerm(lines, start)) start += 1;
  if (start === end) {
    errors.push(`no definition-list entries precede {: #${anchor}}`);
    return { start, end, entries: [], errors };
  }
  if (start > 0 && lines[start - 1] !== "") {
    errors.push(`line ${start}: a blank line must separate the list from the text before it`);
  }

  const entries = [];
  let cur = null;
  for (let i = start; i < end; i++) {
    const line = lines[i];
    if (isTerm(lines, i)) {
      if (cur && lines[i - 1] !== "") {
        errors.push(`line ${i + 1}: a blank line must precede the term "${line}"`);
      }
      cur = { name: line.replace(/:$/, ""), line: i + 1, raw: [] };
      entries.push(cur);
      continue;
    }
    const first = cur.raw.length === 0;
    if (first ? !line.startsWith(": ") : line !== "" && !line.startsWith("  ")) {
      errors.push(`line ${i + 1} (${cur.name}): ${first ? 'a definition opens with ": "' : "definition lines are blank or indented two spaces"}`);
    }
    cur.raw.push(line.slice(2));
  }

  for (const entry of entries) {
    const paragraphs = [];
    let para = [];
    for (const l of entry.raw) {
      if (l.trim() === "") {
        if (para.length) paragraphs.push(para.join(" "));
        para = [];
      } else {
        para.push(l.trim());
      }
    }
    if (para.length) paragraphs.push(para.join(" "));
    entry.members = {};
    const labelled = paragraphs.length === LABELS.length && paragraphs.every((p, k) => p.startsWith(`${LABELS[k]}:`));
    if (!labelled) {
      errors.push(`line ${entry.line} (${entry.name}): an entry's definition is exactly four paragraphs led by ${LABELS.map((l) => `"${l}:"`).join(", ")}, in that order`);
      continue;
    }
    paragraphs.forEach((p, k) => {
      entry.members[LABELS[k]] = p.slice(LABELS[k].length + 1).trim();
    });
    delete entry.raw;
  }
  return { start, end, entries, errors };
}

// Checks (a) to (d) on one located list. Returns findings as [tag, msg].
export function validateCapabilityList(parsed, where) {
  const findings = [];
  if (parsed.errors.length > 0) {
    for (const e of parsed.errors) findings.push(["statement-format", `${where}: ${e}`]);
    return findings;
  }
  const names = parsed.entries.map((e) => e.name);
  if (names.length !== CAPABILITIES.length || names.some((n, i) => n !== CAPABILITIES[i])) {
    findings.push(["statement-capabilities", `${where}: entries must be exactly the canonical eight capabilities in order; found [${names.join(", ")}]`]);
    return findings;
  }
  for (const { name, members } of parsed.entries) {
    const claim = members.Claim;
    const activation = members.Activation;
    const scope = members["Scope and defining sections"];
    const limitations = members.Limitations;
    if (claim !== "supplied" && claim !== "not supplied") {
      findings.push(["statement-claim", `${where} ${name}: claim must be "supplied" or "not supplied", found "${claim}"`]);
      continue;
    }
    if (claim === "supplied") {
      if (!activation || activation === "--") {
        findings.push(["statement-activation", `${where} ${name}: a supplied entry must state its activation condition`]);
      }
      if (!scope || scope === "--" || !limitations) {
        findings.push(["statement-elements", `${where} ${name}: a supplied entry must carry Scope and Limitations members (the temporal and failure elements)`]);
      }
    } else {
      if (activation !== "--" || scope !== "--") {
        findings.push(["statement-not-supplied", `${where} ${name}: a not-supplied entry uses "--" for Activation and Scope`]);
      }
      if (!limitations) {
        findings.push(["statement-not-supplied", `${where} ${name}: a not-supplied entry states its reason in Limitations`]);
      }
    }
  }
  return findings;
}

// Guarded so importing REGISTRY (scripts/generate-drafts-index.mjs does, as
// the single source of truth for "which manifest slugs are bindings") never
// runs this file's own validation as an import side effect; only running
// this file directly does.
function main() {
  let failures = 0;
  const fail = (tag, msg) => {
    failures += 1;
    console.error(`[${tag}] ${msg}`);
  };

  // Line ranges of every located list, per file, for tripwire (f).
  const covered = new Map();
  for (const entry of [...REGISTRY, SKELETON]) {
    const where = `${entry.file} (#${entry.anchor})`;
    let text;
    try {
      text = readFileSync(path.join(ROOT, entry.file), "utf8");
    } catch {
      fail("statement-missing", `${entry.file}: file not found`);
      continue;
    }
    const parsed = parseCapabilityList(text.split("\n"), entry.anchor);
    if (parsed.missing) {
      fail("statement-missing", `${entry.file}: no capability list closed by {: #${entry.anchor}}`);
      continue;
    }
    if (!covered.has(entry.file)) covered.set(entry.file, []);
    covered.get(entry.file).push([parsed.start, parsed.end]);
    for (const [tag, msg] of validateCapabilityList(parsed, where)) fail(tag, msg);
  }

  // Repo-wide tripwires.
  let consumerTables = 0;
  for (const file of readdirSync(ROOT).filter((f) => f.startsWith("draft-") && f.endsWith(".md"))) {
    const lines = readFileSync(path.join(ROOT, file), "utf8").split("\n");
    const ranges = covered.get(file) ?? [];
    const inList = (i) => ranges.some(([s, e]) => i >= s && i <= e);
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if ((line.startsWith("|") && RETIRED.test(line)) || RETIRED_CLAIM.test(line)) {
        fail("retired-vocabulary", `${file}:${i + 1}: retired capability-claim vocabulary in a table row or Claim member`);
      }
      // A capability entry outside every located list: a Claim member, or
      // a canonical capability opening a definition. Either one is a
      // Statement, Assessment, or skeleton that is not registered here.
      if (!inList(i) && (CLAIM_MEMBER.test(line) || (isTerm(lines, i) && CAPABILITIES.includes(line.replace(/:$/, ""))))) {
        fail("statement-unregistered", `${file}:${i + 1}: a capability entry outside every list registered in check-substrate-statements.mjs`);
      }
      // The retired table form (#1382) fails wherever it appears, under
      // its header or its old "...substrate capabilities" title.
      if (line.trim() === RETIRED_HEADER) {
        fail("statement-unregistered", `${file}:${i + 1}: the retired five-column Statement table; the Statement form is a capability list`);
      }
      const m = line.match(/\{: title="([^"]*substrate capabilities[^"]*)"\}/i);
      if (m) {
        fail("statement-unregistered", `${file}:${i + 1}: a table titled "${m[1]}"; the Statement form is a capability list`);
      }
      // A section titled "Mission Substrate Statement" must live in a file
      // that registers a Statement here. The substrate document itself is
      // exempt: it defines the section.
      if (/^#+\s.*Mission Substrate Statement/.test(line) && !REGISTRY.some((e) => e.file === file) && file !== "draft-mcguinness-mission-substrate.md") {
        fail("statement-unregistered", `${file}:${i + 1}: a "Mission Substrate Statement" section in a file with no registered Statement`);
      }

      // Consumer capability-consumption tables self-register by header: any
      // table with this exact three-column header is validated, no allowlist
      // needed (#620).
      if (line.trim() === CONSUMER_HEADER) {
        consumerTables += 1;
        if (lines[i + 1]?.trim() !== CONSUMER_SEPARATOR) {
          fail("consumer-format", `${file}:${i + 2}: a consumer table's header must be followed by the three-column separator row`);
          continue;
        }
        let j = i + 2;
        const seen = new Set();
        while (j < lines.length && lines[j].startsWith("|")) {
          const [name, claim, scope] = cells(lines[j]);
          if (!CAPABILITIES.includes(name)) {
            fail("consumer-capability", `${file}:${j + 1}: "${name}" is not one of the canonical eight capabilities`);
          } else if (seen.has(name)) {
            fail("consumer-capability", `${file}:${j + 1}: "${name}" appears more than once in this table`);
          } else {
            seen.add(name);
          }
          if (!CONSUMER_CLAIM.test(claim ?? "")) {
            fail(
              "consumer-claim",
              `${file}:${j + 1} (${name}): consumption must be "required", "required and produced", "required when <condition>", "not consumed", or "produced"; found "${claim}"`
            );
          }
          if (!scope) {
            fail("consumer-scope", `${file}:${j + 1} (${name}): a consumer row must carry a non-empty Scope of consumption cell`);
          }
          j += 1;
        }
        if (j === i + 2) {
          fail("consumer-format", `${file}:${i + 1}: a consumer table must carry at least one row`);
        }
      }
    }
  }

  if (failures > 0) {
    console.error(`substrate-statements check FAILED: ${failures} finding(s).`);
    process.exit(1);
  }
  const statementCount = REGISTRY.filter((e) => e.kind === "statement").length;
  const assessmentCount = REGISTRY.filter((e) => e.kind === "assessment").length;
  console.log(`substrate-statements check OK: ${statementCount} Statements, ${assessmentCount} Assessments, the substrate skeleton, ${consumerTables} consumer tables validated.`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main();
}
