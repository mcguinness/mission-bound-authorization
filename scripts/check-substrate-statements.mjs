#!/usr/bin/env node
// Structural tripwire for Mission Substrate Statement AND Mapping
// Assessment capability tables (#554 review, item 6; kind-tagged per the
// #717 review on #708). Three binding Statements retained the retired
// three-state vocabulary and omitted an entire capability without any
// validator noticing; this check makes both classes of drift fail CI.
//
// The registry covers two distinct kinds sharing one table format (the
// substrate requires a Mapping Assessment to use "the Statement's form"):
// a Statement (kind "statement") is a conforming binding's own normative
// conformance result; an Assessment (kind "assessment") is a non-claiming
// specification's informative self-description, never a conformance
// result, and never implies the assessed specification takes a normative
// dependency on the substrate. The structural checks below apply
// identically to both kinds; only the summary line and any future
// kind-specific rule would differ.
//
// Checks, per registered table:
//   (a) exactly the canonical eight capabilities, in canonical order;
//   (b) the Claim column says only `supplied` or `not supplied`;
//   (c) every supplied row states an activation condition (never empty,
//       never `--`) and carries non-empty Scope and Limitations cells,
//       the cells that hold its temporal and failure elements; and
//   (d) every not-supplied row uses `--` for Activation and Scope and
//       states its reason in Limitations.
// Plus repo-wide tripwires:
//   (e) the retired `supported`/`conditional`/`not supported` claim
//       vocabulary appears in no draft table cell;
//   (f) any table titled "…substrate capabilities" outside the registry
//       fails, so a new binding's Statement must register here; and
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
// a capability table here is what "binding" means architecturally (the
// README says as much: new bindings are authored against the substrate and
// claim their capabilities through a Statement, or, for a non-claiming
// specification, are assessed through an Assessment). `slug` names the
// family-manifest.json draft the table is FOR, which is not always the
// file it lives in. scripts/generate-drafts-index.mjs imports this array as
// the single source of truth for "which manifest slugs are bindings," so
// this list is exhaustive by construction: the tripwires below
// (statement-unregistered) already fail CI the moment a new Statement or
// Assessment table appears anywhere in the corpus without a matching entry
// here.
export const REGISTRY = [
  { file: "draft-mcguinness-oauth-mission.md", title: "OAuth Mission binding capability table", slug: "draft-mcguinness-oauth-mission", kind: "assessment" },
  { file: "draft-mcguinness-mission-authority-server.md", title: "Standalone MAS Mission substrate capabilities", slug: "draft-mcguinness-mission-authority-server", kind: "statement" },
  { file: "draft-mcguinness-mission-aauth.md", title: "AAuth Mission substrate capabilities", slug: "draft-mcguinness-mission-aauth", kind: "statement" },
  { file: "draft-mcguinness-mission-uma.md", title: "UMA Mission substrate capabilities", slug: "draft-mcguinness-mission-uma", kind: "statement" },
  { file: "draft-mcguinness-mission-gnap.md", title: "GNAP Mission substrate capabilities", slug: "draft-mcguinness-mission-gnap", kind: "statement" },
];

const HEADER = "| Capability | Claim | Activation | Scope and defining sections | Limitations |";
const RETIRED = /\|\s*(supported|conditional|not supported)\s*\|/;
const CONSUMER_HEADER = "| Capability | Consumption | Scope of consumption |";
const CONSUMER_SEPARATOR = "| --- | --- | --- |";
const CONSUMER_CLAIM = /^(required( and produced)?|required when .+|not consumed|produced)$/;

function tableEndingAt(lines, titleIdx) {
  const rows = [];
  for (let i = titleIdx - 1; i >= 0; i--) {
    const line = lines[i];
    if (!line.startsWith("|")) break;
    rows.unshift(line);
  }
  return rows;
}

function cells(row) {
  return row.split("|").slice(1, -1).map((c) => c.trim());
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

  for (const entry of REGISTRY) {
    const filePath = path.join(ROOT, entry.file);
    let text;
    try {
      text = readFileSync(filePath, "utf8");
    } catch {
      fail("statement-missing", `${entry.file}: file not found`);
      continue;
    }
    const lines = text.split("\n");
    const titleIdx = lines.findIndex((l) => l.includes(`{: title="${entry.title}"}`));
    if (titleIdx === -1) {
      fail("statement-missing", `${entry.file}: no table titled "${entry.title}"`);
      continue;
    }
    const rows = tableEndingAt(lines, titleIdx);
    if (rows.length < 2 || rows[0].trim() !== HEADER) {
      fail("statement-format", `${entry.file} ("${entry.title}"): header must be exactly the five-column Statement header`);
      continue;
    }
    const body = rows.slice(2); // header + separator
    const names = body.map((r) => cells(r)[0]);
    if (names.length !== CAPABILITIES.length || names.some((n, i) => n !== CAPABILITIES[i])) {
      fail("statement-capabilities", `${entry.file} ("${entry.title}"): rows must be exactly the canonical eight capabilities in order; found [${names.join(", ")}]`);
      continue;
    }
    for (const row of body) {
      const [name, claim, activation, scope, limitations] = cells(row);
      if (claim !== "supplied" && claim !== "not supplied") {
        fail("statement-claim", `${entry.file} ("${entry.title}") ${name}: claim must be "supplied" or "not supplied", found "${claim}"`);
        continue;
      }
      if (claim === "supplied") {
        if (!activation || activation === "--") {
          fail("statement-activation", `${entry.file} ("${entry.title}") ${name}: a supplied row must state its activation condition`);
        }
        if (!scope || scope === "--" || !limitations) {
          fail("statement-elements", `${entry.file} ("${entry.title}") ${name}: a supplied row must carry Scope and Limitations cells (the temporal and failure elements)`);
        }
      } else {
        if (activation !== "--" || scope !== "--") {
          fail("statement-not-supplied", `${entry.file} ("${entry.title}") ${name}: a not-supplied row uses "--" for Activation and Scope`);
        }
        if (!limitations) {
          fail("statement-not-supplied", `${entry.file} ("${entry.title}") ${name}: a not-supplied row states its reason in Limitations`);
        }
      }
    }
  }

  // Repo-wide tripwires.
  const registered = new Set(REGISTRY.map((e) => `${e.file}::${e.title}`));
  let consumerTables = 0;
  for (const file of readdirSync(ROOT).filter((f) => f.startsWith("draft-") && f.endsWith(".md"))) {
    const lines = readFileSync(path.join(ROOT, file), "utf8").split("\n");
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (line.startsWith("|") && RETIRED.test(line)) {
        fail("retired-vocabulary", `${file}:${i + 1}: retired capability-claim vocabulary in a table row`);
      }
      const m = line.match(/\{: title="([^"]*substrate capabilities[^"]*)"\}/i);
      if (m && !registered.has(`${file}::${m[1]}`)) {
        fail("statement-unregistered", `${file}:${i + 1}: Statement table "${m[1]}" is not registered in check-substrate-statements.mjs`);
      }
      // A differently titled table cannot evade registration: any table using
      // the exact five-column Statement header must be registered, and any
      // section titled "Mission Substrate Statement" must live in a file that
      // registers a Statement here. The substrate document itself is exempt
      // (as it already is on the "Mission Substrate Statement" heading check
      // below): its own non-normative skeleton illustrates the header without
      // being a binding's Statement.
      if (line.trim() === HEADER && !REGISTRY.some((e) => e.file === file) && file !== "draft-mcguinness-mission-substrate.md") {
        fail("statement-unregistered", `${file}:${i + 1}: a five-column Statement table in a file with no registered Statement`);
      }
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
  console.log(`substrate-statements check OK: ${statementCount} Statements, ${assessmentCount} Assessments, ${consumerTables} consumer tables validated.`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main();
}
