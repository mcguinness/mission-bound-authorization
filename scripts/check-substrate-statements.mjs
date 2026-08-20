#!/usr/bin/env node
// Structural tripwire for Mission Substrate Statement capability tables
// (#554 review, item 6). Three binding Statements retained the retired
// three-state vocabulary and omitted an entire capability without any
// validator noticing; this check makes both classes of drift fail CI.
//
// Checks, per registered Statement table:
//   (a) exactly the canonical eight capabilities, in canonical order;
//   (b) the Claim column says only `supplied` or `not supplied`;
//   (c) every supplied row states an activation condition (never empty,
//       never `--`) and carries non-empty Scope and Limitations cells,
//       the cells that hold its temporal and failure elements; and
//   (d) every not-supplied row uses `--` for Activation and Scope and
//       states its reason in Limitations.
// Plus two repo-wide tripwires:
//   (e) the retired `supported`/`conditional`/`not supported` claim
//       vocabulary appears in no draft table cell; and
//   (f) any table titled "…substrate capabilities" outside the registry
//       fails, so a new binding's Statement must register here.
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

const REGISTRY = [
  { file: "draft-mcguinness-mission-substrate.md", title: "OAuth Mission binding capability table" },
  { file: "draft-mcguinness-mission-gnap.md", title: "GNAP Mission substrate capabilities" },
  { file: "draft-mcguinness-mission-aauth.md", title: "AAuth Mission substrate capabilities" },
  { file: "draft-mcguinness-mission-authority-server.md", title: "Standalone MAS Mission substrate capabilities" },
  { file: "draft-mcguinness-mission-uma.md", title: "UMA Mission substrate capabilities" },
];

const HEADER = "| Capability | Claim | Activation | Scope and defining sections | Limitations |";
const RETIRED = /\|\s*(supported|conditional|not supported)\s*\|/;

let failures = 0;
const fail = (tag, msg) => {
  failures += 1;
  console.error(`[${tag}] ${msg}`);
};

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

// Repo-wide tripwires. The five consumer capability tables keep the
// retired vocabulary until #620 migrates them to consumer terms
// (required / required when / not consumed); remove this allowlist with
// that issue, after which retired vocabulary anywhere fails.
const CONSUMER_TABLE_ALLOWLIST_620 = new Set([
  "draft-mcguinness-mission-harness.md",
  "draft-mcguinness-mission-runtime.md",
  "draft-mcguinness-mission-orchestration.md",
  "draft-mcguinness-mission-metering.md",
  "draft-mcguinness-oauth-mission-containment.md",
]);

const registered = new Set(REGISTRY.map((e) => `${e.file}::${e.title}`));
for (const file of readdirSync(ROOT).filter((f) => f.startsWith("draft-") && f.endsWith(".md"))) {
  const lines = readFileSync(path.join(ROOT, file), "utf8").split("\n");
  lines.forEach((line, i) => {
    if (line.startsWith("|") && RETIRED.test(line) && !CONSUMER_TABLE_ALLOWLIST_620.has(file)) {
      fail("retired-vocabulary", `${file}:${i + 1}: retired capability-claim vocabulary in a table row`);
    }
    const m = line.match(/\{: title="([^"]*substrate capabilities[^"]*)"\}/i);
    if (m && !registered.has(`${file}::${m[1]}`)) {
      fail("statement-unregistered", `${file}:${i + 1}: Statement table "${m[1]}" is not registered in check-substrate-statements.mjs`);
    }
  });
}

if (failures > 0) {
  console.error(`substrate-statements check FAILED: ${failures} finding(s).`);
  process.exit(1);
}
console.log(`substrate-statements check OK: ${REGISTRY.length} Statements validated.`);
