#!/usr/bin/env node
// The baseline Mission fixture (#1176 item 5, D510). Builds
// vectors/baseline-q3/baseline-q3.json: the one Mission every example of
// the baseline reference (`https://as.example.com`,
// `msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-`) follows, with its anchors
// computed over the displayed objects, its dated timeline keyed on Status
// versions, and the named variants whose flows need a different Mission.
//
// Anchors use the core's integrity-anchor construction (draft-mcguinness-
// oauth-mission, Section "Integrity Anchors"): JCS (RFC 8785) over
// {typ, iss, value}, SHA-256, `sha-256:` plus unpadded base64url. Before
// building, the script reproduces the core's own test vectors, so a
// construction error cannot produce a fixture.
//
// A variant's Mission identifier is `msn_` plus the first 32 base64url
// characters of SHA-256 over its fixed label, `baseline-q3/variant/<name>`.
//
// Usage: node scripts/generate-baseline-fixture.mjs [--check]
//   --check  fail if the fixture file differs from what this script builds.

import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const OUT = path.join(ROOT, "vectors", "baseline-q3", "baseline-q3.json");

// JCS for the shapes a fixture holds: objects, arrays, strings, integers,
// booleans, null. Member names sort by UTF-16 code units, as the default
// string comparison does.
export function canonicalize(v) {
  if (v === null || typeof v === "boolean" || typeof v === "string") return JSON.stringify(v);
  if (typeof v === "number") {
    if (!Number.isSafeInteger(v)) throw new Error(`fixture numbers are integers: ${v}`);
    return JSON.stringify(v);
  }
  if (Array.isArray(v)) return `[${v.map(canonicalize).join(",")}]`;
  if (typeof v === "object") {
    const keys = Object.keys(v).sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalize(v[k])}`).join(",")}}`;
  }
  throw new Error(`cannot canonicalize ${typeof v}`);
}

const b64u = (buf) => buf.toString("base64url");
const sha256 = (s) => createHash("sha256").update(s, "utf8").digest();

export function anchor(typ, iss, value) {
  return `sha-256:${b64u(sha256(canonicalize({ typ, iss, value })))}`;
}

export function variantId(name) {
  return `msn_${b64u(sha256(`baseline-q3/variant/${name}`)).slice(0, 32)}`;
}

const numericDate = (rfc3339) => {
  const ms = Date.parse(rfc3339);
  if (!Number.isFinite(ms) || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/.test(rfc3339)) {
    throw new Error(`not an RFC 3339 UTC instant: ${rfc3339}`);
  }
  return ms / 1000;
};

// The core's test vectors (Appendix "Test Vectors"): the construction must
// reproduce them before it computes anything else.
function selfTest() {
  const iss = "https://as.example.com";
  const cases = [
    [
      "mission-intent",
      { goal: "Reconcile Q3 invoices", target_resources: ["https://erp.example.com"], expires_at: "2026-12-31T23:59:59Z" },
      "sha-256:sE_2V3NaDpGNYM8dH1tLpNJnj-RmaHN3FC6ZcbOLJSw",
    ],
    [
      "mission-authority-set",
      [
        { type: "mission_resource_access", resource: "https://erp.example.com", actions: ["invoices.read"] },
        {
          type: "mission_resource_access",
          resource: "https://erp.example.com",
          actions: ["journal-entries.write"],
          constraints: { max_amount: { amount: "500.00", currency: "USD" } },
        },
      ],
      "sha-256:vUCCfjGulit9u0qJ0Z6pQSNerZtXMqRlfJNCr4PzLro",
    ],
  ];
  for (const [typ, value, want] of cases) {
    const got = anchor(typ, iss, value);
    if (got !== want) throw new Error(`self-test failed for ${typ}: ${got} != ${want}`);
  }
}

const ISSUER = "https://as.example.com";
const MISSION_ID = "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-";
const ALICE = { iss: "https://idp.example.com", sub: "user_3p2q8mN1a0kV7tR" };
const EXPIRES_AT = "2026-12-31T23:59:59Z";

// D510: the Intent, verbatim.
const INTENT = {
  goal: "Reconcile Q3 invoices and post adjustments of at most USD 500 per journal entry.",
  target_resources: ["https://erp.example.com"],
  task_bounds: ["Read only invoices issued in 2026-Q3.", "Post journal entries of at most USD 500 each."],
  purpose: "urn:example:purpose:reconcile",
  expires_at: EXPIRES_AT,
};

const Q3_BOUNDS = {
  resource_issued_after: "2026-07-01T00:00:00Z",
  resource_issued_before: "2026-09-30T23:59:59Z",
};
const READ_DELEGATION = { max_depth: 2, allowed_delegates: [{ sub_profile: "ai_agent" }] };
const JOURNAL_ENTRY = {
  type: "mission_resource_access",
  resource: "https://erp.example.com",
  actions: ["journal-entries.write"],
  constraints: { max_amount: { amount: "500.00", currency: "USD" } },
};

// The client's proposal and the consented Authority Set the core's Worked
// Example records: separate invoice-read and journal-write entries, the Q3
// issuance bounds, read delegation, the per-action ceiling, no aggregate cap.
const PROPOSED_AUTHORITY = [
  {
    type: "mission_resource_access",
    resource: "https://erp.example.com",
    actions: ["invoices.*"],
    constraints: Q3_BOUNDS,
    delegation: READ_DELEGATION,
  },
  JOURNAL_ENTRY,
];
const AUTHORITY_SET = [
  {
    type: "mission_resource_access",
    resource: "https://erp.example.com",
    actions: ["invoices.read"],
    constraints: Q3_BOUNDS,
    delegation: READ_DELEGATION,
  },
  JOURNAL_ENTRY,
];

// D510's timeline, UTC on 2026-11-02. Token issuance and ordinary execution
// leave the Status version unchanged.
const TIMELINE = [
  { at: "2026-11-02T08:00:00Z", event: "approval-and-creation", state: "active", version: 1 },
  { at: "2026-11-02T08:00:05Z", event: "first-token-issuance", state: "active", version: 1 },
  { at: "2026-11-02T08:20:00Z", event: "suspension", state: "suspended", version: 2 },
  { at: "2026-11-02T08:30:00Z", event: "resume", state: "active", version: 3 },
  { at: "2026-11-02T08:53:20Z", event: "revocation", state: "terminated", termination_reason: "revoked", version: 4 },
];
const ACCESS_TOKEN_LIFETIME = 300;

// The access tokens the examples show, each issued in an active window with
// the 300 s lifetime. `entries` indexes the Authority Set.
const TOKENS = [
  { name: "first", grant: "authorization_code", client_id: "s6BhdRkqt3", jti: "at_9Kp2vN7sR1tY8mZ3qX5b", at: "2026-11-02T08:00:05Z", entries: [0, 1] },
  { name: "delegated", grant: "token-exchange", client_id: "tool-runner-7", jti: "at_3qX5bN7sR1tY8mZ9Kp2v", at: "2026-11-02T08:10:05Z", entries: [0] },
  { name: "journal-write", grant: "refresh_token", client_id: "s6BhdRkqt3", jti: "at_5v9Kq2mR7xW4nP8sL1zT6", at: "2026-11-02T08:14:00Z", entries: [1] },
  { name: "refreshed", grant: "refresh_token", client_id: "s6BhdRkqt3", at: "2026-11-02T08:50:00Z", entries: [0] },
];

// The revocation at 08:53:20 is the Status lifecycle `revoke` by the
// Mission's client, under an explicit lifecycle authorization the scenario
// grants it for this Mission (Status, Authorization): being the Mission's
// client, holding its resource tokens, or a DPoP binding confers none.
const REVOCATION = {
  actor: "s6BhdRkqt3",
  operation: "revoke",
  authorization: "mission_lifecycle grant for this Mission",
  reason: "Quarterly reconcile completed early",
};

// Named variants: flows that need a different Mission than the baseline's
// one history. Each has its own Mission reference; none is inserted into
// the baseline timeline. `id` is set only where an example keeps an
// existing reference under another issuer. `drafts` lists where each
// variant appears.
const VARIANTS = [
  { name: "overnight-revocation", differs_by: "Active by 2026-11-01T22:00:00Z; Alice revokes it at 2026-11-01T23:00:00Z, and the harness suppresses a queued resume at 2026-11-02T02:00:05Z.", drafts: ["harness"] },
  { name: "scheduled-suspend-revoke", differs_by: "Suspended at 08:20:00 (version 2) with `suspend_until` 2026-11-09T08:15:00Z and `on_expiry` `revoke`; never resumed, so the deadline revokes it (version 3).", drafts: ["status"] },
  { name: "superseded-by-expansion", differs_by: "Never suspended; superseded at 09:40:00 (version 2) by the expanded Mission `msn_2Yt7Qv9LqMv4z7sA2bN1k0YpEdHc9RfX`.", drafts: ["expansion", "signals"] },
  { name: "subject-compromise-sweep", differs_by: "Follows the baseline through the 08:30:00 resume (version 3) but is not revoked at 08:53:20; a bulk subject sweep revokes it at 09:33:00 (version 4).", drafts: ["management"] },
  { name: "mas-issued", issuer: "https://mas.example.com", id: MISSION_ID, differs_by: "The baseline task and Authority Set issued by a Mission Authority Server under its own issuer, with no proposal; its anchors use `iss` `https://mas.example.com`.", drafts: ["authority-server", "issuance-grant"] },
  { name: "cap-expansion", issuer: "https://mas.example.com", differs_by: "A Mission Authority Server Mission whose 1,200 USD adjustment leads to an approved expansion to a 2,000 USD cap.", drafts: ["authority-server"] },
  { name: "agr-backed-direct", differs_by: "Alice's approval is recorded through an Approval Governance Record.", drafts: ["approval-governance"] },
  { name: "governed-policy-activation", differs_by: "Activated under `governed_policy`: Alice approved the policy `q3-close-agent` version 3 at 2026-10-30T16:00:00Z, and the policy activates the client's proposal of the baseline task at 08:00:00 with no fresh human decision.", drafts: ["approval-governance"] },
  { name: "metered-consumption", differs_by: "The Intent adds consumption bounds and the Authority Set adds a `reconciliation.run` entry.", drafts: ["metering"] },
  { name: "children-enabled", differs_by: "The invoice-read entry's `delegation` adds `children`.", drafts: ["child-delegation"] },
  { name: "write-delegable", differs_by: "The journal-write entry carries a `delegation` member.", drafts: ["attenuation"] },
  { name: "contained-on-taint", differs_by: "After the 08:30:00 resume, a containment at 08:41:02 (version 4) removes `journal-entries.write`.", drafts: ["containment"] },
  { name: "discharge-at-close", differs_by: "The journal-write entry carries a `terminal_when` discharge condition.", drafts: ["discharge"] },
  { name: "derivation-limited", differs_by: "The Intent requests a derivation limit of 200.", drafts: ["derivation-limits"] },
  { name: "cross-domain-partner", differs_by: "The Intent and Authority Set add the partner ERP `https://erp.partner.example.com`.", drafts: ["cross-domain"] },
  { name: "revision-read-only", differs_by: "A deferred, revised approval: the Approver refuses `journal-entries.write`, so the Mission holds only the invoice-read entry.", drafts: ["approval-revision"] },
  { name: "ceiling-drawdown", differs_by: "Holds only the invoice-read entry, with Alice's consent to an authority ceiling (the baseline's two entries plus `invoices.write`) under drawdown policy `q3-reconcile-drawdown` version 1. A policy-adjudicated drawdown at 09:15:00 adds the journal-write entry and supersedes it with `msn_uG1kkHwXSlzUs4OKztGGk5FOmBnkpTOb`, whose request at 09:18:00 for a 2,000 USD cap is refused `out_of_ceiling`.", drafts: ["progressive"] },
];

function build() {
  selfTest();
  const intentHash = anchor("mission-intent", ISSUER, INTENT);
  const proposalHash = anchor("mission-proposed-authority", ISSUER, PROPOSED_AUTHORITY);
  const authorityHash = anchor("mission-authority-set", ISSUER, AUTHORITY_SET);
  const timeline = TIMELINE.map((e) => ({ ...e, numeric_date: numericDate(e.at) }));
  const tokens = TOKENS.map(({ at, ...t }) => {
    const iat = numericDate(at);
    return { ...t, issued_at: at, iat, exp: iat + ACCESS_TOKEN_LIFETIME };
  });
  const first = tokens.find((t) => t.name === "first");
  const firstToken = { iat: first.iat, exp: first.exp };

  // Invariants the examples rely on: an ordered timeline with increasing
  // versions, and every token issued while the Mission is active.
  for (let i = 1; i < timeline.length; i++) {
    if (timeline[i].numeric_date <= timeline[i - 1].numeric_date) throw new Error("timeline is not ordered");
    if (timeline[i].version < timeline[i - 1].version) throw new Error("version decreased");
  }
  const stateAt = (t) => timeline.filter((e) => e.numeric_date <= t).at(-1)?.state;
  for (const t of tokens) {
    if (stateAt(t.iat) !== "active") throw new Error(`token ${t.name} issued while not active`);
    if (t.exp > numericDate(EXPIRES_AT)) throw new Error(`token ${t.name} outlives the Mission`);
    if (t.entries.some((i) => !AUTHORITY_SET[i])) throw new Error(`token ${t.name} names no entry`);
  }
  if (first.iat !== timeline.find((e) => e.event === "first-token-issuance").numeric_date) {
    throw new Error("the first token is not the first issuance");
  }
  const names = new Set();
  for (const v of VARIANTS) {
    if (names.has(v.name) || !/^[a-z0-9]+(-[a-z0-9]+)*$/.test(v.name)) throw new Error(`bad variant name ${v.name}`);
    names.add(v.name);
    if (v.id && (v.issuer ?? ISSUER) === ISSUER) throw new Error(`variant ${v.name} reuses the baseline reference`);
  }

  const record = {
    id: MISSION_ID,
    issuer: ISSUER,
    state: "active",
    intent: INTENT,
    proposed_authority: PROPOSED_AUTHORITY,
    authority_set: AUTHORITY_SET,
    authority_hash: authorityHash,
    intent_hash: intentHash,
    proposal_hash: proposalHash,
    subject: ALICE,
    approval_basis: {
      type: "direct",
      consent_principal: ALICE,
      activation: { approval_event_id: "ape_8K2nP4qV9rL3tY6sB1z" },
      activation_actor: ALICE,
      adjudication: { kind: "human" },
      root_commitment: authorityHash,
    },
    authority_source: { type: "user_delegated" },
    client_id: "s6BhdRkqt3",
    policy_version: "deploy-policy:v17",
    approval_event_id: "ape_8K2nP4qV9rL3tY6sB1z",
    created_at: timeline[0].at,
    expires_at: EXPIRES_AT,
  };

  return {
    format: "mission-baseline-fixture/1",
    scenario: "baseline-q3",
    refs: ["#1176 item 5", "D510"],
    mission: { issuer: ISSUER, id: MISSION_ID },
    cast: {
      client_id: "s6BhdRkqt3",
      subject: ALICE,
      approver: ALICE,
      identity_provider: "https://idp.example.com",
      resource: "https://erp.example.com",
    },
    expiry: { requested: EXPIRES_AT, effective: EXPIRES_AT, numeric_date: numericDate(EXPIRES_AT) },
    anchors: {
      intent_hash: intentHash,
      proposal_hash: proposalHash,
      authority_hash: authorityHash,
      root_commitment: authorityHash,
    },
    record,
    timeline,
    first_token: firstToken,
    access_token_lifetime: ACCESS_TOKEN_LIFETIME,
    tokens,
    revocation: REVOCATION,
    variants: VARIANTS.map((v) => ({
      name: v.name,
      label: v.id ? null : `baseline-q3/variant/${v.name}`,
      mission: { issuer: v.issuer ?? ISSUER, id: v.id ?? variantId(v.name) },
      differs_by: v.differs_by,
      drafts: v.drafts,
    })),
  };
}

// The README's variants table, between its markers, is generated too.
const README = path.join(path.dirname(OUT), "README.md");
const BEGIN = "<!-- variants:begin -->";
const END = "<!-- variants:end -->";

function readmeWith(fixture, have) {
  const rows = fixture.variants.map(
    (v) => `| \`${v.name}\` | \`${v.mission.issuer}\` | \`${v.mission.id}\` | ${v.differs_by} | ${v.drafts.join(", ")} |`,
  );
  const table = ["| Name | Issuer | ID | Differs from the baseline by | Used in |", "|---|---|---|---|---|", ...rows].join("\n");
  const i = have.indexOf(BEGIN);
  const j = have.indexOf(END);
  if (i < 0 || j < i) throw new Error(`${path.relative(ROOT, README)} lacks the variants markers`);
  return `${have.slice(0, i + BEGIN.length)}\n${table}\n${have.slice(j)}`;
}

function main() {
  const fixture = build();
  const text = `${JSON.stringify(fixture, null, 2)}\n`;
  const readmeHave = fs.readFileSync(README, "utf8");
  const readme = readmeWith(fixture, readmeHave);
  if (process.argv.includes("--check")) {
    const have = fs.existsSync(OUT) ? fs.readFileSync(OUT, "utf8") : "";
    const stale = [have !== text && OUT, readmeHave !== readme && README].filter(Boolean);
    if (stale.length > 0) {
      console.error(
        `baseline-fixture check FAILED: ${stale.map((f) => path.relative(ROOT, f)).join(" and ")} not what the generator builds; run it without --check.`,
      );
      process.exit(1);
    }
    console.log(`baseline-fixture check OK: the fixture and its ${fixture.variants.length} variants are current, and the core's test vectors reproduce.`);
    return;
  }
  fs.writeFileSync(OUT, text);
  fs.writeFileSync(README, readme);
  console.log(`wrote ${path.relative(ROOT, OUT)} and ${path.relative(ROOT, README)}`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
