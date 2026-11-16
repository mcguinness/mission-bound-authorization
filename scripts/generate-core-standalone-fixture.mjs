#!/usr/bin/env node
// The core-standalone example fixture (#2009, P4 of the OAuth binding
// independence plan). Builds vectors/core-standalone/core-standalone.json:
// one Mission whose only authority is RFC 9396's `payment_initiation`
// example (Section 2, Figure 2), carried unchanged from the client's
// proposal into the Authority Set, with the exact Intent, issuer, Mission
// Record member presence, commitment envelopes, their JCS bytes and the
// expected digests.
//
// `payment_initiation` is an illustrative API type here, not a Mission type
// or a standardized payment API. RFC 9396's payment fields define no subset
// relation, so the Mission holds one approved entry, unchanged.
//
// Anchors use the OAuth binding's integrity-anchor construction
// (draft-mcguinness-oauth-mission, Section "Integrity Anchors"): JCS
// (RFC 8785) over {typ, iss, value}, SHA-256, `sha-256:` plus unpadded
// base64url. Before building, the script reproduces every vector in the
// binding's "Integrity Anchor Test Vectors" appendix, read from the draft
// itself: the displayed value, the canonical bytes and the digest. Any
// difference stops the script before it builds or writes anything.
//
// The Mission identifier is `msn_` plus the first 32 base64url characters
// of SHA-256 over the fixed label `core-standalone/mission`.
//
// Usage: node scripts/generate-core-standalone-fixture.mjs [--check]
//   --check  fail if the fixture or its README's generated table differs
//            from what this script builds.

import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { anchor, canonicalize } from "./generate-baseline-fixture.mjs";

const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const DIR = path.join(ROOT, "vectors", "core-standalone");
const OUT = path.join(DIR, "core-standalone.json");
const README = path.join(DIR, "README.md");
const BINDING = path.join(ROOT, "draft-mcguinness-oauth-mission.md");

const b64u = (buf) => buf.toString("base64url");
const sha256 = (s) => createHash("sha256").update(s, "utf8").digest();

const fail = (msg) => {
  throw new Error(`core-standalone fixture: ${msg}`);
};

// The anchor names the appendix prints, and the `typ` each one commits.
const ANCHOR_TYP = {
  intent_hash: "mission-intent",
  authority_hash: "mission-authority-set",
  proposal_hash: "mission-proposed-authority",
  entry_digest: "mission-authority-entry",
};

// Reads the binding's "Integrity Anchor Test Vectors" appendix: each vector
// is a ```json value block, then a canonical-bytes block (wrapped for layout;
// removing the line breaks recovers it), then a `<name> = sha-256:...` block.
export function bindingVectors(text) {
  const start = text.indexOf("\n# Integrity Anchor Test Vectors {#test-vectors}\n");
  if (start < 0) fail("the binding has no Integrity Anchor Test Vectors appendix");
  const end = text.indexOf("\n# ", start + 1);
  const appendix = text.slice(start, end < 0 ? undefined : end);
  const blocks = [...appendix.matchAll(/^~~~ ?(\w*)\n([\s\S]*?)\n~~~$/gm)].map((m) => ({ lang: m[1], body: m[2] }));
  const vectors = [];
  for (let i = 0; i < blocks.length; i++) {
    if (blocks[i].lang !== "json") continue;
    const [value, bytes, result] = blocks.slice(i, i + 3);
    if (bytes?.lang !== "text" || result?.lang !== "text") fail(`appendix vector ${vectors.length + 1} is not json, text, text`);
    const m = /^(\w+) = (sha-256:[A-Za-z0-9_-]{43})$/.exec(result.body.trim());
    if (!m) fail(`appendix vector ${vectors.length + 1} has no "<name> = sha-256:..." line`);
    vectors.push({ value: JSON.parse(value.body), canonical: bytes.body.replace(/\n/g, ""), name: m[1], digest: m[2] });
    i += 2;
  }
  return vectors;
}

// The construction must reproduce every vector the binding carries, byte for
// byte, before it computes anything else. Returns the vectors' anchor names.
export function selfTest(text = fs.readFileSync(BINDING, "utf8")) {
  const vectors = bindingVectors(text);
  const seen = new Set();
  for (const [n, v] of vectors.entries()) {
    const label = `appendix vector ${n + 1} (${v.name})`;
    const envelope = JSON.parse(v.canonical);
    const keys = Object.keys(envelope).sort().join(",");
    if (keys !== "iss,typ,value") fail(`${label}: the canonical envelope's members are ${keys}`);
    if (ANCHOR_TYP[v.name] !== envelope.typ) fail(`${label}: ${v.name} names typ ${ANCHOR_TYP[v.name]}, the bytes carry ${envelope.typ}`);
    if (canonicalize(envelope.value) !== canonicalize(v.value)) fail(`${label}: the displayed value is not the canonical envelope's value`);
    const bytes = canonicalize({ typ: envelope.typ, iss: envelope.iss, value: v.value });
    if (bytes !== v.canonical) fail(`${label}: canonical bytes differ:\n  built ${bytes}\n  shown ${v.canonical}`);
    const digest = anchor(envelope.typ, envelope.iss, v.value);
    if (digest !== v.digest) fail(`${label}: ${digest} != ${v.digest}`);
    seen.add(envelope.typ);
  }
  // A floor, so a reformatted appendix that parses to nothing fails loudly.
  for (const typ of Object.values(ANCHOR_TYP)) {
    if (!seen.has(typ)) fail(`the appendix yielded no ${typ} vector (found ${vectors.length} vectors)`);
  }
  if (vectors.length < 6) fail(`the appendix yielded ${vectors.length} vectors, expected at least 6`);
  return vectors.map((v) => v.name);
}

const RFC3339_UTC = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/;
const instant = (s) => {
  const ms = Date.parse(s);
  if (!RFC3339_UTC.test(s) || !Number.isFinite(ms)) fail(`not an RFC 3339 UTC instant: ${s}`);
  return ms;
};

const ISSUER = "https://as.example.com";
const MISSION_LABEL = "core-standalone/mission";
const MISSION_ID = `msn_${b64u(sha256(MISSION_LABEL)).slice(0, 32)}`;
const SUBJECT = { iss: "https://idp.example.com", sub: "user_5Tn8qW2xK7mR4vBc" };
const CLIENT_ID = "pq7Lm2Xz9K";
const APPROVAL_EVENT_ID = "ape_3Hq8Lm2Vx7Rz9Tc4";
const PAYMENTS = "https://example.com/payments";
const CREATED_AT = "2026-11-02T12:00:00Z";
const EXPIRES_AT = "2026-11-02T13:00:00Z";

// RFC 9396, Section 2, Figure 2: the one entry, member for member and in the
// figure's order. The README quotes the figure; the check compares the two.
const ENTRY = {
  type: "payment_initiation",
  actions: ["initiate", "status", "cancel"],
  locations: [PAYMENTS],
  instructedAmount: { currency: "EUR", amount: "123.50" },
  creditorName: "Merchant A",
  creditorAccount: { iban: "DE02100100109307118603" },
  remittanceInformationUnstructured: "Ref Number Merchant",
};

// The smallest Intent: the three required members.
const INTENT = {
  goal: "Initiate a credit transfer of EUR 123.50 to Merchant A with reference Ref Number Merchant, and check or cancel it.",
  target_resources: [PAYMENTS],
  expires_at: EXPIRES_AT,
};

// The client proposes the entry on `authorization_details`; with no
// `narrowing` capability and no subset relation for the type, derivation
// carries it through unchanged.
const PROPOSED_AUTHORITY = [ENTRY];
const AUTHORITY_SET = [ENTRY];

function build() {
  const reproduced = selfTest();

  const commitments = [
    ["intent_hash", "record.intent", INTENT],
    ["proposal_hash", "record.proposed_authority", PROPOSED_AUTHORITY],
    ["authority_hash", "record.authority_set", AUTHORITY_SET],
  ].map(([name, source, value]) => {
    const typ = ANCHOR_TYP[name];
    const envelope = { typ, iss: ISSUER, value };
    return { anchor: name, typ, iss: ISSUER, value_source: source, envelope, jcs: canonicalize(envelope), digest: anchor(typ, ISSUER, value) };
  });
  const anchors = Object.fromEntries(commitments.map((c) => [c.anchor, c.digest]));

  // Invariants the example relies on.
  if (canonicalize(PROPOSED_AUTHORITY) !== canonicalize(AUTHORITY_SET)) fail("the entry is not carried unchanged");
  if (anchors.proposal_hash === anchors.authority_hash) fail("proposal_hash and authority_hash coincide: typ no longer separates them");
  if (!(instant(CREATED_AT) < instant(EXPIRES_AT) && instant(EXPIRES_AT) <= instant(INTENT.expires_at))) {
    fail("created_at < expires_at <= intent.expires_at does not hold");
  }
  if (!/^[A-Za-z0-9_-]{22,}$/.test(MISSION_ID)) fail(`bad Mission identifier ${MISSION_ID}`);
  for (const e of AUTHORITY_SET) {
    // The binding's target_resources membership rule binds an entry's
    // `resource` member; this type carries `locations` instead. By local
    // assumption every location is a target resource.
    if ("resource" in e) fail("the example entry carries a resource member");
    if (!e.locations.every((l) => INTENT.target_resources.includes(l))) fail("a location is not among target_resources");
  }

  const record = {
    id: MISSION_ID,
    issuer: ISSUER,
    state: "active",
    intent: INTENT,
    proposed_authority: PROPOSED_AUTHORITY,
    authority_set: AUTHORITY_SET,
    authority_hash: anchors.authority_hash,
    intent_hash: anchors.intent_hash,
    proposal_hash: anchors.proposal_hash,
    subject: SUBJECT,
    approval_basis: { type: "direct", consent_principal: SUBJECT },
    authority_source: { type: "user_delegated" },
    client_id: CLIENT_ID,
    approval_event_id: APPROVAL_EVENT_ID,
    created_at: CREATED_AT,
    expires_at: EXPIRES_AT,
  };

  const fixture = {
    format: "mission-core-standalone-fixture/1",
    scenario: "core-standalone",
    refs: ["#2009", "notes/audits/2026-10-31-core-independence/PLAN.md, P4"],
    reproduces_binding_vectors: reproduced,
    example_type: {
      type: ENTRY.type,
      source: "RFC 9396, Section 2, Figure 2",
      status: "illustrative API type; not a Mission type or a standardized payment API",
      transformation: "none: RFC 9396's payment fields define no subset relation, so the one proposed entry is approved unchanged",
    },
    mission: { issuer: ISSUER, id: MISSION_ID, id_label: MISSION_LABEL },
    cast: {
      client_id: CLIENT_ID,
      subject: SUBJECT,
      approver: SUBJECT,
      identity_provider: SUBJECT.iss,
      resource: PAYMENTS,
    },
    submission: {
      mission_intent: { intent: INTENT },
      authorization_details: PROPOSED_AUTHORITY,
    },
    anchors,
    commitments,
    record,
    member_presence: {
      present: Object.keys(record),
      implied: {
        "approval_basis.activation": { approval_event_id: APPROVAL_EVENT_ID },
        "approval_basis.activation_actor": SUBJECT,
        "approval_basis.root_commitment": anchors.authority_hash,
      },
      absent: {
        termination: "state is active",
        submission_evidence: "the submission carried no evidence",
        policy_version: "OPTIONAL; no feature this example uses depends on versioned derivation-policy identification",
        "approval_basis.adjudication": "OPTIONAL; the direct type fixes the mechanism",
        "approval_basis.approved_at": "absent for direct",
      },
    },
  };
  if (JSON.stringify(fixture).includes("mission_resource_access")) fail("the fixture names mission_resource_access");
  return fixture;
}

// The README quotes RFC 9396's Figure 2 between these markers; the check
// requires it to be the fixture's proposal.
const FIGURE_BEGIN = "<!-- rfc9396-figure-2:begin -->";
const FIGURE_END = "<!-- rfc9396-figure-2:end -->";
// The README's anchors table, between these markers, is generated.
const BEGIN = "<!-- anchors:begin -->";
const END = "<!-- anchors:end -->";

function between(have, begin, end) {
  const i = have.indexOf(begin);
  const j = have.indexOf(end);
  if (i < 0 || j < i) fail(`${path.relative(ROOT, README)} lacks the ${begin} markers`);
  return [i + begin.length, j];
}

function readmeWith(fixture, have) {
  const [fi, fj] = between(have, FIGURE_BEGIN, FIGURE_END);
  const quoted = /```json\n([\s\S]*?)\n```/.exec(have.slice(fi, fj));
  if (!quoted) fail("the README's Figure 2 quote is not a json block");
  if (canonicalize(JSON.parse(quoted[1])) !== canonicalize(fixture.submission.authorization_details)) {
    fail("the README's quote of RFC 9396 Figure 2 is not the fixture's proposal");
  }
  const rows = fixture.commitments.map((c) => `| \`${c.anchor}\` | \`${c.typ}\` | \`${c.value_source}\` | \`${c.digest}\` |`);
  const table = ["| Anchor | `typ` | Committed value | Expected digest |", "|---|---|---|---|", ...rows].join("\n");
  const [i, j] = between(have, BEGIN, END);
  return `${have.slice(0, i)}\n${table}\n${have.slice(j)}`;
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
        `core-standalone fixture check FAILED: ${stale.map((f) => path.relative(ROOT, f)).join(" and ")} not what the generator builds; run it without --check.`,
      );
      process.exit(1);
    }
    console.log(
      `core-standalone fixture check OK: the fixture is current, and the binding's ${fixture.reproduces_binding_vectors.length} test vectors reproduce.`,
    );
    return;
  }
  fs.writeFileSync(OUT, text);
  fs.writeFileSync(README, readme);
  console.log(`wrote ${path.relative(ROOT, OUT)} and ${path.relative(ROOT, README)}`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch (e) {
    console.error(e.message);
    process.exit(1);
  }
}
