#!/usr/bin/env node
// The OAuth binding's displayed payment examples (#2009 P4, plan step 7).
// Every JSON example of the binding's illustrative payment Mission must
// agree with vectors/core-standalone/core-standalone.json, so a changed
// example field fails here. Scope: the converted examples only, the blocks
// that name the payment type, the payment Mission or its goal. The
// Delegated Token Example's Resource Access Mission and the Integrity
// Anchor Test Vectors are out of scope.
//
// - an Intent equals the fixture's; an envelope's `intent` does too;
// - an `authorization_details` array equals the fixture's Authority Set
//   (the proposal is the same array);
// - a Mission Record equals the fixture's record;
// - a token response, decoded token or introspection response agrees on
//   every member the fixture determines, and a displayed access token is
//   truncated (it ends in `...`);
// - each anchor the prose displays beside its name is the fixture's.
//
// The fixture holds no times, token identifiers or keys, so those members
// are not checked. Each kind must appear at least as often as it does in
// the converted text, so removing an example fails too.
//
// Usage: node scripts/check-core-standalone-display.mjs [draft.md]

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { isDeepStrictEqual } from "node:util";

const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const FIXTURE = path.join(ROOT, "vectors", "core-standalone", "core-standalone.json");
const NOTE = "=============== NOTE: '\\' line wrapping per RFC 8792 ===============";

// Minimum count of each kind of displayed example.
const MINIMUM = {
  intent: 1,
  envelope: 2,
  authority: 5,
  record: 1,
  "token response": 2,
  "decoded token": 2,
  introspection: 2,
  "prose anchor": 3,
};

// RFC 8792 single-backslash unfolding: drop the header and its blank line,
// then join each line ending in "\" with the next, minus its leading
// whitespace.
export function unfold(text) {
  if (!text.startsWith(NOTE)) return text;
  const lines = text.slice(NOTE.length).replace(/^\n\n/, "").split("\n");
  const out = [];
  let carry = null;
  for (const line of lines) {
    const piece = carry === null ? line : carry + line.replace(/^\s+/, "");
    if (piece.endsWith("\\")) carry = piece.slice(0, -1);
    else {
      out.push(piece);
      carry = null;
    }
  }
  if (carry !== null) out.push(carry);
  return out.join("\n");
}

export function jsonBlocks(src) {
  const re = /^~~~ json\n([\s\S]*?)^~~~$/gm;
  const found = [];
  for (let m; (m = re.exec(src)); ) {
    found.push({ line: src.slice(0, m.index).split("\n").length, text: m[1] });
  }
  return found;
}

export function check(src, fx) {
  const intent = fx.submission.mission_intent.intent;
  const authority = fx.record.authority_set;
  const mission = { id: fx.mission.id, issuer: fx.mission.issuer };
  const markers = ["payment_initiation", fx.mission.id, intent.goal];
  const problems = [];
  const counts = Object.fromEntries(Object.keys(MINIMUM).map((k) => [k, 0]));
  const want = (ok, line, what) => {
    if (!ok) problems.push(`line ${line}: ${what}`);
  };
  for (const b of jsonBlocks(src)) {
    const text = unfold(b.text);
    if (!markers.some((m) => text.includes(m))) continue;
    let o;
    try {
      o = JSON.parse(text);
    } catch (e) {
      problems.push(`line ${b.line}: payment example is not JSON (${e.message})`);
      continue;
    }
    const at = b.line;
    if (Array.isArray(o)) {
      counts.authority++;
      want(isDeepStrictEqual(o, authority), at, "authorization_details array differs from the fixture's Authority Set");
    } else if ("access_token" in o) {
      counts["token response"]++;
      want(o.mission_id === mission.id, at, "token response mission_id");
      want(o.mission_expires_at === fx.record.expires_at, at, "token response mission_expires_at");
      want(isDeepStrictEqual(o.authorization_details, authority), at, "token response authorization_details");
      want(typeof o.access_token === "string" && o.access_token.endsWith("..."), at, "access token not marked truncated");
    } else if ("active" in o) {
      counts.introspection++;
      want(isDeepStrictEqual({ id: o.mission?.id, issuer: o.mission?.issuer }, mission), at, "introspection mission reference");
      for (const a of ["authority_hash", "proposal_hash", "intent_hash"]) {
        if (o.mission && a in o.mission) want(o.mission[a] === fx.anchors[a], at, `introspection ${a}`);
      }
      if (o.active === true) {
        want(o.iss === mission.issuer, at, "introspection iss");
        want(o.sub === fx.record.subject.sub, at, "introspection sub");
        want(o.client_id === fx.record.client_id, at, "introspection client_id");
        want(o.aud === fx.cast.resource, at, "introspection aud");
        want(isDeepStrictEqual(o.authorization_details, authority), at, "introspection authorization_details");
      }
    } else if ("authority_set" in o) {
      counts.record++;
      want(isDeepStrictEqual(o, fx.record), at, "Mission Record differs from the fixture's record");
    } else if ("mission" in o && "aud" in o) {
      counts["decoded token"]++;
      want(o.iss === mission.issuer, at, "token iss");
      want(o.sub === fx.record.subject.sub, at, "token sub");
      want(o.aud === fx.cast.resource, at, "token aud");
      want(o.client_id === fx.record.client_id, at, "token client_id");
      want(isDeepStrictEqual(o.authorization_details, authority), at, "token authorization_details");
      want(isDeepStrictEqual(o.mission, mission), at, "token mission claim");
    } else if ("intent" in o) {
      counts.envelope++;
      want(isDeepStrictEqual(o.intent, intent), at, "envelope intent differs from the fixture's Intent");
    } else if ("goal" in o) {
      counts.intent++;
      want(isDeepStrictEqual(o, intent), at, "Mission Intent differs from the fixture's");
    } else {
      problems.push(`line ${at}: payment example of no known kind`);
    }
  }
  // Anchors displayed in prose beside their names, as the end-to-end example does.
  const flat = src.replace(/\s+/g, " ");
  const prose = /`(authority_hash|intent_hash|proposal_hash)`,? `(sha-256:[A-Za-z0-9_-]+)`/g;
  for (let m; (m = prose.exec(flat)); ) {
    counts["prose anchor"]++;
    if (m[2] !== fx.anchors[m[1]]) problems.push(`prose ${m[1]} ${m[2]} is not the fixture's ${fx.anchors[m[1]]}`);
  }
  for (const [kind, n] of Object.entries(MINIMUM)) {
    if (counts[kind] < n) problems.push(`${kind}: ${counts[kind]} shown, at least ${n} expected`);
  }
  return { problems, counts };
}

function main() {
  const draft = process.argv[2] ?? path.join(ROOT, "draft-mcguinness-oauth-mission.md");
  const { problems, counts } = check(fs.readFileSync(draft, "utf8"), JSON.parse(fs.readFileSync(FIXTURE, "utf8")));
  if (problems.length) {
    console.error(`core-standalone display check FAILED:\n  ${problems.join("\n  ")}`);
    process.exit(1);
  }
  const shown = Object.entries(counts).map(([k, n]) => `${n} ${k}`).join(", ");
  console.log(`core-standalone display check OK: the binding's payment examples agree with the fixture (${shown}).`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
