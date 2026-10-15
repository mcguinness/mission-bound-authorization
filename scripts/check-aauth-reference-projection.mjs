#!/usr/bin/env node
// Acceptance fixtures for the AAuth binding's Mission Reference projection
// (#1169, D368).
//
// draft-mcguinness-mission-aauth's Native Reference defines how a consumer
// that represents an AAuth Mission Reference with `issuer` and `id` projects
// it from validated native context: `issuer` is the approving PS's server
// identifier and `id` is the unchanged `s256`. `project` restates that
// table. The fixtures are the acceptance cases D368 lists, and the draft's
// own carrier table and four-party example are checked against `project`,
// so the text and the fixtures cannot drift apart.
//
// These are acceptance fixtures for the mapping, not a Runtime or AuthZEN
// integration witness: the ledger's aauth.reference.* rows stay `todo` until
// a composed adapter has its own discriminating tests.
//
// Usage: node scripts/check-aauth-reference-projection.mjs [path-to-draft]
// Chained from scripts/check-family-manifest.mjs.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const DRAFT = "draft-mcguinness-mission-aauth.md";

// An unpadded base64url SHA-256 digest, as AAuth's `s256`.
const S256 = /^[A-Za-z0-9_-]{43}$/;
// AAuth server identifier (-11 Section 11.1.1): the https scheme and a
// lowercase host only; no port, path, query, fragment or trailing slash.
const SERVER_ID = /^https:\/\/[a-z0-9-]+(\.[a-z0-9-]+)*$/;

export function isServerIdentifier(v) {
  return typeof v === "string" && SERVER_ID.test(v);
}

// The projection the binding defines. `carrier` is native context the
// consumer has already validated: { kind, verified, claims } for a token, or
// { kind: "ps_context", verified, ps_issuer, s256 } for an approval envelope
// or an authenticated mission-scoped PS request. Returns { issuer, id }, or
// null when no Mission Reference is established.
export function project(carrier) {
  if (!carrier || carrier.verified !== true) return null;
  let issuer;
  let id;
  switch (carrier.kind) {
    case "person_token":
      issuer = carrier.claims?.iss;
      id = carrier.claims?.mission_s256;
      break;
    case "resource_token":
    case "auth_token":
      // Always `ps`; an auth token's `iss` names the Access Server in
      // four-party access and is never a fallback.
      issuer = carrier.claims?.ps;
      id = carrier.claims?.mission_s256;
      break;
    case "ps_context":
      issuer = carrier.ps_issuer;
      id = carrier.s256;
      break;
    default:
      return null;
  }
  if (!isServerIdentifier(issuer) || typeof id !== "string" || !S256.test(id)) return null;
  return { issuer, id };
}

export function sameMission(a, b) {
  return a !== null && b !== null && a.issuer === b.issuer && a.id === b.id;
}

const PS = "https://ps.example";
const PS2 = "https://ps2.example";
const AS = "https://as.example";
const RS = "https://flights.example";
const M = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const U = "Q2h1Y2sgSW50ZWdyaXR5IENoZWNrIGRpZ2VzdCB2YWx1";

const token = (kind, claims, verified = true) => ({ kind, verified, claims });

// D368's acceptance cases. Each returns an error string, or null.
export const FIXTURES = [
  ["person token: issuer is its iss", (p) =>
    sameMission(p(token("person_token", { iss: PS, mission_s256: M })), { issuer: PS, id: M }) ? null : "expected { PS, s256 }"],
  ["resource token: issuer is its ps, never the resource's iss", (p) =>
    sameMission(p(token("resource_token", { iss: RS, ps: PS, mission_s256: M })), { issuer: PS, id: M }) ? null : "expected { PS, s256 }"],
  ["three-party auth token: issuer is its ps", (p) =>
    sameMission(p(token("auth_token", { iss: PS, ps: PS, mission_s256: M })), { issuer: PS, id: M }) ? null : "expected { PS, s256 }"],
  ["four-party auth token: issuer is its ps, not the Access Server", (p) =>
    sameMission(p(token("auth_token", { iss: AS, ps: PS, mission_s256: M })), { issuer: PS, id: M }) ? null : "expected { PS, s256 }, not the Access Server"],
  ["approval envelope or authenticated PS request: the endpoint's PS identifier", (p) =>
    sameMission(p({ kind: "ps_context", verified: true, ps_issuer: PS, s256: M }), { issuer: PS, id: M }) ? null : "expected { PS, s256 }"],
  ["auth token without ps: no reference, no fallback to iss", (p) =>
    p(token("auth_token", { iss: AS, mission_s256: M })) === null ? null : "a reference was built without ps"],
  ["malformed ps (trailing slash): no reference", (p) =>
    p(token("auth_token", { iss: AS, ps: `${PS}/`, mission_s256: M })) === null ? null : "a malformed ps established a reference"],
  ["non-lowercase ps: no reference (exact comparison)", (p) =>
    p(token("auth_token", { iss: AS, ps: "https://PS.example", mission_s256: M })) === null ? null : "a non-identifier ps established a reference"],
  ["malformed s256 (prefixed or padded): no reference", (p) =>
    [`sha-256:${M}`, `${M}=`].every((bad) => p(token("person_token", { iss: PS, mission_s256: bad })) === null)
      ? null : "a malformed s256 established a reference"],
  ["unverified carrier (wrong audience, key or context): no reference", (p) =>
    p(token("auth_token", { iss: AS, ps: PS, mission_s256: M }, false)) === null ? null : "an unverified carrier established a reference"],
  ["missionless token: no reference invented", (p) =>
    p(token("person_token", { iss: PS })) === null ? null : "a missionless token established a reference"],
  ["equal digests under different PS identifiers are two Missions", (p) => {
    const a = p(token("person_token", { iss: PS, mission_s256: M }));
    const b = p(token("person_token", { iss: PS2, mission_s256: M }));
    return a && b && !sameMission(a, b) ? null : "equal digests under two PS identifiers were treated as one Mission";
  }],
  ["accepted update preserves the pair", (p) => {
    // The update's own s256 (U) is verification material, never the id.
    const r = p({ kind: "ps_context", verified: true, ps_issuer: PS, s256: M, update_s256: U, update_position: 1 });
    return sameMission(r, { issuer: PS, id: M }) ? null : "an accepted update changed the pair";
  }],
  ["composed decision, evidence and receipt keep the pair; credential issuer stays distinct", (p) => {
    const t = token("auth_token", { iss: AS, ps: PS, mission_s256: M });
    const mission = p(t);
    if (!mission) return "no reference projected";
    // Decision request (AuthZEN context), Decision Evidence copied from the
    // request's Mission reference, and a Mission Receipt carrying
    // mission.id and mission.issuer.
    const request = { mission, credential: { issuer: t.claims.iss } };
    const evidence = { mission: { id: request.mission.id, issuer: request.mission.issuer } };
    const receipt = { mission: { id: evidence.mission.id, issuer: evidence.mission.issuer } };
    if (!sameMission(receipt.mission, { issuer: PS, id: M })) return "the receipt lost the established pair";
    return request.credential.issuer !== receipt.mission.issuer ? null : "the credential issuer collapsed into the Mission issuer";
  }],
];

// The draft's carrier table: the `issuer` source each token row names must be
// the one `project` uses.
const TABLE_ROWS = [
  ["Person token", "the token's `iss`", "person_token"],
  ["Resource token", "the token's `ps`", "resource_token"],
  ["Auth token, three-party or four-party", "the token's `ps`", "auth_token"],
];

export function validate(text, projector = project) {
  const errors = [];
  for (const [name, run] of FIXTURES) {
    const e = run(projector);
    if (e) errors.push(`fixture "${name}": ${e}`);
  }

  for (const [label, issuerCell] of TABLE_ROWS) {
    const row = text.split("\n").find((l) => l.startsWith(`| ${label} |`));
    if (!row) { errors.push(`carrier table has no "${label}" row`); continue; }
    const cells = row.split("|").map((c) => c.trim());
    if (cells[2] !== issuerCell) errors.push(`carrier table "${label}" names ${cells[2]} as issuer; the projection uses ${issuerCell}`);
    if (cells[3] !== "the token's `mission_s256`") errors.push(`carrier table "${label}" names ${cells[3]} as id`);
  }

  const prose = text.match(/a validated four-party auth token with `iss`\s+`([^`]+)`,\s+`ps`\s+`([^`]+)`,\s+and\s+`mission_s256`\s+`([^`]+)`\s+projects as follows/);
  if (!prose) {
    errors.push("no four-party projection example found");
  } else {
    const [, iss, ps, s256] = prose;
    const after = text.slice(prose.index);
    const block = after.match(/~~~ json\n([\s\S]*?)\n~~~/);
    let ex = null;
    try { ex = block && JSON.parse(block[1]); } catch { ex = null; }
    if (!ex) {
      errors.push("the four-party example is missing or not valid JSON");
    } else {
      if (iss === ps) errors.push("the example's auth token is PS-issued, so it cannot show the issuer distinction");
      const want = projector(token("auth_token", { iss, ps, mission_s256: s256 }));
      if (!sameMission(ex.mission, want)) errors.push(`the example's mission ${JSON.stringify(ex.mission)} is not the projection ${JSON.stringify(want)}`);
      if (ex.credential?.issuer !== iss) errors.push("the example's credential issuer is not the token's iss");
      if (ex.mission?.issuer === ex.credential?.issuer) errors.push("the example's Mission issuer equals its credential issuer");
    }
  }
  return { errors, fixtures: FIXTURES.length };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const file = process.argv[2] || path.join(ROOT, DRAFT);
  const { errors, fixtures } = validate(fs.readFileSync(file, "utf8"));
  if (errors.length) {
    console.error(`aauth-reference-projection check FAILED with ${errors.length} finding(s):`);
    for (const e of errors) console.error(`  - ${e}`);
    process.exit(1);
  }
  console.log(`aauth-reference-projection check OK: ${fixtures} fixtures, the carrier table and the four-party example validated.`);
}
