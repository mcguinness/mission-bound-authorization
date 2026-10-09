#!/usr/bin/env node
// Fixture tests for scripts/check-aauth-management-examples.mjs (#838 review).
// Dependency-free (node:assert and node:test). Each negative case mutates a
// copy of the real draft's text in memory and asserts the specific finding,
// so a rule the checker silently stops enforcing fails here; the positive
// case asserts the draft as committed passes.
//
// Usage: node scripts/test-check-aauth-management-examples.mjs

import fs from "node:fs";
import path from "node:path";
import assert from "node:assert/strict";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

import { validate, instant } from "./check-aauth-management-examples.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const DRAFT = fs.readFileSync(path.join(ROOT, "draft-mcguinness-mission-aauth-management.md"), "utf8");

// Replace exactly one occurrence, so a fixture can never silently stop
// mutating the draft after an edit.
function mutate(text, from, to) {
  const n = text.split(from).length - 1;
  assert.equal(n, 1, `fixture anchor must occur exactly once: ${JSON.stringify(from)}`);
  return text.replace(from, to);
}

function findings(text) {
  return validate(text).errors;
}

function assertFinding(text, pattern) {
  const errors = findings(text);
  assert.ok(errors.some((e) => pattern.test(e)), `expected a finding matching ${pattern}; got:\n  ${errors.join("\n  ") || "(none)"}`);
}

test("the committed draft passes with every example kind present", () => {
  const { errors, seen } = validate(DRAFT);
  assert.deepEqual(errors, []);
  for (const k of ["status-request", "status-response", "terminate-request", "terminate-response", "tree-request", "tree-response", "metadata", "fragment"]) {
    assert.ok(seen.includes(k), `missing example kind ${k}`);
  }
});

test("a delegation response with complete false and no next_cursor fails", () => {
  const t = mutate(DRAFT, '  ],\n  "complete": true\n}', '  ],\n  "complete": false\n}');
  assertFinding(t, /complete is false but next_cursor is absent/);
});

test("a delegation response with next_cursor and complete true fails", () => {
  const t = mutate(DRAFT, '  ],\n  "complete": true\n}', '  ],\n  "next_cursor": "c2",\n  "complete": true\n}');
  assertFinding(t, /next_cursor present but complete is not false/);
});

test("metadata advertising only delegation_tree fails for status and terminate", () => {
  const t = mutate(DRAFT, '    "status", "terminate", "delegation_tree"\n', '    "delegation_tree"\n');
  assertFinding(t, /MUST contain status/);
  assertFinding(t, /MUST contain terminate/);
});

test("a terminate request carrying mission_s256 in its body fails", () => {
  const t = mutate(DRAFT, '  "action": "terminate",\n', '  "action": "terminate",\n  "mission_s256": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",\n');
  assertFinding(t, /\[terminate-request\]: a request body MUST NOT carry mission_s256/);
});

test("a delegation_tree request carrying mission_s256 in its body fails", () => {
  const t = mutate(DRAFT, '  "action": "delegation_tree",\n', '  "action": "delegation_tree",\n  "mission_s256": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",\n');
  assertFinding(t, /\[tree-request\]: a request body MUST NOT carry mission_s256/);
});

test("fresh_until with an offset naming an earlier instant fails", () => {
  // 10:15:32+02:00 is 08:15:32Z, before observed_at 09:15:02Z.
  const t = mutate(DRAFT, '"fresh_until": "2026-04-10T09:15:32Z"', '"fresh_until": "2026-04-10T10:15:32+02:00"');
  assertFinding(t, /\[status-response\]: fresh_until precedes observed_at/);
});

test("fresh_until with an offset naming a later instant passes", () => {
  // 08:15:32-01:00 is 09:15:32Z, after observed_at 09:15:02Z; a string
  // comparison would wrongly reject it.
  const t = mutate(DRAFT, '"fresh_until": "2026-04-10T09:15:32Z"', '"fresh_until": "2026-04-10T08:15:32-01:00"');
  assert.deepEqual(findings(t), []);
});

test("a date-time that names no real calendar day fails", () => {
  const t = mutate(DRAFT, '"approved_at": "2026-04-07T14:30:00Z",\n  "expires_at": "2026-04-14T14:30:00Z",\n  "terminated_at": "2026-04-10T09:12:43Z",\n  "termination_reason": "revoked",\n  "observed_at": "2026-04-10T09:15:02Z"',
    '"approved_at": "2026-02-30T14:30:00Z",\n  "expires_at": "2026-04-14T14:30:00Z",\n  "terminated_at": "2026-04-10T09:12:43Z",\n  "termination_reason": "revoked",\n  "observed_at": "2026-04-10T09:15:02Z"');
  assertFinding(t, /approved_at is not an RFC 3339 date-time/);
});

test("the terminate response without approved_at fails", () => {
  const t = mutate(DRAFT, '  "approved_at": "2026-04-07T14:30:00Z",\n  "expires_at": "2026-04-14T14:30:00Z",\n  "terminated_at": "2026-04-10T09:12:43Z",\n  "termination_reason": "revoked",\n  "observed_at": "2026-04-10T09:12:44Z"',
    '  "expires_at": "2026-04-14T14:30:00Z",\n  "terminated_at": "2026-04-10T09:12:43Z",\n  "termination_reason": "revoked",\n  "observed_at": "2026-04-10T09:12:44Z"');
  assertFinding(t, /\[terminate-response\]: missing REQUIRED member approved_at/);
});

test("a terminated status without token_residual fails", () => {
  const t = mutate(DRAFT, '  "latest_update_s256": "DCPMK1mFVV7rRr2gXYhuIoHABzG8_FrKIuAKTUuqYQA",\n  "token_residual": {\n    "tracked": 4,\n    "revocation_attempted": 4,\n    "revocation_confirmed": 4,\n    "complete": true\n  }\n',
    '  "latest_update_s256": "DCPMK1mFVV7rRr2gXYhuIoHABzG8_FrKIuAKTUuqYQA"\n');
  assertFinding(t, /\[status-response\]: missing token_residual, REQUIRED when terminated/);
});

// The status example's accepted-update members (#965); anchored on its
// unique fresh_until so the terminate example is left untouched.
const STATUS_UPDATES = '  "fresh_until": "2026-04-10T09:15:32Z",\n  "accepted_updates": 2,\n  "latest_update_s256": "DCPMK1mFVV7rRr2gXYhuIoHABzG8_FrKIuAKTUuqYQA",\n';

test("accepted_updates above zero without latest_update_s256 fails", () => {
  const t = mutate(DRAFT, STATUS_UPDATES, '  "fresh_until": "2026-04-10T09:15:32Z",\n  "accepted_updates": 2,\n');
  assertFinding(t, /\[status-response\]: accepted_updates is greater than zero but latest_update_s256 is absent/);
});

test("latest_update_s256 with zero accepted_updates fails", () => {
  const t = mutate(DRAFT, STATUS_UPDATES, STATUS_UPDATES.replace('"accepted_updates": 2', '"accepted_updates": 0'));
  assertFinding(t, /\[status-response\]: latest_update_s256 present with zero accepted_updates/);
});

test("latest_update_s256 without accepted_updates fails", () => {
  const t = mutate(DRAFT, STATUS_UPDATES, STATUS_UPDATES.replace('  "accepted_updates": 2,\n', ""));
  assertFinding(t, /\[status-response\]: latest_update_s256 without accepted_updates/);
});

test("a negative accepted_updates fails", () => {
  const t = mutate(DRAFT, STATUS_UPDATES, STATUS_UPDATES.replace('"accepted_updates": 2', '"accepted_updates": -1'));
  assertFinding(t, /\[status-response\]: accepted_updates is not a non-negative integer/);
});

test("a malformed latest_update_s256 fails", () => {
  const t = mutate(DRAFT, STATUS_UPDATES, STATUS_UPDATES.replace("DCPMK1mFVV7rRr2gXYhuIoHABzG8_FrKIuAKTUuqYQA", "not-a-digest"));
  assertFinding(t, /\[status-response\]: latest_update_s256 is not an unpadded base64url SHA-256 digest/);
});

// The delegation-tree example's call_chain node (#966).
const CALL_CHAIN = '      "relationship": "call_chain",\n      "upstream_token": { "iss": "https://ps.example", "jti": "auth-31" },\n      "person_token": { "iss": "https://ps.example", "jti": "pt-57" }\n';

test("a sub_agent node without parent_agent fails", () => {
  const t = mutate(DRAFT, '      "relationship": "sub_agent",\n      "parent_agent": "aauth:planner.7f3c@vendor.example",\n', '      "relationship": "sub_agent",\n');
  assertFinding(t, /\[tree-response\]: node 1 is sub_agent without parent_agent/);
});

test("a call_chain node with parent_agent fails", () => {
  const t = mutate(DRAFT, CALL_CHAIN, '      "relationship": "call_chain",\n      "parent_agent": "aauth:planner.7f3c@vendor.example",\n      "upstream_token": { "iss": "https://ps.example", "jti": "auth-31" },\n      "person_token": { "iss": "https://ps.example", "jti": "pt-57" }\n');
  assertFinding(t, /\[tree-response\]: node 2 is call_chain with parent_agent/);
});

test("a call_chain node with only upstream_token fails", () => {
  const t = mutate(DRAFT, CALL_CHAIN, '      "relationship": "call_chain",\n      "upstream_token": { "iss": "https://ps.example", "jti": "auth-31" }\n');
  assertFinding(t, /\[tree-response\]: node 2 is call_chain with only upstream_token/);
});

test("a call_chain token reference without jti fails", () => {
  const t = mutate(DRAFT, CALL_CHAIN, CALL_CHAIN.replace('{ "iss": "https://ps.example", "jti": "pt-57" }', '{ "iss": "https://ps.example" }'));
  assertFinding(t, /\[tree-response\]: node 2 person_token is not an \{iss, jti\} object/);
});

test("a call_chain node with both token references omitted passes", () => {
  const t = mutate(DRAFT, CALL_CHAIN, '      "relationship": "call_chain"\n');
  assert.deepEqual(findings(t), []);
});

test("zero accepted_updates with no digest passes", () => {
  const t = mutate(DRAFT, STATUS_UPDATES, '  "fresh_until": "2026-04-10T09:15:32Z",\n  "accepted_updates": 0,\n');
  assert.deepEqual(findings(t), []);
});

test("removing the metadata example fails as a missing kind", () => {
  const start = DRAFT.indexOf('~~~ json\n{\n  "issuer"');
  const end = DRAFT.indexOf("~~~\n", start + 8) + 4;
  assert.ok(start > 0 && end > start);
  assertFinding(DRAFT.slice(0, start) + DRAFT.slice(end), /no metadata example found/);
});

test("instant() compares offsets and rejects impossible dates", () => {
  assert.equal(instant("2026-04-10T10:15:32+02:00"), instant("2026-04-10T08:15:32Z"));
  assert.ok(instant("2026-04-10T08:15:32-01:00") > instant("2026-04-10T09:15:02Z"));
  assert.ok(Number.isNaN(instant("2026-02-30T00:00:00Z")));
  assert.ok(Number.isNaN(instant("2026-04-10 09:15:02Z")));
});
