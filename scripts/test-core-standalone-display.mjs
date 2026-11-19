#!/usr/bin/env node
// Regression tests for check-core-standalone-display.mjs (#2009 P4): the
// binding as committed passes, and each one-field change to a displayed
// payment example, or the removal of one, fails at that example.
//
// Usage: node scripts/test-core-standalone-display.mjs

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { check, unfold } from "./check-core-standalone-display.mjs";

const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const SRC = fs.readFileSync(path.join(ROOT, "draft-mcguinness-oauth-mission.md"), "utf8");
const FX = JSON.parse(fs.readFileSync(path.join(ROOT, "vectors", "core-standalone", "core-standalone.json"), "utf8"));

function mutate(from, to) {
  assert.equal(SRC.split(from).length, 2, `expected one occurrence of ${JSON.stringify(from)}`);
  return SRC.replace(from, to);
}

test("the committed binding passes", () => {
  assert.deepEqual(check(SRC, FX).problems, []);
});

test("RFC 8792 unfolding joins a continued line without its leading whitespace", () => {
  const note = "=============== NOTE: '\\' line wrapping per RFC 8792 ===============";
  assert.equal(unfold(`${note}\n\n{"a": "x \\\n    y"}`), '{"a": "x y"}');
});

const cases = [
  ["a changed amount in the Authority Set Example",
    'retained unchanged\n({{proposal-derivation}}). The type defines no delegation policy, so\nthe entry is non-delegable ({{delegation-constraints}}):\n\n~~~ json\n[\n  { "type": "payment_initiation",\n    "actions": ["initiate", "status", "cancel"],\n    "locations": ["https://example.com/payments"],\n    "instructedAmount": { "currency": "EUR", "amount": "123.50" },',
    /authorization_details array differs/],
  ["a changed anchor in the Mission Record Example",
    '"authority_hash":\n    "sha-256:G5P5feAebBxFgyxOHNoSZwB4DfCqufYXQXEZFTxvgQY"',
    /Mission Record differs/],
  ["a changed anchor in the end-to-end prose",
    "`sha-256:Vo-xrC5HtrAUS9ZAPSWhhpLd7fr43eQsbH6AMiooa5Y`, and",
    /prose intent_hash/],
  ["an access token not marked truncated",
    '"access_token": "eyJhbGciOiJFUzI1NiIsInR5cCI6ImF0K2p3dCJ9...",\n  "token_type": "DPoP",\n  "expires_in": 300,\n  "refresh_token"',
    /not marked truncated/],
  ["a changed client_id in the Mission Claim example",
    'decoded Mission-bound token payload:\n\n~~~ json\n{\n  "iss": "https://as.example.com",\n  "sub": "user_5Tn8qW2xK7mR4vBc",\n  "aud": "https://example.com/payments",\n  "client_id": "pq7Lm2Xz9K",',
    /token client_id/],
];
const swaps = [
  (s) => s.replace('"amount": "123.50" },', '"amount": "123.51" },'),
  (s) => s.replace("QY\"", "QZ\""),
  (s) => s.replace("a5Y`", "a5Z`"),
  (s) => s.replace('J9...",', 'J9",'),
  (s) => s.replace('"pq7Lm2Xz9K"', '"pq7Lm2Xz9X"'),
];

cases.forEach(([name, from, expected], i) => {
  test(`fails on ${name}`, () => {
    const { problems } = check(mutate(from, swaps[i](from)), FX);
    assert.ok(problems.some((p) => expected.test(p)), problems.join("\n"));
  });
});

test("fails when an introspection example is removed", () => {
  const start = SRC.indexOf("The following is an example of the response for the same token, still");
  const end = SRC.indexOf("# Mission Lifecycle {#lifecycle}");
  assert.ok(start > 0 && end > start);
  const { problems } = check(SRC.slice(0, start) + SRC.slice(end), FX);
  assert.ok(problems.some((p) => /introspection: 1 shown/.test(p)), problems.join("\n"));
});
