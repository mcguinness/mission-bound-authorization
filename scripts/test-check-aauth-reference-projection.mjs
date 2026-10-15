#!/usr/bin/env node
// Fixture tests for scripts/check-aauth-reference-projection.mjs (#1169).
// Dependency-free (node:assert and node:test). A broken projector must fail
// the acceptance fixtures, and each mutation of a copy of the real draft must
// produce its specific finding, so a check the script silently stops making
// fails here; the positive case asserts the draft as committed passes.
//
// Usage: node scripts/test-check-aauth-reference-projection.mjs

import fs from "node:fs";
import path from "node:path";
import assert from "node:assert/strict";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

import { validate, project } from "./check-aauth-reference-projection.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const DRAFT = fs.readFileSync(path.join(ROOT, "draft-mcguinness-mission-aauth.md"), "utf8");

function mutate(text, from, to) {
  const n = text.split(from).length - 1;
  assert.equal(n, 1, `fixture anchor must occur exactly once: ${JSON.stringify(from)}`);
  return text.replace(from, to);
}

const has = (errors, fragment) => errors.some((e) => e.includes(fragment));

test("the committed draft and the reference projector pass", () => {
  assert.deepEqual(validate(DRAFT).errors, []);
});

test("a projector that falls back to an auth token's iss fails", () => {
  const fallback = (c) => {
    if (c?.kind === "auth_token" && c.verified && !c.claims?.ps) {
      return project({ ...c, kind: "person_token" });
    }
    return project(c);
  };
  assert.ok(has(validate(DRAFT, fallback).errors, "auth token without ps"));
});

test("a projector that reads an auth token's iss fails the four-party cases", () => {
  const issFirst = (c) => (c?.kind === "auth_token" ? project({ ...c, kind: "person_token" }) : project(c));
  const errors = validate(DRAFT, issFirst).errors;
  assert.ok(has(errors, "four-party auth token"));
  assert.ok(has(errors, "is not the projection"));
});

test("a projector that skips verification fails", () => {
  const unchecked = (c) => project(c && { ...c, verified: true });
  assert.ok(has(validate(DRAFT, unchecked).errors, "unverified carrier"));
});

test("a projector that merges namespaces fails", () => {
  const merged = (c) => {
    const r = project(c);
    return r && { issuer: "https://ps.example", id: r.id };
  };
  assert.ok(has(validate(DRAFT, merged).errors, "equal digests"));
});

test("an example whose Mission issuer is the Access Server fails", () => {
  const text = mutate(DRAFT, '"issuer": "https://ps.example",', '"issuer": "https://as.example",');
  assert.ok(has(validate(text).errors, "is not the projection"));
});

test("a carrier table that sources an auth token's issuer from iss fails", () => {
  const text = mutate(DRAFT, "| Auth token, three-party or four-party | the token's `ps` |", "| Auth token, three-party or four-party | the token's `iss` |");
  assert.ok(has(validate(text).errors, "the projection uses"));
});

test("a PS-issued example cannot stand in for the four-party one", () => {
  const text = mutate(DRAFT, "four-party auth token with `iss`\n`https://as.example`", "four-party auth token with `iss`\n`https://ps.example`");
  assert.ok(has(validate(text).errors, "PS-issued"));
});

test("removing the example fails", () => {
  const text = mutate(DRAFT, "projects as follows.", "is projected.");
  assert.ok(has(validate(text).errors, "no four-party projection example found"));
});
