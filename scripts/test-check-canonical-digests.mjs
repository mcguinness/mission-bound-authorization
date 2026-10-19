#!/usr/bin/env node
// Tests for scripts/check-canonical-digests.mjs (#1188).
// Usage: node scripts/test-check-canonical-digests.mjs

import assert from "node:assert/strict";
import { test } from "node:test";

import { findNonCanonical } from "./check-canonical-digests.mjs";

const CANON = "kP3xR9sQ7nM2vL4tY6bD1eF8jC5wH0pV2nR3kQ4mZ7s";
const NONCANON = "kP3xR9sQ7nM2vL4tY6bD1eF8jC5wH0pV2nR3kQ4mZ7t";

test("a canonical value passes", () => {
  assert.deepEqual(findNonCanonical(`"h": "sha-256:${CANON}"`), []);
});

test("a value with nonzero pad bits is reported with its canonical form", () => {
  const r = findNonCanonical(`a\n"h": "sha-256:${NONCANON}"`);
  assert.deepEqual(r, [{ line: 2, value: NONCANON, canonical: CANON }]);
});

test("values of other lengths are ignored", () => {
  assert.deepEqual(findNonCanonical(`sha-256:${NONCANON}x sha-256:abc`), []);
});
