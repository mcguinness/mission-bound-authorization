/**
 * @spec #831 acceptance item 2 ("no kid is reused for different material"),
 * #1815 gap 5 (D945): the AS's key binding record, kept apart from the key
 * ring, binds each kid the ring has held to its key's thumbprint. A ring
 * recreated under recorded kids is refused; the original ring restored loads;
 * a rotation's new kid is recorded once; a rotation after a restored older
 * ring skips the recorded numbers; a replacement under new configured kids is
 * accepted and noted; a missing, foreign or co-located record refuses, and a
 * new kid that cannot be recorded refuses.
 */

import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { TOPOLOGY } from "@mission/demo-data";
import { describe, expect, it } from "vitest";
import {
  bindSigningKeyRing,
  buildAuthorizationServer,
  initSigningKeyRing,
  type KeyBindingRecord,
  loadSigningKeyRing,
  SigningKeyRingError,
  stageSigningKeyGeneration,
} from "../src/index.js";

const ISSUER = "https://as.example.test";
const ROLES = {
  asToken: TOPOLOGY.keys.asToken,
  asStatus: TOPOLOGY.keys.asStatus,
  asTxn: TOPOLOGY.keys.asTxn,
  asContinuation: TOPOLOGY.keys.asContinuation,
};

/** A ring and a binding record in separate directories (separate restore units). */
function layout() {
  const root = mkdtempSync(join(tmpdir(), "key-bindings-"));
  const ring = join(root, "keys", "ring.json");
  const bindings = join(root, "bindings", "key-bindings.json");
  return { root, ring, bindings };
}
const record = (file: string) => JSON.parse(readFileSync(file, "utf8")) as KeyBindingRecord;
const kidsOf = (file: string) => record(file).bindings.map((b) => b.kid);

describe("the AS's key binding record (@spec #831, #1815, D945)", () => {
  it("refuses a ring recreated under the recorded kids, at load and at AS assembly, and loads the original ring restored", async () => {
    const { ring, bindings } = layout();
    await initSigningKeyRing(ring, ISSUER, ROLES, undefined, { bindings });
    await loadSigningKeyRing(ring, ISSUER, ROLES, { bindings });
    const original = readFileSync(ring, "utf8");

    // The ring is lost and recreated: the same configured kids, new keys.
    rmSync(ring);
    await initSigningKeyRing(ring, ISSUER, ROLES);
    await expect(loadSigningKeyRing(ring, ISSUER, ROLES, { bindings })).rejects.toThrow(
      /the ring holds as-token with key material other than .* records for it: a recreated ring under recorded identifiers/,
    );
    await expect(loadSigningKeyRing(ring, ISSUER, ROLES, { bindings })).rejects.toBeInstanceOf(SigningKeyRingError);
    await expect(buildAuthorizationServer({ issuer: ISSUER, signingKeys: { ring, bindings } })).rejects.toThrow(
      /a recreated ring under recorded identifiers/,
    );
    // Without the record nothing notices: the record is what refuses it.
    await loadSigningKeyRing(ring, ISSUER, ROLES);

    // The original ring restored: the same material, accepted.
    writeFileSync(ring, original, { mode: 0o600 });
    await loadSigningKeyRing(ring, ISSUER, ROLES, { bindings });
  });

  it("records a rotation's new kid at the next load, and a second load changes nothing", async () => {
    const { ring, bindings } = layout();
    await initSigningKeyRing(ring, ISSUER, ROLES, undefined, { bindings });
    expect(kidsOf(bindings)).not.toContain("as-token-2");
    await stageSigningKeyGeneration(ring, ISSUER, ROLES, "asToken", undefined, { bindings });
    await loadSigningKeyRing(ring, ISSUER, ROLES, { bindings });
    expect(kidsOf(bindings)).toContain("as-token-2");
    const after = readFileSync(bindings, "utf8");
    await loadSigningKeyRing(ring, ISSUER, ROLES, { bindings });
    expect(readFileSync(bindings, "utf8")).toBe(after);
  });

  it("after a restored older ring, a rotation given the record skips the recorded kid; one not given it reuses that kid and is refused", async () => {
    const { ring, bindings } = layout();
    await initSigningKeyRing(ring, ISSUER, ROLES, undefined, { bindings });
    const older = readFileSync(ring, "utf8");
    await stageSigningKeyGeneration(ring, ISSUER, ROLES, "asToken", undefined, { bindings });
    await loadSigningKeyRing(ring, ISSUER, ROLES, { bindings });
    expect(kidsOf(bindings)).toContain("as-token-2");

    // The older backup comes back: the ring lacks as-token-2, the record holds it.
    writeFileSync(ring, older, { mode: 0o600 });
    await loadSigningKeyRing(ring, ISSUER, ROLES, { bindings });
    expect(await stageSigningKeyGeneration(ring, ISSUER, ROLES, "asToken", undefined, { bindings })).toEqual({ kid: "as-token-3" });
    await loadSigningKeyRing(ring, ISSUER, ROLES, { bindings });

    // Not given the record, a rotation from the older ring reuses as-token-2 with new material.
    writeFileSync(ring, older, { mode: 0o600 });
    expect(await stageSigningKeyGeneration(ring, ISSUER, ROLES, "asToken")).toEqual({ kid: "as-token-2" });
    await expect(loadSigningKeyRing(ring, ISSUER, ROLES, { bindings })).rejects.toThrow(/the ring holds as-token-2 with key material other than/);
  });

  it("accepts a replacement ring under new configured kids, and records both the new kids and the replacement", async () => {
    const { ring, bindings } = layout();
    await initSigningKeyRing(ring, ISSUER, ROLES, undefined, { bindings });
    const old = kidsOf(bindings);
    rmSync(ring);
    // The explicit replacement: new base kids for every role, consumers to be told to trust them.
    const replaced = Object.fromEntries(Object.entries(ROLES).map(([r, c]) => [r, { ...c, kid: `${c.kid}-r2` }])) as typeof ROLES;
    await initSigningKeyRing(ring, ISSUER, replaced);
    await loadSigningKeyRing(ring, ISSUER, replaced, { bindings });
    const now = record(bindings);
    expect(now.bindings.map((b) => b.kid)).toEqual([...old, ...Object.values(replaced).map((c) => c.kid)]);
    expect(now.replacements.map((r) => [r.role, r.from, r.to])).toEqual(
      Object.entries(ROLES).map(([role, c]) => [role, [c.kid], `${c.kid}-r2`]),
    );
  });

  it("refuses a missing record and never creates it; refuses a record inside the ring's directory, one for another issuer, and a second creation", async () => {
    const { root, ring, bindings } = layout();
    await initSigningKeyRing(ring, ISSUER, ROLES);
    await expect(loadSigningKeyRing(ring, ISSUER, ROLES, { bindings })).rejects.toThrow(/no key binding record at .*pnpm keys bind/);
    expect(existsSync(bindings)).toBe(false);

    const beside = join(root, "keys", "key-bindings.json");
    await expect(bindSigningKeyRing(ring, ISSUER, ROLES, beside)).rejects.toThrow(/must be outside the ring's directory/);
    await expect(initSigningKeyRing(join(root, "other", "ring.json"), ISSUER, ROLES, undefined, { bindings: join(root, "other", "b.json") })).rejects.toThrow(
      /must be outside the ring's directory/,
    );

    const foreign = layout();
    await initSigningKeyRing(foreign.ring, "https://other.example.test", ROLES, undefined, { bindings: foreign.bindings });
    await expect(loadSigningKeyRing(ring, ISSUER, ROLES, { bindings: foreign.bindings })).rejects.toThrow(
      /binds keys for issuer https:\/\/other\.example\.test, not https:\/\/as\.example\.test/,
    );

    await bindSigningKeyRing(ring, ISSUER, ROLES, bindings);
    await expect(bindSigningKeyRing(ring, ISSUER, ROLES, bindings)).rejects.toThrow(/already exists; a key binding record is created once/);
  });

  it("refuses to start when a new kid cannot be recorded, leaving the record as it was", async () => {
    const { ring, bindings } = layout();
    await initSigningKeyRing(ring, ISSUER, ROLES, undefined, { bindings });
    await stageSigningKeyGeneration(ring, ISSUER, ROLES, "asToken", undefined, { bindings });
    const before = readFileSync(bindings, "utf8");
    const dir = join(bindings, "..");
    chmodSync(dir, 0o500);
    try {
      await expect(loadSigningKeyRing(ring, ISSUER, ROLES, { bindings })).rejects.toThrow(/cannot record as-token-2 in/);
    } finally {
      chmodSync(dir, 0o700);
    }
    expect(readFileSync(bindings, "utf8")).toBe(before);
    await loadSigningKeyRing(ring, ISSUER, ROLES, { bindings });
    expect(kidsOf(bindings)).toContain("as-token-2");
  });
});
