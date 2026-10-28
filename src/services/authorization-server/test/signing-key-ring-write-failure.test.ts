/**
 * @spec #831 acceptance item 4, #1815 gap 3: a key ring update that fails part
 * way leaves the ring it started from. Each ring write is a temporary file,
 * flushed, then renamed (or, at initialization, linked) into place; a failure
 * at any of those steps refuses, leaves the ring's bytes and identity as they
 * were, and leaves no temporary copy of its private keys behind.
 */

import { existsSync, mkdtempSync, readdirSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { TOPOLOGY } from "@mission/demo-data";
import { describe, expect, it, vi } from "vitest";

/** The one `node:fs` call to fail next, once. */
const fault = vi.hoisted(() => ({ on: undefined as string | undefined }));

vi.mock("node:fs", async (importOriginal) => {
  const fs = await importOriginal<typeof import("node:fs")>();
  const failing =
    (name: "writeSync" | "fsyncSync" | "renameSync" | "linkSync") =>
    (...args: unknown[]) => {
      if (fault.on === name) {
        fault.on = undefined;
        throw Object.assign(new Error(`injected ${name} failure`), { code: "EIO" });
      }
      return (fs[name] as (...a: unknown[]) => unknown)(...args);
    };
  return {
    ...fs,
    default: fs,
    writeSync: failing("writeSync"),
    fsyncSync: failing("fsyncSync"),
    renameSync: failing("renameSync"),
    linkSync: failing("linkSync"),
  };
});

const { initSigningKeyRing, loadSigningKeyRing, SigningKeyRingError, stageSigningKeyGeneration } = await import(
  "../src/kernel/signing-key-ring.js"
);

const ISSUER = "https://as.example.test";
const ROLES = {
  asToken: TOPOLOGY.keys.asToken,
  asStatus: TOPOLOGY.keys.asStatus,
  asTxn: TOPOLOGY.keys.asTxn,
  asContinuation: TOPOLOGY.keys.asContinuation,
};

const temporaries = (dir: string) => readdirSync(dir).filter((f) => f.startsWith(".ring-"));
const identity = async (ring: string) =>
  Object.fromEntries(
    Object.entries(await loadSigningKeyRing(ring, ISSUER, ROLES)).map(([role, k]) => [role, { kid: k.kid, x: k.publicJwk.x }]),
  );

describe("a key ring update that fails part way (@spec #831, #1815)", () => {
  for (const step of ["writeSync", "fsyncSync", "renameSync"] as const) {
    it(`refuses a rotation whose ${step} fails, leaving the ring's bytes and identity as they were and no temporary copy`, async () => {
      const dir = join(mkdtempSync(join(tmpdir(), "ring-write-")), "keys");
      const ring = join(dir, "ring.json");
      await initSigningKeyRing(ring, ISSUER, ROLES);
      const bytes = readFileSync(ring, "utf8");
      const before = await identity(ring);

      fault.on = step;
      await expect(stageSigningKeyGeneration(ring, ISSUER, ROLES, "asToken")).rejects.toThrow(SigningKeyRingError);
      expect(fault.on).toBeUndefined();

      expect(readFileSync(ring, "utf8")).toBe(bytes);
      expect(temporaries(dir)).toEqual([]);
      expect(await identity(ring)).toEqual(before);
      // The same rotation succeeds once the failure is gone.
      await expect(stageSigningKeyGeneration(ring, ISSUER, ROLES, "asToken")).resolves.toEqual({ kid: "as-token-2" });
    });
  }

  for (const step of ["writeSync", "fsyncSync", "linkSync"] as const) {
    it(`refuses an initialization whose ${step} fails, creating no ring and leaving no temporary copy`, async () => {
      const dir = join(mkdtempSync(join(tmpdir(), "ring-init-")), "keys");
      const ring = join(dir, "ring.json");
      fault.on = step;
      await expect(initSigningKeyRing(ring, ISSUER, ROLES)).rejects.toThrow(SigningKeyRingError);
      expect(fault.on).toBeUndefined();
      expect(existsSync(ring)).toBe(false);
      expect(temporaries(dir)).toEqual([]);
      await initSigningKeyRing(ring, ISSUER, ROLES);
      expect(Object.keys(await identity(ring)).sort()).toEqual(["asContinuation", "asStatus", "asToken", "asTxn"]);
    });
  }
});
