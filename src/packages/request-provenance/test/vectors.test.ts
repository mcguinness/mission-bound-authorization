// Checks that vectors/mission-request-provenance/assertion-cases.json is
// well-formed data for the AS verifier (#939 slice 2): each token differs
// from the positive vector exactly as its case states, a token signed with
// the test key verifies (so a refusal never rests on a bad signature unless
// the case says so), and each producer-checked case names a test here.

import { createHmac, createPublicKey } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { compactVerify } from "jose";
import { describe, expect, it } from "vitest";
import { assertionCases, decodeJws, publicKey, assertionVector as V } from "./fixtures.js";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../../../..");

function without(o: Record<string, unknown>, keys: string[] = []): Record<string, unknown> {
  const c = structuredClone(o);
  for (const k of keys) delete c[k];
  return c;
}

describe("the assertion vectors are well-formed data for the verifier (#939)", () => {
  it("each case's token differs from the positive vector exactly as its construction states", async () => {
    const ids = new Set<string>();
    for (const c of assertionCases) {
      expect(ids.has(c.id), c.id).toBe(false);
      ids.add(c.id);
      const k = c.construction as {
        header_set?: Record<string, unknown>;
        header_delete?: string[];
        claims_set?: Record<string, unknown>;
        claims_delete?: string[];
        payload_set?: Record<string, unknown>;
        signature?: string;
        verifier_context_patch?: Record<string, unknown>;
      };
      const { header, claims } = decodeJws(c.token);
      expect(header, c.id).toEqual({
        ...without(V.expected.protected_header, k.header_delete),
        ...k.header_set,
      });
      if (k.payload_set === undefined) {
        expect(claims, c.id).toEqual({
          ...without(V.expected.claims, k.claims_delete),
          ...k.claims_set,
        });
      } else {
        expect(claims.originator, c.id).toEqual({
          ...(V.expected.claims.originator as object),
          sub: k.payload_set["originator.sub"],
        });
      }
      if (k.signature === undefined) {
        // Signed with the test key: the signature itself is valid.
        await expect(compactVerify(c.token, publicKey), c.id).resolves.toBeDefined();
      } else if (k.signature === "empty") {
        expect(c.token.endsWith("."), c.id).toBe(true);
      } else if (k.signature === "original") {
        await expect(compactVerify(c.token, publicKey), c.id).rejects.toThrow();
      } else {
        const pem = createPublicKey({ key: V.key.public_jwk as never, format: "jwk" }).export({
          type: "spki",
          format: "pem",
        });
        const [h, p, s] = c.token.split(".");
        const mac = createHmac("sha256", Buffer.from(pem as string, "utf8"))
          .update(`${h}.${p}`)
          .digest("base64url");
        expect(s, c.id).toBe(mac);
      }
      if (c.expected.outcome === "refuse") {
        expect(c.expected.error, c.id).toBe("invalid_mission_intent_evidence");
      }
      expect(c.verifier.status, c.id).toBe("pending");
    }
    // The brief's minimum set is present.
    for (const id of [
      "neg-typ-jwt",
      "neg-alg-none",
      "neg-alg-hs256",
      "neg-header-jku",
      "neg-header-x5u",
      "neg-header-jwk",
      "neg-header-x5c",
      "neg-altered-claim",
      "neg-expired",
      "neg-aud-array",
      "neg-missing-request-digest",
      "ign-extra-content-claim",
    ]) {
      expect(ids.has(id), id).toBe(true);
    }
  });

  it("every producer-checked case names a test in this package", () => {
    for (const c of assertionCases) {
      if (c.producer.status !== "checked") continue;
      const [file, describeName, itName, ...rest] = c.producer.test.split(" > ");
      expect(rest, c.id).toEqual([]);
      const source = readFileSync(resolve(repoRoot, file as string), "utf8");
      expect(source.includes(JSON.stringify(describeName)), `${c.id}: ${describeName}`).toBe(true);
      expect(source.includes(JSON.stringify(itName)), `${c.id}: ${itName}`).toBe(true);
    }
  });
});
