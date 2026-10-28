/**
 * The shared Mission-bound AAT helpers (attenuation-chain.ts): the audience
 * and par_hash rules. A Mission-bound chain, in-organization or
 * cross-organization (#1759), is verified by the -02 substrate verifier
 * (aat-verify.test.ts) with the Mission layer on top (mission-aat.test.ts).
 */

import { describe, expect, it } from "vitest";
import { audNesting, parHash } from "../src/index.js";

const RES = "https://erp.example.com";

describe("the per-hop aud and par_hash rules (@spec attenuation#attenuation)", () => {
  it("an aud nests when it equals its parent's or is a subset, as a set of exact strings", () => {
    expect(audNesting(RES, [RES, "https://other.example"])).toBe(true);
    expect(audNesting([RES], RES)).toBe(true);
    expect(audNesting([RES, "https://other.example"], RES)).toBe(false);
    expect(audNesting(`${RES}/`, RES)).toBe(false);
  });

  it("par_hash commits to the parent's JWS signing input, not its signature", () => {
    const signingInput = "eyJhbGciOiJFUzI1NiJ9.eyJhIjoxfQ";
    expect(parHash(`${signingInput}.c2ln`)).toBe(parHash(`${signingInput}.b3RoZXI`));
    expect(parHash(`${signingInput}.c2ln`)).not.toBe(
      parHash("eyJhbGciOiJFUzI1NiJ9.eyJhIjoyfQ.c2ln"),
    );
  });
});
