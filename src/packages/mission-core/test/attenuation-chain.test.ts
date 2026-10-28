/**
 * The shared Mission-bound AAT helpers (attenuation-chain.ts) the
 * cross-organization chain still verifies its hops with until #1759 moves it
 * to -02: capability monotonicity over the legacy tool map, and the
 * audience, expiry and par_hash rules. The Mission-bound chain itself is
 * verified by the -02 substrate verifier (aat-verify.test.ts) with the
 * Mission layer on top (mission-aat.test.ts).
 */

import { describe, expect, it } from "vitest";
import {
  type AATTools,
  aatToolId,
  audNesting,
  expNesting,
  parHash,
  toolsSubset,
} from "../src/index.js";

const RES = "https://erp.example.com";
const READ = aatToolId(RES, "invoices.read");
const WRITE = aatToolId(RES, "journal-entries.write");

const ROOT_TOOLS: AATTools = {
  [READ]: {},
  [WRITE]: { amount_usd: { constraint_type: "range", max: 500 } },
};
const READ_ONLY: AATTools = { [READ]: {} };

describe("toolsSubset (capability monotonicity)", () => {
  it("dropping a tool narrows (subset)", () => {
    expect(toolsSubset(READ_ONLY, ROOT_TOOLS)).toBe(true);
  });
  it("tightening a range narrows (subset)", () => {
    expect(
      toolsSubset({ [WRITE]: { amount_usd: { constraint_type: "range", max: 200 } } }, ROOT_TOOLS),
    ).toBe(true);
  });
  it("adding a tool the parent lacks is NOT a subset (widen)", () => {
    const parent: AATTools = { [READ]: {} };
    expect(toolsSubset(ROOT_TOOLS, parent)).toBe(false);
  });
  it("raising a range cap is NOT a subset (widen)", () => {
    const child: AATTools = { [WRITE]: { amount_usd: { constraint_type: "range", max: 1000 } } };
    expect(toolsSubset(child, ROOT_TOOLS)).toBe(false);
  });
  it("dropping a parent constraint is NOT a subset (broader)", () => {
    expect(toolsSubset({ [WRITE]: {} }, ROOT_TOOLS)).toBe(false);
  });
});

describe("the per-hop aud, exp and par_hash rules (@spec attenuation#attenuation)", () => {
  it("an aud nests when it equals its parent's or is a subset, as a set of exact strings", () => {
    expect(audNesting(RES, [RES, "https://other.example"])).toBe(true);
    expect(audNesting([RES], RES)).toBe(true);
    expect(audNesting([RES, "https://other.example"], RES)).toBe(false);
    expect(audNesting(`${RES}/`, RES)).toBe(false);
  });

  it("an exp nests when it does not exceed its parent's", () => {
    expect(expNesting(1900, 2000)).toBe(true);
    expect(expNesting(2000, 2000)).toBe(true);
    expect(expNesting(2001, 2000)).toBe(false);
  });

  it("par_hash commits to the parent's JWS signing input, not its signature", () => {
    const signingInput = "eyJhbGciOiJFUzI1NiJ9.eyJhIjoxfQ";
    expect(parHash(`${signingInput}.c2ln`)).toBe(parHash(`${signingInput}.b3RoZXI`));
    expect(parHash(`${signingInput}.c2ln`)).not.toBe(
      parHash("eyJhbGciOiJFUzI1NiJ9.eyJhIjoyfQ.c2ln"),
    );
  });
});
