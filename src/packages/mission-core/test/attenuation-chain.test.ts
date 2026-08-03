/**
 * Pure, keyless, deterministic tests for the Mission-bound AAT chain verifier.
 * Tokens are hand-crafted compact JWS strings with a dummy signature segment:
 * the keyless verifier ignores signatures, so this exercises capability
 * monotonicity, the mission-claim invariant, aud/exp nesting, the depth cap,
 * and the par_hash linkage over the exact wire bytes -- including the
 * attenuate-WIDEN attacks a compromised holder would attempt against the
 * consumer's verifier (which never calls the offline mint helper).
 */

import { describe, expect, it } from "vitest";
import {
  type AATClaims,
  type AATTools,
  aatToolId,
  parHash,
  toolsSubset,
  verifyAttenuationChain,
} from "../src/index.js";

const RES = "https://erp.example.com";
const READ = aatToolId(RES, "invoices.read");
const WRITE = aatToolId(RES, "journal-entries.write");
const MISSION = { id: "msn_abc", issuer: "https://as.example.com", authority_hash: "sha-256:H" };

const ROOT_TOOLS: AATTools = {
  [READ]: {},
  [WRITE]: { amount_usd: { constraint_type: "range", max: 500 } },
};
const READ_ONLY: AATTools = { [READ]: {} };

/** Encode claims + header into a compact JWS with a fixed dummy signature. */
function encode(
  claims: AATClaims,
  header: Record<string, unknown> = { alg: "ES256", typ: "aat+jwt" },
): string {
  const b64 = (o: unknown) => Buffer.from(JSON.stringify(o), "utf8").toString("base64url");
  return `${b64(header)}.${b64(claims)}.c2ln`;
}

function root(overrides: Partial<AATClaims> = {}): AATClaims {
  return {
    iss: MISSION.issuer,
    sub: "user_1",
    aud: RES,
    exp: 2000,
    cnf: { jkt: "jkt_root" },
    del_depth: 0,
    del_max_depth: 2,
    mission: MISSION,
    authorization_details: [{ type: "attenuating_agent_token", tools: ROOT_TOOLS }],
    ...overrides,
  };
}

function child(parentCompact: string, overrides: Partial<AATClaims> = {}): AATClaims {
  return {
    iss: "urn:ietf:params:oauth:jwk-thumbprint:sha-256:jkt_root",
    sub: "user_1",
    aud: RES,
    exp: 1900,
    cnf: { jkt: "jkt_child" },
    del_depth: 1,
    del_max_depth: 2,
    par_hash: parHash(parentCompact),
    mission: MISSION,
    authorization_details: [{ type: "attenuating_agent_token", tools: READ_ONLY }],
    ...overrides,
  };
}

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

describe("verifyAttenuationChain", () => {
  it("accepts a valid [root, read-only child] chain and returns the leaf", () => {
    const r = encode(root());
    const c = encode(child(r));
    const res = verifyAttenuationChain([r, c]);
    expect(res.ok, JSON.stringify(res)).toBe(true);
    if (res.ok) expect(Object.keys(res.leaf.authorization_details[0]?.tools ?? {})).toEqual([READ]);
  });

  it("WIDEN by raising the cap on the child is refused (capability_widened)", () => {
    const r = encode(root());
    const c = encode(
      child(r, {
        authorization_details: [
          {
            type: "attenuating_agent_token",
            tools: { [WRITE]: { amount_usd: { constraint_type: "range", max: 1000 } } },
          },
        ],
      }),
    );
    const res = verifyAttenuationChain([r, c]);
    expect(res).toEqual({ ok: false, reason: "capability_widened" });
  });

  it("WIDEN by a grandchild re-adding the dropped write tool is refused", () => {
    const r = encode(root());
    const c = encode(child(r)); // read-only
    const g = encode(
      child(c, {
        del_depth: 2,
        cnf: { jkt: "jkt_grand" },
        authorization_details: [{ type: "attenuating_agent_token", tools: ROOT_TOOLS }],
      }),
    );
    const res = verifyAttenuationChain([r, c, g]);
    expect(res).toEqual({ ok: false, reason: "capability_widened" });
  });

  it("a child re-binding to a different mission is refused (mission_claim_mismatch)", () => {
    const r = encode(root());
    const c = encode(child(r, { mission: { ...MISSION, id: "msn_other" } }));
    const res = verifyAttenuationChain([r, c]);
    expect(res).toEqual({ ok: false, reason: "mission_claim_mismatch" });
  });

  it("a child whose exp exceeds the parent's is refused (exp_exceeds_parent)", () => {
    const r = encode(root());
    const c = encode(child(r, { exp: 2100 }));
    const res = verifyAttenuationChain([r, c]);
    expect(res).toEqual({ ok: false, reason: "exp_exceeds_parent" });
  });

  it("a child whose aud is not within the parent's is refused (aud_widened)", () => {
    const r = encode(root());
    const c = encode(child(r, { aud: "https://other.example.com" }));
    const res = verifyAttenuationChain([r, c]);
    expect(res).toEqual({ ok: false, reason: "aud_widened" });
  });

  it("tampering with the parent's bytes breaks the par_hash linkage", () => {
    const r = encode(root());
    const c = encode(child(r)); // par_hash commits to the untampered root
    const tampered = encode(root({ exp: 1999 })); // one changed claim -> different bytes
    const res = verifyAttenuationChain([tampered, c]);
    expect(res).toEqual({ ok: false, reason: "par_hash_mismatch" });
  });

  it("a chain deeper than del_max_depth is refused (del_max_depth_exceeded)", () => {
    const r = encode(root({ del_max_depth: 1 }));
    const c = encode(child(r, { del_max_depth: 1 })); // depth 1, ok
    const g = encode(child(c, { del_depth: 2, del_max_depth: 1, cnf: { jkt: "jkt_grand" } }));
    const res = verifyAttenuationChain([r, c, g]);
    expect(res).toEqual({ ok: false, reason: "del_max_depth_exceeded" });
  });

  it("a child raising del_max_depth is refused (del_max_depth_raised)", () => {
    const r = encode(root({ del_max_depth: 1 }));
    const c = encode(child(r, { del_max_depth: 5 }));
    const res = verifyAttenuationChain([r, c]);
    expect(res).toEqual({ ok: false, reason: "del_max_depth_raised" });
  });

  it("a root carrying no mission claim is outside this profile (root_not_mission_bound)", () => {
    const r = encode(root({ mission: undefined }));
    const res = verifyAttenuationChain([r]);
    expect(res).toEqual({ ok: false, reason: "root_not_mission_bound" });
  });
});
