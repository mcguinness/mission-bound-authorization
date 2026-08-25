/**
 * @spec mission#authorization-derivation, mission#subset, attenuation#delegation,
 * child-delegation#fanout
 *
 * The AuthorityEntry.delegation core extension (S-15): derivation carries and
 * narrows the per-entry `delegation` GRANT, the subset test treats it as a
 * narrowing dimension (the OPPOSITE direction from constraints), and
 * deriveAttenuationRoot DERIVES `del_max_depth` from the delegable entries.
 *
 * Pure, in-memory, no network (OpenFGA is not on any path here).
 */

import { aatToolId } from "@mission/core";
import { DERIVATION_POLICY } from "@mission/demo-data";
import { type CryptoKey, decodeJwt, generateKeyPair } from "jose";
import { beforeAll, describe, expect, it } from "vitest";
import {
  type AuthorityEntry,
  deriveAttenuationRoot,
  deriveAuthoritySet,
  IntentError,
  isSubsetEntry,
  MissionKernel,
  type MissionIntent,
  validateMissionIntent,
} from "../src/index.js";

const ISS = "https://as.test";
const EXP = "2027-01-01T00:00:00Z";

/** A fully-populated delegation GRANT with a child-delegation `children` object. */
const delegation = (maxDepth: number) => ({
  max_depth: maxDepth,
  allowed_delegates: [{ sub_profile: "ai_agent" }],
  children: {
    max_children: 5,
    max_child_depth: 2,
    allowed_child_actors: [{ sub_profile: "ai_agent" }],
  },
});

const entry = (over: Partial<AuthorityEntry> = {}): AuthorityEntry => ({
  type: "mission_resource_access",
  resource: "https://r.example/mcp",
  actions: ["res.read"],
  ...over,
});

// ---------------------------------------------------------------------------
// (a) intersect: carry + inherit-by-default from the ceiling
// ---------------------------------------------------------------------------
describe("intersect carries and narrows delegation (@spec mission#authorization-derivation)", () => {
  const ceilingEntry = entry({ delegation: delegation(2) });
  const policy = { policy_version: "t", ceiling: [ceilingEntry] };

  it("(a) proposal WITHOUT delegation inherits the ceiling's delegation.children unchanged", () => {
    const intent: MissionIntent = {
      goal: "g",
      target_resources: [ceilingEntry.resource],
      expires_at: EXP,
    };
    const proposal = [entry()]; // no delegation on the proposal
    const derived = deriveAuthoritySet(intent, policy, proposal);
    const del = derived[0]?.delegation;
    expect(del).toBeDefined();
    expect(del?.max_depth).toBe(2);
    const children = del?.children as { max_children?: number; max_child_depth?: number } | undefined;
    expect(children?.max_children).toBe(5);
    expect(children?.max_child_depth).toBe(2);
  });

  it("ceiling-absent delegation is NOT introduced by the proposal (compromised-shaper flip)", () => {
    const freePolicy = { policy_version: "t", ceiling: [entry()] }; // ceiling has NO delegation
    const intent: MissionIntent = {
      goal: "g",
      target_resources: ["https://r.example/mcp"],
      expires_at: EXP,
    };
    const proposal = [entry({ delegation: delegation(9) })]; // proposal TRIES to add it
    const derived = deriveAuthoritySet(intent, freePolicy, proposal);
    expect(derived[0]?.delegation).toBeUndefined();
  });

  it("both present -> max_depth narrows to the min and delegates intersect", () => {
    const intent: MissionIntent = {
      goal: "g",
      target_resources: [ceilingEntry.resource],
      expires_at: EXP,
    };
    const proposal = [
      entry({
        delegation: {
          max_depth: 5, // wider than the ceiling's 2
          allowed_delegates: [{ sub_profile: "ai_agent" }, { sub: "not-allowed" }],
        },
      }),
    ];
    const derived = deriveAuthoritySet(intent, policy, proposal);
    expect(derived[0]?.delegation?.max_depth).toBe(2); // min(5, 2)
    // proposal ∩ ceiling on delegate identity: only ai_agent survives.
    expect(derived[0]?.delegation?.allowed_delegates).toEqual([{ sub_profile: "ai_agent" }]);
    // children is a GRANT: the ceiling has one, the proposal omits it -> inherited.
    expect(derived[0]?.delegation?.children).toBeDefined();
  });
});

// ---------------------------------------------------------------------------
// (b) isSubsetEntry: max_depth narrows, does not relax
// ---------------------------------------------------------------------------
describe("isSubsetEntry treats delegation as a narrowing dimension (@spec mission#subset)", () => {
  const granted = entry({ delegation: delegation(2) });

  it("(b) a NARROWER max_depth is a subset; a BROADER one is not", () => {
    expect(isSubsetEntry(entry({ delegation: delegation(1) }), granted)).toBe(true);
    expect(isSubsetEntry(entry({ delegation: delegation(2) }), granted)).toBe(true); // equal ok
    expect(isSubsetEntry(entry({ delegation: delegation(3) }), granted)).toBe(false);
    // max_depth in isolation (no children on either side): the failure at 3 is
    // attributable to max_depth alone, not to a children mismatch.
    const grantedBare = entry({ delegation: { max_depth: 2 } });
    expect(isSubsetEntry(entry({ delegation: { max_depth: 1 } }), grantedBare)).toBe(true);
    expect(isSubsetEntry(entry({ delegation: { max_depth: 3 } }), grantedBare)).toBe(false);
  });

  it("allowed_delegates must be no wider; children caps must be no broader", () => {
    // A delegate the grantor does not list -> broader -> fail.
    const widerDelegate = entry({
      delegation: { max_depth: 2, allowed_delegates: [{ sub: "stranger" }] },
    });
    expect(isSubsetEntry(widerDelegate, granted)).toBe(false);
    // A larger max_children than the grantor's -> broader -> fail.
    const widerChildren = entry({
      delegation: { max_depth: 2, children: { max_children: 99 } },
    });
    expect(isSubsetEntry(widerChildren, granted)).toBe(false);
  });

  it("(c) a candidate INTRODUCING children where the grantor has none fails", () => {
    const grantedNoChildren = entry({ delegation: { max_depth: 2 } });
    const introducesChildren = entry({
      delegation: { max_depth: 2, children: { max_children: 1 } },
    });
    expect(isSubsetEntry(introducesChildren, grantedNoChildren)).toBe(false);
    // ...but omitting children (grantor has none) is fine.
    expect(isSubsetEntry(entry({ delegation: { max_depth: 2 } }), grantedNoChildren)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// (c) isSubsetEntry: presence flip (opposite of the constraint rule)
// ---------------------------------------------------------------------------
describe("isSubsetEntry delegation presence flip (@spec child-delegation#attenuation)", () => {
  it("(c) candidate OMITTING delegation the grantor has PASSES (does not re-delegate)", () => {
    expect(isSubsetEntry(entry(), entry({ delegation: delegation(2) }))).toBe(true);
  });

  it("(c) candidate INTRODUCING delegation on a delegation-free grant FAILS", () => {
    expect(isSubsetEntry(entry({ delegation: delegation(1) }), entry())).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Regression: a delegation-free ceiling behaves EXACTLY as before, on both sides.
// ---------------------------------------------------------------------------
describe("regression: delegation-free entries are fully additive (unchanged behavior)", () => {
  it("derivation yields delegation-free entries from a delegation-free ceiling", () => {
    const policy = {
      policy_version: "t",
      ceiling: [entry({ constraints: { vendors: ["acme"] } })],
    };
    const intent: MissionIntent = {
      goal: "g",
      target_resources: ["https://r.example/mcp"],
      expires_at: EXP,
    };
    const proposal = [entry({ constraints: { vendors: ["acme"] } })];
    const derived = deriveAuthoritySet(intent, policy, proposal);
    expect(derived[0]?.delegation).toBeUndefined();
  });

  it("both-absent delegation: subset decided purely by actions/constraints, as before", () => {
    // Identical entries -> subset.
    expect(isSubsetEntry(entry(), entry())).toBe(true);
    // Candidate omitting a vendors constraint the grantor has still fails (unchanged).
    const grantedV = entry({ constraints: { vendors: ["acme"] } });
    expect(isSubsetEntry(entry(), grantedV)).toBe(false);
    // Candidate within the granted vendors, both delegation-free -> still subset.
    expect(isSubsetEntry(grantedV, grantedV)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// (d) deriveAttenuationRoot DERIVES del_max_depth (closes S-15)
// ---------------------------------------------------------------------------
describe("deriveAttenuationRoot derives del_max_depth (@spec attenuation#root-mapping S-15)", () => {
  const RES_A = "https://a.example/mcp"; // delegable, depth 3
  const RES_B = "https://b.example/mcp"; // delegable, depth 2  -> min is 2
  const RES_C = "https://c.example/mcp"; // NON-delegable (dropped when depth > 0)

  const mixedPolicy = {
    policy_version: "t",
    ceiling: [
      { type: "mission_resource_access", resource: RES_A, actions: ["a.read"], delegation: delegation(3) },
      { type: "mission_resource_access", resource: RES_B, actions: ["b.read"], delegation: delegation(2) },
      { type: "mission_resource_access", resource: RES_C, actions: ["c.read"] },
    ] as AuthorityEntry[],
  };

  let signKey: CryptoKey;
  let seq = 0;
  beforeAll(async () => {
    signKey = (await generateKeyPair("ES256", { extractable: true })).privateKey;
  });

  const mkKernel = (policy: unknown) =>
    new MissionKernel({ issuer: ISS, policy: policy as never, statusKey: signKey, statusKid: "as-status" });

  const approveTemplate = (kernel: MissionKernel, resources: string[]) =>
    kernel.approve({
      intent: validateMissionIntent(
        JSON.stringify({ goal: "g", target_resources: resources, expires_at: EXP }),
      ),
      subject: { iss: ISS, sub: "alice" },
      approver: { iss: ISS, sub: "bob" },
      clientId: "agent",
      approvalEventId: `apev-${seq++}`,
    });

  it("(d) del_max_depth = min across delegable entries; the non-delegable entry is dropped", async () => {
    const kernel = mkKernel(mixedPolicy);
    const mission = approveTemplate(kernel, [RES_A, RES_B, RES_C]);
    const { root, tools } = await deriveAttenuationRoot(kernel, signKey, "as-token", {
      missionId: mission.id,
      aud: RES_A,
      clientId: "agent",
      cnfJkt: "jkt-holder",
      // NO delMaxDepth: exercises the DERIVED path.
    });
    expect(decodeJwt(root).del_max_depth).toBe(2); // min(3, 2)
    // Delegable tools ride; the non-delegable RES_C tool is dropped (depth > 0).
    expect(tools[aatToolId(RES_A, "a.read")]).toBeDefined();
    expect(tools[aatToolId(RES_B, "b.read")]).toBeDefined();
    expect(tools[aatToolId(RES_C, "c.read")]).toBeUndefined();
  });

  it("a requestedTools narrowing is minted non-delegating (del_max_depth 0, fail-closed)", async () => {
    // A client-requested narrowing does not inherit the full set's derived depth:
    // deriving over the justifying entries is fan-out accounting, deferred; a
    // non-delegating root is fail-closed.
    const kernel = mkKernel(mixedPolicy);
    const mission = approveTemplate(kernel, [RES_A, RES_B, RES_C]);
    const { root, tools } = await deriveAttenuationRoot(kernel, signKey, "as-token", {
      missionId: mission.id,
      aud: RES_A,
      clientId: "agent",
      cnfJkt: "jkt-holder",
      requestedTools: { [aatToolId(RES_A, "a.read")]: {} },
    });
    expect(decodeJwt(root).del_max_depth).toBe(0);
    expect(tools[aatToolId(RES_A, "a.read")]).toBeDefined();
    expect(tools[aatToolId(RES_B, "b.read")]).toBeUndefined();
  });

  it("a delegation-free Authority Set derives del_max_depth 0 and carries every tool", async () => {
    const freePolicy = {
      policy_version: "t",
      ceiling: [{ type: "mission_resource_access", resource: RES_C, actions: ["c.read"] }] as AuthorityEntry[],
    };
    const kernel = mkKernel(freePolicy);
    const mission = approveTemplate(kernel, [RES_C]);
    const { root, tools } = await deriveAttenuationRoot(kernel, signKey, "as-token", {
      missionId: mission.id,
      aud: RES_C,
      clientId: "agent",
      cnfJkt: "jkt-holder",
    });
    expect(decodeJwt(root).del_max_depth).toBe(0);
    expect(tools[aatToolId(RES_C, "c.read")]).toBeDefined();
  });

  it("an explicit delMaxDepth override is honored and drops nothing (back-compat)", async () => {
    // A delegation-free set with an explicit override still carries its tool.
    const freePolicy = {
      policy_version: "t",
      ceiling: [{ type: "mission_resource_access", resource: RES_C, actions: ["c.read"] }] as AuthorityEntry[],
    };
    const kernel = mkKernel(freePolicy);
    const mission = approveTemplate(kernel, [RES_C]);
    const { root, tools } = await deriveAttenuationRoot(kernel, signKey, "as-token", {
      missionId: mission.id,
      aud: RES_C,
      clientId: "agent",
      cnfJkt: "jkt-holder",
      delMaxDepth: 2,
    });
    expect(decodeJwt(root).del_max_depth).toBe(2);
    expect(tools[aatToolId(RES_C, "c.read")]).toBeDefined();
  });
});

// ---------------------------------------------------------------------------
// Wiring: the demo ceiling actually carries delegation (guards against the
// loadPolicy silent-drop making every DERIVATION_POLICY assertion vacuous).
// ---------------------------------------------------------------------------
describe("demo ceiling wiring (@spec attenuation#delegation)", () => {
  it("the payments (read-bearing) entry is delegable; the ledger write entry is not", () => {
    expect(DERIVATION_POLICY.ceiling[0]?.delegation).toBeDefined();
    expect(DERIVATION_POLICY.ceiling[0]?.delegation?.max_depth).toBe(2);
    expect(DERIVATION_POLICY.ceiling[0]?.delegation?.children).toBeDefined();
    expect(DERIVATION_POLICY.ceiling[1]?.delegation).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// (e) intersect FAILS CLOSED on a registered-but-unimplemented Common
// Constraint (@spec mission#common-constraints). Before this fix an
// unrecognized constraint key was silently dropped from the derived entry,
// which WIDENS effective authority (the narrowing it named never applies).
// ---------------------------------------------------------------------------
describe("intersect fails closed on a registered-but-unimplemented Common Constraint", () => {
  it("refuses (never silently widens) when the PROPOSAL carries an unimplemented registered constraint", () => {
    const ceilingEntry = entry();
    const policy = { policy_version: "t", ceiling: [ceilingEntry] };
    const intent: MissionIntent = {
      goal: "g",
      target_resources: [ceilingEntry.resource],
      expires_at: EXP,
    };
    const proposal = [
      entry({
        constraints: { time_window: { not_before: "2026-01-01T00:00:00Z" } } as never,
      }),
    ];
    expect(() => deriveAuthoritySet(intent, policy, proposal)).toThrow(IntentError);
    expect(() => deriveAuthoritySet(intent, policy, proposal)).toThrow(/time_window/);
  });

  it("refuses when the CEILING carries an unimplemented registered constraint (never silently vanishes)", () => {
    const ceilingEntry = entry({
      constraints: { time_window: { not_before: "2026-01-01T00:00:00Z" } } as never,
    });
    const policy = { policy_version: "t", ceiling: [ceilingEntry] };
    const intent: MissionIntent = {
      goal: "g",
      target_resources: [ceilingEntry.resource],
      expires_at: EXP,
    };
    const proposal = [entry()];
    expect(() => deriveAuthoritySet(intent, policy, proposal)).toThrow(/time_window/);
  });

  it("max_amount and vendors (implemented Common/deployment-defined constraints) still narrow normally", () => {
    const ceilingEntry = entry({
      constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
    });
    const policy = { policy_version: "t", ceiling: [ceilingEntry] };
    const intent: MissionIntent = {
      goal: "g",
      target_resources: [ceilingEntry.resource],
      expires_at: EXP,
    };
    const proposal = [
      entry({ constraints: { max_amount: { amount: "100.00", currency: "USD" }, vendors: ["acme"] } }),
    ];
    const derived = deriveAuthoritySet(intent, policy, proposal);
    expect(derived[0]?.constraints?.max_amount?.amount).toBe("100.00");
    expect(derived[0]?.constraints?.vendors).toEqual(["acme"]);
  });
});

// ---------------------------------------------------------------------------
// (f) exact decimal-value comparison for max_amount (@spec mission#max-amount).
// Number.parseFloat compares amounts as IEEE-754 doubles, which can make a
// WIDER candidate compare as equal/narrower once past Number.MAX_SAFE_INTEGER.
// ---------------------------------------------------------------------------
describe("isSubsetEntry compares max_amount by exact decimal value, not IEEE-754 float", () => {
  it("a candidate 1 unit above the granted cap is NOT a subset, even though both amounts round to the same double", () => {
    const granted = entry({ constraints: { max_amount: { amount: "9007199254740992.00", currency: "USD" } } });
    // 9007199254740992 (2^53) and 9007199254740993 are DISTINCT decimal values
    // but Number.parseFloat rounds both to the identical double, so the old
    // float comparison would wrongly treat the candidate as no wider.
    const candidateWider = entry({
      constraints: { max_amount: { amount: "9007199254740993.00", currency: "USD" } },
    });
    expect(Number.parseFloat("9007199254740993.00")).toBe(Number.parseFloat("9007199254740992.00"));
    expect(isSubsetEntry(candidateWider, granted)).toBe(false);

    // An equal amount still passes (unchanged behavior).
    const candidateEqual = entry({
      constraints: { max_amount: { amount: "9007199254740992.00", currency: "USD" } },
    });
    expect(isSubsetEntry(candidateEqual, granted)).toBe(true);
  });

  it("a malformed candidate amount fails closed (not a subset), never silently permitted", () => {
    const granted = entry({ constraints: { max_amount: { amount: "500.00", currency: "USD" } } });
    const malformed = entry({ constraints: { max_amount: { amount: "NaN", currency: "USD" } } });
    expect(isSubsetEntry(malformed, granted)).toBe(false);
  });

  it("a malformed proposed max_amount refuses derivation (IntentError), never silently coerced", () => {
    const ceilingEntry = entry({ constraints: { max_amount: { amount: "500.00", currency: "USD" } } });
    const policy = { policy_version: "t", ceiling: [ceilingEntry] };
    const intent: MissionIntent = {
      goal: "g",
      target_resources: [ceilingEntry.resource],
      expires_at: EXP,
    };
    const proposal = [entry({ constraints: { max_amount: { amount: "1e300", currency: "USD" } } })];
    expect(() => deriveAuthoritySet(intent, policy, proposal)).toThrow(IntentError);
  });
});
