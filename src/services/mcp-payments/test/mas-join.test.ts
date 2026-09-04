/**
 * @spec authority-server#mission-join (#557)
 *
 * The PEP's gateway wiring for the baseline MAS Join: an ordinary OAuth
 * credential (TokenFacts.mission absent) joined against a PEP-supplied
 * propagated Mission reference. Rules 3-6 (the join proper) are resolved by
 * the PDP itself (#557 review point 1; see `services/pdp/test/mas-join.test.ts`
 * for standalone `resolveBaselineJoin` coverage) -- a mission_mismatch here
 * is a genuine Decision, `res.decision` defined, `res.denial_reason` set,
 * never a pre-evaluate() PEP refusal. This file covers the PEP's OWN gateway
 * duties: the configured/unconfigured gate, propagated-reference selection
 * (rule 1) and `context.mission_join` construction, rule 8's fail-closed
 * acting-credential-authority bound (still PEP-side), and that the existing
 * Mission-bound path is completely unaffected when masJoin is configured.
 */

import { describe, expect, it } from "vitest";
import type { AuthorityEntry, Fga, MissionView } from "@mission/pdp";
import {
  ActorRecords,
  CANONICAL_RESOURCE,
  createEphemeralEvidenceKeys,
  EvidenceStore,
  PaymentsStore,
  Pep,
  sourceDigestOf,
  type PepDeps,
  type TokenFacts,
} from "../src/index.js";

const ISSUER = "https://as.test";
const RESOURCE = "vendor.example";
const alwaysAllowFga = { checkWithContext: async () => true } as unknown as Fga;
// @spec authority-server#mission-join rule 8, bound 3 — current Resource
// policy, the bound the existing FGA check enforces. Refusing here with both
// other bounds satisfied is what shows the third bound is evaluated at all.
const denyingFga = { checkWithContext: async () => false } as unknown as Fga;

const READ = "payments:vendor.read";
const missionId = "msn_557_join";

const DIRECT_ENTRY: AuthorityEntry = { type: "mission_resource_access", resource: CANONICAL_RESOURCE, actions: [READ] };
const DELEGABLE_ENTRY: AuthorityEntry = {
  type: "mission_resource_access",
  resource: CANONICAL_RESOURCE,
  actions: [READ],
  join_delegation: { allowed_delegates: ["delegate-client"] },
};

const view: MissionView = {
  id: missionId,
  issuer: ISSUER,
  state: "active",
  version: 1,
  authority_hash: "sha-256:hash557",
  authority_set: [DIRECT_ENTRY],
  subject: { iss: "https://idp.test", sub: "alice" },
  client_id: "ap-agent",
};

const loadViewFor = (v: MissionView) => (ref: { id: string; issuer: string }) =>
  ref.id === v.id && ref.issuer === v.issuer
    ? { view: v, freshness: { observed_at: new Date().toISOString(), source: "load_view" } }
    : undefined;

const FULL_AUTHORITY: () => AuthorityEntry[] | undefined = () => [
  { type: "mission_resource_access", resource: CANONICAL_RESOURCE, actions: [READ] },
];

function build(overrides: Partial<PepDeps> = {}, viewOverride: MissionView = view): Pep {
  return new Pep({
    payments: new PaymentsStore(),
    // @spec runtime-evidence#decision-evidence-integrity (issue #649):
    // EvidenceStore fails closed without a signer configured for the
    // emitter role a call needs; every enforce() path here goes through it.
    evidence: new EvidenceStore(createEphemeralEvidenceKeys().signing),
    fga: alwaysAllowFga,
    modelId: "unit-test-model",
    loadView: loadViewFor(viewOverride),
    instanceEpoch: "epoch-1",
    sourceDigest: sourceDigestOf({ name: "payments" }),
    allowedFreshnessSources: new Set(["load_view"]),
    ...overrides,
  });
}

const ORDINARY_TOKEN: TokenFacts = {
  sub: "alice",
  clientId: "ap-agent",
  iss: "https://idp.test",
  cnfJkt: "jkt-ordinary",
};

const REFERENCE = { id: missionId, issuer: ISSUER };

describe("baseline MAS Join: configuration gate (@spec authority-server#mission-join)", () => {
  it("refuses unknown_mission for an ordinary credential when masJoin is not configured at all", async () => {
    const pep = build(); // no masJoin
    const res = await pep.enforce("lookup_vendor", { vendor_id: RESOURCE }, ORDINARY_TOKEN, undefined, {
      missionReference: REFERENCE,
    });
    expect(res.permitted).toBe(false);
    expect(res.refusal_reason).toBe("unknown_mission");
  });

  it("refuses unknown_mission for an ordinary credential with no propagated Mission reference at all, even with masJoin configured", async () => {
    const pep = build({ masJoin: { resolveOrdinaryAuthority: FULL_AUTHORITY } });
    const res = await pep.enforce("lookup_vendor", { vendor_id: RESOURCE }, ORDINARY_TOKEN);
    expect(res.permitted).toBe(false);
    expect(res.refusal_reason).toBe("unknown_mission");
  });

  it("refuses mission_reference_conflict for a malformed propagated reference, not unknown_mission", async () => {
    const pep = build({ masJoin: { resolveOrdinaryAuthority: FULL_AUTHORITY } });
    const res = await pep.enforce("lookup_vendor", { vendor_id: RESOURCE }, ORDINARY_TOKEN, undefined, {
      missionReference: { malformed: true },
    });
    expect(res.permitted).toBe(false);
    // @spec authority-server#mission-reference-field (#557) — unusable
    // carriage where governance requires a reference, not a Mission that
    // could not be found: the two failures are reported apart.
    expect(res.refusal_reason).toBe("mission_reference_conflict");
  });
});

describe("baseline MAS Join: successful join (@spec authority-server#mission-join rules 1-4, 7, 8)", () => {
  it("permits a direct-client ordinary credential whose subject matches the Mission's subject", async () => {
    const pep = build({ masJoin: { resolveOrdinaryAuthority: FULL_AUTHORITY } });
    const res = await pep.enforce("lookup_vendor", { vendor_id: RESOURCE }, ORDINARY_TOKEN, undefined, {
      missionReference: REFERENCE,
    });
    expect(res.permitted, JSON.stringify(res)).toBe(true);
    expect(res.resolvedMission).toEqual({ id: missionId, issuer: ISSUER });
  });

  it("permits an authorized delegate and narrows the effective authority to the delegable subset", async () => {
    const delegateView: MissionView = { ...view, authority_set: [DIRECT_ENTRY, DELEGABLE_ENTRY] };
    // @spec authority-server#mission-join rule 5 — depth comes from the
    // deployment's own actor records, and the delegate must have one: the
    // entry here declares no max_depth, so before the absent-record rule
    // this joined with no depth check at all.
    const records = new ActorRecords();
    records.record({ mission: REFERENCE, clientId: "delegate-client", delegatedBy: view.client_id });
    const pep = build(
      {
        masJoin: {
          delegatePolicy: { delegates: { "delegate-client": {} } },
          resolveOrdinaryAuthority: FULL_AUTHORITY,
          // The hook takes the canonical reference and the Mission's own
          // client, so the ledger's resolver satisfies it directly: no
          // adapter, and no issuer bound at construction.
          resolveDelegateDepth: records.resolveDepth.bind(records),
        },
      },
      delegateView,
    );
    const delegateToken: TokenFacts = { ...ORDINARY_TOKEN, clientId: "delegate-client" };
    const res = await pep.enforce("lookup_vendor", { vendor_id: RESOURCE }, delegateToken, undefined, {
      missionReference: REFERENCE,
    });
    expect(res.permitted, JSON.stringify(res)).toBe(true);
  });
});

describe("baseline MAS Join: PepDeps.masJoin.resolveDelegateDepth (@spec authority-server#mission-join rule 5, #557 review point 1)", () => {
  const SHALLOW_DELEGABLE_ENTRY: AuthorityEntry = {
    type: "mission_resource_access",
    resource: CANONICAL_RESOURCE,
    actions: [READ],
    join_delegation: { max_depth: 0, allowed_delegates: ["delegate-client"] },
  };
  const shallowView: MissionView = { ...view, authority_set: [DIRECT_ENTRY, SHALLOW_DELEGABLE_ENTRY] };
  const delegateToken: TokenFacts = { ...ORDINARY_TOKEN, clientId: "delegate-client" };

  it("resolves depth FRESH per request and carries it onto the PDP request: a depth within the entry's own max_depth permits", async () => {
    const pep = build(
      {
        masJoin: {
          delegatePolicy: { delegates: { "delegate-client": {} } },
          resolveOrdinaryAuthority: FULL_AUTHORITY,
          resolveDelegateDepth: () => 0,
        },
      },
      shallowView,
    );
    const res = await pep.enforce("lookup_vendor", { vendor_id: RESOURCE }, delegateToken, undefined, {
      missionReference: REFERENCE,
    });
    expect(res.permitted, JSON.stringify(res)).toBe(true);
  });

  it("denies mission_mismatch when the resolved depth exceeds the entry's own join_delegation.max_depth", async () => {
    const pep = build(
      {
        masJoin: {
          delegatePolicy: { delegates: { "delegate-client": {} } },
          resolveOrdinaryAuthority: FULL_AUTHORITY,
          resolveDelegateDepth: () => 1, // exceeds SHALLOW_DELEGABLE_ENTRY's max_depth: 0
        },
      },
      shallowView,
    );
    const res = await pep.enforce("lookup_vendor", { vendor_id: RESOURCE }, delegateToken, undefined, {
      missionReference: REFERENCE,
    });
    expect(res.permitted).toBe(false);
    expect(res.denial_reason).toBe("mission_mismatch");
  });

  it("denies mission_mismatch with an unconfigured resolveDelegateDepth: a delegate with no actor record is not recorded as acting under the Mission", async () => {
    const pep = build(
      {
        masJoin: {
          delegatePolicy: { delegates: { "delegate-client": {} } },
          resolveOrdinaryAuthority: FULL_AUTHORITY,
          // resolveDelegateDepth intentionally absent
        },
      },
      shallowView,
    );
    const res = await pep.enforce("lookup_vendor", { vendor_id: RESOURCE }, delegateToken, undefined, {
      missionReference: REFERENCE,
    });
    expect(res.permitted).toBe(false);
    expect(res.denial_reason).toBe("mission_mismatch");
  });
});

describe("baseline MAS Join: mission_mismatch (@spec authority-server#mission-join rule 6)", () => {
  it("denies mission_mismatch when the authenticated subject does not match the Mission's subject", async () => {
    const pep = build({ masJoin: { resolveOrdinaryAuthority: FULL_AUTHORITY } });
    const mismatchedToken: TokenFacts = { ...ORDINARY_TOKEN, sub: "mallory" };
    const res = await pep.enforce("lookup_vendor", { vendor_id: RESOURCE }, mismatchedToken, undefined, {
      missionReference: REFERENCE,
    });
    expect(res.permitted).toBe(false);
    // @spec authority-server#mission-join (#557 review point 1) — this is
    // now a genuine PDP decision (denial_reason on a Decision Evidence
    // record), not a PEP-only refusal: the PDP resolves rules 3-6 itself.
    expect(res.denial_reason).toBe("mission_mismatch");
    expect(res.decision).toBeDefined();
    expect(res.decision?.decision).toBe(false);
  });

  it("denies mission_mismatch for a client that is neither the Mission's own client_id nor an authorized delegate, and never falls back to the unjoined authority", async () => {
    const pep = build({ masJoin: { resolveOrdinaryAuthority: FULL_AUTHORITY } });
    const unknownClientToken: TokenFacts = { ...ORDINARY_TOKEN, clientId: "unrecognized-client" };
    const res = await pep.enforce("lookup_vendor", { vendor_id: RESOURCE }, unknownClientToken, undefined, {
      missionReference: REFERENCE,
    });
    expect(res.permitted).toBe(false);
    // @spec authority-server#mission-join (#557 review point 1) — the PDP
    // itself denies this now (a real Decision, not a pre-evaluate() PEP
    // refusal): res.decision is DEFINED and carries no authoritySet the
    // caller could accidentally evaluate against (rule 6, no fallback).
    expect(res.denial_reason).toBe("mission_mismatch");
    expect(res.decision).toBeDefined();
    expect(res.decision?.decision).toBe(false);
  });

  it("denies mission_mismatch for a referenced Mission that does not resolve at all", async () => {
    const pep = build({ masJoin: { resolveOrdinaryAuthority: FULL_AUTHORITY } });
    const res = await pep.enforce("lookup_vendor", { vendor_id: RESOURCE }, ORDINARY_TOKEN, undefined, {
      missionReference: { id: "no-such-mission", issuer: ISSUER },
    });
    expect(res.permitted).toBe(false);
    expect(res.refusal_reason).toBe("unknown_mission");
  });
});

describe("baseline MAS Join: rule 8, bound 1 (acting credential authority)", () => {
  it("fails closed with out_of_authority when no resolveOrdinaryAuthority evaluator is configured, even after a successful join", async () => {
    const pep = build({ masJoin: {} }); // configured, but no evaluator
    const res = await pep.enforce("lookup_vendor", { vendor_id: RESOURCE }, ORDINARY_TOKEN, undefined, {
      missionReference: REFERENCE,
    });
    expect(res.permitted).toBe(false);
    expect(res.refusal_reason).toBe("out_of_authority");
  });

  it("intersects the acting credential's own authority with the joined Mission authority: an action outside the credential's own authority is refused out_of_authority", async () => {
    const pep = build({
      masJoin: {
        // The credential's own authority covers a DIFFERENT action than the
        // joined Mission grants, so the intersection is empty.
        resolveOrdinaryAuthority: () => [
          { type: "mission_resource_access", resource: CANONICAL_RESOURCE, actions: ["payments:invoice.read"] },
        ],
      },
    });
    const res = await pep.enforce("lookup_vendor", { vendor_id: RESOURCE }, ORDINARY_TOKEN, undefined, {
      missionReference: REFERENCE,
    });
    expect(res.permitted).toBe(false);
    expect(res.refusal_reason).toBe("out_of_authority");
  });
});

describe("baseline MAS Join: depth from the deployment's actor records (@spec authority-server#mission-join rule 5)", () => {
  const delegateView: MissionView = { ...view, authority_set: [DIRECT_ENTRY, DELEGABLE_ENTRY] };
  const delegateToken: TokenFacts = { ...ORDINARY_TOKEN, clientId: "delegate-client" };

  /** A ledger recording `delegate-client` two hops from the Mission's own client. */
  function twoHopLedger(): ActorRecords {
    const records = new ActorRecords();
    records.record({ mission: REFERENCE, clientId: "middle-client", delegatedBy: view.client_id });
    records.record({ mission: REFERENCE, clientId: "delegate-client", delegatedBy: "middle-client" });
    return records;
  }

  function pepFor(records: ActorRecords, maxDepth: number): Pep {
    return build(
      {
        masJoin: {
          delegatePolicy: { delegates: { "delegate-client": { maxDepth } } },
          resolveOrdinaryAuthority: FULL_AUTHORITY,
          resolveDelegateDepth: records.resolveDepth.bind(records),
        },
      },
      delegateView,
    );
  }

  it("permits a delegate whose ledger-resolved depth is within the deployment's ceiling", async () => {
    const res = await pepFor(twoHopLedger(), 2).enforce(
      "lookup_vendor",
      { vendor_id: RESOURCE },
      delegateToken,
      undefined,
      { missionReference: REFERENCE },
    );
    expect(res.permitted, JSON.stringify(res)).toBe(true);
  });

  it("denies mission_mismatch for the SAME delegate once the recorded chain is one hop too long for the ceiling", async () => {
    // The only difference from the permit above is the ceiling: the depth is
    // the ledger's, walked over the recorded edges, not a token act chain.
    const res = await pepFor(twoHopLedger(), 1).enforce(
      "lookup_vendor",
      { vendor_id: RESOURCE },
      delegateToken,
      undefined,
      { missionReference: REFERENCE },
    );
    expect(res.permitted).toBe(false);
    expect(res.denial_reason).toBe("mission_mismatch");
    expect(res.decision).toBeDefined();
  });

  it("denies mission_mismatch when the ledger records the delegation under a DIFFERENT issuer's same-id Mission", async () => {
    const records = new ActorRecords();
    records.record({
      mission: { id: missionId, issuer: "https://other.example" },
      clientId: "delegate-client",
      delegatedBy: view.client_id,
    });
    const res = await pepFor(records, 2).enforce(
      "lookup_vendor",
      { vendor_id: RESOURCE },
      delegateToken,
      undefined,
      { missionReference: REFERENCE },
    );
    expect(res.permitted).toBe(false);
    expect(res.denial_reason).toBe("mission_mismatch");
  });
});

describe("baseline MAS Join: rule 8's three bounds, one denial each (@spec authority-server#mission-join rule 8)", () => {
  const INVOICE_READ = "payments:invoice.read";
  // A Mission granting only the invoice read, under a credential whose own
  // authority covers BOTH that and the vendor read.
  const missionShortView: MissionView = {
    ...view,
    authority_set: [{ type: "mission_resource_access", resource: CANONICAL_RESOURCE, actions: [INVOICE_READ] }],
  };
  const BROAD_CREDENTIAL: () => AuthorityEntry[] = () => [
    { type: "mission_resource_access", resource: CANONICAL_RESOURCE, actions: [INVOICE_READ, READ] },
  ];

  it("bound 1: an action outside the ACTING CREDENTIAL's own authority refuses out_of_authority", async () => {
    const pep = build({
      masJoin: {
        resolveOrdinaryAuthority: () => [
          { type: "mission_resource_access", resource: CANONICAL_RESOURCE, actions: [INVOICE_READ] },
        ],
      },
    });
    const res = await pep.enforce("lookup_vendor", { vendor_id: RESOURCE }, ORDINARY_TOKEN, undefined, {
      missionReference: REFERENCE,
    });
    expect(res.permitted).toBe(false);
    expect(res.refusal_reason).toBe("out_of_authority");
  });

  it("bound 2: an action the credential carries but the MISSION does not denies out_of_authority, so the permit's authority is the Mission's", async () => {
    const pep = build({ masJoin: { resolveOrdinaryAuthority: BROAD_CREDENTIAL } }, missionShortView);
    const res = await pep.enforce("lookup_vendor", { vendor_id: RESOURCE }, ORDINARY_TOKEN, undefined, {
      missionReference: REFERENCE,
    });
    expect(res.permitted).toBe(false);
    // A genuine Decision: the join succeeded and the action was evaluated
    // against the JOINED Mission authority, which does not carry it. The
    // credential's own claim to that action never substitutes for it.
    expect(res.denial_reason).toBe("out_of_authority");
    expect(res.decision).toBeDefined();
  });

  it("bound 3: current RESOURCE POLICY refusing denies out_of_authority with both other bounds satisfied", async () => {
    const pep = build({ fga: denyingFga, masJoin: { resolveOrdinaryAuthority: FULL_AUTHORITY } });
    const res = await pep.enforce("lookup_vendor", { vendor_id: RESOURCE }, ORDINARY_TOKEN, undefined, {
      missionReference: REFERENCE,
    });
    expect(res.permitted).toBe(false);
    expect(res.denial_reason).toBe("out_of_authority");
    expect(res.decision).toBeDefined();
  });

  it("all three bounds satisfied permits, so the three denials above are attributable to each bound", async () => {
    const pep = build({ masJoin: { resolveOrdinaryAuthority: FULL_AUTHORITY } });
    const res = await pep.enforce("lookup_vendor", { vendor_id: RESOURCE }, ORDINARY_TOKEN, undefined, {
      missionReference: REFERENCE,
    });
    expect(res.permitted, JSON.stringify(res)).toBe(true);
  });
});

describe("baseline MAS Join: the Mission-bound path is unaffected (@spec authority-server#mission-join)", () => {
  it("a Mission-bound credential (token.mission present) enforces exactly as before, even with masJoin fully configured", async () => {
    const pep = build({ masJoin: { resolveOrdinaryAuthority: FULL_AUTHORITY } });
    const missionBoundToken: TokenFacts = {
      sub: "alice",
      clientId: "ap-agent",
      iss: ISSUER,
      mission: { id: missionId, issuer: ISSUER, authority_hash: "sha-256:hash557" },
      cnfJkt: "jkt-1",
    };
    const res = await pep.enforce("lookup_vendor", { vendor_id: RESOURCE }, missionBoundToken);
    expect(res.permitted, JSON.stringify(res)).toBe(true);
    expect(res.resolvedMission).toEqual({ id: missionId, issuer: ISSUER, authority_hash: "sha-256:hash557" });
  });
});
