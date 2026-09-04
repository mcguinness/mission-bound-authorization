/**
 * @spec issuance-grant#effective-set-projection, containment#derivation-gating
 * (#617 review 2) — the Effective Authority Set projection's SEMANTICS.
 *
 * projectThroughEffective is entry-wise INTERSECTION, and the property that
 * defines it is checked on every case here: the result is a subset of the
 * candidate AND a subset of the effective set (isSubsetSet both ways). The
 * prior implementation matched only the FIRST effective entry per resource and
 * carried the candidate's constraints through unchanged, which held only while
 * containment (remove shape `{resource, actions}`) was the sole narrowing
 * mechanism and broke for any mechanism that narrows a constraint VALUE: a
 * discharged entry capped at 1000 projected through a surviving entry capped at
 * 100 kept 1000.
 *
 * gateDerivation's empty-effective-set refusal is also asserted BY CAUSE here:
 * authority_contained only where containment causally removed the authority,
 * authority_exhausted otherwise.
 */

import { generateKeyPair } from "jose";
import { beforeAll, describe, expect, it } from "vitest";
import {
  type AuthorityEntry,
  GateError,
  isSubsetSet,
  MissionKernel,
  projectThroughEffective,
  validateMissionIntent,
} from "../src/index.js";
import { testAuthoritySourceCatalog } from "./authority-source.helper.js";

const ISS = "https://as.projection.test";
const RES = "https://payments.test/mcp";
const NOW = new Date("2026-08-06T12:00:00Z");
const EXPIRES_AT = "2027-01-01T00:00:00Z";
const READ = "payments:invoice.read";
const PAY = "payments:payment.execute";

const usd = (amount: string) => ({ amount, currency: "USD" });

const entry = (over: Partial<AuthorityEntry> = {}): AuthorityEntry => ({
  type: "mission_resource_access",
  resource: RES,
  actions: [READ],
  ...over,
});

/**
 * The defining property of the projection, asserted on EVERY case: the
 * projected remainder is authority BOTH sides still allow.
 */
function expectSubsetOfBoth(
  result: AuthorityEntry[],
  candidate: AuthorityEntry[],
  effective: AuthorityEntry[],
): void {
  expect(isSubsetSet(result, candidate), "result must be a subset of the candidate").toBe(true);
  expect(isSubsetSet(result, effective), "result must be a subset of the effective set").toBe(true);
}

/** Project and assert the subset property in one step. */
function project(candidate: AuthorityEntry[], effective: AuthorityEntry[]): AuthorityEntry[] {
  const result = projectThroughEffective(candidate, effective);
  expectSubsetOfBoth(result, candidate, effective);
  return result;
}

describe("projectThroughEffective: entry-wise intersection (@spec issuance-grant#effective-set-projection)", () => {
  it("intersects max_amount to the SMALLER value: a candidate capped at 1000 through a survivor capped at 100 yields 100", () => {
    const candidate = [entry({ actions: [PAY], constraints: { max_amount: usd("1000.00") } })];
    const effective = [entry({ actions: [PAY], constraints: { max_amount: usd("100.00") } })];
    const result = project(candidate, effective);
    expect(result).toEqual([entry({ actions: [PAY], constraints: { max_amount: usd("100.00") } })]);
  });

  it("keeps the candidate's cap when it is already the smaller one", () => {
    const candidate = [entry({ actions: [PAY], constraints: { max_amount: usd("50.00") } })];
    const effective = [entry({ actions: [PAY], constraints: { max_amount: usd("100.00") } })];
    expect(project(candidate, effective)[0]?.constraints?.max_amount).toEqual(usd("50.00"));
  });

  it("INHERITS a cap the effective side alone carries (the candidate was unbounded by it)", () => {
    const candidate = [entry({ actions: [PAY] })];
    const effective = [entry({ actions: [PAY], constraints: { max_amount: usd("100.00") } })];
    expect(project(candidate, effective)[0]?.constraints?.max_amount).toEqual(usd("100.00"));
  });

  it("pairs a candidate entry against EVERY effective entry sharing the resource, not just the first", () => {
    const candidate = [entry({ actions: [PAY], constraints: { max_amount: usd("1000.00") } })];
    // Two effective entries for the same resource/action with divergent caps:
    // the FIRST-match implementation returned only the first (and unnarrowed).
    const effective = [
      entry({ actions: [PAY], constraints: { max_amount: usd("100.00") } }),
      entry({ actions: [PAY], constraints: { max_amount: usd("250.00") } }),
    ];
    const result = project(candidate, effective);
    expect(result).toHaveLength(2);
    expect(result.map((e) => e.constraints?.max_amount?.amount)).toEqual(["100.00", "250.00"]);
  });

  it("de-duplicates identical fragments (two identical effective entries yield one)", () => {
    const candidate = [entry({ actions: [READ, PAY] })];
    const effective = [entry({ actions: [READ] }), entry({ actions: [READ] })];
    expect(project(candidate, effective)).toEqual([entry({ actions: [READ] })]);
  });

  it("intersects vendors, and drops the fragment when no vendor is permitted by both", () => {
    const candidate = [entry({ constraints: { vendors: ["acme", "globex"] } })];
    const overlap = [entry({ constraints: { vendors: ["globex", "initech"] } })];
    expect(project(candidate, overlap)[0]?.constraints?.vendors).toEqual(["globex"]);

    const disjoint = [entry({ constraints: { vendors: ["initech"] } })];
    expect(project(candidate, disjoint)).toEqual([]);
  });

  it("inherits a vendor restriction the effective side alone carries", () => {
    const candidate = [entry()];
    const effective = [entry({ constraints: { vendors: ["acme"] } })];
    expect(project(candidate, effective)[0]?.constraints?.vendors).toEqual(["acme"]);
  });

  it("ORs requires_action_approval: true on either side rides through", () => {
    const candidate = [entry()];
    const effective = [entry({ constraints: { requires_action_approval: true } })];
    expect(project(candidate, effective)[0]?.constraints?.requires_action_approval).toBe(true);
    // And the reverse direction, where only the candidate carries it.
    const reversed = project([entry({ constraints: { requires_action_approval: true } })], [entry()]);
    expect(reversed[0]?.constraints?.requires_action_approval).toBe(true);
  });

  it("drops the fragment for a constraint key this projection cannot intersect, on EITHER side", () => {
    const unprojectable = { time_window: { not_before: "2026-01-01T00:00:00Z" } } as never;
    expect(project([entry()], [entry({ constraints: unprojectable })])).toEqual([]);
    expect(project([entry({ constraints: unprojectable })], [entry()])).toEqual([]);
  });

  it("drops the fragment on mismatched currencies or a malformed amount, never throwing", () => {
    const candidate = [entry({ actions: [PAY], constraints: { max_amount: usd("100.00") } })];
    const eur = [entry({ actions: [PAY], constraints: { max_amount: { amount: "100.00", currency: "EUR" } } })];
    expect(project(candidate, eur)).toEqual([]);
    const malformed = [entry({ actions: [PAY], constraints: { max_amount: usd("not-a-number") } })];
    expect(project(candidate, malformed)).toEqual([]);
    expect(project(malformed, candidate)).toEqual([]);
  });

  it("carries delegation only where BOTH sides grant it, then narrows max_depth and allowed_delegates", () => {
    const bothSides = project(
      [entry({ delegation: { max_depth: 3, allowed_delegates: [{ sub: "a" }, { sub: "b" }] } })],
      [entry({ delegation: { max_depth: 1, allowed_delegates: [{ sub: "b" }, { sub: "c" }] } })],
    );
    expect(bothSides[0]?.delegation).toEqual({ max_depth: 1, allowed_delegates: [{ sub: "b" }] });

    // Candidate delegable, effective side not: the fragment is NOT delegable
    // (a grant the effective set no longer carries cannot ride through), and
    // omitting it keeps the fragment a subset of the candidate too.
    const onlyCandidate = project([entry({ delegation: { max_depth: 3 } })], [entry()]);
    expect(onlyCandidate[0]?.delegation).toBeUndefined();

    // Effective side delegable, candidate not: never INTRODUCED.
    const onlyEffective = project([entry()], [entry({ delegation: { max_depth: 3 } })]);
    expect(onlyEffective[0]?.delegation).toBeUndefined();
  });

  it("narrows the nested children grant, and drops delegation carrying a member it cannot evaluate", () => {
    const narrowed = project(
      [entry({ delegation: { max_depth: 2, children: { max_children: 5, max_child_depth: 2 } } })],
      [entry({ delegation: { max_depth: 2, children: { max_children: 1, max_child_depth: 3 } } })],
    );
    expect(narrowed[0]?.delegation).toEqual({
      max_depth: 2,
      children: { max_children: 1, max_child_depth: 2 },
    });

    const unknownMember = project(
      [entry({ delegation: { max_depth: 2 } })],
      [entry({ delegation: { max_depth: 2, future_policy: "tbd" } })],
    );
    expect(unknownMember[0]).toBeDefined();
    expect(unknownMember[0]?.delegation).toBeUndefined();
  });

  it("regression (the containment shape): narrows actions and leaves the rest of the entry alone", () => {
    const candidate = [
      entry({ actions: [READ, PAY], constraints: { max_amount: usd("500.00"), vendors: ["acme"] } }),
    ];
    // Containment's remove shape is `{resource, actions}` only, so the
    // effective entry differs from the candidate ONLY in its actions.
    const effective = [
      entry({ actions: [READ], constraints: { max_amount: usd("500.00"), vendors: ["acme"] } }),
    ];
    expect(project(candidate, effective)).toEqual(effective);
  });

  it("drops an entry whose resource or type is absent from the effective set", () => {
    expect(project([entry()], [entry({ resource: "https://other.test/mcp" })])).toEqual([]);
    expect(project([entry()], [])).toEqual([]);
    expect(project([], [entry()])).toEqual([]);
  });
});

describe("gateDerivation refuses an empty effective set BY CAUSE (@spec issuance-grant#effective-set-projection)", () => {
  let statusKey: CryptoKey;

  beforeAll(async () => {
    statusKey = (await generateKeyPair("ES256", { extractable: true })).privateKey;
  });

  const makeKernel = (): MissionKernel =>
    new MissionKernel({
      issuer: ISS,
      policy: {
        policy_version: "projection-v1",
        ceiling: [{ type: "mission_resource_access", resource: RES, actions: [READ, PAY] }],
      } as never,
      authoritySourceCatalog: testAuthoritySourceCatalog([{ type: "mission_resource_access", resource: RES, actions: [READ, PAY] }], ["ap-agent"], ["bob"]),
      statusKey,
      statusKid: "as-status",
      now: () => NOW,
    });

  const approve = (kernel: MissionKernel, eventId: string) =>
    kernel.approve({
      intent: validateMissionIntent(
        JSON.stringify({ goal: "Pay Acme invoices", target_resources: [RES], expires_at: EXPIRES_AT }),
      ),
      subject: { iss: ISS, sub: "alice" },
      approver: { iss: ISS, sub: "bob" },
      clientId: "ap-agent",
      approvalEventId: eventId,
    });

  const reasonOf = (fn: () => unknown): string => {
    try {
      fn();
      expect.unreachable("gateDerivation must refuse");
    } catch (e) {
      expect(e).toBeInstanceOf(GateError);
      return (e as GateError).reason;
    }
    return "unreachable";
  };

  it("authority_contained where containment CAUSALLY emptied the set", () => {
    const kernel = makeKernel();
    const m = approve(kernel, "evt-contained");
    kernel.contain(m.id, {
      event: {
        type: "anomaly.detected",
        source: "svc:soc",
        observed_at: NOW.toISOString(),
        event_id: "evt-contain-all",
      },
      remove: [{ resource: RES }],
    });
    expect(kernel.effectiveAuthoritySet(kernel.get(m.id) as never)).toEqual([]);
    // The no-overlay set is NON-empty (the approved set survives untouched), so
    // containment is what removed the authority: the Containment denial reason
    // may be attributed here, and only here.
    expect(kernel.get(m.id)?.authority_set.length).toBeGreaterThan(0);
    expect(reasonOf(() => kernel.gateDerivation(m.id))).toBe("authority_contained");
  });

  it("authority_exhausted where the set is empty with the containment overlay removed", () => {
    const kernel = makeKernel();
    const m = approve(kernel, "evt-exhausted");
    // Synthesize the state no CURRENT mechanism produces: an approved set that
    // is itself empty. Containment is the only overlay effectiveAuthoritySet
    // composes today, so this is the only way to reach the exhausted branch
    // from outside; the branch exists for the next mechanism (discharge), which
    // will not live in `containment`.
    kernel.db.prepare("UPDATE missions SET authority_set_json = ? WHERE id = ?").run("[]", m.id);
    expect(kernel.effectiveAuthoritySet(kernel.get(m.id) as never)).toEqual([]);
    expect(reasonOf(() => kernel.gateDerivation(m.id))).toBe("authority_exhausted");
  });
});
