/**
 * @spec resource-access#common-constraints, resource-access#rs-enforcement (#1375)
 *
 * Entry-level fail-closed at the point of use: an applicable entry whose
 * constraint cannot be evaluated or satisfied, including one whose predicate
 * needs a fact the enforcement point did not establish, provides no authority.
 * Another applicable entry then authorizes the request only on its own, with
 * every constraint satisfied; without one, the request is refused; parts of
 * entries are never combined.
 *
 * Helper level, through `coveringCredentialEntries` (the call the payments PEP
 * makes, mcp-payments pep.ts) and `credentialAuthorityPermits`, over the
 * `ConstraintFacts` the enforcement point establishes for itself.
 */

import { describe, expect, it } from "vitest";
import {
  type CredentialFacts,
  type CredentialTarget,
  coveringCredentialEntries,
  credentialAuthorityPermits,
  parseCredentialAuthority,
} from "../src/index.js";

const R = "https://payments.example/mcp";
const READ = "payments:invoice.read";
const PAY = "payments:payment.execute";

const entry = (constraints?: Record<string, unknown>, actions: string[] = [READ]) => ({
  type: "mission_resource_access",
  resource: R,
  actions,
  ...(constraints ? { constraints } : {}),
});

/** The facts an enforcement point established; anything omitted is absent. */
const facts = (over: Partial<CredentialFacts> = {}): CredentialFacts => ({
  resource: R,
  action: READ,
  vendorIds: [],
  constraintFacts: {},
  ...over,
});
const target = (over: Partial<CredentialFacts> = {}): CredentialTarget => ({
  ...facts(over),
  approvalEnforced: false,
});

const TENANT = { tenant: "acme-tenant" };
const ISSUED_AFTER = { resource_issued_after: "2026-07-01T00:00:00Z" };
const CAP = { max_amount: { amount: "500.00", currency: "USD" } };

describe("an entry whose constraint cannot be satisfied provides no authority (@spec resource-access#common-constraints)", () => {
  it("an absent amount: an entry bounded by max_amount covers nothing", () => {
    const auth = parseCredentialAuthority([entry(CAP, [PAY])]);
    expect(coveringCredentialEntries(auth, facts({ action: PAY }))).toEqual([]);
    expect(credentialAuthorityPermits(auth, target({ action: PAY }))).toBe(false);
    // Positive control: the same entry covers the action once the amount is established.
    const paid = facts({ action: PAY, amount: { amount: "500.00", currency: "USD" } });
    expect(coveringCredentialEntries(auth, paid)).toHaveLength(1);
  });

  it("an absent tenant: an entry bounded by tenant covers nothing", () => {
    const auth = parseCredentialAuthority([entry(TENANT)]);
    expect(coveringCredentialEntries(auth, facts())).toEqual([]);
    expect(credentialAuthorityPermits(auth, target())).toBe(false);
    expect(
      coveringCredentialEntries(auth, facts({ constraintFacts: { tenant: "acme-tenant" } })),
    ).toHaveLength(1);
  });

  it("an absent issuance instant: an entry bounded by resource_issued_after covers nothing", () => {
    const auth = parseCredentialAuthority([entry(ISSUED_AFTER)]);
    expect(coveringCredentialEntries(auth, facts())).toEqual([]);
    expect(credentialAuthorityPermits(auth, target())).toBe(false);
    const issued = facts({ constraintFacts: { resourceIssuedAt: "2026-08-15T09:30:00Z" } });
    expect(coveringCredentialEntries(auth, issued)).toHaveLength(1);
  });
});

describe("another applicable entry authorizes only on its own (@spec resource-access#common-constraints, resource-access#rs-enforcement)", () => {
  it("an independently sufficient alternative entry authorizes the request beside one whose fact is absent", () => {
    const bounded = entry(TENANT);
    const open = entry();
    const auth = parseCredentialAuthority([bounded, open]);
    expect(coveringCredentialEntries(auth, facts())).toEqual(parseCredentialAuthority([open]));
    expect(credentialAuthorityPermits(auth, target())).toBe(true);
  });

  it("without such an alternative the request is refused: two entries each missing a fact authorize nothing", () => {
    const auth = parseCredentialAuthority([entry(TENANT), entry(ISSUED_AFTER)]);
    expect(coveringCredentialEntries(auth, facts())).toEqual([]);
    expect(credentialAuthorityPermits(auth, target())).toBe(false);
  });

  it("never combines fragments of entries: an action from one entry and another entry's satisfied constraints authorize nothing", () => {
    // The read entry names the action but its tenant is not established; the
    // other entry has no unsatisfied constraint but does not name the action.
    const action = parseCredentialAuthority([entry(TENANT, [READ]), entry(undefined, [PAY])]);
    expect(coveringCredentialEntries(action, facts())).toEqual([]);
    expect(credentialAuthorityPermits(action, target())).toBe(false);
    // One entry satisfies the tenant, the other the amount; neither satisfies both.
    const halves = parseCredentialAuthority([
      entry({ tenant: "acme-tenant", max_amount: { amount: "500.00", currency: "USD" } }, [PAY]),
      entry({ tenant: "other-tenant", max_amount: { amount: "1000.00", currency: "USD" } }, [PAY]),
    ]);
    const request = facts({
      action: PAY,
      amount: { amount: "700.00", currency: "USD" },
      constraintFacts: { tenant: "acme-tenant" },
    });
    expect(coveringCredentialEntries(halves, request)).toEqual([]);
    expect(credentialAuthorityPermits(halves, { ...request, approvalEnforced: false })).toBe(false);
  });
});
