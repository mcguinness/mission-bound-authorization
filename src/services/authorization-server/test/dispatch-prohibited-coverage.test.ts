/**
 * @spec draft-mcguinness-oauth-mission-template (#prohibited-classes) (#813, #1710, D877)
 *
 * "The deployment's configured dispatch-prohibited action set MUST cover
 * every action the published mapping classifies as irreversible,
 * external-commitment, or privileged-administration, as satisfying the
 * runtime profile's external-communication predicate, or as cross-domain."
 * The coverage check, and the shipped configuration it holds for: a unit
 * check that fails loudly when `config/policy.json`'s
 * `dispatch_prohibited_actions` leaves out an action the published mapping
 * places under any of the five predicates. The published mapping is read from
 * configuration alone: `config/approval-floor.json`'s classification (each
 * action's class, and each resource's `cross_domain`) and
 * `config/progressive.json`'s external-communication actions.
 */
import { APPROVAL_FLOOR, DISPATCH_PROHIBITED_ACTIONS, PROGRESSIVE_PROFILE } from "@mission/demo-data";
import { describe, expect, it } from "vitest";
import {
  ALL_PROHIBITED_PREDICATES,
  type AuthorityEntry,
  assertDispatchProhibitedCoverage,
  DispatchProhibitedCoverageError,
  dispatchProhibitedCoverageGaps,
  type ProhibitedPredicate,
  prohibitedPredicatesOf,
  publishedProhibitedPredicateMapping,
} from "../src/index.js";

const PAYMENTS = "http://localhost:4403/mcp";
const LEDGER = "http://localhost:4406/mcp";
const REPORTS = "http://localhost:4410/api";
const HR = "http://localhost:4499/mcp";

/** An entry granting `actions` at `resource`. */
const at = (resource: string, actions: string[] = []): AuthorityEntry => ({
  type: "mission_resource_access",
  resource,
  actions,
});

/** The shipped published mapping, read from configuration alone. */
const published = () =>
  publishedProhibitedPredicateMapping(APPROVAL_FLOOR, PROGRESSIVE_PROFILE.external_communication_actions);

/** The published floor with one more classification, for a predicate no shipped action carries. */
const floorWith = (resource: string, actions: Record<string, string>) => ({
  ...APPROVAL_FLOOR,
  classification: [
    ...APPROVAL_FLOOR.classification,
    { type: "mission_resource_access", resource, cross_domain: false, actions },
  ],
});

/** Every action the reference serves, and the prohibited predicates the published mapping gives it. */
const EXPECTED: Array<[string, string, ProhibitedPredicate[]]> = [
  [PAYMENTS, "payments:invoice.list", []],
  [PAYMENTS, "payments:invoice.read", []],
  [PAYMENTS, "payments:vendor.read", ["external_communication"]],
  [PAYMENTS, "payments:payment.schedule", []],
  [PAYMENTS, "payments:payment.schedule.cancel", []],
  [PAYMENTS, "payments:payment.execute", ["irreversible_action"]],
  [PAYMENTS, "payments:payment.reverse", ["irreversible_action"]],
  [PAYMENTS, "payments:remittance.send", ["external_commitment"]],
  [LEDGER, "ledger:vendor.read", ["cross_domain"]],
  [LEDGER, "ledger:journal.write", ["cross_domain"]],
  [REPORTS, "reports:report.read", []],
  [REPORTS, "reports:report.write", []],
];

describe("dispatch-prohibited coverage (@spec template#prohibited-classes, #813)", () => {
  it("the published mapping states, for every action the reference serves, which prohibited predicates it satisfies, and every classification states whether its resource is cross-domain (@spec template#prohibited-classes, #1710)", () => {
    const served = APPROVAL_FLOOR.classification.flatMap((c) =>
      Object.keys(c.actions).map((a) => `${c.resource} ${a}`),
    );
    expect(served.sort()).toEqual(EXPECTED.map(([r, a]) => `${r} ${a}`).sort());
    for (const c of APPROVAL_FLOOR.classification) {
      expect(typeof c.cross_domain, c.resource).toBe("boolean");
    }
    for (const [resource, action, predicates] of EXPECTED) {
      expect(prohibitedPredicatesOf(published(), at(resource, [action]), action)?.sort(), action).toEqual(
        [...predicates].sort(),
      );
    }
  });

  it("the shipped dispatch-prohibited set covers every action the published mapping classifies as irreversible, external-commitment, privileged-administration, external-communication or cross-domain (@spec template#prohibited-classes, #1710)", () => {
    expect(
      dispatchProhibitedCoverageGaps(
        DISPATCH_PROHIBITED_ACTIONS,
        APPROVAL_FLOOR.classification,
        published(),
        ALL_PROHIBITED_PREDICATES,
      ),
    ).toEqual([]);
    for (const [, action, predicates] of EXPECTED) {
      if (predicates.length > 0) expect(DISPATCH_PROHIBITED_ACTIONS, action).toContain(action);
    }
  });

  it("the shipped dispatch-prohibited set includes payments:payment.reverse, which the published classification classifies as irreversible (@spec template#prohibited-classes)", () => {
    expect(published().classesOf(at(PAYMENTS), "payments:payment.reverse")).toEqual(["irreversible_action"]);
    expect(DISPATCH_PROHIBITED_ACTIONS).toContain("payments:payment.reverse");
  });

  it("names every classified action a configured set leaves out, with the predicates it satisfies (@spec template#prohibited-classes)", () => {
    const configured = DISPATCH_PROHIBITED_ACTIONS.filter((a) => a !== "payments:payment.reverse");
    expect(
      dispatchProhibitedCoverageGaps(configured, APPROVAL_FLOOR.classification, published()),
    ).toEqual([
      {
        action: "payments:payment.reverse",
        resource: PAYMENTS,
        predicates: ["irreversible_action"],
      },
    ]);
  });

  it("names an external-communication action and a cross-domain action a configured set leaves out (@spec template#prohibited-classes)", () => {
    const configured = DISPATCH_PROHIBITED_ACTIONS.filter(
      (a) => !["payments:vendor.read", "ledger:vendor.read", "ledger:journal.write"].includes(a),
    );
    expect(
      dispatchProhibitedCoverageGaps(configured, APPROVAL_FLOOR.classification, published()),
    ).toEqual([
      { action: "payments:vendor.read", resource: PAYMENTS, predicates: ["external_communication"] },
      { action: "ledger:journal.write", resource: LEDGER, predicates: ["cross_domain"] },
      { action: "ledger:vendor.read", resource: LEDGER, predicates: ["cross_domain"] },
    ]);
  });

  // One gap per predicate: the check fails on a gap under each of the five,
  // and names only that predicate. Privileged administration has no shipped
  // action, so its case adds a classification that makes one.
  it.each([
    ["irreversible_action", "payments:payment.execute", PAYMENTS, undefined],
    ["external_commitment", "payments:remittance.send", PAYMENTS, undefined],
    ["external_communication", "payments:vendor.read", PAYMENTS, undefined],
    ["cross_domain", "ledger:journal.write", LEDGER, undefined],
    ["privileged_administration", "hr:role.grant", HR, floorWith(HR, { "hr:role.grant": "privileged_administration" })],
  ] as const)(
    "fails on a configured set that leaves out an action under %s, naming it under that predicate alone (@spec template#prohibited-classes, #1710)",
    (predicate, action, resource, floor) => {
      const policy = floor ?? APPROVAL_FLOOR;
      const mapping = publishedProhibitedPredicateMapping(
        policy as never,
        PROGRESSIVE_PROFILE.external_communication_actions,
      );
      const configured = DISPATCH_PROHIBITED_ACTIONS.filter((a) => a !== action);
      expect(dispatchProhibitedCoverageGaps(configured, policy.classification, mapping)).toEqual([
        { action, resource, predicates: [predicate] },
      ]);
      expect(() =>
        assertDispatchProhibitedCoverage(configured, policy.classification, mapping),
      ).toThrow(DispatchProhibitedCoverageError);
      expect(
        dispatchProhibitedCoverageGaps(
          [...configured, action],
          policy.classification,
          mapping,
        ),
      ).toEqual([]);
    },
  );

  it("refuses a configured set that leaves out an action the published classification classifies as irreversible, naming it (@spec template#prohibited-classes)", () => {
    const floor = floorWith(HR, { "hr:file.read": "consequential_read", "hr:file.purge": "irreversible_action" });
    const mapping = publishedProhibitedPredicateMapping(floor as never, PROGRESSIVE_PROFILE.external_communication_actions);
    const check = () =>
      assertDispatchProhibitedCoverage(DISPATCH_PROHIBITED_ACTIONS, floor.classification, mapping);
    expect(check).toThrow(DispatchProhibitedCoverageError);
    expect(check).toThrow(
      "the configured dispatch-prohibited action set leaves out hr:file.purge at http://localhost:4499/mcp (irreversible_action), which the published mapping classifies as prohibited",
    );
    expect(() =>
      assertDispatchProhibitedCoverage(
        [...DISPATCH_PROHIBITED_ACTIONS, "hr:file.purge"],
        floor.classification,
        mapping,
      ),
    ).not.toThrow();
  });

  it("reads cross-domain from the classification's statement, and the AS's resource-to-AS map only adds to it (@spec template#prohibited-classes, #1710)", () => {
    const configOnly = published();
    expect(configOnly.isCrossDomain(LEDGER, at(LEDGER))).toBe(true);
    expect(configOnly.isCrossDomain(PAYMENTS, at(PAYMENTS))).toBe(false);
    expect(configOnly.isCrossDomain(REPORTS, at(REPORTS))).toBe(false);
    // A resource-to-AS map that places every resource locally cannot unmake
    // the stated cross-domain resource; one that places payments at another
    // AS adds it.
    const allLocal = publishedProhibitedPredicateMapping(
      APPROVAL_FLOOR,
      PROGRESSIVE_PROFILE.external_communication_actions,
      () => false,
    );
    expect(allLocal.isCrossDomain(LEDGER, at(LEDGER))).toBe(true);
    const paymentsRemote = publishedProhibitedPredicateMapping(
      APPROVAL_FLOOR,
      PROGRESSIVE_PROFILE.external_communication_actions,
      (r) => r === PAYMENTS,
    );
    expect(paymentsRemote.isCrossDomain(PAYMENTS, at(PAYMENTS))).toBe(true);
    expect(paymentsRemote.isCrossDomain(REPORTS, at(REPORTS))).toBe(false);
  });
});
