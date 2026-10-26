/**
 * @spec draft-mcguinness-oauth-mission-template (#prohibited-classes) (#813)
 *
 * "The deployment's configured dispatch-prohibited action set MUST cover
 * every action the published mapping classifies as irreversible,
 * external-commitment, or privileged-administration, as satisfying the
 * runtime profile's external-communication predicate, or as cross-domain."
 * The coverage check, and the shipped configuration it holds for: a unit
 * check that fails loudly when `config/policy.json`'s
 * `dispatch_prohibited_actions` leaves out an action `config/approval-floor.json`
 * classifies as irreversible, external-commitment or privileged-administration.
 */
import { APPROVAL_FLOOR, DISPATCH_PROHIBITED_ACTIONS } from "@mission/demo-data";
import { describe, expect, it } from "vitest";
import {
  ALL_PROHIBITED_PREDICATES,
  assertDispatchProhibitedCoverage,
  CLASS_PREDICATES,
  DispatchProhibitedCoverageError,
  dispatchProhibitedCoverageGaps,
  type ProhibitedPredicateMapping,
} from "../src/index.js";
import { actionClassesAt } from "../src/kernel/approval-floor.js";

/** The published classification as the prohibited-predicate mapping reads it, nothing cross-domain. */
const floorMapping = (
  over: { external?: string[]; crossDomain?: (r: string) => boolean } = {},
): ProhibitedPredicateMapping => ({
  classesOf: (entry, action) => actionClassesAt(APPROVAL_FLOOR, entry, action),
  externalCommunicationActions: new Set(over.external ?? []),
  isCrossDomain: over.crossDomain ?? (() => false),
});

describe("dispatch-prohibited coverage (@spec template#prohibited-classes, #813)", () => {
  it("the shipped dispatch-prohibited set covers every action the published classification classifies as irreversible, external-commitment or privileged-administration (@spec template#prohibited-classes)", () => {
    expect(
      dispatchProhibitedCoverageGaps(
        DISPATCH_PROHIBITED_ACTIONS,
        APPROVAL_FLOOR.classification,
        floorMapping(),
        CLASS_PREDICATES,
      ),
    ).toEqual([]);
  });

  it("the shipped dispatch-prohibited set includes payments:payment.reverse, which the published classification classifies as irreversible (@spec template#prohibited-classes)", () => {
    expect(
      actionClassesAt(
        APPROVAL_FLOOR,
        { type: "mission_resource_access", resource: "http://localhost:4403/mcp", actions: [] },
        "payments:payment.reverse",
      ),
    ).toEqual(["irreversible_action"]);
    expect(DISPATCH_PROHIBITED_ACTIONS).toContain("payments:payment.reverse");
  });

  it("names every classified action a configured set leaves out, with the predicates it satisfies (@spec template#prohibited-classes)", () => {
    const configured = DISPATCH_PROHIBITED_ACTIONS.filter((a) => a !== "payments:payment.reverse");
    expect(
      dispatchProhibitedCoverageGaps(
        configured,
        APPROVAL_FLOOR.classification,
        floorMapping(),
        CLASS_PREDICATES,
      ),
    ).toEqual([
      {
        action: "payments:payment.reverse",
        resource: "http://localhost:4403/mcp",
        predicates: ["irreversible_action"],
      },
    ]);
  });

  it("names an external-communication action and a cross-domain action a configured set leaves out (@spec template#prohibited-classes)", () => {
    const mapping = floorMapping({
      external: ["payments:vendor.read"],
      crossDomain: (r) => r === "http://localhost:4410/api",
    });
    const gaps = dispatchProhibitedCoverageGaps(
      DISPATCH_PROHIBITED_ACTIONS,
      APPROVAL_FLOOR.classification,
      mapping,
      ALL_PROHIBITED_PREDICATES,
    );
    expect(gaps).toEqual([
      {
        action: "payments:vendor.read",
        resource: "http://localhost:4403/mcp",
        predicates: ["external_communication"],
      },
      {
        action: "reports:report.read",
        resource: "http://localhost:4410/api",
        predicates: ["cross_domain"],
      },
      {
        action: "reports:report.write",
        resource: "http://localhost:4410/api",
        predicates: ["cross_domain"],
      },
    ]);
  });

  it("refuses a configured set that leaves out an action the published classification classifies as irreversible, naming it (@spec template#prohibited-classes)", () => {
    const classification = [
      ...APPROVAL_FLOOR.classification,
      {
        type: "mission_resource_access",
        resource: "http://localhost:4499/mcp",
        actions: { "hr:file.read": "consequential_read", "hr:file.purge": "irreversible_action" },
      },
    ];
    const mapping: ProhibitedPredicateMapping = {
      classesOf: (entry, action) =>
        actionClassesAt({ ...APPROVAL_FLOOR, classification } as never, entry, action),
      externalCommunicationActions: new Set(),
      isCrossDomain: () => false,
    };
    const check = () =>
      assertDispatchProhibitedCoverage(
        DISPATCH_PROHIBITED_ACTIONS,
        classification,
        mapping,
        CLASS_PREDICATES,
      );
    expect(check).toThrow(DispatchProhibitedCoverageError);
    expect(check).toThrow(
      "the configured dispatch-prohibited action set leaves out hr:file.purge at http://localhost:4499/mcp (irreversible_action), which the published mapping classifies as prohibited",
    );
    expect(() =>
      assertDispatchProhibitedCoverage(
        [...DISPATCH_PROHIBITED_ACTIONS, "hr:file.purge"],
        classification,
        mapping,
        CLASS_PREDICATES,
      ),
    ).not.toThrow();
  });
});
