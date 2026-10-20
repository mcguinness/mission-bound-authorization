/**
 * @spec progressive#in-ceiling-expansion, mission#approval-authentication
 * (#1255)
 *
 * The Progressive drawdown classifies widened actions through its own
 * published mapping (`progressive.actionClasses`), and the
 * approval-authentication floor classifies every admitted action through the
 * AS-owned classification (config/approval-floor.json). A deployment that
 * selects Progressive does not start when the two disagree: an action the
 * floor places in a class some floor applies to must not map to a class a
 * drawdown grants by policy alone. An action the mapping leaves out needs
 * nothing here; its drawdown falls back (`unclassified_action`).
 */
import { APPROVAL_FLOOR, type ApprovalFloorPolicy } from "@mission/demo-data";
import { describe, expect, it } from "vitest";
import { buildAuthorizationServer } from "../src/index.js";
import { assertDrawdownClassesMeetApprovalFloor, type ProgressiveDrawdownOptions } from "../src/kernel/progressive.js";

/** A mapping that agrees with the shipped floor: payment execution is irreversible, remittance unmapped. */
const PROGRESSIVE: ProgressiveDrawdownOptions = {
  chainRateBound: { maxDrawdowns: 2, windowSeconds: 3600 },
  actionClasses: {
    "payments:invoice.list": "consequential_read",
    "payments:invoice.read": "consequential_read",
    "payments:vendor.read": "consequential_read",
    "payments:payment.schedule": "consequential_write",
    "payments:payment.schedule.cancel": "consequential_write",
    "payments:payment.execute": "irreversible_action",
  },
};

describe("the drawdown classification agrees with the approval-authentication floor (@spec progressive#in-ceiling-expansion, mission#approval-authentication, #1255)", () => {
  it("refuses to start when actionClasses maps an action the floor classifies high-risk to a class a drawdown grants by policy", async () => {
    const divergent: ProgressiveDrawdownOptions = {
      ...PROGRESSIVE,
      actionClasses: { ...PROGRESSIVE.actionClasses, "payments:payment.execute": "consequential_write" },
    };
    await expect(buildAuthorizationServer({ issuer: "http://localhost:14841", progressive: divergent })).rejects.toThrow(
      /payments:payment\.execute maps to consequential_write.*classifies it irreversible_action/,
    );
  });

  it("starts with an agreeing mapping: every action the floor classifies high-risk maps into the fresh-approval classes", async () => {
    const agreeing: ProgressiveDrawdownOptions = {
      ...PROGRESSIVE,
      actionClasses: { ...PROGRESSIVE.actionClasses, "payments:remittance.send": "external_commitment" },
    };
    const invoking = new Set<string>(APPROVAL_FLOOR.floors.flatMap((f) => f.applies_to));
    const floorClass = APPROVAL_FLOOR.classification.flatMap((c) =>
      Object.entries(c.actions).filter(([, cls]) => invoking.has(cls)).map(([action]) => action),
    );
    // The control maps every floor-class action, so none passes by being left out.
    expect(floorClass.length).toBeGreaterThan(0);
    expect(floorClass.every((a) => Object.hasOwn(agreeing.actionClasses, a))).toBe(true);
    const built = await buildAuthorizationServer({ issuer: "http://localhost:14842", progressive: agreeing });
    expect(built.issuer).toBe("http://localhost:14842");
  });

  it("follows what the floor invokes, not the class name: under a floor that also applies to consequential_write, a write mapped to consequential_write refuses", () => {
    const writesInvoke: ApprovalFloorPolicy = {
      ...APPROVAL_FLOOR,
      floors: APPROVAL_FLOOR.floors.map((f) => ({ ...f, applies_to: [...f.applies_to, "consequential_write"] })),
    };
    expect(() => assertDrawdownClassesMeetApprovalFloor(PROGRESSIVE, APPROVAL_FLOOR)).not.toThrow();
    expect(() => assertDrawdownClassesMeetApprovalFloor(PROGRESSIVE, writesInvoke)).toThrow(
      /payments:payment\.schedule(\.cancel)? maps to consequential_write/,
    );
  });
});
