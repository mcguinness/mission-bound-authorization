/**
 * @spec orchestration#reversibility (#1735, #1994)
 *
 * A step whose operation satisfies more than one runtime class predicate
 * meets the minimum each of those classes maps to. The three highest classes
 * carry the same requirements in this profile, so any one of them meets the
 * minimum of another: no order among them is introduced.
 */

import { describe, expect, it } from "vitest";
import {
  deriveReversibility,
  enforceReversibilityFloor,
  floorReversibilityOver,
} from "../src/index.js";

describe("a step several runtime class predicates apply to meets each class's minimum (@spec orchestration#reversibility, #1735, #1994)", () => {
  it("raises a trusted reversible_write proposal to a high class when external_commitment also applies", () => {
    const derived = deriveReversibility({
      runtimeActionClass: "consequential_write",
      additionalRuntimeActionClasses: ["external_commitment"],
      proposed: "reversible_write",
      proposedSource: "operation_profile",
    });
    expect(derived.reversibility).toBe("external_commitment");
    expect(derived.adopted).toBe(true);
    expect(floorReversibilityOver(["consequential_write", "external_commitment"])).toBe(
      "external_commitment",
    );
  });

  it("keeps a trusted irreversible_action proposal where external_commitment also applies: any of the three high classes meets another's minimum", () => {
    const derived = deriveReversibility({
      runtimeActionClass: "external_commitment",
      additionalRuntimeActionClasses: ["irreversible_action"],
      proposed: "irreversible_action",
      proposedSource: "operation_profile",
    });
    expect(derived.reversibility).toBe("irreversible_action");
    expect(enforceReversibilityFloor("irreversible_action", "external_commitment")).toBe(
      "irreversible_action",
    );
    expect(
      enforceReversibilityFloor("privileged_administration", [
        "external_commitment",
        "irreversible_action",
      ]),
    ).toBe("privileged_administration");
  });

  it("adopts no untrusted proposal: the floor over every applicable class governs", () => {
    const derived = deriveReversibility({
      runtimeActionClass: "consequential_write",
      additionalRuntimeActionClasses: ["irreversible_action"],
      proposed: "read_only",
      proposedSource: "model_output",
    });
    expect(derived.reversibility).toBe("irreversible_action");
    expect(derived.adopted).toBe(false);
  });

  it("keeps each high class against every other high class's minimum, in all six pairings: no high class ranks below another", () => {
    const high = [
      "irreversible_action",
      "external_commitment",
      "privileged_administration",
    ] as const;
    for (const proposed of high) {
      for (const floor of high) {
        expect(enforceReversibilityFloor(proposed, floor), `${proposed} over ${floor}`).toBe(
          proposed,
        );
      }
    }
  });
});
