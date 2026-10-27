/**
 * @spec metering#settlement-contract, metering#settlement-states (#813, #816,
 * D830 ruling 10, D877) — the payments Operation Profile is the document that
 * states how the metered payment action settles against a standing-payment
 * budget. This test reads the shipped document
 * (`src/docs/operation-profile-payments-v1.md`): it names the live profile
 * version, and its Budget metering section states, for
 * `payments:payment.execute` at its `commit` crossing, that the payment class
 * defines no actual measure so the reserved amount commits, and that a
 * `failed` wire stays charged pending reconciliation.
 */
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { PAYMENTS_PROFILE_VERSION, TOOL_ACTIONS } from "../src/index.js";

const DOC = readFileSync(new URL("../../../docs/operation-profile-payments-v1.md", import.meta.url), "utf8");

/** The body of the `## <heading>` section, with line breaks and runs of spaces collapsed. */
function section(heading: string): string {
  const start = DOC.indexOf(`\n## ${heading}\n`);
  if (start < 0) return "";
  const body = DOC.slice(start + heading.length + 5);
  const end = body.indexOf("\n## ");
  return (end < 0 ? body : body.slice(0, end)).replace(/\s+/g, " ");
}

describe("the payments Operation Profile states how the metered payment settles (@spec metering#settlement-contract, metering#settlement-states, #813, #816, D877)", () => {
  it("names the live profile version, and states for payments:payment.execute at commit that the payment class defines no actual measure so the reserved amount commits, and that a failed wire stays charged pending reconciliation", () => {
    // The shipped document is the live profile's.
    expect(DOC.split("\n", 1)[0]).toBe(`# ${PAYMENTS_PROFILE_VERSION}`);
    const version = /^document\. Version: `([^`]+)`; changes bump the suffix\.$/m.exec(DOC)?.[1];
    expect(version).toBe(PAYMENTS_PROFILE_VERSION);

    const metering = section("Budget metering (#813, #816)");
    // The metered action and crossing, as the live profile performs them.
    const commit = TOOL_ACTIONS.execute_wire_transfer;
    expect([commit?.action, commit?.phase]).toEqual(["payments:payment.execute", "commit"]);
    expect(metering).toContain("meters `payments:payment.execute` at its `commit` crossing, `execute_wire_transfer`");
    // No actual measure: the reserved amount commits.
    expect(metering).toContain("The payment class defines no actual measure.");
    expect(metering).toContain("a `completed` settlement commits the reserved amount.");
    // The commit-or-refund rule for a failed metered payment.
    expect(metering).toContain("A `failed` settlement leaves the reservation held pending reconciliation");
  });
});
