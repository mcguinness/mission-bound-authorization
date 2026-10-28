/**
 * @spec mission#max-amount, resource-access#initial-common-constraints (#1595,
 * D727), attenuation#root-mapping, attenuation#mission-constraints (#1756)
 *
 * An attenuation root carries an entry's `max_amount` in `mission_constraints`
 * exactly as the Authority Set states it: a decimal string with its currency
 * code, never converted to a number and never case-folded. A malformed amount
 * or currency never reaches a root: the root mapping copies the entry, and
 * the check every mint applies before signing (the consumer's own reading,
 * `credentialEntriesFromMissionAat`) refuses it. Pure, in-memory, no network.
 */

import { credentialEntriesFromMissionAat } from "@mission/core";
import { describe, expect, it } from "vitest";
import { type AuthorityEntry, mapAuthorityToCeiling } from "../src/index.js";
import { TEST_OPERATIONS } from "./attenuation.helper.js";

const RESOURCE = "https://r.example/mcp";
const TOOL = `${RESOURCE}#res.pay`;

const capped = (amount: string, currency = "USD"): AuthorityEntry => ({
  type: "mission_resource_access",
  resource: RESOURCE,
  actions: ["res.pay"],
  constraints: { max_amount: { amount, currency } },
});

/** The root mapping, and the check a mint applies to it before signing. */
function carried(entry: AuthorityEntry) {
  const { tools, missionConstraints } = mapAuthorityToCeiling([entry], TEST_OPERATIONS);
  return { tools, missionConstraints, read: () => credentialEntriesFromMissionAat(tools, missionConstraints) };
}

describe("an attenuation root never carries a malformed max_amount (@spec mission#max-amount)", () => {
  it("refuses a malformed amount before signing, rather than carrying it", () => {
    for (const amount of ["NaN", "1e300"]) {
      const { tools, read } = carried(capped(amount));
      expect(Object.keys(tools), amount).toEqual([TOOL]);
      expect(read, amount).toThrow(/max_amount/);
    }
  });

  it("carries a well-formed max_amount unchanged, as a decimal string, and reads it back unchanged", () => {
    const { missionConstraints, read } = carried(capped("500.00"));
    expect(missionConstraints[TOOL]?.constraints).toEqual({ max_amount: { amount: "500.00", currency: "USD" } });
    expect(read()[0]?.constraints?.max_amount).toEqual({ amount: "500.00", currency: "USD" });
  });
});

describe("an attenuation root carries only a well-formed currency code, never folded (#1595, D727)", () => {
  it("refuses a malformed currency before signing, rather than carrying or folding it", () => {
    for (const currency of ["usd", "US", "USDX", "USD\n", "840", ""]) {
      expect(carried(capped("500.00", currency)).read, JSON.stringify(currency)).toThrow(/max_amount/);
    }
  });

  it("carries a well-formed code ISO 4217 does not assign unchanged, and reads it back", () => {
    const { missionConstraints, read } = carried(capped("500.00", "XYZ"));
    expect(missionConstraints[TOOL]?.constraints).toEqual({ max_amount: { amount: "500.00", currency: "XYZ" } });
    expect(read()[0]?.constraints?.max_amount).toEqual({ amount: "500.00", currency: "XYZ" });
  });
});
