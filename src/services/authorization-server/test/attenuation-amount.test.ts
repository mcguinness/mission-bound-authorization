/**
 * @spec mission#max-amount, attenuation#root-mapping
 *
 * The AAT root-mapping (`mapAuthorityToTools`, via `argsFromConstraints`)
 * converts a Common Constraint `max_amount` decimal string into the AAT
 * `range` constraint's numeric `max`. A malformed amount MUST be rejected
 * before that conversion: `Number.parseFloat` on "NaN" yields `NaN`, and
 * `constraintSubset`'s `child.max > parent.max` check never fires against a
 * NaN ceiling (`NaN > x` and `x > NaN` are both false), so an unvalidated
 * malformed max_amount would mint a root whose ceiling is effectively
 * unbounded. Pure, in-memory, no network.
 */

import { describe, expect, it } from "vitest";
import { type AuthorityEntry, mapAuthorityToTools, mapToolsToAuthority } from "../src/index.js";

const RESOURCE = "https://r.example/mcp";

describe("mapAuthorityToTools rejects a malformed max_amount (@spec mission#max-amount)", () => {
  it("throws rather than minting a tool constraint with an unbounded/NaN ceiling", () => {
    const entry: AuthorityEntry = {
      type: "mission_resource_access",
      resource: RESOURCE,
      actions: ["res.pay"],
      constraints: { max_amount: { amount: "NaN", currency: "USD" } },
    };
    expect(() => mapAuthorityToTools([entry])).toThrow(/malformed max_amount/);
  });

  it("also rejects other non-decimal forms (exponent notation)", () => {
    const entry: AuthorityEntry = {
      type: "mission_resource_access",
      resource: RESOURCE,
      actions: ["res.pay"],
      constraints: { max_amount: { amount: "1e300", currency: "USD" } },
    };
    expect(() => mapAuthorityToTools([entry])).toThrow(/malformed max_amount/);
  });

  it("still maps a well-formed max_amount to a numeric range constraint (regression: unchanged behavior)", () => {
    const entry: AuthorityEntry = {
      type: "mission_resource_access",
      resource: RESOURCE,
      actions: ["res.pay"],
      constraints: { max_amount: { amount: "500.00", currency: "USD" } },
    };
    const tools = mapAuthorityToTools([entry]);
    const toolId = Object.keys(tools)[0] as string;
    expect(tools[toolId]?.amount_usd).toEqual({ constraint_type: "range", max: 500 });
  });
});

// @spec resource-access#initial-common-constraints (#1595, D727): the AAT
// argument name carries the code in lower case (`amount_usd`), so the mapping
// names only a well-formed code and reads back only three lower-case letters.
// Lower-casing a malformed `usd` and reading it back as `USD` would be the
// case folding the draft forbids.
describe("the AAT amount argument carries only a well-formed currency code (#1595, D727)", () => {
  const capped = (currency: string): AuthorityEntry => ({
    type: "mission_resource_access",
    resource: RESOURCE,
    actions: ["res.pay"],
    constraints: { max_amount: { amount: "500.00", currency } },
  });

  it("mapAuthorityToTools refuses a malformed currency rather than naming an argument for it", () => {
    for (const currency of ["usd", "US", "USDX", "USD\n", "840", ""]) {
      expect(() => mapAuthorityToTools([capped(currency)]), JSON.stringify(currency)).toThrow(
        /malformed max_amount currency/,
      );
    }
  });

  it("mapToolsToAuthority refuses an amount suffix that is not three lower-case letters", () => {
    for (const name of ["amount_USD", "amount_Usd", "amount_us", "amount_usdx", "amount_840", "amount_"]) {
      expect(
        () => mapToolsToAuthority({ [`${RESOURCE}#res.pay`]: { [name]: { constraint_type: "range", max: 5 } } }),
        name,
      ).toThrow(/amount_\*/);
    }
  });

  it("round-trips a well-formed code ISO 4217 does not assign", () => {
    const tools = mapAuthorityToTools([capped("XYZ")]);
    expect(Object.values(tools)[0]).toHaveProperty("amount_xyz");
    expect(mapToolsToAuthority(tools)[0]?.constraints?.max_amount).toEqual({ amount: "500", currency: "XYZ" });
  });
});
