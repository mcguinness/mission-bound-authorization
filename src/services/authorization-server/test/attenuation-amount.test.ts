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
import { type AuthorityEntry, mapAuthorityToTools } from "../src/index.js";

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
