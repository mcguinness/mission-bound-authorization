/**
 * @spec #831 C: the kids a deployment's consumers trust for a key's role:
 * the topology key's `trusted` list, or its `kid` alone.
 */
import { TOPOLOGY, trustedKids } from "@mission/demo-data";
import { describe, expect, it } from "vitest";

describe("a topology key's trusted kids (@spec #831 C)", () => {
  it("are its trusted list when one is configured, and otherwise its kid alone", () => {
    expect(trustedKids({ kid: "as-token", alg: "RS256" })).toEqual(["as-token"]);
    expect(trustedKids({ kid: "as-token", alg: "RS256", trusted: ["as-token", "as-token-2"] })).toEqual(["as-token", "as-token-2"]);
    // The shipped topology configures none: each AS role is trusted under its kid alone.
    for (const key of [TOPOLOGY.keys.asToken, TOPOLOGY.keys.asStatus, TOPOLOGY.keys.asTxn, TOPOLOGY.keys.asContinuation]) {
      expect(trustedKids(key)).toEqual([key.kid]);
    }
  });
});
