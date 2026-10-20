/**
 * @spec draft-mcguinness-oauth-mission-cross-domain#cross-domain-grant,
 * #pre-established-trust (#1166, D510; ID-JAG -04 Sections 3.1 and 5): the
 * originating AS resolves the requesting client's registration at the target
 * Resource AS from a destination-scoped mapping. A missing or ambiguous mapping
 * is refused (invalid_target) and never answered with the client's identifier
 * at the originating AS; the two identifiers can be the same string.
 */

import { describe, expect, it } from "vitest";
import {
  DestinationClientUnresolvedError,
  resolveDestinationClientId,
  type DestinationClientRegistration,
} from "../src/kernel/cross-domain.js";

const RAS = "https://ras.ledgercloud.test";
const OTHER = "https://ras.other.test";

const MAPPING: DestinationClientRegistration[] = [
  { targetAs: RAS, clientId: "ap-agent", destinationClientId: "ledgercloud-ras-redeemer" },
  { targetAs: OTHER, clientId: "ap-agent", destinationClientId: "ap-agent" },
];

function unresolvedReason(fn: () => unknown): string | undefined {
  try {
    fn();
  } catch (e) {
    if (e instanceof DestinationClientUnresolvedError) return e.reason;
    throw e;
  }
  return undefined;
}

describe("resolveDestinationClientId (@spec cross-domain#cross-domain-grant, #1166, D510)", () => {
  it("resolves a distinct destination ID", () => {
    expect(resolveDestinationClientId(MAPPING, "ap-agent", RAS)).toBe("ledgercloud-ras-redeemer");
  });

  it("resolves an equal-string registration", () => {
    expect(resolveDestinationClientId(MAPPING, "ap-agent", OTHER)).toBe("ap-agent");
  });

  it("a missing mapping is refused, never answered with the requesting client's identifier", () => {
    expect(unresolvedReason(() => resolveDestinationClientId(MAPPING, "ap-agent", "https://ras.unmapped.test"))).toBe("missing");
    expect(unresolvedReason(() => resolveDestinationClientId(MAPPING, "svc-b", RAS))).toBe("missing");
    expect(unresolvedReason(() => resolveDestinationClientId([], "ap-agent", RAS))).toBe("missing");
    expect(unresolvedReason(() => resolveDestinationClientId(undefined, "ap-agent", RAS))).toBe("missing");
  });

  it("two distinct registrations for one client and target are ambiguous and refused", () => {
    const ambiguous = [...MAPPING, { targetAs: RAS, clientId: "ap-agent", destinationClientId: "another-registration" }];
    expect(unresolvedReason(() => resolveDestinationClientId(ambiguous, "ap-agent", RAS))).toBe("ambiguous");
  });

  it("entries that name the same registration count once", () => {
    const repeated = [...MAPPING, { ...MAPPING[0]! }];
    expect(resolveDestinationClientId(repeated, "ap-agent", RAS)).toBe("ledgercloud-ras-redeemer");
  });
});
