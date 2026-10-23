/**
 * @spec mission#transformation-capabilities (#1503 finding 7, D620): the
 * retained original approved audience, at unit level. The endpoint witness is
 * original-approved-audience.test.ts; this covers the record shapes no
 * endpoint produces today (a row with no retained association, or one not
 * aligned with its Authority Set) and the entry an audience does not serve.
 */

import { describe, expect, it } from "vitest";
import { mappedAudiences, unapprovedAudienceRefusal } from "../src/kernel/approved-audience.js";
import type { AuthorityEntry } from "../src/kernel/types.js";

const PAYMENTS = "http://localhost:4403/mcp";
const REPORTS = "http://localhost:4403/reports";
const SAAS = "http://localhost:4406/mcp";
const ORIGIN = { type: "mission_resource_access", resource: "http://localhost:4403/", resource_match: "prefix", actions: ["payments:invoice.read"] } as AuthorityEntry;
const LEDGER = { type: "mission_resource_access", resource: SAAS, actions: ["ledger:vendor.read"] } as AuthorityEntry;
const MAPPING = {
  audiences: {
    [PAYMENTS]: { version: "1", mission_aware: true, mode: "authorization_details" },
    [SAAS]: { version: "1", mission_aware: false, mode: "authorization_details" },
  },
} as never;

describe("the original approved audience (@spec mission#transformation-capabilities, #1503 finding 7)", () => {
  it("assigns an entry every mapped audience whose resource tree overlaps it, never the entry's resource itself", () => {
    expect(mappedAudiences(MAPPING, ORIGIN)).toEqual([PAYMENTS]);
    expect(mappedAudiences(MAPPING, LEDGER)).toEqual([SAAS]);
    expect(mappedAudiences(undefined, ORIGIN)).toEqual([]);
  });

  it("admits a carried entry for a retained audience, and refuses one an audience serves but was not retained for", () => {
    const record = { authority_set: [ORIGIN], approved_audiences: [[PAYMENTS]] };
    expect(unapprovedAudienceRefusal(record, [PAYMENTS], [ORIGIN])).toBeUndefined();
    expect(unapprovedAudienceRefusal(record, [REPORTS], [ORIGIN])).toMatch(
      /audience http:\/\/localhost:4403\/reports is not an original approved audience of the entry for http:\/\/localhost:4403\//,
    );
  });

  it("ties a carried entry to the approved entry it derives from: another entry's approved audience does not admit it", () => {
    const exact = { type: "mission_resource_access", resource: PAYMENTS, actions: ["payments:invoice.read"] } as AuthorityEntry;
    const write = { ...ORIGIN, actions: ["payments:invoice.write"] } as AuthorityEntry;
    const record = { authority_set: [exact, write], approved_audiences: [[PAYMENTS], []] };
    expect(unapprovedAudienceRefusal(record, [PAYMENTS], [exact])).toBeUndefined();
    expect(unapprovedAudienceRefusal(record, [PAYMENTS], [write])).toMatch(/not an original approved audience/);
  });

  it("fails closed when the record retains no association, or one not aligned with its Authority Set", () => {
    expect(unapprovedAudienceRefusal({ authority_set: [ORIGIN] }, [PAYMENTS], [ORIGIN])).toMatch(
      /not an original approved audience/,
    );
    expect(
      unapprovedAudienceRefusal({ authority_set: [ORIGIN, LEDGER], approved_audiences: [[PAYMENTS]] }, [PAYMENTS], [ORIGIN]),
    ).toMatch(/not an original approved audience/);
  });

  it("leaves an entry the token's audience does not serve to ride, as before (boundary)", () => {
    const record = { authority_set: [ORIGIN, LEDGER], approved_audiences: [[PAYMENTS], [SAAS]] };
    expect(unapprovedAudienceRefusal(record, [PAYMENTS], [ORIGIN, LEDGER])).toBeUndefined();
  });
});
