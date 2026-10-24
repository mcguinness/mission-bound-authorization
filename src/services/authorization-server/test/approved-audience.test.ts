/**
 * @spec mission#transformation-capabilities, mission#token-response (#1503
 * finding 7, D620, D733): the retained original approved audience, at unit
 * level. The endpoint witness is original-approved-audience.test.ts; this
 * covers the record shapes no endpoint produces today (a row with no retained
 * association, or one not aligned with its Authority Set), the inheritance
 * relation a derived record uses, and the multi-audience rule, which this
 * reference's token endpoint never reaches (oidc-provider refuses a token
 * request naming more than one resource).
 */

import { describe, expect, it } from "vitest";
import {
  audienceProjection,
  audienceReferences,
  derivedAudiences,
  mappedAudiences,
  unapprovedCarriage,
} from "../src/kernel/approved-audience.js";
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

  it("carries an entry for a retained audience, and leaves out one an audience serves but was not retained for", () => {
    const refs = audienceReferences([ORIGIN], [[PAYMENTS]]);
    expect(audienceProjection(refs, [PAYMENTS], [ORIGIN], false)).toEqual({ issued: [ORIGIN] });
    expect(audienceProjection(refs, [REPORTS], [ORIGIN], false).refusal).toMatch(
      /audience http:\/\/localhost:4403\/reports is not an original approved audience of any entry the token would carry/,
    );
  });

  it("ties a carried entry to the approved entry it derives from: another entry's approved audience does not admit it", () => {
    const exact = { type: "mission_resource_access", resource: PAYMENTS, actions: ["payments:invoice.read"] } as AuthorityEntry;
    const write = { ...ORIGIN, actions: ["payments:invoice.write"] } as AuthorityEntry;
    const refs = audienceReferences([exact, write], [[PAYMENTS], []]);
    expect(audienceProjection(refs, [PAYMENTS], [exact], false)).toEqual({ issued: [exact] });
    expect(audienceProjection(refs, [PAYMENTS], [write], false).refusal).toMatch(/not an original approved audience/);
  });

  it("fails closed when the record retains no association, or one not aligned with its Authority Set", () => {
    expect(audienceProjection(audienceReferences([ORIGIN], undefined), [PAYMENTS], [ORIGIN], false).refusal).toMatch(
      /not an original approved audience/,
    );
    expect(
      audienceProjection(audienceReferences([ORIGIN, LEDGER], [[PAYMENTS]]), [PAYMENTS], [ORIGIN], false).refusal,
    ).toMatch(/not an original approved audience/);
  });
});

describe("a token for an audience carries only the entries approved for it (@spec mission#token-response, #1503 finding 7, D733 ruling 1)", () => {
  const refs = audienceReferences([ORIGIN, LEDGER], [[PAYMENTS], [SAAS]]);

  it("leaves an entry approved for another audience out of the token, never carrying it along", () => {
    expect(audienceProjection(refs, [PAYMENTS], [ORIGIN, LEDGER], false)).toEqual({ issued: [ORIGIN] });
    expect(audienceProjection(refs, [SAAS], [ORIGIN, LEDGER], false)).toEqual({ issued: [LEDGER] });
  });

  it("refuses a request that explicitly names an entry not approved for the token's audience, rather than issuing the rest", () => {
    expect(audienceProjection(refs, [PAYMENTS], [ORIGIN, LEDGER], true).refusal).toMatch(
      /audience http:\/\/localhost:4403\/mcp is not an original approved audience of the requested entry for http:\/\/localhost:4406\/mcp/,
    );
    expect(audienceProjection(refs, [PAYMENTS], [ORIGIN], true)).toEqual({ issued: [ORIGIN] });
  });

  it("issues a token naming several audiences only the entries every one of them is approved for, and refuses it when their permitted entries differ", () => {
    const both = audienceReferences([ORIGIN, LEDGER], [[PAYMENTS, SAAS], [PAYMENTS, SAAS]]);
    expect(audienceProjection(both, [PAYMENTS, SAAS], [ORIGIN, LEDGER], false)).toEqual({ issued: [ORIGIN, LEDGER] });
    expect(audienceProjection(refs, [PAYMENTS, SAAS], [ORIGIN, LEDGER], false).refusal).toMatch(
      /audiences http:\/\/localhost:4403\/mcp and http:\/\/localhost:4406\/mcp are not approved for the same entries; a separate token is issued for each audience/,
    );
  });

  it("the save-time backstop refuses a token carrying an entry one of its audiences is not approved for", () => {
    expect(unapprovedCarriage(refs, [PAYMENTS], [ORIGIN])).toBeUndefined();
    expect(unapprovedCarriage(refs, [PAYMENTS], [ORIGIN, LEDGER])).toMatch(
      /audience http:\/\/localhost:4403\/mcp is not an original approved audience of the carried entry for http:\/\/localhost:4406\/mcp/,
    );
  });
});

describe("a derived entry keeps the association of the authority it derives from (@spec mission#transformation-capabilities, #1503 finding 7, D733 ruling 2)", () => {
  it("takes the audiences every reference it falls within retains, and none when it falls within no reference or one that retains none", () => {
    const narrow = { type: "mission_resource_access", resource: PAYMENTS, actions: ["payments:invoice.read"] } as AuthorityEntry;
    const exactPayments = { ...narrow };
    expect(derivedAudiences(narrow, audienceReferences([ORIGIN], [[PAYMENTS, REPORTS]]))).toEqual([PAYMENTS, REPORTS]);
    // Overlapping references never lend a wider association.
    expect(
      derivedAudiences(narrow, audienceReferences([ORIGIN, exactPayments], [[PAYMENTS, REPORTS], [PAYMENTS]])),
    ).toEqual([PAYMENTS]);
    expect(derivedAudiences(LEDGER, audienceReferences([ORIGIN], [[PAYMENTS]]))).toEqual([]);
    expect(derivedAudiences(narrow, audienceReferences([ORIGIN], undefined))).toEqual([]);
    // A reference whose association cannot be established is never skipped
    // in favor of another: the entry it covers has none (D733 ruling 4).
    expect(
      derivedAudiences(narrow, [
        { entry: ORIGIN, audiences: undefined },
        { entry: exactPayments, audiences: [PAYMENTS] },
      ]),
    ).toEqual([]);
  });
});
