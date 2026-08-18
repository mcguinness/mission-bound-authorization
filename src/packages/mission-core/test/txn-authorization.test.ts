/**
 * @spec txn-authorization#resource-challenge, mission#the-mission-claim — the
 * wire vocabulary the Challenge-Issuing Resource and the Transaction
 * Authorization Server both speak, read exactly as the core defines it.
 *
 * These are the parsers both sides fail closed on, so a shape the core permits
 * and this parser rejects does not surface as a rejected claim: it surfaces as
 * unequal Mission invariants and a refusal with no visible cause.
 */

import { describe, expect, it } from "vitest";
import { missionInvariantsEqual, readTxnMissionClaim } from "../src/index.js";

const INVARIANTS = {
  id: "msn_wire",
  issuer: "https://as.example.com",
  authority_hash: "sha-256:AAAA",
};

describe("the mission claim on the transaction wire (@spec mission#the-mission-claim)", () => {
  it("reads a claim carrying only the REQUIRED invariants", () => {
    // The cross-domain grant mints exactly this: the invariants plus the
    // issuer-qualified origin principal, and no optional members.
    expect(readTxnMissionClaim(INVARIANTS)).toEqual(INVARIANTS);
    expect(
      readTxnMissionClaim({
        ...INVARIANTS,
        subject: { iss: "https://partner.example", sub: "alice" },
      }),
    ).toEqual({ ...INVARIANTS, subject: { iss: "https://partner.example", sub: "alice" } });
  });

  it("reads expires_at as an RFC 3339 date-time string, never epoch seconds", () => {
    expect(
      readTxnMissionClaim({ ...INVARIANTS, expires_at: "2027-01-01T00:00:00.000Z" })?.expires_at,
    ).toBe("2027-01-01T00:00:00.000Z");
    // Epoch seconds are a second representation of one value on one wire.
    expect(readTxnMissionClaim({ ...INVARIANTS, expires_at: 4102444800 })).toBeUndefined();
    // Present but unparseable is a refusal, never a silently dropped member.
    expect(readTxnMissionClaim({ ...INVARIANTS, expires_at: "whenever" })).toBeUndefined();
  });

  it("treats approval_basis as OPTIONAL, and a malformed one as a refusal", () => {
    expect(
      readTxnMissionClaim({ ...INVARIANTS, approval_basis: { type: "direct" } })?.approval_basis,
    ).toEqual({
      type: "direct",
    });
    expect(readTxnMissionClaim({ ...INVARIANTS, approval_basis: {} })).toBeUndefined();
    expect(readTxnMissionClaim({ ...INVARIANTS, approval_basis: "direct" })).toBeUndefined();
  });

  it("refuses a claim missing any REQUIRED invariant, or malformed subject", () => {
    expect(
      readTxnMissionClaim({ issuer: INVARIANTS.issuer, authority_hash: "sha-256:AAAA" }),
    ).toBeUndefined();
    expect(
      readTxnMissionClaim({ ...INVARIANTS, subject: { iss: "https://p.example" } }),
    ).toBeUndefined();
    expect(readTxnMissionClaim(null)).toBeUndefined();
    expect(readTxnMissionClaim([INVARIANTS])).toBeUndefined();
  });

  it("compares invariants by value across the members actually present", () => {
    expect(missionInvariantsEqual(INVARIANTS, { ...INVARIANTS })).toBe(true);
    // An optional member present on one side only is a different claim: the
    // transaction token restates what the challenge carried, verbatim.
    expect(
      missionInvariantsEqual(INVARIANTS, { ...INVARIANTS, expires_at: "2027-01-01T00:00:00Z" }),
    ).toBe(false);
    expect(missionInvariantsEqual(INVARIANTS, { ...INVARIANTS, id: "msn_other" })).toBe(false);
  });
});
