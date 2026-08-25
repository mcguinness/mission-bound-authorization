import { describe, expect, it } from "vitest";
import {
  authorityHash,
  LocalApprovedSetVerificationError,
  verifyLocalApprovedSet,
} from "../src/index.js";

const ISS = "https://as.example.com";

interface Entry {
  resource: string;
  actions: string[];
}

// A minimal, deliberately simplistic stand-in for a REAL type's subset
// comparison (@spec mission#subset is type-owned; this module takes it as
// an injected predicate and defines no type of its own).
const isSubsetOfGranted = (candidate: Entry, granted: Entry): boolean =>
  candidate.resource === granted.resource && candidate.actions.every((a) => granted.actions.includes(a));

const APPROVED: Entry[] = [
  { resource: "https://erp.example.com", actions: ["invoices.read", "journal-entries.write"] },
];
const APPROVED_HASH = authorityHash(ISS, APPROVED as never);

describe("Local Approved-Set Verification — Tier 1 (@spec mission#lasv-retrieval)", () => {
  it("a carried entry that is a subset of a retrieved, correctly-committed entry verifies (permits)", () => {
    expect(() =>
      verifyLocalApprovedSet(
        { issuer: ISS, authority_set: APPROVED, authority_hash: APPROVED_HASH },
        [{ resource: "https://erp.example.com", actions: ["invoices.read"] }],
        isSubsetOfGranted,
      ),
    ).not.toThrow();
  });

  it("rejects when the retrieved set does not recompute to the retrieved authority_hash (commitment_mismatch)", () => {
    expect(() =>
      verifyLocalApprovedSet(
        { issuer: ISS, authority_set: APPROVED, authority_hash: "sha-256:tampered" },
        [{ resource: "https://erp.example.com", actions: ["invoices.read"] }],
        isSubsetOfGranted,
      ),
    ).toThrow(LocalApprovedSetVerificationError);
    try {
      verifyLocalApprovedSet(
        { issuer: ISS, authority_set: APPROVED, authority_hash: "sha-256:tampered" },
        [{ resource: "https://erp.example.com", actions: ["invoices.read"] }],
        isSubsetOfGranted,
      );
      expect.unreachable("must throw");
    } catch (e) {
      expect((e as LocalApprovedSetVerificationError).reason).toBe("commitment_mismatch");
    }
  });

  it("rejects a carried entry that is NOT a subset of any retrieved entry (not_subset)", () => {
    expect(() =>
      verifyLocalApprovedSet(
        { issuer: ISS, authority_set: APPROVED, authority_hash: APPROVED_HASH },
        [{ resource: "https://erp.example.com", actions: ["invoices.delete"] }],
        isSubsetOfGranted,
      ),
    ).toThrowError(/not a subset/);
  });

  it("rejects a carried entry against a DIFFERENT audience's resource (not_subset), never trusting commitment match alone", () => {
    expect(() =>
      verifyLocalApprovedSet(
        { issuer: ISS, authority_set: APPROVED, authority_hash: APPROVED_HASH },
        [{ resource: "https://other.example.com", actions: ["invoices.read"] }],
        isSubsetOfGranted,
      ),
    ).toThrow(LocalApprovedSetVerificationError);
  });
});

describe("Local Approved-Set Verification — Tier 2 (@spec mission#lasv-retrieval, independently retained root)", () => {
  it("a Tier-1-passing retrieval that matches the independently retained authority_hash verifies", () => {
    expect(() =>
      verifyLocalApprovedSet(
        { issuer: ISS, authority_set: APPROVED, authority_hash: APPROVED_HASH },
        [{ resource: "https://erp.example.com", actions: ["invoices.read"] }],
        isSubsetOfGranted,
        APPROVED_HASH,
      ),
    ).not.toThrow();
  });

  it("@spec mission#the-mission-claim, mission#lasv-retrieval (#702/#725 review) -- a SUBSTITUTED set that is internally self-consistent (recomputes correctly under Tier 1) is still refused once an independently retained approval-time root disagrees: Tier 1 alone would have permitted this", () => {
    // The issuer (or a compromised record store) substitutes a DIFFERENT,
    // wider Authority Set after approval, and honestly recomputes
    // authority_hash over ITS OWN substituted set -- Tier 1's checks all
    // pass, because Tier 1 never compares against anything but the same
    // retrieval call. Only a caller holding an independently retained
    // approval-time root (Tier 2) catches the substitution.
    const substituted: Entry[] = [
      { resource: "https://erp.example.com", actions: ["invoices.read", "journal-entries.write", "invoices.delete"] },
    ];
    const substitutedHash = authorityHash(ISS, substituted as never);
    expect(substitutedHash).not.toBe(APPROVED_HASH);

    // Tier 1 alone: recomputation matches the (substituted) retrieval, and
    // the carried entry is a subset of the (wider, substituted) grant --
    // this is exactly the gap the review flagged.
    expect(() =>
      verifyLocalApprovedSet(
        { issuer: ISS, authority_set: substituted, authority_hash: substitutedHash },
        [{ resource: "https://erp.example.com", actions: ["invoices.delete"] }],
        isSubsetOfGranted,
      ),
    ).not.toThrow();

    // Tier 2, with the REAL approval-time root retained independently of
    // this retrieval, refuses the same request.
    expect(() =>
      verifyLocalApprovedSet(
        { issuer: ISS, authority_set: substituted, authority_hash: substitutedHash },
        [{ resource: "https://erp.example.com", actions: ["invoices.delete"] }],
        isSubsetOfGranted,
        APPROVED_HASH,
      ),
    ).toThrow(LocalApprovedSetVerificationError);
  });
});
