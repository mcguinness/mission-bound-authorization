import { describe, expect, it } from "vitest";
import { canonicalDigest } from "../src/index.js";

// @spec draft-mcguinness-mission-runtime-evidence.md#request-digest-worked
// (lines 946-979 at 41f66a4a): the evaluation_request_digest worked value.
// Pinned so a `canonicalDigest` regression is caught before it is ever used
// to sign anything (a buggy canonicalizer round-trips clean against itself,
// so only an external vector like this one catches drift).
describe("canonicalDigest: spec vectors (runtime-evidence.md @ 41f66a4a)", () => {
  it("reproduces the evaluation_request_digest worked value", () => {
    const value = {
      action: "journal-entries.read",
      audience: "https://erp.example.com",
      mission_id: "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
      resource: "je_2026Q3_inv_8421",
      subject: "user_3p2q8mN1a0kV7tR",
    };
    expect(canonicalDigest(value)).toBe("sha-256:sK12VE_g01AHD2v-O1vsf1Gf_xT_htjX0UN0Oe0dDRU");
  });

  it("reproduces the Mission Receipt digest vector over the Execution Evidence stand-in", () => {
    // @spec runtime-evidence.md#mission-receipt-digest-worked (lines 1613-1661):
    // the object is a digest-only vector, deliberately not a signature over
    // these bytes, so only canonicalDigest is under test here.
    const value = {
      audience: "https://erp.example.com",
      emitter: { id: "pep.example.com", role: "executor" },
      evaluation_id: "dec_8K2nP4qV9rL3tY6sB1zN0eF7jB",
      evidence_envelope: {
        format: "jws-compact",
        value:
          "eyJhbGciOiJFUzI1NiIsImtpZCI6InBlcC1rZXktMSJ9.dGhlLXNpZ25lZC1wYXlsb2FkLWJ5dGVzLWFib3Zl.RVMyNTZfc2lnbmF0dXJlX2J5dGVzX2lsbHVzdHJhdGl2ZQ",
      },
      execution_id: "exe_4r9SqLm8tY2pXkV3nR0eF7jB1zN6cQ5w",
      mission_id: "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
      outcome: "completed",
      outcome_at: "2026-11-02T08:14:05Z",
      sequence: 43,
    };
    expect(canonicalDigest(value)).toBe("sha-256:Ims1Xx5FAPYfFB6c6Y2gbqybB-Z2PxCi93yWPcIHmC8");
  });
});
