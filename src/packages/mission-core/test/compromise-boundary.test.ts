import { describe, expect, it } from "vitest";
import {
  type CompromiseBoundaryOutcome,
  evaluateCompromiseBoundary,
  type RecoveryProof,
  type SigningKeyStatus,
} from "../src/index.js";

// runtime-evidence § evidence-integrity-signing-keys and
// § compromise-vectors: the binary compromise-boundary rule.

const BOUNDARY = "2026-08-01T00:00:00Z";
const COMPROMISED: SigningKeyStatus = { compromised: true, boundary: BOUNDARY };
const COMPROMISED_NO_BOUNDARY: SigningKeyStatus = { compromised: true };

const VALID_PRE = (commits: "complete-artifact" | "typed-digest"): RecoveryProof => ({
  presented: true,
  valid: true,
  commits,
  authenticatedTime: "2026-07-15T12:00:00Z",
  proofKey: { compromised: false },
});

// The same outcomes hold for runtime evidence records, Mission
// Receipts, and harness evidence: the evaluator takes no artifact
// kind, and this suite pins that by running the full matrix once per
// kind label.
const ARTIFACT_KINDS = ["record", "mission-receipt", "harness-evidence"] as const;

function expectAudit(outcome: CompromiseBoundaryOutcome): void {
  expect(outcome).toEqual({
    applicable: true,
    verified: false,
    failure: "audit",
    tamperingFinding: false,
  });
}

describe("compromise-boundary rule (@spec runtime-evidence#evidence-integrity-signing-keys)", () => {
  for (const kind of ARTIFACT_KINDS) {
    describe(`artifact kind: ${kind}`, () => {
      it("a self-asserted pre-boundary timestamp never rescues a compromised-key artifact", () => {
        // The artifact's own timestamps are not even an input to the
        // rule: with no independent proof, the outcome is not-verified
        // however early the artifact claims to have been signed.
        expectAudit(
          evaluateCompromiseBoundary(COMPROMISED, {
            presented: false,
            reason: "missing",
          }),
        );
      });

      it("compromised with no authenticated boundary is not verified, even with a valid proof", () => {
        expectAudit(
          evaluateCompromiseBoundary(
            COMPROMISED_NO_BOUNDARY,
            VALID_PRE("complete-artifact"),
          ),
        );
      });

      it("a verified pre-boundary proof over the complete signed artifact permits continuation", () => {
        expect(
          evaluateCompromiseBoundary(COMPROMISED, VALID_PRE("complete-artifact")),
        ).toEqual({ applicable: true, verified: true });
      });

      it("a verified pre-boundary proof over the unambiguous typed digest permits continuation", () => {
        expect(
          evaluateCompromiseBoundary(COMPROMISED, VALID_PRE("typed-digest")),
        ).toEqual({ applicable: true, verified: true });
      });

      it("a proof authenticated exactly at the boundary does not rescue", () => {
        expectAudit(
          evaluateCompromiseBoundary(COMPROMISED, {
            ...VALID_PRE("complete-artifact"),
            authenticatedTime: BOUNDARY,
          }),
        );
      });

      it("a proof authenticated after the boundary does not rescue", () => {
        expectAudit(
          evaluateCompromiseBoundary(COMPROMISED, {
            ...VALID_PRE("complete-artifact"),
            authenticatedTime: "2026-08-02T00:00:00Z",
          }),
        );
      });

      it("a missing, unavailable, or unresolvable proof is an audit failure, never tampering", () => {
        for (const reason of ["missing", "unavailable", "unresolvable"] as const) {
          expectAudit(
            evaluateCompromiseBoundary(COMPROMISED, { presented: false, reason }),
          );
        }
      });

      it("a presented proof failing its own verification is an integrity failure of the proof", () => {
        for (const failure of [
          "signature",
          "inclusion",
          "type-binding",
          "digest-linkage",
        ] as const) {
          expect(
            evaluateCompromiseBoundary(COMPROMISED, {
              presented: true,
              valid: false,
              failure,
            }),
          ).toEqual({
            applicable: true,
            verified: false,
            failure: "proof-integrity",
            tamperingFinding: false,
          });
        }
      });

      it("a proof under a compromised proof key cannot rescue without a distinct anchor", () => {
        expectAudit(
          evaluateCompromiseBoundary(COMPROMISED, {
            ...VALID_PRE("complete-artifact"),
            proofKey: { compromised: true },
          }),
        );
      });

      it("a proof under a compromised proof key with a distinct independent pre-boundary anchor rescues", () => {
        expect(
          evaluateCompromiseBoundary(COMPROMISED, {
            ...VALID_PRE("typed-digest"),
            proofKey: { compromised: true, distinctPreBoundaryAnchor: true },
          }),
        ).toEqual({ applicable: true, verified: true });
      });

      it("a non-compromised key is outside the rule", () => {
        expect(evaluateCompromiseBoundary({ compromised: false })).toEqual({
          applicable: false,
        });
      });
    });
  }
});
