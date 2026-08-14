// Binary compromise-boundary verification rule
// (runtime-evidence § evidence-integrity-signing-keys, #523 / PR #531).
//
// The evaluator is artifact-kind-agnostic: the same outcomes hold for
// runtime evidence records, Mission Receipts, and harness evidence.

/** Key status as supplied by the deployment-defined key-status mechanism. */
export type SigningKeyStatus =
  | { compromised: false }
  | {
      compromised: true;
      /**
       * Authenticated compromise boundary (RFC 3339). Absent when the
       * mechanism identifies compromise without supplying a boundary;
       * the verifier never infers one.
       */
      boundary?: string;
    };

export type ProofCommitment = "complete-artifact" | "typed-digest";

export type ProofFailure =
  | "signature"
  | "inclusion"
  | "type-binding"
  | "digest-linkage";

/** An independently trusted existence proof, as presented to the verifier. */
export type RecoveryProof =
  | { presented: false; reason: "missing" | "unavailable" | "unresolvable" }
  | { presented: true; valid: false; failure: ProofFailure }
  | {
      presented: true;
      valid: true;
      commits: ProofCommitment;
      /** Authenticated time of the proof (RFC 3339), never a payload claim. */
      authenticatedTime: string;
      proofKey: {
        compromised: boolean;
        /**
         * A distinct independent pre-boundary anchor for the proof itself,
         * required when the proof's own authenticating key is compromised.
         */
        distinctPreBoundaryAnchor?: boolean;
      };
    };

export type CompromiseBoundaryOutcome =
  /** The selected key is not compromised: the rule does not apply. */
  | { applicable: false }
  /** A qualifying pre-boundary proof exists: ordinary verification continues. */
  | { applicable: true; verified: true }
  /**
   * Not verified. `failure` separates the two result axes: a missing,
   * unavailable, or unresolvable proof is an audit failure; a presented
   * proof failing its own cryptographic or commitment verification is an
   * integrity failure of the proof. Neither is a tampering finding
   * against the underlying evidence.
   */
  | {
      applicable: true;
      verified: false;
      failure: "audit" | "proof-integrity";
      tamperingFinding: false;
    };

const NOT_VERIFIED_AUDIT: CompromiseBoundaryOutcome = {
  applicable: true,
  verified: false,
  failure: "audit",
  tamperingFinding: false,
};

const NOT_VERIFIED_PROOF_INTEGRITY: CompromiseBoundaryOutcome = {
  applicable: true,
  verified: false,
  failure: "proof-integrity",
  tamperingFinding: false,
};

function instant(value: string, label: string): number {
  const t = Date.parse(value);
  if (Number.isNaN(t)) {
    throw new RangeError(`${label} is not a parsable RFC 3339 instant: ${value}`);
  }
  return t;
}

/**
 * Evaluate the binary compromise-boundary rule for one artifact.
 *
 * Timestamps asserted by the target artifact are deliberately not an
 * input: a self-asserted pre-boundary timestamp never rescues an
 * artifact signed under a compromised key, and the verifier never
 * infers a boundary from artifact timestamps, its own clock, or an
 * implementation default.
 */
export function evaluateCompromiseBoundary(
  key: SigningKeyStatus,
  proof?: RecoveryProof,
): CompromiseBoundaryOutcome {
  if (!key.compromised) {
    return { applicable: false };
  }

  // Compromised with no authenticated boundary: nothing can place the
  // artifact before a boundary that does not exist.
  if (key.boundary === undefined) {
    return NOT_VERIFIED_AUDIT;
  }
  const boundary = instant(key.boundary, "boundary");

  if (proof === undefined || !proof.presented) {
    return NOT_VERIFIED_AUDIT;
  }
  if (!proof.valid) {
    return NOT_VERIFIED_PROOF_INTEGRITY;
  }

  // A proof authenticated by a key itself identified as compromised
  // qualifies only through a distinct independent pre-boundary anchor.
  if (proof.proofKey.compromised && proof.proofKey.distinctPreBoundaryAnchor !== true) {
    return NOT_VERIFIED_AUDIT;
  }

  // Strictly before the boundary; at or after does not rescue.
  if (instant(proof.authenticatedTime, "authenticatedTime") >= boundary) {
    return NOT_VERIFIED_AUDIT;
  }

  return { applicable: true, verified: true };
}
