import { describe, expect, it } from "vitest";
import {
  type ApprovalContextManifestInput,
  approvalContextCommitment,
  approvalContextManifest,
  computeAnchor,
  submissionEvidenceCommitment,
  verifyApprovalContextCommitment,
} from "../src/index.js";

const ISS = "https://as.example.com";

// approval-governance § approval-context-vectors: the always-present members,
// reused byte-exact from core's canonical Worked Example Mission Record.
const ALWAYS_PRESENT = {
  issuer: ISS,
  id: "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
  intent_hash: "sha-256:wQ7p4LHnX9Md0LqJ6sZJ8b8mZ3rN2xT5pV4lE6sQqYY",
  authority_hash: "sha-256:l3KvZ4mP5x0wQrR6tY2nD9bM7sX1cF8gH2vJ4kE5pNQ",
  subject: { iss: "https://idp.example.com", sub: "user_3p2q8mN1a0kV7tR" },
  approver: { iss: "https://idp.example.com", sub: "user_3p2q8mN1a0kV7tR" },
  client_id: "s6BhdRkqt3",
  created_at: "2026-10-15T14:32:11Z",
  expires_at: "2026-12-31T23:59:59Z",
  approval_basis: {
    type: "direct",
    consent_principal: { iss: "https://idp.example.com", sub: "user_3p2q8mN1a0kV7tR" },
    activation: { approval_event_id: "ape_8K2nP4qV9rL3tY6sB1z" },
    activation_actor: { iss: "https://idp.example.com", sub: "user_3p2q8mN1a0kV7tR" },
    adjudication: { kind: "human" },
    root_commitment: "sha-256:l3KvZ4mP5x0wQrR6tY2nD9bM7sX1cF8gH2vJ4kE5pNQ",
  },
  authority_source: { type: "user_delegated" },
  policy_version: "deploy-policy:v17",
  approval_event_id: "ape_8K2nP4qV9rL3tY6sB1z",
} satisfies Omit<
  ApprovalContextManifestInput,
  "proposal_hash" | "ceiling_hash" | "submission_evidence_commitment"
>;

const PROPOSAL_HASH = "sha-256:kT2mR7vX4qL9nY5pB1sD8fJ6wZ3hC0aGeUoNvSqMrYo";

describe("Approval Context Manifest (approval-governance § approval-context-manifest)", () => {
  it("is a deterministic pure function of the Mission Record members alone", () => {
    const a = approvalContextManifest({ ...ALWAYS_PRESENT, proposal_hash: PROPOSAL_HASH });
    const b = approvalContextManifest({ ...ALWAYS_PRESENT, proposal_hash: PROPOSAL_HASH });
    expect(a).toEqual(b);
    expect(approvalContextCommitment(ISS, a)).toBe(approvalContextCommitment(ISS, b));
  });

  it("includes ceiling_hash iff the input carries one", () => {
    const without = approvalContextManifest({ ...ALWAYS_PRESENT });
    expect(without).not.toHaveProperty("ceiling_hash");
    const withCeiling = approvalContextManifest({ ...ALWAYS_PRESENT, ceiling_hash: "sha-256:x" });
    expect(withCeiling).toHaveProperty("ceiling_hash", "sha-256:x");
  });
});

describe("Approval Context Commitment vectors (approval-governance § approval-context-vectors)", () => {
  it("vector 1: base manifest (no conditional members)", () => {
    const manifest = approvalContextManifest({ ...ALWAYS_PRESENT });
    expect(approvalContextCommitment(ISS, manifest)).toBe(
      "sha-256:iRCrkxJWsQL1ZlXYQg1FUy2OIBKFpFn99tYA-2qlC48",
    );
  });

  it("vector 2: conditional proposal_hash (= core's canonical worked example)", () => {
    const manifest = approvalContextManifest({ ...ALWAYS_PRESENT, proposal_hash: PROPOSAL_HASH });
    expect(approvalContextCommitment(ISS, manifest)).toBe(
      "sha-256:7ikugIQZvSkie-Pc25V_sJKGHU5HGymVfrnMaIc8So0",
    );
  });

  it("vector 3: conditional ceiling_hash", () => {
    // Progressive's own ceiling_hash construction (draft-mcguinness-oauth-mission-progressive
    // § progressive-authorization): typ mission-authority-ceiling over
    // {authority_ceiling, drawdown_policy}.
    const ceilingHash = computeAnchor("mission-authority-ceiling", ISS, {
      authority_ceiling: [
        {
          type: "mission_resource_access",
          resource: "https://erp.example.com",
          actions: ["invoices.read", "invoices.write"],
        },
      ],
      drawdown_policy: "https://as.example.com/policies/erp-drawdown-v1",
    });
    expect(ceilingHash).toBe("sha-256:IcftaaatF3MgmbbcDoXB6hEi-kqy-y2IFD2PCeZfB_Q");

    const manifest = approvalContextManifest({ ...ALWAYS_PRESENT, ceiling_hash: ceilingHash });
    expect(approvalContextCommitment(ISS, manifest)).toBe(
      "sha-256:aj_DeEf0vbk7jZnXOMEFiFVSmD0SQg5MEXIMUXSWLFs",
    );
  });

  it("vector 4: conditional submission_evidence_commitment", () => {
    const presentedEntry = {
      type: "mission-intent-admission-assertion",
      assertion:
        "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczovL2FkbWlzc2lvbi5leGFtcGxlLmNvbSJ9.MEUCIQDx7vector",
    };
    const artifactHash = computeAnchor("mission-intent-evidence", ISS, presentedEntry);
    expect(artifactHash).toBe("sha-256:EwtVufH4c6btTaI55w-3mDJaNg0miFuC6-T7jXU2-R8");

    const recordedElement = {
      type: "mission-intent-admission-assertion",
      artifact_hash: artifactHash,
      verified_at: "2026-10-15T14:31:50Z",
      facts: {
        admission_issuer: "https://admission.example.com",
        status: "active",
      },
    };
    const submissionEvidenceHash = submissionEvidenceCommitment(ISS, [recordedElement]);
    expect(submissionEvidenceHash).toBe("sha-256:TwDmwzJgsm8Ik86YuybyctIaMPZK-aKeU6a2BF0kTi0");

    const manifest = approvalContextManifest({
      ...ALWAYS_PRESENT,
      submission_evidence_commitment: submissionEvidenceHash,
    });
    expect(approvalContextCommitment(ISS, manifest)).toBe(
      "sha-256:Msha2eEDtfucgANzT5nmO90gtCEXFQFdRfVUGmOwCZE",
    );
  });
});

describe("Approval Context Commitment verification (approval-governance § approval-context-computation)", () => {
  it("vector 5: rejects a mutated member (recomputed digest differs)", () => {
    const disclosed = "sha-256:7ikugIQZvSkie-Pc25V_sJKGHU5HGymVfrnMaIc8So0"; // vector 2
    const mutated = approvalContextManifest({
      ...ALWAYS_PRESENT,
      proposal_hash: PROPOSAL_HASH,
      approval_event_id: "ape_9K2nP4qV9rL3tY6sB1z",
    });
    expect(approvalContextCommitment(ISS, mutated)).toBe(
      "sha-256:3ZcZC8vR2HiCkgZqop_fUBaAwmj6hLknF8ey9g44dD8",
    );
    expect(verifyApprovalContextCommitment(disclosed, ISS, mutated)).toBe(false);
  });

  it("vector 6: rejects a value committed under a different typ", () => {
    const manifest = approvalContextManifest({ ...ALWAYS_PRESENT, proposal_hash: PROPOSAL_HASH });
    const correctTyp = approvalContextCommitment(ISS, manifest);
    const wrongTyp = computeAnchor("mission-approval-context-v2", ISS, manifest);
    expect(correctTyp).toBe("sha-256:7ikugIQZvSkie-Pc25V_sJKGHU5HGymVfrnMaIc8So0");
    expect(wrongTyp).toBe("sha-256:KSLVjgQRCWLHsswYmBJS2B_n0SPRAZjTvBnkIRqw-aw");
    expect(wrongTyp).not.toBe(correctTyp);
    // A verifier's recompute is fixed to mission-approval-context-v1; presented
    // with wrongTyp as if it were the disclosed commitment, it still mismatches.
    expect(verifyApprovalContextCommitment(wrongTyp, ISS, manifest)).toBe(false);
  });
});
