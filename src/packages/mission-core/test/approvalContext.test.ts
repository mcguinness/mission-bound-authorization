import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  type ApprovalContextManifestInput,
  type AuthorityEntry,
  approvalContextCommitment,
  approvalContextManifest,
  computeAnchor,
  isSubsetSetIgnoringCapabilitySources,
  submissionEvidenceCommitment,
  verifyApprovalContextCommitment,
} from "../src/index.js";

const ISS = "https://as.example.com";

// The canonical baseline Mission (#1176 item 5), whose Authority Set the
// vectors' always-present members commit.
const BASELINE_AUTHORITY_SET = (
  JSON.parse(
    readFileSync(
      fileURLToPath(new URL("../../../../vectors/baseline-q3/baseline-q3.json", import.meta.url)),
      "utf8",
    ),
  ) as { record: { authority_set: AuthorityEntry[] } }
).record.authority_set;

// approval-governance § approval-context-vectors: the always-present members,
// reused byte-exact from core's canonical Worked Example Mission Record.
const ALWAYS_PRESENT = {
  issuer: ISS,
  id: "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
  intent_hash: "sha-256:6T-7s_f-mNW9UpfrrZh3r0HRJmU4My_EsNAf1C1U4r0",
  authority_hash: "sha-256:hjXlwWBY64-RPs1Z-E_gbyklNcViI5c9jiyMbE4KvFM",
  subject: { iss: "https://idp.example.com", sub: "user_3p2q8mN1a0kV7tR" },
  approver: { iss: "https://idp.example.com", sub: "user_3p2q8mN1a0kV7tR" },
  client_id: "s6BhdRkqt3",
  created_at: "2026-11-02T08:00:00Z",
  expires_at: "2026-12-31T23:59:59Z",
  approval_basis: {
    type: "direct",
    consent_principal: { iss: "https://idp.example.com", sub: "user_3p2q8mN1a0kV7tR" },
    activation: { approval_event_id: "ape_8K2nP4qV9rL3tY6sB1z" },
    activation_actor: { iss: "https://idp.example.com", sub: "user_3p2q8mN1a0kV7tR" },
    adjudication: { kind: "human" },
    root_commitment: "sha-256:hjXlwWBY64-RPs1Z-E_gbyklNcViI5c9jiyMbE4KvFM",
  },
  authority_source: { type: "user_delegated" },
  policy_version: "deploy-policy:v17",
  approval_event_id: "ape_8K2nP4qV9rL3tY6sB1z",
} satisfies Omit<
  ApprovalContextManifestInput,
  "proposal_hash" | "ceiling_hash" | "submission_evidence_commitment"
>;

const PROPOSAL_HASH = "sha-256:p-s-EzdNQTn6RoPHXESkwVtGdk8yL1PxryNyMwroKGo";

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
      "sha-256:dPaMl8eUhPExoiVA2zHbz4wPzmDLVsfZnHDxCYHDGos",
    );
  });

  it("vector 2: conditional proposal_hash (= core's canonical worked example)", () => {
    const manifest = approvalContextManifest({ ...ALWAYS_PRESENT, proposal_hash: PROPOSAL_HASH });
    expect(approvalContextCommitment(ISS, manifest)).toBe(
      "sha-256:pGxfIDuyBPfgpyox3J6GP477CQfUE6FS9CfHirjwwvU",
    );
  });

  it("vector 3: conditional ceiling_hash", () => {
    // Progressive's own ceiling_hash construction (draft-mcguinness-oauth-mission-progressive
    // § progressive-authorization): typ mission-authority-ceiling over
    // {authority_ceiling, drawdown_policy}.
    const authorityCeiling: AuthorityEntry[] = [
      {
        type: "mission_resource_access",
        resource: "https://erp.example.com",
        actions: ["invoices.read"],
        delegation: { max_depth: 2, allowed_delegates: [{ sub_profile: "ai_agent" }] },
      },
      {
        type: "mission_resource_access",
        resource: "https://erp.example.com",
        actions: ["invoices.write", "journal-entries.write"],
      },
    ];
    // The vector says its ceiling covers the baseline Authority Set, its read
    // delegation included (#1395 review).
    expect(isSubsetSetIgnoringCapabilitySources(BASELINE_AUTHORITY_SET, authorityCeiling)).toBe(
      true,
    );

    const ceilingHash = computeAnchor("mission-authority-ceiling", ISS, {
      authority_ceiling: authorityCeiling,
      drawdown_policy: {
        id: "erp-drawdown",
        version: "1",
        digest: "sha-256:_hLEAl_ir1vxnex2tgbS6eRR99lyL1r6yyeB4RrC184",
      },
    });
    expect(ceilingHash).toBe("sha-256:I0TgJBsdSkkmaHt4EayPfIjs8uoYiuQvP_O5b9Tlec8");

    const manifest = approvalContextManifest({ ...ALWAYS_PRESENT, ceiling_hash: ceilingHash });
    expect(approvalContextCommitment(ISS, manifest)).toBe(
      "sha-256:85y0i-t8pwRsM-SwHgZ9EaBIQFbnWjYDjBNEO1TTQWA",
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
      verified_at: "2026-11-02T07:59:39Z",
      facts: {
        admission_issuer: "https://admission.example.com",
        status: "active",
      },
    };
    const submissionEvidenceHash = submissionEvidenceCommitment(ISS, [recordedElement]);
    expect(submissionEvidenceHash).toBe("sha-256:jnXhfVteWUHvc1-wyJOMLaVFj-d8ewQWE4R7f0t5otY");

    const manifest = approvalContextManifest({
      ...ALWAYS_PRESENT,
      submission_evidence_commitment: submissionEvidenceHash,
    });
    expect(approvalContextCommitment(ISS, manifest)).toBe(
      "sha-256:iYBvYGC_LpEQkhpPiIE3S1OFINjH2dK0jYMrCwWHvKE",
    );
  });
});

describe("Approval Context Commitment verification (approval-governance § approval-context-computation)", () => {
  it("vector 5: rejects a mutated member (recomputed digest differs)", () => {
    const disclosed = "sha-256:pGxfIDuyBPfgpyox3J6GP477CQfUE6FS9CfHirjwwvU"; // vector 2
    const mutated = approvalContextManifest({
      ...ALWAYS_PRESENT,
      proposal_hash: PROPOSAL_HASH,
      approval_event_id: "ape_9K2nP4qV9rL3tY6sB1z",
    });
    expect(approvalContextCommitment(ISS, mutated)).toBe(
      "sha-256:4Ev4vJSv_VYjxB48tuJTsYKTSU81jfQRD48pOjazBf0",
    );
    expect(verifyApprovalContextCommitment(disclosed, ISS, mutated)).toBe(false);
  });

  it("vector 6: rejects a value committed under a different typ", () => {
    const manifest = approvalContextManifest({ ...ALWAYS_PRESENT, proposal_hash: PROPOSAL_HASH });
    const correctTyp = approvalContextCommitment(ISS, manifest);
    const wrongTyp = computeAnchor("mission-approval-context-v2", ISS, manifest);
    expect(correctTyp).toBe("sha-256:pGxfIDuyBPfgpyox3J6GP477CQfUE6FS9CfHirjwwvU");
    expect(wrongTyp).toBe("sha-256:Al8UIKy7q4_WlWem_O_6kInpGUoOp_NvPQj_YNO4zAY");
    expect(wrongTyp).not.toBe(correctTyp);
    // A verifier's recompute is fixed to mission-approval-context-v1; presented
    // with wrongTyp as if it were the disclosed commitment, it still mismatches.
    expect(verifyApprovalContextCommitment(wrongTyp, ISS, manifest)).toBe(false);
  });
});
