/**
 * @spec approval-governance#approval-context-computation,
 *       approval-governance#approval-context-carriage (#699)
 *
 * The two carriage guarantees the Approval Context Commitment profile places
 * on the issuance profile's own surfaces: `approval_context_commitment` is
 * never a Mission record member, and it is never carried on a Mission-bound
 * access token's baseline `mission` claim. The commitment itself is computed
 * on demand by `@mission/core`'s `approvalContextCommitment`
 * (packages/mission-core/src/approvalContext.ts); nothing here recomputes it,
 * and nothing in this kernel persists it.
 *
 * The profile's other must-not-carry site, the Mission Authority Server's
 * Join Assertion descriptor, has no minting path in this implementation (the
 * MAS Join is resolved by the PDP from a propagated reference, see
 * services/pdp/test/mas-join.test.ts), so only the baseline-claim half of
 * that rule is exercised here.
 */

import { DERIVATION_POLICY } from "@mission/demo-data";
import { generateKeyPair } from "jose";
import { beforeAll, describe, expect, it } from "vitest";
import { MissionKernel, type MissionRecord, validateMissionIntent } from "../src/index.js";

const ISS = "https://as.test";
const RESOURCE = DERIVATION_POLICY.ceiling[0].resource;
const MEMBER = "approval_context_commitment";

let kernel: MissionKernel;
let record: MissionRecord;

beforeAll(async () => {
  const { privateKey } = await generateKeyPair("ES256");
  kernel = new MissionKernel({
    issuer: ISS,
    policy: DERIVATION_POLICY as never,
    statusKey: privateKey,
    statusKid: "as-status",
  });
  record = kernel.approve({
    intent: validateMissionIntent(
      JSON.stringify({
        goal: "Pay Acme invoices for Q3",
        target_resources: [RESOURCE],
        expires_at: "2027-01-01T00:00:00Z",
      }),
    ),
    subject: { iss: ISS, sub: "alice" },
    approver: { iss: ISS, sub: "bob" },
    clientId: "ap-agent",
    approvalEventId: "apev-699",
  });
});

describe("Approval Context Commitment carriage (@spec approval-governance#approval-context-computation, #699)", () => {
  it("adds no Mission record member: a committed record carries no approval_context_commitment", () => {
    expect(record).not.toHaveProperty(MEMBER);
    expect(Object.keys(record)).not.toContain(MEMBER);
    // The ungated issuer view is every issuer-held record fact with no
    // disclosure privilege applied, so it is the widest projection of the
    // record: the commitment is absent there too, because the record never
    // holds it.
    expect(kernel.introspectionMission(record)).not.toHaveProperty(MEMBER);
  });
});

describe("Approval Context Commitment carriage (@spec approval-governance#approval-context-carriage, #699)", () => {
  it("is never carried on a Mission-bound access token's baseline mission claim", () => {
    const claim = kernel.missionClaim(record);
    expect(claim).not.toHaveProperty(MEMBER);
    expect(Object.keys(claim).sort()).toEqual(["id", "issuer"]);
  });
});
