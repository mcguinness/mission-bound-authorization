/**
 * @spec draft-mcguinness-mission-runtime-evidence.md#pre-decision-refusal,
 * #request-digest-worked (issue #971).
 *
 * A Refusal Record without `parameter_digest` carries
 * `evaluation_request_digest` and names the input it covers in
 * `request_digest_input`: the evaluation request as submitted when the
 * refusal follows one, the pre-request input when it precedes one. A
 * parameter-bound refusal carries `parameter_digest` and neither member.
 */

import { canonicalDigest } from "@mission/core";
import { describe, expect, it } from "vitest";
import { CANONICAL_RESOURCE, createEphemeralEvidenceKeys, EvidenceStore } from "../src/index.js";
import { RESOURCE_POLICY_PERMITS_ALL_FIXTURE } from "@mission/pdp/test-support";

const MISSION = { id: "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-", issuer: "https://as.test", authority_hash: "sha-256:fixture" };

function store() {
  const keys = createEphemeralEvidenceKeys({ resourcePolicy: RESOURCE_POLICY_PERMITS_ALL_FIXTURE });
  return new EvidenceStore(keys.signing, keys.resolver);
}

const base = {
  missionId: MISSION.id,
  audience: CANONICAL_RESOURCE,
  action: { name: "journal-entries.read" },
  denial_reason: "out_of_authority",
};

describe("Refusal Record request digest input (@spec runtime-evidence#request-digest-worked, #971)", () => {
  it("a refusal before any request digests the pre-request input, with mission_id exactly when the record carries mission", async () => {
    const evidence = store();
    const established = await evidence.recordRefusal(CANONICAL_RESOURCE, "pep", {
      ...base,
      mission: MISSION,
      resource: { type: "journal-entry", id: "je_2026Q3_inv_8421" },
      subject: { id: "user_3p2q8mN1a0kV7tR" },
    });
    expect(established.content).toMatchObject({
      request_digest_input: "pre_request",
      evaluation_request_digest: canonicalDigest({
        action: "journal-entries.read",
        audience: CANONICAL_RESOURCE,
        mission_id: MISSION.id,
        resource: "je_2026Q3_inv_8421",
        subject: "user_3p2q8mN1a0kV7tR",
      }),
    });

    // No established Mission and no known resource: those members are
    // absent from the input, never present as "".
    const unestablished = await evidence.recordRefusal(CANONICAL_RESOURCE, "pep", { ...base, subject: { id: "user_3p2q8mN1a0kV7tR" } });
    expect(unestablished.content).not.toHaveProperty("mission");
    expect(unestablished.content).toMatchObject({
      request_digest_input: "pre_request",
      evaluation_request_digest: canonicalDigest({ action: "journal-entries.read", audience: CANONICAL_RESOURCE, subject: "user_3p2q8mN1a0kV7tR" }),
    });
  });

  it("a refusal after an evaluation request digests that request as submitted and names decision_request", async () => {
    const request = {
      subject: { type: "user", id: "user_3p2q8mN1a0kV7tR" },
      resource: { type: "journal-entry", id: "je_2026Q3_inv_8421", properties: { audience: CANONICAL_RESOURCE } },
      action: { name: "journal-entries.read" },
      context: { mission: { id: MISSION.id, issuer: MISSION.issuer }, deployment_extension: null },
    };
    const refusal = await store().recordRefusal(CANONICAL_RESOURCE, "pep", { ...base, mission: MISSION, evaluation_request: request });
    expect(refusal.content).toMatchObject({ request_digest_input: "decision_request", evaluation_request_digest: canonicalDigest(request) });
  });

  it("a parameter-bound refusal carries parameter_digest alone, with no request digest and no input name", async () => {
    const parameter_digest = canonicalDigest({ invoice_id: "inv-1" });
    const refusal = await store().recordRefusal(CANONICAL_RESOURCE, "pep", { ...base, mission: MISSION, parameter_digest });
    expect(refusal.content.parameter_digest).toBe(parameter_digest);
    expect(refusal.content).not.toHaveProperty("evaluation_request_digest");
    expect(refusal.content).not.toHaveProperty("request_digest_input");
  });
});
