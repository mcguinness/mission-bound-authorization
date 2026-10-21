/**
 * @spec authzen#context-approval (#249, D553): an approval binds the resource
 * contract reference through the approved Resource. "Where a resource
 * contract applies to the action, the approval binds its reference through
 * the approved Resource, which ARAP requires the approval record or its
 * binding material to contain." The Access Request Service takes the
 * reference from the PDP-signed denial binding, never from the submission,
 * and the approval it mints carries it at `resource.properties`.
 */

import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import { AccessRequestService } from "../src/index.js";

const CONTRACT = {
  id: "https://payments.example/contracts/payments",
  version: "2026-10-20",
  digest: `sha-256:${Buffer.alloc(32, 9).toString("base64url")}`,
};

async function setup() {
  const pdp = await generateKeyPair("ES256", { extractable: true });
  const approval = await generateKeyPair("ES256", { extractable: true });
  const ars = new AccessRequestService({
    pdpJwks: { keys: [{ ...(await exportJWK(pdp.publicKey)), kid: "pdp-denial" }] },
    approvalKey: approval.privateKey,
    approvalKid: "ars-approval",
    issuer: "https://ars.test",
    approvalAudience: "https://pdp.test",
  });
  const binding = (claims: Record<string, unknown>) =>
    new SignJWT({ decision_id: "dec_1", mission_id: "msn_1", action: "payments:payment.execute", parameter_digest: "sha-256:p", ...claims })
      .setProtectedHeader({ alg: "ES256", kid: "pdp-denial", typ: "pdp-denial-binding+jwt" })
      .setIssuedAt()
      .setExpirationTime("5m")
      .sign(pdp.privateKey);
  const requested = { action: "payments:payment.execute", mission_id: "msn_1", parameter_digest: "sha-256:p", subject: "alice" };
  return { ars, binding, requested };
}

describe("the approval binds the denied request's contract reference through the approved Resource (@spec authzen#context-approval, #249)", () => {
  it("carries the reference the PDP signed into the approval's resource.properties, and none where no contract applied", async () => {
    const { ars, binding, requested } = await setup();
    const bound = await ars.submit({ binding_token: await binding({ resource_contract: CONTRACT }), requested });
    expect((await ars.adjudicate(bound.taskId, "approve", "bob"))?.resource).toEqual({
      properties: { resource_contract: CONTRACT },
    });
    const plain = await ars.submit({ binding_token: await binding({}), requested });
    expect(await ars.adjudicate(plain.taskId, "approve", "bob")).not.toHaveProperty("resource");
  });
});
