/**
 * @spec authzen#context-approval (#2067, D1313): the Access Request Service
 * binds each approval to the qualified Mission identity, `issuer` and `id`,
 * the PDP-signed denial binding names (or, for a transaction challenge, the
 * AS-vouched binding names), and signs it into the approval `state` the PEP
 * presents. It never takes the identity from the submission. A denial
 * binding that names no Mission issuer is refused.
 */

import type { TxnApprovalBinding } from "@mission/core";
import { txnApprovalBindingDigest } from "@mission/core";
import { createLocalJWKSet, exportJWK, generateKeyPair, jwtVerify, SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import { AccessRequestService } from "../src/index.js";

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
    new SignJWT({ decision_id: "dec_1", action: "payments:payment.execute", parameter_digest: "sha-256:p", ...claims })
      .setProtectedHeader({ alg: "ES256", kid: "pdp-denial", typ: "pdp-denial-binding+jwt" })
      .setIssuedAt()
      .setExpirationTime("5m")
      .sign(pdp.privateKey);
  const stateClaims = async (state: string | undefined) =>
    (
      await jwtVerify(
        state as string,
        createLocalJWKSet({ keys: [{ ...(await exportJWK(approval.publicKey)), kid: "ars-approval" }] } as never),
        { issuer: "https://ars.test", audience: "https://pdp.test", typ: "arap-approval+jwt" },
      )
    ).payload;
  const requested = { action: "payments:payment.execute", mission_id: "msn_1", parameter_digest: "sha-256:p", subject: "alice" };
  return { ars, binding, stateClaims, requested };
}

describe("the approval state binds the qualified Mission identity (@spec authzen#context-approval, #2067)", () => {
  it("signs the issuer and id the PDP-signed denial binding names into the approval state it returns", async () => {
    const { ars, binding, stateClaims, requested } = await setup();
    const { taskId } = await ars.submit({
      binding_token: await binding({ mission_id: "msn_1", mission_issuer: "https://as.test" }),
      requested,
    });
    const approval = await ars.adjudicate(taskId, "approve", "bob");
    expect((await stateClaims(approval?.state)).mission).toEqual({ issuer: "https://as.test", id: "msn_1" });
    // The task record returns the same signed state.
    expect(ars.getTask(taskId)?.approval?.state).toBe(approval?.state);
  });

  it("refuses a denial binding that names no Mission issuer", async () => {
    const { ars, binding, requested } = await setup();
    await expect(ars.submit({ binding_token: await binding({ mission_id: "msn_1" }), requested })).rejects.toThrow(
      /Mission issuer/,
    );
  });

  it("binds a transaction-challenge task to the vouched transaction's Mission", async () => {
    const { ars, stateClaims } = await setup();
    const txn: TxnApprovalBinding = {
      resource: "https://payments.example/mcp",
      txn: "txn_2067",
      mission: { id: "msn_txn", issuer: "https://as.test" },
      operation_type: "mission_resource_access",
      authorization_details: [],
      parameter_digest: "sha-256:p",
      subject: "alice",
      client_id: "ap-agent",
      cnf_jkt: "jkt-1",
    };
    const { taskId } = ars.openForTxn({
      txn: txn.txn,
      resource: txn.resource,
      missionId: txn.mission.id,
      action: "payments:payment.execute",
      parameter_digest: txn.parameter_digest,
      subject: txn.subject,
      binding: txn,
      binding_digest: txnApprovalBindingDigest(txn),
    });
    const approval = await ars.adjudicate(taskId, "approve", "bob");
    expect((await stateClaims(approval?.state)).mission).toEqual({ issuer: "https://as.test", id: "msn_txn" });
  });
});
