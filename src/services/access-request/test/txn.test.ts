/**
 * @spec txn-authorization#challenge-redemption, #offline-verification
 *
 * The Access Request Service's txn-workflow surface (openForTxn/getTask):
 * the AS's D37 delegation, where the AS owns the txn pending id and the ARS
 * owns the approval. No OpenFGA and no PDP-signed binding_token are
 * involved on this path (openForTxn does not call verifyBinding, unlike
 * submit()), so these tests run in-process with no reachability gate.
 */

import { generateKeyPair } from "jose";
import { beforeAll, describe, expect, it } from "vitest";
import type { TxnApprovalBinding } from "@mission/core";
import { txnApprovalBindingDigest } from "@mission/core";
import { AccessRequestService, TxnBindingConflictError, txnTaskId } from "../src/index.js";

const RESOURCE = "https://payments.example/mcp";
const OTHER_RESOURCE = "https://saas.example/mcp";

function bindingFor(over: Partial<TxnApprovalBinding> = {}): TxnApprovalBinding {
  return {
    resource: RESOURCE,
    txn: "txn_abc123",
    mission: { id: "msn_txn1", issuer: "https://as.test", authority_hash: "sha-256:mhash" },
    operation_type: "mission_resource_access",
    authorization_details: [
      { type: "mission_resource_access", resource: RESOURCE, actions: ["payments:payment.execute"] },
    ],
    parameter_digest: "sha-256:paramdigest",
    subject: "alice",
    client_id: "ap-agent",
    cnf_jkt: "jkt-1",
    ...over,
  };
}

let ars: AccessRequestService;

beforeAll(async () => {
  const approvalKeys = await generateKeyPair("ES256", { extractable: true });
  ars = new AccessRequestService({
    pdpJwks: { keys: [] },
    approvalKey: approvalKeys.privateKey,
    approvalKid: "ars-approval",
    issuer: "https://ars.test",
    approvalAudience: "https://as.test",
  });
});

describe("ARS txn workflow: opening and idempotent completion (@spec txn-authorization#challenge-redemption)", () => {
  it("opens a pending task, and a later open under the SAME binding resolves to the approved task (redemption path)", async () => {
    const binding = bindingFor();
    const digest = txnApprovalBindingDigest(binding);

    const opened = ars.openForTxn({
      txn: binding.txn,
      resource: binding.resource,
      missionId: binding.mission.id,
      action: "payments:payment.execute",
      parameter_digest: binding.parameter_digest,
      subject: binding.subject,
      binding,
      binding_digest: digest,
    });
    expect(opened.state).toBe("pending");
    expect(opened.taskId).toBe(txnTaskId(binding.resource, binding.txn));

    const approval = await ars.adjudicate(opened.taskId, "approve", "bob");
    expect(approval?.parameter_digest).toBe(binding.parameter_digest);

    // The Transaction Authorization Server completes the challenge by
    // recomputing the SAME digest from its own pinned state and opening
    // again: this is the idempotent retry the completion endpoint depends
    // on, and it MUST resolve to the one already-approved task, not a fresh
    // pending one.
    const reopened = ars.openForTxn({
      txn: binding.txn,
      resource: binding.resource,
      missionId: binding.mission.id,
      action: "payments:payment.execute",
      parameter_digest: binding.parameter_digest,
      subject: binding.subject,
      binding,
      binding_digest: digest,
    });
    expect(reopened.taskId).toBe(opened.taskId);
    expect(reopened.state).toBe("approved");

    const task = ars.getTask(reopened.taskId);
    expect(task?.state).toBe("approved");
    expect(task?.approval?.binding_digest).toBe(digest);
    expect(task?.approval?.id).toBe(approval?.id);
  });

  it("refuses a second open of the same (resource, txn) under a DIFFERENT transaction binding", () => {
    const binding = bindingFor({ txn: "txn_conflict" });
    const digest = txnApprovalBindingDigest(binding);
    const opened = ars.openForTxn({
      txn: binding.txn,
      resource: binding.resource,
      missionId: binding.mission.id,
      action: "payments:payment.execute",
      parameter_digest: binding.parameter_digest,
      subject: binding.subject,
      binding,
      binding_digest: digest,
    });
    expect(opened.state).toBe("pending");

    // Same correlation identity (resource, txn), but a DIFFERENT complete
    // transaction (a different client here): resolving it to the first
    // binding's approval would hand this operation one adjudicated for
    // something else, so it fails closed instead.
    const conflicting = bindingFor({ txn: binding.txn, client_id: "other-agent" });
    const conflictingDigest = txnApprovalBindingDigest(conflicting);
    expect(conflictingDigest).not.toBe(digest);

    try {
      ars.openForTxn({
        txn: binding.txn,
        resource: binding.resource,
        missionId: binding.mission.id,
        action: "payments:payment.execute",
        parameter_digest: binding.parameter_digest,
        subject: binding.subject,
        binding: conflicting,
        binding_digest: conflictingDigest,
      });
      expect.unreachable();
    } catch (e) {
      expect(e).toBeInstanceOf(TxnBindingConflictError);
      expect((e as TxnBindingConflictError).code).toBe("txn_binding_conflict");
      expect((e as TxnBindingConflictError).taskId).toBe(opened.taskId);
    }
  });
});

describe("ARS txn correlation identity (@spec txn-authorization#offline-verification)", () => {
  it("scopes the txn correlation identity to the resource: the same txn under two different resources opens two different tasks", () => {
    const same_txn = "txn_shared_across_resources";
    const bindingA = bindingFor({ txn: same_txn, resource: RESOURCE });
    const bindingB = bindingFor({ txn: same_txn, resource: OTHER_RESOURCE });

    const openedA = ars.openForTxn({
      txn: same_txn,
      resource: RESOURCE,
      missionId: bindingA.mission.id,
      action: "payments:payment.execute",
      parameter_digest: bindingA.parameter_digest,
      subject: bindingA.subject,
      binding: bindingA,
      binding_digest: txnApprovalBindingDigest(bindingA),
    });
    const openedB = ars.openForTxn({
      txn: same_txn,
      resource: OTHER_RESOURCE,
      missionId: bindingB.mission.id,
      action: "payments:payment.execute",
      parameter_digest: bindingB.parameter_digest,
      subject: bindingB.subject,
      binding: bindingB,
      binding_digest: txnApprovalBindingDigest(bindingB),
    });

    expect(openedA.taskId).not.toBe(openedB.taskId);
    expect(openedA.taskId).toBe(txnTaskId(RESOURCE, same_txn));
    expect(openedB.taskId).toBe(txnTaskId(OTHER_RESOURCE, same_txn));
  });
});
