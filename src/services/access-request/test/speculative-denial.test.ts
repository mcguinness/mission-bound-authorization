/**
 * @spec authzen#speculative-evaluations, authzen#requestable-denials (#2067,
 * D1313): a speculative deny the PDP would mark requestable may carry
 * `context.access_request`. Its PDP-signed denial binding names the
 * speculative item, never an evaluation, and marks itself speculative, so it
 * is distinguishable from the binding of an execution decision. The
 * speculation itself starts no approval workflow: the Access Request Service
 * holds no task until the requester submits the request in a separate step.
 *
 * The PDP runs in process with a stub OpenFGA on a controlled clock, so this
 * file never skips.
 */

import { currentContractRef, pinnedToCurrentContract } from "@mission/demo-data";
import {
  type EvaluateOptions,
  type Fga,
  type MissionView,
  relationForAction,
  type SpeculativeEvaluationRequest,
  speculate,
  stalenessBound,
} from "@mission/pdp";
import { OPERATION_DECLARATIONS_NONE_FIXTURE, RESOURCE_POLICY_PERMITS_ALL_FIXTURE } from "@mission/pdp/test-support";
import { type CryptoKey, decodeJwt, exportJWK, generateKeyPair, type JWK } from "jose";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { AccessRequestService } from "../src/index.js";

// date-literal: controlled-clock
const CLOCK_MS = Date.parse("2026-11-16T12:00:00Z");
const RESOURCE = "http://localhost:4403/mcp";
const ACTION = "payments:payment.execute";
const ISSUER = "https://as.test";
const CONTRACT = currentContractRef({ resource: RESOURCE, actions: [ACTION] });
const DIGEST = `sha-256:${Buffer.alloc(32, 4).toString("base64url")}`;

const VIEW: MissionView = {
  id: "msn_2067_speculative_denial",
  issuer: ISSUER,
  state: "active",
  version: 1,
  authority_hash: "sha-256:speculative-denial",
  authority_set: [pinnedToCurrentContract({ type: "mission_resource_access", resource: RESOURCE, actions: [ACTION] })],
  subject: { iss: ISSUER, sub: "alice" },
  client_id: "ap-agent",
};

let pdpKey: CryptoKey;
let pdpJwk: JWK;
let arsKey: CryptoKey;

beforeAll(async () => {
  vi.useFakeTimers({ toFake: ["Date"], shouldAdvanceTime: true });
  vi.setSystemTime(CLOCK_MS);
  const pdp = await generateKeyPair("ES256", { extractable: true });
  pdpKey = pdp.privateKey;
  pdpJwk = { ...(await exportJWK(pdp.publicKey)), kid: "pdp-denial", alg: "ES256" };
  arsKey = (await generateKeyPair("ES256", { extractable: true })).privateKey;
});

afterAll(() => {
  vi.useRealTimers();
});

/** The PDP: deployment policy gates the action on an approval, and its denials are requestable. */
const options = (): EvaluateOptions => ({
  view: VIEW,
  fga: { checkWithContext: async () => true } as unknown as Fga,
  modelId: "model-speculative-denial",
  now: () => new Date(),
  stalenessBound,
  relationForAction,
  resourcePolicy: RESOURCE_POLICY_PERMITS_ALL_FIXTURE,
  operationDeclarations: OPERATION_DECLARATIONS_NONE_FIXTURE,
  requiresActionApproval: () => true,
  maxApprovalAgeSeconds: 300,
  requestable: { sign: pdpKey, kid: "pdp-denial", endpoint: "https://ars.test/access-requests" },
});

const speculation = (): SpeculativeEvaluationRequest => ({
  context: { mission: { id: VIEW.id, issuer: VIEW.issuer } },
  items: [
    {
      id: "pay-acme",
      subject: { id: "alice" },
      resource: {
        type: "invoice",
        id: "inv-1",
        properties: { audience: RESOURCE, operation_target: RESOURCE, vendor_id: "acme", ...(CONTRACT ? { resource_contract: CONTRACT } : {}) },
      },
      action: { name: ACTION },
      context: {
        action_class: "consequential_read",
        credential: {
          authority: [
            { type: "mission_resource_access", resource: RESOURCE, actions: [ACTION], ...(CONTRACT ? { resource_contract: CONTRACT } : {}) },
          ],
        },
        amount: { amount: "125.00", currency: "USD" },
        parameter_digest: DIGEST,
      },
    },
  ],
});

const taskCount = (ars: AccessRequestService): number =>
  (ars.db.prepare("SELECT COUNT(*) AS n FROM tasks").get() as { n: number }).n;

describe("a requestable speculative deny and the approval workflow (@spec authzen#speculative-evaluations, authzen#requestable-denials, #2067)", () => {
  it("a requestable speculative deny may carry an access_request whose denial binding marks itself speculative, and the speculation itself opens no Access Request Service task", async () => {
    const ars = new AccessRequestService({
      pdpJwks: { keys: [pdpJwk] },
      approvalKey: arsKey,
      approvalKid: "ars-approval",
      issuer: "https://ars.test",
      approvalAudience: "https://pdp.test",
      now: () => new Date(),
      // A permissive auto-approval policy: were the speculation to submit
      // anything, a task would open and approve at once.
      autoApprove: () => true,
    });
    expect(taskCount(ars)).toBe(0);

    const { items } = await speculate(speculation(), options());
    const [denied] = items;
    expect(denied?.decision).toBe(false);
    expect(denied?.context.reason).toBe("action_approval_required");
    // A preview, never an evaluation: no identifier to redeem or reference.
    expect(denied?.context.evaluation_id).toBeUndefined();
    const ar = denied?.context.access_request as { binding_token: string; denial_binding: string } | undefined;
    expect(ar?.binding_token).toEqual(expect.any(String));

    // The binding names the speculative item and marks itself speculative.
    const binding = decodeJwt(ar?.binding_token ?? "");
    expect(binding.speculative).toBe(true);
    expect(String(binding.decision_id)).toMatch(/^spc_/);
    expect(binding).toMatchObject({ mission_id: VIEW.id, mission_issuer: VIEW.issuer, action: ACTION, parameter_digest: DIGEST });

    // The speculation started no approval workflow.
    expect(taskCount(ars)).toBe(0);
    expect(ars.pending()).toEqual([]);

    // Submitting it is the requester's own, separate step, and the task it
    // opens carries the speculative item's identifier, not an evaluation's.
    const { taskId } = await ars.submit({
      binding_token: ar?.binding_token ?? "",
      requested: { action: ACTION, mission_id: VIEW.id, parameter_digest: DIGEST, subject: "alice" },
    });
    expect(taskId).toMatch(/^arq_spc_/);
    expect(taskCount(ars)).toBe(1);
  });
});
