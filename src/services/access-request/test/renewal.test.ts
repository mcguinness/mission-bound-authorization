/**
 * @spec authzen#requestable-denials, authzen#response-context (#2067, D1328):
 * an `out_of_scope` or `approval_expired` re-evaluation denial is requestable
 * for a replacement approval. The access request it carries is bound to the
 * denied evaluation; the Access Request Service turns it into a new approval
 * that satisfies only a fresh evaluation, and the approval it replaces stays
 * insufficient. Synchronous auto-approval never approves a high-consequence
 * request without an independent approver, whatever the denial reason, and a
 * submission without a binding token that verifies is refused.
 *
 * The PDP runs in process with a stub OpenFGA, so this file never skips.
 */

import { currentContractRef, pinnedToCurrentContract } from "@mission/demo-data";
import {
  type ActionApproval,
  ARAP_APPROVAL_TYP,
  type Decision,
  type EvaluateOptions,
  type EvaluationRequest,
  evaluate,
  type Fga,
  type MissionView,
  relationForAction,
  stalenessBound,
} from "@mission/pdp";
import { OPERATION_DECLARATIONS_NONE_FIXTURE, RESOURCE_POLICY_PERMITS_ALL_FIXTURE } from "@mission/pdp/test-support";
import { type CryptoKey, decodeJwt, exportJWK, generateKeyPair, type JWK, SignJWT } from "jose";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { AccessRequestService, AUTO_APPROVER, type AutoApprovalRequest } from "../src/index.js";

// date-literal: controlled-clock
const START_MS = Date.parse("2026-10-20T12:00:00Z");
let clockMs = START_MS;
const now = () => new Date(clockMs);
const advance = (seconds: number) => {
  clockMs += seconds * 1000;
  vi.setSystemTime(clockMs);
};

const RESOURCE = "http://localhost:4403/mcp";
const ACTION = "payments:payment.execute";
const ISSUER = "https://as.test";
const ARS_ISS = "https://ars.test";
const PDP_AUD = "https://pdp.test";
const CONTRACT = currentContractRef({ resource: RESOURCE, actions: [ACTION] });
const digest = (n: number) => `sha-256:${Buffer.alloc(32, n).toString("base64url")}`;

const VIEW: MissionView = {
  id: "msn_2067_renewal",
  issuer: ISSUER,
  state: "active",
  version: 1,
  authority_hash: "sha-256:renewal",
  authority_set: [pinnedToCurrentContract({ type: "mission_resource_access", resource: RESOURCE, actions: [ACTION] })],
  subject: { iss: ISSUER, sub: "alice" },
  client_id: "ap-agent",
};

let pdpKey: CryptoKey;
let pdpJwk: JWK;
let arsKey: CryptoKey;
let arsJwk: JWK;

beforeAll(async () => {
  vi.useFakeTimers({ toFake: ["Date"], shouldAdvanceTime: true });
  vi.setSystemTime(START_MS);
  const pdp = await generateKeyPair("ES256", { extractable: true });
  pdpKey = pdp.privateKey;
  pdpJwk = { ...(await exportJWK(pdp.publicKey)), kid: "pdp-denial", alg: "ES256" };
  const approval = await generateKeyPair("ES256", { extractable: true });
  arsKey = approval.privateKey;
  arsJwk = { ...(await exportJWK(approval.publicKey)), kid: "ars-approval", alg: "ES256" };
});

afterAll(() => {
  vi.useRealTimers();
});

const service = (autoApprove?: (request: AutoApprovalRequest) => boolean) =>
  new AccessRequestService({
    pdpJwks: { keys: [pdpJwk] },
    approvalKey: arsKey,
    approvalKid: "ars-approval",
    issuer: ARS_ISS,
    approvalAudience: PDP_AUD,
    now,
    ...(autoApprove ? { autoApprove } : {}),
  });

/** The PDP: deployment policy gates the action on an approval, and its denials are requestable. */
const options = (): EvaluateOptions => ({
  view: VIEW,
  fga: { checkWithContext: async () => true } as unknown as Fga,
  modelId: "model-renewal",
  now,
  stalenessBound,
  relationForAction,
  resourcePolicy: RESOURCE_POLICY_PERMITS_ALL_FIXTURE,
  operationDeclarations: OPERATION_DECLARATIONS_NONE_FIXTURE,
  requiresActionApproval: () => true,
  maxApprovalAgeSeconds: 300,
  requestable: { sign: pdpKey, kid: "pdp-denial", endpoint: "https://ars.test/access-requests" },
  approvalVerification: {
    issuers: [{ typ: ARAP_APPROVAL_TYP, issuer: ARS_ISS, audience: PDP_AUD, keys: { keys: [arsJwk] } }],
  },
});

const request = (parameterDigest: string, approval?: ActionApproval): EvaluationRequest => ({
  subject: { id: "alice" },
  resource: {
    type: "invoice",
    id: "inv-1",
    properties: { audience: RESOURCE, operation_target: RESOURCE, vendor_id: "acme", ...(CONTRACT ? { resource_contract: CONTRACT } : {}) },
  },
  action: { name: ACTION },
  context: {
    mission: { id: VIEW.id, issuer: VIEW.issuer, authority_hash: VIEW.authority_hash },
    action_class: "consequential_read",
    credential: {
      authority: [
        { type: "mission_resource_access", resource: RESOURCE, actions: [ACTION], ...(CONTRACT ? { resource_contract: CONTRACT } : {}) },
      ],
    },
    amount: { amount: "125.00", currency: "USD" },
    parameter_digest: parameterDigest,
    ...(approval ? { action_approval: approval } : {}),
  },
});

/** Submit the denial's access request and have an independent approver grant it. */
async function approveOn(ars: AccessRequestService, denied: Decision, parameterDigest: string): Promise<ActionApproval> {
  const ar = denied.context.access_request as { binding_token: string } | undefined;
  if (!ar) throw new Error(`no access_request on ${JSON.stringify(denied.context)}`);
  const { taskId, state } = await ars.submit({
    binding_token: ar.binding_token,
    requested: { action: ACTION, mission_id: VIEW.id, parameter_digest: parameterDigest, subject: "alice" },
  });
  expect(state).toBe("pending");
  const approval = await ars.adjudicate(taskId, "approve", "bob");
  if (!approval) throw new Error("no approval");
  return approval;
}

describe("a replacement approval through the Access Request Service (@spec authzen#requestable-denials, #2067, D1328)", () => {
  it("out_of_scope after a parameter change: the access request it carries yields a replacement approval that satisfies a fresh evaluation, and the approval it replaced stays insufficient", async () => {
    const ars = service();
    const before = digest(1);
    const after = digest(2);
    const first = await approveOn(ars, await evaluate(request(before), options()), before);
    expect((await evaluate(request(before, first), options())).decision).toBe(true);
    // The parameters change: the approval no longer covers them.
    const denied = await evaluate(request(after, first), options());
    expect(denied.context.denial_reason).toBe("out_of_scope");
    expect(denied.context.next_action).toBe("request");
    const replacement = await approveOn(ars, denied, after);
    expect(replacement.parameter_digest).toBe(after);
    // The approval it replaced is still insufficient on a fresh evaluation.
    const stale = await evaluate(request(after, first), options());
    expect(stale.decision).toBe(false);
    expect(stale.context.denial_reason).toBe("out_of_scope");
    // The replacement satisfies a fresh evaluation against current state.
    const permitted = await evaluate(request(after, replacement), options());
    expect(permitted.decision, JSON.stringify(permitted.context)).toBe(true);
  });

  it("approval_expired: the access request it carries yields a renewed approval that satisfies a fresh evaluation, and the expired one stays insufficient", async () => {
    const ars = service();
    const params = digest(4);
    const first = await approveOn(ars, await evaluate(request(params), options()), params);
    expect((await evaluate(request(params, first), options())).decision).toBe(true);
    // Past the 300-second maximum age (and the approval's own approved_until).
    advance(301);
    const denied = await evaluate(request(params, first), options());
    expect(denied.context.denial_reason).toBe("approval_expired");
    expect(denied.context.next_action).toBe("request");
    const renewed = await approveOn(ars, denied, params);
    const stale = await evaluate(request(params, first), options());
    expect(stale.decision).toBe(false);
    expect(stale.context.denial_reason).toBe("approval_expired");
    const permitted = await evaluate(request(params, renewed), options());
    expect(permitted.decision, JSON.stringify(permitted.context)).toBe(true);
  });
});

/** A PDP-signed denial binding, as the reference PDP signs one. */
const bindingFor = (claims: Record<string, unknown>, key: CryptoKey = pdpKey) =>
  new SignJWT({
    decision_id: `dec_${Math.random().toString(36).slice(2)}`,
    mission_id: VIEW.id,
    mission_issuer: VIEW.issuer,
    action: ACTION,
    parameter_digest: digest(7),
    ...claims,
  })
    .setProtectedHeader({ alg: "ES256", kid: "pdp-denial", typ: "pdp-denial-binding+jwt" })
    .setIssuedAt()
    .setExpirationTime("5m")
    .sign(key);
const requested = { action: ACTION, mission_id: VIEW.id, parameter_digest: digest(7), subject: "alice" };

describe("synchronous auto-approval is bounded by the independent-approver rule, renewal requests included (@spec authzen#requestable-denials, #2067, D1328)", () => {
  it("in a high-consequence class, an out_of_scope or approval_expired renewal request, like an approval_required one, is never auto-approved and waits for an independent approver; outside those classes the same requests auto-approve", async () => {
    const ars = service(() => true);
    for (const reason of ["out_of_scope", "approval_expired", "action_approval_required"]) {
      for (const cls of ["irreversible_action", "external_commitment", "privileged_administration"]) {
        const { taskId, state } = await ars.submit({ binding_token: await bindingFor({ reason, action_classes: [cls] }), requested });
        expect(state, `${reason} ${cls}`).toBe("pending");
        expect(ars.getTask(taskId)?.approval, `${reason} ${cls}`).toBeUndefined();
        expect(ars.pending().map((t) => t.id), `${reason} ${cls}`).toContain(taskId);
      }
      const { taskId, state } = await ars.submit({
        binding_token: await bindingFor({ reason, action_classes: ["consequential_read"] }),
        requested,
      });
      expect(state, `${reason} consequential_read`).toBe("approved");
      // Recorded as the policy's approval, not an approver's.
      const approvalState = ars.getTask(taskId)?.approval?.state as string;
      expect(decodeJwt(approvalState).approver, `${reason} consequential_read`).toBe(AUTO_APPROVER);
    }
  });

  it("a request whose binding names no action classes, or no reason, is never auto-approved", async () => {
    const ars = service(() => true);
    for (const claims of [{ reason: "out_of_scope" }, { action_classes: ["irreversible_action"] }, {}]) {
      const { state } = await ars.submit({ binding_token: await bindingFor(claims), requested });
      expect(state, JSON.stringify(claims)).toBe("pending");
    }
  });
});

describe("next_action request without an access_request authorizes no submission (@spec authzen#response-context, #2067, D1328)", () => {
  it("refuses a submission whose binding token is absent or does not verify under the PDP's key", async () => {
    const ars = service(() => true);
    const otherKey = (await generateKeyPair("ES256")).privateKey;
    await expect(ars.submit({ binding_token: "", requested })).rejects.toThrow();
    await expect(
      ars.submit({ binding_token: await bindingFor({ reason: "out_of_scope", action_classes: ["consequential_read"] }, otherKey), requested }),
    ).rejects.toThrow();
    expect(ars.pending()).toHaveLength(0);
  });
});
