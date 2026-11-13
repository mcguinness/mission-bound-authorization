/**
 * @spec authzen#context-approval, authzen#requestable-denials (#2067, D1313):
 * an action approval binds to the qualified Mission identity, `issuer` and
 * `id`, which the PDP establishes from integrity-protected approval material
 * (the Access Request Service's signed `state`) under its own trust anchors,
 * never from the request's `context.mission`. An approval bound to another
 * Mission, the predecessor of an expanded one included, is denied
 * `out_of_scope`; one whose binding cannot be established is denied
 * `approval_unverifiable`; neither is ever `action_approval_required`. After
 * an expansion the re-evaluation runs under the successor, and the expansion
 * supplies no action approval. A `parameter_violation` is never requestable.
 *
 * Pure unit test: `fga` is a stub satisfying the one method `evaluate` calls,
 * so this needs no OpenFGA and never skips.
 */

import { currentContractRef, pinnedToCurrentContract } from "@mission/demo-data";
import { type CryptoKey, decodeJwt, generateKeyPair } from "jose";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { createEphemeralDecisionPoint } from "../src/decision-point.js";
import {
  type ActionApproval,
  type DecisionOptions,
  type EvaluateOptions,
  type EvaluationRequest,
  evaluate as evaluateRequest,
} from "../src/evaluate.js";
import type { Fga } from "../src/fga.js";
import type { MissionView } from "../src/policy-view.js";
import { relationForAction, stalenessBound } from "../src/policy.js";
import {
  type ApprovalSignerFixture,
  approvalSignerFixture,
  OPERATION_DECLARATIONS_NONE_FIXTURE,
  RESOURCE_POLICY_PERMITS_ALL_FIXTURE,
} from "../src/test-support.js";
import { withCredential } from "./with-credential.js";

// date-literal: controlled-clock
const CLOCK_MS = Date.parse("2026-10-20T12:00:00Z");
const NOW = new Date(CLOCK_MS);
const RESOURCE = "http://localhost:4403/mcp";
const ACTION = "payments:payment.execute";
const ISSUER = "https://as.test";
const DIGEST = `sha-256:${Buffer.alloc(32, 9).toString("base64url")}`;
const CONTRACT = currentContractRef({ resource: RESOURCE, actions: [ACTION] });

const evaluate = (req: EvaluationRequest, opts: EvaluateOptions) => evaluateRequest(withCredential(req), opts);

const missionView = (id: string, issuer = ISSUER): MissionView => ({
  id,
  issuer,
  state: "active",
  version: 1,
  authority_hash: "sha-256:testhash",
  authority_set: [
    pinnedToCurrentContract({
      type: "mission_resource_access",
      resource: RESOURCE,
      actions: [ACTION],
      constraints: { max_amount: { amount: "500.00", currency: "USD" } },
    }),
  ],
  subject: { iss: ISSUER, sub: "alice" },
  client_id: "ap-agent",
});

const request = (mission: { id: string; issuer: string }, amount = "125.00", approval?: ActionApproval): EvaluationRequest => ({
  subject: { id: "alice" },
  resource: {
    type: "invoice",
    id: "inv-1",
    properties: {
      audience: RESOURCE,
      operation_target: RESOURCE,
      vendor_id: "acme",
      ...(CONTRACT ? { resource_contract: CONTRACT } : {}),
    },
  },
  action: { name: ACTION },
  context: {
    mission: { id: mission.id, issuer: mission.issuer, authority_hash: "sha-256:testhash" },
    amount: { amount, currency: "USD" },
    parameter_digest: DIGEST,
    ...(approval ? { action_approval: approval } : {}),
  },
});

const unsignedApproval = (): Omit<ActionApproval, "state"> => ({
  id: "apr_2067",
  approved_at: new Date(CLOCK_MS - 60_000).toISOString(),
  approved_until: new Date(CLOCK_MS + 240_000).toISOString(),
  parameter_digest: DIGEST,
  ...(CONTRACT ? { resource: { properties: { resource_contract: CONTRACT } } } : {}),
});

let ars: ApprovalSignerFixture;
let pdpDenialKey: CryptoKey;

/** Deployment policy gates the action on an approval; the denial is requestable. */
const gated = (view: MissionView, extra: Partial<EvaluateOptions> = {}): EvaluateOptions => ({
  view,
  fga: { checkWithContext: async () => true } as unknown as Fga,
  modelId: "model-1",
  now: () => NOW,
  stalenessBound,
  relationForAction,
  resourcePolicy: RESOURCE_POLICY_PERMITS_ALL_FIXTURE,
  operationDeclarations: OPERATION_DECLARATIONS_NONE_FIXTURE,
  requiresActionApproval: () => true,
  maxApprovalAgeSeconds: 300,
  requestable: { sign: pdpDenialKey, kid: "pdp-denial", endpoint: "https://ars.test/access-requests" },
  approvalVerification: ars.verification,
  ...extra,
});

beforeAll(async () => {
  vi.useFakeTimers({ toFake: ["Date"], shouldAdvanceTime: true });
  vi.setSystemTime(CLOCK_MS);
  ars = await approvalSignerFixture();
  pdpDenialKey = (await generateKeyPair("ES256")).privateKey;
});

afterAll(() => {
  vi.useRealTimers();
});

describe("an action approval binds the qualified Mission identity (@spec authzen#context-approval, #2067)", () => {
  const view = missionView("msn_2067");
  const bound = { issuer: view.issuer, id: view.id };

  it("a correctly bound approval satisfies the approval gate (positive control)", async () => {
    const approval = await ars.approve(unsignedApproval(), bound);
    const d = await evaluate(request(bound, "125.00", approval), gated(view));
    expect(d.decision, JSON.stringify(d.context)).toBe(true);
  });

  it("the binding is to the Mission's identity alone: it holds across a change of the Mission's version, and never stands in for the Mission's current state", async () => {
    // The material records the version the Mission had when the approval was
    // given; the binding reads only its identity.
    const observedAtApproval = { ...bound, version: view.version };
    const approval = await ars.approve(unsignedApproval(), observedAtApproval);
    const moved: MissionView = { ...view, version: view.version + 1, authority_hash: "sha-256:moved" };
    const req = request(bound, "125.00", approval);
    req.context.mission.authority_hash = "sha-256:moved";
    const d = await evaluate(req, gated(moved));
    expect(d.decision, JSON.stringify(d.context)).toBe(true);
    // The Mission's state is established at the re-evaluation, approval or not.
    const suspended = await evaluate(req, gated({ ...moved, state: "suspended" }));
    expect(suspended.decision).toBe(false);
    expect(suspended.context.denial_reason).toBe("mission_inactive");
  });

  it("an approval for the same Mission id under a different issuer does not satisfy the gate: out_of_scope", async () => {
    const approval = await ars.approve(unsignedApproval(), { issuer: "https://other-as.test", id: view.id });
    const d = await evaluate(request(bound, "125.00", approval), gated(view));
    expect(d.decision).toBe(false);
    expect(d.context.denial_reason).toBe("out_of_scope");
    expect(d.context.next_action).toBe("request");
    expect(d.context.conditions).toBeUndefined();
  });

  it("an approval whose state fails signature verification does not satisfy the gate: approval_unverifiable", async () => {
    const otherKey = (await generateKeyPair("ES256")).privateKey;
    const approval = await ars.approve(unsignedApproval(), bound, { signingKey: otherKey });
    const d = await evaluate(request(bound, "125.00", approval), gated(view));
    expect(d.decision).toBe(false);
    expect(d.context.denial_reason).toBe("approval_unverifiable");
    expect(d.context.next_action).toBe("none");
  });

  it("an approval whose state names the wrong issuer or audience does not satisfy the gate: approval_unverifiable", async () => {
    for (const override of [{ issuer: "https://rogue-ars.test" }, { audience: "https://another-pdp.test" }]) {
      const approval = await ars.approve(unsignedApproval(), bound, override);
      const d = await evaluate(request(bound, "125.00", approval), gated(view));
      expect(d.decision, JSON.stringify(override)).toBe(false);
      expect(d.context.denial_reason, JSON.stringify(override)).toBe("approval_unverifiable");
    }
  });

  it("an approval whose state carries no Mission claim does not satisfy the gate, although the request's context.mission names the Mission: approval_unverifiable", async () => {
    const approval = await ars.approve(unsignedApproval(), undefined);
    const req = request(bound, "125.00", approval);
    expect(req.context.mission).toMatchObject(bound);
    const d = await evaluate(req, gated(view));
    expect(d.decision).toBe(false);
    expect(d.context.denial_reason).toBe("approval_unverifiable");
    expect(d.context.next_action).toBe("none");
  });

  it("an approval presented with no state at all does not satisfy the gate: approval_unverifiable", async () => {
    const d = await evaluate(request(bound, "125.00", unsignedApproval()), gated(view));
    expect(d.decision).toBe(false);
    expect(d.context.denial_reason).toBe("approval_unverifiable");
  });

  it("the trust anchors are the decision point's own: a caller-supplied approvalVerification is never applied", async () => {
    const approval = await ars.approve(unsignedApproval(), bound);
    const { approvalVerification: _own, ...callerOptions } = gated(view);
    const withCallerAnchors = { ...callerOptions, approvalVerification: ars.verification } as unknown as DecisionOptions;
    const anchorless = createEphemeralDecisionPoint({
      emitterId: RESOURCE,
      audience: RESOURCE,
      resourcePolicy: RESOURCE_POLICY_PERMITS_ALL_FIXTURE,
      operationDeclarations: OPERATION_DECLARATIONS_NONE_FIXTURE,
    });
    const anchored = createEphemeralDecisionPoint({
      emitterId: RESOURCE,
      audience: RESOURCE,
      resourcePolicy: RESOURCE_POLICY_PERMITS_ALL_FIXTURE,
      operationDeclarations: OPERATION_DECLARATIONS_NONE_FIXTURE,
      approvalVerification: ars.verification,
    });
    const req = withCredential(request(bound, "125.00", approval));
    expect((await anchorless.decide(req, withCallerAnchors)).context.denial_reason).toBe("approval_unverifiable");
    expect((await anchored.decide(req, callerOptions as DecisionOptions)).decision).toBe(true);
  });
});

describe("re-evaluation after a Mission expansion runs under the successor (@spec authzen#requestable-denials, #2067)", () => {
  const predecessor = missionView("msn_2067_predecessor");
  const successor = missionView("msn_2067_successor");
  const views = new Map([predecessor, successor].map((v) => [`${v.issuer} ${v.id}`, v]));
  /** The view each request is evaluated under, resolved from its own `context.mission`. */
  const loadView = (req: EvaluationRequest): MissionView => {
    const v = views.get(`${req.context.mission.issuer} ${req.context.mission.id}`);
    if (!v) throw new Error("no view");
    return v;
  };
  const ref = (v: MissionView) => ({ issuer: v.issuer, id: v.id });

  it("a predecessor-bound action approval does not satisfy the approval gate under the successor: out_of_scope", async () => {
    const approval = await ars.approve(unsignedApproval(), ref(predecessor));
    // The approval is good for the predecessor it was given under.
    const before = request(ref(predecessor), "125.00", approval);
    expect((await evaluate(before, gated(loadView(before)))).decision).toBe(true);
    // Re-presented under the successor, it does not cover the action.
    const after = request(ref(successor), "125.00", approval);
    const d = await evaluate(after, gated(loadView(after)));
    expect(d.decision).toBe(false);
    expect(d.context.denial_reason).toBe("out_of_scope");
    expect(d.context.denial_reason).not.toBe("action_approval_required");
    expect(d.context.conditions).toBeUndefined();
  });

  it("the expansion supplies no action approval: under the successor the gated action is denied action_approval_required, requestable for the successor, until a successor-bound approval is presented", async () => {
    const after = request(ref(successor));
    const d = await evaluate(after, gated(loadView(after)));
    expect(d.decision).toBe(false);
    expect(d.context.denial_reason).toBe("action_approval_required");
    const token = (d.context.access_request as { binding_token: string }).binding_token;
    expect(decodeJwt(token)).toMatchObject({ mission_id: successor.id, mission_issuer: successor.issuer });
    const approval = await ars.approve(unsignedApproval(), ref(successor));
    const approved = request(ref(successor), "125.00", approval);
    expect((await evaluate(approved, gated(loadView(approved)))).decision).toBe(true);
  });
});

describe("parameter_violation is never requestable (@spec authzen#requestable-denials, #2067)", () => {
  const view = missionView("msn_2067");
  const bound = { issuer: view.issuer, id: view.id };

  it("a parameter_violation denial carries no access_request, even where approval policy is requestable", async () => {
    // Control: within the cap, the same gated action with no approval is
    // denied requestable, so the requestable path is wired.
    const within = await evaluate(request(bound, "125.00"), gated(view));
    expect(within.context.denial_reason).toBe("action_approval_required");
    expect(within.context.access_request).toBeDefined();
    // Over the cap: a constraint the PDP evaluated and found violated.
    const over = await evaluate(request(bound, "900.00"), gated(view));
    expect(over.decision).toBe(false);
    expect(over.context.denial_reason).toBe("parameter_violation");
    expect(over.context.access_request).toBeUndefined();
    expect(over.context.next_action).not.toBe("request");
  });
});
