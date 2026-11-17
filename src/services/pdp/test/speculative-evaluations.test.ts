/**
 * @spec authzen#speculative-evaluations (#2067, D1313): a speculative
 * evaluation previews whether candidate actions would be permitted under a
 * Mission without attempting any of them. Each item is evaluated on the same
 * terms as an evaluation and answered with a preview: `prospective_conditions`
 * on a permit, the profile's own `reason` on a deny, AuthZEN's per-evaluation
 * `error` for an item the PDP cannot evaluate; never an `evaluation_id`,
 * `conditions` or Decision Evidence. A speculative request sent to the
 * evaluation path is a request error, a PDP without the feature does not
 * answer one, and an unrecognized `context.mission` fails closed.
 *
 * The PDP runs in process and behind the reference HTTP server, with a stub
 * OpenFGA and a controlled clock, so this file never skips.
 */

import { currentContractRef, pinnedToCurrentContract } from "@mission/demo-data";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { evaluateRemote, isDecisionChannelRefusal, speculateRemote } from "../src/client.js";
import { createDecisionEvidenceEmitter } from "../src/decision-evidence.js";
import { createEphemeralDecisionPoint, type EphemeralDecisionPoint } from "../src/decision-point.js";
import { createDurationLeaseLedger } from "../src/duration-lease.js";
import {
  type DecisionOptions,
  type EvaluateOptions,
  type EvaluationRequest,
  evaluate,
  type PdpRefusal,
  type SpeculativeEvaluationItem,
  type SpeculativeEvaluationRequest,
  SpeculativeRequestInvalid,
  SpeculativeRequestMisdirected,
  speculate,
} from "../src/evaluate.js";
import type { Fga } from "../src/fga.js";
import type { MissionView } from "../src/policy-view.js";
import { relationForAction, stalenessBound } from "../src/policy.js";
import { createPdpHttpServer, type PdpHttpServerHandle } from "../src/server.js";
import {
  EVALUATION_CONTEXT_UNCLAIMED_FIXTURE,
  OPERATION_DECLARATIONS_NONE_FIXTURE,
  RESOURCE_POLICY_PERMITS_ALL_FIXTURE,
} from "../src/test-support.js";
import { generateKeyPairSync } from "node:crypto";
import { freshKey, openTestClaims } from "./claim-fixture.js";

// date-literal: controlled-clock
const CLOCK_MS = Date.parse("2026-11-16T12:00:00Z");
const RESOURCE = "http://localhost:4403/mcp";
const OTHER_RESOURCE = "http://localhost:4404/mcp";
const EXECUTE = "payments:payment.execute";
const READ = "payments:invoice.read";
const ISSUER = "https://as.test";
const MISSION = "msn_2067_speculative";
const PEP_ID = "mcp-payments-pep";
const SECRET = "test-shared-secret-do-not-reuse";
const CONTRACT = currentContractRef({ resource: RESOURCE, actions: [EXECUTE] });
const digest = (n: number) => `sha-256:${Buffer.alloc(32, n).toString("base64url")}`;
const alwaysAllowFga = { checkWithContext: async () => true } as unknown as Fga;

const VIEW: MissionView = {
  id: MISSION,
  issuer: ISSUER,
  state: "active",
  version: 1,
  authority_hash: "sha-256:speculative",
  authority_set: [
    pinnedToCurrentContract({
      type: "mission_resource_access",
      resource: RESOURCE,
      actions: [EXECUTE],
      constraints: { max_amount: { amount: "500.00", currency: "USD" } },
    }),
  ],
  subject: { iss: ISSUER, sub: "alice" },
  client_id: "ap-agent",
};

/** The context every item shares: the Mission, the actor and the PEP's state observation. */
const shared = (mission: { id: string; issuer: string } = { id: MISSION, issuer: ISSUER }) => ({
  mission,
  actor: { client_id: "ap-agent" },
  mission_state_observation: { state: "active", mode: "fresh", freshness_at: new Date().toISOString() },
});

/** One candidate payment: irreversible, keyed, under the Mission's 500.00 cap unless `amount` exceeds it. */
function payment(id: string, o: { amount?: string; action?: string; target?: string; audience?: string; context?: Record<string, unknown> } = {}): SpeculativeEvaluationItem {
  const action = o.action ?? EXECUTE;
  const target = o.target ?? RESOURCE;
  return {
    id,
    subject: { id: "alice" },
    resource: {
      type: "invoice",
      id: "inv-1",
      properties: {
        audience: o.audience ?? RESOURCE,
        operation_target: target,
        vendor_id: "acme",
        ...(CONTRACT ? { resource_contract: CONTRACT } : {}),
      } as EvaluationRequest["resource"]["properties"],
    },
    action: { name: action, properties: { idempotency_key: freshKey() } },
    context: {
      action_class: "irreversible_action",
      amount: { amount: o.amount ?? "125.00", currency: "USD" },
      parameter_digest: digest(7),
      credential: {
        authority: [
          { type: "mission_resource_access", resource: target, actions: [action], ...(CONTRACT ? { resource_contract: CONTRACT } : {}) },
        ],
      },
      ...(o.context ?? {}),
    },
  };
}

/** The same candidate as an ordinary evaluation request. */
const asEvaluation = (item: SpeculativeEvaluationItem, context = shared()): EvaluationRequest =>
  ({ subject: item.subject, resource: item.resource, action: item.action, context: { ...context, ...item.context } }) as EvaluationRequest;

const decisionOptions = (over: Partial<DecisionOptions> = {}): DecisionOptions => ({
  view: VIEW,
  fga: alwaysAllowFga,
  modelId: "model-2067",
  now: () => new Date(),
  stalenessBound,
  relationForAction,
  stateSourcePlacement: "pep",
  ...over,
});

function point(o: { speculative?: boolean; refusals?: PdpRefusal[] } = {}): EphemeralDecisionPoint {
  return createEphemeralDecisionPoint({
    emitterId: RESOURCE,
    audience: RESOURCE,
    resourcePolicy: RESOURCE_POLICY_PERMITS_ALL_FIXTURE,
    claims: openTestClaims({ now: () => new Date() }),
    operationDeclarations: OPERATION_DECLARATIONS_NONE_FIXTURE,
    evaluationContextBinding: EVALUATION_CONTEXT_UNCLAIMED_FIXTURE,
    ...(o.refusals ? { refusals: (r: PdpRefusal) => o.refusals?.push(r) } : {}),
    ...(o.speculative === false ? {} : { speculativeEvaluations: true }),
  });
}

beforeAll(() => {
  vi.useFakeTimers({ toFake: ["Date"], shouldAdvanceTime: true });
  vi.setSystemTime(CLOCK_MS);
});

afterAll(() => {
  vi.useRealTimers();
});

describe("speculative previews (@spec authzen#speculative-evaluations, #2067)", () => {
  it("a permit preview carries prospective_conditions and no conditions, evaluation_id or Decision Evidence, and a deny carries the profile's reason", async () => {
    const p = point();
    const candidate = payment("within-cap");
    const response = await p.speculate?.(
      { context: shared(), items: [candidate, payment("over-cap", { amount: "780.00" }), payment("never-approved", { action: READ })] },
      decisionOptions(),
    );
    const [permit, overCap, unapproved] = response?.items ?? [];
    expect(permit?.id).toBe("within-cap");
    expect(permit?.decision, JSON.stringify(permit?.context)).toBe(true);
    // Nothing executable survives: the only member is the preview.
    expect(Object.keys(permit?.context ?? {})).toEqual(["prospective_conditions"]);
    // The conditions an ordinary evaluation of the same request returns, as a preview.
    const ordinary = await p.decide(asEvaluation(candidate), decisionOptions());
    expect(ordinary.decision).toBe(true);
    const { valid_until: _ordinaryUntil, ...ordinaryConditions } = ordinary.context.conditions as Record<string, unknown>;
    const { valid_until: previewUntil, ...previewConditions } = permit?.context.prospective_conditions as Record<string, unknown>;
    expect(previewConditions).toEqual(ordinaryConditions);
    expect(previewConditions.use_limit).toBe(1);
    expect(typeof previewUntil).toBe("string");

    // A deny carries the profile's own reason, and nothing else here.
    expect(overCap).toEqual({ id: "over-cap", decision: false, context: { reason: "parameter_violation" } });
    expect(unapproved).toEqual({ id: "never-approved", decision: false, context: { reason: "out_of_authority" } });
  });

  it("a member present in both an item's context and the shared context is an item error, never an override, and the other items are still evaluated", async () => {
    const p = point();
    const response = await p.speculate?.(
      {
        context: shared(),
        items: [
          payment("overrides-mission", { context: { mission: { id: "msn_other", issuer: ISSUER } } }),
          payment("overrides-observation", { context: { mission_state_observation: { state: "active", mode: "fresh", freshness_at: new Date().toISOString() } } }),
          payment("clean"),
        ],
      },
      decisionOptions(),
    );
    const [mission, observation, clean] = response?.items ?? [];
    for (const collided of [mission, observation]) {
      expect(collided?.decision).toBe(false);
      expect(collided?.context.error).toMatchObject({ status: 400 });
      expect(collided?.context.reason).toBeUndefined();
      expect(collided?.context.prospective_conditions).toBeUndefined();
    }
    expect((mission?.context.error as { message: string }).message).toContain("mission");
    expect((observation?.context.error as { message: string }).message).toContain("mission_state_observation");
    expect(clean?.decision).toBe(true);
  });

  it("an input the PDP would refuse before evaluation is an item error with no Refusal Record", async () => {
    const refusals: PdpRefusal[] = [];
    const p = point({ refusals });
    const noTarget = payment("no-target");
    delete (noTarget.resource.properties as { operation_target?: string }).operation_target;
    const response = await p.speculate?.({ context: shared(), items: [noTarget, payment("clean")] }, decisionOptions());
    expect(response?.items[0]).toEqual({
      id: "no-target",
      decision: false,
      context: { error: { status: 400, message: "operation_target_invalid" } },
    });
    expect(response?.items[1]?.decision).toBe(true);
    expect(refusals).toEqual([]);
    // The same input as an evaluation is refused and recorded (control).
    await expect(p.decide(asEvaluation(noTarget), decisionOptions())).rejects.toThrow(/operation_target_invalid/);
    expect(refusals.map((r) => r.denial_reason)).toEqual(["operation_target_invalid"]);
  });
});

describe("a speculative evaluation reserves no metered capacity (@spec authzen#speculative-evaluations, #2067)", () => {
  it("a speculative evaluation of a duration-leased action opens no lease activity, and a speculative renewal extends none", async () => {
    const ledger = createDurationLeaseLedger({ [EXECUTE]: 60 });
    const p = createEphemeralDecisionPoint({
      emitterId: RESOURCE,
      audience: RESOURCE,
      resourcePolicy: RESOURCE_POLICY_PERMITS_ALL_FIXTURE,
      operationDeclarations: OPERATION_DECLARATIONS_NONE_FIXTURE,
      evaluationContextBinding: EVALUATION_CONTEXT_UNCLAIMED_FIXTURE,
      durationLeases: ledger,
      speculativeEvaluations: true,
    });
    const leased = payment("leased");
    leased.context = { ...leased.context, action_class: "consequential_read" };
    const opening = await p.speculate?.({ context: shared(), items: [leased] }, decisionOptions());
    expect(opening?.items[0]?.decision, JSON.stringify(opening?.items[0])).toBe(true);
    expect(ledger.activities()).toEqual([]);

    // An evaluation of the same request opens the activity (control).
    const opened = await p.decide(asEvaluation(leased), decisionOptions());
    expect(opened.decision).toBe(true);
    const activities = ledger.activities();
    expect(activities).toHaveLength(1);

    // A speculative renewal of it previews, and extends nothing.
    const renewal = { ...leased, id: "renewal", context: { ...leased.context, prior_evaluation_id: opened.context.evaluation_id } };
    const renewed = await p.speculate?.({ context: shared(), items: [renewal] }, decisionOptions());
    expect(renewed?.items[0]?.decision, JSON.stringify(renewed?.items[0])).toBe(true);
    expect(ledger.activities()).toEqual(activities);
  });
});

describe("an unrecognized context.mission fails closed for the affected items (@spec authzen#speculative-evaluations, #2067)", () => {
  it("in process: a context.mission other than the Mission the PDP establishes yields no permit preview for any item", async () => {
    const p = point();
    const response = await p.speculate?.(
      { context: shared({ id: "msn_unrecognized", issuer: ISSUER }), items: [payment("a"), payment("b")] },
      decisionOptions(),
    );
    expect(response?.items.map((i) => [i.id, i.decision, i.context.reason])).toEqual([
      ["a", false, "view_inconsistent"],
      ["b", false, "view_inconsistent"],
    ]);
    for (const item of response?.items ?? []) expect(item.context.prospective_conditions).toBeUndefined();
  });

  it("a request whose shared context carries no context.mission is refused as a whole", async () => {
    const p = point();
    const { mission: _mission, ...missionless } = shared();
    await expect(p.speculate?.({ context: missionless, items: [payment("a")] }, decisionOptions())).rejects.toBeInstanceOf(
      SpeculativeRequestInvalid,
    );
  });
});

describe("speculative evaluation over the reference decision channel (@spec authzen#speculative-evaluations, #2067)", () => {
  let handle: PdpHttpServerHandle | undefined;
  afterEach(async () => {
    await handle?.close();
    handle = undefined;
  });

  const counted = () => {
    const calls = { evaluate: 0, speculate: 0, emitted: 0, refused: 0 };
    const key = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const inner = createDecisionEvidenceEmitter({ signer: { kid: "pdp-2067", key: key.privateKey }, emitterId: RESOURCE, audience: RESOURCE });
    const emitter = {
      ...inner,
      emit: async (input: Parameters<typeof inner.emit>[0]) => {
        calls.emitted += 1;
        return inner.emit(input);
      },
    };
    return { calls, emitter };
  };

  async function start(o: {
    speculative: boolean;
    calls: { evaluate: number; speculate: number; refused: number };
    emitter?: EvaluateOptions["evidence"];
    getOptions?: (req: EvaluationRequest) => DecisionOptions;
    scopes?: string[];
  }): Promise<PdpHttpServerHandle> {
    handle = await createPdpHttpServer({
      peps: new Map([[PEP_ID, { secret: SECRET, scopes: o.scopes ?? [RESOURCE] }]]),
      getOptions: o.getOptions ?? (() => decisionOptions()),
      evaluateFn: async (r, opts) => {
        o.calls.evaluate += 1;
        return evaluate(r, opts);
      },
      speculateFn: async (r, opts) => {
        o.calls.speculate += 1;
        return speculate(r, opts);
      },
      ...(o.emitter ? { evidence: o.emitter } : {}),
      refusals: () => {
        o.calls.refused += 1;
      },
      claims: openTestClaims({ now: () => new Date() }),
      resourcePolicy: RESOURCE_POLICY_PERMITS_ALL_FIXTURE,
      operationDeclarations: OPERATION_DECLARATIONS_NONE_FIXTURE,
      evaluationContextBinding: EVALUATION_CONTEXT_UNCLAIMED_FIXTURE,
      ...(o.speculative ? { speculativeEvaluations: true } : {}),
    });
    return handle;
  }

  /** A read the Mission authorizes, for the channel tests: no claim is needed to permit it. */
  const read = (id: string, o: { audience?: string; target?: string } = {}): SpeculativeEvaluationItem => {
    const item = payment(id, { action: EXECUTE, ...o });
    return { ...item, context: { ...item.context, action_class: "consequential_read" } };
  };

  it("an evaluation request carrying the speculative items member is a request error, with no decision, no evidence and no Refusal Record", async () => {
    for (const speculative of [true, false]) {
      const { calls, emitter } = counted();
      const server = await start({ speculative, calls, emitter });
      const client = { url: server.url, pepId: PEP_ID, secret: SECRET };
      const ordinary = asEvaluation(read("x"));
      const marked = { ...ordinary, items: [read("y")] } as unknown as EvaluationRequest;
      const refused = await evaluateRemote(marked, client);
      expect(isDecisionChannelRefusal(refused), JSON.stringify(refused)).toBe(true);
      expect(refused.context.channel_status).toBe(400);
      expect(calls, `speculative=${speculative}`).toEqual({ evaluate: 0, speculate: 0, emitted: 0, refused: 0 });
      // The same request without the member is an ordinary evaluation (control).
      const decided = await evaluateRemote(ordinary, client);
      expect(decided.decision, JSON.stringify(decided.context)).toBe(true);
      expect(calls.emitted).toBe(1);
      await handle?.close();
      handle = undefined;
    }
    // In process, the decision function refuses it too, recording nothing.
    const refusals: PdpRefusal[] = [];
    const p = point({ refusals });
    const marked = { ...asEvaluation(read("x")), items: [] } as unknown as EvaluationRequest;
    await expect(p.decide(marked, decisionOptions())).rejects.toBeInstanceOf(SpeculativeRequestMisdirected);
    expect(refusals).toEqual([]);
  });

  it("a PDP without the feature does not answer a speculative request, and nothing falls back to ordinary evaluation", async () => {
    const { calls, emitter } = counted();
    const server = await start({ speculative: false, calls, emitter });
    const client = { url: server.url, pepId: PEP_ID, secret: SECRET };
    const request: SpeculativeEvaluationRequest = { context: shared(), items: [read("a"), payment("b")] };
    expect(await speculateRemote(request, client)).toEqual({ error: "decision_channel_refused", status: 404 });
    expect(calls).toEqual({ evaluate: 0, speculate: 0, emitted: 0, refused: 0 });
    // A decision point built without the feature has no speculative entry at all.
    expect(point({ speculative: false }).speculate).toBeUndefined();

    // With the feature, the same request is answered with previews (control).
    await handle?.close();
    const { calls: on, emitter: onEmitter } = counted();
    const served = await start({ speculative: true, calls: on, emitter: onEmitter });
    const previews = await speculateRemote(request, { url: served.url, pepId: PEP_ID, secret: SECRET });
    expect("items" in previews && previews.items.map((i) => [i.id, i.decision])).toEqual([
      ["a", true],
      // The remote channel meters no budget and claims nothing, but the
      // high-consequence preview still runs every check, the claim domain's
      // declaration among them.
      ["b", true],
    ]);
    expect(on).toEqual({ evaluate: 0, speculate: 2, emitted: 0, refused: 0 });
  });

  it("a Mission the PDP cannot establish fails closed for the affected items: no preview, never another Mission's options", async () => {
    const { calls } = counted();
    const server = await start({
      speculative: true,
      calls,
      getOptions: (req) => {
        if (req.context.mission?.id !== MISSION) throw new Error("PDP cannot establish the Mission view");
        return decisionOptions();
      },
    });
    const client = { url: server.url, pepId: PEP_ID, secret: SECRET };
    const unknown = await speculateRemote({ context: shared({ id: "msn_unrecognized", issuer: ISSUER }), items: [read("a"), read("b")] }, client);
    expect("items" in unknown && unknown.items).toEqual([
      { id: "a", decision: false, context: { error: { status: 400, message: "mission_unrecognized" } } },
      { id: "b", decision: false, context: { error: { status: 400, message: "mission_unrecognized" } } },
    ]);
    expect(calls.speculate).toBe(0);
    // The recognized Mission is previewed (control).
    const known = await speculateRemote({ context: shared(), items: [read("a")] }, client);
    expect("items" in known && known.items.map((i) => i.decision)).toEqual([true]);
  });

  it("the speculative endpoint answers only an authenticated requester, and only for items in its authorized scope", async () => {
    const { calls } = counted();
    const server = await start({ speculative: true, calls });
    const request: SpeculativeEvaluationRequest = {
      context: shared(),
      items: [read("in-scope"), read("other-scope", { audience: OTHER_RESOURCE }), read("other-target", { target: OTHER_RESOURCE })],
    };
    expect(await speculateRemote(request, { url: server.url, pepId: PEP_ID, secret: "not-the-secret" })).toEqual({
      error: "decision_channel_refused",
      status: 401,
    });
    expect(await speculateRemote(request, { url: server.url, pepId: "unregistered-pep", secret: SECRET })).toEqual({
      error: "decision_channel_refused",
      status: 401,
    });
    expect(calls.speculate).toBe(0);
    const answered = await speculateRemote(request, { url: server.url, pepId: PEP_ID, secret: SECRET });
    expect("items" in answered && answered.items).toEqual([
      expect.objectContaining({ id: "in-scope", decision: true }),
      { id: "other-scope", decision: false, context: { error: { status: 403, message: "pep_not_authorized_for_scope" } } },
      { id: "other-target", decision: false, context: { error: { status: 403, message: "operation_target_invalid" } } },
    ]);
    // Only the in-scope item reached the PDP's decision work, and the
    // out-of-scope target left no Refusal Record.
    expect(calls.speculate).toBe(1);
    expect(calls.refused).toBe(0);
  });
});
