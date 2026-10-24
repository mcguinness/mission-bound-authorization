/**
 * @spec authzen#runtime-denial-classification `stale_state` (#1629, D744): the
 * Mission state the decision relies on is not current: a freshness-bound
 * violation, state the PDP cannot establish where it is required to, or a
 * state-version mismatch. A Mission the PDP knows is not `active` is
 * `mission_inactive` instead. "Where a fresh read or reconciliation is
 * expected to resolve the condition, the PDP SHOULD mark the denial transient
 * with `next_action: retry`; otherwise it does not recommend a retry."
 *
 * The FGA layer is a stub that always permits, so only evaluate()'s own steps
 * and the decision channel decide, and this file never skips.
 */

import { afterEach, describe, expect, it } from "vitest";
import { evaluateRemote } from "../src/client.js";
import {
  type Decision,
  type DecisionOptions,
  evaluate as evaluateRequest,
  type EvaluateOptions,
  type EvaluationRequest,
} from "../src/evaluate.js";
import type { Fga } from "../src/fga.js";
import { MISSION_RESOURCE_ACCESS_TYPE, type MissionView } from "../src/policy-view.js";
import { relationForAction, stalenessBound } from "../src/policy.js";
import { createPdpHttpServer, type PdpHttpServerHandle } from "../src/server.js";
import { RESOURCE_POLICY_PERMITS_ALL_FIXTURE } from "../src/test-support.js";
import { withCredential } from "./with-credential.js";

const RESOURCE = "http://localhost:4403/mcp";
const NOW = new Date("2026-10-23T12:00:00Z");
const PEP_ID = "mcp-payments-pep";
const SECRET = "test-shared-secret-1629-stale";
const HOUR_AGO = new Date(NOW.getTime() - 3_600_000).toISOString();

const alwaysAllowFga = { checkWithContext: async () => true } as unknown as Fga;

const view = (over: Partial<MissionView> = {}): MissionView => ({
  id: "msn_stale",
  issuer: "https://as.test",
  state: "active",
  version: 3,
  authority_hash: "sha-256:hstale",
  authority_set: [{ type: MISSION_RESOURCE_ACCESS_TYPE, resource: RESOURCE, actions: ["payments:invoice.read"] }],
  subject: { iss: "https://as.test", sub: "alice" },
  client_id: "ap-agent",
  ...over,
});

const decisionOptions = (over: Partial<DecisionOptions> = {}): DecisionOptions => ({
  view: view(),
  fga: alwaysAllowFga,
  modelId: "model-stale",
  now: () => NOW,
  stalenessBound,
  relationForAction,
  ...over,
});

/** A read of one invoice (300 s class bound); `null` omits the observation. */
const read = (observation: Record<string, unknown> | null = observed()): EvaluationRequest =>
  withCredential({
    subject: { id: "alice", properties: { iss: "https://as.test" } },
    resource: { type: "invoice", id: "inv-1", properties: { audience: RESOURCE, operation_target: RESOURCE, vendor_id: "acme" } },
    action: { name: "payments:invoice.read" },
    context: {
      mission: { id: "msn_stale", issuer: "https://as.test" },
      actor: { client_id: "ap-agent" },
      action_class: "consequential_read",
      ...(observation === null ? {} : { mission_state_observation: observation }),
    },
  } as EvaluationRequest);

/** A well-formed `fresh` observation read at the decision instant. */
function observed(over: Record<string, unknown> = {}): Record<string, unknown> {
  return { state: "active", mode: "fresh", freshness_at: NOW.toISOString(), ...over };
}

const evaluate = (req: EvaluationRequest, over: Partial<EvaluateOptions> = {}): Promise<Decision> =>
  evaluateRequest(req, { ...decisionOptions(), resourcePolicy: RESOURCE_POLICY_PERMITS_ALL_FIXTURE, ...over });

interface Case {
  label: string;
  req: EvaluationRequest;
  opts: Partial<DecisionOptions>;
}

/** The three causes of `stale_state`, each a condition a fresh read or reconciliation clears. */
const TRANSIENT: Case[] = [
  { label: "freshness-bound violation: the PEP's observation is an hour old", req: read(observed({ freshness_at: HOUR_AGO })), opts: { stateSourcePlacement: "pep" } },
  { label: "freshness-bound violation: the PDP's own read is an hour old", req: read(null), opts: { stateSourcePlacement: "pdp", stateObservedAt: HOUR_AGO } },
  { label: "freshness-bound violation: the own read's signed fresh_until has passed", req: read(null), opts: { stateSourcePlacement: "pdp", stateObservedAt: NOW.toISOString(), stateFreshUntil: new Date(NOW.getTime() - 1_000).toISOString() } },
  {
    label: "freshness-bound violation: the observation's reported valid-through is reached",
    req: read(observed({ mode: "cached", mission_status_issued_at: NOW.toISOString(), mission_status_expires_at: NOW.toISOString() })),
    opts: { stateSourcePlacement: "pep" },
  },
  { label: "state not establishable at the PDP: no own read under pdp placement", req: read(null), opts: { stateSourcePlacement: "pdp" } },
  { label: "state-version mismatch: the request's version is behind the PDP's", req: read(observed({ version: 2 })), opts: { stateSourcePlacement: "pep" } },
];

/** `stale_state` denials that re-sending cannot clear. */
const NOT_TRANSIENT: Case[] = [
  { label: "a malformed observation", req: read({ state: "active", mode: "fresh", freshness_at: "an hour ago" }), opts: { stateSourcePlacement: "pep" } },
  { label: "an observation dated in the future beyond the skew", req: read(observed({ freshness_at: new Date(NOW.getTime() + 3_600_000).toISOString() })), opts: { stateSourcePlacement: "pep" } },
  { label: "state-version mismatch: the request's version is ahead of the PDP's", req: read(observed({ version: 4 })), opts: { stateSourcePlacement: "pep" } },
  { label: "a missing observation the declared pep placement requires", req: read(null), opts: { stateSourcePlacement: "pep" } },
  { label: "no declared state-source placement", req: read(observed()), opts: {} },
];

/** A Mission the PDP knows is not active: its own view, or the PEP-supplied state. */
const INACTIVE: Case[] = [
  { label: "the PDP's own view is suspended", req: read(observed()), opts: { view: view({ state: "suspended" }), stateSourcePlacement: "pep" } },
  { label: "the PEP-supplied state is terminated", req: read(observed({ state: "terminated" })), opts: { stateSourcePlacement: "pep" } },
];

let handle: PdpHttpServerHandle | undefined;
afterEach(async () => {
  await handle?.close();
  handle = undefined;
});

describe("stale_state is marked transient only where a fresh read or reconciliation is expected to resolve it (@spec authzen#runtime-denial-classification, #1629)", () => {
  it("each cause of stale_state a fresh read or reconciliation clears carries next_action retry", async () => {
    for (const { label, req, opts } of TRANSIENT) {
      const dec = await evaluate(req, opts);
      expect(dec.decision, label).toBe(false);
      expect(dec.context.denial_reason, label).toBe("stale_state");
      expect(dec.context.next_action, label).toBe("retry");
    }
  });

  it("a stale_state denial re-sending cannot clear carries no retry recommendation", async () => {
    for (const { label, req, opts } of NOT_TRANSIENT) {
      const dec = await evaluate(req, opts);
      expect(dec.decision, label).toBe(false);
      expect(dec.context.denial_reason, label).toBe("stale_state");
      expect(dec.context, label).not.toHaveProperty("next_action");
    }
  });

  it("a Mission the PDP knows is not active is mission_inactive, never a transient stale_state", async () => {
    for (const { label, req, opts } of INACTIVE) {
      const dec = await evaluate(req, opts);
      expect(dec.decision, label).toBe(false);
      expect(dec.context.denial_reason, label).toBe("mission_inactive");
      expect(dec.context, label).not.toHaveProperty("next_action");
    }
  });

  it("a current observation at the PDP's version permits, with no denial guidance", async () => {
    for (const opts of [{ stateSourcePlacement: "pep" as const }, { stateSourcePlacement: "pdp" as const, stateObservedAt: NOW.toISOString() }]) {
      const dec = await evaluate(read(observed({ version: 3 })), opts);
      expect(dec.decision, JSON.stringify(dec.context)).toBe(true);
      expect(dec.context).not.toHaveProperty("next_action");
    }
  });

  it("over the remote channel, each cause denies stale_state, transient exactly where a fresh read clears it, and a known non-active Mission denies mission_inactive", async () => {
    let current: Partial<DecisionOptions> = {};
    handle = await createPdpHttpServer({
      peps: new Map([[PEP_ID, { secret: SECRET, scopes: [RESOURCE] }]]),
      getOptions: () => decisionOptions(current),
      evaluateFn: evaluateRequest,
      resourcePolicy: RESOURCE_POLICY_PERMITS_ALL_FIXTURE,
    });
    const server = handle;
    const ask = (c: Case) => {
      current = c.opts;
      return evaluateRemote(c.req, { url: server.url, pepId: PEP_ID, secret: SECRET });
    };
    for (const c of TRANSIENT) {
      const dec = await ask(c);
      expect(dec.decision, c.label).toBe(false);
      expect(dec.context, c.label).toMatchObject({ denial_reason: "stale_state", next_action: "retry" });
    }
    for (const c of NOT_TRANSIENT) {
      const dec = await ask(c);
      expect(dec.decision, c.label).toBe(false);
      expect(dec.context.denial_reason, c.label).toBe("stale_state");
      expect(dec.context, c.label).not.toHaveProperty("next_action");
    }
    for (const c of INACTIVE) {
      const dec = await ask(c);
      expect(dec.decision, c.label).toBe(false);
      expect(dec.context.denial_reason, c.label).toBe("mission_inactive");
      expect(dec.context, c.label).not.toHaveProperty("next_action");
    }
    // Control: a current observation at the PDP's version permits over the same channel.
    const served = await ask({ label: "current", req: read(observed({ version: 3 })), opts: { stateSourcePlacement: "pep" } });
    expect(served.decision, JSON.stringify(served.context)).toBe(true);
  });
});
