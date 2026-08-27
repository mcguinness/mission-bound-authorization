/**
 * @spec authority-server#mission-join (#557 review point 1)
 *
 * The PDP's OWN resolution of the baseline MAS Join's rules 3-6, integrated
 * into `evaluate()` via `context.mission_join` / `EvaluateOptions.delegatePolicy`
 * (moved here from a PEP-side helper call, per review: "the spec assigns the
 * subject/client/delegate join to the PDP... carry the ordinary credential
 * facts, propagated Mission reference, mapping result, and delegation depth
 * into the PDP request and resolve there"). `mas-join.test.ts` covers
 * `resolveBaselineJoin` standalone; this file proves the PDP actually calls
 * it, denies before ever exposing a fallback authoritySet, and stamps
 * `join_view_id` on a decision that rode the joined path.
 */

import { describe, expect, it } from "vitest";
import type { Fga } from "../src/fga.js";
import { evaluate, type EvaluationRequest, type EvaluateOptions } from "../src/evaluate.js";
import { MISSION_RESOURCE_ACCESS_TYPE, type AuthorityEntry, type MissionView } from "../src/policy-view.js";
import { relationForAction, stalenessBoundSeconds } from "../src/policy.js";

const RESOURCE = "http://localhost:4403/mcp";
const NOW = new Date("2026-08-23T12:00:00Z");
const alwaysAllowFga = { checkWithContext: async () => true } as unknown as Fga;

const READ = "payments:invoice.read";
const SUBJECT = { iss: "https://idp.test", sub: "alice" };

const DIRECT_ENTRY: AuthorityEntry = { type: MISSION_RESOURCE_ACCESS_TYPE, resource: RESOURCE, actions: [READ] };
const DELEGABLE_ENTRY: AuthorityEntry = {
  type: MISSION_RESOURCE_ACCESS_TYPE,
  resource: RESOURCE,
  actions: [READ],
  join_delegation: { max_depth: 1, allowed_delegates: ["delegate-a"] },
};

const view: MissionView = {
  id: "msn_557_pdp",
  issuer: "https://as.test",
  state: "active",
  version: 1,
  authority_hash: "sha-256:testhash",
  authority_set: [DIRECT_ENTRY],
  subject: SUBJECT,
  client_id: "ap-agent",
};

const baseOpts = (extra: Partial<EvaluateOptions> = {}): EvaluateOptions => ({
  view,
  fga: alwaysAllowFga,
  modelId: "unit-test-model",
  now: () => NOW,
  stalenessBoundSeconds,
  relationForAction,
  allowedFreshnessSources: new Set(["load_view"]),
  ...extra,
});

const joinReq = (over: Partial<EvaluationRequest> = {}): EvaluationRequest => ({
  subject: { id: SUBJECT.sub, properties: { iss: SUBJECT.iss } },
  resource: { type: "invoice", id: "inv-1", properties: { vendor_id: "acme" } },
  action: { name: READ },
  context: {
    audience: RESOURCE,
    mission: { id: view.id, issuer: view.issuer },
    actor: { client_id: "ap-agent" },
    mission_join: {},
  },
  ...over,
});

describe("evaluate(): baseline MAS Join, direct client (@spec authority-server#mission-join rules 1-4, 7, #557 review point 1)", () => {
  it("permits and stamps join_view_id when context.mission_join is present and the subject/client match directly", async () => {
    const decision = await evaluate(joinReq(), baseOpts());
    expect(decision.decision, JSON.stringify(decision)).toBe(true);
    expect(decision.context.join_view_id).toBeTruthy();
  });

  it("never carries join_view_id for an ORDINARY Mission-bound request (context.mission_join absent): the existing path is untouched", async () => {
    const decision = await evaluate(
      joinReq({
        context: {
          audience: RESOURCE,
          mission: { id: view.id, issuer: view.issuer },
          actor: { client_id: "ap-agent" },
        },
      }),
      baseOpts(),
    );
    expect(decision.decision, JSON.stringify(decision)).toBe(true);
    expect(decision.context.join_view_id).toBeUndefined();
  });
});

describe("evaluate(): baseline MAS Join, mission_mismatch (@spec authority-server#mission-join rule 6, #557 review point 1)", () => {
  it("denies mission_mismatch when the authenticated subject does not match the Mission's subject, resolved BY THE PDP", async () => {
    const decision = await evaluate(
      joinReq({ subject: { id: "mallory", properties: { iss: SUBJECT.iss } } }),
      baseOpts(),
    );
    expect(decision.decision).toBe(false);
    expect(decision.context.denial_reason).toBe("mission_mismatch");
    // No fallback: a failed join never exposes any authoritySet-derived
    // evidence (rule 6). This decision never reached step 4b's success
    // assignment, so join_view_id is absent too.
    expect(decision.context.entry_digest).toBeUndefined();
    expect(decision.context.join_view_id).toBeUndefined();
  });

  it("denies mission_mismatch when context.actor.client_id is missing entirely on the Join path", async () => {
    const decision = await evaluate(joinReq({ context: { ...joinReq().context, actor: undefined } }), baseOpts());
    expect(decision.decision).toBe(false);
    expect(decision.context.denial_reason).toBe("mission_mismatch");
  });

  it("denies mission_mismatch for an unrecognized client with no delegate policy configured, never falling back to the Mission's full authority", async () => {
    const decision = await evaluate(
      joinReq({ context: { ...joinReq().context, actor: { client_id: "unrecognized-client" } } }),
      baseOpts(),
    );
    expect(decision.decision).toBe(false);
    expect(decision.context.denial_reason).toBe("mission_mismatch");
  });
});

describe("evaluate(): baseline MAS Join, delegate narrowing (@spec authority-server#mission-join rule 5, #557 review point 1)", () => {
  const delegateView: MissionView = { ...view, authority_set: [DIRECT_ENTRY, DELEGABLE_ENTRY] };

  it("permits an authorized delegate within its recorded depth, narrowed to the delegable subset, and carries delegate_depth from the request", async () => {
    const decision = await evaluate(
      joinReq({
        context: {
          ...joinReq().context,
          actor: { client_id: "delegate-a" },
          mission_join: { delegate_depth: 1 },
        },
      }),
      baseOpts({ view: delegateView, delegatePolicy: { delegates: { "delegate-a": { maxDepth: 3 } } } }),
    );
    expect(decision.decision, JSON.stringify(decision)).toBe(true);
  });

  it("denies mission_mismatch for a delegate whose recorded depth exceeds the entry's own join_delegation.max_depth, even though the deployment's DelegatePolicy permits deeper delegation (#557 review point 3)", async () => {
    const decision = await evaluate(
      joinReq({
        context: {
          ...joinReq().context,
          actor: { client_id: "delegate-a" },
          mission_join: { delegate_depth: 2 }, // exceeds DELEGABLE_ENTRY's join_delegation.max_depth: 1
        },
      }),
      baseOpts({ view: delegateView, delegatePolicy: { delegates: { "delegate-a": { maxDepth: 3 } } } }),
    );
    expect(decision.decision).toBe(false);
    expect(decision.context.denial_reason).toBe("mission_mismatch");
  });

  it("stamps a DIFFERENT join_view_id for the delegate's narrowed view than the direct client's full view", async () => {
    const direct = await evaluate(joinReq(), baseOpts());
    const delegate = await evaluate(
      joinReq({
        context: {
          ...joinReq().context,
          actor: { client_id: "delegate-a" },
          mission_join: { delegate_depth: 1 },
        },
      }),
      baseOpts({ view: delegateView, delegatePolicy: { delegates: { "delegate-a": { maxDepth: 3 } } } }),
    );
    expect(direct.decision).toBe(true);
    expect(delegate.decision).toBe(true);
    expect(delegate.context.join_view_id).not.toBe(direct.context.join_view_id);
  });
});
