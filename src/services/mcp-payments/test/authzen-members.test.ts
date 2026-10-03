/**
 * @spec authzen#context-audience-freshness, authzen#pdp-request (#1004): what
 * this PEP puts on the wire. Every request carries the PEP's audience at
 * `resource.properties.audience`; where the deployment's declared
 * state-source placement has the PEP supply state, the request carries the
 * loader's observation at `context.mission_state_observation`.
 *
 * The decision function is the real co-resident decision point, wrapped only
 * to record the request each call submits.
 */

import type { EvaluationRequest, Fga, MissionView } from "@mission/pdp";
import { describe, expect, it } from "vitest";
import {
  CANONICAL_RESOURCE,
  createEphemeralEvidenceKeys,
  EvidenceStore,
  type LoadedView,
  PaymentsStore,
  Pep,
  type PepDeps,
  type TokenFacts,
} from "../src/index.js";

const token: TokenFacts = {
  sub: "alice",
  clientId: "ap-agent",
  mission: { id: "msn_1004_pep", issuer: "https://as.test", authority_hash: "sha-256:h1004" },
  cnfJkt: "key",
};

const view: MissionView = {
  id: token.mission!.id,
  issuer: token.mission!.issuer,
  authority_hash: "sha-256:h1004",
  state: "active",
  version: 7,
  authority_set: [
    {
      type: "mission_resource_access",
      resource: CANONICAL_RESOURCE,
      actions: ["payments:invoice.read", "payments:invoice.list"],
    },
  ],
  subject: { iss: "https://as.test", sub: "alice" },
  client_id: "ap-agent",
};

function fixture(over: { observation?: Record<string, unknown>; deps?: Partial<PepDeps> } = {}) {
  const payments = new PaymentsStore();
  payments.seed(
    [{ id: "acme", name: "Acme", status: "approved" }],
    [{ id: "inv-1", vendor_id: "acme", amount: "100.00", currency: "USD", payee_account: "acct", status: "payable" }],
  );
  const keys = createEphemeralEvidenceKeys();
  const evidence = new EvidenceStore(keys.signing, keys.resolver);
  const observation = over.observation ?? {
    state: view.state,
    version: view.version,
    mode: "fresh",
    freshness_at: new Date().toISOString(),
  };
  const loadView = () => ({ view, observation }) as unknown as LoadedView;
  const requests: EvaluationRequest[] = [];
  const pep = new Pep({
    payments,
    evidence,
    decide: async (...args) => {
      requests.push(structuredClone(args[0]));
      return keys.decide(...args);
    },
    fga: { checkWithContext: async () => true } as unknown as Fga,
    modelId: "test",
    loadView,
    instanceEpoch: "epoch-1004",
    ...over.deps,
  });
  return { pep, requests, observation };
}

describe("the PEP sends the AuthZEN profile's members (@spec authzen#context-audience-freshness, #1004)", () => {
  it("carries the PEP's audience at resource.properties.audience on every request, never at context.audience", async () => {
    const f = fixture();
    await f.pep.enforce("get_invoice", { invoice_id: "inv-1" }, token);
    await f.pep.enforce("list_invoices", {}, token);
    expect(f.requests).toHaveLength(2);
    for (const request of f.requests) {
      expect(request.resource.properties.audience).toBe(CANONICAL_RESOURCE);
      expect((request.context as Record<string, unknown>).audience).toBeUndefined();
    }
    // The target object keeps its own identity and members beside the audience.
    expect(f.requests[0]?.resource).toEqual({
      type: "invoice",
      id: "inv-1",
      properties: { audience: CANONICAL_RESOURCE, vendor_id: "acme" },
    });
  });

  it("under PEP placement, carries the loader's observation at context.mission_state_observation, with state, mode and freshness_at, and no context.freshness", async () => {
    const f = fixture({ deps: { stateSourcePlacement: "pep" } });
    const result = await f.pep.enforce("get_invoice", { invoice_id: "inv-1" }, token);
    expect(result.permitted, JSON.stringify(result)).toBe(true);
    const context = f.requests[0]?.context as Record<string, unknown>;
    expect(context.mission_state_observation).toEqual(f.observation);
    expect(context.mission_state_observation).toMatchObject({
      state: expect.any(String),
      mode: expect.any(String),
      freshness_at: expect.any(String),
    });
    expect(context.freshness).toBeUndefined();
  });

  it("under PDP placement, omits context.mission_state_observation, and the co-resident PDP establishes state from its own read", async () => {
    // A fresh read: the PDP's own read within the bound establishes state.
    const fresh = fixture({ deps: { stateSourcePlacement: "pdp" } });
    const permitted = await fresh.pep.enforce("get_invoice", { invoice_id: "inv-1" }, token);
    expect(permitted.permitted, JSON.stringify(permitted)).toBe(true);
    expect((fresh.requests[0]?.context as Record<string, unknown>).mission_state_observation).toBeUndefined();
    // A read an hour old: the PDP's own read is what it relies on, so the
    // consequential read is refused stale_state, though no observation rode
    // the request.
    const stale = fixture({
      deps: { stateSourcePlacement: "pdp" },
      observation: { state: "active", version: 7, mode: "fresh", freshness_at: new Date(Date.now() - 3_600_000).toISOString() },
    });
    const refused = await stale.pep.enforce("get_invoice", { invoice_id: "inv-1" }, token);
    expect((stale.requests[0]?.context as Record<string, unknown>).mission_state_observation).toBeUndefined();
    expect(refused.permitted).toBe(false);
    expect(refused.denial_reason).toBe("stale_state");
  });

  it("under PEP placement, refuses state_unavailable without asking the PDP when the loader's observation lacks a member its mode requires or carries a malformed one", async () => {
    const now = new Date().toISOString();
    const malformed: Array<[string, Record<string, unknown>]> = [
      ["no state", { mode: "fresh", freshness_at: now }],
      ["no mode", { state: "active", freshness_at: now }],
      ["no freshness_at", { state: "active", mode: "fresh" }],
      ["a malformed freshness_at", { state: "active", mode: "fresh", freshness_at: "now" }],
      ["cached with no mission_status_expires_at", { state: "active", mode: "cached", freshness_at: now, mission_status_issued_at: now }],
      ["event_driven with no mission_status_issued_at", { state: "active", mode: "event_driven", freshness_at: now, mission_status_expires_at: now }],
      ["a mode outside the three", { state: "active", mode: "polled", freshness_at: now }],
      ["a non-integer version", { state: "active", version: "7", mode: "fresh", freshness_at: now }],
      ["a non-string assertion", { state: "active", mode: "fresh", freshness_at: now, assertion: { jws: "x" } }],
    ];
    for (const [label, observation] of malformed) {
      const f = fixture({ deps: { stateSourcePlacement: "pep" }, observation });
      const result = await f.pep.enforce("get_invoice", { invoice_id: "inv-1" }, token);
      expect(result.permitted, label).toBe(false);
      expect(result.refusal_reason, label).toBe("state_unavailable");
      expect(f.requests, label).toHaveLength(0);
    }
  });
});
