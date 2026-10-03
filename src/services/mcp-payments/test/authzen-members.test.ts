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
});
