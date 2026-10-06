/**
 * @spec runtime#input-resource-policy, authzen#runtime-denial-classification
 * `resource_policy` (#828): the independently administered Resource policy
 * against a live OpenFGA. Stored entitlements are granted and revoked by an
 * administrator while the token facts, the Mission and its contextual
 * authority stay unchanged, so every change in outcome is the policy's.
 * Skipped automatically when OpenFGA is unreachable; CI runs it.
 */

import { beforeAll, describe, expect, it } from "vitest";
import { createEphemeralDecisionPoint } from "../src/decision-point.js";
import type { DecisionEvidenceObject } from "../src/decision-evidence.js";
import { evaluate, type EvaluateOptions, type EvaluationRequest } from "../src/evaluate.js";
import { Fga, FgaAttachError, FgaDomainAdmin } from "../src/fga.js";
import { type AuthorityEntry, deriveContextualTuples, type MissionView } from "../src/policy-view.js";
import { relationForAction, stalenessBound } from "../src/policy.js";
import { fgaResourcePolicy, issuerLocalPrincipals, principalObject, type ResourcePolicy } from "../src/resource-policy.js";
import { freshKey, openTestClaims } from "./claim-fixture.js";

const API_URL = process.env.OPENFGA_HTTP_URL ?? "https://localhost:8080";
const KEY = process.env.OPENFGA_PRESHARED_KEY ?? "dev-preshared-key-change-me";
const CA = process.env.OPENFGA_CA_CERT;
const RESOURCE = "http://localhost:4403/mcp";
const ISSUER = "https://as.test";

async function reachable(): Promise<boolean> {
  try {
    if (CA) process.env.NODE_EXTRA_CA_CERTS = CA;
    return (await fetch(`${API_URL}/healthz`, { headers: { authorization: `Bearer ${KEY}` } })).ok;
  } catch {
    return false;
  }
}
const up = await reachable();
const d = up ? describe : describe.skip;
if (!up) console.warn("OpenFGA unreachable; skipping the Resource-policy OpenFGA tests (docker compose up)");

const NOW = new Date("2026-07-22T12:00:00Z");
const CLAIMS = openTestClaims({ now: () => NOW });
const ALICE = principalObject({ iss: ISSUER, sub: "alice" });
const CONNECTION = { apiUrl: API_URL, presharedKey: KEY, ...(CA ? { caCertPath: CA } : {}) };

const READ_ENTRY: AuthorityEntry = {
  type: "mission_resource_access",
  resource: RESOURCE,
  actions: ["payments:invoice.read", "payments:invoice.list"],
  constraints: { vendors: ["acme", "globex"] },
};
const PAY_ENTRY: AuthorityEntry = {
  type: "mission_resource_access",
  resource: RESOURCE,
  actions: ["payments:payment.execute"],
  constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme", "globex"] },
};
const view = (authority: AuthorityEntry[] = [READ_ENTRY, PAY_ENTRY]): MissionView => ({
  id: "msn_rp_fga",
  issuer: ISSUER,
  state: "active",
  version: 1,
  authority_hash: "sha-256:rpfga",
  authority_set: authority,
  subject: { iss: ISSUER, sub: "alice" },
  client_id: "ap-agent",
});

const context = (over: Partial<EvaluationRequest["context"]> = {}): EvaluationRequest["context"] => ({
  mission: { id: "msn_rp_fga", issuer: ISSUER },
  actor: { client_id: "ap-agent" },
  mission_state_observation: { state: "active", mode: "fresh", freshness_at: NOW.toISOString() },
  ...over,
});

/** A keyed payment on one invoice: the verified subject, the PEP-resolved vendor, a fresh key. */
const payReq = (invoiceId: string, vendorId: string, iss = ISSUER): EvaluationRequest => ({
  subject: { id: "alice", properties: { iss } },
  resource: { type: "invoice", id: invoiceId, properties: { audience: RESOURCE, vendor_id: vendorId } },
  action: { name: "payments:payment.execute", properties: { idempotency_key: freshKey() } },
  context: context({ action_class: "irreversible_action", parameter_digest: `sha-256:pd-${invoiceId}`, amount: { amount: "125.00", currency: "USD" } }),
});

const readReq = (invoiceId: string, vendorId: string, iss = ISSUER): EvaluationRequest => ({
  subject: { id: "alice", properties: { iss } },
  resource: { type: "invoice", id: invoiceId, properties: { audience: RESOURCE, vendor_id: vendorId } },
  action: { name: "payments:invoice.read" },
  context: context({ action_class: "consequential_read" }),
});

const listReq = (vendorIds: string[]): EvaluationRequest => ({
  subject: { id: "alice", properties: { iss: ISSUER } },
  resource: { type: "vendor", id: vendorIds[0] as string, properties: { audience: RESOURCE, vendor_id: vendorIds[0] as string, vendor_ids: vendorIds } },
  action: { name: "payments:invoice.list" },
  context: context({ action_class: "consequential_read" }),
});

let fga: Fga;
let storeId: string;
let modelId: string;
let admin: FgaDomainAdmin;

const PAY_ACME = { user: ALICE, relation: "authorized_payer", object: "vendor:acme" };
const READ_ACME = { user: ALICE, relation: "authorized_reader", object: "vendor:acme" };

const policyOver = (checker: Fga): ResourcePolicy => fgaResourcePolicy(checker, { principals: issuerLocalPrincipals(ISSUER) });
const opts = (resourcePolicy: ResourcePolicy, v: MissionView = view()): EvaluateOptions => ({
  view: v,
  fga,
  modelId,
  now: () => NOW,
  stalenessBound,
  relationForAction,
  stateSourcePlacement: "pep",
  claims: CLAIMS,
  resourcePolicy,
});

d("independent Resource policy against OpenFGA (@spec runtime#input-resource-policy, #828)", () => {
  beforeAll(async () => {
    ({ fga, storeId, modelId } = await Fga.bootstrap(CONNECTION));
    admin = new FgaDomainAdmin(fga);
    // The administrator's grants: alice may read and pay Acme; every invoice's
    // owning vendor. Nothing here comes from a Mission or a token.
    await admin.grant([
      PAY_ACME,
      READ_ACME,
      { user: "vendor:acme", relation: "vendor", object: "invoice:inv-1" },
      { user: "vendor:acme", relation: "vendor", object: "invoice:inv-2" },
      { user: "vendor:globex", relation: "vendor", object: "invoice:inv-3" },
    ]);
  });

  it("a stored entitlement permits; an external revocation of only that entitlement denies resource_policy on the next decision with signed evidence; restoring it permits", async () => {
    const point = createEphemeralDecisionPoint({ emitterId: RESOURCE, audience: RESOURCE, claims: CLAIMS, resourcePolicy: policyOver(fga) });
    const { resourcePolicy: _bound, claims: _claims, ...decisionOptions } = opts(policyOver(fga));
    // A separate administrator connection, attached to the same store: the
    // writer the PDP does not control.
    const external = new FgaDomainAdmin(await Fga.attach({ ...CONNECTION, storeId, authorizationModelId: modelId }));

    const permitted = await point.decide(payReq("inv-1", "acme"), decisionOptions);
    expect(permitted.decision, JSON.stringify(permitted.context)).toBe(true);

    await external.revoke([PAY_ACME]);
    try {
      const refused = await point.decide(payReq("inv-1", "acme"), decisionOptions);
      expect(refused.decision).toBe(false);
      expect(refused.context).toMatchObject({ denial_reason: "resource_policy", next_action: "none" });
      expect(refused.context).not.toHaveProperty("conditions");
      const record = refused.context.decision_evidence as DecisionEvidenceObject;
      expect(record).toMatchObject({ decision: "deny", denial_reason: "resource_policy" });
      // The Mission's contextual authority over the same invoice is unchanged.
      const tuples = deriveContextualTuples({ view: view(), entry: PAY_ENTRY, target: { objectType: "invoice", objectId: "inv-1", vendorId: "acme" }, relation: "payer" });
      expect(await fga.checkWithContext({ user: "mission:msn_rp_fga", relation: "payer", object: "invoice:inv-1" }, tuples, { higherConsistency: true })).toBe(true);
    } finally {
      await external.grant([PAY_ACME]);
    }

    const restored = await point.decide(payReq("inv-1", "acme"), decisionOptions);
    expect(restored.decision, JSON.stringify(restored.context)).toBe(true);
  });

  it("Mission-context tuples cannot satisfy a stored entitlement: the same tuples that satisfy the Mission relation leave the entitlement unsatisfied, and the model refuses a Mission subject on it", async () => {
    const tuples = deriveContextualTuples({ view: view(), entry: PAY_ENTRY, target: { objectType: "invoice", objectId: "inv-3", vendorId: "globex" }, relation: "payer" });
    expect(tuples).toHaveLength(1);
    expect(await fga.checkWithContext({ user: "mission:msn_rp_fga", relation: "payer", object: "invoice:inv-3" }, tuples, { higherConsistency: true })).toBe(true);
    const entitlement = await fga.client.check(
      { user: ALICE, relation: "authorized_payer", object: "invoice:inv-3", contextualTuples: tuples },
      { authorizationModelId: modelId, consistency: "HIGHER_CONSISTENCY" } as never,
    );
    expect(entitlement.allowed === true).toBe(false);
    const missionOnEntitlement = { user: "mission:msn_rp_fga", relation: "authorized_payer", object: "invoice:inv-3" };
    await expect(fga.client.write({ writes: [missionOnEntitlement] }, { authorizationModelId: modelId })).rejects.toThrow();
    await expect(
      fga.client.check({ ...missionOnEntitlement, contextualTuples: [missionOnEntitlement] }, { authorizationModelId: modelId } as never),
    ).rejects.toThrow();
    const dec = await evaluate(payReq("inv-3", "globex"), opts(policyOver(fga)));
    expect(dec.context.denial_reason).toBe("resource_policy");
  });

  it("Mission authority refusing still denies where the stored entitlement permits", async () => {
    const dec = await evaluate(payReq("inv-1", "acme"), opts(policyOver(fga), view([READ_ENTRY])));
    expect(dec.decision).toBe(false);
    expect(dec.context.denial_reason).toBe("out_of_authority");
  });

  it("restart: attaching to the existing store verifies the model and preserves a revocation; a model that is not the domain model refuses attach", async () => {
    await admin.revoke([PAY_ACME]);
    try {
      const attached = await Fga.attach({ ...CONNECTION, storeId, authorizationModelId: modelId });
      const dec = await evaluate(payReq("inv-1", "acme"), opts(policyOver(attached)));
      expect(dec.context.denial_reason).toBe("resource_policy");
    } finally {
      await admin.grant([PAY_ACME]);
    }
    const other = await fga.client.writeAuthorizationModel({
      schema_version: "1.1",
      type_definitions: [
        { type: "user" },
        {
          type: "vendor",
          relations: { authorized_payer: { this: {} } },
          metadata: { relations: { authorized_payer: { directly_related_user_types: [{ type: "user" }] } } },
        },
      ],
    } as never);
    await expect(Fga.attach({ ...CONNECTION, storeId, authorizationModelId: other.authorization_model_id as string })).rejects.toBeInstanceOf(FgaAttachError);
  });

  it("the same subject under another issuer, an invoice moved to an unentitled vendor, and a collection with one unentitled member each deny resource_policy", async () => {
    expect((await evaluate(readReq("inv-1", "acme"), opts(policyOver(fga)))).decision).toBe(true);
    expect((await evaluate(readReq("inv-1", "acme", "https://other.test"), opts(policyOver(fga)))).context.denial_reason).toBe("resource_policy");

    await admin.moveInvoice("inv-2", "acme", "globex");
    try {
      // The PEP's vendor fact is unchanged; the stored ownership governs.
      expect((await evaluate(payReq("inv-2", "acme"), opts(policyOver(fga)))).context.denial_reason).toBe("resource_policy");
    } finally {
      await admin.moveInvoice("inv-2", "globex", "acme");
    }

    expect((await evaluate(listReq(["acme"]), opts(policyOver(fga)))).decision).toBe(true);
    expect((await evaluate(listReq(["acme", "globex"]), opts(policyOver(fga)))).context.denial_reason).toBe("resource_policy");
  });
});
