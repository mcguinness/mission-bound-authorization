/**
 * @spec runtime#input-resource-policy, authzen#runtime-denial-classification
 * `resource_policy`, authzen#failure-condition-coverage (#828): the
 * independently administered Resource policy at the resource's own surface.
 * The decision point carries the policy; the PEP carries none and passes the
 * verified subject, client and resolved targets in the evaluation request.
 *
 * The first suite runs unconditionally with named policy fixtures, through
 * both the co-resident and the remote decision channel. The second runs the
 * deployment's OpenFGA policy against a live OpenFGA and skips when it is
 * unreachable; CI runs it.
 */

import {
  createDecisionChannel,
  createEphemeralDecisionPoint,
  Fga,
  FgaDomainAdmin,
  fgaResourcePolicy,
  issuerLocalPrincipals,
  loadRuntimePosture,
  type MissionView,
  principalObject,
  relationForAction,
  type ResourcePolicy,
  RUNTIME_POSTURE,
  stalenessBound,
} from "@mission/pdp";
import {
  RESOURCE_POLICY_PERMITS_ALL_FIXTURE,
  RESOURCE_POLICY_REFUSES_ALL_FIXTURE,
  RESOURCE_POLICY_UNAVAILABLE_FIXTURE,
  resourcePolicyFixture,
} from "@mission/pdp/test-support";
import { describe, expect, it } from "vitest";
import {
  buildListEffectiveParams,
  CANONICAL_RESOURCE,
  Connectors,
  createEphemeralEvidenceKeys,
  EvidenceStore,
  McpPaymentsServer,
  openEphemeralWriteReservationStore,
  parameterDigest,
  PaymentsStore,
  Pep,
  type TokenFacts,
  TransactionEngine,
} from "../src/index.js";
import { ALL_ACTIONS_CREDENTIAL } from "./credential-fixtures.js";

const ISSUER = "https://as.test";
const MODES = ["co-resident", "remote"] as const;

const defaultView: MissionView = {
  id: "msn_rp_pep",
  issuer: ISSUER,
  state: "active",
  version: 1,
  authority_hash: "sha-256:rp-pep",
  authority_set: [
    {
      type: "mission_resource_access",
      resource: CANONICAL_RESOURCE,
      actions: ["payments:invoice.read", "payments:payment.schedule"],
      constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
    },
  ],
  subject: { iss: ISSUER, sub: "alice" },
  client_id: "ap-agent",
};

/** The facts the token verifier establishes: the subject under this resource's issuer, and the client. */
const TOKEN: TokenFacts = {
  sub: "alice",
  iss: ISSUER,
  clientId: "ap-agent",
  cnfJkt: "jkt-828",
  mission: { id: defaultView.id, issuer: defaultView.issuer, authority_hash: defaultView.authority_hash },
  credentialAuthority: ALL_ACTIONS_CREDENTIAL,
};

const seedOneInvoice = (payments: PaymentsStore) =>
  payments.seed(
    [{ id: "acme", name: "Acme", status: "approved" }],
    [{ id: "inv-1", vendor_id: "acme", amount: "125.00", currency: "USD", payee_account: "acct-acme", status: "payable" }],
  );

/** One resource with its PEP and a decision point bound to `resourcePolicy`, over `mode`. The Mission check always allows by default. */
async function build(
  mode: (typeof MODES)[number],
  resourcePolicy: ResourcePolicy,
  missionFga: Fga = { checkWithContext: async () => true } as unknown as Fga,
  fixture: { view: MissionView; seed: (payments: PaymentsStore) => void } = { view: defaultView, seed: seedOneInvoice },
) {
  const view = fixture.view;
  const point = createEphemeralDecisionPoint({ emitterId: CANONICAL_RESOURCE, audience: CANONICAL_RESOURCE, resourcePolicy });
  const keys = createEphemeralEvidenceKeys({ decisionPoint: point });
  const evidence = new EvidenceStore(keys.signing, keys.resolver);
  const payments = new PaymentsStore();
  fixture.seed(payments);
  const loadView = (ref: { id: string; issuer: string }) =>
    ref.id === view.id && ref.issuer === view.issuer
      ? { view, observation: { state: view.state, version: view.version, mode: "fresh", freshness_at: new Date().toISOString() } }
      : undefined;
  const channel = await createDecisionChannel(point, {
    mode,
    pepId: "mcp-payments-pep",
    audience: CANONICAL_RESOURCE,
    getOptions: () => ({ view, fga: missionFga, modelId: "test", now: () => new Date(), stalenessBound, relationForAction, stateSourcePlacement: "pep" as const }),
  });
  const pep = new Pep({ payments, evidence, fga: missionFga, modelId: "test", loadView, instanceEpoch: "epoch-828", decide: channel.decide, claims: channel.claims });
  const connectors = new Connectors();
  const writeReservations = openEphemeralWriteReservationStore({ owner: RUNTIME_POSTURE.mediated_scope.pep_locations[0] as string });
  const server = new McpPaymentsServer({
    pep,
    payments,
    loadView,
    issuer: ISSUER,
    jwks: { keys: [] },
    keyRoles: { accessToken: [], attenuationRoot: [], transactionToken: [] },
    enforcementScopeStatement: loadRuntimePosture({ ...RUNTIME_POSTURE, remote_decision_channels: channel.remoteDecisionChannels }),
    transaction: { engine: new TransactionEngine("epoch-828"), connectors, evidence },
    writeReservations,
  });
  const records = () => evidence.forMission(view.id);
  return { server, pep, channel, payments, connectors, writeReservations, records };
}

describe("the resource enforces an independent Resource-policy refusal (@spec runtime#input-resource-policy, #828)", () => {
  it("a policy refusal refuses the read resource_policy with the PDP's signed Decision Evidence and no result, the same over the co-resident and remote channels", async () => {
    for (const mode of MODES) {
      const x = await build(mode, RESOURCE_POLICY_REFUSES_ALL_FIXTURE);
      try {
        const res = await x.server.callReadTool("get_invoice", { invoice_id: "inv-1" }, TOKEN);
        expect(res.ok, mode).toBe(false);
        expect(res.result, mode).toBeUndefined();
        const decisions = x.records().filter((e) => e.kind === "decision");
        expect(decisions, mode).toHaveLength(1);
        expect(decisions[0]?.content, mode).toMatchObject({ decision: "deny", denial_reason: "resource_policy", emitter: { role: "pdp" } });
        expect(x.records().some((e) => e.kind === "execution"), mode).toBe(false);
      } finally {
        await x.channel.close();
        x.payments.db.close();
      }
    }
  });

  it("a policy refusal of a keyed write leaves no effect: no schedule, no reservation, no ledger entry, no Execution Evidence", async () => {
    for (const mode of MODES) {
      const x = await build(mode, RESOURCE_POLICY_REFUSES_ALL_FIXTURE);
      try {
        const res = await x.server.callWriteTool("schedule_payment", { invoice_id: "inv-1", idempotency_key: `idem_${mode}_828_policy` }, TOKEN);
        expect(res.ok, mode).toBe(false);
        expect(x.writeReservations.schedules(), mode).toEqual([]);
        expect(x.writeReservations.reservations(), mode).toEqual([]);
        expect(x.connectors.ledgerEntries(), mode).toEqual([]);
        expect(x.records().some((e) => e.kind === "execution"), mode).toBe(false);
        expect(x.records().find((e) => e.kind === "decision")?.content, mode).toMatchObject({ denial_reason: "resource_policy" });
      } finally {
        await x.channel.close();
        x.payments.db.close();
      }
    }
  });

  it("the same read permits when the policy allows, so each refusal above is the policy's", async () => {
    for (const mode of MODES) {
      const x = await build(mode, RESOURCE_POLICY_PERMITS_ALL_FIXTURE);
      try {
        const res = await x.server.callReadTool("get_invoice", { invoice_id: "inv-1" }, TOKEN);
        expect(res.ok, `${mode} ${JSON.stringify(res)}`).toBe(true);
      } finally {
        await x.channel.close();
        x.payments.db.close();
      }
    }
  });

  it("an unavailable policy refuses pdp_unreachable with no PDP decision attributed and nothing executed, the same over both channels", async () => {
    for (const mode of MODES) {
      const x = await build(mode, RESOURCE_POLICY_UNAVAILABLE_FIXTURE);
      try {
        const res = await x.server.callReadTool("get_invoice", { invoice_id: "inv-1" }, TOKEN);
        expect(res.ok, mode).toBe(false);
        expect(res.refusal_reason, mode).toBe("pdp_unreachable");
        expect(x.records().some((e) => e.kind === "decision"), mode).toBe(false);
        expect(x.records().some((e) => e.kind === "execution"), mode).toBe(false);
        const refusal = x.records().find((e) => e.kind === "refusal");
        expect(refusal?.content, mode).toMatchObject({ denial_reason: "pdp_unreachable", emitter: { role: "pep" } });
        expect(refusal?.content, mode).not.toHaveProperty("evaluation_id");
      } finally {
        await x.channel.close();
        x.payments.db.close();
      }
    }
  });

  it("the policy is asked about the verified subject under this resource's issuer, the authenticated client and the resolved invoice", async () => {
    const policy = resourcePolicyFixture();
    const x = await build("co-resident", policy);
    try {
      expect((await x.server.callReadTool("get_invoice", { invoice_id: "inv-1" }, TOKEN)).ok).toBe(true);
      expect(policy.queries).toEqual([
        { subject: { sub: "alice", iss: ISSUER }, client: "ap-agent", action: "payments:invoice.read", targets: [{ type: "invoice", id: "inv-1" }] },
      ]);
    } finally {
      await x.channel.close();
      x.payments.db.close();
    }
  });
});

/** An unconstrained list Mission: entitled to every vendor's invoices, so the read's targets are whatever the store holds. */
const listView: MissionView = {
  ...defaultView,
  id: "msn_rp_list",
  authority_hash: "sha-256:rp-list",
  authority_set: [{ type: "mission_resource_access", resource: CANONICAL_RESOURCE, actions: ["payments:invoice.list"] }],
};
const LIST_TOKEN: TokenFacts = {
  ...TOKEN,
  mission: { id: listView.id, issuer: listView.issuer, authority_hash: listView.authority_hash },
};
/** Invoices for acme and globex; initech is a vendor with none yet. */
const seedTwoVendors = (payments: PaymentsStore) =>
  payments.seed(
    [
      { id: "acme", name: "Acme", status: "approved" },
      { id: "globex", name: "Globex", status: "approved" },
      { id: "initech", name: "Initech", status: "approved" },
    ],
    [
      { id: "inv-acme-1", vendor_id: "acme", amount: "125.00", currency: "USD", payee_account: "acct-acme", status: "payable" },
      { id: "inv-globex-1", vendor_id: "globex", amount: "50.00", currency: "USD", payee_account: "acct-globex", status: "payable" },
    ],
  );
const LIST_FIXTURE = { view: listView, seed: seedTwoVendors };
const initechInvoice = { id: "inv-initech-1", vendor_id: "initech", amount: "75.00", currency: "USD", payee_account: "acct-initech", status: "payable" };
const vendorsOf = (result: unknown) => (result as Array<{ vendor_id: string }>).map((i) => i.vendor_id).sort();

describe("list_invoices names its actual targets to Resource policy and binds them (@spec runtime#input-resource-policy, runtime#read-binding, #828 step 5)", () => {
  it("an unconstrained read names every vendor the store holds invoices for: the policy is asked about each, and the parameter digest binds that set", async () => {
    for (const mode of MODES) {
      const policy = resourcePolicyFixture();
      const x = await build(mode, policy, undefined, LIST_FIXTURE);
      try {
        const res = await x.server.callReadTool("list_invoices", {}, LIST_TOKEN);
        expect(res.ok, `${mode} ${JSON.stringify(res)}`).toBe(true);
        expect(vendorsOf(res.result), mode).toEqual(["acme", "globex"]);
        expect(policy.queries.map((q) => q.targets), mode).toEqual([
          [
            { type: "vendor", id: "acme" },
            { type: "vendor", id: "globex" },
          ],
        ]);
        const bound = parameterDigest(
          buildListEffectiveParams({ action: "payments:invoice.list", resource: CANONICAL_RESOURCE, vendor_scope: ["acme", "globex"], vendor_scope_source: "all" }),
        );
        expect(x.records().find((e) => e.kind === "decision")?.content, mode).toMatchObject({ decision: "permit", parameter_digest: bound });
      } finally {
        await x.channel.close();
        x.payments.db.close();
      }
    }
  });

  it("a policy refusing one vendor refuses the whole unconstrained read resource_policy with no result, while a read naming the other vendor permits", async () => {
    for (const mode of MODES) {
      const refusesGlobex = resourcePolicyFixture((q) => q.targets.some((t) => t.id === "globex"));
      const x = await build(mode, refusesGlobex, undefined, LIST_FIXTURE);
      try {
        const refused = await x.server.callReadTool("list_invoices", {}, LIST_TOKEN);
        expect(refused.ok, mode).toBe(false);
        expect(refused.result, mode).toBeUndefined();
        expect(x.records().find((e) => e.kind === "decision")?.content, mode).toMatchObject({ decision: "deny", denial_reason: "resource_policy" });
        expect(x.records().some((e) => e.kind === "execution"), mode).toBe(false);
        const acme = await x.server.callReadTool("list_invoices", { vendor_id: "acme" }, LIST_TOKEN);
        expect(acme.ok, `${mode} ${JSON.stringify(acme)}`).toBe(true);
        expect(vendorsOf(acme.result), mode).toEqual(["acme"]);
      } finally {
        await x.channel.close();
        x.payments.db.close();
      }
    }
  });

  it("an invoice for a vendor the decision never named is never returned: before the last check it is a parameter mismatch, after it the bound filter drops it", async () => {
    for (const mode of MODES) {
      const early = await build(mode, RESOURCE_POLICY_PERMITS_ALL_FIXTURE, undefined, LIST_FIXTURE);
      try {
        const res = await early.server.callReadTool("list_invoices", {}, LIST_TOKEN, () => early.payments.seed([], [initechInvoice]));
        expect(res.ok, mode).toBe(false);
        expect(res.refusal_reason, mode).toBe("parameter_mismatch");
        expect(res.result, mode).toBeUndefined();
      } finally {
        await early.channel.close();
        early.payments.db.close();
      }
      const late = await build(mode, RESOURCE_POLICY_PERMITS_ALL_FIXTURE, undefined, LIST_FIXTURE);
      try {
        // The PEP's final permit-use check runs after reverifyList and just
        // before release: an invoice landing there is outside the bound set.
        const verify = late.pep.verifyPermitAtUse.bind(late.pep);
        let calls = 0;
        late.pep.verifyPermitAtUse = async (attempt) => {
          calls += 1;
          if (calls === 2) late.payments.seed([], [initechInvoice]);
          return verify(attempt);
        };
        const res = await late.server.callReadTool("list_invoices", {}, LIST_TOKEN);
        expect(calls, mode).toBe(2);
        expect(res.ok, `${mode} ${JSON.stringify(res)}`).toBe(true);
        expect(vendorsOf(res.result), mode).toEqual(["acme", "globex"]);
      } finally {
        await late.channel.close();
        late.payments.db.close();
      }
    }
  });

  it("a named vendor the store does not hold is refused unknown_vendor before any decision: no policy query, no Decision Evidence, a signed target_unresolvable refusal", async () => {
    for (const mode of MODES) {
      const policy = resourcePolicyFixture();
      const x = await build(mode, policy, undefined, LIST_FIXTURE);
      try {
        const res = await x.server.callReadTool("list_invoices", { vendor_id: "umbrella" }, LIST_TOKEN);
        expect(res.ok, mode).toBe(false);
        expect(res.result, mode).toBeUndefined();
        expect(policy.queries, mode).toEqual([]);
        expect(x.records().some((e) => e.kind === "decision"), mode).toBe(false);
        expect(x.records().find((e) => e.kind === "refusal")?.content, mode).toMatchObject({ denial_reason: "target_unresolvable", emitter: { role: "pep" } });
      } finally {
        await x.channel.close();
        x.payments.db.close();
      }
    }
  });
});

const API_URL = process.env.OPENFGA_HTTP_URL ?? "https://localhost:8080";
const KEY = process.env.OPENFGA_PRESHARED_KEY ?? "dev-preshared-key-change-me";
const CA = process.env.OPENFGA_CA_CERT;

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
if (!up) console.warn("OpenFGA unreachable; skipping the PEP Resource-policy OpenFGA tests");

d("the deployment's OpenFGA Resource policy at the resource (@spec runtime#input-resource-policy, #828)", () => {
  it("revoking only the stored entitlement refuses the next read resource_policy with no result; restoring it permits, the same over both channels", async () => {
    const { fga } = await Fga.bootstrap({ apiUrl: API_URL, presharedKey: KEY, ...(CA ? { caCertPath: CA } : {}) });
    const admin = new FgaDomainAdmin(fga);
    const entitlement = { user: principalObject({ iss: ISSUER, sub: "alice" }), relation: "authorized_reader", object: "vendor:acme" };
    await admin.grant([entitlement, { user: "vendor:acme", relation: "vendor", object: "invoice:inv-1" }]);
    const policy = fgaResourcePolicy(fga, { principals: issuerLocalPrincipals(ISSUER) });
    for (const mode of MODES) {
      // The Mission check runs against the same live OpenFGA, over the
      // Mission's own contextual tuples.
      const x = await build(mode, policy, fga);
      try {
        expect((await x.server.callReadTool("get_invoice", { invoice_id: "inv-1" }, TOKEN)).ok, mode).toBe(true);
        await admin.revoke([entitlement]);
        const refused = await x.server.callReadTool("get_invoice", { invoice_id: "inv-1" }, TOKEN);
        expect(refused.ok, mode).toBe(false);
        expect(refused.result, mode).toBeUndefined();
        expect(x.records().filter((e) => e.kind === "decision").at(-1)?.content, mode).toMatchObject({ decision: "deny", denial_reason: "resource_policy" });
        await admin.grant([entitlement]);
        expect((await x.server.callReadTool("get_invoice", { invoice_id: "inv-1" }, TOKEN)).ok, mode).toBe(true);
        expect(x.records().filter((e) => e.kind === "decision").map((e) => (e.content as { decision: string }).decision), mode)
          .toEqual(["permit", "deny", "permit"]);
      } finally {
        await x.channel.close();
        x.payments.db.close();
      }
    }
  });

  it("an unconstrained list names every invoice vendor to the stored policy: revoking only one vendor's entitlement refuses the whole read resource_policy, a read of the other vendor still permits, and restoring it permits both, the same over both channels (#828 step 5)", async () => {
    const { fga } = await Fga.bootstrap({ apiUrl: API_URL, presharedKey: KEY, ...(CA ? { caCertPath: CA } : {}) });
    const admin = new FgaDomainAdmin(fga);
    const alice = principalObject({ iss: ISSUER, sub: "alice" });
    const globex = { user: alice, relation: "authorized_reader", object: "vendor:globex" };
    await admin.grant([{ user: alice, relation: "authorized_reader", object: "vendor:acme" }, globex]);
    const policy = fgaResourcePolicy(fga, { principals: issuerLocalPrincipals(ISSUER) });
    for (const mode of MODES) {
      const x = await build(mode, policy, fga, LIST_FIXTURE);
      try {
        const both = await x.server.callReadTool("list_invoices", {}, LIST_TOKEN);
        expect(both.ok, `${mode} ${JSON.stringify(both)}`).toBe(true);
        expect(vendorsOf(both.result), mode).toEqual(["acme", "globex"]);
        await admin.revoke([globex]);
        const refused = await x.server.callReadTool("list_invoices", {}, LIST_TOKEN);
        expect(refused.ok, mode).toBe(false);
        expect(refused.result, mode).toBeUndefined();
        expect(x.records().filter((e) => e.kind === "decision").at(-1)?.content, mode).toMatchObject({ decision: "deny", denial_reason: "resource_policy" });
        const acme = await x.server.callReadTool("list_invoices", { vendor_id: "acme" }, LIST_TOKEN);
        expect(acme.ok, `${mode} ${JSON.stringify(acme)}`).toBe(true);
        expect(vendorsOf(acme.result), mode).toEqual(["acme"]);
        await admin.grant([globex]);
        const restored = await x.server.callReadTool("list_invoices", {}, LIST_TOKEN);
        expect(restored.ok, `${mode} ${JSON.stringify(restored)}`).toBe(true);
        expect(vendorsOf(restored.result), mode).toEqual(["acme", "globex"]);
      } finally {
        await x.channel.close();
        x.payments.db.close();
      }
    }
  });
});
