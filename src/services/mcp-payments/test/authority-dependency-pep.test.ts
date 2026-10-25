/**
 * @spec runtime#input-authority-dependency, runtime#input-resource-policy
 * (#830, D798, D794): a declared authority dependency enforced as a composed
 * resource-policy step at the PEP.
 *
 * The declaration routes direct evaluation to the PEP, so the decision point
 * evaluates no dependency: it permits the read within Mission authority, and
 * the PEP's composed step still refuses it when the Subject's continuing
 * delegation is not established (D794's example). The refusal is the
 * mechanism's own `resource_policy`, the permit is disposed `suppressed`
 * before anything is released, and the deployment's dependency evidence
 * keeps the cause: a known withdrawal, an observed invalidation, a stale
 * observation, or no acceptable observation (an unavailable source).
 */

import {
  type AuthorityDependencyDeclaration,
  AuthorityDependencyEvidence,
  AuthorityDependencyResolver,
  parseAuthorityDependencyDeclarations,
} from "@mission/core";
import { AUTHORITY_DEPENDENCIES, parseIdentityState } from "@mission/demo-data";
import {
  createDecisionChannel,
  createEphemeralDecisionPoint,
  type Fga,
  loadRuntimePosture,
  type MissionView,
  relationForAction,
  RUNTIME_POSTURE,
  stalenessBound,
} from "@mission/pdp";
import { RESOURCE_POLICY_PERMITS_ALL_FIXTURE } from "@mission/pdp/test-support";
import { describe, expect, it } from "vitest";
import {
  CANONICAL_RESOURCE,
  Connectors,
  createEphemeralEvidenceKeys,
  EvidenceStore,
  McpPaymentsServer,
  openEphemeralWriteReservationStore,
  PaymentsStore,
  Pep,
  type TokenFacts,
  TransactionEngine,
} from "../src/index.js";
import { ALL_ACTIONS_CREDENTIAL } from "./credential-fixtures.js";

const ISSUER = "https://as.test";
const T0 = Date.now();

const view: MissionView = {
  id: "msn_dep_pep",
  issuer: ISSUER,
  state: "active",
  version: 1,
  authority_hash: "sha-256:dep-pep",
  authority_set: [{ type: "mission_resource_access", resource: CANONICAL_RESOURCE, actions: ["payments:invoice.read"], constraints: { vendors: ["acme"] } }],
  subject: { iss: ISSUER, sub: "alice" },
  client_id: "ap-agent",
};

const TOKEN: TokenFacts = {
  sub: "alice",
  iss: ISSUER,
  clientId: "ap-agent",
  cnfJkt: "jkt-830",
  mission: { id: view.id, issuer: view.issuer, authority_hash: view.authority_hash },
  credentialAuthority: ALL_ACTIONS_CREDENTIAL,
};

/** The shipped declaration with direct evaluation routed to the PEP's composed step. */
function routedToPep(): AuthorityDependencyDeclaration {
  const shipped = AUTHORITY_DEPENDENCIES[0] as AuthorityDependencyDeclaration;
  return parseAuthorityDependencyDeclarations([{ ...shipped, enforcement: { ...shipped.enforcement, direct: "pep" } }])[0] as AuthorityDependencyDeclaration;
}

/** A resource whose PEP evaluates the dependency, over a controlled identity source and clock. */
async function build() {
  let source: unknown = [{ sub: "alice" }];
  let nowMs = T0;
  const evidence = new AuthorityDependencyEvidence();
  const resolver = new AuthorityDependencyResolver({
    issuer: ISSUER,
    read: async () => {
      if (source instanceof Error) throw source;
      return source;
    },
    parse: (raw) => parseIdentityState(raw),
    now: () => nowMs,
  });
  const point = createEphemeralDecisionPoint({
    emitterId: CANONICAL_RESOURCE,
    audience: CANONICAL_RESOURCE,
    resourcePolicy: RESOURCE_POLICY_PERMITS_ALL_FIXTURE,
  });
  const keys = createEphemeralEvidenceKeys({ decisionPoint: point });
  const records = new EvidenceStore(keys.signing, keys.resolver);
  const payments = new PaymentsStore();
  payments.seed(
    [{ id: "acme", name: "Acme", status: "approved" }],
    [{ id: "inv-1", vendor_id: "acme", amount: "125.00", currency: "USD", payee_account: "acct-acme", status: "payable" }],
  );
  const missionFga = { checkWithContext: async () => true } as unknown as Fga;
  const loadView = (ref: { id: string; issuer: string }) =>
    ref.id === view.id && ref.issuer === view.issuer
      ? { view, observation: { state: view.state, version: view.version, mode: "fresh", freshness_at: new Date().toISOString() } }
      : undefined;
  const channel = await createDecisionChannel(point, {
    mode: "co-resident",
    pepId: "mcp-payments-pep",
    audience: CANONICAL_RESOURCE,
    getOptions: () => ({ view, fga: missionFga, modelId: "test", now: () => new Date(), stalenessBound, relationForAction, stateSourcePlacement: "pep" as const }),
  });
  const decisions: unknown[] = [];
  const pep = new Pep({
    payments,
    evidence: records,
    fga: missionFga,
    modelId: "test",
    loadView,
    instanceEpoch: "epoch-830",
    decide: async (req, opts) => {
      const decision = await channel.decide(req, opts);
      decisions.push(decision);
      return decision;
    },
    claims: channel.claims,
    authorityDependency: {
      declaration: routedToPep(),
      resolver,
      evidence,
      now: () => nowMs,
      governed: (mission) => (mission.id === view.id ? { subject: { iss: ISSUER, sub: "alice" }, clientId: "ap-agent" } : undefined),
    },
  });
  const connectors = new Connectors();
  const server = new McpPaymentsServer({
    pep,
    payments,
    loadView,
    issuer: ISSUER,
    jwks: { keys: [] },
    keyRoles: { accessToken: [], attenuationRoot: [], transactionToken: [] },
    enforcementScopeStatement: loadRuntimePosture({ ...RUNTIME_POSTURE, remote_decision_channels: channel.remoteDecisionChannels }),
    transaction: { engine: new TransactionEngine("epoch-830"), connectors, evidence: records },
    writeReservations: openEphemeralWriteReservationStore({ owner: RUNTIME_POSTURE.mediated_scope.pep_locations[0] as string }),
  });
  return {
    server,
    resolver,
    evidence,
    decisions,
    read: () => server.callReadTool("get_invoice", { invoice_id: "inv-1" }, TOKEN),
    executions: () => records.forMission(view.id).filter((e) => e.kind === "execution").map((e) => (e as { content: Record<string, unknown> }).content),
    set: (next: unknown) => {
      source = next;
    },
    after: (seconds: number) => {
      nowMs = T0 + seconds * 1000;
    },
    close: async () => {
      await channel.close();
      payments.db.close();
    },
  };
}

/** The PDP permitted within Mission authority; the PEP's composed step refused `resource_policy` and released nothing. */
function expectComposedRefusal(
  x: Awaited<ReturnType<typeof build>>,
  res: { ok: boolean; denial_reason?: string; result?: unknown },
  label: string,
): void {
  expect(res.ok, label).toBe(false);
  expect(res.denial_reason, label).toBe("resource_policy");
  expect(res.result, label).toBeUndefined();
  expect((x.decisions.at(-1) as { decision: boolean }).decision, label).toBe(true);
  expect(x.executions().at(-1), label).toMatchObject({ outcome: "suppressed", error: "resource_policy" });
}

describe("a declared authority dependency enforced as a composed resource-policy step at the PEP (@spec runtime#input-authority-dependency, #830)", () => {
  it("permits the read while an observation within its bound establishes the dependency", async () => {
    const x = await build();
    try {
      await x.resolver.refresh();
      const res = await x.read();
      expect(res.ok, JSON.stringify(res)).toBe(true);
      expect(x.evidence.entries()).toEqual([]);
    } finally {
      await x.close();
    }
  });

  it("refuses resource_policy at the PEP on a known withdrawal though the PDP permits within Mission authority (D794), and retains it as withdrawn", async () => {
    const x = await build();
    try {
      x.set([{ sub: "alice", withdrawn_delegations: ["ap-agent"] }]);
      await x.resolver.refresh();
      expectComposedRefusal(x, await x.read(), "withdrawn");
      expect(x.evidence.entries().at(-1)).toMatchObject({
        enforcer: "pep",
        dependency: "subject-delegation",
        failure: "withdrawn",
        mission: { id: view.id, issuer: ISSUER },
        client: "ap-agent",
        action: "payments:invoice.read",
      });
    } finally {
      await x.close();
    }
  });

  it("refuses resource_policy at the PEP on an observed invalidation (the Subject disabled), on a stale observation, and when no acceptable observation remains", async () => {
    const x = await build();
    try {
      x.set([{ sub: "alice", status: "disabled" }]);
      await x.resolver.refresh();
      expectComposedRefusal(x, await x.read(), "disabled");
      x.set([{ sub: "alice" }]);
      await x.resolver.refresh();
      expect((await x.read()).ok).toBe(true);
      x.after(300);
      expectComposedRefusal(x, await x.read(), "stale");
      x.set(new Error("identity source unreachable"));
      await x.resolver.refresh();
      expectComposedRefusal(x, await x.read(), "unavailable");
      expect(x.evidence.entries().map((e) => [e.enforcer, e.failure])).toEqual([
        ["pep", "invalidated"],
        ["pep", "stale"],
        ["pep", "unavailable"],
      ]);
    } finally {
      await x.close();
    }
  });

  it("keeps serving through a source outage while the cached observation is within its validity", async () => {
    const x = await build();
    try {
      await x.resolver.refresh();
      x.set(new Error("identity source unreachable"));
      x.after(10);
      expect(await x.resolver.refresh()).toBe(false);
      x.after(200);
      const res = await x.read();
      expect(res.ok, JSON.stringify(res)).toBe(true);
    } finally {
      await x.close();
    }
  });
});
