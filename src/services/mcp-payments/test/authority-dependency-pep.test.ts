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
 *
 * The step's dependency ceiling travels with the permit into execution
 * admission (D813): on every dispatch path (a read, an unkeyed and a keyed
 * reversible write, and the transaction tier) a permit admitted while the
 * observation was valid releases no effect once that validity has passed,
 * and a known withdrawal reaching the PEP between admission and release
 * stops the release too.
 */

import { randomUUID } from "node:crypto";

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
  openEphemeralClaimDomain,
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
  TOOLS,
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
  authority_set: [
    {
      type: "mission_resource_access",
      resource: CANONICAL_RESOURCE,
      actions: [...new Set(TOOLS.map((t) => t.action))],
      constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
    },
  ],
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
  // The resolver the enforcement reads: the test can hand it a different one
  // between admission and release, as a read completing in that window would.
  let viewing = resolver;
  // The transaction tier's high-consequence class needs the PDP's claim
  // domain; settlement verifies against this resource's evidence keys.
  let pepKeys: ((params: never) => unknown) | undefined;
  const point = createEphemeralDecisionPoint({
    emitterId: CANONICAL_RESOURCE,
    audience: CANONICAL_RESOURCE,
    resourcePolicy: RESOURCE_POLICY_PERMITS_ALL_FIXTURE,
    claims: openEphemeralClaimDomain({
      owner: RUNTIME_POSTURE.pdps[0] as string,
      statement: RUNTIME_POSTURE,
      now: () => new Date(nowMs),
      settlementKeys: ((params: never) => pepKeys?.(params)) as never,
    }),
  });
  const keys = createEphemeralEvidenceKeys({ decisionPoint: point });
  pepKeys = keys.resolver as never;
  const records = new EvidenceStore(keys.signing, keys.resolver);
  const payments = new PaymentsStore();
  payments.seed(
    [{ id: "acme", name: "Acme", status: "approved" }],
    [
      { id: "inv-1", vendor_id: "acme", amount: "125.00", currency: "USD", payee_account: "acct-acme", status: "payable" },
      { id: "inv-2", vendor_id: "acme", amount: "75.00", currency: "USD", payee_account: "acct-acme", status: "payable" },
    ],
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
      resolver: { view: (principal: { iss: string; sub: string }) => viewing.view(principal) } as unknown as AuthorityDependencyResolver,
      evidence,
      now: () => nowMs,
      governed: (mission) => (mission.id === view.id ? { subject: { iss: ISSUER, sub: "alice" }, clientId: "ap-agent" } : undefined),
    },
  });
  const connectors = new Connectors(() => new Date(nowMs));
  const server = new McpPaymentsServer({
    pep,
    payments,
    loadView,
    issuer: ISSUER,
    jwks: { keys: [] },
    keyRoles: { accessToken: [], attenuationRoot: [], transactionToken: [] },
    enforcementScopeStatement: loadRuntimePosture({ ...RUNTIME_POSTURE, remote_decision_channels: channel.remoteDecisionChannels }),
    transaction: { engine: new TransactionEngine("epoch-830", () => new Date(nowMs)), connectors, evidence: records },
    writeReservations: openEphemeralWriteReservationStore({ owner: RUNTIME_POSTURE.mediated_scope.pep_locations[0] as string, now: () => new Date(nowMs) }),
  });
  return {
    server,
    resolver,
    evidence,
    decisions,
    read: (hook?: () => void) => server.callReadTool("get_invoice", { invoice_id: "inv-1" }, TOKEN, hook),
    /** Every dispatch path, each called with a hook that runs between admission and release. */
    paths: {
      read: (hook?: () => void, invoice = "inv-1") => server.callReadTool("get_invoice", { invoice_id: invoice }, TOKEN, hook),
      "unkeyed write": (hook?: () => void, invoice = "inv-1") => server.callWriteTool("hold_transfer", { invoice_id: invoice }, TOKEN, hook),
      "keyed write": (hook?: () => void, invoice = "inv-1") =>
        server.callWriteTool("schedule_payment", { invoice_id: invoice, idempotency_key: `idem_${randomUUID()}` }, TOKEN, hook),
      "transaction tier": (hook?: () => void, invoice = "inv-1") =>
        server.callTransactionTool("execute_wire_transfer", { invoice_id: invoice, idempotency_key: `idem_${randomUUID()}` }, TOKEN, hook),
    } as Record<string, (hook?: () => void, invoice?: string) => Promise<{ ok: boolean; refusal_reason?: string; result?: unknown }>>,
    ledger: () => connectors.ledgerEntries(view.id),
    /** From now on the enforcement reads `next` (a resolver the test refreshed). */
    observeWith: (next: AuthorityDependencyResolver) => {
      viewing = next;
    },
    newResolver: (records: unknown) =>
      new AuthorityDependencyResolver({ issuer: ISSUER, read: async () => records, parse: (raw) => parseIdentityState(raw), now: () => nowMs }),
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

describe("the composed step's dependency ceiling and recheck hold at release on every dispatch path (@spec runtime#input-authority-dependency, #830, D813)", () => {
  it("releases no effect once the observation the step relied on has passed its validity, on a read, an unkeyed write, a keyed write and the transaction tier", async () => {
    const x = await build();
    try {
      for (const [path, call] of Object.entries(x.paths)) {
        // An observation 299 s old at admission, of its 300 s validity; released 1 s later.
        x.after(-299);
        await x.resolver.refresh();
        x.after(0);
        const crossed = await call(() => x.after(1));
        expect(crossed.ok, `${path}: ${JSON.stringify(crossed)}`).toBe(false);
        expect(crossed.refusal_reason, `${path}: ${JSON.stringify(crossed)}`).toBe("resource_policy");
        expect(crossed.result, path).toBeUndefined();
        expect(x.executions().at(-1), path).toMatchObject({ outcome: "suppressed", error: "resource_policy" });
        expect(x.evidence.entries().at(-1), path).toMatchObject({ enforcer: "pep", failure: "stale", mission: { id: view.id } });
        expect(x.ledger(), path).toHaveLength(0);
        // The same path on another invoice, admitted and released within a
        // fresh observation's validity (the refused operation's key stays
        // claimed for its lease).
        await x.resolver.refresh();
        const released = await call(() => x.after(2), "inv-2");
        expect(released.ok, `${path}: ${JSON.stringify(released)}`).toBe(true);
      }
      expect(x.ledger()).toHaveLength(1);
    } finally {
      await x.close();
    }
  });

  it("releases no effect when a known withdrawal reaches the PEP between admission and release, on every dispatch path", async () => {
    const x = await build();
    try {
      await x.resolver.refresh();
      const withdrawn = x.newResolver([{ sub: "alice", withdrawn_delegations: ["ap-agent"] }]);
      await withdrawn.refresh();
      for (const [path, call] of Object.entries(x.paths)) {
        x.observeWith(x.resolver);
        const refused = await call(() => x.observeWith(withdrawn));
        expect(refused.ok, `${path}: ${JSON.stringify(refused)}`).toBe(false);
        expect(refused.refusal_reason, path).toBe("resource_policy");
        expect(x.executions().at(-1), path).toMatchObject({ outcome: "suppressed", error: "resource_policy" });
        expect(x.evidence.entries().at(-1), path).toMatchObject({ enforcer: "pep", failure: "withdrawn" });
      }
      expect(x.ledger()).toHaveLength(0);
    } finally {
      await x.close();
    }
  });
});

describe("the composed step's ceiling on a read admitted at the edge of the observation's validity (@spec runtime#input-authority-dependency, #830, D813)", () => {
  it("refuses a read admitted at 299 s of a 300 s validity and reaching release at 300 s", async () => {
    const x = await build();
    try {
      await x.resolver.refresh();
      x.after(299);
      const result = await x.read(() => x.after(300));
      expect(result.ok, JSON.stringify(result)).toBe(false);
      expect(result.refusal_reason).toBe("resource_policy");
      expect(x.executions().at(-1)).toMatchObject({ outcome: "suppressed", error: "resource_policy" });
    } finally {
      await x.close();
    }
  });
});
