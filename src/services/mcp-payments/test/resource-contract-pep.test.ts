/**
 * @spec runtime#resource-contract, resource-access#resource-contract,
 * authzen#context-resource-contract, authzen#response-context,
 * runtime-evidence#pre-decision-refusal,
 * runtime-evidence#execution-evidence-object (#249, D553): the payments
 * resource's contract versions and their enforcement at the PEP.
 *
 * The resource declares its contract versions in the Enforcement Scope
 * Statement. The PEP establishes the reference it presents from the
 * credential's applicable entry against its own declarations, refuses one
 * that does not resolve before any decision request (a Refusal Record),
 * normalizes and performs the operation under the resolved version's
 * Operation Profile, and re-resolves the permit's reference before every
 * release, suppressing the effect (Execution Evidence) when it no longer
 * resolves or differs from the contract it would perform under.
 *
 * Runs through both the co-resident and the remote decision channel, over a
 * stub FGA that always allows and a permitting Resource policy fixture, so
 * only the contract checks decide.
 */

import {
  type ActionPhase,
  establishOperationTarget,
  RESOURCE_CONTRACT_STATES,
  ResourceContractDeclarations,
  type ResourceContractRef,
  resourceContractDigest,
} from "@mission/core";
import { RESOURCE_CONTRACTS, RUNTIME_SCOPE_CONFIG } from "@mission/demo-data";
import {
  createDecisionChannel,
  createEphemeralDecisionPoint,
  type EvaluationRequest,
  type Fga,
  loadRuntimePosture,
  type MissionView,
  PostureConfigError,
  relationForAction,
  RUNTIME_POSTURE,
  stalenessBound,
} from "@mission/pdp";
import { RESOURCE_POLICY_PERMITS_ALL_FIXTURE } from "@mission/pdp/test-support";
import { describe, expect, it } from "vitest";
import {
  type ActionMapping,
  CANONICAL_RESOURCE,
  Connectors,
  createEphemeralEvidenceKeys,
  credentialAuthorityFrom,
  EvidenceStore,
  McpPaymentsServer,
  openEphemeralWriteReservationStore,
  PAYMENTS_INVOICE_CONTRACT,
  PAYMENTS_PROFILE_VERSION,
  PaymentsStore,
  PaymentsToolCatalog,
  Pep,
  TOOL_ACTIONS,
  type TokenFacts,
  TransactionEngine,
} from "../src/index.js";

const ISSUER = "https://as.test";
const MODES = ["co-resident", "remote"] as const;
const CONTRACT = "https://payments.example/contracts/payments";
const ACTIONS = [...new Set(Object.values(TOOL_ACTIONS).map((m) => m.action))];
const NOW = () => new Date("2026-10-20T12:00:00Z");

/** A retained Operation Profile under which `get_invoice` targets the invoice, not the service. */
const RETAINED_PROFILE = "payments-retained-profile";
const RETAINED_TABLE: Record<string, ActionMapping> = {
  ...TOOL_ACTIONS,
  get_invoice: { ...(TOOL_ACTIONS.get_invoice as ActionMapping), target: PAYMENTS_INVOICE_CONTRACT },
};

const doc = (version: string, profile: string) => ({
  id: CONTRACT,
  version,
  operation_profile: profile,
  operations: Object.fromEntries(Object.entries(TOOL_ACTIONS).map(([tool, m]) => [tool, { action: m.action }])),
});
const ref = (version: string, profile = PAYMENTS_PROFILE_VERSION): ResourceContractRef => ({
  id: CONTRACT,
  version,
  digest: resourceContractDigest(doc(version, profile)),
});
const declared = (version: string, state: string, profile = PAYMENTS_PROFILE_VERSION, extra = {}) => ({
  version,
  state,
  digest: ref(version, profile).digest,
  document: doc(version, profile),
  ...extra,
});
const declarations = (versions: unknown[], requires: string[] = []) =>
  new ResourceContractDeclarations([
    { resource: CANONICAL_RESOURCE, resource_match: "prefix", id: CONTRACT, requires_reference: requires, versions },
  ]);

const V1 = ref("v1", RETAINED_PROFILE);
const V2 = ref("v2");
/** v1 retained (superseded, its own profile) and v2 current: both resolve. */
const RETAINED = declarations([
  declared("v1", "superseded", RETAINED_PROFILE, { retained_until: "2026-11-01T00:00:00Z" }),
  declared("v2", "current"),
]);
/** v2 alone: a v1 reference resolves nowhere. */
const V2_ONLY = declarations([declared("v2", "current")]);
/** v1 current under the live profile: the declaration a v1 entry was approved under. */
const V1_LIVE = ref("v1");
const V1_CURRENT = declarations([declared("v1", "current")]);

type Entry = MissionView["authority_set"][number];
const entry = (r: ResourceContractRef | undefined, resource = CANONICAL_RESOURCE, over: Partial<Entry> = {}): Entry =>
  ({
    type: "mission_resource_access",
    resource,
    actions: ACTIONS,
    ...(r ? { resource_contract: r } : {}),
    ...over,
  }) as Entry;
const viewOf = (authority_set: Entry[]): MissionView => ({
  id: "msn_249_pep",
  issuer: ISSUER,
  state: "active",
  version: 1,
  authority_hash: "sha-256:h249-pep",
  authority_set,
  subject: { iss: ISSUER, sub: "alice" },
  client_id: "ap-agent",
});
const tokenFor = (view: MissionView, entries: Entry[] = view.authority_set): TokenFacts => ({
  sub: "alice",
  iss: ISSUER,
  clientId: "ap-agent",
  cnfJkt: "jkt-249",
  mission: { id: view.id, issuer: view.issuer, authority_hash: view.authority_hash },
  credentialAuthority: credentialAuthorityFrom(entries),
});

interface Built {
  server: McpPaymentsServer;
  pep: Pep;
  decided: EvaluationRequest[];
  records: () => ReturnType<EvidenceStore["forMission"]>;
  setPepContracts: (d: ResourceContractDeclarations) => void;
  close: () => Promise<void>;
}

async function build(
  mode: (typeof MODES)[number],
  view: MissionView,
  contracts: ResourceContractDeclarations,
  opts: { pdpContracts?: ResourceContractDeclarations; now?: () => Date } = {},
): Promise<Built> {
  const now = opts.now ?? NOW;
  const point = createEphemeralDecisionPoint({
    emitterId: CANONICAL_RESOURCE,
    audience: CANONICAL_RESOURCE,
    resourcePolicy: RESOURCE_POLICY_PERMITS_ALL_FIXTURE,
    resourceContracts: opts.pdpContracts ?? contracts,
  });
  const keys = createEphemeralEvidenceKeys({ decisionPoint: point });
  const evidence = new EvidenceStore(keys.signing, keys.resolver);
  const payments = new PaymentsStore();
  payments.seed(
    [{ id: "acme", name: "Acme", status: "approved" }],
    ["inv-1", "inv-2"].map((id) => ({
      id,
      vendor_id: "acme",
      amount: "125.00",
      currency: "USD",
      payee_account: "acct-acme",
      status: "payable",
    })),
  );
  const fga = { checkWithContext: async () => true } as unknown as Fga;
  const loadView = (r: { id: string; issuer: string }) =>
    r.id === view.id && r.issuer === view.issuer
      ? { view, observation: { state: view.state, version: view.version, mode: "fresh", freshness_at: now().toISOString() } }
      : undefined;
  const channel = await createDecisionChannel(point, {
    mode,
    pepId: "mcp-payments-pep",
    audience: CANONICAL_RESOURCE,
    operationContracts: [{ service: CANONICAL_RESOURCE }, PAYMENTS_INVOICE_CONTRACT],
    getOptions: () => ({ view, fga, modelId: "test", now, stalenessBound, relationForAction, stateSourcePlacement: "pep" as const }),
  });
  const decided: EvaluationRequest[] = [];
  let pepContracts = contracts;
  const pep = new Pep({
    payments,
    evidence,
    fga,
    modelId: "test",
    loadView,
    instanceEpoch: "epoch-249",
    now,
    resourceContracts: () => pepContracts,
    retainedOperationProfiles: () => ({ [RETAINED_PROFILE]: RETAINED_TABLE }),
    decide: (req, o) => {
      decided.push(req);
      return channel.decide(req, o);
    },
    claims: channel.claims,
  });
  const writeReservations = openEphemeralWriteReservationStore({ owner: RUNTIME_POSTURE.mediated_scope.pep_locations[0] as string });
  const server = new McpPaymentsServer({
    pep,
    payments,
    loadView,
    issuer: ISSUER,
    jwks: { keys: [] },
    keyRoles: { accessToken: [], attenuationRoot: [], transactionToken: [] },
    enforcementScopeStatement: loadRuntimePosture({ ...RUNTIME_POSTURE, remote_decision_channels: channel.remoteDecisionChannels }),
    transaction: { engine: new TransactionEngine("epoch-249", now), connectors: new Connectors(), evidence },
    writeReservations,
  });
  return {
    server,
    pep,
    decided,
    records: () => evidence.forMission(view.id),
    setPepContracts: (d) => {
      pepContracts = d;
    },
    close: () => channel.close(),
  };
}

describe("the payments resource declares its contract versions (@spec runtime#resource-contract, #249)", () => {
  const [shipped] = RESOURCE_CONTRACTS.declarations;
  const current = shipped?.versions.find((v) => v.state === "current");

  it("declares one current version of the payments contract over the canonical resource, covering every operation, with its state", () => {
    expect(RESOURCE_CONTRACTS.declarations).toHaveLength(1);
    expect(shipped).toMatchObject({ resource: CANONICAL_RESOURCE, resource_match: "prefix", id: CONTRACT });
    expect(shipped?.versions.every((v) => (RESOURCE_CONTRACT_STATES as readonly string[]).includes(v.state))).toBe(true);
    expect(current?.operation_profile).toBe(PAYMENTS_PROFILE_VERSION);
    expect([...(current?.operations ?? [])].sort()).toEqual([...ACTIONS].sort());
    expect(current?.digest).toBe(resourceContractDigest(current?.document as never));
  });

  it("the declared contract material is what the resource performs: each operation's action, phase, class and target, and each catalog-sourced capability's digest, so a change to any of it without a new version fails here", () => {
    const operations = (current?.document as { operations: Record<string, Record<string, unknown>> }).operations;
    const catalog = new PaymentsToolCatalog();
    expect(Object.keys(operations).sort()).toEqual(Object.keys(TOOL_ACTIONS).sort());
    for (const [tool, m] of Object.entries(TOOL_ACTIONS)) {
      const op = operations[tool] as { action: string; phase?: ActionPhase; action_class: string; operation_target: string; capability: { tool_id: string; source_digest: string } };
      expect(op.action, tool).toBe(m.action);
      expect(op.phase, tool).toBe(m.phase);
      expect(op.action_class, tool).toBe(m.actionClass);
      expect(op.operation_target, tool).toBe("service");
      expect(establishOperationTarget(m.target, {}), tool).toEqual({ ok: true, target: CANONICAL_RESOURCE });
      const resolved = catalog.resolve(tool);
      if (!resolved.catalog_sourced) throw new Error(`${tool} is catalog-sourced`);
      expect(op.capability, tool).toEqual({ tool_id: resolved.binding.tool_id, source_digest: resolved.binding.source_digest });
    }
  });

  it("refuses at load a statement whose declared document no longer hashes to its digest: published bytes are immutable for a reference", () => {
    const stmt = structuredClone(RUNTIME_SCOPE_CONFIG) as { extensions: { resource_contracts: Array<{ versions: Array<{ document: Record<string, unknown> }> }> } };
    const version = stmt.extensions.resource_contracts[0]?.versions[0];
    if (!version) throw new Error("declared");
    version.document = { ...version.document, operation_profile: "payments-runtime-profile-changed" };
    expect(() => loadRuntimePosture(stmt)).toThrow(PostureConfigError);
    expect(() => loadRuntimePosture(stmt)).toThrow(/does not commit the declared document/);
    expect(() => loadRuntimePosture(structuredClone(RUNTIME_SCOPE_CONFIG))).not.toThrow();
  });

  it("refuses at load a version without a state, and a superseded version without a declared retention", () => {
    for (const [label, mutate] of [
      ["no state", (v: Record<string, unknown>) => delete v.state],
      ["superseded without retention", (v: Record<string, unknown>) => (v.state = "superseded")],
    ] as const) {
      const stmt = structuredClone(RUNTIME_SCOPE_CONFIG) as { extensions: { resource_contracts: Array<{ versions: Array<Record<string, unknown>> }> } };
      mutate(stmt.extensions.resource_contracts[0]?.versions[0] as Record<string, unknown>);
      expect(() => loadRuntimePosture(stmt), label).toThrow(/extensions\.resource_contracts/);
    }
  });
});

describe("the PEP presents the contract it will perform under (@spec authzen#context-resource-contract, #249)", () => {
  it("carries the applicable entry's reference, resolved against its own declarations, and never one an argument asserts", async () => {
    const view = viewOf([entry(V1_LIVE)]);
    for (const mode of MODES) {
      const x = await build(mode, view, V1_CURRENT);
      try {
        // Straight to the enforcement path, past the intake that refuses an
        // unknown argument: the PEP itself must ignore it.
        const res = await x.pep.enforce("get_invoice", { invoice_id: "inv-1", resource_contract: V2 }, tokenFor(view));
        expect(res.permitted, mode).toBe(true);
        expect(x.decided[0]?.resource.properties.resource_contract, mode).toEqual(V1_LIVE);
        expect((res.decision?.context.conditions as Record<string, unknown>).resource_contract, mode).toEqual(V1_LIVE);
      } finally {
        await x.close();
      }
    }
  });
});

describe("a reference that does not resolve at the PEP refuses before the decision request (@spec resource-access#resource-contract, runtime-evidence#pre-decision-refusal, #249)", () => {
  it.each([
    ["the resource serves only v2", V2_ONLY],
    ["the v1 definition changed under the same version", declarations([{ ...declared("v1", "current", "payments-runtime-profile-changed"), version: "v1" }])],
    ["v1 is retired", declarations([{ version: "v1", state: "retired", digest: V1_LIVE.digest }, declared("v2", "current")])],
  ])("a v1-referencing entry is refused resource_contract_unresolvable with no decision and no effect when %s", async (_why, contracts) => {
    const view = viewOf([entry(V1_LIVE)]);
    for (const mode of MODES) {
      for (const [tool, args, call] of [
        ["get_invoice", { invoice_id: "inv-1" }, "read"],
        ["hold_transfer", { invoice_id: "inv-1" }, "write"],
      ] as const) {
        const x = await build(mode, view, contracts);
        try {
          const invoke = call === "read" ? x.server.callReadTool.bind(x.server) : x.server.callWriteTool.bind(x.server);
          const res = await invoke(tool, args, tokenFor(view));
          expect(res, `${mode} ${tool}`).toMatchObject({ ok: false, refusal_reason: "resource_contract_unresolvable" });
          expect(res.result, `${mode} ${tool}`).toBeUndefined();
          expect(x.decided, `${mode} ${tool}`).toHaveLength(0);
          const recorded = x.records();
          expect(recorded.filter((e) => e.kind === "refusal").map((e) => e.content), `${mode} ${tool}`).toEqual([
            expect.objectContaining({ denial_reason: "resource_contract_unresolvable" }),
          ]);
          expect(recorded.filter((e) => e.kind === "execution" || e.kind === "decision"), `${mode} ${tool}`).toEqual([]);
        } finally {
          await x.close();
        }
      }
    }
  });

  it("where the resource requires a reference, an entry without one provides no authority, unless another fully enforceable entry covers the operation", async () => {
    const required = declarations([declared("v1", "current")], ACTIONS);
    for (const mode of MODES) {
      const unpinned = viewOf([entry(undefined)]);
      const x = await build(mode, unpinned, required);
      try {
        const res = await x.server.callReadTool("get_invoice", { invoice_id: "inv-1" }, tokenFor(unpinned));
        expect(res, mode).toMatchObject({ ok: false, refusal_reason: "resource_contract_unresolvable" });
        expect(res.result, mode).toBeUndefined();
        expect(x.decided, mode).toHaveLength(0);
      } finally {
        await x.close();
      }
      const both = viewOf([entry(undefined), entry(V1_LIVE)]);
      const y = await build(mode, both, required);
      try {
        const res = await y.server.callReadTool("get_invoice", { invoice_id: "inv-1" }, tokenFor(both));
        expect(res.ok, `${mode}: ${JSON.stringify(res)}`).toBe(true);
        expect(y.decided[0]?.resource.properties.resource_contract, mode).toEqual(V1_LIVE);
      } finally {
        await y.close();
      }
    }
  });
});

describe("a retained version is performed under its own Operation Profile (@spec runtime#resource-contract, #249)", () => {
  it("normalizes and performs a v1 entry under v1's profile and a v2 entry under v2's, while both resolve: a v1 approval still executes at the resource", async () => {
    const v1View = viewOf([entry(V1, `${CANONICAL_RESOURCE}/invoices`, { resource_match: "prefix" })]);
    const v2View = viewOf([entry(V2)]);
    for (const mode of MODES) {
      const a = await build(mode, v1View, RETAINED);
      const b = await build(mode, v2View, RETAINED);
      try {
        const underV1 = await a.server.callReadTool("get_invoice", { invoice_id: "inv-1" }, tokenFor(v1View));
        const underV2 = await b.server.callReadTool("get_invoice", { invoice_id: "inv-1" }, tokenFor(v2View));
        expect(underV1.ok, `${mode}: ${JSON.stringify(underV1)}`).toBe(true);
        expect(underV2.ok, `${mode}: ${JSON.stringify(underV2)}`).toBe(true);
        expect(underV1.result, mode).toEqual(underV2.result);
        const r1 = a.decided[0];
        const r2 = b.decided[0];
        expect(r1?.resource.properties, mode).toMatchObject({ operation_target: `${CANONICAL_RESOURCE}/invoices/inv-1`, resource_contract: V1 });
        expect(r2?.resource.properties, mode).toMatchObject({ operation_target: CANONICAL_RESOURCE, resource_contract: V2 });
        // The parameters are normalized under each version's profile: the
        // target each establishes enters the effective parameters, so the
        // digests differ for the same arguments.
        expect(r1?.context.parameter_digest, mode).not.toBe(r2?.context.parameter_digest);
      } finally {
        await a.close();
        await b.close();
      }
    }
  });

  it("performs a superseded version only within its declared retention, and a retired one never", async () => {
    const v1View = viewOf([entry(V1, `${CANONICAL_RESOURCE}/invoices`, { resource_match: "prefix" })]);
    for (const mode of MODES) {
      for (const [label, contracts, now] of [
        ["past retention", RETAINED, () => new Date("2026-11-01T00:00:01Z")],
        [
          "retired",
          declarations([{ version: "v1", state: "retired", digest: V1.digest }, declared("v2", "current")]),
          NOW,
        ],
      ] as const) {
        const x = await build(mode, v1View, contracts, { now });
        try {
          const res = await x.server.callReadTool("get_invoice", { invoice_id: "inv-1" }, tokenFor(v1View));
          expect(res, `${mode} ${label}`).toMatchObject({ ok: false, refusal_reason: "resource_contract_unresolvable" });
          expect(x.decided, `${mode} ${label}`).toHaveLength(0);
        } finally {
          await x.close();
        }
      }
    }
  });
});

describe("the executing PEP re-resolves the permit's contract before release (@spec runtime#resource-contract rule 5, authzen#response-context, #249)", () => {
  const view = viewOf([entry(V1_LIVE)]);
  const changes: Array<[string, ResourceContractDeclarations]> = [
    ["the v1 definition changed under the same version", declarations([{ ...declared("v1", "current", "payments-runtime-profile-changed"), version: "v1" }])],
    ["v1 was retired", declarations([{ version: "v1", state: "retired", digest: V1_LIVE.digest }, declared("v2", "current")])],
  ];

  it("a definition change after the decision and before dispatch, with identical parameters, suppresses the effect: Execution Evidence resource_contract_unresolvable, no effect", async () => {
    for (const mode of MODES) {
      for (const [label, changed] of changes) {
        for (const [tool, call] of [
          ["get_invoice", "read"],
          ["hold_transfer", "write"],
        ] as const) {
          const x = await build(mode, view, V1_CURRENT);
          try {
            const invoke = call === "read" ? x.server.callReadTool.bind(x.server) : x.server.callWriteTool.bind(x.server);
            const res = await invoke(tool, { invoice_id: "inv-1" }, tokenFor(view), () => x.setPepContracts(changed));
            expect(res, `${mode} ${label} ${tool}`).toMatchObject({ ok: false, refusal_reason: "resource_contract_unresolvable" });
            expect(res.result, `${mode} ${label} ${tool}`).toBeUndefined();
            expect(x.decided, `${mode} ${label} ${tool}`).toHaveLength(1);
            const executions = x.records().filter((e) => e.kind === "execution").map((e) => e.content);
            expect(executions, `${mode} ${label} ${tool}`).toEqual([
              expect.objectContaining({ outcome: "suppressed", error: "resource_contract_unresolvable" }),
            ]);
            // Never a parameter deviation or a target drift: the parameters and the target are unchanged.
            for (const e of executions) expect(["parameter_mismatch", "target_drift"]).not.toContain(e.error);
            expect(x.records().filter((e) => e.kind === "refusal"), `${mode} ${label} ${tool}`).toEqual([]);
          } finally {
            await x.close();
          }
        }
      }
      // Control: unchanged declarations release the effect.
      const x = await build(mode, view, V1_CURRENT);
      try {
        const res = await x.server.callReadTool("get_invoice", { invoice_id: "inv-1" }, tokenFor(view), () => x.setPepContracts(V1_CURRENT));
        expect(res.ok, `${mode}: ${JSON.stringify(res)}`).toBe(true);
      } finally {
        await x.close();
      }
    }
  });

  it("a permit whose condition is missing, malformed or names another contract than the one the PEP performs under releases no effect", async () => {
    for (const mode of MODES) {
      const x = await build(mode, view, V1_CURRENT);
      try {
        const res = await x.pep.enforce("get_invoice", { invoice_id: "inv-1" }, tokenFor(view));
        const attempt = res.attempt;
        if (!attempt) throw new Error(`${mode}: permitted`);
        expect(x.pep.permitUseFailure(attempt), mode).toBeUndefined();
        for (const [label, bound] of [
          ["missing", undefined],
          ["malformed", { id: CONTRACT }],
          ["another contract", V2],
        ] as const) {
          const altered = { ...attempt };
          if (bound === undefined) delete altered.permitResourceContract;
          else altered.permitResourceContract = bound;
          expect(x.pep.permitUseFailure(altered), `${mode} ${label}`).toBe("resource_contract_unresolvable");
        }
        // A permit decided under no contract, for an operation that has since
        // come to require one, cannot be met either.
        const unbound = { ...attempt };
        delete unbound.permitResourceContract;
        delete unbound.performedContract;
        expect(x.pep.permitUseFailure(unbound), mode).toBeUndefined();
        x.setPepContracts(declarations([declared("v1", "current")], ACTIONS));
        expect(x.pep.permitUseFailure(unbound), mode).toBe("resource_contract_unresolvable");
      } finally {
        await x.close();
      }
    }
  });
});
