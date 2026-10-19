/**
 * @spec resource-access#resource-matching, resource-access#rs-enforcement,
 * authzen#pdp-request (#1276, D447, D457): the payments resource establishes
 * each operation's target from its trusted, explicitly service-level
 * operation contract (`TOOL_ACTIONS[tool].target`), independently of the
 * presented entries, the token's audience and the caller's arguments; sends
 * it as `resource.properties.operation_target` beside `audience`; and
 * executes only the target the permit was decided on.
 *
 * Runs unconditionally through both the co-resident and the remote decision
 * channel, over a stub FGA that always allows and a permitting Resource
 * policy fixture, so only target establishment, the matcher and the use
 * checks decide.
 */

import {
  createDecisionChannel,
  createEphemeralDecisionPoint,
  type EvaluationRequest,
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
  type ActionMapping,
  CANONICAL_RESOURCE,
  Connectors,
  createEphemeralEvidenceKeys,
  credentialAuthorityFrom,
  EvidenceStore,
  McpPaymentsServer,
  openEphemeralWriteReservationStore,
  PaymentsStore,
  Pep,
  TOOL_ACTIONS,
  type TokenFacts,
  TransactionEngine,
  TOOLS,
} from "../src/index.js";

const ISSUER = "https://as.test";
const MODES = ["co-resident", "remote"] as const;
/** A finer service under the same audience: a different operation target. */
const ADMIN = `${CANONICAL_RESOURCE}/admin`;
const FORGED = "https://attacker.example/mcp";
const ACTIONS = ["payments:invoice.read", "payments:vendor.read", "payments:payment.execute"];

const missionEntry = (resource: string, over: Record<string, unknown> = {}) =>
  ({ type: "mission_resource_access", resource, actions: ACTIONS, ...over }) as MissionView["authority_set"][number];

const viewOf = (authority_set: MissionView["authority_set"]): MissionView => ({
  id: "msn_1276_pep",
  issuer: ISSUER,
  state: "active",
  version: 1,
  authority_hash: "sha-256:h1276-pep",
  authority_set,
  subject: { iss: ISSUER, sub: "alice" },
  client_id: "ap-agent",
});

const ALL_ACTIONS = [...new Set(TOOLS.map((t) => t.action))];
const credentialFor = (...resources: string[]) =>
  credentialAuthorityFrom(resources.map((resource) => ({ type: "mission_resource_access" as const, resource, actions: ALL_ACTIONS })));

const tokenFor = (view: MissionView, credentialAuthority = credentialFor(CANONICAL_RESOURCE)): TokenFacts => ({
  sub: "alice",
  iss: ISSUER,
  clientId: "ap-agent",
  cnfJkt: "jkt-1276",
  mission: { id: view.id, issuer: view.issuer, authority_hash: view.authority_hash },
  credentialAuthority,
});

/** The shipped Operation Profile with `tool`'s row replaced by `row` (or removed when `row` is undefined). */
const profileWith = (tool: string, row: Partial<ActionMapping> | undefined, drop: (keyof ActionMapping)[] = []) => {
  const base = TOOL_ACTIONS[tool] as ActionMapping;
  const next: Record<string, unknown> = { ...base, ...row };
  for (const k of drop) delete next[k];
  return { ...TOOL_ACTIONS, [tool]: next as unknown as ActionMapping };
};

interface Built {
  server: McpPaymentsServer;
  pep: Pep;
  decided: EvaluationRequest[];
  records: () => ReturnType<EvidenceStore["forMission"]>;
  setProfile: (p: Record<string, ActionMapping>) => void;
  close: () => Promise<void>;
}

async function build(
  mode: (typeof MODES)[number],
  view: MissionView,
  opts: { profile?: Record<string, ActionMapping>; operationTargets?: readonly string[] } = {},
): Promise<Built> {
  const point = createEphemeralDecisionPoint({
    emitterId: CANONICAL_RESOURCE,
    audience: CANONICAL_RESOURCE,
    resourcePolicy: RESOURCE_POLICY_PERMITS_ALL_FIXTURE,
  });
  const keys = createEphemeralEvidenceKeys({ decisionPoint: point });
  const evidence = new EvidenceStore(keys.signing, keys.resolver);
  const payments = new PaymentsStore();
  payments.seed(
    [{ id: "acme", name: "Acme", status: "approved" }],
    [{ id: "inv-1", vendor_id: "acme", amount: "125.00", currency: "USD", payee_account: "acct-acme", status: "payable" }],
  );
  const fga = { checkWithContext: async () => true } as unknown as Fga;
  const loadView = (ref: { id: string; issuer: string }) =>
    ref.id === view.id && ref.issuer === view.issuer
      ? { view, observation: { state: view.state, version: view.version, mode: "fresh", freshness_at: new Date().toISOString() } }
      : undefined;
  const channel = await createDecisionChannel(point, {
    mode,
    pepId: "mcp-payments-pep",
    audience: CANONICAL_RESOURCE,
    ...(opts.operationTargets ? { operationTargets: opts.operationTargets } : {}),
    getOptions: () => ({ view, fga, modelId: "test", now: () => new Date(), stalenessBound, relationForAction, stateSourcePlacement: "pep" as const }),
  });
  const decided: EvaluationRequest[] = [];
  let profile = opts.profile ?? TOOL_ACTIONS;
  const pep = new Pep({
    payments,
    evidence,
    fga,
    modelId: "test",
    loadView,
    instanceEpoch: "epoch-1276",
    operationProfile: () => profile,
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
    transaction: { engine: new TransactionEngine("epoch-1276"), connectors: new Connectors(), evidence },
    writeReservations,
  });
  return {
    server,
    pep,
    decided,
    records: () => evidence.forMission(view.id),
    setProfile: (p) => {
      profile = p;
    },
    close: () => channel.close(),
  };
}

const SERVICE_VIEW = viewOf([missionEntry(CANONICAL_RESOURCE)]);

describe("the payments resource establishes the operation target from its trusted contract (@spec resource-access#resource-matching, #1276)", () => {
  it("sends the contract's target beside the audience, and never reads a caller-supplied target or resource argument", async () => {
    for (const mode of MODES) {
      const x = await build(mode, SERVICE_VIEW);
      try {
        // Straight to the enforcement path, past the tool-boundary intake that
        // would refuse the unknown arguments: the PEP itself must ignore them.
        const res = await x.pep.enforce(
          "get_invoice",
          { invoice_id: "inv-1", operation_target: FORGED, resource: FORGED },
          tokenFor(SERVICE_VIEW, credentialFor(CANONICAL_RESOURCE, FORGED)),
        );
        expect(res.permitted, mode).toBe(true);
        expect(x.decided, mode).toHaveLength(1);
        expect(x.decided[0]?.resource.properties, mode).toMatchObject({ audience: CANONICAL_RESOURCE, operation_target: CANONICAL_RESOURCE });
        // Through the server, the closed intake refuses the arguments first.
        const viaServer = await x.server.callReadTool("get_invoice", { invoice_id: "inv-1", operation_target: FORGED }, tokenFor(SERVICE_VIEW));
        expect(viaServer, mode).toMatchObject({ ok: false, refusal_reason: "invalid_request" });
        expect(x.decided, mode).toHaveLength(1);
      } finally {
        await x.close();
      }
    }
  });

  it("refuses a tool whose profile declares no contract before any decision request, though the Mission and the credential name the service root; the declared contract permits", async () => {
    for (const mode of MODES) {
      const x = await build(mode, SERVICE_VIEW, { profile: profileWith("get_invoice", {}, ["target"]) });
      try {
        const refused = await x.server.callReadTool("get_invoice", { invoice_id: "inv-1" }, tokenFor(SERVICE_VIEW));
        expect(refused, mode).toMatchObject({ ok: false, refusal_reason: "operation_target_unresolvable" });
        expect(refused.result, mode).toBeUndefined();
        expect(x.decided, mode).toHaveLength(0);
        const refusal = x.records().find((e) => e.kind === "refusal");
        expect(refusal?.content, mode).toMatchObject({ denial_reason: "target_unresolvable" });
        // The explicit service-level contract: the same call permits.
        x.setProfile(TOOL_ACTIONS);
        const permitted = await x.server.callReadTool("get_invoice", { invoice_id: "inv-1" }, tokenFor(SERVICE_VIEW));
        expect(permitted.ok, `${mode}: ${JSON.stringify(permitted)}`).toBe(true);
        expect(x.decided, mode).toHaveLength(1);
      } finally {
        await x.close();
      }
    }
  });

  it("refuses an unsupported finer contract and declarations naming different targets before any decision request", async () => {
    const contracts: Array<[string, unknown]> = [
      ["finer contract", { template: `${CANONICAL_RESOURCE}/invoices/{invoice_id}` }],
      ["ambiguous declarations", [{ service: CANONICAL_RESOURCE }, { service: ADMIN }]],
    ];
    for (const mode of MODES) {
      for (const [label, target] of contracts) {
        const x = await build(mode, viewOf([missionEntry(CANONICAL_RESOURCE), missionEntry(ADMIN)]), {
          profile: profileWith("get_invoice", { target: target as ActionMapping["target"] }),
        });
        try {
          const res = await x.server.callReadTool("get_invoice", { invoice_id: "inv-1" }, tokenFor(SERVICE_VIEW, credentialFor(CANONICAL_RESOURCE, ADMIN)));
          expect(res, `${mode} ${label}`).toMatchObject({ ok: false, refusal_reason: "operation_target_unresolvable" });
          expect(x.decided, `${mode} ${label}`).toHaveLength(0);
        } finally {
          await x.close();
        }
      }
    }
  });

  it("same audience, different target: a contract naming a finer service under the same audience is decided on that target, never on the audience", async () => {
    for (const mode of MODES) {
      const profile = profileWith("get_invoice", { target: { service: ADMIN } });
      const credential = credentialFor(CANONICAL_RESOURCE, ADMIN);
      const denied = await build(mode, SERVICE_VIEW, { profile, operationTargets: [CANONICAL_RESOURCE, ADMIN] });
      try {
        const res = await denied.server.callReadTool("get_invoice", { invoice_id: "inv-1" }, tokenFor(SERVICE_VIEW, credential));
        expect(res, mode).toMatchObject({ ok: false, denial_reason: "out_of_authority" });
        expect(denied.decided[0]?.resource.properties, mode).toMatchObject({ audience: CANONICAL_RESOURCE, operation_target: ADMIN });
      } finally {
        await denied.close();
      }
      const adminView = viewOf([missionEntry(ADMIN)]);
      const permitted = await build(mode, adminView, { profile, operationTargets: [CANONICAL_RESOURCE, ADMIN] });
      try {
        const res = await permitted.server.callReadTool("get_invoice", { invoice_id: "inv-1" }, tokenFor(adminView, credential));
        expect(res.ok, `${mode}: ${JSON.stringify(res)}`).toBe(true);
      } finally {
        await permitted.close();
      }
    }
  });
});

describe("the payments resource matches entries with the Resource Access matcher (@spec resource-access#resource-matching, resource-access#rs-enforcement, #1276)", () => {
  const u = new URL(CANONICAL_RESOURCE);
  const SPELLINGS = [
    `${u.protocol.toUpperCase()}//${u.host.toUpperCase()}${u.pathname}`,
    `${CANONICAL_RESOURCE}/`,
    `${u.origin}${u.pathname.replace(/[a-z]/, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`)}`,
    `${CANONICAL_RESOURCE}?`,
  ].filter((s) => s !== CANONICAL_RESOURCE);

  it("an entry spelled differently from the target never covers it: the credential's is refused before the PDP, and the Mission's is denied out_of_authority", async () => {
    expect(SPELLINGS.length).toBeGreaterThanOrEqual(3);
    for (const mode of MODES) {
      for (const spelling of SPELLINGS) {
        const byCredential = await build(mode, SERVICE_VIEW);
        try {
          const res = await byCredential.server.callReadTool("get_invoice", { invoice_id: "inv-1" }, tokenFor(SERVICE_VIEW, credentialFor(spelling)));
          expect(res, `${mode} ${spelling}`).toMatchObject({ ok: false, denial_reason: "out_of_authority" });
          expect(byCredential.decided, `${mode} ${spelling}`).toHaveLength(0);
        } finally {
          await byCredential.close();
        }
        const spelledView = viewOf([missionEntry(spelling)]);
        const byMission = await build(mode, spelledView);
        try {
          const res = await byMission.server.callReadTool("get_invoice", { invoice_id: "inv-1" }, tokenFor(spelledView));
          expect(res, `${mode} ${spelling}`).toMatchObject({ ok: false, denial_reason: "out_of_authority" });
          expect(byMission.decided, `${mode} ${spelling}`).toHaveLength(1);
        } finally {
          await byMission.close();
        }
      }
    }
  });

  it("a prefix entry or an unrecognized resource_match provides no authority at the resource, even naming the target itself", async () => {
    for (const mode of MODES) {
      for (const resource_match of ["prefix", "glob"]) {
        const prefixView = viewOf([missionEntry(CANONICAL_RESOURCE, { resource_match })]);
        const byMission = await build(mode, prefixView);
        try {
          const res = await byMission.server.callReadTool("get_invoice", { invoice_id: "inv-1" }, tokenFor(prefixView));
          expect(res, `${mode} ${resource_match}`).toMatchObject({ ok: false, denial_reason: "out_of_authority" });
        } finally {
          await byMission.close();
        }
        const byCredential = await build(mode, SERVICE_VIEW);
        try {
          const unenforceable = [{ type: "mission_resource_access", resource: CANONICAL_RESOURCE, resource_match, actions: ALL_ACTIONS }];
          const res = await byCredential.server.callReadTool(
            "get_invoice",
            { invoice_id: "inv-1" },
            tokenFor(SERVICE_VIEW, unenforceable as unknown as TokenFacts["credentialAuthority"] & object),
          );
          expect(res, `${mode} ${resource_match}`).toMatchObject({ ok: false, denial_reason: "out_of_authority" });
          expect(byCredential.decided, `${mode} ${resource_match}`).toHaveLength(0);
        } finally {
          await byCredential.close();
        }
      }
      // Control: a Mission entry stating exact is enforced as exact.
      const statedView = viewOf([missionEntry(CANONICAL_RESOURCE, { resource_match: "exact" })]);
      const stated = await build(mode, statedView);
      try {
        const res = await stated.server.callReadTool("get_invoice", { invoice_id: "inv-1" }, tokenFor(statedView));
        expect(res.ok, `${mode}: ${JSON.stringify(res)}`).toBe(true);
      } finally {
        await stated.close();
      }
    }
  });
});

describe("the payments resource executes only the authorized target (@spec resource-access#resource-matching, #1276)", () => {
  const cases: Array<{ tool: string; args: Record<string, unknown>; path: "read" | "write" }> = [
    // A parameter-bound read, a read with no parameter digest, and a write.
    { tool: "get_invoice", args: { invoice_id: "inv-1" }, path: "read" },
    { tool: "lookup_vendor", args: { vendor_id: "acme" }, path: "read" },
    { tool: "hold_transfer", args: { invoice_id: "inv-1" }, path: "write" },
  ];

  it("a contract that moves or disappears between the decision and the release suppresses the permit with target_drift and no effect", async () => {
    for (const mode of MODES) {
      for (const { tool, args, path } of cases) {
        for (const [label, moved] of [
          ["moved", profileWith(tool, { target: { service: ADMIN } })],
          ["removed", profileWith(tool, {}, ["target"])],
        ] as const) {
          const x = await build(mode, SERVICE_VIEW);
          try {
            const call = path === "read" ? x.server.callReadTool.bind(x.server) : x.server.callWriteTool.bind(x.server);
            const res = await call(tool, args, tokenFor(SERVICE_VIEW), () => x.setProfile(moved));
            expect(res, `${mode} ${tool} ${label}`).toMatchObject({ ok: false, refusal_reason: "target_drift" });
            expect(res.result, `${mode} ${tool} ${label}`).toBeUndefined();
            expect(x.decided, `${mode} ${tool} ${label}`).toHaveLength(1);
            const executions = x.records().filter((e) => e.kind === "execution");
            expect(executions.map((e) => e.content), `${mode} ${tool} ${label}`).toEqual([
              expect.objectContaining({ outcome: "suppressed", error: "target_drift" }),
            ]);
          } finally {
            await x.close();
          }
        }
        // Control: an unmoved contract executes under the same permit path.
        const x = await build(mode, SERVICE_VIEW);
        try {
          const call = path === "read" ? x.server.callReadTool.bind(x.server) : x.server.callWriteTool.bind(x.server);
          const res = await call(tool, args, tokenFor(SERVICE_VIEW), () => {});
          expect(res.ok, `${mode} ${tool}: ${JSON.stringify(res)}`).toBe(true);
        } finally {
          await x.close();
        }
      }
    }
  });
});
