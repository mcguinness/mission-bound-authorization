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
  decisionCacheKey,
  type EvaluationRequest,
  type Fga,
  loadRuntimePosture,
  type MissionView,
  operationIdentity,
  relationForAction,
  RUNTIME_POSTURE,
  stalenessBound,
} from "@mission/pdp";
import { RESOURCE_POLICY_PERMITS_ALL_FIXTURE } from "@mission/pdp/test-support";
import type { OperationContract } from "@mission/core";
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
  opts: {
    profile?: Record<string, ActionMapping>;
    operationTargets?: readonly string[];
    operationContracts?: readonly OperationContract[];
    invoiceIds?: readonly string[];
  } = {},
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
    (opts.invoiceIds ?? ["inv-1", "inv-2"]).map((id) => ({
      id,
      vendor_id: "acme",
      amount: "125.00",
      currency: "USD",
      payee_account: "acct-acme",
      status: "payable",
    })),
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
    ...(opts.operationContracts ? { operationContracts: opts.operationContracts } : {}),
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
      // Finer forms outside the supported argument-derived contract: a second
      // expression, an argument in the host, and an unknown member.
      ["two expressions", { template: `${CANONICAL_RESOURCE}/invoices/{invoice_id}/{line}` }],
      ["host variable", { template: "http://{invoice_id}.example/mcp" }],
      ["unknown form", { prefix: `${CANONICAL_RESOURCE}/invoices` }],
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

  it("refuses a contract naming a target that breaks RFC 3986 syntax before any decision request, though the Mission and the credential name the identical string", async () => {
    // pct-encoded = "%" HEXDIG HEXDIG (RFC 3986, Section 2.1), and an http
    // or https target names a non-empty host (RFC 9110, Section 4.2).
    const malformed = [`${CANONICAL_RESOURCE}/%zz`, `${CANONICAL_RESOURCE}%`, `${CANONICAL_RESOURCE}/%4`, `${new URL(CANONICAL_RESOURCE).protocol}///mcp`];
    for (const mode of MODES) {
      for (const target of malformed) {
        const view = viewOf([missionEntry(CANONICAL_RESOURCE), missionEntry(target)]);
        const x = await build(mode, view, {
          profile: profileWith("get_invoice", { target: { service: target } }),
          operationTargets: [CANONICAL_RESOURCE, target],
        });
        try {
          const res = await x.server.callReadTool("get_invoice", { invoice_id: "inv-1" }, tokenFor(view, credentialFor(CANONICAL_RESOURCE, target)));
          expect(res, `${mode} ${target}`).toMatchObject({ ok: false, refusal_reason: "operation_target_unresolvable" });
          expect(res.result, `${mode} ${target}`).toBeUndefined();
          expect(x.decided, `${mode} ${target}`).toHaveLength(0);
          expect(x.records().find((e) => e.kind === "refusal")?.content, `${mode} ${target}`).toMatchObject({ denial_reason: "target_unresolvable" });
          // Control: the same Mission and credential under the shipped contract permit.
          x.setProfile(TOOL_ACTIONS);
          const permitted = await x.server.callReadTool("get_invoice", { invoice_id: "inv-1" }, tokenFor(view, credentialFor(CANONICAL_RESOURCE, target)));
          expect(permitted.ok, `${mode} ${target}: ${JSON.stringify(permitted)}`).toBe(true);
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
        // A credential naming only the audience's identifier does not cover the target: refused before the PDP.
        const audienceOnly = await denied.server.callReadTool("get_invoice", { invoice_id: "inv-1" }, tokenFor(SERVICE_VIEW));
        expect(audienceOnly, mode).toMatchObject({ ok: false, denial_reason: "out_of_authority" });
        expect(denied.decided, mode).toHaveLength(0);
        // A credential covering the target reaches the PDP, which decides on the target: the Mission names only the audience's identifier.
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

  it("an unrecognized resource_match, or a prefix entry whose resource carries a query, provides no authority at the resource, even naming the target itself", async () => {
    for (const mode of MODES) {
      const variants: Array<[string, Record<string, unknown>]> = [
        ["glob", { resource_match: "glob" }],
        ["prefix with a query", { resource_match: "prefix", resource: `${CANONICAL_RESOURCE}?tenant=a` }],
      ];
      for (const [label, over] of variants) {
        const prefixView = viewOf([missionEntry(CANONICAL_RESOURCE, over)]);
        const byMission = await build(mode, prefixView);
        try {
          const res = await byMission.server.callReadTool("get_invoice", { invoice_id: "inv-1" }, tokenFor(prefixView));
          expect(res, `${mode} ${label}`).toMatchObject({ ok: false, denial_reason: "out_of_authority" });
        } finally {
          await byMission.close();
        }
        const byCredential = await build(mode, SERVICE_VIEW);
        try {
          const unenforceable = [{ type: "mission_resource_access", resource: CANONICAL_RESOURCE, actions: ALL_ACTIONS, ...over }];
          const res = await byCredential.server.callReadTool(
            "get_invoice",
            { invoice_id: "inv-1" },
            tokenFor(SERVICE_VIEW, unenforceable as unknown as TokenFacts["credentialAuthority"] & object),
          );
          expect(res, `${mode} ${label}`).toMatchObject({ ok: false, denial_reason: "out_of_authority" });
          expect(byCredential.decided, `${mode} ${label}`).toHaveLength(0);
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

/** The target the invoice contract establishes for one invoice. */
const invoiceTarget = (id: string) => `${CANONICAL_RESOURCE}/invoices/${id}`;
const INV1 = invoiceTarget("inv-1");
const INV2 = invoiceTarget("inv-2");
/** A moved contract: the same invoice under another collection. */
const BILLS: OperationContract = { template: `${CANONICAL_RESOURCE}/bills/{invoice_id}` };
const BILL1 = `${CANONICAL_RESOURCE}/bills/inv-1`;
/** The remote PDP's registration: this PEP's service-level and argument-derived contracts. */
const CONTRACTS: readonly OperationContract[] = [{ service: CANONICAL_RESOURCE }, PAYMENTS_INVOICE_CONTRACT, BILLS];

/** The shipped Operation Profile with each named tool declaring `contract`. */
const profileDeclaring = (contract: unknown, ...tools: string[]) => {
  const next: Record<string, ActionMapping> = { ...TOOL_ACTIONS };
  for (const tool of tools) next[tool] = { ...(TOOL_ACTIONS[tool] as ActionMapping), target: contract as ActionMapping["target"] };
  return next;
};

describe("the payments resource derives a finer operation target from validated arguments (@spec resource-access#resource-matching, authzen#context-operation-target, #1276)", () => {
  it("same audience, different targets: under the invoice contract each invoice is its own target, and an entry naming one invoice never covers another", async () => {
    for (const mode of MODES) {
      const inv1View = viewOf([missionEntry(INV1)]);
      const x = await build(mode, inv1View, { profile: profileDeclaring(PAYMENTS_INVOICE_CONTRACT, "get_invoice"), operationContracts: CONTRACTS });
      try {
        // The named invoice permits, decided on its own target beside the
        // unchanged audience, and the PEP executes on that invoice.
        const res = await x.server.callReadTool("get_invoice", { invoice_id: "inv-1" }, tokenFor(inv1View, credentialFor(INV1, INV2)));
        expect(res.ok, `${mode}: ${JSON.stringify(res)}`).toBe(true);
        expect((res.result as { id?: string } | undefined)?.id, mode).toBe("inv-1");
        expect(x.decided[0]?.resource, mode).toMatchObject({
          type: "invoice",
          id: "inv-1",
          properties: { audience: CANONICAL_RESOURCE, operation_target: INV1 },
        });
        // Another invoice under the same audience: the PDP decides on that
        // invoice's target, which the Mission does not name.
        const other = await x.server.callReadTool("get_invoice", { invoice_id: "inv-2" }, tokenFor(inv1View, credentialFor(INV1, INV2)));
        expect(other, mode).toMatchObject({ ok: false, denial_reason: "out_of_authority" });
        expect(x.decided[1]?.resource.properties, mode).toMatchObject({ audience: CANONICAL_RESOURCE, operation_target: INV2 });
        // A credential naming only inv-1 is refused for inv-2 before the PDP.
        const narrow = await x.server.callReadTool("get_invoice", { invoice_id: "inv-2" }, tokenFor(inv1View, credentialFor(INV1)));
        expect(narrow, mode).toMatchObject({ ok: false, denial_reason: "out_of_authority" });
        expect(x.decided, mode).toHaveLength(2);
      } finally {
        await x.close();
      }
    }
  });

  it("an argument-derived contract never falls back to the service identifier: entries naming only the service cover no invoice target, while the shipped service-level contract still permits them", async () => {
    for (const mode of MODES) {
      const x = await build(mode, SERVICE_VIEW, { profile: profileDeclaring(PAYMENTS_INVOICE_CONTRACT, "get_invoice"), operationContracts: CONTRACTS });
      try {
        // Mission and credential name the service root only: refused before the PDP.
        const rootOnly = await x.server.callReadTool("get_invoice", { invoice_id: "inv-1" }, tokenFor(SERVICE_VIEW));
        expect(rootOnly, mode).toMatchObject({ ok: false, denial_reason: "out_of_authority" });
        expect(x.decided, mode).toHaveLength(0);
        // A credential covering the invoice reaches the PDP, which decides on
        // the invoice: the Mission's service-root entry does not cover it.
        const res = await x.server.callReadTool("get_invoice", { invoice_id: "inv-1" }, tokenFor(SERVICE_VIEW, credentialFor(CANONICAL_RESOURCE, INV1)));
        expect(res, mode).toMatchObject({ ok: false, denial_reason: "out_of_authority" });
        expect(x.decided[0]?.resource.properties, mode).toMatchObject({ operation_target: INV1 });
        // Control: the shipped service-level contract, unchanged, permits the same call.
        x.setProfile(TOOL_ACTIONS);
        const shipped = await x.server.callReadTool("get_invoice", { invoice_id: "inv-1" }, tokenFor(SERVICE_VIEW));
        expect(shipped.ok, `${mode}: ${JSON.stringify(shipped)}`).toBe(true);
        expect(x.decided[1]?.resource.properties, mode).toMatchObject({ operation_target: CANONICAL_RESOURCE });
      } finally {
        await x.close();
      }
    }
  });

  it("a missing, empty, list-valued, dot-segment or ambiguous argument-derived target refuses before any decision request, though the Mission and the credential name both the service and the invoice", async () => {
    const view = viewOf([missionEntry(CANONICAL_RESOURCE), missionEntry(INV1)]);
    const token = tokenFor(view, credentialFor(CANONICAL_RESOURCE, INV1));
    for (const mode of MODES) {
      const x = await build(mode, view, { profile: profileDeclaring(PAYMENTS_INVOICE_CONTRACT, "get_invoice", "lookup_vendor"), operationContracts: CONTRACTS });
      try {
        // Straight to the enforcement path, past the intake that would refuse
        // some of these shapes first: the PEP must refuse them itself.
        for (const args of [{}, { invoice_id: "" }, { invoice_id: ["inv-1"] }, { invoice_id: ".." }]) {
          const res = await x.pep.enforce("get_invoice", args, token);
          expect(res, `${mode} ${JSON.stringify(args)}`).toMatchObject({ permitted: false, refusal_reason: "operation_target_unresolvable" });
        }
        // Through the server: a tool with no invoice_id argument names no invoice.
        const vendor = await x.server.callReadTool("lookup_vendor", { vendor_id: "acme" }, token);
        expect(vendor, mode).toMatchObject({ ok: false, refusal_reason: "operation_target_unresolvable" });
        // Declarations deriving different targets (the invoice and the service).
        x.setProfile(profileDeclaring([PAYMENTS_INVOICE_CONTRACT, { service: CANONICAL_RESOURCE }], "get_invoice"));
        const ambiguous = await x.server.callReadTool("get_invoice", { invoice_id: "inv-1" }, token);
        expect(ambiguous, mode).toMatchObject({ ok: false, refusal_reason: "operation_target_unresolvable" });
        expect(x.decided, mode).toHaveLength(0);
        const refusals = x.records().filter((e) => e.kind === "refusal");
        expect(refusals, mode).toHaveLength(6);
        for (const r of refusals) expect(r.content, mode).toMatchObject({ denial_reason: "target_unresolvable" });
        // Control: the same invoice, named once, permits.
        x.setProfile(profileDeclaring(PAYMENTS_INVOICE_CONTRACT, "get_invoice"));
        const permitted = await x.server.callReadTool("get_invoice", { invoice_id: "inv-1" }, token);
        expect(permitted.ok, `${mode}: ${JSON.stringify(permitted)}`).toBe(true);
      } finally {
        await x.close();
      }
    }
  });

  it("a caller-supplied target never moves the derived target: operation_target and resource arguments are ignored, and an invoice_id carrying delimiters stays one segment under /invoices/", async () => {
    // The invoice whose identifier is "../admin" is a stored invoice: its
    // target is that one segment, percent-encoded, never ADMIN.
    const ENCODED = `${CANONICAL_RESOURCE}/invoices/..%2Fadmin`;
    const view = viewOf([missionEntry(INV1), missionEntry(ADMIN), missionEntry(ENCODED)]);
    for (const mode of MODES) {
      const x = await build(mode, view, {
        profile: profileDeclaring(PAYMENTS_INVOICE_CONTRACT, "get_invoice"),
        operationContracts: CONTRACTS,
        invoiceIds: ["inv-1", "../admin"],
      });
      try {
        const forged = await x.pep.enforce(
          "get_invoice",
          { invoice_id: "inv-1", operation_target: ADMIN, resource: ADMIN },
          tokenFor(view, credentialFor(INV1, ADMIN)),
        );
        expect(forged.permitted, `${mode}: ${JSON.stringify(forged)}`).toBe(true);
        expect(x.decided[0]?.resource.properties, mode).toMatchObject({ operation_target: INV1 });
        // A credential naming ADMIN does not cover the invoice "../admin".
        const traversal = await x.pep.enforce("get_invoice", { invoice_id: "../admin" }, tokenFor(view, credentialFor(ADMIN)));
        expect(traversal, mode).toMatchObject({ permitted: false, denial_reason: "out_of_authority" });
        expect(x.decided, mode).toHaveLength(1);
        // Its own encoded target does.
        const own = await x.pep.enforce("get_invoice", { invoice_id: "../admin" }, tokenFor(view, credentialFor(ENCODED)));
        expect(own.permitted, `${mode}: ${JSON.stringify(own)}`).toBe(true);
        expect(x.decided[1]?.resource.properties, mode).toMatchObject({ operation_target: ENCODED });
      } finally {
        await x.close();
      }
    }
  });

  it("same type and id, changed target: moving the contract changes the request's target, digest, operation identity and cache key while audience, action and type/id stay equal", async () => {
    const view = viewOf([missionEntry(INV1), missionEntry(BILL1)]);
    const token = tokenFor(view, credentialFor(INV1, BILL1));
    for (const mode of MODES) {
      const x = await build(mode, view, { profile: profileDeclaring(PAYMENTS_INVOICE_CONTRACT, "get_invoice"), operationContracts: CONTRACTS });
      try {
        const first = await x.server.callReadTool("get_invoice", { invoice_id: "inv-1" }, token);
        expect(first.ok, `${mode}: ${JSON.stringify(first)}`).toBe(true);
        x.setProfile(profileDeclaring(BILLS, "get_invoice"));
        const second = await x.server.callReadTool("get_invoice", { invoice_id: "inv-1" }, token);
        expect(second.ok, `${mode}: ${JSON.stringify(second)}`).toBe(true);
        const [a, b] = x.decided as [EvaluationRequest, EvaluationRequest];
        expect([a.resource.type, a.resource.id, a.action.name, a.resource.properties.audience], mode).toEqual([
          b.resource.type,
          b.resource.id,
          b.action.name,
          b.resource.properties.audience,
        ]);
        expect([a.resource.properties.operation_target, b.resource.properties.operation_target], mode).toEqual([INV1, BILL1]);
        expect(a.context.parameter_digest, mode).not.toBe(b.context.parameter_digest);
        expect(operationIdentity(a), mode).not.toBe(operationIdentity(b));
        expect(decisionCacheKey(a, view, "test"), mode).not.toBe(decisionCacheKey(b, view, "test"));
      } finally {
        await x.close();
      }
    }
  });

  it("a target change between the decision and the release suppresses an argument-derived permit with target_drift and no effect", async () => {
    const view = viewOf([missionEntry(INV1), missionEntry(BILL1)]);
    const token = tokenFor(view, credentialFor(INV1, BILL1));
    const cases: Array<{ tool: string; path: "read" | "write" }> = [
      { tool: "get_invoice", path: "read" },
      { tool: "hold_transfer", path: "write" },
    ];
    for (const mode of MODES) {
      for (const { tool, path } of cases) {
        for (const [label, moved] of [
          ["moved", profileDeclaring(BILLS, tool)],
          ["removed", profileDeclaring(undefined, tool)],
        ] as const) {
          const x = await build(mode, view, { profile: profileDeclaring(PAYMENTS_INVOICE_CONTRACT, tool), operationContracts: CONTRACTS });
          try {
            const call = path === "read" ? x.server.callReadTool.bind(x.server) : x.server.callWriteTool.bind(x.server);
            const res = await call(tool, { invoice_id: "inv-1" }, token, () => x.setProfile(moved));
            expect(res, `${mode} ${tool} ${label}`).toMatchObject({ ok: false, refusal_reason: "target_drift" });
            expect(res.result, `${mode} ${tool} ${label}`).toBeUndefined();
            expect(x.decided.map((r) => r.resource.properties.operation_target), `${mode} ${tool} ${label}`).toEqual([INV1]);
            const executions = x.records().filter((e) => e.kind === "execution");
            expect(executions.map((e) => e.content), `${mode} ${tool} ${label}`).toEqual([
              expect.objectContaining({ outcome: "suppressed", error: "target_drift" }),
            ]);
          } finally {
            await x.close();
          }
        }
        // Control: an unmoved argument-derived contract executes under the same permit path.
        const x = await build(mode, view, { profile: profileDeclaring(PAYMENTS_INVOICE_CONTRACT, tool), operationContracts: CONTRACTS });
        try {
          const call = path === "read" ? x.server.callReadTool.bind(x.server) : x.server.callWriteTool.bind(x.server);
          const res = await call(tool, { invoice_id: "inv-1" }, token, () => {});
          expect(res.ok, `${mode} ${tool}: ${JSON.stringify(res)}`).toBe(true);
        } finally {
          await x.close();
        }
      }
    }
  });
});

const INVOICES = `${CANONICAL_RESOURCE}/invoices`;
/** A sibling collection sharing the prefix's characters but not its path segment. */
const ARCHIVE: OperationContract = { template: `${CANONICAL_RESOURCE}/invoices-archive/{invoice_id}` };
const ARCHIVED1 = `${CANONICAL_RESOURCE}/invoices-archive/inv-1`;
/** A target equal to the prefix's base. */
const COLLECTION: OperationContract = { service: INVOICES };
/** A target whose decoded dot-segment leaves /invoices for /admin once normalized. */
const DOTTED_TARGET = `${INVOICES}/%2e%2e/admin`;
const DOTTED: OperationContract = { service: DOTTED_TARGET };
/** A target carrying a query beneath the base. */
const QUERIED_TARGET = `${INVOICES}?status=payable`;
const QUERIED: OperationContract = { service: QUERIED_TARGET };
/** The invoice target with the scheme and host spelled in upper case. */
const UPPER_TARGET = (() => {
  const u = new URL(CANONICAL_RESOURCE);
  return `${u.protocol.toUpperCase()}//${u.host.toUpperCase()}${u.pathname}/invoices/inv-1`;
})();
const UPPER: OperationContract = { service: UPPER_TARGET };
/** The remote PDP's registration for the prefix witnesses: every contract they declare. */
const PREFIX_CONTRACTS: readonly OperationContract[] = [...CONTRACTS, ARCHIVE, COLLECTION, DOTTED, QUERIED, UPPER];

const prefixEntry = (resource: string) => missionEntry(resource, { resource_match: "prefix" });
const prefixCredential = (...resources: string[]) =>
  credentialAuthorityFrom(resources.map((resource) => ({ type: "mission_resource_access" as const, resource, resource_match: "prefix" as const, actions: ALL_ACTIONS })));

describe("the payments resource matches prefix entries against the operation target (@spec resource-access#resource-matching, resource-access#rs-enforcement, #1276)", () => {
  it("a prefix entry covers the target equal to its base and each target beneath it at a path-segment boundary, never a sibling sharing its characters; a base ending in / does not cover the bare path; an exact entry never covers a target beneath it", async () => {
    for (const mode of MODES) {
      const view = viewOf([prefixEntry(INVOICES)]);
      const x = await build(mode, view, { profile: profileDeclaring(PAYMENTS_INVOICE_CONTRACT, "get_invoice"), operationContracts: PREFIX_CONTRACTS });
      try {
        // Beneath the base: each invoice is its own target, and the prefix in
        // the Mission and in the credential covers both.
        for (const id of ["inv-1", "inv-2"]) {
          const res = await x.server.callReadTool("get_invoice", { invoice_id: id }, tokenFor(view, prefixCredential(INVOICES)));
          expect(res.ok, `${mode} ${id}: ${JSON.stringify(res)}`).toBe(true);
          expect(x.decided.at(-1)?.resource.properties, `${mode} ${id}`).toMatchObject({ operation_target: invoiceTarget(id) });
        }
        // The target equal to the base.
        x.setProfile(profileDeclaring(COLLECTION, "get_invoice"));
        const base = await x.server.callReadTool("get_invoice", { invoice_id: "inv-1" }, tokenFor(view, prefixCredential(INVOICES)));
        expect(base.ok, `${mode} base: ${JSON.stringify(base)}`).toBe(true);
        expect(x.decided.at(-1)?.resource.properties, mode).toMatchObject({ operation_target: INVOICES });
        // A sibling sharing the characters: the credential's prefix refuses it
        // before the PDP, and the Mission's is denied there.
        x.setProfile(profileDeclaring(ARCHIVE, "get_invoice"));
        const before = x.decided.length;
        const sibling = await x.server.callReadTool("get_invoice", { invoice_id: "inv-1" }, tokenFor(view, prefixCredential(INVOICES)));
        expect(sibling, mode).toMatchObject({ ok: false, denial_reason: "out_of_authority" });
        expect(x.decided, mode).toHaveLength(before);
        const reached = await x.server.callReadTool("get_invoice", { invoice_id: "inv-1" }, tokenFor(view, [...prefixCredential(INVOICES), ...credentialFor(ARCHIVED1)]));
        expect(reached, mode).toMatchObject({ ok: false, denial_reason: "out_of_authority" });
        expect(x.decided.at(-1)?.resource.properties, mode).toMatchObject({ operation_target: ARCHIVED1 });
      } finally {
        await x.close();
      }
      // A base ending in / covers the invoices beneath it, not the bare collection.
      const slashView = viewOf([prefixEntry(`${INVOICES}/`)]);
      const s = await build(mode, slashView, { profile: profileDeclaring(PAYMENTS_INVOICE_CONTRACT, "get_invoice"), operationContracts: PREFIX_CONTRACTS });
      try {
        const token = tokenFor(slashView, prefixCredential(INVOICES));
        const invoice = await s.server.callReadTool("get_invoice", { invoice_id: "inv-1" }, token);
        expect(invoice.ok, `${mode}: ${JSON.stringify(invoice)}`).toBe(true);
        s.setProfile(profileDeclaring(COLLECTION, "get_invoice"));
        const bare = await s.server.callReadTool("get_invoice", { invoice_id: "inv-1" }, token);
        expect(bare, mode).toMatchObject({ ok: false, denial_reason: "out_of_authority" });
        expect(s.decided.at(-1)?.resource.properties, mode).toMatchObject({ operation_target: INVOICES });
      } finally {
        await s.close();
      }
      // An exact entry naming the base never covers an invoice beneath it,
      // in the Mission (denied at the PDP) or in the credential (refused before it).
      const exactView = viewOf([missionEntry(INVOICES)]);
      const e = await build(mode, exactView, { profile: profileDeclaring(PAYMENTS_INVOICE_CONTRACT, "get_invoice"), operationContracts: PREFIX_CONTRACTS });
      try {
        const byMission = await e.server.callReadTool("get_invoice", { invoice_id: "inv-1" }, tokenFor(exactView, prefixCredential(INVOICES)));
        expect(byMission, mode).toMatchObject({ ok: false, denial_reason: "out_of_authority" });
        expect(e.decided, mode).toHaveLength(1);
        const byCredential = await e.server.callReadTool("get_invoice", { invoice_id: "inv-1" }, tokenFor(viewOf([prefixEntry(INVOICES)]), credentialFor(INVOICES)));
        expect(byCredential, mode).toMatchObject({ ok: false, denial_reason: "out_of_authority" });
        expect(e.decided, mode).toHaveLength(1);
      } finally {
        await e.close();
      }
    }
  });

  it("normalizes before the prefix comparison: a target whose decoded dot-segment leaves the base is denied under it and admitted under the base it lands in, and scheme and host case do not move the boundary", async () => {
    for (const mode of MODES) {
      const ADMIN_BASE = `${CANONICAL_RESOURCE}/admin`;
      // The credential names the dotted target exactly, so the Mission's prefix decides.
      const underInvoices = viewOf([prefixEntry(INVOICES)]);
      const x = await build(mode, underInvoices, { profile: profileDeclaring(DOTTED, "get_invoice"), operationContracts: PREFIX_CONTRACTS });
      try {
        const res = await x.server.callReadTool("get_invoice", { invoice_id: "inv-1" }, tokenFor(underInvoices, credentialFor(DOTTED_TARGET)));
        expect(res, mode).toMatchObject({ ok: false, denial_reason: "out_of_authority" });
        expect(x.decided.at(-1)?.resource.properties, mode).toMatchObject({ operation_target: DOTTED_TARGET });
        // The credential's prefix normalizes too: refused before the PDP.
        const before = x.decided.length;
        const byCredential = await x.server.callReadTool("get_invoice", { invoice_id: "inv-1" }, tokenFor(viewOf([missionEntry(DOTTED_TARGET)]), prefixCredential(INVOICES)));
        expect(byCredential, mode).toMatchObject({ ok: false, denial_reason: "out_of_authority" });
        expect(x.decided, mode).toHaveLength(before);
      } finally {
        await x.close();
      }
      const underAdmin = viewOf([prefixEntry(ADMIN_BASE)]);
      const y = await build(mode, underAdmin, { profile: profileDeclaring(DOTTED, "get_invoice"), operationContracts: PREFIX_CONTRACTS });
      try {
        const res = await y.server.callReadTool("get_invoice", { invoice_id: "inv-1" }, tokenFor(underAdmin, prefixCredential(ADMIN_BASE)));
        expect(res.ok, `${mode}: ${JSON.stringify(res)}`).toBe(true);
        expect(y.decided.at(-1)?.resource.properties, mode).toMatchObject({ operation_target: DOTTED_TARGET });
      } finally {
        await y.close();
      }
      // Scheme and host case are normalized for the comparison; the target keeps its spelling.
      const upperView = viewOf([prefixEntry(INVOICES)]);
      const z = await build(mode, upperView, { profile: profileDeclaring(UPPER, "get_invoice"), operationContracts: PREFIX_CONTRACTS });
      try {
        const res = await z.server.callReadTool("get_invoice", { invoice_id: "inv-1" }, tokenFor(upperView, prefixCredential(INVOICES)));
        expect(res.ok, `${mode}: ${JSON.stringify(res)}`).toBe(true);
        expect(z.decided.at(-1)?.resource.properties, mode).toMatchObject({ operation_target: UPPER_TARGET });
      } finally {
        await z.close();
      }
    }
  });

  it("excludes the target's query from the prefix path comparison only: a target with a query beneath the base is covered, while an exact entry naming the base without the query is not", async () => {
    for (const mode of MODES) {
      const view = viewOf([prefixEntry(INVOICES)]);
      const x = await build(mode, view, { profile: profileDeclaring(QUERIED, "get_invoice"), operationContracts: PREFIX_CONTRACTS });
      try {
        const res = await x.server.callReadTool("get_invoice", { invoice_id: "inv-1" }, tokenFor(view, prefixCredential(INVOICES)));
        expect(res.ok, `${mode}: ${JSON.stringify(res)}`).toBe(true);
        expect(x.decided.at(-1)?.resource.properties, mode).toMatchObject({ operation_target: QUERIED_TARGET });
      } finally {
        await x.close();
      }
      // The query stays part of the target: an exact entry naming the base does not cover it.
      const exactView = viewOf([missionEntry(INVOICES)]);
      const y = await build(mode, exactView, { profile: profileDeclaring(QUERIED, "get_invoice"), operationContracts: PREFIX_CONTRACTS });
      try {
        const res = await y.server.callReadTool("get_invoice", { invoice_id: "inv-1" }, tokenFor(exactView, prefixCredential(INVOICES)));
        expect(res, mode).toMatchObject({ ok: false, denial_reason: "out_of_authority" });
        expect(y.decided.at(-1)?.resource.properties, mode).toMatchObject({ operation_target: QUERIED_TARGET });
      } finally {
        await y.close();
      }
    }
  });
});
