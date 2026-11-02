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
  AUTHORITY_ENTRY_TYP,
  authorityHash,
  computeAnchor,
  establishOperationTarget,
  type JsonValue,
  matchResource,
  RESOURCE_CONTRACT_STATES,
  ResourceContractDeclarations,
  type ResourceContractRef,
  resourceContractDigest,
} from "@mission/core";
import { RESOURCE_CONTRACTS, RUNTIME_SCOPE_CONFIG } from "@mission/demo-data";
import {
  committedEntry,
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
  buildEffectiveParams,
  buildListEffectiveParams,
  buildReversalParams,
  CANONICAL_RESOURCE,
  Connectors,
  createEphemeralEvidenceKeys,
  credentialAuthorityFrom,
  dispatchPathFor,
  EvidenceStore,
  McpPaymentsServer,
  openEphemeralWriteReservationStore,
  PAYMENTS_INVOICE_CONTRACT,
  PAYMENTS_PROFILE_VERSION,
  parameterDigest,
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
  /** The transaction tier's connectors and the write tier's reservations: every effect a tool can leave. */
  connectors: Connectors;
  writeReservations: ReturnType<typeof openEphemeralWriteReservationStore>;
  /** The store the operations read, as seeded. */
  payments: PaymentsStore;
  decided: EvaluationRequest[];
  records: () => ReturnType<EvidenceStore["forMission"]>;
  setPepContracts: (d: ResourceContractDeclarations) => void;
  close: () => Promise<void>;
}

async function build(
  mode: (typeof MODES)[number],
  view: MissionView,
  contracts: ResourceContractDeclarations,
  opts: {
    pdpContracts?: ResourceContractDeclarations;
    now?: () => Date;
    /** The PDP's own clock, where it differs from the PEP's (`now`). */
    pdpNow?: () => Date;
    requiresActionApproval?: (action: string, actionClass: string | undefined) => boolean;
    /** Perform under the shipped `RETAINED_OPERATION_PROFILES` rather than this file's retained table. */
    shippedRetainedProfiles?: boolean;
    /** Further records, after the shared seed. */
    seed?: (payments: PaymentsStore) => void;
  } = {},
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
  opts.seed?.(payments);
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
    getOptions: () => ({
      view,
      fga,
      modelId: "test",
      now: opts.pdpNow ?? now,
      stalenessBound,
      relationForAction,
      stateSourcePlacement: "pep" as const,
      ...(opts.requiresActionApproval ? { requiresActionApproval: opts.requiresActionApproval } : {}),
    }),
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
    ...(opts.shippedRetainedProfiles ? {} : { retainedOperationProfiles: () => ({ [RETAINED_PROFILE]: RETAINED_TABLE }) }),
    ...(opts.requiresActionApproval ? { requiresActionApproval: opts.requiresActionApproval } : {}),
    decide: (req, o) => {
      decided.push(req);
      return channel.decide(req, o);
    },
    claims: channel.claims,
  });
  const writeReservations = openEphemeralWriteReservationStore({ owner: RUNTIME_POSTURE.mediated_scope.pep_locations[0] as string });
  const connectors = new Connectors();
  const server = new McpPaymentsServer({
    pep,
    payments,
    loadView,
    issuer: ISSUER,
    jwks: { keys: [] },
    keyRoles: { accessToken: [], attenuationRoot: [], transactionToken: [] },
    enforcementScopeStatement: loadRuntimePosture({ ...RUNTIME_POSTURE, remote_decision_channels: channel.remoteDecisionChannels }),
    transaction: { engine: new TransactionEngine("epoch-249", now), connectors, evidence },
    writeReservations,
  });
  return {
    server,
    pep,
    connectors,
    writeReservations,
    payments,
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

  // @spec runtime#resource-contract (#249, D1104): the Operation Profile
  // material the document states, the parameter forms and the matcher values,
  // corresponds to what the resource performs, so a change to it without a
  // new version fails here.
  it("each declared parameter form is the fields its normal form carries, every optional member included, and no other form is declared", () => {
    const forms = (current?.document as { parameter_forms: Record<string, string[]> }).parameter_forms;
    const vendor = { id: "acme", name: "Acme", status: "approved", version: 1 };
    const invoice = { id: "inv-1", vendor_id: "acme", amount: "125.00", currency: "USD", payee_account: "acct-acme", status: "payable", version: 1 };
    const built: Record<string, object | undefined> = {
      invoice: buildEffectiveParams({ action: "payments:payment.schedule", invoice, vendor, resource: CANONICAL_RESOURCE, recipients: ["ap@acme.example"] }),
      list: buildListEffectiveParams({ action: "payments:invoice.list", resource: CANONICAL_RESOURCE, vendor_scope: ["acme"], vendor_scope_source: "all", members: [] }),
      none: undefined,
      reversal: buildReversalParams({
        action: "payments:payment.reverse",
        wire: { invoiceId: "inv-1", vendorId: "acme", payeeAccount: "acct-acme", amount: "125.00", currency: "USD" },
        resource: CANONICAL_RESOURCE,
        reverses: "op-1",
      }),
    };
    expect(Object.keys(forms).sort()).toEqual(Object.keys(built).sort());
    for (const [form, params] of Object.entries(built)) {
      expect([...(forms[form] ?? [])].sort(), form).toEqual(params === undefined ? [] : Object.keys(params).sort());
    }
  });

  /**
   * Each parameter form's canonical digest over fixed inputs, recorded per
   * contract version. Normalization (each member's encoding, the canonical
   * object the digest is computed over) is contract material, so a change to
   * it changes these: it needs a new contract version with its own entry
   * here, never an edit of a published version's.
   */
  const NORMAL_FORM_DIGESTS: Record<string, Record<string, string>> = {
    "2026-10-27": {
      invoice: "sha-256:u_Ts2Z1zkNdll-qmricNSCXuAetq5psUkOeCKH3uQS8",
      list: "sha-256:GujuA1Uzv_MUN7wzxQtOyG6iA6FX1Jon_6YpeDFNObs",
      reversal: "sha-256:w2ZqvQP0H3xLDCWwInxrbcxX5mDPInzeIg5wmbimnG8",
    },
  };

  it("each parameter form normalizes fixed inputs to the digest recorded for the current version", () => {
    const vendor = { id: "acme", name: "Acme", status: "approved", version: 3 };
    const invoice = { id: "inv-1", vendor_id: "acme", amount: "125.00", currency: "USD", payee_account: "acct-acme", status: "payable", version: 2 };
    const normalized = {
      invoice: parameterDigest(
        buildEffectiveParams({ action: "payments:payment.schedule", invoice, vendor, resource: CANONICAL_RESOURCE, recipients: ["ap@acme.example", "ar@acme.example"] }),
      ),
      list: parameterDigest(
        buildListEffectiveParams({
          action: "payments:invoice.list",
          resource: CANONICAL_RESOURCE,
          vendor_scope: ["acme", "globex"],
          vendor_scope_source: "entry",
          members: [{ id: "inv-1", issued_at: "2026-08-15T09:30:00Z", tenant: "payments-demo", data_classification: "internal" }],
        }),
      ),
      reversal: parameterDigest(
        buildReversalParams({
          action: "payments:payment.reverse",
          wire: { invoiceId: "inv-1", vendorId: "acme", payeeAccount: "acct-acme", amount: "125.00", currency: "USD" },
          resource: CANONICAL_RESOURCE,
          reverses: "op-1",
        }),
      ),
    };
    expect(normalized).toEqual(NORMAL_FORM_DIGESTS[current?.version as string]);
  });

  it("the declared resource_match values are exactly those the matcher enforces", () => {
    const declaredMatches = (current?.document as { resource_match: string[] }).resource_match;
    const candidates = ["exact", "prefix", "suffix", "regex", "glob", "template", "wildcard"];
    const enforced = candidates.filter((form) => matchResource({ resource: `${CANONICAL_RESOURCE}/`, resource_match: form }, `${CANONICAL_RESOURCE}/`) !== "unsupported");
    expect([...declaredMatches].sort()).toEqual(enforced.sort());
  });

  it("each operation binds the parameter form the document names, accepts an idempotency key and carries resolved recipients exactly where it declares them, and the none form binds no digest", async () => {
    const operations = (current?.document as {
      operations: Record<string, { parameters: string; idempotency_key?: boolean; recipients?: boolean }>;
    }).operations;
    const pinned = viewOf([entry({ id: CONTRACT, version: current?.version as string, digest: current?.digest as string })]);
    const routed = (payments: PaymentsStore) => payments.seedRemittance("acme", ["ap@acme.example", "ar@acme.example"]);
    const callOn = (x: Built, tool: string, mapping: ActionMapping) => {
      const path = dispatchPathFor(mapping, true);
      return path === "read"
        ? x.server.callReadTool.bind(x.server)
        : path === "write"
          ? x.server.callWriteTool.bind(x.server)
          : x.server.callTransactionTool.bind(x.server);
    };
    // The compensate crossing binds the reversal form over the committed
    // wire's own record, witnessed live in compound-actions.test.ts ("reverses
    // exactly the committed amount whatever the invoice now reads"), whose
    // fields the first test above pins to the declared form.
    expect(operations.reverse_wire_transfer).toMatchObject({ parameters: "reversal", idempotency_key: true });
    for (const [tool, mapping] of Object.entries(TOOL_ACTIONS)) {
      if (tool === "reverse_wire_transfer") continue;
      const declaredOp = operations[tool] as { parameters: string; idempotency_key?: boolean; recipients?: boolean };
      const base: Record<string, unknown> = tool === "list_invoices" ? {} : tool === "lookup_vendor" ? { vendor_id: "acme" } : { invoice_id: "inv-1" };
      const key = `idem_${crypto.randomUUID()}`;
      if (declaredOp.idempotency_key !== true) {
        // An operation that declares no idempotency key refuses one before any decision.
        const offered = await build("co-resident", pinned, RESOURCE_CONTRACTS, { shippedRetainedProfiles: true, seed: routed });
        try {
          const res = await callOn(offered, tool, mapping)(tool, { ...base, idempotency_key: key }, tokenFor(pinned));
          expect(res.ok, tool).toBe(false);
          expect(offered.decided, tool).toHaveLength(0);
        } finally {
          await offered.close();
        }
      }
      const x = await build("co-resident", pinned, RESOURCE_CONTRACTS, { shippedRetainedProfiles: true, seed: routed });
      try {
        await callOn(x, tool, mapping)(tool, declaredOp.idempotency_key === true ? { ...base, idempotency_key: key } : base, tokenFor(pinned));
        const req = x.decided[0] as { action: { properties?: Record<string, unknown> }; context: Record<string, unknown> } | undefined;
        expect(req, tool).toBeDefined();
        const invoice = x.payments.getInvoice("inv-1");
        const vendor = x.payments.getVendor("acme");
        if (!invoice || !vendor) throw new Error("seeded records");
        const recipients = x.payments.remittanceRecipients("acme")?.recipients;
        const expected: Record<string, string | undefined> = {
          invoice: parameterDigest(
            buildEffectiveParams({ action: mapping.action, invoice, vendor, resource: CANONICAL_RESOURCE, ...(declaredOp.recipients ? { recipients } : {}) }),
          ),
          list: parameterDigest(
            buildListEffectiveParams({ action: mapping.action, resource: CANONICAL_RESOURCE, vendor_scope: ["acme"], vendor_scope_source: "all" }),
          ),
          none: undefined,
        };
        expect(Object.keys(expected), tool).toContain(declaredOp.parameters);
        expect(req?.context.parameter_digest, tool).toBe(expected[declaredOp.parameters]);
        expect(req?.action.properties?.idempotency_key, tool).toBe(declaredOp.idempotency_key === true ? key : undefined);
        expect(req?.action.properties?.recipients, tool).toEqual(declaredOp.recipients ? recipients : undefined);
      } finally {
        await x.close();
      }
    }
  });

  it("performs the superseded 2026-10-20 version under the retained v13 profile: each crossing it names as the live profile does, and not the compensate crossing it lacks (#252)", () => {
    const superseded = shipped?.versions.find((v) => v.version === "2026-10-20");
    expect(superseded?.state).toBe("superseded");
    expect(superseded?.operation_profile).toBe("payments-runtime-profile-v13");
    const named = Object.keys((superseded?.document as { operations: Record<string, unknown> }).operations).sort();
    expect(named).toEqual(Object.keys(TOOL_ACTIONS).filter((tool) => tool !== "reverse_wire_transfer").sort());
    // No deployment-supplied retained profiles: the shipped default applies.
    const pep = new Pep({} as never);
    for (const tool of Object.keys(TOOL_ACTIONS)) {
      const retained = pep.toolActionUnder(tool, superseded?.operation_profile);
      if (named.includes(tool)) expect(retained, tool).toEqual(TOOL_ACTIONS[tool]);
      else expect(retained, tool).toBeUndefined();
    }
  });

  it("performs the superseded 2026-10-24 version under the retained v14 profile: each crossing as the live profile does, and not the compensate crossing, whose v15 semantics it never gets (#1693, D879)", () => {
    const superseded = shipped?.versions.find((v) => v.version === "2026-10-24");
    expect(superseded?.state).toBe("superseded");
    expect(superseded?.retained_until).toEqual(expect.any(String));
    expect(superseded?.operation_profile).toBe("payments-runtime-profile-v14");
    // Its document names the reversal: v14 performed it, under other semantics.
    const named = Object.keys((superseded?.document as { operations: Record<string, unknown> }).operations).sort();
    expect(named).toEqual(Object.keys(TOOL_ACTIONS).sort());
    // No deployment-supplied retained profiles: the shipped default applies.
    const pep = new Pep({} as never);
    for (const tool of Object.keys(TOOL_ACTIONS)) {
      const retained = pep.toolActionUnder(tool, superseded?.operation_profile);
      if (tool === "reverse_wire_transfer") expect(retained, tool).toBeUndefined();
      else expect(retained, tool).toEqual(TOOL_ACTIONS[tool]);
    }
  });

  it("the 2026-10-26 document differs from 2026-10-24's only in its version, its Operation Profile and the reversal's tenant fact (#1693)", () => {
    const docOf = (version: string) =>
      structuredClone(shipped?.versions.find((v) => v.version === version)?.document) as {
        version: string;
        operation_profile: string;
        constraints: Record<string, string>;
      };
    const v15 = docOf("2026-10-26");
    const v14 = docOf("2026-10-24");
    expect([v15.version, v15.operation_profile]).toEqual(["2026-10-26", "payments-runtime-profile-v15"]);
    expect(v15.constraints.tenant).toMatch(/for reverse_wire_transfer, the current record of the reversed wire's recorded vendor/);
    expect(v14.constraints.tenant).not.toMatch(/reverse_wire_transfer/);
    v15.version = v14.version;
    v15.operation_profile = v14.operation_profile;
    v15.constraints.tenant = v14.constraints.tenant as string;
    expect(v15).toEqual(v14);
  });

  it("the current 2026-10-27 document differs from 2026-10-26's only in its version and its Operation Profile (#813, #816, D877)", () => {
    const docOf = (version: string) =>
      structuredClone(shipped?.versions.find((v) => v.version === version)?.document) as {
        version: string;
        operation_profile: string;
      };
    const v16 = docOf("2026-10-27");
    const v15 = docOf("2026-10-26");
    expect(current?.version).toBe("2026-10-27");
    expect([v16.version, v16.operation_profile]).toEqual(["2026-10-27", "payments-runtime-profile-v16"]);
    v16.version = v15.version;
    v16.operation_profile = v15.operation_profile;
    expect(v16).toEqual(v15);
  });

  it("performs the superseded 2026-10-26 version under the retained v15 profile: every crossing the live v16 profile names, each exactly as the live profile does, the reversal included (#813, #816, D877)", () => {
    const superseded = shipped?.versions.find((v) => v.version === "2026-10-26");
    expect(superseded?.state).toBe("superseded");
    expect(superseded?.retained_until).toBe("2027-10-27T00:00:00Z");
    expect(superseded?.operation_profile).toBe("payments-runtime-profile-v15");
    const named = Object.keys((superseded?.document as { operations: Record<string, unknown> }).operations).sort();
    expect(named).toEqual(Object.keys(TOOL_ACTIONS).sort());
    // No deployment-supplied retained profiles: the shipped default applies.
    const pep = new Pep({} as never);
    for (const tool of Object.keys(TOOL_ACTIONS)) {
      expect(pep.toolActionUnder(tool, superseded?.operation_profile), tool).toEqual(TOOL_ACTIONS[tool]);
    }
  });

  it("resolves the current 2026-10-27 version, naming payments-runtime-profile-v16, for every operation, and the superseded 2026-10-26 version through its retained_until instant and not after it (#813, #816, D877)", () => {
    const refOf = (version: string): ResourceContractRef => {
      const v = shipped?.versions.find((x) => x.version === version);
      return { id: CONTRACT, version, digest: v?.digest as string };
    };
    const at = (iso: string, action: string) => ({ target: CANONICAL_RESOURCE, action, now: new Date(iso) });
    for (const action of ACTIONS) {
      const resolved = RESOURCE_CONTRACTS.resolve(refOf("2026-10-27"), at("2030-01-01T00:00:00Z", action));
      expect(resolved.ok, action).toBe(true);
      expect(resolved.ok ? resolved.version.operation_profile : undefined, action).toBe("payments-runtime-profile-v16");
      const within = RESOURCE_CONTRACTS.resolve(refOf("2026-10-26"), at("2027-10-27T00:00:00Z", action));
      expect(within.ok ? within.version.operation_profile : undefined, action).toBe("payments-runtime-profile-v15");
      expect(RESOURCE_CONTRACTS.resolve(refOf("2026-10-26"), at("2027-10-27T00:00:01Z", action)), action).toEqual({
        ok: false,
        reason: "outside_retention",
      });
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

// @spec runtime#resource-contract, resource-access#initial-common-constraints
// (#249, D1104): the declared inputs of the two constraints no other witness
// tells apart from an alternative source. Every other clause of the document's
// `constraints` is witnessed where its constraint is enforced (the ledger row
// runtime.resource-contract.new-version-on-change lists each).
describe("the declared constraint inputs the payments resource reads (@spec runtime#resource-contract, #249)", () => {
  const [shipped] = RESOURCE_CONTRACTS.declarations;
  const current = shipped?.versions.find((v) => v.state === "current");
  const constraints = (current?.document as { constraints: Record<string, string> } | undefined)?.constraints ?? {};
  const pinnedRef = { id: CONTRACT, version: current?.version as string, digest: current?.digest as string };
  const read = (x: Built, view: MissionView) => x.server.callReadTool("get_invoice", { invoice_id: "inv-1" }, tokenFor(view));

  it("time_window reads each evaluating component's own clock, never a time the request carries: past the window's end on the PDP's clock is denied what the PEP's clock let through, and past it on the PEP's clock is refused before any decision", async () => {
    expect(constraints.time_window).toBe("the evaluating component's own clock");
    // Over the remote channel, the one whose PDP evaluates with its own
    // options and clock; a co-resident PDP decides in the PEP's process, on
    // its clock.
    const t = NOW().getTime();
    const at = (ms: number) => () => new Date(ms);
    const windowed = viewOf([entry(pinnedRef, CANONICAL_RESOURCE, { constraints: { time_window: { not_after: new Date(t + 60_000).toISOString() } } } as Partial<Entry>)]);
    const both = await build("remote", windowed, RESOURCE_CONTRACTS, { now: at(t), pdpNow: at(t) });
    try {
      const res = await read(both, windowed);
      expect(res.ok, JSON.stringify(res)).toBe(true);
    } finally {
      await both.close();
    }
    const pdpPast = await build("remote", windowed, RESOURCE_CONTRACTS, { now: at(t), pdpNow: at(t + 120_000) });
    try {
      const res = await read(pdpPast, windowed);
      expect(res, JSON.stringify(res)).toMatchObject({ ok: false, denial_reason: "parameter_violation" });
      expect(pdpPast.decided).toHaveLength(1);
    } finally {
      await pdpPast.close();
    }
    const pepPast = await build("remote", windowed, RESOURCE_CONTRACTS, { now: at(t + 120_000), pdpNow: at(t) });
    try {
      const res = await read(pepPast, windowed);
      // The PEP's own credential-bound check refuses it before any decision:
      // a pre-decision Refusal Record classified
      // credential_authority_insufficient, where the PDP's evaluated
      // constraint denial above is parameter_violation.
      expect(res.ok, JSON.stringify(res)).toBe(false);
      expect(pepPast.decided).toHaveLength(0);
      expect(pepPast.records().filter((e) => e.kind === "refusal").map((e) => e.content)).toEqual([
        expect.objectContaining({ denial_reason: "credential_authority_insufficient" }),
      ]);
    } finally {
      await pepPast.close();
    }
  });

  it("terminal_when reads the Mission Issuer's discharge state: the entry the issuer's view lists as discharged is denied authority_discharged at the decision, and the same entry undischarged is performed, nothing at the resource differing", async () => {
    expect(constraints.terminal_when).toBe("the Mission Issuer's discharge state");
    const completing = entry(pinnedRef, CANONICAL_RESOURCE, {
      constraints: { terminal_when: [{ event_type: "accounting-period-closed", discharge_authority: "close-management-2026-q3" }] },
    } as Partial<Entry>);
    // A view that holds its committed set, so the PDP can source the
    // credential entry's completion condition from the Mission's.
    const live: MissionView = { ...viewOf([completing]), authority_hash: authorityHash(ISSUER, [committedEntry(completing)] as unknown as JsonValue[]) };
    const discharged: MissionView = {
      ...live,
      version: 2,
      discharged: { entry_digests: [computeAnchor(AUTHORITY_ENTRY_TYP, ISSUER, committedEntry(completing) as unknown as JsonValue)] },
    };
    for (const mode of MODES) {
      const performed = await build(mode, live, RESOURCE_CONTRACTS);
      try {
        const res = await read(performed, live);
        expect(res.ok, `${mode}: ${JSON.stringify(res)}`).toBe(true);
      } finally {
        await performed.close();
      }
      const denied = await build(mode, discharged, RESOURCE_CONTRACTS);
      try {
        const res = await read(denied, discharged);
        expect(res, `${mode}: ${JSON.stringify(res)}`).toMatchObject({ ok: false, denial_reason: "authority_discharged" });
        expect(denied.decided, mode).toHaveLength(1);
        expect(res.result, mode).toBeUndefined();
      } finally {
        await denied.close();
      }
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

describe("each stage records a contract failure on its own carrier (@spec runtime#resource-contract, authzen#failure-condition-coverage, #249)", () => {
  it("a reference the PEP resolves but the PDP does not is a PDP denial resource_contract_drift, retained as Decision Evidence: no Refusal Record, no Execution Evidence, no effect", async () => {
    const view = viewOf([entry(V1_LIVE)]);
    for (const mode of MODES) {
      const x = await build(mode, view, V1_CURRENT, { pdpContracts: V2_ONLY });
      try {
        const res = await x.server.callReadTool("get_invoice", { invoice_id: "inv-1" }, tokenFor(view));
        expect(res, mode).toMatchObject({ ok: false, denial_reason: "resource_contract_drift" });
        expect(res.result, mode).toBeUndefined();
        expect(x.decided, mode).toHaveLength(1);
        const recorded = x.records();
        expect(recorded.filter((e) => e.kind === "decision").map((e) => e.content), mode).toEqual([
          expect.objectContaining({ decision: "deny", denial_reason: "resource_contract_drift" }),
        ]);
        expect(recorded.filter((e) => e.kind === "refusal" || e.kind === "execution"), mode).toEqual([]);
      } finally {
        await x.close();
      }
    }
  });
});

describe("the PDP decides the contract across the decision channel (@spec runtime#resource-contract, authzen#context-resource-contract, authzen#context-approval, #249)", () => {
  const v1View = viewOf([entry(V1, `${CANONICAL_RESOURCE}/invoices`, { resource_match: "prefix" })]);

  it("a reference the PEP resolves and the PDP's declarations no longer do is denied resource_contract_drift, parameters identical: a v1 entry at a PDP serving only v2", async () => {
    const view = viewOf([entry(V1_LIVE)]);
    for (const mode of MODES) {
      const control = await build(mode, view, V1_CURRENT);
      const x = await build(mode, view, V1_CURRENT, { pdpContracts: V2_ONLY });
      try {
        const ok = await control.pep.enforce("get_invoice", { invoice_id: "inv-1" }, tokenFor(view));
        const res = await x.pep.enforce("get_invoice", { invoice_id: "inv-1" }, tokenFor(view));
        expect(ok.permitted, mode).toBe(true);
        expect(res, mode).toMatchObject({ permitted: false, denial_reason: "resource_contract_drift" });
        expect(x.decided[0]?.context.parameter_digest, mode).toBe(control.decided[0]?.context.parameter_digest);
      } finally {
        await control.close();
        await x.close();
      }
    }
  });

  it("where the PDP's declarations require a reference, an unpinned entry is denied resource_contract_drift and gains none", async () => {
    const unpinned = viewOf([entry(undefined)]);
    for (const mode of MODES) {
      const x = await build(mode, unpinned, V1_CURRENT, { pdpContracts: declarations([declared("v1", "current")], ACTIONS) });
      try {
        const res = await x.pep.enforce("get_invoice", { invoice_id: "inv-1" }, tokenFor(unpinned));
        expect(res, mode).toMatchObject({ permitted: false, denial_reason: "resource_contract_drift" });
        expect(x.decided[0]?.resource.properties, mode).not.toHaveProperty("resource_contract");
        expect(unpinned.authority_set[0], mode).not.toHaveProperty("resource_contract");
      } finally {
        await x.close();
      }
    }
  });

  it("a superseded version permits within the retention the PDP declares and is denied past it", async () => {
    const lapsed = declarations([
      declared("v1", "superseded", RETAINED_PROFILE, { retained_until: "2026-10-01T00:00:00Z" }),
      declared("v2", "current"),
    ]);
    for (const mode of MODES) {
      const within = await build(mode, v1View, RETAINED);
      const past = await build(mode, v1View, RETAINED, { pdpContracts: lapsed });
      try {
        expect((await within.pep.enforce("get_invoice", { invoice_id: "inv-1" }, tokenFor(v1View))).permitted, mode).toBe(true);
        expect(await past.pep.enforce("get_invoice", { invoice_id: "inv-1" }, tokenFor(v1View)), mode).toMatchObject({
          permitted: false,
          denial_reason: "resource_contract_drift",
        });
      } finally {
        await within.close();
        await past.close();
      }
    }
  });

  it("under a retained v1, an inactive Mission and contained authority still refuse", async () => {
    for (const mode of MODES) {
      for (const [label, view, expected] of [
        ["inactive", { ...v1View, state: "suspended" }, "mission_inactive"],
        ["contained", { ...v1View, containment: { version: 1, contained: [{ resource: `${CANONICAL_RESOURCE}/invoices`, actions: ACTIONS }] } }, "authority_contained"],
      ] as const) {
        const x = await build(mode, view as MissionView, RETAINED);
        try {
          const res = await x.pep.enforce("get_invoice", { invoice_id: "inv-1" }, tokenFor(view as MissionView));
          expect(res, `${mode} ${label}`).toMatchObject({ permitted: false, denial_reason: expected });
        } finally {
          await x.close();
        }
      }
    }
  });

  it("an approval bound to v1 does not cover the same action under v2, both resolving and the parameters identical: out_of_scope; one bound to v2 permits", async () => {
    const v2View = viewOf([entry(V2)]);
    for (const mode of MODES) {
      const x = await build(mode, v2View, RETAINED, { requiresActionApproval: () => true });
      try {
        const gated = await x.pep.enforce("get_invoice", { invoice_id: "inv-1" }, tokenFor(v2View));
        expect(gated, mode).toMatchObject({ permitted: false, denial_reason: "action_approval_required" });
        const digest = x.decided[0]?.context.parameter_digest as string;
        const approval = (r: ResourceContractRef) => ({
          id: "apr_249",
          approved_at: NOW().toISOString(),
          parameter_digest: digest,
          resource: { properties: { resource_contract: r } },
        });
        expect(await x.pep.enforce("get_invoice", { invoice_id: "inv-1" }, tokenFor(v2View), approval(V1)), mode).toMatchObject({
          permitted: false,
          denial_reason: "out_of_scope",
        });
        expect((await x.pep.enforce("get_invoice", { invoice_id: "inv-1" }, tokenFor(v2View), approval(V2))).permitted, mode).toBe(true);
        expect(new Set(x.decided.map((r) => r.context.parameter_digest)).size, mode).toBe(1);
      } finally {
        await x.close();
      }
    }
  });

  it("an approval bound to v1, parameters unchanged, is refused once the PDP's v1 definition changed after the approval and before the decision", async () => {
    const view = viewOf([entry(V1_LIVE)]);
    const changed = declarations([{ ...declared("v1", "current", "payments-runtime-profile-changed"), version: "v1" }]);
    for (const mode of MODES) {
      const before = await build(mode, view, V1_CURRENT, { requiresActionApproval: () => true });
      const after = await build(mode, view, V1_CURRENT, { pdpContracts: changed, requiresActionApproval: () => true });
      try {
        await before.pep.enforce("get_invoice", { invoice_id: "inv-1" }, tokenFor(view));
        const approval = {
          id: "apr_249_pin",
          approved_at: NOW().toISOString(),
          parameter_digest: before.decided[0]?.context.parameter_digest as string,
          resource: { properties: { resource_contract: V1_LIVE } },
        };
        expect((await before.pep.enforce("get_invoice", { invoice_id: "inv-1" }, tokenFor(view), approval)).permitted, mode).toBe(true);
        expect(await after.pep.enforce("get_invoice", { invoice_id: "inv-1" }, tokenFor(view), approval), mode).toMatchObject({
          permitted: false,
          denial_reason: "resource_contract_drift",
        });
      } finally {
        await before.close();
        await after.close();
      }
    }
  });

  it("a presented reference that resolves but differs from the Mission entry's is denied resource_contract_drift", async () => {
    // The credential names v2; the Mission's entry was approved under v1.
    const view = viewOf([entry(V1)]);
    for (const mode of MODES) {
      const x = await build(mode, view, RETAINED);
      try {
        const res = await x.pep.enforce("get_invoice", { invoice_id: "inv-1" }, tokenFor(view, [entry(V2)]));
        expect(x.decided[0]?.resource.properties.resource_contract, mode).toEqual(V2);
        expect(res, mode).toMatchObject({ permitted: false, denial_reason: "resource_contract_drift" });
      } finally {
        await x.close();
      }
    }
  });
});

describe("the PEP's contract carriers, with no PDP behind it (@spec runtime-evidence#pre-decision-refusal, runtime-evidence#execution-evidence-object, #249)", () => {
  const view = viewOf([entry(V1_LIVE)]);
  const lonePep = (contracts: () => ResourceContractDeclarations) => {
    const keys = createEphemeralEvidenceKeys();
    const evidence = new EvidenceStore(keys.signing, keys.resolver);
    const payments = new PaymentsStore();
    payments.seed(
      [{ id: "acme", name: "Acme", status: "approved" }],
      [{ id: "inv-1", vendor_id: "acme", amount: "125.00", currency: "USD", payee_account: "acct-acme", status: "payable" }],
    );
    let asked = 0;
    const pep = new Pep({
      payments,
      evidence,
      fga: { checkWithContext: async () => true } as unknown as Fga,
      modelId: "test",
      loadView: () => ({ view, observation: { state: "active", version: 1, mode: "fresh", freshness_at: NOW().toISOString() } }),
      instanceEpoch: "epoch-249-unit",
      now: NOW,
      resourceContracts: contracts,
      decide: async () => {
        asked++;
        throw new Error("no PDP is reachable from this test");
      },
    });
    return { pep, evidence, asked: () => asked };
  };

  it("a reference that does not resolve signs a Refusal Record resource_contract_unresolvable, asks no PDP and has no effect", async () => {
    const { pep, evidence, asked } = lonePep(() => V2_ONLY);
    const res = await pep.enforce("get_invoice", { invoice_id: "inv-1" }, tokenFor(view));
    expect(res).toMatchObject({ permitted: false, refusal_reason: "resource_contract_unresolvable" });
    expect(asked()).toBe(0);
    const records = evidence.forMission(view.id);
    expect(records.map((e) => [e.kind, (e.content as { denial_reason?: string }).denial_reason])).toEqual([
      ["refusal", "resource_contract_unresolvable"],
    ]);
  });

  it("at use, a permit whose contract no longer resolves, or whose condition is missing or names another contract, is suppressed with Execution Evidence resource_contract_unresolvable, never a parameter or target error", async () => {
    let contracts = V1_CURRENT;
    const { pep, evidence } = lonePep(() => contracts);
    const established = pep.boundary();
    if (!established.ok) throw new Error("boundary");
    const attempt = (over: Record<string, unknown> = {}) => ({
      evaluationId: `dec_${crypto.randomUUID()}`,
      mission: { id: view.id, issuer: view.issuer },
      audience: established.boundary,
      boundaryVersion: established.version,
      operationTarget: CANONICAL_RESOURCE,
      operationArguments: { invoice_id: "inv-1" },
      performedContract: V1_LIVE,
      permitResourceContract: V1_LIVE as unknown,
      action: "payments:invoice.read",
      tool: "get_invoice",
      permitValidUntil: new Date(NOW().getTime() + 60_000).toISOString(),
      executionId: `exe_${crypto.randomUUID()}`,
      permitId: "permit-249",
      joinKey: "op:msn_249_pep:payments:invoice.read",
      observeEffectiveDigest: () => undefined,
      ...over,
    });
    expect(pep.permitUseFailure(attempt() as never)).toBeUndefined();
    const outcomes: string[] = [];
    for (const [a, swap] of [
      [attempt({ permitResourceContract: undefined }), V1_CURRENT],
      [attempt({ permitResourceContract: V2 }), V1_CURRENT],
      [attempt(), declarations([{ version: "v1", state: "retired", digest: V1_LIVE.digest }, declared("v2", "current")])],
    ] as const) {
      contracts = swap;
      const out = await pep.verifyPermitAtUse(a as never);
      outcomes.push(out.ok ? "ok" : out.error);
    }
    expect(outcomes).toEqual(["resource_contract_unresolvable", "resource_contract_unresolvable", "resource_contract_unresolvable"]);
    const executions = evidence.forMission(view.id).filter((e) => e.kind === "execution").map((e) => e.content as { outcome: string; error: string });
    expect(executions).toHaveLength(3);
    for (const e of executions) {
      expect(e).toMatchObject({ outcome: "suppressed", error: "resource_contract_unresolvable" });
      expect(["parameter_mismatch", "target_drift", "phase_mismatch"]).not.toContain(e.error);
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

describe("the shipped superseded 2026-10-26 version is still performed within its retention (@spec runtime#resource-contract, #813, #816, D877)", () => {
  const [shipped] = RESOURCE_CONTRACTS.declarations;
  const v15 = shipped?.versions.find((v) => v.version === "2026-10-26");
  const V15_REF: ResourceContractRef = { id: CONTRACT, version: "2026-10-26", digest: v15?.digest as string };
  const view = viewOf([entry(V15_REF)]);

  it("a read and a write decided under the 2026-10-26 reference are performed under the retained v15 profile within its retention, and refused before any decision past it (#813, #816, D877)", async () => {
    for (const mode of MODES) {
      const within = await build(mode, view, RESOURCE_CONTRACTS, { now: () => new Date("2026-10-28T12:00:00Z"), shippedRetainedProfiles: true });
      try {
        const read = await within.server.callReadTool("get_invoice", { invoice_id: "inv-1" }, tokenFor(view));
        expect(read.ok, `${mode}: ${JSON.stringify(read)}`).toBe(true);
        const write = await within.server.callWriteTool("schedule_payment", { invoice_id: "inv-2", idempotency_key: `idem-v15-retained-${mode}` }, tokenFor(view));
        expect(write.ok, `${mode}: ${JSON.stringify(write)}`).toBe(true);
        expect(within.decided.map((r) => r.resource.properties.resource_contract), mode).toEqual([V15_REF, V15_REF]);
      } finally {
        await within.close();
      }
      const past = await build(mode, view, RESOURCE_CONTRACTS, { now: () => new Date("2027-10-27T00:00:01Z"), shippedRetainedProfiles: true });
      try {
        const res = await past.server.callReadTool("get_invoice", { invoice_id: "inv-1" }, tokenFor(view));
        expect(res, mode).toMatchObject({ ok: false, refusal_reason: "resource_contract_unresolvable" });
        expect(past.decided, mode).toHaveLength(0);
      } finally {
        await past.close();
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

/** The five non-read payments actions the cutover requires a reference for (D865). */
const CUTOVER = [
  "payments:payment.schedule",
  "payments:payment.schedule.cancel",
  "payments:payment.execute",
  "payments:payment.reverse",
  "payments:remittance.send",
];

/**
 * @spec resource-access#resource-contract, runtime#resource-contract (#249
 * C.3a and C.3b, D1071): under the shipped declarations, which require a
 * reference for the cutover's five actions, the requirement applies per tool:
 * exactly the tools whose action is one of the five, the three that share
 * `payments:payment.execute` and differ only by phase included, and none of
 * the reads.
 */
describe("the per-tool reference requirement under the cutover's five actions (@spec resource-access#resource-contract, runtime#resource-contract, #249, D1071)", () => {
  const requiring = RESOURCE_CONTRACTS;
  const READ_ARGS: Record<string, Record<string, unknown>> = {
    list_invoices: {},
    get_invoice: { invoice_id: "inv-1" },
    lookup_vendor: { vendor_id: "acme" },
    check_transfer: { invoice_id: "inv-1" },
    hold_transfer: { invoice_id: "inv-1" },
  };
  const argsFor = (tool: string): Record<string, unknown> =>
    READ_ARGS[tool] ?? { invoice_id: "inv-1", idempotency_key: `idem_${crypto.randomUUID()}` };

  it("requires a reference for exactly the seven tools whose action is one of the five, the preflight, prepare and commit phases of payments:payment.execute included, and for none of the three reads", () => {
    expect(requiring.declarations[0]?.requires_reference).toEqual(CUTOVER);
    const tools = Object.keys(TOOL_ACTIONS);
    expect(tools).toHaveLength(10);
    const required = tools.filter((t) => requiring.requiresReference(CANONICAL_RESOURCE, (TOOL_ACTIONS[t] as ActionMapping).action));
    expect([...required].sort()).toEqual([
      "cancel_scheduled_payment",
      "check_transfer",
      "execute_wire_transfer",
      "hold_transfer",
      "reverse_wire_transfer",
      "schedule_payment",
      "send_remittance_email",
    ]);
    const execute = tools
      .filter((t) => TOOL_ACTIONS[t]?.action === "payments:payment.execute")
      .map((t) => [t, TOOL_ACTIONS[t]?.phase]);
    expect(execute).toEqual(
      expect.arrayContaining([
        ["check_transfer", "preflight"],
        ["hold_transfer", "prepare"],
        ["execute_wire_transfer", "commit"],
      ]),
    );
    expect(execute).toHaveLength(3);
    expect(tools.filter((t) => !required.includes(t)).sort()).toEqual(["get_invoice", "list_invoices", "lookup_vendor"]);
  });

  it("refuses an unpinned entry resource_contract_unresolvable for each of the seven, before any decision and with no effect, and performs each of the three reads, on its own dispatch path", async () => {
    const unpinned = viewOf([entry(undefined)]);
    for (const mode of MODES) {
      for (const [tool, mapping] of Object.entries(TOOL_ACTIONS)) {
        const label = `${mode} ${tool}`;
        const x = await build(mode, unpinned, requiring, { shippedRetainedProfiles: true });
        try {
          const path = dispatchPathFor(mapping, true);
          const call =
            path === "read"
              ? x.server.callReadTool.bind(x.server)
              : path === "write"
                ? x.server.callWriteTool.bind(x.server)
                : x.server.callTransactionTool.bind(x.server);
          const res = await call(tool, argsFor(tool), tokenFor(unpinned));
          if (CUTOVER.includes(mapping.action)) {
            expect(res, label).toMatchObject({ ok: false, refusal_reason: "resource_contract_unresolvable" });
            expect(res.result, label).toBeUndefined();
            expect(x.decided, label).toHaveLength(0);
            const recorded = x.records();
            expect(recorded.filter((e) => e.kind === "refusal").map((e) => e.content), label).toEqual([
              expect.objectContaining({ denial_reason: "resource_contract_unresolvable" }),
            ]);
            expect(recorded.filter((e) => e.kind === "execution" || e.kind === "decision"), label).toEqual([]);
            expect(x.connectors.ledgerEntries(), label).toEqual([]);
            expect(x.connectors.reversalEntries(), label).toEqual([]);
            expect(x.connectors.committedEffects(), label).toEqual([]);
            expect(x.writeReservations.schedules(), label).toEqual([]);
          } else {
            expect(res.ok, `${label}: ${JSON.stringify(res)}`).toBe(true);
            expect(x.decided, label).toHaveLength(1);
          }
        } finally {
          await x.close();
        }
      }
    }
  });
});
