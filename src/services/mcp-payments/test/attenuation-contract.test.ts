/**
 * @spec attenuation#root-mapping, attenuation#mission-binding-check,
 * runtime#resource-contract (#1756 slice B3, D932): one tool binds
 * verification, contract selection and execution. The holder's proof names
 * the invoked tool; that tool's own `mission_constraints` names the contract
 * the operation is performed under; the contract's Operation Profile
 * establishes the target, which with the action must be that tool; and the
 * credential authority is that tool's alone, so no other leaf tool's
 * restrictions or contract reach the decision.
 *
 * Attenuated operations run under declared contracts here: a retained
 * contract version whose Operation Profile targets the invoice (the
 * resource-contract fixtures' retained table) beside the current one. The
 * leaf's `resource_contract` is enforced at execution: absent where the
 * resource requires one, not declared, or withdrawn between the decision and
 * the release, it is refused. Co-resident decision channel, a stub FGA that
 * always allows, a permitting Resource policy fixture.
 */

import {
  type AttenuatedAuthority,
  deriveAttenuationRoot,
  MissionKernel,
  mintChildOffline,
  validateMissionIntent,
} from "@mission/authorization-server";
import { testAuthoritySourceCatalog } from "@mission/authorization-server/test-support";
import {
  type AttenuationOperations,
  aatToolId,
  ResourceContractDeclarations,
  type ResourceContractRef,
  resourceContractDigest,
} from "@mission/core";
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
import { exportJWK, generateKeyPair } from "jose";
import { beforeAll, describe, expect, it } from "vitest";
import {
  type ActionMapping,
  AatPresentationRefused,
  CANONICAL_RESOURCE,
  createEphemeralEvidenceKeys,
  createMediatedClient,
  EvidenceStore,
  McpPaymentsServer,
  openEphemeralWriteReservationStore,
  PAYMENTS_INVOICE_CONTRACT,
  PAYMENTS_PROFILE_VERSION,
  PaymentsStore,
  Pep,
  signAatPop,
  TOOL_ACTIONS,
} from "../src/index.js";

const ISSUER = "https://as.test";
const READ = "payments:invoice.read";
const INV1 = `${CANONICAL_RESOURCE}/invoices/inv-1`;
const SERVICE_TOOL = aatToolId(CANONICAL_RESOURCE, READ);
const INVOICE_TOOL = aatToolId(INV1, READ);
const CONTRACT = "https://payments.example/contracts/payments";
const ACTIONS = [...new Set(Object.values(TOOL_ACTIONS).map((m) => m.action))];
const NOW = () => new Date();

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

/** v1 retained (superseded, the invoice-level profile) and v2 current: both resolve. */
const V1 = ref("v1", RETAINED_PROFILE);
const RETAINED = declarations([
  declared("v1", "superseded", RETAINED_PROFILE, { retained_until: "2099-01-01T00:00:00Z" }),
  declared("v2", "current"),
]);
const V2_ONLY = declarations([declared("v2", "current")]);
/** v1 current under the live profile, required for every action. */
const V1_LIVE = ref("v1");
const REQUIRED = declarations([declared("v1", "current")], ACTIONS);

/** The resource's declaration to the mint: the invoice read at the service and at inv-1. */
const OPERATIONS: AttenuationOperations = (resource, action) =>
  action === READ && (resource === CANONICAL_RESOURCE || resource === INV1)
    ? [{ name: "get_invoice", arguments: { invoice_id: { required: true } }, establishes: ["vendors", "max_amount"] }]
    : undefined;

type Keys = { privateKey: CryptoKey; publicKey: CryptoKey };
let asKeys: Keys;
let asPub: Record<string, unknown>;
let holder: Keys;
let delegate: Keys;
let seq = 0;

beforeAll(async () => {
  asKeys = await generateKeyPair("ES256", { extractable: true });
  asPub = { ...(await exportJWK(asKeys.publicKey)), kid: "as-attenuation", alg: "ES256" };
  holder = await generateKeyPair("ES256", { extractable: true });
  delegate = await generateKeyPair("Ed25519", { extractable: true });
});

type Entry = MissionView["authority_set"][number];
const entry = (resource: string, over: Record<string, unknown> = {}): Entry =>
  ({ type: "mission_resource_access", resource, actions: [READ], ...over }) as Entry;

/**
 * The declarations the Mission Issuer approved under: v1 (the invoice-level
 * profile) while it was current. The resource has since moved to v2 and
 * retains v1 ({@link RETAINED}).
 */
const AS_CONTRACTS = declarations([declared("v1", "current", RETAINED_PROFILE)]);

/** A Mission over `entries`, approved under `contracts`, and a root the Mission Issuer mints for it from its mapped ceiling. */
async function mint(
  entries: Entry[],
  contracts: ResourceContractDeclarations = AS_CONTRACTS,
): Promise<{ view: MissionView; root: string; authority: AttenuatedAuthority }> {
  const policy = { policy_version: "attn-contract", ceiling: entries };
  const kernel = new MissionKernel({
    issuer: ISSUER,
    policy: policy as never,
    authoritySourceCatalog: testAuthoritySourceCatalog(entries as never, ["ap-agent"], ["bob"]),
    statusKey: asKeys.privateKey,
    statusKid: "as-status",
    resourceContracts: contracts,
  });
  const mission = kernel.approve({
    intent: validateMissionIntent(
      JSON.stringify({ goal: "Read invoices", target_resources: [CANONICAL_RESOURCE], expires_at: "2099-01-01T00:00:00Z" }),
    ),
    proposedAuthority: entries as never,
    subject: { iss: ISSUER, sub: "alice" },
    approver: { iss: ISSUER, sub: "bob" },
    clientId: "ap-agent",
    approvalEventId: `apev-attn-contract-${seq++}`,
  });
  const view: MissionView = {
    id: mission.id,
    issuer: ISSUER,
    state: "active",
    version: 1,
    authority_hash: mission.authority_hash,
    authority_set: mission.authority_set,
    subject: mission.subject,
    client_id: mission.client_id,
  };
  const minted = await deriveAttenuationRoot(kernel, asKeys.privateKey, "as-attenuation", {
    missionId: mission.id,
    aud: CANONICAL_RESOURCE,
    clientId: "ap-agent",
    cnfJwk: await exportJWK(holder.publicKey),
    operations: OPERATIONS,
    delMaxDepth: 1,
  });
  return { view, root: minted.root, authority: { tools: minted.tools, missionConstraints: minted.missionConstraints } };
}

interface Built {
  server: McpPaymentsServer;
  decided: EvaluationRequest[];
  records: () => ReturnType<EvidenceStore["forMission"]>;
  setPepContracts: (d: ResourceContractDeclarations) => void;
  close: () => Promise<void>;
}

/** The payments resource under `contracts`, with the retained invoice-level profile, deciding `view`. */
async function build(view: MissionView, contracts: ResourceContractDeclarations): Promise<Built> {
  const point = createEphemeralDecisionPoint({
    emitterId: CANONICAL_RESOURCE,
    audience: CANONICAL_RESOURCE,
    resourcePolicy: RESOURCE_POLICY_PERMITS_ALL_FIXTURE,
    resourceContracts: contracts,
  });
  const keys = createEphemeralEvidenceKeys({ decisionPoint: point });
  const evidence = new EvidenceStore(keys.signing, keys.resolver);
  const payments = new PaymentsStore();
  payments.seed(
    [{ id: "acme", name: "Acme", status: "approved" }],
    ["inv-1", "inv-2"].map((id) => ({ id, vendor_id: "acme", amount: "125.00", currency: "USD", payee_account: "acct-acme", status: "payable" })),
  );
  const fga = { checkWithContext: async () => true } as unknown as Fga;
  const loadView = (r: { id: string; issuer: string }) =>
    r.id === view.id && r.issuer === view.issuer
      ? { view, observation: { state: view.state, version: view.version, mode: "fresh", freshness_at: NOW().toISOString() } }
      : undefined;
  const channel = await createDecisionChannel(point, {
    mode: "co-resident",
    pepId: "mcp-payments-pep",
    audience: CANONICAL_RESOURCE,
    operationContracts: [{ service: CANONICAL_RESOURCE }, PAYMENTS_INVOICE_CONTRACT],
    getOptions: () => ({ view, fga, modelId: "test", now: NOW, stalenessBound, relationForAction, stateSourcePlacement: "pep" as const }),
  });
  const decided: EvaluationRequest[] = [];
  let pepContracts = contracts;
  const pep = new Pep({
    payments,
    evidence,
    fga,
    modelId: "test",
    loadView,
    instanceEpoch: "epoch-attn-contract",
    resourceContracts: () => pepContracts,
    retainedOperationProfiles: () => ({ [RETAINED_PROFILE]: RETAINED_TABLE }),
    decide: (req, o) => {
      decided.push(req);
      return channel.decide(req, o);
    },
    claims: channel.claims,
  });
  const server = new McpPaymentsServer({
    pep,
    payments,
    loadView,
    issuer: ISSUER,
    jwks: { keys: [asPub] },
    keyRoles: { accessToken: [], attenuationRoot: ["as-attenuation"], transactionToken: [] },
    enforcementScopeStatement: loadRuntimePosture({ ...RUNTIME_POSTURE, remote_decision_channels: channel.remoteDecisionChannels }),
    writeReservations: openEphemeralWriteReservationStore({ owner: RUNTIME_POSTURE.mediated_scope.pep_locations[0] as string }),
  });
  return {
    server,
    decided,
    records: () => evidence.forMission(view.id),
    setPepContracts: (d) => {
      pepContracts = d;
    },
    close: () => channel.close(),
  };
}

/** The presentation of `links` for `get_invoice` on `invoiceId`, its proof naming `tool`. */
async function presentation(links: string[], tool: string, argumentsJson: string, keys: Keys = holder) {
  return {
    aat_chain: links,
    aat_pop: await signAatPop({ leaf: links[links.length - 1] as string, holderKey: keys.privateKey, tool, argumentsJson }),
  };
}

const invoiceArgs = (id: string) => JSON.stringify({ invoice_id: id });

describe("one tool binds verification, contract selection and execution (@spec attenuation#mission-binding-check, runtime#resource-contract, #1756, D932)", () => {
  it("verifies a presentation naming the retained-contract tool and executes it under that contract", async () => {
    const { view, root } = await mint([entry(INV1, { resource_contract: V1 })]);
    const x = await build(view, RETAINED);
    const { client } = await createMediatedClient(x.server);
    try {
      const res = await client.callToolWithPresentation("get_invoice", { invoice_id: "inv-1" }, async (call) =>
        presentation([root], INVOICE_TOOL, call.argumentsJson),
      );
      expect(res.ok, JSON.stringify(res)).toBe(true);
      expect(x.decided).toHaveLength(1);
      expect(x.decided[0]?.resource.properties).toMatchObject({ operation_target: INV1, resource_contract: V1 });
    } finally {
      await client.close();
      await x.close();
    }
  });

  it("refuses the cross-tool substitution: a presentation verified for the service tool never executes under another leaf tool's contract or restrictions", async () => {
    // The leaf grants the service tool (vendor globex only, no contract) and
    // the retained-contract invoice tool, narrowed to inv-2.
    const { view, root, authority } = await mint([
      entry(CANONICAL_RESOURCE, { constraints: { vendors: ["globex"] } }),
      entry(INV1, { resource_contract: V1 }),
    ]);
    const narrowed: AttenuatedAuthority = {
      tools: { ...authority.tools, [INVOICE_TOOL]: { invoice_id: { constraint_type: "one_of", values: ["inv-2"] } } },
      missionConstraints: authority.missionConstraints,
    };
    const child = await mintChildOffline(root, holder.privateKey, narrowed, { cnfJwk: await exportJWK(delegate.publicKey) });
    const x = await build(view, RETAINED);
    const { client } = await createMediatedClient(x.server);
    try {
      // Verified for the service tool on inv-1: only that tool's authority
      // reaches the PEP, and its vendor bound refuses the Acme invoice.
      const substituted = await client.callToolWithPresentation("get_invoice", { invoice_id: "inv-1" }, async (call) =>
        presentation([root, child], SERVICE_TOOL, call.argumentsJson, delegate),
      );
      expect(substituted).toMatchObject({ ok: false, denial_reason: "out_of_authority" });
      expect(substituted.result).toBeUndefined();
      expect(x.decided).toHaveLength(0);
      // The invoice tool itself admits only inv-2.
      const direct = await client.callToolWithPresentation("get_invoice", { invoice_id: "inv-1" }, async (call) =>
        presentation([root, child], INVOICE_TOOL, call.argumentsJson, delegate),
      );
      expect(direct).toEqual({ ok: false, denial_reason: "invalid_credential" });
      expect(x.decided).toHaveLength(0);
    } finally {
      await client.close();
      await x.close();
    }
  });

  it("refuses a proof naming a tool its own contract does not perform the operation as, recording the refusal", async () => {
    // The service tool carries the retained contract, whose profile targets the invoice.
    const { view, root } = await mint([entry(CANONICAL_RESOURCE, { resource_contract: V1 })]);
    const x = await build(view, RETAINED);
    try {
      const p = await presentation([root], SERVICE_TOOL, invoiceArgs("inv-1"));
      await expect(x.server.validateAatPresentation(p, "get_invoice", invoiceArgs("inv-1"))).rejects.toThrow(
        /is not the operation "get_invoice" under its contract/,
      );
      expect(x.records().filter((e) => e.kind === "refusal").map((e) => (e.content as { denial_reason: string }).denial_reason)).toEqual([
        "token_invalid",
      ]);
      expect(x.decided).toHaveLength(0);
    } finally {
      await x.close();
    }
  });

  it("authorizes only the invocation it was verified for: another tool or other arguments with the same facts are refused at intake", async () => {
    const { view, root } = await mint([entry(INV1, { resource_contract: V1 })]);
    const x = await build(view, RETAINED);
    try {
      const facts = await x.server.validateAatPresentation(
        await presentation([root], INVOICE_TOOL, invoiceArgs("inv-1")),
        "get_invoice",
        invoiceArgs("inv-1"),
      );
      const otherArgs = await x.server.callReadTool("get_invoice", { invoice_id: "inv-2" }, facts, undefined, {
        invocation: { argumentsJson: invoiceArgs("inv-2") },
      });
      expect(otherArgs).toMatchObject({ ok: false, refusal_reason: "out_of_authority" });
      const otherTool = await x.server.callReadTool("check_transfer", { invoice_id: "inv-1" }, facts, undefined, {
        invocation: { argumentsJson: invoiceArgs("inv-1") },
      });
      expect(otherTool).toMatchObject({ ok: false, refusal_reason: "out_of_authority" });
      expect(x.decided).toHaveLength(0);
      // Control: the verified invocation itself proceeds.
      const verified = await x.server.callReadTool("get_invoice", { invoice_id: "inv-1" }, facts, undefined, {
        invocation: { argumentsJson: invoiceArgs("inv-1") },
      });
      expect(verified.ok, JSON.stringify(verified)).toBe(true);
    } finally {
      await x.close();
    }
  });
});

describe("the leaf's resource_contract is enforced at execution (@spec attenuation#mission-binding-check, runtime#resource-contract, #1756, D932 ruling 6)", () => {
  it("refuses before any decision a leaf with no contract where the resource requires one, and executes the same operation under the required contract", async () => {
    const absent = await mint([entry(CANONICAL_RESOURCE, { constraints: { vendors: ["acme"] } })]);
    const x = await build(absent.view, REQUIRED);
    try {
      const facts = await x.server.validateAatPresentation(
        await presentation([absent.root], SERVICE_TOOL, invoiceArgs("inv-1")),
        "get_invoice",
        invoiceArgs("inv-1"),
      );
      const res = await x.server.callReadTool("get_invoice", { invoice_id: "inv-1" }, facts, undefined, {
        invocation: { argumentsJson: invoiceArgs("inv-1") },
      });
      expect(res).toMatchObject({ ok: false, refusal_reason: "resource_contract_unresolvable" });
      expect(x.decided).toHaveLength(0);
      expect(x.records().filter((e) => e.kind === "refusal").map((e) => (e.content as { denial_reason: string }).denial_reason)).toEqual([
        "resource_contract_unresolvable",
      ]);
    } finally {
      await x.close();
    }
    const pinned = await mint([entry(CANONICAL_RESOURCE, { constraints: { vendors: ["acme"] }, resource_contract: V1_LIVE })], REQUIRED);
    const y = await build(pinned.view, REQUIRED);
    try {
      const facts = await y.server.validateAatPresentation(
        await presentation([pinned.root], SERVICE_TOOL, invoiceArgs("inv-1")),
        "get_invoice",
        invoiceArgs("inv-1"),
      );
      const res = await y.server.callReadTool("get_invoice", { invoice_id: "inv-1" }, facts, undefined, {
        invocation: { argumentsJson: invoiceArgs("inv-1") },
      });
      expect(res.ok, JSON.stringify(res)).toBe(true);
      expect(y.decided[0]?.resource.properties.resource_contract).toEqual(V1_LIVE);
    } finally {
      await y.close();
    }
  });

  it("refuses a leaf whose contract the resource does not declare, before any decision", async () => {
    const { view, root } = await mint([entry(INV1, { resource_contract: V1 })]);
    const x = await build(view, V2_ONLY);
    try {
      await expect(
        x.server.validateAatPresentation(await presentation([root], INVOICE_TOOL, invoiceArgs("inv-1")), "get_invoice", invoiceArgs("inv-1")),
      ).rejects.toThrow(AatPresentationRefused);
      expect(x.decided).toHaveLength(0);
    } finally {
      await x.close();
    }
  });

  it("suppresses the effect when the leaf's contract is withdrawn between the decision and the release", async () => {
    const { view, root } = await mint([entry(INV1, { resource_contract: V1 })]);
    const x = await build(view, RETAINED);
    try {
      const facts = await x.server.validateAatPresentation(
        await presentation([root], INVOICE_TOOL, invoiceArgs("inv-1")),
        "get_invoice",
        invoiceArgs("inv-1"),
      );
      const res = await x.server.callReadTool(
        "get_invoice",
        { invoice_id: "inv-1" },
        facts,
        () => x.setPepContracts(V2_ONLY),
        { invocation: { argumentsJson: invoiceArgs("inv-1") } },
      );
      expect(res).toMatchObject({ ok: false, refusal_reason: "resource_contract_unresolvable" });
      expect(res.result).toBeUndefined();
      expect(x.decided).toHaveLength(1);
      expect(x.records().filter((e) => e.kind === "execution").map((e) => e.content)).toEqual([
        expect.objectContaining({ outcome: "suppressed", error: "resource_contract_unresolvable" }),
      ]);
    } finally {
      await x.close();
    }
  });
});

