/**
 * Mission-bound attenuation, minted end to end on the -02 substrate wire
 * (#1756 slice B3, D882, D902, D904). The Mission AS mints a root over the
 * payments tools its Authority Set maps to (invoice.read and
 * payment.schedule, each with the entry's USD 500 cap and vendor bound as
 * its `mission_constraints`) via deriveAttenuationRoot and the payments
 * resource's declaration of its operations; the holder mints a read-only
 * child OFFLINE via mintChildOffline, bound to an Ed25519 delegate; the
 * delegate presents the chain with a PoP JWT for one invocation, and the
 * payments RS verifies it (validateAatPresentation: the substrate, then the
 * Mission layer) and the PEP enforces the LEAF authority:
 *
 *   1. an in-leaf action (invoice.read) is PEP-permitted -- OpenFGA-gated, like
 *      the M4 enforcement suite;
 *   2. an in-Mission-but-outside-leaf action (payment.schedule) DENIES
 *      out_of_authority; this runs always (the leaf guard precedes the PDP,
 *      so no OpenFGA).
 *
 * It also proves the cross-organization wire's §root-mapping round trip
 * (with the amount_usd -> USD currency synthesis that isSubsetEntry's
 * currency hard-fail depends on), which #1759 moves to -02.
 */

import { randomUUID } from "node:crypto";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { aatSha256B64url, aatToolId, aatUuidV7, newDpopProofReplay } from "@mission/core";
import { decodeJwt, decodeProtectedHeader, exportJWK, generateKeyPair, type JWK, SignJWT } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  type AttenuatedAuthority,
  deriveAttenuationRoot,
  isSubsetEntry,
  mapAuthorityToTools,
  mapToolsToAuthority,
  MissionKernel,
  mintChildOffline,
  validateMissionIntent,
} from "@mission/authorization-server";
import { Fga, type MissionView } from "@mission/pdp";
import {
  AAT_PRESENTATION_META_KEY,
  type AatPresentation,
  AatPresentationRefused,
  aatKeyThumbprint,
  callToolWithPresentation,
  CANONICAL_RESOURCE,
  createEphemeralEvidenceKeys,
  createHttpMcpChannel,
  createMcpChannel,
  createMediatedClient,
  EvidenceStore,
  type HttpMcpChannel,
  McpPaymentsServer,
  MISSION_TOKEN_META_KEY,
  openEphemeralWriteReservationStore,
  paymentsAatToolId,
  paymentsAttenuationOperations,
  PaymentsStore,
  Pep,
  type PepDeps,
  signAatPop,
  type TokenFacts,
} from "../src/index.js";
import { testAuthoritySourceCatalog } from "@mission/authorization-server/test-support";
import { currentContractRef, pinnedToCurrentContract } from "@mission/demo-data";
import { RESOURCE_POLICY_PERMITS_ALL_FIXTURE } from "@mission/pdp/test-support";

/** Fail-closed EvidenceStore (issue #649): every `evidence:` fixture below needs a signer. */
// @spec runtime-evidence#decision-evidence-object (#741): one bundle per test
// module. `signing`/`resolver` wire the PEP's store; `decide` is the decision
// point's entry point, which closes over the PDP's emission path.
const EVIDENCE_KEYS = createEphemeralEvidenceKeys({ resourcePolicy: RESOURCE_POLICY_PERMITS_ALL_FIXTURE });

const AS_ISS = "https://as.test";
const READ_ACTION = "payments:invoice.read";
const SCHEDULE_ACTION = "payments:payment.schedule";
const READ_TOOL_ID = aatToolId(CANONICAL_RESOURCE, READ_ACTION);
const SCHEDULE_TOOL_ID = aatToolId(CANONICAL_RESOURCE, SCHEDULE_ACTION);
const CAP = { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] };

const POLICY = {
  policy_version: "attn-policy-1",
  ceiling: [
    {
      type: "mission_resource_access",
      resource: CANONICAL_RESOURCE,
      actions: [READ_ACTION, "payments:invoice.list", SCHEDULE_ACTION],
      constraints: CAP,
    },
  ],
} as const;
/** The reference a fresh approval of the ceiling records (#249), carried into each tool's mission_constraints. */
const CONTRACT = currentContractRef(POLICY.ceiling[0]);

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
if (!up) console.warn("OpenFGA unreachable; skipping the attenuation PEP-permit case");

type Keys = { privateKey: CryptoKey; publicKey: CryptoKey };
let asKeys: Keys;
let asPub: Record<string, unknown>;
let holderKeys: Keys;
let delegateKeys: Keys;
let delegateJwk: JWK;
let kernel: MissionKernel;
let view: MissionView;
let chain: string[];
let facts: TokenFacts;
let server: McpPaymentsServer;
let serverEvidence: EvidenceStore;
let root: string;
let rootAuthority: AttenuatedAuthority;
let leafAuthority: AttenuatedAuthority;

/**
 * @spec runtime#state-freshness: a synchronous live read, freshness-stamped
 * at this read (Finding 1), supplied as `context.mission_state_observation`
 * under the published `pep` placement. Implements the canonical (issuer, id) tuple
 * contract (@spec authority-server#reference-tuple, #685 review).
 */
const loadView = (ref: { id: string; issuer: string }) =>
  ref.id === view.id && ref.issuer === view.issuer
    ? { view, observation: { state: view.state, version: view.version, mode: "fresh", freshness_at: new Date().toISOString() } }
    : undefined;

/** A store with Acme invoices of 50 and 125 USD, so the credential check is reached. */
function seededPayments(): PaymentsStore {
  const payments = new PaymentsStore();
  payments.seed(
    [
      { id: "acme", name: "Acme", status: "approved" },
      { id: "globex", name: "Globex", status: "approved" },
    ],
    [
      { id: "inv-1", vendor_id: "acme", amount: "125.00", currency: "USD", payee_account: "acct", status: "payable" },
      { id: "inv-small", vendor_id: "acme", amount: "50.00", currency: "USD", payee_account: "acct", status: "payable" },
    ],
  );
  return payments;
}

/** A payments server over `payments` whose PEP's evidence is `evidence`; `pep` overrides PEP dependencies. */
function serverOver(
  payments: PaymentsStore,
  evidence: EvidenceStore,
  pep: Partial<PepDeps> = {},
  over: Partial<ConstructorParameters<typeof McpPaymentsServer>[0]> = {},
): McpPaymentsServer {
  return new McpPaymentsServer({
    writeReservations: openEphemeralWriteReservationStore({ owner: "mcp-payments-pep" }),
    pep: new Pep({
      decide: EVIDENCE_KEYS.decide,
      payments,
      evidence,
      fga: { checkWithContext: async () => true } as unknown as Fga,
      modelId: "m",
      loadView,
      instanceEpoch: "epoch-1",
      ...pep,
    }),
    payments,
    loadView,
    jwks: { keys: [asPub] },
    keyRoles: { accessToken: [], attenuationRoot: ["as-attenuation"], transactionToken: [] },
    issuer: AS_ISS,
    ...over,
  });
}

/** The presentation for one invocation of `name` with `args`, its proof signed by `keys` over `signedArgs`. */
async function presentationFor(
  links: string[],
  name: string,
  args: Record<string, unknown>,
  keys: Keys = delegateKeys,
  signedArgs: Record<string, unknown> = args,
): Promise<{ presentation: AatPresentation; argumentsJson: string }> {
  const aat_pop = await signAatPop({
    leaf: links[links.length - 1] as string,
    holderKey: keys.privateKey,
    tool: paymentsAatToolId(name),
    argumentsJson: JSON.stringify(signedArgs),
  });
  return { presentation: { aat_chain: links, aat_pop }, argumentsJson: JSON.stringify(args) };
}

/** The request signals a transport hands the server path: the invocation's original arguments text. */
const invocationOf = (args: Record<string, unknown>) => ({ invocation: { argumentsJson: JSON.stringify(args) } });

/** Validate a presentation of `links` for one invocation at `s`. */
async function present(
  s: McpPaymentsServer,
  links: string[],
  name = "get_invoice",
  args: Record<string, unknown> = { invoice_id: "inv-1" },
  keys: Keys = delegateKeys,
): Promise<TokenFacts> {
  const { presentation, argumentsJson } = await presentationFor(links, name, args, keys);
  return s.validateAatPresentation(presentation, name, argumentsJson);
}

/** A PoP JWT over `leaf` whose claims are the conforming ones with `edit` applied. */
async function popWith(
  leaf: string,
  edit: (claims: Record<string, unknown>) => Record<string, unknown>,
  keys: Keys = delegateKeys,
  header: Record<string, unknown> = { alg: "Ed25519", typ: "aat-pop+jwt" },
): Promise<string> {
  const claims = {
    jti: aatUuidV7(),
    iat: Math.floor(Date.now() / 1000),
    aat_id: decodeJwt(leaf).jti,
    aat_hash: aatSha256B64url(leaf.split(".").slice(0, 2).join(".")),
    aat_tool: READ_TOOL_ID,
    hta: { invoice_id: "inv-1" },
  };
  return new SignJWT(edit(claims)).setProtectedHeader(header as never).sign(keys.privateKey);
}

/** `child` with its claims edited and re-signed by the holder: a holder controls its own key, so it can always do this. */
async function resigned(child: string, edit: (claims: Record<string, unknown>) => Record<string, unknown>): Promise<string> {
  return new SignJWT(edit(decodeJwt(child) as Record<string, unknown>))
    .setProtectedHeader(decodeProtectedHeader(child) as never)
    .sign(holderKeys.privateKey);
}

/** A leaf child of the root carrying `entry` (the edited attenuating_agent_token entry), signed by the holder. */
async function childWithEntry(edit: (entry: Record<string, unknown>) => Record<string, unknown>): Promise<string> {
  const child = await mintChildOffline(root, holderKeys.privateKey, leafAuthority, { cnfJwk: delegateJwk });
  return resigned(child, (c) => ({
    ...c,
    authorization_details: [edit({ ...((c.authorization_details as Record<string, unknown>[])[0] as Record<string, unknown>) })],
  }));
}

beforeAll(async () => {
  asKeys = await generateKeyPair("ES256", { extractable: true });
  asPub = { ...(await exportJWK(asKeys.publicKey)), kid: "as-attenuation", alg: "ES256" };
  holderKeys = await generateKeyPair("ES256", { extractable: true });
  delegateKeys = await generateKeyPair("Ed25519", { extractable: true });
  delegateJwk = await exportJWK(delegateKeys.publicKey);

  kernel = new MissionKernel({
    issuer: AS_ISS,
    policy: POLICY as never,
    authoritySourceCatalog: testAuthoritySourceCatalog(POLICY.ceiling, ["ap-agent"], ["bob"]),
    statusKey: asKeys.privateKey,
    statusKid: "as-status",
  });
  const mission = kernel.approve({
    intent: validateMissionIntent(
      JSON.stringify({
        goal: "Reconcile invoices",
        target_resources: [CANONICAL_RESOURCE],
        expires_at: "2027-01-01T00:00:00Z",
      }),
    ),
    proposedAuthority: POLICY.ceiling.map((e) => pinnedToCurrentContract(e)) as never,
    subject: { iss: AS_ISS, sub: "alice" },
    approver: { iss: AS_ISS, sub: "bob" },
    clientId: "ap-agent",
    approvalEventId: "apev-attn",
  });

  view = {
    id: mission.id,
    issuer: AS_ISS,
    state: "active",
    version: 1,
    authority_hash: mission.authority_hash,
    authority_set: mission.authority_set,
    subject: mission.subject,
    client_id: mission.client_id,
    // Containment delta, mapped from the kernel record (absent on a freshly
    // approved Mission, so this is the no-containment fast path).
    ...(mission.containment
      ? {
          containment: {
            version: mission.containment.containment_version,
            contained: mission.containment.contained,
          },
        }
      : {}),
  };

  // The root maps from the payments resource's declaration of its
  // operations; the child narrows to invoice.read only.
  const derived = await deriveAttenuationRoot(kernel, asKeys.privateKey, "as-attenuation", {
    missionId: mission.id,
    aud: CANONICAL_RESOURCE,
    clientId: "ap-agent",
    cnfJwk: await exportJWK(holderKeys.publicKey),
    operations: paymentsAttenuationOperations(),
    delMaxDepth: 2,
  });
  root = derived.root;
  rootAuthority = { tools: derived.tools, missionConstraints: derived.missionConstraints };
  leafAuthority = {
    tools: { [READ_TOOL_ID]: derived.tools[READ_TOOL_ID] as Record<string, unknown> },
    missionConstraints: { [READ_TOOL_ID]: derived.missionConstraints[READ_TOOL_ID] as never },
  };
  const child = await mintChildOffline(root, holderKeys.privateKey, leafAuthority, { cnfJwk: delegateJwk });
  chain = [root, child];

  serverEvidence = new EvidenceStore(EVIDENCE_KEYS.signing, EVIDENCE_KEYS.resolver);
  server = serverOver(new PaymentsStore(), serverEvidence, { fga: {} as unknown as Fga });
  facts = await present(server, chain);
});

describe("§root-mapping (Authority Set <-> AAT tools)", () => {
  it("round-trips an entry back to a subset of itself, synthesizing USD", () => {
    const entry = {
      type: "mission_resource_access" as const,
      resource: CANONICAL_RESOURCE,
      actions: [SCHEDULE_ACTION],
      constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
    };
    const back = mapToolsToAuthority(mapAuthorityToTools([entry]));
    expect(back).toHaveLength(1);
    expect(back[0]?.constraints?.max_amount?.currency).toBe("USD");
    expect(isSubsetEntry(back[0] as never, entry)).toBe(true);
  });

  it("is fail-closed: an unknown tool-argument name is rejected, not dropped", () => {
    const tools = { [aatToolId(CANONICAL_RESOURCE, "x")]: { bogus_arg: { constraint_type: "exact" as const, value: "y" } } };
    expect(() => mapToolsToAuthority(tools)).toThrow();
  });
});

describe("the payments declaration of its operations to the mint (@spec attenuation#root-mapping, #1756)", () => {
  it("declares each action's tools with their catalog arguments, and as established only the facts this PEP establishes from its records", () => {
    const ops = paymentsAttenuationOperations();
    const execute = ops(CANONICAL_RESOURCE, "payments:payment.execute");
    expect(execute?.map((o) => o.name)).toEqual(["check_transfer", "hold_transfer", "execute_wire_transfer"]);
    expect(execute?.[2]?.arguments).toEqual({ invoice_id: { required: true }, idempotency_key: { required: true } });
    for (const op of execute ?? []) expect(op.establishes).toEqual(["vendors", "max_amount"]);
    // A list and a vendor lookup reach vendors and no invoice amount.
    expect(ops(CANONICAL_RESOURCE, "payments:invoice.list")).toEqual([
      { name: "list_invoices", arguments: { vendor_id: { required: false } }, establishes: ["vendors"] },
    ]);
    expect(ops(CANONICAL_RESOURCE, "payments:vendor.read")?.[0]?.establishes).toEqual(["vendors"]);
    // Nothing is declared at another resource or for an action no tool performs.
    expect(ops("https://other.example/mcp", READ_ACTION)).toBeUndefined();
    expect(ops(CANONICAL_RESOURCE, "payments:invoice.delete")).toBeUndefined();
    expect(paymentsAatToolId("execute_wire_transfer")).toBe(aatToolId(CANONICAL_RESOURCE, "payments:payment.execute"));
  });
});

describe("attenuation chain: verify + leaf enforcement", () => {
  it("maps the root from the payments declaration: every argument explicit, the entry's restrictions as mission_constraints, and no tool whose facts the PEP does not establish", () => {
    // invoice.list establishes no invoice amount, so the capped entry does not map it.
    expect(rootAuthority.tools).toEqual({
      [READ_TOOL_ID]: { invoice_id: { constraint_type: "wildcard" } },
      [SCHEDULE_TOOL_ID]: { idempotency_key: { constraint_type: "wildcard" }, invoice_id: { constraint_type: "wildcard" } },
    });
    expect(rootAuthority.missionConstraints).toEqual({
      [READ_TOOL_ID]: { constraints: CAP, resource_contract: CONTRACT },
      [SCHEDULE_TOOL_ID]: { constraints: CAP, resource_contract: CONTRACT },
    });
  });

  it("derives TokenFacts whose credential authority is the leaf's tools with their mission_constraints", () => {
    expect(facts.mission?.id).toBe(view.id);
    expect(facts.cnfJkt).toBe(aatKeyThumbprint(delegateJwk as Record<string, unknown>));
    expect(facts.sub).toBe("alice");
    expect(facts.clientId).toBe("ap-agent");
    expect(facts.mission !== undefined && facts.credentialAuthority).toEqual([
      { type: "mission_resource_access", resource: CANONICAL_RESOURCE, actions: [READ_ACTION], constraints: CAP, resource_contract: CONTRACT },
    ]);
  });

  it("denies an in-Mission-but-outside-leaf action out_of_authority (no OpenFGA needed)", async () => {
    const pep = new Pep({
      decide: EVIDENCE_KEYS.decide,
      payments: seededPayments(),
      evidence: new EvidenceStore(EVIDENCE_KEYS.signing, EVIDENCE_KEYS.resolver),
      fga: {} as unknown as Fga, // never reached: the leaf guard precedes the PDP
      modelId: "m",
      loadView,
      instanceEpoch: "epoch-1",
    });
    const res = await pep.enforce("schedule_payment", { invoice_id: "inv-1" }, facts);
    expect(res.permitted).toBe(false);
    expect(res.denial_reason).toBe("out_of_authority");
  });
});

describe("attenuation chain: the leaf's restrictions bound the action (@spec runtime#input-authority, #825)", () => {
  it("refuses an invoice above the leaf's narrowed amount bound before any PDP call, and admits one within it", async () => {
    // The child narrows the read tool's mission_constraints cap from 500 to
    // 100 USD, so the 125 USD invoice is outside the credential even though
    // the Mission allows it.
    const narrowed = await mintChildOffline(
      root,
      holderKeys.privateKey,
      {
        ...leafAuthority,
        missionConstraints: {
          [READ_TOOL_ID]: { ...leafAuthority.missionConstraints[READ_TOOL_ID], constraints: { ...CAP, max_amount: { amount: "100", currency: "USD" } } },
        },
      },
      { cnfJwk: delegateJwk },
    );
    const narrowedFacts = await present(server, [root, narrowed]);
    const decided: unknown[] = [];
    const evidence = new EvidenceStore(EVIDENCE_KEYS.signing, EVIDENCE_KEYS.resolver);
    const pep = new Pep({
      decide: async (req) => {
        decided.push(req);
        throw new Error("the PDP is not under test here");
      },
      payments: seededPayments(),
      evidence,
      fga: {} as unknown as Fga,
      modelId: "m",
      loadView,
      instanceEpoch: "epoch-1",
      allowedFreshnessSources: new Set(["load_view"]),
    });
    const refused = await pep.enforce("get_invoice", { invoice_id: "inv-1" }, narrowedFacts);
    expect(refused).toMatchObject({ permitted: false, denial_reason: "out_of_authority" });
    expect(decided).toHaveLength(0);
    const refusal = evidence.all().find((e) => e.kind === "refusal");
    expect(refusal?.content).toMatchObject({ denial_reason: "credential_authority_insufficient", resource: { type: "invoice", id: "inv-1" } });

    await pep.enforce("get_invoice", { invoice_id: "inv-small" }, narrowedFacts);
    expect(decided).toHaveLength(1);
  });
});

describe("attenuation chain: proof of possession binds the leaf, fresh and once (@spec runtime-oauth#token-validation, #825)", () => {
  const scheduleArgs = () => ({ invoice_id: "inv-1", idempotency_key: `idem_${randomUUID()}` });

  it("accepts a proof bound to the leaf, and refuses the same proof presented again", async () => {
    // A side-effecting tool tracks the proof's jti (AAT -02 step 7i). The
    // root's holder presents the root for payment.schedule.
    const args = scheduleArgs();
    const { presentation, argumentsJson } = await presentationFor([root], "schedule_payment", args, holderKeys);
    await expect(server.validateAatPresentation(presentation, "schedule_payment", argumentsJson)).resolves.toMatchObject({
      cnfJkt: aatKeyThumbprint((await exportJWK(holderKeys.publicKey)) as Record<string, unknown>),
    });
    await expect(server.validateAatPresentation(presentation, "schedule_payment", argumentsJson)).rejects.toThrow(/step 7i/);
  });

  it("tracks the proof's jti for a read as well: the same get_invoice presentation is refused the second time (D932)", async () => {
    const { presentation, argumentsJson } = await presentationFor(chain, "get_invoice", { invoice_id: "inv-1" });
    await expect(server.validateAatPresentation(presentation, "get_invoice", argumentsJson)).resolves.toMatchObject({
      mission: { id: view.id },
    });
    await expect(server.validateAatPresentation(presentation, "get_invoice", argumentsJson)).rejects.toThrow(/step 7i/);
  });

  it("refuses retryably, rather than admitting, when the proof replay state is at capacity", async () => {
    const full = serverOver(new PaymentsStore(), new EvidenceStore(EVIDENCE_KEYS.signing, EVIDENCE_KEYS.resolver), {}, {
      dpopReplay: newDpopProofReplay(300, Date.now, 0),
    });
    const { presentation, argumentsJson } = await presentationFor([root], "schedule_payment", scheduleArgs(), holderKeys);
    await expect(full.validateAatPresentation(presentation, "schedule_payment", argumentsJson)).rejects.toThrow(/at capacity/);
  });

  it.each([
    ["no jti", (c: Record<string, unknown>) => ({ ...c, jti: undefined }), /step 7c/],
    ["a stale iat", (c: Record<string, unknown>) => ({ ...c, iat: Math.floor(Date.now() / 1000) - 3600 }), /step 7g/],
    ["a tool the leaf does not grant", (c: Record<string, unknown>) => ({ ...c, aat_tool: SCHEDULE_TOOL_ID }), /step 6b/],
    ["arguments other than the invocation's", (c: Record<string, unknown>) => ({ ...c, hta: { invoice_id: "inv-2" } }), /step 7f/],
    ["an audience naming another resource", (c: Record<string, unknown>) => ({ ...c, aat_aud: "https://other-rs.example" }), /step 7d/],
    ["another leaf's jti", (c: Record<string, unknown>) => ({ ...c, aat_id: aatUuidV7() }), /step 7c/],
  ])("refuses a proof with %s", async (_label, edit, error) => {
    const pop = await popWith(chain[1] as string, edit);
    await expect(
      server.validateAatPresentation({ aat_chain: chain, aat_pop: pop }, "get_invoice", JSON.stringify({ invoice_id: "inv-1" })),
    ).rejects.toThrow(error);
  });

  it("refuses a proof whose aat_hash commits to the root rather than the leaf", async () => {
    const pop = await popWith(chain[1] as string, (c) => ({ ...c, aat_hash: aatSha256B64url(root.split(".").slice(0, 2).join(".")) }));
    await expect(
      server.validateAatPresentation({ aat_chain: chain, aat_pop: pop }, "get_invoice", JSON.stringify({ invoice_id: "inv-1" })),
    ).rejects.toThrow(/aat_hash/);
  });
});

describe("attenuation chain: keyed verification (negatives)", () => {
  it("rejects a child not signed by the key its parent's cnf commits to", async () => {
    const stranger = await generateKeyPair("ES256", { extractable: true });
    const child = chain[1] as string;
    const forged = await new SignJWT(decodeJwt(child)).setProtectedHeader(decodeProtectedHeader(child) as never).sign(stranger.privateKey);
    await expect(present(server, [root, forged])).rejects.toThrow(/step 4b/);
  });

  it("rejects proof-of-possession under a key that is not the leaf cnf", async () => {
    await expect(present(server, chain, "get_invoice", { invoice_id: "inv-1" }, holderKeys)).rejects.toThrow(AatPresentationRefused);
    const otherEd = await generateKeyPair("Ed25519", { extractable: true });
    await expect(present(server, chain, "get_invoice", { invoice_id: "inv-1" }, otherEd)).rejects.toThrow(/step 7b/);
  });
});

describe("attenuation chain: the root's mission claim is accepted only from the issuer it names (@spec mission#rs-requirements, #1503)", () => {
  /** The kernel-minted root's claims with `mission.issuer` replaced, re-signed under the root key. */
  async function rootNaming(issuer: string): Promise<string> {
    const claims = decodeJwt(root) as Record<string, unknown>;
    return new SignJWT({ ...claims, mission: { ...(claims.mission as object), issuer } })
      .setProtectedHeader(decodeProtectedHeader(root) as never)
      .sign(asKeys.privateKey);
  }

  it("refuses a root signed by the trusted issuer whose mission.issuer names another issuer, and admits the same root naming its own", async () => {
    await expect(present(server, [await rootNaming(AS_ISS)], undefined, undefined, holderKeys)).resolves.toMatchObject({
      mission: { id: view.id, issuer: AS_ISS },
    });
    await expect(present(server, [await rootNaming("https://other-as.test")], undefined, undefined, holderKeys)).rejects.toThrow(
      /iss is not its mission\.issuer/,
    );
  });

  it("refuses a valid chain on an estate route, whose issuer is not trusted to issue Mission-bound authorization", async () => {
    const estate = new McpPaymentsServer({
      writeReservations: openEphemeralWriteReservationStore({ owner: "mcp-payments-pep" }),
      pep: undefined as never, // token validation alone never reaches the PEP
      payments: new PaymentsStore(),
      loadView,
      jwks: { keys: [asPub] },
      keyRoles: { accessToken: [], attenuationRoot: ["as-attenuation"], transactionToken: [] },
      issuer: AS_ISS,
      ordinaryOnly: true,
    });
    await expect(present(estate, chain)).rejects.toThrow(/not a Mission Issuer/);
    // The same chain verifies on the Mission Issuer's route.
    await expect(present(server, chain)).resolves.toMatchObject({ mission: { id: view.id } });
  });
});

describe("attenuation chain: every token's audience, and the subject from the root only (@spec attenuation#mission-binding-check, #1758)", () => {
  const OTHER_RS = "https://other-rs.example";

  /** The kernel-minted root's claims with `edit` applied, re-signed under the root key. */
  async function rootWith(edit: (claims: Record<string, unknown>) => Record<string, unknown>): Promise<string> {
    return new SignJWT(edit(decodeJwt(root) as Record<string, unknown>))
      .setProtectedHeader(decodeProtectedHeader(root) as never)
      .sign(asKeys.privateKey);
  }

  it("refuses at the consumer a child narrowed to another resource server, and accepts the same chain narrowed to this one", async () => {
    const twoAudiences = await rootWith((c) => ({ ...c, aud: [CANONICAL_RESOURCE, OTHER_RS] }));
    // The child's `aud` nests within its parent's, so only the per-token check refuses it.
    const elsewhere = await mintChildOffline(twoAudiences, holderKeys.privateKey, leafAuthority, { cnfJwk: delegateJwk, aud: OTHER_RS });
    await expect(present(server, [twoAudiences, elsewhere])).rejects.toThrow(/step 6c: token 1 aud does not identify this enforcement point/);
    const here = await mintChildOffline(twoAudiences, holderKeys.privateKey, leafAuthority, { cnfJwk: delegateJwk, aud: CANONICAL_RESOURCE });
    await expect(present(server, [twoAudiences, here])).resolves.toMatchObject({ mission: { id: view.id } });
  });

  it("mints a child with no sub or client_id", async () => {
    const child = decodeJwt(await mintChildOffline(root, holderKeys.privateKey, leafAuthority, { cnfJwk: delegateJwk }));
    expect(child.sub).toBeUndefined();
    expect(child.client_id).toBeUndefined();
  });

  it("takes the subject from the root: a forged child sub changes neither the decision subject, the recorded payment nor its evidence", async () => {
    const { sub: rootSub, client_id: rootClient } = decodeJwt(root);
    expect(typeof rootSub === "string" && rootSub !== "mallory").toBe(true);
    const forged = await resigned(await mintChildOffline(root, holderKeys.privateKey, rootAuthority, { cnfJwk: delegateJwk }), (c) => ({
      ...c,
      sub: "mallory",
      client_id: "mallory-agent",
    }));

    const payments = seededPayments();
    const evidence = new EvidenceStore(EVIDENCE_KEYS.signing, EVIDENCE_KEYS.resolver);
    const writeReservations = openEphemeralWriteReservationStore({ owner: "mcp-payments-pep" });
    const decidedSubjects: string[] = [];
    const writer = serverOver(
      payments,
      evidence,
      {
        decide: (req, opts) => {
          decidedSubjects.push(req.subject.id);
          return EVIDENCE_KEYS.decide(req, opts);
        },
        instanceEpoch: "epoch-1758",
      },
      { writeReservations },
    );

    const args = { invoice_id: "inv-1", idempotency_key: randomUUID() };
    const forgedFacts = await present(writer, [root, forged], "schedule_payment", args);
    expect(forgedFacts.sub).toBe(rootSub);
    expect(forgedFacts.clientId).toBe(rootClient);
    const scheduled = await writer.callWriteTool("schedule_payment", args, forgedFacts, undefined, invocationOf(args));
    expect(scheduled.ok, JSON.stringify(scheduled)).toBe(true);
    expect(decidedSubjects.length).toBeGreaterThan(0);
    expect(new Set(decidedSubjects)).toEqual(new Set([rootSub]));
    expect(writeReservations.schedules().map((s) => s.subject)).toEqual([rootSub]);
    expect(evidence.all().length).toBeGreaterThan(0);
    // Neither forged value reaches the recorded evidence ("mallory" covers both).
    expect(JSON.stringify(evidence.all())).not.toContain("mallory");
  });

  it("refuses a root without its subject rather than falling back to a child's sub", async () => {
    const subless = await rootWith(({ sub: _sub, ...c }) => c);
    const child = await resigned(await mintChildOffline(subless, holderKeys.privateKey, leafAuthority, { cnfJwk: delegateJwk }), (c) => ({
      ...c,
      sub: "alice",
    }));
    await expect(present(server, [subless, child])).rejects.toThrow(/sub must be a non-empty string/);
  });
});

describe("attenuation chain: the mission_constraints member at the consumer (@spec attenuation#mission-constraints, #1756, D902)", () => {
  /** The Refusal Records `run` leaves at the shared server. */
  async function refusalsOf(run: () => Promise<unknown>): Promise<Record<string, unknown>[]> {
    const before = serverEvidence.all().length;
    await run().catch(() => undefined);
    return serverEvidence
      .all()
      .slice(before)
      .filter((e) => e.kind === "refusal")
      .map((e) => e.content as unknown as Record<string, unknown>);
  }

  it("refuses a chain whose child removes mission_constraints or a tool's value, and records each refusal", async () => {
    const removed = [
      await childWithEntry(({ mission_constraints: _mc, ...entry }) => entry),
      await childWithEntry((entry) => ({ ...entry, mission_constraints: {} })),
      await childWithEntry((entry) => ({ ...entry, mission_constraints: { [READ_TOOL_ID]: {} } })),
    ];
    for (const child of removed) {
      await expect(present(server, [root, child])).rejects.toThrow(/mission_constraints/);
      const refusals = await refusalsOf(() => present(server, [root, child]));
      expect(refusals).toHaveLength(1);
      expect(refusals[0]).toMatchObject({ denial_reason: "token_invalid", action: { name: READ_ACTION }, subject: { id: "alice" } });
      expect(refusals[0]?.mission).toBeUndefined();
    }
  });

  it("refuses a child that widens mission_constraints: a raised cap, a removed vendor bound, an added vendor, or an added resource_contract", async () => {
    const widen = (constraints: Record<string, unknown>, extra: Record<string, unknown> = {}) =>
      childWithEntry((entry) => ({
        ...entry,
        mission_constraints: { [READ_TOOL_ID]: { ...leafAuthority.missionConstraints[READ_TOOL_ID], constraints, ...extra } },
      }));
    const widened = [
      await widen({ ...CAP, max_amount: { amount: "900", currency: "USD" } }),
      await widen({ max_amount: CAP.max_amount }),
      await widen({ ...CAP, vendors: ["acme", "globex"] }),
      await widen(CAP, {
        resource_contract: { id: "https://pay.example/contracts/x", version: "1", digest: "sha-256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" },
      }),
    ];
    for (const child of widened) {
      await expect(present(server, [root, child])).rejects.toThrow(/not within its parent's/);
    }
    // Control: the same re-signing with the parent's own value verifies.
    await expect(present(server, [root, await widen(CAP)])).resolves.toMatchObject({ mission: { id: view.id } });
  });

  it("refuses malformed or unsupported constraints and an unknown member key, rather than ignoring them", async () => {
    // Each keeps the parent's resource_contract, so only its own defect differs.
    const kept = leafAuthority.missionConstraints[READ_TOOL_ID];
    const refused = [
      { [READ_TOOL_ID]: { ...kept, constraints: CAP, scope: "x" } },
      { [READ_TOOL_ID]: { ...kept, constraints: { ...CAP, region: "eu" } } },
      { [READ_TOOL_ID]: { ...kept, constraints: { ...CAP, max_amount: { amount: 100, currency: "USD" } } } },
      { [READ_TOOL_ID]: { ...kept, constraints: { ...CAP, max_amount: { amount: "100", currency: "usd" } } } },
      { [READ_TOOL_ID]: { ...kept, constraints: "vendors=acme" } },
    ];
    for (const member of refused) {
      const child = await childWithEntry((entry) => ({ ...entry, mission_constraints: member }));
      await expect(present(server, [root, child]), JSON.stringify(member)).rejects.toThrow(AatPresentationRefused);
    }
  });

  it("refuses a verified chain whose root carries no mission claim as outside the profile, recording mission_claim_missing", async () => {
    const missionless = await new SignJWT((({ mission: _m, ...c }) => c)(decodeJwt(root) as Record<string, unknown>))
      .setProtectedHeader(decodeProtectedHeader(root) as never)
      .sign(asKeys.privateKey);
    const refusals = await refusalsOf(() => present(server, [missionless], undefined, undefined, holderKeys));
    await expect(present(server, [missionless], undefined, undefined, holderKeys)).rejects.toThrow(/no mission claim/);
    expect(refusals.map((r) => r.denial_reason)).toEqual(["mission_claim_missing"]);
  });

  it("refuses with no record a presentation the substrate does not permit", async () => {
    const stranger = await generateKeyPair("ES256", { extractable: true });
    const forged = await new SignJWT(decodeJwt(root)).setProtectedHeader(decodeProtectedHeader(root) as never).sign(stranger.privateKey);
    expect(await refusalsOf(() => present(server, [forged], undefined, undefined, holderKeys))).toEqual([]);
  });

  it("admits a valid substrate proof whose Mission constraints then fail against the invoice, refusing the invocation at the PEP with a Refusal Record", async () => {
    // The leaf's cap is USD 100; the 125 USD invoice is within the substrate
    // proof's tool and arguments but not within its mission_constraints.
    const capped = await mintChildOffline(
      root,
      holderKeys.privateKey,
      {
        ...leafAuthority,
        missionConstraints: {
          [READ_TOOL_ID]: { ...leafAuthority.missionConstraints[READ_TOOL_ID], constraints: { ...CAP, max_amount: { amount: "100", currency: "USD" } } },
        },
      },
      { cnfJwk: delegateJwk },
    );
    const evidence = new EvidenceStore(EVIDENCE_KEYS.signing, EVIDENCE_KEYS.resolver);
    const decided: unknown[] = [];
    const s = serverOver(seededPayments(), evidence, {
      decide: (req, opts) => {
        decided.push(req);
        return EVIDENCE_KEYS.decide(req, opts);
      },
    });
    const { client } = await createMediatedClient(s);
    try {
      const present125 = await client.callToolWithPresentation("get_invoice", { invoice_id: "inv-1" }, async (call) =>
        (await presentationFor([root, capped], call.name, JSON.parse(call.argumentsJson))).presentation,
      );
      expect(present125).toMatchObject({ ok: false, denial_reason: "out_of_authority" });
      expect(decided).toHaveLength(0);
      expect(evidence.all().find((e) => e.kind === "refusal")?.content).toMatchObject({
        denial_reason: "credential_authority_insufficient",
        resource: { type: "invoice", id: "inv-1" },
      });
      // Within the cap: the same leaf reaches the decision and is permitted.
      const present50 = await client.callToolWithPresentation("get_invoice", { invoice_id: "inv-small" }, async (call) =>
        (await presentationFor([root, capped], call.name, JSON.parse(call.argumentsJson))).presentation,
      );
      expect(present50.ok, JSON.stringify(present50)).toBe(true);
      expect(decided).toHaveLength(1);
    } finally {
      await client.close();
    }
  });

  it("refuses a write whose invoice changed after the presentation was validated, before the decision and between decision and execution", async () => {
    const payments = seededPayments();
    const writeReservations = openEphemeralWriteReservationStore({ owner: "mcp-payments-pep" });
    const s = serverOver(payments, new EvidenceStore(EVIDENCE_KEYS.signing, EVIDENCE_KEYS.resolver), {}, { writeReservations });
    // Validated against a 50 USD invoice; the amount then exceeds the root's USD 500 cap.
    const before = { invoice_id: "inv-small", idempotency_key: randomUUID() };
    const beforeFacts = await present(s, [root], "schedule_payment", before, holderKeys);
    payments.bumpInvoiceAmount("inv-small", "600.00");
    expect(await s.callWriteTool("schedule_payment", before, beforeFacts, undefined, invocationOf(before))).toMatchObject({
      ok: false,
      denial_reason: "out_of_authority",
    });
    // Decided at 125 USD; the amount changes before execution.
    const during = { invoice_id: "inv-1", idempotency_key: randomUUID() };
    const duringFacts = await present(s, [root], "schedule_payment", during, holderKeys);
    const res = await s.callWriteTool(
      "schedule_payment",
      during,
      duringFacts,
      () => payments.bumpInvoiceAmount("inv-1", "600.00"),
      invocationOf(during),
    );
    expect(res.ok).toBe(false);
    expect(res.refusal_reason).toBe("parameter_mismatch");
    expect(writeReservations.schedules()).toEqual([]);
  });
});

describe("attenuation presentation on the transports (@spec attenuation#mission-binding-check, AAT -02 Sections 7 and 8, #1756)", () => {
  let http: HttpMcpChannel;
  let httpEvidence: EvidenceStore;
  beforeAll(async () => {
    httpEvidence = new EvidenceStore(EVIDENCE_KEYS.signing, EVIDENCE_KEYS.resolver);
    http = await createHttpMcpChannel(serverOver(seededPayments(), httpEvidence));
  });
  afterAll(async () => {
    await http?.close();
  });

  /** A presentation callback whose proof covers `signed`, or the call's own arguments. */
  const presenting = (links: string[], signed?: Record<string, unknown>) => async (call: { name: string; argumentsJson: string }) =>
    (await presentationFor(links, call.name, JSON.parse(call.argumentsJson), delegateKeys, signed ?? JSON.parse(call.argumentsJson))).presentation;

  it("verifies the proof against the arguments the in-memory call carries: a matching hta is dispatched, another is refused before the PEP", async () => {
    const evidence = new EvidenceStore(EVIDENCE_KEYS.signing, EVIDENCE_KEYS.resolver);
    const { client } = await createMediatedClient(serverOver(seededPayments(), evidence));
    try {
      const ok = await client.callToolWithPresentation("get_invoice", { invoice_id: "inv-1" }, presenting(chain));
      expect(ok.ok, JSON.stringify(ok)).toBe(true);
      const recorded = evidence.all().length;
      const other = await client.callToolWithPresentation("get_invoice", { invoice_id: "inv-1" }, presenting(chain, { invoice_id: "inv-small" }));
      expect(other).toEqual({ ok: false, denial_reason: "invalid_credential" });
      expect(evidence.all()).toHaveLength(recorded);
    } finally {
      await client.close();
    }
  });

  it("verifies the proof against the arguments the HTTP body carries: a matching hta is dispatched statelessly, another is answered 401 before the PEP", async () => {
    const ok = await callToolWithPresentation(http.url, "get_invoice", { invoice_id: "inv-1" }, presenting(chain));
    expect(ok.status).toBe(200);
    expect(ok.verdict?.ok, JSON.stringify(ok.body)).toBe(true);
    const recorded = httpEvidence.all().length;
    const other = await callToolWithPresentation(http.url, "get_invoice", { invoice_id: "inv-1" }, presenting(chain, { invoice_id: "inv-small" }));
    expect(other.status).toBe(401);
    expect(other.verdict).toBeUndefined();
    expect(httpEvidence.all()).toHaveLength(recorded);
    // The arguments as written: a duplicate member is refused before authentication.
    const duplicate = await callToolWithPresentation(http.url, "get_invoice", { invoice_id: "inv-1" }, presenting(chain), {
      argumentsText: '{"invoice_id":"inv-small","invoice_id":"inv-1"}',
    });
    expect(duplicate.status).toBe(400);
  });

  it("refuses a presentation beside another credential: an in-memory token, an HTTP Authorization header or session, and inside a batch", async () => {
    // In memory: the raw MCP client, carrying both a token and a presentation.
    const { clientTransport } = await createMcpChannel(server);
    const raw = new Client({ name: "raw", version: "0" }, { capabilities: {} });
    await raw.connect(clientTransport as InMemoryTransport);
    try {
      const { presentation } = await presentationFor(chain, "get_invoice", { invoice_id: "inv-1" });
      const both = await raw.callTool({
        name: "get_invoice",
        arguments: { invoice_id: "inv-1" },
        _meta: { [MISSION_TOKEN_META_KEY]: "a.b.c", [AAT_PRESENTATION_META_KEY]: presentation },
      });
      expect(both.structuredContent).toEqual({ ok: false, denial_reason: "invalid_credential" });
    } finally {
      await raw.close();
    }
    // Over HTTP: an Authorization header, or a session id, beside a presentation.
    const withHeader = await callToolWithPresentation(http.url, "get_invoice", { invoice_id: "inv-1" }, presenting(chain), {
      headers: { authorization: "DPoP a.b.c" },
    });
    expect(withHeader.status).toBe(401);
    const onSession = await callToolWithPresentation(http.url, "get_invoice", { invoice_id: "inv-1" }, presenting(chain), {
      headers: { "mcp-session-id": randomUUID() },
    });
    expect(onSession.status).toBe(400);
    const { presentation } = await presentationFor(chain, "get_invoice", { invoice_id: "inv-1" });
    const call = (id: number) => ({
      jsonrpc: "2.0",
      id,
      method: "tools/call",
      params: { name: "get_invoice", arguments: { invoice_id: "inv-1" }, _meta: { [AAT_PRESENTATION_META_KEY]: presentation } },
    });
    const batch = await fetch(http.url, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json, text/event-stream" },
      body: JSON.stringify([call(1), call(2)]),
    });
    expect(batch.status).toBe(400);
  });
});

const d = up ? describe : describe.skip;
d("attenuation chain: PEP permits an in-leaf action (OpenFGA)", () => {
  let fga: Fga;
  let modelId: string;
  beforeAll(async () => {
    const conn = await Fga.bootstrap({ apiUrl: API_URL, presharedKey: KEY, caCertPath: CA });
    fga = conn.fga;
    modelId = conn.modelId;
  });

  it("in-leaf invoice.read is capability-monotone and PEP-permitted", async () => {
    const payments = new PaymentsStore();
    payments.seed(
      [{ id: "acme", name: "Acme", status: "approved" }],
      [{ id: "inv-1", vendor_id: "acme", amount: "125.00", currency: "USD", payee_account: "acct-acme", status: "payable" }],
    );
    const pep = new Pep({
      decide: EVIDENCE_KEYS.decide,
      payments,
      evidence: new EvidenceStore(EVIDENCE_KEYS.signing, EVIDENCE_KEYS.resolver),
      fga,
      modelId,
      loadView,
      instanceEpoch: "epoch-1",
    });
    const res = await pep.enforce("get_invoice", { invoice_id: "inv-1" }, facts);
    expect(res.permitted, JSON.stringify(res)).toBe(true);
  });
});
