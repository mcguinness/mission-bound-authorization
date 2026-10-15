/**
 * Mission-bound attenuation, minted end to end (mirrors the cross-domain mint
 * smoke test). The Mission AS mints a root over two tools (invoice.read +
 * payment.schedule <= $500) via deriveAttenuationRoot; the holder mints a
 * read-only child OFFLINE via mintChildOffline; the payments RS verifies the
 * chain (validateAttenuationChain) and the PEP enforces the LEAF authority:
 *
 *   1. an in-leaf action (invoice.read) is PEP-permitted -- OpenFGA-gated, like
 *      the M4 enforcement suite;
 *   2. an in-Mission-but-outside-leaf action (payment.schedule) DENIES
 *      out_of_authority -- the case that permits today without the leaf check;
 *      this runs always (the leaf guard precedes the PDP, so no OpenFGA).
 *
 * It also proves the §root-mapping round-trips (with the amount_usd -> USD
 * currency synthesis that isSubsetEntry's currency hard-fail depends on) and
 * is fail-closed on an unknown tool-argument name.
 */

import { createHash } from "node:crypto";
import { aatToolId, type AATTools, credentialEntriesFromAatTools } from "@mission/core";
import { calculateJwkThumbprint, exportJWK, generateKeyPair, SignJWT } from "jose";
import { beforeAll, describe, expect, it } from "vitest";
import {
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
  CANONICAL_RESOURCE,
  createEphemeralEvidenceKeys,
  EvidenceStore,
  McpPaymentsServer,
  openEphemeralWriteReservationStore,
  PaymentsStore,
  Pep,
  type TokenFacts,
} from "../src/index.js";
import { testAuthoritySourceCatalog } from "@mission/authorization-server/test-support";
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

const POLICY = {
  policy_version: "attn-policy-1",
  ceiling: [
    {
      type: "mission_resource_access",
      resource: CANONICAL_RESOURCE,
      actions: [READ_ACTION, "payments:invoice.list", SCHEDULE_ACTION],
      constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
    },
  ],
} as const;

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

let asKeys: { privateKey: CryptoKey; publicKey: CryptoKey };
let asPub: Record<string, unknown>;
let holderKeys: { privateKey: CryptoKey; publicKey: CryptoKey };
let delegateKeys: { privateKey: CryptoKey; publicKey: CryptoKey };
let delegateJkt: string;
let kernel: MissionKernel;
let view: MissionView;
let chain: string[];
let facts: TokenFacts;
let server: McpPaymentsServer;
let root: string;
let leafTools: AATTools;

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

/** RFC 9449 Section 4.2: `ath` is the base64url SHA-256 of the access token presented. */
const ath = (token: string): string => createHash("sha256").update(token).digest("base64url");

/**
 * A DPoP proof for presenting `leaf`, bound to it by `ath` (#825). `omit` and
 * `override` build the malformed proofs the negative cases present.
 */
async function dpopProof(
  htu: string,
  leaf: string,
  keys: { privateKey: CryptoKey; publicKey: CryptoKey } = delegateKeys,
  opts: { omit?: ("ath" | "iat" | "jti")[]; iat?: number } = {},
): Promise<string> {
  const omit = new Set(opts.omit ?? []);
  const claims: Record<string, unknown> = { htu, htm: "POST" };
  if (!omit.has("ath")) claims.ath = ath(leaf);
  if (!omit.has("iat")) claims.iat = opts.iat ?? Math.floor(Date.now() / 1000);
  if (!omit.has("jti")) claims.jti = crypto.randomUUID();
  return new SignJWT(claims)
    .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: await exportJWK(keys.publicKey) })
    .sign(keys.privateKey);
}

beforeAll(async () => {
  asKeys = await generateKeyPair("ES256", { extractable: true });
  asPub = { ...(await exportJWK(asKeys.publicKey)), kid: "as-attenuation", alg: "ES256" };
  holderKeys = await generateKeyPair("ES256", { extractable: true });
  delegateKeys = await generateKeyPair("ES256", { extractable: true });
  const holderJkt = await calculateJwkThumbprint(await exportJWK(holderKeys.publicKey));
  delegateJkt = await calculateJwkThumbprint(await exportJWK(delegateKeys.publicKey));

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
    proposedAuthority: POLICY.ceiling as never,
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

  // Root over both tools; child narrows to invoice.read only (keeping the
  // read tool's constraints so it stays capability-monotone).
  const derived = await deriveAttenuationRoot(kernel, asKeys.privateKey, "as-attenuation", {
    missionId: mission.id,
    aud: CANONICAL_RESOURCE,
    clientId: "ap-agent",
    cnfJkt: holderJkt,
    delMaxDepth: 2,
  });
  root = derived.root;
  leafTools = { [READ_TOOL_ID]: derived.tools[READ_TOOL_ID] };
  const child = await mintChildOffline(root, holderKeys.privateKey, leafTools, { cnfJkt: delegateJkt });
  chain = [root, child];

  server = new McpPaymentsServer({
    writeReservations: openEphemeralWriteReservationStore({ owner: "mcp-payments-pep" }),
    pep: new Pep({
      decide: EVIDENCE_KEYS.decide,
      payments: new PaymentsStore(),
      evidence: new EvidenceStore(EVIDENCE_KEYS.signing, EVIDENCE_KEYS.resolver),
      fga: {} as unknown as Fga,
      modelId: "m",
      loadView,
      instanceEpoch: "epoch-1",
    }),
    payments: new PaymentsStore(),
    loadView,
    jwks: { keys: [asPub] },
    keyRoles: { accessToken: [], attenuationRoot: ["as-attenuation"], transactionToken: [] },
    issuer: AS_ISS,
  });
  facts = await server.validateAttenuationChain(chain, await dpopProof(CANONICAL_RESOURCE, child), CANONICAL_RESOURCE, "POST");
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

describe("attenuation chain: verify + leaf enforcement", () => {
  it("derives TokenFacts whose credential authority is the leaf's tools with every restriction they carry", () => {
    expect(facts.mission.id).toBe(view.id);
    expect(facts.cnfJkt).toBe(delegateJkt);
    // @spec runtime#input-authority (#825): the leaf's vendor and amount
    // bounds ride along, not just its resource and action.
    expect(facts.mission !== undefined && facts.credentialAuthority).toEqual(credentialEntriesFromAatTools(leafTools));
    expect(facts.mission !== undefined && facts.credentialAuthority).toEqual([
      {
        type: "mission_resource_access",
        resource: CANONICAL_RESOURCE,
        actions: [READ_ACTION],
        constraints: { vendors: ["acme"], max_amount: { amount: "500", currency: "USD" } },
      },
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

/** A store with Acme invoices of 50 and 125 USD, so the credential check is reached. */
function seededPayments(): PaymentsStore {
  const payments = new PaymentsStore();
  payments.seed(
    [{ id: "acme", name: "Acme", status: "approved" }],
    [
      { id: "inv-1", vendor_id: "acme", amount: "125.00", currency: "USD", payee_account: "acct", status: "payable" },
      { id: "inv-small", vendor_id: "acme", amount: "50.00", currency: "USD", payee_account: "acct", status: "payable" },
    ],
  );
  return payments;
}

describe("attenuation chain: the leaf's restrictions bound the action (@spec runtime#input-authority, #825)", () => {
  it("refuses an invoice above the leaf's narrowed amount bound before any PDP call, and admits one within it", async () => {
    // The child narrows the read tool's amount bound from 500 to 100 USD
    // (a capability-monotone narrowing), so the 125 USD invoice is outside
    // the credential even though the Mission allows it.
    const narrowedTools: AATTools = {
      [READ_TOOL_ID]: { ...(leafTools[READ_TOOL_ID] ?? {}), amount_usd: { constraint_type: "range", max: 100 } },
    };
    const holderChild = await mintChildOffline(root, holderKeys.privateKey, narrowedTools, { cnfJkt: delegateJkt });
    const narrowed = await server.validateAttenuationChain(
      [root, holderChild],
      await dpopProof(CANONICAL_RESOURCE, holderChild),
      CANONICAL_RESOURCE,
      "POST",
    );
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
    const refused = await pep.enforce("get_invoice", { invoice_id: "inv-1" }, narrowed);
    expect(refused).toMatchObject({ permitted: false, denial_reason: "out_of_authority" });
    expect(decided).toHaveLength(0);
    const refusal = evidence.all().find((e) => e.kind === "refusal");
    expect(refusal?.content).toMatchObject({ denial_reason: "credential_authority_insufficient", resource: { type: "invoice", id: "inv-1" } });

    await pep.enforce("get_invoice", { invoice_id: "inv-small" }, narrowed);
    expect(decided).toHaveLength(1);
  });
});

describe("attenuation chain: proof of possession binds the leaf, fresh and once (@spec runtime-oauth#token-validation, #825)", () => {
  it("accepts a proof bound to the leaf, and refuses the same proof presented again", async () => {
    const proof = await dpopProof(CANONICAL_RESOURCE, chain[1] as string);
    await expect(server.validateAttenuationChain(chain, proof, CANONICAL_RESOURCE, "POST")).resolves.toMatchObject({ cnfJkt: delegateJkt });
    await expect(server.validateAttenuationChain(chain, proof, CANONICAL_RESOURCE, "POST")).rejects.toThrow(/replayed/);
  });

  it.each([
    ["no ath", { omit: ["ath"] as ("ath" | "iat" | "jti")[] }, /no ath/],
    ["no iat", { omit: ["iat"] as ("ath" | "iat" | "jti")[] }, /no iat/],
    ["a stale iat", { iat: Math.floor(Date.now() / 1000) - 3600 }, /acceptance window/],
    ["no jti", { omit: ["jti"] as ("ath" | "iat" | "jti")[] }, /jti/],
  ])("refuses a proof with %s", async (_label, opts, error) => {
    const proof = await dpopProof(CANONICAL_RESOURCE, chain[1] as string, delegateKeys, opts);
    await expect(server.validateAttenuationChain(chain, proof, CANONICAL_RESOURCE, "POST")).rejects.toThrow(error);
  });

  it("refuses a proof whose ath hashes the root rather than the leaf", async () => {
    const proof = await dpopProof(CANONICAL_RESOURCE, root);
    await expect(server.validateAttenuationChain(chain, proof, CANONICAL_RESOURCE, "POST")).rejects.toThrow(/ath/);
  });
});

describe("attenuation chain: keyed verification (negatives)", () => {
  it("rejects a child not signed by the key its parent's cnf commits to", async () => {
    // Signed with the delegate key, so header jwk thumbprint != root cnf.jkt.
    const forged = await mintChildOffline(root, delegateKeys.privateKey, leafTools, { cnfJkt: delegateJkt });
    await expect(
      server.validateAttenuationChain([root, forged], await dpopProof(CANONICAL_RESOURCE, forged), CANONICAL_RESOURCE, "POST"),
    ).rejects.toThrow(/cnf/);
  });

  it("rejects proof-of-possession under a key that is not the leaf cnf", async () => {
    await expect(
      server.validateAttenuationChain(
        chain,
        await dpopProof(CANONICAL_RESOURCE, chain[1] as string, holderKeys),
        CANONICAL_RESOURCE,
        "POST",
      ),
    ).rejects.toThrow(/cnf/);
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
