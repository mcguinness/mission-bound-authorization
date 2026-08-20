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

import { aatToolId, type AATTools } from "@mission/core";
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
  EvidenceStore,
  McpPaymentsServer,
  PaymentsStore,
  Pep,
  sourceDigestOf,
  type TokenFacts,
} from "../src/index.js";

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

/** @spec runtime#state-freshness: a synchronous live read, freshness-stamped
 *  at this read (Finding 1); `allowedFreshnessSources` below declares "load_view" as trusted. */
const loadView = () => ({ view, freshness: { observed_at: new Date().toISOString(), source: "load_view" } });

async function dpopProof(
  htu: string,
  keys: { privateKey: CryptoKey; publicKey: CryptoKey } = delegateKeys,
): Promise<string> {
  return new SignJWT({ htu, htm: "POST" })
    .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: await exportJWK(keys.publicKey) })
    .setIssuedAt()
    .setJti(crypto.randomUUID())
    .sign(keys.privateKey);
}

beforeAll(async () => {
  asKeys = await generateKeyPair("ES256", { extractable: true });
  asPub = { ...(await exportJWK(asKeys.publicKey)), kid: "as-token", alg: "ES256" };
  holderKeys = await generateKeyPair("ES256", { extractable: true });
  delegateKeys = await generateKeyPair("ES256", { extractable: true });
  const holderJkt = await calculateJwkThumbprint(await exportJWK(holderKeys.publicKey));
  delegateJkt = await calculateJwkThumbprint(await exportJWK(delegateKeys.publicKey));

  kernel = new MissionKernel({
    issuer: AS_ISS,
    policy: POLICY as never,
    statusKey: asKeys.privateKey,
    statusKid: "as-status",
  });
  const mission = kernel.approve({
    intent: validateMissionIntent(
      JSON.stringify({
        goal: "Reconcile invoices",
        resources: [CANONICAL_RESOURCE],
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
  const derived = await deriveAttenuationRoot(kernel, asKeys.privateKey, "as-token", {
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
    pep: new Pep({
      payments: new PaymentsStore(),
      evidence: new EvidenceStore(),
      fga: {} as unknown as Fga,
      modelId: "m",
      loadView,
      instanceEpoch: "epoch-1",
      sourceDigest: "sha-256:x",
      allowedFreshnessSources: new Set(["load_view"]),
    }),
    payments: new PaymentsStore(),
    loadView,
    jwks: { keys: [asPub] },
    issuer: AS_ISS,
    serverCard: {},
  });
  facts = await server.validateAttenuationChain(chain, await dpopProof(CANONICAL_RESOURCE), CANONICAL_RESOURCE, "POST");
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
  it("derives TokenFacts whose effective authority is the leaf's narrowed tools", () => {
    expect(facts.mission.id).toBe(view.id);
    expect(facts.cnfJkt).toBe(delegateJkt);
    expect(facts.leafAuthority).toEqual([{ resource: CANONICAL_RESOURCE, actions: [READ_ACTION] }]);
  });

  it("denies an in-Mission-but-outside-leaf action out_of_authority (no OpenFGA needed)", async () => {
    const pep = new Pep({
      payments: new PaymentsStore(),
      evidence: new EvidenceStore(),
      fga: {} as unknown as Fga, // never reached: the leaf guard precedes the PDP
      modelId: "m",
      loadView,
      instanceEpoch: "epoch-1",
      sourceDigest: "sha-256:x",
      allowedFreshnessSources: new Set(["load_view"]),
    });
    const res = await pep.enforce("schedule_payment", { invoice_id: "inv-1" }, facts);
    expect(res.permitted).toBe(false);
    expect(res.denial_reason).toBe("out_of_authority");
  });
});

describe("attenuation chain: keyed verification (negatives)", () => {
  it("rejects a child not signed by the key its parent's cnf commits to", async () => {
    // Signed with the delegate key, so header jwk thumbprint != root cnf.jkt.
    const forged = await mintChildOffline(root, delegateKeys.privateKey, leafTools, { cnfJkt: delegateJkt });
    await expect(
      server.validateAttenuationChain([root, forged], await dpopProof(CANONICAL_RESOURCE), CANONICAL_RESOURCE, "POST"),
    ).rejects.toThrow(/cnf/);
  });

  it("rejects proof-of-possession under a key that is not the leaf cnf", async () => {
    await expect(
      server.validateAttenuationChain(
        chain,
        await dpopProof(CANONICAL_RESOURCE, holderKeys),
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
    const conn = await Fga.connect({ apiUrl: API_URL, presharedKey: KEY, caCertPath: CA });
    fga = conn.fga;
    modelId = conn.modelId;
  });

  it("in-leaf invoice.read is capability-monotone and PEP-permitted", async () => {
    const payments = new PaymentsStore();
    payments.seed(
      [{ id: "acme", name: "Acme", status: "approved" }],
      [{ id: "inv-1", vendor_id: "acme", amount: "125.00", currency: "USD", payee_account: "acct-acme", status: "payable" }],
    );
    const card = { name: "payments", tools: ["get_invoice"] };
    const pep = new Pep({
      payments,
      evidence: new EvidenceStore(),
      fga,
      modelId,
      loadView,
      instanceEpoch: "epoch-1",
      sourceDigest: sourceDigestOf(card),
      allowedFreshnessSources: new Set(["load_view"]),
    });
    const res = await pep.enforce("get_invoice", { invoice_id: "inv-1" }, facts);
    expect(res.permitted, JSON.stringify(res)).toBe(true);
  });
});
