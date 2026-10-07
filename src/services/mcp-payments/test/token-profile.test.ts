/**
 * @spec runtime-oauth#token-validation, runtime#input-authority (#825)
 *
 * The Mission access-token profile this resource enforces before any token
 * value becomes a decision input, and the credential authority bound the PEP
 * applies on the target it resolved. FGA-independent: the decision function
 * here only records that it was asked, so "reached the PDP" and "refused
 * before it" are told apart without a live PDP.
 */

import { randomUUID } from "node:crypto";
import type { Fga, MissionView } from "@mission/pdp";
import { calculateJwkThumbprint, exportJWK, generateKeyPair, SignJWT } from "jose";
import { beforeAll, describe, expect, it } from "vitest";
import {
  CANONICAL_RESOURCE,
  createEphemeralEvidenceKeys,
  type DpopKeys,
  dpopProofFor,
  EvidenceStore,
  McpPaymentsServer,
  openEphemeralWriteReservationStore,
  PaymentsStore,
  Pep,
  type TokenFacts,
} from "../src/index.js";

const ISSUER = "https://as.test";
const HTU = CANONICAL_RESOURCE;
const HTM = "POST";
const MISSION = { id: "msn_825", issuer: ISSUER };
const EVIDENCE_KEYS = createEphemeralEvidenceKeys();

const entry = (actions: string[], constraints?: Record<string, unknown>) => ({
  type: "mission_resource_access",
  resource: CANONICAL_RESOURCE,
  actions,
  ...(constraints ? { constraints } : {}),
});
const BROAD = [entry(["payments:invoice.read", "payments:vendor.read", "payments:invoice.list"])];

const VIEW: MissionView = {
  id: MISSION.id,
  issuer: ISSUER,
  state: "active",
  version: 1,
  authority_hash: "sha-256:m825",
  subject: { iss: ISSUER, sub: "alice" },
  client_id: "ap-agent",
  authority_set: [
    {
      type: "mission_resource_access",
      resource: CANONICAL_RESOURCE,
      actions: ["payments:invoice.read", "payments:vendor.read", "payments:invoice.list"],
      constraints: { vendors: ["acme", "globex"] },
    },
  ],
};

let signKey: CryptoKey;
let rootSignKey: CryptoKey;
let asJwk: Record<string, unknown>;
let holder: DpopKeys;
let holderJkt: string;
let server: McpPaymentsServer;

/** A signed Mission access token; `header`/`claims` override the conforming defaults, `undefined` removes a claim. */
async function mint(
  claims: Record<string, unknown> = {},
  header: Record<string, unknown> = {},
  key: CryptoKey = signKey,
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const payload: Record<string, unknown> = {
    iss: ISSUER,
    aud: CANONICAL_RESOURCE,
    sub: "alice",
    client_id: "ap-agent",
    jti: randomUUID(),
    iat: now,
    exp: now + 300,
    cnf: { jkt: holderJkt },
    mission: MISSION,
    authorization_details: BROAD,
    ...claims,
  };
  for (const [k, v] of Object.entries(payload)) if (v === undefined) delete payload[k];
  const protectedHeader: Record<string, unknown> = { alg: "ES256", kid: "as-token", typ: "at+jwt", ...header };
  for (const [k, v] of Object.entries(protectedHeader)) if (v === undefined) delete protectedHeader[k];
  return new SignJWT(payload).setProtectedHeader(protectedHeader as never).sign(key);
}

async function overHttp(token: string): Promise<TokenFacts> {
  return server.validateToken(token, await dpopProofFor(holder, HTU, HTM, token), HTU, HTM);
}

function payments(): PaymentsStore {
  const store = new PaymentsStore();
  store.seed(
    [
      { id: "acme", name: "Acme", status: "approved" },
      { id: "globex", name: "Globex", status: "approved" },
    ],
    [
      { id: "inv-1", vendor_id: "acme", amount: "125.00", currency: "USD", payee_account: "acct", status: "payable" },
      { id: "inv-2", vendor_id: "globex", amount: "80.00", currency: "USD", payee_account: "acct", status: "payable" },
    ],
  );
  return store;
}

/** A PEP whose decision function records each request it is asked, and declines to decide. */
function pepRecording(extra: { requiresActionApproval?: (action: string, actionClass: string | undefined) => boolean } = {}) {
  const decided: unknown[] = [];
  const evidence = new EvidenceStore(EVIDENCE_KEYS.signing, EVIDENCE_KEYS.resolver);
  const pep = new Pep({
    decide: async (req) => {
      decided.push(req);
      throw new Error("the PDP is not under test here");
    },
    payments: payments(),
    evidence,
    fga: {} as unknown as Fga,
    modelId: "m",
    loadView: (ref) =>
      ref.id === VIEW.id && ref.issuer === VIEW.issuer
        ? { view: VIEW, observation: { state: VIEW.state, version: VIEW.version, mode: "fresh", freshness_at: new Date().toISOString() } }
        : undefined,
    instanceEpoch: "epoch-825",
    allowedFreshnessSources: new Set(["load_view"]),
    ...extra,
  });
  return { pep, decided, evidence };
}

beforeAll(async () => {
  const kp = await generateKeyPair("ES256", { extractable: true });
  signKey = kp.privateKey;
  asJwk = { ...(await exportJWK(kp.publicKey)), kid: "as-token", alg: "ES256" };
  const root = await generateKeyPair("ES256", { extractable: true });
  rootSignKey = root.privateKey;
  const rootJwk = { ...(await exportJWK(root.publicKey)), kid: "as-attenuation", alg: "ES256" };
  holder = await generateKeyPair("ES256", { extractable: true });
  holderJkt = await calculateJwkThumbprint(await exportJWK(holder.publicKey));
  server = new McpPaymentsServer({
    writeReservations: openEphemeralWriteReservationStore({ owner: "mcp-payments-pep" }),
    pep: undefined as never, // token validation alone never reaches the PEP
    payments: new PaymentsStore(),
    loadView: () => undefined,
    jwks: { keys: [asJwk as never, rootJwk as never] },
    keyRoles: { accessToken: ["as-token"], attenuationRoot: ["as-attenuation"], transactionToken: [] },
    issuer: ISSUER,
  });
});

describe("the Mission access-token profile is met before any claim is trusted (@spec runtime-oauth#token-validation, #825)", () => {
  it("admits a conforming at+jwt over HTTP and the mediated channel, carrying its own authority", async () => {
    const token = await mint();
    for (const facts of [await overHttp(token), await server.validateMissionToken(token)]) {
      expect(facts).toMatchObject({ sub: "alice", clientId: "ap-agent", cnfJkt: holderJkt, mission: MISSION });
      expect(facts.mission !== undefined && facts.credentialAuthority).toEqual(BROAD);
    }
  });

  const now = () => Math.floor(Date.now() / 1000);
  it.each([
    ["no typ", {}, { typ: undefined }],
    ["typ JWT", {}, { typ: "JWT" }],
    ["typ mission-status+jwt", {}, { typ: "mission-status+jwt" }],
    ["typ aat+jwt", {}, { typ: "aat+jwt" }],
    ["no exp", { exp: undefined }, {}],
    ["a string exp", { exp: String(now() + 300) }, {}],
    ["no iat", { iat: undefined }, {}],
    ["an iat in the future", { iat: now() + 3600, exp: now() + 7200 }, {}],
    ["an nbf in the future", { nbf: now() + 3600 }, {}],
    ["an expired exp", { iat: now() - 600, exp: now() - 10 }, {}],
    ["no jti", { jti: undefined }, {}],
    ["an empty jti", { jti: "" }, {}],
    ["no sub", { sub: undefined }, {}],
    ["no client_id", { client_id: undefined }, {}],
    ["a numeric client_id", { client_id: 7 }, {}],
    ["no cnf", { cnf: undefined }, {}],
    ["an empty cnf.jkt", { cnf: { jkt: "" } }, {}],
    ["no mission claim", { mission: undefined }, {}],
    ["a mission claim with an empty id", { mission: { id: "", issuer: ISSUER } }, {}],
    ["no authorization_details", { authorization_details: undefined }, {}],
    ["an unknown authority type", { authorization_details: [{ type: "other", resource: CANONICAL_RESOURCE, actions: ["x"] }] }, {}],
    ["an unknown constraint", { authorization_details: [entry(["payments:invoice.read"], { time_window: "9-5" })] }, {}],
    ["a malformed amount cap", { authorization_details: [entry(["payments:invoice.read"], { max_amount: { amount: "ten", currency: "USD" } })] }, {}],
  ])("refuses a token with %s on both transports, yielding no facts", async (_label, claims, header) => {
    const token = await mint(claims, header);
    // A proof that would verify for this token: the refusal is the profile's.
    await expect(overHttp(token)).rejects.toThrow();
    await expect(server.validateMissionToken(token)).rejects.toThrow();
  });

  it("refuses a transaction token and an attenuation root presented as a Mission access token", async () => {
    await expect(overHttp(await mint({}, { typ: "mission-txn-token+jwt" }))).rejects.toThrow(/transaction token/);
    await expect(overHttp(await mint({}, { typ: "aat+jwt" }))).rejects.toThrow(/typ must be at\+jwt/);
  });

  it("refuses an at+jwt presented as an attenuation root", async () => {
    // Signed under the root role's key, so the profile's type check is what refuses it.
    const token = await mint({}, { kid: "as-attenuation" }, rootSignKey);
    await expect(
      server.validateAttenuationChain([token], await dpopProofFor(holder, HTU, HTM, token), HTU, HTM),
    ).rejects.toThrow(/typ must be aat\+jwt/);
  });

  it("never demotes a Mission-bound token that fails its profile to the ordinary class on a gateway route", async () => {
    const token = await mint({}, { typ: undefined });
    const pop = { proof: await dpopProofFor(holder, HTU, HTM, token), htu: HTU, htm: HTM };
    await expect(server.validateGatewayCredential(token, pop, true)).rejects.toThrow(/typ must be at\+jwt/);
  });
});

describe("the credential authority bounds the action the PEP resolved (@spec runtime#input-authority, #825)", () => {
  /** Enforce `tool` under a token carrying `details`, validated over HTTP. */
  async function attempt(details: unknown[], tool: string, args: Record<string, unknown>) {
    const x = pepRecording();
    const facts = await overHttp(await mint({ authorization_details: details }));
    const result = await x.pep.enforce(tool, args, facts);
    return { ...x, result };
  }
  /** Refused at the credential bound: no PDP request, one Refusal Record naming the resolved target. */
  function refusedBeforePdp(x: Awaited<ReturnType<typeof attempt>>, resource: { type: string; id: string }) {
    expect(x.result).toMatchObject({ permitted: false, denial_reason: "out_of_authority" });
    expect(x.decided).toHaveLength(0);
    const refusal = x.evidence.all().find((e) => e.kind === "refusal");
    expect(refusal?.content).toMatchObject({ denial_reason: "credential_authority_insufficient", resource });
  }

  it("refuses vendor lookup under an invoice-only token, and lets a broad token reach the PDP, on the same broad Mission", async () => {
    refusedBeforePdp(await attempt([entry(["payments:invoice.read"])], "lookup_vendor", { vendor_id: "acme" }), {
      type: "server",
      id: CANONICAL_RESOURCE,
    });
    expect((await attempt(BROAD, "lookup_vendor", { vendor_id: "acme" })).decided).toHaveLength(1);
  });

  it("narrows by vendor independently of the Mission", async () => {
    refusedBeforePdp(await attempt([entry(["payments:invoice.read"], { vendors: ["globex"] })], "get_invoice", { invoice_id: "inv-1" }), {
      type: "invoice",
      id: "inv-1",
    });
    expect((await attempt([entry(["payments:invoice.read"], { vendors: ["acme"] })], "get_invoice", { invoice_id: "inv-1" })).decided).toHaveLength(1);
  });

  it("narrows by amount as an exact decimal, and a cap in another currency is not comparable", async () => {
    const cap = (amount: string, currency: string) => [entry(["payments:invoice.read"], { max_amount: { amount, currency } })];
    refusedBeforePdp(await attempt(cap("100.00", "USD"), "get_invoice", { invoice_id: "inv-1" }), { type: "invoice", id: "inv-1" });
    refusedBeforePdp(await attempt(cap("500.00", "EUR"), "get_invoice", { invoice_id: "inv-1" }), { type: "invoice", id: "inv-1" });
    expect((await attempt(cap("125.00", "USD"), "get_invoice", { invoice_id: "inv-1" })).decided).toHaveLength(1);
  });

  it("refuses an action that only a union of two entries would permit", async () => {
    const split = [entry(["payments:invoice.read"], { vendors: ["globex"] }), entry(["payments:vendor.read"], { vendors: ["acme"] })];
    refusedBeforePdp(await attempt(split, "get_invoice", { invoice_id: "inv-1" }), { type: "invoice", id: "inv-1" });
  });

  it("checks every vendor of a collection read, not a representative one", async () => {
    // The Mission scopes the bulk read to acme and globex; a credential that
    // covers only acme does not cover the read.
    refusedBeforePdp(await attempt([entry(["payments:invoice.list"], { vendors: ["acme"] })], "list_invoices", {}), {
      type: "vendor",
      id: "acme",
    });
    expect((await attempt([entry(["payments:invoice.list"], { vendors: ["acme", "globex"] })], "list_invoices", {})).decided).toHaveLength(1);
  });

  it("resolves a vendor lookup's target from store state, so a vendor-bound credential covers only its own vendors", async () => {
    // The credential also names `initech`, which this resource does not hold.
    const bound = [entry(["payments:vendor.read"], { vendors: ["acme", "initech"] })];
    expect((await attempt(bound, "lookup_vendor", { vendor_id: "acme" })).decided).toHaveLength(1);
    refusedBeforePdp(await attempt(bound, "lookup_vendor", { vendor_id: "globex" }), { type: "server", id: CANONICAL_RESOURCE });
    // The target comes from store state, never the argument: a vendor id the
    // store does not hold resolves to no vendor, which a vendor-bound
    // credential never covers, even one that lists that id.
    refusedBeforePdp(await attempt(bound, "lookup_vendor", { vendor_id: "initech" }), { type: "server", id: CANONICAL_RESOURCE });
  });

  it("honors an approval requirement only with a verified transaction credential's approval, whatever the local approval callback says", async () => {
    const facts = await overHttp(
      await mint({ authorization_details: [entry(["payments:invoice.read"], { requires_action_approval: true })] }),
    );
    // The callback would make a co-resident PDP require approval; a remote
    // PDP never receives it, so it establishes nothing at this PEP.
    const local = { requiresActionApproval: () => true };
    const now = Math.floor(Date.now() / 1000);
    const txn = { txn: "txn_825", jti: "jti_825", iatS: now, expS: now + 60, parameterDigest: "sha-256:op" };
    const approval = { id: "apr_825", approved_at: new Date().toISOString(), parameter_digest: "sha-256:op" };

    for (const [presented, approvalInput] of [
      [facts, undefined],
      [facts, approval],
      [{ ...facts, txn }, undefined],
    ] as const) {
      const x = pepRecording(local);
      const result = await x.pep.enforce("get_invoice", { invoice_id: "inv-1" }, presented as TokenFacts, approvalInput);
      expect(result).toMatchObject({ permitted: false, denial_reason: "out_of_authority" });
      expect(x.decided).toHaveLength(0);
    }
    const x = pepRecording(local);
    await x.pep.enforce("get_invoice", { invoice_id: "inv-1" }, { ...facts, txn } as TokenFacts, approval);
    expect(x.decided).toHaveLength(1);
  });

  it("applies the same bound to a token validated over the mediated channel", async () => {
    const x = pepRecording();
    const facts = await server.validateMissionToken(await mint({ authorization_details: [entry(["payments:invoice.read"])] }));
    const result = await x.pep.enforce("lookup_vendor", { vendor_id: "acme" }, facts);
    expect(result).toMatchObject({ permitted: false, denial_reason: "out_of_authority" });
    expect(x.decided).toHaveLength(0);
  });

  it("never falls back to the Mission's authority when a Mission-bound credential carries none", async () => {
    const facts = await overHttp(await mint());
    for (const credentialAuthority of [[], undefined]) {
      const x = pepRecording();
      const result = await x.pep.enforce("get_invoice", { invoice_id: "inv-1" }, { ...facts, credentialAuthority } as TokenFacts);
      expect(result).toMatchObject({ permitted: false, denial_reason: "out_of_authority" });
      expect(x.decided).toHaveLength(0);
    }
  });
});
