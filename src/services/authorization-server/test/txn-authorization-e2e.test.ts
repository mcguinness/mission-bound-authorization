/**
 * The whole Transaction Authorization profile on one live stack: a real
 * Challenge-Issuing Resource (the payments PEP over live OpenFGA) and a real
 * Transaction Authorization Server over HTTP.
 *
 * Nothing is stubbed across the seam. The resource gates the operation, signs a
 * challenge bound to the verified token and the effective parameters, and
 * retains the pending operation; the client authenticates at the transaction
 * endpoint and redeems the challenge with the Mission-bound token as
 * `subject_token`; the approver adjudicates out of band; the fresh decision
 * runs at completion; and the resource verifies the resulting token OFFLINE
 * against the operation it retained, consuming the `txn` exactly once.
 */

import { type Server } from "node:http";
import { AccessRequestService } from "@mission/access-request";
import { CANONICAL_RESOURCE } from "@mission/demo-data";
import { Fga, type MissionView } from "@mission/pdp";
import {
  Connectors,
  createHttpMcpChannel,
  createHttpMediatedClient,
  EvidenceStore,
  type HttpMcpChannel,
  McpPaymentsServer,
  PaymentsStore,
  Pep,
  sourceDigestOf,
  TransactionEngine,
} from "@mission/mcp-payments";
import {
  calculateJwkThumbprint,
  createLocalJWKSet,
  decodeJwt,
  exportJWK,
  generateKeyPair,
  importJWK,
  type JWK,
  SignJWT,
} from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { buildAuthorizationServer, type BuiltAs, type ChallengeIssuers } from "../src/index.js";

const API_URL = process.env.OPENFGA_HTTP_URL ?? "https://localhost:8080";
const FGA_KEY = process.env.OPENFGA_PRESHARED_KEY ?? "dev-preshared-key-change-me";
const CA = process.env.OPENFGA_CA_CERT;

async function reachable(): Promise<boolean> {
  try {
    if (CA) process.env.NODE_EXTRA_CA_CERTS = CA;
    return (await fetch(`${API_URL}/healthz`, { headers: { authorization: `Bearer ${FGA_KEY}` } })).ok;
  } catch {
    return false;
  }
}
const up = await reachable();
const d = up ? describe : describe.skip;
if (!up) console.warn("OpenFGA unreachable; skipping the transaction-authorization end-to-end test");

const PORT = 14452;
const ISSUER = `http://localhost:${PORT}`;
const REDIRECT_URI = "http://localhost:9999/cb";
const RESOURCE = CANONICAL_RESOURCE;

type DpopKeys = { privateKey: CryptoKey; publicKey: CryptoKey };

let as: BuiltAs;
let asServer: Server;
let ars: AccessRequestService;
let rs: McpPaymentsServer;
const channels: HttpMcpChannel[] = [];

/**
 * A connected MCP-over-HTTP client presenting `credential` as the request's ONE
 * Authorization credential. The transport is one session per channel, so each
 * connection gets its own channel over the SAME resource server (and therefore
 * the same retained operations and consumption domain).
 */
async function connect(
  credential: string,
  extraHeaders: Record<string, string> = {},
): Promise<Awaited<ReturnType<typeof createHttpMediatedClient>>> {
  const channel = await createHttpMcpChannel(rs);
  channels.push(channel);
  return createHttpMediatedClient(channel.url, credential, dpopKeys, extraHeaders);
}
let evidence: EvidenceStore;
let clientKey: CryptoKey;
let dpopKeys: DpopKeys;
let dpopJkt: string;
let accessToken = "";
let missionId = "";

const cookies = new Map<string, string>();
const cookieHeader = () => [...cookies.entries()].map(([k, v]) => `${k}=${v}`).join("; ");
function storeCookies(res: Response): void {
  for (const line of res.headers.getSetCookie()) {
    const [pair] = line.split(";");
    const eq = (pair as string).indexOf("=");
    cookies.set((pair as string).slice(0, eq), (pair as string).slice(eq + 1));
  }
}

const clientAssertion = (aud: string = ISSUER): Promise<string> =>
  new SignJWT({})
    .setProtectedHeader({ alg: "ES256", kid: "ap-agent-auth" })
    .setIssuer("ap-agent")
    .setSubject("ap-agent")
    .setAudience(aud)
    .setIssuedAt()
    .setExpirationTime("2m")
    .setJti(crypto.randomUUID())
    .sign(clientKey);

const dpopProof = async (htu: string, htm: string, extra: Record<string, unknown> = {}): Promise<string> =>
  new SignJWT({ htu, htm, ...extra })
    .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: await exportJWK(dpopKeys.publicKey) })
    .setIssuedAt()
    .setJti(crypto.randomUUID())
    .sign(dpopKeys.privateKey);

/** The full PAR -> approval -> token dance for a real Mission-bound token. */
async function issueMissionToken(): Promise<{ token: string; missionId: string }> {
  const verifier = "txn-e2e-verifier-0123456789-0123456789-012345";
  const codeChallenge = Buffer.from(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)),
  ).toString("base64url");
  const par = await fetch(`${ISSUER}/request`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: "ap-agent",
      response_type: "code",
      redirect_uri: REDIRECT_URI,
      scope: "payments",
      resource: RESOURCE,
      code_challenge: codeChallenge,
      code_challenge_method: "S256",
      mission_intent: JSON.stringify({
        intent: {
          goal: "Pay Acme invoices and send remittance",
          resources: [RESOURCE],
          expires_at: "2027-01-01T00:00:00Z",
        },
      }),
      authorization_details: JSON.stringify([
        {
          type: "mission_resource_access",
          resource: RESOURCE,
          actions: ["payments:invoice.read", "payments:remittance.send"],
          constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
        },
      ]),
      client_assertion: await clientAssertion(),
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    }).toString(),
  });
  const { request_uri } = (await par.json()) as { request_uri: string };

  let res = await fetch(`${ISSUER}/auth?${new URLSearchParams({ client_id: "ap-agent", request_uri })}`, {
    redirect: "manual",
  });
  storeCookies(res);
  let location = res.headers.get("location") as string;
  const uid = location.split("/interaction/")[1] as string;
  res = await fetch(`${ISSUER}/interaction/${uid}/decide`, {
    method: "POST",
    redirect: "manual",
    headers: { "content-type": "application/json", cookie: cookieHeader() },
    body: JSON.stringify({ decision: "approve", approver: "bob", subject: "alice" }),
  });
  storeCookies(res);
  location = res.headers.get("location") as string;
  while (location?.startsWith(ISSUER)) {
    res = await fetch(location, { redirect: "manual", headers: { cookie: cookieHeader() } });
    storeCookies(res);
    location = res.headers.get("location") as string;
  }
  const code = new URL(location).searchParams.get("code") as string;

  const htu = `${ISSUER}/token`;
  const form = async (nonce?: string) =>
    new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: REDIRECT_URI,
      code_verifier: verifier,
      resource: RESOURCE,
      client_assertion: await clientAssertion(),
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      ...(nonce ? { nonce } : {}),
    }).toString();
  let tok = await fetch(htu, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", dpop: await dpopProof(htu, "POST") },
    body: await form(),
  });
  const nonce = tok.headers.get("dpop-nonce");
  if (tok.status === 400 && nonce) {
    tok = await fetch(htu, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        dpop: await dpopProof(htu, "POST", { nonce }),
      },
      body: await form(),
    });
  }
  const body = (await tok.json()) as { access_token: string };
  return {
    token: body.access_token,
    missionId: (decodeJwt(body.access_token).mission as { id: string }).id,
  };
}

/** POST the transaction endpoint with client authentication + a DPoP proof. */
async function postTransaction(payload: Record<string, string>): Promise<Response> {
  const htu = `${ISSUER}/transaction`;
  return fetch(htu, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", dpop: await dpopProof(htu, "POST") },
    body: new URLSearchParams({
      client_id: "ap-agent",
      client_assertion: await clientAssertion(),
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      ...payload,
    }).toString(),
  });
}

d("transaction authorization end to end (@spec txn-authorization#challenge-redemption)", () => {
  beforeAll(async () => {
    const conn = await Fga.connect({ apiUrl: API_URL, presharedKey: FGA_KEY, ...(CA ? { caCertPath: CA } : {}) });

    // The resource's challenge-signing key, published at its
    // txn_challenge_jwks_uri; the TAS resolves THIS issuer's keys from it.
    const rsTxnKeys = await generateKeyPair("ES256", { extractable: true });
    const rsTxnPub = { ...(await exportJWK(rsTxnKeys.publicKey)), kid: "rs-txn", alg: "ES256" };

    const arsKeys = await generateKeyPair("ES256", { extractable: true });
    ars = new AccessRequestService({
      pdpJwks: { keys: [] },
      approvalKey: arsKeys.privateKey,
      approvalKid: "ars",
      issuer: "https://ars.test",
      approvalAudience: "https://pdp.test",
      approvalTtlSeconds: 300,
    });

    const challengeIssuers: ChallengeIssuers = new Map([
      [RESOURCE, { jwks: createLocalJWKSet({ keys: [rsTxnPub as JWK] }), algs: ["ES256"] }],
    ]);
    as = await buildAuthorizationServer({
      issuer: ISSUER,
      allowHeadlessAdjudication: true,
      transactionAuthorization: {
        challengeIssuers,
        ars,
        workflowLifetimeSeconds: 600,
        maxTokenLifetimeSeconds: 300,
        // The deployment's entitlement/policy decision at completion. Permit
        // here: the refusal paths are covered by txn-endpoint.test.ts.
        freshDecision: async () => ({ decision: "permit" }),
      },
    });
    asServer = as.provider.listen(PORT);
    clientKey = (await importJWK(as.agentClientJwk as never, "ES256")) as CryptoKey;
    dpopKeys = await generateKeyPair("ES256", { extractable: true });
    dpopJkt = await calculateJwkThumbprint(await exportJWK(dpopKeys.publicKey));

    const issued = await issueMissionToken();
    accessToken = issued.token;
    missionId = issued.missionId;

    // The resource: a real PEP over the live OpenFGA, reading the Mission from
    // the AS kernel, and configured to sign challenges to this TAS.
    const payments = new PaymentsStore();
    payments.seed(
      [{ id: "acme", name: "Acme", status: "approved" }],
      [
        {
          id: "inv-1",
          vendor_id: "acme",
          amount: "125.00",
          currency: "USD",
          payee_account: "acct-acme",
          status: "payable",
        },
      ],
    );
    const loadView = (id: string): MissionView | undefined => {
      const record = as.kernel.get(id);
      if (!record) return undefined;
      const fresh = as.kernel.applyExpiry(record);
      return {
        id: fresh.id,
        issuer: fresh.issuer,
        state: fresh.state,
        version: fresh.version,
        authority_hash: fresh.authority_hash,
        authority_set: fresh.authority_set,
      };
    };
    evidence = new EvidenceStore();
    const card = { name: "payments" };
    const pep = new Pep({
      payments,
      evidence,
      fga: conn.fga,
      modelId: conn.modelId,
      loadView,
      instanceEpoch: "e2e-epoch",
      sourceDigest: sourceDigestOf(card),
      requiresActionApproval: (action) => action === "payments:remittance.send",
      maxApprovalAgeSeconds: 300,
      challengeSigner: { sign: rsTxnKeys.privateKey, kid: "rs-txn", alg: "ES256", asIssuer: ISSUER },
    });
    const asJwks = (await (await fetch(`${ISSUER}/jwks`)).json()) as { keys: Record<string, unknown>[] };
    rs = new McpPaymentsServer({
      pep,
      payments,
      loadView,
      jwks: asJwks,
      issuer: ISSUER,
      serverCard: card,
      transaction: { engine: new TransactionEngine("e2e-epoch"), connectors: new Connectors(), evidence },
      // The resource trusts the TAS's token-signing key through pre-established
      // federation metadata (this JWKS), never through the request.
      txnTokenJwks: asJwks,
      asIssuer: ISSUER,
    });
  });

  afterAll(async () => {
    for (const channel of channels) await channel.close();
    asServer?.close();
  });

  it("challenges, redeems, approves, decides fresh, and executes exactly once", async () => {
    // 1. The agent calls the gated tool over MCP, signalling that it can redeem
    //    a challenge. Its credential is the Mission-bound access token.
    // The resource runs over a REAL MCP-over-HTTP transport: every request is
    // gated by the credential middleware, so nothing below reaches the PEP
    // except through a validated Authorization credential + DPoP proof.
    const agent = await connect(accessToken, {
      // @spec txn-authorization#resource-challenge — an RFC 8941 Boolean.
      "accept-txn-challenge": "?1",
    });
    const challenged = await agent.client.callTool("send_remittance_email", { invoice_id: "inv-1" });
    expect(challenged.ok).toBe(false);
    expect(challenged.error).toBe("transaction_authorization_required");
    const challenge = challenged.transaction_challenge as string;
    expect(challenge).toBeTruthy();
    const challengeClaims = decodeJwt(challenge);
    expect(challengeClaims.iss).toBe(RESOURCE);
    expect((challengeClaims.cnf as { jkt: string }).jkt).toBe(dpopJkt);
    expect((challengeClaims.mission as { id: string }).id).toBe(missionId);

    // 2. The client redeems it at the TAS, with the Mission-bound token as the
    //    subject_token and a proof of the challenge's cnf key.
    const admitted = await postTransaction({
      transaction_challenge: challenge,
      subject_token: accessToken,
      subject_token_type: "urn:ietf:params:oauth:token-type:access_token",
    });
    const admittedBody = (await admitted.json()) as { transaction_authorization_id: string };
    expect(admitted.status, JSON.stringify(admittedBody)).toBe(200);

    // 3. Pending until the approver acts.
    const pending = await postTransaction({
      transaction_authorization_id: admittedBody.transaction_authorization_id,
    });
    expect((await pending.json()).error).toBe("authorization_pending");

    const queued = ars.pending();
    expect(queued.length).toBeGreaterThan(0);
    await ars.adjudicate(queued[0]?.id as string, "approve", "bob");

    // 4. The fresh decision runs and the TAS issues.
    const issued = await postTransaction({
      transaction_authorization_id: admittedBody.transaction_authorization_id,
    });
    const issuedBody = (await issued.json()) as { access_token: string; token_type: string };
    expect(issued.status, JSON.stringify(issuedBody)).toBe(200);
    expect(issuedBody.token_type).toBe("DPoP");

    // 5. The retry presents the transaction token as the request's SOLE OAuth
    //    credential. The resource verifies it offline against the operation it
    //    retained, and the operation executes exactly once.
    await agent.close();
    const retry = await connect(issuedBody.access_token);
    const executed = await retry.client.callTool("send_remittance_email", { invoice_id: "inv-1" });
    expect(executed.ok, JSON.stringify(executed)).toBe(true);
    expect(evidence.forMission(missionId).filter((e) => e.kind === "execution")).toHaveLength(1);

    // 6. Re-presenting the same credential is the same replay: refused, never a
    //    second execution.
    const replay = await retry.client.callTool("send_remittance_email", { invoice_id: "inv-1" });
    expect(replay.ok).toBe(false);
    expect(replay.refusal_reason).toBe("duplicate_suppressed");
    expect(evidence.forMission(missionId).filter((e) => e.kind === "execution")).toHaveLength(1);

    // The credential authorizes the challenged operation and nothing else: it is
    // never a general credential for another tool.
    const elsewhere = await retry.client.callTool("list_invoices", {});
    expect(elsewhere.ok).toBe(false);
    expect(elsewhere.refusal_reason).toBe("txn_action_mismatch");
    await retry.close();
  });
});
