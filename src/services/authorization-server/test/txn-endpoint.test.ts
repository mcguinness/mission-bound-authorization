/**
 * Phase 1 AROP Transaction Challenge over real HTTP: the AS
 * transaction_authorization_endpoint. A client presents its base mission token
 * (DPoP) + an RS-signed txn-challenge; the AS validates + subset-gates against
 * the ACTIVE Mission (D42), the ARS approves, and the AS issues a txn-bound,
 * audience-restricted, single-use token carrying the active Mission unchanged
 * plus the verified approval (incl. parameter_digest). The hybrid design: the
 * AS signature is the source of the approval, the RS (phase 2) is the carrier.
 */

import { type Server } from "node:http";
import { AccessRequestService } from "@mission/access-request";
import { CANONICAL_RESOURCE } from "@mission/demo-data";
import {
  calculateJwkThumbprint,
  createRemoteJWKSet,
  exportJWK,
  generateKeyPair,
  importJWK,
  jwtVerify,
  SignJWT,
} from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  buildAuthorizationServer,
  signChallenge,
  TXN_TOKEN_TYP,
  type AuthorityEntry,
  type BuiltAs,
} from "../src/index.js";

const PORT = 14450;
const ISSUER = `http://localhost:${PORT}`;
const REDIRECT_URI = "http://localhost:9999/cb";
const RESOURCE = CANONICAL_RESOURCE;

let as: BuiltAs;
let asServer: Server;
let ars: AccessRequestService;
let clientKey: CryptoKey;
let dpopKeys: { privateKey: CryptoKey; publicKey: CryptoKey };
let dpopJkt: string;
let rsTxnKeys: { privateKey: CryptoKey; publicKey: CryptoKey };
let baseToken = "";
let missionId = "";

const cookies = new Map<string, string>();
function cookieHeader(): string {
  return [...cookies.entries()].map(([k, v]) => `${k}=${v}`).join("; ");
}
function storeCookies(res: Response): void {
  for (const line of res.headers.getSetCookie()) {
    const [pair] = line.split(";");
    const eq = (pair as string).indexOf("=");
    cookies.set((pair as string).slice(0, eq), (pair as string).slice(eq + 1));
  }
}

async function clientAssertion(): Promise<string> {
  return new SignJWT({})
    .setProtectedHeader({ alg: "ES256", kid: "ap-agent-auth" })
    .setIssuer("ap-agent")
    .setSubject("ap-agent")
    .setAudience(ISSUER)
    .setIssuedAt()
    .setExpirationTime("2m")
    .setJti(crypto.randomUUID())
    .sign(clientKey);
}

async function dpopProof(htu: string, htm: string, extra: Record<string, unknown> = {}): Promise<string> {
  return new SignJWT({ htu, htm, ...extra })
    .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: await exportJWK(dpopKeys.publicKey) })
    .setIssuedAt()
    .setJti(crypto.randomUUID())
    .sign(dpopKeys.privateKey);
}

async function tokenRequest(params: Record<string, string>): Promise<Response> {
  const htu = `${ISSUER}/token`;
  let res = await fetch(htu, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", dpop: await dpopProof(htu, "POST") },
    body: new URLSearchParams({
      ...params,
      client_assertion: await clientAssertion(),
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    }).toString(),
  });
  const nonce = res.headers.get("dpop-nonce");
  if (res.status === 400 && nonce) {
    res = await fetch(htu, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", dpop: await dpopProof(htu, "POST", { nonce }) },
      body: new URLSearchParams({
        ...params,
        client_assertion: await clientAssertion(),
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      }).toString(),
    });
  }
  return res;
}

/** Full PAR -> approval -> token dance yielding a base DPoP-bound mission token. */
async function issueBaseMissionToken(): Promise<{ token: string; missionId: string }> {
  const verifier = "txn-endpoint-verifier-0123456789-0123456789-01234";
  const challenge = Buffer.from(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)),
  ).toString("base64url");
  const intent = JSON.stringify({
    goal: "Pay Acme invoices and send remittance",
    resources: [RESOURCE],
    expires_at: "2027-01-01T00:00:00Z",
    proposed_authority: [
      {
        type: "mission_resource_access",
        resource: RESOURCE,
        actions: ["payments:invoice.read", "payments:remittance.send"],
        constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
      },
    ],
  });
  const par = await fetch(`${ISSUER}/request`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: "ap-agent",
      response_type: "code",
      redirect_uri: REDIRECT_URI,
      scope: "payments",
      resource: RESOURCE,
      code_challenge: challenge,
      code_challenge_method: "S256",
      mission_intent: intent,
      client_assertion: await clientAssertion(),
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    }).toString(),
  });
  const { request_uri } = (await par.json()) as { request_uri: string };

  const authUrl = `${ISSUER}/auth?${new URLSearchParams({ client_id: "ap-agent", request_uri })}`;
  let res = await fetch(authUrl, { redirect: "manual" });
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

  const tok = await tokenRequest({
    grant_type: "authorization_code",
    code,
    redirect_uri: REDIRECT_URI,
    code_verifier: verifier,
    resource: RESOURCE,
  });
  const body = (await tok.json()) as { access_token: string };
  const claims = JSON.parse(Buffer.from(body.access_token.split(".")[1] as string, "base64url").toString()) as {
    mission: { id: string };
  };
  return { token: body.access_token, missionId: claims.mission.id };
}

/** POST /transaction with the base token (DPoP) + a body-carried challenge. */
async function postTransaction(challengeJws: string): Promise<Response> {
  const htu = `${ISSUER}/transaction`;
  return fetch(htu, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `DPoP ${baseToken}`,
      dpop: await dpopProof(htu, "POST"),
    },
    body: JSON.stringify({ challenge: challengeJws }),
  });
}

beforeAll(async () => {
  // RS txn-challenge signing key (its txn_challenge_jwks_uri); the AS is
  // configured with its public half.
  rsTxnKeys = await generateKeyPair("ES256", { extractable: true });
  const rsTxnPub = { ...(await exportJWK(rsTxnKeys.publicKey)), kid: "rs-txn", alg: "ES256" };

  // The AS-owned ARS (D37). No PDP binding is needed for the AS-vouched path,
  // so pdpJwks is empty; adjudicate uses the approval key.
  const arsKeys = await generateKeyPair("ES256", { extractable: true });
  ars = new AccessRequestService({
    pdpJwks: { keys: [] },
    approvalKey: arsKeys.privateKey,
    approvalKid: "ars",
    approvalTtlSeconds: 300,
  });

  as = await buildAuthorizationServer({
    issuer: ISSUER,
    allowHeadlessAdjudication: true,
    resourceTxnJwks: { keys: [rsTxnPub as never] },
    ars,
  });
  asServer = as.provider.listen(PORT);
  clientKey = (await importJWK(as.agentClientJwk as never, "ES256")) as CryptoKey;
  dpopKeys = await generateKeyPair("ES256", { extractable: true });
  dpopJkt = await calculateJwkThumbprint(await exportJWK(dpopKeys.publicKey));

  const base = await issueBaseMissionToken();
  baseToken = base.token;
  missionId = base.missionId;
});

afterAll(() => {
  asServer?.close();
});

describe("AS transaction_authorization_endpoint (AROP Transaction Challenge, D42)", () => {
  it("advertises transaction_authorization_endpoint in metadata", async () => {
    const meta = (await (await fetch(`${ISSUER}/.well-known/openid-configuration`)).json()) as Record<string, unknown>;
    expect(meta.transaction_authorization_endpoint).toBe(`${ISSUER}/transaction`);
  });

  it("pends, then on approval issues a txn-bound single-use token carrying the ACTIVE Mission", async () => {
    // Requested authority is a genuine subset of the active Mission (the RS
    // read the Mission's Authority Set from the base token).
    const record = as.kernel.get(missionId);
    expect(record).toBeDefined();
    const requested = (record as { authority_set: AuthorityEntry[] }).authority_set.filter((e) =>
      e.actions.includes("payments:remittance.send"),
    );
    expect(requested.length).toBeGreaterThan(0);

    const txn = "txn_http_1";
    const parameter_digest = "sha-256:aa11bb22cc33dd44";
    const challenge = await signChallenge(
      {
        txn,
        authorization_details: requested,
        iss: RESOURCE,
        aud: ISSUER,
        reason: "over-cap remittance requires approval",
        parameter_digest,
      },
      rsTxnKeys.privateKey,
      "rs-txn",
    );

    // First call -> pending (task opened by the AS-vouched ARS).
    const first = await postTransaction(challenge);
    const firstBody = (await first.json()) as { status?: string; txn?: string };
    expect(first.status, JSON.stringify(firstBody)).toBe(200);
    expect(firstBody.status).toBe("authorization_pending");
    expect(firstBody.txn).toBe(txn);

    // Polling before approval stays pending.
    const poll = await postTransaction(challenge);
    expect(((await poll.json()) as { status: string }).status).toBe("authorization_pending");

    // Bob approves via the AS's ARS (endpoint ARS == injected ARS).
    const queued = ars.pending();
    expect(queued.length).toBe(1);
    const approval = await ars.adjudicate(queued[0]?.id as string, "approve", "bob");
    expect(approval).not.toBeNull();
    const approvedUntil = (approval as { approved_until: string }).approved_until;

    // Next call -> 200 with the txn-token.
    const second = await postTransaction(challenge);
    const secondBody = (await second.json()) as { access_token?: string; token_type?: string; txn?: string };
    expect(second.status, JSON.stringify(secondBody)).toBe(200);
    expect(secondBody.token_type).toBe("DPoP");
    expect(secondBody.txn).toBe(txn);

    // Verify the AS-signed txn-token against the AS /jwks (as-txn published).
    const jwks = createRemoteJWKSet(new URL(`${ISSUER}/jwks`));
    const { payload, protectedHeader } = await jwtVerify(secondBody.access_token as string, jwks, {
      issuer: ISSUER,
      audience: RESOURCE,
    });
    expect(protectedHeader.typ).toBe(TXN_TOKEN_TYP);
    expect(payload.txn).toBe(txn);
    expect(payload.single_use).toBe(true);
    expect((payload.cnf as { jkt: string }).jkt).toBe(dpopJkt);
    // D42: the token carries the ACTIVE Mission -- no successor, no predecessor.
    expect((payload.mission as { id: string }).id).toBe(missionId);
    expect((payload.mission as { predecessor?: string }).predecessor).toBeUndefined();
    expect((payload.mission as { successor?: string }).successor).toBeUndefined();
    // The verified approval (incl. parameter_digest) is carried.
    expect((payload.approval as { parameter_digest: string }).parameter_digest).toBe(parameter_digest);
    // The credential never outlives the recorded approval expiry.
    expect(payload.exp).toBe(Math.floor(Date.parse(approvedUntil) / 1000));
  });

  it("rejects a challenge whose authority widens beyond the Mission with 403 out_of_authority", async () => {
    // Same action, but a cap above the Mission's max_amount -> not a subset.
    const widen: AuthorityEntry[] = [
      {
        type: "mission_resource_access",
        resource: RESOURCE,
        actions: ["payments:remittance.send"],
        constraints: { max_amount: { amount: "999999.00", currency: "USD" }, vendors: ["acme"] },
      },
    ];
    const challenge = await signChallenge(
      {
        txn: "txn_http_widen",
        authorization_details: widen,
        iss: RESOURCE,
        aud: ISSUER,
        reason: "attempt to widen",
        parameter_digest: "sha-256:ffffffffffffffff",
      },
      rsTxnKeys.privateKey,
      "rs-txn",
    );
    const res = await postTransaction(challenge);
    const body = (await res.json()) as { error?: string };
    expect(res.status, JSON.stringify(body)).toBe(403);
    expect(body.error).toBe("out_of_authority");
  });
});
