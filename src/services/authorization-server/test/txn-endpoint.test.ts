/**
 * Phase 1 AROP Transaction Challenge over real HTTP: the AS
 * transaction_authorization_endpoint. A client presents its base mission token
 * (DPoP) + an RS-signed txn-challenge ONCE (initiation); the AS validates +
 * subset-gates against the ACTIVE Mission (D42), opens an ARS task, and returns
 * a continuation handle (transaction_authorization_id). The client then POLLS
 * the same endpoint WITH the handle: pending until approval, then a txn-bound,
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

type DpopKeys = { privateKey: CryptoKey; publicKey: CryptoKey };

let as: BuiltAs;
let asServer: Server;
let ars: AccessRequestService;
let clientKey: CryptoKey;
let dpopKeys: DpopKeys;
let dpopJkt: string;
let rsTxnKeys: { privateKey: CryptoKey; publicKey: CryptoKey };
let baseToken = "";
let missionId = "";

const cookies = new Map<string, string>();
function cookieHeader(jar: Map<string, string> = cookies): string {
  return [...jar.entries()].map(([k, v]) => `${k}=${v}`).join("; ");
}
function storeCookies(res: Response, jar: Map<string, string> = cookies): void {
  for (const line of res.headers.getSetCookie()) {
    const [pair] = line.split(";");
    const eq = (pair as string).indexOf("=");
    jar.set((pair as string).slice(0, eq), (pair as string).slice(eq + 1));
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

async function dpopProof(
  htu: string,
  htm: string,
  keys: DpopKeys = dpopKeys,
  extra: Record<string, unknown> = {},
): Promise<string> {
  return new SignJWT({ htu, htm, ...extra })
    .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: await exportJWK(keys.publicKey) })
    .setIssuedAt()
    .setJti(crypto.randomUUID())
    .sign(keys.privateKey);
}

async function tokenRequest(params: Record<string, string>, keys: DpopKeys = dpopKeys): Promise<Response> {
  const htu = `${ISSUER}/token`;
  let res = await fetch(htu, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", dpop: await dpopProof(htu, "POST", keys) },
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
      headers: { "content-type": "application/x-www-form-urlencoded", dpop: await dpopProof(htu, "POST", keys, { nonce }) },
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
async function issueBaseMissionToken(
  keys: DpopKeys = dpopKeys,
  jar: Map<string, string> = cookies,
): Promise<{ token: string; missionId: string }> {
  const verifier = "txn-endpoint-verifier-0123456789-0123456789-01234";
  const challenge = Buffer.from(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)),
  ).toString("base64url");
  // @spec mission#submission-via-par — the wire value is the Submission envelope.
  const intent = JSON.stringify({
    intent: {
      goal: "Pay Acme invoices and send remittance",
      resources: [RESOURCE],
      expires_at: "2027-01-01T00:00:00Z",
    },
  });
  const authorizationDetails = JSON.stringify([
    {
      type: "mission_resource_access",
      resource: RESOURCE,
      actions: ["payments:invoice.read", "payments:remittance.send"],
      constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
    },
  ]);
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
      authorization_details: authorizationDetails,
      client_assertion: await clientAssertion(),
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    }).toString(),
  });
  const { request_uri } = (await par.json()) as { request_uri: string };

  const authUrl = `${ISSUER}/auth?${new URLSearchParams({ client_id: "ap-agent", request_uri })}`;
  let res = await fetch(authUrl, { redirect: "manual" });
  storeCookies(res, jar);
  let location = res.headers.get("location") as string;
  const uid = location.split("/interaction/")[1] as string;

  res = await fetch(`${ISSUER}/interaction/${uid}/decide`, {
    method: "POST",
    redirect: "manual",
    headers: { "content-type": "application/json", cookie: cookieHeader(jar) },
    body: JSON.stringify({ decision: "approve", approver: "bob", subject: "alice" }),
  });
  storeCookies(res, jar);
  location = res.headers.get("location") as string;
  while (location?.startsWith(ISSUER)) {
    res = await fetch(location, { redirect: "manual", headers: { cookie: cookieHeader(jar) } });
    storeCookies(res, jar);
    location = res.headers.get("location") as string;
  }
  const code = new URL(location).searchParams.get("code") as string;

  const tok = await tokenRequest(
    {
      grant_type: "authorization_code",
      code,
      redirect_uri: REDIRECT_URI,
      code_verifier: verifier,
      resource: RESOURCE,
    },
    keys,
  );
  const body = (await tok.json()) as { access_token: string };
  const claims = JSON.parse(Buffer.from(body.access_token.split(".")[1] as string, "base64url").toString()) as {
    mission: { id: string };
  };
  return { token: body.access_token, missionId: claims.mission.id };
}

/**
 * POST /transaction with the base token (DPoP). The body is EITHER
 * `{ challenge }` (initiation) OR `{ transaction_authorization_id }` (poll).
 */
async function postTransaction(
  payload: Record<string, unknown>,
  opts: { token?: string; keys?: DpopKeys } = {},
): Promise<Response> {
  const htu = `${ISSUER}/transaction`;
  return fetch(htu, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `DPoP ${opts.token ?? baseToken}`,
      dpop: await dpopProof(htu, "POST", opts.keys ?? dpopKeys),
    },
    body: JSON.stringify(payload),
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
    issuer: "https://ars.test",
    approvalAudience: "https://pdp.test",
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

  it("initiates with a handle, pends on poll, then on approval issues a txn-bound single-use token carrying the ACTIVE Mission", async () => {
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

    // §4.2: the challenge is typ txn-authz-challenge+jwt, carries the txn as a
    // body claim (not sub), and a jti is REQUIRED.
    const chHeader = JSON.parse(Buffer.from(challenge.split(".")[0] as string, "base64url").toString());
    const chBody = JSON.parse(Buffer.from(challenge.split(".")[1] as string, "base64url").toString());
    expect(chHeader.typ).toBe("txn-authz-challenge+jwt");
    expect(chBody.txn).toBe(txn);
    expect(typeof chBody.jti).toBe("string");
    expect(chBody.sub).toBeUndefined();

    // Initiation: the client presents the challenge ONCE -> a continuation
    // handle, expires_in, interval; and NO access_token yet.
    const initRes = await postTransaction({ challenge });
    const initBody = (await initRes.json()) as {
      transaction_authorization_id?: string;
      expires_in?: number;
      interval?: number;
      access_token?: string;
    };
    expect(initRes.status, JSON.stringify(initBody)).toBe(200);
    expect(initBody.transaction_authorization_id).toMatch(/^txa_/);
    expect(typeof initBody.expires_in).toBe("number");
    expect(initBody.expires_in as number).toBeGreaterThan(0);
    expect(initBody.interval).toBe(5);
    expect(initBody.access_token).toBeUndefined();
    const txaId = initBody.transaction_authorization_id as string;

    // Poll WITH the handle before approval -> 400 authorization_pending (§5.3,
    // RFC 8628-shaped), no token. The client already has interval/expires_in
    // from initiation, so the pending body stays minimal.
    const pollPending = await postTransaction({ transaction_authorization_id: txaId });
    const pendingBody = (await pollPending.json()) as { error?: string; access_token?: string };
    expect(pollPending.status).toBe(400);
    expect(pendingBody.error).toBe("authorization_pending");
    expect(pendingBody.access_token).toBeUndefined();

    // Bob approves via the AS's ARS (endpoint ARS == injected ARS).
    const queued = ars.pending();
    expect(queued.length).toBe(1);
    const approval = await ars.adjudicate(queued[0]?.id as string, "approve", "bob");
    expect(approval).not.toBeNull();
    const approvedUntil = (approval as { approved_until: string }).approved_until;

    // Poll WITH the handle after approval -> 200 with the txn-token.
    const tokenRes = await postTransaction({ transaction_authorization_id: txaId });
    const tokenBody = (await tokenRes.json()) as { access_token?: string; token_type?: string; txn?: string };
    expect(tokenRes.status, JSON.stringify(tokenBody)).toBe(200);
    expect(tokenBody.token_type).toBe("DPoP");
    expect(tokenBody.txn).toBe(txn);

    // Verify the AS-signed txn-token against the AS /jwks (as-txn published).
    const jwks = createRemoteJWKSet(new URL(`${ISSUER}/jwks`));
    const { payload, protectedHeader } = await jwtVerify(tokenBody.access_token as string, jwks, {
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
    const res = await postTransaction({ challenge });
    const body = (await res.json()) as { error?: string };
    expect(res.status, JSON.stringify(body)).toBe(403);
    expect(body.error).toBe("out_of_authority");
  });

  it("returns 404 for a poll with an unknown transaction_authorization_id", async () => {
    const res = await postTransaction({ transaction_authorization_id: "txa_does-not-exist" });
    const body = (await res.json()) as { error?: string };
    expect(res.status, JSON.stringify(body)).toBe(404);
    expect(body.error).toBe("invalid_request");
  });

  it("rejects a poll from a different client (cnf.jkt mismatch) with 403 invalid_token", async () => {
    // Initiate a fresh handle, bound to the real base token's DPoP key.
    const record = as.kernel.get(missionId);
    const requested = (record as { authority_set: AuthorityEntry[] }).authority_set.filter((e) =>
      e.actions.includes("payments:remittance.send"),
    );
    const challenge = await signChallenge(
      {
        txn: "txn_http_cnf",
        authorization_details: requested,
        iss: RESOURCE,
        aud: ISSUER,
        reason: "cnf-binding test",
        parameter_digest: "sha-256:cccccccccccccccc",
      },
      rsTxnKeys.privateKey,
      "rs-txn",
    );
    const initBody = (await (await postTransaction({ challenge })).json()) as { transaction_authorization_id: string };
    const txaId = initBody.transaction_authorization_id;

    // A DIFFERENT client: a second base token minted under a different DPoP key.
    const otherKeys = await generateKeyPair("ES256", { extractable: true });
    const other = await issueBaseMissionToken(otherKeys, new Map());

    // Polling the handle with that client's token + DPoP passes the base-token
    // DPoP check but fails the handle-to-client binding -> 403 invalid_token.
    const res = await postTransaction(
      { transaction_authorization_id: txaId },
      { token: other.token, keys: otherKeys },
    );
    const body = (await res.json()) as { error?: string };
    expect(res.status, JSON.stringify(body)).toBe(403);
    expect(body.error).toBe("invalid_token");
  });

  it("polls a DENIED task -> 400 access_denied (§5.3), so the client stops rather than polling forever", async () => {
    const record = as.kernel.get(missionId);
    const requested = (record as { authority_set: AuthorityEntry[] }).authority_set.filter((e) =>
      e.actions.includes("payments:remittance.send"),
    );
    const txn = "txn_http_denied";
    const challenge = await signChallenge(
      {
        txn,
        authorization_details: requested,
        iss: RESOURCE,
        aud: ISSUER,
        reason: "deny-path test",
        parameter_digest: "sha-256:dddddddddddddddd",
      },
      rsTxnKeys.privateKey,
      "rs-txn",
    );
    const initBody = (await (await postTransaction({ challenge })).json()) as { transaction_authorization_id: string };
    expect(initBody.transaction_authorization_id).toMatch(/^txa_/);

    // Bob denies the AS-vouched task (openForTxn keys it arq_txn_<txn>).
    const denied = await ars.adjudicate(`arq_txn_${txn}`, "deny", "bob");
    expect(denied).toBeNull();

    // Poll -> 400 access_denied, terminal.
    const res = await postTransaction({ transaction_authorization_id: initBody.transaction_authorization_id });
    const body = (await res.json()) as { error?: string; access_token?: string };
    expect(res.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("access_denied");
    expect(body.access_token).toBeUndefined();
  });
});
