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
  TXN_CHALLENGE_TYP,
  TXN_TOKEN_TYP,
  type AuthorityEntry,
  type BuiltAs,
  type ChallengeIssuers,
} from "../src/index.js";
import { createLocalJWKSet, decodeJwt, type JWK } from "jose";

const PORT = 14450;
const ISSUER = `http://localhost:${PORT}`;
const REDIRECT_URI = "http://localhost:9999/cb";
const RESOURCE = CANONICAL_RESOURCE;
/** The pending workflow's own lifetime, independent of any challenge exp. */
const WORKFLOW_LIFETIME_S = 600;
/** The deployment maximum for an issued transaction token. */
const MAX_TOKEN_LIFETIME_S = 300;

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
let missionClaim: Record<string, unknown> = {};
/** `txn` values the deployment's fresh decision refuses. */
const policyDeniesTxns = new Set<string>();
/** Every `txn` the fresh decision was asked about (it must run before issuance). */
const freshDecisionCalls: string[] = [];

/**
 * Stand in for the Challenge-Issuing Resource: sign a challenge carrying every
 * REQUIRED claim, including this profile's `mission`, `parameter_digest` and
 * `cnf` (which a real resource derives from the request and the verified
 * Mission-bound access token).
 */
async function signChallenge(
  claims: {
    txn: string;
    authorization_details: unknown[];
    iss: string;
    aud: string;
    reason: string;
    parameter_digest: string;
    mission?: Record<string, unknown>;
    cnf?: { jkt: string };
    lifetimeSeconds?: number;
  },
  key: CryptoKey,
  kid: string,
): Promise<string> {
  return new SignJWT({
    txn: claims.txn,
    authorization_details: claims.authorization_details,
    reason: claims.reason,
    parameter_digest: claims.parameter_digest,
    mission: claims.mission ?? missionClaim,
    cnf: claims.cnf ?? { jkt: dpopJkt },
  })
    .setProtectedHeader({ alg: "ES256", kid, typ: TXN_CHALLENGE_TYP })
    .setIssuer(claims.iss)
    .setAudience(claims.aud)
    .setJti(crypto.randomUUID())
    .setIssuedAt()
    .setExpirationTime(`${claims.lifetimeSeconds ?? 300}s`)
    .sign(key);
}

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
 * @spec txn-authorization#challenge-redemption — POST to the transaction
 * endpoint: authenticated client, a DPoP proof of the challenge's `cnf` key
 * bound to this endpoint, and either an initial submission
 * (`transaction_challenge` + `subject_token`) or a poll
 * (`transaction_authorization_id`).
 */
async function postTransaction(
  payload: Record<string, string>,
  opts: { keys?: DpopKeys; assertion?: string; omitClientAuth?: boolean } = {},
): Promise<Response> {
  const htu = `${ISSUER}/transaction`;
  const auth = opts.omitClientAuth
    ? {}
    : {
        client_id: "ap-agent",
        client_assertion: opts.assertion ?? (await clientAssertion()),
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      };
  return fetch(htu, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      dpop: await dpopProof(htu, "POST", opts.keys ?? dpopKeys),
    },
    body: new URLSearchParams({ ...auth, ...payload }).toString(),
  });
}

/** An initial submission carrying the Mission-bound access token as subject_token. */
async function submit(
  challenge: string,
  opts: { token?: string; keys?: DpopKeys } = {},
): Promise<Response> {
  return postTransaction(
    {
      transaction_challenge: challenge,
      subject_token: opts.token ?? baseToken,
      subject_token_type: "urn:ietf:params:oauth:token-type:access_token",
    },
    { ...(opts.keys ? { keys: opts.keys } : {}) },
  );
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

  const challengeIssuers: ChallengeIssuers = new Map([
    [RESOURCE, { jwks: createLocalJWKSet({ keys: [rsTxnPub as JWK] }), algs: ["ES256"] }],
  ]);
  as = await buildAuthorizationServer({
    issuer: ISSUER,
    allowHeadlessAdjudication: true,
    transactionAuthorization: {
      challengeIssuers,
      ars,
      workflowLifetimeSeconds: WORKFLOW_LIFETIME_S,
      maxTokenLifetimeSeconds: MAX_TOKEN_LIFETIME_S,
      // @spec txn-authorization#challenge-redemption step 7 — a deployment
      // entitlement/policy decision, run fresh at completion. The suite drives
      // it through `policyDeniesTxns` to prove an approved workflow still
      // refuses when a current input no longer holds.
      freshDecision: async (input) => {
        freshDecisionCalls.push(input.txn);
        return policyDeniesTxns.has(input.txn)
          ? { decision: "deny", reason: "entitlement_denied" }
          : { decision: "permit" };
      },
    },
  });
  asServer = as.provider.listen(PORT);
  clientKey = (await importJWK(as.agentClientJwk as never, "ES256")) as CryptoKey;
  dpopKeys = await generateKeyPair("ES256", { extractable: true });
  dpopJkt = await calculateJwkThumbprint(await exportJWK(dpopKeys.publicKey));

  const base = await issueBaseMissionToken();
  baseToken = base.token;
  missionId = base.missionId;
  missionClaim = decodeJwt(baseToken).mission as Record<string, unknown>;
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
    const initRes = await submit(challenge);
    const initBody = (await initRes.json()) as {
      transaction_authorization_id?: string;
      expires_in?: number;
      interval?: number;
      access_token?: string;
    };
    expect(initRes.status, JSON.stringify(initBody)).toBe(200);
    expect(initBody.transaction_authorization_id).toMatch(/^txa_/);
    // @spec txn-authorization#two-phase-expiry — the workflow's OWN lifetime,
    // not the challenge's remaining admission window.
    expect(initBody.expires_in).toBe(WORKFLOW_LIFETIME_S);
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
    const tokenBody = (await tokenRes.json()) as {
      access_token?: string;
      token_type?: string;
      expires_in?: number;
      txn?: string;
    };
    expect(tokenRes.status, JSON.stringify(tokenBody)).toBe(200);
    expect(tokenBody.token_type).toBe("DPoP");
    // A standard OAuth token response: no bespoke members ride alongside it.
    expect(tokenBody.txn).toBeUndefined();
    expect(tokenBody.expires_in).toBeGreaterThan(0);

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
    // @spec txn-authorization#transaction-token — never later than the earliest
    // of the approval's validity and the deployment maximum, and NEVER bounded
    // by the already-consumed challenge exp.
    expect(payload.exp as number).toBeLessThanOrEqual(Math.floor(Date.parse(approvedUntil) / 1000));
    expect(payload.exp as number).toBeGreaterThan(Math.floor(Date.now() / 1000));
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
    const res = await submit(challenge);
    const body = (await res.json()) as { error?: string };
    expect(res.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("invalid_grant");
  });

  it("returns 404 for a poll with an unknown transaction_authorization_id", async () => {
    const res = await postTransaction({ transaction_authorization_id: "txa_does-not-exist" });
    const body = (await res.json()) as { error?: string };
    expect(res.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("invalid_grant");
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
    const initBody = (await (await submit(challenge)).json()) as { transaction_authorization_id: string };
    const txaId = initBody.transaction_authorization_id;

    // A DIFFERENT client: a second base token minted under a different DPoP key.
    const otherKeys = await generateKeyPair("ES256", { extractable: true });
    const other = await issueBaseMissionToken(otherKeys, new Map());

    // Polling the handle with that client's token + DPoP passes the base-token
    // DPoP check but fails the handle-to-client binding -> 403 invalid_token.
    const res = await postTransaction({ transaction_authorization_id: txaId }, { keys: otherKeys });
    const body = (await res.json()) as { error?: string };
    expect(res.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("invalid_grant");
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
    const initBody = (await (await submit(challenge)).json()) as { transaction_authorization_id: string };
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

describe("two-phase expiry and idempotency (@spec txn-authorization#two-phase-expiry)", () => {
  const requestedEntry = (): AuthorityEntry[] => {
    const record = as.kernel.get(missionId) as { authority_set: AuthorityEntry[] };
    return record.authority_set
      .filter((e) => e.actions.includes("payments:remittance.send"))
      .map((e) => ({ ...e, actions: ["payments:remittance.send"] }));
  };

  const challengeFor = async (txn: string, over: Record<string, unknown> = {}) =>
    signChallenge(
      {
        txn,
        authorization_details: requestedEntry(),
        iss: RESOURCE,
        aud: ISSUER,
        reason: "action_approval_required",
        parameter_digest: `sha-256:${txn}`,
        ...over,
      },
      rsTxnKeys.privateKey,
      "rs-txn",
    );

  it("returns the existing workflow when the same challenge is submitted again", async () => {
    const challenge = await challengeFor("txn_repeat_submit");
    const first = (await (await submit(challenge)).json()) as { transaction_authorization_id: string };
    const second = (await (await submit(challenge)).json()) as { transaction_authorization_id: string };
    expect(first.transaction_authorization_id).toMatch(/^txa_/);
    expect(second.transaction_authorization_id).toBe(first.transaction_authorization_id);
    // Exactly one approval task was opened for the one admitted challenge.
    expect(ars.pending().filter((t) => t.id === "arq_txn_txn_repeat_submit")).toHaveLength(1);
  });

  it("refuses a challenge that expired before it was submitted, rather than reviving one", async () => {
    const challenge = await challengeFor("txn_late", { lifetimeSeconds: -60 });
    const res = await submit(challenge);
    const body = (await res.json()) as { error?: string; error_description?: string };
    expect(res.status).toBe(400);
    expect(body.error).toBe("invalid_grant");
    expect(body.error_description).toContain("expired_challenge");
  });

  it("still issues when the approval lands after the challenge expired but inside the workflow lifetime", async () => {
    // A challenge whose admission window is seconds wide: it admits now, and is
    // long expired by the time the approver acts.
    const challenge = await challengeFor("txn_slow_approval", { lifetimeSeconds: 2 });
    const init = (await (await submit(challenge)).json()) as { transaction_authorization_id: string };
    await new Promise((r) => setTimeout(r, 2500));

    // The challenge would no longer admit anything now...
    const late = await submit(challenge);
    expect((await late.json()).error).toBe("invalid_grant");

    // ...but the workflow it already admitted still completes.
    const approval = await ars.adjudicate("arq_txn_txn_slow_approval", "approve", "bob");
    expect(approval).not.toBeNull();
    const res = await postTransaction({
      transaction_authorization_id: init.transaction_authorization_id,
    });
    const body = (await res.json()) as { access_token?: string; expires_in?: number };
    expect(res.status, JSON.stringify(body)).toBe(200);
    expect(body.access_token).toBeTruthy();
    // The token's lifetime comes from the workflow and the approval, never from
    // the already-consumed challenge exp.
    expect(body.expires_in as number).toBeGreaterThan(2);
  });

  it("returns the same token, under the same jti, on every poll after the decision", async () => {
    const challenge = await challengeFor("txn_stable_result");
    const init = (await (await submit(challenge)).json()) as { transaction_authorization_id: string };
    await ars.adjudicate("arq_txn_txn_stable_result", "approve", "bob");
    const first = (await (
      await postTransaction({ transaction_authorization_id: init.transaction_authorization_id })
    ).json()) as { access_token: string };
    const second = (await (
      await postTransaction({ transaction_authorization_id: init.transaction_authorization_id })
    ).json()) as { access_token: string };
    expect(second.access_token).toBe(first.access_token);
    expect(decodeJwt(second.access_token).jti).toBe(decodeJwt(first.access_token).jti);
  });

  it("bounds the token by the deployment maximum, never by the challenge exp", async () => {
    const challenge = await challengeFor("txn_exp_bound");
    const init = (await (await submit(challenge)).json()) as { transaction_authorization_id: string };
    await ars.adjudicate("arq_txn_txn_exp_bound", "approve", "bob");
    const body = (await (
      await postTransaction({ transaction_authorization_id: init.transaction_authorization_id })
    ).json()) as { access_token: string };
    const claims = decodeJwt(body.access_token);
    const challengeExp = decodeJwt(challenge).exp as number;
    expect(claims.exp as number).toBeLessThanOrEqual(Math.floor(Date.now() / 1000) + MAX_TOKEN_LIFETIME_S);
    // Not clamped to the challenge: the approval TTL is what binds here.
    expect(claims.exp).not.toBe(challengeExp);
  });
});

describe("challenge trust boundaries (@spec txn-authorization#two-phase-expiry)", () => {
  it("refuses a challenge signed by another issuer's key under this resource's iss", async () => {
    const foreign = await generateKeyPair("ES256", { extractable: true });
    const record = as.kernel.get(missionId) as { authority_set: AuthorityEntry[] };
    const challenge = await signChallenge(
      {
        txn: "txn_cross_issuer",
        authorization_details: record.authority_set
          .filter((e) => e.actions.includes("payments:remittance.send"))
          .map((e) => ({ ...e, actions: ["payments:remittance.send"] })),
        iss: RESOURCE,
        aud: ISSUER,
        reason: "action_approval_required",
        parameter_digest: "sha-256:cross-issuer",
      },
      foreign.privateKey,
      "rs-txn",
    );
    const res = await submit(challenge);
    const body = (await res.json()) as { error?: string; error_description?: string };
    expect(res.status).toBe(400);
    expect(body.error_description).toContain("invalid_signature");
  });

  it("refuses a challenge from an issuer this TAS does not accept", async () => {
    const challenge = await signChallenge(
      {
        txn: "txn_unknown_issuer",
        authorization_details: [
          { type: "mission_resource_access", resource: "https://elsewhere.test/mcp", actions: ["x"] },
        ],
        iss: "https://elsewhere.test/mcp",
        aud: ISSUER,
        reason: "action_approval_required",
        parameter_digest: "sha-256:elsewhere",
      },
      rsTxnKeys.privateKey,
      "rs-txn",
    );
    const res = await submit(challenge);
    const body = (await res.json()) as { error_description?: string };
    expect(body.error_description).toContain("unknown_issuer");
  });

  it("refuses an unauthenticated client and a proof of the wrong key", async () => {
    const challenge = await signChallenge(
      {
        txn: "txn_auth_guards",
        authorization_details: (as.kernel.get(missionId) as { authority_set: AuthorityEntry[] }).authority_set
          .filter((e) => e.actions.includes("payments:remittance.send"))
          .map((e) => ({ ...e, actions: ["payments:remittance.send"] })),
        iss: RESOURCE,
        aud: ISSUER,
        reason: "action_approval_required",
        parameter_digest: "sha-256:auth-guards",
      },
      rsTxnKeys.privateKey,
      "rs-txn",
    );
    const unauth = await postTransaction(
      {
        transaction_challenge: challenge,
        subject_token: baseToken,
        subject_token_type: "urn:ietf:params:oauth:token-type:access_token",
      },
      { omitClientAuth: true },
    );
    expect(unauth.status).toBe(401);
    expect((await unauth.json()).error).toBe("invalid_client");

    // A proof of a key the challenge never committed to.
    const otherKeys = await generateKeyPair("ES256", { extractable: true });
    const wrongKey = await submit(challenge, { keys: otherKeys });
    const body = (await wrongKey.json()) as { error?: string; error_description?: string };
    expect(wrongKey.status).toBe(400);
    expect(body.error).toBe("invalid_grant");
    expect(body.error_description).toContain("same key");
  });
});

describe("fresh decision at completion (@spec txn-authorization#challenge-redemption)", () => {
  const requested = (): AuthorityEntry[] =>
    (as.kernel.get(missionId) as { authority_set: AuthorityEntry[] }).authority_set
      .filter((e) => e.actions.includes("payments:remittance.send"))
      .map((e) => ({ ...e, actions: ["payments:remittance.send"] }));

  const admit = async (txn: string, over: Record<string, unknown> = {}) => {
    const challenge = await signChallenge(
      {
        txn,
        authorization_details: requested(),
        iss: RESOURCE,
        aud: ISSUER,
        reason: "action_approval_required",
        parameter_digest: `sha-256:${txn}`,
        ...over,
      },
      rsTxnKeys.privateKey,
      "rs-txn",
    );
    const body = (await (await submit(challenge)).json()) as { transaction_authorization_id: string };
    return body.transaction_authorization_id;
  };

  it("refuses an approved workflow when current entitlement or policy denies", async () => {
    policyDeniesTxns.add("txn_policy_denies");
    const id = await admit("txn_policy_denies");
    const approval = await ars.adjudicate("arq_txn_txn_policy_denies", "approve", "bob");
    expect(approval).not.toBeNull();

    const res = await postTransaction({ transaction_authorization_id: id });
    const body = (await res.json()) as { error?: string; error_description?: string; access_token?: string };
    expect(res.status).toBe(400);
    expect(body.error).toBe("access_denied");
    expect(body.error_description).toBe("entitlement_denied");
    expect(body.access_token).toBeUndefined();
    // The decision ran: completing the approval did not bypass it.
    expect(freshDecisionCalls).toContain("txn_policy_denies");
  });

  it("never issues on a step-up context alone: only approval state satisfies the requirement", async () => {
    // The subject_token carries a stronger authentication context; the workflow
    // is admitted and never approved. No amount of polling issues a token.
    const id = await admit("txn_stepup_only");
    for (let i = 0; i < 3; i++) {
      const res = await postTransaction({ transaction_authorization_id: id });
      const body = (await res.json()) as { error?: string; access_token?: string };
      expect(res.status).toBe(400);
      expect(body.error).toBe("authorization_pending");
      expect(body.access_token).toBeUndefined();
    }
    // And the fresh decision was never even reached without an approval.
    expect(freshDecisionCalls).not.toContain("txn_stepup_only");
  });

  it("refuses after containment narrows the entry away between admission and approval", async () => {
    const id = await admit("txn_contained_after_admission");
    as.kernel.contain(missionId, {
      event: {
        type: "vendor.compromise",
        source: "svc:test",
        observed_at: new Date().toISOString(),
        event_id: "ev_txn_contained",
      },
      remove: [{ resource: RESOURCE, actions: ["payments:remittance.send"] }],
    });
    await ars.adjudicate("arq_txn_txn_contained_after_admission", "approve", "bob");
    const res = await postTransaction({ transaction_authorization_id: id });
    const body = (await res.json()) as { error?: string; error_description?: string };
    expect(res.status).toBe(400);
    expect(body.error).toBe("access_denied");
    expect(body.error_description).toContain("effective Authority Set");
  });
});
