/**
 * A reusable OAuth client that drives REAL mission issuance against a running
 * authorization server: PAR -> authorize -> headless interaction/decide ->
 * token, with DPoP sender-constraint, private_key_jwt client authentication,
 * PKCE, and the mandatory dpop-nonce retry. Ported faithfully from the
 * canonical tracer.test.ts so the exhibit prints the same artifacts the tests
 * prove. Returns the real access_token and id_token plus the DPoP key material
 * (so the caller can build resource-side proofs that match cnf.jkt).
 */

import { calculateJwkThumbprint, exportJWK, generateKeyPair, importJWK, SignJWT, type JWK } from "jose";
import { CANONICAL_RESOURCE } from "@mission/demo-data";

const REDIRECT_URI = "http://localhost:9999/cb";
const CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/** ES256 DPoP keypair the caller holds for the life of a mission credential. */
export interface DpopKeys {
  privateKey: CryptoKey;
  publicKey: CryptoKey;
}

export interface IssueOpts {
  /**
   * The untrusted `mission_intent` parameter VALUE, carried via PAR: the
   * Mission Intent Submission envelope `{intent, evidence?}` as a JSON string
   * (the semantic task context is its `intent` member).
   */
  missionIntent: string;
  /**
   * @spec mission#authority-proposal — the authority proposal: a JSON string
   * carrying the standard RFC 9396 authorization_details array, pushed through
   * PAR alongside mission_intent. Optional: absent means template-mode
   * derivation (task + policy alone).
   */
  authorizationDetails?: string;
  /** Requested scope (e.g. "openid payments" to also receive an id_token). */
  scope: string;
}

/** The raw request params + responses at each leg, for the exhibit to print. */
export interface IssueArtifacts {
  par: { request: Record<string, string>; response: { request_uri: string } };
  decide: { request: { decision: string; approver: string; subject: string }; code: string };
  token: { request: Record<string, string>; response: Record<string, unknown> };
}

export interface IssuedMission {
  accessToken: string;
  /** Present when scope includes "openid" (identifies the user to the client). */
  idToken?: string;
  dpopKeys: DpopKeys;
  dpopJkt: string;
  artifacts: IssueArtifacts;
}

/**
 * The interaction session's cookie jar. The AS resolves an in-flight interaction
 * from its cookie alone, so submit -> complete/deny MUST carry the same jar; a
 * per-approval jar keeps concurrent submits from resolving each other's session.
 */
export type CookieJar = Map<string, string>;

/** The half-completed approval submit hands to complete/deny (jar + uid + PAR). */
export interface SubmittedApproval {
  /** The interaction uid the approver decides against. */
  uid: string;
  /** The per-approval cookie jar (interaction session). */
  jar: CookieJar;
  /** PAR artifacts, carried forward so complete can assemble IssuedMission.artifacts. */
  par: { request: Record<string, string>; response: { request_uri: string } };
}

/** PKCE verifier reused across submit/complete: PKCE binds verifier<->challenge
 * per code, not uniqueness across requests, so a constant is safe for concurrency. */
const PKCE_VERIFIER = "exhibit-verifier-0123456789-0123456789-0123456789";
const pkceChallenge = async (): Promise<string> =>
  Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(PKCE_VERIFIER))).toString("base64url");

/** Cookie-jar accessors over a caller-owned Map (so the jar round-trips by reference). */
function jarClosures(cookies: CookieJar): { cookieHeader: () => string; storeCookies: (res: Response) => void } {
  const cookieHeader = (): string => [...cookies.entries()].map(([k, v]) => `${k}=${v}`).join("; ");
  const storeCookies = (res: Response): void => {
    for (const line of res.headers.getSetCookie()) {
      const [pair] = line.split(";");
      const eq = (pair as string).indexOf("=");
      cookies.set((pair as string).slice(0, eq), (pair as string).slice(eq + 1));
    }
  };
  return { cookieHeader, storeCookies };
}

/** private_key_jwt client-assertion signer for the agent confidential client. */
async function clientAssertionSigner(asUrl: string, agentClientJwk: Record<string, unknown>): Promise<() => Promise<string>> {
  const clientKey = (await importJWK(agentClientJwk as JWK, "ES256")) as CryptoKey;
  return () =>
    new SignJWT({})
      .setProtectedHeader({ alg: "ES256", kid: "ap-agent-auth" })
      .setIssuer("ap-agent")
      .setSubject("ap-agent")
      .setAudience(asUrl)
      .setIssuedAt()
      .setExpirationTime("2m")
      .setJti(crypto.randomUUID())
      .sign(clientKey);
}

/**
 * PAR -> authorize, stopping at the interaction (NO decide). Returns the uid +
 * the per-approval cookie jar + the PAR artifacts, so the approval can be parked
 * and completed (or denied) later by an out-of-band approver decision.
 */
export async function submitMissionApproval(
  asUrl: string,
  agentClientJwk: Record<string, unknown>,
  opts: IssueOpts,
): Promise<SubmittedApproval> {
  const cookies: CookieJar = new Map();
  const { storeCookies } = jarClosures(cookies);
  const clientAssertion = await clientAssertionSigner(asUrl, agentClientJwk);
  const challenge = await pkceChallenge();

  const parParams: Record<string, string> = {
    client_id: "ap-agent",
    response_type: "code",
    redirect_uri: REDIRECT_URI,
    scope: opts.scope,
    resource: CANONICAL_RESOURCE,
    code_challenge: challenge,
    code_challenge_method: "S256",
    mission_intent: opts.missionIntent,
    ...(opts.authorizationDetails ? { authorization_details: opts.authorizationDetails } : {}),
  };
  const parRes = await fetch(`${asUrl}/request`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      ...parParams,
      client_assertion: await clientAssertion(),
      client_assertion_type: CLIENT_ASSERTION_TYPE,
    }).toString(),
  });
  const parBody = (await parRes.json()) as { request_uri?: string; error?: string };
  if (parRes.status !== 201 || !parBody.request_uri) {
    throw new Error(`PAR failed: ${parRes.status} ${JSON.stringify(parBody)}`);
  }
  const requestUri = parBody.request_uri;

  const authUrl = `${asUrl}/auth?${new URLSearchParams({ client_id: "ap-agent", request_uri: requestUri })}`;
  const res = await fetch(authUrl, { redirect: "manual" });
  storeCookies(res);
  const location = res.headers.get("location") as string;
  if (!location?.includes("/interaction/")) {
    throw new Error(`authorize did not redirect to an interaction: ${location}`);
  }
  const uid = location.split("/interaction/")[1] as string;
  return { uid, jar: cookies, par: { request: parParams, response: { request_uri: requestUri } } };
}

/**
 * Complete a parked approval: decide(approve, bob/alice) -> follow the redirect
 * chain to the code -> DPoP-bound token exchange (with the dpop-nonce retry).
 * DPoP is introduced only at /token, so the keypair is generated here. Returns
 * the same IssuedMission shape issueMissionToken returns.
 */
export async function completeMissionApproval(
  asUrl: string,
  agentClientJwk: Record<string, unknown>,
  opts: { uid: string; jar: CookieJar; par?: SubmittedApproval["par"] },
): Promise<IssuedMission> {
  const { uid, jar } = opts;
  const { cookieHeader, storeCookies } = jarClosures(jar);
  const clientAssertion = await clientAssertionSigner(asUrl, agentClientJwk);

  const dpopKeys = await generateKeyPair("ES256", { extractable: true });
  const dpopPubJwk = await exportJWK(dpopKeys.publicKey);
  const dpopJkt = await calculateJwkThumbprint(dpopPubJwk);
  const dpopProof = (htu: string, htm: string, extra: Record<string, unknown> = {}): Promise<string> =>
    new SignJWT({ htu, htm, ...extra })
      .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: dpopPubJwk })
      .setIssuedAt()
      .setJti(crypto.randomUUID())
      .sign(dpopKeys.privateKey);

  // decide: Bob approves alice; follow the redirect chain to the code.
  const decideBody = { decision: "approve", approver: "bob", subject: "alice" };
  let res = await fetch(`${asUrl}/interaction/${uid}/decide`, {
    method: "POST",
    redirect: "manual",
    headers: { "content-type": "application/json", cookie: cookieHeader() },
    body: JSON.stringify(decideBody),
  });
  storeCookies(res);
  let location = res.headers.get("location") as string;
  while (location?.startsWith(asUrl)) {
    res = await fetch(location, { redirect: "manual", headers: { cookie: cookieHeader() } });
    storeCookies(res);
    location = res.headers.get("location") as string;
  }
  if (!location?.includes(`${REDIRECT_URI}?`)) {
    throw new Error(`interaction did not redirect back with a code: ${location}`);
  }
  const code = new URL(location).searchParams.get("code");
  if (!code) throw new Error("no authorization code on the redirect");

  const tokenParams: Record<string, string> = {
    grant_type: "authorization_code",
    code,
    redirect_uri: REDIRECT_URI,
    code_verifier: PKCE_VERIFIER,
    resource: CANONICAL_RESOURCE,
  };
  const tokenReq = async (extra: Record<string, unknown> = {}): Promise<Response> =>
    fetch(`${asUrl}/token`, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        dpop: await dpopProof(`${asUrl}/token`, "POST", extra),
      },
      body: new URLSearchParams({
        ...tokenParams,
        client_assertion: await clientAssertion(),
        client_assertion_type: CLIENT_ASSERTION_TYPE,
      }).toString(),
    });
  let tokenRes = await tokenReq();
  const nonce = tokenRes.headers.get("dpop-nonce");
  if (tokenRes.status === 400 && nonce) tokenRes = await tokenReq({ nonce });
  const tokenBody = (await tokenRes.json()) as Record<string, unknown>;
  if (tokenRes.status !== 200) {
    throw new Error(`token exchange failed: ${tokenRes.status} ${JSON.stringify(tokenBody)}`);
  }
  const accessToken = tokenBody.access_token as string;
  const idToken = tokenBody.id_token as string | undefined;
  return {
    accessToken,
    ...(idToken ? { idToken } : {}),
    dpopKeys,
    dpopJkt,
    artifacts: {
      par: opts.par ?? { request: {}, response: { request_uri: "" } },
      decide: { request: decideBody, code },
      token: { request: tokenParams, response: tokenBody },
    },
  };
}

/**
 * Deny a parked approval: decide(deny) with the interaction jar so the AS
 * finishes the interaction (access_denied) instead of leaving it dangling.
 * Follows the terminal redirect chain (~access_denied) to fully settle it.
 */
export async function denyMissionApproval(asUrl: string, opts: { uid: string; jar: CookieJar }): Promise<void> {
  const { uid, jar } = opts;
  const { cookieHeader, storeCookies } = jarClosures(jar);
  let res = await fetch(`${asUrl}/interaction/${uid}/decide`, {
    method: "POST",
    redirect: "manual",
    headers: { "content-type": "application/json", cookie: cookieHeader() },
    body: JSON.stringify({ decision: "deny", approver: "bob", subject: "alice" }),
  });
  storeCookies(res);
  let location = res.headers.get("location") as string;
  while (location?.startsWith(asUrl)) {
    res = await fetch(location, { redirect: "manual", headers: { cookie: cookieHeader() } });
    storeCookies(res);
    location = res.headers.get("location") as string;
  }
}

/**
 * Drive the full authorization-code + DPoP dance and return the issued tokens.
 * Bob approves alice's mission at the headless interaction (write-bearing
 * missions need a distinct approver).
 */
export async function issueMissionToken(
  asUrl: string,
  agentClientJwk: Record<string, unknown>,
  opts: IssueOpts,
): Promise<IssuedMission> {
  // Per-issuance cookie jar (the interaction session rides cookies).
  const cookies = new Map<string, string>();
  const cookieHeader = (): string => [...cookies.entries()].map(([k, v]) => `${k}=${v}`).join("; ");
  const storeCookies = (res: Response): void => {
    for (const line of res.headers.getSetCookie()) {
      const [pair] = line.split(";");
      const eq = (pair as string).indexOf("=");
      cookies.set((pair as string).slice(0, eq), (pair as string).slice(eq + 1));
    }
  };

  // DPoP key: exported ONCE (never pass the export Promise into a header).
  const dpopKeys = await generateKeyPair("ES256", { extractable: true });
  const dpopPubJwk = await exportJWK(dpopKeys.publicKey);
  const dpopJkt = await calculateJwkThumbprint(dpopPubJwk);
  // The agent's confidential client key (private_key_jwt signer).
  const clientKey = (await importJWK(agentClientJwk as JWK, "ES256")) as CryptoKey;

  const clientAssertion = (): Promise<string> =>
    new SignJWT({})
      .setProtectedHeader({ alg: "ES256", kid: "ap-agent-auth" })
      .setIssuer("ap-agent")
      .setSubject("ap-agent")
      .setAudience(asUrl)
      .setIssuedAt()
      .setExpirationTime("2m")
      .setJti(crypto.randomUUID())
      .sign(clientKey);

  const dpopProof = (htu: string, htm: string, extra: Record<string, unknown> = {}): Promise<string> =>
    new SignJWT({ htu, htm, ...extra })
      .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: dpopPubJwk })
      .setIssuedAt()
      .setJti(crypto.randomUUID())
      .sign(dpopKeys.privateKey);

  // PKCE: a >=43-char verifier; challenge = base64url(SHA-256(verifier)).
  const verifier = "exhibit-verifier-0123456789-0123456789-0123456789";
  const challenge = Buffer.from(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)),
  ).toString("base64url");

  // ---- PAR: push the request (with the mission_intent) -> request_uri -------
  const parParams: Record<string, string> = {
    client_id: "ap-agent",
    response_type: "code",
    redirect_uri: REDIRECT_URI,
    scope: opts.scope,
    resource: CANONICAL_RESOURCE,
    code_challenge: challenge,
    code_challenge_method: "S256",
    mission_intent: opts.missionIntent,
    ...(opts.authorizationDetails ? { authorization_details: opts.authorizationDetails } : {}),
  };
  const parRes = await fetch(`${asUrl}/request`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      ...parParams,
      client_assertion: await clientAssertion(),
      client_assertion_type: CLIENT_ASSERTION_TYPE,
    }).toString(),
  });
  const parBody = (await parRes.json()) as { request_uri?: string; error?: string };
  if (parRes.status !== 201 || !parBody.request_uri) {
    throw new Error(`PAR failed: ${parRes.status} ${JSON.stringify(parBody)}`);
  }
  const requestUri = parBody.request_uri;

  // ---- authorize: redirects to the interaction (manual redirects) -----------
  const authUrl = `${asUrl}/auth?${new URLSearchParams({ client_id: "ap-agent", request_uri: requestUri })}`;
  let res = await fetch(authUrl, { redirect: "manual" });
  storeCookies(res);
  let location = res.headers.get("location") as string;
  if (!location?.includes("/interaction/")) {
    throw new Error(`authorize did not redirect to an interaction: ${location}`);
  }
  const uid = location.split("/interaction/")[1] as string;

  // ---- decide: Bob approves alice; follow the redirect chain to the code ----
  const decideBody = { decision: "approve", approver: "bob", subject: "alice" };
  res = await fetch(`${asUrl}/interaction/${uid}/decide`, {
    method: "POST",
    redirect: "manual",
    headers: { "content-type": "application/json", cookie: cookieHeader() },
    body: JSON.stringify(decideBody),
  });
  storeCookies(res);
  location = res.headers.get("location") as string;
  while (location?.startsWith(asUrl)) {
    res = await fetch(location, { redirect: "manual", headers: { cookie: cookieHeader() } });
    storeCookies(res);
    location = res.headers.get("location") as string;
  }
  if (!location?.includes(`${REDIRECT_URI}?`)) {
    throw new Error(`interaction did not redirect back with a code: ${location}`);
  }
  const code = new URL(location).searchParams.get("code");
  if (!code) throw new Error("no authorization code on the redirect");

  // ---- token: DPoP-bound exchange, with the mandatory dpop-nonce retry ------
  const tokenParams: Record<string, string> = {
    grant_type: "authorization_code",
    code,
    redirect_uri: REDIRECT_URI,
    code_verifier: verifier,
    resource: CANONICAL_RESOURCE,
  };
  const tokenReq = async (extra: Record<string, unknown> = {}): Promise<Response> =>
    fetch(`${asUrl}/token`, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        dpop: await dpopProof(`${asUrl}/token`, "POST", extra),
      },
      body: new URLSearchParams({
        ...tokenParams,
        client_assertion: await clientAssertion(),
        client_assertion_type: CLIENT_ASSERTION_TYPE,
      }).toString(),
    });
  let tokenRes = await tokenReq();
  const nonce = tokenRes.headers.get("dpop-nonce");
  if (tokenRes.status === 400 && nonce) {
    tokenRes = await tokenReq({ nonce });
  }
  const tokenBody = (await tokenRes.json()) as Record<string, unknown>;
  if (tokenRes.status !== 200) {
    throw new Error(`token exchange failed: ${tokenRes.status} ${JSON.stringify(tokenBody)}`);
  }
  const accessToken = tokenBody.access_token as string;
  const idToken = tokenBody.id_token as string | undefined;

  return {
    accessToken,
    ...(idToken ? { idToken } : {}),
    dpopKeys,
    dpopJkt,
    artifacts: {
      par: { request: parParams, response: { request_uri: requestUri } },
      decide: { request: decideBody, code },
      token: { request: tokenParams, response: tokenBody },
    },
  };
}

/**
 * POST an arbitrary grant to the AS /token endpoint with private_key_jwt client
 * authentication + a DPoP proof (same DPoP key, so a minted token's cnf.jkt
 * matches), including the mandatory dpop-nonce retry. Used to drive custom grants
 * (e.g. the AROP deferred grant) over real HTTP. Returns status + parsed body.
 */
export async function tokenGrantRequest(
  asUrl: string,
  agentClientJwk: Record<string, unknown>,
  dpopKeys: DpopKeys,
  params: Record<string, string>,
): Promise<{ status: number; body: Record<string, unknown> }> {
  const htu = `${asUrl}/token`;
  const clientKey = (await importJWK(agentClientJwk as JWK, "ES256")) as CryptoKey;
  const dpopPubJwk = await exportJWK(dpopKeys.publicKey);
  const clientAssertion = (): Promise<string> =>
    new SignJWT({})
      .setProtectedHeader({ alg: "ES256", kid: "ap-agent-auth" })
      .setIssuer("ap-agent")
      .setSubject("ap-agent")
      .setAudience(asUrl)
      .setIssuedAt()
      .setExpirationTime("2m")
      .setJti(crypto.randomUUID())
      .sign(clientKey);
  const dpopProof = (extra: Record<string, unknown> = {}): Promise<string> =>
    new SignJWT({ htu, htm: "POST", ...extra })
      .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: dpopPubJwk })
      .setIssuedAt()
      .setJti(crypto.randomUUID())
      .sign(dpopKeys.privateKey);
  const send = async (extra: Record<string, unknown> = {}): Promise<Response> =>
    fetch(htu, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", dpop: await dpopProof(extra) },
      body: new URLSearchParams({
        ...params,
        client_assertion: await clientAssertion(),
        client_assertion_type: CLIENT_ASSERTION_TYPE,
      }).toString(),
    });
  let res = await send();
  const nonce = res.headers.get("dpop-nonce");
  if (res.status === 400 && nonce) res = await send({ nonce });
  return { status: res.status, body: (await res.json()) as Record<string, unknown> };
}

/**
 * Build a resource-side DPoP proof with the SAME DPoP key the token is bound to
 * (so the proof's jwk thumbprint matches the token's cnf.jkt). The resource
 * server verifies htu/htm against this proof.
 */
export async function dpopProofFor(dpopKeys: DpopKeys, htu: string, htm: string): Promise<string> {
  const jwk = await exportJWK(dpopKeys.publicKey);
  return new SignJWT({ htu, htm })
    .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk })
    .setIssuedAt()
    .setJti(crypto.randomUUID())
    .sign(dpopKeys.privateKey);
}
