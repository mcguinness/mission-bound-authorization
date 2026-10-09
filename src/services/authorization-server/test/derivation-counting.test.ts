/**
 * @spec mission#issuance-gating — Derivation Limits `#counted-operations`: "A
 * derivation that fails, including one refused for exceeding the bound, MUST
 * NOT be counted" (#914 ruling 1). These tests inject a failure AFTER a
 * derivation passed the cap check, on two paths with different counting
 * mechanics:
 *
 * - the async-delegation creating exchange counts inside the transaction that
 *   commits the family: a failure before that commit rolls the count back;
 * - the provider access-token hook (`extraTokenClaims`, used by the code
 *   exchange, refresh, deferred, child redemption, dispatch and the expansion
 *   successor mint) commits the count BEFORE the token is signed and has no
 *   rollback or reservation, so a failure after the count leaves the failed
 *   derivation counted. That test documents the residual (#250); it is not
 *   evidence the clause holds.
 */
import { TEST_APPROVAL_PRINCIPALS, trustedApprovalHeaders } from "./approval-fixture.js";

import { type Server } from "node:http";
import { CANONICAL_RESOURCE } from "@mission/demo-data";
import { exportJWK, generateKeyPair, importJWK, SignJWT } from "jose";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { ACCESS_TOKEN_TOKEN_TYPE, TOKEN_EXCHANGE_GRANT_TYPE } from "../src/adapters/continuation-grant.js";
import { buildAuthorizationServer, type BuiltAs } from "../src/index.js";
import { delegationHandleParams } from "./delegation-handle.helper.js";

const PORT = 14787;
const ISSUER = `http://localhost:${PORT}`;
const REDIRECT_URI = "http://localhost:9999/cb";
const RESOURCE = CANONICAL_RESOURCE;
const FAR_EXP = "2027-06-01T00:00:00Z";
const VERIFIER = "derivation-counting-verifier-0123456789-0123456789-0";
const READ = [{ type: "mission_resource_access", resource: RESOURCE, actions: ["payments:invoice.read"] }];

type Keys = { privateKey: CryptoKey; publicKey: CryptoKey };
type Json = Record<string, unknown>;

let as: BuiltAs;
let server: Server;
let clientKey: CryptoKey;

async function newKeys(): Promise<Keys> {
  return (await generateKeyPair("ES256", { extractable: true })) as Keys;
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

async function dpopProof(keys: Keys, extra: Json = {}): Promise<string> {
  return new SignJWT({ htu: `${ISSUER}/token`, htm: "POST", ...extra })
    .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: await exportJWK(keys.publicKey) })
    .setIssuedAt()
    .setJti(crypto.randomUUID())
    .sign(keys.privateKey);
}

async function token(params: Record<string, string>, keys: Keys): Promise<{ status: number; body: Json }> {
  const send = async (extra: Json = {}) =>
    fetch(`${ISSUER}/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", dpop: await dpopProof(keys, extra) },
      body: new URLSearchParams({
        ...params,
        client_assertion: await clientAssertion(),
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      }).toString(),
    });
  let res = await send();
  const nonce = res.headers.get("dpop-nonce");
  if (res.status === 400 && nonce) res = await send({ nonce });
  return { status: res.status, body: (await res.json()) as Json };
}

/** PAR and approval: an authorization code under a new, active Mission. */
async function issueCode(intentOver: Json = {}): Promise<{ code: string; missionId: string; keys: Keys }> {
  const challenge = Buffer.from(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(VERIFIER)),
  ).toString("base64url");
  const par = await fetch(`${ISSUER}/request`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: "ap-agent",
      response_type: "code",
      redirect_uri: REDIRECT_URI,
      resource: RESOURCE,
      code_challenge: challenge,
      code_challenge_method: "S256",
      login_hint: "alice",
      mission_intent: JSON.stringify({
        intent: { goal: "Read Acme invoices", target_resources: [RESOURCE], expires_at: FAR_EXP, ...intentOver },
      }),
      authorization_details: JSON.stringify(READ),
      client_assertion: await clientAssertion(),
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    }).toString(),
  });
  const pushed = (await par.json()) as Json;
  expect(par.status, JSON.stringify(pushed)).toBe(201);
  const jar = new Map<string, string>();
  const keep = (res: Response) => {
    for (const line of res.headers.getSetCookie()) {
      const [pair] = line.split(";");
      const eq = (pair as string).indexOf("=");
      jar.set((pair as string).slice(0, eq), (pair as string).slice(eq + 1));
    }
  };
  const cookie = () => [...jar].map(([k, v]) => `${k}=${v}`).join("; ");
  let res = await fetch(
    `${ISSUER}/auth?${new URLSearchParams({ client_id: "ap-agent", request_uri: String(pushed.request_uri) })}`,
    { redirect: "manual" },
  );
  keep(res);
  const uid = (res.headers.get("location") ?? "").split("/interaction/")[1] as string;
  res = await fetch(`${ISSUER}/interaction/${uid}/decide`, {
    method: "POST",
    redirect: "manual",
    headers: { ...trustedApprovalHeaders(), "content-type": "application/json", cookie: cookie() },
    body: JSON.stringify({ decision: "approve" }),
  });
  keep(res);
  let location = res.headers.get("location") ?? "";
  while (location.startsWith(ISSUER)) {
    res = await fetch(location, { redirect: "manual", headers: { cookie: cookie() } });
    keep(res);
    location = res.headers.get("location") ?? "";
  }
  const code = new URL(location).searchParams.get("code") as string;
  const stored = (await as.provider.AuthorizationCode.find(code)) as { grantId: string };
  const missionId = as.kernel.findByGrant(stored.grantId)?.id as string;
  return { code, missionId, keys: await newKeys() };
}

/** PAR, approval and the code exchange: an active Mission's access and refresh token. */
/**
 * The acting client's delegation handle for `base` (#1157, D358), the async
 * transport's subject_token, requested under the base token's own key.
 */
async function handle(base: string, keys: Keys): Promise<string> {
  const res = await token(delegationHandleParams(base, "ap-agent"), keys);
  if (res.status !== 200) throw new Error(`delegation handle refused: ${res.status} ${JSON.stringify(res.body)}`);
  return res.body.access_token as string;
}

async function issue(intentOver: Json = {}): Promise<{
  missionId: string;
  accessToken: string;
  refreshToken: string;
  keys: Keys;
}> {
  const { code, keys } = await issueCode(intentOver);
  const exchanged = await token(
    { grant_type: "authorization_code", code, redirect_uri: REDIRECT_URI, code_verifier: VERIFIER, resource: RESOURCE },
    keys,
  );
  expect(exchanged.status, JSON.stringify(exchanged.body)).toBe(200);
  const accessToken = exchanged.body.access_token as string;
  const claims = JSON.parse(Buffer.from(accessToken.split(".")[1] as string, "base64url").toString()) as {
    mission: { id: string };
  };
  return { missionId: claims.mission.id, accessToken, refreshToken: exchanged.body.refresh_token as string, keys };
}

/** The Mission's derivation count. */
const derivations = (missionId: string) => as.kernel.get(missionId)?.derivation_count;

beforeAll(async () => {
  as = await buildAuthorizationServer({
    issuer: ISSUER,
    allowHeadlessAdjudication: true,
    serviceTokenPrincipals: TEST_APPROVAL_PRINCIPALS,
  });
  server = as.provider.listen(PORT);
  await new Promise<void>((r) => server.once("listening", () => r()));
  clientKey = (await importJWK(as.agentClientJwk as never, "ES256")) as CryptoKey;
});

afterAll(async () => {
  await new Promise<void>((r) => server.close(() => r()));
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("a derivation that fails after admission (@spec mission#issuance-gating, #914 ruling 1)", () => {
  it("async-delegation creating exchange: a failure after the cap check, inside the commit, rolls the count back", async () => {
    const m = await issue();
    expect(derivations(m.missionId)).toBe(1); // the code exchange
    // #1157: the delegation handle is requested first, its own counted derivation.
    const subject = await handle(m.accessToken, m.keys);
    expect(derivations(m.missionId)).toBe(2);
    // The exchange runs gateDerivation inside advanceReserved's transaction,
    // which also commits the family-created transition. Fail that transaction
    // after the gate has passed and counted.
    const advance = as.creationIdempotency.advanceReserved.bind(as.creationIdempotency);
    let gated = false;
    vi.spyOn(as.creationIdempotency, "advanceReserved").mockImplementation((clientId, crid, delivery, accompany) =>
      advance(clientId, crid, delivery, () => {
        accompany?.();
        gated = true;
        throw new Error("injected: the family-created write fails after the gate");
      }),
    );
    const acting = m.keys;
    const res = await token(
      {
        grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
        request_refresh_token: "true",
        subject_token: subject,
        subject_token_type: ACCESS_TOKEN_TOKEN_TYPE,
        resource: RESOURCE,
        creation_request_id: crypto.randomUUID(),
      },
      acting,
    );
    expect(gated).toBe(true); // the cap check passed and the count ran
    expect(res.status).toBeGreaterThanOrEqual(400);
    expect(res.body.access_token).toBeUndefined();
    expect(derivations(m.missionId)).toBe(2); // rolled back with the transaction
  });

  it("residual: the provider access-token hook counts before signing, so a code exchange that fails after the count leaves the failed derivation counted (#250)", async () => {
    const pushed = await issueCode();
    const missionId = pushed.missionId;
    const before = derivations(missionId);
    // A failure after extraTokenClaims counted and the token was signed, but
    // before it is delivered: a throwing `access_token.issued` listener (the
    // same event the issuance index listens on).
    const fail = () => {
      throw new Error("injected: post-count issuance failure");
    };
    as.provider.once("access_token.issued", fail);
    const res = await token(
      {
        grant_type: "authorization_code",
        code: pushed.code,
        redirect_uri: REDIRECT_URI,
        code_verifier: VERIFIER,
        resource: RESOURCE,
      },
      pushed.keys,
    );
    as.provider.removeListener("access_token.issued", fail);
    expect(res.status).toBeGreaterThanOrEqual(400);
    expect(res.body.access_token).toBeUndefined();
    // No token was delivered, yet the derivation is counted: the hook has no
    // rollback, reservation or acceptance callback (control-plane-deployment.md).
    expect(derivations(missionId)).toBe((before ?? 0) + 1);
  });
});
