/**
 * @spec mission#issuance-gating (#250): the release fence at the token route.
 *
 * The OAuth binding requires the AS to refuse a derivation request it answers
 * after it has acknowledged a revocation of the Mission. The AS answers when
 * it decides to release the result, so the reference re-reads Mission state
 * at the last synchronous point before the response leaves: after the
 * save-time gate, the signature, the refresh-token save, every response
 * wrapper and the request-path drain. Each revocation here commits inside the
 * issuing request, after the save-time gate passed:
 *  - from the `access_token.issued` event, which oidc-provider emits inside
 *    `AccessToken#save()` after the gate ran and the token was signed, and
 *    before the refresh-token save and the response;
 *  - or while the request-path drain runs, the last awaited step before the
 *    fence.
 * A lifecycle commit is acknowledged only after it commits, so each of these
 * is a revocation acknowledged after the request's own gate. Each test has a
 * control that delivers without the revocation. Only an ended Mission is
 * refused: a suspension committed at the same point still delivers.
 */

import type { Server } from "node:http";
import { CANONICAL_RESOURCE } from "@mission/demo-data";
import { exportJWK, generateKeyPair, importJWK, SignJWT } from "jose";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { ACCESS_TOKEN_TOKEN_TYPE, TOKEN_EXCHANGE_GRANT_TYPE } from "../src/adapters/continuation-grant.js";
import { type BuiltAs, buildAuthorizationServer } from "../src/index.js";
import { renderedRevision, TEST_APPROVAL_PRINCIPALS, trustedApprovalHeaders } from "./approval-fixture.js";
import { delegationHandleParams } from "./delegation-handle.helper.js";

const PORT = 14571;
const ISSUER = `http://localhost:${PORT}`;
const REDIRECT_URI = "http://localhost:9999/cb";
const RESOURCE = CANONICAL_RESOURCE;
const FAR_EXP = "2027-06-01T00:00:00Z";
const VERIFIER = "release-fence-verifier-0123456789-0123456789-0123456789";
const READ = [{ type: "mission_resource_access", resource: RESOURCE, actions: ["payments:invoice.read"] }];

/** The only members a refusal carries: no token member survives the fence. */
const REFUSAL_MEMBERS = ["error", "error_description", "mission_error"];

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

async function dpopProof(keys: Keys): Promise<string> {
  return new SignJWT({ htu: `${ISSUER}/token`, htm: "POST" })
    .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: await exportJWK(keys.publicKey) })
    .setIssuedAt()
    .setJti(crypto.randomUUID())
    .sign(keys.privateKey);
}

/** One token request, sent once: a retry would turn a refused code exchange into code reuse. */
async function token(params: Record<string, string>, keys: Keys): Promise<{ status: number; body: Json }> {
  const res = await fetch(`${ISSUER}/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", dpop: await dpopProof(keys) },
    body: new URLSearchParams({
      ...params,
      client_assertion: await clientAssertion(),
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    }).toString(),
  });
  return { status: res.status, body: (await res.json()) as Json };
}

/** PAR and the approval: an active Mission's authorization code. */
async function authorize(): Promise<string> {
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
        intent: { goal: "Read Acme invoices", target_resources: [RESOURCE], expires_at: FAR_EXP },
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
  const decideHeaders = { ...trustedApprovalHeaders(), "content-type": "application/json", cookie: cookie() };
  const render_revision = await renderedRevision(ISSUER, uid, decideHeaders);
  res = await fetch(`${ISSUER}/interaction/${uid}/decide`, {
    method: "POST",
    redirect: "manual",
    headers: decideHeaders,
    body: JSON.stringify({ decision: "approve", render_revision }),
  });
  keep(res);
  let location = res.headers.get("location") ?? "";
  while (location.startsWith(ISSUER)) {
    res = await fetch(location, { redirect: "manual", headers: { cookie: cookie() } });
    keep(res);
    location = res.headers.get("location") ?? "";
  }
  return new URL(location).searchParams.get("code") as string;
}

const exchange = (code: string, keys: Keys) =>
  token(
    { grant_type: "authorization_code", code, redirect_uri: REDIRECT_URI, code_verifier: VERIFIER, resource: RESOURCE },
    keys,
  );

/** The code exchange, delivered: an active Mission's access and refresh token. */
async function issue(): Promise<{ missionId: string; accessToken: string; refreshToken: string; keys: Keys }> {
  const keys = await newKeys();
  const exchanged = await exchange(await authorize(), keys);
  expect(exchanged.status, JSON.stringify(exchanged.body)).toBe(200);
  const accessToken = exchanged.body.access_token as string;
  return {
    missionId: missionOf(accessToken),
    accessToken,
    refreshToken: exchanged.body.refresh_token as string,
    keys,
  };
}

function missionOf(accessToken: string): string {
  const claims = JSON.parse(Buffer.from(accessToken.split(".")[1] as string, "base64url").toString()) as {
    mission: { id: string };
  };
  return claims.mission.id;
}

const refresh = (refreshToken: string, keys: Keys) =>
  token({ grant_type: "refresh_token", refresh_token: refreshToken }, keys);

/** The delegation-handle request (#1157): an exchange of the Mission's access token, under its own key. */
async function delegationHandle(baseAccessToken: string, keys: Keys): Promise<string> {
  const handle = await token(delegationHandleParams(baseAccessToken, "ap-agent"), keys);
  expect(handle.status, JSON.stringify(handle.body)).toBe(200);
  return handle.body.access_token as string;
}

/** The async-delegation exchange that opens a family over a delegation handle. */
const openFamily = (handle: string, keys: Keys) =>
  token(
    {
      grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
      request_refresh_token: "true",
      subject_token: handle,
      subject_token_type: ACCESS_TOKEN_TOKEN_TYPE,
      resource: RESOURCE,
      creation_request_id: crypto.randomUUID(),
    },
    keys,
  );

/**
 * Commit `op` on the Mission of the next access token oidc-provider issues,
 * from inside its `save()`: after the save-time gate and the signature,
 * before the refresh-token save and the response. Returns the Mission it
 * committed on, once it has.
 */
function commitAtNextIssue(op: "revoke" | "suspend"): { missionId: () => string | undefined } {
  let committed: string | undefined;
  const listener = (at: { extra?: { mission?: { id?: string } } }) => {
    const id = at.extra?.mission?.id as string;
    as.kernel.transition(id, op);
    committed = id;
  };
  armed.push(listener);
  as.provider.once("access_token.issued", listener);
  return { missionId: () => committed };
}

/** Listeners a test armed; removed after it, fired or not. */
const armed: Array<(at: { extra?: { mission?: { id?: string } } }) => void> = [];

/** The refusal carries exactly the error members, and no token member. */
function expectNoTokenMaterial(body: Json): void {
  expect(Object.keys(body).sort()).toEqual(REFUSAL_MEMBERS);
  for (const member of ["access_token", "refresh_token", "issued_token_type", "token_type", "expires_in", "scope", "id_token", "mission_id", "mission_expires_at", "authorization_details"]) {
    expect(Object.hasOwn(body, member), member).toBe(false);
  }
}

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
  for (const listener of armed.splice(0)) as.provider.removeListener("access_token.issued", listener as never);
});

describe("the release fence: a revocation committed after the save-time gate refuses at release (@spec mission#issuance-gating, #250)", () => {
  it("code exchange: a revocation committed after the gate and the signature is refused invalid_grant with mission_error revoked and no token member, where the same exchange without it delivers", async () => {
    const control = await exchange(await authorize(), await newKeys());
    expect(control.status, JSON.stringify(control.body)).toBe(200);
    expect(typeof control.body.access_token).toBe("string");
    expect(typeof control.body.refresh_token).toBe("string");

    const code = await authorize();
    const committed = commitAtNextIssue("revoke");
    const res = await exchange(code, await newKeys());
    const missionId = committed.missionId() as string;
    expect(missionId).toBeDefined();
    expect(as.kernel.get(missionId)?.termination?.reason).toBe("revoked");
    expect(res.status, JSON.stringify(res.body)).toBe(400);
    expect(res.body.error).toBe("invalid_grant");
    expect(res.body.mission_error).toBe("revoked");
    expectNoTokenMaterial(res.body);
  });

  it("refresh: a revocation committed after the gate and the signature is refused invalid_grant with mission_error revoked and no token member, where the same refresh without it delivers", async () => {
    const control = await issue();
    const delivered = await refresh(control.refreshToken, control.keys);
    expect(delivered.status, JSON.stringify(delivered.body)).toBe(200);
    expect(typeof delivered.body.access_token).toBe("string");

    const m = await issue();
    const committed = commitAtNextIssue("revoke");
    const res = await refresh(m.refreshToken, m.keys);
    expect(committed.missionId()).toBe(m.missionId);
    expect(as.kernel.get(m.missionId)?.termination?.reason).toBe("revoked");
    expect(res.status, JSON.stringify(res.body)).toBe(400);
    expect(res.body.error).toBe("invalid_grant");
    expect(res.body.mission_error).toBe("revoked");
    expectNoTokenMaterial(res.body);
  });

  it("Token Exchange: an async-delegation exchange whose Mission is revoked after the gate and the signature is refused invalid_request with mission_error revoked and no token member (D369), where the same exchange without it delivers", async () => {
    const control = await issue();
    const opened = await openFamily(await delegationHandle(control.accessToken, control.keys), control.keys);
    expect(opened.status, JSON.stringify(opened.body)).toBe(200);
    expect(typeof opened.body.access_token).toBe("string");
    expect(typeof opened.body.refresh_token).toBe("string");

    const m = await issue();
    const handle = await delegationHandle(m.accessToken, m.keys);
    const committed = commitAtNextIssue("revoke");
    const res = await openFamily(handle, m.keys);
    expect(committed.missionId()).toBe(m.missionId);
    expect(as.kernel.get(m.missionId)?.termination?.reason).toBe("revoked");
    expect(res.status, JSON.stringify(res.body)).toBe(400);
    expect(res.body.error).toBe("invalid_request");
    expect(res.body.mission_error).toBe("revoked");
    expectNoTokenMaterial(res.body);
  });

  it("a revocation committed while the request-path drain runs, the last awaited step before release, is still refused invalid_grant with mission_error revoked and no token member", async () => {
    const m = await issue();
    const drain = as.kernel.drainLifecycleOutbox.bind(as.kernel);
    let committed = false;
    vi.spyOn(as.kernel, "drainLifecycleOutbox").mockImplementation(async () => {
      if (!committed) {
        committed = true;
        as.kernel.transition(m.missionId, "revoke"); // commits inside the refresh's own drain
      }
      return drain();
    });
    const res = await refresh(m.refreshToken, m.keys);
    vi.restoreAllMocks();
    expect(committed).toBe(true);
    expect(as.kernel.get(m.missionId)?.termination?.reason).toBe("revoked");
    expect(res.status, JSON.stringify(res.body)).toBe(400);
    expect(res.body.error).toBe("invalid_grant");
    expect(res.body.mission_error).toBe("revoked");
    expectNoTokenMaterial(res.body);
  });
});

describe("the release fence refuses only an ended Mission (@spec mission#issuance-gating, #250)", () => {
  it("a suspension committed at the same point, after the gate and the signature, still delivers the code exchange's tokens", async () => {
    const code = await authorize();
    const committed = commitAtNextIssue("suspend");
    const res = await exchange(code, await newKeys());
    const missionId = committed.missionId() as string;
    expect(missionId).toBeDefined();
    expect(as.kernel.get(missionId)?.state).toBe("suspended");
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(typeof res.body.access_token).toBe("string");
    expect(typeof res.body.refresh_token).toBe("string");
    expect(missionOf(res.body.access_token as string)).toBe(missionId);
  });

  it("a suspension committed while the request-path drain runs still delivers the refresh", async () => {
    const m = await issue();
    const drain = as.kernel.drainLifecycleOutbox.bind(as.kernel);
    let committed = false;
    vi.spyOn(as.kernel, "drainLifecycleOutbox").mockImplementation(async () => {
      if (!committed) {
        committed = true;
        as.kernel.transition(m.missionId, "suspend");
      }
      return drain();
    });
    const res = await refresh(m.refreshToken, m.keys);
    vi.restoreAllMocks();
    expect(committed).toBe(true);
    expect(as.kernel.get(m.missionId)?.state).toBe("suspended");
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(typeof res.body.access_token).toBe("string");
  });
});
