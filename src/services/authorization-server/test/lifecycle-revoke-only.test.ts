/**
 * @spec status#conformance, status#mission-lifecycle-endpoint, status#idempotency (#1182, D378):
 * a deployment that serves the Mission Lifecycle endpoint with `revoke` alone.
 *
 * Built without `lifecycle-extended`, `status`, `status-list`, `discharge` and
 * `containment`, so the only lifecycle operation it serves is `revoke`. Covered:
 *  - a caller holding none of the Mission's tokens revokes it, and the refresh,
 *    the family refresh and a new exchange then refuse, issuing nothing;
 *  - a revoke landing after the refresh pre-check is still refused at the
 *    save-time gate, so a racing refresh either commits first or refuses;
 *  - every other operation is refused `invalid_request` before the Mission is
 *    looked up: the refusal is identical for a known and an unknown Mission;
 *  - the Mission Status operation is not served;
 *  - nonce replay, nonce mismatch, a fresh revoke of a revoked Mission, and a
 *    revoke of a completed or expired Mission;
 *  - an unauthorized caller gets the response an unknown Mission gets.
 */

import type { Server } from "node:http";
import { CANONICAL_RESOURCE, DEV_SERVICE_TOKEN } from "@mission/demo-data";
import { exportJWK, generateKeyPair, importJWK, SignJWT } from "jose";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { ACCESS_TOKEN_TOKEN_TYPE, TOKEN_EXCHANGE_GRANT_TYPE } from "../src/adapters/continuation-grant.js";
import {
  ALL_PROVIDER_CAPABILITIES,
  type BuiltAs,
  buildAuthorizationServer,
  MISSION_STATUS_SCOPE,
  type ProviderCapability,
} from "../src/index.js";
import { TEST_APPROVAL_PRINCIPALS, trustedApprovalHeaders } from "./approval-fixture.js";
import { delegationHandleParams } from "./delegation-handle.helper.js";

const PORT = 14797;
const ISSUER = `http://localhost:${PORT}`;
const REDIRECT_URI = "http://localhost:9999/cb";
const RESOURCE = CANONICAL_RESOURCE;
const FAR_EXP = "2027-06-01T00:00:00Z";
const VERIFIER = "revoke-only-verifier-0123456789-0123456789-0123456789";
const READ = [{ type: "mission_resource_access", resource: RESOURCE, actions: ["payments:invoice.read"] }];
/** A registered service caller that may read status but holds no lifecycle authorization. */
const READER_TOKEN = "revoke-only-reader-token";

/** The revoke-only deployment: every capability except the other lifecycle operations and the Status surfaces. */
const OFF: readonly ProviderCapability[] = ["lifecycle-extended", "status", "status-list", "discharge", "containment"];
const REVOKE_ONLY = new Set(ALL_PROVIDER_CAPABILITIES.filter((c) => !OFF.includes(c)));

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

/** PAR, approval and the code exchange: an active Mission's access and refresh token. */
async function issue(): Promise<{ missionId: string; accessToken: string; refreshToken: string; keys: Keys }> {
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
  const keys = await newKeys();
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

const refresh = (refreshToken: string, keys: Keys) =>
  token({ grant_type: "refresh_token", refresh_token: refreshToken }, keys);

/** The delegation-handle request (#1157): an exchange of the Mission's access token, under its own key. */
const handleRequest = (baseAccessToken: string, keys: Keys) =>
  token(delegationHandleParams(baseAccessToken, "ap-agent"), keys);

/** An async-delegation family over the Mission's access token, through its handle; it keeps the base token's key. */
async function delegate(baseAccessToken: string, keys: Keys): Promise<{ status: number; body: Json }> {
  const handle = await handleRequest(baseAccessToken, keys);
  expect(handle.status, JSON.stringify(handle.body)).toBe(200);
  return token(
    {
      grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
      request_refresh_token: "true",
      subject_token: handle.body.access_token as string,
      subject_token_type: ACCESS_TOKEN_TOKEN_TYPE,
      resource: RESOURCE,
      creation_request_id: crypto.randomUUID(),
    },
    keys,
  );
}

/** A Lifecycle request; the response's exact text and parsed body. */
async function lifecycle(
  missionId: string,
  body: Json,
  serviceToken: string = DEV_SERVICE_TOKEN,
): Promise<{ status: number; text: string; json: Json }> {
  const res = await fetch(`${ISSUER}/missions/${missionId}/lifecycle`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-service-token": serviceToken },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  return { status: res.status, text, json: JSON.parse(text) as Json };
}

/** Run `fn`, counting the access and refresh tokens oidc-provider saves meanwhile. */
async function countingSaves<T>(fn: () => Promise<T>): Promise<{ result: T; saved: number }> {
  let saved = 0;
  const onSaved = () => {
    saved += 1;
  };
  as.provider.on("access_token.saved", onSaved);
  as.provider.on("refresh_token.saved", onSaved);
  try {
    return { result: await fn(), saved };
  } finally {
    as.provider.removeListener("access_token.saved", onSaved);
    as.provider.removeListener("refresh_token.saved", onSaved);
  }
}

const lifecycleEvents = (missionId: string): number =>
  (
    as.kernel.db.prepare("SELECT COUNT(*) AS n FROM lifecycle_events WHERE mission_id = ?").get(missionId) as {
      n: number;
    }
  ).n;

beforeAll(async () => {
  as = await buildAuthorizationServer({
    issuer: ISSUER,
    allowHeadlessAdjudication: true,
    capabilities: REVOKE_ONLY,
    serviceTokenPrincipals: {
      ...TEST_APPROVAL_PRINCIPALS,
      [READER_TOKEN]: { principal_id: "svc:reader", scopes: [MISSION_STATUS_SCOPE] },
    },
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

describe("revoke-only Lifecycle deployment: revocation by a party holding no token (@spec status#conformance, mission#revocation, #1182)", () => {
  it("a security tool holding none of the Mission's tokens revokes it, and the refresh, the family refresh and a new exchange then refuse, issuing nothing", async () => {
    const m = await issue();
    // The family keeps the base token's key (#1157). Prove its refresh works
    // with that key before the revocation, so the refusal below is the
    // revocation's and not a key mismatch.
    const fam = await delegate(m.accessToken, m.keys);
    expect(fam.status, JSON.stringify(fam.body)).toBe(200);
    const usable = await refresh(fam.body.refresh_token as string, m.keys);
    expect(usable.status, JSON.stringify(usable.body)).toBe(200);
    const familyRefresh = usable.body.refresh_token as string;

    const revoked = await lifecycle(m.missionId, { operation: "revoke", nonce: crypto.randomUUID() });
    expect(revoked.status, revoked.text).toBe(200);
    expect(revoked.json).toMatchObject({ state: "terminated", termination: { reason: "revoked" } });
    const derivations = as.kernel.get(m.missionId)?.derivation_count;

    const after = await countingSaves(async () => [
      await refresh(m.refreshToken, m.keys),
      await refresh(familyRefresh, m.keys),
      await handleRequest(m.accessToken, m.keys),
    ]);
    for (const res of after.result) {
      expect(res.status, JSON.stringify(res.body)).toBe(400);
      expect(res.body.access_token).toBeUndefined();
      expect(res.body.refresh_token).toBeUndefined();
    }
    // Both refreshes, with the keys that worked before the revocation, refuse invalid_grant.
    expect(after.result[0]?.body.error).toBe("invalid_grant");
    expect(after.result[1]?.body.error).toBe("invalid_grant");
    expect(after.saved).toBe(0);
    expect(as.kernel.get(m.missionId)?.derivation_count).toBe(derivations);
  });

  it("a racing refresh either commits before the revoke or is refused: a revoke landing after the refresh pre-check is still refused at the save-time gate", async () => {
    const committedFirst = await issue();
    const first = await refresh(committedFirst.refreshToken, committedFirst.keys);
    expect(first.status, JSON.stringify(first.body)).toBe(200);
    await lifecycle(committedFirst.missionId, { operation: "revoke", nonce: crypto.randomUUID() });

    const raced = await issue();
    const precheck = as.kernel.checkDerivation.bind(as.kernel);
    vi.spyOn(as.kernel, "checkDerivation").mockImplementation((id: string) => {
      const record = precheck(id);
      as.kernel.transition(id, "revoke"); // the revoke commits after the pre-check passed
      return record;
    });
    const res = await countingSaves(() => refresh(raced.refreshToken, raced.keys));
    vi.restoreAllMocks();
    expect(res.result.status, JSON.stringify(res.result.body)).toBe(400);
    expect(res.result.body.error).toBe("invalid_grant");
    expect(res.result.body.mission_error).toBe("revoked");
    expect(res.result.body.access_token).toBeUndefined();
  });
});

describe("revoke-only Lifecycle deployment: operations outside the class (@spec status#mission-lifecycle-endpoint, #1182)", () => {
  it("refuses every operation the deployment has not adopted invalid_request before looking up the Mission, leaving it unchanged", async () => {
    const m = await issue();
    const before = as.kernel.get(m.missionId);
    for (const operation of ["suspend", "resume", "complete", "discharge", "contain"]) {
      const nonce = `nonce-${operation}`;
      const known = await lifecycle(m.missionId, { operation, nonce });
      const unknown = await lifecycle("msn_unknown_0000000000000000000000", { operation, nonce });
      expect(known.status, `${operation}: ${known.text}`).toBe(400);
      expect(known.json.error, operation).toBe("invalid_request");
      // The refusal names the deployment, not the Mission: a known and an
      // unknown Mission get the same response.
      expect(unknown.status, operation).toBe(known.status);
      expect(unknown.json, operation).toEqual(known.json);
    }
    const after = as.kernel.get(m.missionId);
    expect(after?.state).toBe("active");
    expect(after?.version).toBe(before?.version);
  });

  it("refuses an unrecognized or absent operation invalid_request before looking up the Mission", async () => {
    const m = await issue();
    const before = as.kernel.get(m.missionId);
    for (const body of [
      { operation: "unadopted_extension", nonce: "nonce-unrecognized" },
      { operation: "constructor", nonce: "nonce-prototype-key" },
      { nonce: "nonce-absent-operation" },
    ]) {
      const known = await lifecycle(m.missionId, body);
      const unknown = await lifecycle("msn_unknown_0000000000000000000000", body);
      expect(known.status, `${JSON.stringify(body)}: ${known.text}`).toBe(400);
      expect(known.json.error).toBe("invalid_request");
      expect(unknown.status).toBe(400);
      expect(unknown.json).toEqual(known.json);
    }
    const after = as.kernel.get(m.missionId);
    expect(after?.state).toBe("active");
    expect(after?.version).toBe(before?.version);
  });

  it("does not serve the Mission Status operation", async () => {
    const m = await issue();
    const res = await fetch(`${ISSUER}/missions/${m.missionId}/status`, {
      headers: { "x-service-token": DEV_SERVICE_TOKEN },
    });
    expect(res.status).toBe(404);
    expect(res.headers.get("content-type") ?? "").not.toContain("mission-status-response+jwt");
  });
});

describe("revoke-only Lifecycle deployment: retries and terminal states (@spec status#idempotency, #1182)", () => {
  it("replays a same-nonce retry byte for byte, and refuses the same nonce with a different request invalid_request", async () => {
    const m = await issue();
    const nonce = crypto.randomUUID();
    const original = await lifecycle(m.missionId, { operation: "revoke", nonce });
    expect(original.status, original.text).toBe(200);
    const retry = await lifecycle(m.missionId, { operation: "revoke", nonce });
    expect(retry.status).toBe(200);
    expect(retry.text).toBe(original.text);
    const divergent = await lifecycle(m.missionId, { operation: "revoke", nonce, reason: "a different request" });
    expect(divergent.status, divergent.text).toBe(400);
    expect(divergent.json.error).toBe("invalid_request");
  });

  it("a fresh revoke of a revoked Mission succeeds with no new transition", async () => {
    const m = await issue();
    const first = await lifecycle(m.missionId, { operation: "revoke", nonce: crypto.randomUUID() });
    expect(first.status, first.text).toBe(200);
    const version = as.kernel.get(m.missionId)?.version;
    const events = lifecycleEvents(m.missionId);
    const again = await lifecycle(m.missionId, { operation: "revoke", nonce: crypto.randomUUID() });
    expect(again.status, again.text).toBe(200);
    expect(again.json).toMatchObject({ state: "terminated", termination: { reason: "revoked" }, version });
    expect(as.kernel.get(m.missionId)?.version).toBe(version);
    expect(lifecycleEvents(m.missionId)).toBe(events);
  });

  it("refuses a revoke of a completed or an expired Mission with conflict, keeping its cause", async () => {
    const completed = await issue();
    as.kernel.transition(completed.missionId, "complete");
    const onCompleted = await lifecycle(completed.missionId, { operation: "revoke", nonce: crypto.randomUUID() });
    expect(onCompleted.status, onCompleted.text).toBe(409);
    expect(onCompleted.json.error).toBe("conflict");
    expect(as.kernel.get(completed.missionId)?.termination?.reason).toBe("completed");

    const expired = await issue();
    as.kernel.db
      .prepare("UPDATE missions SET expires_at = ? WHERE id = ?")
      .run(new Date(Date.now() - 60_000).toISOString(), expired.missionId);
    const onExpired = await lifecycle(expired.missionId, { operation: "revoke", nonce: crypto.randomUUID() });
    expect(onExpired.status, onExpired.text).toBe(409);
    expect(onExpired.json.error).toBe("conflict");
    expect(as.kernel.get(expired.missionId)).toMatchObject({
      state: "terminated",
      termination: { reason: "expired" },
    });
  });

  it("answers a caller without lifecycle authorization exactly as it answers an unknown Mission", async () => {
    const m = await issue();
    const nonce = crypto.randomUUID();
    const unauthorized = await lifecycle(m.missionId, { operation: "revoke", nonce }, READER_TOKEN);
    const unknown = await lifecycle("msn_unknown_0000000000000000000000", { operation: "revoke", nonce }, READER_TOKEN);
    expect(unauthorized.status, unauthorized.text).toBe(404);
    expect(unauthorized.json.error).toBe("not_found");
    expect(unknown.status).toBe(404);
    expect(unknown.json).toEqual(unauthorized.json);
    expect(as.kernel.get(m.missionId)?.state).toBe("active");
  });
});
