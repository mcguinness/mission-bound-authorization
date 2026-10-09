/**
 * @spec mission#issuance-gating, status#legal-transitions (#914) — the
 * non-consuming refresh pre-check. oidc-provider consumes the presented
 * refresh token and saves the rotated one before the save-time Mission gate
 * runs, so a rotating refresh refused there spends the lineage: after a
 * `resume`, the client's token is reuse and the grant is revoked. The
 * pre-check in `rotateRefreshToken` runs the same gate, without counting,
 * before consumption.
 *
 * Each test drives the full assembly over HTTP: suspend (or an exhausted
 * cap), a refused refresh that saves no refresh token, then the SAME token
 * succeeding once the cause is gone, and an actual replay still refused by
 * oidc-provider's reuse detection. The last test documents the residual: a
 * suspension landing between the pre-check and the save-time gate is still
 * refused by that gate, after rotation (#250).
 */
import { TEST_APPROVAL_PRINCIPALS, trustedApprovalHeaders } from "./approval-fixture.js";

import { type Server } from "node:http";
import { CANONICAL_RESOURCE, DEV_SERVICE_TOKEN } from "@mission/demo-data";
import { exportJWK, generateKeyPair, importJWK, SignJWT } from "jose";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { ACCESS_TOKEN_TOKEN_TYPE, TOKEN_EXCHANGE_GRANT_TYPE } from "../src/adapters/continuation-grant.js";
import { gateErrorToMissionError } from "../src/adapters/provider.js";
import { buildAuthorizationServer, type BuiltAs } from "../src/index.js";

const PORT = 14783;
const ISSUER = `http://localhost:${PORT}`;
const REDIRECT_URI = "http://localhost:9999/cb";
const RESOURCE = CANONICAL_RESOURCE;
const FAR_EXP = "2027-06-01T00:00:00Z";
const VERIFIER = "refresh-precheck-verifier-0123456789-0123456789-01234";
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

/** PAR, approval and the code exchange: an active Mission's access and refresh token. */
async function issue(intentOver: Json = {}): Promise<{
  missionId: string;
  accessToken: string;
  refreshToken: string;
  keys: Keys;
}> {
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

/** An async-delegation family over the Mission's own access token: its rotating refresh token. */
async function family(baseAccessToken: string): Promise<{ refreshToken: string; keys: Keys }> {
  const acting = await newKeys();
  const res = await token(
    {
      grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
      request_refresh_token: "true",
      subject_token: baseAccessToken,
      subject_token_type: ACCESS_TOKEN_TOKEN_TYPE,
      resource: RESOURCE,
      creation_request_id: crypto.randomUUID(),
    },
    acting,
  );
  expect(res.status, JSON.stringify(res.body)).toBe(200);
  return { refreshToken: res.body.refresh_token as string, keys: acting };
}

async function lifecycle(missionId: string, operation: "suspend" | "resume"): Promise<void> {
  const res = await fetch(`${ISSUER}/missions/${missionId}/lifecycle`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-service-token": DEV_SERVICE_TOKEN },
    body: JSON.stringify({ operation, nonce: crypto.randomUUID() }),
  });
  const body = (await res.json()) as { state?: string };
  expect(res.status, JSON.stringify(body)).toBe(200);
  expect(body.state).toBe(operation === "suspend" ? "suspended" : "active");
}

/** Run `fn`, counting the refresh tokens oidc-provider saves meanwhile. */
async function countingRefreshSaves<T>(fn: () => Promise<T>): Promise<{ result: T; saved: number }> {
  let saved = 0;
  const onSaved = () => {
    saved += 1;
  };
  as.provider.on("refresh_token.saved", onSaved);
  try {
    return { result: await fn(), saved };
  } finally {
    as.provider.removeListener("refresh_token.saved", onSaved);
  }
}

/**
 * An approval grant's refresh token rotates once 70% of its lifetime has
 * passed (oidc-provider's default rule, inlined in `rotateRefreshToken`).
 * Reading the elapsed share as 80% makes every approval refresh rotate,
 * without moving the clock the DPoP proofs and assertions are checked on.
 */
function pastSeventyPercent(): void {
  vi.spyOn(
    as.provider.RefreshToken.prototype as unknown as { ttlPercentagePassed(): number },
    "ttlPercentagePassed",
  ).mockReturnValue(80);
}

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

describe("refresh pre-check: a refused refresh consumes nothing (@spec mission#issuance-gating, #914)", () => {
  it("rotating approval grant: a refresh refused while suspended saves no refresh token, the same token refreshes after resume, and its replay is still reuse", async () => {
    const m = await issue();
    pastSeventyPercent();
    await lifecycle(m.missionId, "suspend");
    const before = derivations(m.missionId);
    const refused = await countingRefreshSaves(() => refresh(m.refreshToken, m.keys));
    expect(refused.result.status, JSON.stringify(refused.result.body)).toBe(400);
    expect(refused.result.body.error).toBe("invalid_grant");
    expect(refused.result.body.mission_error).toBe("suspended");
    expect(refused.saved).toBe(0);
    expect(derivations(m.missionId)).toBe(before);

    await lifecycle(m.missionId, "resume");
    const resumed = await refresh(m.refreshToken, m.keys);
    expect(resumed.status, JSON.stringify(resumed.body)).toBe(200);
    const rotated = resumed.body.refresh_token as string;
    expect(rotated).toBeTruthy();
    expect(rotated).not.toBe(m.refreshToken);

    const replay = await refresh(m.refreshToken, m.keys);
    expect(replay.status).toBe(400);
    expect(replay.body.error).toBe("invalid_grant");
    expect(replay.body.mission_error).toBeUndefined();
    // Reuse detection revoked the grant: the rotated token is gone too.
    expect((await refresh(rotated, m.keys)).body.error).toBe("invalid_grant");
  });

  it("delegation-family grant: a family refresh refused while suspended saves no refresh token, the same token refreshes after resume, and its replay is still reuse", async () => {
    const m = await issue();
    const f = await family(m.accessToken);
    await lifecycle(m.missionId, "suspend");
    const refused = await countingRefreshSaves(() => refresh(f.refreshToken, f.keys));
    expect(refused.result.status, JSON.stringify(refused.result.body)).toBe(400);
    expect(refused.result.body.error).toBe("invalid_grant");
    expect(refused.result.body.mission_error).toBe("suspended");
    expect(refused.saved).toBe(0);

    await lifecycle(m.missionId, "resume");
    const resumed = await refresh(f.refreshToken, f.keys);
    expect(resumed.status, JSON.stringify(resumed.body)).toBe(200);
    const rotated = resumed.body.refresh_token as string;
    expect(rotated).not.toBe(f.refreshToken);

    const replay = await refresh(f.refreshToken, f.keys);
    expect(replay.status).toBe(400);
    expect(replay.body.error).toBe("invalid_grant");
    expect((await refresh(rotated, f.keys)).body.error).toBe("invalid_grant");
  });

  it("approval grant with an exhausted derivation cap: refused derivations_exhausted without counting or consuming, so the same token is refused by the gate again, never as reuse", async () => {
    const m = await issue({ requested_derivation_limit: 1 });
    expect(derivations(m.missionId)).toBe(1);
    pastSeventyPercent();
    for (let attempt = 0; attempt < 2; attempt++) {
      const refused = await countingRefreshSaves(() => refresh(m.refreshToken, m.keys));
      expect(refused.result.status, JSON.stringify(refused.result.body)).toBe(400);
      expect(refused.result.body.error).toBe("invalid_grant");
      // The gate's own refusal both times: had the first attempt consumed the
      // token, the second would be reuse, which carries no mission_error.
      expect(refused.result.body.mission_error).toBe("derivations_exhausted");
      expect(refused.saved).toBe(0);
      expect(derivations(m.missionId)).toBe(1);
    }
  });

  it("delegation-family grant over an exhausted cap: the family refresh is not refused for the Mission's cap and counts nothing", async () => {
    // The code exchange counts 1 and the family's creating exchange counts 2.
    const m = await issue({ requested_derivation_limit: 2 });
    const f = await family(m.accessToken);
    expect(derivations(m.missionId)).toBe(2);
    // The approval grant is out of derivations...
    const approval = await refresh(m.refreshToken, m.keys);
    expect(approval.body.mission_error).toBe("derivations_exhausted");
    // ...and the family's refreshes are not counted, so they continue.
    const refreshed = await refresh(f.refreshToken, f.keys);
    expect(refreshed.status, JSON.stringify(refreshed.body)).toBe(200);
    expect(derivations(m.missionId)).toBe(2);
  });

  it("residual: a suspension landing between the pre-check and the save-time gate is still refused by that gate, after rotation (#250)", async () => {
    const m = await issue();
    pastSeventyPercent();
    const precheck = as.kernel.checkDerivation.bind(as.kernel);
    vi.spyOn(as.kernel, "checkDerivation").mockImplementation((id: string) => {
      const record = precheck(id);
      as.kernel.transition(id, "suspend"); // lands after the pre-check passed
      return record;
    });
    const raced = await countingRefreshSaves(() => refresh(m.refreshToken, m.keys));
    vi.restoreAllMocks();
    // The authoritative save-time gate still refuses: no token is issued.
    expect(raced.result.status, JSON.stringify(raced.result.body)).toBe(400);
    expect(raced.result.body.error).toBe("invalid_grant");
    expect(raced.result.body.access_token).toBeUndefined();
    // But the refusal came after rotation: the lineage is spent, so after a
    // resume the client's token is reuse. Only refusals detected before
    // rotation consume nothing.
    expect(raced.saved).toBe(1);
    await lifecycle(m.missionId, "resume");
    pastSeventyPercent();
    const after = await refresh(m.refreshToken, m.keys);
    expect(after.status).toBe(400);
    expect(after.body.error).toBe("invalid_grant");
  });
});

describe("mission_error for Mission Status states (@spec status#mission-lifecycle-endpoint)", () => {
  it("approval grant on a completed Mission: the refresh is refused invalid_grant with mission_error completed", async () => {
    const m = await issue();
    // The demo's /lifecycle route also destroys the OAuth grant on a terminal
    // transition, so a refresh would fail at the grant lookup before the
    // Mission gate. The raw kernel transition leaves the grant for the gate.
    const completed = as.kernel.transition(m.missionId, "complete");
    expect(completed.state).toBe("terminated");
    expect(completed.termination?.reason).toBe("completed");
    const refused = await refresh(m.refreshToken, m.keys);
    expect(refused.status, JSON.stringify(refused.body)).toBe(400);
    expect(refused.body.error).toBe("invalid_grant");
    expect(refused.body.mission_error).toBe("completed");
  });

  it("the value names the Mission's own state: a lineage refusal while its own state is active carries none", () => {
    const terminated = (reason: string) => ({ state: "terminated", termination: { reason } });
    expect(gateErrorToMissionError("mission_not_active", { state: "suspended" })).toBe("suspended");
    expect(gateErrorToMissionError("mission_not_active", terminated("completed"))).toBe("completed");
    expect(gateErrorToMissionError("mission_not_active", terminated("revoked"))).toBe("revoked");
    expect(gateErrorToMissionError("mission_not_active", { state: "active" })).toBeUndefined();
    expect(gateErrorToMissionError("mission_not_active", undefined)).toBeUndefined();
  });

  it("the value is the observed termination reason, unprefixed: superseded and parent_terminated map, an unknown reason carries none (@spec mission#termination)", () => {
    const terminated = (reason: string) => ({ state: "terminated", termination: { reason } });
    expect(gateErrorToMissionError("mission_not_active", terminated("superseded"))).toBe("superseded");
    expect(gateErrorToMissionError("mission_not_active", terminated("parent_terminated"))).toBe("parent_terminated");
    // A recorded earlier cause wins over expiry: the observed reason is the
    // recorded one, so a revoked Mission past its expires_at still says revoked.
    expect(gateErrorToMissionError("mission_not_active", terminated("expired"))).toBe("expired");
    expect(gateErrorToMissionError("mission_expired", terminated("expired"))).toBe("expired");
    // Fail closed without a misleading diagnostic: an unrecognized reason, or
    // a terminated Mission with no readable termination, gets plain invalid_grant.
    expect(gateErrorToMissionError("mission_not_active", terminated("unknown"))).toBeUndefined();
    expect(gateErrorToMissionError("mission_not_active", terminated("quantum_supervened"))).toBeUndefined();
    expect(gateErrorToMissionError("mission_not_active", { state: "terminated" })).toBeUndefined();
    expect(gateErrorToMissionError("derivation_cap_exhausted", { state: "active" })).toBe("derivations_exhausted");
  });
});
