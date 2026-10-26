/**
 * @spec status#security-considerations ("Mission Status Denial of Service"),
 * status#mission-status-errors (#1686)
 *
 * The AS rate-limits the Mission Status operation per consumer: an
 * authenticated client over its limit is answered `rate_limited` (429) with
 * when to retry, before any Mission is read, while other clients are
 * unaffected and an unauthenticated request counts against no client. Both
 * routes: the advertised form POST (private-key JWT) and the development GET
 * (service token).
 */

import type { Server } from "node:http";
import { CANONICAL_RESOURCE } from "@mission/demo-data";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  type BuiltAs,
  buildAuthorizationServer,
  MISSION_STATUS_SCOPE,
  MissionStatusRateLimiter,
  type MissionRecord,
  validateMissionIntent,
} from "../src/index.js";
import { STATUS_ENDPOINT_PATH } from "../src/adapters/lifecycle-endpoint.js";
import {
  CLIENT_ASSERTION_TYPE,
  type LifecycleAnswer,
  type LifecycleTestClient,
  lifecycleClientAssertion,
  newLifecycleClient,
  readAnswer,
} from "./lifecycle-endpoint.helper.js";

const PORT = 14896;
const ISSUER = `http://localhost:${PORT}`;
const ENDPOINT = `${ISSUER}${STATUS_ENDPOINT_PATH}`;
const LIMIT = 2;
const UNKNOWN = "msn_unknown_rate_limit_0000000000000";

let as: BuiltAs;
let server: Server;
let reader: LifecycleTestClient;
let other: LifecycleTestClient;
let fresh: LifecycleTestClient;
let unauthenticated: LifecycleTestClient;
let approvals = 0;

function approve(): MissionRecord {
  approvals += 1;
  return as.kernel.approve({
    intent: validateMissionIntent(
      JSON.stringify({ goal: "Read Acme invoices", target_resources: [CANONICAL_RESOURCE], expires_at: "2027-01-01T00:00:00Z" }),
    ),
    proposedAuthority: [{ type: "mission_resource_access", resource: CANONICAL_RESOURCE, actions: ["payments:invoice.read"] }],
    subject: { iss: ISSUER, sub: "alice" },
    approver: { iss: ISSUER, sub: "bob" },
    clientId: "ap-agent",
    approvalEventId: `apev-status-rate-limit-${approvals}`,
  });
}

const nonce = (): string => `nonce-rl-${crypto.randomUUID()}`;

/** A form POST Status read by `client`, with a fresh client assertion unless one is given. */
async function read(client: LifecycleTestClient, missionId: string, assertion?: string): Promise<LifecycleAnswer & { retryAfter: string | null }> {
  const res = await fetch(ENDPOINT, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      mission_id: missionId,
      nonce: nonce(),
      client_assertion_type: CLIENT_ASSERTION_TYPE,
      client_assertion: assertion ?? (await lifecycleClientAssertion(ISSUER, client)),
    }).toString(),
  });
  return { ...(await readAnswer(res)), retryAfter: res.headers.get("retry-after") };
}

/** A development GET Status read under a service token. */
async function get(missionId: string, token?: string): Promise<Response> {
  return fetch(`${ISSUER}/missions/${missionId}/status?nonce=${nonce()}`, {
    headers: token ? { "x-service-token": token } : {},
  });
}

beforeAll(async () => {
  reader = await newLifecycleClient("rate-limit-reader");
  other = await newLifecycleClient("rate-limit-other");
  fresh = await newLifecycleClient("rate-limit-fresh");
  unauthenticated = await newLifecycleClient("rate-limit-unauthenticated");
  as = await buildAuthorizationServer({
    issuer: ISSUER,
    testClients: [reader.metadata, other.metadata, fresh.metadata, unauthenticated.metadata],
    lifecycleClientGrants: {
      [reader.clientId]: [MISSION_STATUS_SCOPE],
      [other.clientId]: [MISSION_STATUS_SCOPE],
      [fresh.clientId]: [MISSION_STATUS_SCOPE],
      [unauthenticated.clientId]: [MISSION_STATUS_SCOPE],
    },
    serviceTokenPrincipals: {
      "rate-limit-svc-a": { principal_id: "svc:rate-limit-a", scopes: [MISSION_STATUS_SCOPE] },
      "rate-limit-svc-b": { principal_id: "svc:rate-limit-b", scopes: [MISSION_STATUS_SCOPE] },
    },
    missionStatusRateLimit: { requests: LIMIT, windowSeconds: 60 },
  });
  server = as.provider.listen(PORT);
});

afterAll(() => {
  server?.close();
});

describe("Mission Status rate limiting per consumer (@spec status#security-considerations, status#mission-status-errors, #1686)", () => {
  it("refuses a client over its limit rate_limited (429) with Retry-After, retry_after and its nonce, while another client is unaffected", async () => {
    const record = approve();
    for (let i = 0; i < LIMIT; i += 1) expect((await read(reader, record.id)).status).toBe(200);
    const refused = await read(reader, record.id);
    expect(refused.status).toBe(429);
    expect(refused.cacheControl).toBe("no-store");
    expect(refused.json).toMatchObject({ error: "rate_limited", error_description: expect.any(String), nonce: expect.any(String) });
    const retryAfter = refused.json?.retry_after as number;
    expect(Number.isInteger(retryAfter) && retryAfter >= 1 && retryAfter <= 60).toBe(true);
    expect(refused.retryAfter).toBe(String(retryAfter));
    expect((await read(other, record.id)).status).toBe(200);
  });

  it("decides before any Mission is read: over the limit, an unknown Mission and a known one get the same refusal", async () => {
    const record = approve();
    for (let i = 0; i < LIMIT; i += 1) expect((await read(fresh, UNKNOWN)).status).toBe(404);
    const known = await read(fresh, record.id);
    const unknown = await read(fresh, UNKNOWN);
    for (const answer of [known, unknown]) {
      expect(answer.status).toBe(429);
      expect(answer.json?.error).toBe("rate_limited");
    }
  });

  // @spec status#mission-status-processing: the limit sits after request
  // syntax (step 2) and before authorization (step 3), so a malformed request
  // keeps its step-2 refusal whatever the client's count.
  it("keeps the processing order: an over-limit client's malformed request is still refused invalid_request", async () => {
    const malformed = await newLifecycleClient("rate-limit-malformed");
    const local = await buildAuthorizationServer({
      issuer: ISSUER,
      testClients: [malformed.metadata],
      lifecycleClientGrants: { [malformed.clientId]: [MISSION_STATUS_SCOPE] },
      missionStatusRateLimit: { requests: 1, windowSeconds: 60 },
    });
    const localServer = local.provider.listen(PORT + 100);
    try {
      const at = `http://localhost:${PORT + 100}${STATUS_ENDPOINT_PATH}`;
      const send = async (form: Record<string, string>) =>
        readAnswer(
          await fetch(at, {
            method: "POST",
            headers: { "content-type": "application/x-www-form-urlencoded" },
            body: new URLSearchParams({
              ...form,
              client_assertion_type: CLIENT_ASSERTION_TYPE,
              client_assertion: await lifecycleClientAssertion(ISSUER, malformed),
            }).toString(),
          }),
        );
      expect((await send({ mission_id: UNKNOWN, nonce: nonce() })).status).toBe(404);
      expect((await send({ mission_id: UNKNOWN, nonce: nonce() })).json?.error).toBe("rate_limited");
      const missingMission = await send({ nonce: nonce() });
      expect(missingMission.status).toBe(400);
      expect(missingMission.json?.error).toBe("invalid_request");
    } finally {
      localServer.close();
    }
  });

  it("an unauthenticated request is refused as an authentication failure and counts against no client", async () => {
    const record = approve();
    const forged = await lifecycleClientAssertion(ISSUER, { ...unauthenticated, privateKey: reader.privateKey });
    for (let i = 0; i < LIMIT + 2; i += 1) {
      const answer = await read(unauthenticated, record.id, forged);
      expect(answer.status).toBe(400);
      expect(answer.json?.error).toBe("invalid_client");
    }
    for (let i = 0; i < LIMIT; i += 1) expect((await read(unauthenticated, record.id)).status).toBe(200);
  });

  it("limits the development GET route per service principal the same way; an unauthenticated GET counts against no one", async () => {
    const record = approve();
    for (let i = 0; i < LIMIT + 2; i += 1) expect((await get(record.id)).status).toBe(401);
    for (let i = 0; i < LIMIT; i += 1) expect((await get(record.id, "rate-limit-svc-a")).status).toBe(200);
    const refused = await get(record.id, "rate-limit-svc-a");
    expect(refused.status).toBe(429);
    expect(((await refused.json()) as { error?: string }).error).toBe("rate_limited");
    expect(refused.headers.get("retry-after")).not.toBeNull();
    expect((await get(record.id, "rate-limit-svc-b")).status).toBe(200);
  });
});

describe("the Mission Status rate limiter's window (#1686)", () => {
  it("admits a client up to its limit, refuses it until the window resets with the remaining whole seconds, then admits it again", () => {
    let now = 1_000_000;
    const limiter = new MissionStatusRateLimiter({ requests: 2, windowSeconds: 10 }, () => now);
    expect(limiter.admit("a")).toBeUndefined();
    expect(limiter.admit("a")).toBeUndefined();
    expect(limiter.admit("a")).toBe(10);
    now += 7_500;
    expect(limiter.admit("a")).toBe(3);
    expect(limiter.admit("b")).toBeUndefined();
    now += 2_500;
    expect(limiter.admit("a")).toBeUndefined();
  });

  it("refuses a limit that is not a positive integer, or that omits either member", () => {
    for (const limit of [
      { requests: 0, windowSeconds: 60 },
      { requests: 5, windowSeconds: 0.5 },
      { requests: 1 },
      { windowSeconds: 60 },
      {},
      null,
    ]) {
      expect(() => new MissionStatusRateLimiter(limit as never, () => 0), JSON.stringify(limit)).toThrow(/required and must be a positive integer/);
    }
  });

  it("refuses to build an AS whose configured limit, as read from JSON, omits a member", async () => {
    for (const json of ['{"requests":1}', '{"windowSeconds":60}', "{}"]) {
      await expect(
        buildAuthorizationServer({ issuer: "http://localhost:14996", missionStatusRateLimit: JSON.parse(json) }),
        json,
      ).rejects.toThrow(/missionStatusRateLimit\.(requests|windowSeconds) is required/);
    }
  });
});
