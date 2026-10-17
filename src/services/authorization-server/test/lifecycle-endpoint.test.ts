/**
 * @spec status#mission-lifecycle-endpoint, status#mission-status-authentication,
 * status#mission-status-auth-failures, status#lifecycle-authorization,
 * status#idempotency, status#mission-status-response, status#mission-status-errors,
 * status#as-metadata (#1191): the advertised Mission Lifecycle endpoint.
 *
 * Covered:
 *  - discovery: the endpoint, its private_key_jwt method and assertion
 *    algorithms, and the response-signing algorithms, all absent where no
 *    Lifecycle operation is served;
 *  - transport: a form body only, single-valued members;
 *  - client authentication: no credential, a foreign credential, the
 *    assertion `aud` as the issuer identifier and nothing else, the permitted
 *    `typ` values, `exp`/`jti`, replay, signature and registration;
 *  - authorization: a client without the lifecycle grant gets the unknown
 *    Mission's answer;
 *  - the request members: `nonce`, `mission_id`, `reason`, `expected_version`
 *    and the schedule members;
 *  - the signed state-only response for every base operation, idempotent
 *    success included;
 *  - retries: byte-for-byte replay under a regenerated assertion, divergent
 *    refusal, and recovery of a lost response at its original observation;
 *  - transient failures: `unavailable`, never retained, against the retained
 *    unknown-Mission `not_found`;
 *  - the dev-only path route runs the same engine.
 */

import type { Server } from "node:http";
import { CANONICAL_RESOURCE, DEV_SERVICE_TOKEN } from "@mission/demo-data";
import { createLocalJWKSet, type JWK, jwtVerify } from "jose";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { LIFECYCLE_ENDPOINT_PATH, parseTransitionMembers } from "../src/adapters/lifecycle-endpoint.js";
import {
  type AuthorityEntry,
  type BuiltAs,
  buildAuthorizationServer,
  LIFECYCLE_ENDPOINT_KEY,
  LifecycleResponseStore,
  MISSION_LIFECYCLE_SCOPE,
  MISSION_STATUS_SCOPE,
  type MissionRecord,
  type ProviderCapability,
  validateMissionIntent,
} from "../src/index.js";
import {
  CLIENT_ASSERTION_TYPE,
  decodeStatusResponse,
  type LifecycleAnswer,
  type LifecycleTestClient,
  lifecycleClientAssertion,
  lifecycleRequest,
  newLifecycleClient,
  postLifecycleForm,
  readAnswer,
} from "./lifecycle-endpoint.helper.js";

const PORT = 14798;
const ISSUER = `http://localhost:${PORT}`;
const BARE_PORT = 14799;
const BARE_ISSUER = `http://localhost:${BARE_PORT}`;
const ENDPOINT = `${ISSUER}${LIFECYCLE_ENDPOINT_PATH}`;
const EXPIRES_AT = "2027-01-01T00:00:00Z";
const UNKNOWN = "msn_unknown_0000000000000000000000";

let as: BuiltAs;
let server: Server;
let bare: BuiltAs;
let bareServer: Server;
/** Holds `mission_lifecycle`: a security console that holds none of the Mission's tokens. */
let consoleClient: LifecycleTestClient;
/** Holds `mission_status` only. */
let readerClient: LifecycleTestClient;
/** Registered, authenticates, holds no lifecycle grant. */
let ungrantedClient: LifecycleTestClient;
/** Holds `mission_lifecycle`, but its registered key signs ES384, an algorithm the endpoint does not advertise. */
let es384Client: LifecycleTestClient;
let approvals = 0;

const proposal = (): AuthorityEntry[] => [
  { type: "mission_resource_access", resource: CANONICAL_RESOURCE, actions: ["payments:invoice.read"] },
];

function approve(): MissionRecord {
  approvals += 1;
  return as.kernel.approve({
    intent: validateMissionIntent(
      JSON.stringify({ goal: "Read invoices for the close", target_resources: [CANONICAL_RESOURCE], expires_at: EXPIRES_AT }),
    ),
    proposedAuthority: proposal(),
    subject: { iss: ISSUER, sub: "alice" },
    approver: { iss: ISSUER, sub: "bob" },
    clientId: "ap-agent",
    approvalEventId: `apev-lce-${approvals}`,
  });
}

const nonce = (): string => `nonce-lce-${crypto.randomUUID()}`;

/** A Lifecycle request from the console client. */
const op = (members: Record<string, string>, assertion?: string): Promise<LifecycleAnswer> =>
  lifecycleRequest(ISSUER, consoleClient, members, assertion);

const retainedRow = (clientId: string, missionId: string, n: string): Record<string, unknown> | undefined =>
  as.kernel.db
    .prepare(
      `SELECT * FROM lifecycle_responses WHERE endpoint = ? AND principal = ? AND mission_id = ? AND nonce = ?`,
    )
    .get(LIFECYCLE_ENDPOINT_KEY, clientId, missionId, n) as Record<string, unknown> | undefined;

async function discovery(issuer: string): Promise<Record<string, unknown>> {
  const res = await fetch(`${issuer}/.well-known/openid-configuration`);
  return (await res.json()) as Record<string, unknown>;
}

/** Verify a signed Lifecycle response against the AS's published keys. */
async function verifySigned(text: string): Promise<Record<string, unknown>> {
  const jwks = (await (await fetch(`${ISSUER}/jwks`)).json()) as { keys: JWK[] };
  const { payload } = await jwtVerify(text, createLocalJWKSet(jwks), {
    typ: "mission-status-response+jwt",
    algorithms: ["ES256"],
    issuer: ISSUER,
  });
  return payload as Record<string, unknown>;
}

beforeAll(async () => {
  consoleClient = await newLifecycleClient("security-console");
  readerClient = await newLifecycleClient("status-reader");
  ungrantedClient = await newLifecycleClient("ungranted-tool");
  es384Client = await newLifecycleClient("es384-tool", "ES384");
  as = await buildAuthorizationServer({
    issuer: ISSUER,
    testClients: [consoleClient.metadata, readerClient.metadata, ungrantedClient.metadata, es384Client.metadata],
    lifecycleClientGrants: {
      [consoleClient.clientId]: [MISSION_LIFECYCLE_SCOPE],
      [es384Client.clientId]: [MISSION_LIFECYCLE_SCOPE],
      [readerClient.clientId]: [MISSION_STATUS_SCOPE],
    },
  });
  server = as.provider.listen(PORT);
  await new Promise<void>((r) => server.once("listening", () => r()));
  // No Lifecycle operation and no Status operation: the issuance profile alone.
  bare = await buildAuthorizationServer({
    issuer: BARE_ISSUER,
    capabilities: new Set<ProviderCapability>(["oidc"]),
  });
  bareServer = bare.provider.listen(BARE_PORT);
  await new Promise<void>((r) => bareServer.once("listening", () => r()));
});

afterAll(async () => {
  await new Promise<void>((r) => server.close(() => r()));
  await new Promise<void>((r) => bareServer.close(() => r()));
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("Mission Lifecycle endpoint discovery (@spec status#as-metadata, #1191)", () => {
  it("advertises the endpoint, its private_key_jwt method and assertion algorithms, and the response-signing algorithms", async () => {
    const meta = await discovery(ISSUER);
    expect(meta.mission_lifecycle_endpoint).toBe(ENDPOINT);
    expect(meta.mission_lifecycle_endpoint_auth_methods_supported).toEqual(["private_key_jwt"]);
    expect(meta.mission_lifecycle_endpoint_auth_signing_alg_values_supported).toEqual(["ES256"]);
    expect(meta.mission_status_signing_alg_values_supported).toEqual(["ES256"]);
    expect(meta.mission_lifecycle_endpoint_auth_signing_alg_values_supported).not.toContain("none");
  });

  it("advertises none of them, and serves no endpoint, where no Lifecycle operation is enabled", async () => {
    const meta = await discovery(BARE_ISSUER);
    for (const member of [
      "mission_lifecycle_endpoint",
      "mission_lifecycle_endpoint_auth_methods_supported",
      "mission_lifecycle_endpoint_auth_signing_alg_values_supported",
      "mission_status_signing_alg_values_supported",
    ]) {
      expect(Object.hasOwn(meta, member), member).toBe(false);
    }
    const res = await fetch(`${BARE_ISSUER}${LIFECYCLE_ENDPOINT_PATH}`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: "",
    });
    expect(res.status).toBe(404);
  });
});

describe("Mission Lifecycle endpoint transport and client authentication (@spec status#mission-status-authentication, status#mission-status-auth-failures, #1191)", () => {
  it("accepts only a form body, with every member single-valued", async () => {
    const m = approve();
    const json = await readAnswer(
      await fetch(ENDPOINT, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          mission_id: m.id,
          operation: "revoke",
          nonce: nonce(),
          client_assertion_type: CLIENT_ASSERTION_TYPE,
          client_assertion: await lifecycleClientAssertion(ISSUER, consoleClient),
        }),
      }),
    );
    expect(json.status, json.text).toBe(400);
    expect(json.json?.error).toBe("invalid_request");
    const repeatedNonce = nonce();
    const repeated = new URLSearchParams({
      mission_id: m.id,
      operation: "revoke",
      nonce: repeatedNonce,
      client_assertion_type: CLIENT_ASSERTION_TYPE,
      client_assertion: await lifecycleClientAssertion(ISSUER, consoleClient),
    });
    repeated.append("operation", "suspend");
    const twice = await readAnswer(
      await fetch(ENDPOINT, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: repeated.toString(),
      }),
    );
    expect(twice.status, twice.text).toBe(400);
    expect(twice.json?.error).toBe("invalid_request");
    expect(twice.json?.nonce).toBe(repeatedNonce);
    expect(as.kernel.get(m.id)?.state).toBe("active");
  });

  it("refuses a request with no credential, a client secret, Basic or an access token invalid_client (HTTP 400) with no challenge", async () => {
    const m = approve();
    const members = { mission_id: m.id, operation: "revoke", nonce: nonce() };
    // Each foreign credential rides beside an otherwise valid client
    // assertion: the request is not authenticated by exactly one accepted
    // mechanism, so it is refused rather than authenticated by the assertion.
    const withAssertion = async (): Promise<Record<string, string>> => ({
      ...members,
      client_assertion_type: CLIENT_ASSERTION_TYPE,
      client_assertion: await lifecycleClientAssertion(ISSUER, consoleClient),
    });
    const answers = [
      await postLifecycleForm(ISSUER, members),
      await postLifecycleForm(ISSUER, { ...members, client_id: consoleClient.clientId, client_secret: "s3cret" }),
      await postLifecycleForm(ISSUER, { ...(await withAssertion()), client_secret: "s3cret" }),
      await postLifecycleForm(ISSUER, await withAssertion(), {
        authorization: `Basic ${Buffer.from(`${consoleClient.clientId}:s3cret`).toString("base64")}`,
      }),
      await postLifecycleForm(ISSUER, await withAssertion(), { authorization: "Bearer some.access.token" }),
      await postLifecycleForm(ISSUER, await withAssertion(), { authorization: "DPoP some.access.token" }),
    ];
    for (const a of answers) {
      expect(a.status, a.text).toBe(400);
      expect(a.json?.error).toBe("invalid_client");
      // @spec status#mission-status-errors: `error_description`, and the
      // request's well-formed `nonce` echoed.
      expect(typeof a.json?.error_description).toBe("string");
      expect(a.json?.nonce).toBe(members.nonce);
      expect(a.wwwAuthenticate).toBeNull();
      expect(a.cacheControl).toBe("no-store");
    }
    expect(as.kernel.get(m.id)?.state).toBe("active");
  });

  it("refuses a client assertion whose aud is anything but the issuer identifier as its sole value", async () => {
    const m = approve();
    for (const aud of [
      ENDPOINT,
      `${ISSUER}/token`,
      [ISSUER, `${ISSUER}/token`],
      [ISSUER, ENDPOINT],
      `${ISSUER}/`,
    ]) {
      const refused = await op(
        { mission_id: m.id, operation: "suspend", nonce: nonce() },
        await lifecycleClientAssertion(ISSUER, consoleClient, { aud }),
      );
      expect(refused.status, `${JSON.stringify(aud)}: ${refused.text}`).toBe(400);
      expect(refused.json?.error).toBe("invalid_client");
    }
    expect(as.kernel.get(m.id)?.state).toBe("active");
    // The issuer identifier alone, as a string or as a one-element array.
    const asString = await op({ mission_id: m.id, operation: "suspend", nonce: nonce() });
    expect(asString.status, asString.text).toBe(200);
    const asArray = await op(
      { mission_id: m.id, operation: "resume", nonce: nonce() },
      await lifecycleClientAssertion(ISSUER, consoleClient, { aud: [ISSUER] }),
    );
    expect(asArray.status, asArray.text).toBe(200);
  });

  it("accepts an assertion typed client-authentication+jwt, an untyped one and a generic JWT, and refuses one explicitly typed as another kind of JWT", async () => {
    const m = approve();
    for (const typ of ["client-authentication+jwt", null, "JWT"] as const) {
      const accepted = await op(
        { mission_id: m.id, operation: "suspend", nonce: nonce() },
        await lifecycleClientAssertion(ISSUER, consoleClient, { typ }),
      );
      expect(accepted.status, `${String(typ)}: ${accepted.text}`).toBe(200);
    }
    for (const typ of ["dpop+jwt", "at+jwt", "mission-status-response+jwt"]) {
      const refused = await op(
        { mission_id: m.id, operation: "resume", nonce: nonce() },
        await lifecycleClientAssertion(ISSUER, consoleClient, { typ }),
      );
      expect(refused.status, `${typ}: ${refused.text}`).toBe(400);
      expect(refused.json?.error).toBe("invalid_client");
    }
    expect(as.kernel.get(m.id)?.state).toBe("suspended");
  });

  it("refuses an assertion without exp or jti, one living past the replay window, a replayed jti, a foreign signature and an unregistered client", async () => {
    const m = approve();
    const members = () => ({ mission_id: m.id, operation: "revoke", nonce: nonce() });
    const replayed = await lifecycleClientAssertion(ISSUER, consoleClient, { jti: `jti-${crypto.randomUUID()}` });
    const first = await op({ mission_id: m.id, operation: "suspend", nonce: nonce() }, replayed);
    expect(first.status, first.text).toBe(200);
    const stranger = await newLifecycleClient("not-registered");
    for (const [label, assertion] of [
      ["no exp", await lifecycleClientAssertion(ISSUER, consoleClient, { expiresIn: null })],
      ["no jti", await lifecycleClientAssertion(ISSUER, consoleClient, { jti: null })],
      ["long-lived", await lifecycleClientAssertion(ISSUER, consoleClient, { expiresIn: 3600 })],
      ["replayed jti", replayed],
      ["foreign key", await lifecycleClientAssertion(ISSUER, consoleClient, { key: readerClient.privateKey })],
      ["unregistered", await lifecycleClientAssertion(ISSUER, stranger)],
    ] as const) {
      const refused = await op(members(), assertion);
      expect(refused.status, `${label}: ${refused.text}`).toBe(400);
      expect(refused.json?.error, label).toBe("invalid_client");
    }
    expect(as.kernel.get(m.id)?.state).toBe("suspended");
  });
});

describe("Mission Lifecycle endpoint client-assertion algorithms (@spec status#mission-status-authentication, status#as-metadata, #1191)", () => {
  it("refuses an assertion signed with an algorithm the endpoint does not advertise, none included, from a client registered for it", async () => {
    const m = approve();
    const meta = await discovery(ISSUER);
    expect(meta.mission_lifecycle_endpoint_auth_signing_alg_values_supported).not.toContain("ES384");
    // A validly signed ES384 assertion from a client whose registered key is ES384.
    const es384 = await lifecycleRequest(ISSUER, es384Client, { mission_id: m.id, operation: "revoke", nonce: nonce() });
    expect(es384.status, es384.text).toBe(400);
    expect(es384.json?.error).toBe("invalid_client");
    // An unsecured (`alg` none) assertion naming the console client.
    const now = Math.floor(Date.now() / 1000);
    const part = (o: Record<string, unknown>) => Buffer.from(JSON.stringify(o)).toString("base64url");
    const unsecured = `${part({ alg: "none", typ: "client-authentication+jwt" })}.${part({
      iss: consoleClient.clientId,
      sub: consoleClient.clientId,
      aud: ISSUER,
      iat: now,
      exp: now + 60,
      jti: crypto.randomUUID(),
    })}.`;
    const none = await op({ mission_id: m.id, operation: "revoke", nonce: nonce() }, unsecured);
    expect(none.status, none.text).toBe(400);
    expect(none.json?.error).toBe("invalid_client");
    expect(as.kernel.get(m.id)?.state).toBe("active");
  });
});

describe("Mission Lifecycle endpoint authorization and request members (@spec status#lifecycle-authorization, status#mission-lifecycle-endpoint, #1191)", () => {
  it("refuses at boot a lifecycle grant that names no Lifecycle authorization", async () => {
    await expect(
      buildAuthorizationServer({
        issuer: "http://localhost:1",
        lifecycleClientGrants: { [consoleClient.clientId]: ["mission_admin"] },
      }),
    ).rejects.toThrow(/unknown grant mission_admin/);
  });

  it("answers an authenticated client without the lifecycle grant exactly as it answers an unknown Mission", async () => {
    const m = approve();
    for (const client of [ungrantedClient, readerClient]) {
      const n = nonce();
      const unauthorized = await lifecycleRequest(ISSUER, client, { mission_id: m.id, operation: "revoke", nonce: n });
      const unknown = await lifecycleRequest(ISSUER, consoleClient, { mission_id: UNKNOWN, operation: "revoke", nonce: n });
      expect(unauthorized.status, unauthorized.text).toBe(404);
      expect(unauthorized.json).toEqual({
        error: "not_found",
        error_description: "Mission reference is not found or not visible.",
        nonce: n,
      });
      expect(unknown.status).toBe(404);
      expect(unknown.json).toEqual(unauthorized.json);
      expect(unauthorized.wwwAuthenticate).toBeNull();
    }
    expect(as.kernel.get(m.id)?.state).toBe("active");
  });

  it("refuses an absent or malformed nonce invalid_request with no nonce echoed, and an absent mission_id with it echoed", async () => {
    const m = approve();
    for (const bad of [undefined, "", "n".repeat(256)]) {
      const refused = await op({ mission_id: m.id, operation: "revoke", ...(bad === undefined ? {} : { nonce: bad }) });
      expect(refused.status, refused.text).toBe(400);
      expect(refused.json?.error).toBe("invalid_request");
      expect(Object.hasOwn(refused.json ?? {}, "nonce")).toBe(false);
      expect(typeof refused.json?.error_description).toBe("string");
    }
    const n = nonce();
    const noMission = await op({ operation: "revoke", nonce: n });
    expect(noMission.status, noMission.text).toBe(400);
    expect(noMission.json).toMatchObject({ error: "invalid_request", nonce: n });
    expect(as.kernel.get(m.id)?.state).toBe("active");
  });

  it("refuses schedule members on another operation, as an incomplete pair, and as a schedule this deployment cannot honor, leaving the Mission unchanged", async () => {
    const m = approve();
    const before = as.kernel.get(m.id);
    for (const members of [
      { operation: "revoke", suspend_until: "2026-12-01T00:00:00Z", on_expiry: "revoke" },
      { operation: "suspend", suspend_until: "2026-12-01T00:00:00Z" },
      { operation: "suspend", on_expiry: "resume" },
      { operation: "suspend", suspend_until: "next tuesday", on_expiry: "resume" },
      { operation: "suspend", suspend_until: "2026-12-01T00:00:00Z", on_expiry: "complete" },
      { operation: "suspend", suspend_until: "2026-12-01T00:00:00Z", on_expiry: "resume" },
      { operation: "suspend", reason: "r".repeat(1025) },
    ]) {
      const refused = await op({ mission_id: m.id, nonce: nonce(), ...members });
      expect(refused.status, `${JSON.stringify(members)}: ${refused.text}`).toBe(400);
      expect(refused.json?.error).toBe("invalid_request");
    }
    expect(as.kernel.get(m.id)).toEqual(before);
  });

  it("refuses a stale expected_version 409 stale_version before the transition rule, leaving the Mission unchanged, and applies a current one", async () => {
    const m = approve();
    const malformed = await op({ mission_id: m.id, operation: "suspend", nonce: nonce(), expected_version: "01" });
    expect(malformed.status, malformed.text).toBe(400);
    expect(malformed.json?.error).toBe("invalid_request");
    const n = nonce();
    const stale = await op({ mission_id: m.id, operation: "suspend", nonce: n, expected_version: String(m.version + 1) });
    expect(stale.status, stale.text).toBe(409);
    expect(stale.json).toMatchObject({ error: "stale_version", nonce: n });
    expect(as.kernel.get(m.id)?.state).toBe("active");
    expect(as.kernel.get(m.id)?.version).toBe(m.version);
    const current = await op({ mission_id: m.id, operation: "revoke", nonce: nonce(), expected_version: String(m.version) });
    expect(current.status, current.text).toBe(200);
    const revokedAt = as.kernel.get(m.id)?.version as number;
    // An idempotent `revoke` under a stale guard is refused, not answered as success.
    const idempotentButStale = await op({
      mission_id: m.id,
      operation: "revoke",
      nonce: nonce(),
      expected_version: String(m.version),
    });
    expect(idempotentButStale.status, idempotentButStale.text).toBe(409);
    expect(idempotentButStale.json?.error).toBe("stale_version");
    expect(as.kernel.get(m.id)?.version).toBe(revokedAt);
  });

  it("refuses an operation not legal from the current state 409 conflict, echoing the nonce and leaving the Mission unchanged", async () => {
    const m = approve();
    expect((await op({ mission_id: m.id, operation: "revoke", nonce: nonce() })).status).toBe(200);
    const n = nonce();
    const conflict = await op({ mission_id: m.id, operation: "complete", nonce: n });
    expect(conflict.status, conflict.text).toBe(409);
    expect(conflict.json).toMatchObject({ error: "conflict", nonce: n });
    expect(typeof conflict.json?.error_description).toBe("string");
    expect(as.kernel.get(m.id)?.termination?.reason).toBe("revoked");
  });

  it("parses the schedule members only on suspend, and only as a complete pair", () => {
    const until = "2026-12-01T00:00:00Z";
    expect(parseTransitionMembers("suspend", { suspend_until: until, on_expiry: "revoke" })).toEqual({
      ok: true,
      value: { schedule: { suspendUntil: until, onExpiry: "revoke" } },
    });
    for (const operation of ["revoke", "resume", "complete"] as const) {
      expect(parseTransitionMembers(operation, { suspend_until: until, on_expiry: "revoke" }).ok, operation).toBe(false);
    }
    expect(parseTransitionMembers("suspend", { suspend_until: until }).ok).toBe(false);
    expect(parseTransitionMembers("suspend", { on_expiry: "resume" }).ok).toBe(false);
    expect(parseTransitionMembers("suspend", {})).toEqual({ ok: true, value: {} });
  });
});

describe("Mission Lifecycle endpoint signed state-only response (@spec status#mission-status-response, status#mission-lifecycle-endpoint, #1191)", () => {
  it("answers revoke with the signed state-only Mission Status Response: requester aud and sub, the request's nonce, and every required member", async () => {
    const m = approve();
    const n = nonce();
    const res = await op({ mission_id: m.id, operation: "revoke", nonce: n, reason: "incident 42" });
    expect(res.status, res.text).toBe(200);
    expect(res.contentType).toBe("application/mission-status-response+jwt");
    expect(res.cacheControl).toBe("no-store");
    const payload = await verifySigned(res.text);
    const { header, mission } = decodeStatusResponse(res.text);
    expect(header).toMatchObject({ typ: "mission-status-response+jwt", alg: "ES256" });
    expect(typeof header.kid).toBe("string");
    expect(payload.iss).toBe(ISSUER);
    expect(payload.aud).toBe(consoleClient.clientId);
    expect(payload.sub).toBe(consoleClient.clientId);
    expect(payload.nonce).toBe(n);
    expect(typeof payload.iat).toBe("number");
    expect(payload.exp as number).toBeGreaterThan(payload.iat as number);
    expect(Object.hasOwn(payload, "authorization_details")).toBe(false);
    const record = as.kernel.get(m.id) as MissionRecord;
    expect(mission).toMatchObject({
      id: m.id,
      issuer: ISSUER,
      state: "terminated",
      termination: { reason: "revoked", version: record.version },
      version: record.version,
      expires_at: record.expires_at,
    });
    expect(typeof mission.fresh_until).toBe("string");
    expect(mission.fresh_until).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/);
    expect(Date.parse(mission.fresh_until as string)).toBe((payload.exp as number) * 1000);
  });

  it("answers suspend, resume and complete with the same signed shape, and an idempotent success with the current state", async () => {
    const m = approve();
    const expected: Array<[string, string, string | undefined]> = [
      ["suspend", "suspended", undefined],
      ["suspend", "suspended", undefined],
      ["resume", "active", undefined],
      ["complete", "terminated", "completed"],
    ];
    let lastVersion = m.version;
    for (const [operation, state, reason] of expected) {
      const n = nonce();
      const res = await op({ mission_id: m.id, operation, nonce: n });
      expect(res.status, `${operation}: ${res.text}`).toBe(200);
      expect(res.contentType).toBe("application/mission-status-response+jwt");
      const payload = await verifySigned(res.text);
      const mission = payload.mission as Record<string, unknown>;
      expect(payload).toMatchObject({ aud: consoleClient.clientId, sub: consoleClient.clientId, nonce: n });
      expect(mission.state, operation).toBe(state);
      expect(mission.expires_at).toBe(m.expires_at);
      expect(typeof mission.fresh_until).toBe("string");
      expect(mission.version as number).toBeGreaterThanOrEqual(lastVersion);
      if (reason) expect(mission.termination).toMatchObject({ reason });
      else expect(Object.hasOwn(mission, "termination")).toBe(false);
      lastVersion = mission.version as number;
    }
  });
});

describe("Mission Lifecycle endpoint retries (@spec status#idempotency, control-plane#serialization, #1191)", () => {
  it("replays a same-nonce retry byte for byte under a regenerated client assertion, and refuses the same nonce with different members", async () => {
    const m = approve();
    const n = nonce();
    const first = await op({ mission_id: m.id, operation: "suspend", nonce: n });
    expect(first.status, first.text).toBe(200);
    expect((await op({ mission_id: m.id, operation: "resume", nonce: nonce() })).status).toBe(200);
    // A fresh assertion (new jti) on the retry: authentication parameters are
    // not operation members, so this is the same request and replays.
    const retry = await op({ operation: "suspend", nonce: n, mission_id: m.id });
    expect(retry.status).toBe(200);
    expect(retry.text).toBe(first.text);
    expect(as.kernel.get(m.id)?.state).toBe("active");
    const divergent = await op({ mission_id: m.id, operation: "suspend", nonce: n, reason: "another request" });
    expect(divergent.status, divergent.text).toBe(400);
    expect(divergent.json).toMatchObject({ error: "invalid_request", nonce: n });
  });

  it("recovers a committed response whose bytes were lost at its original observation: the same iat, exp and fresh_until", async () => {
    const m = approve();
    const n = nonce();
    const first = await op({ mission_id: m.id, operation: "revoke", nonce: n });
    expect(first.status, first.text).toBe(200);
    const original = decodeStatusResponse(first.text).payload;
    // The crash after the commit and before the bytes were retained.
    as.kernel.db
      .prepare(
        `UPDATE lifecycle_responses SET state = 'committed', body = ''
         WHERE endpoint = ? AND principal = ? AND mission_id = ? AND nonce = ?`,
      )
      .run(LIFECYCLE_ENDPOINT_KEY, consoleClient.clientId, m.id, n);
    await new Promise((r) => setTimeout(r, 1100));
    const recovered = await op({ mission_id: m.id, operation: "revoke", nonce: n });
    expect(recovered.status, recovered.text).toBe(200);
    const payload = await verifySigned(recovered.text);
    expect(payload.iat).toBe(original.iat);
    expect(payload.exp).toBe(original.exp);
    expect(payload.nonce).toBe(n);
    expect((payload.mission as Record<string, unknown>).fresh_until).toBe(
      (original.mission as Record<string, unknown>).fresh_until,
    );
    expect(payload).toEqual(original);
    expect(retainedRow(consoleClient.clientId, m.id, n)?.state).toBe("final");
  });
});

describe("Mission Lifecycle endpoint transient failures (@spec status#idempotency, status#mission-status-errors, #1191)", () => {
  it("answers a failure inside the transition unavailable (503), retains nothing, and a same-nonce retry is processed afresh and succeeds", async () => {
    const m = approve();
    const n = nonce();
    vi.spyOn(as.kernel, "transition").mockImplementationOnce(() => {
      throw new Error("SQLITE_IOERR: disk I/O error");
    });
    const failed = await op({ mission_id: m.id, operation: "suspend", nonce: n });
    expect(failed.status, failed.text).toBe(503);
    expect(failed.json).toMatchObject({ error: "unavailable", nonce: n });
    expect(typeof failed.json?.error_description).toBe("string");
    expect(retainedRow(consoleClient.clientId, m.id, n)).toBeUndefined();
    expect(as.kernel.get(m.id)?.state).toBe("active");
    const retry = await op({ mission_id: m.id, operation: "suspend", nonce: n });
    expect(retry.status, retry.text).toBe(200);
    expect((decodeStatusResponse(retry.text).mission as Record<string, unknown>).state).toBe("suspended");
  });

  it("answers a failure of the nonce lookup unavailable, and retains nothing", async () => {
    const m = approve();
    const n = nonce();
    vi.spyOn(LifecycleResponseStore.prototype, "find").mockImplementationOnce(() => {
      throw new Error("SQLITE_BUSY: database is locked");
    });
    const failed = await op({ mission_id: m.id, operation: "revoke", nonce: n });
    expect(failed.status, failed.text).toBe(503);
    expect(failed.json?.error).toBe("unavailable");
    expect(retainedRow(consoleClient.clientId, m.id, n)).toBeUndefined();
    expect(as.kernel.get(m.id)?.state).toBe("active");
  });

  it("answers an unknown Mission not_found and retains it, so the same-nonce retry replays the 404", async () => {
    const n = nonce();
    const unknown = await op({ mission_id: UNKNOWN, operation: "revoke", nonce: n });
    expect(unknown.status, unknown.text).toBe(404);
    expect(unknown.json).toMatchObject({ error: "not_found", nonce: n });
    expect(retainedRow(consoleClient.clientId, UNKNOWN, n)?.status).toBe(404);
    const replay = await op({ mission_id: UNKNOWN, operation: "revoke", nonce: n });
    expect(replay.status).toBe(404);
    expect(replay.text).toBe(unknown.text);
  });
});

describe("Mission Lifecycle endpoint extension operations and the common guard (@spec status#idempotency, discharge#discharge-operation, #1191)", () => {
  const containMembers = () => ({
    operation: "contain",
    event: JSON.stringify({
      type: "incident",
      source: "review",
      observed_at: new Date().toISOString(),
      event_id: crypto.randomUUID(),
    }),
    remove: JSON.stringify([{ resource: CANONICAL_RESOURCE, actions: ["payments:invoice.read"] }]),
  });

  it("contain honors the common expected_version guard: a stale one is refused 409 stale_version and nothing commits, a current one narrows", async () => {
    const m = approve();
    const n = nonce();
    const stale = await op({ mission_id: m.id, nonce: n, expected_version: String(m.version + 10), ...containMembers() });
    expect(stale.status, stale.text).toBe(409);
    expect(stale.json).toMatchObject({ error: "stale_version", nonce: n });
    expect(as.kernel.get(m.id)?.version).toBe(m.version);
    expect(as.kernel.get(m.id)?.containment).toBeUndefined();
    const currentNonce = nonce();
    const currentMembers = { mission_id: m.id, nonce: currentNonce, expected_version: String(m.version), ...containMembers() };
    const current = await op(currentMembers);
    expect(current.status, current.text).toBe(200);
    expect(current.json).toMatchObject({ state: "active", version: m.version + 1, containment_version: 1 });
    // The retained response stays ahead of the guard: the retransmit replays
    // its success although its expected_version is now stale.
    const retry = await op(currentMembers);
    expect(retry.status, retry.text).toBe(200);
    expect(retry.text).toBe(current.text);
    expect(as.kernel.get(m.id)?.version).toBe(m.version + 1);
  });

  it("refuses the schedule members on contain and discharge, and expected_version on discharge, before any Mission is read", async () => {
    const m = approve();
    const before = as.kernel.get(m.id);
    const discharge = {
      operation: "discharge",
      entry_digest: `sha-256:${"A".repeat(43)}`,
      condition_digest: `sha-256:${"B".repeat(43)}`,
      event_type: "accounting-period-closed",
      event_id: "close-guard-1",
    };
    for (const members of [
      { ...containMembers(), suspend_until: "2026-12-01T00:00:00Z", on_expiry: "revoke" },
      { ...discharge, suspend_until: "2026-12-01T00:00:00Z", on_expiry: "resume" },
      { ...discharge, expected_version: String(m.version) },
    ]) {
      const known = await op({ mission_id: m.id, nonce: nonce(), ...members });
      const unknown = await op({ mission_id: UNKNOWN, nonce: nonce(), ...members });
      expect(known.status, `${members.operation}: ${known.text}`).toBe(400);
      expect(known.json?.error).toBe("invalid_request");
      expect(unknown.status).toBe(400);
      expect(unknown.json?.error_description).toBe(known.json?.error_description);
    }
    // Without the refused member, the same discharge reaches the endpoint's
    // authority check: this caller holds no discharge grant.
    const plain = await op({ mission_id: m.id, nonce: nonce(), ...discharge });
    expect(plain.status, plain.text).toBe(404);
    expect(as.kernel.get(m.id)).toEqual(before);
  });
});

describe("the dev-only path route runs the same engine (@spec status#mission-lifecycle-endpoint, #1191)", () => {
  const dev = async (missionId: string, body: Record<string, unknown>): Promise<LifecycleAnswer> =>
    readAnswer(
      await fetch(`${ISSUER}/missions/${missionId}/lifecycle`, {
        method: "POST",
        headers: { "content-type": "application/json", "x-service-token": DEV_SERVICE_TOKEN },
        body: JSON.stringify(body),
      }),
    );

  it("answers with the signed state-only response, requires a nonce, and refuses a body naming another Mission", async () => {
    const m = approve();
    const missing = await dev(m.id, { operation: "suspend" });
    expect(missing.status, missing.text).toBe(400);
    expect(missing.json?.error).toBe("invalid_request");
    const other = await dev(m.id, { operation: "suspend", nonce: nonce(), mission_id: UNKNOWN });
    expect(other.status, other.text).toBe(400);
    const n = nonce();
    const res = await dev(m.id, { operation: "suspend", nonce: n });
    expect(res.status, res.text).toBe(200);
    expect(res.contentType).toBe("application/mission-status-response+jwt");
    const payload = await verifySigned(res.text);
    expect(payload).toMatchObject({ aud: "svc:console", sub: "svc:console", nonce: n });
    expect((payload.mission as Record<string, unknown>).state).toBe("suspended");
  });
});
