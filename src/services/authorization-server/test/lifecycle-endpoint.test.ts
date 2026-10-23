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
 *  - client authentication: no credential, a foreign credential, a missing
 *    or foreign `client_assertion_type`, a type without an assertion, the
 *    assertion `aud` as the issuer identifier and nothing else, the permitted
 *    `typ` values, `exp`/`jti`, replay, signature and registration;
 *  - authorization: a client without the lifecycle grant gets the unknown
 *    Mission's answer, and so does one whose deployment policy places the
 *    Mission outside the tenant, Subject or requesting client it may act on
 *    (#1535);
 *  - processing order: authorization precedes deduplication, so a caller
 *    whose grant was withdrawn after a success gets the not-found response,
 *    never a replay, and a refusal decided before deduplication retains
 *    nothing (#1535);
 *  - the request members: `nonce`, `mission_id`, `reason`, `expected_version`
 *    and the schedule members;
 *  - the signed state-only response for every base operation, idempotent
 *    success included;
 *  - retries: byte-for-byte replay under a regenerated assertion, divergent
 *    refusal, and recovery of a lost response at its original observation;
 *  - transient failures: `unavailable`, never retained, and the unknown
 *    Mission's `not_found`, refused at authorization and not retained either;
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
/** Another tenant's Subject issuer, beside this AS's own. */
const TENANT_B = "https://tenant-b.example";

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
/** Holds `mission_lifecycle` under a policy reaching only Missions whose Subject belongs to tenant B, another issuer namespace. */
let tenantClient: LifecycleTestClient;
/** Holds `mission_lifecycle` under a policy reaching every Mission whose Subject belongs to this AS's own namespace. */
let homeTenantClient: LifecycleTestClient;
/** Holds `mission_lifecycle` under a policy reaching only dana's Missions requested by `ap-agent`. */
let danaClient: LifecycleTestClient;
/** Holds `mission_lifecycle` through a grant list a test withdraws and restores. */
let withdrawableClient: LifecycleTestClient;
const withdrawableGrants: string[] = [MISSION_LIFECYCLE_SCOPE];
let approvals = 0;

const proposal = (): AuthorityEntry[] => [
  { type: "mission_resource_access", resource: CANONICAL_RESOURCE, actions: ["payments:invoice.read"] },
];

function approve(subject = { iss: ISSUER, sub: "alice" }, clientId = "ap-agent"): MissionRecord {
  approvals += 1;
  return as.kernel.approve({
    intent: validateMissionIntent(
      JSON.stringify({ goal: "Read invoices for the close", target_resources: [CANONICAL_RESOURCE], expires_at: EXPIRES_AT }),
    ),
    proposedAuthority: proposal(),
    subject,
    approver: { iss: ISSUER, sub: "bob" },
    clientId,
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
  tenantClient = await newLifecycleClient("tenant-b-console");
  homeTenantClient = await newLifecycleClient("home-tenant-console");
  danaClient = await newLifecycleClient("dana-console");
  withdrawableClient = await newLifecycleClient("withdrawable-console");
  as = await buildAuthorizationServer({
    issuer: ISSUER,
    testClients: [
      consoleClient.metadata,
      readerClient.metadata,
      ungrantedClient.metadata,
      es384Client.metadata,
      tenantClient.metadata,
      homeTenantClient.metadata,
      danaClient.metadata,
      withdrawableClient.metadata,
    ],
    lifecycleClientGrants: {
      [consoleClient.clientId]: [MISSION_LIFECYCLE_SCOPE],
      [es384Client.clientId]: [MISSION_LIFECYCLE_SCOPE],
      [readerClient.clientId]: [MISSION_STATUS_SCOPE],
      [tenantClient.clientId]: { grants: [MISSION_LIFECYCLE_SCOPE], missions: { subjects: [{ iss: TENANT_B }] } },
      [homeTenantClient.clientId]: { grants: [MISSION_LIFECYCLE_SCOPE], missions: { subjects: [{ iss: ISSUER }] } },
      [danaClient.clientId]: {
        grants: [MISSION_LIFECYCLE_SCOPE],
        missions: { subjects: [{ iss: ISSUER, sub: "dana" }], clients: ["ap-agent"] },
      },
      [withdrawableClient.clientId]: withdrawableGrants,
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

  it("refuses an assertion sent without client_assertion_type or under another type, and a client_assertion_type sent without an assertion, invalid_client (HTTP 400)", async () => {
    // @spec status#mission-status-request, status#lifecycle-operations (#1535):
    // private-key-JWT client authentication carries both parameters, the type
    // with the jwt-bearer value.
    const m = approve();
    const members = { mission_id: m.id, operation: "revoke", nonce: nonce() };
    const answers = [
      await postLifecycleForm(ISSUER, {
        ...members,
        client_assertion: await lifecycleClientAssertion(ISSUER, consoleClient),
      }),
      await postLifecycleForm(ISSUER, {
        ...members,
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:saml2-bearer",
        client_assertion: await lifecycleClientAssertion(ISSUER, consoleClient),
      }),
      await postLifecycleForm(ISSUER, { ...members, client_assertion_type: CLIENT_ASSERTION_TYPE }),
    ];
    for (const a of answers) {
      expect(a.status, a.text).toBe(400);
      expect(a.json?.error).toBe("invalid_client");
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

describe("Mission Lifecycle authorization for the acting party, operation and Mission (@spec status#lifecycle-authorization, #1535)", () => {
  it("refuses at boot a lifecycle policy naming an operation the lifecycle grant does not govern", async () => {
    await expect(
      buildAuthorizationServer({
        issuer: "http://localhost:1",
        lifecycleClientGrants: { [consoleClient.clientId]: { grants: [MISSION_LIFECYCLE_SCOPE], operations: ["discharge"] } },
      }),
    ).rejects.toThrow(/unknown operation discharge/);
  });

  it("answers a client holding the lifecycle grant for another tenant exactly as it answers an unknown Mission: revoke, complete on a revoked Mission and a stale expected_version alike, leaving the Mission unchanged; a client whose policy names the Mission's tenant acts on it", async () => {
    const m = approve();
    const before = as.kernel.get(m.id);
    const shape = (a: LifecycleAnswer) => ({
      status: a.status,
      contentType: a.contentType,
      cacheControl: a.cacheControl,
      wwwAuthenticate: a.wwwAuthenticate,
      json: a.json,
    });
    const n = nonce();
    const refused = await lifecycleRequest(ISSUER, tenantClient, { mission_id: m.id, operation: "revoke", nonce: n });
    const unknown = await lifecycleRequest(ISSUER, tenantClient, { mission_id: UNKNOWN, operation: "revoke", nonce: n });
    expect(refused.status, refused.text).toBe(404);
    expect(refused.json).toEqual({
      error: "not_found",
      error_description: "Mission reference is not found or not visible.",
      nonce: n,
    });
    expect(shape(refused)).toEqual(shape(unknown));
    expect(refused.text).toBe(unknown.text);
    // A stale guard, which the authorized console is refused 409 stale_version.
    const stale = await lifecycleRequest(ISSUER, tenantClient, {
      mission_id: m.id,
      operation: "suspend",
      nonce: nonce(),
      expected_version: String(m.version + 1),
    });
    expect(stale.status, stale.text).toBe(404);
    expect(stale.json?.error).toBe("not_found");
    expect(as.kernel.get(m.id)).toEqual(before);
    // `complete` on a Mission the console revoked, which it is refused 409 conflict.
    const revoked = approve();
    expect((await op({ mission_id: revoked.id, operation: "revoke", nonce: nonce() })).status).toBe(200);
    const revokedBefore = as.kernel.get(revoked.id);
    const conflict = await op({ mission_id: revoked.id, operation: "complete", nonce: nonce() });
    expect(conflict.json?.error).toBe("conflict");
    const complete = await lifecycleRequest(ISSUER, tenantClient, {
      mission_id: revoked.id,
      operation: "complete",
      nonce: nonce(),
    });
    expect(complete.status, complete.text).toBe(404);
    expect(complete.json?.error).toBe("not_found");
    expect(as.kernel.get(revoked.id)).toEqual(revokedBefore);
    // A client whose policy names this tenant acts on the same Mission.
    const acted = await lifecycleRequest(ISSUER, homeTenantClient, { mission_id: m.id, operation: "revoke", nonce: nonce() });
    expect(acted.status, acted.text).toBe(200);
    expect(as.kernel.get(m.id)?.termination?.reason).toBe("revoked");
  });

  it("scopes a client's lifecycle grant to the Subject and the requesting client its policy names, refusing every other Mission as an unknown one", async () => {
    const alices = approve();
    const anotherClients = approve({ iss: ISSUER, sub: "dana" }, "agent-A1");
    for (const outside of [alices, anotherClients]) {
      const refused = await lifecycleRequest(ISSUER, danaClient, { mission_id: outside.id, operation: "suspend", nonce: nonce() });
      expect(refused.status, refused.text).toBe(404);
      expect(refused.json?.error).toBe("not_found");
      expect(as.kernel.get(outside.id)?.state).toBe("active");
    }
    const danas = approve({ iss: ISSUER, sub: "dana" });
    const acted = await lifecycleRequest(ISSUER, danaClient, { mission_id: danas.id, operation: "suspend", nonce: nonce() });
    expect(acted.status, acted.text).toBe(200);
    expect(as.kernel.get(danas.id)?.state).toBe("suspended");
  });
});

describe("Mission Lifecycle endpoint processing order (@spec status#lifecycle-processing, status#idempotency, #1535)", () => {
  it("authenticates the caller before validating the request: an unauthenticated request is refused invalid_client whatever its operation, members or Mission", async () => {
    const m = approve();
    for (const members of [
      { mission_id: m.id, operation: "rename", nonce: nonce() },
      { mission_id: m.id, operation: "suspend", nonce: nonce(), on_expiry: "resume" },
      { mission_id: m.id, operation: "discharge", nonce: nonce(), event_type: "close", event_id: "not a valid event id" },
      { mission_id: UNKNOWN, operation: "revoke", nonce: nonce() },
    ]) {
      const refused = await postLifecycleForm(ISSUER, members);
      expect(refused.status, `${JSON.stringify(members)}: ${refused.text}`).toBe(400);
      expect(refused.json?.error).toBe("invalid_client");
    }
    expect(as.kernel.get(m.id)?.state).toBe("active");
  });

  it("authorizes a retransmit before deduplication: after the client's grant is withdrawn, the same nonce and members under a fresh assertion get the not-found response, not the replayed success, and the success replays once the grant returns", async () => {
    const m = approve();
    const n = nonce();
    const members = { mission_id: m.id, operation: "revoke", nonce: n };
    const first = await lifecycleRequest(ISSUER, withdrawableClient, members);
    expect(first.status, first.text).toBe(200);
    const withdrawn = withdrawableGrants.splice(0);
    try {
      const refused = await lifecycleRequest(ISSUER, withdrawableClient, members);
      expect(refused.status, refused.text).toBe(404);
      expect(refused.json).toEqual({
        error: "not_found",
        error_description: "Mission reference is not found or not visible.",
        nonce: n,
      });
    } finally {
      withdrawableGrants.push(...withdrawn);
    }
    const replay = await lifecycleRequest(ISSUER, withdrawableClient, members);
    expect(replay.status).toBe(200);
    expect(replay.text).toBe(first.text);
  });

  it("keeps a retained success through a refusal decided before deduplication, so a later authorized request with that nonce and different members is refused as a divergent retry, never processed fresh", async () => {
    const m = approve();
    const n = nonce();
    const first = await lifecycleRequest(ISSUER, withdrawableClient, { mission_id: m.id, operation: "suspend", nonce: n });
    expect(first.status, first.text).toBe(200);
    const retained = retainedRow(withdrawableClient.clientId, m.id, n);
    const divergent = { mission_id: m.id, operation: "resume", nonce: n };
    const withdrawn = withdrawableGrants.splice(0);
    try {
      const refused = await lifecycleRequest(ISSUER, withdrawableClient, divergent);
      expect(refused.status, refused.text).toBe(404);
    } finally {
      withdrawableGrants.push(...withdrawn);
    }
    expect(retainedRow(withdrawableClient.clientId, m.id, n)).toEqual(retained);
    const later = await lifecycleRequest(ISSUER, withdrawableClient, divergent);
    expect(later.status, later.text).toBe(400);
    expect(later.json?.error).toBe("invalid_request");
    expect(as.kernel.get(m.id)?.state).toBe("suspended");
  });

  it("retains nothing for a refusal decided before deduplication, so a committed success whose bytes were lost survives a refused retransmit and is recovered once the grant returns", async () => {
    const m = approve();
    const n = nonce();
    const members = { mission_id: m.id, operation: "revoke", nonce: n };
    const first = await lifecycleRequest(ISSUER, withdrawableClient, members);
    expect(first.status, first.text).toBe(200);
    // The crash after the commit and before the bytes were retained.
    as.kernel.db
      .prepare(
        `UPDATE lifecycle_responses SET state = 'committed', body = ''
         WHERE endpoint = ? AND principal = ? AND mission_id = ? AND nonce = ?`,
      )
      .run(LIFECYCLE_ENDPOINT_KEY, withdrawableClient.clientId, m.id, n);
    const claimed = retainedRow(withdrawableClient.clientId, m.id, n);
    const withdrawn = withdrawableGrants.splice(0);
    try {
      const refused = await lifecycleRequest(ISSUER, withdrawableClient, members);
      expect(refused.status, refused.text).toBe(404);
    } finally {
      withdrawableGrants.push(...withdrawn);
    }
    expect(retainedRow(withdrawableClient.clientId, m.id, n)).toEqual(claimed);
    const recovered = await lifecycleRequest(ISSUER, withdrawableClient, members);
    expect(recovered.status, recovered.text).toBe(200);
    expect(decodeStatusResponse(recovered.text).payload).toEqual(decodeStatusResponse(first.text).payload);
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

  it("answers an unknown Mission not_found at authorization, before deduplication, retaining nothing, so the same-nonce retry is processed afresh and answers the same 404 (#1535)", async () => {
    const n = nonce();
    const unknown = await op({ mission_id: UNKNOWN, operation: "revoke", nonce: n });
    expect(unknown.status, unknown.text).toBe(404);
    expect(unknown.json).toMatchObject({ error: "not_found", nonce: n });
    expect(retainedRow(consoleClient.clientId, UNKNOWN, n)).toBeUndefined();
    const retry = await op({ mission_id: UNKNOWN, operation: "revoke", nonce: n });
    expect(retry.status).toBe(404);
    expect(retry.text).toBe(unknown.text);
    expect(retainedRow(consoleClient.clientId, UNKNOWN, n)).toBeUndefined();
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

/** POST a raw form to the Lifecycle endpoint, which may repeat a parameter. */
async function postLifecyclePairs(pairs: Array<[string, string]>): Promise<LifecycleAnswer> {
  const res = await fetch(ENDPOINT, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(pairs).toString(),
  });
  return readAnswer(res);
}

describe("Mission Lifecycle endpoint parsing and repeated parameters (@spec status#lifecycle-processing, #1535 D704, D708)", () => {
  it("refuses a body it cannot parse as a form invalid_request before authentication, with or without a credential, and changes nothing", async () => {
    const m = approve();
    const n = nonce();
    const json = await readAnswer(
      await fetch(ENDPOINT, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ mission_id: m.id, operation: "revoke", nonce: n }),
      }),
    );
    const textPlain = await readAnswer(
      await fetch(ENDPOINT, {
        method: "POST",
        headers: { "content-type": "text/plain" },
        body: new URLSearchParams({
          mission_id: m.id,
          operation: "revoke",
          nonce: n,
          client_assertion_type: CLIENT_ASSERTION_TYPE,
          client_assertion: await lifecycleClientAssertion(ISSUER, consoleClient),
        }).toString(),
      }),
    );
    for (const [label, answer] of [["JSON, no credential", json], ["text/plain, a valid assertion", textPlain]] as const) {
      expect(answer.status, label).toBe(400);
      expect(answer.json?.error, label).toBe("invalid_request");
      expect(answer.json?.nonce, label).toBeUndefined();
    }
    expect(as.kernel.get(m.id)?.state).toBe("active");
  });

  it("fails authentication on a repeated client authentication parameter, invalid_client, verifies no occurrence and changes nothing", async () => {
    const m = approve();
    const n = nonce();
    const members: Array<[string, string]> = [
      ["mission_id", m.id],
      ["operation", "revoke"],
      ["nonce", n],
    ];
    const first = await lifecycleClientAssertion(ISSUER, consoleClient);
    const second = await lifecycleClientAssertion(ISSUER, consoleClient);
    const cases: Array<[string, Array<[string, string]>]> = [
      ["two valid assertions", [["client_assertion_type", CLIENT_ASSERTION_TYPE], ["client_assertion", first], ["client_assertion", second]]],
      ["one assertion twice", [["client_assertion_type", CLIENT_ASSERTION_TYPE], ["client_assertion", first], ["client_assertion", first]]],
      ["client_assertion_type twice", [["client_assertion_type", CLIENT_ASSERTION_TYPE], ["client_assertion_type", CLIENT_ASSERTION_TYPE], ["client_assertion", first]]],
      ["client_id twice", [["client_id", consoleClient.clientId], ["client_id", consoleClient.clientId], ["client_assertion_type", CLIENT_ASSERTION_TYPE], ["client_assertion", first]]],
    ];
    for (const [label, credential] of cases) {
      const answer = await postLifecyclePairs([...members, ...credential]);
      expect(answer.status, label).toBe(400);
      expect(answer.json?.error, label).toBe("invalid_client");
      expect(answer.json?.nonce, label).toBe(n);
    }
    expect(as.kernel.get(m.id)?.state).toBe("active");
    // No occurrence was tried: the assertion's single-use jti was never
    // admitted, so it still authenticates a request that sends it once.
    const once = await postLifecyclePairs([...members, ["client_assertion_type", CLIENT_ASSERTION_TYPE], ["client_assertion", first]]);
    expect(once.status, once.text).toBe(200);
    expect(as.kernel.get(m.id)?.state).toBe("terminated");
  });

  it("authenticates before refusing a repeated request parameter: invalid_client without a valid credential, invalid_request with one, and changes nothing", async () => {
    const m = approve();
    const n = nonce();
    const credential = async (): Promise<Array<[string, string]>> => [
      ["client_assertion_type", CLIENT_ASSERTION_TYPE],
      ["client_assertion", await lifecycleClientAssertion(ISSUER, consoleClient)],
    ];
    const unauthenticated: Array<[string, Array<[string, string]>]> = [
      [
        "a repeated reason, no credential",
        [["mission_id", m.id], ["operation", "revoke"], ["reason", "a"], ["reason", "b"], ["nonce", n]],
      ],
      [
        "a repeated reason, an assertion that is not a JWT",
        [
          ["mission_id", m.id],
          ["operation", "revoke"],
          ["reason", "a"],
          ["reason", "b"],
          ["nonce", n],
          ["client_assertion_type", CLIENT_ASSERTION_TYPE],
          ["client_assertion", "not-a-jwt"],
        ],
      ],
      [
        "a repeated reason and a repeated assertion",
        [
          ["mission_id", m.id],
          ["operation", "revoke"],
          ["reason", "a"],
          ["reason", "b"],
          ["nonce", n],
          ...(await credential()),
          ["client_assertion", "not-a-jwt"],
        ],
      ],
    ];
    for (const [label, pairs] of unauthenticated) {
      const answer = await postLifecyclePairs(pairs);
      expect(answer.status, label).toBe(400);
      expect(answer.json?.error, label).toBe("invalid_client");
    }
    const repeatedReason = await postLifecyclePairs([
      ["mission_id", m.id],
      ["operation", "revoke"],
      ["reason", "a"],
      ["reason", "b"],
      ["nonce", n],
      ...(await credential()),
    ]);
    expect(repeatedReason.status, repeatedReason.text).toBe(400);
    expect(repeatedReason.json?.error).toBe("invalid_request");
    expect(repeatedReason.json?.nonce).toBe(n);
    const repeatedNonce = await postLifecyclePairs([["mission_id", m.id], ["operation", "revoke"], ["nonce", n], ["nonce", n], ...(await credential())]);
    expect(repeatedNonce.status, repeatedNonce.text).toBe(400);
    expect(repeatedNonce.json?.error).toBe("invalid_request");
    expect(repeatedNonce.json?.nonce).toBeUndefined();
    expect(as.kernel.get(m.id)?.state).toBe("active");
  });
});
