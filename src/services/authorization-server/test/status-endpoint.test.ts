/**
 * @spec status#mission-status-request, status#mission-status-authentication,
 * status#mission-status-auth-failures, status#mission-status-response,
 * status#mission-status-errors, status#as-metadata,
 * authority-server#join-disclosure (#1407): the advertised Mission Status
 * endpoint.
 *
 * Covered:
 *  - discovery: `mission_status_endpoint`, its private_key_jwt method and
 *    assertion algorithms, all absent where the Status operation is not served;
 *  - the profile's form POST (`mission_id`, `audience`, `nonce`) answered with
 *    a signed Mission Status Response whose `sub` is the authenticated client;
 *  - Join Disclosure keyed by that client: only the enrolled client reads the
 *    Mission's client, and no other caller reads it in `mission` or in `sub`;
 *  - the state-only read: `aud` is the client's `client_id`;
 *  - the profile's errors: `invalid_request` for a malformed request,
 *    `invalid_client` for a failed or absent client authentication, and the
 *    anti-oracle `not_found` for a client without the grant and an unknown
 *    Mission, each with `error_description` and the well-formed `nonce`;
 *  - the development GET route signs its service principal as `sub` too.
 */

import type { Server } from "node:http";
import { CANONICAL_RESOURCE } from "@mission/demo-data";
import { createLocalJWKSet, decodeJwt, generateKeyPair, type JWK, jwtVerify } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { STATUS_ENDPOINT_PATH } from "../src/adapters/lifecycle-endpoint.js";
import {
  ALL_PROVIDER_CAPABILITIES,
  type BuiltAs,
  buildAuthorizationServer,
  MISSION_STATUS_SCOPE,
  type MissionRecord,
  validateMissionIntent,
} from "../src/index.js";
import {
  CLIENT_ASSERTION_TYPE,
  type LifecycleAnswer,
  type LifecycleTestClient,
  lifecycleClientAssertion,
  newLifecycleClient,
  readAnswer,
} from "./lifecycle-endpoint.helper.js";

const PORT = 14891;
const ISSUER = `http://localhost:${PORT}`;
const BARE_PORT = 14892;
const BARE_ISSUER = `http://localhost:${BARE_PORT}`;
const ENDPOINT = `${ISSUER}${STATUS_ENDPOINT_PATH}`;
const UNKNOWN = "msn_unknown_0000000000000000000000";
const MISSION_CLIENT = "ap-agent";
const SERVICE_TOKEN = "status-endpoint-service-token";
const SERVICE_PRINCIPAL = "svc:status-endpoint-reader";

let as: BuiltAs;
let server: Server;
let bare: BuiltAs;
let bareServer: Server;
/** Holds `mission_status`, enrolled for Join Disclosure on the payments scope. */
let pdp: LifecycleTestClient;
/** Holds `mission_status`, enrolled for nothing. */
let reader: LifecycleTestClient;
/** Registered and authenticates, holds no grant. */
let ungranted: LifecycleTestClient;
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
    clientId: MISSION_CLIENT,
    approvalEventId: `apev-status-endpoint-${approvals}`,
  });
}

const nonce = (): string => `nonce-se-${crypto.randomUUID()}`;

/** POST a form to the advertised Status endpoint, exactly as given. */
async function post(form: Record<string, string>, headers: Record<string, string> = {}, url = ENDPOINT): Promise<LifecycleAnswer> {
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", ...headers },
    body: new URLSearchParams(form).toString(),
  });
  return readAnswer(res);
}

/** A Status read by `client`, authenticated by a fresh client assertion unless one is given. */
async function read(client: LifecycleTestClient, members: Record<string, string>, assertion?: string): Promise<LifecycleAnswer> {
  return post({
    ...members,
    client_assertion_type: CLIENT_ASSERTION_TYPE,
    client_assertion: assertion ?? (await lifecycleClientAssertion(ISSUER, client)),
  });
}

/** Verify a signed response against the AS's published keys. */
async function verified(text: string): Promise<Record<string, unknown>> {
  const jwks = (await (await fetch(`${ISSUER}/jwks`)).json()) as { keys: JWK[] };
  const { payload } = await jwtVerify(text, createLocalJWKSet(jwks), {
    typ: "mission-status-response+jwt",
    algorithms: ["ES256"],
    issuer: ISSUER,
  });
  return payload as Record<string, unknown>;
}

async function discovery(issuer: string): Promise<Record<string, unknown>> {
  return (await (await fetch(`${issuer}/.well-known/openid-configuration`)).json()) as Record<string, unknown>;
}

beforeAll(async () => {
  pdp = await newLifecycleClient("status-endpoint-pdp");
  reader = await newLifecycleClient("status-endpoint-reader");
  ungranted = await newLifecycleClient("status-endpoint-ungranted");
  as = await buildAuthorizationServer({
    issuer: ISSUER,
    testClients: [pdp.metadata, reader.metadata, ungranted.metadata],
    lifecycleClientGrants: { [pdp.clientId]: [MISSION_STATUS_SCOPE], [reader.clientId]: [MISSION_STATUS_SCOPE] },
    enrolledJoinPdps: { [pdp.clientId]: [CANONICAL_RESOURCE] },
    serviceTokenPrincipals: { [SERVICE_TOKEN]: { principal_id: SERVICE_PRINCIPAL, scopes: [MISSION_STATUS_SCOPE] } },
  });
  server = as.provider.listen(PORT);
  bare = await buildAuthorizationServer({
    issuer: BARE_ISSUER,
    capabilities: new Set(ALL_PROVIDER_CAPABILITIES.filter((c) => c !== "status")),
  });
  bareServer = bare.provider.listen(BARE_PORT);
});

afterAll(() => {
  server?.close();
  bareServer?.close();
});

describe("Mission Status endpoint discovery (@spec status#as-metadata, #1407)", () => {
  it("advertises the endpoint, its private_key_jwt method and assertion algorithms where the Status operation is served, and none of them where it is not", async () => {
    const meta = await discovery(ISSUER);
    expect(meta.mission_status_endpoint).toBe(ENDPOINT);
    expect(meta.mission_status_endpoint_auth_methods_supported).toEqual(["private_key_jwt"]);
    expect(meta.mission_status_endpoint_auth_signing_alg_values_supported).toEqual(["ES256"]);

    const without = await discovery(BARE_ISSUER);
    expect(without.mission_status_endpoint).toBeUndefined();
    expect(without.mission_status_endpoint_auth_methods_supported).toBeUndefined();
    expect(without.mission_status_endpoint_auth_signing_alg_values_supported).toBeUndefined();
    const served = await post({ mission_id: UNKNOWN, nonce: nonce() }, {}, `${BARE_ISSUER}${STATUS_ENDPOINT_PATH}`);
    expect(served.contentType.startsWith("application/mission-status-response+jwt")).toBe(false);
  });
});

describe("Mission Status endpoint request and response (@spec status#mission-status-request, status#mission-status-response, #1407)", () => {
  it("answers the profile's form POST with a signed Mission Status Response: the requested Mission and audience, the request's nonce, and sub the authenticated client", async () => {
    const record = approve();
    const n = nonce();
    const answer = await read(reader, { mission_id: record.id, audience: CANONICAL_RESOURCE, nonce: n });
    expect(answer.status).toBe(200);
    expect(answer.contentType).toBe("application/mission-status-response+jwt");
    expect(answer.cacheControl).toBe("no-store");
    const payload = await verified(answer.text);
    expect(payload).toMatchObject({ aud: CANONICAL_RESOURCE, sub: reader.clientId, nonce: n, mission: { id: record.id, state: "active" } });
    expect(payload.authorization_details).toEqual([expect.objectContaining({ resource: CANONICAL_RESOURCE })]);
  });

  it("binds sub to each caller: two clients read their own identifiers, and the Mission's client reaches only the client enrolled for Join Disclosure", async () => {
    const record = approve();
    const enrolled = await verified((await read(pdp, { mission_id: record.id, audience: CANONICAL_RESOURCE, nonce: nonce() })).text);
    const other = await verified((await read(reader, { mission_id: record.id, audience: CANONICAL_RESOURCE, nonce: nonce() })).text);

    expect(enrolled.sub).toBe(pdp.clientId);
    expect(enrolled.mission).toMatchObject({ client_id: MISSION_CLIENT, subject: { iss: ISSUER, sub: "alice" } });

    expect(other.sub).toBe(reader.clientId);
    const mission = other.mission as Record<string, unknown>;
    expect("client_id" in mission).toBe(false);
    expect("subject" in mission).toBe(false);
    // Nowhere in what the caller not enrolled reads: not in `mission`, not in `sub`.
    expect(JSON.stringify(other)).not.toContain(MISSION_CLIENT);

    // The enrolled client for no scope is any other caller.
    const unscoped = await verified((await read(pdp, { mission_id: record.id, nonce: nonce() })).text);
    expect(unscoped.sub).toBe(pdp.clientId);
    expect(JSON.stringify(unscoped)).not.toContain(MISSION_CLIENT);
  });

  it("answers a read naming no audience state-only: aud is the client's client_id and no authorization_details", async () => {
    const record = approve();
    const payload = await verified((await read(reader, { mission_id: record.id, nonce: nonce() })).text);
    expect(payload.aud).toBe(reader.clientId);
    expect(payload.sub).toBe(reader.clientId);
    expect(payload.authorization_details).toBeUndefined();
  });

  it("signs the authenticated service principal as sub on the development GET route too", async () => {
    const record = approve();
    const res = await fetch(`${ISSUER}/missions/${record.id}/status?audience=${encodeURIComponent(CANONICAL_RESOURCE)}&nonce=n-get`, {
      headers: { "x-service-token": SERVICE_TOKEN },
    });
    expect(res.status).toBe(200);
    const payload = decodeJwt(await res.text());
    expect(payload.sub).toBe(SERVICE_PRINCIPAL);
    expect(JSON.stringify(payload)).not.toContain(MISSION_CLIENT);
  });
});

describe("Mission Status endpoint errors (@spec status#mission-status-auth-failures, status#mission-status-errors, #1407)", () => {
  it("refuses a malformed request invalid_request, echoing a well-formed nonce and never a malformed one", async () => {
    const record = approve();
    const n = nonce();
    const auth = async () => ({ client_assertion_type: CLIENT_ASSERTION_TYPE, client_assertion: await lifecycleClientAssertion(ISSUER, reader) });

    const notForm = await readAnswer(
      await fetch(ENDPOINT, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ mission_id: record.id, nonce: n }),
      }),
    );
    const repeated = await readAnswer(
      await fetch(ENDPOINT, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: `mission_id=${record.id}&mission_id=${UNKNOWN}&nonce=${n}`,
      }),
    );
    const cases: Array<[string, LifecycleAnswer, string | undefined]> = [
      ["not a form", notForm, undefined],
      ["a repeated member", repeated, n],
      ["no nonce", await post({ mission_id: record.id, ...(await auth()) }), undefined],
      ["a malformed nonce", await post({ mission_id: record.id, nonce: "x".repeat(256), ...(await auth()) }), undefined],
      ["no mission_id", await post({ nonce: n, ...(await auth()) }), n],
      ["an empty audience", await post({ mission_id: record.id, audience: "", nonce: n, ...(await auth()) }), n],
    ];
    for (const [label, answer, echoed] of cases) {
      expect(answer.status, label).toBe(400);
      expect(answer.json?.error, label).toBe("invalid_request");
      expect(typeof answer.json?.error_description, label).toBe("string");
      expect(answer.json?.nonce, label).toBe(echoed);
      expect(answer.cacheControl, label).toBe("no-store");
    }
  });

  it("refuses a failed or absent client authentication invalid_client (HTTP 400) with no challenge, before any Mission is read", async () => {
    const record = approve();
    const n = nonce();
    const members = { mission_id: record.id, audience: CANONICAL_RESOURCE, nonce: n };
    const { privateKey: foreignKey } = await generateKeyPair("ES256");
    const cases: Array<[string, LifecycleAnswer]> = [
      ["no credential", await post(members)],
      ["a client secret", await post({ ...members, client_id: reader.clientId, client_secret: "s3cret" })],
      ["an Authorization header", await post(members, { authorization: "Bearer some-token" })],
      ["Basic", await post(members, { authorization: `Basic ${Buffer.from(`${reader.clientId}:s3cret`).toString("base64")}` })],
      ["an assertion audienced to the endpoint", await read(reader, members, await lifecycleClientAssertion(ISSUER, reader, { aud: ENDPOINT }))],
      ["a foreign signature", await read(reader, members, await lifecycleClientAssertion(ISSUER, reader, { key: foreignKey as CryptoKey }))],
      ["an unregistered client", await read(await newLifecycleClient("status-endpoint-stranger"), members)],
    ];
    for (const [label, answer] of cases) {
      expect(answer.status, label).toBe(400);
      expect(answer.json, label).toMatchObject({ error: "invalid_client", nonce: n });
      expect(typeof answer.json?.error_description, label).toBe("string");
      expect(answer.wwwAuthenticate, label).toBeNull();
    }
  });

  it("refuses an assertion sent without client_assertion_type or under another type, and a client_assertion_type sent without an assertion, invalid_client (HTTP 400)", async () => {
    // @spec status#mission-status-request (#1535): private-key-JWT client
    // authentication carries both parameters, the type with the jwt-bearer value.
    const record = approve();
    const n = nonce();
    const members = { mission_id: record.id, audience: CANONICAL_RESOURCE, nonce: n };
    const answers = [
      await post({ ...members, client_assertion: await lifecycleClientAssertion(ISSUER, reader) }),
      await post({
        ...members,
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:saml2-bearer",
        client_assertion: await lifecycleClientAssertion(ISSUER, reader),
      }),
      await post({ ...members, client_assertion_type: CLIENT_ASSERTION_TYPE }),
    ];
    for (const a of answers) {
      expect(a.status, a.text).toBe(400);
      expect(a.json).toMatchObject({ error: "invalid_client", nonce: n });
    }
  });

  it("refuses at the first failing step, in order: authentication, then request syntax, then authorization, and reads no Mission before it", async () => {
    // @spec status#mission-status-processing (#1535): an unauthenticated
    // request is refused as its authentication failure assigns whatever its
    // members or Mission; a malformed one invalid_request alike for a known
    // and an unknown Mission; an unknown Mission and a caller without read
    // authorization alike with the not-found response.
    const record = approve();
    const unauthenticated = [
      await post({ mission_id: record.id }),
      await post({ mission_id: UNKNOWN }),
      await post({ nonce: "x".repeat(256) }),
    ];
    for (const a of unauthenticated) expect(a.json?.error, a.text).toBe("invalid_client");
    const auth = async (client: LifecycleTestClient) => ({
      client_assertion_type: CLIENT_ASSERTION_TYPE,
      client_assertion: await lifecycleClientAssertion(ISSUER, client),
    });
    // Malformed (no nonce): the same refusal for a known and an unknown
    // Mission, and for a client without the read grant.
    const malformed = [
      await post({ mission_id: record.id, ...(await auth(reader)) }),
      await post({ mission_id: UNKNOWN, ...(await auth(reader)) }),
      await post({ mission_id: record.id, ...(await auth(ungranted)) }),
    ];
    for (const a of malformed) {
      expect(a.status, a.text).toBe(400);
      expect(a.json?.error).toBe("invalid_request");
    }
    expect(new Set(malformed.map((a) => a.text)).size).toBe(1);
    // Authorization: an unknown Mission and an ungranted client, alike.
    const n = nonce();
    const refused = [
      await post({ mission_id: UNKNOWN, nonce: n, ...(await auth(reader)) }),
      await post({ mission_id: record.id, nonce: n, ...(await auth(ungranted)) }),
    ];
    expect(refused.map((a) => a.status)).toEqual([404, 404]);
    expect(refused[0]?.text).toBe(refused[1]?.text);
  });

  it("answers a client without the mission_status grant and an unknown Mission with one not-found body, echoing the nonce", async () => {
    const record = approve();
    const n = nonce();
    const ungrantedAnswer = await read(ungranted, { mission_id: record.id, audience: CANONICAL_RESOURCE, nonce: n });
    const unknownAnswer = await read(reader, { mission_id: UNKNOWN, audience: CANONICAL_RESOURCE, nonce: n });
    for (const answer of [ungrantedAnswer, unknownAnswer]) {
      expect(answer.status).toBe(404);
      expect(answer.json).toEqual({
        error: "not_found",
        error_description: "Mission reference is not found or not visible.",
        nonce: n,
      });
      expect(answer.cacheControl).toBe("no-store");
    }
    expect(ungrantedAnswer.text).toBe(unknownAnswer.text);
  });
});

