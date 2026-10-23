/**
 * @spec authority-server#mission-join rule 2, status#mission-status-response,
 * status#mission-status-caching (#818)
 *
 * The PDP's remote Mission Status resolver against a controllable Status
 * server double: every answer the double can give that must not establish
 * Mission state is a typed failure, and nothing is cached from it. The double
 * signs with its own keys and publishes them beside a key it uses for
 * something else, the way an issuer's `jwks_uri` does. It serves the
 * profile's form POST at one endpoint (#1407).
 */

import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { type CryptoKey, createLocalJWKSet, decodeProtectedHeader, exportJWK, generateKeyPair, jwtVerify, SignJWT } from "jose";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import {
  declaredStatusKeys,
  MissionStatusResolver,
  type MissionStatusResolverOptions,
  type MissionStatusResolution,
  privateKeyJwtClient,
  type ResolveOptions,
} from "../src/mission-status-resolver.js";

const ISSUER = "https://mas.pilot.example";
const AUDIENCE = "https://payments.example/api";
const MISSION = "msn_resolver_double_0001";
/** The PDP's client identifier at the Status endpoint, and the `sub` a response to it carries. */
const CLIENT_ID = "pdp-status-client";
const CLIENT_KID = "pdp-status-client-key";
const ENDPOINT_PATH = "/mission/status";
const STATUS_KID = "mas-status";
const TOKEN_KID = "mas-token";

/** `form`: the request's form body, the profile's request members. */
type Handler = (req: IncomingMessage, res: ServerResponse, form: URLSearchParams) => void | Promise<void>;

let server: Server;
let base: string;
let handler: Handler;
const requests: Array<{ method: string; path: string; search: string; contentType: string; form: URLSearchParams }> = [];
let clientKey: CryptoKey;
let clientPublic: Record<string, unknown>;

let statusKey: CryptoKey;
let tokenKey: CryptoKey;
let strangerKey: CryptoKey;
let published: { keys: Record<string, unknown>[] };

/** The shared clock: the double stamps `iat` from it and the resolver reads it. */
let clockMs = Date.now();
const nowS = () => Math.floor(clockMs / 1000);

beforeAll(async () => {
  const status = await generateKeyPair("ES256", { extractable: true });
  const token = await generateKeyPair("ES256", { extractable: true });
  const stranger = await generateKeyPair("ES256", { extractable: true });
  statusKey = status.privateKey;
  tokenKey = token.privateKey;
  strangerKey = stranger.privateKey;
  const client = await generateKeyPair("ES256", { extractable: true });
  clientKey = client.privateKey;
  clientPublic = { ...(await exportJWK(client.publicKey)), kid: CLIENT_KID, alg: "ES256" };
  published = {
    keys: [
      { ...(await exportJWK(status.publicKey)), kid: STATUS_KID, alg: "ES256" },
      { ...(await exportJWK(token.publicKey)), kid: TOKEN_KID, alg: "ES256" },
    ],
  };
  server = createServer((req, res) => {
    const url = new URL(req.url ?? "/", "http://double");
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      const form = new URLSearchParams(Buffer.concat(chunks).toString("utf8"));
      requests.push({
        method: req.method ?? "",
        path: url.pathname,
        search: url.search,
        contentType: req.headers["content-type"] ?? "",
        form,
      });
      void handler(req, res, form);
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterAll(async () => {
  server.closeAllConnections();
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

beforeEach(() => {
  requests.length = 0;
  // On a whole second, so a signed `iat` is exactly the clock it was read from.
  clockMs = Math.floor(Date.now() / 1000) * 1000;
  handler = respond();
});

/** A well-formed response payload for `nonce`, as the reference issuer signs one for an enrolled PDP. */
function payload(nonce: string | null): Record<string, unknown> {
  const iat = nowS();
  return {
    iss: ISSUER,
    aud: AUDIENCE,
    sub: CLIENT_ID,
    iat,
    exp: iat + 60,
    ...(nonce !== null ? { nonce } : {}),
    mission: {
      id: MISSION,
      issuer: ISSUER,
      subject: { iss: ISSUER, sub: "alice" },
      client_id: "ap-agent",
      authority_hash: "sha-256:double-authority-hash",
      state: "active",
      version: 3,
      expires_at: "2027-06-01T00:00:00Z",
      fresh_until: new Date((iat + 60) * 1000).toISOString(),
    },
    authorization_details: [
      {
        type: "mission_resource_access",
        resource: AUDIENCE,
        actions: ["payments:invoice.read"],
        constraints: { vendors: ["acme"] },
        delegation: { max_depth: 1, allowed_delegates: [{ sub: "helper-agent" }, { sub_profile: "ai_agent" }] },
      },
    ],
  };
}

const mission = (p: Record<string, unknown>) => p.mission as Record<string, unknown>;

/** A signed lifetime: `iat` and `exp`, and `fresh_until` at `exp`, as the reference issuer stamps one. */
const lifetime = (p: Record<string, unknown>, iat: number, exp: number) => {
  p.iat = iat;
  p.exp = exp;
  mission(p).fresh_until = new Date(exp * 1000).toISOString();
};

async function sign(
  claims: Record<string, unknown>,
  opts: { key?: CryptoKey; kid?: string; typ?: string } = {},
): Promise<string> {
  return new SignJWT(claims)
    .setProtectedHeader({ alg: "ES256", kid: opts.kid ?? STATUS_KID, typ: opts.typ ?? "mission-status-response+jwt" })
    .sign(opts.key ?? statusKey);
}

/** A 200 Status answer, its payload edited and its signature chosen per case. */
function respond(
  edit: (p: Record<string, unknown>) => void = () => {},
  signing: { key?: CryptoKey; kid?: string; typ?: string } = {},
): Handler {
  return async (_req, res, query) => {
    const claims = payload(query.get("nonce"));
    edit(claims);
    const jws = await sign(claims, signing);
    res.writeHead(200, { "content-type": "application/mission-status-response+jwt", "cache-control": "no-store" });
    res.end(jws);
  };
}

function resolver(extra: Partial<MissionStatusResolverOptions> = {}): MissionStatusResolver {
  return new MissionStatusResolver({
    issuer: ISSUER,
    statusEndpoint: `${base}${ENDPOINT_PATH}`,
    audience: AUDIENCE,
    keys: declaredStatusKeys(published as never, [STATUS_KID]),
    client: privateKeyJwtClient({ clientId: CLIENT_ID, issuer: ISSUER, privateKey: clientKey, kid: CLIENT_KID }),
    maxStaleSeconds: 300,
    timeoutMs: 1000,
    maxResponseBytes: 16 * 1024,
    now: () => new Date(clockMs),
    ...extra,
  });
}

const ref = { id: MISSION, issuer: ISSUER };

/** A failure of `reason`, with nothing cached: the next read goes to the double and verifies. */
async function expectRefusedUncached(
  r: MissionStatusResolver,
  reason: string,
  detail?: string | RegExp,
  options: ResolveOptions = {},
): Promise<void> {
  const before = requests.length;
  const first = await r.resolve(ref, options);
  expect(first.ok).toBe(false);
  expect(first).toMatchObject({ reason });
  if (detail !== undefined) expect((first as { detail: string }).detail).toMatch(detail);
  expect(requests.length).toBe(before + 1);
  handler = respond();
  const after = await r.resolve(ref);
  expect(after).toMatchObject({ ok: true, source: "fetched" });
  expect(requests.length).toBe(before + 2);
}

describe("MissionStatusResolver: a verified answer (@spec authority-server#mission-join rule 2)", () => {
  it("reads the Mission at the issuer's Status endpoint as the profile's form POST, authenticated by private-key JWT, audience-scoped and nonce-bound, and builds the view", async () => {
    const r = resolver();
    const resolved = await r.resolve(ref);
    expect(resolved.ok).toBe(true);
    const { view, observedAtMs, freshUntilMs, source } = resolved as Extract<MissionStatusResolution, { ok: true }>;
    expect(source).toBe("fetched");
    expect(observedAtMs).toBe(nowS() * 1000);
    expect(freshUntilMs).toBe((nowS() + 60) * 1000);
    expect(view).toMatchObject({
      id: MISSION,
      issuer: ISSUER,
      state: "active",
      version: 3,
      authority_hash: "sha-256:double-authority-hash",
      subject: { iss: ISSUER, sub: "alice" },
      client_id: "ap-agent",
    });
    // The recorded `delegation`, mapped by the shared join adapter: an exact
    // `sub` matcher survives, a profile matcher is dropped.
    expect(view.authority_set).toEqual([
      expect.objectContaining({
        resource: AUDIENCE,
        actions: ["payments:invoice.read"],
        join_delegation: { max_depth: 1, allowed_delegates: ["helper-agent"] },
      }),
    ]);
    const [request] = requests;
    expect(request).toMatchObject({ method: "POST", path: ENDPOINT_PATH, search: "", contentType: "application/x-www-form-urlencoded" });
    expect(request?.form.get("mission_id")).toBe(MISSION);
    expect(request?.form.get("audience")).toBe(AUDIENCE);
    expect(request?.form.get("nonce")).toMatch(/^[0-9a-f-]{36}$/);
    expect(request?.form.get("client_assertion_type")).toBe("urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
    // @spec status#mission-status-authentication: the assertion names the
    // client, is audienced to the issuer identifier alone, and is typed.
    const assertion = request?.form.get("client_assertion") ?? "";
    expect(decodeProtectedHeader(assertion).typ).toBe("client-authentication+jwt");
    const { payload: claims } = await jwtVerify(assertion, createLocalJWKSet({ keys: [clientPublic as never] }), {
      issuer: CLIENT_ID,
      subject: CLIENT_ID,
      audience: ISSUER,
      requiredClaims: ["exp", "jti"],
    });
    expect(claims.aud).toBe(ISSUER);
    // A fresh assertion per read.
    await r.resolve(ref, { fresh: true });
    expect(requests[1]?.form.get("client_assertion")).not.toBe(assertion);
  });

  it("reads a response with no Join Disclosure as a view with neither subject nor client_id", async () => {
    handler = respond((p) => {
      delete mission(p).subject;
      delete mission(p).client_id;
    });
    const resolved = await resolver().resolve(ref);
    expect(resolved.ok).toBe(true);
    const { view } = resolved as Extract<MissionStatusResolution, { ok: true }>;
    expect("subject" in view).toBe(false);
    expect("client_id" in view).toBe(false);
  });

  it("never reads a reference naming another issuer", async () => {
    const refused = await resolver().resolve({ id: MISSION, issuer: "https://other-mas.example" });
    expect(refused).toMatchObject({ ok: false, reason: "not_found" });
    expect(requests.length).toBe(0);
  });

  it("never lets a reference's identifier steer the request to another path at the issuer: it travels as the form's mission_id", async () => {
    // The answer for that identifier is refused like any other Mission's.
    expect(await resolver().resolve({ id: "../admin/keys", issuer: ISSUER })).toMatchObject({ ok: false, reason: "unverifiable" });
    expect(requests.map((q) => [q.path, q.search, q.form.get("mission_id")])).toEqual([[ENDPOINT_PATH, "", "../admin/keys"]]);
    // An empty identifier names no Mission and is never requested.
    expect(await resolver().resolve({ id: "", issuer: ISSUER })).toMatchObject({ ok: false, reason: "not_found" });
    expect(requests.length).toBe(1);
  });
});

describe("MissionStatusResolver: a response that does not verify establishes nothing (@spec status#mission-status-response)", () => {
  it("refuses another issuer's response", async () => {
    handler = respond((p) => {
      p.iss = "https://impostor.example";
    });
    await expectRefusedUncached(resolver(), "unverifiable");
  });

  it("refuses a response whose mission.issuer is not its iss (consumer check 4, #1535)", async () => {
    handler = respond((p) => {
      mission(p).issuer = "https://impostor.example";
    });
    await expectRefusedUncached(resolver(), "unverifiable", "signature or claims");
  });

  it("refuses a response signed by a key that is not the declared one under the declared kid", async () => {
    handler = respond(() => {}, { key: strangerKey });
    await expectRefusedUncached(resolver(), "unverifiable");
  });

  it("refuses a response signed by a key the issuer publishes for another purpose", async () => {
    handler = respond(() => {}, { key: tokenKey, kid: TOKEN_KID });
    await expectRefusedUncached(resolver(), "unverifiable");
  });

  it("refuses an unsigned response", async () => {
    handler = async (_req, res, query) => {
      const b64 = (v: unknown) => Buffer.from(JSON.stringify(v)).toString("base64url");
      res.writeHead(200, { "content-type": "application/mission-status-response+jwt" });
      res.end(`${b64({ alg: "none", typ: "mission-status-response+jwt" })}.${b64(payload(query.get("nonce")))}.`);
    };
    await expectRefusedUncached(resolver(), "unverifiable");
  });

  it("refuses a response of another media type", async () => {
    handler = respond(() => {}, { typ: "at+jwt" });
    await expectRefusedUncached(resolver(), "unverifiable");
  });

  it("refuses a response audienced to another enforcement scope", async () => {
    handler = respond((p) => {
      p.aud = "https://other.example/api";
    });
    await expectRefusedUncached(resolver(), "unverifiable");
  });

  it("refuses a response naming another Mission", async () => {
    handler = respond((p) => {
      mission(p).id = "msn_some_other_mission";
    });
    await expectRefusedUncached(resolver(), "unverifiable");
  });

  it("refuses a response signed for another caller: its sub is not this PDP's client identifier (consumer check 6)", async () => {
    handler = respond((p) => {
      p.sub = "ap-agent";
    });
    await expectRefusedUncached(resolver(), "unverifiable", "sub");
  });

  it("refuses a response that does not echo this request's nonce", async () => {
    handler = respond((p) => {
      p.nonce = "an-earlier-request";
    });
    await expectRefusedUncached(resolver(), "unverifiable", "nonce");
  });

  it("refuses a response that has expired", async () => {
    handler = respond((p) => lifetime(p, nowS() - 600, nowS() - 300));
    await expectRefusedUncached(resolver(), "unverifiable");
  });

  it("allows no more receipt-time clock skew than the issuer's mission_max_stale_seconds", async () => {
    // Expired 20 seconds ago: inside the profile's 30-second allowance, past
    // a 10-second advertised maximum staleness.
    handler = respond((p) => lifetime(p, nowS() - 80, nowS() - 20));
    await expectRefusedUncached(resolver({ maxStaleSeconds: 10 }), "unverifiable", "signature or claims");
  });

  it("refuses a response whose signed fresh_until is later than its exp (consumer check 10, #1535)", async () => {
    // Both still ahead: only the ordering of the two refuses it.
    handler = respond((p) => {
      lifetime(p, nowS(), nowS() + 60);
      mission(p).fresh_until = new Date((nowS() + 80) * 1000).toISOString();
    });
    await expectRefusedUncached(resolver(), "unverifiable", "signature or claims");
  });

  it("refuses an active response that carries no mission.expires_at: its Mission expiry could not be enforced (#1535)", async () => {
    handler = respond((p) => {
      delete mission(p).expires_at;
    });
    await expectRefusedUncached(resolver(), "unverifiable", "signature or claims");
  });

  it("refuses a response whose mission.expires_at does not parse (#1535)", async () => {
    handler = respond((p) => {
      mission(p).expires_at = "next year";
    });
    await expectRefusedUncached(resolver(), "unverifiable", "signature or claims");
  });

  it("refuses a response that carries no signed fresh_until", async () => {
    handler = respond((p) => {
      delete mission(p).fresh_until;
    });
    await expectRefusedUncached(resolver(), "unverifiable");
  });

  it("refuses a response without exp (consumer check 9)", async () => {
    handler = respond((p) => {
      delete p.exp;
    });
    await expectRefusedUncached(resolver(), "unverifiable", "signature or claims");
  });

  it("refuses a response without iat (consumer check 9)", async () => {
    handler = respond((p) => {
      delete p.iat;
    });
    await expectRefusedUncached(resolver(), "unverifiable", "signature or claims");
  });

  it("refuses a response observed in the future", async () => {
    handler = respond((p) => {
      p.iat = nowS() + 120;
      p.exp = nowS() + 180;
    });
    await expectRefusedUncached(resolver(), "unverifiable", "iat");
  });

  it("refuses a missing, malformed or unknown state", async () => {
    for (const state of [undefined, 7, "paused"]) {
      handler = respond((p) => {
        if (state === undefined) delete mission(p).state;
        else mission(p).state = state;
      });
      await expectRefusedUncached(resolver(), "unverifiable", "state");
    }
  });

  it("refuses each malformed member the view is built from", async () => {
    const cases: Array<[string, (p: Record<string, unknown>) => void]> = [
      ["version", (p) => void (mission(p).version = 0)],
      ["authority_hash", (p) => void delete mission(p).authority_hash],
      ["subject", (p) => void (mission(p).subject = { iss: ISSUER })],
      ["client_id", (p) => void (mission(p).client_id = 42)],
      ["authorization_details", (p) => void (p.authorization_details = { resource: AUDIENCE })],
      ["authorization_details entry", (p) => void (p.authorization_details = [{ type: "mission_resource_access", resource: AUDIENCE, actions: "payments:invoice.read" }])],
      ["authorization_details entry", (p) => void (p.authorization_details = [{ type: "mission_resource_access", actions: ["payments:invoice.read"] }])],
      [
        "authorization_details entry",
        (p) => void (p.authorization_details = [{ type: "mission_resource_access", resource: AUDIENCE, actions: ["payments:invoice.read"], delegation: { max_depth: "1" } }]),
      ],
      [
        "authorization_details entry",
        (p) =>
          void (p.authorization_details = [
            { type: "mission_resource_access", resource: AUDIENCE, actions: ["payments:invoice.read"], delegation: { max_depth: 1, allowed_delegates: [{ sub: 7 }] } },
          ]),
      ],
    ];
    for (const [detail, edit] of cases) {
      handler = respond(edit);
      await expectRefusedUncached(resolver(), "unverifiable", detail);
    }
  });
});

describe("MissionStatusResolver: an answer that does not arrive establishes nothing", () => {
  it("classifies the issuer's refusals and errors, and caches none of them", async () => {
    for (const [code, reason] of [
      [401, "unauthorized"],
      [403, "unauthorized"],
      [404, "not_found"],
      // @spec status#mission-status-failures (#1535): rate_limited, like
      // unavailable, is a transient failure that establishes nothing.
      [429, "unavailable"],
      [500, "unavailable"],
      [503, "unavailable"],
    ] as const) {
      handler = (_req, res) => {
        res.writeHead(code, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "x" }));
      };
      await expectRefusedUncached(resolver(), reason, `status ${code}`);
    }
    // @spec status#mission-status-auth-failures: a refused client
    // authentication is 400 invalid_client; any other 400 is no answer.
    for (const [error, reason, detail] of [
      ["invalid_client", "unauthorized", "invalid_client"],
      ["invalid_request", "unavailable", "status 400 invalid_request"],
    ] as const) {
      handler = (_req, res) => {
        res.writeHead(400, { "content-type": "application/json" });
        res.end(JSON.stringify({ error, error_description: "refused" }));
      };
      await expectRefusedUncached(resolver(), reason, detail);
    }
  });

  it("never follows a redirect, even to an answer that would verify", async () => {
    handler = (req, res, query) => {
      if (req.url?.startsWith("/elsewhere")) return respond()(req, res, query);
      res.writeHead(307, { location: `/elsewhere${ENDPOINT_PATH}` });
      res.end();
    };
    const refused = await resolver().resolve(ref);
    expect(refused).toMatchObject({ ok: false, reason: "unavailable", detail: "status 307" });
    expect(requests.map((q) => q.path)).toEqual([ENDPOINT_PATH]);
  });

  it("stops reading a body over the cap, its length declared or streamed", async () => {
    const big = "x".repeat(8192);
    handler = (_req, res) => {
      res.writeHead(200, { "content-type": "application/mission-status-response+jwt" });
      res.end(big);
    };
    await expectRefusedUncached(resolver({ maxResponseBytes: 4096 }), "unavailable", "oversized");
    handler = (_req, res) => {
      // Chunked: no length is declared, and the cap still holds.
      res.writeHead(200, { "content-type": "application/mission-status-response+jwt" });
      for (let i = 0; i < 4; i++) res.write(big.slice(0, 2048));
      res.end();
    };
    await expectRefusedUncached(resolver({ maxResponseBytes: 4096 }), "unavailable", "oversized");
  });

  it("gives up at the deadline on a slow answer or a slow body", async () => {
    const r = resolver({ timeoutMs: 300 });
    for (const slow of ["headers", "body"] as const) {
      handler = (_req, res) => {
        const finish = () => setTimeout(() => res.destroyed || res.end("late"), 3000);
        if (slow === "headers") {
          setTimeout(() => {
            if (res.destroyed) return;
            res.writeHead(200, { "content-type": "application/mission-status-response+jwt" });
            res.end("late");
          }, 3000);
          return;
        }
        res.writeHead(200, { "content-type": "application/mission-status-response+jwt" });
        res.write("eyJ");
        finish();
      };
      const started = Date.now();
      const refused = await r.resolve(ref);
      expect(Date.now() - started).toBeLessThan(2000);
      expect(refused, slow).toMatchObject({ ok: false, reason: "unavailable", detail: "timeout" });
    }
    handler = respond();
    expect(await r.resolve(ref)).toMatchObject({ ok: true, source: "fetched" });
  });

  it("gives up at the deadline on a signer that stalls, before any request starts (#1492 review)", async () => {
    const signing = privateKeyJwtClient({ clientId: CLIENT_ID, issuer: ISSUER, privateKey: clientKey, kid: CLIENT_KID });
    const before = requests.length;
    const stalled = resolver({ timeoutMs: 20, client: { clientId: CLIENT_ID, assertion: () => new Promise<string>(() => {}) } });
    // A read still pending after a second is the defect: race it, so it fails as an assertion.
    const refused = await Promise.race([
      stalled.resolve(ref),
      new Promise<string>((settle) => setTimeout(() => settle("still pending after 1000 ms"), 1000)),
    ]);
    expect(refused).toMatchObject({ ok: false, reason: "unavailable", detail: "timeout" });
    expect(requests.length).toBe(before);
    // The same resolver with a signer that answers reads normally: the refusal cached nothing.
    handler = respond();
    const working = resolver({ client: signing });
    expect(await working.resolve(ref)).toMatchObject({ ok: true, source: "fetched" });
  });

  it("drops a signature that arrives after the deadline: it never starts a request (#1492 review)", async () => {
    const signing = privateKeyJwtClient({ clientId: CLIENT_ID, issuer: ISSUER, privateKey: clientKey, kid: CLIENT_KID });
    const before = requests.length;
    let signedLate = false;
    const late = resolver({
      timeoutMs: 20,
      client: {
        clientId: CLIENT_ID,
        assertion: () =>
          new Promise<string>((resolve) =>
            setTimeout(() => {
              signedLate = true;
              void signing.assertion().then(resolve);
            }, 150),
          ),
      },
    });
    const started = Date.now();
    expect(await late.resolve(ref)).toMatchObject({ ok: false, reason: "unavailable", detail: "timeout" });
    // Refused at the deadline, not when the signature arrives (150 ms).
    expect(Date.now() - started).toBeLessThan(120);
    expect(signedLate).toBe(false);
    await new Promise((settle) => setTimeout(settle, 400));
    expect(signedLate).toBe(true);
    expect(requests.length).toBe(before);
  });

  it("holds signing and the request to one deadline together, never a fresh one after signing (#1492 review)", async () => {
    const signing = privateKeyJwtClient({ clientId: CLIENT_ID, issuer: ISSUER, privateKey: clientKey, kid: CLIENT_KID });
    const answer = respond();
    handler = (req, res, query) => {
      setTimeout(() => {
        if (!res.destroyed) void answer(req, res, query);
      }, 200);
    };
    // Signing takes 200 ms of a 300 ms deadline and the answer 200 ms more: past the deadline in total.
    const r = resolver({
      timeoutMs: 300,
      client: {
        clientId: CLIENT_ID,
        assertion: () => new Promise<string>((resolve) => setTimeout(() => void signing.assertion().then(resolve), 200)),
      },
    });
    expect(await r.resolve(ref)).toMatchObject({ ok: false, reason: "unavailable", detail: "timeout" });
  });

  it("reports a source that does not answer at all as unavailable", async () => {
    const r = resolver({ statusEndpoint: "http://127.0.0.1:1/mission/status" });
    expect(await r.resolve(ref)).toMatchObject({ ok: false, reason: "unavailable", detail: "transport" });
  });
});

describe("MissionStatusResolver: a failed read never refreshes or extends a held answer (@spec status#mission-status-failures, #1535)", () => {
  /** The issuer answering `code`, or dropping the connection for `transport`. */
  const failing =
    (cause: number | "transport"): Handler =>
    (req, res) => {
      if (cause === "transport") {
        req.socket.destroy();
        return;
      }
      res.writeHead(cause, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: cause === 429 ? "rate_limited" : "unavailable" }));
    };

  it("leaves a held answer usable until its original reliance bound through a rate-limited, unavailable or unreachable source, never past it, and never reads the failure as termination", async () => {
    for (const cause of [429, 503, "transport"] as const) {
      requests.length = 0;
      const t0 = clockMs;
      handler = respond((p) => lifetime(p, nowS(), nowS() + 20));
      const r = resolver();
      expect(await r.resolve(ref), String(cause)).toMatchObject({ ok: true, source: "fetched", relianceBoundMs: t0 + 20_000 });

      // A read that must reach the source now fails: it establishes nothing.
      handler = failing(cause);
      clockMs = t0 + 5_000;
      expect(await r.resolve(ref, { fresh: true }), String(cause)).toMatchObject({ ok: false, reason: "unavailable" });

      // The held answer is unchanged: still `active`, still bounded where it was.
      clockMs = t0 + 10_000;
      expect(await r.resolve(ref), String(cause)).toMatchObject({
        ok: true,
        source: "cached",
        view: { state: "active", version: 3 },
        observedAtMs: t0,
        relianceBoundMs: t0 + 20_000,
      });

      // At its original bound it is relied on no longer, and the failing
      // source puts nothing in its place.
      clockMs = t0 + 20_000;
      expect(r.peek(ref), String(cause)).toBeUndefined();
      expect(await r.resolve(ref), String(cause)).toMatchObject({ ok: false, reason: "unavailable" });
      expect(requests.length, String(cause)).toBe(3);
      clockMs = Math.floor(Date.now() / 1000) * 1000;
    }
  });
});

describe("MissionStatusResolver: an observation read now is held to the same reliance bounds as a cached one (@spec status#mission-status-caching)", () => {
  /** A verified response observed `seconds` ago, its `exp` and `fresh_until` still ahead. */
  const observedAgo = (seconds: number, version = 3) =>
    respond((p) => {
      lifetime(p, nowS() - seconds, nowS() + 40);
      mission(p).version = version;
    });

  it("refuses stale a response read now whose signed fresh_until has passed, and caches nothing", async () => {
    handler = respond((p) => {
      mission(p).fresh_until = new Date((nowS() - 1) * 1000).toISOString();
    });
    await expectRefusedUncached(resolver(), "stale", "fresh_until passed");
  });

  it("refuses stale a 20-second-old observation read now when the caller relies on 5 seconds, and caches nothing", async () => {
    handler = observedAgo(20);
    await expectRefusedUncached(resolver(), "stale", "older than maxAgeSeconds", { maxAgeSeconds: 5 });
    // Control: the same observation inside the caller's window is relied on.
    handler = observedAgo(20);
    expect(await resolver().resolve(ref, { maxAgeSeconds: 25 })).toMatchObject({ ok: true, source: "fetched" });
  });

  it("refuses stale a 20-second-old observation read now when the issuer's mission_max_stale_seconds is 10, with no caller window", async () => {
    handler = observedAgo(20);
    await expectRefusedUncached(resolver({ maxStaleSeconds: 10 }), "stale", "older than mission_max_stale_seconds");
  });

  it("refuses stale an over-age observation on a fresh read, and leaves the cached answer as it was", async () => {
    const r = resolver();
    expect(await r.resolve(ref)).toMatchObject({ ok: true, source: "fetched", view: { version: 3 } });
    handler = observedAgo(20, 4);
    const before = requests.length;
    expect(await r.resolve(ref, { fresh: true, maxAgeSeconds: 5 })).toMatchObject({
      ok: false,
      reason: "stale",
      detail: "older than maxAgeSeconds",
    });
    expect(requests.length).toBe(before + 1);
    expect(await r.resolve(ref)).toMatchObject({ ok: true, source: "cached", view: { version: 3 } });
    expect(requests.length).toBe(before + 1);
  });

  it("accepts a response up to 30 seconds past its exp at receipt, and relies on it for nothing: no skew allowance extends exp (#1535)", async () => {
    // Check 9's receipt allowance admits it (not `unverifiable`); its
    // reliance bound has passed all the same. The profile's allowance on
    // `fresh_until` alone, were it taken, would still end at `exp`.
    handler = respond((p) => lifetime(p, nowS() - 80, nowS() - 20));
    await expectRefusedUncached(resolver(), "stale");
  });
});

describe("MissionStatusResolver: the cache never outlives a signed bound (@spec status#mission-status-caching)", () => {
  it("reuses an answer only before its signed fresh_until", async () => {
    handler = respond((p) => {
      mission(p).fresh_until = new Date((nowS() + 20) * 1000).toISOString();
    });
    const r = resolver();
    expect(await r.resolve(ref)).toMatchObject({ ok: true, source: "fetched" });
    clockMs += 19_000;
    expect(await r.resolve(ref)).toMatchObject({ ok: true, source: "cached" });
    clockMs += 1_000;
    expect(await r.resolve(ref)).toMatchObject({ ok: true, source: "fetched" });
    expect(requests.length).toBe(2);
  });

  it("reuses an answer no longer than iat plus the issuer's mission_max_stale_seconds", async () => {
    const r = resolver({ maxStaleSeconds: 10 });
    expect(await r.resolve(ref)).toMatchObject({ ok: true, source: "fetched" });
    clockMs += 10_000;
    expect(await r.resolve(ref)).toMatchObject({ ok: true, source: "cached" });
    clockMs += 1_000;
    expect(await r.resolve(ref)).toMatchObject({ ok: true, source: "fetched" });
  });

  it("reuses an answer no longer than the caller's own staleness window", async () => {
    const r = resolver();
    expect(await r.resolve(ref)).toMatchObject({ ok: true, source: "fetched" });
    clockMs += 6_000;
    expect(await r.resolve(ref, { maxAgeSeconds: 10 })).toMatchObject({ ok: true, source: "cached" });
    expect(await r.resolve(ref, { maxAgeSeconds: 5 })).toMatchObject({ ok: true, source: "fetched" });
  });

  it("never relies on a reported active state at or after the Mission's expires_at, though fresh_until and exp are later, with no skew allowance (#1535)", async () => {
    const t0 = clockMs;
    const expiresAt = new Date(t0 + 10_000).toISOString();
    handler = respond((p) => {
      mission(p).expires_at = expiresAt;
    });
    const r = resolver();
    expect(await r.resolve(ref)).toMatchObject({
      ok: true,
      source: "fetched",
      view: { state: "active" },
      freshUntilMs: t0 + 60_000,
      relianceBoundMs: t0 + 10_000,
    });
    clockMs = t0 + 9_000;
    expect(await r.resolve(ref)).toMatchObject({ ok: true, source: "cached" });
    // At expires_at: the held answer is no longer relied on, and a read now
    // that still reports `active` under the same expiry is refused.
    clockMs = t0 + 10_000;
    expect(r.peek(ref)).toBeUndefined();
    expect(await r.resolve(ref)).toMatchObject({ ok: false, reason: "stale", detail: "expires_at passed" });
    expect(requests.length).toBe(2);
  });

  it("relies on a suspended response past the Mission's expires_at only until its own reliance bound (#1535)", async () => {
    const t0 = clockMs;
    handler = respond((p) => {
      mission(p).state = "suspended";
      mission(p).expires_at = new Date(t0 + 10_000).toISOString();
      mission(p).fresh_until = new Date((nowS() + 20) * 1000).toISOString();
    });
    const r = resolver();
    expect(await r.resolve(ref)).toMatchObject({ ok: true, source: "fetched", relianceBoundMs: t0 + 20_000 });
    clockMs = t0 + 15_000;
    expect(await r.resolve(ref)).toMatchObject({ ok: true, source: "cached", view: { state: "suspended" } });
    clockMs = t0 + 20_000;
    expect(r.peek(ref)).toBeUndefined();
    expect(await r.resolve(ref)).toMatchObject({ ok: true, source: "fetched" });
    expect(requests.length).toBe(2);
  });

  it("reads the source on every fresh request, whatever the cache holds", async () => {
    const r = resolver();
    await r.resolve(ref);
    expect(await r.resolve(ref, { fresh: true })).toMatchObject({ ok: true, source: "fetched" });
    expect(await r.resolve(ref, { fresh: true })).toMatchObject({ ok: true, source: "fetched" });
    expect(requests.length).toBe(3);
  });

  it("never lets a slower, older observation replace a newer one", async () => {
    let n = 0;
    handler = async (req, res, query) => {
      n += 1;
      if (n === 1) {
        // The first read is observed earlier and answered last.
        const older = respond((p) => {
          lifetime(p, nowS() - 5, nowS() + 55);
          mission(p).version = 1;
        });
        setTimeout(() => void older(req, res, query), 300);
        return;
      }
      await respond((p) => {
        mission(p).version = 2;
        mission(p).state = "terminated";
      })(req, res, query);
    };
    const r = resolver();
    const slow = r.resolve(ref);
    while (requests.length < 1) await new Promise((resolve) => setTimeout(resolve, 10));
    const newer = await r.resolve(ref, { fresh: true });
    expect(newer).toMatchObject({ ok: true, view: { version: 2, state: "terminated" } });
    expect(await slow).toMatchObject({ ok: true, view: { version: 1, state: "active" } });
    expect(await r.resolve(ref)).toMatchObject({ ok: true, source: "cached", view: { version: 2, state: "terminated" } });
  });
});

describe("MissionStatusResolver: a synchronous peek answers only from a read still within its bounds (#818, D560)", () => {
  it("returns what an earlier resolve established, never reads the source, and returns nothing once a bound has passed", async () => {
    handler = respond((p) => {
      mission(p).fresh_until = new Date((nowS() + 20) * 1000).toISOString();
    });
    const r = resolver();
    expect(r.peek(ref)).toBeUndefined();
    await r.resolve(ref);
    expect(requests.length).toBe(1);
    expect(r.peek(ref)).toMatchObject({ ok: true, source: "cached", view: { id: MISSION } });
    expect(r.peek({ id: MISSION, issuer: "https://other-mas.example" })).toBeUndefined();
    clockMs += 6_000;
    expect(r.peek(ref, 5)).toBeUndefined();
    expect(r.peek(ref)).toMatchObject({ ok: true });
    clockMs += 14_000;
    expect(r.peek(ref)).toBeUndefined();
    expect(requests.length).toBe(1);
  });
});

describe("MissionStatusResolver: configuration", () => {
  it("refuses a configuration with no bound or no credential", () => {
    for (const extra of [
      { maxStaleSeconds: 0 },
      { timeoutMs: Number.NaN },
      { maxResponseBytes: -1 },
      { client: { clientId: "", assertion: async () => "" } },
      { statusEndpoint: "not a url" },
    ]) {
      expect(() => resolver(extra), JSON.stringify(extra)).toThrow(/MissionStatusResolver/);
    }
  });
});
