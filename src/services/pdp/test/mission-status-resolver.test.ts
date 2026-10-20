/**
 * @spec authority-server#mission-join rule 2, status#mission-status-response,
 * status#mission-status-caching (#818)
 *
 * The PDP's remote Mission Status resolver against a controllable Status
 * server double: every answer the double can give that must not establish
 * Mission state is a typed failure, and nothing is cached from it. The double
 * signs with its own keys and publishes them beside a key it uses for
 * something else, the way an issuer's `jwks_uri` does.
 */

import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { type CryptoKey, exportJWK, generateKeyPair, SignJWT } from "jose";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import {
  declaredStatusKeys,
  MissionStatusResolver,
  type MissionStatusResolverOptions,
  type MissionStatusResolution,
} from "../src/mission-status-resolver.js";

const ISSUER = "https://mas.pilot.example";
const AUDIENCE = "https://payments.example/api";
const MISSION = "msn_resolver_double_0001";
const TOKEN = "pdp-status-token";
const STATUS_KID = "mas-status";
const TOKEN_KID = "mas-token";

type Handler = (req: IncomingMessage, res: ServerResponse, query: URLSearchParams) => void | Promise<void>;

let server: Server;
let base: string;
let handler: Handler;
const requests: Array<{ path: string; query: URLSearchParams; token: string | undefined }> = [];

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
  published = {
    keys: [
      { ...(await exportJWK(status.publicKey)), kid: STATUS_KID, alg: "ES256" },
      { ...(await exportJWK(token.publicKey)), kid: TOKEN_KID, alg: "ES256" },
    ],
  };
  server = createServer((req, res) => {
    const url = new URL(req.url ?? "/", "http://double");
    requests.push({ path: url.pathname, query: url.searchParams, token: req.headers["x-service-token"] as string | undefined });
    void handler(req, res, url.searchParams);
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
    sub: "ap-agent",
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
    statusUrl: (id) => `${base}/missions/${id}/status`,
    audience: AUDIENCE,
    keys: declaredStatusKeys(published as never, [STATUS_KID]),
    serviceToken: TOKEN,
    maxStaleSeconds: 300,
    timeoutMs: 1000,
    maxResponseBytes: 16 * 1024,
    now: () => new Date(clockMs),
    ...extra,
  });
}

const ref = { id: MISSION, issuer: ISSUER };

/** A failure of `reason`, with nothing cached: the next read goes to the double and verifies. */
async function expectRefusedUncached(r: MissionStatusResolver, reason: string, detail?: string | RegExp): Promise<void> {
  const before = requests.length;
  const first = await r.resolve(ref);
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
  it("reads the Mission at the issuer's Status operation as an authenticated, audience-scoped, nonce-bound request and builds the view", async () => {
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
    expect(request?.path).toBe(`/missions/${MISSION}/status`);
    expect(request?.token).toBe(TOKEN);
    expect(request?.query.get("audience")).toBe(AUDIENCE);
    expect(request?.query.get("nonce")).toMatch(/^[0-9a-f-]{36}$/);
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

  it("never lets a reference's identifier steer the request to another path at the issuer", async () => {
    // A slash travels encoded, inside the one Mission segment, and the
    // answer for that identifier is refused like any other Mission's.
    expect(await resolver().resolve({ id: "../admin/keys", issuer: ISSUER })).toMatchObject({ ok: false, reason: "unverifiable" });
    expect(requests.map((q) => q.path)).toEqual(["/missions/..%2Fadmin%2Fkeys/status"]);
    // A dot segment, which encoding leaves as it is, is never requested.
    for (const id of ["..", ".", ""]) {
      expect(await resolver().resolve({ id, issuer: ISSUER }), JSON.stringify(id)).toMatchObject({ ok: false, reason: "not_found" });
    }
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

  it("refuses a response whose mission names another issuer", async () => {
    handler = respond((p) => {
      mission(p).issuer = "https://impostor.example";
    });
    await expectRefusedUncached(resolver(), "unverifiable");
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

  it("refuses a response that does not echo this request's nonce", async () => {
    handler = respond((p) => {
      p.nonce = "an-earlier-request";
    });
    await expectRefusedUncached(resolver(), "unverifiable", "nonce");
  });

  it("refuses a response that has expired", async () => {
    handler = respond((p) => {
      p.iat = nowS() - 600;
      p.exp = nowS() - 300;
    });
    await expectRefusedUncached(resolver(), "unverifiable");
  });

  it("allows no more clock skew than the issuer's mission_max_stale_seconds", async () => {
    // Expired 20 seconds ago: inside the profile's 30-second allowance, past
    // a 10-second advertised maximum staleness.
    const expired = (p: Record<string, unknown>) => {
      p.iat = nowS() - 80;
      p.exp = nowS() - 20;
    };
    handler = respond(expired);
    expect(await resolver().resolve(ref)).toMatchObject({ ok: true });
    handler = respond(expired);
    await expectRefusedUncached(resolver({ maxStaleSeconds: 10 }), "unverifiable");
  });

  it("refuses a response whose signed fresh_until has passed, or that carries none", async () => {
    handler = respond((p) => {
      mission(p).fresh_until = new Date((nowS() - 1) * 1000).toISOString();
    });
    await expectRefusedUncached(resolver(), "unverifiable", "fresh_until passed");
    handler = respond((p) => {
      delete mission(p).fresh_until;
    });
    await expectRefusedUncached(resolver(), "unverifiable");
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
      [500, "unavailable"],
      [503, "unavailable"],
    ] as const) {
      handler = (_req, res) => {
        res.writeHead(code, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "x" }));
      };
      await expectRefusedUncached(resolver(), reason, `status ${code}`);
    }
  });

  it("never follows a redirect, even to an answer that would verify", async () => {
    handler = (req, res, query) => {
      if (req.url?.startsWith("/elsewhere")) return respond()(req, res, query);
      res.writeHead(302, { location: `/elsewhere/missions/${MISSION}/status?${query.toString()}` });
      res.end();
    };
    const refused = await resolver().resolve(ref);
    expect(refused).toMatchObject({ ok: false, reason: "unavailable", detail: "status 302" });
    expect(requests.map((q) => q.path)).toEqual([`/missions/${MISSION}/status`]);
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

  it("reports a source that does not answer at all as unavailable", async () => {
    const r = resolver({ statusUrl: () => "http://127.0.0.1:1/missions/x/status" });
    expect(await r.resolve(ref)).toMatchObject({ ok: false, reason: "unavailable", detail: "transport" });
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
          p.iat = nowS() - 5;
          p.exp = nowS() + 55;
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

describe("MissionStatusResolver: configuration", () => {
  it("refuses a configuration with no bound or no credential", () => {
    for (const extra of [{ maxStaleSeconds: 0 }, { timeoutMs: Number.NaN }, { maxResponseBytes: -1 }, { serviceToken: "" }]) {
      expect(() => resolver(extra), JSON.stringify(extra)).toThrow(/MissionStatusResolver/);
    }
  });
});
