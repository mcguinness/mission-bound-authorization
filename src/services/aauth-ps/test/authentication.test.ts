/**
 * Caller authentication at every PS endpoint: an HTTP Message Signature
 * under the Signature-Key `jwt` scheme presenting an agent token (AAuth
 * -11 Sections 7 and 11.3), over the request's real `@authority`, with
 * Content-Digest and Content-Type covered on a body request, verified by
 * `@mission/aauth-wire`. A failure is 401 with Signature-Error.
 */
import { request } from "node:http";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  type Agent,
  approve,
  issuedCount,
  makeAgent,
  personToken,
  prepare,
  type Reply,
  RS,
  requestPersonToken,
  send,
  type World,
  world,
} from "./helpers.js";

let w: World;
let assistant: Agent;
let s256: string;

beforeEach(async () => {
  w = await world();
  assistant = await makeAgent(w.ap, w.clock);
  ({ s256 } = await approve(w, assistant));
});
afterEach(async () => {
  await w.close();
});

function unauthenticated(r: Reply, code: string): void {
  expect(r.status, JSON.stringify(r.body)).toBe(401);
  expect(r.headers.get("signature-error")).toContain(`error=${code}`);
  expect(r.body.person_token).toBeUndefined();
  expect(issuedCount(w)).toBe(0);
}

/** Send with node:http, which lets a test set the Host field. */
function rawPost(
  port: number,
  path: string,
  headers: Record<string, string>,
  body: string,
): Promise<Reply> {
  return new Promise((resolve, reject) => {
    const req = request({ host: "127.0.0.1", port, path, method: "POST", headers }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c: Buffer) => chunks.push(c));
      res.on("end", () => {
        const text = Buffer.concat(chunks).toString("utf8");
        const h = new Headers();
        for (const [k, v] of Object.entries(res.headers)) if (typeof v === "string") h.set(k, v);
        resolve({ status: res.statusCode ?? 0, headers: h, body: text ? JSON.parse(text) : {} });
      });
    });
    req.on("error", reject);
    req.end(body);
  });
}

describe("PS caller authentication", () => {
  it("refuses an unsigned request: 401 invalid_signature", async () => {
    const r = await send("POST", `${w.origin}/person`, {
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ resource: RS, mission_s256: s256 }),
    });
    unauthenticated(r, "invalid_signature");
  });

  it("refuses a body request whose signature does not cover Content-Digest: 401 invalid_input", async () => {
    const url = `${w.origin}/person`;
    const prepared = prepare(
      w.clock,
      "POST",
      url,
      assistant,
      { resource: RS, mission_s256: s256 },
      {
        components: ["@method", "@authority", "@path", "signature-key", "content-type"],
      },
    );
    unauthenticated(await send("POST", url, prepared), "invalid_input");
  });

  it("refuses a replayed signed request: 401 invalid_signature", async () => {
    const url = `${w.origin}/person`;
    const prepared = prepare(w.clock, "POST", url, assistant, { resource: RS, mission_s256: s256 });
    expect((await send("POST", url, prepared)).status).toBe(200);
    const replay = await send("POST", url, prepared);
    expect(replay.status).toBe(401);
    expect(replay.headers.get("signature-error")).toContain("error=invalid_signature");
    expect(issuedCount(w)).toBe(1);
  });

  it("verifies the authority the request reached, not the Host field: 401 invalid_signature", async () => {
    const port = Number(new URL(w.origin).port);
    const elsewhere = `http://localhost:${port}/person`;
    const prepared = prepare(w.clock, "POST", elsewhere, assistant, {
      resource: RS,
      mission_s256: s256,
    });
    const r = await rawPost(
      port,
      "/person",
      { ...prepared.headers, host: `localhost:${port}` },
      prepared.body as string,
    );
    unauthenticated(r, "invalid_signature");
  });

  it("refuses a person token in place of the agent token: 401 invalid_jwt", async () => {
    const pt = await personToken(w, assistant, RS, s256);
    const before = issuedCount(w);
    const r = await requestPersonToken(
      w,
      { ...assistant, token: pt },
      { resource: RS, mission_s256: s256 },
    );
    expect(r.status).toBe(401);
    expect(r.headers.get("signature-error")).toContain("error=invalid_jwt");
    expect(issuedCount(w)).toBe(before);
  });

  it("refuses an agent token from an issuer outside egress admission: 401 unknown_key", async () => {
    const outsider = { ...assistant };
    outsider.token = await w.ap.mint("aa-agent+jwt", {
      iss: "https://elsewhere.test",
      dwk: "aauth-agent.json",
      sub: "aauth:assistant@elsewhere.test",
      jti: "agent-token-1",
      iat: w.clock.s,
      exp: w.clock.s + 600,
      cnf: { jwk: assistant.key.publicJwk },
    });
    unauthenticated(
      await requestPersonToken(w, outsider, { resource: RS, mission_s256: s256 }),
      "unknown_key",
    );
  });

  it("refuses an expired agent token: 401 expired_jwt", async () => {
    const stale = await makeAgent(w.ap, w.clock, assistant.id, {
      cnf: { jwk: assistant.key.publicJwk },
      exp: w.clock.s + 5,
    });
    w.clock.advance(10);
    unauthenticated(
      await requestPersonToken(
        w,
        { ...assistant, token: stale.token },
        {
          resource: RS,
          mission_s256: s256,
        },
      ),
      "expired_jwt",
    );
  });

  it("authenticates the owner's read, a GET without a body", async () => {
    const url = `${w.origin}/mission/${s256}`;
    expect((await send("GET", url, prepare(w.clock, "GET", url, assistant))).status).toBe(200);
    expect((await send("GET", url, { headers: {} })).status).toBe(401);
  });
});

describe("PS metadata", () => {
  it("publishes its issuer, jwks_uri and endpoints, and a JWKS with a fully-specified alg", async () => {
    const meta = await (await fetch(`${w.origin}/.well-known/aauth-person.json`)).json();
    expect(meta).toEqual({
      issuer: "https://ps.test",
      jwks_uri: "https://ps.test/.well-known/jwks.json",
      person_token_endpoint: "https://ps.test/person",
      auth_token_endpoint: "https://ps.test/token",
      mission_endpoint: "https://ps.test/mission",
    });
    const jwks = (await (await fetch(`${w.origin}/.well-known/jwks.json`)).json()) as {
      keys: Record<string, unknown>[];
    };
    expect(jwks.keys).toHaveLength(1);
    expect(jwks.keys[0]).toMatchObject({
      kty: "OKP",
      crv: "Ed25519",
      alg: "Ed25519",
      kid: "ps-signing-1",
    });
    expect(jwks.keys[0]).not.toHaveProperty("d");
  });
});
