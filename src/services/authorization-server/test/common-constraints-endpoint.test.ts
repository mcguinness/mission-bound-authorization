/**
 * @spec resource-access#common-constraints, resource-access#initial-common-constraints,
 * mission#authority-proposal, mission#introspection, issuance-grant#effective-set-projection
 * (#1266, D457)
 *
 * Endpoint preservation of the implemented Common Constraints through the
 * real authorization server, booted over a copy of the shipped `config/`
 * whose payments read ceiling carries them: PAR intake, derivation at the
 * approval decision, the code exchange, refresh, introspection, and the
 * async-delegation Token Exchange. Every enabled key survives each step
 * without widening or silent loss: a proposal that omits a ceiling key
 * inherits it, an exchange that drops it is refused, and an intersection
 * that is empty refuses the derivation with no Mission created.
 */

const hoisted = await vi.hoisted(async () => {
  const { cpSync, mkdtempSync, readFileSync, writeFileSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const { fileURLToPath } = await import("node:url");
  // The ceiling every slice of #1266 extends: the payments read entry, which
  // already carries `vendors` and a delegation grant.
  const CEILING_CONSTRAINTS = {
    resource_issued_after: "2026-07-01T00:00:00Z",
    resource_issued_before: "2026-09-30T23:59:59Z",
  };
  const dir = mkdtempSync(join(tmpdir(), "mission-config-1266-"));
  cpSync(fileURLToPath(new URL("../../../config", import.meta.url)), dir, { recursive: true });
  const file = join(dir, "policy.json");
  const policy = JSON.parse(readFileSync(file, "utf8")) as { ceiling: { constraints?: Record<string, unknown> }[] };
  const first = policy.ceiling[0] as { constraints?: Record<string, unknown> };
  first.constraints = { ...first.constraints, ...CEILING_CONSTRAINTS };
  writeFileSync(file, JSON.stringify(policy, null, 2));
  const previous = process.env.MISSION_CONFIG_DIR;
  process.env.MISSION_CONFIG_DIR = dir;
  return { dir, previous, CEILING_CONSTRAINTS };
});

import { rmSync } from "node:fs";
import type { Server } from "node:http";
import { DERIVATION_POLICY } from "@mission/demo-data";
import { exportJWK, generateKeyPair, importJWK, SignJWT } from "jose";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { ACCESS_TOKEN_TOKEN_TYPE, TOKEN_EXCHANGE_GRANT_TYPE } from "../src/adapters/continuation-grant.js";
import { type AuthorityEntry, type BuiltAs, buildAuthorizationServer } from "../src/index.js";
import { TEST_APPROVAL_PRINCIPALS, trustedApprovalHeaders } from "./approval-fixture.js";
import { delegationHandleParams } from "./delegation-handle.helper.js";

const PORT = 14866;
const ISSUER = `http://localhost:${PORT}`;
const REDIRECT_URI = "http://localhost:9999/cb";
const RESOURCE = DERIVATION_POLICY.ceiling[0]?.resource as string;
const FAR_EXP = "2027-06-01T00:00:00Z";
const VERIFIER = "common-constraints-verifier-0123456789-0123456789-01";
const RS_PAYMENTS = ["rs-payments", "dev-introspection-rs-payments"] as const;

type Keys = { privateKey: CryptoKey; publicKey: CryptoKey };
type Json = Record<string, unknown>;

let as: BuiltAs;
let server: Server;
let clientKey: CryptoKey;

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

async function push(proposal: AuthorityEntry[]): Promise<{ status: number; body: Json }> {
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
        intent: { goal: "Review third-quarter Acme invoices", target_resources: [RESOURCE], expires_at: FAR_EXP },
      }),
      authorization_details: JSON.stringify(proposal),
      client_assertion: await clientAssertion(),
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    }).toString(),
  });
  return { status: par.status, body: (await par.json()) as Json };
}

/** PAR and the approval decision: the final redirect (a code, or the refusal). */
async function approve(proposal: AuthorityEntry[]): Promise<URL> {
  const pushed = await push(proposal);
  expect(pushed.status, JSON.stringify(pushed.body)).toBe(201);
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
    `${ISSUER}/auth?${new URLSearchParams({ client_id: "ap-agent", request_uri: String(pushed.body.request_uri) })}`,
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
  return new URL(location);
}

/** The full issuance: approval, then the code exchange. */
async function issue(proposal: AuthorityEntry[]): Promise<{ at: string; rt: string; keys: Keys; missionId: string }> {
  const redirect = await approve(proposal);
  const code = redirect.searchParams.get("code");
  expect(code, redirect.toString()).toBeTruthy();
  const keys = (await generateKeyPair("ES256", { extractable: true })) as Keys;
  const exchanged = await token(
    { grant_type: "authorization_code", code: code as string, redirect_uri: REDIRECT_URI, code_verifier: VERIFIER, resource: RESOURCE },
    keys,
  );
  expect(exchanged.status, JSON.stringify(exchanged.body)).toBe(200);
  const at = exchanged.body.access_token as string;
  return { at, rt: exchanged.body.refresh_token as string, keys, missionId: (claims(at).mission as { id: string }).id };
}

const claims = (jwt: string): Json =>
  JSON.parse(Buffer.from(jwt.split(".")[1] as string, "base64url").toString()) as Json;
const constraintsOf = (details: unknown): Array<Record<string, unknown> | undefined> =>
  (details as AuthorityEntry[]).map((e) => e.constraints as Record<string, unknown> | undefined);

async function introspect(tokenValue: string, hint?: string): Promise<Json> {
  const res = await fetch(`${ISSUER}/introspect`, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      authorization: `Basic ${Buffer.from(`${RS_PAYMENTS[0]}:${RS_PAYMENTS[1]}`).toString("base64")}`,
    },
    body: new URLSearchParams({ token: tokenValue, ...(hint ? { token_type_hint: hint } : {}) }).toString(),
  });
  expect(res.status).toBe(200);
  return (await res.json()) as Json;
}

/** The async-delegation Token Exchange over the base token's delegation handle. */
async function exchange(base: string, keys: Keys, requested?: AuthorityEntry[]): Promise<{ status: number; body: Json }> {
  const handle = await token(delegationHandleParams(base, "ap-agent"), keys);
  expect(handle.status, JSON.stringify(handle.body)).toBe(200);
  return token(
    {
      grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
      request_refresh_token: "true",
      subject_token: handle.body.access_token as string,
      subject_token_type: ACCESS_TOKEN_TOKEN_TYPE,
      resource: RESOURCE,
      creation_request_id: crypto.randomUUID(),
      ...(requested ? { authorization_details: JSON.stringify(requested) } : {}),
    },
    keys,
  );
}

const read = (constraints: Record<string, unknown> = {}): AuthorityEntry[] => [
  {
    type: "mission_resource_access",
    resource: RESOURCE,
    actions: ["payments:invoice.read"],
    constraints: { vendors: ["acme"], ...constraints },
  } as AuthorityEntry,
];

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
  if (hoisted.previous === undefined) delete process.env.MISSION_CONFIG_DIR;
  else process.env.MISSION_CONFIG_DIR = hoisted.previous;
  rmSync(hoisted.dir, { recursive: true, force: true });
});

describe("resource_issued_after and resource_issued_before survive every issuance path (@spec resource-access#common-constraints)", () => {
  // The proposal narrows the after-bound (in another offset) and omits the
  // before-bound, which the derived entry inherits from the ceiling.
  const NARROWED = { resource_issued_after: "2026-08-01T00:00:00+02:00" };
  const DERIVED = {
    vendors: ["acme"],
    resource_issued_after: "2026-08-01T00:00:00+02:00",
    resource_issued_before: hoisted.CEILING_CONSTRAINTS.resource_issued_before,
  };
  let issued: { at: string; rt: string; keys: Keys; missionId: string };

  beforeAll(async () => {
    issued = await issue(read(NARROWED));
  });

  it("the approval derives the intersection and the code-exchanged access token carries it", () => {
    expect(as.kernel.get(issued.missionId)?.authority_set.map((e) => e.constraints)).toEqual([DERIVED]);
    expect(constraintsOf(claims(issued.at).authorization_details)).toEqual([DERIVED]);
  });

  it("a refreshed access token carries the same bounds", async () => {
    const refreshed = await token(
      { grant_type: "refresh_token", refresh_token: issued.rt, resource: RESOURCE },
      issued.keys,
    );
    expect(refreshed.status, JSON.stringify(refreshed.body)).toBe(200);
    expect(constraintsOf(claims(refreshed.body.access_token as string).authorization_details)).toEqual([DERIVED]);
  });

  it("introspection of the access token returns the bounds in authorization_details", async () => {
    const body = await introspect(issued.at);
    expect(body.active).toBe(true);
    expect(constraintsOf(body.authorization_details)).toEqual([DERIVED]);
  });

  it("a Token Exchange carries the bounds when it requests nothing narrower", async () => {
    const res = await exchange(issued.at, issued.keys);
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(constraintsOf(claims(res.body.access_token as string).authorization_details)).toEqual([DERIVED]);
  });

  it("a Token Exchange that narrows the window issues the narrower window", async () => {
    const narrower = { ...DERIVED, resource_issued_before: "2026-09-01T00:00:00Z" };
    const res = await exchange(issued.at, issued.keys, read(narrower));
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(constraintsOf(claims(res.body.access_token as string).authorization_details)).toEqual([narrower]);
  });

  it("a Token Exchange compares bounds as UTC instants: a later instant whose text sorts earlier is narrower", async () => {
    // 2026-07-31T23:00:00Z is an hour after the derived 2026-08-01T00:00:00+02:00
    // (2026-07-31T22:00:00Z), though it sorts before it as text.
    const later = { ...DERIVED, resource_issued_after: "2026-07-31T23:00:00Z" };
    const res = await exchange(issued.at, issued.keys, read(later));
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(constraintsOf(claims(res.body.access_token as string).authorization_details)).toEqual([later]);
    // And an hour earlier, whose text sorts later, is broader.
    const earlier = await exchange(issued.at, issued.keys, read({ ...DERIVED, resource_issued_after: "2026-08-01T00:00:00+03:00" }));
    expect(earlier.status).toBe(400);
    expect(earlier.body.error).toBe("invalid_authorization_details");
  });

  it("a Token Exchange that drops or widens a bound is refused invalid_authorization_details", async () => {
    const { resource_issued_before: _dropped, ...dropped } = DERIVED;
    const droppedRes = await exchange(issued.at, issued.keys, read(dropped));
    expect(droppedRes.status).toBe(400);
    expect(droppedRes.body.error).toBe("invalid_authorization_details");
    const widened = await exchange(issued.at, issued.keys, read({ ...DERIVED, resource_issued_after: "2026-07-15T00:00:00Z" }));
    expect(widened.status).toBe(400);
    expect(widened.body.error).toBe("invalid_authorization_details");
    const later = await exchange(issued.at, issued.keys, read({ ...DERIVED, resource_issued_before: "2026-10-31T00:00:00Z" }));
    expect(later.status).toBe(400);
    expect(later.body.error).toBe("invalid_authorization_details");
  });
});

describe("derivation and intake over resource_issued_after and resource_issued_before at the endpoints (@spec mission#authority-proposal)", () => {
  it("a proposal omitting the ceiling's window derives with the ceiling's window, never without it", async () => {
    const issued = await issue(read());
    expect(constraintsOf(claims(issued.at).authorization_details)).toEqual([
      { vendors: ["acme"], ...hoisted.CEILING_CONSTRAINTS },
    ]);
  });

  it("a proposal whose window cannot meet the ceiling's is refused at the approval decision, creating no Mission", async () => {
    const before = as.kernel.allMissions().length;
    const redirect = await approve(read({ resource_issued_after: "2026-10-01T00:00:00Z" }));
    expect(redirect.searchParams.get("error")).toBe("invalid_authorization_details");
    expect(redirect.searchParams.get("error_description")).toMatch(/issuance window is empty/);
    expect(as.kernel.allMissions().length).toBe(before);
  });

  it("PAR refuses a malformed bound invalid_authorization_details", async () => {
    const res = await push(read({ resource_issued_before: "2026-09-30" }));
    expect(res.status).toBe(400);
    expect(res.body.error).toBe("invalid_authorization_details");
  });
});
