/**
 * @spec resource-access#subset, resource-access#resource-matching,
 * mission#derivation-modes, mission#approval-authentication (#1440)
 *
 * A configured `prefix` ceiling through the real authorization server, booted
 * over a copy of the shipped `config/` whose payments read ceiling entry is
 * `prefix`, beside the shipped containment rules (containment pairs by
 * resource-set overlap, #1463): the typed loader admits it, the approval
 * decision derives a narrower `exact` or `prefix` proposal under it and
 * classifies the derived entry through the shared matcher, and the issued
 * token carries the derived entry. The payments write ceiling stays `exact`,
 * so a `prefix` request against an `exact` grant naming the same resource is
 * refused. A containment selector through the lifecycle endpoint reaches an
 * entry approved beneath the `prefix` ceiling.
 */

const hoisted = await vi.hoisted(async () => {
  const { cpSync, mkdtempSync, readFileSync, writeFileSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const { fileURLToPath } = await import("node:url");
  const dir = mkdtempSync(join(tmpdir(), "mission-config-1440-"));
  cpSync(fileURLToPath(new URL("../../../config", import.meta.url)), dir, { recursive: true });
  const file = join(dir, "policy.json");
  const policy = JSON.parse(readFileSync(file, "utf8")) as { ceiling: Record<string, unknown>[] };
  (policy.ceiling[0] as Record<string, unknown>).resource_match = "prefix";
  writeFileSync(file, JSON.stringify(policy, null, 2));
  // The shipped containment rules stay configured: since #1463 containment
  // pairs by resource-set overlap, so a prefix ceiling loads beside them.
  const previous = process.env.MISSION_CONFIG_DIR;
  process.env.MISSION_CONFIG_DIR = dir;
  return { dir, previous };
});

import { rmSync } from "node:fs";
import type { Server } from "node:http";
import { CONTAINMENT_POLICY, DERIVATION_POLICY, DEV_SERVICE_TOKEN } from "@mission/demo-data";
import { exportJWK, generateKeyPair, importJWK, SignJWT } from "jose";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { type AuthorityEntry, type BuiltAs, buildAuthorizationServer } from "../src/index.js";
import { TEST_APPROVAL_PRINCIPALS, trustedApprovalHeaders } from "./approval-fixture.js";

const PORT = 14940;
const ISSUER = `http://localhost:${PORT}`;
const REDIRECT_URI = "http://localhost:9999/cb";
const RESOURCE = DERIVATION_POLICY.ceiling[0]?.resource as string;
const INVOICES = `${RESOURCE}/invoices`;
const INV1 = `${INVOICES}/inv-1`;
const SIBLING = `${RESOURCE}-archive/invoices`;
const FAR_EXP = "2027-06-01T00:00:00Z";
const VERIFIER = "prefix-ceiling-verifier-0123456789-0123456789-0123456";

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

async function push(proposal: AuthorityEntry[], targets: string[]): Promise<{ status: number; body: Json }> {
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
        intent: { goal: "Review third-quarter Acme invoices", target_resources: targets, expires_at: FAR_EXP },
      }),
      authorization_details: JSON.stringify(proposal),
      client_assertion: await clientAssertion(),
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    }).toString(),
  });
  return { status: par.status, body: (await par.json()) as Json };
}

/** PAR and the approval decision: the final redirect (a code, or the refusal). */
async function approve(proposal: AuthorityEntry[], targets: string[]): Promise<URL> {
  const pushed = await push(proposal, targets);
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

const claims = (jwt: string): Json =>
  JSON.parse(Buffer.from(jwt.split(".")[1] as string, "base64url").toString()) as Json;

/** The full issuance: approval, then the code exchange. */
async function issue(
  proposal: AuthorityEntry[],
  targets: string[],
): Promise<{ at: string; rt: string; keys: Keys; missionId: string }> {
  const redirect = await approve(proposal, targets);
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

const read = (resource: string, resource_match?: "prefix"): AuthorityEntry =>
  ({
    type: "mission_resource_access",
    resource,
    ...(resource_match ? { resource_match } : {}),
    actions: ["payments:invoice.read"],
    constraints: { vendors: ["acme"] },
  }) as AuthorityEntry;

const schedule = (resource_match?: "prefix"): AuthorityEntry =>
  ({
    type: "mission_resource_access",
    resource: RESOURCE,
    ...(resource_match ? { resource_match } : {}),
    actions: ["payments:payment.schedule"],
    constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
  }) as AuthorityEntry;

/** The derived entries' resource members, as the Mission records them. */
const resourcesOf = (entries: readonly AuthorityEntry[] | undefined) =>
  (entries ?? []).map((e) => ({ resource: e.resource, ...(e.resource_match ? { resource_match: e.resource_match } : {}) }));

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

describe("a configured prefix ceiling derives through the authorization server (@spec resource-access#subset, #1440)", () => {
  it("the typed loader keeps the configured ceiling entry's prefix", () => {
    expect(DERIVATION_POLICY.ceiling[0]?.resource_match).toBe("prefix");
    expect(DERIVATION_POLICY.ceiling[1]?.resource_match).toBeUndefined();
  });

  it("an exact proposal beneath the prefix ceiling derives as the proposal's own exact resource, is classified by the approval floor, and the issued token carries it", async () => {
    const issued = await issue([read(INV1)], [RESOURCE, INV1]);
    const record = as.kernel.get(issued.missionId);
    expect(resourcesOf(record?.authority_set)).toEqual([{ resource: INV1 }]);
    expect(resourcesOf(claims(issued.at).authorization_details as AuthorityEntry[])).toEqual([{ resource: INV1 }]);
  });

  it("a prefix proposal within the prefix ceiling derives as a prefix entry keeping its own base", async () => {
    const issued = await issue([read(INVOICES, "prefix")], [RESOURCE, INVOICES]);
    const record = as.kernel.get(issued.missionId);
    expect(resourcesOf(record?.authority_set)).toEqual([{ resource: INVOICES, resource_match: "prefix" }]);
    expect(resourcesOf(claims(issued.at).authorization_details as AuthorityEntry[])).toEqual([
      { resource: INVOICES, resource_match: "prefix" },
    ]);
  });

  it("a proposal for a sibling outside the prefix boundary derives nothing and is refused at the approval decision, creating no Mission", async () => {
    const before = as.kernel.allMissions().length;
    const redirect = await approve([read(SIBLING)], [RESOURCE, SIBLING]);
    expect(redirect.searchParams.get("error")).toBe("invalid_authorization_details");
    expect(as.kernel.allMissions().length).toBe(before);
  });
});

describe("a finer entry pairs with the resource that serves it through the shared matcher (@spec mission#introspection, status#mission-status-response, capability-binding#capability-source-binding, #1440)", () => {
  let issued: { at: string; rt: string; keys: Keys; missionId: string };
  beforeAll(async () => {
    issued = await issue([read(INV1)], [RESOURCE, INV1]);
  });

  it("introspection by the payments resource server discloses the finer entry its resource serves", async () => {
    const res = await fetch(`${ISSUER}/introspect`, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        authorization: `Basic ${Buffer.from("rs-payments:dev-introspection-rs-payments").toString("base64")}`,
      },
      body: new URLSearchParams({ token: issued.at }).toString(),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as Json;
    expect(body.active).toBe(true);
    expect(resourcesOf(body.authorization_details as AuthorityEntry[])).toEqual([{ resource: INV1 }]);
  });

  it("the audience-scoped Mission Status response lists the finer entry for the payments audience and nothing for another audience", async () => {
    const scoped = async (audience: string) => {
      const res = await fetch(`${ISSUER}/missions/${issued.missionId}/status?audience=${encodeURIComponent(audience)}`, {
        headers: { "x-service-token": DEV_SERVICE_TOKEN },
      });
      expect(res.status).toBe(200);
      return claims(await res.text()).authorization_details as AuthorityEntry[];
    };
    expect(resourcesOf(await scoped(RESOURCE))).toEqual([{ resource: INV1 }]);
    expect(await scoped(DERIVATION_POLICY.ceiling[2]?.resource as string)).toEqual([]);
  });

  it("the trusted catalog resolves the finer entry's catalog-sourced action, as for the payments service's own entry", () => {
    const sources = as.kernel.get(issued.missionId)?.authority_set[0]?.capability_sources ?? [];
    expect(sources.map((b) => b.action)).toEqual(["payments:invoice.read"]);
    expect(sources[0]?.tool_id).toMatch(/^mcp:\/\/payments\.demo\/tools\//);
  });
});

describe("a prefix request is never within an exact grant naming the same resource (@spec resource-access#subset, #1440)", () => {
  it("a prefix proposal over the exact write ceiling narrows to the exact entry, and a refresh asking for the prefix entry is refused invalid_authorization_details while the exact one is issued", async () => {
    const issued = await issue([schedule("prefix")], [RESOURCE]);
    const record = as.kernel.get(issued.missionId);
    expect(resourcesOf(record?.authority_set)).toEqual([{ resource: RESOURCE }]);
    const refused = await token(
      {
        grant_type: "refresh_token",
        refresh_token: issued.rt,
        resource: RESOURCE,
        authorization_details: JSON.stringify([schedule("prefix")]),
      },
      issued.keys,
    );
    expect(refused.status, JSON.stringify(refused.body)).toBe(400);
    expect(refused.body.error).toBe("invalid_authorization_details");
    // Control: the exact entry naming the same resource is within the grant.
    const exact = await token(
      {
        grant_type: "refresh_token",
        refresh_token: issued.rt,
        resource: RESOURCE,
        authorization_details: JSON.stringify([schedule()]),
      },
      issued.keys,
    );
    expect(exact.status, JSON.stringify(exact.body)).toBe(200);
    expect(resourcesOf(claims(exact.body.access_token as string).authorization_details as AuthorityEntry[])).toEqual([
      { resource: RESOURCE },
    ]);
  });
});

describe("containment beside a configured prefix ceiling, through the lifecycle endpoint (@spec containment#selector-matching, #1463)", () => {
  const LIST = "payments:invoice.list";
  const READ = "payments:invoice.read";
  const both = (resource: string): AuthorityEntry =>
    ({
      type: "mission_resource_access",
      resource,
      actions: [LIST, READ],
      constraints: { vendors: ["acme"] },
    }) as AuthorityEntry;

  const contain = (missionId: string, event_id: string, remove: unknown[]) =>
    fetch(`${ISSUER}/missions/${missionId}/lifecycle`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-service-token": DEV_SERVICE_TOKEN },
      body: JSON.stringify({
        nonce: crypto.randomUUID(),
        operation: "contain",
        event: { type: "anomaly.detected", source: "svc:soc", observed_at: new Date().toISOString(), event_id },
        remove,
      }),
    });

  const refreshedActions = async (issued: { rt: string; keys: Keys }) => {
    const res = await token({ grant_type: "refresh_token", refresh_token: issued.rt, resource: RESOURCE }, issued.keys);
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    issued.rt = (res.body.refresh_token as string | undefined) ?? issued.rt;
    return (claims(res.body.access_token as string).authorization_details as AuthorityEntry[]).map((e) => ({
      resource: e.resource,
      actions: e.actions,
    }));
  };

  it("the authorization server boots with the shipped containment rules beside the prefix ceiling", () => {
    expect(CONTAINMENT_POLICY.rules.length).toBeGreaterThan(0);
    expect(DERIVATION_POLICY.ceiling[0]?.resource_match).toBe("prefix");
  });

  it("an exact service-root selector leaves an entry approved beneath the prefix ceiling untouched, and a declared prefix selector contains it", async () => {
    const issued = await issue([both(INV1)], [RESOURCE, INV1]);
    expect((await contain(issued.missionId, "evt-1463-exact", [{ resource: RESOURCE, actions: [LIST] }])).status).toBe(200);
    expect(await refreshedActions(issued)).toEqual([{ resource: INV1, actions: [LIST, READ] }]);

    const res = await contain(issued.missionId, "evt-1463-prefix", [{ resource: RESOURCE, resource_match: "prefix", actions: [LIST] }]);
    expect(res.status).toBe(200);
    expect(((await res.json()) as Json).containment_version).toBe(2);
    expect(await refreshedActions(issued)).toEqual([{ resource: INV1, actions: [READ] }]);
  });

  it("refuses a selector the matcher cannot decide with invalid_request, committing nothing", async () => {
    const issued = await issue([both(INV1)], [RESOURCE, INV1]);
    const before = as.kernel.get(issued.missionId)?.version;
    const res = await contain(issued.missionId, "evt-1463-glob", [{ resource: RESOURCE, resource_match: "glob", actions: [LIST] }]);
    expect(res.status).toBe(400);
    expect(((await res.json()) as Json).error).toBe("invalid_request");
    expect(as.kernel.get(issued.missionId)?.version).toBe(before);
    expect(as.kernel.get(issued.missionId)?.containment).toBeUndefined();
  });
});
