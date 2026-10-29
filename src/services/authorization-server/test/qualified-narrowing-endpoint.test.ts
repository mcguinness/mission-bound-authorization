/**
 * @spec mission#transformation-capabilities, resource-access#qualified-narrowing
 * (#1720 item 7, #1377, D1025): derivation and the Token Exchange narrow a
 * `mission_resource_access` entry only where the declared `narrowing` permits
 * it for the pair; otherwise an entry is carried only when it is equal. The
 * types metadata entry carries the declaration.
 *
 * Three authorization servers over a copy of the shipped `config/` whose
 * payments read ceiling entry is `prefix` (the payments write entry stays
 * `exact`): the shipped declaration (a narrowing domain covering every entry
 * this implementation admits), `narrowing` undeclared, and a narrowing domain
 * covering `exact` entries only, which shows the domain is read and not only
 * the presence of a declaration.
 */

const hoisted = await vi.hoisted(async () => {
  const { cpSync, mkdtempSync, readFileSync, writeFileSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const { fileURLToPath } = await import("node:url");
  const dir = mkdtempSync(join(tmpdir(), "mission-config-1377-"));
  cpSync(fileURLToPath(new URL("../../../config", import.meta.url)), dir, { recursive: true });
  const file = join(dir, "policy.json");
  const policy = JSON.parse(readFileSync(file, "utf8")) as { ceiling: Record<string, unknown>[] };
  (policy.ceiling[0] as Record<string, unknown>).resource_match = "prefix";
  writeFileSync(file, JSON.stringify(policy, null, 2));
  const previous = process.env.MISSION_CONFIG_DIR;
  process.env.MISSION_CONFIG_DIR = dir;
  return { dir, previous };
});

import { readFileSync, rmSync } from "node:fs";
import type { Server } from "node:http";
import { type JsonValue, NARROWING_UNDECLARED, narrowingDomainDigest, resolveNarrowing } from "@mission/core";
import { DERIVATION_POLICY, TRANSFORMATION_CAPABILITIES, type TransformationCapabilities } from "@mission/demo-data";
import { exportJWK, generateKeyPair, importJWK, SignJWT } from "jose";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { ACCESS_TOKEN_TOKEN_TYPE, TOKEN_EXCHANGE_GRANT_TYPE } from "../src/adapters/continuation-grant.js";
import { type AuthorityEntry, type BuiltAs, buildAuthorizationServer } from "../src/index.js";
import { renderedRevision, TEST_APPROVAL_PRINCIPALS, trustedApprovalHeaders } from "./approval-fixture.js";
import { delegationHandleParams } from "./delegation-handle.helper.js";

const REDIRECT_URI = "http://localhost:9999/cb";
const VERIFIER = "qualified-narrowing-verifier-0123456789-0123456789-01";
const FAR_EXP = "2027-06-01T00:00:00Z";
/** The payments read ceiling entry, `prefix` in this suite's configuration. */
const CEILING = DERIVATION_POLICY.ceiling[0] as AuthorityEntry;
const RESOURCE = CEILING.resource as string;
const INVOICES = `${RESOURCE}/invoices`;

type Keys = { privateKey: CryptoKey; publicKey: CryptoKey };
type Json = Record<string, unknown>;

/** One authorization server under test. */
interface Srv {
  issuer: string;
  as: BuiltAs;
  server: Server;
  clientKey: CryptoKey;
}

async function start(port: number, extra: Record<string, unknown> = {}): Promise<Srv> {
  const issuer = `http://localhost:${port}`;
  const as = await buildAuthorizationServer({
    issuer,
    allowHeadlessAdjudication: true,
    serviceTokenPrincipals: TEST_APPROVAL_PRINCIPALS,
    ...extra,
  });
  const server = as.provider.listen(port);
  await new Promise<void>((r) => server.once("listening", () => r()));
  return { issuer, as, server, clientKey: (await importJWK(as.agentClientJwk as never, "ES256")) as CryptoKey };
}

const stop = (s: Srv) => new Promise<void>((r) => s.server.close(() => r()));

async function clientAssertion(s: Srv): Promise<string> {
  return new SignJWT({})
    .setProtectedHeader({ alg: "ES256", kid: "ap-agent-auth" })
    .setIssuer("ap-agent")
    .setSubject("ap-agent")
    .setAudience(s.issuer)
    .setIssuedAt()
    .setExpirationTime("2m")
    .setJti(crypto.randomUUID())
    .sign(s.clientKey);
}

async function dpopProof(s: Srv, keys: Keys, extra: Json = {}): Promise<string> {
  return new SignJWT({ htu: `${s.issuer}/token`, htm: "POST", ...extra })
    .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: await exportJWK(keys.publicKey) })
    .setIssuedAt()
    .setJti(crypto.randomUUID())
    .sign(keys.privateKey);
}

async function token(s: Srv, params: Record<string, string>, keys: Keys): Promise<{ status: number; body: Json }> {
  const send = async (extra: Json = {}) =>
    fetch(`${s.issuer}/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", dpop: await dpopProof(s, keys, extra) },
      body: new URLSearchParams({
        ...params,
        client_id: "ap-agent",
        client_assertion: await clientAssertion(s),
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      }).toString(),
    });
  let res = await send();
  const nonce = res.headers.get("dpop-nonce");
  if (res.status === 400 && nonce) res = await send({ nonce });
  return { status: res.status, body: (await res.json()) as Json };
}

/** PAR and the approval decision: the final redirect (a code, or the refusal). */
async function approve(s: Srv, proposal: AuthorityEntry[] | undefined, targets: string[] = [RESOURCE]): Promise<URL> {
  const challenge = Buffer.from(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(VERIFIER)),
  ).toString("base64url");
  const par = await fetch(`${s.issuer}/request`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: "ap-agent",
      response_type: "code",
      redirect_uri: REDIRECT_URI,
      resource: targets[0] as string,
      code_challenge: challenge,
      code_challenge_method: "S256",
      login_hint: "alice",
      mission_intent: JSON.stringify({
        intent: { goal: "Review third-quarter Acme invoices", target_resources: targets, expires_at: FAR_EXP },
      }),
      ...(proposal ? { authorization_details: JSON.stringify(proposal) } : {}),
      client_assertion: await clientAssertion(s),
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
    `${s.issuer}/auth?${new URLSearchParams({ client_id: "ap-agent", request_uri: String(pushed.request_uri) })}`,
    { redirect: "manual" },
  );
  keep(res);
  const uid = (res.headers.get("location") ?? "").split("/interaction/")[1] as string;
  const decideHeaders = { ...trustedApprovalHeaders(), "content-type": "application/json", cookie: cookie() };
  // A proposal that derives nothing renders no page; the decision refuses it at derivation.
  const render_revision = await renderedRevision(s.issuer, uid, decideHeaders).catch(() => undefined);
  res = await fetch(`${s.issuer}/interaction/${uid}/decide`, {
    method: "POST",
    redirect: "manual",
    headers: decideHeaders,
    body: JSON.stringify({ decision: "approve", render_revision }),
  });
  keep(res);
  let location = res.headers.get("location") ?? "";
  while (location.startsWith(s.issuer)) {
    res = await fetch(location, { redirect: "manual", headers: { cookie: cookie() } });
    keep(res);
    location = res.headers.get("location") ?? "";
  }
  if (!location) throw new Error(`the approval ended without a redirect: ${res.status} ${await res.text()}`);
  return new URL(location);
}

/** The full issuance: approval, then the code exchange. */
async function issue(s: Srv, proposal: AuthorityEntry[]): Promise<{ at: string; rt: string; keys: Keys; missionId: string }> {
  const redirect = await approve(s, proposal);
  const code = redirect.searchParams.get("code");
  expect(code, redirect.toString()).toBeTruthy();
  const keys = (await generateKeyPair("ES256", { extractable: true })) as Keys;
  const exchanged = await token(
    s,
    { grant_type: "authorization_code", code: code as string, redirect_uri: REDIRECT_URI, code_verifier: VERIFIER, resource: RESOURCE },
    keys,
  );
  expect(exchanged.status, JSON.stringify(exchanged.body)).toBe(200);
  const at = exchanged.body.access_token as string;
  return { at, rt: exchanged.body.refresh_token as string, keys, missionId: (claims(at).mission as { id: string }).id };
}

/** Remove `actions` from the Mission's entries for the payments resource (an authoritative narrowing). */
function contain(s: Srv, missionId: string, actions: string[]): void {
  s.as.kernel.contain(missionId, {
    event: { type: "test.narrowing", source: "qualified-narrowing-endpoint.test", observed_at: new Date().toISOString(), event_id: crypto.randomUUID() },
    remove: [{ resource: RESOURCE, actions }],
  });
}

const refresh = (s: Srv, rt: string, keys: Keys) => token(s, { grant_type: "refresh_token", refresh_token: rt, resource: RESOURCE }, keys);

/** Run `fn`, counting the refresh tokens the provider saves meanwhile. */
async function countingRefreshSaves<T>(s: Srv, fn: () => Promise<T>): Promise<{ result: T; saved: number }> {
  let saved = 0;
  const onSaved = () => {
    saved += 1;
  };
  s.as.provider.on("refresh_token.saved", onSaved);
  try {
    return { result: await fn(), saved };
  } finally {
    s.as.provider.removeListener("refresh_token.saved", onSaved);
  }
}

/** The async-delegation Token Exchange over the base token's delegation handle. */
async function exchange(s: Srv, base: string, keys: Keys, requested: AuthorityEntry[]): Promise<{ status: number; body: Json }> {
  const handle = await token(s, delegationHandleParams(base, "ap-agent"), keys);
  expect(handle.status, JSON.stringify(handle.body)).toBe(200);
  return token(
    s,
    {
      grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
      request_refresh_token: "true",
      subject_token: handle.body.access_token as string,
      subject_token_type: ACCESS_TOKEN_TOKEN_TYPE,
      resource: RESOURCE,
      creation_request_id: crypto.randomUUID(),
      authorization_details: JSON.stringify(requested),
    },
    keys,
  );
}

function claims(jwt: string): Json {
  return JSON.parse(Buffer.from(jwt.split(".")[1] as string, "base64url").toString()) as Json;
}
const entriesOf = (jwt: string) => claims(jwt).authorization_details as AuthorityEntry[];
/**
 * The derived authority as the Mission records it, with the members approval
 * attaches from trusted configuration set aside: `resource_contract`
 * (assembled, never narrowed) and `capability_sources` (from the trusted
 * catalog, never from either operand).
 */
const recorded = (entries: readonly AuthorityEntry[]) =>
  entries.map(({ resource_contract: _assembled, capability_sources: _bindings, ...authority }) => authority as AuthorityEntry);

/** The approval for `proposal`: the entries of the Mission it created, or the refusal's error. */
async function decide(s: Srv, proposal: AuthorityEntry[] | undefined, targets?: string[]) {
  const before = new Set(s.as.kernel.allMissions().map((m) => m.id));
  const redirect = await approve(s, proposal, targets);
  const created = s.as.kernel.allMissions().filter((m) => !before.has(m.id));
  return { error: redirect.searchParams.get("error"), created: created.map((m) => recorded(m.authority_set)) };
}

const narrowerActions = { ...CEILING, actions: ["payments:invoice.read"] } as AuthorityEntry;

/** An exact-only narrowing domain for this implementation's members and keys. */
const EXACT_ONLY = {
  id: "https://mission-reference.example/narrowing-domains/test-exact-only/1",
  type: "mission_resource_access",
  capability: "narrowing",
  resource_match: ["exact"],
  members: ["type", "resource", "resource_match", "actions", "constraints", "delegation", "capability_sources", "resource_contract"],
  constraints: ["max_amount", "vendors", "tenant", "requires_action_approval"],
};

function exactOnlyCapabilities(): TransformationCapabilities {
  const value = { domain: { id: EXACT_ONLY.id, digest: narrowingDomainDigest(EXACT_ONLY as unknown as JsonValue) } };
  const resolved = resolveNarrowing(value, (id) => (id === EXACT_ONLY.id ? EXACT_ONLY : undefined));
  expect(resolved?.declaration.kind).toBe("domain");
  return {
    declared: { mission_resource_access: { narrowing: value } },
    narrowing: resolved?.declaration ?? NARROWING_UNDECLARED,
  };
}

let shipped: Srv;
let undeclared: Srv;
let exactOnly: Srv;

beforeAll(async () => {
  shipped = await start(14951);
  undeclared = await start(14952, { transformationCapabilities: { declared: {}, narrowing: NARROWING_UNDECLARED } });
  exactOnly = await start(14953, { transformationCapabilities: exactOnlyCapabilities() });
});

afterAll(async () => {
  await Promise.all([stop(shipped), stop(undeclared), stop(exactOnly)]);
  if (hoisted.previous === undefined) delete process.env.MISSION_CONFIG_DIR;
  else process.env.MISSION_CONFIG_DIR = hoisted.previous;
  rmSync(hoisted.dir, { recursive: true, force: true });
});

describe("the types metadata entry carries the declared transformation capabilities (@spec mission#transformation-capabilities, resource-access#qualified-narrowing)", () => {
  const metadata = async (s: Srv) => (await (await fetch(`${s.issuer}/authorization-details-types`)).json()) as Record<string, Json>;

  it("the shipped server declares narrowing for mission_resource_access as its qualified value, and nothing it does not declare", async () => {
    const entry = (await metadata(shipped)).mission_resource_access as Json;
    expect(entry.mission_transformation_capabilities).toEqual(TRANSFORMATION_CAPABILITIES.declared.mission_resource_access);
    expect(Object.keys(entry.mission_transformation_capabilities as Json)).toEqual(["narrowing"]);
  });

  it("the deployment documentation states the same declaration as the metadata entry (step 7)", async () => {
    const doc = readFileSync(new URL("../../../docs/resource-access-transformation-capabilities.md", import.meta.url), "utf8");
    const block = /<!-- declaration: mission_resource_access -->\n```json\n([\s\S]*?)\n```/.exec(doc);
    expect(block, "the inventory states the declaration").not.toBeNull();
    const entry = (await metadata(shipped)).mission_resource_access as Json;
    expect(JSON.parse(block?.[1] as string)).toEqual(entry.mission_transformation_capabilities);
    expect(doc).toContain("config/narrowing-domains/mission-resource-access-2026-10-29.json");
  });

  it("a server declaring nothing carries no member, so every capability falls through to deployment documentation", async () => {
    const entry = (await metadata(undeclared)).mission_resource_access as Json;
    expect(entry).not.toHaveProperty("mission_transformation_capabilities");
  });
});

describe("narrowing undeclared: derivation and the Token Exchange carry entries only as approved (@spec mission#transformation-capabilities, #1720 item 7)", () => {
  it("derivation retains a proposal equal to a ceiling entry unchanged, and the issued token carries it", async () => {
    const { error, created } = await decide(undeclared, [structuredClone(CEILING)]);
    expect(error).toBeNull();
    expect(created).toEqual([[CEILING]]);
  });

  it("derivation refuses a proposal it would have narrowed, creating no Mission, where the shipped declaration narrows it", async () => {
    const refused = await decide(undeclared, [narrowerActions]);
    expect(refused.error).toBe("invalid_authorization_details");
    expect(refused.created).toEqual([]);
    const narrowed = await decide(shipped, [narrowerActions]);
    expect(narrowed.error).toBeNull();
    expect(narrowed.created[0]?.[0]?.actions).toEqual(["payments:invoice.read"]);
  });

  it("configured-mapping derivation with no proposal yields each mapped ceiling entry unchanged", async () => {
    // The reports ceiling entry, so the approval meets no high-risk floor.
    const reports = DERIVATION_POLICY.ceiling[3] as AuthorityEntry;
    const { error, created } = await decide(undeclared, undefined, [reports.resource as string]);
    expect(error).toBeNull();
    expect(created).toEqual([[reports]]);
  });

  it("a Token Exchange requesting the presented entry unchanged is issued; one requesting it narrowed is refused", async () => {
    const issued = await issue(undeclared, [structuredClone(CEILING)]);
    const [presented] = entriesOf(issued.at);
    const same = await exchange(undeclared, issued.at, issued.keys, [presented as AuthorityEntry]);
    expect(same.status, JSON.stringify(same.body)).toBe(200);
    expect(entriesOf(same.body.access_token as string)).toEqual([presented]);
    const narrowed = await exchange(undeclared, issued.at, issued.keys, [
      { ...(presented as AuthorityEntry), actions: ["payments:invoice.read"] },
    ]);
    expect(narrowed.status, JSON.stringify(narrowed.body)).toBe(400);
    expect(narrowed.body.error).toBe("invalid_authorization_details");
  });
});

describe("a narrowing domain is read: an entry outside it is carried only as approved (@spec resource-access#qualified-narrowing)", () => {
  it("an exact proposal narrower than an exact ceiling entry derives narrowed: the domain covers exact", async () => {
    const schedule = DERIVATION_POLICY.ceiling[1] as AuthorityEntry;
    const { error, created } = await decide(exactOnly, [{ ...schedule, actions: ["payments:payment.schedule"] } as AuthorityEntry]);
    expect(error).toBeNull();
    expect(created[0]?.[0]?.actions).toEqual(["payments:payment.schedule"]);
  });

  it("a prefix proposal narrower than the prefix ceiling entry is refused, while one equal to it derives unchanged: the domain does not cover prefix", async () => {
    expect(CEILING.resource_match).toBe("prefix");
    const narrower = await decide(exactOnly, [{ ...CEILING, resource: INVOICES } as AuthorityEntry], [RESOURCE, INVOICES]);
    expect(narrower.error).toBe("invalid_authorization_details");
    expect(narrower.created).toEqual([]);
    const equal = await decide(exactOnly, [structuredClone(CEILING)]);
    expect(equal.error).toBeNull();
    expect(equal.created).toEqual([[CEILING]]);
    const narrowedUnderShipped = await decide(shipped, [{ ...CEILING, resource: INVOICES } as AuthorityEntry], [RESOURCE, INVOICES]);
    expect(narrowedUnderShipped.error).toBeNull();
    expect(narrowedUnderShipped.created[0]?.[0]?.resource).toBe(INVOICES);
  });
});

describe("automatic projection after partial containment: an entry the declaration does not let the AS narrow is contained whole (@spec mission#transformation-capabilities, resource-access#qualified-narrowing, #1377, D1025)", () => {
  it("under the shipped declaration, a refresh after partial containment issues the narrowed entry", async () => {
    const issued = await issue(shipped, [structuredClone(CEILING)]);
    contain(shipped, issued.missionId, ["payments:invoice.list"]);
    const refreshed = await refresh(shipped, issued.rt, issued.keys);
    expect(refreshed.status, JSON.stringify(refreshed.body)).toBe(200);
    expect(entriesOf(refreshed.body.access_token as string)[0]?.actions).toEqual(["payments:invoice.read", "payments:vendor.read"]);
  });

  it("with narrowing undeclared, the partially contained entry is contained whole, and the refresh is refused invalid_grant, saving no refresh token", async () => {
    const issued = await issue(undeclared, [structuredClone(CEILING)]);
    contain(undeclared, issued.missionId, ["payments:invoice.list"]);
    expect(undeclared.as.kernel.effectiveAuthoritySet(undeclared.as.kernel.get(issued.missionId) as never)).toEqual([]);
    const refused = await countingRefreshSaves(undeclared, () => refresh(undeclared, issued.rt, issued.keys));
    expect(refused.result.status, JSON.stringify(refused.result.body)).toBe(400);
    expect(refused.result.body.error).toBe("invalid_grant");
    expect(refused.saved).toBe(0);
  });

  it("under an exact-only domain, a partially contained prefix entry is contained whole, and the refresh is refused invalid_grant, saving no refresh token", async () => {
    expect(CEILING.resource_match).toBe("prefix");
    const issued = await issue(exactOnly, [structuredClone(CEILING)]);
    contain(exactOnly, issued.missionId, ["payments:invoice.list"]);
    expect(exactOnly.as.kernel.effectiveAuthoritySet(exactOnly.as.kernel.get(issued.missionId) as never)).toEqual([]);
    const refused = await countingRefreshSaves(exactOnly, () => refresh(exactOnly, issued.rt, issued.keys));
    expect(refused.result.status, JSON.stringify(refused.result.body)).toBe(400);
    expect(refused.result.body.error).toBe("invalid_grant");
    expect(refused.saved).toBe(0);
  });
});
