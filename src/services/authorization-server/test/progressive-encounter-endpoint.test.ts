/**
 * @spec draft-mcguinness-mission-discovery (#encounter, #resource-identity,
 * #adjudication), draft-mcguinness-oauth-mission-progressive (#ceiling-test,
 * #audit-linkage), #1469 stage 1
 *
 * A discovery encounter on the Progressive drawdown path, through the real
 * authorization server. The payments read ceiling is configured `prefix`
 * (#1440), so a drawdown can reach a resource under it that no ceiling entry
 * names: an encounter. Stage 1 detects it from the request's own entries,
 * retrieves the resource's self-declaration through the deployment's port,
 * digests the exact bytes, and records whether the sought actions are
 * declared. Until identity pinning, trusted taint and the floors land (D607),
 * no encounter binds by policy: each falls back to a fresh human approval,
 * whose successor records the digest. Stage 2 pins the encountered resource's
 * identity from the Mission Issuer's own connection, through the deployment's
 * ports, and refuses an unpinnable encounter where the deployment says so.
 * Stage 3 takes the session taint state from the harness through a port the
 * agent does not mediate, counting a missing, stale or unverifiable report as
 * tainted. Stage 4 records the floors, from the deployment's classification and
 * the taint state, and the disclosure content a human approval surface renders,
 * correlated by an encounter_id the approved successor carries.
 */

const hoisted = await vi.hoisted(async () => {
  const { cpSync, mkdtempSync, readFileSync, writeFileSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const { fileURLToPath } = await import("node:url");
  const dir = mkdtempSync(join(tmpdir(), "mission-config-1469-"));
  cpSync(fileURLToPath(new URL("../../../config", import.meta.url)), dir, { recursive: true });
  const file = join(dir, "policy.json");
  const policy = JSON.parse(readFileSync(file, "utf8")) as { ceiling: Record<string, unknown>[] };
  (policy.ceiling[0] as Record<string, unknown>).resource_match = "prefix";
  writeFileSync(file, JSON.stringify(policy, null, 2));
  // Containment pairs a removal with an approved entry exactly, so a prefix
  // ceiling loads only where no containment rule is configured (#1440).
  const containment = join(dir, "containment.json");
  const rules = JSON.parse(readFileSync(containment, "utf8")) as { rules: unknown[] };
  rules.rules = [];
  writeFileSync(containment, JSON.stringify(rules, null, 2));
  const previous = process.env.MISSION_CONFIG_DIR;
  process.env.MISSION_CONFIG_DIR = dir;
  return { dir, previous };
});

import { rmSync } from "node:fs";
import type { Server } from "node:http";
import { CANONICAL_RESOURCE, DERIVATION_POLICY, PROGRESSIVE_PROFILE } from "@mission/demo-data";
import { catalogDigest } from "@mission/core";
import { type CryptoKey, decodeJwt, exportJWK, importJWK, SignJWT, generateKeyPair } from "jose";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { ACCESS_TOKEN_TOKEN_TYPE, TOKEN_EXCHANGE_GRANT_TYPE } from "../src/adapters/continuation-grant.js";
import { DEFERRED_GRANT_TYPE } from "../src/kernel/deferred.js";
import {
  type EncounterDisclosure,
  type EncounterFacts,
  encounterFacts,
  type ProgressiveDrawdownOptions,
  progressiveFromProfile,
  type ResourceConnection,
  type TaintReport,
} from "../src/kernel/progressive.js";
import type { AuthorityEntry, MissionRecord } from "../src/kernel/types.js";
import { ApprovalSessionStore, buildAuthorizationServer, type BuiltAs } from "../src/index.js";
import { FIXTURE_BROWSER_LOGIN, floorApprovalHeaders } from "./approval-fixture.js";

const PORT = 14858;
const ISSUER = `http://localhost:${PORT}`;
const REDIRECT_URI = "http://localhost:9999/cb";
const RESOURCE = CANONICAL_RESOURCE;
const FAR_EXP = "2027-01-01T00:00:00Z";
/** A resource under the payments `prefix` read ceiling that no ceiling entry names. */
const ENCOUNTERED = `${RESOURCE}/vendors/acme`;
const ORIGIN = new URL(RESOURCE).origin;
/** The payments read ceiling entry, configured `prefix`. */
const PREFIX_CEILING = DERIVATION_POLICY.ceiling.filter((e) => e.resource === RESOURCE).slice(0, 1) as unknown as AuthorityEntry[];
const CEILING = { authority_ceiling: PREFIX_CEILING, drawdown_policy: { id: "drawdown-wide", version: "1" } };
const ALICE = { iss: ISSUER, sub: "alice" };

/** The declaration the deployment's port serves for each origin, as the test sets it. */
const declarations = new Map<string, string>();
const declarationOf = (operations: string[]): string => JSON.stringify({ operations });

/**
 * #1469 stage 2: what the deployment's connection to each origin established,
 * and the issuers its domain-authorization mechanism verifies, as the test sets
 * them. Empty, no identity is pinned.
 */
const connections = new Map<string, ResourceConnection>();
const authorizedIssuers = new Set<string>();
/** Issuers the mechanism answers `false` for, as opposed to giving no answer. */
const deniedIssuers = new Set<string>();
/** Whether each port fails outright. */
const failing = { connection: false, issuer: false };
/** The authorization server the encountered resource's metadata names: not this Mission Issuer. */
const VENDOR_AS = "https://auth.vendor.example";
/** Protected Resource Metadata for the encountered origin, pretty-printed so its exact bytes differ from a re-serialization. */
const metadataOf = (doc: Record<string, unknown>): string => JSON.stringify(doc, null, 2);
const METADATA = metadataOf({ resource: ORIGIN, authorization_servers: [VENDOR_AS] });

/**
 * #1469 stage 3: what the harness reports through the deployment's taint port,
 * as the test sets it, and the sessions it was asked about. No report is
 * missing, so tainted.
 */
const harness = {
  report: undefined as unknown,
  fail: false,
  calls: [] as Array<{ missionId: string; clientId: string }>,
  /** Runs inside the port before it answers: a test simulates a slow lookup here. */
  during: undefined as (() => void) | undefined,
};
/** The server's clock runs this far ahead of the system clock; a test advances it to simulate time passing during a lookup. */
const clock = { aheadMs: 0 };
const TAINT_MAX_AGE = 60;
/** An RFC 3339 date-time the given number of seconds ago (negative: in the future). */
const secondsAgo = (n: number): string => new Date(Date.now() - n * 1000).toISOString();

const PUBLISHED = progressiveFromProfile(PROGRESSIVE_PROFILE);
const PROGRESSIVE: ProgressiveDrawdownOptions = {
  ...PUBLISHED.options,
  ceilingOffer: () => CEILING,
  resourceDeclarations: async (origin) => declarations.get(origin),
  resourceMetadata: async (origin) => {
    if (failing.connection) throw new Error("connection failed");
    return connections.get(origin);
  },
  issuerAuthorized: async (origin, issuer) => {
    if (failing.issuer) throw new Error("issuer authorization failed");
    const key = `${origin} ${issuer}`;
    return authorizedIssuers.has(key) ? true : deniedIssuers.has(key) ? false : undefined;
  },
  harnessTaint: async (session) => {
    harness.calls.push(session);
    harness.during?.();
    if (harness.fail) throw new Error("harness unreachable");
    return harness.report as TaintReport | undefined;
  },
  taintMaxAgeSeconds: TAINT_MAX_AGE,
};

type DpopKeys = { privateKey: CryptoKey; publicKey: CryptoKey };
type Client = { id: string; kid: string; key: CryptoKey; dpop: DpopKeys };
let as: BuiltAs;
let server: Server;
let ap: Client;
let verifierSeq = 0;
const approvalSessions = new ApprovalSessionStore();

const entry = (resource: string, actions: string[]): Record<string, unknown> => ({
  type: "mission_resource_access",
  resource,
  actions,
  constraints: { vendors: ["acme"] },
});
const intentJson = (goal: string, targets: string[]): string =>
  JSON.stringify({ intent: { goal, target_resources: targets, expires_at: FAR_EXP } });

async function clientAssertion(): Promise<string> {
  return new SignJWT({})
    .setProtectedHeader({ alg: "ES256", kid: ap.kid })
    .setIssuer(ap.id)
    .setSubject(ap.id)
    .setAudience(ISSUER)
    .setIssuedAt()
    .setExpirationTime("2m")
    .setJti(crypto.randomUUID())
    .sign(ap.key);
}

async function tokenRequest(params: Record<string, string>): Promise<Response> {
  const htu = `${ISSUER}/token`;
  const proof = async (extra: Record<string, unknown> = {}) =>
    new SignJWT({ htu, htm: "POST", ...extra })
      .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: await exportJWK(ap.dpop.publicKey) })
      .setIssuedAt()
      .setJti(crypto.randomUUID())
      .sign(ap.dpop.privateKey);
  const send = async (extra: Record<string, unknown> = {}) =>
    fetch(htu, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", dpop: await proof(extra) },
      body: new URLSearchParams({
        ...params,
        client_assertion: await clientAssertion(),
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      }).toString(),
    });
  let res = await send();
  const nonce = res.headers.get("dpop-nonce");
  if (res.status === 400 && nonce) res = await send({ nonce });
  return res;
}

function cookieHeader(jar: Map<string, string>): string {
  return [...jar.entries()].map(([k, v]) => `${k}=${v}`).join("; ");
}
function storeCookies(res: Response, jar: Map<string, string>): void {
  for (const line of res.headers.getSetCookie()) {
    const [pair] = line.split(";");
    const eq = (pair as string).indexOf("=");
    jar.set((pair as string).slice(0, eq), (pair as string).slice(eq + 1));
  }
}

/** PAR, render the approval page, approve consenting the offered ceiling, code, token: an ACTIVE Mission. */
async function issueMission(): Promise<{ missionId: string; accessToken: string }> {
  const jar = new Map<string, string>();
  const verifier = `encounter-verifier-0123456789-0123456789-0123456789-${verifierSeq++}`;
  const challenge = Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))).toString("base64url");
  const par = await fetch(`${ISSUER}/request`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: ap.id,
      response_type: "code",
      redirect_uri: REDIRECT_URI,
      resource: RESOURCE,
      code_challenge: challenge,
      code_challenge_method: "S256",
      login_hint: "alice",
      mission_intent: intentJson("Pay Acme invoices", [RESOURCE]),
      authorization_details: JSON.stringify([entry(RESOURCE, ["payments:invoice.read"])]),
      client_assertion: await clientAssertion(),
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    }).toString(),
  });
  const parBody = (await par.json()) as { request_uri: string };
  expect(par.status, JSON.stringify(parBody)).toBe(201);
  let res = await fetch(`${ISSUER}/auth?${new URLSearchParams({ client_id: ap.id, request_uri: parBody.request_uri })}`, {
    redirect: "manual",
  });
  storeCookies(res, jar);
  const uid = (res.headers.get("location") as string).split("/interaction/")[1] as string;
  expect((await fetch(`${ISSUER}/interaction/${uid}`, { headers: { cookie: cookieHeader(jar) } })).status).toBe(200);
  res = await fetch(`${ISSUER}/interaction/${uid}/decide`, {
    method: "POST",
    redirect: "manual",
    headers: { ...floorApprovalHeaders(approvalSessions, uid, cookieHeader(jar)), "content-type": "application/json" },
    body: JSON.stringify({ decision: "approve", ...CEILING }),
  });
  storeCookies(res, jar);
  let location = res.headers.get("location") as string;
  while (location?.startsWith(ISSUER)) {
    res = await fetch(location, { redirect: "manual", headers: { cookie: cookieHeader(jar) } });
    storeCookies(res, jar);
    location = res.headers.get("location") as string;
  }
  const code = new URL(location).searchParams.get("code") as string;
  const tok = await tokenRequest({ grant_type: "authorization_code", code, redirect_uri: REDIRECT_URI, code_verifier: verifier, resource: RESOURCE });
  const body = (await tok.json()) as { access_token: string };
  expect(tok.status, JSON.stringify(body)).toBe(200);
  const claims = decodeJwt(body.access_token) as { mission: { id: string } };
  return { missionId: claims.mission.id, accessToken: body.access_token };
}

/** An expansion token exchange: the predecessor's read plus `extra` entries, with optional encounter hints. */
function expansion(subjectToken: string, extra: Record<string, unknown>[], hints: Record<string, string> = {}): Record<string, string> {
  const targets = [RESOURCE, ...extra.map((e) => e.resource as string).filter((r) => r !== RESOURCE)];
  return {
    grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
    subject_token: subjectToken,
    subject_token_type: ACCESS_TOKEN_TOKEN_TYPE,
    requested_token_type: ACCESS_TOKEN_TOKEN_TYPE,
    creation_request_id: crypto.randomUUID(),
    completion_mode: "deferred",
    mission_intent: intentJson("Read the vendor's invoices", targets),
    authorization_details: JSON.stringify([entry(RESOURCE, ["payments:invoice.read"]), ...extra]),
    ...hints,
  };
}

/** Approve a deferral (no re-consent) and complete it by the deferred poll. */
async function approveAndPoll(code: string): Promise<{ access_token: string; mission_id: string }> {
  as.expansionDeferrals.approve(code, {
    approver: ALICE,
    authentication: FIXTURE_BROWSER_LOGIN,
    approvalEventId: `apev-${crypto.randomUUID()}`,
    approvedUntil: FAR_EXP,
  });
  const res = await tokenRequest({ grant_type: DEFERRED_GRANT_TYPE, deferral_code: code });
  const body = (await res.json()) as { access_token: string; mission_id: string };
  expect(res.status, JSON.stringify(body)).toBe(200);
  return body;
}

beforeAll(async () => {
  as = await buildAuthorizationServer({
    issuer: ISSUER,
    approvalSessions,
    activationPolicies: PUBLISHED.policies,
    progressive: PROGRESSIVE,
    now: () => new Date(Date.now() + clock.aheadMs),
  });
  server = as.provider.listen(PORT);
  await new Promise<void>((r) => server.once("listening", () => r()));
  ap = {
    id: "ap-agent",
    kid: "ap-agent-auth",
    key: (await importJWK(as.agentClientJwk as never, "ES256")) as CryptoKey,
    dpop: await generateKeyPair("ES256", { extractable: true }),
  };
});

afterAll(async () => {
  await new Promise<void>((r) => server.close(() => r()));
  if (hoisted.previous === undefined) delete process.env.MISSION_CONFIG_DIR;
  else process.env.MISSION_CONFIG_DIR = hoisted.previous;
  rmSync(hoisted.dir, { recursive: true, force: true });
});

describe("a discovery encounter on the drawdown path, stage 1 (@spec discovery#adjudication, discovery#resource-identity, progressive#ceiling-test, #1469)", () => {
  it("a drawdown onto a resource no ceiling entry names falls back to a fresh human approval though every other guard would admit it", async () => {
    declarations.set(ORIGIN, declarationOf(["payments:invoice.read"]));
    const root = await issueMission();
    // Control: a widening on the named resource is adjudicated by policy.
    const named = await tokenRequest(expansion(root.accessToken, [entry(RESOURCE, ["payments:invoice.list"])]));
    expect(named.status, await named.clone().text()).toBe(200);
    const successor = (await named.json()) as { access_token: string; mission_id: string };
    // The same predecessor's encounter, no hint: a fresh human approval.
    const before = as.kernel.allMissions().length;
    const res = await tokenRequest(expansion(successor.access_token, [entry(ENCOUNTERED, ["payments:invoice.read"])]));
    const body = (await res.json()) as { error?: string; deferral_code?: string };
    expect(res.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("authorization_pending");
    expect(as.kernel.allMissions().length).toBe(before);
    const disclosure = as.expansionDeferrals.disclosure(body.deferral_code as string);
    expect(disclosure?.drawdown_fallback).toBe("encounter");
    expect(disclosure?.encounter).toMatchObject({ origin: ORIGIN, resources: [ENCOUNTERED] });
    expect(disclosure?.encounter?.hint).toBeUndefined();
  });

  it("the declaration digest is the Mission Issuer's own, over the bytes it retrieved; the agent's hint is kept as its claim, and the human-approved successor records the digest", async () => {
    const served = declarationOf(["payments:invoice.read"]);
    declarations.set(ORIGIN, served);
    const root = await issueMission();
    const forged = "sha-256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const res = await tokenRequest(
      expansion(root.accessToken, [entry(ENCOUNTERED, ["payments:invoice.read"])], {
        encountered_resource: JSON.stringify({ origin: ORIGIN }),
        resource_declaration_digest: forged,
      }),
    );
    const body = (await res.json()) as { error?: string; deferral_code?: string };
    expect(body.error, JSON.stringify(body)).toBe("authorization_pending");
    const encounter = as.expansionDeferrals.disclosure(body.deferral_code as string)?.encounter;
    expect(encounter?.declaration_digest).toBe(catalogDigest(served));
    expect(encounter?.declared).toBe(true);
    expect(encounter?.hint).toEqual({ origin: ORIGIN, resource_declaration_digest: forged, digest_matched: false });
    const approved = await approveAndPoll(body.deferral_code as string);
    expect((as.kernel.get(approved.mission_id) as MissionRecord).resource_declaration_digest).toBe(catalogDigest(served));
  });

  it("with no declaration retrievable, nothing is digested or recorded, whatever digest the agent's hint carries", async () => {
    declarations.delete(ORIGIN);
    const root = await issueMission();
    const res = await tokenRequest(
      expansion(root.accessToken, [entry(ENCOUNTERED, ["payments:invoice.read"])], {
        encountered_resource: JSON.stringify({ origin: ORIGIN }),
        resource_declaration_digest: catalogDigest(declarationOf(["payments:invoice.read"])),
      }),
    );
    const body = (await res.json()) as { error?: string; deferral_code?: string };
    expect(body.error, JSON.stringify(body)).toBe("authorization_pending");
    const encounter = as.expansionDeferrals.disclosure(body.deferral_code as string)?.encounter;
    expect(encounter?.declaration_digest).toBeUndefined();
    expect(encounter?.declared).toBeUndefined();
    const approved = await approveAndPoll(body.deferral_code as string);
    expect((as.kernel.get(approved.mission_id) as MissionRecord).resource_declaration_digest).toBeUndefined();
  });

  it("an action the declaration does not list is recorded as undeclared", async () => {
    declarations.set(ORIGIN, declarationOf(["payments:invoice.list"]));
    const root = await issueMission();
    const res = await tokenRequest(expansion(root.accessToken, [entry(ENCOUNTERED, ["payments:invoice.read"])]));
    const body = (await res.json()) as { error?: string; deferral_code?: string };
    expect(body.error, JSON.stringify(body)).toBe("authorization_pending");
    expect(as.expansionDeferrals.disclosure(body.deferral_code as string)?.encounter?.declared).toBe(false);
  });

  it("an encountered_resource that is not an origin object or names no resource the request seeks, and a digest hint without one, are refused invalid_request", async () => {
    declarations.set(ORIGIN, declarationOf(["payments:invoice.read"]));
    const root = await issueMission();
    const before = as.kernel.allMissions().length;
    for (const [hints, reason] of [
      [{ encountered_resource: "not json" }, "encountered_resource is not a JSON object"],
      [{ encountered_resource: JSON.stringify({ origin: `${ORIGIN}/path` }) }, "encountered_resource needs an origin"],
      [
        { encountered_resource: JSON.stringify({ origin: "https://elsewhere.example" }) },
        "the encountered resource names no resource the request seeks",
      ],
      [{ resource_declaration_digest: catalogDigest("x") }, "resource_declaration_digest rides only with encountered_resource"],
    ] as const) {
      const res = await tokenRequest(expansion(root.accessToken, [entry(ENCOUNTERED, ["payments:invoice.read"])], hints));
      const body = (await res.json()) as { error?: string; error_description?: string };
      expect(res.status, JSON.stringify(hints)).toBe(400);
      expect(body.error, JSON.stringify(hints)).toBe("invalid_request");
      // Each refusal is its own check's, so each is proved alone.
      expect(body.error_description, JSON.stringify(hints)).toBe(reason);
    }
    expect(as.kernel.allMissions().length).toBe(before);
  });
});

describe("the encounter's hint names the encounter's own origin (@spec discovery#resource-identity, #1469)", () => {
  // The endpoint config has one origin; a request whose entries span two
  // reaches this through any deployment with more than one resource origin.
  const OTHER = "https://other.example/api";
  const requested = [entry(ENCOUNTERED, ["payments:invoice.read"]), entry(OTHER, ["read"])] as unknown as AuthorityEntry[];

  it("a hint naming another origin the request seeks is refused, so its digest is never compared with a different resource's declaration", async () => {
    declarations.set(ORIGIN, declarationOf(["payments:invoice.read"]));
    const digest = catalogDigest(declarationOf(["payments:invoice.read"]));
    const session = { missionId: "msn_unit", clientId: "ap-agent", now: () => new Date() };
    const facts = await encounterFacts(
      PROGRESSIVE,
      [ENCOUNTERED],
      requested,
      { origin: new URL(OTHER).origin, resource_declaration_digest: digest },
      session,
    );
    expect(facts).toBe("encountered_resource names an origin other than the encounter's");
    // Control: the same hint naming the encounter's origin is recorded, its digest compared.
    const control = await encounterFacts(
      PROGRESSIVE,
      [ENCOUNTERED],
      requested,
      { origin: ORIGIN, resource_declaration_digest: digest },
      session,
    );
    expect(control).toMatchObject({ origin: ORIGIN, hint: { origin: ORIGIN, digest_matched: true } });
  });
});

describe("the encountered resource's identity, pinned from the Mission Issuer's own connection (@spec discovery#resource-identity, discovery#adjudication, #1469 stage 2)", () => {
  beforeEach(() => {
    connections.clear();
    authorizedIssuers.clear();
    deniedIssuers.clear();
    declarations.clear();
    failing.connection = false;
    failing.issuer = false;
  });

  /** An encounter at ENCOUNTERED from a fresh Mission: the response and, when one opened, the deferral's encounter facts. */
  async function encounter(hints: Record<string, string> = {}) {
    const root = await issueMission();
    const res = await tokenRequest(expansion(root.accessToken, [entry(ENCOUNTERED, ["payments:invoice.read"])], hints));
    const body = (await res.json()) as { error?: string; error_description?: string; deferral_code?: string };
    const disclosure = body.deferral_code ? as.expansionDeferrals.disclosure(body.deferral_code) : undefined;
    return { status: res.status, body, disclosure, facts: disclosure?.encounter as EncounterFacts | undefined };
  }

  /** Run with the deployment's unpinned-encounter policy set, restoring it after. */
  async function underPolicy<T>(policy: "fresh_approval" | "refuse", run: () => Promise<T>): Promise<T> {
    const previous = PROGRESSIVE.unpinnedEncounter;
    PROGRESSIVE.unpinnedEncounter = policy;
    try {
      return await run();
    } finally {
      if (previous === undefined) delete PROGRESSIVE.unpinnedEncounter;
      else PROGRESSIVE.unpinnedEncounter = previous;
    }
  }

  const deferralCount = (): number =>
    (as.expansionDeferrals.db.prepare("SELECT COUNT(*) AS n FROM expansion_deferrals").get() as { n: number }).n;

  it("pins the TLS-authenticated origin, the digest of the metadata's exact bytes and the one issuer it names, verified for the domain; the encounter still routes to a human", async () => {
    connections.set(ORIGIN, { tls_authenticated: true, metadata: METADATA });
    authorizedIssuers.add(`${ORIGIN} ${VENDOR_AS}`);
    const { body, disclosure, facts } = await encounter();
    expect(body.error, JSON.stringify(body)).toBe("authorization_pending");
    expect(disclosure?.drawdown_fallback).toBe("encounter");
    expect(facts?.pinned).toBe(true);
    expect(facts?.pin_failure).toBeUndefined();
    expect(facts?.resource).toEqual({ origin: ORIGIN, resource_metadata_digest: catalogDigest(METADATA), issuer: VENDOR_AS });
    // The exact bytes retrieved, not a re-serialization of them.
    expect(catalogDigest(METADATA)).not.toBe(catalogDigest(JSON.stringify(JSON.parse(METADATA))));
    // The same server listed twice still names one issuer.
    const twice = metadataOf({ resource: ORIGIN, authorization_servers: [VENDOR_AS, VENDOR_AS] });
    connections.set(ORIGIN, { tls_authenticated: true, metadata: twice });
    const listedTwice = (await encounter()).facts;
    expect(listedTwice?.pinned).toBe(true);
    expect(listedTwice?.resource).toEqual({ origin: ORIGIN, resource_metadata_digest: catalogDigest(twice), issuer: VENDOR_AS });
  });

  it("an origin the connection did not TLS-authenticate is not pinned, and nothing retrieved over that connection is used", async () => {
    connections.set(ORIGIN, { tls_authenticated: false, metadata: METADATA });
    authorizedIssuers.add(`${ORIGIN} ${VENDOR_AS}`);
    const { body, facts } = await encounter();
    expect(body.error, JSON.stringify(body)).toBe("authorization_pending");
    expect(facts).toMatchObject({ pinned: false, pin_failure: "origin_unauthenticated" });
    expect(facts?.resource).toBeUndefined();
  });

  it("metadata that is absent, not a JSON object, or whose resource is not exactly the origin (RFC 9728 Section 3.3) is not used: no digest, no issuer", async () => {
    authorizedIssuers.add(`${ORIGIN} ${VENDOR_AS}`);
    for (const [metadata, failure] of [
      [undefined, "metadata_unavailable"],
      ["not json", "metadata_invalid"],
      [metadataOf({ resource: `${ORIGIN}/`, authorization_servers: [VENDOR_AS] }), "metadata_invalid"],
      [metadataOf({ resource: ENCOUNTERED, authorization_servers: [VENDOR_AS] }), "metadata_invalid"],
    ] as const) {
      connections.set(ORIGIN, { tls_authenticated: true, ...(metadata === undefined ? {} : { metadata }) });
      const { facts } = await encounter();
      expect(facts, String(metadata)).toMatchObject({ pinned: false, pin_failure: failure });
      expect(facts?.resource, String(metadata)).toEqual({ origin: ORIGIN });
    }
  });

  it("metadata naming an authorization server by anything but an issuer identifier (an https URL with no query or fragment, RFC 8414 Section 2) is not used, even where the domain would authorize it, and is refused where the deployment refuses unpinnable encounters", async () => {
    const malformed = [
      "not-an-issuer-url",
      "http://auth.vendor.example",
      `${VENDOR_AS}?tenant=1`,
      `${VENDOR_AS}?`,
      `${VENDOR_AS}#frag`,
      `${VENDOR_AS}#`,
    ];
    for (const issuer of malformed) {
      // The deployment's mechanism would authorize it: syntax is checked first, and authorization does not repair it.
      authorizedIssuers.add(`${ORIGIN} ${issuer}`);
      connections.set(ORIGIN, { tls_authenticated: true, metadata: metadataOf({ resource: ORIGIN, authorization_servers: [issuer] }) });
      const { body, facts } = await encounter();
      expect(body.error, issuer).toBe("authorization_pending");
      expect(facts, issuer).toMatchObject({ pinned: false, pin_failure: "metadata_invalid" });
      expect(facts?.resource, issuer).toEqual({ origin: ORIGIN });
    }
    await underPolicy("refuse", async () => {
      for (const issuer of malformed) {
        connections.set(ORIGIN, { tls_authenticated: true, metadata: metadataOf({ resource: ORIGIN, authorization_servers: [issuer] }) });
        const deferrals = deferralCount();
        const { status, body } = await encounter();
        expect(status, issuer).toBe(400);
        expect(body, issuer).toEqual({ error: "invalid_request", error_description: "the encounter is refused" });
        expect(deferralCount(), issuer).toBe(deferrals);
      }
    });
  });

  it("metadata naming no authorization server, or more than one, pins no issuer", async () => {
    authorizedIssuers.add(`${ORIGIN} ${VENDOR_AS}`);
    for (const [servers, failure] of [
      [[], "issuer_unnamed"],
      [[VENDOR_AS, "https://auth.other.example"], "issuer_ambiguous"],
    ] as const) {
      const metadata = metadataOf({ resource: ORIGIN, authorization_servers: servers });
      connections.set(ORIGIN, { tls_authenticated: true, metadata });
      const { facts } = await encounter();
      expect(facts, failure).toMatchObject({ pinned: false, pin_failure: failure });
      expect(facts?.resource, failure).toEqual({ origin: ORIGIN, resource_metadata_digest: catalogDigest(metadata) });
    }
  });

  it("a named issuer not verified as authorized for the domain is not pinned, and the encounter routes to a human even where the deployment refuses unpinnable encounters", async () => {
    connections.set(ORIGIN, { tls_authenticated: true, metadata: METADATA });
    await underPolicy("refuse", async () => {
      // The mechanism gives no answer, answers false, or fails: none verifies the issuer.
      for (const answer of ["none", "false", "failure"] as const) {
        deniedIssuers.clear();
        failing.issuer = answer === "failure";
        if (answer === "false") deniedIssuers.add(`${ORIGIN} ${VENDOR_AS}`);
        const { body, facts } = await encounter();
        expect(body.error, answer).toBe("authorization_pending");
        expect(facts, answer).toMatchObject({ pinned: false, pin_failure: "issuer_unverified" });
        expect(facts?.resource, answer).toEqual({ origin: ORIGIN, resource_metadata_digest: catalogDigest(METADATA), issuer: VENDOR_AS });
      }
    });
  });

  it("a connection port that fails establishes nothing: the origin is not pinned", async () => {
    connections.set(ORIGIN, { tls_authenticated: true, metadata: METADATA });
    authorizedIssuers.add(`${ORIGIN} ${VENDOR_AS}`);
    failing.connection = true;
    const { body, facts } = await encounter();
    expect(body.error, JSON.stringify(body)).toBe("authorization_pending");
    expect(facts).toMatchObject({ pinned: false, pin_failure: "origin_unauthenticated" });
    expect(facts?.resource).toBeUndefined();
  });

  it("where the deployment refuses unpinnable encounters, an encounter whose identity cannot be established is refused uniformly, with no deferral and no Mission; a pinned one still routes to a human", async () => {
    await underPolicy("refuse", async () => {
      for (const connection of [
        undefined,
        { tls_authenticated: false, metadata: METADATA },
        { tls_authenticated: true },
        { tls_authenticated: true, metadata: metadataOf({ resource: ORIGIN, authorization_servers: [] }) },
      ] as const) {
        connections.clear();
        if (connection) connections.set(ORIGIN, connection);
        const missions = as.kernel.allMissions().length;
        const deferrals = deferralCount();
        const { status, body } = await encounter();
        expect(status, JSON.stringify(connection)).toBe(400);
        expect(body, JSON.stringify(connection)).toEqual({ error: "invalid_request", error_description: "the encounter is refused" });
        // issueMission created the predecessor; the refused encounter created nothing.
        expect(as.kernel.allMissions().length, JSON.stringify(connection)).toBe(missions + 1);
        expect(deferralCount(), JSON.stringify(connection)).toBe(deferrals);
      }
      connections.set(ORIGIN, { tls_authenticated: true, metadata: METADATA });
      authorizedIssuers.add(`${ORIGIN} ${VENDOR_AS}`);
      const { body, facts } = await encounter();
      expect(body.error, JSON.stringify(body)).toBe("authorization_pending");
      expect(facts?.pinned).toBe(true);
    });
  });

  it("the agent's issuer and metadata digest are recorded as its claims and compared, never adopted", async () => {
    const forged = { resource_metadata_digest: catalogDigest("forged"), issuer: "https://auth.forged.example" };
    const hints = { encountered_resource: JSON.stringify({ origin: ORIGIN, ...forged }) };
    // Pinned: the Mission Issuer's own values stand, and the claims are recorded as not matching.
    connections.set(ORIGIN, { tls_authenticated: true, metadata: METADATA });
    authorizedIssuers.add(`${ORIGIN} ${VENDOR_AS}`);
    authorizedIssuers.add(`${ORIGIN} ${forged.issuer}`);
    const pinned = (await encounter(hints)).facts;
    expect(pinned?.resource).toEqual({ origin: ORIGIN, resource_metadata_digest: catalogDigest(METADATA), issuer: VENDOR_AS });
    expect(pinned?.hint).toEqual({ origin: ORIGIN, ...forged, resource_metadata_digest_matched: false, issuer_matched: false });
    // Matching claims are recorded as matching.
    const honest = { resource_metadata_digest: catalogDigest(METADATA), issuer: VENDOR_AS };
    const matched = (await encounter({ encountered_resource: JSON.stringify({ origin: ORIGIN, ...honest }) })).facts;
    expect(matched?.hint).toMatchObject({ resource_metadata_digest_matched: true, issuer_matched: true });
    // Unpinned: the claims fill nothing in.
    connections.clear();
    const unpinned = (await encounter(hints)).facts;
    expect(unpinned).toMatchObject({ pinned: false, pin_failure: "origin_unauthenticated" });
    expect(unpinned?.resource).toBeUndefined();
    expect(unpinned?.hint).toEqual({ origin: ORIGIN, ...forged });
  });

  it("an encountered_resource whose issuer or metadata digest is not a string is refused invalid_request", async () => {
    for (const member of [{ issuer: 5 }, { resource_metadata_digest: ["x"] }]) {
      const { status, body } = await encounter({ encountered_resource: JSON.stringify({ origin: ORIGIN, ...member }) });
      expect(status, JSON.stringify(member)).toBe(400);
      expect(body, JSON.stringify(member)).toMatchObject({
        error: "invalid_request",
        error_description: "encountered_resource members are strings",
      });
    }
  });

  it("refusing unpinnable encounters without a connection port is a configuration error, before the server starts", async () => {
    await expect(
      buildAuthorizationServer({
        issuer: "http://localhost:1",
        progressive: { ...PROGRESSIVE, unpinnedEncounter: "refuse", resourceMetadata: undefined },
      }),
    ).rejects.toThrow("progressive unpinnedEncounter refuse needs a resourceMetadata port");
  });
});

describe("the session taint state, from the harness through a channel the agent does not mediate (@spec discovery#adjudication, #1469 stage 3)", () => {
  beforeEach(() => {
    harness.report = undefined;
    harness.fail = false;
    harness.calls.length = 0;
    harness.during = undefined;
    clock.aheadMs = 0;
  });

  /** An encounter at ENCOUNTERED from a fresh Mission, with optional hints and extra request parameters. */
  async function encounter(hints: Record<string, string> = {}, extra: Record<string, string> = {}) {
    const root = await issueMission();
    const res = await tokenRequest({ ...expansion(root.accessToken, [entry(ENCOUNTERED, ["payments:invoice.read"])], hints), ...extra });
    const body = (await res.json()) as { error?: string; deferral_code?: string };
    const facts = body.deferral_code ? (as.expansionDeferrals.disclosure(body.deferral_code)?.encounter as EncounterFacts | undefined) : undefined;
    return { missionId: root.missionId, body, facts };
  }

  it("a fresh, session-scoped report is believed, tainted or not, and recorded apart from the effective state; the encounter still routes to a human", async () => {
    for (const report of [
      { tainted: false, granularity: "session", reported_at: secondsAgo(5) },
      { tainted: true, granularity: "session", source_class: "web_fetch", reported_at: secondsAgo(5) },
    ]) {
      harness.report = report;
      const { body, facts } = await encounter();
      expect(body.error, JSON.stringify(report)).toBe("authorization_pending");
      expect(facts?.tainted, JSON.stringify(report)).toBe(report.tainted);
      expect(facts?.taint_failure, JSON.stringify(report)).toBeUndefined();
      expect(facts?.taint_report, JSON.stringify(report)).toEqual(report);
    }
  });

  it("a missing report counts as tainted: no harness port, no answer, or a failing port", async () => {
    const port = PROGRESSIVE.harnessTaint;
    try {
      delete PROGRESSIVE.harnessTaint;
      const none = (await encounter()).facts;
      expect(none).toMatchObject({ tainted: true, taint_failure: "missing" });
      expect(none?.taint_report).toBeUndefined();
    } finally {
      PROGRESSIVE.harnessTaint = port;
    }
    const unanswered = (await encounter()).facts;
    expect(unanswered).toMatchObject({ tainted: true, taint_failure: "missing" });
    harness.fail = true;
    const failed = (await encounter()).facts;
    expect(failed).toMatchObject({ tainted: true, taint_failure: "missing" });
    expect(failed?.taint_report).toBeUndefined();
  });

  it("a report older than the deployment's bound counts as tainted, an untainted one included", async () => {
    for (const tainted of [false, true]) {
      const report = { tainted, granularity: "session", reported_at: secondsAgo(TAINT_MAX_AGE * 2) };
      harness.report = report;
      const { facts } = await encounter();
      expect(facts, String(tainted)).toMatchObject({ tainted: true, taint_failure: "stale" });
      expect(facts?.taint_report, String(tainted)).toEqual(report);
    }
  });

  it("a report that is malformed, future-dated or not session-scoped is unverifiable and counts as tainted", async () => {
    const fresh = { tainted: false, granularity: "session", reported_at: secondsAgo(5) };
    for (const report of [
      { ...fresh, tainted: "false" },
      { ...fresh, granularity: "parameter" },
      { tainted: false, reported_at: secondsAgo(5) },
      { ...fresh, source_class: 5 },
      { ...fresh, reported_at: "yesterday" },
      // Date.parse accepts these; RFC 3339 does not.
      { ...fresh, reported_at: new Date(Date.now() - 5000).toUTCString() },
      { ...fresh, reported_at: secondsAgo(5).slice(0, 10) },
      { tainted: false, granularity: "session" },
      { ...fresh, reported_at: secondsAgo(-TAINT_MAX_AGE) },
      "untainted",
      [fresh],
    ] as unknown[]) {
      harness.report = report;
      const { body, facts } = await encounter();
      expect(body.error, JSON.stringify(report)).toBe("authorization_pending");
      expect(facts, JSON.stringify(report)).toMatchObject({ tainted: true, taint_failure: "unverifiable" });
    }
  });

  it("freshness is judged when the report arrives, after the lookups: a report fresh when asked but past the bound by then is stale, and one the harness made during a slow lookup is not future-dated", async () => {
    try {
      // A 120-second lookup: the report was 5 seconds old when asked for, 125 when it arrived.
      harness.report = { tainted: false, granularity: "session", reported_at: secondsAgo(5) };
      harness.during = () => {
        clock.aheadMs += 120_000;
      };
      const late = (await encounter()).facts;
      expect(late).toMatchObject({ tainted: true, taint_failure: "stale" });
      // The harness made its report 90 seconds into a 120-second lookup: 30 seconds old on arrival.
      clock.aheadMs = 0;
      harness.during = () => {
        clock.aheadMs += 120_000;
        harness.report = { tainted: false, granularity: "session", reported_at: secondsAgo(-90) };
      };
      const during = (await encounter()).facts;
      expect(during?.tainted).toBe(false);
      expect(during?.taint_failure).toBeUndefined();
    } finally {
      clock.aheadMs = 0;
    }
  });

  it("the agent cannot supply the taint state: a tainted=false parameter and a tainted member in its hint change nothing, and the harness is asked about the subject token's Mission and the authenticated client", async () => {
    harness.report = { tainted: true, granularity: "session", source_class: "inbound_message", reported_at: secondsAgo(5) };
    const { missionId, body, facts } = await encounter(
      { encountered_resource: JSON.stringify({ origin: ORIGIN, tainted: false }) },
      { tainted: "false", taint: JSON.stringify({ tainted: false, granularity: "session" }) },
    );
    expect(body.error, JSON.stringify(body)).toBe("authorization_pending");
    expect(facts).toMatchObject({ tainted: true });
    expect(facts?.taint_failure).toBeUndefined();
    expect(facts?.hint).toEqual({ origin: ORIGIN });
    expect(JSON.stringify(facts)).not.toContain('"tainted":false');
    expect(harness.calls).toEqual([{ missionId, clientId: "ap-agent" }]);
  });

  it("the harness is asked only on an encounter: a named widening drawn by policy never consults it", async () => {
    const root = await issueMission();
    const named = await tokenRequest(expansion(root.accessToken, [entry(RESOURCE, ["payments:invoice.list"])]));
    expect(named.status, await named.clone().text()).toBe(200);
    expect(harness.calls).toEqual([]);
  });

  it("a harness port without a freshness bound, or a bound that is not a positive integer, is a configuration error before the server starts", async () => {
    for (const [taintMaxAgeSeconds, message] of [
      [undefined, "progressive harnessTaint needs taintMaxAgeSeconds"],
      [0, "progressive taintMaxAgeSeconds must be a positive integer"],
      [1.5, "progressive taintMaxAgeSeconds must be a positive integer"],
    ] as const) {
      await expect(
        buildAuthorizationServer({ issuer: "http://localhost:1", progressive: { ...PROGRESSIVE, taintMaxAgeSeconds } }),
        String(taintMaxAgeSeconds),
      ).rejects.toThrow(message);
    }
  });
});

describe("the floors and the human-path disclosure (@spec discovery#lying-resource, discovery#injection-discovery, discovery#adjudication, #1469 stage 4)", () => {
  const FRESH_UNTAINTED = () => ({ tainted: false, granularity: "session", reported_at: secondsAgo(5) });
  beforeEach(() => {
    harness.report = FRESH_UNTAINTED();
    harness.fail = false;
    harness.calls.length = 0;
    harness.during = undefined;
    connections.clear();
    authorizedIssuers.clear();
    declarations.clear();
  });

  /** An encounter seeking `action` at ENCOUNTERED from a fresh Mission. */
  async function encounter(action: string) {
    const root = await issueMission();
    const res = await tokenRequest(expansion(root.accessToken, [entry(ENCOUNTERED, [action])]));
    const body = (await res.json()) as { error?: string; deferral_code?: string };
    const disclosure = body.deferral_code ? as.expansionDeferrals.disclosure(body.deferral_code) : undefined;
    return {
      body,
      code: body.deferral_code,
      fallback: disclosure?.drawdown_fallback,
      facts: disclosure?.encounter as EncounterFacts | undefined,
      shown: disclosure?.encounter_disclosure as EncounterDisclosure | undefined,
    };
  }

  /** Run with the deployment's classification of some actions changed (undefined: unclassified), restoring it after. */
  async function withClasses<T>(changes: Record<string, string | undefined>, run: () => Promise<T>): Promise<T> {
    const previous = PROGRESSIVE.actionClasses;
    const next: Record<string, string> = { ...previous };
    for (const [action, cls] of Object.entries(changes)) {
      if (cls === undefined) delete next[action];
      else next[action] = cls;
    }
    PROGRESSIVE.actionClasses = next as ProgressiveDrawdownOptions["actionClasses"];
    try {
      return await run();
    } finally {
      PROGRESSIVE.actionClasses = previous;
    }
  }

  it("the classes sought come from the deployment's classification; an encounter no floor touches records none, and still routes to a human", async () => {
    const { body, fallback, facts } = await encounter("payments:invoice.read");
    expect(body.error, JSON.stringify(body)).toBe("authorization_pending");
    expect(fallback).toBe("encounter");
    expect(facts?.sought_classes).toEqual(["consequential_read"]);
    expect(facts?.floors).toEqual([]);
  });

  it("each high-consequence class is a floor: irreversible, external-commitment and privileged-administration authority each require a human", async () => {
    for (const cls of ["irreversible_action", "external_commitment", "privileged_administration"]) {
      await withClasses({ "payments:invoice.list": cls }, async () => {
        const { body, facts } = await encounter("payments:invoice.list");
        expect(body.error, cls).toBe("authorization_pending");
        expect(facts?.sought_classes, cls).toEqual([cls]);
        expect(facts?.floors, cls).toEqual([cls]);
      });
    }
  });

  it("an action the deployment's classification cannot assign a class is a floor", async () => {
    await withClasses({ "payments:invoice.list": undefined }, async () => {
      const { body, facts } = await encounter("payments:invoice.list");
      expect(body.error).toBe("authorization_pending");
      expect(facts?.sought_classes).toEqual([]);
      expect(facts?.floors).toEqual(["unclassified"]);
    });
  });

  it("an action satisfying the external-communication predicate is a floor, whatever its class", async () => {
    const { body, facts } = await encounter("payments:vendor.read");
    expect(body.error).toBe("authorization_pending");
    expect(facts?.sought_classes).toEqual(["consequential_read"]);
    expect(facts?.floors).toEqual(["external_communication"]);
  });

  it("under taint every encounter meets the taint floor, whatever its class; the disclosure says untrusted content was ingested only when the harness reported it", async () => {
    for (const [report, floors, statement] of [
      [{ tainted: true, granularity: "session", reported_at: secondsAgo(5) }, ["tainted"], "untrusted_content_ingested"],
      [{ tainted: true, granularity: "session", reported_at: secondsAgo(TAINT_MAX_AGE * 2) }, ["tainted"], "untrusted_content_ingested"],
      [undefined, ["tainted"], "taint_state_unknown"],
      [{ tainted: false, granularity: "session", reported_at: secondsAgo(TAINT_MAX_AGE * 2) }, ["tainted"], "taint_state_unknown"],
      [{ tainted: false, granularity: "session", reported_at: secondsAgo(5) }, [], "no_untrusted_content_reported"],
    ] as const) {
      harness.report = report;
      const { body, facts, shown } = await encounter("payments:invoice.read");
      expect(body.error, JSON.stringify(report)).toBe("authorization_pending");
      expect(facts?.floors, JSON.stringify(report)).toEqual(floors);
      expect(shown?.taint, JSON.stringify(report)).toBe(statement);
    }
  });

  it("a declaration never classifies: one that relaxes a class, or makes one stricter, changes neither the classes nor the floors", async () => {
    await withClasses({ "payments:invoice.list": "irreversible_action" }, async () => {
      declarations.set(
        ORIGIN,
        JSON.stringify({ operations: ["payments:invoice.list"], classes: { "payments:invoice.list": "non_consequential" } }),
      );
      const relaxed = (await encounter("payments:invoice.list")).facts;
      expect(relaxed?.sought_classes).toEqual(["irreversible_action"]);
      expect(relaxed?.floors).toEqual(["irreversible_action"]);
    });
    declarations.set(
      ORIGIN,
      JSON.stringify({ operations: ["payments:invoice.read"], classes: { "payments:invoice.read": "irreversible_action" } }),
    );
    const stricter = (await encounter("payments:invoice.read")).facts;
    expect(stricter?.sought_classes).toEqual(["consequential_read"]);
    expect(stricter?.floors).toEqual([]);
  });

  it("the disclosure renders the Encountered Resource object, the declaration as the resource's claim, and the taint status, correlated by the encounter_id the approved successor carries", async () => {
    connections.set(ORIGIN, { tls_authenticated: true, metadata: METADATA });
    authorizedIssuers.add(`${ORIGIN} ${VENDOR_AS}`);
    const declaration = declarationOf(["payments:invoice.read", "payments:invoice.list"]);
    declarations.set(ORIGIN, declaration);
    const { code, facts, shown } = await encounter("payments:invoice.read");
    expect(facts?.encounter_id).toMatch(/^enc_[A-Za-z0-9_-]{24}$/);
    expect(shown).toEqual({
      encounter_id: facts?.encounter_id,
      resource: { origin: ORIGIN, resource_metadata_digest: catalogDigest(METADATA), issuer: VENDOR_AS },
      pinned: true,
      declaration: {
        claimed_by_resource: true,
        digest: catalogDigest(declaration),
        operations: ["payments:invoice.read", "payments:invoice.list"],
      },
      taint: "no_untrusted_content_reported",
      floors: [],
    });
    const approved = await approveAndPoll(code as string);
    expect((as.kernel.get(approved.mission_id) as MissionRecord).encounter_id).toBe(facts?.encounter_id);
  });

  it("an encounter stored before trusted taint and the floors is disclosed with its taint state unknown, claiming no floors, id or pinning, never as untainted", async () => {
    const { code, facts } = await encounter("payments:invoice.read");
    expect(as.expansionDeferrals.disclosure(code as string)?.encounter_disclosure?.taint).toBe("no_untrusted_content_reported");
    // The facts stage 2 stored (identity pinning, no taint or floors), then those stage 1 stored (intake only).
    for (const stored of [
      { origin: facts?.origin, resources: facts?.resources, pinned: false, pin_failure: "origin_unauthenticated" },
      { origin: facts?.origin, resources: facts?.resources },
    ]) {
      as.expansionDeferrals.db
        .prepare("UPDATE expansion_deferrals SET encounter_json = ? WHERE deferral_code = ?")
        .run(JSON.stringify(stored), code);
      const shown = as.expansionDeferrals.disclosure(code as string)?.encounter_disclosure;
      expect(shown, JSON.stringify(stored)).toEqual({ pinned: false, taint: "taint_state_unknown" });
    }
  });

  it("each adjudication has its own encounter_id", async () => {
    const first = (await encounter("payments:invoice.read")).facts?.encounter_id;
    const second = (await encounter("payments:invoice.read")).facts?.encounter_id;
    expect(first).toMatch(/^enc_/);
    expect(second).toMatch(/^enc_/);
    expect(second).not.toBe(first);
  });
});
