/**
 * @spec resource-access#resource-access-type (D634)
 *
 * "The authorization server MUST refuse an entry whose `delegation` carries a
 * member other than `max_depth` and `allowed_delegates` with the
 * `invalid_authorization_details` error code, unless a companion profile it
 * implements defines that member's processing." An authorization server
 * cannot fulfill the processing obligations of a member it does not
 * implement, so it never carries one unchanged.
 *
 * This reference implements Child Delegation, whose `children` grant is the
 * one such member it supports; the members of `children` are those Child
 * Delegation defines. Before D634 the reference admitted any other member at
 * PAR and carried one from a ceiling into the derived entry. One shared
 * declaration (`SUPPORTED_DELEGATION_MEMBERS`, `SUPPORTED_CHILDREN_MEMBERS` in
 * `@mission/core`) now backs every boundary: PAR and the other intakes, the
 * published schema, template consent, the config loaders, derivation, the
 * subset rule and projection. The resource server's permission to disregard
 * `delegation` is unchanged (mcp-saas member-roles.test.ts).
 */

import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { SUPPORTED_CHILDREN_MEMBERS, SUPPORTED_DELEGATION_MEMBERS } from "@mission/core";
import { DERIVATION_POLICY } from "@mission/demo-data";
import { type CryptoKey, importJWK, SignJWT } from "jose";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import {
  type AuthorityEntry,
  authorizationDetailsTypesMetadata,
  type BuiltAs,
  buildAuthorizationServer,
  deriveAuthoritySet,
  IntentError,
  isSubsetEntry,
  MISSION_RESOURCE_ACCESS_TYPE,
  type MissionIntent,
  projectThroughEffective,
} from "../src/index.js";
import { renderedRevision, TEST_APPROVAL_PRINCIPALS, trustedApprovalHeaders } from "./approval-fixture.js";

const PORT = 14634;
const ISSUER = `http://localhost:${PORT}`;
/** The second AS, whose programmatic ceiling carries an unsupported member. */
const CEILING_PORT = 14635;
const CEILING_ISSUER = `http://localhost:${CEILING_PORT}`;
const REDIRECT_URI = "http://localhost:9999/cb";
const REAL_CONFIG_DIR = fileURLToPath(new URL("../../../config", import.meta.url));
const RESOURCE = DERIVATION_POLICY.ceiling[0].resource;
const READ = "payments:invoice.read";
const INTENT = { goal: "Read Acme invoices", target_resources: [RESOURCE], expires_at: "2027-01-01T00:00:00Z" };
const PKCE_VERIFIER = "delegation-extension-verifier-0123456789-0123456789";

/** A `delegation` member no specification this reference implements defines. */
const UNKNOWN = "future_policy";
/** A member inside the `children` grant that Child Delegation does not define. */
const UNKNOWN_CHILD = "future_child_control";

/** Every kind of value the presence check must refuse, including the falsy ones. */
const VALUES: ReadonlyArray<readonly [string, unknown]> = [
  ["an object", { max_uses: 1 }],
  ["a string", "tbd"],
  ["null", null],
  ["false", false],
  ["an empty array", []],
];

const entry = (over: Record<string, unknown> = {}, resource = RESOURCE): AuthorityEntry =>
  ({ type: MISSION_RESOURCE_ACCESS_TYPE, resource, actions: [READ], ...over }) as AuthorityEntry;

const UNSUPPORTED = /delegation\.future_policy is not a supported delegation member/;
const UNSUPPORTED_CHILD = /delegation\.children\.future_child_control is not a supported delegation member/;

let as: BuiltAs;
let ceilingAs: BuiltAs;
let servers: Server[] = [];
let agentKey: CryptoKey;
let ceilingAgentKey: CryptoKey;

async function clientAssertion(issuer: string, key: CryptoKey): Promise<string> {
  return new SignJWT({})
    .setProtectedHeader({ alg: "ES256", kid: "ap-agent-auth" })
    .setIssuer("ap-agent")
    .setSubject("ap-agent")
    .setAudience(issuer)
    .setIssuedAt()
    .setExpirationTime("2m")
    .setJti(crypto.randomUUID())
    .sign(key);
}

/** Push the Intent with `proposal` (or none) through PAR. */
async function push(
  issuer: string,
  key: CryptoKey,
  proposal: Record<string, unknown>[] | undefined,
): Promise<{ status: number; body: { error?: string; error_description?: string; request_uri?: string } }> {
  const challenge = Buffer.from(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(PKCE_VERIFIER)),
  ).toString("base64url");
  const res = await fetch(`${issuer}/request`, {
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
      mission_intent: JSON.stringify({ intent: INTENT }),
      ...(proposal ? { authorization_details: JSON.stringify(proposal) } : {}),
      client_assertion: await clientAssertion(issuer, key),
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    }).toString(),
  });
  return { status: res.status, body: (await res.json()) as { request_uri?: string } };
}

/** A pushed request's interaction: its uid and a cookie header for it. */
async function interaction(issuer: string, requestUri: string): Promise<{ uid: string; cookie: string }> {
  const res = await fetch(`${issuer}/auth?${new URLSearchParams({ client_id: "ap-agent", request_uri: requestUri })}`, {
    redirect: "manual",
  });
  const cookie = res.headers
    .getSetCookie()
    .map((line) => line.split(";")[0])
    .join("; ");
  const uid = (res.headers.get("location") ?? "").split("/interaction/")[1] as string;
  expect(uid).toBeTruthy();
  return { uid, cookie };
}

beforeAll(async () => {
  as = await buildAuthorizationServer({
    issuer: ISSUER,
    allowHeadlessAdjudication: true,
    serviceTokenPrincipals: TEST_APPROVAL_PRINCIPALS,
  });
  // A programmatic ceiling the config loaders would refuse: the first entry's
  // `delegation` carries a member this reference does not implement.
  const ceiling = structuredClone(DERIVATION_POLICY.ceiling) as AuthorityEntry[];
  (ceiling[0]?.delegation as Record<string, unknown>)[UNKNOWN] = { max_uses: 1 };
  ceilingAs = await buildAuthorizationServer({
    issuer: CEILING_ISSUER,
    allowHeadlessAdjudication: true,
    serviceTokenPrincipals: TEST_APPROVAL_PRINCIPALS,
    derivationPolicy: { ...DERIVATION_POLICY, policy_version: "delegation-extension-d634", ceiling },
  });
  servers = [as.provider.listen(PORT), ceilingAs.provider.listen(CEILING_PORT)];
  agentKey = (await importJWK(as.agentClientJwk as never, "ES256")) as CryptoKey;
  ceilingAgentKey = (await importJWK(ceilingAs.agentClientJwk as never, "ES256")) as CryptoKey;
});

afterAll(() => {
  for (const server of servers) server.close();
});

describe("PAR refuses a delegation member the authorization server does not support (@spec resource-access#resource-access-type, D634)", () => {
  it("refuses an entry whose delegation carries a member no specification it implements defines, whatever its value, with invalid_authorization_details and no request_uri", async () => {
    for (const [name, value] of VALUES) {
      const res = await push(ISSUER, agentKey, [entry({ delegation: { max_depth: 1, [UNKNOWN]: value } })]);
      expect(res.status, name).toBe(400);
      expect(res.body.error, name).toBe("invalid_authorization_details");
      expect(res.body.error_description, name).toMatch(UNSUPPORTED);
      expect(res.body.request_uri, name).toBeUndefined();
    }
  });

  it("refuses an entry whose children grant carries a member Child Delegation does not define", async () => {
    const res = await push(ISSUER, agentKey, [
      entry({ delegation: { max_depth: 1, children: { max_children: 2, [UNKNOWN_CHILD]: true } } }),
    ]);
    expect(res.status).toBe(400);
    expect(res.body.error).toBe("invalid_authorization_details");
    expect(res.body.error_description).toMatch(UNSUPPORTED_CHILD);
    expect(res.body.request_uri).toBeUndefined();
  });

  it("admits the children grant Child Delegation defines, and the approved Mission's entry carries it, narrowed by the ceiling", async () => {
    const par = await push(ISSUER, agentKey, [entry({ delegation: { max_depth: 1, children: { max_children: 2 } } })]);
    expect(par.status, JSON.stringify(par.body)).toBe(201);
    const { uid, cookie } = await interaction(ISSUER, par.body.request_uri as string);
    const decideHeaders = { ...trustedApprovalHeaders(), "content-type": "application/json", cookie };
    const render_revision = await renderedRevision(ISSUER, uid, decideHeaders);
    const decided = await fetch(`${ISSUER}/interaction/${uid}/decide`, {
      method: "POST",
      redirect: "manual",
      headers: decideHeaders,
      body: JSON.stringify({ decision: "approve", render_revision }),
    });
    expect(decided.status, await decided.clone().text()).toBe(303);
    const record = as.kernel.findByApprovalEvent(`apev_${uid}`);
    expect(record).toBeDefined();
    // The shipped ceiling grants children { max_children: 5, max_child_depth: 2,
    // allowed_child_actors: [ai_agent] }: the proposal's cap narrows it, and
    // the members it omits are inherited.
    expect(record?.authority_set.map((e) => e.delegation)).toEqual([
      {
        max_depth: 1,
        allowed_delegates: [{ sub_profile: "ai_agent" }],
        children: { max_children: 2, max_child_depth: 2, allowed_child_actors: [{ sub_profile: "ai_agent" }] },
      },
    ]);
  });
});

describe("derivation from an entry whose delegation carries an unsupported member refuses (@spec resource-access#resource-access-type, D634)", () => {
  it("the approval rendering over a ceiling entry carrying one refuses invalid_authorization_details, and no Mission is created", async () => {
    const before = ceilingAs.kernel.allMissions().length;
    const par = await push(CEILING_ISSUER, ceilingAgentKey, [entry()]);
    expect(par.status, JSON.stringify(par.body)).toBe(201);
    const { uid, cookie } = await interaction(CEILING_ISSUER, par.body.request_uri as string);
    const page = await fetch(`${CEILING_ISSUER}/interaction/${uid}`, { headers: { cookie } });
    const text = await page.text();
    expect(page.status, text.slice(0, 200)).toBe(400);
    const body = JSON.parse(text) as { error?: string; error_description?: string };
    expect(body.error).toBe("invalid_authorization_details");
    expect(body.error_description).toMatch(/carries delegation\.future_policy, which is not a supported delegation member/);
    expect(ceilingAs.kernel.allMissions().length).toBe(before);
  });

  it("deriveAuthoritySet refuses a ceiling entry or a submitted proposal entry carrying one, whatever its value", () => {
    const intent = { purpose: "Read invoices", target_resources: [RESOURCE] } as unknown as MissionIntent;
    const policy = (ceiling: AuthorityEntry[]) => ({ policy_version: "delegation-extension-d634", ceiling });
    const delegable = (extra: Record<string, unknown> = {}) => entry({ delegation: { max_depth: 2, ...extra } });
    const refusal = (fn: () => unknown): IntentError => {
      try {
        fn();
      } catch (e) {
        if (e instanceof IntentError) return e;
        throw e;
      }
      throw new Error("expected an IntentError");
    };
    for (const [name, value] of VALUES) {
      const ceilingSide = refusal(() => deriveAuthoritySet(intent, policy([delegable({ [UNKNOWN]: value })])));
      expect(ceilingSide.code, name).toBe("invalid_authorization_details");
      expect(ceilingSide.message, name).toMatch(/carries delegation\.future_policy/);
      const proposalSide = refusal(() =>
        deriveAuthoritySet(intent, policy([delegable()]), [delegable({ [UNKNOWN]: value })]),
      );
      expect(proposalSide.code, name).toBe("invalid_authorization_details");
      expect(proposalSide.message, name).toMatch(/carries delegation\.future_policy/);
    }
    const childSide = refusal(() =>
      deriveAuthoritySet(intent, policy([delegable({ children: { max_children: 1, [UNKNOWN_CHILD]: 1 } })])),
    );
    expect(childSide.message).toMatch(/carries delegation\.children\.future_child_control/);
    // Positive control: the supported members derive, the children grant included.
    expect(
      deriveAuthoritySet(intent, policy([delegable({ children: { max_children: 1 } })]))[0]?.delegation,
    ).toEqual({ max_depth: 2, children: { max_children: 1 } });
  });

  it("the subset rule refuses either side carrying one, a byte-identical pair included", () => {
    const carrying = entry({ delegation: { max_depth: 1, [UNKNOWN]: "tbd" } });
    const clean = entry({ delegation: { max_depth: 1 } });
    expect(isSubsetEntry(carrying, carrying)).toBe(false);
    expect(isSubsetEntry(entry(), carrying)).toBe(false);
    expect(isSubsetEntry(carrying, clean)).toBe(false);
    const childCarrying = entry({ delegation: { max_depth: 1, children: { [UNKNOWN_CHILD]: 1 } } });
    expect(isSubsetEntry(childCarrying, childCarrying)).toBe(false);
    // Positive control: without the member, the same pairs are subsets.
    expect(isSubsetEntry(clean, clean)).toBe(true);
    expect(isSubsetEntry(entry(), clean)).toBe(true);
  });

  it("projection yields no fragment for a candidate carrying one, rather than one rebuilt without it", () => {
    const clean = entry({ delegation: { max_depth: 1 } });
    expect(projectThroughEffective([entry({ delegation: { max_depth: 1, [UNKNOWN]: "tbd" } })], [clean])).toEqual([]);
    expect(projectThroughEffective([clean], [clean])).toEqual([clean]);
  });
});

describe("the published schema closes delegation and its children grant to the supported members (D634)", () => {
  it("declares exactly SUPPORTED_DELEGATION_MEMBERS and SUPPORTED_CHILDREN_MEMBERS, and admits no other member", () => {
    const schema = authorizationDetailsTypesMetadata()[MISSION_RESOURCE_ACCESS_TYPE]?.schema as {
      properties: { delegation: { properties: Record<string, { properties?: object }>; additionalProperties: unknown } };
    };
    const delegation = schema.properties.delegation;
    expect(delegation.additionalProperties).toBe(false);
    expect(Object.keys(delegation.properties).sort()).toEqual([...SUPPORTED_DELEGATION_MEMBERS].sort());
    const children = delegation.properties.children as { properties: object; additionalProperties: unknown };
    expect(children.additionalProperties).toBe(false);
    expect(Object.keys(children.properties).sort()).toEqual([...SUPPORTED_CHILDREN_MEMBERS].sort());
  });
});

describe("the config loader refuses a ceiling entry whose delegation carries an unsupported member, naming it (D634)", () => {
  let previous: string | undefined;
  let dir: string | undefined;

  afterEach(() => {
    if (previous === undefined) delete process.env.MISSION_CONFIG_DIR;
    else process.env.MISSION_CONFIG_DIR = previous;
    if (dir) rmSync(dir, { recursive: true, force: true });
    dir = undefined;
    vi.resetModules();
  });

  it("parseCeilingEntry (policy.json) rejects the entry, naming the entry and the member", async () => {
    dir = mkdtempSync(join(tmpdir(), "mission-config-d634-"));
    const configDir = join(dir, "config");
    cpSync(REAL_CONFIG_DIR, configDir, { recursive: true });
    const file = join(configDir, "policy.json");
    const parsed = JSON.parse(readFileSync(file, "utf8")) as { ceiling: { delegation: Record<string, unknown> }[] };
    (parsed.ceiling[0] as { delegation: Record<string, unknown> }).delegation[UNKNOWN] = { max_uses: 1 };
    writeFileSync(file, JSON.stringify(parsed, null, 2));
    previous = process.env.MISSION_CONFIG_DIR;
    process.env.MISSION_CONFIG_DIR = configDir;
    vi.resetModules();
    await expect(import("@mission/demo-data")).rejects.toThrow(
      "[config:policy.json] policy.ceiling[0] carries delegation.future_policy, which is not a supported delegation member",
    );
  });

  // @spec child-delegation#fanout (#1528, D660): "a configured entry carrying
  // one is a configuration error", for a member inside the children grant.
  it("parseCeilingEntry (policy.json) rejects an entry whose children grant carries a member Child Delegation does not define, naming it", async () => {
    dir = mkdtempSync(join(tmpdir(), "mission-config-1528-"));
    const configDir = join(dir, "config");
    cpSync(REAL_CONFIG_DIR, configDir, { recursive: true });
    const file = join(configDir, "policy.json");
    const parsed = JSON.parse(readFileSync(file, "utf8")) as {
      ceiling: { delegation: { children: Record<string, unknown> } }[];
    };
    (parsed.ceiling[0] as { delegation: { children: Record<string, unknown> } }).delegation.children[UNKNOWN_CHILD] = true;
    writeFileSync(file, JSON.stringify(parsed, null, 2));
    previous = process.env.MISSION_CONFIG_DIR;
    process.env.MISSION_CONFIG_DIR = configDir;
    vi.resetModules();
    await expect(import("@mission/demo-data")).rejects.toThrow(
      "[config:policy.json] policy.ceiling[0] carries delegation.children.future_child_control, which is not a supported delegation member",
    );
  });
});
