/**
 * #2019 G5: the minimal configuration of #2009 P5 step 4
 * (`minimal-baseline-config.test.ts`) with one deployment-defined
 * `authorization_details` type added beside `mission_resource_access`, a type
 * for which the AS declares no transformation capability in any carrier
 * (`@spec mission#other-types`, mission#transformation-capabilities).
 *
 * The capability set is the minimal one, `lifecycle-revoke` alone, and the
 * Approver logs in for real at the reference upstream provider. The added
 * configuration is the type itself (its metadata entry and documented
 * definition, `additionalAuthorizationDetailsTypes`), the agent's client
 * registration listing it in `authorization_details_types` (a copy of the
 * shipped `config/`), and a derivation ceiling, user-delegated source ceiling
 * and approval-floor classification that name two entries of it; nothing
 * else. The type's metadata entry carries no
 * `mission_transformation_capabilities`, and no deployment documentation
 * names the type, so `narrowing`, `delegation` and `projection` are each
 * undeclared for it: the binding carries its entries as approved.
 *
 * The first entry's members are a subset of `mission_resource_access`'s
 * (`type`, `resource`, `resource_match`, `actions`), so the members the
 * reference rebuilds for its own type are where a transformation would show:
 * it states `resource_match: "exact"`, which that rebuild drops, and names
 * `ledger:vendor.read`, the action the SaaS resource maps a tool to. The
 * second also carries `tenant_id`, a member of the type's own that
 * `mission_resource_access` does not define, so the ceiling is mixed: each
 * entry in it is held to its own type's rules (#2019 review).
 *
 * The file runs on a controlled clock (D1091).
 */
const { controlledClock, config } = await vi.hoisted(async () => {
  const { CONTROLLED_CLOCK_MS, installControlledClock } = await import("./controlled-clock.helper.js");
  // The agent's registration lists the type, in a copy of the shipped config.
  const { cpSync, mkdtempSync, readFileSync, writeFileSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const { fileURLToPath } = await import("node:url");
  const dir = mkdtempSync(join(tmpdir(), "mission-config-2019-"));
  cpSync(fileURLToPath(new URL("../../config", import.meta.url)), dir, { recursive: true });
  const file = join(dir, "clients.json");
  const clients = JSON.parse(readFileSync(file, "utf8")) as Array<{ client_id: string; authorization_details_types: string[] }>;
  const agent = clients.find((c) => c.client_id === "ap-agent");
  if (!agent) throw new Error("the shipped clients.json registers no ap-agent");
  agent.authorization_details_types = [...agent.authorization_details_types, "urn:example:mission-reference:vendor-records"];
  writeFileSync(file, JSON.stringify(clients, null, 2));
  const previous = process.env.MISSION_CONFIG_DIR;
  process.env.MISSION_CONFIG_DIR = dir;
  return { controlledClock: installControlledClock(CONTROLLED_CLOCK_MS), config: { dir, previous } };
});

import { rmSync } from "node:fs";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import {
  APPROVER_LOGIN_CALLBACK_PATH,
  ApprovalSessionStore,
  type AuthorityEntry,
  buildAuthorizationServer,
  type BuiltAs,
  type DeploymentDefinedType,
  type ProviderCapability,
} from "@mission/authorization-server";
import { APPROVAL_FLOOR, AUTHORITY_SOURCES, DERIVATION_POLICY } from "@mission/demo-data";
import { SAAS_RESOURCE, SaasMcpServer } from "@mission/mcp-saas";
import { decodeJwt, generateKeyPair } from "jose";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { resolveMissionApproval, type UpstreamApprovalConsole } from "../src/approval-console.js";
import { type ApproverAccount, type ApproverIdp, startApproverIdp } from "../src/approver-idp.js";
import { clientAssertionSigner, type CookieJar, type DpopKeys, dpopProofFor, jarClosures, tokenGrantRequest } from "../src/oauth-client.js";
import { CONTROLLED_CLOCK_MS } from "./controlled-clock.helper.js";

type Json = Record<string, unknown>;

/** The minimal configuration's capability set, as in `minimal-baseline-config.test.ts`. */
const MINIMAL_CAPABILITIES: ReadonlySet<ProviderCapability> = new Set<ProviderCapability>(["lifecycle-revoke"]);

/** The deployment-defined type: an identifier this deployment chose, no relation to `mission_resource_access`. */
const TYPE = "urn:example:mission-reference:vendor-records";
const MEMBERS = ["type", "resource", "resource_match", "actions", "tenant_id"];

/**
 * The type's documented definition: exactly these members, an absolute
 * resource, `exact` matching, non-empty actions, and an optional non-empty
 * `tenant_id`.
 */
const VENDOR_RECORDS: DeploymentDefinedType = {
  metadata: {
    version: "1",
    description: "A deployment-defined type naming vendor-record operations at one resource. No transformation capability is declared for it.",
    schema: {
      $schema: "https://json-schema.org/draft/2020-12/schema",
      type: "object",
      properties: {
        type: { const: TYPE },
        resource: { type: "string", format: "uri" },
        resource_match: { const: "exact" },
        actions: { type: "array", items: { type: "string", minLength: 1 }, minItems: 1 },
        tenant_id: { type: "string", minLength: 1 },
      },
      required: ["type", "resource", "actions"],
      additionalProperties: false,
    },
  },
  validate(entry) {
    const extra = Object.keys(entry).find((m) => !MEMBERS.includes(m));
    if (extra !== undefined) return `${extra} is not a member of ${TYPE}`;
    if (typeof entry.resource !== "string" || !URL.canParse(entry.resource)) return "resource must be an absolute URI";
    if (entry.resource_match !== undefined && entry.resource_match !== "exact") return "resource_match must be exact";
    const actions = entry.actions;
    if (!Array.isArray(actions) || actions.length === 0 || !actions.every((a) => typeof a === "string" && a.length > 0)) {
      return "actions must be a non-empty array of non-empty strings";
    }
    if (entry.tenant_id !== undefined && (typeof entry.tenant_id !== "string" || entry.tenant_id.length === 0)) {
      return "tenant_id must be a non-empty string";
    }
    return undefined;
  },
};

/** The one entry of the type this deployment's policy admits, and the approved entry. */
const ENTRY = { type: TYPE, resource: SAAS_RESOURCE, resource_match: "exact", actions: ["ledger:vendor.read", "ledger:vendor.export"] };
/** The same entry with an action removed: a narrowing under `mission_resource_access`'s relation. */
const NARROWED = { ...ENTRY, actions: ["ledger:vendor.read"] };
/** A second entry of the type the policy admits, carrying `tenant_id`, a member of the type's own. */
const TENANT_ENTRY = { type: TYPE, resource: SAAS_RESOURCE, resource_match: "exact", actions: ["ledger:vendor.read"], tenant_id: "acme" };
const CEILING = [...DERIVATION_POLICY.ceiling, ENTRY as unknown as AuthorityEntry, TENANT_ENTRY as unknown as AuthorityEntry];
/** An ordinary `mission_resource_access` read at the same resource, inside the shipped ceiling. */
const VENDOR_READ = {
  type: "mission_resource_access",
  resource: SAAS_RESOURCE,
  actions: ["ledger:vendor.read"],
  constraints: { vendors: ["acme"] },
};

const REDIRECT_URI = "http://localhost:9999/cb";
const VERIFIER = "minimal-config-deployment-type-verifier-0123456789-01";
const ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
const APPROVER = { sub: "idp-bob", username: "bob@acme.example" };
/** The Intent's requested expiry, a week after the controlled instant. */
const EXPIRES_AT = new Date(CONTROLLED_CLOCK_MS + 7 * 86_400_000).toISOString().replace(".000Z", "Z");

let as: BuiltAs;
let asUrl: string;
let asServer: Server;
let idp: ApproverIdp;
let bob: UpstreamApprovalConsole;

async function readJson(res: Response): Promise<Json> {
  const text = await res.text();
  try {
    return JSON.parse(text) as Json;
  } catch {
    return { body: text };
  }
}

/** A Pushed Authorization Request as `ap-agent` (private_key_jwt) proposing `entries` for the SaaS resource. */
async function par(entries: unknown[]): Promise<{ status: number; body: Json }> {
  const challenge = Buffer.from(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(VERIFIER)),
  ).toString("base64url");
  const assertion = await clientAssertionSigner(asUrl, as.agentClientJwk);
  const res = await fetch(`${asUrl}/request`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: "ap-agent",
      response_type: "code",
      redirect_uri: REDIRECT_URI,
      resource: SAAS_RESOURCE,
      code_challenge: challenge,
      code_challenge_method: "S256",
      mission_intent: JSON.stringify({
        intent: { goal: "Export the Acme vendor records", target_resources: [SAAS_RESOURCE], expires_at: EXPIRES_AT },
      }),
      authorization_details: JSON.stringify(entries),
      client_assertion: await assertion(),
      client_assertion_type: ASSERTION_TYPE,
    }).toString(),
  });
  return { status: res.status, body: await readJson(res) };
}

/** The front channel: redeem the `request_uri` and land on the approval interaction. */
async function startInteraction(requestUri: string): Promise<{ uid: string; jar: CookieJar }> {
  const jar: CookieJar = new Map();
  const { storeCookies } = jarClosures(jar);
  const res = await fetch(`${asUrl}/auth?${new URLSearchParams({ client_id: "ap-agent", request_uri: requestUri })}`, {
    redirect: "manual",
  });
  storeCookies(res);
  const location = res.headers.get("location") ?? "";
  expect(location).toContain("/interaction/");
  return { uid: location.split("/interaction/")[1] as string, jar };
}

/**
 * Resolve the approval as Bob: the code, or the refusal the console met, and
 * the approval page rendered to him before the decision, read from the wire
 * unchanged.
 */
async function approveReadingPage(
  pending: { uid: string; jar: CookieJar },
): Promise<{ code?: string; refusal?: string; pages: string[] }> {
  const pageUrl = `${asUrl}/interaction/${pending.uid}`;
  const pages: string[] = [];
  const realFetch = globalThis.fetch;
  const spy = vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
    const res = await realFetch(input, init);
    if (String(input) === pageUrl && (init?.method ?? "GET") === "GET") pages.push(await res.clone().text());
    return res;
  });
  try {
    return { code: (await resolveMissionApproval(asUrl, bob, pending, "approve", "alice")) as string, pages };
  } catch (e) {
    return { refusal: (e as Error).message, pages };
  } finally {
    spy.mockRestore();
  }
}

/** The derived authority an approval page renders, as the entries it shows. */
function renderedAuthority(page: string): unknown {
  const shown = /<h2>Derived authority \(what approval grants\)<\/h2><pre>([\s\S]*?)<\/pre>/.exec(page)?.[1];
  if (shown === undefined) return undefined;
  return JSON.parse(shown.replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&"));
}

beforeAll(async () => {
  const server = createServer();
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve());
  });
  asServer = server;
  asUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  idp = await startApproverIdp({ redirectUri: `${asUrl}${APPROVER_LOGIN_CALLBACK_PATH}`, accounts: [APPROVER] });
  bob = { upstream: { account: idp.accounts.get(APPROVER.username) as ApproverAccount, secondFactor: "code" } };
  as = await buildAuthorizationServer({
    issuer: asUrl,
    capabilities: MINIMAL_CAPABILITIES,
    approvalSessions: new ApprovalSessionStore(),
    approverLogin: {
      issuer: idp.issuer,
      clientId: idp.client.clientId,
      clientSecret: idp.client.clientSecret,
      idTokenSigningAlgs: ["ES256"],
      identities: [{ iss: idp.issuer, sub: APPROVER.sub, approver: "bob" }],
      acrValues: ["mfa"],
    },
    additionalAuthorizationDetailsTypes: { [TYPE]: VENDOR_RECORDS },
    derivationPolicy: { ...DERIVATION_POLICY, ceiling: CEILING },
    authoritySources: {
      ...AUTHORITY_SOURCES,
      entries: AUTHORITY_SOURCES.entries.map((e) => (e.id === "acme-people" ? { ...e, ceiling: CEILING as never } : e)),
    },
    approvalFloor: {
      ...APPROVAL_FLOOR,
      classification: [
        ...APPROVAL_FLOOR.classification,
        {
          type: TYPE,
          resource: SAAS_RESOURCE,
          actions: { "ledger:vendor.read": "consequential_read", "ledger:vendor.export": "consequential_read" },
        } as unknown as (typeof APPROVAL_FLOOR.classification)[number],
      ],
    },
  });
  asServer.on("request", as.provider.callback());
});

afterAll(async () => {
  asServer?.closeAllConnections();
  asServer?.close();
  await idp?.close();
  controlledClock.restore();
  if (config.previous === undefined) delete process.env.MISSION_CONFIG_DIR;
  else process.env.MISSION_CONFIG_DIR = config.previous;
  rmSync(config.dir, { recursive: true, force: true });
});

describe("a deployment-defined authorization_details type that declares no transformation, on the minimal configuration (#2019 G5; @spec mission#other-types, mission#transformation-capabilities)", () => {
  // State carried from step to step, in order.
  let code = "";
  let missionId = "";
  let accessToken = "";
  let refreshToken = "";
  let dpopKeys: DpopKeys;

  it("the AS supports the type beside mission_resource_access, and its metadata entry declares no transformation capability (@spec mission#other-types, mission#transformation-capabilities)", async () => {
    const meta = (await (await fetch(`${asUrl}/.well-known/openid-configuration`)).json()) as Json;
    expect(meta.authorization_details_types_supported).toEqual(["mission_resource_access", TYPE]);
    const types = (await (await fetch(String(meta.authorization_details_types_metadata_endpoint))).json()) as Record<string, Json>;
    expect(Object.keys(types)).toEqual(["mission_resource_access", TYPE]);
    expect(types[TYPE]).toEqual(VENDOR_RECORDS.metadata);
    expect(types[TYPE]).not.toHaveProperty("mission_transformation_capabilities");
  });

  it("PAR accepts a proposal of the type, and an authenticated Approver approves it as rendered: the record commits the entry exactly as proposed (@spec mission#proposal-derivation, mission#transformation-capabilities)", async () => {
    const pushed = await par([ENTRY]);
    expect(pushed.status, JSON.stringify(pushed.body)).toBe(201);
    const before = as.kernel.allMissions().length;
    const approved = await approveReadingPage(await startInteraction(String(pushed.body.request_uri)));
    // The page Bob reviewed renders the derived authority: the entry, unchanged.
    expect(approved.pages).toHaveLength(1);
    expect(renderedAuthority(approved.pages[0] as string)).toEqual([ENTRY]);
    expect(approved.refusal).toBeUndefined();
    code = String(approved.code);
    const created = as.kernel.allMissions().slice(before);
    expect(created).toHaveLength(1);
    const record = created[0] as unknown as Json;
    missionId = String(record.id);
    expect(record.state).toBe("active");
    expect(record.proposed_authority).toEqual([ENTRY]);
    // Carried as approved: the same members and values, `resource_match` kept.
    expect(record.authority_set).toEqual([ENTRY]);
  });

  it("the code exchange issues the entry exactly as approved in the response and the token, with no scope projected from it (@spec mission#token-response, mission#transformation-capabilities)", async () => {
    dpopKeys = await generateKeyPair("ES256", { extractable: true });
    const redeemed = await tokenGrantRequest(asUrl, as.agentClientJwk, dpopKeys, {
      grant_type: "authorization_code",
      code,
      redirect_uri: REDIRECT_URI,
      code_verifier: VERIFIER,
      resource: SAAS_RESOURCE,
    });
    expect(redeemed.status, JSON.stringify(redeemed.body)).toBe(200);
    accessToken = String(redeemed.body.access_token);
    refreshToken = String(redeemed.body.refresh_token ?? "");
    expect(refreshToken).not.toBe("");
    expect(redeemed.body.mission_id).toBe(missionId);
    expect(redeemed.body.authorization_details).toEqual([ENTRY]);
    const claims = decodeJwt(accessToken);
    expect(claims.aud).toBe(SAAS_RESOURCE);
    expect(claims.mission).toMatchObject({ id: missionId, issuer: asUrl });
    expect(claims.authorization_details).toEqual([ENTRY]);
    expect(claims.scope).toBeUndefined();
  });

  it("a refresh requesting the entry narrowed is refused invalid_authorization_details before consumption, issuing nothing, and the same refresh token then refreshes the entry unchanged (@spec mission#refresh-tokens, mission#subset, mission#transformation-capabilities)", async () => {
    const narrowed = await tokenGrantRequest(asUrl, as.agentClientJwk, dpopKeys, {
      grant_type: "refresh_token",
      refresh_token: refreshToken,
      authorization_details: JSON.stringify([NARROWED]),
    });
    expect(narrowed.status, JSON.stringify(narrowed.body)).toBe(400);
    expect(narrowed.body.error).toBe("invalid_authorization_details");
    expect(narrowed.body).not.toHaveProperty("access_token");
    const refreshed = await tokenGrantRequest(asUrl, as.agentClientJwk, dpopKeys, {
      grant_type: "refresh_token",
      refresh_token: refreshToken,
    });
    expect(refreshed.status, JSON.stringify(refreshed.body)).toBe(200);
    expect(refreshed.body.authorization_details).toEqual([ENTRY]);
    const claims = decodeJwt(String(refreshed.body.access_token));
    expect((claims.mission as Json).id).toBe(missionId);
    expect(claims.authorization_details).toEqual([ENTRY]);
    accessToken = String(refreshed.body.access_token);
  });

  it("derivation does not narrow a proposal of the type: one narrower than the entry the policy admits is refused invalid_authorization_details, rendering and creating no Mission (@spec mission#proposal-derivation, mission#transformation-capabilities)", async () => {
    const pushed = await par([NARROWED]);
    expect(pushed.status, JSON.stringify(pushed.body)).toBe(201);
    const before = as.kernel.allMissions().length;
    const refused = await approveReadingPage(await startInteraction(String(pushed.body.request_uri)));
    expect(refused.code).toBeUndefined();
    expect(refused.refusal).toBe("approval did not yield a code: invalid_authorization_details");
    expect(refused.pages.map(renderedAuthority).filter((shown) => shown !== undefined)).toEqual([]);
    expect(as.kernel.allMissions()).toHaveLength(before);
  });

  it("an entry failing the type's documented definition is refused invalid_authorization_details at PAR (@spec mission#proposal-validation)", async () => {
    const pushed = await par([{ ...ENTRY, locations: [SAAS_RESOURCE] }]);
    expect(pushed.status, JSON.stringify(pushed.body)).toBe(400);
    expect(pushed.body.error).toBe("invalid_authorization_details");
    expect(pushed.body).not.toHaveProperty("request_uri");
  });

  it("the SaaS resource, which implements mission_resource_access alone, gives the entry no authority though its resource and action cover the request (@spec mission#rs-enforcement)", async () => {
    const jwks = (await (await fetch(`${asUrl}/jwks`)).json()) as ConstructorParameters<typeof SaasMcpServer>[0]["rasJwks"];
    const saas = new SaasMcpServer({ rasIssuer: asUrl, rasJwks: jwks, trustedMissionIssuers: [asUrl], resource: SAAS_RESOURCE });
    const result = await saas.callTool(
      "get_vendor_bank_details",
      { vendor_id: "acme" },
      accessToken,
      await dpopProofFor(dpopKeys, SAAS_RESOURCE, "POST", accessToken),
    );
    expect(result).toEqual({ ok: false, error: "out_of_authority" });
  });
});

describe("a mixed ceiling: each entry is held to its own type's rules, so a valid entry of one type never breaks another type's request (#2019 review; @spec mission#other-types, mission#proposal-derivation)", () => {
  /** PAR and Bob's approval of `entries`: the Mission created, or the refusal the console met. */
  async function approveProposal(entries: unknown[]): Promise<{ record?: Json; code?: string; refusal?: string }> {
    const pushed = await par(entries);
    expect(pushed.status, JSON.stringify(pushed.body)).toBe(201);
    const before = as.kernel.allMissions().length;
    const approved = await approveReadingPage(await startInteraction(String(pushed.body.request_uri)));
    const created = as.kernel.allMissions().slice(before);
    expect(created.length).toBeLessThanOrEqual(1);
    return {
      ...(created[0] ? { record: created[0] as unknown as Json } : {}),
      ...(approved.code !== undefined ? { code: approved.code } : {}),
      ...(approved.refusal !== undefined ? { refusal: approved.refusal } : {}),
    };
  }

  it("an ordinary mission_resource_access read is approved and committed as proposed, beside the type's ceiling entry carrying tenant_id (@spec mission#proposal-derivation, mission#other-types)", async () => {
    const approved = await approveProposal([VENDOR_READ]);
    expect(approved.refusal).toBeUndefined();
    expect(approved.record?.state).toBe("active");
    expect(approved.record?.authority_set).toEqual([VENDOR_READ]);
  });

  it("a request for the type's entry carrying tenant_id is approved, committed and issued at the code exchange exactly as approved (@spec mission#proposal-derivation, mission#transformation-capabilities)", async () => {
    const approved = await approveProposal([TENANT_ENTRY]);
    expect(approved.refusal).toBeUndefined();
    expect(approved.record?.authority_set).toEqual([TENANT_ENTRY]);
    const keys = await generateKeyPair("ES256", { extractable: true });
    const redeemed = await tokenGrantRequest(asUrl, as.agentClientJwk, keys, {
      grant_type: "authorization_code",
      code: String(approved.code),
      redirect_uri: REDIRECT_URI,
      code_verifier: VERIFIER,
      resource: SAAS_RESOURCE,
    });
    expect(redeemed.status, JSON.stringify(redeemed.body)).toBe(200);
    expect(redeemed.body.authorization_details).toEqual([TENANT_ENTRY]);
    expect(decodeJwt(String(redeemed.body.access_token)).authorization_details).toEqual([TENANT_ENTRY]);
  });

  it("an entry failing its own type's rules is refused invalid_authorization_details at PAR: a mission_resource_access entry carrying tenant_id, and the type's entry with an empty tenant_id (@spec mission#proposal-validation)", async () => {
    for (const entry of [{ ...VENDOR_READ, tenant_id: "acme" }, { ...TENANT_ENTRY, tenant_id: "" }]) {
      const pushed = await par([entry]);
      expect(pushed.status, JSON.stringify(pushed.body)).toBe(400);
      expect(pushed.body.error).toBe("invalid_authorization_details");
      expect(pushed.body).not.toHaveProperty("request_uri");
    }
  });
});
