/**
 * @spec mission#delegation, mission#designation, mission#delegation-constraints
 * (#869, #1268, D449): same-Mission delegation by designation, at the token
 * endpoint. The approved agent (ap-agent) designates a sub-agent
 * (subagent-invoice-extractor) by Token Exchange, proving its own token's key;
 * the sub-agent redeems the designation as its own client, proving its own key.
 */
import { floorApprovalHeaders, TEST_APPROVAL_PRINCIPALS } from "./approval-fixture.js";
import { ApprovalSessionStore } from "../src/index.js";

import { type Server } from "node:http";
import { CANONICAL_RESOURCE } from "@mission/demo-data";
import { calculateJwkThumbprint, decodeJwt, exportJWK, generateKeyPair, importJWK, SignJWT } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ACCESS_TOKEN_TOKEN_TYPE, TOKEN_EXCHANGE_GRANT_TYPE } from "../src/adapters/continuation-grant.js";
import { ALL_PROVIDER_CAPABILITIES, buildAuthorizationServer, type BuiltAs } from "../src/index.js";

const FLOOR_SESSIONS = new ApprovalSessionStore();
const PORT = 14870;
const ISSUER = `http://localhost:${PORT}`;
const REDIRECT_URI = "http://localhost:9999/cb";
const RESOURCE = CANONICAL_RESOURCE;
const SUBAGENT = "subagent-invoice-extractor";
const RS_PAYMENTS = ["rs-payments", "dev-introspection-rs-payments"] as const;
const DELEGABLE = {
  type: "mission_resource_access",
  resource: RESOURCE,
  actions: ["payments:invoice.read"],
  constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
  delegation: { max_depth: 2, allowed_delegates: [{ sub_profile: "ai_agent" }] },
};

type Keys = { privateKey: CryptoKey; publicKey: CryptoKey };
type Body = Record<string, unknown>;
type Client = "ap-agent" | typeof SUBAGENT;

let as: BuiltAs;
let server: Server;
const clientKeys = new Map<Client, CryptoKey>();
let agentDpop: Keys;
let subagentDpop: Keys;

const assertion = (client: Client) =>
  new SignJWT({})
    .setProtectedHeader({ alg: "ES256", kid: `${client}-auth` })
    .setIssuer(client)
    .setSubject(client)
    .setAudience(ISSUER)
    .setIssuedAt()
    .setExpirationTime("2m")
    .setJti(crypto.randomUUID())
    .sign(clientKeys.get(client) as CryptoKey);

async function proof(keys: Keys, extra: Record<string, unknown> = {}): Promise<string> {
  return new SignJWT({ htu: `${ISSUER}/token`, htm: "POST", ...extra })
    .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: await exportJWK(keys.publicKey) })
    .setIssuedAt()
    .setJti(crypto.randomUUID())
    .sign(keys.privateKey);
}

async function token(client: Client, keys: Keys, params: Record<string, string>): Promise<{ status: number; body: Body }> {
  const send = async (extra: Record<string, unknown> = {}) =>
    fetch(`${ISSUER}/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", dpop: await proof(keys, extra) },
      body: new URLSearchParams({
        ...params,
        client_assertion: await assertion(client),
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      }).toString(),
    });
  let res = await send();
  const nonce = res.headers.get("dpop-nonce");
  if (res.status === 400 && nonce) res = await send({ nonce });
  return { status: res.status, body: (await res.json()) as Body };
}

function storeCookies(res: Response, jar: Map<string, string>): void {
  for (const line of res.headers.getSetCookie()) {
    const [pair] = line.split(";");
    const eq = (pair as string).indexOf("=");
    jar.set((pair as string).slice(0, eq), (pair as string).slice(eq + 1));
  }
}
const cookieHeader = (jar: Map<string, string>) => [...jar.entries()].map(([k, v]) => `${k}=${v}`).join("; ");

/** PAR, approval and code exchange as ap-agent: an active Mission and its access token. */
async function baseMission(authority: unknown[] = [DELEGABLE]): Promise<{ missionId: string; accessToken: string }> {
  const jar = new Map<string, string>();
  const verifier = "delegation-exchange-verifier-0123456789-0123456789-01";
  const challenge = Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))).toString("base64url");
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
      mission_intent: JSON.stringify({ intent: { goal: "Read Acme invoices", target_resources: [RESOURCE], expires_at: "2027-01-01T00:00:00Z" } }),
      authorization_details: JSON.stringify(authority),
      client_assertion: await assertion("ap-agent"),
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    }).toString(),
  });
  const pushed = (await par.json()) as { request_uri?: string };
  expect(par.status, JSON.stringify(pushed)).toBe(201);
  let res = await fetch(`${ISSUER}/auth?${new URLSearchParams({ client_id: "ap-agent", request_uri: pushed.request_uri as string })}`, { redirect: "manual" });
  storeCookies(res, jar);
  let location = res.headers.get("location") as string;
  const uid = location.split("/interaction/")[1] as string;
  res = await fetch(`${ISSUER}/interaction/${uid}/decide`, {
    method: "POST",
    redirect: "manual",
    headers: { ...floorApprovalHeaders(FLOOR_SESSIONS, uid, cookieHeader(jar)), "content-type": "application/json" },
    body: JSON.stringify({ decision: "approve" }),
  });
  storeCookies(res, jar);
  location = res.headers.get("location") as string;
  while (location?.startsWith(ISSUER)) {
    res = await fetch(location, { redirect: "manual", headers: { cookie: cookieHeader(jar) } });
    storeCookies(res, jar);
    location = res.headers.get("location") as string;
  }
  const code = new URL(location).searchParams.get("code") as string;
  const tok = await token("ap-agent", agentDpop, {
    grant_type: "authorization_code",
    code,
    redirect_uri: REDIRECT_URI,
    code_verifier: verifier,
    resource: RESOURCE,
  });
  expect(tok.status, JSON.stringify(tok.body)).toBe(200);
  const accessToken = tok.body.access_token as string;
  return { missionId: (decodeJwt(accessToken) as { mission: { id: string } }).mission.id, accessToken };
}

/** A designation: `client`, proving `keys`, names `designee` for the presented token. */
const designate = (subjectToken: string, designee: string, client: Client = "ap-agent", keys: Keys = agentDpop, extra: Record<string, string> = {}) =>
  token(client, keys, {
    grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
    subject_token: subjectToken,
    subject_token_type: ACCESS_TOKEN_TOKEN_TYPE,
    requested_token_type: ACCESS_TOKEN_TOKEN_TYPE,
    audience: designee,
    ...extra,
  });

/** A delegated exchange: `client`, proving `keys`, redeems the designation for `resource`. */
const redeem = (designation: string, client: Client = SUBAGENT, keys: Keys = subagentDpop, extra: Record<string, string> = {}) =>
  token(client, keys, {
    grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
    subject_token: designation,
    subject_token_type: ACCESS_TOKEN_TOKEN_TYPE,
    requested_token_type: ACCESS_TOKEN_TOKEN_TYPE,
    resource: RESOURCE,
    ...extra,
  });

async function introspect(tokenValue: string): Promise<Body> {
  const res = await fetch(`${ISSUER}/introspect`, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      authorization: `Basic ${Buffer.from(`${RS_PAYMENTS[0]}:${RS_PAYMENTS[1]}`).toString("base64")}`,
    },
    body: new URLSearchParams({ token: tokenValue }).toString(),
  });
  expect(res.status).toBe(200);
  return (await res.json()) as Body;
}

const derivations = (missionId: string) => (as.kernel.get(missionId) as { derivation_count?: number }).derivation_count ?? 0;
const jktOf = async (keys: Keys) => calculateJwkThumbprint(await exportJWK(keys.publicKey));

beforeAll(async () => {
  as = await buildAuthorizationServer({
    issuer: ISSUER,
    allowHeadlessAdjudication: true,
    serviceTokenPrincipals: TEST_APPROVAL_PRINCIPALS,
    approvalSessions: FLOOR_SESSIONS,
    capabilities: new Set([...ALL_PROVIDER_CAPABILITIES, "delegation"]),
  });
  server = as.provider.listen(PORT);
  as.provider.on("server_error", (_ctx: unknown, err: Error) => {
    require("node:fs").appendFileSync("/Users/karl/.claude/jobs/74ec42f1/tmp/dx-server-error.log", `${err.stack}\n`);
  });
  clientKeys.set("ap-agent", (await importJWK(as.agentClientJwk as never, "ES256")) as CryptoKey);
  clientKeys.set(SUBAGENT, (await importJWK(as.childClientJwk as never, "ES256")) as CryptoKey);
  agentDpop = await generateKeyPair("ES256", { extractable: true });
  subagentDpop = await generateKeyPair("ES256", { extractable: true });
});
afterAll(() => server?.close());

describe("delegation by designation: the agent designates, the sub-agent redeems (@spec mission#delegation, mission#designation)", () => {
  it("issues a designation naming the sub-agent, then a delegated token bound to the sub-agent's own key, counting one derivation each", async () => {
    const { missionId, accessToken } = await baseMission();
    const before = derivations(missionId);

    const designation = await designate(accessToken, SUBAGENT);
    expect(designation.status, JSON.stringify(designation.body)).toBe(200);
    expect(designation.body.token_type).toBe("N_A");
    expect(derivations(missionId)).toBe(before + 1);
    const d = decodeJwt(designation.body.access_token as string) as Body;
    expect(d.aud).toBe(SUBAGENT);
    expect(d.may_act).toEqual({ sub: SUBAGENT, iss: ISSUER });
    expect(d.cnf).toBeUndefined();
    expect(d.act).toBeUndefined();
    expect(d.client_id).toBe("ap-agent");
    expect((d.mission as { id: string }).id).toBe(missionId);

    const delegated = await redeem(designation.body.access_token as string);
    expect(delegated.status, JSON.stringify(delegated.body)).toBe(200);
    expect(derivations(missionId)).toBe(before + 2);
    const t = decodeJwt(delegated.body.access_token as string) as Body;
    expect(t.client_id).toBe(SUBAGENT);
    expect((t.cnf as { jkt: string }).jkt).toBe(await jktOf(subagentDpop));
    expect(t.sub).toBe("alice");
    expect(t.mission).toEqual(d.mission);
    expect(t.aud).toBe(RESOURCE);
    expect(t.act).toEqual({ iss: ISSUER, sub: SUBAGENT, sub_profile: "ai_agent client_instance" });
    // Each surviving entry carries its `delegation` member intact, as the Mission recorded it.
    const recorded = (as.kernel.get(missionId)?.authority_set as Body[])[0]?.delegation;
    expect(recorded).toMatchObject(DELEGABLE.delegation);
    expect((t.authorization_details as Body[])[0]?.delegation).toEqual(recorded);

    expect((await introspect(delegated.body.access_token as string)).active).toBe(true);
    expect(await introspect(designation.body.access_token as string)).toEqual({ active: false });
  });
});
