/**
 * SPIKE (#869 Sketch step 1, never merged). Can the AS mint an access token for
 * one client (the delegate) under a grant another client owns (the source
 * token's recorded grant), and do save(), the save-time hook and introspection
 * accept it? Does revoking that source grant, or invalidating an async family,
 * make the delegate's token introspect inactive while the Mission stays active?
 */
import { FIXTURE_BROWSER_LOGIN, floorApprovalHeaders, TEST_APPROVAL_PRINCIPALS } from "./approval-fixture.js";
import { ApprovalSessionStore } from "../src/index.js";

import { appendFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { type Server } from "node:http";
import { CANONICAL_RESOURCE } from "@mission/demo-data";
import { calculateJwkThumbprint, decodeJwt, exportJWK, generateKeyPair, importJWK, SignJWT } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { TOKEN_EXCHANGE_GRANT_TYPE, ACCESS_TOKEN_TOKEN_TYPE } from "../src/adapters/continuation-grant.js";
import { buildAuthorizationServer, type BuiltAs } from "../src/index.js";

void FIXTURE_BROWSER_LOGIN;
const FLOOR_SESSIONS = new ApprovalSessionStore();
const spikeLog = (...a: unknown[]): void => appendFileSync(process.env.SPIKE_LOG ?? join(tmpdir(), "spike-869-observations.log"), a.join(" ") + "\n");
const PORT = 14869;
const ISSUER = `http://localhost:${PORT}`;
const REDIRECT_URI = "http://localhost:9999/cb";
const RESOURCE = CANONICAL_RESOURCE;
const RS_PAYMENTS = ["rs-payments", "dev-introspection-rs-payments"] as const;
const AUTHORITY = [
  {
    type: "mission_resource_access",
    resource: RESOURCE,
    actions: ["payments:invoice.read"],
    constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
  },
];

type Keys = { privateKey: CryptoKey; publicKey: CryptoKey };
let as: BuiltAs;
let server: Server;
let agentKey: CryptoKey;
let subagentKey: CryptoKey;
let agentDpop: Keys;
let subagentDpop: Keys;

const assertion = (client: "ap-agent" | "subagent-invoice-extractor") =>
  new SignJWT({})
    .setProtectedHeader({ alg: "ES256", kid: `${client}-auth` })
    .setIssuer(client)
    .setSubject(client)
    .setAudience(ISSUER)
    .setIssuedAt()
    .setExpirationTime("2m")
    .setJti(crypto.randomUUID())
    .sign(client === "ap-agent" ? agentKey : subagentKey);

async function proof(keys: Keys, extra: Record<string, unknown> = {}): Promise<string> {
  return new SignJWT({ htu: `${ISSUER}/token`, htm: "POST", ...extra })
    .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: await exportJWK(keys.publicKey) })
    .setIssuedAt()
    .setJti(crypto.randomUUID())
    .sign(keys.privateKey);
}

async function token(
  client: "ap-agent" | "subagent-invoice-extractor",
  keys: Keys,
  params: Record<string, string>,
): Promise<{ status: number; body: Record<string, unknown> }> {
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
  return { status: res.status, body: (await res.json()) as Record<string, unknown> };
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
async function baseMission(): Promise<{ missionId: string; accessToken: string }> {
  const jar = new Map<string, string>();
  const verifier = "spike-869-verifier-0123456789-0123456789-0123456789";
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
      authorization_details: JSON.stringify(AUTHORITY),
      client_assertion: await assertion("ap-agent"),
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    }).toString(),
  });
  const { request_uri } = (await par.json()) as { request_uri: string };
  let res = await fetch(`${ISSUER}/auth?${new URLSearchParams({ client_id: "ap-agent", request_uri })}`, { redirect: "manual" });
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

/** The spike mint: the sub-agent, with its own key, under the subject token's recorded grant. */
const spikeMint = (subjectToken: string) =>
  token("subagent-invoice-extractor", subagentDpop, {
    grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
    subject_token: subjectToken,
    subject_token_type: ACCESS_TOKEN_TOKEN_TYPE,
    requested_token_type: "urn:spike:delegated-mint",
    resource: RESOURCE,
  });

async function introspect(tokenValue: string): Promise<Record<string, unknown>> {
  const res = await fetch(`${ISSUER}/introspect`, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      authorization: `Basic ${Buffer.from(`${RS_PAYMENTS[0]}:${RS_PAYMENTS[1]}`).toString("base64")}`,
    },
    body: new URLSearchParams({ token: tokenValue }).toString(),
  });
  expect(res.status).toBe(200);
  return (await res.json()) as Record<string, unknown>;
}

const derivations = (missionId: string) => (as.kernel.get(missionId) as { derivation_count?: number }).derivation_count ?? 0;

beforeAll(async () => {
  as = await buildAuthorizationServer({
    issuer: ISSUER,
    allowHeadlessAdjudication: true,
    serviceTokenPrincipals: TEST_APPROVAL_PRINCIPALS,
    approvalSessions: FLOOR_SESSIONS,
  });
  server = as.provider.listen(PORT);
  agentKey = (await importJWK(as.agentClientJwk as never, "ES256")) as CryptoKey;
  subagentKey = (await importJWK(as.childClientJwk as never, "ES256")) as CryptoKey;
  agentDpop = await generateKeyPair("ES256", { extractable: true });
  subagentDpop = await generateKeyPair("ES256", { extractable: true });
});
afterAll(() => server?.close());

describe("SPIKE #869: minting for the delegate under another client's recorded grant", () => {
  it("under the approval grant: accepted, the delegate's own key and client_id, introspects active, and inactive once that grant is revoked while the Mission stays active", async () => {
    const { missionId, accessToken } = await baseMission();
    const approvalGrant = as.kernel.get(missionId)?.grant_id as string;
    const before = derivations(missionId);
    const minted = await spikeMint(accessToken);
    expect(minted.status, JSON.stringify(minted.body)).toBe(200);
    const after = derivations(missionId);
    const claims = decodeJwt(minted.body.access_token as string) as Record<string, unknown>;
    spikeLog("SPIKE approval:", JSON.stringify({ grant: minted.body.spike_grant_id === approvalGrant, countDelta: after - before, client_id: claims.client_id, sub: claims.sub, mission: claims.mission, aud: claims.aud }));
    expect(minted.body.spike_grant_id).toBe(approvalGrant);
    expect(claims.client_id).toBe("subagent-invoice-extractor");
    expect((claims.cnf as { jkt: string }).jkt).toBe(await calculateJwkThumbprint(await exportJWK(subagentDpop.publicKey)));
    expect((claims.mission as { id: string }).id).toBe(missionId);
    expect((await introspect(minted.body.access_token as string)).active).toBe(true);

    await (await as.provider.Grant.find(approvalGrant))?.destroy();
    expect(as.kernel.get(missionId)?.state).toBe("active");
    const revoked = await introspect(minted.body.access_token as string);
    spikeLog("SPIKE approval after grant revoke:", JSON.stringify(revoked));
    expect(revoked.active).toBe(false);
  });

  it("under an async family: accepted, introspects active, and inactive once the family is invalidated while the Mission stays active", async () => {
    const { missionId, accessToken } = await baseMission();
    const handle = await token("ap-agent", agentDpop, {
      grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
      subject_token: accessToken,
      subject_token_type: ACCESS_TOKEN_TOKEN_TYPE,
      requested_token_type: ACCESS_TOKEN_TOKEN_TYPE,
      audience: "ap-agent",
    });
    expect(handle.status, JSON.stringify(handle.body)).toBe(200);
    const family = await token("ap-agent", agentDpop, {
      grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
      request_refresh_token: "true",
      subject_token: handle.body.access_token as string,
      subject_token_type: ACCESS_TOKEN_TOKEN_TYPE,
      resource: RESOURCE,
      creation_request_id: crypto.randomUUID(),
    });
    expect(family.status, JSON.stringify(family.body)).toBe(200);
    const familyToken = family.body.access_token as string;
    const before = derivations(missionId);
    const minted = await spikeMint(familyToken);
    expect(minted.status, JSON.stringify(minted.body)).toBe(200);
    const after = derivations(missionId);
    const familyGrant = minted.body.spike_grant_id as string;
    spikeLog("SPIKE family:", JSON.stringify({ isFamily: as.delegationFamilyStore.wasEverFamily(familyGrant), countDelta: after - before, client_id: (decodeJwt(minted.body.access_token as string) as Record<string, unknown>).client_id }));
    expect(as.delegationFamilyStore.wasEverFamily(familyGrant)).toBe(true);
    expect((await introspect(minted.body.access_token as string)).active).toBe(true);

    as.delegationFamilyStore.invalidate(familyGrant);
    expect(as.kernel.get(missionId)?.state).toBe("active");
    const invalidated = await introspect(minted.body.access_token as string);
    spikeLog("SPIKE family after invalidate:", JSON.stringify(invalidated));
    expect(invalidated.active).toBe(false);
  });
});
