/**
 * @spec mission#approval-event (#1247): every Mission the authorization
 * server creates follows its own approval event, over the real AS assembly.
 * A browser approval leaves the client's user agent a provider session and a
 * Grant; a second Mission submission from that client, Intent-only and with
 * a different goal, must still reach its own Mission approval interaction
 * rather than receive a code under the earlier Grant. Under `prompt=none`
 * it is refused. Carried through approval and redemption, the second
 * submission yields its own Mission, never the first one's. An ordinary
 * request without `mission_intent` keeps oidc-provider's consent reuse.
 *
 * The submissions are Intent-only on the reports resource, whose derived
 * authority is neither write-bearing nor under the approval floor, so Alice
 * approves her own Missions in the browser and `openid` stays available.
 */

import { type Server } from "node:http";
import { TOPOLOGY } from "@mission/demo-data";
import { exportJWK, generateKeyPair, importJWK, SignJWT, type CryptoKey, type JWK } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ApprovalSessionStore, buildAuthorizationServer, type BuiltAs } from "../src/index.js";
import { browserApprovalHeaders, TEST_APPROVAL_PRINCIPALS } from "./approval-fixture.js";

const PORT = 14848;
const ISSUER = `http://localhost:${PORT}`;
const REDIRECT_URI = "http://localhost:9999/cb";
const PLAIN = TOPOLOGY.resources.plainRs;
const VERIFIER = "mission-approval-interaction-verifier-0123456789-0123";
const SESSIONS = new ApprovalSessionStore();
const ALICE = { sub: "alice", acr: "mfa" };

let as: BuiltAs;
let server: Server;
let clientKey: CryptoKey;

beforeAll(async () => {
  as = await buildAuthorizationServer({
    issuer: ISSUER,
    allowHeadlessAdjudication: true,
    serviceTokenPrincipals: TEST_APPROVAL_PRINCIPALS,
    approvalSessions: SESSIONS,
  });
  server = as.provider.listen(PORT);
  clientKey = (await importJWK(as.agentClientJwk as never, "ES256")) as CryptoKey;
});

afterAll(() => {
  server?.close();
});

type Jar = Map<string, string>;
const cookieOf = (jar: Jar) => [...jar].map(([k, v]) => `${k}=${v}`).join("; ");
const keep = (jar: Jar, res: Response) => {
  for (const line of res.headers.getSetCookie()) {
    const [pair] = line.split(";");
    const eq = (pair as string).indexOf("=");
    jar.set((pair as string).slice(0, eq), (pair as string).slice(eq + 1));
  }
};

const clientAssertion = () =>
  new SignJWT({})
    .setProtectedHeader({ alg: "ES256", kid: "ap-agent-auth" })
    .setIssuer("ap-agent")
    .setSubject("ap-agent")
    .setAudience(ISSUER)
    .setIssuedAt()
    .setExpirationTime("2m")
    .setJti(crypto.randomUUID())
    .sign(clientKey);

/** A pushed authorization request: Intent-only for `goal`, or, with no goal, an ordinary request carrying no `mission_intent`. */
async function push(goal: string | undefined, extra: Record<string, string> = {}): Promise<string> {
  const challenge = Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(VERIFIER))).toString("base64url");
  const res = await fetch(`${ISSUER}/request`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: "ap-agent",
      response_type: "code",
      redirect_uri: REDIRECT_URI,
      resource: PLAIN,
      scope: "openid",
      code_challenge: challenge,
      code_challenge_method: "S256",
      ...(goal !== undefined
        ? { mission_intent: JSON.stringify({ intent: { goal, target_resources: [PLAIN], expires_at: "2027-01-01T00:00:00Z" } }) }
        : {}),
      ...extra,
      client_assertion: await clientAssertion(),
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    }).toString(),
  });
  const body = (await res.json()) as { request_uri?: string };
  expect(res.status, JSON.stringify(body)).toBe(201);
  return body.request_uri as string;
}

/** The authorization endpoint in `jar`'s user agent: the interaction it opens, or the code or error it returns to the client. */
async function authorize(requestUri: string, jar: Jar): Promise<{ uid?: string; code?: string; error?: string }> {
  const res = await fetch(`${ISSUER}/auth?${new URLSearchParams({ client_id: "ap-agent", request_uri: requestUri })}`, {
    redirect: "manual",
    headers: { cookie: cookieOf(jar) },
  });
  keep(jar, res);
  return outcome(res.headers.get("location") ?? "");
}

function outcome(location: string): { uid?: string; code?: string; error?: string } {
  if (location.includes("/interaction/")) return { uid: location.split("/interaction/")[1] as string };
  const q = location ? new URL(location).searchParams : new URLSearchParams();
  return { ...(q.get("code") ? { code: q.get("code") as string } : {}), ...(q.get("error") ? { error: q.get("error") as string } : {}) };
}

/** Alice approves the interaction in the browser, then the resume runs to the client's redirect. */
async function approve(uid: string, jar: Jar): Promise<{ code?: string; error?: string }> {
  let res = await fetch(`${ISSUER}/interaction/${uid}/decide`, {
    method: "POST",
    redirect: "manual",
    headers: { ...browserApprovalHeaders(SESSIONS, uid, ALICE, cookieOf(jar)), "content-type": "application/json" },
    body: JSON.stringify({ decision: "approve" }),
  });
  expect(res.status, await res.clone().text()).toBeLessThan(400);
  keep(jar, res);
  let location = res.headers.get("location") ?? "";
  while (location.startsWith(ISSUER)) {
    res = await fetch(location, { redirect: "manual", headers: { cookie: cookieOf(jar) } });
    keep(jar, res);
    location = res.headers.get("location") ?? "";
  }
  return outcome(location);
}

type Keys = { privateKey: CryptoKey; jwk: JWK };
const newKeys = async (): Promise<Keys> => {
  const pair = await generateKeyPair("ES256", { extractable: true });
  return { privateKey: pair.privateKey as CryptoKey, jwk: await exportJWK(pair.publicKey) };
};

/** Redeem a code at the token endpoint with DPoP (one nonce retry). */
async function redeem(code: string): Promise<Record<string, unknown>> {
  const k = await newKeys();
  const htu = `${ISSUER}/token`;
  const proof = (nonce?: string) =>
    new SignJWT({ htu, htm: "POST", ...(nonce ? { nonce } : {}) })
      .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: k.jwk })
      .setIssuedAt()
      .setJti(crypto.randomUUID())
      .sign(k.privateKey);
  const send = async (nonce?: string) =>
    fetch(htu, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", dpop: await proof(nonce) },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: REDIRECT_URI,
        code_verifier: VERIFIER,
        resource: PLAIN,
        client_assertion: await clientAssertion(),
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      }).toString(),
    });
  let res = await send();
  const nonce = res.headers.get("dpop-nonce");
  if (res.status === 400 && nonce) res = await send(nonce);
  const body = (await res.json()) as Record<string, unknown>;
  expect(res.status, JSON.stringify(body)).toBe(200);
  return body;
}

/** A user agent that holds Alice's provider session and the Grant of one approved Mission, with that Mission's id. */
async function afterFirstApproval(): Promise<{ jar: Jar; firstMission: string }> {
  const jar: Jar = new Map();
  const opened = await authorize(await push("Read the quarterly reports"), jar);
  expect(opened.uid, JSON.stringify(opened)).toBeTruthy();
  const approved = await approve(opened.uid as string, jar);
  expect(approved.code, JSON.stringify(approved)).toBeTruthy();
  const tokens = await redeem(approved.code as string);
  expect(jar.get("_session")).toBeTruthy();
  return { jar, firstMission: tokens.mission_id as string };
}

describe("a new Mission submission reaches its own approval despite prior browser consent (@spec mission#approval-event, #1247)", () => {
  it("a second Intent-only submission with a different goal, in a user agent holding the first approval's session and Grant, opens the Mission approval interaction: no code, no Mission and no Grant until it is approved", async () => {
    const { jar } = await afterFirstApproval();
    const missions = as.kernel.allMissions().length;
    let grantsSaved = 0;
    const onGrant = () => {
      grantsSaved += 1;
    };
    as.provider.on("grant.saved", onGrant);
    try {
      const second = await authorize(await push("Publish a report no one approved"), jar);
      expect(second.code, JSON.stringify(second)).toBeUndefined();
      expect(second.uid, JSON.stringify(second)).toBeTruthy();
    } finally {
      as.provider.off("grant.saved", onGrant);
    }
    expect(as.kernel.allMissions()).toHaveLength(missions);
    expect(grantsSaved).toBe(0);
  });

  it("under prompt=none the second submission is refused consent_required, with no code and no Mission", async () => {
    const { jar } = await afterFirstApproval();
    const missions = as.kernel.allMissions().length;
    const refused = await authorize(await push("Publish a report no one approved", { prompt: "none" }), jar);
    expect(refused).toEqual({ error: "consent_required" });
    expect(as.kernel.allMissions()).toHaveLength(missions);
  });

  it("approved and redeemed, the second submission yields its own Mission, never the first one's", async () => {
    const { jar, firstMission } = await afterFirstApproval();
    const second = await authorize(await push("Publish the quarterly reports"), jar);
    expect(second.uid, JSON.stringify(second)).toBeTruthy();
    const approved = await approve(second.uid as string, jar);
    expect(approved.code, JSON.stringify(approved)).toBeTruthy();
    const tokens = await redeem(approved.code as string);
    expect(tokens.mission_id).toBeTruthy();
    expect(tokens.mission_id).not.toBe(firstMission);
    const created = as.kernel.allMissions().find((m) => m.id === tokens.mission_id);
    expect(JSON.stringify(created)).toContain("Publish the quarterly reports");
  });

  it("an ordinary request carrying no mission_intent keeps consent reuse: the session's Grant answers it with a code and no interaction", async () => {
    const { jar } = await afterFirstApproval();
    const ordinary = await authorize(await push(undefined), jar);
    expect(ordinary.uid, JSON.stringify(ordinary)).toBeUndefined();
    expect(ordinary.code, JSON.stringify(ordinary)).toBeTruthy();
  });
});
