/**
 * @spec mission#approval-event (#1247): every Mission the authorization
 * server creates follows its own approval event, over the real AS assembly.
 * A browser approval leaves the client's user agent a provider session and a
 * Grant; a second Mission submission from that client, Intent-only and with
 * a different goal, must still reach its own Mission approval interaction
 * rather than receive a code under the earlier Grant. Under `prompt=none`
 * it is refused. Carried through approval and redemption, the second
 * submission yields its own Mission, never the first one's.
 *
 * @spec mission#grant-binding-resolution (#1259): the converse. A request
 * carrying no `mission_intent` proposes no Mission, so consent reuse never
 * answers it with a Mission-bound grant, whichever record makes the grant
 * Mission-bound and whichever candidate source names it. With no eligible
 * ordinary grant, this AS refuses: `access_denied` interactively (its only
 * interaction is the Mission approval, a local choice) and `consent_required`
 * under `prompt=none`. An independently ordinary grant still answers, and the
 * earlier Mission's own lineage still continues under its binding.
 *
 * The submissions are Intent-only on the reports resource, whose derived
 * authority is neither write-bearing nor under the approval floor, so Alice
 * approves her own Missions in the browser and `openid` stays available.
 */

import { type Server } from "node:http";
import { CANONICAL_RESOURCE, TOPOLOGY } from "@mission/demo-data";
import { exportJWK, generateKeyPair, importJWK, SignJWT, type CryptoKey, type JWK } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ApprovalSessionStore, buildAuthorizationServer, type BuiltAs } from "../src/index.js";
import { browserApprovalHeaders, renderedRevision, TEST_APPROVAL_PRINCIPALS } from "./approval-fixture.js";
import { delegationHandleParams } from "./delegation-handle.helper.js";

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

/**
 * A pushed authorization request: Intent-only for `goal` on `resource` (the
 * reports resource, with `openid`, unless given), or, with no goal, an
 * ordinary request carrying no `mission_intent`.
 */
async function push(
  goal: string | undefined,
  extra: Record<string, string> = {},
  target: { resource: string; scope?: string } = { resource: PLAIN, scope: "openid" },
): Promise<string> {
  const challenge = Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(VERIFIER))).toString("base64url");
  const res = await fetch(`${ISSUER}/request`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: "ap-agent",
      response_type: "code",
      redirect_uri: REDIRECT_URI,
      resource: target.resource,
      ...(target.scope ? { scope: target.scope } : {}),
      code_challenge: challenge,
      code_challenge_method: "S256",
      ...(goal !== undefined
        ? { mission_intent: JSON.stringify({ intent: { goal, target_resources: [target.resource], expires_at: "2027-01-01T00:00:00Z" } }) }
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
async function authorize(requestUri: string, jar: Jar): Promise<Outcome> {
  const res = await fetch(`${ISSUER}/auth?${new URLSearchParams({ client_id: "ap-agent", request_uri: requestUri })}`, {
    redirect: "manual",
    headers: { cookie: cookieOf(jar) },
  });
  keep(jar, res);
  return outcome(res.headers.get("location") ?? "");
}

type Outcome = { uid?: string; code?: string; error?: string; description?: string; location?: string; status?: number };

function outcome(location: string): Outcome {
  if (location.includes("/interaction/")) return { uid: location.split("/interaction/")[1] as string };
  const q = location ? new URL(location).searchParams : new URLSearchParams();
  return {
    ...(q.get("code") ? { code: q.get("code") as string } : {}),
    ...(q.get("error") ? { error: q.get("error") as string } : {}),
    ...(q.get("error_description") ? { description: q.get("error_description") as string } : {}),
  };
}

/**
 * The user agent follows `url` through every redirect the AS issues (its
 * interactions and resumes) to the client's redirect: the code or error
 * there, with the full redirect `location`. A response that is not a
 * redirect ends the walk with its `status`.
 */
async function walk(url: string, jar: Jar): Promise<Outcome> {
  let next = url;
  for (let hops = 0; hops < 10; hops += 1) {
    const res = await fetch(next, { redirect: "manual", headers: { cookie: cookieOf(jar) } });
    keep(jar, res);
    const location = res.headers.get("location");
    if (!location) return { status: res.status };
    const absolute = new URL(location, ISSUER).toString();
    if (!absolute.startsWith(ISSUER)) return { ...outcome(absolute), location: absolute };
    next = absolute;
  }
  throw new Error("too many redirects");
}

/** The authorization endpoint for `requestUri`, followed in `jar`'s user agent to the client's redirect. */
const authorizeThrough = (requestUri: string, jar: Jar) =>
  walk(`${ISSUER}/auth?${new URLSearchParams({ client_id: "ap-agent", request_uri: requestUri })}`, jar);

/**
 * The approval surface decides the interaction (Alice in the browser unless
 * given), then the resume runs to the client's redirect. The decision names
 * the page rendered to the Approver's session (#1446) unless `render` is
 * false, for an interaction no approval page renders.
 */
async function approve(
  uid: string,
  jar: Jar,
  approver = ALICE as { sub: string; acr?: string; subject?: string },
  render = true,
): Promise<Outcome> {
  const decideHeaders = { ...browserApprovalHeaders(SESSIONS, uid, approver, cookieOf(jar)), "content-type": "application/json" };
  const render_revision = render ? await renderedRevision(ISSUER, uid, decideHeaders) : undefined;
  let res = await fetch(`${ISSUER}/interaction/${uid}/decide`, {
    method: "POST",
    redirect: "manual",
    headers: decideHeaders,
    body: JSON.stringify({ decision: "approve", render_revision }),
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

/** A token request with DPoP under `k` (one nonce retry), authenticated as the client: its status and body. */
async function tokenRequest(params: Record<string, string>, k: Keys): Promise<{ status: number; body: Record<string, unknown> }> {
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
        ...params,
        client_assertion: await clientAssertion(),
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      }).toString(),
    });
  let res = await send();
  const nonce = res.headers.get("dpop-nonce");
  if (res.status === 400 && nonce) res = await send(nonce);
  return { status: res.status, body: (await res.json()) as Record<string, unknown> };
}

/** Redeem a code at the token endpoint with DPoP (under `k`, or a fresh key), expecting success. */
async function redeem(code: string, k?: Keys, resource: string | undefined = PLAIN): Promise<Record<string, unknown>> {
  const { status, body } = await tokenRequest(
    {
      grant_type: "authorization_code",
      code,
      redirect_uri: REDIRECT_URI,
      code_verifier: VERIFIER,
      ...(resource ? { resource } : {}),
    },
    k ?? (await newKeys()),
  );
  expect(status, JSON.stringify(body)).toBe(200);
  return body;
}

/** A JWT's payload (undefined for an opaque token). */
function claimsOf(token: unknown): Record<string, unknown> | undefined {
  const parts = String(token).split(".");
  if (parts.length !== 3) return undefined;
  return JSON.parse(Buffer.from(parts[1] as string, "base64url").toString()) as Record<string, unknown>;
}

/**
 * A user agent that holds Alice's provider session and the Grant of one
 * approved Mission: that Mission's id, its grant, and the tokens its code
 * redeemed to under `keys`.
 */
async function afterFirstApproval(): Promise<{
  jar: Jar;
  firstMission: string;
  grantId: string;
  tokens: Record<string, unknown>;
  keys: Keys;
}> {
  const jar: Jar = new Map();
  const opened = await authorize(await push("Read the quarterly reports"), jar);
  expect(opened.uid, JSON.stringify(opened)).toBeTruthy();
  const approved = await approve(opened.uid as string, jar);
  expect(approved.code, JSON.stringify(approved)).toBeTruthy();
  const keys = await newKeys();
  const tokens = await redeem(approved.code as string, keys);
  expect(jar.get("_session")).toBeTruthy();
  const firstMission = tokens.mission_id as string;
  return { jar, firstMission, grantId: as.kernel.get(firstMission)?.grant_id as string, tokens, keys };
}

/** The grant Alice's provider session in `jar` holds for the client. */
async function sessionGrant(jar: Jar): Promise<string | undefined> {
  const session = await as.provider.Session.find(jar.get("_session") as string);
  return session?.grantIdFor("ap-agent");
}

/** Point Alice's provider session in `jar` at `grantId` as its grant for the client. */
async function holdInSession(jar: Jar, grantId: string): Promise<void> {
  const session = await as.provider.Session.find(jar.get("_session") as string);
  if (!session) throw new Error("no provider session in this user agent");
  session.grantIdFor("ap-agent", grantId);
  await session.persist();
}

/** A provider Grant for Alice and the client covering `openid`, saved outside any approval: Mission-bound only if a test records it so. */
async function plainGrant(): Promise<string> {
  const grant = new as.provider.Grant({ accountId: "alice", clientId: "ap-agent" });
  grant.addOIDCScope("openid");
  return grant.save();
}

/** Count the provider Grants saved while `run` runs. */
async function grantsSavedDuring(run: () => Promise<void>): Promise<number> {
  let saved = 0;
  const onGrant = () => {
    saved += 1;
  };
  as.provider.on("grant.saved", onGrant);
  try {
    await run();
  } finally {
    as.provider.off("grant.saved", onGrant);
  }
  return saved;
}

const derivations = (missionId: string) => as.kernel.get(missionId)?.derivation_count;

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
    expect(refused.code).toBeUndefined();
    expect(refused.uid).toBeUndefined();
    expect(refused).toMatchObject({ error: "consent_required", description: "a Mission submission requires its own Mission approval" });
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

  it("the newly reached interaction applies the approval floor (#1234): a high-risk Intent-only submission in the same user agent is refused at its approval by a password-authenticated Approver, with no code and no Mission", async () => {
    const { jar } = await afterFirstApproval();
    const missions = as.kernel.allMissions().length;
    const highRisk = await authorize(await push("Pay the approved Acme invoices", {}, { resource: CANONICAL_RESOURCE }), jar);
    expect(highRisk.uid, JSON.stringify(highRisk)).toBeTruthy();
    const refused = await approve(highRisk.uid as string, jar, { sub: "bob", acr: "password", subject: "alice" });
    expect(refused.code).toBeUndefined();
    expect(refused.error).toBe("access_denied");
    expect(refused.description).toMatch(/high-risk-authority floor/);
    expect(as.kernel.allMissions()).toHaveLength(missions);
  });
});

describe("a request carrying no mission_intent never reuses a Mission-bound grant (@spec mission#grant-binding-resolution, #1259)", () => {
  /**
   * The refusal's side effects: no code, no Grant saved, no Mission created,
   * no derivation spent on the earlier Mission, nothing about it disclosed,
   * and the excluded grant left as it was.
   */
  async function expectRefusedWithoutEffect(
    run: () => Promise<Outcome>,
    expected: { error: string },
    earlier: { firstMission: string; grantId: string },
  ): Promise<Outcome> {
    const missions = as.kernel.allMissions().length;
    const counted = derivations(earlier.firstMission);
    let refused: Outcome = {};
    const saved = await grantsSavedDuring(async () => {
      refused = await run();
    });
    expect(refused.code, JSON.stringify(refused)).toBeUndefined();
    expect(refused.error, JSON.stringify(refused)).toBe(expected.error);
    expect(saved).toBe(0);
    expect(as.kernel.allMissions()).toHaveLength(missions);
    expect(derivations(earlier.firstMission)).toBe(counted);
    expect(JSON.stringify(refused)).not.toContain(earlier.firstMission);
    expect(JSON.stringify(refused)).not.toContain(earlier.grantId);
    expect(JSON.stringify(refused)).not.toMatch(/mission/i);
    expect(await as.provider.Grant.find(earlier.grantId)).toBeTruthy();
    return refused;
  }

  it("with only the earlier Mission's grant in the user agent, an otherwise valid interactive request is refused access_denied: no code, no Grant, no Mission, no derivation and no disclosure, and the Mission's grant stays bound and held", async () => {
    const earlier = await afterFirstApproval();
    expect(await sessionGrant(earlier.jar)).toBe(earlier.grantId);
    await expectRefusedWithoutEffect(async () => authorizeThrough(await push(undefined), earlier.jar), { error: "access_denied" }, earlier);
    expect(as.kernel.findByGrant(earlier.grantId)?.id).toBe(earlier.firstMission);
    expect(await sessionGrant(earlier.jar)).toBe(earlier.grantId);
  });

  it("under prompt=none the same request is refused consent_required, with the same absence of effects", async () => {
    const earlier = await afterFirstApproval();
    await expectRefusedWithoutEffect(
      async () => authorize(await push(undefined, { prompt: "none" }), earlier.jar),
      { error: "consent_required" },
      earlier,
    );
    expect(as.kernel.findByGrant(earlier.grantId)?.id).toBe(earlier.firstMission);
  });

  it("a Mission's own grant is excluded even where the bound-grant index lacks it (the record's grant_id alone)", async () => {
    const earlier = await afterFirstApproval();
    as.kernel.missionBoundGrants.db.prepare("DELETE FROM mission_bound_grants WHERE grant_id = ?").run(earlier.grantId);
    expect(as.kernel.missionBoundGrants.resolve(earlier.grantId)).toBeUndefined();
    await expectRefusedWithoutEffect(async () => authorizeThrough(await push(undefined), earlier.jar), { error: "access_denied" }, earlier);
  });

  it("a delegation-family grant is excluded, its family terminal and the bound-grant index silent: the family record alone suffices", async () => {
    const earlier = await afterFirstApproval();
    const family = await plainGrant();
    as.delegationFamilyStore.record({ grantId: family, missionId: earlier.firstMission });
    as.delegationFamilyStore.invalidate(family);
    expect(as.delegationFamilyStore.resolve(family)).toBeUndefined();
    expect(as.kernel.missionBoundGrants.resolve(family)).toBeUndefined();
    await holdInSession(earlier.jar, family);
    await expectRefusedWithoutEffect(async () => authorizeThrough(await push(undefined), earlier.jar), { error: "access_denied" }, {
      ...earlier,
      grantId: family,
    });
    expect(await sessionGrant(earlier.jar)).toBe(family);
  });

  it("a grant the bound-grant index lists whose Mission no longer resolves is excluded and refused cleanly, never a server error", async () => {
    const earlier = await afterFirstApproval();
    const orphan = await plainGrant();
    as.kernel.missionBoundGrants.record({ grantId: orphan, missionId: "mis_no_longer_resolves", kind: "approval" });
    expect(as.kernel.get("mis_no_longer_resolves")).toBeUndefined();
    await holdInSession(earlier.jar, orphan);
    await expectRefusedWithoutEffect(async () => authorizeThrough(await push(undefined), earlier.jar), { error: "access_denied" }, {
      ...earlier,
      grantId: orphan,
    });
  });

  it("an explicit consent-result candidate naming the Mission's grant is excluded too: the resume issues no code under it (the result is seeded: no reference surface finishes an ordinary interaction with consent)", async () => {
    const earlier = await afterFirstApproval();
    const opened = await authorize(await push(undefined), earlier.jar);
    expect(opened.uid, JSON.stringify(opened)).toBeTruthy();
    const interaction = await as.provider.Interaction.find(opened.uid as string);
    if (!interaction) throw new Error("no interaction");
    interaction.result = { consent: { grantId: earlier.grantId } };
    await interaction.save(Math.max(1, (interaction.exp ?? 0) - Math.floor(Date.now() / 1000)));
    await expectRefusedWithoutEffect(async () => walk(`${ISSUER}/auth/${opened.uid}`, earlier.jar), { error: "access_denied" }, earlier);
  });

  it("an independently ordinary grant still answers an ordinary request: its code redeems to ordinary authority with no Mission binding, and the earlier Mission's accounting is unchanged", async () => {
    const earlier = await afterFirstApproval();
    const ordinaryGrant = await plainGrant();
    await holdInSession(earlier.jar, ordinaryGrant);
    const missions = as.kernel.allMissions().length;
    const counted = derivations(earlier.firstMission);
    const answered = await authorize(await push(undefined), earlier.jar);
    expect(answered.uid, JSON.stringify(answered)).toBeUndefined();
    expect(answered.code, JSON.stringify(answered)).toBeTruthy();
    const stored = (await as.provider.AuthorizationCode.find(answered.code as string)) as { grantId?: string } | undefined;
    expect(stored?.grantId).toBe(ordinaryGrant);
    const tokens = await redeem(answered.code as string, undefined, undefined);
    // The ordinary grant's authority: `openid` (an ID Token about Alice), and
    // an access token with no Mission, no authorization_details and no
    // resource scope.
    expect(claimsOf(tokens.id_token)?.sub).toBe("alice");
    expect(tokens).not.toHaveProperty("mission_id");
    expect(tokens).not.toHaveProperty("mission_expires_at");
    expect(tokens).not.toHaveProperty("authorization_details");
    expect(tokens.scope ?? "").toBe("");
    const access = claimsOf(tokens.access_token);
    expect(access?.sub).toBe("alice");
    expect(access).not.toHaveProperty("mission");
    expect(access).not.toHaveProperty("authorization_details");
    expect(access).not.toHaveProperty("scope");
    expect(JSON.stringify(tokens)).not.toContain(earlier.firstMission);
    expect(as.kernel.findByGrant(ordinaryGrant)).toBeUndefined();
    expect(as.kernel.missionBoundGrants.resolve(ordinaryGrant)).toBeUndefined();
    expect(as.kernel.allMissions()).toHaveLength(missions);
    expect(derivations(earlier.firstMission)).toBe(counted);
  });

  it("the earlier Mission's own lineage still continues after a refused ordinary request: its refresh and a Token Exchange of its token stay bound to it, each counting one derivation", async () => {
    const earlier = await afterFirstApproval();
    expect(claimsOf(earlier.tokens.access_token)?.mission).toMatchObject({ id: earlier.firstMission });
    expect(derivations(earlier.firstMission)).toBe(1);
    const refused = await authorizeThrough(await push(undefined), earlier.jar);
    expect(refused.error).toBe("access_denied");
    const refreshed = await tokenRequest(
      { grant_type: "refresh_token", refresh_token: earlier.tokens.refresh_token as string, resource: PLAIN },
      earlier.keys,
    );
    expect(refreshed.status, JSON.stringify(refreshed.body)).toBe(200);
    expect(claimsOf(refreshed.body.access_token)?.mission).toMatchObject({ id: earlier.firstMission });
    expect(derivations(earlier.firstMission)).toBe(2);
    const exchanged = await tokenRequest(delegationHandleParams(refreshed.body.access_token as string, "ap-agent"), earlier.keys);
    expect(exchanged.status, JSON.stringify(exchanged.body)).toBe(200);
    expect(claimsOf(exchanged.body.access_token)?.mission).toMatchObject({ id: earlier.firstMission });
    expect(derivations(earlier.firstMission)).toBe(3);
  });

  it("an unauthenticated interactive request is refused access_denied through the authorization response, never a server error from the Mission approval surface", async () => {
    const jar: Jar = new Map();
    const missions = as.kernel.allMissions().length;
    const refused = await authorizeThrough(await push(undefined), jar);
    expect(refused.status, JSON.stringify(refused)).toBeUndefined();
    expect(refused.code).toBeUndefined();
    expect(refused.error, JSON.stringify(refused)).toBe("access_denied");
    expect(refused.location?.startsWith(`${REDIRECT_URI}?`)).toBe(true);
    expect(as.kernel.allMissions()).toHaveLength(missions);
  });

  it("authentication errors keep their precedence: an unauthenticated prompt=none request is refused login_required", async () => {
    const refused = await authorize(await push(undefined, { prompt: "none" }), new Map());
    expect(refused.code).toBeUndefined();
    expect(refused.error, JSON.stringify(refused)).toBe("login_required");
  });

  it("a decision posted on an ordinary request's interaction finishes it refused access_denied, never a server error", async () => {
    const earlier = await afterFirstApproval();
    const opened = await authorize(await push(undefined), earlier.jar);
    expect(opened.uid, JSON.stringify(opened)).toBeTruthy();
    // Rendering an ordinary request's interaction finishes it refused, so the
    // decision is posted unrendered: it is refused before any rendering is consulted.
    await expectRefusedWithoutEffect(async () => approve(opened.uid as string, earlier.jar, ALICE, false), { error: "access_denied" }, earlier);
  });
});
