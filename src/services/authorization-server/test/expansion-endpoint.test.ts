/**
 * @spec draft-mcguinness-oauth-mission-expansion (#expansion, #deferred-window),
 * containment#restoration
 *
 * Mission EXPANSION wired onto the real OAuth surface as an RFC 8693 token
 * exchange (before this, expansion had NO wire path). The requester presents the
 * predecessor's Mission-bound ACCESS token as `subject_token`
 * (`subject_token_type` = access_token) at /token under grant_type=token-exchange
 * with requested_token_type=access_token, authenticating with private_key_jwt and
 * proving possession with a DPoP proof over that token's OWN confirmation key. The
 * predecessor is resolved FROM `subject_token`. Expansion ALWAYS widens and
 * ALWAYS requires a fresh approval:
 *   - a NON-WIDENING request (a pure subset of the predecessor's effective set)
 *     is REFUSED (invalid_request + mission_denial_reason nothing_to_expand):
 *     ordinary token derivation already serves it, and an expansion response
 *     must never ambiguously be a non-successor (#486);
 *   - DEFERRED via the DTR substrate when the request WIDENS (fresh async
 *     approval): authorization_pending + deferral_code, poll, then a successor.
 * Deferred-window checks proven here (@spec #deferred-window):
 *   (a) the predecessor STATE is re-verified AT completion: a predecessor revoked
 *       during the window fails; containment that ADVANCED during the window
 *       fails; a predecessor ALREADY contained at request time still completes
 *       (the check is a containment-version DELTA, not a presence test);
 *   (b) the poll completes with only deferral_code + DPoP and NO subject_token:
 *       the short-lived subject_token's expiry MUST NOT gate completion.
 * Possession negatives: a refresh token as subject_token and a wrong-key DPoP
 * proof are both refused (#448).
 */

import { type Server } from "node:http";
import { CANONICAL_RESOURCE } from "@mission/demo-data";
import {
  createRemoteJWKSet,
  decodeJwt,
  type CryptoKey,
  exportJWK,
  generateKeyPair,
  importJWK,
  jwtVerify,
  SignJWT,
} from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  ACCESS_TOKEN_TOKEN_TYPE,
  REFRESH_TOKEN_TOKEN_TYPE,
  TOKEN_EXCHANGE_GRANT_TYPE,
} from "../src/adapters/continuation-grant.js";
import {
  buildAuthorizationServer,
  type BuiltAs,
  createChildMission,
  registerIntentSubmissionEvidenceType,
  unregisterIntentSubmissionEvidenceType,
} from "../src/index.js";

const PORT = 14485;
const ISSUER = `http://localhost:${PORT}`;
const REDIRECT_URI = "http://localhost:9999/cb";
const RESOURCE = CANONICAL_RESOURCE;
const FAR_EXP = "2027-01-01T00:00:00Z";

type DpopKeys = { privateKey: CryptoKey; publicKey: CryptoKey };

let as: BuiltAs;
let asServer: Server;
let clientKey: CryptoKey;
let dpopKeys: DpopKeys;
let remoteJwks: ReturnType<typeof createRemoteJWKSet>;
let apev = 0;

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

async function dpopProof(htu: string, htm: string, extra: Record<string, unknown> = {}): Promise<string> {
  return new SignJWT({ htu, htm, ...extra })
    .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: await exportJWK(dpopKeys.publicKey) })
    .setIssuedAt()
    .setJti(crypto.randomUUID())
    .sign(dpopKeys.privateKey);
}

/** POST /token with ap-agent private_key_jwt + DPoP (dpopKeys), with the dpop-nonce retry. */
async function tokenRequest(params: Record<string, string>): Promise<Response> {
  const htu = `${ISSUER}/token`;
  const send = async (extra: Record<string, unknown> = {}): Promise<Response> =>
    fetch(htu, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", dpop: await dpopProof(htu, "POST", extra) },
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

/** POST /token token-exchange with a DPoP proof signed by an ARBITRARY key (nonce retry). */
async function tokenRequestWithDpop(dpop: DpopKeys, params: Record<string, string>): Promise<Response> {
  const htu = `${ISSUER}/token`;
  const proof = async (extra: Record<string, unknown>): Promise<string> =>
    new SignJWT({ htu, htm: "POST", ...extra })
      .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: await exportJWK(dpop.publicKey) })
      .setIssuedAt()
      .setJti(crypto.randomUUID())
      .sign(dpop.privateKey);
  const send = async (extra: Record<string, unknown> = {}): Promise<Response> =>
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

const authority = (actions: string[]) => [
  {
    type: "mission_resource_access",
    resource: RESOURCE,
    actions,
    constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
  },
];

// @spec mission#submission-via-par — the wire value is the Submission envelope.
const intentJson = (goal: string, _actions: string[], expiresAt: string = FAR_EXP): string =>
  JSON.stringify({ intent: { goal, target_resources: [RESOURCE], expires_at: expiresAt } });

/**
 * Full PAR -> interactive approval -> code -> token dance yielding an ACTIVE
 * predecessor Mission and its DPoP-bound (dpopKeys) Mission ACCESS token. The
 * approved actions parametrize whether a later expansion widens or is refused
 * as non-widening.
 */
async function issuePredecessor(actions: string[]): Promise<{ missionId: string; accessToken: string }> {
  const jar = new Map<string, string>();
  const verifier = "expansion-endpoint-verifier-0123456789-0123456789";
  const challenge = Buffer.from(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)),
  ).toString("base64url");
  const par = await fetch(`${ISSUER}/request`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: "ap-agent",
      response_type: "code",
      redirect_uri: REDIRECT_URI,
      scope: "payments",
      resource: RESOURCE,
      code_challenge: challenge,
      code_challenge_method: "S256",
      mission_intent: intentJson("Pay Acme invoices", actions),
      authorization_details: JSON.stringify(authority(actions)),
      client_assertion: await clientAssertion(),
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    }).toString(),
  });
  const { request_uri } = (await par.json()) as { request_uri: string };

  let res = await fetch(`${ISSUER}/auth?${new URLSearchParams({ client_id: "ap-agent", request_uri })}`, {
    redirect: "manual",
  });
  storeCookies(res, jar);
  let location = res.headers.get("location") as string;
  const uid = location.split("/interaction/")[1] as string;

  res = await fetch(`${ISSUER}/interaction/${uid}/decide`, {
    method: "POST",
    redirect: "manual",
    headers: { "content-type": "application/json", cookie: cookieHeader(jar) },
    body: JSON.stringify({ decision: "approve", approver: "bob", subject: "alice" }),
  });
  storeCookies(res, jar);
  location = res.headers.get("location") as string;
  while (location?.startsWith(ISSUER)) {
    res = await fetch(location, { redirect: "manual", headers: { cookie: cookieHeader(jar) } });
    storeCookies(res, jar);
    location = res.headers.get("location") as string;
  }
  const code = new URL(location).searchParams.get("code") as string;

  const tok = await tokenRequest({
    grant_type: "authorization_code",
    code,
    redirect_uri: REDIRECT_URI,
    code_verifier: verifier,
    resource: RESOURCE,
  });
  const body = (await tok.json()) as { access_token: string };
  expect(tok.status, JSON.stringify(body)).toBe(200);
  const claims = decodeJwt(body.access_token) as { mission: { id: string } };
  return { missionId: claims.mission.id, accessToken: body.access_token };
}

/** Open an expansion exchange (requested_token_type=access_token). */
async function expandViaExchange(
  subjectToken: string,
  goal: string,
  actions: string[],
  creationRequestId?: string,
  /** The widening submission's requested ceiling; FAR_EXP unless overridden. */
  expiresAt?: string,
): Promise<Response> {
  return tokenRequest({
    grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
    subject_token: subjectToken,
    subject_token_type: ACCESS_TOKEN_TOKEN_TYPE,
    requested_token_type: ACCESS_TOKEN_TOKEN_TYPE,
    mission_intent: intentJson(goal, actions, expiresAt),
    authorization_details: JSON.stringify(authority(actions)),
    // @spec expansion#creation-request-id — REQUIRED on every initiation.
    creation_request_id: creationRequestId ?? crypto.randomUUID(),
  });
}

/** Poll a deferred expansion: deferral_code + DPoP only, NO subject_token (check (b)). */
async function pollExpansion(deferralCode: string): Promise<Response> {
  return tokenRequest({
    grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
    requested_token_type: ACCESS_TOKEN_TOKEN_TYPE,
    deferral_code: deferralCode,
  });
}

function approveDeferral(deferralCode: string): void {
  as.expansionDeferrals.approve(deferralCode, {
    approver: { iss: ISSUER, sub: "bob" },
    approvalEventId: `apev-exp-${apev++}`,
    approvedUntil: FAR_EXP,
  });
}

const containEvent = (id: string) => ({
  type: "tainted_read" as const,
  source: "https://siem.example/detections",
  observed_at: "2026-07-02T00:00:00Z",
  event_id: id,
});

beforeAll(async () => {
  as = await buildAuthorizationServer({ issuer: ISSUER, allowHeadlessAdjudication: true });
  asServer = as.provider.listen(PORT);
  clientKey = (await importJWK(as.agentClientJwk as never, "ES256")) as CryptoKey;
  dpopKeys = await generateKeyPair("ES256", { extractable: true });
  remoteJwks = createRemoteJWKSet(new URL(`${ISSUER}/jwks`));
});

afterAll(() => {
  asServer?.close();
});

describe("expansion wire: NON-WIDENING request is REFUSED (@spec expansion#nothing-to-expand)", () => {
  it("a pure subset request refuses (invalid_request + nothing_to_expand): predecessor stays active, nothing created or reserved, no derivation consumed", async () => {
    const pred = await issuePredecessor(["payments:invoice.read", "payments:remittance.send"]);
    const before = as.kernel.get(pred.missionId);
    expect(before?.state).toBe("active");
    const derivationCountBefore = before?.derivation_count as number;
    const missionCountBefore = as.kernel.allMissions().length;

    // Expansion ALWAYS widens: a request whose derived authority is a subset of
    // the predecessor's own effective set has NOTHING to expand (ordinary token
    // derivation already serves it), and an expansion response must never
    // ambiguously be a non-successor (#486). No synchronous completion exists.
    const crid = crypto.randomUUID();
    const res = await expandViaExchange(pred.accessToken, "Read invoices only", ["payments:invoice.read"], crid);
    const body = (await res.json()) as {
      error?: string;
      mission_denial_reason?: string;
      access_token?: string;
      deferral_code?: string;
    };
    expect(res.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("invalid_request");
    expect(body.mission_denial_reason).toBe("nothing_to_expand");
    // The refusal issues NOTHING: no token, no deferral continuation.
    expect(body.access_token).toBeUndefined();
    expect(body.deferral_code).toBeUndefined();

    // Nothing was CREATED (no successor Mission record)...
    expect(as.kernel.allMissions().length).toBe(missionCountBefore);
    // ...and nothing was RESERVED: the refusal is stateless — no idempotency
    // operation is recorded under the initiation's creation_request_id.
    expect(as.creationIdempotency.find("ap-agent", crid)).toBeUndefined();

    // The predecessor is untouched: still active, and NO derivation was consumed
    // (derivation_count unchanged — the refusal is not a confined derivation).
    const after = as.kernel.get(pred.missionId);
    expect(after?.state).toBe("active");
    expect(after?.derivation_count).toBe(derivationCountBefore);
  });
});

describe("expansion wire: Submission envelope (@spec mission#submission-via-par, issue #506)", () => {
  it("refuses the retired bare-Intent mission_intent shape (the exchange carries the Submission envelope)", async () => {
    const pred = await issuePredecessor(["payments:invoice.read"]);
    const res = await tokenRequest({
      grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
      subject_token: pred.accessToken,
      subject_token_type: ACCESS_TOKEN_TOKEN_TYPE,
      requested_token_type: ACCESS_TOKEN_TOKEN_TYPE,
      // The pre-envelope bare shape, byte-for-byte what intentJson used to emit.
      mission_intent: JSON.stringify({ goal: "Widen", target_resources: [RESOURCE], expires_at: FAR_EXP }),
      authorization_details: JSON.stringify(authority(["payments:invoice.read", "payments:remittance.send"])),
      creation_request_id: crypto.randomUUID(),
    });
    const body = (await res.json()) as { error?: string; error_description?: string };
    expect(res.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("invalid_request");
    expect(body.error_description).toContain("bare Mission Intent shape");
  });
});

describe("expansion: verified facts persist across the deferred window (@spec mission#intent-submission-evidence, issue #506)", () => {
  const EXP_TYPE = "urn:test:intent-evidence:exp-stub";
  let failVerification = false;
  beforeAll(() => {
    registerIntentSubmissionEvidenceType(EXP_TYPE, {
      validate(entry) {
        if (typeof entry.assertion !== "string") throw new Error("assertion required");
      },
      async verify({ intentHash }) {
        if (failVerification) throw new Error("artifact expired during the window");
        return { admitted: true, bound_intent_hash: intentHash };
      },
    });
  });
  afterAll(() => unregisterIntentSubmissionEvidenceType(EXP_TYPE));

  it("facts verified at INITIATION land on the successor at redemption; the window does not re-verify freshness", async () => {
    failVerification = false;
    const pred = await issuePredecessor(["payments:invoice.read"]);
    const entry = { type: EXP_TYPE, assertion: "widening-artifact" };
    const opened = await tokenRequest({
      grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
      subject_token: pred.accessToken,
      subject_token_type: ACCESS_TOKEN_TOKEN_TYPE,
      requested_token_type: ACCESS_TOKEN_TOKEN_TYPE,
      mission_intent: JSON.stringify({
        intent: { goal: "Widen with provenance", target_resources: [RESOURCE], expires_at: FAR_EXP },
        evidence: [entry],
      }),
      authorization_details: JSON.stringify(
        authority(["payments:invoice.read", "payments:remittance.send"]),
      ),
      creation_request_id: crypto.randomUUID(),
    });
    const ob = (await opened.json()) as { error?: string; deferral_code?: string };
    expect(opened.status, JSON.stringify(ob)).toBe(400);
    expect(ob.error).toBe("authorization_pending");

    // The artifact "expires" DURING the deferred window: redemption must NOT
    // re-verify freshness (verification ran once, at initiation; the facts
    // were persisted with the deferral).
    failVerification = true;
    approveDeferral(ob.deferral_code as string);
    const poll = await pollExpansion(ob.deferral_code as string);
    const pb = (await poll.json()) as { access_token?: string; error?: string };
    failVerification = false;
    expect(poll.status, JSON.stringify(pb)).toBe(200);

    // The successor record carries the INITIATION-verified facts.
    const successorId = (decodeJwt(pb.access_token as string) as { mission: { id: string } })
      .mission.id;
    const successor = as.kernel.get(successorId);
    const facts = successor?.submission_evidence;
    expect(facts).toHaveLength(1);
    expect(facts?.[0]?.type).toBe(EXP_TYPE);
    // The provisional hash the verifier was bound to at initiation IS the
    // successor's recorded intent_hash commitment.
    expect(facts?.[0]?.facts).toEqual({
      admitted: true,
      bound_intent_hash: successor?.intent_hash,
    });
  });

  it("a FAILING artifact at INITIATION refuses the widening exchange (stage 2 runs before the deferral opens)", async () => {
    failVerification = true;
    const pred = await issuePredecessor(["payments:invoice.read"]);
    const res = await tokenRequest({
      grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
      subject_token: pred.accessToken,
      subject_token_type: ACCESS_TOKEN_TOKEN_TYPE,
      requested_token_type: ACCESS_TOKEN_TOKEN_TYPE,
      mission_intent: JSON.stringify({
        intent: { goal: "Widen with stale provenance", target_resources: [RESOURCE], expires_at: FAR_EXP },
        evidence: [{ type: EXP_TYPE, assertion: "stale" }],
      }),
      authorization_details: JSON.stringify(
        authority(["payments:invoice.read", "payments:remittance.send"]),
      ),
      creation_request_id: crypto.randomUUID(),
    });
    failVerification = false;
    const body = (await res.json()) as { error?: string; error_description?: string };
    expect(res.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("invalid_mission_intent_evidence");
    expect(body.error_description).toContain("artifact expired during the window");
  });
});

describe("expansion wire: DEFERRED widening via the DTR substrate (@spec expansion#deferred-window)", () => {
  it("a widening request defers (authorization_pending + deferral_code); after async approval a poll (no subject_token) mints the successor and supersedes the predecessor", async () => {
    const pred = await issuePredecessor(["payments:invoice.read"]);
    const opened = await expandViaExchange(pred.accessToken, "Widen to add remittance", [
      "payments:invoice.read",
      "payments:remittance.send",
    ]);
    const ob = (await opened.json()) as { error?: string; deferral_code?: string; interval?: number; expires_in?: number };
    expect(opened.status, JSON.stringify(ob)).toBe(400);
    expect(ob.error).toBe("authorization_pending");
    expect(ob.deferral_code).toBeTruthy();
    expect(ob.interval).toBeGreaterThan(0);
    expect(ob.expires_in).toBeGreaterThan(0);

    // The Approver acts asynchronously (headless adjudication).
    approveDeferral(ob.deferral_code as string);

    // @spec #deferred-window check (b): the poll carries ONLY deferral_code + DPoP,
    // NO subject_token; the short-lived subject_token's expiry does not gate this.
    const poll = await pollExpansion(ob.deferral_code as string);
    const pb = (await poll.json()) as {
      access_token?: string;
      token_type?: string;
      authorization_details?: Array<{ actions: string[] }>;
      mission_id?: string;
      mission_expires_at?: string;
      error?: string;
    };
    expect(poll.status, JSON.stringify(pb)).toBe(200);
    expect(pb.token_type).toBe("DPoP");
    // The successor's widened set includes the newly-approved capability.
    expect(pb.authorization_details?.some((e) => e.actions.includes("payments:remittance.send"))).toBe(true);

    const { payload } = await jwtVerify(pb.access_token as string, remoteJwks, { issuer: ISSUER, audience: RESOURCE });
    const mission = payload.mission as { id?: string; predecessor?: string };
    const successorId = mission.id as string;
    // A NEW successor Mission whose RECORD is lineage-linked to the predecessor,
    // and whose ISSUED access-token `mission` claim carries the same lineage: the
    // claim's own id is the successor, and its `predecessor` member is the
    // predecessor's mission_id (@spec expansion#predecessor-member) — so a resource
    // server sees lineage on the wire WITHOUT introspecting.
    expect(successorId).not.toBe(pred.missionId);
    expect(mission.predecessor).toBe(pred.missionId);
    expect(as.kernel.get(successorId)?.predecessor).toBe(pred.missionId);
    // The predecessor is superseded on the successor's first redemption.
    expect(as.kernel.get(pred.missionId)?.state).toBe("superseded");
    // @spec mission#grant-binding, expansion#successor-expiry (issue #647) —
    // the resolving poll IS the creation-completing body, so it carries the
    // successor's identifier and its committed effective expiry, verbatim.
    expect(pb.mission_id).toBe(successorId);
    expect(pb.mission_expires_at).toBe(as.kernel.get(successorId)?.expires_at);
  });

  it("@spec expansion#successor-expiry: the successor is never later than the predecessor absent a recorded extension", async () => {
    const pred = await issuePredecessor(["payments:invoice.read"]);
    const predRecord = as.kernel.get(pred.missionId);
    // The widening submission asks for a ceiling well BEYOND the predecessor's
    // own expiry. Expansion adds authority; it is not a lifetime-extension
    // mechanism, so the predecessor's expiry binds and the successor cannot
    // outlive the Mission it replaces.
    const opened = await expandViaExchange(
      pred.accessToken,
      "Widen and ask for a longer horizon",
      ["payments:invoice.read", "payments:remittance.send"],
      undefined,
      "2030-01-01T00:00:00Z",
    );
    const ob = (await opened.json()) as { error?: string; deferral_code?: string };
    expect(opened.status, JSON.stringify(ob)).toBe(400);
    expect(ob.error).toBe("authorization_pending");
    approveDeferral(ob.deferral_code as string);
    const poll = await pollExpansion(ob.deferral_code as string);
    const pb = (await poll.json()) as { mission_id?: string; mission_expires_at?: string };
    expect(poll.status, JSON.stringify(pb)).toBe(200);
    const successor = as.kernel.get(pb.mission_id as string);
    expect(successor?.predecessor).toBe(pred.missionId);
    expect(successor?.expires_at).toBe(predRecord?.expires_at);
    expect(Date.parse(successor!.expires_at)).toBeLessThan(Date.parse("2030-01-01T00:00:00Z"));
    // The completing body reports exactly that committed value.
    expect(pb.mission_expires_at).toBe(successor?.expires_at);
  });

  it("@spec mission#approval-event: a ceiling that passes while the approval pends creates NO Mission (access_denied)", async () => {
    const pred = await issuePredecessor(["payments:invoice.read"]);
    const opened = await expandViaExchange(pred.accessToken, "Widen to add remittance", [
      "payments:invoice.read",
      "payments:remittance.send",
    ]);
    const ob = (await opened.json()) as { error?: string; deferral_code?: string };
    expect(opened.status, JSON.stringify(ob)).toBe(400);
    // The Approver adjudicates with an approval whose horizon has ALREADY
    // passed, the deferred-window stand-in for a requested ceiling passing while
    // the approval pends: the effective expiry the successor would commit is not
    // later than its creation instant, so the creation transaction refuses.
    as.expansionDeferrals.approve(ob.deferral_code as string, {
      approver: { iss: ISSUER, sub: "bob" },
      approvalEventId: `apev-exp-past-${apev++}`,
      approvedUntil: "2020-01-01T00:00:00Z",
    });
    const poll = await pollExpansion(ob.deferral_code as string);
    const pb = (await poll.json()) as { error?: string; access_token?: string };
    expect(poll.status, JSON.stringify(pb)).toBe(400);
    expect(pb.error).toBe("access_denied");
    expect(pb.access_token).toBeUndefined();
    // No successor exists, and the predecessor was never superseded: completion
    // created no Mission at all rather than committing a dead one.
    expect(as.kernel.get(pred.missionId)?.state).toBe("active");
  });

  it("check (a): a predecessor REVOKED during the deferred window fails completion (access_denied) — a deferred approval MUST NOT bypass termination", async () => {
    const pred = await issuePredecessor(["payments:invoice.read"]);
    const opened = await expandViaExchange(pred.accessToken, "Widen to add remittance", [
      "payments:invoice.read",
      "payments:remittance.send",
    ]);
    const ob = (await opened.json()) as { error?: string; deferral_code?: string };
    expect(opened.status, JSON.stringify(ob)).toBe(400);
    expect(ob.error).toBe("authorization_pending");
    approveDeferral(ob.deferral_code as string);

    // The predecessor is terminated DURING the window (after approval, before poll).
    as.kernel.transition(pred.missionId, "revoke");

    const poll = await pollExpansion(ob.deferral_code as string);
    const pb = (await poll.json()) as { error?: string };
    expect(poll.status, JSON.stringify(pb)).toBe(400);
    expect(pb.error).toBe("access_denied");

    // Atomicity rollback proof (@spec expansion#superseded-state + the
    // effective-active rule): the denied completion left NO trace of
    // activation. The predecessor keeps its terminal state, was never
    // superseded, and gained no successor link.
    const predRecord = as.kernel.get(pred.missionId);
    expect(predRecord?.state).toBe("revoked");
    expect(predRecord?.successor ?? undefined).toBeUndefined();
  });

  it("round 4 (#639 review): a committed activation is recovered on re-poll, never converted to access_denied", async () => {
    const pred = await issuePredecessor(["payments:invoice.read"]);
    const opened = await expandViaExchange(pred.accessToken, "Widen to add remittance", [
      "payments:invoice.read",
      "payments:remittance.send",
    ]);
    const ob = (await opened.json()) as { error?: string; deferral_code?: string };
    approveDeferral(ob.deferral_code as string);
    const first = await pollExpansion(ob.deferral_code as string);
    const fb = (await first.json()) as { access_token?: string };
    expect(first.status, JSON.stringify(fb)).toBe(200);
    const successorId = (decodeJwt(fb.access_token as string) as { mission: { id: string } }).mission.id;
    expect(as.kernel.get(pred.missionId)?.state).toBe("superseded");

    // Simulate the crash window: the activation transaction committed but
    // the deferral was never marked redeemed, and the durable finalization
    // job was never drained.
    as.expansionDeferrals.db
      .prepare("UPDATE expansion_deferrals SET redeemed = 0 WHERE deferral_code = ?")
      .run(ob.deferral_code as string);
    as.kernel.db.prepare("UPDATE lifecycle_outbox SET done = 0").run();

    const second = await pollExpansion(ob.deferral_code as string);
    const sb = (await second.json()) as { access_token?: string; error?: string };
    // Committed, therefore recovered: the SAME successor, never access_denied.
    expect(second.status, JSON.stringify(sb)).toBe(200);
    const recoveredId = (decodeJwt(sb.access_token as string) as { mission: { id: string } }).mission.id;
    expect(recoveredId).toBe(successorId);
    expect(as.kernel.get(pred.missionId)?.state).toBe("superseded");
    // The replayed outbox job completed (idempotent drain, marked done).
    const undone = as.kernel.db
      .prepare("SELECT COUNT(*) AS n FROM lifecycle_outbox WHERE done = 0")
      .get() as { n: number };
    expect(undone.n).toBe(0);
  });

  it("round 5 (#640 review): a crash BEFORE the drain (failpoint after commit) recovers with the persisted event identity", async () => {
    const pred = await issuePredecessor(["payments:invoice.read"]);
    const opened = await expandViaExchange(pred.accessToken, "Widen to add remittance", [
      "payments:invoice.read",
      "payments:remittance.send",
    ]);
    const ob = (await opened.json()) as { error?: string; deferral_code?: string };
    approveDeferral(ob.deferral_code as string);

    // FAILPOINT: the drain throws immediately after the activation
    // transaction commits, before any finalization work runs.
    const kernelAny = as.kernel as unknown as {
      drainExpansionOutbox: () => void;
      opts: { onLifecycleCommit?: (c: { id: string; event_id?: string; committed_at: string }) => void };
    };
    const realDrain = kernelAny.drainExpansionOutbox.bind(as.kernel);
    kernelAny.drainExpansionOutbox = () => {
      throw new Error("failpoint: crash before drain");
    };
    let firstStatus = 0;
    try {
      const first = await pollExpansion(ob.deferral_code as string);
      firstStatus = first.status;
    } finally {
      kernelAny.drainExpansionOutbox = realDrain;
    }
    expect(firstStatus).not.toBe(200);

    // The crash window: the activation transaction committed (predecessor
    // superseded), the deferral was never marked redeemed, and the durable
    // job is pending with its immutable payloads persisted.
    expect(as.kernel.get(pred.missionId)?.state).toBe("superseded");
    const pending = as.kernel.db
      .prepare("SELECT activation_json FROM lifecycle_outbox WHERE done = 0")
      .get() as { activation_json: string } | undefined;
    expect(pending).toBeDefined();
    const persisted = JSON.parse((pending as { activation_json: string }).activation_json) as {
      id: string;
      event_id?: string;
      committed_at: string;
    };
    expect(persisted.event_id).toBeTruthy();

    // Recovery on the next poll, with the lifecycle hook recorded: the
    // SAME successor is returned, and the replay delivers the PERSISTED
    // event (same event_id, same committed_at), not a newly asserted one.
    const recorded: Array<{ id: string; event_id?: string; committed_at: string }> = [];
    const origHook = kernelAny.opts.onLifecycleCommit;
    kernelAny.opts.onLifecycleCommit = (commitEvt) => {
      recorded.push(commitEvt);
      origHook?.(commitEvt);
    };
    try {
      const second = await pollExpansion(ob.deferral_code as string);
      const sb = (await second.json()) as { access_token?: string; error?: string };
      expect(second.status, JSON.stringify(sb)).toBe(200);
      const recoveredId = (decodeJwt(sb.access_token as string) as { mission: { id: string } })
        .mission.id;
      expect(recoveredId).toBe(persisted.id);
    } finally {
      kernelAny.opts.onLifecycleCommit = origHook;
    }
    const replayed = recorded.find((commitEvt) => commitEvt.id === persisted.id);
    expect(replayed?.event_id).toBe(persisted.event_id);
    expect(replayed?.committed_at).toBe(persisted.committed_at);
    const undoneAfter = as.kernel.db
      .prepare("SELECT COUNT(*) AS n FROM lifecycle_outbox WHERE done = 0")
      .get() as { n: number };
    expect(undoneAfter.n).toBe(0);
  });

  it("cascade under replay (#641): a child-bearing predecessor's crash-window replay re-cascades nothing", async () => {
    // #743 — `authority()` binds a `max_amount`, so every action here must be
    // amount-bearing; `payments:vendor.read` is not, and PAR intake refuses
    // that entry. Nothing below asserts on the second action.
    const pred = await issuePredecessor(["payments:invoice.read"]);
    const { child } = createChildMission(as.kernel, {
      parentId: pred.missionId,
      intent: { goal: "Classify invoices", target_resources: [RESOURCE], expires_at: FAR_EXP },
      proposedAuthority: authority(["payments:invoice.read"]),
      childActor: { sub: "subagent-extractor", sub_profile: "ai_agent" },
    });
    expect(as.kernel.get(child.id)?.state).toBe("active");

    const opened = await expandViaExchange(pred.accessToken, "Widen to add remittance", [
      "payments:invoice.read",
      "payments:remittance.send",
    ]);
    const ob = (await opened.json()) as { error?: string; deferral_code?: string };
    approveDeferral(ob.deferral_code as string);
    const first = await pollExpansion(ob.deferral_code as string);
    const fb = (await first.json()) as { access_token?: string };
    expect(first.status, JSON.stringify(fb)).toBe(200);

    // The finalization drain cascaded the child once, in generation order.
    const cascaded = as.kernel.get(child.id);
    expect(cascaded?.state).toBe("cascaded");
    const versionAfterFirst = cascaded?.version;

    // Crash window: the deferral was never marked redeemed and the durable
    // finalization job was never drained.
    as.expansionDeferrals.db
      .prepare("UPDATE expansion_deferrals SET redeemed = 0 WHERE deferral_code = ?")
      .run(ob.deferral_code as string);
    as.kernel.db.prepare("UPDATE lifecycle_outbox SET done = 0").run();

    const recorded: Array<{ id: string }> = [];
    const kernelAny = as.kernel as unknown as {
      opts: { onLifecycleCommit?: (c: { id: string }) => void };
    };
    const origHook = kernelAny.opts.onLifecycleCommit;
    kernelAny.opts.onLifecycleCommit = (c) => {
      recorded.push(c);
      origHook?.(c);
    };
    try {
      const second = await pollExpansion(ob.deferral_code as string);
      const sb = (await second.json()) as { access_token?: string };
      expect(second.status, JSON.stringify(sb)).toBe(200);
    } finally {
      kernelAny.opts.onLifecycleCommit = origHook;
    }

    // Idempotent under replay: the already-cascaded child is skipped (same
    // terminal state, same version), and no child commit was re-emitted; the
    // replay redelivers only the persisted activation and supersession.
    const after = as.kernel.get(child.id);
    expect(after?.state).toBe("cascaded");
    expect(after?.version).toBe(versionAfterFirst);
    expect(recorded.filter((c) => c.id === child.id)).toHaveLength(0);
    const undone = as.kernel.db
      .prepare("SELECT COUNT(*) AS n FROM lifecycle_outbox WHERE done = 0")
      .get() as { n: number };
    expect(undone.n).toBe(0);
  });

  it("check (a): containment that ADVANCED during the window fails completion (version delta), a deferred approval MUST NOT bypass a later containment", async () => {
    const pred = await issuePredecessor(["payments:invoice.read"]);
    const opened = await expandViaExchange(pred.accessToken, "Widen to add remittance", [
      "payments:invoice.read",
      "payments:remittance.send",
    ]);
    const ob = (await opened.json()) as { error?: string; deferral_code?: string };
    expect(opened.status, JSON.stringify(ob)).toBe(400);
    approveDeferral(ob.deferral_code as string);

    // Containment ADVANCES during the window (version 0 -> 1 after the request).
    as.kernel.contain(pred.missionId, {
      event: containEvent("taint-exp-window"),
      remove: [{ resource: RESOURCE, actions: ["payments:invoice.read"] }],
    });

    const poll = await pollExpansion(ob.deferral_code as string);
    const pb = (await poll.json()) as { error?: string };
    expect(poll.status, JSON.stringify(pb)).toBe(400);
    expect(pb.error).toBe("access_denied");
  });

  it("check (a) is a version DELTA, not presence: a predecessor ALREADY contained at request time (version unchanged during the window) still completes (containment#restoration)", async () => {
    const pred = await issuePredecessor(["payments:invoice.read", "payments:remittance.send"]);
    // Contain remittance.send BEFORE the widening request: effective becomes {invoice.read}.
    as.kernel.contain(pred.missionId, {
      event: containEvent("taint-exp-pre"),
      remove: [{ resource: RESOURCE, actions: ["payments:remittance.send"] }],
    });

    // Restoring remittance.send is now a WIDEN relative to the contained effective set.
    const opened = await expandViaExchange(pred.accessToken, "Restore remittance after review", [
      "payments:invoice.read",
      "payments:remittance.send",
    ]);
    const ob = (await opened.json()) as { error?: string; deferral_code?: string };
    expect(opened.status, JSON.stringify(ob)).toBe(400);
    expect(ob.error).toBe("authorization_pending");
    approveDeferral(ob.deferral_code as string);

    // No further containment during the window -> version unchanged -> completes.
    const poll = await pollExpansion(ob.deferral_code as string);
    const pb = (await poll.json()) as { access_token?: string; error?: string };
    expect(poll.status, JSON.stringify(pb)).toBe(200);
    expect(pb.access_token).toBeTruthy();
  });
});

describe("expansion wire: possession (@spec expansion, #448)", () => {
  it("a refresh token as subject_token is rejected (#448: a reusable bearer refresh credential MUST NOT carry possession)", async () => {
    const res = await tokenRequest({
      grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
      subject_token: "not-an-access-token",
      subject_token_type: REFRESH_TOKEN_TOKEN_TYPE,
      requested_token_type: ACCESS_TOKEN_TOKEN_TYPE,
      mission_intent: intentJson("Widen", ["payments:invoice.read"]),
      authorization_details: JSON.stringify(authority(["payments:invoice.read"])),
    });
    const body = (await res.json()) as { error?: string; error_description?: string };
    expect(res.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("invalid_request");
    expect(body.error_description).toContain("refresh token");
  });

  it("possession: an exchange DPoP proof from a key other than the subject_token cnf is refused (invalid_grant)", async () => {
    const pred = await issuePredecessor(["payments:invoice.read", "payments:remittance.send"]);
    const wrongDpop = await generateKeyPair("ES256", { extractable: true });
    const res = await tokenRequestWithDpop(wrongDpop, {
      grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
      subject_token: pred.accessToken,
      subject_token_type: ACCESS_TOKEN_TOKEN_TYPE,
      requested_token_type: ACCESS_TOKEN_TOKEN_TYPE,
      mission_intent: intentJson("Read invoices only", ["payments:invoice.read"]),
      authorization_details: JSON.stringify(authority(["payments:invoice.read"])),
    });
    const body = (await res.json()) as { error?: string; error_description?: string };
    expect(res.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("invalid_grant");
    expect(body.error_description).toContain("confirmation key");
  });
});
