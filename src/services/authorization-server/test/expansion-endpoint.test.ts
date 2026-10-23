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

import { FIXTURE_BROWSER_LOGIN, floorApprovalHeaders, TEST_APPROVAL_PRINCIPALS } from "./approval-fixture.js";
import { ApprovalFloorRefusedError, ApprovalSessionStore } from "../src/index.js";
const FLOOR_SESSIONS = new ApprovalSessionStore();


import { type Server } from "node:http";
import { APPROVAL_FLOOR, CANONICAL_RESOURCE } from "@mission/demo-data";
import {
  calculateJwkThumbprint,
  compactVerify,
  createRemoteJWKSet,
  decodeJwt,
  type CryptoKey,
  exportJWK,
  generateKeyPair,
  importJWK,
  type JWK,
  jwtVerify,
  SignJWT,
} from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  asTokenSigningKeyPair,
  BARE_REFUSAL_MEMBERS,
  INVALID_ACTOR_TOKENS,
  INVALID_SUBJECT_TOKENS,
  MTLS_CNF,
  resignWithCnf,
  tokenRequestOnce,
} from "./subject-possession.helper.js";
import {
  ACCESS_TOKEN_TOKEN_TYPE,
  JWT_TOKEN_TYPE,
  REFRESH_TOKEN_TOKEN_TYPE,
  TOKEN_EXCHANGE_GRANT_TYPE,
} from "../src/adapters/continuation-grant.js";
import {
  ALL_PROVIDER_CAPABILITIES,
  buildAuthorizationServer,
  type BuiltAs,
  createChildMission,
  DEFERRED_GRANT_TYPE,
  registerIntentSubmissionEvidenceType,
  unregisterIntentSubmissionEvidenceType,
  validateMissionIntent,
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
/**
 * @spec child-delegation#carryover-commit — a TEST-ONLY child actor registered
 * for the token-exchange grant, so a carryover REPLACEMENT's own child actor
 * can authenticate at /token and retrieve its committed result.
 * `config/clients.json` is untouched (the builder's `testClients` seam adds,
 * never redefines).
 */
const CARRY_ACTOR = "test-carryover-child";
let carryActorKey: CryptoKey;
let carryDpop: DpopKeys;

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

/** A DPoP proof with exactly the given claims beside htu, htm and jti: no `iat` unless `claims` sets one. */
async function rawProof(claims: Record<string, unknown>, keys: DpopKeys = dpopKeys): Promise<string> {
  return new SignJWT({ htu: `${ISSUER}/token`, htm: "POST", jti: crypto.randomUUID(), ...claims })
    .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: await exportJWK(keys.publicKey) })
    .sign(keys.privateKey);
}

/**
 * POST /token with ap-agent private_key_jwt + DPoP (dpopKeys), with the
 * dpop-nonce retry. `makeProof` replaces the default fresh proof (the
 * freshness cases).
 */
async function tokenRequest(
  params: Record<string, string>,
  makeProof?: (extra: Record<string, unknown>) => Promise<string>,
): Promise<Response> {
  const htu = `${ISSUER}/token`;
  const proof = makeProof ?? ((extra: Record<string, unknown>) => dpopProof(htu, "POST", extra));
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
      resource: RESOURCE,
      code_challenge: challenge,
      code_challenge_method: "S256",
      login_hint: "alice",
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
    login_hint: "alice",
    mission_intent: intentJson(goal, actions, expiresAt),
    authorization_details: JSON.stringify(authority(actions)),
    // @spec expansion#submission — REQUIRED on every initiation.
    creation_request_id: creationRequestId ?? crypto.randomUUID(),
    completion_mode: "deferred",
  });
}

/**
 * Poll a deferred expansion on the deferred token response's deferred grant:
 * deferral_code + DPoP only, NO subject_token (check (b)).
 */
async function pollExpansion(
  deferralCode: string,
  makeProof?: (extra: Record<string, unknown>) => Promise<string>,
): Promise<Response> {
  return tokenRequest({ grant_type: DEFERRED_GRANT_TYPE, deferral_code: deferralCode }, makeProof);
}

function approveDeferral(deferralCode: string): void {
  as.expansionDeferrals.approve(deferralCode, {
    approver: { iss: ISSUER, sub: "bob" },
    authentication: FIXTURE_BROWSER_LOGIN,
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

/** The injected AS token signing key: the possession cases re-sign a real token's claims (#1210). */
let asSigningKey: CryptoKey;

beforeAll(async () => {
  const carryActorKeys = await generateKeyPair("ES256", { extractable: true });
  carryActorKey = carryActorKeys.privateKey;
  const carryActorJwk = {
    ...(await exportJWK(carryActorKeys.publicKey)),
    kid: `${CARRY_ACTOR}-auth`,
    alg: "ES256",
    use: "sig",
  };
  const asSigning = await asTokenSigningKeyPair();
  asSigningKey = asSigning.privateKey;
  as = await buildAuthorizationServer({
    issuer: ISSUER,
    allowHeadlessAdjudication: true,
    serviceTokenPrincipals: TEST_APPROVAL_PRINCIPALS,
    approvalSessions: FLOOR_SESSIONS,
    testTokenSigningJwk: (await exportJWK(asSigning.privateKey)) as JWK,
    testClients: [
      {
        client_id: CARRY_ACTOR,
        client_name: "Carryover replacement child actor (token-exchange capable)",
        grant_types: [TOKEN_EXCHANGE_GRANT_TYPE, DEFERRED_GRANT_TYPE],
        response_types: [],
        redirect_uris: [],
        token_endpoint_auth_method: "private_key_jwt",
        token_endpoint_auth_signing_alg: "ES256",
        jwks: { keys: [carryActorJwk] },
        authorization_details_types: ["mission_resource_access"],
      },
    ],
    // The AS ASSERTS this actor's type, exactly as config does for the shipped one.
    actorProfiles: { [CARRY_ACTOR]: "ai_agent" },
  });
  asServer = as.provider.listen(PORT);
  clientKey = (await importJWK(as.agentClientJwk as never, "ES256")) as CryptoKey;
  dpopKeys = await generateKeyPair("ES256", { extractable: true });
  carryDpop = await generateKeyPair("ES256", { extractable: true });
  remoteJwks = createRemoteJWKSet(new URL(`${ISSUER}/jwks`));
});

afterAll(() => {
  asServer?.close();
});

describe("expansion wire: a predecessor that is not active (@spec expansion#predecessor-active, mission#issuance-gating, #1154)", () => {
  for (const [transition, status] of [
    ["revoke", "predecessor_state_changed"],
    ["suspend", "predecessor_not_active"],
  ] as const) {
    it(`a ${transition === "revoke" ? "revoked" : "suspended"} predecessor refuses the expansion exchange with invalid_request and ${status}, creating no successor and counting no derivation`, async () => {
      const pred = await issuePredecessor(["payments:invoice.read"]);
      as.kernel.transition(pred.missionId, transition);
      const missionCountBefore = as.kernel.allMissions().length;
      const derivationCountBefore = as.kernel.get(pred.missionId)?.derivation_count;
      const res = await expandViaExchange(pred.accessToken, "Widen to add remittance", [
        "payments:invoice.read",
        "payments:remittance.send",
      ]);
      const body = (await res.json()) as {
        error?: string;
        mission_expansion_status?: string;
        access_token?: string;
        deferral_code?: string;
      };
      expect(res.status, JSON.stringify(body)).toBe(400);
      // A Token Exchange refuses a Mission that is not active with
      // invalid_request (RFC 8693 Section 2.2.2); a predecessor cross-check
      // mismatch keeps invalid_grant.
      expect(body.error).toBe("invalid_request");
      // @spec expansion#predecessor-active (#1177): with a reconciliation
      // status, a terminal-exit code for a terminal predecessor and
      // predecessor_not_active for a suspended one.
      expect(body.mission_expansion_status).toBe(status);
      expect(body.access_token).toBeUndefined();
      expect(body.deferral_code).toBeUndefined();
      expect(as.kernel.allMissions().length).toBe(missionCountBefore);
      expect(as.kernel.get(pred.missionId)?.derivation_count).toBe(derivationCountBefore);
      expect(as.kernel.get(pred.missionId)?.termination?.successor).toBeUndefined();
    });
  }

  it("a predecessor another expansion superseded refuses a further expansion of it with invalid_request and superseded_by_concurrent_expansion, creating no successor and counting no derivation", async () => {
    const pred = await issuePredecessor(["payments:invoice.read"]);
    const wide = ["payments:invoice.read", "payments:remittance.send"];
    const opened = (await (await expandViaExchange(pred.accessToken, "Widen to add remittance", wide)).json()) as {
      deferral_code?: string;
    };
    approveDeferral(opened.deferral_code as string);
    const completed = await pollExpansion(opened.deferral_code as string);
    expect(completed.status, JSON.stringify(await completed.clone().json())).toBe(200);
    expect(as.kernel.get(pred.missionId)?.termination?.reason).toBe("superseded");
    const missionCountBefore = as.kernel.allMissions().length;
    const derivationCountBefore = as.kernel.get(pred.missionId)?.derivation_count;

    const res = await expandViaExchange(pred.accessToken, "Widen again from the old predecessor", wide);
    const body = (await res.json()) as { error?: string; mission_expansion_status?: string; deferral_code?: string };
    expect(res.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("invalid_request");
    // The attribution rule: the predecessor's termination names a concurrent
    // expansion's successor, so the specific code answers.
    expect(body.mission_expansion_status).toBe("superseded_by_concurrent_expansion");
    expect(body.deferral_code).toBeUndefined();
    expect(as.kernel.allMissions().length).toBe(missionCountBefore);
    expect(as.kernel.get(pred.missionId)?.derivation_count).toBe(derivationCountBefore);
  });

  for (const [transition, state, missionError] of [
    ["revoke", "terminated", "revoked"],
    ["suspend", "suspended", "suspended"],
  ] as const) {
    it(`a ${missionError} predecessor's refusal carries mission_error ${missionError}; a proof under another key carries none (@spec mission#issuance-gating, #1179)`, async () => {
      const pred = await issuePredecessor(["payments:invoice.read"]);
      as.kernel.transition(pred.missionId, transition);
      const actions = ["payments:invoice.read", "payments:remittance.send"];
      const res = await expandViaExchange(pred.accessToken, "Widen to add remittance", actions);
      const body = (await res.json()) as { error?: string; error_description?: string; mission_error?: string };
      expect(res.status, JSON.stringify(body)).toBe(400);
      expect(body.error).toBe("invalid_request");
      expect(body.error_description).toBe(`predecessor mission is ${state}`);
      expect(body.mission_error).toBe(missionError);

      // Possession fails before the lifecycle check: no Mission state is disclosed.
      const wrongKey = await tokenRequestWithDpop(carryDpop, {
        grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
        subject_token: pred.accessToken,
        subject_token_type: ACCESS_TOKEN_TOKEN_TYPE,
        requested_token_type: ACCESS_TOKEN_TOKEN_TYPE,
        login_hint: "alice",
        mission_intent: intentJson("Widen to add remittance", actions),
        authorization_details: JSON.stringify(authority(actions)),
        creation_request_id: crypto.randomUUID(),
        completion_mode: "deferred",
      });
      const wrongBody = (await wrongKey.json()) as { error?: string; error_description?: string; mission_error?: string };
      expect(wrongKey.status, JSON.stringify(wrongBody)).toBe(400);
      expect(wrongBody.error_description).toContain("does not match the subject_token confirmation key");
      expect(wrongBody.mission_error).toBeUndefined();
    });
  }
});

describe("expansion wire: NON-WIDENING request is REFUSED (@spec expansion#verification-order)", () => {
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
      login_hint: "alice",
      mission_intent: JSON.stringify({ goal: "Widen", target_resources: [RESOURCE], expires_at: FAR_EXP }),
      authorization_details: JSON.stringify(authority(["payments:invoice.read", "payments:remittance.send"])),
      creation_request_id: crypto.randomUUID(),
      completion_mode: "deferred",
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
      login_hint: "alice",
      mission_intent: JSON.stringify({
        intent: { goal: "Widen with provenance", target_resources: [RESOURCE], expires_at: FAR_EXP },
        evidence: [entry],
      }),
      authorization_details: JSON.stringify(
        authority(["payments:invoice.read", "payments:remittance.send"]),
      ),
      creation_request_id: crypto.randomUUID(),
      completion_mode: "deferred",
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
      login_hint: "alice",
      mission_intent: JSON.stringify({
        intent: { goal: "Widen with stale provenance", target_resources: [RESOURCE], expires_at: FAR_EXP },
        evidence: [{ type: EXP_TYPE, assertion: "stale" }],
      }),
      authorization_details: JSON.stringify(
        authority(["payments:invoice.read", "payments:remittance.send"]),
      ),
      creation_request_id: crypto.randomUUID(),
      completion_mode: "deferred",
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
    const predGrant = as.kernel.get(pred.missionId)?.grant_id as string;
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
    expect(as.kernel.get(pred.missionId)?.termination?.reason).toBe("superseded");
    // @spec mission#grant-binding, expansion#successor-expiry (issue #647) —
    // the resolving poll IS the creation-completing body, so it carries the
    // successor's identifier and its committed effective expiry, verbatim.
    expect(pb.mission_id).toBe(successorId);
    expect(pb.mission_expires_at).toBe(as.kernel.get(successorId)?.expires_at);

    // @spec mission#grant-binding-related (#1590): the successor's internal grant is its own,
    // distinct from the predecessor's, and each still resolves to its own Mission. These witness
    // isolation of the AS's records, not a protocol lineage: the poll returns only an access token.
    const successorGrant = as.kernel.get(successorId)?.grant_id as string;
    expect(predGrant).toBeTruthy();
    expect(successorGrant).toBeTruthy();
    expect(successorGrant).not.toBe(predGrant);
    expect(as.kernel.get(pred.missionId)?.grant_id).toBe(predGrant);
    expect(as.kernel.findByGrant(predGrant)?.id).toBe(pred.missionId);
    expect(as.kernel.findByGrant(successorGrant)?.id).toBe(successorId);
    expect(as.kernel.missionBoundGrants.resolve(successorGrant)?.missionId).toBe(successorId);
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

  it("a successor ending inside the token lifetime gets an access token that expires no later than it (@spec mission#mission-bound-tokens)", async () => {
    const pred = await issuePredecessor(["payments:invoice.read"]);
    const opened = await expandViaExchange(
      pred.accessToken,
      "Widen for one minute",
      ["payments:invoice.read", "payments:remittance.send"],
      undefined,
      new Date(Date.now() + 60_000).toISOString(), // inside the 300 s lifetime
    );
    const ob = (await opened.json()) as { error?: string; deferral_code?: string };
    expect(opened.status, JSON.stringify(ob)).toBe(400);
    approveDeferral(ob.deferral_code as string);
    const poll = await pollExpansion(ob.deferral_code as string);
    const pb = (await poll.json()) as { access_token?: string; mission_id?: string };
    expect(poll.status, JSON.stringify(pb)).toBe(200);
    const successorExp = Math.floor(Date.parse(as.kernel.get(pb.mission_id as string)?.expires_at as string) / 1000);
    const at = decodeJwt(pb.access_token as string) as { iat: number; exp: number };
    expect(at.exp).toBeLessThanOrEqual(successorExp);
    expect(at.exp - at.iat).toBeLessThan(300);
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
      authentication: FIXTURE_BROWSER_LOGIN,
      approvalEventId: `apev-exp-past-${apev++}`,
      approvedUntil: "2020-01-01T00:00:00Z",
    });
    const poll = await pollExpansion(ob.deferral_code as string);
    const pb = (await poll.json()) as { error?: string; access_token?: string; mission_expansion_status?: string };
    expect(poll.status, JSON.stringify(pb)).toBe(400);
    expect(pb.error).toBe("access_denied");
    expect(pb.access_token).toBeUndefined();
    // @spec expansion#successor-expiry (#1177): an expiry refusal is not a
    // reconciliation failure and carries no reconciliation status.
    expect(pb.mission_expansion_status).toBeUndefined();
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
    expect(predRecord?.termination?.reason).toBe("revoked");
    expect(predRecord?.termination).not.toHaveProperty("successor");
  });

  for (const [transition, status] of [
    ["revoke", "predecessor_state_changed"],
    ["suspend", "predecessor_not_active"],
  ] as const) {
    it(`a predecessor ${transition === "revoke" ? "revoked" : "suspended"} during the window refuses completion with access_denied and ${status} on every poll, and a same-fingerprint retry returns the deferral, creating nothing (@spec expansion#reconciliation, #creation-reservation, #1177)`, async () => {
      const pred = await issuePredecessor(["payments:invoice.read"]);
      const wide = ["payments:invoice.read", "payments:remittance.send"];
      const creationRequestId = crypto.randomUUID();
      const opened = await expandViaExchange(pred.accessToken, "Widen to add remittance", wide, creationRequestId);
      const ob = (await opened.json()) as { error?: string; deferral_code?: string };
      expect(ob.error, JSON.stringify(ob)).toBe("authorization_pending");
      approveDeferral(ob.deferral_code as string);
      as.kernel.transition(pred.missionId, transition);
      const missionCountBefore = as.kernel.allMissions().length;

      type Refusal = { error?: string; mission_expansion_status?: string; access_token?: string; deferral_code?: string };
      const expectRefused = async (res: Response): Promise<void> => {
        const body = (await res.json()) as Refusal;
        expect(res.status, JSON.stringify(body)).toBe(400);
        expect(body.error).toBe("access_denied");
        expect(body.mission_expansion_status).toBe(status);
        expect(body.access_token).toBeUndefined();
      };
      await expectRefused(await pollExpansion(ob.deferral_code as string));
      // The refusal is recorded: a later poll repeats it with the same status.
      await expectRefused(await pollExpansion(ob.deferral_code as string));

      // A retry of the same operation returns its deferral, whose next poll
      // answers as the deferred token response defines.
      const retried = await expandViaExchange(pred.accessToken, "Widen to add remittance", wide, creationRequestId);
      const rb = (await retried.json()) as Refusal;
      expect(retried.status, JSON.stringify(rb)).toBe(400);
      expect(rb.error).toBe("authorization_pending");
      expect(rb.deferral_code).toBe(ob.deferral_code);
      await expectRefused(await pollExpansion(rb.deferral_code as string));
      expect(as.kernel.allMissions().length).toBe(missionCountBefore);
    });
  }

  it("a concurrent expansion that activated first refuses the other completion with access_denied and superseded_by_concurrent_expansion (@spec expansion#reconciliation, #1177)", async () => {
    const pred = await issuePredecessor(["payments:invoice.read"]);
    const wide = ["payments:invoice.read", "payments:remittance.send"];
    const first = (await (await expandViaExchange(pred.accessToken, "Widen to add remittance", wide)).json()) as {
      deferral_code?: string;
    };
    const second = (await (await expandViaExchange(pred.accessToken, "Widen for the remittance run", wide)).json()) as {
      error?: string;
      deferral_code?: string;
    };
    expect(second.error, JSON.stringify(second)).toBe("authorization_pending");
    approveDeferral(first.deferral_code as string);
    approveDeferral(second.deferral_code as string);

    const won = await pollExpansion(first.deferral_code as string);
    const wb = (await won.json()) as { mission_id?: string };
    expect(won.status, JSON.stringify(wb)).toBe(200);
    const missionCountBefore = as.kernel.allMissions().length;

    const lost = await pollExpansion(second.deferral_code as string);
    const lb = (await lost.json()) as { error?: string; mission_expansion_status?: string; access_token?: string };
    expect(lost.status, JSON.stringify(lb)).toBe(400);
    expect(lb.error).toBe("access_denied");
    expect(lb.mission_expansion_status).toBe("superseded_by_concurrent_expansion");
    expect(lb.access_token).toBeUndefined();
    expect(as.kernel.allMissions().length).toBe(missionCountBefore);
    expect(as.kernel.get(pred.missionId)?.termination?.successor).toBe(wb.mission_id);
  });

  it("an Approver's denial answers the poll with access_denied and no reconciliation status, and a same-fingerprint retry returns the deferral, creating nothing (@spec expansion#reconciliation, #creation-reservation, #1177)", async () => {
    const pred = await issuePredecessor(["payments:invoice.read"]);
    const wide = ["payments:invoice.read", "payments:remittance.send"];
    const creationRequestId = crypto.randomUUID();
    const opened = (await (
      await expandViaExchange(pred.accessToken, "Widen to add remittance", wide, creationRequestId)
    ).json()) as { deferral_code?: string };
    as.expansionDeferrals.deny(opened.deferral_code as string);
    const missionCountBefore = as.kernel.allMissions().length;
    const expectDenied = async (res: Response): Promise<void> => {
      const body = (await res.json()) as { error?: string; mission_expansion_status?: string };
      expect(res.status, JSON.stringify(body)).toBe(400);
      expect(body.error).toBe("access_denied");
      expect(body.mission_expansion_status).toBeUndefined();
    };
    await expectDenied(await pollExpansion(opened.deferral_code as string));

    const retried = await expandViaExchange(pred.accessToken, "Widen to add remittance", wide, creationRequestId);
    const rb = (await retried.json()) as { error?: string; deferral_code?: string };
    expect(retried.status, JSON.stringify(rb)).toBe(400);
    expect(rb.error).toBe("authorization_pending");
    expect(rb.deferral_code).toBe(opened.deferral_code);
    await expectDenied(await pollExpansion(rb.deferral_code as string));
    expect(as.kernel.allMissions().length).toBe(missionCountBefore);
    expect(as.kernel.get(pred.missionId)?.state).toBe("active");
  });

  it("a deferral-retirement fault rolls back successor, supersession and outbox as one transaction", async () => {
    const pred = await issuePredecessor(["payments:invoice.read"]);
    const opened = await expandViaExchange(pred.accessToken, "Atomic deferral", ["payments:invoice.read", "payments:remittance.send"]);
    const body = await opened.json() as { deferral_code: string };
    approveDeferral(body.deferral_code);
    const before = as.kernel.get(pred.missionId);
    const eventCount = (missionId: string): number =>
      (as.kernel.db
        .prepare("SELECT count(*) AS n FROM lifecycle_events WHERE mission_id = ?")
        .get(missionId) as { n: number }).n;
    const eventsBefore = eventCount(pred.missionId);
    as.kernel.db.exec("CREATE TEMP TRIGGER test_refuse_retirement BEFORE UPDATE OF redeemed ON expansion_deferrals WHEN NEW.redeemed = 1 BEGIN SELECT RAISE(ABORT, 'retirement fault'); END");
    try {
      expect((await pollExpansion(body.deferral_code)).status).not.toBe(200);
      expect(as.kernel.get(pred.missionId)).toEqual(before);
      expect(as.kernel.db.prepare("SELECT count(*) AS n FROM missions WHERE predecessor = ?").get(pred.missionId)).toEqual({ n: 0 });
      // @spec control-plane#fanout — the rolled-back transaction left NO
      // durable event behind: neither the successor's activation nor the
      // predecessor's supersession, and nothing pending publication.
      expect(eventCount(pred.missionId)).toBe(eventsBefore);
      expect(as.kernel.outbox.pendingEventCount()).toBe(0);
      expect(as.kernel.db.prepare("SELECT redeemed, completion_released FROM expansion_deferrals WHERE deferral_code = ?").get(body.deferral_code)).toEqual({ redeemed: 0, completion_released: 0 });
    } finally { as.kernel.db.exec("DROP TRIGGER test_refuse_retirement"); }
    expect((await pollExpansion(body.deferral_code)).status).toBe(200);
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
    expect(as.kernel.get(pred.missionId)?.termination?.reason).toBe("superseded");

    // Simulate the crash window: the activation transaction committed but
    // the completion was not released, and the durable finalization job was
    // never drained. The retired marker is now atomic with activation.
    as.expansionDeferrals.db
      .prepare("UPDATE expansion_deferrals SET completion_released = 0 WHERE deferral_code = ?")
      .run(ob.deferral_code as string);
    as.kernel.db.prepare("UPDATE lifecycle_events SET published = 0").run();

    const second = await pollExpansion(ob.deferral_code as string);
    const sb = (await second.json()) as { access_token?: string; error?: string };
    // Committed, therefore recovered: the SAME successor, never access_denied.
    expect(second.status, JSON.stringify(sb)).toBe(200);
    const recoveredId = (decodeJwt(sb.access_token as string) as { mission: { id: string } }).mission.id;
    expect(recoveredId).toBe(successorId);
    expect(as.kernel.get(pred.missionId)?.termination?.reason).toBe("superseded");
    // The replayed outbox events all published (idempotent drain).
    expect(as.kernel.outbox.pendingEventCount()).toBe(0);
  });

  it("round 5 (#640 review): a crash BEFORE the drain (failpoint after commit) recovers with the persisted event identity", async () => {
    const pred = await issuePredecessor(["payments:invoice.read"]);
    const opened = await expandViaExchange(pred.accessToken, "Widen to add remittance", [
      "payments:invoice.read",
      "payments:remittance.send",
    ]);
    const ob = (await opened.json()) as { error?: string; deferral_code?: string };
    approveDeferral(ob.deferral_code as string);

    // FAILPOINT: publication throws immediately after the activation
    // transaction commits, before any event is marked published. This is the
    // crash window the durable outbox exists to close.
    const kernelAny = as.kernel as unknown as {
      opts: { onLifecycleCommit?: (c: { id: string; event_id?: string; committed_at: string }) => void };
    };
    const realHook = kernelAny.opts.onLifecycleCommit;
    kernelAny.opts.onLifecycleCommit = () => {
      throw new Error("failpoint: crash before publication");
    };
    let firstStatus = 0;
    try {
      const first = await pollExpansion(ob.deferral_code as string);
      firstStatus = first.status;
    } finally {
      kernelAny.opts.onLifecycleCommit = realHook;
    }
    expect(firstStatus).not.toBe(200);

    // The crash window: the activation transaction committed (predecessor
    // superseded), the deferral is retired IN THAT SAME commit, and the durable
    // events are pending with their immutable payloads persisted. The
    // completion has not yet been released to the token adapter, so recovery
    // can return it.
    expect(as.kernel.get(pred.missionId)?.termination?.reason).toBe("superseded");
    expect(as.kernel.db.prepare("SELECT redeemed, completion_released FROM expansion_deferrals WHERE deferral_code = ?").get(ob.deferral_code)).toEqual({ redeemed: 1, completion_released: 0 });
    expect(as.kernel.outbox.pendingEventCount()).toBeGreaterThan(0);
    const successorId = (as.kernel.db
      .prepare("SELECT id FROM missions WHERE predecessor = ?")
      .get(pred.missionId) as { id: string }).id;
    const pending = as.kernel.db
      .prepare("SELECT commit_json FROM lifecycle_events WHERE published = 0 AND mission_id = ?")
      .get(successorId) as { commit_json: string } | undefined;
    expect(pending).toBeDefined();
    const persisted = JSON.parse((pending as { commit_json: string }).commit_json) as {
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
    expect(as.kernel.outbox.pendingEventCount()).toBe(0);
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
    expect(cascaded?.termination?.reason).toBe("parent_terminated");
    const versionAfterFirst = cascaded?.version;

    // The child's `parent_terminated` transition is itself a durable event,
    // committed in the SAME transaction as the supersession that cascaded it.
    const childEvents = as.kernel.db
      .prepare("SELECT event_id, commit_json FROM lifecycle_events WHERE mission_id = ? ORDER BY seq")
      .all(child.id) as Array<{ event_id: string; commit_json: string }>;
    const cascadedEvent = childEvents.find(
      (row) =>
        (JSON.parse(row.commit_json) as { termination?: { reason: string } }).termination?.reason ===
        "parent_terminated",
    );
    expect(cascadedEvent).toBeDefined();

    // Crash window: completion was not released and no event was published.
    as.expansionDeferrals.db
      .prepare("UPDATE expansion_deferrals SET completion_released = 0 WHERE deferral_code = ?")
      .run(ob.deferral_code as string);
    as.kernel.db.prepare("UPDATE lifecycle_events SET published = 0").run();

    const recorded: Array<{ id: string; event_id?: string; state?: string; termination?: { reason: string } }> = [];
    const kernelAny = as.kernel as unknown as {
      opts: {
        onLifecycleCommit?: (c: {
          id: string;
          event_id?: string;
          state?: string;
          termination?: { reason: string };
        }) => void;
      };
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

    // Idempotent under replay: no state moved (the child keeps its terminal
    // state and version, and no NEW event row exists for it), and the
    // descendant's committed transition is REDELIVERED rather than lost, with
    // the identity it was committed under.
    const after = as.kernel.get(child.id);
    expect(after?.termination?.reason).toBe("parent_terminated");
    expect(after?.version).toBe(versionAfterFirst);
    const childEventsAfter = as.kernel.db
      .prepare("SELECT event_id FROM lifecycle_events WHERE mission_id = ?")
      .all(child.id) as Array<{ event_id: string }>;
    expect(childEventsAfter.map((r) => r.event_id).sort()).toEqual(
      childEvents.map((r) => r.event_id).sort(),
    );
    const replayedChild = recorded.filter(
      (c) => c.id === child.id && c.termination?.reason === "parent_terminated",
    );
    expect(replayedChild).toHaveLength(1);
    expect(replayedChild[0]?.event_id).toBe(cascadedEvent?.event_id);
    expect(as.kernel.outbox.pendingEventCount()).toBe(0);
  });

  it("check 3: containment during the window that the successor's authority overlaps refuses completion with access_denied and authority_restricted_since_approval on every poll; a new expansion then restores it (@spec expansion#reconciliation, #1177)", async () => {
    const pred = await issuePredecessor(["payments:invoice.read"]);
    const wide = ["payments:invoice.read", "payments:remittance.send"];
    const opened = await expandViaExchange(pred.accessToken, "Widen to add remittance", wide);
    const ob = (await opened.json()) as { error?: string; deferral_code?: string };
    expect(opened.status, JSON.stringify(ob)).toBe(400);
    approveDeferral(ob.deferral_code as string);

    // Containment after adjudication removes authority the successor carries.
    as.kernel.contain(pred.missionId, {
      event: containEvent(`taint-exp-window-${crypto.randomUUID()}`),
      remove: [{ resource: RESOURCE, actions: ["payments:invoice.read"] }],
    });
    const missionCountBefore = as.kernel.allMissions().length;

    for (let i = 0; i < 2; i++) {
      const poll = await pollExpansion(ob.deferral_code as string);
      const pb = (await poll.json()) as { error?: string; mission_expansion_status?: string; access_token?: string };
      expect(poll.status, JSON.stringify(pb)).toBe(400);
      expect(pb.error).toBe("access_denied");
      expect(pb.mission_expansion_status).toBe("authority_restricted_since_approval");
      expect(pb.access_token).toBeUndefined();
    }
    // The refused completion rolled back: no successor, and the predecessor
    // stays active under its containment.
    expect(as.kernel.allMissions().length).toBe(missionCountBefore);
    expect(as.kernel.get(pred.missionId)?.state).toBe("active");
    expect(as.kernel.get(pred.missionId)?.termination).toBeUndefined();
    expect(as.kernel.get(pred.missionId)?.containment?.containment_version).toBe(1);

    // The contained authority returns only through a new expansion,
    // adjudicated against the current restriction.
    const again = await expandViaExchange(pred.accessToken, "Restore invoice reads and add remittance", wide);
    const ab = (await again.json()) as { error?: string; deferral_code?: string };
    expect(ab.error, JSON.stringify(ab)).toBe("authorization_pending");
    approveDeferral(ab.deferral_code as string);
    const restored = await pollExpansion(ab.deferral_code as string);
    const rb = (await restored.json()) as { mission_id?: string };
    expect(restored.status, JSON.stringify(rb)).toBe(200);
    expect(as.kernel.get(rb.mission_id as string)?.authority_set.some((e) => e.actions.includes("payments:invoice.read"))).toBe(true);
  });

  it("check 3: containment during the window of authority the successor does not carry leaves completion untouched (@spec expansion#reconciliation, #1177)", async () => {
    const pred = await issuePredecessor(["payments:invoice.read"]);
    // The successor carries remittance.send only, not the predecessor's invoice.read.
    const opened = await expandViaExchange(pred.accessToken, "Switch to remittance", ["payments:remittance.send"]);
    const ob = (await opened.json()) as { error?: string; deferral_code?: string };
    expect(ob.error, JSON.stringify(ob)).toBe("authorization_pending");
    approveDeferral(ob.deferral_code as string);
    as.kernel.contain(pred.missionId, {
      event: containEvent(`taint-exp-other-${crypto.randomUUID()}`),
      remove: [{ resource: RESOURCE, actions: ["payments:invoice.read"] }],
    });
    const poll = await pollExpansion(ob.deferral_code as string);
    const pb = (await poll.json()) as { mission_id?: string; mission_expansion_status?: string };
    expect(poll.status, JSON.stringify(pb)).toBe(200);
    expect(pb.mission_expansion_status).toBeUndefined();
    const successor = as.kernel.get(pb.mission_id as string);
    expect(successor?.authority_set.flatMap((e) => e.actions)).toEqual(["payments:remittance.send"]);
    expect(as.kernel.get(pred.missionId)?.termination?.reason).toBe("superseded");
  });

  it("check 3: a containment event during the window that names only authority already contained before the request restricts nothing new, so the restoring completion succeeds (@spec expansion#reconciliation, containment#restoration, #1177)", async () => {
    const pred = await issuePredecessor(["payments:invoice.read", "payments:remittance.send"]);
    as.kernel.contain(pred.missionId, {
      event: containEvent(`taint-exp-before-${crypto.randomUUID()}`),
      remove: [{ resource: RESOURCE, actions: ["payments:remittance.send"] }],
    });
    // The approval restores remittance.send, disclosed at consent, and widens.
    const opened = await expandViaExchange(pred.accessToken, "Restore remittance and add refunds", [
      "payments:invoice.read",
      "payments:remittance.send",
      "payments:refund.issue",
    ]);
    const ob = (await opened.json()) as { error?: string; deferral_code?: string };
    expect(ob.error, JSON.stringify(ob)).toBe("authorization_pending");
    approveDeferral(ob.deferral_code as string);
    // A later event names remittance.send again: the version advances, but no
    // action of the successor came under restriction after adjudication.
    as.kernel.contain(pred.missionId, {
      event: containEvent(`taint-exp-repeat-${crypto.randomUUID()}`),
      remove: [{ resource: RESOURCE, actions: ["payments:remittance.send"] }],
    });
    expect(as.kernel.get(pred.missionId)?.containment?.containment_version).toBe(2);
    const poll = await pollExpansion(ob.deferral_code as string);
    const pb = (await poll.json()) as { mission_id?: string };
    expect(poll.status, JSON.stringify(pb)).toBe(200);
    expect(as.kernel.get(pb.mission_id as string)?.authority_set.some((e) => e.actions.includes("payments:remittance.send"))).toBe(true);
  });

  it("check 3 is about restriction since adjudication, not presence: a predecessor ALREADY contained at request time still completes (containment#restoration)", async () => {
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
      login_hint: "alice",
      mission_intent: intentJson("Widen", ["payments:invoice.read"]),
      authorization_details: JSON.stringify(authority(["payments:invoice.read"])),
    });
    const body = (await res.json()) as { error?: string; error_description?: string };
    expect(res.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("invalid_request");
    expect(body.error_description).toContain("refresh token");
  });

  it("possession: an exchange DPoP proof from a key other than the subject_token cnf is refused (invalid_request)", async () => {
    const pred = await issuePredecessor(["payments:invoice.read", "payments:remittance.send"]);
    const wrongDpop = await generateKeyPair("ES256", { extractable: true });
    const res = await tokenRequestWithDpop(wrongDpop, {
      grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
      subject_token: pred.accessToken,
      subject_token_type: ACCESS_TOKEN_TOKEN_TYPE,
      requested_token_type: ACCESS_TOKEN_TOKEN_TYPE,
      // Otherwise valid (step 1's creation_request_id), so possession is what fails.
      creation_request_id: crypto.randomUUID(),
      completion_mode: "deferred",
      login_hint: "alice",
      mission_intent: intentJson("Read invoices only", ["payments:invoice.read"]),
      authorization_details: JSON.stringify(authority(["payments:invoice.read"])),
    });
    const body = (await res.json()) as { error?: string; error_description?: string };
    expect(res.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("invalid_request");
    expect(body.error_description).toContain("confirmation key");
  });
});

/** A private_key_jwt assertion for an arbitrary registered client. */
const assertionFor = async (clientId: string, kid: string, k: CryptoKey): Promise<string> =>
  new SignJWT({})
    .setProtectedHeader({ alg: "ES256", kid })
    .setIssuer(clientId)
    .setSubject(clientId)
    .setAudience(ISSUER)
    .setIssuedAt()
    .setExpirationTime("2m")
    .setJti(crypto.randomUUID())
    .sign(k);

/** POST /token as an arbitrary client with its OWN DPoP key (nonce retry). */
const requestAs = async (
  clientId: string,
  kid: string,
  k: CryptoKey,
  dpop: DpopKeys,
  params: Record<string, string>,
  makeProof?: (extra: Record<string, unknown>) => Promise<string>,
): Promise<Response> => {
  const htu = `${ISSUER}/token`;
  const fresh = async (extra: Record<string, unknown>): Promise<string> =>
    new SignJWT({ htu, htm: "POST", ...extra })
      .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: await exportJWK(dpop.publicKey) })
      .setIssuedAt()
      .setJti(crypto.randomUUID())
      .sign(dpop.privateKey);
  const proof = makeProof ?? fresh;
  const send = async (extra: Record<string, unknown> = {}): Promise<Response> =>
    fetch(htu, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", dpop: await proof(extra) },
      body: new URLSearchParams({
        ...params,
        client_assertion: await assertionFor(clientId, kid, k),
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      }).toString(),
    });
  let res = await send();
  const nonce = res.headers.get("dpop-nonce");
  if (res.status === 400 && nonce) res = await send({ nonce });
  return res;
};

describe("expansion acting-agent authorization (@spec expansion#verification-order step 4, #1326)", () => {
  const widen = ["payments:invoice.read", "payments:remittance.send"];
  const initiation = (accessToken: string, goal: string, creationRequestId: string) => ({
    grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
    subject_token: accessToken,
    subject_token_type: ACCESS_TOKEN_TOKEN_TYPE,
    requested_token_type: ACCESS_TOKEN_TOKEN_TYPE,
    login_hint: "alice",
    mission_intent: intentJson(goal, widen),
    authorization_details: JSON.stringify(authority(widen)),
    creation_request_id: creationRequestId,
    completion_mode: "deferred",
  });
  type Refusal = { error?: string; error_description?: string; deferral_code?: string; mission_error?: string; access_token?: string };

  it("an unrelated client holding the predecessor's token and key is refused invalid_request at initiation, opening no deferral or reservation and leaving the predecessor active; the predecessor's own client's request defers", async () => {
    const pred = await issuePredecessor(["payments:invoice.read"]);
    const missionsBefore = as.kernel.allMissions().length;
    const countBefore = as.kernel.get(pred.missionId)?.derivation_count;
    const crid = crypto.randomUUID();
    const res = await requestAs(CARRY_ACTOR, `${CARRY_ACTOR}-auth`, carryActorKey, dpopKeys, initiation(pred.accessToken, "Unrelated client widening", crid));
    const body = (await res.json()) as Refusal;
    expect(res.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("invalid_request");
    expect(body.error_description).toContain("not authorized to request expansion");
    expect(body.deferral_code).toBeUndefined();
    expect(body.mission_error).toBeUndefined();
    expect(as.creationIdempotency.find(CARRY_ACTOR, crid)).toBeUndefined();
    expect(as.kernel.get(pred.missionId)?.state).toBe("active");
    expect(as.kernel.get(pred.missionId)?.derivation_count).toBe(countBefore);
    expect(as.kernel.allMissions().length).toBe(missionsBefore);

    const own = await tokenRequest(initiation(pred.accessToken, "Unrelated client widening", crypto.randomUUID()));
    const ownBody = (await own.json()) as Refusal;
    expect(own.status, JSON.stringify(ownBody)).toBe(400);
    expect(ownBody.error).toBe("authorization_pending");
    expect(typeof ownBody.deferral_code).toBe("string");
  });

  it("a retained deferral another client opened is refused invalid_grant at the poll before redeem, creating no successor and leaving the predecessor active; the predecessor's own deferral still completes on a poll that carries no subject_token", async () => {
    const pred = await issuePredecessor(["payments:invoice.read"]);
    // Seeded as a deferral an unrelated client opened before the initiation
    // check existed: deferrals persist, and the poll runs no initiation check.
    const seeded = as.expansionDeferrals.open({
      predecessorId: pred.missionId,
      intent: validateMissionIntent(
        JSON.stringify({ goal: "Retained unrelated widening", target_resources: [RESOURCE], expires_at: FAR_EXP }),
      ),
      proposedAuthority: authority(widen) as never,
      clientId: CARRY_ACTOR,
      jkt: await calculateJwkThumbprint(await exportJWK(carryDpop.publicKey)),
      creationRequestId: crypto.randomUUID(),
    });
    approveDeferral(seeded.deferral_code);
    const missionsBefore = as.kernel.allMissions().length;
    const pollAs = async (dpop: DpopKeys, code: string) => {
      const res = await requestAs(CARRY_ACTOR, `${CARRY_ACTOR}-auth`, carryActorKey, dpop, {
        grant_type: DEFERRED_GRANT_TYPE,
        deferral_code: code,
      });
      return { status: res.status, ...((await res.json()) as Refusal) };
    };
    const body = await pollAs(carryDpop, seeded.deferral_code);
    expect(body.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("invalid_grant");
    // DTR -00 Section 5.6 (#1357): answered exactly as an unknown code, and
    // before the key check, so a poll under another key gets the same answer
    // rather than invalid_dpop_proof.
    const unknown = await pollAs(carryDpop, `xdfr_${"A".repeat(24)}`);
    expect(body).toEqual(unknown);
    expect(await pollAs(dpopKeys, seeded.deferral_code)).toEqual(unknown);
    // The predecessor's own client did not open this deferral either: under
    // its own key, which is not the deferral's, it gets its unknown-code
    // answer, never invalid_dpop_proof (DTR -00 Section 5.5.1 step 2 first).
    const asJson = async (res: Response) => ({ status: res.status, ...((await res.json()) as Refusal) });
    expect(await asJson(await pollExpansion(seeded.deferral_code))).toEqual(
      await asJson(await pollExpansion(`xdfr_${"B".repeat(24)}`)),
    );
    // A missing or invalid proof is refused alike for every code, before the
    // code is looked up (#1357 review): the recorded client (CARRY_ACTOR) and
    // the predecessor's client (ap-agent) each get the same answer for this
    // deferral as for an unknown code.
    const bare = async (asClient: string, code: string, proof: string | null) => {
      const assertion =
        asClient === CARRY_ACTOR
          ? await assertionFor(CARRY_ACTOR, `${CARRY_ACTOR}-auth`, carryActorKey)
          : await clientAssertion();
      const res = await tokenRequestOnce(ISSUER, { grant_type: DEFERRED_GRANT_TYPE, deferral_code: code }, assertion, proof);
      return { status: res.status, ...((await res.json()) as Refusal) };
    };
    const unknownCode = `xdfr_${"C".repeat(24)}`;
    const invalidProof = () => dpopProof(`${ISSUER}/elsewhere`, "POST");
    for (const asClient of [CARRY_ACTOR, "ap-agent"]) {
      const missing = await bare(asClient, seeded.deferral_code, null);
      expect(missing.error, JSON.stringify(missing)).toBe("invalid_dpop_proof");
      expect(missing).toEqual(await bare(asClient, unknownCode, null));
      const invalid = await bare(asClient, seeded.deferral_code, await invalidProof());
      expect(invalid.error, JSON.stringify(invalid)).toBe("invalid_dpop_proof");
      expect(invalid).toEqual(await bare(asClient, unknownCode, await invalidProof()));
    }
    // Refused before redeem: a late mint refusal would also be invalid_grant,
    // after the successor existed and the predecessor was superseded.
    expect(as.kernel.get(pred.missionId)?.state).toBe("active");
    expect(as.kernel.get(pred.missionId)?.termination).toBeUndefined();
    expect(as.kernel.allMissions().length).toBe(missionsBefore);
    expect(body.access_token).toBeUndefined();

    const opened = await expandViaExchange(pred.accessToken, "Own client widening", widen);
    const openedBody = (await opened.json()) as Refusal;
    expect(openedBody.error, JSON.stringify(openedBody)).toBe("authorization_pending");
    approveDeferral(openedBody.deferral_code as string);
    const done = await pollExpansion(openedBody.deferral_code as string);
    expect(done.status, JSON.stringify(await done.clone().json())).toBe(200);
    expect(as.kernel.get(pred.missionId)?.termination?.reason).toBe("superseded");
  });
});

describe("carryover completion and result retrieval (@spec child-delegation#carryover-commit)", () => {
  /** A predecessor with one Child Mission held by the token-exchange-capable actor. */
  const predecessorWithChild = async (): Promise<{
    missionId: string;
    accessToken: string;
    childId: string;
  }> => {
    const pred = await issuePredecessor(["payments:invoice.read"]);
    const child = createChildMission(as.kernel, {
      parentId: pred.missionId,
      intent: validateMissionIntent(
        JSON.stringify({
          goal: "Extract Acme invoices",
          target_resources: [RESOURCE],
          expires_at: FAR_EXP,
        }),
      ),
      proposedAuthority: authority(["payments:invoice.read"]) as never,
      childActor: { sub: CARRY_ACTOR, sub_profile: "ai_agent" },
    }).child;
    return { ...pred, childId: child.id };
  };

  it("completes a widening expansion by carrying the child and returns the authenticated batch map on the completion response", async () => {
    const pred = await predecessorWithChild();
    const opened = await expandViaExchange(pred.accessToken, "Widen to add remittance", [
      "payments:invoice.read",
      "payments:remittance.send",
    ]);
    const openedBody = (await opened.json()) as { deferral_code?: string; error?: string };
    expect(opened.status, JSON.stringify(openedBody)).toBe(400);
    expect(openedBody.error).toBe("authorization_pending");
    approveDeferral(openedBody.deferral_code as string);
    const done = await pollExpansion(openedBody.deferral_code as string);
    const body = (await done.json()) as {
      mission_id?: string;
      carryover_manifest_hash?: string;
      carryover_evidence?: string;
      carryover_replacements?: Array<{ mission_id: string; related_to?: string; client_id: string }>;
    };
    expect(done.status, JSON.stringify(body)).toBe(200);
    // The AUTHENTICATED result rides the completion response: the committed
    // manifest commitment and the retained, signed batch map.
    expect(body.carryover_manifest_hash).toMatch(/^sha-256:/);
    // The signature really verifies against the issuer's PUBLISHED key set,
    // over the real /jwks document: this is a signed result, not a payload.
    const verified = await compactVerify(body.carryover_evidence as string, remoteJwks);
    const decoded = JSON.parse(Buffer.from(verified.payload).toString("utf8")) as {
      manifest_hash: string;
      map: Array<{ old_child: { mission_id: string }; outcome: string; replacement_id?: string }>;
    };
    expect(decoded.manifest_hash).toBe(body.carryover_manifest_hash);
    const row = decoded.map.find((r) => r.old_child.mission_id === pred.childId);
    expect(row?.outcome).toBe("carried");
    expect(body.carryover_replacements).toHaveLength(1);
    const replacement = body.carryover_replacements?.[0];
    expect(replacement?.mission_id).toBe(row?.replacement_id);
    expect(replacement?.related_to).toBe(pred.childId);
    expect(replacement?.client_id).toBe(CARRY_ACTOR);
    // The old child is carried, terminal, and its correlation is committed.
    const oldChild = as.kernel.get(pred.childId);
    expect(oldChild?.termination?.reason).toBe("parent_terminated");
    expect(oldChild?.termination?.carried_to).toBe(replacement?.mission_id);
    // The replacement is a child of the SUCCESSOR with a direct basis.
    const newChild = as.kernel.get(replacement?.mission_id as string);
    expect(newChild?.parent?.id).toBe(body.mission_id);
    expect(newChild?.approval_basis.type).toBe("direct");
  });

  // @spec RFC 9449 Section 4.3 (#1173): the retriever's proof is complete and fresh.
  it("retrieval refuses a proof with no iat, a non-numeric iat, or an iat outside the acceptance window; one inside the window is accepted once and its replay refused", async () => {
    const nowS = (): number => Math.floor(Date.now() / 1000);
    const outside = [
      { label: "no iat", claims: {}, description: "DPoP proof has no iat" },
      { label: "a non-numeric iat", claims: { iat: "now" }, description: "invalid DPoP proof" },
      { label: "a boolean iat", claims: { iat: true }, description: "invalid DPoP proof" },
      { label: "a day old", claims: { iat: nowS() - 86_400 }, description: "outside the acceptance window" },
      { label: "past the window", claims: { iat: nowS() - 260 }, description: "outside the acceptance window" },
      { label: "an hour ahead", claims: { iat: nowS() + 3_600 }, description: "outside the acceptance window" },
    ];
    const pred = await predecessorWithChild();
    const opened = await expandViaExchange(pred.accessToken, "Widen to add remittance for the proof cases", [
      "payments:invoice.read",
      "payments:remittance.send",
    ]);
    const openedBody = (await opened.json()) as { deferral_code: string };
    approveDeferral(openedBody.deferral_code);
    const done = await pollExpansion(openedBody.deferral_code);
    const completion = (await done.json()) as { carryover_replacements: Array<{ mission_id: string }> };
    expect(done.status, JSON.stringify(completion)).toBe(200);
    // Retrieval is idempotent, so one replacement serves every case.
    const params = {
      grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
      requested_token_type: JWT_TOKEN_TYPE,
      carryover_replacement: completion.carryover_replacements[0]?.mission_id as string,
    };
    const retrieve = (makeProof: (extra: Record<string, unknown>) => Promise<string>) =>
      requestAs(CARRY_ACTOR, `${CARRY_ACTOR}-auth`, carryActorKey, carryDpop, params, makeProof);
    for (const { label, claims, description } of outside) {
      const res = await retrieve((extra) => rawProof({ ...claims, ...extra }, carryDpop));
      const body = (await res.json()) as { error?: string; error_description?: string; access_token?: string };
      expect(res.status, label).toBe(400);
      expect(body.error, label).toBe("invalid_dpop_proof");
      expect(body.error_description, label).toContain(description);
      expect(body.access_token, label).toBeUndefined();
    }
    for (const offset of [-230, 50]) {
      let sent = "";
      const ok = await retrieve(async (extra) => {
        sent = await rawProof({ iat: nowS() + offset, ...extra }, carryDpop);
        return sent;
      });
      expect(ok.status, `iat ${offset}: ${JSON.stringify(await ok.clone().json())}`).toBe(200);
      const replay = await retrieve(async () => sent);
      const replayBody = (await replay.json()) as { error?: string; error_description?: string };
      expect(replay.status, `iat ${offset}, replayed`).toBe(400);
      expect(replayBody.error, `iat ${offset}, replayed`).toBe("invalid_dpop_proof");
      expect(replayBody.error_description, `iat ${offset}, replayed`).toContain("replayed");
    }
  });

  it("retrieves the committed replacement result idempotently for its own child actor, and refuses another authenticated client", async () => {
    const pred = await predecessorWithChild();
    const opened = await expandViaExchange(pred.accessToken, "Widen to add remittance again", [
      "payments:invoice.read",
      "payments:remittance.send",
    ]);
    const openedBody = (await opened.json()) as { deferral_code: string };
    approveDeferral(openedBody.deferral_code);
    const done = await pollExpansion(openedBody.deferral_code);
    const completion = (await done.json()) as {
      mission_id: string;
      carryover_replacements: Array<{ mission_id: string }>;
    };
    expect(done.status, JSON.stringify(completion)).toBe(200);
    const replacementId = completion.carryover_replacements[0]?.mission_id as string;

    // The child actor authenticates AS ITSELF and retrieves the committed
    // result through the child-creation completion surface.
    const first = await requestAs(CARRY_ACTOR, `${CARRY_ACTOR}-auth`, carryActorKey, carryDpop, {
      grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
      requested_token_type: JWT_TOKEN_TYPE,
      carryover_replacement: replacementId,
    });
    const firstBody = (await first.json()) as {
      mission_id?: string;
      access_token?: string;
      related_to?: string;
      carryover_manifest_hash?: string;
      carryover_evidence?: string;
    };
    expect(first.status, JSON.stringify(firstBody)).toBe(200);
    expect(firstBody.mission_id).toBe(replacementId);
    expect(firstBody.related_to).toBe(pred.childId);
    expect(firstBody.carryover_evidence).toBeDefined();
    // The returned grant names the replacement's own actor as its redeemer.
    const grant = decodeJwt(firstBody.access_token as string) as { client_id: string; mission: { id: string } };
    expect(grant.client_id).toBe(CARRY_ACTOR);
    expect(grant.mission.id).toBe(replacementId);

    // IDEMPOTENT: a repeat retrieval creates no duplicate replacement and
    // repeats no approval.
    const childrenBefore = as.kernel.findChildren(completion.mission_id).length;
    const second = await requestAs(CARRY_ACTOR, `${CARRY_ACTOR}-auth`, carryActorKey, carryDpop, {
      grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
      requested_token_type: JWT_TOKEN_TYPE,
      carryover_replacement: replacementId,
    });
    const secondBody = (await second.json()) as { mission_id?: string };
    expect(second.status, JSON.stringify(secondBody)).toBe(200);
    expect(secondBody.mission_id).toBe(replacementId);
    expect(as.kernel.findChildren(completion.mission_id).length).toBe(childrenBefore);

    // UNAUTHORIZED: a different authenticated client, holding a valid
    // assertion and a valid DPoP proof, is refused. The deterministic approval
    // event identifier is not retrieval authorization.
    const other = await tokenRequest({
      grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
      requested_token_type: JWT_TOKEN_TYPE,
      carryover_replacement: replacementId,
    });
    const otherBody = (await other.json()) as { error?: string; error_description?: string };
    expect(other.status, JSON.stringify(otherBody)).toBe(400);
    expect(otherBody.error).toBe("invalid_grant");
    expect(otherBody.error_description).toContain("child actor");

    // The OLD child's identifier is not a retrievable replacement: a terminated
    // record is never treated as a credential or a result of its replacement.
    const oldLookup = await requestAs(CARRY_ACTOR, `${CARRY_ACTOR}-auth`, carryActorKey, carryDpop, {
      grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
      requested_token_type: JWT_TOKEN_TYPE,
      carryover_replacement: pred.childId,
    });
    const oldBody = (await oldLookup.json()) as { error?: string };
    expect(oldLookup.status, JSON.stringify(oldBody)).toBe(400);
    expect(oldBody.error).toBe("invalid_request");
  });

  it("retrieval of a replacement that is no longer active is refused invalid_request with its mission_error, minting nothing; another authenticated client gets none (@spec mission#issuance-gating, #1179)", async () => {
    const pred = await predecessorWithChild();
    const opened = await expandViaExchange(pred.accessToken, "Widen to add remittance, then end the replacement", [
      "payments:invoice.read",
      "payments:remittance.send",
    ]);
    const openedBody = (await opened.json()) as { deferral_code: string };
    approveDeferral(openedBody.deferral_code);
    const done = await pollExpansion(openedBody.deferral_code);
    const completion = (await done.json()) as { carryover_replacements: Array<{ mission_id: string }> };
    expect(done.status, JSON.stringify(completion)).toBe(200);
    const params = {
      grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
      requested_token_type: JWT_TOKEN_TYPE,
      carryover_replacement: completion.carryover_replacements[0]?.mission_id as string,
    };
    type Refusal = { error?: string; error_description?: string; mission_error?: string; access_token?: string };
    for (const [transition, state, missionError] of [
      ["suspend", "suspended", "suspended"],
      ["revoke", "terminated", "revoked"],
    ] as const) {
      as.kernel.transition(params.carryover_replacement, transition);
      const res = await requestAs(CARRY_ACTOR, `${CARRY_ACTOR}-auth`, carryActorKey, carryDpop, params);
      const body = (await res.json()) as Refusal;
      expect(res.status, JSON.stringify(body)).toBe(400);
      expect(body.error).toBe("invalid_request");
      expect(body.error_description).toBe(`replacement mission is ${state}`);
      expect(body.mission_error).toBe(missionError);
      expect(body.access_token).toBeUndefined();

      // Another authenticated client is refused as unauthorized before the lifecycle check.
      const other = await tokenRequest(params);
      const otherBody = (await other.json()) as Refusal;
      expect(other.status, JSON.stringify(otherBody)).toBe(400);
      expect(otherBody.error).toBe("invalid_grant");
      expect(otherBody.mission_error).toBeUndefined();
    }
  });

  it("an unrelated client holding the predecessor's token and key gets no predecessor state or mission_error on the expansion refusal; the predecessor's own client does (@spec expansion#verification-order, mission#issuance-gating, #1179)", async () => {
    const pred = await issuePredecessor(["payments:invoice.read"]);
    expect(as.kernel.get(pred.missionId)?.client_id).toBe("ap-agent");
    as.kernel.transition(pred.missionId, "revoke");
    const actions = ["payments:invoice.read", "payments:remittance.send"];
    const params = (goal: string) => ({
      grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
      subject_token: pred.accessToken,
      subject_token_type: ACCESS_TOKEN_TOKEN_TYPE,
      requested_token_type: ACCESS_TOKEN_TOKEN_TYPE,
      login_hint: "alice",
      mission_intent: intentJson(goal, actions),
      authorization_details: JSON.stringify(authority(actions)),
      creation_request_id: crypto.randomUUID(),
      completion_mode: "deferred",
    });
    type Refusal = { error?: string; error_description?: string; mission_error?: string; access_token?: string };

    // Possession of the token's key does not make the presenter the predecessor's acting agent.
    const unrelated = await requestAs(CARRY_ACTOR, `${CARRY_ACTOR}-auth`, carryActorKey, dpopKeys, params("Unrelated client expansion"));
    const unrelatedBody = (await unrelated.json()) as Refusal;
    expect(unrelated.status, JSON.stringify(unrelatedBody)).toBe(400);
    expect(unrelatedBody.mission_error).toBeUndefined();
    expect(unrelatedBody.error_description).not.toContain("terminated");
    expect(unrelatedBody.access_token).toBeUndefined();

    const own = await tokenRequest(params("Own client expansion"));
    const ownBody = (await own.json()) as Refusal;
    expect(own.status, JSON.stringify(ownBody)).toBe(400);
    expect(ownBody.mission_error).toBe("revoked");
  });
});

describe("DPoP proof freshness on the deferred expansion poll (@spec RFC 9449 Section 4.3, #1173)", () => {
  /** An approved widening deferral, ready for its poll. */
  async function approvedExpansion(): Promise<string> {
    const pred = await issuePredecessor(["payments:invoice.read"]);
    const opened = await expandViaExchange(pred.accessToken, "Widen to add remittance", [
      "payments:invoice.read",
      "payments:remittance.send",
    ]);
    const ob = (await opened.json()) as { error?: string; deferral_code?: string };
    expect(opened.status, JSON.stringify(ob)).toBe(400);
    approveDeferral(ob.deferral_code as string);
    return ob.deferral_code as string;
  }

  it("refuses a proof with no iat, a non-numeric iat, or an iat outside the acceptance window; one inside the window is accepted once and its replay refused", async () => {
    const nowS = (): number => Math.floor(Date.now() / 1000);
    const outside = [
      { label: "no iat", claims: {}, description: "DPoP proof has no iat" },
      { label: "a non-numeric iat", claims: { iat: "now" }, description: "invalid DPoP proof" },
      { label: "a boolean iat", claims: { iat: true }, description: "invalid DPoP proof" },
      { label: "a day old", claims: { iat: nowS() - 86_400 }, description: "outside the acceptance window" },
      { label: "past the window", claims: { iat: nowS() - 260 }, description: "outside the acceptance window" },
      { label: "an hour ahead", claims: { iat: nowS() + 3_600 }, description: "outside the acceptance window" },
    ];
    // The proof is checked before the deferral is redeemed, so one deferral
    // serves every refused case.
    const code = await approvedExpansion();
    for (const { label, claims, description } of outside) {
      const res = await pollExpansion(code, (extra) => rawProof({ ...claims, ...extra }));
      const body = (await res.json()) as { error?: string; error_description?: string; access_token?: string };
      expect(res.status, label).toBe(400);
      expect(body.error, label).toBe("invalid_dpop_proof");
      expect(body.error_description, label).toContain(description);
      expect(body.access_token, label).toBeUndefined();
    }
    for (const [index, offset] of [-230, 50].entries()) {
      let sent = "";
      const ok = await pollExpansion(index === 0 ? code : await approvedExpansion(), async (extra) => {
        sent = await rawProof({ iat: nowS() + offset, ...extra });
        return sent;
      });
      expect(ok.status, `iat ${offset}: ${JSON.stringify(await ok.clone().json())}`).toBe(200);
      // A second approved deferral, so only the replayed proof can refuse it.
      const replay = await pollExpansion(await approvedExpansion(), async () => sent);
      const replayBody = (await replay.json()) as { error?: string; error_description?: string };
      expect(replay.status, `iat ${offset}, replayed`).toBe(400);
      expect(replayBody.error, `iat ${offset}, replayed`).toBe("invalid_dpop_proof");
      expect(replayBody.error_description, `iat ${offset}, replayed`).toContain("replayed");
    }
  });
});

describe("subject-token possession at the expansion exchange (@spec expansion#request-binding, #verification-order, #1210)", () => {
  const WIDE = ["payments:invoice.read", "payments:remittance.send"];
  const expandParams = (subjectToken: string, extra: Record<string, string> = {}): Record<string, string> => ({
    grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
    subject_token: subjectToken,
    subject_token_type: ACCESS_TOKEN_TOKEN_TYPE,
    requested_token_type: ACCESS_TOKEN_TOKEN_TYPE,
    login_hint: "alice",
    mission_intent: intentJson("Widen to add remittance", WIDE),
    authorization_details: JSON.stringify(authority(WIDE)),
    creation_request_id: crypto.randomUUID(),
    completion_mode: "deferred",
    ...extra,
  });
  const send = async (params: Record<string, string>, proof: string | null): Promise<Response> =>
    tokenRequestOnce(ISSUER, params, await clientAssertion(), proof);
  const freshProof = (): Promise<string> => dpopProof(`${ISSUER}/token`, "POST");
  const refusal = async (res: Response) => ({
    status: res.status,
    ...((await res.json()) as { error?: string; error_description?: string; deferral_code?: string }),
  });

  it("refuses a subject_token that is not sender-constrained with invalid_request, leaving the predecessor and its count untouched", async () => {
    const pred = await issuePredecessor(["payments:invoice.read"]);
    const count = as.kernel.get(pred.missionId)?.derivation_count;
    const res = await refusal(await send(expandParams(await resignWithCnf(pred.accessToken, asSigningKey, undefined)), await freshProof()));
    expect(res.status, JSON.stringify(res)).toBe(400);
    expect(res.error).toBe("invalid_request");
    expect(res.error_description).toContain("not sender-constrained");
    expect(res.deferral_code).toBeUndefined();
    expect(as.kernel.get(pred.missionId)?.state).toBe("active");
    expect(as.kernel.get(pred.missionId)?.derivation_count).toBe(count);
  });

  it("refuses an mTLS-bound subject_token as a sender constraint it cannot verify, never as unconstrained", async () => {
    const pred = await issuePredecessor(["payments:invoice.read"]);
    const res = await refusal(await send(expandParams(await resignWithCnf(pred.accessToken, asSigningKey, MTLS_CNF)), await freshProof()));
    expect(res.status, JSON.stringify(res)).toBe(400);
    // RFC 8693 Section 2.2.2 (#1178): an unacceptable subject_token.
    expect(res.error).toBe("invalid_request");
    expect(res.error_description).toContain("sender constraint");
    expect(res.error_description).not.toContain("not sender-constrained");
  });

  it("refuses a replayed DPoP proof presented with fresh client authentication", async () => {
    const pred = await issuePredecessor(["payments:invoice.read"]);
    const proof = await freshProof();
    // The widening defers: possession was verified and the proof admitted.
    const first = await refusal(await send(expandParams(pred.accessToken), proof));
    expect(first.error, JSON.stringify(first)).toBe("authorization_pending");
    // A new operation and a new client assertion: only the proof repeats.
    const res = await refusal(await send(expandParams(pred.accessToken), proof));
    expect(res.status, JSON.stringify(res)).toBe(400);
    expect(res.error).toBe("invalid_dpop_proof");
    expect(res.error_description).toContain("replayed");
  });

  it("refuses a request missing both creation_request_id and its DPoP proof at step 1 (invalid_request), before possession", async () => {
    const { creation_request_id: _omitted, ...params } = expandParams((await issuePredecessor(["payments:invoice.read"])).accessToken);
    const res = await refusal(await send(params, null));
    expect(res.status, JSON.stringify(res)).toBe(400);
    expect(res.error).toBe("invalid_request");
    expect(res.error_description).toContain("creation_request_id");
  });

  it("refuses an exchange carrying both predecessor and child_actor with invalid_request", async () => {
    const pred = await issuePredecessor(["payments:invoice.read"]);
    const res = await refusal(
      await send(
        expandParams(pred.accessToken, {
          predecessor: pred.missionId,
          child_actor: JSON.stringify({ sub: "subagent-extractor", sub_profile: "ai_agent" }),
        }),
        await freshProof(),
      ),
    );
    expect(res.status, JSON.stringify(res)).toBe(400);
    expect(res.error).toBe("invalid_request");
    expect(res.error_description).toContain("child_actor");
    expect(res.deferral_code).toBeUndefined();
  });

  it("refuses an expansion exchange carrying child_actor without a predecessor cross-check with invalid_request, creating nothing (@spec expansion#submission, #1177)", async () => {
    const pred = await issuePredecessor(["payments:invoice.read"]);
    const params = expandParams(pred.accessToken, {
      child_actor: JSON.stringify({ sub: "subagent-extractor", sub_profile: "ai_agent" }),
    });
    const missionCountBefore = as.kernel.allMissions().length;
    const res = await refusal(await send(params, await freshProof()));
    expect(res.status, JSON.stringify(res)).toBe(400);
    expect(res.error).toBe("invalid_request");
    expect(res.error_description).toContain("child_actor");
    expect(res.deferral_code).toBeUndefined();
    expect(as.creationIdempotency.find("ap-agent", params.creation_request_id as string)).toBeUndefined();
    expect(as.kernel.allMissions().length).toBe(missionCountBefore);
    expect(as.kernel.get(pred.missionId)?.state).toBe("active");
  });
});

describe("the creation fingerprint's actor member (@spec expansion#creation-fingerprint, #1177)", () => {
  const WIDE = ["payments:invoice.read", "payments:remittance.send"];
  /** A valid actor_token naming ap-agent, sender-constrained to the presenter key. */
  const actorToken = async (): Promise<string> =>
    new SignJWT({ cnf: { jkt: await calculateJwkThumbprint(await exportJWK(dpopKeys.publicKey)) } })
      .setProtectedHeader({ alg: "ES256" })
      .setIssuer("ap-agent")
      .setSubject("ap-agent")
      .setIssuedAt()
      .setExpirationTime("2m")
      .sign(dpopKeys.privateKey);
  const exchange = async (subjectToken: string, creationRequestId: string, withActorToken: boolean) => {
    const res = await tokenRequest({
      grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
      subject_token: subjectToken,
      subject_token_type: ACCESS_TOKEN_TOKEN_TYPE,
      requested_token_type: ACCESS_TOKEN_TOKEN_TYPE,
      login_hint: "alice",
      mission_intent: intentJson("Widen to add remittance", WIDE),
      authorization_details: JSON.stringify(authority(WIDE)),
      creation_request_id: creationRequestId,
      completion_mode: "deferred",
      ...(withActorToken ? { actor_token: await actorToken(), actor_token_type: JWT_TOKEN_TYPE } : {}),
    });
    return { status: res.status, ...((await res.json()) as { error?: string; error_description?: string; deferral_code?: string }) };
  };

  for (const opensWithActorToken of [false, true]) {
    it(`an operation opened ${opensWithActorToken ? "with" : "without"} an actor_token recovers on a retry that matches it, and a retry ${opensWithActorToken ? "without" : "adding"} one is a different request (invalid_request)`, async () => {
      const pred = await issuePredecessor(["payments:invoice.read"]);
      const creationRequestId = crypto.randomUUID();
      const opened = await exchange(pred.accessToken, creationRequestId, opensWithActorToken);
      expect(opened.error, JSON.stringify(opened)).toBe("authorization_pending");

      const same = await exchange(pred.accessToken, creationRequestId, opensWithActorToken);
      expect(same.error, JSON.stringify(same)).toBe("authorization_pending");
      expect(same.deferral_code).toBe(opened.deferral_code);

      // `actor` is the actor_token's iss and sub, absent where client
      // authentication alone identifies the acting agent: the two requests
      // differ in a fingerprint member.
      const other = await exchange(pred.accessToken, creationRequestId, !opensWithActorToken);
      expect(other.status, JSON.stringify(other)).toBe(400);
      expect(other.error).toBe("invalid_request");
      expect(other.error_description).toContain("already used for a different creation request");
      expect(other.deferral_code).toBeUndefined();
    });
  }
});

describe("invalid or unacceptable subject and actor tokens at the expansion exchange (@spec expansion#verification-order, RFC 8693 Section 2.2.2, #1178)", () => {
  const WIDE = ["payments:invoice.read", "payments:remittance.send"];

  /**
   * Send one widening expansion exchange as ap-agent under `proof` (a fresh
   * proof of the predecessor token's key unless given) and report the
   * response with what the exchange left behind: the predecessor's state and
   * count, and any reservation of the operation's creation_request_id.
   */
  async function attempt(
    pred: { missionId: string },
    subjectToken: string,
    extra: Record<string, string> = {},
    proof?: string,
  ) {
    const count = as.kernel.get(pred.missionId)?.derivation_count;
    const creationRequestId = crypto.randomUUID();
    const res = await tokenRequestOnce(
      ISSUER,
      {
        grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
        subject_token: subjectToken,
        subject_token_type: ACCESS_TOKEN_TOKEN_TYPE,
        requested_token_type: ACCESS_TOKEN_TOKEN_TYPE,
        mission_intent: intentJson("Widen to add remittance", WIDE),
        authorization_details: JSON.stringify(authority(WIDE)),
        creation_request_id: creationRequestId,
        completion_mode: "deferred",
        ...extra,
      },
      await clientAssertion(),
      proof ?? (await dpopProof(`${ISSUER}/token`, "POST")),
    );
    const body = (await res.json()) as Record<string, unknown>;
    return {
      status: res.status,
      body,
      untouched:
        as.kernel.get(pred.missionId)?.state === "active" && as.kernel.get(pred.missionId)?.derivation_count === count,
      reserved: as.creationIdempotency.find("ap-agent", creationRequestId) !== undefined,
    };
  }

  /** The refusal is invalid_request, carries no diagnostic, and defers, reserves and counts nothing. */
  function expectRefused(r: Awaited<ReturnType<typeof attempt>>, description: string): void {
    expect(r.status, JSON.stringify(r.body)).toBe(400);
    expect(r.body.error).toBe("invalid_request");
    expect(r.body.error_description).toContain(description);
    expect(Object.keys(r.body).sort()).toEqual([...BARE_REFUSAL_MEMBERS]);
    expect(r.untouched).toBe(true);
    expect(r.reserved).toBe(false);
  }

  it.each(INVALID_SUBJECT_TOKENS)(
    "refuses %s with invalid_request, no Mission diagnostic, and no deferral, reservation or count",
    async (_name, make, description) => {
      const pred = await issuePredecessor(["payments:invoice.read"]);
      expectRefused(await attempt(pred, await make(pred.accessToken, asSigningKey)), description);
    },
  );

  it.each(INVALID_ACTOR_TOKENS)(
    "refuses %s with invalid_request, no Mission diagnostic, and no deferral, reservation or count",
    async (_name, make, description) => {
      const pred = await issuePredecessor(["payments:invoice.read"]);
      expectRefused(
        await attempt(pred, pred.accessToken, { actor_token: await make(dpopKeys), actor_token_type: JWT_TOKEN_TYPE }),
        description,
      );
    },
  );

  it("keeps invalid_dpop_proof for a proof that fails its own checks, distinct from a valid proof under another key", async () => {
    const pred = await issuePredecessor(["payments:invoice.read"]);
    // Signed by the token's own key, but for another endpoint: the proof is invalid.
    const r = await attempt(pred, pred.accessToken, {}, await dpopProof(`${ISSUER}/elsewhere`, "POST"));
    expect(r.status, JSON.stringify(r.body)).toBe(400);
    expect(r.body.error).toBe("invalid_dpop_proof");
    expect(r.body.mission_error).toBeUndefined();
    expect(r.untouched).toBe(true);
    expect(r.reserved).toBe(false);
  });
});

describe("an expansion approval meets the approval-authentication floor (@spec mission#approval-authentication, #826, D425)", () => {
  const maxAge = APPROVAL_FLOOR.floors[0]?.max_authentication_age_seconds as number;
  const approval = (extra: Record<string, unknown> = {}) => ({
    approver: { iss: ISSUER, sub: "bob" },
    approvalEventId: `apev-exp-floor-${apev++}`,
    approvedUntil: FAR_EXP,
    ...extra,
  });
  const successorsOf = (id: string) => as.kernel.allMissions().filter((m) => m.predecessor === id);
  async function openWidening(actions: string[]): Promise<{ predecessorId: string; code: string }> {
    const pred = await issuePredecessor(["payments:invoice.read"]);
    const opened = await expandViaExchange(pred.accessToken, "Widen the Acme invoice work", actions);
    const ob = (await opened.json()) as { error?: string; deferral_code?: string };
    expect(ob.error, JSON.stringify(ob)).toBe("authorization_pending");
    return { predecessorId: pred.missionId, code: ob.deferral_code as string };
  }

  it("refuses a high-risk expansion approval that carries no achieved authentication: nothing is recorded, the deferral stays pending, and no successor exists", async () => {
    const { predecessorId, code } = await openWidening(["payments:invoice.read", "payments:remittance.send"]);
    expect(() => as.expansionDeferrals.approve(code, approval())).toThrow(ApprovalFloorRefusedError);
    const poll = await pollExpansion(code);
    const pb = (await poll.json()) as { error?: string };
    expect(poll.status, JSON.stringify(pb)).toBe(400);
    expect(pb.error).toBe("authorization_pending");
    expect(successorsOf(predecessorId)).toHaveLength(0);
    expect(as.kernel.get(predecessorId)?.state).toBe("active");
  });

  it("refuses a high-risk expansion approval whose recorded login the floor does not accept, a weaker acr or one older than the age bound, then completes from one it accepts", async () => {
    const { predecessorId, code } = await openWidening(["payments:invoice.read", "payments:remittance.send"]);
    expect(() =>
      as.expansionDeferrals.approve(code, approval({ authentication: { ...FIXTURE_BROWSER_LOGIN, acr: "password" } })),
    ).toThrow(/high-risk-authority floor/);
    const stale = Math.floor(as.kernel.nowDate().getTime() / 1000) - maxAge - 5;
    expect(() =>
      as.expansionDeferrals.approve(code, approval({ authentication: { ...FIXTURE_BROWSER_LOGIN, auth_time: stale } })),
    ).toThrow(/older than the high-risk-authority floor allows/);
    expect(successorsOf(predecessorId)).toHaveLength(0);
    as.expansionDeferrals.approve(code, approval({ authentication: FIXTURE_BROWSER_LOGIN }));
    const poll = await pollExpansion(code);
    const pb = (await poll.json()) as { error?: string };
    expect(poll.status, JSON.stringify(pb)).toBe(200);
    expect(successorsOf(predecessorId)).toHaveLength(1);
  });

  it("admits a low-risk widening with no achieved authentication: the floor does not apply", async () => {
    // payment.schedule is a consequential write, below the floor.
    const { predecessorId, code } = await openWidening(["payments:invoice.read", "payments:payment.schedule"]);
    as.expansionDeferrals.approve(code, approval());
    const poll = await pollExpansion(code);
    const pb = (await poll.json()) as { error?: string };
    expect(poll.status, JSON.stringify(pb)).toBe(200);
    expect(successorsOf(predecessorId)).toHaveLength(1);
  });
});

describe("the deferred token response substrate for expansion (@spec expansion#completion-modes, #creation-revalidation, DTR -00, #1177)", () => {
  const WIDE = ["payments:invoice.read", "payments:remittance.send"];
  const DEFERRAL_CODE_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:deferral-code";
  type Body = {
    error?: string;
    error_description?: string;
    deferral_code?: string;
    access_token?: string;
    mission_id?: string;
  };
  const read = async (res: Response) => ({ status: res.status, ...((await res.json()) as Body) });

  /** A widening expansion exchange as ap-agent, with or without the opt-in, or with another completion_mode. */
  const initiate = async (subjectToken: string, creationRequestId: string, completionMode?: string) =>
    read(
      await tokenRequest({
        grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
        subject_token: subjectToken,
        subject_token_type: ACCESS_TOKEN_TOKEN_TYPE,
        requested_token_type: ACCESS_TOKEN_TOKEN_TYPE,
        login_hint: "alice",
        mission_intent: intentJson("Widen to add remittance", WIDE),
        authorization_details: JSON.stringify(authority(WIDE)),
        creation_request_id: creationRequestId,
        ...(completionMode !== undefined ? { completion_mode: completionMode } : {}),
      }),
    );

  /** DTR -00 Section 7: cancel a deferral at the RFC 7009 revocation endpoint, as ap-agent unless another assertion is given. */
  const revokeDeferral = async (code: string, assertion?: string): Promise<Response> =>
    fetch(`${ISSUER}/token/revocation`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        token: code,
        token_type_hint: DEFERRAL_CODE_TOKEN_TYPE,
        client_assertion: assertion ?? (await clientAssertion()),
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      }).toString(),
    });

  /** A pending deferral opened with the opt-in. */
  const openDeferral = async () => {
    const pred = await issuePredecessor(["payments:invoice.read"]);
    const creationRequestId = crypto.randomUUID();
    const opened = await initiate(pred.accessToken, creationRequestId, "deferred");
    expect(opened.error, JSON.stringify(opened)).toBe("authorization_pending");
    return { pred, creationRequestId, code: opened.deferral_code as string };
  };

  for (const completionMode of [undefined, "push"]) {
    it(`refuses a widening exchange ${completionMode === undefined ? "without completion_mode" : "whose completion_mode does not include deferred"} with invalid_request, opening no deferral and recording no operation`, async () => {
      const pred = await issuePredecessor(["payments:invoice.read"]);
      const missionCountBefore = as.kernel.allMissions().length;
      const derivationCountBefore = as.kernel.get(pred.missionId)?.derivation_count;
      const creationRequestId = crypto.randomUUID();
      const res = await initiate(pred.accessToken, creationRequestId, completionMode);
      expect(res.status, JSON.stringify(res)).toBe(400);
      expect(res.error).toBe("invalid_request");
      expect(res.error_description).toContain("completion_mode");
      expect(res.deferral_code).toBeUndefined();
      expect(as.creationIdempotency.find("ap-agent", creationRequestId)).toBeUndefined();
      expect(as.kernel.allMissions().length).toBe(missionCountBefore);
      expect(as.kernel.get(pred.missionId)?.state).toBe("active");
      expect(as.kernel.get(pred.missionId)?.derivation_count).toBe(derivationCountBefore);
    });
  }

  it("refuses a retry of a pending deferred operation without the opt-in with invalid_request and no deferral; a retry that opts in returns the same deferral", async () => {
    const { pred, creationRequestId, code } = await openDeferral();
    const bare = await initiate(pred.accessToken, creationRequestId);
    expect(bare.status, JSON.stringify(bare)).toBe(400);
    expect(bare.error).toBe("invalid_request");
    expect(bare.error_description).toContain("completion_mode");
    expect(bare.deferral_code).toBeUndefined();
    const optedIn = await initiate(pred.accessToken, creationRequestId, "deferred");
    expect(optedIn.error, JSON.stringify(optedIn)).toBe("authorization_pending");
    expect(optedIn.deferral_code).toBe(code);
  });

  it("refuses a retry of a completed deferred operation without the opt-in with invalid_request; a retry that opts in recovers the delivered token", async () => {
    const { pred, creationRequestId, code } = await openDeferral();
    approveDeferral(code);
    const completed = await read(await pollExpansion(code));
    expect(completed.status, JSON.stringify(completed)).toBe(200);
    const bare = await initiate(pred.accessToken, creationRequestId);
    expect(bare.status, JSON.stringify(bare)).toBe(400);
    expect(bare.error).toBe("invalid_request");
    expect(bare.access_token).toBeUndefined();
    const optedIn = await initiate(pred.accessToken, creationRequestId, "deferred");
    expect(optedIn.status, JSON.stringify(optedIn)).toBe(200);
    expect(optedIn.access_token).toBe(completed.access_token);
  });

  it("refuses a token exchange carrying a deferral_code with invalid_request naming the deferred grant, and completes the deferral on the deferred grant", async () => {
    const { pred, code } = await openDeferral();
    approveDeferral(code);
    const viaExchange = await read(
      await tokenRequest({
        grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
        requested_token_type: ACCESS_TOKEN_TOKEN_TYPE,
        deferral_code: code,
      }),
    );
    expect(viaExchange.status, JSON.stringify(viaExchange)).toBe(400);
    expect(viaExchange.error).toBe("invalid_request");
    expect(viaExchange.error_description).toContain(DEFERRED_GRANT_TYPE);
    expect(as.kernel.get(pred.missionId)?.state).toBe("active");
    const polled = await read(await pollExpansion(code));
    expect(polled.status, JSON.stringify(polled)).toBe(200);
    expect(as.kernel.get(pred.missionId)?.termination?.successor).toBe(polled.mission_id);
  });

  it("answers a poll under another key with invalid_dpop_proof and a poll by another client as an unknown code, leaving the deferral redeemable", async () => {
    const { pred, code } = await openDeferral();
    approveDeferral(code);
    const otherKey = await read(await tokenRequestWithDpop(carryDpop, { grant_type: DEFERRED_GRANT_TYPE, deferral_code: code }));
    expect(otherKey.status, JSON.stringify(otherKey)).toBe(400);
    expect(otherKey.error).toBe("invalid_dpop_proof");
    const otherClient = await read(
      await requestAs(CARRY_ACTOR, `${CARRY_ACTOR}-auth`, carryActorKey, dpopKeys, { grant_type: DEFERRED_GRANT_TYPE, deferral_code: code }),
    );
    expect(otherClient.status, JSON.stringify(otherClient)).toBe(400);
    expect(otherClient.error).toBe("invalid_grant");
    // Answered exactly as an unknown code is, so the refusal discloses nothing.
    const unknown = await read(
      await requestAs(CARRY_ACTOR, `${CARRY_ACTOR}-auth`, carryActorKey, dpopKeys, {
        grant_type: DEFERRED_GRANT_TYPE,
        deferral_code: `xdfr_${"A".repeat(24)}`,
      }),
    );
    expect(otherClient).toEqual(unknown);
    // The client check precedes the key check (#1357): another client under
    // another key still gets the unknown code's answer.
    const otherClientOtherKey = await read(
      await requestAs(CARRY_ACTOR, `${CARRY_ACTOR}-auth`, carryActorKey, carryDpop, {
        grant_type: DEFERRED_GRANT_TYPE,
        deferral_code: code,
      }),
    );
    expect(otherClientOtherKey).toEqual(unknown);
    expect(as.kernel.get(pred.missionId)?.state).toBe("active");
    const polled = await read(await pollExpansion(code));
    expect(polled.status, JSON.stringify(polled)).toBe(200);
  });

  it("refuses to assemble a deferred expansion without the revocation endpoint its cancellation needs", async () => {
    await expect(
      buildAuthorizationServer({
        issuer: "http://localhost:14489",
        capabilities: new Set(ALL_PROVIDER_CAPABILITIES.filter((c) => c !== "token-revocation")),
      }),
    ).rejects.toThrow(/token-revocation/);
  });

  it("advertises the deferred token response and the deferral-code revocation token type", async () => {
    const meta = (await (await fetch(`${ISSUER}/.well-known/openid-configuration`)).json()) as Record<string, unknown>;
    expect(meta.deferred_token_response_supported).toBe(true);
    expect(meta.grant_types_supported).toContain(DEFERRED_GRANT_TYPE);
    expect(meta.revocation_endpoint_token_type_values_supported).toContain(DEFERRAL_CODE_TOKEN_TYPE);
  });

  for (const approved of [false, true]) {
    it(`cancels a ${approved ? "approved" : "pending"} deferral at the revocation endpoint: its next poll answers access_denied and no successor exists`, async () => {
      const { pred, code } = await openDeferral();
      if (approved) approveDeferral(code);
      const missionCountBefore = as.kernel.allMissions().length;
      const revoked = await revokeDeferral(code);
      expect(revoked.status).toBe(200);
      const polled = await read(await pollExpansion(code));
      expect(polled.status, JSON.stringify(polled)).toBe(400);
      expect(polled.error).toBe("access_denied");
      expect(polled.access_token).toBeUndefined();
      expect(as.kernel.allMissions().length).toBe(missionCountBefore);
      expect(as.kernel.get(pred.missionId)?.state).toBe("active");
    });
  }

  it("leaves a deferral unchanged when another client revokes its code, and answers 200", async () => {
    const { code } = await openDeferral();
    const revoked = await revokeDeferral(code, await assertionFor(CARRY_ACTOR, `${CARRY_ACTOR}-auth`, carryActorKey));
    expect(revoked.status).toBe(200);
    const polled = await read(await pollExpansion(code));
    expect(polled.status, JSON.stringify(polled)).toBe(400);
    expect(polled.error).toBe("authorization_pending");
  });

  it("leaves a completed deferral and its successor unchanged when the code is revoked after delivery", async () => {
    const { code } = await openDeferral();
    approveDeferral(code);
    const completed = await read(await pollExpansion(code));
    expect(completed.status, JSON.stringify(completed)).toBe(200);
    const revoked = await revokeDeferral(code);
    expect(revoked.status).toBe(200);
    expect(as.kernel.get(completed.mission_id as string)?.state).toBe("active");
    const again = await read(await pollExpansion(code));
    expect(again.status, JSON.stringify(again)).toBe(400);
    expect(again.error).toBe("invalid_grant");
  });

  it("treats a completion committed but never delivered as redeemed and then cancelled: the poll after the revocation answers access_denied, not the token", async () => {
    const { pred, code } = await openDeferral();
    approveDeferral(code);
    // FAILPOINT, as in round 5: publication throws right after the activation
    // transaction commits, before the completion is released.
    const kernelAny = as.kernel as unknown as {
      opts: { onLifecycleCommit?: (c: { id: string; event_id?: string; committed_at: string }) => void };
    };
    const realHook = kernelAny.opts.onLifecycleCommit;
    kernelAny.opts.onLifecycleCommit = () => {
      throw new Error("failpoint: crash before publication");
    };
    try {
      const first = await pollExpansion(code);
      expect(first.status).not.toBe(200);
    } finally {
      kernelAny.opts.onLifecycleCommit = realHook;
    }
    expect(as.kernel.get(pred.missionId)?.termination?.reason).toBe("superseded");
    try {
      const revoked = await revokeDeferral(code);
      expect(revoked.status).toBe(200);
      const polled = await read(await pollExpansion(code));
      expect(polled.status, JSON.stringify(polled)).toBe(400);
      expect(polled.error).toBe("access_denied");
      expect(polled.access_token).toBeUndefined();
    } finally {
      // Drain the crash window's pending events so later tests start clean.
      as.kernel.publishPendingCommits();
    }
  });
});

describe("the per-predecessor, per-client expansion rate limit (@spec expansion#policy-probing, #1177)", () => {
  it("refuses an authorized client's expansion requests for one predecessor beyond the bound with 429 temporarily_unavailable and Retry-After, whatever each would answer; another predecessor is unaffected", async () => {
    const { max } = as.expansionRateLimiter;
    const pred = await issuePredecessor(["payments:invoice.read"]);
    const wide = ["payments:invoice.read", "payments:remittance.send"];
    // A refusal counts: a non-widening request answers nothing_to_expand.
    const narrow = await expandViaExchange(pred.accessToken, "Read invoices only", ["payments:invoice.read"]);
    expect(((await narrow.json()) as { mission_denial_reason?: string }).mission_denial_reason).toBe("nothing_to_expand");
    // So do the request that opens the deferral and every retry that recovers it.
    const creationRequestId = crypto.randomUUID();
    for (let i = 1; i < max; i++) {
      const res = await expandViaExchange(pred.accessToken, "Widen to add remittance", wide, creationRequestId);
      const body = (await res.json()) as { error?: string };
      expect(body.error, `request ${i + 1}: ${JSON.stringify(body)}`).toBe("authorization_pending");
    }
    const beyond = await expandViaExchange(pred.accessToken, "Widen to add remittance", wide, creationRequestId);
    const bb = (await beyond.json()) as { error?: string; deferral_code?: string };
    expect(beyond.status, JSON.stringify(bb)).toBe(429);
    expect(bb.error).toBe("temporarily_unavailable");
    expect(bb.deferral_code).toBeUndefined();
    // The wait is the limiter's own: until the first counted request leaves
    // the window, not the provider's default for a transient refusal.
    const retryAfter = Number(beyond.headers.get("retry-after"));
    expect(retryAfter).toBeGreaterThan(as.expansionRateLimiter.windowSeconds - 60);
    expect(retryAfter).toBeLessThanOrEqual(as.expansionRateLimiter.windowSeconds);
    expect(beyond.headers.get("cache-control")).toBe("no-store");

    const other = await issuePredecessor(["payments:invoice.read"]);
    const fresh = await expandViaExchange(other.accessToken, "Widen to add remittance", wide);
    expect(((await fresh.json()) as { error?: string }).error).toBe("authorization_pending");
  });
});
