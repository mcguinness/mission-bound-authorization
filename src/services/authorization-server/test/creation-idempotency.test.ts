/**
 * @spec expansion#creation-idempotency (owner), child-delegation#creation-request-id,
 * mission-template#dispatch, RFC 9449 §11.1 — issue #467.
 *
 * `creation_request_id` is the REQUIRED idempotency handle of every
 * Mission-creating token exchange: it dedups the CREATION (never the serialized
 * response) through a durable (client, creation_request_id) reservation bound
 * to a typed operation fingerprint, committed atomically with Mission creation.
 * Covered here, per the design lock:
 *  - lost-response retry returns the SAME child (mission id equal), fan-out
 *    counted ONCE, no duplicate lifecycle events (and hence no second Child
 *    Evidence — evidence is built inside the single createChildMission run);
 *  - retry after child-grant expiry mints a FRESH grant for the SAME child;
 *  - concurrent same-id requests yield ONE creation (the datastore uniqueness
 *    constraint, exercised directly at the store level too);
 *  - same id + different fingerprint -> invalid_request;
 *  - missing creation_request_id -> invalid_request on BOTH exchanges;
 *  - missing dispatch_event_id -> invalid_request (fallback removed);
 *  - the deferral dedup key is CLIENT-scoped (two clients, same request, two
 *    deferrals) for BOTH the AROP and the expansion stores;
 *  - a reused DPoP proof jti is rejected (bounded replay cache);
 *  - the lookup-order rule: a retry whose predecessor moved to `superseded`
 *    when the first attempt succeeded recovers its completed operation, and a
 *    pending retry returns the SAME deferral_code.
 */

import { type Server } from "node:http";
import { CANONICAL_RESOURCE } from "@mission/demo-data";
import { UniqueViolationError } from "@mission/store";
import { decodeJwt, exportJWK, generateKeyPair, importJWK, SignJWT } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  ACCESS_TOKEN_TOKEN_TYPE,
  JWT_TOKEN_TYPE,
  TOKEN_EXCHANGE_GRANT_TYPE,
} from "../src/adapters/continuation-grant.js";
import { MISSION_DISPATCH_GRANT_TYPE } from "../src/adapters/provider.js";
import type { LifecycleCommit } from "../src/kernel/types.js";
import {
  buildAuthorizationServer,
  type BuiltAs,
  registerIntentSubmissionEvidenceType,
  unregisterIntentSubmissionEvidenceType,
} from "../src/index.js";
import { aiAgents } from "./actor-profiles.helper.js";

const PORT = 14520;
const ISSUER = `http://localhost:${PORT}`;
const REDIRECT_URI = "http://localhost:9999/cb";
const RESOURCE = CANONICAL_RESOURCE;
const FAR_EXP = "2027-01-01T00:00:00Z";

type DpopKeys = { privateKey: CryptoKey; publicKey: CryptoKey };

let as: BuiltAs;
let asServer: Server;
let clientKey: CryptoKey;
let dpopKeys: DpopKeys;
let verifierSeq = 0;
const commits: LifecycleCommit[] = [];

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
const intentJson = (goal: string): string =>
  JSON.stringify({ intent: { goal, resources: [RESOURCE], expires_at: FAR_EXP } });

/** Full PAR -> approval -> code -> token dance: an ACTIVE Mission + its
 *  DPoP-bound (dpopKeys) Mission ACCESS token (parent or predecessor role). */
async function issueMission(actions: string[]): Promise<{ missionId: string; accessToken: string }> {
  const jar = new Map<string, string>();
  const verifier = `creation-idem-verifier-0123456789-0123456789-${verifierSeq++}`;
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
      mission_intent: intentJson("Pay Acme invoices"),
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

/** A strict subset of the parent authority (narrowed by action; constraints restated). */
const childAuthority = () => [
  {
    type: "mission_resource_access",
    resource: RESOURCE,
    actions: ["payments:invoice.read"],
    constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
  },
];

function childParams(subjectToken: string, creationRequestId: string, goal = "Extract Acme invoices"): Record<string, string> {
  return {
    grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
    subject_token: subjectToken,
    subject_token_type: ACCESS_TOKEN_TOKEN_TYPE,
    requested_token_type: JWT_TOKEN_TYPE,
    creation_request_id: creationRequestId,
    mission_intent: intentJson(goal),
    authorization_details: JSON.stringify(childAuthority()),
    child_actor: JSON.stringify({ sub: "subagent-extractor", sub_profile: "ai_agent" }),
  };
}

function expansionParams(subjectToken: string, creationRequestId: string, actions: string[]): Record<string, string> {
  return {
    grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
    subject_token: subjectToken,
    subject_token_type: ACCESS_TOKEN_TOKEN_TYPE,
    requested_token_type: ACCESS_TOKEN_TOKEN_TYPE,
    creation_request_id: creationRequestId,
    mission_intent: intentJson("Widen to remittance"),
    authorization_details: JSON.stringify(authority(actions)),
  };
}

/** The activating lifecycle commits (creation events) recorded for a Mission. */
function activatingCommits(missionId: string): LifecycleCommit[] {
  return commits.filter(
    (c) => c.id === missionId && c.version === 1 && c.prior_state === undefined && c.state === "active",
  );
}

beforeAll(async () => {
  as = await buildAuthorizationServer({
    issuer: ISSUER,
    allowHeadlessAdjudication: true,
    actorProfiles: aiAgents("subagent-extractor"),
    onLifecycleCommit: (c) => commits.push(c),
  });
  asServer = as.provider.listen(PORT);
  clientKey = (await importJWK(as.agentClientJwk as never, "ES256")) as CryptoKey;
  dpopKeys = await generateKeyPair("ES256", { extractable: true });
});

afterAll(() => {
  asServer?.close();
});

describe("child-creation idempotency (@spec child-delegation#creation-idempotency)", () => {
  it("lost-response retry returns the SAME child: mission id equal, fan-out counted ONCE, one activating lifecycle commit (no second Child Evidence)", async () => {
    const parent = await issueMission(["payments:invoice.read", "payments:remittance.send"]);
    const derivBefore = as.kernel.get(parent.missionId)?.derivation_count;
    const crid = crypto.randomUUID();

    const first = await tokenRequest(childParams(parent.accessToken, crid));
    const b1 = (await first.json()) as { access_token: string; mission_id: string };
    expect(first.status, JSON.stringify(b1)).toBe(200);

    // The lost-response retry: identical request, same creation_request_id.
    const retry = await tokenRequest(childParams(parent.accessToken, crid));
    const b2 = (await retry.json()) as { access_token: string; mission_id: string };
    expect(retry.status, JSON.stringify(b2)).toBe(200);

    // The SAME child, and (the artifact still being valid) the SAME grant.
    expect(b2.mission_id).toBe(b1.mission_id);
    expect(b2.access_token).toBe(b1.access_token);

    // Creation-side effects happened ONCE: one child under the parent (fan-out
    // accounting counts non-terminal children), one activating commit (Child
    // Evidence is built inside the single createChildMission run), and the
    // parent's derivation counter untouched (NON-derivation, unchanged).
    expect(as.kernel.findChildren(parent.missionId)).toHaveLength(1);
    expect(activatingCommits(b1.mission_id)).toHaveLength(1);
    expect(as.kernel.get(parent.missionId)?.derivation_count).toBe(derivBefore);
  });

  it("retry after child-grant expiry mints a FRESH grant for the SAME child (issuance, not re-creation)", async () => {
    const parent = await issueMission(["payments:invoice.read", "payments:remittance.send"]);
    const crid = crypto.randomUUID();

    const first = await tokenRequest(childParams(parent.accessToken, crid));
    const b1 = (await first.json()) as { access_token: string; mission_id: string };
    expect(first.status, JSON.stringify(b1)).toBe(200);

    // Simulate delivery-artifact expiry (the child grant is deliberately
    // short-lived; the tombstone outlives it): age the recorded artifact.
    as.creationIdempotency.recordDelivery("ap-agent", crid, {
      mode: "synchronous",
      assertion: b1.access_token,
      exp: Math.floor(Date.now() / 1000) - 10,
    });

    const retry = await tokenRequest(childParams(parent.accessToken, crid));
    const b2 = (await retry.json()) as { access_token: string; mission_id: string };
    expect(retry.status, JSON.stringify(b2)).toBe(200);

    // A FRESH delivery credential for the SAME already-created child.
    expect(b2.mission_id).toBe(b1.mission_id);
    expect(b2.access_token).not.toBe(b1.access_token);
    const claims = decodeJwt(b2.access_token) as { mission: { id: string } };
    expect(claims.mission.id).toBe(b1.mission_id);

    // Re-minting is issuance accounting only: no second creation.
    expect(as.kernel.findChildren(parent.missionId)).toHaveLength(1);
    expect(activatingCommits(b1.mission_id)).toHaveLength(1);
  });

  it("concurrent same-id requests yield ONE creation; the uniqueness constraint (not a pre-read) is the serializer", async () => {
    const parent = await issueMission(["payments:invoice.read", "payments:remittance.send"]);
    const crid = crypto.randomUUID();

    const [r1, r2] = await Promise.all([
      tokenRequest(childParams(parent.accessToken, crid)),
      tokenRequest(childParams(parent.accessToken, crid)),
    ]);
    const b1 = (await r1.json()) as { mission_id?: string };
    const b2 = (await r2.json()) as { mission_id?: string };
    expect(r1.status, JSON.stringify(b1)).toBe(200);
    expect(r2.status, JSON.stringify(b2)).toBe(200);
    expect(b1.mission_id).toBe(b2.mission_id);
    expect(as.kernel.findChildren(parent.missionId)).toHaveLength(1);

    // The datastore constraint itself: a second reservation under the SAME
    // (client, creation_request_id) is refused by the PRIMARY KEY, never by a
    // read-before-insert.
    expect(() =>
      as.creationIdempotency.reserve({
        clientId: "ap-agent",
        creationRequestId: crid,
        op: "child-creation",
        fingerprint: "sha-256:not-the-recorded-fingerprint",
        cnfJkt: "x",
        sourceMissionId: parent.missionId,
      }),
    ).toThrow(UniqueViolationError);
  });

  it("same creation_request_id + different fingerprint -> invalid_request", async () => {
    const parent = await issueMission(["payments:invoice.read", "payments:remittance.send"]);
    const crid = crypto.randomUUID();

    const first = await tokenRequest(childParams(parent.accessToken, crid));
    expect(first.status).toBe(200);

    // Same identifier, semantically DIFFERENT operation (changed intent goal).
    const res = await tokenRequest(childParams(parent.accessToken, crid, "Exfiltrate everything"));
    const body = (await res.json()) as { error?: string; error_description?: string };
    expect(res.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("invalid_request");
    expect(body.error_description).toContain("different creation request");
  });

  it("missing creation_request_id -> invalid_request (child-creation)", async () => {
    const parent = await issueMission(["payments:invoice.read", "payments:remittance.send"]);
    const params = childParams(parent.accessToken, "unused");
    delete params.creation_request_id;
    const res = await tokenRequest(params);
    const body = (await res.json()) as { error?: string; error_description?: string };
    expect(res.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("invalid_request");
    expect(body.error_description).toContain("creation_request_id");
  });
});

describe("evidence vs recovery ordering (@spec mission#intent-submission-evidence, issue #506)", () => {
  // A test evidence type whose stage-2 verifier can be flipped to FAIL,
  // simulating an artifact whose freshness/status lapsed AFTER the first
  // attempt completed. Registered by this file only; the shipped registry is
  // empty.
  const IDEM_TYPE = "urn:test:intent-evidence:idem-stub";
  let failVerification = false;
  beforeAll(() => {
    registerIntentSubmissionEvidenceType(IDEM_TYPE, {
      validate(entry) {
        if (typeof entry.assertion !== "string") throw new Error("assertion required");
      },
      async verify() {
        if (failVerification) throw new Error("artifact expired after completion");
        return { admitted: true };
      },
    });
  });
  afterAll(() => unregisterIntentSubmissionEvidenceType(IDEM_TYPE));

  const IDEM_ENTRY = { type: IDEM_TYPE, assertion: "idem-artifact" };
  const evidenceChildParams = (subjectToken: string, crid: string): Record<string, string> => ({
    ...childParams(subjectToken, crid),
    mission_intent: JSON.stringify({
      intent: { goal: "Extract Acme invoices", resources: [RESOURCE], expires_at: FAR_EXP },
      evidence: [IDEM_ENTRY],
    }),
  });

  it("the completed-operation recovery lookup PRECEDES evidence re-verification: an artifact that expired after completion does not break recovery; a FRESH operation still verifies", async () => {
    failVerification = false;
    const parent = await issueMission(["payments:invoice.read", "payments:remittance.send"]);
    const crid = crypto.randomUUID();

    // First attempt: stage-2 verification runs (verifier OK) and the child is
    // created with REQUEST-DERIVED facts on its record.
    const first = await tokenRequest(evidenceChildParams(parent.accessToken, crid));
    const fb = (await first.json()) as { mission_id?: string; error?: string };
    expect(first.status, JSON.stringify(fb)).toBe(200);
    const childId = fb.mission_id as string;
    const facts = as.kernel.get(childId)?.submission_evidence;
    expect(facts?.[0]?.type).toBe(IDEM_TYPE);
    expect(facts?.[0]?.facts).toEqual({ admitted: true });

    // The artifact "expires": stage-2 verification would now FAIL...
    failVerification = true;
    // ...but the RETRY of the COMPLETED operation recovers it: the recovery
    // lookup runs BEFORE evidence freshness/status re-verification, so the
    // lost-response retry returns the SAME child, never a refusal.
    const retry = await tokenRequest(evidenceChildParams(parent.accessToken, crid));
    const rb = (await retry.json()) as { mission_id?: string; error?: string };
    expect(retry.status, JSON.stringify(rb)).toBe(200);
    expect(rb.mission_id).toBe(childId);

    // A FRESH operation (new creation_request_id) is NOT a recovery: stage-2
    // verification runs and refuses with the registered error code.
    const fresh = await tokenRequest(evidenceChildParams(parent.accessToken, crypto.randomUUID()));
    const nb = (await fresh.json()) as { error?: string; error_description?: string };
    expect(fresh.status, JSON.stringify(nb)).toBe(400);
    expect(nb.error).toBe("invalid_mission_intent_evidence");
    expect(nb.error_description).toContain("artifact expired after completion");
    failVerification = false;
  });
});

describe("expansion idempotency (@spec expansion#creation-idempotency)", () => {
  it("missing creation_request_id -> invalid_request (expansion initiation)", async () => {
    const pred = await issueMission(["payments:invoice.read"]);
    const params = expansionParams(pred.accessToken, "unused", [
      "payments:invoice.read",
      "payments:remittance.send",
    ]);
    delete params.creation_request_id;
    const res = await tokenRequest(params);
    const body = (await res.json()) as { error?: string; error_description?: string };
    expect(res.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("invalid_request");
    expect(body.error_description).toContain("creation_request_id");
  });

  it("pending retry returns the SAME deferral_code; after completion, the superseded-predecessor retry recovers the SAME successor (lookup-order rule)", async () => {
    const pred = await issueMission(["payments:invoice.read"]);
    const crid = crypto.randomUUID();
    const widened = ["payments:invoice.read", "payments:remittance.send"];

    // Initiation: widening -> deferred (authorization_pending + deferral_code).
    const opened = await tokenRequest(expansionParams(pred.accessToken, crid, widened));
    const ob = (await opened.json()) as { error?: string; deferral_code?: string };
    expect(opened.status, JSON.stringify(ob)).toBe(400);
    expect(ob.error).toBe("authorization_pending");

    // A pending retry (same client, same creation_request_id) returns the SAME
    // deferral continuation, never a second ceremony.
    const pendingRetry = await tokenRequest(expansionParams(pred.accessToken, crid, widened));
    const pb = (await pendingRetry.json()) as { error?: string; deferral_code?: string };
    expect(pendingRetry.status, JSON.stringify(pb)).toBe(400);
    expect(pb.error).toBe("authorization_pending");
    expect(pb.deferral_code).toBe(ob.deferral_code);

    // Async approval + poll: the successor is created and the predecessor
    // superseded on this first redemption.
    as.expansionDeferrals.approve(ob.deferral_code as string, {
      approver: { iss: ISSUER, sub: "bob" },
      approvalEventId: `apev-idem-${crypto.randomUUID()}`,
      approvedUntil: FAR_EXP,
    });
    const poll = await tokenRequest({
      grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
      requested_token_type: ACCESS_TOKEN_TOKEN_TYPE,
      deferral_code: ob.deferral_code as string,
    });
    const polled = (await poll.json()) as { access_token: string };
    expect(poll.status, JSON.stringify(polled)).toBe(200);
    const successorId = (decodeJwt(polled.access_token) as { mission: { id: string } }).mission.id;
    expect(as.kernel.get(pred.missionId)?.state).toBe("superseded");

    // THE LOOKUP-ORDER RULE: the retry recovered here is exactly the one whose
    // predecessor moved to `superseded` when the first attempt succeeded; the
    // idempotency lookup runs BEFORE the predecessor lifecycle gate, so the
    // completed operation is recovered instead of "predecessor is superseded".
    const retry = await tokenRequest(expansionParams(pred.accessToken, crid, widened));
    const rb = (await retry.json()) as { access_token?: string; error?: string };
    expect(retry.status, JSON.stringify(rb)).toBe(200);
    // The stored delivery artifact is still valid: the SAME successor token.
    expect(rb.access_token).toBe(polled.access_token);
    expect((decodeJwt(rb.access_token as string) as { mission: { id: string } }).mission.id).toBe(successorId);

    // Recovery never re-created: exactly one activating commit for the successor.
    expect(activatingCommits(successorId)).toHaveLength(1);
  });

  it("predecessor cross-check != the subject_token-resolved Mission -> invalid_grant; a MATCHING cross-check leaves the fingerprint/idempotency behavior unchanged", async () => {
    const pred = await issueMission(["payments:invoice.read"]);
    const widened = ["payments:invoice.read", "payments:remittance.send"];

    // Mismatch: refused with plain invalid_grant (@spec expansion#request-binding:
    // not a denial reason, so no mission_denial_reason member).
    const mismatch = await tokenRequest({
      ...expansionParams(pred.accessToken, crypto.randomUUID(), widened),
      predecessor: "msn_not-the-resolved-predecessor",
    });
    const mb = (await mismatch.json()) as { error?: string; error_description?: string };
    expect(mismatch.status, JSON.stringify(mb)).toBe(400);
    expect(mb.error).toBe("invalid_grant");
    expect(mb.error_description).toContain("predecessor");
    // No creation happened, and no operation was reserved under the identifier.
    expect(as.kernel.get(pred.missionId)?.state).toBe("active");

    // Match: the exchange proceeds normally (widening -> deferred) and the
    // idempotent retry with the SAME id + SAME matching cross-check returns the
    // SAME deferral (the cross_check fingerprint member is stable).
    const crid = crypto.randomUUID();
    const withCrossCheck = () =>
      tokenRequest({
        ...expansionParams(pred.accessToken, crid, widened),
        predecessor: pred.missionId,
      });
    const opened = await withCrossCheck();
    const ob = (await opened.json()) as { error?: string; deferral_code?: string };
    expect(opened.status, JSON.stringify(ob)).toBe(400);
    expect(ob.error).toBe("authorization_pending");
    const retry = await withCrossCheck();
    const rb = (await retry.json()) as { error?: string; deferral_code?: string };
    expect(retry.status, JSON.stringify(rb)).toBe(400);
    expect(rb.error).toBe("authorization_pending");
    expect(rb.deferral_code).toBe(ob.deferral_code);
  });

  it("deferral dedup is CLIENT-scoped: two clients, same request, two deferrals (AROP + expansion stores)", async () => {
    const m = await issueMission(["payments:invoice.read"]);
    const requested = as.kernel.get(m.missionId)?.authority_set ?? [];

    // AROP DeferralStore (the {m, r} key omitted the client before this fix).
    const a = as.deferrals.open({ missionId: m.missionId, requested, clientId: "client-a" });
    const b = as.deferrals.open({ missionId: m.missionId, requested, clientId: "client-b" });
    expect(a.deferral_code).not.toBe(b.deferral_code);
    // Same client + same request still coalesces (idempotent submission).
    const a2 = as.deferrals.open({ missionId: m.missionId, requested, clientId: "client-a" });
    expect(a2.deferral_code).toBe(a.deferral_code);

    // ExpansionDeferralStore: client-scoped as well.
    const intent = JSON.parse(intentJson("Widen it")) as never;
    const xa = as.expansionDeferrals.open({ predecessorId: m.missionId, intent, clientId: "client-a", jkt: "jkt-a" });
    const xb = as.expansionDeferrals.open({ predecessorId: m.missionId, intent, clientId: "client-b", jkt: "jkt-b" });
    expect(xa.deferral_code).not.toBe(xb.deferral_code);
    const xa2 = as.expansionDeferrals.open({ predecessorId: m.missionId, intent, clientId: "client-a", jkt: "jkt-a" });
    expect(xa2.deferral_code).toBe(xa.deferral_code);
  });
});

describe("dispatch (@spec mission-template#dispatch)", () => {
  it("missing dispatch_event_id -> invalid_request (the server-generated fallback is gone)", async () => {
    const res = await tokenRequest({
      grant_type: MISSION_DISPATCH_GRANT_TYPE,
      template_id: "tmpl_any",
      mission_intent: intentJson("reconcile Acme invoices"),
    });
    const body = (await res.json()) as { error?: string; error_description?: string };
    expect(res.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("invalid_request");
    expect(body.error_description).toContain("dispatch_event_id");
  });
});

describe("DPoP proof-jti replay (@spec RFC 9449)", () => {
  it("a reused proof jti at a custom grant is rejected with invalid_dpop_proof", async () => {
    const parent = await issueMission(["payments:invoice.read", "payments:remittance.send"]);
    const htu = `${ISSUER}/token`;
    // ONE proof, reused verbatim across two requests (fresh creation ids, so
    // only the proof is the duplicate).
    const proof = await dpopProof(htu, "POST");
    const withAssertion = async (crid: string) =>
      fetch(htu, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded", dpop: proof },
        body: new URLSearchParams({
          ...childParams(parent.accessToken, crid),
          client_assertion: await clientAssertion(),
          client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        }).toString(),
      });
    const first = await withAssertion(crypto.randomUUID());
    const fb = (await first.json()) as { error?: string };
    expect(first.status, JSON.stringify(fb)).toBe(200);

    const replay = await withAssertion(crypto.randomUUID());
    const body = (await replay.json()) as { error?: string; error_description?: string };
    expect(replay.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("invalid_dpop_proof");
    expect(body.error_description).toContain("replayed");
  });
});
