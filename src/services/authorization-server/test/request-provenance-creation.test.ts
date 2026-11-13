/**
 * @spec request-provenance#verification, request-provenance#replay,
 * request-provenance#recorded-facts, submission-evidence#presenter-binding,
 * child-delegation#creation-request-id, expansion#creation-idempotency
 * (#939 slice 3a, D1119 Q1, Q2 and Q4, D1315)
 *
 * The `mission-request-provenance` evidence type at the two token-endpoint
 * exchanges that establish a confirmation key, child creation and expansion,
 * through the real token endpoint on a controlled clock. Assertions are
 * minted live by `@mission/request-provenance` for the submitted Intent and
 * the presenter the exchange establishes: the authenticated client and the
 * thumbprint of the exchange's DPoP key. Covered here:
 *
 *  - acceptance: the established key verifies and its facts are recorded;
 *    another key, or no `cnf`, is refused;
 *  - the acceptance point (D1315 ruling 4): the exchange commits the pair
 *    when it succeeds (the child is created) or returns a pending
 *    continuation (the expansion's deferral), under the operation's
 *    reference, and releases it on every other outcome, a failed write
 *    included;
 *  - exact retry after a lost response (D1119 Q4): the same
 *    `creation_request_id` with the original evidence recovers the recorded
 *    outcome or continuation without verifying again, after `exp`; a fresh
 *    assertion is a different operation; the other recovery conditions
 *    still apply;
 *  - the deferred expansion's activation relies on the acceptance record,
 *    after `exp` and the capture age, and refuses without a matching one;
 *  - one replay store across child creation, expansion and PAR, and one
 *    winner of concurrent exchanges.
 *
 * Template dispatch and device authorization still refuse the type
 * (request-provenance-wiring.test.ts).
 */

const controlledClock = await vi.hoisted(async () => {
  const { CONTROLLED_CLOCK_MS, installControlledClock } = await import("./controlled-clock.helper.js");
  return installControlledClock(CONTROLLED_CLOCK_MS);
});

// Count the AS's signature verifications: the module's one verification
// function, wrapped so every call still verifies.
vi.mock("../src/kernel/request-provenance.js", async (importOriginal) => {
  const original = await importOriginal<typeof import("../src/kernel/request-provenance.js")>();
  return { ...original, verifyRequestProvenance: vi.fn(original.verifyRequestProvenance) };
});

import { randomBytes } from "node:crypto";
import type { Server } from "node:http";
import { DERIVATION_POLICY, PROGRESSIVE_PROFILE, parseRequestProvenanceConfig, type RequestProvenanceConfig } from "@mission/demo-data";
import { createRequestIntake, type JsonObject, type Presenter } from "@mission/request-provenance";
import { openStore } from "@mission/store";
import { CompactSign, calculateJwkThumbprint, decodeJwt, exportJWK, generateKeyPair, importJWK, type JWK, SignJWT } from "jose";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { RENDER_REVISION_HEADER } from "../src/adapters/approval-render-revision.js";
import { ACCESS_TOKEN_TOKEN_TYPE, JWT_TOKEN_TYPE, TOKEN_EXCHANGE_GRANT_TYPE } from "../src/adapters/continuation-grant.js";
import {
  ALL_PROVIDER_CAPABILITIES,
  ApprovalSessionStore,
  buildAuthorizationServer,
  type BuiltAs,
  creationAcceptanceRef,
  DEFERRED_GRANT_TYPE,
  IntentError,
  type MissionRecord,
  type ProviderCapability,
  provisionalIntentHash,
  registerIntentSubmissionEvidenceType,
  type RequestProvenanceAcceptance,
  type RequestProvenanceRecord,
  type RequestProvenanceStore,
  SqliteRequestProvenanceStore,
  unregisterIntentSubmissionEvidenceType,
} from "../src/index.js";
import { assembledCeilingOffer, progressiveFromProfile } from "../src/kernel/progressive.js";
import { verifyRequestProvenance } from "../src/kernel/request-provenance.js";
import type { AuthorityEntry } from "../src/kernel/types.js";
import { aiAgents } from "./actor-profiles.helper.js";
import { browserApprovalHeaders, TEST_APPROVAL_PRINCIPALS } from "./approval-fixture.js";
import { FIXTURE_EXPIRES_AT } from "./relative-expiry.helper.js";

type Json = null | boolean | number | string | Json[] | { [key: string]: Json };
type JsonRecord = { [key: string]: Json };

const TYPE = "mission-request-provenance";
const PORT = 14916;
const ISSUER = `http://localhost:${PORT}`;
/** A Progressive deployment, where an in-ceiling expansion completes synchronously as a drawdown. */
const DRAWDOWN_PORT = 14917;
const DRAWDOWN_ISSUER = `http://localhost:${DRAWDOWN_PORT}`;
const REDIRECT_URI = "http://localhost:9999/cb";
const RESOURCE = DERIVATION_POLICY.ceiling[0].resource as string;
const CLIENT = "ap-agent";
const PUSHED_REQUEST_URN = "urn:ietf:params:oauth:request_uri:";

const INTAKE = "https://intake.example.org";
const INTAKE_KID = "intake-1";
const IDP = "https://idp.example.org";
const CHANNEL = "https://intake.example.org/ch/app";

/** One Intent both exchanges submit, so one assertion can be presented at either. */
const INTENT = { goal: "Reconcile Acme invoices against the ledger", target_resources: [RESOURCE], expires_at: FIXTURE_EXPIRES_AT };

const READ = ["payments:invoice.read"];
const WIDENED = ["payments:invoice.read", "payments:remittance.send"];
const entryOf = (actions: string[]) => [
  {
    type: "mission_resource_access",
    resource: RESOURCE,
    actions,
    constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
  },
];

const intakeKeys = await generateKeyPair("ES256", { extractable: true });

/** Skew 5 s; lifetime and capture age at most 30 s. */
const TRUST: RequestProvenanceConfig = parseRequestProvenanceConfig({
  enabled: true,
  clock_skew_seconds: 5,
  max_assertion_lifetime_seconds: 30,
  max_capture_age_seconds: 30,
  signers: [
    {
      iss: INTAKE,
      keys: [{ kid: INTAKE_KID, public_jwk: (await exportJWK(intakeKeys.publicKey)) as unknown as Json, evidence_types: [TYPE], algs: ["ES256"] }],
      originators: [{ iss: IDP }],
      channel_types: [CHANNEL],
    },
  ],
});

/** The exchanges' DPoP key, and another the client does not use. */
const dpopKeys = await generateKeyPair("ES256", { extractable: true });
const dpopJkt = await calculateJwkThumbprint(await exportJWK(dpopKeys.publicKey));
const otherJkt = await calculateJwkThumbprint(await exportJWK((await generateKeyPair("ES256", { extractable: true })).publicKey));

/** The presenter the token exchanges establish: the client and the thumbprint of its DPoP key. */
const EXCHANGE_PRESENTER: Presenter = { client_id: CLIENT, cnf: { jkt: dpopJkt } };

/** Capture and sign through the intake library on the controlled clock: `iat` now, captured 5 s before. */
async function mint(o: { presenter?: Presenter; intent?: JsonObject; audience?: string } = {}) {
  let offsetMs = -5000;
  const intake = createRequestIntake({
    issuer: INTAKE,
    kid: INTAKE_KID,
    signingKey: intakeKeys.privateKey,
    assertionLifetimeSeconds: 20,
    maxCaptureAgeSeconds: 3600,
    now: () => Date.now() + offsetMs,
    randomBytes: (size) => randomBytes(size),
  });
  const receipt = intake.capture({
    workflow: "wf-1",
    instruction: Buffer.from("Reconcile the Acme invoices against the ledger, nothing else.", "utf8"),
    mediaType: "text/plain;charset=utf-8",
    originator: { iss: IDP, sub: "alice" },
    channel: { type: CHANNEL, amr: ["pwd", "otp"], auth_time: Math.floor(Date.now() / 1000) - 60 },
    presenter: o.presenter ?? EXCHANGE_PRESENTER,
  });
  offsetMs = 0;
  return intake.sign({ captureId: receipt.captureId, workflow: "wf-1", audience: o.audience ?? ISSUER, intent: (o.intent ?? INTENT) as JsonObject });
}

const decodePart = (part: string): JsonRecord => JSON.parse(Buffer.from(part, "base64url").toString("utf8")) as JsonRecord;
const claimsOf = (assertion: string): JsonRecord => decodePart(assertion.split(".")[1] as string);

/** Re-sign an assertion with its claims changed, under the configured intake key. */
async function resign(assertion: string, claims: (c: JsonRecord) => JsonRecord): Promise<string> {
  return new CompactSign(new TextEncoder().encode(JSON.stringify(claims(claimsOf(assertion)))))
    .setProtectedHeader(decodePart(assertion.split(".")[0] as string) as never)
    .sign(intakeKeys.privateKey);
}

const envelope = (evidence: unknown[], intent: unknown = INTENT) => ({ intent, evidence });

/**
 * The AS's replay store on a database of its own, observed. A test can make
 * every acceptance record read as missing, fail the next commit write, or
 * gather concurrent reservations so they reach the store in one turn.
 */
class ObservedStore implements RequestProvenanceStore {
  readonly inner = new SqliteRequestProvenanceStore(openStore(""));
  lost = false;
  failNextCommit = false;
  #gathering: { size: number; waiting: Array<() => void> } | undefined;

  gather(size: number): void {
    const gathering = { size, waiting: [] as Array<() => void> };
    this.#gathering = gathering;
    setTimeout(() => {
      if (this.#gathering === gathering) {
        this.#gathering = undefined;
        for (const go of gathering.waiting) go();
      }
    }, 10_000).unref();
  }

  async reserve(record: RequestProvenanceRecord, nowMs: number): Promise<string | undefined> {
    const gathering = this.#gathering;
    if (gathering) {
      await new Promise<void>((go) => {
        gathering.waiting.push(go);
        if (gathering.waiting.length >= gathering.size) {
          this.#gathering = undefined;
          for (const each of gathering.waiting) each();
        }
      });
    }
    return this.inner.reserve(record, nowMs);
  }

  committable(token: string, nowMs: number): boolean {
    return this.inner.committable(token, nowMs);
  }

  transaction(fn: () => void): void {
    this.inner.transaction(fn);
  }

  commit(token: string, ref: string, nowMs: number, retainUntilMs: number): boolean {
    if (this.failNextCommit) {
      this.failNextCommit = false;
      throw new Error("the replay store refused the write");
    }
    return this.inner.commit(token, ref, nowMs, retainUntilMs);
  }

  release(token: string): void {
    this.inner.release(token);
  }

  accepted(iss: string, jti: string, nowMs: number): RequestProvenanceAcceptance | undefined {
    return this.lost ? undefined : this.inner.accepted(iss, jti, nowMs);
  }
}

/** An assembly the client talks to: its issuer, the client's key there, and its Approver sessions. */
interface Target {
  issuer: string;
  agentKey: CryptoKey;
  sessions: ApprovalSessionStore;
}

const SESSIONS = new ApprovalSessionStore();
const store = new ObservedStore();
let as: BuiltAs;
let server: Server;
let main: Target;

/** The Progressive deployment's published drawdown policies and options, its replay store the default one on its kernel's database. */
const PUBLISHED = progressiveFromProfile(PROGRESSIVE_PROFILE);
/** The ceiling its approval surface offers: the payments ceiling under the one-added-action drawdown policy. */
const CEILING_OFFER = {
  authority_ceiling: DERIVATION_POLICY.ceiling.filter((e) => e.resource === RESOURCE) as unknown as AuthorityEntry[],
  drawdown_policy: { id: "drawdown-std", version: "1" },
};
const DRAWDOWN_SESSIONS = new ApprovalSessionStore();
let drawdownAs: BuiltAs;
let drawdownServer: Server;
let drawdownTarget: Target;

/** A test evidence type beside the provenance type, whose verification always fails. */
const REFUSING_TYPE = "urn:test:intent-evidence:creation-refuses";
registerIntentSubmissionEvidenceType(REFUSING_TYPE, {
  validate(e) {
    if (typeof e.assertion !== "string") throw new IntentError("invalid_mission_intent_evidence", "test type: assertion required");
  },
  async verify() {
    throw new Error("test type: this artifact never verifies");
  },
});

const verifications = () => vi.mocked(verifyRequestProvenance).mock.calls.length;

beforeAll(async () => {
  as = await buildAuthorizationServer({
    issuer: ISSUER,
    allowHeadlessAdjudication: true,
    serviceTokenPrincipals: TEST_APPROVAL_PRINCIPALS,
    approvalSessions: SESSIONS,
    capabilities: new Set<ProviderCapability>([...ALL_PROVIDER_CAPABILITIES]),
    actorProfiles: aiAgents("subagent-extractor"),
    requestProvenance: { config: TRUST, store },
  } as Parameters<typeof buildAuthorizationServer>[0]);
  server = as.provider.listen(PORT);
  main = { issuer: ISSUER, agentKey: (await importJWK(as.agentClientJwk as never, "ES256")) as CryptoKey, sessions: SESSIONS };
  drawdownAs = await buildAuthorizationServer({
    issuer: DRAWDOWN_ISSUER,
    approvalSessions: DRAWDOWN_SESSIONS,
    activationPolicies: PUBLISHED.policies,
    progressive: { ...PUBLISHED.options, ceilingOffer: () => CEILING_OFFER },
    requestProvenance: { config: TRUST },
  } as Parameters<typeof buildAuthorizationServer>[0]);
  drawdownServer = drawdownAs.provider.listen(DRAWDOWN_PORT);
  drawdownTarget = {
    issuer: DRAWDOWN_ISSUER,
    agentKey: (await importJWK(drawdownAs.agentClientJwk as never, "ES256")) as CryptoKey,
    sessions: DRAWDOWN_SESSIONS,
  };
});

afterAll(() => {
  server?.close();
  drawdownServer?.close();
  unregisterIntentSubmissionEvidenceType(REFUSING_TYPE);
  controlledClock.restore();
});

async function clientAssertion(t: Target): Promise<string> {
  return new SignJWT({})
    .setProtectedHeader({ alg: "ES256", kid: "ap-agent-auth" })
    .setIssuer(CLIENT)
    .setSubject(CLIENT)
    .setAudience(t.issuer)
    .setIssuedAt()
    .setExpirationTime("2m")
    .setJti(crypto.randomUUID())
    .sign(t.agentKey);
}

interface Reply {
  status: number;
  body: Record<string, unknown>;
}

async function reply(res: Response): Promise<Reply> {
  const text = await res.text();
  try {
    return { status: res.status, body: JSON.parse(text) as Record<string, unknown> };
  } catch {
    return { status: res.status, body: { text } };
  }
}

const PKCE_VERIFIER = "request-provenance-creation-verifier-0123456789-0123456789";
const pkceChallenge = async () =>
  Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(PKCE_VERIFIER))).toString("base64url");

/** A pushed authorization request as ap-agent, its value of mission_intent the given envelope, with an optional proposal. */
async function push(submission: unknown, proposal?: unknown, t: Target = main): Promise<Reply> {
  return reply(
    await fetch(`${t.issuer}/request`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: CLIENT,
        response_type: "code",
        redirect_uri: REDIRECT_URI,
        resource: RESOURCE,
        code_challenge: await pkceChallenge(),
        code_challenge_method: "S256",
        login_hint: "alice",
        mission_intent: JSON.stringify(submission),
        ...(proposal ? { authorization_details: JSON.stringify(proposal) } : {}),
        client_assertion: await clientAssertion(t),
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      }).toString(),
    }),
  );
}

/** POST /token as ap-agent with a DPoP proof under the exchanges' key, with the nonce retry. */
async function tokenRequest(params: Record<string, string>, t: Target = main): Promise<Reply> {
  const htu = `${t.issuer}/token`;
  const send = async (extra: Record<string, unknown> = {}) =>
    fetch(htu, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        dpop: await new SignJWT({ htu, htm: "POST", ...extra })
          .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: (await exportJWK(dpopKeys.publicKey)) as JWK })
          .setIssuedAt()
          .setJti(crypto.randomUUID())
          .sign(dpopKeys.privateKey),
      },
      body: new URLSearchParams({
        ...params,
        client_assertion: await clientAssertion(t),
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      }).toString(),
    });
  let res = await send();
  const nonce = res.headers.get("dpop-nonce");
  if (res.status === 400 && nonce) res = await send({ nonce });
  return reply(res);
}

type Jar = Map<string, string>;
const cookieOf = (jar: Jar) => [...jar].map(([k, v]) => `${k}=${v}`).join("; ");
function keep(jar: Jar, res: Response): void {
  for (const line of res.headers.getSetCookie()) {
    const [pair] = line.split(";");
    const eq = (pair as string).indexOf("=");
    jar.set((pair as string).slice(0, eq), (pair as string).slice(eq + 1));
  }
}

/**
 * An active Mission and its access token, DPoP-bound to the exchanges' key,
 * through a push with no evidence, its authority the read action alone: a
 * child may take it, and an expansion widens it.
 */
async function issueMission(
  t: Target = main,
  o: { proposal?: unknown; decided?: Record<string, unknown> } = {},
): Promise<{ missionId: string; accessToken: string }> {
  const par = await push({ intent: INTENT }, o.proposal ?? entryOf(READ), t);
  expect(par.status, JSON.stringify(par.body)).toBe(201);
  const jar: Jar = new Map();
  const auth = await fetch(`${t.issuer}/auth?${new URLSearchParams({ client_id: CLIENT, request_uri: par.body.request_uri as string })}`, {
    redirect: "manual",
  });
  keep(jar, auth);
  const uid = (auth.headers.get("location") ?? "").split("/interaction/")[1] as string;
  expect(uid).toBeTruthy();
  const headers = browserApprovalHeaders(t.sessions, uid, { sub: "bob", acr: "mfa", auth_time: Math.floor(Date.now() / 1000), subject: "alice" }, cookieOf(jar));
  const page = await fetch(`${t.issuer}/interaction/${uid}`, { headers });
  expect(page.status).toBe(200);
  let res = await fetch(`${t.issuer}/interaction/${uid}/decide`, {
    method: "POST",
    redirect: "manual",
    headers: { ...headers, "content-type": "application/json" },
    body: JSON.stringify({ decision: "approve", render_revision: page.headers.get(RENDER_REVISION_HEADER), ...o.decided }),
  });
  keep(jar, res);
  let location = res.headers.get("location") ?? "";
  while (location.startsWith(t.issuer)) {
    res = await fetch(location, { redirect: "manual", headers: { cookie: cookieOf(jar) } });
    keep(jar, res);
    location = res.headers.get("location") ?? "";
  }
  const code = new URL(location).searchParams.get("code") as string;
  expect(code, location).toBeTruthy();
  const tok = await tokenRequest({ grant_type: "authorization_code", code, redirect_uri: REDIRECT_URI, code_verifier: PKCE_VERIFIER, resource: RESOURCE }, t);
  expect(tok.status, JSON.stringify(tok.body)).toBe(200);
  const accessToken = tok.body.access_token as string;
  return { missionId: (decodeJwt(accessToken) as { mission: { id: string } }).mission.id, accessToken };
}

/** The child-creation exchange under `parent`, presenting `evidence`. */
function createChild(parent: { accessToken: string }, evidence: unknown[], o: { crid?: string; actions?: string[] } = {}): Promise<Reply> {
  return tokenRequest({
    grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
    subject_token: parent.accessToken,
    subject_token_type: ACCESS_TOKEN_TOKEN_TYPE,
    requested_token_type: JWT_TOKEN_TYPE,
    creation_request_id: o.crid ?? crypto.randomUUID(),
    mission_intent: JSON.stringify(envelope(evidence)),
    authorization_details: JSON.stringify(entryOf(o.actions ?? READ)),
    child_actor: JSON.stringify({ sub: "subagent-extractor", sub_profile: "ai_agent" }),
  });
}

/** The expansion exchange of `predecessor`, presenting `evidence`, in the deferred mode unless told otherwise. */
function expand(
  predecessor: { accessToken: string },
  evidence: unknown[],
  o: { crid?: string; actions?: string[]; proposal?: unknown; deferred?: boolean; target?: Target } = {},
): Promise<Reply> {
  return tokenRequest(
    {
      grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
      subject_token: predecessor.accessToken,
      subject_token_type: ACCESS_TOKEN_TOKEN_TYPE,
      requested_token_type: ACCESS_TOKEN_TOKEN_TYPE,
      creation_request_id: o.crid ?? crypto.randomUUID(),
      ...(o.deferred === false ? {} : { completion_mode: "deferred" }),
      mission_intent: JSON.stringify(envelope(evidence)),
      authorization_details: JSON.stringify(o.proposal ?? entryOf(o.actions ?? WIDENED)),
    },
    o.target ?? main,
  );
}

const poll = (deferralCode: string) => tokenRequest({ grant_type: DEFERRED_GRANT_TYPE, deferral_code: deferralCode });

let approvals = 0;
function approveExpansion(deferralCode: string): void {
  expect(
    as.expansionDeferrals.approve(deferralCode, {
      approver: { iss: ISSUER, sub: "bob" },
      authentication: { surface: "browser", acr: "mfa", auth_time: Math.floor(Date.now() / 1000) },
      approvalEventId: `apev-rp-creation-${approvals++}`,
      approvedUntil: FIXTURE_EXPIRES_AT,
    }),
  ).toBe(true);
}

/** The pair's acceptance record in the store, read past any simulated loss. */
const acceptanceOf = (assertion: string) => {
  const c = claimsOf(assertion);
  return store.inner.accepted(String(c.iss), String(c.jti), Date.now());
};

const deferralRow = (code: string) =>
  as.kernel.db.prepare("SELECT acceptance_ref, evidence_json, state FROM expansion_deferrals WHERE deferral_code = ?").get(code) as {
    acceptance_ref: string | null;
    evidence_json: string | null;
    state: string;
  };

function expectEvidenceRefusal(r: Reply, reason?: string): void {
  expect(r.status, JSON.stringify(r.body)).toBe(400);
  expect(r.body.error).toBe("invalid_mission_intent_evidence");
  if (reason !== undefined) expect(String(r.body.error_description)).toContain(reason);
}

function expectPending(r: Reply): string {
  expect(r.status, JSON.stringify(r.body)).toBe(400);
  expect(r.body.error).toBe("authorization_pending");
  return r.body.deferral_code as string;
}

function expectChild(r: Reply): string {
  expect(r.status, JSON.stringify(r.body)).toBe(200);
  return r.body.mission_id as string;
}

describe("child creation accepts mission-request-provenance (@spec request-provenance#verification, request-provenance#replay, submission-evidence#presenter-binding, #939 slice 3a)", () => {
  it("accepts an assertion naming the exchange's DPoP key, commits its (iss, jti) under the operation's reference, and records its facts on the child", async () => {
    const parent = await issueMission();
    const signed = await mint();
    const crid = crypto.randomUUID();
    const before = verifications();
    const childId = expectChild(await createChild(parent, [signed.entry], { crid }));
    expect(verifications()).toBe(before + 1);
    const accepted = acceptanceOf(signed.entry.assertion);
    expect(accepted?.submissionRef).toBe(creationAcceptanceRef("child-creation", CLIENT, crid));
    expect(accepted?.presenter).toEqual({ clientId: CLIENT, cnf: { jkt: dpopJkt } });
    expect(accepted?.intentHash).toBe(provisionalIntentHash(ISSUER, INTENT as never));
    const child = as.kernel.get(childId) as MissionRecord;
    expect(child.submission_evidence).toEqual([
      { type: TYPE, artifact_hash: accepted?.artifactHash, verified_at: accepted?.verifiedAt, facts: accepted?.facts },
    ]);
  });

  it("refuses invalid_mission_intent_evidence an assertion naming another key, and one with no cnf, and creates nothing", async () => {
    const parent = await issueMission();
    const other = await mint({ presenter: { client_id: CLIENT, cnf: { jkt: otherJkt } } });
    const bare = await mint({ presenter: { client_id: CLIENT } });
    const missions = as.kernel.allMissions().length;
    expectEvidenceRefusal(await createChild(parent, [other.entry]), "presenter.cnf is not the confirmation key the exchange established");
    expectEvidenceRefusal(await createChild(parent, [bare.entry]), "presenter carries no cnf where the exchange established a confirmation key");
    expect(as.kernel.allMissions().length).toBe(missions);
    expect(acceptanceOf(other.entry.assertion)).toBeUndefined();
    expect(acceptanceOf(bare.entry.assertion)).toBeUndefined();
  });
});

describe("expansion accepts mission-request-provenance (@spec request-provenance#verification, request-provenance#replay, submission-evidence#presenter-binding, #939 slice 3a)", () => {
  it("accepts an assertion naming the exchange's DPoP key, commits its (iss, jti) under the operation's reference when it returns the pending continuation, and the deferral keeps that reference and the entry", async () => {
    const predecessor = await issueMission();
    const signed = await mint();
    const crid = crypto.randomUUID();
    const before = verifications();
    const code = expectPending(await expand(predecessor, [signed.entry], { crid }));
    expect(verifications()).toBe(before + 1);
    const ref = creationAcceptanceRef("expansion", CLIENT, crid);
    const accepted = acceptanceOf(signed.entry.assertion);
    expect(accepted?.submissionRef).toBe(ref);
    expect(accepted?.presenter).toEqual({ clientId: CLIENT, cnf: { jkt: dpopJkt } });
    const row = deferralRow(code);
    expect(row.acceptance_ref).toBe(ref);
    expect(JSON.parse(row.evidence_json as string)).toEqual([signed.entry]);
  });

  it("refuses invalid_mission_intent_evidence an assertion naming another key, and one with no cnf, and opens no deferral", async () => {
    const predecessor = await issueMission();
    const other = await mint({ presenter: { client_id: CLIENT, cnf: { jkt: otherJkt } } });
    const bare = await mint({ presenter: { client_id: CLIENT } });
    const deferrals = () => (as.kernel.db.prepare("SELECT COUNT(*) AS n FROM expansion_deferrals").get() as { n: number }).n;
    const opened = deferrals();
    expectEvidenceRefusal(await expand(predecessor, [other.entry]), "presenter.cnf is not the confirmation key the exchange established");
    expectEvidenceRefusal(await expand(predecessor, [bare.entry]), "presenter carries no cnf where the exchange established a confirmation key");
    expect(deferrals()).toBe(opened);
    expect(acceptanceOf(other.entry.assertion)).toBeUndefined();
    expect(acceptanceOf(bare.entry.assertion)).toBeUndefined();
  });
});

describe("exact retry after a lost response (@spec request-provenance#replay, child-delegation#creation-request-id, expansion#creation-idempotency, #939 slice 3a, D1119 Q4)", () => {
  it("child creation: a retry with the same creation_request_id and the original assertion recovers the recorded child after exp passes, verifying nothing again", async () => {
    const parent = await issueMission();
    const signed = await mint();
    const crid = crypto.randomUUID();
    const childId = expectChild(await createChild(parent, [signed.entry], { crid }));
    const missions = as.kernel.allMissions().length;
    // The response is lost; the client retries once the assertion has expired.
    controlledClock.advance((signed.exp + 5 + 1) * 1000 - Date.now());
    const before = verifications();
    const retried = await createChild(parent, [signed.entry], { crid });
    expect(expectChild(retried)).toBe(childId);
    expect(verifications()).toBe(before);
    expect(as.kernel.allMissions().length).toBe(missions);
  });

  it("child creation: a retry presenting a fresh assertion is refused invalid_request as a different operation, verifies nothing, and creates nothing", async () => {
    const parent = await issueMission();
    const crid = crypto.randomUUID();
    expectChild(await createChild(parent, [(await mint()).entry], { crid }));
    const fresh = await mint();
    const missions = as.kernel.allMissions().length;
    const before = verifications();
    const r = await createChild(parent, [fresh.entry], { crid });
    expect(r.status, JSON.stringify(r.body)).toBe(400);
    expect(r.body.error).toBe("invalid_request");
    expect(String(r.body.error_description)).toContain("already used for a different creation request");
    expect(verifications()).toBe(before);
    expect(as.kernel.allMissions().length).toBe(missions);
    expect(acceptanceOf(fresh.entry.assertion)).toBeUndefined();
  });

  it("child creation: the other recovery conditions still apply: an exact retry after the recorded child was revoked is refused", async () => {
    const parent = await issueMission();
    const signed = await mint();
    const crid = crypto.randomUUID();
    const childId = expectChild(await createChild(parent, [signed.entry], { crid }));
    as.kernel.transition(childId, "revoke");
    const r = await createChild(parent, [signed.entry], { crid });
    expect(r.status, JSON.stringify(r.body)).toBe(400);
    expect(String(r.body.error_description)).toContain("recorded child mission is terminated");
  });

  it("expansion: a retry with the same creation_request_id and the original assertion recovers the same pending continuation after exp passes, verifying nothing again", async () => {
    const predecessor = await issueMission();
    const signed = await mint();
    const crid = crypto.randomUUID();
    const code = expectPending(await expand(predecessor, [signed.entry], { crid }));
    controlledClock.advance((signed.exp + 5 + 1) * 1000 - Date.now());
    const before = verifications();
    expect(expectPending(await expand(predecessor, [signed.entry], { crid }))).toBe(code);
    expect(verifications()).toBe(before);
  });

  it("expansion: a retry presenting a fresh assertion is refused invalid_request as a different operation, verifies nothing, and opens nothing", async () => {
    const predecessor = await issueMission();
    const crid = crypto.randomUUID();
    expectPending(await expand(predecessor, [(await mint()).entry], { crid }));
    const fresh = await mint();
    const before = verifications();
    const r = await expand(predecessor, [fresh.entry], { crid });
    expect(r.status, JSON.stringify(r.body)).toBe(400);
    expect(r.body.error).toBe("invalid_request");
    expect(String(r.body.error_description)).toContain("already used for a different creation request");
    expect(verifications()).toBe(before);
    expect(acceptanceOf(fresh.entry.assertion)).toBeUndefined();
  });

  it("expansion: the other recovery conditions still apply: an exact retry that does not opt into the deferred mode again is refused", async () => {
    const predecessor = await issueMission();
    const signed = await mint();
    const crid = crypto.randomUUID();
    expectPending(await expand(predecessor, [signed.entry], { crid }));
    const r = await expand(predecessor, [signed.entry], { crid, deferred: false });
    expect(r.status, JSON.stringify(r.body)).toBe(400);
    expect(r.body.error).toBe("invalid_request");
    expect(String(r.body.error_description)).toContain("must include deferred in completion_mode");
  });
});

describe("the deferred expansion's activation (@spec request-provenance#replay, request-provenance#recorded-facts, #939 slice 3a, D1119 Q1 and Q2)", () => {
  it("activates after exp and the capture age pass, relying on the acceptance record: verifies nothing again and records the exchange's verification time and facts", async () => {
    const predecessor = await issueMission();
    const signed = await mint();
    const code = expectPending(await expand(predecessor, [signed.entry]));
    const accepted = acceptanceOf(signed.entry.assertion);
    approveExpansion(code);
    // One minute on: past exp plus the allowance and the capture's maximum age, inside the deferral's lifetime.
    controlledClock.advance(60_000);
    expect(Date.now() / 1000).toBeGreaterThan(signed.exp + 5);
    const before = verifications();
    const delivered = await poll(code);
    expect(delivered.status, JSON.stringify(delivered.body)).toBe(200);
    expect(verifications()).toBe(before);
    const successor = as.kernel.get(delivered.body.mission_id as string) as MissionRecord;
    expect(successor.submission_evidence).toEqual([
      { type: TYPE, artifact_hash: accepted?.artifactHash, verified_at: accepted?.verifiedAt, facts: accepted?.facts },
    ]);
    expect(Date.parse(accepted?.verifiedAt as string)).toBeLessThan(Date.now() - 59_000);
  });

  async function approvedDeferral(): Promise<{ code: string; successors: () => number }> {
    const predecessor = await issueMission();
    const code = expectPending(await expand(predecessor, [(await mint()).entry]));
    approveExpansion(code);
    const successors = () => as.kernel.allMissions().filter((m) => m.predecessor === predecessor.missionId).length;
    return { code, successors };
  }

  function expectActivationRefused(r: Reply, reason: string): void {
    expect(r.status, JSON.stringify(r.body)).toBe(400);
    expect(r.body.error).toBe("access_denied");
    expect(String(r.body.error_description)).toContain(reason);
  }

  it("refuses the activation when the acceptance record is missing: access_denied, with no successor, and every later poll repeats it", async () => {
    const { code, successors } = await approvedDeferral();
    store.lost = true;
    try {
      expectActivationRefused(await poll(code), "no acceptance record for this submission's assertion");
    } finally {
      store.lost = false;
    }
    expect(successors()).toBe(0);
    controlledClock.advance(6000);
    const again = await poll(code);
    expect(again.status, JSON.stringify(again.body)).toBe(400);
    expect(again.body.error).toBe("access_denied");
    expect(successors()).toBe(0);
  });

  it("refuses the activation when the deferral names another submission than the one accepted: access_denied, with no successor", async () => {
    const { code, successors } = await approvedDeferral();
    as.kernel.db
      .prepare("UPDATE expansion_deferrals SET acceptance_ref = ? WHERE deferral_code = ?")
      .run(creationAcceptanceRef("expansion", CLIENT, "another-operation"), code);
    expectActivationRefused(await poll(code), "the acceptance record belongs to another submission");
    expect(successors()).toBe(0);
  });

  it("refuses the activation when the deferral names no accepted submission: access_denied, with no successor", async () => {
    const { code, successors } = await approvedDeferral();
    as.kernel.db.prepare("UPDATE expansion_deferrals SET acceptance_ref = NULL WHERE deferral_code = ?").run(code);
    expectActivationRefused(await poll(code), "the pending operation names no accepted submission");
    expect(successors()).toBe(0);
  });
});

describe("one replay store across carriers (@spec request-provenance#replay, #939 slice 3a)", () => {
  it("an assertion committed at child creation is refused as replay at expansion, and one committed at expansion is refused as replay at child creation", async () => {
    const mission = await issueMission();
    const atChild = await mint();
    expectChild(await createChild(mission, [atChild.entry]));
    expectEvidenceRefusal(await expand(mission, [atChild.entry]), "replay");
    const atExpansion = await mint();
    expectPending(await expand(mission, [atExpansion.entry]));
    expectEvidenceRefusal(await createChild(mission, [atExpansion.entry]), "replay");
  });

  it("a pair committed at a token exchange is refused as replay at PAR, and one committed at PAR as replay at child creation (the same pair re-signed for each presenter)", async () => {
    const mission = await issueMission();
    // Committed at child creation; the same (iss, jti) for the push's presenter, which has no key.
    const atChild = await mint();
    expectChild(await createChild(mission, [atChild.entry]));
    const forPush = await resign(atChild.entry.assertion, (c) => ({ ...c, presenter: { client_id: CLIENT } }));
    expectEvidenceRefusal(await push(envelope([{ type: TYPE, assertion: forPush }])), "replay");
    // Committed at PAR; the same (iss, jti) for the exchange's presenter.
    const atPush = await mint({ presenter: { client_id: CLIENT } });
    const pushed = await push(envelope([atPush.entry]));
    expect(pushed.status, JSON.stringify(pushed.body)).toBe(201);
    expect(acceptanceOf(atPush.entry.assertion)?.submissionRef).toBe(
      `par:${(pushed.body.request_uri as string).slice(PUSHED_REQUEST_URN.length)}`,
    );
    const forExchange = await resign(atPush.entry.assertion, (c) => ({ ...c, presenter: EXCHANGE_PRESENTER as unknown as Json }));
    expectEvidenceRefusal(await createChild(mission, [{ type: TYPE, assertion: forExchange }]), "replay");
    expectEvidenceRefusal(await expand(mission, [{ type: TYPE, assertion: forExchange }]), "replay");
  });
});

describe("release before acceptance at the token exchanges (@spec request-provenance#replay, #939 slice 3a)", () => {
  it("child creation: another evidence entry failing releases the reservation, so the same assertion is accepted next", async () => {
    const parent = await issueMission();
    const signed = await mint();
    expectEvidenceRefusal(await createChild(parent, [signed.entry, { type: REFUSING_TYPE, assertion: "x" }]), "never verifies");
    expectChild(await createChild(parent, [signed.entry]));
  });

  it("child creation: a creation the exchange refuses after verification releases the reservation, so the same assertion is accepted next", async () => {
    const parent = await issueMission();
    const signed = await mint();
    const before = verifications();
    // Wider than the parent's authority: the creation is refused, recorded as the operation's outcome.
    const refused = await createChild(parent, [signed.entry], { actions: WIDENED });
    expect(refused.status, JSON.stringify(refused.body)).toBeGreaterThanOrEqual(400);
    expect(refused.status).toBeLessThan(500);
    expect(verifications()).toBe(before + 1);
    expect(acceptanceOf(signed.entry.assertion)).toBeUndefined();
    expectChild(await createChild(parent, [signed.entry]));
  });

  it("child creation: a failed creation write releases the reservation, so the same assertion is accepted on the retry", async () => {
    const parent = await issueMission();
    const signed = await mint();
    const crid = crypto.randomUUID();
    const createCompleted = vi.spyOn(as.creationIdempotency, "createCompleted").mockImplementationOnce(() => {
      throw new Error("the kernel database refused the write");
    });
    try {
      const r = await createChild(parent, [signed.entry], { crid });
      expect(r.status, JSON.stringify(r.body)).toBe(500);
    } finally {
      createCompleted.mockRestore();
    }
    expect(acceptanceOf(signed.entry.assertion)).toBeUndefined();
    expectChild(await createChild(parent, [signed.entry], { crid }));
  });

  it("child creation: a failed acceptance commit rolls the child's creation back with it, so no child exists and the retry creates one", async () => {
    const parent = await issueMission();
    const signed = await mint();
    const crid = crypto.randomUUID();
    const missions = as.kernel.allMissions().length;
    store.failNextCommit = true;
    let r: Reply;
    try {
      r = await createChild(parent, [signed.entry], { crid });
      // The write was attempted, and refused.
      expect(store.failNextCommit).toBe(false);
    } finally {
      store.failNextCommit = false;
    }
    expect(r.status, JSON.stringify(r.body)).toBe(500);
    expect(as.kernel.allMissions().length).toBe(missions);
    expect(acceptanceOf(signed.entry.assertion)).toBeUndefined();
    const childId = expectChild(await createChild(parent, [signed.entry], { crid }));
    expect(as.kernel.allMissions().length).toBe(missions + 1);
    expect(acceptanceOf(signed.entry.assertion)?.submissionRef).toBe(creationAcceptanceRef("child-creation", CLIENT, crid));
    expect(as.kernel.get(childId)).toBeDefined();
  });

  it("expansion: another evidence entry failing releases the reservation, so the same assertion is accepted next", async () => {
    const predecessor = await issueMission();
    const signed = await mint();
    expectEvidenceRefusal(await expand(predecessor, [signed.entry, { type: REFUSING_TYPE, assertion: "x" }]), "never verifies");
    expectPending(await expand(predecessor, [signed.entry]));
  });

  it("expansion: a refusal after verification (nothing to expand) releases the reservation, so the same assertion is accepted next", async () => {
    const predecessor = await issueMission();
    const signed = await mint();
    const before = verifications();
    const refused = await expand(predecessor, [signed.entry], { actions: READ });
    expect(refused.status, JSON.stringify(refused.body)).toBe(400);
    expect(refused.body.mission_denial_reason).toBe("nothing_to_expand");
    expect(verifications()).toBe(before + 1);
    expect(acceptanceOf(signed.entry.assertion)).toBeUndefined();
    expectPending(await expand(predecessor, [signed.entry]));
  });

  it("expansion: a failed write opening the deferral releases the reservation, so the same assertion is accepted on the retry", async () => {
    const predecessor = await issueMission();
    const signed = await mint();
    const crid = crypto.randomUUID();
    const open = vi.spyOn(as.expansionDeferrals, "open").mockImplementationOnce(() => {
      throw new Error("the kernel database refused the write");
    });
    try {
      const r = await expand(predecessor, [signed.entry], { crid });
      expect(r.status, JSON.stringify(r.body)).toBe(500);
    } finally {
      open.mockRestore();
    }
    expect(acceptanceOf(signed.entry.assertion)).toBeUndefined();
    expectPending(await expand(predecessor, [signed.entry], { crid }));
  });
});

describe("concurrent exchanges (@spec request-provenance#replay, #939 slice 3a)", () => {
  it("of two concurrent child creations presenting one assertion, exactly one is accepted and the other is refused as replay", async () => {
    const parent = await issueMission();
    const signed = await mint();
    const missions = as.kernel.allMissions().length;
    store.gather(2);
    const results = await Promise.all([createChild(parent, [signed.entry]), createChild(parent, [signed.entry])]);
    expect(results.map((r) => r.status).sort()).toEqual([200, 400]);
    expectEvidenceRefusal(results.find((r) => r.status === 400) as Reply, "replay");
    expect(as.kernel.allMissions().length).toBe(missions + 1);
  });

  it("of two concurrent expansions presenting one assertion, exactly one returns the pending continuation and the other is refused as replay", async () => {
    const predecessor = await issueMission();
    const signed = await mint();
    store.gather(2);
    const results = await Promise.all([expand(predecessor, [signed.entry]), expand(predecessor, [signed.entry])]);
    expect(results.map((r) => r.body.error).sort()).toEqual(["authorization_pending", "invalid_mission_intent_evidence"]);
    expectEvidenceRefusal(results.find((r) => r.body.error !== "authorization_pending") as Reply, "replay");
  });
});

describe("a ceiling drawdown accepts the type (@spec request-provenance#replay, progressive#in-ceiling-expansion, #939 slice 3a)", () => {
  /** Read actions under the vendor constraint, as the ceiling's read entry states them. */
  const reads = (actions: string[]) => [{ type: "mission_resource_access", resource: RESOURCE, actions, constraints: { vendors: ["acme"] } }];

  it("commits the pair inside the successor's creation under the operation's reference, on the default store, and records the facts on the successor; an exact retry after exp recovers that successor without verifying again", async () => {
    const decided = assembledCeilingOffer(CEILING_OFFER as never, drawdownAs.kernel.resourceContracts()) as unknown as Record<string, unknown>;
    const predecessor = await issueMission(drawdownTarget, { proposal: reads(READ), decided });
    const signed = await mint({ audience: DRAWDOWN_ISSUER });
    const crid = crypto.randomUUID();
    const widened = reads([...READ, "payments:invoice.list"]);
    const before = verifications();
    const completed = await expand(predecessor, [signed.entry], { crid, proposal: widened, target: drawdownTarget });
    expect(completed.status, JSON.stringify(completed.body)).toBe(200);
    expect(verifications()).toBe(before + 1);
    const successor = drawdownAs.kernel.get(completed.body.mission_id as string) as MissionRecord;
    expect(successor.approval_basis.type).toBe("ceiling_drawdown");
    const accepted = drawdownAs.requestProvenanceStore?.accepted(INTAKE, signed.jti, Date.now());
    expect(accepted?.submissionRef).toBe(creationAcceptanceRef("expansion", CLIENT, crid));
    expect(accepted?.presenter).toEqual({ clientId: CLIENT, cnf: { jkt: dpopJkt } });
    expect(successor.submission_evidence).toEqual([
      { type: TYPE, artifact_hash: accepted?.artifactHash, verified_at: accepted?.verifiedAt, facts: accepted?.facts },
    ]);
    // The response is lost; the client retries once the assertion has expired.
    controlledClock.advance((signed.exp + 5 + 1) * 1000 - Date.now());
    const retried = await expand(predecessor, [signed.entry], { crid, proposal: widened, target: drawdownTarget });
    expect(retried.status, JSON.stringify(retried.body)).toBe(200);
    expect(retried.body.mission_id).toBe(successor.id);
    expect(verifications()).toBe(before + 1);
  });
});
