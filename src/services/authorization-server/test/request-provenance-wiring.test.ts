/**
 * @spec request-provenance#verification, request-provenance#trust-configuration,
 * request-provenance#replay, request-provenance#recorded-facts,
 * submission-evidence#intent-binding, submission-evidence#verification-bounds
 * (#939 slice 2a-2, D1119, D1151)
 *
 * The `mission-request-provenance` evidence type wired into the authorization
 * server, through its real endpoints, on a controlled clock. Assertions are
 * minted live by `@mission/request-provenance` for the test signer, the
 * submitted Intent and the presenter the push authenticates (no `cnf`); a
 * case the conforming intake cannot produce alters one of them and re-signs
 * it with the same configured key. Covered here:
 *
 *  - PAR: every verification step through the endpoint's
 *    `invalid_mission_intent_evidence` refusal, and the facts the Mission
 *    records;
 *  - replay: reserve, commit on the push's 201, release on every refusal
 *    before acceptance (another entry, the verification-work bound, a failed
 *    save, an exception), nothing released after acceptance, and one winner
 *    of concurrent pushes;
 *  - the accepted submission: the authorization endpoint, the rendering and
 *    the decision rely on the acceptance record after `exp` and the capture
 *    age pass, and refuse without a matching one;
 *  - the carriers that do not admit the type, and enabling it: a supplied
 *    replay store beside a file-backed kernel store refuses construction,
 *    and the default store, on the kernel's database, starts there.
 *
 * Deferred activation, a later step on another assembly, is in
 * request-provenance-deferred.test.ts, and the store across a restart of a
 * file-backed kernel in request-provenance-restart.test.ts.
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
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  DERIVATION_POLICY,
  demoReconciliationTemplate,
  DEV_SERVICE_TOKEN,
  parseRequestProvenanceConfig,
  REQUEST_PROVENANCE_CONFIG,
  type RequestProvenanceConfig,
} from "@mission/demo-data";
import { type Channel, createRequestIntake, type JsonObject, type Presenter } from "@mission/request-provenance";
import { openStore } from "@mission/store";
import { CompactSign, calculateJwkThumbprint, decodeJwt, exportJWK, generateKeyPair, importJWK, type JWK, SignJWT } from "jose";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { RENDER_REVISION_HEADER } from "../src/adapters/approval-render-revision.js";
import { ACCESS_TOKEN_TOKEN_TYPE, JWT_TOKEN_TYPE, TOKEN_EXCHANGE_GRANT_TYPE } from "../src/adapters/continuation-grant.js";
import { MISSION_DISPATCH_GRANT_TYPE } from "../src/adapters/provider.js";
import {
  ALL_PROVIDER_CAPABILITIES,
  ApprovalSessionStore,
  buildAuthorizationServer,
  type BuiltAs,
  createRequestProvenanceEvidenceType,
  InMemoryRequestProvenanceStore,
  IntentError,
  type IntentSubmissionEvidenceTypes,
  type ProviderCapability,
  provisionalIntentHash,
  registerIntentSubmissionEvidenceType,
  type RequestProvenanceAcceptance,
  type RequestProvenanceRecord,
  type RequestProvenanceStore,
  SqliteRequestProvenanceStore,
  SubmissionAdmission,
  unregisterIntentSubmissionEvidenceType,
  verifyIntentSubmissionEvidence,
} from "../src/index.js";
import { verifyRequestProvenance } from "../src/kernel/request-provenance.js";
import { aiAgents } from "./actor-profiles.helper.js";
import { browserApprovalHeaders, TEST_APPROVAL_PRINCIPALS } from "./approval-fixture.js";
import { FIXTURE_EXPIRES_AT } from "./relative-expiry.helper.js";

type Json = null | boolean | number | string | Json[] | { [key: string]: Json };
type JsonRecord = { [key: string]: Json };

const TYPE = "mission-request-provenance";
const PORT = 14907;
const ISSUER = `http://localhost:${PORT}`;
const STRICT_PORT = 14908;
const STRICT_ISSUER = `http://localhost:${STRICT_PORT}`;
const UNMETERED_PORT = 14909;
const UNMETERED_ISSUER = `http://localhost:${UNMETERED_PORT}`;
const REDIRECT_URI = "http://localhost:9999/cb";
const RESOURCE = DERIVATION_POLICY.ceiling[0].resource as string;
const DEVICE_CLIENT = "agent-A1";
const DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code";
const PUSHED_REQUEST_URN = "urn:ietf:params:oauth:request_uri:";

const INTAKE = "https://intake.example.org";
const INTAKE_KID = "intake-1";
const OPS_KID = "intake-ops-1";
const DEVICE_SIGNER = "https://device-signer.example.org";
const DEVICE_KID = "device-1";
const IDP = "https://idp.example.org";
const CHANNEL = "https://intake.example.org/ch/app";
const INSTRUCTION = "Reconcile the Q3 invoices against the ledger, nothing else.";

const INTENT = { goal: "Reconcile Q3 invoices", target_resources: [RESOURCE], expires_at: FIXTURE_EXPIRES_AT };
const OTHER_INTENT = { ...INTENT, goal: "Reconcile Q4 invoices" };

const intakeKeys = await generateKeyPair("ES256", { extractable: true });
const opsKeys = await generateKeyPair("ES256", { extractable: true });
const deviceKeys = await generateKeyPair("ES256", { extractable: true });
const intakePublicJwk = await exportJWK(intakeKeys.publicKey);

/**
 * This AS's trust configuration, through the loader the shipped file takes:
 * the intake signer with a key mapped to this type and one mapped to another
 * (whose JWK says `use` sig and `key_ops` verify), and a user-device signer
 * bound to alice. Skew 5 s; lifetime and capture age at most 30 s.
 */
const TRUST: RequestProvenanceConfig = parseRequestProvenanceConfig({
  enabled: true,
  clock_skew_seconds: 5,
  max_assertion_lifetime_seconds: 30,
  max_capture_age_seconds: 30,
  signers: [
    {
      iss: INTAKE,
      keys: [
        { kid: INTAKE_KID, public_jwk: intakePublicJwk as unknown as Json, evidence_types: [TYPE], algs: ["ES256"] },
        {
          kid: OPS_KID,
          public_jwk: { ...(await exportJWK(opsKeys.publicKey)), use: "sig", key_ops: ["verify"] } as unknown as Json,
          evidence_types: ["urn:example:evidence:ops-attestation"],
          algs: ["ES256"],
        },
      ],
      originators: [{ iss: IDP }],
      channel_types: [CHANNEL],
    },
    {
      iss: DEVICE_SIGNER,
      keys: [{ kid: DEVICE_KID, public_jwk: (await exportJWK(deviceKeys.publicKey)) as unknown as Json, evidence_types: [TYPE], algs: ["ES256"] }],
      originators: [{ iss: IDP, sub: "alice" }],
      channel_types: [CHANNEL],
    },
  ],
});

const SIGNERS = {
  intake: { iss: INTAKE, kid: INTAKE_KID, key: intakeKeys.privateKey },
  ops: { iss: INTAKE, kid: OPS_KID, key: opsKeys.privateKey },
  device: { iss: DEVICE_SIGNER, kid: DEVICE_KID, key: deviceKeys.privateKey },
};

interface MintOptions {
  presenter?: Presenter;
  intent?: JsonObject;
  audience?: string;
  originator?: { iss: string; sub: string };
  channel?: Channel;
  /** `exp` minus `iat`. Default 20 s. */
  lifetimeS?: number;
  /** `iat` minus `captured_at`. Default 5 s. */
  captureAgeS?: number;
  /** `iat` relative to the controlled now. Default 0. */
  iatOffsetS?: number;
  signer?: keyof typeof SIGNERS;
  emitCaptureId?: boolean;
}

/** Capture and sign through the intake library on the controlled clock, keeping the capture secret it drew. */
async function mint(o: MintOptions = {}) {
  const signer = SIGNERS[o.signer ?? "intake"];
  const draws: Buffer[] = [];
  let offsetMs = ((o.iatOffsetS ?? 0) - (o.captureAgeS ?? 5)) * 1000;
  const intake = createRequestIntake({
    issuer: signer.iss,
    kid: signer.kid,
    signingKey: signer.key,
    assertionLifetimeSeconds: o.lifetimeS ?? 20,
    maxCaptureAgeSeconds: 3600,
    ...(o.emitCaptureId !== undefined ? { emitCaptureId: o.emitCaptureId } : {}),
    now: () => Date.now() + offsetMs,
    randomBytes: (size) => {
      const b = randomBytes(size);
      draws.push(Buffer.from(b));
      return b;
    },
  });
  const receipt = intake.capture({
    workflow: "wf-1",
    instruction: Buffer.from(INSTRUCTION, "utf8"),
    mediaType: "text/plain;charset=utf-8",
    originator: o.originator ?? { iss: IDP, sub: "alice" },
    channel: o.channel ?? { type: CHANNEL, amr: ["pwd", "otp"], auth_time: Math.floor(Date.now() / 1000) - 60 },
    presenter: o.presenter ?? { client_id: "ap-agent" },
  });
  offsetMs = (o.iatOffsetS ?? 0) * 1000;
  const signed = await intake.sign({
    captureId: receipt.captureId,
    workflow: "wf-1",
    audience: o.audience ?? ISSUER,
    intent: (o.intent ?? INTENT) as JsonObject,
  });
  return { ...signed, secret: draws[0] as Buffer, receipt };
}

const b64 = (value: unknown): string => Buffer.from(JSON.stringify(value)).toString("base64url");
const decodePart = (part: string): JsonRecord => JSON.parse(Buffer.from(part, "base64url").toString("utf8")) as JsonRecord;
const headerOf = (assertion: string): JsonRecord => decodePart(assertion.split(".")[0] as string);
const claimsOf = (assertion: string): JsonRecord => decodePart(assertion.split(".")[1] as string);

/** Re-sign a minted assertion with its header or claims changed, under a configured key (default the intake's). */
async function resign(
  assertion: string,
  edit: { header?: (h: JsonRecord) => JsonRecord; claims?: (c: JsonRecord) => JsonRecord; signer?: keyof typeof SIGNERS },
): Promise<string> {
  const header = (edit.header ?? ((h) => h))(headerOf(assertion));
  const claims = (edit.claims ?? ((c) => c))(claimsOf(assertion));
  return new CompactSign(new TextEncoder().encode(JSON.stringify(claims)))
    .setProtectedHeader(header as never)
    .sign(SIGNERS[edit.signer ?? "intake"].key);
}

const entry = (assertion: unknown): Record<string, unknown> => ({ type: TYPE, assertion });
const envelope = (evidence: unknown[], intent: unknown = INTENT) => ({ intent, evidence });

/**
 * The replay store the main assembly uses: the AS's store class, on a
 * database of its own, observed. A test can make every acceptance record
 * read as missing, or gather concurrent reservations so they reach the
 * store in one turn. The other assemblies keep the default, on their
 * kernel's database.
 */
class ObservedStore implements RequestProvenanceStore {
  readonly inner = new SqliteRequestProvenanceStore(openStore(""));
  lost = false;
  #gathering: { size: number; waiting: Array<() => void> } | undefined;

  /** Hold reservations until `size` submissions reached step 10, then let them reserve in one turn. */
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
    return this.inner.commit(token, ref, nowMs, retainUntilMs);
  }

  release(token: string): void {
    this.inner.release(token);
  }

  accepted(iss: string, jti: string, nowMs: number): RequestProvenanceAcceptance | undefined {
    return this.lost ? undefined : this.inner.accepted(iss, jti, nowMs);
  }
}

interface Instance {
  as: BuiltAs;
  issuer: string;
  server: Server;
  agentKey: CryptoKey;
}

const SESSIONS = new ApprovalSessionStore();
const mainStore = new ObservedStore();
let main: Instance;
let strict: Instance;
let unmetered: Instance;
let dpopKeys: { privateKey: CryptoKey; publicKey: CryptoKey };
let dpopJkt: string;

/** Test evidence types beside the provenance type: one whose verification always fails, one that verifies. */
const REFUSING_TYPE = "urn:test:intent-evidence:refuses";
const PASSING_TYPE = "urn:test:intent-evidence:passes";
const closedEntry = (e: Record<string, unknown>) => {
  if (typeof e.assertion !== "string" || Object.keys(e).some((k) => k !== "type" && k !== "assertion")) {
    throw new IntentError("invalid_mission_intent_evidence", "test type: {type, assertion} only");
  }
};
registerIntentSubmissionEvidenceType(REFUSING_TYPE, {
  validate: closedEntry,
  async verify() {
    throw new Error("test type: this artifact never verifies");
  },
});
registerIntentSubmissionEvidenceType(PASSING_TYPE, {
  validate: closedEntry,
  async verify() {
    return { admitted: true };
  },
});

const verifications = () => vi.mocked(verifyRequestProvenance).mock.calls.length;

async function instance(port: number, issuer: string, extra: Parameters<typeof buildAuthorizationServer>[0] | Record<string, unknown> = {}): Promise<Instance> {
  const as = await buildAuthorizationServer({
    issuer,
    allowHeadlessAdjudication: true,
    serviceTokenPrincipals: TEST_APPROVAL_PRINCIPALS,
    approvalSessions: SESSIONS,
    ...(extra as object),
  } as Parameters<typeof buildAuthorizationServer>[0]);
  const server = as.provider.listen(port);
  const agentKey = (await importJWK(as.agentClientJwk as never, "ES256")) as CryptoKey;
  return { as, issuer, server, agentKey };
}

beforeAll(async () => {
  dpopKeys = await generateKeyPair("ES256", { extractable: true });
  dpopJkt = await calculateJwkThumbprint(await exportJWK(dpopKeys.publicKey));
  main = await instance(PORT, ISSUER, {
    capabilities: new Set<ProviderCapability>([...ALL_PROVIDER_CAPABILITIES, "device-authorization"]),
    actorProfiles: aiAgents("subagent-extractor"),
    testClients: [
      {
        client_id: DEVICE_CLIENT,
        grant_types: [DEVICE_GRANT, "refresh_token"],
        response_types: [],
        redirect_uris: [],
        authorization_details_types: ["mission_resource_access"],
        token_endpoint_auth_method: "none",
      },
    ],
    requestProvenance: { config: TRUST, store: mainStore },
  });
  // One unit of verification work per submission, and the type required.
  strict = await instance(STRICT_PORT, STRICT_ISSUER, {
    submissionEvidenceVerificationWork: 1,
    requiredIntentEvidenceTypes: [TYPE],
    requestProvenance: { config: TRUST },
  });
  unmetered = await instance(UNMETERED_PORT, UNMETERED_ISSUER, {
    submissionEvidenceVerificationWork: 0,
    requestProvenance: { config: TRUST },
  });
});

afterAll(() => {
  main?.server.close();
  strict?.server.close();
  unmetered?.server.close();
  unregisterIntentSubmissionEvidenceType(REFUSING_TYPE);
  unregisterIntentSubmissionEvidenceType(PASSING_TYPE);
  controlledClock.restore();
});

const PKCE_VERIFIER = "request-provenance-wiring-verifier-0123456789-0123456789";
const pkceChallenge = async () =>
  Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(PKCE_VERIFIER))).toString("base64url");

async function clientAssertion(inst: Instance): Promise<string> {
  return new SignJWT({})
    .setProtectedHeader({ alg: "ES256", kid: "ap-agent-auth" })
    .setIssuer("ap-agent")
    .setSubject("ap-agent")
    .setAudience(inst.issuer)
    .setIssuedAt()
    .setExpirationTime("2m")
    .setJti(crypto.randomUUID())
    .sign(inst.agentKey);
}

/** A pushed authorization request as ap-agent, its value of mission_intent the given envelope. */
async function push(
  inst: Instance,
  submission: unknown,
  headers: Record<string, string> = {},
): Promise<{ status: number; body: Record<string, unknown> }> {
  const res = await fetch(`${inst.issuer}/request`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", ...headers },
    body: new URLSearchParams({
      client_id: "ap-agent",
      response_type: "code",
      redirect_uri: REDIRECT_URI,
      resource: RESOURCE,
      code_challenge: await pkceChallenge(),
      code_challenge_method: "S256",
      login_hint: "alice",
      mission_intent: JSON.stringify(submission),
      client_assertion: await clientAssertion(inst),
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    }).toString(),
  });
  const text = await res.text();
  let body: Record<string, unknown>;
  try {
    body = JSON.parse(text) as Record<string, unknown>;
  } catch {
    body = { text };
  }
  return { status: res.status, body };
}

/** The push was refused for its evidence. */
function expectEvidenceRefusal(r: { status: number; body: Record<string, unknown> }, reason?: string): void {
  expect(r.status, JSON.stringify(r.body)).toBe(400);
  expect(r.body.error).toBe("invalid_mission_intent_evidence");
  if (reason !== undefined) expect(String(r.body.error_description)).toContain(reason);
}

function expectAccepted(r: { status: number; body: Record<string, unknown> }): string {
  expect(r.status, JSON.stringify(r.body)).toBe(201);
  const uri = r.body.request_uri as string;
  expect(uri.startsWith(PUSHED_REQUEST_URN)).toBe(true);
  return uri;
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

/** The authorization request redeeming a request_uri: the interaction it opened, or the refusal. */
async function authorize(inst: Instance, requestUri: string) {
  const jar: Jar = new Map();
  const res = await fetch(`${inst.issuer}/auth?${new URLSearchParams({ client_id: "ap-agent", request_uri: requestUri })}`, {
    redirect: "manual",
  });
  keep(jar, res);
  const location = res.headers.get("location") ?? "";
  const uid = location.includes("/interaction/") ? (location.split("/interaction/")[1] as string) : undefined;
  const error = location.startsWith(REDIRECT_URI) ? new URL(location).searchParams.get("error") : null;
  return { status: res.status, location, uid, jar, error, text: uid || error ? "" : await res.text() };
}

/** Bob's approval session for alice's request on interaction `uid`, authenticated now. */
const approverHeaders = (uid: string, jar: Jar): Record<string, string> =>
  browserApprovalHeaders(SESSIONS, uid, { sub: "bob", acr: "mfa", auth_time: Math.floor(Date.now() / 1000), subject: "alice" }, cookieOf(jar));

async function render(inst: Instance, uid: string, headers: Record<string, string>) {
  const res = await fetch(`${inst.issuer}/interaction/${uid}`, { headers });
  const text = await res.text();
  return { status: res.status, text, revision: res.headers.get(RENDER_REVISION_HEADER) };
}

/** The decision, and the resume that commits it: the redirect it ends at. */
async function decide(inst: Instance, uid: string, jar: Jar, headers: Record<string, string>, body: Record<string, unknown>) {
  let res = await fetch(`${inst.issuer}/interaction/${uid}/decide`, {
    method: "POST",
    redirect: "manual",
    headers: { ...headers, "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const status = res.status;
  const text = status === 303 ? "" : await res.text();
  keep(jar, res);
  let location = res.headers.get("location") ?? "";
  while (location.startsWith(inst.issuer)) {
    res = await fetch(location, { redirect: "manual", headers: { cookie: cookieOf(jar) } });
    keep(jar, res);
    location = res.headers.get("location") ?? "";
  }
  return { status, text, location };
}

/** Rewrite the stored interaction, as a later step would find it. */
async function tamper(inst: Instance, uid: string, change: (i: { params: Record<string, unknown>; parJti?: string }) => void): Promise<void> {
  const interaction = await inst.as.provider.Interaction.find(uid);
  if (!interaction) throw new Error(`no interaction ${uid}`);
  change(interaction as unknown as { params: Record<string, unknown>; parJti?: string });
  await interaction.save(Math.max(1, (interaction.exp ?? 0) - Math.floor(Date.now() / 1000)));
}

/** Push, open the interaction and approve: the Mission the approval created. */
async function approveThrough(inst: Instance, submission: unknown) {
  const par = await push(inst, submission);
  const requestUri = expectAccepted(par);
  const auth = await authorize(inst, requestUri);
  expect(auth.uid, auth.location || auth.text).toBeTruthy();
  const uid = auth.uid as string;
  const headers = approverHeaders(uid, auth.jar);
  const page = await render(inst, uid, headers);
  expect(page.status, page.text.slice(0, 300)).toBe(200);
  const decided = await decide(inst, uid, auth.jar, headers, { decision: "approve", render_revision: page.revision });
  expect(decided.status, decided.text).toBe(303);
  expect(new URL(decided.location).searchParams.get("code"), decided.location).toBeTruthy();
  const record = inst.as.kernel.findByApprovalEvent(`apev_${uid}`);
  expect(record).toBeDefined();
  return { record: record as NonNullable<typeof record>, uid, requestUri, page };
}

/** The pair's acceptance record in the main store. */
const acceptanceOf = (assertion: string) => {
  const c = claimsOf(assertion);
  return mainStore.inner.accepted(String(c.iss), String(c.jti), Date.now());
};

/** A NumericDate as the RFC 3339 timestamp the facts record. */
const rfc3339 = (s: number) => `${new Date(s * 1000).toISOString().slice(0, 19)}Z`;

describe("mission-request-provenance at PAR (@spec request-provenance#verification, request-provenance#replay, #939 slice 2a-2)", () => {
  it("accepts an assertion minted by @mission/request-provenance for the submitted Intent and the authenticated client, with no cnf, and commits its (iss, jti) to the push", async () => {
    const signed = await mint();
    const before = verifications();
    const uri = expectAccepted(await push(main, envelope([signed.entry])));
    expect(verifications()).toBe(before + 1);
    const accepted = acceptanceOf(signed.entry.assertion);
    expect(accepted?.submissionRef).toBe(`par:${uri.slice(PUSHED_REQUEST_URN.length)}`);
    expect(accepted?.assertion).toBe(signed.entry.assertion);
    expect(accepted?.presenter).toEqual({ clientId: "ap-agent" });
    expect(accepted?.intentHash).toBe(provisionalIntentHash(ISSUER, INTENT as never));
  });
});

describe("the evidence entry at PAR (@spec request-provenance#entry, request-provenance#verification, #939 slice 2a-2)", () => {
  it("refuses invalid_mission_intent_evidence an entry carrying a member beside type and assertion", async () => {
    const signed = await mint();
    expectEvidenceRefusal(await push(main, envelope([{ ...signed.entry, capture_id: "c-1" }])), "step 1");
  });

  it("refuses invalid_mission_intent_evidence an entry whose assertion is not a string", async () => {
    expectEvidenceRefusal(await push(main, envelope([entry(42)])), "step 1");
    expectEvidenceRefusal(await push(main, envelope([entry({ jws: "a.b.c" })])), "step 1");
  });
});

describe("the protected header at PAR (@spec request-provenance#verification, #939 slice 2a-2)", () => {
  it("refuses invalid_mission_intent_evidence a protected typ other than exactly mission-request-provenance+jwt", async () => {
    const signed = await mint();
    for (const typ of ["JWT", "Mission-Request-Provenance+JWT"]) {
      const token = await resign(signed.entry.assertion, { header: (h) => ({ ...h, typ }) });
      expectEvidenceRefusal(await push(main, envelope([entry(token)])), "step 2");
    }
  });

  it("refuses invalid_mission_intent_evidence alg none", async () => {
    const signed = await mint();
    const [, payload] = signed.entry.assertion.split(".");
    const token = `${b64({ ...headerOf(signed.entry.assertion), alg: "none" })}.${payload}.`;
    expectEvidenceRefusal(await push(main, envelope([entry(token)])), "alg is none");
  });

  it("refuses invalid_mission_intent_evidence a protected header without kid", async () => {
    const signed = await mint();
    const token = await resign(signed.entry.assertion, {
      header: ({ kid: _kid, ...h }) => h,
    });
    expectEvidenceRefusal(await push(main, envelope([entry(token)])), "carries no kid");
  });
});

describe("no key from the assertion at PAR (@spec request-provenance#trust-configuration, #939 slice 2a-2)", () => {
  // A key server that would answer any jku or x5u: it must never be asked.
  let keyServer: Server;
  let keyServerUrl: string;
  let fetched = 0;
  beforeAll(async () => {
    keyServer = createServer((_req, res) => {
      fetched += 1;
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ keys: [{ ...intakePublicJwk, kid: INTAKE_KID }] }));
    });
    await new Promise<void>((done) => keyServer.listen(0, done));
    keyServerUrl = `http://localhost:${(keyServer.address() as AddressInfo).port}`;
  });
  afterAll(() => keyServer?.close());

  it("refuses invalid_mission_intent_evidence an assertion whose header carries jku, and fetches nothing from it", async () => {
    const signed = await mint();
    const token = await resign(signed.entry.assertion, { header: (h) => ({ ...h, jku: `${keyServerUrl}/jwks` }) });
    fetched = 0;
    expectEvidenceRefusal(await push(main, envelope([entry(token)])), "carries jku");
    expect(fetched).toBe(0);
  });

  it("refuses invalid_mission_intent_evidence an assertion whose header carries x5u, and fetches nothing from it", async () => {
    const signed = await mint();
    const token = await resign(signed.entry.assertion, { header: (h) => ({ ...h, x5u: `${keyServerUrl}/cert.pem` }) });
    fetched = 0;
    expectEvidenceRefusal(await push(main, envelope([entry(token)])), "carries x5u");
    expect(fetched).toBe(0);
  });

  it("refuses invalid_mission_intent_evidence an assertion whose header carries jwk, even the configured key under a signature that verifies", async () => {
    const signed = await mint();
    const token = await resign(signed.entry.assertion, { header: (h) => ({ ...h, jwk: intakePublicJwk as unknown as Json }) });
    expectEvidenceRefusal(await push(main, envelope([entry(token)])), "carries jwk");
  });

  it("refuses invalid_mission_intent_evidence an assertion whose header carries x5c", async () => {
    const signed = await mint();
    const token = await resign(signed.entry.assertion, {
      header: (h) => ({ ...h, x5c: [randomBytes(64).toString("base64")] }),
    });
    expectEvidenceRefusal(await push(main, envelope([entry(token)])), "carries x5c");
  });
});

describe("the key's purpose comes from configuration at PAR (@spec request-provenance#trust-configuration, #939 slice 2a-2)", () => {
  it("refuses invalid_mission_intent_evidence an assertion verified under a configured key the configuration maps to another evidence type, though its JWK carries use sig and key_ops verify", async () => {
    const signed = await mint({ signer: "ops" });
    expectEvidenceRefusal(await push(main, envelope([signed.entry])), `does not map this key to ${TYPE}`);
  });
});

describe("the signer, its key and the signature at PAR (@spec request-provenance#verification, #939 slice 2a-2)", () => {
  it("refuses invalid_mission_intent_evidence an assertion from a signer the configuration does not authorize", async () => {
    const signed = await mint();
    const token = await resign(signed.entry.assertion, { claims: (c) => ({ ...c, iss: "https://rogue-intake.example.org" }) });
    expectEvidenceRefusal(await push(main, envelope([entry(token)])), "authorizes no signer");
  });

  it("refuses invalid_mission_intent_evidence a kid the configuration does not map to the signer", async () => {
    const signed = await mint();
    const token = await resign(signed.entry.assertion, { header: (h) => ({ ...h, kid: DEVICE_KID }) });
    expectEvidenceRefusal(await push(main, envelope([entry(token)])), "maps no key with this kid");
  });

  it("refuses invalid_mission_intent_evidence an alg the key does not permit", async () => {
    const signed = await mint();
    const [, payload] = signed.entry.assertion.split(".");
    const token = await new CompactSign(Buffer.from(payload as string, "base64url"))
      .setProtectedHeader({ ...(headerOf(signed.entry.assertion) as object), alg: "HS256" } as never)
      .sign(new TextEncoder().encode(JSON.stringify(intakePublicJwk)));
    expectEvidenceRefusal(await push(main, envelope([entry(token)])), "alg HS256 is not permitted");
  });

  it("refuses invalid_mission_intent_evidence an assertion whose signature does not verify", async () => {
    const signed = await mint();
    const [header, , signature] = signed.entry.assertion.split(".");
    const altered = { ...claimsOf(signed.entry.assertion), request_digest: `hmac-sha-256:${randomBytes(32).toString("base64url")}` };
    expectEvidenceRefusal(await push(main, envelope([entry(`${header}.${b64(altered)}.${signature}`)])), "signature does not verify");
  });
});

/** The claims step 5 requires beside iss (whose absence finds no signer at step 3). */
const REQUIRED_CLAIMS = [
  "aud",
  "iat",
  "exp",
  "jti",
  "intent_hash",
  "presenter",
  "originator",
  "channel",
  "captured_at",
  "request_digest",
];

describe("required claims and the audience at PAR (@spec request-provenance#assertion, request-provenance#verification, #939 slice 2a-2)", () => {
  it("refuses invalid_mission_intent_evidence an assertion missing any required claim", async () => {
    const signed = await mint();
    for (const claim of REQUIRED_CLAIMS) {
      const token = await resign(signed.entry.assertion, {
        claims: (c) => {
          const { [claim]: _dropped, ...rest } = c;
          return rest;
        },
      });
      expectEvidenceRefusal(await push(main, envelope([entry(token)])), "step 5");
    }
  });

  it("refuses invalid_mission_intent_evidence a required claim of the wrong type", async () => {
    const signed = await mint();
    for (const set of [{ iat: String(claimsOf(signed.entry.assertion).iat) }, { originator: "alice" }, { captured_at: "yesterday" }]) {
      const token = await resign(signed.entry.assertion, { claims: (c) => ({ ...c, ...set }) });
      expectEvidenceRefusal(await push(main, envelope([entry(token)])), "step 5");
    }
  });

  it("refuses invalid_mission_intent_evidence an aud that is an array", async () => {
    const signed = await mint();
    const token = await resign(signed.entry.assertion, { claims: (c) => ({ ...c, aud: [ISSUER] }) });
    expectEvidenceRefusal(await push(main, envelope([entry(token)])), "aud is not a string");
  });

  it("refuses invalid_mission_intent_evidence an aud naming another authorization server", async () => {
    const signed = await mint({ audience: STRICT_ISSUER });
    expectEvidenceRefusal(await push(main, envelope([signed.entry])), "aud is not this AS's issuer identifier");
  });
});

describe("the intended authorization server at PAR (@spec submission-evidence#intent-binding, request-provenance#verification, #939 slice 2a-2)", () => {
  // Each refusal comes before any derivation: the kernel derives nothing for a refused push.
  let derive: ReturnType<typeof vi.spyOn>;
  beforeAll(() => {
    derive = vi.spyOn(main.as.kernel, "derive");
  });
  afterAll(() => derive.mockRestore());

  it("refuses invalid_mission_intent_evidence an entry with no intended-AS binding, before derivation", async () => {
    const signed = await mint();
    const token = await resign(signed.entry.assertion, {
      claims: ({ aud: _aud, ...c }) => c,
    });
    derive.mockClear();
    expectEvidenceRefusal(await push(main, envelope([entry(token)])), "aud is not a string");
    expect(derive).not.toHaveBeenCalled();
  });

  it("refuses invalid_mission_intent_evidence an entry whose intended-AS binding is invalid, before derivation", async () => {
    const signed = await mint();
    for (const aud of [42, [ISSUER], { iss: ISSUER }]) {
      const token = await resign(signed.entry.assertion, { claims: (c) => ({ ...c, aud: aud as Json }) });
      derive.mockClear();
      expectEvidenceRefusal(await push(main, envelope([entry(token)])), "aud is not a string");
      expect(derive).not.toHaveBeenCalled();
    }
  });

  it("refuses invalid_mission_intent_evidence an entry bound to another authorization server, before derivation, and accepts the same capture bound to this one", async () => {
    const other = await mint({ audience: STRICT_ISSUER });
    derive.mockClear();
    expectEvidenceRefusal(await push(main, envelope([other.entry])), "aud is not this AS's issuer identifier");
    expect(derive).not.toHaveBeenCalled();
    expectAccepted(await push(main, envelope([(await mint({ audience: ISSUER })).entry])));
  });
});

describe("the time window at PAR (@spec request-provenance#verification, #939 slice 2a-2)", () => {
  it("refuses invalid_mission_intent_evidence an iat in the future beyond the clock-skew allowance", async () => {
    const signed = await mint({ iatOffsetS: 7 });
    expectEvidenceRefusal(await push(main, envelope([signed.entry])), "iat is in the future");
  });

  it("refuses invalid_mission_intent_evidence an assertion whose exp passed beyond the clock-skew allowance", async () => {
    const signed = await mint({ lifetimeS: 20, iatOffsetS: -26 });
    expectEvidenceRefusal(await push(main, envelope([signed.entry])), "exp has passed");
  });

  it("refuses invalid_mission_intent_evidence exp minus iat above the maximum assertion lifetime", async () => {
    const signed = await mint({ lifetimeS: 31 });
    expectEvidenceRefusal(await push(main, envelope([signed.entry])), "maximum assertion lifetime");
  });

  it("refuses invalid_mission_intent_evidence a captured_at later than iat", async () => {
    const signed = await mint();
    const token = await resign(signed.entry.assertion, {
      claims: (c) => ({ ...c, captured_at: (c.iat as number) + 1 }),
    });
    expectEvidenceRefusal(await push(main, envelope([entry(token)])), "captured_at is later than iat");
  });

  it("refuses invalid_mission_intent_evidence iat minus captured_at above the maximum capture age", async () => {
    const signed = await mint({ captureAgeS: 31 });
    expectEvidenceRefusal(await push(main, envelope([signed.entry])), "maximum capture age");
  });
});

describe("the signer's scope at PAR (@spec request-provenance#verification, request-provenance#trust-configuration, #939 slice 2a-2)", () => {
  it("refuses invalid_mission_intent_evidence an originator outside the signer's configured scope", async () => {
    const signed = await mint({ originator: { iss: "https://other-idp.example.org", sub: "alice" } });
    expectEvidenceRefusal(await push(main, envelope([signed.entry])), "not authorized for this originator");
  });

  it("refuses invalid_mission_intent_evidence a channel type outside the signer's configured scope", async () => {
    const signed = await mint({ channel: { type: "https://intake.example.org/ch/email" } });
    expectEvidenceRefusal(await push(main, envelope([signed.entry])), "not authorized for this channel type");
  });

  it("refuses invalid_mission_intent_evidence a user-device signer's assertion for an originator the AS did not bind its key to, and accepts the bound one", async () => {
    const other = await mint({ signer: "device", originator: { iss: IDP, sub: "mallory" } });
    expectEvidenceRefusal(await push(main, envelope([other.entry])), "not authorized for this originator");
    expectAccepted(await push(main, envelope([(await mint({ signer: "device", originator: { iss: IDP, sub: "alice" } })).entry])));
  });
});

describe("the Intent and the presenter at PAR (@spec request-provenance#verification, submission-evidence#presenter-binding, #939 slice 2a-2)", () => {
  it("refuses invalid_mission_intent_evidence an intent_hash that is not the submitted Intent's", async () => {
    const signed = await mint({ intent: OTHER_INTENT as unknown as JsonObject });
    expectEvidenceRefusal(await push(main, envelope([signed.entry])), "intent_hash is not the submitted Intent's");
  });

  it("refuses invalid_mission_intent_evidence a presenter other than the client the push authenticated", async () => {
    const signed = await mint({ presenter: { client_id: DEVICE_CLIENT } });
    expectEvidenceRefusal(await push(main, envelope([signed.entry])), "presenter.client_id is not the client");
  });

  it("refuses invalid_mission_intent_evidence a presenter carrying cnf, since a push establishes no confirmation key (D1119 Q3)", async () => {
    const signed = await mint({ presenter: { client_id: "ap-agent", cnf: { jkt: dpopJkt } } });
    expectEvidenceRefusal(await push(main, envelope([signed.entry])), "established no confirmation key");
  });
});

describe("verification work at PAR (@spec submission-evidence#verification-bounds, request-provenance#verification, #1962, D1151)", () => {
  it("verifies one entry within a verification-work bound of 1: the unit the dispatch charges before verify covers the type's one signature verification", async () => {
    const before = verifications();
    expectAccepted(await push(strict, envelope([(await mint({ audience: STRICT_ISSUER })).entry])));
    expect(verifications()).toBe(before + 1);
  });

  it("refuses invalid_request at a verification-work bound of 0, and no signature verification runs", async () => {
    const before = verifications();
    const r = await push(unmetered, envelope([(await mint({ audience: UNMETERED_ISSUER })).entry]));
    expect(r.status, JSON.stringify(r.body)).toBe(400);
    expect(r.body.error).toBe("invalid_request");
    expect(String(r.body.error_description)).toContain("verification-work bound (0)");
    expect(verifications()).toBe(before);
  });
});

describe("the recorded facts (@spec request-provenance#recorded-facts, #939 slice 2a-2)", () => {
  it("records on the Mission exactly signer, originator, channel, captured_at as RFC 3339, request_digest, assertion_id and capture_id, and nothing from an undefined claim or member", async () => {
    const signed = await mint();
    const token = await resign(signed.entry.assertion, {
      claims: (c) => ({
        ...c,
        workflow_note: "an undefined claim",
        originator: { ...(c.originator as JsonRecord), email: "alice@example.org" },
        channel: { ...(c.channel as JsonRecord), device: "laptop-17" },
      }),
    });
    const claims = claimsOf(token);
    const { record } = await approveThrough(main, envelope([entry(token)]));
    expect(record.submission_evidence).toHaveLength(1);
    expect(record.submission_evidence?.[0]?.type).toBe(TYPE);
    expect(record.submission_evidence?.[0]?.facts).toEqual({
      signer: { iss: INTAKE, kid: INTAKE_KID },
      originator: { iss: IDP, sub: "alice" },
      channel: { type: CHANNEL, amr: ["pwd", "otp"], auth_time: (claims.channel as JsonRecord).auth_time },
      captured_at: rfc3339(claims.captured_at as number),
      request_digest: claims.request_digest,
      assertion_id: claims.jti,
      capture_id: claims.capture_id,
    });
    expect(record.submission_evidence?.[0]?.facts?.capture_id).toBe(signed.receipt.captureId);
  });

  it("records no capture_id when the assertion carries none", async () => {
    const signed = await mint({ emitCaptureId: false });
    expect(claimsOf(signed.entry.assertion)).not.toHaveProperty("capture_id");
    const { record } = await approveThrough(main, envelope([signed.entry]));
    expect(record.submission_evidence?.[0]?.facts).not.toHaveProperty("capture_id");
    expect(record.submission_evidence?.[0]?.facts?.assertion_id).toBe(signed.jti);
  });

  it("records neither the instruction nor the capture secret, even where an undefined claim carries them", async () => {
    const signed = await mint();
    const secretForms = [signed.secret.toString("hex"), signed.secret.toString("base64url"), signed.secret.toString("base64")];
    const token = await resign(signed.entry.assertion, {
      claims: (c) => ({ ...c, instruction: INSTRUCTION, capture_secret: secretForms[0] as string }),
    });
    const { record } = await approveThrough(main, envelope([entry(token)]));
    const recorded = JSON.stringify(record.submission_evidence);
    expect(recorded).not.toContain(INSTRUCTION);
    for (const form of secretForms) expect(recorded).not.toContain(form);
  });
});

describe("replay at PAR (@spec request-provenance#replay, #939 slice 2a-2)", () => {
  it("of two concurrent pushes presenting one assertion, exactly one is accepted and the other is refused as replay", async () => {
    const signed = await mint();
    mainStore.gather(2);
    const results = await Promise.all([push(main, envelope([signed.entry])), push(main, envelope([signed.entry]))]);
    expect(results.map((r) => r.status).sort()).toEqual([201, 400]);
    const refused = results.find((r) => r.status === 400) as { status: number; body: Record<string, unknown> };
    expectEvidenceRefusal(refused, "replay");
  });

  it("refuses as replay an assertion an accepted push committed, until exp plus the clock-skew allowance", async () => {
    const signed = await mint({ lifetimeS: 20 });
    expectAccepted(await push(main, envelope([signed.entry])));
    expectEvidenceRefusal(await push(main, envelope([signed.entry])), "replay");
    // One second before exp plus the allowance: still within step 7, still replay.
    controlledClock.advance((signed.exp + 5 - 1) * 1000 - Date.now());
    expectEvidenceRefusal(await push(main, envelope([signed.entry])), "replay");
  });

  it("refuses as replay an assertion whose accepted push the Approver then denied", async () => {
    const signed = await mint();
    const auth = await authorize(main, expectAccepted(await push(main, envelope([signed.entry]))));
    const uid = auth.uid as string;
    const headers = approverHeaders(uid, auth.jar);
    expect((await render(main, uid, headers)).status).toBe(200);
    const denied = await decide(main, uid, auth.jar, headers, { decision: "deny" });
    expect(new URL(denied.location).searchParams.get("error"), denied.location).toBe("access_denied");
    expect(main.as.kernel.findByApprovalEvent(`apev_${uid}`)).toBeUndefined();
    expectEvidenceRefusal(await push(main, envelope([signed.entry])), "replay");
  });

  it("releases the reservation when another evidence entry fails, so the same assertion is accepted next", async () => {
    const signed = await mint();
    expectEvidenceRefusal(await push(main, envelope([signed.entry, { type: REFUSING_TYPE, assertion: "x" }])), "never verifies");
    expectAccepted(await push(main, envelope([signed.entry])));
  });

  it("releases the reservation when a later entry passes the verification-work bound, so the same assertion is accepted next", async () => {
    const signed = await mint({ audience: STRICT_ISSUER });
    const r = await push(strict, envelope([signed.entry, { type: PASSING_TYPE, assertion: "x" }]));
    expect(r.status, JSON.stringify(r.body)).toBe(400);
    expect(r.body.error).toBe("invalid_request");
    expectAccepted(await push(strict, envelope([signed.entry])));
  });

  it("releases the reservation when saving the pushed request fails after verification, so the same assertion is accepted next", async () => {
    const signed = await mint();
    const PushedAuthorizationRequest = main.as.provider.PushedAuthorizationRequest as unknown as { prototype: { save: (...a: unknown[]) => Promise<unknown> } };
    const save = vi.spyOn(PushedAuthorizationRequest.prototype, "save").mockRejectedValueOnce(new Error("the adapter is unavailable"));
    try {
      const before = verifications();
      const r = await push(main, envelope([signed.entry]));
      expect(r.status, JSON.stringify(r.body)).toBe(500);
      expect(verifications()).toBe(before + 1);
    } finally {
      save.mockRestore();
    }
    expectAccepted(await push(main, envelope([signed.entry])));
  });

  it("releases the reservation when an exception escapes after the 201 was set, so the same assertion is accepted next", async () => {
    const signed = await mint();
    // Inside the admission wrapper, after the provider answered 201.
    let armed = true;
    main.as.provider.use(async (ctx, next) => {
      await next();
      if (armed && ctx.get("x-test-fail-after-push") === "1" && ctx.status === 201) {
        armed = false;
        throw new Error("a failure after the provider answered");
      }
    });
    const r = await push(main, envelope([signed.entry]), { "x-test-fail-after-push": "1" });
    expect(r.status).toBe(500);
    expect(armed).toBe(false);
    expectAccepted(await push(main, envelope([signed.entry])));
  });

  /** Inside the admission wrapper, after the provider answered 201: the clock passes `ms` before the scope commits. */
  function lapseBeforeAcceptance(header: string, ms: number): { fired: () => boolean } {
    let armed = true;
    main.as.provider.use(async (ctx, next) => {
      await next();
      if (armed && ctx.get(header) === "1" && ctx.status === 201) {
        armed = false;
        controlledClock.advance(ms);
      }
    });
    return { fired: () => !armed };
  }

  it.each([false, true])(
    "commits nothing when one of two reservations lapses before the push is accepted, so the still-valid assertion is accepted next (the short assertion first: %s)",
    async (shortFirst) => {
      const long = await mint({ lifetimeS: 20 });
      const short = await mint({ lifetimeS: 1 });
      const header = `x-test-lapse-${shortFirst ? "short" : "long"}-first`;
      // Past the short assertion's exp plus the 5 s allowance, within the long one's.
      const lapse = lapseBeforeAcceptance(header, 7000);
      const evidence = shortFirst ? [short.entry, long.entry] : [long.entry, short.entry];
      const r = await push(main, envelope(evidence), { [header]: "1" });
      expect(r.status).toBe(500);
      expect(lapse.fired()).toBe(true);
      expect(acceptanceOf(long.entry.assertion)).toBeUndefined();
      expect(acceptanceOf(short.entry.assertion)).toBeUndefined();
      expectAccepted(await push(main, envelope([long.entry])));
    },
  );

  it("commits nothing when the one reservation lapses before the push is accepted", async () => {
    const short = await mint({ lifetimeS: 1 });
    const lapse = lapseBeforeAcceptance("x-test-lapse-single", 7000);
    const r = await push(main, envelope([short.entry]), { "x-test-lapse-single": "1" });
    expect(r.status).toBe(500);
    expect(lapse.fired()).toBe(true);
    expect(acceptanceOf(short.entry.assertion)).toBeUndefined();
  });
});

describe("later steps of an accepted push (@spec request-provenance#replay, #939 slice 2a-2, D1119 Q1 and Q2)", () => {
  it("one accepted push opens two interactions, each relying on the one acceptance record without verifying again, and a new push of the assertion is still replay", async () => {
    const signed = await mint();
    const ref = expectAccepted(await push(main, envelope([signed.entry])));
    const before = verifications();
    const a = await authorize(main, ref);
    const b = await authorize(main, ref);
    expect(a.uid).toBeTruthy();
    expect(b.uid).toBeTruthy();
    expect(a.uid).not.toBe(b.uid);
    for (const opened of [a, b]) {
      const uid = opened.uid as string;
      expect((await render(main, uid, approverHeaders(uid, opened.jar))).status).toBe(200);
    }
    expect(verifications()).toBe(before);
    expectEvidenceRefusal(await push(main, envelope([signed.entry])), "replay");
  });

  it("the authorization endpoint, the rendering and the decision succeed after exp and the capture age pass, verify nothing again, and record the push's verification time and facts", async () => {
    // iat 10 s ago, exp 10 s ahead, captured 30 s ago (the maximum capture age).
    const signed = await mint({ iatOffsetS: -10, lifetimeS: 20, captureAgeS: 20 });
    const claims = claimsOf(signed.entry.assertion);
    const before = verifications();
    const requestUri = expectAccepted(await push(main, envelope([signed.entry])));
    const accepted = acceptanceOf(signed.entry.assertion) as RequestProvenanceAcceptance;
    // Past exp plus the allowance and the capture's maximum age, within the pushed request's 60 s.
    controlledClock.advance(40_000);
    const nowS = Date.now() / 1000;
    expect(nowS).toBeGreaterThan((claims.exp as number) + 5);
    expect(nowS).toBeGreaterThan((claims.captured_at as number) + 30);
    const auth = await authorize(main, requestUri);
    expect(auth.uid, auth.location || auth.text).toBeTruthy();
    const uid = auth.uid as string;
    const headers = approverHeaders(uid, auth.jar);
    const page = await render(main, uid, headers);
    expect(page.status, page.text.slice(0, 300)).toBe(200);
    expect(page.text).toContain(String(claims.jti));
    const decided = await decide(main, uid, auth.jar, headers, { decision: "approve", render_revision: page.revision });
    expect(decided.status, decided.text).toBe(303);
    expect(new URL(decided.location).searchParams.get("code"), decided.location).toBeTruthy();
    const record = main.as.kernel.findByApprovalEvent(`apev_${uid}`);
    expect(record?.submission_evidence).toEqual([
      {
        type: TYPE,
        artifact_hash: accepted.artifactHash,
        verified_at: accepted.verifiedAt,
        facts: accepted.facts,
      },
    ]);
    expect(Date.parse(accepted.verifiedAt)).toBeLessThan(Date.now() - 39_000);
    // The push verified once; the authorization endpoint, the rendering and the decision verified nothing.
    expect(verifications()).toBe(before + 1);
  });

  it("the pushed request's own lifetime still applies: past it the authorization endpoint refuses, though the acceptance record remains", async () => {
    const signed = await mint();
    const requestUri = expectAccepted(await push(main, envelope([signed.entry])));
    controlledClock.advance(61_000);
    expect(acceptanceOf(signed.entry.assertion)).toBeDefined();
    const auth = await authorize(main, requestUri);
    expect(auth.uid).toBeUndefined();
    expect(`${auth.location} ${auth.text}`).toContain("invalid_request_uri");
  });

  it("the authorization endpoint refuses invalid_mission_intent_evidence when the acceptance record is missing", async () => {
    const signed = await mint();
    const requestUri = expectAccepted(await push(main, envelope([signed.entry])));
    mainStore.lost = true;
    try {
      const auth = await authorize(main, requestUri);
      expect(auth.uid).toBeUndefined();
      expect(auth.error, auth.location || auth.text).toBe("invalid_mission_intent_evidence");
    } finally {
      mainStore.lost = false;
    }
  });

  /** A push accepted and redeemed at the authorization endpoint: its interaction, before rendering. */
  async function openAccepted() {
    const signed = await mint();
    const auth = await authorize(main, expectAccepted(await push(main, envelope([signed.entry]))));
    expect(auth.uid, auth.location || auth.text).toBeTruthy();
    const uid = auth.uid as string;
    return { signed, uid, jar: auth.jar, headers: approverHeaders(uid, auth.jar) };
  }

  const expectRenderRefusal = (page: { status: number; text: string }, reason: string) => {
    expect(page.status, page.text.slice(0, 300)).toBe(400);
    const body = JSON.parse(page.text) as { error?: string; error_description?: string };
    expect(body.error).toBe("invalid_mission_intent_evidence");
    expect(body.error_description).toContain(reason);
  };

  it("the rendering refuses invalid_mission_intent_evidence when the acceptance record is missing", async () => {
    const opened = await openAccepted();
    mainStore.lost = true;
    try {
      expectRenderRefusal(await render(main, opened.uid, opened.headers), "no acceptance record");
    } finally {
      mainStore.lost = false;
    }
  });

  it("the rendering refuses invalid_mission_intent_evidence when the interaction names another submission than the one accepted", async () => {
    const opened = await openAccepted();
    await tamper(main, opened.uid, (i) => {
      i.parJti = "a-pushed-request-that-accepted-nothing";
    });
    expectRenderRefusal(await render(main, opened.uid, opened.headers), "belongs to another submission");
  });

  it("the rendering refuses invalid_mission_intent_evidence when the Intent differs from the one accepted", async () => {
    const opened = await openAccepted();
    await tamper(main, opened.uid, (i) => {
      i.params.mission_intent = JSON.stringify(envelope([opened.signed.entry], OTHER_INTENT));
    });
    expectRenderRefusal(await render(main, opened.uid, opened.headers), "binds another Intent");
  });

  it("the rendering refuses invalid_mission_intent_evidence when the presenter differs from the one accepted", async () => {
    const opened = await openAccepted();
    await tamper(main, opened.uid, (i) => {
      i.params.client_id = DEVICE_CLIENT;
    });
    expectRenderRefusal(await render(main, opened.uid, opened.headers), "binds another presenter");
  });

  it("the rendering refuses invalid_mission_intent_evidence when the assertion differs from the one accepted under the same iss and jti", async () => {
    const opened = await openAccepted();
    // The same claims signed again: ES256 signatures differ, the pair does not.
    const again = await resign(opened.signed.entry.assertion, {});
    expect(again).not.toBe(opened.signed.entry.assertion);
    expect(claimsOf(again).jti).toBe(claimsOf(opened.signed.entry.assertion).jti);
    await tamper(main, opened.uid, (i) => {
      i.params.mission_intent = JSON.stringify(envelope([entry(again)]));
    });
    expectRenderRefusal(await render(main, opened.uid, opened.headers), "not the one accepted");
  });

  it("the decision refuses invalid_mission_intent_evidence when the acceptance record is missing, and creates no Mission", async () => {
    const opened = await openAccepted();
    const page = await render(main, opened.uid, opened.headers);
    expect(page.status).toBe(200);
    mainStore.lost = true;
    try {
      const decided = await decide(main, opened.uid, opened.jar, opened.headers, { decision: "approve", render_revision: page.revision });
      expect(decided.status, decided.text).toBe(400);
      expect((JSON.parse(decided.text) as { error?: string }).error).toBe("invalid_mission_intent_evidence");
    } finally {
      mainStore.lost = false;
    }
    expect(main.as.kernel.findByApprovalEvent(`apev_${opened.uid}`)).toBeUndefined();
  });

  it("the approval checks still apply: the rendering refuses an Approver who is not authenticated, though the acceptance record matches", async () => {
    const opened = await openAccepted();
    const page = await render(main, opened.uid, { cookie: cookieOf(opened.jar) });
    expect(page.status).toBe(401);
    expect(page.text).not.toContain(String(claimsOf(opened.signed.entry.assertion).jti));
  });

  it("the required-evidence check still applies: a later step whose submission no longer presents the required type is refused", async () => {
    const signed = await mint({ audience: STRICT_ISSUER });
    const auth = await authorize(strict, expectAccepted(await push(strict, envelope([signed.entry]))));
    const uid = auth.uid as string;
    await tamper(strict, uid, (i) => {
      i.params.mission_intent = JSON.stringify({ intent: INTENT });
    });
    expectRenderRefusal(await render(strict, uid, approverHeaders(uid, auth.jar)), `required evidence type absent: ${TYPE}`);
  });
});

/** An active Mission and its DPoP-bound (dpopKeys) access token, through a push with no evidence. */
async function issueMission(): Promise<{ missionId: string; accessToken: string }> {
  const par = await push(main, { intent: INTENT });
  const auth = await authorize(main, expectAccepted(par));
  const uid = auth.uid as string;
  const headers = approverHeaders(uid, auth.jar);
  const page = await render(main, uid, headers);
  const decided = await decide(main, uid, auth.jar, headers, { decision: "approve", render_revision: page.revision });
  const code = new URL(decided.location).searchParams.get("code") as string;
  const tok = await tokenRequest({ grant_type: "authorization_code", code, redirect_uri: REDIRECT_URI, code_verifier: PKCE_VERIFIER, resource: RESOURCE });
  const body = (await tok.json()) as { access_token: string };
  expect(tok.status, JSON.stringify(body)).toBe(200);
  return { missionId: (decodeJwt(body.access_token) as { mission: { id: string } }).mission.id, accessToken: body.access_token };
}

/** POST /token as ap-agent with a DPoP proof under dpopKeys, with the nonce retry. */
async function tokenRequest(params: Record<string, string>): Promise<Response> {
  const htu = `${ISSUER}/token`;
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
        client_assertion: await clientAssertion(main),
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      }).toString(),
    });
  let res = await send();
  const nonce = res.headers.get("dpop-nonce");
  if (res.status === 400 && nonce) res = await send({ nonce });
  return res;
}

const readEntry = [
  {
    type: "mission_resource_access",
    resource: RESOURCE,
    actions: ["payments:invoice.read"],
    constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
  },
];

async function expectCarrierRefusal(res: Response): Promise<void> {
  const body = (await res.json()) as { error?: string; error_description?: string };
  expect(res.status, JSON.stringify(body)).toBe(400);
  expect(body.error).toBe("invalid_mission_intent_evidence");
  expect(body.error_description).toContain("does not accept the evidence type");
}

describe("carriers that do not admit the type (@spec request-provenance#verification, request-provenance#replay, #939 slice 2a-2)", () => {
  it("the device authorization endpoint refuses invalid_mission_intent_evidence an otherwise valid assertion, before any signature verification", async () => {
    const signed = await mint({ presenter: { client_id: DEVICE_CLIENT } });
    const before = verifications();
    const res = await fetch(`${ISSUER}/device/auth`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: DEVICE_CLIENT,
        resource: RESOURCE,
        mission_intent: JSON.stringify(envelope([signed.entry])),
        authorization_details: JSON.stringify([{ type: "mission_resource_access", resource: RESOURCE, actions: ["payments:invoice.read"] }]),
      }).toString(),
    });
    await expectCarrierRefusal(res);
    expect(verifications()).toBe(before);
  });

  it("template dispatch refuses invalid_mission_intent_evidence an otherwise valid assertion, before any signature verification", async () => {
    const created = await fetch(`${ISSUER}/templates`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-service-token": DEV_SERVICE_TOKEN },
      body: JSON.stringify({ ...demoReconciliationTemplate(ISSUER), approval_event_id: `tmpl-rp-${crypto.randomUUID()}` }),
    });
    const { template_id } = (await created.json()) as { template_id: string };
    expect(created.status).toBe(201);
    const intent = { goal: "reconcile Acme invoices", target_resources: [RESOURCE], expires_at: FIXTURE_EXPIRES_AT };
    const signed = await mint({ intent: intent as unknown as JsonObject });
    const before = verifications();
    await expectCarrierRefusal(
      await tokenRequest({
        grant_type: MISSION_DISPATCH_GRANT_TYPE,
        template_id,
        mission_intent: JSON.stringify(envelope([signed.entry], intent)),
        dispatch_event_id: `evt-rp-${crypto.randomUUID()}`,
      }),
    );
    expect(verifications()).toBe(before);
  });

  it("the child-creation exchange refuses invalid_mission_intent_evidence an otherwise valid assertion bound to the exchange's key, before any signature verification", async () => {
    const parent = await issueMission();
    const intent = { goal: "Extract Acme invoices", target_resources: [RESOURCE], expires_at: FIXTURE_EXPIRES_AT };
    const signed = await mint({ intent: intent as unknown as JsonObject, presenter: { client_id: "ap-agent", cnf: { jkt: dpopJkt } } });
    const before = verifications();
    await expectCarrierRefusal(
      await tokenRequest({
        grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
        subject_token: parent.accessToken,
        subject_token_type: ACCESS_TOKEN_TOKEN_TYPE,
        requested_token_type: JWT_TOKEN_TYPE,
        creation_request_id: crypto.randomUUID(),
        login_hint: "alice",
        mission_intent: JSON.stringify(envelope([signed.entry], intent)),
        authorization_details: JSON.stringify(readEntry),
        child_actor: JSON.stringify({ sub: "subagent-extractor", sub_profile: "ai_agent" }),
      }),
    );
    expect(verifications()).toBe(before);
  });

  it("the expansion exchange refuses invalid_mission_intent_evidence an otherwise valid assertion bound to the exchange's key, before any signature verification", async () => {
    const predecessor = await issueMission();
    const intent = { goal: "Widen to remittance", target_resources: [RESOURCE], expires_at: FIXTURE_EXPIRES_AT };
    const signed = await mint({ intent: intent as unknown as JsonObject, presenter: { client_id: "ap-agent", cnf: { jkt: dpopJkt } } });
    const before = verifications();
    await expectCarrierRefusal(
      await tokenRequest({
        grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
        subject_token: predecessor.accessToken,
        subject_token_type: ACCESS_TOKEN_TOKEN_TYPE,
        requested_token_type: ACCESS_TOKEN_TOKEN_TYPE,
        creation_request_id: crypto.randomUUID(),
        completion_mode: "deferred",
        login_hint: "alice",
        mission_intent: JSON.stringify(envelope([signed.entry], intent)),
        authorization_details: JSON.stringify([
          { ...readEntry[0], actions: ["payments:invoice.read", "payments:remittance.send"] },
        ]),
      }),
    );
    expect(verifications()).toBe(before);
  });
});

describe("enabling the type (@spec request-provenance#replay, D1119 Q5, D1151, #1963)", () => {
  it("refuses construction with a file-backed kernel store and a supplied, non-durable replay store, whose restart would forget the replay history and acceptance records, before the kernel file is opened", async () => {
    const dir = mkdtempSync(join(tmpdir(), "rp-file-backed-"));
    const file = join(dir, "kernel.db");
    try {
      await expect(
        buildAuthorizationServer({
          issuer: "https://file-backed.as.example",
          kernelStore: { file },
          requestProvenance: { config: TRUST, store: new InMemoryRequestProvenanceStore() },
        }),
      ).rejects.toThrow(
        "mission-request-provenance on a file-backed kernel store keeps its replay history and acceptance records on the kernel's database: a supplied replay store does not survive a restart with the kernel (D1119 Q5, #1963)",
      );
      expect(existsSync(file)).toBe(false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("starts with a file-backed kernel store and the default replay store, which keeps its pairs on the kernel's database in that file", async () => {
    const dir = mkdtempSync(join(tmpdir(), "rp-file-backed-"));
    const file = join(dir, "kernel.db");
    try {
      const built = await buildAuthorizationServer({
        issuer: "https://file-backed.as.example",
        kernelStore: { file },
        requestProvenance: { config: TRUST },
      });
      try {
        const store = built.requestProvenanceStore;
        expect(store).toBeInstanceOf(SqliteRequestProvenanceStore);
        expect((store as SqliteRequestProvenanceStore).db).toBe(built.kernel.db);
        expect(built.kernel.db.name).toBe(file);
        expect(
          built.kernel.db.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'request_provenance_pairs'").get(),
        ).toEqual({ name: "request_provenance_pairs" });
      } finally {
        built.suspensionScheduler?.stop();
        built.kernel.close();
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }, 30_000);

  it("registers nothing for a disabled configuration, the shipped one included: the type is unknown there", async () => {
    expect(REQUEST_PROVENANCE_CONFIG.enabled).toBe(false);
    for (const config of [REQUEST_PROVENANCE_CONFIG, { ...TRUST, enabled: false }]) {
      const built = await buildAuthorizationServer({ issuer: "https://disabled.as.example", requestProvenance: { config } });
      const intent = built.kernel.validateIntent(JSON.stringify(INTENT));
      await expect(
        built.kernel.verifySubmissionEvidence({ intent, evidence: [entry("a.b.c") as never], presenter: { clientId: "ap-agent" } }),
      ).rejects.toThrow(`unknown evidence type: ${TYPE}`);
    }
  }, 30_000);
});

describe("the admission scope at the dispatch (@spec request-provenance#replay, submission-evidence#verification-bounds, #939 slice 2a-2)", () => {
  const store = new InMemoryRequestProvenanceStore();
  const types: IntentSubmissionEvidenceTypes = new Map([
    [TYPE, createRequestProvenanceEvidenceType({ trust: TRUST, store, acceptanceRetentionSeconds: 3600 })],
  ]);
  const ctx = (admission?: SubmissionAdmission, accepted?: { ref: string }) => ({
    intentHash: provisionalIntentHash(ISSUER, INTENT as never),
    issuer: ISSUER,
    presenter: { clientId: "ap-agent" },
    now: new Date(),
    ...(admission ? { admission } : {}),
    ...(accepted ? { accepted } : {}),
  });

  it("releases the reservation when another entry fails, before the carrier settles the scope", async () => {
    const signed = await mint();
    const first = new SubmissionAdmission();
    await expect(
      verifyIntentSubmissionEvidence([signed.entry, { type: REFUSING_TYPE, assertion: "x" }] as never, ctx(first), [], {}, types),
    ).rejects.toThrow("never verifies");
    expect(first.state).toBe("released");
    const second = new SubmissionAdmission();
    const facts = await verifyIntentSubmissionEvidence([signed.entry] as never, ctx(second), [], {}, types);
    expect(facts?.[0]?.facts?.assertion_id).toBe(signed.jti);
  });

  it("releases the reservation when a later entry passes the verification-work bound, before the carrier settles the scope", async () => {
    const signed = await mint();
    const first = new SubmissionAdmission();
    const refused = verifyIntentSubmissionEvidence(
      [signed.entry, { type: PASSING_TYPE, assertion: "x" }] as never,
      ctx(first),
      [],
      { maxVerificationWork: 1 },
      types,
    );
    await expect(refused).rejects.toMatchObject({ code: "invalid_request" });
    expect(first.state).toBe("released");
    const second = new SubmissionAdmission();
    await expect(verifyIntentSubmissionEvidence([signed.entry] as never, ctx(second), [], { maxVerificationWork: 1 }, types)).resolves.toHaveLength(1);
  });

  it("a committed scope releases nothing, a released scope commits nothing, and release is idempotent", async () => {
    const signed = await mint();
    const admission = new SubmissionAdmission();
    await verifyIntentSubmissionEvidence([signed.entry] as never, ctx(admission), [], {}, types);
    admission.commit("par:scope-test");
    admission.release();
    const c = claimsOf(signed.entry.assertion);
    expect(store.accepted(String(c.iss), String(c.jti), Date.now())?.submissionRef).toBe("par:scope-test");
    // The scope's own guard, apart from the store's: a committed scope calls no hold's release.
    expect(admission.state).toBe("committed");
    const recorded = new SubmissionAdmission();
    let holdReleases = 0;
    recorded.hold({
      prepare: () => () => {},
      release() {
        holdReleases += 1;
      },
    });
    recorded.commit("par:recorded");
    recorded.release();
    expect(holdReleases).toBe(0);
    expect(recorded.state).toBe("committed");
    const released = new SubmissionAdmission();
    released.release();
    released.release();
    expect(() => released.commit("par:late")).toThrow("a released admission commits nothing");
    expect(released.state).toBe("released");
  });

  it("resumes an accepted entry with no verification work, and refuses a record that names another authorization server, or a step presenting a confirmation key", async () => {
    const signed = await mint();
    const admission = new SubmissionAdmission();
    const verified = await verifyIntentSubmissionEvidence([signed.entry] as never, ctx(admission), [], {}, types);
    admission.commit("par:resume-test");
    const before = verifications();
    // A bound of 0: a resume verifies no signature and is charged nothing.
    const resumed = await verifyIntentSubmissionEvidence([signed.entry] as never, ctx(undefined, { ref: "par:resume-test" }), [], { maxVerificationWork: 0 }, types);
    expect(resumed).toEqual(verified);
    expect(verifications()).toBe(before);
    // Only the issuer differs: the step's own provisional hash is the record's.
    await expect(
      verifyIntentSubmissionEvidence(
        [signed.entry] as never,
        { ...ctx(undefined, { ref: "par:resume-test" }), issuer: STRICT_ISSUER },
        [],
        {},
        types,
      ),
    ).rejects.toThrow("names another authorization server");
    await expect(
      verifyIntentSubmissionEvidence(
        [signed.entry] as never,
        { ...ctx(undefined, { ref: "par:resume-test" }), presenter: { clientId: "ap-agent", cnf: { jkt: dpopJkt } } },
        [],
        {},
        types,
      ),
    ).rejects.toThrow("binds another presenter");
  });

  it.each([false, true])(
    "settles all or nothing: when one hold can no longer commit, none commits and every hold is released (the lapsed hold first: %s)",
    (lapsedFirst) => {
      const admission = new SubmissionAdmission();
      const commits: string[] = [];
      let releases = 0;
      const live = { prepare: (ref: string) => () => void commits.push(ref), release: () => void (releases += 1) };
      const lapsed = { prepare: () => undefined, release: () => void (releases += 1) };
      for (const hold of lapsedFirst ? [lapsed, live] : [live, lapsed]) admission.hold(hold);
      expect(() => admission.commit("par:all-or-nothing")).toThrow("nothing is committed");
      expect(commits).toEqual([]);
      expect(releases).toBe(2);
      expect(admission.state).toBe("released");
    },
  );

  it("settles in one transaction: when a commit step throws, the shared transaction rolls every commit back, the scope releases every hold, and none is committed", () => {
    const admission = new SubmissionAdmission();
    let applied: string[] = [];
    const released: string[] = [];
    const atomically = (steps: () => void): void => {
      const before = [...applied];
      try {
        steps();
      } catch (e) {
        applied = before;
        throw e;
      }
    };
    admission.hold({ prepare: (ref) => () => void applied.push(`a:${ref}`), release: () => void released.push("a"), atomically });
    admission.hold({
      prepare: () => () => {
        throw new Error("the store refused the write");
      },
      release: () => void released.push("b"),
      atomically,
    });
    expect(() => admission.commit("par:failed-write")).toThrow("the store refused the write");
    expect(applied).toEqual([]);
    expect(released.sort()).toEqual(["a", "b"]);
    expect(admission.state).toBe("released");
  });

  it("releases every hold when a commit step throws, even where the holds share no transaction: the scope is never committed by a failed settlement", () => {
    const admission = new SubmissionAdmission();
    const released: string[] = [];
    admission.hold({ prepare: () => () => {}, release: () => void released.push("a") });
    admission.hold({
      prepare: () => () => {
        throw new Error("the store refused the write");
      },
      release: () => void released.push("b"),
    });
    expect(() => admission.commit("par:failed-write")).toThrow("the store refused the write");
    expect(released.sort()).toEqual(["a", "b"]);
    expect(admission.state).toBe("released");
  });

  it("the replay store releases only a reservation: releasing a committed pair's token keeps its acceptance record and its pair", async () => {
    const own = new InMemoryRequestProvenanceStore();
    const at = Date.UTC(2026, 10, 2, 12);
    const record = {
      iss: "https://intake.example.org",
      jti: "store-committed",
      expiresAtMs: at + 60_000,
      issuer: ISSUER,
      intentHash: provisionalIntentHash(ISSUER, INTENT as never),
      presenter: { clientId: "ap-agent" },
      assertion: "a.b.c",
      artifactHash: "sha-256:x",
      verifiedAt: new Date(at).toISOString(),
      facts: {},
    };
    const committed = await own.reserve(record, at);
    expect(committed).toBeDefined();
    expect(own.commit(committed as string, "par:store-test", at, at + 3_600_000)).toBe(true);
    own.release(committed as string);
    expect(own.accepted(record.iss, record.jti, at)?.submissionRef).toBe("par:store-test");
    expect(await own.reserve({ ...record }, at)).toBeUndefined();
    // The control: a reservation does release, and its pair is free again.
    const reserved = await own.reserve({ ...record, jti: "store-reserved" }, at);
    expect(reserved).toBeDefined();
    own.release(reserved as string);
    expect(await own.reserve({ ...record, jti: "store-reserved" }, at)).toBeDefined();
  });

  it("refuses a verification with neither an admission scope nor an accepted reference, before any signature verification", async () => {
    const signed = await mint();
    const before = verifications();
    await expect(verifyIntentSubmissionEvidence([signed.entry] as never, ctx(), [], {}, types)).rejects.toThrow(
      "does not accept the evidence type",
    );
    expect(verifications()).toBe(before);
  });
});
