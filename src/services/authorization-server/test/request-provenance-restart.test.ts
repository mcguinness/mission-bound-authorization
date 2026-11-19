/**
 * @spec request-provenance#replay (D1119 Q1, Q2 and Q5, #1963)
 *
 * The `mission-request-provenance` replay store across a restart of the
 * authorization server, on a file-backed kernel store with its recovery
 * witness, on a controlled clock. Each AS here keeps the type's default
 * store, on the kernel's database; a restart closes the AS and its kernel,
 * replaces oidc-provider's process-global memory (what a new process
 * starts with), and builds a new AS on the same kernel file and witness.
 *
 *  - Replay: a push whose assertion committed before the restart is refused
 *    as replay after it; the committed pair is kept past `exp` plus skew
 *    within its retention, and swept once that ends.
 *  - The acceptance record: a deferred activation staged before the
 *    restart, which relies on the push's record, activates after it, past
 *    the assertion's `exp`; a missing or mismatched record still refuses.
 *  - What does not survive: the pushed request itself, and so the
 *    authorization endpoint, rendering and decision of a push accepted
 *    before the restart, are the provider's, in its memory.
 *  - Concurrency on the durable store: of two concurrent pushes of one
 *    assertion, exactly one is accepted.
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

import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import type { Server } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { DERIVATION_POLICY, parseRequestProvenanceConfig, TOPOLOGY } from "@mission/demo-data";
import { type Channel, createRequestIntake, type JsonObject } from "@mission/request-provenance";
import { calculateJwkThumbprint, exportJWK, generateKeyPair, importJWK, type JWK, SignJWT } from "jose";
import { setStorage } from "oidc-provider/lib/adapters/memory_adapter.js";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import {
  ALL_PROVIDER_CAPABILITIES,
  buildAuthorizationServer,
  type BuiltAs,
  DEFERRED_GRANT_TYPE,
  type GovernedPolicyRoot,
  governedPolicyConsentDisclosure,
  initSigningKeyRing,
  type MissionRecord,
  reconcileKernelRecovery,
  type RegisteredActivationPolicy,
  type RequestProvenanceAcceptance,
  type RequestProvenanceRecord,
  recordGovernedPolicyConsent,
  requestProvenanceAcceptanceRetention,
  SqliteRequestProvenanceStore,
} from "../src/index.js";
import { verifyRequestProvenance } from "../src/kernel/request-provenance.js";
import { TEST_APPROVAL_PRINCIPALS } from "./approval-fixture.js";
import { FIXTURE_EXPIRES_AT } from "./relative-expiry.helper.js";

/** Each test boots and restarts the AS on a loaded machine. */
const RESTART_TIMEOUT_MS = 120_000;
const verifications = () => vi.mocked(verifyRequestProvenance).mock.calls.length;
const claimsOf = (assertion: string): Record<string, unknown> =>
  JSON.parse(Buffer.from(assertion.split(".")[1] as string, "base64url").toString("utf8")) as Record<string, unknown>;

const TYPE = "mission-request-provenance";
const REPLAY_PORT = 14911;
const DEFERRED_PORT = 14912;
const CONCURRENT_PORT = 14913;
const FAULT_PORT = 14914;
const REDIRECT_URI = "http://localhost:9999/cb";
const RESOURCE = DERIVATION_POLICY.ceiling[0].resource as string;
const PUSHED_REQUEST_URN = "urn:ietf:params:oauth:request_uri:";
const SKEW_S = 5;

const INTAKE = "https://intake.example.org";
const KID = "intake-1";
const IDP = "https://idp.example.org";
const APP_CHANNEL = "https://intake.example.org/ch/app";
const SERVICE_CHANNEL = "https://intake.example.org/ch/service";

const AGENT = "ap-agent";
const RECONCILER = "ledger-reconciler";
const WORKLOAD = "agt_ledger_reconciler";
const READ = ["payments:invoice.list", "payments:invoice.read", "payments:vendor.read"];
const VERIFIER = "request-provenance-restart-verifier-0123456789-0123456";

const INTENT = { goal: "Reconcile Q3 invoices", target_resources: [RESOURCE], expires_at: FIXTURE_EXPIRES_AT };
const RECONCILE_INTENT = {
  goal: "Reconcile Acme invoices against the ledger",
  target_resources: [RESOURCE],
  expires_at: FIXTURE_EXPIRES_AT,
};

const intakeKeys = await generateKeyPair("ES256", { extractable: true });

/** One configured signer, for both clients' channels. Skew 5 s; lifetime and capture age at most 120 s. */
const TRUST = parseRequestProvenanceConfig({
  enabled: true,
  clock_skew_seconds: SKEW_S,
  max_assertion_lifetime_seconds: 120,
  max_capture_age_seconds: 120,
  signers: [
    {
      iss: INTAKE,
      keys: [{ kid: KID, public_jwk: (await exportJWK(intakeKeys.publicKey)) as never, evidence_types: [TYPE], algs: ["ES256"] }],
      originators: [{ iss: IDP }],
      channel_types: [APP_CHANNEL, SERVICE_CHANNEL],
    },
  ],
});

/** A deferred approval's pending lifetime here, which the retention composes. */
const PENDING_LIFETIME_S = 600;

const dirs: string[] = [];
const open: Instance[] = [];
/** Close every AS still open, so a failed test leaves no port or kernel file held. */
const closeOpen = async (): Promise<void> => {
  for (const inst of [...open]) await shutdown(inst);
};
afterAll(async () => {
  await closeOpen();
  for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
  controlledClock.restore();
});

interface Paths {
  store: string;
  witness: string;
  ring: string;
}

/**
 * A file-backed deployment of the AS on `port`: a kernel file and its
 * recovery witness, in separate directories, the witness created once, and
 * a signing key ring, so what the first boot signed (a governed policy
 * consent among it) verifies after the restart, as a deployment that keeps
 * its kernel keeps its keys.
 */
async function deployment(port: number): Promise<Paths> {
  const root = mkdtempSync(join(tmpdir(), "rp-restart-"));
  dirs.push(root);
  const store = join(root, "state", "kernel.db");
  const witness = join(root, "witness", "kernel.witness");
  const ring = join(root, "keys", "as-signing-keys.json");
  mkdirSync(dirname(store), { recursive: true });
  mkdirSync(dirname(witness), { recursive: true });
  reconcileKernelRecovery({ storeFile: store, witnessFile: witness, action: "init" });
  const { asToken, asStatus, asTxn, asContinuation } = TOPOLOGY.keys;
  await initSigningKeyRing(ring, `http://localhost:${port}`, { asToken, asStatus, asTxn, asContinuation });
  return { store, witness, ring };
}

interface Instance {
  as: BuiltAs;
  issuer: string;
  server: Server;
  keys: Record<string, CryptoKey>;
}

const governance: { roots: Record<string, RegisteredActivationPolicy>; approvers: Record<string, string[]> } = {
  roots: {},
  approvers: {},
};
const ROOT_ID = "urn:root:request-provenance-restart";

/** The AS on the kernel file, with the type's default store, listening on `port`. */
async function boot(port: number, paths: Paths): Promise<Instance> {
  const issuer = `http://localhost:${port}`;
  const as = await buildAuthorizationServer({
    issuer,
    allowHeadlessAdjudication: true,
    serviceTokenPrincipals: { ...TEST_APPROVAL_PRINCIPALS },
    capabilities: new Set([...ALL_PROVIDER_CAPABILITIES, "deferred-approval"]),
    governedPolicyApproval: governance,
    activationPolicies: {},
    deferredApproval: { pendingLifetimeS: PENDING_LIFETIME_S },
    kernelStore: { file: paths.store, witness: paths.witness },
    signingKeys: { ring: paths.ring },
    requestProvenance: { config: TRUST },
  });
  const server = as.provider.listen(port);
  await new Promise<void>((r) => server.once("listening", () => r()));
  const inst: Instance = {
    as,
    issuer,
    server,
    keys: {
      [AGENT]: (await importJWK(as.agentClientJwk as never, "ES256")) as CryptoKey,
      [RECONCILER]: (await importJWK(as.ledgerReconcilerClientJwk as never, "ES256")) as CryptoKey,
    },
  };
  open.push(inst);
  return inst;
}

/** Stop the AS and release its kernel file and witness. */
async function shutdown(inst: Instance): Promise<void> {
  const at = open.indexOf(inst);
  if (at >= 0) open.splice(at, 1);
  inst.server.closeAllConnections();
  await new Promise<void>((r) => inst.server.close(() => r()));
  inst.as.suspensionScheduler?.stop();
  inst.as.kernel.close();
}

/**
 * A restart: the AS and its kernel close, and the next AS starts with
 * empty provider memory, as a new process does (oidc-provider's memory
 * adapter is process-global, so an AS rebuilt in this process would
 * otherwise still find the first one's pushed requests and interactions).
 */
async function restart(inst: Instance, port: number, paths: Paths): Promise<Instance> {
  await shutdown(inst);
  setStorage(new Map());
  return boot(port, paths);
}

interface MintOptions {
  audience: string;
  presenter: string;
  intent: JsonObject;
  channel: Channel;
  /** `exp` minus `iat`. */
  lifetimeS?: number;
  /** `iat` relative to the controlled now. Default 0. */
  iatOffsetS?: number;
}

/** Capture and sign through the intake library on the controlled clock: captured 5 s before `iat`. */
async function mint(o: MintOptions) {
  let offsetMs = ((o.iatOffsetS ?? 0) - 5) * 1000;
  const intake = createRequestIntake({
    issuer: INTAKE,
    kid: KID,
    signingKey: intakeKeys.privateKey,
    assertionLifetimeSeconds: o.lifetimeS ?? 90,
    maxCaptureAgeSeconds: 3600,
    now: () => Date.now() + offsetMs,
  });
  const receipt = intake.capture({
    workflow: "wf-restart",
    instruction: Buffer.from("Reconcile the invoices against the ledger.", "utf8"),
    mediaType: "text/plain;charset=utf-8",
    originator: { iss: IDP, sub: "alice" },
    channel: o.channel,
    presenter: { client_id: o.presenter },
  });
  offsetMs = (o.iatOffsetS ?? 0) * 1000;
  return intake.sign({ captureId: receipt.captureId, workflow: "wf-restart", audience: o.audience, intent: o.intent });
}

const mintFor = (inst: Instance, extra: Partial<MintOptions> = {}) =>
  mint({ audience: inst.issuer, presenter: AGENT, intent: INTENT as unknown as JsonObject, channel: { type: APP_CHANNEL }, ...extra });

const mintForReconciler = (inst: Instance, extra: Partial<MintOptions> = {}) =>
  mint({
    audience: inst.issuer,
    presenter: RECONCILER,
    intent: RECONCILE_INTENT as unknown as JsonObject,
    channel: { type: SERVICE_CHANNEL },
    ...extra,
  });

const clientAuth = async (inst: Instance, clientId: string) => ({
  client_assertion: await new SignJWT({})
    .setProtectedHeader({ alg: "ES256", kid: `${clientId}-auth` })
    .setIssuer(clientId)
    .setSubject(clientId)
    .setAudience(inst.issuer)
    .setIssuedAt()
    .setExpirationTime("2m")
    .setJti(crypto.randomUUID())
    .sign(inst.keys[clientId] as CryptoKey),
  client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
});

const challenge = async () =>
  Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(VERIFIER))).toString("base64url");

const readEntry = (actions: string[] = READ) => ({
  type: "mission_resource_access",
  resource: RESOURCE,
  actions,
  constraints: { vendors: ["acme"] },
});

type Reply = { status: number; body: Record<string, unknown> };

async function reply(res: Response): Promise<Reply> {
  const text = await res.text();
  try {
    return { status: res.status, body: JSON.parse(text) as Record<string, unknown> };
  } catch {
    return { status: res.status, body: { text } };
  }
}

/** A pushed authorization request as ap-agent, its mission_intent the envelope of `evidence`. */
async function push(inst: Instance, evidence: unknown[]): Promise<Reply> {
  return reply(
    await fetch(`${inst.issuer}/request`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: AGENT,
        response_type: "code",
        redirect_uri: REDIRECT_URI,
        resource: RESOURCE,
        code_challenge: await challenge(),
        code_challenge_method: "S256",
        login_hint: "alice",
        mission_intent: JSON.stringify({ intent: INTENT, evidence }),
        ...(await clientAuth(inst, AGENT)),
      }).toString(),
    }),
  );
}

/** A deferred pushed authorization request as ledger-reconciler. */
async function pushDeferred(inst: Instance, evidence: unknown[]): Promise<Reply> {
  return reply(
    await fetch(`${inst.issuer}/request`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: RECONCILER,
        response_type: "code",
        redirect_uri: REDIRECT_URI,
        code_challenge: await challenge(),
        code_challenge_method: "S256",
        mission_intent: JSON.stringify({ intent: RECONCILE_INTENT, evidence }),
        authorization_details: JSON.stringify([readEntry(["payments:invoice.read"])]),
        completion_mode: "deferred",
        ...(await clientAuth(inst, RECONCILER)),
      }).toString(),
    }),
  );
}

function expectAccepted(r: Reply): string {
  expect(r.status, JSON.stringify(r.body)).toBe(201);
  const uri = r.body.request_uri as string;
  expect(uri.startsWith(PUSHED_REQUEST_URN)).toBe(true);
  return uri;
}

function expectReplay(r: Reply): void {
  expect(r.status, JSON.stringify(r.body)).toBe(400);
  expect(r.body.error).toBe("invalid_mission_intent_evidence");
  expect(String(r.body.error_description)).toContain("step 10: replay");
}

/** The authorization request redeeming `requestUri`, as the client's user agent: where it lands. */
async function authorize(inst: Instance, clientId: string, requestUri: string): Promise<{ location: string; text: string }> {
  const res = await fetch(`${inst.issuer}/auth?${new URLSearchParams({ client_id: clientId, request_uri: requestUri })}`, {
    redirect: "manual",
  });
  const location = res.headers.get("location") ?? "";
  return { location, text: location ? "" : await res.text() };
}

type Keys = { privateKey: CryptoKey; jwk: JWK; jkt: string };
const newKeys = async (): Promise<Keys> => {
  const pair = await generateKeyPair("ES256", { extractable: true });
  const jwk = await exportJWK(pair.publicKey);
  return { privateKey: pair.privateKey as CryptoKey, jwk, jkt: await calculateJwkThumbprint(jwk) };
};

async function tokenRequest(inst: Instance, params: Record<string, string>, keys: Keys): Promise<Reply> {
  const htu = `${inst.issuer}/token`;
  const dpop = await new SignJWT({ htu, htm: "POST" })
    .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: keys.jwk })
    .setIssuedAt()
    .setJti(crypto.randomUUID())
    .sign(keys.privateKey);
  return reply(
    await fetch(htu, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", dpop },
      body: new URLSearchParams({ ...params, ...(await clientAuth(inst, RECONCILER)) }).toString(),
    }),
  );
}

/** The agent's deferred push of `evidence`, redeemed into a pending approval: its deferral code and the push's jti. */
async function openDeferral(inst: Instance, keys: Keys, evidence: unknown[]): Promise<{ deferralCode: string; pushedJti: string }> {
  const requestUri = expectAccepted(await pushDeferred(inst, evidence));
  const jar = new Map<string, string>();
  const keep = (res: Response) => {
    for (const line of res.headers.getSetCookie()) {
      const [pair] = line.split(";");
      const eq = (pair as string).indexOf("=");
      jar.set((pair as string).slice(0, eq), (pair as string).slice(eq + 1));
    }
  };
  const cookie = () => [...jar].map(([k, v]) => `${k}=${v}`).join("; ");
  let res = await fetch(`${inst.issuer}/auth?${new URLSearchParams({ client_id: RECONCILER, request_uri: requestUri })}`, {
    redirect: "manual",
  });
  keep(res);
  let location = res.headers.get("location") ?? "";
  while (location.startsWith(inst.issuer) || location.startsWith("/")) {
    res = await fetch(new URL(location, inst.issuer), { redirect: "manual", headers: { cookie: cookie() } });
    keep(res);
    location = res.headers.get("location") ?? "";
  }
  const code = location.startsWith(REDIRECT_URI) ? new URL(location).searchParams.get("code") : null;
  expect(code, location).toBeTruthy();
  const r = await tokenRequest(
    inst,
    { grant_type: "authorization_code", code: code as string, redirect_uri: REDIRECT_URI, code_verifier: VERIFIER, completion_mode: "deferred" },
    keys,
  );
  expect(r.status, JSON.stringify(r.body)).toBe(400);
  expect(r.body.error).toBe("authorization_pending");
  return { deferralCode: r.body.deferral_code as string, pushedJti: requestUri.slice(PUSHED_REQUEST_URN.length) };
}

const poll = (inst: Instance, deferralCode: string, keys: Keys) =>
  tokenRequest(inst, { grant_type: DEFERRED_GRANT_TYPE, deferral_code: deferralCode }, keys);

/** The rows the kernel's file holds for the pair (INTAKE, `jti`). */
const pairRows = (inst: Instance, jti: string) =>
  inst.as.kernel.db
    .prepare("SELECT state, submission_ref FROM request_provenance_pairs WHERE iss = ? AND jti = ?")
    .all(INTAKE, jti) as Array<{ state: string; submission_ref: string | null }>;

const storeOf = (inst: Instance) => inst.as.requestProvenanceStore as SqliteRequestProvenanceStore;

describe("replay across a restart (@spec request-provenance#replay, D1119 Q5, #1963)", () => {
  afterEach(closeOpen);

  it("refuses as replay after a restart an assertion whose push committed before it, keeps the committed pair past exp plus the clock-skew allowance within its retention, and sweeps it once the retention ends", async () => {
    const paths = await deployment(REPLAY_PORT);
    const first = await boot(REPLAY_PORT, paths);
    const signed = await mintFor(first);
    const requestUri = expectAccepted(await push(first, [signed.entry]));
    const committedAt = Date.now();
    const ref = `par:${requestUri.slice(PUSHED_REQUEST_URN.length)}`;

    const second = await restart(first, REPLAY_PORT, paths);
    // Within exp plus the allowance, step 7 still passes: the refusal is step 10's.
    expect(Date.now() / 1000).toBeLessThan(signed.exp);
    expectReplay(await push(second, [signed.entry]));
    // The pair the first boot committed, read back from the kernel's file by the AS's default store.
    expect(storeOf(second)).toBeInstanceOf(SqliteRequestProvenanceStore);
    expect(storeOf(second).db).toBe(second.as.kernel.db);
    expect(pairRows(second, signed.jti)).toEqual([{ state: "committed", submission_ref: ref }]);
    expect(storeOf(second).accepted(INTAKE, signed.jti, Date.now())?.submissionRef).toBe(ref);

    // Past exp plus the allowance, within the retention: a fresh push sweeps
    // lapsed pairs first, and the committed one is kept.
    controlledClock.advance((signed.exp + SKEW_S) * 1000 + 1000 - Date.now());
    const later = await mintFor(second);
    expectAccepted(await push(second, [later.entry]));
    expect(pairRows(second, signed.jti)).toEqual([{ state: "committed", submission_ref: ref }]);

    // Past the retention: the next push sweeps it.
    const retentionMs = requestProvenanceAcceptanceRetention(SKEW_S, PENDING_LIFETIME_S) * 1000;
    controlledClock.advance(committedAt + retentionMs + 1000 - Date.now());
    expect(storeOf(second).accepted(INTAKE, signed.jti, Date.now())).toBeUndefined();
    const last = await mintFor(second);
    expectAccepted(await push(second, [last.entry]));
    expect(pairRows(second, signed.jti)).toEqual([]);
    await shutdown(second);
  }, RESTART_TIMEOUT_MS);

  it("does not keep the pushed request across a restart: it is the provider's, in its memory, so the authorization endpoint refuses its request_uri invalid_request_uri, while the committed pair still refuses the assertion as replay", async () => {
    const paths = await deployment(REPLAY_PORT);
    const first = await boot(REPLAY_PORT, paths);
    const signed = await mintFor(first);
    const requestUri = expectAccepted(await push(first, [signed.entry]));
    // Before the restart the request_uri opens an interaction.
    const opened = await authorize(first, AGENT, requestUri);
    expect(opened.location, opened.text).toContain("/interaction/");

    const second = await restart(first, REPLAY_PORT, paths);
    const after = await authorize(second, AGENT, requestUri);
    expect(`${after.location} ${after.text}`).toContain("invalid_request_uri");
    expectReplay(await push(second, [signed.entry]));
    await shutdown(second);
  }, RESTART_TIMEOUT_MS);
});

describe("the acceptance record across a restart (@spec request-provenance#replay, deferred-approval#deferred-sequencing, D1119 Q1, Q2 and Q5, #1963)", () => {
  let second: Instance;
  afterAll(closeOpen);
  const staged: Array<{
    keys: Keys;
    deferralCode: string;
    jti: string;
    accepted: RequestProvenanceAcceptance;
    exp: number;
    capturedAt: number;
  }> = [];

  /** Three deferred pushes, each redeemed into a pending approval, staged before a restart. */
  beforeAll(async () => {
    const paths = await deployment(DEFERRED_PORT);
    const first = await boot(DEFERRED_PORT, paths);
    governance.roots[ROOT_ID] = { version: "1", content_type: "application/json", content: JSON.stringify(rootDoc()) };
    governance.approvers[ROOT_ID] = ["dana"];
    recordGovernedPolicyConsent(first.as.kernel, {
      root: { id: ROOT_ID, version: "1" },
      approver: { iss: first.issuer, sub: "dana" },
      consentEventId: `gpce-${ROOT_ID}`,
      // The commitment of the disclosure rendered to the approver (#2040, D1278).
      disclosure: governedPolicyConsentDisclosure(first.as.kernel, { id: ROOT_ID, version: "1" }).commitment,
    });
    for (let i = 0; i < 3; i += 1) {
      const keys = await newKeys();
      // iat 10 s ago and exp 10 s ahead: the activation comes well after exp.
      const signed = await mintForReconciler(first, { iatOffsetS: -10, lifetimeS: 20 });
      const { deferralCode, pushedJti } = await openDeferral(first, keys, [signed.entry]);
      const accepted = storeOf(first).accepted(INTAKE, signed.jti, Date.now()) as RequestProvenanceAcceptance;
      expect(accepted.submissionRef).toBe(`par:${pushedJti}`);
      const capturedAt = claimsOf(signed.entry.assertion).captured_at as number;
      staged.push({ keys, deferralCode, jti: signed.jti, accepted, exp: signed.exp, capturedAt });
    }
    second = await restart(first, DEFERRED_PORT, paths);
    // Past every staged assertion's exp plus the allowance and its capture's
    // maximum age (120 s), within the pending approvals' lifetime.
    controlledClock.advance(130_000);
    for (const s of staged) {
      expect(Date.now() / 1000).toBeGreaterThan(s.exp + SKEW_S);
      expect(Date.now() / 1000).toBeGreaterThan(s.capturedAt + 120);
    }
    // A fresh push sweeps lapsed pairs before it reserves; the committed records are kept.
    expectAccepted(await pushDeferred(second, [(await mintForReconciler(second)).entry]));
  }, RESTART_TIMEOUT_MS);

  it("activates after the restart and past the assertion's exp a deferred approval staged before it, relying on the push's acceptance record from the kernel's file: the push's verification time and facts, and no verification again", async () => {
    const [s] = staged as [(typeof staged)[number]];
    const before = verifications();
    const delivered = await poll(second, s.deferralCode, s.keys);
    expect(delivered.status, `${JSON.stringify(delivered.body)} ${second.as.missionApprovalDeferrals?.resolutionReason(s.deferralCode)}`).toBe(200);
    const mission = second.as.kernel.get(delivered.body.mission_id as string) as MissionRecord;
    expect(mission.submission_evidence).toEqual([
      { type: TYPE, artifact_hash: s.accepted.artifactHash, verified_at: s.accepted.verifiedAt, facts: s.accepted.facts },
    ]);
    expect(Date.parse(s.accepted.verifiedAt)).toBeLessThan(Date.now() - 129_000);
    // The activation verified nothing: the push before the restart did.
    expect(verifications()).toBe(before);
    // The record it relied on is the committed row in the kernel's file.
    expect(pairRows(second, s.jti)).toEqual([{ state: "committed", submission_ref: s.accepted.submissionRef }]);
  }, RESTART_TIMEOUT_MS);

  it("refuses after the restart a staged activation whose acceptance record is missing: access_denied, with no Mission", async () => {
    const s = staged[1] as (typeof staged)[number];
    second.as.kernel.db.prepare("DELETE FROM request_provenance_pairs WHERE iss = ? AND jti = ?").run(INTAKE, s.jti);
    const missions = second.as.kernel.allMissions().length;
    const r = await poll(second, s.deferralCode, s.keys);
    expect(r.status, JSON.stringify(r.body)).toBe(400);
    expect(r.body.error).toBe("access_denied");
    expect(second.as.kernel.allMissions().length).toBe(missions);
    expect(second.as.missionApprovalDeferrals?.resolutionReason(s.deferralCode)).toBe("invalid_mission_intent_evidence");
  }, RESTART_TIMEOUT_MS);

  it("refuses after the restart a staged activation whose stored acceptance record does not match its submission: access_denied, with no Mission", async () => {
    const s = staged[2] as (typeof staged)[number];
    const row = second.as.kernel.db
      .prepare("SELECT record_json FROM request_provenance_pairs WHERE iss = ? AND jti = ?")
      .get(INTAKE, s.jti) as { record_json: string };
    const record = JSON.parse(row.record_json) as RequestProvenanceRecord;
    second.as.kernel.db
      .prepare("UPDATE request_provenance_pairs SET record_json = ? WHERE iss = ? AND jti = ?")
      .run(JSON.stringify({ ...record, intentHash: "sha-256:another-intent" }), INTAKE, s.jti);
    const missions = second.as.kernel.allMissions().length;
    const r = await poll(second, s.deferralCode, s.keys);
    expect(r.status, JSON.stringify(r.body)).toBe(400);
    expect(r.body.error).toBe("access_denied");
    expect(second.as.kernel.allMissions().length).toBe(missions);
    expect(second.as.missionApprovalDeferrals?.resolutionReason(s.deferralCode)).toBe("invalid_mission_intent_evidence");
  }, RESTART_TIMEOUT_MS);
});

describe("concurrency on the durable store (@spec request-provenance#replay, #1963)", () => {
  afterEach(closeOpen);

  it("of two concurrent pushes presenting one assertion on a file-backed kernel, exactly one is accepted and the other is refused as replay, and the kernel's file holds one committed pair", async () => {
    const inst = await boot(CONCURRENT_PORT, await deployment(CONCURRENT_PORT));
    const store = storeOf(inst);
    // Hold both reservations until both pushes reach step 10, then let them reserve in one turn.
    const reserve = store.reserve.bind(store);
    const waiting: Array<() => void> = [];
    const gather = vi.spyOn(store, "reserve").mockImplementation(async (record: RequestProvenanceRecord, nowMs: number) => {
      await new Promise<void>((go) => {
        waiting.push(go);
        if (waiting.length === 2) for (const each of waiting) each();
        else setTimeout(go, 10_000).unref();
      });
      return reserve(record, nowMs);
    });
    try {
      const signed = await mintFor(inst);
      const results = await Promise.all([push(inst, [signed.entry]), push(inst, [signed.entry])]);
      expect(waiting).toHaveLength(2);
      expect(results.map((r) => r.status).sort()).toEqual([201, 400]);
      expectReplay(results.find((r) => r.status === 400) as Reply);
      const accepted = results.find((r) => r.status === 201) as Reply;
      expect(pairRows(inst, signed.jti)).toEqual([
        { state: "committed", submission_ref: `par:${(accepted.body.request_uri as string).slice(PUSHED_REQUEST_URN.length)}` },
      ]);
    } finally {
      gather.mockRestore();
      await shutdown(inst);
    }
  }, RESTART_TIMEOUT_MS);
});

describe("a failed settlement on the durable store (@spec request-provenance#replay, #1963, #2060 review)", () => {
  afterEach(closeOpen);

  it.each([0, 1])(
    "releases both assertions when the commit of the push's entry %i fails on a file-backed kernel: the push answers 500, neither pair stays committed or reserved, and after the fault is removed and the AS restarted each assertion is accepted",
    async (failing) => {
      const paths = await deployment(FAULT_PORT);
      const first = await boot(FAULT_PORT, paths);
      const signed = [await mintFor(first), await mintFor(first)];
      const target = signed[failing] as (typeof signed)[number];
      // A statement failure on that pair's commit only, injected in the database, not the source.
      first.as.kernel.db.exec(
        `CREATE TEMP TRIGGER fail_settlement BEFORE UPDATE OF state ON main.request_provenance_pairs
         WHEN NEW.state = 'committed' AND NEW.jti = '${target.jti}'
         BEGIN SELECT RAISE(ABORT, 'injected commit failure'); END`,
      );
      const refused = await push(first, signed.map((s) => s.entry));
      expect(refused.status).toBe(500);
      for (const s of signed) expect(pairRows(first, s.jti)).toEqual([]);
      first.as.kernel.db.exec("DROP TRIGGER temp.fail_settlement");

      const second = await restart(first, FAULT_PORT, paths);
      for (const s of signed) expectAccepted(await push(second, [s.entry]));
      for (const s of signed) expect(pairRows(second, s.jti).map((r) => r.state)).toEqual(["committed"]);
      await shutdown(second);
    },
    RESTART_TIMEOUT_MS,
  );
});

function rootDoc(): GovernedPolicyRoot {
  return {
    admits: { clients: [RECONCILER], subjects: [WORKLOAD], authority_sources: ["service_owned"] },
    authority_ceiling: [readEntry()] as never,
    lifetime: { max_lifetime_s: 3600 },
    rules: { max_entries: 3 },
    recency: { ceilings: { default: 30 * 86400 }, clock_skew_s: 60 },
    classification: { standard: READ },
  };
}
