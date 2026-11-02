/**
 * @spec request-provenance#replay, request-provenance#recorded-facts,
 * deferred-approval#deferred-sequencing (#939 slice 2a-2, D1119 Q1 and Q2)
 *
 * A deferred activation as a later step of an accepted push of
 * `mission-request-provenance` evidence, on a controlled clock. The agent
 * `ledger-reconciler` pushes a deferred submission carrying an assertion
 * minted live by `@mission/request-provenance`; the pending-request code
 * carries the push's reference (`par:<jti>`) into the pending approval, and
 * the `governed_policy` activation, well after the assertion's `exp` and the
 * capture's maximum age, relies on the push's acceptance record instead of
 * verifying again. A pending approval that names no accepted submission, or
 * another one, is refused.
 */

const controlledClock = await vi.hoisted(async () => {
  const { CONTROLLED_CLOCK_MS, installControlledClock } = await import("./controlled-clock.helper.js");
  return installControlledClock(CONTROLLED_CLOCK_MS);
});

vi.mock("../src/kernel/request-provenance.js", async (importOriginal) => {
  const original = await importOriginal<typeof import("../src/kernel/request-provenance.js")>();
  return { ...original, verifyRequestProvenance: vi.fn(original.verifyRequestProvenance) };
});

import { type Server } from "node:http";
import { DERIVATION_POLICY, parseRequestProvenanceConfig } from "@mission/demo-data";
import { createRequestIntake, type JsonObject } from "@mission/request-provenance";
import { calculateJwkThumbprint, exportJWK, generateKeyPair, importJWK, type JWK, SignJWT } from "jose";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import {
  ALL_PROVIDER_CAPABILITIES,
  buildAuthorizationServer,
  type BuiltAs,
  DEFERRED_GRANT_TYPE,
  type GovernedPolicyRoot,
  InMemoryRequestProvenanceStore,
  type MissionRecord,
  type RegisteredActivationPolicy,
  recordGovernedPolicyConsent,
} from "../src/index.js";
import { verifyRequestProvenance } from "../src/kernel/request-provenance.js";
import { TEST_APPROVAL_PRINCIPALS } from "./approval-fixture.js";
import { FIXTURE_EXPIRES_AT } from "./relative-expiry.helper.js";

const TYPE = "mission-request-provenance";
const PORT = 14910;
const ISSUER = `http://localhost:${PORT}`;
const REDIRECT_URI = "http://localhost:9999/cb";
const RESOURCE = DERIVATION_POLICY.ceiling[0].resource as string;
const AGENT = "ledger-reconciler";
const WORKLOAD = "agt_ledger_reconciler";
const VERIFIER = "request-provenance-deferred-verifier-0123456789-0123456";
const READ = ["payments:invoice.list", "payments:invoice.read", "payments:vendor.read"];
const INTAKE = "https://intake.example.org";
const KID = "intake-1";
const IDP = "https://idp.example.org";
const CHANNEL = "https://intake.example.org/ch/service";
const INTENT = { goal: "Reconcile Acme invoices against the ledger", target_resources: [RESOURCE], expires_at: FIXTURE_EXPIRES_AT };

const intakeKeys = await generateKeyPair("ES256", { extractable: true });
const store = new InMemoryRequestProvenanceStore();
const TRUST = parseRequestProvenanceConfig({
  enabled: true,
  clock_skew_seconds: 5,
  max_assertion_lifetime_seconds: 30,
  max_capture_age_seconds: 30,
  signers: [
    {
      iss: INTAKE,
      keys: [{ kid: KID, public_jwk: (await exportJWK(intakeKeys.publicKey)) as never, evidence_types: [TYPE], algs: ["ES256"] }],
      originators: [{ iss: IDP }],
      channel_types: [CHANNEL],
    },
  ],
});

const readEntry = (actions: string[] = READ) => ({
  type: "mission_resource_access",
  resource: RESOURCE,
  actions,
  constraints: { vendors: ["acme"] },
});

const rootDoc = (): GovernedPolicyRoot => ({
  admits: { clients: [AGENT], subjects: [WORKLOAD], authority_sources: ["service_owned"] },
  authority_ceiling: [readEntry()] as never,
  lifetime: { max_lifetime_s: 3600 },
  rules: { max_entries: 3 },
  recency: { ceilings: { default: 30 * 86400 }, clock_skew_s: 60 },
  classification: { standard: READ },
});

const governance: { roots: Record<string, RegisteredActivationPolicy>; approvers: Record<string, string[]> } = {
  roots: {},
  approvers: {},
};

let as: BuiltAs;
let server: Server;
let agentKey: CryptoKey;

beforeAll(async () => {
  as = await buildAuthorizationServer({
    issuer: ISSUER,
    allowHeadlessAdjudication: true,
    serviceTokenPrincipals: { ...TEST_APPROVAL_PRINCIPALS },
    capabilities: new Set([...ALL_PROVIDER_CAPABILITIES, "deferred-approval"]),
    governedPolicyApproval: governance,
    activationPolicies: {},
    deferredApproval: { pendingLifetimeS: 600 },
    requestProvenance: { config: TRUST, store },
  });
  server = as.provider.listen(PORT);
  agentKey = (await importJWK(as.ledgerReconcilerClientJwk as never, "ES256")) as CryptoKey;
  const id = "urn:root:request-provenance-deferred";
  governance.roots[id] = { version: "1", content_type: "application/json", content: JSON.stringify(rootDoc()) };
  governance.approvers[id] = ["dana"];
  recordGovernedPolicyConsent(as.kernel, {
    root: { id, version: "1" },
    approver: { iss: ISSUER, sub: "dana" },
    consentEventId: `gpce-${id}`,
  });
});

afterAll(() => {
  server?.close();
  controlledClock.restore();
});

const verifications = () => vi.mocked(verifyRequestProvenance).mock.calls.length;

/** An assertion for the agent's submission: iat 10 s ago, exp 10 s ahead, captured 30 s ago. */
async function mint() {
  let offsetMs = -30_000;
  const intake = createRequestIntake({
    issuer: INTAKE,
    kid: KID,
    signingKey: intakeKeys.privateKey,
    assertionLifetimeSeconds: 20,
    maxCaptureAgeSeconds: 3600,
    now: () => Date.now() + offsetMs,
  });
  const receipt = intake.capture({
    workflow: "wf-deferred",
    instruction: Buffer.from("Reconcile the Acme invoices against the ledger.", "utf8"),
    mediaType: "text/plain;charset=utf-8",
    originator: { iss: IDP, sub: "ops-scheduler" },
    channel: { type: CHANNEL },
    presenter: { client_id: AGENT },
  });
  offsetMs = -10_000;
  return intake.sign({ captureId: receipt.captureId, workflow: "wf-deferred", audience: ISSUER, intent: INTENT as unknown as JsonObject });
}

const clientAuth = async () => ({
  client_assertion: await new SignJWT({})
    .setProtectedHeader({ alg: "ES256", kid: `${AGENT}-auth` })
    .setIssuer(AGENT)
    .setSubject(AGENT)
    .setAudience(ISSUER)
    .setIssuedAt()
    .setExpirationTime("2m")
    .setJti(crypto.randomUUID())
    .sign(agentKey),
  client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
});

type Keys = { privateKey: CryptoKey; jwk: JWK; jkt: string };
const newKeys = async (): Promise<Keys> => {
  const pair = await generateKeyPair("ES256", { extractable: true });
  const jwk = await exportJWK(pair.publicKey);
  return { privateKey: pair.privateKey as CryptoKey, jwk, jkt: await calculateJwkThumbprint(jwk) };
};

async function tokenRequest(params: Record<string, string>, keys: Keys): Promise<{ status: number; body: Record<string, unknown> }> {
  const htu = `${ISSUER}/token`;
  const dpop = await new SignJWT({ htu, htm: "POST" })
    .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: keys.jwk })
    .setIssuedAt()
    .setJti(crypto.randomUUID())
    .sign(keys.privateKey);
  const res = await fetch(htu, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", dpop },
    body: new URLSearchParams({ ...params, ...(await clientAuth()) }).toString(),
  });
  return { status: res.status, body: (await res.json()) as Record<string, unknown> };
}

/** The agent's deferred push of `evidence`, redeemed into a pending approval: its deferral code and the push's jti. */
async function openDeferral(keys: Keys, evidence: unknown[]): Promise<{ deferralCode: string; pushedJti: string }> {
  const challenge = Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(VERIFIER))).toString("base64url");
  const par = await fetch(`${ISSUER}/request`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: AGENT,
      response_type: "code",
      redirect_uri: REDIRECT_URI,
      code_challenge: challenge,
      code_challenge_method: "S256",
      mission_intent: JSON.stringify({ intent: INTENT, evidence }),
      authorization_details: JSON.stringify([readEntry(["payments:invoice.read"])]),
      completion_mode: "deferred",
      ...(await clientAuth()),
    }).toString(),
  });
  expect(par.status, await par.clone().text()).toBe(201);
  const { request_uri } = (await par.json()) as { request_uri: string };
  const jar = new Map<string, string>();
  const keep = (res: Response) => {
    for (const line of res.headers.getSetCookie()) {
      const [pair] = line.split(";");
      const eq = (pair as string).indexOf("=");
      jar.set((pair as string).slice(0, eq), (pair as string).slice(eq + 1));
    }
  };
  const cookie = () => [...jar].map(([k, v]) => `${k}=${v}`).join("; ");
  let res = await fetch(`${ISSUER}/auth?${new URLSearchParams({ client_id: AGENT, request_uri })}`, { redirect: "manual" });
  keep(res);
  let location = res.headers.get("location") ?? "";
  while (location.startsWith(ISSUER) || location.startsWith("/")) {
    res = await fetch(new URL(location, ISSUER), { redirect: "manual", headers: { cookie: cookie() } });
    keep(res);
    location = res.headers.get("location") ?? "";
  }
  const code = location.startsWith(REDIRECT_URI) ? new URL(location).searchParams.get("code") : null;
  expect(code, location).toBeTruthy();
  const r = await tokenRequest(
    { grant_type: "authorization_code", code: code as string, redirect_uri: REDIRECT_URI, code_verifier: VERIFIER, completion_mode: "deferred" },
    keys,
  );
  expect(r.status, JSON.stringify(r.body)).toBe(400);
  expect(r.body.error).toBe("authorization_pending");
  return { deferralCode: r.body.deferral_code as string, pushedJti: request_uri.split(":").pop() as string };
}

const poll = (deferralCode: string, keys: Keys) => tokenRequest({ grant_type: DEFERRED_GRANT_TYPE, deferral_code: deferralCode }, keys);
const setAcceptanceRef = (deferralCode: string, ref: string | null) =>
  as.kernel.db.prepare("UPDATE mission_approval_deferrals SET acceptance_ref = ? WHERE deferral_code = ?").run(ref, deferralCode);

describe("deferred activation of an accepted push (@spec request-provenance#replay, deferred-approval#deferred-sequencing, #939 slice 2a-2)", () => {
  it("activates after exp and the capture age pass, verifying nothing again and recording the push's verification time and facts", async () => {
    const keys = await newKeys();
    const signed = await mint();
    const before = verifications();
    const { deferralCode, pushedJti } = await openDeferral(keys, [signed.entry]);
    const accepted = store.accepted(INTAKE, signed.jti, Date.now());
    expect(accepted?.submissionRef).toBe(`par:${pushedJti}`);
    const row = as.kernel.db.prepare("SELECT acceptance_ref FROM mission_approval_deferrals WHERE deferral_code = ?").get(deferralCode) as {
      acceptance_ref: string | null;
    };
    expect(row.acceptance_ref).toBe(`par:${pushedJti}`);
    // Two minutes on: past exp plus the allowance and the capture's maximum age.
    controlledClock.advance(120_000);
    expect(Date.now() / 1000).toBeGreaterThan(signed.exp + 5);
    const delivered = await poll(deferralCode, keys);
    expect(delivered.status, JSON.stringify(delivered.body)).toBe(200);
    const mission = as.kernel.get(delivered.body.mission_id as string) as MissionRecord;
    expect(mission.submission_evidence).toEqual([
      { type: TYPE, artifact_hash: accepted?.artifactHash, verified_at: accepted?.verifiedAt, facts: accepted?.facts },
    ]);
    expect(Date.parse(accepted?.verifiedAt as string)).toBeLessThan(Date.now() - 119_000);
    // The push verified once; the authorization endpoint and the activation verified nothing.
    expect(verifications()).toBe(before + 1);
  });

  it("refuses the activation when the pending approval names no accepted submission: access_denied, with no Mission", async () => {
    const keys = await newKeys();
    const { deferralCode } = await openDeferral(keys, [(await mint()).entry]);
    setAcceptanceRef(deferralCode, null);
    const missions = as.kernel.allMissions().length;
    const r = await poll(deferralCode, keys);
    expect(r.status, JSON.stringify(r.body)).toBe(400);
    expect(r.body.error).toBe("access_denied");
    expect(as.kernel.allMissions().length).toBe(missions);
    expect(as.missionApprovalDeferrals?.resolutionReason(deferralCode)).toBe("invalid_mission_intent_evidence");
  });

  it("refuses the activation when the pending approval names another submission than the one accepted: access_denied, with no Mission", async () => {
    const keys = await newKeys();
    const { deferralCode } = await openDeferral(keys, [(await mint()).entry]);
    setAcceptanceRef(deferralCode, "par:a-pushed-request-that-accepted-nothing");
    const missions = as.kernel.allMissions().length;
    const r = await poll(deferralCode, keys);
    expect(r.status, JSON.stringify(r.body)).toBe(400);
    expect(r.body.error).toBe("access_denied");
    expect(as.kernel.allMissions().length).toBe(missions);
    expect(as.missionApprovalDeferrals?.resolutionReason(deferralCode)).toBe("invalid_mission_intent_evidence");
  });
});
