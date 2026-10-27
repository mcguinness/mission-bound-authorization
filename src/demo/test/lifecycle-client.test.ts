/**
 * @spec status#lifecycle-operations, status#idempotency: the reference
 * Lifecycle client (src/lifecycle-client.ts) against a real reference AS.
 *
 * The client draws a fresh `nonce` for each new operation it requests on a
 * Mission and repeats it only to retransmit that request, from the request it
 * retained. It verifies each response by the consumer checks, with keys the
 * AS's `jwks_uri` publishes at verification time, and accepts a replay whose
 * `exp` has passed only as confirmation of its retained request's outcome,
 * when it correlates to that request and passes every other check. Every
 * request goes to the advertised `mission_lifecycle_endpoint` under the
 * console's own private-key-JWT credential. The AS runs on a key ring and a
 * kernel file, so it can be stopped, have its Status key compromised, and be
 * started again with its retained responses intact.
 */
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import type { Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  type BuiltAs,
  buildAuthorizationServer,
  compromiseSigningKeyGeneration,
  initSigningKeyRing,
  type MissionRecord,
  validateMissionIntent,
} from "@mission/authorization-server";
import { CANONICAL_RESOURCE, TOPOLOGY } from "@mission/demo-data";
import { decodeJwt, decodeProtectedHeader, importJWK, type JWK, SignJWT } from "jose";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import {
  type LifecycleConsoleCredentials,
  type LifecycleRequestRecord,
  newLifecycleConsole,
  newLifecycleRequest,
  transmitLifecycle,
  verifyLifecycleResponse,
} from "../src/lifecycle-client.js";

const PORT = 15411;
const ISSUER = `http://localhost:${PORT}`;
const ROLES = {
  asToken: TOPOLOGY.keys.asToken,
  asStatus: TOPOLOGY.keys.asStatus,
  asTxn: TOPOLOGY.keys.asTxn,
  asContinuation: TOPOLOGY.keys.asContinuation,
};

let dir: string;
let ring: string;
let kernelFile: string;
let as: BuiltAs | undefined;
let server: Server | undefined;
let registrations: Awaited<ReturnType<typeof newLifecycleConsole>>["registration"][];
/** The lifecycle console under test. */
let console1: LifecycleConsoleCredentials;
let approvals = 0;

/** Start the AS on the ring and the kernel file. */
async function start(): Promise<BuiltAs> {
  as = await buildAuthorizationServer({
    issuer: ISSUER,
    signingKeys: { ring },
    kernelStore: { file: kernelFile },
    lifecycleClients: registrations,
  });
  server = as.provider.listen(PORT);
  await new Promise<void>((r) => server?.once("listening", () => r()));
  return as;
}

/** Stop the AS, releasing its port and its kernel file. */
async function stop(): Promise<void> {
  if (server) await new Promise<void>((r) => server?.close(() => r()));
  as?.kernel.db.close();
  server = undefined;
  as = undefined;
}

function running(): BuiltAs {
  if (!as) throw new Error("the AS is not running");
  return as;
}

function approve(): MissionRecord {
  approvals += 1;
  return running().kernel.approve({
    intent: validateMissionIntent(
      JSON.stringify({ goal: "Read Acme invoices", target_resources: [CANONICAL_RESOURCE], expires_at: "2027-06-01T00:00:00Z" }),
    ),
    proposedAuthority: [{ type: "mission_resource_access", resource: CANONICAL_RESOURCE, actions: ["payments:invoice.read"] }],
    subject: { iss: ISSUER, sub: "alice" },
    approver: { iss: ISSUER, sub: "bob" },
    clientId: "ap-agent",
    approvalEventId: `apev-lifecycle-client-${approvals}`,
  });
}

const versionOf = (id: string): number => (running().kernel.get(id) as MissionRecord).version;

/** The form members of every Lifecycle request `spy` saw sent, client authentication removed. */
function sentForms(spy: { mock: { calls: unknown[][] } }): Record<string, string>[] {
  return spy.mock.calls
    .filter(([url, init]) => String(url).endsWith("/mission/lifecycle") && (init as RequestInit | undefined)?.method === "POST")
    .map(([, init]) => {
      const form = Object.fromEntries(new URLSearchParams(String((init as RequestInit).body)));
      delete form.client_assertion;
      delete form.client_assertion_type;
      return form;
    });
}

beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), "lifecycle-client-"));
  ring = join(dir, "keys", "as-signing-keys.json");
  kernelFile = join(dir, "kernel.db");
  await initSigningKeyRing(ring, ISSUER, ROLES);
  const first = await newLifecycleConsole("lifecycle-console-1");
  console1 = first.credentials;
  registrations = [first.registration];
  await start();
});

afterAll(async () => {
  await stop();
  rmSync(dir, { recursive: true, force: true });
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("the reference Lifecycle client's nonces (@spec status#lifecycle-operations, status#idempotency)", () => {
  it("draws a fresh nonce for each new operation on a Mission and repeats it only to retransmit that request, so the AS replays the original response with no second transition", async () => {
    const m = approve();
    const fetches = vi.spyOn(globalThis, "fetch");
    const suspend: LifecycleRequestRecord = newLifecycleRequest(m.id, { operation: "suspend" });
    const first = await transmitLifecycle(ISSUER, console1, suspend);
    expect(first.status, first.text).toBe(200);
    // A second new operation on the same Mission: a reused nonce with other
    // members would be refused invalid_request, never performed.
    const resume = newLifecycleRequest(m.id, { operation: "resume" });
    expect(resume.nonce).not.toBe(suspend.nonce);
    const second = await transmitLifecycle(ISSUER, console1, resume);
    expect(second.status, second.text).toBe(200);
    const resumed = versionOf(m.id);
    expect(running().kernel.get(m.id)?.state).toBe("active");
    // The retransmit of the first request: its members and nonce, so the AS
    // replays the original suspend and does not suspend the resumed Mission.
    const retransmit = await transmitLifecycle(ISSUER, console1, suspend);
    expect(retransmit.status).toBe(200);
    expect(retransmit.text).toBe(first.text);
    expect(versionOf(m.id)).toBe(resumed);
    expect(running().kernel.get(m.id)?.state).toBe("active");
    const [sentFirst, sentSecond, sentRetransmit] = sentForms(fetches);
    expect(sentFirst).toEqual({ operation: "suspend", mission_id: m.id, nonce: suspend.nonce });
    expect(sentSecond).toEqual({ operation: "resume", mission_id: m.id, nonce: resume.nonce });
    expect(sentRetransmit).toEqual(sentFirst);
    // Unique among the console's nonces for the Mission, however many it draws.
    const drawn = new Set(Array.from({ length: 1000 }, () => newLifecycleRequest(m.id, { operation: "revoke" }).nonce));
    expect(drawn.size).toBe(1000);
  });
});

/** The verification context for a retained request: the configured issuer, the console, and the Status kid it trusts. */
const verifying = (request: LifecycleRequestRecord, extra: { now?: () => Date; trustedKids?: string[] } = {}) => ({
  issuer: ISSUER,
  client: console1,
  request,
  trustedKids: [ROLES.asStatus.kid],
  ...extra,
});

/** An instant two minutes past a response's `exp`, well beyond the profile's 30 second skew. */
const afterExpiry = (jws: string) => () => new Date(((decodeJwt(jws).exp as number) + 120) * 1000);

/** A new suspend on a fresh Mission, transmitted: the retained request and the AS's signed answer. */
async function suspended(): Promise<{ m: MissionRecord; request: LifecycleRequestRecord; jws: string }> {
  const m = approve();
  const request = newLifecycleRequest(m.id, { operation: "suspend" });
  const answer = await transmitLifecycle(ISSUER, console1, request);
  expect(answer.status, answer.text).toBe(200);
  return { m, request, jws: answer.text };
}

describe("the reference Lifecycle client's verification of an expired replay (@spec status#idempotency, status#mission-status-response)", () => {
  it("accepts the AS's replay of its retained request, verified after its exp, only as confirmation of that request's outcome, which carries no Mission state", async () => {
    const { m, request, jws } = await suspended();
    expect(await verifyLifecycleResponse(jws, verifying(request))).toMatchObject({
      kind: "observation",
      mission: { id: m.id, state: "suspended" },
    });
    const replay = await transmitLifecycle(ISSUER, console1, request);
    expect(replay.text).toBe(jws);
    // Exactly the confirmation: no payload, no Mission object, nothing to cache or rely on.
    expect(await verifyLifecycleResponse(replay.text, verifying(request, { now: afterExpiry(jws) }))).toEqual({
      kind: "confirmation",
      missionId: m.id,
      nonce: request.nonce,
      outcome: { state: "suspended", version: m.version + 1 },
    });
  });

  it("refuses an expired replay that does not correlate to the retained request: another request's nonce, or another Mission", async () => {
    const { m, request, jws } = await suspended();
    const late = afterExpiry(jws);
    const another = newLifecycleRequest(m.id, { operation: "suspend" });
    expect(await verifyLifecycleResponse(jws, verifying(another, { now: late }))).toEqual({ kind: "refused", reason: "nonce" });
    const elsewhere: LifecycleRequestRecord = { missionId: approve().id, members: request.members, nonce: request.nonce };
    expect(await verifyLifecycleResponse(jws, verifying(elsewhere, { now: late }))).toEqual({
      kind: "refused",
      reason: "signature or claims",
    });
  });

  it("refuses an expired replay that fails any other check: an audience or a sub naming another client, or a kid its configuration does not trust", async () => {
    const { request, jws } = await suspended();
    const late = afterExpiry(jws);
    // Variants of the AS's own answer, signed under the AS's Status key, each failing one check.
    const ringFile = JSON.parse(readFileSync(ring, "utf8")) as {
      roles: { asStatus: { generations: Array<{ kid: string; private_jwk: JWK }> } };
    };
    const generation = ringFile.roles.asStatus.generations.find((g) => g.kid === ROLES.asStatus.kid);
    const statusKey = await importJWK(generation?.private_jwk as JWK, ROLES.asStatus.alg);
    const variant = (edit: Record<string, unknown>) =>
      new SignJWT({ ...decodeJwt(jws), ...edit })
        .setProtectedHeader({ alg: ROLES.asStatus.alg, kid: ROLES.asStatus.kid, typ: "mission-status-response+jwt" })
        .sign(statusKey);
    // The unedited re-signature is accepted: each refusal below is its one edit's.
    expect(await verifyLifecycleResponse(await variant({}), verifying(request, { now: late }))).toMatchObject({ kind: "confirmation" });
    expect(await verifyLifecycleResponse(await variant({ aud: "another-console" }), verifying(request, { now: late }))).toEqual({
      kind: "refused",
      reason: "signature or claims",
    });
    expect(await verifyLifecycleResponse(await variant({ sub: "another-console" }), verifying(request, { now: late }))).toEqual({
      kind: "refused",
      reason: "sub",
    });
    expect(
      await verifyLifecycleResponse(jws, verifying(request, { now: late, trustedKids: ["as-status-of-another-role"] })),
    ).toEqual({ kind: "refused", reason: "signature or claims" });
  });

  // Last: it compromises the AS's Status key.
  it("refuses the AS's replay of its retained request once the Status key that signed it is compromised, before and after its exp", async () => {
    const { m, request, jws } = await suspended();
    expect(decodeProtectedHeader(jws).kid).toBe(ROLES.asStatus.kid);
    expect(await verifyLifecycleResponse(jws, verifying(request))).toMatchObject({ kind: "observation" });
    await stop();
    const { replacement } = await compromiseSigningKeyGeneration(ring, ISSUER, ROLES, "asStatus", ROLES.asStatus.kid);
    await start();
    // The AS replays the original response unchanged, signed under the withdrawn key.
    const replay = await transmitLifecycle(ISSUER, console1, request);
    expect(replay.status).toBe(200);
    expect(replay.text).toBe(jws);
    // Trusted by configuration, but no longer published at the jwks_uri: refused, never even a confirmation.
    const trustedKids = [ROLES.asStatus.kid, replacement as string];
    const refused = { kind: "refused", reason: "signature or claims" };
    expect(await verifyLifecycleResponse(replay.text, verifying(request, { trustedKids }))).toEqual(refused);
    expect(await verifyLifecycleResponse(replay.text, verifying(request, { trustedKids, now: afterExpiry(jws) }))).toEqual(refused);
    // A new operation is signed under the replacement, which verifies.
    const resume = newLifecycleRequest(m.id, { operation: "resume" });
    const resumed = await transmitLifecycle(ISSUER, console1, resume);
    expect(decodeProtectedHeader(resumed.text).kid).toBe(replacement);
    expect(await verifyLifecycleResponse(resumed.text, verifying(resume, { trustedKids }))).toMatchObject({
      kind: "observation",
      mission: { id: m.id, state: "active" },
    });
  });
});
