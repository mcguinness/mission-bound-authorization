/**
 * @spec control-plane#serialization, control-plane#fresh-observation — THE
 * LIFECYCLE RESPONSE SIGNING BOUNDARY.
 *
 * Response recording used to happen only after the response bytes existed, and
 * for `discharge` that meant after an awaited signature. A synchronous
 * `withTransaction` cannot span an asynchronous signing handler, so the fix is
 * a boundary rather than a bigger transaction: the nonce claim, the committed
 * operation outcome and enough immutable response material commit WITH the
 * transition, and the exact bytes are finalized (and, after a loss, recovered)
 * outside it.
 *
 * Covered here:
 *  - the crash after the transition and before signing: the retry replays the
 *    committed outcome instead of re-executing and conflicting;
 *  - the crash after signing and before response retention: the retained
 *    observation is signed again with its ORIGINAL `iat`/`exp`, so recovery
 *    reports the state at the observation point and re-dates nothing;
 *  - the crash before network delivery: retention precedes delivery, so the
 *    exact bytes are already replayable;
 *  - replay lookup runs BEFORE any state-dependent check, so a request that
 *    already succeeded still replays its success after the Mission moves on;
 *  - a retained signed envelope past its own validity is never replayed.
 */

import type { Server } from "node:http";
import { CANONICAL_RESOURCE, DERIVATION_POLICY, DEV_SERVICE_TOKEN } from "@mission/demo-data";
import { type CryptoKey, decodeJwt, generateKeyPair } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  type AuthorityEntry,
  type BuiltAs,
  buildAuthorizationServer,
  LIFECYCLE_ENDPOINT_KEY,
  LifecycleResponseStore,
  MissionKernel,
  type MissionRecord,
  validateMissionIntent,
} from "../src/index.js";
import { testAuthoritySourceCatalog } from "./authority-source.helper.js";

const PORT = 14561;
const ISSUER = `http://localhost:${PORT}`;
const EXPIRES_AT = "2027-01-01T00:00:00Z";

let as: BuiltAs;
let server: Server;
let approvals = 0;
let nonces = 0;
const freshNonce = (): string => `nonce-cpr-${(nonces += 1)}`;

const proposal = (): AuthorityEntry[] => [
  { type: "mission_resource_access", resource: CANONICAL_RESOURCE, actions: ["payments:invoice.read"] },
];

function approveOnAs(): MissionRecord {
  approvals += 1;
  return as.kernel.approve({
    intent: validateMissionIntent(
      JSON.stringify({
        goal: "Read invoices for the close",
        target_resources: [CANONICAL_RESOURCE],
        expires_at: EXPIRES_AT,
      }),
    ),
    proposedAuthority: proposal(),
    subject: { iss: ISSUER, sub: "alice" },
    approver: { iss: ISSUER, sub: "bob" },
    clientId: "ap-agent",
    approvalEventId: `apev-cpr-${approvals}`,
  });
}

const lifecycle = (missionId: string, body: unknown): Promise<Response> =>
  fetch(`${ISSUER}/missions/${missionId}/lifecycle`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-service-token": DEV_SERVICE_TOKEN },
    body: JSON.stringify(body),
  });

/** The retained row for one exchange, straight out of the kernel database. */
const retained = (missionId: string, nonce: string): Record<string, unknown> | undefined =>
  as.kernel.db
    .prepare(
      `SELECT * FROM lifecycle_responses
       WHERE endpoint = ? AND principal = ? AND mission_id = ? AND nonce = ?`,
    )
    .get(LIFECYCLE_ENDPOINT_KEY, "svc:console", missionId, nonce) as
    | Record<string, unknown>
    | undefined;

/**
 * The state a crash between the transition transaction and the response leaves
 * behind: the claim and the committed outcome are durable, the bytes are not.
 */
const loseTheResponseBytes = (missionId: string, nonce: string): void => {
  as.kernel.db
    .prepare(
      `UPDATE lifecycle_responses SET state = 'committed', body = ''
       WHERE endpoint = ? AND principal = ? AND mission_id = ? AND nonce = ?`,
    )
    .run(LIFECYCLE_ENDPOINT_KEY, "svc:console", missionId, nonce);
};

describe("control-plane lifecycle response boundary", () => {
  beforeAll(async () => {
    as = await buildAuthorizationServer({ issuer: ISSUER, allowHeadlessAdjudication: true });
    server = as.provider.listen(PORT);
  });
  afterAll(() => {
    server?.close();
  });

  it("retains the exact response before delivering it", async () => {
    const record = approveOnAs();
    const nonce = freshNonce();
    const res = await lifecycle(record.id, { operation: "suspend", nonce });
    expect(res.status).toBe(200);
    const delivered = await res.text();
    const row = retained(record.id, nonce);
    // The bytes the client received are the bytes already retained, so a loss
    // between retention and delivery replays rather than re-executes.
    expect(row?.state).toBe("final");
    expect(row?.body).toBe(delivered);
    expect(JSON.parse(delivered)).toEqual({
      id: record.id,
      state: "suspended",
      version: record.version + 1,
    });
  });

  it("replays a committed resume after the response was lost, instead of conflicting", async () => {
    const record = approveOnAs();
    expect((await lifecycle(record.id, { operation: "suspend", nonce: freshNonce() })).status).toBe(200);
    const nonce = freshNonce();
    const first = await lifecycle(record.id, { operation: "resume", nonce });
    expect(first.status).toBe(200);
    const original = await first.text();
    expect(as.kernel.get(record.id)?.state).toBe("active");
    const version = as.kernel.get(record.id)?.version;

    // Crash after the transition committed and before the response was signed
    // or retained. The claim and the outcome survived; the bytes did not.
    // `resume` is the sharp case: it is legal only from `suspended`, so
    // re-executing it would refuse an operation that in fact succeeded.
    loseTheResponseBytes(record.id, nonce);
    expect(retained(record.id, nonce)?.state).toBe("committed");

    const retry = await lifecycle(record.id, { operation: "resume", nonce });
    expect(retry.status).toBe(200);
    expect(await retry.text()).toBe(original);
    // Recovery finalized the row from its retained material rather than
    // re-executing the operation, so the version did not move again.
    expect(retained(record.id, nonce)?.state).toBe("final");
    expect(as.kernel.get(record.id)?.version).toBe(version);
  });

  it("conflicts on the same retry when no claim was retained, which is what the claim fixes", async () => {
    const record = approveOnAs();
    expect((await lifecycle(record.id, { operation: "suspend", nonce: freshNonce() })).status).toBe(200);
    const nonce = freshNonce();
    expect((await lifecycle(record.id, { operation: "resume", nonce })).status).toBe(200);
    // Delete the whole row: the pre-fix behavior, where a lost process left no
    // record of a committed operation at all.
    as.kernel.db
      .prepare(
        `DELETE FROM lifecycle_responses
         WHERE endpoint = ? AND principal = ? AND mission_id = ? AND nonce = ?`,
      )
      .run(LIFECYCLE_ENDPOINT_KEY, "svc:console", record.id, nonce);
    const retry = await lifecycle(record.id, { operation: "resume", nonce });
    expect(retry.status).toBe(409);
    expect(await retry.json()).toMatchObject({ error: "conflict" });
  });

  it("replays a successful request before any state-dependent check, after the state moved on", async () => {
    const record = approveOnAs();
    const nonce = freshNonce();
    const first = await lifecycle(record.id, { operation: "suspend", nonce });
    expect(first.status).toBe(200);
    const original = await first.text();
    // The Mission then moves to a terminal state, from which `suspend` is
    // illegal and re-execution would refuse.
    expect((await lifecycle(record.id, { operation: "revoke", nonce: freshNonce() })).status).toBe(200);
    expect(as.kernel.get(record.id)?.state).toBe("revoked");
    const replay = await lifecycle(record.id, { operation: "suspend", nonce });
    expect(replay.status).toBe(200);
    expect(await replay.text()).toBe(original);
  });

  it("claims the containment outcome with the narrowing commit", async () => {
    const record = approveOnAs();
    const nonce = freshNonce();
    const body = {
      operation: "contain",
      nonce,
      event: {
        type: "credential-compromise",
        source: "svc:console",
        observed_at: new Date().toISOString(),
        event_id: `cpr-contain-${record.id.slice(-6)}`,
      },
      remove: [{ resource: CANONICAL_RESOURCE }],
    };
    const res = await lifecycle(record.id, body);
    expect(res.status).toBe(200);
    const original = await res.text();
    expect(JSON.parse(original)).toMatchObject({ state: "active", containment_version: 1 });
    loseTheResponseBytes(record.id, nonce);
    const retry = await lifecycle(record.id, body);
    expect(retry.status).toBe(200);
    expect(await retry.text()).toBe(original);
    // One narrowing, not two.
    expect(as.kernel.get(record.id)?.containment?.containment_version).toBe(1);
  });
});

/**
 * The signed half of the boundary, on a kernel with a controllable clock: a
 * recovered signed response and a retained response past its own validity.
 */
describe("control-plane retained signed responses", () => {
  let statusKey: CryptoKey;
  beforeAll(async () => {
    statusKey = (await generateKeyPair("ES256")).privateKey;
  });

  const setup = () => {
    const issuer = "https://issuer-responses.test";
    const clock = { at: new Date("2026-09-01T00:00:00Z") };
    const kernel = new MissionKernel({
      issuer,
      policy: DERIVATION_POLICY as never,
      authoritySourceCatalog: testAuthoritySourceCatalog(
        DERIVATION_POLICY.ceiling,
        ["agent"],
        ["bob"],
      ),
      statusKey,
      statusKid: "status",
      now: () => clock.at,
    });
    const record = kernel.approve({
      intent: validateMissionIntent(
        JSON.stringify({
          goal: "Read an invoice",
          target_resources: [DERIVATION_POLICY.ceiling[0].resource],
          expires_at: EXPIRES_AT,
        }),
      ),
      subject: { iss: issuer, sub: "alice" },
      approver: { iss: issuer, sub: "bob" },
      clientId: "agent",
      approvalEventId: "approval-responses",
    });
    const store = new LifecycleResponseStore(kernel.db, { now: () => clock.at });
    const key = {
      endpoint: LIFECYCLE_ENDPOINT_KEY,
      principal: "svc:close",
      missionId: record.id,
      nonce: "nonce-signed",
    };
    return { kernel, record, clock, store, key };
  };

  it("signs a recovered response over the original observation, never re-dating it", async () => {
    const { kernel, record, clock, store, key } = setup();
    try {
      const observed = kernel.statusObservation(record.id, { requester: "svc:close", nonce: key.nonce });
      store.claimInCallerTx(key, {
        requestDigest: "sha-256:req",
        status: 200,
        contentType: "application/mission-status-response+jwt",
        material: { kind: "status-observation", observation: observed as unknown as Record<string, unknown> },
        responseValidUntil: observed.exp * 1000,
      });
      // The signature and the retention were both lost; the claim survived.
      const stored = store.find(key);
      expect(stored?.state).toBe("committed");
      // State moves on, and the clock advances, before the retry arrives.
      kernel.transition(record.id, "suspend");
      clock.at = new Date(clock.at.getTime() + 20_000);
      const material = stored?.material;
      if (material?.kind !== "status-observation") throw new Error("expected an observation");
      const recovered = decodeJwt(
        await kernel.signObservation(material.observation as unknown as never),
      );
      expect(recovered.iat).toBe(observed.iat);
      expect(recovered.exp).toBe(observed.exp);
      expect(recovered.mission).toMatchObject({ state: "active", version: record.version });
      expect(recovered.nonce).toBe(key.nonce);
    } finally {
      kernel.db.close();
    }
  });

  it("stops replaying a retained signed response once it passes its own validity", async () => {
    const { kernel, record, clock, store, key } = setup();
    try {
      const observed = kernel.statusObservation(record.id, { requester: "svc:close", nonce: key.nonce });
      const jws = await kernel.signObservation(observed);
      store.claimInCallerTx(key, {
        requestDigest: "sha-256:req",
        status: 200,
        contentType: "application/mission-status-response+jwt",
        material: { kind: "status-observation", observation: observed as unknown as Record<string, unknown> },
        responseValidUntil: observed.exp * 1000,
      });
      store.record(key, {
        requestDigest: "sha-256:req",
        status: 200,
        contentType: "application/mission-status-response+jwt",
        body: jws,
      });
      // Inside its own validity the retained envelope replays verbatim.
      expect(store.find(key)?.body).toBe(jws);
      // Past it, the retained envelope is gone: an expired observation is
      // never handed back as though it were current, and the store retention
      // window (ten minutes) is deliberately longer than the envelope's own
      // validity, so this clock is the one that decides.
      clock.at = new Date((observed.exp + 1) * 1000);
      expect(store.find(key)).toBeUndefined();
    } finally {
      kernel.db.close();
    }
  });

  it("keeps a plain JSON outcome replayable for the whole nonce window", () => {
    const { kernel, clock, store, key } = setup();
    try {
      // A JSON outcome asserts no freshness, so no second clock applies: it
      // stays replayable for the nonce retention window.
      store.claimInCallerTx(key, {
        requestDigest: "sha-256:req",
        status: 200,
        contentType: "application/json",
        material: { kind: "json", body: { id: key.missionId, state: "revoked", version: 2 } },
      });
      store.record(key, {
        requestDigest: "sha-256:req",
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ id: key.missionId, state: "revoked", version: 2 }),
      });
      clock.at = new Date(clock.at.getTime() + 120_000);
      expect(store.find(key)?.state).toBe("final");
      clock.at = new Date(clock.at.getTime() + 600_001);
      expect(store.find(key)).toBeUndefined();
    } finally {
      kernel.db.close();
    }
  });
});
