/**
 * @spec draft-mcguinness-oauth-mission-signals
 *
 * In-process, deterministic (no HTTP, no OpenFGA): a real MissionKernel fires
 * its lifecycle-commit hook into a MissionSignalEmitter, which signs a SET per
 * consumer audience and hands it to a MissionSignalReceiver. The consumer's
 * `loadView` builds the PDP MissionView FROM THE RECEIVER CACHE ALONE (state and
 * version come from the pushed signal, never from `kernel.get()`), so a passing
 * decision proves the signal drove it. A stub Fga keeps the PDP path
 * OpenFGA-free.
 */

import {
  type AuthorityEntry,
  type LifecycleCommit,
  MissionKernel,
} from "@mission/authorization-server";
import { type EvaluationRequest, evaluate, type Fga, type MissionView } from "@mission/pdp";
import { exportJWK, generateKeyPair } from "jose";
import { describe, expect, it } from "vitest";
import { MissionSignalEmitter, MissionSignalReceiver, signLifecycleEvent } from "../src/index.js";

const ISS = "https://as.test";
const CONSUMER_AUD = "https://erp.consumer.test";
const RESOURCE = "https://payments.test/mcp";
const NOW = new Date("2026-08-02T12:00:00Z");
const EXPIRES_AT = "2027-01-01T00:00:00Z";

/** Minimal derivation policy: one resource, a read + an execute action, no constraints. */
const POLICY = {
  policy_version: "signals-test-v1",
  ceiling: [
    {
      type: "mission_resource_access",
      resource: RESOURCE,
      actions: ["payments:invoice.read", "payments:payment.execute"],
    },
  ],
};

const INTENT = {
  goal: "Read approved invoices",
  target_resources: [RESOURCE],
  expires_at: EXPIRES_AT,
};

const PROPOSED_AUTHORITY: AuthorityEntry[] = [
  { type: "mission_resource_access", resource: RESOURCE, actions: ["payments:invoice.read"] },
];

/** A stub PDP authority backend: authority is granted, so the decision turns on
 *  Mission state (step 2), which is exactly what the signal drives. */
const fga = { checkWithContext: async () => true } as unknown as Fga;
const relationForAction = (action: string) =>
  action === "payments:invoice.read" ? { relation: "reader" as const, needsAmount: false } : null;
const stalenessBoundSeconds = () => 300;

/** Wire a real kernel + emitter + receiver, approve one Mission (the activating
 *  commit emits an `active`/v1 SET), and expose a receiver-cache-only loadView. */
async function bootstrap() {
  const statusKeys = await generateKeyPair("ES256", { extractable: true });
  const statusPub = {
    ...(await exportJWK(statusKeys.publicKey)),
    kid: "as-status",
    alg: "ES256",
    use: "sig",
  };
  const emitter = new MissionSignalEmitter({
    key: statusKeys.privateKey,
    kid: "as-status",
    consumers: [{ audience: CONSUMER_AUD }],
  });
  const receiver = new MissionSignalReceiver({
    jwks: { keys: [statusPub] },
    issuer: ISS,
    audience: CONSUMER_AUD,
  });
  emitter.register(receiver);

  const kernel = new MissionKernel({
    issuer: ISS,
    policy: POLICY as never,
    statusKey: statusKeys.privateKey,
    statusKid: "as-status",
    now: () => NOW,
    onLifecycleCommit: emitter.onCommit,
  });

  const record = kernel.approve({
    intent: INTENT as never,
    proposedAuthority: PROPOSED_AUTHORITY,
    subject: { iss: ISS, sub: "alice" },
    approver: { iss: ISS, sub: "bob" },
    clientId: "ap-agent",
    approvalEventId: "apev-signals-1",
  });
  await emitter.drain(); // the activating SET (active/v1) reaches the receiver

  // The static Mission-claim fields a consumer legitimately holds from issuance;
  // captured ONCE here, never re-read from the kernel inside loadView.
  const snapshot = {
    id: record.id,
    issuer: record.issuer,
    authority_hash: record.authority_hash,
    authority_set: record.authority_set,
    subject: record.subject,
    client_id: record.client_id,
  };

  const loadView = (id: string): MissionView | undefined => {
    const s = receiver.viewState(id); // state + version from the signal cache ONLY
    if (!s) return undefined;
    return {
      id: snapshot.id,
      issuer: snapshot.issuer,
      state: s.state,
      version: s.version,
      authority_hash: snapshot.authority_hash,
      authority_set: snapshot.authority_set,
      subject: snapshot.subject,
      client_id: snapshot.client_id,
    };
  };

  const req = (): EvaluationRequest => ({
    subject: { id: "alice" },
    resource: { type: "invoice", id: "inv-1", properties: { vendor_id: "acme" } },
    action: { name: "payments:invoice.read" },
    context: {
      audience: RESOURCE,
      mission: { id: record.id, issuer: record.issuer, authority_hash: snapshot.authority_hash },
    },
  });

  const decide = async (id: string) => {
    const view = loadView(id);
    if (!view) throw new Error("no view for mission");
    return evaluate(req(), {
      view,
      fga,
      modelId: "signals-test-model",
      now: () => NOW,
      stalenessBoundSeconds,
      relationForAction,
    });
  };

  const revokedSet = (
    over: {
      audience?: string;
      issuer?: string;
      key?: CryptoKey;
      version?: number;
      state?: string;
    } = {},
  ) =>
    signLifecycleEvent(
      {
        id: record.id,
        issuer: over.issuer ?? ISS,
        state: over.state ?? "revoked",
        prior_state: "active",
        version: over.version ?? 2,
        committed_at: NOW.toISOString(),
        expires_at: EXPIRES_AT,
      } as LifecycleCommit,
      {
        audience: over.audience ?? CONSUMER_AUD,
        key: over.key ?? statusKeys.privateKey,
        kid: "as-status",
      },
    );

  return { kernel, emitter, receiver, statusKeys, record, decide, revokedSet };
}

const ACTIVE_V1 = { state: "active", version: 1, expires_at: EXPIRES_AT };
const REVOKED_V2 = { state: "revoked", version: 2, expires_at: EXPIRES_AT };

describe("Mission Signals — SET lifecycle events (@spec signals#lifecycle-event)", () => {
  it("permits before the signal, then denies mission_inactive after a revoke SET (@spec signals#consumer-behavior)", async () => {
    const b = await bootstrap();
    // The activating SET seeded active/v1 into the receiver cache.
    expect(b.receiver.viewState(b.record.id)).toEqual(ACTIVE_V1);
    const permit = await b.decide(b.record.id);
    expect(permit.decision, JSON.stringify(permit.context)).toBe(true);

    // A committed revoke fires the kernel hook -> emitter signs -> receiver applies.
    b.kernel.transition(b.record.id, "revoke");
    await b.emitter.drain();
    expect(b.receiver.viewState(b.record.id)).toEqual(REVOKED_V2); // signal drove the state

    const denied = await b.decide(b.record.id);
    expect(denied.decision).toBe(false);
    expect(denied.context.denial_reason).toBe("mission_inactive"); // PDP step 2, not stale_state

    // The signal-established state is also readable as the shared harness lease.
    expect(b.receiver.lease(b.record.id, NOW.toISOString())).toEqual({
      state: "revoked",
      version: 2,
      status_checked_at: NOW.toISOString(),
      status_expires_at: EXPIRES_AT,
      state_source: "signal",
    });
  });

  it("does not revive on a stale lower-version active SET (anti-revive) (@spec signals#consumer-behavior)", async () => {
    const b = await bootstrap();
    b.kernel.transition(b.record.id, "revoke");
    await b.emitter.drain();
    expect(b.receiver.viewState(b.record.id)).toEqual(REVOKED_V2);

    // A stale active/v1 SET with a FRESH jti: only the version rule can refuse it.
    const staleSet = await signLifecycleEvent(
      {
        id: b.record.id,
        issuer: ISS,
        state: "active",
        version: 1,
        committed_at: NOW.toISOString(),
        expires_at: EXPIRES_AT,
      } as LifecycleCommit,
      { audience: CONSUMER_AUD, key: b.statusKeys.privateKey, kid: "as-status" },
    );
    const res = await b.receiver.verifyAndApply(staleSet);
    expect(res.status).toBe("stale");
    expect(b.receiver.viewState(b.record.id)).toEqual(REVOKED_V2); // never regressed

    const denied = await b.decide(b.record.id);
    expect(denied.context.denial_reason).toBe("mission_inactive");
  });

  it("refuses a SET with the wrong audience (@spec signals#set-protection)", async () => {
    const b = await bootstrap();
    const res = await b.receiver.verifyAndApply(
      await b.revokedSet({ audience: "https://evil.test" }),
    );
    expect(res).toEqual({ status: "refused", reason: "audience" });
    expect(b.receiver.viewState(b.record.id)).toEqual(ACTIVE_V1);
  });

  it("refuses a SET with the wrong issuer (@spec signals#set-protection)", async () => {
    const b = await bootstrap();
    // Signed with the trusted key (kid as-status), but iss claims another issuer.
    // signLifecycleEvent sets both the envelope `iss` and `mission.issuer` from
    // commit.issuer, so the SET is internally consistent: only the receiver's
    // explicit iss check can refuse it.
    const res = await b.receiver.verifyAndApply(
      await b.revokedSet({ issuer: "https://evil-issuer.test" }),
    );
    expect(res).toEqual({ status: "refused", reason: "issuer" });
    expect(b.receiver.viewState(b.record.id)).toEqual(ACTIVE_V1);
  });

  it("refuses a SET with an untrusted signature (@spec signals#set-protection)", async () => {
    const b = await bootstrap();
    const rogue = await generateKeyPair("ES256", { extractable: true });
    const res = await b.receiver.verifyAndApply(await b.revokedSet({ key: rogue.privateKey }));
    expect(res).toEqual({ status: "refused", reason: "signature" });
    expect(b.receiver.viewState(b.record.id)).toEqual(ACTIVE_V1);
  });

  it("treats redelivery of the same jti as a duplicate, with no regression (@spec signals#set-protection)", async () => {
    const b = await bootstrap();
    const set = await b.revokedSet();
    const first = await b.receiver.verifyAndApply(set);
    expect(first.status).toBe("applied");
    expect(b.receiver.viewState(b.record.id)).toEqual(REVOKED_V2);

    const second = await b.receiver.verifyAndApply(set); // same jti
    expect(second).toEqual({ status: "duplicate" });
    expect(b.receiver.viewState(b.record.id)).toEqual(REVOKED_V2);
  });
});
