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
import { testAuthoritySourceCatalog } from "@mission/authorization-server/test-support";
import {
  type EvaluationRequest,
  evaluate as evaluateRequest,
  type Fga,
  type MissionView,
} from "@mission/pdp";
import { decodeJwt, exportJWK, generateKeyPair, SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import { withCredential } from "../../../services/pdp/test/with-credential.js";
import {
  LIFECYCLE_CHANGE_EVENT_URI,
  MissionSignalEmitter,
  MissionSignalReceiver,
  SET_TYP,
  signLifecycleEvent,
} from "../src/index.js";

// Every decision carries the credential's own authority (#825 PR 2b); the
// fixture adds a neutral one where a test does not name it.
const evaluate = (req: EvaluationRequest, opts: Parameters<typeof evaluateRequest>[1]) =>
  evaluateRequest(withCredential(req), opts);

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
const stalenessBound = () => ({ kind: "bounded" as const, seconds: 300 });

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
    authoritySourceCatalog: testAuthoritySourceCatalog(POLICY.ceiling, ["ap-agent"], ["bob"]),
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
    resource: {
      type: "invoice",
      id: "inv-1",
      properties: { audience: RESOURCE, vendor_id: "acme" },
    },
    action: { name: "payments:invoice.read" },
    context: {
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
      stalenessBound,
      relationForAction,
    });
  };

  const revokedSet = (
    over: { audience?: string; issuer?: string; key?: CryptoKey; version?: number } = {},
  ) =>
    signLifecycleEvent(
      {
        id: record.id,
        issuer: over.issuer ?? ISS,
        state: "terminated",
        termination: {
          reason: "revoked",
          terminated_at: NOW.toISOString(),
          version: over.version ?? 2,
        },
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
/** A revoke at v2: `terminated`, reason `revoked`, the termination's version the event's. */
const REVOKED_V2 = {
  state: "terminated",
  termination: { reason: "revoked", terminated_at: NOW.toISOString(), version: 2 },
  version: 2,
  expires_at: EXPIRES_AT,
};

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
      state: "terminated",
      termination: REVOKED_V2.termination,
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

/**
 * @spec mission#termination, signals#lifecycle-event: the SET reports a
 * Mission's lifecycle as `active`, `suspended` or `terminated`, with
 * `termination` in the event body exactly beside `terminated` and holding the
 * termination's references; no top-level `successor` or `carried_to` exists.
 * The receiver reads `termination` from the event body, never refuses a
 * terminated event over a bad one, and reads a legacy terminal `state` as
 * `terminated` with that reason only after the signature verifies.
 * Kernel-free: commits and SETs are built by hand.
 */
describe("Mission Signals: termination in the lifecycle-change event (@spec mission#termination)", () => {
  const MISSION_ID = "msn_termination_000000000000001";
  const LIFECYCLE_STATES = ["active", "suspended", "terminated"];

  async function fixture() {
    const keys = await generateKeyPair("ES256", { extractable: true });
    const pub = {
      ...(await exportJWK(keys.publicKey)),
      kid: "as-status",
      alg: "ES256",
      use: "sig",
    };
    const receiver = new MissionSignalReceiver({
      jwks: { keys: [pub] },
      issuer: ISS,
      audience: CONSUMER_AUD,
    });
    let n = 0;
    /** Sign an arbitrary event body as the trusted issuer (or `key`), as a pre-existing emitter might have. */
    const signEvent = (
      body: Record<string, unknown>,
      key: CryptoKey = keys.privateKey,
      id = MISSION_ID,
    ) =>
      new SignJWT({
        sub_id: { format: "opaque", id },
        events: {
          [LIFECYCLE_CHANGE_EVENT_URI]: {
            mission: { id, issuer: ISS },
            committed_at: NOW.toISOString(),
            expires_at: EXPIRES_AT,
            ...body,
          },
        },
      })
        .setProtectedHeader({ alg: "ES256", kid: "as-status", typ: SET_TYP })
        .setIssuer(ISS)
        .setAudience(CONSUMER_AUD)
        .setIssuedAt()
        .setJti(`set_termination_${++n}`)
        .sign(key);
    const eventOf = (set: string) =>
      (decodeJwt(set).events as Record<string, Record<string, unknown>>)[
        LIFECYCLE_CHANGE_EVENT_URI
      ] as Record<string, unknown>;
    const build = (commit: Record<string, unknown>) =>
      signLifecycleEvent(
        {
          id: MISSION_ID,
          issuer: ISS,
          committed_at: NOW.toISOString(),
          expires_at: EXPIRES_AT,
          ...commit,
        } as unknown as LifecycleCommit,
        { audience: CONSUMER_AUD, key: keys.privateKey, kid: "as-status" },
      );
    return { keys, receiver, signEvent, eventOf, build };
  }

  it("the SET builder emits only active, suspended or terminated, with termination exactly beside terminated and no top-level successor or carried_to", async () => {
    const { build, eventOf } = await fixture();
    const T = NOW.toISOString();
    const commits: Array<[string, Record<string, unknown>]> = [
      ["activation", { state: "active", version: 1 }],
      ["suspend", { state: "suspended", prior_state: "active", version: 2 }],
      [
        "active with a stray termination",
        { state: "active", prior_state: "active", version: 3, termination: { reason: "revoked" } },
      ],
      [
        "revoke",
        {
          state: "terminated",
          prior_state: "active",
          version: 4,
          termination: { reason: "revoked", terminated_at: T, version: 4 },
        },
      ],
      [
        "complete",
        {
          state: "terminated",
          prior_state: "suspended",
          version: 4,
          termination: { reason: "completed", terminated_at: T, version: 4 },
        },
      ],
      [
        "expire",
        {
          state: "terminated",
          prior_state: "active",
          version: 4,
          termination: { reason: "expired", terminated_at: EXPIRES_AT, version: 4 },
        },
      ],
      [
        "supersede",
        {
          state: "terminated",
          prior_state: "active",
          version: 4,
          termination: {
            reason: "superseded",
            terminated_at: T,
            version: 4,
            successor: "msn_successor",
          },
        },
      ],
      [
        "cascade with carryover",
        {
          state: "terminated",
          prior_state: "active",
          version: 4,
          termination: {
            reason: "parent_terminated",
            terminated_at: T,
            version: 4,
            parent: "msn_parent",
            origin: "msn_root",
            origin_reason: "revoked",
            carried_to: "msn_replacement",
          },
        },
      ],
      // Journaled before the termination vocabulary, never signed: signed in it.
      ["legacy revoked", { state: "revoked", prior_state: "active", version: 4 }],
      ["legacy expired", { state: "expired", prior_state: "active", version: 4 }],
      ["legacy completed", { state: "completed", prior_state: "active", version: 4 }],
      [
        "legacy superseded",
        { state: "superseded", prior_state: "active", version: 4, successor: "msn_successor" },
      ],
      [
        "legacy cascaded",
        { state: "cascaded", prior_state: "suspended", version: 4, carried_to: "msn_replacement" },
      ],
      [
        "a legacy prior_state",
        {
          state: "terminated",
          prior_state: "revoked",
          version: 4,
          termination: { reason: "revoked", terminated_at: T, version: 4 },
        },
      ],
    ];
    const events = new Map<string, Record<string, unknown>>();
    for (const [label, commit] of commits) {
      const event = eventOf(await build(commit));
      events.set(label, event);
      expect(LIFECYCLE_STATES, label).toContain(event.state);
      expect("termination" in event, label).toBe(event.state === "terminated");
      if (event.state === "terminated") {
        expect(typeof (event.termination as { reason?: unknown }).reason, label).toBe("string");
      }
      expect(event, label).not.toHaveProperty("successor");
      expect(event, label).not.toHaveProperty("carried_to");
      if (event.prior_state !== undefined)
        expect(["active", "suspended"], label).toContain(event.prior_state);
    }
    // A committed termination: every member its reason requires, its version the event's.
    expect(events.get("revoke")?.termination).toEqual({
      reason: "revoked",
      terminated_at: T,
      version: 4,
    });
    const revoke = events.get("revoke") as { termination: { version: number }; version: number };
    expect(revoke.termination.version).toBe(revoke.version);
    expect(events.get("expire")?.termination).toEqual({
      reason: "expired",
      terminated_at: EXPIRES_AT,
      version: 4,
    });
    expect(events.get("supersede")?.termination).toMatchObject({
      reason: "superseded",
      successor: "msn_successor",
    });
    expect(events.get("cascade with carryover")?.termination).toMatchObject({
      reason: "parent_terminated",
      parent: "msn_parent",
      carried_to: "msn_replacement",
    });
    // A legacy commit: its reason and its retained reference only, nothing invented.
    expect(events.get("legacy revoked")?.termination).toEqual({ reason: "revoked" });
    expect(events.get("legacy expired")?.termination).toEqual({ reason: "expired" });
    expect(events.get("legacy completed")?.termination).toEqual({ reason: "completed" });
    expect(events.get("legacy superseded")?.termination).toEqual({
      reason: "superseded",
      successor: "msn_successor",
    });
    expect(events.get("legacy cascaded")?.termination).toEqual({
      reason: "parent_terminated",
      carried_to: "msn_replacement",
    });
    expect(events.get("a legacy prior_state")).not.toHaveProperty("prior_state");
  });

  it("the receiver reads termination from the event body beside terminated only, and carries it to the harness lease", async () => {
    const { receiver, signEvent } = await fixture();
    const T = NOW.toISOString();
    const superseded = await signEvent({
      state: "terminated",
      termination: {
        reason: "superseded",
        terminated_at: T,
        version: 1,
        successor: "msn_successor",
        successor_note: 1,
      },
      // A top-level member is not the termination's reference: never read.
      successor: "msn_wrong",
      version: 1,
    });
    const applied = await receiver.verifyAndApply(superseded);
    const termination = {
      reason: "superseded",
      terminated_at: T,
      version: 1,
      successor: "msn_successor",
    };
    expect(applied).toEqual({
      status: "applied",
      state: "terminated",
      termination,
      version: 1,
      rematerialize: false,
    });
    expect(receiver.viewState(MISSION_ID)).toEqual({
      state: "terminated",
      termination,
      version: 1,
      expires_at: EXPIRES_AT,
    });
    expect(receiver.lease(MISSION_ID, T)).toEqual({
      state: "terminated",
      termination,
      version: 1,
      status_checked_at: T,
      status_expires_at: EXPIRES_AT,
      state_source: "signal",
    });

    // A termination beside any other state is dropped.
    const other = "msn_termination_000000000000002";
    const { receiver: second, signEvent: signSecond } = await fixture();
    const suspended = await signSecond(
      { state: "suspended", termination: { reason: "revoked" }, version: 1 },
      undefined,
      other,
    );
    expect(await second.verifyAndApply(suspended)).toEqual({
      status: "applied",
      state: "suspended",
      version: 1,
      rematerialize: false,
    });
    expect(second.viewState(other)).toEqual({
      state: "suspended",
      version: 1,
      expires_at: EXPIRES_AT,
    });
  });

  it("a missing or malformed termination never refuses a terminated event: an earlier active is never left in place", async () => {
    for (const termination of [
      undefined,
      "revoked",
      { reason: 7 },
      { reason: "" },
      [{ reason: "revoked" }],
    ]) {
      const { receiver, signEvent } = await fixture();
      expect(
        (await receiver.verifyAndApply(await signEvent({ state: "active", version: 1 }))).status,
      ).toBe("applied");
      const set = await signEvent({
        state: "terminated",
        ...(termination !== undefined ? { termination } : {}),
        version: 2,
      });
      const res = await receiver.verifyAndApply(set);
      expect(res, JSON.stringify(termination)).toEqual({
        status: "applied",
        state: "terminated",
        version: 2,
        rematerialize: false,
      });
      expect(receiver.viewState(MISSION_ID)?.state, JSON.stringify(termination)).toBe("terminated");
      expect(
        receiver.viewState(MISSION_ID)?.termination,
        JSON.stringify(termination),
      ).toBeUndefined();
    }
  });

  it("normalizes a legacy SET's state only after its signature verifies, reading no top-level successor or carried_to", async () => {
    const legacy: Array<[Record<string, unknown>, Record<string, unknown>]> = [
      [{ state: "revoked", prior_state: "active" }, { reason: "revoked" }],
      [{ state: "expired", prior_state: "active" }, { reason: "expired" }],
      [{ state: "completed", prior_state: "active" }, { reason: "completed" }],
      [
        { state: "superseded", prior_state: "active", successor: "msn_successor" },
        { reason: "superseded" },
      ],
      [
        { state: "cascaded", prior_state: "active", carried_to: "msn_replacement" },
        { reason: "parent_terminated" },
      ],
    ];
    for (const [body, termination] of legacy) {
      const { keys, receiver, signEvent } = await fixture();
      // Verify before normalize: a legacy SET under an untrusted key is refused, the cache untouched.
      const rogue = await generateKeyPair("ES256", { extractable: true });
      const forged = await signEvent({ ...body, version: 1 }, rogue.privateKey);
      expect(await receiver.verifyAndApply(forged)).toEqual({
        status: "refused",
        reason: "signature",
      });
      expect(receiver.viewState(MISSION_ID)).toBeUndefined();

      const set = await signEvent({ ...body, version: 1 }, keys.privateKey);
      const res = await receiver.verifyAndApply(set);
      expect(res, String(body.state)).toEqual({
        status: "applied",
        state: "terminated",
        termination,
        version: 1,
        rematerialize: false,
      });
      expect(
        receiver.lease(MISSION_ID, NOW.toISOString())?.termination,
        String(body.state),
      ).toEqual(termination);
    }
  });
});
