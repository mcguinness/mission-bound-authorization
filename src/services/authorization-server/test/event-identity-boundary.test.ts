/**
 * @spec mission#approval-idempotency (#1915, D1056): the common event-identity
 * rule at its boundaries.
 *
 *  - One approval event creates at most one Mission; expiring a request-key
 *    reservation never replays that decision into another Mission.
 *  - A request key (Template's `dispatch_event_id`, the `creation_request_id`
 *    of Progressive drawdown, Child Delegation and Expansion) identifies
 *    retries within the published retention horizon. After its tombstone
 *    expires, a reuse may start a NEW operation, which passes the CURRENT
 *    checks and receives a NEW `approval_event_id`.
 *  - A tombstone horizon never lets a reuse start a new operation while the
 *    first operation is still pending.
 *  - Each path keeps its own replay semantics; the common requirement is no
 *    duplicate creation.
 *
 * Where the horizon starts (creation-idempotency.ts `insertRow`): ONE clock
 * read stamps the reservation's `created_at` and `expires_at = created_at +
 * retention` when the reservation row is INSERTED. For the synchronous paths
 * (Dispatch, drawdown, child creation) that is the first statement of the
 * creation transaction (`createCompleted`); for a deferred Expansion it is
 * INITIATION (`reserve`). Completion (`completeInCallerTx`,
 * `completeDelivered`) and delivery (`recordDelivery`) never move it. `find`
 * purges only when `now > expires_at`, so the key is retained at exactly
 * `expires_at` and free one millisecond later.
 *
 * Part A drives Template Dispatch through the kernel with an exact clock.
 * Part B drives the token endpoint of one assembly whose kernel clock the
 * suite pins; DPoP `iat`, client assertions and access-token expiry run on the
 * real clock and are unaffected by the pin.
 */

import type { Server } from "node:http";
import {
  CANONICAL_RESOURCE,
  DERIVATION_POLICY,
  demoReconciliationTemplate,
  DEV_SERVICE_TOKEN,
  PROGRESSIVE_PROFILE,
} from "@mission/demo-data";
import { UniqueViolationError } from "@mission/store";
import { type CryptoKey, decodeJwt, exportJWK, generateKeyPair, importJWK, SignJWT } from "jose";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import {
  ACCESS_TOKEN_TOKEN_TYPE,
  JWT_TOKEN_TYPE,
  TOKEN_EXCHANGE_GRANT_TYPE,
} from "../src/adapters/continuation-grant.js";
import { MISSION_DISPATCH_GRANT_TYPE } from "../src/adapters/provider.js";
import type { RegisteredActivationPolicy } from "../src/kernel/activation-policy.js";
import {
  CreationIdempotencyStore,
  DEFAULT_CREATION_TOMBSTONE_TTL_S,
} from "../src/kernel/creation-idempotency.js";
import { DEFERRED_GRANT_TYPE } from "../src/kernel/deferred.js";
import { ExpiryPassedError } from "../src/kernel/intent.js";
import {
  assembledCeilingOffer,
  type ProgressiveDrawdownOptions,
  progressiveFromProfile,
} from "../src/kernel/progressive.js";
import type { LifecycleCommit } from "../src/kernel/types.js";
import {
  activateGovernedPolicy,
  ApprovalSessionStore,
  type AuthorityEntry,
  type AuthoritySourceCatalog,
  buildAuthorizationServer,
  type BuiltAs,
  createTemplate,
  type CreateTemplateInput,
  DispatchError,
  type DispatchInput,
  DispatchMismatchError,
  type DispatchPolicies,
  type DispatchResult,
  dispatchFromTemplate,
  type GovernedPolicyRoot,
  MissionApprovalDeferralError,
  MissionApprovalDeferralStore,
  MissionKernel,
  type MissionRecord,
  recordDispatchDelivery,
  recordGovernedPolicyConsent,
  TemplateStore,
  validateMissionIntent,
} from "../src/index.js";
import { aiAgents } from "./actor-profiles.helper.js";
import { FIXTURE_BROWSER_LOGIN, floorApprovalHeaders, renderedRevision, TEST_APPROVAL_PRINCIPALS } from "./approval-fixture.js";
import { testAuthoritySourceCatalog } from "./authority-source.helper.js";

/** The shipped published retry horizon, in milliseconds. */
const R = DEFAULT_CREATION_TOMBSTONE_TTL_S * 1000;
const TAG = "(@spec mission#approval-idempotency, #1915)";

// ===========================================================================
// Part A: Template Dispatch through the kernel, on an exact clock.
// ===========================================================================

const ISS = "https://as.test";
const KRESOURCE = DERIVATION_POLICY.ceiling[0].resource;
const POLICY_VERSION = DERIVATION_POLICY.policy_version;
const T0 = Date.parse("2026-07-01T00:00:00Z");
/** Part A's kernel clock: fixed at T0 unless a test moves it. */
let kClock = T0;
const kNow = () => new Date(kClock);

let statusKey: CryptoKey;
let kernel: MissionKernel;
let store: TemplateStore;
let tmplSeq = 0;

beforeAll(async () => {
  statusKey = (await generateKeyPair("ES256")).privateKey;
});

beforeEach(() => {
  kClock = T0;
  kernel = new MissionKernel({
    issuer: ISS,
    policy: DERIVATION_POLICY as never,
    authoritySourceCatalog: testAuthoritySourceCatalog(DERIVATION_POLICY.ceiling, ["worker", "orchestrator"], ["human-approver", "bob"]),
    statusKey,
    statusKid: "as-status",
    now: kNow,
  });
  store = new TemplateStore(kNow);
});

const snapshotOf = (id: string, content = JSON.stringify({ id, rule: "dispatch within the template ceiling" })) => ({
  version: "1",
  content_type: "application/json",
  content,
});
const REGISTRY: DispatchPolicies = { "test-policy": snapshotOf("test-policy") };
/** The same policy id and version, edited after consent (its digest no longer matches). */
const EDITED_REGISTRY: DispatchPolicies = {
  "test-policy": snapshotOf("test-policy", JSON.stringify({ id: "test-policy", rule: "edited after consent" })),
};

const ceilEntry = (actions: string[]): AuthorityEntry => ({
  type: "mission_resource_access",
  resource: KRESOURCE,
  actions,
  constraints: { max_amount: { amount: "200.00", currency: "USD" }, vendors: ["acme"] },
});

/** A template whose review cadence (30 days) outlives the retry horizon unless a case shortens it. */
const mkTemplate = (over: Partial<CreateTemplateInput> = {}) =>
  createTemplate(
    store,
    {
      template_version: "tmpl-v1",
      issuer: ISS,
      approver: { iss: ISS, sub: "human-approver" },
      ceiling: [ceilEntry(["payments:invoice.read", "payments:vendor.read", "payments:payment.schedule"])],
      dispatch_policy: { id: "test-policy", version: "1" },
      dispatchers: ["orchestrator"],
      recipients: { subjects: [{ iss: ISS, sub: "alice" }], agents: ["worker"] },
      per_instance_lifetime_s: 3600,
      max_active: 3,
      rate_per_min: 5,
      review_cadence_s: 30 * 86400,
      approval_event_id: `tmpl-ev-${tmplSeq++}`,
      expires_at: "2026-12-01T00:00:00Z",
      ...over,
    },
    { ...kernel.authoritySourceOptions(), dispatchPolicies: REGISTRY },
  );

const kIntent = (expiresAt = "2027-01-01T00:00:00Z") =>
  kernel.validateIntent(JSON.stringify({ goal: "reconcile Acme", target_resources: [KRESOURCE], expires_at: expiresAt }));

const kProposal = (maxAmount: string): AuthorityEntry[] => [
  {
    type: "mission_resource_access",
    resource: KRESOURCE,
    actions: ["payments:invoice.read"],
    constraints: { max_amount: { amount: maxAmount, currency: "USD" } },
  },
];

/** One Dispatch under `dispatchEventId` through `idempotency` (the shipped horizon unless a case builds another). */
const kDispatch = (templateId: string, dispatchEventId: string, idempotency: CreationIdempotencyStore, over: Partial<DispatchInput> = {}) =>
  dispatchFromTemplate(kernel, store, {
    templateId,
    dispatchEventId,
    dispatcher: "orchestrator",
    intent: kIntent(),
    subject: { iss: ISS, sub: "alice" },
    policyVersion: POLICY_VERSION,
    dispatchPolicies: REGISTRY,
    presenterJkt: "jkt-1",
    idempotency,
    ...over,
  });

/** The stored reservation row, read from the kernel database (the parsed operation omits `completed_at`). */
const reservationRow = (db: MissionKernel["db"], clientId: string, key: string) =>
  db
    .prepare("SELECT created_at, completed_at, expires_at, state, mission_id FROM creation_idempotency WHERE client_id = ? AND creation_request_id = ?")
    .get(clientId, key) as { created_at: number; completed_at: number | null; expires_at: number; state: string; mission_id: string | null } | undefined;

describe(`Template Dispatch: the dispatch_event_id horizon at its boundary ${TAG}`, () => {
  it(`retains the key 1 ms before and exactly at reservation + horizon (recovering the instance and its approval_event_id) and frees it 1 ms after (a new instance, a new approval_event_id) ${TAG}`, () => {
    const t = mkTemplate();
    const idem = new CreationIdempotencyStore(kernel);
    const first = kDispatch(t.id, "evt-boundary", idem).mission;
    const op = idem.find("orchestrator", "evt-boundary");
    // The horizon starts at the reservation insert, which is this Dispatch's
    // creation instant (one clock read, one transaction).
    expect(op?.createdAt).toBe(T0);
    expect(Date.parse(first.created_at)).toBe(T0);
    expect(op?.expiresAt).toBe(T0 + R);
    // Delivery recorded later never moves the horizon.
    kClock = T0 + 5_000;
    recordDispatchDelivery(kernel, { dispatcher: "orchestrator", dispatchEventId: "evt-boundary", idempotency: idem }, { access_token: "delivered", exp: 1 });
    expect(idem.find("orchestrator", "evt-boundary")?.expiresAt).toBe(T0 + R);
    const committed = kernel.allMissions().length;

    for (const at of [T0 + R - 1, T0 + R]) {
      kClock = at;
      const retry = kDispatch(t.id, "evt-boundary", idem).mission;
      expect(retry.id).toBe(first.id);
      expect(retry.approval_event_id).toBe(first.approval_event_id);
      expect(kernel.allMissions().length).toBe(committed);
    }

    kClock = T0 + R + 1;
    const reused = kDispatch(t.id, "evt-boundary", idem).mission;
    expect(reused.id).not.toBe(first.id);
    expect(reused.approval_event_id).not.toBe(first.approval_event_id);
    expect(Date.parse(reused.created_at)).toBe(T0 + R + 1);
    expect(kernel.allMissions().length).toBe(committed + 1);
    // The key now names the new operation, under a horizon of its own.
    const renewed = idem.find("orchestrator", "evt-boundary");
    expect(renewed?.missionId).toBe(reused.id);
    expect(renewed?.createdAt).toBe(T0 + R + 1);
    expect(renewed?.expiresAt).toBe(T0 + R + 1 + R);
    // The first instance keeps its own event identity.
    expect(kernel.get(first.id)?.approval_event_id).toBe(first.approval_event_id);
  });

  it(`measures the horizon from the reservation insert, not from the completion written later in the same transaction ${TAG}`, () => {
    const t = mkTemplate();
    // Every read of this store's clock is one second later than the last.
    let tick = T0;
    const idem = new CreationIdempotencyStore(kernel, {
      retentionSeconds: 60,
      now: () => {
        tick += 1000;
        return new Date(tick);
      },
    });
    kDispatch(t.id, "evt-ticking", idem);
    const row = reservationRow(kernel.db, "orchestrator", "evt-ticking");
    expect(row?.state).toBe("completed");
    expect((row?.completed_at as number) > (row?.created_at as number)).toBe(true);
    expect(row?.expires_at).toBe((row?.created_at as number) + 60_000);
  });
});

describe(`Template Dispatch: concurrent reuse of one expired dispatch_event_id ${TAG}`, () => {
  it(`two Dispatches racing on an expired key create one new instance under one new approval_event_id, and the loser recovers it ${TAG}`, () => {
    const t = mkTemplate();
    const idem = new CreationIdempotencyStore(kernel);
    const first = kDispatch(t.id, "evt-race", idem).mission;
    kClock = T0 + R + 1;
    const before = kernel.allMissions().length;
    // The outer Dispatch has passed its (purging) lookup; a competitor runs to
    // completion before the outer one reaches its reservation insert.
    const real = idem.createCompleted.bind(idem);
    let competitor: DispatchResult | undefined;
    let raced = false;
    const spy = vi.spyOn(idem, "createCompleted").mockImplementation((res, create) => {
      if (!raced) {
        raced = true;
        competitor = kDispatch(t.id, "evt-race", idem);
      }
      return real(res, create);
    });
    let outer: DispatchResult;
    try {
      outer = kDispatch(t.id, "evt-race", idem);
    } finally {
      spy.mockRestore();
    }
    expect(competitor).toBeDefined();
    expect(outer.mission.id).toBe(competitor?.mission.id);
    expect(outer.mission.approval_event_id).toBe(competitor?.mission.approval_event_id);
    expect(outer.mission.id).not.toBe(first.id);
    expect(outer.mission.approval_event_id).not.toBe(first.approval_event_id);
    expect(kernel.allMissions().length).toBe(before + 1);
    expect(idem.find("orchestrator", "evt-race")?.missionId).toBe(outer.mission.id);
  });
});

describe(`Template Dispatch: a changed fingerprint inside the window ${TAG}`, () => {
  it(`1 ms before the horizon a reused key with another presenter key or proposal is refused DispatchMismatchError and creates nothing; 1 ms after, the same changed request is a new Dispatch ${TAG}`, () => {
    const t = mkTemplate();
    const idem = new CreationIdempotencyStore(kernel);
    const first = kDispatch(t.id, "evt-fp", idem).mission;
    kClock = T0 + R - 1;
    const committed = kernel.allMissions().length;
    expect(() => kDispatch(t.id, "evt-fp", idem, { presenterJkt: "jkt-2" })).toThrow(DispatchMismatchError);
    expect(() => kDispatch(t.id, "evt-fp", idem, { proposedAuthority: kProposal("100.00") })).toThrow(DispatchMismatchError);
    expect(kernel.allMissions().length).toBe(committed);
    expect(idem.find("orchestrator", "evt-fp")?.missionId).toBe(first.id);

    kClock = T0 + R + 1;
    const changed = kDispatch(t.id, "evt-fp", idem, { presenterJkt: "jkt-2" }).mission;
    expect(changed.id).not.toBe(first.id);
    expect(changed.approval_event_id).not.toBe(first.approval_event_id);
    expect(kernel.allMissions().length).toBe(committed + 1);
  });
});

describe(`Template Dispatch: a reuse after expiry meets the current checks ${TAG}`, () => {
  /** The first instance as committed, for the unchanged check. */
  const snapshot = (m: MissionRecord) => JSON.stringify(kernel.get(m.id));

  it(`a review cadence that lapsed inside the window still recovers the instance; after the horizon the reuse is refused review_overdue and creates nothing ${TAG}`, () => {
    const t = mkTemplate({ review_cadence_s: 3600 });
    const idem = new CreationIdempotencyStore(kernel);
    const first = kDispatch(t.id, "evt-review", idem).mission;
    const before = snapshot(first);
    kClock = T0 + 7200_000;
    expect(kDispatch(t.id, "evt-review", idem).mission.id).toBe(first.id);
    kClock = T0 + R + 1;
    const committed = kernel.allMissions().length;
    let refused: unknown;
    try {
      kDispatch(t.id, "evt-review", idem);
    } catch (e) {
      refused = e;
    }
    expect(refused).toBeInstanceOf(DispatchError);
    expect((refused as DispatchError).reason).toBe("review_overdue");
    expect(kernel.allMissions().length).toBe(committed);
    expect(idem.find("orchestrator", "evt-review")).toBeUndefined();
    expect(snapshot(first)).toBe(before);
  });

  it(`a Dispatch Policy edited after consent does not touch a retry inside the window; after the horizon the reuse is refused dispatch_policy_changed and creates nothing ${TAG}`, () => {
    const t = mkTemplate();
    const idem = new CreationIdempotencyStore(kernel);
    const first = kDispatch(t.id, "evt-policy", idem).mission;
    const before = snapshot(first);
    kClock = T0 + R - 1;
    expect(kDispatch(t.id, "evt-policy", idem, { dispatchPolicies: EDITED_REGISTRY }).mission.id).toBe(first.id);
    kClock = T0 + R + 1;
    const committed = kernel.allMissions().length;
    let refused: unknown;
    try {
      kDispatch(t.id, "evt-policy", idem, { dispatchPolicies: EDITED_REGISTRY });
    } catch (e) {
      refused = e;
    }
    expect((refused as DispatchError).reason).toBe("dispatch_policy_changed");
    expect(kernel.allMissions().length).toBe(committed);
    expect(snapshot(first)).toBe(before);
  });

  it(`a template revoked inside the window still recovers the instance; after the horizon the reuse is refused template_not_active and creates nothing ${TAG}`, () => {
    const t = mkTemplate();
    const idem = new CreationIdempotencyStore(kernel);
    const first = kDispatch(t.id, "evt-revoked", idem).mission;
    const before = snapshot(first);
    store.revoke(t.id);
    kClock = T0 + R - 1;
    expect(kDispatch(t.id, "evt-revoked", idem).mission.id).toBe(first.id);
    kClock = T0 + R + 1;
    const committed = kernel.allMissions().length;
    let refused: unknown;
    try {
      kDispatch(t.id, "evt-revoked", idem);
    } catch (e) {
      refused = e;
    }
    expect((refused as DispatchError).reason).toBe("template_not_active");
    expect(kernel.allMissions().length).toBe(committed);
    expect(snapshot(first)).toBe(before);
  });

  it(`a requested Mission expiry that passed at the horizon is refused for the reuse after it, creating nothing, while the retry before it recovers ${TAG}`, () => {
    const t = mkTemplate();
    const idem = new CreationIdempotencyStore(kernel);
    const intent = kIntent(new Date(T0 + R).toISOString());
    const first = kDispatch(t.id, "evt-expiry", idem, { intent }).mission;
    const before = snapshot(first);
    kClock = T0 + R;
    expect(kDispatch(t.id, "evt-expiry", idem, { intent }).mission.id).toBe(first.id);
    kClock = T0 + R + 1;
    const committed = kernel.allMissions().length;
    expect(() => kDispatch(t.id, "evt-expiry", idem, { intent })).toThrow(ExpiryPassedError);
    expect(kernel.allMissions().length).toBe(committed);
    expect(idem.find("orchestrator", "evt-expiry")).toBeUndefined();
    expect(snapshot(first)).toBe(before);
  });
});

// ---------------------------------------------------------------------------
// Part A (continued): one approval event, at most one Mission, after any horizon.
// ---------------------------------------------------------------------------

describe(`direct approval: one approval_event_id never yields a second Mission ${TAG}`, () => {
  const approveInput = (approvalEventId: string, goal = "reconcile Acme") => ({
    intent: validateMissionIntent(
      JSON.stringify({ goal, target_resources: [KRESOURCE], expires_at: "2027-01-01T00:00:00Z" }),
      { now: kNow() },
    ),
    subject: { iss: ISS, sub: "alice" },
    approver: { iss: ISS, sub: "bob" },
    clientId: "worker",
    approvalEventId,
  });

  it(`a decision replayed past every request-key horizon, after its Mission was revoked, returns that Mission and creates none ${TAG}`, () => {
    const m = kernel.approve(approveInput("apev-direct-1"));
    kernel.transition(m.id, "revoke");
    kClock = T0 + R + 86_400_000;
    const committed = kernel.allMissions().length;
    const replay = kernel.approve(approveInput("apev-direct-1"));
    expect(replay.id).toBe(m.id);
    expect(replay.state).toBe("terminated");
    // A replay carrying another task still resolves to the one Mission.
    expect(kernel.approve(approveInput("apev-direct-1", "another task")).id).toBe(m.id);
    expect(kernel.allMissions().length).toBe(committed);
  });

  it(`a fresh record reusing a committed approval_event_id is refused by the store's uniqueness, never inserted ${TAG}`, () => {
    const m = kernel.approve(approveInput("apev-direct-2"));
    kClock = T0 + R + 1;
    const committed = kernel.allMissions().length;
    const forged: MissionRecord = { ...m, id: `${m.id}x`, grant_id: null, status_list_idx: null, created_at: kNow().toISOString() };
    expect(() =>
      kernel.insertRecord(forged, undefined, { source: { inherited: kernel.committedSourceBinding(m.id) }, audiences: "fresh" }),
    ).toThrow(UniqueViolationError);
    expect(kernel.allMissions().length).toBe(committed);
  });
});

describe(`Deferred Mission Approval: the pending approval's event yields one Mission after any horizon ${TAG}`, () => {
  const DANA = { iss: ISS, sub: "dana" };
  const SUBJECT = { iss: ISS, sub: "svc-reconciler" };
  const readEntry = (): AuthorityEntry => ({
    type: "mission_resource_access",
    resource: KRESOURCE,
    actions: ["payments:invoice.list", "payments:invoice.read", "payments:vendor.read"],
    constraints: { vendors: ["acme"] },
  });
  const rootDoc: GovernedPolicyRoot = {
    admits: { clients: ["svc-agent"], subjects: ["svc-reconciler"], authority_sources: ["service_owned"] },
    authority_ceiling: [readEntry()],
    lifetime: { max_lifetime_s: 3600 },
    rules: { max_entries: 3 },
    recency: { ceilings: { default: 30 * 86400 }, clock_skew_s: 60 },
    classification: {
      standard: [
        "payments:invoice.list",
        "payments:invoice.read",
        "payments:vendor.read",
        "payments:payment.schedule",
        "payments:payment.schedule.cancel",
      ],
      irreversible_action: ["payments:payment.execute"],
      external_commitment: ["payments:remittance.send"],
    },
  };
  const catalog: AuthoritySourceCatalog = {
    humanPrincipals: ["alice", "bob", "dana"],
    entries: [
      {
        id: "reconciler",
        type: "service_owned",
        clients: ["svc-agent"],
        subjects: ["svc-reconciler"],
        activators: ["dana"],
        principals: ["svc-reconciler"],
        ceiling: DERIVATION_POLICY.ceiling as never,
      },
    ],
  } as AuthoritySourceCatalog;
  const setup = () => {
    const k = new MissionKernel({
      issuer: ISS,
      policy: DERIVATION_POLICY as never,
      statusKey,
      statusKid: "as-status",
      authoritySourceCatalog: catalog as never,
      governedPolicyApproval: {
        roots: { "urn:root:reconciler": { version: "1", content_type: "application/json", content: JSON.stringify(rootDoc) } as RegisteredActivationPolicy },
        approvers: { "urn:root:reconciler": ["dana"] },
      },
      now: kNow,
    });
    const consent = recordGovernedPolicyConsent(k, {
      root: { id: "urn:root:reconciler", version: "1" },
      approver: DANA,
      consentEventId: `gpce-${tmplSeq++}`,
    });
    return { k, consent, deferrals: new MissionApprovalDeferralStore(k, { now: kNow }) };
  };
  const openPending = (deferrals: MissionApprovalDeferralStore) =>
    deferrals.open({
      intent: validateMissionIntent(
        JSON.stringify({ goal: "Reconcile Acme invoices", target_resources: [KRESOURCE], expires_at: "2027-01-01T00:00:00Z" }),
        { now: kNow() },
      ),
      clientId: "svc-agent",
      jkt: "jkt-svc-agent",
    }).deferral_code;

  it(`a policy-completed approval, completed again, approved directly, or re-activated under its event past the pending lifetime and every request-key horizon, yields its one Mission ${TAG}`, async () => {
    const { k, consent, deferrals } = setup();
    const code = openPending(deferrals);
    const done = await deferrals.completeByPolicy(code);
    if (done.outcome !== "approved") throw new Error(`not approved: ${JSON.stringify(done)}`);
    const event = deferrals.approvalEventId(code) as string;
    expect(done.mission.approval_event_id).toBe(event);
    kClock = T0 + 600_000 + R + 1;
    const again = await deferrals.completeByPolicy(code);
    expect(again.outcome === "approved" ? again.mission.id : again.outcome).toBe(done.mission.id);
    expect(() => deferrals.approveDirect(code, { approver: DANA, subject: SUBJECT })).toThrow(MissionApprovalDeferralError);
    // The activation itself, replayed under the same event (even for another
    // task), resolves to the committed Mission and evaluates nothing again.
    for (const goal of ["Reconcile Acme invoices", "another task"]) {
      const replayed = activateGovernedPolicy(k, {
        approvalEventId: event,
        consentId: consent.consent_id,
        intent: validateMissionIntent(
          JSON.stringify({ goal, target_resources: [KRESOURCE], expires_at: "2027-01-01T00:00:00Z" }),
          { now: kNow() },
        ),
        clientId: "svc-agent",
      });
      expect(replayed.mission.id).toBe(done.mission.id);
    }
    expect(k.allMissions()).toHaveLength(1);
    expect(k.allMissions().filter((m) => m.approval_event_id === event)).toHaveLength(1);
  });

  it(`a directly approved pending approval admits no second approval or policy completion past the horizon ${TAG}`, async () => {
    const { k, deferrals } = setup();
    const code = openPending(deferrals);
    const m = deferrals.approveDirect(code, { approver: DANA, subject: SUBJECT });
    kClock = T0 + 600_000 + R + 1;
    expect(() => deferrals.approveDirect(code, { approver: DANA, subject: SUBJECT })).toThrow(MissionApprovalDeferralError);
    expect(await deferrals.completeByPolicy(code)).toEqual({ outcome: "not_pending", state: "approved" });
    expect(k.allMissions().map((x) => x.id)).toEqual([m.id]);
  });
});

// ===========================================================================
// Part B: the token endpoint of one assembly, its kernel clock pinned per case.
// ===========================================================================

const PORT = 14946;
const ISSUER = `http://localhost:${PORT}`;
const RESOURCE = CANONICAL_RESOURCE;
const REDIRECT_URI = "http://localhost:9999/cb";
const FAR_EXP = "2027-01-01T00:00:00Z";
/** The Part B kernel clock: real time unless a case pins it. Roots are issued unpinned. */
let pinned: number | undefined;
const asNow = () => new Date(pinned ?? Date.now());

type DpopKeys = { privateKey: CryptoKey; publicKey: CryptoKey };
type Client = { id: string; kid: string; key: CryptoKey; dpop: DpopKeys };

let as: BuiltAs;
let server: Server | undefined;
let ap: Client;
let verifierSeq = 0;
const commits: LifecycleCommit[] = [];
const sessions = new ApprovalSessionStore();

/** What the Approver consents on the approval surface beside the Mission. */
type CeilingDecision = { authority_ceiling: AuthorityEntry[]; drawdown_policy?: { id: string; version: string } };
let currentOffer: CeilingDecision | undefined;
const PUBLISHED = progressiveFromProfile(PROGRESSIVE_PROFILE);
const PROGRESSIVE: ProgressiveDrawdownOptions = { ...PUBLISHED.options, ceilingOffer: () => currentOffer };
const FULL_CEILING = DERIVATION_POLICY.ceiling.filter((e) => e.resource === RESOURCE) as unknown as AuthorityEntry[];
const READ_CEILING = FULL_CEILING.slice(0, 1);
const READ_ACTIONS = new Set(["payments:invoice.list", "payments:invoice.read", "payments:vendor.read"]);
const READ = ["payments:invoice.read"];
const READ_LIST = ["payments:invoice.read", "payments:invoice.list"];
const SCHEDULE = [...READ_LIST, "payments:payment.schedule"];

/** The proposal: read actions under the vendor constraint, amount-bearing ones also under max_amount. */
const authority = (actions: string[], extra: Record<string, unknown> = {}) => {
  const reads = actions.filter((a) => READ_ACTIONS.has(a));
  const writes = actions.filter((a) => !READ_ACTIONS.has(a));
  return [
    ...(reads.length ? [{ type: "mission_resource_access", resource: RESOURCE, actions: reads, constraints: { vendors: ["acme"] }, ...extra }] : []),
    ...(writes.length
      ? [
          {
            type: "mission_resource_access",
            resource: RESOURCE,
            actions: writes,
            constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
            ...extra,
          },
        ]
      : []),
  ];
};

const intentJson = (goal: string): string =>
  JSON.stringify({ intent: { goal, target_resources: [RESOURCE], expires_at: FAR_EXP } });

async function clientAssertion(client: Client): Promise<string> {
  return new SignJWT({})
    .setProtectedHeader({ alg: "ES256", kid: client.kid })
    .setIssuer(client.id)
    .setSubject(client.id)
    .setAudience(ISSUER)
    .setIssuedAt()
    .setExpirationTime("2m")
    .setJti(crypto.randomUUID())
    .sign(client.key);
}

async function dpopProof(client: Client, htu: string, extra: Record<string, unknown> = {}): Promise<string> {
  return new SignJWT({ htu, htm: "POST", ...extra })
    .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: await exportJWK(client.dpop.publicKey) })
    .setIssuedAt()
    .setJti(crypto.randomUUID())
    .sign(client.dpop.privateKey);
}

/** POST /token as `client` (private_key_jwt + DPoP), with the dpop-nonce retry. */
async function tokenRequest(params: Record<string, string>, client: Client = ap): Promise<Response> {
  const htu = `${ISSUER}/token`;
  const post = async (extra: Record<string, unknown> = {}): Promise<Response> =>
    fetch(htu, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", dpop: await dpopProof(client, htu, extra) },
      body: new URLSearchParams({
        ...params,
        client_assertion: await clientAssertion(client),
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      }).toString(),
    });
  let res = await post();
  const nonce = res.headers.get("dpop-nonce");
  if (res.status === 400 && nonce) res = await post({ nonce });
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

/** The offer the approval page renders, assembled from this assembly's configuration, which the decision posts. */
function renderedOfferOf(ceiling: CeilingDecision | undefined): CeilingDecision | undefined {
  if (!ceiling) return undefined;
  return (assembledCeilingOffer(ceiling, as.kernel.resourceContracts()) as CeilingDecision | undefined) ?? ceiling;
}

/** PAR, approval (consenting `ceiling` when given), code, token: an ACTIVE Mission and its DPoP-bound access token. */
async function issueMission(
  actions: string[],
  ceiling: CeilingDecision | undefined,
  proposal?: Record<string, unknown>[],
): Promise<{ missionId: string; accessToken: string }> {
  currentOffer = ceiling;
  const jar = new Map<string, string>();
  const verifier = `event-identity-verifier-0123456789-0123456789-${verifierSeq++}`;
  const challenge = Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))).toString("base64url");
  const par = await fetch(`${ISSUER}/request`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: ap.id,
      response_type: "code",
      redirect_uri: REDIRECT_URI,
      resource: RESOURCE,
      code_challenge: challenge,
      code_challenge_method: "S256",
      login_hint: "alice",
      mission_intent: intentJson("Pay Acme invoices"),
      authorization_details: JSON.stringify(proposal ?? authority(actions)),
      client_assertion: await clientAssertion(ap),
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    }).toString(),
  });
  const parBody = (await par.json()) as { request_uri: string };
  expect(par.status, JSON.stringify(parBody)).toBe(201);
  let res = await fetch(`${ISSUER}/auth?${new URLSearchParams({ client_id: ap.id, request_uri: parBody.request_uri })}`, {
    redirect: "manual",
  });
  storeCookies(res, jar);
  let location = res.headers.get("location") as string;
  const uid = location.split("/interaction/")[1] as string;
  const decideHeaders = floorApprovalHeaders(sessions, uid, cookieHeader(jar));
  const render_revision = await renderedRevision(ISSUER, uid, decideHeaders);
  res = await fetch(`${ISSUER}/interaction/${uid}/decide`, {
    method: "POST",
    redirect: "manual",
    headers: { ...decideHeaders, "content-type": "application/json" },
    body: JSON.stringify({ decision: "approve", render_revision, ...(renderedOfferOf(ceiling) ?? {}) }),
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

const ceilingOf = (policyId = "drawdown-std", authorityCeiling = FULL_CEILING): CeilingDecision => ({
  authority_ceiling: authorityCeiling,
  drawdown_policy: { id: policyId, version: "1" },
});

/** An expansion token exchange (a drawdown when the predecessor carries a ceiling, else a deferred fresh approval). */
const expansionParams = (subjectToken: string, crid: string, actions: string[], goal = "Widen the invoice work"): Record<string, string> => ({
  grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
  subject_token: subjectToken,
  subject_token_type: ACCESS_TOKEN_TOKEN_TYPE,
  requested_token_type: ACCESS_TOKEN_TOKEN_TYPE,
  creation_request_id: crid,
  completion_mode: "deferred",
  mission_intent: intentJson(goal),
  authorization_details: JSON.stringify(authority(actions)),
});

/** A child creation token exchange naming the shipped child actor. */
const childParams = (subjectToken: string, crid: string, goal = "Extract Acme invoices"): Record<string, string> => ({
  grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
  subject_token: subjectToken,
  subject_token_type: ACCESS_TOKEN_TOKEN_TYPE,
  requested_token_type: JWT_TOKEN_TYPE,
  creation_request_id: crid,
  mission_intent: intentJson(goal),
  authorization_details: JSON.stringify(authority(READ)),
  child_actor: JSON.stringify({ sub: "subagent-extractor", sub_profile: "ai_agent" }),
});

type Body = {
  access_token?: string;
  mission_id?: string;
  error?: string;
  error_description?: string;
  mission_denial_reason?: string;
  mission_error?: string;
  deferral_code?: string;
};

async function send(params: Record<string, string>): Promise<{ status: number; body: Body }> {
  const res = await tokenRequest(params);
  return { status: res.status, body: (await res.json()) as Body };
}

/** Expect a 200 creation response and return its body. */
async function created(params: Record<string, string>): Promise<Body & { mission_id: string }> {
  const { status, body } = await send(params);
  expect(status, JSON.stringify(body)).toBe(200);
  return body as Body & { mission_id: string };
}

/** The activating commits (creation events) published for a Mission. */
const activatingCommits = (missionId: string): LifecycleCommit[] =>
  commits.filter((c) => c.id === missionId && c.version === 1 && c.prior_state === undefined && c.state === "active");

const reservation = (key: string) => as.creationIdempotency.find(ap.id, key);

/** Every expansion deferral opened under one creation_request_id. */
const deferralsUnder = (crid: string) =>
  as.kernel.db
    .prepare("SELECT deferral_code, state FROM expansion_deferrals WHERE client_id = ? AND creation_request_id = ? ORDER BY created_at")
    .all(ap.id, crid) as Array<{ deferral_code: string; state: string }>;

/**
 * Hold `n` concurrent requests after their reservation lookup until all have
 * passed it, so they reach the creation commit together (every path awaits
 * Intent Submission Evidence verification between the two).
 */
async function concurrently(n: number, request: () => Promise<Response>): Promise<Array<{ status: number; body: Body }>> {
  let arrived = 0;
  let release: () => void = () => {};
  const gate = new Promise<void>((r) => {
    release = r;
  });
  const verify = as.kernel.verifySubmissionEvidence.bind(as.kernel);
  const hold = vi.spyOn(as.kernel, "verifySubmissionEvidence").mockImplementation(async (input) => {
    arrived += 1;
    if (arrived === n) release();
    await gate;
    return verify(input);
  });
  try {
    const responses = await Promise.all(Array.from({ length: n }, request));
    expect(arrived).toBe(n);
    return await Promise.all(responses.map(async (r) => ({ status: r.status, body: (await r.json()) as Body })));
  } finally {
    hold.mockRestore();
  }
}

beforeAll(async () => {
  as = await buildAuthorizationServer({
    issuer: ISSUER,
    now: asNow,
    approvalSessions: sessions,
    activationPolicies: PUBLISHED.policies,
    actorProfiles: aiAgents("subagent-extractor"),
    onLifecycleCommit: (c) => commits.push(c),
    progressive: PROGRESSIVE,
    allowHeadlessAdjudication: true,
    serviceTokenPrincipals: TEST_APPROVAL_PRINCIPALS,
  });
  server = as.provider.listen(PORT);
  const key = (await importJWK(as.agentClientJwk as never, "ES256")) as CryptoKey;
  ap = { id: "ap-agent", kid: "ap-agent-auth", key, dpop: await generateKeyPair("ES256", { extractable: true }) };
});

afterEach(() => {
  pinned = undefined;
});

afterAll(() => {
  server?.close();
});

describe(`Progressive drawdown: the creation_request_id horizon at its boundary ${TAG}`, () => {
  it(`retains the key 1 ms before and exactly at reservation + horizon (recovering the successor and its approval_event_id) and frees it 1 ms after, when the same request is a new operation judged on current state ${TAG}`, async () => {
    const root = await issueMission(READ, ceilingOf());
    const crid = crypto.randomUUID();
    pinned = Date.now();
    const first = await created(expansionParams(root.accessToken, crid, READ_LIST));
    const successor = as.kernel.get(first.mission_id) as MissionRecord;
    const op = reservation(crid);
    // The horizon starts at the reservation insert, inside the drawdown's
    // creation transaction: the successor's own creation instant.
    expect(op?.createdAt).toBe(pinned);
    expect(Date.parse(successor.created_at)).toBe(pinned);
    expect(op?.expiresAt).toBe(pinned + R);
    const horizon = op?.expiresAt as number;
    const before = as.kernel.allMissions().length;

    for (const at of [horizon - 1, horizon]) {
      pinned = at;
      const retry = await created(expansionParams(root.accessToken, crid, READ_LIST));
      expect(retry.mission_id).toBe(successor.id);
      expect(as.kernel.get(retry.mission_id)?.approval_event_id).toBe(successor.approval_event_id);
    }
    expect(as.kernel.allMissions().length).toBe(before);
    expect(activatingCommits(successor.id)).toHaveLength(1);

    // One millisecond later the key is free: the same request is a NEW
    // operation, judged on current state, and its predecessor is superseded.
    pinned = horizon + 1;
    const stale = await send(expansionParams(root.accessToken, crid, READ_LIST));
    expect(stale.status, JSON.stringify(stale.body)).toBe(400);
    expect(stale.body.error).toBe("invalid_request");
    expect(stale.body.mission_error).toBe("superseded");
    expect(as.kernel.allMissions().length).toBe(before);
    expect(reservation(crid)).toBeUndefined();

    // Naming the active successor, the reused key is a new drawdown under a new approval_event_id.
    const reused = await created(expansionParams(first.access_token as string, crid, SCHEDULE));
    const next = as.kernel.get(reused.mission_id) as MissionRecord;
    expect(next.predecessor).toBe(successor.id);
    expect(next.approval_event_id).not.toBe(successor.approval_event_id);
    expect(reservation(crid)?.missionId).toBe(next.id);
    expect(reservation(crid)?.createdAt).toBe(horizon + 1);
    expect(as.kernel.allMissions().length).toBe(before + 1);
  });
});

describe(`Progressive drawdown: concurrent reuse of one expired creation_request_id ${TAG}`, () => {
  it(`four concurrent reuses of an expired key create one successor with one new approval_event_id, and every response names it ${TAG}`, async () => {
    const root = await issueMission(READ, ceilingOf());
    const crid = crypto.randomUUID();
    const first = await created(expansionParams(root.accessToken, crid, READ_LIST));
    pinned = (reservation(crid)?.expiresAt as number) + 1;
    const before = as.kernel.allMissions().length;
    const results = await concurrently(4, () => tokenRequest(expansionParams(first.access_token as string, crid, SCHEDULE)));
    for (const r of results) expect(r.status, JSON.stringify(r.body)).toBe(200);
    const ids = new Set(results.map((r) => r.body.mission_id));
    expect(ids.size).toBe(1);
    const id = [...ids][0] as string;
    expect(id).not.toBe(first.mission_id);
    expect(as.kernel.allMissions().length).toBe(before + 1);
    expect(as.kernel.allMissions().filter((m) => m.predecessor === first.mission_id)).toHaveLength(1);
    expect(activatingCommits(id)).toHaveLength(1);
    expect(as.kernel.get(id)?.approval_event_id).not.toBe(as.kernel.get(first.mission_id)?.approval_event_id);
  });
});

describe(`Progressive drawdown: a changed fingerprint inside the window ${TAG}`, () => {
  it(`1 ms before the horizon a reused key with another task or another predecessor is refused invalid_request and creates nothing; 1 ms after, the changed request is a new drawdown ${TAG}`, async () => {
    const root = await issueMission(READ, ceilingOf());
    const crid = crypto.randomUUID();
    const first = await created(expansionParams(root.accessToken, crid, READ_LIST));
    const horizon = reservation(crid)?.expiresAt as number;
    pinned = horizon - 1;
    const before = as.kernel.allMissions().length;
    for (const params of [
      expansionParams(root.accessToken, crid, READ_LIST, "A different task"),
      expansionParams(first.access_token as string, crid, SCHEDULE),
    ]) {
      const refused = await send(params);
      expect(refused.status, JSON.stringify(refused.body)).toBe(400);
      expect(refused.body.error).toBe("invalid_request");
      expect(refused.body.error_description).toBe("creation_request_id was already used for a different creation request");
    }
    expect(as.kernel.allMissions().length).toBe(before);
    expect(reservation(crid)?.missionId).toBe(first.mission_id);

    pinned = horizon + 1;
    const reused = await created(expansionParams(first.access_token as string, crid, SCHEDULE));
    expect(reused.mission_id).not.toBe(first.mission_id);
    expect(as.kernel.get(reused.mission_id)?.approval_event_id).not.toBe(as.kernel.get(first.mission_id)?.approval_event_id);
  });
});

describe(`Progressive drawdown: a reuse after expiry meets the current checks ${TAG}`, () => {
  it(`a source narrowed since consent does not touch a retry inside the window; after the horizon the reuse is refused access_denied, creating and reserving nothing, and the successor is unchanged ${TAG}`, async () => {
    const root = await issueMission(READ, ceilingOf());
    const crid = crypto.randomUUID();
    const first = await created(expansionParams(root.accessToken, crid, READ_LIST));
    const horizon = reservation(crid)?.expiresAt as number;
    const resolve = as.kernel.resolveCommittedSource.bind(as.kernel);
    const narrowed = vi.spyOn(as.kernel, "resolveCommittedSource").mockImplementation((binding) => {
      const current = resolve(binding);
      return { ...current, entry: { ...current.entry, ceiling: READ_CEILING } };
    });
    let committed = "";
    try {
      pinned = horizon - 1;
      expect((await created(expansionParams(root.accessToken, crid, READ_LIST))).mission_id).toBe(first.mission_id);
      // The recovery re-delivered a token (ordinary issuance); the successor as it now stands.
      committed = JSON.stringify(as.kernel.get(first.mission_id));
      pinned = horizon + 1;
      const before = as.kernel.allMissions().length;
      const refused = await send(expansionParams(first.access_token as string, crid, SCHEDULE));
      expect(refused.status, JSON.stringify(refused.body)).toBe(400);
      expect(refused.body.error).toBe("access_denied");
      expect(as.kernel.allMissions().length).toBe(before);
      expect(reservation(crid)).toBeUndefined();
    } finally {
      narrowed.mockRestore();
    }
    const after = as.kernel.get(first.mission_id) as MissionRecord;
    expect(after.state).toBe("active");
    expect(JSON.stringify(after)).toBe(committed);
  });
});

describe(`Child Delegation: the creation_request_id horizon ${TAG}`, () => {
  it(`retains the key 1 ms before and exactly at reservation + horizon (recovering the child and its approval_event_id) and frees it 1 ms after (a new child, a new approval_event_id) ${TAG}`, async () => {
    const parent = await issueMission(READ, undefined);
    const crid = crypto.randomUUID();
    pinned = Date.now();
    const first = await created(childParams(parent.accessToken, crid));
    const child = as.kernel.get(first.mission_id) as MissionRecord;
    const op = reservation(crid);
    expect(op?.createdAt).toBe(pinned);
    expect(Date.parse(child.created_at)).toBe(pinned);
    expect(op?.expiresAt).toBe(pinned + R);
    const horizon = op?.expiresAt as number;
    const before = as.kernel.allMissions().length;
    for (const at of [horizon - 1, horizon]) {
      pinned = at;
      const retry = await created(childParams(parent.accessToken, crid));
      expect(retry.mission_id).toBe(child.id);
      expect(as.kernel.get(retry.mission_id)?.approval_event_id).toBe(child.approval_event_id);
    }
    expect(as.kernel.allMissions().length).toBe(before);
    pinned = horizon + 1;
    const reused = await created(childParams(parent.accessToken, crid));
    expect(reused.mission_id).not.toBe(child.id);
    expect(as.kernel.get(reused.mission_id)?.approval_event_id).not.toBe(child.approval_event_id);
    expect(as.kernel.allMissions().length).toBe(before + 1);
  });

  it(`four concurrent reuses of an expired key create one child with one new approval_event_id, and every response names it ${TAG}`, async () => {
    const parent = await issueMission(READ, undefined);
    const crid = crypto.randomUUID();
    const first = await created(childParams(parent.accessToken, crid));
    pinned = (reservation(crid)?.expiresAt as number) + 1;
    const before = as.kernel.allMissions().length;
    const results = await concurrently(4, () => tokenRequest(childParams(parent.accessToken, crid)));
    for (const r of results) expect(r.status, JSON.stringify(r.body)).toBe(200);
    const ids = new Set(results.map((r) => r.body.mission_id));
    expect(ids.size).toBe(1);
    const id = [...ids][0] as string;
    expect(id).not.toBe(first.mission_id);
    expect(as.kernel.allMissions().length).toBe(before + 1);
    expect(activatingCommits(id)).toHaveLength(1);
  });

  it(`1 ms before the horizon a reused key with another task is refused invalid_request and creates nothing ${TAG}`, async () => {
    const parent = await issueMission(READ, undefined);
    const crid = crypto.randomUUID();
    const first = await created(childParams(parent.accessToken, crid));
    pinned = (reservation(crid)?.expiresAt as number) - 1;
    const before = as.kernel.allMissions().length;
    const refused = await send(childParams(parent.accessToken, crid, "A different child task"));
    expect(refused.status, JSON.stringify(refused.body)).toBe(400);
    expect(refused.body.error).toBe("invalid_request");
    expect(refused.body.error_description).toBe("creation_request_id was already used for a different creation request");
    expect(as.kernel.allMissions().length).toBe(before);
    expect(reservation(crid)?.missionId).toBe(first.mission_id);
  });

  it(`a parent whose child allowance is spent still recovers the child inside the window; after the horizon the reuse is refused on the current fan-out and creates nothing ${TAG}`, async () => {
    // The policy ceiling admits five children per parent entry.
    const parent = await issueMission(READ, undefined);
    const children = as.kernel.get(parent.missionId)?.authority_set[0]?.delegation?.children as { max_children?: number } | undefined;
    expect(children?.max_children).toBe(5);
    const crid = crypto.randomUUID();
    const first = await created(childParams(parent.accessToken, crid));
    for (let i = 0; i < 4; i += 1) await created(childParams(parent.accessToken, crypto.randomUUID()));
    const committed = JSON.stringify(as.kernel.get(first.mission_id));
    const horizon = reservation(crid)?.expiresAt as number;
    pinned = horizon - 1;
    expect((await created(childParams(parent.accessToken, crid))).mission_id).toBe(first.mission_id);
    pinned = horizon + 1;
    const before = as.kernel.allMissions().length;
    const refused = await send(childParams(parent.accessToken, crid));
    expect(refused.status, JSON.stringify(refused.body)).toBe(400);
    expect(refused.body.error).toBe("invalid_request");
    expect(refused.body.mission_denial_reason).toBe("fanout_exceeded");
    expect(as.kernel.allMissions().length).toBe(before);
    expect(JSON.stringify(as.kernel.get(first.mission_id))).toBe(committed);
    // The refusal is recorded under the key, replayed to a retry inside the new window.
    expect(reservation(crid)?.state).toBe("failed");
    expect((await send(childParams(parent.accessToken, crid))).body).toEqual(refused.body);
  });
});

/** The review surface approves a deferral (the suite's recorded browser login). */
const approveDeferral = (code: string, approvalEventId = `apev-${crypto.randomUUID()}`) =>
  as.expansionDeferrals.approve(code, {
    approver: { iss: ISSUER, sub: "bob" },
    authentication: FIXTURE_BROWSER_LOGIN,
    approvalEventId,
    approvedUntil: FAR_EXP,
  });

/** Open a deferred expansion and return its deferral code. */
async function openDeferral(subjectToken: string, crid: string, goal?: string): Promise<string> {
  const { status, body } = await send(expansionParams(subjectToken, crid, READ_LIST, goal));
  expect(status, JSON.stringify(body)).toBe(400);
  expect(body.error).toBe("authorization_pending");
  return body.deferral_code as string;
}

describe(`Expansion (deferred): the horizon runs from initiation ${TAG}`, () => {
  it(`a key reserved at initiation and completed later keeps its initiation horizon: retained at it, free 1 ms after, when the same request is judged on current state and creates nothing ${TAG}`, async () => {
    const root = await issueMission(READ, undefined);
    const crid = crypto.randomUUID();
    const t = Date.now();
    pinned = t;
    const code = await openDeferral(root.accessToken, crid);
    expect(reservation(crid)?.state).toBe("reserved");
    expect(reservation(crid)?.createdAt).toBe(t);
    pinned = t + 5_000;
    expect(approveDeferral(code)).toBe(true);
    pinned = t + 10_000;
    const res = await tokenRequest({ grant_type: DEFERRED_GRANT_TYPE, deferral_code: code });
    const done = (await res.json()) as Body;
    expect(res.status, JSON.stringify(done)).toBe(200);
    const row = reservationRow(as.kernel.db, ap.id, crid);
    expect(row?.state).toBe("completed");
    expect(row?.mission_id).toBe(done.mission_id);
    expect(row?.completed_at).toBe(t + 10_000);
    // Completion did not move the horizon off initiation.
    expect(row?.expires_at).toBe(t + R);
    const before = as.kernel.allMissions().length;
    pinned = t + R;
    expect((await created(expansionParams(root.accessToken, crid, READ_LIST))).mission_id).toBe(done.mission_id);
    pinned = t + R + 1;
    const stale = await send(expansionParams(root.accessToken, crid, READ_LIST));
    expect(stale.status, JSON.stringify(stale.body)).toBe(400);
    expect(stale.body.mission_error).toBe("superseded");
    expect(as.kernel.allMissions().length).toBe(before);
    expect(deferralsUnder(crid)).toHaveLength(1);
  });

  it(`a pending deferral's key reused with another task inside the window is refused invalid_request and opens no second deferral ${TAG}`, async () => {
    const root = await issueMission(READ, undefined);
    const crid = crypto.randomUUID();
    await openDeferral(root.accessToken, crid);
    const refused = await send(expansionParams(root.accessToken, crid, READ_LIST, "A different expansion"));
    expect(refused.status, JSON.stringify(refused.body)).toBe(400);
    expect(refused.body.error).toBe("invalid_request");
    expect(refused.body.error_description).toBe("creation_request_id was already used for a different creation request");
    expect(deferralsUnder(crid)).toHaveLength(1);
  });

  it(`with the shipped horizon, an identical reuse after it is handed the first deferral, long past its lifetime, rather than a new operation; nothing is created ${TAG}`, async () => {
    const root = await issueMission(READ, undefined);
    const crid = crypto.randomUUID();
    const t = Date.now();
    pinned = t;
    const code = await openDeferral(root.accessToken, crid);
    pinned = t + R + 1;
    const before = as.kernel.allMissions().length;
    const reused = await send(expansionParams(root.accessToken, crid, READ_LIST));
    expect(reused.status, JSON.stringify(reused.body)).toBe(400);
    expect(reused.body.error).toBe("authorization_pending");
    // Observed: the coalescing lookup in ExpansionDeferralStore.open ignores
    // the deferral lifetime, so the reuse is answered with the dead handle.
    expect(reused.body.deferral_code).toBe(code);
    const poll = await send({ grant_type: DEFERRED_GRANT_TYPE, deferral_code: code });
    expect(poll.body.error).toBe("expired_token");
    expect(as.kernel.allMissions().length).toBe(before);
    expect(deferralsUnder(crid)).toHaveLength(1);
  });
});

describe(`Expansion (deferred): a horizon that elapses while the operation is still pending ${TAG}`, () => {
  /** A deployment whose published horizon (60 s) is shorter than the deferral lifetime (600 s): the key lapses mid-ceremony. */
  const lapseKeyAfter60s = (crid: string): void => {
    const createdAt = reservation(crid)?.createdAt as number;
    as.kernel.db
      .prepare("UPDATE creation_idempotency SET expires_at = ? WHERE client_id = ? AND creation_request_id = ?")
      .run(createdAt + 60_000, ap.id, crid);
    pinned = createdAt + 60_001;
  };

  it(`an identical reuse while the deferral awaits the Approver joins the pending deferral and opens no second one ${TAG}`, async () => {
    const root = await issueMission(READ, undefined);
    const crid = crypto.randomUUID();
    pinned = Date.now();
    const code = await openDeferral(root.accessToken, crid);
    lapseKeyAfter60s(crid);
    const reused = await send(expansionParams(root.accessToken, crid, READ_LIST));
    expect(reused.status, JSON.stringify(reused.body)).toBe(400);
    expect(reused.body.error).toBe("authorization_pending");
    expect(reused.body.deferral_code).toBe(code);
    expect(deferralsUnder(crid)).toHaveLength(1);
  });

  it(`whatever a key that lapsed mid-ceremony admits, approving and polling every deferral under it yields at most one successor ${TAG}`, async () => {
    const root = await issueMission(READ, undefined);
    const crid = crypto.randomUUID();
    pinned = Date.now();
    const code = await openDeferral(root.accessToken, crid);
    lapseKeyAfter60s(crid);
    await send(expansionParams(root.accessToken, crid, READ_LIST, "A different expansion"));
    const codes = deferralsUnder(crid).map((d) => d.deferral_code);
    expect(codes).toContain(code);
    const before = as.kernel.allMissions().length;
    for (const c of codes) approveDeferral(c);
    const polls: Array<{ status: number; body: Body }> = [];
    for (const c of codes) polls.push(await send({ grant_type: DEFERRED_GRANT_TYPE, deferral_code: c }));
    expect(polls.filter((p) => p.status === 200)).toHaveLength(1);
    const successors = as.kernel.allMissions().filter((m) => m.predecessor === root.missionId);
    expect(successors).toHaveLength(1);
    expect(as.kernel.allMissions().length).toBe(before + 1);
  });
});

/** POST /templates (the service-token admin plane): a read-only template ap-agent may dispatch from. */
async function createDispatchTemplate(): Promise<string> {
  const res = await fetch(`${ISSUER}/templates`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-service-token": DEV_SERVICE_TOKEN },
    body: JSON.stringify({ ...demoReconciliationTemplate(ISSUER), approval_event_id: `tmpl-evt-${crypto.randomUUID()}` }),
  });
  const body = (await res.json()) as { template_id: string };
  expect(res.status, JSON.stringify(body)).toBe(201);
  return body.template_id;
}

const dispatchParams = (templateId: string, dispatchEventId: string, goal = "reconcile Acme invoices"): Record<string, string> => ({
  grant_type: MISSION_DISPATCH_GRANT_TYPE,
  template_id: templateId,
  mission_intent: intentJson(goal),
  dispatch_event_id: dispatchEventId,
});

describe(`Template Dispatch at the token endpoint: the dispatch_event_id horizon ${TAG}`, () => {
  it(`1 ms before the horizon a reused dispatch_event_id with another task is refused invalid_request; four concurrent reuses after it create one instance under one new approval_event_id ${TAG}`, async () => {
    const templateId = await createDispatchTemplate();
    const evt = `evt-${crypto.randomUUID()}`;
    pinned = Date.now();
    const first = await created(dispatchParams(templateId, evt));
    const op = reservation(evt);
    expect(op?.createdAt).toBe(pinned);
    expect(Date.parse(as.kernel.get(first.mission_id)?.created_at as string)).toBe(pinned);
    const horizon = op?.expiresAt as number;
    expect(horizon).toBe(pinned + R);

    pinned = horizon - 1;
    const before = as.kernel.allMissions().length;
    const refused = await send(dispatchParams(templateId, evt, "another task"));
    expect(refused.status, JSON.stringify(refused.body)).toBe(400);
    expect(refused.body.error).toBe("invalid_request");
    expect(refused.body.error_description).toBe(`dispatch_event_id ${evt} was already used for a different dispatch request`);
    // At the horizon the key is still retained: the retry is answered for the
    // committed instance, which outlived its 900 s lifetime, so the delivery
    // gate refuses it (the Dispatch path's own replay semantics) and nothing
    // new is created.
    pinned = horizon;
    const retained = await send(dispatchParams(templateId, evt));
    expect(retained.status, JSON.stringify(retained.body)).toBe(400);
    expect(retained.body.error).toBe("invalid_grant");
    expect(retained.body.mission_error).toBe("expired");
    expect(as.kernel.allMissions().length).toBe(before);
    expect(reservation(evt)?.missionId).toBe(first.mission_id);

    // The Dispatch grant runs one request per (Dispatcher, dispatch_event_id)
    // at a time in this process (provider.ts serializeDispatch), so the four
    // are not held at a common point: the later ones wait, then recover.
    pinned = horizon + 1;
    const results = await Promise.all(
      Array.from({ length: 4 }, async () => {
        const res = await tokenRequest(dispatchParams(templateId, evt));
        return { status: res.status, body: (await res.json()) as Body };
      }),
    );
    for (const r of results) expect(r.status, JSON.stringify(r.body)).toBe(200);
    const ids = new Set(results.map((r) => r.body.mission_id));
    expect(ids.size).toBe(1);
    const id = [...ids][0] as string;
    expect(id).not.toBe(first.mission_id);
    expect(as.kernel.allMissions().length).toBe(before + 1);
    expect(activatingCommits(id)).toHaveLength(1);
    expect(as.kernel.get(id)?.approval_event_id).not.toBe(as.kernel.get(first.mission_id)?.approval_event_id);
    expect(reservation(evt)?.missionId).toBe(id);
  });
});

describe(`Expansion (deferred): an approval event replayed into another Mission ${TAG}`, () => {
  it(`a second deferral approved under an approval_event_id that already created a successor creates no second Mission under it ${TAG}`, async () => {
    const first = await issueMission(READ, undefined);
    const second = await issueMission(READ, undefined);
    const event = `apev-${crypto.randomUUID()}`;
    const crid = crypto.randomUUID();
    const d1 = await openDeferral(first.accessToken, crid);
    expect(approveDeferral(d1, event)).toBe(true);
    const r1 = await send({ grant_type: DEFERRED_GRANT_TYPE, deferral_code: d1 });
    expect(r1.status, JSON.stringify(r1.body)).toBe(200);
    expect(as.kernel.get(r1.body.mission_id as string)?.approval_event_id).toBe(event);

    // The first operation's request key lapses; the same decision is then
    // presented for another predecessor's deferral.
    as.kernel.db
      .prepare("UPDATE creation_idempotency SET expires_at = 0 WHERE client_id = ? AND creation_request_id = ?")
      .run(ap.id, crid);
    expect(reservation(crid)).toBeUndefined();
    const d2 = await openDeferral(second.accessToken, crypto.randomUUID());
    const before = as.kernel.allMissions().length;
    approveDeferral(d2, event);
    const r2 = await send({ grant_type: DEFERRED_GRANT_TYPE, deferral_code: d2 });
    // Observed: the missions table's approval_event_id uniqueness refuses the
    // insert and the poll answers 500 server_error; nothing is delivered.
    expect(r2.status, JSON.stringify(r2.body)).not.toBe(200);
    expect(r2.body.access_token).toBeUndefined();
    expect(as.kernel.allMissions().length).toBe(before);
    expect(as.kernel.allMissions().filter((m) => m.approval_event_id === event)).toHaveLength(1);
    expect(as.kernel.allMissions().filter((m) => m.predecessor === second.missionId)).toHaveLength(0);
    expect(as.kernel.get(second.missionId)?.state).toBe("active");
  });
});

describe(`Expansion (deferred): a lapsed key never starts a second operation while the first is pending (expected to fail today) ${TAG}`, () => {
  /** A deployment whose published horizon (60 s) is shorter than the deferral lifetime (600 s): the key lapses mid-ceremony. */
  const lapseKey = (crid: string): void => {
    const createdAt = reservation(crid)?.createdAt as number;
    as.kernel.db
      .prepare("UPDATE creation_idempotency SET expires_at = ? WHERE client_id = ? AND creation_request_id = ?")
      .run(createdAt + 60_000, ap.id, crid);
    pinned = createdAt + 60_001;
  };

  it(`a reuse with another task while the first deferral awaits the Approver opens no second deferral under the key ${TAG}`, async () => {
    const root = await issueMission(READ, undefined);
    const crid = crypto.randomUUID();
    pinned = Date.now();
    const code = await openDeferral(root.accessToken, crid);
    lapseKey(crid);
    const reused = await send(expansionParams(root.accessToken, crid, READ_LIST, "A different expansion"));
    // The pending operation still owns the key: the changed request is
    // refused as a mismatch, or at most joins the pending deferral.
    expect(reused.body.deferral_code === undefined || reused.body.deferral_code === code, JSON.stringify(reused.body)).toBe(true);
    expect(deferralsUnder(crid)).toHaveLength(1);
  });

  it(`an identical reuse after the first deferral was approved, and before its poll completed it, opens no second deferral under the key ${TAG}`, async () => {
    const root = await issueMission(READ, undefined);
    const crid = crypto.randomUUID();
    pinned = Date.now();
    const code = await openDeferral(root.accessToken, crid);
    expect(approveDeferral(code)).toBe(true);
    lapseKey(crid);
    const reused = await send(expansionParams(root.accessToken, crid, READ_LIST));
    expect(reused.body.deferral_code === undefined || reused.body.deferral_code === code, JSON.stringify(reused.body)).toBe(true);
    expect(deferralsUnder(crid)).toHaveLength(1);
  });

  it(`the first deferral's completion never binds its successor to a reservation a changed reuse re-made under the key ${TAG}`, async () => {
    const root = await issueMission(READ, undefined);
    const crid = crypto.randomUUID();
    pinned = Date.now();
    const code = await openDeferral(root.accessToken, crid);
    lapseKey(crid);
    const changed = expansionParams(root.accessToken, crid, READ_LIST, "A different expansion");
    await send(changed);
    expect(approveDeferral(code)).toBe(true);
    const done = await send({ grant_type: DEFERRED_GRANT_TYPE, deferral_code: code });
    expect(done.status, JSON.stringify(done.body)).toBe(200);
    // A retry of the changed request must not be handed the successor the
    // first request's approval created.
    const retry = await send(changed);
    expect(retry.body.mission_id, JSON.stringify(retry.body)).not.toBe(done.body.mission_id);
  });
});
