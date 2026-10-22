/**
 * @spec metering#lease-renewal, metering#metering (`max_duration` rules 3 and
 * 4) (#1440): a duration-lease renewal at the PDP. A permit for a
 * duration-leased action opens one metered activity and expires with its
 * lease; a renewal carrying `context.prior_evaluation_id` continues that
 * activity, opening no second reservation, only when its Mission, subject,
 * action, operation target and audience match the evaluation it names.
 *
 * Decisions go through a decision point whose ledger is bound PDP-side. The
 * FGA layer is a stub that always permits, so only evaluate()'s own steps
 * decide, and this file never skips.
 *
 * #1464 (D606): a renewal never revives an ended activity, is denied
 * `out_of_authority` when it continues nothing, passes every current check,
 * and, for a keyed high-consequence action, carries its own idempotency key
 * claimed with the renewal's identity in a real Exact claim domain. Duration
 * accumulation, the measured-duration commit and settlement are not built.
 */

import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { openDurableStore } from "@mission/store";
import { describe, expect, it } from "vitest";
import { createEphemeralDecisionPoint } from "../src/decision-point.js";
import { createDurationLeaseLedger, type DurationLeaseDomain } from "../src/duration-lease.js";
import type { Decision, DecisionOptions, EvaluationRequest } from "../src/evaluate.js";
import type { Fga } from "../src/fga.js";
import {
  type ClaimRequester,
  type ConsumptionStatusFn,
  type IdempotencyClaimDomain,
  type IndeterminateClaim,
  openIdempotencyClaimDomain,
} from "../src/idempotency-claims.js";
import { MISSION_RESOURCE_ACCESS_TYPE, type MissionView } from "../src/policy-view.js";
import { relationForAction, stalenessBound } from "../src/policy.js";
import { operationIdentity } from "../src/projections.js";
import { RESOURCE_POLICY_PERMITS_ALL_FIXTURE } from "../src/test-support.js";
import { CLAIM_OWNER, freshKey, statementWithPrivilegedAdministration } from "./claim-fixture.js";
import { withCredential } from "./with-credential.js";

const AUDIENCE = "http://localhost:4403/mcp";
const OTHER_AUDIENCE = "http://localhost:4403/mcp-reports";
const INVOICES = `${AUDIENCE}/invoices`;
const INV1 = `${INVOICES}/inv-1`;
const INV2 = `${INVOICES}/inv-2`;
const T0 = Date.parse("2026-10-20T12:00:00Z");
const LEASE_S = 60;
const READ = "payments:invoice.read";
const LIST = "payments:invoice.list";
/** A keyed irreversible action, duration-leased in the keyed cases below. */
const PAY = "payments:payment.execute";
/** Inside the irreversible class's 30 s staleness bound, so the lease end is the permit's valid_until. */
const PAY_LEASE_S = 20;

const alwaysAllowFga = { checkWithContext: async () => true } as unknown as Fga;

/** A Mission whose one `prefix` entry admits both invoices, for every leased action. */
const view = (id = "msn_lease_a", over: Partial<MissionView> = {}): MissionView => ({
  id,
  issuer: "https://as.test",
  state: "active",
  version: 1,
  authority_hash: `sha-256:${id}`,
  authority_set: [
    { type: MISSION_RESOURCE_ACCESS_TYPE, resource: INVOICES, resource_match: "prefix", actions: [READ, LIST, PAY] },
  ] as MissionView["authority_set"],
  subject: { iss: "https://as.test", sub: "alice" },
  client_id: "ap-agent",
  ...over,
});

interface Over {
  mission?: string;
  subject?: string;
  action?: string;
  target?: string;
  audience?: string;
  prior?: unknown;
}

/** A read of an invoice, renewing `prior` when it is given. */
const request = (at: number, over: Over = {}): EvaluationRequest =>
  withCredential({
    subject: { id: over.subject ?? "alice", properties: { iss: "https://as.test" } },
    resource: {
      type: "invoice",
      id: "inv-1",
      properties: { vendor_id: "acme", audience: over.audience ?? AUDIENCE, operation_target: over.target ?? INV1 },
    },
    action: { name: over.action ?? READ },
    context: {
      mission: { id: over.mission ?? "msn_lease_a", issuer: "https://as.test" },
      actor: { client_id: "ap-agent" },
      action_class: "consequential_read",
      mission_state_observation: { state: "active", mode: "fresh", freshness_at: new Date(at).toISOString() },
      ...(over.prior !== undefined ? { prior_evaluation_id: over.prior } : {}),
    },
  } as EvaluationRequest);

function harness() {
  const ledger: DurationLeaseDomain = createDurationLeaseLedger({ [READ]: LEASE_S, [LIST]: LEASE_S });
  const point = createEphemeralDecisionPoint({
    emitterId: "pdp-lease",
    audience: AUDIENCE,
    resourcePolicy: RESOURCE_POLICY_PERMITS_ALL_FIXTURE,
    durationLeases: ledger,
    // The emitter's key is published for both enforcement scopes the audience case uses.
    authorizesAudience: (a) => a === AUDIENCE || a === OTHER_AUDIENCE,
  });
  const decide = (req: EvaluationRequest, at: number, mission = "msn_lease_a", over: Partial<MissionView> = {}) => {
    const options: DecisionOptions = {
      view: view(mission, over),
      fga: alwaysAllowFga,
      modelId: "model-lease",
      now: () => new Date(at),
      stalenessBound,
      relationForAction,
      stateSourcePlacement: "pep",
    };
    return point.decide(req, options);
  };
  /** The initial permit: its evaluation_id, and the activity it opened. */
  const opened = async () => {
    const first = await decide(request(T0), T0);
    expect(first.decision, JSON.stringify(first.context)).toBe(true);
    return first.context.evaluation_id as string;
  };
  return { ledger, decide, opened };
}

describe("a duration-leased permit opens one metered activity that expires with its lease (@spec metering#metering, #1440)", () => {
  it("the initial permit opens an activity leased by it, and its valid_until is the lease's end", async () => {
    const { ledger, decide } = harness();
    const first = await decide(request(T0), T0);
    expect(first.decision, JSON.stringify(first.context)).toBe(true);
    const validUntil = Date.parse((first.context.conditions as { valid_until: string }).valid_until);
    expect(validUntil).toBe(T0 + LEASE_S * 1000);
    expect(ledger.activities()).toEqual([
      { activityId: expect.any(String), evaluations: [first.context.evaluation_id], leaseEndMs: validUntil },
    ]);
  });
});

describe("a duration-lease renewal is verified against the evaluation it renews (@spec metering#lease-renewal, #1440)", () => {
  it("a renewal matching the renewed evaluation in Mission, subject, action, operation target and audience continues the same activity, opening no new reservation, and moves the lease's end", async () => {
    const { ledger, decide, opened } = harness();
    const prior = await opened();
    const at = T0 + 30_000;
    const renewal = await decide(request(at, { prior }), at);
    expect(renewal.decision, JSON.stringify(renewal.context)).toBe(true);
    const validUntil = Date.parse((renewal.context.conditions as { valid_until: string }).valid_until);
    expect(validUntil).toBe(at + LEASE_S * 1000);
    expect(ledger.activities()).toEqual([
      { activityId: expect.any(String), evaluations: [prior, renewal.context.evaluation_id], leaseEndMs: validUntil },
    ]);
    // A renewal of the renewal continues the same activity again.
    const later = T0 + 75_000;
    const again = await decide(request(later, { prior: renewal.context.evaluation_id }), later);
    expect(again.decision, JSON.stringify(again.context)).toBe(true);
    expect(ledger.activities()).toHaveLength(1);
    expect(ledger.activities()[0]?.evaluations).toEqual([prior, renewal.context.evaluation_id, again.context.evaluation_id]);
  });

  /**
   * One mismatched member: the renewal is denied and continues nothing, while
   * the same request without `prior_evaluation_id` is an ordinary permit.
   */
  async function mismatched(over: Omit<Over, "prior">, mission?: string) {
    const { ledger, decide, opened } = harness();
    const prior = await opened();
    const before = ledger.activities();
    const at = T0 + 10_000;
    const control = await decide(request(at, over), at, mission);
    expect(control.decision, JSON.stringify(control.context)).toBe(true);
    const renewal = await decide(request(at, { ...over, prior }), at, mission);
    expect(renewal.decision, JSON.stringify(renewal.context)).toBe(false);
    expect(renewal.context.denial_reason).toBe("out_of_authority");
    // The renewed activity is unchanged: neither continued nor joined.
    expect(ledger.activities()).toContainEqual(before[0]);
    expect(ledger.activities().some((a) => a.evaluations.includes(renewal.context.evaluation_id as string))).toBe(false);
  }

  it("a renewal for another Mission does not continue the activity", async () => {
    await mismatched({ mission: "msn_lease_b" }, "msn_lease_b");
  });

  it("a renewal for another subject does not continue the activity", async () => {
    await mismatched({ subject: "bob" });
  });

  it("a renewal for another action does not continue the activity", async () => {
    await mismatched({ action: LIST });
  });

  it("a renewal at another operation target, though the Mission's prefix entry admits both, does not continue the activity", async () => {
    await mismatched({ target: INV2 });
  });

  it("a renewal for another audience does not continue the activity", async () => {
    await mismatched({ audience: OTHER_AUDIENCE });
  });

  it("a renewal naming no lease this PDP issued, a malformed identifier, or a lease that has ended continues nothing", async () => {
    const { ledger, decide, opened } = harness();
    const prior = await opened();
    for (const [label, renewed, at] of [
      ["unknown", "dec_unknown", T0 + 10_000],
      ["malformed", 42, T0 + 10_000],
      ["ended", prior, T0 + LEASE_S * 1000],
    ] as const) {
      const renewal = await decide(request(at, { prior: renewed }), at);
      expect(renewal.decision, label).toBe(false);
      expect(renewal.context.denial_reason, label).toBe("out_of_authority");
    }
    expect(ledger.activities()).toHaveLength(1);
    expect(ledger.activities()[0]?.evaluations).toEqual([prior]);
  });
});

describe("a renewal never revives an ended activity: the boundary is the activity's current lease (@spec metering#lease-renewal, #1464)", () => {
  it("a renewal through an earlier permit whose own valid_until has passed continues the live activity, and at the activity's current boundary a renewal through any of its permits is denied out_of_authority", async () => {
    const { ledger, decide, opened } = harness();
    const first = await opened();
    // A renewal at T0 + 30 s moves the boundary past the first permit's own expiry (T0 + 60 s).
    const at1 = T0 + 30_000;
    const second = await decide(request(at1, { prior: first }), at1);
    expect(second.decision, JSON.stringify(second.context)).toBe(true);
    // After the first permit expired, before the activity's boundary: the activity is live.
    const at2 = T0 + LEASE_S * 1000 + 5_000;
    const viaFirst = await decide(request(at2, { prior: first }), at2);
    expect(viaFirst.decision, JSON.stringify(viaFirst.context)).toBe(true);
    const [activity] = ledger.activities();
    expect(activity?.evaluations).toEqual([first, second.context.evaluation_id, viaFirst.context.evaluation_id]);
    const boundary = activity?.leaseEndMs as number;
    expect(boundary).toBe(at2 + LEASE_S * 1000);
    // At the boundary the activity has ended, whichever of its permits the renewal names.
    for (const prior of [first, second.context.evaluation_id, viaFirst.context.evaluation_id]) {
      const late = await decide(request(boundary, { prior }), boundary);
      expect(late.decision, String(prior)).toBe(false);
      expect(late.context.denial_reason, String(prior)).toBe("out_of_authority");
    }
    expect(ledger.activities()).toEqual([activity]);
  });
});

describe("a renewal passes every current check, and a failed check keeps its own denial (@spec metering#lease-renewal, #1464)", () => {
  it("a renewal naming a live, matching activity is denied mission_inactive once the Mission is no longer active, and continues nothing", async () => {
    const { ledger, decide, opened } = harness();
    const prior = await opened();
    const before = ledger.activities();
    const at = T0 + 10_000;
    const renewal = await decide(request(at, { prior }), at, "msn_lease_a", { state: "suspended" });
    expect(renewal.decision, JSON.stringify(renewal.context)).toBe(false);
    expect(renewal.context.denial_reason).toBe("mission_inactive");
    expect(ledger.activities()).toEqual(before);
  });

  it("a renewal naming a live, matching activity is denied authority_contained once containment removes the action, and continues nothing", async () => {
    const { ledger, decide, opened } = harness();
    const prior = await opened();
    const before = ledger.activities();
    const at = T0 + 10_000;
    const contained = { containment: { version: 2, contained: [{ resource: INVOICES, actions: [READ] }] } };
    const renewal = await decide(request(at, { prior }), at, "msn_lease_a", contained);
    expect(renewal.decision, JSON.stringify(renewal.context)).toBe(false);
    expect(renewal.context.denial_reason).toBe("authority_contained");
    expect(ledger.activities()).toEqual(before);
  });
});

/** The authenticated PEP the keyed decisions are issued to. */
const REQUESTER: ClaimRequester = { pep_id: "mcp-payments-pep", pep_epoch: "epoch-1464" };

/** A keyed, irreversible payment at INV1 under `key`, renewing `prior` when it is given. */
const keyedRequest = (at: number, key: string | undefined, over: { prior?: string; digest?: string } = {}): EvaluationRequest =>
  withCredential({
    subject: { id: "alice", properties: { iss: "https://as.test" } },
    resource: {
      type: "invoice",
      id: "inv-1",
      properties: { vendor_id: "acme", audience: AUDIENCE, operation_target: INV1 },
    },
    action: { name: PAY, ...(key !== undefined ? { properties: { idempotency_key: key } } : {}) },
    context: {
      mission: { id: "msn_lease_a", issuer: "https://as.test" },
      actor: { client_id: "ap-agent" },
      action_class: "irreversible_action",
      parameter_digest: over.digest ?? "sha-256:pay-inv-1",
      mission_state_observation: { state: "active", mode: "fresh", freshness_at: new Date(at).toISOString() },
      ...(over.prior !== undefined ? { prior_evaluation_id: over.prior } : {}),
    },
  } as EvaluationRequest);

/**
 * A decision point leasing the keyed payment, with a real Exact claim domain
 * on a fresh file, deciding for one authenticated PEP whose redemption store
 * answers `consumption`.
 */
function keyedHarness(
  consumption: ConsumptionStatusFn = () => "unconsumed",
  over: {
    ledger?: DurationLeaseDomain;
    domainNow?: () => Date;
    onIndeterminate?: (c: IndeterminateClaim) => void;
    /** The claim domain as the decision point is bound to it; the real one by default. */
    wrapClaims?: (claims: IdempotencyClaimDomain) => IdempotencyClaimDomain;
  } = {},
) {
  const ledger: DurationLeaseDomain = over.ledger ?? createDurationLeaseLedger({ [PAY]: PAY_LEASE_S });
  const file = join(mkdtempSync(join(tmpdir(), "lease-1464-")), "claims.sqlite");
  const claims = openIdempotencyClaimDomain({
    file,
    owner: CLAIM_OWNER,
    statement: statementWithPrivilegedAdministration(),
    ...(over.domainNow ? { now: over.domainNow } : {}),
    ...(over.onIndeterminate ? { onIndeterminate: over.onIndeterminate } : {}),
  });
  const point = createEphemeralDecisionPoint({
    emitterId: "pdp-lease",
    audience: AUDIENCE,
    resourcePolicy: RESOURCE_POLICY_PERMITS_ALL_FIXTURE,
    durationLeases: ledger,
    claims: over.wrapClaims ? over.wrapClaims(claims) : claims,
  });
  const decideFor = point.decideAs(REQUESTER, consumption);
  const decide = (req: EvaluationRequest, at: number): Promise<Decision> =>
    decideFor(req, {
      view: view(),
      fga: alwaysAllowFga,
      modelId: "model-lease",
      now: () => new Date(at),
      stalenessBound,
      relationForAction,
      stateSourcePlacement: "pep",
    });
  /** The initial permit under `key`: its evaluation_id. */
  const opened = async (key: string) => {
    const first = await decide(keyedRequest(T0, key), T0);
    expect(first.decision, JSON.stringify(first.context)).toBe(true);
    return first.context.evaluation_id as string;
  };
  return { ledger, claims, file, decide, opened };
}

/** The claim rows, read from the file after the domain released it, through the same single-writer opener. */
function claimRowsOf(file: string): Array<{ evaluation_id: string; state: string; outcome: string | null }> {
  const db = openDurableStore({ file, migrations: ["-- claims schema v1", "-- claims schema v2"], owner: CLAIM_OWNER });
  try {
    return db.prepare("SELECT evaluation_id, state, outcome FROM claims ORDER BY claimed_at_ms").all() as Array<{
      evaluation_id: string;
      state: string;
      outcome: string | null;
    }>;
  } finally {
    db.close();
  }
}

const validUntilOf = (d: Decision): number => Date.parse((d.context.conditions as { valid_until: string }).valid_until);

describe("a keyed renewal carries its own idempotency key, claimed with the renewal's identity (@spec metering#lease-renewal, runtime#idempotency, #1464)", () => {
  it("a keyed high-consequence renewal under a fresh key is permitted, single use, and continues the activity, moving its lease's end", async () => {
    const { ledger, claims, decide, opened } = keyedHarness();
    const prior = await opened(freshKey());
    const at = T0 + 10_000;
    const renewal = await decide(keyedRequest(at, freshKey(), { prior }), at);
    expect(renewal.decision, JSON.stringify(renewal.context)).toBe(true);
    expect((renewal.context.conditions as { use_limit?: number }).use_limit).toBe(1);
    expect(validUntilOf(renewal)).toBe(at + PAY_LEASE_S * 1000);
    expect(ledger.activities()).toEqual([
      { activityId: expect.any(String), evaluations: [prior, renewal.context.evaluation_id], leaseEndMs: validUntilOf(renewal) },
    ]);
    claims.close();
  });

  it("a retransmitted renewal returns the same permit and concurrent duplicates are suppressed: the lease is extended once", async () => {
    const { ledger, claims, decide, opened } = keyedHarness();
    const prior = await opened(freshKey());
    const key = freshKey();
    const at = T0 + 10_000;
    const settled = await Promise.all(Array.from({ length: 8 }, () => decide(keyedRequest(at, key, { prior }), at)));
    const permits = settled.filter((d) => d.decision);
    expect(permits.length).toBeGreaterThanOrEqual(1);
    const renewalId = permits[0]?.context.evaluation_id;
    // Every permit among the duplicates is the one renewal's, returned again.
    expect(permits.every((d) => d.context.evaluation_id === renewalId)).toBe(true);
    for (const d of settled.filter((d) => !d.decision)) expect(d.context.denial_reason).toBe("duplicate_suppressed");
    expect(ledger.activities()[0]?.evaluations).toEqual([prior, renewalId]);
    // A later retransmission of the same renewal, inside its validity, is the stored permit again.
    const later = at + 5_000;
    const again = await decide(keyedRequest(later, key, { prior }), later);
    expect(again.decision, JSON.stringify(again.context)).toBe(true);
    expect(again.context.evaluation_id).toBe(renewalId);
    expect(ledger.activities()).toEqual([
      { activityId: expect.any(String), evaluations: [prior, renewalId], leaseEndMs: at + PAY_LEASE_S * 1000 },
    ]);
    claims.close();
  });

  it("a renewal's key presented for another renewal or for the operation itself, or the operation's key presented on a renewal, is idempotency_conflict and continues nothing", async () => {
    const { ledger, claims, decide, opened } = keyedHarness();
    const k0 = freshKey();
    const prior = await opened(k0);
    const k1 = freshKey();
    const at = T0 + 10_000;
    const renewal = await decide(keyedRequest(at, k1, { prior }), at);
    expect(renewal.decision, JSON.stringify(renewal.context)).toBe(true);
    const renewalId = renewal.context.evaluation_id as string;
    const before = ledger.activities();
    const later = at + 2_000;
    const outcomes: Record<string, unknown[]> = {};
    for (const [label, req] of [
      ["k1 renewing the renewal", keyedRequest(later, k1, { prior: renewalId })],
      ["k1 for the operation itself", keyedRequest(later, k1)],
      ["k1 renewing with other parameters", keyedRequest(later, k1, { prior, digest: "sha-256:pay-inv-1-other" })],
      ["k0 renewing the original", keyedRequest(later, k0, { prior })],
    ] as const) {
      const d = await decide(req, later);
      outcomes[label] = [d.decision, d.context.denial_reason, d.context.next_action];
    }
    const conflict = [false, "idempotency_conflict", "none"];
    expect(outcomes).toEqual({
      "k1 renewing the renewal": conflict,
      "k1 for the operation itself": conflict,
      "k1 renewing with other parameters": conflict,
      "k0 renewing the original": conflict,
    });
    expect(ledger.activities()).toEqual(before);
    claims.close();
  });

  it("a successful renewal continues the original activity and reservation without executing the effect again: the operation keeps its identity, and its own key still refuses a second execution", async () => {
    // The PEP consumed the opening permit: the effect is under way.
    let opening: string | undefined;
    const { ledger, claims, decide, opened } = keyedHarness((id) => (id === opening ? "consumed" : "unconsumed"));
    const k0 = freshKey();
    opening = await opened(k0);
    const [activity] = ledger.activities();
    const at = T0 + 10_000;
    const renewalRequest = keyedRequest(at, freshKey(), { prior: opening });
    const renewal = await decide(renewalRequest, at);
    expect(renewal.decision, JSON.stringify(renewal.context)).toBe(true);
    // The same activity, its opener kept, and no second reservation.
    expect(ledger.activities()).toEqual([
      { activityId: activity?.activityId, evaluations: [opening, renewal.context.evaluation_id], leaseEndMs: validUntilOf(renewal) },
    ]);
    // The resource-side identity of the underlying operation is unchanged by the renewal.
    expect(operationIdentity(renewalRequest)).toBe(operationIdentity(keyedRequest(T0, k0)));
    // The operation's own key still refuses a second execution of the effect.
    const later = at + 2_000;
    const replay = await decide(keyedRequest(later, k0), later);
    expect(replay.decision, JSON.stringify(replay.context)).toBe(false);
    expect(replay.context.denial_reason).toBe("duplicate_suppressed");
    expect(ledger.activities()).toHaveLength(1);
    claims.close();
  });

  it("a keyed renewal carrying no idempotency key is refused parameter_violation, though it names a live, matching activity", async () => {
    const { ledger, claims, decide, opened } = keyedHarness();
    const prior = await opened(freshKey());
    const before = ledger.activities();
    const at = T0 + 10_000;
    const renewal = await decide(keyedRequest(at, undefined, { prior }), at);
    expect(renewal.decision, JSON.stringify(renewal.context)).toBe(false);
    expect(renewal.context.denial_reason).toBe("parameter_violation");
    expect(ledger.activities()).toEqual(before);
    claims.close();
  });
});

/** The shipped statement's execution-lease maximum and reconciliation window for the class. */
const CLASS_LEASE_MS = 30_000;
const WINDOW_MS = 15 * 60_000;

describe("a keyed renewal's claim settles when the PDP commits the lease extension (@spec metering#lease-renewal, runtime#idempotency, #1464)", () => {
  it("the renewal's claim settles completed with no Execution Evidence, never ages to unresolved or indeterminate, raises no operator alert, and its retransmission returns the same permit without extending the lease again", async () => {
    let domainMs = T0;
    const alerts: IndeterminateClaim[] = [];
    const { ledger, claims, file, decide, opened } = keyedHarness(undefined, {
      domainNow: () => new Date(domainMs),
      onIndeterminate: (c) => alerts.push(c),
    });
    // The opening permit's claim is never settled here: it is the control that does age and alert.
    const opening = await opened(freshKey());
    const key = freshKey();
    const at = T0 + 10_000;
    domainMs = at;
    const renewal = await decide(keyedRequest(at, key, { prior: opening }), at);
    expect(renewal.decision, JSON.stringify(renewal.context)).toBe(true);
    const renewalId = renewal.context.evaluation_id as string;
    // After settlement, a retransmission under the same key is the same permit, and the lease moves once.
    const retry = at + 2_000;
    const again = await decide(keyedRequest(retry, key, { prior: opening }), retry);
    expect(again.context.evaluation_id, JSON.stringify(again.context)).toBe(renewalId);
    expect(ledger.activities()[0]?.evaluations).toEqual([opening, renewalId]);
    // Past every permit and lease: the unsettled opening claim is unresolved, the renewal's is not.
    const validUntil = validUntilOf(renewal);
    domainMs = validUntil + CLASS_LEASE_MS + 1_000;
    claims.sweep();
    expect(claims.listUnresolved(REQUESTER).map((c) => c.evaluation_id)).toEqual([opening]);
    // Past every reconciliation window: only the opening claim closes indeterminate and alerts.
    domainMs = validUntil + CLASS_LEASE_MS + WINDOW_MS + 1_000;
    claims.sweep();
    expect(alerts.map((c) => c.evaluation_id)).toEqual([opening]);
    claims.close();
    const rows = claimRowsOf(file);
    expect(rows.find((r) => r.evaluation_id === renewalId)).toEqual({ evaluation_id: renewalId, state: "completed", outcome: "lease_extended" });
    expect(rows.find((r) => r.evaluation_id === opening)?.state).toBe("indeterminate");
  });

  it("a lease commit that fails releases the renewal's claim, so the retry under the same key renews once instead of meeting a held claim", async () => {
    const real = createDurationLeaseLedger({ [PAY]: PAY_LEASE_S });
    let failNext = false;
    const ledger: DurationLeaseDomain = {
      ...real,
      extend: (...args) => {
        if (failNext) {
          failNext = false;
          throw new Error("lease ledger unavailable");
        }
        return real.extend(...args);
      },
    };
    const { claims, decide, opened } = keyedHarness(undefined, { ledger });
    const opening = await opened(freshKey());
    const key = freshKey();
    const at = T0 + 10_000;
    failNext = true;
    await expect(decide(keyedRequest(at, key, { prior: opening }), at)).rejects.toThrow("lease ledger unavailable");
    expect(real.activities()[0]?.evaluations).toEqual([opening]);
    const retry = await decide(keyedRequest(at + 1_000, key, { prior: opening }), at + 1_000);
    expect(retry.decision, JSON.stringify(retry.context)).toBe(true);
    expect(real.activities()[0]?.evaluations).toEqual([opening, retry.context.evaluation_id]);
    claims.close();
  });

  it("a persist that fails after the lease commit leaves the extension applied once: the retry under the same key gets a permit ending at that extension, and the lease end moves exactly once", async () => {
    let failPersist = false;
    const wrapClaims = (real: IdempotencyClaimDomain): IdempotencyClaimDomain =>
      ({
        declares: (c: string | undefined) => real.declares(c),
        retransmit: (...args: Parameters<IdempotencyClaimDomain["retransmit"]>) => real.retransmit(...args),
        claim: async (input: Parameters<IdempotencyClaimDomain["claim"]>[0]) => {
          const outcome = await real.claim(input);
          if (outcome.kind !== "claimed" || !failPersist) return outcome;
          failPersist = false;
          const { ticket } = outcome;
          return {
            kind: "claimed",
            ticket: {
              evaluationId: ticket.evaluationId,
              persist: () => {
                throw new Error("claim store unavailable at persist");
              },
              release: () => ticket.release(),
            },
          };
        },
      }) as unknown as IdempotencyClaimDomain;
    const { ledger, claims, decide, opened } = keyedHarness(undefined, { wrapClaims });
    const opening = await opened(freshKey());
    const key = freshKey();
    const at = T0 + 10_000;
    failPersist = true;
    await expect(decide(keyedRequest(at, key, { prior: opening }), at)).rejects.toThrow("claim store unavailable at persist");
    // The lease commit ran before the persist failed: the extension is applied, though no permit left.
    const extended = at + PAY_LEASE_S * 1000;
    expect(ledger.activities()[0]?.leaseEndMs).toBe(extended);
    const later = at + 3_000;
    const retry = await decide(keyedRequest(later, key, { prior: opening }), later);
    expect(retry.decision, JSON.stringify(retry.context)).toBe(true);
    expect(validUntilOf(retry)).toBe(extended);
    expect(ledger.activities()).toHaveLength(1);
    expect(ledger.activities()[0]?.leaseEndMs).toBe(extended);
    claims.close();
  });
});
