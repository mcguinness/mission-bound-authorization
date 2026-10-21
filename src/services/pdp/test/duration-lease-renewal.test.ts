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
 */

import { describe, expect, it } from "vitest";
import { createEphemeralDecisionPoint } from "../src/decision-point.js";
import { createDurationLeaseLedger, type DurationLeaseDomain } from "../src/duration-lease.js";
import type { DecisionOptions, EvaluationRequest } from "../src/evaluate.js";
import type { Fga } from "../src/fga.js";
import { MISSION_RESOURCE_ACCESS_TYPE, type MissionView } from "../src/policy-view.js";
import { relationForAction, stalenessBound } from "../src/policy.js";
import { RESOURCE_POLICY_PERMITS_ALL_FIXTURE } from "../src/test-support.js";
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

const alwaysAllowFga = { checkWithContext: async () => true } as unknown as Fga;

/** A Mission whose one `prefix` entry admits both invoices, for both leased actions. */
const view = (id = "msn_lease_a"): MissionView => ({
  id,
  issuer: "https://as.test",
  state: "active",
  version: 1,
  authority_hash: `sha-256:${id}`,
  authority_set: [
    { type: MISSION_RESOURCE_ACCESS_TYPE, resource: INVOICES, resource_match: "prefix", actions: [READ, LIST] },
  ] as MissionView["authority_set"],
  subject: { iss: "https://as.test", sub: "alice" },
  client_id: "ap-agent",
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
  const decide = (req: EvaluationRequest, at: number, mission = "msn_lease_a") => {
    const options: DecisionOptions = {
      view: view(mission),
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
