/**
 * @spec metering#retry, metering#aggregate-bounds, metering#settlement-states,
 * metering#metering-evidence, metering#capacity-across-missions (#816, D814,
 * D830): the PDP's exact `max_budget` reservations, kept in the idempotency
 * claim file and debited in the claim's own transaction.
 *
 * Every case runs `evaluate()` (or a decision point over it) against a real
 * claim domain on a real SQLite file in a fresh temporary directory: a
 * "restart" closes the domain and reopens the same file, and concurrency is
 * real interleaving, with every evaluation parked in its Decision Evidence
 * emission after its claim step. The FGA layer is a stub that always
 * permits, so the claim and its reservations are what decide, and this file
 * never skips.
 *
 * Two counters meter every charge: the instance counter (`counter_scope`
 * `mission`, keyed by the first Mission of the successor chain, limited by
 * the instance Intent's `max_budget`) and the shared counter
 * (`standing_consent`, keyed by budget owner and budget id, limited by the
 * approved policy's limit). Amounts are USD at exponent 2, so "1000.00" is
 * 100,000 minor units.
 */

import { generateKeyPairSync, randomUUID } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { type Database, openDurableStore, setCommitGuard } from "@mission/store";
import { describe, expect, it } from "vitest";
import { canonicalDigest } from "@mission/core";
import {
  type BudgetMeteringDeclaration,
  budgetCounterId,
  CLAIM_SETTLEMENT_INTAKE,
  type DispatchPolicyRef,
  type MissionBudgetBinding,
  type MissionBudgetSource,
  UNDERIVABLE_BUDGET,
} from "../src/budget-metering.js";
import { createDecisionChannel } from "../src/decision-channel.js";
import {
  createDecisionEvidenceEmitter,
  type DecisionEvidenceEmitter,
  type DecisionEvidenceObject,
  type DecisionMeteringEntry,
} from "../src/decision-evidence.js";
import { createDecisionPoint, createEphemeralDecisionPoint } from "../src/decision-point.js";
import type { EnforcementScopeStatement } from "../src/enforcement-scope.js";
import {
  type Decision,
  type DecisionOptions,
  evaluate as evaluateRequest,
  type EvaluateOptions,
  type EvaluationRequest,
} from "../src/evaluate.js";
import type { Fga } from "../src/fga.js";
import {
  ClaimDomainConfigError,
  type ClaimRequester,
  type ConsumptionStatusFn,
  type BudgetOverspend,
  type HeldReservation,
  type IdempotencyClaimDomain,
  openIdempotencyClaimDomain,
} from "../src/idempotency-claims.js";
import { MISSION_RESOURCE_ACCESS_TYPE, type MissionView } from "../src/policy-view.js";
import { relationForAction, stalenessBound } from "../src/policy.js";
import {
  DECISION_EVIDENCE_MEDIA_TYPE,
  EXECUTION_EVIDENCE_MEDIA_TYPE,
  signEvidenceEnvelope,
  verifyEvidenceEnvelope,
} from "../src/runtime-evidence-integrity.js";
import { RUNTIME_POSTURE } from "../src/runtime-posture.js";
import { EVALUATION_CONTEXT_UNCLAIMED_FIXTURE, RESOURCE_POLICY_PERMITS_ALL_FIXTURE } from "../src/test-support.js";
import { CLAIM_OWNER, claimSchemaPlaceholders, freshKey, statementWithPrivilegedAdministration } from "./claim-fixture.js";
import { withCredential } from "./with-credential.js";

const evaluate = (req: EvaluationRequest, opts: EvaluateOptions) => evaluateRequest(withCredential(req), opts);

const RESOURCE = "http://localhost:4403/mcp";
const ISSUER = "https://as.test";
const EXECUTE = "payments:payment.execute";
const SCHEDULE = "payments:payment.schedule";
const REVERSE = "payments:payment.reverse";
const READ = "payments:invoice.read";
const REMIT = "payments:remittance.send";
const T0 = Date.parse("2026-10-25T12:00:00Z");
/** irreversible_action: the 30 s staleness bound caps the permit; the published lease is 30 s more. */
const PAST_LEASE_MS = 61_000;
/** Past the shipped 15-minute reconciliation window, too. */
const PAST_WINDOW_MS = PAST_LEASE_MS + 15 * 60_000;
/** Past the published 604,800 s idempotency horizon, measured from settlement. */
const HORIZON_MS = 604_800_000;

const OWNER = "acme-treasury";
const BUDGET_ID = "vendor-payments-2026";
/** The payee account the committed Dispatch Policy names for `acme` (#813, D830 ruling 4). */
const PAYEE = "acct-acme-001";
/** The committed Dispatch Policy the budget was approved under, and its re-consented successor. */
const POLICY_V1: DispatchPolicyRef = { id: "dp_vendor_payments", version: "1", digest: canonicalDigest({ dispatch_policy: "v1" }) };
const POLICY_V2: DispatchPolicyRef = { id: "dp_vendor_payments", version: "2", digest: canonicalDigest({ dispatch_policy: "v2" }) };
/** Another template's committed policy for the same budget, and a policy that commits no declared budget. */
const POLICY_EU: DispatchPolicyRef = { id: "dp_vendor_payments_eu", version: "1", digest: canonicalDigest({ dispatch_policy: "eu-v1" }) };
const POLICY_UNLISTED: DispatchPolicyRef = { id: "dp_contractor_payments", version: "1", digest: canonicalDigest({ dispatch_policy: "contractor-v1" }) };

const alwaysAllowFga = { checkWithContext: async () => true } as unknown as Fga;

interface Clock {
  now: () => Date;
  set: (ms: number) => void;
}
function clock(start = T0): Clock {
  let current = start;
  return { now: () => new Date(current), set: (ms) => { current = ms; } };
}

const evidenceKey = generateKeyPairSync("ec", { namedCurve: "P-256" });
const EMITTER = createDecisionEvidenceEmitter({
  signer: { kid: "pdp-816", key: evidenceKey.privateKey },
  emitterId: RESOURCE,
  audience: RESOURCE,
});

/** The executing PEP's published Execution Evidence key, as the claim domain resolves it. */
const executionKey = generateKeyPairSync("ec", { namedCurve: "P-256" });
const settlementKeys = (params: { kid: string; emitter: { id: string; role: string }; audience?: string }) =>
  params.kid === "pep-exec-816" && params.emitter.id === RESOURCE && params.audience === RESOURCE
    ? { key: executionKey.publicKey }
    : undefined;

/** A PEP-signed Execution Evidence Object for one attempt at one permit. */
async function executionRecord(
  evaluationId: string,
  outcome: "completed" | "failed" | "suppressed",
  executionId = `exe_${randomUUID()}`,
  over: { error?: string; role?: "pep" | "executor" } = {},
): Promise<Record<string, unknown>> {
  const content = {
    execution_id: executionId,
    evaluation_id: evaluationId,
    mission_id: "msn_a",
    audience: RESOURCE,
    outcome,
    outcome_at: new Date(T0).toISOString(),
    sequence: 1,
    emitter: { id: RESOURCE, role: over.role ?? (outcome === "completed" ? "executor" : "pep") },
    ...(outcome === "suppressed" ? { error: over.error ?? "kill_switch" } : {}),
  };
  const evidence_envelope = await signEvidenceEnvelope(content, EXECUTION_EVIDENCE_MEDIA_TYPE, {
    kid: "pep-exec-816",
    key: executionKey.privateKey,
  });
  return { ...content, evidence_envelope };
}

function declaration(o: { limit?: string; policies?: DispatchPolicyRef[] } = {}): BudgetMeteringDeclaration {
  return {
    unit: { currency: "USD", exponent: 2 },
    enforcement_profile: "exact",
    topology: "local-single-writer",
    reserve_posture: "reserve_then_commit",
    settlement_intake: CLAIM_SETTLEMENT_INTAKE,
    metered_actions: [{ action: EXECUTE, phase: "commit" }],
    budgets: [
      {
        owner: OWNER,
        budget_id: BUDGET_ID,
        counter_scope: "standing_consent",
        currency: "USD",
        limit: o.limit ?? "1000.00",
        policies: o.policies ?? [POLICY_V1],
      },
    ],
  };
}

/** The fixture statement, claiming `budget_metering` with `decl` attached (or declaring it unclaimed). */
function budgetStatement(decl: unknown = declaration(), claimed = true): EnforcementScopeStatement {
  const statement = statementWithPrivilegedAdministration() as unknown as Record<string, unknown> & {
    claims?: string[];
    extensions: Record<string, unknown>;
  };
  statement.claims = [...(statement.claims ?? []), ...(claimed ? ["budget_metering"] : [])];
  statement.extensions = { ...statement.extensions, budget_metering: decl };
  return statement as unknown as EnforcementScopeStatement;
}

/** A claim domain on its own file; `open` again is a PDP restart against the same file. */
function domainOnFile(c: Clock, hooks: { held?: HeldReservation[]; overspent?: BudgetOverspend[] } = {}) {
  const file = join(mkdtempSync(join(tmpdir(), "budget-816-")), "claims.sqlite");
  const open = (statement: EnforcementScopeStatement = budgetStatement()) =>
    openIdempotencyClaimDomain({
      file,
      owner: CLAIM_OWNER,
      statement,
      now: c.now,
      settlementKeys,
      ...(hooks.held ? { onReservationHeld: (r: HeldReservation) => hooks.held?.push(r) } : {}),
      ...(hooks.overspent ? { onBudgetOverspend: (o: BudgetOverspend) => hooks.overspent?.push(o) } : {}),
    });
  return { file, open };
}

/** Row counts straight from the file, after the domain released it. */
function countsOf(file: string): { claims: number; reservations: number; counters: number } {
  const db = openDurableStore({ file, migrations: claimSchemaPlaceholders(), owner: CLAIM_OWNER });
  try {
    const n = (table: string) => (db.prepare(`SELECT COUNT(*) AS n FROM ${table}`).get() as { n: number }).n;
    return { claims: n("claims"), reservations: n("budget_reservations"), counters: n("budget_counters") };
  } finally {
    db.close();
  }
}

/** The budget binding of one instance; `root` is the first Mission of its successor chain. */
function binding(root: string, o: Partial<MissionBudgetBinding> & { maxBudget?: string } = {}): MissionBudgetBinding {
  const { maxBudget, ...over } = o;
  return {
    owner: OWNER,
    budget_id: BUDGET_ID,
    currency: "USD",
    limit: "1000.00",
    policy: POLICY_V1,
    destinations: { acme: PAYEE },
    instance: { max_budget: { amount: maxBudget ?? "1000.00", currency: "USD" }, root_mission_id: root },
    ...over,
  };
}

function view(id: string, budget?: MissionBudgetBinding): MissionView {
  return {
    id,
    issuer: ISSUER,
    state: "active",
    version: 1,
    authority_hash: `sha-256:h-${id}`,
    authority_set: [{ type: MISSION_RESOURCE_ACCESS_TYPE, resource: RESOURCE, actions: [EXECUTE, SCHEDULE, REVERSE, READ, REMIT] }],
    subject: { iss: ISSUER, sub: "alice" },
    client_id: "ap-agent",
    ...(budget ? { budget } : {}),
  };
}

interface RequestOptions {
  action?: string;
  /** The deployment class; `null` sends an unclassified request. */
  actionClass?: string | null;
  missionId?: string;
  key?: string;
  amount?: string;
  currency?: string;
  phase?: string | null;
  /** `context.compensates_evaluation_id`, for a compensate-phase request. */
  compensates?: string;
  digest?: string;
  /** The request's vendor (`resource.properties.vendor_id`). */
  vendor?: string;
  /**
   * The normalized parameter object the PEP supplies (#813), whose digest is
   * the request's `parameter_digest` unless `digest` is given; members here
   * replace the PEP-established defaults, and `null` sends none.
   */
  parameters?: Record<string, unknown> | null;
}

function request(c: Clock, o: RequestOptions = {}): EvaluationRequest {
  const amount = o.amount ?? "100.00";
  const vendor = o.vendor ?? "acme";
  // @spec authzen#parameter-digest (#813): the effective parameters the PEP
  // established from the payments store, the payee among them.
  const parameters = {
    action: o.action ?? EXECUTE,
    invoice_id: "inv-1",
    vendor_id: vendor,
    amount: { amount, currency: o.currency ?? "USD" },
    payee_account: PAYEE,
    resource: RESOURCE,
    ...(o.parameters ?? {}),
  };
  return {
    subject: { id: "alice", properties: { iss: ISSUER } },
    resource: { type: "invoice", id: "inv-1", properties: { vendor_id: vendor, audience: RESOURCE, operation_target: RESOURCE } },
    action: {
      name: o.action ?? EXECUTE,
      properties: { idempotency_key: o.key ?? freshKey(), ...(o.parameters === null ? {} : { parameters }) },
    },
    context: {
      mission: { id: o.missionId ?? "msn_a", issuer: ISSUER },
      actor: { client_id: "ap-agent" },
      ...(o.actionClass === null ? {} : { action_class: o.actionClass ?? "irreversible_action" }),
      parameter_digest: o.digest ?? canonicalDigest(parameters),
      amount: { amount, currency: o.currency ?? "USD" },
      mission_state_observation: { state: "active", mode: "fresh", freshness_at: c.now().toISOString() },
      ...(o.phase === null ? {} : { action_phase: o.phase ?? "commit" }),
      ...(o.compensates !== undefined ? { compensates_evaluation_id: o.compensates } : {}),
    },
  };
}

const REQUESTER: ClaimRequester = { pep_id: "mcp-payments-pep", pep_epoch: "epoch-816-a" };
const unconsumed: ConsumptionStatusFn = () => "unconsumed";

/** The decision options a co-resident PDP that meters budgets applies. */
function options(claims: IdempotencyClaimDomain, c: Clock, v: MissionView, over: Partial<EvaluateOptions> = {}): EvaluateOptions {
  const budgets = claims.budgetMetering();
  return {
    view: v,
    fga: alwaysAllowFga,
    modelId: "model-816",
    now: c.now,
    stalenessBound,
    relationForAction,
    resourcePolicy: RESOURCE_POLICY_PERMITS_ALL_FIXTURE,
    stateSourcePlacement: "pep" as const,
    evidence: EMITTER,
    claims,
    ...(budgets ? { budgets } : {}),
    requester: REQUESTER,
    evaluationContextBinding: EVALUATION_CONTEXT_UNCLAIMED_FIXTURE,
    ...over,
  };
}

const instanceCounter = (root: string) => budgetCounterId("mission", { issuer: ISSUER, mission_id: root });
const SHARED = budgetCounterId("standing_consent", { owner: OWNER, budget_id: BUDGET_ID });

function meteringOf(d: Decision): DecisionMeteringEntry[] {
  return ((d.context.decision_evidence as DecisionEvidenceObject | undefined)?.metering ?? []) as DecisionMeteringEntry[];
}
function entry(d: Decision, scope: "mission" | "standing_consent"): DecisionMeteringEntry | undefined {
  return meteringOf(d).find((e) => e.counter_scope === scope);
}

function expectPermit(d: Decision): void {
  expect(d.decision, JSON.stringify(d.context)).toBe(true);
}
function expectDenied(d: Decision, reason: string): void {
  expect(d.decision, JSON.stringify(d.context)).toBe(false);
  expect(d.context.denial_reason).toBe(reason);
  expect(d.context.conditions).toBeUndefined();
}

/** An emitter that holds every emission until released, counting arrivals. */
function heldEmitter(): { emitter: DecisionEvidenceEmitter; release: () => void; arrived: () => number } {
  let release!: () => void;
  let arrivals = 0;
  const gate = new Promise<void>((resolve) => { release = resolve; });
  return {
    emitter: { emit: async (input) => { arrivals += 1; await gate; return EMITTER.emit(input); } },
    release,
    arrived: () => arrivals,
  };
}
async function until(condition: () => boolean): Promise<void> {
  for (let i = 0; i < 1000 && !condition(); i++) await new Promise<void>((resolve) => setImmediate(resolve));
  expect(condition()).toBe(true);
}

/** Permit one charge and return its evaluation id. */
async function permitted(claims: IdempotencyClaimDomain, c: Clock, v: MissionView, o: RequestOptions = {}): Promise<string> {
  const d = await evaluate(request(c, { missionId: v.id, ...o }), options(claims, c, v));
  expectPermit(d);
  return d.context.evaluation_id as string;
}

describe("PDP exact budget reservations (@spec metering#retry, metering#aggregate-bounds, metering#settlement-states, metering#metering-evidence, #816)", () => {
  describe("both counters are debited in the claim's own transaction", () => {
    it("eight concurrent metered requests in flight at once against one shared counter of 1000.00 leave three permits of 300.00 and five quota_exceeded, and the counter never overshoots (@spec metering#topology, #816)", async () => {
      const c = clock();
      const { file, open } = domainOnFile(c);
      const claims = open();
      const held = heldEmitter();
      const pending = Array.from({ length: 8 }, (_, i) => {
        const v = view(`msn_c${i}`, binding(`msn_c${i}`));
        return evaluate(request(c, { missionId: v.id, amount: "300.00" }), options(claims, c, v, { evidence: held.emitter }));
      });
      // Every evaluation has passed its claim step and is parked in emission.
      await until(() => held.arrived() === 8);
      expect(claims.budgetCounter(SHARED)?.reserved).toEqual({ amount: "900.00", currency: "USD" });
      held.release();
      const decisions = await Promise.all(pending);
      expect(decisions.filter((d) => d.decision)).toHaveLength(3);
      const refused = decisions.filter((d) => !d.decision);
      expect(refused).toHaveLength(5);
      for (const d of refused) {
        expectDenied(d, "quota_exceeded");
        expect(entry(d, "standing_consent")).toMatchObject({ counter_id: SHARED, requested: { amount: "300.00" }, remaining: { amount: "100.00" } });
      }
      expect(claims.budgetCounter(SHARED)).toMatchObject({ reserved: { amount: "900.00" }, held: { amount: "0.00" }, committed: { amount: "0.00" } });
      claims.close();
      // A refusal claims nothing: only the three permits hold claims.
      expect(countsOf(file)).toMatchObject({ claims: 3, reservations: 6 });
    });

    it("the instance bound refuses quota_exceeded naming the mission counter while the shared budget still has headroom (@spec metering#capacity-across-missions, #816)", async () => {
      const c = clock();
      const { open } = domainOnFile(c);
      const claims = open();
      const v = view("msn_a", binding("msn_a", { maxBudget: "300.00" }));
      await permitted(claims, c, v, { amount: "200.00" });
      // The decision itself, with no evidence emitter in the way.
      const noEvidence = options(claims, c, v);
      delete noEvidence.evidence;
      expectDenied(await evaluate(request(c, { missionId: "msn_a", amount: "200.00" }), noEvidence), "quota_exceeded");
      const refused = await evaluate(request(c, { missionId: "msn_a", amount: "200.00" }), options(claims, c, v));
      expectDenied(refused, "quota_exceeded");
      expect(entry(refused, "mission")).toMatchObject({ counter_id: instanceCounter("msn_a"), requested: { amount: "200.00" }, remaining: { amount: "100.00" } });
      expect(entry(refused, "standing_consent")).toMatchObject({ counter_id: SHARED, remaining: { amount: "800.00" } });
      // Neither counter moved for the refusal.
      expect(claims.budgetCounter(instanceCounter("msn_a"))?.reserved.amount).toBe("200.00");
      expect(claims.budgetCounter(SHARED)?.reserved.amount).toBe("200.00");
      // At the boundary: a request for exactly the remaining 100.00 is permitted.
      expectPermit(await evaluate(request(c, { missionId: "msn_a", amount: "100.00" }), options(claims, c, v)));
      expect(claims.budgetCounter(instanceCounter("msn_a"))?.reserved.amount).toBe("300.00");
      claims.close();
    });

    it("the shared budget refuses quota_exceeded naming the standing_consent counter while the instance bound still has headroom, and the instance counter is left untouched (@spec metering#aggregate-bounds, #816)", async () => {
      const c = clock();
      const { open } = domainOnFile(c);
      const claims = open(budgetStatement(declaration({ limit: "500.00" })));
      await permitted(claims, c, view("msn_a", binding("msn_a", { limit: "500.00" })), { amount: "400.00" });
      const b = view("msn_b", binding("msn_b", { limit: "500.00" }));
      const refused = await evaluate(request(c, { missionId: "msn_b", amount: "200.00" }), options(claims, c, b));
      expectDenied(refused, "quota_exceeded");
      expect(entry(refused, "standing_consent")).toMatchObject({ counter_id: SHARED, requested: { amount: "200.00" }, remaining: { amount: "100.00" } });
      expect(entry(refused, "mission")).toMatchObject({ counter_id: instanceCounter("msn_b"), remaining: { amount: "1000.00" } });
      // Both counters are checked before either is debited: no partial reservation.
      expect(claims.budgetCounter(instanceCounter("msn_b"))).toBeUndefined();
      expect(claims.budgetCounter(SHARED)?.reserved.amount).toBe("400.00");
      claims.close();
    });

    it("a successor that shares its predecessor's first Mission draws on the same mission counter, never on a fresh one (@spec metering#capacity-across-missions, #816)", async () => {
      const c = clock();
      const { open } = domainOnFile(c);
      const claims = open();
      const first = await evaluate(
        request(c, { missionId: "msn_a", amount: "300.00" }),
        options(claims, c, view("msn_a", binding("msn_a", { maxBudget: "500.00" }))),
      );
      expectPermit(first);
      const successor = view("msn_a2", binding("msn_a", { maxBudget: "500.00" }));
      const refused = await evaluate(request(c, { missionId: "msn_a2", amount: "300.00" }), options(claims, c, successor));
      expectDenied(refused, "quota_exceeded");
      expect(entry(refused, "mission")?.counter_id).toBe(entry(first, "mission")?.counter_id);
      expect(entry(refused, "mission")?.remaining.amount).toBe("200.00");
      // The successor's shared counter is the predecessor's, with the cumulative remainder.
      expect(entry(refused, "standing_consent")?.counter_id).toBe(entry(first, "standing_consent")?.counter_id);
      expect(entry(refused, "standing_consent")?.remaining.amount).toBe("700.00");
      const permit = await evaluate(request(c, { missionId: "msn_a2", amount: "200.00" }), options(claims, c, successor));
      expectPermit(permit);
      expect(entry(permit, "standing_consent")).toMatchObject({ counter_id: SHARED, remaining: { amount: "500.00" } });
      expect(claims.budgetCounter(instanceCounter("msn_a"))?.reserved.amount).toBe("500.00");
      claims.close();
    });

    it("two instances under two different committed Dispatch Policies that commit one budget share its standing_consent counter, and a policy reference outside the budget's list is refused constraint_unsupported (@spec metering#aggregate-bounds, #816)", async () => {
      const c = clock();
      const { open } = domainOnFile(c);
      const claims = open(budgetStatement(declaration({ policies: [POLICY_V1, POLICY_EU] })));
      const a = await evaluate(request(c, { missionId: "msn_a", amount: "300.00" }), options(claims, c, view("msn_a", binding("msn_a", { policy: POLICY_V1 }))));
      const b = await evaluate(request(c, { missionId: "msn_b", amount: "300.00" }), options(claims, c, view("msn_b", binding("msn_b", { policy: POLICY_EU }))));
      expectPermit(a);
      expectPermit(b);
      expect(entry(a, "standing_consent")).toMatchObject({ counter_id: SHARED, remaining: { amount: "700.00" } });
      expect(entry(b, "standing_consent")).toMatchObject({ counter_id: SHARED, remaining: { amount: "400.00" } });
      expect(claims.budgetCounter(SHARED)?.reserved.amount).toBe("600.00");
      // An unlisted policy, and a reference mixing two listed ones, commit nothing this budget meters.
      const outside: Array<[string, DispatchPolicyRef]> = [
        ["unlisted policy", POLICY_UNLISTED],
        ["listed id and version with another listed policy's digest", { ...POLICY_V1, digest: POLICY_EU.digest }],
      ];
      for (const [label, policy] of outside) {
        const d = await evaluate(request(c, { missionId: "msn_c", amount: "100.00" }), options(claims, c, view("msn_c", binding("msn_c", { policy }))));
        expect(d.decision, label).toBe(false);
        expect(d.context.denial_reason, label).toBe("constraint_unsupported");
        expect(claims.reservationsFor(d.context.evaluation_id as string), label).toEqual([]);
      }
      expect(claims.budgetCounter(SHARED)?.reserved.amount).toBe("600.00");
      claims.close();
    });

    it("two instances of one standing approval draw on one standing_consent counter and on two separate mission counters (@spec metering#aggregate-bounds, #816)", async () => {
      const c = clock();
      const { open } = domainOnFile(c);
      const claims = open();
      const a = await evaluate(request(c, { missionId: "msn_a", amount: "300.00" }), options(claims, c, view("msn_a", binding("msn_a"))));
      const b = await evaluate(request(c, { missionId: "msn_b", amount: "300.00" }), options(claims, c, view("msn_b", binding("msn_b"))));
      expectPermit(a);
      expectPermit(b);
      expect(entry(a, "standing_consent")?.counter_id).toBe(SHARED);
      expect(entry(b, "standing_consent")?.counter_id).toBe(SHARED);
      expect(entry(b, "standing_consent")?.remaining.amount).toBe("400.00");
      expect(entry(a, "mission")?.counter_id).not.toBe(entry(b, "mission")?.counter_id);
      expect(entry(b, "mission")?.remaining.amount).toBe("700.00");
      claims.close();
    });
  });

  describe("retry, replay and key reuse (@spec metering#retry)", () => {
    it("a retry and a replay under the same idempotency key reserve once (@spec metering#retry, #816)", async () => {
      const c = clock();
      const { open } = domainOnFile(c);
      const claims = open();
      const v = view("msn_a", binding("msn_a"));
      const key = freshKey();
      const first = await permitted(claims, c, v, { key, amount: "250.00" });
      expectDenied(await evaluate(request(c, { key, amount: "250.00" }), options(claims, c, v)), "duplicate_suppressed");
      // Settled, then replayed under the same key: still the one charge.
      expect((await claims.settle(REQUESTER, await executionRecord(first, "completed"))).accepted).toBe(true);
      expectDenied(await evaluate(request(c, { key, amount: "250.00" }), options(claims, c, v)), "duplicate_suppressed");
      expect(claims.reservationsFor(first).map((r) => r.state)).toEqual(["committed", "committed"]);
      expect(claims.budgetCounter(SHARED)).toMatchObject({ reserved: { amount: "0.00" }, committed: { amount: "250.00" } });
      expect(claims.budgetCounter(instanceCounter("msn_a"))).toMatchObject({ reserved: { amount: "0.00" }, committed: { amount: "250.00" } });
      claims.close();
    });

    it("a key reused for a different operation is refused idempotency_conflict and reserves nothing (@spec metering#retry, #816)", async () => {
      const c = clock();
      const { open } = domainOnFile(c);
      const claims = open();
      const v = view("msn_a", binding("msn_a"));
      const key = freshKey();
      await permitted(claims, c, v, { key, amount: "250.00" });
      const reused = await evaluate(request(c, { key, amount: "300.00" }), options(claims, c, v));
      expectDenied(reused, "idempotency_conflict");
      expect(claims.reservationsFor(reused.context.evaluation_id as string)).toEqual([]);
      expect(claims.budgetCounter(SHARED)?.reserved.amount).toBe("250.00");
      expect(claims.budgetCounter(instanceCounter("msn_a"))?.reserved.amount).toBe("250.00");
      claims.close();
    });

    it("a duplicate settlement is acknowledged as a no-op and commits the reservation once (@spec metering#settlement-contract, #816)", async () => {
      const c = clock();
      const { open } = domainOnFile(c);
      const claims = open();
      const evaluationId = await permitted(claims, c, view("msn_a", binding("msn_a")), { amount: "250.00" });
      const record = await executionRecord(evaluationId, "completed");
      expect(await claims.settle(REQUESTER, record)).toEqual({ accepted: true, state: "completed", duplicate: false });
      expect(await claims.settle(REQUESTER, record)).toEqual({ accepted: true, state: "completed", duplicate: true });
      expect(claims.budgetCounter(SHARED)).toMatchObject({ reserved: { amount: "0.00" }, committed: { amount: "250.00" } });
      expect(claims.reservationsFor(evaluationId).map((r) => r.state)).toEqual(["committed", "committed"]);
      claims.close();
    });

    it("a lost permit response followed by a retry under the same key does not reserve a second time (@spec metering#retry, #816)", async () => {
      const c = clock();
      const { file, open } = domainOnFile(c);
      const claims = open();
      const v = view("msn_a", binding("msn_a"));
      const key = freshKey();
      // The permit's response is lost in transit; the PEP retries one second later.
      const lost = await evaluate(request(c, { key, amount: "400.00" }), options(claims, c, v, { consumptionStatus: unconsumed }));
      expectPermit(lost);
      c.set(T0 + 1_000);
      const retry = await evaluate(request(c, { key, amount: "400.00" }), options(claims, c, v, { consumptionStatus: unconsumed }));
      expectDenied(retry, "duplicate_suppressed");
      expect(claims.budgetCounter(SHARED)?.reserved.amount).toBe("400.00");
      expect(claims.budgetCounter(instanceCounter("msn_a"))?.reserved.amount).toBe("400.00");
      claims.close();
      expect(countsOf(file).reservations).toBe(2);
    });

    it("a metered action is not served from the decision cache: the retry of a lost permit is suppressed where an unmetered one is retransmitted (@spec metering#retry, authzen#projections, #816)", async () => {
      const c = clock();
      const { open } = domainOnFile(c);
      const claims = open();
      // Control: an unmetered Mission's lost permit is returned byte for byte.
      const plain = view("msn_plain");
      const plainKey = freshKey();
      const plainFirst = await evaluate(request(c, { missionId: "msn_plain", key: plainKey }), options(claims, c, plain, { consumptionStatus: unconsumed }));
      expectPermit(plainFirst);
      const plainAgain = await evaluate(request(c, { missionId: "msn_plain", key: plainKey }), options(claims, c, plain, { consumptionStatus: unconsumed }));
      expect(JSON.stringify(plainAgain)).toBe(JSON.stringify(plainFirst));
      // The metered Mission's identical retry is never answered from the stored decision.
      const metered = view("msn_a", binding("msn_a"));
      const key = freshKey();
      const first = await evaluate(request(c, { key }), options(claims, c, metered, { consumptionStatus: unconsumed }));
      expectPermit(first);
      const again = await evaluate(request(c, { key }), options(claims, c, metered, { consumptionStatus: unconsumed }));
      expectDenied(again, "duplicate_suppressed");
      expect(again.context.next_action).toBe("retry");
      expect(again.context.evaluation_id).not.toBe(first.context.evaluation_id);
      expect(claims.reservationsFor(first.context.evaluation_id as string)).toHaveLength(2);
      claims.close();
    });
  });

  describe("settlement and recovery transitions (@spec metering#settlement-states)", () => {
    it("a crash before the decision is persisted releases the reservation at the next boot, since no permit existed, and the retry under the same key reserves once (@spec metering#settlement-states, metering#retry, #816)", async () => {
      const c = clock();
      const { open } = domainOnFile(c);
      let claims = open();
      const held = heldEmitter();
      const v = view("msn_a", binding("msn_a"));
      const key = freshKey();
      const parked = evaluate(request(c, { key, amount: "700.00" }), options(claims, c, v, { evidence: held.emitter }));
      await until(() => held.arrived() === 1);
      expect(claims.budgetCounter(SHARED)?.reserved.amount).toBe("700.00");
      expect(claims.listHeldReservations()).toEqual([]);
      // The process dies with the evaluation parked before it persisted anything.
      claims.close();
      held.release();
      await expect(parked).rejects.toThrow(/unavailable/);
      claims = open();
      expect(claims.budgetCounter(SHARED)).toMatchObject({ reserved: { amount: "0.00" }, held: { amount: "0.00" } });
      expect(claims.budgetCounter(instanceCounter("msn_a"))?.reserved.amount).toBe("0.00");
      // The retry under the same key adopts the abandoned claim and reserves once.
      expectPermit(await evaluate(request(c, { key, amount: "700.00" }), options(claims, c, v)));
      expect(claims.budgetCounter(SHARED)?.reserved.amount).toBe("700.00");
      expect(claims.budgetCounter(instanceCounter("msn_a"))?.reserved.amount).toBe("700.00");
      claims.close();
    });

    it("an evaluation that ends without persisting its permit releases its reservation in the same boot (@spec metering#settlement-states, #816)", async () => {
      const c = clock();
      const { open } = domainOnFile(c);
      const claims = open();
      const failing: DecisionEvidenceEmitter = { emit: async () => { throw new Error("evidence signer down"); } };
      const v = view("msn_a", binding("msn_a"));
      await expect(evaluate(request(c, { amount: "700.00" }), options(claims, c, v, { evidence: failing }))).rejects.toThrow(/signer down/);
      expect(claims.budgetCounter(SHARED)?.reserved.amount).toBe("0.00");
      expectPermit(await evaluate(request(c, { amount: "1000.00" }), options(claims, c, v)));
      claims.close();
    });

    it("when the store fails with the persist and the evaluation's own release, the next sweep in the same boot releases the unpersisted reservation (@spec metering#settlement-states, #816)", async () => {
      const c = clock();
      const { open } = domainOnFile(c);
      const claims = open();
      // Fault injection: every transaction on the claim file fails while `failing` is set.
      let failing = false;
      setCommitGuard((claims as unknown as { db: Database }).db, {
        begin: () => {
          if (failing) throw new Error("store failing");
        },
        beforeCommit: () => {},
        settled: () => {},
        afterCommit: () => {},
      });
      // The store starts failing after the claim reserved, before the permit is persisted.
      const failsAfterClaim: DecisionEvidenceEmitter = {
        emit: async (input) => {
          failing = true;
          return EMITTER.emit(input);
        },
      };
      const v = view("msn_a", binding("msn_a"));
      await expect(evaluate(request(c, { amount: "700.00" }), options(claims, c, v, { evidence: failsAfterClaim }))).rejects.toThrow(
        /unavailable/,
      );
      failing = false;
      // The evaluation's own release failed with the store: still charged.
      expect(claims.budgetCounter(SHARED)?.reserved.amount).toBe("700.00");
      claims.sweep();
      expect(claims.budgetCounter(SHARED)?.reserved.amount).toBe("0.00");
      expect(claims.budgetCounter(instanceCounter("msn_a"))?.reserved.amount).toBe("0.00");
      expectPermit(await evaluate(request(c, { amount: "1000.00" }), options(claims, c, v)));
      claims.close();
    });

    it("a crash after the permit was issued leaves the reservation held across the restart, and the operator alert fires once (@spec metering#settlement-states, #816)", async () => {
      const c = clock();
      const alerts: HeldReservation[] = [];
      const { open } = domainOnFile(c, { held: alerts });
      let claims = open();
      const evaluationId = await permitted(claims, c, view("msn_a", binding("msn_a")), { amount: "600.00" });
      expect(alerts).toEqual([]);
      claims.close();
      claims = open();
      expect(claims.reservationsFor(evaluationId).map((r) => r.state)).toEqual(["held", "held"]);
      expect(claims.budgetCounter(SHARED)).toMatchObject({ reserved: { amount: "0.00" }, held: { amount: "600.00" } });
      expect(alerts).toHaveLength(1);
      expect(alerts[0]).toMatchObject({ evaluation_id: evaluationId, mission_id: "msn_a", cause: "restart_unknown" });
      expect(alerts[0]?.counters.map((x) => x.counter_scope).sort()).toEqual(["mission", "standing_consent"]);
      expect(alerts[0]?.counters.every((x) => x.amount.amount === "600.00" && x.amount.currency === "USD")).toBe(true);
      claims.close();
      // Another restart: still held, and no second alert.
      claims = open();
      expect(claims.reservationsFor(evaluationId).map((r) => r.state)).toEqual(["held", "held"]);
      expect(alerts).toHaveLength(1);
      claims.close();
    });

    it("with a limit of 100,000 minor units, a 60,000 reservation held after a lost acknowledgement makes a 50,000 request quota_exceeded (@spec metering#settlement-states, metering#aggregate-bounds, #816)", async () => {
      const c = clock();
      const { open } = domainOnFile(c);
      const claims = open();
      const first = await permitted(claims, c, view("msn_a", binding("msn_a")), { amount: "600.00" });
      // The PEP executed and sent its settlement; the acknowledgement was lost
      // and nothing reached the PDP, so the lease elapses unsettled.
      c.set(T0 + PAST_LEASE_MS);
      claims.sweep();
      expect(claims.reservationsFor(first).map((r) => r.state)).toEqual(["held", "held"]);
      const b = view("msn_b", binding("msn_b"));
      const refused = await evaluate(request(c, { missionId: "msn_b", amount: "500.00" }), options(claims, c, b));
      expectDenied(refused, "quota_exceeded");
      expect(entry(refused, "standing_consent")).toMatchObject({
        counter_id: SHARED,
        requested: { amount: "500.00", currency: "USD" },
        remaining: { amount: "400.00", currency: "USD" },
      });
      claims.close();
    });

    it("suppressed settlement releases a reservation while failed settlement leaves it held and raises the alert (@spec metering#settlement-states, #816)", async () => {
      const c = clock();
      const alerts: HeldReservation[] = [];
      const { open } = domainOnFile(c, { held: alerts });
      const claims = open();
      const s = await permitted(claims, c, view("msn_a", binding("msn_a")), { amount: "300.00" });
      const f = await permitted(claims, c, view("msn_b", binding("msn_b")), { amount: "200.00" });
      const suppressed = await executionRecord(s, "suppressed");
      expect((await claims.settle(REQUESTER, suppressed, () => String(suppressed.execution_id))).accepted).toBe(true);
      const failed = await executionRecord(f, "failed");
      expect((await claims.settle(REQUESTER, failed, () => String(failed.execution_id))).accepted).toBe(true);
      expect(claims.reservationsFor(s).map((r) => r.state)).toEqual(["released", "released"]);
      expect(claims.reservationsFor(f).map((r) => r.state)).toEqual(["held", "held"]);
      expect(claims.budgetCounter(SHARED)).toMatchObject({ reserved: { amount: "0.00" }, held: { amount: "200.00" }, committed: { amount: "0.00" } });
      expect(alerts.map((a) => [a.evaluation_id, a.cause])).toEqual([[f, "failed"]]);
      claims.close();
    });

    it("lease expiry, the reconciliation window and the claim's horizon never release a held reservation, and a purged claim keeps its committed spend (@spec metering#settlement-states, #816)", async () => {
      const c = clock();
      const { open } = domainOnFile(c);
      const claims = open();
      const leased = await permitted(claims, c, view("msn_a", binding("msn_a")), { amount: "300.00" });
      const done = await permitted(claims, c, view("msn_b", binding("msn_b")), { amount: "200.00" });
      expect((await claims.settle(REQUESTER, await executionRecord(done, "completed"))).accepted).toBe(true);
      c.set(T0 + PAST_LEASE_MS);
      expect(claims.listUnresolved(REQUESTER).map((u) => u.evaluation_id)).toEqual([leased]);
      expect(claims.reservationsFor(leased).map((r) => r.state)).toEqual(["held", "held"]);
      c.set(T0 + PAST_WINDOW_MS);
      claims.sweep();
      expect(claims.reservationsFor(leased).map((r) => r.state)).toEqual(["held", "held"]);
      // Past the horizon the completed claim is purged; its reservations are not.
      c.set(T0 + PAST_WINDOW_MS + HORIZON_MS);
      claims.sweep();
      expect(claims.reservationsFor(leased).map((r) => r.state)).toEqual(["held", "held"]);
      expect(claims.reservationsFor(done).map((r) => r.state)).toEqual(["committed", "committed"]);
      expect(claims.budgetCounter(SHARED)).toMatchObject({ reserved: { amount: "0.00" }, held: { amount: "300.00" }, committed: { amount: "200.00" } });
      // The next request sees the reduced headroom.
      const refused = await evaluate(
        request(c, { missionId: "msn_c", amount: "600.00" }),
        options(claims, c, view("msn_c", binding("msn_c"))),
      );
      expectDenied(refused, "quota_exceeded");
      expect(entry(refused, "standing_consent")?.remaining.amount).toBe("500.00");
      claims.close();
    });

    it("a later suppressed settlement from the redeeming attempt for the permit's own evaluation releases a held reservation (@spec metering#settlement-states, #816)", async () => {
      const c = clock();
      const { open } = domainOnFile(c);
      const claims = open();
      const a = await permitted(claims, c, view("msn_a", binding("msn_a")), { amount: "300.00" });
      c.set(T0 + PAST_LEASE_MS);
      claims.sweep();
      expect(claims.reservationsFor(a).map((r) => r.state)).toEqual(["held", "held"]);
      // Affirmative non-execution before redemption, from the attempt the redemption record names.
      const late = await executionRecord(a, "suppressed");
      expect((await claims.settle(REQUESTER, late, () => String(late.execution_id))).accepted).toBe(true);
      expect(claims.reservationsFor(a).map((r) => r.state)).toEqual(["released", "released"]);
      expect(claims.budgetCounter(SHARED)).toMatchObject({ reserved: { amount: "0.00" }, held: { amount: "0.00" }, committed: { amount: "0.00" } });
      expectPermit(await evaluate(request(c, { missionId: "msn_b", amount: "1000.00" }), options(claims, c, view("msn_b", binding("msn_b")))));
      claims.close();
    });

    it("a suppressed settlement for a different evaluation releases nothing held under another (@spec metering#settlement-states, #816)", async () => {
      const c = clock();
      const { open } = domainOnFile(c);
      const claims = open();
      const a = await permitted(claims, c, view("msn_a", binding("msn_a")), { amount: "300.00" });
      const plain = await permitted(claims, c, view("msn_plain"), { amount: "50.00" });
      c.set(T0 + PAST_LEASE_MS);
      claims.sweep();
      expect(claims.reservationsFor(a).map((r) => r.state)).toEqual(["held", "held"]);
      const other = await permitted(claims, c, view("msn_b", binding("msn_b")), { amount: "200.00" });
      for (const evaluationId of [plain, other]) {
        const record = await executionRecord(evaluationId, "suppressed");
        expect((await claims.settle(REQUESTER, record, () => String(record.execution_id))).accepted).toBe(true);
      }
      const unknown = await executionRecord("dec_unknown", "suppressed");
      expect((await claims.settle(REQUESTER, unknown, () => String(unknown.execution_id))).accepted).toBe(false);
      expect(claims.reservationsFor(other).map((r) => r.state)).toEqual(["released", "released"]);
      expect(claims.reservationsFor(a).map((r) => r.state)).toEqual(["held", "held"]);
      expect(claims.budgetCounter(SHARED)).toMatchObject({ reserved: { amount: "0.00" }, held: { amount: "300.00" } });
      claims.close();
    });

    it("the PEP's unredeemed reconciliation leaves a held reservation held for operator reconciliation (@spec metering#settlement-states, #816)", async () => {
      const c = clock();
      const { open } = domainOnFile(c);
      const claims = open();
      const a = await permitted(claims, c, view("msn_a", binding("msn_a")), { amount: "300.00" });
      c.set(T0 + PAST_LEASE_MS);
      claims.sweep();
      // The redemption owner's same-epoch answer settles the claim; it is not authoritative for the budget.
      expect((await claims.reconcile(REQUESTER, a, { kind: "unredeemed" })).accepted).toBe(true);
      expect(claims.reservationsFor(a).map((r) => r.state)).toEqual(["held", "held"]);
      expect(claims.budgetCounter(SHARED)?.held.amount).toBe("300.00");
      expect(claims.listHeldReservations().map((r) => r.evaluation_id)).toEqual([a, a]);
      claims.close();
    });

    it("an operator not_executed answer is refused while a restart-held permit can still be redeemed, and its later completed settlement commits the spend so the next instance's 1000.00 is quota_exceeded (@spec metering#settlement-states, #816)", async () => {
      const c = clock();
      const { open } = domainOnFile(c);
      let claims = open();
      const a = await permitted(claims, c, view("msn_a", binding("msn_a")), { amount: "300.00" });
      // The PDP restarts one second later, well inside the permit's validity.
      claims.close();
      c.set(T0 + 1_000);
      claims = open();
      expect(claims.reservationsFor(a).map((r) => r.state)).toEqual(["held", "held"]);
      expect(claims.reconcileHeldReservation(a, { kind: "not_executed", reference: "bank-no-entry-yet" })).toEqual({
        accepted: false,
        reason: "lease_not_elapsed",
      });
      expect(claims.reservationsFor(a).map((r) => r.state)).toEqual(["held", "held"]);
      // The wire completes under the permit and its evidence settles the claim.
      expect(await claims.settle(REQUESTER, await executionRecord(a, "completed"))).toMatchObject({ accepted: true, state: "completed" });
      expect(claims.reservationsFor(a).map((r) => r.state)).toEqual(["committed", "committed"]);
      expect(claims.budgetCounter(SHARED)).toMatchObject({ held: { amount: "0.00" }, committed: { amount: "300.00" } });
      const next = await evaluate(request(c, { missionId: "msn_b", amount: "1000.00" }), options(claims, c, view("msn_b", binding("msn_b"))));
      expectDenied(next, "quota_exceeded");
      expect(entry(next, "standing_consent")?.remaining.amount).toBe("700.00");
      claims.close();
    });

    it("a completed settlement for a reservation the operator released after its lease commits it anyway and raises the overspend alert for the counter it pushes past its limit (@spec metering#settlement-states, #816)", async () => {
      const c = clock();
      const overspent: BudgetOverspend[] = [];
      const { open } = domainOnFile(c, { overspent });
      const claims = open();
      const a = await permitted(claims, c, view("msn_a", binding("msn_a")), { amount: "300.00" });
      c.set(T0 + PAST_LEASE_MS);
      claims.sweep();
      expect(claims.reconcileHeldReservation(a, { kind: "not_executed", reference: "bank-statement-2026-10-25" })).toEqual({ accepted: true, state: "released" });
      // The released headroom is spent by another instance before the late evidence arrives.
      await permitted(claims, c, view("msn_b", binding("msn_b")), { amount: "1000.00" });
      expect(overspent).toEqual([]);
      expect((await claims.settle(REQUESTER, await executionRecord(a, "completed"))).accepted).toBe(true);
      // The money moved: the spend is committed, never dropped, and the shared counter is over its limit.
      expect(claims.reservationsFor(a).map((r) => r.state)).toEqual(["committed", "committed"]);
      expect(claims.budgetCounter(SHARED)).toMatchObject({ reserved: { amount: "1000.00" }, committed: { amount: "300.00" } });
      expect(overspent).toHaveLength(1);
      expect(overspent[0]).toMatchObject({
        evaluation_id: a,
        mission_id: "msn_a",
        counter_scope: "standing_consent",
        counter_id: SHARED,
        amount: { amount: "300.00", currency: "USD" },
        limit: { amount: "1000.00", currency: "USD" },
        used: { amount: "1300.00", currency: "USD" },
      });
      claims.close();
    });

    it("operator reconciliation releases or commits a held reservation, a restart does not release it, and a reservation that is not held is refused unchanged (@spec metering#settlement-states, #816)", async () => {
      const c = clock();
      const { open } = domainOnFile(c);
      let claims = open();
      const a = await permitted(claims, c, view("msn_a", binding("msn_a")), { amount: "300.00" });
      const b = await permitted(claims, c, view("msn_b", binding("msn_b")), { amount: "200.00" });
      c.set(T0 + PAST_LEASE_MS);
      claims.sweep();
      claims.close();
      claims = open();
      expect(claims.reservationsFor(a).map((r) => r.state)).toEqual(["held", "held"]);
      expect(claims.reservationsFor(b).map((r) => r.state)).toEqual(["held", "held"]);
      expect(claims.listHeldReservations().map((r) => r.evaluation_id).sort()).toEqual([a, a, b, b].sort());
      // A reservation that is not held, or no reservation at all, is refused unchanged.
      c.set(T0 + PAST_LEASE_MS + 1_000);
      const open1 = await permitted(claims, c, view("msn_c", binding("msn_c")), { amount: "100.00" });
      expect(claims.reconcileHeldReservation(open1, { kind: "not_executed", reference: "ticket-1" })).toEqual({ accepted: false, reason: "not_held_reserved" });
      expect(claims.reconcileHeldReservation("dec_unknown", { kind: "not_executed", reference: "ticket-1" })).toEqual({ accepted: false, reason: "unknown_evaluation" });
      // The operator's authoritative reconciliation is the way out of held.
      expect(claims.reconcileHeldReservation(a, { kind: "not_executed", reference: "bank-statement-2026-10-25" })).toEqual({ accepted: true, state: "released" });
      expect(claims.reconcileHeldReservation(b, { kind: "executed", reference: "bank-statement-2026-10-25" })).toEqual({ accepted: true, state: "committed" });
      expect(claims.reservationsFor(a).map((r) => r.state)).toEqual(["released", "released"]);
      expect(claims.reservationsFor(b).map((r) => r.state)).toEqual(["committed", "committed"]);
      expect(claims.budgetCounter(SHARED)).toMatchObject({ reserved: { amount: "100.00" }, held: { amount: "0.00" }, committed: { amount: "200.00" } });
      expect(claims.reconcileHeldReservation(a, { kind: "not_executed", reference: "again" })).toEqual({ accepted: false, reason: "not_held_released" });
      claims.close();
    });

    it("a new policy version for the same budget leaves a held reservation held and reduces the next instance's headroom (@spec metering#capacity-across-missions, #816, D830 ruling 7)", async () => {
      const c = clock();
      const { open } = domainOnFile(c);
      let claims = open();
      const first = await permitted(claims, c, view("msn_a", binding("msn_a")), { amount: "600.00" });
      c.set(T0 + PAST_LEASE_MS);
      claims.sweep();
      claims.close();
      // Re-consent: version 2 of the policy raises the limit to 1200.00.
      claims = open(budgetStatement(declaration({ limit: "1200.00", policies: [POLICY_V2] })));
      expect(claims.reservationsFor(first).map((r) => r.state)).toEqual(["held", "held"]);
      const v2 = (id: string) => view(id, binding(id, { limit: "1200.00", policy: POLICY_V2 }));
      const refused = await evaluate(request(c, { missionId: "msn_b", amount: "700.00" }), options(claims, c, v2("msn_b")));
      expectDenied(refused, "quota_exceeded");
      expect(entry(refused, "standing_consent")?.remaining.amount).toBe("600.00");
      expectPermit(await evaluate(request(c, { missionId: "msn_b", amount: "600.00" }), options(claims, c, v2("msn_b"))));
      expect(claims.reservationsFor(first).map((r) => r.state)).toEqual(["held", "held"]);
      claims.close();
    });
  });

  describe("a budget this PDP cannot meter is refused (decision b)", () => {
    it("currency mismatch, an undeclared budget, another owner, and a limit or a Dispatch Policy id, version or digest that disagrees with the declaration each deny constraint_unsupported and reserve and claim nothing (@spec authzen#failure-condition-coverage, metering#metering, #816)", async () => {
      const c = clock();
      const { file, open } = domainOnFile(c);
      const claims = open();
      const cases: Array<[string, MissionBudgetBinding, RequestOptions?]> = [
        ["binding in another currency", binding("msn_x", { currency: "EUR", instance: { max_budget: { amount: "1000.00", currency: "EUR" }, root_mission_id: "msn_x" } })],
        ["request amount in another currency", binding("msn_x"), { currency: "EUR" }],
        ["undeclared budget", binding("msn_x", { budget_id: "another-budget" })],
        ["another budget owner", binding("msn_x", { owner: "globex-treasury" })],
        ["limit that disagrees with the declaration", binding("msn_x", { limit: "2000.00" })],
        ["policy id that disagrees with the declaration", binding("msn_x", { policy: { ...POLICY_V1, id: "dp_other" } })],
        ["policy version that disagrees with the declaration", binding("msn_x", { policy: { ...POLICY_V1, version: "2" } })],
        ["policy digest that disagrees with the declaration", binding("msn_x", { policy: { ...POLICY_V1, digest: POLICY_V2.digest } })],
      ];
      for (const [label, b, o] of cases) {
        const d = await evaluate(request(c, { missionId: "msn_x", ...o }), options(claims, c, view("msn_x", b)));
        expect(d.decision, label).toBe(false);
        expect(d.context.denial_reason, label).toBe("constraint_unsupported");
        expect(claims.reservationsFor(d.context.evaluation_id as string), label).toEqual([]);
      }
      // Control: the declared limit spelled with another scale is the same value, and meters.
      expectPermit(await evaluate(request(c, { missionId: "msn_ok" }), options(claims, c, view("msn_ok", binding("msn_ok", { limit: "1000" })))));
      claims.close();
      expect(countsOf(file)).toEqual({ claims: 1, reservations: 2, counters: 2 });
    });

    it("an unmetered Mission with no budget binding is unaffected on a PDP that meters budgets (@spec metering#metering, #816)", async () => {
      const c = clock();
      const { file, open } = domainOnFile(c);
      const claims = open();
      const d = await evaluate(request(c, { missionId: "msn_plain", amount: "5000.00" }), options(claims, c, view("msn_plain")));
      expectPermit(d);
      expect((d.context.decision_evidence as DecisionEvidenceObject).metering).toBeUndefined();
      expect((d.context.decision_evidence as DecisionEvidenceObject).contributing_constraints ?? []).not.toContain("max_budget");
      claims.close();
      expect(countsOf(file)).toEqual({ claims: 1, reservations: 0, counters: 0 });
    });

    it("the metered action's preflight and prepare phases charge nothing and its commit phase charges the amount once (@spec metering#metering, #816, decision h)", async () => {
      const c = clock();
      const { file, open } = domainOnFile(c);
      const claims = open();
      const v = view("msn_a", binding("msn_a"));
      for (const phase of ["preflight", "prepare"]) {
        const d = await evaluate(request(c, { amount: "300.00", phase }), options(claims, c, v));
        expectPermit(d);
        expect((d.context.decision_evidence as DecisionEvidenceObject).metering, phase).toBeUndefined();
      }
      expect(claims.budgetCounter(SHARED)).toBeUndefined();
      const key = freshKey();
      const commit = await evaluate(request(c, { key, amount: "300.00", phase: "commit" }), options(claims, c, v));
      expectPermit(commit);
      expect(meteringOf(commit)).toHaveLength(2);
      expectDenied(await evaluate(request(c, { key, amount: "300.00", phase: "commit" }), options(claims, c, v)), "duplicate_suppressed");
      expect(claims.budgetCounter(SHARED)?.reserved.amount).toBe("300.00");
      expect(claims.budgetCounter(instanceCounter("msn_a"))?.reserved.amount).toBe("300.00");
      claims.close();
      expect(countsOf(file)).toEqual({ claims: 3, reservations: 2, counters: 2 });
    });

    it("an amount-bearing action other than the metered action under a budget-bound Mission, whether consequential_write, irreversible_action, external_commitment or unclassified, is denied constraint_unsupported and reserves and claims nothing (@spec metering#metering, #816, decision h)", async () => {
      const c = clock();
      const { file, open } = domainOnFile(c);
      const claims = open();
      const others: Array<[string, string | null]> = [
        [SCHEDULE, "consequential_write"],
        [REVERSE, "irreversible_action"],
        [REMIT, "external_commitment"],
        [SCHEDULE, null],
      ];
      for (const [action, actionClass] of others) {
        const label = `${action} (${actionClass ?? "unclassified"})`;
        const d = await evaluate(request(c, { action, actionClass, phase: null }), options(claims, c, view("msn_a", binding("msn_a"))));
        expect(d.decision, label).toBe(false);
        expect(d.context.denial_reason, label).toBe("constraint_unsupported");
      }
      claims.close();
      expect(countsOf(file)).toEqual({ claims: 0, reservations: 0, counters: 0 });
      // Control: the same requests under a Mission with no budget binding are permitted.
      const unbound = open();
      for (const [action, actionClass] of others) {
        expectPermit(await evaluate(request(c, { action, actionClass, phase: null, missionId: "msn_plain" }), options(unbound, c, view("msn_plain"))));
      }
      unbound.close();
    });

    it("a compensate phase of the metered action carrying an amount is denied constraint_unsupported and reserves and claims nothing (@spec metering#metering, #816, decision h)", async () => {
      const c = clock();
      const { file, open } = domainOnFile(c);
      const claims = open();
      const compensate: RequestOptions = { phase: "compensate", compensates: "dec_committed_wire", amount: "300.00" };
      const d = await evaluate(request(c, compensate), options(claims, c, view("msn_a", binding("msn_a"))));
      expectDenied(d, "constraint_unsupported");
      claims.close();
      expect(countsOf(file)).toEqual({ claims: 0, reservations: 0, counters: 0 });
      // Control: the same request under a Mission with no budget binding is permitted.
      const unbound = open();
      expectPermit(await evaluate(request(c, { ...compensate, missionId: "msn_plain" }), options(unbound, c, view("msn_plain"))));
      unbound.close();
    });

    it("an amount-bearing consequential_read under a budget-bound Mission is permitted and charges neither counter (@spec metering#metering, #816, decision h)", async () => {
      const c = clock();
      const { file, open } = domainOnFile(c);
      const claims = open();
      const d = await evaluate(
        request(c, { action: READ, actionClass: "consequential_read", phase: null, amount: "600.00" }),
        options(claims, c, view("msn_a", binding("msn_a"))),
      );
      expectPermit(d);
      expect((d.context.decision_evidence as DecisionEvidenceObject).metering).toBeUndefined();
      expect(claims.budgetCounter(SHARED)).toBeUndefined();
      expect(claims.budgetCounter(instanceCounter("msn_a"))).toBeUndefined();
      claims.close();
      expect(countsOf(file)).toEqual({ claims: 0, reservations: 0, counters: 0 });
    });

    it("a remote PDP and an ephemeral decision point deny a budget-bound Mission constraint_unsupported and reserve nothing, while the co-resident decision point over the same domain meters it (@spec metering#topology, #816, decision f)", async () => {
      const c = clock();
      const { file, open } = domainOnFile(c);
      const claims = open();
      const v = view("msn_a", binding("msn_a"));
      const decisionOptions: DecisionOptions = {
        view: v,
        fga: alwaysAllowFga,
        modelId: "model-816",
        now: c.now,
        stalenessBound,
        relationForAction,
        stateSourcePlacement: "pep",
      };
      // The co-resident point takes the binding from its own source (decision
      // d); the ephemeral point has none, so the caller's binding is one it
      // cannot derive.
      const point = createDecisionPoint({
        claims,
        resourcePolicy: RESOURCE_POLICY_PERMITS_ALL_FIXTURE,
        evaluationContextBinding: EVALUATION_CONTEXT_UNCLAIMED_FIXTURE,
        budgetBindings: (m) => (m.id === "msn_a" ? binding("msn_a") : undefined),
      });
      const remote = await createDecisionChannel(point, {
        mode: "remote",
        pepId: "mcp-payments-pep",
        audience: RESOURCE,
        getOptions: () => decisionOptions,
      });
      try {
        const overRemote = await remote.decide(withCredential(request(c)), decisionOptions);
        expectDenied(overRemote, "constraint_unsupported");
      } finally {
        await remote.close();
      }
      const ephemeral = createEphemeralDecisionPoint({
        emitterId: RESOURCE,
        audience: RESOURCE,
        claims,
        resourcePolicy: RESOURCE_POLICY_PERMITS_ALL_FIXTURE,
        evaluationContextBinding: EVALUATION_CONTEXT_UNCLAIMED_FIXTURE,
      });
      expectDenied(await ephemeral.decide(withCredential(request(c)), decisionOptions), "constraint_unsupported");
      expect(claims.budgetCounter(SHARED)).toBeUndefined();
      // Control: the co-resident decision point over the same domain meters it.
      expectPermit(await point.decide(withCredential(request(c, { amount: "250.00" })), decisionOptions));
      expect(claims.budgetCounter(SHARED)?.reserved.amount).toBe("250.00");
      claims.close();
      expect(countsOf(file)).toEqual({ claims: 1, reservations: 2, counters: 2 });
    });
  });

  describe("Decision Evidence (@spec metering#metering-evidence)", () => {
    it("a charged permit's signed Decision Evidence carries one metering entry per counter, mission and standing_consent, with the reservation, and a quota_exceeded refusal carries the exhausted counter's entry with its unchanged remainder and charges neither counter (@spec metering#metering-evidence, #816)", async () => {
      const c = clock();
      const { open } = domainOnFile(c);
      const claims = open();
      const permit = await evaluate(request(c, { amount: "600.00" }), options(claims, c, view("msn_a", binding("msn_a"))));
      expectPermit(permit);
      expect(meteringOf(permit)).toEqual([
        {
          bound: "max_budget",
          counter_scope: "mission",
          counter_id: instanceCounter("msn_a"),
          requested: { amount: "600.00", currency: "USD" },
          reserved: { amount: "600.00", currency: "USD" },
          remaining: { amount: "400.00", currency: "USD" },
          settlement_state: "reserved",
        },
        {
          bound: "max_budget",
          counter_scope: "standing_consent",
          counter_id: SHARED,
          requested: { amount: "600.00", currency: "USD" },
          reserved: { amount: "600.00", currency: "USD" },
          remaining: { amount: "400.00", currency: "USD" },
          settlement_state: "reserved",
        },
      ]);
      expect((permit.context.decision_evidence as DecisionEvidenceObject).contributing_constraints).toContain("max_budget");
      const refused = await evaluate(
        request(c, { missionId: "msn_b", amount: "500.00" }),
        options(claims, c, view("msn_b", binding("msn_b"))),
      );
      expectDenied(refused, "quota_exceeded");
      const record = refused.context.decision_evidence as DecisionEvidenceObject;
      expect(record.denial_reason).toBe("quota_exceeded");
      expect(record.metering).toEqual([
        {
          bound: "max_budget",
          counter_scope: "mission",
          counter_id: instanceCounter("msn_b"),
          requested: { amount: "500.00", currency: "USD" },
          remaining: { amount: "1000.00", currency: "USD" },
        },
        {
          bound: "max_budget",
          counter_scope: "standing_consent",
          counter_id: SHARED,
          requested: { amount: "500.00", currency: "USD" },
          remaining: { amount: "400.00", currency: "USD" },
        },
      ]);
      // The entries are signed content, never a raw lineage or owner key.
      const verified = await verifyEvidenceEnvelope(record, DECISION_EVIDENCE_MEDIA_TYPE, (p) =>
        p.kid === "pdp-816" ? { key: evidenceKey.publicKey } : undefined,
      );
      expect(verified.valid).toBe(true);
      expect(JSON.stringify(record.metering)).not.toContain(OWNER);
      expect(JSON.stringify(record.metering)).not.toContain(BUDGET_ID);
      // The exhausted counter is named, and the refusal charged neither counter.
      const exhausted = (record.metering ?? []).filter((e) => Number(e.requested.amount) > Number(e.remaining.amount));
      expect(exhausted.map((e) => [e.counter_scope, e.counter_id])).toEqual([["standing_consent", SHARED]]);
      expect(claims.budgetCounter(SHARED)?.reserved.amount).toBe("600.00");
      expect(claims.budgetCounter(instanceCounter("msn_b"))).toBeUndefined();
      expect(claims.reservationsFor(refused.context.evaluation_id as string)).toEqual([]);
      claims.close();
    });
  });

  describe("the budget_metering declaration (decision c)", () => {
    it("the claim domain refuses to open on a malformed budget_metering declaration, claimed or not (@spec metering#topology, #816)", () => {
      const malformed: Array<[string, unknown]> = [
        ["not an object", "metered"],
        ["Bounded profile", { ...declaration(), enforcement_profile: "bounded" }],
        ["another topology", { ...declaration(), topology: "shared-linearizable" }],
        ["commit before execution", { ...declaration(), reserve_posture: "commit_before_execution" }],
        ["budget without an owner", { ...declaration(), budgets: [{ ...declaration().budgets[0], owner: "" }] }],
        ["owner at the declaration's top level", { ...declaration(), owner: OWNER }],
        ["unit without exponent", { ...declaration(), unit: { currency: "USD" } }],
        ["no metered action", { ...declaration(), metered_actions: [] }],
        ["unknown phase", { ...declaration(), metered_actions: [{ action: EXECUTE, phase: "settle" }] }],
        ["metered action without a phase", { ...declaration(), metered_actions: [{ action: EXECUTE }] }],
        ["no budget", { ...declaration(), budgets: [] }],
        ["lineage counter scope", { ...declaration(), budgets: [{ ...declaration().budgets[0], counter_scope: "lineage" }] }],
        ["budget in another currency", { ...declaration(), budgets: [{ ...declaration().budgets[0], currency: "EUR" }] }],
        ["limit the unit cannot count", { ...declaration(), budgets: [{ ...declaration().budgets[0], limit: "1000.001" }] }],
        ["policy without a version", { ...declaration(), budgets: [{ ...declaration().budgets[0], policies: [{ id: POLICY_V1.id, digest: POLICY_V1.digest }] }] }],
        ["policy without a digest", { ...declaration(), budgets: [{ ...declaration().budgets[0], policies: [{ id: POLICY_V1.id, version: "1" }] }] }],
        ["policy digest not sha-256", { ...declaration(), budgets: [{ ...declaration().budgets[0], policies: [{ ...POLICY_V1, digest: "md5:abc" }] }] }],
        ["policy in the template shape", { ...declaration(), budgets: [{ ...declaration().budgets[0], policies: [{ template_id: "tmpl_vendor_payments", template_version: "1" }] }] }],
        ["no policies", { ...declaration(), budgets: [{ ...declaration().budgets[0], policies: [] }] }],
        ["a single policy, not a list", { ...declaration(), budgets: [{ ...(({ policies: _list, ...rest }) => rest)(declaration().budgets[0] as BudgetMeteringDeclaration["budgets"][number]), policy: POLICY_V1 }] }],
        ["one policy version listed twice", { ...declaration(), budgets: [{ ...declaration().budgets[0], policies: [POLICY_V1, { ...POLICY_V1, digest: POLICY_V2.digest }] }] }],
        ["duplicate budget for one owner", { ...declaration(), budgets: [declaration().budgets[0], declaration().budgets[0]] }],
        ["unknown member", { ...declaration(), counter_owner: "mcp-payments-pdp" }],
      ];
      for (const [label, decl] of malformed) {
        for (const claimed of [true, false]) {
          const file = join(mkdtempSync(join(tmpdir(), "budget-816-")), "claims.sqlite");
          expect(
            () => openIdempotencyClaimDomain({ file, owner: CLAIM_OWNER, statement: budgetStatement(decl, claimed) }),
            `${label} (claimed: ${claimed})`,
          ).toThrow(ClaimDomainConfigError);
        }
      }
      // Claimed with no declaration attached.
      const bare = statementWithPrivilegedAdministration() as unknown as { claims?: string[] };
      bare.claims = [...(bare.claims ?? []), "budget_metering"];
      const file = join(mkdtempSync(join(tmpdir(), "budget-816-")), "claims.sqlite");
      expect(() =>
        openIdempotencyClaimDomain({ file, owner: CLAIM_OWNER, statement: bare as unknown as EnforcementScopeStatement }),
      ).toThrow(/budget_metering/);
    });

    it("a budget_metering declaration that does not name the claim settlement channel as its settlement intake is refused at load, claimed or not (@spec metering#settlement-contract, #816)", () => {
      const { settlement_intake: _named, ...unnamed } = declaration();
      const cases: Array<[string, unknown]> = [
        ["no settlement intake", unnamed],
        ["another settlement intake", { ...declaration(), settlement_intake: "event-api:ssf" }],
      ];
      for (const [label, decl] of cases) {
        for (const claimed of [true, false]) {
          const file = join(mkdtempSync(join(tmpdir(), "budget-816-")), "claims.sqlite");
          expect(
            () => openIdempotencyClaimDomain({ file, owner: CLAIM_OWNER, statement: budgetStatement(decl, claimed) }),
            `${label} (claimed: ${claimed})`,
          ).toThrow(/settlement/);
        }
      }
      // Control: the declaration naming the claim settlement channel opens and meters.
      const file = join(mkdtempSync(join(tmpdir(), "budget-816-")), "claims.sqlite");
      const claims = openIdempotencyClaimDomain({ file, owner: CLAIM_OWNER, statement: budgetStatement() });
      expect(claims.budgetMetering()).toBeDefined();
      claims.close();
    });

    it("a declaration in force only where claimed: unclaimed, and in the shipped statement that declares none, the PDP meters nothing and a budget-bound Mission is denied constraint_unsupported (@spec metering#topology, #816)", async () => {
      expect(RUNTIME_POSTURE.claims ?? []).not.toContain("budget_metering");
      expect(RUNTIME_POSTURE.extensions?.budget_metering).toBeUndefined();
      const c = clock();
      for (const statement of [budgetStatement(declaration(), false), RUNTIME_POSTURE as EnforcementScopeStatement]) {
        const file = join(mkdtempSync(join(tmpdir(), "budget-816-")), "claims.sqlite");
        const claims = openIdempotencyClaimDomain({ file, owner: CLAIM_OWNER, statement, now: c.now });
        expect(claims.budgetMetering()).toBeUndefined();
        const d = await evaluate(request(c), options(claims, c, view("msn_a", binding("msn_a"))));
        expectDenied(d, "constraint_unsupported");
        claims.close();
        expect(countsOf(file)).toEqual({ claims: 0, reservations: 0, counters: 0 });
      }
    });
  });
});

describe("the PDP-side budget binding and the committed destinations (@spec metering#metering, mission-template#standing-payment-exception, #813, #816)", () => {
  /** Decision options a caller (the PEP) supplies to a decision point, over `v`. */
  const callerOptions = (c: Clock, v: MissionView): DecisionOptions => ({
    view: v,
    fga: alwaysAllowFga,
    modelId: "model-816",
    now: c.now,
    stalenessBound,
    relationForAction,
    stateSourcePlacement: "pep",
  });
  const pointOver = (claims: IdempotencyClaimDomain, budgetBindings?: MissionBudgetSource) =>
    createDecisionPoint({
      claims,
      resourcePolicy: RESOURCE_POLICY_PERMITS_ALL_FIXTURE,
      evaluationContextBinding: EVALUATION_CONTEXT_UNCLAIMED_FIXTURE,
      ...(budgetBindings ? { budgetBindings } : {}),
    });

  it("a co-resident decision point meters the binding its own source derives, whether the caller's view omits the binding or carries another budget's, and a Mission its source does not bind stays unmetered whatever the caller's view carries (@spec metering#metering, #816, #813, decision d)", async () => {
    const c = clock();
    const { file, open } = domainOnFile(c);
    const claims = open();
    const point = pointOver(claims, (m) => (m.id === "msn_a" && m.issuer === ISSUER ? binding("msn_a") : undefined));
    // The caller's view omits the binding: the source's is metered.
    expectPermit(await point.decide(withCredential(request(c)), callerOptions(c, view("msn_a"))));
    expect(claims.budgetCounter(SHARED)?.reserved.amount).toBe("100.00");
    expect(claims.budgetCounter(instanceCounter("msn_a"))?.reserved.amount).toBe("100.00");
    // The caller's view carries a budget this PDP does not declare: the
    // source's binding is metered in its place, never refused for the caller's.
    const another = binding("msn_a", { budget_id: "undeclared-budget", limit: "999999.00" });
    expectPermit(await point.decide(withCredential(request(c)), callerOptions(c, view("msn_a", another))));
    expect(claims.budgetCounter(SHARED)?.reserved.amount).toBe("200.00");
    expect(claims.budgetCounter(budgetCounterId("standing_consent", { owner: OWNER, budget_id: "undeclared-budget" }))).toBeUndefined();
    // The source binds no budget to msn_b: the caller's binding meters nothing.
    expectPermit(
      await point.decide(withCredential(request(c, { missionId: "msn_b" })), callerOptions(c, view("msn_b", binding("msn_b")))),
    );
    expect(claims.budgetCounter(instanceCounter("msn_b"))).toBeUndefined();
    expect(claims.budgetCounter(SHARED)?.reserved.amount).toBe("200.00");
    claims.close();
    expect(countsOf(file)).toEqual({ claims: 3, reservations: 4, counters: 2 });
  });

  it("a decision point with no budget source denies constraint_unsupported a caller's view that carries a binding and reserves and claims nothing, and decides a view without one unmetered (@spec metering#metering, #816, #813, decision d)", async () => {
    const c = clock();
    const { file, open } = domainOnFile(c);
    const claims = open();
    const point = pointOver(claims);
    expectDenied(
      await point.decide(withCredential(request(c)), callerOptions(c, view("msn_a", binding("msn_a")))),
      "constraint_unsupported",
    );
    expect(claims.budgetCounter(SHARED)).toBeUndefined();
    claims.close();
    expect(countsOf(file)).toEqual({ claims: 0, reservations: 0, counters: 0 });
    // Control: the same request over a view without a binding is permitted, unmetered.
    const reopened = open();
    expectPermit(await pointOver(reopened).decide(withCredential(request(c)), callerOptions(c, view("msn_a"))));
    expect(reopened.budgetCounter(SHARED)).toBeUndefined();
    reopened.close();
    expect(countsOf(file)).toEqual({ claims: 1, reservations: 0, counters: 0 });
  });

  it("a Mission whose source answers the underivable marker, throws, or answers a malformed binding is denied constraint_unsupported for every action that would otherwise permit, a read included, and reserves and claims nothing (@spec metering#metering, mission-template#standing-payment-exception, #813, decision d)", async () => {
    const c = clock();
    const { file, open } = domainOnFile(c);
    const claims = open();
    const point = pointOver(claims, (m) => {
      if (m.id === "msn_a") return binding("msn_a");
      if (m.id === "msn_u") return UNDERIVABLE_BUDGET;
      if (m.id === "msn_m") return { ...binding("msn_m"), destinations: {} };
      throw new Error("the committed policy snapshot is unavailable");
    });
    const read = (missionId: string) => request(c, { missionId, action: READ, actionClass: "consequential_read", phase: null });
    for (const missionId of ["msn_u", "msn_m", "msn_t"]) {
      expectDenied(
        await point.decide(withCredential(request(c, { missionId })), callerOptions(c, view(missionId, binding(missionId)))),
        "constraint_unsupported",
      );
      // The caller's view omitting the binding changes nothing.
      expectDenied(await point.decide(withCredential(request(c, { missionId })), callerOptions(c, view(missionId))), "constraint_unsupported");
      expectDenied(await point.decide(withCredential(read(missionId)), callerOptions(c, view(missionId))), "constraint_unsupported");
    }
    // Control: the same read under a Mission whose binding derives is permitted and charges nothing.
    expectPermit(await point.decide(withCredential(read("msn_a")), callerOptions(c, view("msn_a"))));
    claims.close();
    expect(countsOf(file)).toEqual({ claims: 0, reservations: 0, counters: 0 });
  });

  it("a metered payment whose PEP-established payee is not the destination the policy commits for its vendor, whose vendor has no committed destination, or that carries no parameters is denied parameter_violation and reserves and claims nothing (@spec mission-template#standing-payment-exception, #813, D830 ruling 4)", async () => {
    const c = clock();
    const { file, open } = domainOnFile(c);
    const claims = open();
    const v = view("msn_a", binding("msn_a"));
    const cases: Array<[string, RequestOptions]> = [
      ["a changed bank account for the approved vendor", { parameters: { payee_account: "acct-acme-002" } }],
      ["a vendor without a committed destination", { vendor: "initech" }],
      ["no parameters", { parameters: null }],
    ];
    for (const [label, o] of cases) {
      const d = await evaluate(request(c, o), options(claims, c, v));
      expect(d.context.denial_reason, label).toBe("parameter_violation");
      expectDenied(d, "parameter_violation");
    }
    expect(claims.budgetCounter(SHARED)).toBeUndefined();
    expect(claims.budgetCounter(instanceCounter("msn_a"))).toBeUndefined();
    claims.close();
    expect(countsOf(file)).toEqual({ claims: 0, reservations: 0, counters: 0 });
    // Control: the committed destination is permitted and charged.
    const control = open();
    await permitted(control, c, v);
    expect(control.budgetCounter(SHARED)?.reserved.amount).toBe("100.00");
    control.close();
  });

  it("a metered payment whose parameters do not recompute to its parameter_digest, or name another vendor, amount or currency than the request, is denied parameter_violation and reserves and claims nothing, so the payee compared is the one the permit binds (@spec authzen#parameter-digest, mission-template#standing-payment-exception, #813)", async () => {
    const c = clock();
    const { file, open } = domainOnFile(c);
    const claims = open();
    // Both vendors have committed destinations, so only the consistency of
    // the parameters with the request and its digest can refuse.
    const v = view("msn_a", binding("msn_a", { destinations: { acme: PAYEE, globex: "acct-globex-001" } }));
    const boundElsewhere = canonicalDigest({
      action: EXECUTE,
      invoice_id: "inv-1",
      vendor_id: "acme",
      amount: { amount: "100.00", currency: "USD" },
      payee_account: "acct-acme-002",
      resource: RESOURCE,
    });
    const cases: Array<[string, RequestOptions]> = [
      ["a parameter_digest computed over another payee", { digest: boundElsewhere }],
      ["parameters naming another vendor than the request", { parameters: { vendor_id: "globex", payee_account: "acct-globex-001" } }],
      ["parameters naming another amount than the request", { parameters: { amount: { amount: "50.00", currency: "USD" } } }],
      ["parameters naming another currency than the request", { parameters: { amount: { amount: "100.00", currency: "EUR" } } }],
    ];
    for (const [label, o] of cases) {
      const d = await evaluate(request(c, o), options(claims, c, v));
      expect(d.context.denial_reason, label).toBe("parameter_violation");
      expectDenied(d, "parameter_violation");
    }
    claims.close();
    expect(countsOf(file)).toEqual({ claims: 0, reservations: 0, counters: 0 });
  });

  it("the preflight and prepare phases of the metered action are held to the committed destination too: another payee is denied parameter_violation, the committed one permitted (@spec mission-template#standing-payment-exception, metering#metering, #813)", async () => {
    const c = clock();
    const { open } = domainOnFile(c);
    const claims = open();
    const v = view("msn_a", binding("msn_a"));
    for (const [phase, actionClass] of [
      ["preflight", "consequential_read"],
      ["prepare", "consequential_write"],
    ] as const) {
      expectDenied(
        await evaluate(request(c, { phase, actionClass, parameters: { payee_account: "acct-acme-002" } }), options(claims, c, v)),
        "parameter_violation",
      );
      expectPermit(await evaluate(request(c, { phase, actionClass }), options(claims, c, v)));
    }
    claims.close();
  });
});

describe("a budget-bound permit suppressed before redemption (@spec metering#settlement-states, #813, #816, decision e)", () => {
  /** The redemption owner's answer for a permit no attempt redeemed. */
  const notRedeemed = () => undefined;
  const states = (claims: IdempotencyClaimDomain, evaluationId: string) => claims.reservationsFor(evaluationId).map((r) => r.state);

  it("the permit holder's signed suppressed record for a permit no attempt redeemed releases both reservations without settling the claim, and the redeeming attempt's later completed settlement still commits them (@spec metering#settlement-states, #813, #816, decision e)", async () => {
    const c = clock();
    const { open } = domainOnFile(c);
    const claims = open();
    const evaluationId = await permitted(claims, c, view("msn_a", binding("msn_a")), { amount: "300.00" });
    expect(await claims.releaseUnredeemed(REQUESTER, await executionRecord(evaluationId, "suppressed"), notRedeemed)).toEqual({
      accepted: true,
      released: 2,
    });
    expect(states(claims, evaluationId)).toEqual(["released", "released"]);
    expect(claims.budgetCounter(SHARED)).toMatchObject({ reserved: { amount: "0.00" }, held: { amount: "0.00" }, committed: { amount: "0.00" } });
    // The claim is not settled: a retransmitted permit can still be redeemed,
    // and its completed record commits the spend from released.
    expect(await claims.settle(REQUESTER, await executionRecord(evaluationId, "completed"))).toEqual({
      accepted: true,
      state: "completed",
      duplicate: false,
    });
    expect(states(claims, evaluationId)).toEqual(["committed", "committed"]);
    expect(claims.budgetCounter(SHARED)?.committed.amount).toBe("300.00");
    expect(claims.budgetCounter(instanceCounter("msn_a"))?.committed.amount).toBe("300.00");
    claims.close();
  });

  it("the permit holder's suppression before redemption releases a reservation already held for its elapsed lease too (@spec metering#settlement-states, #813, #816, decision e)", async () => {
    const c = clock();
    const { open } = domainOnFile(c);
    const claims = open();
    const evaluationId = await permitted(claims, c, view("msn_a", binding("msn_a")), { amount: "300.00" });
    c.set(T0 + PAST_LEASE_MS);
    claims.sweep();
    expect(states(claims, evaluationId)).toEqual(["held", "held"]);
    expect(await claims.releaseUnredeemed(REQUESTER, await executionRecord(evaluationId, "suppressed"), notRedeemed)).toEqual({
      accepted: true,
      released: 2,
    });
    expect(states(claims, evaluationId)).toEqual(["released", "released"]);
    expect(claims.budgetCounter(SHARED)).toMatchObject({ reserved: { amount: "0.00" }, held: { amount: "0.00" } });
    claims.close();
  });

  it("a release on a suppression before redemption does not outlive the redeeming attempt's later failed settlement, which holds the reservations again (@spec metering#settlement-states, #813, #816, D830 ruling 10)", async () => {
    const c = clock();
    const { open } = domainOnFile(c);
    const claims = open();
    const evaluationId = await permitted(claims, c, view("msn_a", binding("msn_a")), { amount: "300.00" });
    expect((await claims.releaseUnredeemed(REQUESTER, await executionRecord(evaluationId, "suppressed"), notRedeemed)).accepted).toBe(true);
    const redeeming = `exe_${randomUUID()}`;
    expect(await claims.settle(REQUESTER, await executionRecord(evaluationId, "failed", redeeming), () => redeeming)).toEqual({
      accepted: true,
      state: "failed",
      duplicate: false,
    });
    expect(states(claims, evaluationId)).toEqual(["held", "held"]);
    expect(claims.budgetCounter(SHARED)).toMatchObject({ reserved: { amount: "0.00" }, held: { amount: "300.00" } });
    claims.close();
  });

  it("a suppression is refused and releases nothing when the redemption owner names a redeeming attempt, the record marks a consumed permit or is not a PEP's suppressed record, another PEP or epoch presents it, the domain is bound to no redemption record, the claim is already settled, or the permit reserved no budget (@spec metering#settlement-states, runtime#idempotency, #813, #816)", async () => {
    const c = clock();
    const { open } = domainOnFile(c);
    const claims = open();
    const v = view("msn_a", binding("msn_a", { limit: "1000.00" }));
    const permit = () => permitted(claims, c, v, { amount: "10.00" });
    const cases: Array<[string, (id: string) => ReturnType<IdempotencyClaimDomain["releaseUnredeemed"]>, string]> = [
      ["the redemption owner names a redeeming attempt", async (id) => claims.releaseUnredeemed(REQUESTER, await executionRecord(id, "suppressed"), () => "exe_redeemer"), "permit_redeemed"],
      [
        "the record marks a permit already consumed",
        async (id) => claims.releaseUnredeemed(REQUESTER, await executionRecord(id, "suppressed", undefined, { error: "permit_consumed" }), notRedeemed),
        "permit_consumed",
      ],
      [
        "an executor's record",
        async (id) => claims.releaseUnredeemed(REQUESTER, await executionRecord(id, "suppressed", undefined, { role: "executor" }), notRedeemed),
        "not_a_pep_record",
      ],
      ["a failed record", async (id) => claims.releaseUnredeemed(REQUESTER, await executionRecord(id, "failed"), notRedeemed), "not_a_suppression"],
      [
        "another PEP",
        async (id) => claims.releaseUnredeemed({ ...REQUESTER, pep_id: "another-pep" }, await executionRecord(id, "suppressed"), notRedeemed),
        "not_the_permit_holder",
      ],
      [
        "another epoch of the same PEP",
        async (id) => claims.releaseUnredeemed({ ...REQUESTER, pep_epoch: "epoch-816-b" }, await executionRecord(id, "suppressed"), notRedeemed),
        "not_the_permit_holder",
      ],
      ["no redemption record bound", async (id) => claims.releaseUnredeemed(REQUESTER, await executionRecord(id, "suppressed")), "no_redemption_record"],
    ];
    for (const [label, release, reason] of cases) {
      const evaluationId = await permit();
      expect(await release(evaluationId), label).toEqual({ accepted: false, reason });
      expect(states(claims, evaluationId), label).toEqual(["reserved", "reserved"]);
    }
    // A claim the redeeming attempt already settled failed: held, and no
    // later suppression releases it.
    const settled = await permit();
    const redeeming = `exe_${randomUUID()}`;
    expect((await claims.settle(REQUESTER, await executionRecord(settled, "failed", redeeming), () => redeeming)).accepted).toBe(true);
    expect(await claims.releaseUnredeemed(REQUESTER, await executionRecord(settled, "suppressed"), notRedeemed)).toEqual({
      accepted: false,
      reason: "already_settled",
    });
    expect(states(claims, settled)).toEqual(["held", "held"]);
    // A permit that reserved no budget has nothing to release, and its claim stays open.
    const unmetered = await permitted(claims, c, view("msn_b"));
    expect(await claims.releaseUnredeemed(REQUESTER, await executionRecord(unmetered, "suppressed"), notRedeemed)).toEqual({
      accepted: false,
      reason: "no_open_reservation",
    });
    expect((await claims.settle(REQUESTER, await executionRecord(unmetered, "completed"))).accepted).toBe(true);
    claims.close();
  });
});
