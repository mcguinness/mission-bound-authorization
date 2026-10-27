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
  BudgetMeteringConfigError,
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
  DecisionRequestRefused,
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
  type ReleasedReservation,
  openIdempotencyClaimDomain,
  type SettlementConflict,
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
  o: { error?: string | null; signer?: CryptoKeyLike } = {},
): Promise<Record<string, unknown>> {
  const content = {
    execution_id: executionId,
    evaluation_id: evaluationId,
    mission_id: "msn_a",
    audience: RESOURCE,
    outcome,
    outcome_at: new Date(T0).toISOString(),
    sequence: 1,
    emitter: { id: RESOURCE, role: outcome === "completed" ? "executor" : "pep" },
    ...(outcome === "suppressed" ? { error: o.error ?? "kill_switch" } : o.error !== undefined ? { error: o.error } : {}),
  };
  const evidence_envelope = await signEvidenceEnvelope(content, EXECUTION_EVIDENCE_MEDIA_TYPE, {
    kid: "pep-exec-816",
    key: o.signer ?? executionKey.privateKey,
  });
  return { ...content, evidence_envelope };
}

/** The private-key type `generateKeyPairSync` returns, for a record signed under another key. */
type CryptoKeyLike = ReturnType<typeof generateKeyPairSync>["privateKey"];

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
function domainOnFile(
  c: Clock,
  hooks: { held?: HeldReservation[]; overspent?: BudgetOverspend[]; released?: ReleasedReservation[]; conflicts?: SettlementConflict[] } = {},
) {
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
      ...(hooks.released ? { onReservationReleased: (r: ReleasedReservation) => hooks.released?.push(r) } : {}),
      ...(hooks.conflicts ? { onSettlementConflict: (s: SettlementConflict) => hooks.conflicts?.push(s) } : {}),
    });
  return { file, open };
}

/** One claim row straight from the file, after the domain released it. */
function claimRowOf(
  file: string,
  evaluationId: string,
): { state: string; execution_id: string | null; outcome: string | null; error: string | null; decision_json: string | null } | undefined {
  const db = openDurableStore({ file, migrations: claimSchemaPlaceholders(), owner: CLAIM_OWNER });
  try {
    return db
      .prepare("SELECT state, execution_id, outcome, error, decision_json FROM claims WHERE evaluation_id = ?")
      .get(evaluationId) as { state: string; execution_id: string | null; outcome: string | null; error: string | null; decision_json: string | null } | undefined;
  } finally {
    db.close();
  }
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
  /** The request's `parameter_digest`; `null` sends none. */
  digest?: string | null;
  /** `context.actor`; defaults to the approved client. */
  actor?: NonNullable<EvaluationRequest["context"]["actor"]>;
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
      actor: o.actor ?? { client_id: "ap-agent" },
      ...(o.actionClass === null ? {} : { action_class: o.actionClass ?? "irreversible_action" }),
      ...(o.digest === null ? {} : { parameter_digest: o.digest ?? canonicalDigest(parameters) }),
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

/**
 * A permit whose reservation an operator released after its lease, though
 * the wire did execute: the incorrect release a budget correction repairs.
 * The clock is left past the lease.
 */
async function incorrectlyReleased(claims: IdempotencyClaimDomain, c: Clock, missionId = "msn_a", amount = "300.00"): Promise<string> {
  const evaluationId = await permitted(claims, c, view(missionId, binding(missionId)), { amount });
  c.set(c.now().getTime() + PAST_LEASE_MS);
  claims.sweep();
  expect(claims.reconcileHeldReservation(evaluationId, { kind: "not_executed", reference: "bank-no-entry-yet" })).toEqual({
    accepted: true,
    state: "released",
  });
  return evaluationId;
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

    it("lease expiry, the reconciliation window and the claim's horizon never release a held reservation, and committed spend persists past the class horizon (@spec metering#settlement-states, #816)", async () => {
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
      // Past the class horizon: a metered claim is not purged, and its reservations never are.
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

    it("after an incorrect operator release and the claim's reconciliation window, the permit's own PEP's verified completed record commits the 300.00 once, reports the overspend, and further reservations are refused while no headroom remains (@spec metering#settlement-states, #816)", async () => {
      const c = clock();
      const overspent: BudgetOverspend[] = [];
      const { open } = domainOnFile(c, { overspent });
      const claims = open();
      const a = await incorrectlyReleased(claims, c);
      // The released headroom is spent by another instance meanwhile.
      await permitted(claims, c, view("msn_b", binding("msn_b")), { amount: "800.00" });
      c.set(c.now().getTime() + PAST_WINDOW_MS + 1_000);
      claims.sweep();
      const record = await executionRecord(a, "completed");
      expect(await claims.settle(REQUESTER, record)).toEqual({ accepted: true, state: "completed", duplicate: false, budget_corrected: true });
      expect(claims.reservationsFor(a).map((r) => r.state)).toEqual(["committed", "committed"]);
      expect(claims.budgetCounter(SHARED)?.committed.amount).toBe("300.00");
      expect(overspent.map((o) => [o.evaluation_id, o.counter_scope, o.used.amount, o.limit.amount])).toEqual([[a, "standing_consent", "1100.00", "1000.00"]]);
      // A redelivery is acknowledged and changes nothing.
      expect(await claims.settle(REQUESTER, record)).toEqual({ accepted: true, state: "completed", duplicate: true, budget_corrected: true });
      expect(claims.budgetCounter(SHARED)?.committed.amount).toBe("300.00");
      expect(overspent).toHaveLength(1);
      // No headroom remains: the next reservation is refused.
      expectDenied(await evaluate(request(c, { missionId: "msn_c", amount: "1.00" }), options(claims, c, view("msn_c", binding("msn_c")))), "quota_exceeded");
      claims.close();
    });

    it("after an incorrect operator release and the claim's reconciliation window, an operator correction recording execution commits the 300.00 once (@spec metering#settlement-states, #816)", async () => {
      const c = clock();
      const { open } = domainOnFile(c);
      const claims = open();
      const a = await incorrectlyReleased(claims, c);
      c.set(c.now().getTime() + PAST_WINDOW_MS + 1_000);
      claims.sweep();
      const correction = { kind: "executed" as const, reference: "bank-statement-2026-10-26" };
      expect(claims.reconcileHeldReservation(a, correction)).toEqual({ accepted: true, state: "committed" });
      expect(claims.reservationsFor(a).map((r) => r.state)).toEqual(["committed", "committed"]);
      expect(claims.budgetCounter(SHARED)?.committed.amount).toBe("300.00");
      expect(claims.reconcileHeldReservation(a, correction)).toEqual({ accepted: true, state: "committed", duplicate: true });
      expect(claims.budgetCounter(SHARED)?.committed.amount).toBe("300.00");
      claims.close();
    });

    it("the PEP's verified completed record and the operator's executed correction together commit each released reservation once, in either order (@spec metering#settlement-states, #816)", async () => {
      const c = clock();
      const { open } = domainOnFile(c);
      const claims = open();
      const a = await incorrectlyReleased(claims, c, "msn_a", "300.00");
      const b = await incorrectlyReleased(claims, c, "msn_b", "200.00");
      c.set(c.now().getTime() + PAST_WINDOW_MS + 1_000);
      claims.sweep();
      const correction = { kind: "executed" as const, reference: "bank-statement-2026-10-26" };
      expect((await claims.settle(REQUESTER, await executionRecord(a, "completed"))).accepted).toBe(true);
      expect(claims.reconcileHeldReservation(a, correction)).toEqual({ accepted: true, state: "committed", duplicate: true });
      expect(claims.reconcileHeldReservation(b, correction)).toEqual({ accepted: true, state: "committed" });
      expect(await claims.settle(REQUESTER, await executionRecord(b, "completed"))).toMatchObject({ accepted: true, duplicate: true, budget_corrected: true });
      expect(claims.budgetCounter(SHARED)?.committed.amount).toBe("500.00");
      expect(claims.budgetCounter(instanceCounter("msn_a"))?.committed.amount).toBe("300.00");
      expect(claims.budgetCounter(instanceCounter("msn_b"))?.committed.amount).toBe("200.00");
      claims.close();
    });

    it("a budget correction for an unknown evaluation, from another PEP or epoch, or for an evaluation that never issued a permit is refused and commits nothing (@spec metering#settlement-states, #816)", async () => {
      const c = clock();
      const { open } = domainOnFile(c);
      const claims = open();
      // An evaluation that never persisted its permit: its reservation is released, no permit left the PDP.
      let unpersisted = "";
      const failing: DecisionEvidenceEmitter = {
        emit: async (input) => {
          unpersisted = input.evaluation_id;
          throw new Error("evidence signer down");
        },
      };
      await expect(evaluate(request(c, { missionId: "msn_x", amount: "100.00" }), options(claims, c, view("msn_x", binding("msn_x")), { evidence: failing }))).rejects.toThrow(/signer down/);
      expect(claims.reservationsFor(unpersisted).map((r) => r.state)).toEqual(["released", "released"]);
      const a = await incorrectlyReleased(claims, c);
      c.set(c.now().getTime() + PAST_WINDOW_MS + 1_000);
      claims.sweep();
      const record = await executionRecord(a, "completed");
      expect((await claims.settle(REQUESTER, await executionRecord("dec_unknown", "completed"))).accepted).toBe(false);
      expect(await claims.settle({ pep_id: "another-pep", pep_epoch: REQUESTER.pep_epoch }, record)).toMatchObject({ accepted: false });
      expect(await claims.settle({ pep_id: REQUESTER.pep_id, pep_epoch: "epoch-816-b" }, record)).toMatchObject({ accepted: false });
      expect(await claims.settle(REQUESTER, await executionRecord(unpersisted, "completed"))).toMatchObject({ accepted: false });
      expect(claims.reconcileHeldReservation(unpersisted, { kind: "executed", reference: "bank-statement-2026-10-26" })).toEqual({
        accepted: false,
        reason: "no_permit_issued",
      });
      expect(claims.reconcileHeldReservation("dec_unknown", { kind: "executed", reference: "bank-statement-2026-10-26" })).toEqual({
        accepted: false,
        reason: "unknown_evaluation",
      });
      expect(claims.reservationsFor(a).map((r) => r.state)).toEqual(["released", "released"]);
      expect(claims.reservationsFor(unpersisted).map((r) => r.state)).toEqual(["released", "released"]);
      expect(claims.budgetCounter(SHARED)?.committed.amount).toBe("0.00");
      // A second, conflicting completed record for a claim its own settlement committed keeps the claim's refusal.
      const d = await permitted(claims, c, view("msn_d", binding("msn_d")), { amount: "50.00" });
      expect((await claims.settle(REQUESTER, await executionRecord(d, "completed"))).accepted).toBe(true);
      expect(await claims.settle(REQUESTER, await executionRecord(d, "completed"))).toEqual({ accepted: false, reason: "already_settled" });
      expect(claims.budgetCounter(SHARED)?.committed.amount).toBe("50.00");
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
      // A repeated not_executed on the released reservation is an idempotent no-op; an executed
      // correction after an incorrect release is the correction path's (witnessed separately).
      expect(claims.reconcileHeldReservation(a, { kind: "not_executed", reference: "again" })).toEqual({ accepted: true, state: "released" });
      expect(claims.reservationsFor(a).map((r) => r.state)).toEqual(["released", "released"]);
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

    it("an amount-bearing action other than the metered action under a budget-bound Mission, whether consequential_write, irreversible_action or external_commitment, is denied constraint_unsupported and reserves and claims nothing (@spec metering#metering, #816, decision h)", async () => {
      const c = clock();
      const { file, open } = domainOnFile(c);
      const claims = open();
      const others: Array<[string, string | null]> = [
        [SCHEDULE, "consequential_write"],
        [REVERSE, "irreversible_action"],
        [REMIT, "external_commitment"],
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

    it("an unclassified amount-bearing action under a budget-bound Mission is refused before evaluation as action_class_missing and reserves and claims nothing (@spec runtime#classification, metering#metering, #956, #816)", async () => {
      const c = clock();
      const { file, open } = domainOnFile(c);
      const claims = open();
      const req = request(c, { action: SCHEDULE, actionClass: null, phase: null });
      // An explicit absent class: the shared fixture adds a default class only when the key is missing.
      const unclassified: EvaluationRequest = { ...req, context: { ...req.context, action_class: undefined } };
      const refused = evaluate(unclassified, options(claims, c, view("msn_a", binding("msn_a"))));
      await expect(refused).rejects.toBeInstanceOf(DecisionRequestRefused);
      await expect(refused).rejects.toMatchObject({ denial_reason: "action_class_missing" });
      claims.close();
      expect(countsOf(file)).toEqual({ claims: 0, reservations: 0, counters: 0 });
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

  it("createDecisionPoint over a claim domain that meters budgets refuses construction without a budget source, and a decision point over one that meters none denies constraint_unsupported a caller's view that carries a binding and reserves and claims nothing (@spec metering#metering, #816, #813, decision d)", async () => {
    const c = clock();
    const metering = domainOnFile(c);
    const claims = metering.open();
    expect(() => pointOver(claims)).toThrow(BudgetMeteringConfigError);
    expect(() => pointOver(claims)).toThrow(
      "createDecisionPoint over a claim domain that meters budgets requires a budget binding source (budgetBindings)",
    );
    claims.close();
    // A domain whose statement meters no budget needs no source, and never meters a caller's binding.
    const { file, open } = domainOnFile(c);
    const plain = open(budgetStatement(declaration(), false));
    const point = pointOver(plain);
    expectDenied(await point.decide(withCredential(request(c)), callerOptions(c, view("msn_a", binding("msn_a")))), "constraint_unsupported");
    plain.close();
    expect(countsOf(file)).toEqual({ claims: 0, reservations: 0, counters: 0 });
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

  it("under a standing-payment instance the PDP itself refuses parameter_violation a payment over the entry's per-payment max_amount, decided on the Mission bound with an unconstrained credential, reserving and claiming nothing, and permits and charges exactly the bound (@spec mission-template#standing-payment-exception, mission#max-amount, #813)", async () => {
    const c = clock();
    const { file, open } = domainOnFile(c);
    const claims = open();
    const capped: MissionView = {
      ...view("msn_a", binding("msn_a")),
      authority_set: [
        {
          type: MISSION_RESOURCE_ACCESS_TYPE,
          resource: RESOURCE,
          actions: [EXECUTE],
          constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
        },
      ],
    };
    // withCredential gives the request a credential with no constraints, so
    // only the Mission's own entry bounds the amount.
    const over = await evaluate(request(c, { amount: "500.01" }), options(claims, c, capped));
    expectDenied(over, "parameter_violation");
    expect((over.context.decision_evidence as DecisionEvidenceObject).authority_bound).toBe("mission");
    expect(claims.budgetCounter(SHARED)).toBeUndefined();
    claims.close();
    expect(countsOf(file)).toEqual({ claims: 0, reservations: 0, counters: 0 });
    const reopened = open();
    expectPermit(await evaluate(request(c, { amount: "500.00" }), options(reopened, c, capped)));
    expect(reopened.budgetCounter(SHARED)?.reserved.amount).toBe("500.00");
    reopened.close();
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

describe("a budget-bound permit suppressed before redemption stays charged (@spec metering#settlement-states, #813, #816, owner ruling)", () => {
  const states = (claims: IdempotencyClaimDomain, evaluationId: string) => claims.reservationsFor(evaluationId).map((r) => r.state);

  it("the owner's sequence: a permit of 300 suppressed before redemption stays charged, its PEP-signed suppressed record is no settlement without the redeeming attempt, the next 1,000 against a 1,000 budget is quota_exceeded naming the standing_consent counter, and the permit's later completed commits its own 300 alone (@spec metering#settlement-states, metering#aggregate-bounds, #813, #816, owner ruling)", async () => {
    const c = clock();
    const { open } = domainOnFile(c);
    const claims = open();
    const first = await permitted(claims, c, view("msn_a", binding("msn_a")), { amount: "300.00" });
    // The PEP refused the permit before redeeming it. Its signed record names
    // no redeeming attempt, so it settles nothing and releases nothing.
    expect(await claims.settle(REQUESTER, await executionRecord(first, "suppressed"), () => undefined)).toEqual({
      accepted: false,
      reason: "redeeming_attempt_unknown",
    });
    expect(states(claims, first)).toEqual(["reserved", "reserved"]);
    const second = await evaluate(request(c, { missionId: "msn_b", amount: "1000.00" }), options(claims, c, view("msn_b", binding("msn_b"))));
    expectDenied(second, "quota_exceeded");
    expect(entry(second, "standing_consent")).toMatchObject({ counter_id: SHARED, remaining: { amount: "700.00", currency: "USD" } });
    // Should the permit complete after all, only its own 300 commits.
    expect((await claims.settle(REQUESTER, await executionRecord(first, "completed"))).accepted).toBe(true);
    expect(claims.budgetCounter(SHARED)).toMatchObject({ reserved: { amount: "0.00" }, held: { amount: "0.00" }, committed: { amount: "300.00" } });
    claims.close();
  });

  it("an operator's not_executed on a held reservation releases it with one resolution notice, and a repeated not_executed on the released reservation is an idempotent no-op raising none (@spec metering#settlement-states, #813, #816)", async () => {
    const c = clock();
    const held: HeldReservation[] = [];
    const released: ReleasedReservation[] = [];
    const { open } = domainOnFile(c, { held, released });
    const claims = open();
    const evaluationId = await permitted(claims, c, view("msn_a", binding("msn_a")), { amount: "300.00" });
    c.set(T0 + PAST_LEASE_MS + 1);
    claims.sweep();
    expect(held.map((h) => [h.evaluation_id, h.cause])).toEqual([[evaluationId, "lease_elapsed"]]);
    expect(claims.reconcileHeldReservation(evaluationId, { kind: "not_executed", reference: "ticket-1" })).toEqual({ accepted: true, state: "released" });
    expect(released.map((r) => [r.evaluation_id, r.cause])).toEqual([[evaluationId, "operator_reconciled:not_executed:ticket-1"]]);
    expect(claims.reconcileHeldReservation(evaluationId, { kind: "not_executed", reference: "ticket-1-again" })).toEqual({
      accepted: true,
      state: "released",
    });
    expect(claims.reservationsFor(evaluationId).map((r) => [r.state, r.cause])).toEqual([
      ["released", "operator_reconciled:not_executed:ticket-1"],
      ["released", "operator_reconciled:not_executed:ticket-1"],
    ]);
    expect(released).toHaveLength(1);
    claims.close();
  });
});

describe("PDP exact budget reservations, slice 4 (@spec metering#settlement-contract, metering#retry, metering#aggregate-bounds, metering#metering-evidence, metering#settlement-states, #816, D877)", () => {
  describe("a conflicting settlement fails closed (@spec metering#settlement-contract)", () => {
    it("a completed record arriving after an applied suppressed settlement commits the budget, leaves the applied claim settlement unchanged, is retained, and raises the conflict alarm once (@spec metering#settlement-contract, metering#settlement-states, #816, D877)", async () => {
      const c = clock();
      const conflicts: SettlementConflict[] = [];
      const { file, open } = domainOnFile(c, { conflicts });
      const claims = open();
      const a = await permitted(claims, c, view("msn_a", binding("msn_a")), { amount: "300.00" });
      const suppressed = await executionRecord(a, "suppressed");
      expect(await claims.settle(REQUESTER, suppressed, () => String(suppressed.execution_id))).toEqual({ accepted: true, state: "failed", duplicate: false });
      expect(claims.reservationsFor(a).map((r) => r.state)).toEqual(["released", "released"]);
      // The wire did move after all: a completed record from another attempt.
      const completed = await executionRecord(a, "completed");
      expect(await claims.settle(REQUESTER, completed)).toEqual({ accepted: false, reason: "already_settled" });
      expect(claims.reservationsFor(a).map((r) => r.state)).toEqual(["committed", "committed"]);
      expect(claims.budgetCounter(SHARED)).toMatchObject({ reserved: { amount: "0.00" }, committed: { amount: "300.00" } });
      expect(claims.settlementConflicts(a)).toEqual([
        { execution_id: completed.execution_id, outcome: "completed", applied_execution_id: suppressed.execution_id, applied_outcome: "suppressed", record: completed },
      ]);
      expect(conflicts).toEqual([
        expect.objectContaining({ evaluation_id: a, mission_id: "msn_a", execution_id: completed.execution_id, outcome: "completed", applied_outcome: "suppressed" }),
      ]);
      // A redelivery of the conflicting record retains nothing new, alarms nothing new and commits nothing twice.
      expect(await claims.settle(REQUESTER, completed)).toEqual({ accepted: false, reason: "already_settled" });
      expect(claims.settlementConflicts(a)).toHaveLength(1);
      expect(conflicts).toHaveLength(1);
      expect(claims.budgetCounter(SHARED)?.committed.amount).toBe("300.00");
      claims.close();
      // The applied claim settlement is unchanged.
      expect(claimRowOf(file, a)).toMatchObject({ state: "failed", execution_id: suppressed.execution_id, outcome: "suppressed" });
    });

    it("a record from the applied attempt with another outcome is retained and alarmed, never acknowledged as a duplicate, and leaves the applied settlement and both counters unchanged (@spec metering#settlement-contract, #816, D877)", async () => {
      const c = clock();
      const conflicts: SettlementConflict[] = [];
      const { file, open } = domainOnFile(c, { conflicts });
      const claims = open();
      const a = await permitted(claims, c, view("msn_a", binding("msn_a")), { amount: "300.00" });
      const executionId = `exe_${randomUUID()}`;
      const completed = await executionRecord(a, "completed", executionId);
      expect((await claims.settle(REQUESTER, completed)).accepted).toBe(true);
      // The same attempt now reports suppression: a conflict, not a duplicate.
      const suppressed = await executionRecord(a, "suppressed", executionId);
      expect(await claims.settle(REQUESTER, suppressed, () => executionId)).toEqual({ accepted: false, reason: "already_settled" });
      expect(claims.settlementConflicts(a)).toEqual([
        { execution_id: executionId, outcome: "suppressed", applied_execution_id: executionId, applied_outcome: "completed", record: suppressed },
      ]);
      expect(conflicts).toEqual([expect.objectContaining({ evaluation_id: a, execution_id: executionId, outcome: "suppressed", applied_outcome: "completed" })]);
      expect(claims.reservationsFor(a).map((r) => r.state)).toEqual(["committed", "committed"]);
      expect(claims.budgetCounter(SHARED)).toMatchObject({ reserved: { amount: "0.00" }, committed: { amount: "300.00" } });
      expect(claims.budgetCounter(instanceCounter("msn_a"))).toMatchObject({ reserved: { amount: "0.00" }, committed: { amount: "300.00" } });
      // Control: the applied record itself, redelivered, is the duplicate.
      expect(await claims.settle(REQUESTER, completed)).toEqual({ accepted: true, state: "completed", duplicate: true });
      claims.close();
      expect(claimRowOf(file, a)).toMatchObject({ state: "completed", execution_id: executionId, outcome: "completed" });
    });

    it("once a settlement is applied, a non-completed record goes to the conflict check whatever the redemption owner can answer: the applied attempt's suppressed record with no answer and a second attempt's failed record are each retained and alarmed, and neither moves a counter (@spec metering#settlement-contract, #816, D877)", async () => {
      const c = clock();
      const conflicts: SettlementConflict[] = [];
      const { open } = domainOnFile(c, { conflicts });
      const claims = open();
      const a = await permitted(claims, c, view("msn_a", binding("msn_a")), { amount: "300.00" });
      const executionId = `exe_${randomUUID()}`;
      const completed = await executionRecord(a, "completed", executionId);
      expect((await claims.settle(REQUESTER, completed)).accepted).toBe(true);
      // The PEP lost its redemption record (a restart, a timeout, another epoch): no answer names the redeeming attempt.
      const suppressed = await executionRecord(a, "suppressed", executionId);
      expect(await claims.settle(REQUESTER, suppressed, () => undefined)).toEqual({ accepted: false, reason: "already_settled" });
      // A second attempt's failed record, which the redemption owner says did not redeem.
      const failed = await executionRecord(a, "failed");
      expect(await claims.settle(REQUESTER, failed, () => executionId)).toEqual({ accepted: false, reason: "already_settled" });
      expect(claims.settlementConflicts(a).map((r) => [r.execution_id, r.outcome, r.applied_execution_id])).toEqual([
        [executionId, "suppressed", executionId],
        [failed.execution_id, "failed", executionId],
      ]);
      expect(conflicts.map((r) => [r.execution_id, r.outcome])).toEqual([
        [executionId, "suppressed"],
        [failed.execution_id, "failed"],
      ]);
      expect(claims.reservationsFor(a).map((r) => r.state)).toEqual(["committed", "committed"]);
      expect(claims.budgetCounter(SHARED)).toMatchObject({ reserved: { amount: "0.00" }, held: { amount: "0.00" }, committed: { amount: "300.00" } });
      expect(claims.budgetCounter(instanceCounter("msn_a"))).toMatchObject({ reserved: { amount: "0.00" }, held: { amount: "0.00" }, committed: { amount: "300.00" } });
      claims.close();
    });

    it("a completed record from another attempt commits a reservation an applied failed record holds, and is retained and alarmed (@spec metering#settlement-contract, metering#settlement-states, #816, D877)", async () => {
      const c = clock();
      const conflicts: SettlementConflict[] = [];
      const { open } = domainOnFile(c, { conflicts });
      const claims = open();
      const a = await permitted(claims, c, view("msn_a", binding("msn_a")), { amount: "300.00" });
      const failed = await executionRecord(a, "failed");
      expect(await claims.settle(REQUESTER, failed, () => String(failed.execution_id))).toEqual({ accepted: true, state: "failed", duplicate: false });
      expect(claims.reservationsFor(a).map((r) => r.state)).toEqual(["held", "held"]);
      const completed = await executionRecord(a, "completed");
      expect(await claims.settle(REQUESTER, completed)).toEqual({ accepted: false, reason: "already_settled" });
      expect(claims.reservationsFor(a).map((r) => [r.state, r.cause])).toEqual([
        ["committed", `conflict_completed:${String(completed.execution_id)}`],
        ["committed", `conflict_completed:${String(completed.execution_id)}`],
      ]);
      expect(claims.budgetCounter(SHARED)).toMatchObject({ reserved: { amount: "0.00" }, held: { amount: "0.00" }, committed: { amount: "300.00" } });
      expect(claims.settlementConflicts(a).map((r) => [r.execution_id, r.applied_outcome])).toEqual([[completed.execution_id, "failed"]]);
      expect(conflicts).toHaveLength(1);
      claims.close();
    });

    it("an applied failed record holds the reservation, and the same attempt's later suppressed record is a conflict that leaves it held, retained and alarmed, while the failed record redelivered without a redemption answer is the duplicate (@spec metering#settlement-contract, metering#settlement-states, #816, D877)", async () => {
      const c = clock();
      const conflicts: SettlementConflict[] = [];
      const { open } = domainOnFile(c, { conflicts });
      const claims = open();
      const a = await permitted(claims, c, view("msn_a", binding("msn_a")), { amount: "300.00" });
      const executionId = `exe_${randomUUID()}`;
      const failed = await executionRecord(a, "failed", executionId);
      expect(await claims.settle(REQUESTER, failed, () => executionId)).toEqual({ accepted: true, state: "failed", duplicate: false });
      expect(await claims.settle(REQUESTER, failed, () => undefined)).toEqual({ accepted: true, state: "failed", duplicate: true });
      const suppressed = await executionRecord(a, "suppressed", executionId);
      expect(await claims.settle(REQUESTER, suppressed, () => executionId)).toEqual({ accepted: false, reason: "already_settled" });
      expect(claims.reservationsFor(a).map((r) => r.state)).toEqual(["held", "held"]);
      expect(claims.budgetCounter(SHARED)).toMatchObject({ reserved: { amount: "0.00" }, held: { amount: "300.00" }, committed: { amount: "0.00" } });
      expect(claims.settlementConflicts(a).map((r) => [r.execution_id, r.outcome, r.applied_outcome])).toEqual([[executionId, "suppressed", "failed"]]);
      expect(conflicts).toHaveLength(1);
      claims.close();
    });

    it("a conflicting completed record from another redemption-store epoch of the permit's PEP is retained and alarmed but commits nothing, as the correction path refuses it, and the same record from the permit's own epoch commits (@spec metering#settlement-states, metering#settlement-contract, #816, D877)", async () => {
      const c = clock();
      const conflicts: SettlementConflict[] = [];
      const { open } = domainOnFile(c, { conflicts });
      const claims = open();
      const a = await permitted(claims, c, view("msn_a", binding("msn_a")), { amount: "300.00" });
      const failed = await executionRecord(a, "failed");
      expect((await claims.settle(REQUESTER, failed, () => String(failed.execution_id))).accepted).toBe(true);
      const completed = await executionRecord(a, "completed");
      expect(await claims.settle({ ...REQUESTER, pep_epoch: "epoch-816-b" }, completed)).toEqual({ accepted: false, reason: "already_settled" });
      expect(claims.reservationsFor(a).map((r) => r.state)).toEqual(["held", "held"]);
      expect(claims.budgetCounter(SHARED)).toMatchObject({ held: { amount: "300.00" }, committed: { amount: "0.00" } });
      expect(claims.settlementConflicts(a)).toHaveLength(1);
      expect(conflicts).toHaveLength(1);
      // Control: from the epoch the permit was issued to, the record commits (already retained, so not alarmed again).
      expect(await claims.settle(REQUESTER, completed)).toEqual({ accepted: false, reason: "already_settled" });
      expect(claims.reservationsFor(a).map((r) => r.state)).toEqual(["committed", "committed"]);
      expect(conflicts).toHaveLength(1);
      claims.close();
    });

    it("a conflicting completed record never commits a reservation released because no permit left the PDP, a state written into the file here since no path produces it on a settled claim (@spec metering#settlement-states, #816, D877)", async () => {
      const c = clock();
      const conflicts: SettlementConflict[] = [];
      const { file, open } = domainOnFile(c, { conflicts });
      let claims = open();
      const a = await permitted(claims, c, view("msn_a", binding("msn_a")), { amount: "300.00" });
      const suppressed = await executionRecord(a, "suppressed");
      expect((await claims.settle(REQUESTER, suppressed, () => String(suppressed.execution_id))).accepted).toBe(true);
      claims.close();
      const db = openDurableStore({ file, migrations: claimSchemaPlaceholders(), owner: CLAIM_OWNER });
      db.prepare("UPDATE budget_reservations SET cause = 'not_persisted' WHERE evaluation_id = ?").run(a);
      db.close();
      claims = open();
      expect(await claims.settle(REQUESTER, await executionRecord(a, "completed"))).toEqual({ accepted: false, reason: "already_settled" });
      expect(claims.reservationsFor(a).map((r) => r.state)).toEqual(["released", "released"]);
      expect(claims.budgetCounter(SHARED)).toMatchObject({ reserved: { amount: "0.00" }, held: { amount: "0.00" }, committed: { amount: "0.00" } });
      expect(claims.settlementConflicts(a)).toHaveLength(1);
      expect(conflicts).toHaveLength(1);
      claims.close();
    });

    it("two conflicting records of one attempt that differ only in their error are each retained and alarmed once, and a redelivery of either retains nothing new (@spec metering#settlement-contract, #816, D877)", async () => {
      const c = clock();
      const conflicts: SettlementConflict[] = [];
      const { open } = domainOnFile(c, { conflicts });
      const claims = open();
      const a = await permitted(claims, c, view("msn_a", binding("msn_a")), { amount: "300.00" });
      const executionId = `exe_${randomUUID()}`;
      expect((await claims.settle(REQUESTER, await executionRecord(a, "completed", executionId))).accepted).toBe(true);
      const killSwitch = await executionRecord(a, "suppressed", executionId, { error: "kill_switch" });
      const drift = await executionRecord(a, "suppressed", executionId, { error: "target_drift" });
      for (const record of [killSwitch, drift, killSwitch, drift]) {
        expect(await claims.settle(REQUESTER, record, () => executionId)).toEqual({ accepted: false, reason: "already_settled" });
      }
      expect(claims.settlementConflicts(a).map((r) => (r.record as { error?: string }).error)).toEqual(["kill_switch", "target_drift"]);
      expect(conflicts).toHaveLength(2);
      expect(claims.budgetCounter(SHARED)).toMatchObject({ reserved: { amount: "0.00" }, committed: { amount: "300.00" } });
      claims.close();
    });

    it("a record from the applied suppressed attempt with the same outcome and another error is a conflict: refused already_settled, never acknowledged as the duplicate, retained and alarmed once, and the applied settlement, its error and both counters are unchanged (@spec metering#settlement-contract, #816, D877)", async () => {
      const c = clock();
      const conflicts: SettlementConflict[] = [];
      const { file, open } = domainOnFile(c, { conflicts });
      const claims = open();
      const a = await permitted(claims, c, view("msn_a", binding("msn_a")), { amount: "300.00" });
      const executionId = `exe_${randomUUID()}`;
      const first = await executionRecord(a, "suppressed", executionId, { error: "kill_switch" });
      const changed = await executionRecord(a, "suppressed", executionId, { error: "target_drift" });
      expect(await claims.settle(REQUESTER, first, () => executionId)).toEqual({ accepted: true, state: "failed", duplicate: false });
      // The changed record, delivered twice: retained and alarmed once, never the duplicate.
      for (const record of [changed, changed]) {
        expect(await claims.settle(REQUESTER, record, () => executionId)).toEqual({ accepted: false, reason: "already_settled" });
      }
      expect(claims.settlementConflicts(a)).toEqual([
        { execution_id: executionId, outcome: "suppressed", applied_execution_id: executionId, applied_outcome: "suppressed", record: changed },
      ]);
      expect(conflicts).toEqual([
        expect.objectContaining({ evaluation_id: a, execution_id: executionId, outcome: "suppressed", applied_execution_id: executionId, applied_outcome: "suppressed" }),
      ]);
      expect(claims.reservationsFor(a).map((r) => r.state)).toEqual(["released", "released"]);
      expect(claims.budgetCounter(SHARED)).toMatchObject({ reserved: { amount: "0.00" }, held: { amount: "0.00" }, committed: { amount: "0.00" } });
      expect(claims.budgetCounter(instanceCounter("msn_a"))).toMatchObject({ reserved: { amount: "0.00" }, held: { amount: "0.00" }, committed: { amount: "0.00" } });
      claims.close();
      expect(claimRowOf(file, a)).toMatchObject({ state: "failed", execution_id: executionId, outcome: "suppressed", error: "kill_switch" });
    });

    it("a record from the applied failed attempt with the same outcome and a changed error, one added where the applied record carried none or one replacing the error it carried, is a conflict: refused already_settled, never acknowledged as the duplicate, retained and alarmed once, and the applied settlement and the held reservations are unchanged (@spec metering#settlement-contract, #816, D877)", async () => {
      const c = clock();
      const conflicts: SettlementConflict[] = [];
      const { file, open } = domainOnFile(c, { conflicts });
      const claims = open();
      const cases = [
        { amount: "300.00", applied: undefined, changed: "connector_timeout" },
        { amount: "200.00", applied: "connector_timeout", changed: "connector_refused" },
      ];
      const settled: Array<{ id: string; executionId: string; applied: string | undefined }> = [];
      for (const k of cases) {
        const id = await permitted(claims, c, view("msn_a", binding("msn_a")), { amount: k.amount });
        const executionId = `exe_${randomUUID()}`;
        const failed = await executionRecord(id, "failed", executionId, k.applied === undefined ? {} : { error: k.applied });
        const changed = await executionRecord(id, "failed", executionId, { error: k.changed });
        expect(await claims.settle(REQUESTER, failed, () => executionId)).toEqual({ accepted: true, state: "failed", duplicate: false });
        for (const record of [changed, changed]) {
          expect(await claims.settle(REQUESTER, record, () => executionId)).toEqual({ accepted: false, reason: "already_settled" });
        }
        expect(claims.settlementConflicts(id)).toEqual([
          { execution_id: executionId, outcome: "failed", applied_execution_id: executionId, applied_outcome: "failed", record: changed },
        ]);
        expect(conflicts.filter((r) => r.evaluation_id === id)).toEqual([
          expect.objectContaining({ evaluation_id: id, execution_id: executionId, outcome: "failed", applied_execution_id: executionId, applied_outcome: "failed" }),
        ]);
        expect(claims.reservationsFor(id).map((r) => r.state)).toEqual(["held", "held"]);
        settled.push({ id, executionId, applied: k.applied });
      }
      expect(conflicts).toHaveLength(2);
      expect(claims.budgetCounter(SHARED)).toMatchObject({ reserved: { amount: "0.00" }, held: { amount: "500.00" }, committed: { amount: "0.00" } });
      expect(claims.budgetCounter(instanceCounter("msn_a"))).toMatchObject({ reserved: { amount: "0.00" }, held: { amount: "500.00" }, committed: { amount: "0.00" } });
      claims.close();
      for (const s of settled) {
        expect(claimRowOf(file, s.id)).toMatchObject({ state: "failed", execution_id: s.executionId, outcome: "failed", error: s.applied ?? null });
      }
    });

    it("a redelivery identical to the applied record, its attempt, outcome and non-empty error alike, is acknowledged as the duplicate and retains and alarms nothing, for an applied suppressed record and an applied failed one (@spec metering#settlement-contract, #816, D877)", async () => {
      const c = clock();
      const conflicts: SettlementConflict[] = [];
      const { file, open } = domainOnFile(c, { conflicts });
      const claims = open();
      const a = await permitted(claims, c, view("msn_a", binding("msn_a")), { amount: "300.00" });
      const b = await permitted(claims, c, view("msn_a", binding("msn_a")), { amount: "200.00" });
      const suppressed = await executionRecord(a, "suppressed", `exe_${randomUUID()}`, { error: "target_drift" });
      const failed = await executionRecord(b, "failed", `exe_${randomUUID()}`, { error: "connector_timeout" });
      for (const record of [suppressed, failed]) {
        const redeemer = () => String(record.execution_id);
        expect(await claims.settle(REQUESTER, record, redeemer)).toEqual({ accepted: true, state: "failed", duplicate: false });
        expect(await claims.settle(REQUESTER, record, redeemer)).toEqual({ accepted: true, state: "failed", duplicate: true });
        expect(await claims.settle(REQUESTER, record, () => undefined)).toEqual({ accepted: true, state: "failed", duplicate: true });
      }
      expect(claims.settlementConflicts(a)).toEqual([]);
      expect(claims.settlementConflicts(b)).toEqual([]);
      expect(conflicts).toEqual([]);
      expect(claims.reservationsFor(a).map((r) => r.state)).toEqual(["released", "released"]);
      expect(claims.reservationsFor(b).map((r) => r.state)).toEqual(["held", "held"]);
      expect(claims.budgetCounter(SHARED)).toMatchObject({ reserved: { amount: "0.00" }, held: { amount: "200.00" }, committed: { amount: "0.00" } });
      claims.close();
      expect(claimRowOf(file, a)).toMatchObject({ state: "failed", outcome: "suppressed", error: "target_drift" });
      expect(claimRowOf(file, b)).toMatchObject({ state: "failed", outcome: "failed", error: "connector_timeout" });
    });

    it("a redelivery of an applied record that carried no error, now carrying error null, is acknowledged as the duplicate and retains and alarms nothing, for an applied failed record and an applied completed one (@spec metering#settlement-contract, #816, D877)", async () => {
      const c = clock();
      const conflicts: SettlementConflict[] = [];
      const { file, open } = domainOnFile(c, { conflicts });
      const claims = open();
      const a = await permitted(claims, c, view("msn_a", binding("msn_a")), { amount: "300.00" });
      const b = await permitted(claims, c, view("msn_a", binding("msn_a")), { amount: "200.00" });
      const failedId = `exe_${randomUUID()}`;
      const completedId = `exe_${randomUUID()}`;
      const failed = await executionRecord(a, "failed", failedId);
      const completed = await executionRecord(b, "completed", completedId);
      expect(failed).not.toHaveProperty("error");
      expect(completed).not.toHaveProperty("error");
      expect(await claims.settle(REQUESTER, failed, () => failedId)).toEqual({ accepted: true, state: "failed", duplicate: false });
      expect(await claims.settle(REQUESTER, completed)).toEqual({ accepted: true, state: "completed", duplicate: false });
      const failedNull = await executionRecord(a, "failed", failedId, { error: null });
      const completedNull = await executionRecord(b, "completed", completedId, { error: null });
      expect(failedNull).toHaveProperty("error", null);
      expect(completedNull).toHaveProperty("error", null);
      expect(await claims.settle(REQUESTER, failedNull, () => failedId)).toEqual({ accepted: true, state: "failed", duplicate: true });
      expect(await claims.settle(REQUESTER, completedNull)).toEqual({ accepted: true, state: "completed", duplicate: true });
      expect(claims.settlementConflicts(a)).toEqual([]);
      expect(claims.settlementConflicts(b)).toEqual([]);
      expect(conflicts).toEqual([]);
      expect(claims.reservationsFor(a).map((r) => r.state)).toEqual(["held", "held"]);
      expect(claims.reservationsFor(b).map((r) => r.state)).toEqual(["committed", "committed"]);
      expect(claims.budgetCounter(SHARED)).toMatchObject({ reserved: { amount: "0.00" }, held: { amount: "300.00" }, committed: { amount: "200.00" } });
      claims.close();
      expect(claimRowOf(file, a)).toMatchObject({ state: "failed", outcome: "failed", error: null });
      expect(claimRowOf(file, b)).toMatchObject({ state: "completed", outcome: "completed", error: null });
    });
  });

  describe("a metered claim is retained while its Mission can present it (@spec metering#retry)", () => {
    it("a metered claim outlives the class idempotency horizon: while the Mission is active a duplicate, from its own credential or another client instance, resolves against it duplicate_suppressed and draws nothing; once the Mission is terminal every presentation is refused mission_inactive with no fresh claim or reservation, and a stale active view still meets the retained claim (@spec metering#retry, #816, D877)", async () => {
      const c = clock();
      const { file, open } = domainOnFile(c);
      const claims = open();
      const active = view("msn_a", binding("msn_a"));
      const key = freshKey();
      const a = await permitted(claims, c, active, { key, amount: "300.00" });
      expect((await claims.settle(REQUESTER, await executionRecord(a, "completed"))).accepted).toBe(true);
      const presentations: RequestOptions[] = [
        { key, amount: "300.00" },
        { key, amount: "300.00", actor: { client_id: "ap-agent", client_instance_id: "instance-2" } },
      ];
      // Past the class horizon (604,800 s after settlement), the Mission still active: the last moment it can present.
      c.set(T0 + HORIZON_MS + 60_000);
      claims.sweep();
      for (const presented of presentations) {
        expectDenied(await evaluate(request(c, presented), options(claims, c, active)), "duplicate_suppressed");
      }
      expect(claims.budgetCounter(SHARED)).toMatchObject({ reserved: { amount: "0.00" }, committed: { amount: "300.00" } });
      // The Mission is terminal: no presentation reaches the claim step.
      const terminal: MissionView = { ...active, state: "revoked" };
      for (const presented of presentations) {
        expectDenied(await evaluate(request(c, presented), options(claims, c, terminal)), "mission_inactive");
      }
      // A view still reporting it active (a stale observation) meets the retained claim, never a fresh one.
      expectDenied(await evaluate(request(c, { key, amount: "300.00" }), options(claims, c, active)), "duplicate_suppressed");
      expect(claims.budgetCounter(SHARED)).toMatchObject({ reserved: { amount: "0.00" }, committed: { amount: "300.00" } });
      claims.close();
      expect(countsOf(file)).toEqual({ claims: 1, reservations: 2, counters: 2 });
    });

    it("the sweep alone tombstones a settled metered claim's stored decision past the reconciliation window, and past the class horizon keeps the claim and its reservations (@spec metering#retry, metering#settlement-states, #816, D877)", async () => {
      const c = clock();
      const { file, open } = domainOnFile(c);
      const claims = open();
      const a = await permitted(claims, c, view("msn_a", binding("msn_a")), { amount: "300.00" });
      expect((await claims.settle(REQUESTER, await executionRecord(a, "completed"))).accepted).toBe(true);
      c.set(T0 + PAST_WINDOW_MS + 60_000);
      claims.sweep();
      c.set(T0 + HORIZON_MS + 60_000);
      claims.sweep();
      claims.close();
      expect(claimRowOf(file, a)).toMatchObject({ state: "completed", decision_json: null });
      expect(countsOf(file)).toEqual({ claims: 1, reservations: 2, counters: 2 });
    });
  });

  describe("the PDP witness batch (@spec metering#metering, metering#aggregate-bounds, metering#settlement-contract, metering#settlement-states)", () => {
    it("a metered action presented under a class the claim domain does not claim is denied constraint_unsupported and reserves and claims nothing (@spec metering#metering, #816)", async () => {
      const c = clock();
      const { file, open } = domainOnFile(c);
      const claims = open();
      const d = await evaluate(request(c, { actionClass: "consequential_write", amount: "300.00" }), options(claims, c, view("msn_a", binding("msn_a"))));
      expectDenied(d, "constraint_unsupported");
      claims.close();
      expect(countsOf(file)).toEqual({ claims: 0, reservations: 0, counters: 0 });
    });

    it("a key reused for the same amount to another payee is refused idempotency_conflict and leaves both counters unchanged (@spec metering#retry, #816)", async () => {
      const c = clock();
      const { open } = domainOnFile(c);
      const claims = open();
      const v = view("msn_a", binding("msn_a", { destinations: { acme: PAYEE, globex: "acct-globex-001" } }));
      const key = freshKey();
      await permitted(claims, c, v, { key, amount: "250.00" });
      const reused = await evaluate(
        request(c, { key, amount: "250.00", vendor: "globex", parameters: { payee_account: "acct-globex-001" } }),
        options(claims, c, v),
      );
      expectDenied(reused, "idempotency_conflict");
      expect(claims.reservationsFor(reused.context.evaluation_id as string)).toEqual([]);
      expect(claims.budgetCounter(SHARED)?.reserved.amount).toBe("250.00");
      expect(claims.budgetCounter(instanceCounter("msn_a"))?.reserved.amount).toBe("250.00");
      claims.close();
    });

    it("a suppressed record from a replay refused permit_consumed settles nothing: the reservation stays charged and is held once the lease elapses (@spec metering#settlement-states, #816)", async () => {
      const c = clock();
      const { open } = domainOnFile(c);
      const claims = open();
      const a = await permitted(claims, c, view("msn_a", binding("msn_a")), { amount: "300.00" });
      const replay = await executionRecord(a, "suppressed", undefined, { error: "permit_consumed" });
      expect(await claims.settle(REQUESTER, replay, () => String(replay.execution_id))).toEqual({ accepted: false, reason: "not_a_settling_outcome" });
      expect(claims.reservationsFor(a).map((r) => r.state)).toEqual(["reserved", "reserved"]);
      c.set(T0 + PAST_LEASE_MS);
      claims.sweep();
      expect(claims.reservationsFor(a).map((r) => r.state)).toEqual(["held", "held"]);
      expect(claims.budgetCounter(SHARED)).toMatchObject({ reserved: { amount: "0.00" }, held: { amount: "300.00" } });
      claims.close();
    });

    it("two budgets with one budget id under different owners draw on separate standing_consent counters, each held to its own declared limit (@spec metering#aggregate-bounds, #816)", async () => {
      const c = clock();
      const { open } = domainOnFile(c);
      const acme = declaration().budgets[0] as BudgetMeteringDeclaration["budgets"][number];
      const globexBudget = { ...acme, owner: "globex-treasury", limit: "500.00" };
      const claims = open(budgetStatement({ ...declaration(), budgets: [acme, globexBudget] }));
      const globex = (id: string) => view(id, binding(id, { owner: "globex-treasury", limit: "500.00" }));
      const a = await evaluate(request(c, { missionId: "msn_a", amount: "300.00" }), options(claims, c, view("msn_a", binding("msn_a"))));
      const b = await evaluate(request(c, { missionId: "msn_b", amount: "300.00" }), options(claims, c, globex("msn_b")));
      expectPermit(a);
      expectPermit(b);
      const globexShared = budgetCounterId("standing_consent", { owner: "globex-treasury", budget_id: BUDGET_ID });
      expect(entry(a, "standing_consent")?.counter_id).toBe(SHARED);
      expect(entry(b, "standing_consent")?.counter_id).toBe(globexShared);
      expect(claims.budgetCounter(SHARED)?.reserved.amount).toBe("300.00");
      expect(claims.budgetCounter(globexShared)?.reserved.amount).toBe("300.00");
      // The globex budget is held to its own 500.00, while the acme budget still has headroom.
      const refused = await evaluate(request(c, { missionId: "msn_c", amount: "300.00" }), options(claims, c, globex("msn_c")));
      expectDenied(refused, "quota_exceeded");
      expect(entry(refused, "standing_consent")).toMatchObject({ counter_id: globexShared, remaining: { amount: "200.00" } });
      claims.close();
    });

    it("the loader refuses a budget declared by its identifier alone and a policy reference without its id (@spec metering#aggregate-bounds, #816)", () => {
      const acme = declaration().budgets[0] as BudgetMeteringDeclaration["budgets"][number];
      const cases: Array<[string, unknown]> = [
        ["budget by identifier alone", { ...declaration(), budgets: [{ owner: OWNER, budget_id: BUDGET_ID }] }],
        ["policy reference without its id", { ...declaration(), budgets: [{ ...acme, policies: [{ version: "1", digest: POLICY_V1.digest }] }] }],
      ];
      for (const [label, decl] of cases) {
        for (const claimed of [true, false]) {
          const file = join(mkdtempSync(join(tmpdir(), "budget-816-")), "claims.sqlite");
          expect(() => openIdempotencyClaimDomain({ file, owner: CLAIM_OWNER, statement: budgetStatement(decl, claimed) }), `${label} (claimed: ${claimed})`).toThrow(
            ClaimDomainConfigError,
          );
        }
      }
    });

    it("committed spend and the remaining headroom on both counters are unchanged across a restart (@spec metering#aggregate-bounds, #816)", async () => {
      const c = clock();
      const { open } = domainOnFile(c);
      let claims = open();
      const v = view("msn_a", binding("msn_a"));
      const a = await permitted(claims, c, v, { amount: "300.00" });
      expect((await claims.settle(REQUESTER, await executionRecord(a, "completed"))).accepted).toBe(true);
      claims.close();
      claims = open();
      expect(claims.budgetCounter(SHARED)).toMatchObject({ reserved: { amount: "0.00" }, held: { amount: "0.00" }, committed: { amount: "300.00" } });
      expect(claims.budgetCounter(instanceCounter("msn_a"))?.committed.amount).toBe("300.00");
      const next = await evaluate(request(c, { amount: "100.00" }), options(claims, c, v));
      expectPermit(next);
      expect(entry(next, "standing_consent")?.remaining.amount).toBe("600.00");
      expect(entry(next, "mission")?.remaining.amount).toBe("600.00");
      claims.close();
    });

    it("a new policy version with committed, reserved and held quantities present at the change keeps every one of them charged on the same counter and measures the raised limit against that whole exposure (@spec metering#aggregate-bounds, #816, D830 ruling 7)", async () => {
      const c = clock();
      const { open } = domainOnFile(c);
      let claims = open();
      const a = await permitted(claims, c, view("msn_a", binding("msn_a")), { amount: "200.00" });
      expect((await claims.settle(REQUESTER, await executionRecord(a, "completed"))).accepted).toBe(true);
      await permitted(claims, c, view("msn_b", binding("msn_b")), { amount: "300.00" });
      c.set(T0 + PAST_LEASE_MS);
      claims.sweep();
      await permitted(claims, c, view("msn_c", binding("msn_c")), { amount: "100.00" });
      // At the version change: 200.00 committed, 300.00 held, 100.00 reserved.
      expect(claims.budgetCounter(SHARED)).toMatchObject({ committed: { amount: "200.00" }, held: { amount: "300.00" }, reserved: { amount: "100.00" } });
      claims.close();
      // Re-consent: version 2 raises the limit to 1200.00. The restart holds the open reservation; nothing is released.
      claims = open(budgetStatement(declaration({ limit: "1200.00", policies: [POLICY_V2] })));
      expect(claims.budgetCounter(SHARED)).toMatchObject({ committed: { amount: "200.00" }, held: { amount: "400.00" }, reserved: { amount: "0.00" } });
      const v2 = view("msn_d", binding("msn_d", { limit: "1200.00", policy: POLICY_V2 }));
      const over = await evaluate(request(c, { missionId: "msn_d", amount: "601.00" }), options(claims, c, v2));
      expectDenied(over, "quota_exceeded");
      expect(entry(over, "standing_consent")).toMatchObject({ counter_id: SHARED, remaining: { amount: "600.00" } });
      expectPermit(await evaluate(request(c, { missionId: "msn_d", amount: "600.00" }), options(claims, c, v2)));
      claims.close();
    });

    it("at the parked point of eight concurrent requests, each permitted instance has debited its own counter and the shared one together, and no refused instance has debited either (@spec metering#aggregate-bounds, metering#topology, #816)", async () => {
      const c = clock();
      const { open } = domainOnFile(c);
      const claims = open();
      const held = heldEmitter();
      const ids = Array.from({ length: 8 }, (_, i) => `msn_p${i}`);
      const pending = ids.map((id) =>
        evaluate(request(c, { missionId: id, amount: "300.00" }), options(claims, c, view(id, binding(id)), { evidence: held.emitter })),
      );
      await until(() => held.arrived() === 8);
      const debited = ids.filter((id) => claims.budgetCounter(instanceCounter(id)) !== undefined);
      expect(debited).toHaveLength(3);
      for (const id of debited) expect(claims.budgetCounter(instanceCounter(id))?.reserved.amount).toBe("300.00");
      expect(claims.budgetCounter(SHARED)?.reserved.amount).toBe("900.00");
      held.release();
      const decisions = await Promise.all(pending);
      expect(ids.filter((_, i) => decisions[i]?.decision)).toEqual(debited);
      claims.close();
    });

    it("a counter's committed identifier is the same across a restart (@spec metering#metering-evidence, #816)", async () => {
      const c = clock();
      const { open } = domainOnFile(c);
      let claims = open();
      const v = view("msn_a", binding("msn_a"));
      const before = await evaluate(request(c, { amount: "100.00" }), options(claims, c, v));
      expectPermit(before);
      claims.close();
      claims = open();
      const after = await evaluate(request(c, { amount: "100.00" }), options(claims, c, v));
      expectPermit(after);
      expect(meteringOf(after).map((e) => [e.counter_scope, e.counter_id])).toEqual(meteringOf(before).map((e) => [e.counter_scope, e.counter_id]));
      expect(meteringOf(after).map((e) => e.counter_id)).toEqual([instanceCounter("msn_a"), SHARED]);
      claims.close();
    });

    it("the stored decision's Decision Evidence keeps settlement_state reserved, byte for byte, after its reservation commits, is released or is held (@spec metering#metering-evidence, #816)", async () => {
      const c = clock();
      const { file, open } = domainOnFile(c);
      const claims = open();
      const decide = async (id: string) => {
        const d = await evaluate(request(c, { missionId: id, amount: "100.00" }), options(claims, c, view(id, binding(id))));
        expectPermit(d);
        return { id: d.context.evaluation_id as string, evidence: JSON.stringify(d.context.decision_evidence) };
      };
      const committed = await decide("msn_a");
      const released = await decide("msn_b");
      const held = await decide("msn_c");
      expect((await claims.settle(REQUESTER, await executionRecord(committed.id, "completed"))).accepted).toBe(true);
      const suppressed = await executionRecord(released.id, "suppressed");
      expect((await claims.settle(REQUESTER, suppressed, () => String(suppressed.execution_id))).accepted).toBe(true);
      const failed = await executionRecord(held.id, "failed");
      expect((await claims.settle(REQUESTER, failed, () => String(failed.execution_id))).accepted).toBe(true);
      expect(claims.reservationsFor(committed.id)[0]?.state).toBe("committed");
      expect(claims.reservationsFor(released.id)[0]?.state).toBe("released");
      expect(claims.reservationsFor(held.id)[0]?.state).toBe("held");
      claims.close();
      for (const decision of [committed, released, held]) {
        const stored = JSON.parse(claimRowOf(file, decision.id)?.decision_json ?? "null") as { context: { decision_evidence: DecisionEvidenceObject } };
        expect(JSON.stringify(stored.context.decision_evidence)).toBe(decision.evidence);
        expect(stored.context.decision_evidence.metering?.map((e) => e.settlement_state)).toEqual(["reserved", "reserved"]);
      }
    });

    it("forged, wrongly signed and wrong-PEP settlements for a budget-bound claim are refused and leave both counters unchanged (@spec metering#settlement-contract, #816)", async () => {
      const c = clock();
      const { open } = domainOnFile(c);
      const claims = open();
      const a = await permitted(claims, c, view("msn_a", binding("msn_a")), { amount: "300.00" });
      const forged = { ...(await executionRecord(a, "completed")), mission_id: "msn_other" };
      const otherKey = generateKeyPairSync("ec", { namedCurve: "P-256" });
      const wronglySigned = await executionRecord(a, "completed", undefined, { signer: otherKey.privateKey });
      expect((await claims.settle(REQUESTER, forged)).accepted).toBe(false);
      expect((await claims.settle(REQUESTER, wronglySigned)).accepted).toBe(false);
      expect((await claims.settle({ pep_id: "another-pep", pep_epoch: REQUESTER.pep_epoch }, await executionRecord(a, "completed"))).accepted).toBe(false);
      expect(claims.reservationsFor(a).map((r) => r.state)).toEqual(["reserved", "reserved"]);
      expect(claims.budgetCounter(SHARED)).toMatchObject({ reserved: { amount: "300.00" }, committed: { amount: "0.00" } });
      expect(claims.budgetCounter(instanceCounter("msn_a"))).toMatchObject({ reserved: { amount: "300.00" }, committed: { amount: "0.00" } });
      claims.close();
    });

    it("a settlement is acknowledged only once it is durably applied: an acknowledged one survives a restart, and one whose transaction fails is not acknowledged and applies once when redelivered (@spec metering#settlement-contract, #816)", async () => {
      const c = clock();
      const { open } = domainOnFile(c);
      let claims = open();
      const a = await permitted(claims, c, view("msn_a", binding("msn_a")), { amount: "300.00" });
      expect(await claims.settle(REQUESTER, await executionRecord(a, "completed"))).toEqual({ accepted: true, state: "completed", duplicate: false });
      // The process stops after the acknowledgement: the settlement is in the file.
      claims.close();
      claims = open();
      expect(claims.reservationsFor(a).map((r) => r.state)).toEqual(["committed", "committed"]);
      expect(claims.budgetCounter(SHARED)?.committed.amount).toBe("300.00");
      // Fault injection: the next settlement's transaction fails at commit.
      let failing = true;
      setCommitGuard((claims as unknown as { db: Database }).db, {
        begin: () => {},
        beforeCommit: () => {
          if (failing) throw new Error("store failing at commit");
        },
        settled: () => {},
        afterCommit: () => {},
      });
      failing = false;
      const b = await permitted(claims, c, view("msn_b", binding("msn_b")), { amount: "200.00" });
      const record = await executionRecord(b, "completed");
      failing = true;
      await expect(claims.settle(REQUESTER, record)).rejects.toThrow(/unavailable/);
      failing = false;
      expect(claims.reservationsFor(b).map((r) => r.state)).toEqual(["reserved", "reserved"]);
      expect(claims.budgetCounter(SHARED)?.committed.amount).toBe("300.00");
      // The PEP redelivers: applied once, then acknowledged as the duplicate.
      expect(await claims.settle(REQUESTER, record)).toEqual({ accepted: true, state: "completed", duplicate: false });
      expect(await claims.settle(REQUESTER, record)).toEqual({ accepted: true, state: "completed", duplicate: true });
      expect(claims.budgetCounter(SHARED)?.committed.amount).toBe("500.00");
      claims.close();
    });

    it("a redelivered suppressed settlement is acknowledged as a duplicate and releases nothing a second time (@spec metering#settlement-contract, #816)", async () => {
      const c = clock();
      const { open } = domainOnFile(c);
      const claims = open();
      const a = await permitted(claims, c, view("msn_a", binding("msn_a")), { amount: "300.00" });
      await permitted(claims, c, view("msn_b", binding("msn_b")), { amount: "200.00" });
      const suppressed = await executionRecord(a, "suppressed");
      const redeemer = () => String(suppressed.execution_id);
      expect(await claims.settle(REQUESTER, suppressed, redeemer)).toEqual({ accepted: true, state: "failed", duplicate: false });
      expect(claims.budgetCounter(SHARED)?.reserved.amount).toBe("200.00");
      expect(await claims.settle(REQUESTER, suppressed, redeemer)).toEqual({ accepted: true, state: "failed", duplicate: true });
      expect(claims.budgetCounter(SHARED)?.reserved.amount).toBe("200.00");
      expect(claims.budgetCounter(instanceCounter("msn_a"))?.reserved.amount).toBe("0.00");
      claims.close();
    });

    it("after a completed payment, a retry under its key and a refused compensate request leave the committed amount committed (@spec metering#settlement-states, #816)", async () => {
      const c = clock();
      const { open } = domainOnFile(c);
      const claims = open();
      const v = view("msn_a", binding("msn_a"));
      const key = freshKey();
      const a = await permitted(claims, c, v, { key, amount: "300.00" });
      expect((await claims.settle(REQUESTER, await executionRecord(a, "completed"))).accepted).toBe(true);
      expectDenied(await evaluate(request(c, { key, amount: "300.00" }), options(claims, c, v)), "duplicate_suppressed");
      expectDenied(await evaluate(request(c, { phase: "compensate", compensates: a, amount: "300.00" }), options(claims, c, v)), "constraint_unsupported");
      expect(claims.reservationsFor(a).map((r) => r.state)).toEqual(["committed", "committed"]);
      expect(claims.budgetCounter(SHARED)).toMatchObject({ reserved: { amount: "0.00" }, committed: { amount: "300.00" } });
      claims.close();
    });

    it("containing a Mission that holds an open reservation settles nothing: the contained request is refused authority_contained, no counter moves, and the permit's later completed settlement still commits (@spec metering#settlement-states, #816)", async () => {
      const c = clock();
      const { open } = domainOnFile(c);
      const claims = open();
      const v = view("msn_a", binding("msn_a"));
      const a = await permitted(claims, c, v, { amount: "300.00" });
      const contained: MissionView = { ...v, version: 2, containment: { version: 1, contained: [{ resource: RESOURCE, actions: [EXECUTE] }] } };
      expectDenied(await evaluate(request(c, { amount: "100.00" }), options(claims, c, contained)), "authority_contained");
      expect(claims.reservationsFor(a).map((r) => r.state)).toEqual(["reserved", "reserved"]);
      expect(claims.budgetCounter(SHARED)).toMatchObject({ reserved: { amount: "300.00" }, committed: { amount: "0.00" } });
      expect((await claims.settle(REQUESTER, await executionRecord(a, "completed"))).accepted).toBe(true);
      expect(claims.budgetCounter(SHARED)).toMatchObject({ reserved: { amount: "0.00" }, committed: { amount: "300.00" } });
      claims.close();
    });

    it("an admitted instance's payment still takes a fresh runtime decision: one requiring an action-bound approval is refused without it, and one with no parameter_digest is refused, each reserving nothing (@spec mission-template#standing-payment-exception, metering#metering, #813)", async () => {
      const c = clock();
      const { file, open } = domainOnFile(c);
      const claims = open();
      const v = view("msn_a", binding("msn_a"));
      expectDenied(
        await evaluate(request(c, { amount: "100.00" }), options(claims, c, v, { requiresActionApproval: () => true })),
        "action_approval_required",
      );
      expectDenied(await evaluate(request(c, { amount: "100.00", digest: null }), options(claims, c, v)), "parameter_violation");
      claims.close();
      expect(countsOf(file)).toEqual({ claims: 0, reservations: 0, counters: 0 });
    });

    it("a constraint_unsupported denial records denial_reason constraint_unsupported in its signed Decision Evidence (@spec authzen#failure-condition-coverage, #816)", async () => {
      const c = clock();
      const { open } = domainOnFile(c);
      const claims = open();
      const d = await evaluate(request(c, { amount: "100.00" }), options(claims, c, view("msn_a", binding("msn_a", { budget_id: "undeclared-budget" }))));
      expectDenied(d, "constraint_unsupported");
      const record = d.context.decision_evidence as DecisionEvidenceObject;
      expect(record.decision).toBe("deny");
      expect(record.denial_reason).toBe("constraint_unsupported");
      const verified = await verifyEvidenceEnvelope(record, DECISION_EVIDENCE_MEDIA_TYPE, (p) => (p.kid === "pdp-816" ? { key: evidenceKey.publicKey } : undefined));
      expect(verified.valid).toBe(true);
      claims.close();
    });

    it("a request or binding whose currency differs from the budget's only in case is denied constraint_unsupported and reserves nothing (@spec metering#bounds, metering#metering, #816)", async () => {
      const c = clock();
      const { file, open } = domainOnFile(c);
      const claims = open();
      expectDenied(await evaluate(request(c, { amount: "100.00", currency: "usd" }), options(claims, c, view("msn_a", binding("msn_a")))), "constraint_unsupported");
      const lowerCase = binding("msn_b", { currency: "usd", instance: { max_budget: { amount: "1000.00", currency: "usd" }, root_mission_id: "msn_b" } });
      expectDenied(await evaluate(request(c, { missionId: "msn_b", amount: "100.00" }), options(claims, c, view("msn_b", lowerCase))), "constraint_unsupported");
      claims.close();
      expect(countsOf(file)).toEqual({ claims: 0, reservations: 0, counters: 0 });
    });

    it("a well-formed binding whose currency, or whose instance max_budget currency, is not the budget's declared currency is denied constraint_unsupported and reserves nothing (@spec metering#bounds, metering#metering, #816, D877)", async () => {
      const c = clock();
      const { file, open } = domainOnFile(c);
      const claims = open();
      // Each binding passes the currency-code shape check, so only the comparison with the declared currency refuses it.
      const bindingInEuros = binding("msn_b", { currency: "EUR" });
      expectDenied(await evaluate(request(c, { missionId: "msn_b", amount: "100.00" }), options(claims, c, view("msn_b", bindingInEuros))), "constraint_unsupported");
      const instanceInEuros = binding("msn_c", { instance: { max_budget: { amount: "1000.00", currency: "EUR" }, root_mission_id: "msn_c" } });
      expectDenied(await evaluate(request(c, { missionId: "msn_c", amount: "100.00" }), options(claims, c, view("msn_c", instanceInEuros))), "constraint_unsupported");
      // Control: the same binding in the declared currency is charged.
      expectPermit(await evaluate(request(c, { missionId: "msn_d", amount: "100.00" }), options(claims, c, view("msn_d", binding("msn_d")))));
      claims.close();
      expect(countsOf(file)).toEqual({ claims: 1, reservations: 2, counters: 2 });
    });
  });
});
