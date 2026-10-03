/**
 * @spec runtime#idempotency, authzen#parameter-digest, authzen#projections
 * (#917, D223): the PDP-owned, local, durable, single-writer Exact
 * idempotency claim.
 *
 * Every case runs `evaluate()` against a real claim domain on a real SQLite
 * file in a fresh temporary directory, never a stub: a "restart" closes the
 * domain and reopens the same file, and concurrency is real interleaving at
 * the Decision Evidence signing await. The FGA layer is a stub that always
 * permits, so the claim step is what decides and this file never skips.
 *
 * Clocks: one mutable clock drives both the PDP's decisions and the claim
 * domain's sweeps, settlement and reconciliation, so a horizon or window
 * boundary is crossed exactly where a case says it is.
 */

import { generateKeyPairSync, randomUUID } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { openDurableStore } from "@mission/store";
import { describe, expect, it } from "vitest";
import { createDecisionEvidenceEmitter, type DecisionEvidenceEmitter } from "../src/decision-evidence.js";
import type { EnforcementScopeStatement } from "../src/enforcement-scope.js";
import { type Decision, evaluate, type EvaluateOptions, type EvaluationRequest } from "../src/evaluate.js";
import type { Fga } from "../src/fga.js";
import {
  ClaimDomainConfigError,
  ClaimDomainUnavailableError,
  type ClaimRequester,
  type ConsumptionStatusFn,
  type IdempotencyClaimDomain,
  openIdempotencyClaimDomain,
} from "../src/idempotency-claims.js";
import { MISSION_RESOURCE_ACCESS_TYPE, type MissionView } from "../src/policy-view.js";
import { relationForAction, stalenessBound } from "../src/policy.js";
import { decisionCacheKey } from "../src/projections.js";
import { EXECUTION_EVIDENCE_MEDIA_TYPE, signEvidenceEnvelope } from "../src/runtime-evidence-integrity.js";
import { RUNTIME_POSTURE } from "../src/runtime-posture.js";
import { CLAIM_OWNER, freshKey, statementWithPrivilegedAdministration } from "./claim-fixture.js";

const RESOURCE = "http://localhost:4403/mcp";
const OTHER_RESOURCE = "http://localhost:4499/mcp";
const T0 = Date.parse("2026-10-02T12:00:00Z");
/** irreversible_action: a 30 s staleness bound caps the permit at now + 30 s. */
const VALID_MS = 30_000;
/** The shipped statement's lease maximum for the class, and its 15-minute window. */
const LEASE_MS = 30_000;
const WINDOW_MS = 15 * 60_000;
const HORIZON_MS = 604_800_000;
const ADMIN_ACTION = "payments:admin.rotate";

const alwaysAllowFga = { checkWithContext: async () => true } as unknown as Fga;
/** The shipped relation map, plus the fixture privileged-administration action no shipped tool offers. */
const fixtureRelation = (action: string) =>
  action === ADMIN_ACTION ? { relation: "payer" as const, needsAmount: false } : relationForAction(action);

interface Clock {
  now: () => Date;
  ms: () => number;
  set: (ms: number) => void;
}
function clock(start = T0): Clock {
  let current = start;
  return { now: () => new Date(current), ms: () => current, set: (ms) => { current = ms; } };
}

const evidenceKey = generateKeyPairSync("ec", { namedCurve: "P-256" });
const EMITTER = createDecisionEvidenceEmitter({
  signer: { kid: "pdp-917", key: evidenceKey.privateKey },
  emitterId: RESOURCE,
  audience: RESOURCE,
});

/** The executing PEP's published Execution Evidence key, as the claim domain resolves it. */
const executionKey = generateKeyPairSync("ec", { namedCurve: "P-256" });
const settlementKeys = (params: { kid: string; emitter: { id: string; role: string }; audience?: string }) =>
  params.kid === "pep-exec-917" &&
  (params.emitter.role === "executor" || params.emitter.role === "pep") &&
  params.emitter.id === RESOURCE &&
  params.audience === RESOURCE
    ? { key: executionKey.publicKey }
    : undefined;

/** A PEP-signed Execution Evidence Object for one attempt at one permit. */
async function executionRecord(
  evaluationId: string,
  outcome: "completed" | "failed" | "suppressed",
  executionId = `exe_${randomUUID()}`,
  error?: string,
): Promise<Record<string, unknown>> {
  const content = {
    execution_id: executionId,
    evaluation_id: evaluationId,
    mission_id: "msn_917",
    audience: RESOURCE,
    outcome,
    outcome_at: new Date(T0).toISOString(),
    sequence: 1,
    emitter: { id: RESOURCE, role: outcome === "completed" ? "executor" : "pep" },
    ...(error !== undefined ? { error } : {}),
  };
  const evidence_envelope = await signEvidenceEnvelope(content, EXECUTION_EVIDENCE_MEDIA_TYPE, {
    kid: "pep-exec-917",
    key: executionKey.privateKey,
  });
  return { ...content, evidence_envelope };
}

const view = (over: Partial<MissionView> = {}): MissionView => ({
  id: "msn_917",
  issuer: "https://as.test",
  state: "active",
  version: 1,
  authority_hash: "sha-256:h917",
  authority_set: [
    {
      type: MISSION_RESOURCE_ACCESS_TYPE,
      resource: RESOURCE,
      actions: ["payments:payment.execute", "payments:remittance.send", ADMIN_ACTION],
    },
    { type: MISSION_RESOURCE_ACCESS_TYPE, resource: OTHER_RESOURCE, actions: ["payments:payment.execute"] },
  ],
  subject: { iss: "https://as.test", sub: "alice" },
  client_id: "ap-agent",
  ...over,
});

interface RequestOptions {
  key?: string | null;
  digest?: string;
  actionClass?: string;
  action?: string;
  phase?: string;
  missionId?: string;
  sub?: string;
  subIss?: string;
  actor?: NonNullable<EvaluationRequest["context"]["actor"]>;
  audience?: string;
  /** The target object; the request's `resource.properties.audience` comes from `audience`. */
  resource?: { type: string; id: string; properties?: { vendor_id?: string } };
  /** The PEP's Mission state observation; defaults to a `fresh` read at the clock's instant. */
  observation?: NonNullable<EvaluationRequest["context"]["mission_state_observation"]>;
}

function request(c: Clock, o: RequestOptions = {}): EvaluationRequest {
  const target = o.resource ?? { type: "invoice", id: "inv-1", properties: { vendor_id: "acme" } };
  return {
    subject: { id: o.sub ?? "alice", properties: { iss: o.subIss ?? "https://as.test" } },
    resource: { ...target, properties: { ...target.properties, audience: o.audience ?? RESOURCE } },
    action: {
      name: o.action ?? "payments:payment.execute",
      ...(o.key === null ? {} : { properties: { idempotency_key: o.key ?? freshKey() } }),
    },
    context: {
      mission: { id: o.missionId ?? "msn_917", issuer: "https://as.test" },
      actor: o.actor ?? { client_id: "ap-agent" },
      action_class: o.actionClass ?? "irreversible_action",
      parameter_digest: o.digest ?? "sha-256:operation-1",
      mission_state_observation: o.observation ?? { state: "active", mode: "fresh", freshness_at: c.now().toISOString() },
      ...(o.phase !== undefined ? { action_phase: o.phase } : {}),
    },
  };
}

const REQUESTER: ClaimRequester = { pep_id: "mcp-payments-pep", pep_epoch: "epoch-917-a" };
const unconsumed: ConsumptionStatusFn = () => "unconsumed";

function options(claims: IdempotencyClaimDomain, c: Clock, over: Partial<EvaluateOptions> = {}): EvaluateOptions {
  return {
    view: view(),
    fga: alwaysAllowFga,
    modelId: "model-917",
    now: c.now,
    stalenessBound,
    relationForAction: fixtureRelation,
    stateSourcePlacement: "pep" as const,
    evidence: EMITTER,
    claims,
    requester: REQUESTER,
    ...over,
  };
}

/** A claim domain on its own file; `reopen` is a PDP restart against the same file. */
function domainOnFile(c: Clock, statement: EnforcementScopeStatement = statementWithPrivilegedAdministration()) {
  const file = join(mkdtempSync(join(tmpdir(), "claim-917-")), "claims.sqlite");
  const open = () => openIdempotencyClaimDomain({ file, owner: CLAIM_OWNER, statement, now: c.now, settlementKeys });
  return { file, open };
}

/**
 * Read the claim rows straight from the file, after the domain released it,
 * through the same single-writer opener at the domain's schema version.
 */
function rowsOf(file: string): Array<{ evaluation_id: string; state: string; decision_json: string | null }> {
  const db = openDurableStore({ file, migrations: ["-- claims schema v1"], owner: CLAIM_OWNER });
  try {
    return db.prepare("SELECT evaluation_id, state, decision_json FROM claims ORDER BY claimed_at_ms").all() as Array<{
      evaluation_id: string;
      state: string;
      decision_json: string | null;
    }>;
  } finally {
    db.close();
  }
}

function expectDenied(d: Decision, reason: string, next: { next_action: string; retry_after?: number }): void {
  expect(d.decision, JSON.stringify(d.context)).toBe(false);
  expect(d.context.denial_reason).toBe(reason);
  expect(d.context.reason).toBe(reason);
  expect(d.context.next_action).toBe(next.next_action);
  if (next.retry_after !== undefined) expect(d.context.retry_after).toBe(next.retry_after);
  expect(d.context.conditions).toBeUndefined();
}

/** An emitter that holds every emission until released: an evaluation parked inside its claim. */
function heldEmitter(): { emitter: DecisionEvidenceEmitter; release: () => void } {
  let release!: () => void;
  const gate = new Promise<void>((resolve) => { release = resolve; });
  return { emitter: { emit: async (input) => { await gate; return EMITTER.emit(input); } }, release };
}
const settle = () => new Promise<void>((resolve) => setImmediate(resolve));

describe("PDP idempotency claim (@spec runtime#idempotency, #917)", () => {
  describe("the claim is one linearizable operation", () => {
    it("eight concurrent identical evaluations on one file store yield one permit, one row, and seven transient duplicate_suppressed", async () => {
      const c = clock();
      const { file, open } = domainOnFile(c);
      const claims = open();
      const key = freshKey();
      const settled = await Promise.allSettled(
        Array.from({ length: 8 }, () => evaluate(request(c, { key }), options(claims, c))),
      );
      // Every caller got a decision: none fell through to "no decision".
      expect(settled.filter((s) => s.status === "rejected").map((s) => String((s as PromiseRejectedResult).reason))).toEqual([]);
      const decisions = settled.map((s) => (s as PromiseFulfilledResult<Decision>).value);
      const permits = decisions.filter((d) => d.decision);
      expect(permits).toHaveLength(1);
      const suppressed = decisions.filter((d) => !d.decision);
      expect(suppressed).toHaveLength(7);
      for (const d of suppressed) expectDenied(d, "duplicate_suppressed", { next_action: "retry", retry_after: 1 });
      claims.close();
      const rows = rowsOf(file);
      expect(rows).toHaveLength(1);
      expect(rows[0]?.evaluation_id).toBe(permits[0]?.context.evaluation_id);
      expect(rows[0]?.state).toBe("permit_issued");
    });
  });

  describe("a key reused under a different operation identity is a conflict", () => {
    it("denies idempotency_conflict with next_action none in every claim state", async () => {
      const c = clock();
      const { open } = domainOnFile(c);
      const claims = open();
      const other = (key: string) => evaluate(request(c, { key, digest: "sha-256:a-different-operation" }), options(claims, c));

      // claimed: the first evaluation is parked inside its claim.
      const k1 = freshKey();
      const held = heldEmitter();
      const first = evaluate(request(c, { key: k1 }), options(claims, c, { evidence: held.emitter }));
      await settle();
      await settle();
      expectDenied(await other(k1), "idempotency_conflict", { next_action: "none" });
      held.release();
      expect((await first).decision).toBe(true);
      // permit_issued
      expectDenied(await other(k1), "idempotency_conflict", { next_action: "none" });
      // completed and failed, by settlement
      const k3 = freshKey();
      const p3 = await evaluate(request(c, { key: k3 }), options(claims, c));
      expect((await claims.settle(REQUESTER, await executionRecord(String(p3.context.evaluation_id), "completed"))).accepted).toBe(true);
      expectDenied(await other(k3), "idempotency_conflict", { next_action: "none" });
      const k4 = freshKey();
      const p4 = await evaluate(request(c, { key: k4 }), options(claims, c));
      // A failure settles only from the attempt the redemption record names.
      const failure = await executionRecord(String(p4.context.evaluation_id), "failed");
      expect((await claims.settle(REQUESTER, failure, () => String(failure.execution_id))).accepted).toBe(true);
      expectDenied(await other(k4), "idempotency_conflict", { next_action: "none" });
      // unresolved: the permit and its lease elapsed with nothing settled.
      const k2 = freshKey();
      expect((await evaluate(request(c, { key: k2 }), options(claims, c))).decision).toBe(true);
      c.set(T0 + VALID_MS + LEASE_MS + 1_000);
      expectDenied(await other(k2), "idempotency_conflict", { next_action: "none" });
      // indeterminate: the reconciliation window closed, still unresolved.
      c.set(T0 + VALID_MS + LEASE_MS + WINDOW_MS + 1_000);
      expectDenied(await other(k2), "idempotency_conflict", { next_action: "none" });
      // and the compacted completed row still conflicts.
      expectDenied(await other(k3), "idempotency_conflict", { next_action: "none" });
      claims.close();
    });

    it("denies idempotency_conflict to a concurrent different operation under the same key", async () => {
      const c = clock();
      const { open } = domainOnFile(c);
      const claims = open();
      const key = freshKey();
      const [a, b] = await Promise.all([
        evaluate(request(c, { key }), options(claims, c)),
        evaluate(request(c, { key, digest: "sha-256:a-different-operation" }), options(claims, c)),
      ]);
      expect(a?.decision).toBe(true);
      expectDenied(b as Decision, "idempotency_conflict", { next_action: "none" });
      claims.close();
    });
  });

  describe("the idempotency scope is the published namespace", () => {
    it("pairs differing in mission, subject, actor, audience, resource or phase never collide, and a separator-ambiguous pair stays distinct", async () => {
      const c = clock();
      const { open } = domainOnFile(c);
      const claims = open();
      // No evidence emitter here: the audience pair would otherwise need two
      // emission scopes, and the scope is what is under test.
      const run = (o: RequestOptions, v: MissionView = view()) =>
        evaluate(request(c, o), options(claims, c, { evidence: undefined, view: v }));
      const pairs: Array<[string, RequestOptions, RequestOptions, MissionView?, MissionView?]> = [
        ["mission", {}, { missionId: "msn_917_b" }, view(), view({ id: "msn_917_b" })],
        ["subject", {}, { sub: "bob" }],
        ["subject issuer", {}, { subIss: "https://other-as.test" }],
        ["actor client", {}, { actor: { client_id: "other-agent" } }],
        [
          "actor leaf",
          { actor: { client_id: "ap-agent", act: [{ iss: "https://as.test", sub: "agent-1" }] } },
          { actor: { client_id: "ap-agent", act: [{ iss: "https://as.test", sub: "agent-2" }] } },
        ],
        [
          "actor leaf naming another ai_agent delegate",
          { actor: { client_id: "ap-agent", act: [{ iss: "https://as.test", sub: "agent-1", sub_profile: "ai_agent" }] } },
          { actor: { client_id: "ap-agent", act: [{ iss: "https://as.test", sub: "agent-2", sub_profile: "ai_agent" }] } },
        ],
        ["audience", {}, { audience: OTHER_RESOURCE }],
        ["resource", {}, { resource: { type: "invoice", id: "inv-2", properties: { vendor_id: "acme" } } }],
        ["phase", { phase: "prepare" }, { phase: "commit" }],
        [
          "separator-ambiguous resource",
          { resource: { type: "invoice", id: "a:b", properties: { vendor_id: "acme" } } },
          { resource: { type: "invoice:a", id: "b", properties: { vendor_id: "acme" } } },
        ],
      ];
      for (const [dimension, left, right, leftView, rightView] of pairs) {
        const key = freshKey();
        const first = await run({ ...left, key }, leftView);
        const second = await run({ ...right, key }, rightView);
        expect(first.decision, `${dimension}: ${JSON.stringify(first.context)}`).toBe(true);
        expect(second.decision, `${dimension} collided: ${JSON.stringify(second.context)}`).toBe(true);
      }
      claims.close();
    });

    it("a new client_instance_id does not split the scope", async () => {
      const c = clock();
      const { open } = domainOnFile(c);
      const claims = open();
      const key = freshKey();
      const first = await evaluate(
        request(c, { key, actor: { client_id: "ap-agent", client_instance_id: "instance-1" } }),
        options(claims, c),
      );
      expect(first.decision).toBe(true);
      const retry = await evaluate(
        request(c, { key, actor: { client_id: "ap-agent", client_instance_id: "instance-2" } }),
        options(claims, c),
      );
      expectDenied(retry, "duplicate_suppressed", { next_action: "retry", retry_after: 1 });
      claims.close();
    });

    // #1016 review: a leaf act entry that names a client instance is the
    // instance, not a delegate; another instance of the same client is the
    // same intended execution and must not obtain a second permit.
    it("another instance of the same client under the same key, carried as an instance-profiled leaf, never obtains a second permit", async () => {
      const c = clock();
      const { file, open } = domainOnFile(c);
      const claims = open();
      for (const profile of ["client_instance", "ai_agent client_instance"]) {
        const key = freshKey();
        const asInstance = (sub: string): RequestOptions => ({
          key,
          actor: { client_id: "ap-agent", act: [{ iss: "https://as.test", sub, sub_profile: profile }] },
        });
        const first = await evaluate(request(c, asInstance("inst-1")), options(claims, c, { consumptionStatus: unconsumed }));
        expect(first.decision, `${profile}: ${JSON.stringify(first.context)}`).toBe(true);
        // The second instance's binding differs, so it is not a retransmission
        // of the first permit either: transient suppression, per the table.
        const second = await evaluate(request(c, asInstance("inst-2")), options(claims, c, { consumptionStatus: unconsumed }));
        expectDenied(second, "duplicate_suppressed", { next_action: "retry", retry_after: 1 });
        // The first instance retrying is still the retransmission it was.
        const resent = await evaluate(request(c, asInstance("inst-1")), options(claims, c, { consumptionStatus: unconsumed }));
        expect(resent.context.evaluation_id).toBe(first.context.evaluation_id);
      }
      claims.close();
      expect(rowsOf(file)).toHaveLength(2);
    });

    it("an instance-profiled leaf with no client to key it on has no stable actor and is refused actor_invalid", async () => {
      const c = clock();
      const { file, open } = domainOnFile(c);
      const claims = open();
      const refused = await evaluate(
        request(c, { actor: { act: [{ iss: "https://as.test", sub: "inst-1", sub_profile: "client_instance" }] } }),
        options(claims, c),
      );
      expect(refused.decision).toBe(false);
      expect(refused.context.denial_reason).toBe("actor_invalid");
      expect(refused.context.conditions).toBeUndefined();
      claims.close();
      expect(rowsOf(file)).toHaveLength(0);
    });
  });

  describe("retransmission returns the prior decision only when every condition holds", () => {
    it("returns the identical stored decision, its evidence included, when the PEP answers unconsumed", async () => {
      const c = clock();
      const { open } = domainOnFile(c);
      const claims = open();
      let emissions = 0;
      const counting: DecisionEvidenceEmitter = { emit: async (input) => { emissions += 1; return EMITTER.emit(input); } };
      const key = freshKey();
      const first = await evaluate(request(c, { key }), options(claims, c, { evidence: counting, consumptionStatus: unconsumed }));
      expect(first.decision).toBe(true);
      // The response was lost; the PEP retries one second later with fresh observation telemetry.
      c.set(T0 + 1_000);
      const again = await evaluate(request(c, { key }), options(claims, c, { evidence: counting, consumptionStatus: unconsumed }));
      expect(JSON.stringify(again)).toBe(JSON.stringify(first));
      expect(again.context.evaluation_id).toBe(first.context.evaluation_id);
      expect(emissions).toBe(1);
      claims.close();
    });

    it("does not return it when the cache key changed", async () => {
      const c = clock();
      const { open } = domainOnFile(c);
      const claims = open();
      const key = freshKey();
      expect((await evaluate(request(c, { key }), options(claims, c, { consumptionStatus: unconsumed }))).decision).toBe(true);
      // The state generation the decision consulted moved on.
      const newerState = await evaluate(
        request(c, { key }),
        options(claims, c, { consumptionStatus: unconsumed, view: view({ version: 2 }) }),
      );
      expectDenied(newerState, "duplicate_suppressed", { next_action: "retry", retry_after: 1 });
      // A different authorization binding (another client instance) with the same operation.
      const otherBinding = await evaluate(
        request(c, { key, actor: { client_id: "ap-agent", client_instance_id: "instance-9" } }),
        options(claims, c, { consumptionStatus: unconsumed }),
      );
      expectDenied(otherBinding, "duplicate_suppressed", { next_action: "retry", retry_after: 1 });
      claims.close();
    });

    it("does not return it to another PEP epoch", async () => {
      const c = clock();
      const { open } = domainOnFile(c);
      const claims = open();
      const key = freshKey();
      expect((await evaluate(request(c, { key }), options(claims, c, { consumptionStatus: unconsumed }))).decision).toBe(true);
      const restartedPep = await evaluate(
        request(c, { key }),
        options(claims, c, { consumptionStatus: unconsumed, requester: { pep_id: REQUESTER.pep_id, pep_epoch: "epoch-917-b" } }),
      );
      expectDenied(restartedPep, "duplicate_suppressed", { next_action: "retry", retry_after: 1 });
      claims.close();
    });

    it("does not return it once the claim settled", async () => {
      const c = clock();
      const { open } = domainOnFile(c);
      const claims = open();
      const key = freshKey();
      const first = await evaluate(request(c, { key }), options(claims, c, { consumptionStatus: unconsumed }));
      await claims.settle(REQUESTER, await executionRecord(String(first.context.evaluation_id), "completed"));
      const again = await evaluate(request(c, { key }), options(claims, c, { consumptionStatus: unconsumed }));
      expectDenied(again, "duplicate_suppressed", { next_action: "none" });
      claims.close();
    });

    it("does not return it once the permit expired", async () => {
      const c = clock();
      const { open } = domainOnFile(c);
      const claims = open();
      const key = freshKey();
      expect((await evaluate(request(c, { key }), options(claims, c, { consumptionStatus: unconsumed }))).decision).toBe(true);
      c.set(T0 + VALID_MS + 1_000);
      const late = await evaluate(request(c, { key }), options(claims, c, { consumptionStatus: unconsumed }));
      expectDenied(late, "duplicate_suppressed", { next_action: "retry", retry_after: 1 });
      claims.close();
    });

    // #1016 review: the expiry check reads the clock after the consumption
    // query, not before it.
    it("does not return a permit that expires while the PEP is answering", async () => {
      const c = clock();
      const { open } = domainOnFile(c);
      const claims = open();
      const key = freshKey();
      expect((await evaluate(request(c, { key }), options(claims, c, { consumptionStatus: unconsumed }))).decision).toBe(true);
      const slowAnswer: ConsumptionStatusFn = () => {
        c.set(T0 + VALID_MS + 1);
        return "unconsumed";
      };
      const late = await evaluate(request(c, { key }), options(claims, c, { consumptionStatus: slowAnswer }));
      expectDenied(late, "duplicate_suppressed", { next_action: "retry", retry_after: 1 });
      claims.close();
    });

    it("does not return it when the PEP answers consumed or unknown, fails, or does not answer in time", async () => {
      const c = clock();
      const file = join(mkdtempSync(join(tmpdir(), "claim-917-")), "claims.sqlite");
      const claims = openIdempotencyClaimDomain({
        file,
        owner: CLAIM_OWNER,
        statement: statementWithPrivilegedAdministration(),
        now: c.now,
        consumptionStatusTimeoutMs: 50,
      });
      const answers: Array<[string, ConsumptionStatusFn | undefined]> = [
        ["consumed", () => "consumed"],
        ["unknown", () => "unknown"],
        ["no capability", undefined],
        ["a failing query", () => { throw new Error("redemption store unavailable"); }],
        ["no answer in time", () => new Promise(() => {})],
      ];
      for (const [label, status] of answers) {
        const key = freshKey();
        const first = await evaluate(request(c, { key }), options(claims, c, status ? { consumptionStatus: status } : {}));
        expect(first.decision, label).toBe(true);
        const again = await evaluate(request(c, { key }), options(claims, c, status ? { consumptionStatus: status } : {}));
        expect(again.decision, label).toBe(false);
        expect(again.context.denial_reason, label).toBe("duplicate_suppressed");
        expect(again.context.next_action, label).toBe("retry");
      }
      claims.close();
    });
  });

  // @spec authzen#projections (#1004): "State generation is cache-relevant;
  // observation telemetry never is." The PEP's observation contributes its
  // state generation (`state`, `version`) to the cache key, never when or
  // how it was read.
  describe("the cache key excludes observation telemetry and keeps the state generation (@spec authzen#projections, #1004)", () => {
    /** A `cached` observation read at `atMs`, relying on a status response issued then. */
    const cachedAt = (atMs: number, over: Record<string, unknown> = {}) =>
      ({
        state: "active",
        version: 1,
        mode: "cached",
        freshness_at: new Date(atMs).toISOString(),
        mission_status_issued_at: new Date(atMs).toISOString(),
        mission_status_expires_at: new Date(atMs + 60_000).toISOString(),
        ...over,
      }) as NonNullable<EvaluationRequest["context"]["mission_state_observation"]>;

    it("a refreshed observation (new freshness_at, issued and expiry timestamps and assertion, same state and version) leaves the cache key unchanged", () => {
      const c = clock();
      const key = freshKey();
      const first = request(c, { key, observation: cachedAt(T0, { assertion: "status-response-1" }) });
      const refreshed = request(c, { key, observation: cachedAt(T0 + 1_000, { assertion: "status-response-2" }) });
      expect(decisionCacheKey(refreshed, view(), "model-917")).toBe(decisionCacheKey(first, view(), "model-917"));
      // `mode` says how the PEP obtained state, not which state: a retry that
      // reads the source synchronously this time is still the same decision.
      const synchronous = request(c, { key, observation: cachedAt(T0 + 1_000, { mode: "fresh" }) });
      expect(decisionCacheKey(synchronous, view(), "model-917")).toBe(decisionCacheKey(first, view(), "model-917"));
    });

    it("so a retry carrying a refreshed observation is still #917's retransmission of the prior permit", async () => {
      const c = clock();
      const { open } = domainOnFile(c);
      const claims = open();
      const key = freshKey();
      const first = await evaluate(
        request(c, { key, observation: cachedAt(T0) }),
        options(claims, c, { consumptionStatus: unconsumed }),
      );
      expect(first.decision, JSON.stringify(first.context)).toBe(true);
      // The response was lost; the PEP retries one second later on a newer status response.
      c.set(T0 + 1_000);
      const again = await evaluate(
        request(c, { key, observation: cachedAt(T0 + 1_000) }),
        options(claims, c, { consumptionStatus: unconsumed }),
      );
      expect(JSON.stringify(again)).toBe(JSON.stringify(first));
      claims.close();
    });

    it("a changed state generation changes the cache key: the observation's state or version, or the PDP's tracked version", () => {
      const c = clock();
      const key = freshKey();
      const base = decisionCacheKey(request(c, { key, observation: cachedAt(T0) }), view(), "model-917");
      expect(decisionCacheKey(request(c, { key, observation: cachedAt(T0, { version: 2 }) }), view(), "model-917")).not.toBe(base);
      expect(decisionCacheKey(request(c, { key, observation: cachedAt(T0, { state: "suspended" }) }), view(), "model-917")).not.toBe(base);
      expect(decisionCacheKey(request(c, { key, observation: cachedAt(T0) }), view({ version: 2 }), "model-917")).not.toBe(base);
    });
  });

  describe("an unreachable claim domain fails closed", () => {
    it("a closed domain yields no decision and no permit", async () => {
      const c = clock();
      const { open } = domainOnFile(c);
      const claims = open();
      claims.close();
      await expect(evaluate(request(c), options(claims, c))).rejects.toBeInstanceOf(ClaimDomainUnavailableError);
    });

    it("a failing store yields no decision and no permit", async () => {
      const c = clock();
      const { open } = domainOnFile(c);
      const claims = open();
      const db = (claims as unknown as { db: { prepare: unknown } }).db;
      db.prepare = () => {
        throw Object.assign(new Error("database is locked"), { code: "SQLITE_BUSY" });
      };
      await expect(evaluate(request(c), options(claims, c))).rejects.toBeInstanceOf(ClaimDomainUnavailableError);
    });
  });

  describe("the claim runs under the Exact profile only, and an unsupported topology is refused at startup", () => {
    type Refusal = [string, (s: EnforcementScopeStatement) => void, RegExp];
    const declaration = (s: EnforcementScopeStatement) =>
      (s.extensions?.transaction_assurance?.[0] ?? {}) as unknown as Record<string, unknown>;
    const refusals: Refusal[] = [
      ["the Bounded enforcement profile", (s) => { declaration(s).idempotency_enforcement_profile = "bounded"; }, /Exact profile only/],
      ["an unsupported topology", (s) => { declaration(s).idempotency_claim_topology = "shared-replicated"; }, /unsupported claim topology/],
      ["two PDPs in the statement", (s) => { (s as { pdps: string[] }).pdps = [CLAIM_OWNER, "second-pdp"]; }, /only PDP/],
      [
        "a statement whose claim domain another PDP owns",
        (s) => {
          (s as { pdps: string[] }).pdps = ["another-pdp"];
          for (const decl of s.extensions?.transaction_assurance ?? []) (decl as { idempotency_claim_owner?: string }).idempotency_claim_owner = "another-pdp";
        },
        /only PDP/,
      ],
      ["a volatile scope member", (s) => { declaration(s).idempotency_scope = [...(declaration(s).idempotency_scope as string[]), "client_instance_id"]; }, /volatile member/],
      ["a scope missing a required dimension", (s) => { declaration(s).idempotency_scope = (declaration(s).idempotency_scope as string[]).filter((d) => d !== "actor"); }, /omits actor/],
      ["no reconciliation window", (s) => { delete (s.extensions as Record<string, unknown>).outcome_reconciliation; }, /outcome_reconciliation/],
      ["no horizon", (s) => { delete declaration(s).idempotency_horizon_seconds; }, /no idempotency horizon/],
    ];
    for (const [label, mutate, message] of refusals) {
      it(`refuses ${label}`, () => {
        const statement = statementWithPrivilegedAdministration();
        mutate(statement);
        const file = join(mkdtempSync(join(tmpdir(), "claim-917-")), "claims.sqlite");
        expect(() => openIdempotencyClaimDomain({ file, owner: CLAIM_OWNER, statement })).toThrow(ClaimDomainConfigError);
        expect(() => openIdempotencyClaimDomain({ file, owner: CLAIM_OWNER, statement })).toThrow(message);
      });
    }

    it("refuses an absent, empty or in-memory store file", () => {
      for (const file of [undefined, "", ":memory:"]) {
        expect(() => openIdempotencyClaimDomain({ file, owner: CLAIM_OWNER, statement: statementWithPrivilegedAdministration() }), String(file)).toThrow(ClaimDomainConfigError);
      }
    });

    it("refuses a second handle on a file another domain holds", () => {
      const c = clock();
      const { open } = domainOnFile(c);
      const first = open();
      expect(() => open()).toThrow(/locked/);
      first.close();
      open().close();
    });

    it("refuses a file recorded for another owner", () => {
      const file = join(mkdtempSync(join(tmpdir(), "claim-917-")), "claims.sqlite");
      const statement = statementWithPrivilegedAdministration();
      openIdempotencyClaimDomain({ file, owner: CLAIM_OWNER, statement }).close();
      const other = structuredClone(statement) as EnforcementScopeStatement & { pdps: string[] };
      other.pdps = ["another-pdp"];
      for (const decl of other.extensions?.transaction_assurance ?? []) (decl as { idempotency_claim_owner?: string }).idempotency_claim_owner = "another-pdp";
      expect(() => openIdempotencyClaimDomain({ file, owner: "another-pdp", statement: other })).toThrow(/owned by/);
    });

    it("refuses a store whose schema is newer than this build", () => {
      const file = join(mkdtempSync(join(tmpdir(), "claim-917-")), "claims.sqlite");
      openIdempotencyClaimDomain({ file, owner: CLAIM_OWNER, statement: statementWithPrivilegedAdministration() }).close();
      // A later build migrated the file one version further.
      openDurableStore({ file, migrations: ["-- claims schema v1", "CREATE TABLE claims_v2 (x INTEGER) STRICT"], owner: CLAIM_OWNER }).close();
      expect(() => openIdempotencyClaimDomain({ file, owner: CLAIM_OWNER, statement: statementWithPrivilegedAdministration() })).toThrow(/newer than this build/);
    });
  });

  describe("the statement names the claim domain per class, never per key", () => {
    it("refuses a mediated high-consequence class with no declaration at all", () => {
      const statement = statementWithPrivilegedAdministration();
      const extensions = statement.extensions as { transaction_assurance: Array<Record<string, unknown>> };
      extensions.transaction_assurance = extensions.transaction_assurance.filter(
        (d) => d.mediated_class_or_scope !== "privileged_administration",
      );
      const file = join(mkdtempSync(join(tmpdir(), "claim-917-")), "claims.sqlite");
      expect(() => openIdempotencyClaimDomain({ file, owner: CLAIM_OWNER, statement })).toThrow(
        /mediated class privileged_administration names no Exact claim domain/,
      );
    });

    it("refuses a mediated high-consequence class whose declaration names no claim domain", () => {
      const statement = statementWithPrivilegedAdministration();
      const declarations = statement.extensions?.transaction_assurance as Array<Record<string, unknown>>;
      const admin = declarations.find((d) => d.mediated_class_or_scope === "privileged_administration") as Record<string, unknown>;
      for (const member of ["idempotency_claim_owner", "idempotency_enforcement_profile", "idempotency_claim_topology", "idempotency_scope", "idempotency_horizon_seconds"]) {
        delete admin[member];
      }
      admin.idempotency_claim_domain = "unnamed";
      const file = join(mkdtempSync(join(tmpdir(), "claim-917-")), "claims.sqlite");
      expect(() => openIdempotencyClaimDomain({ file, owner: CLAIM_OWNER, statement })).toThrow(/privileged_administration/);
    });

    it("refuses a declaration keyed to an individual claim rather than a mediated class", () => {
      const statement = statementWithPrivilegedAdministration();
      const declarations = statement.extensions?.transaction_assurance as Array<Record<string, unknown>>;
      declarations.push({ ...declarations[0], mediated_class_or_scope: `key:${freshKey()}` });
      const file = join(mkdtempSync(join(tmpdir(), "claim-917-")), "claims.sqlite");
      expect(() => openIdempotencyClaimDomain({ file, owner: CLAIM_OWNER, statement })).toThrow(/outside mediated_scope\.action_classes/);
    });

    it("refuses a high-consequence class the statement names no domain for, out_of_authority, and permits nothing without one", async () => {
      const c = clock();
      // The shipped statement: privileged administration is not mediated here.
      const { open } = domainOnFile(c, RUNTIME_POSTURE);
      const claims = open();
      const admin = await evaluate(request(c, { action: ADMIN_ACTION, actionClass: "privileged_administration" }), options(claims, c));
      expect(admin.decision).toBe(false);
      expect(admin.context.denial_reason).toBe("out_of_authority");
      const noDomain = await evaluate(request(c), { ...options(claims, c), claims: undefined });
      expect(noDomain.decision).toBe(false);
      expect(noDomain.context.denial_reason).toBe("out_of_authority");
      claims.close();
    });
  });

  describe("crash boundaries and restart", () => {
    it("a claim inserted with no persisted decision is adopted after restart and issues once; a different operation conflicts", async () => {
      const c = clock();
      const { file, open } = domainOnFile(c);
      let claims = open();
      const key = freshKey();
      const crashing: DecisionEvidenceEmitter = { emit: async () => { throw new Error("crash before persist"); } };
      await expect(evaluate(request(c, { key }), options(claims, c, { evidence: crashing }))).rejects.toThrow(/crash before persist/);
      claims.close();
      expect(rowsOf(file)).toEqual([expect.objectContaining({ state: "claimed", decision_json: null })]);
      claims = open();
      expectDenied(
        await evaluate(request(c, { key, digest: "sha-256:a-different-operation" }), options(claims, c)),
        "idempotency_conflict",
        { next_action: "none" },
      );
      const adopted = await evaluate(request(c, { key }), options(claims, c));
      expect(adopted.decision).toBe(true);
      claims.close();
      const rows = rowsOf(file);
      expect(rows).toHaveLength(1);
      expect(rows[0]?.evaluation_id).toBe(adopted.context.evaluation_id);
      expect(rows[0]?.state).toBe("permit_issued");
    });

    it("a persisted permit is unknown after restart: suppressed, never returned, never fresh", async () => {
      const c = clock();
      const { open } = domainOnFile(c);
      let claims = open();
      const key = freshKey();
      expect((await evaluate(request(c, { key }), options(claims, c, { consumptionStatus: unconsumed }))).decision).toBe(true);
      claims.close();
      claims = open();
      // Same PEP, same epoch, and the PEP even answers unconsumed: a prior
      // boot's permit is still not returned, because the PDP cannot know.
      const retry = await evaluate(request(c, { key }), options(claims, c, { consumptionStatus: unconsumed }));
      expect(retry.decision).toBe(false);
      expect(retry.context.denial_reason).toBe("duplicate_suppressed");
      expect(retry.context.next_action).toBe("retry");
      claims.close();
    });

    it("a same-boot permit with no consumption answer is suppressed, never assumed unused", async () => {
      const c = clock();
      const { open } = domainOnFile(c);
      const claims = open();
      const key = freshKey();
      expect((await evaluate(request(c, { key }), options(claims, c))).decision).toBe(true);
      const retry = await evaluate(request(c, { key }), options(claims, c));
      expectDenied(retry, "duplicate_suppressed", { next_action: "retry", retry_after: 1 });
      claims.close();
    });

    it("a lost settlement acknowledgement is resent and applied once", async () => {
      const c = clock();
      const { open } = domainOnFile(c);
      const claims = open();
      const permit = await evaluate(request(c), options(claims, c));
      const record = await executionRecord(String(permit.context.evaluation_id), "completed");
      expect(await claims.settle(REQUESTER, record)).toEqual({ accepted: true, state: "completed", duplicate: false });
      expect(await claims.settle(REQUESTER, record)).toEqual({ accepted: true, state: "completed", duplicate: true });
      const second = await executionRecord(String(permit.context.evaluation_id), "completed");
      expect(await claims.settle(REQUESTER, second)).toEqual({ accepted: false, reason: "already_settled" });
      claims.close();
    });

    it("settlement is refused unless it is authenticated, from the permit holder, and from a redeeming attempt", async () => {
      const c = clock();
      const { open } = domainOnFile(c);
      const claims = open();
      const permit = await evaluate(request(c), options(claims, c));
      const id = String(permit.context.evaluation_id);
      const tampered = { ...(await executionRecord(id, "completed")), outcome: "failed" };
      expect((await claims.settle(REQUESTER, tampered)).accepted).toBe(false);
      expect(await claims.settle({ pep_id: "another-pep", pep_epoch: "x" }, await executionRecord(id, "completed"))).toEqual({ accepted: false, reason: "not_the_permit_holder" });
      expect(await claims.settle(REQUESTER, await executionRecord(id, "suppressed", undefined, "permit_consumed"))).toEqual({ accepted: false, reason: "not_a_settling_outcome" });
      claims.close();
    });

    it("an unresolved claim is reconciled from evidence, or as unredeemed within its epoch once the lease elapsed", async () => {
      const c = clock();
      const { open } = domainOnFile(c);
      let claims = open();
      const committed = await evaluate(request(c), options(claims, c));
      const unredeemed = await evaluate(request(c), options(claims, c));
      // The PDP restarts before any settlement arrives.
      claims.close();
      claims = open();
      expect(claims.listUnresolved(REQUESTER).map((u) => u.evaluation_id).sort()).toEqual(
        [committed.context.evaluation_id, unredeemed.context.evaluation_id].sort(),
      );
      const committedId = String(committed.context.evaluation_id);
      const unredeemedId = String(unredeemed.context.evaluation_id);
      expect(await claims.reconcile(REQUESTER, committedId, { kind: "execution_evidence", record: await executionRecord(committedId, "completed") })).toMatchObject({ accepted: true, state: "completed" });
      // Proof of no effect waits for the permit and its longest lease.
      expect(await claims.reconcile(REQUESTER, unredeemedId, { kind: "unredeemed" })).toEqual({ accepted: false, reason: "lease_not_elapsed" });
      c.set(T0 + VALID_MS + LEASE_MS + 1_000);
      expect(await claims.reconcile({ pep_id: REQUESTER.pep_id, pep_epoch: "another-epoch" }, unredeemedId, { kind: "unredeemed" })).toEqual({ accepted: false, reason: "other_epoch" });
      expect(await claims.reconcile(REQUESTER, unredeemedId, { kind: "unredeemed" })).toMatchObject({ accepted: true, state: "failed" });
      expect(claims.listUnresolved(REQUESTER)).toEqual([]);
      claims.close();
    });

    it("an unresolved claim closes indeterminate at the window's end and stays refused", async () => {
      const c = clock();
      const { file, open } = domainOnFile(c);
      const claims = open();
      const key = freshKey();
      expect((await evaluate(request(c, { key }), options(claims, c))).decision).toBe(true);
      c.set(T0 + VALID_MS + LEASE_MS + 1_000);
      expectDenied(await evaluate(request(c, { key }), options(claims, c)), "duplicate_suppressed", {
        next_action: "retry",
        retry_after: Math.ceil((WINDOW_MS - 1_000) / 1000),
      });
      c.set(T0 + VALID_MS + LEASE_MS + WINDOW_MS);
      expectDenied(await evaluate(request(c, { key }), options(claims, c)), "duplicate_suppressed", { next_action: "none" });
      claims.close();
      expect(rowsOf(file)).toEqual([expect.objectContaining({ state: "indeterminate" })]);
    });
  });

  // #1016 review round 2: a failed or suppressed record proves no effect only
  // for the attempt that took the single use.
  describe("a failure settles only from the attempt that redeemed the permit", () => {
    it("a suppression from any other attempt never settles: the claim stays unresolved, closes indeterminate, and is never purged", async () => {
      const c = clock();
      const { file, open } = domainOnFile(c);
      const claims = open();
      const key = freshKey();
      const permit = await evaluate(request(c, { key }), options(claims, c));
      const id = String(permit.context.evaluation_id);
      c.set(T0 + VALID_MS + LEASE_MS + 1_000);
      // A replay of the same permit, refused at admission, never redeemed it.
      const replay = await executionRecord(id, "suppressed", "exe_replay", "permit_expired");
      const redeemer = () => "exe_redeeming_attempt";
      expect(await claims.reconcile(REQUESTER, id, { kind: "execution_evidence", record: replay }, redeemer)).toEqual({
        accepted: false,
        reason: "not_the_redeeming_attempt",
      });
      expect(await claims.settle(REQUESTER, replay)).toEqual({ accepted: false, reason: "redeeming_attempt_unknown" });
      expect(await claims.settle(REQUESTER, replay, () => { throw new Error("redemption store unreachable"); })).toEqual({
        accepted: false,
        reason: "redeeming_attempt_unknown",
      });
      expect(claims.listUnresolved(REQUESTER).map((u) => u.evaluation_id)).toEqual([id]);
      c.set(T0 + VALID_MS + LEASE_MS + WINDOW_MS);
      expectDenied(await evaluate(request(c, { key }), options(claims, c)), "duplicate_suppressed", { next_action: "none" });
      c.set(T0 + 3 * HORIZON_MS);
      expectDenied(await evaluate(request(c, { key }), options(claims, c)), "duplicate_suppressed", { next_action: "none" });
      claims.close();
      expect(rowsOf(file)).toEqual([expect.objectContaining({ evaluation_id: id, state: "indeterminate" })]);
    });

    it("a failure from the attempt the redemption record names settles failed", async () => {
      const c = clock();
      const { open } = domainOnFile(c);
      const claims = open();
      const key = freshKey();
      const permit = await evaluate(request(c, { key }), options(claims, c));
      const id = String(permit.context.evaluation_id);
      const failure = await executionRecord(id, "suppressed", "exe_redeeming_attempt", "parameter_mismatch");
      expect(await claims.settle(REQUESTER, failure, () => "exe_redeeming_attempt")).toEqual({
        accepted: true,
        state: "failed",
        duplicate: false,
      });
      expectDenied(await evaluate(request(c, { key }), options(claims, c)), "duplicate_suppressed", { next_action: "none" });
      claims.close();
    });
  });

  describe("retention through the declared horizon", () => {
    it("a completed key is refused at the horizon minus one second and is new after it", async () => {
      const c = clock();
      const { open } = domainOnFile(c);
      const claims = open();
      const key = freshKey();
      const first = await evaluate(request(c, { key }), options(claims, c));
      await claims.settle(REQUESTER, await executionRecord(String(first.context.evaluation_id), "completed"));
      c.set(T0 + HORIZON_MS - 1_000);
      expectDenied(await evaluate(request(c, { key }), options(claims, c)), "duplicate_suppressed", { next_action: "none" });
      c.set(T0 + HORIZON_MS);
      const fresh = await evaluate(request(c, { key }), options(claims, c));
      expect(fresh.decision, JSON.stringify(fresh.context)).toBe(true);
      expect(fresh.context.evaluation_id).not.toBe(first.context.evaluation_id);
      claims.close();
    });

    it("an indeterminate key is still refused past the horizon", async () => {
      const c = clock();
      const { open } = domainOnFile(c);
      const claims = open();
      const key = freshKey();
      expect((await evaluate(request(c, { key }), options(claims, c))).decision).toBe(true);
      c.set(T0 + VALID_MS + LEASE_MS + WINDOW_MS + 1_000);
      claims.sweep();
      c.set(T0 + 2 * HORIZON_MS);
      expectDenied(await evaluate(request(c, { key }), options(claims, c)), "duplicate_suppressed", { next_action: "none" });
      claims.close();
    });
  });

  describe("every keyed high-consequence action requires a well-formed key", () => {
    it("a missing or malformed key denies parameter_violation in all three classes", async () => {
      const c = clock();
      const { open } = domainOnFile(c);
      const claims = open();
      const classes: Array<[string, string]> = [
        ["irreversible_action", "payments:payment.execute"],
        ["external_commitment", "payments:remittance.send"],
        ["privileged_administration", ADMIN_ACTION],
      ];
      for (const [actionClass, action] of classes) {
        for (const key of [null, "too-short", "has spaces in it, not allowed", "x".repeat(129)]) {
          const d = await evaluate(request(c, { key, actionClass, action }), options(claims, c));
          expect(d.decision, `${actionClass} ${String(key)}`).toBe(false);
          expect(d.context.denial_reason, `${actionClass} ${String(key)}`).toBe("parameter_violation");
        }
        // The positive control: a well-formed key is claimed and permitted.
        expect((await evaluate(request(c, { actionClass, action }), options(claims, c))).decision, actionClass).toBe(true);
      }
      claims.close();
    });
  });
});
