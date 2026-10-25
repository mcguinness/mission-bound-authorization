/**
 * @spec runtime#state-freshness (#830, D798, D813): the external-change
 * bound, measured end to end: from the identity source recording the change
 * (its `changed_at`) to no action under the governed Mission being able to
 * begin an effect, which is the issuance gate refusing, the PDP refusing, the
 * payments PEP releasing no effect under a permit it was issued before the
 * change and has not used, and the reconciler having suspended the Mission.
 *
 * The measurement runs the reference composition (the AS's resolver, issuance
 * gates and reconciler, and the PDP's `evaluate()` given the AS's dependency
 * enforcement) under a controlled clock at the declaration's own periods
 * (`detection_period_seconds`, `reconciliation_period_seconds`), from every
 * phase of the two schedules against the change in 5 s steps, the worst being
 * a read and a pass that both land just before the change. Each figure is in
 * declared seconds, and every one is within the declared `seconds`.
 *
 * Permit issuance is not already-started work. A permit issued before the
 * change and not yet used is held across the cutoff: from the first read
 * showing the change, the PEP's release check refuses it, while its own
 * `valid_until` has not passed, and no effect is released under it. Work
 * whose effect had begun is stated separately in the declaration; a permit
 * decided before the change also expires no later than its observation's
 * validity (asserted here, and witnessed on its own in the PDP's permit-cap
 * test).
 *
 * A second run drives the same composition with real timers through the AS's
 * own `refreshIntervalMs` and `reconcileIntervalMs`, scaled down, over a
 * rewritten identity file. It shows the schedules are wired and converge,
 * not the bound; a composition scheduling either period slower than declared
 * is refused at startup.
 */

import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { type AuthorityDependencyDeclaration, AuthorityDependencyResolver } from "@mission/core";
import {
  createEphemeralEvidenceKeys,
  credentialAuthorityFrom,
  EvidenceStore,
  type ExecutionAttempt,
  PaymentsStore,
  Pep,
  type TokenFacts,
} from "@mission/mcp-payments";
import { AUTHORITY_DEPENDENCIES, CANONICAL_RESOURCE, parseIdentityState, readIdentitySource } from "@mission/demo-data";
import { evaluate as evaluateRequest, type EvaluationRequest, type Fga, relationForAction, stalenessBound } from "@mission/pdp";
import { RESOURCE_POLICY_PERMITS_ALL_FIXTURE } from "@mission/pdp/test-support";
import { afterAll, describe, expect, it } from "vitest";
import { withCredential } from "../../pdp/test/with-credential.js";
import { type BuiltAs, buildAuthorizationServer, type MissionRecord, validateMissionIntent } from "../src/index.js";
import { capabilityPresentationFor } from "./capability-presentation.helper.js";

const evaluate = (req: EvaluationRequest, opts: Parameters<typeof evaluateRequest>[1]) => evaluateRequest(withCredential(req), opts);

const ISSUER = "http://localhost:15324";
const RESOURCE = CANONICAL_RESOURCE;
const READ = "payments:invoice.read";
const DECLARATION = AUTHORITY_DEPENDENCIES[0] as AuthorityDependencyDeclaration;
const BOUND = DECLARATION.external_change_bound as NonNullable<AuthorityDependencyDeclaration["external_change_bound"]>;
const DETECTION_S = BOUND.detection_period_seconds;
const RECONCILIATION_S = BOUND.reconciliation_period_seconds as number;
const allowAll = { checkWithContext: async () => true } as unknown as Fga;

function built<T>(value: T | undefined, what: string): T {
  if (value === undefined) throw new Error(`${what} is not assembled`);
  return value;
}

function approve(as: BuiltAs, sub: string): MissionRecord {
  return as.kernel.approve({
    intent: validateMissionIntent(JSON.stringify({ goal: `Read Acme invoices for ${sub}`, target_resources: [RESOURCE], expires_at: "2027-01-01T00:00:00Z" })),
    proposedAuthority: [{ type: "mission_resource_access", resource: RESOURCE, actions: [READ], constraints: { vendors: ["acme"] } }],
    subject: { iss: ISSUER, sub },
    approver: { iss: ISSUER, sub: "bob" },
    clientId: "ap-agent",
    approvalEventId: `apev-bound-${crypto.randomUUID()}`,
  });
}

async function decide(as: BuiltAs, id: string, nowMs: number) {
  const r = as.kernel.applyExpiry(built(as.kernel.get(id), `mission ${id}`));
  return evaluate(
    {
      subject: { id: r.subject.sub, properties: { iss: ISSUER } },
      resource: { type: "invoice", id: "inv-1", properties: { audience: RESOURCE, operation_target: RESOURCE, vendor_id: "acme" } },
      action: { name: READ },
      context: {
        ...capabilityPresentationFor(READ),
        mission: { id: r.id, issuer: r.issuer, authority_hash: r.authority_hash },
        actor: { client_id: "ap-agent" },
      },
    },
    {
      view: {
        id: r.id,
        issuer: r.issuer,
        state: r.state,
        version: r.version,
        authority_hash: r.authority_hash,
        authority_set: r.authority_set,
        subject: r.subject,
        client_id: r.client_id,
      },
      fga: allowAll,
      modelId: "unit-test-model",
      now: () => new Date(nowMs),
      stalenessBound,
      relationForAction,
      resourcePolicy: RESOURCE_POLICY_PERMITS_ALL_FIXTURE,
      authorityDependency: built(as.authorityDependency, "the dependency enforcement"),
    },
  );
}

const gateRefuses = (as: BuiltAs, id: string): boolean => {
  try {
    as.kernel.checkDerivation(id);
    return false;
  } catch {
    return true;
  }
};

interface Measured {
  detectionPhase: number;
  reconciliationPhase: number;
  gate: number;
  pdp: number;
  /** The first time a permit issued before the change, and not yet used, can no longer release an effect. */
  effect: number;
  suspended: number;
  end: number;
}

/**
 * The payments PEP composed with the authorization server's dependency: the
 * decision point evaluates it (direct evaluation routed to the PDP) and the
 * PEP, holding it too, rechecks it at release. One clock throughout.
 */
function paymentsPep(as: BuiltAs, clock: () => number) {
  const dependency = built(as.authorityDependency, "the dependency enforcement");
  const keys = createEphemeralEvidenceKeys({ resourcePolicy: RESOURCE_POLICY_PERMITS_ALL_FIXTURE, authorityDependency: dependency });
  const payments = new PaymentsStore();
  payments.seed(
    [{ id: "acme", name: "Acme", status: "approved" }],
    [{ id: "inv-1", vendor_id: "acme", amount: "125.00", currency: "USD", payee_account: "acct-acme", status: "payable" }],
  );
  const pep = new Pep({
    now: () => new Date(clock()),
    payments,
    evidence: new EvidenceStore(keys.signing, keys.resolver),
    fga: allowAll,
    modelId: "unit-test-model",
    decide: keys.decide,
    claims: keys.claims,
    instanceEpoch: "epoch-830-bound",
    loadView: (ref: { id: string; issuer: string }) => {
      const r = as.kernel.get(ref.id);
      if (!r || r.issuer !== ref.issuer) return undefined;
      const view = {
        id: r.id,
        issuer: r.issuer,
        state: r.state,
        version: r.version,
        authority_hash: r.authority_hash,
        authority_set: r.authority_set,
        subject: r.subject,
        client_id: r.client_id,
      };
      return { view, observation: { state: r.state, version: r.version, mode: "fresh", freshness_at: new Date(clock()).toISOString() } };
    },
    authorityDependency: dependency,
  });
  /** A permit for the Mission's read, issued now and held unused. */
  const issue = async (mission: MissionRecord): Promise<{ attempt: ExecutionAttempt; validUntilMs: number }> => {
    const token: TokenFacts = {
      sub: mission.subject.sub,
      iss: ISSUER,
      clientId: "ap-agent",
      cnfJkt: "jkt-830-bound",
      mission: { id: mission.id, issuer: mission.issuer, authority_hash: mission.authority_hash },
      credentialAuthority: credentialAuthorityFrom([{ type: "mission_resource_access", resource: RESOURCE, actions: [READ] }]),
    };
    const intake = await pep.intake("get_invoice", { invoice_id: "inv-1" }, token);
    if (!intake.ok) throw new Error(`intake refused: ${intake.refusal_reason}`);
    const res = await pep.enforce("get_invoice", intake.args, token);
    if (!res.permitted || !res.attempt) throw new Error(`no permit: ${JSON.stringify(res)}`);
    return { attempt: res.attempt, validUntilMs: Date.parse(res.attempt.permitValidUntil as string) };
  };
  return { pep, issue };
}

describe("the external-change bound, measured end to end (@spec runtime#state-freshness, #830)", () => {
  it("stops every dependent action within the declared bound from the source recording the change, from every phase of the declared schedules, a permit issued before the change and held unused included; a permit decided before the change expires within its observation's validity", async () => {
    const PHASES = [5, 10, 15, 20, 25, 30];
    const subjects = PHASES.flatMap((d) => PHASES.map((c) => `phase-${d}-${c}`));
    let records: { sub: string; status?: string; changed_at?: string }[] = [{ sub: "bob" }, ...subjects.map((sub) => ({ sub }))];
    let nowMs = Date.parse("2026-10-25T12:00:00Z");
    const resolver = new AuthorityDependencyResolver({
      issuer: ISSUER,
      read: async () => records,
      parse: (raw) => parseIdentityState(raw),
      now: () => nowMs,
    });
    await resolver.refresh();
    const as = await buildAuthorizationServer({ issuer: ISSUER, authorityDependency: { declaration: DECLARATION, resolver, now: () => nowMs } });
    const reconciler = built(as.authorityReconciler, "the reconciler");
    const payments = paymentsPep(as, () => nowMs);
    const measured: Measured[] = [];
    for (const detectionPhase of PHASES) {
      for (const reconciliationPhase of PHASES) {
        const sub = `phase-${detectionPhase}-${reconciliationPhase}`;
        const base = nowMs + 3_600_000;
        const at = (seconds: number) => {
          nowMs = base + seconds * 1000;
        };
        const mission = approve(as, sub);
        // The schedules' last runs before the change: the read and the pass
        // whose next runs are detectionPhase and reconciliationPhase seconds
        // after it.
        at(reconciliationPhase - RECONCILIATION_S);
        expect((await reconciler.reconcile()).ok).toBe(true);
        at(detectionPhase - DETECTION_S);
        await resolver.refresh();
        // Already-started work: a permit decided just before the change.
        at(-1);
        const permit = await decide(as, mission.id, nowMs);
        expect(permit.decision, JSON.stringify(permit.context)).toBe(true);
        const observedAt = Date.parse(built(resolver.view({ iss: ISSUER, sub }).observation, "the observation").observedAt);
        const validUntil = Date.parse((permit.context.conditions as { valid_until: string }).valid_until);
        expect(validUntil).toBeLessThanOrEqual(observedAt + DECLARATION.max_staleness_seconds * 1000);
        // A permit the PEP was issued just before the change, held unused across it.
        const held = await payments.issue(mission);
        expect(payments.pep.permitUseFailure(held.attempt), sub).toBeUndefined();
        // The source records the change.
        at(0);
        records = records.map((r) => (r.sub === sub ? { sub, status: "disabled", changed_at: new Date(nowMs).toISOString() } : r));
        const first: Partial<Record<"gate" | "pdp" | "effect" | "suspended", number>> = {};
        let start: number | undefined;
        for (let t = 0; t <= BOUND.seconds; t += 1) {
          at(t);
          if (t > 0 && t % DETECTION_S === detectionPhase % DETECTION_S) await resolver.refresh();
          if (t > 0 && t % RECONCILIATION_S === reconciliationPhase % RECONCILIATION_S) await reconciler.reconcile();
          start ??= (() => {
            const changedAt = resolver.view({ iss: ISSUER, sub }).observation?.changedAt;
            return changedAt !== undefined ? Date.parse(changedAt) : undefined;
          })();
          const elapsed = start !== undefined ? (nowMs - start) / 1000 : t;
          if (first.gate === undefined && gateRefuses(as, mission.id)) first.gate = elapsed;
          if (first.pdp === undefined && !(await decide(as, mission.id, nowMs)).decision) first.pdp = elapsed;
          if (first.effect === undefined) {
            const failure = payments.pep.permitUseFailure(held.attempt);
            if (failure !== undefined) {
              // Refused by the dependency recheck while the permit's own validity still ran.
              expect(failure, sub).toBe("resource_policy");
              expect(nowMs, sub).toBeLessThan(held.validUntilMs);
              first.effect = elapsed;
            }
          }
          if (first.suspended === undefined && as.kernel.get(mission.id)?.state === "suspended") first.suspended = elapsed;
          if (first.gate !== undefined && first.pdp !== undefined && first.effect !== undefined && first.suspended !== undefined) break;
        }
        expect(start, sub).toBe(base);
        const gate = built(first.gate, `${sub}: the gate refusal`);
        const pdp = built(first.pdp, `${sub}: the PDP refusal`);
        expect(first.effect, `${sub}: the held permit's refusal at release`).toBeDefined();
        const effect = built(first.effect, `${sub}: the held permit's refusal at release`);
        const suspended = built(first.suspended, `${sub}: the suspension`);
        // Released after the cutoff, the held permit releases no effect.
        expect(await payments.pep.verifyPermitAtUse(held.attempt), sub).toMatchObject({ ok: false, error: "resource_policy" });
        measured.push({ detectionPhase, reconciliationPhase, gate, pdp, effect, suspended, end: Math.max(gate, pdp, effect, suspended) });
      }
    }
    for (const m of measured) expect(m.end, JSON.stringify(m)).toBeLessThanOrEqual(BOUND.seconds);
    // Each figure's worst case over the phases: a read and a pass both just before the change.
    const worst = (figure: "gate" | "pdp" | "effect" | "suspended" | "end") => Math.max(...measured.map((m) => m[figure]));
    expect({ gate: worst("gate"), pdp: worst("pdp"), effect: worst("effect"), suspended: worst("suspended"), end: worst("end") }).toEqual({
      gate: RECONCILIATION_S,
      pdp: RECONCILIATION_S,
      effect: RECONCILIATION_S,
      suspended: RECONCILIATION_S,
      end: RECONCILIATION_S,
    });
    expect(measured.find((m) => m.detectionPhase === DETECTION_S && m.reconciliationPhase === RECONCILIATION_S)).toMatchObject({
      gate: DETECTION_S,
      pdp: DETECTION_S,
      effect: DETECTION_S,
      suspended: RECONCILIATION_S,
    });
    as.kernel.close();
  });
});

describe("the declared schedules, run by the authorization server's own timers (@spec runtime#state-freshness, #830)", () => {
  const dir = mkdtempSync(join(tmpdir(), "authority-dependency-bound-"));
  const identityFile = join(dir, "identity.json");
  afterAll(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it("re-reads a rewritten identity file and reconciles on its scaled-down periods, stopping the Mission's derivation and suspending it", async () => {
    writeFileSync(identityFile, JSON.stringify([{ sub: "alice" }, { sub: "bob" }]));
    const resolver = new AuthorityDependencyResolver({
      issuer: ISSUER,
      read: () => readIdentitySource(identityFile),
      parse: (raw) => parseIdentityState(raw, identityFile),
    });
    await resolver.refresh();
    const as = await buildAuthorizationServer({
      issuer: ISSUER,
      authorityDependency: { declaration: DECLARATION, resolver, refreshIntervalMs: 50, reconcileIntervalMs: 50 },
    });
    try {
      const mission = approve(as, "alice");
      writeFileSync(identityFile, JSON.stringify([{ sub: "alice", status: "disabled", changed_at: new Date().toISOString() }, { sub: "bob" }]));
      const deadline = Date.now() + 3_000;
      while (Date.now() < deadline && !(gateRefuses(as, mission.id) && as.kernel.get(mission.id)?.state === "suspended")) {
        await new Promise((r) => setTimeout(r, 10));
      }
      expect(gateRefuses(as, mission.id)).toBe(true);
      expect(as.kernel.get(mission.id)?.state).toBe("suspended");
      expect(built(as.authorityReconciler, "the reconciler").last()?.ok).toBe(true);
    } finally {
      as.stopAuthorityDependency?.();
      as.kernel.close();
    }
  }, 10_000);

  it("refuses to start a composition that schedules either period slower than declared", async () => {
    const resolver = new AuthorityDependencyResolver({ issuer: ISSUER, read: async () => [], parse: (raw) => parseIdentityState(raw) });
    await expect(
      buildAuthorizationServer({ issuer: ISSUER, authorityDependency: { declaration: DECLARATION, resolver, refreshIntervalMs: DETECTION_S * 1000 + 1 } }),
    ).rejects.toThrow(/refreshIntervalMs .* exceeds the declared period of 30 s/);
    await expect(
      buildAuthorizationServer({ issuer: ISSUER, authorityDependency: { declaration: DECLARATION, resolver, reconcileIntervalMs: RECONCILIATION_S * 1000 + 1 } }),
    ).rejects.toThrow(/reconcileIntervalMs .* exceeds the declared period of 30 s/);
  });
});
