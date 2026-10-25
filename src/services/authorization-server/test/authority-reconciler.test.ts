/**
 * @spec runtime#input-authority-dependency, runtime#state-freshness,
 * mission#revocation (#830 Q-d and Q-e, D798): lifecycle-mediated enforcement
 * of the declared authority dependency by the reconciler.
 *
 * The authorization server is assembled with the deployment's declaration
 * (config/authority-dependencies.json: the Mission Subject's continuing
 * delegation to the Mission's client, governing user-delegated Missions,
 * enforced directly at the PDP and through lifecycle operations: `suspend`
 * for a disabled Subject or a withdrawn delegation, `revoke` for a
 * deprovisioned Subject, with a 60 s reconciliation lag bound) over a
 * controlled identity source and clock. Each decision is the PDP's
 * `evaluate()` over the kernel's view of the Mission, given the AS's
 * dependency enforcement and the reconciler's progress.
 *
 *  - The reconciler commits `suspend` and `revoke` through the lifecycle
 *    operations, a suspended Mission's revocation included, and a repeat pass
 *    commits nothing.
 *  - An outage, a principal the source holds no record of, and a disabled
 *    Subject never revoke; an approver's or a client's departure changes
 *    nothing unless that principal is the recorded Subject.
 *  - A lost event is caught at the next gate and at the PDP; a disconnected
 *    feed and a failed reconciliation leave the reconciler's progress
 *    unadvanced, so the PDP refuses once it is overdue while the Mission's
 *    state still reads `active`.
 *  - A reconciler restarted mid-pass, or on a file-backed kernel after a
 *    restart, completes the remainder and commits each transition once; until
 *    its first pass the PDP refuses.
 *  - Re-enablement resumes nothing and revives no terminated Mission; a
 *    suspended Mission resumes only through an authorized Lifecycle request,
 *    authority removed through Containment stays removed, and every remaining
 *    check still applies after the resume.
 */

import { mkdtempSync, rmSync } from "node:fs";
import type { Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  type AuthorityDependencyDeclaration,
  type AuthorityDependencyEnforcement,
  AuthorityDependencyEvidence,
  AuthorityDependencyResolver,
} from "@mission/core";
import { AUTHORITY_DEPENDENCIES, CANONICAL_RESOURCE, parseIdentityState } from "@mission/demo-data";
import { evaluate as evaluateRequest, type EvaluationRequest, type Fga, type MissionView, relationForAction, stalenessBound } from "@mission/pdp";
import { RESOURCE_POLICY_PERMITS_ALL_FIXTURE } from "@mission/pdp/test-support";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { withCredential } from "../../pdp/test/with-credential.js";
import {
  AuthorityReconciler,
  type BuiltAs,
  buildAuthorizationServer,
  MISSION_LIFECYCLE_SCOPE,
  MISSION_STATUS_SCOPE,
  type MissionRecord,
  type ReconcileOutcome,
  validateMissionIntent,
} from "../src/index.js";
import { capabilityPresentationFor } from "./capability-presentation.helper.js";
import { type LifecycleTestClient, lifecycleRequest, newLifecycleClient } from "./lifecycle-endpoint.helper.js";

const evaluate = (req: EvaluationRequest, opts: Parameters<typeof evaluateRequest>[1]) => evaluateRequest(withCredential(req), opts);

const PORT = 15322;
const ISSUER = `http://localhost:${PORT}`;
const RESOURCE = CANONICAL_RESOURCE;
const READ = "payments:invoice.read";
const SEND = "payments:remittance.send";
const DECLARATION = AUTHORITY_DEPENDENCIES[0] as AuthorityDependencyDeclaration;
const LAG_MS = (DECLARATION.enforcement.reconciliation_max_lag_seconds as number) * 1000;
const PRINCIPALS = ["alice", "bob", "dana", "erin", "frank", "gina", "hana", "june", "kim", "lena", "omar", "pat", "quinn", "rui"];

type SourceRecord = { sub: string; status?: string; withdrawn_delegations?: string[] };
/** Every principal active and delegating, with `changes` applied: a principal mapped to null is absent from the source. */
function sourceWith(changes: Record<string, Omit<SourceRecord, "sub"> | null> = {}): SourceRecord[] {
  const records: SourceRecord[] = [];
  for (const sub of [...PRINCIPALS, ...Object.keys(changes).filter((s) => !PRINCIPALS.includes(s))]) {
    const change = changes[sub];
    if (change === null) continue;
    records.push({ sub, ...(change ?? {}) });
  }
  return records;
}

let source: unknown = sourceWith();
let nowMs = Date.now();
/** While set, each read waits for the test to complete it (`held[i](records)`), as a slow read does. */
let held: Array<(records: unknown) => void> | undefined;
const read = async () => {
  if (held) {
    const waiting = held;
    return new Promise((resolve) => waiting.push(resolve));
  }
  if (source instanceof Error) throw source;
  return source;
};
const newResolver = () => new AuthorityDependencyResolver({ issuer: ISSUER, read, parse: (raw) => parseIdentityState(raw), now: () => nowMs });
const evidence = new AuthorityDependencyEvidence();
const resolver = newResolver();

let as: BuiltAs;
let server: Server;
/** Holds `mission_lifecycle`. */
let consoleClient: LifecycleTestClient;
/** Holds `mission_status` only. */
let readerClient: LifecycleTestClient;

beforeAll(async () => {
  consoleClient = await newLifecycleClient("dependency-console");
  readerClient = await newLifecycleClient("dependency-status-reader");
  as = await buildAuthorizationServer({
    issuer: ISSUER,
    testClients: [consoleClient.metadata, readerClient.metadata],
    lifecycleClientGrants: {
      [consoleClient.clientId]: [MISSION_LIFECYCLE_SCOPE],
      [readerClient.clientId]: [MISSION_STATUS_SCOPE],
    },
    authorityDependency: { declaration: DECLARATION, resolver, evidence, now: () => nowMs },
  });
  server = as.provider.listen(PORT);
  await new Promise<void>((r) => server.once("listening", () => r()));
});

afterAll(async () => {
  await new Promise<void>((r) => server.close(() => r()));
});

function built<T>(value: T | undefined, what: string): T {
  if (value === undefined) throw new Error(`${what} is not assembled`);
  return value;
}
const reconciler = () => built(as.authorityReconciler, "the reconciler");
const enforcement = () => built(as.authorityDependency, "the dependency enforcement");

/** Point the identity source at `records` (an Error for an outage) and read it. */
async function observe(records: unknown): Promise<boolean> {
  source = records;
  return resolver.refresh();
}

/** A user-delegated Mission for `sub`, approved at the kernel by `approver`. */
function approve(target: BuiltAs, sub: string, approver = "bob"): MissionRecord {
  return target.kernel.approve({
    intent: validateMissionIntent(JSON.stringify({ goal: `Pay Acme invoices for ${sub}`, target_resources: [RESOURCE], expires_at: "2027-01-01T00:00:00Z" })),
    proposedAuthority: [
      {
        type: "mission_resource_access",
        resource: RESOURCE,
        actions: [READ, SEND],
        constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
      },
    ],
    subject: { iss: ISSUER, sub },
    approver: { iss: ISSUER, sub: approver },
    clientId: "ap-agent",
    approvalEventId: `apev-rec-${crypto.randomUUID()}`,
  });
}

/** The PDP's view of a Mission, from the kernel (the containment delta included). */
function viewFor(target: BuiltAs, id: string): MissionView {
  const r = target.kernel.applyExpiry(built(target.kernel.get(id), `mission ${id}`));
  return {
    id: r.id,
    issuer: r.issuer,
    state: r.state,
    version: r.version,
    authority_hash: r.authority_hash,
    authority_set: r.authority_set,
    subject: r.subject,
    client_id: r.client_id,
    ...(r.containment ? { containment: { version: r.containment.containment_version, contained: r.containment.contained } } : {}),
  };
}

const allowAll = { checkWithContext: async () => true } as unknown as Fga;

/** A PDP decision for `action` under the Mission, given the dependency enforcement (the AS's own by default). */
async function decide(id: string, action = READ, dependency: AuthorityDependencyEnforcement = enforcement(), target: BuiltAs = as) {
  const view = viewFor(target, id);
  return evaluate(
    {
      subject: { id: view.subject.sub, properties: { iss: ISSUER } },
      resource: { type: "invoice", id: "inv-1", properties: { audience: RESOURCE, operation_target: RESOURCE, vendor_id: "acme" } },
      action: { name: action },
      context: {
        ...capabilityPresentationFor(action),
        mission: { id: view.id, issuer: view.issuer, authority_hash: view.authority_hash },
        actor: { client_id: "ap-agent" },
        amount: { amount: "100.00", currency: "USD" },
      },
    },
    {
      view,
      fga: allowAll,
      modelId: "unit-test-model",
      now: () => new Date(nowMs),
      stalenessBound,
      relationForAction,
      resourcePolicy: RESOURCE_POLICY_PERMITS_ALL_FIXTURE,
      authorityDependency: dependency,
    },
  );
}

/** The transitions a pass committed for the given Missions. */
const mine = (outcome: ReconcileOutcome, ...missions: MissionRecord[]) =>
  outcome.transitions.filter((t) => missions.some((m) => m.id === t.mission));
const stateOf = (id: string, target: BuiltAs = as) => {
  const r = built(target.kernel.get(id), `mission ${id}`);
  return { state: r.state, reason: r.termination?.reason, version: r.version };
};

describe("lifecycle-mediated enforcement of the declared dependency by the reconciler (@spec runtime#input-authority-dependency, #830)", () => {
  it("suspends an active Mission when its Subject is disabled or withdraws the delegation, revokes on deprovisioning a suspended Mission included, and a repeat pass commits nothing", async () => {
    nowMs = Date.now();
    await observe(sourceWith());
    const disabled = approve(as, "erin");
    const withdrawn = approve(as, "frank");
    const deprovisioned = approve(as, "gina");
    const suspendedFirst = approve(as, "gina");
    as.kernel.transition(suspendedFirst.id, "suspend");
    source = sourceWith({ erin: { status: "disabled" }, frank: { withdrawn_delegations: ["ap-agent"] }, gina: { status: "deprovisioned" } });
    const pass = await reconciler().reconcile();
    expect(pass.ok, JSON.stringify(pass.failures)).toBe(true);
    expect(mine(pass, disabled, withdrawn, deprovisioned, suspendedFirst)).toEqual([
      { mission: disabled.id, operation: "suspend", change: "subject_disabled" },
      { mission: withdrawn.id, operation: "suspend", change: "delegation_withdrawn" },
      { mission: deprovisioned.id, operation: "revoke", change: "subject_deprovisioned" },
      { mission: suspendedFirst.id, operation: "revoke", change: "subject_deprovisioned" },
    ]);
    expect(stateOf(disabled.id)).toMatchObject({ state: "suspended", reason: undefined });
    expect(stateOf(withdrawn.id)).toMatchObject({ state: "suspended", reason: undefined });
    expect(stateOf(deprovisioned.id)).toMatchObject({ state: "terminated", reason: "revoked" });
    expect(stateOf(suspendedFirst.id)).toMatchObject({ state: "terminated", reason: "revoked" });
    const versions = [disabled, withdrawn, deprovisioned, suspendedFirst].map((m) => stateOf(m.id).version);
    const repeat = await reconciler().reconcile();
    expect(repeat.ok).toBe(true);
    expect(repeat.transitions).toEqual([]);
    expect([disabled, withdrawn, deprovisioned, suspendedFirst].map((m) => stateOf(m.id).version)).toEqual(versions);
  });

  it("revokes on deprovisioning a Mission an earlier pass suspended for disablement", async () => {
    nowMs = Date.now();
    await observe(sourceWith());
    const m = approve(as, "dana");
    source = sourceWith({ dana: { status: "disabled" } });
    expect(mine(await reconciler().reconcile(), m)).toEqual([{ mission: m.id, operation: "suspend", change: "subject_disabled" }]);
    source = sourceWith({ dana: { status: "deprovisioned" } });
    expect(mine(await reconciler().reconcile(), m)).toEqual([{ mission: m.id, operation: "revoke", change: "subject_deprovisioned" }]);
    expect(stateOf(m.id)).toMatchObject({ state: "terminated", reason: "revoked" });
  });

  it("never revokes on an outage, a principal the source holds no record of, or a disabled Subject; an approver's or the client's departure changes nothing", async () => {
    nowMs = Date.now();
    await observe(sourceWith());
    const m = approve(as, "hana");
    const before = reconciler().lag();
    // An outage: the pass fails, commits nothing, and its progress stays where it was.
    source = new Error("identity source unreachable");
    const outage = await reconciler().reconcile();
    expect(outage.ok).toBe(false);
    expect(outage.transitions).toEqual([]);
    expect(reconciler().lag()).toEqual(before);
    expect(stateOf(m.id).state).toBe("active");
    // The source holds no record of the Subject: an unavailable lookup does not establish deprovisioning.
    source = sourceWith({ hana: null });
    const unknown = await reconciler().reconcile();
    expect(unknown.ok).toBe(true);
    expect(mine(unknown, m)).toEqual([]);
    expect(stateOf(m.id).state).toBe("active");
    // The approver deprovisioned, and the client's identifier deprovisioned as a principal: neither is the recorded Subject.
    source = sourceWith({ bob: { status: "deprovisioned" }, "ap-agent": { status: "deprovisioned" } });
    expect(mine(await reconciler().reconcile(), m)).toEqual([]);
    expect(stateOf(m.id).state).toBe("active");
    expect((await decide(m.id)).decision).toBe(true);
    // A disabled Subject: suspend, never revoke.
    source = sourceWith({ hana: { status: "disabled" } });
    expect(mine(await reconciler().reconcile(), m)).toEqual([{ mission: m.id, operation: "suspend", change: "subject_disabled" }]);
    expect(stateOf(m.id)).toMatchObject({ state: "suspended", reason: undefined });
  });
});

describe("a lost event, a disconnected feed and a failed reconciliation are each caught while the Mission still reads active (@spec runtime#input-authority-dependency, #830)", () => {
  it("catches a lost event at the next issuance gate and at the PDP: the change reached the source, the reconciler's pass did not run", async () => {
    nowMs = Date.now();
    await observe(sourceWith());
    const m = approve(as, "june");
    expect((await reconciler().reconcile()).ok).toBe(true);
    expect((await decide(m.id)).decision).toBe(true);
    // The resolver's own read sees the change; no reconciliation pass follows.
    await observe(sourceWith({ june: { status: "disabled" } }));
    expect(stateOf(m.id).state).toBe("active");
    expect(() => as.kernel.checkDerivation(m.id)).toThrow(/declared authority dependency is not established/);
    const dec = await decide(m.id);
    expect(dec.decision).toBe(false);
    expect(dec.context.denial_reason).toBe("resource_policy");
    expect(evidence.entries().at(-1)).toMatchObject({ enforcer: "pdp", failure: "invalidated", mission: { id: m.id } });
    // The next pass restricts the Mission.
    expect(mine(await reconciler().reconcile(), m)).toEqual([{ mission: m.id, operation: "suspend", change: "subject_disabled" }]);
  });

  it("refuses at the PDP once a disconnected feed leaves the reconciliation overdue, though the cached observation is still within its validity and the Mission reads active", async () => {
    nowMs = Date.now();
    await observe(sourceWith());
    const m = approve(as, "omar");
    expect((await reconciler().reconcile()).ok).toBe(true);
    const reconciledAt = nowMs;
    source = new Error("identity source unreachable");
    nowMs = reconciledAt + LAG_MS / 2;
    expect((await reconciler().reconcile()).ok).toBe(false);
    expect((await decide(m.id)).decision).toBe(true);
    nowMs = reconciledAt + LAG_MS;
    expect((await reconciler().reconcile()).ok).toBe(false);
    const dec = await decide(m.id);
    expect(dec.decision).toBe(false);
    expect(dec.context.denial_reason).toBe("resource_policy");
    expect(evidence.entries().at(-1)).toMatchObject({ enforcer: "pdp", failure: "reconciliation_overdue", mission: { id: m.id } });
    expect(stateOf(m.id).state).toBe("active");
    // The issuance gates evaluate the observation directly and do not read the
    // reconciler's progress: the cached observation is still within its validity.
    expect(() => as.kernel.checkDerivation(m.id)).not.toThrow();
    // The feed reconnects: the next complete pass makes the reconciliation current again.
    source = sourceWith();
    expect((await reconciler().reconcile()).ok).toBe(true);
    expect((await decide(m.id)).decision).toBe(true);
  });

  it("does not advance its progress over a failed reconciliation, so the PDP refuses the Mission it could not restrict; a reconciler restarted mid-pass commits only the remainder", async () => {
    nowMs = Date.now();
    await observe(sourceWith());
    const first = approve(as, "kim");
    const second = approve(as, "kim");
    source = sourceWith({ kim: { status: "disabled" } });
    let calls = 0;
    const crashing = new AuthorityReconciler({
      kernel: as.kernel,
      declaration: DECLARATION,
      resolver,
      transition: (id, op) => {
        calls += 1;
        if (id === second.id) throw new Error("the store refused the commit");
        return as.kernel.transition(id, op);
      },
    });
    const failed = await crashing.reconcile();
    expect(failed.ok).toBe(false);
    expect(mine(failed, first, second)).toEqual([{ mission: first.id, operation: "suspend", change: "subject_disabled" }]);
    expect(failed.failures).toEqual([{ mission: second.id, error: "the store refused the commit" }]);
    expect(crashing.lag()).toEqual({});
    expect(stateOf(second.id).state).toBe("active");
    const overdue = await decide(second.id, READ, { ...enforcement(), reconciliation: () => crashing.lag() });
    expect(overdue.decision).toBe(false);
    expect(overdue.context.denial_reason).toBe("resource_policy");
    expect(evidence.entries().at(-1)).toMatchObject({ enforcer: "pdp", failure: "reconciliation_overdue", mission: { id: second.id } });
    // Restarted: a fresh reconciler reconciles from the source and the kernel alone.
    const restarted = new AuthorityReconciler({ kernel: as.kernel, declaration: DECLARATION, resolver });
    const completed = await restarted.reconcile();
    expect(completed.ok).toBe(true);
    expect(mine(completed, first, second)).toEqual([{ mission: second.id, operation: "suspend", change: "subject_disabled" }]);
    expect(restarted.lag().lastReconciledAtMs).toBe(nowMs);
    expect(calls).toBe(2);
  });
});

describe("recovery: re-enablement resumes nothing, and an authorized resumption is subject to every remaining check (@spec runtime#input-authority-dependency, #830)", () => {
  it("revives no terminated Mission and resumes no suspended one on re-enablement; an unauthorized resumption is refused; an authorized one leaves contained authority contained", async () => {
    nowMs = Date.now();
    await observe(sourceWith());
    const m = approve(as, "pat");
    const gone = approve(as, "quinn");
    as.kernel.contain(m.id, {
      event: { type: "tainted_read", source: "https://siem.example/detections", observed_at: new Date().toISOString(), event_id: `taint-rec-${crypto.randomUUID()}` },
      remove: [{ resource: RESOURCE, actions: [SEND] }],
    });
    const contained = built(as.kernel.get(m.id)?.containment, "the containment").contained;
    source = sourceWith({ pat: { status: "disabled" }, quinn: { status: "deprovisioned" } });
    await reconciler().reconcile();
    expect(stateOf(m.id).state).toBe("suspended");
    expect(stateOf(gone.id)).toMatchObject({ state: "terminated", reason: "revoked" });
    // Re-enabled at the source: the reconciler commits nothing.
    await observe(sourceWith());
    expect(mine(await reconciler().reconcile(), m, gone)).toEqual([]);
    expect(stateOf(m.id).state).toBe("suspended");
    expect(stateOf(gone.id)).toMatchObject({ state: "terminated", reason: "revoked" });
    // A terminated Mission stays terminated, even to an authorized Lifecycle client.
    const revive = await lifecycleRequest(ISSUER, consoleClient, { mission_id: gone.id, operation: "resume", nonce: `nonce-rec-${crypto.randomUUID()}` });
    expect(revive.status, revive.text).not.toBe(200);
    expect(stateOf(gone.id)).toMatchObject({ state: "terminated", reason: "revoked" });
    // A client without the lifecycle grant cannot resume the suspended one.
    const unauthorized = await lifecycleRequest(ISSUER, readerClient, { mission_id: m.id, operation: "resume", nonce: `nonce-rec-${crypto.randomUUID()}` });
    expect(unauthorized.status, unauthorized.text).not.toBe(200);
    expect(stateOf(m.id).state).toBe("suspended");
    // An authorized Lifecycle request resumes it; the containment is unchanged.
    const resumed = await lifecycleRequest(ISSUER, consoleClient, { mission_id: m.id, operation: "resume", nonce: `nonce-rec-${crypto.randomUUID()}` });
    expect(resumed.status, resumed.text).toBe(200);
    expect(stateOf(m.id).state).toBe("active");
    expect(as.kernel.get(m.id)?.containment?.contained).toEqual(contained);
    expect((await reconciler().reconcile()).ok).toBe(true);
    const send = await decide(m.id, SEND);
    expect(send.decision).toBe(false);
    expect(send.context.denial_reason).toBe("authority_contained");
    expect((await decide(m.id, READ)).decision).toBe(true);
  });

  it("applies every remaining check after an authorized resumption while the Subject is still disabled: the gate and the PDP refuse, and the next pass suspends it again", async () => {
    nowMs = Date.now();
    await observe(sourceWith());
    const m = approve(as, "rui");
    await observe(sourceWith({ rui: { status: "disabled" } }));
    expect(mine(await reconciler().reconcile(), m)).toEqual([{ mission: m.id, operation: "suspend", change: "subject_disabled" }]);
    const resumed = await lifecycleRequest(ISSUER, consoleClient, { mission_id: m.id, operation: "resume", nonce: `nonce-rec-${crypto.randomUUID()}` });
    expect(resumed.status, resumed.text).toBe(200);
    expect(stateOf(m.id).state).toBe("active");
    expect(() => as.kernel.checkDerivation(m.id)).toThrow(/declared authority dependency is not established/);
    const dec = await decide(m.id);
    expect(dec.decision).toBe(false);
    expect(dec.context.denial_reason).toBe("resource_policy");
    expect(evidence.entries().at(-1)).toMatchObject({ enforcer: "pdp", failure: "invalidated", mission: { id: m.id } });
    expect(mine(await reconciler().reconcile(), m)).toEqual([{ mission: m.id, operation: "suspend", change: "subject_disabled" }]);
    expect(stateOf(m.id).state).toBe("suspended");
  });
});

describe("the reconciler across a restart of a file-backed authorization server (@spec runtime#input-authority-dependency, #830)", () => {
  const dir = mkdtempSync(join(tmpdir(), "authority-reconciler-"));
  const kernelFile = join(dir, "kernel.sqlite");
  const RESTART_ISSUER = "http://localhost:15323";
  const boot = (bootResolver: AuthorityDependencyResolver) =>
    buildAuthorizationServer({
      issuer: RESTART_ISSUER,
      kernelStore: { file: kernelFile },
      authorityDependency: { declaration: DECLARATION, resolver: bootResolver, evidence, now: () => nowMs },
    } as never);
  const restartResolver = () =>
    new AuthorityDependencyResolver({ issuer: RESTART_ISSUER, read, parse: (raw) => parseIdentityState(raw), now: () => nowMs });
  const approveThere = (target: BuiltAs, sub: string) =>
    target.kernel.approve({
      intent: validateMissionIntent(JSON.stringify({ goal: `Pay Acme invoices for ${sub}`, target_resources: [RESOURCE], expires_at: "2027-01-01T00:00:00Z" })),
      proposedAuthority: [{ type: "mission_resource_access", resource: RESOURCE, actions: [READ], constraints: { vendors: ["acme"] } }],
      subject: { iss: RESTART_ISSUER, sub },
      approver: { iss: RESTART_ISSUER, sub: "bob" },
      clientId: "ap-agent",
      approvalEventId: `apev-rec-restart-${crypto.randomUUID()}`,
    });

  afterAll(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it("refuses at the PDP until its first pass after the restart, then commits no transition twice and acts on the next change", async () => {
    nowMs = Date.now();
    source = sourceWith();
    const firstResolver = restartResolver();
    await firstResolver.refresh();
    const before = await boot(firstResolver);
    const lena = [approveThere(before, "lena"), approveThere(before, "lena")];
    const active = approveThere(before, "alice");
    source = sourceWith({ lena: { status: "disabled" } });
    const pass = await built(before.authorityReconciler, "the reconciler").reconcile();
    expect(pass.transitions.map((t) => [t.mission, t.operation])).toEqual(lena.map((m) => [m.id, "suspend"]));
    before.suspensionScheduler?.stop();
    before.kernel.close();

    // The restart: the same kernel file, a fresh resolver and reconciler holding nothing.
    const after = await boot(restartResolver());
    const restarted = built(after.authorityReconciler, "the reconciler");
    expect(restarted.lag()).toEqual({});
    expect(lena.map((m) => stateOf(m.id, after))).toEqual(lena.map(() => expect.objectContaining({ state: "suspended" })));
    const versions = lena.map((m) => stateOf(m.id, after).version);
    const beforeFirstPass = await decide(active.id, READ, built(after.authorityDependency, "the dependency enforcement"), after);
    expect(beforeFirstPass.decision).toBe(false);
    expect(beforeFirstPass.context.denial_reason).toBe("resource_policy");
    expect(evidence.entries().at(-1)).toMatchObject({ enforcer: "pdp", failure: "reconciliation_overdue", mission: { id: active.id } });
    // The first pass after the restart: nothing to commit again.
    const firstPass = await restarted.reconcile();
    expect(firstPass.ok).toBe(true);
    expect(firstPass.transitions).toEqual([]);
    expect(lena.map((m) => stateOf(m.id, after).version)).toEqual(versions);
    expect((await decide(active.id, READ, built(after.authorityDependency, "the dependency enforcement"), after)).decision).toBe(true);
    // The next change: deprovisioning revokes the suspended Missions, each once.
    source = sourceWith({ lena: { status: "deprovisioned" } });
    const revoked = await restarted.reconcile();
    expect(revoked.transitions.map((t) => [t.mission, t.operation])).toEqual(lena.map((m) => [m.id, "revoke"]));
    expect((await restarted.reconcile()).transitions).toEqual([]);
    after.suspensionScheduler?.stop();
    after.kernel.close();
  });
});

describe("an unresolved Subject under lifecycle-only enforcement is an uncertainty that refuses, never a revocation (@spec runtime#input-authority-dependency, #830, D813)", () => {
  it("refuses dependent actions once the source no longer holds the Subject, though the reconciliation is current and the Mission active, records the uncertainty apart from a withdrawal, and revokes nothing", async () => {
    const LIFECYCLE_ISSUER = "http://localhost:15325";
    const { direct: _direct, ...lifecycleOnly } = DECLARATION.enforcement;
    const declaration = { ...DECLARATION, enforcement: lifecycleOnly } as AuthorityDependencyDeclaration;
    let records: unknown = [{ sub: "alice" }, { sub: "bob" }];
    nowMs = Date.now();
    const lifecycleEvidence = new AuthorityDependencyEvidence();
    const lifecycleResolver = new AuthorityDependencyResolver({
      issuer: LIFECYCLE_ISSUER,
      read: async () => records,
      parse: (raw) => parseIdentityState(raw),
      now: () => nowMs,
    });
    await lifecycleResolver.refresh();
    const lifecycleAs = await buildAuthorizationServer({
      issuer: LIFECYCLE_ISSUER,
      authorityDependency: { declaration, resolver: lifecycleResolver, evidence: lifecycleEvidence, now: () => nowMs },
    });
    try {
      const mission = lifecycleAs.kernel.approve({
        intent: validateMissionIntent(JSON.stringify({ goal: "Read Acme invoices for alice", target_resources: [RESOURCE], expires_at: "2027-01-01T00:00:00Z" })),
        proposedAuthority: [{ type: "mission_resource_access", resource: RESOURCE, actions: [READ, SEND], constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] } }],
        subject: { iss: LIFECYCLE_ISSUER, sub: "alice" },
        approver: { iss: LIFECYCLE_ISSUER, sub: "bob" },
        clientId: "ap-agent",
        approvalEventId: `apev-rec-unresolved-${crypto.randomUUID()}`,
      });
      const reconciler = built(lifecycleAs.authorityReconciler, "the reconciler");
      const dependency = built(lifecycleAs.authorityDependency, "the dependency enforcement");
      expect((await reconciler.reconcile()).ok).toBe(true);
      expect((await decide(mission.id, READ, dependency, lifecycleAs)).decision).toBe(true);
      // The source answers without the Subject, past the previous observation's validity.
      records = [{ sub: "bob" }];
      nowMs += 301_000;
      const pass = await reconciler.reconcile();
      expect(pass.ok).toBe(true);
      expect(pass.unresolved).toEqual([mission.id]);
      expect(pass.transitions).toEqual([]);
      expect(stateOf(mission.id, lifecycleAs)).toMatchObject({ state: "active", reason: undefined });
      expect(lifecycleResolver.view({ iss: LIFECYCLE_ISSUER, sub: "alice" }).observation?.known).toBe(false);
      const refused = await decide(mission.id, READ, dependency, lifecycleAs);
      expect(refused.decision).toBe(false);
      expect(refused.context.denial_reason).toBe("resource_policy");
      expect(lifecycleEvidence.entries().at(-1)).toMatchObject({ enforcer: "pdp", failure: "unresolved", mission: { id: mission.id } });
      // The issuance gates record the same uncertainty, never a withdrawal.
      expect(() => lifecycleAs.kernel.checkDerivation(mission.id)).toThrow(/declared authority dependency is not established/);
      expect(lifecycleEvidence.entries().at(-1)).toMatchObject({ enforcer: "as", failure: "unresolved" });
      expect(lifecycleEvidence.entries().map((e) => e.failure)).not.toContain("withdrawn");
      // The Subject resolves again: the next pass clears the uncertainty.
      records = [{ sub: "alice" }, { sub: "bob" }];
      expect((await reconciler.reconcile()).unresolved).toEqual([]);
      expect((await decide(mission.id, READ, dependency, lifecycleAs)).decision).toBe(true);
    } finally {
      lifecycleAs.kernel.close();
    }
  });
});

describe("the reconciler's reads are ordered with the scheduled refreshes and dated from issue (@spec runtime#input-authority-dependency, #830, D813)", () => {
  it("acts on a newer scheduled read that overtook its own, so an older read cannot undo the Subject's disablement", async () => {
    nowMs = Date.now();
    await observe(sourceWith());
    const m = approve(as, "lena");
    held = [];
    const pending = held;
    try {
      // The pass issues its read first; a scheduled refresh issued later completes first.
      const pass = reconciler().reconcile();
      nowMs += 1000;
      const scheduled = resolver.refresh();
      pending[1]?.(sourceWith({ lena: { status: "disabled" } }));
      await scheduled;
      pending[0]?.(sourceWith());
      const outcome = await pass;
      expect(outcome.ok).toBe(true);
      expect(mine(outcome, m)).toEqual([{ mission: m.id, operation: "suspend", change: "subject_disabled" }]);
      expect(reconciler().lag().lastReconciledAtMs).toBe(nowMs);
    } finally {
      held = undefined;
    }
  });

  it("dates its progress from when its read was issued, so a slow read does not make an overdue reconciliation current", async () => {
    nowMs = Date.now();
    await observe(sourceWith());
    const m = approve(as, "omar");
    held = [];
    const pending = held;
    const issuedAt = nowMs;
    try {
      const pass = reconciler().reconcile();
      nowMs = issuedAt + LAG_MS + 10_000;
      pending[0]?.(sourceWith());
      expect((await pass).ok).toBe(true);
    } finally {
      held = undefined;
    }
    expect(reconciler().lag().lastReconciledAtMs).toBe(issuedAt);
    const dec = await decide(m.id);
    expect(dec.decision).toBe(false);
    expect(evidence.entries().at(-1)).toMatchObject({ enforcer: "pdp", failure: "reconciliation_overdue", mission: { id: m.id } });
  });
});
