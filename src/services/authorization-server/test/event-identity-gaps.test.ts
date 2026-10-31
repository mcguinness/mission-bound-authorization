/**
 * @spec mission#approval-idempotency (#1915, D1056): the event-identity rule on
 * the paths event-identity-boundary.test.ts does not reach.
 *
 * One approval event creates at most one Mission; retries or duplicate
 * deliveries of one creation decision resolve to one Mission; distinct
 * decisions get distinct `approval_event_id` values the AS allocates. Each
 * path keeps its own replay response; the common requirement is no duplicate
 * creation.
 *
 * Part A runs against bare kernels: the `missions.approval_event_id`
 * uniqueness reached across two store instances, Deferred Mission Approval
 * delivered twice, and Child Mission Carryover replayed. Part B drives a
 * device-capable assembly (RFC 8628). Part C drives the assembly
 * event-identity-boundary.test.ts uses, for the Expansion poll race and Child
 * Delegation's event allocation.
 *
 * Where a race is witnessed, the first request is held inside its commit (its
 * grant or token save) while the second runs, so the interleaving is the
 * dangerous one on every run, not a timing accident.
 */

import type { Server } from "node:http";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CANONICAL_RESOURCE, DERIVATION_POLICY, PROGRESSIVE_PROFILE, TOPOLOGY } from "@mission/demo-data";
import { UniqueViolationError, withTransaction } from "@mission/store";
import { type CryptoKey, decodeJwt, exportJWK, generateKeyPair, importJWK, SignJWT } from "jose";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { ACCESS_TOKEN_TOKEN_TYPE, JWT_TOKEN_TYPE, TOKEN_EXCHANGE_GRANT_TYPE } from "../src/adapters/continuation-grant.js";
import type { RegisteredActivationPolicy } from "../src/kernel/activation-policy.js";
import { DEFERRED_GRANT_TYPE } from "../src/kernel/deferred.js";
import { progressiveFromProfile } from "../src/kernel/progressive.js";
import {
  ALL_PROVIDER_CAPABILITIES,
  applyCarryoverInCallerTx,
  ApprovalSessionStore,
  type AuthorityEntry,
  type AuthoritySourceCatalog,
  buildAuthorizationServer,
  type BuiltAs,
  type CarryoverConfig,
  CarryoverError,
  type CarryoverManifest,
  carryoverApprovalEventId,
  carryoverManifestHash,
  commitCarryoverManifest,
  createChildMission,
  createExpansion,
  ExpansionDeferralStore,
  type GovernedPolicyRoot,
  type LifecycleCommit,
  MissionApprovalDeferralError,
  MissionApprovalDeferralStore,
  MissionKernel,
  type MissionRecord,
  prepareCarryover,
  type ProviderCapability,
  recordGovernedPolicyConsent,
  validateMissionIntent,
} from "../src/index.js";
import { aiAgents } from "./actor-profiles.helper.js";
import {
  browserApprovalHeaders,
  FIXTURE_BROWSER_LOGIN,
  floorApprovalHeaders,
  renderedRevision,
  TEST_APPROVAL_PRINCIPALS,
} from "./approval-fixture.js";
import { testAuthoritySourceCatalog } from "./authority-source.helper.js";

const TAG = "(@spec mission#approval-idempotency, #1915)";

/** A promise and the function that settles it. */
function latch(): { promise: Promise<void>; open: () => void } {
  let open: () => void = () => {};
  const promise = new Promise<void>((r) => {
    open = r;
  });
  return { promise, open };
}

/**
 * Await `p` while the first request is still held; if it has not settled
 * within `ms` (it is waiting on the held request), report that instead of
 * hanging the suite.
 */
async function settleWhileHeld<T>(p: Promise<T>, ms = 3000): Promise<T | "blocked"> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const blocked = new Promise<"blocked">((r) => {
    timer = setTimeout(() => r("blocked"), ms);
  });
  try {
    return await Promise.race([p, blocked]);
  } finally {
    clearTimeout(timer);
  }
}

let statusKey: CryptoKey;
const tempDirs: string[] = [];

beforeAll(async () => {
  statusKey = (await generateKeyPair("ES256")).privateKey;
});

afterAll(() => {
  for (const dir of tempDirs) rmSync(dir, { recursive: true, force: true });
});

// ===========================================================================
// Part A: bare kernels.
// ===========================================================================

const ISS = "https://as.test";
const KRESOURCE = DERIVATION_POLICY.ceiling[0].resource;
let eventSeq = 0;

describe(`direct approval: the missions.approval_event_id uniqueness across two store instances ${TAG}`, () => {
  const kernelOver = (file: string) =>
    new MissionKernel({
      issuer: ISS,
      policy: DERIVATION_POLICY as never,
      authoritySourceCatalog: testAuthoritySourceCatalog(DERIVATION_POLICY.ceiling, ["worker"], ["human-approver", "bob"]),
      statusKey,
      statusKid: "as-status",
      store: { file },
    });
  const approveInput = (approvalEventId: string, goal = "reconcile Acme") => ({
    intent: validateMissionIntent(JSON.stringify({ goal, target_resources: [KRESOURCE], expires_at: "2027-01-01T00:00:00Z" })),
    subject: { iss: ISS, sub: "alice" },
    approver: { iss: ISS, sub: "bob" },
    clientId: "worker",
    approvalEventId,
  });
  /** Record, on `k`, whether a record insert met the store's uniqueness. */
  const watchInserts = (k: MissionKernel) => {
    const seen = { uniqueViolations: 0 };
    const insert = k.insertRecord.bind(k);
    const spy = vi.spyOn(k, "insertRecord").mockImplementation((...args: Parameters<MissionKernel["insertRecord"]>) => {
      try {
        return insert(...args);
      } catch (e) {
        if (e instanceof UniqueViolationError) seen.uniqueViolations += 1;
        throw e;
      }
    });
    return { seen, restore: () => spy.mockRestore() };
  };

  it(`a second kernel over the same database, sharing no per-event queue or approval reservation with the first, meets the uniqueness on the event the first committed and resolves to that Mission ${TAG}`, () => {
    const dir = mkdtempSync(join(tmpdir(), "event-gaps-"));
    tempDirs.push(dir);
    const file = join(dir, "kernel.sqlite");
    const a = kernelOver(file);
    const b = kernelOver(file);
    try {
      const event = "apev-two-stores";
      // B prepares first, as a decision that read no Mission under the event
      // before A committed one.
      const preparedEarly = b.prepareApproval(approveInput(event));
      const committed = a.approve(approveInput(event));
      const watched = watchInserts(b);
      let raced: MissionRecord;
      let replayed: MissionRecord;
      try {
        raced = b.approve(approveInput(event), preparedEarly);
        // A replay carrying another task still resolves to the one Mission.
        replayed = b.approve(approveInput(event, "another task"));
      } finally {
        watched.restore();
      }
      // Both reached the insert and were turned back by the store itself.
      expect(watched.seen.uniqueViolations).toBe(2);
      expect(raced.id).toBe(committed.id);
      expect(replayed.id).toBe(committed.id);
      expect(raced.intent.goal).toBe("reconcile Acme");
      for (const k of [a, b]) {
        expect(k.db.prepare("SELECT COUNT(*) AS n FROM missions WHERE approval_event_id = ?").get(event)).toEqual({ n: 1 });
        expect(k.findByApprovalEvent(event)?.id).toBe(committed.id);
      }
      // A distinct event is a distinct Mission, whichever store commits it.
      const other = b.approve(approveInput("apev-two-stores-other"));
      expect(other.id).not.toBe(committed.id);
      expect(a.allMissions()).toHaveLength(2);
    } finally {
      a.close();
      b.close();
    }
  });
});

describe(`Deferred Mission Approval: approveDirect delivered twice for one pending approval ${TAG}`, () => {
  const DANA = { iss: ISS, sub: "dana" };
  const BOB = { iss: ISS, sub: "bob" };
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
        activators: ["dana", "bob"],
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
        roots: {
          "urn:root:reconciler": { version: "1", content_type: "application/json", content: JSON.stringify(rootDoc) } as RegisteredActivationPolicy,
        },
        approvers: { "urn:root:reconciler": ["dana"] },
      },
    });
    recordGovernedPolicyConsent(k, {
      root: { id: "urn:root:reconciler", version: "1" },
      approver: DANA,
      consentEventId: `gpce-gaps-${eventSeq++}`,
    });
    return { k, deferrals: new MissionApprovalDeferralStore(k) };
  };
  const openPending = (deferrals: MissionApprovalDeferralStore) =>
    deferrals.open({
      intent: validateMissionIntent(
        JSON.stringify({ goal: "Reconcile Acme invoices", target_resources: [KRESOURCE], expires_at: "2027-01-01T00:00:00Z" }),
      ),
      clientId: "svc-agent",
      jkt: "jkt-svc-agent",
    }).deferral_code;
  const refusal = (f: () => unknown): MissionApprovalDeferralError => {
    try {
      f();
    } catch (e) {
      if (e instanceof MissionApprovalDeferralError) return e;
      throw e;
    }
    throw new Error("the repeated approveDirect was not refused");
  };

  it(`the second delivery is refused not_pending, through the same store, a second store instance or for another Approver, and the pending approval's one event names one Mission ${TAG}`, () => {
    const { k, deferrals } = setup();
    const code = openPending(deferrals);
    const event = deferrals.approvalEventId(code) as string;
    const first = deferrals.approveDirect(code, { approver: DANA, subject: SUBJECT });
    expect(first.approval_event_id).toBe(event);
    const committed = JSON.stringify(k.get(first.id));

    const again = refusal(() => deferrals.approveDirect(code, { approver: DANA, subject: SUBJECT }));
    expect(again.code).toBe("not_pending");
    expect(again.message).toBe("the approval is approved");
    // A second delivery handler over the same kernel database.
    const second = new MissionApprovalDeferralStore(k);
    expect(refusal(() => second.approveDirect(code, { approver: DANA, subject: SUBJECT })).code).toBe("not_pending");
    // Another reviewer delivering the same pending approval.
    expect(refusal(() => deferrals.approveDirect(code, { approver: BOB, subject: SUBJECT })).code).toBe("not_pending");

    expect(k.allMissions().map((m) => m.id)).toEqual([first.id]);
    expect(k.allMissions().filter((m) => m.approval_event_id === event)).toHaveLength(1);
    expect(JSON.stringify(k.get(first.id))).toBe(committed);
    expect(k.get(first.id)?.approval_basis.consent_principal).toEqual(DANA);
    expect(deferrals.state(code)).toBe("approved");
    // The client's poll is answered with the one Mission.
    const polled = deferrals.poll(code, { clientId: "svc-agent", jkt: "jkt-svc-agent" });
    expect("mission" in polled ? polled.mission.id : polled).toBe(first.id);
  });
});

describe(`Child Mission Carryover: a replayed completion and the child approval event ${TAG}`, () => {
  const RESOURCE = DERIVATION_POLICY.ceiling[0].resource;
  const LEDGER = TOPOLOGY.resources.saas;
  const PRED_EXP = "2027-01-01T00:00:00Z";
  const ACTORS = aiAgents("child-a", "child-b");
  const clock = new Date("2026-07-01T00:00:00Z");
  const config: CarryoverConfig = {
    enabled: true,
    maxRows: null,
    exclusionPolicy: { mode: "all_or_nothing" },
    noApplicableExternalState: true,
  };
  const proposed = (actions: string[]): AuthorityEntry[] => [
    {
      type: "mission_resource_access",
      resource: RESOURCE,
      actions,
      constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
    },
  ];
  const mkKernel = () =>
    new MissionKernel({
      issuer: ISS,
      policy: DERIVATION_POLICY as never,
      authoritySourceCatalog: testAuthoritySourceCatalog(DERIVATION_POLICY.ceiling, ["parent-agent"], ["bob"]),
      statusKey,
      statusKid: "as-status",
      now: () => clock,
      actorProfiles: ACTORS,
    });
  const intentOf = (over: Record<string, unknown> = {}) =>
    validateMissionIntent(JSON.stringify({ goal: "Pay Acme invoices", target_resources: [RESOURCE], expires_at: PRED_EXP, ...over }));
  const widerIntent = () =>
    validateMissionIntent(
      JSON.stringify({ goal: "Pay Acme invoices and post the ledger", target_resources: [RESOURCE, LEDGER], expires_at: PRED_EXP }),
    );
  const widerProposal = (): AuthorityEntry[] => [
    ...proposed(["payments:invoice.read", "payments:invoice.list", "payments:vendor.read"]),
    { type: "mission_resource_access", resource: LEDGER, actions: ["ledger:vendor.read"], constraints: { vendors: ["acme"] } },
  ];
  /** A predecessor with one live child. */
  const lineage = (k: MissionKernel) => {
    const pred = k.approve({
      intent: intentOf(),
      proposedAuthority: proposed(["payments:invoice.read", "payments:invoice.list"]),
      subject: { iss: ISS, sub: "alice" },
      approver: { iss: ISS, sub: "bob" },
      clientId: "parent-agent",
      approvalEventId: `apev-carry-${eventSeq++}`,
    });
    const child = createChildMission(k, {
      parentId: pred.id,
      intent: intentOf(),
      proposedAuthority: proposed(["payments:invoice.read"]),
      childActor: { sub: "child-a", sub_profile: "ai_agent" },
    }).child;
    return { pred, child };
  };
  /** Open and approve a deferred expansion carrying the child. */
  const openApproved = (k: MissionKernel, predecessorId: string) => {
    const store = new ExpansionDeferralStore(k, () => clock, config);
    const pending = store.open({
      predecessorId,
      intent: widerIntent(),
      proposedAuthority: widerProposal(),
      clientId: "parent-agent",
      jkt: "jkt-test",
      creationRequestId: `crid-carry-${eventSeq++}`,
    });
    const approvalEventId = `xapev-carry-${eventSeq++}`;
    store.approve(pending.deferral_code, { approver: { iss: ISS, sub: "bob" }, approvalEventId, approvedUntil: PRED_EXP });
    return { store, code: pending.deferral_code, approvalEventId };
  };
  const manifestOf = (store: ExpansionDeferralStore, code: string): CarryoverManifest =>
    JSON.parse(
      (store.db.prepare("SELECT carryover_manifest_json FROM expansion_deferrals WHERE deferral_code = ?").get(code) as {
        carryover_manifest_json: string;
      }).carryover_manifest_json,
    ) as CarryoverManifest;
  /** The manifest with the child's replacement relabelled under another approval event, its hash recomputed so the hash check passes. */
  const relabelled = (manifest: CarryoverManifest, childId: string, forgedEvent: string) => {
    const forged: CarryoverManifest = {
      ...manifest,
      entries: manifest.entries.map((e) =>
        e.child_id === childId && e.replacement ? { ...e, replacement: { ...e.replacement, approval_event_id: forgedEvent } } : e,
      ),
    };
    return { manifest: forged, manifestHash: carryoverManifestHash(ISS, forged) };
  };

  it(`a completion replayed after release is refused invalid_grant, and one replayed in the window before release recovers the same successor and replacement; one replacement exists, under the one deterministic child event ${TAG}`, () => {
    const k = mkKernel();
    const { pred, child } = lineage(k);
    const run = openApproved(k, pred.id);
    const entry = manifestOf(run.store, run.code).entries.find((e) => e.child_id === child.id);
    const replacementId = entry?.replacement?.replacement_id as string;
    const childEvent = carryoverApprovalEventId(ISS, run.approvalEventId, { issuer: ISS, mission_id: child.id });
    expect(entry?.replacement?.approval_event_id).toBe(childEvent);

    const first = run.store.redeem(run.code);
    if ("error" in first) throw new Error(`completion refused: ${JSON.stringify(first)}`);
    expect(first.carryover?.replacements.map((m) => m.id)).toEqual([replacementId]);
    expect(k.get(replacementId)?.approval_event_id).toBe(childEvent);
    const before = k.allMissions().length;

    // Released: the completion is single-use.
    expect(run.store.redeem(run.code)).toEqual({ error: "invalid_grant" });
    // The window between the committed batch and its release (a crash or a
    // lost response): the replay recovers the retained result.
    run.store.db.prepare("UPDATE expansion_deferrals SET completion_released = 0 WHERE deferral_code = ?").run(run.code);
    const replay = run.store.redeem(run.code);
    if ("error" in replay) throw new Error(`replay refused: ${JSON.stringify(replay)}`);
    expect(replay.successor.id).toBe(first.successor.id);
    expect(replay.carryover?.replacements.map((m) => m.id)).toEqual([replacementId]);
    expect(replay.carryover?.evidenceJws).toBe(first.carryover?.evidenceJws);

    expect(k.allMissions().length).toBe(before);
    expect(k.allMissions().filter((m) => m.related_to === child.id)).toHaveLength(1);
    expect(k.allMissions().filter((m) => m.approval_event_id === childEvent)).toHaveLength(1);
    expect(k.allMissions().filter((m) => m.predecessor === pred.id)).toHaveLength(1);
  });

  it(`a manifest naming any child approval event but the deterministic one is refused manifest_mismatch at the batch, even with its hash recomputed, creating nothing ${TAG}`, () => {
    const k = mkKernel();
    const { pred, child } = lineage(k);
    const store = new ExpansionDeferralStore(k, () => clock, config);
    const plan = prepareCarryover(k, store.carryover, {
      predecessorId: pred.id,
      successorIntent: widerIntent(),
      successorProposal: widerProposal(),
      config,
    });
    if (!plan) throw new Error("no carryover plan");
    const approvalEventId = `xapev-carry-${eventSeq++}`;
    const committed = commitCarryoverManifest(plan, approvalEventId);
    const forgedEvent = "apev-carry-forged";
    const forged = relabelled(committed.manifest, child.id, forgedEvent);
    const before = k.allMissions().length;
    let refused: unknown;
    try {
      withTransaction(k.db, () => {
        const res = createExpansion(k, {
          predecessorId: pred.id,
          intent: widerIntent(),
          proposedAuthority: widerProposal(),
          approver: { iss: ISS, sub: "bob" },
          approvalEventId,
          approvedUntil: PRED_EXP,
          successorId: forged.manifest.successor.mission_id,
        });
        return applyCarryoverInCallerTx(k, store.carryover, {
          planId: plan.plan_id,
          manifest: forged.manifest,
          manifestHash: forged.manifestHash,
          successor: res.successor,
          approver: { iss: ISS, sub: "bob" },
          expansionApprovalEventId: approvalEventId,
          directApproval: true,
          config,
        });
      });
    } catch (e) {
      refused = e;
    }
    expect(refused).toBeInstanceOf(CarryoverError);
    expect((refused as CarryoverError).code).toBe("manifest_mismatch");
    expect((refused as CarryoverError).message).toBe(
      `the committed child approval event for ${child.id} is not the deterministic identifier`,
    );
    // The transaction rolled back: no successor, no replacement, nothing under the forged event.
    expect(k.allMissions().length).toBe(before);
    expect(k.get(forged.manifest.successor.mission_id)).toBeUndefined();
    expect(k.findByApprovalEvent(forgedEvent)).toBeUndefined();
    expect(k.get(child.id)?.state).toBe("active");
    expect(k.get(pred.id)?.state).toBe("active");
  });

  it(`through completion, a stored manifest relabelled the same way is refused access_denied and creates nothing ${TAG}`, () => {
    const k = mkKernel();
    const { pred, child } = lineage(k);
    const run = openApproved(k, pred.id);
    const manifest = manifestOf(run.store, run.code);
    const forged = relabelled(manifest, child.id, "apev-carry-forged-stored");
    run.store.db
      .prepare("UPDATE expansion_deferrals SET carryover_manifest_json = ?, carryover_manifest_hash = ? WHERE deferral_code = ?")
      .run(JSON.stringify(forged.manifest), forged.manifestHash, run.code);
    const before = k.allMissions().length;
    expect(run.store.redeem(run.code)).toEqual({ error: "access_denied" });
    expect(k.allMissions().length).toBe(before);
    expect(k.get(manifest.successor.mission_id)).toBeUndefined();
    expect(k.findByApprovalEvent("apev-carry-forged-stored")).toBeUndefined();
    expect(k.get(child.id)?.state).toBe("active");
    expect(k.get(pred.id)?.state).toBe("active");
  });
});

// ===========================================================================
// Part B: Mission Device Authorization (RFC 8628) on a device-capable assembly.
// ===========================================================================

const DEV_PORT = 14948;
const DEV_ISSUER = `http://localhost:${DEV_PORT}`;
const DEV_RESOURCE = DERIVATION_POLICY.ceiling[0].resource as string;
const DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code";
const DEVICE_CLIENT = "agent-A1";
const DEV_SESSIONS = new ApprovalSessionStore();
const FORM = { "content-type": "application/x-www-form-urlencoded" };
const ALICE_BY_BOB = { sub: "bob", subject: "alice" };
const CONFIRMED = { decision: "approve", confirm_user_code: true, confirm_started: true };

let dev: BuiltAs;
let devServer: Server | undefined;

type Jar = Map<string, string>;
const cookieOf = (jar: Jar) => [...jar].map(([k, v]) => `${k}=${v}`).join("; ");
const keep = (jar: Jar, res: Response) => {
  for (const line of res.headers.getSetCookie()) {
    const [pair] = line.split(";");
    const eq = (pair as string).indexOf("=");
    jar.set((pair as string).slice(0, eq), (pair as string).slice(eq + 1));
  }
};
const hidden = (html: string, name: string): string => {
  const m = new RegExp(`name="${name}" value="([^"]*)"`).exec(html);
  if (!m) throw new Error(`no ${name} input in ${html.slice(0, 400)}`);
  return m[1] as string;
};

/** A device authorization request for the Reconcile Q3 invoices Mission. */
async function deviceAuthorize(): Promise<{ deviceCode: string; userCode: string }> {
  const res = await fetch(`${DEV_ISSUER}/device/auth`, {
    method: "POST",
    headers: FORM,
    body: new URLSearchParams({
      client_id: DEVICE_CLIENT,
      resource: DEV_RESOURCE,
      mission_intent: JSON.stringify({
        intent: { goal: "Reconcile Q3 invoices.", target_resources: [DEV_RESOURCE], expires_at: "2027-01-01T00:00:00Z" },
      }),
      authorization_details: JSON.stringify([
        { type: "mission_resource_access", resource: DEV_RESOURCE, actions: ["payments:invoice.read"] },
      ]),
    }).toString(),
  });
  const body = (await res.json()) as { device_code: string; user_code: string };
  expect(res.status, JSON.stringify(body)).toBe(200);
  return { deviceCode: body.device_code, userCode: body.user_code };
}

/** The verification user agent `jar` enters and confirms the `user_code`, starting an approval interaction; returns its uid. */
async function enterCode(userCode: string, jar: Jar): Promise<string> {
  let res = await fetch(`${DEV_ISSUER}/device`, { headers: { cookie: cookieOf(jar) }, redirect: "manual" });
  keep(jar, res);
  let html = await res.text();
  const form = (xsrf: string, more: Record<string, string> = {}) => new URLSearchParams({ xsrf, user_code: userCode, ...more }).toString();
  res = await fetch(`${DEV_ISSUER}/device`, {
    method: "POST",
    redirect: "manual",
    headers: { ...FORM, cookie: cookieOf(jar) },
    body: form(hidden(html, "xsrf")),
  });
  keep(jar, res);
  html = await res.text();
  res = await fetch(`${DEV_ISSUER}/device`, {
    method: "POST",
    redirect: "manual",
    headers: { ...FORM, cookie: cookieOf(jar) },
    body: form(hidden(html, "xsrf"), { confirm: "yes" }),
  });
  keep(jar, res);
  const location = res.headers.get("location") ?? "";
  expect(location, await res.text()).toMatch(/\/interaction\/[^/]+$/);
  return location.split("/interaction/")[1] as string;
}

/** One verification user agent on one interaction, its Approver authenticated and the page rendered. */
async function reviewer(userCode: string): Promise<{ uid: string; headers: Record<string, string>; revision: string }> {
  const jar: Jar = new Map();
  const uid = await enterCode(userCode, jar);
  const headers = browserApprovalHeaders(DEV_SESSIONS, uid, ALICE_BY_BOB, cookieOf(jar));
  return { uid, headers, revision: await renderedRevision(DEV_ISSUER, uid, headers) };
}

/** A fresh verification user agent typing `userCode`: where the provider sends it, and its page. */
async function codeEntryAnswer(userCode: string): Promise<{ location: string | null; html: string }> {
  const jar: Jar = new Map();
  let res = await fetch(`${DEV_ISSUER}/device`, { headers: { cookie: cookieOf(jar) }, redirect: "manual" });
  keep(jar, res);
  const html = await res.text();
  res = await fetch(`${DEV_ISSUER}/device`, {
    method: "POST",
    redirect: "manual",
    headers: { ...FORM, cookie: cookieOf(jar) },
    body: new URLSearchParams({ xsrf: hidden(html, "xsrf"), user_code: userCode }).toString(),
  });
  return { location: res.headers.get("location"), html: await res.text() };
}

/** The device decision on `uid`, naming the page `revision` rendered. */
async function deviceDecision(r: { uid: string; headers: Record<string, string>; revision: string }): Promise<{ status: number; text: string }> {
  const res = await fetch(`${DEV_ISSUER}/interaction/${r.uid}/decide`, {
    method: "POST",
    redirect: "manual",
    headers: { ...r.headers, "content-type": "application/json" },
    body: JSON.stringify({ ...CONFIRMED, render_revision: r.revision }),
  });
  return { status: res.status, text: await res.text() };
}

/** A device access token request: the poll, DPoP-bound under a fresh key. */
async function devicePoll(deviceCode: string): Promise<{ status: number; body: Record<string, unknown> }> {
  const htu = `${DEV_ISSUER}/token`;
  const pair = await generateKeyPair("ES256", { extractable: true });
  const dpop = await new SignJWT({ htu, htm: "POST" })
    .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: await exportJWK(pair.publicKey) })
    .setIssuedAt()
    .setJti(crypto.randomUUID())
    .sign(pair.privateKey);
  const res = await fetch(htu, {
    method: "POST",
    headers: { ...FORM, dpop },
    body: new URLSearchParams({ grant_type: DEVICE_GRANT, device_code: deviceCode, client_id: DEVICE_CLIENT }).toString(),
  });
  return { status: res.status, body: (await res.json()) as Record<string, unknown> };
}

const deviceMissionOf = (uid: string) => dev.kernel.findByApprovalEvent(`apev_${uid}`);

/**
 * Hold the first provider grant save (made inside a committing decision,
 * after it claimed its session) until `release`; later saves pass.
 */
function holdFirstGrantSave() {
  const proto = dev.provider.Grant.prototype as { save: (...args: unknown[]) => Promise<unknown> };
  const original = proto.save;
  const reached = latch();
  const gate = latch();
  let armed = true;
  const spy = vi.spyOn(proto, "save").mockImplementation(async function (this: unknown, ...args: unknown[]) {
    if (armed) {
      armed = false;
      reached.open();
      await gate.promise;
    }
    return original.apply(this, args);
  });
  return {
    reached: reached.promise,
    release: () => gate.open(),
    restore: () => {
      gate.open();
      spy.mockRestore();
    },
  };
}

describe(`Mission Device Authorization ${TAG}`, () => {
  beforeAll(async () => {
    dev = await buildAuthorizationServer({
      issuer: DEV_ISSUER,
      approvalSessions: DEV_SESSIONS,
      allowHeadlessAdjudication: true,
      serviceTokenPrincipals: TEST_APPROVAL_PRINCIPALS,
      capabilities: new Set<ProviderCapability>([...ALL_PROVIDER_CAPABILITIES, "device-authorization"]),
      testClients: [
        {
          client_id: DEVICE_CLIENT,
          token_endpoint_auth_method: "none",
          grant_types: [DEVICE_GRANT, "refresh_token"],
          response_types: [],
          redirect_uris: [],
          authorization_details_types: ["mission_resource_access"],
        },
      ],
    });
    devServer = dev.provider.listen(DEV_PORT);
  });

  afterAll(() => {
    devServer?.close();
  });

  describe(`two concurrent decisions on one device session ${TAG}`, () => {
    it(`a second verification user agent entering a user_code already confirmed is refused at the code entry and starts no interaction ${TAG}`, async () => {
      const { userCode } = await deviceAuthorize();
      await reviewer(userCode);
      const second = await codeEntryAnswer(userCode);
      expect(second.location).toBeNull();
      expect(second.html).toContain("The code was not accepted.");
    });

    it(`where a second interaction does exist over one device session (the provider's in-flight mark cleared in its store), deciding both while the first commits creates one Mission, and the second decision is refused while the session is claimed ${TAG}`, async () => {
      const { deviceCode, userCode } = await deviceAuthorize();
      const a = await reviewer(userCode);
      // oidc-provider refuses a second entry of a confirmed code (its
      // `inFlight` mark, never cleared). Cleared here, as a store or library
      // that kept no such mark would leave it, so a second interaction starts.
      const pendingCode = await dev.provider.DeviceCode.find(deviceCode, { ignoreExpiration: true });
      (pendingCode as unknown as { inFlight?: boolean }).inFlight = false;
      await pendingCode?.save();
      const b = await reviewer(userCode);
      // Two interactions, so two approval events: only the session claim stands
      // between them and two Missions.
      expect(b.uid).not.toBe(a.uid);
      const hold = holdFirstGrantSave();
      let first: Promise<{ status: number; text: string }> | undefined;
      let second: { status: number; text: string } | "blocked";
      try {
        first = deviceDecision(a);
        await hold.reached;
        second = await settleWhileHeld(deviceDecision(b));
      } finally {
        hold.restore();
      }
      const firstRes = await (first as Promise<{ status: number; text: string }>);
      expect(firstRes.status, firstRes.text).toBe(200);
      expect(firstRes.text).toContain("Mission approved");
      expect(second, JSON.stringify(second)).not.toBe("blocked");
      const loser = second as { status: number; text: string };
      expect(loser.status, loser.text).toBe(400);
      expect(JSON.parse(loser.text)).toEqual({
        error: "invalid_request",
        error_description: "the device authorization session is no longer pending",
      });
      const mission = deviceMissionOf(a.uid) as MissionRecord;
      expect(mission?.state).toBe("active");
      expect(deviceMissionOf(b.uid)).toBeUndefined();
      // The session is decided now: a later decision on the second interaction
      // is refused at the pending check and creates nothing.
      const late = await deviceDecision(b);
      expect(late.status).toBe(400);
      expect(deviceMissionOf(b.uid)).toBeUndefined();
      const stored = await dev.provider.DeviceCode.find(deviceCode, { ignoreExpiration: true });
      expect(stored?.grantId).toBe(mission.grant_id);
      const redeemed = await devicePoll(deviceCode);
      expect(redeemed.status, JSON.stringify(redeemed.body)).toBe(200);
      expect(redeemed.body.mission_id).toBe(mission.id);
      expect(dev.kernel.allMissions().filter((m) => m.grant_id === mission.grant_id)).toHaveLength(1);
    });

    it(`two tabs deciding one interaction while the first commits create one Mission; the second is refused while the session is claimed ${TAG}`, async () => {
      const { deviceCode, userCode } = await deviceAuthorize();
      const a = await reviewer(userCode);
      const hold = holdFirstGrantSave();
      let first: Promise<{ status: number; text: string }> | undefined;
      let second: { status: number; text: string } | "blocked";
      try {
        first = deviceDecision(a);
        await hold.reached;
        second = await settleWhileHeld(deviceDecision(a));
      } finally {
        hold.restore();
      }
      const firstRes = await (first as Promise<{ status: number; text: string }>);
      expect(firstRes.status, firstRes.text).toBe(200);
      expect(second, JSON.stringify(second)).not.toBe("blocked");
      const loser = second as { status: number; text: string };
      expect(loser.status, loser.text).toBe(400);
      expect(JSON.parse(loser.text).error_description).toBe("the device authorization session is no longer pending");
      expect(dev.kernel.allMissions().filter((m) => m.approval_event_id === `apev_${a.uid}`)).toHaveLength(1);
      expect((await devicePoll(deviceCode)).body.mission_id).toBe(deviceMissionOf(a.uid)?.id);
    });
  });

  describe(`distinct decisions, distinct approval events ${TAG}`, () => {
    it(`two device sessions, each approved, carry two different approval_event_id values the AS minted from their own interactions ${TAG}`, async () => {
      const decided: string[] = [];
      for (let i = 0; i < 2; i += 1) {
        const { userCode } = await deviceAuthorize();
        const r = await reviewer(userCode);
        const res = await deviceDecision(r);
        expect(res.status, res.text).toBe(200);
        decided.push(r.uid);
      }
      const [m1, m2] = decided.map((uid) => deviceMissionOf(uid) as MissionRecord);
      expect(m1?.approval_event_id).toBe(`apev_${decided[0]}`);
      expect(m2?.approval_event_id).toBe(`apev_${decided[1]}`);
      expect(m1?.approval_event_id).not.toBe(m2?.approval_event_id);
      expect(m1?.id).not.toBe(m2?.id);
    });
  });
});

// ===========================================================================
// Part C: the token endpoint of the assembly event-identity-boundary.test.ts uses.
// ===========================================================================

const PORT = 14947;
const ISSUER = `http://localhost:${PORT}`;
const RESOURCE = CANONICAL_RESOURCE;
const REDIRECT_URI = "http://localhost:9999/cb";
const FAR_EXP = "2027-01-01T00:00:00Z";
const PUBLISHED = progressiveFromProfile(PROGRESSIVE_PROFILE);
const READ_ACTIONS = new Set(["payments:invoice.list", "payments:invoice.read", "payments:vendor.read"]);
const READ = ["payments:invoice.read"];
const READ_LIST = ["payments:invoice.read", "payments:invoice.list"];

type DpopKeys = { privateKey: CryptoKey; publicKey: CryptoKey };
type Client = { id: string; kid: string; key: CryptoKey; dpop: DpopKeys };

let as: BuiltAs;
let server: Server | undefined;
let ap: Client;
let verifierSeq = 0;
const commits: LifecycleCommit[] = [];
const sessions = new ApprovalSessionStore();

const authority = (actions: string[]) => {
  const reads = actions.filter((a) => READ_ACTIONS.has(a));
  return reads.length ? [{ type: "mission_resource_access", resource: RESOURCE, actions: reads, constraints: { vendors: ["acme"] } }] : [];
};
const intentJson = (goal: string): string => JSON.stringify({ intent: { goal, target_resources: [RESOURCE], expires_at: FAR_EXP } });

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

/** PAR, approval, code, token: an ACTIVE Mission and its DPoP-bound access token. */
async function issueMission(actions: string[]): Promise<{ missionId: string; accessToken: string }> {
  const jar: Jar = new Map();
  const verifier = `event-gaps-verifier-0123456789-0123456789-${verifierSeq++}`;
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
      authorization_details: JSON.stringify(authority(actions)),
      client_assertion: await clientAssertion(ap),
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    }).toString(),
  });
  const parBody = (await par.json()) as { request_uri: string };
  expect(par.status, JSON.stringify(parBody)).toBe(201);
  let res = await fetch(`${ISSUER}/auth?${new URLSearchParams({ client_id: ap.id, request_uri: parBody.request_uri })}`, {
    redirect: "manual",
  });
  keep(jar, res);
  let location = res.headers.get("location") as string;
  const uid = location.split("/interaction/")[1] as string;
  const decideHeaders = floorApprovalHeaders(sessions, uid, cookieOf(jar));
  const render_revision = await renderedRevision(ISSUER, uid, decideHeaders);
  res = await fetch(`${ISSUER}/interaction/${uid}/decide`, {
    method: "POST",
    redirect: "manual",
    headers: { ...decideHeaders, "content-type": "application/json" },
    body: JSON.stringify({ decision: "approve", render_revision }),
  });
  keep(jar, res);
  location = res.headers.get("location") as string;
  while (location?.startsWith(ISSUER)) {
    res = await fetch(location, { redirect: "manual", headers: { cookie: cookieOf(jar) } });
    keep(jar, res);
    location = res.headers.get("location") as string;
  }
  const code = new URL(location).searchParams.get("code") as string;
  const tok = await tokenRequest({ grant_type: "authorization_code", code, redirect_uri: REDIRECT_URI, code_verifier: verifier, resource: RESOURCE });
  const body = (await tok.json()) as { access_token: string };
  expect(tok.status, JSON.stringify(body)).toBe(200);
  const claims = decodeJwt(body.access_token) as { mission: { id: string } };
  return { missionId: claims.mission.id, accessToken: body.access_token };
}

/** An expansion token exchange that opens a deferred fresh approval. */
const expansionParams = (subjectToken: string, crid: string, actions: string[]): Record<string, string> => ({
  grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
  subject_token: subjectToken,
  subject_token_type: ACCESS_TOKEN_TOKEN_TYPE,
  requested_token_type: ACCESS_TOKEN_TOKEN_TYPE,
  creation_request_id: crid,
  completion_mode: "deferred",
  mission_intent: intentJson("Widen the invoice work"),
  authorization_details: JSON.stringify(authority(actions)),
});

/** A child creation token exchange naming the shipped child actor. */
const childParams = (subjectToken: string, crid: string): Record<string, string> => ({
  grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
  subject_token: subjectToken,
  subject_token_type: ACCESS_TOKEN_TOKEN_TYPE,
  requested_token_type: JWT_TOKEN_TYPE,
  creation_request_id: crid,
  mission_intent: intentJson("Extract Acme invoices"),
  authorization_details: JSON.stringify(authority(READ)),
  child_actor: JSON.stringify({ sub: "subagent-extractor", sub_profile: "ai_agent" }),
});

type Body = { access_token?: string; mission_id?: string; error?: string; error_description?: string; deferral_code?: string };

async function send(params: Record<string, string>): Promise<{ status: number; body: Body }> {
  const res = await tokenRequest(params);
  return { status: res.status, body: (await res.json()) as Body };
}

/** The activating commits (creation events) published for a Mission. */
const activatingCommits = (missionId: string): LifecycleCommit[] =>
  commits.filter((c) => c.id === missionId && c.version === 1 && c.prior_state === undefined && c.state === "active");

/**
 * Hold the first access token save (made by a poll that has already committed
 * its successor) until `release`; later saves pass.
 */
function holdFirstAccessTokenSave() {
  const proto = as.provider.AccessToken.prototype as { save: (...args: unknown[]) => Promise<unknown> };
  const original = proto.save;
  const reached = latch();
  const gate = latch();
  let armed = true;
  const spy = vi.spyOn(proto, "save").mockImplementation(async function (this: unknown, ...args: unknown[]) {
    if (armed) {
      armed = false;
      reached.open();
      await gate.promise;
    }
    return original.apply(this, args);
  });
  return {
    reached: reached.promise,
    restore: () => {
      gate.open();
      spy.mockRestore();
    },
  };
}

describe(`token endpoint: the Expansion poll race and Child Delegation's event allocation ${TAG}`, () => {
  beforeAll(async () => {
    as = await buildAuthorizationServer({
      issuer: ISSUER,
      approvalSessions: sessions,
      activationPolicies: PUBLISHED.policies,
      actorProfiles: aiAgents("subagent-extractor"),
      onLifecycleCommit: (c) => commits.push(c),
      allowHeadlessAdjudication: true,
      serviceTokenPrincipals: TEST_APPROVAL_PRINCIPALS,
    });
    server = as.provider.listen(PORT);
    const key = (await importJWK(as.agentClientJwk as never, "ES256")) as CryptoKey;
    ap = { id: "ap-agent", kid: "ap-agent-auth", key, dpop: await generateKeyPair("ES256", { extractable: true }) };
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  afterAll(() => {
    server?.close();
  });

  it(`two polls completing one approved expansion deferral, the second arriving while the first is delivering, create one successor: the first is answered with it and the second is refused invalid_grant (single-use) ${TAG}`, async () => {
    const root = await issueMission(READ);
    const crid = crypto.randomUUID();
    const opened = await send(expansionParams(root.accessToken, crid, READ_LIST));
    expect(opened.status, JSON.stringify(opened.body)).toBe(400);
    expect(opened.body.error).toBe("authorization_pending");
    const code = opened.body.deferral_code as string;
    const event = `apev-${crypto.randomUUID()}`;
    expect(
      as.expansionDeferrals.approve(code, {
        approver: { iss: ISSUER, sub: "bob" },
        authentication: FIXTURE_BROWSER_LOGIN,
        approvalEventId: event,
        approvedUntil: FAR_EXP,
      }),
    ).toBe(true);
    const before = as.kernel.allMissions().length;
    const poll = () => send({ grant_type: DEFERRED_GRANT_TYPE, deferral_code: code });

    const hold = holdFirstAccessTokenSave();
    let first: Promise<{ status: number; body: Body }> | undefined;
    let second: { status: number; body: Body } | "blocked";
    try {
      first = poll();
      await hold.reached;
      second = await settleWhileHeld(poll());
    } finally {
      hold.restore();
    }
    const firstRes = await (first as Promise<{ status: number; body: Body }>);
    expect(firstRes.status, JSON.stringify(firstRes.body)).toBe(200);
    expect(second, JSON.stringify(second)).not.toBe("blocked");
    const loser = second as { status: number; body: Body };
    expect(loser.status, JSON.stringify(loser.body)).toBe(400);
    expect(loser.body.error).toBe("invalid_grant");
    // oidc-provider's InvalidGrant keeps its detail out of the response.
    expect(loser.body.error_description).toBe("grant request is invalid");
    expect(loser.body.access_token).toBeUndefined();

    const successorId = firstRes.body.mission_id as string;
    const successors = as.kernel.allMissions().filter((m) => m.predecessor === root.missionId);
    expect(successors.map((m) => m.id)).toEqual([successorId]);
    expect(as.kernel.get(successorId)?.approval_event_id).toBe(event);
    expect(as.kernel.allMissions().filter((m) => m.approval_event_id === event)).toHaveLength(1);
    expect(as.kernel.allMissions().length).toBe(before + 1);
    expect(activatingCommits(successorId)).toHaveLength(1);
    // Every later poll repeats the single-use refusal; the deferral stays redeemed, not refused.
    expect((await poll()).body.error).toBe("invalid_grant");
    expect(
      as.kernel.db.prepare("SELECT state, redeemed FROM expansion_deferrals WHERE deferral_code = ?").get(code),
    ).toEqual({ state: "approved", redeemed: 1 });
  });

  it(`two child creations under one parent with different creation_request_id values carry two different approval_event_id values the AS minted; a retry of either keeps its own ${TAG}`, async () => {
    const parent = await issueMission(READ);
    const crids = [crypto.randomUUID(), crypto.randomUUID()];
    const ids: string[] = [];
    for (const crid of crids) {
      const { status, body } = await send(childParams(parent.accessToken, crid));
      expect(status, JSON.stringify(body)).toBe(200);
      ids.push(body.mission_id as string);
    }
    const [c1, c2] = ids.map((id) => as.kernel.get(id) as MissionRecord);
    expect(c1?.id).not.toBe(c2?.id);
    expect(c1?.approval_event_id).toMatch(/^dlg_/);
    expect(c2?.approval_event_id).toMatch(/^dlg_/);
    expect(c1?.approval_event_id).not.toBe(c2?.approval_event_id);
    const retry = await send(childParams(parent.accessToken, crids[0] as string));
    expect(retry.body.mission_id).toBe(c1?.id);
    expect(as.kernel.get(retry.body.mission_id as string)?.approval_event_id).toBe(c1?.approval_event_id);
  });
});
