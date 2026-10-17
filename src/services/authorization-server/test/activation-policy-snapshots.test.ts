import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ACTIVATION_POLICY_TYP, type ActivationPolicyRef, activationPolicyDigest } from "@mission/core";
import { DERIVATION_POLICY } from "@mission/demo-data";
import { withTransaction } from "@mission/store";
import { type CryptoKey, generateKeyPair } from "jose";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import {
  type ActivationPolicyRegistry,
  type AuthorityEntry,
  ChildDelegationError,
  createChildMission,
  createTemplate,
  DispatchError,
  dispatchFromTemplate,
  type DispatchPolicies,
  MissionKernel,
  type MissionRecord,
  type RegisteredActivationPolicy,
  TemplateStore,
  validateMissionIntent,
} from "../src/index.js";
import {
  ActivationPolicyRetentionError,
  type RetainedActivationPolicySnapshot,
} from "../src/kernel/activation-policy-snapshots.js";
import { DEFAULT_AUDIT_RETENTION_S } from "../src/kernel/tombstones.js";
import { aiAgents } from "./actor-profiles.helper.js";
import { testAuthoritySourceCatalog } from "./authority-source.helper.js";

/**
 * @spec mission#standing-consent-bases, mission#mission-record: activation
 * policy snapshot retention. Every successful Template Dispatch and
 * policy-adjudicated child creation retains the exact snapshot its gate
 * verified, keyed by (issuer, policy id, version, digest), for the audit
 * horizon of the Mission it activated. The current registry alone decides
 * eligibility; the retained snapshots are audit evidence only.
 */

const ISS = "https://as.test";
const T0 = Date.parse("2026-07-01T00:00:00Z");
let clockMs = T0;
const now = () => new Date(clockMs);
const AUDIT_MS = DEFAULT_AUDIT_RETENTION_S * 1000;

let key: CryptoKey;
let seq = 0;
const dirs: string[] = [];

beforeAll(async () => {
  key = (await generateKeyPair("ES256")).privateKey;
});

beforeEach(() => {
  clockMs = T0;
});

afterAll(() => {
  for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
});

const storeFile = (): string => {
  const dir = mkdtempSync(join(tmpdir(), "mission-985-"));
  dirs.push(dir);
  return join(dir, "kernel.db");
};

const snapshot = (version: string, rule: string): RegisteredActivationPolicy => ({
  version,
  content_type: "application/json",
  content: JSON.stringify({ rule }),
});

const utf8 = (bytes: Uint8Array) => Buffer.from(bytes).toString("utf8");

/** The retained row for a committed reference, or undefined. */
const retained = (kernel: MissionKernel, ref: ActivationPolicyRef): RetainedActivationPolicySnapshot | undefined =>
  kernel.activationPolicySnapshots.resolve({ issuer: ISS, ...ref });

const horizonOf = (mission: MissionRecord) => new Date(Date.parse(mission.expires_at) + AUDIT_MS).toISOString();

const countRows = (kernel: MissionKernel) =>
  (kernel.db.prepare("SELECT COUNT(*) AS n FROM activation_policy_snapshots").get() as { n: number }).n;

// ---------------------------------------------------------------- Template --

const DISPATCH_POLICY_ID = "urn:policy:dispatch";
const RESOURCE = DERIVATION_POLICY.ceiling[0].resource;

const ceilEntry = (): AuthorityEntry => ({
  type: "mission_resource_access",
  resource: RESOURCE,
  actions: ["payments:invoice.read", "payments:vendor.read"],
  constraints: { max_amount: { amount: "200.00", currency: "USD" }, vendors: ["acme"] },
});

const templateKernel = () =>
  new MissionKernel({
    issuer: ISS,
    policy: DERIVATION_POLICY as never,
    authoritySourceCatalog: testAuthoritySourceCatalog(DERIVATION_POLICY.ceiling, ["worker", "orchestrator"], ["human-approver"]),
    statusKey: key,
    statusKid: "as-status",
    now,
  });

const consent = (kernel: MissionKernel, store: TemplateStore, registry: DispatchPolicies, version = "1") =>
  createTemplate(
    store,
    {
      template_version: "tmpl-v1",
      issuer: ISS,
      approver: { iss: ISS, sub: "human-approver" },
      ceiling: [ceilEntry()],
      dispatch_policy: { id: DISPATCH_POLICY_ID, version },
      dispatchers: ["orchestrator"],
      recipients: { subjects: [{ iss: ISS, sub: "alice" }], agents: ["worker"] },
      per_instance_lifetime_s: 3600,
      max_active: 50,
      rate_per_min: 50,
      review_cadence_s: 30 * 86400,
      approval_event_id: `tmpl-ev-${seq++}`,
      expires_at: "2026-12-01T00:00:00Z",
    } as never,
    { ...kernel.authoritySourceOptions(), dispatchPolicies: registry },
  );

const dispatch = (
  kernel: MissionKernel,
  store: TemplateStore,
  templateId: string,
  registry: DispatchPolicies,
  dispatchEventId = `dsp-${seq++}`,
) =>
  dispatchFromTemplate(kernel, store, {
    templateId,
    dispatchEventId,
    dispatcher: "orchestrator",
    intent: kernel.validateIntent(
      JSON.stringify({ goal: "reconcile Acme", target_resources: [RESOURCE], expires_at: "2027-01-01T00:00:00Z" }),
    ),
    subject: { iss: ISS, sub: "alice" },
    policyVersion: DERIVATION_POLICY.policy_version,
    dispatchPolicies: registry,
  }).mission;

const refusedWith = (fn: () => unknown, reason: string) => {
  try {
    fn();
    expect.unreachable();
  } catch (e) {
    expect((e as DispatchError | ChildDelegationError).reason).toBe(reason);
  }
};

describe("activation policy snapshot retention: Template Dispatch (@spec mission#standing-consent-bases)", () => {
  it("retains the verified Dispatch Policy snapshot under (issuer, id, version, digest) with its exact bytes and media type, and the instance's committed digest recomputes from it", () => {
    const kernel = templateKernel();
    const store = new TemplateStore(now);
    const v1 = snapshot("1", "dispatch within the template ceiling");
    const registry: DispatchPolicies = { [DISPATCH_POLICY_ID]: v1 };
    const t = consent(kernel, store, registry);
    const mission = dispatch(kernel, store, t.id, registry);
    const ref = mission.template?.dispatch_policy as ActivationPolicyRef;

    const row = retained(kernel, ref) as RetainedActivationPolicySnapshot;
    expect(row).toMatchObject({ issuer: ISS, id: DISPATCH_POLICY_ID, version: "1", digest: ref.digest });
    // The digest's envelope context and exact input are on the row.
    expect(row.typ).toBe(ACTIVATION_POLICY_TYP);
    expect(row.content_type).toBe("application/json");
    expect(utf8(row.content)).toBe(v1.content);
    // An auditor recomputes the committed digest from the row alone.
    expect(activationPolicyDigest(row.issuer, { content_type: row.content_type, content: row.content })).toBe(ref.digest);
    expect(kernel.verifyActivationPolicyCommitment(mission)).toMatchObject({ status: "verified", ref });
    // Retained for this instance's audit horizon: its expiry plus the declared audit retention.
    expect(row.retain_until).toBe(horizonOf(mission));
    expect(row.first_activated_at).toBe(mission.created_at);
    expect(row.activations).toBe(1);
  });

  it("a later activation under the same snapshot extends its horizon, and no write shrinks the horizon or rewrites the bytes", () => {
    const kernel = templateKernel();
    const store = new TemplateStore(now);
    const v1 = snapshot("1", "dispatch within the template ceiling");
    const registry: DispatchPolicies = { [DISPATCH_POLICY_ID]: v1 };
    const t = consent(kernel, store, registry);
    const first = dispatch(kernel, store, t.id, registry);
    clockMs = T0 + 86_400_000;
    const second = dispatch(kernel, store, t.id, registry);
    const ref = first.template?.dispatch_policy as ActivationPolicyRef;
    expect(second.template?.dispatch_policy).toEqual(ref);

    const row = retained(kernel, ref) as RetainedActivationPolicySnapshot;
    expect(row.retain_until).toBe(horizonOf(second));
    expect(Date.parse(row.retain_until)).toBeGreaterThan(Date.parse(horizonOf(first)));
    expect(row.activations).toBe(2);
    expect(row.first_activated_at).toBe(first.created_at);
    expect(countRows(kernel)).toBe(1);

    // A retention write carrying an earlier expiry leaves the horizon where it is.
    withTransaction(kernel.db, () =>
      kernel.activationPolicySnapshots.retainInCallerTx(
        { issuer: ISS, created_at: first.created_at, expires_at: first.expires_at },
        { ref, snapshot: v1 },
      ),
    );
    const after = retained(kernel, ref) as RetainedActivationPolicySnapshot;
    expect(after.retain_until).toBe(horizonOf(second));
    expect(utf8(after.content)).toBe(v1.content);
    // Outside an activation's transaction, nothing is retained.
    expect(() =>
      kernel.activationPolicySnapshots.retainInCallerTx(
        { issuer: ISS, created_at: first.created_at, expires_at: first.expires_at },
        { ref, snapshot: v1 },
      ),
    ).toThrow(/inside its activation's transaction/);
  });

  it("replacement under a new version: the old instance's digest recomputes from its retained snapshot after the registry moves on, and both snapshots are retained", () => {
    const kernel = templateKernel();
    const store = new TemplateStore(now);
    const v1 = snapshot("1", "dispatch within the template ceiling");
    const v2 = snapshot("2", "dispatch only on weekdays");
    const before: DispatchPolicies = { [DISPATCH_POLICY_ID]: v1 };
    const old = dispatch(kernel, store, consent(kernel, store, before).id, before);
    const oldTemplateId = old.template?.id as string;

    // The deployment replaces the policy with version 2; a new template consents to it.
    const replaced: DispatchPolicies = { [DISPATCH_POLICY_ID]: v2 };
    const fresh = dispatch(kernel, store, consent(kernel, store, replaced, "2").id, replaced);
    // The old template's policy is no longer current: it activates nothing.
    const missions = kernel.allMissions().length;
    refusedWith(() => dispatch(kernel, store, oldTemplateId, replaced), "dispatch_policy_changed");
    expect(kernel.allMissions().length).toBe(missions);

    const oldCheck = kernel.verifyActivationPolicyCommitment(kernel.get(old.id) as MissionRecord);
    expect(oldCheck.status).toBe("verified");
    expect(utf8((oldCheck as { snapshot: RetainedActivationPolicySnapshot }).snapshot.content)).toBe(v1.content);
    const freshCheck = kernel.verifyActivationPolicyCommitment(kernel.get(fresh.id) as MissionRecord);
    expect(freshCheck.status).toBe("verified");
    expect(utf8((freshCheck as { snapshot: RetainedActivationPolicySnapshot }).snapshot.content)).toBe(v2.content);
    expect(old.template?.dispatch_policy.digest).not.toBe(fresh.template?.dispatch_policy.digest);
    expect(countRows(kernel)).toBe(2);
  });

  it("changed bytes under the same version: the Dispatch is refused, nothing is retained for the edited bytes, and the committed bytes are never overwritten", () => {
    const kernel = templateKernel();
    const store = new TemplateStore(now);
    const v1 = snapshot("1", "dispatch within the template ceiling");
    const registry: DispatchPolicies = { [DISPATCH_POLICY_ID]: v1 };
    const t = consent(kernel, store, registry);
    const mission = dispatch(kernel, store, t.id, registry);
    const ref = mission.template?.dispatch_policy as ActivationPolicyRef;

    const edited = snapshot("1", "dispatch at any hour");
    const missions = kernel.allMissions().length;
    refusedWith(() => dispatch(kernel, store, t.id, { [DISPATCH_POLICY_ID]: edited }), "dispatch_policy_changed");
    expect(kernel.allMissions().length).toBe(missions);
    expect(retained(kernel, { ...ref, digest: activationPolicyDigest(ISS, edited) })).toBeUndefined();

    // Bytes that do not reproduce the committed digest are refused, never written behind it.
    expect(() =>
      withTransaction(kernel.db, () =>
        kernel.activationPolicySnapshots.retainInCallerTx(
          { issuer: ISS, created_at: mission.created_at, expires_at: mission.expires_at },
          { ref, snapshot: edited },
        ),
      ),
    ).toThrow(ActivationPolicyRetentionError);
    const row = retained(kernel, ref) as RetainedActivationPolicySnapshot;
    expect(utf8(row.content)).toBe(v1.content);
    expect(row.activations).toBe(1);
    expect(countRows(kernel)).toBe(1);
    expect(kernel.verifyActivationPolicyCommitment(mission).status).toBe("verified");
  });

  it("retirement: a retained snapshot never re-admits a retired Dispatch Policy, and retiring it erases no evidence before the audit horizon", () => {
    const kernel = templateKernel();
    const store = new TemplateStore(now);
    const v1 = snapshot("1", "dispatch within the template ceiling");
    const registry: DispatchPolicies = { [DISPATCH_POLICY_ID]: v1 };
    const t = consent(kernel, store, registry);
    const mission = dispatch(kernel, store, t.id, registry);
    const ref = mission.template?.dispatch_policy as ActivationPolicyRef;

    // Retired: the registry no longer holds the policy, though the exact snapshot is retained.
    expect(retained(kernel, ref)).toBeDefined();
    const missions = kernel.allMissions().length;
    refusedWith(() => dispatch(kernel, store, t.id, {}), "dispatch_policy_changed");
    expect(kernel.allMissions().length).toBe(missions);
    expect(store.dispatchesSince(t.id, "1970-01-01T00:00:00.000Z")).toBe(1);
    expect(kernel.verifyActivationPolicyCommitment(mission).status).toBe("verified");

    // Kept through the horizon, deleted only once it has passed.
    const horizon = Date.parse(horizonOf(mission));
    clockMs = horizon;
    expect(kernel.activationPolicySnapshots.pruneExpired()).toBe(0);
    expect(kernel.verifyActivationPolicyCommitment(mission).status).toBe("verified");
    clockMs = horizon + 1;
    expect(kernel.activationPolicySnapshots.pruneExpired()).toBe(1);
    expect(kernel.verifyActivationPolicyCommitment(mission)).toEqual({ status: "unavailable", ref });
  });

  it("an unretained commitment verifies as unavailable, a tampered row as a mismatch, and a Mission that commits no activation policy as not_applicable", () => {
    const kernel = templateKernel();
    const store = new TemplateStore(now);
    const v1 = snapshot("1", "dispatch within the template ceiling");
    const registry: DispatchPolicies = { [DISPATCH_POLICY_ID]: v1 };
    const mission = dispatch(kernel, store, consent(kernel, store, registry).id, registry);
    const ref = mission.template?.dispatch_policy as ActivationPolicyRef;

    // A commitment no activation retained a snapshot for.
    const unretainedRef = { ...ref, digest: activationPolicyDigest(ISS, snapshot("1", "never activated")) };
    const unretained = { ...mission, template: { ...(mission.template as NonNullable<MissionRecord["template"]>), dispatch_policy: unretainedRef } };
    expect(kernel.verifyActivationPolicyCommitment(unretained)).toEqual({ status: "unavailable", ref: unretainedRef });

    // A retained row whose bytes no longer reproduce its digest fails the recompute.
    kernel.db
      .prepare("UPDATE activation_policy_snapshots SET content = ? WHERE digest = ?")
      .run(Buffer.from('{"rule":"tampered"}', "utf8"), ref.digest);
    expect(kernel.verifyActivationPolicyCommitment(mission).status).toBe("mismatch");

    const direct = kernel.approve({
      intent: kernel.validateIntent(
        JSON.stringify({ goal: "reconcile Acme", target_resources: [RESOURCE], expires_at: "2027-01-01T00:00:00Z" }),
      ),
      subject: { iss: ISS, sub: "alice" },
      approver: { iss: ISS, sub: "human-approver" },
      clientId: "worker",
      approvalEventId: `apev-${seq++}`,
    });
    expect(kernel.verifyActivationPolicyCommitment(direct)).toEqual({ status: "not_applicable" });
  });

  it("a Dispatch whose snapshot cannot be retained commits no instance, no dispatch row and no reservation", () => {
    const kernel = templateKernel();
    const store = new TemplateStore(now);
    const v1 = snapshot("1", "dispatch within the template ceiling");
    const registry: DispatchPolicies = { [DISPATCH_POLICY_ID]: v1 };
    const t = consent(kernel, store, registry);
    const missions = kernel.allMissions().length;
    const spy = vi.spyOn(kernel.activationPolicySnapshots, "retainInCallerTx").mockImplementation(() => {
      throw new ActivationPolicyRetentionError("snapshot store unavailable");
    });
    expect(() => dispatch(kernel, store, t.id, registry, "dsp-retain-fails")).toThrow(ActivationPolicyRetentionError);
    expect(kernel.allMissions().length).toBe(missions);
    expect(store.dispatchesSince(t.id, "1970-01-01T00:00:00.000Z")).toBe(0);
    expect(countRows(kernel)).toBe(0);
    spy.mockRestore();
    // The reservation rolled back with it: the same dispatch_event_id now activates.
    const mission = dispatch(kernel, store, t.id, registry, "dsp-retain-fails");
    expect(kernel.verifyActivationPolicyCommitment(mission).status).toBe("verified");
  });
});

// ------------------------------------------------------------------- Child --

const R1 = "https://basis.example/mcp";
const R2 = "https://basis-two.example/mcp";
const CHILD_POLICY_ID = "urn:policy:child-drawdown";
const SECOND_POLICY_ID = "urn:policy:child-drawdown-two";
const PARENT_EXP = "2027-01-01T00:00:00Z";
const CHILD_V1 = snapshot("1", "one child per invoice");
const SECOND_V1 = snapshot("1", "one child per ledger");

const childRef = (id: string, held: RegisteredActivationPolicy): ActivationPolicyRef => ({
  id,
  version: held.version,
  digest: activationPolicyDigest(ISS, held),
});

const childEntry = (resource: string, ref: ActivationPolicyRef) => ({
  type: "mission_resource_access",
  resource,
  actions: ["res.read"],
  delegation: {
    max_depth: 1,
    children: { max_children: 50, child_creation_policy: ref, allowed_child_actors: [{ sub_profile: "ai_agent" }] },
  },
});

/** A kernel whose ceiling's two entries each commit their own child creation policy. */
const childKernel = (registry: ActivationPolicyRegistry, store?: { file: string }) => {
  const policy = {
    policy_version: "basis-policy",
    ceiling: [childEntry(R1, childRef(CHILD_POLICY_ID, CHILD_V1)), childEntry(R2, childRef(SECOND_POLICY_ID, SECOND_V1))],
  };
  return new MissionKernel({
    issuer: ISS,
    policy: policy as never,
    authoritySourceCatalog: testAuthoritySourceCatalog(policy.ceiling, ["parent-agent"], ["bob"]),
    statusKey: key,
    statusKid: "as-status",
    now,
    actorProfiles: aiAgents("basis-child"),
    activationPolicies: registry,
    ...(store ? { store } : {}),
  });
};

const approveParent = (kernel: MissionKernel) =>
  kernel.approve({
    intent: validateMissionIntent(JSON.stringify({ goal: "root", target_resources: [R1, R2], expires_at: PARENT_EXP })),
    subject: { iss: ISS, sub: "alice" },
    approver: { iss: ISS, sub: "bob" },
    clientId: "parent-agent",
    approvalEventId: `apev-${seq++}`,
  });

const createChild = (kernel: MissionKernel, parentId: string) =>
  createChildMission(kernel, {
    parentId,
    intent: validateMissionIntent(JSON.stringify({ goal: "sub", target_resources: [R1, R2], expires_at: PARENT_EXP })),
    childActor: { sub: "basis-child", sub_profile: "ai_agent" },
  }).child;

describe("activation policy snapshot retention: Child Delegation (@spec mission#standing-consent-bases)", () => {
  it("retains every justifying child_creation_policy snapshot, and the child's root_commitment recomputes from it after the policy is replaced, edited or retired", () => {
    const registry: Record<string, RegisteredActivationPolicy> = { [CHILD_POLICY_ID]: CHILD_V1, [SECOND_POLICY_ID]: SECOND_V1 };
    const kernel = childKernel(registry);
    const parent = approveParent(kernel);
    const child = createChild(kernel, parent.id);
    const primary = childRef(CHILD_POLICY_ID, CHILD_V1);
    expect(child.approval_basis.root_commitment).toBe(primary.digest);

    // Both policies adjudicated the creation; both snapshots are retained, each with exact bytes.
    const first = retained(kernel, primary) as RetainedActivationPolicySnapshot;
    const second = retained(kernel, childRef(SECOND_POLICY_ID, SECOND_V1)) as RetainedActivationPolicySnapshot;
    expect(utf8(first.content)).toBe(CHILD_V1.content);
    expect(utf8(second.content)).toBe(SECOND_V1.content);
    expect(first.retain_until).toBe(horizonOf(child));
    expect(second.retain_until).toBe(horizonOf(child));
    expect(kernel.verifyActivationPolicyCommitment(child)).toMatchObject({ status: "verified", ref: primary });

    const missions = kernel.allMissions().length;
    const changes: Array<RegisteredActivationPolicy | undefined> = [
      snapshot("2", "two children per invoice"),
      snapshot("1", "any number of children"),
      undefined,
    ];
    for (const held of changes) {
      if (held) registry[CHILD_POLICY_ID] = held;
      else delete registry[CHILD_POLICY_ID];
      refusedWith(() => createChild(kernel, parent.id), "policy_denied");
      expect(kernel.allMissions().length).toBe(missions);
      if (held) expect(retained(kernel, childRef(CHILD_POLICY_ID, held))).toBeUndefined();
      // The registry change rewrites no evidence: the old child still verifies.
      const check = kernel.verifyActivationPolicyCommitment(kernel.get(child.id) as MissionRecord);
      expect(check.status).toBe("verified");
      expect(utf8((check as { snapshot: RetainedActivationPolicySnapshot }).snapshot.content)).toBe(CHILD_V1.content);
    }
    expect(countRows(kernel)).toBe(2);
  });

  it("a child creation whose snapshot cannot be retained commits no child", () => {
    const registry = { [CHILD_POLICY_ID]: CHILD_V1, [SECOND_POLICY_ID]: SECOND_V1 };
    const kernel = childKernel(registry);
    const parent = approveParent(kernel);
    const missions = kernel.allMissions().length;
    const spy = vi.spyOn(kernel.activationPolicySnapshots, "retainInCallerTx").mockImplementation(() => {
      throw new ActivationPolicyRetentionError("snapshot store unavailable");
    });
    expect(() => createChild(kernel, parent.id)).toThrow(ActivationPolicyRetentionError);
    expect(kernel.allMissions().length).toBe(missions);
    spy.mockRestore();
    expect(countRows(kernel)).toBe(0);
  });

  it("retained snapshots survive a restart on the file-backed kernel store and are pruned at boot only past their audit horizon", async () => {
    const file = storeFile();
    const first = childKernel({ [CHILD_POLICY_ID]: CHILD_V1, [SECOND_POLICY_ID]: SECOND_V1 }, { file });
    const parent = approveParent(first);
    const child = createChild(first, parent.id);
    first.db.close();

    // The deployment restarts with the policy retired: the evidence is still there.
    const afterRestart = childKernel({ [SECOND_POLICY_ID]: SECOND_V1 }, { file });
    try {
      await afterRestart.recoverAtBoot();
      const record = afterRestart.get(child.id) as MissionRecord;
      const check = afterRestart.verifyActivationPolicyCommitment(record);
      expect(check.status).toBe("verified");
      expect(utf8((check as { snapshot: RetainedActivationPolicySnapshot }).snapshot.content)).toBe(CHILD_V1.content);
      refusedWith(() => createChild(afterRestart, parent.id), "policy_denied");
    } finally {
      afterRestart.db.close();
    }

    // A boot past the horizon prunes it, and only then.
    clockMs = Date.parse(horizonOf(child)) + 1;
    const pastHorizon = childKernel({}, { file });
    try {
      expect(countRows(pastHorizon)).toBe(2);
      await pastHorizon.recoverAtBoot();
      expect(countRows(pastHorizon)).toBe(0);
      expect(pastHorizon.verifyActivationPolicyCommitment(pastHorizon.get(child.id) as MissionRecord).status).toBe(
        "unavailable",
      );
    } finally {
      pastHorizon.db.close();
    }
  });
});
