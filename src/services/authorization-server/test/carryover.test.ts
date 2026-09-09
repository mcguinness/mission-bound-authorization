/**
 * @spec draft-mcguinness-oauth-mission-child-delegation (#carryover,
 * #carryover-manifest, #carryover-cas, #carryover-generations,
 * #carryover-no-reset, #carryover-records, #carryover-commit,
 * #carryover-evidence), expansion (#deferred-window, #successor-expiry,
 * #superseded-state)
 *
 * Child Mission Carryover, driven through the REAL deferred-expansion
 * completion transaction: preparation reserves identifiers and renders the
 * manifest, the approval event commits it, and completion re-enumerates the
 * whole old subtree, compare-and-sets every committed input, creates the
 * replacements, terminates the old subtree and retains the authenticated map.
 *
 * Each test is a FOCUSED witness of one failure or one invariant. Where a
 * refusal is expected the assertions are always three-part: the completion
 * fails, nothing partial survives (no successor, no replacement, the old
 * subtree untouched), and the reason is the one the spec names.
 */

import { canonicalize, type JsonValue } from "@mission/core";
import { DERIVATION_POLICY, TOPOLOGY } from "@mission/demo-data";
import { withTransaction } from "@mission/store";
import { compactVerify, type CryptoKey, generateKeyPair, jwtVerify } from "jose";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { beforeAll, beforeEach, afterEach, describe, expect, it } from "vitest";
import {
  type AuthorityEntry,
  type CarryoverConfig,
  type CarryoverExclusionPolicy,
  type CarryoverExternalStateAdapter,
  type CarryoverManifest,
  CarryoverRetrievalError,
  CarryoverStore,
  applyCarryoverInCallerTx,
  carryoverManifestHash,
  commitCarryoverManifest,
  createChildMission,
  createExpansion,
  decodeCarryoverEvidence,
  ExpansionDeferralError,
  ExpansionDeferralStore,
  type LifecycleCommit,
  MissionKernel,
  type MissionRecord,
  prepareCarryover,
  validateMissionIntent,
} from "../src/index.js";
import { aiAgents } from "./actor-profiles.helper.js";
import { testAuthoritySourceCatalog } from "./authority-source.helper.js";

const ISS = "https://as.test";
const RESOURCE = DERIVATION_POLICY.ceiling[0].resource;
const LEDGER = TOPOLOGY.resources.saas;
const ACTORS = aiAgents("child-a", "child-b", "child-c", "grandchild-a", "other-agent");
const PRED_EXP = "2027-01-01T00:00:00Z";
const LATE_EXP = "2027-06-01T00:00:00Z";

const ALL_OR_NOTHING: CarryoverExclusionPolicy = { mode: "all_or_nothing" };
const DISCLOSED: CarryoverExclusionPolicy = {
  mode: "disclosed_exclusions",
  change_classes: ["state_changed", "record_missing", "unrendered_descendant", "fanout_occupancy_changed"],
  dependent_descendant_exclusion: true,
  unrendered_child_cascade: true,
};

const config = (over: Partial<CarryoverConfig> = {}): CarryoverConfig => ({
  enabled: true,
  maxRows: null,
  exclusionPolicy: ALL_OR_NOTHING,
  noApplicableExternalState: true,
  ...over,
});

/** A proposed entry restating the ceiling's Common Constraints. */
const proposed = (actions: string[]): AuthorityEntry[] => [
  {
    type: "mission_resource_access",
    resource: RESOURCE,
    actions,
    constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
  },
];

let key: CryptoKey;
let pubKey: CryptoKey;
let kernel: MissionKernel;
let commits: LifecycleCommit[];
let seq = 0;
let clock = new Date("2026-07-01T00:00:00Z");
let tmp: string | undefined;

const mkKernel = (over: { file?: string; onCommit?: (c: LifecycleCommit) => void } = {}): MissionKernel =>
  new MissionKernel({
    issuer: ISS,
    policy: DERIVATION_POLICY as never,
    authoritySourceCatalog: testAuthoritySourceCatalog(
      DERIVATION_POLICY.ceiling,
      ["parent-agent"],
      ["bob"],
    ),
    statusKey: key,
    statusKid: "as-status",
    now: () => clock,
    actorProfiles: ACTORS,
    ...(over.file ? { store: { file: over.file } } : {}),
    onLifecycleCommit: over.onCommit ?? ((c) => commits.push(c)),
  });

beforeAll(async () => {
  const pair = await generateKeyPair("ES256");
  key = pair.privateKey;
  pubKey = pair.publicKey;
});

beforeEach(() => {
  commits = [];
  clock = new Date("2026-07-01T00:00:00Z");
  kernel = mkKernel();
});

afterEach(() => {
  if (tmp) rmSync(tmp, { recursive: true, force: true });
  tmp = undefined;
});

const intentOf = (actions: string[], over: Record<string, unknown> = {}) =>
  validateMissionIntent(
    JSON.stringify({
      goal: "Pay Acme invoices",
      target_resources: [RESOURCE],
      expires_at: PRED_EXP,
      ...over,
    }),
  );

const approvePredecessor = (k: MissionKernel = kernel) =>
  k.approve({
    intent: intentOf(["payments:invoice.read"]),
    proposedAuthority: proposed(["payments:invoice.read", "payments:invoice.list"]),
    subject: { iss: ISS, sub: "alice" },
    approver: { iss: ISS, sub: "bob" },
    clientId: "parent-agent",
    approvalEventId: `apev-${seq++}`,
  });

const addChild = (
  parentId: string,
  actor: string,
  actions = ["payments:invoice.read"],
  k: MissionKernel = kernel,
) =>
  createChildMission(k, {
    parentId,
    intent: intentOf(actions),
    proposedAuthority: proposed(actions),
    childActor: { sub: actor, sub_profile: "ai_agent" },
  }).child;

/** The widened successor submission: the predecessor's actions plus the ledger. */
const widerIntent = (over: Record<string, unknown> = {}) =>
  validateMissionIntent(
    JSON.stringify({
      goal: "Pay Acme invoices and post the ledger",
      target_resources: [RESOURCE, LEDGER],
      expires_at: PRED_EXP,
      ...over,
    }),
  );

const widerProposal = (): AuthorityEntry[] => [
  ...proposed(["payments:invoice.read", "payments:invoice.list", "payments:vendor.read"]),
  { type: "mission_resource_access", resource: LEDGER, actions: ["ledger:vendor.read"], constraints: { vendors: ["acme"] } },
];

interface Run {
  store: ExpansionDeferralStore;
  code: string;
  approvalEventId: string;
}

/** Open and approve a deferred expansion carrying a prepared carryover plan. */
const openApproved = (
  predecessorId: string,
  over: {
    config?: CarryoverConfig;
    intent?: ReturnType<typeof widerIntent>;
    proposal?: AuthorityEntry[];
    store?: ExpansionDeferralStore;
  } = {},
): Run => {
  const store = over.store ?? new ExpansionDeferralStore(kernel, () => clock, over.config ?? config());
  const pending = store.open({
    predecessorId,
    intent: over.intent ?? widerIntent(),
    proposedAuthority: over.proposal ?? widerProposal(),
    clientId: "parent-agent",
    jkt: "jkt-test",
    creationRequestId: `crid-${seq++}`,
  });
  const approvalEventId = `xapev-${seq++}`;
  store.approve(pending.deferral_code, {
    approver: { iss: ISS, sub: "bob" },
    approvalEventId,
    approvedUntil: PRED_EXP,
  });
  return { store, code: pending.deferral_code, approvalEventId };
};

/** The committed manifest a run's deferral row holds. */
const manifestOf = (run: Run): CarryoverManifest =>
  JSON.parse(
    (
      run.store.db
        .prepare("SELECT carryover_manifest_json FROM expansion_deferrals WHERE deferral_code = ?")
        .get(run.code) as { carryover_manifest_json: string }
    ).carryover_manifest_json,
  ) as CarryoverManifest;

const redeem = (run: Run) => run.store.redeem(run.code);

describe("Child Mission Carryover (@spec child-delegation#carryover)", () => {
  it("carries an active leaf child under the successor with a fresh direct approval basis, the preserved budget and bare same-issuer correlation", () => {
    const pred = approvePredecessor();
    const child = addChild(pred.id, "child-a");
    const run = openApproved(pred.id);
    const manifest = manifestOf(run);
    const entry = manifest.entries.find((e) => e.child_id === child.id);
    expect(entry?.outcome).toBe("carry");
    // The proposed identifiers were RESERVED during preparation: the manifest
    // names them, and completion uses exactly those.
    const reservedSuccessor = manifest.successor.mission_id;
    const reservedReplacement = entry?.replacement?.replacement_id as string;
    expect(reservedSuccessor).toMatch(/^msn_/);
    expect(kernel.get(reservedSuccessor)).toBeUndefined();
    expect(kernel.get(reservedReplacement)).toBeUndefined();

    const out = redeem(run);
    expect("error" in out).toBe(false);
    if ("error" in out) return;
    expect(out.successor.id).toBe(reservedSuccessor);
    const replacement = kernel.get(reservedReplacement) as MissionRecord;
    expect(replacement).toBeDefined();
    // A FRESH record with a `direct` basis and its own child-specific approval
    // event; the old child's parent and approval anchors are untouched.
    expect(replacement.approval_basis.type).toBe("direct");
    expect(replacement.approval_basis.activation?.approval_event_id).toBe(
      entry?.replacement?.approval_event_id,
    );
    expect(replacement.approval_basis.root_commitment).toBe(replacement.authority_hash);
    expect(replacement.parent?.id).toBe(out.successor.id);
    expect(replacement.client_id).toBe(child.client_id);
    // Bare same-issuer correlation in both directions, granting nothing.
    expect(replacement.related_to).toBe(child.id);
    expect(typeof replacement.related_to).toBe("string");
    const oldChild = kernel.get(child.id) as MissionRecord;
    expect(oldChild.state).toBe("cascaded");
    expect(oldChild.carried_to).toBe(replacement.id);
    expect(oldChild.parent?.id).toBe(pred.id);
    expect(oldChild.approval_event_id).toBe(child.approval_event_id);
    // The derivation budget continues; it is not reset to a fresh counter.
    expect(replacement.derivation_limit).toBe(child.derivation_limit);
    expect(replacement.derivation_count).toBe(child.derivation_count);
  });

  it("cascades an uncovered child with a rendered reason and authenticates the complete map under the issuer's signing key", async () => {
    const pred = approvePredecessor();
    const covered = addChild(pred.id, "child-a", ["payments:invoice.read"]);
    const uncovered = addChild(pred.id, "child-b", ["payments:invoice.read", "payments:invoice.list"]);
    // The successor's own proposal reorders the predecessor's authority: it
    // widens onto the ledger but no longer restates `payments:invoice.list`, so
    // the second child is not a subset of its prospective parent's effective
    // set. The ordinary strict-subset proof, not a carryover-specific rule,
    // renders it a cascade.
    const run = openApproved(pred.id, {
      proposal: [
        ...proposed(["payments:invoice.read", "payments:vendor.read"]),
        {
          type: "mission_resource_access",
          resource: LEDGER,
          actions: ["ledger:vendor.read"],
          constraints: { vendors: ["acme"] },
        },
      ],
    });
    const manifest = manifestOf(run);
    expect(manifest.entries.find((e) => e.child_id === covered.id)?.outcome).toBe("carry");
    const uncoveredEntry = manifest.entries.find((e) => e.child_id === uncovered.id);
    expect(uncoveredEntry?.outcome).toBe("cascade");
    expect(uncoveredEntry?.reason).toBe("not_strict_subset");
    expect(uncoveredEntry?.replacement).toBeUndefined();
    const out = redeem(run);
    expect("error" in out).toBe(false);
    if ("error" in out) return;
    const result = run.store.carryoverResultFor(run.code);
    expect(result).toBeDefined();
    if (!result) return;
    // The authenticated Carryover Evidence really verifies under the issuer's
    // published key, and its payload is the complete map.
    const verified = await compactVerify(result.evidence_jws, pubKey);
    const evidence = JSON.parse(Buffer.from(verified.payload).toString("utf8")) as ReturnType<
      typeof decodeCarryoverEvidence
    >;
    expect(evidence.manifest_hash).toBe(result.manifest_hash);
    expect(evidence.map).toHaveLength(manifest.entries.length);
    for (const id of [covered.id, uncovered.id]) {
      expect(evidence.map.some((r) => r.old_child.mission_id === id)).toBe(true);
    }
    // The rendered cascade produced no replacement and no `carried_to`.
    expect((kernel.get(uncovered.id) as MissionRecord).carried_to).toBeUndefined();
    expect(kernel.findChildren(out.successor.id)).toHaveLength(1);
    expect(
      evidence.map.find((r) => r.old_child.mission_id === uncovered.id && r.outcome === "excluded"),
    ).toMatchObject({ reason: "not_strict_subset", terminal_state: "cascaded" });
    // The hash alone authenticates no approval: the retained manifest is the
    // approved object and its commitment recomputes over it.
    expect(carryoverManifestHash(ISS, result.manifest)).toBe(result.manifest_hash);
  });

  it("does not restore containment removed from the old child's effective set", () => {
    const pred = approvePredecessor();
    const child = addChild(pred.id, "child-a", ["payments:invoice.read", "payments:invoice.list"]);
    kernel.contain(child.id, {
      event: {
        type: "anomaly.detected",
        source: "svc:soc",
        observed_at: clock.toISOString(),
        event_id: "ev-contain-1",
      },
      remove: [{ resource: RESOURCE, actions: ["payments:invoice.list"] }],
    });
    const run = openApproved(pred.id);
    const out = redeem(run);
    expect("error" in out).toBe(false);
    if ("error" in out) return;
    const manifest = manifestOf(run);
    const replacementId = manifest.entries[0]?.replacement?.replacement_id as string;
    const replacement = kernel.get(replacementId) as MissionRecord;
    // The replacement's approved set is the RECHECKED EFFECTIVE set: the
    // contained action is gone, and no overlay reset restores it.
    const actions = replacement.authority_set.flatMap((e) => e.actions);
    expect(actions).toContain("payments:invoice.read");
    expect(actions).not.toContain("payments:invoice.list");
    expect(replacement.containment).toBeUndefined();
  });

  it("excludes a suspended child and never resumes it", () => {
    const pred = approvePredecessor();
    const suspended = addChild(pred.id, "child-a");
    const active = addChild(pred.id, "child-b");
    kernel.transition(suspended.id, "suspend");
    const run = openApproved(pred.id);
    const manifest = manifestOf(run);
    const suspendedEntry = manifest.entries.find((e) => e.child_id === suspended.id);
    expect(suspendedEntry?.outcome).toBe("cascade");
    expect(suspendedEntry?.reason).toBe("suspended_not_resumed");
    const out = redeem(run);
    expect("error" in out).toBe(false);
    if ("error" in out) return;
    // The suspended child is terminated, never restored to active, and gains no
    // `carried_to`; the active sibling carries.
    const after = kernel.get(suspended.id) as MissionRecord;
    expect(after.state).toBe("cascaded");
    expect(after.carried_to).toBeUndefined();
    const activeEntry = manifest.entries.find((e) => e.child_id === active.id);
    expect(activeEntry?.outcome).toBe("carry");
    expect((kernel.get(active.id) as MissionRecord).carried_to).toBe(
      activeEntry?.replacement?.replacement_id,
    );
  });

  it("carries a grandchild under its replacement parent, never the root successor", () => {
    const pred = approvePredecessor();
    const child = addChild(pred.id, "child-a");
    const grandchild = addChild(child.id, "grandchild-a");
    const run = openApproved(pred.id);
    const manifest = manifestOf(run);
    const childEntry = manifest.entries.find((e) => e.child_id === child.id);
    const grandEntry = manifest.entries.find((e) => e.child_id === grandchild.id);
    expect(childEntry?.outcome).toBe("carry");
    expect(grandEntry?.outcome).toBe("carry");
    // The deeper row's committed parent is its own replacement, not the successor.
    expect(grandEntry?.replacement?.parent.mission_id).toBe(
      childEntry?.replacement?.replacement_id,
    );
    const out = redeem(run);
    expect("error" in out).toBe(false);
    if ("error" in out) return;
    const newChild = kernel.get(childEntry?.replacement?.replacement_id as string) as MissionRecord;
    const newGrand = kernel.get(grandEntry?.replacement?.replacement_id as string) as MissionRecord;
    expect(newChild.parent?.id).toBe(out.successor.id);
    expect(newChild.parent?.depth).toBe(1);
    expect(newGrand.parent?.id).toBe(newChild.id);
    expect(newGrand.parent?.depth).toBe(2);
    // The whole old subtree is terminal, each with exactly one terminal commit.
    expect((kernel.get(child.id) as MissionRecord).state).toBe("cascaded");
    expect((kernel.get(grandchild.id) as MissionRecord).state).toBe("cascaded");
    expect(commits.filter((c) => c.id === grandchild.id && c.state === "cascaded")).toHaveLength(1);
  });

  it("excludes every dependent descendant of an excluded parent rather than attaching a replacement to a missing parent", () => {
    const pred = approvePredecessor();
    const child = addChild(pred.id, "child-a");
    const grandchild = addChild(child.id, "grandchild-a");
    // Suspend the intermediate BEFORE rendering: it is rendered as a cascade,
    // and its descendant must be rendered as a dependent exclusion.
    kernel.transition(child.id, "suspend");
    const run = openApproved(pred.id);
    const manifest = manifestOf(run);
    expect(manifest.entries.find((e) => e.child_id === child.id)?.reason).toBe(
      "suspended_not_resumed",
    );
    const grandEntry = manifest.entries.find((e) => e.child_id === grandchild.id);
    expect(grandEntry?.outcome).toBe("cascade");
    expect(grandEntry?.reason).toBe("dependent_parent_excluded");
    const out = redeem(run);
    expect("error" in out).toBe(false);
    if ("error" in out) return;
    expect(kernel.findChildren(out.successor.id)).toHaveLength(0);
    expect((kernel.get(grandchild.id) as MissionRecord).state).toBe("cascaded");
    expect((kernel.get(grandchild.id) as MissionRecord).carried_to).toBeUndefined();
  });

  it("recounts fan-out occupancy against the successor's own justifying entries as each carried generation is inserted", () => {
    const pred = approvePredecessor();
    const a = addChild(pred.id, "child-a");
    const b = addChild(pred.id, "child-b");
    const grand = addChild(a.id, "grandchild-a");
    const run = openApproved(pred.id);
    const manifest = manifestOf(run);
    expect(manifest.entries.filter((e) => e.outcome === "carry")).toHaveLength(3);
    // Rows are ordered by old `created_at`, then old identifier byte order: a
    // DISPLAY order, deliberately distinct from the generation order derivation
    // uses (the grandchild derives after its parent regardless of where it
    // sorts here).
    const display = [...manifest.entries].sort((x, y) =>
      x.created_at === y.created_at
        ? x.child_id < y.child_id
          ? -1
          : 1
        : x.created_at < y.created_at
          ? -1
          : 1,
    );
    expect(manifest.entries.map((e) => e.child_id)).toEqual(display.map((e) => e.child_id));
    const out = redeem(run);
    expect("error" in out).toBe(false);
    if ("error" in out) return;
    // Occupancy is counted in the SAME serialization domain: two direct
    // replacements under the successor, and the carried grandchild under its
    // own replacement parent, not under the successor.
    expect(kernel.findChildren(out.successor.id)).toHaveLength(2);
    const newA = kernel.get(
      manifest.entries.find((e) => e.child_id === a.id)?.replacement?.replacement_id as string,
    ) as MissionRecord;
    expect(kernel.findChildren(newA.id).map((c) => c.id)).toEqual([
      manifest.entries.find((e) => e.child_id === grand.id)?.replacement?.replacement_id,
    ]);
    // Each replacement records the fan-out it was admitted under.
    const evidence = out.carryover?.map.filter((r) => r.outcome === "carried");
    expect(evidence).toHaveLength(3);
    expect(kernel.findChildren(pred.id).every((c) => c.state === "cascaded")).toBe(true);
    void b;
  });

  it("refuses to extend a carried child under a successor whose approved extension outlives the predecessor", () => {
    const pred = approvePredecessor();
    const child = addChild(pred.id, "child-a");
    const store = new ExpansionDeferralStore(kernel, () => clock, config());
    const plan = prepareCarryover(kernel, store.carryover, {
      predecessorId: pred.id,
      successorIntent: widerIntent({ expires_at: LATE_EXP }),
      successorProposal: widerProposal(),
      config: config(),
    });
    expect(plan).toBeDefined();
    if (!plan) return;
    const approvalEventId = `xapev-${seq++}`;
    const committed = commitCarryoverManifest(plan, approvalEventId);
    const applied = withTransaction(kernel.db, () => {
      const res = createExpansion(kernel, {
        predecessorId: pred.id,
        intent: widerIntent({ expires_at: LATE_EXP }),
        proposedAuthority: widerProposal(),
        approver: { iss: ISS, sub: "bob" },
        approvalEventId,
        approvedUntil: LATE_EXP,
        // The disclosed, policy-permitted extension: the successor legitimately
        // outlives the predecessor.
        approvedExtensionUntil: LATE_EXP,
        successorId: committed.manifest.successor.mission_id,
      });
      return applyCarryoverInCallerTx(kernel, store.carryover, {
        planId: plan.plan_id,
        manifest: committed.manifest,
        manifestHash: committed.manifestHash,
        successor: res.successor,
        approver: { iss: ISS, sub: "bob" },
        expansionApprovalEventId: approvalEventId,
        directApproval: true,
        config: config(),
      });
    });
    const successor = kernel.get(committed.manifest.successor.mission_id) as MissionRecord;
    expect(Date.parse(successor.expires_at)).toBeGreaterThan(Date.parse(pred.expires_at));
    const replacement = applied.replacements[0] as MissionRecord;
    // The old child's own horizon binds: the successor's approved extension
    // does not reach the replacement.
    expect(replacement.expires_at).toBe(child.expires_at);
    expect(Date.parse(replacement.expires_at)).toBeLessThan(Date.parse(successor.expires_at));
  });

  it("refuses a completion whose manifest hash does not match the approved commitment, creating nothing", () => {
    const pred = approvePredecessor();
    const child = addChild(pred.id, "child-a");
    const run = openApproved(pred.id);
    // Tamper the committed hash: the manifest and its authenticated approval no
    // longer agree.
    run.store.db
      .prepare("UPDATE expansion_deferrals SET carryover_manifest_hash = ? WHERE deferral_code = ?")
      .run("sha-256:tampered", run.code);
    const out = redeem(run);
    expect(out).toEqual({ error: "access_denied" });
    expect(kernel.findChildren(pred.id).map((c) => c.state)).toEqual(["active"]);
    expect((kernel.get(child.id) as MissionRecord).carried_to).toBeUndefined();
    expect(kernel.get(pred.id)?.state).toBe("active");
    expect(commits.filter((c) => c.state === "cascaded")).toHaveLength(0);
  });

  it("refuses a batch whose derivation counter moved after rendering with no lifecycle version bump", () => {
    const pred = approvePredecessor();
    const child = addChild(pred.id, "child-a");
    const run = openApproved(pred.id);
    const manifest = manifestOf(run);
    const entry = manifest.entries.find((e) => e.child_id === child.id);
    expect(entry?.derivation_count).toBe(0);
    // A derivation consumes the counter WITHOUT incrementing `version`, which
    // is exactly why a state/version compare-and-set alone is insufficient.
    kernel.gateDerivation(child.id);
    const moved = kernel.get(child.id) as MissionRecord;
    expect(moved.derivation_count).toBe(1);
    expect(moved.version).toBe(entry?.version);
    const out = redeem(run);
    expect(out).toEqual({ error: "access_denied" });
    expect((kernel.get(child.id) as MissionRecord).state).toBe("active");
    expect(kernel.get(manifest.successor.mission_id)).toBeUndefined();
    expect(kernel.get(entry?.replacement?.replacement_id as string)).toBeUndefined();
  });

  it("refuses a batch whose fan-out occupancy moved after rendering", () => {
    const pred = approvePredecessor();
    const child = addChild(pred.id, "child-a");
    const run = openApproved(pred.id);
    const manifest = manifestOf(run);
    expect(manifest.entries.find((e) => e.child_id === child.id)?.child_occupancy).toBe(0);
    // A new occupant under a RENDERED row: its committed non-terminal child
    // occupancy no longer holds.
    addChild(child.id, "grandchild-a");
    const out = redeem(run);
    expect(out).toEqual({ error: "access_denied" });
    expect(kernel.get(manifest.successor.mission_id)).toBeUndefined();
    expect((kernel.get(child.id) as MissionRecord).state).toBe("active");
  });

  it("refuses a batch when a rendered child was terminated after approval rather than treating it as an acceptable exclusion", () => {
    const pred = approvePredecessor();
    const a = addChild(pred.id, "child-a");
    const b = addChild(pred.id, "child-b");
    const run = openApproved(pred.id);
    const manifest = manifestOf(run);
    kernel.transition(a.id, "revoke");
    const out = redeem(run);
    expect(out).toEqual({ error: "access_denied" });
    // Under all-or-nothing the disappearance of a rendered row requires a fresh
    // approval; the surviving sibling is NOT carried on its own.
    expect(kernel.get(manifest.successor.mission_id)).toBeUndefined();
    expect((kernel.get(b.id) as MissionRecord).state).toBe("active");
    expect((kernel.get(a.id) as MissionRecord).state).toBe("revoked");
  });

  it("refuses a batch when a grandchild was inserted after approval, so no unrendered descendant is silently carried", () => {
    const pred = approvePredecessor();
    const child = addChild(pred.id, "child-a");
    const run = openApproved(pred.id);
    const manifest = manifestOf(run);
    const inserted = addChild(child.id, "grandchild-a");
    expect(manifest.entries.some((e) => e.child_id === inserted.id)).toBe(false);
    const out = redeem(run);
    expect(out).toEqual({ error: "access_denied" });
    expect(kernel.get(manifest.successor.mission_id)).toBeUndefined();
    expect((kernel.get(inserted.id) as MissionRecord).state).toBe("active");
  });

  it("refuses an oversized plan at intake, before any approval event names it", () => {
    const pred = approvePredecessor();
    addChild(pred.id, "child-a");
    addChild(pred.id, "child-b");
    const store = new ExpansionDeferralStore(kernel, () => clock, config({ maxRows: 1 }));
    expect(() =>
      store.open({
        predecessorId: pred.id,
        intent: widerIntent(),
        proposedAuthority: widerProposal(),
        clientId: "parent-agent",
        jkt: "jkt-test",
        creationRequestId: `crid-${seq++}`,
      }),
    ).toThrow(ExpansionDeferralError);
    // Nothing was reserved and no deferral exists, so no approval can name it.
    expect(
      store.db.prepare("SELECT COUNT(*) AS n FROM expansion_deferrals").get() as { n: number },
    ).toEqual({ n: 0 });
  });

  it("reserves identifiers once and hands the same reservations back to an idempotent retry", () => {
    const pred = approvePredecessor();
    addChild(pred.id, "child-a");
    const store = new ExpansionDeferralStore(kernel, () => clock, config());
    const open = () =>
      store.open({
        predecessorId: pred.id,
        intent: widerIntent(),
        proposedAuthority: widerProposal(),
        clientId: "parent-agent",
        jkt: "jkt-test",
        creationRequestId: "crid-stable",
      });
    const first = open();
    const second = open();
    expect(second.deferral_code).toBe(first.deferral_code);
    const reservations = store.carryover.db
      .prepare("SELECT COUNT(*) AS n FROM carryover_reservations")
      .get() as { n: number };
    // One plan, two identifiers (the successor and the one replacement): the
    // retry re-minted nothing.
    expect(reservations.n).toBe(2);
  });

  it("holds a cancelled plan's reserved identifiers and never completes it", () => {
    const pred = approvePredecessor();
    addChild(pred.id, "child-a");
    const run = openApproved(pred.id);
    const manifest = manifestOf(run);
    run.store.deny(run.code);
    const states = run.store.carryover.db
      .prepare("SELECT state FROM carryover_reservations")
      .all() as Array<{ state: string }>;
    expect(states.every((r) => r.state === "cancelled")).toBe(true);
    expect(redeem(run)).toEqual({ error: "access_denied" });
    expect(kernel.get(manifest.successor.mission_id)).toBeUndefined();
  });
});

describe("Child Mission Carryover exclusion modes (@spec child-delegation#carryover-cas)", () => {
  it("excludes only a committed change class under disclosed exclusions and carries the rest", () => {
    const pred = approvePredecessor();
    const a = addChild(pred.id, "child-a");
    const b = addChild(pred.id, "child-b");
    const run = openApproved(pred.id, { config: config({ exclusionPolicy: DISCLOSED }) });
    const manifest = manifestOf(run);
    expect(manifest.exclusion_policy).toEqual(DISCLOSED);
    // `state_changed` IS a committed class for this plan.
    kernel.transition(a.id, "revoke");
    const out = redeem(run);
    expect("error" in out).toBe(false);
    if ("error" in out) return;
    const result = run.store.carryoverResultFor(run.code);
    expect(result).toBeDefined();
    if (!result) return;
    const rowA = result.map.find((r) => r.old_child.mission_id === a.id);
    const rowB = result.map.find((r) => r.old_child.mission_id === b.id);
    expect(rowA?.outcome).toBe("excluded");
    // An already-terminal excluded row keeps its OWN terminal state and is
    // never transitioned again to `cascaded`.
    expect(rowA && rowA.outcome === "excluded" ? rowA.terminal_state : undefined).toBe("revoked");
    expect((kernel.get(a.id) as MissionRecord).state).toBe("revoked");
    expect(commits.filter((c) => c.id === a.id && c.state === "cascaded")).toHaveLength(0);
    expect(rowB?.outcome).toBe("carried");
    expect((kernel.get(b.id) as MissionRecord).carried_to).toBe(
      rowB && rowB.outcome === "carried" ? rowB.replacement_id : undefined,
    );
  });

  it("refuses a change class the plan did not commit, even under disclosed exclusions", () => {
    const pred = approvePredecessor();
    const child = addChild(pred.id, "child-a");
    const run = openApproved(pred.id, { config: config({ exclusionPolicy: DISCLOSED }) });
    const manifest = manifestOf(run);
    // `derivation_consumed` is NOT among this plan's committed change classes.
    kernel.gateDerivation(child.id);
    const out = redeem(run);
    expect(out).toEqual({ error: "access_denied" });
    expect(kernel.get(manifest.successor.mission_id)).toBeUndefined();
    expect((kernel.get(child.id) as MissionRecord).state).toBe("active");
  });

  it("cascades an unrendered descendant under disclosed exclusions and lists it explicitly in the authenticated map", () => {
    const pred = approvePredecessor();
    const child = addChild(pred.id, "child-a");
    const run = openApproved(pred.id, { config: config({ exclusionPolicy: DISCLOSED }) });
    const inserted = addChild(child.id, "grandchild-a");
    const out = redeem(run);
    expect("error" in out).toBe(false);
    if ("error" in out) return;
    const result = run.store.carryoverResultFor(run.code);
    expect(result).toBeDefined();
    if (!result) return;
    const row = result.map.find((r) => r.old_child.mission_id === inserted.id);
    expect(row?.outcome).toBe("excluded");
    expect(row && row.outcome === "excluded" ? row.unrendered : undefined).toBe(true);
    // The new descendant cascades rather than being silently carried, and no
    // replacement was invented for it.
    expect((kernel.get(inserted.id) as MissionRecord).state).toBe("cascaded");
    expect((kernel.get(inserted.id) as MissionRecord).carried_to).toBeUndefined();
    expect(kernel.findChildren(out.successor.id)).toHaveLength(0);
  });

  it("terminates a live descendant hidden behind a terminal intermediate, leaving the post-supersession cascade nothing", () => {
    const pred = approvePredecessor();
    const child = addChild(pred.id, "child-a");
    const grandchild = addChild(child.id, "grandchild-a");
    const run = openApproved(pred.id, { config: config({ exclusionPolicy: DISCLOSED }) });
    // Fault injection: the intermediate goes terminal WITHOUT its cascade, the
    // one shape in which the state-guarded walker skips a live descendant.
    kernel.db.prepare("UPDATE missions SET state = 'revoked', version = version + 1 WHERE id = ?").run(child.id);
    expect((kernel.get(grandchild.id) as MissionRecord).state).toBe("active");
    const out = redeem(run);
    expect("error" in out).toBe(false);
    if ("error" in out) return;
    // The explicit traversal reached the hidden live descendant inside the
    // completion transaction: nothing is left non-terminal for a later walker.
    expect((kernel.get(grandchild.id) as MissionRecord).state).toBe("cascaded");
    expect((kernel.get(child.id) as MissionRecord).state).toBe("revoked");
    expect(kernel.descendantsOf(pred.id).every((d) => d.state !== "active")).toBe(true);
    const result = run.store.carryoverResultFor(run.code);
    expect(result?.map.map((r) => r.old_child.mission_id).sort()).toEqual(
      [child.id, grandchild.id].sort(),
    );
  });
});

describe("Child Mission Carryover budgets and external state (@spec child-delegation#carryover-no-reset)", () => {
  it("transfers the derivation budget verbatim across two expand-and-carry cycles", () => {
    const pred = approvePredecessor();
    const child = addChild(pred.id, "child-a");
    kernel.gateDerivation(child.id);
    const consumed = (kernel.get(child.id) as MissionRecord).derivation_count;
    expect(consumed).toBe(1);
    const first = openApproved(pred.id);
    const out1 = redeem(first);
    expect("error" in out1).toBe(false);
    if ("error" in out1) return;
    const gen1 = out1.carryover?.replacements[0] as MissionRecord;
    expect(gen1.derivation_count).toBe(consumed);
    // A second expansion over the successor carries the SAME remaining budget:
    // repeated expansion and carryover cannot replenish it.
    const second = openApproved(out1.successor.id);
    const out2 = redeem(second);
    expect("error" in out2).toBe(false);
    if ("error" in out2) return;
    const gen2 = out2.carryover?.replacements[0] as MissionRecord;
    expect(gen2.derivation_count).toBe(consumed);
    expect(gen2.derivation_limit).toBe(child.derivation_limit);
    expect(gen2.related_to).toBe(gen1.id);
  });

  it("renders a child ineligible when no external meter or latch can participate and the deployment declares none absent", () => {
    const pred = approvePredecessor();
    const child = addChild(pred.id, "child-a");
    const run = openApproved(pred.id, {
      config: config({ noApplicableExternalState: false }),
    });
    const manifest = manifestOf(run);
    const entry = manifest.entries.find((e) => e.child_id === child.id);
    // An absent adapter means NOT transferable: the ineligibility is rendered
    // and its reason disclosed BEFORE approval, never discovered at completion.
    expect(entry?.outcome).toBe("cascade");
    expect(entry?.reason).toBe("external_state_not_transferable");
    expect(entry?.external_state).toEqual({ transferable: false, declared_absent: false });
    const out = redeem(run);
    expect("error" in out).toBe(false);
    if ("error" in out) return;
    expect(kernel.findChildren(out.successor.id)).toHaveLength(0);
  });

  it("rolls the whole batch back when a transaction-participating external transfer fails", () => {
    const pred = approvePredecessor();
    const a = addChild(pred.id, "child-a");
    const b = addChild(pred.id, "child-b");
    let transfers = 0;
    const adapter: CarryoverExternalStateAdapter = {
      id: "meter-test",
      eligible: () => ({ transferable: true, declared_absent: false, adapter: "meter-test" }),
      transferInCallerTx: () => {
        transfers += 1;
        if (transfers === 2) throw new Error("external meter refused to participate");
      },
    };
    const run = openApproved(pred.id, {
      config: config({ noApplicableExternalState: false, externalState: adapter }),
    });
    const manifest = manifestOf(run);
    expect(manifest.entries.filter((e) => e.outcome === "carry")).toHaveLength(2);
    expect(() => redeem(run)).toThrow(/external meter refused/);
    // A failure AFTER the first replacement already existed leaves nothing: no
    // successor, no replacement, no cascade and no published event.
    expect(kernel.get(manifest.successor.mission_id)).toBeUndefined();
    for (const entry of manifest.entries) {
      expect(kernel.get(entry.replacement?.replacement_id as string)).toBeUndefined();
    }
    expect((kernel.get(a.id) as MissionRecord).state).toBe("active");
    expect((kernel.get(b.id) as MissionRecord).state).toBe("active");
    expect(commits.filter((c) => c.state === "cascaded")).toHaveLength(0);
    expect(kernel.get(pred.id)?.state).toBe("active");
  });
});

describe("Child Mission Carryover observation and retrieval (@spec child-delegation#carryover-evidence, #carryover-commit)", () => {
  it("pairs the signed Status projection and the signed lifecycle event on carried_to and omits it for an excluded child", async () => {
    const pred = approvePredecessor();
    const carried = addChild(pred.id, "child-a");
    const excludedChild = addChild(pred.id, "child-b");
    kernel.transition(excludedChild.id, "suspend");
    const run = openApproved(pred.id);
    const out = redeem(run);
    expect("error" in out).toBe(false);
    if ("error" in out) return;
    const replacementId = (kernel.get(carried.id) as MissionRecord).carried_to as string;
    expect(replacementId).toBeDefined();
    // The SIGNED Status response carries the committed replacement identifier
    // on the old child's `cascaded` state, and omits it for the excluded one.
    const jws = await kernel.signedStatus(carried.id, { requester: "svc-observer" });
    const { payload } = await jwtVerify(jws, pubKey, { issuer: ISS, currentDate: clock });
    const mission = payload.mission as Record<string, unknown>;
    expect(mission.state).toBe("cascaded");
    expect(mission.carried_to).toBe(replacementId);
    const excludedJws = await kernel.signedStatus(excludedChild.id, { requester: "svc-observer" });
    const excludedPayload = (await jwtVerify(excludedJws, pubKey, { issuer: ISS, currentDate: clock })).payload;
    expect((excludedPayload.mission as Record<string, unknown>).carried_to).toBeUndefined();
    // The lifecycle commit the Signals emitter builds its SET from carries the
    // same correlation, on the carried child only.
    const carriedCommit = commits.find((c) => c.id === carried.id && c.state === "cascaded");
    expect(carriedCommit?.carried_to).toBe(replacementId);
    const excludedCommit = commits.find((c) => c.id === excludedChild.id && c.state === "cascaded");
    expect(excludedCommit).toBeDefined();
    expect(excludedCommit?.carried_to).toBeUndefined();
    // Introspection projects the same correlation.
    const projected = kernel.introspectionProjection(kernel.get(carried.id) as MissionRecord, {
      disclose: new Set(["provenance"]),
    });
    expect(projected.carried_to).toBe(replacementId);
  });

  it("lets an out-of-order consumer that saw the cascade first resolve the replacement through the verified map", async () => {
    const pred = approvePredecessor();
    const child = addChild(pred.id, "child-a");
    const run = openApproved(pred.id);
    const out = redeem(run);
    expect("error" in out).toBe(false);
    if ("error" in out) return;
    // A consumer that received the cascade before any creation event MUST NOT
    // infer absence of a replacement: it resynchronizes through the retained,
    // authenticated map.
    const cascade = commits.find((c) => c.id === child.id && c.state === "cascaded");
    expect(cascade?.carried_to).toBeDefined();
    const result = run.store.carryoverResultFor(run.code);
    expect(result).toBeDefined();
    if (!result) return;
    const verified = await compactVerify(result.evidence_jws, pubKey);
    const evidence = JSON.parse(Buffer.from(verified.payload).toString("utf8")) as ReturnType<
      typeof decodeCarryoverEvidence
    >;
    const row = evidence.map.find((r) => r.old_child.mission_id === child.id);
    expect(row?.outcome).toBe("carried");
    if (!row || row.outcome !== "carried") return;
    expect(row.replacement_id).toBe(cascade?.carried_to);
    // The map, not `related_to`, is the normative record of replacement, and
    // the pairing is by issuer-qualified identity.
    expect(row.old_child.issuer).toBe(ISS);
    expect(kernel.get(row.replacement_id)?.related_to).toBe(child.id);
    expect(decodeCarryoverEvidence(result.evidence_jws).manifest_hash).toBe(result.manifest_hash);
  });

  it("retrieves a committed replacement result only for its own child actor and refuses another actor", () => {
    const pred = approvePredecessor();
    const child = addChild(pred.id, "child-a");
    const run = openApproved(pred.id);
    const out = redeem(run);
    expect("error" in out).toBe(false);
    if ("error" in out) return;
    const replacementId = (kernel.get(child.id) as MissionRecord).carried_to as string;
    const store = run.store.carryover;
    const retrieved = store.retrieve({ replacementId, actor: { sub: child.client_id } });
    expect(retrieved.replacement.id).toBe(replacementId);
    expect(retrieved.result.manifest_hash).toBe(run.store.carryoverResultFor(run.code)?.manifest_hash);
    // Repeated retrieval is idempotent: no duplicate replacement, no second
    // approval, the same committed result.
    const again = store.retrieve({ replacementId, actor: { sub: child.client_id } });
    expect(again.replacement.version).toBe(retrieved.replacement.version);
    expect(kernel.findChildren(out.successor.id)).toHaveLength(1);
    // The deterministic approval event identifier is NOT retrieval
    // authorization: a different authenticated actor is refused.
    expect(() => store.retrieve({ replacementId, actor: { sub: "other-agent" } })).toThrow(
      CarryoverRetrievalError,
    );
    try {
      store.retrieve({ replacementId, actor: { sub: "other-agent" } });
    } catch (e) {
      expect((e as CarryoverRetrievalError).code).toBe("unauthorized");
    }
  });

  it("keeps the old child's credential bound to the old record and never rebinds it to the replacement", () => {
    const pred = approvePredecessor();
    const child = addChild(pred.id, "child-a");
    const oldApprovalEvent = child.approval_event_id;
    const run = openApproved(pred.id);
    const out = redeem(run);
    expect("error" in out).toBe(false);
    if ("error" in out) return;
    const replacementId = (kernel.get(child.id) as MissionRecord).carried_to as string;
    // The old child's own identity still resolves to the OLD record, which is
    // terminal: no derivation continues under it.
    expect(kernel.findByApprovalEvent(oldApprovalEvent)?.id).toBe(child.id);
    expect(() => kernel.gateDerivation(child.id)).toThrow();
    expect(() => kernel.gateActive(child.id)).toThrow();
    // The replacement is reachable only through its OWN child-specific approval
    // event, and its client is its own actor.
    const replacement = kernel.get(replacementId) as MissionRecord;
    expect(replacement.approval_event_id).not.toBe(oldApprovalEvent);
    expect(kernel.findByApprovalEvent(replacement.approval_event_id)?.id).toBe(replacementId);
    expect(kernel.gateActive(replacementId).id).toBe(replacementId);
  });
});

describe("Child Mission Carryover durable recovery (@spec child-delegation#carryover-commit)", () => {
  it("redelivers every carried transition byte-identically after a crash between commit and publication", async () => {
    tmp = mkdtempSync(join(tmpdir(), "carryover-"));
    const file = join(tmp, "kernel.sqlite");
    // Boot 1: publication throws AFTER the completion transaction commits, so
    // the records, the map and the outbox rows are committed and unpublished.
    // The setup transitions publish normally; only the completion crashes.
    let crash = false;
    const failing = mkKernel({
      file,
      onCommit: () => {
        if (crash) throw new Error("subscriber unavailable");
      },
    });
    const pred = approvePredecessor(failing);
    const child = addChild(pred.id, "child-a", ["payments:invoice.read"], failing);
    const store = new ExpansionDeferralStore(failing, () => clock, config());
    const pending = store.open({
      predecessorId: pred.id,
      intent: widerIntent(),
      proposedAuthority: widerProposal(),
      clientId: "parent-agent",
      jkt: "jkt-test",
      creationRequestId: `crid-${seq++}`,
    });
    const approvalEventId = `xapev-${seq++}`;
    store.approve(pending.deferral_code, {
      approver: { iss: ISS, sub: "bob" },
      approvalEventId,
      approvedUntil: PRED_EXP,
    });
    const manifest = JSON.parse(
      (
        store.db
          .prepare("SELECT carryover_manifest_json FROM expansion_deferrals WHERE deferral_code = ?")
          .get(pending.deferral_code) as { carryover_manifest_json: string }
      ).carryover_manifest_json,
    ) as CarryoverManifest;
    crash = true;
    expect(() => store.redeem(pending.deferral_code)).toThrow(/subscriber unavailable/);
    // The batch COMMITTED: the replacement exists, the old child is carried and
    // the map is durably retained.
    const replacementId = manifest.entries[0]?.replacement?.replacement_id as string;
    expect(failing.get(replacementId)).toBeDefined();
    expect((failing.get(child.id) as MissionRecord).carried_to).toBe(replacementId);
    const committedResult = store.carryover.result(manifest.entries[0] ? (
      store.db.prepare("SELECT carryover_plan_id FROM expansion_deferrals WHERE deferral_code = ?")
        .get(pending.deferral_code) as { carryover_plan_id: string }
    ).carryover_plan_id : "");
    expect(committedResult?.map).toHaveLength(1);

    // Boot 2: the same file, a recording subscriber, boot recovery.
    const delivered: LifecycleCommit[] = [];
    const recovered = mkKernel({ file, onCommit: (c) => delivered.push(c) });
    await recovered.recoverAtBoot();
    const carriedEvent = delivered.find((c) => c.id === child.id && c.state === "cascaded");
    expect(carriedEvent).toBeDefined();
    // Redelivery is the SAME event: the identity, the commit instant and the
    // carried correlation are the committed payload, never rebuilt from state.
    expect(carriedEvent?.carried_to).toBe(replacementId);
    expect(carriedEvent?.event_id).toBeDefined();
    const again: LifecycleCommit[] = [];
    const third = mkKernel({ file, onCommit: (c) => again.push(c) });
    await third.recoverAtBoot();
    expect(again.filter((c) => c.id === child.id && c.state === "cascaded")).toHaveLength(0);
    // The authenticated result survives the restart and is read back, never
    // recomputed.
    const reopened = new CarryoverStore(third, () => clock);
    const persisted = reopened.result(committedResult?.plan_id as string);
    expect(persisted?.evidence_jws).toBe(committedResult?.evidence_jws);
    expect(canonicalize(persisted?.map as unknown as JsonValue)).toBe(
      canonicalize(committedResult?.map as unknown as JsonValue),
    );
  });
});
