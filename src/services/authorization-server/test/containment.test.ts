/**
 * Mission Containment: the issuer-held, versioned, MONOTONIC narrowing overlay
 * on an active Mission's effective authority. Covered here:
 *   - monotonic union of contained entries + event_id idempotency (a repeat
 *     returns the current record: no version bump, no extra event row);
 *   - the metadata-only commit (version n+1, prior_state === state) rides the
 *     existing lifecycle-commit fan-out: the Status List republishes with the
 *     bit unchanged for an active Mission;
 *   - authority_hash is byte-identical before/after while signedStatus omits
 *     the contained entry and carries containment_version; introspectionMission
 *     carries it only when containment exists (absent-means-none);
 *   - derivation draws on the EFFECTIVE set: a mint after containment omits the
 *     contained capability; a fully contained Mission refuses with GateError
 *     authority_contained;
 *   - the delegation surfaces are bound to the effective set: child creation
 *     (not_strict_subset), the cross-domain audience-scoped grant, and the
 *     attenuation root mapping all exclude contained capability;
 *   - terminal-state contain refused (409 on the wire); suspended permitted;
 *   - the lifecycle endpoint's operation: "contain" end-to-end via the dev
 *     service token;
 *   - (#572) `authority_changed` on the emitted commit reflects an actual
 *     narrowing of the EFFECTIVE set, not merely a fresh event_id reaching
 *     the metadata-only commit path: both a repeat-narrowing event and a
 *     rule naming a never-held capability leave it absent.
 */

import { type Server } from "node:http";
import { CANONICAL_RESOURCE, CONTAINMENT_POLICY, DEV_SERVICE_TOKEN } from "@mission/demo-data";
import { decodeJwt, generateKeyPair, jwtVerify } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  type AuthorityEntry,
  type BuiltAs,
  buildAuthorizationServer,
  ChildDelegationError,
  CONTAINMENT_EVIDENCE_MEDIA_TYPE,
  containmentEvidenceBytes,
  type ContainmentPolicy,
  createChildMission,
  deriveAttenuationRoot,
  GateError,
  issueCrossDomainGrant,
  type LifecycleCommit,
  LifecycleConflictError,
  MissionKernel,
  mintChildGrant,
  readStatusBit,
  STATUS_VALID,
  StatusListPublisher,
  statusListUri,
  UnknownProtectedEventError,
  validateMissionIntent,
  verifyStatusListToken,
} from "../src/index.js";
import { aiAgents } from "./actor-profiles.helper.js";
import { testAuthoritySourceCatalog } from "./authority-source.helper.js";

const ISS = "https://as.containment.test";
const RES_PAY = "https://payments.test/mcp";
const RES_FILE = "https://files.test/mcp";
const NOW = new Date("2026-08-06T12:00:00Z");
const EXPIRES_AT = "2027-01-01T00:00:00Z";

/** RES_PAY is delegable (child-creation on-switch); RES_FILE is plain. */
const POLICY = {
  policy_version: "containment-v1",
  ceiling: [
    {
      type: "mission_resource_access",
      resource: RES_PAY,
      actions: ["payments:invoice.read", "payments:payment.execute"],
      delegation: {
        max_depth: 2,
        // Explicit child-actor eligibility (fail-closed matcher): this suite's
        // children are AS-asserted ai_agents (see makeHarness actorProfiles).
        children: { max_children: 5, max_child_depth: 2, allowed_child_actors: [{ sub_profile: "ai_agent" }] },
      },
    },
    { type: "mission_resource_access", resource: RES_FILE, actions: ["files:doc.read"] },
  ],
};

const intent = (over: Record<string, unknown> = {}) =>
  validateMissionIntent(
    JSON.stringify({
      goal: "Pay Acme invoices for Q3",
      target_resources: [RES_PAY, RES_FILE],
      expires_at: EXPIRES_AT,
      ...over,
    }),
  );

const ev = (id: string) => ({
  type: "anomaly.detected",
  source: "svc:soc",
  observed_at: NOW.toISOString(),
  event_id: id,
});

let statusKeys: { privateKey: CryptoKey; publicKey: CryptoKey };

interface Harness {
  kernel: MissionKernel;
  commits: LifecycleCommit[];
  publisher: StatusListPublisher;
  dirtyMarks: () => number;
}

function makeHarness(containmentPolicy?: ContainmentPolicy): Harness {
  const commits: LifecycleCommit[] = [];
  let marks = 0;
  let publisher: StatusListPublisher | undefined;
  const kernel = new MissionKernel({
    issuer: ISS,
    policy: POLICY as never,
    authoritySourceCatalog: testAuthoritySourceCatalog(POLICY.ceiling, ["ap-agent"], ["bob"]),
    ...(containmentPolicy ? { containmentPolicy } : {}),
    actorProfiles: aiAgents(
      "child-agent",
      "grandchild-agent",
      "subagent",
      "subagent-a",
      "subagent-b",
      "subagent-both",
      "subagent-exec",
      "subagent-pay-only",
      "subagent-term",
    ),
    statusKey: statusKeys.privateKey,
    statusKid: "as-status",
    now: () => NOW,
    onLifecycleCommit: (c) => {
      commits.push(c);
      marks++;
      publisher?.markDirty();
    },
  });
  publisher = new StatusListPublisher(() => kernel.publishStatusList());
  return { kernel, commits, publisher, dirtyMarks: () => marks };
}

let seq = 0;
const approve = (kernel: MissionKernel, over: Record<string, unknown> = {}) =>
  kernel.approve({
    intent: intent(over),
    subject: { iss: ISS, sub: "alice" },
    approver: { iss: ISS, sub: "bob" },
    clientId: "ap-agent",
    approvalEventId: `apev-cnt-${++seq}`,
  });

beforeAll(async () => {
  statusKeys = await generateKeyPair("ES256", { extractable: true });
});

describe("contain(): monotonic union + event_id idempotency", () => {
  it("unions removals across events; a repeated event_id is a no-op", () => {
    const { kernel } = makeHarness();
    const m = approve(kernel);
    expect(m.containment).toBeUndefined(); // a fresh mission has none

    const r1 = kernel.contain(m.id, {
      event: ev("evt-1"),
      remove: [{ resource: RES_PAY, actions: ["payments:payment.execute"] }],
    });
    expect(r1.record.version).toBe(2);
    expect(r1.record.containment?.containment_version).toBe(1);
    expect(r1.record.containment?.contained).toEqual([
      { resource: RES_PAY, actions: ["payments:payment.execute"] },
    ]);
    expect(r1.record.containment?.events).toHaveLength(1);
    expect(r1.evidence).toMatchObject({
      mission: { id: m.id, issuer: ISS, authority_hash: m.authority_hash },
      // The manual break-glass contain() path passes no policyRule, so the
      // evidence policy is "manual" (was the derivation policy_version before
      // the issuer-held ContainmentPolicy landed; the doc comment was fixed too).
      policy: "manual",
      prior_version: 1,
      new_version: 2,
      prior_containment_version: 0,
      new_containment_version: 1,
      removed: [{ resource: RES_PAY, actions: ["payments:payment.execute"] }],
    });
    // Evidence conventions: JCS canonical bytes round-trip; the media type.
    expect(JSON.parse(containmentEvidenceBytes(r1.evidence))).toEqual(
      JSON.parse(JSON.stringify(r1.evidence)),
    );
    expect(CONTAINMENT_EVIDENCE_MEDIA_TYPE).toBe("application/mission-containment-evidence+json");

    // Second event: per-action union on RES_PAY plus a whole-resource removal.
    const r2 = kernel.contain(m.id, {
      event: ev("evt-2"),
      remove: [{ resource: RES_PAY, actions: ["payments:invoice.read"] }, { resource: RES_FILE }],
    });
    expect(r2.record.version).toBe(3);
    expect(r2.record.containment?.containment_version).toBe(2);
    const contained = r2.record.containment?.contained ?? [];
    expect(contained.find((c) => c.resource === RES_PAY)?.actions?.sort()).toEqual([
      "payments:invoice.read",
      "payments:payment.execute",
    ]);
    expect(contained.find((c) => c.resource === RES_FILE)).toEqual({ resource: RES_FILE });
    expect(r2.record.containment?.events).toHaveLength(2);

    // Idempotent repeat of evt-1: current record, no version bump, no event row.
    const r3 = kernel.contain(m.id, { event: ev("evt-1"), remove: [{ resource: RES_FILE }] });
    expect(r3.record.version).toBe(3);
    expect(r3.record.containment?.containment_version).toBe(2);
    expect(r3.record.containment?.events).toHaveLength(2);
    expect(r3.evidence.prior_version).toBe(r3.evidence.new_version);
    expect(r3.evidence.prior_containment_version).toBe(r3.evidence.new_containment_version);
  });
});

describe("contain(): authority_changed reflects actual narrowing, not merely a fresh event (#572)", () => {
  it("a FRESH event_id whose removal is already fully represented in the contained set still commits (version/containment_version bump) but omits authority_changed", () => {
    // Distinct from event_id idempotency above: evt-dup-b is a NEW event_id
    // (not a repeat of evt-dup-a), so contain()'s idempotency check does not
    // short-circuit it. It still reaches the metadata-only commit, but the
    // EFFECTIVE set is unchanged, so the emitted signal must not claim a
    // narrowing that did not happen.
    const { kernel, commits } = makeHarness();
    const m = approve(kernel);

    kernel.contain(m.id, {
      event: ev("evt-dup-a"),
      remove: [{ resource: RES_PAY, actions: ["payments:payment.execute"] }],
    });
    expect(commits.at(-1)?.authority_changed).toBe(true); // the genuine narrowing

    const r2 = kernel.contain(m.id, {
      event: ev("evt-dup-b"),
      remove: [{ resource: RES_PAY, actions: ["payments:payment.execute"] }],
    });
    expect(r2.record.version).toBe(3); // NOT a no-op: a real version bump
    expect(r2.record.containment?.containment_version).toBe(2);
    expect(r2.record.containment?.events).toHaveLength(2); // a new event row
    expect(commits.at(-1)?.authority_changed).toBeUndefined();
  });
});

describe("the metadata-only commit rides the lifecycle fan-out", () => {
  it("emits version n+1 with prior_state === state and republishes the Status List (bit unchanged)", async () => {
    const { kernel, commits, publisher, dirtyMarks } = makeHarness();
    const m = approve(kernel);
    const idx = kernel.participateInStatusList(m.id);
    await publisher.current(); // publish once, clearing the dirty flag
    const marksBefore = dirtyMarks();

    kernel.contain(m.id, {
      event: ev("evt-commit"),
      remove: [{ resource: RES_PAY, actions: ["payments:payment.execute"] }],
    });

    const last = commits.at(-1);
    expect(last).toMatchObject({
      id: m.id,
      issuer: ISS,
      state: "active",
      prior_state: "active",
      version: 2,
      expires_at: EXPIRES_AT,
      // @spec containment#propagation — the metadata-only commit carries the
      // new containment_version, so an active-to-active narrowing is legible
      // to a subscriber comparing only `state`.
      containment_version: 1,
    });
    // The commit marked the publisher dirty: the next fetch is a regeneration.
    expect(dirtyMarks()).toBe(marksBefore + 1);
    const tok = await verifyStatusListToken(await publisher.current(), statusKeys.publicKey, {
      uri: statusListUri(ISS),
      now: NOW,
    });
    // Containment does not change lifecycle state: the bit stays VALID.
    expect(readStatusBit(tok, idx)).toBe(STATUS_VALID);
  });

  it("surfaces the changed containment_version across a contained-then-still-active sequence", () => {
    // The activating commit precedes any containment: containment_version is
    // absent (absent-means-none), not 0, mirroring introspectionMission.
    const { kernel, commits } = makeHarness();
    const m = approve(kernel);
    expect(commits.at(-1)).toMatchObject({ state: "active", version: 1 });
    expect(commits.at(-1)?.containment_version).toBeUndefined();

    // First contain: state stays active (metadata-only), containment_version
    // moves 0 -> 1 on the emitted commit.
    kernel.contain(m.id, {
      event: ev("evt-seq-1"),
      remove: [{ resource: RES_FILE }],
    });
    const afterFirst = commits.at(-1);
    expect(afterFirst).toMatchObject({ state: "active", prior_state: "active" });
    expect(afterFirst?.containment_version).toBe(1);

    // Second contain: state is STILL active (prior_state === state again), so
    // a consumer watching `state` alone sees no change between these two
    // commits -- but containment_version moved 1 -> 2, which is exactly the
    // authorization-change signal a version-gap-only consumer would miss on a
    // sequential (non-gapped) delivery.
    kernel.contain(m.id, {
      event: ev("evt-seq-2"),
      remove: [{ resource: RES_PAY, actions: ["payments:payment.execute"] }],
    });
    const afterSecond = commits.at(-1);
    expect(afterSecond).toMatchObject({ state: "active", prior_state: "active" });
    expect(afterSecond?.containment_version).toBe(2);
    expect(afterSecond?.containment_version).not.toBe(afterFirst?.containment_version);
  });
});

describe("authority_hash immutability + projections", () => {
  it("keeps authority_hash byte-identical while signedStatus omits the contained entry and carries containment_version", async () => {
    const { kernel } = makeHarness();
    const m = approve(kernel);
    const hashBefore = m.authority_hash;

    kernel.contain(m.id, { event: ev("evt-hash"), remove: [{ resource: RES_FILE }] });
    const fresh = kernel.get(m.id) as NonNullable<ReturnType<MissionKernel["get"]>>;
    expect(fresh.authority_hash).toBe(hashBefore); // immutable approval anchor

    // The contained entry is omitted from the audience-scoped Status surface.
    const jwsFile = await kernel.signedStatus(m.id, { audience: RES_FILE, requester: "svc:test" });
    const { payload: pFile } = await jwtVerify(jwsFile, statusKeys.publicKey, {
      issuer: ISS,
      audience: RES_FILE,
      currentDate: NOW,
    });
    expect(pFile.authorization_details).toEqual([]);
    expect((pFile.mission as { containment_version?: number }).containment_version).toBe(1);
    expect((pFile.mission as { authority_hash: string }).authority_hash).toBe(hashBefore);

    // An uncontained resource still projects, minus nothing.
    const jwsPay = await kernel.signedStatus(m.id, { audience: RES_PAY, requester: "svc:test" });
    const { payload: pPay } = await jwtVerify(jwsPay, statusKeys.publicKey, {
      issuer: ISS,
      audience: RES_PAY,
      currentDate: NOW,
    });
    expect((pPay.authorization_details as AuthorityEntry[])).toHaveLength(1);

    // Introspection carries containment_version; absent means none.
    expect(kernel.introspectionMission(fresh).containment_version).toBe(1);
    const m2 = approve(kernel);
    expect("containment_version" in kernel.introspectionMission(m2)).toBe(false);
  });
});

describe("derivation over the effective set", () => {
  it("a mint after containment omits the contained capability from authorization_details", async () => {
    const { kernel } = makeHarness();
    const parent = approve(kernel);
    const { child } = createChildMission(kernel, {
      parentId: parent.id,
      intent: intent({ target_resources: [RES_PAY] }),
      childActor: { sub: "subagent", sub_profile: "ai_agent" },
    });
    kernel.contain(child.id, {
      event: ev("evt-child-mint"),
      remove: [{ resource: RES_PAY, actions: ["payments:payment.execute"] }],
    });
    const contained = kernel.get(child.id) as NonNullable<ReturnType<MissionKernel["get"]>>;
    const { assertion } = await mintChildGrant(
      kernel,
      { key: statusKeys.privateKey, kid: "as-status", alg: "ES256" },
      { child: contained, tokenEndpoint: `${ISS}/token` },
    );
    const details = decodeJwt(assertion).authorization_details as AuthorityEntry[];
    expect(details).toHaveLength(1);
    expect(details[0]?.resource).toBe(RES_PAY);
    expect(details[0]?.actions).toEqual(["payments:invoice.read"]);
    // @spec mission#the-mission-claim (#702) — the assertion's `mission`
    // claim carries only the baseline {id, issuer} plus the child-delegation
    // profile's own `parent` lineage member, never `authority_hash`; the
    // child's authority commitment (over its APPROVED, not effective, set)
    // stays record-resident and is unaffected by containment.
    expect(Object.keys(decodeJwt(assertion).mission as object).sort()).toEqual(["id", "issuer", "parent"]);
    expect(contained.authority_hash).toBeTruthy();
  });

  it("a fully contained mission refuses derivation with GateError authority_contained", () => {
    const { kernel } = makeHarness();
    const m = approve(kernel);
    kernel.contain(m.id, {
      event: ev("evt-full"),
      remove: [{ resource: RES_PAY }, { resource: RES_FILE }],
    });
    expect(kernel.effectiveAuthoritySet(kernel.get(m.id) as never)).toEqual([]);
    try {
      kernel.gateDerivation(m.id);
      expect.unreachable("gateDerivation must refuse a fully contained mission");
    } catch (e) {
      expect(e).toBeInstanceOf(GateError);
      expect((e as GateError).reason).toBe("authority_contained");
    }
  });
});

describe("delegation surfaces bound to the effective set", () => {
  it("refuses a child whose intent needs the contained capability (not_strict_subset)", () => {
    const { kernel } = makeHarness();
    const parent = approve(kernel);
    kernel.contain(parent.id, {
      event: ev("evt-deleg"),
      remove: [{ resource: RES_PAY, actions: ["payments:payment.execute"] }],
    });
    try {
      createChildMission(kernel, {
        parentId: parent.id,
        intent: intent({
          target_resources: [RES_PAY],
        }),
        proposedAuthority: [
          {
            type: "mission_resource_access",
            resource: RES_PAY,
            actions: ["payments:payment.execute"],
          },
        ],
        childActor: { sub: "subagent", sub_profile: "ai_agent" },
      });
      expect.unreachable("child needing the contained capability must be refused");
    } catch (e) {
      expect(e).toBeInstanceOf(ChildDelegationError);
      expect((e as ChildDelegationError).reason).toBe("not_strict_subset");
    }
    // A child within the effective set is still creatable.
    const { child } = createChildMission(kernel, {
      parentId: parent.id,
      intent: intent({
        target_resources: [RES_PAY],
      }),
      proposedAuthority: [
        { type: "mission_resource_access", resource: RES_PAY, actions: ["payments:invoice.read"] },
      ],
      childActor: { sub: "subagent", sub_profile: "ai_agent" },
    });
    expect(child.authority_set[0]?.actions).toEqual(["payments:invoice.read"]);
  });

  it("excludes contained capability from the cross-domain audience-scoped set and the attenuation root", async () => {
    const { kernel } = makeHarness();
    const m = approve(kernel);
    kernel.contain(m.id, {
      event: ev("evt-surfaces"),
      remove: [{ resource: RES_PAY, actions: ["payments:payment.execute"] }, { resource: RES_FILE }],
    });

    const { audienceScoped } = await issueCrossDomainGrant(kernel, statusKeys.privateKey, "as-status", {
      missionId: m.id,
      targetAs: ISS,
      clientId: "ap-agent",
      cnfJkt: "test-jkt",
      resourceToAs: () => ISS,
    });
    expect(audienceScoped).toHaveLength(1);
    expect(audienceScoped[0]?.resource).toBe(RES_PAY);
    expect(audienceScoped[0]?.actions).toEqual(["payments:invoice.read"]);

    const { tools } = await deriveAttenuationRoot(kernel, statusKeys.privateKey, "as-status", {
      missionId: m.id,
      aud: RES_PAY,
      clientId: "ap-agent",
      cnfJkt: "test-jkt",
      delMaxDepth: 0,
    });
    expect(Object.keys(tools)).toEqual([`${RES_PAY}#payments:invoice.read`]);
  });
});

describe("containment propagates entry-wise to existing children (@spec child-delegation#child-state, issue #412)", () => {
  it("a contained parent entry narrows a justified child's effective set; a non-contained action and the parent's own state are unaffected", () => {
    const { kernel, commits } = makeHarness();
    const parent = approve(kernel);

    // childBoth draws on BOTH RES_PAY actions: proves the removal is ENTRY-WISE
    // (only payment.execute drops), not a wholesale wipe of the child.
    const { child: childBoth } = createChildMission(kernel, {
      parentId: parent.id,
      intent: intent({
        target_resources: [RES_PAY],
      }),
      proposedAuthority: [
        {
          type: "mission_resource_access",
          resource: RES_PAY,
          actions: ["payments:invoice.read", "payments:payment.execute"],
        },
      ],
      childActor: { sub: "subagent-both", sub_profile: "ai_agent" },
    });
    const commitsBefore = commits.length;

    const { record: parentAfter } = kernel.contain(parent.id, {
      event: ev("evt-cascade-1"),
      remove: [{ resource: RES_PAY, actions: ["payments:payment.execute"] }],
    });

    // The parent itself only narrows; its lifecycle state is untouched.
    expect(parentAfter.state).toBe("active");

    const childAfter = kernel.get(childBoth.id) as NonNullable<ReturnType<MissionKernel["get"]>>;
    // Propagated: same version bump / containment shape contain() always produces.
    expect(childAfter.version).toBe(2);
    expect(childAfter.containment?.containment_version).toBe(1);
    expect(childAfter.containment?.contained).toEqual([
      { resource: RES_PAY, actions: ["payments:payment.execute"] },
    ]);
    // Entry-wise: invoice.read (never removed from the parent) survives.
    const childEffective = kernel.effectiveAuthoritySet(childAfter);
    expect(childEffective).toHaveLength(1);
    expect(childEffective[0]?.resource).toBe(RES_PAY);
    expect(childEffective[0]?.actions).toEqual(["payments:invoice.read"]);
    // The child's own approved authority_set (and hash) is untouched; only the
    // overlay narrows.
    expect(childAfter.authority_hash).toBe(childBoth.authority_hash);

    // The propagation committed on the CHILD too (metadata-only: prior_state ===
    // state), so Status List / Signals subscribers see it, exactly like the
    // parent's own contain() commit.
    const childCommit = commits.slice(commitsBefore).find((c) => c.id === childBoth.id);
    expect(childCommit).toMatchObject({ id: childBoth.id, state: "active", prior_state: "active", version: 2 });

    // The child can no longer derive the contained capability: a further child
    // (grandchild) needing payment.execute is refused not_strict_subset because
    // the ceiling is now the child's EFFECTIVE (not approved) set.
    try {
      createChildMission(kernel, {
        parentId: childBoth.id,
        intent: intent({
          target_resources: [RES_PAY],
        }),
        proposedAuthority: [
          { type: "mission_resource_access", resource: RES_PAY, actions: ["payments:payment.execute"] },
        ],
        childActor: { sub: "grandchild-agent", sub_profile: "ai_agent" },
      });
      expect.unreachable("a grandchild must not re-derive contained authority");
    } catch (e) {
      expect(e).toBeInstanceOf(ChildDelegationError);
      expect((e as ChildDelegationError).reason).toBe("not_strict_subset");
    }
  });

  it("leaves a same-family child untouched (no overlay, no version bump) when the containment names a DIFFERENT resource entirely", () => {
    const { kernel } = makeHarness();
    const parent = approve(kernel); // holds both RES_PAY and RES_FILE
    // childPay holds ONLY the RES_PAY entry; it draws nothing from RES_FILE.
    const { child: childPay } = createChildMission(kernel, {
      parentId: parent.id,
      intent: intent({
        target_resources: [RES_PAY],
      }),
      proposedAuthority: [
        { type: "mission_resource_access", resource: RES_PAY, actions: ["payments:invoice.read"] },
      ],
      childActor: { sub: "subagent-pay-only", sub_profile: "ai_agent" },
    });

    const { record: parentAfter } = kernel.contain(parent.id, {
      event: ev("evt-cascade-6"),
      remove: [{ resource: RES_FILE }],
    });
    expect(parentAfter.containment?.containment_version).toBe(1);

    // Entry-granularity "unaffected": the child is not written AT ALL (no
    // overlay, no version bump), because none of its Authority Set entries
    // share the contained resource. Distinct from the action-granularity case
    // above, where the child IS written but a specific action survives.
    const childAfter = kernel.get(childPay.id) as NonNullable<ReturnType<MissionKernel["get"]>>;
    expect(childAfter.containment).toBeUndefined();
    expect(childAfter.version).toBe(1);
  });

  it("fully containing a child's only capability refuses its OWN derivation with GateError authority_contained", () => {
    const { kernel } = makeHarness();
    const parent = approve(kernel);
    // childExecOnly draws on ONLY payment.execute: containing it empties the
    // child's effective set entirely.
    const { child: childExecOnly } = createChildMission(kernel, {
      parentId: parent.id,
      intent: intent({
        target_resources: [RES_PAY],
      }),
      proposedAuthority: [
        { type: "mission_resource_access", resource: RES_PAY, actions: ["payments:payment.execute"] },
      ],
      childActor: { sub: "subagent-exec", sub_profile: "ai_agent" },
    });

    kernel.contain(parent.id, {
      event: ev("evt-cascade-2"),
      remove: [{ resource: RES_PAY, actions: ["payments:payment.execute"] }],
    });

    expect(kernel.effectiveAuthoritySet(kernel.get(childExecOnly.id) as never)).toEqual([]);
    try {
      kernel.gateDerivation(childExecOnly.id);
      expect.unreachable("a fully contained child must refuse derivation");
    } catch (e) {
      expect(e).toBeInstanceOf(GateError);
      expect((e as GateError).reason).toBe("authority_contained");
    }
  });

  it("does not touch an unrelated child (different parent, no shared justifying entry)", () => {
    const { kernel } = makeHarness();
    const parentA = approve(kernel);
    const parentB = approve(kernel);
    const { child: childOfA } = createChildMission(kernel, {
      parentId: parentA.id,
      intent: intent({
        target_resources: [RES_PAY],
      }),
      proposedAuthority: [
        { type: "mission_resource_access", resource: RES_PAY, actions: ["payments:payment.execute"] },
      ],
      childActor: { sub: "subagent-a", sub_profile: "ai_agent" },
    });
    const { child: childOfB } = createChildMission(kernel, {
      parentId: parentB.id,
      intent: intent({
        target_resources: [RES_PAY],
      }),
      proposedAuthority: [
        { type: "mission_resource_access", resource: RES_PAY, actions: ["payments:payment.execute"] },
      ],
      childActor: { sub: "subagent-b", sub_profile: "ai_agent" },
    });

    kernel.contain(parentA.id, {
      event: ev("evt-cascade-3"),
      remove: [{ resource: RES_PAY, actions: ["payments:payment.execute"] }],
    });

    // childOfA (justified by the contained parent) narrows.
    expect(kernel.get(childOfA.id)?.containment?.containment_version).toBe(1);
    // childOfB (a different family entirely) is completely untouched.
    const bAfter = kernel.get(childOfB.id) as NonNullable<ReturnType<MissionKernel["get"]>>;
    expect(bAfter.containment).toBeUndefined();
    expect(bAfter.version).toBe(1);
    expect(kernel.get(parentB.id)?.containment).toBeUndefined();
  });

  it("is transitive: a grandchild justified through the child also narrows", () => {
    const { kernel } = makeHarness();
    const parent = approve(kernel);
    const { child } = createChildMission(kernel, {
      parentId: parent.id,
      intent: intent({
        target_resources: [RES_PAY],
      }),
      proposedAuthority: [
        {
          type: "mission_resource_access",
          resource: RES_PAY,
          actions: ["payments:invoice.read", "payments:payment.execute"],
        },
      ],
      childActor: { sub: "child-agent", sub_profile: "ai_agent" },
    });
    const { child: grandchild } = createChildMission(kernel, {
      parentId: child.id,
      intent: intent({
        target_resources: [RES_PAY],
      }),
      proposedAuthority: [
        {
          type: "mission_resource_access",
          resource: RES_PAY,
          actions: ["payments:invoice.read", "payments:payment.execute"],
        },
      ],
      childActor: { sub: "grandchild-agent", sub_profile: "ai_agent" },
    });

    kernel.contain(parent.id, {
      event: ev("evt-cascade-4"),
      remove: [{ resource: RES_PAY, actions: ["payments:payment.execute"] }],
    });

    const grandchildEffective = kernel.effectiveAuthoritySet(
      kernel.get(grandchild.id) as NonNullable<ReturnType<MissionKernel["get"]>>,
    );
    expect(grandchildEffective).toHaveLength(1);
    expect(grandchildEffective[0]?.resource).toBe(RES_PAY);
    expect(grandchildEffective[0]?.actions).toEqual(["payments:invoice.read"]);
  });

  it("skips an already-terminal child without aborting or throwing", () => {
    const { kernel } = makeHarness();
    const parent = approve(kernel);
    const { child } = createChildMission(kernel, {
      parentId: parent.id,
      intent: intent({
        target_resources: [RES_PAY],
      }),
      proposedAuthority: [
        { type: "mission_resource_access", resource: RES_PAY, actions: ["payments:payment.execute"] },
      ],
      childActor: { sub: "subagent-term", sub_profile: "ai_agent" },
    });
    kernel.transition(child.id, "revoke");
    expect(kernel.get(child.id)?.state).toBe("revoked");

    expect(() =>
      kernel.contain(parent.id, {
        event: ev("evt-cascade-5"),
        remove: [{ resource: RES_PAY, actions: ["payments:payment.execute"] }],
      }),
    ).not.toThrow();

    // Untouched: a terminal Mission cannot derive further, so nothing to propagate.
    const revokedChild = kernel.get(child.id) as NonNullable<ReturnType<MissionKernel["get"]>>;
    expect(revokedChild.state).toBe("revoked");
    expect(revokedChild.containment).toBeUndefined();
  });
});

describe("contain legality by lifecycle state", () => {
  it("refuses a terminal-state contain; permits a suspended-state contain", () => {
    const { kernel, commits } = makeHarness();
    const revoked = approve(kernel);
    kernel.transition(revoked.id, "revoke");
    expect(() =>
      kernel.contain(revoked.id, { event: ev("evt-term"), remove: [{ resource: RES_FILE }] }),
    ).toThrow(LifecycleConflictError);

    const held = approve(kernel);
    kernel.transition(held.id, "suspend");
    const { record } = kernel.contain(held.id, {
      event: ev("evt-susp"),
      remove: [{ resource: RES_FILE }],
    });
    expect(record.state).toBe("suspended");
    expect(record.version).toBe(3); // approve v1, suspend v2, contain v3
    expect(record.containment?.containment_version).toBe(1);
    expect(commits.at(-1)).toMatchObject({
      id: held.id,
      state: "suspended",
      prior_state: "suspended",
      version: 3,
    });
  });
});

describe("containOnEvent(): issuer-held ContainmentPolicy drives a deterministic narrowing", () => {
  // A test ContainmentPolicy over this suite's POLICY resources: one rule that
  // removes a HELD capability, one that removes a capability the Mission never
  // held (payments:remittance.send is NOT in this suite's RES_PAY ceiling).
  const TEST_CONTAINMENT: ContainmentPolicy = {
    policy_version: "test-containment-1",
    rules: [
      {
        rule_id: "contain-exec-on-taint-v1",
        event_type: "content.tainted_read",
        remove: [{ resource: RES_PAY, actions: ["payments:payment.execute"] }],
      },
      {
        rule_id: "contain-phantom-v1",
        event_type: "content.phantom_capability",
        remove: [{ resource: RES_PAY, actions: ["payments:remittance.send"] }],
      },
    ],
  };
  const pev = (type: string, id: string) => ({
    type,
    source: "svc:soc",
    observed_at: NOW.toISOString(),
    event_id: id,
  });

  it("a matching event_type applies the rule's removal (same effect as a manual contain) and stamps evidence.policy = rule_id", () => {
    const { kernel } = makeHarness(TEST_CONTAINMENT);
    const m = approve(kernel);
    const { record, evidence } = kernel.containOnEvent(m.id, pev("content.tainted_read", "pe-1"));
    expect(record.version).toBe(2);
    expect(record.containment?.containment_version).toBe(1);
    expect(record.containment?.contained).toEqual([
      { resource: RES_PAY, actions: ["payments:payment.execute"] },
    ]);
    expect(evidence.policy).toBe("contain-exec-on-taint-v1");

    // Same effect as a manual contain() with that exact remove[].
    const { kernel: manualKernel } = makeHarness();
    const m2 = approve(manualKernel);
    const manual = manualKernel.contain(m2.id, {
      event: pev("content.tainted_read", "pe-1"),
      remove: [{ resource: RES_PAY, actions: ["payments:payment.execute"] }],
    });
    expect(record.containment?.contained).toEqual(manual.record.containment?.contained);
    expect(kernel.effectiveAuthoritySet(record)).toEqual(
      manualKernel.effectiveAuthoritySet(manual.record),
    );
  });

  it("an unknown event_type fails closed (UnknownProtectedEventError): no version bump, no containment row", () => {
    const { kernel } = makeHarness(TEST_CONTAINMENT);
    const m = approve(kernel);
    expect(() => kernel.containOnEvent(m.id, pev("content.unmapped", "pe-x"))).toThrow(
      UnknownProtectedEventError,
    );
    const fresh = kernel.get(m.id) as NonNullable<ReturnType<MissionKernel["get"]>>;
    expect(fresh.version).toBe(1);
    expect(fresh.containment).toBeUndefined();
  });

  it("a kernel with NO ContainmentPolicy fails every event closed", () => {
    const { kernel } = makeHarness();
    const m = approve(kernel);
    expect(() => kernel.containOnEvent(m.id, pev("content.tainted_read", "pe-none"))).toThrow(
      UnknownProtectedEventError,
    );
    expect((kernel.get(m.id) as NonNullable<ReturnType<MissionKernel["get"]>>).version).toBe(1);
  });

  it("a rule naming a capability the Mission never held still commits; the effective set is unchanged for un-held entries", () => {
    const { kernel, commits } = makeHarness(TEST_CONTAINMENT);
    const m = approve(kernel);
    const before = kernel.effectiveAuthoritySet(m);
    const { record } = kernel.containOnEvent(m.id, pev("content.phantom_capability", "pe-2"));
    expect(record.version).toBe(2); // it commits: a version bump and a containment overlay
    expect(record.containment?.containment_version).toBe(1);
    // Subtraction ignores non-matching entries: the effective set is unchanged.
    expect(kernel.effectiveAuthoritySet(record)).toEqual(before);
    // #572: removing a never-held capability does not narrow the EFFECTIVE
    // set, so the emitted commit must not claim authority_changed.
    expect(commits.at(-1)?.authority_changed).toBeUndefined();
  });

  it("is idempotent by event.event_id through the policy path (single version bump)", () => {
    const { kernel } = makeHarness(TEST_CONTAINMENT);
    const m = approve(kernel);
    const first = kernel.containOnEvent(m.id, pev("content.tainted_read", "pe-dup"));
    expect(first.record.version).toBe(2);
    const second = kernel.containOnEvent(m.id, pev("content.tainted_read", "pe-dup"));
    expect(second.record.version).toBe(2); // no extra bump
    expect(second.record.containment?.containment_version).toBe(1);
    expect(second.record.containment?.events).toHaveLength(1);
  });

  // Guard the REAL demo CONTAINMENT_POLICY shape (mirrors derivation-delegation's
  // guard against a silent loader drop making every assertion vacuous). Also pins
  // the CANONICAL_RESOURCE mapping (a no-op without MCP_PAYMENTS_RESOURCE set).
  it("the seeded demo CONTAINMENT_POLICY resolves the external-comms rule to CANONICAL_RESOURCE", () => {
    expect(CONTAINMENT_POLICY.policy_version).toBe("demo-containment-1");
    const rule = CONTAINMENT_POLICY.rules[0];
    expect(rule?.rule_id).toBe("contain-external-comms-on-taint-v1");
    expect(rule?.event_type).toBe("content.tainted_read");
    expect(rule?.remove[0]?.resource).toBe(CANONICAL_RESOURCE);
    expect(rule?.remove[0]?.actions).toContain("payments:remittance.send");
  });
});

describe("lifecycle endpoint operation: contain (end-to-end)", () => {
  const PORT = 14490;
  const ISSUER = `http://localhost:${PORT}`;
  let as: BuiltAs;
  let server: Server;

  beforeAll(async () => {
    as = await buildAuthorizationServer({ issuer: ISSUER, allowHeadlessAdjudication: true });
    server = as.provider.listen(PORT);
  });
  afterAll(() => {
    server?.close();
  });

  const lifecycle = (missionId: string, body: unknown, token: string | null = DEV_SERVICE_TOKEN) =>
    fetch(`${ISSUER}/missions/${missionId}/lifecycle`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...(token !== null ? { "x-service-token": token } : {}),
      },
      body: JSON.stringify(body),
    });

  it("contains via the dev service token, idempotently, and 409s from a terminal state", async () => {
    const record = as.kernel.approve({
      intent: validateMissionIntent(
        JSON.stringify({
          goal: "Pay Acme invoices for Q3",
          target_resources: [CANONICAL_RESOURCE],
          expires_at: EXPIRES_AT,
        }),
      ),
      subject: { iss: ISSUER, sub: "alice" },
      approver: { iss: ISSUER, sub: "bob" },
      clientId: "ap-agent",
      approvalEventId: "apev-cnt-e2e-1",
    });
    const containBody = {
      operation: "contain",
      event: ev("evt-e2e-1"),
      remove: [{ resource: CANONICAL_RESOURCE, actions: ["payments:payment.schedule"] }],
    };

    // The same dev service-token guard as the other lifecycle operations.
    expect((await lifecycle(record.id, containBody, null)).status).toBe(401);
    // A malformed contain (no event/remove) is refused.
    expect((await lifecycle(record.id, { operation: "contain" })).status).toBe(400);

    const res = await lifecycle(record.id, containBody);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      id: record.id,
      state: "active",
      version: 2,
      containment_version: 1,
    });

    // Idempotent repeat by event_id: no version bump.
    const repeat = await lifecycle(record.id, containBody);
    expect(repeat.status).toBe(200);
    expect(await repeat.json()).toEqual({
      id: record.id,
      state: "active",
      version: 2,
      containment_version: 1,
    });

    // Terminal state: contain conflicts (mirrors the other operations' 409).
    expect((await lifecycle(record.id, { operation: "revoke" })).status).toBe(200);
    const conflict = await lifecycle(record.id, {
      ...containBody,
      event: ev("evt-e2e-2"),
    });
    expect(conflict.status).toBe(409);
    expect(((await conflict.json()) as { error: string }).error).toBe("conflict");
  });
});
