import { authorityHash, canonicalize, intentHash, type JsonValue } from "@mission/core";
import { DERIVATION_POLICY } from "@mission/demo-data";
import { type CryptoKey, generateKeyPair } from "jose";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import {
  type AuthorityEntry,
  CHILD_EVIDENCE_MEDIA_TYPE,
  ChildDelegationError,
  type ChildEvidence,
  childEvidenceBytes,
  childMissionClaim,
  createChildMission,
  GateError,
  isSubsetSet,
  type LifecycleCommit,
  MissionKernel,
  type MissionRecord,
  validateMissionIntent,
} from "../src/index.js";

const ISS = "https://as.test";
const RESOURCE = DERIVATION_POLICY.ceiling[0].resource;
// The ledger ceiling entry carries NO delegation (used by the on-switch test).
const LEDGER = DERIVATION_POLICY.ceiling[1].resource;
const now = () => new Date("2026-07-01T00:00:00Z");
const PARENT_EXP = "2027-01-01T00:00:00Z";

/** A proposed entry restating the ceiling's Common Constraints (so the derived
 * entry carries max_amount/vendors and subset probes are constraint-attributable). */
const proposed = (actions: string[]): AuthorityEntry[] => [
  {
    type: "mission_resource_access",
    resource: RESOURCE,
    actions,
    constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
  },
];

/** A proposed entry on the (delegation-free) ledger resource, restating its vendors. */
const ledgerProposed = (actions: string[]): AuthorityEntry => ({
  type: "mission_resource_access",
  resource: LEDGER,
  actions,
  constraints: { vendors: ["acme"] },
});

let key: CryptoKey;
let kernel: MissionKernel;
let commits: LifecycleCommit[];
let seq = 0;

beforeAll(async () => {
  key = (await generateKeyPair("ES256")).privateKey;
});

beforeEach(() => {
  commits = [];
  kernel = new MissionKernel({
    issuer: ISS,
    policy: DERIVATION_POLICY as never,
    statusKey: key,
    statusKid: "as-status",
    now,
    // The lifecycle-commit spy: proves Status List / Signals propagate on cascade.
    onLifecycleCommit: (c) => commits.push(c),
  });
});

/** Approve a Parent Mission with the given actions (defaults to read + execute). */
const approveParent = (actions = ["payments:invoice.read", "payments:payment.execute"]) =>
  kernel.approve({
    intent: validateMissionIntent(
      JSON.stringify({
        goal: "Pay Acme invoices for Q3",
        resources: [RESOURCE],
        expires_at: PARENT_EXP,
        proposed_authority: proposed(actions),
      }),
    ),
    subject: { iss: ISS, sub: "alice" },
    approver: { iss: ISS, sub: "bob" },
    clientId: "parent-agent",
    approvalEventId: `apev-${seq++}`,
  });

const childIntent = (actions: string[], over: Record<string, unknown> = {}) =>
  validateMissionIntent(
    JSON.stringify({
      goal: "Extract Acme invoices",
      resources: [RESOURCE],
      expires_at: PARENT_EXP,
      proposed_authority: proposed(actions),
      ...over,
    }),
  );

const createChild = (parentId: string, actions: string[], over: Record<string, unknown> = {}) =>
  createChildMission(kernel, {
    parentId,
    intent: childIntent(actions, over.intentOver as Record<string, unknown>),
    childActor: { sub: "subagent-extractor", sub_profile: "ai_agent", ...(over.childActor ?? {}) },
    ...(over.cascadeMode ? { cascadeMode: over.cascadeMode as "immediate" } : {}),
    ...(over.delegationId ? { delegationId: over.delegationId as string } : {}),
  });

/** A probe entry carrying the child's own constraints, actions overridden. */
const probeOf = (child: { authority_set: AuthorityEntry[] }, actions: string[]): AuthorityEntry[] => [
  { ...(child.authority_set[0] as AuthorityEntry), actions },
];

describe("child mission creation (@spec child-delegation#child-creation, #parent-member)", () => {
  it("creates an active child scoped to a subset, with parent lineage and a fresh actor", () => {
    const parent = approveParent();
    const { child, parent: parentId } = createChild(parent.id, ["payments:invoice.read"]);

    expect(child.state).toBe("active");
    expect(parentId).toBe(parent.id);
    expect(child.issuer).toBe(parent.issuer);
    // @spec child-delegation#child-client-identity — client_id == child actor sub.
    expect(child.client_id).toBe("subagent-extractor");
    // Fresh integrity anchors over the CHILD set.
    expect(child.authority_hash).toMatch(/^sha-256:/);
    expect(child.authority_hash).not.toBe(parent.authority_hash);
    expect(child.approval_event_id).toMatch(/^dlg_/);
    // @spec child-delegation#parent-member — lineage object.
    expect(child.parent?.id).toBe(parent.id);
    expect(child.parent?.issuer).toBe(parent.issuer);
    expect(child.parent?.authority_hash).toBe(parent.authority_hash);
    expect(child.parent?.depth).toBe(1);
    expect(child.parent?.cascade_mode).toBe("immediate");

    // In-slice: a child action within the child slice is a subset of the child set.
    expect(isSubsetSet(probeOf(child, ["payments:invoice.read"]), child.authority_set)).toBe(true);
    // gateDerivation succeeds for the active child.
    expect(() => kernel.gateDerivation(child.id)).not.toThrow();

    // The child claim carries the parent lineage member.
    const claim = childMissionClaim(kernel, child);
    expect((claim as { id: string }).id).toBe(child.id);
    expect((claim as { parent?: { id: string } }).parent?.id).toBe(parent.id);
  });

  it("parent-but-outside-child action is NOT a subset of the child set (denied)", () => {
    const parent = approveParent(["payments:invoice.read", "payments:payment.execute"]);
    const { child } = createChild(parent.id, ["payments:invoice.read"]);

    // payment.execute is granted by the parent but absent from the child.
    const probe = probeOf(child, ["payments:payment.execute"]);
    expect(isSubsetSet(probe, child.authority_set)).toBe(false);
    // Same probe (same constraints) IS a subset of the parent: the child failure
    // is attributable to the missing action, not to a constraint mismatch.
    expect(isSubsetSet(probe, parent.authority_set)).toBe(true);
  });

  it("rejects a child whose authority exceeds the parent (@spec child-delegation#strict-subset)", () => {
    const parent = approveParent(["payments:invoice.read", "payments:payment.execute"]);
    try {
      // remittance.send is within policy but NOT in the parent.
      createChild(parent.id, [
        "payments:invoice.read",
        "payments:payment.execute",
        "payments:remittance.send",
      ]);
      expect.unreachable();
    } catch (e) {
      expect(e).toBeInstanceOf(ChildDelegationError);
      expect((e as ChildDelegationError).reason).toBe("not_strict_subset");
      // The one evidence path where attenuation.result is NOT strict_subset.
      const ev = (e as ChildDelegationError).evidence;
      expect(ev?.decision).toBe("denied");
      expect(ev?.attenuation.result).toBe("not_strict_subset");
    }
  });

  it("clamps the child expires_at to the parent's (@spec child-delegation#attenuation)", () => {
    const parent = approveParent();
    const { child } = createChild(parent.id, ["payments:invoice.read"], {
      intentOver: { expires_at: "2030-01-01T00:00:00Z" },
    });
    expect(child.expires_at).toBe(parent.expires_at);
    expect(child.expires_at).toBe(PARENT_EXP);
  });
});

describe("cascade revocation (@spec child-delegation#cascade)", () => {
  it("revoke -> child cascaded -> derivation denied, and the commit hook observed it", () => {
    const parent = approveParent();
    const { child } = createChild(parent.id, ["payments:invoice.read"]);
    const before = commits.length;

    kernel.transition(parent.id, "revoke");

    // The child row is terminal `cascaded` (distinct from revoked/expired).
    expect(kernel.get(child.id)?.state).toBe("cascaded");
    // Derivation under the cascaded child is refused.
    expect(() => kernel.gateDerivation(child.id)).toThrow(GateError);
    try {
      kernel.gateDerivation(child.id);
      expect.unreachable();
    } catch (e) {
      expect((e as GateError).reason).toBe("mission_not_active");
    }

    // The lifecycle-commit hook observed the CHILD's cascaded commit: this is
    // what makes the Status List republisher and Mission Signals propagate.
    const childCommit = commits
      .slice(before)
      .find((c) => c.id === child.id && c.state === "cascaded");
    expect(childCommit).toBeDefined();
    expect(childCommit?.prior_state).toBe("active");
    expect(childCommit?.version).toBe(2);
  });

  it("cascade is transitive: a grandchild also cascades (in generation order)", () => {
    const parent = approveParent();
    const { child } = createChild(parent.id, ["payments:invoice.read"], {
      childActor: { sub: "child-agent" },
    });
    const { child: grandchild } = createChildMission(kernel, {
      parentId: child.id,
      intent: childIntent(["payments:invoice.read"]),
      childActor: { sub: "grandchild-agent", sub_profile: "ai_agent" },
    });
    expect(grandchild.parent?.depth).toBe(2);

    kernel.transition(parent.id, "revoke");
    expect(kernel.get(child.id)?.state).toBe("cascaded");
    expect(kernel.get(grandchild.id)?.state).toBe("cascaded");
  });

  it("an already-terminal grandchild does not abort the cascade", () => {
    const parent = approveParent();
    const { child } = createChild(parent.id, ["payments:invoice.read"], {
      childActor: { sub: "child-agent" },
    });
    const { child: grandchild } = createChildMission(kernel, {
      parentId: child.id,
      intent: childIntent(["payments:invoice.read"]),
      childActor: { sub: "grandchild-agent", sub_profile: "ai_agent" },
    });
    // Terminate the grandchild directly first.
    kernel.transition(grandchild.id, "revoke");
    expect(kernel.get(grandchild.id)?.state).toBe("revoked");

    // Revoking the parent must still cascade the child despite the terminal
    // grandchild (setState would throw on an already-terminal source; the skip
    // guard prevents that from aborting the whole cascade).
    kernel.transition(parent.id, "revoke");
    expect(kernel.get(child.id)?.state).toBe("cascaded");
    expect(kernel.get(grandchild.id)?.state).toBe("revoked"); // unchanged, skipped
  });
});

describe("child creation guards (@spec child-delegation#denial-reasons)", () => {
  it("rejects creation under a non-active parent (parent_not_active)", () => {
    const parent = approveParent();
    kernel.transition(parent.id, "revoke");
    try {
      createChild(parent.id, ["payments:invoice.read"]);
      expect.unreachable();
    } catch (e) {
      expect((e as ChildDelegationError).reason).toBe("parent_not_active");
    }
  });

  it("(a) refuses when the justifying parent entry carries no children (delegation_not_permitted)", () => {
    // The ledger ceiling entry (ceiling[1]) carries NO delegation at all, so its
    // justifying entry lacks a `children` on-switch. The child restates the
    // ledger vendors so the strict-subset check passes FIRST.
    const parent = kernel.approve({
      intent: validateMissionIntent(
        JSON.stringify({
          goal: "Reconcile the ledger",
          resources: [LEDGER],
          expires_at: PARENT_EXP,
          proposed_authority: [ledgerProposed(["ledger:vendor.read"])],
        }),
      ),
      subject: { iss: ISS, sub: "alice" },
      approver: { iss: ISS, sub: "bob" },
      clientId: "parent-agent",
      approvalEventId: `apev-${seq++}`,
    });
    try {
      createChildMission(kernel, {
        parentId: parent.id,
        intent: validateMissionIntent(
          JSON.stringify({
            goal: "Read ledger vendors",
            resources: [LEDGER],
            expires_at: PARENT_EXP,
            proposed_authority: [ledgerProposed(["ledger:vendor.read"])],
          }),
        ),
        childActor: { sub: "subagent-ledger", sub_profile: "ai_agent" },
      });
      expect.unreachable();
    } catch (e) {
      expect(e).toBeInstanceOf(ChildDelegationError);
      expect((e as ChildDelegationError).reason).toBe("delegation_not_permitted");
      const ev = (e as ChildDelegationError).evidence;
      expect(ev?.decision).toBe("denied");
      expect(ev?.denial_reason).toBe("delegation_not_permitted");
      // The subset proof passed, so the recorded attenuation result is strict_subset.
      expect(ev?.attenuation.result).toBe("strict_subset");
    }
  });

  it("enforces the hard child-generation depth cap (fanout_exceeded)", () => {
    const parent = approveParent();
    const { child } = createChild(parent.id, ["payments:invoice.read"], {
      childActor: { sub: "child-agent" },
    });
    const { child: grandchild } = createChildMission(kernel, {
      parentId: child.id,
      intent: childIntent(["payments:invoice.read"]),
      childActor: { sub: "grandchild-agent", sub_profile: "ai_agent" },
    });
    // A great-grandchild would be depth 3 > MAX_CHILD_DEPTH (2).
    try {
      createChildMission(kernel, {
        parentId: grandchild.id,
        intent: childIntent(["payments:invoice.read"]),
        childActor: { sub: "ggc-agent", sub_profile: "ai_agent" },
      });
      expect.unreachable();
    } catch (e) {
      expect((e as ChildDelegationError).reason).toBe("fanout_exceeded");
    }
  });
});

describe("fan-out accounting and child evidence (@spec child-delegation#fanout, #child-evidence)", () => {
  it("(b) refuses a child actor not matching allowed_child_actors (child_actor_not_allowed)", () => {
    const parent = approveParent();
    try {
      // The demo payments entry's allowed_child_actors is [{ sub_profile: ai_agent }];
      // a human actor matches no matcher.
      createChild(parent.id, ["payments:invoice.read"], {
        childActor: { sub: "human-user", sub_profile: "human" },
      });
      expect.unreachable();
    } catch (e) {
      expect(e).toBeInstanceOf(ChildDelegationError);
      expect((e as ChildDelegationError).reason).toBe("child_actor_not_allowed");
      expect((e as ChildDelegationError).evidence?.decision).toBe("denied");
      expect((e as ChildDelegationError).evidence?.denial_reason).toBe("child_actor_not_allowed");
    }
  });

  it("(c) refuses the (max_children+1)th concurrent child; a slot frees on termination (fanout_exceeded)", () => {
    const parent = approveParent(); // demo payments entry: max_children 5
    const kids: MissionRecord[] = [];
    for (let i = 0; i < 5; i++) {
      const { child } = createChild(parent.id, ["payments:invoice.read"], {
        childActor: { sub: `subagent-${i}`, sub_profile: "ai_agent" },
      });
      kids.push(child);
    }
    // The 6th concurrent child would exceed the cap of 5.
    try {
      createChild(parent.id, ["payments:invoice.read"], {
        childActor: { sub: "subagent-6", sub_profile: "ai_agent" },
      });
      expect.unreachable();
    } catch (e) {
      expect((e as ChildDelegationError).reason).toBe("fanout_exceeded");
      expect((e as ChildDelegationError).evidence?.fanout).toEqual({
        active_children: 5,
        max_children: 5,
      });
    }
    // Terminate one child: a slot frees and a fresh creation SUCCEEDS. Witness
    // the termination so the re-create below can only pass because the bucket
    // dropped to 4 (not because the cap silently failed to enforce).
    kernel.transition(kids[0]!.id, "revoke");
    expect(kernel.get(kids[0]!.id)?.state).toBe("revoked");
    const { child, evidence } = createChild(parent.id, ["payments:invoice.read"], {
      childActor: { sub: "subagent-7", sub_profile: "ai_agent" },
    });
    expect(child.state).toBe("active");
    expect(evidence.decision).toBe("created");
    expect(evidence.fanout).toEqual({ active_children: 5, max_children: 5 });
  });

  it("(d) counts a child subset of two parent entries against the FIRST-in-order entry only", () => {
    const R = "https://d.example/mcp";
    // children.max_children = 1 on the policy ceiling so the child's INHERITED cap
    // subsets entry A (also 1); entry B allows 5. Both parent entries share R.
    const childrenCtl = (maxChildren: number) => ({
      max_children: maxChildren,
      max_child_depth: 2,
      allowed_child_actors: [{ sub_profile: "ai_agent" }],
    });
    const dPolicy = {
      policy_version: "d-policy",
      ceiling: [
        {
          type: "mission_resource_access",
          resource: R,
          actions: ["res.read"],
          constraints: { max_amount: { amount: "100.00", currency: "USD" } },
          delegation: { max_depth: 2, children: childrenCtl(1) },
        },
      ],
    };
    const dKernel = new MissionKernel({
      issuer: ISS,
      policy: dPolicy as never,
      statusKey: key,
      statusKid: "as-status",
      now,
    });
    // Hand-built parent whose Authority Set is TWO same-resource entries:
    // A (index 0, cap 1) then B (index 1, cap 5). The child subsets both.
    const entryOf = (maxAmount: string, maxChildren: number): AuthorityEntry => ({
      type: "mission_resource_access",
      resource: R,
      actions: ["res.read"],
      constraints: { max_amount: { amount: maxAmount, currency: "USD" } },
      delegation: { max_depth: 2, children: childrenCtl(maxChildren) },
    });
    const dApprovalEventId = `apev-d-${seq++}`;
    const parentRecord: MissionRecord = {
      id: `msn_dparent_${seq++}`,
      issuer: ISS,
      state: "active",
      intent: { goal: "root", resources: [R], expires_at: PARENT_EXP },
      authority_set: [entryOf("100.00", 1), entryOf("500.00", 5)],
      intent_hash: "sha-256:d-intent",
      authority_hash: "sha-256:d-authority",
      subject: { iss: ISS, sub: "alice" },
      approver: { iss: ISS, sub: "bob" },
      approval_basis: {
        type: "direct",
        consent_principal: { iss: ISS, sub: "bob" },
        activation: { approval_event_id: dApprovalEventId },
        activation_actor: { iss: ISS, sub: "bob" },
        root_commitment: "sha-256:d-authority",
      },
      client_id: "parent-agent",
      policy_version: "d-policy",
      approval_event_id: dApprovalEventId,
      created_at: now().toISOString(),
      expires_at: PARENT_EXP,
      version: 1,
      max_derivations: null,
      derivation_count: 0,
      grant_id: null,
      status_list_idx: null,
    };
    dKernel.insertRecord(parentRecord);

    const dChildIntent = () =>
      validateMissionIntent(
        JSON.stringify({
          goal: "read",
          resources: [R],
          expires_at: PARENT_EXP,
          proposed_authority: [
            {
              type: "mission_resource_access",
              resource: R,
              actions: ["res.read"],
              constraints: { max_amount: { amount: "100.00", currency: "USD" } },
            },
          ],
        }),
      );

    // First child: bucket for entry A (index 0) goes 0 -> 1 (== its cap).
    const first = createChildMission(dKernel, {
      parentId: parentRecord.id,
      intent: dChildIntent(),
      childActor: { sub: "d-agent-0", sub_profile: "ai_agent" },
    });
    expect(first.child.state).toBe("active");
    // Attributed to entry A (cap 1), NOT entry B (cap 5).
    expect(first.evidence.fanout).toEqual({ active_children: 1, max_children: 1 });

    // Second child: entry A is full (1/1) so it MUST refuse, even though entry B
    // (cap 5) has room — this is what proves first-in-order attribution.
    try {
      createChildMission(dKernel, {
        parentId: parentRecord.id,
        intent: dChildIntent(),
        childActor: { sub: "d-agent-1", sub_profile: "ai_agent" },
      });
      expect.unreachable();
    } catch (e) {
      expect((e as ChildDelegationError).reason).toBe("fanout_exceeded");
      expect((e as ChildDelegationError).evidence?.fanout).toEqual({
        active_children: 1,
        max_children: 1,
      });
    }
  });

  it("(e) emits a Child Evidence record with stable JCS bytes (permit and deny)", () => {
    const parent = approveParent();
    const { child, evidence } = createChild(parent.id, ["payments:invoice.read"]);

    // Shape (@spec child-delegation#child-evidence-object).
    expect(evidence.evidence_id).toMatch(/^chd_/);
    expect(evidence.parent).toEqual({
      id: parent.id,
      issuer: parent.issuer,
      authority_hash: parent.authority_hash,
    });
    expect(evidence.child).toEqual({
      id: child.id,
      issuer: child.issuer,
      authority_hash: child.authority_hash,
    });
    expect(evidence.child_actor).toEqual({ sub: "subagent-extractor", sub_profile: "ai_agent" });
    expect(evidence.attenuation).toEqual({ result: "strict_subset" });
    expect(evidence.fanout).toEqual({ active_children: 1, max_children: 5 });
    expect(evidence.cascade_mode).toBe("immediate");
    expect(evidence.decision).toBe("created");
    expect(evidence.created_at).toBe(now().toISOString());
    expect(CHILD_EVIDENCE_MEDIA_TYPE).toBe("application/mission-child-evidence+json");

    // Stable JCS bytes: equal to canonicalize of an object rebuilt from the
    // (random) evidence_id and the deterministic members. JCS sorts members
    // lexicographically, so this also pins member ordering and rejects extras.
    const permitExpected = {
      evidence_id: evidence.evidence_id,
      parent: { id: parent.id, issuer: parent.issuer, authority_hash: parent.authority_hash },
      child: { id: child.id, issuer: child.issuer, authority_hash: child.authority_hash },
      child_actor: { sub: "subagent-extractor", sub_profile: "ai_agent" },
      attenuation: { result: "strict_subset" },
      fanout: { active_children: 1, max_children: 5 },
      cascade_mode: "immediate",
      decision: "created",
      created_at: now().toISOString(),
    };
    expect(childEvidenceBytes(evidence)).toBe(canonicalize(permitExpected as unknown as JsonValue));
    expect(
      childEvidenceBytes(evidence).startsWith(
        '{"attenuation":{"result":"strict_subset"},"cascade_mode":"immediate"',
      ),
    ).toBe(true);

    // Deny evidence: a real (prospective) child member and denial_reason, canonical.
    let denyEvidence: ChildEvidence | undefined;
    try {
      createChild(parent.id, ["payments:invoice.read"], {
        childActor: { sub: "human-user", sub_profile: "human" },
      });
      expect.unreachable();
    } catch (e) {
      denyEvidence = (e as ChildDelegationError).evidence;
    }
    const dev = denyEvidence as ChildEvidence;
    expect(dev.decision).toBe("denied");
    expect(dev.denial_reason).toBe("child_actor_not_allowed");
    expect(dev.child.id).toMatch(/^msn_/); // a real prospective child id even on refusal
    const denyExpected = {
      evidence_id: dev.evidence_id,
      parent: { id: parent.id, issuer: parent.issuer, authority_hash: parent.authority_hash },
      child: { id: dev.child.id, issuer: parent.issuer, authority_hash: dev.child.authority_hash },
      child_actor: { sub: "human-user", sub_profile: "human" },
      attenuation: { result: "strict_subset" },
      cascade_mode: "immediate",
      decision: "denied",
      denial_reason: "child_actor_not_allowed",
      created_at: now().toISOString(),
    };
    expect(childEvidenceBytes(dev)).toBe(canonicalize(denyExpected as unknown as JsonValue));
  });
});

describe("child derivation cap is independent of the parent's (@spec child-delegation#child-creation, PR #408)", () => {
  it("uses the child's OWN controls.max_derivations, not the parent's", () => {
    const parent = kernel.approve({
      intent: validateMissionIntent(
        JSON.stringify({
          goal: "Pay Acme invoices for Q3",
          resources: [RESOURCE],
          expires_at: PARENT_EXP,
          proposed_authority: proposed(["payments:invoice.read"]),
          controls: { max_derivations: 5 },
        }),
      ),
      subject: { iss: ISS, sub: "alice" },
      approver: { iss: ISS, sub: "bob" },
      clientId: "parent-agent",
      approvalEventId: `apev-${seq++}`,
    });
    expect(parent.max_derivations).toBe(5);

    const { child } = createChild(parent.id, ["payments:invoice.read"], {
      intentOver: { controls: { max_derivations: 2 } },
    });
    // The child's cap is its OWN intent's value, distinct from the parent's.
    expect(child.max_derivations).toBe(2);
    expect(child.max_derivations).not.toBe(parent.max_derivations);
  });

  it("a child intent omitting controls.max_derivations gets null (unbounded), like an ordinary Mission", () => {
    const parent = kernel.approve({
      intent: validateMissionIntent(
        JSON.stringify({
          goal: "Pay Acme invoices for Q3",
          resources: [RESOURCE],
          expires_at: PARENT_EXP,
          proposed_authority: proposed(["payments:invoice.read"]),
          controls: { max_derivations: 5 },
        }),
      ),
      subject: { iss: ISS, sub: "alice" },
      approver: { iss: ISS, sub: "bob" },
      clientId: "parent-agent",
      approvalEventId: `apev-${seq++}`,
    });
    const { child } = createChild(parent.id, ["payments:invoice.read"]);
    expect(child.max_derivations).toBeNull();
  });
});

describe("approval basis (@spec mission#approval-basis, child-delegation#child-creation)", () => {
  it("records a policy_drawdown basis, root_commitment falling back to the parent's authority_hash (no child_creation_policy reference carried)", () => {
    const parent = approveParent();
    const { child } = createChild(parent.id, ["payments:invoice.read"]);
    const persisted = kernel.get(child.id);
    expect(persisted?.approval_basis).toEqual({
      type: "policy_drawdown",
      consent_principal: { iss: ISS, sub: "bob" },
      activation: {
        policy_version: parent.policy_version,
        activation_event_id: child.approval_event_id,
      },
      // The requesting principal: the PARENT's own agent, distinct from the
      // consenting human ("bob").
      activation_actor: { iss: ISS, sub: "parent-agent" },
      root_commitment: parent.authority_hash,
    });
    // approver IS approval_basis.consent_principal (D48/O-38 convergence).
    expect(persisted?.approver).toEqual(persisted?.approval_basis.consent_principal);
    expect(persisted?.approval_basis.activation_actor).not.toEqual(
      persisted?.approval_basis.consent_principal,
    );
    // Not folded into either integrity anchor: recomputing both from `intent`
    // and `authority_set` alone still matches, so approval_basis carries no
    // weight in the digests (the lock's hashing decision, made checkable).
    expect(child.intent_hash).toBe(intentHash(child.issuer, child.intent as never));
    expect(child.authority_hash).toBe(authorityHash(child.issuer, child.authority_set as never));
  });

  it("carries approval_basis.type on the child mission claim", () => {
    const parent = approveParent();
    const { child } = createChild(parent.id, ["payments:invoice.read"]);
    const claim = childMissionClaim(kernel, kernel.get(child.id) as MissionRecord);
    expect((claim as { approval_basis: unknown }).approval_basis).toEqual({ type: "policy_drawdown" });
  });

  it("uses the justifying entry's child_creation_policy reference as root_commitment when the entry carries one", () => {
    const R = "https://basis.example/mcp";
    const policy = {
      policy_version: "basis-policy",
      ceiling: [
        {
          type: "mission_resource_access",
          resource: R,
          actions: ["res.read"],
          delegation: {
            max_depth: 1,
            children: { max_children: 5, child_creation_policy: "urn:policy:child-drawdown:v1" },
          },
        },
      ],
    };
    const basisKernel = new MissionKernel({
      issuer: ISS,
      policy: policy as never,
      statusKey: key,
      statusKid: "as-status",
      now,
    });
    const parent = basisKernel.approve({
      intent: validateMissionIntent(
        JSON.stringify({ goal: "root", resources: [R], expires_at: PARENT_EXP }),
      ),
      subject: { iss: ISS, sub: "alice" },
      approver: { iss: ISS, sub: "bob" },
      clientId: "parent-agent",
      approvalEventId: `apev-basis-${seq++}`,
    });
    const { child } = createChildMission(basisKernel, {
      parentId: parent.id,
      intent: validateMissionIntent(
        JSON.stringify({ goal: "sub", resources: [R], expires_at: PARENT_EXP }),
      ),
      childActor: { sub: "basis-child", sub_profile: "ai_agent" },
    });
    const persisted = basisKernel.get(child.id);
    expect(persisted?.approval_basis.type).toBe("policy_drawdown");
    expect(persisted?.approval_basis.root_commitment).toBe("urn:policy:child-drawdown:v1");
    expect(
      (persisted?.approval_basis as { activation: { policy_id?: string } }).activation.policy_id,
    ).toBe("urn:policy:child-drawdown:v1");
  });
});
