import { DERIVATION_POLICY } from "@mission/demo-data";
import { type CryptoKey, generateKeyPair } from "jose";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import {
  type AuthorityEntry,
  ChildDelegationError,
  childMissionClaim,
  createChildMission,
  GateError,
  isSubsetSet,
  type LifecycleCommit,
  MissionKernel,
  validateMissionIntent,
} from "../src/index.js";

const ISS = "https://as.test";
const RESOURCE = DERIVATION_POLICY.ceiling[0].resource;
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
    delegationAllowed: over.delegationAllowed === undefined ? true : (over.delegationAllowed as boolean),
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
      delegationAllowed: true,
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
      delegationAllowed: true,
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

  it("rejects creation when the parent does not permit delegation (policy_denied)", () => {
    const parent = approveParent();
    try {
      createChild(parent.id, ["payments:invoice.read"], { delegationAllowed: false });
      expect.unreachable();
    } catch (e) {
      expect((e as ChildDelegationError).reason).toBe("policy_denied");
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
      delegationAllowed: true,
    });
    // A great-grandchild would be depth 3 > MAX_CHILD_DEPTH (2).
    try {
      createChildMission(kernel, {
        parentId: grandchild.id,
        intent: childIntent(["payments:invoice.read"]),
        childActor: { sub: "ggc-agent", sub_profile: "ai_agent" },
        delegationAllowed: true,
      });
      expect.unreachable();
    } catch (e) {
      expect((e as ChildDelegationError).reason).toBe("fanout_exceeded");
    }
  });
});
