import { activationPolicyDigest, authorityHash, canonicalize, intentHash, type JsonValue } from "@mission/core";
import { DERIVATION_POLICY, pinnedToCurrentContract, TOPOLOGY } from "@mission/demo-data";
import { type CryptoKey, generateKeyPair } from "jose";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { withTransaction } from "@mission/store";
import {
  type AuthorityEntry,
  CHILD_EVIDENCE_MEDIA_TYPE,
  ChildDelegationError,
  type ChildEvidence,
  childEvidenceBytes,
  childMissionClaim,
  createChildMission,
  GateError,
  isSubsetEntry,
  isSubsetSet,
  type LifecycleCommit,
  MissionKernel,
  type MissionRecord,
  validateMissionIntent,
} from "../src/index.js";
import { approvalDerivationRendering } from "../src/adapters/provider.js";
import { inheritActionApprovalRequirement, presentedTokenChildRefusal } from "../src/kernel/child-delegation.js";
import { aiAgents } from "./actor-profiles.helper.js";
import { testAuthoritySourceCatalog } from "./authority-source.helper.js";
import { FIXTURE_EXPIRES_AT, daysAfter } from "./relative-expiry.helper.js";

const ISS = "https://as.test";
// The AS asserts these child actors as `ai_agent` (config-driven in production;
// declared here for the suite). A sub NOT listed (e.g. `human-user`) has no
// asserted class and is denied by a `{ sub_profile }` matcher — the conformant,
// self-asserted-safe behaviour these tests exercise.
const CHILD_ACTORS = aiAgents(
  "subagent-extractor",
  "child-agent",
  "grandchild-agent",
  "ggc-agent",
  "subagent-ledger",
  "subagent-0",
  "subagent-1",
  "subagent-2",
  "subagent-3",
  "subagent-4",
  "subagent-6",
  "subagent-7",
);
const RESOURCE = DERIVATION_POLICY.ceiling[0].resource;
// The ledger ceiling entry carries NO delegation (used by the on-switch test).
// @spec mission#authorization-derivation (#743) — selected by name, not
// index: the payments resource is now two ceiling entries (money-carrying
// and read-only), so `ceiling[1]` no longer names the ledger resource.
const LEDGER = TOPOLOGY.resources.saas;
const now = () => new Date("2026-07-01T00:00:00Z");
const PARENT_EXP = FIXTURE_EXPIRES_AT;

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
    authoritySourceCatalog: testAuthoritySourceCatalog(DERIVATION_POLICY.ceiling, ["parent-agent"], ["bob"]),
    statusKey: key,
    statusKid: "as-status",
    now,
    actorProfiles: CHILD_ACTORS,
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
        target_resources: [RESOURCE],
        expires_at: PARENT_EXP,
      }),
    ),
    proposedAuthority: proposed(actions),
    subject: { iss: ISS, sub: "alice" },
    approver: { iss: ISS, sub: "bob" },
    clientId: "parent-agent",
    approvalEventId: `apev-${seq++}`,
  });

const childIntent = (actions: string[], over: Record<string, unknown> = {}) =>
  validateMissionIntent(
    JSON.stringify({
      goal: "Extract Acme invoices",
      target_resources: [RESOURCE],
      expires_at: PARENT_EXP,
      ...over,
    }),
  );

const createChild = (parentId: string, actions: string[], over: Record<string, unknown> = {}) =>
  createChildMission(kernel, {
    parentId,
    intent: childIntent(actions, over.intentOver as Record<string, unknown>),
    proposedAuthority: proposed(actions),
    childActor: { sub: "subagent-extractor", sub_profile: "ai_agent", ...(over.childActor ?? {}) },
    ...(over.cascadeMode ? { cascadeMode: over.cascadeMode as "immediate" } : {}),
    ...(over.delegationId ? { delegationId: over.delegationId as string } : {}),
  });

/** A probe entry carrying the child's own constraints, actions overridden. */
const probeOf = (child: { authority_set: AuthorityEntry[] }, actions: string[]): AuthorityEntry[] => [
  { ...(child.authority_set[0] as AuthorityEntry), actions },
];

describe("child mission creation (@spec child-delegation#child-creation, #parent-member)", () => {
  it("checks fanout in the insertion transaction and a post-check fault leaves no child or publication", () => {
    const parent = approveParent();
    commits.length = 0;
    const original = kernel.insertRecord.bind(kernel);
    const insertion = vi.spyOn(kernel, "insertRecord").mockImplementationOnce((record, precondition, options) => {
      expect(precondition).toBeTypeOf("function");
      return original(
        record,
        () => {
          expect(kernel.db.inTransaction).toBe(true);
          precondition!();
          throw new Error("fault after fanout admission");
        },
        options,
      );
    });
    try {
      expect(() => createChild(parent.id, ["payments:invoice.read"])).toThrow("fault after fanout admission");
      expect(kernel.db.prepare("SELECT count(*) AS n FROM missions").get()).toEqual({ n: 1 });
      expect(commits).toEqual([]);
    } finally { insertion.mockRestore(); }
    expect(createChild(parent.id, ["payments:invoice.read"]).child.state).toBe("active");
    expect(kernel.db.prepare("SELECT count(*) AS n FROM missions").get()).toEqual({ n: 2 });
  });

  it("rolls back a parent transition and its whole child cascade without publishing either", () => {
    const parent = approveParent();
    const { child } = createChild(parent.id, ["payments:invoice.read"]);
    commits.length = 0;
    expect(() => withTransaction(kernel.db, () => {
      kernel.transition(parent.id, "revoke");
      expect(kernel.get(child.id)?.termination?.reason).toBe("parent_terminated");
      expect(commits).toEqual([]);
      throw new Error("outer cascade fault");
    })).toThrow("outer cascade fault");
    expect(kernel.get(parent.id)).toEqual(parent);
    expect(kernel.get(child.id)).toEqual(child);
    expect(commits).toEqual([]);
    kernel.transition(parent.id, "revoke");
    expect(commits.map(c => [c.id, c.state, c.termination?.reason])).toEqual([
      [parent.id, "terminated", "revoked"],
      [child.id, "terminated", "parent_terminated"],
    ]);
  });
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

    // payment.execute is granted by the parent but absent from the child. The
    // probe restates the parent's grant of it, with any contract reference
    // that grant carries (#249, D865).
    const granted = parent.authority_set.find((e) => e.actions.includes("payments:payment.execute"))?.resource_contract;
    const probe = probeOf(child, ["payments:payment.execute"]).map((e) =>
      granted === undefined ? e : { ...e, resource_contract: granted },
    );
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

  it("bounds the child by the presented token's authority, naming that bound in the evidence (@spec child-delegation#attenuation, D353)", () => {
    const parent = approveParent(["payments:invoice.read", "payments:payment.execute"]);
    // The presented token carries the parent's invoice read only.
    const token = parent.authority_set
      .map((e) => ({ ...e, actions: e.actions.filter((a) => a === "payments:invoice.read") }))
      .filter((e) => e.actions.length > 0);
    const within = createChildMission(kernel, {
      parentId: parent.id,
      intent: childIntent(["payments:invoice.read"]),
      proposedAuthority: proposed(["payments:invoice.read"]),
      childActor: { sub: "subagent-extractor", sub_profile: "ai_agent" },
      presentedAuthority: token,
    });
    expect(within.child.authority_set.flatMap((e) => e.actions)).toEqual(["payments:invoice.read"]);
    try {
      createChildMission(kernel, {
        parentId: parent.id,
        intent: childIntent(["payments:invoice.read", "payments:payment.execute"]),
        proposedAuthority: proposed(["payments:invoice.read", "payments:payment.execute"]),
        childActor: { sub: "subagent-extractor", sub_profile: "ai_agent" },
        presentedAuthority: token,
      });
      expect.unreachable();
    } catch (e) {
      expect(e).toBeInstanceOf(ChildDelegationError);
      expect((e as ChildDelegationError).reason).toBe("not_strict_subset");
      const ev = (e as ChildDelegationError).evidence;
      expect(ev?.decision).toBe("denied");
      expect(ev?.attenuation.result).toBe("exceeds_presented_authority");
    }
    // A token carrying the same action without the delegation right: the
    // child's delegation right exceeds it, so this bound refuses (the parent
    // carries the right, so the parent bound would not).
    const undelegable = token.map(({ delegation: _dropped, ...rest }) => rest as AuthorityEntry);
    try {
      createChildMission(kernel, {
        parentId: parent.id,
        intent: childIntent(["payments:invoice.read"]),
        proposedAuthority: proposed(["payments:invoice.read"]),
        childActor: { sub: "subagent-extractor", sub_profile: "ai_agent" },
        presentedAuthority: undelegable,
      });
      expect.unreachable();
    } catch (e) {
      expect(e).toBeInstanceOf(ChildDelegationError);
      expect((e as ChildDelegationError).reason).toBe("not_strict_subset");
      expect((e as ChildDelegationError).evidence?.attenuation.result).toBe("exceeds_presented_authority");
    }
  });

  it("the presented token's children controls govern this creation, the evidence naming the bound (@spec child-delegation#attenuation, #fanout, #1192 review)", () => {
    const parent = approveParent(["payments:invoice.read", "payments:payment.execute"]);
    const readOnly = (mutate: (children: Record<string, unknown>) => void) =>
      parent.authority_set
        .map((e) => {
          const delegation = structuredClone(e.delegation) as Record<string, unknown>;
          mutate(delegation.children as Record<string, unknown>);
          return { ...e, actions: e.actions.filter((a) => a === "payments:invoice.read"), delegation } as AuthorityEntry;
        })
        .filter((e) => e.actions.length > 0);
    const attempt = (token: AuthorityEntry[]) =>
      createChildMission(kernel, {
        parentId: parent.id,
        intent: childIntent(["payments:invoice.read"]),
        proposedAuthority: token.map(({ capability_sources: _s, ...rest }) => rest as AuthorityEntry),
        childActor: { sub: "subagent-extractor", sub_profile: "ai_agent" },
        presentedAuthority: token,
      });
    const refusedWith = (token: AuthorityEntry[]) => {
      try {
        attempt(token);
      } catch (e) {
        expect(e).toBeInstanceOf(ChildDelegationError);
        return e as ChildDelegationError;
      }
      return expect.unreachable();
    };
    const actors = refusedWith(readOnly((c) => { c.allowed_child_actors = []; }));
    expect(actors.reason).toBe("child_actor_not_allowed");
    expect(actors.evidence?.attenuation.result).toBe("exceeds_presented_authority");
    const count = refusedWith(readOnly((c) => { c.max_children = 0; }));
    expect(count.reason).toBe("fanout_exceeded");
    expect(count.evidence?.attenuation.result).toBe("exceeds_presented_authority");
    expect(count.evidence?.fanout).toEqual({ active_children: 0, max_children: 0 });
    // A grandchild (depth 2) under a token whose max_child_depth is 1: the depth control refuses.
    const depthToken = readOnly((c) => { c.max_child_depth = 1; });
    expect(
      presentedTokenChildRefusal(kernel, depthToken.map(({ capability_sources: _s, ...rest }) => rest as AuthorityEntry), "subagent-extractor", 2, depthToken, undefined)?.reason,
    ).toBe("fanout_exceeded");
    expect(
      presentedTokenChildRefusal(kernel, depthToken.map(({ capability_sources: _s, ...rest }) => rest as AuthorityEntry), "subagent-extractor", 1, depthToken, undefined),
    ).toBeUndefined();
    // A token whose delegation right carries no `children` object authorizes no
    // child: the child carries its parent entry's `children` object, so the
    // authority bound refuses it.
    const noChildren = parent.authority_set
      .map((e) => {
        const { children: _c, ...delegation } = structuredClone(e.delegation) as Record<string, unknown>;
        return { ...e, actions: e.actions.filter((a) => a === "payments:invoice.read"), delegation } as AuthorityEntry;
      })
      .filter((e) => e.actions.length > 0);
    const childless = refusedWith(noChildren);
    expect(childless.reason).toBe("not_strict_subset");
    expect(childless.evidence?.attenuation.result).toBe("exceeds_presented_authority");
    // Admitted when the token's controls admit the child.
    expect(attempt(readOnly(() => {})).child.authority_set.flatMap((e) => e.actions)).toEqual(["payments:invoice.read"]);
  });

  it("clamps the child expires_at to the parent's (@spec child-delegation#attenuation)", () => {
    const parent = approveParent();
    const { child } = createChild(parent.id, ["payments:invoice.read"], {
      intentOver: { expires_at: daysAfter(PARENT_EXP, 365) },
    });
    expect(child.expires_at).toBe(parent.expires_at);
    expect(child.expires_at).toBe(PARENT_EXP);
  });
});

describe("cascade revocation (@spec child-delegation#cascade)", () => {
  it("revoke -> child terminated parent_terminated -> derivation denied, and the commit hook observed it", () => {
    const parent = approveParent();
    const { child } = createChild(parent.id, ["payments:invoice.read"]);
    const before = commits.length;

    const revoked = kernel.transition(parent.id, "revoke");

    // @spec child-delegation#cascade, mission#termination: the child row is
    // `terminated` with reason `parent_terminated` (distinct from its own
    // revocation or expiry), naming its immediate parent and carrying the
    // parent's own `terminated_at` (one instant for the cascade), with the
    // origin of the cascade as provenance and its own committing version.
    expect(kernel.get(child.id)).toMatchObject({
      state: "terminated",
      termination: {
        reason: "parent_terminated",
        parent: parent.id,
        terminated_at: revoked.termination?.terminated_at,
        origin: parent.id,
        origin_reason: "revoked",
        version: 2,
      },
    });
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
      .find((c) => c.id === child.id && c.termination?.reason === "parent_terminated");
    expect(childCommit).toBeDefined();
    expect(childCommit?.state).toBe("terminated");
    expect(childCommit?.prior_state).toBe("active");
    expect(childCommit?.version).toBe(2);
    expect(childCommit?.termination?.version).toBe(childCommit?.version);
  });

  it("cascade is transitive: a grandchild also cascades (in generation order)", () => {
    const parent = approveParent();
    const { child } = createChild(parent.id, ["payments:invoice.read"], {
      childActor: { sub: "child-agent" },
    });
    const { child: grandchild } = createChildMission(kernel, {
      parentId: child.id,
      intent: childIntent(["payments:invoice.read"]),
      proposedAuthority: proposed(["payments:invoice.read"]),
      childActor: { sub: "grandchild-agent", sub_profile: "ai_agent" },
    });
    expect(grandchild.parent?.depth).toBe(2);

    const revoked = kernel.transition(parent.id, "revoke");
    expect(kernel.get(child.id)?.termination?.reason).toBe("parent_terminated");
    // The grandchild names its IMMEDIATE parent (the child), reports the one
    // instant the cascade started at, and keeps the originating ancestor and
    // its reason as provenance.
    expect(kernel.get(grandchild.id)).toMatchObject({
      state: "terminated",
      termination: {
        reason: "parent_terminated",
        parent: child.id,
        terminated_at: revoked.termination?.terminated_at,
        origin: parent.id,
        origin_reason: "revoked",
      },
    });
  });

  it("an already-terminal grandchild does not abort the cascade", () => {
    const parent = approveParent();
    const { child } = createChild(parent.id, ["payments:invoice.read"], {
      childActor: { sub: "child-agent" },
    });
    const { child: grandchild } = createChildMission(kernel, {
      parentId: child.id,
      intent: childIntent(["payments:invoice.read"]),
      proposedAuthority: proposed(["payments:invoice.read"]),
      childActor: { sub: "grandchild-agent", sub_profile: "ai_agent" },
    });
    // Terminate the grandchild directly first.
    kernel.transition(grandchild.id, "revoke");
    expect(kernel.get(grandchild.id)?.termination?.reason).toBe("revoked");

    // Revoking the parent must still cascade the child despite the terminal
    // grandchild (setState would throw on an already-terminal source; the skip
    // guard prevents that from aborting the whole cascade).
    kernel.transition(parent.id, "revoke");
    expect(kernel.get(child.id)?.termination?.reason).toBe("parent_terminated");
    // unchanged, skipped: the recorded cause is never replaced
    expect(kernel.get(grandchild.id)?.termination?.reason).toBe("revoked");
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
          target_resources: [LEDGER],
          expires_at: PARENT_EXP,
        }),
      ),
      proposedAuthority: [ledgerProposed(["ledger:vendor.read"])],
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
            target_resources: [LEDGER],
            expires_at: PARENT_EXP,
          }),
        ),
        proposedAuthority: [ledgerProposed(["ledger:vendor.read"])],
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
      proposedAuthority: proposed(["payments:invoice.read"]),
      childActor: { sub: "grandchild-agent", sub_profile: "ai_agent" },
    });
    // A great-grandchild would be depth 3 > MAX_CHILD_DEPTH (2).
    try {
      createChildMission(kernel, {
        parentId: grandchild.id,
        intent: childIntent(["payments:invoice.read"]),
        proposedAuthority: proposed(["payments:invoice.read"]),
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
      // `human-user` has no AS-asserted class (absent from actorProfiles), so no
      // matcher admits it.
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

  it("(b') a SELF-ASSERTED sub_profile does NOT satisfy allowed_child_actors (must be AS-asserted)", () => {
    // @spec oauth-mission 2989-2991 (inherited by child-delegation#fanout): the
    // request CLAIMS `ai_agent`, but the AS asserts no class for `impostor` (it is
    // absent from actorProfiles). A self-asserted sub_profile MUST NOT satisfy a
    // { sub_profile } matcher — otherwise a client could claim any actor type to
    // bypass the constraint — so creation is refused.
    const parent = approveParent();
    try {
      createChild(parent.id, ["payments:invoice.read"], {
        childActor: { sub: "impostor", sub_profile: "ai_agent" },
      });
      expect.unreachable();
    } catch (e) {
      expect((e as ChildDelegationError).reason).toBe("child_actor_not_allowed");
    }
  });

  it("(b'') an ABSENT allowed_child_actors list DENIES (fail-closed), even an AS-asserted ai_agent", () => {
    // @spec oauth-mission 2964-2968: an absent matcher list is a decision deferred
    // to policy, never a blanket grant. The on-switch (children) is present but
    // carries NO allowed_child_actors; the reference impl's policy is fail-closed,
    // so even an AS-asserted ai_agent is refused.
    const R = "https://noactors.example/mcp";
    const openPolicy = {
      policy_version: "open-policy",
      ceiling: [
        {
          type: "mission_resource_access",
          resource: R,
          actions: ["res.read"],
          constraints: { max_amount: { amount: "100.00", currency: "USD" } },
          delegation: { max_depth: 2, children: { max_children: 5 } },
        },
      ],
    };
    const k = new MissionKernel({
      issuer: ISS,
      policy: openPolicy as never,
      authoritySourceCatalog: testAuthoritySourceCatalog(openPolicy.ceiling, ["parent-agent"], ["bob"]),
      statusKey: key,
      statusKid: "as-status",
      now,
      actorProfiles: aiAgents("some-agent"),
    });
    const noActorsProposal: AuthorityEntry[] = [
      {
        type: "mission_resource_access",
        resource: R,
        actions: ["res.read"],
        constraints: { max_amount: { amount: "100.00", currency: "USD" } },
      },
    ];
    const intentFor = (goal: string) =>
      validateMissionIntent(
        JSON.stringify({
          goal,
          target_resources: [R],
          expires_at: PARENT_EXP,
        }),
      );
    const parent = k.approve({
      intent: intentFor("parent"),
      proposedAuthority: noActorsProposal,
      subject: { iss: ISS, sub: "alice" },
      approver: { iss: ISS, sub: "bob" },
      clientId: "parent-agent",
      approvalEventId: `apev-${seq++}`,
    });
    try {
      createChildMission(k, {
        parentId: parent.id,
        intent: intentFor("child"),
        proposedAuthority: noActorsProposal,
        childActor: { sub: "some-agent", sub_profile: "ai_agent" },
      });
      expect.unreachable();
    } catch (e) {
      expect(e).toBeInstanceOf(ChildDelegationError);
      expect((e as ChildDelegationError).reason).toBe("child_actor_not_allowed");
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
    expect(kernel.get(kids[0]!.id)?.termination?.reason).toBe("revoked");
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
      actorProfiles: aiAgents("d-agent-0", "d-agent-1"),
      // @spec mission#authority-sources — the hand-built parent below stands in
      // for one a real approval would have produced, so the deployment declares
      // the user-delegated source whose authority covers it; the drawdown's
      // ceiling assertion then runs against that source, not the narrower
      // derivation ceiling this fan-out case deliberately exceeds.
      authoritySourceCatalog: {
        humanPrincipals: ["alice", "bob"],
        entries: [
          {
            id: "d-people",
            type: "user_delegated",
            clients: ["parent-agent"],
            activators: ["bob"],
            ceiling: [
              {
                type: "mission_resource_access",
                resource: R,
                actions: ["res.read"],
                constraints: { max_amount: { amount: "500.00", currency: "USD" } },
                delegation: { max_depth: 2, children: childrenCtl(5) },
              },
            ],
          },
        ],
      } as never,
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
      intent: { goal: "root", target_resources: [R], expires_at: PARENT_EXP },
      authority_set: [entryOf("100.00", 1), entryOf("500.00", 5)],
      // @spec child-delegation#fanout (#1304): the child-actor origins a
      // derivation would have retained: both entries derive from a ceiling
      // entry whose `children` names its actors, so each list decides.
      child_actor_provenance: ["list", "list"],
      // @spec derivation-limits#effective-limit (#2026): the per-child figure
      // a direct approval would have retained for each entry: this kernel's
      // policy sets no ceiling, so no finite maximum.
      child_derivation_maxima: [{ finite: null }, { finite: null }],
      // The anchors and root_commitment are omitted, so each is implied by
      // the object it commits (#1912, #1917).
      subject: { iss: ISS, sub: "alice" },
      approval_basis: {
        type: "direct",
        consent_principal: { iss: ISS, sub: "bob" },
        activation: { approval_event_id: dApprovalEventId },
        activation_actor: { iss: ISS, sub: "bob" },
      },
      // @spec mission#authority-sources — REQUIRED and immutable; the source
      // this kernel's catalog declares, which is what a real approval would
      // have established.
      authority_source: { type: "user_delegated" },
      client_id: "parent-agent",
      policy_version: "d-policy",
      approval_event_id: dApprovalEventId,
      created_at: now().toISOString(),
      expires_at: PARENT_EXP,
      version: 1,
      derivation_limit: null,
      derivation_count: 0,
      grant_id: null,
      status_list_idx: null,
    };
    // A hand-built direct approval: its source is what the catalog resolves
    // for this Subject through this client, exactly as approve() would (#827).
    dKernel.insertRecord(parentRecord, undefined, {
      source: dKernel.resolveAuthoritySource({ clientId: parentRecord.client_id, subject: parentRecord.subject }),
      audiences: "fresh",
    });

    const dProposal: AuthorityEntry[] = [
      {
        type: "mission_resource_access",
        resource: R,
        actions: ["res.read"],
        constraints: { max_amount: { amount: "100.00", currency: "USD" } },
      },
    ];
    const dChildIntent = () =>
      validateMissionIntent(
        JSON.stringify({
          goal: "read",
          target_resources: [R],
          expires_at: PARENT_EXP,
        }),
      );

    // First child: bucket for entry A (index 0) goes 0 -> 1 (== its cap).
    const first = createChildMission(dKernel, {
      parentId: parentRecord.id,
      intent: dChildIntent(),
      proposedAuthority: dProposal,
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
        proposedAuthority: dProposal,
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
  it("uses the child's OWN requested_derivation_limit, not the parent's", () => {
    const parent = kernel.approve({
      intent: validateMissionIntent(
        JSON.stringify({
          goal: "Pay Acme invoices for Q3",
          target_resources: [RESOURCE],
          expires_at: PARENT_EXP,
          requested_derivation_limit: 5,
        }),
      ),
      proposedAuthority: proposed(["payments:invoice.read"]),
      subject: { iss: ISS, sub: "alice" },
      approver: { iss: ISS, sub: "bob" },
      clientId: "parent-agent",
      approvalEventId: `apev-${seq++}`,
    });
    expect(parent.derivation_limit).toBe(5);

    const { child } = createChild(parent.id, ["payments:invoice.read"], {
      intentOver: { requested_derivation_limit: 2 },
    });
    // The child's cap is its OWN intent's value, distinct from the parent's.
    expect(child.derivation_limit).toBe(2);
    expect(child.derivation_limit).not.toBe(parent.derivation_limit);
  });

  it("a child intent omitting requested_derivation_limit gets null (unbounded), like an ordinary Mission", () => {
    const parent = kernel.approve({
      intent: validateMissionIntent(
        JSON.stringify({
          goal: "Pay Acme invoices for Q3",
          target_resources: [RESOURCE],
          expires_at: PARENT_EXP,
          requested_derivation_limit: 5,
        }),
      ),
      proposedAuthority: proposed(["payments:invoice.read"]),
      subject: { iss: ISS, sub: "alice" },
      approver: { iss: ISS, sub: "bob" },
      clientId: "parent-agent",
      approvalEventId: `apev-${seq++}`,
    });
    const { child } = createChild(parent.id, ["payments:invoice.read"]);
    expect(child.derivation_limit).toBeNull();
  });
});

describe("approval basis (@spec approval-governance#standing-consent-bases, child-delegation#child-creation)", () => {
  it("records a policy_drawdown basis, root_commitment falling back to the parent's authority_hash (no child_creation_policy reference carried)", () => {
    const parent = approveParent();
    const { child } = createChild(parent.id, ["payments:invoice.read"]);
    const persisted = kernel.get(child.id);
    expect(persisted?.approval_basis).toEqual({
      type: "policy_drawdown",
      consent_principal: { iss: ISS, sub: "bob" },
      // Without a child_creation_policy, activation carries only the event
      // identifier (@spec child-delegation#child-creation).
      activation: {
        activation_event_id: child.approval_event_id,
      },
      // The requesting principal: the PARENT's own agent, distinct from the
      // consenting human ("bob").
      activation_actor: { iss: ISS, sub: "parent-agent" },
      root_commitment: parent.authority_hash,
      // @spec mission#mission-record (#580) — the consented root was approved
      // at the PARENT's approval event: retained state, never the request.
      approved_at: parent.created_at,
    });
    // @spec child-delegation#record-requirements — the record's
    // approval_event_id is the creation's activation_event_id, never the
    // Parent Mission's approval event.
    const activationEventId = (persisted?.approval_basis.activation as { activation_event_id?: string })
      .activation_event_id;
    expect(persisted?.approval_event_id).toBe(activationEventId);
    expect(persisted?.approval_event_id).not.toBe(parent.approval_event_id);
    // The Approver IS approval_basis.consent_principal (D48/O-38
    // convergence); the record carries no separate `approver` alias (#705).
    expect(persisted).not.toHaveProperty("approver");
    expect(persisted?.approval_basis.activation_actor).not.toEqual(
      persisted?.approval_basis.consent_principal,
    );
    // Not folded into either integrity anchor: recomputing both from `intent`
    // and `authority_set` alone still matches, so approval_basis carries no
    // weight in the digests (the lock's hashing decision, made checkable).
    expect(child.intent_hash).toBe(intentHash(child.issuer, child.intent as never));
    expect(child.authority_hash).toBe(authorityHash(child.issuer, child.authority_set as never));
  });

  it("the child mission claim carries id, issuer, and parent, never approval_basis (#702)", () => {
    const parent = approveParent();
    const { child } = createChild(parent.id, ["payments:invoice.read"]);
    const claim = childMissionClaim(kernel, kernel.get(child.id) as MissionRecord);
    expect(Object.keys(claim).sort()).toEqual(["id", "issuer", "parent"]);
  });

  it("discloses the child's approval_basis.type via introspection only to a privileged caller", () => {
    const parent = approveParent();
    const { child } = createChild(parent.id, ["payments:invoice.read"]);
    const fresh = kernel.get(child.id) as MissionRecord;
    const privileged = kernel.introspectionProjection(fresh, { disclose: new Set(["provenance"]) });
    expect(privileged.approval_basis).toEqual({ type: "policy_drawdown" });
    const unprivileged = kernel.introspectionProjection(fresh, { disclose: new Set() });
    expect(unprivileged.approval_basis).toBeUndefined();
  });

  it("uses the justifying entry's child_creation_policy digest as root_commitment when the entry carries one", () => {
    const R = "https://basis.example/mcp";
    const snapshot = { version: "1", content_type: "application/json", content: '{"rule":"one child per invoice"}' };
    const policyRef = { id: "urn:policy:child-drawdown", version: "1", digest: activationPolicyDigest(ISS, snapshot) };
    const registry: Record<string, typeof snapshot> = { "urn:policy:child-drawdown": snapshot };
    const policy = {
      policy_version: "basis-policy",
      ceiling: [
        {
          type: "mission_resource_access",
          resource: R,
          actions: ["res.read"],
          delegation: {
            max_depth: 1,
            children: {
              max_children: 5,
              child_creation_policy: policyRef,
              allowed_child_actors: [{ sub_profile: "ai_agent" }],
            },
          },
        },
      ],
    };
    const basisKernel = new MissionKernel({
      issuer: ISS,
      policy: policy as never,
      authoritySourceCatalog: testAuthoritySourceCatalog(policy.ceiling, ["parent-agent"], ["bob"]),
      statusKey: key,
      statusKid: "as-status",
      now,
      actorProfiles: aiAgents("basis-child"),
      activationPolicies: registry,
    });
    const parent = basisKernel.approve({
      intent: validateMissionIntent(
        JSON.stringify({ goal: "root", target_resources: [R], expires_at: PARENT_EXP }),
      ),
      subject: { iss: ISS, sub: "alice" },
      approver: { iss: ISS, sub: "bob" },
      clientId: "parent-agent",
      approvalEventId: `apev-basis-${seq++}`,
    });
    const { child } = createChildMission(basisKernel, {
      parentId: parent.id,
      intent: validateMissionIntent(
        JSON.stringify({ goal: "sub", target_resources: [R], expires_at: PARENT_EXP }),
      ),
      childActor: { sub: "basis-child", sub_profile: "ai_agent" },
    });
    const persisted = basisKernel.get(child.id);
    expect(persisted?.approval_basis.type).toBe("policy_drawdown");
    expect(persisted?.approval_basis.root_commitment).toBe(policyRef.digest);
    expect(persisted?.approval_basis.activation).toEqual({
      policy_id: policyRef.id,
      policy_version: policyRef.version,
      policy_digest: policyRef.digest,
      activation_event_id: child.approval_event_id,
    });
    // @spec child-delegation#record-requirements — under a child_creation_policy
    // too, the record's approval_event_id is the creation's activation_event_id,
    // never the Parent Mission's approval event.
    const policyActivationEventId = (persisted?.approval_basis.activation as { activation_event_id?: string })
      .activation_event_id;
    expect(persisted?.approval_event_id).toBe(policyActivationEventId);
    expect(persisted?.approval_event_id).not.toBe(parent.approval_event_id);

    // @spec approval-governance#activation-policy-commitment, child-delegation#child-creation —
    // the held snapshot no longer matching the committed digest (content
    // edited under the same version, a new version, or no snapshot held)
    // denies child creation with policy_denied, committing nothing.
    const intent = validateMissionIntent(
      JSON.stringify({ goal: "sub", target_resources: [R], expires_at: PARENT_EXP }),
    );
    const committed = basisKernel.allMissions().length;
    const changes: Array<typeof snapshot | undefined> = [
      { ...snapshot, content: '{"rule":"edited under the same version"}' },
      { ...snapshot, version: "2" },
      undefined,
    ];
    for (const held of changes) {
      if (held) registry["urn:policy:child-drawdown"] = held;
      else delete registry["urn:policy:child-drawdown"];
      try {
        createChildMission(basisKernel, {
          parentId: parent.id,
          intent,
          childActor: { sub: "basis-child", sub_profile: "ai_agent" },
        });
        expect.unreachable();
      } catch (e) {
        expect(e).toBeInstanceOf(ChildDelegationError);
        expect((e as ChildDelegationError).reason).toBe("policy_denied");
        expect((e as ChildDelegationError).evidence?.denial_reason).toBe("policy_denied");
      }
      expect(basisKernel.allMissions().length).toBe(committed);
    }
    // Restoring the committed snapshot admits creation again.
    registry["urn:policy:child-drawdown"] = snapshot;
    expect(
      createChildMission(basisKernel, {
        parentId: parent.id,
        intent,
        childActor: { sub: "basis-child", sub_profile: "ai_agent" },
      }).child.approval_basis.root_commitment,
    ).toBe(policyRef.digest);
  });
});

describe("requires_action_approval Common Constraint (@spec txn-authorization#applicability)", () => {
  /** A proposal restating the ceiling's constraints plus the approval requirement. */
  const gated = (actions: string[]): AuthorityEntry[] => [
    {
      type: "mission_resource_access",
      resource: RESOURCE,
      actions,
      constraints: {
        max_amount: { amount: "500.00", currency: "USD" },
        vendors: ["acme"],
        requires_action_approval: true,
      },
    },
  ];

  const approveGatedParent = (actions = ["payments:invoice.read", "payments:payment.execute"]) =>
    kernel.approve({
      intent: validateMissionIntent(
        JSON.stringify({ goal: "Pay Acme invoices for Q3", target_resources: [RESOURCE], expires_at: PARENT_EXP }),
      ),
      proposedAuthority: gated(actions),
      subject: { iss: ISS, sub: "alice" },
      approver: { iss: ISS, sub: "bob" },
      clientId: "parent-agent",
      approvalEventId: `apev-gated-${seq++}`,
    });

  it("carries the requirement onto the derived Authority Set", () => {
    const parent = approveGatedParent();
    expect(parent.authority_set[0]?.constraints?.requires_action_approval).toBe(true);
  });

  it("keeps a delegated child under the requirement even when the child's own proposal omits it", () => {
    const parent = approveGatedParent();
    const { child } = createChildMission(kernel, {
      parentId: parent.id,
      intent: childIntent(["payments:invoice.read"]),
      // The child restates max_amount/vendors but says nothing about approval.
      proposedAuthority: proposed(["payments:invoice.read"]),
      childActor: { sub: "subagent-extractor", sub_profile: "ai_agent" },
    });
    expect(child.authority_set[0]?.constraints?.requires_action_approval).toBe(true);
  });

  it("refuses a candidate entry that drops a requirement the grant carries", () => {
    const parent = approveGatedParent();
    const granted = parent.authority_set;
    const dropped: AuthorityEntry[] = [
      { ...(granted[0] as AuthorityEntry), constraints: { ...granted[0]?.constraints, requires_action_approval: false } },
    ];
    expect(isSubsetSet(dropped, granted)).toBe(false);
    // Pinned as the grant is (#249 C.3b, D989), so only the dropped requirement refuses it.
    const omitted: AuthorityEntry[] = [
      pinnedToCurrentContract({
        type: "mission_resource_access",
        resource: RESOURCE,
        actions: ["payments:invoice.read"],
        constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
      }),
    ];
    expect(isSubsetSet(omitted, granted)).toBe(false);
  });

  it("accepts a candidate that adds the requirement the grant does not carry", () => {
    const parent = approveParent();
    // The candidate carries the reference the grant carries: the payments
    // resource requires one, so a fresh approval records it (#249 C.3b, D989).
    expect(isSubsetSet(gated(["payments:invoice.read"]).map((e) => pinnedToCurrentContract(e)), parent.authority_set)).toBe(true);
  });

  it("normalizes a child entry beneath a prefix ancestor entry carrying the requirement, through the shared matcher, and leaves a sibling outside the boundary alone (#1440)", () => {
    const at = (resource: string, resource_match?: "prefix", requires?: true): AuthorityEntry => ({
      type: "mission_resource_access",
      resource,
      ...(resource_match ? { resource_match } : {}),
      actions: ["payments:invoice.read"],
      ...(requires ? { constraints: { requires_action_approval: true } } : {}),
    });
    const ancestor = at(`${RESOURCE}/invoices`, "prefix", true);
    const [finer, nested, sibling] = inheritActionApprovalRequirement(
      [at(`${RESOURCE}/invoices/inv-1`), at(`${RESOURCE}/invoices/2026`, "prefix"), at(`${RESOURCE}/invoices-archive`)],
      [ancestor],
    );
    expect(finer?.constraints?.requires_action_approval).toBe(true);
    expect(nested?.constraints?.requires_action_approval).toBe(true);
    expect(isSubsetEntry(finer as AuthorityEntry, ancestor)).toBe(true);
    expect(sibling?.constraints?.requires_action_approval).toBeUndefined();
  });
});

describe("per-child derivation limit from the committed policy state (@spec child-delegation#derivation-budget, derivation-limits#effective-limit, #1119)", () => {
  const RA = "https://limit-a.example/mcp";
  const RB = "https://limit-b.example/mcp";
  type Snapshot = { version: string; content_type: string; content: string };
  const stating = (member: Record<string, unknown>): Snapshot => ({
    version: "1",
    content_type: "application/json",
    content: JSON.stringify({ rule: "children within the entry", ...member }),
  });
  /**
   * A kernel at `deploymentCeiling` whose policy carries one delegable entry
   * per element of `snapshots` (RA, then RB), each committing that snapshot as
   * its child_creation_policy (undefined: none), and an approved parent.
   * With `store`, the kernel is file-backed, and `reopenDisabled` closes it
   * and reopens the same file and options with Derivation Limits off, as a
   * restart with the capability disabled (#2018); `k` and `child` then use
   * the reopened kernel. `reopenWithCeiling` does the same with the
   * deployment's `derivation_limit_ceiling` replaced, under the same
   * `policy_version` or the given one, as a restart after an operator edits
   * the policy (#2026). `approveParent` approves another parent on the
   * current kernel, and `childOf` creates a child under any parent. With
   * `grandchildren`, each entry's children may delegate one generation more.
   */
  function limitLineage(
    deploymentCeiling: number | null,
    snapshots: Array<Snapshot | undefined>,
    store?: { file: string },
    grandchildren = false,
  ) {
    const registry: Record<string, Snapshot> = {};
    const ceiling = snapshots.map((snapshot, i) => {
      const children: Record<string, unknown> = {
        max_children: 5,
        allowed_child_actors: [{ sub_profile: "ai_agent" }],
        ...(grandchildren ? { max_child_depth: 2 } : {}),
      };
      if (snapshot) {
        const id = `urn:policy:child-limit-${i}`;
        registry[id] = snapshot;
        children.child_creation_policy = { id, version: "1", digest: activationPolicyDigest(ISS, snapshot) };
      }
      return {
        type: "mission_resource_access",
        resource: i === 0 ? RA : RB,
        actions: ["res.read"],
        delegation: { max_depth: 1, children },
      };
    });
    const policy = { policy_version: "limit-policy", ceiling, derivation_limit_ceiling: deploymentCeiling };
    const opts: ConstructorParameters<typeof MissionKernel>[0] = {
      issuer: ISS,
      policy: policy as never,
      authoritySourceCatalog: testAuthoritySourceCatalog(policy.ceiling, ["parent-agent"], ["bob"]),
      statusKey: key,
      statusKid: "as-status",
      now,
      actorProfiles: aiAgents("limit-child", "limit-grandchild"),
      activationPolicies: registry,
      ...(store ? { store } : {}),
    };
    let k = new MissionKernel(opts);
    const approveParent = (): MissionRecord =>
      k.approve({
        intent: validateMissionIntent(
          JSON.stringify({ goal: "root", target_resources: ceiling.map((e) => e.resource), expires_at: PARENT_EXP }),
        ),
        subject: { iss: ISS, sub: "alice" },
        approver: { iss: ISS, sub: "bob" },
        clientId: "parent-agent",
        approvalEventId: `apev-limit-${seq++}`,
      });
    const parent = approveParent();
    const childOf = (parentId: string, requested?: number, resources: string[] = [RA], actor = "limit-child") =>
      createChildMission(k, {
        parentId,
        intent: validateMissionIntent(
          JSON.stringify({
            goal: "sub",
            target_resources: resources,
            expires_at: PARENT_EXP,
            ...(requested === undefined ? {} : { requested_derivation_limit: requested }),
          }),
        ),
        childActor: { sub: actor, sub_profile: "ai_agent" },
      }).child;
    const child = (requested?: number, resources: string[] = [RA]) => childOf(parent.id, requested, resources);
    const reopenDisabled = (): MissionKernel => {
      k.close();
      // A deployment without Derivation Limits sets no ceiling (#2018).
      k = new MissionKernel({ ...opts, policy: { ...policy, derivation_limit_ceiling: null } as never, derivationLimits: false });
      return k;
    };
    const reopenWithCeiling = (next: number | null, policyVersion?: string): MissionKernel => {
      k.close();
      k = new MissionKernel({
        ...opts,
        policy: { ...policy, derivation_limit_ceiling: next, ...(policyVersion ? { policy_version: policyVersion } : {}) } as never,
      });
      return k;
    };
    return {
      get k() {
        return k;
      },
      parent,
      child,
      childOf,
      approveParent,
      reopenDisabled,
      reopenWithCeiling,
    };
  }

  it("a child with no requested limit records the entry's committed figure; a larger request is capped at it and a smaller one stands, each child counting its own", () => {
    const { child } = limitLineage(null, [stating({ derivation_limit_ceiling: 3 })]);
    const unrequested = child();
    expect(unrequested.derivation_limit).toBe(3);
    expect(child(10).derivation_limit).toBe(3);
    const smaller = child(2);
    expect(smaller.derivation_limit).toBe(2);
    expect(unrequested.derivation_count).toBe(0);
    expect(smaller.derivation_count).toBe(0);
  });

  it("a deployment ceiling above the figure does not lift a child above it, and a stricter one narrows it", () => {
    const raised = limitLineage(100, [stating({ derivation_limit_ceiling: 3 })]);
    expect(raised.child().derivation_limit).toBe(3);
    expect(raised.child(50).derivation_limit).toBe(3);
    expect(limitLineage(2, [stating({ derivation_limit_ceiling: 3 })]).child().derivation_limit).toBe(2);
  });

  it("a figure stated as null, or not stated, guarantees no finite maximum (positive control)", () => {
    for (const snapshot of [stating({ derivation_limit_ceiling: null }), stating({})]) {
      const { child } = limitLineage(null, [snapshot]);
      expect(child().derivation_limit).toBeNull();
      expect(child(7).derivation_limit).toBe(7);
    }
  });

  it("the strictest committed figure binds a child drawing on several entries", () => {
    const { child } = limitLineage(null, [stating({ derivation_limit_ceiling: 3 }), stating({ derivation_limit_ceiling: 5 })]);
    expect(child(undefined, [RA, RB]).derivation_limit).toBe(3);
  });

  it("a malformed committed figure denies creation policy_denied, committing nothing", () => {
    for (const value of [0, -1, 2.5, "3", true]) {
      const { k, child } = limitLineage(null, [stating({ derivation_limit_ceiling: value })]);
      const before = k.allMissions().length;
      try {
        child();
        expect.unreachable(JSON.stringify(value));
      } catch (e) {
        expect((e as ChildDelegationError).reason, JSON.stringify(value)).toBe("policy_denied");
        expect((e as Error).message).toMatch(/states a malformed derivation_limit_ceiling/);
      }
      expect(k.allMissions().length).toBe(before);
    }
  });

  describe("the per-child figure a parent's approval rendered for an entry with no child_creation_policy is retained with it (#2026, D1249; @spec derivation-limits#effective-limit)", () => {
    let dir: string;
    beforeEach(() => {
      dir = mkdtempSync(join(tmpdir(), "child-limit-retained-"));
    });
    afterEach(() => {
      rmSync(dir, { recursive: true, force: true });
    });
    const onFile = (name = "kernel.sqlite") => ({ file: join(dir, name) });
    /** The child creation's refusal, or undefined when it created a child. */
    const refusal = (create: () => unknown): ChildDelegationError | undefined => {
      try {
        create();
      } catch (e) {
        expect(e).toBeInstanceOf(ChildDelegationError);
        return e as ChildDelegationError;
      }
      return undefined;
    };
    /** The stored figures column, read from the row. */
    const storedFigures = (k: MissionKernel, id: string): unknown =>
      (k.db.prepare("SELECT child_derivation_maxima_json AS v FROM missions WHERE id = ?").get(id) as { v: unknown }).v;
    /**
     * A store written before the figure was retained: the column is dropped
     * while the kernel is open, so the reopen that follows migrates it back
     * with no value for any row, as the upgrade of an older store does.
     */
    const asLegacyStore = (k: MissionKernel): void => {
      k.db.exec("ALTER TABLE missions DROP COLUMN child_derivation_maxima_json");
    };

    it("the approval retains the figure it renders: the deployment's ceiling for an entry with no child_creation_policy, an explicit no-finite-maximum where the deployment sets none, and no figure for an entry committing a child_creation_policy", () => {
      const lineage = limitLineage(3, [undefined, stating({ derivation_limit_ceiling: 4 })], onFile());
      expect(lineage.parent.child_derivation_maxima).toEqual([{ finite: 3 }, null]);
      // The page renders the same figure for the same entry from the same read.
      const rendered = approvalDerivationRendering({
        limit: lineage.k.resolveDerivationLimit(undefined),
        deploymentCeiling: lineage.k.resolveDerivationLimit(undefined),
        authority: lineage.parent.authority_set,
        held: () => undefined,
        asyncDelegation: false,
        progressive: false,
      });
      expect(rendered.children[0]?.lines).toContain(
        "Each child Mission created under this consent establishes its own derivation limit from its own request, never above 3.",
      );
      // Read back from the store after a restart.
      const k = lineage.reopenWithCeiling(3);
      try {
        expect(k.get(lineage.parent.id)?.child_derivation_maxima).toEqual([{ finite: 3 }, null]);
        expect(JSON.parse(String(storedFigures(k, lineage.parent.id)))).toEqual([{ finite: 3 }, null]);
      } finally {
        k.close();
      }
      expect(limitLineage(null, [undefined]).parent.child_derivation_maxima).toEqual([{ finite: null }]);
    });

    it("removing the deployment ceiling under the same policy_version leaves a later child, after a restart, at the rendered maximum; a smaller request still stands and the earlier child keeps its limit", () => {
      const lineage = limitLineage(3, [undefined], onFile());
      const first = lineage.child();
      expect(first.derivation_limit).toBe(3);
      const k = lineage.reopenWithCeiling(null);
      try {
        expect(k.policyVersion()).toBe(lineage.parent.policy_version);
        expect(k.resolveDerivationLimit(undefined)).toBeNull();
        expect(lineage.child().derivation_limit).toBe(3);
        expect(lineage.child(10).derivation_limit).toBe(3);
        expect(lineage.child(2).derivation_limit).toBe(2);
        expect(k.get(first.id)?.derivation_limit).toBe(3);
      } finally {
        k.close();
      }
    });

    it("raising the deployment ceiling under the same policy_version leaves a later child, after a restart, at the rendered maximum, whatever it requests", () => {
      const lineage = limitLineage(3, [undefined], onFile());
      const first = lineage.child();
      expect(first.derivation_limit).toBe(3);
      const k = lineage.reopenWithCeiling(10);
      try {
        expect(k.policyVersion()).toBe(lineage.parent.policy_version);
        expect(lineage.child().derivation_limit).toBe(3);
        expect(lineage.child(8).derivation_limit).toBe(3);
        expect(k.get(first.id)?.derivation_limit).toBe(3);
      } finally {
        k.close();
      }
    });

    it("a changed policy_version alone leaves the retained figure usable: with the ceiling removed or raised under a new version, a later child still records the rendered maximum", () => {
      for (const [i, next] of [null, 10].entries()) {
        const lineage = limitLineage(3, [undefined], onFile(`kernel-${i}.sqlite`));
        expect(lineage.child().derivation_limit).toBe(3);
        const k = lineage.reopenWithCeiling(next, "limit-policy-2");
        try {
          expect(k.policyVersion()).not.toBe(lineage.parent.policy_version);
          expect(lineage.child().derivation_limit, String(next)).toBe(3);
          expect(lineage.child(50).derivation_limit, String(next)).toBe(3);
        } finally {
          k.close();
        }
      }
    });

    it("a stricter deployment ceiling after a restart narrows a later child below the rendered maximum, and the earlier child keeps its limit", () => {
      const lineage = limitLineage(3, [undefined], onFile());
      const first = lineage.child();
      const k = lineage.reopenWithCeiling(2);
      try {
        expect(lineage.child().derivation_limit).toBe(2);
        expect(lineage.child(1).derivation_limit).toBe(1);
        expect(lineage.child(5).derivation_limit).toBe(2);
        expect(k.get(first.id)?.derivation_limit).toBe(3);
      } finally {
        k.close();
      }
    });

    it("an explicitly retained no-finite-maximum creates children after a restart, bounded only by the current ceiling and request (positive control for the legacy refusal)", () => {
      const lineage = limitLineage(null, [undefined], onFile());
      expect(lineage.parent.child_derivation_maxima).toEqual([{ finite: null }]);
      expect(lineage.child().derivation_limit).toBeNull();
      lineage.reopenWithCeiling(5);
      expect(lineage.child().derivation_limit).toBe(5);
      expect(lineage.child(7).derivation_limit).toBe(5);
      expect(lineage.child(2).derivation_limit).toBe(2);
      const k = lineage.reopenWithCeiling(null);
      try {
        expect(lineage.child().derivation_limit).toBeNull();
      } finally {
        k.close();
      }
    });

    it("a parent stored before the figure was retained creates no child under an entry with no child_creation_policy: refused policy_denied, committing nothing and leaving its stored approval unchanged, however the current policy matches its policy_version and derivation_limit", () => {
      const lineage = limitLineage(3, [undefined], onFile());
      expect(lineage.parent.derivation_limit).toBe(3);
      asLegacyStore(lineage.k);
      // Reopened under the very policy the parent was approved under: the same
      // policy_version, and a ceiling equal to the parent's own derivation_limit.
      const k = lineage.reopenWithCeiling(3);
      try {
        const legacy = k.get(lineage.parent.id) as MissionRecord;
        expect(legacy.child_derivation_maxima).toBeUndefined();
        expect(legacy.policy_version).toBe(k.policyVersion());
        const missions = k.allMissions().length;
        const parentCount = legacy.derivation_count;
        for (const requested of [undefined, 1, 3]) {
          const refused = refusal(() => lineage.child(requested));
          expect(refused?.reason, String(requested)).toBe("policy_denied");
          expect(refused?.message).toMatch(/is not retained, and the entry carries no child_creation_policy/);
          expect(refused?.evidence?.decision).toBe("denied");
        }
        expect(k.allMissions()).toHaveLength(missions);
        expect(k.findChildren(lineage.parent.id)).toHaveLength(0);
        expect(k.get(lineage.parent.id)?.derivation_count).toBe(parentCount);
        // Nothing is backfilled into the immutable approval.
        expect(storedFigures(k, lineage.parent.id)).toBeNull();
        expect(k.get(lineage.parent.id)).toEqual(legacy);
      } finally {
        k.close();
      }
    });

    it("the legacy refusal leaves existing children and unrelated operations alone: the earlier child keeps its limit, and an entry committing a child_creation_policy still creates children", () => {
      const lineage = limitLineage(3, [undefined, stating({ derivation_limit_ceiling: 4 })], onFile());
      const first = lineage.child();
      expect(first.derivation_limit).toBe(3);
      asLegacyStore(lineage.k);
      const k = lineage.reopenWithCeiling(10);
      try {
        expect(refusal(() => lineage.child())?.reason).toBe("policy_denied");
        const kept = k.get(first.id) as MissionRecord;
        expect(kept.state).toBe("active");
        expect(kept.derivation_limit).toBe(3);
        expect(kept.authority_set).toEqual(first.authority_set);
        expect(k.get(lineage.parent.id)?.state).toBe("active");
        // The entry committing a child_creation_policy reads its figure from
        // the snapshot, so it needs no retained figure.
        expect(lineage.child(undefined, [RB]).derivation_limit).toBe(4);
      } finally {
        k.close();
      }
    });

    it("a fresh approval of a new parent under the current policy retains the current figure and creates children again, while the legacy parent stays refused", () => {
      const lineage = limitLineage(3, [undefined], onFile());
      asLegacyStore(lineage.k);
      const k = lineage.reopenWithCeiling(5, "limit-policy-2");
      try {
        expect(refusal(() => lineage.child())?.reason).toBe("policy_denied");
        const fresh = lineage.approveParent();
        expect(fresh.child_derivation_maxima).toEqual([{ finite: 5 }]);
        expect(lineage.childOf(fresh.id).derivation_limit).toBe(5);
        expect(lineage.childOf(fresh.id, 2).derivation_limit).toBe(2);
        expect(refusal(() => lineage.child())?.reason).toBe("policy_denied");
      } finally {
        k.close();
      }
    });

    it("only a fresh human approval replaces the rendered maximum: after the ceiling is raised under the same policy_version and a restart, the earlier parent's children stay at 3, while a parent freshly approved under the raised ceiling admits children at its figure", () => {
      const lineage = limitLineage(3, [undefined], onFile());
      expect(lineage.child().derivation_limit).toBe(3);
      const k = lineage.reopenWithCeiling(5);
      try {
        const fresh = lineage.approveParent();
        expect(fresh.policy_version).toBe(lineage.parent.policy_version);
        expect(fresh.child_derivation_maxima).toEqual([{ finite: 5 }]);
        expect(lineage.childOf(fresh.id).derivation_limit).toBe(5);
        expect(lineage.child().derivation_limit).toBe(3);
        expect(lineage.child(5).derivation_limit).toBe(3);
      } finally {
        k.close();
      }
    });

    it("an entry committing a child_creation_policy is unaffected by the deployment ceiling: removed or raised under the same policy_version after a restart, its snapshot's figure still binds (control)", () => {
      const lineage = limitLineage(5, [stating({ derivation_limit_ceiling: 3 })], onFile());
      expect(lineage.parent.child_derivation_maxima).toEqual([null]);
      expect(lineage.child().derivation_limit).toBe(3);
      lineage.reopenWithCeiling(null);
      expect(lineage.child().derivation_limit).toBe(3);
      const k = lineage.reopenWithCeiling(10);
      try {
        expect(lineage.child(9).derivation_limit).toBe(3);
      } finally {
        k.close();
      }
    });

    it("a child's own children are created under the same consent: a child created after the ceiling is removed keeps the root's rendered figure, and so does its own child", () => {
      const lineage = limitLineage(3, [undefined], onFile(), true);
      const k = lineage.reopenWithCeiling(null);
      try {
        const child = lineage.child();
        expect(child.derivation_limit).toBe(3);
        expect(child.child_derivation_maxima).toEqual([{ finite: 3 }]);
        const grandchild = lineage.childOf(child.id, undefined, [RA], "limit-grandchild");
        expect(grandchild.parent?.depth).toBe(2);
        expect(grandchild.derivation_limit).toBe(3);
      } finally {
        k.close();
      }
    });

    it("a retained finite figure outlives a restart with Derivation Limits off: the next child is refused policy_denied, committing nothing, while the earlier child keeps its limit", () => {
      const lineage = limitLineage(3, [undefined], onFile());
      const first = lineage.child();
      const k = lineage.reopenDisabled();
      try {
        const missions = k.allMissions().length;
        const refused = refusal(() => lineage.child());
        expect(refused?.reason).toBe("policy_denied");
        expect(refused?.message).toMatch(/committed a per-Mission derivation limit of at most 3/);
        expect(k.allMissions()).toHaveLength(missions);
        expect(k.get(first.id)?.derivation_limit).toBe(3);
      } finally {
        k.close();
      }
    });
  });

  describe("with Derivation Limits turned off after the parent's approval (#2018 review F1; @spec derivation-limits#effective-limit)", () => {
    let dir: string;
    beforeEach(() => {
      dir = mkdtempSync(join(tmpdir(), "child-limit-off-"));
    });
    afterEach(() => {
      rmSync(dir, { recursive: true, force: true });
    });

    it("a finite per-child maximum the parent committed outlives the restart: with the capability on the child records it, and after a restart with it off the next child is refused policy_denied, committing nothing, while the earlier child keeps its limit", () => {
      const lineage = limitLineage(null, [stating({ derivation_limit_ceiling: 3 })], { file: join(dir, "kernel.sqlite") });
      const first = lineage.child();
      expect(first.derivation_limit).toBe(3);
      const k = lineage.reopenDisabled();
      try {
        const before = k.allMissions().length;
        const parentCount = k.get(lineage.parent.id)?.derivation_count;
        try {
          lineage.child();
          expect.unreachable();
        } catch (e) {
          expect(e).toBeInstanceOf(ChildDelegationError);
          expect((e as ChildDelegationError).reason).toBe("policy_denied");
          expect((e as Error).message).toMatch(/committed a per-Mission derivation limit of at most 3/);
        }
        expect(k.allMissions()).toHaveLength(before);
        expect(k.get(lineage.parent.id)?.derivation_count).toBe(parentCount);
        // The Mission created before the restart keeps its own finite limit.
        expect(k.get(first.id)?.derivation_limit).toBe(3);
      } finally {
        k.close();
      }
    });

    it("a per-child figure guaranteeing no finite maximum still creates a child after the restart, recording no limit (positive control)", () => {
      for (const [i, snapshot] of [stating({ derivation_limit_ceiling: null }), stating({})].entries()) {
        const lineage = limitLineage(null, [snapshot], { file: join(dir, `kernel-${i}.sqlite`) });
        expect(lineage.child().derivation_limit).toBeNull();
        const k = lineage.reopenDisabled();
        try {
          const before = k.allMissions().length;
          expect(lineage.child().derivation_limit).toBeNull();
          expect(k.allMissions()).toHaveLength(before + 1);
        } finally {
          k.close();
        }
      }
    });
  });
});

describe("a Child Mission keeps its parent's original approved audiences (@spec mission#transformation-capabilities, #1503 finding 7, D733 ruling 2)", () => {
  it("a child created after the trusted mapping changes keeps the association its parent's approved entries retain, never the mapping current at its creation", () => {
    // The trusted mapping the kernel reads at an approval event: every entry
    // is assigned `mapped`, which the case changes between the two creations.
    let mapped = ["https://rs-a.test/"];
    const k = new MissionKernel({
      issuer: ISS,
      policy: DERIVATION_POLICY as never,
      authoritySourceCatalog: testAuthoritySourceCatalog(DERIVATION_POLICY.ceiling, ["parent-agent"], ["bob"]),
      statusKey: key,
      statusKid: "as-status",
      now,
      actorProfiles: CHILD_ACTORS,
      entryAudiences: () => mapped,
    });
    const parent = k.approve({
      intent: validateMissionIntent(
        JSON.stringify({ goal: "Pay Acme invoices for Q3", target_resources: [RESOURCE], expires_at: PARENT_EXP }),
      ),
      proposedAuthority: proposed(["payments:invoice.read", "payments:payment.execute"]),
      subject: { iss: ISS, sub: "alice" },
      approver: { iss: ISS, sub: "bob" },
      clientId: "parent-agent",
      approvalEventId: `apev-${seq++}`,
    });
    expect(parent.approved_audiences).toEqual(parent.authority_set.map(() => ["https://rs-a.test/"]));
    mapped = ["https://rs-a.test/", "https://rs-b.test/"];
    const { child } = createChildMission(k, {
      parentId: parent.id,
      intent: childIntent(["payments:invoice.read"]),
      proposedAuthority: proposed(["payments:invoice.read"]),
      childActor: { sub: "subagent-extractor", sub_profile: "ai_agent" },
    });
    expect(child.approved_audiences).toEqual([["https://rs-a.test/"]]);
    expect(k.get(child.id)?.approved_audiences).toEqual([["https://rs-a.test/"]]);
  });
});
