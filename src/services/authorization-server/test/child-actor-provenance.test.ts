/**
 * @spec child-delegation#fanout (inherited child-actor eligibility, #1304, D486)
 *
 * Retained child-actor provenance at derivation and in the kernel: each
 * approved entry's child-actor origin is recorded from the exact ceiling entry
 * it was derived from, apart from its delegate origin, retained with the
 * Mission (persisted and read back), carried through a second derivation
 * (template dispatch), and read fail-closed. The child-creation policy is the
 * kernel's hook, deny-all unless a deployment installs one; carryover under
 * that default is witnessed through the deferred-expansion completion over a
 * store reopened with no policy installed.
 *
 * In-memory or temporary-file stores, no network.
 */

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { activationPolicyDigest } from "@mission/core";
import { DERIVATION_POLICY, TOPOLOGY } from "@mission/demo-data";
import { type CryptoKey, generateKeyPair } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  type AuthorityEntry,
  type CarryoverManifest,
  type ChildCreationAuthorizationPolicy,
  ChildDelegationError,
  childActorRefusal,
  createChildMission,
  createTemplate,
  deriveAuthoritySetWithProvenance,
  dispatchFromTemplate,
  type DispatchPolicies,
  ExpansionDeferralStore,
  MissionKernel,
  type MissionIntent,
  TemplateStore,
  validateMissionIntent,
} from "../src/index.js";
import { aiAgents } from "./actor-profiles.helper.js";
import { testAuthoritySourceCatalog } from "./authority-source.helper.js";

const ISS = "https://as.test";
const EXP = "2099-01-01T00:00:00Z";
const R = "https://r.example/mcp";
const READ = "res.read";
const LIST = "res.list";
const MRA = "mission_resource_access" as const;

type Delegation = AuthorityEntry["delegation"];
const entry = (actions: string[], delegation?: Record<string, unknown>): AuthorityEntry => ({
  type: MRA,
  resource: R,
  actions,
  ...(delegation ? { delegation: delegation as Delegation } : {}),
});
const intent: MissionIntent = { goal: "g", target_resources: [R], expires_at: EXP };
const childrenOf = (e: AuthorityEntry | undefined) => e?.delegation?.children as Record<string, unknown> | undefined;

let statusKey: CryptoKey;
const dirs: string[] = [];
beforeAll(async () => {
  ({ privateKey: statusKey } = await generateKeyPair("ES256", { extractable: true }));
});
afterAll(() => {
  for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
});

let events = 0;
function kernelOver(
  ceiling: AuthorityEntry[],
  childCreationPolicy?: ChildCreationAuthorizationPolicy,
  file?: string,
): MissionKernel {
  return new MissionKernel({
    issuer: ISS,
    policy: { policy_version: "child-actor-1", ceiling },
    authoritySourceCatalog: testAuthoritySourceCatalog(ceiling, ["agent", "child-agent"], ["bob"]),
    statusKey,
    statusKid: "as-status",
    ...(childCreationPolicy ? { childCreationPolicy } : {}),
    ...(file ? { store: { file } } : {}),
  });
}
const approveOn = (kernel: MissionKernel, proposal: AuthorityEntry[]) =>
  kernel.approve({
    intent: validateMissionIntent(JSON.stringify({ goal: "g", target_resources: [R], expires_at: EXP })),
    proposedAuthority: proposal,
    subject: { iss: ISS, sub: "alice" },
    approver: { iss: ISS, sub: "bob" },
    clientId: "agent",
    approvalEventId: `apev-cap-${events++}`,
  });
const childOn = (kernel: MissionKernel, parentId: string, actor: string, proposal: AuthorityEntry[]) =>
  createChildMission(kernel, {
    parentId,
    intent: validateMissionIntent(JSON.stringify({ goal: "child", target_resources: [R], expires_at: EXP })),
    proposedAuthority: proposal,
    childActor: { sub: actor },
  }).child;

describe("derivation records each entry's child-actor origin, apart from its delegate origin (@spec child-delegation#fanout, #1304)", () => {
  it("a list the proposal adds over a children grant without one is kept as a restriction, and the entry's child-actor origin is policy", () => {
    const { entries, provenance, childActorProvenance } = deriveAuthoritySetWithProvenance(
      intent,
      {
        policy_version: "t",
        ceiling: [entry([READ], { max_depth: 2, allowed_delegates: [{ sub: "bob" }], children: { max_children: 2 } })],
      },
      [entry([READ], { max_depth: 2, children: { allowed_child_actors: [{ sub: "carol" }] } })],
    );
    expect(childrenOf(entries[0])?.allowed_child_actors).toEqual([{ sub: "carol" }]);
    expect(childActorProvenance).toEqual(["policy"]);
    // The delegate list came from the ceiling: one origin never establishes the other.
    expect(provenance).toEqual(["list"]);
  });

  it("an entry derived from a children grant naming its actors has the list origin, with or without a proposal list, and an empty list is kept", () => {
    const ceiling = [entry([READ], { max_depth: 2, children: { allowed_child_actors: [{ sub: "bob" }, { sub: "carol" }] } })];
    const withList = deriveAuthoritySetWithProvenance(intent, { policy_version: "t", ceiling }, [
      entry([READ], { max_depth: 2, children: { allowed_child_actors: [{ sub: "carol" }] } }),
    ]);
    const without = deriveAuthoritySetWithProvenance(intent, { policy_version: "t", ceiling }, [entry([READ])]);
    const empty = deriveAuthoritySetWithProvenance(intent, { policy_version: "t", ceiling }, [
      entry([READ], { max_depth: 2, children: { allowed_child_actors: [] } }),
    ]);
    expect(withList.childActorProvenance).toEqual(["list"]);
    expect(without.childActorProvenance).toEqual(["list"]);
    expect(childrenOf(empty.entries[0])?.allowed_child_actors).toEqual([]);
    expect(empty.childActorProvenance).toEqual(["list"]);
  });

  it("one proposal entry under overlapping ceiling entries derives entries with different child-actor origins, each recorded", () => {
    const { entries, childActorProvenance } = deriveAuthoritySetWithProvenance(
      intent,
      {
        policy_version: "t",
        ceiling: [
          entry([READ, LIST], { max_depth: 2, children: { max_children: 2 } }),
          entry([READ], { max_depth: 2, children: { max_children: 2, allowed_child_actors: [{ sub: "bob" }] } }),
        ],
      },
      [entry([READ], { max_depth: 2, children: { allowed_child_actors: [{ sub: "bob" }] } })],
    );
    expect(entries[0]).toEqual(entries[1]);
    expect(childActorProvenance).toEqual(["policy", "list"]);
  });

  it("a second derivation under a further ceiling keeps the child-actor origin the first one recorded, independently of the delegate origin", () => {
    const delegation = { max_depth: 2, allowed_delegates: [{ sub: "bob" }], children: { allowed_child_actors: [{ sub: "carol" }] } };
    const further = [entry([READ], delegation)];
    const derived = [entry([READ], delegation)];
    const kept = deriveAuthoritySetWithProvenance(intent, { policy_version: "t", ceiling: further }, derived, ["list"], ["policy"]);
    const fresh = deriveAuthoritySetWithProvenance(intent, { policy_version: "t", ceiling: further }, derived, ["list"]);
    expect(kept.childActorProvenance).toEqual(["policy"]);
    expect(kept.provenance).toEqual(["list"]);
    expect(fresh.childActorProvenance).toEqual(["list"]);
  });
});

describe("the kernel retains child-actor provenance with the Mission and reads it fail-closed (@spec child-delegation#fanout, #1304)", () => {
  const CEILING = [entry([READ], { max_depth: 2, children: { max_children: 5, max_child_depth: 2 } })];

  it("approval persists each approved entry's child-actor origin in its own column, read back from the store", () => {
    const kernel = kernelOver(CEILING);
    const mission = approveOn(kernel, [entry([READ], { max_depth: 2, children: { allowed_child_actors: [{ sub: "carol" }] } })]);
    const row = kernel.db
      .prepare("SELECT child_actor_provenance_json, eligibility_provenance_json FROM missions WHERE id = ?")
      .get(mission.id) as { child_actor_provenance_json: string; eligibility_provenance_json: string };
    expect(JSON.parse(row.child_actor_provenance_json)).toEqual(["policy"]);
    expect(JSON.parse(row.eligibility_provenance_json)).toEqual(["policy"]);
    expect(kernel.get(mission.id)?.child_actor_provenance).toEqual(["policy"]);
  });

  it("a stored value it does not recognize reads as unresolved, and no child is created under that entry", () => {
    const kernel = kernelOver(CEILING, () => true);
    const parent = approveOn(kernel, [entry([READ], { max_depth: 2, children: { allowed_child_actors: [{ sub: "carol" }] } })]);
    kernel.db.prepare("UPDATE missions SET child_actor_provenance_json = ? WHERE id = ?").run('["everyone"]', parent.id);
    expect(kernel.get(parent.id)?.child_actor_provenance).toEqual([null]);
    try {
      childOn(kernel, parent.id, "carol", [entry([READ], { max_depth: 1, children: { max_children: 1, max_child_depth: 1, allowed_child_actors: [] } })]);
      expect.unreachable();
    } catch (e) {
      expect((e as ChildDelegationError).reason).toBe("child_actor_not_allowed");
      expect((e as ChildDelegationError).evidence?.decision).toBe("denied");
    }
    expect(kernel.findChildren(parent.id)).toHaveLength(0);
  });

  it("a permitting policy creates no children grant and relaxes no control: the on-switch, max_children and max_child_depth still refuse", () => {
    const kernel = kernelOver(
      [entry([READ], { max_depth: 2, children: { max_children: 1, max_child_depth: 1 } }), entry([LIST])],
      () => true,
    );
    const parent = approveOn(kernel, [entry([READ]), entry([LIST])]);
    expect(parent.child_actor_provenance).toEqual(["policy", "list"]);
    const reasonOf = (fn: () => unknown): string => {
      try {
        fn();
      } catch (e) {
        return (e as ChildDelegationError).reason;
      }
      return "created";
    };
    // No children grant on the list entry: the policy cannot supply one.
    expect(reasonOf(() => childOn(kernel, parent.id, "carol", [entry([LIST])]))).toBe("delegation_not_permitted");
    const childEntry = entry([READ], { max_depth: 1, children: { max_children: 1, max_child_depth: 1 } });
    const child = childOn(kernel, parent.id, "carol", [childEntry]);
    // max_children 1 is full: the policy does not lift it.
    expect(reasonOf(() => childOn(kernel, parent.id, "dave", [childEntry]))).toBe("fanout_exceeded");
    // A grandchild at depth 2 exceeds max_child_depth 1: the policy does not lift it.
    expect(reasonOf(() => childOn(kernel, child.id, "erin", [entry([READ], { max_depth: 1 })]))).toBe("fanout_exceeded");
  });

  it("an entry's child_creation_policy reference admits no actor by itself: with no list and no installed policy, a verified reference still refuses", () => {
    const snapshot = { version: "1", content_type: "application/json", content: '{"rule":"one child per invoice"}' };
    const ref = { id: "urn:policy:child-drawdown", version: "1", digest: activationPolicyDigest(ISS, snapshot) };
    const ceiling = [entry([READ], { max_depth: 2, children: { max_children: 5, child_creation_policy: ref } })];
    const kernel = new MissionKernel({
      issuer: ISS,
      policy: { policy_version: "child-actor-1", ceiling },
      authoritySourceCatalog: testAuthoritySourceCatalog(ceiling, ["agent"], ["bob"]),
      statusKey,
      statusKid: "as-status",
      activationPolicies: { [ref.id]: snapshot },
    });
    const parent = approveOn(kernel, [entry([READ])]);
    expect(parent.child_actor_provenance).toEqual(["policy"]);
    try {
      childOn(kernel, parent.id, "carol", [entry([READ], { max_depth: 1, children: { max_children: 1, child_creation_policy: ref } })]);
      expect.unreachable();
    } catch (e) {
      expect((e as ChildDelegationError).reason).toBe("child_actor_not_allowed");
    }
    expect(kernel.findChildren(parent.id)).toHaveLength(0);
  });

  it("the gate asks the policy about the parent, its approved entry, the authenticated child actor and the child-generation depth, only for a policy origin", () => {
    const asked: Parameters<ChildCreationAuthorizationPolicy>[0][] = [];
    const policy: ChildCreationAuthorizationPolicy = (request) => {
      asked.push(request);
      return true;
    };
    const approved = [entry([READ], { max_depth: 2, children: {} }), entry([LIST], { max_depth: 2, children: { allowed_child_actors: [{ sub: "carol" }] } })];
    const parent = { mission: { id: "msn_p", issuer: ISS, client_id: "agent", subject: { iss: ISS, sub: "alice" } }, approved, origins: ["policy", "list"] as const };
    const actor = { sub: "carol", assertedProfile: "ai_agent" };
    expect(childActorRefusal(parent, [1], actor, 1, "creation", policy)).toBeUndefined();
    expect(asked).toHaveLength(0);
    expect(childActorRefusal(parent, [0], actor, 2, "carryover", policy)).toBeUndefined();
    expect(asked).toEqual([{ operation: "carryover", parent: parent.mission, approved: approved[0], child_actor: actor, depth: 2 }]);
  });
});

describe("a template ceiling that grants children without allowed_child_actors defers its instances to the child-creation policy (@spec child-delegation#fanout, #1304)", () => {
  // The shipped deployment ceiling: every children grant names `ai_agent`.
  const RESOURCE = DERIVATION_POLICY.ceiling[0].resource;
  const DISPATCH_POLICY_ID = "urn:policy:dispatch";
  const registry: DispatchPolicies = {
    [DISPATCH_POLICY_ID]: { version: "1", content_type: "application/json", content: '{"rule":"within the ceiling"}' },
  };
  const templateKernel = (
    childCreationPolicy?: ChildCreationAuthorizationPolicy,
    ceiling: readonly AuthorityEntry[] = DERIVATION_POLICY.ceiling,
  ) =>
    new MissionKernel({
      issuer: ISS,
      policy: { policy_version: DERIVATION_POLICY.policy_version, ceiling },
      authoritySourceCatalog: testAuthoritySourceCatalog(ceiling, ["worker", "orchestrator"], ["human-approver"]),
      statusKey,
      statusKid: "as-status",
      actorProfiles: aiAgents("tmpl-child"),
      ...(childCreationPolicy ? { childCreationPolicy } : {}),
    });
  const instanceOf = (
    kernel: MissionKernel,
    templateChildren: Record<string, unknown> = { max_children: 5, max_child_depth: 2 },
  ) => {
    const store = new TemplateStore();
    const template = createTemplate(
      store,
      {
        template_version: "tmpl-v1",
        issuer: ISS,
        approver: { iss: ISS, sub: "human-approver" },
        ceiling: [
          {
            type: MRA,
            resource: RESOURCE,
            actions: ["payments:invoice.read"],
            constraints: { vendors: ["acme"] },
            delegation: { max_depth: 2, children: templateChildren },
          },
        ],
        dispatch_policy: { id: DISPATCH_POLICY_ID, version: "1" },
        dispatchers: ["orchestrator"],
        recipients: { subjects: [{ iss: ISS, sub: "alice" }], agents: ["worker"] },
        per_instance_lifetime_s: 3600,
        max_active: 50,
        rate_per_min: 50,
        review_cadence_s: 30 * 86400,
        approval_event_id: `tmpl-ev-${events++}`,
        expires_at: "2098-12-01T00:00:00Z",
      } as never,
      { ...kernel.authoritySourceOptions(), dispatchPolicies: registry },
    );
    return dispatchFromTemplate(kernel, store, {
      templateId: template.id,
      dispatchEventId: `dsp-${events++}`,
      dispatcher: "orchestrator",
      intent: kernel.validateIntent(JSON.stringify({ goal: "read Acme invoices", target_resources: [RESOURCE], expires_at: EXP })),
      subject: { iss: ISS, sub: "alice" },
      policyVersion: DERIVATION_POLICY.policy_version,
      dispatchPolicies: registry,
    }).mission;
  };
  const childProposal = (): AuthorityEntry[] => [
    {
      type: MRA,
      resource: RESOURCE,
      actions: ["payments:invoice.read"],
      constraints: { vendors: ["acme"] },
      delegation: { max_depth: 1, children: { max_children: 1, max_child_depth: 1, allowed_child_actors: [] } } as Delegation,
    },
  ];

  it("the instance entry keeps the deployment's list but retains the policy origin, so the reference default refuses the child its list admits", () => {
    const kernel = templateKernel();
    const instance = instanceOf(kernel);
    expect(childrenOf(instance.authority_set[0])?.allowed_child_actors).toEqual([{ sub_profile: "ai_agent" }]);
    expect(instance.child_actor_provenance).toEqual(["policy"]);
    try {
      createChildMission(kernel, {
        parentId: instance.id,
        intent: validateMissionIntent(JSON.stringify({ goal: "child", target_resources: [RESOURCE], expires_at: EXP })),
        proposedAuthority: childProposal(),
        childActor: { sub: "tmpl-child" },
      });
      expect.unreachable();
    } catch (e) {
      expect((e as ChildDelegationError).reason).toBe("child_actor_not_allowed");
    }
    expect(kernel.findChildren(instance.id)).toHaveLength(0);
  });

  it("a deployment ceiling that defers keeps its policy origin through a template ceiling that names the actors", () => {
    const deferring: AuthorityEntry[] = [
      {
        type: MRA,
        resource: RESOURCE,
        actions: ["payments:invoice.read"],
        constraints: { vendors: ["acme"] },
        delegation: { max_depth: 2, children: { max_children: 5, max_child_depth: 2 } } as Delegation,
      },
    ];
    const kernel = templateKernel(undefined, deferring);
    const instance = instanceOf(kernel, { max_children: 5, max_child_depth: 2, allowed_child_actors: [{ sub_profile: "ai_agent" }] });
    expect(childrenOf(instance.authority_set[0])?.allowed_child_actors).toEqual([{ sub_profile: "ai_agent" }]);
    // The second derivation keeps the first one's policy origin: the
    // template's list only restricts it.
    expect(instance.child_actor_provenance).toEqual(["policy"]);
    try {
      createChildMission(kernel, {
        parentId: instance.id,
        intent: validateMissionIntent(JSON.stringify({ goal: "child", target_resources: [RESOURCE], expires_at: EXP })),
        proposedAuthority: childProposal(),
        childActor: { sub: "tmpl-child" },
      });
      expect.unreachable();
    } catch (e) {
      expect((e as ChildDelegationError).reason).toBe("child_actor_not_allowed");
    }
  });

  it("with a policy that permits the actor, the instance's list and the policy both admit it", () => {
    const kernel = templateKernel((request) => request.child_actor.sub === "tmpl-child");
    const instance = instanceOf(kernel);
    const { child } = createChildMission(kernel, {
      parentId: instance.id,
      intent: validateMissionIntent(JSON.stringify({ goal: "child", target_resources: [RESOURCE], expires_at: EXP })),
      proposedAuthority: childProposal(),
      childActor: { sub: "tmpl-child" },
    });
    expect(child.child_actor_provenance).toEqual(["policy"]);
  });
});

describe("carryover under the reference default (@spec child-delegation#fanout, #carryover-generations, #1304)", () => {
  it("a child created while a policy permitted it is rendered as a cascade once no policy is installed, and completion creates no replacement", () => {
    const dir = mkdtempSync(join(tmpdir(), "child-actor-"));
    dirs.push(dir);
    const file = join(dir, "kernel.sqlite");
    // Classified, shipped actions, so the expansion approval floor admits them.
    const RESOURCE = DERIVATION_POLICY.ceiling[0].resource;
    const LEDGER = TOPOLOGY.resources.saas;
    const read = (delegation?: Record<string, unknown>): AuthorityEntry => ({
      type: MRA,
      resource: RESOURCE,
      actions: ["payments:invoice.read"],
      constraints: { vendors: ["acme"] },
      ...(delegation ? { delegation: delegation as Delegation } : {}),
    });
    const ledger: AuthorityEntry = { type: MRA, resource: LEDGER, actions: ["ledger:vendor.read"], constraints: { vendors: ["acme"] } };
    const ceiling = [read({ max_depth: 2, children: { max_children: 5, max_child_depth: 2 } }), ledger];
    const permissive = kernelOver(ceiling, () => true, file);
    const predecessor = permissive.approve({
      intent: validateMissionIntent(JSON.stringify({ goal: "read", target_resources: [RESOURCE], expires_at: EXP })),
      proposedAuthority: [read()],
      subject: { iss: ISS, sub: "alice" },
      approver: { iss: ISS, sub: "bob" },
      clientId: "agent",
      approvalEventId: `apev-cap-${events++}`,
    });
    const child = createChildMission(permissive, {
      parentId: predecessor.id,
      intent: validateMissionIntent(JSON.stringify({ goal: "child", target_resources: [RESOURCE], expires_at: EXP })),
      proposedAuthority: [read({ max_depth: 1, children: { max_children: 1, max_child_depth: 1, allowed_child_actors: [] } })],
      childActor: { sub: "child-agent" },
    }).child;
    permissive.db.close();
    const kernel = kernelOver(ceiling, undefined, file);
    try {
      const store = new ExpansionDeferralStore(kernel, () => new Date(), {
        enabled: true,
        maxRows: null,
        exclusionPolicy: { mode: "all_or_nothing" },
        noApplicableExternalState: true,
      });
      const pending = store.open({
        predecessorId: predecessor.id,
        intent: validateMissionIntent(
          JSON.stringify({ goal: "widen to the ledger", target_resources: [RESOURCE, LEDGER], expires_at: EXP }),
        ),
        proposedAuthority: [read(), ledger],
        clientId: "agent",
        jkt: "jkt-test",
        creationRequestId: `crid-${events++}`,
      });
      store.approve(pending.deferral_code, {
        approver: { iss: ISS, sub: "bob" },
        approvalEventId: `xapev-${events++}`,
        approvedUntil: EXP,
      });
      const manifest = JSON.parse(
        (
          store.db
            .prepare("SELECT carryover_manifest_json FROM expansion_deferrals WHERE deferral_code = ?")
            .get(pending.deferral_code) as { carryover_manifest_json: string }
        ).carryover_manifest_json,
      ) as CarryoverManifest;
      expect(manifest.entries.find((e) => e.child_id === child.id)).toMatchObject({
        outcome: "cascade",
        reason: "child_actor_not_allowed",
      });
      const out = store.redeem(pending.deferral_code);
      if ("error" in out) throw new Error(`expansion failed: ${JSON.stringify(out)}`);
      const old = kernel.get(child.id);
      expect(old?.termination?.reason).toBe("parent_terminated");
      expect(old?.termination?.carried_to).toBeUndefined();
      expect(kernel.findChildren(out.successor.id)).toHaveLength(0);
    } finally {
      kernel.db.close();
    }
  });
});
