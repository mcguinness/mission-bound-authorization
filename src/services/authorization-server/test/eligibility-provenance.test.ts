/**
 * @spec resource-access#delegate-eligibility (inherited eligibility, #1275, D457)
 * @spec resource-access#subset (the `allowed_delegates` bullet)
 *
 * Retained eligibility provenance at derivation and in the kernel: each
 * approved entry's origin is recorded from the exact ceiling entry it was
 * derived from, retained with the Mission (persisted and read back), carried
 * into entries derived from it, and resolved from a presented credential's
 * entries, failing closed where an origin is missing or ambiguous. The
 * delegation-authorization policy is the kernel's hook, deny-all unless a
 * deployment (here, the test) installs one.
 *
 * Pure, in-memory, no network.
 */

import { type CryptoKey, generateKeyPair } from "jose";
import { beforeAll, describe, expect, it } from "vitest";
import {
  type AuthorityEntry,
  createChildMission,
  type DelegationAuthorizationPolicy,
  type DelegationPolicyRequest,
  deriveAuthoritySetWithProvenance,
  isSubsetEntry,
  MissionKernel,
  type MissionIntent,
  validateMissionIntent,
} from "../src/index.js";
import { testAuthoritySourceCatalog } from "./authority-source.helper.js";

const ISS = "https://as.test";
const EXP = "2099-01-01T00:00:00Z";
const R = "https://r.example/mcp";
const READ = "res.read";
const LIST = "res.list";

const entry = (actions: string[], delegation?: AuthorityEntry["delegation"]): AuthorityEntry => ({
  type: "mission_resource_access",
  resource: R,
  actions,
  ...(delegation ? { delegation } : {}),
});
const intent: MissionIntent = { goal: "g", target_resources: [R], expires_at: EXP };

let statusKey: CryptoKey;
beforeAll(async () => {
  ({ privateKey: statusKey } = await generateKeyPair("ES256", { extractable: true }));
});

let events = 0;
function kernelOver(ceiling: AuthorityEntry[], delegationPolicy?: DelegationAuthorizationPolicy): MissionKernel {
  return new MissionKernel({
    issuer: ISS,
    policy: { policy_version: "eligibility-1", ceiling },
    authoritySourceCatalog: testAuthoritySourceCatalog(ceiling, ["agent", "child-agent"], ["bob"]),
    statusKey,
    statusKid: "as-status",
    ...(delegationPolicy ? { delegationPolicy } : {}),
  });
}
const approveOn = (kernel: MissionKernel, proposal: AuthorityEntry[]) =>
  kernel.approve({
    intent: validateMissionIntent(JSON.stringify({ goal: "g", target_resources: [R], expires_at: EXP })),
    proposedAuthority: proposal,
    subject: { iss: ISS, sub: "alice" },
    approver: { iss: ISS, sub: "bob" },
    clientId: "agent",
    approvalEventId: `apev-prov-${events++}`,
  });

describe("derivation records each entry's eligibility origin (@spec resource-access#delegate-eligibility)", () => {
  it("a list the proposal adds over a ceiling entry without one is kept as a restriction, and the entry's origin is policy", () => {
    const { entries, provenance } = deriveAuthoritySetWithProvenance(
      intent,
      { policy_version: "t", ceiling: [entry([READ], { max_depth: 2 })] },
      [entry([READ], { max_depth: 2, allowed_delegates: [{ sub: "carol" }] })],
    );
    expect(entries[0]?.delegation).toEqual({ max_depth: 2, allowed_delegates: [{ sub: "carol" }] });
    expect(provenance).toEqual(["policy"]);
  });

  it("an entry derived from a ceiling entry carrying allowed_delegates has the list origin, with or without a proposal list", () => {
    const ceiling = [entry([READ], { max_depth: 2, allowed_delegates: [{ sub: "bob" }, { sub: "carol" }] })];
    const withList = deriveAuthoritySetWithProvenance(intent, { policy_version: "t", ceiling }, [
      entry([READ], { max_depth: 2, allowed_delegates: [{ sub: "carol" }] }),
    ]);
    const without = deriveAuthoritySetWithProvenance(intent, { policy_version: "t", ceiling }, [entry([READ])]);
    expect(withList.provenance).toEqual(["list"]);
    expect(without.provenance).toEqual(["list"]);
  });

  it("configured mapping (no proposal) takes each entry's origin from its own ceiling entry", () => {
    const { entries, provenance } = deriveAuthoritySetWithProvenance(intent, {
      policy_version: "t",
      ceiling: [entry([READ], { max_depth: 1 }), entry([LIST], { max_depth: 1, allowed_delegates: [{ sub: "bob" }] })],
    });
    expect(entries.map((e) => e.actions)).toEqual([[READ], [LIST]]);
    expect(provenance).toEqual(["policy", "list"]);
  });

  it("one proposal entry under overlapping ceiling entries derives byte-identical entries with different origins, each recorded", () => {
    const { entries, provenance } = deriveAuthoritySetWithProvenance(
      intent,
      {
        policy_version: "t",
        ceiling: [entry([READ, LIST], { max_depth: 2 }), entry([READ], { max_depth: 2, allowed_delegates: [{ sub: "bob" }] })],
      },
      [entry([READ], { max_depth: 2, allowed_delegates: [{ sub: "bob" }] })],
    );
    expect(entries[0]).toEqual(entries[1]);
    expect(provenance).toEqual(["policy", "list"]);
  });

  it("a second derivation under a further ceiling keeps the origin the first one recorded", () => {
    const furtherCeiling = [entry([READ], { max_depth: 2, allowed_delegates: [{ sub: "carol" }] })];
    const derived = [entry([READ], { max_depth: 2, allowed_delegates: [{ sub: "carol" }] })];
    const kept = deriveAuthoritySetWithProvenance(intent, { policy_version: "t", ceiling: furtherCeiling }, derived, ["policy"]);
    const fresh = deriveAuthoritySetWithProvenance(intent, { policy_version: "t", ceiling: furtherCeiling }, derived);
    expect(kept.provenance).toEqual(["policy"]);
    expect(fresh.provenance).toEqual(["list"]);
  });

  it("the subset comparison stays structural: a list under a reference without one is a structural subset, which grants nothing", () => {
    expect(
      isSubsetEntry(
        entry([READ], { max_depth: 2, allowed_delegates: [{ sub: "carol" }] }),
        entry([READ], { max_depth: 2 }),
      ),
    ).toBe(true);
  });
});

describe("the kernel retains provenance with the Mission and resolves it at each delegated issuance (@spec resource-access#delegate-eligibility)", () => {
  it("approval persists each approved entry's origin, read back from the store", () => {
    const kernel = kernelOver([entry([READ], { max_depth: 2 }), entry([LIST], { max_depth: 2, allowed_delegates: [{ sub: "bob" }] })]);
    const mission = approveOn(kernel, [
      entry([READ], { max_depth: 2, allowed_delegates: [{ sub: "carol" }] }),
      entry([LIST]),
    ]);
    const row = kernel.db
      .prepare("SELECT eligibility_provenance_json FROM missions WHERE id = ?")
      .get(mission.id) as { eligibility_provenance_json: string };
    expect(JSON.parse(row.eligibility_provenance_json)).toEqual(["policy", "list"]);
    expect(kernel.get(mission.id)?.eligibility_provenance).toEqual(["policy", "list"]);
  });

  it("a stored value it does not recognize reads as unresolved, and that entry narrows out", () => {
    const kernel = kernelOver([entry([READ], { max_depth: 2, allowed_delegates: [{ sub: "bob" }] })], () => true);
    const mission = approveOn(kernel, [entry([READ])]);
    kernel.db.prepare("UPDATE missions SET eligibility_provenance_json = ? WHERE id = ?").run('["everyone"]', mission.id);
    const record = kernel.get(mission.id);
    if (!record) throw new Error("no Mission");
    expect(record.eligibility_provenance).toEqual([null]);
    const [decision] = kernel.delegationEligibility(record, kernel.effectiveDelegationCandidates(record), { sub: "bob" }, 1);
    expect(decision?.outcome).toBe("narrowed-out");
  });

  it("the deny-all default: without an installed policy, an entry deferring to policy is never eligible", () => {
    const kernel = kernelOver([entry([READ], { max_depth: 2 })]);
    const mission = approveOn(kernel, [entry([READ], { max_depth: 2, allowed_delegates: [{ sub: "carol" }] })]);
    const record = kernel.get(mission.id);
    if (!record) throw new Error("no Mission");
    const [decision] = kernel.delegationEligibility(record, kernel.effectiveDelegationCandidates(record), { sub: "carol" }, 1);
    expect(decision?.outcome).toBe("not-eligible");
  });

  it("the policy is asked about the Mission, the approved entry, the carried entry, the authenticated delegate and the accounted depth", () => {
    const asked: DelegationPolicyRequest[] = [];
    const kernel = kernelOver([entry([READ], { max_depth: 2 })], (request) => {
      asked.push(request);
      return true;
    });
    const mission = approveOn(kernel, [entry([READ])]);
    const record = kernel.get(mission.id);
    if (!record) throw new Error("no Mission");
    const delegate = { sub: "carol", assertedProfile: "ai_agent" };
    const [decision] = kernel.delegationEligibility(record, kernel.effectiveDelegationCandidates(record), delegate, 2);
    expect(decision?.outcome).toBe("eligible");
    expect(asked).toEqual([
      {
        mission: { id: mission.id, issuer: ISS, client_id: "agent", subject: { iss: ISS, sub: "alice" } },
        approved: record.authority_set[0],
        entry: record.authority_set[0],
        delegate,
        depth: 2,
      },
    ]);
  });

  it("a presented entry resolving to overlapping approved entries of different origins narrows out, even where the policy permits", () => {
    const kernel = kernelOver(
      [entry([READ, LIST], { max_depth: 2 }), entry([READ], { max_depth: 2, allowed_delegates: [{ sub: "bob" }] })],
      () => true,
    );
    const mission = approveOn(kernel, [entry([READ], { max_depth: 2, allowed_delegates: [{ sub: "bob" }] })]);
    const record = kernel.get(mission.id);
    if (!record) throw new Error("no Mission");
    expect(record.eligibility_provenance).toEqual(["policy", "list"]);
    // The credential's one entry folds both approved entries into one fragment.
    const projected = kernel.projectCredentialWithOrigin(record, [record.authority_set[0] as AuthorityEntry]);
    expect(projected).toHaveLength(1);
    expect(projected[0]?.origins).toHaveLength(2);
    const [decision] = kernel.delegationEligibility(record, projected, { sub: "bob" }, 1);
    expect(decision?.outcome).toBe("narrowed-out");
    // Each approved entry on its own resolves to its own origin and is eligible.
    const own = kernel.delegationEligibility(record, kernel.effectiveDelegationCandidates(record), { sub: "bob" }, 1);
    expect(own.map((d) => d.outcome)).toEqual(["eligible", "eligible"]);
  });

  it("an origin that is not an entry of the Mission Record resolves nothing and narrows out", () => {
    const kernel = kernelOver([entry([READ], { max_depth: 2, allowed_delegates: [{ sub: "bob" }] })], () => true);
    const mission = approveOn(kernel, [entry([READ])]);
    const record = kernel.get(mission.id);
    if (!record) throw new Error("no Mission");
    // A structurally equal copy is not the approved entry itself.
    const copy = structuredClone(record.authority_set[0] as AuthorityEntry);
    const [decision] = kernel.delegationEligibility(record, [{ entry: copy, origins: [copy] }], { sub: "bob" }, 1);
    expect(decision?.outcome).toBe("narrowed-out");
  });
});

describe("an entry derived from an approved entry inherits its origin (@spec resource-access#subset, resource-access#delegate-eligibility)", () => {
  const CHILDREN = { max_children: 5, max_child_depth: 2, allowed_child_actors: [{ sub: "child-agent" }] };
  const childOf = (kernel: MissionKernel, parentId: string, proposal: AuthorityEntry[]) =>
    createChildMission(kernel, {
      parentId,
      intent: validateMissionIntent(JSON.stringify({ goal: "child", target_resources: [R], expires_at: EXP })),
      proposedAuthority: proposal,
      childActor: { sub: "child-agent" },
    }).child;

  it("a Child Mission's list over a policy-deferring parent entry keeps the policy origin", () => {
    const kernel = kernelOver([entry([READ], { max_depth: 2, children: CHILDREN })]);
    const parent = approveOn(kernel, [entry([READ])]);
    const child = childOf(kernel, parent.id, [entry([READ], { max_depth: 2, allowed_delegates: [{ sub: "carol" }] })]);
    expect(child.authority_set[0]?.delegation?.allowed_delegates).toEqual([{ sub: "carol" }]);
    expect(kernel.get(child.id)?.eligibility_provenance).toEqual(["policy"]);
  });

  it("a Child Mission drawn on a parent entry whose provenance is gone retains no origin for that entry", () => {
    const kernel = kernelOver([entry([READ], { max_depth: 2, allowed_delegates: [{ sub: "carol" }], children: CHILDREN })]);
    const parent = approveOn(kernel, [entry([READ])]);
    expect(parent.eligibility_provenance).toEqual(["list"]);
    kernel.db.prepare("UPDATE missions SET eligibility_provenance_json = NULL WHERE id = ?").run(parent.id);
    const child = childOf(kernel, parent.id, [entry([READ], { max_depth: 2, allowed_delegates: [{ sub: "carol" }] })]);
    // Its own derivation alone would say list; the parent's missing origin is kept.
    expect(kernel.get(child.id)?.eligibility_provenance).toEqual([null]);
  });
});
