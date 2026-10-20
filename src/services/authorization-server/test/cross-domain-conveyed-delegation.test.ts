/**
 * @spec cross-domain#conveyed-delegation (#1374)
 * @spec resource-access#delegate-eligibility (current-hop eligibility vs onward delegation)
 *
 * The `delegation` member a cross-domain grant conveys. The grant carries no
 * eligibility provenance and no way to evaluate the Mission Issuer's
 * delegation-authorization policy, so the issuer keeps an entry's `delegation`
 * only where every retained origin of its eligibility is a committed list and
 * the conveyed member is no broader than each approved entry it resolves to.
 * Otherwise the conveyed copy omits it, nested `children` grant included.
 *
 * Both branches of the one emitter: the depth-0 projection, and the depth > 0
 * continuation, where the delegation gate first decides the current grant's
 * eligibility against the approved record. The approved record and its
 * `authority_hash` never change.
 *
 * Pure, in-memory kernel, no network.
 */

import { type CryptoKey, decodeJwt, generateKeyPair } from "jose";
import { beforeAll, describe, expect, it } from "vitest";
import { conveysDelegation } from "../src/kernel/cross-domain.js";
import {
  type AuthorityEntry,
  AuthorityNarrowedToEmptyError,
  createChildMission,
  type DelegationAuthorizationPolicy,
  issueCrossDomainGrant,
  MissionKernel,
  type MissionRecord,
  RequestedAuthorityExceededError,
  validateMissionIntent,
} from "../src/index.js";
import { testAuthoritySourceCatalog } from "./authority-source.helper.js";

const ISS = "https://as.test";
const RAS = "https://ras.partner.test";
const EXP = "2099-01-01T00:00:00Z";
/** Its ceiling entry grants `delegation` with no `allowed_delegates`: eligibility defers to policy. */
const R_POLICY = "https://api.partner.test/policy";
/** Its ceiling entry commits `allowed_delegates`: eligibility is the list's. */
const R_LIST = "https://api.partner.test/list";
/** Two overlapping ceiling entries, one deferring to policy and one naming bob. */
const R_MIXED = "https://api.partner.test/mixed";
/** Two overlapping ceiling entries, each committing a list. */
const R_LISTS = "https://api.partner.test/lists";
/** Its ceiling entry grants no `delegation`: non-delegable. */
const R_NONE = "https://api.partner.test/none";
const READ = "res.read";
const LIST = "res.list";
const CHILDREN = { max_children: 5, max_child_depth: 2, allowed_child_actors: [{ sub: "child-agent" }] };

const entry = (resource: string, actions: string[], delegation?: AuthorityEntry["delegation"]): AuthorityEntry => ({
  type: "mission_resource_access",
  resource,
  actions,
  ...(delegation ? { delegation } : {}),
});

const CEILING: AuthorityEntry[] = [
  entry(R_POLICY, [READ, LIST], { max_depth: 2, children: CHILDREN }),
  entry(R_LIST, [READ, LIST], { max_depth: 2, allowed_delegates: [{ sub: "bob" }, { sub: "carol" }], children: CHILDREN }),
  entry(R_MIXED, [READ, LIST], { max_depth: 2, children: CHILDREN }),
  entry(R_MIXED, [READ], { max_depth: 2, allowed_delegates: [{ sub: "bob" }], children: CHILDREN }),
  entry(R_LISTS, [READ, LIST], { max_depth: 2, allowed_delegates: [{ sub: "bob" }, { sub: "carol" }], children: CHILDREN }),
  entry(R_LISTS, [READ], { max_depth: 2, allowed_delegates: [{ sub: "bob" }], children: CHILDREN }),
  entry(R_NONE, [READ]),
];

let signKey: CryptoKey;
beforeAll(async () => {
  ({ privateKey: signKey } = await generateKeyPair("ES256", { extractable: true }));
});

function kernelWith(delegationPolicy?: DelegationAuthorizationPolicy): MissionKernel {
  return new MissionKernel({
    issuer: ISS,
    policy: { policy_version: "conveyed-delegation-1", ceiling: CEILING },
    authoritySourceCatalog: testAuthoritySourceCatalog(CEILING, ["agent", "child-agent"], ["approver"]),
    statusKey: signKey,
    statusKid: "as-status",
    ...(delegationPolicy ? { delegationPolicy } : {}),
  });
}

let events = 0;
function approve(kernel: MissionKernel, proposal: AuthorityEntry[]): MissionRecord {
  return kernel.approve({
    intent: validateMissionIntent(
      JSON.stringify({
        goal: "Work at a partner domain",
        target_resources: [...new Set(proposal.map((e) => e.resource))],
        expires_at: EXP,
      }),
    ),
    proposedAuthority: proposal,
    subject: { iss: ISS, sub: "alice" },
    approver: { iss: ISS, sub: "approver" },
    clientId: "agent",
    approvalEventId: `apev-conveyed-${events++}`,
  });
}

type Grant = Parameters<typeof issueCrossDomainGrant>[3];
async function conveyed(kernel: MissionKernel, missionId: string, over: Partial<Grant> = {}): Promise<AuthorityEntry[]> {
  const { grant } = await issueCrossDomainGrant(kernel, signKey, "as-xd", {
    missionId,
    targetAs: RAS,
    clientId: "agent",
    cnfJkt: "jkt-agent",
    resourceToAs: () => RAS,
    ...over,
  });
  return decodeJwt(grant).authorization_details as AuthorityEntry[];
}

const ONLY = (resource: string) => (entries: AuthorityEntry[]) => entries.filter((e) => e.resource === resource);

describe("the conveyed copy keeps `delegation` only where every retained origin is a committed list (@spec cross-domain#conveyed-delegation)", () => {
  it("policy origin with a list the proposal added: the conveyed copy omits `delegation`, while the approved entry keeps its list", async () => {
    const kernel = kernelWith();
    const mission = approve(kernel, [entry(R_POLICY, [READ], { max_depth: 2, allowed_delegates: [{ sub: "carol" }] })]);
    expect(kernel.get(mission.id)?.eligibility_provenance).toEqual(["policy"]);
    const [sent] = await conveyed(kernel, mission.id);
    expect(sent).toEqual({ type: "mission_resource_access", resource: R_POLICY, actions: [READ] });
    expect(kernel.get(mission.id)?.authority_set[0]?.delegation?.allowed_delegates).toEqual([{ sub: "carol" }]);
  });

  it("policy origin with no list: the conveyed copy omits `delegation`, and with it the nested `children` grant", async () => {
    const kernel = kernelWith();
    const mission = approve(kernel, [entry(R_POLICY, [READ])]);
    // The approved entry inherits the ceiling's delegation, children grant included.
    expect(kernel.get(mission.id)?.authority_set[0]?.delegation).toEqual({ max_depth: 2, children: CHILDREN });
    const [sent] = await conveyed(kernel, mission.id);
    expect(sent).not.toHaveProperty("delegation");
    expect(JSON.stringify(sent)).not.toContain("children");
  });

  it("missing or unreadable provenance: the conveyed copy of a list-origin entry omits `delegation`", async () => {
    for (const stored of [null, '["everyone"]']) {
      const kernel = kernelWith();
      const mission = approve(kernel, [entry(R_LIST, [READ], { max_depth: 2, allowed_delegates: [{ sub: "carol" }] })]);
      expect(kernel.get(mission.id)?.eligibility_provenance).toEqual(["list"]);
      kernel.db.prepare("UPDATE missions SET eligibility_provenance_json = ? WHERE id = ?").run(stored, mission.id);
      const [sent] = await conveyed(kernel, mission.id);
      expect(sent, `stored provenance ${stored}`).not.toHaveProperty("delegation");
    }
  });

  it("list origin: the conveyed copy keeps `delegation`, equal to the approved entry's and so no wider than its list", async () => {
    const kernel = kernelWith();
    const mission = approve(kernel, [entry(R_LIST, [READ], { max_depth: 1, allowed_delegates: [{ sub: "carol" }] })]);
    const [sent] = await conveyed(kernel, mission.id);
    expect(sent?.delegation).toEqual({ max_depth: 1, allowed_delegates: [{ sub: "carol" }], children: CHILDREN });
    expect(sent?.delegation).toEqual(kernel.get(mission.id)?.authority_set[0]?.delegation);
  });

  it("overlapping approved entries keep their own origins: the policy-origin entry is conveyed without `delegation`, the list-origin entry with it", async () => {
    const kernel = kernelWith();
    const mission = approve(kernel, [entry(R_MIXED, [READ], { max_depth: 2, allowed_delegates: [{ sub: "bob" }] })]);
    expect(kernel.get(mission.id)?.eligibility_provenance).toEqual(["policy", "list"]);
    const sent = await conveyed(kernel, mission.id);
    expect(sent.map((e) => e.delegation?.allowed_delegates ?? null)).toEqual([null, [{ sub: "bob" }]]);
  });

  it("an entry the authority filter rebuilt resolves to no approved entry: its conveyed copy omits `delegation`", async () => {
    const kernel = kernelWith();
    const mission = approve(kernel, [entry(R_LIST, [READ], { max_depth: 2, allowed_delegates: [{ sub: "carol" }] })]);
    const sent = await conveyed(kernel, mission.id, { authorityFilter: (entries) => entries.map((e) => ({ ...e })) });
    expect(sent).toHaveLength(1);
    expect(sent[0]).not.toHaveProperty("delegation");
  });

  it("the approved record, its `authority_hash` and the projection's audience-scoped set are unchanged", async () => {
    const kernel = kernelWith();
    const mission = approve(kernel, [entry(R_POLICY, [READ]), entry(R_LIST, [READ])]);
    const before = structuredClone(kernel.get(mission.id));
    const { grant, audienceScoped } = await issueCrossDomainGrant(kernel, signKey, "as-xd", {
      missionId: mission.id,
      targetAs: RAS,
      clientId: "agent",
      cnfJkt: "jkt-agent",
      resourceToAs: () => RAS,
    });
    const after = kernel.get(mission.id);
    expect(after?.authority_set).toEqual(before?.authority_set);
    expect(after?.authority_hash).toBe(before?.authority_hash);
    expect(after?.eligibility_provenance).toEqual(before?.eligibility_provenance);
    expect((decodeJwt(grant).mission as { authority_hash: string }).authority_hash).toBe(before?.authority_hash);
    // The policy-origin entry is conveyed without delegation; the approved
    // entries the projection read keep theirs.
    expect((decodeJwt(grant).authorization_details as AuthorityEntry[])[0]).not.toHaveProperty("delegation");
    expect(audienceScoped.map((e) => e.delegation?.max_depth)).toEqual([2, 2]);
  });

  it("a Child Mission entry within a policy-origin and a list-origin parent entry combines to policy: omitted", async () => {
    const kernel = kernelWith();
    const parent = approve(kernel, [entry(R_MIXED, [READ], { max_depth: 2, allowed_delegates: [{ sub: "bob" }] })]);
    const { child } = createChildMission(kernel, {
      parentId: parent.id,
      intent: validateMissionIntent(JSON.stringify({ goal: "child", target_resources: [R_MIXED], expires_at: EXP })),
      proposedAuthority: [entry(R_MIXED, [READ], { max_depth: 1, allowed_delegates: [{ sub: "bob" }] })],
      childActor: { sub: "child-agent" },
    });
    // Each child entry falls within both parent entries, so each combines to policy.
    const provenance = kernel.get(child.id)?.eligibility_provenance ?? [];
    expect(provenance.length).toBeGreaterThan(0);
    expect(new Set(provenance)).toEqual(new Set(["policy"]));
    const sent = await conveyed(kernel, child.id);
    expect(sent).toHaveLength(provenance.length);
    for (const e of sent) expect(e).not.toHaveProperty("delegation");
  });

  it("a Child Mission entry within two list-origin parent entries combines to list: kept, no wider than the child's approved list", async () => {
    const kernel = kernelWith();
    const parent = approve(kernel, [entry(R_LISTS, [READ], { max_depth: 2, allowed_delegates: [{ sub: "bob" }] })]);
    expect(kernel.get(parent.id)?.eligibility_provenance).toEqual(["list", "list"]);
    const { child } = createChildMission(kernel, {
      parentId: parent.id,
      intent: validateMissionIntent(JSON.stringify({ goal: "child", target_resources: [R_LISTS], expires_at: EXP })),
      proposedAuthority: [entry(R_LISTS, [READ], { max_depth: 1, allowed_delegates: [{ sub: "bob" }] })],
      childActor: { sub: "child-agent" },
    });
    // Each child entry falls within both parent entries, so each combines to list.
    const record = kernel.get(child.id);
    const provenance = record?.eligibility_provenance ?? [];
    expect(provenance.length).toBeGreaterThan(0);
    expect(new Set(provenance)).toEqual(new Set(["list"]));
    const sent = await conveyed(kernel, child.id);
    expect(sent.map((e) => e.delegation)).toEqual(record?.authority_set.map((e) => e.delegation));
    for (const e of sent) expect(e.delegation?.allowed_delegates).toEqual([{ sub: "bob" }]);
  });
});

describe("the delegated branch, at depth above 0: the gate decides the current grant, the conveyed copy restricts only onward delegation (@spec cross-domain#conveyed-delegation)", () => {
  const atDepth1 = (sub: string) => ({ delegate: { sub }, depth: 1 });

  it("a policy-origin entry the installed policy admits at depth 1 is carried, its conveyed copy without `delegation`", async () => {
    const asked: string[] = [];
    const kernel = kernelWith((request) => {
      asked.push(request.delegate.sub);
      return request.delegate.sub === "bob";
    });
    const mission = approve(kernel, [entry(R_POLICY, [READ])]);
    const sent = await conveyed(kernel, mission.id, { delegation: atDepth1("bob") });
    expect(sent).toEqual([{ type: "mission_resource_access", resource: R_POLICY, actions: [READ] }]);
    expect(asked).toEqual(["bob"]);
  });

  it("the omission never admits what the gate excluded: a policy-denied candidate, and an unresolved one under a permitting policy, are refused before export", async () => {
    const denied = kernelWith();
    const deniedMission = approve(denied, [entry(R_POLICY, [READ])]);
    let signed = 0;
    await expect(
      conveyed(denied, deniedMission.id, { delegation: atDepth1("bob"), beforeSign: () => void signed++ }),
    ).rejects.toBeInstanceOf(AuthorityNarrowedToEmptyError);

    const permitting = kernelWith(() => true);
    const unresolved = approve(permitting, [entry(R_LIST, [READ], { max_depth: 2, allowed_delegates: [{ sub: "bob" }] })]);
    permitting.db.prepare("UPDATE missions SET eligibility_provenance_json = NULL WHERE id = ?").run(unresolved.id);
    await expect(
      conveyed(permitting, unresolved.id, { delegation: atDepth1("bob"), beforeSign: () => void signed++ }),
    ).rejects.toBeInstanceOf(AuthorityNarrowedToEmptyError);
    expect(signed).toBe(0);
  });

  it("a non-delegable entry is never carried at depth 1, whatever the policy: the omission grants nothing", async () => {
    const kernel = kernelWith(() => true);
    const mission = approve(kernel, [entry(R_POLICY, [READ]), entry(R_NONE, [READ])]);
    // The R_NONE ceiling entry grants no delegation, so the approved entry is non-delegable.
    expect(kernel.get(mission.id)?.authority_set[1]?.delegation).toBeUndefined();
    const sent = await conveyed(kernel, mission.id, { delegation: atDepth1("bob") });
    expect(sent.map((e) => e.resource)).toEqual([R_POLICY]);
  });

  it("a list-origin entry the list admits at depth 1 keeps `delegation` on the conveyed copy", async () => {
    const kernel = kernelWith();
    const mission = approve(kernel, [entry(R_LIST, [READ], { max_depth: 2, allowed_delegates: [{ sub: "bob" }] })]);
    const [sent] = await conveyed(kernel, mission.id, { delegation: atDepth1("bob") });
    expect(sent?.delegation?.allowed_delegates).toEqual([{ sub: "bob" }]);
  });

  it("a requested `authorization_details` that keeps an omitted `delegation` exceeds the conveyed copy: refused before beforeSign; a request without it is issued", async () => {
    const kernel = kernelWith((request) => request.delegate.sub === "bob");
    const mission = approve(kernel, [entry(R_POLICY, [READ])]);
    const approved = kernel.get(mission.id)?.authority_set[0] as AuthorityEntry;
    let signed = 0;
    await expect(
      conveyed(kernel, mission.id, {
        delegation: atDepth1("bob"),
        requestedAuthority: [approved],
        beforeSign: () => void signed++,
      }),
    ).rejects.toBeInstanceOf(RequestedAuthorityExceededError);
    expect(signed).toBe(0);
    const sent = await conveyed(kernel, mission.id, {
      delegation: atDepth1("bob"),
      requestedAuthority: [entry(R_POLICY, [READ])],
      authorityFilter: ONLY(R_POLICY),
    });
    expect(sent).toEqual([{ type: "mission_resource_access", resource: R_POLICY, actions: [READ] }]);
  });
});

describe("the keep test over a conveyed entry's resolved approved entries (@spec cross-domain#conveyed-delegation)", () => {
  const listed = (delegates: string[], max_depth = 2): AuthorityEntry =>
    entry(R_LIST, [READ], { max_depth, allowed_delegates: delegates.map((sub) => ({ sub })) });

  it("several list origins: kept when the conveyed member is no wider than every approved entry, omitted when wider than any one", () => {
    const conveyedEntry = listed(["bob"]);
    const wide = { entry: listed(["bob", "carol"]), origin: "list" as const };
    const narrow = { entry: listed(["bob"]), origin: "list" as const };
    expect(conveysDelegation({ entry: conveyedEntry, approved: [wide, narrow] })).toBe(true);
    expect(conveysDelegation({ entry: listed(["bob", "carol"]), approved: [wide, narrow] })).toBe(false);
    expect(conveysDelegation({ entry: listed(["bob"], 2), approved: [{ entry: listed(["bob"], 1), origin: "list" }] })).toBe(false);
  });

  it("a list and policy combination never selects the more permissive origin: omitted", () => {
    const e = listed(["bob"]);
    expect(conveysDelegation({ entry: e, approved: [{ entry: e, origin: "list" }, { entry: e, origin: "policy" }] })).toBe(false);
    expect(conveysDelegation({ entry: e, approved: [{ entry: e, origin: "policy" }] })).toBe(false);
  });

  it("an unresolved or ambiguous resolution is omitted: no approved entry, or any origin unresolved", () => {
    const e = listed(["bob"]);
    expect(conveysDelegation({ entry: e, approved: [] })).toBe(false);
    expect(conveysDelegation({ entry: e, approved: [{ entry: e, origin: "list" }, { entry: e, origin: null }] })).toBe(false);
  });

  it("a list origin whose conveyed member commits no list is omitted: absence would defer to the receiving AS's policy", () => {
    const bare = entry(R_LIST, [READ], { max_depth: 2 });
    expect(conveysDelegation({ entry: bare, approved: [{ entry: bare, origin: "list" }] })).toBe(false);
  });

  it("an entry without `delegation` has nothing to omit", () => {
    const plain = entry(R_LIST, [READ]);
    expect(conveysDelegation({ entry: plain, approved: [] })).toBe(true);
  });
});
