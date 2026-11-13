import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { withTransaction } from "@mission/store";
import { type CryptoKey, generateKeyPair } from "jose";
import { afterEach, beforeAll, describe, expect, it } from "vitest";
import {
  type AuthorityEntry,
  ChildDelegationError,
  createChildMission,
  createExpansion,
  MissionKernel,
  type MissionRecord,
  validateMissionIntent,
} from "../src/index.js";
import { adjudicateDrawdown, assembledCeilingOffer, createCeilingDrawdownInCallerTx } from "../src/kernel/progressive.js";
import { figureMaximum } from "../src/kernel/standing-consent-limit.js";
import { aiAgents } from "./actor-profiles.helper.js";
import { testAuthoritySourceCatalog } from "./authority-source.helper.js";

/**
 * @spec derivation-limits#effective-limit (#2026, D1249; owner review F1 of
 * PR #2037): a record derived from earlier authority keeps every per-child
 * figure that authority retains, even where it widens or regroups an entry.
 * An entry is bounded by each earlier entry whose authority it may carry,
 * stays unknown where any of them is unknown, and only authority no earlier
 * entry holds takes the figure the consent admitting it rendered and
 * retained (#2040): an Expansion decision's, or a Progressive ceiling
 * consent's for a drawdown. Each case restarts the file-backed kernel under
 * the same `policy_version` with the deployment ceiling raised from 3 to 10,
 * on a fixed clock.
 */

const ISS = "https://as.test";
const R = "https://resource.test/data";
const EXP = "2027-01-01T00:00:00Z";
const now = () => new Date("2026-07-01T00:00:00Z");
const CHILDREN = { max_children: 5, allowed_child_actors: [{ sub_profile: "ai_agent" }], max_child_depth: 2 };
const CEILING: AuthorityEntry[] = [
  {
    type: "mission_resource_access",
    resource: R,
    actions: ["res.read", "res.list", "res.other"],
    delegation: { max_depth: 2, children: CHILDREN },
  },
];
/** The drawdown policy the parent's ceiling consent commits: one added action per drawdown. */
const DRAWDOWN = {
  version: "1",
  content_type: "application/json",
  content: JSON.stringify({ max_added_actions: 1, ceiling_review_cadence_s: 30 * 86400 }),
};
const ADJUDICATION = {
  chainRateBound: { maxDrawdowns: 5, windowSeconds: 3600 },
  actionClasses: { "res.read": "consequential_read", "res.list": "consequential_read", "res.other": "consequential_read" },
};

let key: CryptoKey;
const dirs: string[] = [];
const opened: MissionKernel[] = [];
beforeAll(async () => {
  key = (await generateKeyPair("ES256")).privateKey;
});
afterEach(() => {
  for (const k of opened.splice(0)) {
    try {
      k.close();
    } catch {
      // already closed
    }
  }
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

/** One file-backed store, opened at a deployment ceiling, with Derivation Limits on unless `enabled` is false. */
function store() {
  const dir = mkdtempSync(join(tmpdir(), "retained-child-maximum-"));
  dirs.push(dir);
  const file = join(dir, "kernel.sqlite");
  return (ceiling: number | null, enabled = true): MissionKernel => {
    const k = new MissionKernel({
      issuer: ISS,
      policy: { policy_version: "same", ceiling: CEILING, derivation_limit_ceiling: ceiling } as never,
      authoritySourceCatalog: testAuthoritySourceCatalog(CEILING, ["agent"], ["bob"]),
      statusKey: key,
      statusKid: "as-status",
      now,
      actorProfiles: aiAgents("child"),
      activationPolicies: { draw: DRAWDOWN },
      store: { file },
      derivationLimits: enabled,
    });
    opened.push(k);
    return k;
  };
}

const intent = () => validateMissionIntent(JSON.stringify({ goal: "read", target_resources: [R], expires_at: EXP }), { now: now() });
/** One proposed entry per element, each naming its actions. */
const proposal = (...groups: string[][]): AuthorityEntry[] =>
  groups.map((actions) => ({ type: "mission_resource_access", resource: R, actions }));

/** A human approval of `groups`, with the ceiling consent when `progressive`. */
const approve = (k: MissionKernel, groups: string[][], progressive = false): MissionRecord =>
  k.approve({
    intent: intent(),
    proposedAuthority: proposal(...groups),
    subject: { iss: ISS, sub: "alice" },
    approver: { iss: ISS, sub: "bob" },
    clientId: "agent",
    approvalEventId: crypto.randomUUID(),
    ...(progressive
      ? {
          ceiling: assembledCeilingOffer(
            { authority_ceiling: CEILING, drawdown_policy: { id: "draw", version: "1" } },
            k.resourceContracts(),
          ) as never,
        }
      : {}),
  });

/** A policy-adjudicated ceiling drawdown of `predecessor` to `groups`. */
const drawdown = (k: MissionKernel, predecessor: MissionRecord, groups: string[][]): MissionRecord => {
  const requested = k.deriveWithProvenance(intent(), proposal(...groups)).entries;
  const decision = adjudicateDrawdown(k, ADJUDICATION as never, {
    predecessor: k.get(predecessor.id) as MissionRecord,
    requested,
    isCrossDomain: () => false,
  });
  expect(decision.outcome).toBe("policy");
  return withTransaction(k.db, () =>
    createCeilingDrawdownInCallerTx(k, {
      predecessorId: predecessor.id,
      intent: intent(),
      proposedAuthority: proposal(...groups),
      activationActor: { iss: ISS, sub: "agent" },
      policy: { ref: predecessor.drawdown_policy as never, snapshot: DRAWDOWN },
      restrictionsAtAdjudication: { containment: 0, discharge: 0 },
    }),
  );
};

/**
 * An Expansion of `predecessor` to `groups`, approved by a human whose
 * decision, at this kernel's instant, rendered and retained the deployment's
 * per-child figure for the authority it adds (#2040).
 */
const expand = (k: MissionKernel, predecessor: MissionRecord, groups: string[][]): MissionRecord =>
  createExpansion(k, {
    predecessorId: predecessor.id,
    intent: intent(),
    proposedAuthority: proposal(...groups),
    approver: { iss: ISS, sub: "bob" },
    approvalEventId: crypto.randomUUID(),
    approvedUntil: EXP,
    decidedChildMaximum: figureMaximum(k.resolveDerivationLimit(undefined)),
  }).successor;

/** A policy-created child of `parent` drawing on `actions`. */
const child = (k: MissionKernel, parent: MissionRecord, actions = ["res.read"]): MissionRecord =>
  createChildMission(k, {
    parentId: parent.id,
    intent: intent(),
    proposedAuthority: proposal(actions),
    childActor: { sub: "child", sub_profile: "ai_agent" },
  }).child;

/** The child creation's refusal, after checking it committed nothing. */
const refusedChild = (k: MissionKernel, parent: MissionRecord, actions?: string[]): ChildDelegationError => {
  const missions = k.allMissions().length;
  try {
    child(k, parent, actions);
  } catch (e) {
    expect(e).toBeInstanceOf(ChildDelegationError);
    expect(k.allMissions()).toHaveLength(missions);
    return e as ChildDelegationError;
  }
  throw new Error("expected the child creation to be refused");
};

/** Simulates a parent stored before the figure was retained. */
const asLegacy = (k: MissionKernel, record: MissionRecord): void => {
  k.db.prepare("UPDATE missions SET child_derivation_maxima_json = NULL WHERE id = ?").run(record.id);
};

/** Sets the per-child figures a record's stored ceiling retains; `undefined` removes them, as a ceiling consented before #2040. */
const setCeilingFigures = (k: MissionKernel, record: MissionRecord, figures: unknown): void => {
  const row = k.db.prepare("SELECT ceiling_json FROM missions WHERE id = ?").get(record.id) as { ceiling_json: string };
  const ceiling = JSON.parse(row.ceiling_json) as Record<string, unknown>;
  if (figures === undefined) delete ceiling.ceiling_child_derivation_maxima;
  else ceiling.ceiling_child_derivation_maxima = figures;
  k.db.prepare("UPDATE missions SET ceiling_json = ? WHERE id = ?").run(JSON.stringify(ceiling), record.id);
};

describe("a successor that widens or regroups an entry keeps every carried per-child bound (#2026 review F1, D1249; @spec derivation-limits#effective-limit)", () => {
  it("off at approval, on after a restart: the parent retains an explicit no-finite-maximum, and a child records the current ceiling with nothing backfilled", () => {
    const open = store();
    let k = open(null, false);
    const parent = approve(k, [["res.read"]]);
    expect(parent.child_derivation_maxima).toEqual([{ finite: null }]);
    k.close();
    k = open(5);
    expect(child(k, parent).derivation_limit).toBe(5);
    expect(k.get(parent.id)?.child_derivation_maxima).toEqual([{ finite: null }]);
  });

  it("a drawdown that widens a carried entry keeps the rendered maximum: [res.read] approved at 3 and drawn to [res.read, res.list] after a restart at 10 retains 3, and its child records 3", () => {
    const open = store();
    let k = open(3);
    const parent = approve(k, [["res.read"]], true);
    expect(parent.child_derivation_maxima).toEqual([{ finite: 3 }]);
    k.close();
    k = open(10);
    const successor = drawdown(k, parent, [["res.read", "res.list"]]);
    expect(successor.child_derivation_maxima).toEqual([{ finite: 3 }]);
    expect(child(k, successor).derivation_limit).toBe(3);
    expect(child(k, successor, ["res.list"]).derivation_limit).toBe(3);
  });

  it("a drawdown that widens an entry of a parent stored before the figure was retained stays unknown: its child is refused policy_denied, committing nothing", () => {
    const open = store();
    let k = open(3);
    const parent = approve(k, [["res.read"]], true);
    asLegacy(k, parent);
    k.close();
    k = open(10);
    const successor = drawdown(k, parent, [["res.read", "res.list"]]);
    expect(successor.child_derivation_maxima).toEqual([null]);
    const refused = refusedChild(k, successor);
    expect(refused.reason).toBe("policy_denied");
    expect(refused.message).toMatch(/is not retained, and the entry carries no child_creation_policy/);
  });

  it("an entry mixing carried and drawn authority takes no figure current at the drawdown: [res.read] approved with its ceiling at 10 and widened by a drawdown at 3 retains 10, its child records 3 under the stricter ceiling and 10 after it is raised to 20 (#2040)", () => {
    const open = store();
    let k = open(10);
    const parent = approve(k, [["res.read"]], true);
    expect(parent.child_derivation_maxima).toEqual([{ finite: 10 }]);
    expect(parent.ceiling_child_derivation_maxima).toEqual([{ finite: 10 }]);
    k.close();
    k = open(3);
    const successor = drawdown(k, parent, [["res.read", "res.list"]]);
    expect(successor.child_derivation_maxima).toEqual([{ finite: 10 }]);
    expect(child(k, successor, ["res.list"]).derivation_limit).toBe(3);
    k.close();
    k = open(20);
    expect(child(k, successor, ["res.list"]).derivation_limit).toBe(10);
  });

  it("an entry mixing carried and drawn authority is bounded by the ceiling consent's retained figure where it is the stricter: a ceiling retaining 2 bounds a widened entry carrying 10 (#2040)", () => {
    const open = store();
    let k = open(10);
    const parent = approve(k, [["res.read"]], true);
    setCeilingFigures(k, parent, [{ finite: 2 }]);
    k.close();
    k = open(20);
    const successor = drawdown(k, parent, [["res.read", "res.list"]]);
    expect(successor.child_derivation_maxima).toEqual([{ finite: 2 }]);
    expect(child(k, successor, ["res.list"]).derivation_limit).toBe(2);
  });

  it("authority a drawdown adds takes the figure its ceiling consent rendered, never the one current at the drawdown: a drawn entry no earlier entry overlaps retains 3 after a restart at 10, as the carried entry does (control)", () => {
    const open = store();
    let k = open(3);
    const parent = approve(k, [["res.read"]], true);
    expect(parent.ceiling_child_derivation_maxima).toEqual([{ finite: 3 }]);
    k.close();
    k = open(10);
    const successor = drawdown(k, parent, [["res.read"], ["res.list"]]);
    expect(successor.child_derivation_maxima).toEqual([{ finite: 3 }, { finite: 3 }]);
    expect(successor.ceiling_child_derivation_maxima).toEqual([{ finite: 3 }]);
    expect(child(k, successor, ["res.read"]).derivation_limit).toBe(3);
    expect(child(k, successor, ["res.list"]).derivation_limit).toBe(3);
  });

  it("malformed or misaligned retained state retains no figure: a child is refused policy_denied, committing nothing", () => {
    for (const value of ["oops", '[{"finite":0}]', "[]", '[{"finite":3},null]']) {
      const k = store()(3);
      const parent = approve(k, [["res.read"]]);
      k.db.prepare("UPDATE missions SET child_derivation_maxima_json = ? WHERE id = ?").run(value, parent.id);
      expect(refusedChild(k, parent).message, value).toMatch(/is not retained/);
    }
  });

  it("an Expansion of an unchanged entry keeps its rendered maximum after a restart at a raised ceiling", () => {
    const open = store();
    let k = open(3);
    const parent = approve(k, [["res.read"]]);
    k.close();
    k = open(10);
    const successor = expand(k, parent, [["res.read"]]);
    expect(successor.child_derivation_maxima).toEqual([{ finite: 3 }]);
    expect(child(k, successor).derivation_limit).toBe(3);
  });

  it("an Expansion that widens a carried entry keeps the rendered maximum after a restart at a raised ceiling", () => {
    const open = store();
    let k = open(3);
    const parent = approve(k, [["res.read"]]);
    k.close();
    k = open(10);
    const successor = expand(k, parent, [["res.read", "res.list"]]);
    expect(successor.child_derivation_maxima).toEqual([{ finite: 3 }]);
    expect(child(k, successor, ["res.list"]).derivation_limit).toBe(3);
  });

  it("partial overlap: an Expansion entry sharing one action with an earlier entry and adding another is bounded by the carried figure, for its new action too", () => {
    const open = store();
    let k = open(3);
    const parent = approve(k, [["res.read", "res.list"]]);
    k.close();
    k = open(10);
    const successor = expand(k, parent, [["res.list", "res.other"]]);
    expect(successor.child_derivation_maxima).toEqual([{ finite: 3 }]);
    expect(child(k, successor, ["res.other"]).derivation_limit).toBe(3);
  });

  it("several sources: an Expansion merging entries that retain 3 and 10 keeps the strictest, 3", () => {
    const open = store();
    let k = open(3);
    const parent = approve(k, [["res.read"]]);
    k.close();
    k = open(10);
    // The Expansion's decision at 10 retains 10 for the entry it adds.
    const added = expand(k, parent, [["res.read"], ["res.list"]]);
    expect(added.child_derivation_maxima).toEqual([{ finite: 3 }, { finite: 10 }]);
    const merged = expand(k, added, [["res.read", "res.list"]]);
    expect(merged.child_derivation_maxima).toEqual([{ finite: 3 }]);
    expect(child(k, merged, ["res.list"]).derivation_limit).toBe(3);
  });

  it("several sources, one unknown: an Expansion merging an unknown entry with one that retains 10 is unknown, and its child is refused policy_denied, committing nothing", () => {
    const open = store();
    let k = open(3);
    const parent = approve(k, [["res.read"]]);
    asLegacy(k, parent);
    k.close();
    k = open(10);
    const drawn = expand(k, parent, [["res.read"], ["res.list"]]);
    expect(drawn.child_derivation_maxima).toEqual([null, { finite: 10 }]);
    expect(child(k, drawn, ["res.list"]).derivation_limit).toBe(10);
    expect(refusedChild(k, drawn, ["res.read"]).reason).toBe("policy_denied");
    const merged = expand(k, drawn, [["res.read", "res.list"]]);
    expect(merged.child_derivation_maxima).toEqual([null]);
    expect(refusedChild(k, merged, ["res.list"]).reason).toBe("policy_denied");
  });
});
