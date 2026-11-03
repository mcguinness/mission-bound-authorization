import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ApprovalFloorPolicy } from "@mission/demo-data";
import { withTransaction } from "@mission/store";
import { type CryptoKey, generateKeyPair } from "jose";
import { afterEach, beforeAll, describe, expect, it } from "vitest";
import {
  type AuthorityEntry,
  ChildDelegationError,
  createChildMission,
  createTemplate,
  dispatchFromTemplate,
  ExpansionDeferralStore,
  MissionKernel,
  type MissionRecord,
  TemplateStore,
  validateMissionIntent,
} from "../src/index.js";
import {
  adjudicateDrawdown,
  assembledCeilingOffer,
  type CeilingConsent,
  createCeilingDrawdownInCallerTx,
} from "../src/kernel/progressive.js";
import { aiAgents } from "./actor-profiles.helper.js";
import { testAuthoritySourceCatalog } from "./authority-source.helper.js";

/**
 * @spec derivation-limits#approval-rendering, derivation-limits#effective-limit
 * (#2040, D1260 ruling 3): at the human approval of a standing consent under
 * which policy creates Missions, the per-child figure the approval rendered for
 * each delegable entry with no `child_creation_policy` is retained with that
 * consent's own state, and the Missions created later under it take it, never
 * a figure read at their creation:
 * - a Progressive ceiling consent, and its re-consent at an Expansion
 *   decision: the authority a later drawdown adds;
 * - an Expansion deferral's decision: the authority its completion adds;
 * - a Mission Template consent: every dispatched instance.
 * A consent stored before the figure was retained admits no child under that
 * authority until a fresh human approval retains one (D1249's rule). Each case
 * restarts the file-backed kernel under the same `policy_version` with the
 * deployment ceiling removed or raised, on a fixed clock. The page renderings
 * are witnessed in consent-per-child-rule-endpoint.test.ts.
 */

const ISS = "https://as.test";
const R = "https://resource.test/data";
const EXP = "2027-01-01T00:00:00Z";
const NOW = new Date("2026-07-01T00:00:00Z");
const now = () => NOW;
const CHILDREN = { max_children: 5, allowed_child_actors: [{ sub_profile: "ai_agent" }], max_child_depth: 2 };
const CEILING: AuthorityEntry[] = [
  {
    type: "mission_resource_access",
    resource: R,
    actions: ["res.read", "res.list", "res.other", "res.extra"],
    delegation: { max_depth: 2, children: CHILDREN },
  },
];
/** The drawdown policy the ceiling consent commits: one added action per drawdown. */
const DRAWDOWN = {
  version: "1",
  content_type: "application/json",
  content: JSON.stringify({ max_added_actions: 1, ceiling_review_cadence_s: 30 * 86400 }),
};
const ADJUDICATION = {
  chainRateBound: { maxDrawdowns: 20, windowSeconds: 3600 },
  actionClasses: {
    "res.read": "consequential_read",
    "res.list": "consequential_read",
    "res.other": "consequential_read",
    "res.extra": "consequential_read",
  },
};
/** A Dispatch Policy stating no per-instance maximum. */
const DISPATCH = { version: "1", content_type: "application/json", content: JSON.stringify({ id: "dispatch" }) };
/** Every action classified, no floor invoked: an Expansion decision here is decided by the Approver alone. */
const FLOOR: ApprovalFloorPolicy = {
  policy_id: "test-floor",
  deployment_scope: ISS,
  floors: [],
  classification: [
    {
      type: "mission_resource_access",
      resource: R,
      actions: {
        "res.read": "consequential_read",
        "res.list": "consequential_read",
        "res.other": "consequential_read",
        "res.extra": "consequential_read",
      },
    },
  ],
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

/** One file-backed kernel store, opened at a deployment ceiling under one policy_version. */
function store() {
  const dir = mkdtempSync(join(tmpdir(), "consent-per-child-"));
  dirs.push(dir);
  const file = join(dir, "kernel.sqlite");
  return (ceiling: number | null): MissionKernel => {
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
    });
    opened.push(k);
    return k;
  };
}

const intent = (goal = "read") =>
  validateMissionIntent(JSON.stringify({ goal, target_resources: [R], expires_at: EXP }), { now: NOW });
/** One proposed entry per element, each naming its actions. */
const proposal = (...groups: string[][]): AuthorityEntry[] =>
  groups.map((actions) => ({ type: "mission_resource_access", resource: R, actions }));

/** The ceiling the approval surface offers, assembled as the page renders it. */
const offer = (k: MissionKernel): CeilingConsent =>
  assembledCeilingOffer({ authority_ceiling: CEILING, drawdown_policy: { id: "draw", version: "1" } }, k.resourceContracts()) as CeilingConsent;

/** A human approval of `groups`, with the ceiling consent when `progressive`. */
const approve = (k: MissionKernel, groups: string[][], progressive = false): MissionRecord =>
  k.approve({
    intent: intent(),
    proposedAuthority: proposal(...groups),
    subject: { iss: ISS, sub: "alice" },
    approver: { iss: ISS, sub: "bob" },
    clientId: "agent",
    approvalEventId: crypto.randomUUID(),
    ...(progressive ? { ceiling: offer(k) } : {}),
  });

/** A policy-adjudicated ceiling drawdown of `predecessor` to `groups`. */
const drawdown = (k: MissionKernel, predecessor: MissionRecord, groups: string[][]): MissionRecord => {
  const current = k.get(predecessor.id) as MissionRecord;
  const requested = k.deriveWithProvenance(intent(), proposal(...groups)).entries;
  const decision = adjudicateDrawdown(k, ADJUDICATION as never, { predecessor: current, requested, isCrossDomain: () => false });
  expect(decision.outcome, JSON.stringify(decision)).toBe("policy");
  return withTransaction(k.db, () =>
    createCeilingDrawdownInCallerTx(k, {
      predecessorId: predecessor.id,
      intent: intent(),
      proposedAuthority: proposal(...groups),
      activationActor: { iss: ISS, sub: "agent" },
      policy: { ref: current.drawdown_policy as never, snapshot: DRAWDOWN },
      restrictionsAtAdjudication: { containment: 0, discharge: 0 },
    }),
  );
};

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

/** Removes the per-child figures a record's stored ceiling retains, as a ceiling consented before #2040. */
const asLegacyCeiling = (k: MissionKernel, record: MissionRecord): void => {
  const row = k.db.prepare("SELECT ceiling_json FROM missions WHERE id = ?").get(record.id) as { ceiling_json: string };
  const ceiling = JSON.parse(row.ceiling_json) as Record<string, unknown>;
  delete ceiling.ceiling_child_derivation_maxima;
  k.db.prepare("UPDATE missions SET ceiling_json = ? WHERE id = ?").run(JSON.stringify(ceiling), record.id);
};

/** An Expansion deferral store over `k`, its approval surface offering the ceiling re-consent. */
const deferrals = (k: MissionKernel) => new ExpansionDeferralStore(k, now, undefined, FLOOR, () => offer(k));

/** Opens and approves an Expansion of `predecessor` to `groups`, re-consenting the ceiling when `reconsent`. */
const approvedDeferral = (k: MissionKernel, predecessor: MissionRecord, groups: string[][], reconsent = false): string => {
  const store = deferrals(k);
  const code = store.open({
    predecessorId: predecessor.id,
    intent: intent(`widen ${crypto.randomUUID()}`),
    proposedAuthority: proposal(...groups),
    clientId: "agent",
    jkt: "jkt",
  }).deferral_code;
  // The approval surface renders the disclosure, retaining the re-consent offer it shows.
  store.disclosure(code);
  expect(
    store.approve(code, {
      approver: { iss: ISS, sub: "bob" },
      approvalEventId: `apev-${crypto.randomUUID()}`,
      approvedUntil: EXP,
      ...(reconsent ? { ceiling: offer(k) } : {}),
    }),
  ).toBe(true);
  return code;
};

/** Completes an approved deferral on `k`: the successor. */
const complete = (k: MissionKernel, code: string): MissionRecord => {
  const result = deferrals(k).redeem(code);
  if (!("successor" in result)) throw new Error(`completion refused: ${JSON.stringify(result)}`);
  return result.successor;
};

describe("a Progressive ceiling consent retains the per-child figure it rendered (#2040; @spec derivation-limits#approval-rendering, derivation-limits#effective-limit)", () => {
  it("the authority a drawdown adds takes the figure the ceiling consent rendered: after the ceiling is removed or raised under the same policy_version and a restart, a drawn entry retains 3 and its child records 3", () => {
    for (const next of [null, 10]) {
      const open = store();
      let k = open(3);
      const parent = approve(k, [["res.read"]], true);
      expect(parent.ceiling_child_derivation_maxima).toEqual([{ finite: 3 }]);
      k.close();
      k = open(next);
      const successor = drawdown(k, parent, [["res.read"], ["res.list"]]);
      expect(successor.child_derivation_maxima, String(next)).toEqual([{ finite: 3 }, { finite: 3 }]);
      expect(successor.ceiling_child_derivation_maxima, String(next)).toEqual([{ finite: 3 }]);
      expect(child(k, successor, ["res.list"]).derivation_limit, String(next)).toBe(3);
    }
  });

  it("a ceiling consented before the figure was retained admits no child under the authority a drawdown adds: refused policy_denied, committing nothing, while the carried entry keeps its figure", () => {
    const open = store();
    let k = open(3);
    const parent = approve(k, [["res.read"]], true);
    asLegacyCeiling(k, parent);
    k.close();
    k = open(10);
    expect(k.get(parent.id)?.ceiling_child_derivation_maxima).toBeUndefined();
    const successor = drawdown(k, parent, [["res.read"], ["res.list"]]);
    expect(successor.child_derivation_maxima).toEqual([{ finite: 3 }, null]);
    const refused = refusedChild(k, successor, ["res.list"]);
    expect(refused.reason).toBe("policy_denied");
    expect(refused.message).toMatch(/is not retained, and the entry carries no child_creation_policy/);
    expect(child(k, successor, ["res.read"]).derivation_limit).toBe(3);
  });

  it("a re-consent at an Expansion decision is a fresh ceiling consent: it retains the figure its decision rendered through the deferred completion after a restart at a raised ceiling, recovering a ceiling stored before the figure was retained, and a later drawdown's added authority takes it", () => {
    const open = store();
    let k = open(3);
    const parent = approve(k, [["res.read"]], true);
    asLegacyCeiling(k, parent);
    const code = approvedDeferral(k, parent, [["res.read"], ["res.list"]], true);
    k.close();
    k = open(10);
    const successor = complete(k, code);
    expect(successor.ceiling_child_derivation_maxima).toEqual([{ finite: 3 }]);
    const drawn = drawdown(k, successor, [["res.read"], ["res.list"], ["res.other"]]);
    expect(drawn.child_derivation_maxima).toEqual([{ finite: 3 }, { finite: 3 }, { finite: 3 }]);
    expect(child(k, drawn, ["res.other"]).derivation_limit).toBe(3);
  });
});

describe("an Expansion deferral retains the per-child figure its decision rendered (#2040; @spec derivation-limits#approval-rendering, derivation-limits#effective-limit)", () => {
  it("the authority an Expansion adds takes the figure its decision rendered: completed after the ceiling is removed or raised under the same policy_version and a restart, the added entry retains 3 and its child records 3", () => {
    for (const next of [null, 10]) {
      const open = store();
      let k = open(3);
      const parent = approve(k, [["res.read"]]);
      const code = approvedDeferral(k, parent, [["res.read"], ["res.list"]]);
      k.close();
      k = open(next);
      const successor = complete(k, code);
      expect(successor.child_derivation_maxima, String(next)).toEqual([{ finite: 3 }, { finite: 3 }]);
      expect(child(k, successor, ["res.list"]).derivation_limit, String(next)).toBe(3);
    }
  });

  it("a deferral approved before the figure was retained completes, but admits no child under the authority it adds: refused policy_denied, committing nothing, while the carried entry keeps its figure", () => {
    const open = store();
    let k = open(3);
    const parent = approve(k, [["res.read"]]);
    const code = approvedDeferral(k, parent, [["res.read"], ["res.list"]]);
    k.db.prepare("UPDATE expansion_deferrals SET decision_child_maximum_json = NULL WHERE deferral_code = ?").run(code);
    k.close();
    k = open(10);
    const successor = complete(k, code);
    expect(successor.child_derivation_maxima).toEqual([{ finite: 3 }, null]);
    expect(refusedChild(k, successor, ["res.list"]).reason).toBe("policy_denied");
    expect(child(k, successor, ["res.read"]).derivation_limit).toBe(3);
  });

  it("a deferral approved before the figure was retained that widens a carried entry leaves the widened entry unknown, never at the carried figure: [res.read] widened to one entry [res.read, res.list] retains no figure, and a child under it is refused policy_denied, committing nothing", () => {
    const open = store();
    let k = open(3);
    const parent = approve(k, [["res.read"]]);
    const code = approvedDeferral(k, parent, [["res.read", "res.list"]]);
    k.db.prepare("UPDATE expansion_deferrals SET decision_child_maximum_json = NULL WHERE deferral_code = ?").run(code);
    k.close();
    k = open(10);
    const successor = complete(k, code);
    expect(successor.child_derivation_maxima).toEqual([null]);
    expect(refusedChild(k, successor, ["res.read"]).reason).toBe("policy_denied");
    expect(refusedChild(k, successor, ["res.list"]).reason).toBe("policy_denied");
  });

  it("a fresh approval recovers it: beside a deferral approved before the figure was retained, a fresh deferral of the same Mission approved after a restart at 10 retains 10 for the authority it adds, and its child is created", () => {
    const open = store();
    let k = open(3);
    const parent = approve(k, [["res.read"]]);
    const legacy = approvedDeferral(k, parent, [["res.read"], ["res.list"]]);
    k.db.prepare("UPDATE expansion_deferrals SET decision_child_maximum_json = NULL WHERE deferral_code = ?").run(legacy);
    k.close();
    k = open(10);
    const successor = complete(k, approvedDeferral(k, parent, [["res.read"], ["res.list"]]));
    expect(successor.child_derivation_maxima).toEqual([{ finite: 3 }, { finite: 10 }]);
    expect(child(k, successor, ["res.list"]).derivation_limit).toBe(10);
  });
});

describe("a Mission Template consent retains the per-child figure it rendered (#2040; @spec derivation-limits#approval-rendering, derivation-limits#effective-limit)", () => {
  // The template store is in memory; one store stands in for a durable one
  // across each kernel restart, as the #2026 Template audit does.
  let seq = 0;
  const consent = (templates: TemplateStore, k: MissionKernel, retained: boolean) =>
    createTemplate(
      templates,
      {
        template_version: "tmpl-v1",
        issuer: ISS,
        approver: { iss: ISS, sub: "bob" },
        ceiling: CEILING,
        dispatch_policy: { id: "dispatch", version: "1" },
        dispatchers: ["orchestrator"],
        recipients: { subjects: [{ iss: ISS, sub: "alice" }], agents: ["agent"] },
        per_instance_lifetime_s: 30 * 86400,
        max_active: 50,
        rate_per_min: 50,
        review_cadence_s: 30 * 86400,
        approval_event_id: `tmpl-ev-${seq++}`,
        expires_at: EXP,
      },
      {
        ...k.authoritySourceOptions(),
        dispatchPolicies: { dispatch: DISPATCH },
        // The figure the consent page renders at this instant, as the approval surface retains it.
        ...(retained ? { ceilingChildMaxima: (entries: readonly AuthorityEntry[]) => k.establishedChildMaxima(entries) } : {}),
      },
    );
  const dispatch = (k: MissionKernel, templates: TemplateStore, templateId: string): MissionRecord =>
    dispatchFromTemplate(k, templates, {
      templateId,
      dispatchEventId: `dsp-${seq++}`,
      dispatcher: "orchestrator",
      intent: intent(),
      proposedAuthority: proposal(["res.read"]),
      subject: { iss: ISS, sub: "alice" },
      policyVersion: "same",
      dispatchPolicies: { dispatch: DISPATCH },
    }).mission;

  it("an instance dispatched after the ceiling is removed or raised under the same policy_version and a restart takes the figure the template consent rendered, and its child records 3", () => {
    for (const next of [null, 10]) {
      const open = store();
      const templates = new TemplateStore(now);
      let k = open(3);
      const template = consent(templates, k, true);
      expect(template.ceiling_child_derivation_maxima).toEqual([{ finite: 3 }]);
      k.close();
      k = open(next);
      const instance = dispatch(k, templates, template.id);
      expect(instance.child_derivation_maxima, String(next)).toEqual([{ finite: 3 }]);
      expect(child(k, instance).derivation_limit, String(next)).toBe(3);
    }
  });

  it("a template consented before the figure was retained still dispatches, but admits no child under its instance: refused policy_denied, committing nothing", () => {
    const k = store()(3);
    const templates = new TemplateStore(now);
    const template = consent(templates, k, false);
    expect(template.ceiling_child_derivation_maxima).toBeUndefined();
    const instance = dispatch(k, templates, template.id);
    expect(instance.child_derivation_maxima).toEqual([null]);
    const refused = refusedChild(k, instance);
    expect(refused.reason).toBe("policy_denied");
    expect(refused.message).toMatch(/is not retained/);
  });

  it("a fresh template consent recovers it: the same body consented again after a restart at 10 retains 10, and its instance admits a child at it", () => {
    const open = store();
    const templates = new TemplateStore(now);
    let k = open(3);
    const legacy = consent(templates, k, false);
    k.close();
    k = open(10);
    expect(refusedChild(k, dispatch(k, templates, legacy.id)).reason).toBe("policy_denied");
    const fresh = consent(templates, k, true);
    expect(fresh.ceiling_child_derivation_maxima).toEqual([{ finite: 10 }]);
    expect(child(k, dispatch(k, templates, fresh.id)).derivation_limit).toBe(10);
  });
});
