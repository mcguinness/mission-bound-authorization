import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { activationPolicyDigest } from "@mission/core";
import { type CryptoKey, generateKeyPair } from "jose";
import { afterEach, beforeAll, describe, expect, it } from "vitest";
import {
  activateGovernedPolicy,
  type AuthorityEntry,
  ChildDelegationError,
  createChildMission,
  type GovernedPolicyConsent,
  GovernedPolicyError,
  type GovernedPolicyRoot,
  governedPolicyConsentDisclosure,
  MissionKernel,
  type MissionRecord,
  recordGovernedPolicyConsent,
  type RegisteredActivationPolicy,
  validateMissionIntent,
} from "../src/index.js";
import { aiAgents } from "./actor-profiles.helper.js";

/**
 * @spec derivation-limits#approval-rendering, derivation-limits#effective-limit
 * (#2040 governed, D1278 ruling 1): the `governed_policy` standing consent.
 * The governance surface renders the root's disclosure
 * (`governedPolicyConsentDisclosure`) before the human approves: the rule for
 * the Missions the root activates, and each delegable root ceiling entry's
 * per-child rule and maximum. The consent is recorded only with the
 * commitment of that disclosure, still matching the root, the committed
 * policy state and the per-child figures; it retains the figures, and every
 * activation's children take them, never a figure read at activation. A
 * consent recorded before the figures were retained admits no child until a
 * fresh consent. Each case runs on a file-backed kernel store, restarted
 * under the same `policy_version`, on a fixed clock.
 */

const ISS = "https://as.test";
const R = "https://resource.test/data";
const DOCS = "https://resource.test/docs";
const EXP = "2027-01-01T00:00:00Z";
const NOW = new Date("2026-07-01T00:00:00Z");
const now = () => NOW;
const ROOT_ID = "urn:policy:governed-root";
const P_ID = "urn:policy:docs-children";
const snapshot = (limit: number): RegisteredActivationPolicy => ({
  version: "1",
  content_type: "application/json",
  content: JSON.stringify({ rule: "children within the entry", derivation_limit_ceiling: limit }),
});
/** The docs entry's child creation policy: valid (maximum 4), or malformed (0 is not a maximum). */
const P_VALID = snapshot(4);
const P_MALFORMED = snapshot(0);
const ref = (s: RegisteredActivationPolicy) => ({ id: P_ID, version: "1", digest: activationPolicyDigest(ISS, s) });

/** The delegable data entry, whose children take the deployment's per-child figure. */
const DATA: AuthorityEntry = {
  type: "mission_resource_access",
  resource: R,
  actions: ["res.read", "res.list"],
  delegation: { max_depth: 2, children: { max_children: 5, max_child_depth: 2, allowed_child_actors: [{ sub_profile: "ai_agent" }] } },
};
/** The delegable docs entry, whose children take the maximum its child creation policy states. */
const docs = (policy: RegisteredActivationPolicy): AuthorityEntry => ({
  type: "mission_resource_access",
  resource: DOCS,
  actions: ["doc.read"],
  delegation: { max_depth: 1, children: { max_children: 2, child_creation_policy: ref(policy) } },
});

const RULE = (n: number) =>
  `Each child Mission created under this consent establishes its own derivation limit from its own request, never above ${n}.`;
const NO_FINITE =
  "Each child Mission created under this consent establishes its own derivation limit from its own request; no finite maximum is guaranteed.";
const SCOPE =
  "This maximum is local to each child Mission: it is not a budget across the Missions this consent admits, their descendants, or their lifetimes.";
const GOVERNED =
  "Each governed Mission created under this consent establishes its own derivation limit from its own request; no finite maximum is guaranteed.";
const GOVERNED_SCOPE =
  "This maximum is local to each governed Mission: it is not a budget across the Missions this consent admits, their descendants, or their lifetimes.";
const ASYNC = "The refreshes of an async delegation family are not counted against this limit.";

const rootDoc = (ceiling: AuthorityEntry[]): GovernedPolicyRoot => ({
  admits: { clients: ["svc-agent"], subjects: ["svc-reconciler"], authority_sources: ["service_owned"] },
  authority_ceiling: ceiling,
  lifetime: { max_lifetime_s: 30 * 86400 },
  rules: { max_entries: 3 },
  recency: { ceilings: { default: 30 * 86400 }, clock_skew_s: 60 },
  classification: { standard: ["res.read", "res.list", "doc.read"] },
});

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

/**
 * One file-backed kernel store, opened at a deployment ceiling under one
 * policy_version. `held` is the activation policy registry, by reference, so
 * a case withdraws and restores the docs policy in place.
 */
function store(opts: { policy?: RegisteredActivationPolicy; withDocs?: boolean } = {}) {
  const dir = mkdtempSync(join(tmpdir(), "governed-per-child-"));
  dirs.push(dir);
  const file = join(dir, "kernel.sqlite");
  const policy = opts.policy ?? P_VALID;
  const ceiling = opts.withDocs ? [DATA, docs(policy)] : [DATA];
  const held: Record<string, RegisteredActivationPolicy> = { [P_ID]: policy };
  const open = (deploymentCeiling: number | null, derivationLimits = true): MissionKernel => {
    const k = new MissionKernel({
      issuer: ISS,
      policy: { policy_version: "same", ceiling, derivation_limit_ceiling: deploymentCeiling } as never,
      authoritySourceCatalog: {
        humanPrincipals: ["dana"],
        entries: [
          {
            id: "reconciler",
            type: "service_owned",
            clients: ["svc-agent"],
            subjects: ["svc-reconciler"],
            activators: ["dana"],
            principals: ["svc-reconciler"],
            ceiling,
          },
        ],
      } as never,
      governedPolicyApproval: {
        roots: { [ROOT_ID]: { version: "1", content_type: "application/json", content: JSON.stringify(rootDoc(ceiling)) } },
        approvers: { [ROOT_ID]: ["dana"] },
      },
      activationPolicies: held,
      statusKey: key,
      statusKid: "as-status",
      now,
      actorProfiles: aiAgents("child"),
      store: { file },
      derivationLimits,
    });
    opened.push(k);
    return k;
  };
  return { open, held };
}

const ROOT = { id: ROOT_ID, version: "1" };
let seq = 0;
const disclose = (k: MissionKernel) => governedPolicyConsentDisclosure(k, ROOT);
/**
 * The human's consent, recorded with `disclosure.value` as its commitment, or,
 * without one, with the commitment of the disclosure rendered now.
 */
const consent = (k: MissionKernel, disclosure?: { value: unknown }): GovernedPolicyConsent =>
  recordGovernedPolicyConsent(k, {
    root: ROOT,
    approver: { iss: ISS, sub: "dana" },
    consentEventId: `gpce-${seq++}`,
    disclosure: (disclosure ? disclosure.value : disclose(k).commitment) as string,
  });
const intent = () => validateMissionIntent(JSON.stringify({ goal: "reconcile", target_resources: [R], expires_at: EXP }), { now: NOW });
const activate = (k: MissionKernel, consentId: string): MissionRecord =>
  activateGovernedPolicy(k, {
    consentId,
    approvalEventId: `ape-${seq++}`,
    intent: intent(),
    proposedAuthority: [{ type: "mission_resource_access", resource: R, actions: ["res.read", "res.list"] }],
    clientId: "svc-agent",
  }).mission;
const child = (k: MissionKernel, parent: MissionRecord): MissionRecord =>
  createChildMission(k, {
    parentId: parent.id,
    intent: intent(),
    proposedAuthority: [{ type: "mission_resource_access", resource: R, actions: ["res.read"] }],
    childActor: { sub: "child", sub_profile: "ai_agent" },
  }).child;

/** The child creation's refusal, after checking it committed nothing. */
const refusedChild = (k: MissionKernel, parent: MissionRecord): ChildDelegationError => {
  const missions = k.allMissions().length;
  try {
    child(k, parent);
  } catch (e) {
    expect(e).toBeInstanceOf(ChildDelegationError);
    expect(k.allMissions()).toHaveLength(missions);
    return e as ChildDelegationError;
  }
  throw new Error("expected the child creation to be refused");
};

/** The consent's refusal code, after checking nothing was written: no consent row and no root snapshot. */
const refusedConsent = (k: MissionKernel, disclosure: unknown): string => {
  const count = () => ({
    consents: (k.db.prepare("SELECT COUNT(*) AS n FROM governed_policy_consents").get() as { n: number }).n,
    roots: (k.db.prepare("SELECT COUNT(*) AS n FROM governed_policy_roots").get() as { n: number }).n,
  });
  const before = count();
  try {
    consent(k, { value: disclosure });
  } catch (e) {
    expect(e).toBeInstanceOf(GovernedPolicyError);
    expect(count()).toEqual(before);
    return (e as GovernedPolicyError).code;
  }
  throw new Error("expected the consent to be refused");
};

describe("a governed root's disclosure renders the per-child rule its consent commits (#2040 governed; @spec derivation-limits#approval-rendering, child-delegation#subtree-rendering)", () => {
  it("renders the rule for the Missions the root activates, and for each delegable root ceiling entry the per-child rule, its maximum and its local scope: the deployment's figure for an entry with no child creation policy, the maximum its policy states for one with a policy, and that no finite maximum is guaranteed where the deployment sets none", () => {
    const { open } = store({ withDocs: true });
    const finite = disclose(open(3));
    expect(finite.root).toMatchObject(ROOT);
    expect(finite.instance).toContain(GOVERNED);
    expect(finite.child_grants).toHaveLength(2);
    expect(finite.child_grants[0]?.lines).toEqual(expect.arrayContaining([RULE(3), SCOPE]));
    expect(finite.child_grants[1]?.lines).toContain(RULE(4));
    expect(finite.child_derivation_maxima).toEqual([{ finite: 3 }, null]);
    expect(finite.instance).toContain(GOVERNED_SCOPE);
    expect(finite.instance).not.toContain(ASYNC);
    const none = disclose(open(null));
    expect(none.child_grants[0]?.lines).toContain(NO_FINITE);
    expect(none.child_derivation_maxima).toEqual([{ finite: null }, null]);
    expect(none.commitment).not.toBe(finite.commitment);
  });

  it("states that refreshes of an async delegation family are not counted, for the activated Missions and each delegable entry, where the governance surface supports that transport; the statement does not change the commitment", () => {
    const k = store({ withDocs: true }).open(3);
    const withAsync = governedPolicyConsentDisclosure(k, ROOT, { asyncDelegation: true });
    expect(withAsync.instance).toContain(ASYNC);
    for (const grant of withAsync.child_grants) expect(grant.lines).toContain(ASYNC);
    expect(withAsync.commitment).toBe(disclose(k).commitment);
  });
});

describe("a governed consent requires the commitment of the disclosure it rendered, and retains its figures (#2040 governed, D1278 ruling 1; @spec derivation-limits#approval-rendering, derivation-limits#effective-limit)", () => {
  it("a consent carrying the commitment of the disclosure rendered to its approver is recorded and retains the per-child figures that disclosure showed, across a restart", () => {
    const { open } = store({ withDocs: true });
    let k = open(3);
    const recorded = consent(k);
    expect(recorded.ceiling_child_derivation_maxima).toEqual([{ finite: 3 }, null]);
    k.close();
    k = open(10);
    expect(k.governedPolicyConsents.get(recorded.consent_id)?.ceiling_child_derivation_maxima).toEqual([{ finite: 3 }, null]);
  });

  it("a consent with no commitment, or one that no longer matches the root, the policy state or the per-child figures, is refused before anything is written: no consent and no root snapshot", () => {
    const { open, held } = store({ withDocs: true });
    let k = open(3);
    expect(refusedConsent(k, undefined)).toBe("disclosure_required");
    expect(refusedConsent(k, "")).toBe("disclosure_required");
    expect(refusedConsent(k, "sha-256:not-a-rendered-disclosure")).toBe("disclosure_changed");
    // Rendered at 3; the deployment's figure is 10 after a restart under the same policy_version.
    const atThree = disclose(k).commitment;
    k.close();
    k = open(10);
    expect(refusedConsent(k, atThree)).toBe("disclosure_changed");
    // Rendered while the docs entry's policy was not held; the policy is restored before the consent.
    const kept = held[P_ID] as RegisteredActivationPolicy;
    delete held[P_ID];
    const withheld = disclose(k);
    expect(withheld.child_grants[1]?.undisclosed).toContain(P_ID);
    held[P_ID] = kept;
    expect(refusedConsent(k, withheld.commitment)).toBe("disclosure_changed");
    // A fresh disclosure shows the restored rule and records the consent.
    const fresh = disclose(k);
    expect(fresh.child_grants[1]?.lines).toContain(RULE(4));
    expect(consent(k, { value: fresh.commitment }).ceiling_child_derivation_maxima).toEqual([{ finite: 10 }, null]);
  });

  it("a root whose delegable entry commits a child creation policy not held, or one stating a malformed maximum, is refused per_child_undisclosable before anything is written, even with the matching commitment", () => {
    const unheld = store({ withDocs: true });
    const k = unheld.open(3);
    delete unheld.held[P_ID];
    const shown = disclose(k);
    expect(shown.child_grants[1]?.lines.join(" ")).toContain(`child creation policy ${P_ID} version 1 is not one this issuer holds`);
    expect(refusedConsent(k, shown.commitment)).toBe("per_child_undisclosable");
    const malformed = store({ withDocs: true, policy: P_MALFORMED }).open(3);
    const bad = disclose(malformed);
    expect(bad.child_grants[1]?.lines.join(" ")).toContain(`child creation policy ${P_ID} states a malformed derivation_limit_ceiling`);
    expect(refusedConsent(malformed, bad.commitment)).toBe("per_child_undisclosable");
  });

  it("with Derivation Limits off the disclosure renders no derivation-limit rule, a root whose child creation policy is not held is consented, and the consent retains no finite maximum; on again after a restart, a child records the ceiling then current (control)", () => {
    const { open, held } = store({ withDocs: true });
    let k = open(null, false);
    delete held[P_ID];
    const shown = disclose(k);
    expect(shown.instance).toEqual([]);
    expect(shown.child_grants.flatMap((g) => g.lines).some((l) => /derivation limit/i.test(l))).toBe(false);
    const recorded = consent(k, { value: shown.commitment });
    expect(recorded.ceiling_child_derivation_maxima).toEqual([{ finite: null }, null]);
    k.close();
    held[P_ID] = P_VALID;
    k = open(5);
    expect(child(k, activate(k, recorded.consent_id)).derivation_limit).toBe(5);
  });
});

describe("a governed activation's children take the figure its consent retained (#2040 governed, D1278 ruling 1; @spec derivation-limits#effective-limit)", () => {
  it("an activation after the deployment ceiling is removed or raised under the same policy_version and a restart takes the figure the consent rendered: its entry retains 3 and its child records 3", () => {
    for (const next of [null, 10]) {
      const { open } = store();
      let k = open(3);
      const recorded = consent(k);
      k.close();
      k = open(next);
      const mission = activate(k, recorded.consent_id);
      expect(mission.child_derivation_maxima, String(next)).toEqual([{ finite: 3 }]);
      expect(child(k, mission).derivation_limit, String(next)).toBe(3);
    }
  });

  it("each child of a governed activation counts its own derivations against the retained figure: three under one child exhaust its limit of 3 and a fourth is refused derivation_cap_exhausted, while its sibling and the activated Mission count none", () => {
    const { open } = store();
    let k = open(3);
    const recorded = consent(k);
    k.close();
    k = open(10);
    const mission = activate(k, recorded.consent_id);
    const first = child(k, mission);
    const second = child(k, mission);
    for (let i = 0; i < 3; i++) k.gateDerivation(first.id);
    expect(k.get(first.id)?.derivation_count).toBe(3);
    expect(() => k.gateDerivation(first.id)).toThrow(/derivation cap exhausted/);
    expect(k.get(second.id)?.derivation_count).toBe(0);
    expect(k.get(mission.id)?.derivation_count).toBe(0);
    expect(k.gateDerivation(second.id).derivation_count).toBe(1);
  });

  it("a governed consent recorded before the figures were retained still activates, but admits no child under its entry: refused policy_denied, committing nothing", () => {
    const { open } = store();
    let k = open(3);
    const recorded = consent(k);
    k.db.prepare("UPDATE governed_policy_consents SET ceiling_child_derivation_maxima_json = NULL WHERE consent_id = ?").run(recorded.consent_id);
    k.close();
    k = open(10);
    expect(k.governedPolicyConsents.get(recorded.consent_id)?.ceiling_child_derivation_maxima).toBeUndefined();
    const mission = activate(k, recorded.consent_id);
    expect(mission.child_derivation_maxima).toEqual([null]);
    const refused = refusedChild(k, mission);
    expect(refused.reason).toBe("policy_denied");
    expect(refused.message).toMatch(/is not retained, and the entry carries no child_creation_policy/);
  });

  it("a fresh governed consent recovers it: beside a consent recorded before the figures were retained, a consent recorded after a restart at 10 retains 10, and an activation under it admits a child at it", () => {
    const { open } = store();
    let k = open(3);
    const legacy = consent(k);
    k.db.prepare("UPDATE governed_policy_consents SET ceiling_child_derivation_maxima_json = NULL WHERE consent_id = ?").run(legacy.consent_id);
    k.close();
    k = open(10);
    expect(refusedChild(k, activate(k, legacy.consent_id)).reason).toBe("policy_denied");
    const fresh = consent(k);
    expect(fresh.ceiling_child_derivation_maxima).toEqual([{ finite: 10 }]);
    expect(child(k, activate(k, fresh.consent_id)).derivation_limit).toBe(10);
  });
});
