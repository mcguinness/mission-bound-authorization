/**
 * @spec progressive#sec-drawdown-policy (#1017, D1162): a drawdown policy is
 * versioned like approval policy, so each version commits one content. Every
 * ceiling consent and re-consent pins its policy's (issuer, id, version) to
 * the digest it commits, in the consent's own transaction; a consent naming a
 * pinned version with other content is refused and commits nothing. The pin
 * holds with no activation, across a restart, past the activation snapshots'
 * pruning, and is rebuilt from the retained consents of a store that predates
 * it.
 *
 * @spec progressive#audit-linkage (#1017, D1162): every record of a chain that
 * a policy narrowing and a re-consent shaped keeps its ceiling members, and
 * the consented ceiling each consent commitment names stays retained, through
 * a restart past the chain's audit horizon.
 *
 * Every AS is built over a file-backed kernel on a controlled clock (`now`);
 * each restart builds a new one over the same file.
 */
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CANONICAL_RESOURCE, DERIVATION_POLICY, PROGRESSIVE_PROFILE } from "@mission/demo-data";
import { withTransaction } from "@mission/store";
import { afterAll, describe, expect, it } from "vitest";
import {
  buildAuthorizationServer,
  type BuiltAs,
  createExpansion,
  type RegisteredActivationPolicy,
  validateMissionIntent,
} from "../src/index.js";
import { DrawdownPolicyVersionReuseError } from "../src/kernel/drawdown-policy-pins.js";
import {
  assembledCeilingOffer,
  type CeilingConsent,
  ceilingHash,
  consentCeiling,
  createCeilingDrawdownInCallerTx,
  type ProgressiveDrawdownOptions,
  progressiveFromProfile,
} from "../src/kernel/progressive.js";
import type { AuthorityEntry, MissionRecord } from "../src/kernel/types.js";
import { FIXTURE_BROWSER_LOGIN } from "./approval-fixture.js";

const ISSUER = "http://localhost:14869";
const TAG = "(@spec progressive#sec-drawdown-policy, #1017)";
const dirs: string[] = [];

afterAll(() => {
  for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
});

/** The payments ceiling exactly as the derivation policy states it. */
const CEILING = DERIVATION_POLICY.ceiling.filter((e) => e.resource === CANONICAL_RESOURCE) as unknown as AuthorityEntry[];
/** What each drawdown below draws: the narrowing policy retires every other ceiling action. */
const DRAWN = ["payments:invoice.read", "payments:invoice.list"];
const RETIRED = [...new Set(CEILING.flatMap((e) => e.actions))].filter((a) => !DRAWN.includes(a));

const policy = (content: Record<string, unknown>, version = "1"): RegisteredActivationPolicy => ({
  version,
  content_type: "application/json",
  content: JSON.stringify(content),
});
const STD = { max_added_actions: 1, ceiling_review_cadence_s: 2_592_000 };
const EDITED = { max_added_actions: 2, ceiling_review_cadence_s: 2_592_000 };

const reads = (actions: string[]) =>
  [{ type: "mission_resource_access", resource: CANONICAL_RESOURCE, actions, constraints: { vendors: ["acme"] } }] as unknown as AuthorityEntry[];
const BOB = { iss: ISSUER, sub: "bob" };

/** A clock a test moves, and a fresh store directory. */
function fixture() {
  const dir = mkdtempSync(join(tmpdir(), "drawdown-policy-pins-"));
  dirs.push(dir);
  const clock = { ms: Date.now() };
  return { file: join(dir, "kernel.db"), clock, now: () => new Date(clock.ms) };
}

/** An AS over `file`, reading `policies` live (the registry object is shared, as a deployment's is). */
const build = (
  file: string,
  now: () => Date,
  policies: Record<string, RegisteredActivationPolicy>,
  extra: { auditRetentionSeconds?: number; progressive?: ProgressiveDrawdownOptions } = {},
): Promise<BuiltAs> =>
  buildAuthorizationServer({
    issuer: ISSUER,
    allowHeadlessAdjudication: true,
    activationPolicies: policies,
    kernelStore: { file },
    now,
    ...extra,
  });

const intent = (as: BuiltAs, goal: string, expiresAt: string) =>
  validateMissionIntent(JSON.stringify({ goal, target_resources: [CANONICAL_RESOURCE], expires_at: expiresAt }));

/** The ceiling consent offer the approval surface assembles for `policyId`, `version`. */
const offer = (as: BuiltAs, policyId: string, version = "1", ceiling = CEILING) =>
  assembledCeilingOffer(
    { authority_ceiling: ceiling, drawdown_policy: { id: policyId, version } },
    as.kernel.resourceContracts(),
  ) as never;

/** A direct approval consenting the payments ceiling under `policyId`, `version`. */
const consent = (as: BuiltAs, policyId: string, expiresAt: string, version = "1"): MissionRecord =>
  as.kernel.approve({
    intent: intent(as, "Read Acme invoices", expiresAt),
    proposedAuthority: reads(["payments:invoice.read"]) as never,
    subject: { iss: ISSUER, sub: "alice" },
    approver: BOB,
    clientId: "ap-agent",
    approvalEventId: `apev-${crypto.randomUUID()}`,
    ceiling: offer(as, policyId, version),
  });

/** An in-ceiling successor of `predecessorId`, adjudicated under `snapshot`, drawing DRAWN. */
const drawdown = (as: BuiltAs, predecessorId: string, snapshot: RegisteredActivationPolicy, expiresAt: string): MissionRecord => {
  const pred = as.kernel.get(predecessorId) as MissionRecord;
  return withTransaction(as.kernel.db, () =>
    createCeilingDrawdownInCallerTx(as.kernel, {
      predecessorId,
      intent: intent(as, `Widen ${crypto.randomUUID()}`, expiresAt),
      proposedAuthority: reads(DRAWN),
      activationActor: { iss: ISSUER, sub: "ap-agent" },
      policy: { ref: pred.drawdown_policy as never, snapshot },
      restrictionsAtAdjudication: { containment: 0, discharge: 0 },
    }),
  );
};

/** A human-approved successor of `predecessorId` that re-consents the ceiling under `policyId`. */
const reconsent = (as: BuiltAs, predecessorId: string, policyId: string, at: Date, expiresAt: string): MissionRecord => {
  const { drawdown_count: _count, ...committed } = consentCeiling(
    ISSUER,
    as.kernel.activationPolicies(),
    offer(as, policyId),
    at.toISOString(),
    BOB,
    as.kernel.resourceContracts(),
  );
  return createExpansion(as.kernel, {
    predecessorId,
    intent: intent(as, "Read and list Acme invoices", expiresAt),
    proposedAuthority: reads(DRAWN),
    approver: BOB,
    approvalEventId: `apev-${crypto.randomUUID()}`,
    approvedUntil: expiresAt,
    ceilingReconsent: committed,
  }).successor;
};

const pins = (as: BuiltAs, policyId: string) =>
  as.kernel.db
    .prepare("SELECT version, digest FROM drawdown_policy_pins WHERE issuer = ? AND policy_id = ? ORDER BY version")
    .all(ISSUER, policyId) as Array<{ version: string; digest: string }>;

const farExpiry = (clock: { ms: number }) => new Date(clock.ms + 30 * 24 * 60 * 60 * 1000).toISOString();

/** The published Progressive deployment, offering at a fresh approval the ceiling a case sets. */
const PUBLISHED = progressiveFromProfile(PROGRESSIVE_PROFILE);
let currentOffer: CeilingConsent | undefined;
const WITH_PROGRESSIVE = { progressive: { ...PUBLISHED.options, ceilingOffer: () => currentOffer } };

/**
 * A fresh approval of an expansion of `predecessorId` that re-consents the
 * ceiling under `policyId`: the decision is recorded and the successor never
 * created. Returns the digest the re-consent committed.
 */
const reconsentDecision = (as: BuiltAs, predecessorId: string, policyId: string, expiresAt: string): string => {
  const { deferral_code: code } = as.expansionDeferrals.open({
    predecessorId,
    intent: intent(as, "Schedule Acme payments", expiresAt),
    proposedAuthority: reads(DRAWN),
    clientId: "ap-agent",
    jkt: "jkt-drawdown-policy-pins",
  });
  currentOffer = { authority_ceiling: CEILING, drawdown_policy: { id: policyId, version: "1" } } as never;
  as.expansionDeferrals.disclosure(code);
  expect(
    as.expansionDeferrals.approve(code, {
      approver: BOB,
      authentication: FIXTURE_BROWSER_LOGIN,
      approvalEventId: `apev-${crypto.randomUUID()}`,
      approvedUntil: expiresAt,
      ceiling: offer(as, policyId),
    }),
  ).toBe(true);
  const row = as.kernel.db
    .prepare("SELECT state, ceiling_reconsent_json AS reconsent FROM expansion_deferrals WHERE deferral_code = ?")
    .get(code) as { state: string; reconsent: string };
  expect(row.state).toBe("approved");
  return (JSON.parse(row.reconsent) as { drawdown_policy: { digest: string } }).drawdown_policy.digest;
};

/** Each case builds a file-backed AS once or twice. */
const SLOW = { timeout: 30_000 };

describe(`a drawdown policy version commits one content ${TAG}`, SLOW, () => {
  it(`a first consent pins its version with no activation: the unchanged content is consented again, changed content under that version is refused and commits nothing, and changed content under a new version is consented ${TAG}`, async () => {
    const { file, clock, now } = fixture();
    const policies: Record<string, RegisteredActivationPolicy> = { "drawdown-p": policy(STD) };
    const as = await build(file, now, policies);
    try {
      const first = consent(as, "drawdown-p", farExpiry(clock));
      expect(pins(as, "drawdown-p")).toEqual([{ version: "1", digest: first.drawdown_policy?.digest }]);
      // No drawdown was adjudicated: no activation snapshot exists.
      expect(as.kernel.db.prepare("SELECT COUNT(*) AS n FROM activation_policy_snapshots").get()).toEqual({ n: 0 });

      expect(consent(as, "drawdown-p", farExpiry(clock)).drawdown_policy).toEqual(first.drawdown_policy);

      policies["drawdown-p"] = policy(EDITED);
      const before = as.kernel.allMissions().length;
      expect(() => consent(as, "drawdown-p", farExpiry(clock))).toThrow(DrawdownPolicyVersionReuseError);
      expect(as.kernel.allMissions().length).toBe(before);
      expect(pins(as, "drawdown-p")).toEqual([{ version: "1", digest: first.drawdown_policy?.digest }]);

      policies["drawdown-p"] = policy(EDITED, "2");
      const moved = consent(as, "drawdown-p", farExpiry(clock), "2");
      expect(moved.drawdown_policy?.digest).not.toBe(first.drawdown_policy?.digest);
      expect(pins(as, "drawdown-p")).toEqual([
        { version: "1", digest: first.drawdown_policy?.digest },
        { version: "2", digest: moved.drawdown_policy?.digest },
      ]);
    } finally {
      as.kernel.close();
    }
  });

  it(`a re-consent pins too: a successor re-consenting a pinned version with other content is refused and creates no successor ${TAG}`, async () => {
    const { file, clock, now } = fixture();
    const policies: Record<string, RegisteredActivationPolicy> = { "drawdown-p": policy(STD) };
    const as = await build(file, now, policies);
    try {
      const root = consent(as, "drawdown-p", farExpiry(clock));
      policies["drawdown-p"] = policy(EDITED);
      const before = as.kernel.allMissions().length;
      expect(() => reconsent(as, root.id, "drawdown-p", now(), farExpiry(clock))).toThrow(DrawdownPolicyVersionReuseError);
      expect(as.kernel.allMissions().length).toBe(before);
      expect(as.kernel.get(root.id)?.state).toBe("active");
      policies["drawdown-p"] = policy(STD);
      const successor = reconsent(as, root.id, "drawdown-p", now(), farExpiry(clock));
      expect(successor.drawdown_policy).toEqual(root.drawdown_policy);
    } finally {
      as.kernel.close();
    }
  });

  it(`the pin survives a restart: an AS rebuilt over the store refuses changed content under the pinned version ${TAG}`, async () => {
    const { file, clock, now } = fixture();
    const policies: Record<string, RegisteredActivationPolicy> = { "drawdown-p": policy(STD) };
    const first = await build(file, now, policies);
    const committed = consent(first, "drawdown-p", farExpiry(clock)).drawdown_policy;
    first.kernel.close();

    clock.ms += 60_000;
    policies["drawdown-p"] = policy(EDITED);
    const second = await build(file, now, policies);
    try {
      const before = second.kernel.allMissions().length;
      expect(() => consent(second, "drawdown-p", farExpiry(clock))).toThrow(DrawdownPolicyVersionReuseError);
      expect(second.kernel.allMissions().length).toBe(before);
      policies["drawdown-p"] = policy(STD);
      expect(consent(second, "drawdown-p", farExpiry(clock)).drawdown_policy).toEqual(committed);
    } finally {
      second.kernel.close();
    }
  });

  it(`the pin survives the activation snapshots' pruning past their audit horizon ${TAG}`, async () => {
    const { file, clock, now } = fixture();
    const policies: Record<string, RegisteredActivationPolicy> = { "drawdown-p": policy(STD) };
    const soon = new Date(clock.ms + 10 * 60_000).toISOString();
    const first = await build(file, now, policies, { auditRetentionSeconds: 1 });
    const root = consent(first, "drawdown-p", soon);
    drawdown(first, root.id, policy(STD), soon);
    expect(first.kernel.db.prepare("SELECT COUNT(*) AS n FROM activation_policy_snapshots WHERE policy_id = 'drawdown-p'").get()).toEqual({ n: 1 });
    first.kernel.close();

    // An hour on: past every chain record's expiry plus the one-second audit retention.
    clock.ms += 60 * 60_000;
    policies["drawdown-p"] = policy(EDITED);
    const second = await build(file, now, policies, { auditRetentionSeconds: 1 });
    try {
      expect(second.kernel.db.prepare("SELECT COUNT(*) AS n FROM activation_policy_snapshots WHERE policy_id = 'drawdown-p'").get()).toEqual({ n: 0 });
      const before = second.kernel.allMissions().length;
      expect(() => consent(second, "drawdown-p", farExpiry(clock))).toThrow(DrawdownPolicyVersionReuseError);
      expect(second.kernel.allMissions().length).toBe(before);
    } finally {
      second.kernel.close();
    }
  });

  it(`a store without pins pins a version an unredeemed re-consent alone committed to that re-consent's content ${TAG}`, async () => {
    const { file, clock, now } = fixture();
    const policies: Record<string, RegisteredActivationPolicy> = {
      ...PUBLISHED.policies,
      "drawdown-q": policy(STD),
      "drawdown-p": policy(STD),
    };
    const first = await build(file, now, policies, WITH_PROGRESSIVE);
    const root = consent(first, "drawdown-q", farExpiry(clock));
    const recorded = reconsentDecision(first, root.id, "drawdown-p", farExpiry(clock));
    // No Mission record carries the re-consented policy: the decision is its only record.
    expect(first.kernel.allMissions().some((m) => m.drawdown_policy?.id === "drawdown-p")).toBe(false);
    first.kernel.db.prepare("DELETE FROM drawdown_policy_pins").run();
    first.kernel.close();

    policies["drawdown-p"] = policy(EDITED);
    const second = await build(file, now, policies, WITH_PROGRESSIVE);
    try {
      expect(pins(second, "drawdown-p")).toEqual([{ version: "1", digest: recorded }]);
      expect(() => consent(second, "drawdown-p", farExpiry(clock))).toThrow(DrawdownPolicyVersionReuseError);
      policies["drawdown-p"] = policy(STD);
      expect(consent(second, "drawdown-p", farExpiry(clock)).drawdown_policy?.digest).toBe(recorded);
    } finally {
      second.kernel.close();
    }
  });

  it(`a store without pins pins a version two consents committed with different contents to the earliest consent's, across both sources: an earlier unredeemed re-consent wins over a later root consent ${TAG}`, async () => {
    const { file, clock, now } = fixture();
    const policies: Record<string, RegisteredActivationPolicy> = {
      ...PUBLISHED.policies,
      "drawdown-q": policy(STD),
      "drawdown-p": policy(STD),
    };
    const first = await build(file, now, policies, WITH_PROGRESSIVE);
    const root = consent(first, "drawdown-q", farExpiry(clock));
    clock.ms += 1_000;
    const earlier = reconsentDecision(first, root.id, "drawdown-p", farExpiry(clock));
    // As a store before the pins held it: nothing refused the later consent below.
    first.kernel.db.prepare("DELETE FROM drawdown_policy_pins").run();
    clock.ms += 60_000;
    policies["drawdown-p"] = policy(EDITED);
    const later = consent(first, "drawdown-p", farExpiry(clock)).drawdown_policy?.digest;
    expect(later).not.toBe(earlier);
    first.kernel.db.prepare("DELETE FROM drawdown_policy_pins").run();
    first.kernel.close();

    const second = await build(file, now, policies, WITH_PROGRESSIVE);
    try {
      expect(pins(second, "drawdown-p")).toEqual([{ version: "1", digest: earlier }]);
      // The later content is refused under the version; the earliest is consented.
      expect(() => consent(second, "drawdown-p", farExpiry(clock))).toThrow(DrawdownPolicyVersionReuseError);
      policies["drawdown-p"] = policy(STD);
      expect(consent(second, "drawdown-p", farExpiry(clock)).drawdown_policy?.digest).toBe(earlier);
    } finally {
      second.kernel.close();
    }
  });

  it(`a store without pins rebuilds them from its retained consents, so changed content under a version they committed is refused ${TAG}`, async () => {
    const { file, clock, now } = fixture();
    const policies: Record<string, RegisteredActivationPolicy> = { "drawdown-p": policy(STD) };
    const first = await build(file, now, policies);
    const committed = consent(first, "drawdown-p", farExpiry(clock)).drawdown_policy;
    // As a store written before the pins existed would hold it.
    first.kernel.db.prepare("DELETE FROM drawdown_policy_pins").run();
    first.kernel.close();

    policies["drawdown-p"] = policy(EDITED);
    const second = await build(file, now, policies);
    try {
      expect(pins(second, "drawdown-p")).toEqual([{ version: "1", digest: committed?.digest }]);
      expect(() => consent(second, "drawdown-p", farExpiry(clock))).toThrow(DrawdownPolicyVersionReuseError);
    } finally {
      second.kernel.close();
    }
  });
});

describe("a drawdown chain retains its ceilings through a restart past its audit horizon (@spec progressive#audit-linkage, #1017)", SLOW, () => {
  it("every record keeps its ceiling members, and each consent commitment's consented ceiling and policy stay retained, through a policy narrowing, a re-consent and a restart past the audit horizon", async () => {
    const { file, clock, now } = fixture();
    const policies: Record<string, RegisteredActivationPolicy> = {
      "drawdown-narrow": policy({ ...STD, retire_undrawn_actions: RETIRED }),
      "drawdown-p": policy(STD),
    };
    expect(RETIRED.length).toBeGreaterThan(0);
    const soon = new Date(clock.ms + 10 * 60_000).toISOString();
    const first = await build(file, now, policies, { auditRetentionSeconds: 1 });
    // The root consent, a narrowing drawdown, a re-consent under another policy, and a drawdown under it.
    const root = consent(first, "drawdown-narrow", soon);
    const narrowed = drawdown(first, root.id, policies["drawdown-narrow"] as RegisteredActivationPolicy, soon);
    clock.ms += 1_000;
    const reconsented = reconsent(first, narrowed.id, "drawdown-p", now(), soon);
    const drawn = drawdown(first, reconsented.id, policies["drawdown-p"] as RegisteredActivationPolicy, soon);
    const chain = [root, narrowed, reconsented, drawn].map((m) => first.kernel.get(m.id) as MissionRecord);

    // The narrowing recomputed the carried ceiling under the root's consent commitment.
    expect(chain[1]?.authority_ceiling).not.toEqual(chain[0]?.authority_ceiling);
    expect(chain[1]?.ceiling_hash).not.toBe(chain[0]?.ceiling_hash);
    expect(chain[1]?.ceiling_consent_hash).toBe(chain[0]?.ceiling_hash);
    // The re-consent is its own consent; the drawdown under it carries it.
    expect(chain[2]?.ceiling_consent_hash).toBe(chain[2]?.ceiling_hash);
    expect(chain[2]?.ceiling_consent_hash).not.toBe(chain[0]?.ceiling_hash);
    expect(chain[3]?.ceiling_consent_hash).toBe(chain[2]?.ceiling_hash);

    const members = (m: MissionRecord) => ({
      authority_ceiling: m.authority_ceiling,
      drawdown_policy: m.drawdown_policy,
      ceiling_hash: m.ceiling_hash,
      ceiling_consent_hash: m.ceiling_consent_hash,
      ceiling_consented_at: m.ceiling_consented_at,
      ceiling_consent_principal: m.ceiling_consent_principal,
    });
    const before = chain.map(members);
    first.kernel.close();

    // An hour on: past every record's expiry plus the one-second audit retention.
    clock.ms += 60 * 60_000;
    const second = await build(file, now, policies, { auditRetentionSeconds: 1 });
    try {
      // The store's own audit-horizon pruning ran: the chain's activation snapshots are gone.
      expect(second.kernel.db.prepare("SELECT COUNT(*) AS n FROM activation_policy_snapshots").get()).toEqual({ n: 0 });
      const after = chain.map((m) => second.kernel.get(m.id) as MissionRecord);
      expect(after.map(members)).toEqual(before);
      // Each record's consent commitment names a consented ceiling and policy a record of the chain still holds.
      const consents = new Map(after.filter((m) => m.ceiling_consent_hash === m.ceiling_hash).map((m) => [m.ceiling_hash, m]));
      expect([...consents.keys()].sort()).toEqual([chain[0]?.ceiling_hash, chain[2]?.ceiling_hash].sort());
      for (const m of after) {
        const consented = consents.get(m.ceiling_consent_hash) as MissionRecord;
        expect(ceilingHash(ISSUER, consented.authority_ceiling as AuthorityEntry[], consented.drawdown_policy)).toBe(
          m.ceiling_consent_hash,
        );
      }
    } finally {
      second.kernel.close();
    }
  });
});
