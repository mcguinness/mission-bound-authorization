/**
 * @spec draft-mcguinness-oauth-mission-status (#completion, #terminal-when,
 * #discharge, #discharge-operation, #discharge-authority,
 * #discharge-anti-oracle, #discharge-idempotency, #discharge-result,
 * #visibility, #idempotency)
 *
 * Entry DISCHARGE: the fifth lifecycle-endpoint operation (issue #287
 * residual). It changes no Mission state; it latches one entry's
 * `terminal_when` completion so the entry stops deriving while the Mission
 * stays `active`. Covered here, kernel-level and over real HTTP:
 *
 *  - `terminal_when` derivation (union, dedup, reproducible order), the subset
 *    rule (a child cannot drop a parent condition), and the fail-closed
 *    `discharge_authority` value resolution at every point a condition can
 *    first enter an immutable record entry;
 *  - the monotonic equivalence-class latch: duplicate entries discharge as ONE
 *    transition with ONE version increment; `already_discharged` for a sibling
 *    condition and for the same condition under a different `event_id`;
 *    `terminal_noop` after a terminal state; `suspended` still narrows;
 *  - the anti-oracle collapse (six cases, one identical `not_found` body) and
 *    the normative validation ORDER (a terminal Mission is never a
 *    selector-existence oracle);
 *  - the two idempotency identities: `nonce` (verbatim replay of the stored
 *    signed response; `invalid_request` on a divergent retry) and `event_id`
 *    (fresh envelope with the ORIGINAL versions on a new nonce, `conflict` on a
 *    divergent fingerprint, independent assertion against another target);
 *  - authority: `mission_discharge` is distinct and `mission_lifecycle` never
 *    implies it;
 *  - visibility: a discharged entry is omitted from the signed Status
 *    `authorization_details` and from derivation, including a Child Mission's;
 *  - atomicity under a concurrency race, and evidence members that are neither
 *    dereferenced nor authorization input.
 */

import { type Server } from "node:http";
import { CANONICAL_RESOURCE, DEV_SERVICE_TOKEN } from "@mission/demo-data";
import { openStore } from "@mission/store";
import { decodeJwt } from "jose";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import {
  type AuthorityEntry,
  type BuiltAs,
  buildAuthorizationServer,
  ChildDelegationError,
  conditionDigest,
  createChildMission,
  type DischargeAuthorityMapping,
  type DischargeAuthorityPolicy,
  DischargeConflictError,
  DischargeNotFoundError,
  DischargeSelectorStore,
  entryDigest,
  GateError,
  isSubsetEntry,
  type LifecycleCommit,
  MISSION_DISCHARGE_SCOPE,
  MISSION_LIFECYCLE_SCOPE,
  MissionKernel,
  type MissionRecord,
  validateMissionIntent,
} from "../src/index.js";
import { aiAgents } from "./actor-profiles.helper.js";
import { testAuthoritySourceCatalog } from "./authority-source.helper.js";

const ISS = "https://as.discharge.test";
const RES = "https://payments.test/mcp";
const NOW = new Date("2026-08-20T12:00:00Z");
const EXPIRES_AT = "2027-01-01T00:00:00Z";

const CLOSE_EVENT = "accounting-period-closed";
const CLOSE_POLICY = "close-management-2026-q3";
const AUDIT_EVENT = "audit-window-closed";

/** The close-management system's workload identity, and nobody else. */
const DISCHARGE_AUTHORITY: DischargeAuthorityPolicy = {
  policies: {
    [CLOSE_POLICY]: {
      mapping_id: "close-management",
      mapping_version: "1",
      event_types: [CLOSE_EVENT],
      principals: ["svc:close-management", "svc:console"],
    },
  },
  baseline: {
    [AUDIT_EVENT]: {
      mapping_id: "audit-baseline",
      mapping_version: "1",
      principals: ["svc:close-management", "svc:console"],
    },
  },
};

const CEILING: AuthorityEntry[] = [
  {
    type: "mission_resource_access",
    resource: RES,
    actions: ["payments:invoice.read", "payments:journal.write"],
    delegation: { max_depth: 1, children: { max_children: 2, allowed_child_actors: [{ sub: "sub-agent" }] } },
  },
];

const POLICY = { policy_version: "discharge-v1", ceiling: CEILING };

const intent = (goal = "Reconcile Q3 payables") =>
  validateMissionIntent(JSON.stringify({ goal, target_resources: [RES], expires_at: EXPIRES_AT }));

/** A write entry discharged when the Q3 close is finalized, plus a live read entry. */
const proposal = (): AuthorityEntry[] => [
  { type: "mission_resource_access", resource: RES, actions: ["payments:invoice.read"] },
  {
    type: "mission_resource_access",
    resource: RES,
    actions: ["payments:journal.write"],
    constraints: { terminal_when: [{ event_type: CLOSE_EVENT, discharge_authority: CLOSE_POLICY }] },
  },
];

interface Harness {
  kernel: MissionKernel;
  commits: LifecycleCommit[];
}

function makeKernel(overrides: Partial<Parameters<typeof newKernel>[0]> = {}): Harness {
  return newKernel({ dischargeAuthority: DISCHARGE_AUTHORITY, ...overrides });
}

function newKernel(opts: {
  dischargeAuthority?: DischargeAuthorityPolicy;
  dischargeEventRetentionSeconds?: number;
}): Harness {
  const commits: LifecycleCommit[] = [];
  const kernel = new MissionKernel({
    issuer: ISS,
    policy: POLICY as never,
    authoritySourceCatalog: testAuthoritySourceCatalog(POLICY.ceiling, ["ap-agent"], ["bob"]),
    statusKey: {} as never,
    statusKid: "as-status",
    now: () => NOW,
    actorProfiles: aiAgents("sub-agent"),
    onLifecycleCommit: (c) => commits.push(c),
    ...(opts.dischargeAuthority ? { dischargeAuthority: opts.dischargeAuthority } : {}),
    ...(opts.dischargeEventRetentionSeconds !== undefined
      ? { dischargeEventRetentionSeconds: opts.dischargeEventRetentionSeconds }
      : {}),
  });
  return { kernel, commits };
}

let approvals = 0;
function approve(kernel: MissionKernel, entries: AuthorityEntry[] = proposal()): MissionRecord {
  approvals += 1;
  return kernel.approve({
    intent: intent(),
    proposedAuthority: entries,
    subject: { iss: ISS, sub: "alice" },
    approver: { iss: ISS, sub: "bob" },
    clientId: "ap-agent",
    approvalEventId: `apev-dis-${approvals}`,
  });
}

/** The write entry (the one carrying terminal_when) and its selectors. */
function selectorsFor(record: MissionRecord, action = "payments:journal.write") {
  const entry = record.authority_set.find((e) => e.actions.includes(action));
  if (!entry) throw new Error(`no entry for ${action}`);
  const condition = entry.constraints?.terminal_when?.[0];
  if (!condition) throw new Error("entry carries no terminal_when");
  return {
    entry,
    entry_digest: entryDigest(record.issuer, entry),
    condition_digest: conditionDigest(condition),
    event_type: condition.event_type,
  };
}

describe("terminal_when: derivation, subset rule, and selector resolution", () => {
  it("derives the union of ceiling and proposal conditions, deduplicated and order-stable", () => {
    const { kernel } = makeKernel();
    const ceilingWithCondition: AuthorityEntry[] = [
      {
        ...(CEILING[0] as AuthorityEntry),
        constraints: { terminal_when: [{ event_type: AUDIT_EVENT }] },
      },
    ];
    const local = new MissionKernel({
      issuer: ISS,
      policy: { policy_version: "u", ceiling: ceilingWithCondition } as never,
      authoritySourceCatalog: testAuthoritySourceCatalog(ceilingWithCondition, ["ap-agent"], ["bob"]),
      statusKey: {} as never,
      statusKid: "as-status",
      now: () => NOW,
      dischargeAuthority: DISCHARGE_AUTHORITY,
    });
    const derived = local.derive(intent(), [
      {
        type: "mission_resource_access",
        resource: RES,
        actions: ["payments:journal.write"],
        constraints: {
          terminal_when: [
            { event_type: CLOSE_EVENT, discharge_authority: CLOSE_POLICY },
            { event_type: AUDIT_EVENT },
          ],
        },
      },
    ]);
    const conditions = derived[0]?.constraints?.terminal_when;
    // Union: the ceiling's condition survives a proposal that also names it,
    // deduplicated by canonical bytes; the proposal's extra condition is added.
    expect(conditions).toEqual([
      { event_type: CLOSE_EVENT, discharge_authority: CLOSE_POLICY },
      { event_type: AUDIT_EVENT },
    ]);
    // Sorted by canonical bytes, so a re-derivation reproduces the same array.
    expect(local.derive(intent(), [
      {
        type: "mission_resource_access",
        resource: RES,
        actions: ["payments:journal.write"],
        constraints: { terminal_when: [{ event_type: AUDIT_EVENT }, { event_type: CLOSE_EVENT, discharge_authority: CLOSE_POLICY }] },
      },
    ])[0]?.constraints?.terminal_when).toEqual(conditions);
    expect(kernel.derive(intent(), proposal())[1]?.constraints?.terminal_when).toEqual([
      { event_type: CLOSE_EVENT, discharge_authority: CLOSE_POLICY },
    ]);
  });

  it("refuses a value carrying two identical conditions", () => {
    const { kernel } = makeKernel();
    expect(() =>
      kernel.derive(intent(), [
        {
          type: "mission_resource_access",
          resource: RES,
          actions: ["payments:journal.write"],
          constraints: {
            terminal_when: [
              { event_type: CLOSE_EVENT, discharge_authority: CLOSE_POLICY },
              { event_type: CLOSE_EVENT, discharge_authority: CLOSE_POLICY },
            ],
          },
        },
      ]),
    ).toThrow(/two identical conditions/);
  });

  it("the subset rule: a candidate may add conditions but never drop or alter one", () => {
    const parentEntry = proposal()[1] as AuthorityEntry;
    const dropped: AuthorityEntry = {
      type: "mission_resource_access",
      resource: RES,
      actions: ["payments:journal.write"],
    };
    const altered: AuthorityEntry = {
      ...dropped,
      constraints: { terminal_when: [{ event_type: CLOSE_EVENT }] },
    };
    const added: AuthorityEntry = {
      ...dropped,
      constraints: {
        terminal_when: [
          { event_type: CLOSE_EVENT, discharge_authority: CLOSE_POLICY },
          { event_type: AUDIT_EVENT },
        ],
      },
    };
    expect(isSubsetEntry(dropped, parentEntry)).toBe(false);
    expect(isSubsetEntry(altered, parentEntry)).toBe(false); // discharge_authority removed
    expect(isSubsetEntry(added, parentEntry)).toBe(true);
  });

  it("fails closed when a discharge_authority value maps to nothing, at approval and at child creation", () => {
    // No policy configured at all: the condition cannot enter a record.
    const { kernel: unconfigured } = newKernel({});
    expect(() => approve(unconfigured)).toThrow(/maps to no discharge-authority mapping/);
    // A condition with no selector needs a baseline mapping for its event type.
    const { kernel } = makeKernel();
    expect(() =>
      approve(kernel, [
        {
          type: "mission_resource_access",
          resource: RES,
          actions: ["payments:journal.write"],
          constraints: { terminal_when: [{ event_type: "never-registered" }] },
        },
      ]),
    ).toThrow(/no baseline discharge-authority mapping/);
    // And at child creation, where a derived entry ADDS a condition after
    // activation: insertRecord is the single record funnel, so it is checked
    // there too, not only at initial approval.
    const parent = approve(kernel);
    expect(() =>
      createChildMission(kernel, {
        parentId: parent.id,
        intent: intent("Post journal entries for the child"),
        proposedAuthority: [
          {
            type: "mission_resource_access",
            resource: RES,
            actions: ["payments:journal.write"],
            constraints: {
              terminal_when: [
                { event_type: CLOSE_EVENT, discharge_authority: CLOSE_POLICY },
                { event_type: "unapproved-fallback", discharge_authority: "not-registered" },
              ],
            },
          },
        ],
        childActor: { sub: "sub-agent", sub_profile: "ai_agent" },
      }),
    ).toThrow(/maps to no discharge-authority mapping/);
  });
});

describe("the discharge latch: outcomes, versions, and visibility", () => {
  it("discharges the entry once: the Mission stays active, the entry stops deriving", () => {
    const { kernel, commits } = makeKernel();
    const record = approve(kernel);
    const s = selectorsFor(record);
    expect(kernel.effectiveAuthoritySet(record)).toHaveLength(2);

    const { record: after, result } = kernel.discharge(record.id, {
      authority: "svc:close-management",
      entry_digest: s.entry_digest,
      condition_digest: s.condition_digest,
      event_type: s.event_type,
      event_id: "close-2026-q3",
    });
    expect(result).toEqual({
      entry_digest: s.entry_digest,
      condition_digest: s.condition_digest,
      event_id: "close-2026-q3",
      outcome: "discharged",
      prior_version: 1,
      current_version: 2,
    });
    // No Mission-state transition: `state` is unchanged, `version` incremented.
    expect(after.state).toBe("active");
    expect(after.version).toBe(2);
    const commit = commits.at(-1);
    expect(commit?.prior_state).toBe("active");
    expect(commit?.state).toBe("active");
    expect(commit?.authority_changed).toBe(true);
    // The entry no longer derives; the other entry is untouched.
    expect(kernel.effectiveAuthoritySet(after).map((e) => e.actions)).toEqual([
      ["payments:invoice.read"],
    ]);
  });

  it("already_discharged for a sibling condition and for a different event_id, with no re-latch", () => {
    const { kernel } = makeKernel();
    const record = approve(kernel, [
      {
        type: "mission_resource_access",
        resource: RES,
        actions: ["payments:journal.write"],
        constraints: {
          terminal_when: [
            { event_type: CLOSE_EVENT, discharge_authority: CLOSE_POLICY },
            { event_type: AUDIT_EVENT },
          ],
        },
      },
    ]);
    const entry = record.authority_set[0] as AuthorityEntry;
    const digest = entryDigest(record.issuer, entry);
    const conditions = entry.constraints?.terminal_when ?? [];
    const first = conditions.find((c) => c.event_type === CLOSE_EVENT);
    const sibling = conditions.find((c) => c.event_type === AUDIT_EVENT);
    const base = { authority: "svc:close-management", entry_digest: digest };
    const one = kernel.discharge(record.id, {
      ...base,
      condition_digest: conditionDigest(first as never),
      event_type: CLOSE_EVENT,
      event_id: "occurrence-1",
    });
    expect(one.result.outcome).toBe("discharged");
    expect(one.record.version).toBe(2);

    // A SIBLING condition against the already-latched entry.
    const two = kernel.discharge(record.id, {
      ...base,
      condition_digest: conditionDigest(sibling as never),
      event_type: AUDIT_EVENT,
      event_id: "occurrence-2",
    });
    expect(two.result.outcome).toBe("already_discharged");
    expect(two.result.prior_version).toBe(2);
    expect(two.result.current_version).toBe(2);

    // The SAME condition under a different event_id.
    const three = kernel.discharge(record.id, {
      ...base,
      condition_digest: conditionDigest(first as never),
      event_type: CLOSE_EVENT,
      event_id: "occurrence-3",
    });
    expect(three.result.outcome).toBe("already_discharged");
    expect(kernel.get(record.id)?.version).toBe(2); // never incremented again
    expect(kernel.get(record.id)?.discharged).toHaveLength(1);
  });

  it("one entry_digest discharges every byte-identical entry as ONE transition", () => {
    const { kernel, commits } = makeKernel();
    const duplicate = proposal()[1] as AuthorityEntry;
    // Two byte-identical recorded entries (the equivalence class).
    const record = approve(kernel, [duplicate, duplicate]);
    expect(record.authority_set).toHaveLength(2);
    const s = selectorsFor(record);
    const before = commits.length;
    const { record: after } = kernel.discharge(record.id, {
      authority: "svc:close-management",
      entry_digest: s.entry_digest,
      condition_digest: s.condition_digest,
      event_type: s.event_type,
      event_id: "close-dup",
    });
    expect(after.version).toBe(2); // exactly one increment
    expect(commits.length - before).toBe(1); // exactly one notification
    expect(after.discharged).toHaveLength(1);
    expect(kernel.effectiveAuthoritySet(after)).toEqual([]); // both entries gone
  });

  it("applies while suspended, and is a terminal_noop after a terminal state", () => {
    const { kernel } = makeKernel();
    const suspended = approve(kernel);
    const s = selectorsFor(suspended);
    kernel.transition(suspended.id, "suspend");
    const held = kernel.discharge(suspended.id, {
      authority: "svc:close-management",
      entry_digest: s.entry_digest,
      condition_digest: s.condition_digest,
      event_type: s.event_type,
      event_id: "close-while-suspended",
    });
    expect(held.result.outcome).toBe("discharged");
    expect(held.record.state).toBe("suspended");
    expect(kernel.effectiveAuthoritySet(held.record).map((e) => e.actions)).toEqual([
      ["payments:invoice.read"],
    ]);

    const revoked = approve(kernel);
    const rs = selectorsFor(revoked);
    kernel.transition(revoked.id, "revoke");
    const noop = kernel.discharge(revoked.id, {
      authority: "svc:close-management",
      entry_digest: rs.entry_digest,
      condition_digest: rs.condition_digest,
      event_type: rs.event_type,
      event_id: "close-after-revoke",
    });
    expect(noop.result.outcome).toBe("terminal_noop");
    expect(noop.result.prior_version).toBe(noop.result.current_version);
    expect(kernel.get(revoked.id)?.discharged).toBeUndefined();
    expect(kernel.get(revoked.id)?.version).toBe(2); // the revoke's own increment only
  });

  it("gates derivation and refuses a Child Mission naming the discharged entry", () => {
    const { kernel } = makeKernel();
    const parent = approve(kernel);
    const s = selectorsFor(parent);
    // A child justified by the write entry, created while it still derives.
    const child = createChildMission(kernel, {
      parentId: parent.id,
      intent: intent("Post journal entries"),
      proposedAuthority: [
        {
          type: "mission_resource_access",
          resource: RES,
          actions: ["payments:journal.write"],
          constraints: { terminal_when: [{ event_type: CLOSE_EVENT, discharge_authority: CLOSE_POLICY }] },
        },
      ],
      childActor: { sub: "sub-agent", sub_profile: "ai_agent" },
    });
    expect(kernel.gateDerivation(child.child.id).id).toBe(child.child.id);

    kernel.discharge(parent.id, {
      authority: "svc:close-management",
      entry_digest: s.entry_digest,
      condition_digest: s.condition_digest,
      event_type: s.event_type,
      event_id: "close-child-prop",
    });

    // The parent's latch propagated entry-wise: the existing child can no longer
    // derive the discharged authority, even though both Missions stay active.
    const childAfter = kernel.get(child.child.id) as MissionRecord;
    expect(childAfter.state).toBe("active");
    expect(kernel.effectiveAuthoritySet(childAfter)).toEqual([]);
    expect(() => kernel.gateDerivation(childAfter.id)).toThrow(GateError);

    // And a NEW child naming the discharged entry is refused: child creation is
    // proven against the parent's EFFECTIVE set.
    expect(() =>
      createChildMission(kernel, {
        parentId: parent.id,
        intent: intent("Post journal entries after the close"),
        proposedAuthority: [
          {
            type: "mission_resource_access",
            resource: RES,
            actions: ["payments:journal.write"],
            constraints: { terminal_when: [{ event_type: CLOSE_EVENT, discharge_authority: CLOSE_POLICY }] },
          },
        ],
        childActor: { sub: "sub-agent", sub_profile: "ai_agent" },
      }),
    ).toThrow(ChildDelegationError);
  });
});

// ---------------------------------------------------------------------------
// Propagation by recorded justification, downward only (#898 fix 2).
// ---------------------------------------------------------------------------

/** A ceiling admitting two child generations, so recursion is observable. */
const DEEP_CEILING: AuthorityEntry[] = [
  {
    type: "mission_resource_access",
    resource: RES,
    actions: ["payments:invoice.read", "payments:journal.write"],
    delegation: {
      max_depth: 1,
      children: {
        max_children: 5,
        max_child_depth: 2,
        allowed_child_actors: [{ sub: "sub-agent" }, { sub: "sub-agent-2" }],
      },
    },
  },
];

function deepKernel(): MissionKernel {
  const policy = { policy_version: "discharge-deep-v1", ceiling: DEEP_CEILING };
  return new MissionKernel({
    issuer: ISS,
    policy: policy as never,
    authoritySourceCatalog: testAuthoritySourceCatalog(policy.ceiling, ["ap-agent"], ["bob"]),
    statusKey: {} as never,
    statusKid: "as-status",
    now: () => NOW,
    actorProfiles: aiAgents("sub-agent", "sub-agent-2"),
    dischargeAuthority: DISCHARGE_AUTHORITY,
  });
}

const CLOSE_CONDITION = { event_type: CLOSE_EVENT, discharge_authority: CLOSE_POLICY };

/** One entry on RES for `actions`, completing on the close condition. */
const closing = (actions: string[]): AuthorityEntry => ({
  type: "mission_resource_access",
  resource: RES,
  actions,
  constraints: { terminal_when: [{ ...CLOSE_CONDITION }] },
});

/** Discharge the record entry carrying `action` on `record`, as the close authority. */
function dischargeEntry(kernel: MissionKernel, record: MissionRecord, action: string, eventId: string) {
  const s = selectorsFor(record, action);
  return kernel.discharge(record.id, {
    authority: "svc:close-management",
    entry_digest: s.entry_digest,
    condition_digest: s.condition_digest,
    event_type: s.event_type,
    event_id: eventId,
  });
}

describe("discharge propagation by recorded justification, downward only (#898 fix 2)", () => {
  it("reaches a child entry only through its recorded justification, never a parent entry with an identical condition", () => {
    const kernel = deepKernel();
    // E1 and E2 carry byte-identical conditions on the SAME resource.
    const parent = approve(kernel, [closing(["payments:invoice.read"]), closing(["payments:journal.write"])]);
    const [e1, e2] = parent.authority_set as [AuthorityEntry, AuthorityEntry];
    expect(conditionDigest(e1.constraints?.terminal_when?.[0] as never)).toBe(
      conditionDigest(e2.constraints?.terminal_when?.[0] as never),
    );
    // The child entry is a subset of E2 only, so E2 is its recorded justification.
    const child = createChildMission(kernel, {
      parentId: parent.id,
      intent: intent("Post journal entries"),
      proposedAuthority: [closing(["payments:journal.write"])],
      childActor: { sub: "sub-agent", sub_profile: "ai_agent" },
    }).child;
    const childEntry = child.authority_set[0] as AuthorityEntry;
    expect(isSubsetEntry(childEntry, e1)).toBe(false);
    expect(isSubsetEntry(childEntry, e2)).toBe(true);
    // A grandchild justified by the child's entry: recursion follows justification.
    const grandchild = createChildMission(kernel, {
      parentId: child.id,
      intent: intent("Post one journal entry"),
      proposedAuthority: [closing(["payments:journal.write"])],
      childActor: { sub: "sub-agent-2", sub_profile: "ai_agent" },
    }).child;

    // Discharging E1 fires the identical condition on the same resource, but
    // E1 justifies nothing in the child: neither descendant is reached.
    expect(dischargeEntry(kernel, parent, "payments:invoice.read", "close-e1").result.outcome).toBe(
      "discharged",
    );
    expect((kernel.get(child.id) as MissionRecord).discharged).toBeUndefined();
    expect((kernel.get(grandchild.id) as MissionRecord).discharged).toBeUndefined();
    expect(kernel.effectiveAuthoritySet(kernel.get(child.id) as MissionRecord)).toHaveLength(1);
    expect(kernel.gateDerivation(child.id).id).toBe(child.id);
    expect(kernel.gateDerivation(grandchild.id).id).toBe(grandchild.id);

    // Discharging E2, the recorded justification, reaches the child entry and,
    // recursively, the grandchild entry the discharge has already reached.
    dischargeEntry(kernel, parent, "payments:journal.write", "close-e2");
    const childAfter = kernel.get(child.id) as MissionRecord;
    expect(childAfter.discharged?.map((d) => d.entry_digest)).toEqual([entryDigest(ISS, childEntry)]);
    expect(kernel.effectiveAuthoritySet(childAfter)).toEqual([]);
    const grandAfter = kernel.get(grandchild.id) as MissionRecord;
    expect(grandAfter.discharged).toHaveLength(1);
    expect(kernel.effectiveAuthoritySet(grandAfter)).toEqual([]);
    // Observed at the derivation gate the token endpoint calls.
    expect(() => kernel.gateDerivation(child.id)).toThrow(GateError);
    expect(() => kernel.gateDerivation(grandchild.id)).toThrow(GateError);
  });

  it("never discharges a parent's or a sibling's entry because a child entry was discharged", () => {
    const kernel = deepKernel();
    const parent = approve(kernel, [closing(["payments:journal.write"])]);
    const spawn = (goal: string) =>
      createChildMission(kernel, {
        parentId: parent.id,
        intent: intent(goal),
        proposedAuthority: [closing(["payments:journal.write"])],
        childActor: { sub: "sub-agent", sub_profile: "ai_agent" },
      }).child;
    const first = spawn("Post the first ten journal entries");
    const sibling = spawn("Post the next ten journal entries");
    const parentVersion = (kernel.get(parent.id) as MissionRecord).version;
    const siblingVersion = (kernel.get(sibling.id) as MissionRecord).version;

    // The child completes ITS share of the work...
    expect(dischargeEntry(kernel, first, "payments:journal.write", "child-done").result.outcome).toBe(
      "discharged",
    );
    expect(kernel.effectiveAuthoritySet(kernel.get(first.id) as MissionRecord)).toEqual([]);
    // ...which completes neither the parent's entry nor the sibling's.
    const parentAfter = kernel.get(parent.id) as MissionRecord;
    const siblingAfter = kernel.get(sibling.id) as MissionRecord;
    expect(parentAfter.discharged).toBeUndefined();
    expect(parentAfter.version).toBe(parentVersion);
    expect(kernel.effectiveAuthoritySet(parentAfter)).toHaveLength(1);
    expect(siblingAfter.discharged).toBeUndefined();
    expect(siblingAfter.version).toBe(siblingVersion);
    expect(kernel.effectiveAuthoritySet(siblingAfter)).toHaveLength(1);
    // Both still derive at the gate the token endpoint calls; the child does not.
    expect(kernel.gateDerivation(parent.id).id).toBe(parent.id);
    expect(kernel.gateDerivation(sibling.id).id).toBe(sibling.id);
    expect(() => kernel.gateDerivation(first.id)).toThrow(GateError);
  });
});

describe("condition selector mapping for a projected entry (#898 fix 1)", () => {
  it("gives an ambiguous projected condition no selector, and a uniquely held one its record target", () => {
    const { kernel } = makeKernel();
    const audit = { event_type: AUDIT_EVENT };
    const both = ["payments:invoice.read", "payments:journal.write"];
    // Two DIFFERENT record entries, each a superset of the projected entry
    // below; both carry the close condition, only the second the audit one.
    const record = approve(kernel, [
      { type: "mission_resource_access", resource: RES, actions: both, constraints: { terminal_when: [{ ...CLOSE_CONDITION }] } },
      {
        type: "mission_resource_access",
        resource: RES,
        actions: both,
        constraints: { terminal_when: [{ ...CLOSE_CONDITION }, { ...audit }] },
      },
    ]);
    const [, holder] = record.authority_set as [AuthorityEntry, AuthorityEntry];
    const projected: AuthorityEntry = {
      type: "mission_resource_access",
      resource: RES,
      actions: ["payments:invoice.read"],
      constraints: { terminal_when: holder.constraints?.terminal_when ?? [] },
    };
    const conditions = projected.constraints?.terminal_when ?? [];
    const auditIndex = conditions.findIndex((c) => c.event_type === AUDIT_EVENT);
    const selectors = kernel.dischargeSelectorsFor(record, [projected]);
    // The close condition is held by both entries: ambiguous, no selector. The
    // audit condition is held by exactly one: that entry is the target.
    expect(selectors.map((s) => [s.entry, s.condition])).toEqual([[0, auditIndex]]);
    expect(kernel.dischargeSelectors.resolve((selectors[0] as { selector: string }).selector)).toEqual({
      mission_id: record.id,
      entry_digest: entryDigest(ISS, holder),
      condition_digest: conditionDigest(audit),
    });
  });
});

// ---------------------------------------------------------------------------
// The lifecycle endpoint, over real HTTP.
// ---------------------------------------------------------------------------

describe("review hardening: mapping pinning and terminal idempotency", () => {
  it("pins the approved mapping at record creation: a later policy edit never re-points who may discharge", () => {
    // A LIVE policy object the deployment later edits in place: "version 2"
    // re-points the selector at a different principal AFTER approval.
    const livePolicy: DischargeAuthorityPolicy = JSON.parse(JSON.stringify(DISCHARGE_AUTHORITY));
    const { kernel } = makeKernel({ dischargeAuthority: livePolicy });
    const record = approve(kernel);
    const s = selectorsFor(record);
    (livePolicy.policies as Record<string, DischargeAuthorityMapping>)[CLOSE_POLICY] = {
      mapping_id: "close-management",
      mapping_version: "2",
      event_types: [CLOSE_EVENT],
      principals: ["svc:intruder"],
    };
    // The principal the EDITED policy names may not discharge the
    // already-approved entry (premature authority retirement)...
    expect(() =>
      kernel.discharge(record.id, {
        authority: "svc:intruder",
        entry_digest: s.entry_digest,
        condition_digest: s.condition_digest,
        event_type: s.event_type,
        event_id: "pin-intruder-1",
      }),
    ).toThrow(DischargeNotFoundError);
    // ...and the pin retains the approved identifier, version, and content,
    // so the originally admitted principal still may.
    expect(kernel.dischargePins.find(record.id, s.entry_digest, s.condition_digest)).toMatchObject({
      mapping_id: "close-management",
      mapping_version: "1",
    });
    const { result } = kernel.discharge(record.id, {
      authority: "svc:close-management",
      entry_digest: s.entry_digest,
      condition_digest: s.condition_digest,
      event_type: s.event_type,
      event_id: "pin-original-1",
    });
    expect(result.outcome).toBe("discharged");
  });

  it("terminal_noop records through the event store: same-fingerprint replay returns it, divergent re-assertion conflicts", () => {
    const { kernel } = makeKernel();
    const record = approve(kernel);
    const s = selectorsFor(record);
    kernel.transition(record.id, "revoke");
    const req = {
      authority: "svc:close-management",
      entry_digest: s.entry_digest,
      condition_digest: s.condition_digest,
      event_type: s.event_type,
      event_id: "terminal-idem-1",
    };
    const first = kernel.discharge(record.id, { ...req });
    expect(first.result.outcome).toBe("terminal_noop");
    // Same tuple, same fingerprint (an at-least-once retry under a fresh
    // HTTP nonce lands here): the STORED outcome and versions, no rework.
    const replay = kernel.discharge(record.id, { ...req });
    expect(replay.result).toEqual(first.result);
    // Same tuple, different fingerprint: a divergent re-assertion of the
    // occurrence is a conflict, never a second terminal_noop.
    expect(() =>
      kernel.discharge(record.id, { ...req, evidence_ref: "https://evidence.test/divergent" }),
    ).toThrow(DischargeConflictError);
  });
});

const PORT = 14545;
const ISSUER = `http://localhost:${PORT}`;
/** A caller holding `mission_lifecycle` and NOTHING else. */
const LIFECYCLE_ONLY_TOKEN = "dev-lifecycle-only-token";
/** A caller holding `mission_discharge` that no condition's mapping admits. */
const UNMAPPED_SOURCE_TOKEN = "dev-unmapped-source-token";
const ENDPOINT_AUTHORITY: DischargeAuthorityPolicy = {
  policies: {
    [CLOSE_POLICY]: {
      mapping_id: "close-management",
      mapping_version: "1",
      event_types: [CLOSE_EVENT],
      // svc:console is the shipped dev token's principal; svc:lifecycle-only is
      // deliberately NOT admitted here either, so its refusal is attributable to
      // the missing SCOPE as well as to the mapping.
      principals: ["svc:console"],
    },
  },
};

let as: BuiltAs;
let server: Server;
let endpointApprovals = 0;

const endpointProposal = (): AuthorityEntry[] => [
  {
    type: "mission_resource_access",
    resource: CANONICAL_RESOURCE,
    actions: ["payments:invoice.read"],
  },
  {
    type: "mission_resource_access",
    resource: CANONICAL_RESOURCE,
    actions: ["payments:remittance.send"],
    constraints: { terminal_when: [{ event_type: CLOSE_EVENT, discharge_authority: CLOSE_POLICY }] },
  },
];

const endpointIntent = () =>
  validateMissionIntent(
    JSON.stringify({
      goal: "Send remittances for the Q3 close",
      target_resources: [CANONICAL_RESOURCE],
      expires_at: EXPIRES_AT,
    }),
  );

function approveOnAs(entries: AuthorityEntry[] = endpointProposal()): MissionRecord {
  endpointApprovals += 1;
  return as.kernel.approve({
    intent: endpointIntent(),
    proposedAuthority: entries,
    subject: { iss: ISSUER, sub: "alice" },
    approver: { iss: ISSUER, sub: "bob" },
    clientId: "ap-agent",
    approvalEventId: `apev-dis-http-${endpointApprovals}`,
  });
}

const lifecycle = (
  missionId: string,
  body: unknown,
  token: string | null = DEV_SERVICE_TOKEN,
): Promise<Response> =>
  fetch(`${ISSUER}/missions/${missionId}/lifecycle`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...(token !== null ? { "x-service-token": token } : {}),
    },
    body: JSON.stringify(body),
  });

let nonces = 0;
const freshNonce = (): string => `nonce-dis-${(nonces += 1)}`;

/** A well-formed discharge body for the completing entry of `record`. */
function dischargeBody(
  record: MissionRecord,
  over: Record<string, unknown> = {},
  action = "payments:remittance.send",
): Record<string, unknown> {
  const s = selectorsFor(record, action);
  return {
    operation: "discharge",
    mission_id: record.id,
    nonce: freshNonce(),
    entry_digest: s.entry_digest,
    condition_digest: s.condition_digest,
    event_type: s.event_type,
    event_id: `close-${record.id.slice(-6)}`,
    ...over,
  };
}

/** The decoded `discharge_result` of a 200 signed response. */
async function dischargeResultOf(res: Response): Promise<Record<string, unknown>> {
  const payload = decodeJwt(await res.text()) as Record<string, unknown>;
  return payload.discharge_result as Record<string, unknown>;
}

describe("the discharge operation on the lifecycle endpoint", () => {
  beforeAll(async () => {
    as = await buildAuthorizationServer({
      issuer: ISSUER,
      allowHeadlessAdjudication: true,
      dischargeAuthority: ENDPOINT_AUTHORITY,
      serviceTokenPrincipals: {
        [LIFECYCLE_ONLY_TOKEN]: {
          principal_id: "svc:lifecycle-only",
          scopes: [MISSION_LIFECYCLE_SCOPE],
        },
        // Holds the discharge grant, but no condition's mapping admits it.
        [UNMAPPED_SOURCE_TOKEN]: {
          principal_id: "svc:unmapped-source",
          scopes: [MISSION_DISCHARGE_SCOPE],
        },
      },
    });
    server = as.provider.listen(PORT);
  });
  afterAll(() => {
    server?.close();
  });

  it("discharges over HTTP, returning the signed discharge_result beside `mission`", async () => {
    const record = approveOnAs();
    const s = selectorsFor(record, "payments:remittance.send");
    const body = dischargeBody(record);
    const res = await lifecycle(record.id, body);
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toBe("application/mission-status-response+jwt");
    expect(res.headers.get("cache-control")).toBe("no-store");
    const payload = decodeJwt(await res.text()) as Record<string, unknown>;
    expect(payload.discharge_result).toEqual({
      entry_digest: s.entry_digest,
      condition_digest: s.condition_digest,
      event_id: body.event_id,
      outcome: "discharged",
      prior_version: 1,
      current_version: 2,
    });
    // A sibling of `mission`, which reports the UNCHANGED state and the new version.
    expect(payload.mission).toMatchObject({ id: record.id, state: "active", version: 2 });
    expect(payload.nonce).toBe(body.nonce);
    // @spec discharge#visibility — the discharged entry is omitted from the
    // audience-scoped authorization_details the Status surface returns.
    const status = await fetch(
      `${ISSUER}/missions/${record.id}/status?audience=${encodeURIComponent(CANONICAL_RESOURCE)}`,
      { headers: { "x-service-token": DEV_SERVICE_TOKEN } },
    );
    const details = (decodeJwt(await status.text()) as Record<string, unknown>)
      .authorization_details as AuthorityEntry[];
    expect(details).toHaveLength(1);
    expect(details[0]?.actions).toEqual(["payments:invoice.read"]);
  });

  it("mission_lifecycle does not imply mission_discharge", async () => {
    const record = approveOnAs();
    // The lifecycle-only caller CAN perform a state operation...
    const suspend = await lifecycle(
      record.id,
      { operation: "suspend", nonce: freshNonce() },
      LIFECYCLE_ONLY_TOKEN,
    );
    expect(suspend.status).toBe(200);
    // ...and is refused `discharge` with the endpoint's not-found body: the
    // grant is distinct and this token holds only the lifecycle one.
    const refused = await lifecycle(record.id, dischargeBody(record), LIFECYCLE_ONLY_TOKEN);
    expect(refused.status).toBe(404);
    expect(await refused.json()).toMatchObject({ error: "not_found" });
    expect(as.kernel.get(record.id)?.discharged).toBeUndefined();
    // An unauthenticated caller is the endpoint's only 401.
    const unauth = await lifecycle(record.id, dischargeBody(record), null);
    expect(unauth.status).toBe(401);
    expect(await unauth.json()).toMatchObject({ error: "unauthorized" });
  });

  it("collapses all six anti-oracle cases to one identical not_found body", async () => {
    const record = approveOnAs();
    const plain = approveOnAs([
      {
        type: "mission_resource_access",
        resource: CANONICAL_RESOURCE,
        actions: ["payments:invoice.read"],
      },
    ]);
    const responses: Array<{ status: number; body: Record<string, unknown> }> = [];
    const collect = async (missionId: string, body: Record<string, unknown>): Promise<void> => {
      const res = await lifecycle(missionId, body);
      responses.push({ status: res.status, body: (await res.json()) as Record<string, unknown> });
    };
    // 1. unknown mission_id
    await collect("msn_does_not_exist", dischargeBody(record, { mission_id: "msn_does_not_exist" }));
    // 2. unknown entry_digest
    await collect(record.id, dischargeBody(record, { entry_digest: `sha-256:${"A".repeat(43)}` }));
    // 3. unknown condition_digest
    await collect(
      record.id,
      dischargeBody(record, { condition_digest: `sha-256:${"B".repeat(43)}` }),
    );
    // 4. an entry with no terminal_when (a real entry of a real Mission)
    await collect(
      plain.id,
      dischargeBody(record, {
        mission_id: plain.id,
        entry_digest: entryDigest(plain.issuer, plain.authority_set[0] as AuthorityEntry),
      }),
    );
    // 5. an event_type that does not match the condition condition_digest names
    await collect(record.id, dischargeBody(record, { event_type: "some-other-event" }));
    // 6. a caller not authorized FOR THAT TARGET: it holds the discharge scope,
    // but this condition's mapping admits a different principal.
    const otherPort = PORT + 1;
    const otherAs = await buildAuthorizationServer({
      issuer: `http://localhost:${otherPort}`,
      allowHeadlessAdjudication: true,
      dischargeAuthority: {
        policies: {
          [CLOSE_POLICY]: {
            mapping_id: "close-management",
            mapping_version: "1",
            event_types: [CLOSE_EVENT],
            principals: ["svc:someone-else"],
          },
        },
      },
    });
    const otherServer = otherAs.provider.listen(otherPort);
    try {
      const mission = otherAs.kernel.approve({
        intent: endpointIntent(),
        proposedAuthority: endpointProposal(),
        subject: { iss: ISSUER, sub: "alice" },
        approver: { iss: ISSUER, sub: "bob" },
        clientId: "ap-agent",
        approvalEventId: "apev-dis-unauth-target",
      });
      const unauthTarget = await fetch(
        `http://localhost:${otherPort}/missions/${mission.id}/lifecycle`,
        {
          method: "POST",
          headers: { "content-type": "application/json", "x-service-token": DEV_SERVICE_TOKEN },
          body: JSON.stringify(dischargeBody(mission)),
        },
      );
      responses.push({
        status: unauthTarget.status,
        body: (await unauthTarget.json()) as Record<string, unknown>,
      });
      expect(otherAs.kernel.get(mission.id)?.discharged).toBeUndefined();
    } finally {
      otherServer.close();
    }

    expect(responses).toHaveLength(6);
    for (const r of responses) {
      expect(r.status).toBe(404);
      // Identical apart from the echoed nonce, which is the caller's own value.
      const { nonce, ...rest } = r.body;
      expect(nonce).toBeTypeOf("string");
      expect(rest).toEqual({
        error: "not_found",
        error_description: "Mission reference is not found or not visible.",
      });
    }
    // None of the six latched anything.
    expect(as.kernel.get(record.id)?.discharged).toBeUndefined();
  });

  it("checks the selectors before distinguishing a terminal Mission", async () => {
    const record = approveOnAs();
    const s = selectorsFor(record, "payments:remittance.send");
    await lifecycle(record.id, { operation: "revoke", nonce: freshNonce() });
    // A terminal Mission with an UNKNOWN entry_digest must not answer
    // terminal_noop: that would make the terminal state a selector oracle.
    const unknownSelector = await lifecycle(
      record.id,
      dischargeBody(record, { entry_digest: `sha-256:${"C".repeat(43)}` }),
    );
    expect(unknownSelector.status).toBe(404);
    expect(await unknownSelector.json()).toMatchObject({ error: "not_found" });
    // With every selector resolving, the same terminal Mission answers
    // terminal_noop, with no transition and no version increment.
    const versionBefore = as.kernel.get(record.id)?.version;
    const res = await lifecycle(record.id, dischargeBody(record));
    expect(res.status).toBe(200);
    expect(await dischargeResultOf(res)).toMatchObject({
      outcome: "terminal_noop",
      entry_digest: s.entry_digest,
      prior_version: versionBefore,
      current_version: versionBefore,
    });
    expect(as.kernel.get(record.id)?.version).toBe(versionBefore);
    expect(as.kernel.get(record.id)?.discharged).toBeUndefined();
  });

  it("discharges a suspended Mission, and acknowledges already_discharged after it", async () => {
    const record = approveOnAs();
    await lifecycle(record.id, { operation: "suspend", nonce: freshNonce() });
    const res = await lifecycle(record.id, dischargeBody(record));
    expect(res.status).toBe(200);
    expect(await dischargeResultOf(res)).toMatchObject({
      outcome: "discharged",
      prior_version: 2,
      current_version: 3,
    });
    expect(as.kernel.get(record.id)?.state).toBe("suspended");
    expect(as.kernel.effectiveAuthoritySet(as.kernel.get(record.id) as MissionRecord)).toHaveLength(1);

    // A later delivery under a DIFFERENT event_id: already_discharged, no second
    // increment.
    const again = await lifecycle(
      record.id,
      dischargeBody(record, { event_id: "close-second-occurrence" }),
    );
    expect(again.status).toBe(200);
    expect(await dischargeResultOf(again)).toMatchObject({
      outcome: "already_discharged",
      prior_version: 3,
      current_version: 3,
    });
    expect(as.kernel.get(record.id)?.version).toBe(3);
  });

  it("discharges duplicate entries as one equivalence-class transition", async () => {
    const duplicate = endpointProposal()[1] as AuthorityEntry;
    const record = approveOnAs([duplicate, duplicate]);
    expect(record.authority_set).toHaveLength(2);
    const res = await lifecycle(record.id, dischargeBody(record));
    expect(res.status).toBe(200);
    expect(await dischargeResultOf(res)).toMatchObject({
      outcome: "discharged",
      prior_version: 1,
      current_version: 2,
    });
    const after = as.kernel.get(record.id) as MissionRecord;
    expect(after.version).toBe(2); // exactly one increment for the whole class
    expect(after.discharged).toHaveLength(1);
    expect(as.kernel.effectiveAuthoritySet(after)).toEqual([]);
  });

  it("replays the stored signed response verbatim on a byte-identical retransmission", async () => {
    const record = approveOnAs();
    const body = dischargeBody(record);
    const first = await lifecycle(record.id, body);
    const firstJws = await first.text();
    const retransmit = await lifecycle(record.id, body);
    expect(retransmit.status).toBe(200);
    // The SAME signed response, byte for byte (not a re-signature).
    expect(await retransmit.text()).toBe(firstJws);
    expect(as.kernel.get(record.id)?.version).toBe(2); // executed once

    // The same nonce with a request that is not byte-identical is refused, never
    // answered with the unrelated original response.
    const divergent = await lifecycle(record.id, { ...body, event_id: "close-divergent" });
    expect(divergent.status).toBe(400);
    expect(await divergent.json()).toMatchObject({ error: "invalid_request", nonce: body.nonce });
    // The original response is still replayable (first writer wins).
    expect(await (await lifecycle(record.id, body)).text()).toBe(firstJws);
  });

  it("replays the event under a NEW nonce as a fresh envelope carrying the original versions", async () => {
    const record = approveOnAs();
    const body = dischargeBody(record, {
      evidence_ref: "https://close.example/q3",
      // Relative to the REAL clock: this HTTP harness runs on real time (no
      // injected `now`), and the endpoint bounds observed_at to +/- 24h of the
      // AS clock, so a hardcoded instant is a time bomb that arms as the wall
      // clock drifts past the window (it did: authored 2026-08-20, failing
      // from 2026-08-21).
      observed_at: new Date(Date.now() - 60_000).toISOString(),
    });
    const first = await lifecycle(record.id, body);
    expect(await dischargeResultOf(first)).toMatchObject({
      outcome: "discharged",
      prior_version: 1,
      current_version: 2,
    });

    // Same event tuple, same fingerprint, FRESH nonce: no state work, a new
    // envelope echoing the new nonce with the ORIGINAL versions.
    const replayNonce = freshNonce();
    const replay = await lifecycle(record.id, { ...body, nonce: replayNonce });
    expect(replay.status).toBe(200);
    const payload = decodeJwt(await replay.text()) as Record<string, unknown>;
    expect(payload.nonce).toBe(replayNonce);
    expect(payload.discharge_result).toMatchObject({
      outcome: "discharged",
      prior_version: 1,
      current_version: 2,
    });
    expect(as.kernel.get(record.id)?.version).toBe(2); // no re-latch

    // The same tuple with a DIFFERENT assertion fingerprint is a conflict.
    const conflict = await lifecycle(record.id, {
      ...body,
      nonce: freshNonce(),
      evidence_ref: "https://close.example/q3-amended",
    });
    expect(conflict.status).toBe(409);
    expect(await conflict.json()).toMatchObject({ error: "conflict" });
  });

  it("accepts the same event_id against a different target as an independent assertion", async () => {
    const one = approveOnAs();
    const two = approveOnAs();
    const shared = "close-fanout-2026-q3";
    const first = await lifecycle(one.id, dischargeBody(one, { event_id: shared }));
    const second = await lifecycle(two.id, dischargeBody(two, { event_id: shared }));
    expect(await dischargeResultOf(first)).toMatchObject({
      outcome: "discharged",
      event_id: shared,
    });
    expect(await dischargeResultOf(second)).toMatchObject({
      outcome: "discharged",
      event_id: shared,
    });
    expect(as.kernel.get(one.id)?.version).toBe(2);
    expect(as.kernel.get(two.id)?.version).toBe(2);
  });

  it("never dereferences evidence_ref and never lets an evidence member decide authorization", async () => {
    const record = approveOnAs();
    // Observe every outbound request this process makes while the discharge is
    // processed. A spy (rather than an unreachable host) is what actually proves
    // non-dereference: a fetch the handler never awaits, or awaits inside a
    // catch, would still be RECORDED here while leaving the response a prompt
    // 200. The AS runs in-process, so its own outbound calls are visible.
    const evidenceRef = "https://192.0.2.1/close-evidence.json";
    const original = globalThis.fetch;
    const requested: string[] = [];
    globalThis.fetch = ((input: RequestInfo | URL, init?: RequestInit) => {
      requested.push(typeof input === "string" ? input : input.toString());
      return original(input as never, init);
    }) as typeof fetch;
    let res: Response;
    try {
      res = await lifecycle(
        record.id,
        dischargeBody(record, {
          evidence_ref: evidenceRef,
          evidence_digest: `sha-256:${"D".repeat(43)}`,
        }),
      );
    } finally {
      globalThis.fetch = original;
    }
    expect(res.status).toBe(200);
    expect(await dischargeResultOf(res)).toMatchObject({ outcome: "discharged" });
    // Exactly one request: the test's own lifecycle POST. Nothing touched the
    // evidence reference.
    expect(requested.filter((u) => u.includes("192.0.2.1"))).toEqual([]);
    expect(requested).toEqual([`${ISSUER}/missions/${record.id}/lifecycle`]);
    // And evidence cannot buy authorization: the same members presented by a
    // caller without the discharge grant are still refused.
    const other = approveOnAs();
    const refused = await lifecycle(
      other.id,
      dischargeBody(other, {
        evidence_ref: "https://192.0.2.1/close-evidence.json",
        evidence_digest: `sha-256:${"D".repeat(43)}`,
      }),
      LIFECYCLE_ONLY_TOKEN,
    );
    expect(refused.status).toBe(404);
    expect(as.kernel.get(other.id)?.discharged).toBeUndefined();
  });

  it("refuses a malformed discharge request without touching the latch", async () => {
    const record = approveOnAs();
    const cases: Array<[string, Record<string, unknown>]> = [
      ["bad event_id", dischargeBody(record, { event_id: "not a valid id!" })],
      ["unprefixed entry_digest", dischargeBody(record, { entry_digest: "deadbeef" })],
      ["reason carried", dischargeBody(record, { reason: "because" })],
      [
        "oversized evidence_ref",
        dischargeBody(record, { evidence_ref: `https://x.example/${"a".repeat(520)}` }),
      ],
      ["skewed observed_at", dischargeBody(record, { observed_at: "2030-01-01T00:00:00Z" })],
    ];
    for (const [name, body] of cases) {
      const res = await lifecycle(record.id, body);
      expect(res.status, name).toBe(400);
      expect((await res.json()) as Record<string, unknown>, name).toMatchObject({
        error: "invalid_request",
      });
    }
    // A missing nonce is refused with NO nonce echoed.
    const noNonce = await lifecycle(record.id, { ...dischargeBody(record), nonce: undefined });
    expect(noNonce.status).toBe(400);
    const body = (await noNonce.json()) as Record<string, unknown>;
    expect(body.error).toBe("invalid_request");
    expect(body.nonce).toBeUndefined();
    expect(as.kernel.get(record.id)?.discharged).toBeUndefined();
  });

  it("commits atomically under a concurrency race: one discharged, one already_discharged, one increment", async () => {
    const record = approveOnAs();
    // Distinct nonces AND distinct event_ids, so neither idempotency store is
    // what serializes these: the monotonic latch is.
    const [a, b] = await Promise.all([
      lifecycle(record.id, dischargeBody(record, { event_id: "race-a" })),
      lifecycle(record.id, dischargeBody(record, { event_id: "race-b" })),
    ]);
    const outcomes = [
      (await dischargeResultOf(a as Response)).outcome,
      (await dischargeResultOf(b as Response)).outcome,
    ].sort();
    expect(outcomes).toEqual(["already_discharged", "discharged"]);
    const after = as.kernel.get(record.id) as MissionRecord;
    expect(after.version).toBe(2); // exactly one increment
    expect(after.discharged).toHaveLength(1); // exactly one latch
    expect(as.kernel.effectiveAuthoritySet(after).map((e) => e.actions)).toEqual([
      ["payments:invoice.read"],
    ]);
  });

  it("never authenticates an inherited Object.prototype name as a service token", async () => {
    const record = approveOnAs();
    for (const inherited of ["__proto__", "constructor", "toString", "hasOwnProperty"]) {
      const res = await lifecycle(record.id, dischargeBody(record), inherited);
      expect(res.status, `x-service-token: ${inherited} on lifecycle`).toBe(401);
      // The template admin plane gates on the same registry via
      // requireServiceToken and must refuse identically.
      const tpl = await fetch(`${ISSUER}/templates`, {
        method: "POST",
        headers: { "content-type": "application/json", "x-service-token": inherited },
        body: "{}",
      });
      expect(tpl.status, `x-service-token: ${inherited} on /templates`).toBe(401);
    }
    expect(as.kernel.get(record.id)?.discharged).toBeUndefined();
  });

  it("refuses malformed wire shapes as invalid_request, never a 500", async () => {
    const record = approveOnAs();
    const overrides: Array<Record<string, unknown>> = [
      { entry_digest: "sha-256:tooshort" }, // not 43 base64url chars
      { entry_digest: `sha-256:${"A".repeat(44)}` }, // one char too long
      { condition_digest: `sha-256:${"+".repeat(43)}` }, // base64, not base64url
      { observed_at: "Aug 20, 2026" }, // Date.parse-friendly, not RFC 3339
      { observed_at: "2026-08-20" }, // bare date, not RFC 3339 date-time
      { nonce: null }, // JSON null must be malformed-nonce, not a crash
      { nonce: "n".repeat(256) }, // exceeds the documented 255-char bound
    ];
    for (const over of overrides) {
      const res = await lifecycle(record.id, dischargeBody(record, over));
      expect(res.status, JSON.stringify(over)).toBe(400);
      expect(((await res.json()) as Record<string, unknown>).error).toBe("invalid_request");
    }
    // A valid-JSON body that is not an object lands as an empty member set:
    // no operation resolves, so it collapses into the endpoint's own
    // `not_found` vocabulary — a refusal, never a member-access 500.
    const nullBody = await lifecycle(record.id, null);
    expect(nullBody.status).toBe(404);
    expect(await nullBody.json()).toMatchObject({ error: "not_found" });
    expect(as.kernel.get(record.id)?.discharged).toBeUndefined();
  });

  it("terminal_noop over HTTP is event-idempotent: fresh-nonce replay returns the stored outcome, divergent re-assertion conflicts", async () => {
    const record = approveOnAs();
    expect((await lifecycle(record.id, { operation: "revoke", nonce: freshNonce() })).status).toBe(200);
    const body = dischargeBody(record);
    const first = await dischargeResultOf(await lifecycle(record.id, body));
    expect(first.outcome).toBe("terminal_noop");
    // An at-least-once sender's retry under a FRESH nonce: the stored
    // outcome with the original versions, not a second processing.
    const replay = await dischargeResultOf(await lifecycle(record.id, { ...body, nonce: freshNonce() }));
    expect(replay).toEqual(first);
    // The same tuple re-asserted with a different fingerprint: conflict.
    const divergent = await lifecycle(record.id, {
      ...body,
      nonce: freshNonce(),
      evidence_ref: "https://evidence.test/divergent",
    });
    expect(divergent.status).toBe(409);
    expect(await divergent.json()).toMatchObject({ error: "conflict" });
  });

  // -------------------------------------------------------------------------
  // Condition selectors (#898 fix 1), on the same endpoint.
  // -------------------------------------------------------------------------

  describe("condition selectors (#898 fix 1)", () => {
    /** The issuer's selector for the completing entry of `record`. */
    const selectorOf = (record: MissionRecord, action = "payments:remittance.send"): string => {
      const s = selectorsFor(record, action);
      return as.kernel.dischargeSelectors.selectorFor({
        mission_id: record.id,
        entry_digest: s.entry_digest,
        condition_digest: s.condition_digest,
      });
    };

    /** A selector-form discharge body for the completing entry of `record`. */
    const selectorBody = (
      record: MissionRecord,
      over: Record<string, unknown> = {},
    ): Record<string, unknown> => {
      const { entry_digest: _e, condition_digest: _c, ...rest } = dischargeBody(record);
      return { ...rest, condition_selector: selectorOf(record), ...over };
    };

    it("issues one selector per target, resolving to exactly that target, and discharges it", async () => {
      // Two entries carrying byte-identical conditions, plus a byte-identical
      // duplicate of the second: three record entries, two targets.
      const completing = (actions: string[]): AuthorityEntry => ({
        type: "mission_resource_access",
        resource: CANONICAL_RESOURCE,
        actions,
        constraints: { terminal_when: [{ event_type: CLOSE_EVENT, discharge_authority: CLOSE_POLICY }] },
      });
      const record = approveOnAs([
        completing(["payments:invoice.read"]),
        completing(["payments:remittance.send"]),
        completing(["payments:remittance.send"]),
      ]);
      const issued = as.kernel.dischargeSelectorsFor(record, record.authority_set);
      expect(issued.map((s) => [s.entry, s.condition])).toEqual([
        [0, 0],
        [1, 0],
        [2, 0],
      ]);
      const [read, send, duplicate] = issued.map((s) => s.selector);
      // Identical condition content on DIFFERENT targets: different selectors.
      expect(read).not.toBe(send);
      // The byte-identical duplicate is the same target: the same selector.
      expect(duplicate).toBe(send);
      // Asking again never mints a second selector for a target.
      expect(as.kernel.dischargeSelectorsFor(record, record.authority_set).map((s) => s.selector)).toEqual(
        [read, send, duplicate],
      );
      // Each selector resolves to exactly its own target.
      const sendSel = selectorsFor(record, "payments:remittance.send");
      expect(as.kernel.dischargeSelectors.resolve(send as string)).toEqual({
        mission_id: record.id,
        entry_digest: sendSel.entry_digest,
        condition_digest: sendSel.condition_digest,
      });
      expect(as.kernel.dischargeSelectors.resolve(read as string)?.entry_digest).toBe(
        entryDigest(record.issuer, record.authority_set[0] as AuthorityEntry),
      );
      // Discharging by the send selector latches the send target (and its
      // byte-identical duplicate, one equivalence class), never the read entry.
      const res = await lifecycle(record.id, selectorBody(record, { condition_selector: send }));
      expect(res.status).toBe(200);
      expect(await dischargeResultOf(res)).toMatchObject({ outcome: "discharged", current_version: 2 });
      const after = as.kernel.get(record.id) as MissionRecord;
      expect(after.discharged?.map((d) => d.entry_digest)).toEqual([sendSel.entry_digest]);
      expect(as.kernel.effectiveAuthoritySet(after).map((e) => e.actions)).toEqual([
        ["payments:invoice.read"],
      ]);
    });

    it("never derives a selector from the entry's content", () => {
      // Two Missions with byte-identical entries share entry and condition
      // digests; only the issuer-held random selector differs.
      const one = approveOnAs();
      const two = approveOnAs();
      const s1 = selectorsFor(one, "payments:remittance.send");
      const s2 = selectorsFor(two, "payments:remittance.send");
      expect(s1.entry_digest).toBe(s2.entry_digest);
      expect(s1.condition_digest).toBe(s2.condition_digest);
      const sel1 = selectorOf(one);
      const sel2 = selectorOf(two);
      expect(sel1).not.toBe(sel2);
      for (const sel of [sel1, sel2]) {
        expect(sel).toMatch(/^dcs_[A-Za-z0-9_-]{24}$/);
        // Nothing of either digest appears in it.
        expect(sel).not.toContain(s1.entry_digest.slice("sha-256:".length, 16));
        expect(sel).not.toContain(s1.condition_digest.slice("sha-256:".length, 16));
      }
      // A fresh issuer store minting for the SAME target yields a different
      // value: the selector is not a function of the target at all.
      const fresh = new DischargeSelectorStore(openStore(""));
      expect(
        fresh.selectorFor({ mission_id: one.id, entry_digest: s1.entry_digest, condition_digest: s1.condition_digest }),
      ).not.toBe(sel1);
    });

    it("keeps a selector resolvable after its target discharged, through a fresh-nonce event replay", async () => {
      const record = approveOnAs();
      const selector = selectorOf(record);
      // The target discharges by the DIGEST form.
      const original = dischargeBody(record);
      expect(await dischargeResultOf(await lifecycle(record.id, original))).toMatchObject({
        outcome: "discharged",
      });
      // The selector still resolves to the same target...
      expect(as.kernel.dischargeSelectors.resolve(selector)).toMatchObject({ mission_id: record.id });
      // ...so an at-least-once sender retrying the same occurrence by selector,
      // under a fresh nonce, recovers the stored result rather than not_found.
      const { entry_digest: _e, condition_digest: _c, ...rest } = original;
      const retry = await lifecycle(record.id, { ...rest, nonce: freshNonce(), condition_selector: selector });
      expect(retry.status).toBe(200);
      expect(await dischargeResultOf(retry)).toMatchObject({ outcome: "discharged", prior_version: 1, current_version: 2 });
    });

    it("refuses a request carrying both target forms, or neither, as invalid_request", async () => {
      const record = approveOnAs();
      const both = await lifecycle(record.id, { ...dischargeBody(record), condition_selector: selectorOf(record) });
      expect(both.status).toBe(400);
      expect(await both.json()).toMatchObject({ error: "invalid_request" });
      const { entry_digest: _e, condition_digest: _c, ...neitherBody } = dischargeBody(record);
      const neither = await lifecycle(record.id, neitherBody);
      expect(neither.status).toBe(400);
      expect(await neither.json()).toMatchObject({ error: "invalid_request" });
      // A selector beside only HALF the digest pair still carries both forms.
      const half = await lifecycle(record.id, {
        ...neitherBody,
        nonce: freshNonce(),
        condition_selector: selectorOf(record),
        entry_digest: selectorsFor(record, "payments:remittance.send").entry_digest,
      });
      expect(half.status).toBe(400);
      // A malformed selector is a request-shape failure too.
      const malformed = await lifecycle(record.id, selectorBody(record, { condition_selector: "bad selector!" }));
      expect(malformed.status).toBe(400);
      expect(as.kernel.get(record.id)?.discharged).toBeUndefined();
    });

    it("collapses an unresolvable selector, and one resolving outside the mission_id, into the identical not_found", async () => {
      const record = approveOnAs();
      const other = approveOnAs();
      const responses: Array<Record<string, unknown>> = [];
      // A well-formed selector that resolves to nothing.
      const unknown = await lifecycle(record.id, selectorBody(record, { condition_selector: "dcs_unknownSelector000000" }));
      expect(unknown.status).toBe(404);
      responses.push((await unknown.json()) as Record<string, unknown>);
      // A real selector of ANOTHER Mission, presented against this one.
      const elsewhere = await lifecycle(record.id, selectorBody(record, { condition_selector: selectorOf(other) }));
      expect(elsewhere.status).toBe(404);
      responses.push((await elsewhere.json()) as Record<string, unknown>);
      // A RESOLVING selector presented by a caller its target's mapping does
      // not admit: knowing a selector authorizes nothing.
      const unauthorized = await lifecycle(record.id, selectorBody(record), UNMAPPED_SOURCE_TOKEN);
      expect(unauthorized.status).toBe(404);
      responses.push((await unauthorized.json()) as Record<string, unknown>);
      // A digest-form unknown entry, for comparison.
      const digest = await lifecycle(record.id, dischargeBody(record, { entry_digest: `sha-256:${"D".repeat(43)}` }));
      expect(digest.status).toBe(404);
      responses.push((await digest.json()) as Record<string, unknown>);
      for (const body of responses) {
        const { nonce, ...rest } = body;
        expect(nonce).toBeTypeOf("string");
        expect(rest).toEqual({
          error: "not_found",
          error_description: "Mission reference is not found or not visible.",
        });
      }
      expect(as.kernel.get(record.id)?.discharged).toBeUndefined();
      expect(as.kernel.get(other.id)?.discharged).toBeUndefined();
    });

    it("shares one deduplication identity between the digest form and the selector form", async () => {
      const record = approveOnAs();
      const selector = selectorOf(record);
      // Selector form FIRST this time.
      const bySelector = selectorBody(record, { event_id: "close-shared-identity" });
      expect(await dischargeResultOf(await lifecycle(record.id, bySelector))).toMatchObject({
        outcome: "discharged",
        prior_version: 1,
        current_version: 2,
      });
      // The same occurrence in the DIGEST form is a replay, not a new assertion
      // (no already_discharged) and not a conflict.
      const byDigest = dischargeBody(record, { event_id: "close-shared-identity" });
      const replay = await lifecycle(record.id, byDigest);
      expect(replay.status).toBe(200);
      expect(await dischargeResultOf(replay)).toMatchObject({
        outcome: "discharged",
        prior_version: 1,
        current_version: 2,
      });
      expect(as.kernel.get(record.id)?.version).toBe(2);
      // And it is the SAME tuple: a divergent assertion in the other form conflicts.
      const divergent = await lifecycle(record.id, {
        ...byDigest,
        nonce: freshNonce(),
        evidence_ref: "https://close.example/divergent",
      });
      expect(divergent.status).toBe(409);
      expect(selector).toMatch(/^dcs_/);
    });

    it("never adds a digest to the result of a selector-form request", async () => {
      const record = approveOnAs();
      const body = selectorBody(record);
      const res = await lifecycle(record.id, body);
      expect(res.status).toBe(200);
      expect(await dischargeResultOf(res)).toEqual({
        condition_selector: body.condition_selector,
        event_id: body.event_id,
        outcome: "discharged",
        prior_version: 1,
        current_version: 2,
      });
    });

    it("echoes the current request's form on a fresh-nonce replay of a digest-form original", async () => {
      const record = approveOnAs();
      const original = dischargeBody(record, { event_id: "close-cross-form" });
      expect(await dischargeResultOf(await lifecycle(record.id, original))).toMatchObject({
        entry_digest: original.entry_digest,
        outcome: "discharged",
      });
      const { entry_digest: _e, condition_digest: _c, ...rest } = original;
      const retryNonce = freshNonce();
      const retry = await lifecycle(record.id, { ...rest, nonce: retryNonce, condition_selector: selectorOf(record) });
      expect(retry.status).toBe(200);
      const payload = decodeJwt(await retry.text()) as Record<string, unknown>;
      expect(payload.nonce).toBe(retryNonce);
      // The stored outcome and versions, with the SELECTOR echoed and no digest.
      expect(payload.discharge_result).toEqual({
        condition_selector: selectorOf(record),
        event_id: "close-cross-form",
        outcome: "discharged",
        prior_version: 1,
        current_version: 2,
      });
    });
  });
});

/**
 * @spec control-plane#serialization (#844) — THE EXPIRY CLOCK AND THE DISCHARGE
 * OPERATION'S TRANSACTION.
 *
 * `handleDischarge` opens the operation's transaction and `kernel.discharge`
 * applies the expiry clock inside it, before its selector and conflict
 * refusals. A refused discharge against a Mission past its ceiling therefore
 * discovered the expiry, wrote it, and unwound it with the refusal, leaving the
 * Mission `active` with neither its transition nor its publication. The fix
 * materializes expiry OUTSIDE the operation's transaction, guarded on
 * existence so an unknown Mission still gets the one indistinguishable
 * not-found body. Its own AS carries a lifecycle-commit subscriber that
 * witnesses the publication.
 */
describe("discharge: a refused discharge keeps the expiry it discovered (#844)", () => {
  const EXPIRY_PORT = PORT + 3;
  const EXPIRY_ISSUER = `http://localhost:${EXPIRY_PORT}`;
  let expiryAs: BuiltAs;
  let expiryServer: Server;
  const commits: LifecycleCommit[] = [];
  let approvals = 0;

  beforeAll(async () => {
    expiryAs = await buildAuthorizationServer({
      issuer: EXPIRY_ISSUER,
      allowHeadlessAdjudication: true,
      dischargeAuthority: ENDPOINT_AUTHORITY,
      onLifecycleCommit: (commit) => commits.push(commit),
    });
    expiryServer = expiryAs.provider.listen(EXPIRY_PORT);
  });
  afterAll(() => {
    expiryServer?.close();
  });

  const approve = (): MissionRecord => {
    approvals += 1;
    return expiryAs.kernel.approve({
      intent: endpointIntent(),
      proposedAuthority: endpointProposal(),
      subject: { iss: EXPIRY_ISSUER, sub: "alice" },
      approver: { iss: EXPIRY_ISSUER, sub: "bob" },
      clientId: "ap-agent",
      approvalEventId: `apev-dis-expiry-${approvals}`,
    });
  };

  const post = (missionId: string, body: unknown): Promise<Response> =>
    fetch(`${EXPIRY_ISSUER}/missions/${missionId}/lifecycle`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-service-token": DEV_SERVICE_TOKEN },
      body: JSON.stringify(body),
    });

  // Past the ceiling without touching the clock: the expiry clock reads the
  // STORED `expires_at`, so moving it into the past is the same discovery a
  // Mission that simply ran out of time presents.
  const expireStored = (record: MissionRecord): void => {
    expiryAs.kernel.db
      .prepare("UPDATE missions SET expires_at = ? WHERE id = ?")
      .run("2020-01-01T00:00:00Z", record.id);
  };

  const eventRows = (missionId: string): number =>
    (
      expiryAs.kernel.db
        .prepare("SELECT COUNT(*) AS n FROM discharge_events WHERE mission_id = ?")
        .get(missionId) as { n: number }
    ).n;

  const responseShape = async (res: Response) => {
    const { nonce, ...rest } = (await res.json()) as Record<string, unknown>;
    return {
      status: res.status,
      contentType: res.headers.get("content-type"),
      cacheControl: res.headers.get("cache-control"),
      nonce,
      rest,
    };
  };

  it("a selector refusal on an expired Mission leaves it expired at version + 1, published once, latching nothing", async () => {
    const record = approve();
    expireStored(record);
    commits.length = 0;
    const body = dischargeBody(record, { entry_digest: `sha-256:${"A".repeat(43)}` });

    const res = await post(record.id, body);
    expect(res.status).toBe(404);
    expect(await res.json()).toMatchObject({ error: "not_found" });

    const after = expiryAs.kernel.get(record.id);
    expect(after?.state).toBe("expired");
    expect(after?.version).toBe(record.version + 1);
    expect(after?.discharged).toBeUndefined();
    expect(eventRows(record.id)).toBe(0);
    expect(commits.map((c) => c.state)).toEqual(["expired"]);

    // The refusal claimed no success: a byte-identical retransmission is no 200.
    expect((await post(record.id, body)).status).not.toBe(200);
    // Refusing again under a fresh nonce materializes no second expiry.
    expect((await post(record.id, { ...body, nonce: freshNonce() })).status).toBe(404);
    expect(expiryAs.kernel.get(record.id)?.version).toBe(record.version + 1);
    expect(commits).toHaveLength(1);
  });

  it("a fingerprint conflict on an expired Mission keeps the expiry despite the 409", async () => {
    const record = approve();
    const body = dischargeBody(record);
    // A previously recorded event, so the divergent re-assertion below really
    // reaches the conflict branch.
    expect((await dischargeResultOf(await post(record.id, body))).outcome).toBe("discharged");
    const discharged = expiryAs.kernel.get(record.id) as MissionRecord;
    expireStored(record);
    commits.length = 0;

    const divergent = {
      ...body,
      nonce: freshNonce(),
      evidence_ref: "https://evidence.test/divergent",
    };
    const res = await post(record.id, divergent);
    expect(res.status).toBe(409);
    expect(await res.json()).toMatchObject({ error: "conflict" });

    const after = expiryAs.kernel.get(record.id);
    expect(after?.state).toBe("expired");
    expect(after?.version).toBe(discharged.version + 1);
    expect(commits.map((c) => c.state)).toEqual(["expired"]);

    // A second conflicting request transitions nothing further.
    expect((await post(record.id, { ...divergent, nonce: freshNonce() })).status).toBe(409);
    expect(expiryAs.kernel.get(record.id)?.version).toBe(discharged.version + 1);
    expect(commits).toHaveLength(1);
  });

  it("an unknown Mission and an expired known Mission with an unknown entry answer identically", async () => {
    const record = approve();
    expireStored(record);
    const unknownNonce = freshNonce();
    const knownNonce = freshNonce();

    const unknown = await responseShape(
      await post(
        "msn_does_not_exist",
        dischargeBody(record, { mission_id: "msn_does_not_exist", nonce: unknownNonce }),
      ),
    );
    const known = await responseShape(
      await post(
        record.id,
        dischargeBody(record, { entry_digest: `sha-256:${"C".repeat(43)}`, nonce: knownNonce }),
      ),
    );

    expect(unknown.status).toBe(404);
    expect(known.status).toBe(unknown.status);
    expect(known.contentType).toBe(unknown.contentType);
    expect(known.cacheControl).toBe(unknown.cacheControl);
    expect(known.rest).toEqual(unknown.rest);
    // Each nonce-bearing field follows the same rule: echoed by both, or neither.
    expect(known.nonce === undefined).toBe(unknown.nonce === undefined);
    if (unknown.nonce !== undefined) {
      expect(unknown.nonce).toBe(unknownNonce);
      expect(known.nonce).toBe(knownNonce);
    }
    // The guard touched only the known Mission: its expiry committed.
    expect(expiryAs.kernel.get(record.id)?.state).toBe("expired");
  });

  it("valid selectors on an expired Mission: terminal_noop, the expiry committed once, exact replay unchanged", async () => {
    const record = approve();
    expireStored(record);
    commits.length = 0;
    const body = dischargeBody(record);

    const res = await post(record.id, body);
    expect(res.status).toBe(200);
    const bytes = await res.text();
    const result = (decodeJwt(bytes) as Record<string, unknown>).discharge_result as Record<
      string,
      unknown
    >;
    expect(result.outcome).toBe("terminal_noop");
    expect(result.prior_version).toBe(record.version + 1);
    expect(result.current_version).toBe(record.version + 1);

    const after = expiryAs.kernel.get(record.id);
    expect(after?.state).toBe("expired");
    expect(after?.version).toBe(record.version + 1);
    expect(commits.map((c) => c.state)).toEqual(["expired"]);

    // A byte-identical retransmission replays the stored signed bytes verbatim.
    expect(await (await post(record.id, body)).text()).toBe(bytes);
    expect(commits).toHaveLength(1);
  });

  it("an injected failure inside the operation's transaction rolls the operation back and keeps the expiry", async () => {
    const record = approve();
    expireStored(record);
    commits.length = 0;
    const spy = vi.spyOn(expiryAs.kernel, "observeInCallerTx").mockImplementationOnce(() => {
      throw new Error("injected observation failure");
    });
    try {
      const res = await post(record.id, dischargeBody(record));
      expect(res.status).toBeGreaterThanOrEqual(500);
    } finally {
      spy.mockRestore();
    }

    const after = expiryAs.kernel.get(record.id);
    expect(after?.state).toBe("expired");
    expect(after?.version).toBe(record.version + 1);
    // The operation's own write (its terminal_noop event row) rolled back.
    expect(eventRows(record.id)).toBe(0);
    expect(commits.map((c) => c.state)).toEqual(["expired"]);
  });

  it("an expiry-store failure answers no success and is never disguised as not-found", async () => {
    const record = approve();
    expireStored(record);
    const spy = vi.spyOn(expiryAs.kernel, "materializeExpiry").mockImplementationOnce(() => {
      throw new Error("injected expiry-store failure");
    });
    let res: Response;
    try {
      res = await post(record.id, dischargeBody(record));
    } finally {
      spy.mockRestore();
    }
    expect(res.status).toBeGreaterThanOrEqual(500);
    expect(await res.text()).not.toContain("not_found");
    expect(eventRows(record.id)).toBe(0);
  });
});
