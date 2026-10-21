/**
 * @spec containment#selector-matching, containment#overlay,
 * child-delegation#child-state (#1463, D606)
 *
 * Containment by resource-set overlap through the kernel's public API: a
 * contained capability is a selector, `exact` by default and `prefix` by
 * declaration, and it applies to every approved entry whose resource set
 * overlaps it under Resource Access matching. The ceiling here is a
 * programmatic `prefix` entry, so entries approved beneath it can be finer
 * than any selector; prefix-ceiling-endpoint.test.ts drives the same rule
 * through the lifecycle endpoint over a configured `prefix` ceiling.
 */

import { CONTAINMENT_POLICY } from "@mission/demo-data";
import { generateKeyPair } from "jose";
import { beforeAll, describe, expect, it } from "vitest";
import {
  type AuthorityEntry,
  ContainmentSelectorError,
  createChildMission,
  GateError,
  type MissionKernel as Kernel,
  MissionKernel,
  validateMissionIntent,
} from "../src/index.js";
import { restrictedSinceAdjudication } from "../src/kernel/expansion.js";
import { aiAgents } from "./actor-profiles.helper.js";
import { testAuthoritySourceCatalog } from "./authority-source.helper.js";

const ISS = "https://as.overlap.test";
const SERVICE = "https://payments.test/mcp";
const INVOICES = `${SERVICE}/invoices`;
const INV1 = `${INVOICES}/inv-1`;
const INV2 = `${INVOICES}/inv-2`;
const INVOICESX = `${SERVICE}/invoicesx/inv-1`;
const FILES = "https://files.test/mcp";
const NOW = new Date("2026-10-20T12:00:00Z");

const READ = "payments:invoice.read";
const SEND = "payments:remittance.send";
const EXECUTE = "payments:payment.execute";

const CHILDREN = { max_children: 5, max_child_depth: 2, allowed_child_actors: [{ sub_profile: "ai_agent" }] };

/** A `prefix` ceiling over the whole service and an exact files service, both delegable to children. */
const ceilingFor = (base: string) => [
  {
    type: "mission_resource_access",
    resource: base,
    resource_match: "prefix",
    actions: [READ, SEND, EXECUTE],
    delegation: { max_depth: 2, children: CHILDREN },
  },
  {
    type: "mission_resource_access",
    resource: FILES,
    actions: ["files:doc.read"],
    delegation: { max_depth: 2, children: CHILDREN },
  },
];

const entry = (resource: string, actions: string[], resource_match?: "prefix"): AuthorityEntry =>
  ({
    type: "mission_resource_access",
    resource,
    ...(resource_match ? { resource_match } : {}),
    actions,
  }) as AuthorityEntry;

let statusKey: CryptoKey;
beforeAll(async () => {
  ({ privateKey: statusKey } = (await generateKeyPair("ES256", { extractable: true })) as { privateKey: CryptoKey });
});

function kernelOver(base = `${SERVICE}/`, containmentPolicy?: typeof CONTAINMENT_POLICY): Kernel {
  const ceiling = ceilingFor(base);
  return new MissionKernel({
    issuer: ISS,
    policy: { policy_version: "containment-overlap-1463", ceiling } as never,
    authoritySourceCatalog: testAuthoritySourceCatalog(ceiling, ["ap-agent"], ["bob"]),
    actorProfiles: aiAgents("child-a", "child-b", "child-c"),
    ...(containmentPolicy ? { containmentPolicy: containmentPolicy as never } : {}),
    statusKey,
    statusKid: "overlap-status",
    now: () => NOW,
  });
}

let seq = 0;
function approve(kernel: Kernel, proposed: AuthorityEntry[]) {
  return kernel.approve({
    intent: validateMissionIntent(
      JSON.stringify({
        goal: "Pay and reconcile Acme invoices",
        target_resources: [...new Set(proposed.map((e) => e.resource))],
        expires_at: "2027-01-01T00:00:00Z",
      }),
    ),
    proposedAuthority: proposed,
    subject: { iss: ISS, sub: "alice" },
    approver: { iss: ISS, sub: "bob" },
    clientId: "ap-agent",
    approvalEventId: `apev-overlap-${++seq}`,
  });
}

const ev = (id: string) => ({ type: "anomaly.detected", source: "svc:soc", observed_at: NOW.toISOString(), event_id: id });

/** The effective set as (resource, resource_match, actions) triples. */
function effective(kernel: Kernel, id: string) {
  const record = kernel.get(id);
  if (!record) throw new Error(`no mission ${id}`);
  return kernel.effectiveAuthoritySet(record).map((e) => ({
    resource: e.resource,
    ...(e.resource_match ? { resource_match: e.resource_match } : {}),
    actions: e.actions,
  }));
}

describe("a selector applies to every approved entry whose resource set overlaps it (@spec containment#selector-matching, #1463)", () => {
  it("a broad prefix selector contains a finer entry approved beneath a prefix ceiling", () => {
    const kernel = kernelOver();
    const m = approve(kernel, [entry(INV1, [READ, SEND])]);
    kernel.contain(m.id, { event: ev("evt-broad"), remove: [{ resource: SERVICE, resource_match: "prefix", actions: [SEND] }] });
    expect(effective(kernel, m.id)).toEqual([{ resource: INV1, actions: [READ] }]);
  });

  it("an exact selector is never a subtree selector: an exact service root leaves a finer entry untouched", () => {
    const kernel = kernelOver();
    const m = approve(kernel, [entry(INV1, [READ, SEND]), entry(`${SERVICE}/`, [READ, SEND], "prefix")]);
    kernel.contain(m.id, { event: ev("evt-root"), remove: [{ resource: SERVICE, actions: [SEND] }] });
    // `https://payments.test/mcp` exactly is outside both the finer entry and the `/mcp/` base.
    expect(effective(kernel, m.id)).toEqual([
      { resource: INV1, actions: [READ, SEND] },
      { resource: `${SERVICE}/`, resource_match: "prefix", actions: [READ, SEND] },
    ]);
  });

  it("a fine selector over a broad prefix entry removes the selected action across the whole entry (conservative over-containment)", () => {
    const kernel = kernelOver();
    const m = approve(kernel, [entry(`${SERVICE}/`, [READ, SEND], "prefix")]);
    kernel.contain(m.id, { event: ev("evt-fine"), remove: [{ resource: INV1, actions: [SEND] }] });
    // The entry cannot express "this prefix except inv-1", so SEND leaves the whole entry, inv-2 included.
    expect(effective(kernel, m.id)).toEqual([{ resource: `${SERVICE}/`, resource_match: "prefix", actions: [READ] }]);
  });

  it("disjoint siblings and path-segment boundaries are untouched", () => {
    const kernel = kernelOver();
    const m = approve(kernel, [entry(INV1, [READ, SEND]), entry(INV2, [READ, SEND]), entry(INVOICESX, [READ, SEND])]);
    kernel.contain(m.id, { event: ev("evt-sib-1"), remove: [{ resource: INVOICES, resource_match: "prefix", actions: [SEND] }] });
    // `/invoicesx/inv-1` shares the base's characters but not a path-segment boundary.
    expect(effective(kernel, m.id)).toEqual([
      { resource: INV1, actions: [READ] },
      { resource: INV2, actions: [READ] },
      { resource: INVOICESX, actions: [READ, SEND] },
    ]);
    kernel.contain(m.id, { event: ev("evt-sib-2"), remove: [{ resource: INV1 }] });
    // An exact selector for one invoice drops that entry and no sibling.
    expect(effective(kernel, m.id)).toEqual([
      { resource: INV2, actions: [READ] },
      { resource: INVOICESX, actions: [READ, SEND] },
    ]);
  });

  it("multiple overlapping selectors form a union: every overlapping selector contributes, never only the first", () => {
    const kernel = kernelOver();
    const m = approve(kernel, [entry(INV1, [READ, SEND, EXECUTE]), entry(INV2, [READ, SEND, EXECUTE])]);
    kernel.contain(m.id, {
      event: ev("evt-multi"),
      remove: [
        { resource: INVOICES, resource_match: "prefix", actions: [SEND] },
        { resource: INV1, actions: [EXECUTE] },
      ],
    });
    expect(effective(kernel, m.id)).toEqual([
      { resource: INV1, actions: [READ] },
      { resource: INV2, actions: [READ, EXECUTE] },
    ]);
  });

  it("selectors naming one resource string under different modes stay separate in the overlay and select different resource sets", () => {
    const kernel = kernelOver();
    const m = approve(kernel, [entry(INVOICES, [READ, SEND, EXECUTE]), entry(INV1, [READ, SEND, EXECUTE])]);
    const { record } = kernel.contain(m.id, {
      event: ev("evt-modes"),
      remove: [
        { resource: INVOICES, actions: [SEND] },
        { resource: INVOICES, resource_match: "prefix", actions: [EXECUTE] },
      ],
    });
    expect(record.containment?.contained).toEqual([
      { resource: INVOICES, actions: [SEND] },
      { resource: INVOICES, resource_match: "prefix", actions: [EXECUTE] },
    ]);
    // The exact `/invoices` entry loses both; the finer invoice loses only the prefix selector's action.
    expect(effective(kernel, m.id)).toEqual([
      { resource: INVOICES, actions: [READ] },
      { resource: INV1, actions: [READ, SEND] },
    ]);
  });

  it("removes only the selected actions from an overlapping entry, and the whole entry for a selector with no actions", () => {
    const kernel = kernelOver();
    const m = approve(kernel, [entry(INV1, [READ, SEND]), entry(FILES, ["files:doc.read"])]);
    kernel.contain(m.id, { event: ev("evt-act-1"), remove: [{ resource: SERVICE, resource_match: "prefix", actions: [SEND] }] });
    expect(effective(kernel, m.id)).toEqual([
      { resource: INV1, actions: [READ] },
      { resource: FILES, actions: ["files:doc.read"] },
    ]);
    kernel.contain(m.id, { event: ev("evt-act-2"), remove: [{ resource: SERVICE, resource_match: "prefix" }] });
    expect(effective(kernel, m.id)).toEqual([{ resource: FILES, actions: ["files:doc.read"] }]);
    kernel.contain(m.id, { event: ev("evt-act-3"), remove: [{ resource: FILES }] });
    expect(() => kernel.gateDerivation(m.id)).toThrow(GateError);
  });

  it("refuses a selector the matcher cannot decide before anything commits", () => {
    const kernel = kernelOver();
    const m = approve(kernel, [entry(INV1, [READ, SEND])]);
    for (const selector of [
      { resource: SERVICE, resource_match: "glob" },
      { resource: `${SERVICE}?tenant=a`, resource_match: "prefix" },
      { resource: SERVICE, actions: [] },
    ]) {
      expect(() => kernel.contain(m.id, { event: ev("evt-bad"), remove: [selector as never] })).toThrow(
        ContainmentSelectorError,
      );
    }
    expect(kernel.get(m.id)?.containment).toBeUndefined();
    expect(kernel.get(m.id)?.version).toBe(m.version);
  });

  it("resolves the overlay onto the approved entries for a consumer that pairs by an entry's own resource", () => {
    const kernel = kernelOver();
    const m = approve(kernel, [entry(INV1, [READ, SEND]), entry(`${SERVICE}/`, [READ, EXECUTE], "prefix"), entry(FILES, ["files:doc.read"])]);
    const { record } = kernel.contain(m.id, {
      event: ev("evt-resolve"),
      remove: [{ resource: INVOICES, resource_match: "prefix", actions: [SEND] }],
    });
    expect(kernel.containedEntryRemovals(record)).toEqual([
      { resource: INV1, actions: [SEND] },
      { resource: `${SERVICE}/`, resource_match: "prefix", actions: [SEND] },
    ]);
  });
});

describe("containment propagates by overlap to existing children (@spec child-delegation#child-state, containment#selector-matching, #1463)", () => {
  it("a fine selector over the parent's broad prefix entry reaches an existing child's sibling entry justified by it", () => {
    const kernel = kernelOver();
    const parent = approve(kernel, [entry(`${SERVICE}/`, [READ, SEND], "prefix"), entry(FILES, ["files:doc.read"])]);
    const { child } = createChildMission(kernel, {
      parentId: parent.id,
      intent: validateMissionIntent(
        JSON.stringify({ goal: "Pay invoice 2", target_resources: [INV2], expires_at: "2027-01-01T00:00:00Z" }),
      ),
      proposedAuthority: [entry(INV2, [READ, SEND])],
      childActor: { sub: "child-a", sub_profile: "ai_agent" },
    });
    const { child: filesChild } = createChildMission(kernel, {
      parentId: parent.id,
      intent: validateMissionIntent(
        JSON.stringify({ goal: "Read files", target_resources: [FILES], expires_at: "2027-01-01T00:00:00Z" }),
      ),
      proposedAuthority: [entry(FILES, ["files:doc.read"])],
      childActor: { sub: "child-b", sub_profile: "ai_agent" },
    });

    kernel.contain(parent.id, { event: ev("evt-prop-fine"), remove: [{ resource: INV1, actions: [SEND] }] });

    // The parent's `/mcp/` entry lost SEND whole; the child's inv-2, justified by it, loses it too.
    expect(effective(kernel, parent.id)).toEqual([
      { resource: `${SERVICE}/`, resource_match: "prefix", actions: [READ] },
      { resource: FILES, actions: ["files:doc.read"] },
    ]);
    expect(effective(kernel, child.id)).toEqual([{ resource: INV2, actions: [READ] }]);
    expect(kernel.get(child.id)?.containment?.contained).toContainEqual({
      resource: `${SERVICE}/`,
      resource_match: "prefix",
      actions: [SEND],
    });
    // A child no selector reaches is untouched: no overlay, no version bump.
    expect(kernel.get(filesChild.id)?.containment).toBeUndefined();
    expect(kernel.get(filesChild.id)?.version).toBe(filesChild.version);
  });

  it("a broad prefix selector reaches an existing child's finer entry", () => {
    const kernel = kernelOver();
    const parent = approve(kernel, [entry(`${SERVICE}/`, [READ, SEND], "prefix")]);
    const { child } = createChildMission(kernel, {
      parentId: parent.id,
      intent: validateMissionIntent(
        JSON.stringify({ goal: "Pay invoice 1", target_resources: [INV1], expires_at: "2027-01-01T00:00:00Z" }),
      ),
      proposedAuthority: [entry(INV1, [READ, SEND])],
      childActor: { sub: "child-c", sub_profile: "ai_agent" },
    });

    kernel.contain(parent.id, {
      event: ev("evt-prop-broad"),
      remove: [{ resource: INVOICES, resource_match: "prefix", actions: [SEND] }],
    });

    expect(effective(kernel, child.id)).toEqual([{ resource: INV1, actions: [READ] }]);
  });
});

describe("an expansion's reconciliation compares containment restrictions by overlap (@spec expansion#reconciliation check 3, containment#selector-matching, #1463)", () => {
  it("a removal after adjudication restricts a successor entry its selector overlaps under another resource string, and no disjoint sibling", () => {
    const kernel = kernelOver();
    const m = approve(kernel, [entry(INV1, [READ, SEND]), entry(INVOICESX, [READ, SEND])]);
    const { record } = kernel.contain(m.id, {
      event: ev("evt-recon-1"),
      remove: [{ resource: INVOICES, resource_match: "prefix", actions: [SEND] }],
    });
    const at = { containment: 0, discharge: 0 };
    expect(restrictedSinceAdjudication(record, [entry(INV1, [SEND])], at)).toBe(true);
    expect(restrictedSinceAdjudication(record, [entry(`${SERVICE}/`, [SEND], "prefix")], at)).toBe(true);
    expect(restrictedSinceAdjudication(record, [entry(INVOICESX, [SEND])], at)).toBe(false);
    expect(restrictedSinceAdjudication(record, [entry(INV1, [READ])], at)).toBe(false);
  });

  it("a removal naming authority already contained at adjudication restricts nothing new, judged by resource set", () => {
    const kernel = kernelOver();
    const m = approve(kernel, [entry(INV1, [READ, SEND]), entry(INV2, [READ, SEND])]);
    kernel.contain(m.id, { event: ev("evt-recon-before"), remove: [{ resource: INV1, actions: [SEND] }] });
    const { record } = kernel.contain(m.id, {
      event: ev("evt-recon-after"),
      remove: [{ resource: INVOICES, resource_match: "prefix", actions: [SEND] }],
    });
    const at = { containment: 1, discharge: 0 };
    // inv-1 was contained before adjudication, so the later, broader removal adds nothing there...
    expect(restrictedSinceAdjudication(record, [entry(INV1, [SEND])], at)).toBe(false);
    // ...but it newly restricts its sibling.
    expect(restrictedSinceAdjudication(record, [entry(INV2, [SEND])], at)).toBe(true);
  });
});
