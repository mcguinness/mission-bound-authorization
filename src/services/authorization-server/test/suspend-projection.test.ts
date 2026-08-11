/**
 * @spec child-delegation#cascade (reversible trigger), #child-state
 *
 * Suspend-projection and restore-on-resume: when a PARENT Mission is suspended,
 * its active descendants are projected to the REVERSIBLE `suspended` hold (not
 * the terminal `cascaded` cascade), recorded via `projected_from`; on parent
 * resume they are restored to their pre-suspension state, with expiry precedence
 * and independent-suspend safety. Plus the ancestor-active derivation gate. All
 * deterministic, no network.
 */

import { DERIVATION_POLICY } from "@mission/demo-data";
import { type CryptoKey, generateKeyPair } from "jose";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import {
  createChildMission,
  GateError,
  type LifecycleCommit,
  MissionKernel,
  validateMissionIntent,
} from "../src/index.js";
import { aiAgents } from "./actor-profiles.helper.js";

const ISS = "https://as.test";
const RESOURCE = DERIVATION_POLICY.ceiling[0].resource as string;
const PARENT_EXP = "2027-01-01T00:00:00Z";

// A mutable clock so a child can expire mid-suspension deterministically.
let clock: Date;
const now = () => clock;

/** A proposed entry restating the ceiling's Common Constraints so the derived
 *  entry carries max_amount/vendors and the child subset probe is exact. */
const proposed = (actions: string[]) => [
  {
    type: "mission_resource_access",
    resource: RESOURCE,
    actions,
    constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
  },
];

let key: CryptoKey;
let kernel: MissionKernel;
let commits: LifecycleCommit[];
let seq = 0;

beforeAll(async () => {
  key = (await generateKeyPair("ES256")).privateKey;
});

beforeEach(() => {
  clock = new Date("2026-07-01T00:00:00Z");
  commits = [];
  kernel = new MissionKernel({
    issuer: ISS,
    policy: DERIVATION_POLICY as never,
    statusKey: key,
    statusKid: "as-status",
    now,
    actorProfiles: aiAgents("child-agent", "grandchild-agent"),
    onLifecycleCommit: (c) => commits.push(c),
  });
});

const approveParent = () =>
  kernel.approve({
    intent: validateMissionIntent(
      JSON.stringify({
        goal: "Pay Acme invoices for Q3",
        resources: [RESOURCE],
        expires_at: PARENT_EXP,
        proposed_authority: proposed(["payments:invoice.read", "payments:payment.execute"]),
      }),
    ),
    subject: { iss: ISS, sub: "alice" },
    approver: { iss: ISS, sub: "bob" },
    clientId: "parent-agent",
    approvalEventId: `apev-${seq++}`,
  });

/** Create a child under `parentId`, actor an ai_agent, optionally overriding the
 *  child intent (e.g. an earlier expires_at). */
const createChild = (
  parentId: string,
  sub: string,
  intentOver: Record<string, unknown> = {},
) =>
  createChildMission(kernel, {
    parentId,
    intent: validateMissionIntent(
      JSON.stringify({
        goal: "Extract Acme invoices",
        resources: [RESOURCE],
        expires_at: PARENT_EXP,
        proposed_authority: proposed(["payments:invoice.read"]),
        ...intentOver,
      }),
    ),
    childActor: { sub, sub_profile: "ai_agent" },
  }).child;

describe("suspend-projection (@spec child-delegation#cascade reversible trigger)", () => {
  it("(a) parent suspend projects active descendants to suspended, in generation order", () => {
    const parent = approveParent();
    const child = createChild(parent.id, "child-agent");
    const grandchild = createChild(child.id, "grandchild-agent");
    expect(child.parent?.depth).toBe(1);
    expect(grandchild.parent?.depth).toBe(2);
    const before = commits.length;

    kernel.transition(parent.id, "suspend");

    // Each active descendant is now a reversible `suspended` hold with a marker.
    const c = kernel.get(child.id);
    const g = kernel.get(grandchild.id);
    expect(c?.state).toBe("suspended");
    expect(c?.projected_from).toBe("active");
    expect(c?.version).toBe(2); // insert v1 -> projected v2
    expect(g?.state).toBe("suspended");
    expect(g?.projected_from).toBe("active");
    expect(g?.version).toBe(2);

    // A lifecycle commit was observed for the child (Status List / Signals fan-out).
    const childCommit = commits
      .slice(before)
      .find((x) => x.id === child.id && x.state === "suspended");
    expect(childCommit?.prior_state).toBe("active");
    expect(childCommit?.version).toBe(2);

    // Generation order: parent, then child, then grandchild.
    const order = commits
      .slice(before)
      .filter((x) => x.state === "suspended")
      .map((x) => x.id);
    expect(order).toEqual([parent.id, child.id, grandchild.id]);
  });

  it("(b) a child whose expires_at passed during suspension is reported expired on resume", () => {
    const parent = approveParent();
    // Child expires 2026-08-01 (< parent 2027, so the clamp keeps the child's own).
    const child = createChild(parent.id, "child-agent", { expires_at: "2026-08-01T00:00:00Z" });
    expect(child.expires_at).toBe("2026-08-01T00:00:00Z");

    kernel.transition(parent.id, "suspend");
    expect(kernel.get(child.id)?.state).toBe("suspended");

    // Advance past the child's expiry but before the parent's, then resume.
    clock = new Date("2026-09-01T00:00:00Z");
    kernel.transition(parent.id, "resume");

    // Expiry precedence: expired, NOT restored to active.
    expect(kernel.get(child.id)?.state).toBe("expired");
    expect(() => kernel.gateDerivation(child.id)).toThrow(GateError);
  });

  it("(c) parent resume restores a projected child to its exact prior state, version +1", () => {
    const parent = approveParent();
    const child = createChild(parent.id, "child-agent");
    kernel.transition(parent.id, "suspend");
    expect(kernel.get(child.id)?.version).toBe(2);
    const before = commits.length;

    kernel.transition(parent.id, "resume");

    const c = kernel.get(child.id);
    expect(c?.state).toBe("active"); // restored to the exact pre-suspension state
    expect(c?.projected_from).toBeUndefined(); // marker cleared
    expect(c?.version).toBe(3); // v1 insert -> v2 suspended -> v3 restored
    // The restore (suspended -> active) lift commit was observed.
    const lift = commits
      .slice(before)
      .find((x) => x.id === child.id && x.state === "active");
    expect(lift?.prior_state).toBe("suspended");
    expect(lift?.version).toBe(3);
    // gateDerivation permitted again.
    expect(() => kernel.gateDerivation(child.id)).not.toThrow();
  });

  it("(d) an independently-suspended child is NOT restored on parent resume", () => {
    const parent = approveParent();
    const child = createChild(parent.id, "child-agent");

    // The child is suspended INDEPENDENTLY first: no projection marker is stamped.
    kernel.transition(child.id, "suspend");
    expect(kernel.get(child.id)?.projected_from).toBeUndefined();

    kernel.transition(parent.id, "suspend"); // child already suspended -> skipped, still no marker
    expect(kernel.get(child.id)?.projected_from).toBeUndefined();

    kernel.transition(parent.id, "resume");
    // The child stays suspended: it was never projected, so it is not restored.
    expect(kernel.get(child.id)?.state).toBe("suspended");
    expect(kernel.get(child.id)?.version).toBe(2); // never touched by project/restore
  });

  it("(f) a parent revoked while suspended still cascades the child terminally", () => {
    const parent = approveParent();
    const child = createChild(parent.id, "child-agent");
    const grandchild = createChild(child.id, "grandchild-agent");

    kernel.transition(parent.id, "suspend");
    expect(kernel.get(child.id)?.state).toBe("suspended");
    expect(kernel.get(child.id)?.projected_from).toBe("active");

    // Terminal wins: revoking the suspended parent drives descendants to `cascaded`.
    kernel.transition(parent.id, "revoke");
    expect(kernel.get(child.id)?.state).toBe("cascaded");
    expect(kernel.get(grandchild.id)?.state).toBe("cascaded");
  });
});

describe("ancestor-active gate (@spec child-delegation#child-state)", () => {
  it("(e) derivation under a child is refused while an ancestor is suspended, permitted after resume", () => {
    const parent = approveParent();
    const child = createChild(parent.id, "child-agent");

    // Projection covers the direct case: the child is itself suspended.
    kernel.transition(parent.id, "suspend");
    expect(() => kernel.gateDerivation(child.id)).toThrow(GateError);
    kernel.transition(parent.id, "resume");
    expect(() => kernel.gateDerivation(child.id)).not.toThrow();
  });

  it("(e') the ancestor walk refuses an ACTIVE child under a still-suspended ancestor", () => {
    const parent = approveParent();
    const child = createChild(parent.id, "child-agent");

    kernel.transition(parent.id, "suspend"); // child projected -> suspended, marker set
    kernel.transition(child.id, "resume"); // child directly back to active, marker cleared
    expect(kernel.get(child.id)?.state).toBe("active");
    expect(kernel.get(child.id)?.projected_from).toBeUndefined();

    // The child is active but its parent is still suspended: only the ancestor
    // walk can refuse here (the self-state check passes).
    try {
      kernel.gateDerivation(child.id);
      expect.unreachable();
    } catch (e) {
      expect(e).toBeInstanceOf(GateError);
      expect((e as GateError).reason).toBe("mission_not_active");
    }

    // Resuming the parent lets the child derive again; and the directly-resumed
    // child is NOT double-restored (state !== suspended, so it is skipped).
    const v = kernel.get(child.id)?.version;
    kernel.transition(parent.id, "resume");
    expect(kernel.get(child.id)?.version).toBe(v); // untouched by the parent's restore
    expect(() => kernel.gateDerivation(child.id)).not.toThrow();
  });
});
