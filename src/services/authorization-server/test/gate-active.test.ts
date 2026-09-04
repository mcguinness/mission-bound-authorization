/**
 * Unit tests for kernel.gateActive (async-delegation foundation). gateActive runs
 * the SAME active/lineage gate as gateDerivation (expiry, active-state, ancestor
 * walk) but WITHOUT consuming a derivation: no requested_derivation_limit cap
 * check and no derivation_count increment. Network-free: a bare kernel over a
 * generated key.
 */

import { DERIVATION_POLICY } from "@mission/demo-data";
import { type CryptoKey, generateKeyPair } from "jose";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import {
  type AuthorityEntry,
  createChildMission,
  GateError,
  MissionKernel,
  validateMissionIntent,
} from "../src/index.js";
import { aiAgents } from "./actor-profiles.helper.js";
import { testAuthoritySourceCatalog } from "./authority-source.helper.js";

const ISS = "https://as.test";
const RESOURCE = DERIVATION_POLICY.ceiling[0].resource;
const now = () => new Date("2026-07-01T00:00:00Z");
const PARENT_EXP = "2027-01-01T00:00:00Z";

/** Restates the ceiling's Common Constraints so a subset probe is attributable. */
const proposed = (actions: string[]): AuthorityEntry[] => [
  {
    type: "mission_resource_access",
    resource: RESOURCE,
    actions,
    constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
  },
];

let key: CryptoKey;
let kernel: MissionKernel;
let seq = 0;

beforeAll(async () => {
  key = (await generateKeyPair("ES256")).privateKey;
});

beforeEach(() => {
  kernel = new MissionKernel({
    issuer: ISS,
    policy: DERIVATION_POLICY as never,
    authoritySourceCatalog: testAuthoritySourceCatalog(DERIVATION_POLICY.ceiling, ["parent-agent"]),
    statusKey: key,
    statusKid: "as-status",
    now,
    actorProfiles: aiAgents("subagent-reader"),
  });
});

const approve = (over: Record<string, unknown> = {}) =>
  kernel.approve({
    intent: validateMissionIntent(
      JSON.stringify({
        goal: "Pay Acme invoices for Q3",
        target_resources: [RESOURCE],
        expires_at: PARENT_EXP,
        ...over,
      }),
    ),
    proposedAuthority: proposed(["payments:invoice.read", "payments:payment.execute"]),
    subject: { iss: ISS, sub: "alice" },
    approver: { iss: ISS, sub: "bob" },
    clientId: "parent-agent",
    approvalEventId: `apev-${seq++}`,
  });

describe("kernel.gateActive (@spec mission#lifecycle)", () => {
  it("an active mission passes and derivation_count is UNCHANGED", () => {
    const r = approve();
    expect(kernel.get(r.id)?.derivation_count).toBe(0);
    // The distinguishing property vs gateDerivation: assert against the PERSISTED
    // row, before and after, so a stray increment could not hide in the return.
    expect(kernel.gateActive(r.id).state).toBe("active");
    expect(kernel.get(r.id)?.derivation_count).toBe(0);
    kernel.gateActive(r.id);
    expect(kernel.get(r.id)?.derivation_count).toBe(0);
  });

  it("a non-active (suspended) mission throws GateError", () => {
    const r = approve();
    kernel.transition(r.id, "suspend");
    expect(() => kernel.gateActive(r.id)).toThrow(GateError);
    expect(() => kernel.gateActive(r.id)).toThrow(/suspended/);
  });

  it("an expired mission throws GateError (mission_expired)", () => {
    const r = approve({ expires_at: "2020-01-01T00:00:00Z" });
    expect(() => kernel.gateActive(r.id)).toThrow(GateError);
    expect(() => kernel.gateActive(r.id)).toThrow(/expired/);
  });

  it("a mission whose ancestor is non-active throws (lineage walk)", () => {
    const parent = approve();
    const { child } = createChildMission(kernel, {
      parentId: parent.id,
      intent: validateMissionIntent(
        JSON.stringify({
          goal: "Read Acme invoices",
          target_resources: [RESOURCE],
          expires_at: PARENT_EXP,
        }),
      ),
      proposedAuthority: proposed(["payments:invoice.read"]),
      childActor: { sub: "subagent-reader", sub_profile: "ai_agent" },
    });
    // Raw UPDATE bypasses setState, so NO cascade fires and the child stays
    // active: this isolates the ancestor-active branch of the gate. (Going
    // through transition() would cascade the child to `cascaded` and the gate
    // would instead trip on the child's own state, testing nothing.)
    kernel.db.prepare("UPDATE missions SET state = 'revoked' WHERE id = ?").run(parent.id);
    expect(kernel.get(child.id)?.state).toBe("active"); // precondition
    // The regex is discriminating: only the lineage branch produces this message,
    // proving the walk fired rather than the child's own state check.
    expect(() => kernel.gateActive(child.id)).toThrow(/non-active ancestor/);
  });

  it("a mission at its requested_derivation_limit cap still passes gateActive (cap NOT enforced)", () => {
    const r = approve({ requested_derivation_limit: 1 });
    // Exhaust the cap via gateDerivation.
    kernel.gateDerivation(r.id);
    expect(kernel.get(r.id)?.derivation_count).toBe(1);
    expect(() => kernel.gateDerivation(r.id)).toThrow(GateError); // cap now exhausted
    // gateActive ignores the cap AND does not increment.
    expect(kernel.gateActive(r.id).state).toBe("active");
    expect(kernel.get(r.id)?.derivation_count).toBe(1);
  });
});
