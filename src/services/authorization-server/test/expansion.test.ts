/**
 * @spec draft-mcguinness-oauth-mission-expansion, containment#restoration
 *
 * The containment anti-laundering MUST (D52): an expansion whose predecessor
 * carries a non-empty containment overlay MUST surface the predecessor's
 * containment history at expansion consent (at minimum the contained
 * capability and the event class that contained it). Pure, in-memory, no
 * network.
 */

import { DERIVATION_POLICY } from "@mission/demo-data";
import { type CryptoKey, generateKeyPair } from "jose";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { createExpansion, MissionKernel, validateMissionIntent } from "../src/index.js";
import { testAuthoritySourceCatalog } from "./authority-source.helper.js";

const ISS = "https://as.test";
const RESOURCE = DERIVATION_POLICY.ceiling[0].resource;
const EXP = "2027-01-01T00:00:00Z";
const now = () => new Date("2026-07-01T00:00:00Z");

const proposed = (actions: string[]) => [
  {
    type: "mission_resource_access" as const,
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
  kernel = new MissionKernel({ issuer: ISS, policy: DERIVATION_POLICY as never, authoritySourceCatalog: testAuthoritySourceCatalog(DERIVATION_POLICY.ceiling, ["ap-agent"]), statusKey: key, statusKid: "as-status", now });
});

const approve = (actions: string[]) =>
  kernel.approve({
    intent: validateMissionIntent(
      JSON.stringify({
        goal: "Pay Acme invoices for Q3",
        target_resources: [RESOURCE],
        expires_at: EXP,
      }),
    ),
    proposedAuthority: proposed(actions),
    subject: { iss: ISS, sub: "alice" },
    approver: { iss: ISS, sub: "bob" },
    clientId: "ap-agent",
    approvalEventId: `apev-${seq++}`,
  });

describe("expansion of an uncontained predecessor (regression: unchanged behavior)", () => {
  it("carries no containment history and evidence.containment_history is absent", () => {
    const mission = approve(["payments:invoice.read", "payments:payment.execute"]);
    const expansion = createExpansion(kernel, {
      predecessorId: mission.id,
      intent: validateMissionIntent(
        JSON.stringify({
          goal: "Pay Acme invoices for Q3 (widened)",
          target_resources: [RESOURCE],
          expires_at: EXP,
        }),
      ),
      proposedAuthority: proposed(["payments:invoice.read", "payments:payment.execute"]),
      approver: { iss: ISS, sub: "bob" },
      approvalEventId: `apev-succ-${seq++}`,
      approvedUntil: EXP,
    });
    expect(expansion.containmentHistory).toBeUndefined();
    expect(expansion.evidence.containment_history).toBeUndefined();
    expect(expansion.successor.containment).toBeUndefined();
  });
});

describe("expansion of a CONTAINED predecessor (@spec containment#restoration anti-laundering MUST)", () => {
  it("surfaces the predecessor's containment history in the disclosure and the evidence", () => {
    const mission = approve(["payments:invoice.read", "payments:remittance.send"]);

    const { evidence: containEvidence } = kernel.contain(mission.id, {
      event: {
        type: "tainted_read",
        source: "https://siem.example/detections",
        observed_at: now().toISOString(),
        event_id: "taint-exp-1",
      },
      remove: [{ resource: RESOURCE, actions: ["payments:remittance.send"] }],
    });
    expect(containEvidence.new_containment_version).toBe(1);

    const expansion = createExpansion(kernel, {
      predecessorId: mission.id,
      intent: validateMissionIntent(
        JSON.stringify({
          goal: "Pay Acme invoices and send remittance (restored after containment review)",
          target_resources: [RESOURCE],
          expires_at: EXP,
        }),
      ),
      proposedAuthority: proposed(["payments:invoice.read", "payments:remittance.send"]),
      approver: { iss: ISS, sub: "bob" },
      approvalEventId: `apev-succ-${seq++}`,
      approvedUntil: EXP,
    });

    // The disclosure: at minimum the contained capability and the event class.
    expect(expansion.containmentHistory).toEqual([
      { event_type: "tainted_read", removed: [{ resource: RESOURCE, actions: ["payments:remittance.send"] }] },
    ]);
    // The evidence record carries the same history.
    expect(expansion.evidence.containment_history).toEqual(expansion.containmentHistory);
    expect(expansion.evidence.predecessor).toEqual({
      id: mission.id,
      issuer: mission.issuer,
      authority_hash: mission.authority_hash,
    });
    expect(expansion.evidence.successor.id).toBe(expansion.successor.id);
    expect(expansion.evidence.evidence_id).toMatch(/^exp_/);

    // The successor's OWN overlay stays empty regardless (no laundering, no
    // propagation): this is disclosure only, never a re-application.
    expect(expansion.successor.containment).toBeUndefined();
  });

  it("carries multiple applied events, each with its own class and removed capability", () => {
    const mission = approve(["payments:invoice.read", "payments:remittance.send"]);
    kernel.contain(mission.id, {
      event: {
        type: "tainted_read",
        source: "https://siem.example/detections",
        observed_at: now().toISOString(),
        event_id: "taint-exp-2a",
      },
      remove: [{ resource: RESOURCE, actions: ["payments:remittance.send"] }],
    });
    kernel.contain(mission.id, {
      event: {
        type: "vendor_flagged",
        source: "https://siem.example/detections",
        observed_at: now().toISOString(),
        event_id: "taint-exp-2b",
      },
      remove: [{ resource: RESOURCE, actions: ["payments:invoice.read"] }],
    });

    const expansion = createExpansion(kernel, {
      predecessorId: mission.id,
      intent: validateMissionIntent(
        JSON.stringify({
          goal: "Restore after double containment review",
          target_resources: [RESOURCE],
          expires_at: EXP,
        }),
      ),
      proposedAuthority: proposed(["payments:invoice.read", "payments:remittance.send"]),
      approver: { iss: ISS, sub: "bob" },
      approvalEventId: `apev-succ-${seq++}`,
      approvedUntil: EXP,
    });

    expect(expansion.containmentHistory).toEqual([
      { event_type: "tainted_read", removed: [{ resource: RESOURCE, actions: ["payments:remittance.send"] }] },
      { event_type: "vendor_flagged", removed: [{ resource: RESOURCE, actions: ["payments:invoice.read"] }] },
    ]);
  });
});

describe("expansion: derivation_limit establishment (@spec mission#derivation-issuance-policy)", () => {
  it("is established fresh from the successor's own Intent, never inherited from the predecessor", () => {
    // Predecessor's OWN requested_derivation_limit (50) establishes ITS
    // derivation_limit under the demo deployment's default (no-ceiling) policy.
    const mission = kernel.approve({
      intent: validateMissionIntent(
        JSON.stringify({
          goal: "Pay Acme invoices for Q3",
          target_resources: [RESOURCE],
          expires_at: EXP,
          requested_derivation_limit: 50,
        }),
      ),
      proposedAuthority: proposed(["payments:invoice.read"]),
      subject: { iss: ISS, sub: "alice" },
      approver: { iss: ISS, sub: "bob" },
      clientId: "ap-agent",
      approvalEventId: `apev-${seq++}`,
    });
    expect(mission.derivation_limit).toBe(50);

    // A successor requesting a DIFFERENT, narrower limit (5) gets ITS OWN
    // value, not the predecessor's 50: proof of independence, not a
    // null/null coincidence.
    const narrower = createExpansion(kernel, {
      predecessorId: mission.id,
      intent: validateMissionIntent(
        JSON.stringify({
          goal: "Pay Acme invoices for Q3 (widened)",
          target_resources: [RESOURCE],
          expires_at: EXP,
          requested_derivation_limit: 5,
        }),
      ),
      proposedAuthority: proposed(["payments:invoice.read", "payments:payment.execute"]),
      approver: { iss: ISS, sub: "bob" },
      approvalEventId: `apev-succ-${seq++}`,
      approvedUntil: EXP,
    });
    expect(narrower.successor.derivation_limit).toBe(5);

    // A successor that OMITS requested_derivation_limit gets the
    // deployment's own ceiling (null here), never the predecessor's 50.
    const omitted = createExpansion(kernel, {
      predecessorId: mission.id,
      intent: validateMissionIntent(
        JSON.stringify({
          goal: "Pay Acme invoices for Q3 (widened, no request)",
          target_resources: [RESOURCE],
          expires_at: EXP,
        }),
      ),
      proposedAuthority: proposed(["payments:invoice.read", "payments:payment.execute"]),
      approver: { iss: ISS, sub: "bob" },
      approvalEventId: `apev-succ-${seq++}`,
      approvedUntil: EXP,
    });
    expect(omitted.successor.derivation_limit).toBeNull();
  });
});
