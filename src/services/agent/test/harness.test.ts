/**
 * M12 scenario 14: the 02:00 resume. The agent idles; the mission is
 * completed/cancelled meanwhile; on resume the harness reads state and stops
 * before attempting any action. Plus the compromised-shaper property: a
 * shaper proposal is untrusted and cannot widen derived authority.
 */

import { generateKeyPair } from "jose";
import { describe, expect, it } from "vitest";
import { MissionKernel, validateMissionIntent } from "@mission/authorization-server";
import { DERIVATION_POLICY } from "@mission/demo-data";
import { checkOnResume, EMA_CAPABILITY, initializeCapabilities, shapeIntent } from "../src/index.js";

const ISS = "https://as.test";

async function kernel() {
  const { privateKey } = await generateKeyPair("ES256", { extractable: true });
  return new MissionKernel({ issuer: ISS, policy: DERIVATION_POLICY as never, statusKey: privateKey, statusKid: "as-status" });
}

describe("M12 scenario 14: 02:00 resume (harness stop-on-non-active)", () => {
  it("proceeds while active, stops once the mission completes", async () => {
    const k = await kernel();
    const m = k.approve({
      intent: validateMissionIntent(
        JSON.stringify({ goal: "board packet", resources: [DERIVATION_POLICY.ceiling[0].resource], expires_at: "2027-01-01T00:00:00Z" }),
      ),
      subject: { iss: ISS, sub: "alice" },
      approver: { iss: ISS, sub: "bob" },
      clientId: "ap-agent",
      approvalEventId: "apev-14",
    });
    const readState = async (id: string) => k.get(id)?.state;

    // Before the meeting is cancelled: the harness allows resumption.
    expect((await checkOnResume(m.id, readState)).proceed).toBe(true);

    // The meeting is cancelled at 23:00 -> mission completed.
    k.transition(m.id, "complete");

    // At 02:00 the agent wakes: the harness reads state and refuses to resume.
    const decision = await checkOnResume(m.id, readState);
    expect(decision.proceed).toBe(false);
    expect(decision.state).toBe("completed");
    expect(decision.reason).toContain("completed");
  });

  it("fails closed when mission state is unavailable", async () => {
    const decision = await checkOnResume("msn_unknown", async () => undefined);
    expect(decision.proceed).toBe(false);
    expect(decision.reason).toContain("fail closed");
  });
});

describe("M12 agent: EMA capability and untrusted shaper", () => {
  it("declares the EMA extension at initialize", () => {
    const caps = initializeCapabilities() as { capabilities: { extensions: Record<string, unknown> } };
    expect(caps.capabilities.extensions).toHaveProperty(EMA_CAPABILITY);
  });

  it("a shaper proposal is only a proposal -- the AS derivation still bounds it", async () => {
    const k = await kernel();
    // Compromised shaper proposes an over-broad action set + huge scope.
    const raw = shapeIntent({
      goal: "pay everything",
      resources: [DERIVATION_POLICY.ceiling[0].resource],
      expiresAt: "2027-01-01T00:00:00Z",
      proposedActions: ["payments:payment.execute", "payments:vendor.delete"],
      vendors: ["acme", "evilcorp"],
    });
    const m = k.approve({
      intent: validateMissionIntent(raw),
      subject: { iss: ISS, sub: "alice" },
      approver: { iss: ISS, sub: "bob" },
      clientId: "ap-agent",
      approvalEventId: "apev-shaper",
    });
    const actions = m.authority_set.flatMap((e) => e.actions);
    // The bogus action never survives derivation; vendors are clamped to policy.
    expect(actions).not.toContain("payments:vendor.delete");
    expect(m.authority_set[0]?.constraints?.vendors ?? []).not.toContain("evilcorp");
  });
});
