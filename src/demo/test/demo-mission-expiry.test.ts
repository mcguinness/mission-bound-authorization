/**
 * The demo's default Mission expiries derive from the owning clock (#1976,
 * D1141). With `Date` at a future instant past every former fixed default
 * (2027-01-01 and 2027-06-01), the stack's demo Mission is approved and
 * active, and the demo server's Intent validates, each expiring the default
 * distance after that clock. Only the FGA dependency is stubbed.
 */

import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { validateMissionIntent } from "@mission/authorization-server";
import { Fga } from "@mission/pdp";
import { afterAll, describe, expect, it, vi } from "vitest";
import { DEMO_MISSION_LIFETIME_DAYS, defaultMissionExpiry } from "../src/mission-expiry.js";
import { demoMissionIntent } from "../src/server.js";
import { approveDemoMission, composeStack } from "../src/stack.js";

// A controlled clock past every former fixed default, installed before the
// modules that read the time at load.
const controlledClock = await vi.hoisted(async () => {
  const { installControlledClock } = await import("./controlled-clock.helper.js");
  return installControlledClock(Date.parse("2030-01-01T12:00:00Z"));
});
afterAll(() => controlledClock.restore());

const DAY_MS = 86_400_000;
const tempFile = (prefix: string, name: string): string => join(mkdtempSync(join(tmpdir(), prefix)), name);

describe("the demo's default Mission expiry follows the owning clock (#1976)", () => {
  it("is the default distance after the given instant, in whole seconds, and a caller's distance where it names one", () => {
    const now = new Date("2030-01-01T12:00:00.250Z");
    expect(defaultMissionExpiry(now)).toBe(new Date(Date.parse("2030-01-01T12:00:01Z") + DEMO_MISSION_LIFETIME_DAYS * DAY_MS).toISOString().replace(".000Z", "Z"));
    expect(defaultMissionExpiry(now, 212)).toBe("2030-08-01T12:00:01Z");
  });

  it("approves the stack's demo Mission past every former fixed default: active, expiring the default distance after the stack's clock", async () => {
    const stubFga = {
      checkWithContext: async () => true,
      checkStored: async () => true,
      client: { write: async () => ({}) },
      modelId: "test",
    } as unknown as Fga;
    const bootstrap = vi.spyOn(Fga, "bootstrap").mockResolvedValue({ fga: stubFga, storeId: "test", modelId: "test" });
    const stack = await composeStack({
      openfgaUrl: "http://unused.test",
      presharedKey: "unused",
      claimsFile: tempFile("demo-expiry-claims-", "claims.sqlite"),
      writeReservationsFile: tempFile("demo-expiry-reservations-", "write-reservations.sqlite"),
      resourcePolicyStore: { bootstrap: "development" },
    });
    try {
      const now = stack.kernel.nowDate().getTime();
      expect(now).toBeGreaterThan(Date.parse("2027-06-01T00:00:00Z"));
      const mission = approveDemoMission(stack);
      const record = stack.kernel.get(mission.id);
      expect(record?.state).toBe("active");
      const lifetime = Date.parse(record?.expires_at as string) - now;
      expect(lifetime).toBeGreaterThan((DEMO_MISSION_LIFETIME_DAYS * DAY_MS) - 60_000);
      expect(lifetime).toBeLessThanOrEqual(DEMO_MISSION_LIFETIME_DAYS * DAY_MS + 1_000);
    } finally {
      bootstrap.mockRestore();
      await stack.decisionChannel.close();
      await stack.masGovernedChannel?.close();
      stack.authServer?.closeAuthServer();
    }
  });

  it("builds the demo server's Intent so that it validates past every former fixed default, expiring the default distance after the clock", () => {
    const now = new Date();
    const envelope = JSON.parse(demoMissionIntent(now)) as { intent: Record<string, unknown> };
    expect(envelope.intent.expires_at).toBe(defaultMissionExpiry(now));
    expect(() => validateMissionIntent(JSON.stringify(envelope.intent))).not.toThrow();
  });
});
