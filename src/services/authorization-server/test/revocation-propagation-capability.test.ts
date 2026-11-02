/**
 * #2018: Mission Status metadata is advertised only under the capability that
 * owns it. `mission_max_stale_seconds` belongs to Mission Status's
 * Revocation propagation extension (status#revocation-enforcement-classes,
 * status#conformance), switched by `revocation-propagation`
 * (adapters/capabilities.ts), not to the Mission Status operation (`status`)
 * or the Lifecycle endpoint. The disabled configuration's wire witness is also
 * demo/test/minimal-baseline-config.test.ts.
 *
 * The file runs on a controlled clock (D1091).
 */
const controlledClock = await vi.hoisted(async () => {
  const { CONTROLLED_CLOCK_MS, installControlledClock } = await import("./controlled-clock.helper.js");
  return installControlledClock(CONTROLLED_CLOCK_MS);
});

import { MISSION_MAX_STALE_SECONDS } from "@mission/demo-data";
import { afterAll, describe, expect, it, vi } from "vitest";
import type { ProviderCapability } from "../src/index.js";
import { type Json, metadata, startAs } from "./capability-switch.helper.js";

afterAll(() => controlledClock.restore());

async function metadataOf(capabilities: ProviderCapability[]): Promise<Json> {
  const h = await startAs(capabilities);
  try {
    return await metadata(h);
  } finally {
    await h.close();
  }
}

describe("the Revocation propagation capability switch owns mission_max_stale_seconds (#2018; @spec status#as-metadata, status#conformance)", () => {
  it("on, the deployment advertises the issuer's ceiling, the bound the access-token lifetime is sized to", async () => {
    const meta = await metadataOf(["lifecycle-revoke", "revocation-propagation"]);
    expect(meta.mission_max_stale_seconds).toBe(MISSION_MAX_STALE_SECONDS);
  });

  it("off, the member is not advertised, though the Lifecycle endpoint's own Status members are", async () => {
    const meta = await metadataOf(["lifecycle-revoke"]);
    expect(meta).not.toHaveProperty("mission_max_stale_seconds");
    expect(meta.mission_lifecycle_endpoint).toBeDefined();
    expect(meta.mission_status_signing_alg_values_supported).toEqual(["ES256"]);
  });

  it("off, construction refuses an AS serving Mission join, whose Mission Authority Server metadata requires the member (@spec authority-server#discovery)", async () => {
    const joinEnrollment = { "pdp-join": { roles: ["pdp" as const], enforcementScopes: [] } };
    await expect(startAs(["lifecycle-revoke", "status"], { joinEnrollment })).rejects.toThrow(
      "this AS serves Mission join (joinEnrollment or joinAssertions), whose metadata requires mission_max_stale_seconds, but the revocation-propagation capability is off",
    );
    const on = await startAs(["lifecycle-revoke", "status", "revocation-propagation"], { joinEnrollment });
    try {
      expect((await metadata(on)).mission_max_stale_seconds).toBe(MISSION_MAX_STALE_SECONDS);
    } finally {
      await on.close();
    }
  });

  it("the Mission Status operation does not own it: with status on and Revocation propagation off, the Status endpoint's members are advertised and the ceiling is not", async () => {
    const meta = await metadataOf(["status"]);
    expect(meta.mission_status_endpoint).toBeDefined();
    expect(meta.mission_status_signing_alg_values_supported).toEqual(["ES256"]);
    expect(meta).not.toHaveProperty("mission_max_stale_seconds");
  });
});
