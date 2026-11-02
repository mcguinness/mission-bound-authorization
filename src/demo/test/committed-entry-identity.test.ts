/**
 * @spec discharge#discharge-operation, runtime-evidence#decision-evidence-object
 * (#1133, D335)
 *
 * The canonical Mission loader (`viewFor`) adds the PDP-local `join_delegation`
 * to each delegable entry. The PDP's committed-entry identity must still be the
 * issuer's: the discharge delta and a permit's `entry_digest` are keyed by the
 * entry the Mission Issuer committed, and the set proof recomputes the
 * committed `authority_hash`. Only the FGA dependency is stubbed; the kernel,
 * its approval and the loader are real.
 */

import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { entryDigest } from "@mission/authorization-server";
import { committedEntryDigest, Fga, viewHoldsCommittedSet } from "@mission/pdp";
import { afterAll, describe, expect, it, vi } from "vitest";
import { approveDemoMission, composeStack } from "../src/stack.js";

// The stack approves its demo Mission with a fixed expires_at, so the file runs
// on a controlled clock before it (#1968, D1133; D1091), installed before the
// modules that read the time at load.
const controlledClock = await vi.hoisted(async () => {
  const { CONTROLLED_CLOCK_MS, installControlledClock } = await import("./controlled-clock.helper.js");
  return installControlledClock(CONTROLLED_CLOCK_MS);
});
afterAll(() => controlledClock.restore());

const tempFile = (prefix: string, name: string): string => join(mkdtempSync(join(tmpdir(), prefix)), name);

describe("the canonical Mission loader preserves the committed entry identity (D335)", () => {
  it("reproduces the committed authority_hash and each entry's issuer digest, though it adds join_delegation", async () => {
    // The stub allows the contextual and stored checks, and the development
    // Resource-policy seed (#828) writes nowhere.
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
      claimsFile: tempFile("demo-claims-", "claims.sqlite"),
      writeReservationsFile: tempFile("demo-reservations-", "write-reservations.sqlite"),
      resourcePolicyStore: { bootstrap: "development" },
    });
    try {
      const mission = approveDemoMission(stack);
      const view = stack.viewFor(mission.id);
      const record = stack.kernel.get(mission.id);
      if (!view || !record) throw new Error("the approved Mission has no view");
      const delegable = view.authority_set.findIndex((e) => e.join_delegation !== undefined);
      expect(delegable, "the demo ceiling carries a delegable entry").toBeGreaterThanOrEqual(0);
      expect(viewHoldsCommittedSet(view)).toBe(true);
      view.authority_set.forEach((e, i) => {
        expect(committedEntryDigest(view.issuer, e)).toBe(entryDigest(record.issuer, record.authority_set[i] as never));
      });
      // Hashing the materialized entry as it stands would miss the issuer's digest.
      expect(entryDigest(view.issuer, view.authority_set[delegable] as never)).not.toBe(
        entryDigest(record.issuer, record.authority_set[delegable] as never),
      );
    } finally {
      bootstrap.mockRestore();
      await stack.decisionChannel.close();
      await stack.masGovernedChannel?.close();
      stack.authServer?.closeAuthServer();
    }
  });
});
