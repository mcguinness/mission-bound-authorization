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
import { describe, expect, it, vi } from "vitest";
import { approveDemoMission, composeStack } from "../src/stack.js";

const tempFile = (prefix: string, name: string): string => join(mkdtempSync(join(tmpdir(), prefix)), name);

describe("the canonical Mission loader preserves the committed entry identity (D335)", () => {
  it("reproduces the committed authority_hash and each entry's issuer digest, though it adds join_delegation", async () => {
    const connect = vi
      .spyOn(Fga, "connect")
      .mockResolvedValue({ fga: { checkWithContext: async () => true } as unknown as Fga, modelId: "test" } as never);
    const stack = await composeStack({
      openfgaUrl: "http://unused.test",
      presharedKey: "unused",
      claimsFile: tempFile("demo-claims-", "claims.sqlite"),
      writeReservationsFile: tempFile("demo-reservations-", "write-reservations.sqlite"),
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
      connect.mockRestore();
      await stack.decisionChannel.close();
      await stack.masGovernedChannel?.close();
      stack.authServer?.closeAuthServer();
    }
  });
});
