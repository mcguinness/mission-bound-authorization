/**
 * @spec txn-authorization#resource-challenge, runtime#resource-contract (#249,
 * #1846): the composed stack's Transaction Authorization Server resolves every
 * contract version the payments resource declares to its own Operation
 * Profile, so a supported older reference is not refused for want of one.
 */
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it, type MockInstance, vi } from "vitest";
import { CANONICAL_RESOURCE, RESOURCE_CONTRACTS } from "@mission/demo-data";
import type { JsonValue } from "@mission/core";
import { Fga } from "@mission/pdp";
import { composeStack, type DemoStack } from "../src/stack.js";

const tempFile = (prefix: string, name: string): string => join(mkdtempSync(join(tmpdir(), prefix)), name);

describe("the composed stack's TAS resolves each declared contract version to its own Operation Profile (@spec txn-authorization#resource-challenge, #249, #1846)", () => {
  let fgaBootstrap: MockInstance;
  let stack: DemoStack;
  beforeAll(async () => {
    fgaBootstrap = vi.spyOn(Fga, "bootstrap").mockResolvedValue({
      fga: { checkWithContext: async () => true, checkStored: async () => true, client: { write: async () => ({}) }, modelId: "test" } as unknown as Fga,
      storeId: "test",
      modelId: "test",
    });
    stack = await composeStack({
      openfgaUrl: "http://unused.test",
      presharedKey: "unused",
      withAuthServer: true,
      asPort: 14933,
      claimsFile: tempFile("tas-profiles-claims-", "claims.sqlite"),
      writeReservationsFile: tempFile("tas-profiles-reservations-", "write-reservations.sqlite"),
      resourcePolicyStore: { bootstrap: "development" },
    });
  });
  afterAll(async () => {
    if (stack) {
      await stack.authServer?.closeAuthServer();
      await stack.reconciler.stop();
      await stack.decisionChannel.close();
      await stack.masGovernedChannel?.close();
      stack.pdpClaims.close();
      stack.writeReservations.close();
      stack.evidenceRetention.close();
      stack.payments.db.close();
      stack.kernel.db.close();
    }
    fgaBootstrap.mockRestore();
  });

  it("admits a reference to every declared version under that version's profile", () => {
    const registry = stack.operationProfiles;
    expect(registry).toBeDefined();
    const [declared] = RESOURCE_CONTRACTS.declarations;
    for (const v of declared?.versions ?? []) {
      const entry = {
        type: "mission_resource_access",
        resource: CANONICAL_RESOURCE,
        actions: ["payments:remittance.send"],
        resource_contract: { id: declared?.id, version: v.version, digest: v.digest },
      } as JsonValue;
      expect(registry?.admit(CANONICAL_RESOURCE, entry, new Date()), v.version).toMatchObject({ ok: true, version: v.operation_profile });
    }
  });
});
