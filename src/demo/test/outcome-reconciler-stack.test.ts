/**
 * @spec runtime#evidence (outcome reconciliation), runtime#runtime-conformance
 * (#1103): the declared outcome reconciler as `composeStack` assembles it.
 * `composeStack` builds it over the PEP's own claim channel, redemption
 * store, connectors, evidence and write reservations, wires the claim
 * domain's indeterminate hook to the stderr operator sink, and returns it
 * stopped: the launchers start it (`as-native-stack.test.ts` witnesses
 * `pnpm as-native`).
 *
 * Only the OpenFGA client is stubbed, as `remote-pdp-stack.test.ts` does; the
 * kernel, PEP, PDP, claim domain and decision channel are real, so this file
 * never skips.
 */

import { randomUUID } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it, type MockInstance, vi } from "vitest";
import { credentialAuthorityFrom, type TokenFacts } from "@mission/mcp-payments";
import { Fga } from "@mission/pdp";
import { approveDemoMission, composeStack, type DemoStack } from "../src/stack.js";

const tempClaimsFile = (): string => join(mkdtempSync(join(tmpdir(), "demo-claims-")), "claims.sqlite");
const tempReservationsFile = (): string =>
  join(mkdtempSync(join(tmpdir(), "demo-reservations-")), "write-reservations.sqlite");

/** Release everything a composed stack without the AS holds, the claim file's lock included. */
async function closeStack(stack: DemoStack): Promise<void> {
  await stack.reconciler.stop();
  await stack.decisionChannel.close();
  await stack.masGovernedChannel?.close();
  stack.pdpClaims.close();
  stack.writeReservations.close();
  stack.payments.db.close();
  stack.kernel.db.close();
}

describe("the composed stack's declared outcome reconciler (@spec runtime#evidence outcome reconciliation, #1103)", () => {
  let fgaConnect: MockInstance;
  beforeAll(() => {
    fgaConnect = vi.spyOn(Fga, "connect").mockResolvedValue({
      fga: { checkWithContext: async () => true } as unknown as Fga,
      storeId: "test",
      modelId: "test",
    });
  });
  afterAll(() => fgaConnect.mockRestore());

  for (const pdpMode of ["co-resident", "remote"] as const) {
    it(`composeStack returns the declared reconciler stopped, a third of the PT15M window apart, and one run over the ${pdpMode} channel completes every step`, async () => {
      const stack = await composeStack({
        openfgaUrl: "http://unused.test",
        presharedKey: "unused",
        pdpMode,
        claimsFile: tempClaimsFile(),
        writeReservationsFile: tempReservationsFile(),
      });
      try {
        expect(stack.reconciler.started).toBe(false);
        expect(stack.reconciler.windowMs).toBe(15 * 60_000);
        expect(stack.reconciler.intervalMs).toBe(5 * 60_000);
        const run = await stack.reconciler.runOnce();
        expect(run).toMatchObject({ skipped: false, failed: [], reserved: [] });
        expect(run.claims).toEqual({ settled: [], unredeemed: [], open: [], states: {} });
        expect(stack.reconciler.started).toBe(false);
      } finally {
        await closeStack(stack);
      }
    });
  }

  it("a prior process's unsettled claim raises one operator_alert JSON line on stderr when the restarted stack's reconciler runs past its window", async () => {
    const claimsFile = tempClaimsFile();
    const writeReservationsFile = tempReservationsFile();
    const options = { openfgaUrl: "http://unused.test", presharedKey: "unused", claimsFile, writeReservationsFile };
    const startedAt = Date.now();
    // The first process obtains a wire permit and stops before redeeming it.
    const before = await composeStack(options);
    let evaluationId: string;
    let missionId: string;
    try {
      const mission = approveDemoMission(before);
      const view = before.viewFor(mission.id);
      if (!view) throw new Error("no view");
      missionId = view.id;
      const token: TokenFacts = {
        sub: "alice",
        clientId: "ap-agent",
        cnfJkt: "jkt",
        mission: { id: view.id, issuer: view.issuer, authority_hash: view.authority_hash },
        credentialAuthority: credentialAuthorityFrom(view.authority_set),
      };
      const permit = await before.pep.enforce("execute_wire_transfer", { invoice_id: "inv-1", idempotency_key: `idem_${randomUUID()}` }, token);
      expect(permit.permitted, JSON.stringify(permit.denial_reason)).toBe(true);
      evaluationId = String(permit.decision?.context.evaluation_id);
    } finally {
      await closeStack(before);
    }
    const stderr = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
    vi.useFakeTimers({ toFake: ["Date"] });
    try {
      // The restarted process, inside the window: its epoch lists nothing.
      vi.setSystemTime(startedAt + 60_000);
      const after = await composeStack(options);
      try {
        const alerts = () =>
          stderr.mock.calls
            .map(([chunk]) => String(chunk))
            .filter((line) => line.startsWith('{"type":"operator_alert"'))
            .map((line) => JSON.parse(line) as Record<string, unknown>);
        expect((await after.reconciler.runOnce()).claims?.open).toEqual([]);
        expect(alerts()).toEqual([]);
        // Past the claim's window: the run's listing sweeps it indeterminate,
        // and the claim domain's hook writes the declared alert.
        vi.setSystemTime(startedAt + 30_000 + 30_000 + 15 * 60_000 + 5_000);
        await after.reconciler.runOnce();
        expect(alerts()).toEqual([
          expect.objectContaining({ type: "operator_alert", kind: "claim_indeterminate", evaluation_id: evaluationId, mission_id: missionId, cause: "window_closed" }),
        ]);
        await after.reconciler.runOnce();
        expect(alerts()).toHaveLength(1);
      } finally {
        await closeStack(after);
      }
    } finally {
      vi.useRealTimers();
      stderr.mockRestore();
    }
  });
});
