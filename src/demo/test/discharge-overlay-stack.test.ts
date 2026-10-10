/**
 * @spec discharge#runtime, discharge#visibility (#1144, D335): the composed
 * stack's canonical Mission loader, `viewFor`, carries the committed discharge
 * delta, so the PDP refuses a discharged entry at the point of use
 * (`authority_discharged`, step 5b) and reads a credential's discharge
 * condition through the Mission entries it derives from (step 5c).
 *
 * The shipped demo registers no discharge authority, so its Missions carry no
 * completion condition; this file composes the stack with one. Only the
 * OpenFGA client is stubbed, as `remote-pdp-stack.test.ts` does; the kernel,
 * PEP, PDP and decision channel are real, so this file never skips.
 */

import { randomUUID } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  type AuthorityEntry,
  conditionDigest,
  type DischargeAuthorityPolicy,
  entryDigest,
  validateMissionIntent,
} from "@mission/authorization-server";
import { DERIVATION_POLICY } from "@mission/demo-data";
import { credentialAuthorityFrom, type TokenFacts } from "@mission/mcp-payments";
import { Fga, type MissionView } from "@mission/pdp";
import { afterAll, beforeAll, describe, expect, it, type MockInstance, vi } from "vitest";
import { composeStack, type DemoStack } from "../src/stack.js";

const RESOURCE = DERIVATION_POLICY.ceiling[0].resource;
const PAID_EVENT = "invoice-batch-paid";
const PAID_POLICY = "payables-close-q3";
const CLOSER = "svc:payables-close";
const CONDITION = { event_type: PAID_EVENT, discharge_authority: PAID_POLICY };

const DISCHARGE_AUTHORITY: DischargeAuthorityPolicy = {
  policies: {
    [PAID_POLICY]: { mapping_id: "payables-close", mapping_version: "1", event_types: [PAID_EVENT], principals: [CLOSER] },
  },
};

const tempFile = (prefix: string, name: string): string => join(mkdtempSync(join(tmpdir(), prefix)), name);

async function closeStack(stack: DemoStack): Promise<void> {
  await stack.reconciler.stop();
  await stack.decisionChannel.close();
  await stack.masGovernedChannel?.close();
  stack.pdpClaims.close();
  stack.writeReservations.close();
  stack.payments.db.close();
  stack.kernel.db.close();
}

/** An invoice-read entry; `closing` adds the completion condition. */
const readEntry = (closing: boolean): AuthorityEntry => ({
  type: "mission_resource_access",
  resource: RESOURCE,
  actions: ["payments:invoice.read"],
  constraints: { vendors: ["acme"], ...(closing ? { terminal_when: [{ ...CONDITION }] } : {}) },
});

let approvals = 0;
function approve(stack: DemoStack, entries: AuthorityEntry[]): MissionView {
  approvals += 1;
  const record = stack.kernel.approve({
    intent: validateMissionIntent(
      JSON.stringify({ goal: "Review Acme invoices until the batch is paid", target_resources: [RESOURCE], expires_at: "2027-01-01T00:00:00Z" }),
    ),
    proposedAuthority: entries,
    subject: { iss: stack.issuer, sub: "alice" },
    approver: { iss: stack.issuer, sub: "bob" },
    clientId: "ap-agent",
    approvalEventId: `apev-discharge-stack-${approvals}`,
  });
  const view = stack.viewFor(record.id);
  if (!view) throw new Error("no view");
  return view;
}

/** A Mission-bound credential carrying `entries` as its own authority. */
const tokenFor = (view: MissionView, entries: MissionView["authority_set"]): TokenFacts => ({
  sub: "alice",
  clientId: "ap-agent",
  cnfJkt: "jkt",
  mission: { id: view.id, issuer: view.issuer, authority_hash: view.authority_hash },
  credentialAuthority: credentialAuthorityFrom(entries),
});

/** Commit the discharge of the record entry carrying the completion condition. */
function dischargeClosingEntry(stack: DemoStack, missionId: string): string {
  const record = stack.kernel.get(missionId);
  const entry = record?.authority_set.find((e) => e.constraints?.terminal_when?.length);
  if (!record || !entry) throw new Error("no closing entry");
  const digest = entryDigest(record.issuer, entry);
  stack.kernel.discharge(missionId, {
    authority: CLOSER,
    entry_digest: digest,
    condition_digest: conditionDigest(CONDITION),
    event_type: PAID_EVENT,
    event_id: randomUUID(),
  });
  return digest;
}

const readInvoice = (stack: DemoStack, token: TokenFacts) => stack.pep.enforce("get_invoice", { invoice_id: "inv-1" }, token);

describe("the composed stack refuses a discharged entry at the point of use (@spec discharge#runtime, #1144)", () => {
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
    it(`after a discharge commit, the next decision for that entry is authority_discharged, and a credential deriving only from it is refused at step 5c while a live entry's credential still permits (${pdpMode})`, async () => {
      const stack = await composeStack({
        openfgaUrl: "http://unused.test",
        presharedKey: "unused",
        pdpMode,
        claimsFile: tempFile("demo-claims-", "claims.sqlite"),
        writeReservationsFile: tempFile("demo-reservations-", "write-reservations.sqlite"),
        dischargeAuthority: DISCHARGE_AUTHORITY,
      });
      try {
        // Step 5b: one closing entry, the credential carrying it.
        const single = approve(stack, [readEntry(true)]);
        const singleToken = tokenFor(single, single.authority_set);
        expect((await readInvoice(stack, singleToken)).permitted).toBe(true);
        const singleDigest = dischargeClosingEntry(stack, single.id);
        expect(stack.viewFor(single.id)?.discharged).toEqual({ entry_digests: [singleDigest] });
        const refused = await readInvoice(stack, singleToken);
        expect(refused.permitted).toBe(false);
        expect(refused.denial_reason).toBe("authority_discharged");
        expect(refused.decision?.context.entry_digest).toBe(singleDigest);

        // Step 5c: a live entry matches first, so only the credential's own
        // discharge condition, read through the entry it derives from, refuses.
        const both = approve(stack, [readEntry(false), readEntry(true)]);
        expect(both.authority_set[0]?.constraints).not.toHaveProperty("terminal_when");
        const closingToken = tokenFor(both, [both.authority_set[1] as MissionView["authority_set"][number]]);
        const liveToken = tokenFor(both, [both.authority_set[0] as MissionView["authority_set"][number]]);
        expect((await readInvoice(stack, closingToken)).permitted).toBe(true);
        const bothDigest = dischargeClosingEntry(stack, both.id);
        const viaCredential = await readInvoice(stack, closingToken);
        expect(viaCredential.denial_reason).toBe("authority_discharged");
        expect(viaCredential.decision?.context.entry_digest).toBe(bothDigest);
        expect((await readInvoice(stack, liveToken)).permitted).toBe(true);
      } finally {
        await closeStack(stack);
      }
    });
  }

  it("a Mission with nothing discharged carries no delta, as before", async () => {
    const stack = await composeStack({
      openfgaUrl: "http://unused.test",
      presharedKey: "unused",
      claimsFile: tempFile("demo-claims-", "claims.sqlite"),
      writeReservationsFile: tempFile("demo-reservations-", "write-reservations.sqlite"),
      dischargeAuthority: DISCHARGE_AUTHORITY,
    });
    try {
      const view = approve(stack, [readEntry(true)]);
      expect(view).not.toHaveProperty("discharged");
    } finally {
      await closeStack(stack);
    }
  });
});
