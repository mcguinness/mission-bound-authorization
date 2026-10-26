/**
 * @spec runtime#evidence, runtime#record-integrity (#821 Sketch step 6; feeds
 * #288): what the local accountability minimum costs this composition, per
 * action. `pnpm measure:evidence` composes the stack in process on fresh
 * store files, with only the OpenFGA client stubbed (it permits every check),
 * runs one action of each path, and prints a Markdown table of what each
 * added: retained records and their bytes, signing operations, and the
 * pre-effect attempt record. Bytes are the logical size of the stored JSON,
 * not file pages. It then states the per-boot key-set cost, a retention
 * projection, and the export backlog.
 */

import { randomUUID } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { credentialAuthorityFrom, type TokenFacts } from "@mission/mcp-payments";
import { Fga } from "@mission/pdp";
import { approveDemoMission, composeStack, type DemoStack } from "./stack.js";

// Only the OpenFGA client is stubbed, as the stack tests do.
Fga.bootstrap = async () => ({
  fga: { checkWithContext: async () => true, checkStored: async () => true, client: { write: async () => ({}) }, modelId: "measure" } as unknown as Fga,
  storeId: "measure",
  modelId: "measure",
});

interface Snapshot {
  rows: Array<{ kind: string; bytes: number; signed: boolean }>;
  attempts: number;
  attemptBytes: number;
}

function snapshot(stack: DemoStack): Snapshot {
  const rows = stack.evidenceRetention.retained().map((r) => {
    const content = (r.row as { content?: { evidence_envelope?: unknown } }).content;
    return { kind: r.kind, bytes: JSON.stringify(r.row).length, signed: content?.evidence_envelope !== undefined };
  });
  const attempts = stack.writeReservations.attempts();
  return { rows, attempts: attempts.length, attemptBytes: attempts.reduce((n, a) => n + JSON.stringify(a).length, 0) };
}

function delta(before: Snapshot, after: Snapshot) {
  const added = after.rows.slice(before.rows.length);
  const kinds = added.map((r) => r.kind).join(", ") || "none";
  return {
    kinds,
    recordBytes: added.reduce((n, r) => n + r.bytes, 0),
    signatures: added.filter((r) => r.signed).length,
    attempts: after.attempts - before.attempts,
    attemptBytes: after.attemptBytes - before.attemptBytes,
  };
}

const dir = mkdtempSync(join(tmpdir(), "measure-evidence-"));
const stack = await composeStack({
  openfgaUrl: "http://unused.test",
  presharedKey: "unused",
  claimsFile: join(dir, "claims.sqlite"),
  writeReservationsFile: join(dir, "write-reservations.sqlite"),
  resourcePolicyStore: { bootstrap: "development" },
});
try {
  const mission = approveDemoMission(stack);
  const view = stack.viewFor(mission.id);
  if (!view) throw new Error("no view for the demo Mission");
  const token: TokenFacts = {
    sub: "alice",
    iss: stack.issuer,
    clientId: "ap-agent",
    cnfJkt: "jkt-measure",
    mission: { id: view.id, issuer: view.issuer, authority_hash: view.authority_hash },
    credentialAuthority: credentialAuthorityFrom(view.authority_set),
  };
  const actions: Array<[string, () => Promise<{ ok: boolean; refusal_reason?: string; denial_reason?: string }>]> = [
    ["read (`get_invoice`), completed", () => stack.server.callReadTool("get_invoice", { invoice_id: "inv-1" }, token)],
    [
      "wire (`execute_wire_transfer`), completed",
      () => stack.server.callTransactionTool("execute_wire_transfer", { invoice_id: "inv-1", idempotency_key: `idem_${randomUUID()}` }, token),
    ],
    // The same operation under a new key: the operation key omits
    // `idempotency_key`, so redemption refuses it after the permit (§7).
    [
      "wire refused after the permit",
      () => stack.server.callTransactionTool("execute_wire_transfer", { invoice_id: "inv-1", idempotency_key: `idem_${randomUUID()}` }, token),
    ],
  ];
  const lines = [
    "| Action | Outcome | Records added | Record bytes | Signing operations | Attempt records | Attempt bytes |",
    "|---|---|---|---|---|---|---|",
  ];
  for (const [label, run] of actions) {
    const before = snapshot(stack);
    const result = await run();
    const d = delta(before, snapshot(stack));
    const outcome = result.ok ? "ok" : (result.refusal_reason ?? result.denial_reason ?? "refused");
    lines.push(`| ${label} | ${outcome} | ${d.kinds} | ${d.recordBytes} | ${d.signatures} | ${d.attempts} | ${d.attemptBytes} |`);
  }
  console.log(lines.join("\n"));

  const keySets = stack.evidenceKeySets.locations().map((location) => stack.evidenceKeySets.publishedKeySet(location));
  const keys = keySets.reduce((n, set) => n + set.keys.length, 0);
  const keyBytes = keySets.reduce((n, set) => n + JSON.stringify(set).length, 0);
  const window = stack.evidenceRetention.retentionWindowSeconds;
  const all = snapshot(stack);
  const perAction = Math.round((all.rows.reduce((n, r) => n + r.bytes, 0) + all.attemptBytes) / actions.length);
  console.log(`\nKey sets: ${keys} published keys at ${keySets.length} key-set location(s), ${keyBytes} bytes, regenerated per boot and held in memory (#831).`);
  console.log(`Retention window: ${window} s. At the mean of ${perAction} bytes per action above, 1,000 actions a day held for the window is about ${Math.round((perAction * 1000 * (window / 86_400)) / 1e6)} MB of logical record bytes.`);
  console.log("Export backlog: 0. Every record is signed at emission and retained locally; nothing is exported or registered asynchronously.");
} finally {
  await stack.reconciler.stop();
  await stack.decisionChannel.close();
  stack.pdpClaims.close();
  stack.writeReservations.close();
  stack.evidenceRetention.close();
  stack.payments.db.close();
  stack.kernel.db.close();
}
// The composed stack keeps listeners and timers a measurement does not need
// to wait for; everything it wrote is closed above.
process.exit(0);
