/**
 * Terminal exhibit mode (O-28): a narrated end-to-end walk of the Mission
 * lifecycle, printing the real wire artifacts at each step so the flow is
 * visible. Drives the composed stack -- the same enforcement path the tests
 * and the browser UI use. `pnpm -C demo exhibit`.
 */

import type { TokenFacts } from "@mission/mcp-payments";
import { approveDemoMission, composeStack, ISS } from "./stack.js";

const C = { dim: "\x1b[2m", green: "\x1b[32m", red: "\x1b[31m", cyan: "\x1b[36m", bold: "\x1b[1m", reset: "\x1b[0m" };
const step = (n: number, title: string) => console.log(`\n${C.bold}${C.cyan}[${n}] ${title}${C.reset}`);
const wire = (label: string, obj: unknown) => console.log(`  ${C.dim}${label}:${C.reset} ${JSON.stringify(obj)}`);
const outcome = (ok: boolean, text: string) => console.log(`  ${ok ? C.green : C.red}${ok ? "PERMIT" : "DENY  "}${C.reset} ${text}`);

async function main() {
  const ca = `${process.cwd()}/certs/openfga.crt`;
  const stack = await composeStack({
    openfgaUrl: process.env.OPENFGA_HTTP_URL ?? "https://localhost:8080",
    presharedKey: process.env.OPENFGA_PRESHARED_KEY ?? "dev-preshared-key-change-me",
    caCertPath: ca,
  });

  console.log(`${C.bold}Mission-Bound Authorization — exhibit${C.reset}\n${C.dim}One end-to-end story, real artifacts at each step.${C.reset}`);

  // 0. Discovery: before any mission, the payments service is reachable but consent-required.
  step(0, "Discovery — the agent asks what it can reach");
  const before = stack.catalog.catalog("alice", { type: "mcp" }).services.find((s) => s.id === "payments");
  wire("catalog status", before?.connections[0]?.status);

  // 1. Issuance: Bob approves Alice's write-bearing mission (subject != approver).
  step(1, "Issuance — shaper proposes, issuer derives, Bob approves");
  const mission = approveDemoMission(stack);
  const record = stack.kernel.get(mission.id);
  wire("mission id", record?.id);
  wire("intent_hash", record?.intent_hash);
  wire("authority_hash", record?.authority_hash);
  wire("derived authority", record?.authority_set);
  wire("subject / approver", `${record?.subject.sub} / ${record?.approver.sub}`);

  const token = (over: Partial<TokenFacts> = {}): TokenFacts => ({
    sub: "alice",
    clientId: "ap-agent",
    clientInstanceId: "inst-1",
    mission: { id: mission.id, authority_hash: record?.authority_hash ?? "" },
    cnfJkt: "jkt-demo",
    ...over,
  });

  // Catalog now reflects the active mission.
  const after = stack.catalog.catalog("alice", { type: "mcp" }).services.find((s) => s.id === "payments");
  wire("catalog status now", after?.connections[0]?.status);

  // 2. Happy path read.
  step(2, "Happy path — in-authority read");
  const read = await stack.server.callReadTool("get_invoice", { invoice_id: "inv-1" }, token());
  outcome(read.ok, `get_invoice(inv-1) -> ${read.ok ? JSON.stringify(read.result) : read.denial_reason ?? read.refusal_reason}`);

  // 3. Wire transfer (transaction-assurance tier): permit -> execute -> evidence -> reconcile.
  step(3, "Wire transfer — transaction-assurance tier (permit, lease, evidence, reconcile)");
  const wireRes = await stack.server.callTransactionTool("execute_wire_transfer", { invoice_id: "inv-1" }, token());
  outcome(wireRes.ok, `execute_wire_transfer(inv-1) -> ${wireRes.ok ? JSON.stringify(wireRes.result) : wireRes.denial_reason ?? wireRes.refusal_reason}`);
  // Publish the evidence to the transparency log.
  for (const ev of stack.evidence.forMission(mission.id)) {
    await stack.publishEvidence(mission.id, ev.kind === "decision" ? "decision-evidence" : ev.kind === "execution" ? "execution-evidence" : "refusal-record", ev as unknown as Record<string, unknown>);
  }
  wire("ledger entries", stack.connectors.ledgerEntries(mission.id).length);

  // 4. Over-cap wire -> denied by bounds.
  step(4, "Bounds — an over-cap wire is denied");
  const overcap = await stack.server.callTransactionTool("execute_wire_transfer", { invoice_id: "inv-2" }, token());
  outcome(overcap.ok, `execute_wire_transfer(inv-2, $900) -> ${overcap.denial_reason ?? overcap.refusal_reason}`);

  // 5. Vendor outside constraint -> denied.
  step(5, "Narrowing — a vendor outside the mission's constraint is denied");
  const globex = await stack.server.callTransactionTool("execute_wire_transfer", { invoice_id: "inv-3" }, token());
  outcome(globex.ok, `execute_wire_transfer(inv-3, globex) -> ${globex.denial_reason ?? globex.refusal_reason}`);

  // 6. Revocation freshness -> the next action is denied.
  step(6, "Termination — operator revokes; the next action is denied");
  stack.kernel.transition(mission.id, "revoke");
  wire("mission state", stack.kernel.get(mission.id)?.state);
  const afterRevoke = await stack.server.callReadTool("get_invoice", { invoice_id: "inv-1" }, token());
  outcome(afterRevoke.ok, `get_invoice(inv-1) after revoke -> ${afterRevoke.denial_reason ?? afterRevoke.refusal_reason}`);

  // 7. Transparent audit — the verified evidence feed.
  step(7, "Evidence — the tamper-evident feed, verified");
  const opSession = stack.bff.sessions.create("olivia", ["operator"]);
  const timeline = await stack.bff.timeline(opSession, mission.id);
  for (const row of timeline) {
    console.log(`  ${row.verified ? C.green + "VERIFIED" : C.red + "FAILED  "}${C.reset} ${row.evidence_type} from ${row.producer}${row.detail ? ` (${row.detail})` : ""}`);
  }

  console.log(`\n${C.green}${C.bold}Exhibit complete.${C.reset} ${C.dim}Every step ran through the real PEP -> PDP -> OpenFGA path.${C.reset}`);
  void ISS;
  process.exit(0);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
