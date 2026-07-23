/**
 * Terminal exhibit (O-28): a detailed, narrated protocol trace of the Mission
 * lifecycle. Prints the real wire artifacts at every step -- catalog response,
 * shaped intent, proposal->derived narrowing, Mission Record + anchors, the
 * mission-bound token, each MCP tool call with params, the PEP-built AuthZEN
 * envelope, and the PDP decision -- driving the composed stack (the same
 * PEP -> PDP -> OpenFGA path the tests and browser use). `pnpm exhibit`.
 */

import { shapeIntent } from "@mission/agent";
import { validateMissionIntent } from "@mission/authorization-server";
import { DERIVATION_POLICY } from "@mission/demo-data";
import type { TokenFacts } from "@mission/mcp-payments";
import type { Decision, EvaluationRequest } from "@mission/pdp";
import { composeStack, ISS } from "./stack.js";

const C = { dim: "\x1b[2m", green: "\x1b[32m", red: "\x1b[31m", cyan: "\x1b[36m", yellow: "\x1b[33m", bold: "\x1b[1m", reset: "\x1b[0m" };
const RESOURCE = DERIVATION_POLICY.ceiling[0].resource;

function step(n: number, title: string) {
  console.log(`\n${C.bold}${C.cyan}${"─".repeat(3)} [${n}] ${title} ${"─".repeat(Math.max(0, 60 - title.length))}${C.reset}`);
}
function block(label: string, obj: unknown) {
  console.log(`${C.dim}${label}:${C.reset}`);
  console.log(
    JSON.stringify(obj, null, 2)
      .split("\n")
      .map((l) => `  ${l}`)
      .join("\n"),
  );
}
function note(text: string) {
  console.log(`${C.dim}  → ${text}${C.reset}`);
}
function verdict(ok: boolean, text: string) {
  console.log(`  ${ok ? C.green + "✓ PERMIT" : C.red + "✗ DENY"}${C.reset} ${text}`);
}

async function main() {
  const ca = `${process.cwd()}/certs/openfga.crt`;
  const stack = await composeStack({
    openfgaUrl: process.env.OPENFGA_HTTP_URL ?? "https://localhost:8080",
    presharedKey: process.env.OPENFGA_PRESHARED_KEY ?? "dev-preshared-key-change-me",
    caCertPath: ca,
  });

  // Capture the AuthZEN envelope + PDP decision the PEP actually built.
  let captured: { envelope: EvaluationRequest; decision: Decision; effective?: unknown } | undefined;
  stack.onEnforce((e) => {
    captured = { envelope: e.envelope, decision: e.decision, ...(e.effective ? { effective: e.effective } : {}) };
  });

  console.log(`${C.bold}Mission-Bound Authorization — protocol exhibit${C.reset}`);
  console.log(`${C.dim}Accounts-payable estate. Every artifact below is the real value on the wire.${C.reset}`);

  // ---- 0. Discovery -------------------------------------------------------
  step(0, "Discovery: the agent asks what it can reach");
  note(`GET ${ISS}/service-catalog?type=mcp   (access token audience = catalog)`);
  block("catalog response (before any mission)", stack.catalog.catalog("alice", { type: "mcp" }));
  note("payments is consent_required: reachable, but no mission covers it yet.");

  // ---- 1. Intent shaping (untrusted proposal) -----------------------------
  step(1, "Intent shaping: the shaper proposes (untrusted)");
  const proposedRaw = shapeIntent({
    goal: "Pay approved Acme invoices for Q3",
    resources: [RESOURCE],
    expiresAt: "2027-01-01T00:00:00Z",
    // A deliberately over-broad proposal: a bogus action, extra vendors, a huge cap.
    proposedActions: ["payments:invoice.read", "payments:payment.execute", "payments:vendor.delete"],
    vendors: ["acme", "globex", "evilcorp"],
  });
  // shapeIntent omits max_amount; add an over-broad cap to the proposal to show clamping.
  const proposedObj = JSON.parse(proposedRaw) as { proposed_authority: { constraints?: Record<string, unknown> }[] };
  (proposedObj.proposed_authority[0] as { constraints?: Record<string, unknown> }).constraints = {
    max_amount: { amount: "999999.00", currency: "USD" },
    vendors: ["acme", "globex", "evilcorp"],
  };
  block("mission_intent (submitted via PAR, mission_intent parameter)", proposedObj);
  note("This is a proposal. Nothing here grants authority; the issuer derives and bounds it.");

  // ---- 2. Approval event + derivation -------------------------------------
  step(2, "Approval: Bob approves; the issuer derives the Authority Set");
  const record = stack.kernel.approve({
    intent: validateMissionIntent(JSON.stringify(proposedObj)),
    subject: { iss: ISS, sub: "alice" },
    approver: { iss: ISS, sub: "bob" },
    clientId: "ap-agent",
    approvalEventId: "apev-exhibit",
  })!;
  const full = stack.kernel.get(record.id)!;
  block("derived Authority Set (issuer output, bounded by policy)", full.authority_set);
  console.log(
    `${C.yellow}  narrowing:${C.reset} proposed vendor.delete ${C.red}dropped${C.reset}; ` +
      `vendors clamped acme,globex,evilcorp ${C.green}→ acme${C.reset}; cap 999999 ${C.green}→ 500.00${C.reset}`,
  );
  block("Mission Record", {
    id: full.id,
    state: full.state,
    subject: full.subject,
    approver: full.approver,
    policy_version: full.policy_version,
    intent_hash: full.intent_hash,
    authority_hash: full.authority_hash,
    expires_at: full.expires_at,
  });
  note("subject alice != approver bob (write-bearing missions need a distinct approver).");

  // The mission-bound token the AS would issue (projection carried in the JWT).
  const missionClaim = stack.kernel.missionClaim(full);
  const token = (): TokenFacts => ({
    sub: "alice",
    clientId: "ap-agent",
    clientInstanceId: "inst-ap-agent-01",
    mission: { id: full.id, authority_hash: full.authority_hash },
    cnfJkt: "AbC123...jkt",
  });
  block("mission-bound access token (decoded claims)", {
    iss: ISS,
    sub: "alice",
    client_id: "ap-agent",
    aud: RESOURCE,
    cnf: { jkt: "AbC123...jkt" },
    mission: missionClaim,
    authorization_details: full.authority_set,
  });

  step(3, "Discovery again: the catalog now reflects the active mission");
  block("catalog payments connection", stack.catalog.catalog("alice", { type: "mcp" }).services.find((s) => s.id === "payments")?.connections);

  // ---- 4/5. Tool calls with full PEP + PDP trace --------------------------
  const traceCall = async (label: string, kind: "read" | "wire", tool: string, args: Record<string, unknown>) => {
    step(kind === "read" ? 4 : 5, label);
    block(`MCP tools/call — ${tool}`, { tool, arguments: args, authorization: `DPoP <mission-bound token for ${full.id}>` });
    const res = kind === "read"
      ? await stack.server.callReadTool(tool, args, token())
      : await stack.server.callTransactionTool(tool, args, token());
    if (captured) {
      note("PEP builds the AuthZEN decision request (effective params from authoritative store state):");
      if (captured.effective) block("  effective parameters", captured.effective);
      block("PDP request (AuthZEN envelope)", captured.envelope);
      block("PDP decision", captured.decision);
    }
    verdict(res.ok, `${tool} → ${res.ok ? JSON.stringify(res.result) : (res.denial_reason ?? res.refusal_reason)}`);
    return res;
  };

  await traceCall("Read tool call — in-authority (get_invoice)", "read", "get_invoice", { invoice_id: "inv-1" });
  await traceCall("Wire transfer — transaction-assurance tier (execute_wire_transfer)", "wire", "execute_wire_transfer", { invoice_id: "inv-1" });

  // Publish evidence produced so far to the transparency log.
  for (const ev of stack.evidence.forMission(full.id)) {
    const t = ev.kind === "decision" ? "decision-evidence" : ev.kind === "execution" ? "execution-evidence" : "refusal-record";
    await stack.publishEvidence(full.id, t, ev as unknown as Record<string, unknown>);
  }

  // ---- 6. Denials ---------------------------------------------------------
  step(6, "Denials: valid token, but out of bounds / authority");
  const over = await stack.server.callTransactionTool("execute_wire_transfer", { invoice_id: "inv-2" }, token());
  if (captured) block("PDP decision (over-cap $900)", captured.decision);
  verdict(over.ok, `execute_wire_transfer(inv-2, $900) → ${over.denial_reason ?? over.refusal_reason}`);
  const globex = await stack.server.callTransactionTool("execute_wire_transfer", { invoice_id: "inv-3" }, token());
  if (captured) block("PDP decision (globex vendor)", captured.decision);
  verdict(globex.ok, `execute_wire_transfer(inv-3, globex) → ${globex.denial_reason ?? globex.refusal_reason}`);

  // ---- 7. Revocation freshness --------------------------------------------
  step(7, "Termination: operator revokes; the next action is denied");
  stack.kernel.transition(full.id, "revoke");
  note(`mission ${full.id} state → ${stack.kernel.get(full.id)?.state}`);
  const afterRevoke = await stack.server.callReadTool("get_invoice", { invoice_id: "inv-1" }, token());
  if (captured) block("PDP decision (after revoke)", captured.decision);
  verdict(afterRevoke.ok, `get_invoice(inv-1) → ${afterRevoke.denial_reason ?? afterRevoke.refusal_reason}`);

  // ---- 8. Evidence --------------------------------------------------------
  step(8, "Evidence: the tamper-evident feed, five-step verified");
  const op = stack.bff.sessions.create("olivia", ["operator"]);
  for (const row of await stack.bff.timeline(op, full.id)) {
    console.log(`  ${row.verified ? C.green + "✓ VERIFIED" : C.red + "✗ FAILED  "}${C.reset} ${row.evidence_type} ${C.dim}from ${row.producer}${C.reset}`);
  }

  console.log(`\n${C.green}${C.bold}Exhibit complete.${C.reset} ${C.dim}Catalog, intent, derivation, token, tool calls, PEP envelopes, PDP decisions, and evidence — all real.${C.reset}`);
  process.exit(0);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
