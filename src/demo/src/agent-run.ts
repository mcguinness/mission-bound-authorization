/**
 * Opt-in live agent loop (increment 2). An end-to-end run: compose the demo
 * stack against a live AS + OpenFGA, mint a REAL DPoP-bound mission token via the
 * OAuth dance, then let an Anthropic model PLAN over a goal -- reaching payments
 * tools ONLY through the increment-1 mediated harness. Every tool call crosses
 * the MCP channel + PEP (duty 2) and is gated by the fail-closed resume guard
 * (duty 1); the planner sees each mediated verdict as its tool result.
 *
 * Requires ANTHROPIC_API_KEY. With no key this prints a hint and exits 0 (it
 * never hangs and never throws), so `pnpm agent` is safe to run key-free and the
 * deterministic CI gate is never affected. `pnpm agent`.
 */

import { createAnthropic } from "@ai-sdk/anthropic";
import { buildScopeStatement, createMediatedHarness, EgressGate, type MissionState, runAgentLoop } from "@mission/agent";
import { CANONICAL_RESOURCE, DEMO_AGENT_PROPOSAL, TOPOLOGY } from "@mission/demo-data";
import { composeStack } from "./stack.js";
import { issueMissionToken } from "./oauth-client.js";

const C = { dim: "\x1b[2m", green: "\x1b[32m", red: "\x1b[31m", cyan: "\x1b[36m", bold: "\x1b[1m", reset: "\x1b[0m" };

/** Decode a compact JWS payload (base64url) without verifying. */
function decodeClaims(jwt: string): Record<string, unknown> {
  return JSON.parse(Buffer.from(jwt.split(".")[1] as string, "base64url").toString());
}

async function main(): Promise<void> {
  if (!process.env.ANTHROPIC_API_KEY) {
    console.log("set ANTHROPIC_API_KEY to run the live agent loop (pnpm agent).");
    console.log(`${C.dim}The key-free proof is the deterministic test suite (services/agent/test/agent-loop.test.ts).${C.reset}`);
    process.exit(0);
  }

  const modelId = process.env.AGENT_MODEL ?? "claude-sonnet-5";
  const goal = "Pay the payable Acme invoices within your mission's limits.";

  const ca = `${process.cwd()}/certs/openfga.crt`;
  const stack = await composeStack({
    openfgaUrl: process.env.OPENFGA_HTTP_URL ?? TOPOLOGY.openfga.url,
    presharedKey: process.env.OPENFGA_PRESHARED_KEY ?? TOPOLOGY.openfga.presharedKey,
    caCertPath: ca,
    withAuthServer: true,
  });
  if (!stack.authServer) throw new Error("expected authServer extras (composeStack withAuthServer)");
  const as = stack.authServer;

  // Real issuance: PAR -> authorize -> approve -> token, DPoP-bound. The proposal
  // is untrusted; the AS derives + bounds authority (read + under-cap execute for
  // acme). The resulting access token is what crosses IN the MCP `_meta`. The
  // authority proposal rides the standard RFC 9396 authorization_details
  // parameter, pushed through PAR alongside mission_intent.
  const missionIntent = JSON.stringify({
    intent: {
      goal,
      target_resources: [CANONICAL_RESOURCE],
      expires_at: "2027-01-01T00:00:00Z",
    },
  });
  // @spec mission#authorization-derivation (#743, review #745 finding 3) —
  // DEMO_AGENT_PROPOSAL (@mission/demo-data) is this loop's actual proposal,
  // not a copy of it: shipped-config.test.ts imports the SAME constant, so
  // that test exercises the proposal this loop really sends rather than a
  // hand-duplicated one that could silently drift from it. See the constant's
  // doc comment for why it is split money/non-money.
  const authorizationDetails = JSON.stringify(DEMO_AGENT_PROPOSAL);
  const issued = await issueMissionToken(as.asUrl, as.agentClientJwk, { missionIntent, authorizationDetails, scope: "payments" });
  const missionClaim = decodeClaims(issued.accessToken).mission as { id: string; authority_hash: string };
  const missionId = missionClaim.id;

  // Duty-1 input: read the mission's authoritative state (fail-closed if unknown).
  const readState = async (id: string): Promise<MissionState | undefined> =>
    stack.viewFor(id)?.state as MissionState | undefined;
  const harness = await createMediatedHarness(stack.server, missionId, readState);

  // The second mediation boundary (@spec harness#mediated-egress): the agent's
  // OTHER declared channel, the inference API, egresses only through a
  // default-deny gate keyed to the published scope statement -- the demo agent
  // has no unmediated egress path. The statement is the honest single-process
  // form (in_memory -> containment_claim "none": no containment claim); the
  // remaining channel classes stay outside the claim, and the process's own
  // direct network access is the named unmediated exclusion.
  const scopeStatement = buildScopeStatement({
    isolation_mechanism: "in-memory demo process (mediated harness + egress gate; no isolation boundary)",
    transport: "in_memory",
    mediated_action_classes: ["payments"],
    excluded_unmediated_paths: ["direct process network access outside the gated inference fetch"],
    channel_classes: [
      { channel_class: "inference_api", disposition: "mediated", destinations: ["https://api.anthropic.com"] },
    ],
  });
  // The gate retains its own records (D32); use the stack's egress store so the
  // records join the Activity Log without relocating the store. The gate stays
  // the sole writer.
  const gate = new EgressGate({
    statement: scopeStatement,
    missionId,
    readState,
    evidence: stack.egressEvidence,
    emitterId: "demo-agent-egress-gate",
    instanceEpoch: "demo-epoch",
    authorityHash: missionClaim.authority_hash,
  });
  const anthropic = createAnthropic({ fetch: gate.guardedFetch() });

  console.log(`${C.bold}Mission-Bound Authorization -- live agent loop${C.reset}`);
  console.log(`${C.dim}model=${modelId}  mission=${missionId}  goal="${goal}"${C.reset}`);
  const granted = await harness.listTools(issued.accessToken);
  console.log(`${C.dim}mission-scoped tools offered to the planner: ${granted.join(", ") || "(none)"}${C.reset}\n`);

  const { text, steps } = await runAgentLoop({
    harness,
    missionToken: issued.accessToken,
    goal,
    model: anthropic(modelId),
  });

  // Transcript: each step's tool calls + the mediated verdict (permit/deny reason).
  steps.forEach((step, i) => {
    if (step.toolResults.length === 0 && step.text) {
      console.log(`${C.dim}[step ${i + 1}] (reasoning)${C.reset} ${step.text}`);
      return;
    }
    for (const r of step.toolResults) {
      const out = r.output as { ok?: boolean; result?: unknown; denial_reason?: string; refusal_reason?: string };
      const args = JSON.stringify(r.input);
      if (out?.ok) {
        console.log(`  ${C.green}✓ PERMIT${C.reset} ${r.toolName}(${args}) -> ${JSON.stringify(out.result)}`);
      } else {
        const reason = out?.denial_reason ?? out?.refusal_reason ?? "denied";
        console.log(`  ${C.red}✗ DENY${C.reset}   ${r.toolName}(${args}) -> ${reason}`);
      }
    }
  });

  console.log(`\n${C.bold}Planner's final answer:${C.reset} ${text}`);

  // The gate recorded EVERY inference egress (permitted and refused alike).
  const egressRecords = stack.egressEvidence.forMission(missionId);
  const permitted = egressRecords.filter((r) => r.kind === "egress" && r.outcome === "permitted").length;
  console.log(
    `${C.dim}egress gate: ${egressRecords.length} inference egress(es) mediated (${permitted} permitted, ${egressRecords.length - permitted} refused) -> https://api.anthropic.com only${C.reset}`,
  );
  console.log(`\n${C.green}${C.bold}Agent loop complete.${C.reset} ${C.dim}Every tool call crossed the mediated harness (channel + PEP + resume guard); every inference call crossed the egress gate.${C.reset}`);
  as.closeAuthServer();
  process.exit(0);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
