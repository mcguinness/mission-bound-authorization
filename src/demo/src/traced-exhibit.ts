/**
 * Traced exhibit: the same end-to-end flow as exhibit.ts, but with OpenTelemetry
 * initialized so each step becomes a distributed trace in Jaeger
 * (http://localhost:16686). The PEP, PDP, and FGA emit child spans, so a trace
 * shows agent -> pep.enforce -> pdp.evaluate -> fga.check per action.
 * `pnpm demo:trace`, then open Jaeger and pick service "mission-demo".
 */

import { getTracer, initTelemetry } from "@mission/telemetry";
import type { TokenFacts } from "@mission/mcp-payments";
import { approveDemoMission, composeStack } from "./stack.js";

async function main() {
  const { shutdown } = initTelemetry("mission-demo");
  const tracer = getTracer("mission-demo");
  const ca = `${process.cwd()}/certs/openfga.crt`;
  const stack = await composeStack({
    openfgaUrl: process.env.OPENFGA_HTTP_URL ?? "https://localhost:8080",
    presharedKey: process.env.OPENFGA_PRESHARED_KEY ?? "dev-preshared-key-change-me",
    caCertPath: ca,
  });

  const traced = <T>(name: string, fn: () => Promise<T> | T): Promise<T> =>
    tracer.startActiveSpan(name, async (span) => {
      try {
        return await fn();
      } finally {
        span.end();
      }
    });

  // Capture the last enforced decision's digest to bind a JIT access request.
  let lastDigest = "";
  stack.onEnforce((e) => {
    const d = e.decision.context.parameter_digest;
    if (typeof d === "string") lastDigest = d;
  });

  const mission = await traced("flow.issuance", () => approveDemoMission(stack));
  const record = stack.kernel.get(mission.id);
  const token = (): TokenFacts => ({
    sub: "alice",
    clientId: "ap-agent",
    clientInstanceId: "inst-1",
    mission: { id: mission.id, authority_hash: record?.authority_hash ?? "" },
    cnfJkt: "jkt-demo",
  });

  await traced("flow.read", () => stack.server.callReadTool("get_invoice", { invoice_id: "inv-1" }, token()));
  await traced("flow.wire", () => stack.server.callTransactionTool("execute_wire_transfer", { invoice_id: "inv-1" }, token()));
  // JIT/ARAP: deny (approval required) -> ARS submit -> approve -> retry -> permit.
  await traced("flow.jit", async () => {
    const first = await stack.server.callTransactionTool("send_remittance_email", { invoice_id: "inv-1" }, token());
    const ar = (first as { access_request?: { binding_token: string } }).access_request;
    if (!ar) return first;
    const submitted = await stack.ars.submit({
      binding_token: ar.binding_token,
      requested: { action: "payments:remittance.send", mission_id: mission.id, parameter_digest: lastDigest, subject: "alice" },
    });
    const approval = await stack.ars.adjudicate(submitted.taskId, "approve", "bob");
    if (!approval) return first;
    return stack.server.callTransactionTool("send_remittance_email", { invoice_id: "inv-1" }, token(), undefined, {
      id: approval.id,
      approved_at: approval.approved_at,
      parameter_digest: approval.parameter_digest,
    });
  });
  await traced("flow.over_cap", () => stack.server.callTransactionTool("execute_wire_transfer", { invoice_id: "inv-2" }, token()));
  await traced("flow.revoke", async () => {
    stack.kernel.transition(mission.id, "revoke");
    return stack.server.callReadTool("get_invoice", { invoice_id: "inv-1" }, token());
  });

  console.log("Traced flow complete. Open http://localhost:16686 and select service 'mission-demo'.");
  console.log("Each flow.* span nests pep.enforce -> pdp.evaluate -> fga.check.");
  await shutdown(); // flush spans to Jaeger
  process.exit(0);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
