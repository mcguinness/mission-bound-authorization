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
