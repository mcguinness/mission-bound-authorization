/**
 * Live demo server: composes the full stack, seeds a scenario, and serves a
 * clickable dashboard (demo/public/index.html) plus the persona HTTP APIs the
 * dashboard drives. This is the interactive browser demo -- every button hits
 * the real console-bff / catalog / MCP PEP path. `pnpm demo:serve`, open
 * http://localhost:4407.
 *
 * Note: the apps/ React SPAs are production-shaped thin views; this single
 * dashboard is the runnable interactive surface (no per-app Vite build).
 */

import { readFileSync } from "node:fs";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { fileURLToPath } from "node:url";
import type { TokenFacts } from "@mission/mcp-payments";
import { approveDemoMission, composeStack, type DemoStack, ISS } from "./stack.js";

const PORT = Number(process.env.CONSOLE_BFF_PORT ?? 4407);
const INDEX = fileURLToPath(new URL("../public/index.html", import.meta.url));

async function seed(stack: DemoStack): Promise<{ missionId: string }> {
  const mission = approveDemoMission(stack);
  const record = stack.kernel.get(mission.id);
  const token = (): TokenFacts => ({
    sub: "alice",
    clientId: "ap-agent",
    clientInstanceId: "inst-1",
    mission: { id: mission.id, authority_hash: record?.authority_hash ?? "" },
    cnfJkt: "jkt-demo",
  });
  // Generate some evidence to populate the timeline. Use inv-seed for the
  // wire so inv-1's single-use permit stays fresh for the dashboard button.
  await stack.server.callReadTool("get_invoice", { invoice_id: "inv-1" }, token());
  await stack.server.callTransactionTool("execute_wire_transfer", { invoice_id: "inv-seed" }, token());
  for (const ev of stack.evidence.forMission(mission.id)) {
    const t = ev.kind === "decision" ? "decision-evidence" : ev.kind === "execution" ? "execution-evidence" : "refusal-record";
    await stack.publishEvidence(mission.id, t, ev as unknown as Record<string, unknown>);
  }
  return { missionId: mission.id };
}

function json(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify(body));
}

async function readBody(req: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  for await (const c of req) chunks.push(c as Buffer);
  const t = Buffer.concat(chunks).toString("utf8");
  return t ? (JSON.parse(t) as Record<string, unknown>) : {};
}

async function main() {
  const ca = `${process.cwd()}/certs/openfga.crt`;
  const stack = await composeStack({
    openfgaUrl: process.env.OPENFGA_HTTP_URL ?? "https://localhost:8080",
    presharedKey: process.env.OPENFGA_PRESHARED_KEY ?? "dev-preshared-key-change-me",
    caCertPath: ca,
  });
  const { missionId } = await seed(stack);
  // One dev session with both persona roles (auto-login for the demo).
  const session = stack.bff.sessions.create("demo-operator", ["operator", "approver"]);
  const missionToken = (): TokenFacts => {
    const r = stack.kernel.get(missionId);
    return { sub: "alice", clientId: "ap-agent", clientInstanceId: "inst-1", mission: { id: missionId, authority_hash: r?.authority_hash ?? "" }, cnfJkt: "jkt-demo" };
  };

  const server = createServer(async (req, res) => {
    const url = new URL(req.url ?? "/", `http://localhost:${PORT}`);
    const p = url.pathname;
    try {
      if (p === "/" || p === "/index.html") {
        res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
        res.end(readFileSync(INDEX, "utf8"));
        return;
      }
      if (p === "/bff/session") return json(res, 200, { sub: session.sub, roles: session.roles, csrf: session.csrf, missionId });
      if (p === "/bff/operator/fleet") return json(res, 200, stack.bff.fleet(session));
      const tl = p.match(/^\/bff\/operator\/missions\/([^/]+)\/timeline$/);
      if (tl) return json(res, 200, await stack.bff.timeline(session, tl[1] as string));
      const lc = p.match(/^\/bff\/operator\/missions\/([^/]+)\/lifecycle$/);
      if (lc && req.method === "POST") {
        const body = await readBody(req);
        return json(res, 200, stack.bff.lifecycle(session, lc[1] as string, body.operation as never, session.csrf));
      }
      if (p === "/bff/approver/queue") return json(res, 200, stack.bff.approverQueue(session));
      if (p === "/agent/catalog") return json(res, 200, stack.catalog.catalog("alice", { type: "mcp" }));
      // Agent action: attempt a tool call and report the enforcement outcome.
      if (p === "/agent/act" && req.method === "POST") {
        const body = await readBody(req);
        const tool = String(body.tool);
        const args = (body.args as Record<string, unknown>) ?? {};
        const r =
          tool === "execute_wire_transfer"
            ? await stack.server.callTransactionTool(tool, args, missionToken())
            : await stack.server.callReadTool(tool, args, missionToken());
        return json(res, 200, r);
      }
      json(res, 404, { error: "not found" });
    } catch (e) {
      json(res, 500, { error: (e as Error).message });
    }
  });
  server.listen(PORT, () => {
    console.log(`\nMission demo console: http://localhost:${PORT}`);
    console.log(`Seeded mission ${missionId} (subject alice, approver bob), one wire executed with evidence.`);
    console.log("Operator: fleet + lifecycle + verified evidence timeline. Agent: catalog + act. Approver: queue.\n");
  });
  void ISS;
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
