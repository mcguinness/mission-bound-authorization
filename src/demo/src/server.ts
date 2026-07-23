/**
 * Live demo server: composes the full stack, seeds a scenario, and serves a
 * clickable dashboard (demo/public/index.html) plus the persona HTTP APIs the
 * dashboard drives. This is the interactive browser demo -- every button hits
 * the real console-bff / catalog / MCP PEP path. `pnpm demo:serve`, open
 * http://localhost:4407.
 *
 * Routing is a small Hono app (readable route table + JSON/error middleware);
 * the demo remains a single one-command process. The apps/ React SPAs are the
 * production-shaped thin views; this dashboard is the runnable surface (no
 * per-app Vite build).
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { serve } from "@hono/node-server";
import { Hono, type Context } from "hono";
import { type TokenFacts, TOOLS } from "@mission/mcp-payments";
import { approveDemoMission, composeStack, type DemoStack } from "./stack.js";

const TX_TOOLS = new Set(["execute_wire_transfer", "send_remittance_email"]);
const actionFor = (tool: string): string => TOOLS.find((t) => t.name === tool)?.action ?? "";

const PORT = Number(process.env.CONSOLE_BFF_PORT ?? 4407);
const INDEX = fileURLToPath(new URL("../public/index.html", import.meta.url));

/** Parse a JSON request body, tolerating an empty body. */
const readJson = (c: Context): Promise<Record<string, unknown>> =>
  c.req.json().catch(() => ({}) as Record<string, unknown>);

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

  // Capture the digest of the last enforced decision so a JIT access request
  // can be bound to the exact parameters that were denied.
  let lastDigest = "";
  stack.onEnforce((e) => {
    const d = e.decision.context.parameter_digest;
    if (typeof d === "string") lastDigest = d;
  });

  // Publish any evidence produced since the last call to the transparency log
  // so the operator timeline reflects the newest agent activity.
  let published = stack.evidence.forMission(missionId).length;
  const publishNew = async () => {
    const all = stack.evidence.forMission(missionId);
    for (const ev of all.slice(published)) {
      const t = ev.kind === "decision" ? "decision-evidence" : ev.kind === "execution" ? "execution-evidence" : "refusal-record";
      await stack.publishEvidence(missionId, t, ev as unknown as Record<string, unknown>);
    }
    published = all.length;
  };

  const app = new Hono();
  app.onError((err, c) => c.json({ error: err.message }, 500));
  app.notFound((c) => c.json({ error: "not found" }, 404));

  // Dashboard.
  const index = (c: Context) => c.html(readFileSync(INDEX, "utf8"));
  app.get("/", index);
  app.get("/index.html", index);

  // Console BFF (operator + approver personas).
  app.get("/bff/session", (c) => c.json({ sub: session.sub, roles: session.roles, csrf: session.csrf, missionId }));
  app.get("/bff/operator/fleet", (c) => c.json(stack.bff.fleet(session)));
  app.get("/bff/operator/missions/:id/timeline", async (c) => c.json(await stack.bff.timeline(session, c.req.param("id"))));
  app.post("/bff/operator/missions/:id/lifecycle", async (c) => {
    const body = await readJson(c);
    return c.json(stack.bff.lifecycle(session, c.req.param("id"), body.operation as never, session.csrf));
  });
  app.get("/bff/approver/queue", (c) => c.json(stack.bff.approverQueue(session)));
  // Approver adjudicates a pending ARAP task (JIT approval).
  app.post("/bff/approver/adjudicate", async (c) => {
    const body = await readJson(c);
    return c.json(await stack.bff.adjudicateTask(session, String(body.taskId), body.decision as "approve" | "deny", session.csrf));
  });

  // Agent surface.
  app.get("/agent/catalog", (c) => c.json(stack.catalog.catalog("alice", { type: "mcp" })));
  // Agent action: attempt a tool call and report the enforcement outcome. A
  // requestable action_approval_required denial opens an ARS access request and
  // hands the pending task back to the agent (JIT/ARAP).
  app.post("/agent/act", async (c) => {
    const body = await readJson(c);
    const tool = String(body.tool);
    const args = (body.args as Record<string, unknown>) ?? {};
    const r = TX_TOOLS.has(tool)
      ? await stack.server.callTransactionTool(tool, args, missionToken())
      : await stack.server.callReadTool(tool, args, missionToken());
    await publishNew();
    const ar = (r as { access_request?: { endpoint: string; denial_binding: string; binding_token: string } }).access_request;
    if (!r.ok && ar) {
      const submitted = await stack.ars.submit({
        binding_token: ar.binding_token,
        requested: { action: actionFor(tool), mission_id: missionId, parameter_digest: lastDigest, subject: "alice" },
      });
      return c.json({ ...r, taskId: submitted.taskId, task_state: submitted.state });
    }
    return c.json(r);
  });
  // Agent retries a JIT-gated call, carrying the approval as context.
  app.post("/agent/retry", async (c) => {
    const body = await readJson(c);
    const taskId = String(body.taskId);
    const tool = String(body.tool);
    const args = (body.args as Record<string, unknown>) ?? {};
    const task = stack.ars.getTask(taskId);
    if (!task || task.state !== "approved" || !task.approval) {
      return c.json({ ok: false, pending: true, state: task?.state ?? "unknown" });
    }
    const a = task.approval;
    const approvalCtx = { id: a.id, approved_at: a.approved_at, parameter_digest: a.parameter_digest };
    const r = await stack.server.callTransactionTool(tool, args, missionToken(), undefined, approvalCtx);
    await publishNew();
    return c.json(r);
  });

  serve({ fetch: app.fetch, port: PORT }, () => {
    console.log(`\nMission demo console: http://localhost:${PORT}`);
    console.log(`Seeded mission ${missionId} (subject alice, approver bob), one wire executed with evidence.`);
    console.log("Operator: fleet + lifecycle + verified evidence timeline. Agent: catalog + act. Approver: queue.\n");
  });
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
