/**
 * Live demo server: composes the full stack against a real authorization
 * server, mints a real DPoP-bound mission token, and serves a clickable
 * dashboard (demo/public/index.html) plus the persona HTTP APIs the dashboard
 * drives. Every button hits the real console-bff / catalog / MCP PEP path, and
 * the JIT step runs the AROP Transaction Challenge over real HTTP against the
 * AS transaction endpoint. `pnpm demo:serve`, open http://localhost:4407.
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
import type { TokenFacts } from "@mission/mcp-payments";
import { CANONICAL_RESOURCE, TOPOLOGY } from "@mission/demo-data";
import { composeStack } from "./stack.js";
import { dpopProofFor, issueMissionToken } from "./oauth-client.js";

const TX_TOOLS = new Set(["execute_wire_transfer", "send_remittance_email"]);

const PORT = Number(process.env.CONSOLE_BFF_PORT ?? TOPOLOGY.ports.console);
const INDEX = fileURLToPath(new URL("../public/index.html", import.meta.url));

/** Parse a JSON request body, tolerating an empty body. */
const readJson = (c: Context): Promise<Record<string, unknown>> =>
  c.req.json().catch(() => ({}) as Record<string, unknown>);

/** Decode a compact JWS payload (base64url) without verifying, for display. */
function decodeClaims(jwt: string): Record<string, unknown> {
  return JSON.parse(Buffer.from(jwt.split(".")[1] as string, "base64url").toString());
}

async function main() {
  const ca = `${process.cwd()}/certs/openfga.crt`;
  const stack = await composeStack({
    openfgaUrl: process.env.OPENFGA_HTTP_URL ?? TOPOLOGY.openfga.url,
    presharedKey: process.env.OPENFGA_PRESHARED_KEY ?? TOPOLOGY.openfga.presharedKey,
    caCertPath: ca,
    withAuthServer: true,
  });
  if (!stack.authServer) throw new Error("expected authServer extras (composeStack withAuthServer)");
  const asUrl = stack.authServer.asUrl;

  // Real issuance: PAR -> authorize -> Bob approves alice -> DPoP-bound token.
  // The mission covers reading, wire execution, and remittance (the JIT-gated
  // action). The base token + its DPoP key are held server-side to drive the
  // resource calls and the AROP transaction endpoint.
  const missionIntent = JSON.stringify({
    goal: "Pay approved Acme invoices and send remittance",
    resources: [CANONICAL_RESOURCE],
    expires_at: "2027-01-01T00:00:00Z",
    proposed_authority: [
      {
        type: "mission_resource_access",
        resource: CANONICAL_RESOURCE,
        actions: ["payments:invoice.read", "payments:payment.execute", "payments:remittance.send"],
        constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
      },
    ],
  });
  const issued = await issueMissionToken(asUrl, stack.authServer.agentClientJwk, { missionIntent, scope: "payments" });
  const rsProof = await dpopProofFor(issued.dpopKeys, CANONICAL_RESOURCE, "POST");
  const facts: TokenFacts = {
    ...(await stack.server.validateToken(issued.accessToken, rsProof, CANONICAL_RESOURCE, "POST")),
    clientInstanceId: "inst-1",
  };
  const missionId = facts.mission.id;

  // Seed evidence: one wire on inv-seed (keeps inv-1's single-use permit fresh
  // for the dashboard button), then publish it to the transparency log.
  await stack.server.callReadTool("get_invoice", { invoice_id: "inv-1" }, facts);
  await stack.server.callTransactionTool("execute_wire_transfer", { invoice_id: "inv-seed" }, facts);
  for (const ev of stack.evidence.forMission(missionId)) {
    const t = ev.kind === "decision" ? "decision-evidence" : ev.kind === "execution" ? "execution-evidence" : "refusal-record";
    await stack.publishEvidence(missionId, t, ev as unknown as Record<string, unknown>);
  }

  // One dev session with both persona roles (auto-login for the demo).
  const session = stack.bff.sessions.create("demo-operator", ["operator", "approver"]);

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

  // POST the RS-signed txn-challenge to the AS transaction endpoint, presenting
  // the base mission token (DPoP). First call opens the AROP task (pending);
  // re-presenting the SAME challenge after approval returns the txn-token.
  const postTransaction = async (challenge: string) => {
    const res = await fetch(`${asUrl}/transaction`, {
      method: "POST",
      headers: {
        authorization: `DPoP ${issued.accessToken}`,
        dpop: await dpopProofFor(issued.dpopKeys, `${asUrl}/transaction`, "POST"),
        "content-type": "application/json",
      },
      body: JSON.stringify({ challenge }),
    });
    return (await res.json()) as { status?: string; txn?: string; access_token?: string; token_type?: string };
  };
  // taskId -> the challenge JWS, so /agent/retry re-POSTs the SAME challenge.
  const challenges = new Map<string, string>();

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
  // Approver adjudicates a pending AROP task on the shared ARS (JIT approval).
  app.post("/bff/approver/adjudicate", async (c) => {
    const body = await readJson(c);
    return c.json(await stack.bff.adjudicateTask(session, String(body.taskId), body.decision as "approve" | "deny", session.csrf));
  });

  // Agent surface.
  app.get("/agent/catalog", (c) => c.json(stack.catalog.catalog("alice", { type: "mcp" })));
  // Agent action: attempt a tool call and report the enforcement outcome. When
  // a gated action yields an access_challenge (AROP), the server presents it to
  // the AS transaction endpoint on the agent's behalf, opening an AROP task on
  // the shared ARS, and hands the pending txn back to the agent.
  app.post("/agent/act", async (c) => {
    const body = await readJson(c);
    const tool = String(body.tool);
    const args = (body.args as Record<string, unknown>) ?? {};
    const r = TX_TOOLS.has(tool)
      ? await stack.server.callTransactionTool(tool, args, facts)
      : await stack.server.callReadTool(tool, args, facts);
    await publishNew();
    const ch = (r as { access_challenge?: { challenge: string; txn_endpoint: string } }).access_challenge;
    if (!r.ok && ch) {
      const pending = await postTransaction(ch.challenge);
      const taskId = pending.txn ? `arq_txn_${pending.txn}` : undefined;
      if (taskId) challenges.set(taskId, ch.challenge);
      return c.json({
        ...r,
        txn: pending.txn,
        taskId,
        task_state: pending.status,
        access_challenge: { txn_endpoint: ch.txn_endpoint, challenge: decodeClaims(ch.challenge) },
      });
    }
    return c.json(r);
  });
  // Agent retries a JIT-gated call after approval: re-POST the SAME challenge to
  // the AS transaction endpoint for the txn-token, then re-present it to the RS.
  // The approval is carried by the AS-issued token, never as a tool input.
  app.post("/agent/retry", async (c) => {
    const body = await readJson(c);
    const taskId = String(body.taskId);
    const tool = String(body.tool);
    const args = (body.args as Record<string, unknown>) ?? {};
    const challenge = challenges.get(taskId);
    const task = stack.ars.getTask(taskId);
    if (!challenge || !task || task.state !== "approved") {
      return c.json({ ok: false, pending: true, state: task?.state ?? "unknown" });
    }
    const issuedTxn = await postTransaction(challenge);
    const txnToken = issuedTxn.access_token;
    if (!txnToken) return c.json({ ok: false, pending: true, state: task.state });
    const r = await stack.server.callTransactionTool(tool, args, facts, undefined, txnToken);
    await publishNew();
    challenges.delete(taskId);
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
