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
import { shapeIntent } from "@mission/agent";
import { composeStack } from "./stack.js";
import { ACTION_LABELS, REASON_LABELS, TOOL_LABELS } from "./labels.js";
import { dpopProofFor, issueMissionToken } from "./oauth-client.js";

const TX_TOOLS = new Set(["execute_wire_transfer", "send_remittance_email"]);

/** Minimal read-side shapes for the proposal/narrowing diff (display only). */
interface Amount {
  amount: string;
  currency: string;
}
interface AuthEntry {
  type: string;
  resource: string;
  actions: string[];
  constraints?: { max_amount?: Amount; vendors?: string[] };
}
interface IntentShape {
  proposed_authority?: AuthEntry[];
  [k: string]: unknown;
}

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
  const agentClientJwk = stack.authServer.agentClientJwk;

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

  // The agent's ACTIVE mission: the credential material it currently acts under.
  // Held mutably so /agent/issue can swap the whole set (facts + the DPoP-bound
  // token used for resource calls and the AROP transaction endpoint) atomically.
  let active = { facts, missionId, issued };

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
  // Per-mission high-water mark: the active mission changes across /agent/issue,
  // so track how much of each mission's evidence has been published and flush
  // only the tail for whichever mission the caller names (default: active).
  const publishedCounts = new Map<string, number>([[missionId, stack.evidence.forMission(missionId).length]]);
  const publishNew = async (mid: string = active.missionId) => {
    const all = stack.evidence.forMission(mid);
    const already = publishedCounts.get(mid) ?? 0;
    for (const ev of all.slice(already)) {
      const t = ev.kind === "decision" ? "decision-evidence" : ev.kind === "execution" ? "execution-evidence" : "refusal-record";
      await stack.publishEvidence(mid, t, ev as unknown as Record<string, unknown>);
    }
    publishedCounts.set(mid, all.length);
  };

  // POST to the AS transaction endpoint, presenting the base mission token
  // (DPoP). Initiation carries { challenge } (presented once) and returns a
  // continuation handle; the poll carries { transaction_authorization_id } and
  // returns the txn-token once the AROP task is approved.
  const postTransaction = async (payload: Record<string, unknown>) => {
    const res = await fetch(`${asUrl}/transaction`, {
      method: "POST",
      headers: {
        authorization: `DPoP ${active.issued.accessToken}`,
        dpop: await dpopProofFor(active.issued.dpopKeys, `${asUrl}/transaction`, "POST"),
        "content-type": "application/json",
      },
      body: JSON.stringify(payload),
    });
    const body = (await res.json()) as {
      transaction_authorization_id?: string;
      expires_in?: number;
      interval?: number;
      access_token?: string;
      token_type?: string;
      // §5.3 poll errors: authorization_pending (400), access_denied/expired_token (terminal).
      error?: string;
    };
    return { status: res.status, body };
  };
  // taskId -> transaction_authorization_id, so /agent/retry polls the AS by the
  // continuation handle (the challenge is presented only once, at act time).
  const txnHandles = new Map<string, string>();

  const app = new Hono();
  app.onError((err, c) => c.json({ error: err.message }, 500));
  app.notFound((c) => c.json({ error: "not found" }, 404));

  // Dashboard.
  const index = (c: Context) => c.html(readFileSync(INDEX, "utf8"));
  app.get("/", index);
  app.get("/index.html", index);

  // Display-only label maps (single source of truth: demo/src/labels.ts). The
  // dashboard fetches these once to gloss machine ids with human names; no wire
  // value is derived from them.
  app.get("/labels", (c) => c.json({ tools: TOOL_LABELS, actions: ACTION_LABELS, reasons: REASON_LABELS }));

  // Console BFF (operator + approver personas).
  app.get("/bff/session", (c) => c.json({ sub: session.sub, roles: session.roles, csrf: session.csrf, missionId: active.missionId }));
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

  // Which mission the agent currently acts under (Agent console binding).
  app.get("/agent/mission", (c) =>
    c.json({ missionId: active.missionId, authority: stack.kernel.get(active.missionId)?.authority_set ?? [] }));

  // ---- Shaper -> Mission Proposal -> Issue ----------------------------------
  // The shaper is UNTRUSTED client input: it only PROPOSES a Mission Intent from
  // a goal. The AS derives and bounds authority regardless of what is proposed,
  // so a compromised shaper can propose more but never widen past the ceiling.

  // Shape a goal into a proposed Mission Intent. The shaper carries no cap, so
  // the demo injects the proposed max_amount here (services/agent untouched) to
  // surface an over-ask the derivation will visibly narrow.
  app.post("/agent/shape", async (c) => {
    const b = await readJson(c);
    const resources = (b.resources as string[]) ?? [CANONICAL_RESOURCE];
    const raw = shapeIntent({
      goal: String(b.goal ?? ""),
      resources,
      expiresAt: (b.expiresAt as string) ?? "2027-01-01T00:00:00Z",
      ...(Array.isArray(b.actions) ? { proposedActions: b.actions as string[] } : {}),
      ...(Array.isArray(b.vendors) ? { vendors: b.vendors as string[] } : {}),
    });
    const intent = JSON.parse(raw) as Record<string, unknown>;
    const cap = (b.cap ?? b.max_amount) as string | undefined;
    const entries = intent.proposed_authority as Array<Record<string, unknown>> | undefined;
    if (cap && entries?.[0]) {
      const e = entries[0];
      const constraints = (e.constraints as Record<string, unknown> | undefined) ?? {};
      constraints.max_amount = { amount: String(cap), currency: "USD" };
      e.constraints = constraints;
    }
    return c.json({ intent });
  });

  // Derive the bounded Authority Set from the (untrusted) Intent and compute the
  // narrowing server-side: per resource entry, which vendors/actions were
  // DROPPED and which constraints were TIGHTENED (e.g. max_amount 900 -> 500).
  // The UI renders this diff; it never diffs two authority blobs itself.
  app.post("/agent/propose", async (c) => {
    const b = await readJson(c);
    const raw = typeof b.intent === "string" ? b.intent : JSON.stringify(b.intent ?? {});
    let proposed: AuthEntry[];
    let derived: AuthEntry[];
    try {
      const parsed = stack.kernel.validateIntent(raw);
      derived = stack.kernel.derive(parsed) as unknown as AuthEntry[];
      proposed = (parsed as unknown as IntentShape).proposed_authority ?? [];
    } catch (e) {
      return c.json({ error: (e as Error).message }, 400);
    }
    const amt = (m?: Amount) => (m ? `${m.amount} ${m.currency}` : "unbounded");
    const diff = proposed.map((p) => {
      const g = derived.find((d) => d.resource === p.resource);
      const gActions = g?.actions ?? [];
      const gVendors = g?.constraints?.vendors ?? [];
      const pVendors = p.constraints?.vendors ?? [];
      const gCap = g?.constraints?.max_amount;
      const pCap = p.constraints?.max_amount;
      const tightened =
        gCap && (!pCap || pCap.amount !== gCap.amount || pCap.currency !== gCap.currency)
          ? [{ name: "max_amount", proposed: amt(pCap), granted: amt(gCap) }]
          : [];
      return {
        resource: p.resource,
        actions_dropped: p.actions.filter((a) => !gActions.includes(a)),
        vendors_dropped: pVendors.filter((v) => !gVendors.includes(v)),
        constraints_tightened: tightened,
      };
    });
    return c.json({ proposed, derived, diff });
  });

  // Issue the (narrowed) mission for real: PAR -> headless approve -> DPoP token.
  // The AS derives the granted authority; we rebuild TokenFacts and swap the
  // agent's ACTIVE credential set so subsequent /agent/act calls run under it.
  // The new mission is a real kernel record, so it appears in the operator fleet.
  app.post("/agent/issue", async (c) => {
    const b = await readJson(c);
    const missionIntent = typeof b.intent === "string" ? b.intent : JSON.stringify(b.intent ?? {});
    let issuedMission: Awaited<ReturnType<typeof issueMissionToken>>;
    try {
      issuedMission = await issueMissionToken(asUrl, agentClientJwk, { missionIntent, scope: "payments" });
    } catch (e) {
      return c.json({ error: (e as Error).message }, 400);
    }
    const proof = await dpopProofFor(issuedMission.dpopKeys, CANONICAL_RESOURCE, "POST");
    const newFacts: TokenFacts = {
      ...(await stack.server.validateToken(issuedMission.accessToken, proof, CANONICAL_RESOURCE, "POST")),
      clientInstanceId: "inst-1",
    };
    const newId = newFacts.mission.id;
    active = { facts: newFacts, missionId: newId, issued: issuedMission };
    publishedCounts.set(newId, stack.evidence.forMission(newId).length);
    await publishNew();
    return c.json({ missionId: newId, authority: stack.kernel.get(newId)?.authority_set ?? [] });
  });
  // Agent action: attempt a tool call and report the enforcement outcome. When
  // a gated action yields an access_challenge (AROP), the server presents it to
  // the AS transaction endpoint on the agent's behalf, opening an AROP task on
  // the shared ARS, and hands the pending txn back to the agent.
  app.post("/agent/act", async (c) => {
    const body = await readJson(c);
    const tool = String(body.tool);
    const args = (body.args as Record<string, unknown>) ?? {};
    const r = TX_TOOLS.has(tool)
      ? await stack.server.callTransactionTool(tool, args, active.facts)
      : await stack.server.callReadTool(tool, args, active.facts);
    await publishNew();
    const ch = (r as { access_challenge?: { challenge: string; txn_endpoint: string } }).access_challenge;
    if (!r.ok && ch) {
      // Initiate the AROP flow: present the challenge ONCE and capture the AS's
      // continuation handle. The ARS task id is derived from the challenge's txn
      // (openForTxn keys the task arq_txn_<txn>), so the approver queue + retry
      // correlate on it while the client polls the AS by the handle.
      const challengeClaims = decodeClaims(ch.challenge);
      const txn = challengeClaims.txn as string | undefined;
      const taskId = txn ? `arq_txn_${txn}` : undefined;
      const pending = await postTransaction({ challenge: ch.challenge });
      if (taskId && pending.body.transaction_authorization_id) {
        txnHandles.set(taskId, pending.body.transaction_authorization_id);
      }
      return c.json({
        ...r,
        txn,
        taskId,
        transaction_authorization_id: pending.body.transaction_authorization_id,
        task_state: "authorization_pending",
        access_challenge: { txn_endpoint: ch.txn_endpoint, challenge: challengeClaims },
      });
    }
    return c.json(r);
  });
  // Agent retries a JIT-gated call after approval: poll the AS transaction
  // endpoint by the continuation handle for the txn-token, then re-present it to
  // the RS. The approval is carried by the AS-issued token, never a tool input.
  app.post("/agent/retry", async (c) => {
    const body = await readJson(c);
    const taskId = String(body.taskId);
    const tool = String(body.tool);
    const args = (body.args as Record<string, unknown>) ?? {};
    const handle = txnHandles.get(taskId);
    const task = stack.ars.getTask(taskId);
    if (!handle || !task || task.state === "pending") {
      return c.json({ ok: false, pending: true, state: task?.state ?? "unknown" });
    }
    const issuedTxn = await postTransaction({ transaction_authorization_id: handle });
    const txnToken = issuedTxn.body.access_token;
    // §5.3 poll shape: 400 authorization_pending -> still pending; a terminal
    // access_denied/expired_token reaps the handle and surfaces the denial.
    if (issuedTxn.status !== 200 || !txnToken) {
      const err = issuedTxn.body.error;
      if (err === "access_denied" || err === "expired_token") {
        txnHandles.delete(taskId);
        return c.json({ ok: false, refusal_reason: err });
      }
      return c.json({ ok: false, pending: true, state: task.state });
    }
    const r = await stack.server.callTransactionTool(tool, args, active.facts, undefined, txnToken);
    await publishNew();
    txnHandles.delete(taskId);
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
