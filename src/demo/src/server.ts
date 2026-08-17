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
import {
  clientAssertionSigner,
  completeMissionApproval,
  denyMissionApproval,
  dpopProofFor,
  issueMissionToken,
  submitMissionApproval,
} from "./oauth-client.js";

const TX_TOOLS = new Set(["execute_wire_transfer", "send_remittance_email"]);

/**
 * The seeded payable invoices the deterministic /agent/run planner attempts, in
 * order: inv-1 (acme $125, within cap -> commits), inv-2 (acme $900, over the
 * $500 cap -> constraint_exceeded), inv-3 (globex, off-vendor -> out_of_authority).
 * inv-seed is excluded (already wired at boot). Reading the store would pull it
 * in as already-paid noise, so the demo set is fixed.
 */
const RUN_INVOICES = ["inv-1", "inv-2", "inv-3"];

/**
 * @spec txn-authorization#resource-challenge — this console redeems challenges,
 * so it signals `Accept-Txn-Challenge` on every transaction-tier call.
 */
const ACCEPT_CHALLENGE = { acceptTxnChallenge: true } as const;

/** A tool-call result, loosely typed for the display-only step detail below. */
interface ToolResult {
  ok: boolean;
  result?: unknown;
  denial_reason?: string | undefined;
  refusal_reason?: string | undefined;
  deduped?: boolean | undefined;
  /** @spec txn-authorization#resource-challenge — the upstream wire members. */
  error?: string | undefined;
  transaction_challenge?: string | undefined;
}

/**
 * Structured, display-only detail for one agent step. The dashboard has ONE
 * renderer (renderStep) that consumes this shape for both single actions and
 * /agent/run steps, so the shape is kept stable. Nothing here is a wire value;
 * it is derived entirely from the tool result + args the enforcement path
 * already produced.
 */
interface StepDetail {
  tool: string;
  args: Record<string, unknown>;
  ok: boolean;
  /** Raw denial/refusal code; the UI glosses it via the #361 label map. */
  reason: string | null;
  missionId: string;
  target: { invoice_id: string; vendor: string | null; amount: string | null; currency: string | null } | null;
  outcome: "executed" | "read" | "denied" | "paused";
  evidence: "execution committed" | "read" | "refused" | "awaiting approval" | null;
  deduped?: boolean;
}

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
  // The wire value is the Mission Intent Submission envelope; the semantic
  // task context is its `intent` member.
  const missionIntent = JSON.stringify({
    intent: {
      goal: "Pay approved Acme invoices and send remittance",
      resources: [CANONICAL_RESOURCE],
      expires_at: "2027-01-01T00:00:00Z",
    },
  });
  // The authority proposal rides the standard RFC 9396 authorization_details
  // parameter, pushed through PAR alongside mission_intent.
  const authorizationDetails = JSON.stringify([
    {
      type: "mission_resource_access",
      resource: CANONICAL_RESOURCE,
      actions: ["payments:invoice.read", "payments:payment.execute", "payments:remittance.send"],
      constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
    },
  ]);
  const issued = await issueMissionToken(asUrl, stack.authServer.agentClientJwk, { missionIntent, authorizationDetails, scope: "payments" });
  const rsProof = await dpopProofFor(issued.dpopKeys, CANONICAL_RESOURCE, "POST");
  const facts: TokenFacts = {
    ...(await stack.server.validateToken(issued.accessToken, rsProof, CANONICAL_RESOURCE, "POST")),
    clientInstanceId: "inst-1",
  };
  const missionId = facts.mission.id;

  // The agent's ACTIVE mission: the credential material it currently acts under.
  // Held mutably so an APPROVED mission approval can swap the whole set (facts +
  // the DPoP-bound token used for resource calls and the AROP transaction
  // endpoint) atomically, once the approver adjudicates it.
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
  // Per-mission high-water mark: the active mission changes when a mission
  // approval is approved, so track how much of each mission's evidence has been
  // published and flush
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

  // @spec txn-authorization#challenge-redemption — POST to the AS transaction
  // endpoint. The client authenticates as itself (private_key_jwt), presents
  // the challenge with the Mission-bound access token as `subject_token`, and
  // proves possession of the challenge's cnf key with a DPoP proof bound to
  // this endpoint. Polls carry `transaction_authorization_id` alone.
  const clientAssertion = await clientAssertionSigner(asUrl, stack.authServer.agentClientJwk);
  const postTransaction = async (payload: Record<string, string>) => {
    const res = await fetch(`${asUrl}/transaction`, {
      method: "POST",
      headers: {
        dpop: await dpopProofFor(active.issued.dpopKeys, `${asUrl}/transaction`, "POST"),
        "content-type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        client_id: "ap-agent",
        client_assertion: await clientAssertion(),
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        ...payload,
      }).toString(),
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

  // taskId -> challenge-derived JIT detail, stashed at initiation so the enriched
  // approver queue can show what the approver is deciding (tool + invoice + digest)
  // without re-deriving anything the enforcement path already produced.
  const jitDetails = new Map<string, { tool: string; invoice_id?: string; parameter_digest?: string }>();

  // A parked mission approval: PAR/authorize done, decide NOT yet made. The jar
  // lives INSIDE each record so two concurrent submits get two DISTINCT jars
  // (the AS resolves an interaction from its cookie alone). state advances to
  // "active" (completed -> swapped in) or "denied" (interaction settled).
  type SubmittedApproval = Awaited<ReturnType<typeof submitMissionApproval>>;
  interface MissionApproval {
    submitted: SubmittedApproval;
    intent: string;
    goal: string;
    derived: AuthEntry[];
    subject: string;
    state: "pending" | "active" | "denied";
    missionId?: string;
  }
  const missionApprovals = new Map<string, MissionApproval>();

  // The approver's enriched queue, assembled in the DEMO server (console-bff is
  // untouched): JIT/AROP tasks (from the shared ARS + the stashed challenge
  // detail + the payments store) and parked mission approvals, in ONE shape the
  // Approver tab renders. Each entry: { id, type: "jit" | "mission", subject, context }.
  const enrichedQueue = () => {
    const mission = [...missionApprovals.entries()]
      .filter(([, r]) => r.state === "pending")
      .map(([id, r]) => ({
        id,
        type: "mission" as const,
        subject: r.subject,
        context: { goal: r.goal, derived: r.derived, subject: r.subject },
      }));
    const jit = stack.bff.approverQueue(session).map((t) => {
      const d = jitDetails.get(t.id);
      const inv = d?.invoice_id ? stack.payments.getInvoice(d.invoice_id) : undefined;
      return {
        id: t.id,
        type: "jit" as const,
        subject: t.subject,
        context: {
          action: t.action,
          action_label: ACTION_LABELS[t.action] ?? t.action,
          tool: d?.tool ?? null,
          invoice_id: d?.invoice_id ?? null,
          amount: inv?.amount ?? null,
          currency: inv?.currency ?? null,
          vendor: inv?.vendor_id ?? null,
          parameter_digest: d?.parameter_digest ?? null,
          mission_id: t.mission_id,
        },
      };
    });
    return [...mission, ...jit];
  };

  // Build the display-only StepDetail for one tool call from data ALREADY in the
  // result + args (no extra enforcement, no PEP observe hook). The target's
  // amount/vendor come from a direct payments-store read (stack.payments), which
  // does NOT run through the PEP, so it never changes enforcement or double-counts.
  const stepDetail = (tool: string, args: Record<string, unknown>, r: ToolResult, missionId: string): StepDetail => {
    const res = r.result as { invoice_id?: string; id?: string } | undefined;
    const invoiceId =
      (typeof args.invoice_id === "string" && args.invoice_id) || res?.invoice_id || res?.id || undefined;
    let target: StepDetail["target"] = null;
    if (invoiceId) {
      const inv = stack.payments.getInvoice(invoiceId);
      target = inv
        ? { invoice_id: inv.id, vendor: inv.vendor_id, amount: inv.amount, currency: inv.currency }
        : { invoice_id: invoiceId, vendor: null, amount: null, currency: null };
    }
    const paused = !r.ok && !!r.transaction_challenge;
    const outcome: StepDetail["outcome"] = paused ? "paused" : !r.ok ? "denied" : TX_TOOLS.has(tool) ? "executed" : "read";
    const evidence: StepDetail["evidence"] =
      outcome === "executed" ? "execution committed" : outcome === "read" ? "read" : outcome === "paused" ? "awaiting approval" : "refused";
    return {
      tool,
      args,
      ok: !!r.ok,
      reason: r.denial_reason ?? r.refusal_reason ?? null,
      missionId,
      target,
      outcome,
      evidence,
      ...(r.deduped ? { deduped: true } : {}),
    };
  };

  // Initiate the AROP flow for a challenge-bearing denial: present the RS
  // challenge to the AS transaction endpoint ONCE, capture the continuation
  // handle keyed by the ARS task id (arq_txn_<txn>), and return the pending
  // fields the UI/JIT retry wire on. Shared by /agent/act and /agent/run so both
  // open the AROP task through identical logic.
  const initiateArop = async (challenge: string, tool: string, invoiceId?: string) => {
    const challengeClaims = decodeClaims(challenge);
    const txn = challengeClaims.txn as string | undefined;
    const taskId = txn ? `arq_txn_${txn}` : undefined;
    if (taskId) {
      // Stash the challenge-derived detail keyed by taskId so the enriched queue
      // can show tool + invoice + digest for this pending approval.
      jitDetails.set(taskId, {
        tool,
        ...(invoiceId ? { invoice_id: invoiceId } : {}),
        ...(challengeClaims.parameter_digest ? { parameter_digest: challengeClaims.parameter_digest as string } : {}),
      });
    }
    const pending = await postTransaction({
      transaction_challenge: challenge,
      subject_token: active.issued.accessToken,
      subject_token_type: "urn:ietf:params:oauth:token-type:access_token",
    });
    if (taskId && pending.body.transaction_authorization_id) {
      txnHandles.set(taskId, pending.body.transaction_authorization_id);
    }
    return {
      txn,
      taskId,
      transaction_authorization_id: pending.body.transaction_authorization_id,
      task_state: "authorization_pending" as const,
      transaction_challenge: challengeClaims,
    };
  };

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
  // Enriched approver queue (demo-assembled): JIT + parked mission approvals with
  // enough context per entry to decide (see enrichedQueue). Extends the shape the
  // console-bff method returns; the console-bff itself is untouched.
  app.get("/bff/approver/queue", (c) => c.json(enrichedQueue()));
  // Approver adjudicates EITHER a parked mission approval (approvalId in
  // missionApprovals) or a pending AROP/JIT task on the shared ARS.
  app.post("/bff/approver/adjudicate", async (c) => {
    const body = await readJson(c);
    const id = String(body.taskId ?? body.id ?? "");
    const decision = (body.decision as "approve" | "deny") ?? "deny";
    const rec = missionApprovals.get(id);
    if (rec) {
      // Guard against a double-fire (the poll + the queue button both refresh):
      // once settled, echo the terminal state rather than re-deciding the jar.
      if (rec.state !== "pending") {
        return c.json({ approved: rec.state === "active", state: rec.state, ...(rec.missionId ? { missionId: rec.missionId } : {}) });
      }
      if (decision === "deny") {
        await denyMissionApproval(asUrl, { uid: rec.submitted.uid, jar: rec.submitted.jar });
        rec.state = "denied";
        return c.json({ approved: false, state: "denied" });
      }
      // Approve: complete the interaction (decide -> code -> token), rebuild
      // TokenFacts (mirroring the boot path), and swap the ACTIVE mission. Only
      // now does the mission become a kernel record visible in the fleet.
      let issuedMission: Awaited<ReturnType<typeof completeMissionApproval>>;
      try {
        issuedMission = await completeMissionApproval(asUrl, agentClientJwk, {
          uid: rec.submitted.uid,
          jar: rec.submitted.jar,
          par: rec.submitted.par,
        });
      } catch (e) {
        return c.json({ approved: false, error: (e as Error).message }, 400);
      }
      const proof = await dpopProofFor(issuedMission.dpopKeys, CANONICAL_RESOURCE, "POST");
      const newFacts: TokenFacts = {
        ...(await stack.server.validateToken(issuedMission.accessToken, proof, CANONICAL_RESOURCE, "POST")),
        clientInstanceId: "inst-1",
      };
      const newId = newFacts.mission.id;
      active = { facts: newFacts, missionId: newId, issued: issuedMission };
      // Active-mission swap: prior JIT continuation handles belong to the OLD
      // mission, so drop them (a stale /agent/retry must not execute against the
      // new mission). The frontend also guards its poll by mission id.
      txnHandles.clear();
      publishedCounts.set(newId, stack.evidence.forMission(newId).length);
      await publishNew();
      rec.state = "active";
      rec.missionId = newId;
      return c.json({ approved: true, missionId: newId, authority: stack.kernel.get(newId)?.authority_set ?? [] });
    }
    // JIT/AROP task on the shared ARS.
    return c.json(await stack.bff.adjudicateTask(session, id, decision, session.csrf));
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

  // Shape a goal into a proposed Mission Intent plus its authority proposal
  // (the standard RFC 9396 authorization_details array, sent beside the
  // intent). The shaper carries no cap, so the demo injects the proposed
  // max_amount into the proposal entry here (services/agent untouched) to
  // surface an over-ask the derivation will visibly narrow.
  app.post("/agent/shape", async (c) => {
    const b = await readJson(c);
    const resources = (b.resources as string[]) ?? [CANONICAL_RESOURCE];
    const shaped = shapeIntent({
      goal: String(b.goal ?? ""),
      resources,
      expiresAt: (b.expiresAt as string) ?? "2027-01-01T00:00:00Z",
      ...(Array.isArray(b.actions) ? { proposedActions: b.actions as string[] } : {}),
      ...(Array.isArray(b.vendors) ? { vendors: b.vendors as string[] } : {}),
    });
    const intent = JSON.parse(shaped.missionIntent) as Record<string, unknown>;
    const entries = shaped.authorizationDetails
      ? (JSON.parse(shaped.authorizationDetails) as Array<Record<string, unknown>>)
      : undefined;
    const cap = (b.cap ?? b.max_amount) as string | undefined;
    if (cap && entries?.[0]) {
      const e = entries[0];
      const constraints = (e.constraints as Record<string, unknown> | undefined) ?? {};
      constraints.max_amount = { amount: String(cap), currency: "USD" };
      e.constraints = constraints;
    }
    return c.json({ intent, ...(entries ? { authorization_details: entries } : {}) });
  });

  // Derive the bounded Authority Set from the (untrusted) Intent and compute the
  // narrowing server-side: per resource entry, which vendors/actions were
  // DROPPED and which constraints were TIGHTENED (e.g. max_amount 900 -> 500).
  // The UI renders this diff; it never diffs two authority blobs itself.
  app.post("/agent/propose", async (c) => {
    const b = await readJson(c);
    const raw = typeof b.intent === "string" ? b.intent : JSON.stringify(b.intent ?? {});
    // The proposal arrives as a separate authorization_details member (array
    // or JSON string), never inside the Intent.
    const rawDetails = b.authorization_details;
    let proposed: AuthEntry[];
    let derived: AuthEntry[];
    try {
      const parsed = stack.kernel.validateIntent(raw);
      const proposal =
        rawDetails == null
          ? undefined
          : stack.kernel.validateProposal(
              typeof rawDetails === "string" ? rawDetails : JSON.stringify(rawDetails),
              parsed.resources,
            );
      derived = stack.kernel.derive(parsed, proposal) as unknown as AuthEntry[];
      proposed = (proposal ?? []) as unknown as AuthEntry[];
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

  // Submit the (narrowed) mission FOR APPROVAL: PAR -> authorize -> interaction
  // uid, then park it (jar keyed per approvalId). NO decide yet, so no kernel
  // record and NOTHING in the operator fleet until an approver adjudicates. The
  // enriched approver queue surfaces it as a type:"mission" entry (goal + derived).
  app.post("/agent/submit", async (c) => {
    const b = await readJson(c);
    // The shaper proposes the SEMANTIC Intent; the wire submission is the
    // Mission Intent Submission envelope wrapped below.
    const semanticIntent = typeof b.intent === "string" ? b.intent : JSON.stringify(b.intent ?? {});
    const rawDetails = b.authorization_details;
    const authorizationDetails =
      rawDetails == null ? undefined : typeof rawDetails === "string" ? rawDetails : JSON.stringify(rawDetails);
    // Validate + derive up front (same as /agent/propose) so the queue can show
    // the approver the goal and the authority they are about to grant.
    let goal: string;
    let derived: AuthEntry[];
    let missionIntent: string;
    try {
      const parsed = stack.kernel.validateIntent(semanticIntent);
      const proposal = authorizationDetails
        ? stack.kernel.validateProposal(authorizationDetails, parsed.resources)
        : undefined;
      derived = stack.kernel.derive(parsed, proposal) as unknown as AuthEntry[];
      goal = String((parsed as unknown as { goal?: unknown }).goal ?? "");
      missionIntent = JSON.stringify({ intent: parsed });
    } catch (e) {
      return c.json({ error: (e as Error).message }, 400);
    }
    let submitted: Awaited<ReturnType<typeof submitMissionApproval>>;
    try {
      submitted = await submitMissionApproval(asUrl, agentClientJwk, {
        missionIntent,
        scope: "payments",
        ...(authorizationDetails ? { authorizationDetails } : {}),
      });
    } catch (e) {
      return c.json({ error: (e as Error).message }, 400);
    }
    const approvalId = `apv_${crypto.randomUUID()}`;
    missionApprovals.set(approvalId, { submitted, intent: missionIntent, goal, derived, subject: "alice", state: "pending" });
    return c.json({ pending: true, approvalId, derived });
  });

  // Poll a parked mission approval: pending (awaiting the approver), active
  // (completed + swapped in, with its missionId), or denied. `unknown` is a
  // terminal answer for an id the server no longer tracks (never a poll loop).
  app.get("/agent/approval-status", (c) => {
    const rec = missionApprovals.get(c.req.query("id") ?? "");
    if (!rec) return c.json({ state: "unknown" });
    return c.json({ state: rec.state, ...(rec.missionId ? { missionId: rec.missionId } : {}) });
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
      ? await stack.server.callTransactionTool(tool, args, active.facts, undefined, undefined, ACCEPT_CHALLENGE)
      : await stack.server.callReadTool(tool, args, active.facts);
    await publishNew();
    // Structured detail for the log renderer, ADDED alongside the existing
    // fields (ok/denial_reason/... stay for the JIT UI + /agent/retry contract).
    const detail = stepDetail(tool, args, r, active.missionId);
    const ch = (r as ToolResult).transaction_challenge;
    if (!r.ok && ch) {
      // The ARS task id is derived from the challenge's txn (openForTxn keys the
      // task arq_txn_<txn>), so the approver queue + retry correlate on it while
      // the client polls the AS by the continuation handle. `arop` is spread
      // AFTER `r` so its decoded challenge overrides the raw one; `detail` carries
      // no transaction_challenge/taskId, so it never clobbers those.
      const arop = await initiateArop(ch, tool, args.invoice_id as string | undefined);
      return c.json({ ...r, ...arop, ...detail });
    }
    return c.json({ ...r, ...detail });
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

  // One-click autonomous run: a DETERMINISTIC planner (no LLM, no API key) that
  // works the mission end to end through the SAME PEP path /agent/act uses. Wire
  // each seeded payable invoice (inv-1 commits; inv-2 over cap; inv-3 off-vendor),
  // then attempt the JIT-gated remittance, which PAUSES on an AROP challenge
  // (never auto-approved). Returns an ARRAY of the SAME per-step shape as a single
  // action, so the UI renders every step through one renderStep() path; the final
  // step is the paused JIT one carrying the taskId the retry button wires on.
  app.post("/agent/run", async (c) => {
    const steps: Array<StepDetail & { taskId?: string | undefined; transaction_authorization_id?: string | undefined }> = [];
    for (const invoice_id of RUN_INVOICES) {
      const args = { invoice_id };
      const r = await stack.server.callTransactionTool("execute_wire_transfer", args, active.facts, undefined, undefined, ACCEPT_CHALLENGE);
      await publishNew();
      steps.push(stepDetail("execute_wire_transfer", args, r, active.missionId));
    }
    // JIT-gated remittance on inv-1: initiate AROP exactly as /agent/act does and
    // STOP (no auto-approve). The paused step carries taskId + tool + args so the
    // UI can arm the existing retry button against the AROP task.
    const jitArgs = { invoice_id: "inv-1" };
    const jr = await stack.server.callTransactionTool("send_remittance_email", jitArgs, active.facts, undefined, undefined, ACCEPT_CHALLENGE);
    await publishNew();
    const jitDetail = stepDetail("send_remittance_email", jitArgs, jr, active.missionId);
    if (!jr.ok && jr.transaction_challenge) {
      const arop = await initiateArop(jr.transaction_challenge, "send_remittance_email", jitArgs.invoice_id);
      steps.push({ ...jitDetail, taskId: arop.taskId, transaction_authorization_id: arop.transaction_authorization_id });
    } else {
      steps.push(jitDetail);
    }
    return c.json({ steps });
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
