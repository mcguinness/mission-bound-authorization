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

import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";
import { serve } from "@hono/node-server";
import { Hono, type Context } from "hono";
import { txnTaskId } from "@mission/access-request";
import { evaluateApprovalFloor } from "@mission/authorization-server";
import type { MissionBoundTokenFacts } from "@mission/mcp-payments";
import { APPROVAL_FLOOR, CANONICAL_RESOURCE, TOPOLOGY } from "@mission/demo-data";
import { shapeIntent } from "@mission/agent";
import { callWithTransactionCredential, composeStack } from "./stack.js";
import { evidenceKeysFromEnv } from "./evidence-key-files.js";
import { resourcePolicyStoreFromEnv } from "./resource-policy-store.js";
import { ACTION_LABELS, REASON_LABELS, TOOL_LABELS } from "./labels.js";
import {
  clientAssertionSigner,
  dpopProofFor,
  submitMissionApproval,
  tokenGrantRequest,
} from "./oauth-client.js";
import { completeMissionApproval, denyMissionApproval, issueMissionToken, logInAgain } from "./approval-console.js";
import { installConsoleSessionBoundary } from "./console-session-boundary.js";
import { defaultMissionExpiry } from "./mission-expiry.js";

/** @spec runtime#idempotency (#917): one fresh `idempotency_key` per intended execution. */
const idem = (): string => `idem_${randomUUID()}`;

const TX_TOOLS = new Set(["execute_wire_transfer", "reverse_wire_transfer", "send_remittance_email"]);
/** @spec runtime#idempotency (#917, #918): every tool whose Operation Profile defines a key. */
const KEYED_TOOLS = new Set([...TX_TOOLS, "schedule_payment", "cancel_scheduled_payment"]);

/**
 * @spec runtime#idempotency (#917, #918): the demo stands in for the agent, so
 * it mints one `idempotency_key` per intended execution of a keyed tool when
 * the caller supplied none. A retry of the same execution (the JIT retry)
 * carries the key its first attempt used, from the args the step reported.
 */
const keyed = (tool: string, args: Record<string, unknown>): Record<string, unknown> =>
  KEYED_TOOLS.has(tool) && typeof args.idempotency_key !== "string" ? { ...args, idempotency_key: idem() } : args;

/**
 * The seeded payable invoices the deterministic /agent/run planner attempts, in
 * order: inv-1 (acme $125, within cap -> commits), inv-2 (acme $900, over the
 * $500 cap -> out_of_authority), inv-3 (globex, off-vendor -> out_of_authority).
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

const amt = (m?: Amount) => (m ? `${m.amount} ${m.currency}` : "unbounded");

/**
 * @spec mission#authorization-derivation (#743, review #745 P1) — the
 * `/agent/propose` preview's narrowing diff, extracted so it is unit-testable
 * without the full composed stack (nothing here reads network/kernel state;
 * `proposed` and `derived` are already-derived Authority Set entries).
 *
 * `derive()` returns one fragment PER matching ceiling entry, so a single
 * mixed proposed entry (e.g. read + money actions together, the default UI
 * proposal) can derive into more than one same-resource fragment. Selecting
 * ONE derived entry by resource (the prior shape) silently picked a single
 * fragment and reported everything it didn't grant as dropped, even when a
 * second fragment actually granted it. This aggregates every derived
 * fragment applicable to a proposed entry (same resource) and compares at
 * ACTION grain: an action counts as granted if ANY applicable fragment
 * carries it, and a tightened `max_amount` is reported per distinct granting
 * cap among the fragments that actually cover one of the proposed actions.
 *
 * `vendors_dropped` unions granted vendors across every applicable fragment,
 * which is exactly right for the shipped config (every payments ceiling
 * entry shares the same vendor set). It is a display-only widening risk in
 * the general case: a policy where two same-resource fragments grant
 * DISJOINT vendor sets (fragment A: acme-only, fragment B: globex-only)
 * would union-report neither as dropped even though no SINGLE fragment
 * grants both — the preview would need to compare per-action-and-vendor,
 * not per-resource, to close that. Flagged, not fixed here: the shipped
 * config has no such policy, and no ceiling entry carries a vendor
 * constraint the sibling entries don't share.
 */
export function proposalDiff(
  proposed: readonly AuthEntry[],
  derived: readonly AuthEntry[],
): { resource: string; actions_dropped: string[]; vendors_dropped: string[]; constraints_tightened: { name: string; proposed: string; granted: string }[] }[] {
  return proposed.map((p) => {
    const applicable = derived.filter((d) => d.resource === p.resource);
    const gActions = new Set(applicable.flatMap((d) => d.actions));
    const gVendors = new Set(applicable.flatMap((d) => d.constraints?.vendors ?? []));
    const pVendors = p.constraints?.vendors ?? [];
    const pCap = p.constraints?.max_amount;
    const tightened: { name: string; proposed: string; granted: string }[] = [];
    const seenCaps = new Set<string>();
    for (const fragment of applicable) {
      // Only a fragment that actually carries one of this proposed entry's
      // actions speaks to what THIS entry was tightened to; a fragment born
      // of a disjoint action subset (e.g. the read-only ceiling entry, when
      // p also proposed money actions) is irrelevant to p's own cap.
      if (!fragment.actions.some((a) => p.actions.includes(a))) continue;
      const gCap = fragment.constraints?.max_amount;
      if (!gCap) continue;
      if (pCap && pCap.amount === gCap.amount && pCap.currency === gCap.currency) continue;
      const key = `${gCap.amount}|${gCap.currency}`;
      if (seenCaps.has(key)) continue;
      seenCaps.add(key);
      tightened.push({ name: "max_amount", proposed: amt(pCap), granted: amt(gCap) });
    }
    return {
      resource: p.resource,
      actions_dropped: p.actions.filter((a) => !gActions.has(a)),
      vendors_dropped: pVendors.filter((v) => !gVendors.has(v)),
      constraints_tightened: tightened,
    };
  });
}

const PORT = Number(process.env.CONSOLE_BFF_PORT ?? TOPOLOGY.ports.console);
const INDEX = fileURLToPath(new URL("../public/index.html", import.meta.url));
const STORY_MODULE = fileURLToPath(new URL("../public/console-story.js", import.meta.url));

/** Parse a JSON request body, tolerating an empty body. */
const readJson = (c: Context): Promise<Record<string, unknown>> =>
  c.req.json().catch(() => ({}) as Record<string, unknown>);

/**
 * The demo server's Mission Intent Submission envelope: the semantic task
 * context is its `intent` member, expiring a fixed distance after `now`, the
 * stack's kernel clock (#1976).
 */
export function demoMissionIntent(now: Date): string {
  return JSON.stringify({
    intent: {
      goal: "Pay approved Acme invoices and send remittance",
      target_resources: [CANONICAL_RESOURCE],
      expires_at: defaultMissionExpiry(now),
    },
  });
}

/**
 * The second Mission the agent holds at boot: a read-only reconciliation task
 * beside the payments one, so revoking one Mission visibly leaves the agent's
 * other task working.
 */
export function reconciliationMissionIntent(now: Date): { missionIntent: string; authorizationDetails: string } {
  return {
    missionIntent: JSON.stringify({
      intent: {
        goal: "Reconcile Acme invoices (read-only)",
        target_resources: [CANONICAL_RESOURCE],
        expires_at: defaultMissionExpiry(now),
      },
    }),
    authorizationDetails: JSON.stringify([
      {
        type: "mission_resource_access",
        resource: CANONICAL_RESOURCE,
        actions: ["payments:invoice.read", "payments:invoice.list"],
        constraints: { vendors: ["acme"] },
      },
    ]),
  };
}

/**
 * The edit the console's tamper step makes to one retained Execution Evidence
 * record: its outcome is rewritten from `completed` to `failed`, as an insider
 * hiding a payment would. Returns the change made, with the action the
 * record's operation key names (`op:<mission>:<action>:...`), or undefined
 * when the record carries no completed outcome to rewrite. Display and demo
 * only.
 */
export function rewriteExecutionOutcome(
  evidence: Record<string, unknown>,
): { path: string; from: string; to: string; action: string | null } | undefined {
  const content = evidence.content as Record<string, unknown> | undefined;
  if (!content || content.outcome !== "completed") return undefined;
  content.outcome = "failed";
  const action = typeof evidence.op_key === "string" ? (/^op:[^:]+:([^:]+:[^:]+):/.exec(evidence.op_key)?.[1] ?? null) : null;
  return { path: "content.outcome", from: "completed", to: "failed", action };
}

/**
 * The Mission an agent action runs under. An omitted `missionId` selects the
 * active Mission; an explicit one must name a Mission the agent holds, and is
 * refused otherwise, never replaced by the active one: a stale or mistyped id
 * would otherwise run the action under another task's authority.
 */
export function selectBinding<B>(
  requested: unknown,
  bindings: ReadonlyMap<string, B>,
  active: B,
): { binding: B } | { status: 400 | 404; error: string } {
  if (requested === undefined) return { binding: active };
  if (typeof requested !== "string" || requested === "") {
    return { status: 400, error: "missionId must be a non-empty string naming a Mission the agent holds" };
  }
  const binding = bindings.get(requested);
  return binding === undefined ? { status: 404, error: `the agent holds no Mission ${requested}` } : { binding };
}

/**
 * The Mission an approval retry runs under: the one its challenge was opened
 * under, and no other. With no Mission recorded for the task, or one the
 * agent no longer holds, there is none, and the retry is refused.
 */
export function challengedBinding<B>(
  taskId: string,
  challengedUnder: ReadonlyMap<string, string>,
  bindings: ReadonlyMap<string, B>,
): B | undefined {
  const id = challengedUnder.get(taskId);
  return id === undefined ? undefined : bindings.get(id);
}

/**
 * POST /agent/act: select the Mission first, and refuse a bad selection
 * before any token renewal or tool call; then renew, invoke the tool under
 * that Mission, and report.
 */
export async function handleAgentAct<B>(
  body: Record<string, unknown>,
  deps: {
    bindings: ReadonlyMap<string, B>;
    active: B;
    renew: (b: B) => Promise<unknown>;
    invoke: (tool: string, args: Record<string, unknown>, b: B) => Promise<ToolResult>;
    report: (tool: string, args: Record<string, unknown>, r: ToolResult, b: B, renewal: unknown) => Promise<Record<string, unknown>>;
  },
): Promise<{ status: 200 | 400 | 404; body: Record<string, unknown> }> {
  const selected = selectBinding(body.missionId, deps.bindings, deps.active);
  if (!("binding" in selected)) return { status: selected.status, body: { ok: false, error: selected.error } };
  const tool = String(body.tool);
  const args = keyed(tool, (body.args as Record<string, unknown>) ?? {});
  const renewal = await deps.renew(selected.binding);
  const r = await deps.invoke(tool, args, selected.binding);
  return { status: 200, body: await deps.report(tool, args, r, selected.binding, renewal) };
}

/** A parked Mission approval, as {@link adjudicateMissionApproval} decides it. */
export interface ParkedApproval {
  /**
   * `failed`: a decision was attempted and did not complete. The console
   * cannot tell whether the authorization server's interaction is still open,
   * so it stops using it; that is not a denial.
   */
  state: "pending" | "active" | "denied" | "failed";
  missionId?: string;
  error?: string;
  /** The one decision in flight; a concurrent request observes its result. */
  inflight?: Promise<AdjudicationResult>;
}
export interface AdjudicationResult {
  status: 200 | 400 | 409;
  body: Record<string, unknown>;
}

/**
 * Decide a parked Mission approval once. Concurrent requests (a double click,
 * the queue beside the story bar) share the decision in flight, whatever they
 * asked for; a settled record answers with its state. An approval whose
 * login the floor would refuse is refused first, before the interaction is
 * touched, so the approver can log in again and still approve. A failed
 * attempt never overwrites a record another attempt settled.
 */
export function adjudicateMissionApproval<I>(
  rec: ParkedApproval,
  decision: "approve" | "deny",
  deps: {
    floor: () => { outcome: string; reason?: string; unclassified?: true };
    complete: () => Promise<I>;
    adopt: (issued: I) => Promise<{ missionId: string; authority: unknown }>;
    deny: () => Promise<void>;
  },
): Promise<AdjudicationResult> {
  if (rec.inflight) return rec.inflight;
  if (rec.state !== "pending") {
    return Promise.resolve({
      status: 200,
      body: {
        approved: rec.state === "active",
        state: rec.state,
        ...(rec.missionId ? { missionId: rec.missionId } : {}),
        ...(rec.error ? { error: rec.error } : {}),
      },
    });
  }
  if (decision === "approve") {
    const floor = deps.floor();
    if (floor.outcome === "refused" && !floor.unclassified) {
      return Promise.resolve({ status: 409, body: { approved: false, state: "pending", error: `log in again first: ${floor.reason}`, floor } });
    }
  }
  const fail = (message: string): AdjudicationResult => {
    if (rec.state === "pending") {
      rec.state = "failed";
      rec.error = message;
    }
    return { status: 400, body: { approved: false, state: rec.state, error: message } };
  };
  const run = async (): Promise<AdjudicationResult> => {
    if (decision === "deny") {
      try {
        await deps.deny();
      } catch (e) {
        return fail((e as Error).message);
      }
      rec.state = "denied";
      return { status: 200, body: { approved: false, state: "denied" } };
    }
    let issued: I;
    try {
      issued = await deps.complete();
    } catch (e) {
      return fail((e as Error).message);
    }
    let adopted: { missionId: string; authority: unknown };
    try {
      adopted = await deps.adopt(issued);
    } catch (e) {
      return fail(`the Mission was issued, but the console could not bind it: ${(e as Error).message}`);
    }
    rec.state = "active";
    rec.missionId = adopted.missionId;
    return { status: 200, body: { approved: true, missionId: adopted.missionId, authority: adopted.authority } };
  };
  rec.inflight = run().finally(() => {
    rec.inflight = undefined;
  });
  return rec.inflight;
}

/** Decode a compact JWS payload (base64url) without verifying, for display. */
function decodeClaims(jwt: string): Record<string, unknown> {
  return JSON.parse(Buffer.from(jwt.split(".")[1] as string, "base64url").toString());
}

async function main() {
  const ca = `${process.cwd()}/certs/openfga.crt`;
  const evidenceKeys = evidenceKeysFromEnv(process.env);
  const stack = await composeStack({
    openfgaUrl: process.env.OPENFGA_HTTP_URL ?? TOPOLOGY.openfga.url,
    presharedKey: process.env.OPENFGA_PRESHARED_KEY ?? TOPOLOGY.openfga.presharedKey,
    resourcePolicyStore: resourcePolicyStoreFromEnv(),
    caCertPath: ca,
    withAuthServer: true,
    // @spec #831 (scope inventory): durable evidence keys, or keys generated per boot.
    ...(evidenceKeys ? { evidenceKeys } : {}),
  });
  if (!stack.authServer) throw new Error("expected authServer extras (composeStack withAuthServer)");
  // @spec runtime#evidence (outcome reconciliation) (#1103): the declared
  // reconciler runs for the server's lifetime on a timer that keeps no
  // process alive; its operator alerts go to stderr.
  stack.reconciler.start();
  const asUrl = stack.authServer.asUrl;
  const agentClientJwk = stack.authServer.agentClientJwk;

  // Real issuance: PAR -> authorize -> Bob approves alice -> DPoP-bound token.
  // The mission covers reading, wire execution, and remittance (the JIT-gated
  // action). The base token + its DPoP key are held server-side to drive the
  // resource calls and the AROP transaction endpoint.
  // The wire value is the Mission Intent Submission envelope; the semantic
  // task context is its `intent` member.
  const missionIntent = demoMissionIntent(stack.kernel.nowDate());
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
  const issued = await issueMissionToken(asUrl, stack.authServer.agentClientJwk, { missionIntent, authorizationDetails }, stack.authServer.approverConsole);
  const rsProof = await dpopProofFor(issued.dpopKeys, CANONICAL_RESOURCE, "POST", issued.accessToken);
  // @spec authority-server#mission-join (#557 review point 5) — validateToken()
  // returns MissionBoundTokenFacts specifically (mission REQUIRED, never
  // optional), so `facts.mission.id` below needs no assertion: the type
  // system proves presence, rather than this call site trusting a documented
  // invariant on a single hybrid TokenFacts shape.
  const facts: MissionBoundTokenFacts = {
    ...(await stack.server.validateToken(issued.accessToken, rsProof, CANONICAL_RESOURCE, "POST")),
    clientInstanceId: "inst-1",
  };
  const missionId = facts.mission.id;

  // The agent's ACTIVE mission: the credential material it currently acts under.
  // Held mutably so an APPROVED mission approval can swap the whole set (facts +
  // the DPoP-bound token used for resource calls and the AROP transaction
  // endpoint) atomically, once the approver adjudicates it.
  type Binding = { facts: MissionBoundTokenFacts; missionId: string; issued: typeof issued; refreshToken: string | undefined };
  const refreshTokenOf = (credential: typeof issued): string | undefined => {
    const rt = credential.artifacts.token.response.refresh_token;
    return typeof rt === "string" ? rt : undefined;
  };
  let active: Binding = { facts, missionId, issued, refreshToken: refreshTokenOf(issued) };
  // Every Mission the agent holds, by id. An action names one, or runs under
  // `active`; revoking one Mission leaves the others' credentials in force.
  const bindings = new Map<string, Binding>([[missionId, active]]);
  const factsFor = async (credential: typeof issued): Promise<MissionBoundTokenFacts> => {
    const proof = await dpopProofFor(credential.dpopKeys, CANONICAL_RESOURCE, "POST", credential.accessToken);
    return {
      ...(await stack.server.validateToken(credential.accessToken, proof, CANONICAL_RESOURCE, "POST")),
      clientInstanceId: "inst-1",
    };
  };
  const bind = async (credential: typeof issued): Promise<Binding> => {
    const bound = await factsFor(credential);
    const b = { facts: bound, missionId: bound.mission.id, issued: credential, refreshToken: refreshTokenOf(credential) };
    bindings.set(b.missionId, b);
    return b;
  };
  const nowSeconds = () => Math.floor(stack.kernel.nowDate().getTime() / 1000);

  // Access tokens live minutes; the Mission lives as long as its approval
  // says. Like any OAuth client, the agent renews a token about to lapse with
  // its refresh token, under the same DPoP key, before it acts. The AS refuses
  // that renewal once the Mission is no longer active. Returns undefined when
  // no renewal was due.
  const RENEW_WITHIN_SECONDS = 60;
  const renew = async (b: Binding): Promise<{ renewed: true } | { renewed: false; error: string } | undefined> => {
    const exp = decodeClaims(b.issued.accessToken).exp;
    if (typeof exp !== "number" || exp - nowSeconds() > RENEW_WITHIN_SECONDS || !b.refreshToken) return undefined;
    const res = await tokenGrantRequest(asUrl, agentClientJwk, b.issued.dpopKeys, {
      grant_type: "refresh_token",
      refresh_token: b.refreshToken,
    });
    const accessToken = res.body.access_token;
    if (res.status !== 200 || typeof accessToken !== "string") {
      return { renewed: false, error: String(res.body.error ?? `HTTP ${res.status}`) };
    }
    b.issued = { ...b.issued, accessToken };
    if (typeof res.body.refresh_token === "string") b.refreshToken = res.body.refresh_token;
    b.facts = await factsFor(b.issued);
    return { renewed: true };
  };

  // The agent's second task, read-only, issued the same way as the first.
  const reconciliation = await bind(
    await issueMissionToken(asUrl, agentClientJwk, reconciliationMissionIntent(stack.kernel.nowDate()), stack.authServer.approverConsole),
  );

  // Seed evidence: one wire on inv-seed (keeps inv-1's single-use permit fresh
  // for the dashboard button), then publish it to the transparency log.
  await stack.server.callReadTool("get_invoice", { invoice_id: "inv-1" }, facts);
  await stack.server.callTransactionTool("execute_wire_transfer", { invoice_id: "inv-seed", idempotency_key: idem() }, facts);
  await stack.server.callReadTool("get_invoice", { invoice_id: "inv-1" }, reconciliation.facts);
  for (const mid of [missionId, reconciliation.missionId]) {
    for (const ev of stack.evidence.forMission(mid)) {
      const t = ev.kind === "decision" ? "decision-evidence" : ev.kind === "execution" ? "execution-evidence" : "refusal-record";
      await stack.publishEvidence(mid, t, ev as unknown as Record<string, unknown>);
    }
  }

  // Separate operator login: its random bootstrap secret is never served by
  // an agent route. The downstream approver credential remains server-side.
  const session = stack.bff.sessions.create("bob", ["operator", "approver"]);

  // Publish any evidence produced since the last call to the transparency log
  // so the operator timeline reflects the newest agent activity.
  // Per-mission high-water mark: the active mission changes when a mission
  // approval is approved, so track how much of each mission's evidence has been
  // published and flush
  // only the tail for whichever mission the caller names (default: active).
  const publishedCounts = new Map<string, number>(
    [missionId, reconciliation.missionId].map((mid) => [mid, stack.evidence.forMission(mid).length]),
  );
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
  const postTransaction = async (payload: Record<string, string>, b: Binding = active) => {
    const res = await fetch(`${asUrl}/transaction`, {
      method: "POST",
      headers: {
        dpop: await dpopProofFor(b.issued.dpopKeys, `${asUrl}/transaction`, "POST"),
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
  // taskId -> the Mission the challenged action ran under, so the retry
  // presents that Mission's credential.
  const txnMissions = new Map<string, string>();

  // taskId -> challenge-derived JIT detail, stashed at initiation so the enriched
  // approver queue can show what the approver is deciding (tool + invoice + digest)
  // without re-deriving anything the enforcement path already produced.
  const jitDetails = new Map<string, { tool: string; invoice_id?: string; parameter_digest?: string }>();

  // A parked mission approval: PAR/authorize done, decide NOT yet made. The jar
  // lives INSIDE each record so two concurrent submits get two DISTINCT jars
  // (the AS resolves an interaction from its cookie alone). state advances to
  // "active" (completed -> swapped in) or "denied" (interaction settled).
  type SubmittedApproval = Awaited<ReturnType<typeof submitMissionApproval>>;
  interface MissionApproval extends ParkedApproval {
    submitted: SubmittedApproval;
    intent: string;
    goal: string;
    proposed: AuthEntry[];
    derived: AuthEntry[];
    diff: ReturnType<typeof proposalDiff>;
    subject: string;
  }
  const missionApprovals = new Map<string, MissionApproval>();

  // The approval-authentication floor as the AS will apply it to this
  // authority, against the approver's recorded login as it stands now
  // (@spec mission#approval-authentication). Display only: the AS evaluates
  // the floor again when the approver decides.
  const floorFor = (derived: AuthEntry[]) =>
    evaluateApprovalFloor(APPROVAL_FLOOR, derived as never, stack.approverLogin, { interactive: true, nowSeconds: nowSeconds() });
  const loginState = () => ({
    sub: stack.approverLogin.sub,
    acr: stack.approverLogin.acr,
    auth_time: stack.approverLogin.auth_time,
    now: nowSeconds(),
    max_age_seconds: Math.min(...APPROVAL_FLOOR.floors.map((f) => f.max_authentication_age_seconds)),
  });

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
        context: {
          goal: r.goal,
          expires_at: (JSON.parse(r.intent) as { intent: { expires_at?: string } }).intent.expires_at ?? null,
          proposed: r.proposed,
          derived: r.derived,
          diff: r.diff,
          subject: r.subject,
          floor: floorFor(r.derived),
        },
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
  // handle keyed by the ARS task id (resource-scoped: a `txn` is unique within
  // a Challenge-Issuing Resource, never globally), and return the pending
  // fields the UI/JIT retry wire on. Shared by /agent/act and /agent/run so both
  // open the AROP task through identical logic.
  const initiateArop = async (challenge: string, tool: string, invoiceId?: string, b: Binding = active) => {
    const challengeClaims = decodeClaims(challenge);
    const txn = challengeClaims.txn as string | undefined;
    const resource = challengeClaims.iss as string | undefined;
    const taskId = txn && resource ? txnTaskId(resource, txn) : undefined;
    if (taskId) {
      txnMissions.set(taskId, b.missionId);
      // Stash the challenge-derived detail keyed by taskId so the enriched queue
      // can show tool + invoice + digest for this pending approval.
      jitDetails.set(taskId, {
        tool,
        ...(invoiceId ? { invoice_id: invoiceId } : {}),
        ...(challengeClaims.parameter_digest ? { parameter_digest: challengeClaims.parameter_digest as string } : {}),
      });
    }
    const pending = await postTransaction(
      {
        transaction_challenge: challenge,
        subject_token: b.issued.accessToken,
        subject_token_type: "urn:ietf:params:oauth:token-type:access_token",
      },
      b,
    );
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
  installConsoleSessionBoundary(app, session);
  app.onError((err, c) => c.json({ error: err.message }, 500));
  app.notFound((c) => c.json({ error: "not found" }, 404));

  // Dashboard.
  const index = (c: Context) => c.html(readFileSync(INDEX, "utf8"));
  app.get("/", index);
  app.get("/index.html", index);
  // The story's revocation proof, an ES module the dashboard imports.
  app.get("/console-story.js", (c) =>
    c.body(readFileSync(STORY_MODULE, "utf8"), 200, { "content-type": "text/javascript; charset=utf-8" }));

  // Display-only label maps (single source of truth: demo/src/labels.ts). The
  // dashboard fetches these once to gloss machine ids with human names; no wire
  // value is derived from them.
  app.get("/labels", (c) => c.json({ tools: TOOL_LABELS, actions: ACTION_LABELS, reasons: REASON_LABELS }));

  // Console BFF (operator + approver personas).
  app.get("/bff/session", (c) => c.json({ sub: session.sub, roles: session.roles, csrf: session.csrf, missionId: active.missionId }));
  app.get("/bff/operator/fleet", (c) => c.json(stack.bff.fleet(session)));
  app.get("/bff/operator/missions/:id/timeline", async (c) => c.json(await stack.bff.timeline(session, c.req.param("id"))));
  // Demo only: rewrite one retained Execution Evidence record of the Mission
  // (its outcome, completed -> failed) behind the transparency log's back.
  // The log and receipts are untouched, so the timeline's five-step
  // verification fails that row.
  app.post("/bff/operator/missions/:id/tamper", async (c) => {
    const id = c.req.param("id");
    for (const row of await stack.bff.timeline(session, id)) {
      if (row.evidence_type !== "execution-evidence" || !row.verified) continue;
      const changes: Array<NonNullable<ReturnType<typeof rewriteExecutionOutcome>>> = [];
      stack.alterRetainedEvidence(row.digest, (ev) => {
        const change = rewriteExecutionOutcome(ev);
        if (change) changes.push(change);
      });
      if (changes[0]) return c.json({ digest: row.digest, evidence_type: row.evidence_type, change: changes[0] });
    }
    return c.json({ error: "no verified execution record to alter" }, 409);
  });
  app.post("/bff/operator/missions/:id/lifecycle", async (c) => {
    const body = await readJson(c);
    return c.json(stack.bff.lifecycle(session, c.req.param("id"), body.operation as never, session.csrf));
  });
  // Enriched approver queue (demo-assembled): JIT + parked mission approvals with
  // enough context per entry to decide (see enrichedQueue). Extends the shape the
  // console-bff method returns; the console-bff itself is untouched.
  app.get("/bff/approver/queue", (c) => c.json(enrichedQueue()));
  // @spec mission#approval-authentication (#826, D425) — the approver logs in
  // again: a new recorded login for the console (simulated; the shared demo
  // has no Approver identity provider). Adjudication never logs in, so a high-risk
  // approval more than the floor's age bound after the last login refuses
  // until this is called.
  app.post("/bff/approver/login", (c) => {
    logInAgain(stack.approverLogin, nowSeconds());
    return c.json(loginState());
  });
  // The approver's recorded login and the floor's age bound, so the approval
  // card can say when a fresh login is needed before it is refused.
  app.get("/bff/approver/login", (c) => c.json(loginState()));
  // Approver adjudicates EITHER a parked mission approval (approvalId in
  // missionApprovals) or a pending AROP/JIT task on the shared ARS.
  app.post("/bff/approver/adjudicate", async (c) => {
    const body = await readJson(c);
    const id = String(body.taskId ?? body.id ?? "");
    const decision = (body.decision as "approve" | "deny") ?? "deny";
    const rec = missionApprovals.get(id);
    if (rec) {
      // One decision per approval, however many requests arrive (the poll and
      // the queue button both refresh); see adjudicateMissionApproval.
      const approver = stack.authServer!.approverConsole;
      const result = await adjudicateMissionApproval(rec, decision, {
        floor: () => floorFor(rec.derived),
        // Approve: complete the interaction (decide -> code -> token). Only
        // now does the mission become a kernel record visible in the fleet.
        complete: () =>
          completeMissionApproval(asUrl, agentClientJwk, { uid: rec.submitted.uid, jar: rec.submitted.jar, par: rec.submitted.par }, approver),
        adopt: async (issuedMission) => {
          // The new Mission joins the agent's set and becomes the one it acts
          // under; the Missions it already held stay bound.
          active = await bind(issuedMission);
          const newId = active.missionId;
          // Active-mission swap: prior JIT continuation handles belong to the
          // OLD mission, so drop them (a stale /agent/retry must not execute
          // against the new mission). The frontend also guards its poll.
          txnHandles.clear();
          txnMissions.clear();
          publishedCounts.set(newId, stack.evidence.forMission(newId).length);
          await publishNew();
          return { missionId: newId, authority: stack.kernel.get(newId)?.authority_set ?? [] };
        },
        deny: () => denyMissionApproval(asUrl, { uid: rec.submitted.uid, jar: rec.submitted.jar }, approver),
      });
      return c.json(result.body, result.status);
    }
    // JIT/AROP task on the shared ARS.
    return c.json(await stack.bff.adjudicateTask(session, id, decision, session.csrf));
  });

  // Agent surface.
  app.get("/agent/catalog", (c) => c.json(stack.catalog.catalog("alice", { type: "mcp" })));

  // Which mission the agent currently acts under (Agent console binding).
  app.get("/agent/mission", (c) =>
    c.json({ missionId: active.missionId, authority: stack.kernel.get(active.missionId)?.authority_set ?? [] }));

  // Every Mission the agent holds, read from the kernel at request time: its
  // observed state, the approved and the effective Authority Set, the
  // Mission's own expiry, and the decoded claims of the access token bound to
  // it (never the token itself). Display only.
  app.get("/agent/missions", (c) =>
    c.json({
      active: active.missionId,
      missions: [...bindings.values()].map((b) => {
        const rec = stack.kernel.get(b.missionId);
        if (!rec) return { id: b.missionId, state: "unknown" };
        const observed = stack.kernel.applyExpiry(rec);
        const claims = decodeClaims(b.issued.accessToken);
        return {
          id: rec.id,
          goal: rec.intent.goal,
          state: observed.state,
          ...(observed.termination ? { termination: observed.termination } : {}),
          version: observed.version,
          subject: rec.subject.sub,
          approver: rec.approval_basis.consent_principal.sub,
          origin: rec.id === missionId || rec.id === reconciliation.missionId ? "seeded" : "approved",
          expires_at: rec.intent.expires_at,
          authority: rec.authority_set,
          effective: observed.state === "active" ? stack.kernel.effectiveAuthoritySet(observed) : [],
          token: {
            claims,
            expires_at: typeof claims.exp === "number" ? new Date(claims.exp * 1000).toISOString() : null,
            renewable: b.refreshToken !== undefined,
          },
        };
      }),
    }));

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
      expiresAt: (b.expiresAt as string) ?? defaultMissionExpiry(stack.kernel.nowDate()),
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
              parsed.target_resources,
            );
      derived = stack.kernel.derive(parsed, proposal) as unknown as AuthEntry[];
      proposed = (proposal ?? []) as unknown as AuthEntry[];
    } catch (e) {
      return c.json({ error: (e as Error).message }, 400);
    }
    const diff = proposalDiff(proposed, derived);
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
    let proposed: AuthEntry[];
    let derived: AuthEntry[];
    let missionIntent: string;
    try {
      const parsed = stack.kernel.validateIntent(semanticIntent);
      const proposal = authorizationDetails
        ? stack.kernel.validateProposal(authorizationDetails, parsed.target_resources)
        : undefined;
      derived = stack.kernel.derive(parsed, proposal) as unknown as AuthEntry[];
      proposed = (proposal ?? []) as unknown as AuthEntry[];
      goal = String((parsed as unknown as { goal?: unknown }).goal ?? "");
      missionIntent = JSON.stringify({ intent: parsed });
    } catch (e) {
      return c.json({ error: (e as Error).message }, 400);
    }
    let submitted: Awaited<ReturnType<typeof submitMissionApproval>>;
    try {
      submitted = await submitMissionApproval(asUrl, agentClientJwk, {
        missionIntent,
        ...(authorizationDetails ? { authorizationDetails } : {}),
      });
    } catch (e) {
      return c.json({ error: (e as Error).message }, 400);
    }
    const approvalId = `apv_${crypto.randomUUID()}`;
    missionApprovals.set(approvalId, {
      submitted,
      intent: missionIntent,
      goal,
      proposed,
      derived,
      diff: proposalDiff(proposed, derived),
      subject: "alice",
      state: "pending",
    });
    return c.json({ pending: true, approvalId, derived });
  });

  // Poll a parked mission approval: pending (awaiting the approver), active
  // (completed + swapped in, with its missionId), denied, or failed (a
  // decision that did not complete, with its error). `unknown` is a terminal
  // answer for an id the server no longer tracks (never a poll loop).
  app.get("/agent/approval-status", (c) => {
    const rec = missionApprovals.get(c.req.query("id") ?? "");
    if (!rec) return c.json({ state: "unknown" });
    return c.json({ state: rec.state, ...(rec.missionId ? { missionId: rec.missionId } : {}), ...(rec.error ? { error: rec.error } : {}) });
  });
  // Agent action: attempt a tool call and report the enforcement outcome. When
  // a gated action yields a transaction_challenge, the server redeems it at the
  // AS transaction endpoint on the agent's behalf, opening an approval task on
  // the shared ARS, and hands the pending txn back to the agent.
  app.post("/agent/act", async (c) => {
    // The Mission the action runs under: the one named, else the active one;
    // a named Mission the agent does not hold is refused (handleAgentAct).
    const result = await handleAgentAct(await readJson(c), {
      bindings,
      active,
      renew,
      invoke: (tool, args, b) =>
        TX_TOOLS.has(tool)
          ? stack.server.callTransactionTool(tool, args, b.facts, undefined, ACCEPT_CHALLENGE)
          : stack.server.callReadTool(tool, args, b.facts),
      report: async (tool, args, r, b, renewal) => {
        await publishNew(b.missionId);
        // Structured detail for the log renderer, ADDED alongside the existing
        // fields (ok/denial_reason/... stay for the JIT UI + /agent/retry contract).
        const detail = stepDetail(tool, args, r, b.missionId);
        const ch = r.transaction_challenge;
        if (!r.ok && ch) {
          // The ARS task id is derived from the challenge's issuer and txn (a
          // `txn` is unique within the resource), so the approver queue + retry
          // correlate on it while the client polls the AS by the continuation
          // handle. `arop` is spread AFTER `r` so its decoded challenge
          // overrides the raw one; `detail` carries no transaction_challenge or
          // taskId, so it never clobbers those.
          const arop = await initiateArop(ch, tool, args.invoice_id as string | undefined, b);
          return { ...r, ...arop, ...detail, ...(renewal ? { renewal } : {}) };
        }
        return { ...r, ...detail, ...(renewal ? { renewal } : {}) };
      },
    });
    return c.json(result.body, result.status);
  });
  // Agent retries a JIT-gated call after approval: poll the AS transaction
  // endpoint by the continuation handle for the txn-token, then re-present it to
  // the RS. The approval is carried by the AS-issued token, never a tool input.
  app.post("/agent/retry", async (c) => {
    const body = await readJson(c);
    const taskId = String(body.taskId);
    const tool = String(body.tool);
    // The retry carries the first attempt's key when the UI resends the step's
    // args; otherwise it is minted here (the challenged attempt claimed nothing).
    const args = keyed(tool, (body.args as Record<string, unknown>) ?? {});
    const handle = txnHandles.get(taskId);
    const task = stack.ars.getTask(taskId);
    if (!handle || !task || task.state === "pending") {
      return c.json({ ok: false, pending: true, state: task?.state ?? "unknown" });
    }
    // The retry presents the credential of the Mission the challenge was
    // opened under, and no other: with no Mission recorded, it is refused.
    const b = challengedBinding(taskId, txnMissions, bindings);
    if (!b) return c.json({ ok: false, error: "no Mission the agent holds is recorded for this approval task" }, 409);
    await renew(b);
    const issuedTxn = await postTransaction({ transaction_authorization_id: handle }, b);
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
    // @spec txn-authorization#transaction-token, #offline-verification step 2 —
    // the retry runs under the transaction token as its sole credential, never
    // alongside the base one, and over a REAL HTTP request: proof of possession
    // of the key the challenge committed to is not optional for this class.
    const r = await callWithTransactionCredential(
      stack.server,
      String(txnToken),
      b.issued.dpopKeys,
      tool,
      args,
    );
    if (!r.ok && r.refusal_reason?.startsWith("txn_")) txnHandles.delete(taskId);
    await publishNew(b.missionId);
    txnHandles.delete(taskId);
    txnMissions.delete(taskId);
    return c.json({ ...r, missionId: b.missionId });
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
    const renewal = await renew(active);
    for (const invoice_id of RUN_INVOICES) {
      const args = { invoice_id, idempotency_key: idem() };
      const r = await stack.server.callTransactionTool("execute_wire_transfer", args, active.facts, undefined, ACCEPT_CHALLENGE);
      await publishNew();
      steps.push(stepDetail("execute_wire_transfer", args, r, active.missionId));
    }
    // JIT-gated remittance on inv-1: initiate AROP exactly as /agent/act does and
    // STOP (no auto-approve). The paused step carries taskId + tool + args so the
    // UI can arm the existing retry button against the AROP task.
    const jitArgs = { invoice_id: "inv-1", idempotency_key: idem() };
    const jr = await stack.server.callTransactionTool("send_remittance_email", jitArgs, active.facts, undefined, ACCEPT_CHALLENGE);
    await publishNew();
    const jitDetail = stepDetail("send_remittance_email", jitArgs, jr, active.missionId);
    if (!jr.ok && jr.transaction_challenge) {
      const arop = await initiateArop(jr.transaction_challenge, "send_remittance_email", jitArgs.invoice_id);
      steps.push({ ...jitDetail, taskId: arop.taskId, transaction_authorization_id: arop.transaction_authorization_id });
    } else {
      steps.push(jitDetail);
    }
    return c.json({ steps, ...(renewal ? { renewal } : {}) });
  });

  serve({ fetch: app.fetch, port: PORT }, () => {
    console.log(`\nMission demo console (operator-only login link): http://localhost:${PORT}/#console-login=${session.id}`);
    console.log(`Seeded mission ${missionId} (subject alice, approver bob), one wire executed with evidence.`);
    console.log(`Seeded mission ${reconciliation.missionId} (read-only reconciliation), one read with evidence.`);
    console.log("Story mode walks the narrated run; the Request, Agent, Approver and Operator views stay open for exploring.\n");
  });
}

// @spec review #745 P1 — guarded so importing this module (e.g. the
// proposalDiff regression test) does not itself boot a real server: only run
// when this file is the process entrypoint (`tsx src/server.ts` /
// `pnpm demo:serve`), never on a plain import.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((e) => {
    console.error(e);
    process.exit(1);
  });
}
