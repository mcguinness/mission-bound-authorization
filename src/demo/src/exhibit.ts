/**
 * Terminal exhibit (O-28): a detailed, narrated protocol trace of the Mission
 * lifecycle driven against a REAL authorization server. It performs genuine
 * OAuth issuance (PAR -> authorize -> approve -> token) to mint a real
 * access_token AND id_token, validates the token at the resource server, runs
 * the full tool-call path (PEP -> PDP -> OpenFGA), crosses domains via an
 * ID-JAG grant into the LedgerCloud (SaaS) estate, and then drives the mission
 * lifecycle (suspend/resume, expansion/supersession, revocation). Every
 * request and response below is the real value on the wire. `pnpm exhibit`.
 */

import { createExpansion, successorWidensOnly, validateMissionIntent } from "@mission/authorization-server";
import { CANONICAL_RESOURCE, DEV_SERVICE_TOKEN, TOPOLOGY } from "@mission/demo-data";
import { SAAS_RESOURCE } from "@mission/mcp-saas";
import type { TokenFacts } from "@mission/mcp-payments";
import type { Decision, EvaluationRequest } from "@mission/pdp";
import { composeStack } from "./stack.js";
import { dpopProofFor, issueMissionToken } from "./oauth-client.js";

const C = { dim: "\x1b[2m", green: "\x1b[32m", red: "\x1b[31m", cyan: "\x1b[36m", yellow: "\x1b[33m", bold: "\x1b[1m", reset: "\x1b[0m" };

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

/** Decode a compact JWS payload (base64url) without verifying. */
function decodeClaims(jwt: string): Record<string, unknown> {
  return JSON.parse(Buffer.from(jwt.split(".")[1] as string, "base64url").toString());
}
/** Decode a compact JWS protected header. */
function decodeHeader(jwt: string): Record<string, unknown> {
  return JSON.parse(Buffer.from(jwt.split(".")[0] as string, "base64url").toString());
}
/** Print a compact token with the signature truncated (still a real value). */
function truncTok(jwt: string): string {
  const parts = jwt.split(".");
  return `${parts[0]}.${parts[1]}.${(parts[2] ?? "").slice(0, 12)}...`;
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
  const as = stack.authServer;
  const asUrl = as.asUrl;

  // Capture the AuthZEN envelope + PDP decision the PEP actually built.
  let captured: { envelope: EvaluationRequest; decision: Decision; effective?: unknown } | undefined;
  stack.onEnforce((e) => {
    captured = { envelope: e.envelope, decision: e.decision, ...(e.effective ? { effective: e.effective } : {}) };
  });

  console.log(`${C.bold}Mission-Bound Authorization — protocol exhibit${C.reset}`);
  console.log(`${C.dim}Real OAuth issuance against a live AS at ${asUrl}. Every artifact below is the real value on the wire.${C.reset}`);

  // ---- 0. Discovery -------------------------------------------------------
  step(0, "Discovery: the agent asks what it can reach");
  note(`GET ${asUrl}/service-catalog?type=mcp   (access token audience = catalog)`);
  block("catalog response (before any mission)", stack.catalog.catalog("alice", { type: "mcp" }));
  note("payments is consent_required: reachable, but no mission covers it yet.");

  // ---- 1. Intent shaping (untrusted, two-estate proposal) -----------------
  step(1, "Intent shaping: a two-estate proposal (untrusted)");
  const missionIntent = JSON.stringify({
    goal: "Pay approved Acme invoices for Q3 and post the corresponding ledger entries",
    resources: [CANONICAL_RESOURCE, SAAS_RESOURCE],
    expires_at: "2027-01-01T00:00:00Z",
    proposed_authority: [
      {
        // Payments estate: deliberately over-broad (bogus action, extra vendors, huge cap).
        type: "mission_resource_access",
        resource: CANONICAL_RESOURCE,
        actions: ["payments:invoice.read", "payments:payment.execute", "payments:remittance.send", "payments:vendor.delete"],
        constraints: { max_amount: { amount: "999999.00", currency: "USD" }, vendors: ["acme", "globex", "evilcorp"] },
      },
      {
        // Cross-domain SaaS (LedgerCloud) estate.
        type: "mission_resource_access",
        resource: SAAS_RESOURCE,
        actions: ["ledger:vendor.read", "ledger:journal.write"],
      },
    ],
  });
  block("mission_intent (submitted via PAR, mission_intent parameter)", JSON.parse(missionIntent));
  note("This is a proposal. Nothing here grants authority; the issuer derives and bounds it at approval.");

  // ---- 2. REAL issuance: PAR -> authorize -> approve -> token --------------
  step(2, "Real issuance: the live OAuth dance mints a real token pair");
  const issued = await issueMissionToken(asUrl, as.agentClientJwk, { missionIntent, scope: "openid payments" });

  block("PAR request (POST /request, form-encoded, private_key_jwt)", {
    ...issued.artifacts.par.request,
    mission_intent: `${missionIntent.slice(0, 60)}... (full proposal in step 1)`,
  });
  block("PAR response (201 Created)", issued.artifacts.par.response);

  note("GET /auth redirects to /interaction/{uid}; Bob approves alice at the headless consent.");
  block("interaction/decide request (POST /interaction/{uid}/decide)", issued.artifacts.decide.request);
  note(`authorization code issued: ${issued.artifacts.decide.code.slice(0, 14)}...`);

  block("token request (POST /token, DPoP-bound + private_key_jwt)", issued.artifacts.token.request);
  const tokRes = issued.artifacts.token.response;
  block("token response (200)", {
    ...tokRes,
    access_token: truncTok(tokRes.access_token as string),
    ...(tokRes.id_token ? { id_token: truncTok(tokRes.id_token as string) } : {}),
    ...(tokRes.refresh_token ? { refresh_token: `${String(tokRes.refresh_token).slice(0, 12)}...` } : {}),
  });

  if (!issued.idToken) throw new Error("expected an id_token from scope=openid");
  const at = decodeClaims(issued.accessToken);
  const idt = decodeClaims(issued.idToken);
  block("REAL access token — decoded claims", {
    iss: at.iss,
    sub: at.sub,
    aud: at.aud,
    cnf: at.cnf,
    mission: at.mission,
    authorization_details: at.authorization_details,
  });
  note("aud = CANONICAL_RESOURCE (resource-audienced); cnf.jkt DPoP-binds the token; authorization_details spans BOTH estates (payments + SaaS).");
  block("REAL id_token — decoded claims", {
    iss: idt.iss,
    sub: idt.sub,
    aud: idt.aud,
    ...(idt.auth_time ? { auth_time: idt.auth_time } : {}),
    iat: idt.iat,
    exp: idt.exp,
  });
  note("aud = client_id ap-agent: the id_token identifies the USER to the client, distinct from the resource-audienced access token.");

  const missionId = (at.mission as { id: string }).id;
  const record = stack.kernel.get(missionId);
  if (!record) throw new Error("mission record not found for issued token");
  block("derived Mission Record (issuer output)", {
    id: record.id,
    state: record.state,
    subject: record.subject,
    approver: record.approver,
    policy_version: record.policy_version,
    intent_hash: record.intent_hash,
    authority_hash: record.authority_hash,
    expires_at: record.expires_at,
  });
  block("derived Authority Set (bounded by the policy ceiling)", record.authority_set);
  console.log(
    `${C.yellow}  narrowing:${C.reset} proposed payments:vendor.delete ${C.red}dropped${C.reset}; ` +
      `vendors acme,globex,evilcorp ${C.green}→ acme${C.reset}; cap 999999.00 ${C.green}→ 500.00${C.reset} (SaaS estate preserved)`,
  );
  note("subject alice != approver bob (write-bearing missions need a distinct approver).");

  block("raw access_token (compact JWS, signature truncated)", truncTok(issued.accessToken));
  block("raw id_token (compact JWS, signature truncated)", truncTok(issued.idToken));

  // ---- 3. Validate the real token at the resource server ------------------
  step(3, "Validate the real token at the resource server");
  note(`RS-side DPoP proof: same DPoP key as the token, htu=${CANONICAL_RESOURCE}, htm=POST.`);
  const rsProof = await dpopProofFor(issued.dpopKeys, CANONICAL_RESOURCE, "POST");
  let facts: TokenFacts = await stack.server.validateToken(issued.accessToken, rsProof, CANONICAL_RESOURCE, "POST");
  // Augment with the client instance id for a richer actor in the envelope.
  facts = { ...facts, clientInstanceId: "inst-ap-agent-01" };
  note("verified: JWT signature via AS /jwks, DPoP proof jkt == token cnf.jkt, mission claim present.");
  block("TokenFacts (drives every payments tool call below)", facts);

  // ---- 4. Discovery again -------------------------------------------------
  step(4, "Discovery again: the catalog now reflects the active mission");
  block(
    "catalog payments connection",
    stack.catalog.catalog("alice", { type: "mcp" }).services.find((s) => s.id === "payments")?.connections,
  );

  // ---- Tool-call tracer (real token) --------------------------------------
  const traceCall = async (n: number, label: string, kind: "read" | "wire", tool: string, args: Record<string, unknown>) => {
    step(n, label);
    block(`MCP tools/call — ${tool}`, { tool, arguments: args, authorization: "DPoP <real mission-bound access token>" });
    const res =
      kind === "read" ? await stack.server.callReadTool(tool, args, facts) : await stack.server.callTransactionTool(tool, args, facts);
    if (captured) {
      note("PEP builds the AuthZEN decision request (effective params from authoritative store state):");
      if (captured.effective) block("  effective parameters", captured.effective);
      block("PDP request (AuthZEN envelope)", captured.envelope);
      block("PDP decision", captured.decision);
    }
    verdict(res.ok, `${tool} → ${res.ok ? JSON.stringify(res.result) : (res.denial_reason ?? res.refusal_reason)}`);
    return res;
  };

  // ---- 5. Read tool -------------------------------------------------------
  await traceCall(5, "Read tool call — in-authority (get_invoice)", "read", "get_invoice", { invoice_id: "inv-1" });
  // ---- 6. Wire transfer ---------------------------------------------------
  await traceCall(6, "Wire transfer — transaction-assurance tier (execute_wire_transfer)", "wire", "execute_wire_transfer", {
    invoice_id: "inv-1",
  });

  // ---- 7. JIT access via ARAP --------------------------------------------
  step(7, "JIT access: an in-mission action, gated behind a per-action approval (ARAP)");
  note("send_remittance_email is WITHIN the mission's authority, but deployment policy requires an action-bound approval, resolved just-in-time.");

  // Attempt 1: no approval → the PDP denies action_approval_required and
  // marks the denial requestable (a signed binding + the ARS intake endpoint).
  block("MCP tools/call — send_remittance_email (first attempt, no approval)", {
    tool: "send_remittance_email",
    arguments: { invoice_id: "inv-1" },
    authorization: "DPoP <real mission-bound access token>",
  });
  const attempt = await stack.server.callTransactionTool("send_remittance_email", { invoice_id: "inv-1" }, facts);
  if (captured) {
    block("PDP request (AuthZEN envelope)", captured.envelope);
    block("PDP decision (requestable: approval required)", captured.decision);
  }
  verdict(attempt.ok, `send_remittance_email(inv-1) → ${attempt.denial_reason ?? attempt.refusal_reason}`);
  const denial = attempt.access_request;
  const digest = captured?.decision.context.parameter_digest as string;
  if (!denial) throw new Error("expected a requestable denial with an access_request");
  block("requestable denial → access_request (ARAP intake)", denial);

  // The agent submits an access request to the ARS: a distinct trusted-base
  // component (not the PDP) that verifies the PDP-signed denial binding.
  note("Agent submits an access request to the ARS; the ARS verifies the PDP-signed denial binding before it opens a task.");
  const submitted = await stack.ars.submit({
    binding_token: denial.binding_token,
    requested: { action: "payments:remittance.send", mission_id: missionId, parameter_digest: digest, subject: "alice" },
  });
  note(`ARS task ${submitted.taskId} → ${submitted.state}`);
  block("ARS approver queue", stack.ars.pending());

  // Bob adjudicates (distinct from the acting subject alice). On approval the
  // ARS mints an action-bound approval object, scoped to this parameter_digest.
  const approval = await stack.ars.adjudicate(submitted.taskId, "approve", "bob");
  if (!approval) throw new Error("expected an approval object");
  block("action-bound approval (ARAP reevaluate: input context, NOT a bearer grant)", approval);

  // Attempt 2: retry the SAME tool call, now carrying the approval as
  // context.action_approval. The PDP re-evaluates; no new token is issued.
  const approvalCtx = { id: approval.id, approved_at: approval.approved_at, parameter_digest: approval.parameter_digest };
  block("MCP tools/call — send_remittance_email (retry with approval context)", {
    tool: "send_remittance_email",
    arguments: { invoice_id: "inv-1" },
    context: { action_approval: approvalCtx },
  });
  const granted = await stack.server.callTransactionTool("send_remittance_email", { invoice_id: "inv-1" }, facts, undefined, approvalCtx);
  if (captured) block("PDP decision (permit: approval matched parameter_digest, within max age)", captured.decision);
  verdict(granted.ok, `send_remittance_email(inv-1) → ${granted.ok ? JSON.stringify(granted.result) : (granted.denial_reason ?? granted.refusal_reason)}`);
  note("The mission was never widened. The JIT approval satisfied a per-action gate that already sat inside the mission's authority.");

  // ---- 8. Cross-domain: the ID-JAG leg into the SaaS estate ---------------
  step(8, "Cross-domain: an ID-JAG grant crosses into the LedgerCloud (SaaS) estate");
  const grant = await as.issueCrossDomainGrant(missionId, issued.dpopJkt);
  block("ID-JAG grant — protected header", decodeHeader(grant.grant));
  block("ID-JAG grant — decoded payload", decodeClaims(grant.grant));
  note(`audience-scoped: authorization_details carries ONLY the SaaS estate; aud = the RAS issuer (${as.rasIssuer}); cnf.jkt binds the same DPoP key.`);

  const redeemed = await as.ras.redeem(grant.grant, issued.dpopJkt);
  block("RAS local token — decoded claims", decodeClaims(redeemed.access_token));
  note(`the RAS minted a LOCAL token (iss = ${as.rasIssuer}, aud = ${as.saasResource}); the SaaS PEP enforces from this token alone (token-only, no PDP).`);

  const saasDpop = await dpopProofFor(issued.dpopKeys, as.saasResource, "POST");
  block("MCP tools/call — post_journal_entry (SaaS estate)", {
    tool: "post_journal_entry",
    arguments: { vendor_id: "acme", amount: "125.00" },
    authorization: "DPoP <RAS local token>",
  });
  const saasCall = await as.saas.callTool("post_journal_entry", { vendor_id: "acme", amount: "125.00" }, redeemed.access_token, saasDpop);
  block("SaaS tool result", saasCall);
  verdict(saasCall.ok, `post_journal_entry(acme, $125.00) → ${saasCall.ok ? JSON.stringify(saasCall.result) : saasCall.error}`);

  // Replay: the ID-JAG grant is single-use (one-time jti).
  let replayFailed = false;
  try {
    await as.ras.redeem(grant.grant, issued.dpopJkt);
  } catch (e) {
    replayFailed = true;
    const code = (e as { code?: string }).code ?? "error";
    block("replay rejected", { error: code, message: (e as Error).message });
    verdict(false, `second redemption of the SAME grant → ${code} (single-use)`);
  }
  if (!replayFailed) throw new Error("expected the ID-JAG replay to fail invalid_grant");

  // ---- 9. Denials ---------------------------------------------------------
  step(9, "Denials: valid token, but out of bounds / authority");
  const over = await stack.server.callTransactionTool("execute_wire_transfer", { invoice_id: "inv-2" }, facts);
  if (captured) block("PDP decision (over-cap $900)", captured.decision);
  verdict(over.ok, `execute_wire_transfer(inv-2, $900) → ${over.denial_reason ?? over.refusal_reason}`);
  const globex = await stack.server.callTransactionTool("execute_wire_transfer", { invoice_id: "inv-3" }, facts);
  if (captured) block("PDP decision (globex vendor)", captured.decision);
  verdict(globex.ok, `execute_wire_transfer(inv-3, globex) → ${globex.denial_reason ?? globex.refusal_reason}`);

  // ---- 10. Lifecycle ------------------------------------------------------
  // MUST run AFTER the cross-domain leg and all tool calls: these transitions
  // drive the mission non-active / superseded and deny everything downstream.
  step(10, "Lifecycle: transitions that gate everything downstream");
  const lifecycle = async (operation: string, id: string): Promise<unknown> => {
    const res = await fetch(`${asUrl}/missions/${id}/lifecycle`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-service-token": DEV_SERVICE_TOKEN },
      body: JSON.stringify({ operation }),
    });
    return res.json();
  };

  // 10a. suspend -> the next action is denied (mission not active).
  block("lifecycle request — suspend (POST /missions/{id}/lifecycle)", { operation: "suspend", mission: missionId });
  block("lifecycle response", await lifecycle("suspend", missionId));
  const whileSuspended = await stack.server.callReadTool("get_invoice", { invoice_id: "inv-1" }, facts);
  if (captured) block("PDP decision (suspended)", captured.decision);
  verdict(whileSuspended.ok, `get_invoice(inv-1) while suspended → ${whileSuspended.denial_reason ?? whileSuspended.refusal_reason}`);

  // 10b. resume -> the action is permitted again.
  block("lifecycle request — resume", { operation: "resume", mission: missionId });
  block("lifecycle response", await lifecycle("resume", missionId));
  const afterResume = await stack.server.callReadTool("get_invoice", { invoice_id: "inv-1" }, facts);
  if (captured) block("PDP decision (resumed)", captured.decision);
  verdict(afterResume.ok, `get_invoice(inv-1) after resume → ${afterResume.ok ? JSON.stringify(afterResume.result) : (afterResume.denial_reason ?? afterResume.refusal_reason)}`);

  // 10c. Expansion: a successor mission from a fresh approval that widens authority.
  // The cap is already at the policy ceiling (500), so the widening is on ACTIONS:
  // payments:payment.schedule is added (in the ceiling, absent from the predecessor).
  const predecessor = stack.kernel.get(missionId);
  if (!predecessor) throw new Error("predecessor mission missing");
  const successorIntent = validateMissionIntent(
    JSON.stringify({
      goal: "Pay approved Acme invoices for Q3 (expanded: also schedule payments)",
      resources: [CANONICAL_RESOURCE, SAAS_RESOURCE],
      expires_at: "2027-01-01T00:00:00Z",
      proposed_authority: [
        {
          type: "mission_resource_access",
          resource: CANONICAL_RESOURCE,
          actions: ["payments:invoice.read", "payments:payment.execute", "payments:remittance.send", "payments:payment.schedule"],
          constraints: { max_amount: { amount: "999999.00", currency: "USD" }, vendors: ["acme"] },
        },
        {
          type: "mission_resource_access",
          resource: SAAS_RESOURCE,
          actions: ["ledger:vendor.read", "ledger:journal.write"],
        },
      ],
    }),
  );
  const expansion = createExpansion(stack.kernel, {
    predecessorId: missionId,
    intent: successorIntent,
    approver: { iss: asUrl, sub: "bob" },
    approvalEventId: "apev-exhibit-successor",
    approvedUntil: "2027-01-01T00:00:00Z",
  });
  block("successor Mission Record (fresh approval, widened authority)", {
    id: expansion.successor.id,
    state: expansion.successor.state,
    predecessor: expansion.successor.predecessor,
    subject: expansion.successor.subject,
    approver: expansion.successor.approver,
    authority_hash: expansion.successor.authority_hash,
    expires_at: expansion.successor.expires_at,
  });
  block("predecessor authority actions", predecessor.authority_set.flatMap((e) => e.actions));
  block("successor authority actions (bounded by the SAME ceiling)", expansion.successor.authority_set.flatMap((e) => e.actions));
  note(
    `successorWidensOnly = ${successorWidensOnly(predecessor.authority_set, expansion.successor.authority_set)}: ` +
      "all predecessor actions retained, +payments:payment.schedule. Cap stays 500 (already at ceiling); the widening is on actions.",
  );

  // Supersession: on the successor's first redemption the predecessor is superseded atomically.
  stack.kernel.supersedeOnRedemption(expansion.successor.id);
  note(`predecessor ${missionId} state → ${stack.kernel.get(missionId)?.state}`);
  const afterSupersede = await stack.server.callReadTool("get_invoice", { invoice_id: "inv-1" }, facts);
  if (captured) block("PDP decision (predecessor superseded)", captured.decision);
  verdict(afterSupersede.ok, `get_invoice(inv-1) with the original token → ${afterSupersede.denial_reason ?? afterSupersede.refusal_reason}`);
  note("the original credential no longer authorizes; the successor is the active mission going forward.");

  // 10d. revoke the successor over the wire.
  block("lifecycle request — revoke (successor)", { operation: "revoke", mission: expansion.successor.id });
  block("lifecycle response", await lifecycle("revoke", expansion.successor.id));

  // ---- 11. Evidence -------------------------------------------------------
  step(11, "Evidence: the tamper-evident feed, verified");
  for (const ev of stack.evidence.forMission(missionId)) {
    const t = ev.kind === "decision" ? "decision-evidence" : ev.kind === "execution" ? "execution-evidence" : "refusal-record";
    await stack.publishEvidence(missionId, t, ev as unknown as Record<string, unknown>);
  }
  const op = stack.bff.sessions.create("olivia", ["operator"]);
  for (const row of await stack.bff.timeline(op, missionId)) {
    console.log(`  ${row.verified ? C.green + "✓ VERIFIED" : C.red + "✗ FAILED  "}${C.reset} ${row.evidence_type} ${C.dim}from ${row.producer}${C.reset}`);
  }

  console.log(
    `\n${C.green}${C.bold}Exhibit complete.${C.reset} ${C.dim}Real issuance (access + id token), RS validation, tool calls, cross-domain ID-JAG, lifecycle, and evidence — all on the wire.${C.reset}`,
  );
  as.closeAuthServer();
  process.exit(0);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
