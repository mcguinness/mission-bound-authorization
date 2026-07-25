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

const C = {
  dim: "\x1b[2m",
  green: "\x1b[32m",
  red: "\x1b[31m",
  cyan: "\x1b[36m",
  yellow: "\x1b[33m",
  magenta: "\x1b[35m",
  bold: "\x1b[1m",
  reset: "\x1b[0m",
};

/**
 * Minimal ANSI JSON syntax highlighter (dependency-free, matching the
 * exhibit's hand-rolled color style): keys cyan, string values green, numbers
 * yellow, booleans/null magenta; punctuation stays the terminal default.
 * Quoted strings are matched as whole tokens first, so digits or braces inside
 * a string are never recolored.
 */
function highlightJson(obj: unknown): string {
  const src = JSON.stringify(obj, null, 2);
  return src.replace(
    /"(?:\\.|[^"\\])*"(:)?|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?|\b(?:true|false|null)\b/g,
    (match: string, colon: string | undefined) => {
      if (colon !== undefined) {
        // a quoted string immediately followed by ':' is an object key
        const key = match.slice(0, -1);
        return `${C.cyan}${key}${C.reset}:`;
      }
      if (match[0] === '"') return `${C.green}${match}${C.reset}`;
      if (match === "true" || match === "false" || match === "null") return `${C.magenta}${match}${C.reset}`;
      return `${C.yellow}${match}${C.reset}`;
    },
  );
}

function step(n: number, title: string) {
  console.log(`\n${C.bold}${C.cyan}${"─".repeat(3)} [${n}] ${title} ${"─".repeat(Math.max(0, 60 - title.length))}${C.reset}`);
}
function block(label: string, obj: unknown) {
  console.log(`${C.dim}${label}:${C.reset}`);
  console.log(
    highlightJson(obj)
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
  const issued = await issueMissionToken(asUrl, as.agentClientJwk, { missionIntent, scope: "openid profile email payments" });

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
    ...(idt.name ? { name: idt.name } : {}),
    ...(idt.preferred_username ? { preferred_username: idt.preferred_username } : {}),
    ...(idt.email ? { email: idt.email } : {}),
    ...(idt.auth_time ? { auth_time: idt.auth_time } : {}),
    iat: idt.iat,
    exp: idt.exp,
  });
  note("aud = client_id ap-agent: the id_token identifies the USER to the client (name/email from the identity store), distinct from the resource-audienced access token.");

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

  // ---- 7. JIT access via AROP Transaction Challenge ----------------------
  step(7, "JIT access: an in-mission action, gated behind a per-action approval (AROP)");
  note("send_remittance_email is WITHIN the mission's authority, but deployment policy requires an action-bound approval, resolved just-in-time over real HTTP.");

  // 7.1 Base token, no txn-token: the RS gates the action and returns an
  // access_challenge (an rs-txn-signed txn-challenge + the AS endpoint for it).
  block("MCP tools/call — send_remittance_email (base token, no txn-token)", {
    tool: "send_remittance_email",
    arguments: { invoice_id: "inv-1" },
    authorization: "DPoP <real mission-bound access token>",
  });
  const challengeAttempt = await stack.server.callTransactionTool("send_remittance_email", { invoice_id: "inv-1" }, facts);
  verdict(challengeAttempt.ok, `send_remittance_email(inv-1) → ${challengeAttempt.denial_reason ?? challengeAttempt.refusal_reason}`);
  const accessChallenge = challengeAttempt.access_challenge;
  if (!accessChallenge) throw new Error("expected an access_challenge (RS challengeSigner wired)");
  note(`RS emitted a txn-challenge to present to ${accessChallenge.txn_endpoint}`);
  block("access_challenge — protected header", decodeHeader(accessChallenge.challenge));
  block("access_challenge — decoded txn-challenge", decodeClaims(accessChallenge.challenge));

  // 7.2 Agent POSTs the challenge to the AS transaction endpoint over HTTP ONCE
  // (initiation), authenticating with its base mission token (DPoP). The AS
  // mints an opaque continuation handle (transaction_authorization_id) bound to
  // the validated challenge; the client polls WITH that handle from here on.
  // A fresh DPoP proof per call binds htu=/transaction, htm=POST to the base
  // token's cnf.jkt.
  const postTxn = async (payload: Record<string, unknown>) =>
    fetch(accessChallenge.txn_endpoint, {
      method: "POST",
      headers: {
        authorization: `DPoP ${issued.accessToken}`,
        dpop: await dpopProofFor(issued.dpopKeys, accessChallenge.txn_endpoint, "POST"),
        "content-type": "application/json",
      },
      body: JSON.stringify(payload),
    });
  block(`POST ${accessChallenge.txn_endpoint} (initiation: base token DPoP + challenge, presented ONCE)`, {
    authorization: "DPoP <real mission-bound access token>",
    dpop: "<DPoP proof: htu=/transaction, htm=POST>",
    body: { challenge: `${accessChallenge.challenge.slice(0, 40)}... (the txn-challenge above)` },
  });
  const pendingRes = await postTxn({ challenge: accessChallenge.challenge });
  const pendingBody = (await pendingRes.json()) as {
    transaction_authorization_id?: string;
    expires_in?: number;
    interval?: number;
  };
  block(`transaction response (${pendingRes.status}) — pending`, pendingBody);
  const txaId = pendingBody.transaction_authorization_id;
  if (!txaId) {
    throw new Error(`expected a transaction_authorization_id, got ${JSON.stringify(pendingBody)}`);
  }
  note(
    `the transaction_authorization_id is the AS's continuation handle, bound to the validated challenge; the client ` +
      `presents the challenge only once and polls with this handle (expires_in=${pendingBody.expires_in}s, interval=${pendingBody.interval}s).`,
  );

  // 7.3 Approver (Bob) adjudicates the AS-vouched task on the SAME ARS the AS
  // opened it on (distinct from the acting subject alice).
  block("ARS approver queue (task opened by the AS transaction endpoint)", stack.ars.pending());
  const pendingTask = stack.ars.pending()[0];
  if (!pendingTask) throw new Error("expected a pending AROP task on the shared ARS");
  const approval = await stack.ars.adjudicate(pendingTask.id, "approve", "bob");
  if (!approval) throw new Error("expected an approval object");
  block("action-bound approval (ARS mints it, scoped to the parameter_digest)", approval);

  // 7.4 Agent POLLS the transaction endpoint WITH the handle (fresh DPoP proof),
  // never re-presenting the challenge. Now the AS issues the txn-token: ACTIVE
  // mission unchanged (D42), carrying the verified approval + cnf(base jkt),
  // single-use.
  block(`POST ${accessChallenge.txn_endpoint} (poll: base token DPoP + transaction_authorization_id)`, {
    authorization: "DPoP <real mission-bound access token>",
    dpop: "<DPoP proof: htu=/transaction, htm=POST>",
    body: { transaction_authorization_id: txaId },
  });
  const tokenRes = await postTxn({ transaction_authorization_id: txaId });
  const tokenBody = (await tokenRes.json()) as { access_token?: string; token_type?: string; txn?: string };
  block(`transaction response (${tokenRes.status})`, {
    ...tokenBody,
    ...(tokenBody.access_token ? { access_token: truncTok(tokenBody.access_token) } : {}),
  });
  const txnToken = tokenBody.access_token;
  if (!txnToken) throw new Error("expected a txn-token from the transaction endpoint");
  const txnClaims = decodeClaims(txnToken);
  block("txn-token — protected header", decodeHeader(txnToken));
  block("txn-token — decoded claims", {
    txn: txnClaims.txn,
    mission: txnClaims.mission,
    authorization_details: txnClaims.authorization_details,
    approval: txnClaims.approval,
    cnf: txnClaims.cnf,
    single_use: txnClaims.single_use,
  });
  note(
    `mission.id == active mission ${missionId} (unchanged, D42); approval.parameter_digest carries the gated operation; ` +
      `cnf.jkt ${(txnClaims.cnf as { jkt: string }).jkt === issued.dpopJkt ? "==" : "!="} base token jkt; single_use=${txnClaims.single_use}.`,
  );

  // 7.5 Agent re-calls the RS tool WITH the txn-token (5th arg, no approval
  // object anywhere). The RS validates it and derives the approval; the
  // UNCHANGED PDP step 8 permits and the operation commits.
  block("MCP tools/call — send_remittance_email (re-present, carrying the txn-token)", {
    tool: "send_remittance_email",
    arguments: { invoice_id: "inv-1" },
    authorization: "DPoP <real mission-bound access token>",
    txn_token: truncTok(txnToken),
  });
  const granted = await stack.server.callTransactionTool("send_remittance_email", { invoice_id: "inv-1" }, facts, undefined, txnToken);
  if (captured) block("PDP decision (permit: token-derived approval matched parameter_digest)", captured.decision);
  verdict(granted.ok, `send_remittance_email(inv-1) → ${granted.ok ? JSON.stringify(granted.result) : (granted.denial_reason ?? granted.refusal_reason)}`);
  note("The approval was carried by the AS-issued txn-token, never as a tool input. The mission was never widened; the gate sat inside the mission's authority.");

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
