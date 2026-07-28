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

import { createExpansion, DEFERRED_GRANT_TYPE, successorWidensOnly, validateMissionIntent } from "@mission/authorization-server";
import { CANONICAL_RESOURCE, DEV_SERVICE_TOKEN, TOPOLOGY } from "@mission/demo-data";
import { SAAS_RESOURCE } from "@mission/mcp-saas";
import type { TokenFacts } from "@mission/mcp-payments";
import type { Decision, EvaluationRequest } from "@mission/pdp";
import { composeStack } from "./stack.js";
import { dpopProofFor, issueMissionToken, tokenGrantRequest } from "./oauth-client.js";

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

/** HTTP status reason phrases for the request/response renderer. */
const REASON: Record<number, string> = {
  200: "OK",
  201: "Created",
  302: "Found",
  400: "Bad Request",
  401: "Unauthorized",
};

/**
 * A protocol hop: WHO → WHO, over WHICH endpoint, and whether it is on the wire.
 * Printed at the start of each step's action so the whole exhibit reads as an
 * annotated sequence of exchanges. `mode` is the bracketed annotation, e.g.
 * "HTTP", "in-process MCP · O-33", "in-process · D28".
 */
function hop(from: string, to: string, endpoint: string, mode: string) {
  console.log(
    `\n  ${C.magenta}${C.bold}${from}${C.reset}${C.magenta} → ${C.bold}${to}${C.reset}` +
      `  ${C.magenta}${endpoint}${C.reset}  ${C.dim}[${mode}]${C.reset}`,
  );
}

/** Render a real HTTP request as a wire exchange (method, URL, key headers, body). */
function httpReq(method: string, url: string, opts: { headers?: Record<string, string>; body?: unknown } = {}) {
  console.log(`  ${C.cyan}→ ${C.bold}${method}${C.reset}${C.cyan} ${url}${C.reset}`);
  if (opts.headers && Object.keys(opts.headers).length > 0) {
    console.log(`    ${C.dim}headers:${C.reset} ${Object.entries(opts.headers).map(([k, v]) => `${k}: ${v}`).join("; ")}`);
  }
  if (opts.body !== undefined) {
    console.log(`    ${C.dim}body:${C.reset}`);
    console.log(
      highlightJson(opts.body)
        .split("\n")
        .map((l) => `    ${l}`)
        .join("\n"),
    );
  }
}

/**
 * Render a real HTTP response: status + reason, an optional headers block (used
 * for 3xx legs, which carry a Location header and no body), and a JSON body.
 */
function httpRes(status: number, body?: unknown, opts: { headers?: Record<string, string> } = {}) {
  console.log(`  ${C.cyan}← ${C.bold}${status}${REASON[status] ? ` ${REASON[status]}` : ""}${C.reset}`);
  if (opts.headers && Object.keys(opts.headers).length > 0) {
    console.log(`    ${C.dim}headers:${C.reset} ${Object.entries(opts.headers).map(([k, v]) => `${k}: ${v}`).join("; ")}`);
  }
  if (body !== undefined) {
    console.log(
      highlightJson(body)
        .split("\n")
        .map((l) => `    ${l}`)
        .join("\n"),
    );
  }
}

/** The cast of actors + which hops are on the wire vs in-process in this demo. */
function legend(asUrl: string) {
  const row = (role: string, endpoint: string, mode: string) =>
    console.log(`  ${C.bold}${C.cyan}${role.padEnd(19)}${C.reset}${C.dim}${endpoint.padEnd(38)}${C.reset}${C.dim}${mode}${C.reset}`);
  console.log(`\n${C.bold}Cast & wire${C.reset} ${C.dim}— [HTTP] hops are on the wire; [in-process] hops run inside this demo process.${C.reset}`);
  row("Agent", "ap-agent OAuth client", "drives issuance + tool calls");
  row("AS", asUrl, "[HTTP]");
  row("Payments RS", "mcp://payments → localhost:4403/mcp", "[in-process · MCP transport = prod swap, O-33]");
  row("PDP", "pure decision function", "[in-process · D28]");
  row("OpenFGA", "https://localhost:8080", "[HTTP · the PDP's authority store]");
  row("ARS", "Access Request Service", "[in-process · opens/adjudicates AROP tasks]");
  row("RAS", "https://ras.ledgercloud.test", "[in-process · redeems the ID-JAG grant]");
  row("SaaS RS", "http://localhost:4406/mcp", "[in-process · token-only PEP, no PDP]");
  row("Transparency", "tamper-evident evidence log", "[in-process]");
  row("Approver (Bob)", "human — adjudicates per-action approvals", "");
  row("Operator (Olivia)", "human — drives lifecycle + reads evidence", "");
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
  legend(asUrl);

  // ---- 0. Discovery -------------------------------------------------------
  step(0, "Discovery: the agent asks what it can reach");
  hop("Agent", "AS", "GET /service-catalog?type=mcp", `in-process; represents GET ${asUrl}/service-catalog`);
  note("access token audience = catalog");
  block("catalog response (before any mission)", stack.catalog.catalog("alice", { type: "mcp" }));
  note("payments is consent_required: reachable, but no mission covers it yet.");

  // ---- 1. Intent shaping (untrusted, two-estate proposal) -----------------
  step(1, "Intent shaping: a two-estate proposal (untrusted)");
  hop("Agent", "Agent (self)", "compose mission_intent", "in-process; submitted via PAR in step 2");
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

  // PAR (Agent → AS, real HTTP): push the request carrying the mission_intent.
  hop("Agent", "AS", "POST /request", "HTTP");
  httpReq("POST", `${asUrl}/request`, {
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: {
      ...issued.artifacts.par.request,
      mission_intent: `${missionIntent.slice(0, 60)}... (full proposal in step 1)`,
      client_assertion: "<private_key_jwt>",
    },
  });
  httpRes(201, issued.artifacts.par.response);

  // Authorize (Agent → AS, real HTTP): 302 to the headless interaction.
  hop("Agent", "AS", "GET /auth", "HTTP");
  httpReq("GET", `${asUrl}/auth?client_id=ap-agent&request_uri=${issued.artifacts.par.response.request_uri}`);
  httpRes(302, undefined, { headers: { location: "/interaction/{uid}  (headless consent)" } });

  // Decide (Approver Bob → AS, real HTTP): Bob approves alice; 302 carries the code.
  hop("Approver (Bob)", "AS", "POST /interaction/{uid}/decide", "HTTP");
  httpReq("POST", `${asUrl}/interaction/{uid}/decide`, {
    headers: { "content-type": "application/json", cookie: "<interaction session>" },
    body: issued.artifacts.decide.request,
  });
  httpRes(302, undefined, {
    headers: { location: `${issued.artifacts.par.request.redirect_uri}?code=${issued.artifacts.decide.code.slice(0, 14)}...` },
  });
  note(`authorization code issued: ${issued.artifacts.decide.code.slice(0, 14)}...`);

  // Token (Agent → AS, real HTTP): DPoP-bound + private_key_jwt exchange.
  hop("Agent", "AS", "POST /token", "HTTP");
  const tokRes = issued.artifacts.token.response;
  httpReq("POST", `${asUrl}/token`, {
    headers: { "content-type": "application/x-www-form-urlencoded", dpop: "<DPoP proof: htu=/token, htm=POST>" },
    body: { ...issued.artifacts.token.request, client_assertion: "<private_key_jwt>" },
  });
  httpRes(200, {
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
  hop("Payments RS", "AS", "verify AS-signed token — GET /jwks", "in-process; fetches the AS jwks");
  note(`RS-side DPoP proof: same DPoP key as the token, htu=${CANONICAL_RESOURCE}, htm=POST.`);
  const rsProof = await dpopProofFor(issued.dpopKeys, CANONICAL_RESOURCE, "POST");
  let facts: TokenFacts = await stack.server.validateToken(issued.accessToken, rsProof, CANONICAL_RESOURCE, "POST");
  // Augment with the client instance id for a richer actor in the envelope.
  facts = { ...facts, clientInstanceId: "inst-ap-agent-01" };
  note("verified: JWT signature via AS /jwks, DPoP proof jkt == token cnf.jkt, mission claim present.");
  block("TokenFacts (drives every payments tool call below)", facts);

  // ---- 4. Discovery again -------------------------------------------------
  step(4, "Discovery again: the catalog now reflects the active mission");
  hop("Agent", "AS", "GET /service-catalog?type=mcp", `in-process; represents GET ${asUrl}/service-catalog`);
  block(
    "catalog payments connection",
    stack.catalog.catalog("alice", { type: "mcp" }).services.find((s) => s.id === "payments")?.connections,
  );

  // ---- Tool-call tracer (real token) --------------------------------------
  const traceCall = async (n: number, label: string, kind: "read" | "wire", tool: string, args: Record<string, unknown>) => {
    step(n, label);
    hop("Agent", "Payments RS", `tools/call ${tool}`, "in-process MCP · O-33");
    block(`MCP tools/call — ${tool}`, { tool, arguments: args, authorization: "DPoP <real mission-bound access token>" });
    const res =
      kind === "read" ? await stack.server.callReadTool(tool, args, facts) : await stack.server.callTransactionTool(tool, args, facts);
    hop("Payments RS (PEP)", "PDP", "evaluate", "in-process · D28");
    hop("PDP", "OpenFGA", "check", "HTTP https://localhost:8080");
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
  hop("Agent", "Payments RS", "tools/call send_remittance_email (base token, no txn-token)", "in-process MCP · O-33");
  block("MCP tools/call — send_remittance_email (base token, no txn-token)", {
    tool: "send_remittance_email",
    arguments: { invoice_id: "inv-1" },
    authorization: "DPoP <real mission-bound access token>",
  });
  const challengeAttempt = await stack.server.callTransactionTool("send_remittance_email", { invoice_id: "inv-1" }, facts);
  verdict(challengeAttempt.ok, `send_remittance_email(inv-1) → ${challengeAttempt.denial_reason ?? challengeAttempt.refusal_reason}`);
  const accessChallenge = challengeAttempt.access_challenge;
  if (!accessChallenge) throw new Error("expected an access_challenge (RS challengeSigner wired)");
  hop("Payments RS", "Agent", "401-style txn-challenge (RS-signed)", "in-process");
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
  hop("Agent", "AS", "POST /transaction (initiation — challenge presented once)", "HTTP");
  httpReq("POST", accessChallenge.txn_endpoint, {
    headers: {
      authorization: "DPoP <base token>",
      dpop: "<DPoP proof: htu=/transaction, htm=POST>",
      "content-type": "application/json",
    },
    body: { challenge: `${accessChallenge.challenge.slice(0, 40)}... (the txn-challenge above)` },
  });
  const pendingRes = await postTxn({ challenge: accessChallenge.challenge });
  const pendingBody = (await pendingRes.json()) as {
    transaction_authorization_id?: string;
    expires_in?: number;
    interval?: number;
  };
  httpRes(pendingRes.status, pendingBody);
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
  hop("Approver (Bob)", "ARS", "adjudicate AROP task (approve)", "in-process");
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
  hop("Agent", "AS", "POST /transaction (poll — with transaction_authorization_id)", "HTTP");
  httpReq("POST", accessChallenge.txn_endpoint, {
    headers: {
      authorization: "DPoP <base token>",
      dpop: "<DPoP proof: htu=/transaction, htm=POST>",
      "content-type": "application/json",
    },
    body: { transaction_authorization_id: txaId },
  });
  const tokenRes = await postTxn({ transaction_authorization_id: txaId });
  // §5.3 poll shape: 200 carries the txn-token; a 400 carries authorization_pending
  // / access_denied / expired_token. This exhibit approves before polling, so it
  // sees 200 -- but surface the error reason if the shape ever changes underfoot.
  const tokenBody = (await tokenRes.json()) as {
    access_token?: string;
    token_type?: string;
    txn?: string;
    error?: string;
  };
  httpRes(tokenRes.status, {
    ...tokenBody,
    ...(tokenBody.access_token ? { access_token: truncTok(tokenBody.access_token) } : {}),
  });
  const txnToken = tokenBody.access_token;
  if (!txnToken) {
    throw new Error(
      `expected a txn-token from the transaction endpoint (${tokenRes.status} ${tokenBody.error ?? "no error"})`,
    );
  }
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
  hop("Agent", "Payments RS", "tools/call send_remittance_email (re-present txn-token)", "in-process MCP · O-33");
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

  // ---- 8. AROP over DTR: deferred token response on the real /token endpoint --
  step(8, "AROP over DTR: a deferred token response, approved just-in-time (real /token)");
  note("Sibling AROP binding to step 7: instead of an RS-signed challenge, the client asks the /token endpoint itself for a mission-subset credential; when it cannot be issued yet, the AS returns a deferral_code the client polls (DTR draft-00).");

  // 8.1 Initiation: the agent POSTs the deferred grant with the mission subset it
  // wants; the AS opens a deferral and returns authorization_pending + a code.
  const deferredSubset = record.authority_set.filter((e) => e.resource === CANONICAL_RESOURCE);
  hop("Agent", "AS", "POST /token (deferred grant — initiation)", "HTTP");
  httpReq("POST", `${asUrl}/token`, {
    headers: { "content-type": "application/x-www-form-urlencoded", dpop: "<DPoP proof: htu=/token, htm=POST>" },
    body: {
      grant_type: DEFERRED_GRANT_TYPE,
      deferred_authorization: JSON.stringify({ mission_id: missionId, requested: deferredSubset }),
      client_assertion: "<private_key_jwt>",
    },
  });
  const dtrInit = await tokenGrantRequest(asUrl, as.agentClientJwk, issued.dpopKeys, {
    grant_type: DEFERRED_GRANT_TYPE,
    deferred_authorization: JSON.stringify({ mission_id: missionId, requested: deferredSubset }),
  });
  httpRes(dtrInit.status, dtrInit.body);
  const deferralCode = dtrInit.body.deferral_code as string;
  if (!deferralCode) throw new Error(`expected a deferral_code, got ${JSON.stringify(dtrInit.body)}`);
  note(
    `the deferral_code is the client's continuation handle; it polls the SAME grant with it ` +
      `(expires_in=${dtrInit.body.expires_in}s, interval=${dtrInit.body.interval}s, RFC 8628-shaped).`,
  );

  // 8.2 Poll before approval -> still authorization_pending (no token yet).
  hop("Agent", "AS", "POST /token (deferred grant — poll)", "HTTP");
  const dtrPending = await tokenGrantRequest(asUrl, as.agentClientJwk, issued.dpopKeys, {
    grant_type: DEFERRED_GRANT_TYPE,
    deferral_code: deferralCode,
  });
  httpRes(dtrPending.status, dtrPending.body);

  // 8.3 Approver (Bob) approves the deferral (headless) with an expiry that bounds
  // the credential; distinct from the acting subject alice.
  hop("Approver (Bob)", "AS", "approve deferral (headless adjudication)", "in-process");
  const dtrApprovedUntil = new Date(Date.now() + 120_000).toISOString();
  as.deferrals.approve(deferralCode, dtrApprovedUntil);
  note(`approved_until=${dtrApprovedUntil} — the issued credential's exp never outlives this.`);

  // 8.4 Redeem: poll again -> 200 with a REAL resource-bound mission token, the
  // ACTIVE Mission unchanged (D42), DPoP-bound to the same key.
  hop("Agent", "AS", "POST /token (deferred grant — redeem)", "HTTP");
  const dtrToken = await tokenGrantRequest(asUrl, as.agentClientJwk, issued.dpopKeys, {
    grant_type: DEFERRED_GRANT_TYPE,
    deferral_code: deferralCode,
  });
  const dtrAccessToken = dtrToken.body.access_token as string | undefined;
  httpRes(dtrToken.status, {
    ...dtrToken.body,
    ...(dtrAccessToken ? { access_token: truncTok(dtrAccessToken) } : {}),
  });
  if (!dtrAccessToken) {
    throw new Error(`expected a deferred mission token, got ${dtrToken.status} ${JSON.stringify(dtrToken.body)}`);
  }
  const dtrClaims = decodeClaims(dtrAccessToken);
  block("deferred mission token — decoded claims", {
    iss: dtrClaims.iss,
    sub: dtrClaims.sub,
    aud: dtrClaims.aud,
    mission: dtrClaims.mission,
    authorization_details: dtrClaims.authorization_details,
    cnf: dtrClaims.cnf,
    exp: dtrClaims.exp,
  });
  const dtrOk =
    (dtrClaims.mission as { id: string }).id === missionId &&
    (dtrClaims.cnf as { jkt: string }).jkt === issued.dpopJkt &&
    dtrClaims.aud === CANONICAL_RESOURCE;
  verdict(dtrOk, `deferred grant → REAL mission token (aud=${dtrClaims.aud as string}, single-use handle consumed)`);
  note(
    `mission.id == active mission ${missionId} (unchanged, D42); cnf.jkt ${(dtrClaims.cnf as { jkt: string }).jkt === issued.dpopJkt ? "==" : "!="} base token jkt; ` +
      `NOT opaque (3-segment JWT, aud-bound); exp <= approved_until.`,
  );

  // ---- 9. Cross-domain: the ID-JAG leg into the SaaS estate ---------------
  step(9, "Cross-domain: an ID-JAG grant crosses into the LedgerCloud (SaaS) estate");
  hop("AS", "Agent", "ID-JAG grant issued", "in-process");
  const grant = await as.issueCrossDomainGrant(missionId, issued.dpopJkt);
  block("ID-JAG grant — protected header", decodeHeader(grant.grant));
  block("ID-JAG grant — decoded payload", decodeClaims(grant.grant));
  note(`audience-scoped: authorization_details carries ONLY the SaaS estate; aud = the RAS issuer (${as.rasIssuer}); cnf.jkt binds the same DPoP key.`);

  hop("Agent", "RAS", "redeem ID-JAG grant — POST /token", `in-process; represents POST ${as.rasIssuer}/token`);
  const redeemed = await as.ras.redeem(grant.grant, issued.dpopJkt);
  block("RAS local token — decoded claims", decodeClaims(redeemed.access_token));
  note(`the RAS minted a LOCAL token (iss = ${as.rasIssuer}, aud = ${as.saasResource}); the SaaS PEP enforces from this token alone (token-only, no PDP).`);

  const saasDpop = await dpopProofFor(issued.dpopKeys, as.saasResource, "POST");
  hop("Agent", "SaaS RS", "tools/call post_journal_entry", `in-process; represents ${as.saasResource}`);
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

  // ---- 10. Denials --------------------------------------------------------
  step(10, "Denials: valid token, but out of bounds / authority");
  hop("Agent", "Payments RS", "tools/call execute_wire_transfer (inv-2, over-cap)", "in-process MCP · O-33");
  const over = await stack.server.callTransactionTool("execute_wire_transfer", { invoice_id: "inv-2" }, facts);
  hop("Payments RS (PEP)", "PDP", "evaluate", "in-process · D28");
  hop("PDP", "OpenFGA", "check", "HTTP https://localhost:8080");
  if (captured) block("PDP decision (over-cap $900)", captured.decision);
  verdict(over.ok, `execute_wire_transfer(inv-2, $900) → ${over.denial_reason ?? over.refusal_reason}`);
  hop("Agent", "Payments RS", "tools/call execute_wire_transfer (inv-3, globex)", "in-process MCP · O-33");
  const globex = await stack.server.callTransactionTool("execute_wire_transfer", { invoice_id: "inv-3" }, facts);
  hop("Payments RS (PEP)", "PDP", "evaluate", "in-process · D28");
  hop("PDP", "OpenFGA", "check", "HTTP https://localhost:8080");
  if (captured) block("PDP decision (globex vendor)", captured.decision);
  verdict(globex.ok, `execute_wire_transfer(inv-3, globex) → ${globex.denial_reason ?? globex.refusal_reason}`);

  // ---- 10. Lifecycle ------------------------------------------------------
  // MUST run AFTER the cross-domain leg and all tool calls: these transitions
  // drive the mission non-active / superseded and deny everything downstream.
  step(11, "Lifecycle: transitions that gate everything downstream");
  const lifecycle = async (operation: string, id: string): Promise<{ status: number; body: unknown }> => {
    const res = await fetch(`${asUrl}/missions/${id}/lifecycle`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-service-token": DEV_SERVICE_TOKEN },
      body: JSON.stringify({ operation }),
    });
    return { status: res.status, body: await res.json() };
  };

  // 10a. suspend -> the next action is denied (mission not active).
  hop("Operator", "AS", "POST /missions/{id}/lifecycle (suspend)", "HTTP");
  httpReq("POST", `${asUrl}/missions/${missionId}/lifecycle`, {
    headers: { "content-type": "application/json", "x-service-token": "<service token>" },
    body: { operation: "suspend" },
  });
  const suspendRes = await lifecycle("suspend", missionId);
  httpRes(suspendRes.status, suspendRes.body);
  hop("Agent", "Payments RS", "tools/call get_invoice (while suspended)", "in-process MCP · O-33");
  const whileSuspended = await stack.server.callReadTool("get_invoice", { invoice_id: "inv-1" }, facts);
  if (captured) block("PDP decision (suspended)", captured.decision);
  verdict(whileSuspended.ok, `get_invoice(inv-1) while suspended → ${whileSuspended.denial_reason ?? whileSuspended.refusal_reason}`);

  // 10b. resume -> the action is permitted again.
  hop("Operator", "AS", "POST /missions/{id}/lifecycle (resume)", "HTTP");
  httpReq("POST", `${asUrl}/missions/${missionId}/lifecycle`, {
    headers: { "content-type": "application/json", "x-service-token": "<service token>" },
    body: { operation: "resume" },
  });
  const resumeRes = await lifecycle("resume", missionId);
  httpRes(resumeRes.status, resumeRes.body);
  hop("Agent", "Payments RS", "tools/call get_invoice (after resume)", "in-process MCP · O-33");
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
  hop("Operator", "AS", "expand mission — successor from a fresh approval (kernel op)", "in-process");
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
  hop("Operator", "AS", "supersede predecessor on the successor's first redemption (kernel op)", "in-process");
  stack.kernel.supersedeOnRedemption(expansion.successor.id);
  note(`predecessor ${missionId} state → ${stack.kernel.get(missionId)?.state}`);
  hop("Agent", "Payments RS", "tools/call get_invoice (original token, predecessor superseded)", "in-process MCP · O-33");
  const afterSupersede = await stack.server.callReadTool("get_invoice", { invoice_id: "inv-1" }, facts);
  if (captured) block("PDP decision (predecessor superseded)", captured.decision);
  verdict(afterSupersede.ok, `get_invoice(inv-1) with the original token → ${afterSupersede.denial_reason ?? afterSupersede.refusal_reason}`);
  note("the original credential no longer authorizes; the successor is the active mission going forward.");

  // 10d. revoke the successor over the wire.
  hop("Operator", "AS", "POST /missions/{id}/lifecycle (revoke successor)", "HTTP");
  httpReq("POST", `${asUrl}/missions/${expansion.successor.id}/lifecycle`, {
    headers: { "content-type": "application/json", "x-service-token": "<service token>" },
    body: { operation: "revoke" },
  });
  const revokeRes = await lifecycle("revoke", expansion.successor.id);
  httpRes(revokeRes.status, revokeRes.body);

  // ---- 11. Evidence -------------------------------------------------------
  step(12, "Evidence: the tamper-evident feed, verified");
  hop("Operator (Olivia)", "Transparency", "read verified timeline", "in-process");
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
