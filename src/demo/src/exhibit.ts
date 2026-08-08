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
import { buildScopeStatement, EgressGate, type MissionState, scopeDigest } from "@mission/agent";
import { CANONICAL_RESOURCE, type CeilingEntry, DERIVATION_POLICY, DEV_SERVICE_TOKEN, TOPOLOGY } from "@mission/demo-data";
import { SAAS_RESOURCE } from "@mission/mcp-saas";
import type { TokenFacts } from "@mission/mcp-payments";
import type { Decision, EvaluationRequest } from "@mission/pdp";
import { calculateJwkThumbprint, exportJWK, generateKeyPair, importJWK, SignJWT } from "jose";
import { composeStack, type AuthServerExtras, type DemoStack } from "./stack.js";
import { label as humanName } from "./labels.js";
import { dpopProofFor, issueMissionToken, tokenGrantRequest } from "./oauth-client.js";

/**
 * The AAM grant-type URNs are NOT re-exported from @mission/authorization-server
 * (defined at services/authorization-server/src/adapters/provider.ts:95 and
 * .../adapters/continuation-grant.ts:45,48). The exhibit is a downstream package,
 * so it pins the wire values locally; token-exchange + access_token are the
 * RFC 8693 standard URNs. If the grant strings ever drift, the dispatch/exchange
 * legs of the AAM section below will fail loudly at /token.
 */
const MISSION_DISPATCH_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:mission-dispatch";
const TOKEN_EXCHANGE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange";
const ACCESS_TOKEN_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";
/** The single declared inference destination the harness egress gate mediates. */
const ANTHROPIC = "https://api.anthropic.com";

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

/**
 * Append a dim human gloss beside a machine id (tool name, action id, or reason
 * code), e.g. `execute_wire_transfer (Execute wire transfer)`. Display only:
 * the technical id stays verbatim so the exhibit still shows the real wire
 * value; an unmapped id is returned unchanged. Never used inside `block(...)`.
 */
function gloss(kind: "tool" | "action" | "reason", id: string): string {
  const human = humanName(kind, id);
  return human === id ? id : `${id} ${C.dim}(${human})${C.reset}`;
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

// ---------------------------------------------------------------------------
// Reader framing (O-40): a plain-language Task/Expect frame before each step, a
// two-axis outcome (protocol decision vs. whether it matched expectation), act
// banners that group the steps into phases, and a mission lifecycle rail. This
// is presentation only. Every value the outcome and rail render is read from
// REAL returned values / the live kernel at print time (never a hand-kept
// mirror of state that could drift).
// ---------------------------------------------------------------------------

/**
 * The plain-language frame printed right after step() and before the trace:
 * `task` is what this step does and for whom; `expect` is the desired outcome
 * in spec terms. Static narration (one line each) that orients the reader.
 */
function goal(task: string, expect: string) {
  console.log(`  ${C.bold}${C.yellow}Task${C.reset}    ${task}`);
  console.log(`  ${C.bold}${C.yellow}Expect${C.reset}  ${expect}`);
}

/**
 * The two orthogonal axes a step that ends in a decision actually has:
 *   - the protocol DECISION the PDP/gate/issuer returned (PERMIT / DENY + reason),
 *     rendered NEUTRAL: it is just what came back, not a pass/fail;
 *   - whether that matched what we EXPECTED (✓ as expected / ✗ deviation).
 * A deny-by-design step therefore reads `DENY <reason>` AND `✓ as expected`.
 * `observed` is a one-line summary built from REAL returned values; `ok` is a
 * REAL computed predicate, never a literal. `decision` is omitted only for a
 * pure read-model assertion (the Activity Log join) that has no PERMIT/DENY.
 */
function outcome(o: { decision?: "PERMIT" | "DENY"; reason?: string; observed: string; ok: boolean }) {
  const dec = o.decision === undefined ? "" : `${C.bold}${o.decision}${C.reset}${o.reason ? ` ${o.reason}` : ""}  `;
  const exp = o.ok ? `${C.green}✓ as expected${C.reset}` : `${C.red}✗ deviation${C.reset}`;
  console.log(`  ${dec}${exp}`);
  console.log(`    ${C.dim}observed: ${o.observed}${C.reset}`);
}

/** A short, readable mission id for the rail (ids are `msn_<base64url>`). */
function shortMission(id: string): string {
  return id.length > 14 ? `${id.slice(0, 12)}..` : id;
}

// The mission the lifecycle rail is tracking, and a snapshot of what the rail
// last DISPLAYED. The snapshot is used ONLY to print on-change and to name the
// delta; the authoritative values are always re-read from the kernel below.
type RailSnap = { id: string; state: string; version: number; policy: string; cv: number; effActions: number };
let focusedMissionId: string | undefined;
let lastRail: RailSnap | undefined;

/** Read the focused mission's rail snapshot from the live kernel (print time). */
function readRail(stack: DemoStack): RailSnap | undefined {
  if (!focusedMissionId) return undefined;
  const rec = stack.kernel.get(focusedMissionId);
  if (!rec) return undefined;
  const eff = stack.kernel.effectiveAuthoritySet(rec);
  return {
    id: rec.id,
    state: rec.state,
    version: rec.version,
    policy: rec.policy_version,
    cv: rec.containment?.containment_version ?? 0,
    effActions: eff.flatMap((e) => e.actions).length,
  };
}

/**
 * Render the compact rail line for the focused mission, naming any contained
 * actions when the effective set (read live) differs from the approved
 * authority_set. Values come straight from the kernel at print time.
 */
function railLine(stack: DemoStack): string {
  const rec = focusedMissionId ? stack.kernel.get(focusedMissionId) : undefined;
  if (!rec) return `  ${C.dim}│ mission focus: none yet${C.reset}`;
  const eff = stack.kernel.effectiveAuthoritySet(rec);
  const key = (r: string, a: string) => `${r}::${a}`;
  const approvedKeys = rec.authority_set.flatMap((e) => e.actions.map((a) => key(e.resource, a)));
  const effKeys = new Set(eff.flatMap((e) => e.actions.map((a) => key(e.resource, a))));
  const contained = approvedKeys.filter((k) => !effKeys.has(k)).map((k) => k.split("::")[1]);
  const cv = rec.containment?.containment_version ?? 0;
  const stateColor = rec.state === "active" ? C.green : rec.state === "suspended" ? C.yellow : C.red;
  const sep = `${C.dim}  ·  ${C.reset}`;
  const cells = [
    `${C.cyan}mission ${shortMission(rec.id)}${C.reset}`,
    `${C.dim}state=${C.reset}${stateColor}${rec.state}${C.reset}`,
    `${C.dim}v${rec.version}${C.reset}`,
    `${C.dim}policy=${rec.policy_version}${C.reset}`,
    `${C.dim}authority ${effKeys.size}/${approvedKeys.length}${C.reset}`,
    `${C.dim}containment v${cv}${C.reset}`,
  ];
  let line = `  ${C.dim}│${C.reset} ${cells.join(sep)}`;
  if (contained.length > 0) line += `\n  ${C.dim}│ contained: ${contained.join(", ")}${C.reset}`;
  return line;
}

/** Name the one thing that changed between two rail snapshots (or a focus shift). */
function describeChange(prev: RailSnap | undefined, cur: RailSnap | undefined): string | undefined {
  if (!cur) return undefined;
  if (!prev || prev.id !== cur.id) return `focus is now mission ${shortMission(cur.id)} (${cur.state})`;
  if (prev.state !== cur.state) return `mission ${shortMission(cur.id)}: ${prev.state} → ${cur.state}`;
  if (prev.cv !== cur.cv) return `containment v${prev.cv} → v${cur.cv} (effective authority narrowed)`;
  if (prev.effActions !== cur.effActions) return `effective authority: ${prev.effActions} → ${cur.effActions} actions`;
  if (prev.version !== cur.version) return `version v${prev.version} → v${cur.version}`;
  return undefined;
}

/**
 * Print the lifecycle rail. At an act banner (`force`) it re-anchors the
 * reader; elsewhere it prints ON CHANGE ONLY, deduped against what was last
 * shown, and names the transition/containment bump/focus shift.
 */
function rail(stack: DemoStack, opts: { force?: boolean } = {}) {
  const snap = readRail(stack);
  const sig = (s: RailSnap | undefined) => (s ? `${s.id}|${s.state}|${s.version}|${s.cv}|${s.effActions}` : "none");
  if (!opts.force && sig(snap) === sig(lastRail)) return;
  const change = describeChange(lastRail, snap);
  console.log(railLine(stack));
  if (change) console.log(`  ${C.dim}↳ ${change}${C.reset}`);
  lastRail = snap;
}

/** An act banner grouping the existing steps into a phase (no renumbering), with
 *  the lifecycle rail re-anchored underneath it. */
function act(stack: DemoStack, numeral: string, title: string, oneLine: string) {
  console.log(`\n${C.bold}${C.magenta}${"━".repeat(72)}${C.reset}`);
  console.log(`${C.bold}${C.magenta}  ACT ${numeral}  ${title}${C.reset}`);
  console.log(`${C.dim}  ${oneLine}${C.reset}`);
  console.log(`${C.bold}${C.magenta}${"━".repeat(72)}${C.reset}`);
  rail(stack, { force: true });
}

// ===========================================================================
// Agent Access Model (Nightly Reconciliation) — the AAM run narrated ENTIRELY
// in Mission vocabulary, driven against the SAME live stack the sections above
// use. The AAM -> Mission mapping is in AAM.md; the wire recipes below are the
// ones the authoritative e2e proves
// (services/authorization-server/test/aam-nightly-reconciliation.test.ts).
// ===========================================================================

/** The bounded per-instance lifetime (the AAM "bounded task budget"). */
const AAM_LIFETIME_S = 900;
/** A far-future ceiling expiry, well above the per-instance clamp so the clamp
 *  (and the refresh-family lifetime bound) is observable but never expires mid-run. */
const AAM_FAR_FUTURE = "2099-01-01T00:00:00Z";
const AAM_TAINT_EVENT_ID = "aam-exhibit-taint-1";

/**
 * The read-only reconciliation ceiling PLUS the single external-communication
 * capability (payments:remittance.send = "post to one finance channel"), built
 * from the derivation policy so every entry stays entry-wise within it: keep
 * read/list + remittance.send, copy constraints verbatim, keep CANONICAL_RESOURCE
 * (so containment's resource-remap targets the resource the Mission holds).
 */
function aamCeiling(): CeilingEntry[] {
  const keep = (a: string) => a.endsWith(".read") || a.endsWith(".list") || a === "payments:remittance.send";
  return DERIVATION_POLICY.ceiling
    .map((e) => {
      const entry: CeilingEntry = { type: e.type, resource: e.resource, actions: e.actions.filter(keep) };
      if (e.constraints) entry.constraints = e.constraints;
      return entry;
    })
    .filter((e) => e.actions.length > 0);
}

/** The Task Template body (consent once): the ceiling, a bounded lifetime, and the
 *  human approver of record. */
function aamTemplateBody(issuer: string, seq: number): Record<string, unknown> {
  return {
    template_version: "aam-nightly-reconciliation-1",
    issuer,
    approver: { iss: issuer, sub: "bob" }, // the consenting human of record
    ceiling: aamCeiling(),
    dispatch_policy: "aam-nightly-reconciliation",
    dispatchers: ["ap-agent"], // the scheduler dispatches
    recipients: ["subagent-invoice-extractor"], // the reconciliation sub-agent receives
    per_instance_lifetime_s: AAM_LIFETIME_S,
    max_active: 5,
    rate_per_min: 30,
    approval_event_id: `aam-tmpl-evt-${seq}`,
    expires_at: AAM_FAR_FUTURE,
  };
}

/** In-ceiling reconciliation intent: read invoices + post the finance remittance. */
function aamIntent(): string {
  return JSON.stringify({
    goal: "nightly reconciliation of Acme invoices",
    resources: [CANONICAL_RESOURCE],
    expires_at: AAM_FAR_FUTURE,
    proposed_authority: [
      {
        type: "mission_resource_access",
        resource: CANONICAL_RESOURCE,
        actions: ["payments:invoice.read", "payments:remittance.send"],
        constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
      },
    ],
  });
}

/** An intent that exceeds the read/post ceiling (payment.schedule is in the
 *  derivation policy but was filtered out of this template's ceiling). */
function aamOverCeilingIntent(): string {
  return JSON.stringify({
    goal: "schedule a payment (exceeds the reconciliation ceiling)",
    resources: [CANONICAL_RESOURCE],
    expires_at: AAM_FAR_FUTURE,
    proposed_authority: [
      {
        type: "mission_resource_access",
        resource: CANONICAL_RESOURCE,
        actions: ["payments:payment.schedule"],
        constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
      },
    ],
  });
}

/** The AAM component -> Mission surface legend (mirrors legend()'s row style). */
function aamLegend() {
  const row = (component: string, surface: string) =>
    console.log(`  ${C.bold}${C.cyan}${component.padEnd(27)}${C.reset}${C.dim}${surface}${C.reset}`);
  console.log(`\n${C.bold}AAM → Mission${C.reset} ${C.dim}— each Agent Access Model component and the Mission surface that realizes it (AAM.md).${C.reset}`);
  row("Task Template + ceiling", "Mission Template + POST /templates (consent once)");
  row("Agent Identity Broker", "mission-dispatch grant + async-delegation refresh family");
  row("Task-Scoped Access Engine", "the PDP (@mission/pdp) over OpenFGA");
  row("Mediation Layer", "the payments PEP + the harness EgressGate");
  row("Trust Ratchet", "Mission Containment (signed protected-event ingestion)");
  row("Agent Activity Log", "ConsoleBff.activityLog() (the console-bff join)");
  row("Grant Review Loop", "not adopted — a Mission is lifetime-bounded, not a standing grant");
}

/**
 * The seven-step AAM Nightly Reconciliation walk, driven against the SAME stack
 * as the sections above (do not spin a second stack): consent once (Template),
 * dispatch at machine speed (mission-dispatch grant), run disconnected
 * (async-delegation refresh family), mediate per action (PEP + EgressGate),
 * ratchet down on a signed protected event (Containment), restore only in a
 * fresh task, and read the joined task-run graph back from the Activity Log.
 */
async function runAamSection(stack: DemoStack, as: AuthServerExtras, asUrl: string) {
  // A fresh Template chapter, independent of the primary mission superseded and
  // revoked above: reset the rail focus so the act opens with no mission yet.
  focusedMissionId = undefined;
  act(
    stack,
    "VII",
    "Agent Access Model (Nightly Reconciliation)",
    "Cloudflare's AAM run, narrated entirely in Mission vocabulary (AAM.md), on the same live AS, PDP, OpenFGA, PEP, egress gate, and Activity Log.",
  );

  let seq = 0;
  // Threaded across the seven sequential steps.
  let templateId = "";
  // The dispatcher (ap-agent) DPoP key: the dispatched mission token binds to it,
  // and the RS-side proof in step 16 re-presents it (proof jkt == token cnf.jkt).
  const dispatcherDpop = await generateKeyPair("ES256", { extractable: true });

  const dispatch = (intent: string, evtId: string) =>
    tokenGrantRequest(asUrl, as.agentClientJwk, dispatcherDpop, {
      grant_type: MISSION_DISPATCH_GRANT_TYPE,
      template_id: templateId,
      mission_intent: intent,
      dispatch_event_id: evtId,
    });

  // The harness egress scope statement: inference_api is mediated to a single
  // destination; transport in_memory forces containment_claim "none" (the honest
  // downgrade — an in-process gate cannot contain a compromised agent; see AAM.md).
  const scopeStatement = buildScopeStatement({
    isolation_mechanism: "in-process AAM reference demo (no isolation boundary)",
    transport: "in_memory",
    mediated_action_classes: ["payments"],
    excluded_unmediated_paths: ["direct process network access"],
    channel_classes: [{ channel_class: "inference_api", disposition: "mediated", destinations: [ANTHROPIC] }],
  });

  // ---- 13. Consent once (AAM Task Template + ceiling -> Mission Template) ----
  step(13, "Consent once: AAM Task Template → a Mission Template (POST /templates)");
  goal(
    "Bob consents once by registering an AAM Task Template (its ceiling, bounded lifetime, and approver of record).",
    "the template is recorded with an integrity hash; consent is captured a single time for every later dispatch.",
  );
  hop("Operator (Bob)", "AS", "POST /templates (consent once)", "HTTP");
  const templateBody = aamTemplateBody(asUrl, seq++);
  httpReq("POST", `${asUrl}/templates`, {
    headers: { "content-type": "application/json", "x-service-token": "<service token>" },
    body: templateBody,
  });
  const tmplRes = await fetch(`${asUrl}/templates`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-service-token": DEV_SERVICE_TOKEN },
    body: JSON.stringify(templateBody),
  });
  const tmplJson = (await tmplRes.json()) as { template_id?: string; template_version?: string; template_hash?: string };
  httpRes(tmplRes.status, tmplJson);
  if (tmplRes.status !== 201 || !tmplJson.template_id || !tmplJson.template_hash) {
    throw new Error(`POST /templates failed: ${tmplRes.status} ${JSON.stringify(tmplJson)}`);
  }
  templateId = tmplJson.template_id;
  const templateHash = tmplJson.template_hash;
  note(
    "consent is captured ONCE here: the human approver of record is bob; the ceiling carries the read actions " +
      "PLUS one external-comms capability (payments:remittance.send), and NOT payments:payment.schedule.",
  );
  const ceilingActions = aamCeiling().flatMap((e) => e.actions);
  const consentOk =
    tmplRes.status === 201 &&
    ceilingActions.includes("payments:remittance.send") &&
    !ceilingActions.includes("payments:payment.schedule");
  outcome({
    decision: "PERMIT",
    observed: `template ${templateId} recorded (template_hash=${templateHash}); ceiling carries payments:remittance.send and NOT payments:payment.schedule`,
    ok: consentOk,
  });

  // ---- 14. Machine-speed dispatch (AAM Agent Identity Broker) ----------------
  step(14, "Machine-speed dispatch: AAM Agent Identity Broker → the mission-dispatch grant");
  goal(
    "The scheduler dispatches a mission from the template with no human in the loop, then attempts an over-ceiling dispatch.",
    "the in-ceiling dispatch is admitted (template-clipped, approver of record bob); the over-ceiling one is refused out_of_template_ceiling.",
  );
  hop("Scheduler (ap-agent)", "AS", "POST /token (mission-dispatch grant, no human)", "HTTP");
  httpReq("POST", `${asUrl}/token`, {
    headers: { "content-type": "application/x-www-form-urlencoded", dpop: "<DPoP proof: htu=/token, htm=POST>" },
    body: {
      grant_type: MISSION_DISPATCH_GRANT_TYPE,
      template_id: templateId,
      mission_intent: "<in-ceiling reconciliation intent (read invoices + post remittance)>",
      dispatch_event_id: "evt-dispatch-...",
      client_assertion: "<private_key_jwt>",
    },
  });
  const dispRes = await dispatch(aamIntent(), `evt-dispatch-${seq++}`);
  const dispBody = dispRes.body as {
    access_token?: string;
    token_type?: string;
    mission_id?: string;
    authorization_details?: unknown;
    expires_in?: number;
  };
  httpRes(dispRes.status, {
    ...dispBody,
    ...(dispBody.access_token ? { access_token: truncTok(dispBody.access_token) } : {}),
  });
  if (dispRes.status !== 200 || !dispBody.mission_id || !dispBody.access_token) {
    throw new Error(`mission-dispatch failed: ${dispRes.status} ${JSON.stringify(dispBody)}`);
  }
  const dispatchedMissionId = dispBody.mission_id;
  const dispatchedAccessToken = dispBody.access_token;
  const dispatchedRecord = stack.kernel.get(dispatchedMissionId);
  if (!dispatchedRecord) throw new Error("dispatched mission record not found");
  block("dispatched Mission Record (issuer output — no human in this loop)", {
    id: dispatchedRecord.id,
    state: dispatchedRecord.state,
    subject: dispatchedRecord.subject,
    approver: dispatchedRecord.approver,
    template: dispatchedRecord.template,
    authority_hash: dispatchedRecord.authority_hash,
    expires_at: dispatchedRecord.expires_at,
  });
  const dispClaims = decodeClaims(dispatchedAccessToken);
  block("dispatched access token — decoded claims", {
    iss: dispClaims.iss,
    sub: dispClaims.sub,
    aud: dispClaims.aud,
    cnf: dispClaims.cnf,
    mission: dispClaims.mission,
    authorization_details: dispClaims.authorization_details,
    exp: dispClaims.exp,
  });
  note(
    `machine speed, no human: approver-of-record == the template's human (${dispatchedRecord.approver.sub}); ` +
      `template lineage template_hash ${dispatchedRecord.template?.template_hash === templateHash ? "==" : "!="} the consented template; ` +
      "the Authority Set == the template-clipped effective set.",
  );
  note(
    `subject == approver == ${dispatchedRecord.subject.sub} here by construction: at machine-speed dispatch the recipient ` +
      "acts under the template's approver-of-record, not a distinct human subject (contrast step 2, where a human approval " +
      "bound subject alice under a distinct approver bob for a write-bearing mission).",
  );
  focusedMissionId = dispatchedMissionId;
  rail(stack);
  const dispatchOk =
    dispRes.status === 200 &&
    dispatchedRecord.approver.sub === "bob" &&
    dispatchedRecord.template?.template_hash === templateHash;
  outcome({
    decision: "PERMIT",
    observed: `dispatched mission ${dispatchedMissionId}, approver-of-record ${dispatchedRecord.approver.sub}, template-clipped authority`,
    ok: dispatchOk,
  });

  // Over-ceiling dispatch is refused out_of_template_ceiling.
  hop("Scheduler (ap-agent)", "AS", "POST /token (mission-dispatch — over ceiling)", "HTTP");
  httpReq("POST", `${asUrl}/token`, {
    headers: { "content-type": "application/x-www-form-urlencoded", dpop: "<DPoP proof>" },
    body: {
      grant_type: MISSION_DISPATCH_GRANT_TYPE,
      template_id: templateId,
      mission_intent: "<intent adding payments:payment.schedule — outside the ceiling>",
    },
  });
  const overRes = await dispatch(aamOverCeilingIntent(), `evt-over-${seq++}`);
  const overBody = overRes.body as { mission_denial_reason?: string };
  httpRes(overRes.status, overBody);
  outcome({
    decision: "DENY",
    reason: gloss("reason", overBody.mission_denial_reason ?? ""),
    observed: `the over-ceiling intent (adds payments:payment.schedule) was refused ${overBody.mission_denial_reason ?? "(no reason)"}`,
    ok: overBody.mission_denial_reason === "out_of_template_ceiling",
  });

  // ---- 15. Disconnected run (AAM Agent Identity Broker: async-delegation) ----
  step(15, "Disconnected run: AAM Agent Identity Broker → the async-delegation refresh family");
  goal(
    "The scheduler exchanges the dispatched token for a rotating refresh-token family so a disconnected reconciler can run.",
    "each issued access token is clamped to the mission expiry, and the refresh token rotates on every use.",
  );
  const missionExp = Math.floor(Date.parse(dispatchedRecord.expires_at) / 1000);
  hop("Scheduler (ap-agent)", "AS", "POST /token (RFC 8693 request_refresh_token)", "HTTP");
  httpReq("POST", `${asUrl}/token`, {
    headers: { "content-type": "application/x-www-form-urlencoded", dpop: "<DPoP proof>" },
    body: {
      grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
      request_refresh_token: "true",
      subject_token: "<dispatched mission access token>",
      subject_token_type: ACCESS_TOKEN_TOKEN_TYPE,
      resource: CANONICAL_RESOURCE,
    },
  });
  const exchRes = await tokenGrantRequest(asUrl, as.agentClientJwk, dispatcherDpop, {
    grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
    request_refresh_token: "true",
    subject_token: dispatchedAccessToken,
    subject_token_type: ACCESS_TOKEN_TOKEN_TYPE,
    resource: CANONICAL_RESOURCE,
  });
  const exchBody = exchRes.body as { access_token?: string; token_type?: string; refresh_token?: string };
  httpRes(exchRes.status, {
    ...exchBody,
    ...(exchBody.access_token ? { access_token: truncTok(exchBody.access_token) } : {}),
    ...(exchBody.refresh_token ? { refresh_token: `${String(exchBody.refresh_token).slice(0, 12)}...` } : {}),
  });
  if (exchRes.status !== 200 || !exchBody.refresh_token || !exchBody.access_token) {
    throw new Error(`async-delegation exchange failed: ${exchRes.status} ${JSON.stringify(exchBody)}`);
  }
  const familyRefreshToken = exchBody.refresh_token;
  const exchExp = decodeClaims(exchBody.access_token).exp as number;
  note(
    `a rotated, sender-constrained refresh-token FAMILY, whose issued access token never outlives the Mission: ` +
      `token exp ${exchExp} ${exchExp <= missionExp ? "<=" : ">"} mission expiry ${missionExp} (absolute-lifetime clamp).`,
  );

  hop("Reconciler (offline, disconnected)", "AS", "POST /token (grant_type=refresh_token)", "HTTP");
  httpReq("POST", `${asUrl}/token`, {
    headers: { "content-type": "application/x-www-form-urlencoded", dpop: "<DPoP proof>" },
    body: { grant_type: "refresh_token", refresh_token: "<family refresh token>" },
  });
  const refRes = await tokenGrantRequest(asUrl, as.agentClientJwk, dispatcherDpop, {
    grant_type: "refresh_token",
    refresh_token: familyRefreshToken,
  });
  const refBody = refRes.body as { access_token?: string; token_type?: string; refresh_token?: string };
  httpRes(refRes.status, {
    ...refBody,
    ...(refBody.access_token ? { access_token: truncTok(refBody.access_token) } : {}),
    ...(refBody.refresh_token ? { refresh_token: `${String(refBody.refresh_token).slice(0, 12)}...` } : {}),
  });
  const refreshedMissionId = refBody.access_token ? (decodeClaims(refBody.access_token).mission as { id?: string })?.id : undefined;
  const refreshOk =
    refRes.status === 200 &&
    refreshedMissionId === dispatchedMissionId &&
    refBody.refresh_token !== familyRefreshToken &&
    exchExp <= missionExp;
  outcome({
    decision: "PERMIT",
    observed: `fresh access token for mission ${refreshedMissionId} (unchanged); refresh token rotated; issued exp ${exchExp} <= mission expiry ${missionExp}`,
    ok: refreshOk,
  });

  // ---- 16. Per-action mediation (AAM Mediation Layer: PEP + EgressGate) ------
  step(16, "Per-action mediation: AAM Mediation Layer → the payments PEP + the harness EgressGate");
  goal(
    "The reconciler reads an invoice, then requests inference egress to a declared destination and to an exfil host.",
    "the read and the declared destination are permitted; the exfil destination is refused (not on the allowlist).",
  );
  // Validate the REAL dispatched token at the RS (exhibit idiom): the RS-side
  // DPoP proof re-presents the dispatcher key, so proof jkt == token cnf.jkt.
  const rsProof = await dpopProofFor(dispatcherDpop, CANONICAL_RESOURCE, "POST");
  const facts: TokenFacts = await stack.server.validateToken(dispatchedAccessToken, rsProof, CANONICAL_RESOURCE, "POST");
  note(`verified dispatched token at the RS (aud=${CANONICAL_RESOURCE}, DPoP jkt==cnf.jkt, mission claim present).`);
  hop("Reconciler", "Payments RS", `tools/call ${gloss("tool", "get_invoice")}`, "in-process MCP · O-33");
  const readRes = await stack.server.callReadTool("get_invoice", { invoice_id: "inv-1" }, facts);
  outcome({
    decision: readRes.ok ? "PERMIT" : "DENY",
    ...(readRes.ok ? {} : { reason: gloss("reason", readRes.denial_reason ?? readRes.refusal_reason ?? "") }),
    observed: readRes.ok
      ? `${gloss("tool", "get_invoice")}(inv-1) returned ${JSON.stringify(readRes.result)}`
      : `${gloss("tool", "get_invoice")}(inv-1) denied`,
    ok: readRes.ok,
  });

  // The harness egress gate: an in-process reference realization bound to the
  // dispatched Mission, reading the REAL kernel state (no mock), over the shared
  // scope statement, writing to the stack's OWN egress evidence store (joins step 19).
  const egressGate = new EgressGate({
    statement: scopeStatement,
    missionId: dispatchedMissionId,
    readState: async (id) => stack.kernel.get(id)?.state as MissionState | undefined,
    authorityHash: dispatchedRecord.authority_hash,
    evidence: stack.egressEvidence,
    emitterId: "aam-egress-gate",
    instanceEpoch: "demo-epoch",
    onRefusal: (r) => note(`gate reporter: ${r.refusal_reason}`),
  });
  hop("Reconciler", "EgressGate", `request inference_api → ${ANTHROPIC}`, "in-process · harness");
  const allowedEgress = await egressGate.request("inference_api", `${ANTHROPIC}/v1/messages`);
  outcome({
    decision: allowedEgress.permitted ? "PERMIT" : "DENY",
    ...(allowedEgress.permitted ? {} : { reason: gloss("reason", allowedEgress.refusal_reason ?? "") }),
    observed: `egress inference_api → ${ANTHROPIC}/v1/messages (the one declared destination)`,
    ok: allowedEgress.permitted,
  });
  hop("Reconciler", "EgressGate", "request inference_api → exfil.example.com", "in-process · harness");
  const refusedEgress = await egressGate.request("inference_api", "https://exfil.example.com/collect");
  outcome({
    decision: refusedEgress.permitted ? "PERMIT" : "DENY",
    ...(refusedEgress.permitted ? {} : { reason: gloss("reason", refusedEgress.refusal_reason ?? "") }),
    observed: "egress inference_api → https://exfil.example.com/collect refused (not on the declared allowlist)",
    ok: !refusedEgress.permitted && (refusedEgress.refusal_reason ?? "").startsWith("egress_destination_unlisted"),
  });
  note(
    "the in-process gate reports containment_claim \"none\" (an in-process gate cannot contain a compromised agent); " +
      "its value is an honest allowlist + an evidence trail — recorded and threaded into the Activity Log (step 19).",
  );

  // ---- 17. Protected event -> containment (AAM Trust Ratchet) ----------------
  step(17, "Protected event → containment: AAM Trust Ratchet → Mission Containment (Baseline → Restricted)");
  goal(
    "A signed SOC event (content.tainted_read) is ingested, ratcheting the mission from Baseline to Restricted (AAM terms).",
    "the effective authority narrows deterministically: send_remittance_email is denied authority_contained, while the read still permits.",
  );
  const soc = as.protectedEventSources.find((s) => s.source === "svc:soc");
  if (!soc) throw new Error("svc:soc trusted source not seeded (config/containment.json)");
  const socKey = await importJWK(soc.privateJwk, soc.alg);
  const socEvent = await new SignJWT({
    type: "content.tainted_read",
    source: "svc:soc",
    observed_at: new Date().toISOString(),
    event_id: AAM_TAINT_EVENT_ID,
    mission_id: dispatchedMissionId,
  })
    .setProtectedHeader({ alg: soc.alg, kid: soc.kid })
    .setIssuedAt()
    .sign(socKey);
  hop("SOC source (svc:soc)", "AS", `POST /missions/{id}/protected-events (signed content.tainted_read)`, "HTTP");
  httpReq("POST", `${asUrl}/missions/${dispatchedMissionId}/protected-events`, {
    headers: { "content-type": "application/protected-event+jwt" },
    body: { "<compact JWS>": "content.tainted_read, signed by svc:soc (decoded below)" },
  });
  block("protected-event — protected header", decodeHeader(socEvent));
  block("protected-event — decoded claims", decodeClaims(socEvent));
  const peRes = await fetch(`${asUrl}/missions/${dispatchedMissionId}/protected-events`, {
    method: "POST",
    headers: { "content-type": "application/protected-event+jwt" },
    body: socEvent,
  });
  const peBody = (await peRes.json()) as { containment_version?: number; removed?: unknown };
  httpRes(peRes.status, peBody);
  note(
    "AAM Baseline → Restricted: the issuer narrows the EFFECTIVE Authority Set deterministically from the signed event; " +
      "the approved authority_hash stays immutable (containment is a versioned removal-only overlay).",
  );
  rail(stack);
  hop("Reconciler", "Payments RS", `tools/call ${gloss("tool", "send_remittance_email")} (contained capability)`, "in-process MCP · O-33");
  const containedCall = await stack.server.callTransactionTool("send_remittance_email", { invoice_id: "inv-1" }, facts);
  outcome({
    decision: "DENY",
    reason: gloss("reason", containedCall.denial_reason ?? containedCall.refusal_reason ?? ""),
    observed: `${gloss("tool", "send_remittance_email")}(inv-1) denied ${containedCall.denial_reason ?? containedCall.refusal_reason ?? ""}`,
    ok: !containedCall.ok && containedCall.denial_reason === "authority_contained",
  });
  hop("Reconciler", "Payments RS", `tools/call ${gloss("tool", "get_invoice")} (uncontained read)`, "in-process MCP · O-33");
  const stillRead = await stack.server.callReadTool("get_invoice", { invoice_id: "inv-1" }, facts);
  outcome({
    decision: stillRead.ok ? "PERMIT" : "DENY",
    ...(stillRead.ok ? {} : { reason: gloss("reason", stillRead.denial_reason ?? stillRead.refusal_reason ?? "") }),
    observed: stillRead.ok
      ? `${gloss("tool", "get_invoice")}(inv-1) still returns ${JSON.stringify(stillRead.result)}`
      : `${gloss("tool", "get_invoice")}(inv-1) denied`,
    ok: stillRead.ok,
  });

  // ---- 18. Restore only in a new task ---------------------------------------
  step(18, "Restore only in a new task: the capability returns via a FRESH dispatch, never mid-run");
  goal(
    "The scheduler dispatches a fresh mission to restore the capability; the contained mission is retried.",
    "the fresh task carries remittance.send again; the contained mission never regains it mid-run.",
  );
  hop("Scheduler (ap-agent)", "AS", "POST /token (mission-dispatch — a fresh task)", "HTTP");
  const restoreRes = await dispatch(aamIntent(), `evt-restore-${seq++}`);
  const restoreBody = restoreRes.body as { access_token?: string; mission_id?: string; authorization_details?: unknown };
  httpRes(restoreRes.status, {
    ...restoreBody,
    ...(restoreBody.access_token ? { access_token: truncTok(restoreBody.access_token) } : {}),
  });
  if (restoreRes.status !== 200 || !restoreBody.mission_id) {
    throw new Error(`restore dispatch failed: ${restoreRes.status} ${JSON.stringify(restoreBody)}`);
  }
  const restoredMissionId = restoreBody.mission_id;
  const restoredActions = (restoreBody.authorization_details as Array<{ actions: string[] }>).flatMap((e) => e.actions);
  const restoreOk = restoredMissionId !== dispatchedMissionId && restoredActions.includes("payments:remittance.send");
  outcome({
    decision: "PERMIT",
    observed: `fresh dispatch → mission ${restoredMissionId} (a new task) carries ${gloss("action", "payments:remittance.send")} again`,
    ok: restoreOk,
  });
  // The contained Mission never regains it mid-run.
  hop("Reconciler", "Payments RS", `tools/call ${gloss("tool", "send_remittance_email")} (contained mission, re-tried)`, "in-process MCP · O-33");
  const stillContained = await stack.server.callTransactionTool("send_remittance_email", { invoice_id: "inv-1" }, facts);
  outcome({
    decision: "DENY",
    reason: gloss("reason", stillContained.denial_reason ?? stillContained.refusal_reason ?? ""),
    observed: `contained mission ${dispatchedMissionId} still denied ${stillContained.denial_reason ?? stillContained.refusal_reason ?? ""} (never regained mid-run)`,
    ok: !stillContained.ok && stillContained.denial_reason === "authority_contained",
  });

  // ---- 19. Agent Activity Log (the console-bff join) ------------------------
  step(19, "Agent Activity Log: AAM Agent Activity Log → ConsoleBff.activityLog() (the joined task-run graph)");
  goal(
    "Olivia reads the joined task-run graph from the Activity Log for the dispatched mission.",
    "ingestion, containment evidence, the authority_contained decision, and the egress refusal all join under the one mission.",
  );
  hop("Operator (Olivia)", "Console BFF", "activityLog(dispatched mission)", "in-process · read-model join");
  const session = stack.bff.sessions.create("olivia", ["operator"]);
  const run = stack.bff.activityLog(session, dispatchedMissionId);
  block("task-run graph — lineage", { mission_id: run.mission_id, template: run.lineage.template });
  console.log(`${C.dim}  entries (ingestion → Containment Evidence → authority_contained; + the egress refusal):${C.reset}`);
  for (const e of run.entries) {
    const detail = [
      e.action ? `action=${e.action}` : "",
      e.outcome ? `outcome=${e.outcome}` : "",
      e.denial_reason ? `reason=${e.denial_reason}` : "",
      e.event_id ? `event_id=${e.event_id}` : "",
      e.containment_version !== undefined ? `containment_version=${e.containment_version}` : "",
    ]
      .filter(Boolean)
      .join("  ");
    console.log(`  ${C.cyan}${e.kind.padEnd(11)}${C.reset} ${C.dim}${detail}${C.reset}`);
  }
  const ingestion = run.entries.find((e) => e.kind === "ingestion" && e.action === "content.tainted_read" && e.outcome === "applied");
  const containment = run.entries.find((e) => e.kind === "containment");
  const contained = run.entries.find((e) => e.kind === "decision" && e.denial_reason === "authority_contained");
  const egress = run.entries.find((e) => e.kind === "egress" && e.outcome === "refused");
  // The read-model timeline is timestamp-ordered (activity-log.ts: `at` is the
  // primary ordering key). "Follows" is therefore a TIMESTAMP relation, not an
  // array-index one: the earlier `indexOf(contained) > indexOf(ingestion)` check
  // was flaky, going false whenever the ingestion record and the first
  // authority_contained decision landed in the same millisecond (the sort's
  // tiebreak is input order, which places the decision first). Comparing `at`
  // (>=, since same-tick logging is legitimate) is stable and matches the
  // narration's "follows both".
  const followsBoth =
    !!ingestion &&
    !!containment &&
    !!contained &&
    Date.parse(contained.at) >= Date.parse(ingestion.at) &&
    Date.parse(contained.at) >= Date.parse(containment.at);
  const joinedOk =
    !!ingestion &&
    !!containment &&
    !!contained &&
    !!egress &&
    ingestion.event_id === AAM_TAINT_EVENT_ID &&
    containment.event_id === AAM_TAINT_EVENT_ID &&
    followsBoth &&
    egress.scope_statement_digest === scopeDigest(scopeStatement);
  outcome({
    observed:
      `ingestion and Containment Evidence share event_id ${AAM_TAINT_EVENT_ID}; ` +
      "an authority_contained decision follows both (by timestamp), and the egress refusal carries the published scope-statement digest.",
    ok: joinedOk,
  });

  aamLegend();
  console.log(
    `\n${C.green}${C.bold}AAM section complete.${C.reset} ${C.dim}Consent-once Template, machine-speed dispatch, disconnected run, per-action mediation, protected-event containment, fresh-task restore, and the Activity Log — all on the same live stack.${C.reset}`,
  );
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

  act(
    stack,
    "I",
    "Discovery and intent",
    "The agent discovers what it can reach and drafts an over-broad proposal. Nothing is granted yet.",
  );

  // ---- 0. Discovery -------------------------------------------------------
  step(0, "Discovery: the agent asks what it can reach");
  goal(
    "Alice's agent asks the catalog what it can reach, before any mission exists.",
    "payments shows as reachable but consent_required; no authority is granted yet.",
  );
  hop("Agent", "AS", "GET /service-catalog?type=mcp", `in-process; represents GET ${asUrl}/service-catalog`);
  note("access token audience = catalog");
  block("catalog response (before any mission)", stack.catalog.catalog("alice", { type: "mcp" }));
  note("payments is consent_required: reachable, but no mission covers it yet.");

  // ---- 1. Intent shaping (untrusted, two-estate proposal) -----------------
  step(1, "Intent shaping: a two-estate proposal (untrusted)");
  goal(
    "Alice's agent drafts an over-broad two-estate proposal (payments plus the LedgerCloud SaaS ledger).",
    "nothing is granted here; the proposal is untrusted input the issuer will bound at approval.",
  );
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

  act(
    stack,
    "II",
    "Consent and issuance",
    "The real OAuth dance mints a mission-bound token pair, narrowed by the issuer to the policy ceiling.",
  );

  // ---- 2. REAL issuance: PAR -> authorize -> approve -> token --------------
  step(2, "Real issuance: the live OAuth dance mints a real token pair");
  goal(
    "The agent runs the real OAuth dance (PAR, authorize, Bob approves, token) to mint a mission-bound token pair.",
    "the issuer narrows the proposal to the policy ceiling: bogus vendor.delete dropped, vendors reduced to acme, cap 999999 to 500; a real access token and id_token are issued.",
  );
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
    `${C.yellow}  narrowing:${C.reset} proposed ${gloss("action", "payments:vendor.delete")} ${C.red}dropped${C.reset}; ` +
      `vendors acme,globex,evilcorp ${C.green}→ acme${C.reset}; cap 999999.00 ${C.green}→ 500.00${C.reset} (SaaS estate preserved)`,
  );
  note("subject alice != approver bob (write-bearing missions need a distinct approver).");

  block("raw access_token (compact JWS, signature truncated)", truncTok(issued.accessToken));
  block("raw id_token (compact JWS, signature truncated)", truncTok(issued.idToken));
  focusedMissionId = missionId;
  rail(stack);

  act(
    stack,
    "III",
    "Doing the work",
    "The resource server validates the token, then the agent runs the mission's tool calls, including two just-in-time approval bindings.",
  );

  // ---- 3. Validate the real token at the resource server ------------------
  step(3, "Validate the real token at the resource server");
  goal(
    "The payments resource server validates the real access token before trusting it.",
    "the signature verifies against the AS jwks, the DPoP proof jkt matches the token cnf.jkt, and the mission claim is present.",
  );
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
  goal(
    "The agent re-reads the catalog now that an active mission covers payments.",
    "the payments connection reflects the active mission, no longer just consent_required.",
  );
  hop("Agent", "AS", "GET /service-catalog?type=mcp", `in-process; represents GET ${asUrl}/service-catalog`);
  block(
    "catalog payments connection",
    stack.catalog.catalog("alice", { type: "mcp" }).services.find((s) => s.id === "payments")?.connections,
  );

  // ---- Tool-call tracer (real token) --------------------------------------
  const traceCall = async (
    n: number,
    label: string,
    kind: "read" | "wire",
    tool: string,
    args: Record<string, unknown>,
    g: { task: string; expect: string },
  ) => {
    step(n, label);
    goal(g.task, g.expect);
    hop("Agent", "Payments RS", `tools/call ${gloss("tool", tool)}`, "in-process MCP · O-33");
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
    outcome({
      decision: res.ok ? "PERMIT" : "DENY",
      ...(res.ok ? {} : { reason: gloss("reason", res.denial_reason ?? res.refusal_reason ?? "") }),
      observed: res.ok ? `${gloss("tool", tool)} returned ${JSON.stringify(res.result)}` : `${gloss("tool", tool)} denied`,
      ok: res.ok,
    });
    return res;
  };

  // ---- 5. Read tool -------------------------------------------------------
  await traceCall(5, "Read tool call: in-authority (get_invoice)", "read", "get_invoice", { invoice_id: "inv-1" }, {
    task: "The agent calls get_invoice, a read squarely inside the mission's authority.",
    expect: "the PDP permits; the invoice is returned.",
  });
  // ---- 6. Wire transfer ---------------------------------------------------
  await traceCall(
    6,
    "Wire transfer: transaction-assurance tier (execute_wire_transfer)",
    "wire",
    "execute_wire_transfer",
    { invoice_id: "inv-1" },
    {
      task: "The agent executes a wire transfer for inv-1, a transaction-tier action within cap and vendor bounds.",
      expect: "the PDP permits; the transfer executes.",
    },
  );

  // ---- 7. JIT access via AROP Transaction Challenge ----------------------
  step(7, "JIT access: an in-mission action, gated behind a per-action approval (AROP)");
  goal(
    "The agent attempts send_remittance_email, an in-authority action that deployment policy gates behind a per-action approval.",
    "the first call is denied pending a challenge; after Bob approves over the wire, the re-presented txn-token lets it through.",
  );
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
  outcome({
    decision: "DENY",
    reason: gloss("reason", challengeAttempt.denial_reason ?? challengeAttempt.refusal_reason ?? ""),
    observed: `${gloss("tool", "send_remittance_email")}(inv-1) denied ${challengeAttempt.denial_reason ?? challengeAttempt.refusal_reason ?? ""}; the RS returns an access_challenge to present`,
    ok: !challengeAttempt.ok && (challengeAttempt.denial_reason ?? challengeAttempt.refusal_reason) === "action_approval_required",
  });
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
  outcome({
    decision: granted.ok ? "PERMIT" : "DENY",
    ...(granted.ok ? {} : { reason: gloss("reason", granted.denial_reason ?? granted.refusal_reason ?? "") }),
    observed: granted.ok
      ? `${gloss("tool", "send_remittance_email")}(inv-1) executed with the txn-token: ${JSON.stringify(granted.result)}`
      : `${gloss("tool", "send_remittance_email")}(inv-1) denied`,
    ok: granted.ok,
  });
  note("The approval was carried by the AS-issued txn-token, never as a tool input. The mission was never widened; the gate sat inside the mission's authority.");

  // ---- 8. AROP over DTR: deferred token response on the real /token endpoint --
  step(8, "AROP over DTR: a deferred token response, approved just-in-time (real /token)");
  goal(
    "The agent asks the /token endpoint itself for a mission-subset credential, deferred until Bob approves.",
    "the AS returns a deferral to poll; once Bob approves, a real resource-bound mission token is issued, single-use.",
  );
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
  outcome({
    decision: "PERMIT",
    observed: `deferred grant issued a real mission token (aud=${dtrClaims.aud as string}); mission id matches ${missionId}, cnf.jkt matches the base token, single-use handle consumed`,
    ok: dtrOk,
  });
  note(
    `mission.id == active mission ${missionId} (unchanged, D42); cnf.jkt ${(dtrClaims.cnf as { jkt: string }).jkt === issued.dpopJkt ? "==" : "!="} base token jkt; ` +
      `NOT opaque (3-segment JWT, aud-bound); exp <= approved_until.`,
  );

  act(
    stack,
    "IV",
    "Cross-domain continuation",
    "The mission carries across domains: an ID-JAG grant into the LedgerCloud SaaS estate.",
  );

  // ---- 9. Cross-domain: the ID-JAG leg into the SaaS estate ---------------
  step(9, "Cross-domain: an ID-JAG grant crosses into the LedgerCloud (SaaS) estate");
  goal(
    "The agent carries the mission across domains: an ID-JAG grant is redeemed at the LedgerCloud RAS, then a journal entry is posted.",
    "the RAS mints a local SaaS token, the post succeeds, and a second redemption of the same grant is rejected (single-use).",
  );
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
  outcome({
    decision: saasCall.ok ? "PERMIT" : "DENY",
    ...(saasCall.ok ? {} : { reason: saasCall.error ?? "" }),
    observed: saasCall.ok ? `post_journal_entry(acme, $125.00) returned ${JSON.stringify(saasCall.result)}` : "post_journal_entry denied",
    ok: saasCall.ok,
  });

  // Replay: the ID-JAG grant is single-use (one-time jti).
  let replayFailed = false;
  try {
    await as.ras.redeem(grant.grant, issued.dpopJkt);
  } catch (e) {
    replayFailed = true;
    const code = (e as { code?: string }).code ?? "error";
    block("replay rejected", { error: code, message: (e as Error).message });
    outcome({
      decision: "DENY",
      reason: code,
      observed: `second redemption of the SAME grant rejected ${code} (single-use)`,
      ok: code === "invalid_grant",
    });
  }
  if (!replayFailed) throw new Error("expected the ID-JAG replay to fail invalid_grant");

  act(
    stack,
    "V",
    "Authority boundaries",
    "The token is valid and its bounds still bind: a wire over the cap and a wire to an unlisted vendor are both denied by design.",
  );

  // ---- 10. Denials --------------------------------------------------------
  step(10, "Denials: valid token, but out of bounds / authority");
  goal(
    "The agent pushes past the mission's bounds: a wire over the cap, then a wire to an unlisted vendor.",
    "both are denied by design (over the 500 cap; vendor not in the mission's allowlist).",
  );
  hop("Agent", "Payments RS", "tools/call execute_wire_transfer (inv-2, over-cap)", "in-process MCP · O-33");
  const over = await stack.server.callTransactionTool("execute_wire_transfer", { invoice_id: "inv-2" }, facts);
  hop("Payments RS (PEP)", "PDP", "evaluate", "in-process · D28");
  hop("PDP", "OpenFGA", "check", "HTTP https://localhost:8080");
  if (captured) block("PDP decision (over-cap $900)", captured.decision);
  outcome({
    decision: "DENY",
    reason: gloss("reason", over.denial_reason ?? over.refusal_reason ?? ""),
    observed: `${gloss("tool", "execute_wire_transfer")}(inv-2, $900) denied ${over.denial_reason ?? over.refusal_reason ?? ""} (over the 500 cap)`,
    ok: !over.ok && over.denial_reason === "constraint_exceeded",
  });
  hop("Agent", "Payments RS", "tools/call execute_wire_transfer (inv-3, globex)", "in-process MCP · O-33");
  const globex = await stack.server.callTransactionTool("execute_wire_transfer", { invoice_id: "inv-3" }, facts);
  hop("Payments RS (PEP)", "PDP", "evaluate", "in-process · D28");
  hop("PDP", "OpenFGA", "check", "HTTP https://localhost:8080");
  if (captured) block("PDP decision (globex vendor)", captured.decision);
  outcome({
    decision: "DENY",
    reason: gloss("reason", globex.denial_reason ?? globex.refusal_reason ?? ""),
    observed: `${gloss("tool", "execute_wire_transfer")}(inv-3, globex) denied ${globex.denial_reason ?? globex.refusal_reason ?? ""} (vendor not in the mission's allowlist)`,
    ok: !globex.ok && globex.denial_reason === "out_of_authority",
  });

  act(
    stack,
    "VI",
    "Mission lifecycle",
    "The operator drives the mission's lifecycle (suspend, resume, contain, expand, supersede, revoke); then Olivia reads the tamper-evident feed.",
  );

  // ---- 10. Lifecycle ------------------------------------------------------
  // MUST run AFTER the cross-domain leg and all tool calls: these transitions
  // drive the mission non-active / superseded and deny everything downstream.
  step(11, "Lifecycle: transitions that gate everything downstream");
  goal(
    "The operator drives the mission through its lifecycle: suspend, resume, contain a tainted capability, expand via a fresh approval, supersede, and revoke.",
    "each transition gates what follows: suspended and superseded tokens are denied, containment removes one capability while others still permit, and the successor restores it.",
  );
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
  rail(stack);
  hop("Agent", "Payments RS", "tools/call get_invoice (while suspended)", "in-process MCP · O-33");
  const whileSuspended = await stack.server.callReadTool("get_invoice", { invoice_id: "inv-1" }, facts);
  if (captured) block("PDP decision (suspended)", captured.decision);
  outcome({
    decision: "DENY",
    reason: gloss("reason", whileSuspended.denial_reason ?? whileSuspended.refusal_reason ?? ""),
    observed: `${gloss("tool", "get_invoice")}(inv-1) while suspended denied ${whileSuspended.denial_reason ?? whileSuspended.refusal_reason ?? ""}`,
    ok: !whileSuspended.ok && whileSuspended.denial_reason === "mission_inactive",
  });

  // 10b. resume -> the action is permitted again.
  hop("Operator", "AS", "POST /missions/{id}/lifecycle (resume)", "HTTP");
  httpReq("POST", `${asUrl}/missions/${missionId}/lifecycle`, {
    headers: { "content-type": "application/json", "x-service-token": "<service token>" },
    body: { operation: "resume" },
  });
  const resumeRes = await lifecycle("resume", missionId);
  httpRes(resumeRes.status, resumeRes.body);
  rail(stack);
  hop("Agent", "Payments RS", "tools/call get_invoice (after resume)", "in-process MCP · O-33");
  const afterResume = await stack.server.callReadTool("get_invoice", { invoice_id: "inv-1" }, facts);
  if (captured) block("PDP decision (resumed)", captured.decision);
  outcome({
    decision: afterResume.ok ? "PERMIT" : "DENY",
    ...(afterResume.ok ? {} : { reason: gloss("reason", afterResume.denial_reason ?? afterResume.refusal_reason ?? "") }),
    observed: afterResume.ok
      ? `${gloss("tool", "get_invoice")}(inv-1) permitted again: ${JSON.stringify(afterResume.result)}`
      : `${gloss("tool", "get_invoice")}(inv-1) denied`,
    ok: afterResume.ok,
  });

  // 10c. Containment: a protected event narrows the EFFECTIVE authority while
  // the approved authority_set/authority_hash stay immutable. A simulated
  // tainted read is reported via the lifecycle contain operation; the issuer
  // removes payments:remittance.send. The PDP now denies exactly that action
  // authority_contained (approved, then narrowed — distinct from
  // out_of_authority, never approved) while other actions still permit.
  const containBody = {
    operation: "contain",
    event: {
      type: "tainted_read",
      source: "https://siem.example/detections",
      observed_at: new Date().toISOString(),
      event_id: "taint-exhibit-1",
    },
    remove: [{ resource: CANONICAL_RESOURCE, actions: ["payments:remittance.send"] }],
  };
  hop("SIEM / Operator", "AS", "POST /missions/{id}/lifecycle (contain: tainted read)", "HTTP");
  httpReq("POST", `${asUrl}/missions/${missionId}/lifecycle`, {
    headers: { "content-type": "application/json", "x-service-token": "<service token>" },
    body: containBody,
  });
  const containRes = await fetch(`${asUrl}/missions/${missionId}/lifecycle`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-service-token": DEV_SERVICE_TOKEN },
    body: JSON.stringify(containBody),
  });
  httpRes(containRes.status, await containRes.json());
  rail(stack);
  hop("Agent", "Payments RS", "tools/call send_remittance_email (contained capability)", "in-process MCP · O-33");
  const containedCall = await stack.server.callTransactionTool("send_remittance_email", { invoice_id: "inv-1" }, facts);
  if (captured) block("PDP decision (contained capability)", captured.decision);
  outcome({
    decision: "DENY",
    reason: gloss("reason", containedCall.denial_reason ?? containedCall.refusal_reason ?? ""),
    observed: `${gloss("tool", "send_remittance_email")}(inv-1) after contain denied ${containedCall.denial_reason ?? containedCall.refusal_reason ?? ""}`,
    ok: !containedCall.ok && containedCall.denial_reason === "authority_contained",
  });
  hop("Agent", "Payments RS", "tools/call get_invoice (uncontained action)", "in-process MCP · O-33");
  const uncontainedCall = await stack.server.callReadTool("get_invoice", { invoice_id: "inv-1" }, facts);
  outcome({
    decision: uncontainedCall.ok ? "PERMIT" : "DENY",
    ...(uncontainedCall.ok ? {} : { reason: gloss("reason", uncontainedCall.denial_reason ?? uncontainedCall.refusal_reason ?? "") }),
    observed: uncontainedCall.ok
      ? `${gloss("tool", "get_invoice")}(inv-1) still permits: ${JSON.stringify(uncontainedCall.result)}`
      : `${gloss("tool", "get_invoice")}(inv-1) denied`,
    ok: uncontainedCall.ok,
  });
  note("containment is removal-only and versioned; restore exists only via the Expansion successor below.");

  // 10d. Expansion: a successor mission from a fresh approval that widens authority.
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
  note(
    `successor carries NO containment (containment = ${JSON.stringify(stack.kernel.get(expansion.successor.id)?.containment ?? null)}): ` +
      "the fresh approval restores payments:remittance.send that containment removed from the predecessor.",
  );

  // Supersession: on the successor's first redemption the predecessor is superseded atomically.
  hop("Operator", "AS", "supersede predecessor on the successor's first redemption (kernel op)", "in-process");
  stack.kernel.supersedeOnRedemption(expansion.successor.id);
  note(`predecessor ${missionId} state → ${stack.kernel.get(missionId)?.state}`);
  rail(stack);
  hop("Agent", "Payments RS", "tools/call get_invoice (original token, predecessor superseded)", "in-process MCP · O-33");
  const afterSupersede = await stack.server.callReadTool("get_invoice", { invoice_id: "inv-1" }, facts);
  if (captured) block("PDP decision (predecessor superseded)", captured.decision);
  outcome({
    decision: "DENY",
    reason: gloss("reason", afterSupersede.denial_reason ?? afterSupersede.refusal_reason ?? ""),
    observed: `${gloss("tool", "get_invoice")}(inv-1) with the original token denied ${afterSupersede.denial_reason ?? afterSupersede.refusal_reason ?? ""}`,
    ok: !afterSupersede.ok && afterSupersede.denial_reason === "mission_inactive",
  });
  note("the original credential no longer authorizes; the successor is the active mission going forward.");
  focusedMissionId = expansion.successor.id;
  rail(stack);

  // 10e. revoke the successor over the wire.
  hop("Operator", "AS", "POST /missions/{id}/lifecycle (revoke successor)", "HTTP");
  httpReq("POST", `${asUrl}/missions/${expansion.successor.id}/lifecycle`, {
    headers: { "content-type": "application/json", "x-service-token": "<service token>" },
    body: { operation: "revoke" },
  });
  const revokeRes = await lifecycle("revoke", expansion.successor.id);
  httpRes(revokeRes.status, revokeRes.body);
  rail(stack);

  // ---- 11. Evidence -------------------------------------------------------
  step(12, "Evidence: the tamper-evident feed, verified");
  goal(
    "Olivia reads the tamper-evident evidence feed for the mission.",
    "every evidence row verifies against the transparency log.",
  );
  hop("Operator (Olivia)", "Transparency", "read verified timeline", "in-process");
  for (const ev of stack.evidence.forMission(missionId)) {
    const t = ev.kind === "decision" ? "decision-evidence" : ev.kind === "execution" ? "execution-evidence" : "refusal-record";
    await stack.publishEvidence(missionId, t, ev as unknown as Record<string, unknown>);
  }
  const op = stack.bff.sessions.create("olivia", ["operator"]);
  for (const row of await stack.bff.timeline(op, missionId)) {
    console.log(`  ${row.verified ? C.green + "✓ VERIFIED" : C.red + "✗ FAILED  "}${C.reset} ${row.evidence_type} ${C.dim}from ${row.producer}${C.reset}`);
  }

  // ---- 13-19. Agent Access Model (Nightly Reconciliation) -----------------
  // A second, self-contained chapter on the SAME live stack: Cloudflare's AAM
  // run narrated entirely in Mission vocabulary (its own Template + dispatched
  // missions; independent of the primary mission superseded/revoked above).
  await runAamSection(stack, as, asUrl);

  console.log(
    `\n${C.green}${C.bold}Exhibit complete.${C.reset} ${C.dim}Real issuance (access + id token), RS validation, tool calls, cross-domain ID-JAG, lifecycle, and evidence — plus the AAM Nightly Reconciliation walk — all on the same live stack.${C.reset}`,
  );
  as.closeAuthServer();
  process.exit(0);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
