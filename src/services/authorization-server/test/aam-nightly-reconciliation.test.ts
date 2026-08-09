/**
 * Cloudflare's Agent Access Model "Nightly Reconciliation", expressed ENTIRELY
 * in Mission vocabulary and driven end-to-end against the LIVE stack: the real
 * AS over HTTP, the OpenFGA-backed PDP, the real payments PEP, the real egress
 * gate, and the real console-bff activity-log join. Each `it()` is one AAM step;
 * the AAM -> Mission mapping is narrated in the names and comments. See AAM.md.
 *
 * AAM component            -> Mission realization exercised here
 *   Task Template + ceiling ->  oauth-mission-template + POST /templates
 *   Agent Identity Broker   ->  the mission-dispatch grant (low-consequence) +
 *                                an ordinary human approval (external-commitment)
 *   Task-Scoped Access Eng. ->  the PDP (@mission/pdp evaluate over OpenFGA)
 *   Mediation Layer         ->  the payments PEP + the harness EgressGate
 *   Trust Ratchet           ->  Mission Containment (protected-event ingestion)
 *   Agent Activity Log      ->  ConsoleBff.activityLog() (the console-bff join)
 *
 * @spec draft-mcguinness-oauth-mission-template#prohibited-classes: the
 * Template draft forbids a Dispatch from ever conferring a prohibited class
 * (external-commitment among them), even when that class sits inside the
 * Template Ceiling. Bob's consent ceiling below still names
 * payments:remittance.send (the nightly job's whole scope, consented once),
 * but every dispatch attempt that would grant it is refused
 * dispatch_prohibited_class: the Template only ever instantiates the
 * low-consequence read and reconcile slice at machine speed. The actual
 * remittance runs under a SEPARATE, ordinarily-approved Mission (a `direct`
 * approval_basis) that a human approved, never under a dispatched instance.
 * Containment (the Trust Ratchet) applies to whichever Mission actually
 * holds the capability, not only to a dispatched instance (step 6).
 *
 * Auto-skips only when OpenFGA is unreachable (docker compose up); with the
 * gate up this file runs all eight steps (0 skipped).
 */

import { type Server } from "node:http";
import {
  CANONICAL_RESOURCE,
  type CeilingEntry,
  DERIVATION_POLICY,
  DEV_SERVICE_TOKEN,
  type SeededTrustedSource,
} from "@mission/demo-data";
import {
  EvidenceStore,
  PaymentsStore,
  Pep,
  sourceDigestOf,
  type TokenFacts,
} from "@mission/mcp-payments";
import {
  evaluate,
  Fga,
  type MissionView,
  relationForAction,
  stalenessBoundSeconds,
} from "@mission/pdp";
import {
  calculateJwkThumbprint,
  type CryptoKey,
  decodeJwt,
  exportJWK,
  generateKeyPair,
  importJWK,
  SignJWT,
} from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { EgressGate, type EgressRefusal } from "../../agent/src/egress-gate.js";
import { buildScopeStatement, scopeDigest } from "../../agent/src/harness-scope.js";
import { ConsoleBff } from "../../console-bff/src/index.js";
import { ACCESS_TOKEN_TOKEN_TYPE, TOKEN_EXCHANGE_GRANT_TYPE } from "../src/adapters/continuation-grant.js";
import { MISSION_DISPATCH_GRANT_TYPE } from "../src/adapters/provider.js";
import { type BuiltAs, buildAuthorizationServer } from "../src/index.js";

const PORT = 14501;
const ISSUER = `http://localhost:${PORT}`;
const RESOURCE = CANONICAL_RESOURCE;
const FAR_FUTURE = "2099-01-01T00:00:00Z";
// The consent ceiling's bounded lifetime (the AAM "bounded task budget"). Well
// below FAR_FUTURE, so the clamp is observable but never expires mid-run.
const LIFETIME_S = 900;
const ANTHROPIC = "https://api.anthropic.com";
const TAINT_EVENT_ID = "aam-taint-1";

const API_URL = process.env.OPENFGA_HTTP_URL ?? "https://localhost:8080";
const KEY = process.env.OPENFGA_PRESHARED_KEY ?? "dev-preshared-key-change-me";
const CA = process.env.OPENFGA_CA_CERT;

async function reachable(): Promise<boolean> {
  try {
    if (CA) process.env.NODE_EXTRA_CA_CERTS = CA;
    const res = await fetch(`${API_URL}/healthz`, { headers: { authorization: `Bearer ${KEY}` } });
    return res.ok;
  } catch {
    return false;
  }
}

const up = await reachable();
const d = up ? describe : describe.skip;
if (!up) console.warn("OpenFGA unreachable; skipping AAM nightly-reconciliation e2e (docker compose up)");

type DpopKeys = { privateKey: CryptoKey; publicKey: CryptoKey };

let as: BuiltAs;
let asServer: Server;
let fga: Fga;
let modelId: string;
let clientKey: CryptoKey; // the dispatcher (ap-agent) private_key_jwt key
let dpopKeys: DpopKeys; // the dispatcher's DPoP key (binds the dispatched token)
let dispatcherJkt: string;
let payments: PaymentsStore;
let pep: Pep;
let pepEvidence: EvidenceStore;
let egressEvidence: EvidenceStore;
const egressRefusals: EgressRefusal[] = [];
let seq = 0;

// The harness egress scope statement: inference_api is mediated to a single
// destination; transport in_memory forces containment_claim: "none" (the honest
// downgrade; see AAM.md). The gate itself is built in step 4, once the
// dispatched Mission id exists.
const SCOPE_STATEMENT = buildScopeStatement({
  isolation_mechanism: "in-process AAM reference demo (no isolation boundary)",
  transport: "in_memory",
  mediated_action_classes: ["payments"],
  excluded_unmediated_paths: ["direct process network access"],
  channel_classes: [{ channel_class: "inference_api", disposition: "mediated", destinations: [ANTHROPIC] }],
});

// State threaded across the eight sequential steps.
let templateId = "";
let templateHash = "";
let dispatchedMissionId = ""; // low-consequence, machine-speed (Template-dispatched)
let dispatchedAccessToken = "";
let familyRefreshToken = "";
let humanMissionId = ""; // the external-commitment capability, human-approved
let restoredHumanMissionId = "";

// --- Auth helpers (ap-agent = the scheduler/dispatcher client) ---------------

async function clientAssertion(): Promise<string> {
  return new SignJWT({})
    .setProtectedHeader({ alg: "ES256", kid: "ap-agent-auth" })
    .setIssuer("ap-agent")
    .setSubject("ap-agent")
    .setAudience(ISSUER)
    .setIssuedAt()
    .setExpirationTime("2m")
    .setJti(crypto.randomUUID())
    .sign(clientKey);
}

async function dpopProof(htu: string, htm: string, extra: Record<string, unknown> = {}): Promise<string> {
  return new SignJWT({ htu, htm, ...extra })
    .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: await exportJWK(dpopKeys.publicKey) })
    .setIssuedAt()
    .setJti(crypto.randomUUID())
    .sign(dpopKeys.privateKey);
}

/** POST /token with private_key_jwt + DPoP and the mandatory dpop-nonce retry. */
async function tokenRequest(params: Record<string, string>): Promise<Response> {
  const htu = `${ISSUER}/token`;
  const send = async (extra: Record<string, unknown> = {}): Promise<Response> =>
    fetch(htu, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", dpop: await dpopProof(htu, "POST", extra) },
      body: new URLSearchParams({
        ...params,
        client_assertion: await clientAssertion(),
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      }).toString(),
    });
  let res = await send();
  const nonce = res.headers.get("dpop-nonce");
  if (res.status === 400 && nonce) res = await send({ nonce });
  return res;
}

async function createTemplateAdmin(body: unknown): Promise<Response> {
  return fetch(`${ISSUER}/templates`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-service-token": DEV_SERVICE_TOKEN },
    body: JSON.stringify(body),
  });
}

async function dispatch(params: { intent: string; dispatchEventId: string }): Promise<Response> {
  return tokenRequest({
    grant_type: MISSION_DISPATCH_GRANT_TYPE,
    template_id: templateId,
    mission_intent: params.intent,
    dispatch_event_id: params.dispatchEventId,
  });
}

/** The RFC 8693 request_refresh_token exchange: a base mission access token in,
 *  a rotated, sender-constrained refresh-token FAMILY out (async-delegation). */
async function asyncDelegate(baseAccessToken: string): Promise<Response> {
  return tokenRequest({
    grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
    request_refresh_token: "true",
    subject_token: baseAccessToken,
    subject_token_type: ACCESS_TOKEN_TOKEN_TYPE,
    resource: RESOURCE,
  });
}

/** A disconnected refresh: native grant_type=refresh_token against the family. */
async function refreshFamily(refreshToken: string): Promise<Response> {
  return tokenRequest({ grant_type: "refresh_token", refresh_token: refreshToken });
}

/**
 * Mint an ORDINARY, human-approved Mission directly at the kernel (the
 * `direct` approval_basis path {@link ApproveInput}): approver bob, subject
 * alice (write-bearing missions need a distinct approver, per Governance D37),
 * never a Dispatcher, never a Template. This is the "human path" the
 * prohibited-class rule requires for payments:remittance.send.
 */
function approveHumanMission(intentJson: string): { id: string } {
  const intent = as.kernel.validateIntent(intentJson);
  const record = as.kernel.approve({
    intent,
    subject: { iss: ISSUER, sub: "alice" },
    approver: { iss: ISSUER, sub: "bob" },
    clientId: "ap-agent",
    approvalEventId: `aam-human-evt-${seq++}`,
  });
  return { id: record.id };
}

// --- The consent ceiling + intents ------------------------------------------

/**
 * The read-only reconciliation ceiling PLUS the single external-communication
 * capability (payments:remittance.send = "post to one finance channel"), built
 * programmatically from the derivation policy so every entry stays entry-wise
 * within it: keep read/list actions and remittance.send, copy constraints
 * verbatim, drop delegation, keep CANONICAL_RESOURCE (so containment's
 * resource-remap targets the same resource the Mission holds). Consenting to
 * this ceiling does NOT mean a Dispatch may ever instantiate remittance.send:
 * the prohibited-class rule blocks that regardless of ceiling membership; see
 * lowConsequenceIntent() below for what actually gets dispatched.
 */
function reconciliationCeiling(): CeilingEntry[] {
  const keep = (a: string) => a.endsWith(".read") || a.endsWith(".list") || a === "payments:remittance.send";
  return DERIVATION_POLICY.ceiling
    .map((e) => {
      const entry: CeilingEntry = { type: e.type, resource: e.resource, actions: e.actions.filter(keep) };
      if (e.constraints) entry.constraints = e.constraints;
      return entry;
    })
    .filter((e) => e.actions.length > 0);
}

function reconciliationTemplateBody(): Record<string, unknown> {
  return {
    template_version: "aam-nightly-reconciliation-1",
    issuer: ISSUER,
    approver: { iss: ISSUER, sub: "bob" }, // the consenting human of record
    ceiling: reconciliationCeiling(),
    dispatch_policy: "aam-nightly-reconciliation",
    dispatchers: ["ap-agent"], // the scheduler dispatches
    recipients: ["subagent-invoice-extractor"], // the reconciliation sub-agent receives
    per_instance_lifetime_s: LIFETIME_S,
    max_active: 5,
    rate_per_min: 30,
    approval_event_id: `aam-tmpl-evt-${seq++}`,
    expires_at: FAR_FUTURE,
  };
}

/**
 * The LOW-CONSEQUENCE dispatch intent: read only. This is the only intent a
 * machine-speed Dispatch of this Template ever successfully instantiates.
 */
function lowConsequenceIntent(): string {
  return JSON.stringify({
    goal: "nightly reconciliation of Acme invoices (read-only)",
    resources: [RESOURCE],
    expires_at: FAR_FUTURE,
    proposed_authority: [
      {
        type: "mission_resource_access",
        resource: RESOURCE,
        actions: ["payments:invoice.read"],
        constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
      },
    ],
  });
}

/**
 * The PROHIBITED-CLASS intent: read invoices + post the finance remittance.
 * `payments:remittance.send` is within the Template Ceiling, but a Dispatch of
 * this intent MUST be refused dispatch_prohibited_class (external_commitment).
 * The same JSON string is reused, unmodified, as the mission_intent of the
 * ordinary human approval below: one intent, two paths, one of which the
 * Template refuses and one of which a human approves.
 */
function reconciliationIntent(): string {
  return JSON.stringify({
    goal: "nightly reconciliation of Acme invoices",
    resources: [RESOURCE],
    expires_at: FAR_FUTURE,
    proposed_authority: [
      {
        type: "mission_resource_access",
        resource: RESOURCE,
        actions: ["payments:invoice.read", "payments:remittance.send"],
        constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
      },
    ],
  });
}

/** An intent that exceeds the read/post ceiling (payment.schedule is in POLICY
 *  but was filtered out of this template's ceiling). */
function overCeilingIntent(): string {
  return JSON.stringify({
    goal: "schedule a payment (exceeds the reconciliation ceiling)",
    resources: [RESOURCE],
    expires_at: FAR_FUTURE,
    proposed_authority: [
      {
        type: "mission_resource_access",
        resource: RESOURCE,
        actions: ["payments:payment.schedule"],
        constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
      },
    ],
  });
}

// --- PDP + PEP helpers -------------------------------------------------------

/** The PDP's view of a Mission (kernel record -> MissionView incl. the containment delta). */
function viewFor(missionId: string): MissionView {
  const r = as.kernel.get(missionId);
  if (!r) throw new Error(`mission ${missionId} missing`);
  const fresh = as.kernel.applyExpiry(r);
  return {
    id: fresh.id,
    issuer: fresh.issuer,
    state: fresh.state,
    version: fresh.version,
    authority_hash: fresh.authority_hash,
    authority_set: fresh.authority_set,
    ...(fresh.containment
      ? { containment: { version: fresh.containment.containment_version, contained: fresh.containment.contained } }
      : {}),
  };
}

const loadView = (id: string): MissionView | undefined => (as.kernel.get(id) ? viewFor(id) : undefined);

/** A raw PDP decision for one Mission action (the Task-Scoped Access Engine). */
const evalAction = async (missionId: string, action: string) => {
  const view = viewFor(missionId);
  return evaluate(
    {
      subject: { id: as.kernel.get(missionId)?.subject.sub ?? "unknown" },
      resource: { type: "invoice", id: "inv-1", properties: { vendor_id: "acme" } },
      action: { name: action },
      context: { audience: RESOURCE, mission: { id: view.id, authority_hash: view.authority_hash } },
    },
    { view, fga, modelId, now: () => new Date(), stalenessBoundSeconds, relationForAction },
  );
};

/** TokenFacts the PEP enforces from (token validation is upstream of the PEP). */
function tokenFactsFor(missionId: string): TokenFacts {
  const r = as.kernel.get(missionId);
  if (!r) throw new Error(`mission ${missionId} missing`);
  return {
    sub: r.subject.sub,
    clientId: "subagent-invoice-extractor",
    clientInstanceId: "aam-reconciler-inst",
    mission: { id: r.id, authority_hash: r.authority_hash },
    cnfJkt: dispatcherJkt,
  };
}

d("AAM Nightly Reconciliation, realized on Missions", () => {
  beforeAll(async () => {
    as = await buildAuthorizationServer({ issuer: ISSUER, allowHeadlessAdjudication: true });
    asServer = as.provider.listen(PORT);
    clientKey = (await importJWK(as.agentClientJwk as never, "ES256")) as CryptoKey;
    dpopKeys = await generateKeyPair("ES256", { extractable: true });
    dispatcherJkt = await calculateJwkThumbprint(await exportJWK(dpopKeys.publicKey));

    const conn = await Fga.connect({ apiUrl: API_URL, presharedKey: KEY, caCertPath: CA });
    fga = conn.fga;
    modelId = conn.modelId;

    // The authoritative payments store the PEP reads effective params from.
    payments = new PaymentsStore();
    payments.seed(
      [{ id: "acme", name: "Acme", status: "approved" }],
      [{ id: "inv-1", vendor_id: "acme", amount: "125.00", currency: "USD", payee_account: "acct-acme", status: "payable" }],
    );
    pepEvidence = new EvidenceStore();
    pep = new Pep({
      payments,
      evidence: pepEvidence,
      fga,
      modelId,
      loadView,
      instanceEpoch: "aam-epoch",
      sourceDigest: sourceDigestOf({ name: "payments", tools: ["get_invoice", "send_remittance_email"] }),
    });

    // The gate's own evidence store; the gate is built in step 4 (needs the mission id).
    egressEvidence = new EvidenceStore();
  });

  afterAll(() => {
    asServer?.close();
  });

  // STEP 1: Consent once. AAM Task Template + capability ceiling.
  it("step 1 (consent once): POST /templates records the reconciliation ceiling + human approver", async () => {
    const res = await createTemplateAdmin(reconciliationTemplateBody());
    const body = (await res.json()) as { template_id?: string; template_version?: string; template_hash?: string };
    expect(res.status, JSON.stringify(body)).toBe(201);
    expect(body.template_id).toMatch(/^tmpl_/);
    expect(body.template_version).toBeTruthy();
    expect(body.template_hash).toMatch(/^sha-256:/);
    templateId = body.template_id as string;
    templateHash = body.template_hash as string;

    // The human approver of record is recorded on the Template (consent once).
    const stored = as.templateStore.get(templateId);
    expect(stored?.approver.sub).toBe("bob");
    // The ceiling carries the external-comms capability, consented to once for
    // the WHOLE nightly job, but consent to the ceiling is not consent for a
    // Dispatch to ever confer it (step 2 refuses every attempt).
    const ceilingActions = (stored?.ceiling ?? []).flatMap((e) => e.actions);
    expect(ceilingActions).toContain("payments:invoice.read");
    expect(ceilingActions).toContain("payments:remittance.send");
    expect(ceilingActions).not.toContain("payments:payment.schedule");
  });

  // STEP 2: Machine-speed dispatch, kept low-consequence. AAM Agent Identity Broker.
  it("step 2 (machine-speed dispatch): only the low-consequence read intent is admitted; remittance and over-ceiling are both refused", async () => {
    const res = await dispatch({ intent: lowConsequenceIntent(), dispatchEventId: `evt-dispatch-${seq++}` });
    const body = (await res.json()) as {
      access_token?: string;
      token_type?: string;
      mission_id?: string;
      authorization_details?: unknown;
    };
    expect(res.status, JSON.stringify(body)).toBe(200);
    expect(body.token_type).toBe("DPoP");
    expect(body.mission_id).toBeTruthy();
    dispatchedMissionId = body.mission_id as string;
    dispatchedAccessToken = body.access_token as string;

    const record = as.kernel.get(dispatchedMissionId);
    expect(record).toBeDefined();
    // Template lineage + approver-of-record == the template's human.
    expect(record?.template?.template_hash).toBe(templateHash);
    expect(record?.approver.sub).toBe("bob");
    // Authority Set == the template-clipped effective set (the dispatch response),
    // and it is READ-ONLY: the Dispatch never confers the prohibited class.
    expect(body.authorization_details).toEqual(as.kernel.effectiveAuthoritySet(record!));
    const actions = (body.authorization_details as Array<{ actions: string[] }>).flatMap((e) => e.actions);
    expect(actions).toContain("payments:invoice.read");
    expect(actions).not.toContain("payments:remittance.send");

    // @spec mission-template#prohibited-classes: the CONFORMANCE proof, an
    // intent that IS within the Template Ceiling (remittance.send is a
    // consented ceiling entry) is still refused, because it is a prohibited
    // class. This is what closes the finding: config now covers the class the
    // PEP classifies external_commitment, so no Dispatch can grant it.
    const prohibited = await dispatch({ intent: reconciliationIntent(), dispatchEventId: `evt-prohibited-${seq++}` });
    const prohibitedBody = (await prohibited.json()) as { mission_denial_reason?: string };
    expect(prohibited.status, JSON.stringify(prohibitedBody)).toBe(400);
    expect(prohibitedBody.mission_denial_reason).toBe("dispatch_prohibited_class");

    // A dispatch exceeding the ceiling is refused out_of_template_ceiling (a
    // DIFFERENT reason, distinguishing "not consented" from "consented but
    // too consequential for machine-speed dispatch").
    const refused = await dispatch({ intent: overCeilingIntent(), dispatchEventId: `evt-over-${seq++}` });
    const refusedBody = (await refused.json()) as { mission_denial_reason?: string };
    expect(refused.status, JSON.stringify(refusedBody)).toBe(400);
    expect(refusedBody.mission_denial_reason).toBe("out_of_template_ceiling");
  });

  // STEP 3: Disconnected run. AAM Agent Identity Broker (async-delegation transport).
  it("step 3 (disconnected run): the dispatched Mission obtains a refresh-token family clamped to its expiry", async () => {
    const record = as.kernel.get(dispatchedMissionId);
    // The Mission's absolute lifetime is bounded by the template (well below FAR_FUTURE).
    const missionExp = Math.floor(Date.parse(record?.expires_at as string) / 1000);
    expect(Date.parse(record?.expires_at as string)).toBeLessThan(Date.parse(FAR_FUTURE));

    const res = await asyncDelegate(dispatchedAccessToken);
    const body = (await res.json()) as {
      access_token?: string;
      token_type?: string;
      refresh_token?: string;
      error?: string;
    };
    expect(res.status, JSON.stringify(body)).toBe(200);
    expect(body.token_type).toBe("DPoP");
    expect(typeof body.refresh_token).toBe("string");
    familyRefreshToken = body.refresh_token as string;
    // The minted access token never outlives the Mission (absolute-lifetime clamp).
    const atExp = decodeJwt(body.access_token as string).exp as number;
    expect(atExp).toBeLessThanOrEqual(missionExp);

    // A disconnected refresh yields a FRESH access token + a rotated refresh token.
    const refreshed = await refreshFamily(familyRefreshToken);
    const rbody = (await refreshed.json()) as { access_token?: string; token_type?: string; refresh_token?: string };
    expect(refreshed.status, JSON.stringify(rbody)).toBe(200);
    expect(rbody.token_type).toBe("DPoP");
    expect(typeof rbody.access_token).toBe("string");
    expect(rbody.refresh_token).not.toBe(familyRefreshToken); // mandatory rotation
    expect((decodeJwt(rbody.access_token as string).mission as { id?: string })?.id).toBe(dispatchedMissionId);
  });

  // STEP 4: Per-action mediation. AAM Mediation Layer (PEP/PDP + egress gate).
  it("step 4 (per-action mediation): the read is permitted; remittance is out_of_authority on this mission; off-allowlist egress is refused", async () => {
    const token = tokenFactsFor(dispatchedMissionId);

    // A permitted tool call, mediated by the real PEP over the live PDP.
    const permit = await pep.enforce("get_invoice", { invoice_id: "inv-1" }, token);
    expect(permit.permitted, JSON.stringify(permit)).toBe(true);
    expect(
      pepEvidence
        .forMission(dispatchedMissionId)
        .some((e) => e.kind === "decision" && e.decision === true && e.action === "payments:invoice.read"),
    ).toBe(true);

    // The low-consequence dispatched Mission never held the external-comms
    // capability (step 2), so the PDP denies it out_of_authority: a SECOND,
    // independent line of defense behind the Dispatch-time refusal.
    const remittanceDecision = await evalAction(dispatchedMissionId, "payments:remittance.send");
    expect(remittanceDecision.decision).toBe(false);
    const remittanceAttempt = await pep.enforce("send_remittance_email", { invoice_id: "inv-1" }, token);
    expect(remittanceAttempt.permitted).toBe(false);
    expect(remittanceAttempt.denial_reason ?? remittanceAttempt.refusal_reason).toBe("out_of_authority");

    // The harness egress gate: an in-process reference realization bound to the
    // dispatched Mission, over the shared scope statement.
    const egressGate = new EgressGate({
      statement: SCOPE_STATEMENT,
      missionId: dispatchedMissionId,
      readState: async () => "active",
      evidence: egressEvidence,
      emitterId: "aam-egress-gate",
      instanceEpoch: "aam-epoch",
      onRefusal: (r) => egressRefusals.push(r),
    });
    // A permitted egress (the declared inference destination) passes the gate...
    const allowed = await egressGate.request("inference_api", `${ANTHROPIC}/v1/messages`);
    expect(allowed.permitted).toBe(true);

    // ...while an off-allowlist egress is refused and recorded by the gate.
    const refused = await egressGate.request("inference_api", "https://exfil.example.com/collect");
    expect(refused.permitted).toBe(false);
    expect(refused.refusal_reason).toBe("egress_destination_unlisted:https://exfil.example.com");
    const rec = egressEvidence.all().find((e) => e.kind === "egress" && e.outcome === "refused");
    expect(rec, "an egress refusal is recorded by the gate").toBeDefined();
    expect(egressRefusals.some((r) => r.refusal_reason.startsWith("egress_destination_unlisted"))).toBe(true);
  });

  // STEP 5: The human path. AAM Agent Identity Broker (approval-gated issuance,
  // never a Dispatch) for the external-commitment capability the Template may
  // not confer.
  it("step 5 (human path): the SAME intent a Dispatch refused is approved directly by a human, with a direct approval_basis", async () => {
    const { id } = approveHumanMission(reconciliationIntent());
    humanMissionId = id;
    const record = as.kernel.get(humanMissionId);
    expect(record).toBeDefined();
    // A direct approval_basis: a fresh human decision, NOT template lineage.
    expect(record?.approval_basis.type).toBe("direct");
    expect(record?.template).toBeUndefined();
    expect(record?.approver.sub).toBe("bob");
    expect(record?.subject.sub).toBe("alice"); // distinct approver (Governance D37)

    // The external-comms capability is genuinely granted here...
    expect((await evalAction(humanMissionId, "payments:remittance.send")).decision).toBe(true);

    // ...and the actual remittance now runs, mediated by the same PEP, under
    // THIS Mission, not under any Template-dispatched instance.
    const token = tokenFactsFor(humanMissionId);
    const send = await pep.enforce("send_remittance_email", { invoice_id: "inv-1" }, token);
    expect(send.permitted, JSON.stringify(send)).toBe(true);
  });

  // STEP 6: Protected event -> containment. AAM Trust Ratchet (Baseline -> Restricted).
  // Targets the human-approved Mission (the one actually holding the
  // external-comms capability); the low-consequence dispatched Mission from
  // step 2 is untouched, proving containment is Mission-scoped.
  it("step 6 (containment): a trusted SOC taint report contains the human-approved mission's remittance.send; the machine-speed mission is untouched", async () => {
    const soc = as.protectedEventSources.find((s) => s.source === "svc:soc") as SeededTrustedSource;
    expect(soc, "svc:soc seeded from config").toBeDefined();
    const key = (await importJWK(soc.privateJwk, soc.alg)) as CryptoKey;
    const jws = await new SignJWT({
      type: "content.tainted_read",
      source: "svc:soc",
      observed_at: new Date().toISOString(),
      event_id: TAINT_EVENT_ID,
      mission_id: humanMissionId,
    })
      .setProtectedHeader({ alg: soc.alg, kid: soc.kid })
      .setIssuedAt()
      .sign(key);
    const res = await fetch(`${ISSUER}/missions/${humanMissionId}/protected-events`, {
      method: "POST",
      headers: { "content-type": "application/protected-event+jwt" },
      body: jws,
    });
    const body = (await res.json()) as { containment_version?: number; removed?: unknown };
    expect(res.status, JSON.stringify(body)).toBe(200);
    expect(body.containment_version).toBe(1);
    expect(body.removed).toEqual([{ resource: RESOURCE, actions: ["payments:remittance.send"] }]);

    // The PDP now denies the external-comms action authority_contained...
    const contained = await evalAction(humanMissionId, "payments:remittance.send");
    expect(contained.decision).toBe(false);
    expect(contained.context.denial_reason).toBe("authority_contained");
    expect(contained.context.containment_version).toBe(1);
    // ...while the still-permitted read action on the SAME mission stays permitted.
    expect((await evalAction(humanMissionId, "payments:invoice.read")).decision).toBe(true);

    // Mediated through the real PEP, the contained action denies authority_contained
    // (this Decision Evidence is what threads into the Activity Log in step 8)...
    const humanToken = tokenFactsFor(humanMissionId);
    const send = await pep.enforce("send_remittance_email", { invoice_id: "inv-1" }, humanToken);
    expect(send.permitted).toBe(false);
    expect(send.denial_reason).toBe("authority_contained");

    // ...and the low-consequence, machine-speed dispatched Mission from step 2
    // is a DIFFERENT Mission: this containment event never named it, so its
    // read still permits, undisturbed by the human-approved mission's ratchet.
    const dispatchedToken = tokenFactsFor(dispatchedMissionId);
    const stillRead = await pep.enforce("get_invoice", { invoice_id: "inv-1" }, dispatchedToken);
    expect(stillRead.permitted).toBe(true);
    expect(as.kernel.get(dispatchedMissionId)?.containment).toBeUndefined();
  });

  // STEP 7: Restore only in a new task. AAM: capability returns via a fresh
  // human approval (a Dispatch can never restore a prohibited class either).
  it("step 7 (restore in a new task): a fresh human approval restores remittance.send; the contained Mission never does", async () => {
    const { id } = approveHumanMission(reconciliationIntent());
    restoredHumanMissionId = id;
    expect(restoredHumanMissionId).not.toBe(humanMissionId);
    const record = as.kernel.get(restoredHumanMissionId);
    expect(record?.approval_basis.type).toBe("direct");

    // The NEW task restores the external-comms capability.
    expect((await evalAction(restoredHumanMissionId, "payments:remittance.send")).decision).toBe(true);

    // The contained Mission never regains it mid-run.
    expect(as.kernel.get(humanMissionId)?.containment).toBeDefined();
    const stillContained = await evalAction(humanMissionId, "payments:remittance.send");
    expect(stillContained.decision).toBe(false);
    expect(stillContained.context.denial_reason).toBe("authority_contained");
  });

  // STEP 8: Activity Log. AAM Agent Activity Log (the console-bff join), over
  // BOTH missions: the machine-speed read/egress trail, and the human-approved
  // mission's ingestion -> containment -> authority_contained trail.
  it("step 8 (activity log): the dispatched mission's read+egress trail, and the human mission's ingestion -> containment -> authority_contained", () => {
    const bff = new ConsoleBff({
      kernel: as.kernel,
      ars: {} as never,
      transparency: {} as never,
      retrieveEvidence: () => undefined,
      producerJwks: { keys: [] },
      serviceJwks: { keys: [] },
      receiptFor: () => undefined,
      activity: { evidence: [pepEvidence, egressEvidence], issuerEvidence: as.issuerEvidence },
    });
    const session = bff.sessions.create("olivia", ["operator"]);

    // The machine-speed, Template-dispatched run: its own read decision + the
    // egress refusal, with Template lineage. NO containment ever touched it.
    const dispatchedRun = bff.activityLog(session, dispatchedMissionId);
    expect(dispatchedRun.mission_id).toBe(dispatchedMissionId);
    expect(dispatchedRun.lineage.template).toBeDefined();
    const dispatchedRead = dispatchedRun.entries.find(
      (e) => e.kind === "decision" && e.decision === true && e.action === "payments:invoice.read",
    );
    const dispatchedEgress = dispatchedRun.entries.find((e) => e.kind === "egress" && e.outcome === "refused");
    expect(dispatchedRead, "the dispatched mission's read decision is present").toBeDefined();
    expect(dispatchedEgress, "the egress refusal is present").toBeDefined();
    expect(dispatchedEgress?.mission_id).toBe(dispatchedMissionId);
    expect(dispatchedEgress?.scope_statement_digest).toBe(scopeDigest(SCOPE_STATEMENT));

    // The human-approved run: NO Template lineage; ingestion -> Containment
    // Evidence -> authority_contained, joined under the SAME protected event.
    const humanRun = bff.activityLog(session, humanMissionId);
    expect(humanRun.mission_id).toBe(humanMissionId);
    expect(humanRun.lineage.template).toBeUndefined();

    const entries = humanRun.entries;
    const ingestion = entries.find(
      (e) => e.kind === "ingestion" && e.action === "content.tainted_read" && e.outcome === "applied",
    );
    const containment = entries.find((e) => e.kind === "containment");
    const contained = entries.find((e) => e.kind === "decision" && e.denial_reason === "authority_contained");

    expect(ingestion, "ingestion entry present").toBeDefined();
    expect(containment, "containment entry present").toBeDefined();
    expect(contained, "authority_contained decision present").toBeDefined();

    // ingestion -> ContainmentEvidence are the SAME protected event (shared event_id),
    // and the authority_contained denial follows both in the timeline.
    expect(ingestion?.event_id).toBe(TAINT_EVENT_ID);
    expect(containment?.event_id).toBe(TAINT_EVENT_ID);
    expect(containment?.containment_version).toBe(1);
    const idxIng = entries.indexOf(ingestion!);
    const idxCont = entries.indexOf(containment!);
    const idxDen = entries.indexOf(contained!);
    expect(idxDen).toBeGreaterThan(idxIng);
    expect(idxDen).toBeGreaterThan(idxCont);

    expect(ingestion?.mission_id).toBe(humanMissionId);
  });
});
