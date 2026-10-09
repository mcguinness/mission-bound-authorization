/**
 * @spec draft-mcguinness-oauth-mission-template (#dispatch, #dispatch-refusals,
 * #lifecycle)
 *
 * Mission Template dispatch wired onto the real OAuth surface. A dispatcher
 * (ap-agent) redeems the impl-local MISSION_DISPATCH_GRANT_TYPE grant at
 * /token, authenticating with private_key_jwt + DPoP; the AS resolves the
 * Mission Template, runs dispatchFromTemplate, and returns a DPoP-bound
 * mission access token in ONE round trip. Covered here:
 *   - the /templates admin plane: create (service-token gated) + the
 *     template_id/template_version/template_hash it returns;
 *   - happy path dispatch + idempotency by dispatch_event_id;
 *   - out_of_template_ceiling (within policy, outside the template ceiling);
 *   - dispatch_prohibited_class (within both ceilings, but a prohibited action);
 *   - dispatcher_not_allowed;
 *   - the param-stripping regression (template_id/mission_intent/dispatch_event_id
 *     must survive stripGrantIrrelevantParams);
 *   - lifecycle revoke -> template_not_active on a subsequent dispatch.
 */

import { type Server } from "node:http";
import {
  aamReconciliationTemplate,
  CANONICAL_RESOURCE,
  DERIVATION_POLICY,
  demoReconciliationTemplate,
  DEV_SERVICE_TOKEN,
  DISPATCH_PROHIBITED_ACTIONS,
} from "@mission/demo-data";
import {
  calculateJwkThumbprint,
  createRemoteJWKSet,
  decodeJwt,
  exportJWK,
  generateKeyPair,
  importJWK,
  jwtVerify,
  SignJWT,
} from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { MISSION_DISPATCH_GRANT_TYPE } from "../src/adapters/provider.js";
import {
  buildAuthorizationServer,
  type BuiltAs,
  registerIntentSubmissionEvidenceType,
  unregisterIntentSubmissionEvidenceType,
} from "../src/index.js";

const PORT = 14477;
const ISSUER = `http://localhost:${PORT}`;
const RESOURCE = CANONICAL_RESOURCE;
const FAR_FUTURE = "2099-01-01T00:00:00Z";

type DpopKeys = { privateKey: CryptoKey; publicKey: CryptoKey };

let as: BuiltAs;
let asServer: Server;
let clientKey: CryptoKey;
let dpopKeys: DpopKeys;
let seq = 0;

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

/** POST /token with private_key_jwt + DPoP, with the mandatory dpop-nonce retry. */
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

/**
 * POST /templates (service-token admin plane). `token: null` omits the header
 * entirely (the "absent" case); a default parameter cannot express that,
 * since it substitutes on an explicit `undefined` argument too.
 */
async function createTemplateAdmin(body: unknown, token: string | null = DEV_SERVICE_TOKEN): Promise<Response> {
  return fetch(`${ISSUER}/templates`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...(token !== null ? { "x-service-token": token } : {}),
    },
    body: JSON.stringify(body),
  });
}

async function templateLifecycle(id: string, operation: string): Promise<Response> {
  return fetch(`${ISSUER}/templates/${id}/lifecycle`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-service-token": DEV_SERVICE_TOKEN },
    body: JSON.stringify({ operation }),
  });
}

/** The demo read-only reconciliation template body, with a fresh (unique)
 *  approval_event_id so each call mints a DISTINCT template_id (createTemplate
 *  is idempotent by approval_event_id, and the demo instance is already seeded
 *  under its own fixed id at server construction). */
function readOnlyTemplateBody(): Record<string, unknown> {
  return {
    ...demoReconciliationTemplate(ISSUER),
    approval_event_id: `tmpl-evt-${seq++}`,
  };
}

/** A read-only Mission Intent: invoice.read only, within both ceilings. */
// @spec mission#submission-via-par — the wire value is the Submission envelope.
function readOnlyIntent(): string {
  return JSON.stringify({
    intent: {
      goal: "reconcile Acme invoices",
      target_resources: [RESOURCE],
      expires_at: FAR_FUTURE,
    },
  });
}

async function dispatch(params: {
  templateId: string;
  intent: string;
  dispatchEventId: string;
  /** @spec mission#authority-proposal — the dispatcher's proposal on the
   *  standard authorization_details parameter of the dispatch grant. */
  authorizationDetails?: string;
}): Promise<Response> {
  return tokenRequest({
    grant_type: MISSION_DISPATCH_GRANT_TYPE,
    template_id: params.templateId,
    mission_intent: params.intent,
    dispatch_event_id: params.dispatchEventId,
    ...(params.authorizationDetails ? { authorization_details: params.authorizationDetails } : {}),
  });
}

/** A held Dispatch Policy snapshot; `select_agent` is its Agent selection rule (@spec mission#standing-consent-bases). */
const heldPolicy = (id: string, rule: { select_agent?: string } = {}) => ({
  version: "1",
  content_type: "application/json",
  content: JSON.stringify({ id, ...rule }),
});

beforeAll(async () => {
  as = await buildAuthorizationServer({
    issuer: ISSUER,
    allowHeadlessAdjudication: true,
    // @spec mission-template#the-mission-template, mission#standing-consent-bases
    // — deployment Dispatch Policies: each held snapshot (whose digest a
    // template commits) and, for multi-Agent templates, an Agent selection rule.
    dispatchPolicies: {
      "test-route-a1": heldPolicy("test-route-a1", { select_agent: "agent-A1" }),
      "test-route-unlisted": heldPolicy("test-route-unlisted", { select_agent: "governed-agent" }),
      "test-no-rule": heldPolicy("test-no-rule"),
      "wide-reconciliation": heldPolicy("wide-reconciliation"),
    },
  });
  asServer = as.provider.listen(PORT);
  clientKey = (await importJWK(as.agentClientJwk as never, "ES256")) as CryptoKey;
  dpopKeys = await generateKeyPair("ES256", { extractable: true });
});

afterAll(() => {
  asServer?.close();
});

describe("Mission Template admin plane (@spec mission-template)", () => {
  it("POST /templates creates a template (service-token gated)", async () => {
    const res = await createTemplateAdmin(readOnlyTemplateBody());
    const body = (await res.json()) as { template_id?: string; template_version?: string; template_hash?: string };
    expect(res.status, JSON.stringify(body)).toBe(201);
    expect(body.template_id).toMatch(/^tmpl_/);
    expect(body.template_version).toBeTruthy();
    expect(body.template_hash).toMatch(/^sha-256:/);
  });

  it("accepts the shared AAM reconciliation template body, the terminal exhibit's payload (@spec mission-template#the-mission-template)", async () => {
    const res = await createTemplateAdmin(aamReconciliationTemplate(ISSUER, `aam-shared-${seq++}`));
    const body = (await res.json()) as { template_id?: string };
    expect(res.status, JSON.stringify(body)).toBe(201);
    expect(body.template_id).toMatch(/^tmpl_/);
  });

  it("rejects an absent or wrong x-service-token with 401", async () => {
    const absent = await createTemplateAdmin(readOnlyTemplateBody(), null);
    expect(absent.status).toBe(401);
    const wrong = await createTemplateAdmin(readOnlyTemplateBody(), "not-the-token");
    expect(wrong.status).toBe(401);
  });
});

describe("mission-dispatch grant at /token (@spec mission-template#dispatch)", () => {
  it("happy path: dispatch mints a DPoP-bound mission token, and a repeated dispatch_event_id is idempotent", async () => {
    const created = await createTemplateAdmin(readOnlyTemplateBody());
    const { template_id } = (await created.json()) as { template_id: string };

    const res = await dispatch({ templateId: template_id, intent: readOnlyIntent(), dispatchEventId: "evt-happy" });
    const body = (await res.json()) as {
      access_token?: string;
      token_type?: string;
      expires_in?: number;
      mission_id?: string;
      mission_expires_at?: string;
      authorization_details?: unknown;
    };
    expect(res.status, JSON.stringify(body)).toBe(200);
    expect(body.token_type).toBe("DPoP");
    expect(body.mission_id).toBeTruthy();
    expect(res.headers.get("cache-control")).toContain("no-store");

    // The token is a real, resource-bound JWT (verifies on the AS jwks_uri).
    const jwks = createRemoteJWKSet(new URL(`${ISSUER}/jwks`));
    const { payload } = await jwtVerify(body.access_token as string, jwks, {
      issuer: ISSUER,
      audience: RESOURCE,
    });
    // cnf.jkt is the DISPATCHER's own DPoP key.
    const dispatcherJkt = await calculateJwkThumbprint(await exportJWK(dpopKeys.publicKey));
    expect((payload.cnf as { jkt?: string } | undefined)?.jkt).toBe(dispatcherJkt);
    // The load-bearing mission-binding claim: extraTokenClaims attaches it via
    // grantId -> findByGrant -> gateDerivation. This exercises the novel bit of
    // the dispatch flow (the Grant is owned by the dispatcher while the record's
    // client_id is the recipient), and confirms it still resolves to the instance.
    const missionClaim = payload.mission as { id?: string } | undefined;
    expect(missionClaim?.id).toBe(body.mission_id);

    // @spec mission#delegation (delegate model, P0-2) — the dispatcher is the
    // party actually redeeming this token (the immediate client), so the
    // token's top-level client_id names it, NOT the template's recipient
    // (record.client_id, asserted separately below).
    expect(payload.client_id).toBe("ap-agent");

    const record = as.kernel.get(body.mission_id as string);
    expect(record).toBeDefined();
    // @spec mission#grant-binding (issue #647) — the dispatch body carries the
    // instance's COMMITTED effective expiry verbatim off the record.
    expect(body.mission_expires_at).toBe(record?.expires_at);
    // @spec mission-template#dispatch — the template's per_instance_lifetime_s
    // (900s) is the narrowest bound here, and the addend is measured from the
    // instance's OWN committed created_at: created_at + 900s EXACTLY, not from a
    // second clock read taken elsewhere in the dispatch.
    expect(Date.parse(record!.expires_at) - Date.parse(record!.created_at)).toBe(900_000);
    expect(Date.parse(record!.expires_at)).toBeLessThan(Date.parse(FAR_FUTURE));
    expect(body.authorization_details).toEqual(as.kernel.effectiveAuthoritySet(record!));
    const actions = (body.authorization_details as Array<{ actions: string[] }>).flatMap((e) => e.actions);
    for (const a of actions) {
      expect(a.endsWith(".read") || a.endsWith(".list")).toBe(true);
    }
    expect(record?.approval_basis.consent_principal.sub).toBe("bob");
    expect(record?.client_id).toBe("subagent-invoice-extractor");
    expect(record?.template?.template_hash).toMatch(/^sha-256:/);

    // A SECOND dispatch with the SAME dispatch_event_id is idempotent: same mission_id.
    const second = await dispatch({ templateId: template_id, intent: readOnlyIntent(), dispatchEventId: "evt-happy" });
    const secondBody = (await second.json()) as { mission_id?: string; mission_expires_at?: string };
    expect(second.status, JSON.stringify(secondBody)).toBe(200);
    expect(secondBody.mission_id).toBe(body.mission_id);
    // @spec mission#grant-binding — a creation replay returns the COMMITTED
    // value unchanged: the same string, never re-derived from the replay's own
    // (later) clock.
    expect(secondBody.mission_expires_at).toBe(body.mission_expires_at);
  });

  it("a dispatched instance ending inside the token lifetime gets an access token that expires no later than it (@spec mission#mission-bound-tokens)", async () => {
    const created = await createTemplateAdmin(readOnlyTemplateBody());
    const { template_id } = (await created.json()) as { template_id: string };
    const intent = JSON.stringify({
      intent: {
        goal: "reconcile Acme invoices",
        target_resources: [RESOURCE],
        expires_at: new Date(Date.now() + 60_000).toISOString(), // inside the 300 s lifetime
      },
    });
    const res = await dispatch({ templateId: template_id, intent, dispatchEventId: "evt-exp-clamp" });
    const body = (await res.json()) as { access_token?: string; mission_id?: string; expires_in?: number };
    expect(res.status, JSON.stringify(body)).toBe(200);
    const missionExp = Math.floor(Date.parse(as.kernel.get(body.mission_id as string)?.expires_at as string) / 1000);
    const at = decodeJwt(body.access_token as string) as { iat: number; exp: number };
    expect(at.exp).toBeLessThanOrEqual(missionExp);
    expect(at.exp - at.iat).toBeLessThan(300);
  });

  it("param-stripping regression: template_id/mission_intent/dispatch_event_id survive to the handler", async () => {
    const created = await createTemplateAdmin(readOnlyTemplateBody());
    const { template_id } = (await created.json()) as { template_id: string };
    const res = await dispatch({ templateId: template_id, intent: readOnlyIntent(), dispatchEventId: "evt-stripping" });
    const body = (await res.json()) as { error?: string; error_description?: string; mission_id?: string };
    expect(res.status, JSON.stringify(body)).toBe(200);
    expect(body.error).toBeUndefined();
    expect(body.mission_id).toBeTruthy();
  });

  it("out_of_template_ceiling: within POLICY but outside the (read-only) TEMPLATE ceiling", async () => {
    const created = await createTemplateAdmin(readOnlyTemplateBody());
    const { template_id } = (await created.json()) as { template_id: string };
    // payments:payment.schedule is within the derivation policy ceiling (so the
    // FIRST derivation succeeds) but is dropped from the read-only template's
    // ceiling (only .read/.list actions survive there).
    const intent = JSON.stringify({
      intent: {
        goal: "schedule a payment",
        target_resources: [RESOURCE],
        expires_at: FAR_FUTURE,
      },
    });
    const res = await dispatch({
      templateId: template_id,
      intent,
      dispatchEventId: "evt-ceiling",
      authorizationDetails: JSON.stringify([
        { type: "mission_resource_access", resource: RESOURCE, actions: ["payments:payment.schedule"] },
      ]),
    });
    const body = (await res.json()) as { mission_denial_reason?: string };
    expect(res.status, JSON.stringify(body)).toBe(400);
    expect(body.mission_denial_reason).toBe("out_of_template_ceiling");
  });

  it("dispatch_prohibited_class: within both ceilings, but a dispatch-prohibited action", async () => {
    // A template whose ceiling equals the full derivation-policy ceiling
    // (includes payments:payment.execute, which DISPATCH_PROHIBITED_ACTIONS bars).
    const created = await createTemplateAdmin({
      template_version: "tmpl-wide-1",
      issuer: ISSUER,
      approver: { iss: ISSUER, sub: "bob" },
      ceiling: DERIVATION_POLICY.ceiling,
      dispatch_policy: { id: "wide-reconciliation", version: "1" },
      dispatchers: ["ap-agent"],
      recipients: { subjects: [{ iss: ISSUER, sub: "bob" }], agents: ["subagent-invoice-extractor"] },
      per_instance_lifetime_s: 900,
      max_active: 5,
      rate_per_min: 30,
      review_cadence_s: 86400,
      approval_event_id: `tmpl-evt-wide-${seq++}`,
      expires_at: FAR_FUTURE,
    });
    const { template_id } = (await created.json()) as { template_id: string };
    expect(DISPATCH_PROHIBITED_ACTIONS).toContain("payments:payment.execute");

    const intent = JSON.stringify({
      intent: {
        goal: "execute a payment",
        target_resources: [RESOURCE],
        expires_at: FAR_FUTURE,
      },
    });
    const res = await dispatch({ templateId: template_id, intent, dispatchEventId: "evt-prohibited" });
    const body = (await res.json()) as { mission_denial_reason?: string };
    expect(res.status, JSON.stringify(body)).toBe(400);
    expect(body.mission_denial_reason).toBe("dispatch_prohibited_class");
  });

  it("dispatcher_not_allowed: ap-agent is not on the template's dispatchers list", async () => {
    const created = await createTemplateAdmin({
      ...readOnlyTemplateBody(),
      dispatchers: ["not-ap-agent"],
    });
    const { template_id } = (await created.json()) as { template_id: string };
    const missionsBefore = as.kernel.allMissions().length;
    const res = await dispatch({ templateId: template_id, intent: readOnlyIntent(), dispatchEventId: "evt-dispatcher" });
    const body = (await res.json()) as { mission_denial_reason?: string };
    expect(res.status, JSON.stringify(body)).toBe(403);
    expect(body.mission_denial_reason).toBe("dispatcher_not_allowed");
    // A refused Dispatch commits nothing: no Mission and no dispatch event.
    expect(as.kernel.allMissions().length).toBe(missionsBefore);
    expect(as.templateStore.dispatchesSince(template_id, "1970-01-01T00:00:00.000Z")).toBe(0);
  });

  it("recipient_not_allowed: the established Subject (the template's approver) is not in recipients.subjects (@spec mission-template#the-mission-template)", async () => {
    const created = await createTemplateAdmin({
      ...readOnlyTemplateBody(),
      recipients: { subjects: [{ iss: ISSUER, sub: "carol" }], agents: ["subagent-invoice-extractor"] },
    });
    const { template_id } = (await created.json()) as { template_id: string };
    const missionsBefore = as.kernel.allMissions().length;
    const res = await dispatch({ templateId: template_id, intent: readOnlyIntent(), dispatchEventId: "evt-subject" });
    const body = (await res.json()) as { mission_denial_reason?: string };
    expect(res.status, JSON.stringify(body)).toBe(403);
    expect(body.mission_denial_reason).toBe("recipient_not_allowed");
    // A refused Dispatch commits nothing: no Mission and no dispatch event.
    expect(as.kernel.allMissions().length).toBe(missionsBefore);
    expect(as.templateStore.dispatchesSince(template_id, "1970-01-01T00:00:00.000Z")).toBe(0);
  });

  // @spec mission-template#the-mission-template — the Mission Issuer selects
  // the Agent; the request names none, and a parameter that tries is ignored.
  it("the Agent is never taken from the request: a Dispatch naming an Agent commits the template's Agent", async () => {
    const created = await createTemplateAdmin(readOnlyTemplateBody());
    const { template_id } = (await created.json()) as { template_id: string };
    const res = await tokenRequest({
      grant_type: MISSION_DISPATCH_GRANT_TYPE,
      template_id,
      mission_intent: readOnlyIntent(),
      dispatch_event_id: `evt-agent-param-${seq++}`,
      recipient: "agent-A1",
      agent: "agent-A1",
    });
    const body = (await res.json()) as { mission_id?: string };
    expect(res.status, JSON.stringify(body)).toBe(200);
    expect(as.kernel.get(body.mission_id as string)?.client_id).toBe("subagent-invoice-extractor");
  });

  // @spec mission-template#the-mission-template, mission-template#grant-type —
  // with several listed Agents the Dispatch Policy selects one; the selection
  // is committed and kept on retry, and the token stays the Dispatcher's.
  it("with several listed Agents, the Dispatch Policy selects the Agent, a retry keeps it, and the token is bound to the Dispatcher", async () => {
    const created = await createTemplateAdmin({
      ...readOnlyTemplateBody(),
      dispatch_policy: { id: "test-route-a1", version: "1" },
      recipients: { subjects: [{ iss: ISSUER, sub: "bob" }], agents: ["subagent-invoice-extractor", "agent-A1"] },
    });
    const createdBody = (await created.json()) as { template_id: string };
    expect(created.status, JSON.stringify(createdBody)).toBe(201);
    const eventId = `evt-agent-policy-${seq++}`;
    const res = await dispatch({ templateId: createdBody.template_id, intent: readOnlyIntent(), dispatchEventId: eventId });
    const body = (await res.json()) as { mission_id?: string; access_token?: string };
    expect(res.status, JSON.stringify(body)).toBe(200);
    expect(as.kernel.get(body.mission_id as string)?.client_id).toBe("agent-A1");
    const { payload } = await jwtVerify(body.access_token as string, createRemoteJWKSet(new URL(`${ISSUER}/jwks`)), { issuer: ISSUER, audience: RESOURCE });
    expect(payload.client_id).toBe("ap-agent");
    expect((payload.cnf as { jkt?: string } | undefined)?.jkt).toBe(await calculateJwkThumbprint(await exportJWK(dpopKeys.publicKey)));

    const retry = await dispatch({ templateId: createdBody.template_id, intent: readOnlyIntent(), dispatchEventId: eventId });
    const retryBody = (await retry.json()) as { mission_id?: string };
    expect(retry.status, JSON.stringify(retryBody)).toBe(200);
    expect(retryBody.mission_id).toBe(body.mission_id);
    expect(as.kernel.get(retryBody.mission_id as string)?.client_id).toBe("agent-A1");
  });

  it("agent_not_selected: several listed Agents and no Dispatch Policy rule refuses the Dispatch with access_denied", async () => {
    // @spec mission#standing-consent-bases — template consent naming a policy
    // the issuer does not hold is refused: it cannot commit unheld content.
    const unheld = await createTemplateAdmin({
      ...readOnlyTemplateBody(),
      dispatch_policy: { id: "no-such-policy", version: "1" },
    });
    const unheldBody = (await unheld.json()) as { error?: string };
    expect(unheld.status, JSON.stringify(unheldBody)).toBe(400);
    expect(unheldBody.error).toBe("invalid_request");
    const created = await createTemplateAdmin({
      ...readOnlyTemplateBody(),
      dispatch_policy: { id: "test-no-rule", version: "1" },
      recipients: { subjects: [{ iss: ISSUER, sub: "bob" }], agents: ["subagent-invoice-extractor", "agent-A1"] },
    });
    const { template_id } = (await created.json()) as { template_id: string };
    const res = await dispatch({ templateId: template_id, intent: readOnlyIntent(), dispatchEventId: `evt-agent-none-${seq++}` });
    const body = (await res.json()) as { error?: string; mission_denial_reason?: string; access_token?: string };
    expect(res.status, JSON.stringify(body)).toBe(403);
    expect(body.error).toBe("access_denied");
    expect(body.mission_denial_reason).toBe("agent_not_selected");
    expect(body.access_token).toBeUndefined();
  });

  it("recipient_not_allowed: a Dispatch Policy that selects an unlisted Agent is refused", async () => {
    const created = await createTemplateAdmin({
      ...readOnlyTemplateBody(),
      dispatch_policy: { id: "test-route-unlisted", version: "1" },
      recipients: { subjects: [{ iss: ISSUER, sub: "bob" }], agents: ["subagent-invoice-extractor", "agent-A1"] },
    });
    const { template_id } = (await created.json()) as { template_id: string };
    const before = as.kernel.allMissions().length;
    const res = await dispatch({ templateId: template_id, intent: readOnlyIntent(), dispatchEventId: `evt-agent-unlisted-${seq++}` });
    const body = (await res.json()) as { error?: string; mission_denial_reason?: string };
    expect(res.status, JSON.stringify(body)).toBe(403);
    expect(body.mission_denial_reason).toBe("recipient_not_allowed");
    expect(as.kernel.allMissions().length).toBe(before);
  });

  it("lifecycle revoke: a revoked template refuses a subsequent dispatch with template_not_active", async () => {
    const created = await createTemplateAdmin(readOnlyTemplateBody());
    const { template_id } = (await created.json()) as { template_id: string };

    const revoke = await templateLifecycle(template_id, "revoke");
    const revokeBody = (await revoke.json()) as { template_id?: string; state?: string };
    expect(revoke.status, JSON.stringify(revokeBody)).toBe(200);
    expect(revokeBody.state).toBe("revoked");

    const res = await dispatch({ templateId: template_id, intent: readOnlyIntent(), dispatchEventId: "evt-revoked" });
    const body = (await res.json()) as { mission_denial_reason?: string };
    expect(res.status, JSON.stringify(body)).toBe(403);
    expect(body.mission_denial_reason).toBe("template_not_active");
  });

  // @spec mission-template#template-consent — a template whose most recent
  // human approval is older than its review_cadence dispatches nothing until a
  // fresh approval re-consents. The refusal reason is implementation-local
  // (D205) and rides access_denied, as template_not_active does.
  it("review_overdue: a template dispatches inside its review_cadence and is refused with access_denied once the approval is older", async () => {
    const created = await createTemplateAdmin({ ...readOnlyTemplateBody(), review_cadence_s: 2 });
    const createdBody = (await created.json()) as { template_id: string };
    expect(created.status, JSON.stringify(createdBody)).toBe(201);
    const fresh = await dispatch({ templateId: createdBody.template_id, intent: readOnlyIntent(), dispatchEventId: `evt-review-${seq++}` });
    expect(fresh.status, await fresh.clone().text()).toBe(200);

    await new Promise((resolve) => setTimeout(resolve, 2200));
    const res = await dispatch({ templateId: createdBody.template_id, intent: readOnlyIntent(), dispatchEventId: `evt-review-${seq++}` });
    const body = (await res.json()) as { error?: string; mission_denial_reason?: string; access_token?: string };
    expect(res.status, JSON.stringify(body)).toBe(403);
    expect(body.error).toBe("access_denied");
    expect(body.mission_denial_reason).toBe("review_overdue");
    expect(body.access_token).toBeUndefined();
  }, 15_000);
});

describe("Dispatch idempotency at /token (@spec mission-template#dispatch, mission#intent-submission-evidence)", () => {
  // A test evidence type whose stage-2 verifier can be flipped to FAIL,
  // simulating an artifact that lapsed AFTER the first Dispatch completed.
  // Registered by this block only; the shipped registry is empty.
  const STUB_TYPE = "urn:test:intent-evidence:dispatch-stub";
  let failVerification = false;
  beforeAll(() => {
    registerIntentSubmissionEvidenceType(STUB_TYPE, {
      validate(entry) {
        if (typeof entry.assertion !== "string") throw new Error("assertion required");
      },
      async verify() {
        if (failVerification) throw new Error("artifact expired after completion");
        return { admitted: true };
      },
    });
  });
  afterAll(() => unregisterIntentSubmissionEvidenceType(STUB_TYPE));

  /** The read-only Intent's Submission envelope, with optional evidence. */
  const envelope = (goal: string, assertion?: string): string =>
    JSON.stringify({
      intent: { goal, target_resources: [RESOURCE], expires_at: FAR_FUTURE },
      ...(assertion ? { evidence: [{ type: STUB_TYPE, assertion }] } : {}),
    });
  const newTemplate = async (): Promise<string> => {
    const created = await createTemplateAdmin(readOnlyTemplateBody());
    return ((await created.json()) as { template_id: string }).template_id;
  };

  it("a completed Dispatch recovers before evidence re-verification; a new Dispatch still verifies", async () => {
    failVerification = false;
    const templateId = await newTemplate();
    const first = await dispatch({ templateId, intent: envelope("reconcile Acme invoices", "a-1"), dispatchEventId: "evt-evidence" });
    const fb = (await first.json()) as { mission_id?: string };
    expect(first.status, JSON.stringify(fb)).toBe(200);

    // The artifact lapses: stage-2 verification would now fail...
    failVerification = true;
    // ...but the identical retry of the completed Dispatch recovers it.
    const retry = await dispatch({ templateId, intent: envelope("reconcile Acme invoices", "a-1"), dispatchEventId: "evt-evidence" });
    const rb = (await retry.json()) as { mission_id?: string; error?: string };
    expect(retry.status, JSON.stringify(rb)).toBe(200);
    expect(rb.mission_id).toBe(fb.mission_id);

    // A new Dispatch is not a recovery: verification runs and refuses.
    const fresh = await dispatch({ templateId, intent: envelope("reconcile Acme invoices", "a-1"), dispatchEventId: "evt-evidence-new" });
    const nb = (await fresh.json()) as { error?: string; error_description?: string };
    expect(fresh.status, JSON.stringify(nb)).toBe(400);
    expect(nb.error).toBe("invalid_mission_intent_evidence");
    failVerification = false;
  });

  it("a reused dispatch_event_id with a different intent or evidence is invalid_request, with no mission_denial_reason", async () => {
    failVerification = false;
    const templateId = await newTemplate();
    const first = await dispatch({ templateId, intent: envelope("reconcile Acme invoices", "b-1"), dispatchEventId: "evt-mismatch" });
    expect(first.status).toBe(200);
    const firstBody = (await first.json()) as { mission_id?: string };

    for (const changed of [envelope("reconcile Globex invoices", "b-1"), envelope("reconcile Acme invoices", "b-2")]) {
      const res = await dispatch({ templateId, intent: changed, dispatchEventId: "evt-mismatch" });
      const body = (await res.json()) as { error?: string; error_description?: string; mission_denial_reason?: string };
      expect(res.status, JSON.stringify(body)).toBe(400);
      expect(body.error).toBe("invalid_request");
      expect(body.error_description).toContain("dispatch_event_id");
      expect(body.mission_denial_reason).toBeUndefined();
    }

    // The unchanged retry still recovers the committed instance.
    const retry = await dispatch({ templateId, intent: envelope("reconcile Acme invoices", "b-1"), dispatchEventId: "evt-mismatch" });
    expect(((await retry.json()) as { mission_id?: string }).mission_id).toBe(firstBody.mission_id);
  });
});
