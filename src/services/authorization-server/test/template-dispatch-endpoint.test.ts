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
  CANONICAL_RESOURCE,
  DERIVATION_POLICY,
  demoReconciliationTemplate,
  DEV_SERVICE_TOKEN,
  DISPATCH_PROHIBITED_ACTIONS,
} from "@mission/demo-data";
import {
  calculateJwkThumbprint,
  createRemoteJWKSet,
  exportJWK,
  generateKeyPair,
  importJWK,
  jwtVerify,
  SignJWT,
} from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { MISSION_DISPATCH_GRANT_TYPE } from "../src/adapters/provider.js";
import { buildAuthorizationServer, type BuiltAs } from "../src/index.js";

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
function readOnlyIntent(): string {
  return JSON.stringify({
    goal: "reconcile Acme invoices",
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

async function dispatch(params: {
  templateId: string;
  intent: string;
  dispatchEventId: string;
}): Promise<Response> {
  return tokenRequest({
    grant_type: MISSION_DISPATCH_GRANT_TYPE,
    template_id: params.templateId,
    mission_intent: params.intent,
    dispatch_event_id: params.dispatchEventId,
  });
}

beforeAll(async () => {
  as = await buildAuthorizationServer({ issuer: ISSUER, allowHeadlessAdjudication: true });
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

    const record = as.kernel.get(body.mission_id as string);
    expect(record).toBeDefined();
    expect(body.authorization_details).toEqual(as.kernel.effectiveAuthoritySet(record!));
    const actions = (body.authorization_details as Array<{ actions: string[] }>).flatMap((e) => e.actions);
    for (const a of actions) {
      expect(a.endsWith(".read") || a.endsWith(".list")).toBe(true);
    }
    expect(record?.approver.sub).toBe("bob");
    expect(record?.client_id).toBe("subagent-invoice-extractor");
    expect(record?.template?.template_hash).toMatch(/^sha-256:/);

    // A SECOND dispatch with the SAME dispatch_event_id is idempotent: same mission_id.
    const second = await dispatch({ templateId: template_id, intent: readOnlyIntent(), dispatchEventId: "evt-happy" });
    const secondBody = (await second.json()) as { mission_id?: string };
    expect(second.status, JSON.stringify(secondBody)).toBe(200);
    expect(secondBody.mission_id).toBe(body.mission_id);
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
      goal: "schedule a payment",
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
    const res = await dispatch({ templateId: template_id, intent, dispatchEventId: "evt-ceiling" });
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
      dispatch_policy: "wide-reconciliation",
      dispatchers: ["ap-agent"],
      recipients: ["subagent-invoice-extractor"],
      per_instance_lifetime_s: 900,
      max_active: 5,
      rate_per_min: 30,
      approval_event_id: `tmpl-evt-wide-${seq++}`,
      expires_at: FAR_FUTURE,
    });
    const { template_id } = (await created.json()) as { template_id: string };
    expect(DISPATCH_PROHIBITED_ACTIONS).toContain("payments:payment.execute");

    const intent = JSON.stringify({
      goal: "execute a payment",
      resources: [RESOURCE],
      expires_at: FAR_FUTURE,
      proposed_authority: [
        {
          type: "mission_resource_access",
          resource: RESOURCE,
          actions: ["payments:payment.execute"],
          constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
        },
      ],
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
    const res = await dispatch({ templateId: template_id, intent: readOnlyIntent(), dispatchEventId: "evt-dispatcher" });
    const body = (await res.json()) as { mission_denial_reason?: string };
    expect(res.status, JSON.stringify(body)).toBe(403);
    expect(body.mission_denial_reason).toBe("dispatcher_not_allowed");
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
});
