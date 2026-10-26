/**
 * @spec draft-mcguinness-oauth-mission-template (#prohibited-classes,
 * #template-consent, #grant-type), draft-mcguinness-oauth-mission
 * (#approval-context-changes, #approval-authentication) (#813, D814, D830)
 *
 * The standing-payment dispatch workflow on the real surfaces, with the
 * opt-in `standing-payment-dispatch` capability enabled for this file only:
 * the human template consent (rendered, with its render revision, at the
 * approval floor), the refusals of the service-token stand-in and the boot
 * seed, the startup checks, and the dispatch grant, unattended, alongside an
 * assembly with the capability off that refuses the payment as today.
 */
import type { Server } from "node:http";
import {
  CANONICAL_RESOURCE,
  DEV_SERVICE_TOKEN,
  demoReconciliationTemplate,
} from "@mission/demo-data";
import { exportJWK, generateKeyPair, importJWK, SignJWT } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { RENDER_REVISION_HEADER } from "../src/adapters/approval-render-revision.js";
import {
  ALL_PROVIDER_CAPABILITIES,
  type ProviderCapability,
} from "../src/adapters/capabilities.js";
import { MISSION_DISPATCH_GRANT_TYPE } from "../src/adapters/provider.js";
import {
  ApprovalSessionStore,
  type BuiltAs,
  buildAuthorizationServer,
  STANDING_PAYMENT_OPERATION,
  StandingPaymentConfigError,
} from "../src/index.js";
import { floorApprovalHeaders, TEST_APPROVAL_PRINCIPALS } from "./approval-fixture.js";

const PORT = 14995;
const OFF_PORT = 14996;
const ISSUER = `http://localhost:${PORT}`;
const OFF_ISSUER = `http://localhost:${OFF_PORT}`;
const RESOURCE = CANONICAL_RESOURCE;
const FAR_FUTURE = "2099-01-01T00:00:00Z";
const ON = new Set<ProviderCapability>([...ALL_PROVIDER_CAPABILITIES, "standing-payment-dispatch"]);
/** A designable client (an ai_agent registration). */
const DESIGNEE = "subagent-invoice-extractor";
const SESSIONS = new ApprovalSessionStore();

const TERMS = {
  operation: STANDING_PAYMENT_OPERATION,
  resource: RESOURCE,
  destinations: { acme: "acct-acme-0001" },
  max_amount: { amount: "500.00", currency: "USD" },
  budget: {
    owner: "payments-operator",
    id: "ap-standing-endpoint",
    currency: "USD",
    limit: "5000.00",
    per_instance_max: "1000.00",
  },
  approval_governance: {
    recency: {
      ceilings: { default: 86400 },
      clock_skew_s: 60,
      exceptions: {
        irreversible_action: { max_age_s: 3600 },
        consumption_bound: { max_age_s: 3600 },
      },
    },
  },
};
const spPolicy = (id: string, terms: unknown = TERMS) => ({
  version: "1",
  content_type: "application/json",
  content: JSON.stringify({ id, derivation_limit_ceiling: 3, standing_payment: terms }),
});
const POLICIES = { "sp-endpoint": spPolicy("sp-endpoint") };

let as: BuiltAs;
let off: BuiltAs;
let server: Server;
let offServer: Server;
let clientKey: CryptoKey;
let offClientKey: CryptoKey;
let dpopKeys: { privateKey: CryptoKey; publicKey: CryptoKey };
let seq = 0;

beforeAll(async () => {
  as = await buildAuthorizationServer({
    issuer: ISSUER,
    // Same-Mission delegation by designation is on too, so a designation
    // from a standing-payment instance reaches its refusal.
    capabilities: new Set<ProviderCapability>([...ON, "delegation"]),
    designableClients: [DESIGNEE],
    approvalSessions: SESSIONS,
    allowHeadlessAdjudication: true,
    serviceTokenPrincipals: TEST_APPROVAL_PRINCIPALS,
    dispatchPolicies: POLICIES,
  });
  server = as.provider.listen(PORT);
  off = await buildAuthorizationServer({ issuer: OFF_ISSUER, dispatchPolicies: POLICIES });
  offServer = off.provider.listen(OFF_PORT);
  clientKey = (await importJWK(as.agentClientJwk as never, "ES256")) as CryptoKey;
  offClientKey = (await importJWK(off.agentClientJwk as never, "ES256")) as CryptoKey;
  dpopKeys = await generateKeyPair("ES256", { extractable: true });
});

afterAll(() => {
  server?.close();
  offServer?.close();
});

/** The standing-payment template proposal: no approver, approval event or issuer. */
const proposal = (over: Record<string, unknown> = {}) => ({
  template_version: `sp-endpoint-${seq++}`,
  ceiling: [
    {
      type: "mission_resource_access",
      resource: RESOURCE,
      actions: [STANDING_PAYMENT_OPERATION],
      constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
    },
  ],
  dispatch_policy: { id: "sp-endpoint", version: "1" },
  dispatchers: ["ap-agent"],
  recipients: { subjects: [{ iss: ISSUER, sub: "bob" }], agents: ["subagent-invoice-extractor"] },
  per_instance_lifetime_s: 900,
  max_active: 1,
  rate_per_min: 30,
  review_cadence_s: 86400,
  expires_at: FAR_FUTURE,
  ...over,
});

async function propose(issuer: string, body: unknown): Promise<string> {
  const res = await fetch(`${issuer}/templates/proposals`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-service-token": DEV_SERVICE_TOKEN },
    body: JSON.stringify(body),
  });
  const out = (await res.json()) as { proposal_id: string };
  expect(res.status, JSON.stringify(out)).toBe(201);
  return out.proposal_id;
}

/** Bob's login on the consent page's user agent, at the floor (mfa), selecting no Subject. */
const bob = (id: string) => floorApprovalHeaders(SESSIONS, id, "", { sub: "bob", subject: null });

/** Render the consent page to `headers` and return the revision it retained. */
async function rendered(id: string, headers: Record<string, string>): Promise<string | null> {
  const { "x-csrf-token": _csrf, ...cookieOnly } = headers;
  const res = await fetch(`${ISSUER}/templates/proposals/${id}`, { headers: cookieOnly });
  expect(res.status).toBe(200);
  return res.headers.get(RENDER_REVISION_HEADER);
}

async function decide(
  id: string,
  headers: Record<string, string>,
  extra: Record<string, unknown> = {},
) {
  return fetch(`${ISSUER}/templates/proposals/${id}/decide`, {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify({ decision: "approve", ...extra }),
  });
}

/** A consented standing-payment template's id. */
async function consented(over: Record<string, unknown> = {}): Promise<string> {
  const id = await propose(ISSUER, proposal(over));
  const headers = bob(id);
  const revision = await rendered(id, headers);
  const res = await decide(id, headers, { render_revision: revision });
  const out = (await res.json()) as { template_id: string };
  expect(res.status, JSON.stringify(out)).toBe(201);
  return out.template_id;
}

async function clientAssertion(issuer: string, key: CryptoKey): Promise<string> {
  return new SignJWT({})
    .setProtectedHeader({ alg: "ES256", kid: "ap-agent-auth" })
    .setIssuer("ap-agent")
    .setSubject("ap-agent")
    .setAudience(issuer)
    .setIssuedAt()
    .setExpirationTime("2m")
    .setJti(crypto.randomUUID())
    .sign(key);
}

async function dpopProof(htu: string, extra: Record<string, unknown> = {}): Promise<string> {
  return new SignJWT({ htu, htm: "POST", ...extra })
    .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: await exportJWK(dpopKeys.publicKey) })
    .setIssuedAt()
    .setJti(crypto.randomUUID())
    .sign(dpopKeys.privateKey);
}

/** The dispatch grant at `issuer`'s token endpoint, with the dpop-nonce retry. */
async function dispatch(
  issuer: string,
  templateId: string,
  maxBudget: { amount: string; currency: string } | null = { amount: "1000.00", currency: "USD" },
) {
  const htu = `${issuer}/token`;
  const key = issuer === ISSUER ? clientKey : offClientKey;
  const intent = JSON.stringify({
    intent: {
      goal: "pay approved Acme invoices",
      target_resources: [RESOURCE],
      expires_at: FAR_FUTURE,
      ...(maxBudget ? { max_budget: maxBudget } : {}),
    },
  });
  const eventId = `sp-dsp-${seq++}`;
  const send = async (extra: Record<string, unknown> = {}) =>
    fetch(htu, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        dpop: await dpopProof(htu, extra),
      },
      body: new URLSearchParams({
        grant_type: MISSION_DISPATCH_GRANT_TYPE,
        template_id: templateId,
        mission_intent: intent,
        dispatch_event_id: eventId,
        client_assertion: await clientAssertion(issuer, key),
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      }).toString(),
    });
  let res = await send();
  const nonce = res.headers.get("dpop-nonce");
  if (res.status === 400 && nonce) res = await send({ nonce });
  return res;
}

describe("standing-payment template consent on the approval surface (@spec template#template-consent, #813)", () => {
  it("creates a standing-payment template only through the human consent decision, retaining its provenance with the latest render revision (#813)", async () => {
    const id = await propose(ISSUER, proposal());
    const headers = bob(id);
    const revision = await rendered(id, headers);
    expect(revision).toBeTruthy();
    const res = await decide(id, headers, { render_revision: revision });
    const out = (await res.json()) as { template_id: string };
    expect(res.status, JSON.stringify(out)).toBe(201);
    const template = as.templateStore.get(out.template_id);
    expect(template?.consent_provenance).toMatchObject({
      interactive: true,
      principal: { iss: ISSUER, sub: "bob" },
      acr: "mfa",
      floors: ["high-risk-authority"],
      render_revision: revision,
      proposal_id: id,
    });
  });

  it("renders the standing payment's committed destinations, budget and exceptions on the consent page (#813)", async () => {
    const id = await propose(ISSUER, proposal());
    const { "x-csrf-token": _csrf, ...cookie } = bob(id);
    const html = await (
      await fetch(`${ISSUER}/templates/proposals/${id}`, { headers: cookie })
    ).text();
    expect(html).toContain('<ul class="standing-payment">');
    expect(html).toContain("acme to account acct-acme-0001");
    expect(html).toContain(
      "Budget payments-operator/ap-standing-endpoint: at most 5000.00 USD in total",
    );
    expect(html).toContain('name="render_revision"');
  });

  it("refuses a template consent decision that names no render revision under the capability (@spec mission#approval-context-changes, #1586, #813)", async () => {
    const id = await propose(ISSUER, proposal());
    const headers = bob(id);
    await rendered(id, headers);
    const res = await decide(id, headers);
    const out = (await res.json()) as { error?: string };
    expect(res.status).toBe(409);
    expect(out.error).toBe("rendering_required");
  });

  it("refuses the service-token template route a template designating the standing payment, creating none (#813)", async () => {
    const res = await fetch(`${ISSUER}/templates`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-service-token": DEV_SERVICE_TOKEN },
      body: JSON.stringify({
        ...proposal(),
        issuer: ISSUER,
        approver: { iss: ISSUER, sub: "bob" },
        approval_event_id: "sp-service-token",
      }),
    });
    const out = (await res.json()) as { error?: string; error_description?: string };
    expect(res.status).toBe(400);
    expect(out.error).toBe("invalid_request");
    expect(out.error_description).toBe(
      "a standing-payment template is consented only by a human Approver at the approval floor on the approval surface; this consent establishes none",
    );
    expect(as.templateStore.getByApprovalEvent("sp-service-token")).toBeUndefined();
  });
});

describe("standing-payment startup checks (@spec template#prohibited-classes, #813)", () => {
  it("refuses startup when the boot seed's Dispatch Policy designates the standing payment (#813)", async () => {
    const seedPolicy = demoReconciliationTemplate("http://localhost:14997").dispatch_policy.id;
    await expect(
      buildAuthorizationServer({
        issuer: "http://localhost:14997",
        capabilities: ON,
        dispatchPolicies: { [seedPolicy]: spPolicy(seedPolicy) },
      }),
    ).rejects.toThrow(/consented only by a human Approver at the approval floor/);
  });

  it("refuses startup when a Dispatch Policy designates an operation at a resource the published mapping does not cover (#813)", async () => {
    const built = buildAuthorizationServer({
      issuer: "http://localhost:14998",
      capabilities: ON,
      dispatchPolicies: {
        "sp-uncovered": spPolicy("sp-uncovered", {
          ...TERMS,
          resource: "https://unclassified.example/api",
        }),
      },
    });
    await expect(built).rejects.toBeInstanceOf(StandingPaymentConfigError);
    await expect(built).rejects.toThrow(
      "Dispatch Policy sp-uncovered names payments:payment.execute at https://unclassified.example/api, which the published mapping does not cover",
    );
  });

  it("refuses startup when a Dispatch Policy designates an operation other than the payment (#813)", async () => {
    await expect(
      buildAuthorizationServer({
        issuer: "http://localhost:14999",
        capabilities: ON,
        dispatchPolicies: {
          "sp-reverse": spPolicy("sp-reverse", { ...TERMS, operation: "payments:payment.reverse" }),
        },
      }),
    ).rejects.toThrow(
      "Dispatch Policy sp-reverse designates payments:payment.reverse; only payments:payment.execute is a standing payment",
    );
  });

  it("refuses startup when the standing-payment capability is on without templates (#813)", async () => {
    await expect(
      buildAuthorizationServer({
        issuer: "http://localhost:15000",
        capabilities: new Set<ProviderCapability>(["standing-payment-dispatch"]),
      }),
    ).rejects.toThrow("the standing-payment-dispatch capability needs templates");
  });
});

describe("standing-payment dispatch grant (@spec template#grant-type, #813)", () => {
  it("dispatches a standing-payment instance at the token endpoint unattended with the capability on (#813)", async () => {
    const templateId = await consented({ max_active: 3 });
    const res = await dispatch(ISSUER, templateId);
    const out = (await res.json()) as { access_token?: string; error?: string };
    expect(res.status, JSON.stringify(out)).toBe(200);
    expect(out.access_token).toBeTruthy();
    const [missionId] = as.kernel.standingPayments.dispatchedInstances(templateId);
    const mission = as.kernel.get(missionId as string);
    expect(mission?.authority_set.flatMap((e) => e.actions)).toEqual([STANDING_PAYMENT_OPERATION]);
    expect(as.kernel.standingPayments.admission(missionId as string)?.budget).toEqual({
      owner: "payments-operator",
      id: "ap-standing-endpoint",
    });
  });

  it("refuses a standing-payment dispatch whose Intent carries no max_budget at the token endpoint (#813)", async () => {
    const templateId = await consented();
    const res = await dispatch(ISSUER, templateId, null);
    const out = (await res.json()) as { mission_denial_reason?: string };
    expect(res.status).toBe(400);
    expect(out.mission_denial_reason).toBe("dispatch_prohibited_class");
  });

  it("refuses the payment dispatch_prohibited_class at the token endpoint with the capability off, and max_budget as an unknown member (#813)", async () => {
    const created = await fetch(`${OFF_ISSUER}/templates`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-service-token": DEV_SERVICE_TOKEN },
      body: JSON.stringify({
        ...proposal({
          recipients: {
            subjects: [{ iss: OFF_ISSUER, sub: "bob" }],
            agents: ["subagent-invoice-extractor"],
          },
        }),
        issuer: OFF_ISSUER,
        approver: { iss: OFF_ISSUER, sub: "bob" },
        approval_event_id: "sp-off",
      }),
    });
    const { template_id } = (await created.json()) as { template_id: string };
    expect(created.status).toBe(201);
    const refused = await dispatch(OFF_ISSUER, template_id, null);
    const out = (await refused.json()) as { mission_denial_reason?: string };
    expect(refused.status).toBe(400);
    expect(out.mission_denial_reason).toBe("dispatch_prohibited_class");
    const unknown = await dispatch(OFF_ISSUER, template_id);
    const why = (await unknown.json()) as { error?: string; error_description?: string };
    expect(unknown.status).toBe(400);
    expect(why.error_description).toBe("unknown top-level member: max_budget");
  });

  it("refuses a designation of a standing-payment instance's access token invalid_target at the token endpoint (@spec mission#designation, #813)", async () => {
    const templateId = await consented({ max_active: 3 });
    const dispatched = await dispatch(ISSUER, templateId);
    const { access_token } = (await dispatched.json()) as { access_token: string };
    expect(dispatched.status).toBe(200);
    const htu = `${ISSUER}/token`;
    const send = async (extra: Record<string, unknown> = {}) =>
      fetch(htu, {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
          dpop: await dpopProof(htu, extra),
        },
        body: new URLSearchParams({
          grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
          subject_token: access_token,
          subject_token_type: "urn:ietf:params:oauth:token-type:access_token",
          requested_token_type: "urn:ietf:params:oauth:token-type:access_token",
          audience: DESIGNEE,
          client_assertion: await clientAssertion(ISSUER, clientKey),
          client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        }).toString(),
      });
    let res = await send();
    const nonce = res.headers.get("dpop-nonce");
    if (res.status === 400 && nonce) res = await send({ nonce });
    const out = (await res.json()) as { error?: string; error_description?: string };
    expect(res.status, JSON.stringify(out)).toBe(400);
    expect(out.error).toBe("invalid_target");
    expect(out.error_description).toBe("a standing-payment lineage is not delegated (#813)");
  });

  it("admits exactly max_active of concurrent standing-payment dispatches, with one accounting row per committed instance (#813)", async () => {
    const templateId = await consented({ max_active: 1 });
    const results = await Promise.all([
      dispatch(ISSUER, templateId),
      dispatch(ISSUER, templateId),
      dispatch(ISSUER, templateId),
    ]);
    const bodies = (await Promise.all(results.map((r) => r.json()))) as Array<{
      access_token?: string;
      mission_denial_reason?: string;
    }>;
    expect(results.filter((r) => r.status === 200)).toHaveLength(1);
    expect(bodies.filter((b) => b.mission_denial_reason === "max_active_exceeded")).toHaveLength(2);
    expect(as.kernel.standingPayments.dispatchedInstances(templateId)).toHaveLength(1);
  });
});
