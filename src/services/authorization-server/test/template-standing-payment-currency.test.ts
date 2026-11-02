/**
 * @spec draft-mcguinness-oauth-mission-template (#standing-payment-exception,
 * #dispatch-adjudication) (#813, D1143)
 *
 * "The per-payment `max_amount`, the budget, and every `max_budget` share one
 * currency", observed at the token endpoint in the order the Mission Issuer
 * adjudicates a Dispatch. A stored Template Ceiling bounding the payment in
 * another currency than the deployment's derivation policy has no
 * intersection with it, so the Dispatch is refused `out_of_template_ceiling`
 * at the double intersection (step 5) before the currency check. Under a
 * derivation policy bounding the payment in that same other currency, the
 * intersection survives and the prohibited-class check (step 6) refuses the
 * Dispatch `dispatch_prohibited_class`. Each refusal creates nothing.
 *
 * The consent route refuses a ceiling in another currency, so each witness
 * rewrites the stored ceiling after consent, as a store written at rest would
 * hold it.
 */
import type { Server } from "node:http";
import { activationPolicyDigest } from "@mission/core";
import { CANONICAL_RESOURCE, DERIVATION_POLICY, DEV_SERVICE_TOKEN } from "@mission/demo-data";
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
} from "../src/index.js";
import { floorApprovalHeaders } from "./approval-fixture.js";
import { FakeBudgetCounters } from "./budget-exposure.helper.js";

const SHIPPED_PORT = 15093;
const EURO_PORT = 15094;
const RESOURCE = CANONICAL_RESOURCE;
const FAR_FUTURE = "2099-01-01T00:00:00Z";
const ON = new Set<ProviderCapability>([...ALL_PROVIDER_CAPABILITIES, "standing-payment-dispatch"]);
const SESSIONS = new ApprovalSessionStore();
const OWNER = "payments-operator";

const TERMS = {
  operation: STANDING_PAYMENT_OPERATION,
  resource: RESOURCE,
  destinations: { acme: "acct-acme-0001" },
  max_amount: { amount: "500.00", currency: "USD" },
  budget: {
    owner: OWNER,
    id: "ap-currency",
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
const POLICIES = {
  "sp-currency": {
    version: "1",
    content_type: "application/json",
    content: JSON.stringify({ id: "sp-currency", derivation_limit_ceiling: 3, standing_payment: TERMS }),
  },
};

/** The statement metering the policy's budget under the Exact profile, as `issuer` digests it. */
const meteringStatement = (issuer: string) => ({
  claims: ["budget_metering"],
  extensions: {
    budget_metering: {
      unit: { currency: "USD", exponent: 2 },
      enforcement_profile: "exact",
      topology: "local-single-writer",
      reserve_posture: "reserve_then_commit",
      settlement_intake: "pdp-claim-settlement:execution-evidence",
      metered_actions: [{ action: STANDING_PAYMENT_OPERATION, phase: "commit" }],
      budgets: [
        {
          owner: OWNER,
          budget_id: TERMS.budget.id,
          counter_scope: "standing_consent",
          currency: "USD",
          limit: TERMS.budget.limit,
          policies: [
            {
              id: "sp-currency",
              version: "1",
              digest: activationPolicyDigest(issuer, POLICIES["sp-currency"]),
            },
          ],
        },
      ],
    },
  },
});

/**
 * The shipped derivation policy with every ceiling entry granting the payment
 * bounded per payment in EUR instead of USD: a deployment whose derivation
 * policy bounds the payment in the currency a stored Template Ceiling names.
 */
const EURO_DERIVATION_POLICY = (() => {
  const euro = structuredClone(DERIVATION_POLICY) as typeof DERIVATION_POLICY;
  for (const entry of euro.ceiling) {
    if (entry.actions.includes(STANDING_PAYMENT_OPERATION) && entry.constraints?.max_amount) {
      entry.constraints.max_amount = { amount: "500.00", currency: "EUR" };
    }
  }
  return euro;
})();

interface Deployment {
  issuer: string;
  as: BuiltAs;
  server: Server;
  clientKey: CryptoKey;
}

let shipped: Deployment;
let euro: Deployment;
let dpopKeys: { privateKey: CryptoKey; publicKey: CryptoKey };
let seq = 0;

async function deploy(port: number, derivationPolicy?: typeof DERIVATION_POLICY): Promise<Deployment> {
  const issuer = `http://localhost:${port}`;
  const as = await buildAuthorizationServer({
    issuer,
    capabilities: ON,
    approvalSessions: SESSIONS,
    dispatchPolicies: POLICIES,
    enforcementScopeStatement: meteringStatement(issuer),
    budgetExposure: new FakeBudgetCounters(),
    ...(derivationPolicy ? { derivationPolicy } : {}),
  });
  const server = as.provider.listen(port);
  const clientKey = (await importJWK(as.agentClientJwk as never, "ES256")) as CryptoKey;
  return { issuer, as, server, clientKey };
}

beforeAll(async () => {
  shipped = await deploy(SHIPPED_PORT);
  euro = await deploy(EURO_PORT, EURO_DERIVATION_POLICY);
  dpopKeys = await generateKeyPair("ES256", { extractable: true });
});

afterAll(() => {
  shipped?.server.close();
  euro?.server.close();
});

/** A Template Ceiling entry granting the payment, bounded per payment in `currency`. */
const paymentEntry = (currency: string) => ({
  type: "mission_resource_access",
  resource: RESOURCE,
  actions: [STANDING_PAYMENT_OPERATION],
  constraints: { max_amount: { amount: "500.00", currency }, vendors: ["acme"] },
});

/** Consent, as Bob at the approval floor, to a USD standing-payment template; returns its id. */
async function consented(d: Deployment): Promise<string> {
  const proposed = await fetch(`${d.issuer}/templates/proposals`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-service-token": DEV_SERVICE_TOKEN },
    body: JSON.stringify({
      template_version: `sp-currency-${seq++}`,
      ceiling: [paymentEntry("USD")],
      dispatch_policy: { id: "sp-currency", version: "1" },
      dispatchers: ["ap-agent"],
      recipients: {
        subjects: [{ iss: d.issuer, sub: "bob" }],
        agents: ["subagent-invoice-extractor"],
      },
      per_instance_lifetime_s: 900,
      max_active: 5,
      rate_per_min: 30,
      review_cadence_s: 86400,
      expires_at: FAR_FUTURE,
    }),
  });
  const { proposal_id: id } = (await proposed.json()) as { proposal_id: string };
  expect(proposed.status).toBe(201);
  const headers = floorApprovalHeaders(SESSIONS, id, "", { sub: "bob", subject: null });
  const page = await fetch(`${d.issuer}/templates/proposals/${id}`, {
    headers: { cookie: headers.cookie as string },
  });
  expect(page.status).toBe(200);
  const decided = await fetch(`${d.issuer}/templates/proposals/${id}/decide`, {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify({
      decision: "approve",
      render_revision: page.headers.get(RENDER_REVISION_HEADER),
    }),
  });
  const out = (await decided.json()) as { template_id: string };
  expect(decided.status, JSON.stringify(out)).toBe(201);
  return out.template_id;
}

/** Rewrite the stored template's ceiling to bound the payment in `currency`. */
const storeCeilingIn = (d: Deployment, templateId: string, currency: string) => {
  d.as.templateStore.db
    .prepare("UPDATE templates SET ceiling_json = ? WHERE id = ?")
    .run(JSON.stringify([paymentEntry(currency)]), templateId);
};

/** What exists: every Mission the kernel holds, and the template's dispatched instances. */
const created = (d: Deployment, templateId: string) => ({
  missions: d.as.kernel.allMissions().length,
  instances: d.as.kernel.standingPayments.dispatchedInstances(templateId).length,
});

/** A Dispatch at `d`'s token endpoint of `templateId`, its Intent carrying a USD 1000.00 max_budget. */
async function dispatch(
  d: Deployment,
  templateId: string,
): Promise<{ status: number; body: Record<string, unknown> }> {
  const htu = `${d.issuer}/token`;
  const eventId = `sp-currency-dsp-${seq++}`;
  const send = async (extra: Record<string, unknown> = {}) =>
    fetch(htu, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        dpop: await new SignJWT({ htu, htm: "POST", ...extra })
          .setProtectedHeader({
            alg: "ES256",
            typ: "dpop+jwt",
            jwk: await exportJWK(dpopKeys.publicKey),
          })
          .setIssuedAt()
          .setJti(crypto.randomUUID())
          .sign(dpopKeys.privateKey),
      },
      body: new URLSearchParams({
        grant_type: MISSION_DISPATCH_GRANT_TYPE,
        template_id: templateId,
        mission_intent: JSON.stringify({
          intent: {
            goal: "pay approved Acme invoices",
            target_resources: [RESOURCE],
            expires_at: FAR_FUTURE,
            max_budget: { amount: "1000.00", currency: "USD" },
          },
        }),
        dispatch_event_id: eventId,
        client_assertion: await new SignJWT({})
          .setProtectedHeader({ alg: "ES256", kid: "ap-agent-auth" })
          .setIssuer("ap-agent")
          .setSubject("ap-agent")
          .setAudience(d.issuer)
          .setIssuedAt()
          .setExpirationTime("2m")
          .setJti(crypto.randomUUID())
          .sign(d.clientKey),
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      }).toString(),
    });
  let res = await send();
  const nonce = res.headers.get("dpop-nonce");
  if (res.status === 400 && nonce) res = await send({ nonce });
  return { status: res.status, body: (await res.json()) as Record<string, unknown> };
}

describe("standing-payment currencies refused in adjudication order at the token endpoint (@spec template#standing-payment-exception, template#dispatch-adjudication, #813, D1143)", () => {
  it("dispatches at /token a consented template whose stored ceiling bounds the payment in USD under the shipped USD derivation policy (#813)", async () => {
    const id = await consented(shipped);
    const { status, body } = await dispatch(shipped, id);
    expect(status, JSON.stringify(body)).toBe(200);
    expect(created(shipped, id).instances).toBe(1);
  });

  it("refuses out_of_template_ceiling at /token, before the currency check, a Dispatch from a stored ceiling bounding the payment in EUR under the shipped USD derivation policy, creating nothing (#813)", async () => {
    const id = await consented(shipped);
    storeCeilingIn(shipped, id, "EUR");
    const before = created(shipped, id);
    const { status, body } = await dispatch(shipped, id);
    expect(status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("invalid_request");
    expect(body.mission_denial_reason).toBe("out_of_template_ceiling");
    expect(body.access_token).toBeUndefined();
    expect(created(shipped, id)).toEqual(before);
  });

  it("refuses dispatch_prohibited_class at /token a Dispatch from a stored ceiling bounding the payment in EUR under a derivation policy bounding it in EUR, where the intersection survives to the currency check, creating nothing (#813)", async () => {
    const id = await consented(euro);
    storeCeilingIn(euro, id, "EUR");
    const before = created(euro, id);
    const { status, body } = await dispatch(euro, id);
    expect(status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("invalid_request");
    expect(body.mission_denial_reason).toBe("dispatch_prohibited_class");
    expect(body.access_token).toBeUndefined();
    expect(created(euro, id)).toEqual(before);
  });
});
