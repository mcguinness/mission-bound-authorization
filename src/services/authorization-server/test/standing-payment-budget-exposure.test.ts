/**
 * @spec draft-mcguinness-oauth-mission-template (#standing-payment-exception,
 * #instance-composition), draft-mcguinness-mission-metering (#aggregate-bounds,
 * #capacity-across-missions), draft-mcguinness-oauth-mission
 * (#approval-context-changes) (#813, #816, D830 ruling 7, D877)
 *
 * The budget exposure an approval discloses: a standing-payment template
 * consent and a standing-payment successor's approval render the budget's
 * consumption to date and outstanding reservations, read through the
 * deployment's port onto the co-resident PDP's counters (here an in-memory
 * stand-in). The figures are part of what the render revision commits, so a
 * change between rendering and decision refuses the decision, and a reading
 * that cannot be made refuses the approval.
 */
import type { Server } from "node:http";
import { activationPolicyDigest } from "@mission/core";
import { CANONICAL_RESOURCE, DEV_SERVICE_TOKEN } from "@mission/demo-data";
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

const PORT = 15005;
const ISSUER = `http://localhost:${PORT}`;
const RESOURCE = CANONICAL_RESOURCE;
const FAR_FUTURE = "2099-01-01T00:00:00Z";
const ON = new Set<ProviderCapability>([...ALL_PROVIDER_CAPABILITIES, "standing-payment-dispatch"]);
const SESSIONS = new ApprovalSessionStore();
const TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";
const ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token";
const OWNER = "payments-operator";
const BUDGET_ID = "ap-standing-exposure";
const SHARED = { counter_scope: "standing_consent", owner: OWNER, budget_id: BUDGET_ID } as const;

const TERMS = {
  operation: STANDING_PAYMENT_OPERATION,
  resource: RESOURCE,
  destinations: { acme: "acct-acme-0001" },
  max_amount: { amount: "500.00", currency: "USD" },
  budget: {
    owner: OWNER,
    id: BUDGET_ID,
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
const POLICY = {
  version: "1",
  content_type: "application/json",
  content: JSON.stringify({
    id: "sp-exposure",
    derivation_limit_ceiling: 3,
    standing_payment: TERMS,
  }),
};
const POLICIES = { "sp-exposure": POLICY };

/** The statement metering the policy's budget under the Exact profile. */
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
          budget_id: BUDGET_ID,
          counter_scope: "standing_consent",
          currency: "USD",
          limit: TERMS.budget.limit,
          policies: [
            { id: "sp-exposure", version: "1", digest: activationPolicyDigest(issuer, POLICY) },
          ],
        },
      ],
    },
  },
});

const counters = new FakeBudgetCounters();
let as: BuiltAs;
let server: Server;
let clientKey: CryptoKey;
let dpopKeys: { privateKey: CryptoKey; publicKey: CryptoKey };
let seq = 0;

beforeAll(async () => {
  as = await buildAuthorizationServer({
    issuer: ISSUER,
    capabilities: ON,
    approvalSessions: SESSIONS,
    dispatchPolicies: POLICIES,
    enforcementScopeStatement: meteringStatement(ISSUER),
    budgetExposure: counters,
  });
  server = as.provider.listen(PORT);
  clientKey = (await importJWK(as.agentClientJwk as never, "ES256")) as CryptoKey;
  dpopKeys = await generateKeyPair("ES256", { extractable: true });
});

afterAll(() => {
  server?.close();
});

/**
 * The template proposal. `approver` names whose recipients it lists: the
 * instances' Subject is the consenting Approver, and Alice's instances are
 * the ones Bob may approve a write-bearing successor for.
 */
const proposal = (subject: string) => ({
  template_version: `sp-exposure-${seq++}`,
  ceiling: [
    {
      type: "mission_resource_access",
      resource: RESOURCE,
      actions: [STANDING_PAYMENT_OPERATION],
      constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
    },
  ],
  dispatch_policy: { id: "sp-exposure", version: "1" },
  dispatchers: ["ap-agent"],
  recipients: { subjects: [{ iss: ISSUER, sub: subject }], agents: ["ap-agent"] },
  per_instance_lifetime_s: 900,
  max_active: 5,
  rate_per_min: 30,
  review_cadence_s: 86400,
  expires_at: FAR_FUTURE,
});

async function propose(subject = "bob"): Promise<string> {
  const res = await fetch(`${ISSUER}/templates/proposals`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-service-token": DEV_SERVICE_TOKEN },
    body: JSON.stringify(proposal(subject)),
  });
  const out = (await res.json()) as { proposal_id: string };
  expect(res.status, JSON.stringify(out)).toBe(201);
  return out.proposal_id;
}

/** `sub`'s login, at the floor (mfa), on the user agent reviewing `key`, selecting no Subject. */
const login = (key: string, sub: string) =>
  floorApprovalHeaders(SESSIONS, key, "", { sub, subject: null });
const cookieOf = (headers: Record<string, string>) => ({ cookie: headers.cookie as string });

async function consentPage(id: string, headers: Record<string, string>) {
  const res = await fetch(`${ISSUER}/templates/proposals/${id}`, { headers: cookieOf(headers) });
  return {
    status: res.status,
    html: await res.text(),
    revision: res.headers.get(RENDER_REVISION_HEADER),
  };
}

async function decideConsent(id: string, headers: Record<string, string>, revision: string | null) {
  const res = await fetch(`${ISSUER}/templates/proposals/${id}/decide`, {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify({ decision: "approve", render_revision: revision }),
  });
  return {
    status: res.status,
    body: (await res.json()) as {
      template_id?: string;
      error?: string;
      error_description?: string;
    },
  };
}

/** A template the Approver `sub` consented to, for instances acting for `sub`. */
async function consented(sub: string): Promise<string> {
  const id = await propose(sub);
  const headers = login(id, sub);
  const { revision } = await consentPage(id, headers);
  const decided = await decideConsent(id, headers, revision);
  expect(decided.status, JSON.stringify(decided.body)).toBe(201);
  return decided.body.template_id as string;
}

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

async function token(
  params: Record<string, string>,
): Promise<{ status: number; body: Record<string, unknown> }> {
  const htu = `${ISSUER}/token`;
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
        ...params,
        client_assertion: await clientAssertion(),
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      }).toString(),
    });
  let res = await send();
  const nonce = res.headers.get("dpop-nonce");
  if (res.status === 400 && nonce) res = await send({ nonce });
  return { status: res.status, body: (await res.json()) as Record<string, unknown> };
}

const maxBudget = { amount: "1000.00", currency: "USD" };

/** Dispatch an instance of `templateId`; returns its access token and Mission id. */
async function dispatched(templateId: string): Promise<{ accessToken: string; missionId: string }> {
  const before = new Set(as.kernel.standingPayments.dispatchedInstances(templateId));
  const { status, body } = await token({
    grant_type: MISSION_DISPATCH_GRANT_TYPE,
    template_id: templateId,
    mission_intent: JSON.stringify({
      intent: {
        goal: "pay approved Acme invoices",
        target_resources: [RESOURCE],
        expires_at: FAR_FUTURE,
        max_budget: maxBudget,
      },
    }),
    dispatch_event_id: `sp-exposure-dsp-${seq++}`,
  });
  expect(status, JSON.stringify(body)).toBe(200);
  const [missionId] = as.kernel.standingPayments
    .dispatchedInstances(templateId)
    .filter((m) => !before.has(m));
  return { accessToken: body.access_token as string, missionId: missionId as string };
}

/** Open a deferred expansion of the instance that keeps its max_budget; returns the deferral code. */
async function expansionDeferral(accessToken: string): Promise<string> {
  const { status, body } = await token({
    grant_type: TOKEN_EXCHANGE,
    subject_token: accessToken,
    subject_token_type: ACCESS_TOKEN,
    requested_token_type: ACCESS_TOKEN,
    mission_intent: JSON.stringify({
      intent: {
        goal: "pay and read Acme invoices",
        target_resources: [RESOURCE],
        expires_at: FAR_FUTURE,
        max_budget: maxBudget,
      },
    }),
    authorization_details: JSON.stringify([
      {
        type: "mission_resource_access",
        resource: RESOURCE,
        actions: [STANDING_PAYMENT_OPERATION, "payments:invoice.read"],
        constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
      },
    ]),
    creation_request_id: crypto.randomUUID(),
    completion_mode: "deferred",
  });
  expect(typeof body.deferral_code, `${status} ${JSON.stringify(body)}`).toBe("string");
  return body.deferral_code as string;
}

async function deferralPage(code: string, headers: Record<string, string>) {
  const res = await fetch(`${ISSUER}/expansions/deferrals/${code}`, { headers: cookieOf(headers) });
  return {
    status: res.status,
    html: await res.text(),
    revision: res.headers.get(RENDER_REVISION_HEADER),
  };
}

async function decideDeferral(
  code: string,
  headers: Record<string, string>,
  revision: string | null,
) {
  const res = await fetch(`${ISSUER}/expansions/deferrals/${code}/decide`, {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify({ decision: "approve", render_revision: revision }),
  });
  return {
    status: res.status,
    body: (await res.json()) as { state?: string; error?: string; changed?: string[] },
  };
}

/** A pending deferral of a fresh instance of a template Alice consented to, and the instance. */
async function standingPaymentSuccessorDeferral(): Promise<{ code: string; instance: string }> {
  const templateId = await consented("alice");
  const { accessToken, missionId } = await dispatched(templateId);
  return { code: await expansionDeferral(accessToken), instance: missionId };
}

const exposureLine = (label: string, committed: string, reserved: string, held: string) =>
  `${label}: consumption to date ${committed} USD committed; outstanding reservations ${reserved} USD reserved and ${held} USD held pending reconciliation, as read at this rendering.`;

describe("budget exposure on the standing-payment template consent (@spec template#standing-payment-exception, metering#aggregate-bounds, #813, D877)", () => {
  it("refuses to build the authorization server with the standing-payment capability and no budget exposure port (#813, D877)", async () => {
    await expect(
      buildAuthorizationServer({
        issuer: "http://localhost:15006",
        capabilities: ON,
        dispatchPolicies: POLICIES,
        enforcementScopeStatement: meteringStatement("http://localhost:15006"),
      }),
    ).rejects.toThrow(
      "the standing-payment-dispatch capability needs a budget exposure port (budgetExposure)",
    );
  });

  it("renders the budget's consumption to date and outstanding reservations on the standing-payment consent page, as the counters read (#813, D877)", async () => {
    counters.set(SHARED, { committed: "125.00", reserved: "30.00", held: "20.00" });
    const id = await propose();
    const { status, html } = await consentPage(id, login(id, "bob"));
    expect(status).toBe(200);
    expect(html).toContain(
      exposureLine(`Budget ${OWNER}/${BUDGET_ID} exposure`, "125.00", "30.00", "20.00"),
    );
  });

  it("refuses a consent decision when the budget's consumption changed between its rendering and the decision, and approves the consent rendered again (@spec mission#approval-context-changes, #1586, #813, D877)", async () => {
    counters.set(SHARED, { committed: "125.00", reserved: "0.00", held: "0.00" });
    const id = await propose();
    const headers = login(id, "bob");
    const first = await consentPage(id, headers);
    counters.set(SHARED, { committed: "250.00", reserved: "0.00", held: "0.00" });
    const refused = await decideConsent(id, headers, first.revision);
    expect(refused.status).toBe(409);
    expect(refused.body.error).toBe("approval_context_changed");
    expect(as.templateStore.getByApprovalEvent(`apev_${id}`)).toBeUndefined();
    const again = await consentPage(id, headers);
    expect(again.html).toContain(
      exposureLine(`Budget ${OWNER}/${BUDGET_ID} exposure`, "250.00", "0.00", "0.00"),
    );
    const approved = await decideConsent(id, headers, again.revision);
    expect(approved.status, JSON.stringify(approved.body)).toBe(201);
  });

  it("refuses to render a decision on a standing-payment consent whose budget counters cannot be read (@spec template#standing-payment-exception, #813, D830 ruling 7)", async () => {
    const id = await propose();
    counters.failing = true;
    try {
      const { status, html, revision } = await consentPage(id, login(id, "bob"));
      expect(status).toBe(200);
      expect(html).toContain(
        `The consumption and outstanding reservations of budget ${OWNER}/${BUDGET_ID} cannot be read`,
      );
      expect(html).not.toContain('name="decision"');
      expect(revision).toBeNull();
    } finally {
      counters.failing = false;
    }
  });

  it("refuses a standing-payment consent decision access_denied when the budget counters cannot be read at the decision, creating no template (@spec template#standing-payment-exception, #813, D830 ruling 7)", async () => {
    const id = await propose();
    const headers = login(id, "bob");
    const { revision } = await consentPage(id, headers);
    counters.failing = true;
    try {
      const refused = await decideConsent(id, headers, revision);
      expect(refused.status).toBe(403);
      expect(refused.body.error).toBe("access_denied");
      expect(refused.body.error_description).toContain(
        `budget ${OWNER}/${BUDGET_ID} cannot be read`,
      );
      expect(as.templateStore.getByApprovalEvent(`apev_${id}`)).toBeUndefined();
    } finally {
      counters.failing = false;
    }
  });
});

describe("budget exposure on a standing-payment successor's approval (@spec template#instance-composition, metering#capacity-across-missions, #813, D877)", () => {
  it("renders the dispatched instance's and the shared budget's consumption to date and outstanding reservations on the successor's approval page (#813, D877)", async () => {
    const { code, instance } = await standingPaymentSuccessorDeferral();
    counters.set(
      { counter_scope: "mission", issuer: ISSUER, mission_id: instance },
      { committed: "40.00", reserved: "10.00", held: "5.00" },
    );
    counters.set(SHARED, { committed: "300.00", reserved: "10.00", held: "5.00" });
    const { status, html } = await deferralPage(code, login(code, "bob"));
    expect(status, html).toBe(200);
    expect(html).toContain(`continues the counter of the dispatched instance ${instance}`);
    expect(html).toContain(exposureLine(`Instance ${instance}`, "40.00", "10.00", "5.00"));
    expect(html).toContain(exposureLine(`Budget ${OWNER}/${BUDGET_ID}`, "300.00", "10.00", "5.00"));
  });

  it("refuses a successor approval when the budget's consumption changed between its rendering and the decision, naming the budget exposure, and approves the successor rendered again (@spec mission#approval-context-changes, #1586, #813, D877)", async () => {
    const { code, instance } = await standingPaymentSuccessorDeferral();
    const key = { counter_scope: "mission", issuer: ISSUER, mission_id: instance } as const;
    counters.set(key, { committed: "40.00", reserved: "0.00", held: "0.00" });
    const headers = login(code, "bob");
    const first = await deferralPage(code, headers);
    counters.set(key, { committed: "90.00", reserved: "0.00", held: "0.00" });
    const refused = await decideDeferral(code, headers, first.revision);
    expect(refused.status).toBe(409);
    expect(refused.body.error).toBe("approval_context_changed");
    expect(refused.body.changed).toEqual(["budget_exposure"]);
    expect(as.expansionDeferrals.pendingRequest(code)).toBeDefined();
    const again = await deferralPage(code, headers);
    const approved = await decideDeferral(code, headers, again.revision);
    expect(approved.status, JSON.stringify(approved.body)).toBe(200);
    expect(approved.body.state).toBe("approved");
  });

  it("refuses to render a standing-payment successor's approval page whose budget counters cannot be read (@spec template#instance-composition, #813, D830 ruling 7)", async () => {
    const { code } = await standingPaymentSuccessorDeferral();
    counters.failing = true;
    try {
      const { status, html, revision } = await deferralPage(code, login(code, "bob"));
      expect(status).toBe(503);
      expect(html).toContain("The standing-payment budget this successor continues cannot be read");
      expect(revision).toBeNull();
    } finally {
      counters.failing = false;
    }
  });

  it("refuses a standing-payment successor approval when the budget counters cannot be read at the decision, approving nothing (@spec template#instance-composition, #813, D830 ruling 7)", async () => {
    const { code } = await standingPaymentSuccessorDeferral();
    const headers = login(code, "bob");
    const { revision } = await deferralPage(code, headers);
    counters.failing = true;
    try {
      const refused = await decideDeferral(code, headers, revision);
      expect(refused.status).toBe(503);
      expect(refused.body.error).toBe("temporarily_unavailable");
    } finally {
      counters.failing = false;
    }
    expect(as.expansionDeferrals.pendingRequest(code)).toBeDefined();
  });
});
