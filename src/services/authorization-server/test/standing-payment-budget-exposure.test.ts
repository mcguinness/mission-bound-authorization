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
import { activationPolicyDigest, authorityHash, intentHash } from "@mission/core";
import { CANONICAL_RESOURCE, DEV_SERVICE_TOKEN } from "@mission/demo-data";
import { decodeJwt, exportJWK, generateKeyPair, importJWK, SignJWT } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { contentDigest, RENDER_REVISION_HEADER } from "../src/adapters/approval-render-revision.js";
import {
  ALL_PROVIDER_CAPABILITIES,
  type ProviderCapability,
} from "../src/adapters/capabilities.js";
import {
  type DeferralBudgetExposure,
  deferralContext,
  renderDeferralPage,
} from "../src/adapters/expansion-deferral-surface.js";
import { MISSION_DISPATCH_GRANT_TYPE } from "../src/adapters/provider.js";
import {
  type BudgetCounterKey,
  BudgetExposureUnavailableError,
  meteringUnitOf,
  readCounterExposure,
} from "../src/kernel/budget-exposure.js";
import type { DeferralReview } from "../src/kernel/deferred.js";
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
const DEFERRED_GRANT = "urn:ietf:params:oauth:grant-type:deferred";
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
      expect(status).toBe(503);
      expect(html).toContain(
        `The consumption and outstanding reservations of budget ${OWNER}/${BUDGET_ID} cannot be read`,
      );
      expect(html).toContain("It cannot be decided until they can be read.");
      expect(html).not.toContain('name="decision"');
      expect(revision).toBeNull();
    } finally {
      counters.failing = false;
    }
  });

  it("answers a standing-payment consent decision temporarily_unavailable when the budget counters cannot be read at the decision, creating no template and leaving the proposal pending for a decision once they can be read (@spec template#standing-payment-exception, #813, D830 ruling 7)", async () => {
    const id = await propose();
    const headers = login(id, "bob");
    const { revision } = await consentPage(id, headers);
    counters.failing = true;
    try {
      const refused = await decideConsent(id, headers, revision);
      expect(refused.status).toBe(503);
      expect(refused.body.error).toBe("temporarily_unavailable");
      expect(refused.body.error_description).toContain(
        `budget ${OWNER}/${BUDGET_ID} cannot be read`,
      );
      expect(as.templateStore.getByApprovalEvent(`apev_${id}`)).toBeUndefined();
    } finally {
      counters.failing = false;
    }
    const again = await consentPage(id, headers);
    const approved = await decideConsent(id, headers, again.revision);
    expect(approved.status, JSON.stringify(approved.body)).toBe(201);
  });

  it("shows no budget figures on the standing-payment consent page to a viewer who has not authenticated as the Approver, and reads no counter for it, while the Approver's rendering shows them (@spec template#standing-payment-exception, #813, D877)", async () => {
    counters.set(SHARED, { committed: "321.00", reserved: "4.00", held: "5.00" });
    const id = await propose();
    const readsBefore = counters.reads;
    const res = await fetch(`${ISSUER}/templates/proposals/${id}`);
    const html = await res.text();
    expect(res.status).toBe(200);
    expect(res.headers.get(RENDER_REVISION_HEADER)).toBeNull();
    expect(counters.reads).toBe(readsBefore);
    expect(html).not.toContain("321.00");
    expect(html).not.toContain("USD committed");
    expect(html).toContain(
      `Budget ${OWNER}/${BUDGET_ID} exposure: its consumption to date and outstanding reservations are shown once the Approver signs in.`,
    );
    const shown = await consentPage(id, login(id, "bob"));
    expect(shown.html).toContain(
      exposureLine(`Budget ${OWNER}/${BUDGET_ID} exposure`, "321.00", "4.00", "5.00"),
    );
    expect(counters.reads).toBeGreaterThan(readsBefore);
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

/**
 * Swap the port's reading for `reading` while `fn` runs, then restore it. The
 * swap stands in for a deployment port that is not the shipped synchronous
 * one: a JavaScript port of another shape, or an asynchronous one.
 */
async function withReading<T>(reading: () => unknown, fn: () => Promise<T>): Promise<T> {
  const original = counters.read;
  counters.read = reading as typeof counters.read;
  try {
    return await fn();
  } finally {
    counters.read = original;
  }
}

/**
 * A consent and a successor approval each rendered against a reading the
 * port makes properly, then rendered and decided while the port answers
 * `reading`: both renderings and both decisions are refused, naming
 * `reason`, no template is created and the successor stays pending.
 */
async function refusedOnBothSurfaces(reading: () => unknown, reason: string): Promise<void> {
  const id = await propose();
  const headers = login(id, "bob");
  const consent = await consentPage(id, headers);
  expect(consent.revision).not.toBeNull();
  const { code } = await standingPaymentSuccessorDeferral();
  const bob = login(code, "bob");
  const successor = await deferralPage(code, bob);
  expect(successor.revision).not.toBeNull();
  await withReading(reading, async () => {
    const page = await consentPage(id, headers);
    expect(page.status).toBe(503);
    expect(page.html).toContain(reason);
    expect(page.html).not.toContain("USD committed");
    expect(page.html).not.toContain('name="decision"');
    expect(page.revision).toBeNull();
    const decided = await decideConsent(id, headers, consent.revision);
    expect(decided.status).toBe(503);
    expect(decided.body.error).toBe("temporarily_unavailable");
    expect(decided.body.error_description).toContain(reason);
    const deferral = await deferralPage(code, bob);
    expect(deferral.status).toBe(503);
    expect(deferral.html).toContain(reason);
    expect(deferral.html).not.toContain("USD committed");
    expect(deferral.revision).toBeNull();
    const approved = await decideDeferral(code, bob, successor.revision);
    expect(approved.status).toBe(503);
    expect(approved.body.error).toBe("temporarily_unavailable");
  });
  expect(as.templateStore.getByApprovalEvent(`apev_${id}`)).toBeUndefined();
  expect(as.expansionDeferrals.pendingRequest(code)).toBeDefined();
}

describe("a budget port reading that is not the counters' totals, made now, refuses the approval (@spec template#standing-payment-exception, template#instance-composition, #813, D830 ruling 7, D877)", () => {
  it("refuses to render and to decide a standing-payment consent and a standing-payment successor approval when the budget port's reading has no totals, creating no template and approving no successor (#813, D830 ruling 7)", async () => {
    await refusedOnBothSurfaces(() => ({}), "committed total is not a decimal amount in USD at exponent 2");
  });

  it("refuses to render and to decide a standing-payment consent and a standing-payment successor approval when the budget port answers with a Promise of the totals, creating no template and approving no successor (#813, D830 ruling 7)", async () => {
    const original = counters.read.bind(counters);
    await refusedOnBothSurfaces(
      () => Promise.resolve(original(SHARED)),
      "reading was deferred, not made now",
    );
  });

  it("refuses to render and to decide a standing-payment consent and a standing-payment successor approval when the budget port answers with a rejected Promise, creating no template, approving no successor and leaving no rejection unhandled (#813, D830 ruling 7)", async () => {
    const unhandled: unknown[] = [];
    const onUnhandled = (reason: unknown) => {
      unhandled.push(reason);
    };
    process.on("unhandledRejection", onUnhandled);
    try {
      await refusedOnBothSurfaces(
        () => Promise.reject(new Error("the claim domain is down")),
        "reading was deferred, not made now",
      );
      await new Promise((resolve) => setTimeout(resolve, 50));
    } finally {
      process.off("unhandledRejection", onUnhandled);
    }
    expect(unhandled).toEqual([]);
  });
});

describe("reading one budget counter in the declared unit (@spec template#standing-payment-exception, metering#aggregate-bounds, #813, D877)", () => {
  const key: BudgetCounterKey = SHARED;
  const usd2 = { currency: "USD", exponent: 2 };
  const port = (totals: unknown) => ({ read: () => totals as never });
  const amounts = (committed: string, reserved: string, held: string, currency = "USD") => ({
    committed: { amount: committed, currency },
    reserved: { amount: reserved, currency },
    held: { amount: held, currency },
  });

  it("reads a counter never charged as zero written at the declared exponent, not at a fixed two digits (#813, D877)", () => {
    for (const [exponent, zero] of [
      [0, "0"],
      [2, "0.00"],
      [3, "0.000"],
    ] as const) {
      const read = readCounterExposure(port(undefined), key, { currency: "JPY", exponent });
      expect(read.committed).toEqual({ amount: zero, currency: "JPY" });
      expect(read.reserved).toEqual({ amount: zero, currency: "JPY" });
      expect(read.held).toEqual({ amount: zero, currency: "JPY" });
    }
  });

  it("reads a counter's committed, reserved and held totals as the port reports them in the declared unit (#813, D877)", () => {
    expect(readCounterExposure(port(amounts("125.00", "30.00", "20.00")), key, usd2)).toEqual({
      counter_scope: "standing_consent",
      ...amounts("125.00", "30.00", "20.00"),
    });
  });

  it("refuses a counter reading with a total in another currency than the declared unit's, for each of committed, reserved and held (#813, D830 ruling 7)", () => {
    for (const member of ["committed", "reserved", "held"] as const) {
      const totals = { ...amounts("125.00", "30.00", "20.00"), [member]: { amount: "1.00", currency: "EUR" } };
      expect(() => readCounterExposure(port(totals), key, usd2)).toThrow(BudgetExposureUnavailableError);
      expect(() => readCounterExposure(port(totals), key, usd2)).toThrow(`${member} total`);
    }
  });

  it("refuses a counter reading with a total that is not a decimal amount at the declared exponent, for each of committed, reserved and held (#813, D830 ruling 7)", () => {
    for (const member of ["committed", "reserved", "held"] as const) {
      for (const amount of ["125", "125.0", "125.000", "-1.00", "1e2", "", "NaN"]) {
        const totals = { ...amounts("125.00", "30.00", "20.00"), [member]: { amount, currency: "USD" } };
        expect(() => readCounterExposure(port(totals), key, usd2), `${member} ${amount}`).toThrow(
          BudgetExposureUnavailableError,
        );
      }
      const missing: Record<string, unknown> = amounts("125.00", "30.00", "20.00");
      delete missing[member];
      expect(() => readCounterExposure(port(missing), key, usd2)).toThrow(BudgetExposureUnavailableError);
      const numeric = { ...amounts("125.00", "30.00", "20.00"), [member]: { amount: 125, currency: "USD" } };
      expect(() => readCounterExposure(port(numeric), key, usd2)).toThrow(BudgetExposureUnavailableError);
    }
    expect(() => readCounterExposure(port(null), key, usd2)).toThrow(BudgetExposureUnavailableError);
  });

  it("renders a never-charged budget counter on the standing-payment consent page as zero at the exponent the Enforcement Scope Statement declares (#813, D877)", async () => {
    const issuer = "http://localhost:15008";
    const statement = meteringStatement(issuer);
    statement.extensions.budget_metering.unit = { currency: "USD", exponent: 3 };
    const sessions = new ApprovalSessionStore();
    const built = await buildAuthorizationServer({
      issuer,
      capabilities: ON,
      approvalSessions: sessions,
      dispatchPolicies: POLICIES,
      enforcementScopeStatement: statement,
      budgetExposure: new FakeBudgetCounters(),
    });
    const listening = built.provider.listen(15008);
    try {
      const proposed = await fetch(`${issuer}/templates/proposals`, {
        method: "POST",
        headers: { "content-type": "application/json", "x-service-token": DEV_SERVICE_TOKEN },
        body: JSON.stringify({
          ...proposal("bob"),
          recipients: { subjects: [{ iss: issuer, sub: "bob" }], agents: ["ap-agent"] },
        }),
      });
      const { proposal_id } = (await proposed.json()) as { proposal_id: string };
      expect(proposed.status).toBe(201);
      const headers = floorApprovalHeaders(sessions, proposal_id, "", { sub: "bob", subject: null });
      const page = await fetch(`${issuer}/templates/proposals/${proposal_id}`, {
        headers: { cookie: headers.cookie as string },
      });
      expect(page.status).toBe(200);
      expect(await page.text()).toContain(
        `Budget ${OWNER}/${BUDGET_ID} exposure: consumption to date 0.000 USD committed; outstanding reservations 0.000 USD reserved and 0.000 USD held pending reconciliation, as read at this rendering.`,
      );
    } finally {
      listening.close();
    }
  });

  it("refuses a counter reading when no unit is declared, as when the Enforcement Scope Statement declares none (#813, D877)", () => {
    expect(() => readCounterExposure(port(undefined), key, undefined)).toThrow(BudgetExposureUnavailableError);
  });

  it("takes the counters' unit from the Enforcement Scope Statement's budget_metering declaration only when it is a currency code and a whole exponent from 0 to 9 (#813, D877)", () => {
    const statement = (unit: unknown) => ({ extensions: { budget_metering: { unit } } });
    expect(meteringUnitOf(statement({ currency: "USD", exponent: 2 }))).toEqual({ currency: "USD", exponent: 2 });
    expect(meteringUnitOf(statement({ currency: "JPY", exponent: 0 }))).toEqual({ currency: "JPY", exponent: 0 });
    expect(meteringUnitOf(statement({ currency: "XAU", exponent: 9 }))).toEqual({ currency: "XAU", exponent: 9 });
    for (const unit of [
      { currency: "USD", exponent: 10 },
      { currency: "USD", exponent: -1 },
      { currency: "USD", exponent: 1.5 },
      { currency: "USD", exponent: "2" },
      { currency: "USD" },
      { currency: "usd", exponent: 2 },
      { exponent: 2 },
      null,
    ]) {
      expect(meteringUnitOf(statement(unit)), JSON.stringify(unit)).toBeUndefined();
    }
    expect(meteringUnitOf(undefined)).toBeUndefined();
    expect(meteringUnitOf({ extensions: {} })).toBeUndefined();
  });
});

describe("a second-generation standing-payment successor's approval (@spec template#instance-composition, metering#capacity-across-missions, #813, D877)", () => {
  it("keys a second-generation successor's approval page by the dispatched instance's counter, not by its predecessor's (#813, D877)", async () => {
    const { code, instance } = await standingPaymentSuccessorDeferral();
    const bob = login(code, "bob");
    const first = await deferralPage(code, bob);
    expect((await decideDeferral(code, bob, first.revision)).status).toBe(200);
    const polled = await token({ grant_type: DEFERRED_GRANT, deferral_code: code });
    expect(polled.status, JSON.stringify(polled.body)).toBe(200);
    const successorToken = polled.body.access_token as string;
    const successorId = (decodeJwt(successorToken) as { mission: { id: string } }).mission.id;
    expect(successorId).not.toBe(instance);
    const { status, body } = await token({
      grant_type: TOKEN_EXCHANGE,
      subject_token: successorToken,
      subject_token_type: ACCESS_TOKEN,
      requested_token_type: ACCESS_TOKEN,
      mission_intent: JSON.stringify({
        intent: {
          goal: "pay, read and list Acme invoices",
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
        { type: "mission_resource_access", resource: RESOURCE, actions: ["payments:invoice.list"] },
      ]),
      creation_request_id: crypto.randomUUID(),
      completion_mode: "deferred",
    });
    expect(typeof body.deferral_code, `${status} ${JSON.stringify(body)}`).toBe("string");
    const second = body.deferral_code as string;
    expect(as.expansionDeferrals.pendingRequest(second)?.predecessor.id).toBe(successorId);
    counters.set({ counter_scope: "mission", issuer: ISSUER, mission_id: instance }, { committed: "77.00", reserved: "1.00", held: "2.00" });
    counters.set({ counter_scope: "mission", issuer: ISSUER, mission_id: successorId }, { committed: "88.00", reserved: "3.00", held: "4.00" });
    counters.set(SHARED, { committed: "410.00", reserved: "6.00", held: "7.00" });
    const page = await deferralPage(second, login(second, "bob"));
    expect(page.status, page.html).toBe(200);
    expect(page.html).toContain(`continues the counter of the dispatched instance ${instance}`);
    expect(page.html).toContain(exposureLine(`Instance ${instance}`, "77.00", "1.00", "2.00"));
    expect(page.html).toContain(exposureLine(`Budget ${OWNER}/${BUDGET_ID}`, "410.00", "6.00", "7.00"));
    expect(page.html).not.toContain("88.00");
  });
});

describe("an ordinary deferral's approval is unchanged by the budget exposure (@spec mission#approval-context-changes, expansion#completion-modes, #1558, #813, D877)", () => {
  const issuer = "https://as.example";
  const review = {
    deferralCode: "dfr_ordinary",
    clientId: "client-ordinary",
    predecessor: { id: "msn_ordinary", issuer, subject: { iss: issuer, sub: "alice" } },
    intent: { goal: "read invoices", target_resources: [RESOURCE], expires_at: FAR_FUTURE },
    successor: [{ type: "mission_resource_access", resource: RESOURCE, actions: ["payments:invoice.read"] }],
    disclosure: { predecessor: "msn_ordinary", restrictions: { contained: [], discharged: [] } },
  } as unknown as DeferralReview;
  const exposure: DeferralBudgetExposure = {
    instance: "msn_instance",
    budget: { owner: OWNER, id: BUDGET_ID },
    counters: [
      { counter_scope: "mission", ...{ committed: { amount: "1.00", currency: "USD" }, reserved: { amount: "2.00", currency: "USD" }, held: { amount: "3.00", currency: "USD" } } },
      { counter_scope: "standing_consent", ...{ committed: { amount: "4.00", currency: "USD" }, reserved: { amount: "5.00", currency: "USD" }, held: { amount: "6.00", currency: "USD" } } },
    ],
  };

  it("commits an ordinary deferral's rendering with no budget_exposure member, as before the budget exposure, and renders its page with no line for it (#813, D877)", () => {
    const { context, commitment } = deferralContext(review, FAR_FUTURE);
    expect(Object.hasOwn(context, "budget_exposure")).toBe(false);
    expect(commitment).toBe(
      contentDigest({
        predecessor: "msn_ordinary",
        client_id: "client-ordinary",
        subject: { iss: issuer, sub: "alice" },
        intent_hash: intentHash(issuer, review.intent as never),
        proposal_hash: null,
        successor_hash: authorityHash(issuer, review.successor as never),
        expires_at: FAR_FUTURE,
        fallback: null,
        encounter: null,
        restrictions: contentDigest({ contained: [], discharged: [] }),
        reconsent_offer: null,
        review: null,
        carryover: null,
      }),
    );
    const ordinary = renderDeferralPage(review, context, {});
    expect(ordinary).not.toContain("budget-exposure");
    // As the page rendered before the budget exposure: one line per section
    // between the expiry and the form, the empty ones included, and no more.
    expect(ordinary.slice(ordinary.indexOf("</time></p>"), ordinary.indexOf("<form"))).toBe(
      `</time></p>\n\n<h2>The chain's outstanding restrictions (this approval clears none)</h2>\n<p class="restrictions">None.</p>\n\n\n`,
    );
    // The exposure section is the only difference a standing-payment
    // successor's page makes: removing it leaves the ordinary page exactly.
    const metered = renderDeferralPage(review, deferralContext(review, FAR_FUTURE, exposure).context, {});
    const section = metered.match(/<section class="budget-exposure">[\s\S]*?<\/section>\n/)?.[0];
    expect(section).toBeDefined();
    expect(metered.replace(section as string, "")).toBe(ordinary);
  });
});
