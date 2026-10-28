/**
 * @spec draft-mcguinness-oauth-mission-template (#standing-payment-exception,
 * #template-consent, #grant-type, #instance-composition),
 * draft-mcguinness-mission-metering (#bounds, #capacity-across-missions)
 * (#813, #816, D877)
 *
 * Each template defect the kernel refuses, driven through the surface where
 * it is observed: the token endpoint for a Dispatch, the consent route for a
 * consent, and construction for a Dispatch Policy defect (a running AS holds
 * no defective policy: its startup checks parse every held policy). Every
 * refusal asserts its reason and that nothing was created: no Mission, no
 * dispatched instance, no template.
 */
import type { Server } from "node:http";
import { activationPolicyDigest, intentHash } from "@mission/core";
import { APPROVAL_FLOOR, CANONICAL_RESOURCE, DEV_SERVICE_TOKEN } from "@mission/demo-data";
import {
  calculateJwkThumbprint,
  decodeJwt,
  exportJWK,
  generateKeyPair,
  importJWK,
  SignJWT,
} from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { RENDER_REVISION_HEADER } from "../src/adapters/approval-render-revision.js";
import {
  ALL_PROVIDER_CAPABILITIES,
  type ProviderCapability,
} from "../src/adapters/capabilities.js";
import { MISSION_DISPATCH_GRANT_TYPE } from "../src/adapters/provider.js";
import {
  MACHINE_SPEED_STATEMENT,
  STANDING_PAYMENT_STATEMENT,
  TEMPLATE_CEILING_STATEMENT,
} from "../src/adapters/template-consent.js";
import {
  ApprovalSessionStore,
  type BuiltAs,
  buildAuthorizationServer,
  STANDING_PAYMENT_OPERATION,
  StandingPaymentConfigError,
  standingPaymentBudgetBindingOf,
} from "../src/index.js";
import { actionClassesAt } from "../src/kernel/approval-floor.js";
import { browserApprovalHeaders, floorApprovalHeaders } from "./approval-fixture.js";
import { FakeBudgetCounters } from "./budget-exposure.helper.js";

const PORT = 15007;
const ISSUER = `http://localhost:${PORT}`;
const OFF_PORT = 15009;
const OFF_ISSUER = `http://localhost:${OFF_PORT}`;
const RESOURCE = CANONICAL_RESOURCE;
const FAR_FUTURE = "2099-01-01T00:00:00Z";
const ON = new Set<ProviderCapability>([...ALL_PROVIDER_CAPABILITIES, "standing-payment-dispatch"]);
const SESSIONS = new ApprovalSessionStore();
const TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";
const ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token";
const JWT_TOKEN = "urn:ietf:params:oauth:token-type:jwt";
const OWNER = "payments-operator";
const DEFERRED_GRANT = "urn:ietf:params:oauth:grant-type:deferred";
const ID_JAG = "urn:ietf:params:oauth:token-type:id-jag";
const ICA_TOKEN = "urn:ietf:params:oauth:token-type:identity-continuation";
/** The Resource AS a cross-domain continuation is audienced to, and the assertion issuer trusted for it. */
const RAS = "https://ras.ledgercloud.test";
const CAI = "https://cai.batch.example";
/**
 * Whether the payments resource is served by the RAS. It is local while a
 * standing payment is dispatched (a cross-domain payment is never admitted)
 * and is switched to the RAS only to drive a cross-domain continuation of an
 * instance already admitted, as a topology change after admission would.
 */
let paymentsAtRas = false;

const recency = (exceptions: Record<string, { max_age_s: number }>) => ({
  recency: { ceilings: { default: 86400 }, clock_skew_s: 60, exceptions },
});
const BOTH_EXCEPTIONS = {
  irreversible_action: { max_age_s: 3600 },
  consumption_bound: { max_age_s: 3600 },
};
const terms = (budgetId: string, over: Record<string, unknown> = {}) => ({
  operation: STANDING_PAYMENT_OPERATION,
  resource: RESOURCE,
  destinations: { acme: "acct-acme-0001" },
  max_amount: { amount: "500.00", currency: "USD" },
  budget: {
    owner: OWNER,
    id: budgetId,
    currency: "USD",
    limit: "5000.00",
    per_instance_max: "1000.00",
  },
  approval_governance: recency(BOTH_EXCEPTIONS),
  ...over,
});
const policy = (id: string, t: unknown) => ({
  version: "1",
  content_type: "application/json",
  content: JSON.stringify({ id, derivation_limit_ceiling: 3, standing_payment: t }),
});

/**
 * The batch's Dispatch Policies, each with its own budget: the ordinary one,
 * one with no class-named exception for the consumption bound, and one an
 * operator edits in place under its version.
 */
const POLICIES: Record<string, { version: string; content_type: string; content: string }> = {
  "sp-batch": policy("sp-batch", terms("ap-batch")),
  "sp-batch-no-cb": policy(
    "sp-batch-no-cb",
    terms("ap-batch-no-cb", {
      approval_governance: recency({ irreversible_action: { max_age_s: 3600 } }),
    }),
  ),
  "sp-batch-editable": policy("sp-batch-editable", terms("ap-batch-editable")),
};

/** The statement metering each policy's budget under the Exact profile, as `issuer` digests it. */
const meteringStatement = (issuer: string, policies = POLICIES) => ({
  claims: ["budget_metering"],
  extensions: {
    budget_metering: {
      unit: { currency: "USD", exponent: 2 },
      enforcement_profile: "exact",
      topology: "local-single-writer",
      reserve_posture: "reserve_then_commit",
      settlement_intake: "pdp-claim-settlement:execution-evidence",
      metered_actions: [{ action: STANDING_PAYMENT_OPERATION, phase: "commit" }],
      budgets: Object.entries(policies).map(([id, held]) => {
        const t = JSON.parse(held.content).standing_payment as ReturnType<typeof terms>;
        return {
          owner: t.budget.owner,
          budget_id: t.budget.id,
          counter_scope: "standing_consent",
          currency: "USD",
          limit: t.budget.limit,
          policies: [{ id, version: held.version, digest: activationPolicyDigest(issuer, held) }],
        };
      }),
    },
  },
});

let as: BuiltAs;
let off: BuiltAs;
let server: Server;
let offServer: Server;
let clientKey: CryptoKey;
let dpopKeys: { privateKey: CryptoKey; publicKey: CryptoKey };
let caiKeys: { privateKey: CryptoKey; publicKey: CryptoKey };
let seq = 0;

beforeAll(async () => {
  caiKeys = await generateKeyPair("ES256", { extractable: true });
  as = await buildAuthorizationServer({
    issuer: ISSUER,
    capabilities: ON,
    approvalSessions: SESSIONS,
    dispatchPolicies: POLICIES,
    enforcementScopeStatement: meteringStatement(ISSUER),
    budgetExposure: new FakeBudgetCounters(),
    // The continuation path: an assertion issuer trusted for this AS's and
    // the RAS's hops, the agent's registration at the RAS, and the
    // resource-to-AS map the switch above drives.
    continuationAssertionIssuers: [
      {
        iss: CAI,
        jwks: {
          keys: [{ ...(await exportJWK(caiKeys.publicKey)), kid: "cai-key", alg: "ES256" }],
        } as never,
        attestsFor: [ISSUER, RAS],
      },
    ],
    crossDomainClients: [{ targetAs: RAS, clientId: "ap-agent", destinationClientId: "ap-agent" }],
    resourceToAs: (resource) => (paymentsAtRas && resource === RESOURCE ? RAS : ISSUER),
  });
  server = as.provider.listen(PORT);
  off = await buildAuthorizationServer({
    issuer: OFF_ISSUER,
    approvalSessions: SESSIONS,
    dispatchPolicies: POLICIES,
  });
  offServer = off.provider.listen(OFF_PORT);
  clientKey = (await importJWK(as.agentClientJwk as never, "ES256")) as CryptoKey;
  dpopKeys = await generateKeyPair("ES256", { extractable: true });
});

afterAll(() => {
  server?.close();
  offServer?.close();
});

const paymentEntry = (
  constraints: Record<string, unknown> = {
    max_amount: { amount: "500.00", currency: "USD" },
    vendors: ["acme"],
  },
) => ({
  type: "mission_resource_access",
  resource: RESOURCE,
  actions: [STANDING_PAYMENT_OPERATION],
  constraints,
});

/** A standing-payment template proposal acting for `subject` through `agent`, dispatched by ap-agent. */
const proposal = (
  over: {
    subject?: string;
    agent?: string;
    policy?: string;
    ceiling?: unknown[];
    issuer?: string;
  } = {},
) => ({
  template_version: `sp-batch-${seq++}`,
  ceiling: over.ceiling ?? [paymentEntry()],
  dispatch_policy: { id: over.policy ?? "sp-batch", version: "1" },
  dispatchers: ["ap-agent"],
  recipients: {
    subjects: [{ iss: over.issuer ?? ISSUER, sub: over.subject ?? "bob" }],
    agents: [over.agent ?? "subagent-invoice-extractor"],
  },
  per_instance_lifetime_s: 900,
  max_active: 5,
  rate_per_min: 30,
  review_cadence_s: 86400,
  expires_at: FAR_FUTURE,
});

async function propose(body: unknown, issuer = ISSUER): Promise<string> {
  const res = await fetch(`${issuer}/templates/proposals`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-service-token": DEV_SERVICE_TOKEN },
    body: JSON.stringify(body),
  });
  const out = (await res.json()) as { proposal_id: string };
  expect(res.status, JSON.stringify(out)).toBe(201);
  return out.proposal_id;
}

const login = (key: string, sub: string) =>
  floorApprovalHeaders(SESSIONS, key, "", { sub, subject: null });
const cookieOf = (headers: Record<string, string>) => ({ cookie: headers.cookie as string });

async function page(path: string, headers: Record<string, string>, issuer = ISSUER) {
  const res = await fetch(`${issuer}${path}`, { headers: cookieOf(headers) });
  return {
    status: res.status,
    html: await res.text(),
    revision: res.headers.get(RENDER_REVISION_HEADER),
  };
}

async function post(path: string, headers: Record<string, string>, body: unknown) {
  const res = await fetch(`${ISSUER}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
  return { status: res.status, body: (await res.json()) as Record<string, unknown> };
}

/** Consent to `body` as `sub` at the approval floor; returns the template id. */
async function consented(body: ReturnType<typeof proposal>, sub = "bob"): Promise<string> {
  const id = await propose(body);
  const headers = login(id, sub);
  const { revision } = await page(`/templates/proposals/${id}`, headers);
  const decided = await post(`/templates/proposals/${id}/decide`, headers, {
    decision: "approve",
    render_revision: revision,
  });
  expect(decided.status, JSON.stringify(decided.body)).toBe(201);
  return decided.body.template_id as string;
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
        client_assertion: await new SignJWT({})
          .setProtectedHeader({ alg: "ES256", kid: "ap-agent-auth" })
          .setIssuer("ap-agent")
          .setSubject("ap-agent")
          .setAudience(ISSUER)
          .setIssuedAt()
          .setExpirationTime("2m")
          .setJti(crypto.randomUUID())
          .sign(clientKey),
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      }).toString(),
    });
  let res = await send();
  const nonce = res.headers.get("dpop-nonce");
  if (res.status === 400 && nonce) res = await send({ nonce });
  return { status: res.status, body: (await res.json()) as Record<string, unknown> };
}

const USD_1000 = { amount: "1000.00", currency: "USD" };

/** A Dispatch at /token of `templateId` with `intent` members beside the goal, resource and expiry. */
const dispatch = (templateId: string, intent: Record<string, unknown> = { max_budget: USD_1000 }) =>
  token({
    grant_type: MISSION_DISPATCH_GRANT_TYPE,
    template_id: templateId,
    mission_intent: JSON.stringify({
      intent: {
        goal: "pay approved Acme invoices",
        target_resources: [RESOURCE],
        expires_at: FAR_FUTURE,
        ...intent,
      },
    }),
    dispatch_event_id: `sp-batch-dsp-${seq++}`,
  });

/** What exists: every Mission the kernel holds, and the template's dispatched instances. */
const created = (templateId?: string) => ({
  missions: as.kernel.allMissions().length,
  instances: templateId ? as.kernel.standingPayments.dispatchedInstances(templateId).length : 0,
});

/** Rewrite a stored template's columns, as a store written at rest would hold them. */
const tamper = (templateId: string, columns: Record<string, string>) => {
  for (const [column, value] of Object.entries(columns)) {
    as.templateStore.db
      .prepare(`UPDATE templates SET ${column} = ? WHERE id = ?`)
      .run(value, templateId);
  }
};

/** The stored consent provenance of a template, with its principal replaced. */
const provenanceOf = (templateId: string, over: Record<string, unknown> = {}) =>
  JSON.stringify({ ...(as.templateStore.get(templateId)?.consent_provenance as object), ...over });

/** The Dispatch is refused with `reason`, at `status`, and nothing was created. */
async function refusedAtToken(
  templateId: string,
  intent: Record<string, unknown> | undefined,
  expected: { status: number; error?: string; reason?: string; description?: string },
) {
  const before = created(templateId);
  const { status, body } = await dispatch(templateId, intent);
  expect(status, JSON.stringify(body)).toBe(expected.status);
  if (expected.error) expect(body.error).toBe(expected.error);
  if (expected.reason) expect(body.mission_denial_reason).toBe(expected.reason);
  if (expected.description) expect(body.error_description).toBe(expected.description);
  expect(body.access_token).toBeUndefined();
  expect(created(templateId)).toEqual(before);
}

const PROHIBITED = { status: 400, error: "invalid_request", reason: "dispatch_prohibited_class" };

describe("standing-payment template defects refused at the token endpoint, creating nothing (@spec template#standing-payment-exception, template#grant-type, #813, D877)", () => {
  it("refuses dispatch_prohibited_class at /token a Dispatch from a stored template whose ceiling lost its per-payment max_amount, creating nothing (#813)", async () => {
    const id = await consented(proposal());
    tamper(id, { ceiling_json: JSON.stringify([paymentEntry({ vendors: ["acme"] })]) });
    await refusedAtToken(id, { max_budget: USD_1000 }, PROHIBITED);
  });

  it("refuses dispatch_prohibited_class at /token a Dispatch from a stored template whose ceiling names a vendor the policy commits no destination for, creating nothing (#813)", async () => {
    const id = await consented(proposal());
    tamper(id, {
      ceiling_json: JSON.stringify([
        paymentEntry({
          max_amount: { amount: "500.00", currency: "USD" },
          vendors: ["acme", "globex"],
        }),
      ]),
    });
    await refusedAtToken(id, { max_budget: USD_1000 }, PROHIBITED);
  });

  it("refuses dispatch_prohibited_class at /token a Dispatch from a stored template whose approver of record is its Dispatcher, creating nothing (#813)", async () => {
    const id = await consented(proposal());
    tamper(id, {
      approver_sub: "ap-agent",
      // The instance acts for its approver of record, so the stored recipients
      // list it too, as such a store would.
      recipients_json: JSON.stringify({
        subjects: [{ iss: ISSUER, sub: "ap-agent" }],
        agents: ["subagent-invoice-extractor"],
      }),
      consent_provenance_json: provenanceOf(id, { principal: { iss: ISSUER, sub: "ap-agent" } }),
    });
    await refusedAtToken(id, { max_budget: USD_1000 }, PROHIBITED);
  });

  it("refuses dispatch_prohibited_class at /token a Dispatch from a stored template whose approver of record is the instance's Agent, creating nothing (#813)", async () => {
    const id = await consented(proposal());
    tamper(id, {
      approver_sub: "subagent-invoice-extractor",
      // The instance acts for its approver of record, so the stored recipients
      // list it too, as such a store would.
      recipients_json: JSON.stringify({
        subjects: [{ iss: ISSUER, sub: "subagent-invoice-extractor" }],
        agents: ["subagent-invoice-extractor"],
      }),
      consent_provenance_json: provenanceOf(id, {
        principal: { iss: ISSUER, sub: "subagent-invoice-extractor" },
      }),
    });
    await refusedAtToken(id, { max_budget: USD_1000 }, PROHIBITED);
  });

  it("refuses dispatch_prohibited_class at /token a Dispatch from a stored template whose consent did not satisfy the approval floor, creating nothing (#813)", async () => {
    const id = await consented(proposal());
    tamper(id, { consent_provenance_json: provenanceOf(id, { floors: [] }) });
    await refusedAtToken(id, { max_budget: USD_1000 }, PROHIBITED);
  });

  it("refuses dispatch_prohibited_class at /token an instance whose max_budget is above the policy's per_instance_max, creating nothing (#813)", async () => {
    const id = await consented(proposal());
    await refusedAtToken(id, { max_budget: { amount: "1000.01", currency: "USD" } }, PROHIBITED);
  });

  it("refuses dispatch_prohibited_class at /token an instance whose Intent carries no max_budget, creating nothing (#813)", async () => {
    const id = await consented(proposal());
    await refusedAtToken(id, {}, PROHIBITED);
  });

  it("refuses dispatch_prohibited_class at /token an instance under a Dispatch Policy that commits no class-named exception for the consumption bound, creating nothing (#813)", async () => {
    const id = await consented(proposal({ policy: "sp-batch-no-cb" }));
    await refusedAtToken(id, { max_budget: USD_1000 }, PROHIBITED);
  });

  it("refuses dispatch_policy_changed at /token once the Dispatch Policy is changed in place under its version, so a raise needs a new version and consent, creating nothing (#813)", async () => {
    const id = await consented(proposal({ policy: "sp-batch-editable" }));
    const held = POLICIES["sp-batch-editable"] as { content: string };
    const original = held.content;
    held.content = JSON.stringify({
      id: "sp-batch-editable",
      derivation_limit_ceiling: 3,
      standing_payment: terms("ap-batch-editable", {
        max_amount: { amount: "900.00", currency: "USD" },
      }),
    });
    try {
      await refusedAtToken(
        id,
        { max_budget: USD_1000 },
        { status: 403, error: "access_denied", reason: "dispatch_policy_changed" },
      );
    } finally {
      held.content = original;
    }
  });

  it("refuses invalid_request at /token a max_budget whose amount is not a decimal string: 100 as a number, 1e3 or empty, creating nothing (@spec metering#bounds, #813)", async () => {
    const id = await consented(proposal());
    for (const amount of [100, "1e3", ""]) {
      await refusedAtToken(
        id,
        { max_budget: { amount, currency: "USD" } },
        {
          status: 400,
          error: "invalid_request",
          description:
            "max_budget must be {amount, currency} with a decimal amount and a currency code",
        },
      );
    }
  });

  it("refuses invalid_request at /token a max_budget currency that is not three upper-case letters: usd or USDX, creating nothing (@spec metering#bounds, #813)", async () => {
    const id = await consented(proposal());
    for (const currency of ["usd", "USDX"]) {
      await refusedAtToken(
        id,
        { max_budget: { amount: "100.00", currency } },
        {
          status: 400,
          error: "invalid_request",
          description:
            "max_budget must be {amount, currency} with a decimal amount and a currency code",
        },
      );
    }
  });

  it("refuses invalid_request at /token a dispatch Intent carrying destinations or budget, which only the approved policy commits, creating nothing (#813)", async () => {
    const id = await consented(proposal());
    for (const member of ["destinations", "budget"]) {
      await refusedAtToken(
        id,
        { max_budget: USD_1000, [member]: { acme: "acct-other" } },
        {
          status: 400,
          error: "invalid_request",
          description: `unknown top-level member: ${member}`,
        },
      );
    }
  });

  it("refuses invalid_request at /token max_budget on the dispatch of an ordinary template, creating nothing (@spec metering#capacity-across-missions, #813)", async () => {
    const seeded = as.templateStore.getByApprovalEvent("tmpl-approval-demo-reconciliation");
    expect(seeded).toBeDefined();
    const before = created();
    const { status, body } = await token({
      grant_type: MISSION_DISPATCH_GRANT_TYPE,
      template_id: seeded?.id as string,
      mission_intent: JSON.stringify({
        intent: {
          goal: "reconcile Acme invoices",
          target_resources: [RESOURCE],
          expires_at: FAR_FUTURE,
          max_budget: USD_1000,
        },
      }),
      dispatch_event_id: `sp-batch-dsp-${seq++}`,
    });
    expect(status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("invalid_request");
    expect(body.error_description).toBe(
      "max_budget is admitted only on the dispatch of a standing-payment template",
    );
    expect(created()).toEqual(before);
  });

  it("commits max_budget in the instance's intent_hash: the dispatched instance's hash recomputes over its Intent, and another max_budget yields another hash (@spec metering#bounds, #813)", async () => {
    const id = await consented(proposal());
    const { status, body } = await dispatch(id);
    expect(status, JSON.stringify(body)).toBe(200);
    const [missionId] = as.kernel.standingPayments.dispatchedInstances(id);
    const instance = as.kernel.get(missionId as string);
    expect(instance?.intent_hash).toBe(intentHash(ISSUER, instance?.intent as never));
    expect(
      intentHash(ISSUER, {
        ...instance?.intent,
        max_budget: { amount: "999.00", currency: "USD" },
      } as never),
    ).not.toBe(instance?.intent_hash);
    expect(
      (decodeJwt(body.access_token as string) as { mission?: { id?: string } }).mission?.id,
    ).toBe(missionId);
  });
});

describe("standing-payment template defects refused at the consent route, creating no template (@spec template#template-consent, #813, D877)", () => {
  it("refuses access_denied a standing-payment consent whose Approver authenticated below the approval floor, creating no template (#813)", async () => {
    const id = await propose(proposal());
    const headers = browserApprovalHeaders(SESSIONS, id, { sub: "bob", acr: "password" }, "");
    const { revision } = await page(`/templates/proposals/${id}`, headers);
    const decided = await post(`/templates/proposals/${id}/decide`, headers, {
      decision: "approve",
      render_revision: revision,
    });
    expect(decided.status).toBe(403);
    expect(decided.body.error).toBe("access_denied");
    expect(as.templateStore.getByApprovalEvent(`apev_${id}`)).toBeUndefined();
  });

  it("refuses invalid_request a standing-payment consent whose ceiling bounds the payment in a currency other than the budget's, creating no template (#813)", async () => {
    const id = await propose(
      proposal({
        ceiling: [
          paymentEntry({ max_amount: { amount: "500.00", currency: "EUR" }, vendors: ["acme"] }),
        ],
      }),
    );
    const headers = login(id, "bob");
    const { revision } = await page(`/templates/proposals/${id}`, headers);
    const decided = await post(`/templates/proposals/${id}/decide`, headers, {
      decision: "approve",
      render_revision: revision,
    });
    expect(decided.status).toBe(400);
    expect(decided.body.error_description).toBe(
      "the Template Ceiling: entry 0 bounds payments:payment.execute in EUR, not USD",
    );
    expect(as.templateStore.getByApprovalEvent(`apev_${id}`)).toBeUndefined();
  });

  it("renders the template-consent minimum on the capability-on standing-payment consent page: the ceiling, the machine-speed and standing-payment statements, the dispatch bounds and the terms (@spec template#template-consent, #813)", async () => {
    const id = await propose(proposal());
    const { html } = await page(`/templates/proposals/${id}`, login(id, "bob"));
    for (const statement of [
      TEMPLATE_CEILING_STATEMENT,
      MACHINE_SPEED_STATEMENT,
      STANDING_PAYMENT_STATEMENT,
    ]) {
      expect(html).toContain(statement.replace(/'/g, "'"));
    }
    expect(html).toContain('<pre class="template-ceiling">');
    expect(html).toContain("At most 5 dispatched instances are active at once.");
    expect(html).toContain("At most 30 dispatches per minute.");
    expect(html).toContain("Each dispatched instance lives at most 900 seconds.");
    expect(html).toContain(`The template expires at ${FAR_FUTURE}.`);
    expect(html).toContain("Dispatchers: ap-agent.");
    expect(html).toContain("Dispatch Policy: sp-batch version 1.");
  });

  it("renders no standing-payment terms or budget lines on the consent page with the capability off, where nothing would meter the budget (@spec metering#consent, #813)", async () => {
    const id = await propose(proposal({ issuer: OFF_ISSUER }), OFF_ISSUER);
    const { status, html } = await page(`/templates/proposals/${id}`, login(id, "bob"), OFF_ISSUER);
    expect(status).toBe(200);
    expect(html).toContain('<pre class="template-ceiling">');
    expect(html).not.toContain("Standing payment");
    expect(html).not.toContain(`Budget ${OWNER}/`);
    expect(html).not.toContain('<ul class="standing-payment">');
  });
});

describe("standing-payment Dispatch Policy defects refused at construction (@spec template#standing-payment-exception, #813, D877)", () => {
  const startup = (id: string, t: unknown) => {
    const issuer = "http://localhost:15010";
    const policies = { [id]: policy(id, t) };
    return buildAuthorizationServer({
      issuer,
      capabilities: ON,
      dispatchPolicies: policies,
      enforcementScopeStatement: meteringStatement(issuer, policies),
      budgetExposure: new FakeBudgetCounters(),
    });
  };

  it("refuses to start with a Dispatch Policy committing a destination with an empty payee account (#813)", async () => {
    const built = startup("sp-bad-payee", terms("ap-bad-payee", { destinations: { acme: "" } }));
    await expect(built).rejects.toBeInstanceOf(StandingPaymentConfigError);
    await expect(built).rejects.toThrow(
      "each destination is a vendor_id naming a non-empty payee_account",
    );
  });

  it("refuses to start with a Dispatch Policy whose budget is in a currency other than USD (#813)", async () => {
    const t = terms("ap-eur");
    const built = startup("sp-eur", { ...t, budget: { ...t.budget, currency: "EUR" } });
    await expect(built).rejects.toBeInstanceOf(StandingPaymentConfigError);
    await expect(built).rejects.toThrow("budget currency is not USD");
  });

  it("refuses to start with a Dispatch Policy whose budget omits its limit (#813)", async () => {
    const t = terms("ap-no-limit");
    const { limit: _limit, ...budget } = t.budget;
    const built = startup("sp-no-limit", { ...t, budget });
    await expect(built).rejects.toBeInstanceOf(StandingPaymentConfigError);
    await expect(built).rejects.toThrow(
      "budget is not {owner, id, currency, limit, per_instance_max}",
    );
  });

  it("classifies the designated payment under the shipped mapping as irreversible and no other prohibited class, and refuses to start where the mapping covers it but not as irreversible (#813)", async () => {
    const entry = {
      type: "mission_resource_access" as const,
      resource: RESOURCE,
      actions: [STANDING_PAYMENT_OPERATION],
    };
    expect(actionClassesAt(APPROVAL_FLOOR, entry, STANDING_PAYMENT_OPERATION)).toEqual([
      "irreversible_action",
    ]);
    const issuer = "http://localhost:15011";
    const policies = { "sp-batch": POLICIES["sp-batch"] as (typeof POLICIES)[string] };
    const approvalFloor = {
      ...APPROVAL_FLOOR,
      classification: APPROVAL_FLOOR.classification.map((c) =>
        c.resource === RESOURCE
          ? {
              ...c,
              actions: {
                ...c.actions,
                [STANDING_PAYMENT_OPERATION]: "consequential_write" as const,
              },
            }
          : c,
      ),
    };
    const built = buildAuthorizationServer({
      issuer,
      capabilities: ON,
      approvalFloor,
      dispatchPolicies: policies,
      enforcementScopeStatement: meteringStatement(issuer, policies),
      budgetExposure: new FakeBudgetCounters(),
    });
    await expect(built).rejects.toBeInstanceOf(StandingPaymentConfigError);
    await expect(built).rejects.toThrow(
      `Dispatch Policy sp-batch names ${STANDING_PAYMENT_OPERATION} at ${RESOURCE}, which the published mapping does not classify as irreversible_action`,
    );
  });
});

describe("max_budget at intakes other than the dispatch (@spec metering#consent, #813)", () => {
  it("refuses at PAR a Mission Intent carrying max_budget as an unknown member, creating no Mission (@spec metering#consent, #813)", async () => {
    const before = created();
    const res = await fetch(`${ISSUER}/request`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: "ap-agent",
        response_type: "code",
        redirect_uri: "http://localhost:9999/cb",
        resource: RESOURCE,
        code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        code_challenge_method: "S256",
        mission_intent: JSON.stringify({
          intent: {
            goal: "pay Acme",
            target_resources: [RESOURCE],
            expires_at: FAR_FUTURE,
            max_budget: USD_1000,
          },
        }),
        client_assertion: await new SignJWT({})
          .setProtectedHeader({ alg: "ES256", kid: "ap-agent-auth" })
          .setIssuer("ap-agent")
          .setSubject("ap-agent")
          .setAudience(ISSUER)
          .setIssuedAt()
          .setExpirationTime("2m")
          .setJti(crypto.randomUUID())
          .sign(clientKey),
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      }).toString(),
    });
    const body = (await res.json()) as {
      error?: string;
      error_description?: string;
      request_uri?: string;
    };
    expect(res.status, JSON.stringify(body)).toBe(400);
    expect(body.error_description).toBe("unknown top-level member: max_budget");
    expect(body.request_uri).toBeUndefined();
    expect(created()).toEqual(before);
  });
});

/** A standing-payment instance acting for Alice through ap-agent, its Dispatcher and Agent; its access token and id. */
async function aliceInstance(): Promise<{
  templateId: string;
  accessToken: string;
  missionId: string;
}> {
  const templateId = await consented(proposal({ subject: "alice", agent: "ap-agent" }), "alice");
  const { status, body } = await dispatch(templateId);
  expect(status, JSON.stringify(body)).toBe(200);
  const [missionId] = as.kernel.standingPayments.dispatchedInstances(templateId);
  return { templateId, accessToken: body.access_token as string, missionId: missionId as string };
}

/** A child-creation exchange at /token from the Mission `accessToken` is for. */
const childOf = (accessToken: string) =>
  token({
    grant_type: TOKEN_EXCHANGE,
    subject_token: accessToken,
    subject_token_type: ACCESS_TOKEN,
    requested_token_type: JWT_TOKEN,
    creation_request_id: crypto.randomUUID(),
    mission_intent: JSON.stringify({
      intent: { goal: "read Acme invoices", target_resources: [RESOURCE], expires_at: FAR_FUTURE },
    }),
    authorization_details: JSON.stringify([
      {
        type: "mission_resource_access",
        resource: RESOURCE,
        actions: ["payments:invoice.read"],
        constraints: { vendors: ["acme"] },
      },
    ]),
    child_actor: JSON.stringify({ sub: "subagent-extractor", sub_profile: "ai_agent" }),
  });

/** A deferred expansion exchange for the Mission `accessToken` is for, with `maxBudget` (null: none) in the widened Intent. */
const openExpansion = (accessToken: string, maxBudget: unknown) =>
  token({
    grant_type: TOKEN_EXCHANGE,
    subject_token: accessToken,
    subject_token_type: ACCESS_TOKEN,
    requested_token_type: ACCESS_TOKEN,
    mission_intent: JSON.stringify({
      intent: {
        goal: "pay and read Acme invoices",
        target_resources: [RESOURCE],
        expires_at: FAR_FUTURE,
        ...(maxBudget !== null ? { max_budget: maxBudget } : {}),
      },
    }),
    authorization_details: JSON.stringify([
      {
        type: "mission_resource_access",
        resource: RESOURCE,
        actions: [STANDING_PAYMENT_OPERATION, "payments:invoice.read"],
        constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
        delegation: { max_depth: 1, children: { max_children: 2, max_child_depth: 1 } },
      },
    ]),
    creation_request_id: crypto.randomUUID(),
    completion_mode: "deferred",
  });

/** Open a deferred expansion that keeps the instance's max_budget; returns its deferral code. */
async function expansion(accessToken: string): Promise<string> {
  const { status, body } = await openExpansion(accessToken, USD_1000);
  expect(typeof body.deferral_code, `${status} ${JSON.stringify(body)}`).toBe("string");
  return body.deferral_code as string;
}

/** Bob, who approves for Alice, decides the deferral on its rendered page. */
async function approveDeferral(code: string) {
  const headers = login(code, "bob");
  const { revision } = await page(`/expansions/deferrals/${code}`, headers);
  return post(`/expansions/deferrals/${code}/decide`, headers, {
    decision: "approve",
    render_revision: revision,
  });
}

describe("standing-payment lineage at the token endpoint (@spec template#instance-composition, metering#capacity-across-missions, #813, D830 ruling 3, D877)", () => {
  it("refuses delegation_not_permitted at /token a Child Mission of a standing-payment instance, creating nothing (#813)", async () => {
    const { accessToken } = await aliceInstance();
    const before = created();
    const { status, body } = await childOf(accessToken);
    expect(status, JSON.stringify(body)).toBe(400);
    expect(body.mission_denial_reason).toBe("delegation_not_permitted");
    expect(created()).toEqual(before);
  });

  it("admits at /token an expansion successor of a standing-payment instance, approved on its page, that carries the instance's budget binding (#813)", async () => {
    const { accessToken, missionId } = await aliceInstance();
    const code = await expansion(accessToken);
    const approved = await approveDeferral(code);
    expect(approved.status, JSON.stringify(approved.body)).toBe(200);
    const polled = await token({ grant_type: DEFERRED_GRANT, deferral_code: code });
    expect(polled.status, JSON.stringify(polled.body)).toBe(200);
    const successorId = (
      decodeJwt(polled.body.access_token as string) as { mission: { id: string } }
    ).mission.id;
    const successor = as.kernel.get(successorId);
    expect(successor?.predecessor).toBe(missionId);
    const instance = as.kernel.get(missionId);
    const bound = standingPaymentBudgetBindingOf(as.kernel, successor as never);
    const instanceBound = standingPaymentBudgetBindingOf(as.kernel, instance as never);
    expect(bound.kind).toBe("bound");
    expect(bound).toEqual(instanceBound);
    expect(bound.kind === "bound" && bound.binding.instance.root_mission_id).toBe(missionId);
  });

  it("refuses delegation_not_permitted at /token a Child Mission of a standing-payment instance's expansion successor that holds a children grant, creating nothing (#813)", async () => {
    const { accessToken } = await aliceInstance();
    const code = await expansion(accessToken);
    expect((await approveDeferral(code)).status).toBe(200);
    const polled = await token({ grant_type: DEFERRED_GRANT, deferral_code: code });
    expect(polled.status, JSON.stringify(polled.body)).toBe(200);
    const successorId = (
      decodeJwt(polled.body.access_token as string) as { mission: { id: string } }
    ).mission.id;
    expect(
      as.kernel.get(successorId)?.authority_set.some((e) => e.delegation?.children !== undefined),
    ).toBe(true);
    const before = created();
    const { status, body } = await childOf(polled.body.access_token as string);
    expect(status, JSON.stringify(body)).toBe(400);
    expect(body.mission_denial_reason).toBe("delegation_not_permitted");
    expect(created()).toEqual(before);
  });

  it("refuses invalid_request at /token an expansion of a standing-payment instance whose max_budget is raised, in another currency or absent, opening no deferral and creating nothing (@spec metering#capacity-across-missions, #813)", async () => {
    const { accessToken, missionId } = await aliceInstance();
    for (const cap of [
      { amount: "1000.01", currency: "USD" },
      { amount: "1000.00", currency: "EUR" },
      null,
    ]) {
      const before = created();
      const { status, body } = await openExpansion(accessToken, cap);
      expect(status, JSON.stringify(body)).toBe(400);
      expect(body.error).toBe("invalid_request");
      expect(body.error_description).toBe(
        `a successor of standing-payment instance ${missionId} keeps its max_budget of 1000.00 USD`,
      );
      expect(body.deferral_code).toBeUndefined();
      expect(created()).toEqual(before);
    }
  });

  it("refuses invalid_grant at /token a cross-domain continuation of a standing-payment instance, recording no hop and counting no derivation (#813)", async () => {
    const { missionId } = await aliceInstance();
    const handles = as.continuationStore.handlesForMission(missionId);
    const derivations = as.kernel.get(missionId)?.derivation_count;
    const now = Math.floor(Date.now() / 1000);
    const ica = await new SignJWT({
      identity_continuation_handle: handles[0],
      cnf: { jkt: await calculateJwkThumbprint(await exportJWK(dpopKeys.publicKey)) },
      act: { iss: ISSUER, sub: "ap-agent" },
    })
      .setProtectedHeader({ alg: "ES256", kid: "cai-key", typ: "oauth-identity-continuation+jwt" })
      .setIssuer(CAI)
      .setAudience(ISSUER)
      .setIssuedAt(now)
      .setExpirationTime(now + 120)
      .setJti(crypto.randomUUID())
      .sign(caiKeys.privateKey);
    paymentsAtRas = true;
    let result: { status: number; body: Record<string, unknown> };
    try {
      result = await token({
        grant_type: TOKEN_EXCHANGE,
        requested_token_type: ID_JAG,
        subject_token: ica,
        subject_token_type: ICA_TOKEN,
        audience: RAS,
        resource: RESOURCE,
      });
    } finally {
      paymentsAtRas = false;
    }
    expect(result.status, JSON.stringify(result.body)).toBe(400);
    expect(result.body.error).toBe("invalid_grant");
    expect(result.body.error_description).toBe(
      `mission ${missionId} descends from standing-payment instance ${missionId}; a cross-domain grant would not share its budget accounting, so it is refused (#813)`,
    );
    expect(as.continuationStore.handlesForMission(missionId)).toEqual(handles);
    expect(as.kernel.get(missionId)?.derivation_count).toBe(derivations);
  });
});
