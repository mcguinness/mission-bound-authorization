/**
 * @spec runtime#input-resource-policy, authzen#runtime-denial-classification
 * `resource_policy` (#828): the independently administered Resource policy
 * as the third bound, without a live OpenFGA. The policy outcome is
 * controlled separately from the Mission-authority outcome, so each bound's
 * denial is attributable to it. A fake OpenFGA HTTP endpoint stands in where
 * the real SDK client's behavior on the wire is the point (attach
 * verification, no contextual tuples, backend failure). The stored-
 * entitlement behavior against a real OpenFGA is
 * `resource-policy-fga.test.ts`.
 */

import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { afterEach, describe, expect, it } from "vitest";
import { evaluateRemote, isDecisionChannelRefusal } from "../src/client.js";
import { createDecisionPoint, createEphemeralDecisionPoint } from "../src/decision-point.js";
import type { DecisionEvidenceObject } from "../src/decision-evidence.js";
import { evaluate, type EvaluateOptions, type EvaluationRequest } from "../src/evaluate.js";
import { assertDomainTuple, DomainTupleError, DOMAIN_MODEL, Fga, FgaAttachError, FgaDomainAdmin } from "../src/fga.js";
import type { MissionView } from "../src/policy-view.js";
import { relationForAction, stalenessBound } from "../src/policy.js";
import {
  fgaResourcePolicy,
  issuerLocalPrincipals,
  principalObject,
  ResourcePolicyConfigError,
  ResourcePolicyUnavailableError,
} from "../src/resource-policy.js";
import { createPdpHttpServer, type PdpHttpServerHandle } from "../src/server.js";
import {
  RESOURCE_POLICY_PERMITS_ALL_FIXTURE,
  RESOURCE_POLICY_REFUSES_ALL_FIXTURE,
  RESOURCE_POLICY_UNAVAILABLE_FIXTURE,
  resourcePolicyFixture,
} from "../src/test-support.js";
import { freshKey, openTestClaims } from "./claim-fixture.js";

const RESOURCE = "http://localhost:4403/mcp";
const ISSUER = "https://as.test";
const NOW = new Date("2026-07-22T12:00:00Z");

const view = (over: Partial<MissionView> = {}): MissionView => ({
  id: "msn_rp_1",
  issuer: ISSUER,
  state: "active",
  version: 1,
  authority_hash: "sha-256:rphash",
  authority_set: [
    { type: "mission_resource_access", resource: RESOURCE, actions: ["payments:invoice.read", "payments:invoice.list"], constraints: { vendors: ["acme", "globex"] } },
    { type: "mission_resource_access", resource: RESOURCE, actions: ["payments:payment.execute", "payments:remittance.send"] },
  ],
  subject: { iss: ISSUER, sub: "alice" },
  client_id: "ap-agent",
  ...over,
});

const req = (over: Partial<EvaluationRequest> = {}): EvaluationRequest => ({
  subject: { id: "alice", properties: { iss: ISSUER } },
  resource: { type: "invoice", id: "inv-1", properties: { audience: RESOURCE, vendor_id: "acme" } },
  action: { name: "payments:invoice.read" },
  context: {
    mission: { id: "msn_rp_1", issuer: ISSUER },
    actor: { client_id: "ap-agent" },
    mission_state_observation: { state: "active", mode: "fresh", freshness_at: NOW.toISOString() },
  },
  ...over,
});

/** A Mission-authority checker whose answer the test controls, recording what it was asked. */
function missionFga(allowed: boolean) {
  const calls: Array<{ check: { user: string; relation: string; object: string }; contextual: unknown[] }> = [];
  return {
    calls,
    fga: {
      checkWithContext: async (check: { user: string; relation: string; object: string }, contextual: unknown[]) => {
        calls.push({ check, contextual });
        return allowed;
      },
    } as unknown as Fga,
  };
}

const opts = (over: Partial<EvaluateOptions> & Pick<EvaluateOptions, "resourcePolicy" | "fga">): EvaluateOptions => ({
  view: view(),
  modelId: "unit-test-model",
  now: () => NOW,
  stalenessBound,
  relationForAction,
  stateSourcePlacement: "pep",
  ...over,
});

describe("independent Resource policy in the decision (@spec runtime#input-resource-policy, #828)", () => {
  it("truth table: permits only when both Mission authority and Resource policy permit; either refusing denies", async () => {
    const cases = [
      { mission: true, policy: true, decision: true, reason: undefined },
      { mission: true, policy: false, decision: false, reason: "resource_policy" },
      { mission: false, policy: true, decision: false, reason: "out_of_authority" },
      { mission: false, policy: false, decision: false, reason: "out_of_authority" },
    ];
    for (const c of cases) {
      const policy = resourcePolicyFixture(() => !c.policy);
      const dec = await evaluate(req(), opts({ fga: missionFga(c.mission).fga, resourcePolicy: policy }));
      const label = `mission ${c.mission} policy ${c.policy}`;
      expect(dec.decision, label).toBe(c.decision);
      expect(dec.context.denial_reason, label).toBe(c.reason);
      // A Mission refusal comes first: the policy is never asked about an
      // action the Mission does not authorize.
      expect(policy.queries.length, label).toBe(c.mission ? 1 : 0);
    }
  });

  it("a policy refusal denies resource_policy with next_action none, whatever the Mission allows", async () => {
    const dec = await evaluate(req(), opts({ fga: missionFga(true).fga, resourcePolicy: RESOURCE_POLICY_REFUSES_ALL_FIXTURE }));
    expect(dec.decision).toBe(false);
    expect(dec.context).toMatchObject({ denial_reason: "resource_policy", reason: "resource_policy", next_action: "none" });
    expect(dec.context).not.toHaveProperty("conditions");
  });

  it("the policy receives the authenticated subject and issuer, the authenticated client, the action and every collection target, and nothing from the Mission", async () => {
    const policy = resourcePolicyFixture();
    const mission = missionFga(true);
    const dec = await evaluate(
      req({
        action: { name: "payments:invoice.list" },
        resource: { type: "vendor", id: "acme", properties: { audience: RESOURCE, vendor_id: "acme", vendor_ids: ["acme", "globex"] } },
      }),
      opts({ fga: mission.fga, resourcePolicy: policy }),
    );
    expect(dec.decision, JSON.stringify(dec.context)).toBe(true);
    expect(policy.queries).toEqual([
      {
        subject: { sub: "alice", iss: ISSUER },
        client: "ap-agent",
        action: "payments:invoice.list",
        targets: [
          { type: "vendor", id: "acme" },
          { type: "vendor", id: "globex" },
        ],
      },
    ]);
    // The Mission check is the one carrying contextual tuples.
    expect(mission.calls.every((c) => c.contextual.length > 0)).toBe(true);
  });

  it("a collection with one member the policy refuses denies the whole action", async () => {
    const policy = resourcePolicyFixture((q) => q.targets.some((t) => t.id === "globex"));
    const dec = await evaluate(
      req({
        action: { name: "payments:invoice.list" },
        resource: { type: "vendor", id: "acme", properties: { audience: RESOURCE, vendor_id: "acme", vendor_ids: ["acme", "globex"] } },
      }),
      opts({ fga: missionFga(true).fga, resourcePolicy: policy }),
    );
    expect(dec.context.denial_reason).toBe("resource_policy");
  });

  it("a policy refusal is recorded in the decision point's signed Decision Evidence as resource_policy", async () => {
    const point = createEphemeralDecisionPoint({ emitterId: RESOURCE, audience: RESOURCE, resourcePolicy: RESOURCE_POLICY_REFUSES_ALL_FIXTURE });
    const { resourcePolicy: _bound, ...decisionOptions } = opts({ fga: missionFga(true).fga, resourcePolicy: RESOURCE_POLICY_REFUSES_ALL_FIXTURE });
    const dec = await point.decide(req(), decisionOptions);
    const record = dec.context.decision_evidence as DecisionEvidenceObject;
    expect(record.decision).toBe("deny");
    expect(record.denial_reason).toBe("resource_policy");
  });

  it("a policy refusal is never requestable: no access request is offered for an approval-gated action", async () => {
    const dec = await evaluate(
      req({
        action: { name: "payments:remittance.send" },
        context: { ...req().context, action_class: "consequential_write", parameter_digest: "sha-256:pd-rp" },
      }),
      opts({
        fga: missionFga(true).fga,
        resourcePolicy: RESOURCE_POLICY_REFUSES_ALL_FIXTURE,
        requiresActionApproval: () => true,
      }),
    );
    expect(dec.context.denial_reason).toBe("resource_policy");
    expect(dec.context).not.toHaveProperty("access_request");
  });

  it("a policy refusal claims no idempotency key: the same key permits once the policy allows", async () => {
    const claims = openTestClaims({ now: () => NOW });
    const key = freshKey();
    const keyed = req({
      action: { name: "payments:payment.execute", properties: { idempotency_key: key } },
      context: { ...req().context, action_class: "irreversible_action", parameter_digest: "sha-256:pd-claim" },
    });
    const refused = await evaluate(keyed, opts({ fga: missionFga(true).fga, resourcePolicy: RESOURCE_POLICY_REFUSES_ALL_FIXTURE, claims }));
    expect(refused.context.denial_reason).toBe("resource_policy");
    const permitted = await evaluate(keyed, opts({ fga: missionFga(true).fga, resourcePolicy: RESOURCE_POLICY_PERMITS_ALL_FIXTURE, claims }));
    expect(permitted.decision, JSON.stringify(permitted.context)).toBe(true);
  });

  it("a policy that cannot answer yields no decision: an unavailable backend, a thrown error and a malformed result each throw ResourcePolicyUnavailableError", async () => {
    const thrown = { check: async () => { throw new Error("connection reset"); } };
    const malformed = { check: async () => ({ allowed: "yes" }) as never };
    for (const policy of [RESOURCE_POLICY_UNAVAILABLE_FIXTURE, thrown, malformed]) {
      await expect(evaluate(req(), opts({ fga: missionFga(true).fga, resourcePolicy: policy }))).rejects.toBeInstanceOf(ResourcePolicyUnavailableError);
    }
  });

  it("no Resource policy bound: evaluate refuses to decide, an ephemeral decision point throws at each decision, and createDecisionPoint refuses construction", async () => {
    const { resourcePolicy: _none, ...unbound } = opts({ fga: missionFga(true).fga, resourcePolicy: RESOURCE_POLICY_PERMITS_ALL_FIXTURE });
    await expect(evaluate(req(), unbound as EvaluateOptions)).rejects.toBeInstanceOf(ResourcePolicyConfigError);
    const point = createEphemeralDecisionPoint({ emitterId: RESOURCE, audience: RESOURCE });
    await expect(point.decide(req(), unbound)).rejects.toBeInstanceOf(ResourcePolicyConfigError);
    expect(() => createDecisionPoint({} as never)).toThrow(ResourcePolicyConfigError);
  });

  it("an enforcement component cannot replace the decision point's policy: a caller-supplied one is stripped", async () => {
    const point = createEphemeralDecisionPoint({ emitterId: RESOURCE, audience: RESOURCE, resourcePolicy: RESOURCE_POLICY_REFUSES_ALL_FIXTURE });
    const widened = opts({ fga: missionFga(true).fga, resourcePolicy: RESOURCE_POLICY_PERMITS_ALL_FIXTURE });
    const dec = await point.decide(req(), widened);
    expect(dec.context.denial_reason).toBe("resource_policy");
    // A decision point bound to none does not adopt the caller's: it refuses to decide.
    const unbound = createEphemeralDecisionPoint({ emitterId: RESOURCE, audience: RESOURCE });
    await expect(unbound.decide(req(), widened)).rejects.toBeInstanceOf(ResourcePolicyConfigError);
  });
});

describe("the remote PDP binds its own Resource policy (@spec runtime#input-resource-policy, runtime#decision-channel, #828)", () => {
  const PEP_ID = "payments-pep";
  const SECRET = "resource-policy-remote-secret";
  let handle: PdpHttpServerHandle | undefined;
  afterEach(async () => {
    await handle?.close();
    handle = undefined;
  });

  async function start(serverPolicy: EvaluateOptions["resourcePolicy"] | undefined) {
    handle = await createPdpHttpServer({
      peps: new Map([[PEP_ID, { secret: SECRET, scopes: [RESOURCE] }]]),
      // The request-side options name a permit-all policy; the server strips it.
      getOptions: () => opts({ fga: missionFga(true).fga, resourcePolicy: RESOURCE_POLICY_PERMITS_ALL_FIXTURE }),
      ...(serverPolicy ? { resourcePolicy: serverPolicy } : {}),
    });
    return handle;
  }

  it("a server bound to no policy never adopts the one the options resolver names: no decision", async () => {
    const server = await start(undefined);
    const dec = await evaluateRemote(req(), { url: server.url, pepId: PEP_ID, secret: SECRET });
    expect(dec.decision).toBe(false);
    expect(isDecisionChannelRefusal(dec)).toBe(true);
  });

  it("a refusing server policy denies resource_policy even though the options resolver names a permit-all one", async () => {
    const server = await start(RESOURCE_POLICY_REFUSES_ALL_FIXTURE);
    const dec = await evaluateRemote(req(), { url: server.url, pepId: PEP_ID, secret: SECRET });
    expect(dec.decision).toBe(false);
    expect(dec.context.denial_reason).toBe("resource_policy");
  });

  it("an unavailable server policy answers 503: the PEP obtains no decision, never a refusal", async () => {
    const server = await start(RESOURCE_POLICY_UNAVAILABLE_FIXTURE);
    const dec = await evaluateRemote(req(), { url: server.url, pepId: PEP_ID, secret: SECRET });
    expect(isDecisionChannelRefusal(dec)).toBe(true);
    expect(dec.context).toMatchObject({ channel_status: 503 });
    expect(dec.context.denial_reason).not.toBe("resource_policy");
  });
});

describe("issuer-local principal mapping (@spec runtime#input-resource-policy, #828)", () => {
  const principals = issuerLocalPrincipals(ISSUER);

  it("maps a subject authenticated under the configured issuer, and no other", () => {
    expect(principals({ sub: "alice", iss: ISSUER })).toBe(principalObject({ iss: ISSUER, sub: "alice" }));
    expect(principals({ sub: "alice", iss: "https://other.test" })).toBeUndefined();
    expect(principals({ sub: "alice" })).toBeUndefined();
    expect(principals({ sub: "", iss: ISSUER })).toBeUndefined();
  });

  it("encodes the issuer-qualified pair collision-free, with no separator or whitespace reaching the tuple", () => {
    expect(principalObject({ iss: "a|b", sub: "c" })).not.toBe(principalObject({ iss: "a", sub: "b|c" }));
    expect(principalObject({ iss: "https://as.test", sub: "x#y z:w" })).toMatch(/^user:[^\s#:]+$/);
  });
});

describe("fgaResourcePolicy checks stored entitlements only (@spec runtime#input-resource-policy, #828)", () => {
  function recordingChecker(entitled: (object: string) => boolean) {
    const calls: Array<{ check: { user: string; relation: string; object: string }; opts: unknown; extra: number }> = [];
    return {
      calls,
      checkStored: async (check: { user: string; relation: string; object: string }, opts: unknown, ...extra: unknown[]) => {
        calls.push({ check, opts, extra: extra.length });
        return entitled(check.object);
      },
    };
  }
  const principal = principalObject({ iss: ISSUER, sub: "alice" });
  const query = (over: Record<string, unknown> = {}) => ({
    subject: { sub: "alice", iss: ISSUER },
    action: "payments:payment.execute",
    targets: [{ type: "invoice", id: "inv-1" }],
    ...over,
  });

  it("checks every target's mapped stored relation with an authoritative read and nothing else", async () => {
    const checker = recordingChecker(() => true);
    const policy = fgaResourcePolicy(checker, { principals: issuerLocalPrincipals(ISSUER) });
    const result = await policy.check(query({ targets: [{ type: "invoice", id: "inv-1" }, { type: "vendor", id: "acme" }] }));
    expect(result).toEqual({ allowed: true });
    expect(checker.calls).toEqual([
      { check: { user: principal, relation: "authorized_payer", object: "invoice:inv-1" }, opts: { higherConsistency: true }, extra: 0 },
      { check: { user: principal, relation: "authorized_payer", object: "vendor:acme" }, opts: { higherConsistency: true }, extra: 0 },
    ]);
  });

  it("refuses at the first unentitled target, an unmapped subject, an unmapped action and an unadministered target type", async () => {
    const checker = recordingChecker((object) => object !== "vendor:globex");
    const policy = fgaResourcePolicy(checker, { principals: issuerLocalPrincipals(ISSUER) });
    expect(await policy.check(query({ targets: [{ type: "vendor", id: "acme" }, { type: "vendor", id: "globex" }, { type: "vendor", id: "initech" }] })))
      .toEqual({ allowed: false, target: { type: "vendor", id: "globex" } });
    expect(checker.calls.map((c) => c.check.object)).toEqual(["vendor:acme", "vendor:globex"]);
    checker.calls.length = 0;
    expect((await policy.check(query({ subject: { sub: "alice", iss: "https://other.test" } }))).allowed).toBe(false);
    expect((await policy.check(query({ action: "payments:unknown" }))).allowed).toBe(false);
    expect((await policy.check(query({ targets: [{ type: "server", id: RESOURCE }] }))).allowed).toBe(false);
    expect((await policy.check(query({ targets: [] }))).allowed).toBe(false);
    expect(checker.calls).toEqual([]);
  });

  it("a failed read throws ResourcePolicyUnavailableError, never a refusal", async () => {
    const policy = fgaResourcePolicy({ checkStored: async () => { throw new Error("ECONNREFUSED"); } }, { principals: issuerLocalPrincipals(ISSUER) });
    await expect(policy.check(query())).rejects.toBeInstanceOf(ResourcePolicyUnavailableError);
  });
});

/**
 * A minimal OpenFGA HTTP endpoint: serves one stored model and answers
 * checks as the test directs, recording every request it receives.
 */
const STORE_ID = "01J8Z5Q4Y7C3V2N6M9K0P1R2S3";
const MODEL_ID = "01J8Z5Q4Y7C3V2N6M9K0P1R2S4";

interface FakeFga {
  url: string;
  requests: Array<{ method: string; path: string; body: Record<string, unknown> | undefined }>;
  close: () => Promise<void>;
}

async function fakeOpenFga(options: {
  model?: unknown;
  check?: (body: Record<string, unknown>) => { status: number; body?: unknown } | "hang";
}): Promise<FakeFga> {
  const requests: FakeFga["requests"] = [];
  const server: Server = createServer((req: IncomingMessage, res: ServerResponse) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      const raw = Buffer.concat(chunks).toString("utf8");
      const body = raw ? (JSON.parse(raw) as Record<string, unknown>) : undefined;
      const path = req.url ?? "";
      requests.push({ method: req.method ?? "", path, body });
      const send = (status: number, payload: unknown) => {
        res.writeHead(status, { "content-type": "application/json" });
        res.end(JSON.stringify(payload));
      };
      if (req.method === "GET" && path === `/stores/${STORE_ID}/authorization-models/${MODEL_ID}` && options.model) {
        send(200, { authorization_model: { id: MODEL_ID, ...(options.model as object) } });
      } else if (req.method === "POST" && path === `/stores/${STORE_ID}/check` && options.check) {
        const answer = options.check(body ?? {});
        if (answer === "hang") return;
        send(answer.status, answer.body ?? {});
      } else {
        send(404, { code: "not_found", message: "not found" });
      }
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  const addr = server.address();
  const port = typeof addr === "object" && addr ? addr.port : 0;
  return {
    url: `http://127.0.0.1:${port}`,
    requests,
    close: async () => {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}

describe("Fga.attach verifies the configured model and never creates a store (@spec runtime#input-resource-policy, #828)", () => {
  let fake: FakeFga | undefined;
  afterEach(async () => {
    await fake?.close();
    fake = undefined;
  });
  const attach = (url: string, requestTimeoutMs?: number) =>
    Fga.attach({ apiUrl: url, presharedKey: "k", storeId: STORE_ID, authorizationModelId: MODEL_ID, ...(requestTimeoutMs ? { requestTimeoutMs } : {}) });

  it("attaches to the configured store and model by reading the model back, with no store or model write", async () => {
    fake = await fakeOpenFga({ model: DOMAIN_MODEL });
    const fga = await attach(fake.url);
    expect(fga.storeId).toBe(STORE_ID);
    expect(fga.modelId).toBe(MODEL_ID);
    expect(fake.requests.map((r) => `${r.method} ${r.path}`)).toEqual([`GET /stores/${STORE_ID}/authorization-models/${MODEL_ID}`]);
  });

  it("refuses a model that is not the domain model, a missing model, and an unreachable backend", async () => {
    const widened = structuredClone(DOMAIN_MODEL) as unknown as { type_definitions: Array<{ type: string; metadata?: { relations: Record<string, { directly_related_user_types: Array<{ type: string }> }> } }> };
    const invoice = widened.type_definitions.find((t) => t.type === "invoice");
    invoice?.metadata?.relations.authorized_payer?.directly_related_user_types.push({ type: "mission" });
    fake = await fakeOpenFga({ model: widened });
    await expect(attach(fake.url)).rejects.toBeInstanceOf(FgaAttachError);
    await fake.close();
    fake = await fakeOpenFga({});
    await expect(attach(fake.url)).rejects.toBeInstanceOf(FgaAttachError);
    const deadUrl = fake.url;
    await fake.close();
    fake = undefined;
    await expect(attach(deadUrl)).rejects.toBeInstanceOf(FgaAttachError);
  });

  it("sends the stored entitlement check with no contextual tuples, pinned to the attached model at higher consistency", async () => {
    fake = await fakeOpenFga({ model: DOMAIN_MODEL, check: () => ({ status: 200, body: { allowed: true } }) });
    const policy = fgaResourcePolicy(await attach(fake.url), { principals: issuerLocalPrincipals(ISSUER) });
    expect(await policy.check({ subject: { sub: "alice", iss: ISSUER }, action: "payments:invoice.read", targets: [{ type: "invoice", id: "inv-1" }] })).toEqual({ allowed: true });
    const check = fake.requests.find((r) => r.path.endsWith("/check"));
    expect(check?.body).toMatchObject({
      tuple_key: { user: principalObject({ iss: ISSUER, sub: "alice" }), relation: "authorized_reader", object: "invoice:inv-1" },
      authorization_model_id: MODEL_ID,
      consistency: "HIGHER_CONSISTENCY",
    });
    // The SDK always sends the member; it carries no tuple.
    expect(check?.body?.contextual_tuples ?? { tuple_keys: [] }).toEqual({ tuple_keys: [] });
  });

  it("a failing or silent backend makes the decision throw: no permit and no resource_policy refusal", async () => {
    for (const answer of [() => ({ status: 500, body: { code: "internal_error" } }), () => "hang" as const]) {
      fake = await fakeOpenFga({ model: DOMAIN_MODEL, check: answer });
      const policy = fgaResourcePolicy(await attach(fake.url, 200), { principals: issuerLocalPrincipals(ISSUER) });
      await expect(evaluate(req(), opts({ fga: missionFga(true).fga, resourcePolicy: policy }))).rejects.toBeInstanceOf(ResourcePolicyUnavailableError);
      await fake.close();
      fake = undefined;
    }
  }, 30_000);
});

describe("FgaDomainAdmin writes durable domain tuples only (@spec runtime#input-resource-policy, #828)", () => {
  function recordingAdmin() {
    const writes: unknown[] = [];
    const admin = new FgaDomainAdmin({ client: { write: async (body: unknown) => { writes.push(body); return {}; } } as never, modelId: MODEL_ID });
    return { admin, writes };
  }
  const principal = principalObject({ iss: ISSUER, sub: "alice" });

  it("refuses a Mission subject, a Mission-context relation, a wrong user type and a wrong object type, writing nothing", async () => {
    const { admin, writes } = recordingAdmin();
    const refused = [
      { user: "mission:msn_rp_1", relation: "authorized_payer", object: "vendor:acme" },
      { user: principal, relation: "payer", object: "invoice:inv-1" },
      { user: principal, relation: "vendor", object: "invoice:inv-1" },
      { user: principal, relation: "authorized_reader", object: "mission:msn_rp_1" },
      { user: "client:ap-agent", relation: "authorized_reader", object: "vendor:acme" },
    ];
    for (const tuple of refused) {
      expect(() => assertDomainTuple(tuple), JSON.stringify(tuple)).toThrow(DomainTupleError);
      await expect(admin.grant([{ user: principal, relation: "authorized_reader", object: "vendor:acme" }, tuple])).rejects.toBeInstanceOf(DomainTupleError);
      await expect(admin.revoke([tuple])).rejects.toBeInstanceOf(DomainTupleError);
    }
    expect(writes).toEqual([]);
  });

  it("grants, revokes and moves an invoice in single writes pinned to the model, batching past 100 tuples", async () => {
    const { admin, writes } = recordingAdmin();
    await admin.grant([{ user: principal, relation: "authorized_payer", object: "vendor:acme" }]);
    await admin.revoke([{ user: principal, relation: "authorized_payer", object: "vendor:acme" }]);
    await admin.moveInvoice("inv-1", "acme", "globex");
    expect(writes).toEqual([
      { writes: [{ user: principal, relation: "authorized_payer", object: "vendor:acme" }] },
      { deletes: [{ user: principal, relation: "authorized_payer", object: "vendor:acme" }] },
      {
        writes: [{ user: "vendor:globex", relation: "vendor", object: "invoice:inv-1" }],
        deletes: [{ user: "vendor:acme", relation: "vendor", object: "invoice:inv-1" }],
      },
    ]);
    writes.length = 0;
    await admin.grant(Array.from({ length: 150 }, (_, i) => ({ user: "vendor:acme", relation: "vendor", object: `invoice:bulk-${i}` })));
    expect(writes.map((w) => (w as { writes: unknown[] }).writes.length)).toEqual([100, 50]);
  });
});
