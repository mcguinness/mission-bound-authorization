/**
 * @spec authzen#pdp-request, resource-access#resource-matching (#1276, D447,
 * D457): the PDP matches the credential's and the Mission's
 * `mission_resource_access` entries against the operation target the
 * authenticated PEP established (`resource.properties.operation_target`),
 * with the Resource Access matcher. `audience` stays the token-validation
 * and decision-channel scope input, `resource.type`/`id` stay Resource-policy
 * object identity, and none of the three stands in for another.
 *
 * The FGA layer is a stub that always permits, so only evaluate()'s own
 * steps and the decision channel decide, and this file never skips.
 */

import { afterEach, describe, expect, it } from "vitest";
import { evaluateRemote } from "../src/client.js";
import { evaluate as evaluateRequest, type EvaluateOptions, type EvaluationRequest } from "../src/evaluate.js";
import type { Fga } from "../src/fga.js";
import { MISSION_RESOURCE_ACCESS_TYPE, type MissionView } from "../src/policy-view.js";
import { relationForAction, stalenessBound } from "../src/policy.js";
import { authorizationBinding, decisionCacheKey, operationIdentity } from "../src/projections.js";
import { createPdpHttpServer, type PdpHttpServerHandle } from "../src/server.js";
import { RESOURCE_POLICY_PERMITS_ALL_FIXTURE, resourcePolicyFixture } from "../src/test-support.js";
import { withCredential } from "./with-credential.js";

// A request that names no credential authority gets a neutral one covering
// exactly its own target and action (./with-credential.ts), so the Mission
// bound decides; a test of the credential bound names `authority` itself.
const evaluate = (req: EvaluationRequest, opts: EvaluateOptions) => evaluateRequest(withCredential(req), opts);

const AUDIENCE = "http://localhost:4403/mcp";
const SERVICE = AUDIENCE;
const ADMIN = "http://localhost:4403/mcp/admin";
const NOW = new Date("2026-10-18T12:00:00Z");
const PEP_ID = "mcp-payments-pep";
const SECRET = "test-shared-secret-1276";

const alwaysAllowFga = { checkWithContext: async () => true } as unknown as Fga;

const entry = (resource: string, over: Record<string, unknown> = {}) =>
  ({ type: MISSION_RESOURCE_ACCESS_TYPE, resource, actions: ["payments:invoice.read"], ...over }) as MissionView["authority_set"][number];

const view = (authority_set: MissionView["authority_set"] = [entry(SERVICE)]): MissionView => ({
  id: "msn_1276",
  issuer: "https://as.test",
  state: "active",
  version: 1,
  authority_hash: "sha-256:h1276",
  authority_set,
  subject: { iss: "https://as.test", sub: "alice" },
  client_id: "ap-agent",
});

const options = (over: Partial<EvaluateOptions> = {}): EvaluateOptions => ({
  view: view(),
  fga: alwaysAllowFga,
  modelId: "model-1276",
  now: () => NOW,
  stalenessBound,
  relationForAction,
  resourcePolicy: RESOURCE_POLICY_PERMITS_ALL_FIXTURE,
  stateSourcePlacement: "pep",
  ...over,
});

/** A read of invoice inv-1; `properties` replaces the resource-scoped members whole. */
const read = (properties: Record<string, unknown>, context: Record<string, unknown> = {}): EvaluationRequest =>
  ({
    subject: { id: "alice", properties: { iss: "https://as.test" } },
    resource: { type: "invoice", id: "inv-1", properties: { vendor_id: "acme", ...properties } },
    action: { name: "payments:invoice.read" },
    context: {
      mission: { id: "msn_1276", issuer: "https://as.test" },
      actor: { client_id: "ap-agent" },
      action_class: "consequential_read",
      mission_state_observation: { state: "active", mode: "fresh", freshness_at: NOW.toISOString() },
      ...context,
    },
  }) as EvaluationRequest;

const credential = (...entries: Record<string, unknown>[]) => ({ credential: { authority: entries } });
const credentialEntry = (resource: string, over: Record<string, unknown> = {}) => ({
  type: "mission_resource_access",
  resource,
  actions: ["payments:invoice.read"],
  ...over,
});

let handle: PdpHttpServerHandle | undefined;
afterEach(async () => {
  await handle?.close();
  handle = undefined;
});

describe("the PDP matches entries against the PEP-established operation target (@spec authzen#pdp-request, resource-access#resource-matching, #1276)", () => {
  it("same audience, different targets: the target the Mission names permits, and another target under the same audience is out_of_authority", async () => {
    const named = await evaluate(read({ audience: AUDIENCE, operation_target: SERVICE }), options());
    expect(named.decision, JSON.stringify(named.context)).toBe(true);
    const other = await evaluate(read({ audience: AUDIENCE, operation_target: ADMIN }), options());
    expect(other.decision).toBe(false);
    expect(other.context.denial_reason).toBe("out_of_authority");
    // Control: the Mission naming the other target permits it under the same audience.
    const renamed = await evaluate(read({ audience: AUDIENCE, operation_target: ADMIN }), options({ view: view([entry(ADMIN)]) }));
    expect(renamed.decision, JSON.stringify(renamed.context)).toBe(true);
  });

  it("matches the credential's authority on the same target: an entry naming the audience's identifier does not cover another target", async () => {
    const opts = options({ view: view([entry(ADMIN)]) });
    const audienceOnly = await evaluate(read({ audience: AUDIENCE, operation_target: ADMIN }, credential(credentialEntry(AUDIENCE))), opts);
    expect(audienceOnly.decision).toBe(false);
    expect(audienceOnly.context.denial_reason).toBe("out_of_authority");
    const covering = await evaluate(read({ audience: AUDIENCE, operation_target: ADMIN }, credential(credentialEntry(ADMIN))), opts);
    expect(covering.decision, JSON.stringify(covering.context)).toBe(true);
  });

  it("exact matching is literal: a target spelled differently from the entry by host case, default port, percent spelling, trailing slash or query never matches", async () => {
    const T = "https://api.example/orders/123";
    const opts = options({ view: view([entry(T)]) });
    const exact = await evaluate(read({ audience: AUDIENCE, operation_target: T }), opts);
    expect(exact.decision, JSON.stringify(exact.context)).toBe(true);
    for (const spelling of [
      "https://API.EXAMPLE/orders/123",
      "https://api.example:443/orders/123",
      "https://api.example/orders/%31%32%33",
      "https://api.example/orders/123/",
      "https://api.example/orders/123?",
    ]) {
      const dec = await evaluate(read({ audience: AUDIENCE, operation_target: spelling }), opts);
      expect(dec.decision, spelling).toBe(false);
      expect(dec.context.denial_reason, spelling).toBe("out_of_authority");
    }
  });

  it("a prefix entry or an unrecognized resource_match provides no authority, even for its own base; a credential carrying one is refused credential_invalid", async () => {
    for (const resource_match of ["prefix", "glob"]) {
      const dec = await evaluate(read({ audience: AUDIENCE, operation_target: SERVICE }), options({ view: view([entry(SERVICE, { resource_match })]) }));
      expect(dec.decision, resource_match).toBe(false);
      expect(dec.context.denial_reason, resource_match).toBe("out_of_authority");
      const cred = await evaluate(
        read({ audience: AUDIENCE, operation_target: SERVICE }, credential(credentialEntry(SERVICE, { resource_match }))),
        options(),
      );
      expect(cred.decision, resource_match).toBe(false);
      expect(cred.context.denial_reason, resource_match).toBe("credential_invalid");
    }
    // Control: an entry stating exact is enforced as exact.
    const stated = await evaluate(
      read({ audience: AUDIENCE, operation_target: SERVICE }, credential(credentialEntry(SERVICE, { resource_match: "exact" }))),
      options({ view: view([entry(SERVICE, { resource_match: "exact" })]) }),
    );
    expect(stated.decision, JSON.stringify(stated.context)).toBe(true);
  });

  it("a missing, malformed or ambiguous target is refused, with no fallback to the audience or to type and id", async () => {
    const cases: Array<[string, Record<string, unknown>]> = [
      ["relative", { audience: AUDIENCE, operation_target: "/mcp" }],
      ["fragment", { audience: AUDIENCE, operation_target: `${SERVICE}#x` }],
      ["missing", { audience: AUDIENCE }],
      ["empty", { audience: AUDIENCE, operation_target: "" }],
      ["one-element array", { audience: AUDIENCE, operation_target: [SERVICE] }],
      ["two targets", { audience: AUDIENCE, operation_target: [SERVICE, ADMIN] }],
      ["number", { audience: AUDIENCE, operation_target: 1 }],
    ];
    // The Mission also names each malformed string verbatim, so only the
    // target's own shape check can refuse it.
    const opts = options({ view: view([entry(SERVICE), entry("/mcp"), entry(`${SERVICE}#x`)]) });
    // So does the credential: no other bound refuses in the target check's place.
    const covering = credential(credentialEntry(SERVICE), credentialEntry("/mcp"), credentialEntry(`${SERVICE}#x`));
    for (const [label, properties] of cases) {
      // The audience, the type and the id each name the entry's resource.
      const req = read(properties, covering);
      req.resource.type = SERVICE;
      req.resource.id = SERVICE;
      const dec = await evaluate(req, opts);
      expect(dec.decision, label).toBe(false);
      expect(dec.context.denial_reason, label).toBe("out_of_authority");
    }
  });

  it("validates the audience independently of the target: a missing or array audience refuses though the target matches, and a logical audience no entry names permits on the target", async () => {
    for (const [label, properties] of [
      ["missing audience", { operation_target: SERVICE }],
      ["array audience", { audience: [AUDIENCE], operation_target: SERVICE }],
    ] as const) {
      const dec = await evaluate(read(properties), options());
      expect(dec.decision, label).toBe(false);
      expect(dec.context.denial_reason, label).toBe("out_of_authority");
    }
    const logical = await evaluate(read({ audience: "urn:example:payments-pep", operation_target: SERVICE }), options());
    expect(logical.decision, JSON.stringify(logical.context)).toBe(true);
  });

  it("same type and id with a changed target: the entry match follows the target while Resource policy sees the same object identity", async () => {
    const policy = resourcePolicyFixture();
    const permitted = await evaluate(read({ audience: AUDIENCE, operation_target: SERVICE }), options({ resourcePolicy: policy }));
    expect(permitted.decision, JSON.stringify(permitted.context)).toBe(true);
    const moved = await evaluate(read({ audience: AUDIENCE, operation_target: ADMIN }), options({ resourcePolicy: policy }));
    expect(moved.decision).toBe(false);
    expect(moved.context.denial_reason).toBe("out_of_authority");
    // Resource policy was asked once, about the object, never about a target.
    expect(policy.queries).toHaveLength(1);
    expect(policy.queries[0]?.targets).toEqual([{ type: "invoice", id: "inv-1" }]);
    // Both targets under one Mission: Resource policy decides the same object identically for each.
    const refusing = resourcePolicyFixture(() => true);
    for (const target of [SERVICE, ADMIN]) {
      const dec = await evaluate(
        read({ audience: AUDIENCE, operation_target: target }),
        options({ view: view([entry(SERVICE), entry(ADMIN)]), resourcePolicy: refusing }),
      );
      expect(dec.context.denial_reason, target).toBe("resource_policy");
    }
    expect(refusing.queries.map((q) => q.targets)).toEqual([[{ type: "invoice", id: "inv-1" }], [{ type: "invoice", id: "inv-1" }]]);
  });

  it("binds the target into operation identity, the authorization binding and the cache key while audience, action and type/id stay equal", () => {
    const a = read({ audience: AUDIENCE, operation_target: SERVICE, }, { parameter_digest: "sha-256:same" });
    const b = read({ audience: AUDIENCE, operation_target: ADMIN }, { parameter_digest: "sha-256:same" });
    expect(operationIdentity(a)).not.toBe(operationIdentity(b));
    expect(authorizationBinding(a, view(), "m")).not.toEqual(authorizationBinding(b, view(), "m"));
    expect(decisionCacheKey(a, view(), "m")).not.toBe(decisionCacheKey(b, view(), "m"));
    // Control: the same target is the same identity, binding and key.
    const a2 = read({ audience: AUDIENCE, operation_target: SERVICE }, { parameter_digest: "sha-256:same" });
    expect(operationIdentity(a2)).toBe(operationIdentity(a));
    expect(decisionCacheKey(a2, view(), "m")).toBe(decisionCacheKey(a, view(), "m"));
  });

  it("the remote PDP refuses a target the authenticated PEP may not establish before evaluation, independently of its audience scope", async () => {
    const evaluations = { n: 0 };
    const start = async (operationTargets?: readonly string[]) => {
      await handle?.close();
      handle = await createPdpHttpServer({
        peps: new Map([[PEP_ID, { secret: SECRET, scopes: [AUDIENCE], ...(operationTargets ? { operationTargets } : {}) }]]),
        getOptions: () => options({ view: view([entry(SERVICE), entry(ADMIN)]) }),
        evaluateFn: async (r, o) => {
          evaluations.n += 1;
          return evaluateRequest(r, o);
        },
        resourcePolicy: RESOURCE_POLICY_PERMITS_ALL_FIXTURE,
      });
      return handle;
    };
    const ask = (server: PdpHttpServerHandle, target: string) =>
      evaluateRemote(withCredential(read({ audience: AUDIENCE, operation_target: target })), { url: server.url, pepId: PEP_ID, secret: SECRET });

    // Registered for its audience alone: only the service-level target.
    let server = await start();
    const refused = await ask(server, ADMIN);
    expect(refused.decision).toBe(false);
    expect(refused.context.denial_reason).toBe("decision_channel_refused");
    expect(evaluations.n).toBe(0);
    const served = await ask(server, SERVICE);
    expect(served.decision, JSON.stringify(served.context)).toBe(true);
    expect(evaluations.n).toBe(1);

    // Registered for the finer target too: it is evaluated.
    server = await start([SERVICE, ADMIN]);
    const registered = await ask(server, ADMIN);
    expect(registered.decision, JSON.stringify(registered.context)).toBe(true);
    expect(evaluations.n).toBe(2);
  });
});
