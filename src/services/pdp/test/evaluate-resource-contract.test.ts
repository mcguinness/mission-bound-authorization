/**
 * @spec runtime#resource-contract, runtime#permit-binding,
 * authzen#context-resource-contract, authzen#context-approval,
 * authzen#runtime-denial-classification, authzen#response-context (#249,
 * D553): the PDP's resource contract checks. A presented reference must
 * resolve under the PDP's own declarations and equal an applicable entry's;
 * a missing one refuses where a contract applies; a retained version relaxes
 * no other input; an approval under one reference never covers an action
 * under another; and a permit binds the reference.
 */
import {
  type CredentialAuthorityEntry,
  ResourceContractDeclarations,
  type ResourceContractRef,
  resourceContractDigest,
} from "@mission/core";
import { describe, expect, it } from "vitest";
import {
  type ActionApproval,
  type EvaluateOptions,
  type EvaluationRequest,
  evaluate,
} from "../src/evaluate.js";
import type { Fga } from "../src/fga.js";
import type { AuthorityEntry, MissionView } from "../src/policy-view.js";
import { relationForAction, stalenessBound } from "../src/policy.js";
import { authorizationBinding, decisionCacheKey } from "../src/projections.js";
import { RESOURCE_POLICY_PERMITS_ALL_FIXTURE, resourcePolicyFixture } from "../src/test-support.js";

const RS = "https://payments.test/mcp";
const ACTION = "payments:invoice.read";
const CONTRACT = "https://payments.test/contracts/payments";
const NOW = new Date("2026-10-20T12:00:00Z");
const DIGEST = `sha-256:${Buffer.alloc(32, 7).toString("base64url")}`;

const doc = (version: string, note = "") => ({
  id: CONTRACT,
  version,
  operation_profile: `payments-profile-${version}${note}`,
  operations: { get_invoice: { action: ACTION } },
});
const ref = (version: string, note = ""): ResourceContractRef => ({
  id: CONTRACT,
  version,
  digest: resourceContractDigest(doc(version, note)),
});
const current = (version: string, note = "") => ({
  version,
  state: "current",
  digest: ref(version, note).digest,
  document: doc(version, note),
});
const superseded = (version: string, retained_until: string) => ({ ...current(version), state: "superseded", retained_until });
const retired = (version: string) => ({ version, state: "retired", digest: ref(version).digest });
const declarations = (versions: unknown[], requires: string[] = []) =>
  new ResourceContractDeclarations([
    { resource: RS, resource_match: "prefix", id: CONTRACT, requires_reference: requires, versions },
  ]);

const V1 = ref("v1");
const V2 = ref("v2");
/** v1 declared current and v2 not yet: the declaration a v1 entry was approved under. */
const V1_CURRENT = declarations([current("v1")]);
/** v1 superseded within its retention, v2 current: both resolve. */
const BOTH = declarations([superseded("v1", "2026-11-01T00:00:00Z"), current("v2")]);

const entryUnder = (r?: ResourceContractRef | null): AuthorityEntry => ({
  type: "mission_resource_access",
  resource: RS,
  actions: [ACTION],
  ...(r ? { resource_contract: r } : {}),
});
const view = (r: ResourceContractRef | null = V1, extra: Partial<MissionView> = {}): MissionView => ({
  id: "msn_contract",
  issuer: "https://as.test",
  authority_hash: "sha-256:test",
  state: "active",
  version: 1,
  subject: { iss: "https://as.test", sub: "alice" },
  client_id: "ap-agent",
  authority_set: [entryUnder(r)],
  ...extra,
});
const credentialUnder = (r?: ResourceContractRef | null): CredentialAuthorityEntry[] => [
  { type: "mission_resource_access", resource: RS, actions: [ACTION], ...(r ? { resource_contract: r } : {}) },
];
const request = (
  presented: ResourceContractRef | null = V1,
  credential: ResourceContractRef | null = presented,
): EvaluationRequest => ({
  subject: { id: "alice" },
  resource: {
    type: "invoice",
    id: "inv-1",
    properties: {
      audience: RS,
      operation_target: RS,
      vendor_id: "acme",
      ...(presented ? { resource_contract: presented } : {}),
    },
  },
  action: { name: ACTION },
  context: {
    mission: { id: "msn_contract", issuer: "https://as.test" },
    credential: { authority: credentialUnder(credential) },
    parameter_digest: DIGEST,
  },
});
const options = (
  contracts: ResourceContractDeclarations,
  v: MissionView = view(),
  extra: Partial<EvaluateOptions> = {},
): EvaluateOptions => ({
  view: v,
  fga: { checkWithContext: async () => true } as unknown as Fga,
  modelId: "test",
  now: () => NOW,
  relationForAction,
  resourcePolicy: RESOURCE_POLICY_PERMITS_ALL_FIXTURE,
  stalenessBound,
  resourceContracts: contracts,
  ...extra,
});
const reason = async (req: EvaluationRequest, opts: EvaluateOptions) => {
  const d = await evaluate(req, opts);
  return d.decision ? "permit" : (d.context.denial_reason as string);
};

describe("the PDP refuses a reference that does not resolve (@spec runtime#resource-contract, #249)", () => {
  it("permits an action under an entry whose reference resolves under the PDP's own declarations (control)", async () => {
    expect(await reason(request(), options(V1_CURRENT))).toBe("permit");
  });

  it.each([
    ["the version is retired", declarations([retired("v1"), current("v2")])],
    ["the definition changed under the same version (another digest)", declarations([current("v1", " changed")])],
    ["the resource serves only v2 (v1 is unknown there)", declarations([current("v2")])],
    ["v1 is superseded and its retention has passed", declarations([superseded("v1", "2026-10-20T11:59:59Z"), current("v2")])],
    ["the PDP declares no contract at all", ResourceContractDeclarations.NONE],
  ])("denies resource_contract_drift, with identical parameters, when %s", async (_why, contracts) => {
    const d = await evaluate(request(), options(contracts));
    expect(d.decision).toBe(false);
    expect(d.context.denial_reason).toBe("resource_contract_drift");
    expect(d.context.conditions).toBeUndefined();
  });

  it("resolves a superseded version within its declared retention, and the permit binds it", async () => {
    const d = await evaluate(request(V1), options(BOTH));
    expect(d.decision).toBe(true);
    expect((d.context.conditions as Record<string, unknown>).resource_contract).toEqual(V1);
    expect(
      await reason(request(V1), options(BOTH, view(), { now: () => new Date("2026-11-01T00:00:01Z") })),
    ).toBe("resource_contract_drift");
  });
});

describe("a missing reference refuses where the resource requires one (@spec runtime#resource-contract, #249)", () => {
  const REQUIRED = declarations([current("v1")], [ACTION]);

  it("denies an action under an entry without a reference, and never supplies the current contract's", async () => {
    const unpinned = view(null);
    expect(await reason(request(null), options(REQUIRED, unpinned))).toBe("resource_contract_drift");
    // A request presenting today's current reference does not attach it to
    // the approval that committed none: no applicable entry carries it.
    expect(await reason(request(V1, null), options(REQUIRED, unpinned))).toBe("resource_contract_drift");
    expect(unpinned.authority_set[0]?.resource_contract).toBeUndefined();
    // Not required: the same unpinned entry permits (control).
    expect(await reason(request(null), options(V1_CURRENT, unpinned))).toBe("permit");
  });
});

describe("the request's reference must equal an authorizing entry's (@spec authzen#context-resource-contract, #249)", () => {
  it.each([
    ["absent while the entry references a contract", request(null, V1)],
    ["unequal to the entry's although it resolves", request(V2, V2)],
    ["unequal to the credential's", request(V1, V2)],
  ])("denies resource_contract_drift with no permit when the presented reference is %s", async (_why, req) => {
    const d = await evaluate(req, options(BOTH));
    expect(d.decision).toBe(false);
    expect(d.context.denial_reason).toBe("resource_contract_drift");
  });

  it("classifies a contract failure as resource_contract_drift, never out_of_authority, capability_drift or parameter_violation", async () => {
    for (const contracts of [declarations([current("v2")]), ResourceContractDeclarations.NONE]) {
      const r = await reason(request(), options(contracts));
      expect(r).toBe("resource_contract_drift");
      expect(["out_of_authority", "capability_drift", "parameter_violation"]).not.toContain(r);
    }
  });

  it("relies on the applicable entry whose reference equals the request's when entries under two contracts name the action", async () => {
    const two = view(V1, { authority_set: [entryUnder(V1), { ...entryUnder(V2), constraints: { vendors: ["acme"] } }] });
    const d = await evaluate(request(V2), options(BOTH, two));
    expect(d.decision).toBe(true);
    expect((d.context.conditions as Record<string, unknown>).resource_contract).toEqual(V2);
  });
});

describe("a retained contract relaxes no other decision input (@spec runtime#resource-contract rule 2, #249)", () => {
  it("under a retained superseded v1, an inactive Mission, contained authority and a Resource-policy refusal each still refuse", async () => {
    expect(await reason(request(V1), options(BOTH))).toBe("permit");
    expect(await reason(request(V1), options(BOTH, view(V1, { state: "suspended" })))).toBe("mission_inactive");
    expect(
      await reason(
        request(V1),
        options(BOTH, view(V1, { containment: { version: 1, contained: [{ resource: RS, actions: [ACTION] }] } })),
      ),
    ).toBe("authority_contained");
    expect(
      await reason(request(V1), options(BOTH, view(V1), { resourcePolicy: resourcePolicyFixture(() => true) })),
    ).toBe("resource_policy");
    expect(await reason(request(V1), options(BOTH, view(V1, { authority_set: [] })))).toBe("out_of_authority");
  });
});

describe("an action-bound approval binds the reference (@spec authzen#context-approval, runtime#resource-contract rule 4, #249)", () => {
  const approval = (r?: ResourceContractRef): ActionApproval => ({
    id: "apr_1",
    approved_at: "2026-10-20T11:59:00Z",
    parameter_digest: DIGEST,
    ...(r ? { resource: { properties: { resource_contract: r } } } : {}),
  });
  const withApproval = (req: EvaluationRequest, a?: ActionApproval): EvaluationRequest => ({
    ...req,
    context: { ...req.context, ...(a ? { action_approval: a } : {}) },
  });
  const gated = (contracts: ResourceContractDeclarations, v: MissionView) =>
    options(contracts, v, { requiresActionApproval: () => true });

  it("denies out_of_scope, with no permit, an approval given under v1 presented for the same action under v2, both resolving and the parameters identical", async () => {
    const under = (r: ResourceContractRef) => view(r);
    const d = await evaluate(withApproval(request(V2), approval(V1)), gated(BOTH, under(V2)));
    expect(d.decision).toBe(false);
    expect(d.context.denial_reason).toBe("out_of_scope");
    expect(d.context.conditions).toBeUndefined();
    // The approval given under the request's own reference satisfies the gate.
    expect(await reason(withApproval(request(V2), approval(V2)), gated(BOTH, under(V2)))).toBe("permit");
    expect(await reason(withApproval(request(V1), approval(V1)), gated(BOTH, under(V1)))).toBe("permit");
  });

  it("an approval whose approved Resource names no contract does not satisfy an action under one", async () => {
    expect(await reason(withApproval(request(V1), approval()), gated(BOTH, view(V1)))).toBe("out_of_scope");
    // Where no contract applies, neither side names one and the approval stands.
    expect(
      await reason(withApproval(request(null), approval()), gated(ResourceContractDeclarations.NONE, view(null))),
    ).toBe("permit");
  });

  it("refuses an approved action, parameters unchanged, when the definition changed after the approval and before the decision", async () => {
    const approved = withApproval(request(V1), approval(V1));
    expect(await reason(approved, gated(V1_CURRENT, view(V1)))).toBe("permit");
    // The resource changed the v1 definition (the same version, another
    // digest): the approval and parameter_digest are unchanged, and the
    // decision refuses.
    expect(await reason(approved, gated(declarations([current("v1", " changed")]), view(V1)))).toBe(
      "resource_contract_drift",
    );
  });
});

describe("the permit binds the reference (@spec runtime#permit-binding, authzen#response-context, #249)", () => {
  it("returns conditions.resource_contract equal to the validated request's, and none where no contract applies", async () => {
    const d = await evaluate(request(V1), options(V1_CURRENT));
    expect(d.decision).toBe(true);
    expect((d.context.conditions as Record<string, unknown>).resource_contract).toEqual(V1);
    const plain = await evaluate(request(null), options(ResourceContractDeclarations.NONE, view(null)));
    expect(plain.decision).toBe(true);
    expect(plain.context.conditions as Record<string, unknown>).not.toHaveProperty("resource_contract");
  });

  it("binds the reference into the authorization binding and the cache key: two requests differing only in it are never one", () => {
    const a = request(V1);
    // Only the reference differs: the credential and every other member are the same.
    const b = request(V1);
    b.resource.properties.resource_contract = V2;
    expect(authorizationBinding(a, view(), "m")).not.toEqual(authorizationBinding(b, view(), "m"));
    expect(decisionCacheKey(a, view(), "m")).not.toBe(decisionCacheKey(b, view(), "m"));
    expect(decisionCacheKey(a, view(), "m")).toBe(decisionCacheKey(request(V1), view(), "m"));
  });
});
