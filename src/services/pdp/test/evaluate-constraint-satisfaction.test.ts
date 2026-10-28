/**
 * @spec resource-access#common-constraints, resource-access#rs-enforcement (#1375)
 *
 * Entry-level fail-closed at the PDP's credential bound (step 5c): a credential
 * entry whose Common Constraint needs a fact the PEP did not establish
 * provides no authority; another credential entry then permits only on its
 * own, with every constraint satisfied; without one, the decision refuses;
 * fragments of entries never combine.
 *
 * The Mission bound applies the same rule (#1375): every applicable Authority
 * Set entry is a candidate, each entry-scoped check narrows the candidates,
 * and the request is refused only when none survives, so an independently
 * sufficient alternative entry authorizes and fragments of entries never
 * combine. The credential-bound tests below keep the Mission entry
 * unconstrained, so only the credential's constraints can fail; the
 * Mission-bound tests keep the credential unconstrained.
 *
 * `requires_action_approval` (@spec resource-access#initial-common-constraints):
 * `false` needs no approval input; `true` is satisfied only by an approval
 * fresh within the maximum age and bound to the request's parameter digest.
 *
 * Unit level: a stub `Fga` satisfies the one method evaluate() calls.
 */

import { capabilitySourceDigest } from "@mission/core";
import { describe, expect, it } from "vitest";
import type { Fga } from "../src/fga.js";
import {
  type EvaluationRequest,
  evaluate,
  type MissionView,
  relationForAction,
  stalenessBound,
} from "../src/index.js";
import { RESOURCE_POLICY_PERMITS_ALL_FIXTURE } from "../src/test-support.js";
import { withActionClass } from "./with-credential.js";

const RESOURCE = "http://localhost:4403/mcp";
const ACTION = "payments:invoice.read";
const OTHER_ACTION = "payments:vendor.read";
const NOW = new Date("2026-10-18T12:00:00Z");
const alwaysAllowFga = { checkWithContext: async () => true } as unknown as Fga;

const missionView = (constraints?: Record<string, unknown>): MissionView => ({
  id: "msn_1375",
  issuer: "https://as.test",
  state: "active",
  version: 1,
  authority_hash: "sha-256:testhash",
  authority_set: [
    {
      type: "mission_resource_access",
      resource: RESOURCE,
      actions: [ACTION],
      ...(constraints ? { constraints } : {}),
    } as MissionView["authority_set"][number],
  ],
  subject: { iss: "https://as.test", sub: "alice" },
  client_id: "ap-agent",
});
const view = missionView();

const credentialEntry = (constraints?: Record<string, unknown>, actions: string[] = [ACTION]) => ({
  type: "mission_resource_access",
  resource: RESOURCE,
  actions,
  ...(constraints ? { constraints } : {}),
});

/** A decision on the facts the PEP established: anything omitted is absent. */
async function decide(
  credential: unknown[],
  properties: Record<string, unknown> = {},
  amount?: { amount: string; currency: string },
  v: MissionView = view,
  context: Partial<EvaluationRequest["context"]> = {},
) {
  const req: EvaluationRequest = withActionClass({
    subject: { id: "alice" },
    resource: {
      type: "invoice",
      id: "inv-1",
      properties: { audience: RESOURCE, operation_target: RESOURCE, vendor_id: "acme", ...properties },
    },
    action: { name: ACTION },
    context: {
      mission: { id: "msn_1375", issuer: "https://as.test", authority_hash: "sha-256:testhash" },
      credential: { authority: credential as never },
      ...(amount ? { amount } : {}),
      ...context,
    },
  });
  const d = await evaluate(req, {
    view: v,
    fga: alwaysAllowFga,
    modelId: "model-1",
    now: () => NOW,
    stalenessBound,
    relationForAction,
    resourcePolicy: RESOURCE_POLICY_PERMITS_ALL_FIXTURE,
    maxApprovalAgeSeconds: 300,
  });
  return { permit: d.decision, reason: d.context.denial_reason, digest: d.context.entry_digest as string | undefined };
}

const TENANT = { tenant: "payments-demo" };
const ISSUED_AFTER = { resource_issued_after: "2026-07-01T00:00:00Z" };
const CAP = { max_amount: { amount: "500.00", currency: "USD" } };
const REFUSED = { permit: false, reason: "parameter_violation" };

describe("PDP: a credential entry whose constraint cannot be satisfied provides no authority (@spec resource-access#common-constraints)", () => {
  it("refuses when the only credential entry needs a tenant, issuance or amount fact the PEP did not establish", async () => {
    expect(await decide([credentialEntry(TENANT)])).toMatchObject(REFUSED);
    expect(await decide([credentialEntry(ISSUED_AFTER)])).toMatchObject(REFUSED);
    expect(await decide([credentialEntry(CAP)])).toMatchObject(REFUSED);
    // Positive controls: each entry permits once its fact is established.
    expect((await decide([credentialEntry(TENANT)], { tenant: "payments-demo" })).permit).toBe(true);
    expect((await decide([credentialEntry(ISSUED_AFTER)], { issued_at: "2026-08-15T09:30:00Z" })).permit).toBe(true);
    expect((await decide([credentialEntry(CAP)], {}, { amount: "500.00", currency: "USD" })).permit).toBe(true);
  });
});

describe("PDP: another credential entry permits only on its own (@spec resource-access#common-constraints, resource-access#rs-enforcement)", () => {
  it("permits through an independently sufficient alternative entry beside one whose fact is absent", async () => {
    expect((await decide([credentialEntry(TENANT), credentialEntry()])).permit).toBe(true);
    expect((await decide([credentialEntry(ISSUED_AFTER), credentialEntry()])).permit).toBe(true);
  });

  it("refuses when every applicable entry misses a fact", async () => {
    expect(await decide([credentialEntry(TENANT), credentialEntry(ISSUED_AFTER), credentialEntry(CAP)])).toMatchObject(
      REFUSED,
    );
  });

  it("never combines fragments: one entry's action and another entry's constraints, or one entry's tenant and another's amount, do not permit", async () => {
    // The entry naming the action lacks its tenant fact; the unconstrained entry names another action.
    expect(await decide([credentialEntry(TENANT), credentialEntry(undefined, [OTHER_ACTION])])).toMatchObject(REFUSED);
    // Each entry satisfies one of tenant and amount, never both.
    const halves = [
      credentialEntry({ tenant: "payments-demo", max_amount: { amount: "500.00", currency: "USD" } }),
      credentialEntry({ tenant: "other-tenant", max_amount: { amount: "1000.00", currency: "USD" } }),
    ];
    expect(await decide(halves, { tenant: "payments-demo" }, { amount: "700.00", currency: "USD" })).toMatchObject(
      REFUSED,
    );
    // Positive control: one entry satisfying both permits.
    const whole = credentialEntry({ tenant: "payments-demo", max_amount: { amount: "1000.00", currency: "USD" } });
    expect(
      (await decide([...halves, whole], { tenant: "payments-demo" }, { amount: "700.00", currency: "USD" })).permit,
    ).toBe(true);
  });
});

describe("PDP: requires_action_approval's input and predicate (@spec resource-access#initial-common-constraints)", () => {
  const DIGEST = "sha-256:op-1375";
  const approval = (over: Record<string, unknown> = {}) => ({
    parameter_digest: DIGEST,
    action_approval: { id: "apr_1375", approved_at: NOW.toISOString(), parameter_digest: DIGEST, ...over },
  });
  const required = { permit: false, reason: "action_approval_required" };

  it("false needs no approval input: an entry carrying false permits with no approval, as one omitting the member does", async () => {
    const off = { requires_action_approval: false };
    expect((await decide([credentialEntry()], {}, undefined, missionView(off))).permit).toBe(true);
    expect((await decide([credentialEntry(off)])).permit).toBe(true);
    // Control: true with no approval refuses.
    const gated = missionView({ requires_action_approval: true });
    expect(await decide([credentialEntry()], {}, undefined, gated)).toMatchObject(required);
  });

  it("true is satisfied only by an approval fresh within the maximum age and bound to the request's parameter digest", async () => {
    const gated = missionView({ requires_action_approval: true });
    const ask = (context: Partial<EvaluationRequest["context"]>) =>
      decide([credentialEntry()], {}, undefined, gated, context);
    expect((await ask(approval())).permit).toBe(true);
    // Older than the deployment's 300-second maximum age.
    const stale = new Date(NOW.getTime() - 301_000).toISOString();
    expect(await ask(approval({ approved_at: stale }))).toMatchObject(required);
    // Bound to other parameters than the request's.
    expect(await ask(approval({ parameter_digest: "sha-256:other-op" }))).toMatchObject(required);
  });
});

// @spec resource-access#common-constraints, resource-access#rs-enforcement
// (#1375): "It MUST refuse the request unless another applicable entry
// independently authorizes the whole request with every constraint
// satisfied." The credential here is unconstrained, so only the Mission
// bound can refuse.
describe("PDP Mission bound: applicable entries are alternative grants (#1375)", () => {
  type Entry = MissionView["authority_set"][number];
  const mEntry = (over: Record<string, unknown> = {}, actions: string[] = [ACTION]) =>
    ({ type: "mission_resource_access", resource: RESOURCE, actions, ...over }) as Entry;
  const viewOf = (...entries: Entry[]): MissionView => ({ ...view, authority_set: entries });
  const free = [credentialEntry()];
  const decideOn = (v: MissionView, properties: Record<string, unknown> = {}, amount?: { amount: string; currency: string }, context: Partial<EvaluationRequest["context"]> = {}) =>
    decide(free, properties, amount, v, context);
  const tenant = mEntry({ constraints: TENANT });
  const issued = mEntry({ constraints: ISSUED_AFTER });
  const capped = mEntry({ constraints: CAP });
  const plain = mEntry();

  it("permits through an independently sufficient later entry beside one whose fact is absent", async () => {
    for (const [label, first] of [["tenant", tenant], ["issuance", issued], ["amount", capped]] as const) {
      expect(await decideOn(viewOf(first)), `${label} alone`).toMatchObject(REFUSED);
      expect((await decideOn(viewOf(first, plain))).permit, `${label} then plain`).toBe(true);
    }
  });

  it("refuses with the classified reason when every applicable entry misses a fact", async () => {
    expect(await decideOn(viewOf(tenant, issued, capped))).toMatchObject(REFUSED);
  });

  it("never combines fragments: one entry's tenant and another's amount, or another entry's action, do not permit", async () => {
    const halves = [
      mEntry({ constraints: { tenant: "payments-demo", max_amount: { amount: "500.00", currency: "USD" } } }),
      mEntry({ constraints: { tenant: "other-tenant", max_amount: { amount: "1000.00", currency: "USD" } } }),
    ];
    const facts = { tenant: "payments-demo" };
    const amount = { amount: "700.00", currency: "USD" };
    expect(await decideOn(viewOf(...halves), facts, amount)).toMatchObject(REFUSED);
    // An unconstrained entry naming another action lends nothing to one naming this action.
    expect(await decideOn(viewOf(tenant, mEntry({}, [OTHER_ACTION])))).toMatchObject(REFUSED);
    // Positive control: one entry satisfying both permits.
    const whole = mEntry({ constraints: { tenant: "payments-demo", max_amount: { amount: "1000.00", currency: "USD" } } });
    expect((await decideOn(viewOf(...halves, whole), facts, amount)).permit).toBe(true);
  });

  it("binds the permit to the entry that authorized it, not the first applicable entry", async () => {
    const alone = await decideOn(viewOf(plain));
    expect(alone.permit).toBe(true);
    const behind = await decideOn(viewOf(tenant, plain));
    expect(behind.permit).toBe(true);
    expect(behind.digest).toBe(alone.digest);
    const tenantDigest = (await decideOn(viewOf(tenant), { tenant: "payments-demo" })).digest;
    expect(behind.digest).not.toBe(tenantDigest);
  });

  it("a later entry outside the vendors constraint's exclusion authorizes, as does one for every member of a collection read", async () => {
    const other = mEntry({ constraints: { vendors: ["globex"] } });
    const acme = mEntry({ constraints: { vendors: ["acme"] } });
    expect(await decideOn(viewOf(other))).toMatchObject(REFUSED);
    expect((await decideOn(viewOf(other, acme))).permit).toBe(true);
    const both = mEntry({ constraints: { vendors: ["acme", "globex"] } });
    const members = { vendor_ids: ["acme", "globex"] };
    expect(await decideOn(viewOf(acme), members)).toMatchObject(REFUSED);
    expect((await decideOn(viewOf(acme, both), members)).permit).toBe(true);
  });

  it("an entry carrying a key the PDP does not evaluate lends nothing, and a later entry authorizes on its own", async () => {
    const unknown = mEntry({ constraints: { x_unknown: true } });
    // @spec authzen#failure-condition-coverage (#1772, D907): refused alone as
    // an unrecognized constraint, never as an evaluated violation.
    expect(await decideOn(viewOf(unknown))).toMatchObject({ permit: false, reason: "constraint_unsupported" });
    expect((await decideOn(viewOf(unknown, plain))).permit).toBe(true);
  });

  it("a contained entry provides no authority, while an entry the containment does not reach still authorizes", async () => {
    const base = mEntry({ resource: "http://localhost:4403/", resource_match: "prefix" });
    const contained = { version: 3, contained: [{ resource: RESOURCE }] };
    expect((await decideOn({ ...viewOf(plain), containment: contained })).reason).toBe("authority_contained");
    expect((await decideOn({ ...viewOf(plain, base), containment: contained })).permit).toBe(true);
  });

  it("a discharged entry provides no authority, while another applicable entry still authorizes", async () => {
    const tenantDigest = (await decideOn(viewOf(tenant), { tenant: "payments-demo" })).digest as string;
    const discharged = { entry_digests: [tenantDigest] };
    const facts = { tenant: "payments-demo" };
    expect((await decideOn({ ...viewOf(tenant), discharged }, facts)).reason).toBe("authority_discharged");
    expect((await decideOn({ ...viewOf(tenant, plain), discharged }, facts)).permit).toBe(true);
  });

  it("an entry whose recorded capability binding the request does not present lends nothing; an entry without one authorizes", async () => {
    const bound = mEntry({
      capability_sources: [
        {
          action: ACTION,
          tool_id: "mcp://payments.test/tools/get_invoice",
          source_uri: "https://payments.test/.well-known/mcp",
          source_digest: capabilitySourceDigest({ name: "get_invoice" }),
          operation_ref: "get_invoice",
        },
      ],
    });
    expect((await decideOn(viewOf(bound))).reason).toBe("capability_drift");
    expect((await decideOn(viewOf(bound, plain))).permit).toBe(true);
  });

  // @spec resource-access#rs-enforcement (#1258 item 4): an entry carrying a
  // member the resource server does not recognize, or `locations`, is one it
  // cannot fully enforce. It provides no authority, alone or as a fallback.
  it("an entry carrying an unknown member or locations provides no authority, alone or as the fallback for a failing entry", async () => {
    const unknown = mEntry({ x_unknown: true });
    const located = mEntry({ locations: [] });
    for (const [label, unenforceable] of [["unknown member", unknown], ["locations", located]] as const) {
      expect(await decideOn(viewOf(unenforceable)), label).toMatchObject({ permit: false, reason: "out_of_authority" });
      // The first entry needs an absent tenant fact; the fallback is unenforceable.
      expect(await decideOn(viewOf(tenant, unenforceable)), `tenant then ${label}`).toMatchObject(REFUSED);
      // An enforceable entry beside it still authorizes on its own.
      expect((await decideOn(viewOf(unenforceable, plain))).permit, `${label} then plain`).toBe(true);
    }
  });

  it("disregards delegation, whatever it carries: an entry with a companion member inside it still authorizes", async () => {
    const delegating = mEntry({ delegation: { max_depth: 1, x_companion: { anything: true } } });
    expect((await decideOn(viewOf(delegating))).permit).toBe(true);
  });

  it("an entry requiring an action-bound approval is satisfied only by one; without it, an entry requiring none authorizes", async () => {
    const gated = mEntry({ constraints: { requires_action_approval: true } });
    expect((await decideOn(viewOf(gated))).reason).toBe("action_approval_required");
    const behind = await decideOn(viewOf(gated, plain));
    expect(behind.permit).toBe(true);
    // The permit relies on the entry that needs no approval, never the gated one.
    expect(behind.digest).toBe((await decideOn(viewOf(plain))).digest);
    expect((await decideOn(viewOf(gated, gated))).reason).toBe("action_approval_required");
  });
});
