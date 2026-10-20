/**
 * @spec resource-access#common-constraints, resource-access#rs-enforcement (#1375)
 *
 * Entry-level fail-closed at the PDP's credential bound (step 5c): a credential
 * entry whose Common Constraint needs a fact the PEP did not establish
 * provides no authority; another credential entry then permits only on its
 * own, with every constraint satisfied; without one, the decision refuses;
 * fragments of entries never combine.
 *
 * The Mission bound (step 5) relies on the first Authority Set entry that
 * names the target and action and evaluates that entry whole, so it refuses
 * an absent fact (evaluate-common-constraints.test.ts, evaluate-amount.test.ts)
 * but does not yet look past that entry to an alternative (#1375 Outstanding).
 * The Mission entry here carries no constraint, so only the credential's can
 * fail.
 *
 * `requires_action_approval` (@spec resource-access#initial-common-constraints):
 * `false` needs no approval input; `true` is satisfied only by an approval
 * fresh within the maximum age and bound to the request's parameter digest.
 *
 * Unit level: a stub `Fga` satisfies the one method evaluate() calls.
 */

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
  const req: EvaluationRequest = {
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
  };
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
  return { permit: d.decision, reason: d.context.denial_reason };
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
