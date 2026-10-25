/**
 * @spec resource-access#rs-enforcement, resource-access#common-constraints (#1375)
 *
 * The reference policy decision point's executor for the `rs-authorize` cases in
 * `vectors/mission-resource-access/`. The authorization server's case reader
 * (resource-access-cases.test.ts) has no executor for this check, because an
 * `rs-authorize` case is a resource server's decision; in the reference the
 * payments resource server's decision is this PDP's (runtime-enforced profile).
 *
 * Each case's `entries` are the Mission's Authority Set and the credential
 * covers the operation unconstrained, so only the Mission bound decides. The
 * case's `target` is the operation target the PEP established, `amount` the
 * action's amount and `tenant` the target's tenant fact; FGA and Resource
 * policy permit, so the entries alone decide. A run case is decision-level
 * evidence: it does not establish token validation or the PEP's own checks.
 *
 * The executor runs a case when it implements every capability in `requires`
 * and none in `unless`, and reports every other case as skipped. It sees no
 * token, so it claims no `rs.enforcement` (`fc-04` expects `reject-token`, a
 * PEP outcome), and it declares no member roles or extension members
 * (`rs.member-roles`, `rs.extension-members`).
 */

import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import type { Fga } from "../src/fga.js";
import { type EvaluationRequest, evaluate, type MissionView, stalenessBound } from "../src/index.js";
import { RESOURCE_POLICY_PERMITS_ALL_FIXTURE } from "../src/test-support.js";

const DIR = fileURLToPath(new URL("../../../../vectors/mission-resource-access/", import.meta.url));

/** The capabilities this executor implements (README, Capabilities). */
const IMPLEMENTED: ReadonlySet<string> = new Set([
  "operation-target",
  "rs.alternative-grants",
  "constraint.max_amount",
  "constraint.tenant",
  "constraint.resource_issued_after",
  "constraint.resource_issued_before",
  "constraint.time_window",
  "constraint.recipient_domain",
  "constraint.data_classification",
  "constraint.allowed_tools",
  "constraint.requires_action_approval",
]);

interface Case {
  id: string;
  description: string;
  check: string;
  requires: string[];
  unless?: string[];
  input: Record<string, unknown>;
  expected: { outcome: string; reason: string };
}

const cases: Case[] = readdirSync(DIR)
  .filter((f) => f.endsWith(".json"))
  .sort()
  .flatMap((f) => (JSON.parse(readFileSync(join(DIR, f), "utf8")) as { cases: Case[] }).cases)
  .filter((c) => c.check === "rs-authorize");

/** Why a case is not run, or undefined when it is. */
function skipReason(c: Case): string | undefined {
  const missing = c.requires.filter((cap) => !IMPLEMENTED.has(cap));
  if (missing.length > 0) return `requires ${missing.join(", ")}`;
  const excluded = (c.unless ?? []).filter((cap) => IMPLEMENTED.has(cap));
  if (excluded.length > 0) return `inapplicable: implements ${excluded.join(", ")}`;
  return undefined;
}

const NOW = new Date("2026-10-24T12:00:00Z");
const alwaysAllowFga = { checkWithContext: async () => true } as unknown as Fga;

/** The PDP's decision on one case's inputs. */
async function decide(input: Record<string, unknown>): Promise<boolean> {
  const target = input.target as string;
  const action = input.action as string;
  const view: MissionView = {
    id: "msn_rs_cases",
    issuer: "https://as.test",
    state: "active",
    version: 1,
    authority_hash: "sha-256:rs-cases",
    authority_set: input.entries as MissionView["authority_set"],
    subject: { iss: "https://as.test", sub: "alice" },
    client_id: "ap-agent",
  };
  const req: EvaluationRequest = {
    subject: { id: "alice" },
    resource: {
      type: "invoice",
      id: "op-1",
      properties: {
        audience: target,
        operation_target: target,
        vendor_id: "",
        ...(input.tenant !== undefined ? { tenant: input.tenant } : {}),
      },
    },
    action: { name: action },
    context: {
      mission: { id: view.id, issuer: view.issuer, authority_hash: view.authority_hash },
      credential: { authority: [{ type: "mission_resource_access", resource: target, actions: [action] }] },
      ...(input.amount !== undefined ? { amount: input.amount as { amount: string; currency: string } } : {}),
    },
  };
  const decision = await evaluate(req, {
    view,
    fga: alwaysAllowFga,
    modelId: "model-rs-cases",
    now: () => NOW,
    stalenessBound,
    // The cases name their own actions; any action maps to one relation, so the
    // entries alone decide.
    relationForAction: () => ({ relation: "payer", needsAmount: false }),
    resourcePolicy: RESOURCE_POLICY_PERMITS_ALL_FIXTURE,
  });
  return decision.decision;
}

describe("the PDP's rs-authorize executor for the Mission Resource Access cases (#1375)", () => {
  const run = cases.filter((c) => skipReason(c) === undefined);
  const skipped = cases.filter((c) => skipReason(c) !== undefined);

  it("every rs-authorize case names an outcome the check defines", () => {
    expect(cases.length).toBeGreaterThan(0);
    for (const c of cases) expect(["allow", "deny", "reject-token"], c.id).toContain(c.expected.outcome);
  });

  it.each(run.map((c) => [`${c.id}: ${c.description}`, c] as const))("%s", async (_label, c) => {
    expect(await decide(c.input), c.expected.reason).toBe(c.expected.outcome === "allow");
  });

  it("runs the alternative-grant and Common Constraint cases, and skips the token-validation and member-role ones", () => {
    expect(run.map((c) => c.id).sort()).toEqual([
      "cc-satisfaction-alternative",
      "cc-satisfaction-fragments",
      "cc-satisfaction-no-alternative",
      "fc-01",
      "fc-02",
      "fc-03",
      "fc-05",
      "fc-07",
    ]);
    const reasons = Object.fromEntries(skipped.map((c) => [c.id, skipReason(c)]));
    expect(reasons["fc-04"]).toBe("requires rs.enforcement");
    expect(reasons["fc-06"]).toBe("requires rs.member-roles");
    for (const reason of Object.values(reasons)) expect(reason).toMatch(/^requires rs\.(enforcement|member-roles)/);
  });
});
