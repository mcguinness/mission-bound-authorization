/**
 * @spec resource-access#rs-enforcement, resource-access#initial-common-constraints,
 * runtime#input-parameters, runtime#input-authority (#1266, D457)
 *
 * The PDP's enforcement of the implemented Common Constraints, on both the
 * Mission bound (the matched Authority Set entry, step 7a) and the credential
 * bound (step 5c), against the authoritative facts the PEP establishes. An
 * absent or malformed fact refuses, never permits open, and a Mission entry
 * carrying a `constraints` key this PDP does not evaluate refuses whole.
 *
 * Unit level: a stub `Fga` satisfies the one method evaluate() calls, so this
 * file never skips. The resource-server witnesses through the payments PEP
 * are in `services/mcp-payments/test/common-constraints-enforcement.test.ts`.
 */

import { describe, expect, it } from "vitest";
import type { Fga } from "../src/fga.js";
import {
  evaluate as evaluateRequest,
  type EvaluationRequest,
  type MissionView,
  relationForAction,
  stalenessBound,
} from "../src/index.js";
import { RESOURCE_POLICY_PERMITS_ALL_FIXTURE } from "../src/test-support.js";
import { withCredential } from "./with-credential.js";

const evaluate = (req: EvaluationRequest, opts: Parameters<typeof evaluateRequest>[1]) =>
  evaluateRequest(withCredential(req), opts);

const RESOURCE = "http://localhost:4403/mcp";
const ACTION = "payments:invoice.read";
const NOW = new Date("2026-10-18T12:00:00Z");
const alwaysAllowFga = { checkWithContext: async () => true } as unknown as Fga;

const view = (constraints?: Record<string, unknown>): MissionView => ({
  id: "msn_1266",
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

const request = (
  properties: Record<string, unknown> = {},
  credentialAuthority?: unknown[],
): EvaluationRequest => ({
  subject: { id: "alice" },
  resource: { type: "invoice", id: "inv-1", properties: { audience: RESOURCE, vendor_id: "acme", ...properties } },
  action: { name: ACTION },
  context: {
    mission: { id: "msn_1266", issuer: "https://as.test", authority_hash: "sha-256:testhash" },
    ...(credentialAuthority ? { credential: { authority: credentialAuthority } } : {}),
  },
});

const opts = (v: MissionView) => ({
  view: v,
  fga: alwaysAllowFga,
  modelId: "model-1",
  now: () => NOW,
  stalenessBound,
  relationForAction,
  resourcePolicy: RESOURCE_POLICY_PERMITS_ALL_FIXTURE,
});

const Q3 = { resource_issued_after: "2026-07-01T00:00:00Z", resource_issued_before: "2026-09-30T23:59:59Z" };

async function decide(v: MissionView, properties: Record<string, unknown>, credential?: unknown[]) {
  const d = await evaluate(request(properties, credential), opts(v));
  return { permit: d.decision, reason: d.context.denial_reason };
}

describe("PDP enforces resource_issued_after and resource_issued_before on the Mission bound (@spec resource-access#rs-enforcement)", () => {
  it("permits a resource the PEP established as issued within the window", async () => {
    expect((await decide(view(Q3), { issued_at: "2026-08-15T09:30:00Z" })).permit).toBe(true);
  });

  it("refuses a resource issued before the after-bound or after the before-bound", async () => {
    expect(await decide(view(Q3), { issued_at: "2026-06-30T23:59:59Z" })).toMatchObject({
      permit: false,
      reason: "parameter_violation",
    });
    expect(await decide(view(Q3), { issued_at: "2026-10-01T00:00:00Z" })).toMatchObject({
      permit: false,
      reason: "parameter_violation",
    });
  });

  it("treats both bounds as inclusive and compares in value space, across offsets", async () => {
    expect((await decide(view(Q3), { issued_at: "2026-07-01T02:00:00+02:00" })).permit).toBe(true);
    expect((await decide(view(Q3), { issued_at: "2026-09-30T23:59:59.000Z" })).permit).toBe(true);
    expect((await decide(view(Q3), { issued_at: "2026-09-30T23:59:59.001Z" })).permit).toBe(false);
  });

  it("refuses when the issuance fact is missing or malformed, never permitting open", async () => {
    expect(await decide(view(Q3), {})).toMatchObject({ permit: false, reason: "parameter_violation" });
    expect(await decide(view(Q3), { issued_at: "2026-08-15" })).toMatchObject({
      permit: false,
      reason: "parameter_violation",
    });
    // Each bound alone, so neither gate's refusal hides the other's.
    for (const key of ["resource_issued_after", "resource_issued_before"] as const) {
      expect(await decide(view({ [key]: Q3[key] }), {}), key).toMatchObject({
        permit: false,
        reason: "parameter_violation",
      });
    }
  });

  it("an entry with no issuance bound needs no issuance fact (the gate is keyed on the constraint's presence)", async () => {
    expect((await decide(view(), {})).permit).toBe(true);
  });
});

describe("PDP enforces resource_issued_after and resource_issued_before on the credential bound (@spec runtime#input-authority)", () => {
  const bounded = [
    {
      type: "mission_resource_access",
      resource: RESOURCE,
      actions: [ACTION],
      constraints: { resource_issued_after: "2026-08-01T00:00:00Z" },
    },
  ];

  it("a credential narrower than its Mission is enforced at its own window", async () => {
    expect((await decide(view(), { issued_at: "2026-08-15T00:00:00Z" }, bounded)).permit).toBe(true);
    expect(await decide(view(), { issued_at: "2026-07-15T00:00:00Z" }, bounded)).toMatchObject({
      permit: false,
      reason: "parameter_violation",
    });
    expect(await decide(view(), {}, bounded)).toMatchObject({ permit: false, reason: "parameter_violation" });
  });

  it("refuses a credential carrying a malformed bound as credential_invalid", async () => {
    const malformed = [{ ...bounded[0], constraints: { resource_issued_after: "2026-08-01" } }];
    expect(await decide(view(), { issued_at: "2026-08-15T00:00:00Z" }, malformed)).toMatchObject({
      permit: false,
      reason: "credential_invalid",
    });
  });
});

describe("PDP fails closed on a Mission entry constraint it does not evaluate (@spec resource-access#rs-enforcement)", () => {
  it("refuses an entry carrying an unrecognized constraints key rather than ignoring it", async () => {
    expect(await decide(view({ x_region: "eu" }), { issued_at: "2026-08-15T00:00:00Z" })).toMatchObject({
      permit: false,
      reason: "parameter_violation",
    });
  });
});
