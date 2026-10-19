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

describe("PDP enforces tenant on the Mission and credential bounds (@spec resource-access#rs-enforcement)", () => {
  const TENANT = { tenant: "payments-demo" };

  it("permits the bound's tenant and refuses another, compared as exact strings", async () => {
    expect((await decide(view(TENANT), { tenant: "payments-demo" })).permit).toBe(true);
    for (const other of ["other-tenant", "Payments-Demo", "payments-demo "]) {
      expect(await decide(view(TENANT), { tenant: other }), other).toMatchObject({
        permit: false,
        reason: "parameter_violation",
      });
    }
  });

  it("refuses when the PEP established no tenant", async () => {
    expect(await decide(view(TENANT), {})).toMatchObject({ permit: false, reason: "parameter_violation" });
  });

  it("a credential bound to a tenant is enforced at its own tenant under an unbounded Mission", async () => {
    const credential = [
      { type: "mission_resource_access", resource: RESOURCE, actions: [ACTION], constraints: TENANT },
    ];
    expect((await decide(view(), { tenant: "payments-demo" }, credential)).permit).toBe(true);
    expect(await decide(view(), { tenant: "other-tenant" }, credential)).toMatchObject({
      permit: false,
      reason: "parameter_violation",
    });
  });
});

describe("PDP enforces time_window at the decision and bounds the permit by it (@spec resource-access#initial-common-constraints)", () => {
  const at = (offsetSeconds: number) => new Date(NOW.getTime() + offsetSeconds * 1000).toISOString();
  const validUntil = async (v: MissionView, credential?: unknown[]) => {
    const d = await evaluate(request({}, credential), opts(v));
    expect(d.decision, JSON.stringify(d.context)).toBe(true);
    return Date.parse((d.context.conditions as { valid_until: string }).valid_until);
  };

  it("permits within the window, both bounds inclusive, and refuses before it opens or after it closes", async () => {
    expect((await decide(view({ time_window: { not_before: at(-60), not_after: at(60) } }), {})).permit).toBe(true);
    expect((await decide(view({ time_window: { not_before: at(0) } }), {})).permit).toBe(true);
    expect(await decide(view({ time_window: { not_before: at(1) } }), {})).toMatchObject({
      permit: false,
      reason: "parameter_violation",
    });
    expect(await decide(view({ time_window: { not_after: at(-1) } }), {})).toMatchObject({
      permit: false,
      reason: "parameter_violation",
    });
  });

  it("a window that closes at the decision instant leaves no permit, refused as the window's, not the state's", async () => {
    expect(await decide(view({ time_window: { not_after: at(0) } }), {})).toMatchObject({
      permit: false,
      reason: "parameter_violation",
    });
  });

  it("caps the permit's valid_until at the matched entry's window end", async () => {
    const unbounded = await validUntil(view());
    expect(unbounded).toBeGreaterThan(NOW.getTime() + 30_000);
    expect(await validUntil(view({ time_window: { not_after: at(30) } }))).toBe(NOW.getTime() + 30_000);
    // A window ending after the permit's own lifetime does not extend it.
    expect(await validUntil(view({ time_window: { not_after: at(86_400) } }))).toBe(unbounded);
  });

  it("caps the permit at the credential's window when every covering credential entry carries one", async () => {
    const windowed = (seconds: number) => ({
      type: "mission_resource_access",
      resource: RESOURCE,
      actions: [ACTION],
      constraints: { time_window: { not_after: at(seconds) } },
    });
    const unbounded = await validUntil(view());
    expect(await validUntil(view(), [windowed(20)])).toBe(NOW.getTime() + 20_000);
    // Alternatives: the permit rests on whichever covering entry lasts longest.
    expect(await validUntil(view(), [windowed(20), windowed(40)])).toBe(NOW.getTime() + 40_000);
    const open = { type: "mission_resource_access", resource: RESOURCE, actions: [ACTION] };
    expect(await validUntil(view(), [windowed(20), open])).toBe(unbounded);
    expect(await decide(view(), {}, [windowed(-5)])).toMatchObject({ permit: false, reason: "parameter_violation" });
  });
});

describe("PDP enforces recipient_domain over every resolved recipient (@spec resource-access#initial-common-constraints)", () => {
  const DOMAIN = { recipient_domain: "example.com" };
  const send = async (recipients: unknown, v: MissionView, credential?: unknown[]) => {
    const base = request({}, credential);
    const req = {
      ...base,
      action: { name: ACTION, ...(recipients === undefined ? {} : { properties: { recipients } }) },
    } as EvaluationRequest;
    const d = await evaluate(req, opts(v));
    return { permit: d.decision, reason: d.context.denial_reason };
  };

  it("permits when every recipient is within the domain, subdomains and case included", async () => {
    expect((await send(["a@example.com", "b@Mail.EXAMPLE.com"], view(DOMAIN))).permit).toBe(true);
  });

  it("refuses when any one recipient is outside the domain", async () => {
    expect(await send(["a@example.com", "b@example.net"], view(DOMAIN))).toMatchObject({
      permit: false,
      reason: "parameter_violation",
    });
  });

  it("refuses when no recipient was established, or the list cannot be read", async () => {
    for (const recipients of [undefined, [], ["a@example.com", 7], ["not-an-address"]]) {
      expect(await send(recipients, view(DOMAIN)), JSON.stringify(recipients)).toMatchObject({
        permit: false,
        reason: "parameter_violation",
      });
    }
  });

  it("a credential bound to a domain is enforced at its own domain under an unbounded Mission", async () => {
    const credential = [
      { type: "mission_resource_access", resource: RESOURCE, actions: [ACTION], constraints: DOMAIN },
    ];
    expect((await send(["a@example.com"], view(), credential)).permit).toBe(true);
    expect(await send(["a@example.com", "b@example.org"], view(), credential)).toMatchObject({
      permit: false,
      reason: "parameter_violation",
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
