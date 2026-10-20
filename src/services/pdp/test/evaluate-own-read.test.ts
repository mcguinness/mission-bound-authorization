/**
 * @spec runtime#state-freshness, authority-server#mission-join rules 2 and 6,
 * authority-server#join-disclosure (#818)
 *
 * The decision point's own read of a remote Mission state source, under
 * `pdp` placement: the read's signed `fresh_until` caps the permit through the
 * `signed_state_fresh_until` ceiling, and one already passed establishes no
 * state. A view read without Join Disclosure (no `subject`, no `client_id`)
 * never joins.
 *
 * The FGA layer is a stub that always permits, so only evaluate()'s own
 * steps decide, and this file never skips.
 */

import { describe, expect, it } from "vitest";
import { evaluate as evaluateRequest, type EvaluateOptions, type EvaluationRequest } from "../src/evaluate.js";
import type { Fga } from "../src/fga.js";
import { MISSION_RESOURCE_ACCESS_TYPE, type MissionView } from "../src/policy-view.js";
import { relationForAction, stalenessBound } from "../src/policy.js";
import { RESOURCE_POLICY_PERMITS_ALL_FIXTURE } from "../src/test-support.js";
import { freshKey, openTestClaims } from "./claim-fixture.js";
import { withCredential } from "./with-credential.js";

const evaluate = (req: EvaluationRequest, opts: Parameters<typeof evaluateRequest>[1]) => evaluateRequest(withCredential(req), opts);

const RESOURCE = "http://localhost:4403/mcp";
const ISSUER = "https://mas.test";
const NOW = new Date("2026-10-20T12:00:00Z");
const at = (seconds: number) => new Date(NOW.getTime() + seconds * 1000).toISOString();

const view = (over: Partial<MissionView> = {}): MissionView => ({
  id: "msn_own_read",
  issuer: ISSUER,
  state: "active",
  version: 2,
  authority_hash: "sha-256:own-read",
  authority_set: [{ type: MISSION_RESOURCE_ACCESS_TYPE, resource: RESOURCE, actions: ["payments:payment.execute"] }],
  subject: { iss: ISSUER, sub: "alice" },
  client_id: "ap-agent",
  ...over,
});

const options = (over: Partial<EvaluateOptions> = {}): EvaluateOptions => ({
  view: view(),
  fga: { checkWithContext: async () => true } as unknown as Fga,
  modelId: "model-own-read",
  now: () => NOW,
  stalenessBound,
  relationForAction,
  resourcePolicy: RESOURCE_POLICY_PERMITS_ALL_FIXTURE,
  claims: openTestClaims({ now: () => NOW }),
  stateSourcePlacement: "pdp",
  stateObservedAt: NOW.toISOString(),
  ...over,
});

/** A consequential write (300 s window and lifetime), carrying no PEP observation. */
const request = (o: { action?: string; join?: boolean } = {}): EvaluationRequest =>
  ({
    subject: { id: "alice", properties: { iss: ISSUER } },
    resource: { type: "invoice", id: "inv-1", properties: { audience: RESOURCE, operation_target: RESOURCE, vendor_id: "acme" } },
    action: { name: o.action ?? "payments:payment.execute", properties: { idempotency_key: freshKey() } },
    context: {
      mission: { id: "msn_own_read", issuer: ISSUER },
      actor: { client_id: "ap-agent" },
      action_class: "consequential_write",
      ...(o.join ? { mission_join: {} } : {}),
    },
  }) as EvaluationRequest;

const validUntil = (context: Record<string, unknown>) => Date.parse((context.conditions as { valid_until: string }).valid_until);

describe("the own read's signed fresh_until under pdp placement (@spec runtime#state-freshness)", () => {
  it("caps the permit at a short signed fresh_until, which the class window alone would not", async () => {
    const capped = await evaluate(request(), options({ stateFreshUntil: at(5) }));
    expect(capped.decision, JSON.stringify(capped.context)).toBe(true);
    expect(validUntil(capped.context)).toBeLessThanOrEqual(NOW.getTime() + 5_000);
    // Control: the same read reporting no valid-through runs to the window.
    const uncapped = await evaluate(request(), options());
    expect(uncapped.decision, JSON.stringify(uncapped.context)).toBe(true);
    expect(validUntil(uncapped.context)).toBeGreaterThan(NOW.getTime() + 5_000);
  });

  it("establishes no state from a read whose signed fresh_until has passed or does not parse: stale_state, before the authority match", async () => {
    // The action is outside the Authority Set, so a decision that reached the
    // match would deny out_of_authority instead.
    for (const stateFreshUntil of [at(0), at(-1), "not-a-time"]) {
      const dec = await evaluate(request({ action: "payments:invoice.read" }), options({ stateFreshUntil }));
      expect(dec.decision, stateFreshUntil).toBe(false);
      expect(dec.context.denial_reason, stateFreshUntil).toBe("stale_state");
    }
  });
});

describe("a view without Join Disclosure never joins (@spec authority-server#join-disclosure, #mission-join rule 6)", () => {
  it("denies mission_binding_failed when the view carries no subject or no client_id, and joins when it carries both", async () => {
    const { subject: _s, ...noSubject } = view();
    const { client_id: _c, ...noClient } = view();
    const { subject: _s2, client_id: _c2, ...neither } = view();
    for (const [label, v] of [
      ["no subject", noSubject],
      ["no client_id", noClient],
      ["neither", neither],
    ] as const) {
      const dec = await evaluate(request({ join: true }), options({ view: v as MissionView }));
      expect(dec.decision, label).toBe(false);
      expect(dec.context.denial_reason, label).toBe("mission_binding_failed");
    }
    const joined = await evaluate(request({ join: true }), options());
    expect(joined.decision, JSON.stringify(joined.context)).toBe(true);
  });
});
