/**
 * @spec authzen#pdp-request, authzen#context-audience-freshness (#1004): the
 * PDP reads the AuthZEN profile's own members. The approved entry's resource
 * is matched against `resource.properties.audience`, never the AuthZEN
 * `resource` object's `type`/`id` identity.
 *
 * The FGA layer is a stub that always permits, so only evaluate()'s own
 * steps decide, and this file never skips.
 */

import { describe, expect, it } from "vitest";
import { evaluate, type EvaluateOptions, type EvaluationRequest } from "../src/evaluate.js";
import type { Fga } from "../src/fga.js";
import { MISSION_RESOURCE_ACCESS_TYPE, type MissionView } from "../src/policy-view.js";
import { relationForAction, stalenessBound } from "../src/policy.js";
import { freshKey, openTestClaims } from "./claim-fixture.js";

const RESOURCE = "http://localhost:4403/mcp";
const OTHER_RESOURCE = "http://localhost:4499/mcp";
const NOW = new Date("2026-10-02T12:00:00Z");

const alwaysAllowFga = { checkWithContext: async () => true } as unknown as Fga;
const CLAIMS = openTestClaims({ now: () => NOW });

const view = (over: Partial<MissionView> = {}): MissionView => ({
  id: "msn_1004",
  issuer: "https://as.test",
  state: "active",
  version: 3,
  authority_hash: "sha-256:h1004",
  authority_set: [
    {
      type: MISSION_RESOURCE_ACCESS_TYPE,
      resource: RESOURCE,
      actions: ["payments:invoice.read", "payments:payment.execute"],
    },
  ],
  subject: { iss: "https://as.test", sub: "alice" },
  client_id: "ap-agent",
  ...over,
});

const options = (over: Partial<EvaluateOptions> = {}): EvaluateOptions => ({
  view: view(),
  fga: alwaysAllowFga,
  modelId: "model-1004",
  now: () => NOW,
  stalenessBound,
  relationForAction,
  claims: CLAIMS,
  ...over,
});

/** A read of one invoice: below the high-consequence floor, no observation needed. */
const readRequest = (resource: EvaluationRequest["resource"]): EvaluationRequest =>
  ({
    subject: { id: "alice" },
    resource,
    action: { name: "payments:invoice.read", properties: { idempotency_key: freshKey() } },
    context: {
      mission: { id: "msn_1004", issuer: "https://as.test" },
      actor: { client_id: "ap-agent" },
    },
  }) as EvaluationRequest;

const HIGH_CONSEQUENCE_CLASSES = ["irreversible_action", "external_commitment", "privileged_administration"];

/** A well-formed `fresh` observation read at the decision instant. */
const observed = (over: Record<string, unknown> = {}): Record<string, unknown> => ({
  state: "active",
  mode: "fresh",
  freshness_at: NOW.toISOString(),
  ...over,
});

interface ObservedRequest {
  actionClass?: string;
  /** The observation carried; `null` omits the member. Defaults to {@link observed}(). */
  observation?: Record<string, unknown> | null;
}

/** A keyed payment request; the class label is the request's own. */
const observedRequest = (o: ObservedRequest = {}): EvaluationRequest =>
  ({
    subject: { id: "alice", properties: { iss: "https://as.test" } },
    resource: { type: "invoice", id: "inv-1", properties: { audience: RESOURCE, vendor_id: "acme" } },
    action: { name: "payments:payment.execute", properties: { idempotency_key: freshKey() } },
    context: {
      mission: { id: "msn_1004", issuer: "https://as.test" },
      actor: { client_id: "ap-agent" },
      ...(o.actionClass !== undefined ? { action_class: o.actionClass } : {}),
      ...(o.observation === null ? {} : { mission_state_observation: o.observation ?? observed() }),
    },
  }) as EvaluationRequest;

describe("AuthZEN profile members (@spec authzen#pdp-request, authzen#context-audience-freshness, #1004)", () => {
  describe("under PEP placement the PDP reads context.mission_state_observation", () => {
    it("a well-formed, fresh observation establishes Mission state for every high-consequence class, with no context.freshness", async () => {
      for (const actionClass of HIGH_CONSEQUENCE_CLASSES) {
        const req = observedRequest({ actionClass });
        expect((req.context as Record<string, unknown>).freshness).toBeUndefined();
        const dec = await evaluate(req, options({ stateSourcePlacement: "pep" }));
        expect(dec.decision, `${actionClass}: ${JSON.stringify(dec.context)}`).toBe(true);
      }
    });
  });

  describe("the entry match reads resource.properties.audience", () => {
    it("matches the approved entry's resource against resource.properties.audience, with no context.audience and a resource id that names an object", async () => {
      const req = readRequest({ type: "invoice", id: "inv-1", properties: { audience: RESOURCE, vendor_id: "acme" } });
      expect((req.context as Record<string, unknown>).audience).toBeUndefined();
      const dec = await evaluate(req, options());
      expect(dec.decision, JSON.stringify(dec.context)).toBe(true);
    });

    it("never matches on the resource object's id or type: an id naming the entry's resource under another audience is out_of_authority", async () => {
      const dec = await evaluate(
        readRequest({ type: RESOURCE, id: RESOURCE, properties: { audience: OTHER_RESOURCE, vendor_id: "acme" } }),
        options(),
      );
      expect(dec.decision).toBe(false);
      expect(dec.context.denial_reason).toBe("out_of_authority");
    });
  });
});
