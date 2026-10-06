/**
 * @spec authzen#context-credential, authzen#pdp-request rule 6,
 * runtime#input-authority (#825 PR 2b, D312) — the PDP evaluates the
 * presented credential's own authority as an independent bound, from
 * `context.credential.authority`, identically co-resident and over a real
 * remote hop. Every request here goes to the decision point directly, with no
 * PEP and so no PEP pre-check in the path: an allowing Mission and an
 * allowing Resource policy are fixed, so each refusal is the credential
 * bound's own.
 */

import { AUTHORITY_ENTRY_TYP, computeAnchor } from "@mission/core";
import { describe, expect, it } from "vitest";
import {
  createDecisionChannel,
  createEphemeralDecisionPoint,
  type Decision,
  type DecisionEvidenceObject,
  type DecisionOptions,
  type EvaluationRequest,
  type Fga,
  type MissionView,
  relationForAction,
  stalenessBound,
} from "../src/index.js";

const RESOURCE = "http://localhost:4403/mcp";
const OTHER_RESOURCE = "https://other.example/mcp";
const READ = "payments:invoice.read";
const VENDOR_READ = "payments:vendor.read";
const LIST = "payments:invoice.list";

/** Allows every relationship, so Resource policy never refuses here. */
const alwaysAllowFga = { checkWithContext: async () => true } as unknown as Fga;

const MISSION_ENTRY = { type: "mission_resource_access" as const, resource: RESOURCE, actions: [READ, VENDOR_READ, LIST] };

/** A broad Mission: every action this file requests is within it. */
const broadView = (over: Partial<MissionView> = {}): MissionView => ({
  id: "msn_825_bound",
  issuer: "https://as.test",
  state: "active",
  version: 1,
  authority_hash: "sha-256:fixture",
  authority_set: [MISSION_ENTRY],
  subject: { iss: "https://as.test", sub: "alice" },
  client_id: "ap-agent",
  ...over,
});

const entry = (actions: string[], constraints?: Record<string, unknown>, resource = RESOURCE) => ({
  type: "mission_resource_access",
  resource,
  actions,
  ...(constraints ? { constraints } : {}),
});
const BROAD_CREDENTIAL = [entry([READ, VENDOR_READ, LIST])];

interface Ask {
  action?: string;
  properties?: Record<string, unknown>;
  credential?: unknown;
  context?: Record<string, unknown>;
}

function request(view: MissionView, ask: Ask): EvaluationRequest {
  return {
    subject: { id: "alice" },
    resource: { type: "invoice", id: "inv-1", properties: { audience: RESOURCE, vendor_id: "acme", ...ask.properties } },
    action: { name: ask.action ?? READ },
    context: {
      mission: { id: view.id, issuer: view.issuer },
      mission_state_observation: { state: "active", version: view.version, mode: "fresh", freshness_at: new Date().toISOString() },
      action_class: "consequential_read",
      ...("credential" in ask ? { credential: ask.credential } : { credential: { issuer: view.issuer, authority: BROAD_CREDENTIAL } }),
      ...ask.context,
    },
  } as EvaluationRequest;
}

const withAuthority = (authority: unknown) => ({ issuer: "https://as.test", authority });

describe.each(["co-resident", "remote"] as const)(
  "the PDP enforces the credential authority bound (%s) (@spec authzen#context-credential, #825)",
  (mode) => {
    /** Decide `ask` against `view` over a fresh decision channel of this mode. */
    async function decide(
      view: MissionView,
      ask: Ask,
      fga: Fga = alwaysAllowFga,
    ): Promise<{ decision: Decision; evidence: DecisionEvidenceObject }> {
      const point = createEphemeralDecisionPoint({ emitterId: RESOURCE, audience: RESOURCE });
      const options = (): DecisionOptions => ({
        view,
        fga,
        modelId: "m",
        now: () => new Date(),
        stalenessBound,
        relationForAction,
        stateSourcePlacement: "pep",
      });
      const channel = await createDecisionChannel(point, { mode, pepId: "pep-825", audience: RESOURCE, getOptions: options });
      try {
        const decision = await channel.decide(request(view, ask), options());
        return { decision, evidence: decision.context.decision_evidence as DecisionEvidenceObject };
      } finally {
        await channel.close();
      }
    }
    const refusedAt = async (bound: "credential" | "mission", view: MissionView, ask: Ask) => {
      const { decision, evidence } = await decide(view, ask);
      expect(decision.decision, JSON.stringify(decision.context)).toBe(false);
      expect(decision.context.denial_reason).toBe("out_of_authority");
      expect(evidence.authority_bound).toBe(bound);
    };
    const permitted = async (view: MissionView, ask: Ask) => {
      const { decision, evidence } = await decide(view, ask);
      expect(decision.decision, JSON.stringify(decision.context)).toBe(true);
      expect(evidence).not.toHaveProperty("authority_bound");
    };

    it("an allowing Mission and Resource policy never repair a narrower credential", async () => {
      await refusedAt("credential", broadView(), { action: VENDOR_READ, credential: withAuthority([entry([READ])]) });
      await permitted(broadView(), { action: VENDOR_READ, credential: withAuthority(BROAD_CREDENTIAL) });
    });

    it("narrows independently by resource, action, vendor, and amount, and a cap in another currency is not comparable", async () => {
      const v = broadView();
      await refusedAt("credential", v, { credential: withAuthority([entry([READ], undefined, OTHER_RESOURCE)]) });
      await refusedAt("credential", v, { credential: withAuthority([entry([LIST])]) });
      await refusedAt("credential", v, { credential: withAuthority([entry([READ], { vendors: ["globex"] })]) });
      await permitted(v, { credential: withAuthority([entry([READ], { vendors: ["acme"] })]) });
      const amount = { amount: "125.00", currency: "USD" };
      const cap = (a: string, currency: string) => withAuthority([entry([READ], { max_amount: { amount: a, currency } })]);
      await refusedAt("credential", v, { credential: cap("100.00", "USD"), context: { amount } });
      await refusedAt("credential", v, { credential: cap("500.00", "EUR"), context: { amount } });
      await refusedAt("credential", v, { credential: cap("500.00", "USD") });
      await permitted(v, { credential: cap("125.00", "USD"), context: { amount } });
    });

    it("a credential that mirrors its Mission keeps the Mission's classification of a failed constraint", async () => {
      // The Mission's own checks run first, so a constraint both bounds carry
      // is the Mission's `parameter_violation` (#801); only a credential
      // narrower than its Mission is refused at the credential bound.
      const mirrored = broadView({ authority_set: [{ ...MISSION_ENTRY, constraints: { vendors: ["globex"] } }] });
      const { decision, evidence } = await decide(mirrored, {
        credential: withAuthority([entry(MISSION_ENTRY.actions, { vendors: ["globex"] })]),
      });
      expect(decision.context.denial_reason).toBe("parameter_violation");
      expect(evidence).not.toHaveProperty("authority_bound");
    });

    it("refuses an action that only a union of two entries would permit", async () => {
      await refusedAt("credential", broadView(), {
        credential: withAuthority([entry([READ], { vendors: ["globex"] }), entry([VENDOR_READ], { vendors: ["acme"] })]),
      });
    });

    it("covers a collection read only when one entry covers every vendor it reaches", async () => {
      const collection = { action: LIST, properties: { vendor_id: "acme", vendor_ids: ["acme", "globex"] } };
      await refusedAt("credential", broadView(), { ...collection, credential: withAuthority([entry([LIST], { vendors: ["acme"] })]) });
      await permitted(broadView(), { ...collection, credential: withAuthority([entry([LIST], { vendors: ["acme", "globex"] })]) });
    });

    it.each([
      ["no authority", { issuer: "https://as.test" }],
      ["an authority that is not an array", withAuthority({ type: "mission_resource_access" })],
      ["an unknown authority type", withAuthority([{ type: "other", resource: RESOURCE, actions: [READ] }])],
      ["an unknown entry member", withAuthority([{ ...entry([READ]), locations: ["x"] }])],
      ["an unknown constraint", withAuthority([entry([READ], { time_window: "9-5" })])],
      ["a malformed amount cap", withAuthority([entry([READ], { max_amount: { amount: "ten", currency: "USD" } })])],
      ["an expiry that has passed", { ...withAuthority(BROAD_CREDENTIAL), expires_at: new Date(Date.now() - 1000).toISOString() }],
      ["a malformed expiry", { ...withAuthority(BROAD_CREDENTIAL), expires_at: "tomorrow" }],
      ["a credential that is not an object", "credential"],
      ["a null credential", null],
    ])("refuses credential_invalid for %s, never falling back to the Mission (rule 6)", async (_label, credential) => {
      const { decision, evidence } = await decide(broadView(), { credential });
      expect(decision.decision).toBe(false);
      expect(decision.context.denial_reason).toBe("credential_invalid");
      expect(evidence.denial_reason).toBe("credential_invalid");
      expect(evidence).not.toHaveProperty("authority_bound");
    });

    it("an empty authority covers nothing, and a live expiry is accepted", async () => {
      await refusedAt("credential", broadView(), { credential: withAuthority([]) });
      await permitted(broadView(), {
        credential: { ...withAuthority(BROAD_CREDENTIAL), expires_at: new Date(Date.now() + 60_000).toISOString() },
      });
    });

    it("a Mission narrowed after issuance refuses even a credential that covers the action", async () => {
      // The credential still carries the vendor read; the Mission no longer does.
      const narrowed = broadView({ authority_set: [{ ...MISSION_ENTRY, actions: [READ] }] });
      await refusedAt("mission", narrowed, { action: VENDOR_READ, credential: withAuthority(BROAD_CREDENTIAL) });
      const contained = broadView({ containment: { version: 1, contained: [{ resource: RESOURCE, actions: [READ] }] } });
      const { decision } = await decide(contained, { credential: withAuthority(BROAD_CREDENTIAL) });
      expect(decision.context.denial_reason).toBe("authority_contained");
    });

    it("records the Mission bound for a Resource-policy refusal past a covering credential", async () => {
      const denyingFga = { checkWithContext: async () => false } as unknown as Fga;
      const { decision, evidence } = await decide(broadView(), { credential: withAuthority(BROAD_CREDENTIAL) }, denyingFga);
      expect(decision.context.denial_reason).toBe("out_of_authority");
      expect(evidence.authority_bound).toBe("mission");
    });

    it("requires the action-bound approval a covering credential entry demands", async () => {
      const gated = withAuthority([entry([READ], { requires_action_approval: true })]);
      const digest = "sha-256:op-825";
      const { decision } = await decide(broadView(), { credential: gated, context: { parameter_digest: digest } });
      expect(decision.context.denial_reason).toBe("action_approval_required");
      await permitted(broadView(), {
        credential: gated,
        context: { parameter_digest: digest, action_approval: { id: "apr_825", approved_at: new Date().toISOString(), parameter_digest: digest } },
      });
      // A second covering entry that demands no approval covers the action.
      await permitted(broadView(), {
        credential: withAuthority([entry([READ], { requires_action_approval: true }), entry([READ])]),
        context: { parameter_digest: digest },
      });
    });

    it("enforces a credential entry's discharge condition through the Mission's current effective authority", async () => {
      const discharging = withAuthority([entry([READ], { terminal_when: [{ event_type: "invoice.paid" }] })]);
      await permitted(broadView(), { credential: discharging });
      const digest = computeAnchor(AUTHORITY_ENTRY_TYP, "https://as.test", MISSION_ENTRY as never);
      const discharged = broadView({ discharged: { entry_digests: [digest] } });
      const { decision } = await decide(discharged, { credential: discharging });
      expect(decision.context.denial_reason).toBe("authority_discharged");
    });
  },
);
