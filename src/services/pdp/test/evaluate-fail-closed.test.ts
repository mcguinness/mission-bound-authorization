/**
 * Fail-closed gaps in evaluateInner (#608), each proven with an
 * unconditional stub-FGA fixture: `fga` satisfies only the one method
 * evaluate() calls and always permits, so nothing here depends on a live
 * OpenFGA / docker compose, and this file never skips.
 *
 * GAP 1: the authority-entry match (step 5) recognizes entry.type as a
 * whitelist. An entry of any type other than mission_resource_access MUST
 * NOT match by resource/actions alone (@spec runtime#input-authority: "For
 * any other `authorization_details` type, the PDP MUST evaluate the action
 * under that type's documented runtime semantics and MUST refuse if it
 * does not understand or cannot enforce those semantics").
 *
 * GAP 2: freshness (step 3) fails closed when context.freshness is absent
 * for a high-consequence action class (irreversible_action,
 * external_commitment, privileged_administration), which @spec
 * runtime#state-freshness requires an active freshness mechanism for: "The
 * PDP MUST refuse a consequential action when it cannot establish, within
 * the deployment's published staleness bound, that the Mission is
 * `active`." Below that floor, token-lifetime expiry is itself a
 * conforming state source (@spec runtime#state-freshness, "Token-lifetime
 * freshness"), so an absent member there stays a permit.
 *
 * GAP 3 (finding 2 of the follow-on author review): a PRESENT
 * context.freshness was accepted on shape alone. `ageMs > bound` is the
 * only check step 3 ran: a malformed `observed_at` parses to NaN, and
 * `NaN > bound` is false, so it passed; a future-dated `observed_at` yields
 * a negative age, also never greater than the bound, so it passed too;
 * `source` was never checked against anything. Each of these means the PDP
 * cannot actually establish Mission state from the observation, so each now
 * denies the same way as present-but-stale (@spec runtime#state-freshness).
 */

import { describe, expect, it } from "vitest";
import type { Fga } from "../src/fga.js";
import { evaluate, type EvaluationRequest } from "../src/evaluate.js";
import { MISSION_RESOURCE_ACCESS_TYPE, type AuthorityEntry, type MissionView } from "../src/policy-view.js";
import { relationForAction, stalenessBoundSeconds } from "../src/policy.js";

const RESOURCE = "http://localhost:4403/mcp";
const NOW = new Date("2026-07-22T12:00:00Z");

/** Always permits at the FGA layer, so only evaluate()'s own steps decide the outcome. */
const alwaysAllowFga = { checkWithContext: async () => true } as unknown as Fga;

const opts = (v: MissionView) => ({
  view: v,
  fga: alwaysAllowFga,
  modelId: "unit-test-model",
  now: () => NOW,
  stalenessBoundSeconds,
  relationForAction,
  allowedFreshnessSources: new Set(["status"]),
});

const view = (entry: AuthorityEntry): MissionView => ({
  id: "msn_test_1",
  issuer: "https://as.test",
  state: "active",
  version: 1,
  authority_hash: "sha-256:testhash",
  authority_set: [entry],
});

const req = (over: Partial<EvaluationRequest> = {}): EvaluationRequest => ({
  subject: { id: "alice" },
  resource: { type: "invoice", id: "inv-1", properties: { vendor_id: "acme" } },
  action: { name: "payments:invoice.read" },
  context: {
    audience: RESOURCE,
    mission: { id: "msn_test_1", authority_hash: "sha-256:testhash" },
  },
  ...over,
});

describe("evaluateInner fail-closed gaps (#608)", () => {
  describe("GAP 1: authority-entry type recognition is a whitelist (@spec runtime#input-authority)", () => {
    // Bypasses the type system on purpose, the same way as the kernel test the
    // manifest cites for the analogous mission_not_active whitelist: a value
    // outside the recognized literal, written directly onto the fixture to
    // simulate a deserialization change or a new type admitted upstream.
    const entryOfType = (type: string): AuthorityEntry =>
      ({
        type,
        resource: RESOURCE,
        actions: ["payments:invoice.read"],
      }) as unknown as AuthorityEntry;

    it("an entry of the recognized type, matched on resource+actions -> permit (positive control)", async () => {
      const dec = await evaluate(req(), opts(view(entryOfType(MISSION_RESOURCE_ACCESS_TYPE))));
      expect(dec.decision, JSON.stringify(dec.context)).toBe(true);
    });

    it("an entry of an unrecognized type, otherwise identical resource+actions -> deny out_of_authority, never permit", async () => {
      const dec = await evaluate(req(), opts(view(entryOfType("future_authorization_details_type"))));
      expect(dec.decision, JSON.stringify(dec.context)).toBe(false);
      expect(dec.context.denial_reason).toBe("out_of_authority");
    });

    it("an entry with the type member absent entirely -> deny out_of_authority, never a bare-undefined pass-through", async () => {
      const bare = { resource: RESOURCE, actions: ["payments:invoice.read"] } as unknown as AuthorityEntry;
      const dec = await evaluate(req(), opts(view(bare)));
      expect(dec.decision).toBe(false);
      expect(dec.context.denial_reason).toBe("out_of_authority");
    });

    it("an unrecognized-type entry alongside a valid entry for the same resource+actions -> permit via the valid entry, never short-circuited by the unrecognized one", async () => {
      const mixedView: MissionView = {
        id: "msn_test_1",
        issuer: "https://as.test",
        state: "active",
        version: 1,
        authority_hash: "sha-256:testhash",
        authority_set: [entryOfType("future_authorization_details_type"), entryOfType(MISSION_RESOURCE_ACCESS_TYPE)],
      };
      const dec = await evaluate(req(), opts(mixedView));
      expect(dec.decision, JSON.stringify(dec.context)).toBe(true);
    });
  });

  describe("GAP 2: freshness absence fails closed for high-consequence classes (@spec runtime#state-freshness)", () => {
    const entry: AuthorityEntry = {
      type: MISSION_RESOURCE_ACCESS_TYPE,
      resource: RESOURCE,
      actions: ["payments:invoice.read", "payments:payment.execute", "payments:remittance.send"],
    };

    const HIGH_CONSEQUENCE_CLASSES = ["irreversible_action", "external_commitment", "privileged_administration"];

    it("every high-consequence action_class with context.freshness absent -> deny stale_state, Mission state cannot be established, never a bypass", async () => {
      for (const actionClass of HIGH_CONSEQUENCE_CLASSES) {
        const dec = await evaluate(
          req({
            context: {
              audience: RESOURCE,
              mission: { id: "msn_test_1", authority_hash: "sha-256:testhash" },
              action_class: actionClass,
            },
          }),
          opts(view(entry)),
        );
        expect(dec.decision, actionClass).toBe(false);
        expect(dec.context.denial_reason, actionClass).toBe("stale_state");
      }
    });

    it("every high-consequence action_class with context.freshness present and fresh -> permit (the fix denies absence, not presence)", async () => {
      for (const actionClass of HIGH_CONSEQUENCE_CLASSES) {
        const dec = await evaluate(
          req({
            context: {
              audience: RESOURCE,
              mission: { id: "msn_test_1", authority_hash: "sha-256:testhash" },
              action_class: actionClass,
              freshness: { observed_at: NOW.toISOString(), source: "status" },
            },
          }),
          opts(view(entry)),
        );
        expect(dec.decision, actionClass).toBe(true);
      }
    });

    it("every high-consequence action_class with context.freshness present but stale -> deny stale_state (the pre-existing arm, unchanged)", async () => {
      for (const actionClass of HIGH_CONSEQUENCE_CLASSES) {
        const dec = await evaluate(
          req({
            context: {
              audience: RESOURCE,
              mission: { id: "msn_test_1", authority_hash: "sha-256:testhash" },
              action_class: actionClass,
              // an hour old: beyond every class's staleness bound (30s/60s/300s default)
              freshness: { observed_at: "2026-07-22T11:00:00Z", source: "status" },
            },
          }),
          opts(view(entry)),
        );
        expect(dec.decision, actionClass).toBe(false);
        expect(dec.context.denial_reason, actionClass).toBe("stale_state");
      }
    });

    it("a non-high-consequence action_class with context.freshness absent -> permit (token-lifetime freshness suffices below the floor)", async () => {
      const dec = await evaluate(
        req({
          context: {
            audience: RESOURCE,
            mission: { id: "msn_test_1", authority_hash: "sha-256:testhash" },
            action_class: "consequential_write",
          },
        }),
        opts(view(entry)),
      );
      expect(dec.decision, JSON.stringify(dec.context)).toBe(true);
    });

    it("no action_class at all, context.freshness absent -> permit (unclassified requests are unaffected)", async () => {
      const dec = await evaluate(req(), opts(view(entry)));
      expect(dec.decision, JSON.stringify(dec.context)).toBe(true);
    });
  });

  describe("GAP 3: malformed/future/untrusted freshness fails closed, never merely shape-checked (@spec runtime#state-freshness)", () => {
    const entry: AuthorityEntry = {
      type: MISSION_RESOURCE_ACCESS_TYPE,
      resource: RESOURCE,
      actions: ["payments:invoice.read", "payments:payment.execute", "payments:remittance.send"],
    };

    const HIGH_CONSEQUENCE_CLASSES = ["irreversible_action", "external_commitment", "privileged_administration"];

    const reqWith = (actionClass: string, freshness: { observed_at: string; source: string }) =>
      req({
        context: {
          audience: RESOURCE,
          mission: { id: "msn_test_1", authority_hash: "sha-256:testhash" },
          action_class: actionClass,
          freshness,
        },
      });

    it("the reported repro -- a non-parseable observed_at with an unrecognized source -- denies stale_state, never permits, for every high-consequence class", async () => {
      for (const actionClass of HIGH_CONSEQUENCE_CLASSES) {
        const dec = await evaluate(
          reqWith(actionClass, { observed_at: "not-a-date", source: "bogus" }),
          opts(view(entry)),
        );
        expect(dec.decision, actionClass).toBe(false);
        expect(dec.context.denial_reason, actionClass).toBe("stale_state");
      }
    });

    it("a future observed_at beyond the skew tolerance denies stale_state, for every high-consequence class", async () => {
      // Bound-independent: even irreversible_action's tight 30s staleness
      // bound would forgive a small negative age; this is minutes ahead, far
      // past the default 5s skew tolerance, so only the new skew check
      // catches it.
      const future = new Date(NOW.getTime() + 5 * 60_000).toISOString();
      for (const actionClass of HIGH_CONSEQUENCE_CLASSES) {
        const dec = await evaluate(reqWith(actionClass, { observed_at: future, source: "status" }), opts(view(entry)));
        expect(dec.decision, actionClass).toBe(false);
        expect(dec.context.denial_reason, actionClass).toBe("stale_state");
      }
    });

    it("a well-formed, fresh observation from a source outside the deployment's allowed set denies stale_state, for every high-consequence class", async () => {
      for (const actionClass of HIGH_CONSEQUENCE_CLASSES) {
        const dec = await evaluate(
          reqWith(actionClass, { observed_at: NOW.toISOString(), source: "unrecognized_source" }),
          opts(view(entry)),
        );
        expect(dec.decision, actionClass).toBe(false);
        expect(dec.context.denial_reason, actionClass).toBe("stale_state");
      }
    });

    it("a future observed_at within the skew tolerance still permits (boundary control: the tolerance itself is not itself a denial)", async () => {
      // Exactly at the 5s default tolerance boundary, inclusive.
      const withinSkew = new Date(NOW.getTime() + 5_000).toISOString();
      const dec = await evaluate(
        reqWith("irreversible_action", { observed_at: withinSkew, source: "status" }),
        opts(view(entry)),
      );
      expect(dec.decision, JSON.stringify(dec.context)).toBe(true);
    });
  });
});
