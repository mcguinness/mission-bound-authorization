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
 * GAP 2: freshness (step 3) fails closed when the Mission state
 * observation (`context.mission_state_observation`) is absent for a
 * high-consequence action class (irreversible_action,
 * external_commitment, privileged_administration), which @spec
 * runtime#state-freshness requires an active freshness mechanism for: "The
 * PDP MUST refuse a consequential action when it cannot establish, within
 * the deployment's published staleness bound, that the Mission is
 * `active`." Below that floor, token-lifetime expiry is itself a
 * conforming state source (@spec runtime#state-freshness, "Token-lifetime
 * freshness"), but under a declared placement the state input is still
 * REQUIRED (#1049 owner ruling), so an absent member denies at every class.
 *
 * GAP 3 (finding 2 of the follow-on author review): a PRESENT observation
 * was accepted on shape alone. `ageMs > bound` is the only check step 3 ran:
 * a malformed timestamp parses to NaN, and `NaN > bound` is false, so it
 * passed; a future-dated one yields a negative age, also never greater than
 * the bound, so it passed too; and nothing tied the observation to the
 * deployment's declared state source. Each of these means the PDP cannot
 * actually establish Mission state from the observation, so each now denies
 * the same way as present-but-stale (@spec runtime#state-freshness). The
 * trusted source is the enforcement scope's declared one (#1004): the PDP
 * relies on a PEP-supplied observation only where the declared state-source
 * placement is `pep` (@spec authzen#context-audience-freshness).
 *
 * GAP 4 (finding 3 of the follow-on author review): step 5's "no entry
 * matched" arm collapsed two different failure kinds into one
 * `out_of_authority`. draft-mcguinness-mission-authzen.md's normative
 * mapping table (@spec authzen#failure-condition-coverage) keeps them
 * separate: "Action outside the Authority Set" is `out_of_authority` (the
 * PDP understood the entry and it was insufficient); "Unsupported
 * `authorization_details` type" is `unsupported_authorization_type` (the
 * PDP could not evaluate the entry's semantics at all). An entry matching
 * this request's resource/actions under an unrecognized type is the
 * second kind, not the first; the two GAP 1 cases below that exercised this
 * exact shape are updated to the corrected classification.
 */

import { describe, expect, it } from "vitest";
import type { Fga } from "../src/fga.js";
import { evaluate, type EvaluationRequest } from "../src/evaluate.js";
import { MISSION_RESOURCE_ACCESS_TYPE, type AuthorityEntry, type MissionView } from "../src/policy-view.js";
import { relationForAction, stalenessBound } from "../src/policy.js";
import { freshKey, openTestClaims } from "./claim-fixture.js";
import { RESOURCE_POLICY_PERMITS_ALL_FIXTURE } from "@mission/pdp/test-support";

const RESOURCE = "http://localhost:4403/mcp";
const NOW = new Date("2026-07-22T12:00:00Z");

/** Always permits at the FGA layer, so only evaluate()'s own steps decide the outcome. */
const alwaysAllowFga = { checkWithContext: async () => true } as unknown as Fga;
const CLAIMS = openTestClaims({ now: () => NOW });

const opts = (v: MissionView) => ({
  view: v,
  fga: alwaysAllowFga,
  modelId: "unit-test-model",
  now: () => NOW,
  stalenessBound,
  relationForAction,
  resourcePolicy: RESOURCE_POLICY_PERMITS_ALL_FIXTURE,
  stateSourcePlacement: "pep" as const,
  // @spec runtime#idempotency (#917): every high-consequence permit is claimed;
  // a fixture domain that also mediates privileged administration.
  claims: CLAIMS,
});

const view = (entry: AuthorityEntry): MissionView => ({
  id: "msn_test_1",
  issuer: "https://as.test",
  state: "active",
  version: 1,
  authority_hash: "sha-256:testhash",
  authority_set: [entry],
  subject: { iss: "https://as.test", sub: "alice" },
  client_id: "ap-agent",
});

const req = (over: Partial<EvaluationRequest> = {}): EvaluationRequest => ({
  subject: { id: "alice" },
  resource: { type: "invoice", id: "inv-1", properties: { audience: RESOURCE, vendor_id: "acme" } },
  action: { name: "payments:invoice.read", properties: { idempotency_key: freshKey() } },
  context: {
    mission: { id: "msn_test_1", issuer: "https://as.test", authority_hash: "sha-256:testhash" },
    // REQUIRED under the declared pep placement (#1049 owner ruling).
    mission_state_observation: { state: "active", mode: "fresh", freshness_at: NOW.toISOString() },
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

    it("an entry of an unrecognized type, otherwise identical resource+actions -> deny unsupported_authorization_type (@spec authzen#failure-condition-coverage), never out_of_authority or permit", async () => {
      const dec = await evaluate(req(), opts(view(entryOfType("future_authorization_details_type"))));
      expect(dec.decision, JSON.stringify(dec.context)).toBe(false);
      expect(dec.context.denial_reason).toBe("unsupported_authorization_type");
    });

    it("an entry with the type member absent entirely -> deny unsupported_authorization_type, never a bare-undefined pass-through or out_of_authority", async () => {
      const bare = { resource: RESOURCE, actions: ["payments:invoice.read"] } as unknown as AuthorityEntry;
      const dec = await evaluate(req(), opts(view(bare)));
      expect(dec.decision).toBe(false);
      expect(dec.context.denial_reason).toBe("unsupported_authorization_type");
    });

    it("an unrecognized-type entry alongside a valid entry for the same resource+actions -> permit via the valid entry, never short-circuited by the unrecognized one", async () => {
      const mixedView: MissionView = {
        id: "msn_test_1",
        issuer: "https://as.test",
        state: "active",
        version: 1,
        authority_hash: "sha-256:testhash",
        authority_set: [entryOfType("future_authorization_details_type"), entryOfType(MISSION_RESOURCE_ACCESS_TYPE)],
        subject: { iss: "https://as.test", sub: "alice" },
        client_id: "ap-agent",
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

    it("every high-consequence action_class with context.mission_state_observation absent -> deny stale_state, Mission state cannot be established, never a bypass", async () => {
      for (const actionClass of HIGH_CONSEQUENCE_CLASSES) {
        const dec = await evaluate(
          req({
            context: {
              mission: { id: "msn_test_1", issuer: "https://as.test", authority_hash: "sha-256:testhash" },
              action_class: actionClass,
            },
          }),
          opts(view(entry)),
        );
        expect(dec.decision, actionClass).toBe(false);
        expect(dec.context.denial_reason, actionClass).toBe("stale_state");
      }
    });

    it("every high-consequence action_class with context.mission_state_observation present and fresh -> permit (the fix denies absence, not presence)", async () => {
      for (const actionClass of HIGH_CONSEQUENCE_CLASSES) {
        const dec = await evaluate(
          req({
            context: {
              mission: { id: "msn_test_1", issuer: "https://as.test", authority_hash: "sha-256:testhash" },
              action_class: actionClass,
              mission_state_observation: { state: "active", mode: "fresh", freshness_at: NOW.toISOString() },
            },
          }),
          opts(view(entry)),
        );
        expect(dec.decision, actionClass).toBe(true);
      }
    });

    it("every high-consequence action_class with context.mission_state_observation present but stale -> deny stale_state (the pre-existing arm, unchanged)", async () => {
      for (const actionClass of HIGH_CONSEQUENCE_CLASSES) {
        const dec = await evaluate(
          req({
            context: {
              mission: { id: "msn_test_1", issuer: "https://as.test", authority_hash: "sha-256:testhash" },
              action_class: actionClass,
              // an hour old: beyond every class's staleness bound (30s/60s/300s default)
              mission_state_observation: { state: "active", mode: "fresh", freshness_at: "2026-07-22T11:00:00Z" },
            },
          }),
          opts(view(entry)),
        );
        expect(dec.decision, actionClass).toBe(false);
        expect(dec.context.denial_reason, actionClass).toBe("stale_state");
      }
    });

    // #1049 owner ruling: under pep placement the observation is REQUIRED at
    // every class. Token-lifetime freshness may be a lower class's state
    // source, but it never excuses omitting the state input, so these two
    // cases, which asserted the old floor's permit, now deny.
    it("a non-high-consequence action_class with context.mission_state_observation absent under pep placement -> deny stale_state (the observation is REQUIRED; token-lifetime freshness does not excuse omitting it)", async () => {
      const dec = await evaluate(
        req({
          context: {
            mission: { id: "msn_test_1", issuer: "https://as.test", authority_hash: "sha-256:testhash" },
            action_class: "consequential_write",
          },
        }),
        opts(view(entry)),
      );
      expect(dec.decision, JSON.stringify(dec.context)).toBe(false);
      expect(dec.context.denial_reason).toBe("stale_state");
    });

    it("no action_class at all, context.mission_state_observation absent under pep placement -> deny stale_state (unclassified requests are not exempt)", async () => {
      const dec = await evaluate(
        req({ context: { mission: { id: "msn_test_1", issuer: "https://as.test", authority_hash: "sha-256:testhash" } } }),
        opts(view(entry)),
      );
      expect(dec.decision, JSON.stringify(dec.context)).toBe(false);
      expect(dec.context.denial_reason).toBe("stale_state");
    });
  });

  describe("GAP 3: malformed/future/untrusted freshness fails closed, never merely shape-checked (@spec runtime#state-freshness)", () => {
    const entry: AuthorityEntry = {
      type: MISSION_RESOURCE_ACCESS_TYPE,
      resource: RESOURCE,
      actions: ["payments:invoice.read", "payments:payment.execute", "payments:remittance.send"],
    };

    const HIGH_CONSEQUENCE_CLASSES = ["irreversible_action", "external_commitment", "privileged_administration"];

    const reqWith = (actionClass: string, freshnessAt: string) =>
      req({
        context: {
          mission: { id: "msn_test_1", issuer: "https://as.test", authority_hash: "sha-256:testhash" },
          action_class: actionClass,
          mission_state_observation: { state: "active", mode: "fresh", freshness_at: freshnessAt },
        },
      });

    it("the reported repro -- a non-parseable freshness_at -- denies stale_state, never permits, for every high-consequence class", async () => {
      for (const actionClass of HIGH_CONSEQUENCE_CLASSES) {
        const dec = await evaluate(reqWith(actionClass, "not-a-date"), opts(view(entry)));
        expect(dec.decision, actionClass).toBe(false);
        expect(dec.context.denial_reason, actionClass).toBe("stale_state");
      }
    });

    it("a future freshness_at beyond the skew tolerance denies stale_state, for every high-consequence class", async () => {
      // Bound-independent: even irreversible_action's tight 30s staleness
      // bound would forgive a small negative age; this is minutes ahead, far
      // past the default 5s skew tolerance, so only the new skew check
      // catches it.
      const future = new Date(NOW.getTime() + 5 * 60_000).toISOString();
      for (const actionClass of HIGH_CONSEQUENCE_CLASSES) {
        const dec = await evaluate(reqWith(actionClass, future), opts(view(entry)));
        expect(dec.decision, actionClass).toBe(false);
        expect(dec.context.denial_reason, actionClass).toBe("stale_state");
      }
    });

    it("a well-formed, fresh observation the deployment's declared state source does not place with the PEP denies stale_state, for every high-consequence class", async () => {
      // No declared placement, and a declared `pdp` placement with no read of
      // the PDP's own: either way the PEP-supplied observation is not the
      // trusted source, so it establishes nothing.
      for (const placement of [undefined, "pdp" as const]) {
        for (const actionClass of HIGH_CONSEQUENCE_CLASSES) {
          const dec = await evaluate(reqWith(actionClass, NOW.toISOString()), {
            ...opts(view(entry)),
            stateSourcePlacement: placement,
          });
          expect(dec.decision, `${placement} ${actionClass}`).toBe(false);
          expect(dec.context.denial_reason, `${placement} ${actionClass}`).toBe("stale_state");
        }
      }
    });

    it("a future freshness_at within the skew tolerance still permits (boundary control: the tolerance itself is not itself a denial)", async () => {
      // Exactly at the 5s default tolerance boundary, inclusive.
      const withinSkew = new Date(NOW.getTime() + 5_000).toISOString();
      const dec = await evaluate(
        reqWith("irreversible_action", withinSkew),
        opts(view(entry)),
      );
      expect(dec.decision, JSON.stringify(dec.context)).toBe(true);
    });
  });

  describe("GAP 4: unsupported_authorization_type is distinct from out_of_authority (@spec authzen#failure-condition-coverage)", () => {
    // Skip-not-shortcircuit (a mixed authority_set still permits via the
    // recognized entry, never denied by the unrecognized one) is already
    // proven above by GAP 1's unchanged mixed-authority_set case: that
    // outcome does not turn on which denial reason the unrecognized branch
    // would have produced.
    it("side by side: no entry at all for this resource/action denies out_of_authority; an unrecognized-type entry for the SAME resource/action instead denies unsupported_authorization_type", async () => {
      const recognizedElsewhere: AuthorityEntry = {
        type: MISSION_RESOURCE_ACCESS_TYPE,
        resource: RESOURCE,
        actions: ["payments:vendor.read"], // a different action: never matches this request
      };
      const noMatch = await evaluate(req(), opts(view(recognizedElsewhere)));
      expect(noMatch.decision).toBe(false);
      expect(noMatch.context.denial_reason).toBe("out_of_authority");

      const unrecognizedTypeEntry = {
        type: "future_authorization_details_type",
        resource: RESOURCE,
        actions: ["payments:invoice.read"],
      } as unknown as AuthorityEntry;
      const unrecognizedTypeMatch = await evaluate(req(), opts(view(unrecognizedTypeEntry)));
      expect(unrecognizedTypeMatch.decision).toBe(false);
      expect(unrecognizedTypeMatch.context.denial_reason).toBe("unsupported_authorization_type");
    });
  });
});
