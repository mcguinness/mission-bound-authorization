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
});
