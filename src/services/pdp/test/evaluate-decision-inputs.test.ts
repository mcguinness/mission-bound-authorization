/**
 * @spec runtime#input-actor (actor-context-required-and-not-shortcut)
 * @spec runtime#input-time (mission-expires-at-refusal)
 *
 * Unconditional (no live OpenFGA needed): every case supplies a stub `Fga`
 * satisfying only the one method `evaluate` calls, so this file never skips.
 * Wave 2 slice A, decision-inputs cluster.
 *
 * The first describe block below is NOT a Resource-policy test (see its own
 * comment): evaluate() has no Resource-policy input independent of Mission
 * authority, so it carries no `@spec runtime#input-resource-policy` citation
 * and is uncited in the conformance manifest.
 */

import { describe, expect, it } from "vitest";
import type { ContextActor } from "@mission/actor-chain";
import type { Fga } from "../src/fga.js";
import { evaluate, type EvaluationRequest, type MissionView, relationForAction, stalenessBoundSeconds } from "../src/index.js";

const RESOURCE = "http://localhost:4403/mcp";
const NOW = new Date("2026-07-22T12:00:00Z");

const view = (over: Partial<MissionView> = {}): MissionView => ({
  id: "msn_test_1",
  issuer: "https://as.test",
  state: "active",
  version: 1,
  authority_hash: "sha-256:testhash",
  authority_set: [
    {
      type: "mission_resource_access",
      resource: RESOURCE,
      actions: ["payments:invoice.read"],
    },
  ],
  subject: { iss: "https://as.test", sub: "alice" },
  client_id: "ap-agent",
  ...over,
});

const req = (over: Partial<EvaluationRequest> = {}): EvaluationRequest => ({
  subject: { id: "alice" },
  resource: { type: "invoice", id: "inv-1", properties: { vendor_id: "acme" } },
  action: { name: "payments:invoice.read" },
  context: {
    audience: RESOURCE,
    mission: { id: "msn_test_1", issuer: "https://as.test", authority_hash: "sha-256:testhash" },
  },
  ...over,
});

const optsWith = (fga: Fga, v: MissionView = view()) => ({
  view: v,
  fga,
  modelId: "unit-test-model",
  now: () => NOW,
  stalenessBoundSeconds,
  relationForAction,
});

describe("the FGA dependency call denying fails the action closed (not a Resource-policy test)", () => {
  it("authority and constraints permit, but the FGA check denies -> the action still fails closed", async () => {
    // NOT a Resource-policy test. The entry matches and there is no vendor
    // constraint to exclude the target, so the contextual tuple is derived
    // and step 6's fga.checkWithContext is reached and stubbed to deny. That
    // call IS the Mission-authority projection: policy-view.ts's
    // deriveContextualTuples grants `mission:<id>` the relation directly from
    // the matched Authority Set entry, and checkWithContext verifies that
    // ephemeral grant, so a denial here is Mission authority itself failing
    // closed on its own backing check, never an independent Resource policy
    // (@spec runtime#input-resource-policy) conjunct: no such conjunct
    // exists anywhere in this PDP. This is a dependency-fail-closed
    // regression test, left uncited in the conformance manifest.
    const denyingFga = { checkWithContext: async () => false } as unknown as Fga;
    const dec = await evaluate(req(), optsWith(denyingFga));
    expect(dec.decision, JSON.stringify(dec.context)).toBe(false);
    expect(dec.context.denial_reason).toBe("out_of_authority");
  });
});

describe("Actor context: a malformed act chain entry is refused (@spec runtime#input-actor)", () => {
  it("a context.actor.act entry missing iss (or sub) is refused as actor_invalid, never silently accepted", async () => {
    const malformedActor = {
      act: [{ sub: "agent-1" }] as unknown as ContextActor["act"],
    };
    const dec = await evaluate(
      req({ context: { audience: RESOURCE, mission: { id: "msn_test_1", issuer: "https://as.test", authority_hash: "sha-256:testhash" }, actor: malformedActor } }),
      optsWith({ checkWithContext: async () => true } as unknown as Fga),
    );
    expect(dec.decision).toBe(false);
    expect(dec.context.denial_reason).toBe("actor_invalid");
  });

  // Two arms of the row's observation are NOT asserted here, and stay
  // unaddressed by this test:
  // - "refuse a chain that is ... missing": evaluateInner only validates
  //   context.actor when the PEP supplies it at all (`if (req.context.actor)`,
  //   evaluate.ts step 4); whether the PEP correctly builds context.actor.act
  //   from a token's `act` claim whenever delegation is in fact in effect is a
  //   token-to-context construction duty of the PEP, outside evaluate()'s pure
  //   boundary.
  // - "client_id alone is never treated as the immediate actor when an act
  //   chain is present": this deployment's decision subject is the Mission
  //   itself (`mission:<id>` in the FGA check), never the actor/client_id, so
  //   there is no code path in evaluate() that could substitute client_id for
  //   an actor in the first place to test against.
});

describe("Time input: a Mission state source reporting the Mission expired refuses (@spec runtime#input-time)", () => {
  it("a Mission state of expired refuses the action; evaluate() has no token-exp input to depend on in the first place", async () => {
    // EvaluationRequest carries no token-expiry field at all (see evaluate.ts's
    // context type), so this outcome cannot be reached through a token exp
    // check; it is the Mission active-state gate (step 2) firing on the
    // deployment's own state-source report, independent by construction.
    const dec = await evaluate(req(), optsWith({ checkWithContext: async () => true } as unknown as Fga, view({ state: "expired" })));
    expect(dec.decision).toBe(false);
    expect(dec.context.denial_reason).toBe("mission_inactive");
  });

  // The other disjunct of the row ("a Mission state source ... does expose
  // [expires_at]") has no representation at all: MissionView carries no
  // expires_at member, and evaluateInner never reads one. See the manifest
  // note; this stays the honest remainder for this row.
});
