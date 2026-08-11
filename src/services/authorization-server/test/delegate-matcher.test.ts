/**
 * The shared actor-eligibility matcher (@spec oauth-mission#per-entry-enforcement
 * `allowed_delegates`; @spec child-delegation#fanout `allowed_child_actors`).
 * One helper, one set of conformance rules, exercised directly: `sub` exact,
 * `sub_profile` MEMBERSHIP against the AS-ASSERTED profile only, self-asserted
 * profiles denied, absent list fail-closed, empty matcher never allow-all.
 */

import { describe, expect, it } from "vitest";
import { type DelegateCandidate, delegatePermitted } from "../src/index.js";
import type { DelegateMatcher } from "../src/kernel/types.js";

const agent: DelegateCandidate = { sub: "subagent-1", assertedProfile: "ai_agent client_instance" };

describe("delegatePermitted — absent list is fail-closed (never a blanket grant)", () => {
  it("DENIES when the matcher list is absent (undefined)", () => {
    // Core draft 2964-2968: an absent matcher list is deferred to policy, never a
    // blanket grant; the reference impl's policy is fail-closed.
    expect(delegatePermitted(agent, undefined)).toBe(false);
  });

  it("DENIES when the matcher list is not an array", () => {
    expect(delegatePermitted(agent, "ai_agent" as unknown as DelegateMatcher[])).toBe(false);
  });

  it("DENIES on an empty (present but zero-entry) list", () => {
    expect(delegatePermitted(agent, [])).toBe(false);
  });
});

describe("delegatePermitted — sub_profile MEMBERSHIP against the ASSERTED profile", () => {
  it("matches when the matcher value is AMONG the actor's space-separated asserted values", () => {
    expect(delegatePermitted(agent, [{ sub_profile: "ai_agent" }])).toBe(true);
    expect(delegatePermitted(agent, [{ sub_profile: "client_instance" }])).toBe(true);
  });

  it("does NOT match a class the actor is not asserted to be (raw non-membership denied)", () => {
    expect(delegatePermitted(agent, [{ sub_profile: "human" }])).toBe(false);
    // Not raw string equality against the full "ai_agent client_instance" value.
    expect(delegatePermitted({ sub: "x", assertedProfile: "ai_agent" }, [{ sub_profile: "ai" }])).toBe(false);
  });

  it("requires EVERY token of a multi-token matcher to be a member", () => {
    expect(delegatePermitted(agent, [{ sub_profile: "ai_agent client_instance" }])).toBe(true);
    expect(delegatePermitted(agent, [{ sub_profile: "ai_agent human" }])).toBe(false);
  });
});

describe("delegatePermitted — a SELF-ASSERTED sub_profile MUST NOT satisfy a matcher", () => {
  it("DENIES a sub_profile matcher when the candidate carries NO asserted profile", () => {
    // The candidate's class was not asserted by the AS (e.g. a request-supplied
    // claim was correctly withheld from assertedProfile). It must not match.
    expect(delegatePermitted({ sub: "subagent-1" }, [{ sub_profile: "ai_agent" }])).toBe(false);
    expect(delegatePermitted({ sub: "subagent-1", assertedProfile: "" }, [{ sub_profile: "ai_agent" }])).toBe(
      false,
    );
  });

  it("still permits by a `sub` matcher (sub is authenticated, not a self-asserted class)", () => {
    expect(delegatePermitted({ sub: "subagent-1" }, [{ sub: "subagent-1" }])).toBe(true);
  });
});

describe("delegatePermitted — sub exact match", () => {
  it("matches an exact sub and rejects a different sub", () => {
    expect(delegatePermitted(agent, [{ sub: "subagent-1" }])).toBe(true);
    expect(delegatePermitted(agent, [{ sub: "subagent-2" }])).toBe(false);
  });

  it("requires BOTH fields when a matcher carries sub AND sub_profile", () => {
    expect(delegatePermitted(agent, [{ sub: "subagent-1", sub_profile: "ai_agent" }])).toBe(true);
    // right class, wrong sub
    expect(delegatePermitted(agent, [{ sub: "subagent-2", sub_profile: "ai_agent" }])).toBe(false);
    // right sub, class not asserted
    expect(delegatePermitted(agent, [{ sub: "subagent-1", sub_profile: "human" }])).toBe(false);
  });

  it("permits if ANY matcher in the list matches", () => {
    expect(delegatePermitted(agent, [{ sub: "other" }, { sub_profile: "ai_agent" }])).toBe(true);
  });
});

describe("delegatePermitted — an EMPTY matcher asserts no eligibility (never allow-all)", () => {
  it("does NOT match on an empty matcher object", () => {
    expect(delegatePermitted(agent, [{}])).toBe(false);
    expect(delegatePermitted({ sub: "anyone" }, [{}])).toBe(false);
  });

  it("does NOT let a malformed empty matcher fail the whole list open", () => {
    // {} contributes nothing; only the real matcher decides.
    expect(delegatePermitted(agent, [{}, { sub: "subagent-1" }])).toBe(true);
    expect(delegatePermitted(agent, [{}, { sub: "nobody" }])).toBe(false);
  });
});
