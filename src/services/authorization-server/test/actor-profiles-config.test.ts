/**
 * The shipped AS-asserted actor-type registry (config/actor-profiles.json, loaded
 * as @mission/demo-data ACTOR_PROFILES). This is load-bearing: the child-delegation
 * endpoint suite relies on the shipped assertions for `subagent-extractor` and
 * `subagent-invoice-extractor` (it injects only its OTHER child actors), so a
 * `{ sub_profile: "ai_agent" }` matcher admits them. This test pins that the
 * config file loads and asserts those subs, so the reliance is intentional and the
 * loader (demo-data loadActorProfiles) is exercised on the happy path.
 */

import { parseSubProfile } from "@mission/actor-chain";
import { ACTOR_PROFILES } from "@mission/demo-data";
import { describe, expect, it } from "vitest";

describe("config/actor-profiles.json — the AS-asserted actor registry", () => {
  it("loads and asserts the reference deployment's demo sub-agents as ai_agent", () => {
    expect(parseSubProfile(ACTOR_PROFILES["subagent-invoice-extractor"])).toContain("ai_agent");
    expect(parseSubProfile(ACTOR_PROFILES["subagent-extractor"])).toContain("ai_agent");
  });

  it("asserts no class for an unregistered actor (self-asserted-safe: matcher denies it)", () => {
    expect(ACTOR_PROFILES["human-user"]).toBeUndefined();
    expect(parseSubProfile(ACTOR_PROFILES["not-registered"])).toEqual([]);
  });
});
