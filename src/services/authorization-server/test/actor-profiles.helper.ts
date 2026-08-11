/**
 * Test support (NOT a spec file): build an AS-asserted actor-type registry.
 *
 * Under the shared actor-eligibility matcher (@spec
 * oauth-mission#per-entry-enforcement / child-delegation#fanout) a
 * `{ "sub_profile": ... }` matcher is satisfied ONLY against the profile the AS
 * asserts for an actor's `sub` (never a request-supplied claim), and an actor
 * with no asserted class is denied by such a matcher. These suites create
 * children / delegates whose subs are test fixtures, not the reference
 * deployment's shipped agents, so each suite declares its OWN asserted registry
 * and passes it as `actorProfiles` to the kernel / AS. A sub NOT listed here is
 * correctly (self-asserted-safe) denied.
 */

/** Assert every given actor `sub` as the `ai_agent` class. */
export function aiAgents(...subs: string[]): Record<string, string> {
  return Object.fromEntries(subs.map((s) => [s, "ai_agent"]));
}
