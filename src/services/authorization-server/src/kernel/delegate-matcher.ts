/**
 * @spec draft-mcguinness-oauth-mission#per-entry-enforcement (allowed_delegates)
 * @spec draft-mcguinness-oauth-mission-child-delegation#fanout (allowed_child_actors)
 *
 * The ONE shared actor-eligibility matcher for both delegation vocabularies:
 * the core's per-Authority-Set-entry `allowed_delegates` and the
 * child-delegation companion's `allowed_child_actors`. Both are lists of
 * {@link DelegateMatcher} objects modeled on the RFC 8693 `may_act` actor
 * object, and both drafts state the SAME matching rules; this module is their
 * single realization so the two vocabularies cannot drift apart.
 *
 * The rules, verbatim from the drafts:
 *
 *  - A `{ "sub": ... }` matcher permits a specific delegate by CLIENT IDENTIFIER
 *    (exact match against the candidate's `sub`, the delegate's client_id in the
 *    issuing AS's namespace, core draft "Matching allowed_delegates").
 *  - A `{ "sub_profile": ... }` matcher permits an actor CLASS: it is satisfied
 *    when its value is among the actor's space-separated `sub_profile` values
 *    (MEMBERSHIP, not raw string equality; both drafts). A matcher carrying
 *    several space-separated values is satisfied only when EVERY one is a member.
 *  - A SELF-ASSERTED `sub_profile` MUST NOT satisfy a matcher (core draft:
 *    "otherwise a client could claim any actor type to bypass the constraint").
 *    This module realizes that by matching `sub_profile` ONLY against the
 *    profile the AS itself asserts for the candidate ({@link
 *    DelegateCandidate.assertedProfile}) after authenticating / resolving the
 *    actor from a trusted source. A caller MUST NOT place a request-supplied
 *    (self-asserted) profile there; a candidate with no asserted profile can
 *    satisfy a `sub` matcher but never a `sub_profile` matcher.
 *  - An ABSENT matcher list is "a decision deferred to policy, never a blanket
 *    grant of eligibility" (core draft). The reference implementation's policy is
 *    FAIL-CLOSED: with no matcher list present it DENIES. A deployment MAY
 *    substitute a permissive delegation-authorization policy; that is a
 *    deployment choice, out of this module's scope, and does NOT change the
 *    normative drafts.
 *  - An EMPTY matcher (`{}`, carrying neither `sub` nor `sub_profile`) asserts no
 *    eligibility and therefore matches nothing: a malformed config entry must not
 *    silently become allow-all.
 */

import { parseSubProfile } from "@mission/actor-chain";
import type { DelegateMatcher } from "./types.js";

/** The actor being tested for delegation/child-creation eligibility. */
export interface DelegateCandidate {
  /**
   * The delegate's client identifier in the issuing AS's namespace (the target
   * of a `{ "sub": ... }` matcher). For a delegated token exchange this is the
   * authenticated client_id; for a Child Mission it is the child actor's `sub`
   * (which becomes the child's client_id).
   */
  sub: string;
  /**
   * The delegate's `sub_profile` tokens AS-ASSERTED by this AS (space-separated
   * string, e.g. `"ai_agent client_instance"`). ONLY this value is matched
   * against a `{ "sub_profile": ... }` matcher, never a request-supplied claim:
   * a self-asserted profile MUST NOT be passed here. Absent/empty means the AS
   * asserts no class for the candidate, so no `sub_profile` matcher is satisfied.
   */
  assertedProfile?: string;
}

/**
 * True iff `candidate` is permitted by `matchers` under the shared rules above.
 * A delegate is permitted if it matches ANY matcher (per-entry, OR across the
 * list); an absent/non-array list DENIES (fail-closed).
 */
export function delegatePermitted(
  candidate: DelegateCandidate,
  matchers: DelegateMatcher[] | undefined,
): boolean {
  // Absent matcher list => DENY. Deferred to policy, never a blanket grant; the
  // reference impl's policy is fail-closed.
  if (!Array.isArray(matchers)) return false;
  const asserted = new Set(parseSubProfile(candidate.assertedProfile));
  return matchers.some((m) => {
    if (m === null || typeof m !== "object" || Array.isArray(m)) return false;
    const hasSub = typeof m.sub === "string" && m.sub.length > 0;
    const hasProfile = typeof m.sub_profile === "string" && m.sub_profile.length > 0;
    // An empty matcher asserts no eligibility (never allow-all).
    if (!hasSub && !hasProfile) return false;
    // `sub`: exact match against the candidate's client identifier.
    if (hasSub && m.sub !== candidate.sub) return false;
    // `sub_profile`: MEMBERSHIP — every token the matcher names must be among the
    // candidate's AS-ASSERTED profile tokens. A self-asserted profile is never
    // placed in `assertedProfile`, so it can never satisfy this branch.
    if (hasProfile) {
      const wanted = parseSubProfile(m.sub_profile);
      if (wanted.length === 0) return false;
      if (!wanted.every((t) => asserted.has(t))) return false;
    }
    return true;
  });
}
