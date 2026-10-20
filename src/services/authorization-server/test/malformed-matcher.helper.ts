/**
 * @spec resource-access#matching-allowed-delegates, child-delegation#fanout
 * (#1373): the shared cases of the requested-authority exchange witnesses (the
 * deferred initiation, the dispatch handoff and the async-delegation
 * exchange). The reproduction is a delegate matcher carrying a member other
 * than `sub` and `sub_profile`. Each requested `delegation` stays within the
 * demo policy's delegation grant (`max_depth` 2, `ai_agent` delegates and
 * child actors, five children of depth 2), so the same request with a
 * well-formed matcher is admitted, and only the matcher check refuses the
 * reproduction. Without that check the exchange would issue the matcher
 * rebuilt without `org`, or carrying it unread.
 */
export const MATCHER_REPRODUCTION: Readonly<Record<string, string>> = { sub_profile: "ai_agent", org: "A" };
export const WELL_FORMED_MATCHER: Readonly<Record<string, string>> = { sub_profile: "ai_agent" };

export type MatcherList = "allowed_delegates" | "allowed_child_actors";

/** Each matcher list, with the violation an exchange names for the reproduction in it. */
export const MATCHER_LIST_CASES: ReadonlyArray<readonly [MatcherList, string]> = [
  ["allowed_delegates", "delegation.allowed_delegates entries carry no member 'org'"],
  ["allowed_child_actors", "delegation.children.allowed_child_actors entries carry no member 'org'"],
];

/** A requested `delegation` whose `list` holds `matcher` as its only matcher. */
export function delegationWithMatcher(
  matcher: Readonly<Record<string, string>>,
  list: MatcherList,
): Record<string, unknown> {
  return list === "allowed_delegates"
    ? { max_depth: 1, allowed_delegates: [matcher] }
    : {
        max_depth: 1,
        allowed_delegates: [WELL_FORMED_MATCHER],
        children: { max_children: 5, max_child_depth: 2, allowed_child_actors: [matcher] },
      };
}
