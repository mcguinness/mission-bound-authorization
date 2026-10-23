/**
 * @spec resource-access (#1258, D452): the capability vocabulary of the Mission
 * Resource Access expected-outcome cases (`vectors/mission-resource-access/README.md`)
 * and the capabilities this reference implementation implements. Shared by the case
 * reader and the supported-subset fixture test (#249, D676), so both read one set.
 */

/**
 * The deployment capability configuration: what this reference implementation implements.
 *
 * `operation-target` and `resource-match.exact` (#1276, D457): the payments PEP and the
 * SaaS resource establish each operation's target from an explicit service-level
 * operation contract and refuse a missing, unsupported or ambiguous one; the PDP, the
 * payments PEP and the SaaS resource match entries against that target with the one
 * Resource Access matcher in `@mission/core`. The case reader's executors run that same
 * matcher and contract evaluation (helper level).
 *
 * `resource-match.prefix` (#1276): that matcher also enforces `prefix` entries, and the
 * authorization server's subset test (`isSubsetEntry`), PAR intake and derivation compare
 * them with the same prefix comparison, so the unsupported-prefix refusals (der-03, der-04)
 * no longer apply.
 */
export const IMPLEMENTED: ReadonlySet<string> = new Set([
  "subset.exact-resource",
  "constraint.max_amount",
  "constraint.requires_action_approval",
  "constraint.resource_issued_after",
  "constraint.resource_issued_before",
  "constraint.tenant",
  "constraint.time_window",
  "constraint.recipient_domain",
  "constraint.data_classification",
  "constraint.allowed_tools",
  "refusal.unsupported-input",
  "refusal.locations",
  "delegate-matcher",
  "operation-target",
  "resource-match.exact",
  "resource-match.prefix",
  // #1275 (D457): retained eligibility provenance and the delegation-authorization policy hook.
  "delegation.policy",
  "delegation.inherited-eligibility",
  // #249 (D553, D605): the `resource_contract` member, admitted with its shape and
  // preserved exactly by subset step 4. No case requires it yet; #819 adds them (D676).
  "member.resource_contract",
]);

/** The declared capability vocabulary (README.md). */
export const KNOWN_CAPABILITIES: ReadonlySet<string> = new Set([
  ...IMPLEMENTED,
  "resource-match.prefix",
  "action-families",
  "constraint.resource_issued_after",
  "constraint.resource_issued_before",
  "constraint.tenant",
  "constraint.recipient_domain",
  "constraint.time_window",
  "constraint.data_classification",
  "constraint.allowed_tools",
  "rs.enforcement",
  "rs.alternative-grants",
  "rs.member-roles",
  "rs.extension-members",
  "delegation.policy",
  "delegation.inherited-eligibility",
  "transformation-capabilities",
  "scope-projection",
]);

/** The checks the case reader has an executor for; a case with any other check is skipped. */
export const EXECUTABLE_CHECKS: ReadonlySet<string> = new Set([
  "subset",
  "derive",
  "delegate-matcher",
  "delegate-eligibility",
  "resource-match",
  "target-resolution",
  "entry-validation",
]);

/** A capability is known when the README names it, or it is one `constraints` key or entry member. */
export const knownCapability = (cap: string) =>
  KNOWN_CAPABILITIES.has(cap) || /^(constraint|member)\.[a-z0-9_]+$/.test(cap);
