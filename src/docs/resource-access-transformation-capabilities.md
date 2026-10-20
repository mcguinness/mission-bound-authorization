# Resource Access transformation capabilities

The reference Authorization Server's inventory of every rule a `narrowing`,
`delegation` or `projection` declaration for `mission_resource_access` would
claim (#1377, Sketch step 1). Resource Access names deployment documentation
as a declaration carrier (§ Transformation Capabilities,
`{#transformation-capabilities}`). **This note is not a declaration.** It
declares no transformation capability for the type and leaves all three
undeclared. It is not the interoperable supported-subset profile either: D414
reserves that profile and its vectors for #819, after #249.

Every statement here is true of the reference implementation at `405f153c`
(paths relative to `src/`). Each rule names the code that applies or refuses
it and the test (`it` title, in the named file) or case
(`vectors/mission-resource-access/`) that witnesses it. Test files are under
`services/authorization-server/test/` unless a path says otherwise; cases run
through `resource-access-cases.test.ts`. A rule with no witness says so.

Status values:

- **implemented**: the reference applies the rule.
- **refused**: the reference refuses the input as unsupported before
  approval or issuance.
- **not implemented**: the reference neither applies the rule nor refuses the
  input.

## 1. What is declared, and why

No carrier declares a capability for the type:

- The `mission_resource_access` entry of `AUTHORIZATION_DETAILS_TYPES_METADATA`
  (`services/authorization-server/src/kernel/authorization-details-metadata.ts`),
  served at the `authorization_details_types_metadata_endpoint`, carries no
  `mission_transformation_capabilities` member.
- Its `documentation_uri` names this repository, whose documentation, this
  note included, declares none.

The reference nonetheless narrows entries of this type (derivation, Token
Exchange, and refresh and code-exchange requests), delegates them (the
delegated exchange's eligibility gate), and projects them to `scope`
(`projectScope` on every Mission-bound mint). The OAuth binding states: "The
AS MUST NOT narrow, delegate, or project to `scope` an entry of a type for
which it has not declared the corresponding capability; on an undeclared
capability the entry is carried as approved." Ledger rows
`core.other-types.transformation-boundary-declared` and the four
`resource-access.transformation-capabilities.*` rows are `todo`.

Why nothing is declared:

- **`narrowing`** claims the subset rule "over every member this document
  specifies" and the Common Constraint intersection rules. The reference
  refuses `prefix` and compares action families as literal strings (§2.1), and
  compares delegate matchers structurally (§2.4), so it does not implement the
  whole relation. D444: "refusing unsupported input
  does not establish the `narrowing` capability". The nine Common Constraint
  comparisons (§2.2) are necessary evidence, not the whole claim.
- **`delegation`** is inventoried in §3; #1377 audits its declaration
  separately. A `delegation` declaration without `narrowing` would also not
  describe the reference: the OAuth binding then permits a delegated entry
  only when it is equal to a presented one, and the reference narrows
  delegated entries (§2.4).
- **`projection`** is applied conservatively (§4) and needs its own
  evidence (§6).

## 2. `narrowing`

### 2.1 Resource and actions

Resource Access § Subset Rule, steps 1 and 2.

| Rule | Status | Code | Witness |
|---|---|---|---|
| `exact` A under `exact` B: literal equality | implemented | `isSubsetEntry` (`packages/mission-core/src/authority-subset.ts`); derivation pairs entries by equal `resource` (`deriveAuthoritySetWithProvenance`, `services/authorization-server/src/kernel/derive.ts`) | cases sub-res-01, sub-res-02, sub-res-03 |
| `exact` A under `prefix` B; `prefix` A under `prefix` B; `prefix` A under `exact` B | refused: any `resource_match` other than `exact` | `validateMissionResourceAccessSchema` (intake); `assertExactResourceMatch` (`derive.ts`); `rejectUnsupportedResourceMatch` (`packages/demo-data/src/index.ts`) | `rar-carriage.test.ts` "refuses a proposal entry naming resource_match prefix before any interaction, creating no Mission"; `resource-match-unsupported.test.ts` "refuses a ceiling entry naming resource_match prefix" and "parseCeilingEntry (policy.json) rejects a ceiling entry naming resource_match prefix"; cases der-03, der-04. Cases sub-res-04 to sub-res-08 skip (`resource-match.prefix`). |
| The authorization server compares with the resource server's matcher | implemented for `exact`: both compare the decoded strings literally (`matchResource`, `packages/mission-core/src/operation-target.ts`) | as above | none; row `resource-access.subset.same-matcher` is `todo` |
| An action is within an equal action | implemented: literal membership | `isSubsetEntry`; `intersect` and `intersectForProjection` (`derive.ts`) | `token-request-rar-narrowing.test.ts` "an action outside the grant is refused invalid_authorization_details, saving no refresh token, and the same token still refreshes" |
| A literal action within a family; a family within a family | not implemented: a family value is admitted as an opaque string (intake checks only for a non-empty array of strings) and compared literally, so `invoices.read` is not within `invoices.*` | as above | none; case sub-act-01 skips (`action-families`) |
| A family is never within a literal action | implemented, as a consequence of literal comparison | as above | none |

No enforcement point expands a family. The decision point, the payments
resource and the SaaS resource match an operation's action by literal
membership (`services/pdp/src/evaluate.ts`, `services/mcp-payments/src/pep.ts`,
`services/mcp-saas/src/index.ts`), so a family value never authorizes more
than its literal spelling.

### 2.2 Common Constraints

Resource Access § Subset Rule step 3, § Initial Common Constraints and
§ Value-Space Comparison. All nine are implemented for both rules. Seven take
their semantics from one table (`SEMANTICS`, read by
`commonConstraintsNoBroader` and `intersectCommonConstraints`,
`packages/mission-core/src/common-constraints.ts`); `max_amount` and
`requires_action_approval` are compared in `isSubsetEntry` and intersected in
`intersect` and `intersectForProjection`. Each key's cases
(`constraints.json`, `cc-<key>-*`) run. Tests named below without a file are
in `common-constraints-endpoint.test.ts`.

| Key | Subset witness | Intersection witness |
|---|---|---|
| `max_amount` | `derivation-delegation.test.ts` "a candidate 1 unit above the granted cap is NOT a subset, even though both amounts round to the same double" | `rar-carriage.test.ts` "refuses a proposal whose max_amount currency differs from the ceiling's, creating no Mission"; the smaller amount only at helper level: case der-02, `effective-set-projection.test.ts` "intersects max_amount to the SMALLER value: a candidate capped at 1000 through a survivor capped at 100 yields 100" |
| `requires_action_approval` | cases sub-ra-01, sub-ra-02 | helper level only: case der-08, `effective-set-projection.test.ts` "ORs requires_action_approval: true on either side rides through" |
| `resource_issued_after`, `resource_issued_before` | "a Token Exchange that drops or widens a bound is refused invalid_authorization_details" | "the approval derives the intersection and the code-exchanged access token carries it"; "a proposal whose window cannot meet the ceiling's is refused at the approval decision, creating no Mission" |
| `tenant` | "a Token Exchange that drops the tenant or names another is refused invalid_authorization_details" | "a proposal naming another tenant is refused at the approval decision, creating no Mission" |
| `recipient_domain` | "a Token Exchange compares domains on whole labels, case-insensitively: a parent or sibling is refused" | "a proposal naming a subdomain derives it, and refresh and introspection carry it" |
| `time_window` | "a Token Exchange that drops a window bound or extends it is refused; one that narrows it is issued" | "a proposal narrowing the window derives the overlap, and refresh and introspection carry it" |
| `data_classification` | "a Token Exchange that adds a label or drops the bound is refused; one naming fewer labels is issued" | "a proposal naming some of the ceiling's labels derives the common labels, and refresh and introspection carry them" |
| `allowed_tools` | "a Token Exchange that adds a tool or drops the bound is refused; one naming fewer tools is issued" | "a proposal naming some of the ceiling's tools derives the common tools, and refresh and introspection carry them" |

The value-space comparisons are witnessed by the `resource-access.value-space.*`
rows and, for decimal amounts, by `compareAmounts`'s tests
(`packages/mission-core/test/decimal-amount.test.ts`).

### 2.3 Other keys and members

| Rule | Status | Code | Witness |
|---|---|---|---|
| `vendors` (deployment-defined) and `terminal_when` (Discharge), compared by their own rules | implemented | `isSubsetEntry`, `intersect`, `intersectForProjection` | `packages/mission-core/test/authority-subset.test.ts` "never drops vendor, approval, or completion restrictions to meet a ceiling"; `token-request-rar-narrowing.test.ts` "relaxing a constraint (an entry without the grant's vendors) is refused, not re-narrowed" |
| A `constraints` key outside `SUPPORTED_CONSTRAINT_KEYS` (unknown, or a Common Constraint registered later), on the ceiling or the candidate | refused at intake, configuration load and derivation (`assertSupportedConstraints`); a projection fragment carrying one is dropped (`onlyProjectableConstraints`) | `SUPPORTED_CONSTRAINT_KEYS` (`authority-subset.ts`) | `unsupported-constraint-keys.test.ts` "configured-mapping mode refuses a Common Constraint registered after this implementation on a directly-supplied ceiling entry" and "submitted-proposal mode refuses an unsupported key on a proposal entry no ceiling entry shares a resource with, even though a sibling entry derives fine"; cases der-07, der-09, cc-unsupported-extension |
| A key present only in the candidate narrows only when it has defined semantics | implemented | as above | cases der-08 (narrows), der-09 (refused) |
| `locations` | refused, by presence | `REFUSED_ENTRY_MEMBERS`, `refusedEntryMember` (`authority-subset.ts`) | `rar-carriage.test.ts` "refuses a proposal entry carrying locations, whatever its value, before any interaction, creating no Mission"; case fc-08 |
| An unknown top-level member | not implemented: admitted at intake (the published schema allows additional members, and `validateMissionResourceAccessSchema` refuses only `locations` by name), then dropped wherever an entry is rebuilt member by member (`intersect`, `intersectForProjection`, `parseCeilingEntry`); never refused | as named | none |

`capability_sources`, a member another specification defines for this type,
is compared by `capabilitySourcesNoBroader` (`authority-subset.ts`).

### 2.4 The `delegation` member under narrowing

Resource Access § Subset Rule, the closing list on `delegation`.

| Rule | Status | Code | Witness |
|---|---|---|---|
| `max_depth` no greater than the parent's | implemented | `isSubsetEntry`; `narrowDelegation` and `intersectDelegation` take the minimum (`derive.ts`) | `derivation-delegation.test.ts` "(b) a NARROWER max_depth is a subset; a BROADER one is not" and "both present -> max_depth narrows to the min and delegates intersect" |
| `allowed_delegates` no wider; a list under an inherited policy decision only restricts it | implemented structurally: a candidate list is no wider when each of its matchers equals a granted matcher on the `(sub, sub_profile)` pair | `matchersSubset` (`authority-subset.ts`); `narrowMatchers` and `intersectMatchers` (`derive.ts`); origin recorded in `deriveAuthoritySetWithProvenance` | `derivation-delegation.test.ts` "allowed_delegates must be no wider; children caps must be no broader"; `eligibility-provenance.test.ts` "a list the proposal adds over a ceiling entry without one is kept as a restriction, and the entry's origin is policy" |
| A candidate matcher narrower by containment: it admits only actors a granted matcher admits, as `{"sub": "bob", "sub_profile": "ai_agent"}` does under `{"sub_profile": "ai_agent"}` | not implemented: the comparison is of matcher identities, not of the actors each matcher permits, so the narrower list is refused by `isSubsetEntry` and narrows to `[]` at derivation and projection. The refusal is conservative; it never widens. | `matchersSubset`; `narrowMatchers`; `intersectMatchers` | none; the probe below |
| `children.allowed_child_actors` (Child Delegation) no wider | implemented structurally, with the same limitation: a matcher narrower by containment is refused and narrows to `[]` | `childrenNoBroader` with `matchersSubset` (`authority-subset.ts`); `narrowChildren` with `narrowMatchers` and `intersectChildren` with `intersectMatchers` (`derive.ts`) | none for the list comparison; the probe below |
| No `delegation` introduced where the parent has none | implemented | `isSubsetEntry`; `narrowDelegation` | `derivation-delegation.test.ts` "(c) candidate INTRODUCING delegation on a delegation-free grant FAILS" and "ceiling-absent delegation is NOT introduced by the proposal (compromised-shaper flip)" |
| A companion `delegation` member the server does not understand is carried unchanged | implemented at derivation: carried from the ceiling entry, never from a proposal (`narrowDelegation`). Elsewhere stricter: projection drops the whole `delegation` member (`intersectDelegation`), configuration load refuses the entry (`isAuthorityEntry`). `isSubsetEntry` does not compare such members. | as named | `effective-set-projection.test.ts` "narrows the nested children grant, and drops delegation carrying a member it cannot evaluate"; derivation's carriage: none |

A throwaway probe (not committed) compared a candidate matcher
`{"sub": "bob", "sub_profile": "ai_agent"}` with a granted
`{"sub_profile": "ai_agent"}`, in `allowed_delegates` and in
`children.allowed_child_actors`, and observed for each list:

- `isSubsetEntry`: `false`;
- `deriveAuthoritySet` (the granted entry as ceiling, the candidate as
  proposal): the list derives as `[]`;
- `projectThroughEffective` (the candidate through the granted entry): the
  list projects as `[]`.

## 3. `delegation`

Resource Access § Delegate Eligibility and § Matching `allowed_delegates`. The
gate is `delegateEligibility` and `gateDelegableAuthority`
(`services/authorization-server/src/kernel/eligibility-provenance.ts`); the
matcher is `delegatePermitted` (`kernel/delegate-matcher.ts`).

| Rule | Status | Witness |
|---|---|---|
| 1. The entry carries `delegation`; otherwise it is non-delegable | implemented | `delegation.test.ts` "(1) narrows out an entry that carries NO delegation member (non-delegable default)" |
| 2. `d` is within `max_depth`, with `d` from the server's own accounting | implemented | `delegation.test.ts` "(2) narrows out an entry when depth EXCEEDS delegation.max_depth" and "gates on the accounted depth, not the nesting of the presented act (@spec mission#delegation-constraints, D198)" |
| 3. The delegate is permitted by `allowed_delegates` or, when absent, by policy at every exchange | implemented; the reference policy denies every delegate (`DENY_ALL_DELEGATION_POLICY`) | `delegation.test.ts` "(3) an ABSENT allowed_delegates list defers to policy and is never a blanket grant"; case dg-policy-01 |
| Surviving entries keep `delegation` intact | implemented | `delegation.test.ts` "(3) includes an entry when the delegate matches allowed_delegates by sub_profile MEMBERSHIP" |
| Inherited eligibility: the policy decision and every retained list must both permit | implemented (`ceilingOrigin`, `combineOrigins`, `inheritOrigins`) | cases dg-inherit-01, -02, -04, -05, -07; row `resource-access.subset.inherited-allowed-delegates` |
| Provenance retained with the Mission; an unresolvable approved entry or origin narrows out | implemented (`MissionRecord.eligibility_provenance`, `retainedOrigins`) | cases dg-inherit-03, dg-inherit-06 |
| A `sub` matcher compares the client identifier exactly | implemented | `delegation.test.ts` "a { sub } matcher permits by CLIENT IDENTIFIER (the delegate's sub), and rejects a different sub" |
| A `sub_profile` matcher is satisfied by membership among the actor's values | implemented; a matcher value naming several space-separated tokens requires every token | `delegation.test.ts` "(3) includes an entry when the delegate matches allowed_delegates by sub_profile MEMBERSHIP" |
| A matcher with both members needs both; any matcher in the list permits | implemented | cases dg-match-01 to dg-match-04 |
| Only an asserted `sub_profile` satisfies a matcher, never a self-asserted one | implemented (`DelegateCandidate.assertedProfile`) | `delegation.test.ts` "a SELF-ASSERTED profile (no asserted class) does NOT satisfy a sub_profile matcher"; case dg-match-05 |

How a Resource AS evaluates conveyed `sub` matchers is Cross-Domain's rule and
is outside this inventory.

## 4. `projection`

Resource Access § Scope Projection. The conditions are
`scopeValueSafeForEntry` and the issuance algorithm is `projectScope`
(`packages/mission-core/src/scope-projection.ts`); the mapping is the trusted
per-audience document `parseScopeProjectionMapping` validates.

| Rule | Status | Witness |
|---|---|---|
| 1. The mapping covers the entry's resource set | implemented for `exact`: the same `resource`, byte for byte, under the same `resource_match`. A `prefix` value is never safe for an `exact` entry. A narrower resource within a `prefix` entry is never treated as safe; `prefix` entries are refused upstream (§2.1). | `packages/mission-core/test/scope-projection.test.ts` "resource match: a prefix value is never safe for an exact entry, nor a broader ancestor for a narrower prefix entry"; `scope-projection.test.ts` "refuses a prefix scope for an exact entry"; cases pj-05, pj-06 skip |
| 2. Actions match without aggregation; a proper subset is allowed | implemented, by literal membership, one entry per value | `packages/mission-core/test/scope-projection.test.ts` "action aggregation: a value granting an action the entry does not carry is not safe" and "union widening: a value only two entries together cover is not emitted"; `scope-projection.test.ts` "a mapped value granting a proper subset of the entry's actions is a safe projection (@spec resource-access#scope-projection)" |
| 3. Every carried `constraints` key is independently enforced | implemented for `max_amount` and `vendors`, the only controls a mapping can declare (`SCOPE_CONTROL_KEYS`); `requires_action_approval: false` counts as omitted. An entry carrying any other key, including the seven `common-constraints.ts` keys, `terminal_when` and `requires_action_approval: true`, is never projected. | `packages/mission-core/test/scope-projection.test.ts` "constraints: every carried key needs an independently enforced control at least as tight"; `scope-projection.test.ts` "refuses invalid_target when an entry constraint is not independently enforced by the target, and projects once the mapping declares a control at least as tight" |
| An entry member the projection does not understand fails closed | implemented (`KNOWN_ENTRY_MEMBERS`) | `packages/mission-core/test/scope-projection.test.ts` "an entry member the projection does not understand, or a capability-source binding, fails closed" |
| With `projection` undeclared, emit no projected `scope` for the type | not implemented: the reference projects without a declaration | none; cases pj-01 to pj-04 skip (`transformation-capabilities` and `scope-projection` are not in the case reader's implemented set) |

## 5. Supported domain

The reference narrows within `exact` resources and literal action
identifiers. There it applies the subset and intersection rules of the nine
initial Common Constraints, `vendors` and `terminal_when`, and the
`delegation` rules of §2.4, with one limitation: delegate and child-actor
matchers are compared by `(sub, sub_profile)` identity, not by the actors
they permit, so a candidate list narrower by containment is refused (§2.4).
Outside that domain, `prefix` is refused, action families are admitted and
compared literally, and an unknown top-level member is dropped.

D414 selects the same shape for #819's first interoperable subset:
"exact-resource matching, explicit actions and agreed typed constraints",
with prefix behavior only under separately enabled vectors. This note does
not define that profile or its vectors.

## 6. Route to a declaration

D538 rules the route: a qualified supported-subset declaration aligned with
D414, made through a reviewable specification and declaration change. No
declaration is published yet. Before one is made:

- unsupported input, including action families (§2.1) and unknown top-level
  members (§2.3), is refused consistently before approval or transformation;
- this inventory is kept correct as that handling changes;
- each claimed transformation has its own evidence; and
- the declaration states its domain: `exact` resources, literal actions, the
  supported members and constraints, the matcher-comparison limitation of
  §2.4, and each transformation's scope.

A declaration is never an unqualified whole-type boolean narrowed by prose.
A qualified `narrowing` choice establishes no `projection` evidence, and the
three per-entry, per-target projection conditions of §4 still apply. The
`delegation` declaration remains a separate audit.
