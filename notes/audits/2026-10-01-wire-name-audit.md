# Wire-name audit (2026-10-01)

Baseline: `origin/main` at `bf7a753b`, all 50 drafts. Question: are
parameter, claim, metadata, error-code, member, and value names named
consistently across the family, and which names should be revisited?

This note proposes; it renames nothing. Renames are owner decisions.
Anything that renames a core wire name (published `-00`) belongs in the
parked #705 breaking window, not a piecemeal respin.

## Method

- Extracted every defining position (definition-list term, `` - `name` ``
  bullet, table first column, IANA entry) from the 50 drafts: 1,143
  positions, 593 distinct names. Case-style counts use all 1,365
  distinct backticked tokens.
- Verified registry placement, value spaces, and semantics in three
  passes: registries and error codes, record members, and external
  specifications (RFC 6749, 6755, 7591, 8414, 8693, 9396, 9449, 9995,
  OpenID Connect Core, AuthZEN 1.0, Transaction Tokens -11, and the IANA
  Structured Syntax Suffixes registry).
- Excluded inherited names: RFC 8693 token-exchange parameters, JOSE
  and JWT claims, AuthZEN and ARAP members, AAuth-native names, Cedar
  `policySet`, OpenAPI `operationId`.
- Blast radius per name: drafts that use it, `src/` files
  (`packages`, `services`, `apps`, `config`), and word-match hits in
  `conformance-manifest.json`.

## The convention in force

No repository document (CONTRIBUTING.md, README.md, DRAFTS.md,
src/PLAN.md) states a naming rule. Usage implies one, and the family
follows it closely:

| Rule | Evidence | Exceptions |
|---|---|---|
| C1. snake_case for parameters, claims, metadata, error codes, record members, and enumerated values | 659 distinct snake_case tokens; no family-coined camelCase | `op` and `format` values (F11) |
| C2. Family-coined names in a shared IETF registry (OAuth Parameters, OAuth Extensions Error, AS and PR Metadata, Token Introspection Response) carry `mission`: as a prefix, or inside the `invalid_<x>` error pattern | core, attenuation, issuance-grant, status, signals, management | F1 |
| C3. Members inside a Mission-owned object stay unprefixed; the OAuth-layer parameter that carries one is prefixed | `expires_at` member and `mission_expires_at` parameter; `intent` and `mission_intent` | none |
| C4. RFC 8414 shapes: `<x>_endpoint`, `<endpoint>_auth_methods_supported`, `<endpoint>_auth_signing_alg_values_supported`, boolean `<feature>_supported` (RFC 9207 precedent), PR-metadata `<x>_required` (RFC 9728 precedent) | status, signals, management, issuance-grant, core | F7 |
| C5. Instants end in `_at` (bounds in `_until`, `_before`, `_after`) and are RFC 3339 strings, including inside JWT payloads; NumericDate only for JWT-level `iat`, `exp`, `mandate_exp` | stated only locally: mandate.md:424, core.md:2813 | F10 |
| C6. Media subtypes `mission-<thing>+json`, `+jws`, `+jwt`; `typ` labels and URN tails in lowercase kebab | all three suffixes are registered (`+jws`: RFC 7515, IANA 2025-12-09) | none |

**R0.** Write C1 to C6 down once (a "Wire names" section in
CONTRIBUTING.md), together with the duration and digest rules decided
under F9 and F10. C2 is cheap to lint: an IANA entry in one of the
listed registries whose name lacks `mission` fails.

## Names to revisit

Ranked by interoperability cost. Counts are `src` files / ledger hits.

### Tier 1: shared IETF registries

**F1. Unprefixed family names requested in IETF registries.** "OAuth
Parameters" (RFC 6749 Section 11.2) and "OAuth Extensions Error" are
Specification Required and first-come. A generic name such as `parent` or `predecessor` takes that word from
every other OAuth extension. RFC 6749 Section 8.2 asks only unregistered
vendor parameters for a prefix, so C2 is a family choice; five
companions don't follow it.

| Name | Requested at | Usage | src / ledger |
|---|---|---|---|
| `predecessor` | expansion.md:1895 | token and authorization request | 33 / 40 (includes the record member, which stays) |
| `creation_request_id` | expansion.md:1912 | token request | 13 / 2 |
| `parent`, `child_actor` | child-delegation.md:1989-1990 | token request | `parent` not counted (generic word); `child_actor` 11 / 0 |
| `dispatch_event_id` | template.md:1021 | token request | 8 / 7 |
| `revision_required`, `revision_handle`, `rejected_scope`, `rejected_authorization_details` | approval-revision.md:695-699 | token response, authorization request | 0 / 0 |
| `revision_not_narrowing` | approval-revision.md:712 (OAuth Extensions Error) | token error response | 0 / 0 |

Proposal: `mission_predecessor`, `mission_parent`,
`mission_child_actor`, `mission_creation_request_id`,
`mission_dispatch_event_id` at the OAuth layer, with the record members
unchanged (C3). Approval-revision needs an owner answer first: are its
five names deliberately generic OAuth vocabulary, useful without
Missions alongside the deferred token response? If so, keep them and say
so in the draft; if not, prefix them.

Prior rulings: D69 chose `creation_request_id` as an expansion-owned
token-request parameter (over the httpapi `Idempotency-Key` header) but
did not rule its spelling. No D-entry rules the other names.

### Tier 2: one concept, several names

**F2. The Mission state version has five names.** `version` (status
response, status.md:578), `mission_state_version` (runtime-evidence.md:424,
mapped to `version` at runtime-oauth.md:322), `prior_version` and
`current_version` (discharge.md:866), `prior_version` and `new_version`
(containment.md:802), plus the `expected_version` guard and
`stale_version` error (status.md:709). The two transition records
disagree on the after-value: `current_version` in discharge,
`new_version` in containment. Proposal: one before/after pair
(`prior_version`, `new_version`), so discharge renames `current_version`
(4 / 5). Keep `version` on the status read surface and
`mission_state_version` where the counter sits in a non-Mission object,
and state once in status that they are the same counter. Containment's
own `containment_version` counter is distinct and fine. Coordinate with
open #896, which reworks the discharge state model.

**F3. "Relied-on status, valid through" has three names.** `fresh_until`
(status.md:556); harness `status_checked_at` and `status_expires_at`
(harness.md:476-481, a lease end that may come from `fresh_until`);
AuthZEN `mission_status_issued_at` and `mission_status_expires_at`
(authzen.md:945-952). None cites the others. Harness and AuthZEN record
the same fact on two evidence surfaces. Proposal: one pair for both,
defined as "the relied-on response's `fresh_until`, or the lease end".
Harness's `status_expires_at` is the more widely implemented of the two
(7 / 0, against 0 / 1).

**F4. "Derivation limit reached" has two spellings.**
`derivations_exhausted` (`mission_error` value, derivation-limits.md:331,
named in core.md:5725) and `derivation_limit_exhausted`
(issuance-grant.md:443, a 409). Same condition. Proposal:
issuance-grant adopts `derivations_exhausted`, which pairs with
`derivations_remaining`, and states the mapping, since a shared
spelling across carriers means nothing unless the defining documents
say so (expansion.md:1840-1848) (0 / 0).

**F5. Intent-evidence error.** The Mission Authority Server's (MAS)
`invalid_intent_evidence` is declared "the MAS equivalent of" the core's
registered `invalid_mission_intent_evidence` (authority-server.md:545).
The MAS also defines `invalid_mission_intent`, so it uses `mission` in
one code and not the other. Proposal: the MAS uses the core spelling
(0 / 0).

**F6. "Mission not active" has four spellings.** `mission_not_active`
(issuance-grant.md:441), `parent_not_active` (child-delegation.md:910),
`predecessor_not_active` (expansion.md:1122), and `mission_inactive`
(AuthZEN denial reason, authzen.md:1949). Expansion declares
cross-carrier value spaces separate (expansion.md:1840-1848), so this is
cosmetic, but three of four follow `<x>_not_active`. Proposal: AuthZEN
`mission_not_active` with a sentence stating the mapping to the
issuance-grant code (7 / 5), or leave as is.

**F7. Two metadata names for the same endpoints' caller
authentication.** The MAS's `mission_auth_methods_supported`
(authority-server.md:1129) is one array covering its submission, status,
and lifecycle endpoints. Status defines
`mission_status_endpoint_auth_methods_supported` and
`mission_lifecycle_endpoint_auth_methods_supported` (and the
`_auth_signing_alg_values_supported` pair) for the same endpoints, per
RFC 8414; no OAuth RFC defines a cross-endpoint name. A deployment
serving both surfaces publishes one fact under two names. Proposal: the
MAS registers per-endpoint names (adding
`mission_submission_endpoint_auth_methods_supported`) and drops the
umbrella name (0 / 0).

**F8. The deprecated `approver` is still carried.** The core marks
`approver` both REQUIRED and a DEPRECATED alias for
`approval_basis.consent_principal` (core.md:1918-1921). Consent-evidence
(:797), mandate (:353), and template (:519) still carry `approver`;
child-delegation uses `consent_principal`. Companions can't drop a
member the core still requires. #701 already ruled this: alias removal
is parked to the #705 breaking window. Proposal: add these three
companions to the #705 sweep list; nothing to do now. `approver`
appears in 79 `src` files.

### Tier 3: suffixes and encodings

**F9. Digest suffixes don't track construction.** The substrate defines
three species (envelope anchor, canonical-object digest, raw-octet
digest; substrate.md:540-558), but each suffix spans species:

- envelope anchors are named `_hash` (`authority_hash`, `intent_hash`,
  `proposal_hash`), `_digest` (`entry_digest`, `entries_digest`), and
  `_commitment` (`approval_context_commitment`,
  `submission_evidence_commitment`);
- `root_commitment` (child-delegation.md:1070, 1083) computes nothing
  of its own: it holds either an existing `authority_hash` or a
  `child_creation_policy` reference, so its value is not always a
  digest (14 / 3);
- `source_hashes` (consent-evidence.md:306) is an object, not an array;
- `token_sha256` (authority-server.md:1662) and `token_digest`
  (audit.md:721) hash the same token in two encodings. `token_sha256`
  matches the construction of RFC 9449 `ath` but doesn't cite it.

Proposal: don't rename the core anchors (`authority_hash` is in 36
drafts and 101 `src` files). Put a forward rule in R0, for example
`_hash` for envelope anchors and `_digest` for the other two species,
with no new `_commitment` names. Fix the misleading outliers:
`root_commitment` and, if the MAS can, `token_sha256` (cite `ath` or use
the prefixed `token_digest` form).

**F10. Durations have three encodings and no rule.**

- ISO 8601 strings: `max_duration`, `measured_duration`
  (metering.md:439).
- Integer seconds named in the member: `mission_max_stale_seconds`.
- No stated encoding: template `instance_lifetime`, `review_cadence`,
  `dispatch_rate` (template.md:356-373).

An unstated encoding is an interoperability gap, not only a style
issue. Proposal: template states an encoding, and R0 picks a family
default. OAuth's own idiom is integer seconds (`expires_in`,
`interval`).

Separately, an example contradicts C5: issuance-grant.md:325 uses
`"resource_issued_after": "2026-07-01"`, a full-date, where
resource-access.md:390 requires an RFC 3339 date-time.

**F11. Kebab-case enumerated values.** The creation fingerprint's `op`
(expansion.md:1214) takes `expansion`, `dispatch`, `child-creation`, and
`async-delegation`. `format` takes `jws-compact` (approval-governance.md:393
and 7 other drafts). Every other enumerated value is snake_case. `op`
sits inside a JCS-hashed fingerprint, so renaming it changes committed
bytes and fixtures. Proposal: R0 states whether such values are labels
(kebab, like `typ`) or enumerated values (snake).

**F12. `_ref` and `_reference`.** `evidence_ref` (discharge.md:640, a
URI) and `evidence_reference` (authzen.md:1069, a free string) spell
one word two ways for different things. The family term is "Mission
Reference" (`Mission-Reference` field, `hop_reference`). Proposal:
`_reference` for new names; consider renaming `evidence_ref` to
`evidence_uri`, since it is one (5 / 5).

**F13. `goal_lang` and `locale` cite different references.** #534
(PR #625) chose `goal_lang` deliberately, with consent-evidence's
`locale` as precedent, as one BCP 47 tag for `goal`, `task_bounds`, and
`success_criteria` (core.md:738). One tag for three members is a sound
reason not to use the RFC 7591 / OpenID Connect `#` suffix. Residual:
core cites RFC5646 and consent-evidence cites BCP47 for the same kind of
value. Harmonize the citation; no rename.

**F14. `mission_error` values mix forms.** The values are
`mission_revoked`, `mission_expired`, and `mission_superseded`
(core.md:2504), plus `derivations_exhausted`. The prefix stutters inside
a member already named `mission_error`. The #705 breaking window
already moves these values to termination reasons; drop the stutter
there.

## Checked and consistent

- Case: no family-coined camelCase, including JSON keys in fenced
  examples. `rarFormat` and `policySet` (draft-cecchetti-oauth-rar-cedar,
  in a core example), `inputSchema` (MCP), and `operationId` (OpenAPI)
  are external.
- Metadata: `mission_<x>_endpoint` is uniform across status, lifecycle,
  submission, event stream, join assertion, issuance grant, and
  management.
- Media types: `+jws`, `+jwt`, and `+sd-jwt` are registered structured
  syntax suffixes.
- COSE names: `payload-hash-alg` and `payload-preimage-content-type`
  (audit) are RFC 9995's own hyphenated names.
- AuthZEN URNs: the seven `urn:ietf:params:authzen:mission-runtime*`
  values are requested in AuthZEN's PDP Capabilities registry, under the
  `authzen` sub-namespace AuthZEN Section 12.4 requests.
- AAuth: `mission_not_found` and `mission_control_endpoint` are
  AAuth-native names.
- Error codes: `insufficient_authority` (a `mission_denial` value) and
  `insufficient_authorization` (the RAR-remediation error code) are
  complementary by design (core.md:3055-3064).
- Depth: `max_depth` (act-chain nesting) and `children.max_child_depth`
  (child generations) are distinct (child-delegation.md:329).
- Containment counters: `prior_version`/`new_version` (state version)
  and `prior_containment_version`/`new_containment_version` (overlay
  counter) are distinct.
- Architecture labels: the Mission Binding Properties (`action-bound`,
  `instance-bound`, ...) are prose labels, not wire values.
- Value sets: lifecycle states are uniform past participles, and the
  `allowed_*` constraint lists are uniform plurals.
- URNs: the token type `mission-delegation-chain` is kebab while RFC
  8693's are snake, but IETF practice is mixed (ID-JAG uses `id-jag`).

Noticed in passing (registration, not naming): `mission-delegation-chain`
lists change controller IESG (cross-org-delegation.md:700), while
`mission-dispatch` lists IETF (template.md:998).

## Proposed order

1. Owner decisions: R0, and F1's approval-revision question.
2. Companion fixes, one PR per finding, renaming the matching ledger
   rows and `src` fixtures in the same PR: F1, F4, F5, F7, F2, F3, F10,
   then the remaining Tier 3 items.
3. Core-touching items ride the parked #705 breaking window instead
   of separate respins: F8 (alias removal, per #701) and F14. F13 is a
   citation fix, not a rename.
