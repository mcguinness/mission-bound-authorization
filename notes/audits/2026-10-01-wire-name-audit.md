# Wire-name audit (2026-10-01)

Baseline: `origin/main` at `bf7a753b`, all 50 drafts. Question: are
parameter, claim, metadata, error-code, member, and value names named
consistently across the family, and which names should be revisited?

This note proposes; it renames nothing. Renames are owner decisions.
Anything that renames a core wire name (published `-00`) belongs in the
parked #705 breaking window, not a piecemeal respin.

The findings fall into four kinds, handled in this order:
interoperability defects, naming drift where two names carry the same
value, names whose semantics must be defined before they can converge,
and optional cleanup.

## Method

- Extracted every defining position (definition-list term, `` - `name` ``
  bullet, table first column, IANA entry) from the 50 drafts: 1,143
  positions, 593 distinct names. Case-style counts use all 1,365
  distinct backticked tokens, plus a scan of JSON keys in fenced
  examples.
- Verified registry placement, value spaces, and semantics in three
  passes: registries and error codes, record members, and external
  specifications (RFC 6749, 6755, 7591, 8414, 8693, 8705, 9396, 9449,
  9995, OpenID Connect Core, AuthZEN 1.0, Transaction Tokens -11, and
  the IANA Structured Syntax Suffixes and OAuth Token Endpoint
  Authentication Methods registries).
- Excluded inherited names: RFC 8693 token-exchange parameters, JOSE
  and JWT claims, AuthZEN and ARAP members, AAuth-native names, Cedar
  `policySet`, OpenAPI `operationId`.
- Counts given as `src` / ledger are files under `src/` (`packages`,
  `services`, `apps`, `config`) and word-match hits in
  `conformance-manifest.json`. They are a floor, not a migration
  assessment: a wire rename also reaches clients, stored records, and
  signed artifacts, which each finding names where known.

## The pattern in use

No repository document (CONTRIBUTING.md, README.md, DRAFTS.md,
src/PLAN.md) states a naming rule. The pattern below is inferred from
usage; it isn't yet a convention anyone has adopted.

| Pattern | Evidence | Exceptions |
|---|---|---|
| P1. snake_case for parameters, claims, metadata, error codes, record members, and enumerated values | 659 distinct snake_case tokens; no family-coined camelCase | `op` and `format` values (F11) |
| P2. Family-coined names in a shared IETF registry (OAuth Parameters, OAuth Extensions Error, AS and PR Metadata, Token Introspection Response) carry `mission`: as a prefix, or inside the `invalid_<x>` error pattern | core, attenuation, issuance-grant, status, signals, management | F1 |
| P3. Members inside a Mission-owned object stay unprefixed; the OAuth-layer parameter that carries one is prefixed | `expires_at` member and `mission_expires_at` parameter; `intent` and `mission_intent` | none |
| P4. RFC 8414 shapes: `<x>_endpoint`, `<endpoint>_auth_methods_supported`, `<endpoint>_auth_signing_alg_values_supported`, boolean `<feature>_supported` (RFC 9207 precedent), PR-metadata `<x>_required` (RFC 9728 precedent) | status, signals, management, issuance-grant, core | F7 |
| P5. Instants end in `_at` (bounds in `_until`, `_before`, `_after`) and are RFC 3339 strings, including inside JWT payloads; NumericDate only for JWT-level `iat`, `exp`, `mandate_exp` | stated only locally: mandate.md:424, core.md:2813 | F10 |
| P6. Media subtypes `mission-<thing>+json`, `+jws`, `+jwt`; `typ` labels and URN tails in lowercase kebab | all three suffixes are registered (`+jws`: RFC 7515, IANA 2025-12-09) | none |

**R0 (prospective).** Adopt P1 to P6 as the rule for new family-owned
definitions only, in a "Wire names" section of CONTRIBUTING.md. Lint
new IANA entries and new members against P2, with an explicit exception
list for inherited names and for vocabulary ruled deliberately generic
(F1's approval-revision question). Existing names stay unless a
finding below justifies a migration on its own merits. Values inside
committed or signed objects (fingerprint `op` values, digest preimages)
stay stable.

## Tier 1: interoperability defects

Fix these first; each one can make two conforming implementations fail
to interoperate today.

**F7. Mission authentication discovery disagrees between Status and the
MAS.** The Mission Authority Server (MAS) states that its values come
"from the mechanism set of" the Status draft (authority-server.md:1131),
but the two disagree on member names, values, token presentation,
algorithms, and requirement level:

| Aspect | Status | MAS |
|---|---|---|
| Member names | per endpoint, per RFC 8414: `mission_status_endpoint_auth_methods_supported`, `mission_lifecycle_endpoint_auth_methods_supported` (status.md:1431, 1471) | one array, `mission_auth_methods_supported`, for the submission, status, and lifecycle endpoints (authority-server.md:1129) |
| mTLS value | `mtls_client_auth` (status.md:1435) | `tls_client_auth` (authority-server.md:1135) |
| Token presentation | `access_token`; the DPoP or mTLS sender constraint is described separately by Protected Resource Metadata (status.md:1437-1440) | `dpop_bound_token`, which fixes DPoP (authority-server.md:1140) |
| Client-assertion algorithms | `*_endpoint_auth_signing_alg_values_supported` per endpoint (status.md:1446) | none; only the response-signing `mission_status_signing_alg_values_supported` (authority-server.md:1121) |
| Requirement level | OPTIONAL, "SHOULD be advertised" when the endpoint is served (status.md:1440-1444) | REQUIRED |

Status also says its first two values are "spelled identically to
registered token-endpoint authentication methods by intent"
(status.md:1440). The registered RFC 8705 value is `tls_client_auth`,
so that claim is false for `mtls_client_auth`.

Proposal: one discovery contract for both surfaces, covering
- per-endpoint member names (the MAS adds
  `mission_submission_endpoint_auth_methods_supported`);
- one value set, using registered spellings (`tls_client_auth`,
  `private_key_jwt`) plus one token-presentation value with a single
  sender-constraint rule;
- per-endpoint client-assertion algorithms;
- one rule for what a client assumes when a member is absent.

Renaming the MAS member alone leaves discovery incompatible. Consumers:
every client of the submission, status, and lifecycle endpoints. No
signed artifact carries these values (0 / 0 for all three method
values).

**F10. Undefined encodings and one invalid example.**

- `instance_lifetime` ("A duration", template.md:357) and
  `review_cadence` (no type, template.md:373) need a type, unit, range,
  and boundary rule (inclusive or exclusive, and measured from what).
- `dispatch_rate` ("A rate bound on Dispatch from this template per
  unit time", template.md:366) is a rate, so no duration default can
  define it. The draft does define one count per instantiation,
  committed atomically with derivation, and no count for a recovered
  retry (template.md:596-641). It doesn't define the counting window
  (fixed or sliding), burst behavior, whether refused dispatches count,
  or the value encoding. Specify these, or delegate them explicitly to
  a named policy.
- The example at issuance-grant.md:325,
  `"resource_issued_after": "2026-07-01"`, is a full-date, but
  resource-access.md:390 requires an RFC 3339 date-time. Fix the
  example.

Elsewhere, durations use ISO 8601 strings (`max_duration`,
`measured_duration`, metering.md:439) or integer seconds named in the
member (`mission_max_stale_seconds`). R0 can set a default for new
duration members; OAuth's idiom is integer seconds (`expires_in`,
`interval`).

## Tier 2: one value, two names

**F2. The Mission state version has five names.**
- `version` in the status response (status.md:578).
- `mission_state_version` (runtime-evidence.md:424), mapped to
  `version` at runtime-oauth.md:322.
- `prior_version` and `current_version` in discharge (discharge.md:866).
- `prior_version` and `new_version` in containment (containment.md:802).
- The `expected_version` guard and the `stale_version` error
  (status.md:709).

The two transition records disagree on the after-value:
`current_version` in discharge, `new_version` in containment.

Proposal: one before/after pair, `prior_version` and `new_version`, so
discharge renames `current_version` (4 / 5). Keep `version` on the
status read surface, keep `mission_state_version` where the counter sits
in a non-Mission object, and state once in status that they are the
same counter.

Consumers: the pair sits in the Discharge Result, which the AS returns
as a signed Discharge Receipt (discharge.md:938-948). The rename
therefore reaches receipt verifiers and stored receipts, not only the
4 `src` files. Containment's own `containment_version` counter is
distinct and fine. Coordinate with open #896, which reworks the
discharge state model.

**F4. "Derivation limit reached" has two spellings.**
`derivations_exhausted` (`mission_error` value, derivation-limits.md:331,
named in core.md:5725) and `derivation_limit_exhausted`
(issuance-grant.md:443, a 409). Same condition. Proposal:
issuance-grant adopts `derivations_exhausted`, which pairs with
`derivations_remaining`, and states the mapping, since a shared
spelling across carriers means nothing unless the defining documents
say so (expansion.md:1840-1848) (0 / 0).

**F5. Intent-evidence error.** The MAS's `invalid_intent_evidence` is
declared "the MAS equivalent of" the core's registered
`invalid_mission_intent_evidence` (authority-server.md:545). The MAS
also defines `invalid_mission_intent`, so it uses `mission` in one code
and not the other. Proposal: the MAS uses the core spelling and keeps
the stated mapping (0 / 0).

**F1. Unprefixed family names requested in IETF registries.** "OAuth
Parameters" and "OAuth Extensions Error" are Specification Required,
with Designated Expert review (RFC 6749 Section 11.2). Unprefixed names
are valid. The cost is that a registered generic name such as `parent`
or `predecessor` fixes that word's meaning for every later OAuth
extension. The core and three companions already prefix (P2); these
five companions don't.

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
unchanged (P3). Consumers: clients that send these parameters and AS
request parsers. The creation fingerprint has member names of its own
(expansion.md:1196-1285). It commits a `child_actor` member, holds the
supplied `predecessor` or `parent` value under `cross_check`, and
excludes `creation_request_id`. Renaming the parameters therefore leaves
committed fingerprint bytes unchanged only if the fingerprint's
`child_actor` member keeps its name, which it should.

Approval-revision needs an owner answer first: are its five names
deliberately generic OAuth vocabulary, useful without Missions
alongside the deferred token response? If so, keep them, say so in the
draft, and list them as an R0 exception. If not, prefix them.

Prior rulings: D69 chose `creation_request_id` as an expansion-owned
token-request parameter (over the httpapi `Idempotency-Key` header) but
did not rule its spelling. No D-entry rules the other names.

## Tier 3: define the semantics before converging the names

**F3. Status issuance, observation, and reliance are three facts.**
- Issuance: AuthZEN `mission_status_issued_at`, "when the relied-on
  Mission state was issued" (authzen.md:945).
- Observation: harness `status_checked_at`, when the harness checked
  (harness.md:476).
- Reliance deadline: the issuer's `fresh_until` (status.md:556), set
  against the consumer's own reliance end (harness
  `status_expires_at`, harness.md:479; AuthZEN
  `mission_status_expires_at`, "(or its lease)", authzen.md:950).

A response issued at 10:00 and checked at 10:02 must keep both times.
A consumer's local policy can end reliance before the issuer's
`fresh_until`.

Proposal: define the relationships first. For example, a consumer's
reliance end never exceeds `fresh_until`, and observation never
precedes issuance. Then harmonize names only where values and semantics
coincide. Harness `status_expires_at` and AuthZEN
`mission_status_expires_at` are the likely pair if both are defined as
the consumer's reliance end. Implementation counts don't decide which
meaning survives.

**F8. `approver` needs an object-by-object inventory, not a rename.**
- The record alias: the core marks `approver` both REQUIRED and a
  DEPRECATED alias for `approval_basis.consent_principal`
  (core.md:1918-1921). #701 parked its removal to the #705 breaking
  window.
- Writers and readers of the alias: child-delegation assigns the child
  record's `approver` and reads the parent's (child-delegation.md:1065,
  1078, 1100, 1899). Mandate mirrors the record member (mandate.md:353).
  Template sets each instance's `approver` (template.md:519). These
  change with the alias.
- Independent evidence fields: Consent Evidence's authenticated
  `approver` (consent-evidence.md:797) and its rendered `approver`
  (:446) cover declined and narrowed decisions in which no Mission was
  created (:769). They are not the record alias.

Proposal: the #705 sweep removes the record alias and updates the
companions that write or read it, including child-delegation. Consent
Evidence's fields are a separate decision. No mechanical rename of every
`approver` (79 `src` files).

**F9. Each digest needs its contract stated; suffixes can only
supplement it.** The substrate defines three constructions (envelope
anchor, canonical-object digest, raw-octet digest; substrate.md:540-558)
and explicitly permits member-named constructions such as
`token_sha256` (substrate.md:540-546). The suffixes `_hash`, `_digest`,
and `_commitment` each span constructions, so a reader can't infer the
contract from the name:

- `token_sha256` (authority-server.md:1662) hashes the access token's
  ASCII bytes. `token_digest` (audit.md:721) hashes the JWS, or its
  `jti`, as selected by `token_digest_kind`. These are not the same hash
  in two encodings. `token_sha256` matches the construction of RFC 9449
  `ath` but doesn't cite it.
- `root_commitment` is defined in the core (core.md:1956) to hold either
  an integrity anchor or a committed reference; child-delegation
  instantiates both forms (child-delegation.md:1070, 1083-1088).
- `shaping_evidence_hash` and `unwind_plan_hash` defer their
  construction to other sections; that wasn't traced here.

Proposal: no renames. Where a definition leaves any of these implicit,
state the input bytes, canonicalization, domain separation (`typ`),
algorithm, and encoding. `token_sha256` should cite `ath` as the same
construction. R0 may add a suffix guideline for new names, and
`_commitment` stays available.

## Tier 4: optional cleanup

**F6. "Mission not active" has four spellings.** The four are
`mission_not_active` (issuance-grant.md:441), `parent_not_active`
(child-delegation.md:910), `predecessor_not_active`
(expansion.md:1122), and `mission_inactive` (AuthZEN denial reason,
authzen.md:1949). Expansion declares cross-carrier value spaces
separate (expansion.md:1840-1848), so the difference is cosmetic.
Proposal: AuthZEN adopts `mission_not_active` with a sentence stating
the mapping (7 / 5), or leave it.

**F11. Kebab-case enumerated values.** The creation fingerprint's `op`
(expansion.md:1214) takes `expansion`, `dispatch`, `child-creation`, and
`async-delegation`. `format` takes `jws-compact`
(approval-governance.md:393 and 7 other drafts). Every other enumerated
value is snake_case. `op` sits inside a JCS-hashed fingerprint, so a
rename changes the committed bytes of stored reservations and
tombstones. Proposal: keep the values, and have R0 class them as labels
(kebab, like `typ`).

**F12. `_ref` and `_reference`.** `evidence_ref` (discharge.md:640, a
URI) and `evidence_reference` (authzen.md:1069, a free string) spell
one word two ways for different things. The family term is "Mission
Reference" (`Mission-Reference` field, `hop_reference`). Proposal:
`_reference` for new names; optionally rename `evidence_ref` to
`evidence_uri`, since it is one (5 / 5).

**F13. `goal_lang` and `locale` cite different references.** #534
(PR #625) chose `goal_lang` deliberately, with Consent Evidence's
`locale` as precedent, as one BCP 47 tag for `goal`, `task_bounds`, and
`success_criteria` (core.md:738). One tag for three members is a sound
reason not to use the RFC 7591 / OpenID Connect `#` suffix. Residual:
core cites RFC5646 and Consent Evidence cites BCP47 for the same kind of
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

1. Authentication discovery (F7).
2. Undefined encodings and the invalid example (F10).
3. Same-value name fixes (F2, F4, F5), and the owner decisions: R0 and
   F1's approval-revision question, then F1.
4. Semantics first, names after (F3, F8, F9).
5. Optional cleanup (F6, F11, F12, F13).

Core-touching renames ride the parked #705 breaking window: F8's alias
removal (per #701) and F14.

Each wire rename names its affected consumers and any stored or signed
artifacts it reaches. Matching `src` files and ledger rows alone don't
establish that a migration is safe.
