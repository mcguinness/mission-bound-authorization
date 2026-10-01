# Core editorial and structural review

draft-mcguinness-oauth-mission at PR #864 head `162b63e1`. Review only;
nothing is applied. Line numbers (L) are BASE.md lines at that head.

## Verdict

The section order is sound. It follows the protocol flow, as RFC 9126 and
RFC 9396 do, and a wholesale reorder is not worth the churn. The problems
are density and duplication:

- 259 of 462 BCP 14 occurrences (56%) fail the normative audit. 107 are
  duplicates of another rule in this document, 25 restate a dependency,
  and 67 bind deployment practice, internal implementation, or audit.
- 45 paragraphs run past 120 words (17 past 180, the longest 661), and 67
  sentences run past 70 words.
- An estimated 22-25% of the body is not needed to implement the protocol
  or to understand its security properties.

Twelve defects (A below) should land whatever the style decisions.

## Baseline

| Measure | Value |
| --- | --- |
| Words, whole file | 45,652 |
| Main body | 38,076 (36,100 without fences and tables) |
| Back matter, without history | 3,863 (2,889 prose) |
| BCP 14 occurrences | 456 body + 6 back matter |
| Paragraphs over 120 / 180 words | 45 / 17 (max 661) |
| Sentences over 45 / 70 words | 230 / 67 |
| Ledger rows quoting core text | 82 (38 tested, 8 partial, 36 todo) |
| "AS" in prose / "Resource Server" capitalized | 272 / 84 (0 lowercase) |
| Citations in `{{REF}} Section N` form | 30 (0 in `{{Section N of REF}}`) |

## A. Defects (verified against the draft and the cited RFC text)

1. **One case, three rules.** L961-968: "the AS SHOULD refuse with
   `invalid_authorization_details`" for a proposal entry that is
   "unsupported or policy-barred". L1068: the AS "MUST refuse" an
   unsupported type. L1075: the AS "MAY narrow or omit" a policy-barred
   entry. Fix: delete the Section 4.1 bullet; Section 4.2 and the error
   table are the homes.
2. **The error table is incomplete.** L3532 says the table "is the
   normative statement" and that other rules do not restate it. It has
   no row for `invalid_mission_intent_evidence` (L1179) or `invalid_scope`
   (L1836). Four refusals have no code anywhere: the scope-only target
   refusal (#291), the two downgrade refusals (#422, #424), and #60.
   Codes are an author call (B6).
3. **A MUST that contradicts its condition.** L4725: `authorization_details_types_supported`
   is "a MUST for an advertising AS, above". L4738: "where the AS also
   advertises it".
4. **Body rules that live only in Security Considerations.** #422 ("A
   deployment that designates a resource Mission-governed MUST NOT issue
   tokens for that resource outside a Mission") and #424 (an AS "MUST
   reject a bare `authorization_details` request" from a governed client)
   exist only in Downgrade by Omission, and the body points there
   (L3350). Move both to the body.
5. **Appendix D miscounts.** L6514: "This document's three OPTIONAL
   implementation roles". Conformance defines four OPTIONAL capabilities,
   and "role" collides with its three roles.
6. **Misattributed dependency.** L989 cites "the {{RFC9101}} duplication
   rule". RFC 9101 Section 6.3 says the authorization server "MUST only
   use the parameters in the Request Object, even if the same parameter
   is provided in the query parameter": it ignores duplicates, not
   rejects them.
7. **Worked example versus test vectors.** L2563 says "the test vectors
   ({{test-vectors}}) compute over them". The vectors hash a different
   Intent (L6219), and the worked example's hashes are illustrative.
8. **IANA Change Controller.** All nine OAuth registrations say "IESG".
   RFC 6749 Section 11.2.1: "For Standards Track RFCs, state 'IETF'."
   The draft's own new registries already say "IETF".
9. **"Present iff" members labelled OPTIONAL:** #161 `proposed_authority`,
   #165 `proposal_hash`, #166 `submission_evidence`, #219
   `derivation_limit`. Use the "REQUIRED when ...; absent otherwise"
   form that `approved_at` already uses.
10. **MUSTs with no party:** #198 ("MUST be refused"), #199, #222 ("It MUST
    NOT be reused"). Name the issuer.
11. **The core frames itself as part of a family.** 13 uses of "the
    family" or "this document series", for example L4607 "The family's
    extensible namespaces" and L2689 "The family's default prefixed
    construction".
12. **Temporal and roadmap text:** L2201 "its removal is scheduled for a
    future", L2257 "A future breaking-change window", L4507 "is no
    longer", L863 "today", L4149, L4273.

## B. Rulings needed (with a recommendation for each)

1. **Normative audit, by class.** Adopt the dispositions in E, class by
   class. Recommend yes for duplicates (one home plus pointers),
   restatements (pointer; keep only narrowings, written "strengthening
   Section N of [REF]"), and deployment, audit, or implementation duties
   (lowercase statements of fact or guidance). Each demotion keeps the
   substance as a declarative sentence: none deletes a capability.
2. **Consumer-interpretation guards.** About eight MUST NOTs tell a
   consumer what not to infer. Examples: #326 (`authority_hash` is not
   an enforcement input), #361 (the `act` chain is not proof of
   narrowing), #401, #446, #449. No other party can observe compliance.
   Recommend: state each as a declarative fact in its defining section.
   RFC 8693 Section 4.1 is the model: "Prior actors ... are informational
   only". Where a threat note needs it, add it in Security
   Considerations.
3. **`acr` and `auth_time` against RFC 9068 Section 2.2.1.** RFC 9068
   says the claims "reflect the types and strength of authentication ...
   enforced prior to returning the authorization response" and "are fixed
   and remain the same across all access tokens that derive from a given
   authorization response". The draft forbids them "to convey
   approval-event context" (#284) and says they describe "the token's
   own presentation" (#285). In this flow, the authentication before the
   authorization response is the approval-time authentication.
   Recommend: when present, the claims follow RFC 9068 Section 2.2.1.
   Keep the rule that their presence proves nothing about approval
   provenance when the Approver is not the Subject.
   Ledger cost: this is the one ruling that touches a tested row. The row
   is `core.approval-authentication.no-token-claim-carriage` ("they MUST
   NOT be carried on, or inferred from, ..."); aligning with RFC 9068
   rewords or retires it.
4. **Introspection caching.** L3624 ("each response as an observation
   ..., not as a cacheable state assertion") and L3732 narrow RFC 7662
   Section 4 ("a protected resource MAY cache the response"). This is
   stricter than the lifetime-bounded reliance the JWT form allows.
   Recommend: state the narrowing explicitly as "strengthening Section 4
   of [RFC7662]", or allow caching bounded by the token's `exp`. The
   choice is yours.
5. **Family-wide style calls.** Do not decide these inside a core-only
   pass.
   - Spelling out "AS" (272 uses) re-quotes 29 ledger rows (13 tested),
     and the 45 companions (484 uses) diverge.
   - Lowercasing role nouns takes about 100 edits and touches 1 tested
     row.
   - Spelling out "RS" takes 18 edits and touches no ledger row.
   Recommend: spell out "RS" now; run "AS" and lowercase role nouns as one
   scripted family-wide pass with the ledger re-quote, after this one.
6. **Error codes for the gaps in A2.** #291 (scope-only target), #422 and
   #424 (downgrade), and #60. Recommend `invalid_target` for #291
   (Section 2.2.2 of RFC 8693, Section 2 of RFC 8707), and
   `invalid_request` for #424, with the row added to the table.
7. **Structural moves.** All are whole-section and keep anchors, so
   there is no ledger cost. Recommend:
   - Design Context (Section 16) goes to an appendix. #864 placed it in
     the body; it carries 5 keywords, all dispositioned.
   - Adopted Model: `client_id` Names (14.2), Selective-Inclusion Proof
     (15.2), and Role Mapping (7.1, companion scenarios) go to that
     appendix.
   - Namespace Taxonomy (17.1) is rescoped to this document's namespaces
     or moved to the architecture draft.
   - Authority Sources (3.3) folds into Mission Approval, since L722 is
     an approval-time duty.
   - Internationalization moves after Privacy.
   - The enforcement table moves from Section 4 to Section 11.
8. **Heading suffixes.** "(Informative)", "(Optional)", and
   "(Non-Normative)" are mixed across six headings, and each section's
   first sentence already states its status. Recommend: drop the
   suffixes, which also removes the two #864 added.
9. **Tested ledger row `core.introspection.caller-authentication`.** R4
   classes it as a restatement of Section 2.1 of RFC 7662. That section
   requires "some form of authorization ..., such as client
   authentication ... or a separate OAuth 2.0 access token". Recommend:
   keep it as a narrowing (authentication, not just authorization) and
   do not retire the row.
10. **The revocation kill switch (#255).** A deployment MUST with no wire
    form, and the only home of the kill switch. Recommend: keep it, under
    the availability guard.
11. **Metering-owned IANA rows** (L5800). These seed the core's registry
    with a companion's members. Recommend: the metering companion
    registers them.
12. **Worked example and test vectors (A7).** Either reword L2563 (the
    vectors use a reduced Intent; the example's hashes are illustrative),
    or compute real vectors over the worked example's objects. Recommend:
    reword now, and compute real vectors when the example next changes.

## C. Track 1: mechanical, provable as no normative change

From STYLE.md, Section 6. Each commit is independently revertible and is
checked with `noop_check.py`.

| # | Commit | Changes | Ledger rows |
| --- | --- | --- | --- |
| 1 | Citations to `{{Section N of REF}}` | 25 | 0 |
| 2 | Grammar and punctuation ("with", "for example,") | 5 | 0 |
| 3 | "AND"/"IS" lowercase, cut "Note that" | 4 | 0 |
| 4 | "this specification" to "this document"; one scope phrase | 3 | 0 |
| 5 | "merely"/"not merely" | 7 | 0 |
| 6 | Example openers ("The following is an example of ...") | 5 | 0 |
| 7 | IANA intros: "This document requests registration of ..." | 8 | 0 |
| 8 | Change Controller "IESG" to "IETF" (A8) | 9 | 0 |
| 9 | Spell out "RS" (B5) | 18 | 0 |

Judgment edits that follow, by a person or an editor, per instance (lists
in STYLE.md L-1 to L-5):

- Register, about 60: "deliberately" (14 cut), figurative verbs such as
  "rides", "launder", "blast radius", and "estate", and argument phrasing.
- "never" as an intensifier: 41 cut to "not" (2 in the ledger). The 44
  "never" rule predicates are kept.
- "this profile" and family or series uses: 46.
- Error phrasing, about 26: "responds with ... the `X` error code", citing
  the defining section once, in the table.
- Openers for Security Considerations and Privacy Considerations that
  point to the base specifications' considerations. RFC 8693 Section 5
  is the model; neither section has one today.
- Twenty requirement sentences rewritten actor-first or condition-first
  (STYLE.md Part 5; three carry a ledger cost).

## D. Track 2: structure and readability

The rule for readability versus scanability: a numbered list for parallel
checks, validation steps, and enumerations (the RFC 9449 Section 4.3
shape); prose where clauses reason about one another. A condition always
travels with its keyword.

- **Moves:** B7.
- **One new list: the derivation processing order in Section 9.2,**
  modelled on Section 4.4. The authorization server's central checks are
  now spread over L1893, Section 9, L2857, L2995, Section 10.1, and the
  `exp` clamp. This is a restructure of existing rules, not new
  requirements.
- **Enumerations buried in prose** (STRUCT.md Part 5), to become lists:
  - the introspection `mission` member (L3579-3600, one 200-word
    sentence);
  - the carrier preference order (L1535);
  - the `expires_at` acceptance and recovery rules (L816-835);
  - the three `openid` cases (L1831);
  - the grant types (L1893).
- **Bullets that carry an argument**, to return to prose or be split into
  rule and reason: L961, L1193, L1317, L722, L4542 (a 190-word bullet).
- **Long paragraphs.** Each classifier's Part B gives every over-long
  paragraph a target shape. 25 sample rewrites (five per region) are
  written as plan blocks, and all 25 pass an `apply_plan.py` dry run
  against the #864 head. They preserve every keyword with its party and
  condition unless the disposition says otherwise.
- **Signal to noise.** STRUCT.md Part 4 lists fifteen passages. Together
  they account for about 2,700 words cut and 2,800 moved off the
  normative path. The largest:
  - Consent Binding's restatement of Local Approved-Set Verification
    mechanics (about 330);
  - the child-Mission cascade text in Grant Binding (about 250);
  - the Resource Server denial cases that restate the error table (about
    180);
  - the smallest-conforming-deployment text in Conformance (about 280).
- **Terminology** (STRUCT.md Part 7):
  - "Mission Record" versus "Mission record" (21 and 17);
  - three names for the grant binding;
  - four names for the runtime layer;
  - "Mission-referenced token" is defined but never used;
  - "Submission envelope" is defined twice.

## E. Track 3: normative dispositions

| Class | Count | KEEP | Other dispositions |
| --- | --- | --- | --- |
| INTEROP | 131 | 114 | RECAST 9, NARROW 4, DEMOTE 3, MERGE 1 |
| DUPLICATE | 107 | 0 | pointer 63, DEMOTE 23, MERGE 19, RECAST 2 |
| SEC-OBS | 80 | 69 | RECAST 8, MERGE 3 |
| EXT-HOOK | 41 | 19 | DEMOTE 14, RECAST 3, MERGE 2, pointer 2, NARROW 1 |
| DEPLOYMENT | 37 | 1 | DEMOTE 33, RECAST 2, MERGE 1 |
| RESTATES | 25 | 0 | pointer 18, NARROW 4, DEMOTE 2, RECAST 1 |
| LOCAL-IMPL | 23 | 0 | DEMOTE 15, RECAST 6, MERGE 1, pointer 1 |
| SECCONS | 11 | 0 | DEMOTE 8, MOVE 3 |
| AUDIT | 7 | 0 | DEMOTE 7 |
| **Total** | **462** | **203** | **259** |

- **Result:** about 245 of 462 occurrences keep BCP 14 force (53%).
  Security and Privacy Considerations end with no keywords of their own.
  Five move to the body (#422, #424, #426, #438, #442); IANA keeps three
  Designated Expert keywords.
- **Ledger:** no tested row is reworded by the dispositions (B3 is the
  exception if adopted). One tested row retires unless B9 keeps it, and about nine untested rows are reworded in the same commits
  as their clauses. The classifiers kept every tested quoted clause
  verbatim, which the ledger check (d) requires.
- **Ledger drift since the review base.** PR #867 merged to main after
  `162b63e1` without touching the core's text. It moved eight
  scope-projection rows from todo to tested or partial, so the core now
  has 44 tested rows. The dispositions touch none of the eight. STYLE.md
  rewrite 5.14 now touches a tested row (`core.tokens.scope-ceiling`).
- **Recast** (31): a rule on internal state becomes its observable
  outcome, the same party under the same condition. Example: #49, "The AS
  MUST treat the submission as a proposal", becomes a declarative
  statement, with the observable bounds kept at #59, #77, and #88.
- **Restatements** (25): each quotes its dependency sentence. They cover:
  - RFC 9396 Sections 5 and 7;
  - RFC 9068 Section 4;
  - RFC 9700 Sections 2.2.1 and 2.3;
  - RFC 8707 Section 2;
  - RFC 8785 Section 3.1;
  - RFC 8693 Section 4.3;
  - RFC 7636 Section 4.6;
  - RFC 8705 Section 3 and RFC 9449 Section 6.2.
- **Duplicates.** The same rule is stated three to eleven times. The
  worst:
  - capability optionality, 11 times;
  - opaque-token introspection is required, 5;
  - prose members have no machine meaning, 5;
  - `client_id` meaning, 5;
  - `authority_hash` stays off the claim, 5.
- The full list is in DISPOSITIONS.md, grouped by disposition and class,
  with each proposal and dependency quote. The per-region JSONL files
  hold every row.

## F. Apply plan (after the rulings)

1. Branch from `162b63e1` as a second PR stacked on
   `docs/oauth-core-reading-path`. #864 keeps its no-normative-change
   claim and merges first.
2. Commit A1-A12 one per defect, then Track 1 commits 1-9 (each checked
   with `noop_check.py`).
3. Structural moves (B7): whole sections by script, with no anchor
   changes.
4. Track 3, one commit per class per region. Each moves ledger text in
   the same commit when a quoted clause changes.
5. Track 2 register and paragraph work: six opus section editors in
   detached worktrees under frozen EDIT-RULES. They get RECORD.txt and a
   length budget: -12% to -15% for the long-paragraph set, +/-3%
   elsewhere.
6. Verification:
   - an obligation verifier over RECORD.txt (SAME, RESTRUCTURED-OK,
     CHANGED, MISSING, or ADDED, judged on party, condition, behavior,
     and keyword);
   - `condition_record.py leads` for keywords that newly open a
     paragraph;
   - a post-churn consistency reader;
   - `normative_diff.py` on the fix commits.
7. Re-pin the core in `conformance-manifest.json`. Then run the family
   and conformance manifest checks, their tests, `make lint`, and a full
   build.

Estimated cost is about 1.2M subagent tokens. The expected result is a
body 12-15% shorter, with about 2,800 more words moved to appendices.

## Files (`notes/audits/2026-09-29-core-editorial-review-inputs/`, untracked)

- This file, and `2026-09-29-core-editorial-review-dispositions.md` (every non-KEEP row).
- STRUCT.md (structure), STYLE.md (language and tone).
- CLASS-R1..R5.md and .jsonl (per-region audit, paragraph shapes, noise,
  25 sample rewrites).
- RECORD.txt (the fixed sentence record), LEDGER-core.tsv, BRIEF.md,
  ALL.json (every row). The reviewed text is `git show 162b63e1:draft-mcguinness-oauth-mission.md`.
