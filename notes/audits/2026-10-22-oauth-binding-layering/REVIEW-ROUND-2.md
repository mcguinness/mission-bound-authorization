# Fresh-Eyes Review of PLAN.md Revision 2

Reviewed: `PLAN.md` at commit `3884d21b1`, branch
`worktree-notes+oauth-binding-layering-plan`, base `5344f4ed6`.

Two reviewers with no prior context read it. A fact-checker checked
about 150 claims: about 131 were confirmed, with 1 error, 3
consistency problems and 15 minor issues. A cold reader (WG reviewer
and implementer persona) gave 3 blockers, 5 majors and several minors.
Every finding below was re-verified against the repository before it
was recorded here; "Verified" names the evidence.

## Verdict

Revision 2 is accurate on almost every number. Its main proposal (P1)
does not survive the review:
- moving the designation protocol out would break three base MUSTs;
- the Actor Profile cannot leave the submission set, because Resource
  Access needs it through the binding;
- what P1 can actually achieve is removing client-instance-id, which
  #1412 already scoped as its option B.

P4's premise is wrong. P2 should shrink to a body-only edit. Revision
3 should be a smaller plan.

## Blockers

### B1. P1 moves three exceptions that qualify base MUSTs

No family draft declares `Updates:`, so a companion cannot relax a
base MUST. Verified: `grep -l '^updates:' draft-*.md` finds none.

| Exception | Base MUST it qualifies | Problem if the exception moves |
|---|---|---|
| Self-Exchange: "A designation ... names a delegate, so it is not a self-exchange, and these rules do not apply to it" (3724-3726) | Rule 1: refuse a no-actor exchange unless the client is the approved agent (3728-3732) | A designation request carries no actor, and a delegate may hold a designation ("otherwise the delegate that the AS's accounting records", 3543-3545). Without the exception, rule 1 refuses it. Revision 2 keeps the sentence but moves its row and anchors it to a companion concept. |
| Introspection: a designation gets "`active: false` ... with no `mission` member" (3318-3320) | Terminated Mission: "MUST return `active: false` and include `mission.state`" (3327-3329) | Today it is an in-document exception. In a companion it contradicts the base. Revision 2's disposition R5 checked only the `active: true` condition. |
| Token Claims `aud`: a token "only for presentation back to itself at a Token Exchange, such as a designation" (2500-2502) | `aud` MUST name the consuming resource servers | Revision 2 already keeps this one. |

**Fix (cold reader).** Define, in the base, one class: a token the AS
issues only for presentation back to itself. State all three
exceptions against that class.

### B2. The Actor Profile cannot leave the submission set

- Resource Access's `sub_profile` matcher cites the binding for the
  `act` claim's `sub_profile` member (RA 1162-1165).
- RA requires the AS to "assert the actor's `sub` and `sub_profile`
  itself" (RA 1173-1176).
- RA's references do not include the Actor Profile. Verified.

So under P1-R1 option (a), or any option that takes the Actor Profile
members out of the binding, RA must cite the Actor Profile or the
unsubmitted companion. That is the cost revision 2 used to reject
variant C. Counted over the submission set (binding plus Resource
Access, C9), P1 removes client-instance-id only.

### B3. Delegation's capability bar would leave the base, contrary to C1

- Revision 2 keeps normative Delegation Constraints and five
  `core.delegation`-gated rows in the base, but moves the capability's
  conformance to the companion.
- It gives `core.delegation` two meanings (PLAN lines 416-417: "the AS
  supports the designation protocol"; line 744: "a delegation profile
  is implemented").
- Moving "The exchange is explicit" also removes the audience-replay
  defense ("an access token issued for resource access is never
  sufficient", 3589-3592) and the residual analysis that rests on it
  (5335-5354).

**Fix (cold reader).** If the designation protocol moves at all, the
base keeps a Delegation capability with a self-contained bar, as the
Cross-Domain capability already has (4982-4999). The bar covers:
- the delegate model;
- depth accounting;
- the delegate's own key;
- no resource-access token as the delegating `subject_token`.

The companion then supplies the interoperable mechanism.

## Major

- **M1. Hidden decisions.** These are missing from Section 8:
  - whether the new companion joins the submission set;
  - D559's trigger, a concrete publication plan (P1 reopens D559 on a
    different premise and supplies no plan);
  - #1503 finding 11;
  - who owns the `delegated-exchange` anchor;
  - the companion's `Updates` relationship.
- **M2. Section 8 is not decidable.**
  - It has recommendations only: no options, cost, effect or
    prerequisite.
  - "Go, variant B" contradicts Section 9, which rules P1 only after
    the maps exist.
  - P1 and P1-R1 are one decision.
  - P2 bundles a body-only edit (no IANA cost) with a registry.
- **M3. Appendix A is incomplete.**
  - In-base references to the moving anchors have no disposition:
    lines 527, 531, 863, 1216, 2292, 2504, 3368, 5219, 6385 and 6529.
    A build fails on dangling anchors.
  - The `invalid_client_attestation` note (3210-3214) cites
    client-instance-id Section 5.2 but is not in the move list.
    Verified.
  - The accounting-completeness list (3772-3777) and Self-Exchange
    3731-3732 point at the designation and delegated exchange.
  - Four more rows are affected by witness re-checks or P1-R1:
    - `core.introspection.malformed-token-inactive`;
    - `core.tokens.client-id-requesting-client`;
    - `core.issuance-gating.after-acknowledged-revocation`;
    - `core.tokens.response-authorization-details-exact`.
- **M4. P2's registry design contradicts itself.**
  - A "Basis class: `direct`" field reopens `direct`, which the draft
    "defines ... in full" (4136). Verified.
  - Seeding only `direct` while the four companion short names "stay
    valid until registered" contradicts "a short name is registered
    before use".
  - The taxonomy amendment would sweep in integrity-anchor `typ`, which
    has a MUST but "no registry of `typ` values" (4529-4533). Verified.
    It would also sweep in `adjudication.kind` and evidence types.
- **M5. A simpler path was not weighed, and the questions are not
  answered directly.**
  - The variant "move Instance Context only" is never evaluated. It is
    #1412 option B: 65 lines, 3 todo rows, 1 annotation.
  - P5's "ask the WG first" logic applies equally to P1.
  - 5.4 items 4 and 5 get no disposition.
  - The plan never answers the owner's four questions in one place.

## P4 premise is wrong

The base itself uses the non-envelope species. `authority_source.policy.digest`
"is a prefixed commitment ({{commitment-mechanisms}}) whose exact
committed input and construction the policy's format specifies: its
species and, for an envelope anchor, its `typ` ..." (4277-4283).
Verified. P4 should be withdrawn, not deferred.

## Factual corrections (fact-checker, verified)

| Location | Correction |
|---|---|
| C10, Section 4 | Stale. D645 "settles D427's open decisions on the editor's-copy citations" (`src/PLAN.md` line 730). P3's pairing with C10 goes. |
| Section 3 | Resource Access `-00` publication is D646 (2026-10-22); D645 is the ruling and merge. |
| C7 | rar-metadata-remediation became normative under D620 (#1503 finding 9); the Actor Profile under D625 (#1516). |
| Section 3 | D140 and #708 record the substrate's reference to the binding becoming informative, not the reverse. The binding's informative substrate reference stands on its front matter. |
| Section 11, row 1 | By the plan's definition, variant C is 21 rows (16 tested, 1 partial, 4 todo). The chat's 20 counted only rows anchored in the Delegation section. |
| 7.4, Q5 | Five "both" paragraphs, not four: Orchestration 410 too. |
| `@spec` counts | With Markdown files: `mission#designation` 23 in 12 files, `mission#delegation` 21 in 11, `mission#delegation-constraints` 28 in 16. The extras are `src/config/README.md:45`, `src/docs/issuance-only-deployment.md:639` and `src/docs/resource-access-transformation-capabilities.md:172`. |
| 7.1 | "designation" is on 37 lines (47 occurrences). The one Transaction Authorization hit (line 359) is another sense of the word. |
| 7.1 | Only Cross-Domain 814 covers the depth reset (the reset is at 818). 411 and 858 cite other parts of Delegation Constraints. |
| 7.1 | Derivation Limits 365 counts the delegated-token Token Exchange as a derivation, so it needs repointing whatever P1-R1 decides. |
| 7.1 | "every derivation, refresh and Token Exchange" is the Implementation Map (524), not Issuance Gating (2432-2434). |
| 5.4 item 3 | The envelope-anchor list is at 4599-4602; line 4654 is the classification sentence. |
| Ranges | Standing consent ends at 4008 (865 words); the Token Exchange bullet ends at 2336. |
| 5.3 | `6a7c616e` is dated 2026-10-19 (-0700). |
| Appendix B | Missing vocabulary: Approval Governance 217 (envelope anchor); Approval Governance 1470 and Expansion 1650 (commitment mechanisms). |
| `measure.py` | Job buckets are numbered 1, 2, 3, 5, 6, and the comment points to "Section 2". The counts are right. |

## Minor (cold reader)

- **Section 6.**
  - RFC 9396 leaving `type` to the AS is a precedent *against* a P2
    registry.
  - RFCs 7009, 7662, 8693 and 8414 were written as separate documents,
    not extracted from RFC 6749, so they are not extraction precedents.
- **Designated Expert style.** The base's registries use "A Designated
  Expert MUST reject" (5780, 5804). P2's "create no obligation" breaks
  that house style.
- **Remediation Grains** is a closed list ("The three remediation
  grains", 3093). Moving the AuthZEN grain needs an open list.
- **Section 10.** "Shorter" and "materially longer" have no unit. Add
  an obligation-diff criterion, a no-coverage-loss criterion, and a
  submission-set dependency count with a baseline (111 citations).
- **Readability.**
  - Section 1 (dispositions) comes before the question.
  - "Move-on-touch", "Issue Convention" and "act-bearing" are
    undefined.
  - `-delegation` reads as an umbrella beside `-child-delegation` and
    `-cross-org-delegation`.
  - Cross-Org Delegation was never assessed as an existing home.

## Recommended shape for revision 3

1. **Open with "Answers"**: one paragraph per owner question. Move the
   review dispositions to an appendix.
2. **Narrow P1 to Instance Context**: Instance Context in Delegated
   Tokens, error rows 3196 and 3197, and the note at 3210-3214, moved
   to an existing home first (client-instance-id itself, or a
   companion), leaving an extension point.
   - This is #1412 option B. It removes client-instance-id from the
     submission set's normative references.
   - Its trigger (a publication plan) still governs. Say so, or ask
     the owner to waive it.
   - The designation protocol, the delegate model and the Actor
     Profile stay in the base (D625). P1-R1 then has nothing to decide.
   - Keep the base-class and Delegation-bar design (B1, B3) as the
     route if the designation protocol is ever moved for readability;
     the reading tasks in Section 10 would measure it.
3. **Add the two unledgered delegate MUSTs** (3609, 3617) as rows,
   independent of any move.
4. **P2 becomes body-only.**
   - Rephrase lines 3913, 3935 and 3937 for "a standing-consent basis",
     keeping each keyword and condition.
   - Turn the four-value list into an informative example.
   - No registry. If a registry is ever wanted, it needs the M4 fixes.
5. **P3 stays**, by semantic ownership. Drop the C10 pairing. Keep the
   AuthZEN grain unless the grains list is opened, with a non-widening
   invariant.
6. **Withdraw P4**, because the base uses the species. Keep the import
   inventory as a record.
7. **P5 stays.**
8. **Section 8** becomes one row per decision: options, recommendation,
   cost, effect and prerequisite.
9. **Apply the factual corrections above.**
