# OAuth Binding Layering: Plan for Review (revision 3)

Status: proposal for review, revision 3 (2026-10-22). Nothing has been
filed or edited in any draft, the ledger or `src/`.

Two review rounds came before it:
- Round 1 reviewed revision 1: "revise before approving execution".
- Round 2 was a fresh-eyes review of revision 2, recorded in
  `REVIEW-ROUND-2.md`.

Revision 3 is smaller than revision 2. The designation-protocol move is
withdrawn, P1 is narrowed to Instance Context, P2 becomes a body-only
edit, and P4 is withdrawn. Appendix C records how each review point was
handled.

## 0. Instructions for the reviewing model

- **Base commit:** `origin/main` at `5344f4ed6`. The OAuth binding,
  the substrate, Resource Access, Discharge and Consent Evidence are
  byte-identical to `d7ab66ff9`, where the analysis began.
- **Line numbers** refer to `draft-mcguinness-oauth-mission.md` at the
  base commit unless another file is named.
- **Reproduce the counts** from the repository root (standard library
  only):
  - `python3 notes/audits/2026-10-22-oauth-binding-layering/measure.py`;
  - `python3 notes/audits/2026-10-22-oauth-binding-layering/companion_cites.py`
    (named-section citations only, so it cannot prove absence);
  - `python3 notes/audits/2026-10-22-oauth-binding-layering/commitment_imports.py`
    (the record behind withdrawn P4).
- **What we want from you:**
  - a verdict per decision in Section 8;
  - any factual error, with evidence;
  - any blast radius we missed;
  - any conflict with Section 4.
- **Do not** recommend merging existing drafts (C2) or moving a family
  companion into the binding's normative references (C1).

## 1. Answers to the owner's questions

**Q1. Does it make sense to split the binding out from a core spec
that does issuance?**

No document split.
- The binding *is* the issuance protocol. The content that is purely
  "binding" (mapping the protocol onto the substrate kernel) is two
  informative appendices: the Mapping Assessment (1,157 words) and Role
  Mapping (477 words). Informative appendices are the conventional
  place for it.
- The literal split, a binding-neutral Mission Model draft beneath the
  binding (#207), stays parked. None of its triggers has fired, and the
  relocation round is large. OAuth convention does not forbid it:
  RFC 7521 is an abstract framework that RFC 7523 cites normatively.
- The one job that could leave for a dependency reason is Instance
  Context in Delegated Tokens (P1). It holds the binding's only
  normative dependency that nothing else in the submission set needs.

**Q2. Why does it reference so much of the family?**

140 citations of 30 family drafts, 111 of them in the middle matter.
Four causes:
1. **The binding is the only normative home left.** The substrate is
   an informative reference of the binding, and no companion may be a
   normative one (C1). So vocabulary several companions share at MUST
   strength lands in the binding, which then names its users. #880 is
   the explicit case.
2. **Some prose explains how companions behave**, mainly Grant
   Bindings and Related Mechanisms and Composition and the Effective
   Ceiling. P3 moves that prose to its owners.
3. **The examples use Resource Access's type.** The binding defines no
   `authorization_details` type, and Resource Access is its partner in
   the submission set.
4. **Some citations exist by ruling.** The Cross-Domain capability bar
   is stated in the binding with the companion informative (#169).

P2 removes the four citations in the standing-consent list.

**Q3. Why does it define things it does not use itself?**

| Item | Why it is there | Disposition |
|---|---|---|
| `approval_basis` structure under `direct` | Every member is derivable for `direct`, but #880 kept one uniform record that every substrate and companion reads | Keep (C3) |
| Standing-consent rules (lines 3881-4008) | One home for rules four companions share (#1483) | Keep. P2 removes only the companion list. |
| Commitment species | Not unused: the base's `authority_source.policy.digest` admits any species (lines 4277-4283) | Keep. P4 withdrawn. |
| `mission.expires_at` MUST for downstream profiles (line 2825) | A rule on the base claim's own member; the profiles that mint downstream credentials rely on it | Keep |
| Termination transition reading for legacy state values (line 2175) | Lets consumers read reports from earlier revisions | Keep for now. Removing it is a normative change, and needs a check that no emitter remains. |
| Delegation Constraints, with no issuance path in the base except Delegated Exchange | Shared invariants: Resource Access, Continuation and Cross-Domain rest on them | Keep (the reason revision 2's designation move was withdrawn) |

**Q4. What layering fits OAuth practice?**

Broadly the one the family has:
- the binding, which owns its issuance protocol, the record, its
  registries and a type-agnostic delegation discipline;
- Resource Access as the base `authorization_details` type;
- optional companions that define and register their own values;
- informative Architecture and Substrate documents.

The departures from common practice are smaller than the question
suggests:
- the binding names specific companions in normative text (P2, P3);
- its RFC publication is coupled to two individual drafts:
  - the Actor Profile coupling is deliberate (D625) and shared with
    Resource Access, which needs `sub_profile`;
  - client-instance-id is the one P1 addresses.

Section 6 gives the precedents both ways.

## 2. Terms

- **The binding** (or "the base"): `draft-mcguinness-oauth-mission.md`.
  #1089 retired calling it "core". In `DRAFTS.md`, "core" is the
  substrate kernel.
- **Submission set:** the binding plus Resource Access, the author's
  proposed initial OAuth WG set (#704, D140).
- **`act`-bearing token:** a Mission-bound access token whose `act`
  claim names a delegate (RFC 8693 Section 4.1).
- **Row, gate:** a ledger requirement in `conformance-manifest.json`,
  and the capability id its applicability names.
- **Move-on-touch:** the family's deferral policy, stated in the
  substrate's Family Use appendix: "Ownership migrates by touch, not by
  relocation".
- **Issue Convention:** the repository's issue template (Problem,
  Current state, Decisions of record, Analysis, Sketch, Acceptance).

## 3. Context

- **Publication state.**
  - The binding's `-01` is on the datatracker (D644, 2026-10-21).
  - Resource Access `-00` is published (D646, 2026-10-22).
  - No other family draft has a datatracker revision.
  - The binding is an editor's draft: findings are filed as issues
    first, and it changes only through a reviewable PR on the owner's
    go.
- **References.**
  - The binding's references to the substrate and to every companion
    are informative.
  - The AAuth, UMA, GNAP and MAS bindings cite the substrate
    normatively.
  - Resource Access's only normative Internet-Draft is the binding.
- **The submission set's normative Internet-Drafts**, through the
  binding:
  - `draft-mcguinness-oauth-client-instance-id` (individual);
  - `draft-mcguinness-oauth-actor-profile` (individual);
  - `draft-ietf-oauth-rar-metadata-remediation` (WG).
- **Ledger.**
  - Rows are keyed by `spec` and `anchor`.
  - Applicability is `unconditional`, gated on one capability, or a
    `capabilities` set (`all_of` or `any_of`). Capability ids are
    declared in `model.capabilities`.
  - The checker (`scripts/check-conformance-manifest.mjs`) enforces no
    row-id prefix.
- **Implementation.** Optional AS surfaces are `ProviderCapability`
  switches in
  `src/services/authorization-server/src/adapters/capabilities.ts`.
  Code, tests and some docs carry `@spec <draft>#<anchor>` annotations.

## 4. Constraints and prior rulings

| Id | Ruling | Effect |
|---|---|---|
| C1 | The binding stands alone. It takes no family companion as a normative reference, and it states a capability's property bar in its own terms (#169, Option 2). | Anything that moves leaves a self-contained bar or an extension point behind. |
| C2 | Existing drafts are never merged. A new draft must pass New Draft Admission (`CONTRIBUTING.md` line 171), after an existing home is assessed. | P1 option B2 needs the test. |
| C3 | #880 kept the generalized `approval_basis`: shared vocabulary, REQUIRED on every record, breaking change otherwise, no hub draft. | No record change. |
| C4 | #1483 / D610 consolidated standing consent into one section. | P2 edits in place. |
| C5 | #882 moved the optional Approved-Set Verification capability to a companion. | Precedent for moving an optional capability that leaves no residual base obligations. |
| C6 | #1412 / D559 (2026-10-20) kept Instance Context and its normative client-instance-id reference "while its interoperability requirements remain". It names its trigger: a concrete publication plan for the binding. When triggered, assess an existing home first. | P1 follows D559. Executing it now needs the owner to waive the trigger. |
| C7 | D620 (#1503 finding 9) made rar-metadata-remediation normative, and D625 (#1516) the Actor Profile. The owner rejected keeping them informative. | No proposal reclassifies a reference while the text that needs it stays. |
| C8 | #207 (parked): the Mission Model split, with three triggers (an OAuth WG adoption conversation, asking the WG's document-architecture preference first; a second non-OAuth binding with real implementer commitment; MAS control-plane cadence). | P5 keeps it parked. |
| C9 | #704 / D140: the submission set is the binding plus Resource Access, and the substrate is withheld. | Count dependency changes over the submission set. A new normative substrate reference adds a dependency on a withheld draft. |
| C10 | D645 (2026-10-21) settled D427's open decisions on family editor's-copy citations and Resource Access's binding target. | Settled; this plan does not reopen it. |
| C11 | Working style: prefer existing surfaces; make minimal changes that preserve capability; an editorial change preserves every obligation (actor, trigger, scope), not just its keyword; every stated obligation needs a ledger row; ids and anchors stay stable. | Applies to every proposal. |
| C12 | No family draft declares `Updates:`, so a companion cannot relax or override a base MUST. | Exceptions to base MUSTs stay in the base. This is why revision 2's designation move was withdrawn (Appendix C, B1). |

## 5. Findings

### 5.1 Where the text sits

These counts measure placement, not how much text an implementer could
do without. Middle matter: 34,747 words, 261 BCP 14 keywords, 133
sections. Each section's count excludes its subsections.

| Job | Words | BCP 14 | Sections |
|---|---|---|---|
| 1. Issuance protocol, including approval | 21,872 | 193 | 79 |
| 2. RFC 8693 delegation profile, plus Optional Capabilities | 2,708 | 17 | 8 |
| 3. Hooks for companions and the extension framework | 5,036 | 51 | 14 |
| 4. Tutorial and examples in the middle matter | 947 | 0 | 4 |
| 5. Security, privacy, i18n, applicability | 4,184 | 0 | 28 |

Job 3 is mixed. For example, `record-principal-members` holds base
vocabulary next to the generalized `approval_basis`, and Commitment
Mechanisms holds rules the base's own commitments need. Appendices
total 7,321 words with no BCP 14 keywords.

### 5.2 Family citations

- 140 citations of 30 family drafts; 111 in the middle matter, which is
  the baseline for Section 10.
- The most-cited drafts: Resource Access 25, Cross-Domain 20, Approval
  Governance 9.
- The densest sections:
  - Grant Bindings and Related Mechanisms (line 2322): 6;
  - Composition and the Effective Ceiling (line 5428): 6;
  - Standing-Consent Bases (line 3881): 4;
  - Principals and Approval Basis (line 4128): 4.

### 5.3 Normative Internet-Draft references and publication

| Reference | Kind | Cited from |
|---|---|---|
| client-instance-id | individual | Instance Context in Delegated Tokens (8 citations); the error-table note (lines 3210-3214); appendix line 6450; Document History line 7290 |
| Actor Profile | individual | Delegation lead (3496 onward), Delegated Exchange (3602-3608), Instance Context (3664-3667); appendix line 6405. Resource Access's `sub_profile` matcher reaches it through the binding (RA 1162-1176). |
| rar-metadata-remediation | WG | Denial Responses, Remediation Grains, Authorization Server Metadata |

- **History.** At `6a7c616e` (dated 2026-10-19 -0700, the basis of
  D559), only client-instance-id was normative. `2e7c08608` (D620) and
  `e6f6c911a` (D625) added the other two on 2026-10-21.
- **What a normative reference costs.** RFC 7322 Section 4.8.6:
  "Normative references to Internet-Drafts will cause publication of
  the RFC to be suspended until the referenced draft is also ready for
  publication". The documents then publish together, and the RFC
  Editor queue shows the state as "Reference Not Received" (queue
  About page).
- **What it does not cost.** It does not block submission, adoption or
  last call. The cost is a coupled RFC publication date.
- **Side finding.** `notes/oauth-wg-submission-set.md` lines 56-60
  predate `2e7c08608`. They still say `DEPENDENCIES.md` has no
  external-normative-ids entry for the binding; line 20 of
  `DEPENDENCIES.md` now lists rar-metadata-remediation.

### 5.4 Delegated-token obligations without ledger rows

Two MUSTs in Delegated Exchange have no row:
- "Authority only narrows" (line 3609);
- "Each delegate is bound to its own key" (line 3617).

The only Delegated Exchange rows are
`core.delegation.designation-only-subject-token` and
`core.delegation.redemption-evaluated-afresh`. P1b adds the missing
rows.

## 6. Precedents and trade-offs

Each was verified against the RFC text.

| Choice | For | Against, or the trade-off |
|---|---|---|
| A registry for an extensible value | RFC 6749 Section 11, RFC 7519 Section 10.1 | RFC 9396 creates no `type` registry: "The AS controls the interpretation of the value of the `type` parameter" (Section 2.1). A registry costs IANA review time. |
| Requirements on future extensions | RFC 6749 Section 8 states them in its body ("All other types MUST be registered"). The binding's registries also instruct the Designated Expert in BCP 14 ("A Designated Expert MUST reject", lines 5780 and 5804). | RFC 8126 expects registry guidance for the expert (Section 1.3, item 7). Body rules and expert guidance complement each other. |
| Optional features in their own documents | RFC 7009, 7662, 8693 and 8414 were written as documents separate from RFC 6749; GNAP's RS connections were published as RFC 9767, separately from core RFC 9635 | These were separate from the start, not extracted. A later extraction is justified by an independent dependency or independent adoption, not by size. |
| An abstract framework under concrete profiles | RFC 7521, cited normatively by RFC 7523 Section 9.1 | Convention allows it; whether to do it is a trigger and cost question (P5). |
| Normative references to Internet-Drafts | Allowed; dependent documents publish together (RFC 7322 Section 4.8.6) | They couple the RFC publication date. |

## 7. Proposals

### 7.1 P1. Instance Context in Delegated Tokens (`decide`, under D559)

**What the section does** (lines 3652-3717; 418 words, 4 BCP 14
keywords):
- When a deployment conveys `client_instance` in delegated tokens, the
  AS uses the presenting instance validated under client-instance-id
  Section 5. It associates that instance with the separately
  authenticated delegate and binds the output token to an
  instance-unique key.
- It MUST NOT substitute context copied from an input token.
- Where policy requires attribution, it MUST refuse when the evidence
  or the association cannot be established.

Most of this is generic Token Exchange plus instance-context behavior.
The Mission-specific part is one paragraph (lines 3693-3699): instance
evidence satisfies none of the binding's authorization checks for the
exchange.

**Options.**

| Option | Change | Effect |
|---|---|---|
| A. Keep (D559, recommended now) | none | client-instance-id stays a normative dependency of the submission set until D559's trigger fires. |
| B1. Upstream, when triggered (recommended destination) | The generic delegated-token rules move into client-instance-id itself, which the author controls. The binding keeps an extension point: a deployment conveying `client_instance` in delegated tokens follows client-instance-id, and instance evidence satisfies none of this document's authorization checks (the current 3693-3699, kept). | client-instance-id becomes informative in the binding. The submission set's normative I-Ds go from three to two (Actor Profile, rar-metadata-remediation). |
| B2. New companion | The whole section moves to a small Mission companion. | Same dependency effect as B1, plus one more draft. Needs New Draft Admission. |
| B3. An existing companion | Child Delegation cites client-instance-id for Child Missions' actors; runtime-oauth has Required Instance Attribution at the PEP | Neither has this contract (same-Mission delegated tokens issued by the AS). Not recommended. |

**What moves under B1 or B2:**
- the section;
- Error and Challenge Mapping rows 3196 (`invalid_client_attestation`)
  and 3197;
- the note under the tables (lines 3210-3214), which names
  client-instance-id Section 5.2 as the source of
  `invalid_client_attestation`.

**What stays:**
- the Mission-specific paragraph (3693-3699) as the extension point;
- the future-work example at line 6450 and Document History at line
  7290. client-instance-id becomes an informative reference for these.

**Blast radius (B1 or B2).** The full map is in Appendix A.
- 3 ledger rows (all `todo`, gated `core.instance-context`), re-anchored
  or retired depending on the destination. No provider switch exists.
- One `@spec` annotation (`src/packages/mission-core/src/idempotency.ts`
  line 106).
- No companion cites the section; companions that use Instance Context
  cite client-instance-id directly (AuthZEN, MAS, Architecture,
  runtime-oauth).
- The Actor Profile stays normative (C7): the delegate model and
  Resource Access's `sub_profile` need it.
- **Prerequisite:** D559's trigger (a concrete publication plan), or an
  owner waiver. B1 also needs a client-instance-id revision, which is a
  separate document outside this repository.

### 7.2 P1b. Ledger rows for the two delegated-token MUSTs

Add rows for lines 3609 and 3617 (5.4), gated `core.delegation` and
anchored at `delegated-exchange`.
- Candidate witnesses: the "who presents which proof" and "authority
  bounds every exchange" blocks of
  `src/services/authorization-server/test/delegation-exchange.test.ts`
  (lines 546 and 691).
- Mark a row `tested` only after a mutation run shows the test fails
  when the rule is disabled. Otherwise mark it `todo`.

This is independent of every other proposal. It changes no draft text.

### 7.3 P2. The standing-consent list becomes informative (body only)

- **Proposal.** Replace the normative list of four companion `type`
  values and their documents (lines 3887-3904) with one sentence:
  companion profiles define standing-consent `type` values, and the
  Architecture lists them under "Authorization bases" in its Mission
  Invariants section (`draft-mcguinness-mission-architecture.md` line
  1976, which names all four). The Architecture is already an
  informative reference of the binding. (Its Mission Creation Paths
  section names only two of the four, so it is not the pointer.)
- **Unchanged:**
  - every BCP 14 sentence, including the companion-directed rules at
    lines 3913, 3935 and 3937, whose actor (the defining
    specification) and conditions stay as written;
  - the `adjudication.kind` rule (line 4193);
  - the unknown-type rule;
  - the record shape;
  - the 7 ledger rows.
- **Effect:**
  - Four family citations leave the binding's normative text.
  - Nothing changes for implementations.
  - No IANA request.
- **Not proposed:** an Approval Basis Types registry. Revision 2's
  design reopened `direct`, contradicted its own name policy, and
  needed a Namespace Taxonomy amendment that would also sweep in
  integrity-anchor `typ` and `adjudication.kind` (Appendix C, M4).
  RFC 9396 is the precedent for leaving such values unregistered.

### 7.4 P3. Move explanations of companion behavior to their owners

- **Rule.**
  - *Stays:* a base rule; an exception to a base rule (C12); a security
    residual an implementer of the base needs where the rule is stated;
    and a one-sentence pointer where the base defers a mechanism.
  - *Moves:* an explanation of how a companion behaves.
- **Candidates** (line; family citations):
  - Grant Bindings and Related Mechanisms (2322; 6). Keep the Token
    Exchange bullet (2326-2336). Move the Cross-Domain, Child Missions
    and successors, and Continuation bullets, and the MAS-join
    paragraph, to those documents. Keep one sentence: a profile that
    creates another grant lineage or Mission states its relation to
    the grant binding.
  - Composition and the Effective Ceiling (5428; 6) and Authority
    Materialized Before Containment (5464; 2). Keep the base's own
    residual; move the cross-companion composition analysis to the
    Security Model guide.
  - Principals and Approval Basis (4128; 4) and Consent Binding (5053;
    3). Move the paragraphs on which profiles commit `approval_basis`
    to those profiles.
  - Remediation Grains (3090; 3). No move. The list is closed ("The
    three remediation grains", line 3093), and moving the AuthZEN grain
    would need an open list and a non-widening invariant.
  - Keep as they are: the security pointers in runtime-boundary,
    downgrade-by-omission, prompt-injection and
    information-propagation.
- **Each paragraph** gets a disposition in the issue: kept (with the
  reason), moved to X, or cut as a duplicate of X. Each moved paragraph
  lands in its companion in the same PR, so nothing is lost.

### 7.5 P4. Commitment species: withdrawn

The base uses the non-envelope species itself. `authority_source.policy.digest`
is "a prefixed commitment ({{commitment-mechanisms}}) whose exact
committed input and construction the policy's format specifies: its
species" (lines 4277-4283).

At least Discharge and Consent Evidence also import the binding's
section for those species, and repointing them would add a normative
dependency on the withheld substrate (C9). Appendix B keeps the
inventory as a record.

### 7.6 P5. Keep #207 parked

No trigger has fired (C8), and the relocation is large. Move-on-touch
already migrates ownership one change at a time. Convention neither
requires nor forbids the split (Section 6).

### 7.7 Withdrawn or not proposed

- **Moving the designation protocol (revision 2's P1 and P1-R1).**
  - It would move three exceptions that qualify base MUSTs (C12):
    - the Self-Exchange carve-out (3724-3726);
    - designation introspection (3318-3320);
    - the `aud` exception (2500-2502).
  - It would not remove the Actor Profile from the submission set,
    because Resource Access needs it.
  - It would take the Delegation capability bar out of the base,
    against C1.

  A readability-motivated version remains possible later. The base
  would define the class "a token the AS issues only for presentation
  back to itself" and hold all three exceptions against it, and keep a
  self-contained Delegation bar, as Cross-Domain has (4982-4999),
  covering the delegate model, depth accounting, the delegate's own
  key, and no resource-access token as the delegating `subject_token`.
  The companion would supply the mechanism. Pursue it only if the
  reading tasks in Section 10 show a gain.
- **Reclassifying a normative reference** while its text stays (C7).
- **Making `direct`-case members optional; a standing-consent hub
  draft** (C3).
- **Any merge** (C2).
- **Renaming ledger ids, capability ids or provider switches.**

## 8. Decisions for the owner

| Decision | Options | Recommendation | Cost | Effect | Prerequisite |
|---|---|---|---|---|---|
| D-1: Instance Context (P1) | A keep; B1 upstream to client-instance-id; B2 new companion | A now; B1 when D559's trigger fires | B1: a client-instance-id revision, 2 error rows and a note moved, 3 todo rows re-homed, 1 annotation | B1: the submission set's normative I-Ds go from 3 to 2 | D559's trigger, or a waiver |
| D-2: Delegated-token rows (P1b) | add; defer | Add now | Two rows; a mutation run per witness | Two stated MUSTs gain rows (C11) | None |
| D-3: Standing-consent list (P2) | informative pointer; keep | Pointer | One paragraph | Four companion citations leave normative text; no obligation changes | None |
| D-4: Companion-behavior prose (P3) | move by semantic ownership; keep | Move, paragraph by paragraph | Edits in the binding and each receiving companion; re-pins | Family citations in normative text fall from 111, each traced to a disposition | The obligation map for each moved paragraph (Section 9) |
| D-5: Mission Model split (P5) | keep parked; execute | Keep parked | None | None | A #207 trigger |
| D-6: Side finding (5.3) | update `notes/oauth-wg-submission-set.md`; leave | Update | One table and one sentence | The submission-set record matches the front matter | None |

## 9. Sequence and verification

**Sequence.**
1. D-2 and D-6. They are independent and small.
2. D-3. A single-paragraph PR.
3. D-4: produce the obligation map for the candidate paragraphs, then
   move them.
4. D-1 when its trigger fires.

Each step is one issue in the Issue Convention format, plus one PR.

**Obligation map** (for D-4, and for D-1 when it runs). For each
obligation in the moved text, BCP 14 or present-tense without a keyword
("is rejected with", "carries", "never"), record:
- actor;
- trigger;
- scope;
- exceptions;
- refusal (error and endpoint);
- conformance applicability;
- ledger row, or "none";
- witness test.

**Verification per PR.**
- The obligation map is identical before and after, except for changes
  the owner ruled on.
- The BCP 14 sentence record is necessary but not sufficient.
- A row keeps its coverage only after its witness is re-checked against
  the relocated text. Otherwise it is demoted, with the reason.
- Run the ledger and family-manifest checks, build every touched draft,
  and re-pin the companions that cite the binding.

## 10. Success criteria

**Dependency (measurable):**
- the submission set's normative Internet-Draft closure, now three
  (client-instance-id, Actor Profile, rar-metadata-remediation), is two
  after D-1 option B1;
- no new normative reference to a withheld draft.

**Obligation integrity:**
- the obligation-map diff contains only ruled changes;
- no `tested` row loses coverage without a recorded reason.

**Citations:** family citations in the binding's middle matter, from
111, with every removed citation traced to a D-3 or D-4 disposition.

**Readability.** A cold reader runs each task before and after,
recording sections read, documents opened, cross-document jumps and
errors. Use a model reader with no repository context, as in the
repository's reader checks.
1. Implement a Mission Issuer with no optional capability: list every
   token-endpoint obligation.
2. Implement a Mission-aware RS that receives delegated tokens.
3. Find every rule a new standing-consent basis must meet.
4. Find where Cross-Domain's grant-binding relationship is specified.

D-3 and D-4 succeed on readability if tasks 3 and 4 need no more
cross-document jumps than before, and tasks 1 and 2 need fewer sections.

## 11. Questions for review round 3

1. Is option B1 right? Is the Mission-specific remainder (lines
   3693-3699) enough of an extension point that no base MUST depends on
   the moved rules?
2. Does any base MUST outside the Instance Context section depend on
   `client_instance` or the two moved error rows?
3. P2: does replacing the list change any obligation? In particular,
   does any rule rely on the list's being the complete set of
   standing-consent values?
4. P3: which candidate paragraphs carry a rule rather than an
   explanation?
5. Are the readability tasks and their pass conditions the right ones?

## Appendix A. P1 map (options B1 and B2)

| Item | Location | Disposition |
|---|---|---|
| Section text | lines 3652-3717 | moves, except 3693-3699 |
| Mission-specific paragraph | lines 3693-3699 | stays as the extension point |
| Error row: Client Attestation fails | line 3196 | moves |
| Error row: instance association fails | line 3197 | moves |
| Error-table note on `invalid_client_attestation` | lines 3210-3214 | moves |
| Future-work example | line 6450 | stays; reference becomes informative |
| Document History mention | line 7290 | stays |
| `core.instance-context.current-presenter-binding` | ledger, todo | re-home or retire |
| `core.instance-context.no-input-substitution` | ledger, todo | re-home or retire |
| `core.instance-context.required-attribution-refusal` | ledger, todo | re-home or retire |
| Capability id `core.instance-context` | `model.capabilities` | keep while rows reference it |
| Provider switch | none | none |
| `@spec` annotation | `src/packages/mission-core/src/idempotency.ts:106` | repoint |
| Companion citations of the section | none | none |
| Actor Profile citation inside the section | lines 3664-3667 | moves with the text; the reference stays normative elsewhere |

## Appendix B. Commitment-vocabulary inventory (record for withdrawn P4)

From `commitment_imports.py`, by paragraph. "Both" means the paragraph
cites both binding and substrate.

| Draft | Line | Cites | Vocabulary |
|---|---|---|---|
| Discharge | 282, 679, 841 | binding | canonical-object; raw-octet; canonical-object and commitment mechanisms |
| Consent Evidence | 701 | binding | commitment mechanisms, raw-octet, agility, unrecognized-prefix, envelope anchor |
| Approval Governance | 217 | both | canonical-object, commitment mechanisms, Default Commitment Construction, envelope anchor |
| AuthZEN | 466 | both | canonical-object, Default Commitment Construction |
| Harness | 1414 | both | raw-octet, Default Commitment Construction |
| Transaction Authorization | 289 | both | canonical-object, raw-octet, envelope anchor, Default Commitment Construction |
| Orchestration | 410 | both | envelope anchor, Default Commitment Construction |
| Approval Governance | 1470, 1478 | binding | commitment mechanisms, envelope anchor |
| Expansion | 1650 | binding | commitment mechanisms, envelope anchor |
| Work Products | 493, 512 | binding | envelope anchor; unrecognized-prefix |
| Mandate | 285 | binding | algorithm agility |
| Audit, Capability Binding, Discovery, Evidence Envelope, Runtime, Runtime Evidence, Shaping | various | substrate | already sourced from the substrate |

## Appendix C. Review dispositions

**Round 1** (reviewing revision 1). All 17 points were agreed and
verified. Revision 2 recorded them in full; in summary:
- the missed introspection row;
- applicability-only changes;
- the provider switch name;
- the delegated-token scope question;
- appendix reference dispositions;
- P2 keeping the body rules;
- P4's missed importer;
- Section 6 recast as precedents;
- the RFC Editor queue state;
- obligation-level verification;
- semantic ownership for P3;
- the placement caveat;
- separate success criteria;
- the sequence.

Revision 3 supersedes the P1 and P2 dispositions. See `git log` for
revision 2.

**Round 2** (fresh eyes, reviewing revision 2; `REVIEW-ROUND-2.md`):

| Finding | Disposition in revision 3 |
|---|---|
| B1: the designation move takes three base-MUST exceptions with it | Agreed and verified (C12). The designation move is withdrawn (7.7). |
| B2: the Actor Profile cannot leave the submission set | Agreed and verified (RA 1162-1176). The dependency goal is restated over the submission set (Section 10). |
| B3: the Delegation bar would leave the base, contrary to C1 | Agreed. The designation move is withdrawn; the bar design is recorded for a possible later readability move (7.7). |
| M1: hidden decisions | Section 8 now lists every decision. |
| M2: Section 8 not decidable | Rebuilt with options, cost, effect and prerequisite. |
| M3: Appendix A incomplete | Rebuilt for the narrowed P1. It includes the error-table note and the annotation. |
| M4: the registry design contradicts itself | The registry is withdrawn; P2 is body-only. |
| M5: simpler path not weighed; questions unanswered | Section 1 answers the questions. The simpler path (Instance Context only) is now P1. |
| P4 premise wrong | Withdrawn (7.5). |
| Fact-checker corrections (C10 settled by D645; D646; D620 versus D625; D140 direction; variant C at 21 rows; five "both" paragraphs; `@spec` counts including Markdown; "designation" on 37 lines; Cross-Domain 814; Derivation Limits 365; the Implementation Map line 524; the envelope list at 4599-4602; range ends 4008 and 2336; the commit date; Appendix B vocabulary; script numbering) | Applied where the text survives into revision 3. Items about the withdrawn designation move are moot. `measure.py` buckets are renumbered 1 to 5. |
| Section 6, Designated Expert style, closed grains list, Section 10 units, undefined terms | Applied (Sections 6, 2, 7.4, 10). |

## Appendix D. Corrections log

| Earlier claim | Corrected |
|---|---|
| Chat and revisions 1 and 2: the Actor Profile can leave the binding's dependencies | It cannot leave the submission set: Resource Access needs `sub_profile` through the binding. |
| Chat: D427's editor's-copy question is unruled | D645 settled it. |
| Revision 2: move the designation protocol (15 rows) | Withdrawn (C12, C1). |
| Revisions 1 and 2: P4 targets species the base never uses | The base uses them through `authority_source.policy.digest`. |
| Revisions 1 and 2: a registry for approval basis types | Withdrawn; P2 is body-only. |
| Revision 2: "Resource Access -00 published (D645)" | D646. |
| Revision 2: C7 credits both references to D625 | D620 for rar-metadata-remediation; D625 for the Actor Profile. |
| Revision 2: `6a7c616e` dated 2026-10-20 | 2026-10-19 (-0700). |
