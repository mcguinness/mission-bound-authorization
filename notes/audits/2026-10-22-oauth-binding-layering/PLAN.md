# OAuth Binding Layering: Plan for Review (revision 5)

Status: proposal for review, revision 5 (2026-10-22).

**Outcomes (2026-10-23):**
- **D-2, D-3, D-4 and D-6:** executed in #1557 (merged `d5a22add`,
  D679).
- **D-1:** keep; D559 stands. #1412's body records the corrected
  inventory and the B1 conditions.
- **D-5:** #207 stays parked (comment on #207). Its two open questions
  await owner rulings.
- **D-7:** analysis in `D7-ACTOR-PROFILE-REFERENCES.md`. All five
  normative Internet-Drafts stay; promote identity-chaining. No material
  closure reduction.
- **Submission-set record:** re-bound in #1562.

Four review rounds came before it (Appendix C records how each finding
was handled):
- Round 1 reviewed revision 1.
- Round 2 was a fresh-eyes review of revision 2 (`REVIEW-ROUND-2.md`).
- Round 3 reviewed revision 3 at `66df29ee`.
- Round 4 reviewed revision 4 at `50e765c2f`, against main
  `635c1a1b6`.

Rounds 3 and 4 both found D-2, D-3, D-4 and D-6 ready to proceed.
Round 4 asked for three things:
- a complete obligation map for option B1;
- B1's retained text with its original qualifications;
- a reading task for every D-4 move.

It also corrected one Appendix E edge and asked for its two dependency
measurements to be distinguished.

## 0. Instructions for the reviewing model

- **Base commit:** `origin/main` at `5344f4ed6`. The binding, the
  substrate, Resource Access, Discharge and Consent Evidence are
  byte-identical to `d7ab66ff9`.
- **Line numbers** refer to `draft-mcguinness-oauth-mission.md` at the
  base commit unless another file is named.
- **Reproduce** from the repository root (standard library only):
  - `python3 notes/audits/2026-10-22-oauth-binding-layering/measure.py`;
  - `python3 notes/audits/2026-10-22-oauth-binding-layering/companion_cites.py`;
  - `python3 notes/audits/2026-10-22-oauth-binding-layering/commitment_imports.py`.
- **Newer main.** At `635c1a1b6` the binding is unchanged, and none of
  its 182 ledger rows that this plan names changed.
- **The external dependency inventory** (Appendix E) was read from the
  datatracker on 2026-10-22, at latest revisions. It is not
  reproducible offline, and it is not yet a verified closure.
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
  Mapping (477 words). That is where convention puts such content.
- The literal split, a binding-neutral Mission Model draft beneath the
  binding (#207), stays parked. None of its triggers has fired, and the
  relocation is large. OAuth convention does not forbid it: RFC 7521 is
  an abstract framework that RFC 7523 cites normatively.
- No other job leaves the binding now. Instance Context in Delegated
  Tokens is a candidate for later (P1), with a small dependency effect
  (Section 5.3).

**Q2. Why does it reference so much of the family?**

140 citations of 30 family drafts, 111 in the middle matter. Four
causes:
1. **The binding is the only normative home left.** The substrate is an
   informative reference of the binding, and no companion may be a
   normative one (C1). So vocabulary several companions share at MUST
   strength lands in the binding, which then names its users (#880).
2. **Some prose explains how companions behave**, mainly Grant Bindings
   and Related Mechanisms and Composition and the Effective Ceiling.
   P3 moves those explanations to their owners.
3. **The examples use Resource Access's type**, the binding's partner
   in the submission set.
4. **Some citations exist by ruling** (the Cross-Domain capability bar,
   #169).

P2 removes the four citations in the standing-consent list.

**Q3. Why does it define things it does not use itself?**

| Item | Why it is there | Disposition |
|---|---|---|
| `approval_basis` structure under `direct` | Every member is derivable for `direct`, but #880 kept one uniform record that every substrate and companion reads | Keep (C3) |
| Standing-consent rules (lines 3881-4008) | One home for rules four companions share (#1483) | Keep. P2 removes only the companion list. |
| Commitment species | Not unused: `authority_source.policy.digest` admits any species (lines 4277-4283) | Keep. P4 withdrawn. |
| `mission.expires_at` MUST for downstream profiles (line 2825) | A rule on the base claim's own member | Keep |
| Termination transition reading (line 2175) | Lets consumers read reports from earlier revisions | Keep. Removing it is a normative change that needs a check that no emitter remains. |
| Delegation Constraints | Shared invariants: Resource Access, Continuation and Cross-Domain rest on them | Keep |

**Q4. What layering fits OAuth practice?**

Broadly the one the family has:
- the binding, which owns its issuance protocol, the record, its
  registries and a type-agnostic delegation discipline;
- Resource Access as the base `authorization_details` type;
- optional companions that define and register their own values;
- informative Architecture and Substrate documents.

The real departures from common practice:
- **The binding names specific companions in normative text.** P2 and
  P3 address this.
- **Its RFC publication is coupled to a large set of dependencies.**
  The submission set has 3 direct external normative Internet-Draft
  references. The latest-revision inventory (Appendix E, not yet a
  verified closure) finds 16 distinct Internet-Drafts:
  - 13 are the Actor Profile (D625) and the 12 drafts it pulls in;
  - 2 are client-instance-id and the one draft it pulls in;
  - 1 is rar-metadata-remediation, which pulls in none.

  The publication coupling is a question about the Actor Profile's
  normative references, which live in that draft (D-7), more than about
  the binding's layering.

## 2. Terms

- **The binding** (or "the base"): `draft-mcguinness-oauth-mission.md`.
  In `DRAFTS.md`, "core" is the substrate kernel (#1089).
- **Submission set:** the binding plus Resource Access, the author's
  proposed initial OAuth WG set (#704, D140).
- **Direct external normative I-D reference:** an Internet-Draft in a
  submission-set document's `normative:` block, outside the family.
- **Cited-revision closure:** those references plus every
  Internet-Draft they cite normatively, recursively, each at the
  revision its citer names, with a source section for every edge. Not
  yet computed.
- **Latest-revision inventory:** the same traversal over each draft's
  latest revision, for planning (Appendix E).
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
    are informative. The AAuth, UMA, GNAP and MAS bindings cite the
    substrate normatively.
  - Resource Access's only normative Internet-Draft is the binding.
- **Direct external normative I-D references** of the submission set
  (all through the binding):
  - `draft-mcguinness-oauth-client-instance-id` (individual, `-00`);
  - `draft-mcguinness-oauth-actor-profile` (individual, `-01`);
  - `draft-ietf-oauth-rar-metadata-remediation` (WG, `-00`).

  Only rar-metadata-remediation is pinned (`notes/external-pins.json`).
  `DEPENDENCIES.md` skips `draft-mcguinness-*` references by prefix.
- **Ledger.** Rows are keyed by `spec` and `anchor`. Applicability is
  `unconditional`, one capability, or a `capabilities` set. Capability
  ids are declared in `model.capabilities`. The checker enforces no
  row-id prefix.
- **Implementation.** Optional AS surfaces are `ProviderCapability`
  switches in
  `src/services/authorization-server/src/adapters/capabilities.ts`.
  Code, tests and some docs carry `@spec <draft>#<anchor>` annotations.

## 4. Constraints and prior rulings

| Id | Ruling | Effect |
|---|---|---|
| C1 | The binding stands alone. It takes no family companion as a normative reference, and it states a capability's property bar in its own terms (#169, Option 2). | Anything that moves leaves a self-contained bar or extension point. |
| C2 | Existing drafts are never merged. A new draft must pass New Draft Admission (`CONTRIBUTING.md` line 171), after an existing home is assessed. | Applies to any new companion. |
| C3 | #880 kept the generalized `approval_basis`. | No record change. |
| C4 | #1483 / D610 consolidated standing consent into one section. | P2 edits in place. |
| C5 | #882 moved the optional Approved-Set Verification capability, which left no residual base obligations, to a companion. | Precedent. |
| C6 | #1412 / D559 (2026-10-20) kept Instance Context and its normative client-instance-id reference "while its interoperability requirements remain". Its trigger is a concrete publication plan for the binding; when triggered, assess an existing home first. | P1 follows D559. |
| C7 | D620 (#1503 finding 9) made rar-metadata-remediation normative; D625 (#1516) the Actor Profile. The owner rejected keeping them informative. | No reference is reclassified while text that needs it stays. |
| C8 | #207 is parked, with its three triggers. | P5. |
| C9 | #704 / D140: the submission set is the binding plus Resource Access, and the substrate is withheld. | Count dependency effects over the submission set. |
| C10 | D645 settled D427's open citation decisions. | Not reopened. |
| C11 | An editorial change preserves every obligation (actor, trigger, scope), not just its keyword. Every stated obligation needs a ledger row. A row is not retired because neighboring text moves. Ids and anchors stay stable. | Applies everywhere. |
| C12 | No family draft declares `Updates:`, so a companion cannot relax or override a base MUST. | Base-MUST exceptions stay in the base. |

## 5. Findings

### 5.1 Where the text sits

These counts measure placement, not how much text an implementer could
do without. Middle matter: 34,747 words, 261 BCP 14 keywords, 133
sections.

| Job | Words | BCP 14 | Sections |
|---|---|---|---|
| 1. Issuance protocol, including approval | 21,872 | 193 | 79 |
| 2. RFC 8693 delegation profile, plus Optional Capabilities | 2,708 | 17 | 8 |
| 3. Hooks for companions and the extension framework (mixed: it also holds base vocabulary) | 5,036 | 51 | 14 |
| 4. Tutorial and examples in the middle matter | 947 | 0 | 4 |
| 5. Security, privacy, i18n, applicability | 4,184 | 0 | 28 |

### 5.2 Family citations

- 140 citations of 30 family drafts; 111 in the middle matter, which is
  the baseline for Section 10.
- The densest sections:
  - Grant Bindings and Related Mechanisms (line 2322): 6;
  - Composition and the Effective Ceiling (line 5428): 6;
  - Standing-Consent Bases (line 3881): 4;
  - Principals and Approval Basis (line 4128): 4.

### 5.3 Normative Internet-Draft dependencies and publication

**Where the binding cites the three direct references:**

| Reference | Kind | Cited from |
|---|---|---|
| client-instance-id | individual | Instance Context in Delegated Tokens (8); the error-table note (3210-3214); appendix line 6450; Document History line 7290 |
| Actor Profile | individual | Delegation lead (3496 onward), Delegated Exchange (3602-3608), Instance Context (3664-3667); appendix line 6405. Resource Access's `sub_profile` matcher reaches it through the binding (RA 1162-1176). |
| rar-metadata-remediation | WG | Denial Responses, Remediation Grains, Authorization Server Metadata |

**Latest-revision inventory** (Appendix E; read 2026-10-22; for
planning, not yet a verified closure): 16 distinct Internet-Drafts.

| Reached through | Distinct I-Ds, including the root | Notes |
|---|---|---|
| Actor Profile | 13 | The Actor Profile plus 12 it pulls in: Transaction Tokens, four WIMSE drafts, ID-JAG, rfc7523bis, identity-chaining, an individual draft (`draft-mora-oauth-entity-profiles`) and an expired individual draft (`draft-parecki-oauth-jwt-dpop-grant`, through ID-JAG). One node, `draft-ietf-tls-rfc8446bis`, is reported as published (RFC 9846). |
| client-instance-id | 2 | client-instance-id and Attestation-Based Client Authentication (WG consensus, waiting for write-up) |
| rar-metadata-remediation | 1 | No normative I-D references |
| Total | 16 | 15 unpublished |

- **What a normative reference costs.** RFC 7322 Section 4.8.6:
  "Normative references to Internet-Drafts will cause publication of
  the RFC to be suspended until the referenced draft is also ready for
  publication". The RFC Editor queue shows the state as "Reference Not
  Received", and dependent documents publish together.
- **What it does not cost.** It does not block submission, adoption or
  last call. The cost is a coupled RFC publication date. The
  cited-revision closure, not the direct list, determines it.
- **Consequence for P1.** If all its conditions held (7.1), option B1
  would take the direct references from 3 to 2 and the latest-revision
  inventory from 16 to 14. The Actor Profile's subtree, 13 of the 16,
  would be unchanged.
- **Side finding.** `notes/oauth-wg-submission-set.md` lines 56-60 say
  `DEPENDENCIES.md` has no external-normative-ids entry for the
  binding. That predates `2e7c08608`; `DEPENDENCIES.md` line 20 now
  lists rar-metadata-remediation.

### 5.4 Delegated-token obligations without ledger rows

Two MUSTs in Delegated Exchange have no row:
- "Authority only narrows" (line 3609);
- "Each delegate is bound to its own key" (line 3617).

The only Delegated Exchange rows are
`core.delegation.designation-only-subject-token` and
`core.delegation.redemption-evaluated-afresh`.

## 6. Precedents and trade-offs

Each was verified against the RFC text.

| Choice | For | Against, or the trade-off |
|---|---|---|
| A registry for an extensible value | RFC 6749 Section 11, RFC 7519 Section 10.1 | RFC 9396 creates no `type` registry ("The AS controls the interpretation of the value of the `type` parameter", Section 2.1). |
| Requirements on future extensions | RFC 6749 Section 8 states them in its body. The binding's registries instruct the Designated Expert in BCP 14 (lines 5780 and 5804). | RFC 8126 expects expert guidance (Section 1.3, item 7). Body rules and expert guidance complement each other. |
| Optional features in their own documents | RFC 7009, 7662, 8693 and 8414 were written separately from RFC 6749; GNAP's RS connections were published as RFC 9767, separately from RFC 9635 | These were separate from the start, not extracted. A later extraction is justified by an independent dependency or adoption, not by size. |
| An abstract framework under concrete profiles | RFC 7521, cited normatively by RFC 7523 Section 9.1 | Allowed; whether to do it is a trigger and cost question (P5). |
| Normative references to Internet-Drafts | Allowed; dependent documents publish together (RFC 7322 Section 4.8.6) | They couple the RFC publication date to the whole closure. |

## 7. Proposals

### 7.1 P1. Instance Context in Delegated Tokens: keep now (D559)

**Recommendation: option A** (no change). D559's trigger has not
fired, and the dependency effect of moving the section is small (5.3).

**Candidate for later: option B1** (upstream into client-instance-id).
It is a candidate, not an established dependency reduction. It holds
only under the conditions below.

**What the section requires today: every paragraph** (lines
3652-3717). All of it applies only where a deployment conveys
`client_instance` in delegated tokens (the MAY at 3670) under the
optional Delegation capability.

| # | Lines | Content | Kind | Actor | Row | Depends on client-instance-id text? |
|---|---|---|---|---|---|---|
| a | 3654-3662 | Instance evidence does not establish the delegate's actor; the AS establishes the actor identity and its association with the instance separately | keyword-free | AS | none | Cites Section 5 for the premise; the rule stands without it |
| b | 3664-3668 | The delegated token's `cnf` is a key the instance possesses (a consequence of the delegate-key rule and the Actor Profile) | descriptive | none | none | No |
| c | 3670-3677 | A deployment MAY convey `client_instance`; client-instance-id owns attestation validation, instance-to-key association, mapping and Context Consumer validation; deployments configure use and whether attribution is required | MAY, scope | deployment | none | Yes (it delegates to the spec) |
| d | 3679-3691 | MUST use the presenting instance validated under Section 5, associate it with the delegate, and bind to an instance-unique key; map context under Section 7.1; MUST NOT substitute copied or remapped input context | MUST | AS | `current-presenter-binding`, `no-input-substitution` (both todo) | Yes |
| e | 3693-3699 | The checks of Delegated Exchange and Delegation Constraints still authorize the exchange; instance evidence satisfies none of them by itself. Where policy requires attribution, MUST refuse when evidence or association cannot be established. Points at the error mappings. | keyword-free and MUST | AS | `required-attribution-refusal` (todo) for the MUST; none for the first sentence | The MUST, yes (it uses "required instance evidence" and "association"); the first sentence, no |
| f | 3701-3704 | If the exchange issues a refresh token, the grant-continuity rules of Section 5.1 apply alongside the grant binding; instance continuity alone does not authorize replacing the recorded instance or rebinding the key | keyword-free | AS | none | Yes for the first clause; the second clause is the binding's own |
| g | 3706-3709 | Consumers establish presenter attribution under Sections 7.3 and 7.5; a consumer requiring attribution rejects unestablished associations under Section 7.6 | keyword-free | consumer (RS) | none | Yes (it restates client-instance-id's consumer rules) |
| h | 3711-3716 | This composition adds no provenance to `client_instance`; direct-attestation trust is usable only when the issuer meets that configuration's restriction on upstream context; an issuer conveying upstream context needs a separately specified, authenticated provenance mechanism before its context supports attribution | keyword-free | consumer, issuer | none | Yes for the configuration restriction; the "needs a provenance mechanism" rule is the binding's own |

Error mappings: table rows 3196 (`invalid_client_attestation`) and
3197 (association failure, `invalid_request`), and the note at
3210-3214. Six of the eight paragraphs carry obligations; only two of
them have rows (C11).

**Option B1, exact before and after** (a candidate).
- *Before:* lines 3652-3717, rows 3196 and 3197, and the note
  3210-3214.
- *After:* the binding keeps the binding's own rules, with their
  original wording and qualifications:

  > Where a deployment authenticates client instances, the delegate
  > named by the outermost `act` can be an actor that an authenticated
  > instance represents. Instance evidence does not establish that
  > actor, so the AS establishes the delegate's actor identity, and
  > that actor's trusted association with the instance, separately.
  > {{I-D.draft-mcguinness-oauth-client-instance-id}} defines how an
  > issuer conveys instance context in a token it issues.
  >
  > The actor authentication, delegation eligibility, subset, and
  > lifecycle checks of {{delegated-exchange}} and
  > {{delegation-constraints}} still authorize the exchange; instance
  > evidence satisfies none of them by itself. Instance continuity alone
  > does not authorize replacement of the recorded instance or key
  > rebinding.

  The first paragraph is paragraph a verbatim, except for two changes:
  its two parenthetical citations (client-instance-id with
  client-attesters, and "Section 5 of" client-instance-id) are dropped,
  and one descriptive sentence naming client-instance-id is added. The
  second paragraph is e's first sentence and f's second clause, both
  verbatim. Nothing else is reworded.

**Conditions for B1 to make the reference informative.** All must hold.
1. **No retained text requires behavior that client-instance-id
   defines.** The retained text above describes client-instance-id
   once and states only the binding's own rules. A reviewer must
   confirm this sentence by sentence before the edit.
2. **Every moved obligation exists first in a published
   client-instance-id revision:**
   - d: presenter selection, key binding, context mapping, and no
     input substitution;
   - e: the MUST, the attribution refusal, with
     `invalid_client_attestation` (already client-instance-id Section
     5.2) and the association-failure code;
   - f: the first clause, grant continuity on refresh, which Section
     5.1 already states in part;
   - h: the configuration restriction, which client-instance-id
     already defines, and the "needs a provenance mechanism" rule.

   The current `-00` defines Context Consumer rules (Sections 7.3, 7.5
   and 7.6, covering g) but not the issuer-side Token Exchange
   selection or refusal (d and e).
3. **The same deployments stay bound.**
   - Today, a and c-h bind every deployment that conveys
     `client_instance` in a delegated token.
   - After B1, the upstream text must apply to every issuer that
     conveys `client_instance` in a token issued by Token Exchange
     with an actor, as a requirement of conveying it, not as an
     optional profile within client-instance-id.
   - Otherwise B1 narrows scope, which needs an explicit ruling, not a
     relocation note.
4. **Ledger mechanism.** The ledger's coverage states are `tested`,
   `partial`, `todo` and `blocked` (`scripts/check-conformance-manifest.mjs`
   line 280); there is no "relocated" state.
   - Before any row moves, the owner rules on an explicit mechanism: a
     relocation record, or an external-source row that names an
     outside specification.
   - That mechanism must preserve each row's id, destination revision
     and section, applicability, and outstanding coverage.
   - It also decides how the five unledgered obligations (a, e's first
     sentence, f, g, h) get rows.
   - RFC publication of client-instance-id need not be the threshold.
5. **Rows for the retained rules.** Add rows for a, for e's first
   sentence (defined by its preserved meaning: instance evidence is
   insufficient by itself, not irrelevant), and for f's second clause.
   They are gated `core.instance-context` and start `todo`.

If any condition fails, B1 leaves client-instance-id normative.
Condition 3 is the hardest: whether client-instance-id should
require, for every conveying issuer, what this section requires is a
decision about that draft.

**Not recommended: B2 (a new companion), B3 (Child Delegation or
runtime-oauth).** B2 adds a draft for a 65-line section with the same
conditions. B3 hosts a different contract.

### 7.2 P1b. Rows for the two delegated-token MUSTs (D-2)

- Add rows for lines 3609 and 3617, anchored `delegated-exchange` and
  gated `core.delegation`.
- **Coverage, stated honestly:**
  - Each row starts `todo`.
  - It becomes `tested` only when a witness asserts every clause of the
    row and a mutation run shows the test fails with the rule disabled.
  - It becomes `partial` when a witness covers some clauses; the row's
    notes name the uncovered clause. For 3617, the clauses are "`cnf`
    is the delegate's key" and "the delegate proves possession of that
    key in the Token Exchange".
- **Candidate witnesses** in
  `src/services/authorization-server/test/delegation-exchange.test.ts`:
  "who presents which proof" (line 546) and "authority bounds every
  exchange" (line 691).
- No draft text changes.

### 7.3 P2. The standing-consent list becomes informative (D-3)

- **Change.** Replace the normative list of four companion `type`
  values and their documents (lines 3887-3904) with one sentence:
  companion profiles define standing-consent `type` values, and the
  Architecture lists them under "Authorization bases" in its Mission
  Invariants section (`draft-mcguinness-mission-architecture.md` line
  1976, which names all four).
- **Unchanged, explicitly:**
  - the extension rule that a companion profile can define a
    standing-consent basis (lines 3883-3887);
  - the companion-directed rules at 3913, 3935 and 3937, with their
    actor and conditions;
  - the activation and `activation_actor` rule (3906-3908);
  - the unknown-value handling (3910-3911, pointing to the record's
    common rule);
  - the `adjudication.kind` rule (4193);
  - the record shape;
  - the 7 ledger rows.
- **Effect.** Four companion citations leave normative text; no
  obligation and no IANA action changes.
- **Check before the PR.** Confirm that no rule relies on the list
  being the complete set of standing-consent values.

### 7.4 P3. Move explanations of companion behavior to their owners (D-4)

- **Rule.**
  - *Stays:* a base rule; an exception to a base rule (C12); a security
    residual a base implementer needs where the rule is stated; and a
    one-sentence pointer where the base defers a mechanism.
  - *Moves:* an explanation of how a companion behaves.
- **Process.** Build the obligation map (Section 9) for each candidate
  paragraph before any move. Review each move on its own, as one
  commit, with its receiving companion edited in the same PR.
- **Candidates** (line; family citations):
  - **Grant Bindings and Related Mechanisms** (2322; 6). Keep the Token
    Exchange bullet (2326-2336). Move the Cross-Domain bullet (M1), the
    Child Missions and successors bullet (M2), the Continuation bullet
    (M3) and the MAS-join paragraph (M4). Keep one sentence: a profile
    that creates another grant lineage or Mission states its relation
    to the grant binding.
  - **Composition and the Effective Ceiling** (5428; 6; M5) and
    **Authority Materialized Before Containment** (5464; 2; M6). Keep
    the base's own residual; move the cross-companion analysis to the
    Security Model guide.
  - **Principals and Approval Basis** (4239-4255).
    - *Keep* the base rules: "`approval_basis` is provenance: none of
      the record's integrity anchors ... covers it", "a profile that
      commits the Mission Record itself covers it under that profile's
      own anchor", the introspection-disclosure pointer, "not carried
      on the baseline `mission` claim", and "MUST NOT be relied on to
      grant or widen authority wherever it does appear".
    - *Move* only the two sentences describing Audit Transparency's and
      Approval Governance's commitments (4244-4250; M7). Keep the
      pointer to Consent Binding.
  - **Consent Binding** (5053; 3; M8). The same split: keep the base's
    consent-binding rules; move the descriptions of the companions'
    commitment mechanisms (around 5114-5120).
  - **Remediation Grains** (3090). No move: the list is closed ("The
    three remediation grains", line 3093).
  - Keep as they are: the security pointers in runtime-boundary,
    downgrade-by-omission, prompt-injection and
    information-propagation.

### 7.5 P4. Commitment species: withdrawn

The base uses the non-envelope species itself
(`authority_source.policy.digest`, lines 4277-4283). Repointing the
companions that import them (Discharge, Consent Evidence and possibly
others; Appendix B) would add a normative dependency on the withheld
substrate (C9).

### 7.6 P5. Keep #207 parked (D-5)

No trigger has fired (C8), and the relocation is large. Convention
neither requires nor forbids the split.

### 7.7 Withdrawn: moving the designation protocol

Revision 2 proposed it. The reasons it is withdrawn differ, and are
not equivalent:
1. **Self-Exchange carve-out** (3724-3726). It relaxes a base MUST.
   Without it, rule 1 (3728-3732) would refuse designation requests,
   which carry no actor, from delegates who hold the token (3543-3545).
   A relaxation cannot live in a companion (C12).
2. **Designation introspection** (3318-3320). Its `active: false` case
   *strengthens* the base's "`active: true` only when" rule (3315), so
   a companion could add that part. Its "with no `mission` member"
   clause conflicts with the base MUST to include `mission.state` and
   `mission.termination` for an otherwise-valid token on a terminated
   Mission (3327-3329). That clause is a base exception.
3. **The `aud` exception** (2500-2502). It qualifies the base `aud`
   MUST. It stayed in the base in every variant.
4. **The Actor Profile cannot leave the submission set**, because
   Resource Access needs `sub_profile` (5.3). So the move's main
   dependency goal fails.
5. **The Delegation capability bar would leave the base**, contrary to
   C1.

A readability-motivated version remains possible later. It would need
a base-defined token class for 1 and 2, and a self-contained Delegation
bar like Cross-Domain's (4982-4999).

### 7.8 Not proposed

- Reclassifying a normative reference while its text stays (C7).
- Making `direct`-case members optional; a standing-consent hub draft
  (C3).
- Any merge (C2).
- Renaming ledger ids, capability ids or provider switches.

## 8. Decisions for the owner

| Decision | Options | Recommendation | Cost | Effect | Prerequisite |
|---|---|---|---|---|---|
| D-1: Instance Context (P1) | A keep; B1 upstream (candidate) | A. B1 stays a candidate until its full obligation and applicability map is accepted. | B1: a client-instance-id revision carrying d, e, f and h first; then the binding edit, 2 error rows, a note, 3 new rows, 3 rows moved under a ledger mechanism, 1 annotation | B1, only if all five conditions hold: direct external normative I-Ds 3 to 2; latest-revision inventory 16 to 14 (the cited-revision closure must be computed before this is claimed) | D559's trigger; the five B1 conditions; a ledger-mechanism ruling (condition 4) |
| D-2: Delegated-token rows (P1b) | add; defer | Add now | Two rows, a witness check and a mutation run each | Two stated MUSTs gain rows with honest coverage | None |
| D-3: Standing-consent list (P2) | informative pointer; keep | Pointer | One paragraph | Four companion citations leave normative text; no obligation changes | The completeness check in 7.3 |
| D-4: Companion explanations (P3) | move by semantic ownership; keep | Build the obligation maps; approve each move individually once its reading-task item exists (Section 10) | Edits in the binding and each receiving companion; re-pins | Fewer family citations in normative text, each traced | Obligation map per paragraph; the move's named task item |
| D-5: #207 (P5) | keep parked; execute | Keep parked | None | None | A #207 trigger |
| D-6: Side finding (5.3) | update the submission-set record; leave | Update | One table and a sentence | The record matches the front matter | None |
| D-7: The Actor Profile's own normative references | review them in the Actor Profile draft; leave | Review separately (outside this repository): for each reference, establish why it is normative, at the revision cited | An Actor Profile review, and a revision if any classification changes | Unknown until each reference is examined. The Actor Profile accounts for 13 of the 16 nodes in the latest-revision inventory (Appendix E), but no reduction is promised. | A verified cited-revision graph (Appendix E caveats); owner's call on that draft |

## 9. Sequence and verification

**Sequence.**
1. D-2 and D-6. Independent and small.
2. D-3. A single-paragraph PR.
3. D-4: the obligation maps, then one reviewed move at a time.
4. D-7, in the Actor Profile draft, if the owner takes it up.
5. D-1 when its trigger fires and the B1 conditions can be met.

Each step is one issue in the Issue Convention format, plus one PR.

**Obligation map.** For every obligation in text that moves, BCP 14 or
keyword-free ("is rejected with", "carries", "never", "satisfies
none"), record:
- actor;
- trigger;
- scope;
- exceptions;
- refusal (error and endpoint);
- conformance applicability;
- ledger row, or "none";
- witness test.

**Verification per PR.**
- The obligation map is identical before and after, apart from ruled
  changes.
- A row keeps its coverage only after its witness is re-checked against
  the relocated text. Otherwise it is demoted, with the reason.
- Run the ledger and family-manifest checks, build every touched draft,
  and re-pin the companions that cite the binding.

## 10. Success criteria

**Dependency.**
- *Direct external normative I-D references* of the submission set:
  3 today.
- *Latest-revision inventory*: 16 distinct I-Ds, read on 2026-10-22
  (Appendix E). For planning only.
- *Cited-revision closure*: not yet computed. Compute it, with a source
  section for every edge, before any change is justified by a
  dependency reduction (D-1, D-7).
- Report each before and after every change that touches a reference.
  No change may add a normative reference to a withheld draft.

**Obligation integrity.**
- The obligation-map diff contains only ruled changes.
- No `tested` row loses coverage without a recorded reason.

**Citations.** Family citations in the middle matter, from 111, with
every removal traced to a D-3 or D-4 disposition.

**Readability protocol.** Applies to D-3 and D-4.
- *Readers.* A fresh model session with no repository context for each
  task and each version (before and after), so no reader sees both
  versions.
- *Fixed wording.* Every reader gets the same task wording and only the
  document set named for that task.
- *Hidden answer key.* The key is written from the obligation map
  before any reader runs and is never shown to readers. It lists every
  expected item with its section.
- *Scoring, in this order:*
  1. **Correctness.** No item the key does not contain, and no wrong
     item.
  2. **Completeness.** Every key item is found.
  3. **Navigation**, only for answers that pass 1 and 2: sections read,
     documents opened, cross-document jumps.
- *Tasks, with defined outputs.* Each task's document set includes
  every document the moved text lands in. Each D-4 move (M1-M8, 7.4)
  is reviewed by the task items named for it.
  1. **T1 (D-3).** "List every rule that applies when a specification
     defines a new standing-consent `approval_basis.type`. For each,
     say whether it binds the defining specification or the activating
     issuer, and give its section."
     - Documents: the binding, the Architecture.
  2. **T2 (D-4, M1-M3).** "For each item, state whether it creates a new
     grant binding, under what condition, and the section that says so":
     - (i) a Token Exchange that returns only an access token;
     - (ii) a Token Exchange that establishes reusable authorization
       state, such as Continuation's delegation-family-creating
       exchange;
     - (iii) a cross-domain projection;
     - (iv) a Child Mission;
     - (v) an expansion successor;
     - (vi) a continuation handle.

     Conditional answers are expected: (i) and (ii) differ.
     - Documents: the binding, Cross-Domain, Child Delegation,
       Expansion, Continuation.
     - Items: M1 is (iii); M2 is (iv) and (v); M3 is (ii) and (vi).
  3. **T3 (D-4, M4).** "Does a Mission Authority Server's Mission Join
     make the joined OAuth grant Mission-bound? What does a join rest
     on? Can one credential be joined to different Missions?" Give
     sections.
     - Documents: the binding, the Mission Authority Server.
  4. **T4 (D-4, M5-M6).** "For each of Child Delegation, Cross-Domain
     projection, Derivation Limits and Metering, state its effect on
     the authority a Mission can still yield, with its section. Then
     state what authority materialized before containment remains
     usable, and what bounds it."
     - Documents: the binding, the Security Model, Child Delegation,
       Cross-Domain, Derivation Limits, Metering, Containment.
  5. **T5 (D-4, M7-M8).** "State every rule about whether
     `approval_basis` is committed (by which anchor or profile),
     disclosed, carried on tokens, or relied on for authority, and every
     consent-binding rule, with its section."
     - Documents: the binding, Approval Governance, Mission Audit
       Transparency, Consent Evidence.
- *The moves (7.4):*
  - M1: the Cross-Domain bullet of Grant Bindings and Related
    Mechanisms;
  - M2: its Child Missions and successors bullet;
  - M3: its Continuation bullet;
  - M4: the MAS-join paragraph;
  - M5: the composition analysis;
  - M6: the containment-residual analysis;
  - M7: the `approval_basis` commitment descriptions (Audit
    Transparency, Approval Governance);
  - M8: the consent-binding companion descriptions.
- *Judging.* Assess D-3 and each D-4 move separately. A move passes
  when the task items named for it keep correctness and completeness. A change in navigation
  is reported as a trade-off (for example, D-4 may add a document jump
  to task 2), not as a pass or fail condition. No change must improve
  a task it does not touch.

## 11. Questions for review round 5

1. Is the eight-paragraph map in 7.1 complete, and are the kinds and
   actors right? In particular: is paragraph g already fully stated by
   client-instance-id Sections 7.3, 7.5 and 7.6, so that removing it
   loses nothing?
2. Does the retained B1 text keep the exact meaning of paragraphs a, e
   (first sentence) and f (second clause)?
3. Is condition 3 (the same deployments stay bound) the right test, and
   is it achievable without making client-instance-id Mission-aware?
4. Do T2-T5 give every D-4 move (M1-M8) an item whose answer would
   change if that move lost or altered a rule?
5. Is the edge-source labeling in Appendix E enough to tell a planning
   number from a verified one?

## Appendix A. P1 map (option B1, for later)

| Item | Location | Disposition under B1 |
|---|---|---|
| Paragraph a | 3654-3662 | stays (retained text, two citations dropped) |
| Paragraph b | 3664-3668 | removed; it is a consequence, and it cites the Actor Profile, which stays normative for 3496 and 3602-3608 |
| Paragraph c | 3670-3677 | replaced by the retained descriptive sentence; the MAY and the deployment configuration move upstream |
| Paragraph d | 3679-3691 | moves upstream (condition 2) |
| Paragraph e, first sentence | 3693-3696 | stays verbatim |
| Paragraph e, MUST and error pointer | 3696-3699 | moves upstream (condition 2) |
| Paragraph f, first clause | 3701-3703 | moves upstream (condition 2) |
| Paragraph f, second clause | 3703-3704 | stays verbatim |
| Paragraph g | 3706-3709 | removed; client-instance-id Sections 7.3, 7.5 and 7.6 already state it for consumers (to be confirmed by sentence) |
| Paragraph h | 3711-3716 | moves upstream (condition 2) |
| Error row: Client Attestation fails | 3196 | moves upstream |
| Error row: association fails | 3197 | moves upstream |
| Error-table note | 3210-3214 | removed (it names a client-instance-id code the binding no longer uses) |
| Future-work example | 6450 | stays; the reference is informative |
| Document History mention | 7290 | stays |
| `core.instance-context.current-presenter-binding` | ledger, todo | moves under the condition 4 mechanism, id preserved |
| `core.instance-context.no-input-substitution` | ledger, todo | moves under the condition 4 mechanism, id preserved |
| `core.instance-context.required-attribution-refusal` | ledger, todo | moves under the condition 4 mechanism, id preserved |
| New rows for a, e's first sentence, f's second clause | ledger | added, todo (condition 5) |
| Capability id `core.instance-context` | `model.capabilities` | kept (the new rows use it) |
| Provider switch | none | none |
| `@spec` annotation | `src/packages/mission-core/src/idempotency.ts:106` | kept; the anchor is unchanged |
| Companion citations of the section | none | none |

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

- **Round 1** (revision 1): 17 points, all agreed and verified;
  recorded in revision 2 (see `git log`).
- **Round 2** (revision 2): `REVIEW-ROUND-2.md`. Revision 3 applied it:
  - the designation move was withdrawn;
  - P1 was narrowed to Instance Context;
  - P2 became body-only;
  - P4 was withdrawn;
  - the decision table was rebuilt;
  - the factual corrections were applied.

**Round 3** (revision 3, at `66df29ee`):

| Finding | Disposition in revision 4 |
|---|---|
| Decision verdicts: D-1 keep A with B1 as a candidate; D-2, D-3, D-4 and D-6 proceed; D-5 keep parked | Adopted as the Section 8 recommendations. |
| 1. P1 keeps a requirement whose row it would retire. "Follow client-instance-id" may stay normative. B1 needs exact text. | Agreed and verified: lines 3696-3698 are `required-attribution-refusal`. 7.1 now gives exact before and after text, an obligation table, four conditions under which the reference becomes informative, a new row for the keyword-free rule, and no row retirement. |
| 2. "Three to two" counts direct references, not closure. | Agreed and verified. The metric is renamed. The traversal is computed (Appendix E): 16 distinct I-Ds, 13 of them the Actor Profile and the drafts it pulls in. Revision 5 relabels it a latest-revision inventory. New decision D-7. |
| 3. The reading test can reward incomplete answers. | Agreed. Section 10 adds a correctness-and-completeness gate, fresh sessions per version, fixed wording, hidden keys, defined outputs, and separate judging of D-3 and D-4, with navigation reported as a trade-off. |
| Correction: designation introspection strengthens `active: true only when`. | Agreed. 7.7 separates the reasons: the `active: false` part is a strengthening; only the "no `mission` member" clause conflicts with 3327-3329. |
| P3: preserve the anchors-do-not-commit and no-widening statements. | Agreed and verified at 4239-4255. 7.4 lists exactly what stays and what moves. |
| D-2: validate witnesses and preserve partial coverage honestly. D-3: preserve the extension rules and unknown-value handling. D-4: maps first, individual review. | Adopted in 7.2, 7.3 and 7.4. |

**Round 4** (revision 4, at `50e765c2f`, against main `635c1a1b6`):

| Finding | Disposition in revision 5 |
|---|---|
| Decision verdicts: D-1 keep A with B1 pending a complete map; D-2, D-3, D-4 (moves approved individually), D-5 and D-6 as recommended; D-7 reviewed separately with no promised reduction | Adopted in Section 8. |
| 1. B1's map omits paragraphs f (3701-3704), g (3706-3709) and h (3711-3716). Map every paragraph, including keyword-free obligations, with destination and applicability. Prove the same deployments stay bound, or treat it as a ruled scope change. | Agreed and verified. 7.1 maps all eight paragraphs (a-h), with kind, actor, row and dependence. Condition 2 covers d, e, f and h upstream. Condition 3 (the same deployments stay bound) is new. Five unledgered obligations are named. |
| 2. The retained text drops "by itself" and adds "which alone authorize the exchange". | Agreed. The retained text now uses e's first sentence verbatim ("satisfies none of them by itself"), and the new row is defined by that meaning (condition 5). |
| 3. T3 lacked Audit Transparency; the MAS-join and composition/containment moves had no task; Token Exchange answers must stay conditional. | Agreed. T2-T5 now name each move M1-M8; T5 adds Audit Transparency and Consent Evidence; T3 covers the MAS join; T4 covers composition and containment; T2 splits Token Exchange into its two cases. |
| 4. Entity Profiles `-02` lists Transaction Tokens normatively; distinguish the latest-revision inventory from the cited-revision graph; record edge sources. | Agreed and verified: Section 15.1 in both `-01` and `-02`, with the Actor Profile citing `-01`. Appendix E is relabeled, has an edge-source column, and the cited-revision closure is a prerequisite for D-1 and D-7. |
| Ledger: "relocated" is not a coverage state; decide an explicit mechanism first. | Agreed and verified (`COVERAGES` = tested, partial, todo, blocked). Condition 4 makes the mechanism a prior ruling that preserves ids, destination revisions, applicability and outstanding coverage. |

## Appendix D. Corrections log

| Earlier claim | Corrected |
|---|---|
| Revision 4: B1's obligation table covers the section | It covered 2 of 8 paragraphs; revision 5 maps all eight. |
| Revision 4: retained text "satisfies none of ... which alone authorize the exchange" | Changed the rule; replaced by the original "satisfies none of them by itself". |
| Revision 4: rows "recorded as relocated" | No such coverage state; a mechanism needs a ruling first. |
| Revision 4: Entity Profiles has no normative I-D references | It lists Transaction Tokens (an edge, not a node). |
| Revision 4: Appendix E is the "transitive normative closure" | It is a latest-revision planning inventory. |
| Revision 3: the submission set's normative I-D "closure" is three | Three is the direct count. The latest-revision inventory is 16 (Appendix E). |
| Revision 3: B1 makes client-instance-id informative | Only under the conditions in 7.1 (four in revision 4, five in revision 5). |
| Revision 3: the retained paragraph is a self-contained extension point; three rows "re-home or retire" | The paragraph contained the refusal MUST. B1's retained text is now given exactly, and no row is retired. |
| Revision 3: the three withdrawal cases are equivalent base-MUST exceptions | The introspection `active: false` part is a strengthening; see 7.7. |
| Revision 3: readability passes on navigation counts | Correctness and completeness come first (Section 10). |
| Earlier rounds | See revision 3's log in `git log` (the Actor Profile and Resource Access; D645; P4; D646; D620 versus D625; the commit date). |

## Appendix E. Latest-revision dependency inventory (planning, not a verified closure)

This is a **planning inventory**. It traverses each draft's latest
revision on the datatracker as of 2026-10-22 (pinned `-00` for
rar-metadata-remediation). It is **not** the graph of revisions actually
cited.
- Example: the Actor Profile `-01` cites Entity Profiles `-01`, while
  this inventory reads `-02`. Both list Transaction Tokens as their only
  normative I-D, so the node set does not change here, but it could
  elsewhere.
- **Before any dependency claim is made** (D-1, D-7), build the
  verified cited-revision graph: each node at the revision its citer
  names, and each edge with the source section that lists it as
  normative.

Depth 1 means cited by a direct reference. Root: AP = Actor Profile,
CI = client-instance-id.

**Edge source:**
- *Text*: read from the draft's normative-references section;
- *Summary*: from a model summary of that section;
- *Tab*: the datatracker's References tab, which is heuristic.

| Draft | Revision read | Stream | State | Depth | Root | Normative I-D references | Edge source |
|---|---|---|---|---|---|---|---|
| draft-mcguinness-oauth-client-instance-id | -00 | individual | I-D Exists | direct | CI | attestation-based-client-auth (cited -11) | Text, Section 12.1 |
| draft-mcguinness-oauth-actor-profile | -01 | individual | I-D Exists | direct | AP | transaction-tokens (cited -11), wimse-workload-creds (-02), wimse-wpt (-02), mora-oauth-entity-profiles (-01), oauth-identity-assertion-authz-grant (-04) | Text, Section 16.1 (cited revisions from a summary) |
| draft-ietf-oauth-rar-metadata-remediation | -00 | oauth WG | WG Document | direct | (itself) | none | Text, Section 10 |
| draft-ietf-oauth-attestation-based-client-auth | -12 | oauth WG | WG Consensus: Waiting for Write-Up | 1 | CI | none | Tab |
| draft-ietf-oauth-transaction-tokens | -11 | oauth WG | WG Consensus: Waiting for Write-Up | 1 | AP | identity-chaining | Tab |
| draft-ietf-wimse-workload-creds | -02 | wimse WG | WG Document | 1 | AP | wimse-identifier, wimse-mutual-tls | Tab |
| draft-ietf-wimse-wpt | -02 | wimse WG | WG Document | 1 | AP | wimse-arch, wimse-workload-creds | Tab |
| draft-mora-oauth-entity-profiles | -02 (the Actor Profile cites -01) | individual | I-D Exists | 1 | AP | transaction-tokens (both -01 and -02) | Summary, Section 15.1 |
| draft-ietf-oauth-identity-assertion-authz-grant | -04 | oauth WG | WG Document | 1 | AP | identity-chaining, oauth-rfc7523bis, parecki-oauth-jwt-dpop-grant | Tab |
| draft-ietf-oauth-identity-chaining | -17 | oauth WG | RFC Ed Queue | 2 | AP | none | Tab |
| draft-ietf-wimse-identifier | -03 | wimse WG | WG Document | 2 | AP | wimse-workload-creds | Text, Section 9.1 |
| draft-ietf-wimse-mutual-tls | -02 | wimse WG | WG Document | 2 | AP | wimse-workload-creds, tls-rfc8446bis | Text, Section 6.1 |
| draft-ietf-wimse-arch | -08 | wimse WG | WG Document | 2 | AP | wimse-identifier | Tab |
| draft-ietf-oauth-rfc7523bis | -11 | oauth WG | RFC Ed Queue | 2 | AP | none | Text, Section 9.1 |
| draft-parecki-oauth-jwt-dpop-grant | -01 | individual | Expired | 2 | AP | oauth-rfc7523bis | Tab |
| draft-ietf-tls-rfc8446bis | -14 (cited) | tls WG | reported published as RFC 9846 | 3 | AP | branch stops at the RFC | datatracker document page |

**Notes.**
- The Entity Profiles row was corrected in revision 5: it adds an edge
  to Transaction Tokens, not a node. The count of 16 distinct I-Ds is
  unchanged.
- The Actor Profile lists identity-chaining and jwt-dpop-grant as
  informative. Both enter through other nodes' edges, which come from
  the Tab source.
- There are cycles between wimse-workload-creds and wimse-identifier,
  and between wimse-workload-creds and wimse-mutual-tls.
