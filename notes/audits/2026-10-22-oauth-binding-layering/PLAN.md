# OAuth Binding Layering: Plan for Review (revision 2)

Status: proposal for review, revision 2 (2026-10-22). It follows
review round 1, which reviewed revision 1 at commit `330fb180` with
the verdict "revise before approving execution". Section 1 records how
each review point was handled. Nothing has been filed or edited in any
draft, the ledger or `src/`. Every proposal becomes a GitHub issue
only after the owner says go.

## 0. Instructions for the reviewing model

You are reviewing a restructuring plan for one Internet-Draft in a
family of about 50 drafts. Read Sections 1 to 4 for context and
dispositions, then judge Sections 5 to 9, then answer Section 12.

- **Base commit:** `origin/main` at `5344f4ed6`. The OAuth binding,
  the substrate, Discharge, Consent Evidence and Resource Access are
  byte-identical to `d7ab66ff9`, where the analysis began. The ledger
  counts were re-measured on `5344f4ed6`.
- **Line numbers** refer to `draft-mcguinness-oauth-mission.md` at the
  base commit unless another file is named.
- **Reproduce the counts** from the repository root (standard library
  only):
  - `python3 notes/audits/2026-10-22-oauth-binding-layering/measure.py`
    (jobs, citations, normative I-Ds, ledger groups, identifiers);
  - `python3 notes/audits/2026-10-22-oauth-binding-layering/companion_cites.py`
    (named-section citations only, so it cannot prove absence);
  - `python3 notes/audits/2026-10-22-oauth-binding-layering/commitment_imports.py`
    (P4 vocabulary inventory, by paragraph).
- **What we want from you:**
  - a verdict per proposal: adopt, revise (say how), or reject (say
    why);
  - any factual error, with the line or quote that shows it;
  - any missed blast radius: drafts, ledger rows, applicability,
    implementation switches, `@spec` annotations;
  - any conflict with Section 4;
  - whether the Section 6 precedents are stated fairly.
- **Do not** recommend merging existing drafts (Section 4, C2) or
  moving a family companion into the binding's normative references
  (C1). Those are settled.

## 1. Review round 1: dispositions

| # | Review point | Disposition | Where |
|---|---|---|---|
| R1 | P1's 14-row move omits `core.introspection.designation-inactive` (partial). | **Agree.** It is gated `all_of [core.delegation, core.introspection]`; revision 1's script read only single-capability gates. Now 15 rows move: 10 tested, 1 partial, 4 todo. | 7.1, Appendix A |
| R2 | Applicability changes also reach `core.other-types.delegation-only-unchanged` and `resource-access.delegate-eligibility.as-authenticates-delegate`. | **Agree.** Both are gated on `core.delegation`. Appendix A lists every row by disposition, including applicability-only changes. | Appendix A |
| R3 | `capabilities.ts` declares the provider switch `delegation`, not `core.delegation`; there is no Instance Context switch. | **Agree; revision 1 was wrong.** `capabilities.ts` line 26 declares `"delegation"`; `core.delegation` appears only in its comment (line 24). The ledger declares `core.delegation` and `core.instance-context` in `model.capabilities`. Revised: keep the switch and every id; move document ownership only. | 7.1, Appendix A |
| R4 | Keep the Mission-unaware routing prohibition in the base. | **Agree** (revision 1 already kept it). Its row `core.rs-enforcement.delegated-routing-mission-aware` is unconditional and stays. | 7.1 |
| R5 | Moving designation introspection is compatible with composite active, because the base says `active: true` only when its conditions hold. | **Agree.** This answers revision 1's question 3. | 7.1 |
| R6 | Record whether the delegated-token sender-constraint sentence governs all delegated tokens or only the designation exchange. | **Agree; it is genuinely ambiguous.** The MUST (line 3617) sits in a list scoped to "The AS issues the delegated token subject to all of the following" (line 3581). But Token Claims (line 2515) restates it generically, and Cross-Domain (line 821) cites the list as "the issuance profile's delegate model". New ruling P1-R1. | 7.1 |
| R7 | Give the appendix Actor Profile and Instance Context citations a disposition. | **Agree.** Line 6405: rewrite. Line 6450: stays, reference becomes informative. Line 7290 (Document History): stays as history. Neither reference disappears; both leave the `normative:` block. | 7.1 |
| R8 | P2 changes the scope of obligations if the common rules move into registry criteria. `direct` conflicts with standing-consent criteria, and the `adjudication.kind` prohibition governs a separate discriminator. | **Agree.** Revised: the common semantic rules stay in the body; the Designated Expert checks conformance to them; the standing-consent checks are conditional on a basis class; no `adjudication.kind` registry. Registry fields, extension-name policy and existing values are specified. | 7.2 |
| R9 | P4 missed Consent Evidence, and a normative substrate reference adds a dependency on a withheld draft. "As the bindings' substrate references already are" is wrong for the OAuth binding. | **Agree.** Consent Evidence line 701 imports the binding's commitment mechanisms normatively, including the raw-octet species. The vocabulary inventory finds more candidates. The AAuth, UMA, GNAP and MAS bindings cite the substrate normatively; the OAuth binding cites it informatively. P4 is deferred pending an inventory and its own ruling. | 7.4, Appendix B |
| R10 | Rewrite Section 5 as precedents and trade-offs, not universal conventions. | **Agree.** RFC 6749 Section 8 places extension requirements in its body, and RFC 7521 is an abstract framework that RFC 7523 cites normatively. Both verified. | 6 |
| R11 | Normative I-D dependencies delay RFC publication, not submission or adoption; dependent documents can publish together; the queue state is "Reference Not Received". | **Agree; verified** against RFC 7322 Section 4.8.6 and the RFC Editor queue's About page. | 5.3, 6 |
| R12 | Verification must go beyond BCP 14 preservation: actor, trigger, scope, exceptions, refusal and applicability per obligation, including keyword-free requirements; preserve coverage only after re-checking the witness. | **Agree.** Section 9 makes the obligation map step 1. | 9 |
| R13 | P3's one-sentence rule is too mechanical: keep base rules, exceptions and essential security residuals; the generic `aud` exception stays with the base audience rule. | **Agree.** P3 now uses semantic ownership. | 7.3 |
| R14 | The job buckets measure placement, not dispensable complexity; `record-principal-members` mixes base vocabulary and extension hooks. | **Agree.** Stated in 5.1, and no claim relies on job 3's whole word count. | 5.1 |
| R15 | P5: adopt, but justify it by the trigger and migration cost, not by OAuth convention. | **Agree.** | 7.5 |
| R16 | Define success separately for dependency reduction and readability, and test readability with named reading tasks. | **Agree.** | 10 |
| R17 | Sequence: maps first, then selected P3 moves, then decide and build P1; P2 separately; P4 deferred. | **Agree.** | 9 |

## 2. The question

The owner asked about `draft-mcguinness-oauth-mission.md` (the "OAuth
binding"):

1. It is doing a lot of jobs. Does it make sense to split the
   "binding" out from a core spec that does issuance?
2. Why does it need to reference so much of the family?
3. Why does it define parameters and implementation detail that it
   does not use itself but later specifications do?
4. What layering best fits OAuth best practices and conventions?

## 3. Context

- **The family.** About 50 drafts. `DRAFTS.md` gives each a role.
  - **core:** the substrate kernel (`draft-mcguinness-mission-substrate`).
  - **adapter-binding:** a binding of the Mission model to a wire
    protocol. The OAuth binding is one, beside MAS, AAuth, UMA and
    GNAP.
  - **companion:** a profile or extension built on a binding or on
    the kernel.
  - **guide:** an informational explainer.

  #1089 retired "core" as a name for the OAuth binding.
- **Publication state.** The binding's `-01` is on the datatracker
  (2026-10-21, D644). The file is the editor's draft: findings are
  filed as issues first, and the draft changes only through a
  reviewable PR on the owner's go. Resource Access `-00` is also
  published (D645). By this repository's submission tags, no other
  family draft has a datatracker revision.
- **Dependency direction.** Companions depend on the binding
  normatively. The binding depends on no companion normatively, and
  its reference to the substrate is informative (D140, #708). The
  AAuth, UMA, GNAP and MAS bindings cite the substrate normatively.
- **Ledger.** `conformance-manifest.json` holds one row per
  requirement, keyed by `spec` and `anchor`, with a coverage (`tested`,
  `partial`, `todo`) and an applicability.
  - Applicability is `unconditional`, gated on one capability, or a
    `capabilities` set (`all_of` or `any_of`).
  - Capability ids are declared in `model.capabilities`.
  - The ledger checker (`scripts/check-conformance-manifest.mjs`)
    enforces no row-id prefix.
- **Implementation.** The reference AS turns optional surfaces on and
  off with `ProviderCapability` switches in
  `src/services/authorization-server/src/adapters/capabilities.ts`.
  Code and tests carry `@spec <draft>#<anchor>` annotations.

## 4. Constraints and prior rulings

| Id | Ruling | Effect |
|---|---|---|
| C1 | The binding stands alone. It never takes a family companion as a normative reference, and it states a capability's property bar in its own terms with the companion informative (#169, Option 2). | A moved capability leaves an informative pointer behind, as Approved-Set Verification did (#882). |
| C2 | No consolidation: existing drafts are never merged. A new draft is allowed if it passes the New Draft Admission test (`CONTRIBUTING.md`). | P1 answers that test and assesses existing homes first. |
| C3 | #880 (2026-10-01) kept the generalized `approval_basis` in the binding: shared vocabulary, REQUIRED on every record, breaking change if the direct-case members became optional, and no hub draft. | P2 keeps the record shape and moves no member. |
| C4 | #1483 / D610 (2026-10-21) consolidated standing consent into one section, keeping the unknown-type rule in the record's common definitions. | P2 edits in place. |
| C5 | #882 moved the optional Approved-Set Verification capability to a companion. | Precedent for P1. |
| C6 | #1412 / D559 (2026-10-20) kept Instance Context and its normative `client-instance-id` reference until a concrete publication plan exists. Before proposing a new draft, assess an existing home. | P1 revisits D559 because its premise changed (5.3). It is a `decide` item. |
| C7 | #1503 finding 9 / D625 (2026-10-21) made the Actor Profile and rar-metadata-remediation normative. The owner rejected keeping them informative. | No proposal reclassifies a reference to escape a dependency. P1 moves the text that needs it. |
| C8 | #207 (open, parked): the Mission Model split, with three triggers: an OAuth WG adoption conversation (ask the WG's document-architecture preference first); a second non-OAuth binding with real implementer commitment; or MAS control-plane evolution that forces binding revisions at a felt cadence. | P5 keeps it parked. |
| C9 | #704 / D140: the initial OAuth WG submission set is the binding plus Resource Access. The substrate is withheld. | Resource Access's dependencies weigh more (P1). A normative reference to the substrate from a submission-set or companion draft adds a withheld-draft dependency (P4). |
| C10 | D427 / PR #1231 left "Option A on family editor's-copy citations" unruled: submit Resource Access `-00`, and keep the other family drafts as informative editor's-copy references. | P3 pairs with it. |
| C11 | Working style: prefer existing OAuth and JOSE surfaces; make minimal changes that preserve capability; an editorial change preserves every obligation (not just its keyword); every stated obligation needs a ledger row; ids and anchors stay stable across retitles. | Applies to every proposal. |

## 5. Findings

### 5.1 Where the text sits (placement, not dispensable complexity)

These counts measure where text sits, not how much of it an
implementer could do without. Middle matter: 34,747 words, 261 BCP 14
keywords, 133 sections. Each section's count excludes its subsections.
The bucketing is a judgment call, and `measure.py` lists every anchor.

| Job | Words | BCP 14 | Sections |
|---|---|---|---|
| 1. Issuance protocol, including approval | 21,872 | 193 | 79 |
| 2. RFC 8693 delegation profile, plus Optional Capabilities | 2,708 | 17 | 8 |
| 3. Hooks for companions and the extension framework | 5,036 | 51 | 14 |
| 4. Tutorial and examples in the middle matter | 947 | 0 | 4 |
| 5. Security, privacy, i18n, applicability | 4,184 | 0 | 28 |

Job 3 is mixed. `record-principal-members` (979 words, line 4128)
holds base vocabulary (`subject`, `client_id`, `authority_source`)
next to the generalized `approval_basis`. Commitment Mechanisms holds
rules the base's own anchors need. The job 3 total is therefore not a
measure of removable text.

Appendices total 7,321 words with no BCP 14 keywords. The Mapping
Assessment (line 7006, 1,157 words) and Role Mapping (line 6546, 477
words) are the substrate-binding content proper.

### 5.2 Family citations

- 140 citations of 30 family drafts; 111 in the middle matter.
- The most-cited drafts are Resource Access (25), Cross-Domain (20)
  and Approval Governance (9).
- The densest sections:
  - Grant Bindings and Related Mechanisms (line 2322): 6;
  - Composition and the Effective Ceiling (line 5428): 6;
  - Standing-Consent Bases (line 3881): 4;
  - Principals and Approval Basis (line 4128): 4.
- 29 of the 30 cited drafts have no datatracker revision, so their
  targets are github.io editor's copies (C10).

### 5.3 Normative Internet-Draft references and publication

| Reference | Kind | Cited from |
|---|---|---|
| `draft-mcguinness-oauth-client-instance-id` | individual | Instance Context in Delegated Tokens (8); one Error and Challenge Mapping row; appendix line 6450; Document History line 7290 |
| `draft-mcguinness-oauth-actor-profile` | individual | Delegation lead, Delegated Exchange, Instance Context; appendix line 6405 |
| `draft-ietf-oauth-rar-metadata-remediation` | WG | Denial Responses, Remediation Grains, Authorization Server Metadata |

- At `6a7c616e` (2026-10-20), the basis of D559, only
  `client-instance-id` was normative. Commits `e6f6c911a` (D625, "the
  OAuth Actor Profile is a normative reference, scoped to the optional
  Delegation capability") and `2e7c08608` (#1503 finding 9) added the
  other two on 2026-10-21.
- **What the dependency costs.** RFC 7322 Section 4.8.6: "Normative
  references to Internet-Drafts will cause publication of the RFC to
  be suspended until the referenced draft is also ready for
  publication", and the RFC Editor then publishes both together. The
  queue state is "Reference Not Received" (RFC Editor queue, About
  page).
- **What it does not cost.** It does not block draft submission, WG
  adoption or WG last call. Its cost is a coupled RFC publication
  date: the binding's RFC would wait for, and then publish with, both
  individual drafts.
- **Side finding.** `notes/oauth-wg-submission-set.md` lines 56-60
  say `DEPENDENCIES.md` has no external-normative-ids entry for
  `oauth-mission`. That predates `2e7c08608`; `DEPENDENCIES.md` line
  20 now lists rar-metadata-remediation.

### 5.4 Definitions the binding does not use itself

1. **`approval_basis` under `direct`** (line 4128 onward). Every member
   can be derived from members the record already has:
   - `consent_principal` is the Approver;
   - `activation.approval_event_id` mirrors the record's own
     `approval_event_id`;
   - `activation_actor` equals `consent_principal`;
   - `root_commitment` is the record's `authority_hash`;
   - where `adjudication` is present, its `kind` MUST be `human` (line
     4223).

   Uses in other drafts:

   | Member | Drafts | Mentions |
   |---|---|---|
   | `consent_principal` | 12 | 69 |
   | `approved_at` | 10 | 58 |
   | `root_commitment` | 5 | 29 |
   | `activation_actor` | 6 | 19 |

   C3 explains why the structure stays.
2. **Standing consent** (lines 3881-4005).
   - About 850 words, 16 BCP 14 keywords and 7 ledger rows. None of it
     applies to an AS whose only basis is `direct`.
   - Line 3888 onward names four companion `type` values with their
     documents:
     - `template` (Template);
     - `policy_drawdown` (Child Delegation);
     - `ceiling_drawdown` (Progressive);
     - `governed_policy` (Approval Governance).
   - Lines 3913, 3935 and 3937 put MUSTs on companion specifications;
     line 4193 constrains `adjudication.kind` values a companion may
     define.
3. **Commitment Mechanisms** (line 4593) defines three hash species.
   - Every anchor the binding defines is an envelope anchor (line
     4654).
   - The substrate's Default Commitment Construction defines all
     three (substrate line 534 onward). The binding's line 4616 says it
     "instantiates" that construction, through an informative
     reference.
   - At least Discharge and Consent Evidence import the binding's
     section for non-envelope species (Appendix B).
4. **`mission.expires_at`** (line 2825). Its MUST binds only "a
   profile that mints a further credential downstream of this one, or
   that verifies a Mission's remaining lifetime from retained state":
   in practice, Cross-Domain.
5. **Termination transition reading** (line 2175). It covers legacy
   state values, three of which are older companion values.
6. **Contrast case.** The Intent members (line 906 onward) are lean,
   and the base's own flow uses every one.

### 5.5 Root causes

1. **The binding is the only normative home left.** The substrate is
   informative to it (D140), and no companion may become its normative
   reference (C1). So shared vocabulary that must carry MUST strength
   lands in the binding, which then names who uses it (C3).
2. **Some relationship prose runs backwards.** Normative sections
   explain how companions behave: Grant Bindings and Related Mechanisms
   (lines 2322-2373) and Composition and the Effective Ceiling (line
   5428). Other mentions are legitimate: a base rule, an exception, or
   a security residual an implementer needs where it is stated (P3).
3. **The examples borrow Resource Access's type.**
   `mission_resource_access` appears in 16 binding sections, because
   the binding defines no type. This is defensible, since the binding
   and Resource Access form the submission set (C9).
4. **Some citations exist by ruling** (C1, #169).

### 5.6 Delegated-token obligations without ledger rows

Two MUSTs in Delegated Exchange have no row:
- "Authority only narrows" (line 3609: a subset of the designation's
  authority);
- "Each delegate is bound to its own key" (line 3617).

This holds whatever P1 decides. Under C11 they need rows.

## 6. Precedents and trade-offs

All of these were verified against the RFC text in this session.

| Choice | Precedent for it | Precedent against it, or the trade-off |
|---|---|---|
| Extensions register their own values | RFC 6749 Section 11 registries; RFC 7519 Section 10.1; RFC 9396 creates no `type` registry ("The AS controls the interpretation of the value of the `type` parameter", Section 2.1) | None found. Registries need IANA review time. |
| Requirements on future extensions | RFC 6749 Section 8 states them in its body ("All other types MUST be registered"; "Extension error codes MUST be registered") | RFC 8126 expects a registry document to give the designated expert review guidance (Section 1.3, item 7). Body rules and DE guidance are complementary: the body governs meaning, and the DE checks registrations against it. |
| Optional features in separate documents | RFC 7009, 7662, 8693 and 8414 sit outside RFC 6749; GNAP's RS connections (RFC 9767) are separate from GNAP core (RFC 9635) | More documents to navigate. A separate document is justified by independent dependencies or independent adoption, not by size. |
| An abstract framework beneath concrete profiles | RFC 7521 ("only defines abstract message flows and processing rules ... companion specifications are necessary"), cited normatively by RFC 7523 Section 9.1 | Convention allows it. Whether to do it for the Mission Model is a question of triggers and migration cost (P5). |
| Normative references to Internet-Drafts | Allowed; the RFC Editor publishes dependent documents together (RFC 7322 Section 4.8.6) | They couple the RFC publication date to the referenced drafts ("Reference Not Received"). |

## 7. Proposals

Every proposal is `-02` scope and issue-first. None changes a wire
member, endpoint, parameter, claim or error code, except where a ruling
below says otherwise.

### 7.1 P1. Move the designation protocol into a companion (`decide`; revisits D559)

**Proposal (variant B).**
- *Moves* to a new companion, working title "Mission Delegation for
  OAuth 2.0", docname `draft-mcguinness-oauth-mission-delegation`,
  intended category `std`:
  - Designation (lines 3533-3576);
  - the exchange-specific rules of Delegated Exchange: "The exchange is
    explicit" (lines 3584-3594) and "Each redemption is gated" (lines
    3624-3632);
  - Instance Context in Delegated Tokens (lines 3652-3717);
  - Delegated Token Example (lines 3819-3880);
  - the two-step figure and the Actor Profile framing in the lead
    (lines 3496-3532);
  - Error and Challenge Mapping rows 3193, 3194, 3196 and 3197;
  - the designation introspection rule (lines 3318-3320);
  - Token Theft's designation sentences (lines 5309-5312);
  - the designation and exchange parts of Delegation and Chain
    Compromise (lines 5316-5355);
  - the Delegation entry of Optional Capabilities (lines 4971-4975),
    which becomes the companion's conformance, with an informative
    pointer left in the base.
- *Stays* in the base:
  - Delegation Constraints (lines 3739-3818);
  - Self-Exchange Down-Scoping (lines 3718-3738);
  - the Mission-unaware routing MUST (lines 2966-2969);
  - Error rows 3192 (self-exchange) and 3195 (empty result);
  - Enforcement Requirements item 4 (lines 2929-2933) and the RS
    `act`-chain option (line 2955);
  - Client Attribution and Delegation Lineage (lines 5356-5372) and the
    appendix "Client Identification in Delegated Tokens" (line 6523);
  - the generic Token Exchange rules: grant resolution (lines
    2286-2294), the Token Exchange bullet of Grant Bindings (lines
    2326-2333), and Issuance Gating's "every derivation, refresh and
    Token Exchange";
  - the Token Claims `aud` exception for "a token the AS issues only
    for presentation back to itself at a Token Exchange", with
    designation as an example, because it qualifies the base audience
    MUST (lines 2496-2502);
  - the Extensibility stable-interface line "the `act` delegation
    chain" (line 4679).
- *Depends on ruling P1-R1:* the delegate-model properties of Delegated
  Exchange: stable `sub`, the meaning of `client_id`, the `act` chain,
  narrowing, the unchanged `mission` claim and the delegate's own key
  (lines 3595-3623), plus the chain-nesting and "attribution, not
  authority" paragraphs (lines 3633-3651).

**Why this cut.** The shared invariants live in Delegation
Constraints, and every act-bearing issuance path depends on them:
- Resource Access's Delegate Eligibility rests on it for depth `d`:
  "That document's Delegation Constraints section defines `d`" (RA
  line 1101). Resource Access `-00` is published and in the submission
  set.
- Continuation discharges the depth-accounting duty for its own
  transport (D202; Continuation line 393).
- Cross-Domain cites the depth reset (lines 411, 814, 858), and
  Derivation Limits cites the constraints (line 593).

The designation protocol is used almost only by the binding:
"designation" appears 37 times in the binding and once elsewhere
(Transaction Authorization). Child Delegation and Expansion each define
their own RFC 8693 exchange "per RFC 8693" (Child Delegation lines
452-461 and 790; Expansion lines 450-458 and 684). Neither relies on
the binding's Delegated Exchange rules.

**Ruling P1-R1: the scope of the delegate-model properties.**
- *Today:* the list at lines 3595-3623 is scoped by its lead-in, "The
  AS issues the delegated token subject to all of the following" (line
  3581), so it governs tokens from the designation exchange. But Token
  Claims restates the key rule generically, "A delegated token is
  sender-constrained to the delegate's own key" (line 2515). And
  Cross-Domain cites the list as "the issuance profile's delegate
  model" (Cross-Domain line 821).
- *Option (a), recommended:* the properties stay in the base and are
  stated for every act-bearing Mission-bound token, whichever profile
  issues it. This is a normative broadening, not an editorial move. It
  needs its own obligation-map entries and ledger rows (see 5.6), and a
  check of every other path that issues `act`-bearing tokens.
- *Option (b):* the properties move with the exchange, keeping today's
  scope. Cross-Domain line 821 then repoints to the companion, giving
  Cross-Domain a companion dependency, and Token Claims line 2515
  becomes a pointer.
- *Not acceptable:* moving them without a ruling. That would narrow
  their applicability (option b) or widen it (option a) silently.

**Variants considered.**

| Variant | What moves | Assessment |
|---|---|---|
| A. Status quo (D559) | nothing | The base keeps two individual-draft normative references for an optional capability, and its RFC publication couples to both drafts. |
| B. Designation protocol only (recommended) | as above | Both individual-draft references leave the `normative:` block, and the shared invariants stay. |
| C. All of the Section "Delegation Within a Mission" | B plus Delegation Constraints and Self-Exchange | Resource Access `-00`, Continuation, Cross-Domain and Derivation Limits would gain a dependency on an unsubmitted companion. |
| D. Host it in Child Delegation | as B, into Child Delegation | Different contract: Child Delegation creates new Missions with lineage. It does not use designations. |
| E. Fence it as a part of the binding | nothing | The references stay normative, so nothing changes for publication. |

**Reference dispositions.**
- `draft-mcguinness-oauth-actor-profile`: leaves `normative:`. Line
  6405 (Scope and Future Work, which states its normative scope) is
  rewritten to point at the companion. It stays an informative
  reference if any appendix mention remains.
- `draft-mcguinness-oauth-client-instance-id`: leaves `normative:`.
  Line 6450 (a future-work example, with client-attesters) and line
  7290 (Document History) stay, so it becomes informative.
- `draft-mcguinness-oauth-client-attesters` (already informative):
  stays, for line 6450.

**Blast radius.** The full map is in Appendix A.
- **Ledger.**
  - 15 rows change `spec` to the companion: 10 tested, 1 partial, 4
    todo.
  - 5 rows stay where they are but carry a `core.delegation` gate
    whose owner changes: 3 Delegation Constraints rows,
    `core.other-types.delegation-only-unchanged`, and Resource Access's
    `resource-access.delegate-eligibility.as-authenticates-delegate`.
  - Keep every row id and the capability ids `core.delegation` and
    `core.instance-context`: no checker requires an id prefix, and
    stable ids keep pins and history intact.
  - `core.delegation` remains the gate for "the AS supports the
    designation protocol"; Appendix A lists which rows keep it.
- **Implementation.** Keep the `delegation` provider switch
  (`capabilities.ts` line 26) unchanged. No Instance Context switch
  exists, and none is added. No behavior changes.
- **`@spec` annotations.** `mission#designation` appears 22 times in 11
  files and `mission#delegated-instance-context` once. These repoint to
  the companion's anchors. `mission#delegation` (20 in 10 files) is
  split by meaning: the delegate model stays, and the exchange moves.
  `mission#delegation-constraints` (27 in 15 files) and
  `mission#self-exchange` (14 in 3 files) are unchanged.
- **Companion citations.** The three citations of Section "Delegation
  Within a Mission" (Cross-Domain 821, Derivation Limits 365,
  Transaction Authorization 650) concern the delegate model, so they
  depend on P1-R1. The five citations of Delegation Constraints stay
  valid.
- **Pending finding.** #1503 finding 11 (a delegated token's lifetime
  and "that credential's grant") touches the moving text. Rule it
  before the move, or move it with the text.

**New Draft Admission answers (draft).**
- *Contract:* the Token Exchange protocol by which an agent designates
  a delegate and the delegate redeems the designation for a
  Mission-bound token, plus instance context for that token.
- *Why a separate document:* it is an optional capability whose two
  normative individual-draft dependencies the base does not otherwise
  need. Child Delegation has a different contract, and Continuation is
  an identity-continuity transport.
- *Parties:* the delegating client, the delegate client, and the AS.
- *What crosses the boundary:* the designation, a Token Exchange
  request and response, and the delegated token.
- *Existing mechanism tried:* plain RFC 8693 with `actor_token` does
  not bind redemption to a named delegate without the designation step
  (the binding's current design, unchanged).
- *Property:* authority. Delegated authority narrows and is bound to a
  named delegate; lifecycle is inherited.

### 7.2 P2. Add an Approval Basis Types registry; keep the common rules in the body

**Proposal.**
- **Body.**
  - Keep every semantic rule in the body.
  - Rephrase lines 3913, 3935 and 3937 from "A companion profile
    defining a standing-consent `type` MUST ..." to rules over "a
    standing-consent basis" whatever document defines it. They keep
    their keywords and conditions.
  - Keep the `adjudication.kind` prohibition (line 4193) in the body,
    where it governs any specification that extends `kind`.
  - Replace the named list of four companion values (line 3888 onward)
    with a pointer to the registry.
- **Registry: "Mission Approval Basis Types", Specification Required.**
  - Fields:
    - **Value**, matching `^[a-z][a-z0-9_]*$`;
    - **Basis class**: `direct` or `standing-consent`;
    - **Semantics**: one sentence;
    - **Activation shape**: the members of `activation` for this type;
    - **Change Controller**;
    - **Reference**.
  - Designated Expert instructions:
    - check that the registering specification meets the body's rules
      for its basis class. For `standing-consent`, that means lines
      3913-3939; for `direct`, the direct-approval rules (`kind`
      `human`, a human approval event);
    - reject a registration that redefines the unknown-type rule;
    - reject a registration that lets a basis supply or widen
      authority.

    These instructions restate checks; they create no obligation.
  - Extension-name policy, following the Namespace Taxonomy's postures:
    a short name is registered before use; a collision-resistant name
    (RFC 7519 Section 4.2 style) may be used unregistered, and the
    unknown-type rule applies to it.
  - Existing values: the registry is seeded with `direct` only. The
    four companion values stay valid as specification-defined names
    until their companions register them. Each of Template, Child
    Delegation, Progressive and Approval Governance adds an IANA
    request.
  - No `adjudication.kind` registry.
- **Namespace Taxonomy** (line 4768): its registry criterion is
  "values determine fail-closed behavior and span multiple documents",
  and an unknown basis type is not fail-closed. Amend it to cover a
  namespace "whose registrants must meet obligations this document
  states". Termination Reasons is already registry-backed with a
  fail-safe unknown value.

**Unchanged.**
- The record shape (C3).
- The unknown-type rule (C4).
- Every issuer obligation: `approved_at` verification (line 3928),
  Activation Policy Commitment, and Recency.
- The 7 ledger rows.

**What P2 buys.** The base stops naming four companions in a normative
list, and each value gets one registered owner. It buys no size
reduction. Ask whether that is worth four companion IANA requests.

### 7.3 P3. Move companion behavior into the companions, by semantic ownership

**Rule.**
- *Stays in the base:* a base rule; an exception to a base rule (for
  example, the Token Claims `aud` exception); a security residual an
  implementer of the base needs at the point the rule is stated; and a
  one-sentence pointer where the base defers a mechanism.
- *Moves to the owning companion:* an explanation of how a companion
  behaves or relates to the base.

**Candidates** (line; citations):
- Grant Bindings and Related Mechanisms (2322; 6): keep the Token
  Exchange bullet. Move the Cross-Domain, Child Missions and
  successors, and Continuation bullets, and the MAS-join paragraph.
  Keep one sentence: a profile that creates another grant lineage or
  Mission states its relation to the grant binding.
- Composition and the Effective Ceiling (5428; 6) and Authority
  Materialized Before Containment (5464; 2): keep the base's own
  residual statement, and move the cross-companion composition analysis
  to the Security Model guide.
- Remediation Grains (3090; 3): keep `mission_denial` and the
  RAR-remediation grain. Move the AuthZEN requestable-denial grain to
  the AuthZEN profile.
- Principals and Approval Basis (4128; 4) and Consent Binding (5053; 3):
  move the paragraphs on which profiles commit `approval_basis`.
- Policy-Language Types (1648; 2): an informative example; keep it or
  trim it.
- Keep: the security pointers in runtime-boundary,
  downgrade-by-omission, prompt-injection and information-propagation.

Each paragraph gets a disposition in the issue: kept (with the reason),
moved to X, or cut as a duplicate of X. Pair it with C10.

### 7.4 P4. Commitment species: deferred

Do not schedule P4 until two things are settled:
1. **The import inventory.** `commitment_imports.py` (Appendix B) finds
   these paragraphs citing the binding while using a non-envelope
   species:
   - Discharge (lines 282, 679, 841);
   - Consent Evidence (line 701, which "imports the issuance profile's
     commitment mechanisms normatively, including the algorithm-agility
     and unrecognized-prefix rules", and classifies
     `rendering_template_digest` as raw-octet).

   Four paragraphs cite both binding and substrate and need reading by
   hand: Approval Governance 217, AuthZEN 466, Harness 1414 and
   Transaction Authorization 289. Paragraphs that cite neither inherit
   their source from elsewhere in the draft. Named-section citation
   search cannot prove absence.
2. **The publication consequence.** Repointing an importer to the
   substrate gives it a normative reference to a draft withheld from
   the submission set (C9). Today that would affect Discharge and
   Consent Evidence; more if the hand-read paragraphs qualify. That
   needs its own ruling.

If both resolve in favor, P4 is the change revision 1 described: the
base keeps the envelope anchor, the prefix and agility rules and the
I-JSON rules, and points informatively to the substrate for the other
two species.

### 7.5 P5. Keep #207 (the Mission Model split) parked

#207 is the literal "split the binding from a core". Recommendation: no
change, for two reasons.
- No trigger has fired (C8). The first trigger is to ask the WG's
  document-architecture preference.
- The relocation round is large, and move-on-touch already migrates
  ownership one change at a time.

OAuth convention does not forbid the split: RFC 7521 is the precedent
for an abstract framework under concrete profiles (Section 6). The
Mapping Assessment and Role Mapping already sit in informative
appendices.

### 7.6 Not proposed

- Making rar-metadata-remediation, the Actor Profile or
  client-instance-id informative while their text stays (C7).
- Making the `direct`-case `approval_basis` members optional (C3).
- Moving standing consent to a hub draft (C3).
- Any merge of existing drafts (C2).
- Renaming ledger ids, capability ids or the provider switch (7.1).

## 8. What the owner decides

| Decision | Recommendation |
|---|---|
| P1 go or no-go (revisits D559) | Go, variant B. |
| P1-R1 delegate-model scope | (a): state the properties for every act-bearing Mission-bound token, as a normative clarification with ledger rows. |
| P2 go or no-go | Optional. Go only if removing the companion list is worth four IANA requests. |
| P3 dispositions | Go, paragraph by paragraph. |
| P4 | Deferred until Appendix B is complete and the withheld-draft dependency is ruled on. |
| P5 | Stays parked. |
| The two unledgered delegate MUSTs (5.6) | Add rows, whatever P1 decides. |

## 9. Sequence and verification

**Sequence.**
1. Produce the obligation map and the dependency map for every
   obligation P1 and P3 would move.
   - *Obligation map.* For each obligation, BCP 14 or present-tense
     without a keyword ("is rejected with", "carries", "never"):
     - actor;
     - trigger;
     - scope (which tokens, requests or records);
     - exceptions;
     - refusal (error code and endpoint);
     - conformance applicability;
     - its ledger row, or "none";
     - the witness test.
   - *Dependency map.* Appendix A, completed: rows, applicability,
     switches, `@spec` annotations, anchors, and companion citations.
2. Selected P3 moves.
3. Rule P1 and P1-R1, then build P1.
4. P2 on its own, if wanted.
5. P4 only after 7.4 resolves.

Each step is one issue under the Issue Convention.

**Verification per PR.**
- Compare the obligation map before and after. Every obligation keeps
  its actor, trigger, scope, exceptions, refusal and applicability, or
  the change is listed as normative and cites its ruling (P1-R1).
- The BCP 14 sentence record is necessary but not sufficient.
- Preserve a row's coverage only after re-checking that its witness
  test still exercises the relocated text. Otherwise demote it to
  `partial` and say why.
- Run the ledger and family-manifest checks, build every touched draft,
  and re-pin the companions that cite the binding.
- P1 only: repoint the `@spec` annotations listed in Appendix A, and
  prove with a test run that behavior is unchanged.

## 10. Success criteria

**Dependency reduction (measurable):**
- the binding's `normative:` block holds one Internet-Draft
  (rar-metadata-remediation) instead of three;
- no individual draft is a normative dependency of the binding;
- the binding's RFC publication no longer couples to the Actor Profile
  or client-instance-id;
- family citations in the binding's middle matter fall, with each
  removed citation traced to a P3 disposition.

**Readability (tested, not inferred from word counts).** Run each
reading task by a cold reader before and after, and record the sections
and documents read, the cross-document jumps, and the errors.
1. Implement a Mission Issuer with no optional capability: list every
   obligation on the token endpoint.
2. Implement Delegation end to end: designation, redemption, depth
   accounting, introspection of a designation.
3. Implement a Mission-aware RS that receives delegated tokens.
4. Register a new standing-consent basis (P2): find every rule it must
   meet.

Readability improves only if tasks 1 and 3 get shorter without task 2
getting materially longer. Moving about 1,500 words is not itself
evidence.

## 11. Corrections log

| Earlier claim | Corrected |
|---|---|
| Chat: Delegation moves 20 rows (16 tested) | 20 is variant C, which includes Self-Exchange. Variant B moves 15 (10 tested, 1 partial, 4 todo). |
| Chat: 10 companion citations in 6 drafts repoint | 2 cite Self-Exchange, which stays. Of the other 8, the 5 Delegation Constraints citations stay valid, and the 3 "Delegation Within a Mission" citations depend on P1-R1. |
| Revision 1: 14 rows move | 15. `core.introspection.designation-inactive` was missed (R1). |
| Revision 1: `capabilities.ts` declares `core.delegation` and `core.instance-context`, to be renamed | It declares the provider switch `delegation`. The ledger declares those two ids. Nothing is renamed (R3). |
| Revision 1: Actor Profile and client-instance-id "leave the binding" | They leave the `normative:` block; client-instance-id stays informative for lines 6450 and 7290 (R7). |
| Revision 1: P2 moves companion MUSTs into DE criteria | The rules stay in the body; the DE checks them (R8). |
| Revision 1: only Discharge imports the non-envelope species; "as the bindings' substrate references already are" | Consent Evidence too, and possibly four more. The OAuth binding's substrate reference is informative; the other bindings' are normative (R9). |
| Revision 1: "rules on future extensions go in registry instructions" as a convention | RFC 6749 Section 8 puts them in the body (R10). |
| Revision 1 and chat: RFC Editor state "MISSREF", publication "held" | The state is "Reference Not Received"; it delays RFC publication only, and dependent documents publish together (R11). |

## 12. Questions for review round 2

1. Is P1-R1 option (a) the right default? Is there any act-bearing
   Mission-bound token path in the family (Cross-Domain destination,
   Continuation, Template dispatch) whose tokens could not meet the
   delegate-model properties today?
2. Does Appendix A miss any row, applicability set, switch, annotation
   or citation?
3. P2: does the "Basis class" field adequately separate `direct` from
   standing-consent checks? Is seeding only `direct`, with companion
   values valid until registered, workable for the IANA review?
4. P2: is the Namespace Taxonomy amendment phrased so that Mission
   Record members and `mission` claim members do not also need
   registries?
5. P4: of the four "both" paragraphs in Appendix B, which actually
   import a non-envelope species from the binding?
6. Are the four reading tasks in Section 10 the right ones?
7. Does any P3 candidate carry a rule a companion cannot restate
   without an "Updates:" relationship to the base?

## Appendix A. P1 dependency map (variant B)

**Ledger rows** (`P1` = this plan's disposition):

| Row id | Spec | Anchor | Coverage | Applicability | P1 |
|---|---|---|---|---|---|
| `core.designation.holder-proves-possession` | binding | designation | tested | `core.delegation` | moves |
| `core.designation.holder-is-current-actor` | binding | designation | todo | `core.delegation` | moves |
| `core.designation.subset-and-mission` | binding | designation | tested | `core.delegation` | moves |
| `core.designation.audience-names-client` | binding | designation | tested | `core.delegation` | moves |
| `core.designation.no-cnf-no-act` | binding | designation | tested | `core.delegation` | moves |
| `core.designation.expiry` | binding | designation | tested | `core.delegation` | moves |
| `core.designation.audience-separation` | binding | designation | tested | `core.delegation` | moves |
| `core.designation.audience-separation-refusal` | binding | designation | tested | `core.delegation` | moves |
| `core.delegation.designation-only-subject-token` | binding | delegated-exchange | tested | `core.delegation` | moves |
| `core.delegation.redemption-evaluated-afresh` | binding | delegated-exchange | tested | `core.delegation` | moves |
| `core.instance-context.current-presenter-binding` | binding | delegated-instance-context | todo | `core.instance-context` | moves |
| `core.instance-context.no-input-substitution` | binding | delegated-instance-context | todo | `core.instance-context` | moves |
| `core.instance-context.required-attribution-refusal` | binding | delegated-instance-context | todo | `core.instance-context` | moves |
| `core.self-exchange.designation-not-self-exchange` | binding | self-exchange | tested | `core.delegation` | moves (it is about designations) |
| `core.introspection.designation-inactive` | binding | composite-active | partial | `all_of [core.delegation, core.introspection]` | moves |
| `core.delegation-constraints.depth-from-accounting` | binding | delegation-constraints | tested | `core.delegation` | stays; gate owner changes |
| `core.delegation-constraints.unestablished-depth-refused` | binding | delegation-constraints | tested | `core.delegation` | stays; gate owner changes |
| `core.delegation-constraints.designation-adds-no-delegate` | binding | delegation-constraints | tested | `core.delegation` | stays; its text names designations, so re-check the witness |
| `core.delegation-constraints.cross-domain-carriage` | binding | delegation-constraints | tested | `cross-domain.projection` | stays |
| `core.other-types.delegation-only-unchanged` | binding | other-types | todo | `core.delegation` | stays; gate owner changes |
| `core.self-exchange.approved-agent` | binding | self-exchange | tested | unconditional | stays |
| `core.self-exchange.result-subset` | binding | self-exchange | tested | unconditional | stays |
| `resource-access.delegate-eligibility.as-authenticates-delegate` | Resource Access | delegate-eligibility | tested | `core.delegation` | stays in RA; gate owner changes |
| `core.rs-enforcement.delegated-routing-mission-aware` | binding | rs-enforcement | partial | unconditional | stays (R4) |
| `core.error-mapping.token-exchange-token-refusal` | binding | error-mapping | partial | unconditional | stays; re-check which moved error rows it witnesses |
| `core.authority-sources.actor-model-source-independent` | binding | authority-sources | partial | unconditional | stays (line 1989) |
| `core.authority-proposal.governed-client-token-request-not-reached` | binding | authority-proposal | todo | unconditional | stays (lines 1215-1216) |
| (none) | binding | delegated-exchange | none | none | "Authority only narrows" (line 3609): add a row (5.6) |
| (none) | binding | delegated-exchange | none | none | "Each delegate is bound to its own key" (line 3617): add a row (5.6); its placement depends on P1-R1 |

**Capability ids** (`model.capabilities`): `core.delegation` and
`core.instance-context`. Both are kept. `core.delegation` becomes owned
by the companion, and the base's rows that keep this gate read it as
"a delegation profile is implemented".

**Implementation switch:** `delegation` (`capabilities.ts` line 26),
opt-in, unchanged. There is no Instance Context switch.

**`@spec` annotations in `src/`:**

| Anchor | Annotations | Files | P1 |
|---|---|---|---|
| `mission#designation` | 22 | 11 | repoint to the companion |
| `mission#delegated-instance-context` | 1 | 1 | repoint to the companion |
| `mission#delegated-exchange` | 0 | 0 | none |
| `mission#delegation` | 20 | 10 | split by meaning (delegate model stays; exchange moves) |
| `mission#delegation-constraints` | 27 | 15 | unchanged |
| `mission#self-exchange` | 14 | 3 | unchanged |

**Companion citations** (`companion_cites.py`):
- Self-Exchange: Runtime Evidence 1949 and Shaping 607, unchanged.
- Delegation Constraints: Continuation 393, Cross-Domain 411, 814 and
  858, and Derivation Limits 593, unchanged.
- Delegation Within a Mission: Cross-Domain 821, Derivation Limits 365
  and Transaction Authorization 650, which depend on P1-R1.

## Appendix B. P4 vocabulary inventory

Output of `commitment_imports.py`, by paragraph. "Both" means the
paragraph cites the binding and the substrate. Paragraphs citing
neither are counted but not listed.

| Draft | Line | Cites | Vocabulary |
|---|---|---|---|
| Discharge | 282 | binding | canonical-object |
| Discharge | 679 | binding | raw-octet |
| Discharge | 841 | binding | canonical-object, commitment mechanisms |
| Consent Evidence | 701 | binding | commitment mechanisms, raw-octet, agility, unrecognized-prefix, envelope anchor |
| Approval Governance | 217 | both | canonical-object, commitment mechanisms, Default Commitment Construction |
| AuthZEN | 466 | both | canonical-object, Default Commitment Construction |
| Harness | 1414 | both | raw-octet, Default Commitment Construction |
| Transaction Authorization | 289 | both | canonical-object, raw-octet, envelope anchor, Default Commitment Construction |
| Approval Governance | 1470, 1478 | binding | envelope anchor (unaffected by P4) |
| Expansion | 1650 | binding | envelope anchor (unaffected) |
| Work Products | 493, 512 | binding | envelope anchor, unrecognized-prefix (unaffected) |
| Mandate | 285 | binding | algorithm agility (unaffected) |
| Orchestration | 410 | both | envelope anchor (unaffected) |
| Audit, Capability Binding, Discovery, Evidence Envelope, Runtime, Runtime Evidence, Shaping | various | substrate | already substrate-sourced |
