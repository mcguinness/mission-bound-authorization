# OAuth binding independence implementation plan

The OAuth binding will define a complete direct approval and issuance protocol, together with the invariants and extension rules that other specifications must preserve. An authorization server must be able to obtain useful Mission functionality without implementing a Mission companion. Companions will define their additional mechanisms and explain how they satisfy the binding's contracts.

This plan implements the owner's direction to remove companion dependencies and reduce the knowledge needed to implement the binding. The owner's subsequent direction is to be aggressive for `-02`: complete the independence pass before publishing that revision, rather than defer its substantive work to a later revision. It separates editorial removals from changes to normative ownership. It does not create a smaller conformance class or another specification.

Revision 3 (2026-11-02) reconciles Revision 2 with `main` at `ac00dc76`, as the owner's D1195 assessment required before reuse. P3's dependency inversion has landed (D1134; #1974, #1992, #2006). This revision rescopes P3 to its remaining contract work, records the decisions taken since, and freezes the execution baseline. Package IDs remain stable; the remaining order is P0, P3, P2, P1, P4, P5.

## Baseline and delivery status

Revision 2's source baseline was `b2b6c052d7a0987c4822d534587b23bdc2b17a6f` (2026-10-31). Revision 3 freezes the execution baseline at `ac00dc76a1e86a30dc0b092cdbf1d0ff71e3fc82` (2026-11-02), after the overlapping merges below. Exit condition 8 and P5 compare against it.

Landed since Revision 2:

- #1939 (#1937): Revocation states what a token's consumer does after its Mission terminates.
- #1942 (#1504): the legacy Mission-state reading is removed.
- #1974 and #1992 (#1967, ruled D1134): Approval Governance becomes informative; Mission-Creating Paths states the binding's local standing-consent requirements; the Governance-owned Contract rows leave the binding's baseline profiles. D1134 records this as an intentional normative relaxation.
- #2006 (F1 of D1192): the family manifest's conditional Governance edge for the binding is removed. Template, Progressive and Child Delegation keep their own edges.
- #1960 (#1895, D1114): Status states that a Lifecycle endpoint serving as the token-independent revocation means accepts `revoke` through client authentication. The binding's surface sentence names the condition and no longer points to Status.
- #2004: the binding's `-02` Document History is consolidated, outside the measured regions.

Package status at the frozen baseline:

| Package | Status |
| --- | --- |
| P0 | Baseline frozen by this revision. The tracking issue and the P5 readers remain open. |
| P3 | Dependency inversion done. Remaining: the local extension contract, A1, the adopter review and the Governance member explanations. |
| P2 | Not started. Item 5 (Status and revocation) is complete through #1960. |
| P1, P4 | Not started. |
| P5 | Not run. |

Supporting files:

- [Companion citation inventory](CITATIONS.md), regenerated at the frozen baseline. Revision 2's inventory at `b2b6c052` is in this directory's git history.
- [Machine-readable citation inventory](citations.json).
- [Inventory generator](inventory.py), which regenerates the inventory from an explicit git revision without changing the checkout.
- [Prose budget measure](measure.py) for exit condition 8.

This revision changes only these planning files and its own decision-log row. No specification, ledger or issue changes with it. Implementation PRs remain the deliverables; the plan is not evidence that their acceptance checks have passed.

## The implementation boundary

The standalone implementation consists of the OAuth binding, its underlying OAuth and JOSE standards, and an authorization-details type the deployment supports. That type supplies the application's authorization semantics. It need not be Mission Resource Access.

The baseline AS supports the direct approval path and no optional Mission capabilities. It can use one supported authorization-details type, refuse all unsupported evidence types, and carry approved entries unchanged when no transformation is supported. Narrowing-mode derivation is not the same claim as support for every transformation of an entry; the existing distinction must remain explicit.

This implementation provides task approval, a committed authority ceiling, Mission-bound grants and tokens, bounded subsequent issuance, expiry, and authorized revocation independent of possession of a token. It does not promise that an already-issued token stops working immediately, that prose determines authority, or that every business action is independently approved.

A resource server either enforces the selected authorization-details type or uses a safe scope projection under the binding's existing conditions. No Runtime, Status, Signals, Metering or Approval Governance implementation is a prerequisite of the baseline AS.

### Exit conditions

1. No normative reference from the OAuth binding to an in-repository Mission-family document remains. Conditional requirements count as normative dependencies and must be resolved, not relabelled informative.
2. A reader can implement and explain the baseline flow without consulting a Mission companion. Existing OAuth standards and the selected authorization-details type remain permitted inputs.
3. No companion citation is needed to implement the baseline. A remaining informative citation must sit at the extension hook it illustrates, add useful navigation, and supply no missing rule. Architecture may hold the family catalogue. Repeated solution catalogues in the direct flow are removed. There is no arbitrary numerical cap on informative links.
4. Every removed requirement still has an appropriate owner, or is explicitly identified as a separately reviewed semantic change. No obligation loses its actors, conditions, timing, refusal behavior or evidence merely because its citation disappears.
5. Every retained extension hook states the responsibilities of an extension author and the behavior of a deployment that does not implement the extension.
6. The direct flow remains useful and interoperable without any new endpoint, capability negotiation scheme, wire identifier, conformance class or mandatory companion.
7. The ledger and family manifest describe the resulting dependency graph and obligation ownership accurately. Citation and keyword counts are diagnostics, not proof of correctness or readability.
8. The completed series does not increase the protocol body's prose word count or the Extensibility chapter's prose word count against the frozen execution baseline. A builder reports each PR's additions and removals, including intermediate growth. A necessary exception must identify the unique obligation that cannot be stated within the budget and receive explicit review; it must never be hidden by removing another necessary rule. This is a scope budget, not evidence of improved readability.

The zero-reference target is for Mission-family dependencies. External OAuth dependencies, including Actor Profile and RAR remediation where retained requirements use them, must remain honestly classified. The client-instance question has its own existing decision and is handled separately below.

## Current dependency inventory

At the frozen baseline the binding contains 112 citation occurrences to 29 in-repository family documents. Revision 2's baseline had 114 across 28: Approval Governance fell from 12 to 9, and a Mission Mandate citation was added. The count covers citation markup from the abstract through the material before Document History. It excludes bibliography declarations and historical notes. Another 16 occurrences cite three adjacent McGuinness documents outside the family manifest: client-instance-id, Actor Profile and client-attesters.

| Family document or group | Occurrences | Primary problem | Planned treatment |
| --- | ---: | --- | --- |
| Cross-Domain | 18 | A particular optional issuance mechanism is threaded through generic issuance, principal and grant rules. | Keep generic invariants locally and put mechanism-specific duties in Cross-Domain. |
| Resource Access | 17 | Type-specific explanations and examples appear to be part of the baseline protocol. | Keep the type contract locally and replace the baseline examples. |
| Approval Governance | 9 | Informative since #1974. The citations explain `adjudication` members and `governance_record` (Principals and Approval Basis, four), the Approval Governance Record (Single Accountable Approver, two), the Contract (Mission-Creating Paths), the approval basis (Consent Binding) and `policy_version`'s example (A1). | Delete A1's example. Keep the Mission-Creating Paths pointer at its hook. Leave companion-defined members to Governance where the binding's rule is complete without the explanation (P3, P1). |
| Expansion | 8 | Successor and review mechanics are repeated in the baseline path. | Keep generic new-Mission and changed-authority rules; let Expansion specify its procedure. |
| Submission Evidence | 6 | The baseline dispatch/refusal contract is mixed with the optional verification framework. | Complete the baseline contract locally; move the framework's additional duties to its adopters. |
| Consent Evidence and Status | 5 each | Optional disclosure or observation mechanisms are presented beside baseline obligations. | Keep baseline confidentiality, revocation and consumption rules; move named solutions out. |
| Architecture, Child Delegation and Security Model | 4 each | Explanatory navigation and optional mechanism comparisons interrupt the main flow. | Retain only indispensable generic explanations; place family navigation in Architecture. |
| Other family documents | 32 | Small references accumulate across creation, issuance, security, privacy and extensibility. | Classify each occurrence using the disposition procedure below. |

No in-family normative reference remains: #1974 made Approval Governance informative, and #2006 removed the conditional manifest edge. Exit condition 1 is met at the references level (D1192). The remaining work is the reading burden and the local contract that keeps each informative link optional.

## Decisions retained and decisions revised

| Decision or issue | Treatment in this plan |
| --- | --- |
| D1054 and D1056 (the Approval Basis Contract's mandatory connection), D1057 and D1058 | D1134 supersedes the mandatory connection of D1054 and D1056 to the extent it states: a profile defined elsewhere may meet the binding's local requirements by another mechanism. The Contract stays in Governance, and Template, Progressive, Child Delegation and `governed_policy` keep adopting it. This is a recorded, intentional normative relaxation; the import is not restored (D1195). |
| D1061 and D1070, implied anchors | Preserve computation from authoritative immutable inputs, the specified algorithm, rejection of mismatching stored anchors, creation-time availability and whole-record member presence. This work does not make commitments weaker or change their preimages. |
| D1081 and PR #1941, direct approval procedure | Preserve the seven numbered steps, their order and atomicity, and the topic subsections that now own their rules. Do not recreate the former long procedure. |
| #1915 and #1917 | Keep these completed issues closed. This plan concerns dependency direction, not unfinished execution of their old proposals. D1134 records the supersession. |
| #1723 and #1793 | Keep their measured results and closures. Previous reader work did not demonstrate the proposed improvement. Do not reuse keyword totals or those results as evidence that this plan succeeds. |
| #1412 and D559, client-instance composition | Reuse #1412. Its current decision keeps the normative reference until its publication trigger and destination conditions are met. This work must not silently move the material into an unsuitable companion or downgrade the citation. The optional extraction is not a prerequisite of Mission-family independence. |
| #207, Mission Model split | Remain parked. This work makes the OAuth binding self-contained and introduces no normative Substrate dependency. It neither executes the split nor retires or merges documents. |
| #1895, token-independent revocation | Closed by #1960 (ruling D1114, review D1120, merge D1123). Status owns the conditional client-authentication duty; the binding's requirement is self-contained. |
| #1937 and PR #1939, issued-token validity | Merged. Do not restore an unconditional claim that every issued token remains valid until expiry. |
| #1504 and PR #1942, editorial residue and legacy states | Merged. Do not reintroduce removed legacy interpretations or duplicate the consumption-mode rewrite. |
| #1927, record and evidence follow-ups | Keep its ledger, commitment-input and Consent Evidence work separate. Re-anchor its rows if this plan changes their owning sections; do not silently change the proposed `verified_at` behavior. |
| D1144, the tracking issue | D1144 filed no separate core-independence tracker because #1967 owned the work. #1967 is closed, so P0 files one, as D1195 recommends, on the owner's "file". |
| D1192 and D1195, the gate review | D1192 reviewed the pass against the exit conditions. D1195 confirmed the criteria and corrected the review: exit 5 is not evaluated, exit 3 rests on the mechanism catalogue in Grant Bindings and Related Mechanisms (P2 item 1), and A1 is resolved locally. |

The owner's instruction authorizes developing this plan and the independence direction. It does not turn every implementation choice below into an already-published protocol rule. Any actual requirement change must be identified in its PR. Early-draft status removes the need to invent a legacy compatibility mode, but it does not justify losing an obligation during relocation.

## Target ownership

### Rules that remain complete in the OAuth binding

The binding retains:

- Submission shape, supported-type dispatch, processing order, authority derivation and refusal behavior.
- Direct approval authentication, Subject establishment, authority-source checks, consent rendering, expiry and atomic commitment.
- The minimum Mission Record, the direct approval basis, core commitments and verification behavior.
- Mission identity, grant binding, token claims, issuance gates, refresh, audience restrictions and lifetimes.
- Existing optional Self-Exchange and Delegation procedures, without expanding their scope in this project.
- Token consumption, safe scope projection, introspection and privacy minimization.
- Lifecycle semantics, issuance consequences and token-independent revocation authorization.
- Extension naming and recognition rules, immutable commitments, authority limits and conformance roles.

The binding must state its own security limits. In particular, a signed or matching commitment is not independent proof that the approved authority was appropriate, and historical approval evidence does not establish every condition for later reliance.

### Rules that extensions own

Extensions own their particular transports, activation bases, evidence formats, new commitment species, operational interfaces and additional conformance requirements. Each extension identifies which binding contract it uses, which additional duties it imposes, and which deployments adopt those duties.

Architecture owns the feature catalogue and adoption guidance. It can explain which optional documents add value after the baseline implementation works. This does not make Architecture an implementation dependency.

### The extension contract

Use the existing Extensibility section rather than adding another overview of the family. Organize it around the following responsibilities, with local links to each rule's defining section:

| Extension point | Contract the binding must state locally |
| --- | --- |
| Authorization-details types | The owner defines validation and enforcement semantics. Narrowing, delegation, projection and normalization are used only under the existing declared-support rules. No generic object comparison is invented. |
| Input and evidence types | Names, schema ownership, recognition and refusal are explicit. Evidence contributes verified policy input, not authority. A deployment supporting no evidence type has a complete refusal procedure. |
| Alternative creation paths | The extension identifies its authorized approval basis and preserves accountable authorization, Subject and source checks, bounded authority, expiry, event identity, commitments and atomic creation. |
| Additional grants and issuance paths | The extension defines when its own grant binding is established and resolved, and how issuance remains within the Mission. A transient artifact or per-request join is not silently a reusable grant lineage. |
| Additional commitments | Domain separation, issuer binding, canonicalization, byte construction and verification rules are explicit. Extensions define new objects and `typ` values without redefining existing constructions. |
| Additional record or token members | Namespace and unknown-value behavior are defined for that surface. Opaque provenance retention does not authorize interpreting an unknown approval basis. |
| Lifecycle extensions | An unknown state does not permit issuance. A new interface does not weaken authorization, terminal-state behavior or the binding's revocation duty. |

Do not copy every companion requirement into this table in the draft. It is a builder checklist. The final prose should point to one local home for each invariant and state only the extension author's additional responsibility.

## Requirement disposition procedure

Before deleting or moving a paragraph, record:

1. Its source anchor and exact text, including normative prose without a BCP 14 keyword.
2. The responsible role, applicability condition, trigger and required observation or refusal.
3. Its ledger rows, test citations and any external sections that cite it.
4. Its disposition: retain locally, replace with a local pointer, remove a redundant explanation, move to an extension, or propose a semantic change.
5. The destination anchor and wording, if moved, and why the same adopters remain bound.
6. The effect on wire members, metadata, commitments, example bytes and consumer behavior.
7. The checks that distinguish preservation from accidental weakening.

A citation occurrence is a review location, not a proof that its whole paragraph can be deleted. The citation inventory's work-package assignment is provisional. An informative paragraph can contain a unique normative condition, and an unchanged keyword sequence can conceal a changed antecedent or scope.

Keep row IDs for moves within the same document when the obligation is unchanged. For cross-document transfers, default to destination-prefixed IDs with an explicit old-ID to new-ID map. Update every live row reference, capability mapping, test citation and `@spec mission#anchor` tag that the move affects in the same PR. Existing historical references retain their history, and the PR disposition records where their obligations now live. Re-run affected tests after changing their names or tags, even if assertions are unchanged.

The prefix is not currently an enforced ownership rule: main already contains `core.approval-basis.*` rows whose `spec` is Approval Governance following the earlier transfer. The authoritative owner is the row's `spec` and anchor. Inventory those existing cases in P3 and make the naming treatment explicit; do not perform unrelated global renaming or claim that a stale prefix alone invalidates coverage. If retaining a stable old ID is necessary, document the exception and its destination rather than silently treating the prefix as current ownership.

Re-quote and re-anchor rows in the same commit as the text. Split or retire a row only with an explicit mapping to its surviving obligations; do not invent a `relocated` coverage state. Preserve `partial`, `todo` and role-specific coverage unless new evidence justifies a change. Do not promote coverage because the owning document changed.

## Implementation sequence

### P0 Establish the work record

1. **Ruling of record.** D1134 is the recorded supersession, and Revision 2's proposed P0 text is withdrawn. D1195 confirms that the eight exit conditions, P5 and this plan's completion record remain the full gate for `-02`.
2. **Baseline.** Frozen by this revision at `ac00dc76`: body 35,829 words, Extensibility 2,089 and appendices 2,804 ([measure.py](measure.py)); 112 family citations across 29 documents ([inventory.py](inventory.py)).
3. **Tracking issue.** File a self-contained issue that quotes the exit conditions and lists the remaining packages and their acceptance, in about 1,000 words, linking this plan at its merged commit. Search first, add it to #302 after re-reading its body, and record one D-row. Filing needs the owner's "file".
4. **P5 readers.** Name the two independent readers before P3's remaining work starts, or obtain a ruling on whether a disclosed cold model reader may serve as one. Without them P5 cannot pass and `-02` cannot publish.

Do not rewrite historical D-rows. A builder must not promote its own proposal to a ruling.

### P3 Complete the creation-extension contract

**Done:** the binding's normative import of Approval Governance is removed (#1974). Mission-Creating Paths states the local requirements D1134 sets: the defining profile specifies its basis type and activation semantics, and the activating issuer records `activation`, `activation_actor`, `root_commitment` and `approved_at`. `mission-activation-policy` left the binding's anchors, the retired Contract rows are mapped (#1992), and the manifest edge is gone (#2006). The import is not restored and the relaxation is not undone (D1195).

**Remaining:**

1. **The local extension contract.** Implement the seven-point checklist above in the existing Extension Points (777 words at the baseline), so that each retained hook states the extension author's duties and the behavior of a deployment that does not implement it (exit 5). Fund it within the Extensibility budget (Size measurement, below). The table is a review checklist, not seven new normative paragraphs.
2. **A1.** Delete the Governance example from `policy_version`'s definition; the conditional REQUIRED rule stays complete without it (D1195).
3. **Adopter review.** Confirm that Template, Progressive, Child Delegation and `governed_policy` each state their adoption of the Contract, with explicit scope for profile authors and activating issuers; that their manifest edges match (#2006 asserted them); and that the ledger carries their scoped rows. Correct an incomplete chain in its own document.
4. **Governance member explanations.** For the four Principals and Approval Basis citations and the Single Accountable Approver pair, keep the binding's recognition and opacity rules complete locally and leave the companion-defined members to Governance. An informative pointer stays only at its hook (exit 3).

**Required preservation checks:** the contract's root limits, policy identity and version, historical inputs, recency, activation classification, accountability and per-instance validation remain imposed on the same adopting deployments. Stored unknown discriminators remain opaque provenance and never become an inference of `direct` or `policy`. Direct human adjudication remains defined locally. The D1061 implied-anchor rules remain intact.

**Acceptance:** direct-only conformance is fully answerable from the binding; a second reviewer can explain the alternative-creation contract from the binding alone; every standing-consent adopter keeps a complete normative chain; incoming anchor and section-title references resolve; and the prose budget is reported. This package requires substantive review even where wording is relocated unchanged.

### P2 Put optional mechanism duties in their owning profiles

**Files:** the binding and the existing profiles whose duties actually move, selected from Cross-Domain, Expansion, Child Delegation, Template, Continuation, Submission Evidence, Status, MAS and the associated manifests. Do not touch all of these merely because they are named in the inventory.

**Changes:**

1. Rewrite Grant Bindings and Related Mechanisms around generic categories: issuance under an existing binding, establishment of a new reusable binding, creation of another Mission, transient exchange artifacts and runtime joins. Keep the distinctions that matter without listing every family mechanism.
2. Audit the Cross-Domain references individually. Keep identity, authority, expiry and authenticated-binding requirements locally. Move destination-specific token, lineage, subject-resolution and local actor-chain procedures to Cross-Domain, preserving their conditional applicability.
3. Audit the Cross-Domain optional-capability declaration and its four properties. Prefer retaining its property-based bar with no mandatory document reference if it is complete locally. If the named claim is inseparable from the profile, relocate the claim and its rows explicitly; do not silently erase the interoperability bar.
4. Make Submission Evidence dispatch and refusal complete for an AS that supports no evidence types. Remove any unconditional instruction to implement the companion's verification-cost or output framework. For an AS supporting a type, its owning profile adopts the framework's additional obligations explicitly.
5. Done by #1960: the revocation requirement is property-based, and Status owns the conditional client-authentication duty of a Lifecycle endpoint that serves as the token-independent means (D1114, D1120).
6. Keep optional back-channel and deferred creation hooks in terms of approval sequencing and grant establishment. Put named transport examples in their profiles.

**Packaging:** use one coordinated family PR if the transfer is compact. Split Cross-Domain and evidence/creation transfers only if the paragraph inventory shows independent changes large enough to obscure review. A transfer lands atomically with its destination and row updates, or destination-first while the source remains binding. Never land a source deletion before the destination imposes the duty.

**Acceptance:** the same adopter roles remain subject to each moved requirement; supporting no extension requires no companion lookup; known request and token behavior is unchanged. Internal anchors and incoming section-title citations from every affected draft resolve to the correct surviving or relocated obligation, not merely an existing heading. Any intended behavior change becomes an explicit finding and separate reviewed change, not a relocation side effect.

### P1 Make the baseline explicit and remove explanatory detours

**Files:** the OAuth binding, Architecture only where the adoption pointer needs a destination, family and conformance manifests where references or quoted text change, and the generated index when required.

**Changes:**

1. Put a short baseline implementation paragraph in Applicability or Overview, linked to Conformance. Explain the value delivered without enumerating absent companions.
2. Remove named companion solution paragraphs from Single Accountable Approver, security, privacy, deployment choices and non-goals where the binding's own limitation is already complete.
3. Remove repeated type-specific parentheticals that add no requirement. Defer the examples and any unique type rules to P4.
4. Replace redundant Substrate pointers with local commitment or conformance references. Do not import the Substrate's construction as a new normative dependency.
5. Retain useful informative navigation at the extension hook it explains, with a complete local contract and no mandatory lookup. Remove repeated pointers and family catalogues from the direct flow. Architecture should provide optional family navigation, not repeat a second set of protocol rules.

**Do not change:** direct approval ordering, token and grant semantics, commitments, error meanings or any optional capability's obligations. Where a paragraph has a unique duty, assign it to P2 or P3 instead of deleting it in P1.

**Acceptance:** each cut has a disposition; all security limitations survive; internal and incoming section references resolve; all changed drafts build and manifest checks pass. A reader can identify the baseline without following the Architecture pointer. This PR is editorial only if its disposition review confirms no requirement change.

### P4 Replace the baseline examples

**Files:** the binding, the example's chosen existing destination if the Resource Access walkthrough is retained, relevant example fixtures and digest tooling, and manifests if quoted obligations or pins change.

**Changes:**

1. Reuse the `payment_initiation` example from [RFC 9396](https://www.rfc-editor.org/rfc/rfc9396.html#section-2), rather than minting a new example type identifier. State clearly that it is an illustrative API type, not a complete standardized payment API or a mandatory Mission type. RFC 9396 leaves the interpretation of a type to the AS and API; citing its example does not supply a missing executable schema.
2. State the exact limited semantics this walkthrough assumes for that example: the accepted field shapes and values, audience, requested payment, rejection of malformed or unsupported entries, and the RS enforcement needed to demonstrate the Mission bound. Prefer one approved entry carried unchanged, avoiding an unintroduced subset algebra. Do not turn the illustrative choice into a new protocol requirement.
3. Use the same type in the introductory example, Authority Set example, Mission Record, token examples and the main end-to-end walkthrough. Audit the delegated example too so a supposedly optional chapter does not refer to an unexplained entry type. RFC 9396's payment fields define no subset relation, so the delegated example carries its entry unchanged or illustrates delegation without narrowing. Label the example's fields so it is not read as the family's standing-payment scenario.
4. Walk through submission, authenticated approval, atomic creation, code redemption, token consumption, refresh and revocation with no companion. Show at least one refusal and explain which consumer mode supplies current state.
5. Preserve an existing Resource Access integration fixture where other drafts and tests rely on it. Separate the new illustrative example from that fixture rather than changing every family's example to the new type.
6. Add a dedicated fixture under `vectors/core-standalone/` and a deterministic generator/check command, proposed as `scripts/generate-core-standalone-fixture.mjs --check`. Record the exact Intent, approved entry, issuer, record member presence, commitment envelopes, JCS bytes and expected digests. Verify the generator against the binding's existing integrity vectors before generating the fixture. A test using the reference's independent anchor implementation must reproduce the new fixture's digests; the canonical-base64 checker alone does not prove correct preimages.
7. Check that every displayed example object and hash agrees with the dedicated fixture, so a changed example field fails verification. If compact signed tokens are displayed, generate them from test-only keys and verify their signatures and claims. If signatures are omitted, label them as illustrative and do not present an invalid compact token as verifiable. Keep `baseline-q3` and its Resource Access consumers unchanged unless an independently reviewed change requires otherwise.
8. Do not assume the existing AS accepts `payment_initiation`. The example fixture and its validation are part of P4; an actual end-to-end AS witness needs explicit support for the illustrated type. Report that separately from successful digest and schema checks. Never hand-edit a displayed hash to match an assumed result.

**Acceptance:** all example fields and operations are defined by the binding, the underlying OAuth standards or the locally stated example type. A consumer can reproduce changed commitments. No example implies immediate revocation of every JWT or imports an optional runtime decision. No normative requirement is inferred from a merely illustrative application type.

### P5 Prove the resulting boundary

**Files:** the issue's acceptance record and local review materials. Add repository regression checks only where they protect a meaningful dependency boundary, rather than enforcing a fragile count of names.

1. Run the implementation-reading exercise below against a frozen final source commit.
2. Compare the final citation and dependency inventories with the baseline. Classify every remaining informative family citation by its extension hook and navigation purpose. Prove that deleting the link, while retaining the surrounding text, would leave a complete baseline implementation contract. A residual hidden normative dependency is a failure; the number of useful informative links is not.
3. Review the final requirement-transfer map as a whole, especially subjects that were edited in more than one PR.
4. Check the minimal reference configuration with optional capabilities unclaimed. If the implementation cannot run such a configuration, record and scope the implementation gap separately. A specification-only plan cannot claim an independent implementation witness that did not run.
5. Record success or failure per acceptance item. Keep the tracking issue open for unresolved semantic or implementation-reading failures; fewer words alone does not justify closure.

### Separate work under issue 1412

The current issue already records an eight-paragraph inventory, three ledger rows, two error-table rows and a proposed existing-document destination. Its decision keeps the text until a publication trigger and a published destination are available. Retain that decision for this project's required PRs.

If the owner separately advances extraction, use #1412's destination-first path: place generic client-instance rules in client-instance-id, preserve Mission-specific identity and authorization limitations in the binding, account for keyword-free duties, and remove the normative reference only when no remaining clause depends on it. Do not send or file anything in that separate repository or upstream without the owner's explicit instruction.

This is a correction to treating client-instance extraction as an ordinary cleanup in the initial analysis. It is useful optional follow-on work, but not required to remove Mission-family dependencies.

## Baseline implementation reading exercise

Use a small defect-hunting panel: two independent readers who did not author the changed text, one taking the AS implementer's perspective and one the extension author's perspective. Both answer the baseline questions; the second also attempts the two extension exercises. Karl is the adjudicator for disputed requirements and dispositions. Record the actual readers before starting; if two independent readers are unavailable, report that acceptance as incomplete rather than substituting repeated runs by the author. This is a planned review arrangement, not authorization to spawn agents in this session.

Freeze the inputs, questions and answer key before the final review. Permit only the candidate binding, its normative underlying OAuth standards and the example type defined locally. Do not provide Architecture, Governance, Resource Access or another Mission companion as explanatory material.

Ask the reader to produce an implementation outline and answer these questions with local section references:

1. What does a client submit through PAR, and what is refused if the AS supports no evidence type?
2. How does the AS establish the Approver, Subject and authority source before showing or committing consent?
3. What exactly is approved, and why can task prose not widen it?
4. Which checks must still hold at the atomic creation commit?
5. Which record members are required, which can be implied, and how are unknown approval discriminators handled?
6. How are commitments constructed and checked, including a stored value that disagrees with its authoritative inputs?
7. What binds an authorization code and subsequent refresh lineage to the Mission?
8. Which state, expiry, audience and authority checks apply to issuance and refresh?
9. What can a JWT consumer establish without a status service, and what does an introspected consumer additionally establish?
10. How can an authorized caller revoke the Mission without presenting one of its tokens, and what happens to tokens already issued?
11. What can the AS carry unchanged when it supports no narrowing, delegation or projection transformation for a type?
12. Which additional behavior is required if the deployment adopts an extension, and where is that adoption specified?

For each answer record correctness, omissions, incorrect conclusions, unresolved assumptions, sections consulted and whether a companion lookup was necessary. Time and navigation effort are secondary observations. One unexplained baseline requirement or required companion lookup is a defect to resolve, even if the aggregate score is high.

This panel is a defect review, not another scored comparison study. Each finding receives an adjudicated disposition and a focused recheck after correction. No aggregate percentage can compensate for an unexplained requirement or mandatory companion lookup. Reading-speed or comparative-readability claims are outside the release gate; if later desired, they require a separately designed comparison. Any automated review must disclose its limitations.

Separately test the extension contract with two paper implementations: a new evidence type and an alternative approval carriage. Each should be able to identify its naming, validation, authorization, commitment, failure and conformance duties without a companion-specific amendment to the binding. An extension is not required to be implementable without its own chosen dependencies.

## Validation by change type

| Change | Required validation |
| --- | --- |
| Explanatory deletion | Paragraph disposition, retained security boundary, incoming and local reference checks, draft build. No implementation test merely mirroring deleted prose. |
| Normative relocation | Before/after role, condition and timing comparison; source and destination builds; ledger re-quotation; preserved test citations and applicability. |
| Changed protocol behavior | Explicit finding and review scope, distinguishing public-surface test, relevant mutation proof, typecheck, lint and appropriate test suites. |
| Example conversion | Parsed example validation, computed digest/signature checks, fixture consumers, rendered review and baseline reading exercise. |
| Manifest edits | Family, conformance and external-pin checks, regenerated index and applicable checker tests. |
| Whole-series completion | No mandatory companion lookup, correct normative dependency graph, complete disposition map and recorded acceptance results. |

Use the repository's current commands from a fresh implementation worktree:

```sh
make draft-mcguinness-oauth-mission.txt
node scripts/check-family-manifest.mjs
node scripts/check-conformance-manifest.mjs
node scripts/check-external-pins.mjs
node scripts/generate-drafts-index.mjs
```

Build each changed companion as well. Run `check-substrate-statements.mjs` if mapping-assessment references or capability declarations change, and the canonical-digest and fixture checks when examples change. Where code changes are needed, run `pnpm typecheck`, `pnpm lint` and the appropriate `pnpm test` invocation in `src/`; account for OpenFGA-gated tests through the established live environment or CI. An unrelated timeout must be distinguished from a protocol failure, not silently counted as a pass.

Keep all changed source pins current. Inspect rendered tables, examples, internal anchors and external section-title references. Treat keyword totals as a useful alarm, not an acceptance criterion for requirement ownership changes.

## Sequencing and concurrent work

P0's remaining items, the tracking issue and the P5 readers, precede renewed draft edits. P3's remaining work lands next, then P2, P1 and P4, one PR each; P5 evaluates the combined result. Package IDs are stable labels, not execution order. A relocation lands destination-first and its source deletion waits. P2 never starts relocating against an unwritten contract.

The dependency removal has landed, so normative family independence holds at the references level. The `-02` release gate is not complete (D1195). The owner has selected aggressive scope for `-02`; do not move P1, P2 or P4 to a later revision solely to preserve the current schedule. Present any newly discovered semantic blocker explicitly instead of quietly publishing a partial pass.

Queue reviews one implementation PR at a time. Prepare inventories and fixtures while a PR is reviewed, but avoid competing rewrites of the same binding sections. This reduces repeated conflict resolution without weakening the `-02` scope.

Build from a fresh `origin/main` in an isolated worktree. Do not modify this older checkout's tracked draft. Before beginning a package, re-read the tracking issue, current open PRs and the affected sections. PRs #1939 and #1942 have merged, and their results are part of the baseline.

Keep each PR independently reviewable, state whether it is editorial, normative relocation or behavior-changing, and include its paragraph disposition. PRs say Part of the tracking issue until all exit conditions are satisfied. Every applicable check must pass at the actual reviewed merge head. Regenerate `DRAFTS.md` rather than resolving generated counts by hand. A semantic conflict resolution returns for review.

The owner retains merge, publication and upstream actions. Publication of `-02` waits for P1 to P5; the release tag still requires the owner's separate publish instruction. No tag or automatic publication is part of this plan. The plan does not require a new reader edition, a new protocol draft or a document merger.

## Size measurement and the Mapping Assessment

P0 froze the execution baseline after the overlapping merges. Count whitespace-separated prose tokens from Introduction to before IANA Considerations, excluding fenced code blocks, bibliography and Document History. Count the Extensibility chapter separately under the same rules. Keep the exact extraction script and both baseline values with the issue's acceptance record. Report appendix and example growth separately so moving text outside the measured body cannot conceal extra baseline reading. P5 compares the same regions and requires no net growth; a correctness-driven exception is an explicit reviewed change to the budget, not a silent waiver.

Frozen at `ac00dc76` with [measure.py](measure.py): body 35,829 words, Extensibility 2,089 and appendices 2,804. At Revision 2's baseline the same script gives 35,639, 2,026 and 2,800. D1192's figures used a different extraction, so only this script's values are compared.

Exit condition 5 adds duties to Extension Points while exit 8 holds Extensibility flat, so the contract is funded from text already in that chapter: Mission-Creating Paths grew 56 words with #1974, and Extension Points restates rules that their home sections state. The owner may instead rule a single body budget with Extensibility reported separately; until then both budgets hold.

Architecture's Mapping Assessment is an assessment of its pinned older binding snapshot. P5 must run check (t), confirm that the assessed snapshot and its scope warning remain accurate, and confirm the new binding does not claim that the old assessment covers it. Do not update the pin as mechanical housekeeping. A current-revision assessment requires a separate substantive clause-by-clause reassessment and its own disposition record. Keeping the honestly labelled historical assessment is compatible with `-02` publication; claiming current coverage without that reassessment is not.

## Main risks and controls

| Risk | Control |
| --- | --- |
| Removing a companion citation also removes a condition or exception. | Review the full paragraph and its ledger applicability, not just the linked sentence. |
| Governance no longer binds an existing activation path. | Enumerate actual basis producers and add explicit adopter duties before removing the binding's bridge. |
| Generic extensibility prose becomes another large specification. | Keep one local home for each invariant, enforce the measured prose budget and require extensions to specify their mechanisms. Do not copy whole companion contracts into the binding. |
| The baseline appears to need Resource Access despite formal independence. | Reuse the RFC 9396 illustrative payment type with explicit local assumptions and a dedicated verified fixture throughout the walkthrough. |
| Example changes disturb committed artifacts elsewhere. | Separate illustrative examples from shared integration fixtures and recompute all affected commitments. |
| Unknown extension handling becomes permissive. | Preserve refusal for unsupported authority-bearing input and distinguish it from opaque provenance retention. |
| Reduced companion coverage is mistaken for reduced runtime obligations. | Preserve the binding's limits and each adopted extension's duties; never represent a baseline issuance guarantee as an effect-time guarantee. |
| The work repeats prior editorial moves without helping implementers. | Require the baseline reading exercise and record unresolved questions, not just a shorter word count. |
| A future generic Mission Model split reintroduces dependencies. | Keep #207's trigger separate; this plan defines the current OAuth implementation boundary, not the outcome of a future WG architecture decision. |

## Completion record

The tracking issue can close only when P1 to P4 are merged, P5 has recorded its results, every moved obligation has a destination, and the baseline requires no Mission companion. Record any separately deferred external dependency under its existing issue rather than claiming it was removed.

The final report should give the merged heads, the before/after citation and normative-dependency counts, the complete baseline exercise results, any deliberate semantic changes, and remaining optional work. It must distinguish successful implementation independence from any separately unproved claim of improved reading speed.
