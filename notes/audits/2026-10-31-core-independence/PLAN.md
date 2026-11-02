# OAuth binding independence implementation plan

Revision 3, 2026-11-02. Revision 2 (2026-10-31) is this file's first committed version.

The OAuth binding will define a complete direct approval and issuance protocol, together with the invariants and extension rules that other specifications must preserve. An authorization server must be able to obtain useful Mission functionality without implementing a Mission companion. Companions will define their additional mechanisms and explain how they satisfy the binding's contracts.

This plan implements the owner's direction to remove companion dependencies and reduce the knowledge needed to implement the binding. The owner's subsequent direction is to be aggressive for `-02`: complete the independence pass before publishing that revision, rather than defer its substantive work to a later revision. It separates editorial removals from changes to normative ownership. It does not create a smaller conformance class or another specification.

Revision 2 incorporated the critique of sequencing, extension-contract ownership, size controls, citations, examples and validation. Revision 3 updates the execution text for what has landed, without changing the gate. Package IDs remain stable so the citation inventory still applies; the remaining execution order is P0, the extension-contract review, P2, P1, P4, P5.

## Revision 3 status

Landed since Revision 2:

- **P3's dependency inversion:** #1974, merged as `f02a1306` (#1967, D1167) under D1134's option B. The binding's `normative:` list holds no Mission family draft, and it states its standing-consent requirements locally. A profile defined elsewhere may use another mechanism while meeting them, which D1134 records as an intentional normative relaxation. The Approval Basis Contract stays in Governance and keeps binding its adopters.
- **The Contract rows:** Governance's Approval Basis Contract rows leave the binding's baseline profiles (#1992, #1985, D1189).
- **The manifest edge:** the family manifest's conditional Governance edge on the binding is removed (#2006, D1198).

Not complete, per the review against these criteria at `1988e136` (D1192), as corrected by the owner's assessment (D1195):

- **The extension contract (exit condition 5)** is not demonstrated, since no clause-by-clause audit of the hooks has been performed. The preparatory commit Revision 2 placed before the dependency removal cannot now precede it, so the contract review is its own step.
- **P2, P1 and P4** have not started. Grant Bindings and Related Mechanisms still carries the mechanism catalogue that P2 item 1 replaces.
- **P5** has not run, and neither P0's tracking issue nor its execution baseline exists.

D1195 confirms this plan's eight exit conditions, P5 and completion record as the full gate for `-02`, subject to D1134's semantic ruling. The text below keeps the gate as written; passages about work that has since landed carry dated status notes.

## Baseline and delivery status

The source baseline is `b2b6c052d7a0987c4822d534587b23bdc2b17a6f`, fetched from `origin/main` on 2026-10-31. Some decision rows at that commit use 2026-11-01 dates; the commit identifies the baseline unambiguously. The working checkout is older, so all source analysis uses the fetched commit rather than the checkout's draft files.

Completed for this plan:

- The companion citation inventory has been refreshed against that baseline.
- The recent approval-procedure, approval-basis and implied-anchor decisions have been reconciled with the proposed changes.
- Open issues and PRs have been checked for overlapping work.
- The implementation sequence, requirement-transfer controls and acceptance exercises are specified below.

Revision 2 and its inventory were local, untracked working files; Revision 3 commits them (#1944). The planning pass changed no specification, ledger, issue, PR or decision-log entry. The plan is not evidence that any acceptance check has passed.

Supporting files:

- [Companion citation inventory](CITATIONS.md) identifies each occurrence and its source section.
- [Machine-readable citation inventory](citations.json) records the same occurrences for subsequent comparison.
- [Inventory generator](inventory.py) regenerates the inventory from an explicit git revision without changing the checkout. It requires `--output`; the inventory files beside it are the pinned baseline.

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

D1195 (2026-11-02): these eight conditions, P5 and the completion record are the full gate for `-02`, subject to D1134's semantic ruling.

The zero-reference target is for Mission-family dependencies. External OAuth dependencies, including Actor Profile and RAR remediation where retained requirements use them, must remain honestly classified. The client-instance question has its own existing decision and is handled separately below.

## Current dependency inventory

At the baseline, the binding contained 114 citation occurrences to 28 in-repository family documents. The count covers citation markup from the abstract through the material before Document History. It excludes bibliography declarations and historical notes. Another 16 occurrences cite three adjacent McGuinness documents outside the family manifest: client-instance-id, Actor Profile and client-attesters.

| Family document or group | Occurrences | Primary problem | Planned treatment |
| --- | ---: | --- | --- |
| Cross-Domain | 18 | A particular optional issuance mechanism is threaded through generic issuance, principal and grant rules. | Keep generic invariants locally and put mechanism-specific duties in Cross-Domain. |
| Resource Access | 17 | Type-specific explanations and examples appear to be part of the baseline protocol. | Keep the type contract locally and replace the baseline examples. |
| Approval Governance | 12 | The binding normatively imports its standing-consent contract and explains extension-specific record members. | Invert adoption dependencies while preserving creation invariants and all adopter duties. |
| Expansion | 8 | Successor and review mechanics are repeated in the baseline path. | Keep generic new-Mission and changed-authority rules; let Expansion specify its procedure. |
| Submission Evidence | 6 | The baseline dispatch/refusal contract is mixed with the optional verification framework. | Complete the baseline contract locally; move the framework's additional duties to its adopters. |
| Consent Evidence and Status | 5 each | Optional disclosure or observation mechanisms are presented beside baseline obligations. | Keep baseline confidentiality, revocation and consumption rules; move named solutions out. |
| Architecture, Child Delegation and Security Model | 4 each | Explanatory navigation and optional mechanism comparisons interrupt the main flow. | Retain only indispensable generic explanations; place family navigation in Architecture. |
| Other family documents | 31 | Small references accumulate across creation, issuance, security, privacy and extensibility. | Classify each occurrence using the disposition procedure below. |

At the baseline, the only in-family normative reference was Approval Governance. The family manifest had an empty unconditional `adoption_requires` list for the binding, and a conditional Governance dependency for standing-consent activation. Therefore this project removes a real conditional dependency and a much larger reading burden; it does not repair a requirement that every existing AS implement the whole family.

Status (2026-11-02): the normative reference and the conditional edge are both removed (#1974, D1167; #2006, D1198). At `1988e136` the inventory generator counts 112 occurrences to 29 family documents. Approval Governance's 12 are now 9, a Mandate citation was added, and every other document's count is unchanged.

## Decisions retained and decisions revised

| Decision or issue | Treatment in this plan |
| --- | --- |
| D1057 and D1058, Approval Basis Contract | D1134 (2026-11-01, option B) records the supersession, in its own wording. The binding states its standing-consent requirements locally, and a profile defined elsewhere may use another mechanism while meeting them. The Contract stays in Governance and keeps binding its adopters: Template, Progressive, Child Delegation and `governed_policy`. D1054 and D1056's mandatory connection is superseded only to that extent. It landed in #1974 (D1167). |
| D1061 and D1070, implied anchors | Preserve computation from authoritative immutable inputs, the specified algorithm, rejection of mismatching stored anchors, creation-time availability and whole-record member presence. This work does not make commitments weaker or change their preimages. |
| D1081 and PR #1941 (merged), direct approval procedure | Preserve the seven numbered steps, their order and atomicity, and the topic subsections that now own their rules. Do not recreate the former long procedure. |
| #1915 and #1917 | Keep these completed issues closed. This plan concerns dependency direction, not unfinished execution of their old proposals. Record the limited supersession of D1057 in the new work's issue and D-row. |
| #1723 and #1793 | Keep their measured results and closures. Previous reader work did not demonstrate the proposed improvement. Do not reuse keyword totals or those results as evidence that this plan succeeds. |
| #1412 and D559, client-instance composition | Reuse #1412. Its current decision keeps the normative reference until its publication trigger and destination conditions are met. This work must not silently move the material into an unsuitable companion or downgrade the citation. The optional extraction is not a prerequisite of Mission-family independence. |
| #207, Mission Model split | Remain parked. This work makes the OAuth binding self-contained and introduces no normative Substrate dependency. It neither executes the split nor retires or merges documents. |
| #1895, token-independent revocation | Ruled (D1114, adopting A with B's clarification) and implemented by PR #1960 (merged as `208f2aaf`, D1123); #1895 is closed as completed. Preserve the token-independent authorization result in P2. |
| #1937 and PR #1939, issued-token validity | PR #1939 is merged and #1937 is closed; the consumer-specific revocation wording is on main. Do not restore an unconditional claim that every issued token remains valid until expiry. |
| #1504 and PR #1942, editorial residue and legacy states | PR #1942 is merged and #1504 is closed. Work from the merged result in overlapping sections. Do not reintroduce removed legacy interpretations or duplicate the consumption-mode rewrite. |
| #1927, record and evidence follow-ups | #1927 is closed as completed. Re-anchor its rows if this plan changes their owning sections, and do not silently change its `verified_at` outcome. |

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

**Status (2026-11-02):** D1134 records the D1057 supersession in its own wording (see the decisions table), so the text quoted below is historical. #1895 is closed (PR #1960, D1123). Still to do: the tracking issue, its #302 row and the execution-baseline freeze. The issue is filed only on the owner's word.

The inventory and this plan complete the initial local preparation. The owner's direction authorizes pursuing independence for `-02`; the plan itself is not a substitute for an explicit record of which previous decision is superseded. The P0 record must state:

> For `-02`, supersede D1057 only as to the OAuth binding's normative import of Approval Governance. Keep the Approval Basis Contract in Governance, place its adoption duties in each profile that uses it, and retain the universal creation invariants in the binding. Do not publish `-02` until the independence acceptance criteria pass. Retain useful informative citations at their extension hooks; impose no single-pointer limit.

Record this as the implementation direction, with the owner's instruction as its authority, before treating D1057 as superseded in an issue or PR. If the recorded owner direction is narrower, obtain the missing specific ruling before implementing that part; a builder must not promote its own proposal to a ruling. No D-row has been written by this planning revision.

Reconcile #1895 using its posted owner-ruling permalink rather than treating its stale label as the absence of a decision. Its open state represents implementation and bookkeeping work. P2 must coordinate with its owner and must not assume its proposed text is already on main.

Before changing the Editor's Draft, file a self-contained tracking issue with four implementation items and the acceptance exercise below. Search again immediately before filing because other sessions may have added an owner. Use separate child issues for the Approval Governance dependency and example conversion if they have independently reviewable acceptance. Reuse #1412 rather than duplicating it.

The issue body must include the scope, required invariants, D1057 supersession, PR order and closure criteria; it must not depend on these local files being available. Add the issue to #302 after re-reading its current body. Record the owner's direction and the limited supersession in one fresh D-row, taking the number only after fetching current main. Do not rewrite historical D-rows.

### P3 Remove the Approval Governance dependency

**Status (2026-11-02):** the dependency inversion has landed (#1974, D1167; #1992, D1189; #2006, D1198), under D1134's option B, which differs from the steps below. The binding states local standing-consent requirements, and a profile defined elsewhere may meet them by another mechanism. The extension-contract work remains, as its own reviewable step. Its preparatory commit can no longer precede the landed change, and P3's acceptance item "direct-only conformance is fully answerable from the binding" is not demonstrated (D1195). The steps below stay as the record of the intended preservation checks. Do not restore the import or undo D1134's relaxation to recreate their order.

**Files:** the binding, Approval Governance, every existing standing-consent profile that adopts its contract, and the family and conformance manifests. Determine the adopter list from both normative references and actual `approval_basis.type` producers; searching only the phrase Approval Basis Contract is insufficient.

**First commit: the local extension contract.** This is assigned work within P3, not an implied prerequisite. Implement the seven-point ownership checklist above in the existing Extensibility section, using local pointers to existing invariants. Define the creation-extension contract before removing Governance's import. Keep the import in force through this preparatory commit.

This commit's acceptance is: each hook identifies its author duties and baseline behavior without consulting a companion; no existing invariant is weakened; no universal duty is accidentally imposed on a direct-only issuer; incoming anchor and title references still identify the intended rules; and the prose budget is reported. The seven-point table is a review checklist, not a requirement to add seven new normative paragraphs. A second reviewer must be able to explain the alternative-creation contract from the resulting binding alone.

**Subsequent commits: dependency inversion.**

1. Inventory all standing-consent bases and their activation paths. Include governed policy, Template activation, progressive drawdown and child activation where applicable. Check non-OAuth bindings that already adopt the Governance contract without changing their unrelated semantics.
2. Record the binding's universal creation invariants and the Governance contract's additional obligations separately. Reuse existing clauses rather than copying the entire contract back.
3. Give each adopting profile a direct normative dependency on the Approval Basis Contract, with explicit scope for profile authors and activating issuers. A profile whose existing dependency is incomplete must be corrected in this change.
4. Replace the binding's named normative import with the local creation-extension contract. Keep its root-authorization and per-instance checks, including authenticating the consenting principal and recording accountable consent, at their appropriate level of generality.
5. Keep a complete direct approval basis in the binding. Move extension-specific standing-consent member rules, policy adjudication detail and governance-record explanations to their owners only after all consumers have a usable definition. Preserve recognition rules and retained record bytes.
6. Remove `mission-activation-policy` from the list of binding-defined commitment species if Governance fully owns its definition. Preserve its existing `typ`, issuer binding, bytes and vectors. Removing its mention must not remove the generic envelope rules that apply to it.
7. Update the binding's normative references and `requires_when` edge only after the obligation map has no unresolved destination. Update adopter edges and reference classification together.

**Required preservation checks:** the contract's root limits, policy identity and version, historical inputs, recency, activation classification, accountability and per-instance validation remain imposed on the same adopting deployments. Stored unknown discriminators remain opaque provenance and never become an inference of `direct` or `policy`. Direct human adjudication remains defined locally. The D1061 implied-anchor rules remain intact.

**Acceptance:** direct-only conformance is fully answerable from the binding; every existing standing-consent adopter still has a complete normative chain; no Mission-family normative reference remains in the binding; all transferred rows have an owner and honest coverage. Incoming anchors and section-title references are checked across the family, and the text is reviewed against the completed extension-contract commit. This PR explicitly implements the recorded supersession of D1057 and requires substantive review even if most wording is relocated unchanged.

### P2 Put optional mechanism duties in their owning profiles

**Files:** the binding and the existing profiles whose duties actually move, selected from Cross-Domain, Expansion, Child Delegation, Template, Continuation, Submission Evidence, Status, MAS and the associated manifests. Do not touch all of these merely because they are named in the inventory.

**Changes:**

1. Rewrite Grant Bindings and Related Mechanisms around generic categories: issuance under an existing binding, establishment of a new reusable binding, creation of another Mission, transient exchange artifacts and runtime joins. Keep the distinctions that matter without listing every family mechanism.
2. Audit the Cross-Domain references individually. Keep identity, authority, expiry and authenticated-binding requirements locally. Move destination-specific token, lineage, subject-resolution and local actor-chain procedures to Cross-Domain, preserving their conditional applicability.
3. Audit the Cross-Domain optional-capability declaration and its four properties. Prefer retaining its property-based bar with no mandatory document reference if it is complete locally. If the named claim is inseparable from the profile, relocate the claim and its rows explicitly; do not silently erase the interoperability bar.
4. Make Submission Evidence dispatch and refusal complete for an AS that supports no evidence types. Remove any unconditional instruction to implement the companion's verification-cost or output framework. For an AS supporting a type, its owning profile adopts the framework's additional obligations explicitly.
5. Keep the revocation requirement property-based. If Status is used to satisfy it, Status owns the concrete method and its conditional duty. Preserve #1895's token-independent authorization result.
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
3. Use the same type in the introductory example, Authority Set example, Mission Record, token examples and the main end-to-end walkthrough. Audit the delegated example too so a supposedly optional chapter does not refer to an unexplained entry type.
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

P0 precedes any further draft edit. P3's dependency inversion has landed (D1167, D1189, D1198). Next comes the extension-contract review as its own reviewable step, then P2, P1 and P4. P5 evaluates the combined result. Package IDs are stable labels, not execution order. The remaining work is four main implementation PRs: the extension contract, P2, P1 and P4. P2 never starts relocating against an unwritten contract.

The dependency removal was the first useful stopping point, and the series has reached it: normative family independence (D1167). It has not completed the `-02` release gate (D1192, D1195). The owner has selected aggressive scope for `-02`; do not move P1, P2 or P4 to a later revision solely to preserve the current schedule. Present any newly discovered semantic blocker explicitly instead of quietly publishing a partial pass.

Queue reviews one implementation PR at a time. Prepare inventories and fixtures while a PR is reviewed, but avoid four competing rewrites of the same binding sections. This reduces repeated conflict resolution without weakening the `-02` scope.

Build from a fresh `origin/main` in an isolated worktree. Do not modify this older checkout's tracked draft. Before beginning a package, re-read the tracking issue, current open PRs and the affected sections. PR #1942 (broad editorial work) and PR #1939 (Revocation) have merged; work from their results, not from any earlier hunk.

Keep each PR independently reviewable, state whether it is editorial, normative relocation or behavior-changing, and include its paragraph disposition. PRs say Part of the tracking issue until all exit conditions are satisfied. Every applicable check must pass at the actual reviewed merge head. Regenerate `DRAFTS.md` rather than resolving generated counts by hand. A semantic conflict resolution returns for review.

The owner retains merge, publication and upstream actions. Publication of `-02` waits for P1 to P5; the release tag still requires the owner's separate publish instruction. No tag or automatic publication is part of this plan. The plan does not require a new reader edition, a new protocol draft or a document merger.

## Size measurement and the Mapping Assessment

At P0 freeze the execution baseline after incorporating any already-merged overlapping PRs. Status (2026-11-02): it is not yet frozen; freeze it before renewed package work, on a commit that includes #1974 (D1195). Count whitespace-separated prose tokens from Introduction to before IANA Considerations, excluding fenced code blocks, bibliography and Document History. Count the Extensibility chapter separately under the same rules. Keep the exact extraction script and both baseline values with the issue's acceptance record. Report appendix and example growth separately so moving text outside the measured body cannot conceal extra baseline reading. P5 compares the same regions and requires no net growth; a correctness-driven exception is an explicit reviewed change to the budget, not a silent waiver.

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
