# Substrate Completeness Audit, 2026-08-25

This is the versioned audit report `candidate-gate.json`'s
`documents["draft-mcguinness-mission-substrate"].requirement_inventory.report`
points to (path and `document_sha256`). It is the durable record behind the
`attested: true` claim: not a mutable PR description, a repository file that
this candidate's attestation cites by digest.

Audited document: `draft-mcguinness-mission-substrate.md`.
Audit method: mechanical BCP-14 keyword-line extraction against the
document's working tree, cross-referenced against every
`conformance-manifest.json` row naming this spec.

## (b) Audited document digest

sha256(`draft-mcguinness-mission-substrate.md`) as of the audit commit
(post-regeneration bytes, the same bytes `conformance-manifest.json`'s
`source.specs["draft-mcguinness-mission-substrate.md"].content_sha256`
pins at that commit):

```
5553530d68a34c7c8c83865c0584fb0334b04ad78ca17cce4a30e4f4fb3525c0
```

If `candidate-gate.json`'s `report.document_sha256` ever differs from
`conformance-manifest.json`'s current `content_sha256` for this file, that is
a staleness signal (`scripts/generate-drafts-index.mjs`'s `validateCandidateGate`
prints a warning; it does not fail the gate), not proof this report is wrong:
a family-status regeneration changes the document's bytes on every unrelated
maturity flip anywhere in the family. A human judges, from the diff, whether
the change is substantive enough to warrant a fresh audit.

## (a) Clause-level inventory

Every BCP-14 keyword line in the document (mechanical extraction: every
line matching `MUST|MUST NOT|SHOULD|SHOULD NOT|SHALL|SHALL NOT|REQUIRED|
RECOMMENDED|MAY|OPTIONAL`, excluding the `{::boilerplate}` directive itself),
grouped by anchor, in document order. 105 keyword lines exist. 93 map to one
of the document's 88 conformance rows (several rows each cover a short
clause that runs onto a second physical line; two rows each cover a line
that both closes one clause and opens the next). The remaining 12 are
excluded, each with a stated rationale: 11 descriptive or permissive `MAY`
sentences carrying no independent testable obligation, and one umbrella
`MUST` covered by aggregation across the kernel's nine constituent anchors.

One genuine gap surfaced by this extraction (line 604, Default Commitment
Construction) did not exist as an "explicit exclusion with rationale": it
was simply unrowed. Per the same precedent this audit wave already applies
to the Composition by Capability clauses (document-directed MUSTs get rows
in this ledger, at whatever coverage state the evidence supports), a row was
added: `substrate.default-commitment.new-prefix-transition-duties`,
`coverage: "todo"`. This is disclosed here rather than silently folded in,
so the owner can reverse it in one edit if a narrower scope was intended.
It does not change the audit's verdict: criterion 1 is inventory
completeness, not test coverage, and `todo` is where most of the document's
rows already sit.

Row ids are given without the `substrate.` prefix for width.

### Scope and Kernel umbrella

| Line | Anchor | Disposition |
| ---: | --- | --- |
| 211 | scope | Excluded: descriptive `MAY`, restates that capability-supplied guarantees originate in the binding, not the kernel; no independent testable content. |
| 289 | kernel | Excluded (aggregate): "Every Mission Substrate Binding MUST provide all requirements in this section" is the umbrella introducing the kernel's nine constituent duties, each separately rowed below (`reference`, `authority-roles`, `actor-binding`, `approved-context`, `approval`, `basic-gate`, `bounded-reliance`, `propagation`, `governance-record`). Rowing it again would duplicate those rows under a tenth, redundant id. |

### Mission Reference {#reference}

| Line | Row |
| ---: | --- |
| 311 | `reference.stable-unambiguous-non-reassigned` |
| 320 | `reference.namespace-disambiguation` |
| 325 | `reference.unguessability` |
| 332 | `reference.controller-identification` |
| 335 | `reference.no-overclaim-global-uniqueness` |

### Authority Roles {#authority-roles}

| Line | Disposition |
| ---: | --- |
| 342 | Excluded: "Roles MAY be co-located in one implementation" is scene-setting for the MUST NOT at line 343; not independently testable. |
| 343 | `authority-roles.no-silent-collapse` |

### Actor Binding {#actor-binding}

| Line | Row |
| ---: | --- |
| 368 | `actor-binding.bind-at-approval` |
| 370 | `actor-binding.authenticated-derivation-only` (clause opens here) |
| 371 | `actor-binding.authenticated-derivation-only` |
| 374 | `actor-binding.statement-disclosure` |
| 382 | `actor-binding.identifier-mapping-definition` |

### Approved Context {#approved-context}

| Line | Row |
| ---: | --- |
| 387 | `approved-context.maintain-or-commit` |
| 388 | Closes `maintain-or-commit`, opens `approved-context.immutability` |
| 390 | `approved-context.mutable-fields-distinguishable` |
| 395 | `approved-context.no-silent-replacement` |
| 399 | `approved-context.commitment-definition-requirements` |
| 414 | Excluded: "A default construction a binding MAY adopt" points to the Default Commitment Construction section; the construction's own duties are separately rowed there. |

### Approval {#approval}

| Line | Row |
| ---: | --- |
| 419 | `approval.atomic-ceremony` |
| 421 | `approval.ceremony-steps` |
| 433 | `approval.no-create-without-consent-to-changed-context` |
| 437 | `approval.untrusted-material-identification` |

### Basic Governance Gate {#basic-gate}

| Line | Row |
| ---: | --- |
| 449 | `basic-gate.active-predicate-and-outcome` |
| 454 | `basic-gate.decision-only-while-active` |
| 456 | `basic-gate.unrecognized-fails-closed` |
| 466 | `basic-gate.non-active-transition-definition` |
| 467 | `basic-gate.non-active-transition-definition` (its `observation.normative` folds in "identifies the authorized parties and the effect on subsequent Controller decisions") |
| 469 | Excluded: "A binding MAY express completion, revocation, expiry, or supersession as reasons" is a naming-freedom permission, not a testable obligation. |

### Bounded Reliance {#bounded-reliance}

| Line | Row |
| ---: | --- |
| 475 | `bounded-reliance.stated-bound-required` |
| 478 | `bounded-reliance.stated-bound-required` (its `observation.normative` folds in the two-forms enumeration: decision-point residual interval, or artifact expiry bounded by/disclosed with the Approved Context) |
| 489 | `bounded-reliance.should-not-exceed-purpose` |

### Context Propagation {#propagation}

| Line | Row |
| ---: | --- |
| 500 | `propagation.carry-or-joinable` |
| 501 | `propagation.carry-or-joinable` (its `observation.normative` folds in "the binding defines the join and the party performing it") |
| 509 | `propagation.proof-property-distinction` |
| 510 | `propagation.proof-property-distinction` |

### Ordered Governance Record {#governance-record}

| Line | Row |
| ---: | --- |
| 525 | `governance-record.maintain-integrity-protected-ordered` |
| 526 | `governance-record.minimum-coverage-and-attribution` |
| 528 | `governance-record.minimum-coverage-and-attribution` (its `observation.normative` folds in "events are attributable to their source and correlated with the Mission Reference") |
| 534 | `governance-record.ordering-and-retention-statement` |
| 536 | `governance-record.retention-covers-post-termination` |

### Default Commitment Construction {#default-commitment}

| Line | Disposition |
| ---: | --- |
| 546 | Excluded: "MAY satisfy the commitment duties... with the following default construction" is the section's optional-adoption intro; the construction's own MUSTs are rowed below. |
| 583 | `default-commitment.ijson-conformance` |
| 585 | `default-commitment.ijson-conformance` (its `observation.normative` folds in the duplicate-member/non-conformant-input rejection detail) |
| 600 | `default-commitment.reject-unknown-prefix` |
| 601 | `default-commitment.reject-unknown-prefix` |
| 604 | `default-commitment.new-prefix-transition-duties` (new row, see above) |
| 642 | Excluded: "A binding MAY publish additional worked examples" is a permission to add non-normative material, not an obligation. |

### Optional Capabilities {#capabilities}

| Line | Row |
| ---: | --- |
| 655 | `capabilities.claim-requires-complete-satisfaction` |
| 658 | `capabilities.scope-must-appear-in-statement` |

### Lifecycle-Gated {#lifecycle-gated}

| Line | Row |
| ---: | --- |
| 681 | `lifecycle-gated.statement-enumerates-operations` |
| 685 | `lifecycle-gated.decision-point-establishes-active` |
| 687 | `lifecycle-gated.freshness-fail-closed` |
| 688 | Closes `freshness-fail-closed`, opens `lifecycle-gated.residual-interval-statement` |
| 694 | `lifecycle-gated.no-generalize-narrower-claim` |

### State-Observable {#state-observable}

| Line | Row |
| ---: | --- |
| 699 | `state-observable.expose-authenticated-source` |
| 702 | `state-observable.statement-disclosure` |
| 710 | Excluded: "The source MAY return native state names" is a permitted-form statement, not a testable obligation. |
| 711 | `state-observable.projection-preserves-distinction` |
| 712 | `state-observable.projection-preserves-distinction` |

### Structured Authority {#structured-authority}

| Line | Row |
| ---: | --- |
| 721 | `structured-authority.define-representation-and-owner` |
| 723 | `structured-authority.define-representation-and-owner` |
| 724 | `structured-authority.statement-specifics` |
| 733 | Excluded: "Different resources or administrative domains MAY use different authority languages" is scope-setting, not an obligation. |
| 738 | `structured-authority.comparison-definition-and-fail-closed` |
| 740 | `structured-authority.comparison-definition-and-fail-closed` |

### Monotonic Derivation {#monotonic-derivation}

| Line | Row |
| ---: | --- |
| 745 | `monotonic-derivation.also-claims-structured-authority` |
| 746 | `monotonic-derivation.no-broader-than-relation-definition` |
| 751 | `monotonic-derivation.verify-no-broader-and-fail-closed` |
| 752 | `monotonic-derivation.verify-no-broader-and-fail-closed` |
| 753 | `monotonic-derivation.statement-identifies-narrowing-points` |
| 774 | `monotonic-derivation.no-constrain-uncovered-hop` |

### Credential-Bound {#credential-bound}

| Line | Row |
| ---: | --- |
| 782 | `credential-bound.integrity-protected-association` |
| 785 | `credential-bound.identify-elements` |
| 794 | Excluded: "The association MAY be a JWT claim, another credential field..." lists permitted mechanisms, not an obligation. |
| 799 | `credential-bound.fact-semantics-selection` |
| 800 | `credential-bound.fact-semantics-selection` |
| 811 | `credential-bound.no-shared-unqualified-claim` |

### Authorized Context Correlation {#authorized-context-correlation}

| Line | Row |
| ---: | --- |
| 818 | `authorized-context-correlation.supply-authorized-association` |
| 823 | `authorized-context-correlation.claim-identifies-elements` |

### Independently Verifiable {#independently-verifiable}

| Line | Row |
| ---: | --- |
| 846 | `independently-verifiable.online-query-free-verification` |
| 848 | `independently-verifiable.statement-enumerates-properties` |
| 852 | `independently-verifiable.define-verification-elements` |
| 855 | `independently-verifiable.failure-fails-closed` |

### Portable Evidence {#portable-evidence}

| Line | Row |
| ---: | --- |
| 864 | `portable-evidence.define-transferable-evidence` |
| 866 | `portable-evidence.statement-identifies-elements` |
| 876 | Excluded: "Portable Evidence MAY reveal only a commitment to Approved Context" describes a permitted minimization, not an obligation. |

### Composition by Capability {#composition}

Superseded classification: see "(d) Superseded classification" below.

| Line | Row |
| ---: | --- |
| 885 | `composition.declare-consumed-capabilities` |
| 886 | `composition.no-inferred-capability-from-generic-claim` |
| 905 | `composition.adapter-states-assumptions-and-failure-behavior` |
| 914 | `composition.preserve-capability-scope-boundaries` |

### Mission Substrate Statement {#statement}

| Line | Row |
| ---: | --- |
| 942 | `statement.section-required-with-version-and-mode` |
| 943 | Excluded: "another document MAY instead publish a Mapping Assessment" describes the alternative-path mechanism, not itself an obligation on either party. |
| 953 | `statement.section-required-with-version-and-mode` (its `observation.normative` folds in "identifying the specification version and mode it applies to", covering "Either form MUST identify...") |
| 956 | `statement.kernel-checklist` |
| 977 | `statement.capability-table-required` |
| 978 | `statement.binary-supplied-state` |
| 984 | `statement.supplied-row-requirements` |
| 1021 | `statement.added-capability-requires-updated-statement` |

### Context Splicing {#context-splicing}

| Line | Row |
| ---: | --- |
| 1064 | `context-splicing.correlation-required-and-no-coincidence-association` |

### Privacy Considerations {#privacy-considerations}

| Line | Row |
| ---: | --- |
| 1112 | `privacy.reference-disclosure-limited-to-correlation-need` |
| 1114 | `privacy.prefer-audience-specific-derived-handles` |
| 1120 | `privacy.minimize-context-in-credentials-state-evidence` |
| 1121 | `privacy.document-disclosure-from-capability-claims` |

## (c) Decide-issue query snapshot

Date: 2026-08-25. Command:

```
gh issue list --label decide --state open --json number,title -R mcguinness/mission-bound-authorization
```

Result, verbatim:

```json
[{"number":722,"title":"conformance-manifest.json: missing object boundary silently drops cross-domain.resource-as.client-id-identifies-redeemer"},{"number":664,"title":"Harness/discovery: SHOULD-level taint duties are MUST-strength load-bearing input"},{"number":663,"title":"Family: three uncross-referenced accounts of what earns 'Mission-bound'"},{"number":662,"title":"Audit: three experimental normative down-references vs CONTRIBUTING's maturity bound"},{"number":661,"title":"Cross-boundary freshness: projection's lease vs cross-org's live check, one boundary, two mandatory postures"},{"number":660,"title":"Approval-time: template/progressive prohibited sets diverge from the core's high-risk classification"},{"number":653,"title":"Child-delegation: draft retains the interactive creation path the D62 ruling removed"},{"number":648,"title":"Impl: transaction-assurance idempotency claim states, idempotency_conflict, tombstones, active reconciliation (S-6 disposition stale)"},{"number":238,"title":"Runtime: define a runtime-core conformance subset with named assurance extensions"}]
```

None of these nine name `draft-mcguinness-mission-substrate` in a way this
audit found load-bearing for its interface. This snapshot is a limited,
not a complete, check on criterion 2, and the limitation is concrete
rather than theoretical: `candidate-gate.json`'s own `decide_issue_scope`
carries entries for #708, #705, #703, and #242, none of which carries the
`decide` label this query filters on (#708 and #703 carry `coordinated`,
#705 carries `parked`, #242 carries `coordinated`). A query scoped to the
`decide` label alone would have missed all four. `validateCandidateGate()`'s
criterion-2 loop only iterates issues already present in
`decide_issue_scope`, so it is fail-open with respect to any issue,
however labeled, that should be scoped but is not yet an entry; this
snapshot is disclosure of that boundary, not a fix for it. Recording the
date, command, and full result verbatim at least makes the boundary
checkable: a future audit can re-run the same query and diff.

## (d) Superseded classification

Commit `ac7c59a3d3489c9ce5cc0cdcbb260532cd93f974` (this audit wave's first
commit) classified the Composition by Capability section's four MUST
clauses as a "document-directed requirements" class the conformance ledger
"deliberately does not model as per-implementation rows," recording the
substrate's requirement inventory complete with that class marked
out-of-ledger.

That classification is **superseded** by this report. A subsequent review
of this pull request pointed out that the ledger already inventories
Statement-directed requirements aimed at other specifications (the seven
`statement.*` rows above, each addressed to a specification other than
this one, each rowed with `role: "Controller"` and quoted text exactly as
it appears in {{statement}}): the four Composition by Capability MUSTs are
the same class, not a different one, and the "does not model" premise was
wrong. They are rowed above (`composition.declare-consumed-capabilities`,
`composition.no-inferred-capability-from-generic-claim`,
`composition.adapter-states-assumptions-and-failure-behavior`,
`composition.preserve-capability-scope-boundaries`), each `coverage: "todo"`,
matching every `statement.*` row's own coverage state.

This correction does not change the audit's verdict (the substrate's
requirement inventory was, and remains, assessed complete); it changes the
reasoning: completeness here comes from those four clauses being rowed,
not from a now-abandoned argument that they never needed to be.
