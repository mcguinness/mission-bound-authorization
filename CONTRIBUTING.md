# Contributing

This repository relates to activities in the Internet Engineering Task Force
([IETF](https://www.ietf.org/)). All material in this repository is considered
Contributions to the IETF Standards Process, as defined in the intellectual
property policies of IETF currently designated as
[BCP 78](https://www.rfc-editor.org/info/bcp78),
[BCP 79](https://www.rfc-editor.org/info/bcp79) and the
[IETF Trust Legal Provisions (TLP) Relating to IETF Documents](http://trustee.ietf.org/trust-legal-provisions.html).

Any edit, commit, pull request, issue, comment or other change made to this
repository constitutes Contributions to the IETF Standards Process
(https://www.ietf.org/).

You agree to comply with all applicable IETF policies and procedures, including,
BCP 78, 79, the TLP, and the TLP rules regarding code components (e.g. being
subject to a Simplified BSD License) in Contributions.

## How to Contribute

Contributions can be made by creating pull requests, opening an issue, or
posting to the working group mailing list. See above for the email address
and a note about policy.

Here are two ways to create a pull request ("PR"):

- Copy the repository and make a pull request using the Git command-line tool;
  see the [GitHub documentation](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/proposing-changes-to-your-work-with-pull-requests/creating-a-pull-request) for more.

- You can use the GitHub UI as follows:
  - View the draft source
  - Select the pencil icon to edit the file (usually top-right on the screen)
  - Make edits
  - Select "Commit changes"
  - Add a title and explanatory text
  - Select "Propose"
  - When prompted, click on "Create Pull Request"

Document authors/editors are often happy to accept contributions of text,
and might be willing to help you through the process. Email them and ask.

## Reference Classification Convention

A draft in this repository lists a reference as normative when any
BCP 14 requirement, even one conditional on adopting an OPTIONAL
capability or companion profile, requires implementing or consulting
it. A conditional dependency stays normative and states its scope in
the text ("binds only a deployment that adopts X"); the OAuth binding's Actor
Profile reference, confined to its OPTIONAL Delegation capability, is
the template.

Two bounds:

- **Maturity is a dependency boundary.** A Standards-Track draft never
  lists an Experimental draft as normative. A requirement that would
  create such a dependency moves into the Experimental draft, which
  places the duty on its own adopters; the Standards-Track draft keeps
  the reference informative and, where useful, points to it.
- **Named claims bind to properties, not documents.** Where a claim's
  condition can be stated as a deployment property (no unmediated
  path, isolated disclosure rendering), the profile states the
  property and cites the companion that defines the standard way to
  establish it; the citation may then stay informative.


## Document History Convention

Only the OAuth binding carries a Document History appendix today. A companion
adds its own by touch: the next substantive revision of a companion
adds `# Document History {#document-history}` with a real entry
describing that revision. Empty stubs are never bulk-added; git
history remains the pre-publication record, and the appendix records
substantive deltas between published revisions.

## Conformance Traceability Convention

Every new or changed externally testable normative requirement
identifies its observable conformance assertion and lands with a
manifest-linked test at the lowest public surface that can
distinguish conforming from non-conforming behavior.
Negative/refusal, no-side-effect, output-bound, replay, concurrency,
and privacy assertions are all valid forms; a requirement is not
covered merely because a refusal exists somewhere.

The record is `conformance-manifest.json`, validated in CI by
`scripts/check-conformance-manifest.mjs`: unknown anchors, quoted
clauses missing from their anchored section, duplicate IDs, missing
tests, and coverage states inconsistent with their test mappings
fail; rows whose coverage is `partial`, `todo`, or `blocked` are the
visible outstanding report (the reverse mapping is the metric, not
tag coverage). Each row carries the conforming role, BCP 14 strength
(`stated` for present-tense normative prose), a machine-readable
applicability condition, the published baseline profile(s) it belongs
to (`profiles`, validated against the manifest's own top-level enum;
empty when the requirement belongs to no published baseline profile),
protocol surface,
assertion form, a declared coverage state, per-test level and surface
mappings, and the normative observation separated from any locally
chosen behavior.

Two rules keep the record honest. Only pin an OAuth error code or
Mission diagnostic where the draft normatively specifies it: a test
must not turn an implementation's preferred error into an accidental
protocol requirement. And a runner never marks an unclaimed optional
capability nonconforming, or a justified SHOULD departure a failure
(RFC 2119 Section 3); both are recorded, not failed.

## Maintenance Classes Convention

`family-manifest.json`'s `maintenance` field states how responsively
this repository maintains a draft. Maintenance is orthogonal to
maturity: `maturity` is specification stability, `maintenance` is
repository responsiveness, and neither implies the other. The design
record for this split, and for the classes below, is
[notes/adoption-plan.md](notes/adoption-plan.md).

Five classes, machine-enumerated in `family-manifest.json`'s
`maintenance_classes` array and enforced by
`scripts/check-family-manifest.mjs`:

- **active**: full peer-symmetry maintenance.
- **active-experimental**: active maintenance while the draft stays
  experimental, earned by implementation evidence (a named
  `maintenance_owner`, an active implementation, and meaningful
  tested conformance coverage, recorded in `maintenance_evidence`).
  Promotion to `active` is always a recorded human decision, made
  against a `maintenance_review_after` horizon rather than
  automatically.
- **frozen-until-upstream-release**: text fixes only; a shape change
  waits on the cited upstream specification's own release.
- **lab-floor-referenced**: Lab maturity, but active-tier
  responsiveness for the specific property that a floor document's
  text points at.
- **lab-best-effort**: best effort, no maintenance cadence; the gate
  out of the Lab is a four-condition check (a Mission Substrate
  Statement where the draft binds a new substrate, the abstract
  dropping deferred/sketch language, a named adopter or implementer
  commitment on record, and category/maturity updated together
  in one PR).

## Consolidation Policy

No document consolidation happens before WG adoption or publication planning.
Reader editions are the chosen remedy for reader-facing coherence in the
meantime: navigation-linked per-document HTML copies plus a separately
concatenated bundle-text artifact, built from the existing separate
documents, never a merge of their source. Concatenated HTML inlining was
rejected. The lifecycle group's and the runtime/evidence pair's document
boundaries are reconsidered only when WG adoption or publication planning
is reached; see `notes/adoption-plan.md` for the measured basis.

`aauth-mission-expiry` retirement goes upstream-first, and requires a
released upstream AAuth revision, cited stably (never a transient
editor-copy merge), that absorbs every normative requirement this
profile's Conformance section adds: the rule that `expires_at`, once
present, must name an instant later than `approved_at`; the
deployment's documented clock synchronization, comparison precision,
and tolerated clock skew; and the prompt deadline-transition SHOULD.
The standalone profile retires only once that revision is released and
covers all of it. Folding it into the Mission AAuth binding stays
rejected, since that would strand the bare-AAuth audience.

## Working Group Information

Discussion of this work occurs on the [Web Authorization Protocol
Working Group mailing list](mailto:oauth@ietf.org)
([archive](https://mailarchive.ietf.org/arch/browse/oauth/),
[subscribe](https://www.ietf.org/mailman/listinfo/oauth)).
In addition to contributions in GitHub, you are encouraged to participate in
discussions there.

**Note**: Some working groups adopt a policy whereby substantive discussion of
technical issues needs to occur on the mailing list.

You might also like to familiarize yourself with other
[Working Group documents](https://datatracker.ietf.org/wg/oauth/documents/).
