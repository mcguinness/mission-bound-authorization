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


## Wire Names Convention

This convention governs names a draft newly defines. Existing
definitions are grandfathered; changing one is a migration that needs
its own justification. The pattern was inferred from the family's
usage in the wire-name audit (#911).

New Mission-specific names introduced into shared registries outside
the family include `mission`, using the registry's required syntax.
Members within Mission-owned objects need no additional prefix: the
OAuth parameter is `mission_expires_at`, while the record member stays
`expires_at`.

New names otherwise follow the family's existing pattern:

- **Case.** Parameters, claims, metadata members, error codes, record
  members, and enumerated values are lowercase snake_case. Media
  subtypes, JWS `typ` labels, and URN tails are lowercase kebab-case
  (`application/mission-<thing>+json`, `+jws`, or `+jwt`).
- **Metadata shapes.** Endpoint metadata follows RFC 8414:
  `<x>_endpoint`, per-endpoint `<endpoint>_auth_methods_supported` and
  `<endpoint>_auth_signing_alg_values_supported`, and
  `<feature>_supported` for a boolean.
- **Instants.** An instant ends in `_at` (a bound in `_until`,
  `_before`, or `_after`) and is an RFC 3339 date-time string.
  NumericDate is used only for JWT-level claims such as `iat` and `exp`.
- **Durations.** A new duration defaults to integer seconds. Each
  definition states its permitted range, the instant it is measured
  from, and its boundary behavior; positive-only is a per-definition
  choice, not the default.

Three bounds:

- **Signed and committed values are stable.** Existing names and
  values inside signed or committed objects (fingerprint `op` values,
  digest preimages, signed receipts) keep their spelling. A newly
  defined signed object follows this convention.
- **Inherited names keep their upstream form.** A name taken from
  another specification (RFC 8693 parameters, JOSE and JWT claims,
  AuthZEN and AAuth members) keeps its upstream spelling and semantics.
- **A lint checks declarations, not words.** An automated check of
  this convention examines definitions in their namespace (IANA
  registration entries and member definitions), not every matching
  word or JSON member, and carries an explicit list of grandfathered
  definitions.


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

Coverage changes follow the same discipline:

- A row reaches `tested` only with a real assertion and a citation that
  matches the test's exact `describe > it` path. Never change a row's
  coverage by editing its note; a note explains coverage, it never
  establishes it.
- Prove each new test by disabling the code it covers and watching it
  fail.
- Cite a row under the role it proves; a PEP test is not a PDP
  witness. Demote a row tested on the wrong role's test, even though
  the count drops.
- A change to a clause a row quotes re-quotes that row in the same
  commit, and a changed draft is re-pinned in `source.specs`.

## Maintenance Classes Convention

`family-manifest.json`'s `maintenance` field states how responsively
this repository maintains a draft. Maintenance is orthogonal to spec
maturity: `spec_maturity` is a five-criteria gate on the document's own
claimed interface (complete requirement inventory, no internal
contradiction or open `decide` issue on that interface, a named
interoperability floor with representative evidence where evidence is
claimed, examples and a clean build, and disclosed unstable external
dependencies), never a raw coverage percentage; `maintenance` is
repository responsiveness; and neither implies the other. (`role`,
covering core, adapter-binding, companion, and guide, is a third
axis, orthogonal to both, and architectural rather than a maturity
signal.) The design record for this split, and for the classes below,
is
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
  commitment on record, and category/spec_maturity updated together
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

## Issue Convention

These rules apply to every issue, whether a person or an agent files or
edits it. #302 holds the stack rank for the open set.

### Body

An issue body is canonical: when a ruling lands or a PR merges, edit
the body (Current state, Decisions of record) rather than only adding a
comment. Comments are history. Use these headings, in this order:

- **Problem**: the gap or decision, stated as a fact about the drafts or
  code on `main`, not the thread's history.
- **Current state**: what has merged (PR, commit, `src/PLAN.md` D-row)
  and what remains.
- **Decisions of record**: each owner ruling, cited by comment permalink
  or D-row. A review or recommendation posted under the owner's account
  is a ruling only when a D-row records it as ruled or the comment says
  it is the owner's ruling, approval, or plan of record. Anything else
  goes under Analysis or Open questions.
- **Analysis**: why it matters, the constraints that apply, the options.
- **Sketch**: numbered steps a builder can execute (files, ledger rows,
  tests, re-pins), then the alternatives and the recommendation.
- **Acceptance**: observable checks.
- **Dependencies**: Blocked by, Blocks, Related.
- **Open questions**: each owner ruling still needed, with a
  recommended answer.

A `parked` issue replaces Sketch with **Trigger** (the named condition)
and **When triggered** (the first steps). A `tracking` issue uses
**Purpose**, **Items** (a status table), **Rules** and **Exit
condition**.

Bodies are self-contained. Do not cite files that exist only in a local
checkout; carry the needed content into the body. Write another
repository's issues as `owner/repo#N` (upstream AAuth is
`dickhardt/AAuth#N`) and review-finding numbers as "finding N", so
GitHub does not autolink them to this repository's issues. No
em-dashes.

### Labels

- Exactly one tier: `now` (executable, no open dependency), `decide`
  (needs an owner ruling; the body states the question and a
  recommended answer), `blocked` (waits on an open issue named in
  Dependencies), `roadmap` (later, no trigger), `parked` (deferred until
  a named trigger), or `tracking` (open by design).
- Exactly one priority, `P1` (next round), `P2` or `P3`, on every issue
  that is not `parked` or `tracking`.
- At most one type: `bug`, `enhancement`, `documentation`, or
  `question`. Trackers carry none.
- `upstream` when the issue has an owner-only external action (a send,
  an upstream filing, a working-group engagement).

Change a tier or priority only with a recorded reason. A parked issue
moves only on its trigger or the owner's word.

### Filing

Search open issues first (`gh issue list --search`); extend an existing
issue rather than filing a duplicate. A new issue gets its tier,
priority and type labels when it is filed, and a row in #302. Re-read
#302's current body immediately before editing it; never write it back
from an earlier copy.

### Closing, splitting, reissuing

- A PR body uses `Fixes #N` or `Closes #N` only when the PR resolves
  every item in the issue. Move any remaining item to its own issue
  first, and say so in both bodies.
- Before reopening an issue a PR closed, read its current body: items
  may have been split out on purpose.
- Close a superseded issue with a comment naming its successor, and the
  `duplicate` or `completed` reason.
- An issue cited from the ledger, `src/PLAN.md` or other issues keeps
  its number; a thread that has grown hard to read gets a rewritten
  body, not a new issue.
- Every ledger row with `blocked_by` points at an open issue; when that
  issue closes, repoint the row.
- A ruling or merge that changes an issue also gets one D-row in
  `src/PLAN.md` (committed directly to `main`).

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
