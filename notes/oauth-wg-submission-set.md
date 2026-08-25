# Author's Proposed Initial Submission Set for OAuth WG Discussion

This document records the author's own proposal, prepared under the
ruling on issue #704 (2026-08-24). A repository-owner ruling authorizes
preparing this record; it does not itself create a working-group package
or imply working-group adoption. This record implies no WG adoption, no
consensus, and no standing beyond the author's own intent. Its members
remain individual `draft-mcguinness-*` submissions, not a package with
standing of its own.

The proposal is one of three distinct products the ruling names, not the
only publication surface the family maintains:

| Product | Composition |
|---|---|
| Initial WG conversation | The OAuth Mission core and, separately, the Mission Resource Access RAR profile (this document) |
| Normative dependency closure | Whatever each selected specification actually imports (computed below) |
| Implementation reader bundle | `notes/oauth-mission-baseline-bundle-preview.md`, a separate publication artifact |

The reader-bundle preview constrains nothing here: it is an implementation
guide assembled for a different audience and purpose, and this document
does not draw on it as precedent or restrict it in return.

## Submission set composition

The proposed submission set is exactly two Internet-Drafts, presented
separately:

- `draft-mcguinness-oauth-mission`, "Mission-Bound Authorization for OAuth
  2.0" (the OAuth Mission core, the issuance profile).
- `draft-mcguinness-oauth-mission-resource-access`, "Mission Resource
  Access Profile for OAuth 2.0" (the RAR profile: the
  `mission_resource_access` `authorization_details` type).

The profile's split out of the core executed first: issue #637, merged as
PR #718. The submission set therefore names two documents that already
exist as an actual split in the tree, not a relocation still pending.

## Record binding

The composition, the dependency closure, and the category verification
below are all bound to one commit, not asserted as a standing current
state. Computed at main commit `c41a39844fc1bedf04470f6c88ed5d9c06bd7fb1`
(2026-08-25, the merge of PR #727):

| Member | Commit | Content SHA-256 |
|---|---|---|
| `draft-mcguinness-oauth-mission.md` | `c41a39844fc1bedf04470f6c88ed5d9c06bd7fb1` | `8fb582dc630c9cc7edc8989187d1e5f56cd28489445d1ec3e4dd1595b505619b` |
| `draft-mcguinness-oauth-mission-resource-access.md` | `c41a39844fc1bedf04470f6c88ed5d9c06bd7fb1` | `6d42f9224efa92e2133c4028af083b703c0b1f19cd080bfad083bc567880c3b1` |

A later change to either file does not retroactively change this record;
it would need a fresh binding.

## Normative dependency closure

Extracted from each draft's front matter `normative:` block at the bound
commit, cross-checked against `DEPENDENCIES.md`'s generated
external-normative-ids block (no entry there for either
`oauth-mission` or `oauth-mission-resource-access`, confirming neither
draft normatively cites a work-in-progress external Internet-Draft).

Publication venue and standards maturity are different axes: an
Internet-Draft citing a reference does not inherit that reference's own
RFC category, and a Standards Track submission's normative references
are not all required to themselves be Standards Track. The table below
records each reference's actual category and, for every
non-Standards-Track entry, whether it already carries precedent in the
IETF downref registry. Method, so a future audit can re-run and diff:
category is each RFC's `std_level` field from the datatracker document
API (`datatracker.ietf.org/api/v1/doc/document/?name=rfcNNNN`); downref
presence is a lookup of the RFC number in the registry table at
`datatracker.ietf.org/doc/downref/`. Both checked live on 2026-08-25.
"Cited by" marks which of the two submission-set members references it;
every entry below is cited at least by the core, and 9 RFCs plus
ISO 4217 are also cited by the resource-access profile.

| Reference | Category | Cited by | Downref registry |
|---|---|---|---|
| RFC 3339 | Proposed Standard | core, resource-access | not applicable (Standards Track) |
| RFC 3986 | Internet Standard | core, resource-access | not applicable (Standards Track) |
| RFC 4648 | Proposed Standard | core | not applicable (Standards Track) |
| RFC 5646 | BCP | core | not in registry |
| RFC 6234 | Informational | core | in registry |
| RFC 6749 | Proposed Standard | core | not applicable (Standards Track) |
| RFC 6750 | Proposed Standard | core, resource-access | not applicable (Standards Track) |
| RFC 6920 | Proposed Standard | core | not applicable (Standards Track) |
| RFC 7493 | Proposed Standard | core | not applicable (Standards Track) |
| RFC 7519 | Proposed Standard | core | not applicable (Standards Track) |
| RFC 7636 | Proposed Standard | core | not applicable (Standards Track) |
| RFC 7662 | Proposed Standard | core | not applicable (Standards Track) |
| RFC 7800 | Proposed Standard | core | not applicable (Standards Track) |
| RFC 8259 | Internet Standard | core, resource-access | not applicable (Standards Track) |
| RFC 8414 | Proposed Standard | core | not applicable (Standards Track) |
| RFC 8693 | Proposed Standard | core, resource-access | not applicable (Standards Track) |
| RFC 8705 | Proposed Standard | core | not applicable (Standards Track) |
| RFC 8707 | Proposed Standard | core, resource-access | not applicable (Standards Track) |
| RFC 8785 | Informational | core, resource-access | not in registry |
| RFC 9068 | Proposed Standard | core | not applicable (Standards Track) |
| RFC 9101 | Proposed Standard | core | not applicable (Standards Track) |
| RFC 9126 | Proposed Standard | core | not applicable (Standards Track) |
| RFC 9207 | Proposed Standard | core | not applicable (Standards Track) |
| RFC 9396 | Proposed Standard | core, resource-access | not applicable (Standards Track) |
| RFC 9449 | Proposed Standard | core | not applicable (Standards Track) |
| RFC 9470 | Proposed Standard | core | not applicable (Standards Track) |
| RFC 9700 | BCP | core | not in registry |
| RFC 9728 | Proposed Standard | core, resource-access | not applicable (Standards Track) |
| ISO 4217:2015 | External SDO standard | core, resource-access | not applicable (non-IETF) |

Category counts across the 28 RFCs: 22 Proposed Standard, 2 Internet
Standard, 2 BCP (RFC 5646, RFC 9700), 2 Informational (RFC 6234,
RFC 8785). Plus ISO 4217:2015, an external-SDO reference outside the
IETF's own category scheme entirely.

Resource-access's normative set (9 RFCs, ISO 4217, and one
Internet-Draft: the core itself) is a strict subset of the table above
plus the in-family core reference; it introduces no reference the table
does not already carry.

Downref handling a Standards Track submission would need to address:
RFC 8785 (JSON Canonicalization Scheme), an Informational normative
reference, carries no entry in the IETF downref registry as fetched on
2026-08-25, so a Standards Track submission citing it normatively would
raise the downref during IETF Last Call with no established precedent to
point to. RFC 6234, also Informational, does already carry a registry
entry (approved precedent for a different document's normative
citation); that does not exempt a new citing document from Last Call
review, but it is precedent a reviewer can be pointed to. Neither BCP
reference (RFC 5646, RFC 9700) appears in the registry, consistent with
BCP normally not requiring downref handling from a Standards Track
citer. ISO 4217:2015 is an external-SDO normative reference outside the
IETF's downref process altogether; RFC 2026 permits a normative
reference to an external standard given a stable citation, which a fixed
edition (2015) provides.

This live verification confirms, without exception, the two specific
claims raised in review: RFC 6234 is in the downref registry and
RFC 8785 is not. Checking the remaining 26 references found none of them
present in the registry either.

The property that survives this correction: every reference in the
closure is either a published RFC (of whatever category) or a finalized
external standard with a stable citation. None is a work-in-progress
external Internet-Draft.

## What the submission set omits, and why

### Substrate

`draft-mcguinness-mission-substrate` is the family's only
`spec_maturity: candidate` document, the sole document to earn the
candidate gate's attestation in the 2026-08-25 completeness audit
(`notes/audits/2026-08-25-substrate-completeness-audit.md`; reviewed and
merged as PR #727). It is a Standards-Track candidate in-repository, and
it is omitted from this proposed submission set.

Two preconditions gate a separate substrate submission. The first,
removing the substrate's normative OAuth dependency (#708), is resolved
in tree at commit `30982cda740aa761272d847e476d9a77a1ee9726` (PR #717):
the substrate's normative references are now crypto and canonicalization
RFCs only (RFC 4648, RFC 6234, RFC 6920, RFC 7493, RFC 8785), and its
references to the OAuth core and the Mission Authority Server are
informative. The second, independent non-OAuth implementation feedback,
is outstanding: the substrate audit report records the caveat plainly,
"all implementation evidence is OAuth-shaped, no non-OAuth binding
evidence exists yet" (first recorded during the PR #727 review).

The omission is a decision under the family's internal readiness gate,
not an RFC-category judgment. The two-implementations bar is an Internet
Standard advancement criterion (RFC 6410 Section 2), not a Proposed
Standard entry gate (RFC 2026 Section 4.1.1). Publishing the substrate
Informational while an AAuth binding normatively depends on it and
remains Standards Track would manufacture a downref (RFC 8067).

### Architecture

`draft-mcguinness-mission-architecture` is informational context for the
WG conversation, not a submission-set member.

### MAS

`draft-mcguinness-mission-authority-server` (MAS) is classified as a
normative standalone-controller protocol binding over the OAuth Mission
data model: a peer deployment topology, not an independent substrate
model, since it normatively imports the OAuth Mission record and issuance
profile. Bindings, including MAS, are not submission-set members.

### Everything else

Companions, overlays, and the remaining bindings follow later, each per
its own maturity. `candidate-gate.json` (check (z) in
`scripts/generate-drafts-index.mjs`) is the promotion mechanism toward
`spec_maturity: candidate`. The current per-document gap lists live in
the dated audit records: `notes/audits/2026-08-25-substrate-completeness-audit.md`,
`notes/audits/2026-08-25-core-completeness-audit.md`, and
`notes/audits/2026-08-25-resource-access-completeness-audit.md`. PR #727
is the review venue those records were reached under, not the tracker
for their content.

## Maturity disclosure

Both submission-set members carry `spec_maturity: experimental` under
the family's candidate gate. The 2026-08-25 audit wave found the core
failing criterion 1 (61 conformance rows against approximately 322
BCP-14 keyword hits, with several named Conformance sections rowless;
full gap list in `notes/audits/2026-08-25-core-completeness-audit.md`)
and the resource-access profile failing the same criterion (13 rows, all
`todo`, with the Subset Rule algebra and the Common Constraints registry
uninventoried; full gap list in
`notes/audits/2026-08-25-resource-access-completeness-audit.md`).

This proposal leads with the WG conversation regardless: the candidate
gate is an internal completeness bar the family holds itself to, not a
submission prerequisite the IETF imposes. The dated audit records are
the work queue toward candidate, not a blocker to opening the
conversation this document proposes.
