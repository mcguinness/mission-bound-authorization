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
| Normative dependency closure | Whatever each selected specification actually imports; direct references are inventoried below, while the transitive closure remains unverified |
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

Both are on the datatracker:
- the core as `-01`, published 2026-10-21 (D644);
- the profile as `-00`, published 2026-10-22 (D646).

The profile was published alone, with its companion references made
informative and its own invariants stated in the profile (D645).

## Record binding

The composition, the direct-reference inventory, and the category verification
below are all bound to one commit, not asserted as a standing current
state. Computed at main commit `a9e35e79064409136f438b6495f110c68f67b059`
(2026-10-23):

| Member | Commit | Content SHA-256 |
|---|---|---|
| `draft-mcguinness-oauth-mission.md` | `a9e35e79064409136f438b6495f110c68f67b059` | `7b5f76eb4de93469d688e8d5420ad6f9fecdcd8f9a95234ec3dc0b4ae760b3ae` |
| `draft-mcguinness-oauth-mission-resource-access.md` | `a9e35e79064409136f438b6495f110c68f67b059` | `52dcce6f6f809438190f6b8685a9c24cf0d4f261f13f04f63f078d4ca8e44a54` |

A later change to either file does not retroactively change this record;
it would need a fresh binding.

This binding replaces the first one, at `c41a39844fc1bedf04470f6c88ed5d9c06bd7fb1`
(2026-08-25, the merge of PR #727; that record is in this file's git
history). The first binding's closure property ("None is a
work-in-progress external Internet-Draft") no longer holds. Since then
the core's `normative:` block has gained three external Internet-Drafts:
- `draft-mcguinness-oauth-client-instance-id`, by `45221526` (#851,
  D159);
- `draft-ietf-oauth-rar-metadata-remediation`, by `2e7c08608` (#1503
  finding 9, D620);
- `draft-mcguinness-oauth-actor-profile`, by `e6f6c911a` (D625).

## Direct normative references and dependency planning

Extracted from each draft's front matter `normative:` block at the bound
commit.

Cross-checked against `DEPENDENCIES.md`'s generated external-normative-ids
block:
- That block lists `draft-ietf-oauth-rar-metadata-remediation` for
  `oauth-mission`, and nothing for `oauth-mission-resource-access`.
- The generator skips `draft-mcguinness-*` references by prefix, so the
  core's two individual-draft references are listed below from the front
  matter, not from that block.

Publication venue and standards maturity are different axes: an
Internet-Draft citing a reference does not inherit that reference's own
RFC category, and a Standards Track submission's normative references
are not all required to themselves be Standards Track.

The table below records each RFC's actual category and, for every
non-Standards-Track entry, whether it already carries precedent in the
IETF downref registry.

Method, so a future audit can re-run and diff:
- Category is each RFC's `std_level` field from the datatracker
  document API (`datatracker.ietf.org/api/v1/doc/document/?name=rfcNNNN`).
- Downref presence is a lookup of the RFC number in the "Referenced RFC"
  column of the registry table at `datatracker.ietf.org/doc/downref/`.
- Both were checked live on 2026-10-23.
- "Cited by" marks which of the two submission-set members references the
  RFC.

| Reference | Category | Cited by | Downref registry |
|---|---|---|---|
| RFC 3339 | Proposed Standard | core, resource-access | not applicable (Standards Track) |
| RFC 3986 | Internet Standard | resource-access | not applicable (Standards Track) |
| RFC 4648 | Proposed Standard | core | not applicable (Standards Track) |
| RFC 5646 | BCP | core | not in registry |
| RFC 5890 | Proposed Standard | resource-access | not applicable (Standards Track) |
| RFC 6234 | Informational | core | in registry |
| RFC 6749 | Proposed Standard | core | not applicable (Standards Track) |
| RFC 6750 | Proposed Standard | core | not applicable (Standards Track) |
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
| RFC 8707 | Proposed Standard | core | not applicable (Standards Track) |
| RFC 8785 | Informational | core, resource-access | not in registry |
| RFC 9068 | Proposed Standard | core | not applicable (Standards Track) |
| RFC 9101 | Proposed Standard | core | not applicable (Standards Track) |
| RFC 9110 | Internet Standard | resource-access | not applicable (Standards Track) |
| RFC 9126 | Proposed Standard | core | not applicable (Standards Track) |
| RFC 9207 | Proposed Standard | core | not applicable (Standards Track) |
| RFC 9396 | Proposed Standard | core, resource-access | not applicable (Standards Track) |
| RFC 9449 | Proposed Standard | core | not applicable (Standards Track) |
| RFC 9470 | Proposed Standard | core | not applicable (Standards Track) |
| RFC 9700 | BCP | core | not in registry |
| RFC 9728 | Proposed Standard | core, resource-access | not applicable (Standards Track) |
| OpenID Connect Core 1.0 (errata set 2, 2023) | External standard (OpenID Foundation) | core | not applicable (non-IETF) |
| ISO 4217:2015 | External SDO standard | resource-access | not applicable (non-IETF) |

Category counts across the 30 RFCs: 23 Proposed Standard, 3 Internet
Standard, 2 BCP (RFC 5646, RFC 9700), 2 Informational (RFC 6234,
RFC 8785). Plus two non-IETF standards with fixed editions: OpenID
Connect Core 1.0 incorporating errata set 2 (the core, since #1503
finding 9) and ISO 4217:2015 (resource-access).

Resource-access's normative set is 9 RFCs, ISO 4217, and one
Internet-Draft: the core itself. It is no longer a subset of the core's
set. It adds RFC 3986, RFC 5890, RFC 9110 and ISO 4217, which the core
does not cite normatively.

Downref handling a Standards Track submission would need to address is
unchanged from the first binding:
- RFC 8785 (JSON Canonicalization Scheme) is an Informational normative
  reference with no entry in the downref registry, so a Standards Track
  submission citing it normatively raises the downref during IETF Last
  Call with no established precedent.
- RFC 6234, also Informational, carries a registry entry. That does not
  exempt a new citing document from Last Call review, but it is precedent
  a reviewer can be pointed to.
- Neither BCP reference (RFC 5646, RFC 9700) appears in the registry,
  consistent with BCP normally not requiring downref handling from a
  Standards Track citer.
- OpenID Connect Core and ISO 4217:2015 are external-standard normative
  references outside the IETF's downref process. RFC 2026 permits a
  normative reference to an external standard given a stable citation,
  which a fixed edition provides.

### Internet-Draft dependencies

The core cites three external Internet-Drafts normatively.
Resource-access cites none beyond the core. Datatracker states, checked
live on 2026-10-23:

| Internet-Draft | Revision | Stream | State | Cited from (core) |
|---|---|---|---|---|
| `draft-mcguinness-oauth-client-instance-id` | `-00` | individual | I-D Exists, expires 2027-04-01 | Instance Context in Delegated Tokens; the error-table note; an appendix future-work example |
| `draft-mcguinness-oauth-actor-profile` | `-01` | individual | I-D Exists, expires 2027-04-12 | Delegation Within a Mission; Delegated Exchange; Instance Context in Delegated Tokens; Scope and Future Work |
| `draft-ietf-oauth-rar-metadata-remediation` | `-00` | IETF, oauth WG | WG Document, expires 2027-02-24 | Denial Responses; Remediation Grains; Authorization Server Metadata |

A normative reference to an Internet-Draft does not block submission,
adoption or last call. Per RFC 7322 Section 4.8.6, it holds the RFC's
publication until the referenced draft is also ready, and the RFC
Editor then publishes the documents together; the queue state is
"Reference Not Received".

Those drafts have normative references of their own. A planning
inventory of that wider set lives with the layering plan (unmerged
notes branch `worktree-notes+oauth-binding-layering-plan`, PLAN.md
Appendix E):
- It traverses each draft's latest revision, not the revisions actually
  cited.
- It lists 16 distinct draft names reachable from the three above,
  including `draft-ietf-tls-rfc8446bis`, already published as
  [RFC 9846](https://datatracker.ietf.org/doc/rfc9846/). Within that
  inventory, 15 nodes remain unpublished drafts:
  - 12 through the Actor Profile: itself and 11 it pulls in, including
    an expired individual draft;
  - 2 through client-instance-id;
  - 1 through rar-metadata-remediation, which cites none.
- These counts describe the existing planning inventory after separating
  its published node; they do not establish a verified transitive closure.
- Some of its edges come from the datatracker's heuristic References
  tab.

The property this binding can state: every normative reference is a
published RFC, a fixed-edition external standard, the in-family core,
or one of the three Internet-Drafts above. It is not yet a verified
closure. A verified closure needs each node at the revision its citer
names, with a source section for every edge. Until then, use the
inventory for planning, not as a publication-date claim.

## What the submission set omits, and why

### Substrate

`draft-mcguinness-mission-substrate` is the family's only
`spec_maturity: candidate` document, the sole document to earn the
candidate gate's attestation in the 2026-08-25 completeness audit
(`notes/audits/2026-08-25-substrate-completeness-audit.md`; reviewed and
merged as PR #727). It is a Standards-Track candidate in-repository, and
it is omitted from this proposed submission set.

Two preconditions gate a separate substrate submission:
- **Remove the substrate's normative OAuth dependency (#708).** Resolved
  in tree at commit `30982cda740aa761272d847e476d9a77a1ee9726` (PR #717).
  The substrate's normative references are crypto and canonicalization
  RFCs only (RFC 4648, RFC 6234, RFC 6920, RFC 7493, RFC 8785), and its
  references to the OAuth core and the Mission Authority Server are
  informative. This holds at the bound commit.
- **Independent non-OAuth implementation feedback.** Outstanding. The
  substrate audit report records the caveat plainly: "all
  implementation evidence is OAuth-shaped, no non-OAuth binding evidence
  exists yet" (first recorded during the PR #727 review).

The omission is a decision under the family's internal readiness gate,
not an RFC-category judgment:
- The two-implementations bar is an Internet Standard advancement
  criterion (RFC 6410 Section 2), not a Proposed Standard entry gate
  (RFC 2026 Section 4.1.1).
- Publishing the substrate as Informational while the AAuth binding
  normatively depends on it and remains Standards Track would
  manufacture a downref (RFC 8067). The AAuth binding still cites the
  substrate normatively at the bound commit.

### Architecture

`draft-mcguinness-mission-architecture` (category `info`) is
informational context for the WG conversation, not a submission-set
member.

### MAS

`draft-mcguinness-mission-authority-server` (MAS) is classified as a
normative standalone-controller protocol binding over the OAuth Mission
data model: a peer deployment topology, not an independent substrate
model, since it normatively imports the OAuth Mission record and issuance
profile (at the bound commit its normative references still include the
core). Bindings, including MAS, are not submission-set members.

### Everything else

Companions, overlays, and the remaining bindings follow later, each per
its own maturity. `candidate-gate.json` (check (z) in
`scripts/generate-drafts-index.mjs`) is the promotion mechanism toward
`spec_maturity: candidate`.

## Maturity disclosure

Both submission-set members carry `spec_maturity: experimental` under
the family's candidate gate, and neither has an entry in
`candidate-gate.json` at the bound commit. Ledger coverage at the bound
commit (`conformance-manifest.json`):

| Member | Rows | Tested | Partial | Todo |
|---|---|---|---|---|
| core | 184 | 116 | 25 | 43 |
| resource-access | 149 | 110 | 27 | 12 |

The core's body carries 261 BCP 14 keywords.

The 2026-08-25 audit records are historical: they found 61 core rows
and 13 resource-access rows, all `todo`. They remain the method of
record for a candidate attestation:
- `notes/audits/2026-08-25-core-completeness-audit.md`;
- `notes/audits/2026-08-25-resource-access-completeness-audit.md`.

A candidate attestation needs a fresh audit against the gate's criteria,
not these counts.

This proposal leads with the WG conversation regardless: the candidate
gate is an internal completeness bar the family holds itself to, not a
submission prerequisite the IETF imposes.
