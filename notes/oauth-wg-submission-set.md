# OAuth WG Package: Initial Composition

This is the record of the initial OAuth working-group package, per the
ruling on issue #704 (2026-08-24). It is one of three distinct products
the ruling adopts, not the only publication surface the family maintains:

| Product | Composition |
|---|---|
| Initial WG conversation | The OAuth Mission core and, separately, the Mission Resource Access RAR profile |
| Normative dependency closure | Whatever each selected specification actually imports (computed below) |
| Implementation reader bundle | `notes/oauth-mission-baseline-bundle-preview.md`, a separate publication artifact |

The reader-bundle preview constrains nothing here: it is an implementation
guide assembled for a different audience and purpose, and this document
does not draw on it as precedent or restrict it in return.

## Package composition

The initial package is exactly two Internet-Drafts, presented separately:

- `draft-mcguinness-oauth-mission`, "Mission-Bound Authorization for OAuth
  2.0" (the OAuth Mission core, the issuance profile).
- `draft-mcguinness-oauth-mission-resource-access`, "Mission Resource
  Access Profile for OAuth 2.0" (the RAR profile: the
  `mission_resource_access` `authorization_details` type).

The profile's split out of the core executed first: issue #637, merged as
PR #718. The package therefore records a standardization unit that
exists in the tree, not one still pending relocation.

## Normative dependency closure

Computed from each draft's front matter `normative:` block at HEAD,
cross-checked against `DEPENDENCIES.md`'s generated external-normative-ids
block.

The core's normative references are 28 ratified RFCs plus ISO 4217, and
no Internet-Draft:

- OAuth wire protocol: RFC 6749, RFC 6750, RFC 7636, RFC 7662, RFC 8414,
  RFC 8693, RFC 8705, RFC 8707, RFC 9068, RFC 9101, RFC 9126, RFC 9207,
  RFC 9396, RFC 9449, RFC 9470, RFC 9700, RFC 9728.
- JOSE, hashing, and canonicalization: RFC 4648, RFC 6234, RFC 6920,
  RFC 7519, RFC 7800, RFC 8785.
- Data formats: RFC 3339, RFC 3986, RFC 5646, RFC 7493, RFC 8259.
- Currency codes: ISO 4217:2015.

The resource-access profile's normative references are 9 ratified RFCs,
ISO 4217, and one Internet-Draft: the core itself
(`I-D.draft-mcguinness-oauth-mission`). Every one of its 9 RFCs (RFC 3339,
RFC 3986, RFC 6750, RFC 8259, RFC 8693, RFC 8707, RFC 8785, RFC 9396,
RFC 9728) is already in the core's list above, so the profile's normative
closure adds nothing new outside the package.

`DEPENDENCIES.md`'s generated external-normative-ids block, which lists
every `I-D.`-prefixed normative reference cited anywhere in the family,
carries no entry for either `oauth-mission` or
`oauth-mission-resource-access`. That is the mechanical confirmation:
neither draft normatively cites a work-in-progress external
Internet-Draft.

The computed closure, stated once as the union: the package's normative
dependency closure is the 28 RFCs listed above plus ISO 4217:2015. Every
member of that closure is a ratified RFC or a finalized ISO standard. The
package's normative closure contains no work-in-progress external
dependencies.

## What the package omits, and why

### Substrate

`draft-mcguinness-mission-substrate` is the family's only
`spec_maturity: candidate` document, the sole document to earn the
candidate gate's attestation in the 2026-08-25 completeness audit
(`notes/audits/2026-08-25-substrate-completeness-audit.md`, PR #727). It
is a Standards-Track candidate in-repository, and it is omitted from this
initial package.

Two preconditions gate a separate substrate submission. The first,
removing the substrate's normative OAuth dependency (#708), is resolved
in tree at commit `30982cda740aa761272d847e476d9a77a1ee9726` (PR #717):
the substrate's normative references are now crypto and canonicalization
RFCs only (RFC 4648, RFC 6234, RFC 6920, RFC 7493, RFC 8785), and its
references to the OAuth core and the Mission Authority Server are
informative. The second, independent non-OAuth implementation feedback,
is outstanding: PR #727's audit records the caveat plainly, "all
implementation evidence is OAuth-shaped, no non-OAuth binding evidence
exists yet."

The omission is a decision under the family's internal readiness gate,
not an RFC-category judgment. The two-implementations bar is an Internet
Standard advancement criterion (RFC 6410 Section 2), not a Proposed
Standard entry gate (RFC 2026 Section 4.1.1). Publishing the substrate
Informational while an AAuth binding normatively depends on it and
remains Standards Track would manufacture a downref (RFC 8067).

### Architecture

`draft-mcguinness-mission-architecture` is informational context for the
WG conversation, not a package member.

### MAS

`draft-mcguinness-mission-authority-server` (MAS) is classified as a
normative standalone-controller protocol binding over the OAuth Mission
data model: a peer deployment topology, not an independent substrate
model, since it normatively imports the OAuth Mission record and issuance
profile. Bindings, including MAS, are not package members.

### Everything else

Companions, overlays, and the remaining bindings follow later, each per
its own maturity. `candidate-gate.json` (check (z) in
`scripts/generate-drafts-index.mjs`) is the promotion mechanism toward
`spec_maturity: candidate`; PR #727 is where the current per-document gap
lists live for every document the 2026-08-25 audit wave covered.

## Maturity disclosure

Both package members carry `spec_maturity: experimental` under the
family's candidate gate. PR #727's audit found the core failing
criterion 1 (61 conformance rows against approximately 322 BCP-14
keyword hits, with entire named Conformance sections rowless) and the
resource-access profile failing the same criterion (13 rows, all
`todo`, with the Subset Rule algebra and the Common Constraints registry
uninventoried).

The package leads the WG conversation regardless: the candidate gate is
an internal completeness bar the family holds itself to, not a
submission prerequisite the IETF imposes. The audit's gap lists are the
work queue toward candidate, tracked in PR #727, not a blocker to opening
the conversation this document records.
