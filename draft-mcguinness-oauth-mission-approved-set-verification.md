---
title: "Mission Approved-Set Verification for OAuth 2.0"
abbrev: "OAuth Mission Approved-Set Verification"
category: std

docname: draft-mcguinness-oauth-mission-approved-set-verification-latest
submissiontype: IETF
workgroup: Web Authorization Protocol
number:
date:
consensus: true
v: 3
keyword:
 - oauth
 - mission
 - agent
 - authority hash
 - verification
venue:
  github: "mcguinness/mission-bound-authorization"
  latest: "https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-approved-set-verification.html"

author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com

normative:
  RFC9396:
  I-D.draft-mcguinness-oauth-mission:
    title: "Mission-Bound Authorization for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026

informative:
  I-D.draft-mcguinness-oauth-mission-status:
    title: "Mission Status and Lifecycle for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-status.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-mission-substrate:
    title: "Mission Substrate Requirements"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-substrate.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026

--- abstract

Mission-Bound Authorization for OAuth 2.0 commits a Mission's approved
Authority Set as an integrity anchor, while a token derived under the
Mission can carry a narrowed subset of that set. A Resource Server
under that specification relies on the signed token as the
authorization server's assertion that the carried authority is a
subset of the approved set. This document defines Local Approved-Set
Verification, an optional capability under which a Resource Server or
policy decision point independently checks that a token's carried
authority is a subset of the Mission's complete committed Authority
Set. It defines authenticated retrieval of the complete set at two
tiers, the second adding an independently retained commitment;
fail-closed processing; and the disclosure gate on the retrieval
surface.

--- middle

# Introduction {#introduction}

Mission-Bound Authorization for OAuth 2.0
{{I-D.draft-mcguinness-oauth-mission}} (the OAuth binding) commits a
Mission's approved Authority Set as `authority_hash`, while a derived
token can carry a narrowed subset of that set. This document adds an
independent check that a token's carried authority is a subset of the
complete committed Authority Set, without relying on the authorization
server's subset assertion alone. It uses three seams of the OAuth
binding and changes none of its rules: `authority_hash`
({{I-D.draft-mcguinness-oauth-mission}}, Section "Integrity Anchors"),
the subset rule ({{I-D.draft-mcguinness-oauth-mission}}, Section
"Subset Rule"), and introspection's disclosure privilege
({{I-D.draft-mcguinness-oauth-mission}}, Section "Caller Authorization
and Minimization").

A Resource Server that does not implement this document enforces
under the OAuth binding alone
({{I-D.draft-mcguinness-oauth-mission}}, Section "Resource Server
Enforcement").

# Conventions and Terminology {#conventions}

{::boilerplate bcp14-tagged}

This document uses the terms Mission, Mission Record, Mission Issuer
(the authorization server, or "AS"), Approver, approval event,
Authority Set, Mission-bound token, and `authority_hash` from
{{I-D.draft-mcguinness-oauth-mission}}, and `authorization_details`
from {{RFC9396}}.

Verifying party:
: A Resource Server, policy decision point, or auditor that checks a
  token's carried authority against the Mission's complete approved
  Authority Set under this document.

# Local Approved-Set Verification {#verification}

This optional capability lets a verifying party check a token's carried
authority against the Mission's complete approved Authority Set,
rather than relying on the token signature and the AS's subset
assertion alone ({{I-D.draft-mcguinness-oauth-mission}}, Section
"Resource Server Enforcement"). A deployment adopts it when a
Resource Server, a policy decision point, or an auditor needs that
independent check.

For example, take the two-entry Authority Set of the OAuth binding's
test vectors ({{I-D.draft-mcguinness-oauth-mission}}, Section
"Integrity Anchor Test Vectors") and a single-audience token that
carries one narrowed entry: `journal-entries.write`, with the approved
`max_amount` of `500.00` USD tightened to `250.00`. A party outside
this profile verifies the token signature and `cnf`, checks `aud`,
and enforces the carried entry ({{I-D.draft-mcguinness-oauth-mission}},
Section "Resource Server Enforcement"), but cannot recompute
`authority_hash`: hashing the carried entry digests a one-entry array
the anchor never committed, and the tightened entry is a semantic
narrowing, not a byte-level member, of the approved set. Whether
`250.00` sits within the approved ceiling is the subset test
({{I-D.draft-mcguinness-oauth-mission}}, Section "Subset Rule"), which
needs the approved entry to compare against.

A party claiming this profile holds or retrieves the full Authority
Set, recomputes the commitment over it, matches the result against
the Mission's independently obtained `authority_hash`, and verifies
the carried entry as a subset of the approved `journal-entries.write`
entry.

An implementation claims this capability ({{conformance}}) through
authenticated complete-set retrieval ({{retrieval}}), at one of the
two tiers defined in {{retrieval}} and {{independent-pinning}}. A
typed selective-inclusion proof is a future composition point
({{selective-inclusion-proofs}}), not an alternative a conforming
implementation can claim.

## Authenticated Complete-Set Retrieval {#retrieval}

The verifying party retrieves the complete Authority Set, and the
`authority_hash` it expects to match, over a channel authenticated to
the Mission `issuer`, never from an unauthenticated or self-reported
source, and:

- MUST recompute the commitment over the retrieved set
  ({{I-D.draft-mcguinness-oauth-mission}}, Section "Integrity
  Anchors") and reject on mismatch, rather than trust the retrieval
  channel alone;
- MUST verify each carried `authorization_details` entry is a subset
  ({{I-D.draft-mcguinness-oauth-mission}}, Section "Subset Rule") of
  an entry in the retrieved set; and
- MUST fail closed: a retrieval failure, an unauthenticated response,
  a commitment mismatch, or a subset-test failure refuses the request
  under {{I-D.draft-mcguinness-oauth-mission}}, Section "Resource
  Server Enforcement", never falls back to trusting the token
  signature alone as if this profile were not claimed.

That much is **Tier 1**. Because the same `issuer` supplies both the
retrieved set and the `authority_hash` it is checked against, Tier 1
does not by itself establish that the retrieved set is the one the
Approver consented to: an issuer that returns a substituted set with
a digest recomputed to match passes it undetected. Tier 1 defends
against a projection bug, a stale or corrupted materialization, or a
compromised link between the record store and the retrieval endpoint,
not against an issuer dishonest at retrieval time or a signing key
compromised after approval ({{I-D.draft-mcguinness-oauth-mission}},
Section "Consent Binding").

## Independent Pinning {#independent-pinning}

**Tier 2** adds that defense: the verifying party additionally holds
an expected `authority_hash` obtained from a source independent of
the Tier 1 retrieval channel, never re-derived from the same call
being verified, and MUST reject unless the retrieved (and
recomputed-matching) value also equals that independently held one.
This independent pinning is what defends against post-approval
substitution ({{I-D.draft-mcguinness-oauth-mission}}, Section
"Consent Binding"). A deployment claiming Tier 2 declares:

- a **retention point**: which party retains the expected
  `authority_hash` and where, independent of the retrieval channel
  (for example, a Resource Server's own durable copy of the value
  disclosed to it under the `authority_hash` disclosure privilege
  ({{I-D.draft-mcguinness-oauth-mission}}, Section "Caller
  Authorization and Minimization") when it first received the
  Mission's tokens);
- a **trust basis**: how the retaining party authenticated that value
  when it captured it, which is the same issuer-authenticated channel
  any disclosure under the OAuth binding requires, never an
  unauthenticated or self-reported source; and
- a **retention rule**: how long the retained value is held and
  when, if ever, it is replaced, always from a source that meets the
  independence rule above.

A conforming implementation claims Tier 1 alone or Tier 1 with
Tier 2 and states which ({{conformance}}): a "verified" result means
different things under each.

## Retaining the Verified Set {#retention}

The approved Authority Set and its `authority_hash` are immutable for
the Mission's life ({{I-D.draft-mcguinness-oauth-mission}}, Section
"Mission Record"). Once retrieved and verified under the tier(s)
claimed, they can be retained for as long as the verifying party
relies on the Mission; this profile imposes no re-retrieval
requirement of its own. Re-retrieving the immutable set is not a
freshness signal for the Mission's current state or its effective
(containment-filtered) authority; a verifying party that needs those
observes them from a state surface, such as introspection
({{I-D.draft-mcguinness-oauth-mission}}, Section "Mission State via
Token Introspection").

## Retrieval Surface {#retrieval-surface}

This document does not mandate a specific retrieval endpoint or
transport; a deployment provisions a discoverable one. The retrieval
surface MUST refuse a caller that does not hold the disclosure
privilege ({{I-D.draft-mcguinness-oauth-mission}}, Section "Caller
Authorization and Minimization") for every audience the Mission has
issued to, because a complete-set response discloses every audience's
entries, while introspection minimizes its response to one audience
at a time.

Mission Status ({{I-D.draft-mcguinness-oauth-mission-status}}) is not
a compatible retrieval surface for this profile. Its authenticated,
`mission_id`-keyed lookup returns only the requesting audience's own
entries and, once containment has applied, the Mission's current
effective set rather than its complete immutable approved set.
Recomputing `authority_hash` over a Status response therefore fails
by construction for any multi-audience Mission, and fails after any
containment or discharge even for a single-audience one. A deployment
claiming this profile provisions a retrieval surface distinct from
Status, meeting the disclosure rule above.

# Conformance {#conformance}

A verifying party claiming this capability is a Mission-aware
Resource Server or policy decision point that independently
recomputes and subset-checks a Mission's complete approved Authority
Set. It MUST implement:

- authenticated complete-set retrieval with recomputation, the subset
  check, and fail-closed processing ({{retrieval}}); and
- where it claims Tier 2, independent pinning with its declared
  retention point, trust basis, and retention rule
  ({{independent-pinning}}).

It states which tier it supports, Tier 1 alone or Tier 1 with Tier 2.
A Mission Issuer that serves a claiming party provisions a retrieval
surface that meets {{retrieval-surface}}.

Local Approved-Set Verification is a capability of a Resource Server
or policy decision point, not of the Authorization Server, and has no
OAuth metadata signal: its activation, tier, and retrieval surface
are established out of band between the claiming party and the
Mission Issuer ({{retrieval-surface}}).

Conformance to the OAuth binding does not require this document, and
a Resource Server that does not claim this capability enforces
Mission-bound tokens under the OAuth binding alone.

In the terms of the Mission Substrate contract
({{I-D.draft-mcguinness-mission-substrate}}), this capability
exercises the Structured Authority and Monotonic Derivation claims of
the OAuth binding's Mapping Assessment
({{I-D.draft-mcguinness-oauth-mission}}, Section "OAuth Binding
Mapping Assessment"). Both claims are supplied always; this document
adds an independent check of them and creates no claim.

# Security Considerations {#security-considerations}

The security considerations of the OAuth binding apply
({{I-D.draft-mcguinness-oauth-mission}}, Section "Security
Considerations"). Its Consent Binding analysis states why a flat
commitment needs the complete set and how the protection verification
gives depends on when the issuer is compromised
({{I-D.draft-mcguinness-oauth-mission}}, Section "Consent Binding").
This section covers what verification adds.

## What a Verified Result Means {#sec-verified-result}

A Tier 1 result shows that the retrieved set recomputes to the
retrieved `authority_hash` and contains the carried authority. It
does not show that the retrieved set is the one the Approver
consented to, because the same issuer supplies both values
({{retrieval}}). A Tier 2 result adds agreement with an independently
retained value, which defends against post-approval substitution
({{independent-pinning}}). Neither tier defends against an issuer
malicious at approval time, which can approve and commit arbitrary
authority. A relying party reads a "verified" result under the tier
the verifying party states.

## No Fallback to the Token Signature {#sec-fail-closed}

An attacker who can block or corrupt retrieval gains from a verifying
party that falls back to the token signature alone. The fail-closed
rule ({{retrieval}}) turns each such failure into a refusal, so a
claiming party never reverts silently to the assurance it adopted
this profile to exceed.

## Independence of the Pinned Value {#sec-pinned-value}

Tier 2 is only as strong as the independence of its retained value. A
value re-derived from the call being verified, or captured from an
unauthenticated source, adds nothing to Tier 1. The declared retention
point, trust basis, and retention rule ({{independent-pinning}}) make
that independence reviewable, and a replacement from a source that
does not meet the independence rule forfeits the Tier 2 defense.

## Immutability Is Not Freshness {#sec-freshness}

A verified result says nothing about the Mission's current state or
its effective authority: a token whose authority verifies can belong
to a revoked Mission, or to one whose authority containment has
narrowed. A verifying party that needs current state observes it from
a state surface ({{retention}}).

# Privacy Considerations {#privacy-considerations}

A complete-set response discloses every audience's entries: the
resources, actions, and constraints the Mission authorizes at other
Resource Servers. Introspection minimizes its response to one
audience at a time ({{I-D.draft-mcguinness-oauth-mission}}, Section
"Caller Authorization and Minimization"). The retrieval surface
instead requires the disclosure privilege for every audience the
Mission has issued to ({{retrieval-surface}}). A deployment grants
that privilege only to a party whose role warrants the whole approved
set, and a verifying party that retains the set ({{retention}}) holds
that cross-audience disclosure for as long as it retains it.

# IANA Considerations {#iana}

This document has no IANA actions.

--- back

# Selective-Inclusion Proofs {#selective-inclusion-proofs}

Rather than retrieving the complete set, a future profile could
define a proof type under which the verifying party holds, per
carried entry, a proof that the entry's unnarrowed approved parent
entry is included in the Mission's committed Authority Set. The
verifying party then applies the type-owned subset test
({{I-D.draft-mcguinness-oauth-mission}}, Section "Subset Rule") with
that disclosed parent entry as the approved entry and the carried,
possibly narrowed, entry as the candidate. The proof cannot be of the
carried entry itself, since a narrowed entry was never itself an
array member that `authority_hash` committed.

A concrete proof type would need to:

1. cover every carried entry, not only one;
2. authenticate its own proof root as the Mission's approval-time
   commitment, under a collision-resistant `typ` distinct from that
   of `authority_hash` ({{I-D.draft-mcguinness-oauth-mission}},
   Section "Integrity Anchors");
3. define the verifier's processing, so that a party lacking the
   proof type's software cannot misread it as a plain digest;
4. reject an unrecognized proof `typ` rather than skip verification;
   and
5. define no downgrade path back to bare digest equality.

The second property is the open problem. The flat `authority_hash`
digests a single array and authenticates nothing about a differently
structured proof root (a Merkle root or an accumulator, for example),
so a concrete proof type needs its own construction binding that root
to the Mission, such as the Mission Issuer signing or committing to
it alongside `authority_hash` at the approval event.

# Document History {#document-history}

\[\[ To be removed from the final specification ]]

-00

- Initial version. Carries Local Approved-Set Verification of
  Mission-Bound Authorization for OAuth 2.0 with its rules unchanged:
  authenticated complete-set retrieval at Tier 1 and Tier 2, the
  retrieval surface and its disclosure gate, the rule that Mission
  Status is not a compatible retrieval surface, the capability's
  conformance entry, and the selective-inclusion future-work note.
