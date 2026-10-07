---
title: "Mission Intent Submission Evidence for OAuth 2.0"
abbrev: "OAuth Mission Submission Evidence"
category: std

docname: draft-mcguinness-oauth-mission-submission-evidence-latest
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
 - submission
 - evidence
venue:
  github: "mcguinness/mission-bound-authorization"
  latest: "https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-submission-evidence.html"

author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com

normative:
  RFC6749:
  RFC9126:
  I-D.draft-mcguinness-oauth-mission:
    title: "Mission-Bound Authorization for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026

informative:
  I-D.draft-mcguinness-mission-shaping:
    title: "Mission Intent Shaping"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-shaping.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-oauth-mission-child-delegation:
    title: "Mission Child Delegation for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-child-delegation.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-oauth-mission-approval-revision:
    title: "Mission Approval Revision for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-approval-revision.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  RFC7800:
  I-D.draft-mcguinness-oauth-mission-expansion:
    title: "Mission Expansion for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-expansion.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026

--- abstract

Mission-Bound Authorization for OAuth 2.0 lets a client present
Intent Submission Evidence alongside a submitted Mission Intent. The
authorization server refuses any entry it cannot verify and treats a
verified entry as policy input, never authority. This document
defines the framework that evidence types and authorization servers
share: the entry convention an evidence type follows, resolution of
required evidence before derivation, binding of evidence to one exact
Mission Intent and to the presenter the containing exchange
establishes, a bound on verification cost, where the error is
returned, and the place of presented evidence in a Mission-creation
idempotency fingerprint. It defines no evidence types.

--- middle

# Introduction {#introduction}

Mission-Bound Authorization for OAuth 2.0
{{I-D.draft-mcguinness-oauth-mission}} (the OAuth binding) carries
Intent Submission Evidence in the Submission envelope, refuses an
entry it cannot verify, and treats a verified entry as policy input.
This document adds the rest of the evidence framework: how an
evidence type is specified, when evidence is required, what verified
evidence binds, how much verification a submission can demand, and
where the error is returned.

The framework uses these seams of the OAuth binding and changes none
of its rules:

- the Submission envelope's optional `evidence` member, with its size
  and count bounds ({{I-D.draft-mcguinness-oauth-mission}}, Section
  "Submission via PAR");
- the "reject, do not ignore" and "policy input, not authority" rules
  ({{I-D.draft-mcguinness-oauth-mission}}, Section "Intent Submission
  Evidence");
- the `invalid_mission_intent_evidence` error code, which the OAuth
  binding registers ({{I-D.draft-mcguinness-oauth-mission}}, Section
  "OAuth Extensions Error Registration"); and
- the Mission Record's `submission_evidence` member, which records
  the verified facts ({{I-D.draft-mcguinness-oauth-mission}}, Section
  "Mission Record").

This document defines no evidence types. A companion profile defines
each type under the convention of {{entry-convention}}.

# Conventions and Terminology {#conventions}

{::boilerplate bcp14-tagged}

This document uses the terms Mission, Mission Intent, Submission
envelope, Intent Submission Evidence, Mission Record, Mission Issuer
(the "AS"), approval event, Authority Set, and `intent_hash` from
{{I-D.draft-mcguinness-oauth-mission}}.

Evidence type:
: The collision-resistant name an entry's `type` member carries. The
  specification that owns the name is the evidence type's
  specification ({{entry-convention}}).

# Evidence Entries {#entry-convention}

Each entry is a JSON object with a REQUIRED `type` member: a string
naming the evidence type as a collision-resistant name, under the
same guidance as anchor `typ` values
({{I-D.draft-mcguinness-oauth-mission}}, Section "Integrity
Anchors"). The specification that owns a `type` defines the entry's
remaining members as a closed schema, the artifact format, the
verification procedure, and the verified output facts that
verification yields.

This document defines no generic member other than `type`, and no
evidence types; an AS that supports no evidence type refuses every
presented entry under the OAuth binding's dispatch rule
({{I-D.draft-mcguinness-oauth-mission}}, Section "Intent Submission
Evidence").

# Processing Rules {#processing}

These rules apply alongside the OAuth binding's "reject, do not
ignore" and "policy input, not authority" rules
({{I-D.draft-mcguinness-oauth-mission}}, Section "Intent Submission
Evidence"), on every surface that carries the Submission envelope:
PAR, and each carriage a companion profile defines. They apply to
every submission, including one that carries no `evidence` member.

## Required Evidence Is Resolved Before Derivation {#required-evidence}

The AS determines the evidence types its applicable profile, client,
resource, or admission policy requires before derivation. When a
required type is absent from the submission, the AS MUST refuse the
submission with the `invalid_mission_intent_evidence` error code.
This is the submission-plane form of the downgrade rules of the OAuth
binding ({{I-D.draft-mcguinness-oauth-mission}}, Section "Authority
Proposal").

## Evidence Binds One Exact Intent {#intent-binding}

The owning evidence type's specification defines how intent-bound
evidence identifies its intended AS and how that binding is verified.
The AS MUST refuse an intent-bound entry that does not verifiably
identify this AS, with `invalid_mission_intent_evidence`. This includes
an absent binding or a binding to a different AS.

Before derivation, the AS verifies that intent-bound evidence is
bound to this AS, names exactly the provisional `intent_hash`
computed from the submitted Intent, and agrees with the presenter
established by the containing exchange ({{presenter-binding}}).

Evidence bound to an `intent_hash` applies only to that exact
semantic Intent. When a shaping
({{I-D.draft-mcguinness-mission-shaping}}) or approval revision
({{I-D.draft-mcguinness-oauth-mission-approval-revision}}) changes
`intent_hash`, the AS MUST NOT treat evidence bound to the
predecessor Intent as evidence for the revised Intent, unless the
evidence type's specification explicitly authorizes that
transformation and defines how its lineage is verified.

## The Exchange Establishes the Presenter {#presenter-binding}

The AS establishes the presenter through the containing exchange:
client authentication and, where present, proof of possession. An
entry that names an authorized presenter (a `client_id`, a `cnf` key
binding {{RFC7800}}) MUST match the established presenter, and a
mismatch fails
that entry's verification. Evidence is never an alternative
client-authentication mechanism and never selects the presenter.

## Bounded Verification {#verification-bounds}

Beyond the size and count bounds of the OAuth binding
({{I-D.draft-mcguinness-oauth-mission}}, Section "Submission via
PAR"), the AS MUST bound the verification cost a submission can
impose (for example, the number of signature verifications it
performs), refusing a submission that exceeds the bound with the
`invalid_request` error code.

# Error Responses {#error-responses}

The AS returns the `invalid_mission_intent_evidence` error code where
the containing exchange returns its errors: in the PAR error response
({{Section 2.3 of RFC9126}}) for a PAR submission, and in the token
error response ({{Section 5.2 of RFC6749}}) for a token-endpoint
carriage that a companion profile defines.

# Evidence on Idempotent Creation Surfaces {#creation-idempotency}

On a surface that carries a Mission-creation idempotency fingerprint
(the expansion and child-creation token exchanges,
{{I-D.draft-mcguinness-oauth-mission-expansion}},
{{I-D.draft-mcguinness-oauth-mission-child-delegation}}), presented
evidence is a member of that fingerprint, which the owning profile
lists.
Recovery of a completed operation on those surfaces returns the
recorded outcome without re-verifying the presented evidence, even
when an artifact's freshness or status has since lapsed. PAR-based
creation and surfaces that submit no Mission Intent carry no such
fingerprint and keep their own replay and idempotency mechanisms.

# Conformance {#conformance}

An AS conforming to this document implements the OAuth binding's
Intent Submission Evidence rules
({{I-D.draft-mcguinness-oauth-mission}}, Section "Intent Submission
Evidence") and MUST implement:

- required-evidence resolution ({{required-evidence}});
- Intent binding ({{intent-binding}});
- presenter agreement ({{presenter-binding}}); and
- the verification bound ({{verification-bounds}}).

It returns errors as {{error-responses}} describes and, on a surface
that carries a Mission-creation idempotency fingerprint, treats
presented evidence as {{creation-idempotency}} describes.

A specification that defines an evidence type follows the entry
convention ({{entry-convention}}). An AS that supports an evidence
type conforms to this document.

Verified evidence is not copied into the Authority Set, and the facts
the Mission Record retains are not carried on the `mission` claim
({{I-D.draft-mcguinness-oauth-mission}}, Section "Mission Record"). A
resource server does not need to understand this document.

# Security Considerations {#security-considerations}

The security considerations of the OAuth binding apply
({{I-D.draft-mcguinness-oauth-mission}}, Section "Security
Considerations").

## Evidence Is Not Authority {#sec-not-authority}

A verified entry informs admission and derivation policy. It never
enters the Authority Set and never stands in for the approval event
({{I-D.draft-mcguinness-oauth-mission}}, Section "Intent Submission
Evidence"). Evidence that passes verification can still steer a
policy decision, so that decision is only as strong as the
verification the evidence type's specification defines.

## Downgrade by Omission {#sec-downgrade}

Stripping a required entry from a submission is a downgrade attempt.
Resolving required types before derivation ({{required-evidence}})
turns the omission into a refusal rather than an admission on weaker
evidence.

## Reuse Across Revisions {#sec-reuse}

An admission or consent decision covers the Intent it was made for.
Carrying it to a revised Intent would apply it to a task it never
covered; {{intent-binding}} confines it to one `intent_hash`.

## Presenter Substitution {#sec-presenter}

An evidence artifact is not a credential. Because the containing
exchange establishes the presenter ({{presenter-binding}}), a stolen
artifact neither authenticates its holder nor lets a different
client present it as the named presenter.

## Verification Cost {#sec-verification-cost}

An entry can demand signature verification, status retrieval, or
other work. Without a bound, a small submission could impose a large
cost on the AS; {{verification-bounds}} refuses such a submission.

# Privacy Considerations {#privacy-considerations}

An evidence artifact can carry personal data, such as an originator
identity or a consent reference. The OAuth binding keeps it off the
front channel through PAR and governs access to the facts the Mission
Record retains ({{I-D.draft-mcguinness-oauth-mission}}, Section
"Mission Record and Evidence Access"). An evidence type's
specification controls that exposure through the verified output
facts it designates for recording.

# IANA Considerations {#iana}

This document has no IANA actions. The
`invalid_mission_intent_evidence` error code it uses is registered by
the OAuth binding ({{I-D.draft-mcguinness-oauth-mission}}, Section
"OAuth Extensions Error Registration").

--- back

# Document History {#document-history}

\[\[ To be removed from the final specification ]]

-00

- Clarified the boundary with the OAuth binding: the framework owns
  the pre-derivation checks on intent-bound evidence, including its
  AS, exact-Intent, and presenter binding. An intent-bound entry whose
  intended-AS binding is absent, invalid, or identifies another AS is
  refused with `invalid_mission_intent_evidence`; its evidence type
  defines how the binding is expressed and verified. The OAuth binding
  keeps its evidence dispatch and refusal rules and permits an AS that
  supports no evidence types.

- Initial version. Carries the Intent Submission Evidence framework of
  Mission-Bound Authorization for OAuth 2.0 with its wire names and
  rules unchanged: the entry convention, required-evidence resolution,
  binding to one exact Intent, presenter agreement, the verification
  bound, error placement, and the creation-fingerprint note. The OAuth
  binding keeps the `evidence` member and its bounds, the reject and
  policy-input rules, the `invalid_mission_intent_evidence`
  registration, and the `submission_evidence` record member.
