---
title: "Mission-Bound Authorization Binding Profile"
abbrev: "Mission Binding Profile"
category: std

docname: draft-mcguinness-oauth-mission-binding-profile-latest
submissiontype: IETF
workgroup: Web Authorization Protocol
number:
date:
consensus: true
v: 3
keyword:
 - oauth
 - mission
 - profile
venue:
  github: "mcguinness/mission-bound-authorization"
  latest: "https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-binding-profile.html"

author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com

normative:
  RFC8414:
  RFC9728:
  MISSION-GRANTS:
    title: "OAuth 2.0 Mission Grants"
    target: https://github.com/mcguinness/mission-bound-authorization/blob/main/notes/mission-grants-sketch.md
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  MISSION-INTENT:
    title: "OAuth 2.0 Mission Intent"
    target: https://github.com/mcguinness/mission-bound-authorization/blob/main/notes/mission-intent-sketch.md
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  MISSION-APPROVAL-CEREMONY:
    title: "OAuth 2.0 Mission Approval Ceremony"
    target: https://github.com/mcguinness/mission-bound-authorization/blob/main/notes/mission-approval-ceremony-sketch.md
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  MISSION-COMMITMENTS:
    title: "OAuth 2.0 Mission Commitments"
    target: https://github.com/mcguinness/mission-bound-authorization/blob/main/notes/mission-commitments-sketch.md
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026

informative:
  I-D.draft-mcguinness-oauth-mission:
    title: "Mission-Bound Authorization for OAuth 2.0"
    target: https://datatracker.ietf.org/doc/draft-mcguinness-oauth-mission/
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-liu-mcguinness-oauth-bounded-work:
    title: "OAuth 2.0 Bounded Work Authorization"
    target: https://datatracker.ietf.org/doc/draft-liu-mcguinness-oauth-bounded-work/
    author:
      -
        ins: D. Liu
        name: Dapeng Liu
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026

--- abstract

OAuth 2.0 Mission Grants defines a minimal Mission: one approval of
authorization details, identified, bounded, gated, and ended through
standard OAuth surfaces. Independent layers add a description of the
work, an approval ceremony, and commitments, and each evolves on its
own. This document composes the base and those layers into
Mission-Bound Authorization, the full contract that a specification
building on Missions cites as one target. It names the documents a
conforming party implements, fixes the choices they leave to a
profile, defines no new protocol element, and maps each part of the
composed contract to the document that defines it.

--- middle

# Introduction {#introduction}

OAuth 2.0 Mission Grants {{MISSION-GRANTS}} is the smallest Mission:
the substrate for approved bounded work
{{I-D.draft-liu-mcguinness-oauth-bounded-work}} that others build on.
Layers extend it without changing it: OAuth 2.0 Mission Intent
{{MISSION-INTENT}} records what the work is, OAuth 2.0 Mission Approval
Ceremony {{MISSION-APPROVAL-CEREMONY}} governs who approves and how,
and OAuth 2.0 Mission Commitments {{MISSION-COMMITMENTS}} makes the
approval verifiable and citable. A different description of the work,
or a different approval model, can replace a layer without touching
the base.

A specification that needs all of this, such as one that relies on
the approved task, the accountable approver, and the authority
commitment together, needs one stable target rather than a list of
documents that evolve separately. This document is that target. It:

- names the documents a conforming party implements ({{composed}});
- fixes the choices those documents leave to a profile ({{choices}});
- states how a party shows conformance, with no new protocol element
  ({{conformance}}); and
- maps each part of the composed contract to the document and section
  that defines it, for specifications that cite it ({{map}}).

The composition is named after Mission-Bound Authorization for OAuth
2.0 {{I-D.draft-mcguinness-oauth-mission}}, whose contract it
re-expresses as a base and layers. The parts of that contract that no
layer defines yet are listed in {{not-composed}}.

## Conventions and Terminology {#terminology}

{::boilerplate bcp14-tagged}

This document uses the terms Mission, Mission request, Mission Record,
Approved Authority, and Mission-bound token from {{MISSION-GRANTS}}.

Composed document:
: A document this profile requires a conforming party to implement
  ({{composed}}).

# Composed Documents {#composed}

A conforming authorization server implements all of these:

| Document | Role |
|---|---|
| OAuth 2.0 Mission Grants {{MISSION-GRANTS}} | Base: the Mission, its record, issuance by code, refresh and Token Exchange, the subset rule, gating, lifecycle, the management endpoint, and resource server enforcement |
| OAuth 2.0 Mission Intent {{MISSION-INTENT}} | Layer: the Mission Intent, its ceiling on resources, lifetime and audiences, and its confirmation |
| OAuth 2.0 Mission Approval Ceremony {{MISSION-APPROVAL-CEREMONY}} | Layer: the Approver and Subject, approval authentication, authority sources, presentation, and the recorded approval |
| OAuth 2.0 Mission Commitments {{MISSION-COMMITMENTS}} | Layer: the commitment construction, the authority commitment, the entry commitment, and the approval event identifier |
{: title="Documents this profile composes"}

A conforming client and a conforming resource server implement the
roles each composed document gives them.

# Profile Choices {#choices}

Where a composed document leaves a choice, this profile fixes it:

- **Every Mission is Intent-bound.** A Mission request under this
  profile MUST carry `mission_intent` ({{MISSION-INTENT}}), and the
  authorization server MUST refuse one that does not with
  `invalid_request`.
- **Every Mission records the approval and its commitments.** The
  Mission Record carries the facts of Mission Intent (`intent`,
  `intent_hash`), of Mission Approval Ceremony (`approver`, `subject`,
  `authority_source`, `approver_authentication`), and of Mission
  Commitments (`authority_hash`, `approval_event_id`).
- **The presentation shows the Intent with the approval.** The
  Intent's `goal`, `task_bounds`, and `target_resources` are among the
  facts the Approval Ceremony presents, so a change to any of them
  before the decision requires the Approver's consent to the changed
  context.
- **The token response confirms both.** The response that redeems the
  authorization code carries `mission_intent_hash` and
  `mission_subject`, and a client confirms each as its document
  states.

This profile adds no other requirement. Each composed document's
error responses, security considerations, and privacy considerations
apply unchanged.

# Conformance and Discovery {#conformance}

An authorization server shows conformance by advertising the metadata
of every composed document {{RFC8414}}: `mission_grants_supported`,
`mission_intent_supported`, `mission_approval_ceremony_supported`, and
`mission_commitments_supported`, each `true`. A client relies on this
profile only at an authorization server that advertises all four. A
resource server declares Mission-governed operations with
`mission_grants_required` in its protected resource metadata
{{RFC9728}}, as the base defines.

This profile defines no metadata member, parameter, claim, or error
code of its own.

# Citation Map {#map}

A specification that builds on Mission-Bound Authorization cites this
profile, or the composed document and section the map names. The map
lists the parts of Mission-Bound Authorization for OAuth 2.0 that the
family's specifications cite most, with the number of named-section
citations each received.

| Contract part (citations) | Defined in |
|---|---|
| Resource Server Enforcement (16) | Grants, "Resource Server Enforcement" |
| Integrity Anchors (15) | Commitments, "The Commitment Construction" and "The Authority Commitment"; Intent, "The Intent Anchor" |
| Mission Approval (13) | Grants, "Approval and Creation"; Approval Ceremony |
| Mission Authority (13) | Grants, "Approval and Creation"; Intent, "The Intent Ceiling" |
| Mission Termination (13) | Grants, "Lifecycle" |
| Principals and Approval Basis (12) | Approval Ceremony, "Principals" and "The Recorded Approval" |
| Subset Rule (12) | Grants, "The Subset Rule" |
| Issuance Gating (12) | Grants, "Issuance Gating" |
| Mission Record (10) | Grants, "The Mission Record", with the facts each layer records |
| Submitting a Mission Intent (9) | Intent, "Requesting an Intent-Bound Mission" and "The Submission Envelope" |
| Revocation (8) | Grants, "Lifecycle" and "Management Endpoint" |
| Binding the Mission to the Grant (8) | Grants, "Mission Grant Lineage" |
| Caller Authorization and Minimization (8) | Each layer's "Disclosure" |
| Mission State via Token Introspection (7) | Grants, "The mission Claim" and "Lifecycle" |
| Intent Submission Evidence (7) | Intent, "The Submission Envelope" |
| Mission-Bound Token Issuance (6) | Grants, "Mission-Bound Tokens" |
| Mission Lifecycle (6) | Grants, "Lifecycle" |
| Commitment Mechanisms (5) | Commitments, "Other Commitments" |
| Authority Sources (5) | Approval Ceremony, "Authority Sources" |
| Consent Binding (5) | Approval Ceremony, "Presenting the Approval" and "Changes Before the Decision" |
| Mission Claim (3) | Grants, "The mission Claim" |
| Self-Exchange Down-Scoping (3) | Grants, "Token Exchange" |
| Extensibility (2) | Grants, "Extension Points"; Commitments, "Other Commitments" |
{: title="Where each cited part of the contract is defined"}

Several of these parts are re-expressed rather than copied, and their
details differ from Mission-Bound Authorization for OAuth 2.0; a
citing specification checks the composed section it cites.

# Parts Not Yet Composed {#not-composed}

No layer defines these parts of Mission-Bound Authorization for OAuth
2.0 yet, so this profile does not include them. A specification that
needs one cites that document for it until a layer defines it:

- **Standing consent and the approval basis**: activation under a
  template or policy, and `approval_basis`.
- **Derivation**: configured-mapping derivation, the authority
  proposal and `proposal_hash`, and declared transformation
  capabilities.
- **Delegation**: designation, delegated exchange, instance context,
  and delegation constraints.
- **Cross-domain**: claim reservation, issuer-only members, and
  introspected consumption.
- **Scope projection.**
- **Termination detail**: termination reasons beyond the base's
  states, such as supersession.
- **Error and challenge mapping** as one table, and conformance roles.

When a layer for one of these exists, a revision of this profile can
compose it.

# Security Considerations {#security}

This profile composes documents without relaxing any of them, so each
document's security considerations apply. Requiring all four documents
together means every Mission carries a verified description of the
work, an authenticated and recorded approval, and verifiable
commitments; a deployment that implements only some of them does not
conform and gets only the guarantees of the documents it implements.

# Privacy Considerations {#privacy}

Each composed document's privacy considerations apply. Composing them
records the Intent, the Approver, the Subject, and the commitments for
every Mission, so every record holds personal data and every
disclosure rule of the composed documents applies to it.

# IANA Considerations {#iana}

This document has no IANA actions.

--- back

# Document History {#document-history}
{:numbered="false"}

\[\[ To be removed from the final specification ]]

-00

- Initial version: Mission-Bound Authorization composed from OAuth 2.0
  Mission Grants and the Intent, Approval Ceremony, and Commitments
  layers, with profile choices and a citation map.
