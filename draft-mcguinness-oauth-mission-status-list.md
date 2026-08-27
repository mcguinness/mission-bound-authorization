---
title: "Mission Status List for OAuth 2.0"
abbrev: "OAuth Mission Status List"
category: std

docname: draft-mcguinness-oauth-mission-status-list-latest
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
 - authorization
 - status
 - status list
venue:
  github: "mcguinness/mission-bound-authorization"
  latest: "https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-status-list.html"

author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com

normative:
  I-D.draft-ietf-oauth-status-list:
  I-D.draft-mcguinness-oauth-mission:
    title: "Mission-Bound Authorization for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-oauth-mission-status:
    title: "Mission Status and Lifecycle for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-status.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026

informative:
  I-D.draft-mcguinness-mission-runtime:
    title: "Mission-Bound Runtime Enforcement"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-runtime.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026

--- abstract

The Mission Status and Lifecycle profile for OAuth 2.0 lets a
consumer holding a `mission_id` resolve current Mission state, one
Mission at a time, from a signed Mission Status Response or a token
introspection projection. This document defines a companion surface
for fleet scale: a Mission Issuer MAY additionally publish Mission
state as an OAuth Status List, a signed, compressed bit array in
which each participating Mission holds an index, fetched once per
freshness window and read locally per action. It is optional and
builds on the Mission Status and Lifecycle profile; a deployment
that does not adopt it is unaffected.

--- middle

# Introduction

This document is a satellite of the Mission Status and Lifecycle
profile {{I-D.draft-mcguinness-oauth-mission-status}} ("the Status
profile"), adding a fleet-scale reliance surface.

The Status profile lets a consumer resolve current Mission state
from the dedicated Mission Status operation or the token
introspection projection, one Mission at a time. A consumer that
relies on many Missions concurrently, such as a gateway fronting an
agent fleet, can instead read Mission state from a compact, signed
bit array published once and read locally per action. This document
defines that surface: a Mission Status List
({{I-D.draft-ietf-oauth-status-list}}) profile of a `status_list`
extension member the Status profile's response and introspection
surfaces already accommodate.

This document is optional. A Mission Issuer that does not publish a
Status List, and a consumer that does not read one, are unaffected;
they rely on the Status profile's per-Mission surfaces directly.

This document defines no new Mission semantics and changes no
meaning of any existing member: the Mission, its lifecycle states,
and the Mission Status Response are defined in
{{I-D.draft-mcguinness-oauth-mission-status}}.

# Status: An Optional Profile {#doc-status}

<!-- family-status: BEGIN (generated from family-manifest.json; exact-matched by scripts/check-family-manifest.mjs) -->
Role: companion. Spec maturity: experimental. Maintenance: active.
Implementation: not yet in the conformance ledger (conformance-manifest.json).
Adopt when: A consumer relies on many Missions concurrently and per-Mission status reads do not scale.
Requires: Mission-Bound Authorization for OAuth 2.0; Mission Status and Lifecycle for OAuth 2.0.
<!-- family-status: END -->

# Conventions and Terminology {#conventions-and-terminology}

{::boilerplate bcp14-tagged}

This document uses the terms defined in the issuance profile
{{I-D.draft-mcguinness-oauth-mission}} and the Status profile
{{I-D.draft-mcguinness-oauth-mission-status}}, in particular Mission,
Mission Issuer, `mission_id`, the Mission lifecycle states, the
Mission Status Response, and the token introspection projection.

All JSON shown in this document is non-normative and illustrative;
the member definitions in the surrounding text are authoritative.

# Mission Status List {#status-list}

This section is OPTIONAL.

One consumer often relies on many Missions at once: a gateway
fronting an agent fleet holds a Mission per unit of work, and
per-Mission status reads at that scale are a latency tax the Status
profile's caching rules cannot amortize. A Mission Issuer MAY
additionally publish Mission state as a Status List
({{I-D.draft-ietf-oauth-status-list}}): a signed, compressed bit
array in which each participating Mission holds an index, fetched
once per freshness window and read locally per action.

The arithmetic is the point. A fleet of 100,000 participating
Missions at two bits per entry is 25,000 bytes before compression,
and a mostly-`active` population compresses far below that; a
consumer fetching that list once per 30-second window spends under a
kilobyte per second to hold fresh state for every Mission it relies
on, where per-Mission status reads would cost 100,000 requests per
window. Fleet scale makes state freshness cheaper per Mission, not
more expensive.

- **Reference.** A participating Mission's `status_list` member
  (`idx` and `uri`, the referenced-token shape of
  {{I-D.draft-ietf-oauth-status-list}}) rides the Mission Status
  Response and the introspection projection
  ({{I-D.draft-mcguinness-oauth-mission-status}}, Sections
  "Response" and "Token Introspection Mission Projection"), so a
  consumer learns its index from the authoritative surface it
  already reads.
- **Mapping.** VALID (0x00) reports `active`; SUSPENDED (0x02)
  reports `suspended`; INVALID (0x01) reports every terminal state.
  A consumer treats any other value as non-active, per the fail-safe
  rule. The list carries reliance bits only: which terminal state,
  the `successor`, and the state version stay on the Status
  profile's authoritative surfaces, and a consumer that observes a
  bit other than VALID re-establishes state there before any further
  reliance.
- **Freshness.** The Status List Token's `ttl` and `exp` are a
  published staleness bound: within them a VALID bit permits
  reliance exactly as a fresh Mission Status Response reporting
  `active` does, and an expired or unfetchable list is stale state,
  never permission ({{I-D.draft-mcguinness-mission-runtime}}). A
  committed lifecycle transition MUST be reflected in the next
  Status List Token published for its list, and where Signals runs,
  the event is the push complement to the list's pull floor.
- **Privacy.** Index assignment MUST NOT be derivable from or
  correlatable with the Mission Identifier, and the list conveys
  bits at opaque indices only, so publishing it preserves the Status
  profile's anti-oracle posture
  ({{I-D.draft-mcguinness-oauth-mission-status}}, Section
  "Anti-Oracle Property") while the fetch itself, covering every
  index at once, reveals no per-Mission interest.

# Security Considerations {#security-considerations}

The security considerations of the issuance profile
{{I-D.draft-mcguinness-oauth-mission}} and the Status profile
{{I-D.draft-mcguinness-oauth-mission-status}} apply in full. This
document introduces no attack surface beyond the Mapping and
Freshness rules of {{status-list}}, which are normative above: a
consumer that fails safe on a non-VALID bit and never relies past
the Status List Token's own `exp` inherits the Status profile's
revocation-propagation guarantees for the fleet-scale path.

# Privacy Considerations {#privacy-considerations}

The privacy considerations of the issuance profile
{{I-D.draft-mcguinness-oauth-mission}} and the Status profile
{{I-D.draft-mcguinness-oauth-mission-status}} apply in full. The
Status List's own privacy rule, that index assignment MUST NOT be
derivable from or correlatable with the Mission Identifier, is given
in {{status-list}}.

# IANA Considerations {#iana}

This document requests no IANA actions. It defines no new OAuth
Authorization Server metadata member, media type, or registry: the
`status_list` object it profiles reuses the Status profile's
existing Mission Status Response and introspection extension point
({{I-D.draft-mcguinness-oauth-mission-status}}).

# Conformance {#conformance}

An implementation claiming this capability MUST publish a Mission
Status List meeting the Reference, Mapping, Freshness, and Privacy
rules of {{status-list}}. An implementation that does not claim it
is unaffected and remains conformant to the Status profile.

# Acknowledgments
{:numbered="false"}

The author thanks the implementers and reviewers of the Mission-Bound
Authorization work for feedback that shaped this extension.
