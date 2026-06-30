---
title: "Mission Lifecycle Signals for OAuth 2.0"
abbrev: "Mission Signals"
category: std

docname: draft-mcguinness-oauth-mission-signals-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
keyword:
 - oauth
 - mission
 - agent
 - authorization
 - shared signals
 - caep
 - revocation
venue:
  github: "mcguinness/draft-mcguinness-oauth-mission"
  latest: "https://mcguinness.github.io/draft-mcguinness-oauth-mission/draft-mcguinness-oauth-mission-signals.html"

author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com

normative:
  RFC3339:
  RFC7515:
  RFC8414:
  RFC8417:
  RFC8935:
  RFC8936:
  RFC9325:
  I-D.draft-mcguinness-oauth-mission:
    title: "Mission-Bound Authorization for OAuth 2.0"
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-oauth-mission-latest
  I-D.draft-mcguinness-oauth-mission-status:
    title: "Mission Status and Lifecycle for OAuth 2.0"
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-oauth-mission-status-latest

informative:
  RFC9700:
  I-D.draft-mcguinness-oauth-mission-expansion:
    title: "Mission Expansion for OAuth 2.0"
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-oauth-mission-expansion-latest
  I-D.draft-mcguinness-oauth-mission-child-delegation:
    title: "Child Mission Delegation for OAuth 2.0"
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-oauth-mission-child-delegation-latest
  OIDC-SSF:
    title: "OpenID Shared Signals Framework Specification 1.0"
    author:
      org: "OpenID Foundation"
    date: 2025
    target: "https://openid.net/specs/openid-sharedsignals-framework-1_0.html"
  OIDC-CAEP:
    title: "OpenID Continuous Access Evaluation Profile 1.0"
    author:
      org: "OpenID Foundation"
    date: 2025
    target: "https://openid.net/specs/openid-caep-1_0.html"

--- abstract

The Mission Status and Lifecycle profile names event-driven propagation
(Mission state changes reaching consumers over a Shared Signals or
equivalent channel) as one way to bound revocation latency, but leaves
the channel itself unspecified. This document
specifies it: a profile
of the OpenID Shared Signals Framework in which a Mission Issuer emits
a Mission lifecycle-change Security Event Token when it commits a state
transition, delivered push or poll, so a consumer learns of a
revocation, expiry, or other transition without polling. It is
OPTIONAL and builds on Mission-Bound Authorization for OAuth 2.0, the
issuance profile; a deployment that does not adopt it is unaffected.

--- middle

# Introduction

Mission-Bound Authorization for OAuth 2.0
{{I-D.draft-mcguinness-oauth-mission}} (the "issuance profile") gates
derivation on Mission state and bounds outstanding self-contained
tokens by their lifetime. The Mission Status and Lifecycle profile
{{I-D.draft-mcguinness-oauth-mission-status}} adds surfaces for
observing and changing state, and points to event-driven propagation
for deployments that need Mission state changes to reach consumers
promptly, without each consumer polling. It does not define the
channel.

This document defines the channel. When a Mission Issuer commits a
Mission lifecycle transition (a revocation, expiry, suspension,
completion, or the approval event that activates a Mission), it emits
a **Mission lifecycle-change Security Event Token** ({{lifecycle-event}})
over a profile of the OpenID Shared Signals Framework {{OIDC-SSF}}: pushed
to a consumer's receiver {{RFC8935}} or made available for the consumer
to poll {{RFC8936}}, as a Security Event Token (SET) {{RFC8417}}. A
consumer that receives a non-`active` transition stops honoring the
Mission ({{consumer-behavior}}). A deployment offers this channel by
publishing the event stream ({{event-stream}}); consumers discover it
from `mission_event_stream_endpoint` ({{as-metadata}}).

This document is OPTIONAL. It defines no new Mission semantics: the
Mission, its lifecycle states, and the `mission` claim are defined in
{{I-D.draft-mcguinness-oauth-mission}}, and the lifecycle states this
event reports are those of
{{I-D.draft-mcguinness-oauth-mission-status}}. A deployment that does
not stand up an event stream uses the polling surfaces of the Status
profile instead and is unaffected by this document.

# Conventions and Terminology {#conventions-and-terminology}

{::boilerplate bcp14-tagged}

This document uses the terms defined in the issuance profile
{{I-D.draft-mcguinness-oauth-mission}} and the Status profile
{{I-D.draft-mcguinness-oauth-mission-status}}, in particular Mission,
Mission Issuer (Authorization Server, the Mission `origin`), `mission_id`,
and the Mission lifecycle states. It additionally uses **Security Event
Token (SET)** {{RFC8417}} and the **Shared Signals Framework (SSF)**
{{OIDC-SSF}} transmitter, receiver, and stream terminology.

A **consumer** here is an SSF receiver that relies on Mission state --
typically a Resource Server, or an Authorization Server acting on a
Mission it did not issue.

All JSON shown in this document is non-normative and illustrative; the
member definitions in the surrounding text are authoritative. JWT and
SET examples are shown as decoded JSON; on the wire the JWS Compact
Serialization {{RFC7515}} applies.

# Mission Lifecycle Event Stream {#event-stream}

This section is OPTIONAL. A Mission Issuer that does not emit lifecycle
events, and a consumer that does not receive them, are unaffected; they
rely on token lifetime and the polling surfaces of
{{I-D.draft-mcguinness-oauth-mission-status}}.

A Mission Issuer that emits lifecycle events publishes a Shared Signals
Framework {{OIDC-SSF}} stream and advertises it in Authorization Server
metadata ({{as-metadata}}) as `mission_event_stream_endpoint`. The
endpoint and its configuration follow {{OIDC-SSF}}; this document
profiles only the event carried, its protection, and the consumer's
duty on receipt. The stream MUST be served over TLS 1.2 or later (TLS
1.3 RECOMMENDED), following the recommendations of {{RFC9325}}.

Delivery uses the Shared Signals Framework delivery methods, advertised
in the SSF stream configuration's `delivery_methods_supported`
{{OIDC-SSF}}:

- push-based delivery, SET delivery method `urn:ietf:rfc:8935`
  {{RFC8935}}: the Mission Issuer pushes SETs {{RFC8417}} to a
  consumer's registered receiver endpoint.
- poll-based delivery, SET delivery method `urn:ietf:rfc:8936`
  {{RFC8936}}: the Mission Issuer makes SETs available for the consumer
  to poll.

A Mission Issuer that emits events MUST support at least one method,
and a consumer discovers the supported methods from the SSF stream
configuration rather than from a separate Authorization Server metadata
member. The consumer's stream configuration declares the method it
uses; the Mission Issuer MUST respect it and MUST NOT silently fall
back to a less-timely method.

# The `mission.lifecycle-change` Event {#lifecycle-event}

A Mission Issuer emits a `mission.lifecycle-change` event, carried in
the Security Event Token shape of the Shared Signals Framework
{{OIDC-SSF}} and informed by the Continuous Access Evaluation Profile
{{OIDC-CAEP}}, when it commits any Mission lifecycle transition or the
approval event that activates a Mission. The event type URI, defined in
this document and described in {{iana}}, is:

`https://schemas.karlmcguinness.com/secevent/mission/lifecycle-change`

This URI is the registered event-type identifier; `mission.lifecycle-change`
is the short name this document uses for it in prose.

The event is carried as the event-type-keyed value of the `events`
claim of a SET {{RFC8417}}, alongside the SET's own `iss`, `aud`,
`iat`, `exp`, and `jti`. Its claims are:

- `mission_id` (string, required): the canonical `mission_id`
  ({{I-D.draft-mcguinness-oauth-mission}}).
- `mission_origin` (string, required): the Mission Issuer (`origin`)
  issuer URL.
- `state` (string, required): the new lifecycle state. The value space
  is the Mission lifecycle state space defined by the issuance profile
  {{I-D.draft-mcguinness-oauth-mission}} (`active`, `revoked`,
  `expired`), as extended by whichever lifecycle profiles a deployment
  also runs: `suspended` and `completed`
  ({{I-D.draft-mcguinness-oauth-mission-status}}), `superseded`
  ({{I-D.draft-mcguinness-oauth-mission-expansion}}), and `cascaded`
  ({{I-D.draft-mcguinness-oauth-mission-child-delegation}}). Following
  the issuance profile's forward-compatibility rule, an event consumer
  MUST treat every value other than `active` as non-deriving, including
  a value it does not recognize. A Mission Issuer that runs a profile
  defining an additional state emits that state here on the
  corresponding transition (for example, `superseded` when a
  predecessor is superseded by an expansion successor).
- `prior_state` (string, conditional): the state immediately before the
  transition, drawn from the same value space. REQUIRED on a transition
  emission; absent only on the approval-event emission, where there is
  no prior state. A supersede transition emits `prior_state` of `active`
  and `state` of `superseded`.
- `version` (integer, required): a strictly monotonic per-Mission
  counter the Mission Issuer maintains and increments on each committed
  lifecycle transition (the approval-event emission is version 1),
  letting a consumer order events and detect gaps. This profile defines
  the counter here; it is not surfaced by the issuance or status
  profiles.
- `committed_at` (string, required): an RFC 3339 {{RFC3339}} date-time
  at which the Mission Issuer committed the transition.
- `tenant` (string, optional): the Mission's deployment tenant. This
  profile defines no tenant model and does not use it; it is present so
  the event type is shared, unchanged, with multi-tenant and
  cross-substrate deployments that do.
- `reason` (string, optional): a human-readable reason, for audit.

Example SET (decoded), for a revocation:

~~~ json
{
  "iss": "https://as.example.com",
  "aud": "https://erp.example.com",
  "iat": 1797843200,
  "exp": 1797843500,
  "jti": "set_9Kp2vN7sR1tY8mZ3qX5b",
  "events": {
    "https://schemas.karlmcguinness.com/secevent/mission/lifecycle-change": {
      "mission_id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
      "mission_origin": "https://as.example.com",
      "prior_state": "active",
      "state": "revoked",
      "version": 2,
      "committed_at": "2026-11-02T09:06:40Z",
      "reason": "Quarterly reconcile completed early"
    }
  }
}
~~~

# SET Protection {#set-protection}

Each SET {{RFC8417}} is a JWS Compact Serialization {{RFC7515}} signed
with a Mission Issuer key resolvable in the issuer's `jwks_uri`, with a
`typ` of `secevent+jwt` and a `kid` identifying the signing key. A
consumer MUST verify the signature against the Mission Issuer's
published keys and MUST refuse a SET whose `iss` does not match the
Mission Issuer it registered with. Because this profile is
single-issuer, the SET `iss` equals the event's `mission_origin`; a
consumer MAY treat a mismatch as a verification failure. (`mission_origin`
is carried in the event for cross-substrate deployments where the two
can differ.)

The SET `aud` MUST be the receiving consumer's registered audience
identifier; a consumer MUST refuse a SET whose `aud` is not its own.
Each SET carries an `exp`; a consumer MUST reject an expired SET and
MUST treat `jti` as a one-time identifier for at least the SET's
validity window (`iat` to `exp`), rejecting a replayed `jti` within it.

# Consumer Behavior on Receipt {#consumer-behavior}

On receiving and verifying ({{set-protection}}) a
`mission.lifecycle-change` event, a consumer MUST:

- Stop honoring the affected Mission for any new consequential use when
  `state` is anything other than `active`: refuse to act on, and refuse
  to derive further authority from, tokens bound to that Mission
  ({{I-D.draft-mcguinness-oauth-mission}}), to the extent of the
  consumer's enforcement role.
- Resume honoring the Mission on a verified event whose `state` is
  `active` and whose `version` is greater than the last applied for
  that `mission_id`, subject to the same gating the issuance profile
  applies. This covers a reversible transition (for example a
  `suspended` Mission that is later resumed to `active`).
- Apply the transition idempotently: a repeated or out-of-order event
  carrying a `version` not greater than the last applied for that
  `mission_id` MUST NOT regress the consumer's view of the state.
- Acknowledge the event per the SSF delivery method in use.

A consumer MUST NOT treat the event as authority to change Mission
state at the Mission Issuer; the Mission Issuer is authoritative
({{I-D.draft-mcguinness-oauth-mission-status}}). A consumer that
believes the reported state is wrong re-checks through Mission Status
rather than inventing a state.

A consumer SHOULD treat a missed or delayed event as a freshness
failure: if it has not received expected events within the Mission
Issuer's advertised `mission_max_stale_seconds`
({{I-D.draft-mcguinness-oauth-mission-status}}), it SHOULD fall back to
polling Mission Status rather than continue on possibly stale state.

# Relationship to Revocation Propagation {#event-driven}

This document is the event-driven mechanism the Status profile's
revocation-propagation guidance points to
({{I-D.draft-mcguinness-oauth-mission-status}}): a Mission Issuer that
offers it emits `mission.lifecycle-change` events ({{lifecycle-event}})
over the stream ({{event-stream}}), and consumers subscribe and apply
{{consumer-behavior}}. A deployment that offers event-driven
propagation MUST advertise `mission_event_stream_endpoint`
({{as-metadata}}) and support at least one SSF delivery method
({{event-stream}}), so consumers discover it.

This document neither requires nor presumes event-driven propagation;
a Mission Issuer MAY emit lifecycle events for audit or operational
purposes independent of any consumer's enforcement posture.

# Worked Example {#example}

A partner ERP (`erp.partner.example.com`) consumes Mission lifecycle
signals so it can stop honoring a Mission promptly rather than wait out
token lifetimes. `alice` cancels her Q3 reconciliation Mission. The
Mission Issuer commits the `revoked` transition and pushes a SET to the
consumer's receiver ({{RFC8935}}). Decoded SET:

~~~ json
{
  "iss": "https://as.example.com",
  "aud": "https://erp.partner.example.com",
  "iat": 1797843600,
  "jti": "set_5kQ8mP2vR9nT",
  "events": {
    "https://schemas.karlmcguinness.com/secevent/mission/lifecycle-change": {
      "mission_id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
      "mission_origin": "https://as.example.com",
      "state": "revoked",
      "prior_state": "active",
      "version": 7,
      "committed_at": "2026-11-02T09:00:00Z",
      "reason": "user_cancelled"
    }
  }
}
~~~

The consumer verifies the SET signature, `iss`, `aud`, and `jti`, sees
`version` 7 is newer than any state it holds, and records the Mission as
`revoked`. Because `revoked` is non-`active`, the consumer stops relying
on the Mission: the next attempt to use a token bound to
`msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-` is refused, seconds after the
cancellation, well inside the token's remaining lifetime. Had a stale
`active` event for an earlier `version` arrived afterward, the
`version` counter would cause the consumer to ignore it rather than
revive the Mission.

# Authorization Server Metadata {#as-metadata}

A Mission Issuer that emits lifecycle events advertises the following in
its Authorization Server metadata {{RFC8414}}, in addition to the
issuance-profile and Status-profile members it already publishes:

`mission_event_stream_endpoint`:
: OPTIONAL. A string containing a URL. The Shared Signals Framework
  {{OIDC-SSF}} stream endpoint for Mission lifecycle events
  ({{event-stream}}). Present when the Mission Issuer emits events. The
  supported delivery methods are discovered from the SSF stream
  configuration's `delivery_methods_supported`, not from a separate
  metadata member.

# Security Considerations {#security-considerations}

The security considerations of the issuance profile
{{I-D.draft-mcguinness-oauth-mission}} and the Status profile
{{I-D.draft-mcguinness-oauth-mission-status}} apply. This section
covers threats specific to event propagation.

## Forged or Replayed Events

A forged event could suppress a Mission (a spurious `revoked`) or, more
dangerously, mask a revocation (a spurious `active`). SET signing
({{set-protection}}) binds each event to the Mission Issuer; a consumer
MUST verify the signature, the `iss`, and its own `aud`, and MUST
reject a replayed `jti`. The `version` ordering rule
({{consumer-behavior}}) prevents an old `active` event from overriding
a newer `revoked` one.

## Missed Events Are Not Fail-Open

Event delivery is best-effort; a consumer that treats "no event" as
"still active" indefinitely defeats the purpose. A consumer MUST bound
its reliance on event freshness and fall back to polling Mission Status
({{consumer-behavior}}) so a dropped revocation event does not leave a
Mission honored past the deployment's advertised staleness bound.

## General OAuth Security

This document inherits OAuth 2.0 Best Current Practice {{RFC9700}} for
the OAuth surfaces it composes with; implementers MUST follow current
OAuth security guidance.

# Privacy Considerations {#privacy-considerations}

A `mission.lifecycle-change` event discloses a Mission's identifier,
state transitions, and timing to its receivers. A Mission Issuer MUST
deliver events only to consumers authorized for the Mission and MUST
scope each SET to a single consumer audience ({{set-protection}}), so a
consumer never learns of Missions it is not party to. Event streams and
their delivery logs record `mission_id` and consumer identity over
time; deployments MUST treat them as Mission information-disclosure
surfaces with the privacy posture of
{{I-D.draft-mcguinness-oauth-mission-status}}.

The OPTIONAL `reason` ({{lifecycle-event}}) is useful operational
context, but the reason for a transition can be more sensitive than the
fact of it. Because each SET is audience-scoped to a single authorized
consumer ({{set-protection}}), `reason` is disclosed only to a party
already authorized for the Mission, not broadcast. Even so, a Mission
Issuer SHOULD include in `reason` only what that consumer needs, keep
sensitive specifics in its own audit log rather than in the event, and
MAY omit `reason` entirely when even a minimal reason would disclose
more than the consumer requires.

# Conformance {#conformance}

This document is OPTIONAL. An implementation that claims it:

- as a **Mission Issuer**, emits a signed `mission.lifecycle-change`
  SET ({{lifecycle-event}}, {{set-protection}}) on every committed
  Mission lifecycle transition, supports at least one SSF delivery
  method ({{event-stream}}), and advertises
  `mission_event_stream_endpoint` ({{as-metadata}});
- as a **consumer**, verifies and applies received events per
  {{set-protection}} and {{consumer-behavior}}.

An implementation that supports neither role is still a conforming
issuance profile {{I-D.draft-mcguinness-oauth-mission}}.

# IANA Considerations {#iana}

## Security Event Token Type

IANA is not requested to create a registry. This document defines the
following Security Event Token (SET) {{RFC8417}} event type URI under
the author-controlled `schemas.karlmcguinness.com/secevent` namespace:

- `https://schemas.karlmcguinness.com/secevent/mission/lifecycle-change`:
  emitted on any Mission lifecycle transition or the approval-event
  emission from a Mission Issuer. Required claims: `mission_id`,
  `mission_origin`, `state`, `version`, `committed_at`. Conditional
  claim: `prior_state` (required on transition emissions, absent on the
  approval-event emission). Optional claims: `tenant`, `reason`. See
  {{lifecycle-event}} for the schema.

This event type uses the OpenID Shared Signals Framework {{OIDC-SSF}}
SET shape. The same event type URI is also referenced by the
substrate-neutral Mission Authority Server work, which makes `tenant` a
required claim; this profile makes `tenant` OPTIONAL because the OAuth
profile has no tenant model. Because the URI is author-controlled and
has no IANA registry or change controller to arbitrate a shared
definition, this profile does not rely on any cross-specification
guarantee about its required-claim set. It relies only on consumer
robustness, which is sufficient on its own: a consumer MUST ignore
members it does not understand and MUST NOT reject an event solely for
a missing OPTIONAL member (notably `tenant`). A consumer built to this
profile therefore interoperates with an emitter of either specification
regardless of how the two reconcile, and a deployment that needs a
binding shared definition should pursue a registered event type rather
than depend on the author-controlled URI.

## OAuth Authorization Server Metadata Registration

IANA is requested to register the following in the "OAuth Authorization
Server Metadata" registry {{RFC8414}}. For each: Change Controller
IETF; Reference this document, {{as-metadata}}.

- `mission_event_stream_endpoint`

--- back

# Acknowledgments
{:numbered="false"}

The author thanks the implementers and reviewers of the Mission-Bound
Authorization work, and the OpenID Shared Signals and CAEP communities,
for the foundations this profile builds on.
