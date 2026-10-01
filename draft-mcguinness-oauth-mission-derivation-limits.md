---
title: "Mission Derivation Limits for OAuth 2.0"
abbrev: "OAuth Mission Derivation Limits"
category: std

docname: draft-mcguinness-oauth-mission-derivation-limits-latest
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
 - issuance
 - derivation limit
venue:
  github: "mcguinness/mission-bound-authorization"
  latest: "https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-derivation-limits.html"

author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com

normative:
  RFC6749:
  RFC7662:
  RFC8693:
  I-D.draft-mcguinness-oauth-mission:
    title: "Mission-Bound Authorization for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026

informative:
  RFC8785:
  I-D.draft-mcguinness-oauth-mission-child-delegation:
    title: "Mission Child Delegation for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-child-delegation.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-oauth-mission-continuation:
    title: "Mission Continuation for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-continuation.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-oauth-mission-cross-domain:
    title: "Mission Cross-Domain Projection for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-cross-domain.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-oauth-mission-expansion:
    title: "Mission Expansion for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-expansion.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-oauth-mission-template:
    title: "Mission Template for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-template.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-mission-metering:
    title: "Mission Consumption Metering"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-metering.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026

--- abstract

Mission-Bound Authorization for OAuth 2.0 gates each token issuance
under a Mission on the Mission's lifecycle state, its approved
authority, and its expiry. This document defines Mission Derivation
Limits, a companion that bounds the number of derivations the Mission
Issuer performs under a Mission. A client can request a ceiling in the
Mission Intent. The authorization server establishes the effective
limit as the minimum of that request and its own policy, records it on
the Mission, renders it at approval, refuses any derivation that would
exceed it, and can report the remaining count through token
introspection. The limit is an issuer-side operational control, not a
bound on the authority a token carries or on how that token is used.

--- middle

# Introduction {#introduction}

Mission-Bound Authorization for OAuth 2.0
{{I-D.draft-mcguinness-oauth-mission}} (the OAuth binding) gates every
derivation under a Mission on its lifecycle state, its Authority Set,
and its expiry. It does not bound how many derivations the issuer
performs. This document adds that bound: a derivation limit on the
number of derivations the issuer AS performs under a Mission. The limit
is an issuer-side operational control. It bounds counted issuance
operations at the token endpoint, not the authority any derived token
carries or how often a token already issued is used. The refreshes of
an async delegation family are not counted ({{refresh-and-exchange}}).

The limit uses these extension seams of the OAuth binding and changes
none of its rules:

- a Mission Intent member, `requested_derivation_limit`, under the
  Mission Intent members extension point and its registry
  ({{I-D.draft-mcguinness-oauth-mission}}, Section "Extensibility");
- a Mission Record member, `derivation_limit`, under the open record
  ({{I-D.draft-mcguinness-oauth-mission}}, Section "Mission Record");
- an issuance gate at the token endpoint, refused with the
  `invalid_grant` error code and a value of the OAuth binding's
  `mission_error` diagnostic
  ({{I-D.draft-mcguinness-oauth-mission}}, Section "Issuance Gating");
- a companion-defined member of the introspection `mission` member,
  `derivations_remaining`, under member-scoped disclosure
  ({{I-D.draft-mcguinness-oauth-mission}}, Section "Caller
  Authorization and Minimization"); and
- rendering of the established limit at the approval event
  ({{I-D.draft-mcguinness-oauth-mission}}, Section "Mission
  Approval").

An AS that does not implement this document establishes no derivation
limit, and its closed-top-level validation refuses a submitted
`requested_derivation_limit` as an unknown member
({{I-D.draft-mcguinness-oauth-mission}}, Section "Submission via
PAR"). Bounding aggregate consumption (calls, spend, or activity over
the life of a Mission) is out of scope; the metering profile defines
it ({{I-D.draft-mcguinness-mission-metering}}).

# Conventions and Terminology {#conventions}

{::boilerplate bcp14-tagged}

This document uses the terms Mission, Mission Intent, Mission Record,
Mission Issuer (the "issuer AS" or the "AS"), Resource AS, Approver,
approval event, Authority Set, Mission-bound token, and derivation
from {{I-D.draft-mcguinness-oauth-mission}}.

Derivation limit:
: The AS-established effective ceiling on the number of derivations
  under one Mission, recorded as the Mission Record's
  `derivation_limit` ({{record-member}}).

Derivation count:
: The number of derivations the issuer AS has committed under a
  Mission ({{counting}}).

# The Derivation Limit {#derivation-limit}

A Mission's derivation limit bounds the number of derivations
({{counting}}) the issuer AS performs under it. The limit is
AS-established operational policy; a client can request a narrower
ceiling through the Mission Intent's `requested_derivation_limit`
member ({{requested-limit}}).

## Requested Limit {#requested-limit}

This document defines one top-level Mission Intent member, under the
OAuth binding's Mission Intent members extension point
({{I-D.draft-mcguinness-oauth-mission}}, Section "Extensibility"):

`requested_derivation_limit`:
: OPTIONAL. A positive integer (1 or greater). A client-requested
  ceiling on the number of derivations the issuer AS performs under
  the Mission. An AS MUST reject a value below 1 with
  `invalid_request`. This member is a request only: the AS-established
  effective ceiling and its omission semantics are defined in
  {{effective-limit}}, its rendering in {{approval-rendering}}, and its
  enforcement in {{enforcement}}.

`intent_hash` commits the member like every Intent member
({{I-D.draft-mcguinness-oauth-mission}}, Section "Integrity Anchors");
{{test-vector}} gives a vector.

The following is an example of a Mission Intent carrying a requested
derivation limit:

~~~ json
{
  "goal": "Reconcile Q3 invoices and post adjustments under $500.",
  "target_resources": ["https://erp.example.com"],
  "expires_at": "2026-12-31T23:59:59Z",
  "requested_derivation_limit": 200
}
~~~

## Effective Limit {#effective-limit}

Omitting `requested_derivation_limit` means no client-requested
ceiling; the effective limit is then set by AS policy alone, which can
impose none.

The Mission Record's `derivation_limit` ({{record-member}}) is the
immutable, AS-established **effective** ceiling. At the approval
event the AS establishes it as the minimum of the deployment's own
policy ceiling for this Mission and the requested
`requested_derivation_limit`, where one was submitted, so a client's
request narrows, and never widens, the AS's own policy ceiling.
{{approval-rendering}} states how the approval surface renders it.

This establishment happens afresh at every approval event that
creates a Mission Record: a Child Mission's
({{I-D.draft-mcguinness-oauth-mission-child-delegation}}), a
dispatched Template instance's
({{I-D.draft-mcguinness-oauth-mission-template}}), and an Expansion
successor's ({{I-D.draft-mcguinness-oauth-mission-expansion}}),
exactly as at direct approval. An established `derivation_limit` is
never inherited unchanged from a parent, a template, or a predecessor
Mission, with one exception: a Child Delegation carryover replacement
preserves the old child's `derivation_limit` and derivation count, so
carryover cannot replenish a derivation budget
({{I-D.draft-mcguinness-oauth-mission-child-delegation}}, Section "No
State, Authority, Expiry, or Budget Reset"). Otherwise each Mission
Record's ceiling comes only from its own Intent's
`requested_derivation_limit`, clamped by the deployment's policy for
that Mission.

## Mission Record Member {#record-member}

This document defines one Mission Record member, under a short name
coordinated with the OAuth binding's open record
({{I-D.draft-mcguinness-oauth-mission}}, Section "Mission Record"):

`derivation_limit`:
: REQUIRED when an effective derivation ceiling is established for
  this Mission, whether by requested narrowing or by policy alone
  ({{effective-limit}}), absent otherwise. A positive integer: the
  AS-established effective ceiling on derivations under this Mission,
  fixed at the approval event. {{enforcement}} defines its enforcement
  and {{counting}} the running derivation count it is gated against.

Neither integrity anchor commits `derivation_limit`
({{I-D.draft-mcguinness-oauth-mission}}, Section "Integrity
Anchors"). {{sec-audit}} describes how an auditor checks it.

# Counting Derivations {#counting}

The running derivation count is AS-side state about the Mission, not a
member of the immutable record. It counts derivations as the OAuth
binding defines them ({{I-D.draft-mcguinness-oauth-mission}}, Section
"Issuance Gating"): one issuance operation the issuer AS performs for
a single request, namely the initial authorization-code exchange, a
refresh, a Token Exchange ({{RFC8693}}), or a cross-domain grant
issuance ({{I-D.draft-mcguinness-oauth-mission-cross-domain}}).

## What Counts {#counted-operations}

Each derivation counts as exactly one, regardless of how many
artifacts it emits: a code exchange that returns both an access token
and a refresh token is one derivation. A derivation that fails,
including one refused for exceeding the bound, MUST NOT be counted.

## Atomicity and Concurrency {#concurrency}

The AS MUST NOT let concurrent derivations collectively exceed the
bound. A derivation is counted when it commits, so the count, and the
`derivations_remaining` it yields ({{introspection}}), reflect
committed issuances only.

## Refresh and Token Exchange {#refresh-and-exchange}

A refresh is one derivation, and a refresh that rotates both the
access token and the refresh token is one. A Token Exchange under the
Mission is one derivation, whether it down-scopes a token for the
approved agent or issues a delegated token
({{I-D.draft-mcguinness-oauth-mission}}, Section "Delegation Within a
Mission").

The one exception is a delegation family under the Continuation
profile's async delegation transport
({{I-D.draft-mcguinness-oauth-mission-continuation}}, Section "Async
Delegation Transport"): the exchange that creates the family is one
derivation, and the family's successive refreshes are not counted
again. That profile makes the Mission's expiry, not this limit, the
family's continuity ceiling ({{sec-async-family}}).

## Cross-Domain Issuance {#cross-domain-counting}

The count covers only derivations the issuer AS performs. Tokens
another domain mints locally under the Mission are not counted by the
issuer, which cannot observe them; the cross-domain issuance that
authorized them was counted once, and the local issuer bounds its own
minting by its policy
({{I-D.draft-mcguinness-oauth-mission-cross-domain}}). The Resource
AS's local issuance under a projected grant is bounded by that grant's
own lifetime and local policy, not counted against the origin
issuer's per-Mission derivation cap.

# Enforcement at Issuance {#enforcement}

The derivation limit is an issuance gate beside those of the OAuth
binding ({{I-D.draft-mcguinness-oauth-mission}}, Section "Issuance
Gating"). When the Mission's `derivation_limit` ({{record-member}}) is
established, the AS MUST refuse, with the `invalid_grant` error code,
any derivation that would make the number of **derivations** under
the Mission exceed it.

The issuer AS enforces the limit at each derivation. The bound is
never absent at the issuer when established, and it does not bound
another domain's local minting ({{cross-domain-counting}}). The
rendered limit ({{approval-rendering}}) is therefore a bound a named
party enforces, so rendering it meets the OAuth binding's rule
against presenting a rendered bound as enforced when no party
enforces it ({{I-D.draft-mcguinness-oauth-mission}}, Section
"Mission Approval").

`invalid_grant` alone does not tell a client which gate refused. On a
refusal under this section the AS SHOULD include, alongside `error`,
the `mission_error` token-error-response member
({{I-D.draft-mcguinness-oauth-mission}}, Section "Issuance Gating")
with the value `derivations_exhausted`. The OAuth binding's rules for
that member apply: it is diagnostic only, it grants nothing, an
unrecognized value is ignored, and it is returned only to the
authenticated client presenting the Mission's grant. The refusal maps
as the OAuth binding's other token-endpoint lifecycle refusals do
({{I-D.draft-mcguinness-oauth-mission}}, Section "Error and Challenge
Mapping"): `invalid_grant` ({{Section 5.2 of RFC6749}}), with
`mission_error` as the optional detail.

The following is an example of a token error response refusing a
derivation under an exhausted limit:

~~~ http-message
HTTP/1.1 400 Bad Request
Content-Type: application/json
Cache-Control: no-store

{
  "error": "invalid_grant",
  "mission_error": "derivations_exhausted"
}
~~~

# Remaining Derivations in Token Introspection {#introspection}

Where the AS supports token introspection {{RFC7662}} for
Mission-bound tokens ({{I-D.draft-mcguinness-oauth-mission}}, Section
"Mission State via Token Introspection"), the `mission` member of the
introspection response can carry one member this document defines:

- `derivations_remaining`: when `derivation_limit`
  ({{record-member}}) is established, the derivations left under the
  cap at the time of the response, counting committed issuances
  ({{concurrency}}) (number).

`derivations_remaining` lets an issuance-budget consumer plan
refreshes against the cap. It is not an enforcement input
({{I-D.draft-mcguinness-oauth-mission}}, Section "Resource Server
Enforcement").

The OAuth binding's caller authorization and minimization rules apply
to it ({{I-D.draft-mcguinness-oauth-mission}}, Section "Caller
Authorization and Minimization"), and its disclosure is member-scoped.
`derivations_remaining` serves issuance-budget consumers, not
Resource Server enforcement, and the AS MUST disclose it only to a
caller the deployment has granted that member's disclosure privilege.
By default, an audience-authorized Resource Server receives the
audience-filtered enforcement projection without it.

An AS MUST NOT include `derivations_remaining` in an introspection
response unless it holds the Mission, that is, unless it is the
Mission `issuer` ({{I-D.draft-mcguinness-oauth-mission}}, Section
"Only the Issuer Reports Mission State").

The following is an example of an introspection response to a caller
granted the `derivations_remaining` disclosure privilege:

~~~ json
{
  "active": true,
  "client_id": "s6BhdRkqt3",
  "exp": 1790000000,
  "mission": {
    "id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
    "issuer": "https://as.example.com",
    "state": "active",
    "derivations_remaining": 187
  }
}
~~~

# Approval Rendering {#approval-rendering}

Where an effective `derivation_limit` is established, the AS MUST
render it for consent at the approval event, as context beside the
derived Authority Set, in the rendering step of the OAuth binding's
approval sequence ({{I-D.draft-mcguinness-oauth-mission}}, Section
"Mission Approval"). The rendering shows the established value, not
only the requested one. Where the AS supports the Continuation
profile's async delegation transport, the rendering MUST also state
that the refreshes of an async delegation family are not counted
against the limit ({{refresh-and-exchange}}).

The rendered limit is one Mission's local bound ({{sec-composition}}).
Where a deployment runs child delegation, that profile states what an
approval interface discloses beside it
({{I-D.draft-mcguinness-oauth-mission-child-delegation}}).

# Conformance {#conformance}

An AS conforming to this document MUST implement:

- the requested limit, the effective limit, and the record member
  ({{derivation-limit}});
- derivation counting ({{counting}});
- enforcement at issuance ({{enforcement}});
- approval rendering ({{approval-rendering}}); and
- where it supports token introspection for Mission-bound tokens, the
  rules for `derivations_remaining` ({{introspection}}).

A Resource Server does not need to understand this document to enforce
Mission-bound tokens; `derivations_remaining` is not an enforcement
input ({{introspection}}).

# Security Considerations {#security-considerations}

The security considerations of {{I-D.draft-mcguinness-oauth-mission}}
apply. This section covers what the derivation limit adds.

## Issuance, Not Authority {#sec-not-authority}

The derivation limit bounds how many counted issuance operations the
issuer performs; the refreshes of an async delegation family are not
counted ({{sec-async-family}}). It does not narrow the Authority Set,
shorten a token's lifetime, or bound the requests a Resource Server
honors under a token already issued: a derived token remains usable
until its `exp`. A deployment that needs to bound use, rather than
issuance, adopts a runtime control such as metering
({{I-D.draft-mcguinness-mission-metering}}).

## Async Delegation Families {#sec-async-family}

Because the refreshes of an async delegation family are not counted
({{refresh-and-exchange}}), the limit does not bound how many tokens
the issuer mints under such a family. The Continuation profile bounds
the family instead: its delegated authorization state is a subset of
the Mission's Authority Set, its absolute lifetime equals the
Mission's `expires_at`, and it is invalidated when the Mission reaches
a terminal state
({{I-D.draft-mcguinness-oauth-mission-continuation}}, Section "Async
Delegation Transport").

## Delegation Fan-Out {#sec-fan-out}

In-Mission delegation bounds the length of a delegation chain with
`max_depth` and its breadth with `allowed_delegates`
({{I-D.draft-mcguinness-oauth-mission}}, Section "Delegation
Constraints"). The derivation limit caps total derivations, including
each Token Exchange that issues a delegated token
({{refresh-and-exchange}}), however the resulting credentials are
distributed.

## Composition Across Missions {#sec-composition}

`derivation_limit` is a per-Mission bound the issuer AS enforces for
that Mission alone; a Child Mission's own `derivation_limit` is
independent of its parent's, and the parent's cap does not bound the
child subtree by default. The derivations summed across an entire
child subtree can therefore exceed what a single approval appears to
bound at consent time.

For example, a child-delegation deployment
({{I-D.draft-mcguinness-oauth-mission-child-delegation}}) allowing
`max_children` 3 per Mission with `max_child_depth` 2 admits up to 12
descendant Missions (3 in the first generation, up to 9 in the
second), each with its own independent `derivation_limit`; at 10
each, the subtree admits up to 120 derivations while no single bound
the Approver saw exceeds 10.

Cross-domain projection composes separately: local issuance at a
Resource AS is not counted against the origin issuer's cap
({{cross-domain-counting}}). The OAuth binding's composition guidance
applies to the derivation limit as to its other bounds
({{I-D.draft-mcguinness-oauth-mission}}, Section "Composition and the
Effective Ceiling").

## Audit Recomputation {#sec-audit}

An auditor recomputes the expected `derivation_limit` from the
recorded `requested_derivation_limit` (or its absence) and the
Mission's `policy_version` ({{I-D.draft-mcguinness-oauth-mission}},
Section "Mission Authority") against the deployment's retained,
versioned policy; a mismatch is a policy-application defect to
investigate, not a Mission-record integrity failure, since neither
integrity anchor commits `derivation_limit`.

## Concurrent Derivation {#sec-concurrency}

A count that is read and then incremented in separate steps lets
parallel refreshes or exchanges exceed the limit. {{concurrency}}
forbids that outcome, not a particular locking design.

# Privacy Considerations {#privacy-considerations}

`derivations_remaining` reveals how actively a Mission's grant is
exercised and, across successive responses, its issuance cadence.
Member-scoped disclosure ({{introspection}}) limits it to callers the
deployment grants that privilege.

# IANA Considerations {#iana}

This document requests registration of the following in the "Mission
Intent Members" registry established by
{{I-D.draft-mcguinness-oauth-mission}}:

- Name: `requested_derivation_limit`
- Status: `stable`
- Semantics: Client-requested derivation-count ceiling
  ({{derivation-limit}}).
- Change Controller: IETF
- Reference: this document, {{requested-limit}}

This document's promotion criterion for the member is a complete
definition of its request semantics, effective limit, counting, and
enforcement. The definitions in {{derivation-limit}}, {{counting}},
and {{enforcement}} meet it, which a Designated Expert confirms before
the `stable` registration ({{I-D.draft-mcguinness-oauth-mission}},
Section "Mission Intent Members Registry").

`derivation_limit` is a Mission Record member and
`derivations_remaining` a member of the introspection `mission`
member, each under an extension point of the OAuth binding, and
`derivations_exhausted` is a value of the OAuth binding's
`mission_error` member. None of these has an IANA registry, so this
document requests no further registration.

--- back

# Integrity Anchor Test Vector {#test-vector}

This non-normative vector shows `requested_derivation_limit`
committed by `intent_hash`, computed as the OAuth binding specifies
({{I-D.draft-mcguinness-oauth-mission}}, Sections "Integrity Anchors"
and "Canonicalization Rules"), with the issuer
`https://as.example.com`. The canonical-bytes block is the exact JCS
{{RFC8785}} output, wrapped here for layout only; removing the line
breaks, and adding no characters, recovers the canonical form.

`intent_hash`, over this Mission Intent as the envelope `value` with
`typ` `mission-intent`:

~~~ json
{
  "goal": "Reconcile Q3 invoices",
  "target_resources": ["https://erp.example.com"],
  "expires_at": "2026-12-31T23:59:59Z",
  "requested_derivation_limit": 20
}
~~~

Canonical bytes of the envelope:

~~~ text
{"iss":"https://as.example.com","typ":"mission-intent","value":{"e
xpires_at":"2026-12-31T23:59:59Z","goal":"Reconcile Q3 invoices","r
equested_derivation_limit":20,"target_resources":["https://erp.exa
mple.com"]}}
~~~

~~~ text
intent_hash = sha-256:r--mF07yZfWRGV6N28A2u_8rUzIG-bNhpvFSS5FhoBk
~~~

# Document History {#document-history}

\[\[ To be removed from the final specification ]]

-00

- Initial version. Carries the derivation limit of Mission-Bound
  Authorization for OAuth 2.0 with its wire names and rules unchanged:
  the `requested_derivation_limit` Intent member, the
  `derivation_limit` record member, counting and refusal at issuance,
  the `derivations_exhausted` diagnostic, the `derivations_remaining`
  introspection member, and approval rendering.
