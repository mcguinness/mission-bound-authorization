---
title: "Mission Expansion for OAuth 2.0"
abbrev: "OAuth Mission Expansion"
category: std

docname: draft-mcguinness-oauth-mission-expansion-latest
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
 - expansion
venue:
  github: "mcguinness/mission-bound-authorization"
  latest: "https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-expansion.html"

author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com

normative:
  RFC9126:
  RFC9396:
  RFC8705:
  RFC9449:
  I-D.draft-mcguinness-oauth-mission:
    title: "Mission-Bound Authorization for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026

informative:
  RFC8126:
  RFC9470:
  I-D.draft-mcguinness-oauth-mission-status:
    title: "Mission Status and Lifecycle for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-status.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-mission-runtime:
    title: "Mission-Bound Runtime Enforcement"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-runtime.html
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
  I-D.draft-mcguinness-oauth-mission-signals:
    title: "Mission Lifecycle Signals for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-signals.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-oauth-mission-progressive:
    title: "Mission Progressive Authorization for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-progressive.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026

--- abstract

Mission-Bound Authorization for OAuth 2.0 commits a Mission's
authority at a single approval event and defers widening: enlarging
authority requires a new approval, a successor Mission. This document
defines that successor mechanism as an OPTIONAL, layered extension to
the issuance profile. When an action falls outside an active Mission's
Authority Set but the deployment's governance policy permits widening,
a client initiates expansion: it submits a new Mission Intent through
Pushed Authorization Requests, bound to the predecessor Mission's
grant, and a fresh approval event records a successor Mission. The
successor carries a `predecessor` member on its `mission` claim
linking it to the Mission it replaces; on the successor's first
redemption it activates and the predecessor enters a terminal
`superseded` state, so an unredeemed code leaves the predecessor
active. Expansion never
widens authority without a new consent: the successor's authority
comes only from its own approval. A deployment that never expands a
Mission is unaffected by this document.

--- middle

# Introduction

Mission-Bound Authorization for OAuth 2.0
{{I-D.draft-mcguinness-oauth-mission}} (the "issuance profile") makes
a Mission a first-class OAuth artifact: a structured, human-approved,
integrity-bound task whose authority bounds and outlives every token
an agent derives. It commits the Authority Set once, at the approval
event, and deliberately defines no mid-stream authorization upgrade.
As that profile states, widening authority requires a new approval, a
successor Mission, as specified by this companion profile.

This document is that successor mechanism. A task an agent pursues
does not always stay within the authority approved for it: the agent
encounters an action the approved Authority Set does not cover, yet
one the deployment's governance policy would permit under a fresh
consent. Expansion is the governed path from that shortfall to a new
approval. It does not patch or widen the existing Mission; it creates
a new Mission, through the issuance profile's own flow, linked to the
one it replaces.

The mechanism reuses the issuance profile end to end. An expansion is
a new Mission Intent submitted through Pushed Authorization Requests
({{RFC9126}}), bound to the predecessor Mission's grant, leading to a
fresh approval event ({{I-D.draft-mcguinness-oauth-mission}}) with its
own `intent_hash`, `authority_hash`, and Mission record. The
successor's authority comes only from that approval. This document
adds exactly three things on top of the issuance profile: a way to
bind an expansion request to the predecessor it expands; a
`predecessor` lineage member on the resulting Mission; and a terminal
`superseded` predecessor state with the reconciliation rules that keep
concurrent expansions consistent.

## Status: an OPTIONAL extension {#optional-status}

This document is OPTIONAL. It is a layered extension to the issuance
profile, not a change to it. A deployment that implements
{{I-D.draft-mcguinness-oauth-mission}} and never expands a Mission is
fully conformant to that profile and is unaffected by this document:
it issues no expansion request, records no `predecessor` member, and
never enters the `superseded` state this document introduces. The
issuance profile's lifecycle (`active`, `revoked`, `expired`) is
complete without expansion; the `superseded` state defined here
({{superseded-state}}) is relevant only when expansion is used.

A Mission Issuer claims conformance to this document only when it
adjudicates expansion; otherwise it remains a plain issuance-profile
Mission Issuer. Nothing here places a new requirement back on the
issuance profile.

## Expansion is not step-up {#not-step-up}

Expansion is a governance operation. It is distinct from
authentication step-up {{RFC9470}}. A request denied because an `acr`
or `amr` constraint requires fresh authentication is satisfied by
step-up, not by expansion: the Authority Set does not change. A
request denied because the requested authority is not in the active
Mission's Authority Set requires expansion: the Authority Set must be
enlarged through a new approval event. The two are not interchangeable;
{{step-up-distinction}} treats the security consequence of conflating
them.

## Relationship to the issuance profile {#relationship}

This document depends normatively on the issuance profile and is not
implementable alone. It reuses, without restating, that profile's
Mission Intent, submission via PAR, authority
derivation, approval event with its integrity anchors, Mission record,
the `mission` claim, the subset rule, and the lifecycle and issuance
gating. It uses the terms Agent (Client), Subject, Approver, Mission
Issuer, Mission Intent, Authority Set, Mission, and derived token as
defined there.

Where this document refers to "the issuance profile" without a section,
it means {{I-D.draft-mcguinness-oauth-mission}} as a whole.

## Scope

This document defines:

- the expansion request: how a client initiates a successor Mission
  and how that request is bound to the predecessor's grant
  ({{expansion-request}});
- the `predecessor` lineage member on the successor's `mission` claim
  and Mission record ({{predecessor-member}});
- the terminal `superseded` predecessor state and its transition
  ({{superseded-state}});
- replacement expansion as the mode, with branch expansion deferred
  ({{replacement}});
- concurrent-expansion reconciliation, with a closed set of
  reconciliation status codes ({{reconciliation}}); and
- the expansion denial reasons ({{denial-reasons}}).

This document does NOT define:

- a way to widen an existing Mission in place; expansion always
  creates a new Mission;
- runtime per-action enforcement or the classification of a denial as
  expansion-eligible; that is the runtime layer's concern
  ({{eligibility}}, {{I-D.draft-mcguinness-mission-runtime}});
- branch expansion, in which predecessor and successor both remain
  active ({{replacement}});
- multi-hop or cross-domain expansion; an expansion is adjudicated by
  the predecessor's Mission Issuer (its `issuer`); or
- policy-adjudicated expansion within a pre-consented authority
  ceiling; that is progressive authorization, defined by an
  experimental companion
  ({{I-D.draft-mcguinness-oauth-mission-progressive}}). Under this
  document alone, every expansion is adjudicated by a fresh human
  approval.

# Conventions and Terminology

{::boilerplate bcp14-tagged}

All JSON shown in this document is non-normative and illustrative; the
member definitions in the surrounding text are authoritative.

The following terms apply in addition to those inherited from the
issuance profile ({{relationship}}).

Predecessor Mission:
: The active Mission an expansion enlarges. It is the baseline for the
  successor and is referenced by the successor's `mission.predecessor`
  member ({{predecessor-member}}).

Successor Mission:
: The Mission a replacement expansion creates through a fresh approval
  event. It carries its own Authority Set, integrity anchors, and
  `mission_id`, and a `predecessor` member linking it to the
  predecessor ({{predecessor-member}}).

Expansion request:
: A Mission Intent submitted via PAR, bound to a predecessor Mission's
  grant, that asks the Mission Issuer to adjudicate a successor
  ({{expansion-request}}).

# Expansion Overview

## Protocol flow

~~~
 Agent (client)               Mission Issuer (AS)
     |                            |
     | denied: action outside     |
     | active Mission's authority |
     |                            |
     | 1. PAR: mission_intent +   | resolve predecessor
     |    predecessor grant -----> | from the grant;
     |    <----- request_uri ----- | gate predecessor active
     |                            |
     | 2. authorization request ->| fresh consent for the
     |                            | broader authority;
     |    <-------- code --------- | predecessor stays active
     |                            |
     | 3. token request --------> | first redemption:
     |    (redeem code)           | -> successor active
     |                            |    -> predecessor
     |                            |       superseded (atomic)
     |    <----- access token ---- | (mission.predecessor set)
     v
~~~

The shape is the issuance profile's own creation flow
({{I-D.draft-mcguinness-oauth-mission}}), with one addition at step 1:
the request is bound to the predecessor Mission's grant, so the
Mission Issuer adjudicates a successor of a specific predecessor rather
than an unrelated new Mission. The fresh consent at step 2 is what
supplies the broader authority; the successor's authority comes only
from this approval. Supersession is deferred to step 3: the successor
activates and the predecessor becomes `superseded` atomically at the
first redemption of the successor's authorization code, so an
unredeemed or expired code leaves the predecessor `active`
({{superseded-state}}).

## Eligibility {#eligibility}

A client initiates expansion after an action is denied because the
requested authority is outside the active Mission's Authority Set and
the deployment's governance policy permits widening it. This document
does not define how a denial is classified as expansion-eligible; that
classification belongs to the component that denies the action.

A Mission-aware Resource Server enforces the token's authority
statelessly and refuses an out-of-bounds action with its usual
insufficient-authority error ({{I-D.draft-mcguinness-oauth-mission}}).
The runtime enforcement profile
{{I-D.draft-mcguinness-mission-runtime}} is one source of an
expansion-eligible denial: in that profile a deny is terminal for the
attempted action, and the authority-expandable-denial escalation that
turns such a deny into an expansion is named there as out of scope.
This document defines that expansion. This document does not require any
particular denial source: a client that knows, by any means, that an
action needs authority the active Mission lacks MAY initiate expansion.
Whether the Mission Issuer adjudicates a successor remains its decision
({{adjudication}}); an eligible denial is not an authorization in favor
of expansion.

# The Expansion Request {#expansion-request}

An expansion request is an ordinary Mission creation request under the
issuance profile, with one added binding to the predecessor.

## Submission via PAR {#submission}

A client initiates an expansion exactly as it creates any Mission: it
submits a Mission Intent through a Pushed Authorization Request
({{RFC9126}}) using the `mission_intent` request parameter, per
{{I-D.draft-mcguinness-oauth-mission}}. The Mission Intent describes
the broadened task: it carries the `goal`, `resources`, `constraints`,
and `controls` the successor needs, including the authority the denied
action required. The Mission Issuer derives the successor's Authority
Set from this Intent and bounds it by policy exactly as for any
Mission; this document adds no authority-derivation rule.

To mark the request as an expansion, the client additionally supplies
the `predecessor` request parameter:

`predecessor`:
: REQUIRED for an expansion request. A string. The `mission_id` of the
  predecessor Mission the successor expands. Its presence signals that
  this Mission creation is an expansion and names the predecessor whose
  `mission.predecessor` lineage member and `superseded` transition the
  Mission Issuer applies. It names the predecessor for cross-checking
  and audit; it does not by itself select or authorize one (the grant
  does, {{request-binding}}). The parameter is carried through PAR with
  `mission_intent`; like `mission_intent`, an AS MUST reject a
  `predecessor` value presented directly on a front-channel
  authorization request rather than through a PAR-issued `request_uri`
  with `invalid_request`.

`predecessor_token`:
: REQUIRED for an expansion request. A string. The predecessor
  Mission's refresh token, presented as proof that the client controls
  the predecessor's grant. The Mission Issuer resolves the predecessor
  from this token and binds the expansion to it ({{request-binding}});
  this value, not `predecessor`, selects the predecessor
  authoritatively. It is carried through PAR with `mission_intent`; an
  AS MUST reject a `predecessor_token` presented directly on a
  front-channel authorization request rather than through a PAR-issued
  `request_uri` with `invalid_request`. Because it carries a refresh
  token, it MUST be sent only on the PAR back
  channel and MUST NOT appear on any front channel.

The `predecessor` parameter names the predecessor but does not
by itself authorize expanding it. Authorization comes from the grant
binding of {{request-binding}}: a client MUST NOT be able to expand a
Mission merely by naming its `mission_id`.

## Binding the request to the predecessor's grant {#request-binding}

The issuance profile binds a Mission to the authorization grant the
Mission Issuer issues, and resolves the Mission from the grant the
client presents, never from a client-supplied `mission_id`
({{I-D.draft-mcguinness-oauth-mission}}, grant binding). An expansion
request MUST be bound to the predecessor's grant the same way.

Because expansion runs as an interactive approval event, a PAR
submission followed by an authorization-code flow ({{adjudication}}),
the binding is established at the PAR submission, a back-channel
request. PAR permits a public client to submit without client
authentication ({{RFC9126}}), so the expansion MUST rest on an
authenticated proof of control over the predecessor's grant. A
confidential client supplies this by authenticating to the PAR
endpoint. A public client's PAR request is not client-authenticated,
so its expansion rests solely on the presented `predecessor_token`,
which MUST then be sender-constrained ({{RFC8705}} or {{RFC9449}}) so
it is not a bearer proof; the Mission Issuer MUST reject a
public-client expansion whose `predecessor_token` is not
sender-constrained with `invalid_request`. In the same PAR request that
carries `mission_intent` and `predecessor`, the client MUST
present the predecessor Mission's refresh token in the
`predecessor_token` parameter ({{submission}}). The Mission
Issuer MUST resolve the predecessor from that refresh token, applying
the same grant-to-Mission resolution the issuance profile uses for a
presented refresh token, and MUST verify that the resolved Mission is
the Mission named in `predecessor`.

Establishing the binding at PAR, before the approval event, is
deliberate: the Mission Issuer resolves the predecessor from a real
grant and confirms it is active and owned by this client before
prompting the Approver. A client that merely names a `mission_id` it
does not hold a grant for cannot reach the consent step, so expansion
cannot be used to drive approval prompts against another party's
Mission.

The grant, not the identifier, determines the predecessor. The Mission
Issuer MUST refuse an expansion request whose `predecessor`
value does not match the Mission resolved from the presented grant,
with `invalid_grant`. A client that does not hold a grant for the named
predecessor cannot present its refresh token and so cannot expand it.

Presenting the predecessor's refresh token in the PAR request MUST
follow the issuance profile's handling for that token: a
sender-constrained refresh token MUST be presented in conformance with
its sender constraint. When the token is DPoP-bound {{RFC9449}}, the PAR
request MUST carry a DPoP proof bound to the PAR endpoint (its `htu` and
`htm`); when it is mTLS-bound {{RFC8705}}, the mutual-TLS connection of
the PAR request satisfies the constraint. Presenting the token for
expansion MUST NOT rotate it and MUST NOT register as a replay in the
deployment's refresh-token replay detection: the token is used here only
to bind and resolve the predecessor, not to refresh. In a
rotation-based deployment that carve-out would let a stolen bearer
refresh token be presented repeatedly without detection, so each
expansion presentation MUST be recorded and counted toward the
deployment's anomaly detection, and the per-predecessor rate limit
({{policy-probing}}) applies unconditionally, with a tighter bound
SHOULD when the presented token is not sender-constrained. The
successor's
authority still comes only from the fresh consent at the approval event,
never from authority the binding token could itself derive.

This binding requires the predecessor to have a refresh token to
present. A Mission issued without one (for example an
access-token-only grant) has no `predecessor_token` to carry and so
cannot be expanded through this binding; a deployment that must expand
such a Mission defines an alternative grant proof by extension, or the
task obtains its broadened authority as an ordinary new Mission under
the issuance profile, linked by the successor's `related_to` member
({{predecessor-member}}) for lineage.

Because expansion reuses the issuance profile's grant binding, it
needs no opaque expansion ticket or other new bearer: the predecessor
is identified and authorized by the grant the client already holds for
it, and a client cannot name an arbitrary predecessor.

## Predecessor must be active {#predecessor-active}

The Mission Issuer MUST resolve the predecessor from the presented
grant and verify it is in the `active` state before adjudicating. An
expansion request against a predecessor that is not `active` MUST be
refused with `invalid_grant` and a reconciliation status
({{reconciliation}}):

- if the predecessor made a terminal exit from `active` (it is
  `revoked`, `expired`, or already `superseded`, {{superseded-state}}),
  the status is `predecessor_state_changed`;
- if the predecessor is in a non-terminal non-active state, for example
  `suspended` where the Mission Status profile
  {{I-D.draft-mcguinness-oauth-mission-status}} is deployed, the status
  is `predecessor_not_active`.

Issuance gating in the issuance profile already refuses to derive from a
non-active Mission; this rule extends the same gate to adjudicating an
expansion of one.

# Adjudication {#adjudication}

Adjudication of an expansion is a fresh approval event under the
issuance profile ({{I-D.draft-mcguinness-oauth-mission}}). The Mission
Issuer runs the approval event as it does for any Mission, with the
expansion-specific steps noted:

1. Resolve the predecessor from the presented grant and verify it is
   the Mission named in `predecessor` and is `active`
   ({{request-binding}}, {{predecessor-active}}).
2. Derive the successor's Authority Set from the submitted Mission
   Intent and bound it by policy, exactly as for any Mission. The
   successor's authority is whatever this derivation and the fresh
   consent yield; it is not the predecessor's authority plus a delta
   computed by this document. A deployment that wants the successor to
   retain the predecessor's authority expresses that authority in the
   expansion Mission Intent so the derivation reproduces it.
3. Authenticate the Approver and obtain fresh consent for the derived
   Authority Set, satisfying any `controls.acr`, and render the Subject
   when the Approver is not the Subject, per the issuance profile's
   approval event. The consent disclosure MUST reflect the successor's
   authority being adjudicated. (The experimental progressive
   authorization companion defines a policy-adjudicated override of
   this step for expansions within a pre-consented ceiling,
   {{I-D.draft-mcguinness-oauth-mission-progressive}}.)
4. Compute the successor's integrity anchors (`intent_hash`,
   `authority_hash`) and commit them in the authorization code the
   approval event issues; defer materializing the successor. On the
   first redemption of that authorization code (the successor's
   grant), create the successor Mission record in the `active` state,
   with its `predecessor` member set ({{predecessor-member}}),
   atomically with the predecessor's transition to `superseded`
   ({{superseded-state}}). Until that redemption the predecessor
   remains `active`; an authorization code that is never redeemed or
   that expires creates no successor and leaves the predecessor
   `active`.

The expansion is governed by the consent obtained at step 3. Expansion
never widens authority without a new consent: if the Approver declines,
no successor is created and the predecessor is untouched
({{denial-reasons}}).

Supersession is a terminal exit from `active`, so it is a terminal
cascade trigger for the predecessor's entire delegation tree under the
child-delegation profile
({{I-D.draft-mcguinness-oauth-mission-child-delegation}}). When the
predecessor has non-terminal Child Missions, the expansion consent
disclosure SHOULD surface that fact as a material notice: at minimum
the count of live Child Missions and that supersession terminates
them. A child still needed after the expansion is re-created under the
successor through ordinary child creation, in generation order. A
deployment MAY additionally support an expansion-request parameter by
which the client asks the Mission Issuer to refuse the expansion while
live Child Missions exist.

## Successor expiry {#successor-expiry}

The successor's `expires_at` MUST NOT exceed the predecessor's
`expires_at` unless the Mission Issuer's policy explicitly permits
extension and the extension is disclosed to the Approver at the
expansion consent event. Expansion is an authority-addition mechanism,
not a lifetime-extension mechanism. The issuance profile caps every
derived credential's `exp` at the Mission's `expires_at`; a successor that
silently outlived its predecessor would let expansion launder a
longer-lived Mission past the originally approved horizon.

# The Predecessor Mission Reference {#predecessor-member}

The successor records a lineage link to the predecessor as a
`predecessor` member, both on the successor's `mission` claim and on
the successor's Mission record.

The issuance profile's `mission` claim is an open object: additional
members MAY appear alongside `id`, `issuer`, and `authority_hash`, each
defined by the profile that introduces it, and a consumer MUST ignore
members it does not understand and MUST NOT use any additional member
to grant or widen authority ({{I-D.draft-mcguinness-oauth-mission}}).
This document introduces one such member:

`predecessor`:
: REQUIRED on a successor Mission; absent otherwise. A string. The
  `mission_id` of the Mission this Mission succeeded by expansion.
  Present on every Mission created by expansion and absent on a Mission
  that was not created by expansion. It is a
  lineage and audit reference only: it links the successor to the
  Mission it replaced so that the expansion chain is observable in
  audit. Consistent with the issuance profile's open-`mission`-claim
  rule, `predecessor` MUST NOT grant or widen authority, and a consumer
  that does not understand it MUST ignore it. The successor's authority
  comes only from its own `authority_hash`, never from its predecessor.

The same `predecessor` value is recorded on the successor's immutable
Mission record so that the lineage is durable independently of any
derived token.

This document defines two further lineage members:

`related_to`:
: OPTIONAL. A string. The `mission_id` of a Mission this Mission is
  related to by lineage without superseding it, used for a non-superseding
  link such as a branch ({{replacement}}). Unlike `predecessor`, its
  presence does not imply that the referenced Mission was superseded and
  it carries no lifecycle consequence. Like `predecessor`, it is lineage
  and audit context only: it MUST NOT grant or widen authority, and a
  consumer that does not understand it MUST ignore it.

`successor`:
: OPTIONAL. A string. The `mission_id` of the successor that superseded
  this Mission by expansion, recorded on the superseded predecessor's
  Mission record at supersession ({{superseded-state}}). It is the
  reverse of the successor's `predecessor` link, letting a consumer that
  holds a superseded predecessor discover its successor directly. It is
  lineage and audit context only and MUST NOT grant or widen authority.
  The Status profile surfaces it in the status response
  ({{I-D.draft-mcguinness-oauth-mission-status}}) and the Signals profile
  in the superseded lifecycle event
  ({{I-D.draft-mcguinness-oauth-mission-signals}}).

`predecessor`, `related_to`, and `successor` are each a bare Mission
Identifier string, not an object like the `parent` member of a Child
Mission
({{I-D.draft-mcguinness-oauth-mission-child-delegation}}): same-issuer
succession needs only the identifier to resolve the linked Mission at the
shared `issuer`, whereas parentage carries cascade semantics and
cross-object integrity that require a structured member.

Properties:

- **Cardinality.** A successor has at most one `predecessor`. An
  expansion chain is expressed by walking `predecessor` links from a
  successor back toward the original Mission.
- **Immutability.** `predecessor` is set at the successor's approval
  event and MUST NOT change thereafter. The Mission record is immutable
  except for its `state` and the one-time `successor` link a supersession
  sets on the predecessor ({{superseded-state}}).
- **Origin.** The predecessor and successor share an `issuer`: an
  expansion is adjudicated by the predecessor's Mission Issuer. A
  consumer correlating a chain resolves each link at that issuer.

Example successor `mission` claim on a derived token (non-normative;
other token claims omitted):

~~~ json
{
  "mission": {
    "id": "msn_2Yt7Qv9LqMv4z7sA2bN1k0YpEdHc9RfX",
    "issuer": "https://as.example.com",
    "authority_hash":
      "sha-256:Td9bM7sX1cF8gH2vJ4kE5pNQl3KvZ4mP5x0wQrR6tY2",
    "predecessor": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-"
  }
}
~~~

# The Superseded Predecessor State {#superseded-state}

This document adds one terminal state to the issuance profile's
lifecycle, used only by expansion:

`superseded`:
: A predecessor Mission that a successor has replaced through a
  replacement expansion. Terminal and non-active.

A deployment that never expands a Mission never produces this state;
the issuance profile's `active`/`revoked`/`expired` lifecycle is
unchanged for it. The transition is:

| From | Event | To |
|---|---|---|
| `active` | successor activates on first redemption of its grant | `superseded` |

The transition has these requirements:

- **Atomic with successor activation at first redemption.** The
  successor activates, and the predecessor enters `superseded`, in one
  atomic operation at the first redemption of the successor's
  authorization code (its grant), not at the approval event
  ({{adjudication}}); in that same operation the Mission Issuer sets
  the predecessor's `successor` member to the successor's `mission_id`
  ({{predecessor-member}}). Until that redemption the predecessor
  remains `active`. An authorization code that is never redeemed or
  that expires activates no successor and leaves the predecessor
  `active`, so an unredeemed or expired code never strands the task's
  authority nor cascade-terminates the predecessor's Child Missions.
  If the atomic operation fails, the predecessor remains `active` and
  no successor record exists; the Mission Issuer MUST NOT produce a
  partial successor or a predecessor left in an indeterminate state.
- **Non-active: no further derivation.** A `superseded` Mission is not
  `active`, so the issuance profile's issuance gating refuses to derive
  any new token, refresh, token exchange, or cross-domain grant under
  it: derivation proceeds only from an `active` Mission
  ({{I-D.draft-mcguinness-oauth-mission}}). New authority for the task
  flows through the successor.
- **Already-issued predecessor tokens.** Tokens already derived under
  the predecessor before it was superseded remain valid until their own
  `exp`, exactly as in the issuance profile's revocation model:
  superseding a Mission stops new derivation; it does not retroactively
  invalidate access tokens already issued. A deployment that needs a
  lower cutoff latency on the predecessor's outstanding tokens SHOULD
  use short token lifetimes, and MAY additionally revoke the
  predecessor's refresh token where the issuance profile's optional
  revocation composition is in use. These tokens MUST NOT be silently
  rebound to the successor; authority under the successor is obtained
  only by deriving from the successor's grant, which is a new
  derivation governed by the successor's Authority Set.
- **Reported as non-active.** A `superseded` predecessor is reported
  through the same mechanisms that report a `revoked` or `expired`
  Mission. Where the issuance profile's optional token introspection is
  offered, the composite `active` is `false` and, from the issuer, the
  `mission.state` member gives `superseded`. Where the Mission Status
  profile {{I-D.draft-mcguinness-oauth-mission-status}} is deployed, the
  dedicated Status operation reports `superseded` among the terminal
  states and the Status Response `mission.state` gives `superseded`. A
  deployment that offers either surface and this document MUST include
  `superseded` among the lifecycle states its issuer may report.
  Consumers rely on the issuance profile's forward-compatibility rule:
  `superseded`, like any non-`active` state, is non-deriving.

## No implicit rollback {#no-rollback}

The Mission Issuer MUST NOT implicitly resurrect a `superseded`
predecessor when its successor is later revoked, expired, or itself
superseded; `superseded` is terminal. A deployment that needs
"revert to the predecessor's authority" semantics expresses that as a
new approval event creating a new Mission that carries the relevant
authority, with its own `predecessor` link preserving the lineage. A
rollback is therefore a new governed Mission, not a state reversal.

# Replacement Expansion {#replacement}

A successful expansion is a **replacement**: the successor replaces the
predecessor, and the predecessor becomes `superseded`
({{superseded-state}}). Replacement is the only mode this document
defines.

Under replacement, exactly one successor is created per predecessor,
and the predecessor is no longer active once the successor activates.
The successor carries its own complete Authority Set as derived and
consented at the expansion approval event; it does not inherit the
predecessor's authority by reference. A deployment that wants the
successor to retain the predecessor's authority alongside the new
authority expresses the combined authority in the expansion Mission
Intent, so the successor's `authority_hash` commits exactly the
authority the Approver saw and approved ({{adjudication}}).

A **branch** mode, in which the predecessor and the successor both
remain `active` after expansion (for example, a separately scoped child
task running alongside the original), is OPTIONAL and is not defined
here. A deployment that needs a separately scoped task alongside a
still-active Mission creates an ordinary new Mission under the issuance
profile and MAY set that Mission's `related_to` member
({{predecessor-member}}) to the original Mission's `mission_id` to
preserve lineage; it does not set `predecessor`, which would imply a
supersession, so the original remains `active`. An atomic, grant-bound
branch
expansion that creates such a child within a single expansion approval
event is deferred to a future revision of this document.

# Concurrent Expansion Reconciliation {#reconciliation}

More than one expansion request MAY be in flight against the same
predecessor at once, and more than one MAY be adjudicated and hold an
unredeemed authorization code. Because replacement produces exactly one
successor per predecessor ({{replacement}}) and supersession is
deferred to first redemption ({{superseded-state}}), the Mission Issuer
MUST serialize the redemptions that would activate a successor of the
same predecessor, so that concurrent expansions cannot each activate
one.

The Mission Issuer MUST apply compare-and-set semantics at the first
redemption of a successor's authorization code. In the same atomic step
that would activate the successor and supersede the predecessor, the
Mission Issuer MUST verify:

1. the predecessor is still in the `active` state; and
2. no other replacement expansion has already activated a successor for
   this predecessor (equivalently, the predecessor has not already
   transitioned to `superseded`).

If either check fails, the Mission Issuer MUST refuse the redemption
with `invalid_grant` and the applicable reconciliation status from the
closed set below. The losing or otherwise stale expansion is rejected
at redemption; it activates no successor.

The reconciliation status codes are:

`superseded_by_concurrent_expansion`:
: A concurrent replacement expansion has already produced a successor;
  the predecessor is now `superseded` rather than `active`. The client
  SHOULD discover the existing successor and re-evaluate whether a
  further expansion is still required (an expansion of the successor is
  a new expansion against the successor as predecessor).

`predecessor_state_changed`:
: The predecessor made a terminal exit from `active` (to `revoked`,
  `expired`, or `superseded`) before this expansion could complete,
  whether caught at request binding ({{predecessor-active}}) or at the
  compare-and-set on first redemption ({{reconciliation}}). The client
  MUST NOT retry the same expansion against this predecessor.

`predecessor_not_active`:
: The predecessor is in a non-terminal non-active state (for example
  `suspended` under the Mission Status profile
  {{I-D.draft-mcguinness-oauth-mission-status}}) and cannot be expanded
  until it returns to `active`. The client MAY retry the expansion after
  the predecessor is `active` again.

The two terminal-exit codes overlap in the `superseded` case by design:
`superseded_by_concurrent_expansion` is the specific reconciliation
outcome when the cause is a concurrent expansion that has already won,
and `predecessor_state_changed` is the general outcome for any other
terminal exit from `active`. A Mission Issuer SHOULD return the specific
code when it can attribute the change to a concurrent expansion.
`predecessor_not_active` is distinct from both: it reports a reversible,
non-terminal state, so it invites the retry the terminal codes forbid.

The Mission Issuer conveys the reconciliation status in a
`mission_expansion_status` member of the OAuth error response body,
alongside the `invalid_grant` error:

`mission_expansion_status`:
: A string carrying one reconciliation status from this document's
  closed set ({{reconciliation}}). It is returned by the step that
  failed. At the PAR and token endpoints it is a member of the JSON
  error response body, alongside the OAuth `error` member. On the
  front-channel authorization error response, which carries error
  parameters rather than a JSON body, it is carried as an error
  response parameter of the same name. Adjudication denial reasons
  ride the separate `mission_denial_reason` member
  ({{denial-reasons}}).

# Expansion Denial Reasons {#denial-reasons}

An adjudication that completes with the Approver declining, or with the
Mission Issuer refusing on policy grounds, denies the expansion: no
successor is created and the predecessor remains `active` and
untouched. Such a denial is an OAuth error at the approval or token
step per the issuance profile (typically `invalid_request` for a
request the Mission Issuer will not derive a valid Authority Set from,
or the approval flow's own decline path). It MAY additionally carry one
machine-readable reason code from the closed set below:

`out_of_policy`:
: The Mission Issuer's governance policy refuses the requested
  authority class for this Mission, independent of who approves.

`approver_rejected`:
: The Approver declined the expansion at the consent step.

`out_of_scope_for_purpose`:
: The requested authority is incompatible with the Mission's recorded
  `purpose`; a different Mission, not an expansion of this one, is the
  appropriate vehicle.

A companion profile MAY extend this set by specification (the
experimental progressive authorization companion defines
`out_of_ceiling`, {{I-D.draft-mcguinness-oauth-mission-progressive}});
a consumer MUST treat an unrecognized reason code as a denial with no
further semantics.

A Mission Issuer MUST NOT use a reason code to disclose policy
boundaries beyond the adjudicated request ({{policy-probing}}); omitting
the reason code is always permitted. When present, a reason code is
carried in a `mission_denial_reason` member: at the PAR and token
endpoints a member of the JSON error response body alongside the OAuth
`error` member, on the front-channel authorization error response an
error response parameter of the same name.

`mission_denial_reason` is the shared carrier for adjudication denial
reasons across the profiles that mint a Mission related to an existing
one: the child delegation profile
({{I-D.draft-mcguinness-oauth-mission-child-delegation}}) carries its
own closed denial-reason set in the same member, and further such
profiles do likewise. Each profile defines its values by
specification; the unrecognized-code rule above applies to the member
wherever it appears.

Two failure classes are not denial reasons and use the issuance
profile's error vocabulary directly: an expansion request whose
`predecessor` does not match the grant-resolved Mission, or
whose predecessor is not `active`, fails with `invalid_grant`
({{request-binding}}, {{predecessor-active}}); an expansion Mission
Intent the Mission Issuer cannot parse or cannot derive a valid
Authority Set from fails with `invalid_request` or, where the issuance
profile uses it, `invalid_authorization_details` ({{RFC9396}}), exactly
as for any Mission creation.

# Worked Example {#example}

The Q3 reconciliation Mission
`msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-` authorizes reading invoices and
posting journal entries under $500. Mid-task the agent finds an
adjustment of $1,200, outside the active Mission's authority. It cannot
widen in place; it requests an expansion, submitting a new Mission
Intent through PAR bound to the predecessor's grant:

~~~ http
POST /par HTTP/1.1
Host: as.example.com
Content-Type: application/x-www-form-urlencoded

mission_intent=%7B...journal-entries%20cap%20%242000...%7D&
predecessor=msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-&
predecessor_token=<refresh%20token%20bound%20to%20the%20predecessor>&
client_id=s6BhdRkqt3
~~~

The Mission Issuer resolves the predecessor from the grant, confirms it
matches `predecessor` and is `active`, derives the successor's Authority
Set, and obtains fresh consent from `alice` for the widened cap,
issuing an authorization code. When the client redeems that code, the
Mission Issuer activates the successor and supersedes the predecessor
atomically; until then the predecessor stays `active`. The successor's
token carries a `predecessor` member:

~~~ json
{
  "mission": {
    "id": "msn_2Yt7Qv9LqMv4z7sA2bN1k0YpEdHc9RfX",
    "issuer": "https://as.example.com",
    "authority_hash":
      "sha-256:Td9bM7sX1cF8gH2vJ4kE5pNQl3KvZ4mP5x0wQrR6tY2",
    "predecessor": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-"
  }
}
~~~

The predecessor is now `superseded`: it derives no new tokens, its
already-issued tokens run out their short lifetimes, and the task
continues under the successor. The widening came only from `alice`'s
fresh consent; the successor's `authority_hash` commits the widened
Authority Set it was actually approved for, not the predecessor's plus a
delta.

# Conformance {#conformance}

An implementation claims conformance to this document only in the
Mission Issuer role and only when it adjudicates expansion. A
conforming **expansion-capable Mission Issuer** MUST:

- accept the `predecessor` and `predecessor_token`
  request parameters on a Mission creation via PAR and treat the
  request as an expansion ({{submission}});
- bind the expansion request to the predecessor's grant and refuse a
  request whose `predecessor` does not match the grant-resolved
  Mission, or whose predecessor is not `active`, with `invalid_grant`
  ({{request-binding}}, {{predecessor-active}});
- adjudicate the expansion as a fresh approval event that obtains new
  consent for the successor's authority ({{adjudication}}), enforcing
  the successor-expiry rule ({{successor-expiry}});
- record the `predecessor` member on the successor's `mission` claim
  and Mission record ({{predecessor-member}});
- activate the successor and transition the predecessor to `superseded`
  atomically at the first redemption of the successor's grant, leaving
  the predecessor `active` until then, and refuse further derivation
  under a `superseded` Mission ({{superseded-state}}); and
- serialize concurrent expansions against the same predecessor with the
  reconciliation semantics of {{reconciliation}}.

An expansion-capable Mission Issuer is also a conforming issuance-profile
Mission Issuer ({{I-D.draft-mcguinness-oauth-mission}}); this document
adds the expansion surface to that role. A Resource Server requires no
new behavior: it enforces a successor's tokens exactly as it enforces
any Mission-bound token, and treats the `predecessor` member, if it
reads it at all, as audit context it MUST NOT use to grant authority
({{predecessor-member}}).

Under this document, every expansion is adjudicated by a fresh human
approval. The experimental progressive authorization companion defines
a further OPTIONAL capability, **Expansion with Progressive
Authorization**, with its own conformance requirements
({{I-D.draft-mcguinness-oauth-mission-progressive}}).

# Security Considerations

Expansion's central guarantee is the issuance profile's, applied to
the successor: a user's fresh approval bounds every token derived for
the broadened task. The risks specific to expansion are in the
predecessor binding, the predecessor-to-successor handoff, and the
lineage link.

## Predecessor confusion {#predecessor-confusion}

A client could attempt to expand a Mission it does not control, for
example by naming another tenant's or subject's `mission_id` in the
`predecessor` parameter.

Mitigations:

- The predecessor is resolved from the grant the client presents, not
  from the `predecessor` value; the Mission Issuer MUST verify
  the resolved Mission matches the named one and MUST refuse a mismatch
  with `invalid_grant` ({{request-binding}}). A client that holds no
  grant for the named predecessor cannot expand it.
- The issuance profile's integrity anchors are issuer-bound, so a
  Mission's governance state cannot be transplanted across Mission
  Issuers; an expansion is adjudicated only at the predecessor's own
  `issuer`.

## Authority comes only from new consent {#new-consent}

An expansion could be misused to widen authority without the Approver
re-consenting, if a successor were allowed to inherit or extend
authority without a fresh approval.

Mitigations:

- The successor's authority comes only from the Authority Set derived
  and consented at the expansion approval event; the `authority_hash`
  commits exactly that set ({{adjudication}}). The `predecessor` member
  carries no authority and MUST NOT widen the successor
  ({{predecessor-member}}).
- The successor's `expires_at` MUST NOT silently exceed the
  predecessor's ({{successor-expiry}}), so expansion cannot launder a
  longer lifetime past the originally approved horizon.

## Race against predecessor lifecycle {#lifecycle-race}

Between the moment a client decides to expand and the moment the
successor activates at first redemption, the predecessor may be
revoked, expire, or be superseded by a concurrent expansion. Without
serialization an expansion could appear to succeed against a
predecessor that is no longer authoritative, or two successors could be
created.

Mitigations:

- The Mission Issuer MUST verify predecessor state and the
  no-existing-successor condition in the same atomic step that would
  activate the successor at first redemption ({{reconciliation}}), and
  serializes the redemptions that activate a successor of the same
  predecessor.
- A failed check refuses with `invalid_grant` and a reconciliation
  status that tells the client whether to discover an existing
  successor or stop, without leaking the predecessor's new internal
  state beyond that ({{reconciliation}}).

## Expansion versus step-up {#step-up-distinction}

Conflating expansion with authentication step-up {{RFC9470}} would
route an authentication shortfall through an approval event the
Approver did not need to perform, surfacing irrelevant consent and
risking approval fatigue, or conversely would treat a genuine
authority shortfall as a mere re-authentication and silently widen
nothing.

Mitigation: a denial that is an authentication shortfall (`acr`,
`amr`) is satisfied by step-up and MUST NOT be routed to expansion; a
denial that is an authority shortfall is the one expansion addresses
({{not-step-up}}). The component that classifies the denial
({{eligibility}}) makes this distinction.

## Policy probing {#policy-probing}

A client could submit many expansion requests for the same predecessor
to map the Mission Issuer's policy boundary from the denial reasons.

Mitigations:

- The Mission Issuer MUST rate-limit expansion requests per predecessor
  per client. The bound is unconditional: it caps both policy probing
  and the approval prompts a client can drive against an Approver
  (prompt fatigue). A deployment SHOULD apply a tighter bound when the
  presented `predecessor_token` is not sender-constrained
  ({{request-binding}}).
- A denial reason MUST NOT disclose policy boundaries beyond the
  adjudicated request ({{denial-reasons}}); a denial reports whether
  the requested authority was approved, not the full surface of what
  would have been.

## Audit linkage {#audit-linkage}

The `predecessor` member makes the expansion chain observable: an
authorized auditor can trace a successor back through its predecessors
to the original Mission. This is a core governance property of
expansion. An implementation that omits the member breaks the chain
and defeats it; the member is therefore REQUIRED on a successor
({{predecessor-member}}).

General OAuth security guidance applies to the underlying credentials
through the issuance profile.

# Privacy Considerations

The privacy surface expansion adds over the issuance profile is the
lineage link and the authority detail disclosed when a task is
broadened.

## Predecessor-chain correlation {#chain-correlation}

The `predecessor` member that gives audit linkage ({{audit-linkage}})
is also a correlation surface: it links a successor to its predecessor
across distinct approval events, so a party that can read the chain can
correlate the evolving task over time, which is more than any single
Mission discloses. This is intrinsic to the governance value of
expansion. Deployments SHOULD scope read access to the `predecessor`
member, and to any Mission-state surface that exposes it, to parties
with a governance need, rather than exposing the chain to every
credential audience. The issuance profile's Mission Identifier
correlation considerations apply to each Mission in the chain.

## Disclosure of the broadened task {#broadened-task}

The expansion Mission Intent and the consent disclosure rendered at the
expansion approval event reveal how the approved task is evolving. The
Mission Issuer SHOULD render that disclosure only to the Approver and
authorized governance consumers, consistent with the issuance profile's
treatment of consent disclosure.

# IANA Considerations

Consistent with the issuance profile, which establishes no registry of
`mission` claim members and registers the `mission` claim as an open
object, this document defines the `predecessor` member of the `mission`
claim ({{predecessor-member}}) without registering it in a dedicated
registry: it is a member defined by this profile, carried inside the
already-registered `mission` claim. No new claim, parameter, or
token-introspection registration is required for the lineage link.

This document defines two closed sets of symbolic codes, the expansion
reconciliation status codes ({{reconciliation}}), conveyed in
`mission_expansion_status`, and the expansion denial reasons
({{denial-reasons}}), conveyed in the shared `mission_denial_reason`
member. As members of the OAuth error response JSON body at the PAR
and token endpoints, both are namespaced to their error responses and
require no registration; their authorization error response parameter
forms are registered below. Like the issuance profile's restraint with
`mission` members, the codes are documented in their defining
specifications rather than placed in new IANA registries: the closed
sets are small and fully specified. Should interoperable extension
prove necessary, a future revision can create a "Mission Expansion
Reconciliation Status" registry and a shared "Mission Denial Reason"
registry with a Specification Required {{RFC8126}} policy; this document
does not create them.

This document registers the following parameters in the "OAuth
Parameters" registry:

- Name: `predecessor`
- Parameter Usage Location: authorization request
- Change Controller: IETF
- Reference: this document, {{submission}}

- Name: `predecessor_token`
- Parameter Usage Location: authorization request
- Change Controller: IETF
- Reference: this document, {{submission}}

- Name: `mission_expansion_status`
- Parameter Usage Location: authorization response
- Change Controller: IETF
- Reference: this document, {{reconciliation}}

- Name: `mission_denial_reason`
- Parameter Usage Location: authorization response
- Change Controller: IETF
- Reference: this document, {{denial-reasons}}; also carried by the
  child delegation profile
  ({{I-D.draft-mcguinness-oauth-mission-child-delegation}})

As with `mission_intent` in the issuance profile, PAR {{RFC9126}}
carries authorization-request parameters without a distinct usage
location, so the pushed submission of these parameters needs no
separate registration. `predecessor_token` carries a refresh
token and MUST be submitted only through PAR, never on a front-channel
authorization request ({{submission}}).

# Acknowledgments
{:numbered="false"}

The author thanks the reviewers of the Mission-Bound Authorization for
OAuth 2.0 profile for feedback on the expansion model and its
composition with the issuance flow.

--- back
