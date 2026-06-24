---
title: "Mission Expansion for OAuth 2.0"
abbrev: "OAuth Mission Expansion"
category: std

docname: draft-mcguinness-oauth-mission-expansion-latest
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
 - expansion
venue:
  github: "mcguinness/draft-mcguinness-oauth-mission"
  latest: "https://mcguinness.github.io/draft-mcguinness-oauth-mission/draft-mcguinness-oauth-mission-expansion.html"

author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com

normative:
  RFC9126:
  RFC9396:
  I-D.draft-mcguinness-oauth-mission:
    title: "Mission-Bound Authorization for OAuth 2.0"
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-oauth-mission-latest

informative:
  RFC8126:
  RFC9470:
  I-D.draft-mcguinness-oauth-mission-status:
    title: "Mission Status and Lifecycle for OAuth 2.0"
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-oauth-mission-status-latest
  I-D.draft-mcguinness-oauth-mission-runtime:
    title: "Mission-Bound Runtime Enforcement for OAuth 2.0"
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-oauth-mission-runtime-latest
  I-D.draft-mcguinness-oauth-mission-child-delegation:
    title: "Child Mission Delegation for OAuth 2.0"
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-oauth-mission-child-delegation-latest

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
linking it to the Mission it replaces; on the successor's activation
the predecessor enters a terminal `superseded` state. Expansion never
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
successor Mission; just-in-time expansion is named as future work.

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
  reconciliation status codes ({{reconciliation}});
- progressive authorization: a pre-consented authority ceiling and
  drawdown policy under which in-ceiling expansions are policy-adjudicated
  rather than freshly human-approved ({{progressive-authorization}}); and
- the expansion denial reasons ({{denial-reasons}}).

This document does NOT define:

- a way to widen an existing Mission in place; expansion always
  creates a new Mission;
- runtime per-action enforcement or the classification of a denial as
  expansion-eligible; that is the runtime layer's concern
  ({{eligibility}}, {{I-D.draft-mcguinness-oauth-mission-runtime}});
- branch expansion, in which predecessor and successor both remain
  active ({{replacement}}); or
- multi-hop or cross-domain expansion; an expansion is adjudicated by
  the predecessor's Mission Issuer (its `origin`).

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
     |                            | broader authority
     |    <-------- code --------- | -> successor active
     |                            |    -> predecessor
     |                            |       superseded (atomic)
     |                            |
     | 3. token request --------> | derive under successor
     |    <----- access token ---- | (mission.predecessor set)
     v
~~~

The shape is the issuance profile's own creation flow
({{I-D.draft-mcguinness-oauth-mission}}), with one addition at step 1:
the request is bound to the predecessor Mission's grant, so the
Mission Issuer adjudicates a successor of a specific predecessor rather
than an unrelated new Mission. The fresh consent at step 2 is what
supplies the broader authority; the successor's authority comes only
from this approval.

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
{{I-D.draft-mcguinness-oauth-mission-runtime}} is one source of an
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
and `context` the successor needs, including the authority the denied
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
  token, it MUST be sent only on the client-authenticated PAR back
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
the binding is established at the PAR submission, which is a
client-authenticated back-channel request. In the same PAR request that
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
its sender constraint. The refresh token is used here only to bind and
resolve the predecessor; the successor's authority still comes only
from the fresh consent at the approval event, never from authority the
binding token could itself derive.

Because expansion reuses the issuance profile's grant binding, it
needs no opaque expansion ticket or other new bearer: the predecessor
is identified and authorized by the grant the client already holds for
it, and a client cannot name an arbitrary predecessor.

## Predecessor must be active {#predecessor-active}

The Mission Issuer MUST resolve the predecessor from the presented
grant and verify it is in the `active` state before adjudicating. An
expansion request against a predecessor that is not `active` (it is
`revoked`, `expired`, or already `superseded`, {{superseded-state}})
MUST be refused with `invalid_grant` and the reconciliation status
`predecessor_state_changed` ({{reconciliation}}). Issuance gating in
the issuance profile already refuses to derive from a non-active
Mission; this rule extends the same gate to adjudicating an expansion
of one.

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
   Authority Set, satisfying any `context.acr`, and render the Subject
   when the Approver is not the Subject, per the issuance profile's
   approval event. The consent disclosure MUST reflect the successor's
   authority being adjudicated.
4. Compute the successor's integrity anchors (`intent_hash`,
   `authority_hash`) and create the successor Mission record in the
   `active` state, with its `predecessor` member set
   ({{predecessor-member}}), atomically with the predecessor's
   transition to `superseded` ({{superseded-state}}).

The expansion is governed by the consent obtained at step 3. Expansion
never widens authority without a new consent: if the Approver declines,
no successor is created and the predecessor is untouched
({{denial-reasons}}).

## Successor expiry {#successor-expiry}

The successor's `mission_expiry` MUST NOT exceed the predecessor's
`mission_expiry` unless the Mission Issuer's policy explicitly permits
extension and the extension is disclosed to the Approver at the
expansion consent event. Expansion is an authority-addition mechanism,
not a lifetime-extension mechanism. The issuance profile caps every
derived credential's `exp` at `mission_expiry`; a successor that
silently outlived its predecessor would let expansion launder a
longer-lived Mission past the originally approved horizon.

# Progressive Authorization {#progressive-authorization}

An open-ended agentic task often cannot have its full authority
enumerated at the initial approval, which leaves a deployment choosing
between over-provisioning a broad standing Mission and interrupting the
user for a fresh approval at every step. Progressive authorization is a
third option: the Approver consents once to a bounded envelope and a
rule for drawing authority from it, so authority can grow within the
envelope at runtime without a fresh human approval each time, while the
active authority any single Mission yields stays narrow.

At the initial approval event ({{I-D.draft-mcguinness-oauth-mission}}),
the Approver MAY additionally consent to:

- an **authority ceiling**: the maximum authority any expansion of this
  Mission may reach without a further human approval, expressed as an
  Authority Set, or as the `constraints` that bound one
  ({{I-D.draft-mcguinness-oauth-mission}}), that every in-ceiling
  successor MUST be a subset of; and
- a **drawdown policy**: the conditions under which the Mission Issuer
  MAY adjudicate an in-ceiling expansion by policy rather than by a
  fresh human approval.

Where present, the ceiling and drawdown policy are part of the Mission's
approved authority record and are covered by its `authority_hash`; the
consent disclosure MUST render the ceiling and the fact that in-ceiling
expansion is policy-adjudicated. A Mission that carries no ceiling has
no progressive authorization: every expansion of it is an ordinary,
freshly approved expansion.

## In-ceiling expansion {#in-ceiling-expansion}

An **in-ceiling expansion** is an expansion ({{adjudication}}) whose
successor Authority Set is a subset of the predecessor's consented
ceiling. When the predecessor consented to a drawdown policy that
authorizes the requested widening, the Mission Issuer MAY satisfy the
adjudication's approval event by policy rather than by a fresh human
approval, exactly as a parent Mission's Authority Set may permit
policy-approved child creation
({{I-D.draft-mcguinness-oauth-mission-child-delegation}}). The successor
is created as in {{adjudication}}: its Authority Set freshly derived and
bound by the ceiling, its `predecessor` member set, the predecessor
superseded.

This does not widen authority without consent ({{new-consent}}). The
consent is the human consent given at the initial approval to the
ceiling and the drawdown policy; policy adjudication only draws within
that pre-given consent and can never exceed the ceiling. The Mission
Issuer MUST refuse, with `out_of_ceiling` ({{denial-reasons}}), a
requested authority that is not a subset of the consented ceiling;
exceeding the ceiling requires a fresh human approval that raises it,
which is an ordinary expansion.

## What it bounds, and what it does not {#progressive-limits}

The ceiling is broad by construction, since it must cover the
open-ended task. What stays narrow is the active authority any single
Mission in the chain yields: each in-ceiling successor is derived for
the authority actually needed at that step and is independently gated
and revocable. A compromised agent cannot instantly wield the ceiling;
it can exercise only the current active authority and request in-ceiling
drawdown, which is policy-gated, recorded for audit ({{audit-linkage}}),
rate-limitable, and enforced per action by the runtime layer
({{I-D.draft-mcguinness-oauth-mission-runtime}}). Progressive
authorization bounds, and does not eliminate, standing-authority
exposure; a deployment SHOULD pair it with short successor lifetimes,
constraint-bounded ceilings, and runtime enforcement.

# The `predecessor` Member {#predecessor-member}

The successor records a lineage link to the predecessor as a
`predecessor` member, both on the successor's `mission` claim and on
the successor's Mission record.

The issuance profile's `mission` claim is an open object: additional
members MAY appear alongside `id`, `origin`, and `authority_hash`, each
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

Properties:

- **Cardinality.** A successor has at most one `predecessor`. An
  expansion chain is expressed by walking `predecessor` links from a
  successor back toward the original Mission.
- **Immutability.** `predecessor` is set at the successor's approval
  event and MUST NOT change thereafter; the Mission record is immutable
  except for its `state`.
- **Origin.** The predecessor and successor share an `origin`: an
  expansion is adjudicated by the predecessor's Mission Issuer. A
  consumer correlating a chain resolves each link at that origin.

Example successor `mission` claim on a derived token (non-normative;
other token claims omitted):

~~~ json
{
  "mission": {
    "id": "msn_2Yt7Qv9LqMv4z7sA2bN1k0YpEdHc9RfX",
    "origin": "https://as.example.com",
    "authority_hash":
      "sha-256:Td9bM7sX1cF8gH2vJ4kE5pNQl3KvZ4mP5x0wQrR6tY2",
    "predecessor": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-"
  }
}
~~~

# The `superseded` Predecessor State {#superseded-state}

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
| `active` | successor activates by expansion | `superseded` |

The transition has these requirements:

- **Atomic with successor activation.** The predecessor enters
  `superseded` in the same atomic operation that activates the
  successor ({{adjudication}}). If that operation fails, the
  predecessor remains `active` and no successor record exists; the
  Mission Issuer MUST NOT produce a partial successor or a predecessor
  left in an indeterminate state.
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
  offered, the composite `active` is `false` and, from the origin, the
  `mission.state` member gives `superseded`. Where the Mission Status
  profile {{I-D.draft-mcguinness-oauth-mission-status}} is deployed, the
  dedicated Status operation reports `superseded` among the terminal
  states and the Status Response `mission.state` gives `superseded`. A
  deployment that offers either surface and this document MUST include
  `superseded` among the lifecycle states its origin may report.
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
profile and MAY set that Mission's `predecessor` member to the original
Mission's `mission_id` to preserve lineage; doing so does not supersede
the original, which remains `active`. An atomic, grant-bound branch
expansion that creates such a child within a single expansion approval
event is deferred to a future revision of this document.

# Concurrent Expansion Reconciliation {#reconciliation}

More than one expansion request MAY be in flight against the same
predecessor at once. Because replacement produces exactly one successor
per predecessor ({{replacement}}), the Mission Issuer MUST serialize
adjudications against the same predecessor so that concurrent
expansions cannot each produce a successor.

The Mission Issuer MUST serialize expansion adjudications against the
same predecessor with compare-and-set semantics. At the moment of
adjudication, in the same atomic step that would activate the successor
and supersede the predecessor, the Mission Issuer MUST verify:

1. the predecessor resolved from the presented grant is still in the
   `active` state; and
2. no other replacement expansion has already produced a successor for
   this predecessor (equivalently, the predecessor has not already
   transitioned to `superseded`).

If either check fails, the Mission Issuer MUST refuse the request with
`invalid_grant` and the applicable reconciliation status from the
closed set below. The losing or otherwise stale expansion request is
rejected; it does not produce a second successor.

The reconciliation status codes are:

`superseded_by_concurrent_expansion`:
: A concurrent replacement expansion has already produced a successor;
  the predecessor is now `superseded` rather than `active`. The client
  SHOULD discover the existing successor and re-evaluate whether a
  further expansion is still required (an expansion of the successor is
  a new expansion against the successor as predecessor).

`predecessor_state_changed`:
: The predecessor transitioned out of `active` (to `revoked`,
  `expired`, or `superseded`) before this request could be
  adjudicated, including the cases caught at request binding
  ({{predecessor-active}}). The client MUST NOT retry the same
  expansion against this predecessor.

The two codes overlap in the `superseded` case by design:
`superseded_by_concurrent_expansion` is the specific reconciliation
outcome when the cause is a concurrent expansion that has already won,
and `predecessor_state_changed` is the general outcome for any other
exit from `active`. A Mission Issuer SHOULD return the specific code
when it can attribute the change to a concurrent expansion.

How the reconciliation status is conveyed to the client alongside the
`invalid_grant` error is a deployment matter; it MAY be carried in the
OAuth error response's `error_description` or an
implementation-defined member. This document defines the symbolic
codes and their meaning, not a wire location for them.

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

`out_of_ceiling`:
: The requested authority is not a subset of the Mission's consented
  authority ceiling ({{progressive-authorization}}), so it cannot be
  granted by policy drawdown; raising the ceiling requires a fresh human
  approval.

A Mission Issuer MUST NOT use a reason code to disclose policy
boundaries beyond the adjudicated request ({{policy-probing}}); omitting
the reason code is always permitted. As with reconciliation status, the
wire location of a reason code is a deployment matter.

Two failure classes are not denial reasons and use the issuance
profile's error vocabulary directly: an expansion request whose
`predecessor` does not match the grant-resolved Mission, or
whose predecessor is not `active`, fails with `invalid_grant`
({{request-binding}}, {{predecessor-active}}); an expansion Mission
Intent the Mission Issuer cannot parse or cannot derive a valid
Authority Set from fails with `invalid_request` or, where the issuance
profile uses it, `invalid_authorization_details` ({{RFC9396}}), exactly
as for any Mission creation.

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
- transition the predecessor to `superseded` atomically with successor
  activation, and refuse further derivation under a `superseded`
  Mission ({{superseded-state}}); and
- serialize concurrent expansions against the same predecessor with the
  reconciliation semantics of {{reconciliation}}.

An expansion-capable Mission Issuer is also a conforming issuance-profile
Mission Issuer ({{I-D.draft-mcguinness-oauth-mission}}); this document
adds the expansion surface to that role. A Resource Server requires no
new behavior: it enforces a successor's tokens exactly as it enforces
any Mission-bound token, and treats the `predecessor` member, if it
reads it at all, as audit context it MUST NOT use to grant authority
({{predecessor-member}}).

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
  `origin`.

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
- The successor's `mission_expiry` MUST NOT silently exceed the
  predecessor's ({{successor-expiry}}), so expansion cannot launder a
  longer lifetime past the originally approved horizon.

## Race against predecessor lifecycle {#lifecycle-race}

Between the moment a client decides to expand and the moment the
Mission Issuer adjudicates, the predecessor may be revoked, expire, or
be superseded by a concurrent expansion. Without serialization an
expansion could appear to succeed against a predecessor that is no
longer authoritative, or two successors could be created.

Mitigations:

- The Mission Issuer MUST verify predecessor state and the
  no-existing-successor condition in the same atomic step that would
  activate the successor ({{reconciliation}}), and serializes
  adjudications against the same predecessor.
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

- The Mission Issuer SHOULD rate-limit expansion requests per
  predecessor per client.
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
credential audience. The issuance profile's `mission_id` correlation
considerations apply to each Mission in the chain.

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

This document defines two closed sets of symbolic codes: the expansion
reconciliation status codes ({{reconciliation}}) and the expansion
denial reasons ({{denial-reasons}}). Like the issuance profile's
restraint with `mission` members, these are documented in this
specification rather than placed in new IANA registries: they are
conveyed inside existing OAuth error responses at deployment-defined
locations, not on a new wire surface, and the closed sets are small and
fully specified here. Should interoperable extension of either set
prove necessary, a future revision can create a "Mission Expansion
Reconciliation Status" registry and a "Mission Expansion Denial Reason"
registry with a Specification Required {{RFC8126}} policy; this document
does not create them.

This document registers two parameters in the "OAuth Parameters"
registry:

- Name: `predecessor`
- Parameter Usage Location: authorization request
- Change Controller: IETF
- Reference: this document, {{submission}}

- Name: `predecessor_token`
- Parameter Usage Location: authorization request
- Change Controller: IETF
- Reference: this document, {{submission}}

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
