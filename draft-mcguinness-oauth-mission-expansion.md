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
  RFC8693:
  RFC8705:
  RFC8785:
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
  RFC9562:
  I-D.draft-mcguinness-mission-harness:
    title: "Mission-Aware Agent Harnesses"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-harness.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-mission-authority-server:
    title: "Mission Authority Server"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-authority-server.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-gerber-oauth-deferred-token-response:
  I-D.draft-mcguinness-oauth-mission-approval:
    title: "Mission Deferred Approval for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-approval.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-oauth-mission-containment:
    title: "Mission Containment for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-containment.html
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
  I-D.draft-mcguinness-oauth-mission-continuation:
    title: "Mission Continuation: Authorization Continuity for Mission-Bound Authorization"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-continuation.html
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
defines that successor mechanism as an optional, layered extension to
the issuance profile. When an action falls outside an active Mission's
Authority Set but the deployment's governance policy permits widening,
a client initiates expansion through an {{RFC8693}} token exchange: it
presents the predecessor Mission's sender-constrained Mission-bound
access token as the `subject_token`, proving possession of the
predecessor's authority, and a fresh approval records a successor
Mission. The successor carries a `predecessor` member on its `mission`
claim linking it to the Mission it replaces; when the successor
activates the predecessor enters a terminal `superseded` state, so an
expansion that never completes leaves the predecessor active. Expansion
never widens authority without a new consent: the successor's authority
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

The mechanism reuses the issuance profile end to end. An expansion
carries a new Mission Intent in an {{RFC8693}} token exchange
({{expansion-request}}) bound to the predecessor by possession of the
predecessor's Mission-bound access token, leading to a fresh approval
event ({{I-D.draft-mcguinness-oauth-mission}}) with its own
integrity anchors and Mission record. The successor's
authority comes only from that approval. This document adds exactly
three things on top of the issuance profile: a way to bind an expansion
request to the predecessor it expands; a `predecessor` lineage member
on the resulting Mission; and a terminal `superseded` predecessor state
with the reconciliation rules that keep concurrent expansions
consistent.

## Status: an optional extension {#optional-status}

This document is optional. It is a layered extension to the issuance
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
: An {{RFC8693}} token exchange that carries a Mission Intent and
  presents the predecessor Mission's Mission-bound access token as the
  `subject_token`, asking the Mission Issuer to adjudicate a successor
  ({{expansion-request}}).

# Expansion Overview

## Protocol flow

~~~
 Agent (client)               Mission Issuer (AS)
     |                            |
     | denied: action outside     |
     | active Mission's authority |
     |                            |
     | 1. token exchange -------> | resolve predecessor from
     |    subject_token =         | subject_token; verify
     |    predecessor's Mission-  | possession (subject_token
     |    bound access token;     | cnf); gate predecessor
     |    mission_intent          | active
     |                            |
     |                            | 2. complete, one of:
     |                            |
     |    <-- authz_pending ----- | (a) deferred: fresh async
     |    ---- poll ------------> |     approval via DTR;
     |    <-- access token ------ |     token on approval
     |                            |
     |    <-- (front channel) --> | (b) interactive: the
     |                            |     deployment's front-
     |                            |     channel approval
     |                            |
     |         at activation: successor active,
     |         predecessor superseded (atomic)
     v
~~~

The request is an {{RFC8693}} token exchange bound to the predecessor
by possession of the predecessor's Mission-bound access token
({{expansion-request}}), so the Mission Issuer adjudicates a successor
of a specific predecessor rather than an unrelated new Mission. An
expansion always widens authority, so a fresh consent supplies the
broader authority, obtained through the deferred token response
({{I-D.draft-gerber-oauth-deferred-token-response}}) or the
deployment's interactive approval ({{completion-modes}}); a request
that widens nothing is refused ({{verification-order}}). The
successor's authority comes only from that consent. Supersession is
deferred to activation: the successor activates and the predecessor
becomes `superseded` atomically when the successor's authority is
issued, so an expansion that never completes leaves the predecessor
`active` ({{superseded-state}}).

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

# The Expansion Request {#expansion-request}

To expand a predecessor Mission, the requester MUST prove possession of
the predecessor Mission's authority through a sender-constrained proof,
and a reusable bearer refresh credential MUST NOT be the carrier of
that proof. This is the abstract requirement expansion rests on, stated
once and independent of any wire binding.

On the OAuth wire this document binds that requirement to an {{RFC8693}}
token exchange at the token endpoint ({{submission}}), in which the
predecessor's own sender-constrained Mission-bound access token is the
`subject_token` and possession is proven against that token's
confirmation key ({{request-binding}}). The Mission Authority Server
profile ({{I-D.draft-mcguinness-mission-authority-server}}) binds the
same abstract requirement to an authenticated-client submission on its
token-less surface; the two are peer bindings of one requirement.

## The token exchange request {#submission}

A client initiates an expansion as an {{RFC8693}} token exchange at the
token endpoint. The request carries:

`grant_type`:
: REQUIRED. `urn:ietf:params:oauth:grant-type:token-exchange`, the
  {{RFC8693}} token-exchange grant type.

`requested_token_type`:
: REQUIRED. `urn:ietf:params:oauth:token-type:access_token`. This value
  selects expansion: the Mission Issuer returns the successor's
  Mission-bound access token. Child creation, the peer operation on the
  same grant, is selected by the JWT token type
  ({{I-D.draft-mcguinness-oauth-mission-child-delegation}}).

`subject_token`:
: REQUIRED. The predecessor Mission's sender-constrained Mission-bound
  access token. The Mission Issuer resolves the predecessor from this
  token ({{request-binding}}); this token, not any identifier, selects
  the predecessor authoritatively.

`subject_token_type`:
: REQUIRED. `urn:ietf:params:oauth:token-type:access_token`. The
  Mission Issuer MUST reject any other value with `invalid_request`. A
  refresh token MUST NOT be accepted as the `subject_token` for an
  expansion: the possession proof is a sender-constrained access token,
  never a reusable bearer refresh credential.

`actor_token`:
: OPTIONAL. A token identifying the acting agent, per {{RFC8693}}.
  Where it is absent, the request's client authentication identifies
  the acting agent. This document carries the acting-agent identity; it
  does not restructure any act chain. A successor Mission begins its own
  act chain afresh under its own approval.

`actor_token_type`:
: REQUIRED when `actor_token` is present, per {{RFC8693}}.

`mission_intent`:
: REQUIRED. The successor's Mission Intent, per
  {{I-D.draft-mcguinness-oauth-mission}}. It describes the broadened
  task: the `goal`, `resources`, `constraints`, and `controls` the
  successor needs, including the authority the denied action required.
  The Mission Issuer derives the successor's Authority Set from this
  Intent and bounds it by policy exactly as for any Mission; this
  document adds no authority-derivation rule.

`authorization_details`:
: OPTIONAL. The successor's authority proposal: the standard
  {{RFC9396}} parameter carried on the same token request, itself
  ordinary {{RFC9396}} token-request usage. This parameter is this
  exchange's proposal carriage, replacing the issuance profile's
  PAR-only carriage rule; that profile's validation, derivation,
  recording, and hashing semantics apply unchanged
  ({{I-D.draft-mcguinness-oauth-mission}}). It is a proposal, never
  authority: the Mission Issuer derives and bounds the successor's
  Authority Set by policy regardless of what was proposed. A
  successor created from an exchange carrying one records
  `proposed_authority` and `proposal_hash`.

`predecessor`:
: OPTIONAL. A string. The `mission_id` of the predecessor, a
  non-authoritative cross-check and audit value only. The Mission Issuer
  resolves and selects the predecessor from `subject_token`
  ({{request-binding}}); when `predecessor` is present the Mission
  Issuer MUST verify it names that same resolved Mission and refuse a
  mismatch with `invalid_grant`. `predecessor` does not select or
  authorize a predecessor: a client MUST NOT be able to expand a Mission
  merely by naming its `mission_id`.

`creation_request_id`:
: REQUIRED. The creation idempotency identifier: an ASCII string of at
  most 255 octets, opaque to the Mission Issuer beyond equality, that
  identifies this one Mission-creation operation across every
  completion mode ({{creation-idempotency}}). At least 128 bits of
  client-generated randomness is RECOMMENDED; a UUID {{RFC9562}}
  satisfies this. The Mission Issuer MUST refuse an exchange missing
  it with `invalid_request`.

The presence of `mission_intent` on a token exchange marks it as a
Mission-creation exchange under this suite; an exchange whose
`subject_token` resolves to a Mission and that carries no `child_actor`
is an expansion. A token exchange carrying both a `predecessor`
cross-check and the child-delegation profile's `child_actor`
({{I-D.draft-mcguinness-oauth-mission-child-delegation}}) MUST be
refused with `invalid_request`: the operations do not combine.

The possession proof of {{request-binding}} is presented only on the
token endpoint's authenticated back channel and MUST NOT appear on any
front channel. Where a deployment completes an expansion through its
retained interactive approval ({{completion-modes}}), the front-channel
approval ceremony carries only the consent decision; the predecessor
binding and possession proof are established by the token exchange in
every completion mode.

## Proving possession of the predecessor {#request-binding}

The issuance profile resolves a Mission from the credential the client
presents, never from a client-supplied `mission_id`
({{I-D.draft-mcguinness-oauth-mission}}, grant binding). An expansion
resolves the predecessor from the `subject_token` the client presents
and proves possession against that token's own confirmation:

1. The Mission Issuer MUST resolve the predecessor Mission from
   `subject_token`, applying the issuance profile's token-to-Mission
   resolution for a Mission-bound access token.
2. The Mission Issuer MUST verify that the presenter controls the
   `subject_token`'s own confirmation key: a {{RFC9449}} DPoP proof
   whose key matches the token's `cnf` `jkt`, or the {{RFC8705}}
   mutual-TLS certificate whose thumbprint matches the token's `cnf`
   `x5t#S256`. Possession is proven against the token's confirmation, a
   sender-constrained proof; it is not read from any Mission-record
   field. A `subject_token` that is not sender-constrained cannot carry
   this proof, so the Mission Issuer MUST refuse it with
   `invalid_request`.
3. Where the proof is a DPoP proof, its `jti` is single-use per
   {{RFC9449}}: the Mission Issuer MUST reject a replayed proof.
4. When `predecessor` is present, the Mission Issuer MUST verify the
   resolved Mission is the one it names ({{submission}}).

The confirmation key, not the identifier, authorizes the expansion. A
client that does not hold the predecessor's Mission-bound access token
and its sender-constraint key cannot present a valid `subject_token`
and so cannot expand the predecessor. Establishing this at the token
exchange, before any approval, means the Mission Issuer confirms the
predecessor is real, active, and possessed before prompting an Approver,
so expansion cannot drive approval prompts against another party's
Mission.

Stated as the eligibility rule rather than a consequence: this
profile's expansion requires a sender-constrained Mission-bound access
token to present, and a deployment that issues only bearer tokens for a
Mission, or none, forgoes it. Nothing else is lost. Succession stays
reachable through a fresh approval, a new Mission whose disclosure
references the work it continues, since the successor's authority comes
only from the fresh consent in any case; and the Subject or an
administrator acts on the predecessor at the management plane
regardless, whose standing is the authenticated principal, never a
token's possession ({{I-D.draft-mcguinness-oauth-mission-status}}). The
possession proof gates the proposal channel (who may put an expansion
wearing this predecessor's name in front of the Approver, and who may
trigger the atomic supersession), never the authority: no proof failure
can widen anything.

The Mission Issuer MUST record each expansion presentation and count it
toward the deployment's anomaly detection, and the per-predecessor rate
limit ({{policy-probing}}) applies unconditionally. Because the
`subject_token` is a short-lived, sender-constrained access token rather
than a reusable refresh credential, presenting it for expansion carries
no refresh rotation or replay-detection interaction: it is consumed only
to resolve and bind the predecessor, never to refresh.

Because expansion binds to the predecessor's Mission-bound access token,
it needs no opaque expansion ticket or other new bearer: the predecessor
is identified and authorized by a credential the client already holds
and can prove possession of, and a client cannot name an arbitrary
predecessor.

## Predecessor must be active {#predecessor-active}

The Mission Issuer MUST resolve the predecessor from `subject_token`
and verify it is in the `active` state before adjudicating, and MUST
re-verify it at completion when adjudication is deferred or interactive
({{deferred-window}}). An expansion request against a predecessor that
is not `active` MUST be refused with `invalid_grant` and a
reconciliation status ({{reconciliation}}):

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

Adjudication of an expansion derives the successor's Authority Set from
the submitted Mission Intent and bounds it by policy, exactly as for any
Mission. The successor's authority is whatever this derivation and the
completion of {{completion-modes}} yield; it is not the predecessor's
authority plus a delta computed by this document. A deployment that
wants the successor to retain the predecessor's authority expresses that
authority in the expansion Mission Intent so the derivation reproduces
it.

The Mission Issuer processes an expansion token exchange in the
verification order of {{verification-order}} and completes it in one of
the modes of {{completion-modes}}.

## Mission Issuer verification order {#verification-order}

The Mission Issuer MUST evaluate an expansion token exchange in this
order, refusing on the first failure:

1. Parse the exchange, require `subject_token` with
   `subject_token_type` = `urn:ietf:params:oauth:token-type:access_token`,
   rejecting a refresh token, and require `creation_request_id`
   ({{submission}}).
2. Resolve the predecessor Mission from `subject_token`
   ({{request-binding}}).
3. Verify possession: the presenter controls the `subject_token`'s own
   confirmation key ({{RFC9449}} DPoP proof `jkt`, or {{RFC8705}} mTLS
   `x5t#S256`), and, for a DPoP proof, the proof `jti` is single-use
   ({{request-binding}}).
4. Verify the acting agent (`actor_token`, or the request's client
   authentication) is authorized to request expansion of this
   predecessor.
5. Look up the `(client, creation_request_id)` reservation and, where
   one exists, recover the recorded operation instead of proceeding
   ({{creation-idempotency}}). The lookup follows client
   authentication and possession verification and precedes the
   predecessor lifecycle gate of step 6 ({{creation-revalidation}}).
6. Verify the predecessor is `active` ({{predecessor-active}}) and,
   when `predecessor` is present, that it names the resolved Mission.
7. Derive the successor's Authority Set under policy from the
   submitted Mission Intent ({{adjudication}}) and verify that it
   widens the predecessor: when the derived requested authority is a
   subset of the predecessor's own effective Authority Set, refuse the
   exchange with the `nothing_to_expand` denial reason, as there is
   nothing to expand ({{denial-reasons}}).
8. Complete per {{completion-modes}}; at a deferred or interactive
   completion, re-verify the predecessor's Mission state before issuing
   ({{deferred-window}}).

On any failure the Mission Issuer MUST refuse with `invalid_request`,
`invalid_grant`, or `invalid_token` as appropriate, and MUST NOT create
a successor.

The predecessor's **effective Authority Set**, the right-hand side of
step 7's subset test, is its approved Authority Set as reduced by the
overlays the deployment runs: authority removed by the containment
profile's issuer-held overlay
({{I-D.draft-mcguinness-oauth-mission-containment}}) and entries
discharged under the Mission Status profile's completion machinery
({{I-D.draft-mcguinness-oauth-mission-status}}) are not in it. Where
neither profile is deployed, the effective set is the approved set.

Authority the predecessor once held but containment or discharge has
removed is therefore never `nothing_to_expand`: a request for it
widens the effective set and is expansion-eligible. Such authority
returns only through a fresh-consent successor, with the
predecessor's containment history surfaced in the expansion consent
disclosure ({{completion-modes}},
{{I-D.draft-mcguinness-oauth-mission-containment}}), never by
re-deriving under the predecessor.

## Completion modes {#completion-modes}

An expansion completes in one of two modes, each obtaining the fresh
approval the successor's authority requires. The deferred token
response is a completion mode, not a replacement: both modes rest on
the same possession-proven token exchange ({{expansion-request}}), and
the interactive path is retained.

Deferred:
: When approval is asynchronous, the Mission Issuer returns the
  deferred token response of the family's Mission Deferred Approval
  substrate
  ({{I-D.draft-gerber-oauth-deferred-token-response}}, profiled for
  Missions by {{I-D.draft-mcguinness-oauth-mission-approval}}):
  `authorization_pending` with a polling `interval`. The Approver acts
  on the deployment's asynchronous review surface; the client polls;
  the poll resolves to the successor's access token on approval, or to
  `access_denied` or `expired_token`. This document references that
  substrate and does not redefine it.

Interactive:
: When approval is interactive, the Mission Issuer runs the
  deployment's existing front-channel approval event, the
  issuance profile's own approval ceremony
  ({{I-D.draft-mcguinness-oauth-mission}}), issuing an authorization
  code the client redeems to obtain the successor's authority. This is
  the interactive path retained from earlier revisions of this document.

This document defines no synchronous exchange completion. An expansion
response is a successor or a refusal, never a token derived under the
predecessor: a request whose derived authority is a subset of the
predecessor's own effective Authority Set is refused with
`nothing_to_expand` ({{verification-order}}, {{denial-reasons}}).
Policy-adjudicated expansion within a pre-consented authority ceiling
is the experimental progressive authorization companion's concern
({{I-D.draft-mcguinness-oauth-mission-progressive}}): an in-ceiling
drawdown completes through the retained interactive path with the
approval prompt skipped, as that companion defines.

Whichever mode completes, obtaining the fresh approval means the Mission
Issuer authenticates the Approver, obtains fresh consent for the
derived Authority Set, satisfies any `controls.acr`, and renders the
Subject when the Approver is not the Subject, per the issuance profile's
approval event. The consent disclosure MUST reflect the successor's
authority being adjudicated. Expansion never widens authority without a
new consent: if the Approver declines, no successor is created and the
predecessor is untouched ({{denial-reasons}}).

At completion the Mission Issuer computes the successor's integrity
anchors (`intent_hash`, `authority_hash`, and, where the exchange
carried an authority proposal, `proposal_hash`) and, at the point the
successor's authority is issued (the resolving poll for a deferred
completion, or the code redemption for an interactive completion),
creates the successor Mission record in the `active` state, with
its `predecessor` member set
({{predecessor-member}}), atomically with the predecessor's transition
to `superseded` ({{superseded-state}}). Until the successor activates
the predecessor remains `active`; an expansion that never completes,
whose deferred approval lapses, or whose authorization code is never
redeemed or expires, creates no successor and leaves the predecessor
`active`.

Whichever mode is selected, the exchange's `creation_request_id`
reservation ({{creation-idempotency}}) makes completion recoverable:
a client that loses the response recovers the one committed
operation, never a second creation.

## The deferred window {#deferred-window}

A completion may occur later than the request, across a deferred or
interactive approval window. Two rules govern that window:

- The predecessor's Mission state MUST be re-verified at issuance
  (completion), not only at request time. A predecessor that was
  terminated or contained during the window MUST fail completion, per
  the compare-and-set of {{reconciliation}}. This preserves the
  new-derivation kill a terminal predecessor state effects: a deferred
  approval MUST NOT become a bypass of it.
- Expiry of the `subject_token` during the window MUST NOT gate
  completion. The predecessor binding and the possession proof are
  evaluated and recorded at request time ({{request-binding}}); the
  short-lived `subject_token` expiring while approval is pending does
  not invalidate the pending exchange. The re-verification above is of
  the predecessor's Mission state, not of the expired token.

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
  that was not created by expansion. It links the successor to the
  Mission it replaced so that the expansion chain is observable in
  audit.

The same `predecessor` value is recorded on the successor's immutable
Mission record so that the lineage is durable independently of any
derived token.

This document defines two further lineage members:

`related_to`:
: OPTIONAL. A string. The `mission_id` of a Mission this Mission is
  related to by lineage without superseding it, used for a non-superseding
  link such as a branch ({{replacement}}). Unlike `predecessor`, its
  presence does not imply that the referenced Mission was superseded and
  it carries no lifecycle consequence.

`successor`:
: OPTIONAL. A string. The `mission_id` of the successor that superseded
  this Mission by expansion, recorded on the superseded predecessor's
  Mission record at supersession ({{superseded-state}}). It is the
  reverse of the successor's `predecessor` link, letting a consumer that
  holds a superseded predecessor discover its successor directly.
  The Status profile surfaces it in the status response
  ({{I-D.draft-mcguinness-oauth-mission-status}}) and the Signals profile
  in the superseded lifecycle event
  ({{I-D.draft-mcguinness-oauth-mission-signals}}).

`predecessor`, `related_to`, and `successor` are lineage and audit
context only. Consistent with the issuance profile's
open-`mission`-claim rule, each of them MUST NOT grant or widen
authority, and a consumer that does not understand one MUST ignore it.
The successor's authority comes only from its own `authority_hash`,
never from its predecessor.

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
| `active` | successor activates when its authority is issued | `superseded` |

The transition has these requirements:

- **Atomic with successor activation.** The successor activates, and the
  predecessor enters `superseded`, in one atomic operation at the point
  the successor's authority is issued ({{completion-modes}}: the
  resolving deferred poll or the interactive code redemption), not at
  the approval decision that precedes it. In that same operation the
  Mission Issuer sets the predecessor's
  `successor` member to the successor's `mission_id`
  ({{predecessor-member}}). Until the successor activates the
  predecessor remains `active`.
  - An expansion that never completes, whose deferred approval lapses,
    or whose authorization code is never redeemed or expires, activates
    no successor and leaves the predecessor `active`, so it never
    strands the task's authority nor cascade-terminates the
    predecessor's Child Missions.
  - If the atomic operation fails, the predecessor remains `active`
    and no successor record exists. The Mission Issuer MUST NOT
    produce a partial successor or a predecessor left in an
    indeterminate state.
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
  invalidate access tokens already issued.
  - These tokens MUST NOT be silently rebound to the successor.
    Authority under the successor is obtained only by deriving from
    the successor's grant, which is a new derivation governed by the
    successor's Authority Set.
  - A deployment that needs a lower cutoff latency on the
    predecessor's outstanding tokens SHOULD use short token lifetimes.
    It MAY additionally revoke the predecessor's refresh token where
    the issuance profile's optional revocation composition is in use.
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

# Continuing Under an Independently Approved Mission {#independent-continuation}

A deployment can end one Mission and continue the work under another
without this document's expansion protocol: it approves an ordinary
new Mission under the issuance profile and explicitly revokes the
prior Mission. This is independent continuation, an operational
pattern; it is not expansion, succession, or replacement in the
protocol sense, and none of this document's `predecessor`,
`successor`, or `superseded` semantics apply.

The two commits are independent, and the pattern's properties follow
from that:

- both Missions are normally `active` for an interval; revoking first
  instead opens an availability gap if the new approval fails;
- revocation can fail or be omitted, leaving both active until the
  prior Mission's own lifecycle ends it;
- the prior Mission's outstanding tokens retain their ordinary
  residual lifetime, and no credential is rebound: authority under
  the new Mission is obtained only by fresh derivation from it;
- revoking the prior Mission terminal-cascades its Child Missions,
  and continuing child work requires fresh Child Mission creation
  under the new Mission
  ({{I-D.draft-mcguinness-oauth-mission-child-delegation}});
- a harness applies its ordinary stop behavior to the revoked
  Mission; the supersession continuation handoff does not apply
  ({{I-D.draft-mcguinness-mission-harness}}); and
- nothing serializes concurrent continuations, no exactly-one
  guarantee exists, and the new approval is not grant-bound to the
  prior Mission.

A deployment MAY record the relationship as `related_to` on the new
Mission ({{predecessor-member}}). `related_to` is issuer-recorded
correlation metadata, not client-asserted authority: this document
defines no client request parameter for it, and `mission_intent` is
task-only; the input that causes it to be recorded is authenticated
and authorized under the Mission Issuer's management or local policy.
The Mission Issuer MUST authorize and resolve the reference, in its
own namespace, before the new Mission's approval completes (a
cross-issuer relationship requires a structured extension); MUST set
`related_to` atomically when the Mission record is created; and MUST
NOT add or change it afterward. An unresolved or unauthorized
reference is never recorded: deployment policy either rejects the
creation uniformly or proceeds without the relationship, applied
consistently across requests, and neither behavior discloses whether
the referenced Mission exists. The member asserts related work only,
neither mutual recognition nor replacement.

A Mission created this way MUST NOT carry the `predecessor` member,
which asserts the supersession semantics only replacement expansion
provides. Independent continuation does not satisfy any profile that
requires a successor: containment restoration in particular requires
the `predecessor` link and the disclosed history that expansion's
approval renders.

# Concurrent Expansion Reconciliation {#reconciliation}

More than one expansion request MAY be in flight against the same
predecessor at once, and more than one MAY be adjudicated and awaiting
its completion. Because replacement produces exactly one successor per
predecessor ({{replacement}}) and supersession is deferred to
activation ({{superseded-state}}), the Mission Issuer MUST serialize the
completions that would activate a successor of the same predecessor, so
that concurrent expansions cannot each activate one.

The Mission Issuer MUST apply compare-and-set semantics at successor
activation ({{completion-modes}}). This is the completion-side
re-verification of the deferred window ({{deferred-window}}). In the
same atomic step that would activate the successor and supersede the
predecessor, the Mission Issuer MUST verify:

1. the predecessor is still in the `active` state; and
2. no other replacement expansion has already activated a successor for
   this predecessor (equivalently, the predecessor has not already
   transitioned to `superseded`).

If either check fails, the Mission Issuer MUST refuse the completion
with `invalid_grant` and the applicable reconciliation status from the
closed set below. The losing or otherwise stale expansion is rejected
at completion; it activates no successor.

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
  compare-and-set on successor activation ({{reconciliation}}). The
  client MUST NOT retry the same expansion against this predecessor.

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
  failed. At the token endpoint, on the token exchange response and on
  a deferred token response poll ({{completion-modes}}), it is a member
  of the JSON error response body, alongside the OAuth `error` member.
  On the retained interactive path's front-channel authorization error
  response, which carries error parameters rather than a JSON body, it
  is carried as an error response parameter of the same name.
  Adjudication denial reasons ride the separate `mission_denial_reason`
  member ({{denial-reasons}}).

# Creation Idempotency {#creation-idempotency}

A `creation_request_id` identifies one Mission-creation operation
across every completion mode. The Mission Issuer MUST durably bind
the authenticated client, the identifier, the operation fingerprint
({{creation-fingerprint}}), and the resulting continuation or
successor Mission, atomically with the creation decision. Repetition
of the exchange recovers that operation ({{creation-recovery}}); it
MUST NOT repeat Mission creation or any creation-side effect:
creation accounting, creation lifecycle events, evidence emission.

The identifier is REQUIRED in every completion mode because the
client cannot know in advance which mode the Mission Issuer will
select, and because the existing single-use artifacts do not close
the retry fault. DPoP proof `jti` single-use ({{request-binding}})
prevents replay of one captured proof; a client that loses the
response retries with a fresh, valid proof, and without the
identifier that retry is a second creation. The retained interactive
path's single-use artifacts prevent only duplicate redemption within
one ceremony; the reservation made at initiation is what prevents a
retry from starting a second ceremony ({{creation-recovery}}).

The child delegation profile
({{I-D.draft-mcguinness-oauth-mission-child-delegation}}) carries the
same parameter with the same semantics on its child-creation
exchange, as `mission_denial_reason` is shared across the profiles
that mint a Mission related to an existing one ({{denial-reasons}}).
Delegation-family-creating exchanges adopt the same definitions by
reference, each under its own domain-separating `op` value
({{creation-fingerprint}}); the continuation profile's
async-delegation exchange does so
({{I-D.draft-mcguinness-oauth-mission-continuation}}).

## The operation fingerprint {#creation-fingerprint}

The operation fingerprint commits what the operation is, so a
repeated identifier is distinguishable from a reused one. It is
computed as an issuance-profile integrity anchor
({{I-D.draft-mcguinness-oauth-mission}}) whose `typ` is
`mission-creation-fingerprint`, under that profile's
collision-resistant `typ` convention, and whose committed value is
the object below: the anchor envelope is canonicalized with JCS
{{RFC8785}}, hashed with SHA-256, and encoded as `sha-256:` followed
by the base64url, no-padding, encoding of the digest, exactly as for
the profile's other anchors.

The fingerprint object carries exactly these members:

`op`:
: `expansion` for this document's exchange; `child-creation` for the
  child delegation profile's. This member domain-separates the two
  operations that share the token-exchange grant.

`iss`:
: The Mission Issuer's issuer identifier.

`client`:
: The authenticated client identifier.

`source`:
: The `mission_id` of the source Mission resolved from
  `subject_token` ({{request-binding}}): the predecessor here, the
  parent under child delegation. The resolved identifier is the
  member, never the raw `subject_token`, since a legitimate retry
  may carry a newly issued token for the same Mission, and never the
  optional cross-check alone, which is non-authoritative.

`cnf`:
: The verified presenter confirmation: the DPoP proof key's `jkt`,
  or the mTLS certificate's `x5t#S256` ({{request-binding}}).

`actor`:
: The verified acting-agent identity, with its relevant actor
  context, where the exchange carries one (`actor_token`); absent
  where client authentication alone identifies the acting agent.

`intent`:
: The parsed `mission_intent` object.

`proposal`:
: The parsed `authorization_details` array, when present.

`child_actor`:
: The parsed `child_actor` object; child creation only, absent on an
  expansion.

`requested_token_type`:
: The exchange's `requested_token_type` value.

`cross_check`:
: The supplied `predecessor` value (under child delegation, the
  supplied `parent` value), when present.

An extension that defines a new parameter affecting the
authorization, derivation, approval, output, or side effects of the
creation MUST extend the fingerprint object with it. Attempt-specific
material is excluded: the DPoP proof serialization and its `jti`, the
client-authentication assertion serialization, the raw
`subject_token` serialization, and `creation_request_id` itself.

## The durable reservation {#creation-reservation}

A reservation is the durable record binding the authenticated client,
the `creation_request_id`, and the fingerprint. It is created in a
`reserved` state and moves to `completed` or `failed`. The
`(client, creation_request_id)` pair is unique, and the store MUST
enforce that uniqueness as a constraint; a read-before-insert check
without one does not withstand concurrent retries.

The reservation and the created Mission's identifier MUST be
committed atomically with Mission creation; credential generation MAY
follow the commit. This closes the crash window: when the Mission
commits and the Mission Issuer fails before responding, the retry
finds the committed operation and resumes delivery
({{creation-recovery}}), never creating again.

A repeated presentation of the same `(client, creation_request_id)`
resolves by fingerprint:

- same fingerprint, operation completed: recover it
  ({{creation-recovery}});
- same fingerprint, operation reserved or pending: return the same
  continuation, or a retryable in-progress result;
- different fingerprint: refuse with `invalid_request`. The
  identifier was reused for a different operation.

## Recovery is delivery {#creation-recovery}

The Mission Issuer stores the operation's stable outcome, never its
serialized response: the completion mode with its continuation
handle, or the created Mission's identifier with its
delivery-artifact metadata. A revalidated retry
({{creation-revalidation}}) recovers that outcome:

- A pending deferred completion returns the same deferral: the same
  `(client, creation_request_id)` resolves to the same deferred
  continuation, scoped to the authenticated client, never to a
  second deferral.
- A pending interactive completion returns the same continuation
  reference. The reservation is made at initiation, so a retry
  cannot start a second approval ceremony.
- A completed operation whose delivery credential is still valid
  returns that credential.
- A completed operation whose delivery credential has expired is
  recovered by minting a fresh delivery credential for the
  already-created successor, provided that successor remains
  `active` and the requester re-establishes the recorded
  authorization context ({{creation-revalidation}}). The fresh
  credential is a delivery event with ordinary issuance accounting;
  it MUST NOT repeat creation accounting: no second creation
  lifecycle event, no second evidence emission, no second count
  against any creation budget.

Recovery never re-creates. Whatever the outcome tier, a recovered
operation yields the Mission the operation already created, or the
continuation it already opened, and nothing else.

## Revalidation and lookup order {#creation-revalidation}

A matching `creation_request_id` never bypasses authentication or
possession. Before recovering anything, the Mission Issuer MUST
establish:

- the same authenticated client;
- the recorded source Mission;
- the same authorized acting agent;
- possession of the recorded sender-constraint identity, the stored
  `cnf` of {{creation-fingerprint}}; and
- fingerprint compatibility ({{creation-reservation}}).

No key-rotation recovery path is defined: a requester that can no
longer prove possession of the recorded `cnf` does not recover the
operation.

The idempotency lookup occurs after client authentication and
possession verification and before the predecessor lifecycle gate
({{verification-order}}). The order is load-bearing: the retry worth
recovering is exactly the one whose predecessor transitioned to
`superseded` when the first attempt succeeded
({{superseded-state}}), so re-running the predecessor-active gate
first would refuse the very recovery this mechanism exists to serve.

## Tombstone retention {#creation-retention}

Retention has two tiers. The full delivery-artifact record MAY be
retained briefly. The idempotency tombstone, the
`(client, creation_request_id)` binding with its fingerprint and its
Mission or continuation reference, MUST survive at least the
deployment's published retry horizon, and retention to the source or
created Mission's lifetime, or to the deployment's audit horizon, is
RECOMMENDED. The retry horizon is a published deployment bound, like
the deployment's other operational bounds. A client MUST NOT retry a
creation past the published horizon: reuse of an identifier after
its tombstone expires is outside the contract and is processed as a
new operation.

# Expansion Denial Reasons {#denial-reasons}

An adjudication that completes with the Approver declining, or with the
Mission Issuer refusing on policy grounds, denies the expansion: no
successor is created and the predecessor remains `active` and
untouched. Such a denial surfaces per the completion mode
({{completion-modes}}): as an OAuth error on the token exchange response
(typically `invalid_request` for a request the Mission Issuer will not
derive a valid Authority Set from), as the deferred substrate's
`access_denied` resolution on a deferred poll, or through the
interactive approval's own decline path. It MAY additionally carry one
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

`nothing_to_expand`:
: The derived requested authority is a subset of the predecessor's own
  effective Authority Set, so there is nothing to expand: ordinary
  token derivation under the predecessor already serves the request
  ({{verification-order}}). This refusal surfaces on the token exchange
  response itself, as `invalid_request`, and MUST carry this reason
  code; it is never answered with a token derived under the
  predecessor, so an expansion response is never ambiguously a
  non-successor.

A companion profile MAY extend this set by specification (the
experimental progressive authorization companion defines
`out_of_ceiling`, {{I-D.draft-mcguinness-oauth-mission-progressive}});
a consumer MUST treat an unrecognized reason code as a denial with no
further semantics.

A Mission Issuer MUST NOT use a reason code to disclose policy
boundaries beyond the adjudicated request ({{policy-probing}});
omitting the reason code is always permitted, with one exception:
`nothing_to_expand` MUST be carried on its refusal. It reveals only
that the requester already holds the requested authority, which the
requester can observe from its own token, so the policy-probing
rationale for omission does not apply ({{policy-probing}}); carrying
it keeps a non-widening refusal distinguishable from a policy denial.
When present, a reason code is carried in a
`mission_denial_reason` member: at the token endpoint, on
the token exchange response and on a deferred token response poll, a
member of the JSON error response body alongside the OAuth `error`
member; on the retained interactive path's front-channel authorization
error response, an error response parameter of the same name.

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
`predecessor` cross-check does not match the `subject_token`-resolved
Mission, or whose predecessor is not `active`, fails with
`invalid_grant` ({{request-binding}}, {{predecessor-active}}); an
expansion Mission
Intent the Mission Issuer cannot parse or cannot derive a valid
Authority Set from fails with `invalid_request` or, where the issuance
profile uses it, `invalid_authorization_details` ({{RFC9396}}), exactly
as for any Mission creation.

# Worked Example {#example}

The Q3 reconciliation Mission
`msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-` authorizes reading invoices and
posting journal entries under $500. Mid-task the agent finds an
adjustment of $1,200, outside the active Mission's authority. It cannot
widen in place; it requests an expansion as a token exchange presenting
the predecessor's Mission-bound access token as the `subject_token`,
proving possession with a DPoP proof over the token's confirmation key:

~~~ http
POST /token HTTP/1.1
Host: as.example.com
Content-Type: application/x-www-form-urlencoded
DPoP: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2Iiwi...

grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange&
requested_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&
subject_token=<predecessor%20Mission-bound%20access%20token>&
subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&
mission_intent=%7B...journal-entries%20cap%20%242000...%7D&
predecessor=msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-&
creation_request_id=7c9e6679-7425-40de-944b-e07fc1f90ae7&
client_id=s6BhdRkqt3
~~~

The Mission Issuer resolves the predecessor from `subject_token`,
verifies the presenter controls the token's confirmation key, confirms
the `predecessor` cross-check names that Mission and that it is
`active`, and derives the successor's Authority Set. The widening
requires fresh consent and the deployment approves asynchronously, so
the Mission Issuer returns a deferred token response;
`alice` approves the widened cap on the review surface, and the client's
next poll delivers the successor's access token. At that issuance the
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
Mission Issuer role, under one of two targets: as an
expansion-capable Mission Issuer when it adjudicates expansion, or
under the optional `related_to` correlation target below.

A Mission Issuer that records `related_to` without adjudicating
expansion conforms to the **`related_to` correlation** target when it
meets every rule of {{independent-continuation}}: authenticated and
authorized input, pre-approval resolution, creation-time atomic
recording, immutability, consistent non-disclosing failure behavior,
and no `predecessor` member. Nothing else in this section applies to
that target.

A conforming **expansion-capable Mission Issuer** MUST:

- accept an {{RFC8693}} token exchange whose `subject_token` is the
  predecessor's Mission-bound access token, with `subject_token_type`
  of `access_token`, treating it as an expansion ({{submission}}), and
  reject a refresh token as the `subject_token`;
- resolve the predecessor from `subject_token`, verify possession
  against the token's own confirmation key, refuse a `predecessor`
  cross-check that does not match the resolved Mission or a predecessor
  that is not `active` with `invalid_grant`, and evaluate the request in
  the verification order of {{verification-order}}
  ({{request-binding}}, {{predecessor-active}});
- require a `creation_request_id` on every expansion exchange,
  refusing a missing one with `invalid_request`, and recover a
  repeated one under the reservation, recovery, revalidation, and
  retention rules of {{creation-idempotency}};
- refuse an exchange whose derived requested authority is a subset of
  the predecessor's own effective Authority Set, carrying the
  `nothing_to_expand` denial reason ({{verification-order}},
  {{denial-reasons}});
- complete the expansion in one of the modes of {{completion-modes}},
  obtaining new consent for the successor's authority through the
  deferred token response or the retained interactive approval
  ({{adjudication}}) and enforcing the successor-expiry rule
  ({{successor-expiry}});
- record the `predecessor` member on the successor's `mission` claim
  and Mission record ({{predecessor-member}});
- activate the successor and transition the predecessor to `superseded`
  atomically when the successor's authority is issued, leaving the
  predecessor `active` until then, re-verifying predecessor state at
  completion ({{deferred-window}}), and refuse further derivation under
  a `superseded` Mission ({{superseded-state}}); and
- serialize concurrent expansions against the same predecessor with the
  reconciliation semantics of {{reconciliation}}.

An expansion-capable Mission Issuer is also a conforming issuance-profile
Mission Issuer ({{I-D.draft-mcguinness-oauth-mission}}); this document
adds the expansion surface to that role. A Resource Server requires no
new behavior: it enforces a successor's tokens exactly as it enforces
any Mission-bound token, and treats the `predecessor` member, if it
reads it at all, as audit context it MUST NOT use to grant authority
({{predecessor-member}}).

Every expansion this document defines is adjudicated as a fresh
approval event ({{adjudication}}). The experimental progressive
authorization companion defines a further OPTIONAL capability,
**Expansion with Progressive Authorization**, with its own conformance
requirements ({{I-D.draft-mcguinness-oauth-mission-progressive}}).

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

- The predecessor is resolved from the `subject_token` the client
  presents, not from the `predecessor` value, and possession is proven
  against that token's own confirmation key; the Mission Issuer verifies
  that the resolved Mission matches the named one and refuses a mismatch
  with `invalid_grant` ({{request-binding}}). A client that does not
  hold the predecessor's Mission-bound access token and its
  sender-constraint key cannot expand it.
- The issuance profile's integrity anchors are issuer-bound, so a
  Mission's governance state cannot be transplanted across Mission
  Issuers; an expansion is adjudicated only at the predecessor's own
  `issuer`.

## Possession proof {#possession-proof}

A stolen or exfiltrated predecessor credential could be replayed to
request an expansion.

Mitigations:

- The `subject_token` is a sender-constrained access token, not a
  reusable bearer refresh credential, and possession is proven against
  the token's own confirmation key ({{request-binding}}): a bearer copy
  of the token, without its DPoP key or mTLS certificate, cannot carry
  the proof. A refresh token MUST NOT be accepted as the `subject_token`
  ({{submission}}).
- The DPoP proof `jti` is single-use ({{RFC9449}}), so a captured proof
  cannot be replayed ({{verification-order}}).
- The short-lived `subject_token` bounds the window in which even a
  key-holding attacker could act, and the possession proof is bound and
  recorded at request time so a legitimate deferred completion is not
  gated on that lifetime ({{deferred-window}}).

## Authority comes only from new consent {#new-consent}

An expansion could be misused to widen authority without the Approver
re-consenting, if a successor were allowed to inherit or extend
authority without a fresh approval.

Mitigations:

- The successor's authority comes only from the Authority Set derived
  and consented at the expansion approval event; the `authority_hash`
  commits exactly that set ({{adjudication}}). The `predecessor` member
  carries no authority and cannot widen the successor
  ({{predecessor-member}}).
- The successor-expiry rule ({{successor-expiry}}) keeps the
  successor's `expires_at` from silently exceeding the predecessor's,
  so expansion cannot launder a longer lifetime past the originally
  approved horizon.

## Race against predecessor lifecycle {#lifecycle-race}

Between the moment a client decides to expand and the moment the
successor activates, the predecessor may be revoked, expire, or be
superseded by a concurrent expansion. A deferred or interactive
completion widens this window. Without serialization an expansion could
appear to succeed against a predecessor that is no longer authoritative,
or two successors could be created.

Mitigations:

- The Mission Issuer verifies predecessor state and the
  no-existing-successor condition in the same atomic step that would
  activate the successor ({{deferred-window}}), and serializes the
  completions that activate a successor of the same predecessor
  ({{reconciliation}}).
- A failed check refuses with `invalid_grant` and a reconciliation
  status that tells the client whether to discover an existing
  successor or stop, without leaking the predecessor's new internal
  state beyond that ({{reconciliation}}).

## Duplicate creation {#duplicate-creation}

To a client, a lost response is indistinguishable from a failed
creation. Without idempotency the natural retry after a network
fault creates a second Mission: live authority nobody intended and,
under the child delegation profile, a consumed fan-out budget
({{I-D.draft-mcguinness-oauth-mission-child-delegation}}). Proof
`jti` single-use does not close this fault: the retry carries a
fresh, valid proof.

Mitigations:

- The REQUIRED `creation_request_id`, with its durable reservation
  and uniqueness constraint, makes the retry recover the one
  committed operation, concurrent retries included
  ({{creation-idempotency}}, {{creation-reservation}}).
- The identifier is a deduplication handle, not a secret and not a
  credential: recovery re-establishes client authentication,
  possession of the recorded confirmation key, and the recorded
  authorization context, so the recovery path never weakens the
  possession requirements of {{request-binding}}
  ({{creation-revalidation}}).
- Reservations are scoped to the authenticated client, so one
  client's identifiers cannot interfere with, or replay, another's.
- Storage is bounded: the tombstone is small, its horizon is
  published ({{creation-retention}}), and a Mission Issuer MAY cap
  outstanding reservations per client.

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
  (prompt fatigue). Every expansion presentation is recorded and
  counted toward anomaly detection ({{request-binding}}).
- A denial reason MUST NOT disclose policy boundaries beyond the
  adjudicated request ({{denial-reasons}}); a denial reports whether
  the requested authority was approved, not the full surface of what
  would have been.

## Audit linkage {#audit-linkage}

The `predecessor` member makes the expansion chain observable: an
authorized auditor can trace a successor back through its predecessors
to the original Mission. This is a core governance property of
expansion. An implementation that omits the member breaks the chain
and defeats it; the member is therefore mandatory on a successor
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

## Related-work correlation {#related-to-correlation}

`related_to` correlates independently approved tasks the way the
`predecessor` chain correlates a succession, without the authority
linkage. The same scoping applies: deployments SHOULD disclose the
member only to audiences that require the governance relationship,
and the issuance profile's Mission Identifier correlation
considerations apply to both Missions it names.

## Disclosure of the broadened task {#broadened-task}

The expansion Mission Intent and the consent disclosure rendered at the
expansion approval event reveal how the approved task is evolving. The
Mission Issuer SHOULD render that disclosure only to the Approver and
authorized governance consumers, consistent with the issuance profile's
treatment of consent disclosure.

# IANA Considerations

The `predecessor` member of the `mission` claim
({{predecessor-member}}) is not registered in a dedicated registry: it
is carried inside the already-registered `mission` claim, an open
object for which the issuance profile establishes no member registry.
No new claim, parameter, or token-introspection registration is
required for the lineage link.

This document defines two closed sets of symbolic codes, the expansion
reconciliation status codes ({{reconciliation}}), conveyed in
`mission_expansion_status`, and the expansion denial reasons
({{denial-reasons}}), conveyed in the shared `mission_denial_reason`
member. As members of the OAuth error response JSON body at the token
endpoint, both are namespaced to their error responses and require no
registration; their authorization error response parameter forms, used
on the retained interactive path, are registered below. This document
creates no registry for the codes: the closed sets are small and fully
specified in their defining specifications. Should interoperable
extension prove necessary, a future revision can create a "Mission
Expansion Reconciliation Status" registry and a shared "Mission Denial
Reason" registry with a Specification Required {{RFC8126}} policy.

The expansion request is an {{RFC8693}} token exchange carrying the
already-registered `mission_intent` request parameter and the
already-registered token-exchange parameters `subject_token`,
`subject_token_type`, `requested_token_type`, `actor_token`, and
`actor_token_type`; none of these needs registration by this document.
The deferred completion mode
uses the deferred token response substrate
({{I-D.draft-gerber-oauth-deferred-token-response}}) and registers
nothing here. This document removes the earlier revision's registration
request for a `predecessor_token` parameter: the predecessor is
resolved from `subject_token`, so no dedicated predecessor-token
parameter exists.

This document registers the following parameters in the "OAuth
Parameters" registry:

- Name: `predecessor`
- Parameter Usage Location: token request, authorization request
- Change Controller: IETF
- Reference: this document, {{submission}}

- Name: `mission_expansion_status`
- Parameter Usage Location: token response, authorization response
- Change Controller: IETF
- Reference: this document, {{reconciliation}}

- Name: `mission_denial_reason`
- Parameter Usage Location: token response, authorization response
- Change Controller: IETF
- Reference: this document, {{denial-reasons}}; also carried by the
  child delegation profile
  ({{I-D.draft-mcguinness-oauth-mission-child-delegation}})

- Name: `creation_request_id`
- Parameter Usage Location: token request
- Change Controller: IETF
- Reference: this document, {{submission}}, {{creation-idempotency}};
  also carried by the child delegation profile
  ({{I-D.draft-mcguinness-oauth-mission-child-delegation}})

The `predecessor` cross-check rides the token exchange request at the
token endpoint and, on the retained interactive path, the authorization
request; the reconciliation status and denial reason ride the token
error response and, on the interactive path, the authorization error
response. The `creation_request_id` identifier rides the token
exchange request at the token endpoint in every completion mode and
never appears on a front channel.

# Acknowledgments
{:numbered="false"}

The author thanks the reviewers of the Mission-Bound Authorization for
OAuth 2.0 profile for feedback on the expansion model and its
composition with the issuance flow.

--- back
