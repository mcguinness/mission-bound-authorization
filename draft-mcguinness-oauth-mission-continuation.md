---
title: "Mission Continuation for OAuth 2.0"
abbrev: "OAuth Mission Continuation"
docname: draft-mcguinness-oauth-mission-continuation-latest
category: exp
submissiontype: IETF
workgroup: Web Authorization Protocol
consensus: true
v: 3
keyword:
 - mission
 - agent
 - authorization
 - continuity
 - delegation
author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com

normative:
  RFC2119:
  RFC8174:
  RFC6749:
  RFC8693:
  RFC9449:
  I-D.draft-mcguinness-oauth-mission:
    title: "Mission-Bound Authorization for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission.html
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
  I-D.draft-mcguinness-oauth-mission-cross-domain:
    title: "Mission Cross-Domain Projection for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-cross-domain.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026

informative:
  RFC9700:
  I-D.draft-zhu-oauth-async-delegation:
  I-D.draft-mcguinness-oauth-id-continuation-assertion:
  I-D.draft-mcguinness-oauth-mission-template:
    title: "Mission Template for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-template.html
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
  I-D.draft-mcguinness-oauth-mission-derivation-limits:
    title: "Mission Derivation Limits for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-derivation-limits.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-mission-aauth:
    title: "Mission Context Binding for AAuth"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-aauth.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-mission-uma:
    title: "Mission-Bound Authorization for User-Managed Access (UMA) 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-uma.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-mission-harness:
    title: "Mission-Aware Agent Harnesses"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-harness.html
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
  I-D.draft-mcguinness-mission-authzen:
    title: "Mission-Bound Runtime Enforcement: AuthZEN Profile"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-authzen.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-mission-architecture:
    title: "An Architecture for Mission-Bound Authorization"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-architecture.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026

--- abstract

This document profiles authorization continuity for Mission-Bound
Authorization. A Mission is the durable, grant-anchored record of what
work remains authorized, under which constraints, on whose approval.
Mission Continuation binds that authorization to an identity-continuity
transport that re-establishes who is acting, so a Mission's work
continues across hops and over time without re-presenting the original
credential and without widening authority. The Identity Continuation
Assertion, async delegation, and cross-domain projection are the
transports; the Mission binds all of them under one invariant: a
continuation handle grants nothing.

--- middle

# Introduction {#introduction}

Long-running and multi-hop agentic work conflates three questions that
must stay separate:

- identity continuity: who is acting, and how that identity legitimately
  continues, whether across hops within a trust domain or across a trust
  boundary;
- authorization continuity: what work remains authorized, under which
  constraints, on whose approval; and
- execution-time evidence: what was actually done at each continued hop.

Identity-continuity mechanisms answer only the first. The Identity
Continuation Assertion ({{I-D.draft-mcguinness-oauth-id-continuation-assertion}}),
async delegation ({{I-D.draft-zhu-oauth-async-delegation}}), and
cross-domain projection ({{I-D.draft-mcguinness-oauth-mission-cross-domain}})
each carry an acting identity onward, but none of them answers whether
the work is still authorized, or within what bounds, beyond whatever a
token happens to embed. Mission-Bound Authorization
({{I-D.draft-mcguinness-oauth-mission}}) answers the second: the Mission
is the approved, constrained, state-gated, revocable record of the work.

This document connects the two, and adds the evidence that ties each
continued action back to the Mission. It is transport-agnostic:
it defines what a Mission requires of any identity-continuity transport,
and it profiles the three transports above. It defines no new token type,
grant type, or endpoint of its own; it constrains how the transports'
existing mechanisms carry a Mission's authorization. Its place in the
family is the Continue verb of the architecture
({{I-D.draft-mcguinness-mission-architecture}}).

This document is optional and experimental: adopt it for evaluation,
not as a stable interface. It is a profile layered between the
issuance profile and an identity-continuity transport, not a change
to either. A deployment that implements
{{I-D.draft-mcguinness-oauth-mission}} and never continues a Mission
across a transport is fully conformant to that profile and is
unaffected by this document.

It defines no new token type, grant type, or endpoint of its own. No
Standards-Track document depends on this one.

A Mission Issuer claims conformance to this document only when it
continues a Mission across an Identity Continuation, async
delegation, or cross-domain projection hop under the requirements of
{{authorization-continuity}}; otherwise it remains a plain
issuance-profile Mission Issuer. Nothing here places a new
requirement back on the issuance profile.

# Conventions and Terminology {#conventions}

{::boilerplate bcp14-tagged}

This document uses the terms Mission, Authority Set, approval event,
Mission state, `active`, and derivation from
{{I-D.draft-mcguinness-oauth-mission}}. It additionally defines:

Continuation:
: The act of obtaining a fresh credential for a Mission's work after the
  original credential is unavailable or the acting identity must be
  re-established, without a new approval and without widening authority.

Continuation Transport:
: An identity-continuity mechanism that carries an acting identity onward
  and, under this profile, a reference to the Mission whose authorization
  is continued. This document profiles three (see {{transports}}).

Accepted Hop:
: A point at which a Mission's authorization has been established and from
  which a continuation may proceed.

Continuation Handle:
: An opaque reference that names an accepted hop. A continuation handle is
  not a credential (see {{invariant}}). It differs from the async
  delegation transport's delegation handle ({{transport-async}}), an
  access token that carries authority.

Rooting Anchor:
: The record binding a continuation to exactly one Mission. A rooting
  anchor is grant-anchored (durable) or session-anchored (see
  {{authorization-continuity}}).

Continued Grant:
: A credential a transport issues for a Mission's work as the result of a
  continuation.

# The Three Continuities {#three-continuities}

This profile keeps the three continuities of {{introduction}} apart and
assigns each an owner.

Identity continuity is owned by a Continuation Transport, never by this
profile. This profile is transport-agnostic and states the requirements
a transport MUST meet to carry a Mission continuation ({{transports}}).

Authorization continuity is owned by the Mission ({{authorization-continuity}}).

Execution-time evidence is owned by the runtime and recorded against the
Mission ({{evidence}}).

The separation exists to prevent one failure: a transport that embeds
authorization detail being treated as self-authorizing, so that
possession of a continued credential substitutes for the Mission's live
state. The invariant of {{invariant}} forbids exactly this.

# Authorization Continuity and the Mission {#authorization-continuity}

A continuation continues a Mission. The Mission is the durable root; the
transport is the carrier. The following requirements bind every
Continuation Transport regardless of its wire mechanism.

Rooting:
: A continuation MUST be rooted in exactly one Mission through a rooting
  anchor. A grant-anchored rooting is durable and MAY outlive the session
  in which it was established. A session-anchored rooting MUST NOT outlive
  its session; when the session ends, the anchor and every continuation
  handle under it cease to resolve. A continuation MUST NOT be rooted in
  a bare access token; the root is the Mission's grant or an
  authenticated session bound to it.

Subset derivation:
: The authorization a continued grant conveys MUST be derived as a subset
  of the Mission's Authority Set at the time of issuance, per the subset
  rule of {{I-D.draft-mcguinness-oauth-mission}}. A continuation MUST NOT
  widen: it introduces no resource, no action, and no relaxed constraint
  the Mission did not already carry.

State gating:
: A continued grant MUST be issued only while the Mission, and every
  ancestor Mission in its lineage, is `active`. The state check MUST be
  atomic with issuance. Issuance under a non-`active` Mission or ancestor
  MUST fail.

Lifetime:
: A continued credential's expiry MUST NOT exceed the Mission's
  `expires_at`. Where a transport defines its own maximum lifetime, that
  maximum MUST be clamped to the Mission's expiry.

Termination:
: When a Mission reaches a terminal state, continuation under it MUST
  cease: subsequent continuation requests MUST fail, and any durable
  transport state (a continuation handle, a refresh-token family) MUST
  be invalidated.
  Termination does not shorten an already-issued credential; a continued
  credential retains its own expiry, and revocation acts on future
  issuance, not on tokens already in flight.

Continuation is bounded in time by the Mission's expiry; that expiry is
the continuity ceiling. The Mission's `derivation_limit`
({{I-D.draft-mcguinness-oauth-mission-derivation-limits}}), where established,
remains a bound on distinct derivations and is not a separate continuity
ceiling. A continuation that issues a distinct new grant (for example, an
Identity Continuation hop that mints a new audience-scoped credential)
counts as one derivation; the successive refreshes of a single async
delegation family ({{transport-async}}) are one delegation and do not
each count again.

This counts derivations within one Mission; it does
not bound how many derivations a subtree of Child Missions performs in
aggregate, which the child delegation profile's own local, per-Mission
`derivation_limit` warning addresses
({{I-D.draft-mcguinness-oauth-mission-child-delegation}}, Section
"Derivation Budget Is Not Inherited").

# The Grants-Nothing Invariant {#invariant}

The whole profile rests on one invariant:

A continuation handle grants nothing. It names an accepted hop. Every
continued grant re-passes the Mission's `active` gate. Continuity is
never authority.

Concretely: possession of a continuation handle, a refresh token, or any
other transport artifact MUST NOT be treated as evidence that the work is
still authorized. Authorization is established only by deriving a subset
of the Mission's Authority Set under a live state check
({{authorization-continuity}}) at each issuance. A relying party MUST NOT
make an authorization decision from the mere existence or contents of a
continuation artifact.

The family already holds this line elsewhere: the harness binds session
continuity to Mission state and never to authority
({{I-D.draft-mcguinness-mission-harness}}), and the UMA binding's
persisted-claims token is a continuation handle that grants nothing while
every requesting-party token re-passes fresh assessment
({{I-D.draft-mcguinness-mission-uma}}). This profile generalizes the same
rule to the OAuth transports.

# Continuation Transports {#transports}

A Continuation Transport carries an acting identity onward and a reference
to the Mission being continued. Each transport MUST identify the accepted
hop through a reference that resolves to the Mission's rooting anchor.
Possession of that reference alone MUST NOT be treated as evidence that
the Mission's work remains authorized. The reference can be a
continuation handle, which is not a credential ({{conventions}}), or a
credential the transport defines, such as a refresh token
({{transport-async}}, {{transport-xdomain}}). Every transport, whatever
its wire mechanism, also MUST:

- re-establish the acting identity at each hop and bind the continued
  credential to a confirmed key held by that identity; and
- convey no authorization the Mission did not derive under
  {{authorization-continuity}}.

This profile defines both cross-workload continuation (a different
workload continues the Mission at the next hop) and over-time continuation
(the same workload continues after its credential is gone). Neither is a
universal mandatory-to-implement capability: a binding realizes the
transports its substrate supports ({{substrate}}). The three transports
below partition the space this profile addresses.

## Identity Continuation Transport {#transport-ica}

The Identity Continuation Assertion
({{I-D.draft-mcguinness-oauth-id-continuation-assertion}}) is the
multi-hop, cross-workload transport among Resource Authorization Servers
that trust a common IdP authorization server (IdP). A Continuation
Assertion Issuer attests that a Resource Authorization Server accepted
an earlier ID-JAG and that its authorization remains active; the acting
workload presents that assertion to the IdP as an {{RFC8693}} subject
token and redeems the onward ID-JAG it receives at the next Resource
Authorization Server. Under this
profile the assertion's `identity_continuation_handle` MUST resolve to a
Mission rooting anchor; the issued ID-JAG's authorization detail MUST be a
subset of that Mission's Authority Set, state-gated, and lifetime-clamped
per {{authorization-continuity}}; and the ID-JAG MUST be bound
({{RFC9449}}) to the acting identity's key.

The root ID-JAG ({{Section 5.1.1 of I-D.draft-mcguinness-oauth-id-continuation-assertion}})
and each onward ID-JAG MUST identify the originating Mission by
carrying its `mission` claim ({{I-D.draft-mcguinness-oauth-mission}},
Section "Mission Claim") with that Mission's `id` and `issuer`. A
Resource Authorization Server's local access token issued on such an
ID-JAG MUST preserve that `mission` reference.

The IdP's hop record is continuation state, not an additional grant
lineage ({{I-D.draft-mcguinness-oauth-mission}}, Section "Binding the
Mission to the Grant"). A Resource Authorization Server's association
of a continuation handle with the authorization state it establishes is
not by itself a Mission grant binding; a redeemable grant lineage that
server establishes and maps to the Mission is one. The base ID-JAG
profile recommends against a Resource Authorization Server issuing a
refresh token ({{Section 6 of I-D.draft-mcguinness-oauth-id-continuation-assertion}}); a
refresh-token family one creates by exception is a destination-side
Mission grant binding, under the Mission's authority, state, expiry and
termination rules ({{authorization-continuity}}).

The root exchange can coincide with a cross-domain projection exchange
({{I-D.draft-mcguinness-oauth-mission-cross-domain}}) where both
profiles' conditions hold. The two are not the same exchange in
general, and where they coincide, both profiles' restrictions apply.

The IdP authorizes each continuation under the chain authorization
recorded at the root exchange and current policy, and that draft leaves
whether a requested action serves the authorized work to deployment
policy
({{Section 5.5.3 of I-D.draft-mcguinness-oauth-id-continuation-assertion}},
{{Appendix A.5 of I-D.draft-mcguinness-oauth-id-continuation-assertion}});
under this profile the Mission answers it. A chain's lifecycle anchor
({{Section 6.1 of I-D.draft-mcguinness-oauth-id-continuation-assertion}})
is its rooting anchor: the Mission's grant, which can carry unattended
work past logout, or a session bound to it. A Mission's terminal state
withdraws permission to continue and ends the chain
({{Section 6.2 of I-D.draft-mcguinness-oauth-id-continuation-assertion}}).
A refusal at this exchange uses that draft's codes
({{Section 5.5.6 of I-D.draft-mcguinness-oauth-id-continuation-assertion}}),
in place of the issuance profile's `invalid_request`: a terminal Mission
is `invalid_continuation`, a suspended Mission is `unauthorized_client`,
no remaining authority for the audience is `invalid_target`, and a
derivation or hop-count limit is `invalid_grant`. The issuance
profile's requirements for the `mission_error` diagnostic
({{I-D.draft-mcguinness-oauth-mission}}) apply unchanged.
The assertion carries no user subject: the IdP resolves the subject for
each target from the hop, so continuation preserves the Mission's
subject rather than projecting it; the actor is rebound per hop.

Mission delegation depth at this exchange, the depth at which the
issuance profile's per-entry delegation constraints apply
({{I-D.draft-mcguinness-oauth-mission}}, Section "Delegation
Constraints"), is counted over the selected hop's ancestry as the IdP's
hop records hold it, from the root to that hop, followed by the current
authenticated actor. Only consecutive entries with equal `(iss, sub)`
merge. The root entry is the Mission's approved client at depth 0, and
each remaining entry adds 1, so the chain A, B, B has depth 1 and A, B,
A has depth 2. Sibling branches, the presented assertion, and any
narrowing of what the onward `act` discloses do not change the depth
({{Section 5.5.5 of I-D.draft-mcguinness-oauth-id-continuation-assertion}}).
At depth 0 the approved agent continues for itself and no delegation
narrowing applies. This transport defines no reset: continuing to
another Resource Authorization Server, or returning to an earlier
actor, never restarts the count. Where the IdP cannot read a hop's
complete ancestry, it issues nothing.

The onward ID-JAG conveys each entry's `delegation` member under the
cross-domain projection rule
({{I-D.draft-mcguinness-oauth-mission-cross-domain}}, Section
"Conveyed Delegation Policy"), so a requested authorization detail
that keeps an omitted `delegation` exceeds the grant's authority and
is refused. The rule changes only the conveyed copy: the delegation
constraints at this exchange apply at the depth counted above, `act`
attributes the same actors, and that profile's depth reset does not
apply. The dependency on that profile binds only a deployment that
adopts this transport.

## Async Delegation Transport {#transport-async}

Async delegation ({{I-D.draft-zhu-oauth-async-delegation}}) is the
intra-domain, disconnected, over-time transport, for background jobs,
scheduled tasks, agent queues, and multi-stage orchestration. A
delegated refresh-token family is established at the accepted hop and
redeemed later, after the original credential is gone. Under this profile
the family's delegated authorization state MUST be a subset of the
Mission's Authority Set; the family's absolute maximum delegation lifetime
MUST equal the Mission's `expires_at`; and the family MUST be invalidated
when the Mission reaches a terminal state, reusing that draft's
family-revocation and reuse-detection rules with the Mission lifecycle as
the trigger.

This transport's reference ({{transports}}) is the presented refresh
token. It is bound to its family's delegated authorization state
({{Sections 4.3 and 4.4 of I-D.draft-zhu-oauth-async-delegation}}), through
which it resolves to the Mission's rooting anchor, the family's grant
binding. Rotation ({{Section 6 of I-D.draft-zhu-oauth-async-delegation}})
preserves that state, and the issuance profile resolves the family,
one grant lineage, to the same Mission for its whole lifetime
({{I-D.draft-mcguinness-oauth-mission}}, Section "Binding the Mission
to the Grant"). The refresh token is a credential, not a continuation
handle, protected by that draft's client binding
({{Section 5.2 of I-D.draft-zhu-oauth-async-delegation}}).

The exchange's `subject_token` is a delegation handle (Section 4.3 of
{{I-D.draft-zhu-oauth-async-delegation}}): an access token whose
audience is the acting client's own `client_id`, sender-constrained to
the acting client's key. A Mission Issuer MUST refuse a
`subject_token` whose audience is not the authenticated acting client,
including a Mission access token audienced to a resource, and MUST
require proof of possession of the `subject_token`'s own confirmation
key; client authentication never satisfies that sender constraint.

An agent obtains its delegation handle with a Token Exchange that
presents its own Mission access token, proves possession of that
token's key, and names its own `client_id` as `audience`. The
delegation handle keeps that key and carries the presented token's
authority narrowed by the Mission's current effective authority. The
exchange is a no-actor self-exchange under the issuance profile's
Self-Exchange Down-Scoping rules
({{I-D.draft-mcguinness-oauth-mission}}). A dispatched Mission's
selected Agent instead redeems the Template profile's Dispatch Handoff
for its delegation handle
({{I-D.draft-mcguinness-oauth-mission-template}}), unless it is also
the Dispatcher (the same authenticated client), which obtains its
delegation handle through this exchange from the instance's access
token.

This is the "scheduled continuation roots in durable
authorization" case: the Mission is that durable authorization. Successive
refreshes within one family are one delegation and are not counted again
against `derivation_limit` ({{authorization-continuity}}).

Establishing the family is a delegation-family-creating exchange, and a
client that loses the response retries with a fresh, valid proof; without
an idempotency identifier that retry mints a second live refresh-token
family. The exchange therefore carries `creation_request_id`, the
creation idempotency identifier of
{{I-D.draft-mcguinness-oauth-mission-expansion}}. The parameter is
REQUIRED; a Mission Issuer MUST refuse an exchange missing it with
`invalid_request`. Its syntax, the `(client, creation_request_id)`
key uniqueness, fingerprint comparison, reservation ownership,
tombstone retention against the published retry horizon, and the
revalidation rules are that profile's, applied by reference and not
redefined here. A refresh-token family is not a Mission: its delivery
and recovery are defined below, not by that profile's
Mission-creation recovery.

In the operation fingerprint, `op` is `async-delegation`; `iss` and
`client` are as the expansion profile defines them; `source` is the
`mission_id` of the base Mission resolved from `subject_token`, never
the raw token; `cnf` is the acting client's verified confirmation,
which is the delegation handle's own key; `proposal` is the parsed
`authorization_details` array
naming the requested confined subset, when present; `resource` is the
target the family is audienced to; and `request_refresh_token` is the
parameter selecting this exchange. A repetition whose fingerprint
differs is refused with `invalid_request`.

The operation passes through three states. It is reserved when the
`(client, creation_request_id)` reservation is acquired, before any
side effect; family-created once the family and its single derivation
count exist, committed atomically, with the family's identity
recorded on the reservation; and completed once the response is
delivered. A derivation-gate rejection or creation failure
invalidates the provisional family and records the refusal, replayed
to a matching retry.

Recovery is delivery of the recorded family, never a second family
and never a second derivation count. A revalidated retry (the same
authenticated client proving possession of the recorded `cnf`, with a
matching fingerprint) recovers by state: a reserved operation yields
a retryable in-progress result; a family-created operation resumes
delivery, issuing the recorded family's initial tokens; a completed
operation returns the stored response while the initial refresh
token is unissued or unconsumed.

Consumption of the initial refresh token proves delivery: the client
held the response and rotated on it. Once it is consumed, the
operation is delivered and creation recovery MUST be refused with
`invalid_grant`; the client continues on the family's current refresh
token. A rotating refresh-token family is a single lineage
({{RFC9700}}); recovery MUST NOT mint an independent sibling refresh
token into it.

## Cross-Domain Projection Transport {#transport-xdomain}

Cross-domain projection
({{I-D.draft-mcguinness-oauth-mission-cross-domain}}) is the
cross-boundary transport: a single-hop grant that carries a Mission into a
partner trust domain, where a Resource Authorization Server mints a local
token bounded by the projected authority. This profile adds nothing to
projection's wire. Its reference ({{transports}}) is the Mission's
refresh token, which the projection exchange presents as its
`subject_token` and which resolves to exactly one Mission. The
cross-domain grant it yields is the continued grant, and carries the
`mission` claim naming that Mission
({{I-D.draft-mcguinness-oauth-mission-cross-domain}}). It requires that
a Mission continued in the partner domain remains subject to this
profile there: continuation handles minted in the partner domain grant
nothing, and continued grants re-derive a
subset of the projected authority under the partner's state view.
Projection stays single-hop regardless of intra-domain continuation on
either side of the boundary.

# Execution-Time Evidence {#evidence}

Each action taken under a continued credential is a decision point that
produces execution evidence and a Mission Receipt
({{I-D.draft-mcguinness-mission-runtime}},
{{I-D.draft-mcguinness-mission-authzen}}), recorded against the Mission.

Under this profile that evidence MUST additionally record the continuation
hop's identifiers: the continued credential's `jti` and the Mission lineage it
carries (the `mission` claim's parent lineage or the resolved continuation
handle). An action taken through a continuation therefore attributes to
both the Mission that authorized it and the specific hop that carried the
authorization, so that a reviewer can reconstruct which continuation, of
possibly many under one Mission, produced a given effect.

# Substrate Dispositions {#substrate}

This is an OAuth-wire profile, not a substrate requirement. The Mission
substrate restates no definition, and the continuity requirements of
{{authorization-continuity}} are applications of existing substrate
requirements (the Mission identifier, `active`-gated issuance, the subset
rule, revocation, and the anchors) rather than new obligations. A binding
therefore realizes continuation through its own surfaces, not through a
substrate row. Two non-OAuth bindings dispose of continuation as a
composition consequence.

AAuth ({{I-D.draft-mcguinness-mission-aauth}}): over-time continuation is
native and needs no new transport. The mission reference (the
approving Person Server and `s256`) is a handle that grants nothing,
and the Person Server's state-gated, one-hour auth-token issuance and
federation is the continuation point, with revocation latency bounded
by the auth-token lifetime.

The cross-workload transports of this profile have no AAuth
substrate (AAuth has no token exchange, no `act` chain, and no ID-JAG),
and AAuth declines cross-hop authority carry-forward by design: a chained
hop is a fresh decision at its own decision point. AAuth-native
cross-workload continuation is therefore deferred work. AAuth over-time
continuation is scoped to the Person-Server-mediated, attributed path; an
AAuth federated re-issuance in Reference-only mode, where the Access
Server does not carry the Mission members, is a fresh federated decision,
not a Mission continuation, and is out of scope for this profile.

UMA ({{I-D.draft-mcguinness-mission-uma}}): the persisted-claims token is
the continuation handle and already realizes the grants-nothing invariant,
with every requesting-party token re-passing fresh assessment.

# Security Considerations {#security}

Continuation handle theft yields no authority. Because a continuation
handle grants nothing ({{invariant}}), an attacker who steals one
cannot obtain a continued grant without also satisfying the transport's
identity re-establishment and key confirmation and passing the Mission's
live state gate. This is the property that makes conveying a
continuation handle through an intermediary safe: the intermediary
gains no ability to act.
A delegation handle does carry authority, and its sender constraint
({{transport-async}}) withholds that authority from a holder without
the acting client's key. Neither the handle-theft claim nor the
safe-intermediary claim extends to a transport reference that is a
credential, such as a refresh token: a stolen refresh token protected
only as a bearer credential can mint access tokens until detection,
revocation or expiry
({{Section 11 of I-D.draft-zhu-oauth-async-delegation}}).

Revocation latency for a continuation is bounded by the shorter of the
continued credential's remaining lifetime and the transport's re-issuance
interval, and never exceeds the Mission's expiry
({{authorization-continuity}}). Terminating a Mission stops future
continuation immediately but does not shorten a credential already issued;
deployments requiring tighter bounds choose shorter transport lifetimes.

Replay is a transport concern this profile does not relax: the
Identity Continuation Assertion is single-use, keyed on `(iss, jti)`
({{Section 5.5.7 of I-D.draft-mcguinness-oauth-id-continuation-assertion}}),
and an async
delegation family rotates on each refresh with reuse detection over the
family. A continuation MUST NOT widen authority; the subset check of
{{authorization-continuity}} is enforced at every issuance, so a
compromised transport cannot escalate beyond the Mission's Authority Set.
Continued grants are audience-confined by their transport, limiting a
confused-deputy hop to the audiences the Mission already reaches.

# Privacy Considerations {#privacy}

Continuation preserves the Mission's subject rather than minting a new
one, and the transports resolve audience-local subjects where they resolve
a subject at all, so a continued Mission does not become a cross-audience
correlation handle. The Identity Continuation Assertion carries no user
subject, and its handles are hop-specific, but the IdP and a hop's
participants can still correlate a chain
({{Section 10 of I-D.draft-mcguinness-oauth-id-continuation-assertion}}).
Continuation handles are opaque and carry no authorization detail, so their
exposure discloses neither the subject nor the granted authority.

# IANA Considerations {#iana}

This document has no IANA actions. The token types, grant types, and
metadata parameters used by the transports are registered by their
respective documents
({{I-D.draft-mcguinness-oauth-id-continuation-assertion}},
{{I-D.draft-zhu-oauth-async-delegation}},
{{I-D.draft-mcguinness-oauth-mission-cross-domain}}); this profile
constrains their use and introduces none of its own.

--- back

# Document History {#document-history}

\[\[ To be removed from the final specification ]]

- The Identity Continuation Transport requires the root and onward
  ID-JAGs to identify the originating Mission through the `mission`
  claim, and a Resource Authorization Server's local access token to
  preserve it. It also places the hop record, a Resource Authorization
  Server's handle association and any refresh family against grant
  bindings, and says when the root exchange coincides with cross-domain
  projection (#1589, D726).

- Continuation Transports requires each transport to identify the
  accepted hop through a reference that resolves to the Mission's
  rooting anchor, and forbids treating possession of that reference
  alone as evidence that the work remains authorized. The reference no
  longer has to be a non-credential: the async delegation and
  cross-domain transports' references are refresh tokens. This is a
  normative applicability correction; the Grants-Nothing Invariant is
  unchanged (#1588). Execution-Time Evidence names the continuation
  hop's identifiers, so the term does not read as that reference.

- The async transport's handle is called a delegation handle, an
  access token carrying authority, distinct from a continuation
  handle; the Rooting and Termination requirements name the
  continuation handle; and the document calls itself a profile, not a
  binding. No requirement changed.

- The Identity Continuation Transport's onward ID-JAG conveys
  `delegation` under the cross-domain projection rule, so a requested
  authorization detail that keeps an omitted member exceeds the
  grant's authority; the transport's depth count and `act` attribution
  are unchanged, with no depth reset (#1374).

- The Identity Continuation Transport's codes replace the issuance
  profile's Token Exchange code, now `invalid_request`; the codes
  themselves are unchanged (#1154).

- Aligned with the published Identity Continuation Assertion (-02): the
  transport runs among Resource Authorization Servers that trust a
  common IdP, its assertion issuer is the Continuation Assertion
  Issuer, the Mission binds the chain authorization, lifecycle anchor,
  and chain ending, single use is keyed on `(iss, jti)`, and Privacy
  Considerations notes that a chain remains correlatable (#906).
- The Identity Continuation Transport states the refusal codes at that
  exchange, those of the Identity Continuation Assertion in place of
  the issuance profile's `invalid_grant`, as the issuance profile
  permits for a Token Exchange profile that assigns its own code. The
  `mission_error` diagnostic requirements are unchanged (#921).
- The Identity Continuation Transport states how Mission delegation
  depth is counted there: over the hop's IdP-held ancestry plus the
  current actor, merging only consecutive equal actors, from the
  approved client at depth 0, with no reset, and with nothing issued
  when the ancestry is incomplete (#960).
- A dispatched Mission enters the async delegation transport through
  its selected Agent, which redeems the Template profile's Dispatch
  Handoff for a delegation handle of its own (#1158).
- The async delegation transport's `subject_token` is a delegation
  handle: its audience is the acting client and possession of its own
  key is proved at the exchange, as Section 4.3 of the async delegation
  draft requires, replacing the re-binding to the acting key. An agent
  obtains its handle with a no-actor self-exchange naming its own
  `client_id` as `audience` (#1157).
- A dispatched Mission's selected Agent that is also its Dispatcher
  obtains its delegation handle through that self-exchange, from the
  instance's access token, instead of the Dispatch Handoff (#1195).
