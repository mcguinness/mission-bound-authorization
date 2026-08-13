---
title: "Mission Continuation: Authorization Continuity for Mission-Bound Authorization"
abbrev: "Mission Continuation"
docname: draft-mcguinness-oauth-mission-continuation-latest
category: exp
submissiontype: IETF
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

informative:
  I-D.draft-zhu-oauth-async-delegation:
  I-D.draft-mcguinness-oauth-id-continuation-assertion:
    title: "Identity Continuation Assertion for OAuth 2.0 Token Exchange"
    target: https://datatracker.ietf.org/doc/draft-mcguinness-oauth-id-continuation-assertion/
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
  I-D.draft-mcguinness-mission-aauth:
    title: "Mission Context Binding for AAuth"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-aauth.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-mission-uma:
    title: "Mission-Bound Authorization: UMA 2.0 Binding"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-uma.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-mission-harness:
    title: "Mission Harness"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-harness.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-mission-runtime:
    title: "Mission Runtime Enforcement"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-runtime.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-mission-authzen:
    title: "Mission AuthZEN Binding"
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

This document is the binding between the two, plus the evidence that
ties each continued action back to the Mission. It is transport-agnostic:
it defines what a Mission requires of any identity-continuity transport,
and it profiles the three transports above. It defines no new token type,
grant type, or endpoint of its own; it constrains how the transports'
existing mechanisms carry a Mission's authorization. Its place in the
family is the Continue verb of the architecture
({{I-D.draft-mcguinness-mission-architecture}}).

# Status: An Experimental Extension {#optional-status}

This document is optional and experimental: adopt it for evaluation,
not as a stable interface. It is a layered binding between the
issuance profile and an identity-continuity transport, not a change
to either. A deployment that implements
{{I-D.draft-mcguinness-oauth-mission}} and never continues a Mission
across a transport is fully conformant to that profile and is
unaffected by this document. It defines no new token type, grant
type, or endpoint of its own. No Standards-Track document depends on
this one.

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
  not a credential (see {{invariant}}).

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
  its session; when the session ends, the anchor and every handle under it
  cease to resolve. A continuation MUST NOT be rooted in a bare access
  token; the root is the Mission's grant or an authenticated session
  bound to it.

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
  transport state (a handle, a refresh-token family) MUST be invalidated.
  Termination does not shorten an already-issued credential; a continued
  credential retains its own expiry, and revocation acts on future
  issuance, not on tokens already in flight.

Continuation is bounded in time by the Mission's expiry; that expiry is
the continuity ceiling. The Mission's `max_derivations`, where present,
remains a bound on distinct derivations and is not a separate continuity
ceiling. A continuation that issues a distinct new grant (for example, an
Identity Continuation hop that mints a new audience-scoped credential)
counts as one derivation; the successive refreshes of a single async
delegation family ({{transport-async}}) are one delegation and do not
each count again.

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
to the Mission being continued. Every transport, whatever its wire
mechanism, MUST:

- name the accepted hop with a continuation handle that is not itself a
  credential and that resolves to the Mission's rooting anchor;
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
intra-domain, connected, cross-workload transport. A Chain Authority mints
a short-lived, sender-constrained assertion naming an accepted hop; the
acting workload presents it as an {{RFC8693}} token-exchange subject token
and redeems a continuation ID-JAG at the token endpoint. Under this
profile the assertion's `identity_continuation_handle` MUST resolve to a
Mission rooting anchor; the issued ID-JAG's authorization detail MUST be a
subset of that Mission's Authority Set, state-gated, and lifetime-clamped
per {{authorization-continuity}}; and the ID-JAG MUST be bound
({{RFC9449}}) to the acting identity's key. The assertion carries no
subject, so continuation preserves the Mission's subject rather than
projecting it; the actor is rebound per hop.

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
the trigger. This is the "scheduled continuation roots in durable
authorization" case: the Mission is that durable authorization. Successive
refreshes within one family are one delegation and are not counted again
against `max_derivations` ({{authorization-continuity}}).

Establishing the family is a delegation-family-creating exchange, and a
client that loses the response retries with a fresh, valid proof; without
an idempotency identifier that retry mints a second live refresh-token
family. The exchange therefore carries `creation_request_id`, the
creation idempotency identifier of
{{I-D.draft-mcguinness-oauth-mission-expansion}}. The parameter is
REQUIRED; a Mission Issuer MUST refuse an exchange missing it with
`invalid_request`. Its syntax, the reservation state machine and its
uniqueness constraint, tombstone retention against the published retry
horizon, and the revalidation rules are that profile's, applied by
reference and not redefined here.

In the operation fingerprint, `op` is `async-delegation`; `iss` and
`client` are as the expansion profile defines them; `source` is the
`mission_id` of the base Mission resolved from `subject_token`, never
the raw token; `cnf` is the acting client's verified confirmation,
since this exchange deliberately re-binds the family to the acting
key rather than proving possession of the subject token's own
confirmation; `proposal` is the parsed `authorization_details` array
naming the requested confined subset, when present; `resource` is the
target the family is audienced to; and `request_refresh_token` is the
parameter selecting this exchange. A repetition whose fingerprint
differs is refused with `invalid_request`.

Recovery is delivery, never a second family. A revalidated retry (the
same authenticated client proving possession of the recorded `cnf`,
with a matching fingerprint) recovers the recorded operation: it MUST
NOT create a second delegation family and MUST NOT count a second
derivation against `max_derivations`. The stored response is returned
while the initial refresh token is unissued or unused; where that
token has been consumed or has expired, the Mission Issuer mints a
fresh refresh token within the same family (the family's native
rotation), an issuance event with issuance accounting only, never
creation accounting.

## Cross-Domain Projection Transport {#transport-xdomain}

Cross-domain projection
({{I-D.draft-mcguinness-oauth-mission-cross-domain}}) is the
cross-boundary transport: a single-hop grant that carries a Mission into a
partner trust domain, where a Resource Authorization Server mints a local
token bounded by the projected authority. This profile adds nothing to
projection's wire. It requires that a Mission continued in the partner
domain remains subject to this profile there: continuation handles minted
in the partner domain grant nothing, and continued grants re-derive a
subset of the projected authority under the partner's state view.
Projection stays single-hop regardless of intra-domain continuation on
either side of the boundary.

# Execution-Time Evidence {#evidence}

Each action taken under a continued credential is a decision point that
produces execution evidence and a Mission Receipt
({{I-D.draft-mcguinness-mission-runtime}},
{{I-D.draft-mcguinness-mission-authzen}}), recorded against the Mission.

Under this profile that evidence MUST additionally record the continuation
hop reference: the continued credential's `jti` and the Mission lineage it
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
native and needs no new transport. The `(approver, s256)` mission
reference is a handle that grants nothing, and the Person Server's
state-gated, one-hour auth-token issuance and federation is the
continuation point, with revocation latency bounded by the auth-token
lifetime. The cross-workload transports of this profile have no AAuth
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

Handle theft yields no authority. Because a continuation handle grants
nothing ({{invariant}}), an attacker who steals one cannot obtain a
continued grant without also satisfying the transport's identity
re-establishment and key confirmation and passing the Mission's live state
gate. This is the property that makes conveying a handle through an
intermediary safe: the intermediary gains no ability to act.

Revocation latency for a continuation is bounded by the shorter of the
continued credential's remaining lifetime and the transport's re-issuance
interval, and never exceeds the Mission's expiry
({{authorization-continuity}}). Terminating a Mission stops future
continuation immediately but does not shorten a credential already issued;
deployments requiring tighter bounds choose shorter transport lifetimes.

Replay is a transport concern the Mission binding does not relax: the
Identity Continuation Assertion is single-use by `jti`, and an async
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
correlation handle. The Identity Continuation Assertion carries no subject.
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
