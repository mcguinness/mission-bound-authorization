---
title: "Mission-Bound Authorization for UMA 2.0"
abbrev: "Mission UMA"
category: exp

docname: draft-mcguinness-mission-uma-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
keyword:
 - mission
 - agent
 - authorization
 - uma
 - user-managed access
 - governance
venue:
  github: "mcguinness/mission-bound-authorization"
  latest: "https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-uma.html"

author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com

normative:
  RFC3339:
  RFC7662:
  UMA-GRANT:
    title: "User-Managed Access (UMA) 2.0 Grant for OAuth 2.0 Authorization"
    target: https://docs.kantarainitiative.org/uma/wg/rec-oauth-uma-grant-2.0.html
    author:
      -
        ins: E. Maler
        name: Eve Maler
      -
        ins: M. Machulak
        name: Maciej Machulak
      -
        ins: J. Richer
        name: Justin Richer
    date: 2018
    seriesinfo:
      Kantara Initiative: Recommendation
  UMA-FEDAUTHZ:
    title: "Federated Authorization for User-Managed Access (UMA) 2.0"
    target: https://docs.kantarainitiative.org/uma/wg/rec-oauth-uma-federated-authz-2.0.html
    author:
      -
        ins: E. Maler
        name: Eve Maler
      -
        ins: M. Machulak
        name: Maciej Machulak
      -
        ins: J. Richer
        name: Justin Richer
    date: 2018
    seriesinfo:
      Kantara Initiative: Recommendation
  I-D.draft-mcguinness-oauth-mission:
    title: "Mission-Bound Authorization for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-oauth-mission-issuance-grant:
    title: "Mission Issuance Grant for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-issuance-grant.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-mission-substrate:
    title: "Mission Substrate Requirements"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-substrate.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026

informative:
  I-D.draft-mcguinness-mission-architecture:
    title: "An Architecture for Mission-Bound Authorization"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-architecture.html
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
  I-D.draft-mcguinness-mission-aauth:
    title: "Mission-Bound Authorization for AAuth"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-aauth.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-oauth-mission-approval:
    title: "Mission Deferred Approval for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-approval.html
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
  I-D.draft-mcguinness-oauth-mission-status:
    title: "Mission Status and Lifecycle for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-status.html
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
  I-D.draft-mcguinness-oauth-mission-consent-evidence:
    title: "Mission Consent Evidence for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-consent-evidence.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-mission-shaping:
    title: "Mission Intent Shaping"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-shaping.html
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
  I-D.draft-mcguinness-oauth-mission-progressive:
    title: "Mission Progressive Authorization for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-progressive.html
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
  I-D.draft-mcguinness-mission-metering:
    title: "Mission Consumption Metering"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-metering.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-mission-mandate:
    title: "Mission Mandate"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-mandate.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-mission-security-model:
    title: "Mission Security Model"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-security-model.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-mission-audit:
    title: "Mission Audit Transparency"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-audit.html
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
  I-D.draft-mcguinness-oauth-mission-attenuation:
    title: "Mission Offline Attenuation for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-attenuation.html
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

--- abstract

User-Managed Access (UMA) 2.0 standardized the plumbing of
asynchronous, party-asymmetric authorization: a requesting party and
client that can only request, a resource owner who approves at the
authorization server on their own schedule, a rotating permission
ticket carrying the pending request, claims pushing at the token
endpoint, a persisted claims token that carries continuity but grants
nothing, and per-use introspection at the resource server. It
deliberately left the object of that plumbing unspecified: the
authorization assessment is a black box, with no artifact of what was
approved, why, or within what bounds. This document supplies that
interior from the Mission model of Mission-Bound Authorization for
OAuth 2.0. The Mission Intent rides UMA claims pushing as a claim
token, the resource owner's decision is the approval event that
creates the Mission record with its integrity anchors, the Mission
lifecycle gates every RPT issuance and upgrade, the RPT is the
Mission-bound credential, and the persisted claims token is profiled
as Mission continuity that is never authority. This is the fourth
binding of the Mission model and the first authored against the
Mission Substrate Requirements contract. It is an experimental
sketch: the binding's shape and its Mission Substrate Statement are
fixed here, and wire-level completeness is deferred.

--- middle

# Introduction

User-Managed Access (UMA) 2.0 comprises two Kantara Initiative
Recommendations. The UMA grant {{UMA-GRANT}} extends OAuth 2.0 with a
party asymmetry OAuth does not have: the requesting party, on whose
behalf a client seeks access, is distinct from the resource owner,
who sets policy and decides submitted requests at the authorization
server, on the authorization server's own surface and schedule.
Federated authorization {{UMA-FEDAUTHZ}} standardizes the resource
server's contract with that authorization server: resource
registration, the permission endpoint, and extended token
introspection, under a protection API access token. Between them the
two documents standardize the plumbing of asynchronous,
party-asymmetric authorization: the tokenless first attempt, the
rotating permission ticket, claims pushing and interactive claims
gathering, the `request_submitted` deferral, the requesting party
token (RPT), and the persisted claims token (PCT).

What UMA deliberately does not standardize is the object at the
center. How the authorization server assesses a request, what the
resource owner approved, in what bounds, with what durable record,
under what lifecycle: all of it is unspecified policy behind the
token endpoint. The Mission model of
{{I-D.draft-mcguinness-oauth-mission}} (the "issuance profile") is a
specification of exactly that interior: a durable Mission record
created by an explicit approval event, integrity anchors committing
the approved task and its derived authority, a lifecycle whose
only-`active` rule gates issuance, and evidence surfaces built on
the record. This document binds the Mission model to the UMA 2.0
authorization server by filling UMA's assessment with the Mission.

Three mechanics the OAuth binding assembles from parts are native
here. The pushed Mission Intent rides UMA claims pushing at the
token endpoint rather than pushed authorization requests. The
asynchronous approval the OAuth binding reaches through the Mission
Deferred Approval companion, over the unratified OAuth Deferred
Token Response ({{I-D.draft-mcguinness-oauth-mission-approval}}), is
UMA's `request_submitted` with its rotating ticket, a ratified
surface. And the resource server's contract with the Mission Issuer
is the protection API, standardized by {{UMA-FEDAUTHZ}} rather than
assembled per deployment.

This is the fourth binding of the Mission model: the issuance
profile binds it to the OAuth Authorization Server, the Mission
Authority Server to a standalone service beside an unchanged AS
({{I-D.draft-mcguinness-mission-authority-server}}), the AAuth
binding to the AAuth Person Server
({{I-D.draft-mcguinness-mission-aauth}}), and this document to the
UMA 2.0 authorization server. Like the AAuth binding, it provides
issuance gating structurally: no RPT exists without passing the
authorization server's token endpoint. It is also the first binding
authored against the Mission Substrate Requirements contract
({{I-D.draft-mcguinness-mission-substrate}}) rather than one the
contract was extracted from; its Mission Substrate Statement
({{mission-substrate}}) is written to that document's conformance
rules, and exercising the checklist on a substrate none of its
source bindings resemble is part of this sketch's purpose.

## Attempt-First Operation {#inversion}

UMA inverts the OAuth binding's flow. The OAuth binding is
intent-first: the client submits the Mission Intent, approval
happens, and tokens follow. UMA is attempt-first: the client's first
move is a tokenless request at a resource server, and everything
else (the ticket, the claims, the approval) hangs off that attempt.
This binding preserves the model's compile-once property across the
inversion with one rule: the first ticket exchanged under a
prospective Mission carries the whole task as a pushed Mission
Intent, and the authorization server derives and obtains approval
for the full Authority Set, not the ticketed slice
({{mission-intent}}). Without that rule the Approver would meet the
Mission one resource-server slice at a time, which is the
consent-fatigue failure the model exists to prevent. The approved
set is then a ceiling, and each subsequent ticket a drawdown
adjudicated by policy within it, the shape the progressive companion
names ({{I-D.draft-mcguinness-oauth-mission-progressive}}).

## Applicability

This profile targets deployments that operate a UMA 2.0
authorization server implementing {{UMA-GRANT}} and {{UMA-FEDAUTHZ}}
and that route an agent's access through the UMA grant. The agent is
the UMA client; the accountable person is the resource owner.
Resource servers participate through plain UMA: registration,
permission requests, and introspection are unchanged, and a resource
server needs no Mission awareness beyond what introspection already
returns ({{credential}}). Both substrate documents are final Kantara
Initiative Recommendations; {{limitations}} discusses what that
dependency choice trades.

This document is an experimental sketch. It fixes the binding's
shape and its Mission Substrate Statement; worked test vectors and a
per-endpoint error taxonomy are deferred to a later revision.

## Conventions and Terminology

{::boilerplate bcp14-tagged}

All JSON and HTTP shown in this document is non-normative and
illustrative; the member definitions in the surrounding text are
authoritative.

This document uses Mission, Mission Intent, Mission Issuer,
Authority Set, Approver, Subject, `mission_id`, the integrity
anchors (`intent_hash` and `authority_hash`), the subset rule, the
only-`active` rule, and the audit horizon as defined by
{{I-D.draft-mcguinness-oauth-mission}}. It uses resource owner,
requesting party, client, permission ticket, claims pushing, claim
token, claims interaction endpoint, requesting party token (RPT),
persisted claims token (PCT), and the `need_info`,
`request_submitted`, and `request_denied` outcomes as defined by
{{UMA-GRANT}}, and resource server, protection API, protection API
access token (PAT), resource registration, permission endpoint, and
token introspection as defined by {{UMA-FEDAUTHZ}} and {{RFC7662}}.
It additionally uses:

Mission-Bound UMA Authorization Server:
: A UMA 2.0 authorization server conforming to this profile: it
  implements the Mission Issuer role behind its token endpoint and
  owner surfaces ({{conformance}}).

Mission-Bound UMA Client:
: A UMA client that proposes structured intent on its first ticket
  exchange under a prospective Mission and respects the Mission
  lifecycle ({{conformance}}).

# Mission Roles {#roles}

| UMA role | Mission model role |
|---|---|
| Authorization server | Mission Issuer: runs the assessment, holds the Mission record, gates RPT issuance, serves Mission state |
| Resource owner | Approver: sets policy and decides submitted requests |
| Requesting party | Subject: the party on whose behalf the client acts |
| Client | Agent: its OAuth client identifier is the Mission's `client_id` |
| Resource server | Resource Server: protection API participant, no Mission awareness required |

Two properties of this mapping are structural in UMA rather than
profile rules. First, the proposer is never the approver on the
wire: the client and the requesting party can only request, and
every grant of authority is made at the authorization server by the
resource owner or the owner's pre-registered policy. The issuance
profile's rule that the proposing party never approves is the
substrate's own geometry here. Second, both of the issuance
profile's approval modes are native UMA modes: pre-registered owner
policy at the authorization server is the authorized-policy approver
deciding at machine speed, and `request_submitted` is the human
Approver deciding asynchronously ({{approval}}).

UMA permits the requesting party and the resource owner to be the
same natural person, and in the agent deployments this profile
targets they usually are: the person's agent is the client, and the
person is both Subject and Approver, the core's default geometry.
Nothing in this binding requires them to differ.

# Mission Flow {#flow}

This section is informative. An agent holds the task "reconcile Q3
invoices at the finance service and file the summary at the document
service" for Alice, whose resources at both resource servers are
protected by the authorization server `https://as.example.com`.

1. The agent attempts a tokenless request at the finance resource
   server. The resource server registers the needed permissions at
   the authorization server's permission endpoint under its PAT and
   returns the permission ticket with the authorization server's
   location, per {{UMA-GRANT}}.
2. The agent presents the ticket at the token endpoint under
   `grant_type` `urn:ietf:params:oauth:grant-type:uma-ticket`,
   pushing the Mission Intent for the whole task, both services, as
   a claim token ({{mission-intent}}).
3. The authorization server gathers the requesting party's identity
   claims through UMA's ordinary channels (a pushed identity claim
   token, or interactive claims gathering at the claims interaction
   endpoint), accumulating across ticket rotations.
4. The authorization server derives the full Authority Set from the
   Intent, renders it for consent on its owner surface, and returns
   `request_submitted` with a rotated ticket: the decision is
   deferred to Alice ({{approval}}).
5. Alice approves on the owner surface. The Mission record is
   created `active`, the anchors are committed, and Consent
   Evidence is recorded.
6. The agent retries the ticket and receives an RPT carrying the
   finance permissions, the first drawdown of the approved ceiling,
   plus a PCT ({{pct}}).
7. Later the agent attempts the document service. The new ticket
   goes to the token endpoint with the PCT and the existing RPT for
   upgrading; the authorization server resolves the Mission through
   the PCT, checks the requested permissions against the Authority
   Set, and approves by policy without waking Alice ({{drawdown}}).
   The upgraded RPT carries both services' permissions.
8. Each resource server introspects the RPT per use. Revoking the
   Mission at the authorization server takes effect at the next
   introspection everywhere: one Mission, compiled once, projected
   per resource server, killed in one place.

# Mission Intent {#mission-intent}

The Mission Intent reaches the authorization server through claims
pushing: it rides the existing `claim_token` parameter of the token
endpoint's UMA grant, and this binding defines no new endpoint or
parameter.

A Mission Intent claim token is a JWT whose payload carries a
`mission_intent` claim: a Mission Intent object as the issuance
profile defines it, under that profile's syntactic rules (the object
is closed at the top level, the authorization server MUST bound its
size and array lengths, and it is untrusted client input, never
authority). The JWT MAY be signed by the client for attribution; a
signature confers no authority. Its `claim_token_format` identifier
is:

~~~ text
https://mcguinness.github.io/mission-bound-authorization/uma-intent-jwt
~~~

A Mission-Bound UMA Client MUST push the Mission Intent on the first
ticket exchange it performs under a prospective Mission, and the
Intent MUST describe the whole task, not the slice the ticket's
registered permissions name. The authorization server derives the
Authority Set from the Intent, bounded by the issuance profile's
Mission Authority rules; the ticket's permissions locate the first
drawdown, not the Mission's extent ({{inversion}}). A ticket
exchange with no pushed and no PCT-resolved Mission context is plain
UMA, outside this profile's scope.

The Intent is one claim token among UMA's ordinary ones. The
requesting party's identity claims arrive through their own channels
(a pushed identity token or interactive claims gathering), in the
same or other rounds of the `need_info` rotation loop; the
authorization server MUST NOT take the Subject from the Mission
Intent claim token, which is unauthenticated client input
({{approval}}).

The proposal is the shaping profile's Mission Intent proposal, and a
deployment that shapes free-text instructions into structured
Intents composes here unchanged
({{I-D.draft-mcguinness-mission-shaping}}).

# Mission Approval {#approval}

UMA's authorization assessment is this binding's approval surface.
Where the assessment concludes that a new Mission is proposed, it
executes the issuance profile's approval steps:

1. Authenticate the Approver: the resource owner at the
   authorization server, or the principal whose pre-registered
   policy the deployment authorizes to decide. When the Intent
   carries `controls.acr`, the authentication MUST be one the
   deployment's policy maps as satisfying the named class.
2. Establish the Subject: the requesting party, from claims the
   authorization server itself gathered and verified (pushed
   identity claim tokens, interactive claims gathering, or a PCT it
   previously issued), never from the Mission Intent claim token or
   other unauthenticated client input.
3. Derive the Authority Set from the Intent ({{mission-intent}})
   and render it for consent on the owner surface under the
   issuance profile's rendering rules ({{security-rendering}}).
4. Compute the integrity anchors with the authorization server's
   issuer identifier as the envelope `iss`.
5. Create the Mission record in the `active` state atomically with
   the approval decision. The token endpoint MUST NOT complete a
   ticket exchange under the Mission before the record is `active`.

Both native assessment outcomes realize the approval event:

**Deferred owner decision.** The authorization server returns
`request_submitted` with a rotated permission ticket, and the
resource owner decides on the owner surface asynchronously; the
client retries under UMA's own discipline. The rotating ticket is
the deferral handle ({{security-ticket}}). This is the surface the
OAuth binding needs the Mission Deferred Approval companion for
({{I-D.draft-mcguinness-oauth-mission-approval}}); here it is the
substrate's ratified machinery, and that companion does not apply.

**Pre-registered policy.** Where the resource owner's standing
policy at the authorization server covers the proposal, that policy
is the issuance profile's authorized-policy approver: the approval
event records the policy identity and version as the Approver
context, and the anchors commit as in the interactive case. A
deployment SHOULD reserve policy approval for Missions within bounds
the owner has expressly pre-consented and route everything else to
`request_submitted`.

The `need_info` rotation loop is the clarification and narrowing
surface: the authorization server may require further claims, and
the owner or the authorization server may narrow the proposal across
rounds while the rotating ticket persists the pending state. That
loop is most of the state machine the approval-revision companion
defines, native to the substrate
({{I-D.draft-mcguinness-oauth-mission-approval-revision}}); where a
deployment adopts that companion's semantics, the rotated ticket is
its revision handle. If the derived Authority Set changes between
rendering and consent, the authorization server MUST recompute the
anchors and re-obtain consent, per the issuance profile.

Mission Consent Evidence composes unchanged, with the authorization
server as the committing issuer
({{I-D.draft-mcguinness-oauth-mission-consent-evidence}}): the owner
surface is where the disclosure is rendered, and what was shown is
what the evidence commits.

# Mission Record {#mission-record}

UMA has no native artifact for what was approved; the Mission record
supplies it. A Mission-Bound UMA Authorization Server MUST create a
Mission record, as the issuance profile's Mission Record section
defines it, for every Mission it approves, with `issuer` its own
issuer identifier (the `issuer` of its UMA discovery document) and
`client_id` the client's OAuth client identifier. `expires_at` is
REQUIRED, in RFC 3339 {{RFC3339}} date-time form; when the
proposal's Intent carries none, the authorization server MUST set
one by policy.

Unlike the AAuth binding, whose substrate carries a native
(`approver`, `s256`) reference
({{I-D.draft-mcguinness-mission-aauth}}), UMA has no wire-native
mission artifact to commit. The record is held at the authorization
server, `mission_id` and `issuer` name the Mission, and consumers
meet the reference in the RPT's `mission` claim or the introspection
response ({{credential}}). No substrate-native commitment exists
beside the anchors, and nothing substitutes for them.

# Mission Lifecycle {#lifecycle}

The Mission lifecycle is the issuance profile's state space,
extended by the status profile where the deployment adopts it
({{I-D.draft-mcguinness-oauth-mission-status}}), with the
only-`active` rule governing every authorization-server surface and
unrecognized states fail-safe non-active.

| Family state | UMA surface |
|---|---|
| `active` | token endpoint serves ticket exchanges and upgrades; introspection reports the RPT active |
| `completed` | token endpoint refuses (`request_denied`); introspection reports inactive |
| `revoked` | token endpoint refuses (`request_denied`); introspection reports inactive |
| `expired` | token endpoint refuses (`request_denied`); introspection reports inactive |
| `suspended` | token endpoint defers (`request_submitted`); introspection reports inactive |

The projection is fail-safe: every non-`active` state projects to a
non-permitting native signal. The family surfaces report the
distinct state, and the introspection response's `mission.state`
member carries it verbatim ({{mission-claim}}). This binding adds to
UMA's model:

- **Revocation.** The authorization server MUST provide an
  authenticated means for the Subject, the Approver, or an
  administrator to revoke a Mission by `mission_id`, independent of
  any token, per the issuance profile. Because resource servers
  introspect RPTs per use ({{UMA-FEDAUTHZ}}), revocation takes
  effect at the next introspection with no further plumbing; a
  deployment that validates RPTs without introspection needs the
  state surfaces below.
- **Expiry.** When the record's `expires_at` passes, the Mission
  transitions to `expired` without a request.
- **Completion.** The authorization server commits the Mission to
  `completed` with the semantics of the status profile's `complete`
  operation. UMA has no native completion wire, so the operation is
  a family surface.
- **Suspension.** A deployment that adopts the status profile's
  `suspended` state defers rather than denies: the token endpoint
  returns `request_submitted`, so the client waits under UMA's own
  retry discipline rather than treating the Mission as dead.

## Issuance Gating {#gating}

No RPT exists without the authorization server's token endpoint, so
issuance gating is structural, as it is at the AAuth Person Server.
On that precondition the authorization server MUST NOT complete a
ticket exchange, upgrade an RPT, or otherwise extend authority under
a Mission that is not `active`, and the `active` check MUST be
atomic with issuance. Each RPT issuance and each upgrade counts as
one derivation under the Mission; where the Intent's
`controls.max_derivations` is present, the authorization server MUST
refuse the derivation that would exceed it, per the issuance
profile's count-and-gate rule. An RPT issued under a Mission MUST
NOT expire later than the Mission's `expires_at`, and the `exp` of
each permission within it is likewise capped, so no credential
outlives the Mission.

## Mission State Surfaces {#state-surfaces}

Per-use introspection is this binding's native state source: a
response for an RPT under a Mission carries the `mission` member
with its `state` ({{mission-claim}}), so a resource server that
introspects per {{UMA-FEDAUTHZ}} learns of revocation at the next
access. Its staleness bound is the introspection caching the
deployment permits, which the deployment MUST state; with caching
disabled the bound is effectively zero.

A deployment whose RPTs are self-contained and validated without
introspection loses that source, and MUST either cap RPT lifetime at
its declared staleness bound (lifetime-bounded reliance) or serve an
active state surface. A Mission-Bound UMA Authorization Server
SHOULD serve the Mission Status operation of
{{I-D.draft-mcguinness-oauth-mission-status}}, with its signed
responses, authentication, anti-oracle property, and caching rules,
and MAY emit Mission Lifecycle Signals
({{I-D.draft-mcguinness-oauth-mission-signals}}) as the transmitting
Mission Issuer. A deployment claiming runtime enforcement of the
high-consequence classes MUST provide an active freshness source
with a published staleness bound
({{I-D.draft-mcguinness-mission-runtime}}); per-use introspection
with a stated cache bound satisfies it, and token lifetime alone
does not.

An authorization server that serves these surfaces publishes the
corresponding members (`mission_status_endpoint`,
`mission_status_signing_alg_values_supported`,
`mission_lifecycle_endpoint`, `mission_event_stream_endpoint`,
`mission_max_stale_seconds`) in its UMA discovery document, with the
semantics those profiles define; its existing `jwks_uri` is the
published key material for its signed artifacts.

# Mission-Bound Credential {#credential}

The RPT is this binding's Mission-bound credential.

## The Mission Claim {#mission-claim}

An RPT issued under a Mission names it through the `mission` claim:
the family members `id`, `issuer`, and `authority_hash` as the
issuance profile defines them, and it SHOULD carry the `expires_at`
member as the issuance-grant profile defines it
({{I-D.draft-mcguinness-oauth-mission-issuance-grant}}), a bounding
commitment with no liveness. The claim is delivered on one of two
carriage surfaces:

- **Token-carried**: a deployment issuing JWT-format RPTs carries
  the claim in the token per the issuance profile.
- **Introspection-carried**: a deployment issuing opaque RPTs
  carries the same object in the `mission` member of the
  introspection response, the member the issuance profile registers
  for {{RFC7662}}, with the `state` member per that profile's
  introspection section. FedAuthz's extended introspection object
  carries it beside `permissions` unchanged.

Both surfaces satisfy the credential primitive; they differ in who
verifies what. A token-carried claim verifies offline under the
authorization server's published keys; an introspection-carried
claim is asserted by the authorization server over the authenticated
protection API channel at each use. In both, the Mission reference
arrives through token validation itself, so the runtime profile's
binding establishment composes credential-carried with no join
({{mission-substrate}}). A consumer MUST NOT use any `mission`
member to grant or widen authority, per the issuance profile.

## Authority Subset and Grain {#subset}

The permissions an RPT carries MUST be a subset of the Mission's
Authority Set under the issuance profile's subset rule, projected
onto UMA's grain: a permission is a resource and its scopes, so
every scope a permission grants MUST correspond to authority the set
grants at that resource, and no permission may convey authority, or
relaxation of a constraint, that the set does not.

The projection is coarse, and this binding does not pretend
otherwise. A UMA permission carries no parameter bounds and no
consumption bounds: an amount cap on a payment action, argument
constraints on a tool call, and the metering companion's cumulative
bounds ({{I-D.draft-mcguinness-mission-metering}}) do not fit a
`resource_scopes` array. Those constraints bind at the runtime
layer, where the PDP evaluates each consequential action against the
full Authority Set ({{I-D.draft-mcguinness-mission-runtime}},
{{I-D.draft-mcguinness-mission-authzen}}); the substrate swap leaves
that layer untouched ({{limitations}}). An RPT MAY additionally
carry Mission-derived authorization details entries per the issuance
profile where the deployment's RPT format admits them, under the
same subset rule.

## Drawdown and Upgrade {#drawdown}

The approved Authority Set is a pre-consented ceiling, and each RPT
issuance or upgrade is a drawdown within it: the model the
progressive companion defines for the OAuth binding
({{I-D.draft-mcguinness-oauth-mission-progressive}}), which this
substrate runs natively. When the client presents a new ticket with
its existing RPT and PCT, the authorization server resolves the
Mission, checks the requested permissions against the Authority Set,
and where they are within it MAY approve by policy without waking
the Approver: that adjudication is a drawdown, not a new approval,
and the anchors do not change. The upgraded RPT replaces the prior
one and stays bounded per {{gating}}.

A requested permission outside the Authority Set is an expansion,
not a drawdown. The authorization server MUST NOT widen by policy:
it routes the request to the Approver (`request_submitted`), and an
approval revises the Mission under the expansion companion's
semantics, recomputed anchors included
({{I-D.draft-mcguinness-oauth-mission-expansion}}). The wire needs
nothing new: widening is another ticket the owner must decide.

## Mission Continuity: the PCT {#pct}

The persisted claims token is UMA's continuity artifact: it persists
the requesting party's claims across authorization processes and
grants nothing; every RPT still passes fresh assessment. That is the
family's session-continuity discipline (continuity is never
authority, as the harness profile enforces for agent sessions
({{I-D.draft-mcguinness-mission-harness}})), pre-enforced by the
substrate's own design. This binding leans on it: the authorization
server SHOULD associate a PCT it issues under a Mission with the
`mission_id`, so a later ticket presented with the PCT resolves the
Mission without the client re-pushing the Intent. The PCT is the
Mission continuation handle.

Continuity is never authority. PCT possession MUST NOT substitute
for Mission state, for the subset check, or for any approval; a PCT
presented under a non-active Mission yields `request_denied` (or
`request_submitted` under suspension), and a PCT never widens what
assessment would grant without it ({{security-pct}}).

## Worked Example {#credential-example}

The introspection response for the upgraded RPT of {{flow}}, after
the document-service drawdown:

~~~ json
{
  "active": true,
  "exp": 1793610000,
  "permissions": [
    { "resource_id": "finance-q3-ledger",
      "resource_scopes": ["invoices.read", "adjustments.post"],
      "exp": 1793610000 },
    { "resource_id": "board-reports",
      "resource_scopes": ["documents.write"],
      "exp": 1793610000 }
  ],
  "mission": {
    "id": "msn_4Xq7NvR2pTb8Kd1zYw6mA3f5",
    "issuer": "https://as.example.com",
    "authority_hash":
      "sha-256:Qm4dSrX0kJc2uJ9pVzWfY7hTgD1eN8oLxCAiRb63EMk",
    "expires_at": "2026-12-31T23:59:59Z",
    "state": "active"
  }
}
~~~

The `permissions` member is FedAuthz's, unchanged; the `mission`
member is the issuance profile's registered introspection member.
The two permissions are the scope-grain projection of the Mission's
Authority Set entries at each resource server; the amount bound on
`adjustments.post` does not appear, because UMA's grain cannot carry
it, and it binds at the runtime layer instead ({{subset}}).

# Mission Substrate {#mission-substrate}

This section is this binding's Mission Substrate Statement
({{I-D.draft-mcguinness-mission-substrate}}).

1. **Provision level**: full provision. The RPT is the Mission-bound
   credential, and issuance gating is structural at the token
   endpoint ({{gating}}); no join is defined or needed.
2. **Identifier and issuer**: `mission_id` on the record; `issuer`
   the `issuer` of the authorization server's UMA discovery
   document. No substrate-native Mission reference exists; the
   `mission` claim and introspection member carry the family
   reference ({{mission-record}}, {{mission-claim}}).
3. **Lifecycle and state sources**: the issuance profile's states
   with the only-`active` rule, fail-safe unrecognized states, and
   fail-safe projection onto UMA's token-endpoint outcomes
   ({{lifecycle}}). State sources: per-use introspection, with the
   deployment's declared cache bound as its staleness bound; the
   Mission Status operation where served; and RPT lifetime as the
   floor for self-contained validation ({{state-surfaces}}).
4. **Authority Set carriage**: the record at the authorization
   server; RPT permissions are its coarse projection, with every
   narrowing at the token endpoint ({{subset}}, {{drawdown}}); the
   full set is served to consumers that need it through the Status
   operation or a Mission Mandate
   ({{I-D.draft-mcguinness-mission-mandate}}).
5. **Integrity anchors**: the family envelope and canonicalization
   with the authorization server's issuer identifier as the envelope
   `iss`; no native commitment exists beside the anchors, and
   nothing substitutes for them ({{mission-record}}).
6. **Key material**: the `jwks_uri` of the UMA discovery document
   ({{state-surfaces}}).
7. **Audit horizon**: deployment-declared; the Mission record, the
   assessment log, and consent evidence are retained for it.
8. **Approval fidelity**: the assessment surface executes the five
   approval steps across UMA's two native decision modes
   ({{approval}}).

The composition consequences:

- The runtime profile and its AuthZEN binding compose against either
  carriage surface: the Mission reference arrives through token
  validation (JWT claims, or the issuer's introspection response
  that validates the opaque RPT), so binding establishment is
  credential-carried in both ({{mission-claim}}). The constraint
  grain UMA cannot carry is exactly what they enforce ({{subset}}).
- Shaping, consent evidence, status and signals, the Mandate, and
  audit transparency ({{I-D.draft-mcguinness-mission-audit}})
  compose unchanged, with the authorization server as the Mission
  Issuer, committing issuer, minter, and transmitter those profiles
  name.
- Child delegation does not apply as profiled: its request wire is
  OAuth-bound
  ({{I-D.draft-mcguinness-oauth-mission-child-delegation}}), and UMA
  has no actor chain. A sub-agent operates as its own UMA client
  under its own ticket exchanges; UMA-native Child Mission creation
  is deferred work.
- Offline attenuation does not apply: every RPT is issuer-minted,
  and UMA defines no offline mint
  ({{I-D.draft-mcguinness-oauth-mission-attenuation}}).
- Cross-domain projection is not provided: FedAuthz federates a
  resource server to an authorization server, not one Mission Issuer
  to another, so projecting a Mission into a foreign issuer remains
  the cross-domain companion's OAuth-bound mechanism
  ({{I-D.draft-mcguinness-oauth-mission-cross-domain}}). FedAuthz's
  federation does mean one Mission natively governs many resource
  servers within the authorization server's own trust domain, the
  multi-resource-server case the flow shows ({{flow}}).
- The family's Mission Assurance Levels layer on top unchanged
  ({{I-D.draft-mcguinness-mission-architecture}}); a deployment
  states its level, binding, state sources, and staleness bounds in
  its Mission Deployment Profile.

# Limitations {#limitations}

**Authority grain.** UMA's unit of authority is the permission, a
resource and its scopes. The Authority Set's parameter-bound actions
and consumption bounds cannot ride it, so the RPT is always a coarse
projection, and the runtime layer carries the constraint enforcement
this family treats as load-bearing ({{subset}}). The substrate swap
replaces approval and issuance plumbing; it does not move the action
chokepoint.

**Attempt-triggered approval.** The approval moment is the first
ticket exchange, not a moment the client chooses before acting. The
whole-task Intent rule ({{mission-intent}}) preserves compile-once,
but the Approver decides when the agent first collides with a
protected resource. A deployment that wants approval before the run
starts fronts the flow with a deliberate first attempt, or uses an
intent-first binding.

**Substrate reach.** Both UMA documents are final Kantara Initiative
Recommendations, so this binding adds no unratified dependency: the
trade is the reverse of the AAuth binding's, which tracks an
unratified individual draft with an active community
({{I-D.draft-mcguinness-mission-aauth}}). What UMA lacks is deployed
breadth. This binding governs estates that already run UMA; it does
not create them, and a deployment without a UMA substrate has no
reason to adopt one for the Mission's sake, since the OAuth binding
exists.

# Conformance {#conformance}

An implementation conforms in one of two roles. Resource servers
participate through unmodified {{UMA-FEDAUTHZ}} and have no role to
claim.

A **Mission-Bound UMA Authorization Server**:

- accepts the Mission Intent claim token format and bounds it as
  untrusted input ({{mission-intent}});
- executes the approval event on its assessment surface in both
  native decision modes, creating the record `active` atomically
  with the decision and computing the anchors ({{approval}},
  {{mission-record}});
- operates the lifecycle of {{lifecycle}}: authenticated revocation
  by `mission_id`, expiry, completion, fail-safe projection onto
  token-endpoint outcomes, and the only-`active` gate atomic with
  every issuance and upgrade ({{gating}});
- issues RPTs as Mission-bound credentials on a declared carriage
  surface, applies the subset rule at every issuance and upgrade,
  and routes out-of-set requests to the Approver ({{credential}});
- associates PCTs with Missions as continuity, never authority
  ({{pct}});
- serves Mission state with a declared staleness bound per
  {{state-surfaces}}, and retains the record and assessment log for
  the audit horizon; and
- publishes its Mission surfaces in its UMA discovery document.

A **Mission-Bound UMA Client**:

- pushes a whole-task Mission Intent on the first ticket exchange
  under a prospective Mission, and treats every proposal as a
  proposal, never as authority ({{mission-intent}});
- follows UMA's retry discipline under `request_submitted` and
  `need_info`, and stops on `request_denied`;
- presents the PCT for continuity and never treats it, the ticket,
  or `mission_id` as a credential; and
- proposes completion when the task is done, where the deployment
  serves the completion operation.

# Security Considerations

## The Ticket as Deferral Handle {#security-ticket}

Between `request_submitted` and the owner's decision, the rotating
permission ticket is the only artifact binding the client to the
pending approval: the role the deferral code plays in the Mission
Deferred Approval companion
({{I-D.draft-mcguinness-oauth-mission-approval}}). UMA's ticket
properties (single-use, unguessable, rotated on every response) are
load-bearing for the approval's integrity, and an authorization
server MUST maintain them across the rotation loop. A replayed or
long-lived ticket would let a stale or hijacked exchange complete
against a decision the owner made about a different pending state.

## Rendering the Proposal {#security-rendering}

The Mission Intent, its goal text, and every justification are
attacker-influenceable input rendered on the owner surface. The
issuance profile's rendering rules apply unchanged: render client
text inert and sanitized, mitigate direction-override and
confusable-character presentation, and keep the derived Authority
Set visually distinct from client-supplied narrative, so crafted
text cannot pass as derived authority.

## The PCT Is Not Authority {#security-pct}

The PCT is a bearer continuity artifact held by the client. Its
theft replays claims continuity, not authority: assessment still
runs, state still gates, and the subset rule still bounds. An
authorization server MUST keep it that way; an optimization that
lets a PCT skip state evaluation or the subset check converts a
continuity token into a credential and breaks the family's
continuity discipline ({{pct}}). UMA's own PCT rules on client
binding and rotation apply.

## Authorization Server Compromise {#security-as-compromise}

A compromised authorization server is a compromised Mission Issuer:
forged approvals, arbitrary RPTs, false state
({{I-D.draft-mcguinness-mission-security-model}}). UMA concentrates
approval, issuance, introspection, and the owner surface in one
service, so the security model's concentration analysis for the
OAuth binding applies in full. Consent evidence and audit
transparency make forgery detectable after the fact; they do not
prevent it.

## Introspection as the State Channel {#security-introspection}

Where opaque RPTs make introspection the Mission and state channel,
the channel's authentication (the PAT) and its caching policy carry
this binding's freshness claims. A resource server that caches
introspection responses beyond the deployment's declared staleness
bound turns fail-closed rules fail-open in effect; a deployment MUST
size PAT protection and cache bounds to what its Mission Deployment
Profile claims. Self-contained RPTs move the same weight onto token
lifetime ({{state-surfaces}}).

# Privacy Considerations

**The task concentrates at the authorization server.** The
whole-task Intent rule sends the full task description to the
authorization server at the first exchange, earlier and more
completely than per-slice operation would. That is deliberate, and
it is the concentration the issuance profile's record already
implies; the shaping profile's minimization guidance applies to what
the Intent says.

**Resource servers see little.** An opaque RPT shows a resource
server only the permissions relevant to it plus the `mission`
introspection members; the Intent, the constraints, and the rest of
the Authority Set stay at the authorization server. This is the
minimization property the AAuth binding notes for its blob, achieved
here by UMA's own architecture.

**The PCT is a correlation handle.** UMA already names the PCT a
correlation surface across authorization processes; associating it
with a `mission_id` ({{pct}}) adds Mission correlation at the
authorization server only, and nothing new crosses to resource
servers. `mission_id` itself correlates the Mission's activity
across resource servers through introspection responses, the
issuance profile's deliberate stable-anchor property; that profile's
guidance applies.

# IANA Considerations {#iana}

This document has no IANA actions. The `mission` introspection
response member and the `mission` JWT claim are registered by the
issuance profile; UMA `claim_token_format` identifiers are URIs with
no registry, and the identifier of {{mission-intent}} is under this
document's control.

--- back

# Acknowledgments
{:numbered="false"}

This document is part of the Mission-Bound Authorization work. It
binds the Mission model to the User-Managed Access 2.0 authorization
server, and builds on the Mission Substrate Requirements, Mission
Status and Lifecycle, and Mission-Bound Runtime Enforcement
companions. UMA's requesting-party asymmetry, deferred owner
decisions, and continuity-without-authority anticipated the geometry
agents now present; this binding supplies the approved object those
mechanics were built to move.
