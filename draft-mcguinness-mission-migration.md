---
title: "Mission-Bound Authorization Migration Guide"
abbrev: "Mission Migration"
category: info

docname: draft-mcguinness-mission-migration-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
keyword:
 - mission
 - authorization
 - oauth
 - migration
 - adoption
 - governance
venue:
  github: "mcguinness/mission-bound-authorization"
  latest: "https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-migration.html"

author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com

normative:
  RFC2119:
  RFC8174:
  I-D.draft-mcguinness-mission-framework:
  I-D.draft-mcguinness-mission-oauth-profile:

informative:
  RFC6749:
  RFC6750:
  RFC7009:
  RFC7662:
  RFC8414:
  RFC8693:
  RFC8705:
  RFC9068:
  RFC9126:
  RFC9396:
  RFC9449:
  RFC9700:
  RFC9728:
  I-D.draft-ietf-oauth-identity-chaining:
  I-D.draft-ietf-oauth-identity-assertion-authz-grant:
  I-D.draft-mcguinness-oauth-id-continuation-assertion:

--- abstract

This document is an operational migration guide for an existing
OAuth 2.0 deployment adopting Mission-Bound Authorization. It
defines a Stage 0 through Stage 5 incremental adoption path. Each
stage names what the Authorization Server ships, what (if anything)
clients and Resource Servers change, what is observed versus
enforced, and what compatibility hazards apply. The guide makes no
new normative wire requirements beyond what the Mission Framework
and Mission-Bound OAuth Profile already specify; it provides
deployment guidance for sequencing the adoption of those
specifications.

--- middle

# Introduction

The Mission Framework {{I-D.draft-mcguinness-mission-framework}}
defines the Mission as a durable, integrity-anchored,
lifecycle-governed governance object for an approved task. The
Mission-Bound OAuth Profile
{{I-D.draft-mcguinness-mission-oauth-profile}} binds that object
to the OAuth 2.0 substrate: Mission Intent submitted through PAR
{{RFC9126}}, derived authority carried as `authorization_details`
{{RFC9396}}, a `mission` JWT claim on access tokens, sender-
constrained issuance via DPoP {{RFC9449}} or mTLS {{RFC8705}},
Token Exchange {{RFC8693}} gated on Mission state, and a dedicated
Mission Status operation distinct from token introspection
{{RFC7662}}.

A deployment that already runs OAuth 2.0 cannot reach this end
state in a single change. Clients, Authorization Servers, and
Resource Servers (per RFC 9728 {{RFC9728}}) have independent
release cadences; forcing all of them to move at once converts a
sequencing problem into an outage.

This document defines an incremental adoption path. Each stage
preserves backward compatibility. A deployment exits Stage 0 by
enabling Mission recording, gates derivation on Mission state in
Stage 2, derives authority from the approved Mission in Stage 3,
and continues through Resource Server uptake (Stage 4) and
cross-AS continuity (Stage 5). The end state is the Mission-Bound
OAuth Profile as written; the path is sequenced so each step has
a defensible rollback.

The Framework and OAuth Profile are the destinations. Where they
already specify a wire artifact, this guide cites it rather than
restating it. Where this guide uses BCP 14 keywords, the keywords
apply to the operational practice (the recommended order of
adoption), not to the wire (which is owned by the Framework and
the OAuth Profile).

## Audience and scope

This document is written for the operator of an existing OAuth
2.0 Authorization Server deployment. It assumes familiarity with
RFC 6749 {{RFC6749}}, RFC 6750 {{RFC6750}}, RFC 9068 {{RFC9068}},
PAR {{RFC9126}}, RAR {{RFC9396}}, Token Exchange {{RFC8693}},
sender-constrained credentials (DPoP {{RFC9449}} or mTLS
{{RFC8705}}), and the OAuth 2.0 Security BCP {{RFC9700}}.

The path described here is OAuth-substrate-centric. Deployments
on the AAuth substrate, or deployments adopting the Mission
Authority Server (MAS) topology, follow analogous stages through
their respective profiles; this guide does not enumerate those
paths.

This guide does not define new wire parameters, claims, error
codes, registries, or endpoints; wire-level normative
requirements live in
{{I-D.draft-mcguinness-mission-framework}} and
{{I-D.draft-mcguinness-mission-oauth-profile}}. It does not
replace per-deployment risk analysis, specify test vectors, or
address runtime per-action enforcement beyond the OAuth Profile's
enforcement classes.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

Terms from {{I-D.draft-mcguinness-mission-framework}} (Mission,
Mission Proposal, Authority Set, `mission` claim, Mission Status,
state authority, integrity anchor, canonical and pairwise Mission
reference) and from
{{I-D.draft-mcguinness-mission-oauth-profile}} (`mission_intent`,
`mission_resource_access`, `mission_inactive`, enforcement
classes `issuance`, `introspection`, `event_driven`,
`per_request`, `mission_max_stale_seconds`) are inherited
unchanged.

This document uses the following operational terms:

**Pre-Mission deployment**:
: An OAuth 2.0 deployment without any Mission-Bound capabilities
enabled. The Stage 0 baseline.

**Shadow Mission**:
: A Mission record created and maintained alongside an existing
OAuth flow whose issuance is unaffected by Mission state. Used to
validate Mission recording before enforcement.

**Gating**:
: Refusing a derivation (refresh, Token Exchange, ID-JAG issuance)
when Mission state disallows it. Gating produces the
`mission_inactive` error from the OAuth Profile.

**Narrowing**:
: Deriving `authorization_details` from the approved Authority
Set, per the narrowing rules registered for each Authority Set
entry type.

**RS-A / RS-B / RS-C**:
: Resource Server tiers used informally in this guide to describe
uptake order: an RS-A consumes the access token only as a bearer
of authority (no Mission awareness); an RS-B reads Mission state
from token introspection or accepts pushed Mission-state events;
an RS-C queries Mission Status per request for high-assurance
operations. These map onto the enforcement classes the AS
advertises per {{I-D.draft-mcguinness-mission-oauth-profile}}.

# Migration Path at a Glance

| Stage | What ships at the AS | Client changes | RS changes | First enforcement |
|---|---|---|---|---|
| 0 | Existing OAuth 2.0 | None | None | None (baseline) |
| 1 | Shadow Mission recording | None | None | None (audit only) |
| 2 | Gate refresh and exchange on Mission state | None | None | Refresh/exchange refused for revoked or suspended Missions |
| 3 | Derive `authorization_details` from approved Authority Set | Submit Mission Intent through PAR | None | Issued scope narrows to approved authority |
| 4 | Resource Server uptake of Mission state | None additional | Read Mission snapshot; optionally per-request Mission Status | RS-level revocation propagation |
| 5 | Cross-AS continuity | Optional Token Exchange and ID-JAG carriage | Optional resource-side Mission consumption | Mission state preserved across AS hops |

Each stage is additive. A deployment SHOULD complete each stage
before beginning the next, but MAY run two adjacent stages
concurrently across distinct tenants or audiences when the
deployment can independently roll back each.

# Stage 0: Where You Are Today

## Existing OAuth deployment baseline

Stage 0 is the pre-Mission OAuth 2.0 deployment. It includes
some subset of: authorization and token endpoints (RFC 6749
{{RFC6749}}); bearer or sender-constrained access tokens (RFC
6750 {{RFC6750}}, with DPoP {{RFC9449}} or mTLS {{RFC8705}}
where deployed); JWT access tokens (RFC 9068 {{RFC9068}}) or
opaque tokens introspected via RFC 7662 {{RFC7662}}; Token
Exchange (RFC 8693 {{RFC8693}}); PAR (RFC 9126 {{RFC9126}}) and
RAR (RFC 9396 {{RFC9396}}) where adopted; token revocation
(RFC 7009 {{RFC7009}}); AS metadata (RFC 8414 {{RFC8414}}) and
Protected Resource Metadata (RFC 9728 {{RFC9728}}).

Authority in Stage 0 is carried by `scope`, or by typed
`authorization_details` entries that the deployment defined ad
hoc.

## Pre-Mission state

In Stage 0, no Mission record exists for any approved task.
Revocation is per token or per refresh family; there is no
Mission Status operation; tokens do not carry a `mission` claim;
there is no `mission_intent` parameter; and Resource Servers
have no Mission lifecycle event channel.

A deployment SHOULD audit its Stage 0 surface before beginning
Stage 1: inventory clients and target which will submit Mission
Intent in Stage 3; classify Resource Servers by target tier
(RS-A, RS-B, or RS-C) for Stage 4 planning; confirm PAR
deployability (the OAuth Profile requires `mission_intent`
submission through PAR); confirm DPoP or mTLS deployability
(the OAuth Profile requires sender-constrained issuance); and
identify the planned state authority origin
(`mission.origin`) and its metadata document location.

A deployment that cannot satisfy the OAuth 2.0 Security BCP
{{RFC9700}} in Stage 0 SHOULD address those issues before
adopting Mission-Bound semantics. Mission-Bound Authorization
adds governance; it does not substitute for the credential-grade
protections the underlying OAuth deployment already requires.

# Stage 1: Shadow Mission

## Goal

Record a Mission in parallel with existing OAuth flows. Validate
that the Mission data model, integrity anchors, and Mission
Status operation work end to end without affecting any issued
credential.

## What ships

The AS gains the following, non-enforcing:

- A state authority module that creates a Mission Proposal when
  a client interaction implies one. The AS MAY synthesize Mission
  Intent from the authorization request's scope, resource
  parameter, and any RAR entries already present.
- An approval-event hook on the authorization endpoint that
  promotes a Proposal to a Mission per the approval-event
  semantics in {{I-D.draft-mcguinness-mission-framework}}.
- A Mission record store computing `proposal_hash`,
  `authority_hash`, and `consent_disclosure_hash` per the
  Framework's domain-separated, authorization-domain-bound hash
  rules.
- The Mission Status operation per
  {{I-D.draft-mcguinness-mission-oauth-profile}}, returning
  records for shadow Missions to authorized callers.
- AS metadata extensions advertising `mission_status_endpoint`,
  `mission_intent_schema_uri`, `authority_set_types_supported`,
  and `mission_framework_versions_supported`. Enforcement-class
  metadata is omitted at this stage, indicating no enforcement.

The AS continues issuance by its existing logic. Tokens do not
yet carry a `mission` claim. Mission state has no effect on any
issuance decision.

## What clients and Resource Servers change

Nothing required at clients or Resource Servers. Clients MAY
begin to send `mission_intent` through PAR; the AS does not
require it.

## Exit criteria

A deployment exits Stage 1 when:

- The AS reliably creates Mission Proposals and Missions for the
  flows targeted in this stage.
- Integrity-anchor computation matches the Framework reference
  test vectors.
- Mission Status responses pass the authentication, freshness,
  audience, and integrity properties from the Framework.
- Operators can audit Mission records and trace each to its
  originating authorization request without depending on the
  issued credential.

A deployment SHOULD NOT advance to Stage 2 until Stage 1 has run
long enough to expose silent failure modes such as approval-event
races, normalization bugs, and Mission Status caller-authorization
bugs.

# Stage 2: Gate Refresh and Exchange on Mission State

## Goal

First enforcement. The Mission record becomes load-bearing for
derivation events. After Stage 2, a revoked or suspended Mission
prevents new credentials from being derived past it.

## What ships

The AS adopts the `issuance` enforcement class per
{{I-D.draft-mcguinness-mission-oauth-profile}}. Each derivation
event consults Mission state:

- Refresh token grants: Mission must be `active`.
- Token Exchange grants (RFC 8693 {{RFC8693}}): Mission must be
  `active`. The exchanged token references the same Mission as
  the subject token.
- ID-JAG issuance (where deployed, per
  {{I-D.draft-ietf-oauth-identity-assertion-authz-grant}}):
  Mission must be `active`.

When Mission state disallows derivation, the AS returns the
`mission_inactive` error per the OAuth Profile.

The AS adds the `mission` claim to newly issued JWT access tokens
(per RFC 9068 {{RFC9068}}) and includes a Mission snapshot in
introspection responses for opaque tokens. The AS advertises
`mission_enforcement_classes_supported` including `issuance` and
`mission_max_stale_seconds`.

## Per-tier rollout

A deployment SHOULD enable `issuance`-class enforcement
progressively: by audience (begin with audiences whose Resource
Servers are confirmed Mission-unaware, i.e. target RS-A in Stage
4); by client (a staged client allowlist allows quick rollback if
a client misbehaves under the new error surface); and by tenant
(multi-tenant deployments SHOULD gate at the tenant boundary so
cross-tenant blast radius is bounded).

Access-token TTLs SHOULD be aligned with the declared
`mission_max_stale_seconds`. OAuth defaults of one hour are
typically too long once revocation propagation matters; values
in the range 60 to 300 seconds are typical for `issuance`-only
deployments where revocation matters. Deployments adopting
`event_driven` or `per_request` later (Stage 4) MAY lengthen
TTLs at that point.

## What clients and Resource Servers change

Nothing required in the steady-state flow. Clients SHOULD handle
the `mission_inactive` error by surfacing a user-visible signal
that the task has been revoked or suspended, not by silently
retrying. Existing clients that do not recognize the code will
fall through to their generic OAuth error handling and SHOULD
recover by requesting a fresh authorization, which the AS
treats as a new Mission Proposal.

Resource Servers continue to receive existing credentials and
validate them as before. The added `mission` claim is
informational at this stage; an RS that does not consume it is
unaffected.

## Exit criteria

A deployment exits Stage 2 when refresh and Token Exchange refuse
derivation past revoked and suspended Missions end to end; the
declared `mission_max_stale_seconds` is honored in practice;
lifecycle operations on the Mission (revoke, suspend, resume,
complete) per the OAuth Profile's lifecycle endpoint are
exercised in production; and the `mission_inactive` error
surface has been exercised against the client population without
unrecoverable failures.

# Stage 3: Narrow Authority from the Approved Mission

## Goal

Move from coarse scopes to derived authority. After Stage 3, the
`authorization_details` on a newly issued token are derived from
the approved Authority Set carried by the Mission, not from
free-form scope strings.

## What ships at the AS

The AS adopts the full Mission Intent submission path per
{{I-D.draft-mcguinness-mission-oauth-profile}}: accept
`mission_intent` only through PAR {{RFC9126}} with validation
against the published `mission_intent_schema_uri`; render
Mission Intent to the approving principal as part of the consent
disclosure, computing `consent_disclosure_hash` per the
Framework; on approval, derive an Authority Set from Mission
Intent under the AS's policy (`policy_version`), with
`mission_resource_access` entries as defined in the OAuth
Profile; emit derived `authorization_details` to clients in
token responses.

Coarse `scope` continues to be emitted alongside derived
`authorization_details` for legacy consumers. The relationship
between coarse `scope` and the derived Authority Set is a
deployment-policy decision audit-anchored by `proposal_hash` and
`authority_hash`.

## Client-side changes

Clients adopting Stage 3 submit `mission_intent` through PAR
including a structured `goal`, `objects`, `constraints`, and
`success_criteria` per the Framework's Mission Intent schema, a
`mission_expiry` aligned to the task's intended duration, and
optionally `purpose` and `context`. Submission is through PAR
{{RFC9126}} per the OAuth Profile; the client uses the
`request_uri` returned from PAR in the subsequent authorization
request.

Clients that do not adopt `mission_intent` in Stage 3 continue
to work: the AS synthesizes a Mission Intent from the legacy
authorization request shape as in Stage 1 and Stage 2. Clients
SHOULD adopt `mission_intent` because the synthesized Intent
loses fidelity the explicit form captures.

## Approval UX changes

The consent screen changes shape. Where Stage 0 displayed
requested scopes, Stage 3 displays the Mission Intent's goal,
objects, and constraints, with the derived Authority Set surfaced
as the concrete authority being granted. Deployments SHOULD adopt
a consent-disclosure template registered in their consent
template registry; the disclosure template version is recorded
in the Mission record per the Framework.

Approval continues to occur at the authorization endpoint (or
through an out-of-band admin workflow where deployed). The
approval event is the same atomic Proposal-to-Mission transition
the AS implemented in Stage 1; what changes in Stage 3 is the
information surfaced to the approver.

## What Resource Servers change

Resource Servers SHOULD begin to enforce against the derived
`authorization_details` rather than `scope` where the Authority
Set carries the relevant authority. RSes that do not yet consume
`authorization_details` continue to enforce against `scope` and
remain operational; the issued credential will carry both until
the deployment retires the coarse representation.

## Exit criteria

A deployment exits Stage 3 when a measurable fraction of newly
issued tokens carry derived `authorization_details` matching the
Mission's approved Authority Set under the registered narrowing
rules; Mission Intent submission through PAR is exercised by the
client population the deployment expects to convert; consent
disclosure renders the approved Intent and records the
disclosure-template version and `consent_disclosure_hash`; and
the AS can prove, for any issued token, the derivation chain
from Mission Intent (via `proposal_hash`) to Authority Set (via
`authority_hash`) to issued `authorization_details`.

# Stage 4: Resource Server Uptake

## Goal

Move enforcement past the AS boundary. Resource Servers begin to
read Mission state and react to lifecycle events. This is where
revocation propagation becomes real for already-issued tokens.

## RS-A: bearer of authority

RS-A is the baseline tier. The RS accepts a Mission-bound access
token, validates it per its sender constraint and signature (RFC
9068 {{RFC9068}} for JWTs or RFC 7662 {{RFC7662}} for opaque
tokens), and enforces against `scope` and `authorization_details`
exactly as it does without Mission awareness. An RS-A does
nothing additional in Stage 4. Deployments where every Resource
Server is RS-A complete their migration at Stage 3 plus AS-side
`issuance` enforcement.

## RS-B: Mission-snapshot consumer

RS-B reads the Mission snapshot. There are two non-exclusive
mechanisms, both defined in
{{I-D.draft-mcguinness-mission-oauth-profile}}:

- **Introspection projection.** The RS introspects the token
  (RFC 7662 {{RFC7662}}) and consumes the Mission snapshot the
  AS includes in the response. The AS advertises the
  `introspection` enforcement class. The RS treats an
  `active=false` response as authoritative even if the token
  itself has not expired.
- **Event-driven invalidation.** The deployment delivers Mission
  lifecycle events to the RS via Shared Signals/CAEP or
  equivalent. The AS advertises the `event_driven` enforcement
  class. The RS marks affected tokens unusable on receipt of a
  Mission revocation or suspension event.

A deployment SHOULD adopt event-driven invalidation when latency
matters and `event_driven` infrastructure exists. Introspection
projection alone does not reduce revocation latency below the
access-token TTL for RSes that cache token validation.

## RS-C: per-request Mission Status

RS-C queries Mission Status per consequential request for the
freshest possible state. The AS advertises the `per_request`
enforcement class. The RS calls the Mission Status endpoint with
caller authentication and a nonce, validates the response per
the Framework's authentication, freshness, audience, and
integrity properties, and refuses the request if Mission state
is anything other than `active` (or if the response is stale
past the deployment's tolerance). Deployments SHOULD reserve
RS-C for high-assurance operations where the cost of acting on
stale Mission state exceeds the cost of an additional round trip.

## When Mission Status reads become required

Mission Status reads are RECOMMENDED for RS-B (via introspection
projection) and required in practice for RS-C. A deployment
publishing an `event_driven` or `per_request` enforcement class
is committing to a maximum tolerated stale interval; RSes
participating in that commitment SHOULD have a Mission Status
read path as a fallback when event delivery fails.

## Per-tier rollout and exit criteria

A deployment SHOULD roll out tiers in order: RS-A baseline,
then RS-B, then RS-C for the high-assurance subset. Mixed-tier
deployments are supported; the AS advertises the union of
enforcement classes and each RS opts into the classes it
consumes. Clients do not change in Stage 4.

A deployment exits Stage 4 when each Resource Server has been
classified to a tier and operates at that tier; for RS-B
participants Mission revocation propagates within the
deployment's `mission_max_stale_seconds` interval; and for RS-C
participants per-request Mission Status reads are authenticated,
audience-bound, and observe freshness per the Framework.

# Stage 5: Cross-AS Continuity

## Goal

Preserve Mission identity and state across Authorization Server
boundaries. This stage applies only to multi-AS deployments. A
single-AS deployment completes its migration at Stage 4.

## Multi-AS bindings

A deployment with two or more Authorization Servers composes
with two existing OAuth mechanisms:

- **Token Exchange (RFC 8693 {{RFC8693}}).** A token from AS1,
  exchanged at AS2, produces a credential bearing the same
  Mission reference. The `mission` claim is preserved across
  the exchange. Mission state is consulted at the exchange step
  per the `issuance` enforcement class from Stage 2.
- **Identity Assertion Authorization Grant (ID-JAG)**
  {{I-D.draft-ietf-oauth-identity-assertion-authz-grant}}. In
  the common-IdP scenario, the IdP issues an ID-JAG that
  Resource ASes consume to mint audience-bound credentials. The
  Mission reference threads through the ID-JAG per
  {{I-D.draft-mcguinness-mission-oauth-profile}}.

For same-IdP SaaS-to-SaaS chains, the Identity Continuation
Assertion
{{I-D.draft-mcguinness-oauth-id-continuation-assertion}}
composes with ID-JAG to carry the Mission reference through
onward issuance. For cross-trust-domain mapping (where issuer
and subject identifiers differ across domains), the Identity
Chaining draft {{I-D.draft-ietf-oauth-identity-chaining}} is the
composition substrate.

## What ships

Each AS that participates in cross-AS continuity recognizes the
`mission` claim on incoming subject tokens at the Token Exchange
endpoint and preserves it on the exchanged token; resolves the
incoming Mission reference (canonical or pairwise) to the
appropriate sector reference for the target audience per the
Framework, minting the reference for the target audience rather
than copying an upstream pairwise reference into a different
sector; consults Mission Status at the state authority
identified by `mission.origin` before issuing a derived
credential, per the `issuance` class; and cascades Mission
revocation to all derived credentials it has issued.

For Token Exchange, the exchanged token's `mission` claim is the
binding. For ID-JAG, the Mission reference is carried in the
ID-JAG per {{I-D.draft-mcguinness-mission-oauth-profile}}; the
Resource AS consuming the ID-JAG validates the issuing IdP's
authority over the Mission and gates issuance on Mission state
per the `issuance` class.

## Optional move to MAS topology

When governance lives outside any one credential issuer (for
example, when OAuth and AAuth substrates share a governance
object, or when multiple ASes share Mission ownership), the
Mission Authority Server (MAS) topology centralizes the state
authority. A future Mission Authority Server profile defines
this topology; this guide notes the MAS move as a forward-
looking option. A deployment SHOULD NOT adopt the MAS topology
before completing Stages 0 through 5 on at least one AS. MAS
adoption is a topology change, not an incremental gating step,
and inherits all the lifecycle and revocation semantics this
guide walks through.

## Exit criteria

A deployment exits Stage 5 when Token Exchange and (where
deployed) ID-JAG issuance preserve the Mission reference across
AS hops; Mission revocation at the originating state authority
blocks derivation at downstream ASes within the deployment's
stated `mission_max_stale_seconds` interval; and pairwise
Mission references are minted per target audience rather than
propagated across audiences.

# Compatibility Hazards

## Backward compatibility with non-Mission-aware clients

In every stage through Stage 3, clients that have not adopted
Mission Intent submission continue to function. In Stages 1
through 3 the AS synthesizes a Mission Intent from the legacy
authorization request shape (scope, resource parameter, RAR
entries). The synthesized Intent is necessarily coarser than an
explicit `mission_intent`. Deployments SHOULD set an explicit
deprecation horizon for legacy clients rather than supporting
synthesized Intent indefinitely.

Clients that do not handle the `mission_inactive` error code
specifically will treat it as a generic OAuth error. This is
acceptable for backward compatibility but degrades user
experience by losing the signal that the user's task was revoked
or suspended.

## Mixed-RS tier handling

Stage 4 admits a mix of RS-A, RS-B, and RS-C Resource Servers
within the same deployment. The AS advertises the union of
enforcement classes it supports; each RS consumes only the
classes it participates in. Mission revocation propagates to
RS-B and RS-C per their respective mechanisms; RS-A receives
propagation only through access-token expiry, bounded by the
TTL the AS sets per Stage 2.

A deployment SHOULD NOT claim a tighter `mission_max_stale_seconds`
than its lowest-tier RS can deliver. If an RS-A audience must be
covered, the access-token TTL bounds the achievable stale
interval. If a deployment needs a tighter interval than TTL
allows, the affected RSes must move to RS-B or RS-C tiering.

## Refresh-token leakage across stages

A deployment transitioning from Stage 2 to Stage 3 holds refresh
tokens issued under Stage 2's coarse `authorization_details` (or
`scope`) shape. The AS SHOULD continue to honor those refresh
tokens but SHOULD progressively narrow them on each refresh by
re-deriving `authorization_details` from the current Mission's
Authority Set. This is a one-way narrowing: a Stage 2 refresh
token does not gain authority on its first Stage 3 refresh; it
only converges to its Mission-derived bound.

A deployment that revokes a Mission while refresh tokens are
outstanding SHOULD rely on Stage 2 gating (which refuses the
refresh) plus Stage 4 propagation (which invalidates already-
issued access tokens for RS-B and RS-C). The deployment SHOULD
NOT assume Stage 2 alone invalidates already-issued access
tokens; those tokens remain valid until natural expiry unless
introspection, event-driven, or per-request enforcement covers
their audience.

## Token TTL recommendations during transition

Access-token TTL is the dominant control on revocation latency
for RS-A audiences. During the transition:

- **Stage 1.** TTL choice is independent of Mission state.
- **Stage 2 onward.** TTLs SHOULD be aligned with the declared
  `mission_max_stale_seconds`. One-hour defaults are typically
  too long; values in the range 60 to 300 seconds are typical
  when revocation propagation matters and only `issuance`
  enforcement is deployed.
- **Stage 4 (RS-B with `event_driven`, RS-C with `per_request`).**
  TTLs MAY be lengthened for audiences covered by those
  enforcement classes because revocation propagates out-of-band
  of TTL.

Deployments SHOULD set per-audience TTLs aligned with per-
audience tiering rather than a single global TTL.

## Mission Status caching and approval-event races

Mission Status responses declare `issued_at` and `expires_at`
per the Framework. Consumers cache responses within these bounds
and fail closed after expiration. Operators SHOULD NOT extend
cache lifetime past `expires_at`; the freshness property is the
substrate for the revocation-latency claim.

A client retrying an authorization that has already produced a
Mission Proposal can race the approval event. The Framework's
approval event is idempotent on `proposal_id`; deployments
SHOULD ensure client retry logic, network proxies, and approval
workflow preserve the `proposal_id` so retries do not produce
duplicate records or partial commits.

In Stage 3 the consent disclosure changes shape from "scopes
requested" to "Mission Intent rendered." Operators SHOULD A/B
test the new disclosure before cutover. The
`consent_disclosure_hash` captures what was presented; the
operator owns whether that disclosure was comprehensible.

## Rollback considerations

Each stage SHOULD have a defensible rollback path. Stage 1
rollback disables shadow recording with no client or RS impact.
Stage 2 rollback disables `issuance` enforcement; Mission state
returns to advisory and revocation latency returns to TTL.
Stage 3 rollback continues to record Missions but emits legacy
`scope` or ad hoc `authorization_details` on issuance; clients
that submit `mission_intent` still function because the AS
parses and records the Intent. Stage 4 rollback is per RS: an
RS reverts to RS-A while other RSes continue at their adopted
tier, with the AS adjusting its advertised enforcement classes.
Stage 5 rollback is per cross-AS hop. Rollback SHOULD NOT be
the first response to a problem; the stages exist to provide
testable forward progress.

# Security Considerations

This document is operational guidance and inherits the security
considerations of the Mission Framework
{{I-D.draft-mcguinness-mission-framework}}, the Mission-Bound
OAuth Profile {{I-D.draft-mcguinness-mission-oauth-profile}}, and
the OAuth 2.0 Security BCP {{RFC9700}}. The following are
specific to the migration sequence.

Every stage transition changes either what is recorded or what
is enforced. Each transition SHOULD be treated as a change-
control event with the usual disciplines: staged rollout,
observability, kill-switches, and customer communication. A
botched migration that loses audit records is worse than a
slower, well-controlled migration.

Stages 1 through 3 may rely on the AS synthesizing a Mission
Intent from the legacy authorization request shape. The
synthesized Intent is a transitional artifact: it permits the
migration but does not by itself deliver the audit and narrowing
value that explicit `mission_intent` submission provides. The
synthesized Intent's `proposal_hash` anchors what the AS
recorded, but what was recorded may not reflect what the user
would have approved if shown a full Mission Intent.

Access-token TTLs are the dominant control on revocation latency
for RS-A audiences. A deployment that advances through Stages 2
and 3 with unchanged one-hour TTLs effectively has a one-hour
revocation latency for those audiences. This is correct OAuth
behavior, but operators SHOULD set per-audience TTLs aligned
with the declared `mission_max_stale_seconds` rather than
publishing a value they cannot meet.

Deployments advertising multiple enforcement classes (`issuance`
plus `event_driven`, or plus `per_request`) SHOULD ensure each
RS's claimed class is honored. Misadvertisement leads consumers
to assume revocation propagation guarantees that do not hold for
their audience.

Operators introducing pairwise Mission references in Stage 3 or
later SHOULD audit log pipelines for canonical-identifier
leakage. The pairwise model assumes audience-specific visibility;
canonical identifiers leaked through logs, support tools, or
unencrypted backups defeat the model.

# IANA Considerations

This document is Informational and has no IANA actions. Wire-
level registrations (parameters, claims, error codes, metadata
members, media types) belong to
{{I-D.draft-mcguinness-mission-framework}} and
{{I-D.draft-mcguinness-mission-oauth-profile}}.

# Acknowledgments

This document is part of the Mission-Bound Authorization
specification set. The Mission Framework
{{I-D.draft-mcguinness-mission-framework}} and Mission-Bound
OAuth Profile {{I-D.draft-mcguinness-mission-oauth-profile}}
are the destinations this guide leads to; the operational
practice described here is informed by their normative content.
