---
title: "Mission-Bound Authorization for OAuth 2.0"
abbrev: "OAuth Mission"
category: std

docname: draft-mcguinness-oauth-mission-latest
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
 - rar
 - par
venue:
  github: "mcguinness/mission-bound-authorization"
  latest: "https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission.html"

author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com

normative:
  RFC3339:
  RFC3986:
  RFC6234:
  RFC6749:
  RFC7636:
  RFC7800:
  RFC8259:
  RFC8693:
  RFC8785:
  RFC8705:
  RFC8707:
  RFC9068:
  RFC9126:
  RFC9207:
  RFC9396:
  RFC9449:
  RFC7662:
  RFC8414:
  RFC7519:
  RFC9728:
  I-D.draft-mcguinness-oauth-actor-profile:
  ISO4217:
    title: "ISO 4217:2015, Codes for the representation of currencies and funds"
    author:
      org: International Organization for Standardization
    date: 2015-08
    seriesinfo:
      ISO: "4217:2015"

informative:
  RFC8126:
  RFC6750:
  RFC7009:
  RFC8935:
  RFC9493:
  RFC9700:
  FAPI.GrantManagement:
    title: "Grant Management for OAuth 2.0"
    target: https://openid.net/specs/fapi-grant-management-01.html
    author:
      - org: OpenID Foundation
    date: 2022
  MCP:
    title: "Model Context Protocol: Authorization"
    target: https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization
    author:
      - org: Model Context Protocol Project
    date: 2025
  AuthZEN.ARAP:
    title: "OpenID AuthZEN Access Request and Approval Profile 1.0"
    target: https://openid.github.io/authzen/authzen-access-request-approval-profile-1_0.html
    author:
      - org: OpenID Foundation
    date: 2025
  I-D.draft-klrc-aiagent-auth:
  I-D.draft-ietf-oauth-transaction-tokens:
  I-D.draft-niyikiza-oauth-attenuating-agent-tokens:
  I-D.draft-cecchetti-oauth-rar-cedar:
  I-D.draft-mcguinness-oauth-client-instance-assertion:
  I-D.draft-mcguinness-oauth-ai-agent-instance:
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
  I-D.draft-mcguinness-oauth-mission-cross-domain:
    title: "Mission Cross-Domain Projection for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-cross-domain.html
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
  I-D.draft-mcguinness-mission-architecture:
    title: "An Architecture for Mission-Bound Authorization"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-architecture.html
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
  I-D.draft-mcguinness-oauth-mission-consent-evidence:
    title: "Mission Consent Evidence for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-consent-evidence.html
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
  I-D.draft-mcguinness-mission-audit:
    title: "Mission Audit Transparency"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-audit.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026

--- abstract

An AI agent is typically given a mission: a task to pursue on a
user's behalf. OAuth 2.0 issues access tokens for individual
resource requests, but it has no durable, approved artifact that
ties those tokens to the one task a user actually authorized. As a
result, an agent's authority is a collection of independently
obtained tokens with no shared, auditable boundary, and a user's
approval is disconnected from what the agent later does.

This document defines a Mission: a structured, explicitly approved,
integrity-bound authorization artifact for OAuth 2.0. A client submits
a Mission Intent through Pushed Authorization Requests; the
Authorization Server derives Rich Authorization Requests authorization
details from it, binds the approved task and its derived authority to
the Approver's consent through two integrity anchors, and records a
durable Mission. Every access token derived under the Mission carries
that authority and a "mission" claim, and issuance is gated on the
Mission's lifecycle state. Optional capabilities represent
delegation among agents with the OAuth Actor Profile and, as specified by a
companion, let a single Mission be honored across trust domains. This
is the issuance and governance "mission layer" left unspecified by
agent-identity work for OAuth; runtime enforcement of each action is a
separate, optional layer.

--- middle

# Introduction

Agent-identity work such as {{I-D.draft-klrc-aiagent-auth}}
establishes how an AI agent authenticates and how a user delegates
authority to it: the agent is an OAuth 2.0 {{RFC6749}} client
identified by `client_id`, the delegating user is the access token
`sub`, and the
agent obtains tokens for the resources its task requires. That work
deliberately leaves three things out of scope: how an agent's task
(its "mission") is translated into authorization, how a user's
approval of that task is captured as a durable artifact, and how
later token issuance stays bound to what the user approved.

Without that layer the gap is invisible to every individual OAuth
component. Each token is individually valid and each request
individually in scope, yet nothing checks whether the task the user
approved is still the one being pursued. A token issued for a task
remains usable after the user's approval has lapsed or been withdrawn,
because no OAuth object ties the token's validity to the task's
authorization: the credential stays secure while the work it
authorizes has quietly become unauthorized.

This document specifies that missing layer. It defines a
**Mission**: a structured, explicitly approved, integrity-bound OAuth
authorization artifact. The contribution is a single chain:

1. The client submits a structured **Mission Intent** describing the
   task (goal, target resources, constraints) instead of requesting
   raw scopes.
2. The Authorization Server (AS) derives **authorization details**
   ({{RFC9396}}), the **Authority Set**: the concrete authority the
   task needs.
3. At an **approval event**, the Approver consents to that
   authority, and the AS commits the task as an **`intent_hash`** and
   the authority as an **`authority_hash`** and records a durable
   **Mission**.
4. Every access token the agent obtains under the Mission carries the
   derived authorization details and a **`mission` claim** bearing
   the `authority_hash`. A Resource Server enforces statelessly from
   the token.
5. Token issuance and refresh are **gated on Mission state**, so
   revoking or expiring the Mission stops the agent from obtaining
   further authority.

The result is that a user approves a task once, and that approval,
not a per-request scope grant, bounds and outlives every token the
agent derives. Each token carries an `authority_hash` audit anchor back
to the consented authority; a holder of the full Authority Set can
verify it, and a holder of only a narrowed subset (a downstream or
cross-domain party) treats it as an audit anchor it cannot recompute
({{consent-binding}}).

This chain is the first of two deliberate enforcement layers. It gives
task-bound issuance, auditability, and a revocation gate over future
derivation, which is sufficient for a low-risk workflow whose exposure
is bounded by short token lifetimes and narrow authority. It does not
evaluate individual actions: an agent taking consequential autonomous
actions needs the second layer, the runtime enforcement chokepoint
({{runtime-boundary}}), specified separately. A deployment chooses its
layers deliberately, matching the enforcement it runs to the
consequence of what its agents do; the Mission Assurance Levels of
{{I-D.draft-mcguinness-mission-architecture}} name the composed
levels informatively.

## Why a New Object

OAuth already has objects near this need, but none is the approved
task. A `scope` value or an `authorization_details` entry
({{RFC9396}}) expresses authority but neither the task it serves nor a
lifecycle of its own. An access token is a short-lived projection; its
`jti` identifies the token, not the task. A refresh token preserves
the ability to obtain further tokens but commits no bounded, approved
authority. A consent record proves that an approval event happened; it
does not govern the resulting work as it continues. The Mission is the
durable object these project from: the approved task that bounds and
outlives them, and that every derived token refers back to.

Put plainly: Rich Authorization Requests express authority; a Mission
expresses an approved task with a lifecycle. The Mission is a separate
object because that approved-task lifecycle, not a new way to express
authority, is what OAuth lacks. A Mission is therefore not another
`authorization_details` type; it is the durable, approval-backed object
an Authority Set is derived for and gated by.

## Relationship to Other Authorization Objects

A grant, in the sense of FAPI Grant Management {{FAPI.GrantManagement}},
is a durable, queryable, revocable container of consented authorization
data. It records consent to authority but carries no task, no integrity
commitment, and no derivation gating; a deployment MAY surface Mission
revocation through a grant-management-style API.
{{I-D.draft-klrc-aiagent-auth}} names the agent's mission and leaves its
translation into authorization out of scope; this document specifies
that translation. Decision-layer access-request and approval workflows,
such as the OpenID AuthZEN Access Request and Approval Profile
{{AuthZEN.ARAP}}, manage approval tasks but define no issuance binding;
this document supplies the issuance-bound object such workflows
complete into.

Nearby individual proposals each carry one Mission property without the
others: task-linked Rich Authorization Requests with revocation
webhooks carry a task link, intent-digest admission assertions carry an
intent commitment, and offline capability attenuation
({{I-D.draft-niyikiza-oauth-attenuating-agent-tokens}}) carries offline
narrowing. None combines the durable approved object, state-gated
issuance, and integrity anchors this document defines.

## The Mission, the Plan, and Execution

The Mission is the durable, AS-held object that commits the approved
authority and owns the task's lifecycle. Two related things an agent
produces around a task are deliberately not the Mission and carry no
authority of their own.

The agent's **plan**, how it decomposes the task, chooses tools, and
delegates to sub-agents, is the agent's own strategy and is out of
scope for this document. It grants nothing: authority a sub-agent
exercises is carried by the `act` chain ({{delegation}}), derived from
the Mission and only ever narrowed from it ({{subset}}), never created
by the plan.

The agent's **execution**, the tokens it derives, the calls it makes,
and the decisions taken on them, references the Mission but cannot
expand it. Revoking the Mission stops further derivation
({{lifecycle}}); it does not undo actions already completed.
Evaluating each action against the Mission at the point of use is the
runtime layer's concern ({{runtime-boundary}}), not this document's.

The invariant across all three: the plan and the execution draw on the
Mission's authority; neither enlarges it.

## Relationship to Agent-Identity Specifications

This document is complementary to {{I-D.draft-klrc-aiagent-auth}}
and reuses its model: the agent is the OAuth client
(`client_id`); the delegating user or system is the token `sub`.
This document does not define agent identity, credentialing, or
posture; it defines the approved-task artifact those identities act
within. An agent authenticated and delegated per that specification
uses the mechanisms here to obtain Mission-bound tokens.

## Applicability {#applicability}

This profile targets OAuth deployments where authority serves a
durable, user-approved task that spans more than one token, request,
or audience: an agent pursuing a multi-step objective on a user's
behalf, or a workflow whose audit must join activity across hops on a
shared task. It is not intended for, and adds cost without benefit to,
single-request user flows, machine-to-machine service credentials, or
short-lived authorizations where the credential's lifetime is the
task's lifetime; those use OAuth unchanged.

A Mission SHOULD be scoped to a concrete task, not to an agent's whole
lifetime. A deployment SHOULD prefer narrow, per-task Missions, each
separately approved and revocable, over a single broad standing Mission
that accumulates authority across unrelated tasks. The durable object is
the approved task: keeping it task-scoped is what makes its authority
and audit meaningful and bounds the blast radius on compromise to one
task. An agent pursuing many tasks holds many Missions, not one broad
one.

The unit of governance is the action, not the content. A Mission
bounds where an agent may act (resources, actions) and how much
(constraints and, where metered, cumulative bounds); it does not
inspect what content flows within an authorized action, and an
approved egress channel carries a status update or an exfiltrated
payload with equal authority. Content-level controls (data loss
prevention, redaction) are complementary, and mediated execution
places their natural insertion point at the mediating enforcement
component ({{runtime-boundary}},
{{I-D.draft-mcguinness-mission-runtime}}).

## Scope and Future Work

This document is a self-contained, minimum-viable profile: it binds
Missions to OAuth 2.0 and is implementable on its own, depending only
on the OAuth and JOSE specifications it cites.

One normative dependency is on an in-progress individual draft, so
this document cannot advance ahead of it: the OAuth Actor Profile
({{I-D.draft-mcguinness-oauth-actor-profile}}) for the `act` chain.
That dependency is confined to the OPTIONAL Delegation capability,
so the mandatory single-domain core does not depend on it.
Cross-domain projection, a single hop that lets an Authorization
Server in another trust domain honor a Mission, is specified by the
companion Mission Cross-Domain Projection profile
{{I-D.draft-mcguinness-oauth-mission-cross-domain}}, which carries
the identity-chaining and ID-JAG dependencies with it; the
Cross-Domain capability's conformance bar is self-contained in this
document ({{conformance}}), so that companion is not a normative
dependency.

Separate from this document, and not required to implement it, are
several capabilities now specified as OPTIONAL companion profiles: an
additional integrity anchor over a structured consent disclosure
(`consent_rendering_hash`, {{consent-binding}}) is defined by Mission
Consent Evidence {{I-D.draft-mcguinness-oauth-mission-consent-evidence}};
mission expansion is defined by Mission Expansion
{{I-D.draft-mcguinness-oauth-mission-expansion}}; and a cross-domain
status or event-distribution mechanism for tighter revocation is defined
by Mission Status {{I-D.draft-mcguinness-oauth-mission-status}} and
Mission Lifecycle Signals {{I-D.draft-mcguinness-oauth-mission-signals}}.
A deployment implements this document without any of them. A
substrate-neutral statement of the Mission model, generalizing it
across non-OAuth authorization substrates, is specified separately
and is out of scope for this document. Remaining
future work, not yet specified, includes: the normative carriage of
Mission context in Transaction
Tokens ({{I-D.draft-ietf-oauth-transaction-tokens}}), shown only
illustratively in the companion's end-to-end example; and, for a
community that wants cross-vendor agreement on what a task authorizes
within a vertical, an OPTIONAL derivation profile: a registry of
standard task types mapped to authority templates, so that two
vendors in that profile derive comparable Authority Sets. This document
deliberately does not standardize the derivation algorithm itself
({{authorization-derivation}}); a vertical profile is the appropriate
vehicle where portable derivation is genuinely needed.

## Non-Goals {#non-goals}

The following are deliberately out of scope. Each is a recurring
question for agent authorization; naming it here records that it was
considered and where it belongs, not that it was overlooked.

- **Semantic / intent verification.** This profile binds a token to an
  approved authority and task; it does not evaluate whether a given
  runtime action serves the Mission's purpose beyond matching the
  approved `authorization_details` and `constraints`. Per-action
  evaluation is the runtime layer's role ({{runtime-boundary}}).
  Verifying an agent's declared reasoning against the task is a further
  attestation problem outside both layers.
- **Approval-free authorization upgrade.** The Authority Set is
  committed at approval; this profile defines no mid-stream widening
  that bypasses consent. Widening requires a new approval, a successor
  Mission, as specified by Mission Expansion
  {{I-D.draft-mcguinness-oauth-mission-expansion}}; a widening that no
  consent authorizes remains out of scope.
- **Lifecycle event distribution.** A Resource Server learns Mission
  state from the token lifetime or optional introspection
  ({{introspection}}); this profile defines no push-based notification
  of Mission state changes. A Shared Signals ({{RFC8935}}) / CAEP
  profile for Mission lifecycle events is specified separately by the
  Mission Lifecycle Signals profile
  ({{I-D.draft-mcguinness-oauth-mission-signals}}), not here.
- **Human-in-the-loop suspension.** The base lifecycle here is
  `active`, `revoked`, `expired` ({{lifecycle}}). A `suspended` state
  with `resume`/`complete` transitions is defined as an OPTIONAL
  extension by the Mission Status and Lifecycle profile
  ({{I-D.draft-mcguinness-oauth-mission-status}}); a
  pending-human-approval state and a holding-token pause-and-resume
  protocol remain future lifecycle work.
- **Multi-hop cross-domain provenance.** A single cross-domain hop is
  specified by the companion
  ({{I-D.draft-mcguinness-oauth-mission-cross-domain}}); chaining a
  Mission across more than one trust-domain boundary, and the
  verifiable provenance that would require, are future work.
- **Decentralized agent identity.** Agent identity and credentialing
  are out of scope ({{I-D.draft-klrc-aiagent-auth}}, and workload
  identity efforts such as WIMSE); this profile governs the
  approved-task artifact those identities act within, not the
  identities themselves.
- **Cross-audience unlinkability.** A single canonical Mission
  Identifier and the `authority_hash` it shares deliberately let any
  party correlate a
  Mission's activity across audiences and resources. This is a design
  choice, not an omission: a stable, correlatable anchor is what lets a
  Resource Server, a cross-domain Resource AS, and an auditor bind
  evidence to one approved Mission, which is a core goal of this
  document and its companion profiles.
  Pairwise or unlinkable presentation of Mission-bound authority works
  against that anchor and is therefore future work, not a v1 property
  ({{mission-identifier-correlation}}).

## Conventions and Terminology

{::boilerplate bcp14-tagged}

All JSON shown in this document is non-normative and illustrative; the
member definitions in the surrounding text are authoritative.

Agent (Client):
: The OAuth client acting on a user's behalf, identified by
  `client_id`. Agent identity is established per
  {{I-D.draft-klrc-aiagent-auth}} or ordinary OAuth client
  authentication.

Subject:
: The user or system on whose behalf the Mission is approved,
  identified by an (`iss`, `sub`) pair and carried in derived tokens'
  `sub` claim.

Approver:
: The single accountable principal who approves the Mission at the
  approval event. Equal to the Subject for self-approval; different
  for administrator or delegated approval. This document records one
  accountable Approver; multi-party approval and the provenance of
  delegated approval authority are deferred ({{multi-party-approval}}).

Mission Issuer (Authorization Server):
: The OAuth AS that validates a Mission Intent, runs the approval
  event, records the Mission, and derives tokens. It is the Mission's
  `issuer`. "Mission Issuer", "issuer AS", "originating AS", and "AS" are used
  interchangeably in this document.

Resource AS:
: An Authorization Server in another trust domain that honors a
  Mission it did not issue, minting its own tokens for its resources;
  it is never the Mission Issuer. Cross-domain projection is specified
  by the companion Mission Cross-Domain Projection profile
  ({{I-D.draft-mcguinness-oauth-mission-cross-domain}}).

Mission Intent:
: The structured description of the task the client submits
  ({{mission-intent}}).

Authority Set:
: The set of `authorization_details` entries the AS derives from a
  Mission Intent and the Approver approves
  ({{authorization-derivation}}). "Authority Set" names these concrete
  entries; it does not mean an identity authority, a trust authority,
  a legal authority, or an issuing authority.

Mission:
: The durable, immutable record created at the approval event
  ({{mission-record}}), identified by a Mission Identifier
  ({{mission-id}}).

Mission-referenced token:
: A token that carries a Mission reference (the `mission` claim or a
  `mission_id`) without Mission-derived authority or any gating
  guarantee. A reference is never authority.

Derived token (Mission-derived token):
: An access token issued under a Mission, carrying its Mission-derived
  authority (the full Authority Set or a narrowed subset) as
  `authorization_details` and a `mission` claim
  ({{mission-bound-tokens}}).

Mission-bound token:
: A Mission-derived access token or refresh token whose issuance and
  refresh are gated on the Mission's `active` state and bounded by the
  subset rule (with refresh tokens bound server-side). Only this class
  carries this profile's gating guarantee, and this document reserves
  "Mission-bound" for it; a token that merely references or carries
  Mission data without the gates is not Mission-bound
  ({{conformance}}).

# Conformance {#conformance}

An implementation conforms in one of three roles.

A **Mission Issuer** (the Authorization Server) implements the core
issuance surfaces:

- submission of a Mission Intent via PAR ({{mission-intent}});
- derivation of `mission_resource_access` authorization details
  ({{authorization-derivation}});
- the approval event with its integrity anchors ({{approval-event}});
- issuance of Mission-bound access tokens carrying the `mission` claim
  ({{mission-bound-tokens}});
- the subset rule ({{subset}}); and
- gating of issuance on Mission state ({{lifecycle}}).

A **Mission-aware Resource Server** implements Resource Server
enforcement ({{rs-enforcement}}).

A **Mission Client** implements the client surfaces:

- submission of the Mission Intent via PAR only
  ({{submission-via-par}}), never sending `authorization_details`
  alongside `mission_intent`;
- reading its granted authority from the token-response
  `authorization_details` echo ({{mission-bound-tokens}}); and
- obtaining `mission_id` from the `mission_id` token-response parameter
  or the `mission` claim's `id` ({{grant-binding}}), treating it as a
  reference, never a credential.

Beyond these mandatory roles, an implementation MAY additionally claim
three OPTIONAL capabilities. Each is independent, and an implementation
that supports none of them is still conformant:

- **Delegation** ({{delegation}}): issuing and consuming derived tokens
  that carry the `act` delegation chain.
- **Introspection** ({{introspection}}): reporting Mission state through
  the `mission` token introspection response member.
- **Cross-Domain**: projecting a Mission so it is honored by an
  Authorization Server in another trust domain. An implementation
  claiming this capability preserves, across the hop: the Mission
  reference (`mission.id`, `mission.issuer`, `authority_hash`)
  carried intact; authority that only narrows ({{subset}});
  projection performed only by, or under the authorization of, the
  Mission `issuer`, gated on the Mission's `active` state
  ({{lifecycle}}); and projected credential lifetimes capped by the
  Mission's `expires_at` ({{mission-bound-tokens}}). This bar is
  self-contained in this document; the companion Mission Cross-Domain
  Projection profile
  ({{I-D.draft-mcguinness-oauth-mission-cross-domain}}) specifies the
  interoperable mechanism that satisfies it, and implementations that
  interoperate across the hop implement that companion.

A conforming implementation names the optional capabilities it supports
(for example, "Mission Issuer with Delegation and Cross-Domain"); each
capability's defining section or document states its detailed
requirements.

A token carrying a `mission` claim is not, by itself, Mission-bound
authorization. Conformance as a Mission Issuer requires the gates:
authority derived from the approved Intent and committed by the
anchors ({{approval-event}}), issuance bounded by the subset rule
({{subset}}), and derivation gated on Mission state ({{lifecycle}}).
An implementation that carries Mission metadata without these gates
conforms to no role in this document and MUST NOT be described as
implementing it.

The `mission_bound_authorization_supported` metadata ({{discovery}})
advertises Mission Issuer support only. It makes no assertion about any
Resource Server, which does not advertise through Authorization Server
metadata. The OPTIONAL capabilities are discovered first through
existing OAuth metadata ({{RFC8414}}): `introspection_endpoint` for
introspection, and `grant_types_supported` containing
`urn:ietf:params:oauth:grant-type:token-exchange` for delegation and
for the companion's cross-domain grant issuance. Absent such a signal,
a capability is discovered out of band or by attempt: a Token
Exchange, a cross-domain grant issuance, or an introspection request
fails if the issuer does not support it.

The smallest useful conforming deployment, noted here informatively,
is a Mission Issuer that derives in narrowing mode from the Intent's
`proposed_authority` ({{authorization-derivation}}), emits only the
Common Constraints of {{common-constraints}}, and implements none of
the OPTIONAL capabilities; a scope-only Resource Server still operates
at the coarse scope level ({{rs-enforcement}}). This note names a
starting point and creates no new conformance class.

# Overview

## Principal Model

This document maps principals onto native OAuth constructs:

- The **Agent** is the OAuth client, referenced by `client_id`. Agent
  identity and credentialing are out of scope (see
  {{I-D.draft-klrc-aiagent-auth}}).
- The **Subject** and **Approver** are each an (`iss`,
  `sub`) pair, matching the access token `sub` model of {{RFC9068}}.
  The Approver is the accountable principal whose approval created
  the Mission; it may be a human or an authorized policy authority,
  and the provenance standing behind a delegated or policy approval
  is governance state this document does not model
  ({{multi-party-approval}}).

On a derived token the `sub` claim is the Subject's `sub` and the
token `iss` is the AS; within the issuing AS's namespace this
(`iss`, `sub`) pair is authoritative for the Subject, and Resource
Servers authorize against it. The Subject's home issuer is recorded
on the Mission as `subject.iss` for audit and is not carried on the
token; this document defines no runtime lookup of it (there is no
by-Mission status endpoint). Across trust domains, the companion's
cross-domain grant conveys Subject identity to the Resource AS through
its own subject-resolution claims
({{I-D.draft-mcguinness-oauth-mission-cross-domain}}), not through a
Mission lookup.

Issuer roles obey three invariants: a Mission has exactly one Mission
Issuer, its `issuer`; a Resource AS never creates or alters a Mission;
and a local token minted in another domain preserves the `mission`
claim unchanged ({{I-D.draft-mcguinness-oauth-mission-cross-domain}}).

Principals are recorded at the approval event and are immutable. Two
principals are equal when their `iss` and `sub` are byte-equal.
Dynamic delegation (the actors an agent delegates to during
execution) is carried on derived tokens via the `act` chain
({{delegation}}), not on the immutable Mission record. Richer subject
identifier formats (for example, the formats of {{RFC9493}}) MAY be
layered in future versions and are not required here.

## Protocol Flow

~~~
 Agent (client)                       Mission Issuer (AS)
      |                                     |
      | 1. PAR: mission_intent ------------>| derive authority
      |<----------- request_uri ------------| (authz_details)
      |                                     |
      | 2. authorization request ---------->| Approver consents
      |                                     |   -> authority_hash
      |<-------------- code ----------------| -> Mission active
      |                                     |   (bound to the grant)
      |                                     |
      | 3. token request ------------------>| gate: active?
      |<----------- access token -----------| + authz_details
      |                                     |   + mission claim
      v
~~~

The flow then leaves the AS: (4) the agent calls the Resource Server
with the token; the RS enforces the `authorization_details`
statelessly and MAY check the `mission` claim, with no callback to the
AS required. (5) A management revoke, or `expires_at` passing,
moves the Mission to `revoked` or `expired`, after which the AS refuses further
issuance and refresh; a deployment MAY additionally compose RFC 7009
{{RFC7009}} refresh-token revocation ({{revocation}}). The end-to-end
example ({{e2e-example}}) walks this flow with concrete messages.

# Mission Intent {#mission-intent}

A Mission Intent is the proposal; the Mission is the approval; the
integrity anchors commit the moment of transition. Before the approval
event ({{approval-event}}) only the Intent exists, as untrusted client
input ({{submission-via-par}}); after it, only the Mission is
authoritative. A Mission Intent therefore has no protocol identifier
of its own: two submissions of the same Intent produce two distinct
pending requests, and a Mission acquires its Mission
Identifier ({{mission-id}}) only at activation. The approved Intent is
recorded on the Mission and committed by `intent_hash`
({{integrity-anchors}}); it describes the task but commits no
authority, which is committed separately by `authority_hash` over the
derived Authority Set ({{authorization-derivation}}).

A Mission Intent is a JSON object describing the task. The client
submits it in place of `scope`, or alongside a narrowed `scope`. It
has the following members:

`goal`:
: REQUIRED. A string. A human-readable statement of the task,
  for rendering to the Approver. Maximum 4096 characters.

`resources`:
: REQUIRED. An array of strings. The target resources the
  task needs, each an absolute URI identifying a protected resource
  (an OAuth resource per {{RFC8707}}-style indicators or a Protected
  Resource per {{RFC9728}}).

`constraints`:
: OPTIONAL. An array of strings. Human-readable bounds on
  the task (for example, "read only invoices from 2026"). These
  inform derivation and consent rendering.

`proposed_authority`:
: OPTIONAL. An array of objects, each shaped as an {{RFC9396}}
  `authorization_details` entry. The client's concrete authority
  proposal for the task. It is untrusted input like the rest of the
  Intent and is committed by `intent_hash` with it
  ({{integrity-anchors}}). When present, the AS MUST derive each
  Authority Set entry as a subset ({{subset}}) of some
  `proposed_authority` entry ({{authorization-derivation}}); `goal`
  and `constraints` then serve
  as rendering and bounding context over the proposed authority.
  Each entry's `resource` MUST be among the Intent's `resources`;
  the AS refuses an Intent violating this with `invalid_request`.

`success_criteria`:
: OPTIONAL. An array of strings. Human-readable
  observable outcomes that indicate the task is complete. These are
  disclosure and audit material only: they are rendered to the
  Approver and committed by `intent_hash` ({{integrity-anchors}}),
  but carry no machine semantics and MUST NOT be used to derive,
  widen, or gate authority.

`purpose`:
: OPTIONAL. A string. A URI identifying the purpose of the
  task, recorded for disclosure and audit. Its semantics are
  deployment- or registry-defined and opaque to this document; like
  `success_criteria` it MUST NOT be used to derive, widen, or gate
  authority. A deployment MAY consult it for out-of-band policy or
  logging that does not affect the authority derived here.

`expires_at`:
: REQUIRED. A string. An RFC 3339 {{RFC3339}}
  date-time after which the AS MUST NOT derive tokens under the
  Mission. The value is the client's proposal like the rest of the
  Intent: the approved Intent is recorded as submitted, and an AS
  whose policy cannot accept the proposed `expires_at` refuses with
  `invalid_authorization_details` rather than rewriting it.

`controls`:
: OPTIONAL. An object of machine-actionable bounds. This
  document defines the members below; others MAY be added by
  deployments or defined by companion profiles (an extension member
  follows the collision-resistant naming and fail-safe rules of
  {{extensibility}}):

  `acr`:
  : OPTIONAL. A string. An authentication context class for the
    approval event: the approval authentication MUST be one the
    deployment's policy maps as satisfying the named class. No global
    ordering of `acr` values exists; the mapping is deployment policy.

  `max_derivations`:
  : OPTIONAL. A positive integer (1 or greater). A
    bound on the number of derivations the issuer AS performs under the
    Mission, enforced per {{lifecycle}}. A value of 0 is invalid (it
    would forbid even the initial issuance); to stop a Mission, revoke
    it ({{revocation}}). An AS MUST reject `max_derivations` below 1
    with `invalid_request`. This is an issuer-AS
    derivation cap, not an end-to-end credential cap; what counts as
    one derivation, including how cross-domain issuances count and
    what the issuer cannot observe, is defined once in
    {{lifecycle}}. A deployment
    sizes the cap from its derivation cadence (token and grant renewal
    frequency, times audiences, times the Mission's duration), not as
    a flat count: steady-state cross-domain work consumes one
    derivation per short-lived grant per partner audience, so a cap
    sized for single-domain refresh exhausts in hours under
    cross-domain renewal.

  `agent_deployment`:
  : OPTIONAL. A string. A deployment-defined identifier or digest
    naming the approved Agent Deployment (the agent's behavioral
    version: its code, model, system prompt, tool allowlist, data
    scope, and runtime configuration) the Mission is pinned to. At
    every derivation under the Mission, the AS MUST refuse issuance
    when the requesting client's attested or asserted deployment
    identifier does not match the pinned value, and an AS whose
    clients present no deployment identifier MUST refuse an Intent
    carrying this control with `invalid_authorization_details`. The
    identifier's format, and what change constitutes a distinct
    Agent Deployment, are deployment policy; the pin is recorded and
    committed like every control and never widens or derives
    authority. This object is the agent's behavioral version, not
    the deployment's published claims manifest.

This document defines no cumulative consumption bounds (for example, a
budget, call-count, or activity-duration cap): every bound this
document defines is enforced by a party this document names. An
experimental companion defines cumulative consumption bounds as
`controls` extension members together with the runtime metering that
enforces them ({{I-D.draft-mcguinness-mission-metering}}). The
following table summarizes which party enforces each bound a Mission
carries and what holds when that enforcer is absent:

| Bound | Enforced by | When that enforcer is absent |
|---|---|---|
| `resource` and `actions` | any Resource Server that enforces `authorization_details` ({{rs-enforcement}}) | a scope-only RS enforces only the coarse `scope` projection ({{rs-enforcement}}) |
| per-entry `constraints` | a Resource Server that understands and enforces the key ({{rs-enforcement}}) | a Mission-aware RS fails closed; a scope-only RS does not evaluate them |
| `max_derivations` | the issuer AS at each derivation ({{lifecycle}}) | never absent at the issuer; it does not bound another domain's local minting (see the cross-domain companion) |

Example Mission Intent:

~~~ json
{
  "goal": "Reconcile Q3 invoices and post adjustments under $500.",
  "resources": ["https://erp.example.com"],
  "constraints": [
    "Read only invoices issued in 2026-Q3.",
    "Post journal entries under $500."
  ],
  "success_criteria": [
    "All Q3 invoices reconciled.",
    "Each posted adjustment references a source invoice."
  ],
  "purpose": "urn:example:purpose:reconcile",
  "expires_at": "2026-12-31T23:59:59Z",
  "controls": {
    "acr": "urn:example:acr:mfa",
    "max_derivations": 200
  }
}
~~~

## Submission via PAR {#submission-via-par}

A client MUST submit a Mission Intent through a Pushed Authorization
Request {{RFC9126}} using the `mission_intent` request parameter. The
parameter value is the UTF-8 JSON {{RFC8259}} serialization of the
Mission Intent object, carried as an ordinary OAuth request-parameter
value (form-encoded in the `application/x-www-form-urlencoded` PAR
request body, like other OAuth parameters). The AS returns a
`request_uri` as usual, which the client uses to start authorization.
An AS that cannot parse `mission_intent` as a JSON object, or that
parses it but finds it structurally invalid against this document's
member definitions, MUST refuse the request with `invalid_request`.

Submission is governed by the following rules:

- **Closed top level.** The AS MUST reject with `invalid_request` a
  Mission Intent containing a top-level member this document does
  not define; extension data belongs under `controls`
  ({{mission-intent}}), so deployment-defined semantics are explicit
  and cannot masquerade as core Intent semantics. The top level is
  closed because its members
  feed approval rendering and the `intent_hash` commitment, and the
  closure also keeps issuer-output members, such as a client-planted
  `authority_hash`, out of the Intent.
- **Derivation failure is distinct from syntax.** For an Intent that
  is well-formed but yields no valid Authority Set (an unsupported
  resource, action, or authorization details type, or a policy that
  bars the requested authority), the AS SHOULD refuse with
  `invalid_authorization_details` ({{RFC9396}}), even though the
  client did not submit `authorization_details` directly, so a
  client can tell a syntax error from a derivation failure.
- **One carriage, through PAR.** The Intent is accepted only as the
  form-encoded `mission_intent` parameter of the PAR request body.
  The AS MUST reject with `invalid_request` a `mission_intent`
  presented on a front-channel authorization request that does not
  use a PAR-issued `request_uri`, and MUST NOT unwrap a request
  object to find an Intent, whether that object rides the front
  channel or is itself pushed through PAR. A single carriage keeps
  precedence unambiguous and keeps the member set the AS validates
  and bounds in one place; PAR keeps the integrity-sensitive Intent
  off the untrusted front channel.
- **Bounded size.** The AS MUST bound the Intent's total size and
  the lengths of its arrays, refusing an Intent that exceeds the
  deployment-defined limits with `invalid_request`, so an oversized
  Intent cannot exhaust the AS at rendering, derivation, or hashing.
- **No raw authorization details.** A client MUST NOT submit the
  {{RFC9396}} `authorization_details` request parameter together
  with `mission_intent`, and the AS MUST refuse a request carrying
  both with `invalid_request`: concrete authority is proposed inside
  the Intent, through `proposed_authority` ({{mission-intent}}). A
  client MAY submit `scope` and `resource` ({{RFC8707}}) values; the
  AS treats them as a requested subset and MUST NOT grant authority
  beyond what the Mission Intent yields.
- **Pushed parameters are authoritative.** On the front-channel
  request that redeems the `request_uri`, the AS MUST ignore any
  `mission_intent`, `authorization_details`, `scope`, or `resource`
  presented, and MUST NOT let such a value widen the authority
  derived from the pushed Intent.
- **A proposal, never authority.** A Mission Intent is untrusted
  client input; trust enters only when the AS validates it and the
  Approver consents to the rendered result. The AS MUST treat the
  submitted Intent as a proposal and MUST derive and bound authority
  by policy regardless of what the client submitted. How a client
  produces the Intent (for example, a "Mission Shaper" deriving it
  from a natural-language instruction) is out of scope for this
  document.

# Mission Authority {#authorization-derivation}

From the Mission Intent, the AS derives the **Authority Set**: one or
more {{RFC9396}} `authorization_details` entries of type
`mission_resource_access` ({{type-registration}}). Derivation is
mechanical. It happens once, at the approval event, over the
derivation policy then in force, in one of two modes:

- **Narrowing mode** (RECOMMENDED): the Intent carries
  `proposed_authority` ({{mission-intent}}), and the Authority Set is
  the proposal narrowed to policy. Each derived entry MUST be a
  subset ({{subset}}) of some `proposed_authority` entry; a proposed
  entry policy cannot accept is narrowed or omitted.
- **Template mode**: the Intent carries no `proposed_authority`, and
  a deployment-configured mapping, keyed on the Intent's `purpose` or
  `resources`, yields the candidate entries, which are then narrowed
  to policy. The mapping is a lookup, never synthesis; the AS refuses
  an Intent that matches no configured mapping with
  `invalid_authorization_details`.

In both modes the AS MUST bound every derived entry by the Mission
Intent (each derived entry's `resource` MUST be one of the Intent's
`resources` values, and the derived authority MUST NOT exceed any
machine-actionable `controls` bound) and MUST record the policy
version in force as the Mission's `policy_version`: an opaque audit
correlator naming the policy a derivation ran under, not a value
whose policy travels. Deriving authority generatively, from the
Intent's free text or with model assistance, is not one of this
profile's modes: a deployment MAY implement it as a local-policy
extension, it is the least portable option, and the Intent bounds
and recording rule above still apply to it.

A `resources` entry the deployment does not recognize either causes
refusal with `invalid_authorization_details` ({{submission-via-par}})
or is omitted from the Authority Set, by deployment policy. When an
omission or a narrowing leaves the Authority Set short of what the
Intent proposed, derivation is partial, and the AS signals it
machine-readably: a token response under a partially derived Mission
MUST include the `mission_derivation` token-response parameter
({{iana}}) with the value `partial`, and MAY carry it with the value
`full` otherwise, so a client learns of omission without diffing the
`authorization_details` echo ({{mission-bound-tokens}}) against its
proposal. The echo remains the authoritative statement of what was
granted.

The derived Authority Set, not the Mission Intent, is the authority the
Approver consents to: the AS renders the Authority Set for approval and
commits it as `authority_hash` ({{approval-event}}). The Intent's
`goal`, `constraints`, and other members describe and bound the task
but grant no authority by themselves ({{mission-intent}}); they
constrain what the AS MAY derive, never widen it.

Derivation is governed by local policy and is not a portable algorithm:
different Authorization Servers MAY derive different Authority Sets from
the same Mission Intent, exactly as different deployments grant
different authority for the same {{RFC9396}} request or the same scope.
That locality is intended, not a gap. A Mission Intent has no portable
semantics: interoperability begins at the committed result, the derived
Authority Set's structure and vocabulary
({{authorization-derivation}}, {{common-constraints}}) and its
integrity anchors ({{integrity-anchors}}), which a consumer in any
domain interprets, enforces, and audits identically. A consumer enforces
the derived Authority Set, never the Intent, and audit establishes what
was derived, against `intent_hash` and `policy_version`, never whether
the derivation was the right reading of the task. A deployment whose
partners reason about its derivations SHOULD publish a derivation
policy identifier and test fixtures pinning Intent-to-Authority-Set
outcomes; the policy itself does not travel.

For an open-ended task whose concrete objects cannot be enumerated at
approval (for example, "reconcile this customer's ledger," where the
individual invoices are not yet known), the AS SHOULD bound the derived
authority primarily by `constraints` that hold as invariants over those
objects (the owning customer, the tenant, an amount ceiling, read-only
except named write actions, a validity window) rather than by an
exhaustive `resource` enumeration. The runtime layer
({{runtime-boundary}}) checks each concrete object against the
constraint at the point of use. Constraint-bounding lets a Mission cover
an open-ended task with tight authority even though the specific objects
are unknown at approval, and avoids the over-broad enumeration a
deployment would otherwise need in order to anticipate them.

A `mission_resource_access` entry is a {{RFC9396}}
`authorization_details` object with these members:

`type`:
: REQUIRED. A string. `mission_resource_access`.

`resource`:
: REQUIRED. A string. The single protected resource the entry
  applies to: an absolute URI identifying an OAuth protected
  resource ({{RFC8707}}) or a Protected Resource ({{RFC9728}}), the
  same kind of identifier as the {{RFC8707}} `resource` value.
  Carrying it per entry, which {{RFC9396}} permits, lets one token
  scope distinct authority to distinct resources. The token `aud` is
  derived from the carried entries' `resource` values and is
  typically coarser ({{mission-bound-tokens}}). Per {{RFC9396}}
  Section 3.2, the `resource` authorization request parameter does
  not affect how the AS processes `authorization_details`, and this
  member is distinct from the {{RFC9396}} common `locations` field.

`resource_match`:
: OPTIONAL. A string: `exact` (the default, and the behavior when the
  member is absent) or `prefix`. Under `exact` the entry applies to the
  `resource` URI alone. Under `prefix` the entry authorizes the
  `resource` itself and any URI beneath it at a path-segment boundary
  (the `resource` followed by `/` and further path). A `resource`
  value under `prefix` MUST NOT carry a query or fragment component;
  the AS refuses such an entry with `invalid_authorization_details`.
  For prefix purposes, a `resource` with an empty path and one whose
  path is `/` denote the same base: `https://a.example` and
  `https://a.example/` authorize the same set. These two values
  are the only ones defined; a consumer MUST treat an entry whose
  `resource_match` value it does not recognize as unenforceable and
  fail closed ({{rs-enforcement}}). Containment between effective
  resource sets is compared as defined in {{subset}}.

`actions`:
: REQUIRED. An array of strings. Permitted action values: each is an
  action identifier matching `[A-Za-z0-9_.:-]+`, or an action family
  (an identifier followed by `.*`). Like an OAuth scope, an action
  value carries meaning only at the `resource` that defines it; a
  consumer enforces only the actions it recognizes for that resource
  and honors no others, so an unrecognized action is fail-closed by
  construction. An AS SHOULD draw action identifiers from a
  namespace the serving resource documents, so the set is
  interpretable cross-vendor rather than ad hoc.

  An action family authorizes every action whose dot-separated
  identifier extends the family name at a segment boundary
  (`invoices.*` authorizes `invoices.read` and `invoices.q3.export`,
  not `invoicesx.read`). A consent rendering MUST present a family
  as the breadth it is: all actions under the name, not one action.
  An AS SHOULD treat deriving a family as high-risk breadth.

`constraints`:
: OPTIONAL. An object. Machine-actionable per-resource
  bounds (for example, `max_amount`). A member name defined as a
  Common Constraint ({{common-constraints}}) has shared semantics
  across deployments; any other name is deployment-defined.

  - Because a `constraints` member narrows authority, a Resource Server
    that cannot enforce one MUST fail closed ({{rs-enforcement}}).
  - To avoid that failure mode, the AS SHOULD emit for a given
    `resource` only `constraints` keys that the Resource Server serving
    it is known (by registration, deployment policy, or the resource's
    advertised `mission_constraints_supported`
    ({{protected-resource-metadata}})) to understand and enforce.

`delegation`:
: OPTIONAL. An object. The delegation policy for this
  entry ({{delegation-constraints}}). When absent, this entry's
  authority is non-delegable: it MUST NOT appear in a delegated
  token. When present, it has these members:

  `max_depth`:
  : REQUIRED. An integer. The maximum delegation depth at
    which this entry's authority may be exercised
    ({{delegation-constraints}}).

  `allowed_delegates`:
  : RECOMMENDED. An array of objects. The permitted
    delegates, each a `may_act`-style matcher
    ({{delegation-constraints}}): `{ "sub": "<client_id>" }` for a
    specific delegate, or `{ "sub_profile": "<actor-type>" }` for an
    actor-type class. When absent, eligibility falls to the AS's
    delegation-authorization policy, which MUST be applied at every
    exchange ({{delegation-constraints}}); absence delegates the
    decision to policy, it never grants blanket eligibility. The
    member is RECOMMENDED so that eligibility is committed and
    rendered with the entry rather than left wholly to policy.

  A companion profile of this document MAY define additional
  `delegation` members. Such a member is policy, not authority
  ({{delegation-constraints}}): a derived entry's value for it MUST
  NOT be broader than the parent entry's, and a member the AS does not
  understand is carried unchanged.

Example Authority Set (the read entry is delegable to depth 2 and
bounded to a Q3 issuance window by the `resource_issued_after` and
`resource_issued_before` Common Constraints ({{common-constraints}});
the write entry carries no `delegation` and so is non-delegable, because
`delegation` is per entry):

~~~ json
[
  { "type": "mission_resource_access",
    "resource": "https://erp.example.com",
    "actions": ["invoices.read"],
    "constraints": {
      "resource_issued_after": "2026-07-01T00:00:00Z",
      "resource_issued_before": "2026-09-30T23:59:59Z"
    },
    "delegation": {
      "max_depth": 2,
      "allowed_delegates": [{ "sub_profile": "ai_agent" }]
    } },
  { "type": "mission_resource_access",
    "resource": "https://erp.example.com",
    "actions": ["journal-entries.write"],
    "constraints": {
      "max_amount": { "amount": "500.00", "currency": "USD" }
    } }
]
~~~

## Subset Rule {#subset}

When the AS narrows the Authority Set for a derived token, a derived
`mission_resource_access` entry A is a subset of a Mission entry B
when:

1. A's effective resource set is contained in B's
   (`resource_match`, {{authorization-derivation}}): when neither
   entry sets `resource_match: "prefix"`, A.`resource` equals
   B.`resource`; when B is a `prefix` entry, A (whether `exact` or
   `prefix`) is contained when A.`resource` equals B.`resource` or
   extends its path at a path-segment boundary; a `prefix` A is never
   contained in an `exact` B.
2. Every A.`actions` value is within some B.`actions` value: a value
   is within an equal value; a literal action is within a family whose
   name it extends at a segment boundary (`invoices.read` is within
   `invoices.*`); a family is within a reference family when its own
   name extends the reference's name at a segment boundary
   (`invoices.q3.*` is within `invoices.*`). A family is never within
   a literal action.
3. For every key K in **B**.`constraints`, K MUST also be present in
   A.`constraints`, and A's value MUST be no broader than B's under
   K's subset rule: the specification-defined rule when K is a Common
   Constraint
   ({{common-constraints}}), the deployment-defined comparison
   otherwise. A key present in B but absent from A is treated as the
   broadest possible value and therefore fails this test. In short,
   constraints MUST NOT be dropped, only added or tightened.

The AS MUST refuse to derive an entry that is not a subset of some
Mission Authority Set entry.

Authority under a Mission MUST NOT widen after the approval event: a
request that exceeds the Authority Set on any dimension (a new
resource, action, actor, delegation path, longer duration, or
constraint relaxation) is refused under this rule, and broader
authority requires a fresh approval event, either a new Mission or a
successor per the companion
{{I-D.draft-mcguinness-oauth-mission-expansion}}.

Resource containment under a `prefix` reference is compared after
RFC 3986 {{RFC3986}} syntax-based normalization of both URIs: lowercase
the scheme and host, remove a default port, decode percent-encoded
octets of unreserved characters, and remove dot-segments. This
normalization applies to comparison only, never to hashing: anchor
computation ({{integrity-anchors}}, {{canonicalization}}) remains
byte-exact over the recorded values and is untouched by this rule.

The default comparison is deliberately flat: `resource` matches by
exact equality and a literal action by array membership. Hierarchy is
opt-in and closed to the two forms above: `resource_match: "prefix"`
for resource containment and `.*` action families for action
containment ({{authorization-derivation}}). A deployment that uses
neither retains the flat behavior unchanged.

The `delegation` member is policy, not authority, and is not part of
this comparison ({{delegation-constraints}}). A derived entry's
`delegation`, when present, MUST NOT be broader than the parent entry's:
its `max_depth` MUST be no greater and its `allowed_delegates` MUST be
no wider. A derived entry MUST NOT introduce `delegation` where the
parent entry has none.

The comparison is representational, not semantic. A candidate that
compares as no broader can still permit effects the parent's purpose
never contemplated, because narrowing is judged over the entry's
members, not over meaning; semantic narrowing is not a property this
rule can provide. Where the comparison relation cannot decide (an
unrecognized member, an incomparable value), the posture is
conservative refusal, as each consuming rule of this document states.

## Common Constraints {#common-constraints}

A `constraints` member name ({{authorization-derivation}}) is either a
specification-defined **Common Constraint** or a deployment-defined
key. Common
Constraints give independently developed deployments one vocabulary
they interpret, narrow, and compare identically; further Common
Constraints are defined by specification under the naming convention of
{{iana-common-constraints}}.

A Common Constraint definition fixes:

- **Value syntax**: the JSON {{RFC8259}} value type and any additional
  rules.
- **Subset rule**: how a candidate value is judged no broader than a
  reference value, used by the subset comparison of {{subset}}.
- **Intersection rule**: how two values for the same key combine; the
  result MUST be no broader than either operand.

A `constraints` member whose name is a specification-defined Common
Constraint is interpreted per its
definition. Any other member name remains
deployment-defined and is interpreted only within the issuing
deployment; a consumer that does not recognize it MUST fail closed
({{rs-enforcement}}).

This document defines the initial Common Constraints:

- `max_amount` (object): a per-action ceiling on a monetary amount.
  The value is an object with two members: `amount` (REQUIRED, a
  string containing a decimal number) and `currency` (REQUIRED, an
  ISO 4217 {{ISO4217}} currency code). Subset: no broader when the `currency`
  values are equal and the candidate `amount` is less than or equal
  to the reference `amount`, compared in decimal value space;
  differing currencies fail the comparison (no conversion is
  defined). Intersection: when the `currency` values are equal, the
  value with the smaller `amount`; differing currencies have no
  intersection and the combination fails.
- `resource_issued_after` (string, an RFC 3339 {{RFC3339}} date-time):
  the action applies only to resources issued at or after this instant.
  Subset: no broader when greater than or equal to the reference.
  Intersection: the later instant.
- `resource_issued_before` (string, an RFC 3339 {{RFC3339}} date-time):
  the action applies only to resources issued at or before this
  instant. Subset: no broader when less than or equal to the reference.
  Intersection: the earlier instant. The `resource_` qualifier in both
  names marks that the window bounds resource issuance, not token
  issuance.
- `tenant` (string): the action applies only to resources of the named
  tenant. Subset: no broader when equal to the reference value.
  Intersection: the common value when the two are equal; otherwise
  there is no intersection and the combination fails.
- `recipient_domain` (string, a DNS name): the action applies only to
  recipients within the named domain. Subset: no broader when equal to
  the reference or a DNS subdomain of it. Intersection: the narrower
  value when one is equal to or a subdomain of the other; otherwise
  there is no intersection and the combination fails.
- `time_window` (object): the action may be exercised only within the
  window, evaluated at the point of use (unlike `resource_issued_after`
  and `resource_issued_before`, which bound resource issuance, and
  unlike token `exp`, which bounds the credential). The value has two
  members, `not_before` and `not_after` (each an RFC 3339 {{RFC3339}}
  date-time); at least one MUST be present, and an absent member is
  unbounded on that side. Subset: no broader when the candidate window
  lies within the reference window, an absent candidate bound counting
  as unbounded and therefore broader than any present reference bound.
  Intersection: the overlap (the later `not_before`, the earlier
  `not_after`); an empty overlap has no intersection and the
  combination fails.
- `data_classification` (array of strings): the action applies only to
  data whose classification label is among the named values. Label
  semantics are deployment- or registry-defined; the comparison is not.
  Subset: no broader when the candidate array's members are a subset of
  the reference array's, compared as exact strings. Intersection: the
  common members; an empty result has no intersection and the
  combination fails.
- `allowed_tools` (array of strings): the action may be exercised only
  through a capability whose identifier is among the named values (a
  tool or function identity, asserted at the point of use by the
  enforcing component). Subset: no broader when the candidate array's
  members are a subset of the reference array's, compared as exact
  strings. Intersection: the common members; an empty result has no
  intersection and the combination fails.
- `requires_action_approval` (boolean): when `true`, each exercise of
  the action requires a fresh, action-bound approval at the point of
  use; the enforcing component MUST NOT permit the action on Mission
  authority alone. A value of `false` is equivalent to omitting the
  member. Subset: no broader when the candidate is `true` or equals
  the reference (narrowing may add the requirement, never remove it).
  Intersection: the logical OR of the two values.

These comparisons are in value space, not lexical: `max_amount`
`amount` members are compared as the decimal numbers the strings
contain, so `"500"`, `"500.0"`, and `"500.00"` are equal;
`resource_issued_after` and `resource_issued_before` values are
compared as the
instants they denote after normalization to UTC, so two RFC 3339
representations of the same instant that differ only in timezone offset
or trailing subsecond zeros are equal; `recipient_domain` values are
compared as DNS names, case-insensitively and on whole labels, so
`mail.example.com` is within `example.com` and `example.net` is
not. A Common Constraint definition
MUST fix its subset and intersection in value-space terms, so that
independent deployments compute the same result for the same values and
the subset rule of {{subset}} is reproducible.

A numeric constraint value MUST lie within the range JCS {{RFC8785}}
serializes exactly. Monetary amounts avoid that hazard by
construction: `max_amount` carries its `amount` as a string containing
a decimal number, paired with an ISO 4217 {{ISO4217}} `currency` code, and a
future Common Constraint for a monetary value SHOULD reuse this shape
rather than a JSON number.

## Other Authorization Details Types {#other-types}

`mission_resource_access` is the only type this document defines, but
the Authority Set MAY include other AS-supported {{RFC9396}}
`authorization_details` types when an audience consumes them. ("Supported"
here means the AS recognizes and documents the type, as advertised by
`authorization_details_types_supported` ({{discovery}}); RFC 9396
establishes no IANA registry of type identifiers.) The Mission apparatus
is type-agnostic toward such entries:

- they are committed by `authority_hash` and gated on Mission state
  exactly as `mission_resource_access` entries are;
- narrowing and delegation use the subset semantics the type defines
  ({{subset}}, {{delegation-constraints}}). A type whose subset and
  delegation semantics the AS does not understand MUST NOT be
  delegated, audience-projected to a Resource AS, or narrowed: the AS
  cannot prove a transformed copy is still a subset of what was
  approved. Such an entry MAY be issued only to its original approved
  audience, carried exactly as approved, and MUST NOT appear in a
  delegated token or in a cross-domain grant
  ({{I-D.draft-mcguinness-oauth-mission-cross-domain}});
- evaluating the entry against a concrete request is the runtime
  layer's responsibility ({{runtime-boundary}}), not the AS's.

This lets policy-language profiles compose without this document
defining them: for example, an entry carrying a Cedar policy set
({{I-D.draft-cecchetti-oauth-rar-cedar}}), or an analogous AuthZEN
policy entry, for an audience that evaluates it. The AS derives such
an entry from the Mission Intent and bounds it by the Intent like any
other, but treats the carried policy largely opaquely; the Resource
Server or Policy Decision Point (PDP) evaluates it at request time.

Stated as a limit: the subset rule is fully defined only over
`mission_resource_access` and its Common Constraints. Authority
expressed in another type has whatever subset relation that type
defines, or none, and where it has none the entry is carried as
approved: never narrowed, delegated, or projected. The narrowing
guarantee is therefore strongest while authority stays in
`mission_resource_access` entries, and weakens as expressiveness
moves into opaque policy-language entries.

Example (non-normative): an Authority Set with a Cedar policy entry
for a finance audience that consumes Cedar, alongside a
`mission_resource_access` entry for a calendar audience that does not.
The Cedar `policySet` is abbreviated:

~~~ json
[
  {
    "type": "account_information",
    "rarFormat": "cedar",
    "policySet": "permit(principal, action, resource) when {...};"
  },
  {
    "type": "mission_resource_access",
    "resource": "https://calendar.example.com",
    "actions": ["events.read"],
    "constraints": { "window_days": 30 }
  }
]
~~~

Both entries are committed by the one `authority_hash` and bound to
the Mission. The Cedar entry is evaluated by the finance audience's
PDP; the `mission_resource_access` entry is enforced as in
{{mission-bound-tokens}}. Because the Cedar profile defines no subset
or delegation rule over policy sets, the AS carries the Cedar entry as
approved rather than narrowing it, and it MUST NOT appear in a
delegated token or cross-domain grant. Delegation controls on other
entries, such as the `mission_resource_access` entry, apply to those
entries only.

## Modeling Tools and Function Calls {#tools}

This section is non-normative guidance. A "tool" an agent invokes,
such as a Model Context Protocol (MCP) tool or a function call, is
modeled as a `mission_resource_access` entry. No separate entry type
is needed, and the rules above (derivation, subset, delegation,
`authority_hash`) apply unchanged.

The mapping is:

- `resource` is the tool provider. For an MCP tool it is the MCP
  server's URL. The MCP authorization model ({{MCP}}) makes the
  server an OAuth
  2.0 resource server, so this is the resource identifier a token is
  audience-bound to.
- `actions` are the tool names the task needs at that provider.
  Authorizing a tool is authorizing its name as an action, which
  lines up with MCP filtering its tool list by the caller's granted
  authority and routing each tool call for authorization.
- `constraints` carry machine-actionable bounds on a tool's
  arguments, for example an amount ceiling or a recipient domain (the
  `max_amount` and `recipient_domain` Common Constraints,
  {{common-constraints}}).
  Like all `constraints`, they are committed by `authority_hash` and
  carried to the point of use, but they are evaluated against the
  concrete call arguments by a runtime enforcement layer, not at
  issuance ({{runtime-boundary}}).

For example, a Mission authorized to read invoices and post small
adjustments through a finance MCP server, and to send messages
through a messaging MCP server, derives:

~~~ json
[
  { "type": "mission_resource_access",
    "resource": "https://finance.example.com/mcp",
    "actions": ["query_invoices", "post_adjustment"],
    "constraints": {
      "max_amount": { "amount": "500.00", "currency": "USD" }
    } },
  { "type": "mission_resource_access",
    "resource": "https://mail.example.com/mcp",
    "actions": ["send_message"],
    "constraints": { "recipient_domain": "example.com" } }
]
~~~

Delegation to a sub-agent works unchanged: add a `delegation` member
to a tool entry ({{delegation-constraints}}). For example, an entry a
sub-agent of type `ai_agent` may invoke at depth 1, narrowed to the
read tool only:

~~~ json
{ "type": "mission_resource_access",
  "resource": "https://finance.example.com/mcp",
  "actions": ["query_invoices"],
  "delegation": {
    "max_depth": 1,
    "allowed_delegates": [{ "sub_profile": "ai_agent" }]
  } }
~~~

What this profile does not provide for tools is a typed, attenuable
per-argument constraint grammar: narrowing one tool's argument schema
against another (for example, `amount` in a `range`, `recipient` in a
`one_of` set) as the grant is derived or delegated. Argument bounds
here are the same flat, carried `constraints` used for any resource,
evaluated at runtime. Structured per-argument attenuation
({{I-D.draft-niyikiza-oauth-attenuating-agent-tokens}}, with object
capability systems such as UCAN as prior art) is a richer primitive
deferred to future work; it would extend the delegation and subset
model of this document ({{delegation-constraints}}, {{subset}})
rather than introduce a new entry type.

# Mission Approval {#approval-event}

The approval event is the atomic transition at which the Approver
consents and the AS creates the Mission. It runs as an OAuth 2.0
{{RFC6749}} authorization-code flow initiated from the PAR-issued
`request_uri` ({{submission-via-par}}). Because the authorization code
is the artifact the Mission grant binds to ({{grant-binding}}) and it
travels the front channel, the AS MUST bind the code to the requesting
client with PKCE ({{RFC7636}}, `S256` challenge method) or,
equivalently, issue a DPoP-bound authorization code ({{RFC9449}}). The
AS MUST reject a code redemption whose PKCE verifier or DPoP key does
not match the binding established for the request. This prevents
authorization-code injection from yielding the Mission grant. The AS
SHOULD include the `iss` authorization-response parameter
({{RFC9207}}) on the authorization response, so the client can detect
a mix-up attack on the consent-bearing redirect leg (per the guidance
of {{RFC9700}}).

At the approval event the AS MUST, in order:

1. Authenticate the Approver. If the Mission Intent's
   `controls.acr` is present, the authentication MUST satisfy it.
2. Establish the Subject: the principal the task is for, recorded as
   the Mission's `subject` and set as the `sub` of every derived token
   ({{mission-bound-tokens}}). When the Approver is the Subject
   (self-approval), this is the authenticated Approver. When the
   Approver is a different principal (for example, an administrator or
   manager approving on a user's behalf), the AS MUST itself establish
   the Subject's (`iss`, `sub`), and MUST authorize the Approver to
   approve for that Subject under local policy. The AS MUST NOT take the
   Subject from unauthenticated client input. This document defines no
   wire parameter for the Subject; how the AS establishes it
   (administrative selection, a directory, an authenticated reference)
   is a deployment matter.
3. Render for consent the derived Authority Set in human-meaningful
   terms, with the `goal`, `constraints`, `expires_at`, and any
   `controls` bounds (notably `max_derivations`) as context. The object
   the Approver consents to is the **derived Authority Set**, what the
   agent may actually do, not the `goal` or Mission Intent: derivation
   is local policy, and nothing commits that the derived authority
   faithfully reflects the goal the Approver read, so the authority
   itself MUST be what is rendered and consented to. An approval surface
   that renders only the `goal`, `success_criteria`, or Mission Intent
   and not the derived Authority Set does not conform. Additionally:
   - When the Approver is not the Subject, the rendering MUST
     identify the Subject the authority is granted for.
   - When the Intent carried `proposed_authority`
     ({{mission-intent}}), the rendering MUST distinguish the entries
     the client proposed from any narrowing or restructuring the AS
     applied.
4. Compute the integrity anchors ({{integrity-anchors}}):
   `authority_hash` over the consented Authority Set and
   `intent_hash` over the approved Mission Intent.
5. Create the Mission record ({{mission-record}}) in the `active`
   state, atomically with issuance of the authorization code.

The atomic coupling of the approval decision to authorization-code
issuance is this flow's shape, not the model's: a companion profile
({{I-D.draft-mcguinness-oauth-mission-approval}}) relocates the
approval event for deployments whose approvals are asynchronous or
reviewer-narrowed, under the extension seam of {{extensibility}};
the steps above, their order, and the atomicity of record creation
with the approval decision are what any relocation preserves.

The consent rendering is hardened against client text:

- Client-supplied strings (`goal`, `constraints`,
  `success_criteria`) MUST be rendered as inert text and MUST NOT be
  interpreted as markup.
- The AS SHOULD mitigate Unicode direction-override and
  confusable-character presentation in them.
- The rendering MUST visually distinguish the AS-derived Authority
  Set from client-supplied text, so crafted client text cannot pass
  as derived authority.

A deployment MUST declare a minimum approval-authentication strength
for Missions whose derived Authority Set carries high-risk authority:
irreversible, external-commitment, or privileged-administration
actions under the deployment's classification, or a consumption bound
({{I-D.draft-mcguinness-mission-metering}}). The declaration's home
is the deployment's published statement of what it enforces (the
Mission Deployment Profile of
{{I-D.draft-mcguinness-mission-architecture}}), so the floor is a
checkable published fact rather than a floating duty. The approval
authentication for such a Mission MUST meet that minimum, and
`controls.acr` can raise the required strength but never lower it below
the floor. The material notices of the consent-evidence profile
identify these same high-risk classes
({{I-D.draft-mcguinness-oauth-mission-consent-evidence}}).

An Approver who declines, and an Approver whose authentication cannot
satisfy `controls.acr` or the declared approval-strength floor, yield
`access_denied` on the authorization
response ({{RFC6749}}). A token-endpoint `resource` value outside the
Authority Set yields `invalid_target` ({{RFC8707}}).

Rendering a bound is not the same as enforcing it, and a deployment MUST
NOT let the rendering imply otherwise. Which party enforces each bound,
and what holds when that enforcer is absent, is summarized in the
enforcement table ({{mission-intent}}). An AS SHOULD make clear
to the Approver which rendered bounds its deployment actually enforces,
so consent is not given to a limit that binds nowhere.

The `authority_hash` is the **authority commitment**: it binds, by
cryptographic digest, exactly the authority the Approver approved. It
commits the approved authority, not the way that authority was
rendered to the Approver; this profile commits no separate consent
disclosure object (see {{consent-binding}}). Every token derived
under the
Mission carries this value ({{mission-bound-tokens}}), so a party
holding the full Authority Set can verify a token's authority against
what was approved. A party holding only a narrowed subset cannot
recompute it and treats it as an audit anchor (see
{{consent-binding}}).

If the derived Authority Set changes between rendering and consent,
the AS MUST recompute the anchors and MUST NOT activate the Mission
unless the Approver consents to the changed set.

The `intent_hash` commits the **approved Mission Intent**: the
task the Approver consented to, as recorded on the Mission. It makes
the recorded task tamper-evident: an auditor can verify the Mission's
`intent` against `intent_hash` and detect any later
alteration. `intent_hash` commits the task; `authority_hash`
commits the authority derived from it.

## Binding the Mission to the Grant {#grant-binding}

At the approval event the AS binds the Mission to the authorization
grant it issues: the authorization code, and the refresh token
issued from it. The binding is server-side and is what "the
referenced Mission" in {{lifecycle}} refers to. At each subsequent
derivation the AS resolves the Mission from the grant the client
presents: the authorization code at the token endpoint (the initial
exchange uses `grant_type=authorization_code`), the refresh
token on refresh, or the Mission-bound `subject_token` on Token
Exchange (the `actor_token` identifies the delegate, {{delegation}}).
It then applies the gating of {{lifecycle}}. A client does
not supply `mission_id` to obtain a derivation; an AS MUST NOT derive
Mission-bound authority from a client-supplied `mission_id`, because
the grant, not the identifier, determines the Mission. When the
authorization code expires unredeemed, no derivation is possible under
the Mission; the AS SHOULD revoke the Mission or allow it to expire.

A client learns its `mission_id` from the `mission` claim's `id` on
each issued token ({{mission-claim}}) or from the token response. This
document defines `mission_id` as a token-endpoint response
parameter: a string carrying the Mission Identifier, returned
alongside the issued token. An AS SHOULD return it: the client is not
expected to parse the access token, and when the parameter is absent
the only path to the identifier is reading the `mission` claim, which
fails for a token that is encrypted or opaque to the client. It is an
informational reference only:
presenting it authorizes nothing ({{lifecycle}}), and a client MUST
NOT derive authority from it.

## Single Accountable Approver {#multi-party-approval}

This document records exactly one `approver`: the
accountable principal who approved the Mission. Two richer patterns
are deliberately out of scope and deferred:

- **Multi-party approval** (M-of-N or dual control), where more than
  one principal must approve. The number of approvers is orthogonal
  to the consent commitment: however many principals approve the same
  rendered Authority Set, the `authority_hash` is identical, as is
  every token derived from it. Multi-party approval raises the
  assurance of *how* approval was obtained; it does not change the
  artifacts this document produces. A deployment requiring dual
  control records one accountable Approver under the same
  `authority_hash`; this document does not natively represent the
  co-approvers.
- **Approval-authority provenance** (the standing policy or delegation
  an administrator or headless approval traces back to). This is
  governance state about who stands behind a delegated approval, not
  part of binding tokens to approved authority, and is left to a
  governance layer.

Both remain out of the core. Where a deployment needs them, they are
recorded by the deferred-approval profile's Approval Decision Set
({{I-D.draft-mcguinness-oauth-mission-approval}}) and consent
evidence's co-approval members
({{I-D.draft-mcguinness-oauth-mission-consent-evidence}}).

## Integrity Anchors {#integrity-anchors}

Both anchors are computed the same way over a domain-separated,
issuer-bound envelope:

1. Construct the envelope, where `typ` selects the committed object
   and `value` is that object:

   ~~~
   {
     "typ": "<mission-intent | mission-authority-set>",
     "iss": "<the AS issuer URL>",
     "value": <the committed object>
   }
   ~~~

   For `intent_hash`, `typ` is `mission-intent` and `value` is the
   approved Mission Intent object. For `authority_hash`, `typ` is
   `mission-authority-set` and `value` is the Authority Set as a JSON
   array of entries.

2. Canonicalize the envelope with JCS {{RFC8785}}.
3. Compute SHA-256 {{RFC6234}} over the canonical bytes.
4. Encode as `sha-256:` followed by the base64url, no-padding,
   encoding of the digest.

The `typ` field domain-separates the two anchors so a digest of one
object can never be mistaken for the other. The `iss` binding
prevents a committed object from being transplanted across
Authorization Servers.

The `typ` value space is an extension point ({{extensibility}}):
additional committed objects use this same envelope with a new `typ`
and the canonicalization below. This document defines no registry of
`typ` values; each committing specification defines its own and relies
on the `typ` domain separation. To keep that domain separation safe
without a registry, a new `typ` value MUST be a collision-resistant name
(for example, a short name prefixed within a namespace the defining
profile controls, following the Collision-Resistant Name guidance of
{{RFC7519}} Section 4.2). The `mission-` prefixed values defined by
profiles that extend this document share an author-coordinated
namespace for this reason.

SHA-256 is the only digest algorithm this document defines; the
`sha-256:` prefix identifies it. Algorithm agility is future work.

A verifier MUST reject an integrity anchor whose algorithm prefix it
does not recognize. A verifier MUST NOT treat an unrecognized prefix as
`sha-256`. This ensures that adding an algorithm later cannot be
exploited as a downgrade.

## Canonicalization Rules {#canonicalization}

JCS {{RFC8785}} alone does not make two implementations agree on
every byte. The following rules close the remaining gaps; they apply
to computing an anchor and to comparing committed values:

- The committed `value` is exactly the object the AS recorded on the
  Mission: the approved `intent` for `intent_hash`, the
  `authority_set` for `authority_hash`. An auditor reproduces a
  digest from the record alone.
- The AS MUST reject an input object containing duplicate JSON member
  names before canonicalization; such input is invalid.
- JCS does not reorder array elements, and this document defines no
  element sorting, so array order is significant. The AS MUST emit
  each array in a fixed, reproducible order; that order is part of
  the canonical form.
- URI-valued members are compared byte-for-byte unless a member's
  definition specifies a normalization. The only normalization this
  document defines is the RFC 3986 {{RFC3986}} comparison of the
  resource-containment test ({{subset}}), which applies to that
  comparison alone: the default `resource` equality test of {{subset}}
  remains an exact match, and anchor computation is always byte-exact
  over the recorded values.

Test vectors for both anchors are provided in {{test-vectors}}.

# Mission Record {#mission-record}

A Mission is the durable record created at the approval event. Its
members are immutable after creation except for its `state`, and it is
identified by a Mission Identifier ({{mission-id}}). Operational
issuance bookkeeping, such as the derivation count gated under
{{lifecycle}}, is AS-side state about the Mission, not a member of
the immutable record.

Naming follows one rule across every surface that carries Mission
facts. Record members do not repeat the `mission` prefix: the record
is the Mission, and prefixed names belong to surfaces that reference
a Mission from outside it, such as the `mission_intent` request
parameter and the `mission_id` response parameter. Member names are
spelled out (`issuer`, `expires_at`, `created_at`) and spelled
identically everywhere; the compact JWT names (`iss`, `exp`, `iat`)
describe a signed artifact's own envelope, or identify a party in an
`{iss, sub}` object, never the Mission.

Like the `mission` claim ({{mission-claim}}), the record is open
({{extensibility}}): a companion profile of this document MAY record
additional members set at creation using short names coordinated with
it (for example, a lineage member linking the Mission to a
predecessor or parent); any other extension MUST use
collision-resistant names. The members below are the ones this
profile defines:

`id`:
: REQUIRED. A string. The canonical Mission Identifier
  ({{mission-id}}).

`issuer`:
: REQUIRED. A string. The issuer URL of the Mission Issuer
  that approved the Mission. Equals the `iss` of tokens that AS
  derives; for cross-domain tokens it remains the originating AS even
  though the issuing `iss` differs
  ({{I-D.draft-mcguinness-oauth-mission-cross-domain}}).

`state`:
: REQUIRED. A string. The current lifecycle state: `active`, `revoked`,
  or `expired` in this profile, or an additional state defined by a
  companion profile, subject to the forward-compatibility rule of
  {{lifecycle}}.

`intent`:
: REQUIRED. An object. The approved Mission Intent.

`authority_set`:
: REQUIRED. An array. The consented Authority Set.

`authority_hash`:
: REQUIRED. A string. The consent commitment over
  the Authority Set ({{integrity-anchors}}).

`intent_hash`:
: REQUIRED. A string. The integrity commitment over
  the approved Mission Intent ({{integrity-anchors}}), making the
  recorded task tamper-evident.

`subject`:
: REQUIRED. An object. The Subject, an object with `iss` and
  `sub`.

`approver`:
: REQUIRED. An object. The Approver,
  an object with `iss` and `sub`. MAY equal `subject`.

`client_id`:
: REQUIRED. A string. The Agent (OAuth client) that
  submitted the Mission Intent.

`policy_version`:
: REQUIRED. A string. The derivation policy version
  in effect at the approval event.

`approval_event_id`:
: REQUIRED. A string. A unique identifier of the
  approval event, used as the approval idempotency key: a retried or
  duplicate delivery of the same approval decision (a replayed
  callback, a double-submitted consent form) MUST NOT create a second
  Mission, and the AS deduplicates on this identifier. It is otherwise
  an opaque audit identifier with no wire semantics.

`created_at`:
: REQUIRED. A string. RFC 3339 timestamp of creation.

`expires_at`:
: REQUIRED. A string. Mirrors
  `intent.expires_at`.

The **audit horizon** is the deployment-declared retention window for
the Mission record and its evidence: at least the Mission's lifetime
plus a declared post-expiry period. After the Mission reaches a
terminal state (`revoked` or `expired`), the record MUST be retained
for the audit horizon.

## Mission Identifier Format {#mission-id}

A Mission Identifier is an opaque URL-safe ASCII string of
`[A-Za-z0-9_-]` characters, with at least 128 bits of entropy, carrying no
semantic content. It MUST NOT be reused. The record and the `mission`
claim carry it as `id`; a surface that references a Mission from
outside carries it as `mission_id`, as in the token-response parameter
({{grant-binding}}).

## Worked Example

~~~ json
{
  "id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
  "issuer": "https://as.example.com",
  "state": "active",
  "intent": { "goal": "Reconcile Q3 invoices ...",
    "resources": ["https://erp.example.com"],
    "expires_at": "2026-12-31T23:59:59Z" },
  "authority_set": [
    { "type": "mission_resource_access",
      "resource": "https://erp.example.com",
      "actions": ["invoices.read"],
      "constraints": {
        "resource_issued_after": "2026-07-01T00:00:00Z",
        "resource_issued_before": "2026-09-30T23:59:59Z"
      },
      "delegation": {
        "max_depth": 2,
        "allowed_delegates": [{ "sub_profile": "ai_agent" }]
      } },
    { "type": "mission_resource_access",
      "resource": "https://erp.example.com",
      "actions": ["journal-entries.write"],
      "constraints": {
        "max_amount": { "amount": "500.00", "currency": "USD" }
      } }
  ],
  "authority_hash":
    "sha-256:l3KvZ4mP5x0wQrR6tY2nD9bM7sX1cF8gH2vJ4kE5pNQ",
  "intent_hash":
    "sha-256:wQ7p4LHnX9Md0LqJ6sZJ8b8mZ3rN2xT5pV4lE6sQqYY",
  "subject": { "iss": "https://idp.example.com",
    "sub": "user_3p2q8mN1a0kV7tR" },
  "approver": { "iss": "https://idp.example.com",
    "sub": "user_3p2q8mN1a0kV7tR" },
  "client_id": "s6BhdRkqt3",
  "policy_version": "deploy-policy:v17",
  "approval_event_id": "ape_8K2nP4qV9rL3tY6sB1z",
  "created_at": "2026-10-15T14:32:11Z",
  "expires_at": "2026-12-31T23:59:59Z"
}
~~~

This recorded `intent` and `authority_set`, and the anchors above,
are this document's canonical worked example; the test vectors
({{test-vectors}}) compute over them. A companion that extends this
example MUST either reproduce the recorded objects byte-exactly or
state explicitly that its example diverges and its anchors differ;
an extended example with silently different anchors reads as the
same Mission and has repeatedly caused drift.

# Mission-Bound Access Tokens {#mission-bound-tokens}

Access tokens issued under a Mission are JWTs per {{RFC9068}}, which
fixes the required claims (including `jti`) and the `at+jwt` JOSE
header `typ` ({{RFC9068}} Sections 2.1 and 2.2); a Resource Server
MUST verify the `typ` per {{RFC9068}}. In addition to what that
profile requires, a derived token:

- carries the token's Mission-derived authority as
  `authorization_details` ({{RFC9396}}); this MAY be the full Authority
  Set or a narrowed subset ({{subset}});
- carries a `mission` claim ({{mission-claim}});
- sets `sub` to the Mission's Subject `sub` and `client_id` to the
  Mission's `client_id`;
- MUST set `aud` to identify the Resource Server(s) authorized to
  consume the carried `authorization_details`, and MUST NOT include an
  audience unrelated to that carried authority (see below);
- MAY carry an `act` claim when the agent has delegated execution
  ({{delegation}});
- MAY carry a `scope` claim, subject to the rule below;
- SHOULD be sender-constrained, via a `cnf` claim {{RFC7800}}:
  DPoP {{RFC9449}} (`cnf.jkt`) or mTLS {{RFC8705}} (`cnf.x5t#S256`).

Stated explicitly for estates whose access tokens are opaque
reference tokens: this document's token-carried enforcement assumes
the JWT above and does not profile opaque tokens. Such an estate has
two paths. A Resource Server that validates opaque tokens through
introspection receives the `mission` member and Mission state on the
introspection response ({{introspection}}); and an estate whose AS
cannot issue Mission-bound tokens at all deploys the standalone
Mission Issuer binding, which governs ordinary tokens at the
enforcement layer ({{I-D.draft-mcguinness-mission-authority-server}}).

The AS MUST NOT include `authorization_details` exceeding the
Mission's Authority Set. On any issuance that narrows authority (for
example, a single-audience token), each emitted entry MUST be a
subset of a Mission Authority Set entry under {{subset}}.

The `aud` SHOULD be derived from the resource indicators
({{RFC8707}}), Protected Resource metadata ({{RFC9728}}), or the
deployment's resource-to-RS mapping. It identifies the Resource
Server(s) and need not be byte-equal to the `resource` values of the
`authorization_details` entries: an `aud` typically names an RS, API,
or security domain, while entries name resources, accounts,
tools, or locations beneath it. Bounding `aud` to the consuming
Resource Server(s) prevents a confused-deputy or token-redirection
attack, in which a multi-resource Authority Set yields a token an
unrelated Resource Server would accept even though it was obtained to
act elsewhere.

A deployment SHOULD prefer per-RS (single-audience)
tokens, narrowed under {{subset}}: the client requests one at
the token endpoint with the {{RFC8707}} `resource` parameter (and MAY
further narrow with `scope`), and the AS narrows the Authority Set
under {{subset}} to the requested resource(s) and sets `aud` to the
corresponding Resource Server(s). This is the within-domain
counterpart of the audience-scoping the Mission Issuer applies when
projecting authority to a Resource AS
({{I-D.draft-mcguinness-oauth-mission-cross-domain}}).

Sender-constraining is a SHOULD for this primary token, aligned with
{{RFC9700}}. It is stronger (MUST) for delegated tokens, which face
higher replay exposure in the hands of a less-trusted delegate
({{delegation}}); the companion sets the same MUST for the credentials
that cross a trust domain
({{I-D.draft-mcguinness-oauth-mission-cross-domain}}). A deployment
SHOULD sender-constrain the primary token as well where its threat
model warrants.

The token-endpoint response conveys the granted authority to the
client. Because the client submits `mission_intent` rather than
`authorization_details`, and is not expected to parse the access
token, the AS MUST return the granted `authorization_details` in the
token-endpoint response, per {{RFC9396}} Section 7, reflecting
exactly the (possibly narrowed) set assigned to the issued token;
the same applies to refresh and Token Exchange responses. The
`mission_id` response parameter carries the Mission reference beside
it ({{grant-binding}}).

For example, the agent narrows the canonical ERP Mission (the worked
example of {{mission-record}}) to a read-only token, presenting the
Mission's refresh token with the {{RFC8707}} `resource` parameter and
narrowing further with `scope`:

~~~
POST /token HTTP/1.1
Host: as.example.com
Content-Type: application/x-www-form-urlencoded
DPoP: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2Iiwi...

grant_type=refresh_token
&refresh_token=rt_4mN8qV2xP7sL1tY9zB3k
&resource=https%3A%2F%2Ferp.example.com
&scope=invoices.read
~~~

The issuance is a derivation, gated on the Mission being `active`
({{lifecycle}}). The response echoes the narrowed grant and the
`mission_id` reference ({{grant-binding}}); the emitted entry is a
subset ({{subset}}) of the Mission's read entry, its `constraints`
carried intact:

~~~ json
{
  "access_token": "eyJhbGciOiJFUzI1NiIsInR5cCI6ImF0K2p3dCJ9...",
  "token_type": "DPoP",
  "expires_in": 300,
  "mission_id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
  "authorization_details": [
    { "type": "mission_resource_access",
      "resource": "https://erp.example.com",
      "actions": ["invoices.read"],
      "constraints": {
        "resource_issued_after": "2026-07-01T00:00:00Z",
        "resource_issued_before": "2026-09-30T23:59:59Z"
      },
      "delegation": {
        "max_depth": 2,
        "allowed_delegates": [{ "sub_profile": "ai_agent" }]
      } }
  ]
}
~~~

Mission-bound refresh tokens MUST be sender-constrained or use refresh
token rotation. This matters most for a public client, since
Mission-state gating bounds a stolen refresh token's usefulness over
time but not while the Mission is still `active`. This strengthens
the refresh-token guidance of {{RFC9700}} Section 2.2.2, whose MUST
applies to public clients, to all Mission-bound refresh tokens.

The authentication context of the approval event (`controls.acr`,
{{mission-intent}}) describes the Approver at approval time and is
recorded on the Mission, not on derived tokens; a derived token's
authority comes from the Mission, not from a fresh authentication, so
this document requires no `acr` or `auth_time` claim on it. An AS MAY
include `acr` and `auth_time` per {{RFC9068}} to convey the approval
context, but a consumer MUST NOT treat their absence as an
authentication downgrade.

`authorization_details` is the authoritative expression of a
Mission-bound token's authority. Any `scope` the token carries MUST be
derived from, and no broader than, the Authority Set. Specifically:

- every scope value MUST correspond to authority already present in
  `authorization_details`; and
- a scope value MUST NOT convey authority, or relaxation of a
  constraint, that the Authority Set does not grant.

Because `scope` is a coarse string list, it cannot carry the per-entry
`constraints`; it is a compatibility projection, never the
authoritative form of the Mission's authority. The AS MUST NOT issue a
Mission-bound token whose `scope` exceeds the Authority Set.

A credential the Mission Issuer derives MUST have an `exp` that does
not exceed the Mission's `expires_at`, so that no credential outlives
the approved Mission (not merely that none is issued after expiry). How
this bound extends transitively to tokens minted in another trust
domain is specified by the companion
({{I-D.draft-mcguinness-oauth-mission-cross-domain}}).

Short-lived access tokens remain this profile's issuance-only
recommendation: with no runtime layer, token lifetime is the
revocation-latency bound at unmodified Resource Servers. Where a
runtime layer covers the high-consequence classes with an active
freshness source, the point-of-use decision is the revocation
cutoff, and a deployment MAY size lifetimes by action class without
losing the kill switch ({{runtime-boundary}},
{{I-D.draft-mcguinness-mission-runtime}}).

## The Mission Claim {#mission-claim}

The `mission` claim is a JSON object:

`id`:
: REQUIRED. A string. The Mission Identifier ({{mission-id}}).

`issuer`:
: REQUIRED. A string. The Mission's `issuer` ({{mission-record}}). A
  credential's `iss` names the party that minted it; `mission.issuer`
  names the party that approved and serves the Mission, and the two
  deliberately differ for tokens minted in another trust domain
  ({{I-D.draft-mcguinness-oauth-mission-cross-domain}}).

`authority_hash`:
: REQUIRED. A string. The Mission's
  `authority_hash`, binding the token to the consented authority.

`expires_at`:
: OPTIONAL. A string. The Mission's `expires_at`
  ({{mission-record}}), in RFC 3339 {{RFC3339}} date-time form and
  named identically to the record member it mirrors. It is a bounding
  and audit commitment with no liveness: a validator can check that
  the token's `exp` does not exceed it, and its passing says nothing
  a state surface does not, since expiry is not revocation and only
  `active` permits reliance ({{lifecycle}}).

The `mission` claim is an open object ({{extensibility}}): additional
members MAY appear alongside the members above. This document defines no
registry of `mission` members. A companion profile of this document MAY
use short member names coordinated with it; any other extension member
MUST use a collision-resistant name (for example, a name in a namespace
the extension controls, per the Collision-Resistant Name guidance of
{{RFC7519}} Section 4.2) and is defined by the profile that introduces
it. A consumer MUST ignore members it does not understand and MUST NOT
use any additional member to grant or widen authority; the
members above remain authoritative.

`intent_hash` and `authority_hash` are independent commitments to
independent objects. That the approved task bounds the derived
authority is a governance assertion, made by derivation policy and
auditable through `policy_version` ({{authorization-derivation}}),
not a cryptographic relation between the anchors: neither anchor
proves anything about the other's object.

Example decoded token payload:

~~~ json
{
  "iss": "https://as.example.com",
  "sub": "user_3p2q8mN1a0kV7tR",
  "aud": "https://erp.example.com",
  "client_id": "s6BhdRkqt3",
  "iat": 1797840000,
  "exp": 1797840300,
  "jti": "at_9Kp2vN7sR1tY8mZ3qX5b",
  "authorization_details": [
    { "type": "mission_resource_access",
      "resource": "https://erp.example.com",
      "actions": ["invoices.read"],
      "constraints": {
        "resource_issued_after": "2026-07-01T00:00:00Z",
        "resource_issued_before": "2026-09-30T23:59:59Z"
      },
      "delegation": {
        "max_depth": 2,
        "allowed_delegates": [{ "sub_profile": "ai_agent" }]
      } },
    { "type": "mission_resource_access",
      "resource": "https://erp.example.com",
      "actions": ["journal-entries.write"],
      "constraints": {
        "max_amount": { "amount": "500.00", "currency": "USD" }
      } }
  ],
  "cnf": { "jkt": "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I" },
  "mission": {
    "id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
    "issuer": "https://as.example.com",
    "authority_hash":
      "sha-256:l3KvZ4mP5x0wQrR6tY2nD9bM7sX1cF8gH2vJ4kE5pNQ"
  }
}
~~~

## Resource Server Enforcement {#rs-enforcement}

A Resource Server enforces from the token alone; no call to the AS is
required. A Resource Server:

- MUST validate the JWT per {{RFC9068}} and verify any
  sender-constraint binding (`cnf`).
- MUST treat `authorization_details` as the authoritative expression
  of authority and enforce the entries whose `resource` it serves,
  permitting only the listed `actions` subject to `constraints`.
  Where more than one carried entry names a `resource` it serves, a
  request is permitted if at least one carried entry permits it:
  entries are alternative grants of authority, not conjunctive
  filters.
- MUST fail closed on any `constraints` key it does not understand, or
  understands but cannot enforce, in an entry whose `resource` it
  serves: it MUST refuse the request (for example, a `403` with
  `insufficient_scope` {{RFC6750}}, or the deployment's usual
  insufficient-authority error) rather than grant access while ignoring
  the key. A `constraints` member narrows authority, so treating an
  unenforceable key as absent would silently widen the grant; an RS
  MUST NOT reduce a constraint to disclosure-only.
- MUST NOT, when a token also carries `scope`, grant on the basis of a
  scope value any access broader than the corresponding
  `authorization_details` entry permits; in particular, `scope` MUST
  NOT be used to bypass a constraint carried only in
  `authorization_details`.
- MUST NOT treat `client_id` as the identity of the acting party on a
  delegated token. This profile keeps `client_id` equal to the
  Mission's approved agent on every derived token ({{delegation}}); the
  immediate actor is the outermost `act`. An RS that authorizes or logs
  the caller MUST process the `act` chain to identify the acting party,
  or it will attribute a delegate's action to the approved agent.
- This `act`-processing requirement binds a Mission-aware RS. Because a
  Mission-unaware {{RFC9068}} RS reads `client_id` as the immediate
  client and would misattribute, a deployment MUST NOT route
  delegated tokens to an RS that authorizes or logs the caller on
  `client_id` without processing `act`: the misattribution is silent
  and lands in audit records.
- MAY, for a Mission-governed resource, be configured to require the
  `mission` claim, and MUST then reject a token that lacks it with
  `invalid_token`. The downgrade this rejection prevents, and the
  issuance-side duty that pairs with it, are stated once in
  {{downgrade-by-omission}}. A protected resource
  MAY advertise this requirement through the
  `mission_bound_authorization_required` protected resource metadata
  member ({{protected-resource-metadata}}).
- MAY treat the `mission` claim as audit and correlation context.
- SHOULD, when serving Mission-bound requests, log the `mission`
  claim's `id` and the token `jti` with each served request, so its
  access logs join to Mission evidence.
- MAY recompute `authority_hash` ({{integrity-anchors}}). A Resource
  Server that performs it recomputes the anchor
  over the full Authority Set it independently holds, compares the
  result to `mission.authority_hash`, and MUST reject on mismatch. It
  additionally verifies that each carried `authorization_details` entry
  is a subset ({{subset}}) of that held set. A narrowed token matches by
  the subset test, never by hashing its carried entries: the anchor is
  computed only over the full Authority Set, so a Resource Server MUST
  NOT recompute it from a token's carried subset. At a Resource Server
  that holds only the narrowed token, `mission.authority_hash` is an
  audit correlator, not an enforcement input: the subset relationship
  between the carried entries and the approved set rests on trust in
  the AS's signature, not on a per-token cryptographic subset proof.
- MAY, where the AS offers it, introspect the token ({{introspection}})
  to observe the Mission's current state per request rather than
  relying on the token lifetime to bound revocation latency. An RS that
  introspects MUST still verify the token's sender-constraint (`cnf`)
  locally and MUST NOT treat an `active: true` result as proof the
  caller holds the bound key; the AS does not check possession at
  introspection ({{introspection}}).

Three denials above are byte-identical `403`s to a client, and
misrouting them turns a step-up into an authority-widening ceremony
or a fail-closed mismatch into a retry loop. A Mission-aware Resource
Server SHOULD therefore state which path it denies into, using the
`mission_denial` attribute this document defines for the
`WWW-Authenticate` response header, carried alongside `error` per
{{RFC6750}}, with one of three values: `insufficient_authority` (the
action is outside the token's carried authority, and more requires a
new approval or an expansion where that companion is deployed),
`step_up_required` (the authority exists, but the presented token or
its binding does not meet the resource's requirements: a step-up,
not a widening), or `constraint_unrecognized` (an applicable entry
carries a `constraints` key the RS cannot enforce, and the request
fails closed). A value the client does not recognize is treated as
`insufficient_authority`.

A Mission-unaware Resource Server that authorizes only from `scope`
still operates within the Mission at the coarse scope level, because
the AS derived and bounded that scope by the Authority Set
({{mission-bound-tokens}}); but it does not enforce the per-entry
`constraints`, which `scope` cannot carry. A deployment that relies on
those constraints MUST route the protected operation through a
Resource Server that enforces `authorization_details` (or the runtime
layer that evaluates them).

# Mission Lifecycle and Gating {#lifecycle}

A Mission is in one of three states:

- `active`: tokens MAY be derived. The only state from which issuance
  proceeds.
- `revoked`: terminated by the Subject, Approver, or
  policy. Terminal.
- `expired`: `expires_at` has passed. Terminal.

The transitions are:

| From | Event | To |
|---|---|---|
| (none) | approval event | `active` |
| `active` | revoke | `revoked` |
| `active` | `expires_at` reached | `expired` |

These three states are the mandatory core of the Mission lifecycle
state space. This profile owns that state space; an OPTIONAL companion
profile MAY define an additional state for a lifecycle it introduces
(for example, a paused or a superseded state), but only `active` ever
permits issuance. To keep the state space extensible without a registry,
a consumer MUST apply this forward-compatibility rule wherever a Mission
state is reported, including the Mission record and the introspection
`mission` member: only the exact value `active` permits
derivation or continued reliance, and every other value, including a
value the consumer does not recognize, MUST be treated as non-active and
non-deriving. A consumer MUST NOT fail open on an unrecognized state.
This makes a state added by a companion profile fail safe for a consumer
that predates it.

## Issuance Gating

The AS MUST refuse to derive a token, at the token endpoint, on
refresh, and on Token Exchange ({{RFC8693}}), unless the
referenced Mission is `active`. Issuance against a `revoked` or
`expired` Mission MUST fail with `invalid_grant`. Because derivation
is gated on Mission state, revoking or expiring a Mission stops all
further authority for the task, including refresh. The `active` check
MUST be evaluated atomically with issuance, as the derivation-count
check already is, so a revocation serialized before an issuance is
honored by that issuance.

When the Mission Intent sets `controls.max_derivations`, the AS MUST
maintain a per-Mission count of **derivations** and MUST refuse with
`invalid_grant` any derivation that would exceed the bound. A
derivation is one issuance operation the issuer AS performs for a
single request: the initial authorization-code exchange, a refresh, a
Token Exchange, or a cross-domain grant issuance
({{I-D.draft-mcguinness-oauth-mission-cross-domain}}). Each counts
as exactly one, regardless of how many artifacts it emits: a code
exchange that returns both an access token and a refresh token is one
derivation, and a refresh that rotates both is one. The exact rules:

- A derivation that fails, including one refused for exceeding the
  bound, MUST NOT be counted.
- The check and increment MUST be atomic with issuance, so concurrent
  derivations cannot collectively exceed the bound.
- The count covers only derivations the issuer AS performs. Tokens
  another domain mints locally under the Mission are not counted by
  the issuer, which cannot observe them; the cross-domain issuance
  that authorized them was counted once, and the local issuer bounds
  its own minting by its policy
  ({{I-D.draft-mcguinness-oauth-mission-cross-domain}}).

The AS maintains this count as internal bookkeeping; it is operational
state, not part of the immutable Mission record.

`invalid_grant` alone does not tell a client which gate refused. On a
refusal under this section the AS SHOULD include, alongside `error`,
the `mission_error` token-error-response member ({{iana}}) with one
of the values `mission_revoked`, `mission_expired`,
`mission_superseded` (where a companion defines supersession), or
`derivations_exhausted`. The member is diagnostic only: it grants
nothing, an unrecognized value is ignored, and it is returned only to
the authenticated client presenting the Mission's grant.

Derived tokens SHOULD be short-lived so that a transition to
`revoked` or `expired` takes effect promptly without per-request
revocation checks.

## Revocation {#revocation}

A Mission is revoked when the AS receives an authorized revocation
for it. A deployment MUST provide an authenticated means for the
Subject, the Approver, or an administrator to revoke a Mission by
`mission_id`, independent of possession of any token (so a Mission
can be stopped even when no refresh token is held).

This document does not define the wire shape of that operation.
Revocation is a management-plane action by a party in the AS's own
trust domain, not a cross-party protocol exchange, and the lifecycle
gate that makes it effective ({{lifecycle}}, {{introspection}})
already rides on existing endpoints, so no standardized endpoint is
required for interoperability. A standardized Mission management API,
with `suspend`/`resume`/`complete` operations, is specified separately
by Mission Status {{I-D.draft-mcguinness-oauth-mission-status}}; this
document does not require it.

A deployment MAY additionally treat {{RFC7009}} revocation of a
Mission's refresh token as revoking the Mission. A deployment MUST NOT
couple routine token revocation to Mission revocation unless it
documents that behavior. Already-issued access tokens remain valid
until they expire; a deployment requiring lower cutoff latency SHOULD
use short token lifetimes.

The stateless baseline needs no status surface: a token is a
self-contained authorization and verification is stateless. A
deployment MAY additionally offer token introspection
({{introspection}}) so a Resource Server can observe Mission state
per request and cut off a revoked Mission without waiting out the
token lifetime. A canonical Mission Status surface (keyed by
`mission_id`) and signed status responses are specified separately as
an OPTIONAL companion profile by Mission Status
{{I-D.draft-mcguinness-oauth-mission-status}}; this document does not
require them.

Token validity and Mission validity are distinct: a token can outlive
a transition of its Mission, by at most the token lifetime. A
deployment whose consumers rely on Mission state beyond a token's
lifetime SHOULD offer introspection ({{introspection}}) or the Mission
Status companion, so an authorized party can determine the Mission's
current state rather than inferring it from token validity.

# Mission State via Token Introspection {#introspection}

This section is OPTIONAL. The stateless baseline
({{mission-bound-tokens}}) needs no introspection; an AS that does not
offer it, and a Resource Server that does not use it, are unaffected.
It lets a Mission-state-aware Resource Server observe a Mission's
current state per request instead of waiting out a token's lifetime.
Because it can report Mission state for a token whose Mission is no
longer `active`, this section deviates from the SHOULD NOT of
{{RFC7662}} Sections 2.2 and 4 against including additional
information about an inactive token; that deviation is justified and
governed by the caller-authorization and minimization
rules below ({{caller-authorization-and-minimization}}).

An AS MAY support OAuth 2.0 Token Introspection {{RFC7662}} for
Mission-bound access tokens. When it does, the response for such a
token carries, in addition to the standard members, a `mission`
member: `id`, `issuer`, and `authority_hash` (as in the `mission`
claim, {{mission-claim}}) plus, when the responding AS is the Mission
`issuer`, the current lifecycle `state` (string) and, when
`controls.max_derivations` is in force, `derivations_remaining` (a
number): the derivations left under the cap at the time of the
response, counting committed issuances ({{lifecycle}}), so a harness
can plan refreshes against the budget. Like `state`, only the issuer
reports `derivations_remaining`
({{only-issuer-reports-state}}). The core states are `active`, `revoked`,
and `expired` ({{lifecycle}}); a deployment that runs a companion
profile defining an additional state reports that state here, and a
consumer applies the forward-compatibility rule of {{lifecycle}} (only
`active` permits reliance; any other value, recognized or not, is
non-active). Only the issuer reports `state`
({{only-issuer-reports-state}}).

The AS includes the `mission` member only when it has authenticated the
caller, the caller is authorized for the token
({{caller-authorization-and-minimization}}), and the presented token
resolves to a Mission. For a malformed, unknown, individually expired, or
otherwise unresolvable token, the AS responds per {{RFC7662}}
(`active: false`) with no `mission` member; it does not reveal Mission
state for a token it cannot bind to a Mission. The case below
(`active: false` with `mission.state`) applies only to a token that is
itself valid but whose Mission is no longer `active`.

The composite-active rule ({{composite-active}}) and the `mission`
member apply equally when a Mission-bound refresh token is introspected.

Freshness is per use: this document defines no caching semantics for
the `mission` member, so a Resource Server that relies on
introspection for Mission state treats each response as an
observation for that decision, not as a cacheable state assertion. A
deployment that needs bounded-staleness caching adopts the Mission
Status companion, whose signed responses carry explicit freshness
({{I-D.draft-mcguinness-oauth-mission-status}}).

## Caller Authorization and Minimization {#caller-authorization-and-minimization}

The introspection endpoint is protected per {{RFC7662}}. The AS:

- MUST authenticate the calling party.
- MUST return Mission data only to a caller authorized to receive
  it, in particular a Resource Server that is an audience of the
  token.
- MUST audience-filter the response, returning the
  `authorization_details` entries and Mission data relevant to the
  caller's audience and not disclosing entries addressed to other
  audiences ({{mission-bound-tokens}}).

Because this profile returns the `mission` member and `mission.state`
even when `active` is `false` (diverging from the {{RFC7662}}
SHOULD NOT against disclosing detail for inactive tokens), the AS
MUST apply this same
authorization and minimization to that data and MUST NOT reveal
Mission detail to an unauthorized introspection caller.

## Composite Active State {#composite-active}

The introspection `active` member reflects the composite
authorization, not the token in isolation. The AS MUST return
`active: true` only when the access token is itself valid (valid
signature, unexpired, and not individually revoked) AND the Mission
is `active`. The AS does not verify the token's sender-constraint
(`cnf`) at introspection: proof of possession is checked by the
Resource Server when the token is presented, not by the AS over an
introspection call, so `active: true` is not by itself evidence the
caller holds the bound key.

When the token is otherwise valid but the Mission is `revoked` or
`expired`, the AS MUST return `active: false` and include
`mission.state` giving the reason, so a Resource Server can
distinguish a dead Mission from a bad token. (This deviates from the
{{RFC7662}} SHOULD NOT against including members when `active` is
`false`.) A
Mission transition does not by itself revoke the token as an
individual credential; introspection reports the composite
authorization as inactive.

## Only the Issuer Reports Mission State {#only-issuer-reports-state}

An AS MUST NOT include `mission.state` in an introspection response
unless it holds the Mission, that is, unless it is the Mission
`issuer`. Introspection at a non-issuer Resource AS, which returns the
claim-shape members only and never `state`, is specified by the
companion ({{I-D.draft-mcguinness-oauth-mission-cross-domain}}).

This is token introspection: it answers "is this token's
authorization still good," keyed by the token presented. The
canonical Mission Status surface (keyed by `mission_id`) remains out of scope
({{revocation}}).

## Examples

While the Mission is `active`, the response is the standard
{{RFC7662}} body plus the `mission` member. The canonical ERP token
({{mission-claim}}), introspected at the issuer AS:

~~~ json
{
  "active": true,
  "iss": "https://as.example.com",
  "sub": "user_3p2q8mN1a0kV7tR",
  "client_id": "s6BhdRkqt3",
  "aud": "https://erp.example.com",
  "exp": 1797840300,
  "authorization_details": [
    { "type": "mission_resource_access",
      "resource": "https://erp.example.com",
      "actions": ["invoices.read"],
      "constraints": {
        "resource_issued_after": "2026-07-01T00:00:00Z",
        "resource_issued_before": "2026-09-30T23:59:59Z"
      },
      "delegation": {
        "max_depth": 2,
        "allowed_delegates": [{ "sub_profile": "ai_agent" }]
      } },
    { "type": "mission_resource_access",
      "resource": "https://erp.example.com",
      "actions": ["journal-entries.write"],
      "constraints": {
        "max_amount": { "amount": "500.00", "currency": "USD" }
      } }
  ],
  "mission": {
    "id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
    "issuer": "https://as.example.com",
    "authority_hash":
      "sha-256:l3KvZ4mP5x0wQrR6tY2nD9bM7sX1cF8gH2vJ4kE5pNQ",
    "state": "active"
  }
}
~~~

The same token after the Mission is revoked, reported per the
composite-active rule ({{composite-active}}):

~~~ json
{
  "active": false,
  "mission": {
    "id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
    "issuer": "https://as.example.com",
    "authority_hash":
      "sha-256:l3KvZ4mP5x0wQrR6tY2nD9bM7sX1cF8gH2vJ4kE5pNQ",
    "state": "revoked"
  }
}
~~~

# Delegation Within a Mission {#delegation}

This section is OPTIONAL. A deployment whose agents never delegate, and
a Resource Server that sees no delegated tokens, are unaffected.

An agent may delegate execution to downstream actors (a sub-agent,
service, or tool that is itself an OAuth client) within a Mission.
Delegation is represented with the OAuth Actor Profile
{{I-D.draft-mcguinness-oauth-actor-profile}}, which profiles the
RFC 8693 {{RFC8693}} `act` (actor) claim.

A delegate obtains a delegated token by Token Exchange
({{RFC8693}}). The AS issues the delegated token subject to all of
the following:

- **The exchange is explicit.** The delegating Mission-bound access
  token is the `subject_token`, with `subject_token_type` of
  `urn:ietf:params:oauth:token-type:access_token`. The delegate is
  identified by an `actor_token` (with its `actor_token_type`; for
  example, an attested client-instance assertion presented as
  `urn:ietf:params:oauth:token-type:client-instance-jwt`
  ({{I-D.draft-mcguinness-oauth-client-instance-assertion}})) or by
  its own client authentication, and the AS asserts the actor itself
  ({{delegation-constraints}}); a `requested_token_type` of
  `urn:ietf:params:oauth:token-type:access_token` is used. The
  response carries the matching `issued_token_type` and a `token_type`
  for the issued access token, per {{RFC8693}} Section 2.2.1.
- **Subject is stable.** `sub` remains the Mission's Subject. The
  delegate is an actor, not the subject.
- **The approved agent stays `client_id`.** This profile keeps
  `client_id` equal to the Mission's approved agent on every derived
  token ({{mission-bound-tokens}}), so the approved party is
  verifiable everywhere. Downstream delegates are carried in the
  `act` chain, not in `client_id`. For delegated tokens this
  deliberately overrides the `client_id` definition of {{RFC8693}}
  Section 4.3, which {{RFC9068}} Section 2.2 incorporates (the client
  that requested the token); here the immediate delegate is the
  outermost `act`.
- **The `act` chain identifies the delegates.** The delegated token
  carries an `act` claim per the Actor Profile
  {{I-D.draft-mcguinness-oauth-actor-profile}}: the outermost `act` is
  the immediate delegate, with prior delegates nested inward, back
  toward the approved agent. Each actor object
  carries the members that profile defines (`sub`, `iss`, and the
  RECOMMENDED `sub_profile` actor-type classification, e.g.
  `ai_agent`). This document does not re-specify the `act` structure.
- **Authority only narrows.** The delegated token's
  `authorization_details` MUST be a subset ({{subset}}) of the
  delegating token's authority, hence of the Mission Authority Set.
  Delegation MUST NOT add authority.
- **The Mission binding rides unchanged.** The delegated token
  carries the same `mission` claim ({{mission-claim}}), its
  `id`, `issuer`, and `authority_hash`, so every actor in
  the chain operates under the one consented authority.
- **Each delegate is bound to its own key.** The delegated token MUST
  be sender-constrained ({{mission-bound-tokens}}) to the **delegate's
  own** key: its `cnf` is the delegate's DPoP or mTLS key, not the
  delegating party's. The delegate proves possession of that key in
  the Token Exchange. A compromised delegate key therefore cannot be
  replayed as the agent or as another actor in the chain, and each
  actor's credential is independently revocable by key.
- **Each delegation is gated.** Issuing a delegated token is a
  derivation event; the AS MUST refuse it unless the Mission is
  `active` ({{lifecycle}}).

Where a deployment authenticates client instances
({{I-D.draft-mcguinness-oauth-client-instance-assertion}}; for AI
agents, its agent profile
{{I-D.draft-mcguinness-oauth-ai-agent-instance}}), the delegate
identified by the outermost `act` is the concrete instance: `act.sub`
is the instance identifier and `act.cnf` is the instance-specific
key. This profile's requirement that a delegated token be
sender-constrained to the delegate's own key then lands on an
instance-possessed key by construction. An `allowed_delegates`
matcher can select instance-grade actors
({{delegation-constraints}}), for example
`{ "sub_profile": "client_instance" }`. The `sub_profile` values
used here (`ai_agent`, `client_instance`) are drawn from the
entity-profiles vocabulary those instance profiles use; the Actor
Profile {{I-D.draft-mcguinness-oauth-actor-profile}} remains the
structural reference for the actor object.

## Design Alternative: Rebinding client_id to the Delegate {#client-id-rebinding}

A rejected alternative rebinds `client_id` to the immediate delegate
on each hop, the plain {{RFC9068}} reading in which `client_id` names
the immediate client. Rebinding loses the stable approved-agent
binding that every consumer of a derived token can verify: each
downstream token presents as a new client rather than an actor
executing within the approved Mission, and joining who was approved to
who executed requires reconstructing the hop history from issuance
records rather than reading both from the token. Rebinding is also
safe only where every Resource Server processes `act` anyway, since
the delegation history lives nowhere else; that is exactly the
discipline this profile's chosen design requires, so rebinding buys no
relaxation. The operational rule of {{rs-enforcement}} therefore holds
regardless of the binding choice: a Resource Server that authorizes or
logs the caller MUST process the `act` chain, and a deployment MUST
NOT route delegated tokens to a Resource Server that authorizes or
logs on `client_id` without processing `act` ({{rs-enforcement}}).

## Self-Exchange Down-Scoping {#self-exchange}

An agent MAY present its own Mission-bound access token as the
`subject_token` of a Token Exchange ({{RFC8693}}) with no actor, to
obtain a narrowed token (for example, a single-audience one). The AS
MUST verify that the client authenticated at a no-actor exchange is
the Mission's `client_id`; any other party's no-actor exchange is
refused, since a delegate narrows only through a delegated exchange
that names it in the `act` chain. The
result MUST be a subset ({{subset}}) of the presented token's
authority, carries the same `mission` claim ({{mission-claim}}), and
adds no `act` chain. It is a derivation and is gated on the Mission
being `active` ({{lifecycle}}). Because it names no actor, it does not
delegate: it re-scopes the agent's own authority downward.

## Delegation Constraints {#delegation-constraints}

What may be delegated, how far, and to whom is governed per
Authority Set entry by the entry's optional `delegation` member
({{authorization-derivation}}). Because the policy lives in the
entry, it is committed by `authority_hash` with the rest of the
Authority Set and travels with the entries wherever they are carried,
including across a cross-domain projection
({{I-D.draft-mcguinness-oauth-mission-cross-domain}}), needing no
separate mechanism.

**Delegation depth.** The delegation depth of a token is the number
of actors in its `act` chain (the nesting depth of the `act` claim),
counted from the approved agent: the agent's own non-delegated token
is depth 0, the first delegate is depth 1, and each further delegate
adds 1. The depth checked against `max_depth` is that of the token
being issued, computed after appending the new outermost actor, not
the depth of the delegating token. A credential projected across a
trust domain carries no `act` chain and enters the target domain at
depth 0 ({{I-D.draft-mcguinness-oauth-mission-cross-domain}}).

**Per-entry enforcement.** When the AS issues a token to a delegate
(the actor that becomes the outermost `act`) at delegation depth
`d`, it includes a Mission Authority Set entry in the delegated
token's `authorization_details` only if all of the following hold:

1. the entry carries a `delegation` member (otherwise it is
   non-delegable, which is the default);
2. `d` is less than or equal to the entry's `delegation.max_depth`;
   and
3. the delegate is permitted by `delegation.allowed_delegates` or,
   when that member is absent, by the AS's delegation-authorization
   policy, which the AS MUST apply at every exchange: an absent
   matcher list is a decision deferred to policy, never a blanket
   grant of eligibility.

An entry failing any of these narrows out of the delegated token,
consistent with the subset rule ({{subset}}). The `delegation`
member is policy, not authority, and is not part of the subset
comparison; surviving entries are carried with their `delegation`
member intact so the next hop is evaluated the same way.

**Matching `allowed_delegates`.** Each entry is a matcher object
modeled on the RFC 8693 `may_act` actor object ({{RFC8693}} Section
4.4): where `may_act` names a single party eligible to act on a token,
`allowed_delegates` is a per-Authority-Set-entry *list* of such
matchers, generalized to actor-type classes. A `{ "sub": ... }`
matcher permits a specific delegate by client identifier; a
`{ "sub_profile": ... }` matcher permits any actor of that type (for
example, `ai_agent`). An actor's `sub_profile` MAY carry multiple
space-separated values; a `{ "sub_profile": ... }` matcher is
satisfied when its value is among the actor's values. A deployment
can thus permit a specific client,
a class of actors, or both, and a delegate is permitted if it matches
any entry. The AS MUST authenticate the delegate at the Token Exchange
and assert the actor's `sub` and `sub_profile` itself. A self-asserted
`sub_profile` MUST NOT satisfy a matcher; otherwise a client could
claim any actor type to bypass the constraint.

A `{ "sub": ... }` matcher is a client identifier in the issuing AS's
namespace and is not portable across a trust domain; how a Resource AS
evaluates conveyed matchers, failing closed and narrowing out any
`sub` matcher it cannot resolve, is specified by the companion
({{I-D.draft-mcguinness-oauth-mission-cross-domain}}).

**Empty result.** If narrowing leaves no entries for the delegate,
the AS MUST refuse with `invalid_target` ({{RFC8693}} Section 2.2.2)
rather than issue a token with empty authority: the requested
delegation has no authority to carry, while the subject grant itself
remains valid for other exchanges.

**The Resource Server enforces none of this.** Delegation
constraints are applied by the AS at issuance; a Resource Server sees
only the already-narrowed `authorization_details` and enforces those
as usual ({{mission-bound-tokens}}).

## Worked Example: Delegated Token

Suppose the Mission's Authority Set has two entries on the ERP:
`invoices.read`, delegable to `ai_agent` actors through depth 2; and
`journal-entries.write`, which carries no `delegation` member and is
therefore non-delegable. The approved agent `s6BhdRkqt3` delegates to
sub-agent `tool-runner-7`, an `ai_agent`, at depth 1. The read entry
is permitted (depth 1 <= 2, `ai_agent` allowed) and the write entry
narrows out. The decoded delegated access token:

~~~ json
{
  "iss": "https://as.example.com",
  "sub": "user_3p2q8mN1a0kV7tR",
  "aud": "https://erp.example.com",
  "client_id": "s6BhdRkqt3",
  "iat": 1797840600,
  "exp": 1797840900,
  "jti": "at_3qX5bN7sR1tY8mZ9Kp2v",
  "authorization_details": [
    { "type": "mission_resource_access",
      "resource": "https://erp.example.com",
      "actions": ["invoices.read"],
      "constraints": {
        "resource_issued_after": "2026-07-01T00:00:00Z",
        "resource_issued_before": "2026-09-30T23:59:59Z"
      },
      "delegation": {
        "max_depth": 2,
        "allowed_delegates": [{ "sub_profile": "ai_agent" }]
      } }
  ],
  "act": {
    "sub": "tool-runner-7",
    "iss": "https://as.example.com",
    "sub_profile": "ai_agent"
  },
  "cnf": { "jkt": "qVx7y2N0p4Lq9Md3sZJ8b8mZ3rN2xT5pV4lE6sQqYY" },
  "mission": {
    "id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
    "issuer": "https://as.example.com",
    "authority_hash":
      "sha-256:l3KvZ4mP5x0wQrR6tY2nD9bM7sX1cF8gH2vJ4kE5pNQ"
  }
}
~~~

`sub` is still the user and `client_id` is still the approved agent;
`tool-runner-7` appears only as the actor. The `cnf` is
`tool-runner-7`'s own key, not the agent's, so this token cannot be
replayed as the agent. The non-delegable write entry was dropped; the
read entry survives, carrying its `delegation` member so a further hop
can be evaluated: a depth-3 delegate, or a non-`ai_agent` one, would
narrow it out too. The `mission` claim is unchanged.

# Extensibility {#extensibility}

This profile is a base layer that other agent-authorization work is
expected to extend. Extensions build alongside the stable interface
below; they MUST NOT redefine it. An extension MAY rely on these
remaining stable across revisions of this profile:

- the `mission` claim members `id`, `issuer`, and `authority_hash`
  ({{mission-claim}});
- the `mission_resource_access` authorization details shape
  ({{authorization-derivation}}); and
- the `act` delegation chain ({{delegation}}).

The profile offers four extension points, each a declared seam rather
than new machinery:

- **Authority types.** The Authority Set is open to other AS-supported
  `authorization_details` types ({{other-types}}); the Mission
  apparatus (commitment, gating, delegation) is type-agnostic toward
  them, subject to the delegation and projection limits in
  {{other-types}}.
- **Integrity anchors.** Additional committed objects use the same
  domain-separated, issuer-bound envelope with a new `typ`
  ({{integrity-anchors}}). A consent-disclosure commitment, an
  instruction-text attestation, or a delegation receipt can be
  committed this way without changing this profile. A profile that
  commits an evidence or disclosure object MUST commit it with this
  envelope and a collision-resistant `typ`, not by hashing the bare
  object, so the domain separation and issuer binding hold uniformly. A
  `mission` descriptor embedded in such an object uses the `mission`
  claim shape ({{mission-claim}}), optionally extended with
  collision-resistantly named members (for example, an `intent_hash`
  for audit), and is never authority-bearing on its own.
- **The `mission` claim.** It is an open object ({{mission-claim}}):
  additional, collision-resistantly named members ride the mission
  binding (for example, a runtime decision reference, a delegation
  receipt, or an attestation reference), and consumers ignore unknown
  members and never derive authority from them.
- **Lifecycle state.** The lifecycle state space ({{lifecycle}}) is open
  to additional states defined by companion profiles for lifecycles they
  introduce. The forward-compatibility rule in {{lifecycle}} keeps this
  safe without a registry: only `active` permits issuance, and a consumer
  treats every other state, recognized or not, as non-active.
- **Approval-event sequencing.** The approval-event steps, their
  order, and the atomicity of record creation with the approval
  decision are the model's ({{approval-event}}); the coupling of that
  decision to authorization-code issuance is this flow's. A companion
  profile MAY relocate the approval event relative to code issuance
  (for example, deferring the decision beyond the authorization
  response), provided the steps and their atomicity hold unchanged
  and no Mission reference exists before the record is `active`; the
  Mission Deferred Approval companion is such a profile
  ({{I-D.draft-mcguinness-oauth-mission-approval}}).

This document defines no extension registry, capability-negotiation
mechanism, or profile-version field; an extension declares its own
identifiers and, where it needs discovery, its own metadata. The
extensibility of the `typ` value space, the `mission` claim, and the
lifecycle state space rests on collision-resistant naming and the
fail-safe rules above rather than on central registration.

# Authorization Server Metadata {#discovery}

An AS MAY advertise support for this specification in its
authorization server metadata {{RFC8414}}:

`mission_bound_authorization_supported`:
: OPTIONAL boolean. When `true`, the AS supports the core Mission
  Issuer surfaces of this profile ({{conformance}}): the
  `mission_intent` authorization request parameter through PAR
  ({{mission-intent}}), derivation of `mission_resource_access`
  authorization details ({{authorization-derivation}}), Mission-bound
  access tokens ({{mission-bound-tokens}}), and the `mission` JWT claim
  ({{mission-claim}}). It asserts Mission Issuer support only; it makes
  no claim about any Resource Server, nor about the OPTIONAL
  capabilities (delegation, introspection, cross-domain projection),
  which are discovered out of band or by attempt ({{conformance}}).

An AS that advertises this profile SHOULD also include
`mission_resource_access` in its `authorization_details_types_supported`
metadata ({{RFC9396}}), so that RFC 9396-aware clients
discover the authorization details type through the standard mechanism.
A client MAY use the RFC 9396 client metadata `authorization_details_types`
at registration to declare the types it understands.

Discovery is OPTIONAL: a deployment MAY arrange Mission-bound
authorization out of band, and this member only lets an AS advertise
it. When the member is absent or `false`, a client MUST NOT infer
that the AS supports this specification. A client holding a Mission
Intent MUST NOT silently downgrade the task to an ungoverned
authorization request against an AS whose support is not advertised
and not otherwise established: submitting the same authority as plain
`scope` or `authorization_details` obtains tokens no Mission governs,
the client-side face of downgrade by omission
({{downgrade-by-omission}}). The client surfaces the inability
instead; where the estate's AS cannot change, the standalone Mission
Issuer binding is the governed alternative
({{I-D.draft-mcguinness-mission-authority-server}}).

An AS that advertises `mission_bound_authorization_supported: true`
MUST also publish `pushed_authorization_request_endpoint`
({{RFC9126}}), since a Mission Intent is accepted only through PAR
({{submission-via-par}}).

This member and the `mission_bound_authorization_required` member of
{{protected-resource-metadata}} are unauthenticated discovery data:
their integrity rests on the metadata retrieval protections of
{{RFC8414}} and {{RFC9728}}, whose security considerations apply.

# Protected Resource Metadata {#protected-resource-metadata}

A protected resource MAY advertise, in its protected resource metadata
{{RFC9728}}:

`mission_bound_authorization_required`:
: OPTIONAL boolean. When `true`, the protected resource accepts only
  Mission-bound tokens: a token that lacks the `mission` claim
  ({{mission-claim}}) is rejected ({{rs-enforcement}}). When absent or
  `false`, the resource makes no such requirement.

`mission_constraints_supported`:
: OPTIONAL. An array of strings: the `constraints` keys (Common
  Constraints and deployment-defined names) the resource understands
  and enforces ({{rs-enforcement}}). It gives the AS's duty to emit
  only keys the serving resource is known to understand
  ({{authorization-derivation}}) a discovery surface, and lets a
  client predict a fail-closed constraint mismatch before making the
  request. When absent, that knowledge is established out of band.

# Security Considerations

## Consent Binding {#consent-binding}

The security goal of this document is that a user's approval of a
task bounds every token derived for it. The `authority_hash` is the
mechanism: it commits the exact Authority Set the Approver
consented to, and every derived token carries it in the `mission`
claim. An AS MUST compute `authority_hash` over the same Authority
Set it rendered for consent, and MUST re-render and re-consent if that
set changes ({{approval-event}}). `authority_hash` commits the full
Authority Set, while a derived token may carry a narrowed subset, so a
Resource Server cannot in general recompute it from the token alone.
Recomputation is OPTIONAL, and its rules live with the Resource
Server's other duties ({{rs-enforcement}}): the anchor is defined
only over the full Authority Set, a narrowed token matches by the
subset test rather than by hashing its carried entries, and a
Resource Server that does not hold the full set treats
`authority_hash` as a whole-Mission audit and correlation anchor
({{I-D.draft-mcguinness-oauth-mission-cross-domain}}) while enforcing
the token's `authorization_details` directly
({{mission-bound-tokens}}).

`intent_hash` extends the same protection to the task itself: it
commits the approved Mission Intent, so an auditor can detect any
later alteration of the recorded task, independently of the authority
derived from it. The two anchors are domain-separated
({{integrity-anchors}}); neither is a substitute for the other.

The task and the authority are committed separately, rather than folded
into one hash over the whole Mission, because they are distinct objects
with distinct uses. `authority_hash` commits what a Resource Server
enforces and what a cross-domain projection carries, so it MUST be
verifiable from a token that conveys only the authority, without the
Intent. `intent_hash` commits the task as audit material, tamper-evident
even where the authority is projected without the Intent traveling with
it. One combined hash could not serve both a token that carries
authority alone and an auditor that holds the task alone.

Neither anchor proves the Approver understood the rendered task, nor
that the AS rendered it faithfully; they commit what the AS
recorded, and make post-hoc tampering of those records detectable.

This profile commits the task (`intent_hash`) and the authority
(`authority_hash`) the Approver consented to, but deliberately does
not commit the **rendered consent disclosure** itself: the locale,
disclosure-template version, and material notices the Approver was
shown are not bound by any anchor here. Because of this gap, a buggy or
malicious rendering layer could mislead the Approver, showing a
narrower or different task than the Authority Set actually committed,
without leaving any committed trace. A deployment whose Missions carry
high-risk authority SHOULD therefore record presentation-level audit
evidence: for example, a hash over the exact consent disclosure
rendered to the Approver, retained so the disclosure shown can be
reconstructed and audited after the fact. Binding this on the wire (a
`consent_rendering_hash` over a structured consent-disclosure object)
is specified as an OPTIONAL companion profile by Mission Consent
Evidence {{I-D.draft-mcguinness-oauth-mission-consent-evidence}}; an AS
that does not implement it MAY record equivalent evidence out of band.
As that profile makes explicit, such a commitment binds the structured
disclosure the AS records, not the pixels actually presented; it
narrows this gap for audit but does not close it.

## Mission Drift

Because issuance is gated on Mission state and bounded by the
Authority Set, an agent cannot escalate beyond the approved task by
acquiring additional tokens: every derived token is a subset of the
approved authority ({{subset}}), and no token can be derived once the
Mission is `revoked` or `expired`. Deployments SHOULD keep derived
token lifetimes short so state transitions take effect promptly.

## Downgrade by Omission {#downgrade-by-omission}

A token bearing equivalent `authorization_details` but no `mission`
claim is governed by no Mission state, revocation, or consent
commitment. A deployment that designates a resource Mission-governed
MUST NOT issue tokens for that resource outside a Mission, except under
documented policy exceptions. On the enforcement side, a Resource
Server for such a resource rejects a token lacking the `mission` claim
({{rs-enforcement}}), and MAY advertise the requirement through
`mission_bound_authorization_required`
({{protected-resource-metadata}}).

## Prompt Injection and the Exfiltration Leg {#prompt-injection}

An agent that reads attacker-influenceable content can be prompt-injected;
this profile assumes that and does not try to make the agent immune.
Injection is dangerous when one agent combines access to private data,
exposure to untrusted content, and the ability to communicate
externally; the robust defense is architectural, constraining one of
those, not making the model resistant.

This profile constrains the data-access leg: a Mission narrows authority
from everything the agent's standing credentials allow to the resources
the approved task needs, and per-task Missions ({{applicability}}) shrink
the blast radius further. It contributes one thing against the
untrusted-content leg: `purpose` and `success_criteria` are inert,
granting, widening, and gating no authority, and `goal` shapes
authority only through the pre-approval derivation whose result the
Approver reads and consents to ({{mission-intent}},
{{authorization-derivation}}); authority is fixed at the approval
event, so injected text cannot talk an approved Mission into
expanding itself.

This profile does not constrain the external-communication leg and
provides no information-flow control. It models authority over resources
and actions, not how an agent uses authority it holds: within an
approved Authority Set, an injected agent can read what the Mission
permits and write to a sink the Mission permits, and the flat subset and
constraint model cannot express "may read secrets, may write documents,
but not write secrets into documents." Constraining exfiltration by a
compromised agent is the runtime enforcement layer's role
({{runtime-boundary}}), and even there it is bounded, not closed
(see that profile's security considerations). Closing within-scope data
laundering needs a separate taint or information-flow layer this profile
does not define.

## Issuance Scope, Not Runtime Enforcement {#runtime-boundary}

This profile governs the issuance and derivation of authority: it
bounds what authority a Mission yields, binds it to the Approver's
consent, and gates derivation on Mission state. It does not evaluate
individual runtime actions. In particular, it does not:

- evaluate a request's parameters against the Mission at the point of
  use;
- produce runtime enforcement evidence for each consequential action;
- bind tool or function identities to the Mission; or
- re-evaluate at execution time to close the
  approval-to-execution (time-of-check to time-of-use) gap.

Mission governance is necessary but not sufficient. An active Mission
still bounds a set of authority an agent may exercise freely within a
token's lifetime, so an active Mission can become ambient authority
for individual consequential actions. Preventing that requires a
runtime enforcement layer that evaluates each consequential action
against the Mission and records evidence; such a layer composes with
this profile and is out of scope here. Which party enforces each
Mission-carried bound is summarized in the enforcement table
({{mission-intent}}). Short token lifetimes and
narrow authority bound, but do not eliminate, this exposure.

## Token Theft

Derived tokens are sender-constrained (DPoP {{RFC9449}} or mTLS
{{RFC8705}}) at the levels set in {{mission-bound-tokens}} and
{{delegation}}: SHOULD for the primary access token, MUST for
delegated tokens; the companion sets the same MUST for its
cross-domain credentials
({{I-D.draft-mcguinness-oauth-mission-cross-domain}}). A stolen token
is bounded by the Authority Set and the Mission lifetime regardless,
but sender-constraint prevents replay by a different party.

## Delegation and Chain Compromise

Delegation ({{delegation}}) widens the set of parties holding
Mission-derived authority. Because authority only narrows down the
chain, a compromised actor can act only within the authority it was
delegated, for the lifetime of the token it holds: the exposure of
any actor is bounded by its narrowed `authorization_details` times
its token lifetime. The per-entry delegation constraints
({{delegation-constraints}}) bound this exposure at approval time:
non-delegable entries never reach a delegate at all, `max_depth`
caps how far an entry can propagate, and `allowed_delegates`
restricts who may receive it. Note that `max_depth` bounds the
*length* of a delegation chain, not its *breadth*: fan-out to many
distinct depth-1 delegates is bounded only by `allowed_delegates`, so
a deployment that needs to limit breadth MUST constrain
`allowed_delegates` (and MAY use `max_derivations` to cap total
derivations). Because each delegated token is bound
to the delegate's own key ({{delegation}}), a compromised delegate is
confined to its own narrowed credential: it cannot replay as the
agent or another actor, and its credential can be revoked by key
without revoking the rest of the chain. Deployments SHOULD keep
delegated token lifetimes short and SHOULD make only the entries that
need delegation delegable.

A distinct path deserves its name: audience replay into the
exchange. A Mission-bound token obtained by or issued to one party,
presented as a `subject_token`, would launder into a fresh delegated
credential bound to the presenter. The gates above bound it: the
exchange is a derivation gated on Mission state, the AS applies
delegation-authorization policy at every exchange
({{delegation-constraints}}), the result is bound to the
authenticated delegate's own key and narrowed by the subset rule,
and a no-actor exchange is accepted only from the Mission's
`client_id` ({{self-exchange}}). Sender-constraining the primary
token ({{mission-bound-tokens}}) closes the remaining gap, since a
token stolen from an audience then fails presentation at the token
endpoint.

## Signing and Key Rotation {#key-rotation}

The `mission` claim and `authorization_details` are carried inside
the {{RFC9068}} JWT and are covered by the AS's token signature; their
integrity reduces to the AS's signing key. An AS MUST publish its
verification keys (for example, via {{RFC8414}} `jwks_uri`), and the
retired-key rule is: rotation retires a key from signing, never from
resolvability within its retention bound. For this document's
artifacts the floor is token lifetime: a verification key stays
resolvable while tokens signed under it remain valid. Verification
for audit outlives validity, so the key SHOULD remain resolvable at
least as long as the audit horizon ({{mission-record}}) of any
Mission whose tokens were signed under it. A companion
that anchors a longer-lived artifact to the same keys (a status
assertion, a Mandate, registered evidence) states its own retention
bound as an extension of this same rule, not a new one. Revocation for a
known or suspected compromise is distinct from routine retirement:
the issuer publishes the compromised key as revoked, or marks it
with a compromise time, rather than silently rotating it out.

Key custody carries the model: a compromised issuer signing key
voids every guarantee the signature carries. Issuer signing keys
SHOULD be held in non-exportable or HSM/KMS-grade custody with
dual-controlled generation, and SHOULD be segmented by artifact
class under distinct `kid` values within the one `jwks_uri`, so that
high-value, low-volume signing (long-lived evidence and portable
artifacts) can sit under stricter custody than high-volume online
token signing; verification is already `kid`-indexed, so the
segmentation needs no wire change. Recovery from a signing-key
compromise is deployment-owned and belongs in the deployment's
documented procedures.

## Compromised or Over-Broad Derivation

The AS is trusted to derive authority no broader than the Mission
Intent. Both derivation modes ({{authorization-derivation}}) are
mechanical, a proposal narrowed to policy or a configured mapping,
rather than free-form inference, and the recorded `policy_version`
names the policy a derivation ran under so the derivation can be
audited. General OAuth security guidance {{RFC9700}} applies.

## Authority Hash Is Not a Mission Identifier

`authority_hash` commits the approved Authority Set, not the Mission.
Two distinct Missions that approve byte-identical authority carry the
same `authority_hash`: a successor Mission that re-approves the same
Authority Set, or an unrelated Mission with the same derived authority,
differs in its `intent_hash`, `approver`, and `id` while sharing the
`authority_hash`. It is therefore not globally unique to a Mission and
MUST NOT be used as a Mission Identifier or as a replay or idempotency
key for a Mission. The canonical Mission Identifier names the
Mission; `authority_hash` names the authority the Mission
approved. A consumer that needs to bind to or correlate a specific
Mission uses the Mission Identifier, and `intent_hash` and `approver`
distinguish Missions that share an Authority Set.

# Privacy Considerations

A Mission Identifier is a correlation handle: a deployment limits
exposure by giving stable Mission Identifiers only to parties that
enforce, audit, or observe that Mission, preferring audience-scoped
projections of authority where possible, and minimizing status and
introspection disclosures to authorized callers. The subsections that follow and the
introspection minimization rules
({{caller-authorization-and-minimization}}) give the specific rules.

## Mission Identifier Correlation {#mission-identifier-correlation}

This document carries a single canonical Mission Identifier on every
derived token; the companion's cross-domain projection carries it
across trust domains unchanged
({{I-D.draft-mcguinness-oauth-mission-cross-domain}}). Any party that
observes credentials for the
same Mission, whether a Resource Server, a Resource AS, or an auditor
spanning audiences, can correlate that activity by the Mission
Identifier, and `mission.issuer` further identifies the issuing AS.
This is intentional:
a stable, correlatable Mission anchor is what lets a Resource Server, a
cross-domain Resource AS, and an auditor bind credentials and evidence
to one approved Mission, which the governance and audit properties of
this document and its companion profiles depend on. The cost is that
this profile does not provide
cross-audience unlinkability, and that is a deliberate non-goal for this
version ({{non-goals}}), not an unfinished feature. Audience-pairwise
(or request-pairwise) Mission references, in which the issuer projects a
distinct opaque identifier per audience and resolves them server-side,
are the fuller mechanism for unlinkability; because they work against
the stable anchor, they are future work rather than a v1 property. A
deployment that carries the canonical Mission Identifier on the wire
accepts this correlation as part of its privacy posture; the
operative control is limiting who receives the stable identifier,
per the guidance above, and a deployment that publishes its posture
records the property there rather than treating documentation as a
separate duty.

## Token Payload Disclosure

The carried `constraints` and a multi-resource Authority Set disclose
the shape of the task and its business bounds (for example, an amount
ceiling) to every holder and every audience of a derived token.
Per-RS single-audience tokens are the minimization measure: they carry
only the entries the consuming Resource Server needs, and this
document recommends them ({{mission-bound-tokens}}). The privacy
considerations of {{RFC9396}} apply to the carried
`authorization_details`.

## Intent Retention and Anchor Disclosure

The Mission record's Intent members (`goal`, `constraints`) are
personal-data sinks: they carry whatever task description the user
supplied. Record retention and erasure follow the deployment's
retention policy, with the audit profile's erasure record as the
transparency-side mechanism ({{I-D.draft-mcguinness-mission-audit}}).
The integrity anchors are unsalted commitments: a party holding a
candidate Intent can confirm it against `intent_hash`, so over
low-entropy or guessable content the anchor is a disclosure channel,
and deployments treat it as one when the Intent itself is sensitive.

## Mission Record and Evidence Access {#record-access}

The Mission record concentrates the task, its authority, and its
principals at the AS, and every evidence artifact joins on the
Mission Identifier, so the join is a correlation surface equal to
the identifier itself. Tokens carry references and authority, never
the record: nothing in this profile puts `goal`, `constraints`, or
other Intent content in a credential. Access to the record and to
Mission evidence is policy-governed and auditable: reading a
Mission's evidence is a privileged operation, not a byproduct of
holding a Mission reference, and retention is deployment policy
bounded below by the audit horizon ({{mission-record}}).

# IANA Considerations {#iana}

## OAuth Parameters Registration

This document registers the following in the "OAuth Parameters"
registry:

- Name: `mission_intent`
- Parameter Usage Location: authorization request
- Change Controller: IESG
- Specification Document(s): this document, {{mission-intent}}

- Name: `mission_id`
- Parameter Usage Location: token response
- Change Controller: IESG
- Specification Document(s): this document, {{grant-binding}}

- Name: `mission_derivation`
- Parameter Usage Location: token response
- Change Controller: IESG
- Specification Document(s): this document,
  {{authorization-derivation}}

- Name: `mission_error`
- Parameter Usage Location: token response
- Change Controller: IESG
- Specification Document(s): this document, {{lifecycle}}

PAR {{RFC9126}} carries authorization-request parameters without a
distinct usage location, so the pushed submission of `mission_intent`
needs no separate registration. The `mission_denial` attribute rides
the `WWW-Authenticate` scheme's extensible auth-param space
({{RFC6750}}, {{rs-enforcement}}), for which no IANA registry
exists; no action is required for it.

## The Mission Resource Access Authorization Details Type {#type-registration}

`mission_resource_access` is an `authorization_details` type per
{{RFC9396}} Section 2, defined by this document in
{{authorization-derivation}}. RFC 9396 does not establish an IANA
registry of authorization details types (type identifiers are
interpreted by the Authorization Server), so this document creates no
registry entry for it and requires no IANA action here. If a registry
of authorization details types is established in the future, this type
SHOULD be registered in it.

## JSON Web Token Claims Registration

This document registers the following in the "JSON Web Token Claims"
registry:

- Claim Name: `mission`
- Claim Description: Reference to the Mission a token was derived
  under, with the consent-commitment `authority_hash`. An open object;
  additional members may be present and are ignored if unknown.
- Change Controller: IESG
- Specification Document(s): this document, {{mission-claim}}

## OAuth Token Introspection Response Registration

This document registers the following in the "OAuth Token
Introspection Response" registry ({{RFC7662}}):

- Name: `mission`
- Description: The Mission a token was derived under. Same object shape
  as the `mission` JWT claim ({{mission-claim}}); a response from the
  Mission's issuer additionally carries a `state` member giving the
  current lifecycle state and, where a derivation cap is in force, a
  `derivations_remaining` member ({{introspection}}).
- Change Controller: IESG
- Specification Document(s): this document, {{introspection}}

## OAuth Authorization Server Metadata Registration

This document registers the following in the "OAuth Authorization
Server Metadata" registry ({{RFC8414}}):

- Metadata Name: `mission_bound_authorization_supported`
- Metadata Description: Boolean indicating that the Authorization
  Server supports the Mission Issuer core surfaces of this document.
- Change Controller: IESG
- Specification Document(s): this document, {{discovery}}

## OAuth Protected Resource Metadata Registration

This document registers the following in the "OAuth Protected Resource
Metadata" registry ({{RFC9728}}):

- Metadata Name: `mission_bound_authorization_required`
- Metadata Description: Boolean indicating that the protected resource
  accepts only Mission-bound tokens.
- Change Controller: IESG
- Specification Document(s): this document, {{protected-resource-metadata}}

- Metadata Name: `mission_constraints_supported`
- Metadata Description: JSON array of the `constraints` keys the
  protected resource understands and enforces.
- Change Controller: IESG
- Specification Document(s): this document, {{protected-resource-metadata}}

## Common Constraints {#iana-common-constraints}

This document creates no Common Constraints registry. The Common
Constraints it defines (`max_amount`, `resource_issued_after`,
`resource_issued_before`, `tenant`, `recipient_domain`,
`time_window`, `data_classification`, `allowed_tools`,
`requires_action_approval`) are specified in
{{common-constraints}}, and a further
Common Constraint is defined by specification: it fixes a name matching
`^[A-Za-z0-9_.:-]+$`, its JSON {{RFC8259}} value syntax, its subset
rule, and its intersection rule, in value-space terms
({{common-constraints}}). Names are kept collision-free by the same
convention the rest of this document uses: a specification-defined name
is coordinated within this document family, and any other name is
collision-resistant or remains deployment-defined
({{common-constraints}}).

Should the set of interoperable Common Constraints grow beyond what
specification coordination bears, a future revision can create a
"Mission Common Constraints" registry with a Specification Required
{{RFC8126}} policy, seeded with the entries then defined; this document
does not create it.

--- back

# End-to-End Example (Non-Normative) {#e2e-example}

This appendix walks one Mission from an agent through Mission
creation, token issuance, and Resource Server enforcement in a single
trust domain. It is illustrative and adds no normative requirements.
The OAuth pieces use the rules in this document; the identity setup is
by reference to {{I-D.draft-klrc-aiagent-auth}}. Identifiers and hash
values are illustrative and are not computed from the displayed JSON.

This walkthrough is the baseline issuance path: stateless enforcement
bounded only by token lifetime. No stage calls back to the AS for
Mission state; each party enforces from the credential it holds.
Stage 3 notes where the OPTIONAL runtime layer adds a point-of-use
check.

Scenario: agent `s6BhdRkqt3`, acting for `alice`
(`user_3p2q8mN1a0kV7tR`), reconciles Q3 invoices in the home ERP
under Mission `msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-`.

## Stage 0: Agent Identity (by Reference)

The agent is an OAuth client with a workload identity (for example a
WIMSE or SPIFFE identity), and `alice` has delegated to it through an
ordinary authorization-code flow, per
{{I-D.draft-klrc-aiagent-auth}}: `client_id` is the agent and the
token `sub` is `alice`. This document adds the Mission layer on top of
that identity; Stage 0 is otherwise unchanged from that specification.

## Stage 1: Mission Creation

The agent submits this Mission Intent through PAR ({{mission-intent}}):

~~~ json
{
  "goal": "Reconcile Q3 invoices and post adjustments under $500.",
  "resources": ["https://erp.example.com"],
  "constraints": [
    "Read only invoices issued in 2026-Q3.",
    "Post journal entries under $500."
  ],
  "success_criteria": [
    "All Q3 invoices reconciled.",
    "Each posted adjustment references a source invoice."
  ],
  "purpose": "urn:example:purpose:reconcile",
  "expires_at": "2026-12-31T23:59:59Z",
  "controls": {
    "acr": "urn:example:acr:mfa",
    "max_derivations": 200
  }
}
~~~

The AS (`as.example.com`) validates it, derives this Authority Set,
and renders it for `alice`'s consent:

~~~ json
[
  { "type": "mission_resource_access",
    "resource": "https://erp.example.com",
    "actions": ["invoices.read"],
    "constraints": {
      "resource_issued_after": "2026-07-01T00:00:00Z",
      "resource_issued_before": "2026-09-30T23:59:59Z"
    },
    "delegation": {
      "max_depth": 2,
      "allowed_delegates": [{ "sub_profile": "ai_agent" }]
    } },
  { "type": "mission_resource_access",
    "resource": "https://erp.example.com",
    "actions": ["journal-entries.write"],
    "constraints": {
      "max_amount": { "amount": "500.00", "currency": "USD" }
    } }
]
~~~

After approval, the AS records Mission
`msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-` in the `active` state with
`authority_hash`
`sha-256:l3KvZ4mP5x0wQrR6tY2nD9bM7sX1cF8gH2vJ4kE5pNQ` and
`intent_hash`
`sha-256:wQ7p4LHnX9Md0LqJ6sZJ8b8mZ3rN2xT5pV4lE6sQqYY`.

## Stage 2: Mission-Bound Token Issuance

The agent redeems the authorization code at the token endpoint. The
AS resolves the Mission from the grant ({{grant-binding}}), gates on
it being `active` ({{lifecycle}}), and issues a Mission-bound access
token for the ERP, echoing the granted `authorization_details` in the
token response ({{mission-bound-tokens}}). The decoded token:

~~~ json
{
  "iss": "https://as.example.com",
  "sub": "user_3p2q8mN1a0kV7tR",
  "aud": "https://erp.example.com",
  "client_id": "s6BhdRkqt3",
  "iat": 1797840000,
  "exp": 1797840300,
  "jti": "at_9Kp2vN7sR1tY8mZ3qX5b",
  "authorization_details": [
    { "type": "mission_resource_access",
      "resource": "https://erp.example.com",
      "actions": ["invoices.read"],
      "constraints": {
        "resource_issued_after": "2026-07-01T00:00:00Z",
        "resource_issued_before": "2026-09-30T23:59:59Z"
      },
      "delegation": {
        "max_depth": 2,
        "allowed_delegates": [{ "sub_profile": "ai_agent" }]
      } },
    { "type": "mission_resource_access",
      "resource": "https://erp.example.com",
      "actions": ["journal-entries.write"],
      "constraints": {
        "max_amount": { "amount": "500.00", "currency": "USD" }
      } }
  ],
  "cnf": { "jkt": "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I" },
  "mission": {
    "id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
    "issuer": "https://as.example.com",
    "authority_hash":
      "sha-256:l3KvZ4mP5x0wQrR6tY2nD9bM7sX1cF8gH2vJ4kE5pNQ"
  }
}
~~~

Everything enforcement needs is in the token: the audience, the
sender-constraint (`cnf`), the authority with its constraints, and the
`mission` claim carrying the `authority_hash` consent anchor. The
token is short-lived (300 s) and its `exp` is far below
`expires_at`; revoking the Mission stops further derivation, and
this token dies at its own expiry ({{revocation}}).

## Stage 3: The Resource Server Enforces

The agent calls the ERP Resource Server (`erp.example.com`) with that
token. The Resource Server validates the JWT and the `cnf` binding and
enforces the `authorization_details` whose `resource` it serves,
permitting `invoices.read` within the Q3 issuance window and
`journal-entries.write` up to the `max_amount` ceiling of 500.00 USD
({{rs-enforcement}}). It treats the `mission` claim as audit and
correlation context and makes no call to the AS.

This is stateless enforcement from the token alone.
`journal-entries.write` is a consequential write, so where the
deployment runs the runtime profile
({{I-D.draft-mcguinness-mission-runtime}}) it also obtains a
point-of-use PDP permit against current Mission state before
executing. The baseline bounds the write only by token lifetime and
the carried constraints.

The cross-domain continuation of this same Mission, projected to a
partner ERP in another trust domain and enforced there, is walked
through in the companion's end-to-end example
({{I-D.draft-mcguinness-oauth-mission-cross-domain}}).

# Integrity Anchor Test Vectors {#test-vectors}

These non-normative vectors let an implementation verify its anchor
computation ({{integrity-anchors}}, {{canonicalization}}) byte for byte.
Both use the issuer `https://as.example.com`. Each canonical-bytes block
is the exact JCS {{RFC8785}} output: a single line, UTF-8, with no
whitespace outside string values.
It is shown here wrapped only for layout; remove the layout line breaks,
adding no characters, to recover the canonical form. Note that JCS sorts
object member names (so `iss` precedes `typ` precedes `value`, within
an entry `actions` precedes `constraints` precedes `resource` precedes
`type`, and within `max_amount` `amount` precedes `currency`) and
preserves array order.

`intent_hash`, over this Mission Intent as the envelope `value` with
`typ` `mission-intent`:

~~~ json
{
  "goal": "Reconcile Q3 invoices",
  "resources": ["https://erp.example.com"],
  "expires_at": "2026-12-31T23:59:59Z"
}
~~~

Canonical bytes of the envelope:

~~~ text
{"iss":"https://as.example.com","typ":"mission-intent","value":{"e
xpires_at":"2026-12-31T23:59:59Z","goal":"Reconcile Q3 invoices","
resources":["https://erp.example.com"]}}
~~~

~~~ text
intent_hash = sha-256:6mIFoCz79uCHNzKLfBpBwqFjoFXdpmpuc65486IqimQ
~~~

`authority_hash`, over this Authority Set as the envelope `value` with
`typ` `mission-authority-set`:

~~~ json
[
  { "type": "mission_resource_access",
    "resource": "https://erp.example.com",
    "actions": ["invoices.read"] },
  { "type": "mission_resource_access",
    "resource": "https://erp.example.com",
    "actions": ["journal-entries.write"],
    "constraints": {
      "max_amount": { "amount": "500.00", "currency": "USD" }
    } }
]
~~~

Canonical bytes of the envelope:

~~~ text
{"iss":"https://as.example.com","typ":"mission-authority-set","val
ue":[{"actions":["invoices.read"],"resource":"https://erp.example.
com","type":"mission_resource_access"},{"actions":["journal-entrie
s.write"],"constraints":{"max_amount":{"amount":"500.00","currency
":"USD"}},"resource":"https://erp.example.com","type":"mission_res
ource_access"}]}
~~~

~~~ text
authority_hash = sha-256:vUCCfjGulit9u0qJ0Z6pQSNerZtXMqRlfJNCr4PzLro
~~~

The third pair exercises the two nesting shapes the pair above does
not: an Intent `controls` object with nested members, and an
Authority Set entry whose `delegation.allowed_delegates` is an array
of matcher objects, where JCS sorts each object's members but
preserves the array's order (the `sub_profile` matcher stays before
the `sub` matcher).

`intent_hash`, over this Mission Intent as the envelope `value` with
`typ` `mission-intent`:

~~~ json
{
  "goal": "Reconcile Q3 invoices",
  "resources": ["https://erp.example.com"],
  "expires_at": "2026-12-31T23:59:59Z",
  "controls": { "acr": "urn:example:acr:mfa", "max_derivations": 20 }
}
~~~

Canonical bytes of the envelope:

~~~ text
{"iss":"https://as.example.com","typ":"mission-intent","value":{"c
ontrols":{"acr":"urn:example:acr:mfa","max_derivations":20},"expir
es_at":"2026-12-31T23:59:59Z","goal":"Reconcile Q3 invoices","reso
urces":["https://erp.example.com"]}}
~~~

~~~ text
intent_hash = sha-256:DHUg4zS3HHnWtXlO6hu9sTN_jX4LyjZ4tOJiTDAvWAI
~~~

`authority_hash`, over this Authority Set as the envelope `value`
with `typ` `mission-authority-set`:

~~~ json
[
  { "type": "mission_resource_access",
    "resource": "https://erp.example.com",
    "actions": ["invoices.read"],
    "delegation": {
      "max_depth": 2,
      "allowed_delegates": [
        { "sub_profile": "ai_agent" },
        { "sub": "s6BhdRkqt3" }
      ]
    } }
]
~~~

Canonical bytes of the envelope:

~~~ text
{"iss":"https://as.example.com","typ":"mission-authority-set","val
ue":[{"actions":["invoices.read"],"delegation":{"allowed_delegates
":[{"sub_profile":"ai_agent"},{"sub":"s6BhdRkqt3"}],"max_depth":2}
,"resource":"https://erp.example.com","type":"mission_resource_acc
ess"}]}
~~~

~~~ text
authority_hash = sha-256:notrA9wZaP3I5Gx8UzN0mfzUjHYPeX4Ri_B3ilh7BbA
~~~

An implementation that canonicalizes the same `value` under the same
`typ` and `iss`, computes SHA-256, and encodes as `sha-256:` followed by
base64url with no padding ({{integrity-anchors}}) reproduces these
anchors exactly. A divergence indicates a JCS or encoding difference to
resolve before interoperating.

# Document History {#document-history}

\[\[ To be removed from the final specification ]]

-01

- Derivation is mechanical, in two modes: narrowing (RECOMMENDED)
  and template. The deterministic-reproducibility and
  policy-inspectability rules are retired, `policy_version` stays as
  an opaque audit correlator, generative derivation is demoted to a
  local-policy extension, and the derivation trust boundary (no
  portable Intent semantics) is stated (#222, #118, #126).
- New wire signals: the `mission_derivation` token-response
  parameter for partial derivation (#174); the `mission_error`
  member disambiguating non-active token-endpoint refusals and the
  issuer-reported `derivations_remaining` introspection member
  (#176); the `mission_denial` WWW-Authenticate attribute
  distinguishing insufficient authority, step-up, and
  unrecognized-constraint denials (#175); and the
  `mission_constraints_supported` protected-resource metadata member
  (#177).
- The `mission` claim gains an OPTIONAL `expires_at` member, a
  bounding commitment with no liveness (#157, #168); the
  `mission_id` token-response parameter is promoted to a SHOULD
  (#149).
- New Common Constraints: `time_window`, `data_classification`,
  `allowed_tools`, and `requires_action_approval` (#133); the
  `prefix` match prohibits query and fragment components and fixes
  the empty-path case (#181).
- New OPTIONAL Intent control: `controls.agent_deployment`, pinning
  a Mission to an approved Agent Deployment (#233);
  `max_derivations` gains cadence-based sizing guidance (#147).
- Delegation hardening: delegation-authorization policy applies at
  every exchange, `allowed_delegates` is RECOMMENDED and its absence
  is never a blanket grant, a no-actor self-exchange is accepted
  only from the Mission's `client_id`, the
  audience-replay-into-exchange threat is named, the delegated-token
  routing guardrail is raised to MUST NOT, and
  `client-instance-jwt` is named as a concrete `actor_token_type`
  (#179, #107).
- Token-class taxonomy: Mission-referenced, Mission-derived, and
  Mission-bound, with "Mission-bound" reserved for the gated class
  (#132); the Cross-Domain capability's conformance bar is made
  self-contained in this document, with the companion cited
  informatively as the interoperable mechanism (#169).
- Approval-event sequencing is named as an extensibility seam with a
  forward pointer to the Mission Deferred Approval companion (#180,
  #148); the `iss` authorization-response parameter is a SHOULD on
  the consent-bearing redirect; `approval_event_id` is fixed as the
  approval idempotency key; the approval-strength floor's home is
  the published Deployment Profile (#181, #204).
- Anchor-role precision: `intent_hash` and `authority_hash` are
  independent commitments and the task-bounds-authority relation is
  a governance assertion; at a narrowed-token Resource Server,
  `authority_hash` is an audit correlator, not an enforcement input;
  the subset rule is named type-specific and representational, not
  semantic (#123, #124, #223).
- Scope statements: the unit of governance (action, not content) in
  Applicability (#120); class-differentiated token-lifetime guidance
  (#119); the opaque-token position (#186); client guidance against
  silent downgrade at a non-advertising AS (#187); introspection
  freshness named per-use (#188); Intent carriage closed to the
  form-encoded PAR parameter, client-set `expires_at` refusal
  semantics, `proposed_authority` resources bound to the Intent's
  `resources`, and the Resource Server multi-entry combination rule
  (#181).
- Key management: verification-key retention anchored to the audit
  horizon (#183), custody guidance for issuer signing keys (#184),
  and per-artifact-class `kid` segmentation (#185).
- Privacy: a Mission-record and evidence-access section (#223); the
  correlation-property documentation duty recast as guidance
  (#204).
- Editorial and registry hygiene: twice-stated rules de-duplicated
  to one home each (#113); "security tiers" vocabulary retired
  (#145); the substrate-generalization future-work item reworded
  (#146); companions extending the worked example must diverge
  anchors explicitly (#151); `example.net` replaces
  `not-example.net` (#110); a third integrity-anchor test vector
  exercising nested `controls` and `delegation` array ordering
  (#114); change controller corrected to IESG and the malformed
  refresh example fixed (#181).
- Editorial restructuring for requirement signal, no normative
  change: the PAR submission rules, consent-rendering hardening, and
  approval-rendering duties become requirement lists; the `resource`
  and `actions` member definitions, the audience and token-response
  text, and the Mission Record introduction are tightened; the
  rendering-to-consent change rule stands as its own paragraph.

-00

- Initial individual draft.

# Acknowledgments
{:numbered="false"}

This work builds on the OAuth 2.0 Rich Authorization Requests, Pushed
Authorization Requests, and JWT access token specifications, and is
intended to complement agent-identity work including
{{I-D.draft-klrc-aiagent-auth}}.
