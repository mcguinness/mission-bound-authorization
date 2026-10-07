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
  I-D.draft-mcguinness-oauth-client-instance-id:
  RFC3339:
  RFC4648:
  RFC5646:
  RFC6234:
  RFC6920:
  RFC7493:
  RFC6749:
  RFC6750:
  RFC7636:
  RFC7800:
  RFC8259:
  RFC8693:
  RFC8785:
  RFC8705:
  RFC8707:
  RFC9068:
  RFC9101:
  RFC9126:
  RFC9207:
  RFC9396:
  RFC9449:
  RFC9470:
  RFC9700:
  RFC7662:
  RFC8414:
  RFC7519:
  RFC9728:

informative:
  I-D.draft-ietf-oauth-rar-metadata-remediation:
  I-D.draft-ietf-wimse-arch:
  I-D.draft-ietf-oauth-spiffe-client-auth:
  RFC8126:
  RFC7009:
  RFC8935:
  RFC9493:
  RFC9635:
  I-D.draft-mcguinness-oauth-actor-profile:
  I-D.draft-mcguinness-oauth-mission-child-delegation:
    title: "Mission Child Delegation for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-child-delegation.html
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
  I-D.draft-mcguinness-oauth-mission-containment:
    title: "Mission Containment for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-containment.html
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
  FAPI.GrantManagement:
    title: "Grant Management for OAuth 2.0"
    target: https://openid.net/specs/fapi-grant-management-01.html
    author:
      - org: OpenID Foundation
    date: 2022
  AuthZEN.ARAP:
    title: "OpenID AuthZEN Access Request and Approval Profile 1.0"
    target: https://openid.github.io/authzen/authzen-access-request-approval-profile-1_0.html
    author:
      - org: OpenID Foundation
    date: 2025
  OpenID.Core:
    title: "OpenID Connect Core 1.0 incorporating errata set 2"
    target: https://openid.net/specs/openid-connect-core-1_0.html
    author:
      - org: OpenID Foundation
    date: 2023
  I-D.draft-ietf-wimse-aims:
  I-D.draft-ietf-oauth-transaction-tokens:
  I-D.draft-niyikiza-oauth-attenuating-agent-tokens:
  I-D.draft-cecchetti-oauth-rar-cedar:
  I-D.draft-mcguinness-oauth-client-attesters:
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
  I-D.draft-mcguinness-oauth-mission-cross-org-delegation:
    title: "Mission Cross-Organizational Delegation for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-cross-org-delegation.html
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
  I-D.draft-mcguinness-mission-substrate:
    title: "Mission Substrate Requirements"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-substrate.html
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
  I-D.draft-mcguinness-mission-security-model:
    title: "Mission Security Model"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-security-model.html
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
  I-D.draft-mcguinness-oauth-mission-submission-evidence:
    title: "Mission Intent Submission Evidence for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-submission-evidence.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-oauth-mission-approved-set-verification:
    title: "Mission Approved-Set Verification for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-approved-set-verification.html
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
  I-D.draft-mcguinness-oauth-mission-approval:
    title: "Mission Deferred Approval for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-approval.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-mission-approval-governance:
    title: "Mission Approval Governance"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-approval-governance.html
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
  I-D.draft-mcguinness-oauth-mission-work-products:
    title: "Mission Work Products for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-work-products.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-oauth-mission-resource-access:
    title: "Mission Resource Access Profile for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-resource-access.html
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
  I-D.draft-mcguinness-oauth-mission-management:
    title: "Mission Management for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-management.html
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
authorization server derives Rich Authorization Requests authorization
details from it, binds the approved task and its derived authority to
the Approver's consent through integrity anchors, and records a
durable Mission. Every access token derived under the Mission carries
that authority and a "mission" claim, and issuance is gated on the
Mission's lifecycle state. Optional capabilities represent
delegation among agents with the OAuth Actor Profile and, as specified by a
companion, let a single Mission be honored across trust domains. This
is the issuance and governance "mission layer" left unspecified by
agent-identity work for OAuth; runtime enforcement of each action is a
separate, optional layer.

--- middle

# Introduction {#introduction}

Agent-identity work such as {{I-D.draft-ietf-wimse-aims}}
establishes how an AI agent authenticates and how a user delegates
authority to it: the agent is an OAuth 2.0 {{RFC6749}} client
identified by `client_id`, the delegating user is the access token
`sub`, and the agent obtains tokens for the resources its task
requires. That work leaves three things out of scope: how an agent's
task (its "mission") is translated into authorization, how a user's
approval of that task is captured as a durable artifact, and how
later token issuance stays bound to what the user approved.

In current deployments, each token is individually valid and each
request individually in scope, but no OAuth object records the task
the user approved. A token issued for a task remains usable after
the user's approval lapses or is withdrawn, because nothing ties the
token's validity to that approval.

This document defines a **Mission**: a durable authorization object
that binds a disclosed task to an explicitly approved Authority Set
and governs the lifecycle of the authority derived from that
approval. A Mission is created and used in a single chain:

1. The client submits a structured **Mission Intent** describing the
   task (goal, target resources, task bounds) instead of requesting
   raw scopes, optionally proposing concrete authority alongside it
   as standard `authorization_details`.
2. The authorization server (AS) derives **authorization details**
   ({{RFC9396}}), the **Authority Set**: the concrete authority the
   task needs.
3. At an **approval event**, the Approver consents to that
   authority, and the AS commits the task as an **`intent_hash`** and
   the authority as an **`authority_hash`** and records a durable
   **Mission**.
4. The AS binds the OAuth grant that the approval produces to that
   Mission, server-side: every later derivation from that grant
   lineage resolves to exactly this Mission, and the client never
   selects or reassigns it ({{grant-binding}}).
5. Every access token the agent obtains under the Mission carries the
   derived authorization details and a **`mission` claim** identifying
   the Mission (`id`, `issuer`) it was derived under. A resource
   server enforces statelessly from the token.
6. Token issuance and refresh are **gated on Mission state**, so
   revoking or expiring the Mission stops the agent from obtaining
   further authority.

The result is that a user approves a task once, and that approval,
not a per-request scope grant, bounds and outlives every token the
agent derives. The consented authority is committed once, as
`authority_hash`, on the Mission Record; a party holding the full
Authority Set can independently verify it ({{consent-binding}}).
Mission Approved-Set Verification
({{I-D.draft-mcguinness-oauth-mission-approved-set-verification}})
defines that independent check for a token that carries only a
narrowed subset.

This chain is the first of two enforcement layers, and a deployment
can run it alone: a resource server need not be Mission-aware unless
it receives delegated tokens ({{rs-enforcement}}). It gives
task-bound issuance, auditability, and a revocation gate over future
derivation, and every token carries a subset of the approved
Authority Set ({{subset}}) that no resource server over-grants on
({{scope-projection}}). It does not evaluate individual actions, so
token lifetime and narrow authority bound the exposure between
issuance and use. The second layer, a separately specified runtime
layer ({{runtime-boundary}}), adds a per-action check for the action
classes whose consequence needs one.

## Implementation Map {#implementation-map}

This document establishes six properties; {{conformance}} states the
requirements that realize them:

1. The task is disclosed: the approval rendering shows the Intent's
   task, and the AS commits the Intent as `intent_hash`
   ({{approval-event}}, {{integrity-anchors}}).
2. The authority is explicitly approved: the Approver consents to the
   derived Authority Set itself, not to the task description alone
   ({{approval-event}}).
3. The Mission Record durably associates the disclosed task, the
   approved authority, and the approval basis; separate commitments
   protect the recorded Intent and Authority Set ({{mission-record}},
   {{integrity-anchors}}).
4. The OAuth grant lineage is bound to exactly one Mission,
   server-side ({{grant-binding}}).
5. Every derived authority is no broader than the approved Authority
   Set ({{subset}}).
6. A Mission that is not `active` yields no further derivation
   ({{issuance-gating}}).

{{conformance}} is the complete statement of roles and optional
capabilities. The starting path is one client, one authorization
server, direct approval, and a single resource audience. It needs no
runtime profile, delegated token, or cross-domain projection.

| Implementer | Responsibility on the starting path | Defining sections |
| --- | --- | --- |
| Mission Client | Submit an Intent through PAR, optionally propose authority, complete the authorization-code flow, and read the granted authority and Mission references from the response | {{submission-via-par}}, {{authority-proposal}}, {{grant-binding}}, {{mission-bound-tokens}} |
| Mission Issuer (AS) | Validate the submission, derive bounded authority, obtain approval, commit the Mission, and gate every issuance and refresh on its state and limits | {{submission-processing}}, {{authorization-derivation}}, {{approval-event}}, {{mission-record}}, {{issuance-gating}} |
| Mission-aware Resource Server | Validate the credential and any sender constraint, enforce the carried authority, and apply any configured Mission requirement | {{rs-enforcement}}, {{introspected-consumption}} |
{: title="Who implements the issuance path"}

A resource server need not become Mission-aware for this starting
path. A scope-only resource is eligible only when the AS establishes
that its scope projection and the resource's independent controls
cannot over-grant ({{scope-projection}}). Delegated tokens have a
separate Mission-awareness requirement ({{rs-enforcement}}).

Some duties apply only when their condition holds: a submitted
authority proposal, presented or required submission evidence
({{intent-submission-evidence}},
{{I-D.draft-mcguinness-oauth-mission-submission-evidence}}), or
opaque tokens (which require introspection). The optional
capabilities (Delegation, Introspection as a state overlay for JWTs,
and Cross-Domain projection) are adopted explicitly under
{{conformance}}. Ordinary JWT consumption does not require retrieving
the Mission Record or recomputing the complete approved Authority Set.

## Applicability {#applicability}

This document targets OAuth deployments where authority serves a
durable, approved task that spans more than one token, request, or
audience: an agent pursuing a multi-step objective on a user's
behalf, or a workflow whose audit must join activity across hops on
a shared task. It is not intended for single-request user flows and
short-lived authorizations where the credential's lifetime is the
task's lifetime, ordinary machine-to-machine service credentials
among them; those use OAuth unchanged. The boundary is that lifetime
equality, not the absence of a human: a workload's durable
multi-step task is in scope as a service-owned Mission
({{authority-sources}}).

A Mission is intended to cover one concrete task, not an agent's whole
lifetime: narrow, per-task Missions, each separately approved and
revocable, are preferred over a single broad standing Mission that
accumulates authority across unrelated tasks.

This preference has a consent cost. Many narrow Missions can create
approval fatigue; combining unrelated authority into one broad
Mission can make approval difficult to evaluate. A useful boundary
is a task whose purpose, authority, and bounds the Approver can
evaluate together ({{approval-comprehension}}).

For recurring or evolving work, optional, experimental companions
can reduce repeated approvals through standing consent
({{standing-consent-bases}}). Mission Template
({{I-D.draft-mcguinness-oauth-mission-template}}) creates bounded
instances of recurring tasks. Progressive Authorization
({{I-D.draft-mcguinness-oauth-mission-progressive}}) permits successor
Missions within a previously approved authority ceiling as a task
evolves. The template or ceiling still needs a meaningful human
approval. Neither mechanism removes its profile's
fresh-human-approval requirement for prohibited high-consequence
authority.

The unit of governance is the action, not the content. A Mission
bounds where an agent may act (resources, actions) and how much
(constraints and, where metered, cumulative bounds); it does not
inspect what content flows within an authorized action, and an
approved egress channel carries a status update or an exfiltrated
payload with equal authority. Content-level controls (data loss
prevention, redaction) are complementary; under mediated execution
they fit at the mediating enforcement component
({{runtime-boundary}}).

# Conventions and Terminology {#conventions-and-terminology}

{::boilerplate bcp14-tagged}

All JSON shown in this document is non-normative and illustrative; the
member definitions in the surrounding text are authoritative.

Agent (Client):
: The OAuth client acting for the Mission's Subject, identified by
  `client_id`. Agent identity is established per
  {{I-D.draft-ietf-wimse-aims}} or ordinary OAuth client
  authentication.

Subject:
: The user, workload, or organizational principal on whose behalf the
  Mission is approved ({{authority-sources}}), identified by an
  (`iss`, `sub`) pair and carried in derived tokens' `sub` claim.

Approver:
: The single accountable principal who approves the Mission: at its
  direct approval event or, under a standing-consent basis, through
  the earlier standing consent ({{standing-consent-bases}}). Equal to
  the Subject for self-approval; different
  for administrator or delegated approval. This document records one
  accountable Approver; multi-party approval and the provenance of
  delegated approval authority are deferred ({{multi-party-approval}}).

Mission Issuer (authorization server):
: The OAuth AS that validates a Mission Intent, runs the approval
  event, records the Mission, and derives tokens. It is the Mission's
  `issuer`; this document also calls it the "issuer AS" or the "AS".

Resource AS:
: An authorization server in another trust domain that honors a
  Mission it did not issue, minting its own tokens for its resources;
  it is never the Mission Issuer. Cross-domain projection is specified
  by the companion Mission Cross-Domain Projection profile
  ({{I-D.draft-mcguinness-oauth-mission-cross-domain}}).

Mission Intent:
: The structured description of the task the client submits
  ({{mission-intent}}).

Mission Intent Submission (Submission envelope):
: The object a client submits as the `mission_intent` parameter
  value: the Mission Intent under `intent`, and Intent Submission
  Evidence under `evidence` where any is presented
  ({{submission-via-par}}).

Intent Submission Evidence:
: Typed artifacts a client presents in support of claims about a
  submitted Mission Intent ({{intent-submission-evidence}}):
  authenticated policy input, not authority. The term names inbound,
  client-presented material; the evidence this document and
  companion profiles emit and record (a consent-evidence artifact, an
  audit evidence base) is issuer- or runtime-produced output, not
  this.

Authority Proposal:
: The `authorization_details` array a client submits alongside a
  Mission Intent, a proposal for derivation and not authority
  ({{authority-proposal}}).

Authority Set:
: The set of `authorization_details` entries the AS derives from a
  Mission Intent and the Approver approves
  ({{authorization-derivation}}).

Mission:
: The durable authorization object that binds a disclosed task (its
  Mission Intent) to an explicitly approved Authority Set and governs
  the lifecycle of the authority derived from that approval. It is the
  immutable record created at the approval event ({{mission-record}}),
  identified by a Mission Identifier ({{mission-id}}) and, globally, by
  the pair (`issuer`, `id`). A Mission is independent of any OAuth
  grant ({{grant-binding}}). "The approved task" is shorthand for this
  binding: the Approver approves the Authority Set, and the task is
  disclosed and committed beside it.

Mission Grant Binding (Grant Binding):
: The AS-controlled, functional mapping from one persistent,
  redeemable grant lineage to exactly one Mission ({{grant-binding}}).
  Distinct from a Derived token's own `mission` claim, which every
  issued credential carries without itself creating a grant binding.

Mission-referenced token:
: A token that carries a Mission reference (the `mission` claim or a
  `mission_id`) without Mission-derived authority or any gating
  guarantee.

Derived token (Mission-derived token):
: An access token issued under a Mission, carrying its Mission-derived
  authority (the full Authority Set or a narrowed subset) as
  `authorization_details` and a `mission` claim
  ({{mission-bound-tokens}}).

Mission-bound token:
: A Mission-derived access token or refresh token whose issuance and
  refresh are gated on the Mission's `active` state and bounded by the
  subset rule (with refresh tokens bound server-side). Only this class
  carries the gating guarantee of this document; a token that only
  references or carries Mission data without the gates is not
  Mission-bound ({{conformance}}).

# Overview {#overview}

## Principal Model {#principal-model}

This document maps principals onto native OAuth constructs:

- The **Agent** is the OAuth client, referenced by `client_id`. Agent
  identity and credentialing are out of scope (see
  {{I-D.draft-ietf-wimse-aims}}).
- The **Subject** and **Approver** are each an (`iss`,
  `sub`) pair, matching the access token `sub` model of {{RFC9068}}.
  The Approver is the accountable consent principal whose approval
  created the Mission, always equal to
  `approval_basis.consent_principal`; under a standing-consent basis
  a policy adjudicates the activation, which the basis's
  `adjudication` member can make explicit ({{mission-record}}), while
  the Approver remains the human whose consent roots it
  ({{authority-sources}}, {{multi-party-approval}}).

On a derived token, the `iss` claim is the AS and the `sub` claim is
the AS-local `sub` to which the AS maps the Subject under the
injective mapping of {{approval-event}}; adopting the external `sub`
verbatim is the common case. Within the issuing AS's namespace, this
(`iss`, `sub`) pair is the AS-local subject principal, authoritative
for the Subject, and resource servers authorize against it. The
Mission separately records the Subject's home issuer and identifier
as `subject.iss` and `subject.sub`: the external subject identity,
carried as provenance for audit and not on the token. This document
defines no runtime lookup of it.

The record's (`subject.iss`, `subject.sub`) and the token's (AS
`iss`, `sub`) identify the same Subject in two issuer namespaces.
Across trust domains, the cross-domain companion conveys Subject
identity through its own subject-resolution claims, not a Mission
lookup, and a token minted in another domain preserves the `mission`
claim unchanged ({{I-D.draft-mcguinness-oauth-mission-cross-domain}}).

Issuer roles obey two invariants: a Mission has exactly one Mission
Issuer, its `issuer`, and a Resource AS never creates or alters a
Mission.

Principals are recorded at the approval event and are immutable. Two
principals are equal when their `iss` and `sub` are byte-equal, so
the test compares principals only within one issuer namespace; the
external subject identity and the AS-local subject principal
represent one Subject and are never compared under this rule.

Dynamic delegation (the actors an agent delegates to during
execution) is carried on derived tokens in the `act` chain
({{delegation}}), not on the immutable Mission Record. This document
uses only (`iss`, `sub`) pairs; the subject identifier formats of
{{RFC9493}} are not used.

## Protocol Flow {#protocol-flow}

The following figure shows the protocol flow between the agent and
the Mission Issuer:

~~~
 Agent (client)                       Mission Issuer (AS)
      |                                     |
      | 1. PAR: intent + proposal --------->| derive authority
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

The flow then leaves the AS: (4) the agent calls the resource server
with the token; the resource server enforces the `authorization_details`
statelessly and can check the `mission` claim ({{rs-enforcement}}),
with no callback to the AS required. (5) A management revoke, or
`expires_at` passing, moves the Mission to `revoked` or `expired`,
after which the AS refuses further issuance and refresh; a deployment
can also treat {{RFC7009}} revocation of the refresh token as
revoking the Mission ({{revocation}}). The end-to-end example
({{e2e-example}}) walks this flow with concrete messages.

### One Mission from Approval to Revocation {#first-mission}

Consider a registered client reading invoices from one ERP resource
for Alice. Alice is both the Subject and the Approver; the authority
source is user-delegated. The AS and ERP support the
`mission_resource_access` type defined by
{{I-D.draft-mcguinness-oauth-mission-resource-access}}. This example
uses a direct approval, a JWT access token, no delegated token, and
no submission evidence; the AS's admission policy requires none.
The times below are on the same day in UTC.

1. **Submit.** The client pushes a Mission Intent naming
   `https://erp.example.com` and requesting expiry at 13:00. Alongside
   it, the client proposes an `authorization_details` entry of type
   `mission_resource_access` for that resource and the action
   `invoices.read`. It follows the PAR `request_uri` into the
   authorization interaction ({{submission-via-par}}).
2. **Approve and commit.** At 12:00 the AS authenticates Alice,
   verifies the authority source and proposed read authority, and
   renders that authority and the effective 13:00 expiry for her
   approval. On approval it atomically creates the active Mission,
   records its commitments, and binds the authorization code to it
   ({{approval-event}}, {{grant-binding}}).
3. **Issue.** Still at 12:00, the client redeems the code. The AS
   resolves and checks the Mission and returns a sender-constrained
   ERP token that expires at 12:05, with the read authority and a
   `mission` reference. The response also carries the granted
   authority, `mission_id`, and `mission_expires_at`
   ({{grant-binding}}). The access token's five-minute lifetime is
   distinct from the Mission's one-hour lifetime
   ({{mission-bound-tokens}}).
4. **Use.** The ERP, a Mission-aware Resource Server, validates the
   token and proof of possession and permits the authorized read. The
   token grants no write authority.
   No Mission-state lookup or complete-set retrieval is part of this
   example's resource request ({{rs-enforcement}}).
5. **Stop further issuance.** At 12:02 an authorized revocation makes
   the Mission non-active. A subsequent refresh, if the AS issued a
   refresh token, is refused with `invalid_grant`
   ({{issuance-gating}}). The already-issued access token can still
   be honored on this stateless path until 12:05; revocation does not
   undo a completed read ({{revocation}}).

An ERP that instead introspects on every request stops honoring the
token on its next request after revocation, through the composite
`active` result ({{composite-active}}).

# Mission Intent {#mission-intent}

Before the approval event ({{approval-event}}) only the Mission
Intent exists, as untrusted client input ({{submission-via-par}});
after it, only the Mission is authoritative. A Mission Intent
therefore has no protocol identifier of its own: two submissions of
the same Intent produce two distinct pending requests, and a Mission
acquires its Mission Identifier ({{mission-id}}) only at activation.

The approved Intent is recorded on the Mission and committed by
`intent_hash` ({{integrity-anchors}}); it describes the task and
carries no authority members. Concrete authority is proposed
separately, on the standard `authorization_details` parameter
({{authority-proposal}}), and committed by `proposal_hash` when
submitted; the granted authority is committed by `authority_hash`
over the derived Authority Set ({{authorization-derivation}}).

A Mission Intent is a JSON object describing the task. The client
submits it as the `intent` member of the Submission envelope
({{submission-via-par}}), in place of `scope` or alongside a
narrowed `scope`. It has the following members:

`goal`:
: REQUIRED. A string. A human-readable statement of the task,
  for rendering to the Approver. Maximum 4096 characters. Prose
  here persists on the record and can carry personal data about
  third parties ({{third-party-data-subjects}}).

`goal_lang`:
: OPTIONAL. A string. A BCP 47 language tag {{RFC5646}} declaring
  the language of the Intent's human-readable members (`goal`,
  `task_bounds`, `success_criteria`). It is disclosure metadata for
  rendering, committed by `intent_hash` like every Intent member, and
  carries no machine semantics ({{authorization-derivation}}). At
  submission acceptance, the AS MUST refuse a `goal_lang` that is not
  a well-formed language tag with `invalid_request` ({{i18n}}).

`target_resources`:
: REQUIRED. An array of strings. A client-requested Intent
  ceiling on the task's target resources, each an absolute URI
  identifying a protected resource (an OAuth resource per
  {{RFC8707}}-style indicators or a Protected Resource per
  {{RFC9728}}). It is not RFC 8707 `resource` carriage: it bounds
  which resources a derived Authority Set entry may name
  ({{authorization-derivation}}) and serves as a configured-mapping
  lookup key, but a client separately requests the audience of a
  given token with the standard `resource` parameter
  ({{mission-bound-tokens}}).

`task_bounds`:
: OPTIONAL. An array of strings. Human-readable bounds on the task
  (for example, "read only invoices from 2026"). They are disclosure
  and audit context, rendered to the Approver beside the derived
  Authority Set ({{approval-event}}), and carry no machine semantics
  ({{authorization-derivation}}); a machine-enforceable bound enters
  as structure instead.

`success_criteria`:
: OPTIONAL. An array of strings. Human-readable observable outcomes
  that indicate the task is complete. These are disclosure and audit
  material only: they are rendered to the Approver and committed by
  `intent_hash` ({{integrity-anchors}}) and carry no machine
  semantics ({{authorization-derivation}}).

`purpose`:
: OPTIONAL. A string. A URI identifying the purpose of the
  task, recorded for disclosure and audit. Its semantics are
  deployment- or registry-defined and opaque to this document. It is
  an opaque lookup key: a configured mapping can key on it to select
  candidate entries, which the Intent, policy, and the approval event
  bound like any derivation ({{authorization-derivation}}); the key
  alone grants no authority. In any other decision, `purpose` MAY
  contribute only to a refusal or to stricter treatment: its value,
  its absence, or a substituted value MUST NOT supply, widen, relax,
  or refresh authority, or replace a check that applies independently
  of it. After approval, the `purpose` consulted is the approved
  Mission's, or a validated projection of it.

`expires_at`:
: REQUIRED. A string. An RFC 3339 {{RFC3339}} date-time: the
  client's requested not-after ceiling for the Mission's lifetime.
  The submitted Intent is recorded verbatim. The lifetime actually
  granted is the Mission Record's effective `expires_at`, which the
  AS establishes at Mission creation and which is no later than this
  value ({{approval-event}}, {{mission-record}}).

  At submission acceptance, the AS MUST refuse a malformed or
  already-past value with `invalid_request`. Acceptance does not
  freeze time: Mission creation re-checks the effective expiry
  atomically at the commit ({{approval-event}}). A request that
  resolves to an already-committed operation is recovery, not a new
  submission, and returns the stored outcome under the applicable
  idempotency rules even when the ceiling has since passed
  ({{grant-binding}}).

The Approver's authentication strength for the approval event is
requested with the standard `acr_values` and `max_age`
authorization-request parameters, not on the Intent
({{approval-authentication}}).

The Mission Intent's top level is closed to the members above and to
those a companion profile the AS implements defines
({{extensibility}}, {{submission-via-par}}).

The following is an example of a Mission Intent:

~~~ json
{
  "goal": "Reconcile Q3 invoices and post adjustments under $500.",
  "target_resources": ["https://erp.example.com"],
  "task_bounds": [
    "Read only invoices issued in 2026-Q3.",
    "Post journal entries under $500."
  ],
  "success_criteria": [
    "All Q3 invoices reconciled.",
    "Each posted adjustment references a source invoice."
  ],
  "purpose": "urn:example:purpose:reconcile",
  "expires_at": "2026-12-31T23:59:59Z"
}
~~~

## Submission via PAR {#submission-via-par}

A client MUST submit a Mission Intent through a Pushed Authorization
Request {{RFC9126}} using the `mission_intent` request parameter. The
parameter value is the UTF-8 JSON {{RFC8259}} serialization of the
Submission envelope, a JSON object carried as an ordinary OAuth
request-parameter value (form-encoded in the
`application/x-www-form-urlencoded` PAR request body, like other
OAuth parameters) with exactly these members:

`intent`:
: REQUIRED. The Mission Intent object ({{mission-intent}}).

`evidence`:
: OPTIONAL. A non-empty array of Intent Submission Evidence entries
  ({{intent-submission-evidence}}); the AS refuses an empty array
  with the `invalid_request` error code.

`intent_hash` commits exactly the `intent` object, not the
Submission envelope or its `evidence` array ({{integrity-anchors}}).

The AS returns a `request_uri` as usual, which the client uses to
start authorization. An AS that cannot parse `mission_intent` as a
JSON object, or that parses it but finds the Submission envelope or
the Intent structurally invalid against this document's member
definitions, MUST refuse the request with the `invalid_request`
error code.

Submission is governed by the following rules:

- **Closed top levels.** The AS MUST reject a submission with the
  `invalid_request` error code if the Submission envelope contains a
  top-level member other than `intent` and `evidence`, or if the
  `intent` contains a top-level member that neither this document
  nor a companion profile the AS implements defines
  ({{extensibility}}). A bare Mission Intent submitted as the
  parameter value fails this rule, since its `goal` and sibling
  members are unknown envelope members.
- **One carriage, through PAR.** The AS accepts the Intent in one of
  two forms:

  1. the form-encoded `mission_intent` parameter of the PAR request
     body; or
  2. a `mission_intent` claim inside a signed Request Object
     ({{RFC9101}}) that is itself pushed through PAR.

  The AS MUST reject with `invalid_request` a `mission_intent`
  presented on a front-channel authorization request that does not
  use a PAR-issued `request_uri`. A client MUST NOT send
  `mission_intent` as a plaintext front-channel authorization-request
  parameter, whether or not a Request Object is also present. When
  the pushed request carries a Request Object (a `request` parameter
  value), that object is authoritative: a `mission_intent` submitted
  outside the Request Object in the same push MUST be rejected with
  `invalid_request`, strengthening {{Section 6.3 of RFC9101}}, under
  which the AS would only ignore such a value.
- **Bounded size.** The AS MUST bound the Submission envelope's
  total size, the Intent's total size and the lengths of its arrays,
  and the count and per-entry sizes of `evidence` entries, refusing
  a submission that exceeds the deployment-defined limits with
  `invalid_request`. The verification-cost bound of
  {{I-D.draft-mcguinness-oauth-mission-submission-evidence}}
  accompanies these.
- **Concrete authority is proposed via `authorization_details`.**
  A client proposes concrete authority on the standard
  `authorization_details` parameter in the same push
  ({{authority-proposal}}). A client can also push `scope` and
  `resource` ({{RFC8707}}) values; the AS treats them as a requested
  subset of the authority the Mission Intent yields
  ({{authorization-derivation}}).
- **Pushed parameters are authoritative.** On the front-channel
  request that redeems the `request_uri`, the AS MUST ignore any
  `mission_intent`, `authorization_details`, `scope`, or `resource`
  presented.
- **A proposal, not authority.** A Mission Intent, and any authority
  proposal submitted alongside it ({{authority-proposal}}), is
  untrusted client input; trust enters only when the AS validates it
  and the Approver consents to the rendered result. The AS treats the
  submission as a proposal and derives and bounds authority by its
  own policy, whatever the client submitted
  ({{authorization-derivation}}).

The following is an example of a Submission envelope carrying a
compact Intent and one evidence entry of an illustrative,
deployment-defined type:

~~~ json
{
  "intent": {
    "goal": "Reconcile Q3 invoices and post adjustments under $500.",
    "target_resources": ["https://erp.example.com"],
    "expires_at": "2026-12-31T23:59:59Z"
  },
  "evidence": [
    {
      "type": "urn:example:intent-evidence:admission",
      "assertion": "eyJhbGciOiJFUzI1NiIsImtpZCI6ImFkbS0xIn0..."
    }
  ]
}
~~~

## Authority Proposal {#authority-proposal}

A client MAY propose concrete authority for the task by submitting
the standard {{RFC9396}} `authorization_details` request parameter,
a JSON array of `authorization_details` objects, alongside
`mission_intent` in the same pushed request
({{submission-via-par}}).

The submitted `authorization_details` is a proposal, not authority
({{submission-via-par}}); the AS derives and bounds the Authority
Set from it ({{authorization-derivation}}).

The AS validates each submitted entry per {{Section 5 of RFC9396}}:
it refuses a request carrying an entry of a type it does not support
({{other-types}}, {{discovery}}), or one that fails its type's
documented definition, with the `invalid_authorization_details`
error code, and never repairs a failure by omitting the entry. Where
a machine-readable JSON Schema for the type is advertised
({{discovery}}) or established out of band, the entry MUST also
validate against that schema, and the AS MUST refuse a request
carrying an entry that fails it with the
`invalid_authorization_details` error code.

Policy narrowing is distinct. During derivation the AS MAY narrow or
omit a syntactically valid entry that policy cannot accept
({{authorization-derivation}}). The granted `authorization_details`
in the token response reflects every narrowing and omission
({{mission-bound-tokens}}).

When a proposal is present, the AS MUST derive each Authority Set
entry as a subset ({{subset}}) of some proposed entry of the *same
type*: narrowed under that type's own subset rule where it defines
one, or carried through unchanged where it defines none
({{other-types}}).

`goal` and `task_bounds` then serve as rendering and bounding context
over the proposed authority. Each proposed entry that carries a
`resource` member MUST have it among the Intent's `target_resources`,
compared as {{authorization-derivation}} states; the AS refuses a
request violating this with the `invalid_request` error code.

The carriage rules of {{submission-via-par}} apply to the proposal.
The AS records the submitted array on the Mission exactly as
submitted and commits it by `proposal_hash` ({{integrity-anchors}},
{{mission-record}}), separately from the task (`intent_hash`) and
the grant (`authority_hash`), so a narrowed grant can be audited
against the proposal that sought it.

Submitting `authorization_details` without `mission_intent` is an
ordinary {{RFC9396}} request that this document does not govern.
Two AS-side rules keep a governed task from being downgraded to such
a request; {{downgrade-by-omission}} states the client-side rule and
the threat. Where a deployment designates a resource
Mission-governed, its AS MUST NOT issue a token for that resource
outside a Mission, except under documented policy exceptions. If a
client registered as Mission-governed sends an
`authorization_details` request that carries no `mission_intent`,
the AS MUST reject the request with the `invalid_request` error
code, so the client cannot omit the Intent to obtain ungoverned
tokens.

The following is an example of an authority proposal submitted
alongside the example Intent of {{mission-intent}}. Derivation
narrows `invoices.*` to `invoices.read`, keeps the proposed Q3
issuance window and write ceiling, which the Intent's task bounds
support, and carries the proposed `delegation` policy through unchanged (the
example Authority Set of {{authorization-derivation}}):

~~~ json
[
  { "type": "mission_resource_access",
    "resource": "https://erp.example.com",
    "actions": ["invoices.*"],
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

## Intent Submission Evidence {#intent-submission-evidence}

The Submission envelope's `evidence` array carries **Intent
Submission Evidence**: typed artifacts the client presents in support
of claims about the submitted Intent, such as its originator, an
admission or consent decision that applies to it, or the presenter
authorized to submit it. Each entry is a JSON object whose `type`
member names its evidence type.

Processing is governed by the following rules:

- **Reject, do not ignore.** An entry that is not a JSON object, or
  that lacks `type`, is structurally invalid and refused with the
  `invalid_request` error code. The AS MUST refuse an entry whose
  `type` it does not support, and an entry that fails its type's
  validation or verification, with the
  `invalid_mission_intent_evidence` error code ({{iana}}). A
  submission is accepted only when every presented entry verifies.
- **Policy input, not authority.** A verified entry is policy input,
  not authority: it is not copied into the Authority Set and does not
  stand in for the approval event ({{approval-event}}), the sole
  activation of authority. Verified evidence can serve as
  authenticated input to admission and derivation policy; AS policy
  decides whether the verified claims are acceptable for this
  request.

Mission Intent Submission Evidence for OAuth 2.0
({{I-D.draft-mcguinness-oauth-mission-submission-evidence}})
specifies the entry convention, required-evidence resolution, the
binding of evidence to one Intent and to the presenter, the
verification-cost bound, where the error is returned, and evidence on
idempotent creation surfaces.

## Submission Processing Order {#submission-processing}

The AS processes a submission in this order:

1. Parse the Submission envelope and enforce both closed top levels
   ({{submission-via-par}}).
2. Validate the `intent` object against the Mission Intent member
   definitions ({{mission-intent}}).
3. Compute the provisional `intent_hash` over the `intent` object
   ({{integrity-anchors}}).
4. Apply any submission checks that configured admission policy or
   adopted profiles require before evidence verification, including
   when no `evidence` member is present. For example, the Submission
   Evidence companion resolves required evidence here and refuses a
   missing required type
   ({{I-D.draft-mcguinness-oauth-mission-submission-evidence}}, Section
   "Required Evidence Is Resolved Before Derivation").
5. Apply the evidence dispatch and refusal rules, verifying every
   presented entry under its type's rules
   ({{intent-submission-evidence}}).
6. Apply admission policy and derive the Authority Set independently
   ({{authorization-derivation}}).
7. Render the Intent, the Authority Set, and the material verified
   provenance for approval; a change to any of them before the
   decision is re-rendered and approved over the changed context
   ({{approval-event}}).
8. At activation, record the approved `intent`, `intent_hash`, the
   Authority Set, and the verified evidence facts as
   `submission_evidence` ({{mission-record}}).

The material verified provenance of step 7 is part of the approval
surface. Where a deployment commits the rendered approval surface,
that commitment MUST cover the normalized provenance facts, at least
as a digest of their canonical `submission_evidence` representation
({{mission-record}}). For example, the consent-evidence companion
binds them with a `submission_provenance_hash` inside its committed
disclosure ({{I-D.draft-mcguinness-oauth-mission-consent-evidence}}).

# Mission Authority {#authorization-derivation}

From the Mission Intent, and from the authority proposal where one
was submitted ({{authority-proposal}}), the AS derives the
**Authority Set**: one or more {{RFC9396}} `authorization_details`
entries of an AS-supported type ({{other-types}}). Derivation is
mechanical. It happens once, at the approval event, over the
derivation policy then in force, as one procedure whose candidate
entries depend on whether an authority proposal was submitted:

- **Narrowing mode** (preferred where the client can author
  `authorization_details`): the client submitted an authority
  proposal ({{authority-proposal}}), and the Authority Set is the
  proposal narrowed to policy. Each derived entry is a same-type
  subset of a proposed entry ({{authority-proposal}}).
- **Configured-mapping mode**: no authority proposal was submitted,
  and a deployment-configured mapping, keyed on the Intent's
  `purpose` or `target_resources`, yields the candidate entries,
  which are then narrowed to policy.

  The mapping is a lookup, not synthesis; because no
  `authorization_details` object was submitted, the AS refuses an
  Intent that matches no configured mapping, or whose mapped
  candidates policy narrows to nothing, with `access_denied`
  ({{error-mapping}}); its `error_description` can say whether no
  mapping matched or policy narrowed the candidates to nothing.

  Either mode is conforming. A deployment publishes its mapping
  space as deployment documentation. Eligibility can be scoped per
  Subject and client, and a mapping keyed on Subject attributes
  resolves at the approval event, where the Subject is established
  ({{approval-event}}), so a refusal at PAR time is best-effort over
  what is checkable without the Subject. Every Mission this mode
  yields takes its own fresh approval; standing consent to a
  pre-approved ceiling is the separate, experimental Mission
  Template profile ({{I-D.draft-mcguinness-oauth-mission-template}}),
  not this mode.

In both modes the AS bounds every Authority Set entry by the Mission
Intent: each entry that carries a `resource` member MUST have it
among the Intent's `target_resources` values, by exact string
equality. This membership check applies to the Authority Set, and to
a proposal at submission ({{authority-proposal}}). A later token
issuance is bounded by the subset rule against the Authority Set
({{subset}}), not by the target list again: a type whose subset
relation admits a narrower `resource` (for
`mission_resource_access`, a descendant of a `prefix` entry) can
yield a token entry that `target_resources` does not name, and a
candidate outside every Authority Set entry fails that rule.

The Mission records the policy version in force as `policy_version`
({{mission-record}}), an opaque audit correlator; the policy itself
is not conveyed.

Generative derivation is not one of this document's modes. As a
local-policy extension, a model's output can be a recorded input to
the AS's deterministic derivation policy, together with the model's
identifier and version. That input can cause refusal or further
narrow the candidate authority the selected mode and policy otherwise
permit. The AS MUST NOT let it supply or widen authority. Each type's
subset rule ({{subset}}), the Intent bounds, and the prose boundary
below still apply.

A `target_resources` entry the deployment does not recognize is, by
deployment policy, either omitted from the Authority Set or refused
with `access_denied` ({{error-mapping}}). When an omission or a
narrowing leaves the Authority Set short of what was proposed
({{authority-proposal}}), derivation is partial. The granted
`authorization_details` in the token response
({{mission-bound-tokens}}) is the authoritative statement of what was
granted; a client compares it against its proposal, which
`proposal_hash` commits as submitted ({{integrity-anchors}}).

The derived Authority Set, not the Mission Intent, is the authority the
Approver consents to: the AS renders the Authority Set for approval and
commits it as `authority_hash` ({{approval-event}}). The Intent's
members describe and bound the task but grant no authority by
themselves ({{mission-intent}}): its structured members constrain
what the AS can derive mechanically, its prose members bound through
disclosure (the Approver refuses authority the words do not
support), and none widens.

The `goal`, `task_bounds`, and `success_criteria` members are
human-readable disclosure and audit context. The AS MUST derive the
same Authority Set, under the same policy, for two submissions that
differ only in `goal`, `goal_lang`, `task_bounds`, or
`success_criteria`, and MUST NOT gate issuance on those members,
whether in derivation, in an adjudicating policy, or through a model
input to either; translating a user's words into structure is the
shaper's job, before admission and outside the trust boundary
({{I-D.draft-mcguinness-mission-shaping}}).

A client-proposed constraint on an individual Authority Set entry
enters through the `authorization_details` proposal: constraints a
supported type's specification defines (for example, the Common
Constraints that {{I-D.draft-mcguinness-oauth-mission-resource-access}}
defines for `mission_resource_access`), and the collision-resistant
deployment extensions the AS understands ({{extensibility}}).
Authority is further bounded by the Intent's structured members
(`target_resources`, `expires_at`), by the configured mapping (a
lookup over structured values, not an interpretation of prose), and
by local policy and eligibility. The approval surface renders the
prose beside the derived Authority Set ({{approval-event}}) as the
human check that the structure matches the words, not as a machine
enforcement mechanism.

Derivation is governed by local policy and is not a portable
algorithm: different authorization servers can derive different
Authority Sets from the same Mission Intent, as they can grant
different authority for the same {{RFC9396}} request or the same
scope. Interoperability begins at the derived Authority Set, whose
structure and vocabulary each supported type defines
({{other-types}}), and at its integrity anchors
({{integrity-anchors}}). A consumer enforces the derived Authority
Set, not the Intent, and audit establishes what was derived, against
`intent_hash` and `policy_version`, not whether the derivation was
the right reading of the task. A deployment whose partners reason
about its derivations can publish a derivation policy identifier and
test fixtures that pin Intent-to-Authority-Set outcomes; the policy
itself is not conveyed.

For an open-ended task whose concrete objects cannot be enumerated at
approval (for example, "reconcile this customer's ledger," where the
individual invoices are not yet known), bounding the derived
authority by `constraints` that hold as invariants over those
objects (the owning customer, the tenant, an amount ceiling,
read-only except named write actions, a validity window) is
preferable to an exhaustive `resource` enumeration. The runtime layer
({{runtime-boundary}}) checks each concrete object against the
constraint at the point of use.

`mission_resource_access` is defined by the Mission Resource Access
Profile ({{I-D.draft-mcguinness-oauth-mission-resource-access}}); the
Authority Set carries it on the same type-agnostic terms as any
supported type ({{other-types}}).

The following is an example of an Authority Set. The read entry is
delegable to depth 2 and bounded to a Q3 issuance window by the
`resource_issued_after` and `resource_issued_before` Common
Constraints ({{I-D.draft-mcguinness-oauth-mission-resource-access}});
the write entry carries no `delegation` and so is non-delegable,
because `delegation` is per entry:

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

A derived `authorization_details` entry is a subset of a reference
entry when it is no broader under the subset relation the entry's
own type defines; {{other-types}} states the general rule and each
supported type defines its own relation (for `mission_resource_access`,
{{I-D.draft-mcguinness-oauth-mission-resource-access}}). The AS MUST
refuse to derive an entry that is not a subset, under its type's
relation, of some Mission Authority Set entry.

The AS MUST refuse a request that would widen authority under a
Mission after the approval event on any dimension (a new resource,
action, actor, delegation path, longer duration, or constraint
relaxation); broader authority requires a fresh approval event,
either a new Mission or a successor
({{I-D.draft-mcguinness-oauth-mission-expansion}}).

The comparison is representational, not semantic. A candidate that
compares as no broader can still permit effects the parent's purpose
never contemplated, because narrowing is judged over the entry's
members, not over meaning; semantic narrowing is not a property this
rule can provide. Where the comparison relation cannot decide (an
unrecognized member, an incomparable value), the posture is
conservative refusal, as each consuming rule of this document states.

An entry equal to its reference entry, byte-identical under the
canonical form of {{canonicalization}}, is a subset of it for every
type. This is the one case the subset rule decides without the type's
own relation, and it is how an AS that has not declared `narrowing`
for a type establishes a subset ({{other-types}}).

## Authorization Details Types {#other-types}

The Authority Set MAY include any AS-supported {{RFC9396}}
`authorization_details` type an audience consumes; this document
defines no type itself. ("Supported" here means the AS recognizes
and documents the type: it appears in
`authorization_details_types_supported` or, where the AS advertises
the schema endpoint, as a key in its
`authorization_details_types_metadata_endpoint` response, then the
source of truth for the supported set ({{discovery}}).) The Mission
apparatus is type-agnostic toward every supported type:

- an entry is committed by `authority_hash` and gated on Mission state
  the same way regardless of type;
- narrowing and delegation use the subset and delegation semantics
  the type defines ({{subset}}, {{delegation-constraints}}), under
  the transformation capabilities the AS declares for the type
  (below);
- evaluating the entry against a concrete request is the runtime
  layer's responsibility ({{runtime-boundary}}), not the AS's.

The subset rule is fully defined only for a type whose specification
defines it. For every supported type, the AS declares three
independent transformation capabilities; understanding one
establishes none of the others:

- **narrowing:** the AS understands the type's subset relation;
- **delegation:** the AS understands the type's delegation
  semantics; and
- **projection:** the AS establishes a safe scope projection for the
  type ({{scope-projection}}).

The AS MUST NOT narrow, delegate, or project to `scope` an entry of
a type for which it has not declared the corresponding capability;
on an undeclared capability the entry is carried as approved.
Issuing an entry to an audience other than its original approved
audience, including audience projection to a Resource AS
({{I-D.draft-mcguinness-oauth-mission-cross-domain}}), counts as
narrowing and needs `narrowing`, not `projection`. Without
`narrowing`, the AS MUST NOT issue an entry to any audience other
than its original approved audience, or, except as `scope` under a
declared `projection`, in any form other than exactly as approved,
since it cannot prove that a transformed copy is still a subset of
what was approved. A type that declares `delegation` without
`narrowing` is delegable only unchanged: the AS MUST NOT include an
entry of such a type in a delegated token unless it is equal
({{subset}}) to an entry of the presented delegating token, it keeps
that entry's approved audience, and the type's delegation policy
permits the delegate ({{delegation-constraints}}). The reference is
the presented token, not the Mission Authority Set, so equality never
restores an entry, or any part of one, that the presented token omits.

The AS declares the capabilities through these carriers, in order of
preference:

1. a `mission_transformation_capabilities` member in the type's
   entry in the `authorization_details_types_metadata_endpoint`
   response, where the AS advertises that endpoint ({{discovery}});
2. an equivalently shaped member of its supported-type
   documentation; or
3. deployment documentation naming the type as supported
   ({{discovery}}).

Deployment documentation is always a sufficient carrier; a
machine-readable carrier is additive. A
`mission_transformation_capabilities` value is a JSON object with
three OPTIONAL boolean members, `narrowing`, `delegation`, and
`projection`; an absent member leaves that capability undeclared by
this carrier, falling through to the next carrier in the order
above.

Type-agnosticism lets policy-language profiles compose without this
document defining them: for example, an entry carrying a Cedar
policy set ({{I-D.draft-cecchetti-oauth-rar-cedar}}), or an
analogous AuthZEN policy entry, for an audience that evaluates it,
alongside a general-purpose type such as `mission_resource_access`
({{I-D.draft-mcguinness-oauth-mission-resource-access}}). The AS
derives such an entry from the Mission Intent and bounds it by the
Intent like any other, but does not interpret the carried policy
beyond its type's declared capabilities; the resource server or
Policy Decision Point (PDP) evaluates it at request time.

The following is an example of an Authority Set with a Cedar policy
entry for a finance audience that consumes Cedar, alongside a
`mission_resource_access` entry for a calendar audience that does
not. The Cedar `policySet` is abbreviated:

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
or delegation rule over policy sets, the AS carries the Cedar entry
as approved, so it does not appear in a delegated token or
cross-domain grant. Delegation controls on other entries, such as
the `mission_resource_access` entry, apply to those entries only.

Invoking a Model Context Protocol tool or a function call is modeled
as a `mission_resource_access` entry with no separate type; the
mapping is specified in
{{I-D.draft-mcguinness-oauth-mission-resource-access}}.

# Mission Approval {#approval-event}

The approval event is the atomic, adjudicated transition that creates
a Mission under its approval basis (`approval_basis`,
{{mission-record}}). Every Mission is created at its own approval
event, which the record's `approval_event_id` identifies. A `direct`
approval event includes the Approver's contemporaneous consent: it is
a human approval event. Under a standing-consent basis
({{standing-consent-bases}}), the instance is decided under an
accountable human's earlier approval, with no fresh human approval.
The approval basis and its adjudication semantics, not the event
alone, establish whether a human decided at that instant.

The direct realization runs as an OAuth 2.0 {{RFC6749}}
authorization-code flow initiated from the PAR-issued `request_uri`
({{submission-via-par}}). Because the authorization code
is the artifact the Mission grant binds to ({{grant-binding}}) and it
passes through the front channel, the AS MUST bind the code to the
requesting client with PKCE ({{RFC7636}}, `S256` challenge method)
or, equivalently, issue a DPoP-bound authorization code ({{RFC9449}}).
Redemption is then verified as {{Section 4.6 of RFC7636}} or
{{Section 10 of RFC9449}} specifies. This prevents
authorization-code injection from yielding the Mission grant.

The AS SHOULD include the `iss` authorization-response parameter
({{RFC9207}}) on the authorization response, so the client can detect
a mix-up attack on the consent-bearing redirect leg ({{RFC9700}}).

At a direct approval event the AS MUST, in order:

1. Authenticate the Approver, subject to the approval-authentication
   floor and any client-requested strength
   ({{approval-authentication}}). The AS MUST NOT take the Approver's
   identity or achieved authentication context from unauthenticated
   client input; the authenticated surface that resolved the approval
   establishes both.
2. Establish the Subject: the principal the task is for, recorded as
   the Mission's `subject` and mapped to the `sub` of every derived
   token ({{mission-bound-tokens}}). The Subject can be a workload or
   organizational principal ({{authority-sources}}), established and
   mapped the same way.
   - **Self-approval.** When the Approver is the Subject, the Subject
     is the authenticated Approver.
   - **Approval for another principal.** When the Approver is a
     different principal (for example, an administrator approving on
     a user's behalf), the AS MUST NOT take the Subject from
     unauthenticated client input, and MUST authorize the Approver to
     approve for that Subject under local policy. This document
     defines no wire parameter for the Subject; how the AS establishes
     it (administrative selection, a directory, an authenticated
     reference) is a deployment matter.
   - **External Subject.** When the Subject's home issuer
     (`subject.iss`) differs from the AS, the AS MUST map the external
     (`subject.iss`, `subject.sub`) pair to an AS-local `sub` under an
     injective mapping (no two distinct external Subjects map to the
     same local `sub`). A derived token's (`iss`, `sub`) pair then
     denotes exactly one Subject. Adopting the external `sub` verbatim
     is valid only where it collides with no other principal's `sub`.
3. Establish the authority source: whose authority the approval
   draws on, recorded as the Mission's `authority_source`
   ({{authority-sources}}, {{mission-record}}). The AS MUST establish
   it from trusted configuration or authenticated governance state,
   never from client assertion. The AS MUST verify the Approver is
   authorized under local policy to activate the established source,
   and MUST verify the derived Authority Set lies within that
   source's authority (for `organizational`, within the governed
   policy identified by `authority_source.policy`). These are
   distinct checks: an organizational owner may be authorized to
   activate policy without personally holding every operational
   permission. The AS MUST refuse when either relationship cannot be
   established.
4. Establish the effective Mission expiry: the requested
   `intent.expires_at` ceiling narrowed by applicable AS policy and
   any ceiling an applicable Mission-creating profile defines. The
   value is bounded as `expires_at` requires ({{mission-record}}) and
   is rechecked at the creation commit (step 7).
5. Render for consent the derived Authority Set in human-meaningful
   terms, with the `goal`, `task_bounds`, and the effective
   `expires_at` (and, when it differs, the requested
   `intent.expires_at`, so the Approver sees the narrowing) as
   context:
   - The consent object is the **derived Authority Set**, what the
     agent may do, not the `goal` or Mission Intent: derivation is
     local policy, and nothing commits that the derived authority
     reflects the goal the Approver read. An approval surface that
     renders only the `goal`, `success_criteria`, or Mission Intent
     does not conform.
   - When the Approver is not the Subject, the rendering MUST
     identify the Subject the authority is granted for.
   - The rendering MUST identify the authority source and, for
     `organizational`, the governed policy it draws on
     (`authority_source.policy`).
   - When the client submitted an authority proposal
     ({{authority-proposal}}), the rendering MUST distinguish the
     entries the client proposed from any narrowing or restructuring
     the AS applied.
6. Compute the integrity anchors ({{integrity-anchors}}):
   `authority_hash` over the consented Authority Set, `intent_hash`
   over the approved Mission Intent, and, when an authority proposal
   was submitted ({{authority-proposal}}), `proposal_hash` over the
   submitted `authorization_details` array.
7. Create the Mission Record ({{mission-record}}) in the `active`
   state, atomically with issuance of the authorization code. The
   commit MUST verify atomically that the effective expiry is
   strictly later than the creation instant: acceptance of the
   submission does not freeze time, and where the requested ceiling
   passed while the approval was pending, completion creates no
   Mission. A deferred or relocated approval flow ({{extensibility}})
   inherits this check at its own creation commit, with the
   completion error each flow defines.

The `authority_hash` is the **authority commitment**: it commits, by
cryptographic digest, exactly the authority the Approver approved.

Every Mission is rooted in an approved authorization basis
(`approval_basis`, {{mission-record}}). The steps above define the
`direct` basis; a companion profile that relocates a direct approval
keeps them unchanged ({{extensibility}}). Under a standing-consent
basis ({{standing-consent-bases}}), the standing consent and the
instance's adjudication supply the human decision: the Approver's
authentication (step 1), the Approver's authorization for the Subject
and the authority source (steps 2 and 3), and the consent rendering
(step 5). The other creation rules still bind the instance's approval
event wherever they apply: the Subject is never taken from
unauthenticated client input and is mapped injectively (step 2), the
authority source and its ceiling ({{authority-sources}}), the
effective expiry and its creation-commit check (steps 4 and 7), the
integrity anchors (step 6), and atomic creation deduplicated on
`approval_event_id` ({{mission-record}}).

Refusals follow {{error-mapping}}. A token-endpoint `resource` value
outside the Authority Set is an invalid `resource` value in the sense
of {{RFC8707}}.

The consent rendering is hardened against client text:

- Client-supplied strings (`goal`, `task_bounds`,
  `success_criteria`) MUST be rendered as inert text and MUST NOT be
  interpreted as markup.
- The AS SHOULD mitigate Unicode direction-override and
  confusable-character presentation in them.
- The rendering MUST visually distinguish the AS-derived Authority
  Set from client-supplied text, so crafted client text cannot pass
  as derived authority.

Rendering a bound is not the same as enforcing it: a deployment MUST
NOT present a rendered bound as enforced when no party enforces it.
Which party enforces each bound, and what holds when that enforcer is
absent, is summarized in the enforcement table ({{rs-enforcement}}).
An AS SHOULD make clear to the Approver which rendered bounds its
deployment actually enforces, so consent is not given to a limit that
binds nowhere.

If any of the following changes between approval rendering and the
approval decision, the AS MUST recompute the affected values and the
anchors the Mission records, and MUST NOT create the Mission without
the Approver's consent to the changed context:

- the task or the authority proposal;
- the derived Authority Set;
- the established authority source ({{authority-sources}});
- the effective `expires_at`; or
- a policy input establishing any of them.

Each anchor (`intent_hash`, `authority_hash`, and `proposal_hash`
where a proposal was submitted) is computed over the context actually
approved. Because the proposal is committed separately, a proposal
swapped between rendering and decision changes `proposal_hash` even
where `intent_hash` is unchanged.

## Approval Comprehension {#approval-comprehension}

The approval event commits the Mission Intent and Authority Set the
AS records as approved. Those commitments establish neither that the
AS rendered them faithfully nor that the Approver understood them
({{consent-binding}}). Step 5 of {{approval-event}} requires
human-meaningful rendering; comprehension cannot be inferred from an
approval or its integrity anchors.

A short task can legitimately have a large or varied Authority Set:
an erasure request whose proposal or configured lookup
({{authorization-derivation}}) yields dozens of delete entries across
resources. The consent object remains the complete derived Authority
Set. The following non-normative practices can help make it
reviewable:

- **Group** entries by resource and action, so the Approver reviews
  kinds of authority rather than a list of entries, while keeping
  material differences in constraints visible: a group of identical
  actions still shows an entry whose resource range or consumption
  bound is much broader than the rest.
- **Summarize with drill-down**: a summary covering every resource,
  action, and bound, with each complete entry one interaction away. A
  summary is a view of the set, never a substitute for it.
- **Surface high-risk entries**: make the irreversible,
  external-commitment, privileged-administration, and
  consumption-bounded authority of {{approval-authentication}}
  prominent in the initial view, distinguishing materially different
  risks and bounds.
- **Split rather than approve**: when the set is too large or varied
  for one decision, narrower Missions can keep each approval
  meaningful ({{applicability}}).

Mission Consent Evidence
({{I-D.draft-mcguinness-oauth-mission-consent-evidence}}) defines
layered rendering of a committed disclosure, including what its first
layer carries, and lets the Approver ask the basis for an entry before
deciding.

## Authority Sources {#authority-sources}

A Mission draws its authority from one of three sources: a delegating
person's own authority (**user-delegated**), a workload's own
provisioned authority (**service-owned**), or explicitly governed
organizational policy with a named accountable owner
(**organizational**). The source names whose authority the approval
draws on, recorded immutably as the Mission's `authority_source`;
`approval_basis` records how drawing on it was activated
({{mission-record}}), and the two compose: any source may activate
under the `direct` basis or a standing-consent basis a companion
defines. Approval activates authority the source already
holds and manufactures none: the AS establishes the source and
verifies the derived Authority Set against it before approval
({{approval-event}}).

The subject-representation discipline is the same in every source:

- The accountable principal is the record's `approver`, equal to
  `approval_basis.consent_principal`, in every source; it is never
  inferred from the token `sub`.
- `sub` carries a delegating person only in the user-delegated
  source. A service-owned or organizational Mission MUST record the
  workload or organizational principal as `subject` and MUST NOT
  record a human principal in its place. The injective mapping of
  {{approval-event}} applies unchanged: that principal receives its
  own AS-local `sub`, denotes itself, and impersonates nobody. It
  MUST be an authorization subject the AS recognizes as a resource
  owner in its own right (the `sub` model of {{RFC9068}}), not only
  the task's beneficiary.
- The actor model does not vary by source: `client_id` names the
  Agent, and delegates are carried in the `act` chain
  ({{delegation}}).

## Approver Authentication Strength {#approval-authentication}

A deployment publishes a statement declaring the minimum
approval-authentication strength (the approval-authentication floor)
it enforces for Missions whose derived Authority Set carries high-risk
authority (irreversible, external-commitment, or
privileged-administration actions under the deployment's
classification, or a consumption bound
({{I-D.draft-mcguinness-mission-metering}})) and the deployment scope
it applies to. This document requires no particular serialization.

For the direct flow, a client MAY additionally request an
approval-authentication strength on the authorization request using
the `acr_values` and `max_age` parameters defined in Section 3.1.2.1
of {{OpenID.Core}}. In a Mission approval interaction these
parameters describe the requested authentication of the
**Approver**, not of the token's Subject, who can be a different
principal ({{approval-event}}, step 2). Requesting them implies
nothing about the authentication claims of an issued token, which
describe the token's Subject, not the Approver
({{mission-bound-tokens}}); when the Approver is the Subject, one
authentication event can back both.

The Approver's authentication satisfies `acr_values` when it matches
any one listed value under the deployment's own policy mapping (this
document defines no global ordering of `acr` values); `max_age`
bounds the elapsed time since that authentication.

Approval authentication for a high-risk Mission MUST satisfy both the
published floor and, where the client requested one, the
`acr_values`/`max_age` carriage above; the floor is never relaxed by
a narrower or absent client request.

An authorization request whose `scope` includes `openid`
{{OpenID.Core}} asks for an ID Token about the End-User the approval
interaction authenticates, who is the Approver. When the Approver is
not the Subject established at step 2 of {{approval-event}}, the AS
MUST refuse such a request, without creating the Mission, with the
`invalid_scope` error code ({{Section 4.1.2.1 of RFC6749}}). When the
Approver is not the Subject, whether or not `openid` was requested,
the AS MUST NOT issue an ID Token, serve UserInfo, or establish an
authentication session for the Subject solely as a result of the
Approver's authentication or approval.

When the Approver is the Subject, `openid`, `acr_values`, and
`max_age` keep their {{OpenID.Core}} meaning, which then describes the
same authentication this document requires. In every approval
interaction, `prompt`, `login_hint`, and `id_token_hint` concern the
Approver.

The authentication actually achieved for the approval event (`acr`,
`amr`, and `auth_time`, in the sense {{RFC9470}} and {{OpenID.Core}}
define them) is approval-time provenance, not requested Intent: this
document never records it as, and an AS MUST NOT read it back from, a
Mission Intent member. Where a deployment records Consent Evidence,
the achieved values belong in its `authentication_context` member
({{I-D.draft-mcguinness-oauth-mission-consent-evidence}}); this
document defines no Mission Record member for them. A derived access
token carries authentication claims only as authentication information
about its own Subject ({{mission-bound-tokens}}), never as evidence of
approval.

## Binding the Mission to the Grant {#grant-binding}

A Mission is independent of any OAuth grant: it is identified
globally by the pair (`issuer`, `id`) ({{mission-record}}), and it
can be approved, tracked, and terminated with no OAuth grant at all.
Where this document derives a Mission through OAuth, it relates the
Mission to OAuth in two distinct ways: the **Mission grant binding**,
defined below, and the `mission` claim a derived token carries as its
own Mission reference ({{mission-claim}}).

The Mission grant binding is an AS-controlled, functional mapping
from one persistent, redeemable **grant lineage** to exactly one
Mission. A grant lineage is state the AS can resolve again on a
later request: the authorization code issued at approval and, where
its redemption emits one, the refresh-token family that follows it;
or another profile-defined reusable grant, such as a refresh-token
family a continuation transport establishes later for the same
Mission ({{I-D.draft-mcguinness-oauth-mission-continuation}}). The
AS alone establishes and resolves a binding; a client never supplies
or negotiates one.

At a direct approval event the AS binds the Mission to the
authorization code it issues. The binding is server-side and is what
"the referenced Mission" in {{lifecycle}} refers to. The code itself
carries no refresh-token family: only a successful redemption
produces one, and where it does, the resulting refresh-token family
inherits the code's binding atomically with its issuance, extending
the same Mission grant binding rather than starting a second one. At
each subsequent derivation the AS resolves the Mission from the
grant the client presents:

- the authorization code at the token endpoint;
- the refresh token on refresh; or
- the Mission-bound `subject_token` on Token Exchange (the
  `actor_token` identifies the delegate, {{delegation}}).

It then applies the gating of {{lifecycle}}.

A Mission MAY carry zero or more grant bindings. Beyond the
authorization-code lineage established at approval, a refresh-token
family a continuation transport establishes later (above) is a
further binding, rooted in the Mission its own `subject_token`
resolved to.

The AS MUST resolve a bound grant lineage to the same Mission on
every derivation performed against it: the mapping is fixed for the
lineage's lifetime and is never reassigned to a different Mission.
The AS resolves a lineage from the grant itself, and no client input
names its Mission. An AS that finds a lineage resolving to more than
one Mission fails closed on that lineage.

Where a profile-defined operation lets a client present a Mission
identifier alongside a credential, the identifier is a
non-authoritative cross-check: the AS MUST verify it against the
Mission the credential resolves to and refuse a mismatch with the
`invalid_grant` error code. The `predecessor` parameter of
{{I-D.draft-mcguinness-oauth-mission-expansion}} is an example: it
selects the Mission a successor is created from and does not reassign
an existing binding.

The grant binding relates to other mechanisms as follows:

- **Token Exchange.** A Token Exchange derivation ({{RFC8693}}) that
  returns only an access token establishes no new grant lineage:
  ordinary in-Mission delegation ({{delegation}}) and self-exchange
  down-scoping ({{self-exchange}}) both work this way, and the issued
  token is a derived token ({{mission-claim}}) whose `mission` claim
  identifies the one Mission its `subject_token`'s binding resolved
  to. A Token Exchange that instead establishes reusable
  authorization state, such as the continuation profile's
  delegation-family-creating exchange
  ({{I-D.draft-mcguinness-oauth-mission-continuation}}), creates a
  new grant binding, rooted in that same Mission.
- **Cross-domain projection.** A cross-domain projection
  ({{I-D.draft-mcguinness-oauth-mission-cross-domain}}) establishes
  no destination-side grant binding. The cross-domain grant a
  Resource AS consumes is single-use and confers no standing
  authority in the partner domain, and the local access token it
  mints there is a derived token: it identifies the one originating
  Mission (`mission.id`, `mission.issuer`) but is not backed by a
  persistent local lineage. A Resource AS that needs the projected
  Mission again is presented a fresh cross-domain grant.
- **Child Missions and successors.** A Child Mission
  ({{I-D.draft-mcguinness-oauth-mission-child-delegation}}) and an
  expansion successor
  ({{I-D.draft-mcguinness-oauth-mission-expansion}}) are new
  Missions. Any grant binding or derived token they carry is their
  own under this section's rules, not an extension of the origin
  Mission's binding. They relate to their origin only by lineage (the
  child's `parent` member, the successor's `predecessor` member).
- **Continuation handles.** A continuation handle and a
  refresh-token family
  ({{I-D.draft-mcguinness-oauth-mission-continuation}}) are
  credential machinery rooted in one Mission, not the Mission
  itself: they confer no authority of their own, and a live
  derivation re-resolves the reference they carry against the
  Mission's current state.

A grant binding is also distinct from a decision-time runtime join,
such as the Mission Join of
{{I-D.draft-mcguinness-mission-authority-server}}, in which a Policy
Decision Point joins an ordinary OAuth credential to a Mission per
request. The same credential can be joined to different Missions
across separate requests where its subject and client are eligible
for more than one. Such a join is not a Mission grant binding: it
does not make the joined OAuth grant Mission-bound, and it rests on
its own authenticated inputs and evidence, never on this section's
binding.

Non-active state gates every future derivation across every binding
this section defines ({{issuance-gating}}). It does not itself
revoke an OAuth grant the same client or subject holds outside any
Mission binding, and it does not recall an access token already
issued before its `exp` absent a runtime state check the token's
consumer performs ({{revocation}}, {{introspection}}).

An issuer that needs to cascade a lifecycle operation, or to
enumerate a Mission's bound grant lineages and credentials, maintains
its own issuer-side index from the Mission to each binding; a Mission
Management companion
({{I-D.draft-mcguinness-oauth-mission-management}}) can standardize
that index's wire surface.

Because the grant, not the identifier, determines the Mission, a
client does not supply `mission_id` to obtain a derivation, and an AS
MUST NOT derive Mission-bound authority from a client-supplied
`mission_id`.

When the authorization code expires unredeemed, no derivation is
possible under the Mission regardless of which lifecycle outcome
follows. The deployment either revokes the Mission or lets it reach
`expired` at `expires_at`, and applies one choice consistently; both
outcomes are terminal ({{lifecycle}}), so reprocessing the same
timeout changes nothing.

A client learns its `mission_id` from the `mission` claim's `id` on
each issued token ({{mission-claim}}) or from the token response.
This document defines `mission_id` as a token-endpoint response
parameter: a string carrying the Mission Identifier, returned
alongside the issued token. An AS SHOULD return it, because a client
need not parse the access token and cannot read the `mission` claim
of a token that is encrypted or opaque to it. It is an informational
reference only: presenting it authorizes nothing ({{lifecycle}}), and
a client MUST NOT derive authority from it.

Alongside it, this document defines `mission_expires_at`: the exact
RFC 3339 string recorded as the Mission Record's effective
`expires_at` ({{mission-record}}), the common member of every
Mission-creating success response, whatever surface completes the
creation. The success response that first delivers a newly created
Mission's identifier or credential MUST carry it, and a Mission-bound
token response SHOULD carry it beside `mission_id`: `expires_in`
describes the access token's lifetime, not the Mission's, and the
effective expiry can be shorter than the requested
`intent.expires_at`.

A creation replay deduplicated under the applicable operation
identifier (`approval_event_id` for direct approval
({{mission-record}}), or the identifier a Mission-creating profile
defines) returns the committed effective value unchanged. On OAuth
token responses the member is additionally registered as a
token-endpoint response parameter ({{iana}}). It is informational in
the same way: presenting it authorizes nothing.

## Single Accountable Approver {#multi-party-approval}

This document records exactly one `approver`: the accountable
principal who approved the Mission. Two richer patterns are outside
the scope of this document:

- **Multi-party approval** (M-of-N or dual control), where more than
  one principal must approve. The number of approvers does not change
  the authority commitment: principals approving the same rendered
  Authority Set produce the same `authority_hash` and the same
  derived tokens. A deployment requiring dual control records one
  accountable Approver; this document does not represent the
  co-approvers.
- **Approval-authority provenance**: the standing behind a delegate's
  authority to approve for another principal (for example, whether
  an administrator was entitled to approve on a user's behalf). This
  is governance state about the delegate, not the standing-consent
  basis that `approval_basis` records ({{mission-record}}).

Where a deployment needs either, the Approval Governance Record
({{I-D.draft-mcguinness-mission-approval-governance}}) records it,
and Consent Evidence can carry a partial presentation of that record
through `co_approvals` and its approval-governance members
({{I-D.draft-mcguinness-oauth-mission-consent-evidence}}). The
`adjudication.governance_record` member ({{mission-record}}) marks an
approval such a record backs, and {{role-mapping}} shows how each
scenario assigns the three `approval_basis` roles.

# Mission Record {#mission-record}

A Mission is the durable record created at the approval event. Its
members are immutable after creation except for its `state`, and it
is identified by a Mission Identifier ({{mission-id}}).

Record members do not repeat the `mission` prefix, because the record
itself is the Mission; prefixed names, such as the `mission_intent`
request parameter and the `mission_id` response parameter, belong to
surfaces that reference a Mission from outside it. Member names are
spelled out (`issuer`, `expires_at`, `created_at`) and spelled
identically on every surface; the compact JWT names (`iss`, `exp`,
`iat`) describe a signed artifact's own envelope, or identify a party
in an `{iss, sub}` object, not the Mission.

Like the `mission` claim ({{mission-claim}}), the record is open
({{extensibility}}): a companion profile of this document MAY record
additional members set at creation using short names coordinated with
it (for example, a lineage member linking the Mission to a
predecessor or parent); any other extension MUST use
collision-resistant names. The members below are the ones this
document defines:

`id`:
: REQUIRED. A string. The canonical Mission Identifier
  ({{mission-id}}).

`issuer`:
: REQUIRED. A string. The issuer URL of the Mission Issuer that
  approved the Mission. Equals the `iss` of tokens that AS derives;
  for cross-domain tokens it remains the issuer AS that approved the
  Mission even though the issuing `iss` differs
  ({{I-D.draft-mcguinness-oauth-mission-cross-domain}}).

`state`:
: REQUIRED. A string. The current lifecycle state: `active`,
  `revoked`, or `expired` in this document, or an additional state
  defined by a companion profile, subject to the forward-compatibility
  rule of {{lifecycle}}.

`intent`:
: REQUIRED. An object. The approved Mission Intent.

`proposed_authority`:
: REQUIRED when the client submitted an authority proposal
  ({{authority-proposal}}), absent otherwise. An array: the submitted
  `authorization_details` array, recorded exactly as submitted. A
  Mission derived in configured-mapping mode
  ({{authorization-derivation}}) records none.

`authority_set`:
: REQUIRED. An array. The consented Authority Set.

`authority_hash`:
: REQUIRED. A string. The authority commitment over the Authority Set
  ({{integrity-anchors}}). It is not carried on the baseline `mission`
  claim ({{mission-claim}}).

`intent_hash`:
: REQUIRED. A string. The integrity commitment over the approved
  Mission Intent ({{integrity-anchors}}), making the recorded task
  tamper-evident.

`proposal_hash`:
: REQUIRED when `proposed_authority` is present, absent otherwise. A
  string. The integrity commitment over the recorded
  `proposed_authority` ({{integrity-anchors}}). It is approval-time
  provenance, not enforcement input, and is not carried on the
  `mission` claim ({{mission-claim}}).

`submission_evidence`:
: REQUIRED when the approved submission carried evidence, absent
  otherwise. An array. The verified Intent Submission Evidence facts
  ({{intent-submission-evidence}}), one element per verified entry,
  in the submission's `evidence` order so the array has one canonical
  form ({{canonicalization}}). Each element carries exactly these
  members:

  `type`:
  : The entry's evidence type.

  `artifact_hash`:
  : An integrity anchor ({{integrity-anchors}}) with `typ`
    `mission-intent-evidence` over the entry exactly as presented.

  `verified_at`:
  : An RFC 3339 timestamp of verification.

  `facts`:
  : An object holding the verified output facts the type's
    specification designates for recording, nested so type-owned
    facts cannot collide with the common members.

  `submission_evidence` is provenance, not enforcement input, and is
  not carried on the `mission` claim ({{mission-claim}}). Recorded
  facts, such as a verified consent reference, are provenance and
  policy input only; a resource domain validates them under its own
  current policy ({{third-party-data-subjects}}). No integrity anchor
  commits `submission_evidence`: its digests are only as trustworthy
  as this immutable record and do not independently prove which
  artifacts were presented at admission. A profile whose threat model
  requires that proof commits normalized provenance under its own
  anchor `typ` ({{integrity-anchors}}, {{extensibility}}).

`subject`:
: REQUIRED. An object. The Subject, an object with `iss` and `sub`.

`approver`:
: REQUIRED. An object with `iss` and `sub`. DEPRECATED compatibility
  alias for `approval_basis.consent_principal` (below), the canonical
  accountability-root name; normatively equal to it in every Mission
  this document produces. MAY equal `subject`.

`approval_basis`:
: REQUIRED. An object. The authorization basis this Mission is
  rooted in: every Mission is rooted in an approved authorization
  basis, fixed at the approval event and immutable thereafter, like
  `approver` and `subject`. This document defines the `direct` basis
  in full; a companion profile can define a standing-consent basis
  ({{standing-consent-bases}}). The members below apply to every
  approval basis, with the presence each one states. Their
  direct-approval values are described here; standing-consent
  specializations are defined in {{standing-consent-bases}}.

  `type`:
  : REQUIRED. A string: `direct`, defined in full by this document,
    or a standing-consent value that a companion profile defines
    ({{standing-consent-bases}}, which also states how a consumer
    handles an unrecognized value).

  `consent_principal`:
  : REQUIRED. An object with `iss` and `sub`. The accountable human
    (or human-accountable principal) who consented; `approver`
    carries the same value.

  `activation`:
  : REQUIRED. An object naming what activated this Mission
    instance, shaped by `type`. For `direct`: `approval_event_id`,
    mirroring the record's own `approval_event_id` (below).

  `activation_actor`:
  : REQUIRED. An object with `iss` and `sub`. Who or what triggered
    this instance. For `direct` it equals `consent_principal`: the
    Approver triggers their own approval.

  `root_commitment`:
  : REQUIRED. A string. The commitment to the consented root: an
    integrity anchor where the root is a committed object, otherwise
    the committed reference that identifies it. For `direct`, this
    Mission's own `authority_hash`.

  `adjudication`:
  : OPTIONAL. The decision mechanism that adjudicated this instance,
    present when a Mission-creating profile or deployment chooses to
    make it explicit; {{standing-consent-bases}} defines the object
    and the rule it follows for `direct`.

  `approved_at`:
  : Absent for `direct`, whose approval event carries its own instant
    ({{approval-event}}); a standing-consent basis carries it
    ({{standing-consent-bases}}).

  For `direct`, `activation.approval_event_id` MUST identify a human
  approval event ({{approval-event}}).

  `approval_basis` is provenance: neither anchor covers it
  ({{integrity-anchors}}); a profile that commits the Mission Record
  itself covers it under that profile's own anchor. Its disclosure
  through introspection follows
  {{caller-authorization-and-minimization}}. It is not carried on the
  baseline `mission` claim ({{mission-claim}}), and it MUST NOT be
  relied on to grant or widen authority wherever it does appear.

`authority_source`:
: REQUIRED. An object. The source of the authority the approval
  draws on ({{authority-sources}}), established at the approval event
  ({{approval-event}}) and immutable thereafter, like `approver` and
  `approval_basis`. Members:

  `type`:
  : REQUIRED. A string: `user_delegated`, `service_owned`, or
    `organizational`, subject to the forward-compatibility rule of
    {{lifecycle}}.

  `policy`:
  : REQUIRED for `organizational`, absent otherwise. An object with
    `id`, `version`, and `digest`: the stable reference to, and
    commitment over, the governed organizational policy the Mission
    draws on.

  `authority_source` is provenance like `approval_basis`: recorded
  alongside it, folded into neither `intent_hash` nor
  `authority_hash`, and not carried on access tokens; resource
  servers enforce `authorization_details` and do not consult it.

`client_id`:
: REQUIRED. A string. The Agent (OAuth client) that submitted the
  Mission Intent.

`policy_version`:
: REQUIRED. A string. An opaque audit correlator naming the
  derivation policy version in effect at the approval event; the
  policy itself does not travel.

`approval_event_id`:
: REQUIRED. A string. A unique identifier of the approval event, used
  as the approval idempotency key: a retried or duplicate delivery of
  the same approval decision (a replayed callback, a double-submitted
  consent form) MUST NOT create a second Mission, and the AS
  deduplicates on this identifier.

`created_at`:
: REQUIRED. A string. RFC 3339 timestamp of creation.

`expires_at`:
: REQUIRED. A string. An RFC 3339 date-time: the AS-established
  effective Mission expiry ({{lifecycle}}, {{issuance-gating}}). It
  MUST be later than `created_at` and MUST NOT be later than
  `intent.expires_at`, the requested ceiling ({{mission-intent}}).
  Shortening under applicable AS policy, or under an already-approved
  parent, predecessor, or standing-consent bound a Mission-creating
  profile defines, is ordinary narrowing of the granted lifetime, not
  Authority Set derivation; for direct creation under this document
  the only additional ceiling is applicable AS policy.

The **audit horizon** is the deployment-declared retention window for
the Mission Record and its evidence: at least the Mission's lifetime
plus a declared post-expiry period. A deployment retains a terminal
(`revoked` or `expired`) Mission's record for its audit horizon.

## Standing-Consent Bases {#standing-consent-bases}

A companion profile can generalize approval to a named standing-consent
basis, under which a template or policy activates Mission instances
against an accountable human's earlier approval, with no fresh human
approval per instance; each instance is still created at its own
approval event ({{approval-event}}). The `type` values `template`
({{I-D.draft-mcguinness-oauth-mission-template}}), `policy_drawdown`
({{I-D.draft-mcguinness-oauth-mission-child-delegation}}), and
`ceiling_drawdown` ({{I-D.draft-mcguinness-oauth-mission-progressive}})
are such bases. For a standing-consent `type`, `activation` takes the shape that
its companion profile defines, and `activation_actor` names a
dispatching or requesting party distinct from the consenting human.

An unrecognized `type`, and likewise an unrecognized
`adjudication.kind` (below), is preserved unchanged as opaque
provenance on an otherwise valid record: a consumer MUST NOT
infer or fabricate the human, policy, or Approval Governance
Record standing behind it, and MUST refuse only a profile
operation that itself requires recognized adjudication semantics
to proceed (for example, evaluating a policy-approval recency
ceiling). Unlike an unrecognized lifecycle state ({{lifecycle}}),
an unrecognized value here does not by itself invalidate or
deactivate the Mission.

A companion profile defining a standing-consent `type` MUST make its
`consent_principal` and `root_commitment` trace to an accountable
human's approval of the named standing consent, with no fresh human
approval per instance, MUST carry that approval's instant as
`approved_at`, and MUST state what the record's `approval_event_id`
carries for an instance it activates. That value identifies this
instance's approval event, never the standing approval, so a retried
activation deduplicates and each distinct activation creates its own
Mission.

`approved_at`:
: REQUIRED for every standing-consent `type`. An RFC 3339 date-time: the
instant the accountable human approved the exact consented root that
`root_commitment` commits (the template version, the drawdown policy
version), not the instant this Mission instance was activated. The
activating issuer MUST verify `approved_at` against its retained,
authenticated record of that standing consent for that exact version; it
MUST NOT accept the value as the activating request's own uncorroborated
assertion.

`adjudication`:
: A discriminated object naming the decision *mechanism*
  that adjudicated this instance: distinct from `activation_actor`
  (who triggered it) and `consent_principal` (who is accountable
  for it). Present when a Mission-creating profile or deployment
  chooses to make the mechanism explicit; where absent, the
  mechanism is still fixed by `type` and the construction rules of
  this document or a companion profile (below). Members, where
  present:

  `kind`:
  : REQUIRED. A string: `human` or `policy`, naming a decision
    mechanism, not a storage location for supporting evidence; a
    companion profile MUST NOT define a `kind` value that names a
    record, an evidence store, or the requesting or dispatching
    party. An unrecognized value is handled under the same rule as
    `approval_basis.type` (above).

  For `kind: human`: no further members; the deciding human is
  `consent_principal`.

  For `kind: policy`: `policy`, a REQUIRED object with `id` and
  `version` identifying the deciding policy or workflow. It decides
  deterministically over recorded inputs, so re-evaluating that
  `version` over them re-checks the decision. A model's output can
  be one such input, recorded with the model's identifier and
  version: it can refuse an activation or narrow the authority it
  activates, and the AS MUST NOT let it supply or widen authority. A
  model is never itself the deciding policy or workflow.

  `governance_record`:
  : OPTIONAL. A boolean. `true` when an Approval Governance Record
    is recorded for this approval event
    ({{I-D.draft-mcguinness-mission-approval-governance}}), joined
    by this Mission's own `approval_event_id`. When `true`, `kind`
    MUST equal the record's accountable assertion's own `kind`: a
    governed decision still names its mechanism, and the record
    supplies the fuller assertion set behind it, including any
    multi-assertion set, never flattened into it.

The `adjudication` member, where present, follows the basis:

- Where `adjudication` is present for `direct`, `kind` MUST be
  `human` unless `governance_record` is `true`, in which case
  `kind` instead follows the override that member defines (above).
- Where a companion profile defining a standing-consent `type`
  populates `adjudication`, `kind` MUST be `policy`, naming the
  identity and version of the policy or workflow that adjudicated
  the instance, subject to the same `governance_record` override. A
  companion profile MUST NOT flatten a policy's or an Approval
  Governance Record's assertion set into a single principal member.

**Activation policy commitment.** Where a standing-consent basis lets
a separate policy artifact adjudicate activation (a dispatch,
drawdown, or child-creation policy, rather than the consented object
itself), the object the accountable human consented to MUST carry
that policy as an activation policy reference: an object of `id` (a
string), `version` (a string), and `digest`. The `digest` is an
integrity anchor ({{integrity-anchors}}) whose `typ` is
`mission-activation-policy`, whose `iss` is the activating issuer, and
whose `value` is an object of `content_type`, the media type of the
policy snapshot, and `content`, the base64url, no-padding
{{RFC4648}} encoding of the snapshot's exact bytes. Before each
activation, the activating issuer MUST compute `digest` over the exact
snapshot it evaluates, and MUST NOT activate the instance under that
policy when the result differs; the companion profile fixes what
follows, as it does for an activation the policy does not authorize.
The issuer MUST retain each snapshot's bytes and media type for the
audit horizon ({{mission-record}}) of every Mission it activates
under that snapshot, so an auditor can reproduce the digest. Where no
separate policy artifact exists, as when child creation is
adjudicated against the approved delegation entry itself, this rule
does not apply.

**Standing-consent recency.** A deployment can declare a maximum
standing-consent age (a recency ceiling), overall or per
consequence class. Where a declared ceiling applies, the activating
issuer MUST refuse to activate an instance whose `approved_at` is
older than the ceiling. Where ceilings are declared:

- The evaluation instant is the atomic Mission-creation commit
  ({{approval-event}}), including the creation commit of a
  deferred or relocated flow. Recency is issuance-time eligibility
  only: a later change to a ceiling, or the passage of time past
  one, does not terminate an active Mission ({{revocation}}).
- The activating issuer MUST refuse an `approved_at` later than
  the evaluation instant by more than the deployment's declared,
  bounded clock-skew allowance.
- Where ceilings are declared per consequence class, the issuer
  MUST classify the committed Mission from the derived Authority
  Set and from any consumption bound the Mission Intent carries
  (for example, {{I-D.draft-mcguinness-mission-metering}}), and
  MUST apply the strictest ceiling across every class present.
- The ceilings and the skew allowance belong to the versioned
  policy that `policy_version` identifies, or to a separately
  versioned declaration retained with it, so an auditor can
  reproduce the eligibility decision.

## Mission Identifier Format {#mission-id}

A Mission Identifier is an opaque URL-safe ASCII string of
`[A-Za-z0-9_-]` characters, with at least 128 bits of entropy,
carrying no semantic content. The AS MUST NOT reuse a Mission
Identifier. The record and the `mission` claim carry it as `id`; a
surface that references a Mission from outside carries it as
`mission_id`, as in the token-response parameter ({{grant-binding}}).

## Worked Example {#worked-example}

The following is an example of a Mission Record.

~~~ json
{
  "id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
  "issuer": "https://as.example.com",
  "state": "active",
  "intent": { "goal": "Reconcile Q3 invoices ...",
    "target_resources": ["https://erp.example.com"],
    "expires_at": "2026-12-31T23:59:59Z" },
  "proposed_authority": [
    { "type": "mission_resource_access",
      "resource": "https://erp.example.com",
      "actions": ["invoices.*"],
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
  "proposal_hash":
    "sha-256:kT2mR7vX4qL9nY5pB1sD8fJ6wZ3hC0aGeUoNvSqMrYo",
  "subject": { "iss": "https://idp.example.com",
    "sub": "user_3p2q8mN1a0kV7tR" },
  "approver": { "iss": "https://idp.example.com",
    "sub": "user_3p2q8mN1a0kV7tR" },
  "approval_basis": {
    "type": "direct",
    "consent_principal": { "iss": "https://idp.example.com",
      "sub": "user_3p2q8mN1a0kV7tR" },
    "activation": { "approval_event_id": "ape_8K2nP4qV9rL3tY6sB1z" },
    "activation_actor": { "iss": "https://idp.example.com",
      "sub": "user_3p2q8mN1a0kV7tR" },
    "adjudication": { "kind": "human" },
    "root_commitment":
      "sha-256:l3KvZ4mP5x0wQrR6tY2nD9bM7sX1cF8gH2vJ4kE5pNQ"
  },
  "authority_source": { "type": "user_delegated" },
  "client_id": "s6BhdRkqt3",
  "policy_version": "deploy-policy:v17",
  "approval_event_id": "ape_8K2nP4qV9rL3tY6sB1z",
  "created_at": "2026-10-15T14:32:11Z",
  "expires_at": "2026-12-31T23:59:59Z"
}
~~~

The hash values above are illustrative: the test vectors
({{test-vectors}}) compute anchors over a reduced Mission Intent and
Authority Set, not over these objects. A companion that extends this
example either reproduces the recorded objects byte-exactly or states
that its example diverges and its anchors differ.

# Integrity and Commitments {#integrity-and-commitments}

The anchors the Approver consents to at the approval event
({{approval-event}}) are constructed, canonicalized, and bound by the
rules of this section; the Mission Record ({{mission-record}})
records them, and the test vectors ({{test-vectors}}) pin the
construction byte-for-byte.

## Integrity Anchors {#integrity-anchors}

Every anchor is computed the same way over a domain-separated,
issuer-bound envelope:

1. Construct the envelope, where `typ` selects the committed object
   and `value` is that object:

   ~~~
   {
     "typ": "<mission-intent | mission-proposed-authority
             | mission-authority-set | mission-activation-policy>",
     "iss": "<the AS issuer URL>",
     "value": <the committed object>
   }
   ~~~

   For `intent_hash`, `typ` is `mission-intent` and `value` is the
   approved Mission Intent object: the Submission envelope's `intent`
   member, not the envelope or its `evidence`
   ({{submission-via-par}}). For `proposal_hash`, `typ` is
   `mission-proposed-authority` and `value` is the submitted
   `authorization_details` array exactly as recorded
   ({{authority-proposal}}); the anchor is present exactly when a
   proposal was submitted. For `authority_hash`, `typ` is
   `mission-authority-set` and `value` is the Authority Set as a JSON
   array of entries. For an activation policy reference's `digest`,
   `typ` is `mission-activation-policy` and `value` is the policy
   snapshot object that {{standing-consent-bases}} defines.

2. Canonicalize the envelope with JCS {{RFC8785}}.
3. Compute SHA-256 {{RFC6234}} over the canonical bytes.
4. Encode as `sha-256:` followed by the base64url, no-padding
   {{RFC4648}} encoding of the digest.

The `typ` field domain-separates the anchors so a digest of one
object cannot be mistaken for another's. The `iss` binding prevents
a committed object from being transplanted across authorization
servers. The `sha-256:` prefix is the algorithm-agility mechanism
({{commitment-mechanisms}}).

`intent_hash` and `authority_hash` are independent commitments to
independent objects. That the approved task bounds the derived
authority is a governance assertion, made by derivation policy and
auditable through `policy_version` ({{authorization-derivation}}),
not a cryptographic relation between the anchors: neither anchor
proves anything about the other's object.

The `typ` value space is an extension point ({{extensibility}}):
additional committed objects use this same envelope with a new `typ`
and the canonicalization below. This document defines no registry of
`typ` values; each committing specification defines its own and
relies on the `typ` domain separation. To keep that domain separation
safe without a registry, a new `typ` value MUST be a
collision-resistant name (for example, a short name prefixed within a
namespace the defining profile controls, following the
Collision-Resistant Name guidance of {{Section 4.2 of RFC7519}}).
`mission-` prefixed values, used by this document and the profiles
that extend it, form a namespace coordinated through this document's
change controller.

This document also defines the **Authority Set entry commitment**, the
envelope above with `typ` `mission-authority-entry`, `iss` the
Mission `issuer`, and `value` a single Authority Set entry object
exactly as recorded ({{test-vectors}}). A companion that cites an
entry by digest (a decision record naming the entry it evaluated,
containment or completion state keyed to an entry) computes it this
way. Entries whose canonical commitment envelopes are identical
produce the same digest, and within one Mission Record every recorded
entry resolving to the same digest forms one selector equivalence
class; the class is defined by the canonical bytes, not by
pre-canonical source text the record does not preserve.

The commitment is not a globally unique entry identifier: the
envelope binds the issuer, not the Mission, so a protocol that uses
it to select or cite an entry MUST bind it to the Mission `issuer`
and Mission identifier whose recorded Authority Set is searched,
directly or through an enclosing object whose integrity protection
binds them.

`authority_hash` likewise commits an Authority Set, not a Mission:
two Missions that approve byte-identical authority share it, and a
consumer MUST NOT use it as a Mission Identifier or as a replay or
idempotency key for a Mission.

## Canonicalization Rules {#canonicalization}

JCS {{RFC8785}} alone does not make two implementations agree on
every byte. The following rules close the remaining gaps; they apply
to computing an anchor and to comparing committed values:

- The committed `value` is exactly the object the AS recorded on the
  Mission: the approved `intent` for `intent_hash`, the recorded
  `proposed_authority` for `proposal_hash`, and the `authority_set`
  for `authority_hash`. An auditor reproduces a digest from the
  record alone.
- Duplicate member names are rejected at parse time
  ({{commitment-mechanisms}}).
- JCS does not reorder array elements, and this document defines no
  element sorting, so array order is significant. The AS MUST present
  each committed array in its recorded order wherever it emits the
  committed object; that order is part of the canonical form.
- URI-valued members are compared byte-for-byte, consistent with
  {{Section 12 of RFC9396}}, unless a member's own type definition
  specifies a normalization. Where a type defines one, as
  `mission_resource_access` does for its `prefix`-match resource
  containment test
  ({{I-D.draft-mcguinness-oauth-mission-resource-access}}), it applies
  to that comparison alone: the default `resource` equality test
  remains an exact match, and anchor computation is always byte-exact
  over the recorded values.

## Commitment Mechanisms {#commitment-mechanisms}

This document's default prefixed construction commits to bytes in
three ways, and a specification defining a prefixed commitment
classifies it as one of these species:

- **Envelope anchor**: the domain-separated, issuer-bound envelope of
  {{integrity-anchors}} (`intent_hash`, `proposal_hash`,
  `authority_hash`, an activation policy reference's `digest`, and
  commitments produced with companion-defined `typ` values).
- **Canonical-object digest**: `sha-256:` over the JCS serialization
  of a normalized JSON object without the envelope, where protocol
  context already fixes what is committed (for example, a runtime
  parameter digest).
- **Raw-octet digest**: `sha-256:` over an exact,
  specification-defined octet sequence, with no canonicalization: a
  whole artifact as exchanged, or the UTF-8 encoding of a defined
  scalar value (for example, a work-product artifact digest).

The prefix and agility rules below bind all three species. The
I-JSON rule binds the two JSON species. The envelope and `typ`
discipline of {{integrity-anchors}} binds envelope anchors alone.

This section instantiates the default commitment construction of
{{I-D.draft-mcguinness-mission-substrate}}. A commitment outside this
construction (a native content address, a member-named digest whose
member name fixes the algorithm) is permitted; its defining
specification states its own algorithm identification and agility
behavior.

Every committed JSON value and its envelope are I-JSON {{RFC7493}}
data, as {{Section 3.1 of RFC8785}} requires. Strengthening
{{Section 3.1 of RFC8785}}, which adapts input to I-JSON, the party
computing or verifying a commitment MUST reject non-conformant input
before canonicalization rather than adapt it: externally received
JSON destined for commitment is parsed by a duplicate-detecting
parser, and an object carrying duplicate member names is rejected at
parse time, before the parsed data model exists.

The commitment is over the parsed I-JSON data value, not the source
text: JCS does not preserve a source lexeme's spelling or excess
precision. A profile whose values need exact decimal or large-integer
semantics carries them as strings, as {{Section 3.1 of RFC8785}}
recommends, or defines a stricter numeric domain, as the Mission
Resource Access Profile's Common Constraints do for constraint values
({{I-D.draft-mcguinness-oauth-mission-resource-access}}). The
security considerations of {{RFC8785}} apply to every JCS computation.

The algorithm prefix is the agility mechanism. `sha-256` is
mandatory to implement and the only algorithm this document defines.
A new algorithm enters only through a new prefix defined by a
referencing specification, its name drawn from the Named Information
Hash Algorithm Registry ({{RFC6920}}); this document defines no
negotiation.

A verifier MUST reject a digest whose algorithm prefix it does not
recognize, so an algorithm added later cannot be exploited as a
downgrade. These rules bind a prefixed digest of any
species when its defining specification classifies it under this
taxonomy and imports this section normatively; this document so
classifies its three anchors.

This document defines no transition mechanism: every commitment a
current carrier defines is a single prefixed string, and no carrier
defines a location for a second one. A specification that introduces
a new prefix MUST define:

1. the carrier and schema of any parallel commitment;
2. the binding that proves the old and new values commit to the same
   object;
3. producer behavior during the transition;
4. verifier selection and downgrade behavior when recognition sets
   differ; and
5. the transition procedure itself.

# Mission Lifecycle and Gating {#lifecycle}

A Mission is in one of three states:

- `active`: the only state in which the AS derives tokens.
- `revoked`: terminated by the Subject, Approver, or
  policy. Terminal.
- `expired`: `expires_at` has passed. Terminal.

The transitions are:

| From | Event | To |
|---|---|---|
| (none) | approval event | `active` |
| `active` | revoke | `revoked` |
| `active` | `expires_at` reached | `expired` |

The Mission Lifecycle States registry ({{iana-lifecycle-states}})
holds these states. A companion profile MAY register an additional
state for a lifecycle it introduces (for example, a paused or
superseded state); only `active` permits issuance.

Wherever a Mission state is reported, including the Mission Record
and the introspection `mission` member, a consumer MUST treat only
the exact value `active` as permitting derivation or continued
reliance, and MUST treat every other value, including one it does
not recognize, as non-active and non-deriving (the
forward-compatibility rule).

For every state-dependent decision this document defines, the AS MUST
treat a Mission as `active` only when its stored state is `active`
and the decision time is strictly before `expires_at`. Persisting the
`expired` transition, and emitting any lifecycle event a
state-distribution companion defines, can happen after the decision
that observed the boundary.

## Issuance Gating {#issuance-gating}

A derivation (defined below) passes these checks, each stated where
cited:

1. the Mission resolves from the presented grant ({{grant-binding}});
2. the Mission is `active` ({{lifecycle}}, and below);
3. each emitted entry is a subset of a Mission Authority Set entry
   ({{subset}});
4. any emitted `scope` meets {{scope-projection}}; and
5. each token's `exp` does not exceed the Mission's `expires_at`
   ({{mission-bound-tokens}}).

Unless the referenced Mission is `active`, the AS MUST refuse, with
the `invalid_grant` error code, a request to derive a token at the
token endpoint, on refresh, or on Token Exchange ({{RFC8693}}). The
AS MUST refuse, with the `invalid_grant` error code, a derivation
request it answers after it has acknowledged a revocation of the
Mission. Where a profile of a Token Exchange that the AS implements
assigns its own error code to either refusal, such as a continuation
profile's code for an ended chain, the AS uses that profile's code
instead of `invalid_grant`; the refusal itself, and the
`mission_error` member below, still apply.

A derivation is one issuance operation the issuer AS performs for a
single request: the initial authorization-code exchange, a refresh, a
Token Exchange, or a cross-domain grant issuance
({{I-D.draft-mcguinness-oauth-mission-cross-domain}}). A companion
profile bounds the number of derivations under a Mission
({{I-D.draft-mcguinness-oauth-mission-derivation-limits}}).

`invalid_grant` alone does not tell a client which gate refused. On a
refusal under this section the AS SHOULD include, alongside `error`,
the `mission_error` token-error-response member ({{iana}}) with one
of the values `mission_revoked`, `mission_expired`, or
`mission_superseded` (where a companion defines supersession). The
member is diagnostic only: it grants nothing, an unrecognized value is
ignored, and it is returned only to the authenticated client
presenting the Mission's grant.

Derived tokens SHOULD be short-lived so that a transition to
`revoked` or `expired` takes effect promptly without per-request
revocation checks.

## Revocation {#revocation}

A Mission is revoked when the AS receives an authorized revocation
for it. A deployment MUST provide an authenticated means for the
Subject, the Approver, or an administrator to revoke a Mission by
`mission_id`, independent of possession of any token (so a Mission
can be stopped even when no refresh token is held).

This document does not define the wire shape of that operation. A
deployment-defined authenticated surface satisfies this requirement;
Mission Status ({{I-D.draft-mcguinness-oauth-mission-status}})
defines an interoperable `revoke` operation, authorized under its own
lifecycle authorization policy.

As {{Section 2.1 of RFC7009}} permits, a deployment's revocation
policy can treat revoking a Mission's refresh token as revoking the
Mission; a deployment that couples token revocation to Mission
revocation documents that behavior.

Token validity and Mission validity are distinct: an already-issued
access token remains valid until it expires ({{issuance-gating}}), so
a token can outlive a transition of its Mission by at most the token
lifetime. Token introspection ({{introspection}}) is a
state-observable overlay that lets a resource server see Mission
state per request and cut off a revoked Mission before the token
expires; Mission Status specifies another, a status surface keyed by
`mission_id` with signed responses. A deployment whose consumers rely
on Mission state beyond a token's lifetime offers one of these, so
they read current state rather than infer it from token validity.

# Mission-Bound Access Tokens {#mission-bound-tokens}

Access tokens issued under a Mission are JWTs per {{RFC9068}}, which
fixes the required claims (including `jti`), the `at+jwt` `typ`
header parameter, and resource server validation
({{Section 2.1 of RFC9068}}, {{Section 2.2 of RFC9068}},
{{Section 4 of RFC9068}}). In addition to what that profile requires,
a derived token:

- carries the token's Mission-derived authority as
  `authorization_details` ({{RFC9396}}); this MAY be the full Authority
  Set or a narrowed subset ({{subset}});
- carries a `mission` claim ({{mission-claim}});
- sets `sub` to the AS-local `sub` the AS maps the Mission's
  Subject to ({{approval-event}});
- carries `client_id` with its ordinary meaning
  ({{Section 4.3 of RFC8693}}, {{Section 2.2 of RFC9068}}): the client
  that requested this particular token;
- MUST set `aud` to identify the resource server(s) authorized to
  consume the carried `authorization_details`, and MUST NOT include an
  audience unrelated to that carried authority (see below);
- MAY carry an `act` claim when the agent has delegated execution
  ({{delegation}});
- MAY carry a `scope` claim, subject to {{scope-projection}};
- can be sender-constrained, as {{Section 2.2.1 of RFC9700}}
  recommends, via a `cnf` claim {{RFC7800}}: DPoP {{RFC9449}}
  (`cnf.jkt`) or mTLS {{RFC8705}} (`cnf.x5t#S256`).

The primary access token may be a bearer token, preserving
compatibility with bearer-only resource servers while retaining
{{Section 2.2.1 of RFC9700}}'s recommendation; the cost is the
stolen-token exposure ({{token-theft}}).

A delegated token is sender-constrained to the delegate's own key
({{delegation}}); the cross-domain companion requires sender-constraint
for credentials that cross a trust domain
({{I-D.draft-mcguinness-oauth-mission-cross-domain}}).

This document's token-carried enforcement assumes the JWT above. An
opaque Mission-bound token is profiled only under the introspected
consumption mode ({{introspected-consumption}}), where introspection
is its claims carriage, with the same enforcement obligations. A
deployment whose AS can issue neither deploys a Mission Authority
Server ({{I-D.draft-mcguinness-mission-authority-server}}), which
governs ordinary tokens at the enforcement layer.

An AS MUST publish its token verification keys (for example, at its
{{RFC8414}} `jwks_uri`, as {{Section 4 of RFC9068}} recommends);
rotation retires a key from signing, never from resolvability while
tokens signed under it remain valid.

Every emitted `authorization_details` entry is a subset of a Mission
Authority Set entry ({{subset}}).

The AS audience-restricts the token per {{Section 2 of RFC8707}} and
{{Section 3 of RFC9068}}; `aud` names resource server(s), APIs, or
security domains, not necessarily the entries' `resource` values. The
client obtains a single-audience token ({{Section 2.3 of RFC9700}})
with the {{RFC8707}} `resource` parameter, and can narrow it further
with `scope`; the AS narrows the Authority Set under {{subset}} to the
requested resource(s) and sets `aud` accordingly.

The AS returns the granted `authorization_details` in every token
response, including refresh and Token Exchange responses
({{Section 7 of RFC9396}}). Strengthening {{Section 7 of RFC9396}},
the AS MUST NOT omit values from it: the response states exactly the
(possibly narrowed) set assigned to the issued token, and it is the
authoritative statement of what was granted, which the client
compares with its proposal ({{authority-proposal}}). The
`mission_id` response parameter carries the Mission reference beside
it ({{grant-binding}}).

The following is an example of a refresh request that narrows the
canonical ERP Mission (the worked example of {{mission-record}}) to a
read-only token with the {{RFC8707}} `resource` parameter and
`authorization_details` ({{Section 6 of RFC9396}}). The ERP consumes
`authorization_details`, so a resource `scope` for it would be refused
({{scope-projection}}) (with extra line breaks for display purposes
only):

~~~
POST /token HTTP/1.1
Host: as.example.com
Content-Type: application/x-www-form-urlencoded
DPoP: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2Iiwi...

grant_type=refresh_token
&refresh_token=rt_4mN8qV2xP7sL1tY9zB3k
&resource=https%3A%2F%2Ferp.example.com
&authorization_details=%5B%7B%22type%22%3A%22mission_resource_acc...
~~~

The `authorization_details` value, before form encoding, requests the
Mission's read entry alone:

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
    } }
]
~~~

The issuance is a derivation, gated on the Mission being `active`
({{lifecycle}}). The response carries no `scope` member because none
was requested or granted. It echoes the narrowed grant and the
`mission_id` reference ({{grant-binding}}); the emitted entry is a
subset ({{subset}}) of the Mission's read entry, its `constraints`
carried intact:

~~~ json
{
  "access_token": "eyJhbGciOiJFUzI1NiIsInR5cCI6ImF0K2p3dCJ9...",
  "token_type": "DPoP",
  "expires_in": 300,
  "mission_id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
  "mission_expires_at": "2026-12-31T23:59:59Z",
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
token rotation. This strengthens {{Section 2.2.2 of RFC9700}}, which
requires it only of public clients, because Mission-state gating does
not bound a stolen refresh token while the Mission is `active`.

A derived token's authority comes from the Mission, not from a fresh
authentication. Authentication claims (`acr`, `amr`, `auth_time`) on
a derived access token follow {{Section 2.2.1 of RFC9068}}: they
describe the token's Subject and keep the values of the
authentication event behind the grant, so derivation does not
refresh them. An AS MUST NOT use the authentication of an Approver
who is not the token's Subject as authentication information about
that Subject. These claims neither establish approval nor expand
Mission authority; the Approver's approval-time authentication remains
provenance ({{approval-authentication}}). Where no authentication of
the Subject applies, as when a human approves a Mission for another
principal or for a workload, the claims are absent, and their absence
is not an authentication downgrade.

`authorization_details` is the authoritative expression of a
Mission-bound token's authority; a `scope` claim
({{scope-projection}}) is a compatibility projection that cannot
carry per-entry `constraints`.

A credential the Mission Issuer derives MUST have an `exp` that does
not exceed the Mission's `expires_at`, so that no credential outlives
the approved Mission. How this bound extends transitively to tokens
minted in another trust domain is specified by the cross-domain
companion ({{I-D.draft-mcguinness-oauth-mission-cross-domain}}).

## Scope Projection {#scope-projection}

For every target audience, the AS MUST establish that the effective
rights the target's enforcement path grants from the projected
`scope`, together with every independently mandatory control on that
path, are a subset of the rights the token's applicable
`authorization_details` grant. This is a semantic condition, not a
structural one: it fails for a `constraints`-free entry whose `scope`
aggregates a broader action, spans more resource instances or paths
than the entry, carries rights the target's local `scope`
interpretation implies, or arises from the union of several entries,
exactly as it fails for a relaxed constraint.

To emit `scope` for an entry, the AS:

1. determines the target resource server or audience for the token;
2. resolves a trusted, versioned scope-projection mapping for that
   target, established through the target's protected resource
   metadata ({{RFC9728}}) or authenticated
   out-of-band configuration;
3. establishes, under the subset condition above, that the complete
   effective authorization the projected `scope` grants at that
   target is no broader than the applicable carried entries;
4. omits `scope` for an entry where the target's enforcement path
   consumes `authorization_details` instead;
5. MUST refuse issuance to a target that is `scope`-only when no safe
   projection exists for the applicable entries: an issued token no
   enforcement path can safely evaluate is not a usable credential;
   and
6. for a multi-audience token, establishes the condition
   independently for each audience; a single-audience token
   ({{mission-bound-tokens}}) remains preferred.

Unknown `scope` semantics, unknown resource server enforcement
behavior, or an ambiguous or stale mapping all fail closed under step
5 ({{error-mapping}}). A changed mapping is not by itself stale: the AS
evaluates each issuance, refresh included, against the target's
current trusted mapping, and a mapping is stale only when the AS
cannot establish that it is the current trusted mapping for that
target. This rule applies to every issuance path that
can emit `scope` on a Mission-bound token: initial issuance, refresh,
Token Exchange, and
any other derived-token path.

Scope projection does not change OAuth response semantics and does
not make access-token inspection a client requirement. {{Section 3.3 of RFC6749}} requires the token response to carry `scope` whenever the
granted scope differs from the requested scope, and its grammar
defines no empty scope, so an issuance cannot report an ungranted
requested value by omission. The AS MUST refuse, with `invalid_scope`
({{error-mapping}}), a request that explicitly names a `scope` value
the issuance cannot grant: a value the target's trusted mapping names
but no carried entry makes safe (step 3), or any `scope` value the AS
associates with a target that consumes `authorization_details` (step
4). An unknown, ambiguous, or stale mapping is a step 5 failure and
yields `invalid_target` even when the request also names a `scope`
value; `invalid_scope` applies only under a mapping the AS trusts.
Where the AS emits a projected `scope`, a requested `scope`
narrows it to the requested values, and the token response reports
the values granted ({{Section 5.1 of RFC6749}}). Scope values with their
own semantics, such as `openid` ({{OpenID.Core}}), are unaffected and
combine with `authorization_details` as {{Section 3.1 of RFC9396}}
permits. A Mission-creating client does not request a resource `scope`
for a target that consumes `authorization_details`; for a `scope`-only
target, a requested `scope` selects among the values the projection
can grant.

A refusal caused solely by failure to establish a safe scope
projection MUST NOT invalidate an otherwise-valid refresh token or its
authorization grant. Independent expiration, revocation, and
replay-detection rules continue to apply. An AS meets this by
establishing the projection before it consumes or rotates the refresh
token, or within the same atomic issuance, not by disabling rotation
or restoring a consumed token.

This is the type-agnostic form of the rule; a type's own
specification states when the mapping in step 3 is safe for that
type's entries (for `mission_resource_access`,
{{I-D.draft-mcguinness-oauth-mission-resource-access}}).

The runtime profile's enforcement-scope declarations
({{I-D.draft-mcguinness-mission-runtime}}) can reference the same
mapping for the paths it covers; this rule does not depend on that
profile.

## The Mission Claim {#mission-claim}

The `mission` claim is a JSON object:

`id`:
: REQUIRED. A string. The Mission Identifier ({{mission-id}}).

`issuer`:
: REQUIRED. A string. The Mission's `issuer` ({{mission-record}}). A
  credential's `iss` names the party that minted it; `mission.issuer`
  names the party that approved and serves the Mission, and the two
  differ for tokens minted in another trust domain
  ({{I-D.draft-mcguinness-oauth-mission-cross-domain}}).

`id` and `issuer` identify the Mission and carry no authority of
their own; the token's own signature authenticates the pair, and the
carried `authorization_details` remains the token's concrete
authority.

`expires_at`:
: OPTIONAL. A string. The Mission's `expires_at`
  ({{mission-record}}), in RFC 3339 {{RFC3339}} date-time form and
  named identically to the record member it mirrors. It is a bounding
  and audit commitment with no liveness: a validator can check that
  the token's `exp` does not exceed it, and its passing says nothing
  a state surface does not, since expiry is not revocation and only
  `active` permits reliance ({{lifecycle}}).

A consumer that relies only on the presented token's own validity
needs nothing further: the token's `exp` already bounds it. A profile
that mints a further credential downstream of this one, or that
verifies a Mission's remaining lifetime from retained state rather
than a live token, MUST require `expires_at` and MUST treat its
absence as an error. The token's own `exp` bounds only that one
credential, not every credential the Mission may still yield.

This document does not carry `authority_hash` or `approval_basis` on
the baseline claim. Neither is an enforcement input a narrowed-token
resource server can exercise: `authority_hash` commits the complete
Authority Set, which such a resource server does not hold
({{rs-enforcement}}); `approval_basis.type` is provenance, not
authority ({{mission-record}}). An authorized introspection caller
can receive `authority_hash` and `approval_basis.type`
({{caller-authorization-and-minimization}}).

The `mission` claim is an open object ({{extensibility}}): additional
members MAY appear alongside the members above. This document defines no
registry of `mission` members. A companion profile of this document MAY
use short member names coordinated with it; any other extension member
MUST use a collision-resistant name (for example, a name in a namespace
the extension controls, per the Collision-Resistant Name guidance of
{{Section 4.2 of RFC7519}}) and is defined by the profile that
introduces it.

A consumer MUST ignore members it does not understand and MUST NOT
use any additional member to grant or widen authority; the
members above remain authoritative.

The following is an example of a decoded Mission-bound token payload:

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
    "issuer": "https://as.example.com"
  }
}
~~~

# Resource Server Enforcement {#rs-enforcement}

A resource server enforces a JWT Mission-bound token from the token
alone; no call to the AS is required. It validates the token per
{{Section 4 of RFC9068}}, and any sender-constraint binding (`cnf`)
per {{Section 7.1 of RFC9449}} or {{Section 3 of RFC8705}}, locally
even when it introspects ({{composite-active}}). An opaque
Mission-bound token is enforced from its active introspection
response instead, under the same rules
({{introspected-consumption}}).

A resource server:

1. MUST treat `authorization_details` as the authoritative expression
   of authority and enforce each applicable entry according to that
   entry's own type specification (for `mission_resource_access`,
   {{I-D.draft-mcguinness-oauth-mission-resource-access}}). Where
   more than one carried entry applies, entries are alternative
   grants of authority, not conjunctive filters, unless the entry's
   type states otherwise.
2. MUST fail closed (refuse the request, for example, a `403` with
   the `insufficient_scope` error code {{RFC6750}}, or the
   deployment's usual insufficient-authority error) on any applicable
   entry whose type it does not implement, or whose type-defined
   enforcement it cannot complete (an unrecognized member, an
   unenforceable constraint, or an unrecognized matching mode).
3. MUST NOT, when a token also carries `scope`, grant on the basis of
   a scope value any access broader than the corresponding
   `authorization_details` entry permits, including access that
   bypasses a constraint carried only in `authorization_details`.
4. MUST NOT infer the Mission's originally-approved agent from
   `client_id`, which names the client that requested this token, on
   a delegated token or otherwise ({{Section 4.3 of RFC8693}},
   {{client-id-rebinding}}); the approved agent is recorded only in
   the Mission Record ({{mission-record}}) at the issuer.
5. MUST, when configured to require the `mission` claim for a
   Mission-governed resource, reject a token that lacks it with the
   `invalid_token` error code. The issuance-side duty that pairs with
   this rejection is stated in {{authority-proposal}}, the downgrade
   it prevents in {{downgrade-by-omission}}, and the metadata that
   advertises the requirement in {{protected-resource-metadata}}.

A resource server can also require that a token carry an `act` chain
and record it, while authorizing only the token's current actor
({{Section 4.1 of RFC8693}}); log the `mission` claim's `id` and the token
`jti` with each served request, so its access logs join to Mission
evidence; or, where the AS offers it, introspect the token
({{introspection}}) to observe Mission state per request.

A deployment MUST NOT route a delegated Mission-bound token to a
Mission-unaware resource server, or to logging or audit
infrastructure, that authorizes or logs the caller on `client_id`
without processing the `act` chain. A Mission-unaware {{RFC9068}}
resource server reads `client_id` as the immediate client, which is
accurate for that single token, but it cannot see the delegation
lineage in the `act` chain or look up the originally-approved agent
in the Mission Record, so it cannot recognize the current actor as a
delegate, record the delegation lineage, or join a delegate's action
to the Mission's approval in its audit records.

A resource that requires Mission-bound tokens can advertise that
through the `mission_bound_authorization_required` protected resource
metadata member ({{protected-resource-metadata}}); a resource server
that serves such a resource is, by that requirement, Mission-aware.

A Mission-unaware resource server that authorizes only from `scope`
operates within the Mission only to the extent the AS established a
safe projection for it at issuance ({{scope-projection}}).
Constrained authority that no safe projection carries is enforced
only where a resource server, or a runtime layer, evaluates
`authorization_details`.

A type-defined constraint narrows authority, so treating an
unenforceable key or member as absent, or reducing it to
disclosure-only, would widen the grant. This is why an entry whose
type-defined enforcement a resource server cannot complete fails
closed.

The baseline token carries no `authority_hash` ({{mission-claim}}).
Where a deployment discloses it to a resource server (through
introspection's disclosure privilege,
{{caller-authorization-and-minimization}}, or a companion profile
that carries its own copy), it is an audit correlator, not an
enforcement input, and not a cryptographic proof that the carried
entries are a subset of the approved set. That subset relationship is
an assertion by the AS, authenticated by the token signature. Mission
Approved-Set Verification
({{I-D.draft-mcguinness-oauth-mission-approved-set-verification}})
defines an independent check for a resource server that needs more
than that assertion.

A resource server denial falls into one of four cases, each using the
OAuth challenge for its own failure class ({{error-mapping}} gives
the codes):

1. **Weak or stale Subject authentication.** Where the deployment
   conveys the authentication of the token's Subject, through the
   claims of {{mission-bound-tokens}} or introspection
   ({{Section 6 of RFC9470}}), and that authentication does not meet
   the resource's requirement, the resource server challenges with
   `insufficient_user_authentication` and the `acr_values` or
   `max_age` parameters ({{Section 3 of RFC9470}}). Where no Subject
   authentication applies, the token carries no such claims and the
   challenge offers no remediation, so the resource server does not
   use it. The Subject's authentication is a distinct fact from the
   Approver's approval-time authentication; a requirement on the
   Approver is an approval floor ({{approval-authentication}}), not a
   resource server challenge.
2. **Sender-constraint or key-binding failure.** The token's proof of
   possession is missing or invalid: the resource server challenges with
   `invalid_token`, in the `DPoP` scheme for a DPoP-bound token
   ({{Section 7.1 of RFC9449}}, with `use_dpop_nonce` per
   {{Section 9 of RFC9449}}) and in the Bearer scheme for a
   certificate-bound token ({{Section 3 of RFC8705}}). This is not a
   step-up: no fresh user authentication repairs a missing or wrong
   key.
3. **Insufficient carried authority.** The action is outside the
   token's carried authority: the resource server challenges with
   `insufficient_scope` ({{RFC6750}}), or with the RAR-remediation
   challenge where {{I-D.draft-ietf-oauth-rar-metadata-remediation}}
   is deployed ({{remediation-grains}}). More authority requires a
   new approval, or an expansion where that companion is deployed.
4. **Unenforceable constraint.** An applicable entry carries a
   type-defined member or constraint the resource server cannot enforce,
   and the request fails closed under the same base error as case 3.

Cases 3 and 4 are identical `403` responses to a client, which cannot
tell from them whether a new approval would help. A Mission-aware
Resource Server SHOULD therefore indicate which of the two cases
applies by including, alongside `error` ({{RFC6750}}), the
`mission_denial` attribute that this document defines for the
`WWW-Authenticate` response header field, with one of two values:

`insufficient_authority`:
: The action is outside the token's carried authority; more requires
  a new approval or an expansion where that companion is deployed.

`constraint_unrecognized`:
: An applicable entry carries a type-defined member or constraint the
resource server cannot enforce, and the request fails closed. A client
MUST NOT treat this value as inviting retry, step-up, or fresh approval:
none of those makes a resource server enforce a constraint it does not
implement.

A value the client does not recognize is treated as
`insufficient_authority`. A resource server SHOULD include the
attribute only in a response to a validly signed, audience-correct
token whose holder its deployment accepts learning the distinction
({{denial-disclosure}}).

Every bound this document defines is enforced by a party this document
names. The following table summarizes which party enforces each bound a
Mission carries and what holds when that enforcer is absent:

| Bound | Enforced by | When that enforcer is absent |
|---|---|---|
| `resource` and `actions` | any resource server that enforces `mission_resource_access` per its type specification ({{I-D.draft-mcguinness-oauth-mission-resource-access}}, {{rs-enforcement}}) | a scope-only resource server is served only where the AS established a safe scope projection ({{scope-projection}}); the AS refuses issuance to it otherwise |
| per-entry `constraints` | a resource server that understands and enforces the key, per that type's specification ({{I-D.draft-mcguinness-oauth-mission-resource-access}}, {{rs-enforcement}}) | a Mission-aware Resource Server fails closed; a scope-only resource server is served only where the projection independently accounts for the constraint ({{scope-projection}}) |

## Remediation Grains {#remediation-grains}

A denial can carry independent remediation grains, each naming a next
step without granting anything. This document's own grain is
`mission_denial` ({{rs-enforcement}}): which path a denial leads
into.

| Grain | Carriage | Defined by |
| --- | --- | --- |
| `mission_denial` | `WWW-Authenticate` attribute | This document ({{rs-enforcement}}) |
| `insufficient_authorization` with `authorization_remediation` | `WWW-Authenticate` error code and parameter | {{I-D.draft-ietf-oauth-rar-metadata-remediation}} |
| Requestable denial | AuthZEN denial response: `context.access_request` with `next_action: request` | {{AuthZEN.ARAP}}, profiled by {{I-D.draft-mcguinness-mission-authzen}} |
{: title="The three remediation grains"}

A resource server can also return the `insufficient_authorization`
error code with `authorization_remediation`
({{I-D.draft-ietf-oauth-rar-metadata-remediation}}), which names
what `mission_denial: insufficient_authority` only points at. Each
grain keeps the wire shape and response status its defining document
gives it.

A client that decodes `authorization_remediation` can request the
carried entries on the standard `authorization_details` parameter of
a refresh request ({{mission-bound-tokens}}), where they derive under
this document's ordinary rules ({{authorization-derivation}}): of an
advertised, schema-valid type ({{discovery}}), narrowed same-type
({{subset}}, {{other-types}}) like any other request. The AS issues
only what both the presented refresh grant ({{Section 6 of RFC9396}})
and the Authority Set contain, so a refresh-token family narrower than
the Mission does not obtain the Mission's wider authority. For entries
outside the Authority Set, more authority requires a new approval,
proposed as for a new Mission ({{authority-proposal}}), or an
expansion where that companion is deployed ({{rs-enforcement}}). A
client holding no refresh grant that covers the entries proposes them
as for a new Mission.

A third grain routes the same denial into a governed access request
rather than a fresh derivation: the AuthZEN Access Request and
Approval Profile's requestable denial over {{AuthZEN.ARAP}}, adopted
by the Mission AuthZEN Profile
({{I-D.draft-mcguinness-mission-authzen}}). The three grains compose:
a deployment can offer any subset, and none widens authority beyond
what {{authorization-derivation}} derives from the same proposal
unremediated.

# Error and Challenge Mapping {#error-mapping}

This document reuses standard OAuth errors and challenges by
parameter ownership and processing stage. This table is the normative
statement of the base OAuth error for each failure it lists; a rule
elsewhere in this document that names one of these codes
({{submission-via-par}}, {{authority-proposal}},
{{intent-submission-evidence}}, {{authorization-derivation}},
{{approval-authentication}}, {{issuance-gating}}, {{rs-enforcement}},
{{self-exchange}}, {{delegation-constraints}}) applies this mapping.

| Surface / failing input | Base OAuth error | Optional detail |
|---|---|---|
| PAR: malformed Submission envelope or Intent (schema, unknown member, invalid value) | `invalid_request` ({{Section 5.2 of RFC6749}}) | safe `error_description` |
| PAR, or a companion's token-endpoint submission: a presented evidence entry of an unsupported type, or failing its type's validation or verification ({{intent-submission-evidence}}), or a required evidence type absent ({{I-D.draft-mcguinness-oauth-mission-submission-evidence}}) | `invalid_mission_intent_evidence` ({{intent-submission-evidence}}) | safe `error_description` |
| PAR or authorization: malformed or unsupported actual RAR object (an entry of a submitted `authorization_details` proposal) | `invalid_authorization_details` ({{Section 5 of RFC9396}}) | RAR-defined detail |
| PAR: a proposed entry, valid for its type, whose `resource` is not among the Intent's `target_resources` ({{authority-proposal}}) | `invalid_request` ({{Section 5.2 of RFC6749}}) | safe `error_description` |
| Request from a client registered as Mission-governed: `authorization_details` without `mission_intent` ({{authority-proposal}}) | `invalid_request` ({{Section 4.1.2.1 of RFC6749}}, {{Section 5.2 of RFC6749}}) | safe `error_description` |
| Authorization or token request: invalid, unknown, or malformed actual RFC 8707 `resource` parameter, or a token-endpoint `resource` outside the Mission's Authority Set | `invalid_target` ({{Section 2 of RFC8707}}) | safe `error_description` |
| Authorization or token request: the target's scope-projection mapping is unknown, ambiguous, or stale, whether or not the request names a `scope` value, or the target is `scope`-only and no safe projection exists for the applicable entries when the request names no `scope` value ({{scope-projection}}); or, where the AS applies {{rs-enforcement}}'s delegated-token routing rule at issuance, the delegated token's target is not known to be Mission-aware | `invalid_target` ({{Section 2 of RFC8707}}) | safe `error_description` |
| Authorization or token request: an explicitly requested `scope` value the issuance cannot grant under a scope-projection mapping the AS trusts ({{scope-projection}}) | `invalid_scope` ({{Section 4.1.2.1 of RFC6749}}, {{Section 5.2 of RFC6749}}) | safe `error_description` |
| Authorization request: `scope` includes `openid` and the Approver is not the Subject ({{approval-authentication}}) | `invalid_scope` ({{Section 4.1.2.1 of RFC6749}}) | safe `error_description` |
| Authorization decision: the Approver declines, approval authentication fails the floor or a requested `acr_values`/`max_age`, or a well-formed request (including configured-mapping mode) is refused by AS policy | `access_denied` ({{Section 4.1.2.1 of RFC6749}}) | none unless a defined extension applies |
| Token endpoint: the Mission is revoked, expired, or superseded | `invalid_grant` ({{Section 5.2 of RFC6749}}), or the code a Token Exchange profile assigns ({{issuance-gating}}) | `mission_error` ({{iana}}) |
| Token endpoint: the requested RAR subset exceeds the Mission's granted authority | `invalid_authorization_details` ({{Section 6 of RFC9396}}) | safe detail |
| Token exchange with no actor ({{self-exchange}}): the authenticated client is not the Mission's approved agent | `invalid_request` ({{Section 2.2.2 of RFC8693}}) | safe `error_description` |
| Delegated token exchange ({{delegation-constraints}}): narrowing leaves no entries for the delegate | `invalid_target` ({{Section 2.2.2 of RFC8693}}) | safe `error_description` |
| Token exchange using {{delegated-instance-context}}: required Client Attestation fails validation | `invalid_client_attestation` ({{Section 5.2 of I-D.draft-mcguinness-oauth-client-instance-id}}) | no instance-identity disclosure |
| Token exchange using {{delegated-instance-context}}: required instance-to-delegate or output-key association cannot be established | `invalid_request` ({{Section 2.2.2 of RFC8693}}) | no instance-identity disclosure |
| Protected resource: a token lacking the `mission` claim, where the resource requires it ({{rs-enforcement}}) | `invalid_token` ({{Section 3.1 of RFC6750}}) | none |
| Protected resource: weak or stale authentication of the token's Subject, where the deployment conveys it ({{rs-enforcement}}) | `insufficient_user_authentication` ({{Section 3 of RFC9470}}) | `acr_values`/`max_age` |
| Protected resource: DPoP proof missing, invalid, or mismatched | `DPoP` `invalid_token` challenge ({{Section 7.1 of RFC9449}}) | none |
| Protected resource: DPoP nonce required, missing, or stale | `DPoP` `use_dpop_nonce` challenge ({{Section 9 of RFC9449}}) | fresh nonce |
| Protected resource: certificate-bound token's presented certificate mismatch | Bearer `invalid_token` challenge ({{Section 3.1 of RFC6750}}, per {{Section 3 of RFC8705}}) | none |
| Protected resource: insufficient carried authority, or an unenforceable constraint | `insufficient_scope` ({{Section 3.1 of RFC6750}}) or the RAR-remediation challenge ({{remediation-grains}}) | `mission_denial` ({{rs-enforcement}}), minimized |
{: title="Endpoint x parameter x failure-stage error mapping"}

An AS performing an applicable check early, at PAR, returns the same
error class the check would yield at the authorization or token
endpoint: {{Section 2.3 of RFC9126}} permits an authorization-request
error at PAR, and doing so does not change which of the rows above
applies.

# Mission State via Token Introspection {#introspection}

Token introspection lets a Mission-state-aware resource server observe
a Mission's current state per request instead of waiting out a
token's lifetime. For the JWT carriage it is a state-observable
overlay on the lifecycle-gated baseline ({{mission-bound-tokens}});
for opaque Mission-bound tokens it is the claims carriage
({{introspected-consumption}}).

An AS MAY support OAuth 2.0 Token Introspection {{RFC7662}} for
Mission-bound access tokens. When it does, the response for such a
token carries, in addition to the standard members, a `mission`
member: a JSON object with the following members.

- `id` and `issuer`: as in the `mission` claim ({{mission-claim}}).
- `state`: the Mission's current lifecycle state (string). Its value
  space, including a state a deployed companion profile defines, and
  the consumer's forward-compatibility rule are those of
  {{lifecycle}}.
- `proposal_hash`: when the Mission records an authority proposal,
  the Mission's `proposal_hash` ({{mission-record}}) (string).
- `authority_hash`: the Mission's Authority Set commitment
  ({{mission-record}}) (string).
- `approval_basis`: the Mission's `approval_basis`
  ({{mission-record}}), carrying `type` only.
- `authority_source`: the Mission's `authority_source`
  ({{mission-record}}), carrying `type` and, for `organizational`,
  `policy` with `id` and `version` only, never the policy `digest`.

Only the Mission `issuer` reports `state`, `proposal_hash`,
`authority_hash`, `approval_basis`, and `authority_source`
({{only-issuer-reports-state}}). `proposal_hash`, `authority_hash`,
`approval_basis`, and `authority_source` are audit and correlation
signals. None of these four members is an enforcement input
({{rs-enforcement}}), and each is disclosed only as
{{caller-authorization-and-minimization}} permits.

For a malformed, unknown, individually expired, or otherwise
unresolvable token, the AS responds per {{RFC7662}} (`active: false`)
with no `mission` member; it does not reveal Mission state for a
token it cannot bind to a Mission.

The composite-active rule ({{composite-active}}) and the `mission`
member apply equally when a Mission-bound refresh token is
introspected.

Freshness is per use. Strengthening {{Section 4 of RFC7662}}, which
permits a protected resource to cache the response, this document
defines no caching semantics for the `mission` member: a resource
server that relies on introspection for Mission state treats each
response as an observation for that decision, not as a cacheable
state assertion. A deployment that needs bounded-staleness caching
adopts the Mission Status companion, whose signed responses carry
explicit freshness ({{I-D.draft-mcguinness-oauth-mission-status}}).

## Caller Authorization and Minimization {#caller-authorization-and-minimization}

Strengthening {{Section 2.1 of RFC7662}}, which requires some form of
authorization to access the introspection endpoint, the AS:

- MUST authenticate the calling party.
- MUST return Mission data only to a caller authorized to receive
  it, in particular a resource server that is an audience of the
  token.
- MUST audience-filter the response, returning the
  `authorization_details` entries and Mission data relevant to the
  caller's audience and not disclosing entries addressed to other
  audiences ({{mission-bound-tokens}}).

These rules apply equally to the `mission` member of an
`active: false` response ({{composite-active}}).

Disclosure is member-scoped as well as caller-scoped.
`proposal_hash`, `authority_hash`, `approval_basis`, and
`authority_source` serve audit and correlation consumers, not
resource server enforcement, and the AS MUST disclose each only to a
caller the deployment has granted that member's disclosure privilege.
By default, an audience-authorized resource server receives the
audience-filtered enforcement projection above, without them. A
`mission` member that a companion profile defines for disclosure here
follows the same member-scoped rule and is not an enforcement input.

## Composite Active State {#composite-active}

The introspection `active` member reflects the composite
authorization, not the token in isolation. Strengthening
{{Section 4 of RFC7662}}, the AS MUST return `active: true` only when
the access token passes that section's checks (valid signature,
unexpired, and not individually revoked) and the Mission is
`active`. The AS does not verify the token's sender-constraint
(`cnf`) at introspection; the resource server checks proof of
possession when the token is presented, so `active: true` is not by
itself evidence that the caller holds the bound key.

When the token is otherwise valid but the Mission is `revoked` or
`expired`, the AS MUST return `active: false` and include
`mission.state` giving the reason, so a resource server can
distinguish a dead Mission from a bad token. A Mission transition
does not by itself revoke the token as an individual credential;
introspection reports the composite authorization as inactive.

Reporting the `mission` member, `mission.state` included, for an
inactive token deviates from the SHOULD NOT of Sections 2.2 and 4 of
{{RFC7662}} against including additional information about an
inactive token. The caller authorization and minimization rules
({{caller-authorization-and-minimization}}) govern that deviation.

## Only the Issuer Reports Mission State {#only-issuer-reports-state}

An AS MUST NOT include `mission.state`, `proposal_hash`,
`authority_hash`, `approval_basis`, or `authority_source` in an
introspection response unless it holds the Mission, that is, unless
it is the Mission `issuer`. Introspection at a non-issuer Resource
AS, which returns only the claim-shape members, is specified by the
cross-domain companion
({{I-D.draft-mcguinness-oauth-mission-cross-domain}}).

## Introspected Token Consumption {#introspected-consumption}

The RFC 9068 JWT of {{mission-bound-tokens}} is this document's
self-contained carriage. An AS MAY instead issue a Mission-bound
access token as an opaque reference token, under this mode and only
under it; an opaque Mission-bound token outside this mode is not
profiled.

- In this mode, an AS issuing opaque Mission-bound tokens MUST offer
  introspection for them with the members this mode names.
- An active (`active: true`) response for such a token MUST carry,
  as introspection response members, the audience-filtered granted
  `authorization_details` ({{RFC9396}}), the `mission` member above,
  `aud`, `cnf` where the token is sender-constrained ({{RFC8705}},
  {{RFC9449}}), and `act` where execution was delegated
  ({{delegation}}): everything {{mission-bound-tokens}} requires the
  JWT to carry, sourced from the same issuance state.
- The granted `authorization_details` and any `act` chain appear
  only on an active response. An inactive response carries
  `active: false` and the `mission` state facts
  ({{composite-active}}), never the authority itself.
- A resource server consuming an opaque Mission-bound token MUST
  resolve it through introspection before service, MUST verify
  `active` is `true`, its own identity in `aud`, and the
  sender-constraint binding `cnf` names, and MUST enforce the
  response's `authorization_details` under the same rules as the
  token-carried form ({{rs-enforcement}}), the fail-closed duties
  included.
- A resource server that cannot obtain a valid introspection response
  for an opaque Mission-bound token MUST refuse the request rather
  than serve it from any cached or out-of-band belief about the
  token's authority.

The per-use freshness rule of {{introspection}} covers the whole
response in this mode: each response is one observation of the
token's claims and Mission state, not a cacheable authority record.

## Examples {#examples}

The following is an example of an introspection response for the
canonical ERP token ({{mission-claim}}) while the Mission is
`active`. The issuer AS returns the standard {{RFC7662}} members and
the `mission` member to a caller holding the deployment's
audit-and-correlation disclosure privilege, so `authority_hash` and
`proposal_hash` appear; the default audience-filtered enforcement
projection omits them.

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
    "proposal_hash":
      "sha-256:kT2mR7vX4qL9nY5pB1sD8fJ6wZ3hC0aGeUoNvSqMrYo",
    "state": "active"
  }
}
~~~

The following is an example of the response for the same token after
the Mission is revoked ({{composite-active}}):

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

Delegation is an optional capability ({{conformance}}). An agent may
delegate execution to downstream actors (a sub-agent, service, or tool
that is itself an OAuth client) within a Mission. An intermediary in
the agent's own trust domain that presents the agent's own tokens,
such as a gateway holding the agent's credentials, acts as part of
that client and is not a delegate; acting as that client, it can
also narrow by self-exchange ({{self-exchange}}), which does not
delegate. An intermediary authenticated as a distinct actor that
obtains a delegated token by Token Exchange is a delegate.
Delegation is represented with the OAuth Actor Profile
{{I-D.draft-mcguinness-oauth-actor-profile}}, which profiles the
`act` (actor) claim of {{Section 4.1 of RFC8693}}.

A delegate obtains a delegated token by Token Exchange
({{RFC8693}}). The AS issues the delegated token subject to all of
the following:

- **The exchange is explicit.** The delegating Mission-bound access
  token is the `subject_token`, with `subject_token_type`
  `urn:ietf:params:oauth:token-type:access_token`, and the
  `requested_token_type` is
  `urn:ietf:params:oauth:token-type:access_token`. The delegate is
  identified by an `actor_token` or by its own client authentication,
  and the AS asserts the actor itself ({{delegation-constraints}}).
- **Subject is stable.** `sub` remains the Mission's Subject. The
  delegate is an actor, not the subject.
- **`client_id` keeps its ordinary meaning.** A delegated token's
  `client_id` is the OAuth client that requested it
  ({{Section 4.3 of RFC8693}}, {{Section 2.2 of RFC9068}}). The
  originally-approved agent remains recorded in the Mission Record
  ({{mission-record}}, {{client-id-rebinding}}).
- **The `act` chain identifies the delegates.** The delegated token
  carries an `act` claim per {{Section 4.1 of RFC8693}} and the Actor
  Profile {{I-D.draft-mcguinness-oauth-actor-profile}}: the outermost
  `act` is the current delegate, and each earlier delegate is nested
  in the previous actor's `act` member. Each actor object carries the
  members that profile defines (for example, `sub`, `iss`, and the
  `sub_profile` actor-type classification, such as `ai_agent`).
- **Authority only narrows.** The delegated token's
  `authorization_details` MUST be a subset ({{subset}}) of the
  delegating token's authority, hence of the Mission Authority Set.
- **The `mission` claim is unchanged.** The delegated token carries
  the delegating token's `mission` claim ({{mission-claim}})
  unchanged, so every actor in the chain operates under the one
  consented authority.
- **Each delegate is bound to its own key.** The delegated token MUST
  be sender-constrained ({{mission-bound-tokens}}) to the **delegate's
  own** key: its `cnf` is the delegate's DPoP or mTLS key, not the
  delegating party's, and the delegate proves possession of that key
  in the Token Exchange. A compromised delegate key therefore cannot
  be replayed as the agent or as another actor in the chain.
- **Each delegation is gated.** Issuing a delegated token is a
  derivation, refused unless the Mission is `active`
  ({{issuance-gating}}).

The `act` chain nests (`act.act`) for as long as, and only while,
authority continues under the same approved Mission. A new approval
basis, such as a Child Mission
({{I-D.draft-mcguinness-oauth-mission-child-delegation}}) or an
expansion successor ({{I-D.draft-mcguinness-oauth-mission-expansion}}),
begins its own delegation basis and chain, and no organizational,
network, or deployment boundary by itself restarts or extends a
chain. The chain is attribution, not authority: an `act` entry names
who acted, for audit; the input to the eligibility matching of
{{delegation-constraints}} is the delegate the AS authenticates and
asserts at the exchange, not an entry read from the chain; an
asserted actor identity grants nothing; and the
`authorization_details` subset relations ({{subset}}), not the chain,
show that authority narrowed.

## Instance Context in Delegated Tokens {#delegated-instance-context}

Where a deployment authenticates client instances
({{I-D.draft-mcguinness-oauth-client-instance-id}}, with attesters a
client endorses under {{I-D.draft-mcguinness-oauth-client-attesters}}),
the delegate named by the outermost `act` can be an actor that an
authenticated instance represents. Instance evidence does not
establish that actor
({{Section 5 of I-D.draft-mcguinness-oauth-client-instance-id}}), so
the AS establishes the delegate's actor identity, and that actor's
trusted association with the instance, separately. Because a
delegated token is sender-constrained to the delegate's own key
({{delegation}}), and the Actor Profile makes the top-level `cnf` the
current presenter's key ({{I-D.draft-mcguinness-oauth-actor-profile}}),
that `cnf` is a key the instance possesses.

A deployment MAY convey `client_instance` in delegated tokens under
{{I-D.draft-mcguinness-oauth-client-instance-id}}. This optional
composition selects the authenticated presenting instance for output
context. The instance specification owns attestation validation,
instance-to-key association, audience-scoped mapping, and Context
Consumer validation; this section supplies the Mission-specific
authorization and context selection. Deployments configure its use
and whether instance attribution is required.

When issuing context under this composition, the AS MUST use the
presenting instance validated under
{{Section 5 of I-D.draft-mcguinness-oauth-client-instance-id}},
establish its trusted association with the separately authenticated
delegate, and bind the output token to an instance-unique key whose
possession it verified in that exchange. Context is mapped from that
validated instance into the output audience's Consumer Scope under
{{Section 7.1 of I-D.draft-mcguinness-oauth-client-instance-id}}. The
AS MUST NOT use context copied or remapped from an input token as a
substitute for the presenting instance's evidence. For example, when
instance B is authorized to continue work from instance A, output
context names B; A's context does not become B's identity by
remapping it.

The actor authentication, delegation eligibility, subset, and
lifecycle checks of {{delegation}} and {{delegation-constraints}}
still authorize the exchange; instance evidence satisfies none of them
by itself. Where deployment policy requires instance attribution, the
AS MUST refuse the exchange if the required instance evidence or its
association with the delegate and output key cannot be established.
{{error-mapping}} gives the error codes for these refusals. If the
exchange issues a refresh token, the grant-continuity rules of
{{Section 5.1 of I-D.draft-mcguinness-oauth-client-instance-id}}
apply alongside {{grant-binding}}; instance continuity alone does not
authorize replacement of the recorded instance or key rebinding.

Consumers establish presenter attribution under Sections 7.3 and 7.5
of {{I-D.draft-mcguinness-oauth-client-instance-id}}. This composition
does not add provenance to `client_instance`: a consumer can use the
direct-attestation trust configuration only when the issuer meets
that configuration's restriction against upstream context. An issuer
also conveying upstream context needs a separately specified,
authenticated provenance mechanism before its context can support
presenter attribution. A consumer requiring attribution rejects
unestablished associations under
{{Section 7.6 of I-D.draft-mcguinness-oauth-client-instance-id}}.

## Self-Exchange Down-Scoping {#self-exchange}

An agent MAY present its own Mission-bound access token as the
`subject_token` of a Token Exchange ({{RFC8693}}) with no actor, to
obtain a narrowed token (for example, a single-audience one). Because
it names no actor, such an exchange does not delegate: it re-scopes
the agent's own authority downward. A no-actor exchange is subject to
the following:

1. The AS MUST refuse a no-actor exchange with the `invalid_request`
   error code ({{Section 2.2.2 of RFC8693}}) unless the authenticated
   client is the Mission's approved agent (the Mission Record's
   `client_id`, {{mission-record}}). A delegate narrows only through a
   delegated exchange that names it in the `act` chain.
2. The result MUST be a subset ({{subset}}) of the presented token's
   authority; it carries the same `mission` claim ({{mission-claim}})
   and adds no `act` chain.
3. The exchange is a derivation, gated on the Mission being `active`
   ({{issuance-gating}}).

## Delegation Constraints {#delegation-constraints}

What may be delegated, how far, and to whom is governed per Authority
Set entry by a type-defined delegation policy ({{other-types}}). For
`mission_resource_access`, the policy is the `delegation` member,
whose concrete depth and matcher conditions the Mission Resource
Access Profile defines
({{I-D.draft-mcguinness-oauth-mission-resource-access}}). Because the
policy lives in the entry, `authority_hash` commits it with the rest
of the Authority Set, and it is carried with the entries wherever
they go, including across a cross-domain projection
({{I-D.draft-mcguinness-oauth-mission-cross-domain}}).

**Delegation depth.** The delegation depth of a token is the number
of delegations between the approved agent and the token's current
actor: the agent's own non-delegated token is depth 0, the first
delegate is depth 1, and each further delegate adds 1. The depth
checked against `max_depth` is that of the token
being issued, computed after appending the new outermost actor, not
the depth of the delegating token. A credential projected across a
trust domain carries no `act` chain and enters the target domain at
depth 0 ({{I-D.draft-mcguinness-oauth-mission-cross-domain}}).

**Depth accounting.** The AS MUST establish delegation depth from
accounting it maintains for the tokens it issues under the Mission
and associates with the credential it validates (for example, recorded
at issuance against the token), not from the nesting of a presented
`act` claim. The `act` chain is attribution ({{delegation}}): it
renders the accounted chain and is not the source of the count. Over
the exchanges this document defines the accounting is complete: each
delegated exchange adds exactly one delegate, a self-exchange
({{self-exchange}}) adds none, and a cross-domain projection is the
one defined reset. A profile that issues Mission-bound tokens by
another path specifies how it preserves or reconstructs this
accounting and any reset it defines. Where the AS cannot establish
the depth of the token being issued, no entry's delegation policy can
be evaluated at that depth, so every entry narrows out under the
per-entry rule below and the exchange is refused as an empty result.
A resource server bases no authorization decision on a prior actor
({{Section 4.1 of RFC8693}}).

**Per-entry enforcement.** When the AS issues a token to a delegate
(the actor that becomes the outermost `act`) at delegation depth
`d`, it includes a Mission Authority Set entry in the delegated
token's `authorization_details` only if both of the following hold:

1. The entry's type defines a delegation policy for the entry. An
   entry carrying no type-defined delegation policy is non-delegable,
   the default.
2. That policy, evaluated at depth `d`, permits this delegate. The AS
   applies the policy's own eligibility test at every exchange; where
   the policy leaves a matcher unstated, the AS's
   delegation-authorization policy decides, and absence is never a
   blanket grant.

An entry failing either condition narrows out of the delegated token,
consistent with the subset rule ({{subset}}). The delegation policy
is not part of the subset comparison itself, and a surviving entry
carries it intact so the next hop is evaluated the same way.

**Empty result.** If narrowing leaves no entries for the delegate,
the AS MUST refuse the exchange with the `invalid_target` error code
({{Section 2.2.2 of RFC8693}}) rather than issue a token with empty
authority. The requested delegation has no authority to carry, while
the subject grant itself remains valid for other exchanges.

**The resource server enforces none of this.** The AS applies
delegation constraints at issuance; a resource server sees only the
already-narrowed `authorization_details` and enforces those as usual
({{mission-bound-tokens}}).

## Worked Example: Delegated Token {#worked-example-delegated-token}

Suppose the Mission's Authority Set has two entries on the ERP:
`invoices.read`, delegable to `ai_agent` actors through depth 2; and
`journal-entries.write`, which carries no `delegation` member and is
therefore non-delegable. The approved agent `s6BhdRkqt3` delegates to
sub-agent `tool-runner-7`, an `ai_agent`, at depth 1. The read entry
is permitted (depth 1 <= 2, `ai_agent` allowed) and the write entry
narrows out. The following is an example of the decoded delegated
access token:

~~~ json
{
  "iss": "https://as.example.com",
  "sub": "user_3p2q8mN1a0kV7tR",
  "aud": "https://erp.example.com",
  "client_id": "tool-runner-7",
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
    "issuer": "https://as.example.com"
  }
}
~~~

`sub` is still the user. `client_id` is `tool-runner-7`, the delegate
that authenticated the Token Exchange and requested this token
({{client-id-rebinding}}); it matches the outermost `act` only
because `tool-runner-7` authenticated the exchange itself. `client_id`
does not name `s6BhdRkqt3`, the originally-approved agent, whose
identity remains recoverable from the Mission Record via `mission_id`
({{mission-record}}).

The `cnf` is `tool-runner-7`'s own key, not the agent's, so this token
cannot be replayed as the agent. The non-delegable write entry was
dropped; the read entry survives, carrying its `delegation` member so
a further hop can be evaluated: a depth-3 delegate, or a
non-`ai_agent` one, would narrow it out too. The `mission` claim is
unchanged.

# Extensibility {#extensibility}

This document is a base layer that other agent-authorization work is
expected to extend. Extensions build alongside the stable interface
below; they MUST NOT redefine it. The following remain stable across
revisions of this document:

- the `mission` claim members `id` and `issuer` ({{mission-claim}});
- the `authorization_details` carriage and its type-agnostic subset
  discipline ({{other-types}}, {{subset}}); and
- the `act` delegation chain ({{delegation}}).

This document's extension points are:

- **Authority types.** The Authority Set is open to any AS-supported
  `authorization_details` type ({{other-types}}); the Mission
  apparatus (commitment, gating, delegation) is type-agnostic toward
  every type, subject to the delegation and projection limits in
  {{other-types}}.
- **Intent Submission Evidence types.** The `evidence` array of the
  Submission envelope is open to evidence types defined by companion
  profiles: each type is a collision-resistant name whose owning
  specification defines the entry's closed schema, verification, and
  verified output facts
  ({{I-D.draft-mcguinness-oauth-mission-submission-evidence}}), and
  an AS refuses an entry of a type it does not support rather than
  ignoring it ({{intent-submission-evidence}}).
- **Mission Intent members.** The Mission Intent's top level
  ({{mission-intent}}) is open to members a companion profile
  defines, under a short name it registers in the Mission Intent
  Members registry ({{iana-intent-members}}) before use, or under a
  collision-resistant name. The owning specification defines,
  produces, and enforces each such member, and a recognized member
  never grants or widens authority beyond what that specification
  states. Closed-top-level validation ({{submission-via-par}}) refuses
  any top-level member that neither this document nor an implemented
  companion profile defines, and the AS ignores none it recognizes.
  Registration settles which specification owns a short name; it does
  not make an AS implement, recognize, or trust any member.
- **Integrity anchors.** Additional committed objects use the same
  domain-separated, issuer-bound envelope with a new `typ`
  ({{integrity-anchors}}). A consent-disclosure commitment, an
  instruction-text attestation, or a delegation receipt can be
  committed this way without changing this document. A profile that
  commits an evidence or disclosure object MUST commit it with this
  envelope and a `typ` that meets {{integrity-anchors}}, not by
  hashing the bare object, so the domain separation and issuer binding
  hold uniformly. A `mission` descriptor embedded in such an object
  uses the `mission` claim shape ({{mission-claim}}), optionally
  extended with collision-resistantly named members (for example, an
  `intent_hash` for audit), and is never authority-bearing on its own.
- **The `mission` claim.** It is an open object: additional,
  collision-resistantly named members can be carried in it (for
  example, a runtime decision reference, a delegation receipt, or an
  attestation reference), under the consumer rules of
  {{mission-claim}}.
- **Mission Record members.** The Mission Record is open to
  additional members set at creation, under short names a companion
  profile coordinates with this document or under collision-resistant
  names, as {{mission-record}} states.
- **Lifecycle state.** The lifecycle state space ({{lifecycle}}) is
  open to additional states that companion profiles register in the
  Mission Lifecycle States registry ({{iana-lifecycle-states}}) for
  lifecycles they introduce. Under the forward-compatibility rule of
  {{lifecycle}}, only `active` permits issuance.
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

This document defines no capability-negotiation mechanism or
profile-version field; an extension declares its own identifiers and,
where it needs discovery, its own metadata. {{namespace-taxonomy}}
states the general rule these extension points follow.

## Namespace Taxonomy {#namespace-taxonomy}

This document's extensible namespaces follow one of three postures:

- **Registry-backed.** A namespace whose values determine fail-closed
  behavior and span multiple documents is backed by an IANA registry.
  This document creates the Mission Lifecycle States
  ({{iana-lifecycle-states}}) and Mission Intent Members
  ({{iana-intent-members}}) registries and seeds each with the values
  it defines; every further document that defines a value requests
  that value's registration, carrying any Internet-Draft reference as
  a publication dependency under the registry's policy.
- **Specification-defined.** A namespace with a defined fail-safe for
  unknown values and no registry, such as the `mission` claim members
  ({{mission-claim}}) and the Mission Record members
  ({{mission-record}}), is specification-defined: the defining
  documents are its value space.
- **Collision-resistant.** Deployment-defined names are
  collision-resistant names ({{Section 4.2 of RFC7519}}) and are never
  registered.

A `typ` inside a JCS commitment envelope ({{integrity-anchors}}) names
a hash domain, not a representation crossing a protocol boundary, and
is not a media type.

# Authorization Server Metadata {#discovery}

This document defines the following authorization server metadata
parameter {{RFC8414}}:

`mission_bound_authorization_supported`:
: OPTIONAL boolean. When `true`, the AS supports the core Mission
  Issuer surfaces of this document ({{conformance}}): the
  `mission_intent` authorization request parameter through PAR
  ({{mission-intent}}), derivation of `authorization_details` entries
  of its supported types ({{authorization-derivation}},
  {{other-types}}), Mission-bound access tokens
  ({{mission-bound-tokens}}), and the `mission` JWT claim
  ({{mission-claim}}). It asserts Mission Issuer support only; it
  makes no claim about any resource server or about the optional
  capabilities, whose discovery is described below. If omitted, the
  default value is `false`.

A deployment can instead arrange Mission-bound authorization,
including its supported types and schemas, out of band. A client
holding a Mission Intent MUST NOT submit the same authority as bare
`scope` or `authorization_details` to an AS whose Mission support is
neither advertised nor otherwise established; it surfaces the
inability instead ({{downgrade-by-omission}}). Where the deployment's
AS cannot change, the standalone Mission Authority Server
({{I-D.draft-mcguinness-mission-authority-server}}) is the governed
alternative.

An AS that advertises support for this document MUST include at least
one AS-supported type in its `authorization_details_types_supported`
metadata ({{RFC9396}}): the approved-set commitment a Mission-aware
client relies on. Where `mission_resource_access` is among them, the
Mission Resource Access Profile
({{I-D.draft-mcguinness-oauth-mission-resource-access}}), not
out-of-band documentation, is that type's normative definition.

An AS that advertises `mission_bound_authorization_supported: true`
MUST also publish `pushed_authorization_request_endpoint`
({{RFC9126}}), since a Mission Intent is accepted only through PAR
({{submission-via-par}}).

An AS that advertises `mission_bound_authorization_supported: true`
SHOULD also advertise `authorization_details_types_metadata_endpoint`
{{I-D.draft-ietf-oauth-rar-metadata-remediation}} where it implements
that endpoint. Conformance to this document does not depend on that
endpoint. Where the AS advertises it:

- its response's key set is the source of truth for which types the
  AS supports;
- `authorization_details_types_supported` mirrors those keys and MUST
  NOT list a type absent from them; and
- the AS MUST publish, within that response, an entry for every
  supported type whose schema validates that type's documented object
  shape. For `mission_resource_access`, that shape, including the
  Common Constraints structure, is the Mission Resource Access
  Profile's ({{I-D.draft-mcguinness-oauth-mission-resource-access}}).

The optional capabilities are discovered first through existing OAuth
metadata ({{RFC8414}}): `introspection_endpoint` for introspection,
and `grant_types_supported` containing
`urn:ietf:params:oauth:grant-type:token-exchange` for delegation and
for the companion's cross-domain grant issuance. Absent such a signal,
a capability is discovered out of band or by attempt: a Token
Exchange, a cross-domain grant issuance, or an introspection request
fails if the issuer does not support it.

# Protected Resource Metadata {#protected-resource-metadata}

This document defines the following protected resource metadata
parameter {{RFC9728}}:

`mission_bound_authorization_required`:
: OPTIONAL boolean. When `true`, the protected resource accepts only
  Mission-bound tokens: a token that lacks the `mission` claim
  ({{mission-claim}}) is rejected ({{rs-enforcement}}). If omitted, the
  default value is `false`.

A type-defined `authorization_details` member may define its own
constraint-discovery surface; `mission_resource_access`'s is defined
by the Mission Resource Access Profile
({{I-D.draft-mcguinness-oauth-mission-resource-access}}).

A protected resource can list the `authorization_details` types it
accepts in the `authorization_details_types_supported` parameter
({{Section 2 of RFC9728}}), so a client can propose entries of a
type its target accepts.

# Conformance {#conformance}

The smallest useful conforming deployment is a Mission Issuer that
derives in narrowing mode from the client's authority proposal
({{authorization-derivation}}), supports one AS-supported
`authorization_details` type and emits only that type's
specification-defined vocabulary, and implements none of the optional
capabilities. A scope-only resource server is served only where the
AS established a safe scope projection for it ({{scope-projection}}).
A Mission Issuer can instead start from configured-mapping mode
({{authorization-derivation}}), which is equally conforming. Neither
starting point is a conformance class.

An implementation conforms in one of three roles.

A **Mission Issuer** (the authorization server) implements the core
issuance surfaces:

- submission of a Mission Intent, in the Submission envelope, via
  PAR ({{submission-via-par}}), with the Intent Submission Evidence
  dispatch and refusal rules ({{intent-submission-evidence}});
- derivation of `authorization_details` entries of its supported
  types ({{authorization-derivation}}, {{other-types}});
- the approval event with its integrity anchors and its recorded
  `approval_basis` and `authority_source` ({{approval-event}},
  {{mission-record}});
- issuance of Mission-bound access tokens carrying the `mission` claim
  ({{mission-bound-tokens}}), as the RFC 9068 JWT or as an opaque
  reference token under the introspected consumption mode
  ({{introspected-consumption}});
- the subset rule ({{subset}}); and
- gating of issuance on Mission state ({{lifecycle}}).

An AS can conform as a Mission Issuer without supporting any Intent
Submission Evidence type. Such an AS refuses every presented entry
as an unsupported type under the dispatch and refusal rules
({{intent-submission-evidence}}), with
`invalid_mission_intent_evidence`. It does not need to implement the
evidence framework of
{{I-D.draft-mcguinness-oauth-mission-submission-evidence}} for this
configuration. The companion defines conformance for ASs supporting
an evidence type, whether its evidence is optional or required.

A **Mission-aware Resource Server** implements resource server
enforcement ({{rs-enforcement}}), from the token's own claims or from
its active introspection response under the introspected consumption
mode ({{introspected-consumption}}).

A **Mission Client** implements the client surfaces:

- submission of the Mission Intent via PAR only
  ({{submission-via-par}}), proposing concrete authority, where it
  does, on the `authorization_details` parameter pushed alongside
  `mission_intent` ({{authority-proposal}});
- reading its granted authority from the token-response
  `authorization_details` echo ({{mission-bound-tokens}}); and
- obtaining `mission_id` from the `mission_id` token-response parameter
  or the `mission` claim's `id` ({{grant-binding}}), treating it as a
  reference, not a credential.

Beyond these mandatory roles, an implementation can additionally claim
three OPTIONAL capabilities. Each is independent, and an implementation
that supports none of them is still conformant:

- **Delegation** ({{delegation}}): issuing and consuming derived tokens
  that carry the `act` delegation chain.
- **Introspection** ({{introspection}}): reporting Mission state through
  the `mission` token introspection response member. Required where
  the AS issues opaque Mission-bound tokens
  ({{introspected-consumption}}).
- **Cross-Domain**: projecting a Mission so it is honored by an
  authorization server in another trust domain. An implementation
  claiming this capability preserves, across the hop:

  1. the Mission reference (`mission.id`, `mission.issuer`) and the
     `authority_hash` the projection carries, intact;
  2. authority that only narrows ({{subset}});
  3. projection performed only by, or under the authorization of, the
     Mission `issuer`, gated on the Mission's `active` state
     ({{lifecycle}}); and
  4. projected credential lifetimes capped by the Mission's
     `expires_at` ({{mission-bound-tokens}}).

  This bar is self-contained in this document. The companion Mission
  Cross-Domain Projection profile
  ({{I-D.draft-mcguinness-oauth-mission-cross-domain}}) specifies the
  interoperable mechanism that satisfies it, and implementations that
  interoperate across the hop implement that companion.

Mission Approved-Set Verification
({{I-D.draft-mcguinness-oauth-mission-approved-set-verification}})
defines an independent check, by a resource server or policy decision
point, that a token's carried authority is a subset of the complete
approved Authority Set; conformance to this document does not
require it.

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
conforms to no role in this document and does not implement it: in
particular, it MUST NOT advertise
`mission_bound_authorization_supported` as `true` ({{discovery}}),
the machine-checkable form of that claim.

The Mission Binding Properties vector of
{{I-D.draft-mcguinness-mission-architecture}} names this discharge as
its `credential-mission-bound` property, informatively; these gates
remain authoritative for OAuth binding conformance regardless.

This document publishes a Mapping Assessment of how the surfaces
above realize the Mission Substrate contract's kernel and
capabilities ({{oauth-statement}}). It is not this document's
conformance result: this document makes no substrate-conformance
claim, takes no requirement from the substrate, and remains
self-contained; its reference to the substrate contract
({{I-D.draft-mcguinness-mission-substrate}}) is informative.

# Security Considerations {#security-considerations}

The security considerations of OAuth 2.0 ({{Section 10 of RFC6749}}),
the OAuth 2.0 Security Best Current Practice {{RFC9700}}, Rich
Authorization Requests ({{Section 12 of RFC9396}}), Pushed
Authorization Requests ({{Section 7 of RFC9126}}), and JWT access
tokens ({{Section 5 of RFC9068}}) apply to this document. Those of
Token Exchange ({{Section 5 of RFC8693}}) apply to delegation, and
those of DPoP ({{Section 11 of RFC9449}}) and mutual TLS
({{Section 7 of RFC8705}}) apply where a token is sender-constrained.

## Commitment and Consent Integrity {#sec-commitment}

### Consent Binding {#consent-binding}

The security goal of this document is that a user's approval of a task
bounds every token derived for it. The `authority_hash` commits the
exact Authority Set the Approver consented to, recorded on the Mission
({{mission-record}}). The goal rests on the AS deriving only subsets of
that set and signing every token accordingly, and on the resource server
verifying the AS's token signature and enforcing the carried authority,
not on every token carrying the commitment itself ({{mission-claim}}).
A derived token can carry a narrowed subset, so a resource server
cannot in general recompute `authority_hash` from the token: the hash
commits the approved set but supplies no subset proof, and a resource
server that does not verify against the complete set relies on the
signed token as the AS's assertion that the carried authority was
correctly projected from the approved set ({{rs-enforcement}}).

A deployment that needs assurance independent of the token signature
verifies the carried authority against the complete approved set. What
that verification provides depends on when the issuer is compromised.
Retrieval of the complete set under the same trust root as the token
adds nothing against an issuer malicious at approval time: that issuer
can approve and commit arbitrary authority, and no containment
mechanism changes that. The same checks do defend against projection
implementation errors, against corruption of the record after an
independently anchored approval commitment, and against post-approval
signing-key compromise where the original commitment is pinned outside
the issuer. The pinning makes that difference.

`intent_hash` extends the same protection to the task itself: it commits
the approved Mission Intent, so an auditor can detect any later
alteration of the recorded task. The two are committed separately.
`authority_hash` commits what a resource server enforces and what a
cross-domain projection carries, so it is computed over the Authority
Set alone ({{integrity-anchors}}) and can be checked without the Intent;
`intent_hash` stays tamper-evident audit material even where the
authority is projected without the Intent. No anchor substitutes for
another.

This document commits the task (`intent_hash`) and the authority
(`authority_hash`) the Approver consented to, but not the **rendered
consent disclosure** itself: no anchor here binds the locale,
disclosure-template version, or material notices the Approver was
shown, so a buggy or malicious rendering layer could show a narrower or
different task than the Authority Set committed without leaving any
committed trace. A deployment whose Missions carry high-risk authority
can record presentation-level audit evidence, retained so the
disclosure shown can be reconstructed and audited: Mission Consent
Evidence {{I-D.draft-mcguinness-oauth-mission-consent-evidence}} binds
a `consent_rendering_hash` over a structured consent-disclosure object
on the wire, and an AS that does not implement it can record equivalent
evidence out of band. Such a commitment binds the structured disclosure
the AS records, not the presentation itself; it narrows this gap for
audit but does not close it.

### Downgrade by Omission {#downgrade-by-omission}

A token bearing equivalent `authorization_details` but no `mission`
claim is governed by no Mission state, revocation, or consent
commitment. A deployment can designate a resource, or register a
client, as Mission-governed; {{authority-proposal}} states the
issuance-side rules that keep such a resource's tokens and such a
client's requests inside a Mission.

On the client side, a client holding a Mission Intent does not fall
back to an ordinary request where Mission support is not established
({{discovery}}).

On the enforcement side, a resource server for such a resource
rejects a token lacking the `mission` claim and can advertise that
requirement ({{rs-enforcement}}, {{protected-resource-metadata}}).

The `mission_bound_authorization_supported` ({{discovery}}) and
`mission_bound_authorization_required`
({{protected-resource-metadata}}) members are discovery data whose
integrity rests on the metadata retrieval protections of {{RFC8414}}
and {{RFC9728}}; the security considerations of those documents
apply.

## Agent-Specific Threats {#sec-agent}

### Prompt Injection and the Exfiltration Leg {#prompt-injection}

An agent that reads attacker-influenceable content can be
prompt-injected; this document assumes that and does not try to make the
agent immune. Injection is dangerous when one agent combines access to
private data, exposure to untrusted content, and the ability to
communicate externally; the Mission Security Model
({{I-D.draft-mcguinness-mission-security-model}}) analyzes that
combination and its architectural defenses. This document's
contribution to each leg follows.

This document constrains the data-access leg: a Mission narrows
authority from everything the agent's standing credentials allow to the
resources the approved task needs, and per-task Missions
({{applicability}}) further limit the effect of a compromise.

Against the untrusted-content leg, it contributes one thing:
`success_criteria` is inert, granting, widening, and gating no
authority, `purpose` supplies candidate authority only as a lookup key
of the pre-approval derivation whose result the Approver reads and
consents to and otherwise can only refuse or tighten, and `goal`
bounds it only through that disclosure
({{mission-intent}}, {{authorization-derivation}}). Authority is fixed
at the approval event, so injected text cannot expand an approved
Mission.

This document does not constrain the external-communication leg and
provides no information-flow control. It models authority over resources
and actions, not how an agent uses authority it holds: within an
approved Authority Set, an injected agent can read what the Mission
permits and write to a sink the Mission permits. Constraining
exfiltration by a compromised agent is the runtime layer's role
({{runtime-boundary}}), and even there it is bounded, not closed
({{I-D.draft-mcguinness-mission-runtime}}); preventing misuse of data
within the authorized scope needs a taint or information-flow layer
this document does not define.

### Authority Does Not Propagate With Information {#information-propagation}

Issuance gating bounds escalation by token acquisition ({{lifecycle}},
{{subset}}): an agent cannot exceed the approved Authority Set by
acquiring additional tokens. The same bound holds for information: an
agent can
inherit another agent's knowledge, but not its authority.

A work product produced under one Mission, such as a file, message,
memory entry, queue event, or other durable shared artifact, is input,
not authority, when an agent operating under another Mission reads it.
The receiving Mission determines what can be done with the information
under its own Authority Set ({{subset}}); the producing Mission's
authority does not transfer through the artifact by copying,
referencing, embedding, or communicating it. An agent that needs
authority to act on what it read acquires it only through an authorized
derivation or delegation bounded by the Mission ({{delegation}}), not
from the artifact.

The threat is emergent authority through coordination: independent
Missions communicating through shared state, so that individually
acceptable actions compose into behavior no single Mission authorized
({{I-D.draft-mcguinness-mission-security-model}}). The mechanism that
upholds the invariant across such a carrier (work-product provenance
and a non-transitive Mission-to-Mission handoff) is specified by
Mission Work Products
{{I-D.draft-mcguinness-oauth-mission-work-products}}; this document
takes no normative dependency on it.

## Enforcement Boundaries {#sec-enforcement}

### Issuance Scope, Not Runtime Enforcement {#runtime-boundary}

This document governs the issuance and derivation of authority: it
bounds what authority a Mission yields, binds it to the Approver's
consent, and gates derivation on Mission state. It does not evaluate
individual runtime actions. In particular, it does not:

- evaluate a request's parameters against the Mission at the point of
  use;
- produce runtime enforcement evidence for each consequential action;
- bind tool or function identities to the Mission; or
- re-evaluate at execution time to close the approval-to-execution
  (time-of-check to time-of-use) gap.

Within a token's lifetime, an agent exercises the token's authority
without a check of each action against the Mission, so an active Mission
can become ambient authority for individual consequential actions. Short
token lifetimes and narrow authority bound this exposure but do not
eliminate it.

A runtime layer ({{I-D.draft-mcguinness-mission-runtime}}),
outside the scope of this document, evaluates each consequential action
against the Mission, with parameter binding, and records evidence for
the actions it covers. A deployment adds one for an action class that
needs any of the following, which issuance-time bounds alone do not
provide:

- per-action evaluation or evidence;
- approval bound to a single action; or
- a bound the receiving resource server cannot enforce.

Where the resource server or a composing runtime layer matches a
concrete request URI against a `prefix` entry, the Resource Boundary
Canonicalization analysis of the Mission Resource Access Profile
({{I-D.draft-mcguinness-oauth-mission-resource-access}}) gives the
single-normalization rule for that match, for a deployment that supports
that type.

Short-lived access tokens are this document's issuance-only
recommendation: with no runtime layer, token lifetime is the
revocation-latency bound at unmodified resource servers. Where a
runtime layer covers the high-consequence classes with an active
freshness source, the point-of-use decision is the revocation
cutoff, and lifetimes can be sized by action class without
losing the kill switch ({{I-D.draft-mcguinness-mission-runtime}}).

Classes attach to entries while `exp` attaches to the token: an
extended lifetime is appropriate only for a token whose carried
entries are all on runtime-gated paths, since a single ungated entry
stretches its own revocation latency to the extended lifetime.
Narrowed, single-audience tokens ({{subset}}) are the mechanism that
keeps gated and ungated authority from sharing one long-lived token.

### Denial Detail Disclosure {#denial-disclosure}

The `mission_denial` attribute and the {{RFC9470}}
`insufficient_user_authentication` challenge ({{rs-enforcement}}) each
tell a caller which path a denial leads into, and so reveal
authorization shape: an `insufficient_user_authentication` challenge
confirms to the presenting party that the authority exists and only
the Subject's authentication is weak or stale, while
`mission_denial: insufficient_authority` denies the authority's
existence outright. Introspection guards the same class of fact behind
caller authorization ({{caller-authorization-and-minimization}}), and
{{rs-enforcement}} limits the attribute to a token holder that the
deployment accepts learning the distinction. Of the two values,
`insufficient_authority`
reveals least, and omitting the attribute reveals nothing.

## Credentials and Delegation {#sec-credentials}

### Token Theft {#token-theft}

Derived tokens are sender-constrained (DPoP {{RFC9449}} or mTLS
{{RFC8705}}) where {{mission-bound-tokens}} and {{delegation}} require
it. A stolen token is bounded by the Authority Set and the
Mission lifetime regardless, but sender-constraint prevents replay by a
different party.

### Delegation and Chain Compromise {#delegation-and-chain-compromise}

Delegation ({{delegation}}) widens the set of parties holding
Mission-derived authority. Because authority only narrows down the
chain, a compromised actor can act only within its narrowed
`authorization_details`, for the lifetime of the token it holds. The
per-entry delegation constraints (delegability, `max_depth`, and
`allowed_delegates`, {{delegation-constraints}}) bound this exposure at
approval time.

`max_depth` bounds the length of a delegation chain, not its breadth:
only `allowed_delegates` bounds fan-out to many distinct depth-1
delegates. Binding each delegated token to the delegate's own
key ({{delegation}}) confines a compromised delegate to its own
credential. Short derived-token lifetimes ({{issuance-gating}}), and
marking delegable only the entries that need delegation, keep this
exposure small.

Audience replay into the exchange is a distinct path. A Mission-bound
token obtained by or issued to one party, presented as a
`subject_token`, could be exchanged for a fresh delegated credential
bound to the presenter. The gates above bound it: the exchange is a
derivation gated on Mission state, the AS applies
delegation-authorization policy at every exchange
({{delegation-constraints}}), the result is bound to the authenticated
delegate's own key and narrowed by the subset rule, and a no-actor
exchange is accepted only from the Mission's approved agent
({{self-exchange}}). Sender-constraining the primary token
({{mission-bound-tokens}}) closes the remaining gap, since a token
stolen from an audience then fails presentation at the token endpoint.

### client_id Conformance and the Approved-Agent Residual {#client-id-misattribution}

Because this document keeps `client_id`'s ordinary {{RFC9068}} meaning
({{client-id-rebinding}}), a generic {{RFC9068}} resource server, or a
logging, SIEM, or audit pipeline, that keys attribution on `client_id`
attributes a Mission-derived token, delegated or not, to the correct
requesting client. Such a component cannot see the delegation lineage in
the `act` chain ({{delegation}}) or the Mission's originally-approved
agent, which is recorded in the Mission Record ({{mission-record}}), not
in `client_id`.

An existing component that authorizes or logs solely from `client_id`
needs review for this gap before it receives delegated Mission-bound
tokens; {{rs-enforcement}} states what a resource server may not infer
or route on `client_id`.

### Signing and Key Rotation {#key-rotation}

The `mission` claim and `authorization_details` are carried inside the
{{RFC9068}} JWT and covered by the AS's token signature, so their
integrity reduces to the AS's signing key, whose publication and
rotation {{mission-bound-tokens}} specifies.

Verification for audit outlives validity; keeping a key resolvable for
the audit horizon ({{mission-record}}) of every Mission whose tokens it
signed lets an auditor verify those tokens later. A companion that
anchors a longer-lived artifact to the same keys (a status assertion, a
Mandate, registered evidence) states its own retention bound.

Revocation for a known or suspected compromise is distinct from routine
retirement: the issuer publishes the compromised key as revoked, or
marks it with a compromise time, rather than only rotating it out.

A compromised issuer signing key voids every guarantee the signature
carries. Holding issuer signing keys in non-exportable, HSM- or
KMS-grade custody with dual-controlled generation reduces that risk.
Segmenting keys by artifact class under distinct `kid` values within the
one `jwks_uri` lets high-value, low-volume signing (long-lived evidence
and portable artifacts) sit under stricter custody than high-volume
token signing; verification is `kid`-indexed, so this needs no wire
change. Recovery from a signing-key compromise follows the deployment's
documented procedures.

## Composition and Residual Authority {#sec-composition}

### Compromised or Over-Broad Derivation {#compromised-or-over-broad-derivation}

The AS is trusted to derive authority no broader than the Mission
Intent. Both derivation modes ({{authorization-derivation}}) are
mechanical, a proposal narrowed to policy or a configured mapping,
rather than free-form inference, and the recorded `policy_version`
names the policy a derivation ran under so the derivation can be
audited.

### Authority Hash Is Not a Mission Identifier {#authority-hash-is-not-a-mission-identifier}

`authority_hash` commits the approved Authority Set, not the Mission:
two Missions that approve byte-identical authority (a successor that
re-approves the same Authority Set, or an unrelated Mission with the
same derived authority) share it while differing in `intent_hash`,
`approver`, and `id`, which is why {{integrity-anchors}} forbids its
use as a Mission Identifier or as a replay or idempotency key.

A consumer that needs to bind to or correlate a specific Mission uses
the Mission Identifier, and `intent_hash` and `approver` distinguish
Missions that share an Authority Set. Where a deployment discloses
`authority_hash` to a resource server, it is an audit correlator, not an
enforcement input, and not proof that the carried entries are a subset
of the approved set.

### Composition and the Effective Ceiling {#composition-and-the-effective-ceiling}

Delegation depth ({{delegation-constraints}}) resets to 0 at each
cross-domain hop ({{I-D.draft-mcguinness-oauth-mission-cross-domain}})
and, where a deployment runs the child-delegation profile, at each child
generation ({{I-D.draft-mcguinness-oauth-mission-child-delegation}}).

The aggregate surface that a Mission's descendants can reach (the
product of delegation depth, the number of trust domains projected into,
and the number of child generations) can therefore exceed what a
single approval appears to bound at consent time. This is a composition
property of independently bounded mechanisms.

Child Delegation's `max_children` and `max_child_depth` limit the
descendant Missions live at once, not those created over the root's
lifetime: a child that reaches a terminal state frees its slot
({{I-D.draft-mcguinness-oauth-mission-child-delegation}};
{{I-D.draft-mcguinness-oauth-mission-derivation-limits}} works an
example).

Cross-domain projection composes separately: a projected grant preserves
the Mission's lineage rather than rooting a new one, and the Resource
AS's local issuance under it is bounded by that grant's own lifetime and
local policy.

A deployment can disclose the subtree's figures, not only the
immediate Mission's, at the consent surface, as distinct values
rather than one composed total
({{I-D.draft-mcguinness-oauth-mission-child-delegation}}), and can
impose a global cap out of band where a single approval's apparent
bound must hold in practice.
Bounding aggregate consumption (calls, spend, or activity over the life
of a Mission and its descendants) is the metering profile's role
({{I-D.draft-mcguinness-mission-metering}}).

### The Containment Materialized-Capability Residual {#the-containment-materialized-capability-residual}

Where a deployment runs the Mission Containment profile
({{I-D.draft-mcguinness-oauth-mission-containment}}), containment
narrows an Authority Set entry's authorization to derive going forward
and propagates to Child Missions justified by that entry. It does not
reach authority materialized before the containment transition: a
cross-domain grant already redeemed at a Resource AS
({{I-D.draft-mcguinness-oauth-mission-cross-domain}}), or an offline
attenuation root already minted and attenuating outside the issuer's
reach, operates for its own remaining lifetime, the same residual bound
that revocation carries ({{revocation}}). Where containment needs to
take effect quickly against already-materialized authority, short
cross-domain grant and offline attenuation root lifetimes keep that
residual window to one the next lease or re-mint closes.

# Privacy Considerations {#privacy-considerations}

The privacy considerations of {{Section 13 of RFC9396}},
{{Section 8 of RFC9126}}, and {{Section 6 of RFC9068}} apply to this
document, as do those of {{Section 5 of RFC7662}} for introspection and
{{Section 6 of RFC8693}} for delegation.

A Mission Identifier is a correlation handle: a deployment limits
exposure by giving stable Mission Identifiers only to parties that
enforce, audit, or observe that Mission, preferring audience-scoped
projections of authority where possible, and minimizing status and
introspection disclosures to authorized callers
({{caller-authorization-and-minimization}}).

## Mission Identifier Correlation {#mission-identifier-correlation}

This document carries a single canonical Mission Identifier on every
derived token, and the companion's cross-domain projection carries it
across trust domains unchanged
({{I-D.draft-mcguinness-oauth-mission-cross-domain}}). Any party that
observes credentials for the same Mission, whether a resource server, a
Resource AS, or an auditor spanning audiences, can correlate that
activity by the Mission Identifier, and `mission.issuer` further
identifies the issuing AS.

That stable anchor is what lets a resource server, a cross-domain
Resource AS, and an auditor bind credentials and evidence to one
approved Mission; this document does not provide cross-audience
unlinkability ({{non-goals}}).

Audience-pairwise (or request-pairwise) Mission references, in which the
issuer projects a distinct opaque identifier per audience and resolves
them server-side, are the fuller mechanism for unlinkability; they work
against the stable anchor, and this document does not define them. A
deployment that carries the canonical Mission Identifier on the wire
accepts this correlation as part of its privacy posture; the operative
control is limiting who receives the stable identifier, per the guidance
above.

## Token Payload Disclosure {#token-payload-disclosure}

The carried `constraints` and a multi-resource Authority Set disclose
the shape of the task and its business bounds (for example, an amount
ceiling) to every holder and every audience of a derived token.
Single-audience tokens, one per resource server, are the minimization
measure: they carry only the
entries the consuming resource server needs, as
{{Section 2.3 of RFC9700}} recommends ({{mission-bound-tokens}}).

## Intent Retention and Anchor Disclosure {#intent-retention-and-anchor-disclosure}

The Mission Record's Intent members (`goal`, `task_bounds`) are
personal-data sinks: they carry whatever task description the user
supplied, and their retention and erasure follow {{record-access}}. The
integrity anchors are unsalted commitments: a party holding a candidate
Intent can confirm it against `intent_hash`, and a candidate proposal
against `proposal_hash`. Over low-entropy or guessable content each
anchor is therefore a disclosure channel, and deployments treat it as
one when the Intent itself is sensitive.

## Third-Party Data Subjects {#third-party-data-subjects}

A task can be about a person who holds no Mission role: in a background
check, the employer's agent queries a registrar about a candidate who is
neither Subject nor Approver nor resource owner. Mission approval
records the accountable Approver's authorization of the undertaking
({{approval-event}}); it is not, by itself, evidence of such a person's
consent to disclosure or of any other legal basis a disclosure requires.
Whether a basis is required, and what satisfies it, is deployment and
legal policy outside this protocol.

Where the resource domain requires data-subject consent or another
basis, that domain's own lane (the resource server, a gateway, a policy
decision point, or an authorization server acting for the domain)
evaluates it through that lane's mechanisms, such as claims gathering or
a resource-domain consent artifact. That lane refuses access while
required evidence is absent or invalid; the refusal is the resource's
answer, and Mission authority does not override it.

Mission approval and Mission authority are not the data subject's
consent: a Mission Record can retain a verified consent reference or
facts as `submission_evidence` ({{mission-record}}), and those facts are
provenance and policy input only, which the resource domain validates
independently under its current disclosure policy.

Third-party personal data can enter through any Intent, proposal,
authority, or recorded-evidence member:

- the prose members (`goal`, `task_bounds`, `success_criteria`) and
  `purpose`;
- `target_resources` and any explicit member a companion profile defines
  (for example, the metering companion's consumption bounds,
  {{I-D.draft-mcguinness-mission-metering}});
- any type-owned member of a proposed entry, and the derived Authority
  Set entries that reach tokens ({{mission-bound-tokens}});
- `submission_evidence` facts, including a consent reference.

Whatever the member, it persists on the Mission Record for its audit
horizon ({{mission-record}}), concentrates at the AS with the record
({{record-access}}), and, if committed, is confirmable through the
unsalted anchors by any party holding a candidate value
({{intent-retention-and-anchor-disclosure}}). Referencing a third party
through resource-scoped or pseudonymous identifiers, rather than
identifying prose, minimizes this exposure; an opaque identifier is
minimization, not anonymity, and personal-data obligations follow it.

## Mission Record and Evidence Access {#record-access}

The Mission Record concentrates the task, its authority, and its
principals at the AS, and every evidence artifact joins on the Mission
Identifier, so the join is a correlation surface equal to the identifier
itself. Tokens carry references and authority, not the record: nothing
in this document puts `goal`, `task_bounds`, or other Intent content in
a credential. An Intent Submission Evidence artifact can carry personal
data (an originator identity, a consent reference); PAR keeps it off the
front channel, and the record retains the designated verified facts
under the same access governance as the rest of the Mission's evidence.

Access to the record and to Mission evidence is policy-governed and
auditable: reading a Mission's evidence is a privileged operation, not a
byproduct of holding a Mission reference. Retention and erasure are
deployment policy, bounded below by the audit horizon
({{mission-record}}). Where approval-event evidence was registered under
the audit transparency profile ({{I-D.draft-mcguinness-mission-audit}}),
its erasure record and data-subject-request basis are the
transparency-side mechanism: it records an erasure but neither performs
one nor overrides retention law, and it leaves the operational Mission
Record and its audit-horizon retention floor untouched.

# Internationalization Considerations {#i18n}

Mission Intent prose (`goal`, `task_bounds`, `success_criteria`) is
human-readable disclosure. `goal_lang` ({{mission-intent}}) declares the
language of that prose as a BCP 47 language tag {{RFC5646}}, so an
approval surface can render, translate, or route it without guessing the
language.

Three rules apply to the declaration:

- `goal_lang` is a syntactic declaration: the AS checks only its
  well-formedness ({{mission-intent}}), not that the prose is in the
  declared language, so the tag is not a verified property of the text.
- Rendering to the Approver follows the rendering rules of
  {{approval-event}} unchanged: client prose stays inert text in any
  language and any script, including bidirectional text. Where the
  approval surface presents a translation, the rendered disclosure is
  what the deployment's consent evidence records (Mission Consent
  Evidence binds one locale, one disclosure, one hash,
  {{I-D.draft-mcguinness-oauth-mission-consent-evidence}}); `goal_lang`
  declares the source's language and is not a record of what was
  rendered.
- Authority Set entries carry machine-facing identifiers (URIs, action
  strings, structured constraints), not prose, and this document adds no
  language-tagged display fields to them. Localizing how authority is
  explained is the approval surface's duty under {{approval-event}}, not
  a property of the committed set.

# IANA Considerations {#iana}

## OAuth Parameters Registration {#oauth-parameters-registration}

This document requests registration of the following in the "OAuth
Parameters" registry:

- Name: `mission_intent`
- Parameter Usage Location: authorization request
- Change Controller: IETF
- Specification Document(s): this document, {{submission-via-par}}

- Name: `mission_id`
- Parameter Usage Location: token response
- Change Controller: IETF
- Specification Document(s): this document, {{grant-binding}}

- Name: `mission_error`
- Parameter Usage Location: token response
- Change Controller: IETF
- Specification Document(s): this document, {{lifecycle}}

- Name: `mission_expires_at`
- Parameter Usage Location: token response
- Change Controller: IETF
- Specification Document(s): this document, {{grant-binding}}

PAR {{RFC9126}} carries authorization-request parameters without a
distinct usage location, so the pushed submission of `mission_intent`
needs no separate registration. The `mission_error` member is carried in
the token-endpoint error response, for which "token response" is the
registry's applicable usage location; it uses the error response's JSON
extensibility rather than defining a new `error` code. The
`mission_denial` attribute uses the extensible auth-param space of the
`WWW-Authenticate` scheme ({{RFC6750}}, {{rs-enforcement}}), for which
no IANA registry exists; no action is required for it.

## OAuth Extensions Error Registration {#oauth-extensions-error-registration}

This document requests registration of the following in the "OAuth
Extensions Error" registry {{RFC6749}}:

- Name: `invalid_mission_intent_evidence`
- Usage Location: authorization endpoint, token endpoint
- Protocol Extension: Intent Submission Evidence
  ({{intent-submission-evidence}})
- Change Controller: IETF
- Specification Document(s): this document,
  {{intent-submission-evidence}}

A code distinct from `invalid_request` lets a client tell a malformed
submission from missing or untrusted evidence, and remedy each
differently.

## JSON Web Token Claims Registration {#json-web-token-claims-registration}

This document requests registration of the following in the "JSON Web
Token Claims" registry:

- Claim Name: `mission`
- Claim Description: Reference to the Mission a token was derived
  under.
- Change Controller: IETF
- Specification Document(s): this document, {{mission-claim}}

## OAuth Token Introspection Response Registration {#oauth-token-introspection-response-registration}

This document requests registration of the following in the "OAuth Token
Introspection Response" registry ({{RFC7662}}):

- Name: `mission`
- Description: The Mission a token was derived under, with its current
  lifecycle state when returned by the Mission's issuer
  ({{introspection}}).
- Change Controller: IETF
- Specification Document(s): this document, {{introspection}}

## OAuth Authorization Server Metadata Registration {#oauth-authorization-server-metadata-registration}

This document requests registration of the following in the "OAuth
Authorization Server Metadata" registry ({{RFC8414}}):

- Metadata Name: `mission_bound_authorization_supported`
- Metadata Description: Boolean indicating that the authorization
  server supports the Mission Issuer core surfaces of this document.
- Change Controller: IETF
- Specification Document(s): this document, {{discovery}}

## OAuth Protected Resource Metadata Registration {#oauth-protected-resource-metadata-registration}

This document requests registration of the following in the "OAuth
Protected Resource Metadata" registry ({{RFC9728}}):

- Metadata Name: `mission_bound_authorization_required`
- Metadata Description: Boolean indicating that the protected resource
  accepts only Mission-bound tokens.
- Change Controller: IETF
- Specification Document(s): this document, {{protected-resource-metadata}}

## Mission Lifecycle States Registry {#iana-lifecycle-states}

IANA is requested to create the "Mission Lifecycle States" registry.
The registration policy is Specification Required {{RFC8126}}.

A Designated Expert reviews a submission for the discipline
{{lifecycle}} requires:

- a `Value` matching `^[a-z][a-z0-9_]*$` not already registered;
- a `Terminal` designation of `yes` or `no` consistent with the
  transitions the registrant's specification defines (a `yes` state
  admits no further transition; a `no` state does); and
- a `Semantics` sentence precise enough to distinguish the state from
  every registered state.

Whether a Mission in any state is available for reliance is fixed by the
governing rule below, never per row.

Only the exact value `active` permits token derivation or continued
reliance; a consumer treats every other value, including one it does
not recognize, as non-`active` and never widens on it ({{lifecycle}}).
A Designated Expert MUST reject a registration whose governing
specification attempts to redefine this interaction rather than adding
a new value bound by it.

Each registration records:

- **Value**: the lifecycle state's string value.
- **Terminal**: `yes` if the state admits no further transition, `no`
  otherwise.
- **Semantics**: one sentence stating what the state means and, for a
  non-terminal state, what a Mission in that state cannot do.
- **Change Controller**: IETF, or the registrant for any other
  registration.
- **Reference**: the specification defining the state.

This document seeds the registry with the states it defines:

| Value | Terminal | Semantics | Change Controller | Reference |
|---|---|---|---|---|
| `active` | no | The only state from which tokens are derived. | IETF | this document, {{lifecycle}} |
| `revoked` | yes | Terminated by the Subject, Approver, or policy. | IETF | this document, {{lifecycle}} |
| `expired` | yes | The Mission's `expires_at` has passed. | IETF | this document, {{lifecycle}} |

Each further document that defines a lifecycle state requests that
state's registration in its own IANA considerations.

## Mission Intent Members Registry {#iana-intent-members}

IANA is requested to create the "Mission Intent Members" registry.
The registration policy is Specification Required {{RFC8126}}.

A Designated Expert reviews a submission for:

- a `Name` not already registered by a different owning
  specification; and
- a `Semantics` sentence naming what the member means and which
  specification defines its schema, production, and enforcement in
  full.

The registry resolves ownership of a short top-level name, so that
two independently implemented specifications cannot assign it
incompatible schemas. Registration defines no member semantics and
confers no authority ({{extensibility}}). A companion profile can
instead use a collision-resistant name without registering it.

Each registration records:

- **Name**: the member's top-level key in the Mission Intent.
- **Status**: `stable` or `experimental`. An `experimental` entry's
  owning specification has not completed that specification's own
  promotion criteria for the member. A Designated Expert MUST NOT
  register a member as `stable` without confirming that its owning
  specification's promotion criteria are met, and MUST NOT treat
  registration itself as a promotion event for an experimental
  member.
- **Semantics**: one sentence stating what the member means and
  pointing to the section that fully defines it.
- **Change Controller**: IETF, or the registrant for any other
  registration.
- **Reference**: the specification defining the member.

This document seeds the registry with the members it defines itself:

| Name | Status | Semantics | Change Controller | Reference |
|---|---|---|---|---|
| `goal` | stable | The Mission's plain-language objective. | IETF | this document, {{mission-intent}} |
| `goal_lang` | stable | BCP 47 language tag for `goal`. | IETF | this document, {{mission-intent}} |
| `target_resources` | stable | Client-requested derivation ceiling and configured-mapping lookup key. | IETF | this document, {{mission-intent}} |
| `task_bounds` | stable | Non-machine-readable prose bounds on the task. | IETF | this document, {{mission-intent}} |
| `purpose` | stable | URI identifying the task's purpose. | IETF | this document, {{mission-intent}} |
| `expires_at` | stable | Requested Mission expiry ceiling. | IETF | this document, {{mission-intent}} |
{: title="Core-defined Mission Intent members"}

Each further document that defines a Mission Intent member requests that
member's registration in its own IANA considerations.

--- back

# End-to-End Example {#e2e-example}

This appendix walks one Mission from an agent through Mission
creation, token issuance, and resource server enforcement in a single
trust domain. It is illustrative and adds no requirements. The OAuth
steps follow this document; the identity setup follows
{{I-D.draft-ietf-wimse-aims}}. Identifiers and hash values are
illustrative and are not computed from the displayed JSON.

The walkthrough is the baseline issuance path: stateless enforcement
bounded only by token lifetime. No stage calls back to the AS for
Mission state. Stage 3 notes where the optional runtime layer adds a
point-of-use check.

Scenario: agent `s6BhdRkqt3`, acting for `alice`
(`user_3p2q8mN1a0kV7tR`), reconciles Q3 invoices in the home ERP
under Mission `msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-`.

## Stage 0: Agent Identity (by Reference) {#stage-0-agent-identity-by-reference}

The agent is an OAuth client with a workload identity, for example
one established using WIMSE {{I-D.draft-ietf-wimse-arch}} or SPIFFE
{{I-D.draft-ietf-oauth-spiffe-client-auth}}. `alice` has delegated to
it through an ordinary authorization code flow, per
{{I-D.draft-ietf-wimse-aims}}: `client_id` is the agent, and the
token `sub` is `alice`. This document adds the Mission layer on top
of that identity; Stage 0 is otherwise unchanged from that
specification.

## Stage 1: Mission Creation {#stage-1-mission-creation}

The agent submits this Submission envelope through PAR
({{submission-via-par}}), carrying the Mission Intent and no
evidence, and proposing concrete authority alongside it on the
`authorization_details` parameter ({{authority-proposal}}):

~~~ json
{
  "intent": {
    "goal": "Reconcile Q3 invoices and post adjustments under $500.",
    "target_resources": ["https://erp.example.com"],
    "task_bounds": [
      "Read only invoices issued in 2026-Q3.",
      "Post journal entries under $500."
    ],
    "success_criteria": [
      "All Q3 invoices reconciled.",
      "Each posted adjustment references a source invoice."
    ],
    "purpose": "urn:example:purpose:reconcile",
    "expires_at": "2026-12-31T23:59:59Z"
  }
}
~~~

The submitted authority proposal, on `authorization_details` in the
same push:

~~~ json
[
  { "type": "mission_resource_access",
    "resource": "https://erp.example.com",
    "actions": ["invoices.*"],
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

The AS (`as.example.com`) validates both, derives this Authority Set
(each entry a same-type subset of a proposed entry,
{{authority-proposal}}), and renders it for `alice`'s consent:

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
`sha-256:l3KvZ4mP5x0wQrR6tY2nD9bM7sX1cF8gH2vJ4kE5pNQ`,
`intent_hash`
`sha-256:wQ7p4LHnX9Md0LqJ6sZJ8b8mZ3rN2xT5pV4lE6sQqYY`, and
`proposal_hash`
`sha-256:kT2mR7vX4qL9nY5pB1sD8fJ6wZ3hC0aGeUoNvSqMrYo`.

## Stage 2: Mission-Bound Token Issuance {#stage-2-mission-bound-token-issuance}

The agent redeems the authorization code at the token endpoint. The
AS resolves the Mission from the grant ({{grant-binding}}), gates on
it being `active` ({{lifecycle}}), and issues a Mission-bound access
token for the ERP. The token response carries the granted
`authorization_details` echo ({{mission-bound-tokens}}) and the
`mission_id` and `mission_expires_at` response parameters
({{grant-binding}}):

~~~ json
{
  "access_token": "eyJhbGciOiJFUzI1NiIsInR5cCI6ImF0K2p3dCJ9...",
  "token_type": "DPoP",
  "expires_in": 300,
  "mission_id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
  "mission_expires_at": "2026-12-31T23:59:59Z",
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
  ]
}
~~~

The following is the decoded access token payload:

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
    "issuer": "https://as.example.com"
  }
}
~~~

The token carries everything enforcement needs: the audience, the
sender constraint (`cnf`), the authority with its constraints, and
the `mission` claim naming the Mission it was derived under. Its
300-second lifetime ends well before the Mission's `expires_at`.
Revoking the Mission stops further derivation; this token remains
valid until its own `exp` ({{revocation}}).

## Stage 3: The Resource Server Enforces {#stage-3-the-resource-server-enforces}

The agent calls the ERP resource server (`erp.example.com`) with that
token. The resource server validates the JWT and the `cnf` binding and
enforces the `authorization_details` whose `resource` it serves,
permitting `invoices.read` within the Q3 issuance window and
`journal-entries.write` up to the `max_amount` ceiling of 500.00 USD
({{rs-enforcement}}). It treats the `mission` claim as audit and
correlation context and makes no call to the AS.

This is stateless enforcement from the token alone: the baseline
bounds the consequential `journal-entries.write` only by token
lifetime and the carried constraints. Where the deployment runs the
runtime profile ({{I-D.draft-mcguinness-mission-runtime}}), the
resource server also obtains a point-of-use permit from a policy
decision point, against current Mission state, before executing the
write.

The end-to-end example of the Mission Cross-Domain Projection profile
({{I-D.draft-mcguinness-oauth-mission-cross-domain}}) continues this
Mission to a partner ERP in another trust domain.

# Design Context and Boundaries {#design-context}

This appendix explains the design choices behind the Mission and
records what this document leaves to other work.

## Relationship to Existing OAuth Objects {#why-a-new-object}

OAuth already has objects near this need, but none is the approved
task:

- A `scope` value or an `authorization_details` entry
  ({{RFC9396}}) expresses authority but neither the task it serves
  nor a lifecycle of its own.
- An access token is a short-lived projection; its `jti` identifies
  the token, not the task.
- A refresh token preserves the ability to obtain further tokens but
  commits no bounded, approved authority.
- A consent record proves that an approval event happened; it does
  not govern the resulting work as it continues.

The Mission is the durable object these project from: the approved
task that bounds and outlives them, and that every derived token
refers back to. It is therefore not another `authorization_details`
type. Rich Authorization Requests already express authority; what
OAuth lacks is the approved task with a lifecycle, the durable,
approval-backed object an Authority Set is derived for and gated by.

## Relationship to Adjacent Work {#adjacent-work}

A grant, in the sense of FAPI Grant Management {{FAPI.GrantManagement}},
is a durable, queryable, revocable container of consented
authorization data. It records consent to authority but carries no
task, no integrity commitment, and no derivation gating; a deployment
can surface Mission revocation through a grant-management-style API
({{revocation}}).

{{I-D.draft-ietf-wimse-aims}} names the agent's mission and leaves its
translation into authorization requirements out of scope. This
document specifies that translation, reusing its agent-as-client and
delegating-principal-as-token-`sub` assignments unchanged
({{principal-model}}); an agent authenticated and delegated per it
uses the mechanisms here to obtain Mission-bound tokens.

Decision-layer access-request and approval workflows, such as the
OpenID AuthZEN Access Request and Approval Profile {{AuthZEN.ARAP}},
manage approval tasks but do not tie an approval to token issuance;
this document supplies the issuance-bound object such workflows
complete into.

Nearby individual proposals each carry one Mission property without
the others: task-linked Rich Authorization Requests with revocation
webhooks carry a task link, intent-digest admission assertions carry
an intent commitment, and offline capability attenuation
({{I-D.draft-niyikiza-oauth-attenuating-agent-tokens}}) carries
offline narrowing. None combines the durable approved object,
state-gated issuance, and integrity anchors this document defines.

The Grant Negotiation and Authorization Protocol {{RFC9635}} occupies
much of the same design space: a continuable authorization request,
richer client instance identification, and native support for
delegation. Rather than introduce a new grant protocol, endpoints,
and client machinery, this document composes with the OAuth 2.0
surfaces already deployed: Pushed Authorization Requests
({{RFC9126}}), Rich Authorization Requests ({{RFC9396}}), DPoP
({{RFC9449}}), and {{RFC9068}} access tokens. A deployment that
already runs PAR, RAR, and sender-constrained tokens adopts the
Mission model without standing up a GNAP grant endpoint or migrating
its clients to it.

The Authority Set's subset rule ({{subset}}) continues the lineage of
capability systems in which a holder narrows what it passes on
without further contact with an issuer: macaroons' caveat narrowing,
Biscuit's offline attenuation blocks, UCAN's delegation chains,
SPKI/SDSI's local-name reduction, and object-capability designs
generally. What this document narrows is a durable, approval-anchored
object that its issuer can revoke for the Mission's full lifetime,
not a bearer credential whose only life is its caveats, so revoking
the Mission still reaches everything derived from it that has not
already left the issuer's reach ({{revocation}}).

## The Mission, the Plan, and Execution {#the-mission-the-plan-and-execution}

The Mission is the durable, AS-held object that commits the approved
authority and owns the task's lifecycle. Two related things an agent
produces around a task are not the Mission and carry no authority of
their own.

The agent's **plan**, how it decomposes the task, chooses tools, and
delegates to sub-agents, is the agent's own strategy and is out of
scope for this document. It grants nothing: authority a sub-agent
exercises is carried on its delegated token ({{delegation}}), derived
from the Mission and only narrowed from it ({{subset}}), not created
by the plan.

The agent's **execution**, the tokens it derives, the calls it makes,
and the decisions taken on them, references the Mission but cannot
expand it. Revoking the Mission stops further derivation
({{lifecycle}}); it does not undo actions already completed.
Evaluating each action against the Mission at the point of use is the
runtime layer's concern ({{runtime-boundary}}), not this document's.

Across all three, the plan and the execution draw on the Mission's
authority; neither enlarges it.

How a client produces the Intent (for example, a "Mission Shaper"
deriving it from a natural-language instruction) is out of scope for
this document.

## Scope and Future Work {#scope-and-future-work}

This document is self-contained: it binds Missions to OAuth 2.0 and
is implementable on its own, depending only on the OAuth and JOSE
specifications it cites.

It references the OAuth Actor Profile
({{I-D.draft-mcguinness-oauth-actor-profile}}) for the `act` chain
shape the optional Delegation capability uses. That reference is
informative and confined to Delegation, so the mandatory
single-domain core does not depend on it.

Cross-domain projection, a single hop that lets an authorization
server in another trust domain honor a Mission, is specified by the
companion Mission Cross-Domain Projection profile
{{I-D.draft-mcguinness-oauth-mission-cross-domain}}, which carries the
identity-chaining and ID-JAG dependencies with it. The Cross-Domain
capability's conformance bar is self-contained in this document
({{conformance}}), so that companion is not a normative dependency.

Separate from this document, and not required to implement it,
several capabilities are specified as optional companion profiles:

- an additional integrity anchor over a structured consent
  disclosure (`consent_rendering_hash`, {{consent-binding}}), defined
  by Mission Consent Evidence
  {{I-D.draft-mcguinness-oauth-mission-consent-evidence}};
- mission expansion, defined by Mission Expansion
  {{I-D.draft-mcguinness-oauth-mission-expansion}}; and
- a cross-domain status or event-distribution mechanism for tighter
  revocation, defined by Mission Status
  {{I-D.draft-mcguinness-oauth-mission-status}} and Mission Lifecycle
  Signals {{I-D.draft-mcguinness-oauth-mission-signals}}.

Future work includes:

- the normative carriage of Mission context in Transaction Tokens
  ({{I-D.draft-ietf-oauth-transaction-tokens}}), shown only
  illustratively in the companion's end-to-end example; and
- for a community that wants cross-vendor agreement on what a task
  authorizes within a vertical, an optional derivation profile: a
  registry of standard task types mapped to authority templates, so
  that two vendors in that profile derive comparable Authority Sets.
  This document does not standardize the derivation algorithm itself
  ({{authorization-derivation}}); a vertical profile is the
  appropriate vehicle where portable derivation is needed.

This document defines no mechanism that pins a Mission to an
approved agent deployment class or version, and reserves no Intent
member for one. Such a pin needs two objects rather than one Intent
member: a committed approval-context pin, and presenter-instance
evidence checked at every derivation (for example, using
{{I-D.draft-mcguinness-oauth-client-instance-id}} and
{{I-D.draft-mcguinness-oauth-client-attesters}}). A profile that
defines the pin also defines its request carriage and resolution to
an approved deployment identifier, its Mission Record extension and
approval rendering, and its fail-closed behavior when the client
cannot prove the pin.

This document defines no cumulative consumption bounds (for example, a
budget, call-count, or activity-duration cap). An
experimental companion defines cumulative consumption bounds as
explicit Mission Intent extension members together with the runtime
metering that enforces them ({{I-D.draft-mcguinness-mission-metering}}).

## Non-Goals {#non-goals}

The following are out of scope for this document:

- **Semantic / intent verification.** This document binds a token to
  an approved authority and task; it does not evaluate whether a
  given runtime action serves the Mission's purpose beyond matching
  the approved `authorization_details` and `constraints`. Per-action
  evaluation is the runtime layer's role ({{runtime-boundary}}).
  Verifying an agent's declared reasoning against the task is a
  further attestation problem outside both layers.
- **Joint outcome and cross-resource effects.** Whether the actions
  taken under a Mission jointly accomplish its task is outside this
  document, as are the ordering, timing, atomicity, and compensation
  of their effects across resource servers. The `mission` claim joins
  requests to an approval for issuance and audit; it does not
  identify a business transaction.
- **Approval-free authorization upgrade.** The Authority Set is
  committed at approval; this document defines no mid-stream widening
  that bypasses consent. Widening requires a new approval, a successor
  Mission, as specified by Mission Expansion
  {{I-D.draft-mcguinness-oauth-mission-expansion}}; a widening that
  no consent authorizes is out of scope.
- **Lifecycle event distribution.** A resource server learns Mission
  state from the token lifetime or optional introspection
  ({{introspection}}); this document defines no push-based
  notification of Mission state changes. A Shared Signals
  ({{RFC8935}}) / CAEP profile for Mission lifecycle events is
  specified separately by the Mission Lifecycle Signals profile
  ({{I-D.draft-mcguinness-oauth-mission-signals}}).
- **Human-in-the-loop suspension.** The base lifecycle is `active`,
  `revoked`, `expired` ({{lifecycle}}). A `suspended` state with
  `resume`/`complete` transitions is defined as an optional extension
  by Mission Status ({{I-D.draft-mcguinness-oauth-mission-status}});
  a pending-human-approval state and a holding-token pause-and-resume
  protocol are future lifecycle work.
- **Multi-hop cross-domain projection.** A single projection hop is
  specified by Cross-Domain Projection
  ({{I-D.draft-mcguinness-oauth-mission-cross-domain}}); recursive
  delegation across organizations is profiled by Mission
  Cross-Organizational Delegation
  ({{I-D.draft-mcguinness-oauth-mission-cross-org-delegation}}), whose
  chain a destination verifies before projecting. Re-projecting a
  Mission from one Resource AS into a further domain is future work.
- **Decentralized agent identity.** Agent identity and credentialing
  are out of scope ({{I-D.draft-ietf-wimse-aims}} and the WIMSE
  architecture, {{I-D.draft-ietf-wimse-arch}}); this document governs
  the approved-task artifact those identities act within, not the
  identities themselves.
- **Cross-audience unlinkability.** A single canonical Mission
  Identifier lets any party holding a token correlate a Mission's
  activity across audiences and resources. A stable, correlatable
  identifier is what lets a resource server, a cross-domain Resource
  AS, and an auditor bind evidence to one approved Mission, which is a
  core goal of this document. `authority_hash` is not part of that
  baseline correlation surface: it stays on the Mission Record and the
  audit and profile surfaces that carry it by disclosure privilege
  ({{mission-claim}}), rather than traveling by default on every
  token. Pairwise or unlinkable presentation of Mission-bound
  authority works against the identifier and is therefore future work
  ({{mission-identifier-correlation}}).

## The `client_id` Claim in Delegated Tokens {#client-id-rebinding}

This profile keeps `client_id`'s registered meaning, stated
normatively in {{mission-bound-tokens}} and enforced in
{{rs-enforcement}}: the OAuth client that requested the token, on
every issued or derived token, a delegated one included. Downstream
delegates are named in the `act` chain ({{delegation}}), and the
Mission's originally-approved agent remains recorded in the Mission
Record ({{mission-record}}), without redefining a registered claim.

The alternative, fixing `client_id` to the approved agent on every
derived token, would lead a generic {{RFC9068}} resource server or
logging pipeline to attribute a delegate's action to the approved
agent with no error to surface the mismatch. It would be safe only
where every resource server already processes the `act` chain, as a
Mission-aware Resource Server does ({{rs-enforcement}}). The routing
rule of {{rs-enforcement}} does not depend on this choice: the
`mission` claim's presence signals that a token may carry an `act`
chain a consumer needs to process, a Mission-unaware resource server
cannot opt into that processing, and routing a delegated token to one
is therefore forbidden.

# Role Mapping {#role-mapping}

`approval_basis` separates three questions about a Mission's own
creation, and a scenario can assign them to different principals: who
is accountable for it (`consent_principal`), who or what triggered it
(`activation_actor`), and what decided it (`adjudication`). The
companion profiles below define the scenarios; this table names how
each assigns the three roles.

| Scenario | Accountability root (`consent_principal`) | Activation actor (`activation_actor`) | Adjudication (where a profile or deployment populates it) |
|---|---|---|---|
| Direct approval | The approving human | Equal to `consent_principal`: the Approver triggers their own approval | `kind: human`; the deciding human is `consent_principal` itself |
| Relocated human approval ({{I-D.draft-mcguinness-oauth-mission-approval}}) | The human who completes the relocated approval event | Equal to `consent_principal`, unchanged from the direct case: the instance activates at that human's decision, not at any earlier submission | `kind: human`, as direct |
| Template dispatch ({{I-D.draft-mcguinness-oauth-mission-template}}) | The template's human approver, fixed at template creation | The Dispatcher that requested the Dispatch, distinct from `consent_principal` | `kind: policy`, `policy` naming the template's `dispatch_policy` `id` and `version` (already carried in the dispatched Mission's `template` lineage member), never the Template's own `id`/`template_version` nor the Dispatcher |
| Policy drawdown ({{I-D.draft-mcguinness-oauth-mission-child-delegation}}) | The Parent Mission's human Approver | The requesting parent Agent, distinct from `consent_principal` | `kind: policy`, naming the child-creation policy's `id`/`version` where the entry carries one, otherwise the Parent Mission's approved delegation entry; never the requesting parent Agent |
| Ceiling drawdown ({{I-D.draft-mcguinness-oauth-mission-progressive}}) | The Approver who consented the ceiling | The requesting client, distinct from `consent_principal` | `kind: policy`, naming the drawdown policy's `policy_id`/`policy_version` carried in `activation`; never the requesting client |
| AGR-backed approval ({{I-D.draft-mcguinness-mission-approval-governance}}) | The principal the Approval Governance Record's accountable assertion names, equal to `consent_principal` | Unchanged from the underlying basis | `governance_record: true`; `kind` equals the record's accountable assertion's own mechanism (`human` or `policy`), never a value that names the record itself, and its full assertion set is never collapsed into a single principal |

Direct approval is the degenerate case where one human fills every
role. Where a profile or deployment does not populate `adjudication`
({{mission-record}}), the table shows the value it would carry.

# Derivation Policy {#derivation-policy}

This appendix is illustrative and adds no requirements. It
describes an authoring artifact for the contract in
{{authorization-derivation}}, not a standardized policy language or an
alternative subset relation.

## The Policy as an Artifact

A deployment retains a versioned derivation policy with its ceiling,
configured mappings, and issuance limits. Its inputs include a
validated Mission Intent, the client's authority proposal in
narrowing mode (or configured candidates when there is no proposal),
the applicable authority source ceiling, the capability catalog's
per-action properties, and any recorded model output. The output is
the Authority Set committed by `authority_hash`; `policy_version`
identifies the policy used. The policy is not transmitted; its
identifier and published Intent-to-Authority-Set fixtures let a
partner review outcomes.

Reproducing a derivation requires the same inputs and the retained
policy and catalog versions, not just the identifier of a mutable
configuration. Replay uses a model's retained output and never reruns
the model. Derivation is mechanical: a model may suggest an Intent or
a proposal, or contribute a recorded input that refuses or narrows, and
does not make the approval-time narrowing decision.

## Properties a Derivation Policy Holds

The five properties below restate, for a policy author, what
{{authorization-derivation}} and the rules it cites require of a
derivation.

- **Deterministic.** The same Intent, proposal, ceiling, catalog, and
  recorded model output derive the same Authority Set, so
  `policy_version` can serve as an audit correlator
  ({{authorization-derivation}}).
- **Narrowing only.** Every derived entry is a subset of some proposed
  entry of the same type, under that type's own relation
  ({{authority-proposal}}, {{subset}}); in configured-mapping mode the
  configured candidates supply that comparison input. Retaining fewer
  JSON fields is not narrowing: dropping a restriction can grant more.
  Where the relation cannot decide, because two bounds are
  incomparable, the posture is conservative refusal ({{subset}}). For
  `mission_resource_access`, two amount caps naming different
  currencies have no intersection, with no implicit conversion and no
  "ceiling wins" exception;
  {{I-D.draft-mcguinness-oauth-mission-resource-access}} defines the
  Common Constraints and their intersection rules.
- **Refusal over silent drop.** An entry of an unsupported type, an
  entry that fails its schema, and an entry carrying a constraint the
  engine cannot compare, whether registered or deployment-defined,
  are refused ({{authority-proposal}}, {{subset}}, {{error-mapping}}).
  Derivation does not repair them by omitting the entry or dropping
  the constraint: a dropped constraint widens the grant. An entry the
  engine compares but policy cannot accept is the distinct case: it
  is narrowed or omitted, and the granted echo reflects that
  ({{authority-proposal}}).
- **Issuer-established members are not client-supplied.** The issuer
  establishes `policy_version` ({{authorization-derivation}}), and
  `authority_source` and `approval_basis` ({{authority-sources}},
  {{mission-record}}), at the approval event; no proposal member sets
  them.
- **No member the ceiling never granted.** A grant-shaped member absent
  from the ceiling, such as a per-entry `delegation` policy, stays
  absent from the derived entry, so a proposal cannot introduce a
  capability the policy did not confer. A restriction nested inside an
  already-granted delegation, such as `allowed_delegates`, narrows in
  the ordinary direction.

## A Worked Rule

Consider a catalog whose read actions supply no amount for a cap to
compare against, while a journal write does. The ceiling separates
those actions:

~~~ json
[
  { "type": "mission_resource_access",
    "resource": "https://erp.example.com",
    "actions": ["invoices.read", "journal-entries.read"] },
  { "type": "mission_resource_access",
    "resource": "https://erp.example.com",
    "actions": ["journal-entries.write"],
    "constraints": {
      "max_amount": { "amount": "500.00", "currency": "USD" } } }
]
~~~

The validated proposal also separates the read from the amount-bound
write:

~~~ json
[
  { "type": "mission_resource_access",
    "resource": "https://erp.example.com",
    "actions": ["invoices.read"] },
  { "type": "mission_resource_access",
    "resource": "https://erp.example.com",
    "actions": ["journal-entries.write"],
    "constraints": {
      "max_amount": { "amount": "900.00", "currency": "USD" } } }
]
~~~

The resulting Authority Set contains the proposed `invoices.read`
entry unchanged, and the proposed `journal-entries.write` entry with
`max_amount` narrowed to `500.00 USD`. The ceiling's unrequested
`journal-entries.read` does not appear. Each proposed entry
intersects the same-resource ceiling entries; an empty action
intersection contributes no authority.

Attaching the amount cap to a single mixed read and write proposal
does not reach that result: the read supplies no amount for the cap
to compare against, so the deployment refuses the proposal at intake
rather than letting derivation drop the cap from the read fragment.
A write proposal naming a different currency likewise cannot produce
the USD intersection shown. A proposal carrying a Common Constraint
this deployment does not compare is refused with the
`invalid_authorization_details` error code ({{error-mapping}}), not
derived with the constraint dropped. These are negative fixtures
alongside the positive result, not special cases that relax the
type's relation.

## Fixtures and Authoring Discipline

Versioned Intent and proposal fixtures with expected Authority Sets
make the optional publication in {{authorization-derivation}}
concrete. Reviewing their diffs on every policy change exposes
altered grants before approval. Fixtures cover empty intersections,
unknown constraints, incomparable values, and attempts to introduce
delegation, as well as normal template and narrowing outcomes, and
check each subset against both the proposal and the ceiling.

A further check runs the shipped configuration through intake,
derivation, and a real decision path, since a configuration that
loads does not thereby authorize its intended workload. Applying the
same entry checks at configuration load and at client intake keeps
those two surfaces from disagreeing.

## Ownership and Operational Signals

| Artifact | Owner | Responsibility |
|---|---|---|
| Derivation policy, ceilings, versions and issuance limits | Mission Issuer operator | Outer bounds and reproducible approval-time derivation |
| Capability catalog and action properties | Resource owner or service team | Supported operations and the facts their constraints can evaluate |
| Templates and configured mappings | Template author within issuer policy | Candidate authority for supported Intent shapes |

Templates amortize authoring across Missions and do not bypass the
ceilings. The unmapped-resource rate, template-hit rate, and
rule-exception rate show an operator where its policy authoring
remains incomplete.

# Integrity Anchor Test Vectors {#test-vectors}

These non-normative vectors let an implementation verify its anchor
computation ({{integrity-anchors}}, {{canonicalization}}) byte for
byte. All use the issuer `https://as.example.com`. Each
canonical-bytes block is the exact JCS {{RFC8785}} output: a single
line of UTF-8 with no whitespace outside string values. It is wrapped
here for layout only; removing the line breaks, and adding no
characters, recovers the canonical form. JCS sorts object member
names (so `iss` precedes `typ` precedes `value`; within an entry,
`actions` precedes `constraints` precedes `resource` precedes `type`;
and within `max_amount`, `amount` precedes `currency`) and preserves
array order.

`intent_hash`, over this Mission Intent as the envelope `value` with
`typ` `mission-intent`:

~~~ json
{
  "goal": "Reconcile Q3 invoices",
  "target_resources": ["https://erp.example.com"],
  "expires_at": "2026-12-31T23:59:59Z"
}
~~~

Canonical bytes of the envelope:

~~~ text
{"iss":"https://as.example.com","typ":"mission-intent","value":{"e
xpires_at":"2026-12-31T23:59:59Z","goal":"Reconcile Q3 invoices","
target_resources":["https://erp.example.com"]}}
~~~

~~~ text
intent_hash = sha-256:sE_2V3NaDpGNYM8dH1tLpNJnj-RmaHN3FC6ZcbOLJSw
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

The next two vectors exercise an additional flat Intent member beyond
`target_resources`, and an Authority Set entry whose
`delegation.allowed_delegates` is an array of matcher objects, where
JCS sorts each object's members but preserves the array's order (the
`sub_profile` matcher stays before the `sub` matcher).

`intent_hash`, over this Mission Intent as the envelope `value` with
`typ` `mission-intent`:

~~~ json
{
  "goal": "Reconcile Q3 invoices",
  "target_resources": ["https://erp.example.com"],
  "expires_at": "2026-12-31T23:59:59Z",
  "purpose": "urn:example:purpose:reconcile"
}
~~~

Canonical bytes of the envelope:

~~~ text
{"iss":"https://as.example.com","typ":"mission-intent","value":{"e
xpires_at":"2026-12-31T23:59:59Z","goal":"Reconcile Q3 invoices","
purpose":"urn:example:purpose:reconcile","target_resources":["http
s://erp.example.com"]}}
~~~

~~~ text
intent_hash = sha-256:ug7xNsun-TbvBCr-_uFP74-CBEs8pwlPmD-doEyKDu8
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

The next vector exercises the third anchor: `proposal_hash`, over
this submitted `authorization_details` proposal as the envelope
`value` with `typ` `mission-proposed-authority`
({{authority-proposal}}):

~~~ json
[
  { "type": "mission_resource_access",
    "resource": "https://erp.example.com",
    "actions": ["invoices.*"] },
  { "type": "mission_resource_access",
    "resource": "https://erp.example.com",
    "actions": ["journal-entries.write"],
    "constraints": {
      "max_amount": { "amount": "1000.00", "currency": "USD" }
    } }
]
~~~

Canonical bytes of the envelope:

~~~ text
{"iss":"https://as.example.com","typ":"mission-proposed-authority"
,"value":[{"actions":["invoices.*"],"resource":"https://erp.exampl
e.com","type":"mission_resource_access"},{"actions":["journal-entr
ies.write"],"constraints":{"max_amount":{"amount":"1000.00","curre
ncy":"USD"}},"resource":"https://erp.example.com","type":"mission_
resource_access"}]}
~~~

~~~ text
proposal_hash = sha-256:udzftXYQy0pvYNxz4KgtmyL_EV8ry4DhIbBFfwILEBA
~~~

The last vector is the entry commitment ({{integrity-anchors}}),
computed over one immutable Mission-record Authority Set entry, not
an issued or narrowed token projection. Over this entry:

~~~ json
{
  "type": "mission_resource_access",
  "resource": "https://erp.example.com",
  "actions": ["invoices.read"],
  "constraints": {
    "resource_issued_after": "2026-07-01T00:00:00Z",
    "resource_issued_before": "2026-09-30T23:59:59Z"
  },
  "delegation": {
    "max_depth": 2,
    "allowed_delegates": [{ "sub_profile": "ai_agent" }]
  }
}
~~~

as the envelope `value` with `typ` `mission-authority-entry`:

~~~ text
{"iss":"https://as.example.com","typ":"mission-authority-entry","v
alue":{"actions":["invoices.read"],"constraints":{"resource_issued
_after":"2026-07-01T00:00:00Z","resource_issued_before":"2026-09-
30T23:59:59Z"},"delegation":{"allowed_delegates":[{"sub_profile":"
ai_agent"}],"max_depth":2},"resource":"https://erp.example.com","t
ype":"mission_resource_access"}}
~~~

~~~ text
entry_digest = sha-256:OUrwTnuirT29YxQmMSyiJce8W1PfGryvrVViQ1lJCqQ
~~~

An implementation that canonicalizes the same `value` under the same
`typ` and `iss`, computes SHA-256, and encodes as `sha-256:` followed by
base64url with no padding ({{integrity-anchors}}) reproduces these
anchors exactly. A divergence indicates a JCS or encoding difference to
resolve before interoperating.

# OAuth Binding Mapping Assessment {#oauth-statement}

<!-- assessed-substrate-digest: 5488bd571ad351f0 -->

This appendix is informative. It is this document's Mapping
Assessment of itself against the kernel and capabilities of the
Mission Substrate contract (the "Mission Substrate Statement" section
of {{I-D.draft-mcguinness-mission-substrate}}). It describes, in the
Statement's form, how the surfaces this document defines realize
that vocabulary.

The assessment adds no requirement: {{conformance}} alone defines
conformance to this document. This document publishes no Mission
Substrate Statement, makes no substrate-conformance claim, and takes
no requirement from the substrate; each document references the
other informatively.

The assessment applies to the substrate revision published with this
document, in this document's base single-domain mode, with the
optional capabilities active as the conditions below state.

For the kernel:

1. The Mission Reference is `mission_id`: high-entropy, unambiguous
   within the issuer namespace, compared by exact string equality
   together with `mission.issuer`, never reassigned, retained for the
   audit horizon, and disclosed beyond the issuer only on this
   document's authorized surfaces.
2. The Controller is the Mission Issuer (the authorization server),
   established through `mission.issuer` and the deployment's issuer
   trust (AS metadata and published keys).
3. The Actor handle is the authenticated OAuth client at approval; the
   external Subject is fixed by this document's injective mapping;
   delegates are carried in the `act` chain; child and successor
   lineage is recorded through the parent and predecessor members;
   actor-type classification uses `sub_profile` and client-instance
   attestations where deployed.
4. The Approved Context is the Mission Intent recorded verbatim, the
   recorded authority proposal where one was submitted, and the
   derived Authority Set; the immutable boundary is the record's
   immutable members; commitments are the typed integrity anchors
   (`intent_hash`, `proposal_hash`, `authority_hash`); a material
   change obtains a new approval through an expansion successor.
5. The approval ceremony is this document's approval event
   ({{approval-event}}). Its direct realization, interactive or
   deferred, authenticates the Approver, establishes the Subject and
   authority source, renders the derived Authority Set and the
   effective expiry, and commits the record atomically. Under a
   standing-consent basis, such as a dispatch, the authorized policy
   ceremony decides the instance, and `consent_principal` remains the
   accountable owner ({{standing-consent-bases}}).
6. The active predicate is stored `state` equal to `active` with
   the decision time strictly before the record's effective
   `expires_at`, the issuer materializing the resulting `expired`
   transition lazily where it chooses; any other stored value,
   recognized or not, is non-active; transitions are authenticated
   lifecycle operations; a non-active Mission refuses issuance and
   derivation.
7. The reliance bound is the record's effective `expires_at` (never
   later than the requested ceiling), which caps every derived
   credential's `exp`; the maximum residual after a Mission becomes
   non-active is the outstanding credential lifetime ({{revocation}}).
8. The propagation and join surfaces are: the `mission` claim
   (artifact issuance under the Mission, authority derivation, and
   lifecycle-gated issuance); the `mission_id` and
   `mission_expires_at` response members (correlation only); the
   introspection projection (state as of the response, caller
   authorization and minimization applying); the Status surfaces
   (state as of a signed observation with explicit freshness); and
   the grant binding (the issuer's native association of Mission,
   Subject, client, and credential).
9. The governance record is the Mission Record with its approval
   evidence and lifecycle history, retained for the audit horizon,
   with integrity resting on record custody and the typed anchors.

The capability table:

| Capability | Claim | Activation | Scope and defining sections | Limitations |
| --- | --- | --- | --- | --- |
| Lifecycle-Gated Authorization | supplied | always | State-gated issuance and every derivation gate | Outstanding credentials run to their own `exp`; the residual is bounded, not zero |
| State-Observable | supplied | Status, introspection, or Signals companion active | Those surfaces | Staleness bounded by each surface's declared freshness |
| Structured Authority | supplied | always | `authorization_details` of AS-supported types ({{other-types}}), each type's own specification defining semantics (for `mission_resource_access`, the Mission Resource Access Profile's Common Constraints, {{I-D.draft-mcguinness-oauth-mission-resource-access}}) | Semantics exist per supported type, not universally |
| Monotonic Derivation | supplied | always | The subset rule over covered types at every derivation, delegation, and attenuation point | Covered transitions are `attenuate`; a cross-vocabulary transition is `decide_anew`, never silent attenuation |
| Credential-Bound | supplied | always | The `mission` claim on issued tokens | Fact semantics: issuance under the Mission, authority derivation, lifecycle-gated issuance; state-as-of only via the State-Observable surfaces |
| Authorized Context Correlation | supplied | the Delegation capability active ({{delegation}}) | The Token Exchange join at delegated issuance: the AS, as joining authority, joins the Mission and Subject carried by the Mission-bound `subject_token` with the delegate identity independently established by the `actor_token` or the delegate's own client authentication, binding both to the newly issued credential | The base grant binding at issuance co-establishes its facts and is not a join; cross-authority joins are the Mission Authority Server's machinery, not this binding's |
| Independently Verifiable | supplied | Mandate, signed Status, or audit companion active | Anchor recomputation and signed artifacts per those profiles | Signature verification never establishes current state |
| Portable Evidence | supplied | Evidence, Mandate, or audit companion active | Per those profiles | The governance record is otherwise issuer-local |
{: title="OAuth Mission binding capability table"}

Temporal elements: every issued credential's `exp` is capped by the
record's effective `expires_at`; state observations carry their
surface's declared freshness; the residual after non-active is the
outstanding credential lifetime.
Failure behavior: an unknown lifecycle state is non-active; an
unresolvable reference, a failed anchor verification, and an unknown
`authorization_details` type fail closed; where a row's activation
condition does not hold, the property is not supplied, and a consumer
cannot rely on it.

This document's three optional capabilities ({{conformance}}) are
surfaces an implementation may or may not offer, each independent of
the others. The capability table above states scoped guarantee
claims: properties this document supplies and the conditions under
which each is supplied. The entries below relate each optional
capability to those claims. Declaring an optional capability never
creates a claim beyond the eight already stated above.

Introspection:
: Exercises State-Observable. One of State-Observable's three named
  activation surfaces, alongside Status and Signals; declaring it
  activates that otherwise-conditional claim.

Delegation:
: Exercises Lifecycle-Gated Authorization, Structured Authority,
  Monotonic Derivation, Credential-Bound, and Authorized Context
  Correlation ({{delegation}}). The first four are supplied always,
  and Delegation exercises them rather than creating them. Authorized
  Context Correlation is activated by this capability; its supplier
  is the Token Exchange join, which binds the Mission and Subject of
  the `subject_token` and the delegate's identity to the delegated
  credential without creating a new grant binding
  ({{grant-binding}}). The `act` chain itself supplies none of these
  claims: it is attribution, never authority.

Cross-Domain:
: Exercises Lifecycle-Gated Authorization, Structured Authority,
  Monotonic Derivation, and Credential-Bound. Carries these four
  always-supplied guarantees across the domain hop: the Mission
  reference and the `authority_hash` the projection carries,
  intact, authority that only narrows, and projection gated on active state, while adding an
  interoperable projection surface the guarantees alone do not
  provide. It does not become Portable Evidence by crossing a
  domain: that claim activates only when an Evidence, Mandate, or
  audit companion is active, and Cross-Domain is not among them.

# Document History {#document-history}

\[\[ To be removed from the final specification ]]

-01

- Security Considerations: duplicated security prose removed from a
  classified list reviewed on #877 (D330). Each removal restated a body
  rule (Mission Approval, Approval Comprehension, Revocation,
  Introspection, Resource Server Enforcement, Delegation Constraints,
  Mission-Bound Access Tokens, Integrity Anchors) or generic agent
  threats now pointed to the Mission Security Model, added as an
  informative reference. Operative statements, the local limits
  (issuance is not runtime enforcement, commitments are not subset
  proofs, approved authority can still be misused) and every cited
  anchor are kept; no BCP 14 keyword changed. Information Propagation
  says "the approved Authority Set", and Token Theft says
  "sender-constrained where ... require it" (#877).
- Implementation Map and Mapping Assessment, Cross-Domain: the
  Mission reference is `mission.id` and `mission.issuer`;
  `authority_hash` is the value the projection carries, not part of
  the reference (#1086). The Implementation Map says "this
  document" rather than "the core" (#1089). No requirement
  changed.

- Mission Intent: `purpose` stays the configured-mapping lookup key,
  whose candidates the Intent, policy, and the approval event bound;
  in any other decision it can contribute only to a refusal or to
  stricter treatment, never supplying, widening, relaxing, or
  refreshing authority or replacing an independent check, and
  after approval the approved Mission's value is the one consulted.
  This replaces the rule that `purpose` affects no other issuance
  decision and is inert after approval (#1102).

- Mission Approval: the approval event is the atomic, adjudicated
  transition that creates a Mission under its approval basis, for
  every basis. The authorization-code flow and its steps are the
  direct realization; a standing-consent basis supplies the human
  decision from the standing consent and the instance's adjudication,
  and the other creation rules still bind its approval event.
  Standing-Consent Bases says no fresh human approval per instance,
  and an instance's `approval_event_id` identifies this instance's
  approval event. The Mapping Assessment's approval-ceremony item
  separates the direct realization from a standing-consent basis
  (#1078).

- Standing-Consent Bases: a companion profile defining a
  standing-consent type states what the record's `approval_event_id`
  carries for an instance it activates; the value identifies the
  activation event, never the standing approval (#1017). This adds a
  requirement.

- Non-Goals: the multi-hop entry names what is specified (one
  projection hop; recursive cross-organizational delegation, profiled
  by Mission Cross-Organizational Delegation, added as an informative
  reference) and what is not (re-projecting a Mission into a further
  domain) (#1018). No requirement changed.

- Stated that a model's output in derivation is a recorded input to
  the AS's deterministic derivation policy that can refuse or narrow
  and never supplies or widens authority: candidate authority keeps a
  proposal or configured-mapping origin, deterministic policy
  validates every resulting entry, and replay uses the retained
  output. This adds a requirement.

- Stated why the primary access token's confirmation member stays
  optional rather than mandatory: compatibility with bearer-only
  resource servers, retaining the RFC 9700 Section 2.2.1
  recommendation, at the cost of the stolen-token exposure Token Theft
  already names (#1020). No requirement changed.

- Routed RAR remediation by containment: entries that both a
  presented refresh grant and the active Mission's Authority Set
  contain are requested by refresh, and entries outside the Authority
  Set need a new approval or an expansion. Added
  a Non-Goal for joint outcomes and cross-resource effects (the
  `mission` claim does not identify a business transaction), stated
  that an intermediary in the agent's own trust domain presenting the
  agent's own tokens acts as part of that client, self-exchange
  included, while one authenticated as a distinct actor that obtains
  a delegated token is a delegate, and pointed to RFC 9728's
  `authorization_details_types_supported`. No requirement or wire
  behavior changed.

- Standing-Consent Bases defines the activation policy reference: a
  standing-consent basis whose activation a separate policy artifact
  adjudicates commits that policy's content as `{id, version,
  digest}`, with the `mission-activation-policy` digest, and the
  activating issuer verifies it before each activation.

- Stated that a `policy` adjudicator decides deterministically over
  recorded inputs, that a model's output can be one such input that
  refuses or narrows but never supplies or widens authority, and that
  the prose members gate issuance in no adjudicating policy and
  through no model input. These add requirements.

- Corrected the child-delegation example in Composition and the
  Effective Ceiling: `max_children` limits concurrently non-terminal
  children, so the example's 12 descendants are Missions live at
  once, not a lifetime count; disclosure points at the child-delegation
  profile's distinct figures rather than one composed total.

- Separated exact `target_resources` membership, checked for the
  Authority Set and for a proposal at submission, from later token
  narrowing under the subset rule. Made the per-capability
  transformation rule the single home: audience projection to a
  Resource AS needs `narrowing`, and without it a delegated token
  includes an entry only exactly as approved; a type that declares
  `delegation` without `narrowing` is delegable only as an entry
  equal to one in the presented delegating token, under a new
  equality case of the subset rule. Delegation depth comes from
  accounting the AS maintains for its own issuance, not from `act`
  nesting, a depth the AS cannot establish narrows every entry out,
  and a resource server authorizes only the current actor while it
  may record the chain. These add requirements.

- Stated that approval cannot establish comprehension, with
  non-normative rendering practices for large Authority Sets
  (Approval Comprehension), and named the approval-granularity
  trade-off in Applicability. No requirement or wire behavior
  changed.

- Let a profile of a Token Exchange that the AS implements assign its
  own error code to the Issuance Gating refusals, such as a
  continuation profile's code for an ended chain. The refusal and the
  `mission_error` diagnostic are unchanged, and the code stays
  `invalid_grant` everywhere else. This changes a requirement.

- Stated the client no-downgrade requirement in Authorization Server
  Metadata, where discovery establishes Mission support; Downgrade by
  Omission keeps the threat analysis and now holds the
  metadata-integrity note. Added the existing `invalid_request`
  refusal of a proposed entry outside `target_resources` to the error
  mapping table. Presented derivation as one procedure whose two
  named modes differ in where candidate entries come from, and made
  "Mission Record" and "runtime layer" consistent. No requirement or
  wire behavior changed.

- Clarified that a Mission Issuer can conform without supporting any
  Intent Submission Evidence types. The submission-processing
  sequence keeps the baseline dispatch and refusal rules and the
  ordering of admission checks before derivation; the evidence
  companion owns the AS, exact-Intent, and presenter-binding checks.
  No wire behavior changed.

- Moved local approved-set verification to the Mission Approved-Set
  Verification companion
  ({{I-D.draft-mcguinness-oauth-mission-approved-set-verification}})
  with its rules unchanged: authenticated complete-set retrieval at
  Tier 1 and Tier 2, the retrieval surface and its disclosure gate,
  the rule that Mission Status is not a compatible retrieval surface,
  the capability's conformance entry and mapping-assessment entry, and
  the selective-inclusion future-work note. This document keeps
  `authority_hash`, the statement that a party holding the complete
  Authority Set can verify it, and the Consent Binding threat
  analysis, and names three optional capabilities; its references to
  the companion are informative.

- Moved the Intent Submission Evidence framework to the Mission Intent
  Submission Evidence companion
  ({{I-D.draft-mcguinness-oauth-mission-submission-evidence}}) with
  its wire names and rules unchanged: the entry convention,
  required-evidence resolution, binding to one exact Intent,
  presenter agreement, the verification-cost bound, error placement,
  and the creation-fingerprint note. This document keeps the
  `evidence` member and its bounds, the reject and policy-input
  rules, the `invalid_mission_intent_evidence` registration, and the
  `submission_evidence` record member; its references to the
  companion are informative.

- Presented the `direct` approval basis first in the Mission Record and
  collected the standing-consent generalization in Standing-Consent
  Bases; no requirement changed.

- Moved the derivation limit to the Mission Derivation Limits
  companion ({{I-D.draft-mcguinness-oauth-mission-derivation-limits}})
  with its wire names and rules unchanged: the
  `requested_derivation_limit` Intent member and its registry entry,
  the `derivation_limit` record member, the counting and refusal
  rules, the `derivations_exhausted` diagnostic, the
  `derivations_remaining` introspection member, and approval
  rendering. Issuance Gating keeps the definition of a derivation and
  one informative pointer to the companion, and the integrity-anchor
  test vector that exercised the member uses `purpose` instead.

- Stated the six properties the core establishes in the
  Implementation Map, added the grant-lineage binding to the
  Introduction's chain, and defined a Mission as the binding of a
  disclosed task to an explicitly approved Authority Set.

- Reordered the reading path around submission, approval, the record
  and commitments, lifecycle gating, and token issuance and consumption.
  Added an informative implementation map and a single-audience
  approval-to-revocation walkthrough; separated resource-server
  enforcement from optional approved-set verification and moved
  design context to an appendix.

- Reviewed the document against OAuth RFC conventions. Each rule now
  has one home; restatements of RFC 6749, 7662, 8693, 9068, 9396, and
  9700 became pointers; deployment, audit, and implementation duties
  became guidance; and long requirements became numbered lists.
  Conditional members use the "required when; absent otherwise" form,
  and the issuance-side downgrade rules moved from Security
  Considerations to {{authority-proposal}}. The error-mapping table
  gained rows for `invalid_mission_intent_evidence`, `invalid_scope`,
  the governed-client `invalid_request`, the missing-claim
  `invalid_token`, and the delegation refusals. Derived access tokens
  carry authentication claims only as RFC 9068 defines them, about the
  token's own Subject, and never the authentication of an Approver who
  differs from it; RFC 9470 step-up applies where the deployment
  conveys the Subject's authentication. Per-use introspection freshness
  is stated as strengthening RFC 7662.
  The metering members left this document's registry seed, since the
  metering profile registers them. Anchors are unchanged, and no
  conformance capability changed.

- Scope Projection keeps OAuth response semantics: an explicitly
  requested `scope` value the issuance cannot grant is refused with
  `invalid_scope`, a requested `scope` narrows a projected one, and a
  refusal caused solely by a failed projection does not invalidate an
  otherwise-valid refresh token. A changed mapping is re-evaluated,
  not stale by itself. A mapping failure yields `invalid_target` even
  when a `scope` value is requested; the no-resource-`scope` client
  guidance covers targets that consume `authorization_details`; and
  the refresh example narrows with `authorization_details`.

- The Error and Challenge Mapping table maps a scope-projection
  refusal, and an issuance-time refusal under the delegated-token
  routing rule, to `invalid_target`.

- Stated in the Introduction and {{runtime-boundary}} that a
  deployment can run this profile alone, with resource servers that
  need not be Mission-aware outside delegation, named introspection as
  the cutoff shorter than a token lifetime that needs no runtime
  layer, and named the action-class needs that warrant a runtime
  layer; no normative requirements changed.

- Define optional current-presenter Instance Context consumption for
  delegated tokens. Reuse the instance specification for validation and
  mapping; retain Mission actor, authority, and lifecycle checks for
  authorization. Required attribution fails closed.

- Added an informative derivation-policy appendix with an admissible
  split-action worked rule, authoring fixtures and ownership guidance;
  no normative requirements were added.

- PR #725 review round: split Local Approved-Set Verification's
  authenticated complete-set retrieval into two explicit tiers:
  Tier 1 (recompute and subset-check against a
  retrieved set, detecting projection errors under continuing trust
  in the issuer) and Tier 2 (additionally require the expected
  `authority_hash` to come from an independently retained,
  separately authenticated source, defending against post-approval
  substitution). Removed the claim that Mission Status is a
  compatible retrieval surface: Status returns only the requesting
  audience's, and only the current effective (containment-filtered),
  entries, never the complete immutable approved set. Corrected the
  typed selective-inclusion proof from a claimable alternative to a
  future composition point, pending a
  concrete proof type that authenticates its own root as the
  Mission's approval-time commitment, and fixed its description to
  prove the approved parent entry, never the carried narrowed entry
  directly. Added the capability to the Conformance section's
  OPTIONAL capabilities list ({{conformance}}). Closed a mismatched-
  issuer gap in token introspection and child-grant redemption: both
  resolved a Mission by `id` alone without checking the presented
  `mission.issuer` against the resolved record's, now that
  `(id, issuer)` is the complete Mission identity. Clarified that
  Harness Evidence and Orchestration Evidence carry `authority_hash`
  as their own optional audit extension, not inherited from the
  baseline claim.

- Minimal Mission claim (#702, coordinated with #699): the baseline
  `mission` claim shrinks to exactly `id` and `issuer`.
  `authority_hash` and `approval_basis` leave the baseline claim; both
  stay on the Mission record and become available through token
  introspection's member-scoped disclosure privilege, alongside
  `derivations_remaining` and `proposal_hash`. Added the Local
  Approved-Set Verification profile, an OPTIONAL profile defining
  authenticated complete-set retrieval, commitment recomputation, and
  a subset check, or a typed selective-inclusion proof this document
  does not itself define, for a party that needs to verify a token's
  carried authority against the complete approved Authority Set
  independently of the token signature. `expires_at` on the claim is
  now explicitly profile-scoped: a consumer relying only on the
  presented token's own validity needs nothing further, while a
  profile minting a further credential downstream, or verifying
  Mission lifetime from retained state, MUST require it and MUST
  treat its absence as an error, never a silent fall back to the
  token's own `exp`. The Extensibility section's documented stability
  list narrows from `id`, `issuer`, `authority_hash` to `id` and
  `issuer`; an extension that relied on `authority_hash`'s baseline
  presence adopts the new profile or introspection's disclosure
  privilege instead. A companion document that carries the recurring
  `{id, issuer, authority_hash}` micro-descriptor as its own lineage
  or audit anchor (offline attenuation, the cross-domain and cross-org
  grants, the Mission Authority Server's Join Assertion) now carries
  it as its own profile-owned extension member, never inherited from
  this baseline.

- Controls taxonomy retired and error codes reused per typical OAuth
  patterns (#636, #706, #117; one coordinated breaking cut). The
  `controls` extension bucket is removed: `acr` is replaced by the
  standard `acr_values`/`max_age` authorization-request parameters
  for the direct flow, with explicit Approver semantics distinct from
  the token's Subject and an AS approval floor that stays authoritative
  and conjunctive ({{approval-authentication}}); achieved approval
  context (`acr`, `amr`, `auth_time`) is provenance recorded on the
  approval event or Consent Evidence, never a Mission Intent member,
  and an AS MUST NOT carry it on a derived access token
  ({{mission-bound-tokens}}). `max_derivations` is replaced by a
  requested-vs-effective pair, `requested_derivation_limit` (Intent)
  and `derivation_limit` (Mission Record), with the architecture's
  fan-out characterization removed and the clamp, omission, rendering,
  and audit-recomputation rules stated in a dedicated Derivation
  Issuance Policy section.
  `agent_deployment` is removed with no replacement member defined in
  this document series; a pointer names what a future Agent Deployment
  Binding profile would own ({{mission-intent}}). `resources` is
  renamed `target_resources` (a client-requested Intent ceiling,
  explicitly not RFC 8707 `resource` carriage) and `constraints` is
  renamed `task_bounds`, so the name cannot collide with a Resource
  Access entry's enforced `constraints`. The Mission Intent's top
  level is now open to companion-defined members by name
  ({{extensibility}}); this is the seam metering's consumption-bound
  members ride directly, no longer nested under `controls`
  ({{I-D.draft-mcguinness-mission-metering}}). Error codes: two
  no-RAR uses of `invalid_authorization_details` (the configured-mapping
  no-match refusal and the unrecognized-`target_resources` refusal)
  are replaced by `access_denied`, since no `authorization_details`
  object exists for that code to describe
  ({{authorization-derivation}}); the RS `mission_denial` attribute
  drops `step_up_required` in favor of the standard RFC 9470
  `insufficient_user_authentication` challenge for weak or stale
  token-associated user authentication, with sender-constraint/key-binding
  failure routed to the applicable Bearer/DPoP/mTLS `invalid_token`
  challenge instead ({{rs-enforcement}}); `mission_error` and
  `mission_denial_reason` are unchanged, and
  `invalid_mission_intent_evidence` is retained with its rationale now
  stated ({{oauth-extensions-error-registration}}). This is a breaking
  wire-shape change to `intent_hash`'s covered object: the Integrity
  Anchor Test Vectors are regenerated ({{test-vectors}}), and there is
  no deprecated alias for any renamed or relocated member.

- PR #717 review fix: the OAuth Binding Mapping Assessment appendix
  ({{oauth-statement}}) is now explicitly informative throughout,
  correcting a layering contradiction (normative-as-own-content text
  that depended, to be read, on a substrate contract cited only
  informatively). This document's Conformance gates remain its sole
  normative requirements; the appendix publishes no Mission Substrate
  Statement and makes no substrate-conformance claim. The
  digest-marker tripwire is unchanged in mechanism: a mismatch still
  prompts review, now understood as an editorial finding rather than
  a normative one.

- Added an OAuth Binding Mapping Assessment appendix
  ({{oauth-statement}}): this document's own self-assessment against
  the Mission Substrate contract's kernel and capabilities, relocated
  here from the substrate document so the substrate carries no
  binding-specific discharge (#708); its reference to the substrate
  remains informative, and replaces the prior pointer to the
  substrate's family appendix. No requirement on a Mission Issuer,
  resource server, or Client changed.

- Informative pointer from the Conformance section's Mission-bound
  gates to the architecture's Mission Binding Properties vector,
  naming this document's discharge as its `credential-mission-bound`
  property; the core's own gates remain authoritative and the
  document remains self-contained (#663).

- Mission Resource Access Profile split (#637, #645, #698): the
  `mission_resource_access` type definition, its resource and action
  matching, generic constraints, the Common Constraints registry, the
  delegation member and matching rules, the subset and
  intersection algebra, the resource server's enforcement duties for
  this type's `resource`/`actions`/`constraints` members (including
  the `prefix`-match normalization rule) and the
  `mission_constraints_supported` protected-resource metadata member
  (definition and IANA registration), and the Resource Boundary
  Canonicalization security analysis relocated to the Mission
  Resource Access Profile
  ({{I-D.draft-mcguinness-oauth-mission-resource-access}});
  this document keeps type-agnostic commitment, the approved-set
  metadata requirement, and derivation gating
  ({{authorization-derivation}}, {{other-types}}, {{discovery}}).
  Adds the type-agnostic scope-projection rule and issuance algorithm
  ({{scope-projection}}) and the machine-readable per-type
  transformation-capability declaration
  (`mission_transformation_capabilities`, {{other-types}}); sweeps
  every scope-only claim that assumed a lossy projection was always
  available (the Intent enforcement table, Resource Server
  Enforcement, and the minimum-deployment note).
- Mission-to-OAuth-grant cardinality made explicit
  ({{grant-binding}}): a Mission is independent of any OAuth grant
  and identified globally by (`issuer`, `id`). The Mission grant
  persistent, redeemable grant lineage (the authorization-code
  lineage established at approval, or a further reusable grant such
  as a continuation-established refresh-token family) to exactly one
  Mission, zero or more bindings per Mission and never more than one
  Mission per binding, resolved stably on every derivation and never
  client-negotiated; a violation is an AS-internal data-integrity
  fault, not a client-visible refusal. A Token Exchange or
  cross-domain projection that issues only an access token
  establishes no new binding: the issued token is a derived token, a
  `mission`-claim association to its input binding's Mission, not
  itself a grant binding. A Child Mission or expansion successor gets
  its own identity and, where it has one, its own grant binding,
  related to its origin by lineage, never by extending the origin's
  binding; a continuation handle or refresh-token family is
  credential machinery rooted in one Mission, not the Mission itself.
  Non-active state gates every bound derivation without implying
  revocation of an unrelated grant or recall of an unexpired token. A
  decision-time runtime join (the Mission Authority Server's Mission
  Join) never becomes a grant binding. The unredeemed-authorization-code
  fork is now one deployment policy applied consistently, with
  idempotent replay (#700).

- Reader-program normative follow-ups: each supported
  `authorization_details` type's transformation boundary (subset
  relation and delegation semantics understood, or
  carried-as-approved) is declared in the deployment documentation
  that names the type as supported ({{other-types}}, {{discovery}});
  opaque Mission-bound tokens get a defined consumption mode,
  introspection REQUIRED as the claims carriage with active-only
  authority disclosure and fail-closed resource server duties
  ({{introspected-consumption}}); the second derivation mode is
  renamed configured-mapping mode (formerly template mode) and
  framed as the no-RAR on-ramp ({{authorization-derivation}});
  Authority Sources moved after Protocol Flow within the Overview
  (structure only).

- Editorial consolidation; no normative change: every removed
  sentence restates a rule that remains normatively stated at its
  home ({{mission-bound-tokens}} and {{rs-enforcement}} for
  `client_id`'s registered meaning, {{submission-via-par}} for the
  submission trust rule, {{introspection}} for the RFC 7662
  deviation, the (since relocated) Resource Boundary Canonicalization
  section for the
  single-normalization rule, {{lifecycle}} for short-lifetime
  guidance). The rejected `client_id`-freezing narrative compressed
  to its design rationale; spec-archaeology sentences removed in
  favor of this history; the Mission Drift consideration folded
  away. Structure: the commitment machinery promoted to Integrity
  and Commitments; the Introduction's positioning subsections merged
  into Relationship to Adjacent Work; the submission processing
  order given its own section; Security Considerations grouped into
  five themed clusters. Scanability: `mission_denial` values as a
  definition list, a remediation-grains table, a prefix-matching
  example table. Explicit anchors pinned on every previously
  auto-slugged surviving heading, matching the published fragments;
  the end-to-end example now shows `mission_id` and
  `mission_expires_at` on the token response.

- `goal_lang` (OPTIONAL, BCP 47) on the Mission Intent and an
  Internationalization Considerations section: a syntactic language
  declaration for the Intent's human-readable prose, committed by
  `intent_hash`, refused `invalid_request` when malformed, with no
  authority semantics and deliberately no language-tagged display
  fields on Authority Set entries (#534).
- Standing-consent approval instant: `approval_basis.approved_at`
  (REQUIRED for every standing-consent `type`) carries the human
  approval instant of the exact consented root, verified by the
  activating issuer from retained state, never accepted as the
  activating request's own assertion, with deployment-declared
  recency ceilings mirroring the Approval Governance companion's
  policy-approval recency (#580).
- Informative pointer to the substrate-hosted OAuth Mission Binding
  Statement from the Conformance section; the core remains
  self-contained (#551).
- Requested versus effective expiry: `intent.expires_at` is the
  client's requested not-after ceiling and the Mission Record's
  `expires_at` is the AS-established effective lifetime, never later
  than the request (`invalid_request` for a malformed or non-future new
  request; delayed approval rechecks at activation, while idempotent
  recovery returns the stored outcome; the exact-mirror rule and the
  `invalid_authorization_details` refusal are replaced). Approval
  reconsent covers a changed effective expiry. The new
  `mission_expires_at` token-response parameter carries the exact
  effective value on every Mission-creating success response.
- The Authority Set entry commitment: the committed-object `typ`
  `mission-authority-entry` over a single recorded entry, with its
  Mission-binding rule, selector equivalence class, and test vector
  ({{integrity-anchors}}, {{test-vectors}}).
- Breaking change to the Intent carriage shape: the `mission_intent`
  parameter value is the Mission Intent Submission envelope
  ({{submission-via-par}}), `intent` plus an OPTIONAL typed
  `evidence` array, and the bare-Intent value is refused under the
  closed envelope. Anchors are stable: `intent_hash` commits exactly
  the `intent` object, so committed values, recorded anchors, and
  the test vectors are unchanged. The Intent Submission Evidence
  hook ({{intent-submission-evidence}}) adds type-dispatched
  verification that rejects unknown or failing entries, the
  policy-input-never-authority rule, the required-evidence
  anti-downgrade rule, evidence invalidation across shaping and
  revision, the presenter conjunction, verification-cost bounds, the
  `invalid_mission_intent_evidence` error registration, and the
  `submission_evidence` record member as record-trusted provenance
  metadata.
- Breaking change to the authority-proposal carriage: the proposal
  moves from the Intent's `proposed_authority` member, which is
  removed, to the standard top-level `authorization_details`
  parameter pushed alongside `mission_intent`
  ({{authority-proposal}}), and the old prohibition on submitting
  the two together inverts. Anchor inputs changed: `intent_hash` no
  longer covers the authority proposal, and the new `proposal_hash`
  (`typ` `mission-proposed-authority`) commits the submitted
  proposal, recorded on the Mission and surfaced through
  introspection, never on the `mission` claim. Worked examples and
  test vectors are recomputed; an approval-event rule recomputing
  every recorded anchor and a Mission-governed-client bare-request
  rejection accompany the change.
- Derivation is mechanical, in two modes: narrowing (RECOMMENDED)
  and configured-mapping. The deterministic-reproducibility and
  policy-inspectability rules are retired, `policy_version` stays as
  an opaque audit correlator, generative derivation is demoted to a
  local-policy extension, and the derivation trust boundary (no
  portable Intent semantics) is stated. Configured-mapping mode
  publishes its mapping space as deployment documentation and
  distinguishes no-mapping from policy refusals.
- New wire surface: the `mission_error` and `derivations_remaining`
  introspection members, the `mission_denial` WWW-Authenticate
  attribute, and the `mission_constraints_supported`
  protected-resource metadata member. The `mission` claim gains an
  OPTIONAL `expires_at`; the `mission_id` token-response parameter
  is promoted to SHOULD.
- Authority vocabulary: four new Common Constraints (`time_window`,
  `data_classification`, `allowed_tools`,
  `requires_action_approval`) with `prefix`-match fixes; the
  OPTIONAL `controls.agent_deployment` class pin; `max_derivations`
  sizing guidance.
- Delegation hardening: delegation-authorization policy applies at
  every exchange, `allowed_delegates` is RECOMMENDED and its absence
  is never a blanket grant, self-exchange is accepted only from the
  Mission's `client_id`, and the delegated-token routing guardrail
  is raised to MUST NOT.
- Model precision: the Mission-referenced, Mission-derived, and
  Mission-bound token-class taxonomy; anchors as independent
  commitments with `authority_hash` an audit correlator at a
  narrowed-token resource server; the subset rule named
  representational, not semantic; approval-event sequencing named as
  an extensibility seam; Intent carriage closed to the form-encoded
  PAR parameter.
- Operational and privacy: verification-key retention anchored to
  the audit horizon, issuer-key custody and per-artifact-class `kid`
  guidance, a Mission-record and evidence-access privacy section,
  and extended token lifetimes scoped to fully runtime-gated tokens
  with single-audience narrowing as the splitting mechanism.
- Editorial throughout, no normative change: requirement lists for
  the PAR submission and rendering duties, twice-stated rules
  reduced to one home, a third integrity-anchor test vector, and
  registry hygiene.
- External review resolutions: GNAP and capability-system prior art
  positioned in Relationship to Other Authorization Objects; the
  `mission` claim named as the actor-freezing wire signal, with the
  resource server routing guardrail and a new Security
  Considerations subsection on `client_id` misattribution; RFC 6750
  and RFC 9700 promoted to normative and the OAuth Actor Profile
  reference demoted to informative; an actual Common Constraints
  IANA registry replacing the future-revision deferral; and new
  Security Considerations on composition's effective ceiling and the
  containment materialized-capability residual.
- Editorial density pass: split over-dense paragraphs at their
  natural idea boundaries, converted a few flowing comparisons and
  one dense list item into bullets, and reordered surrounding prose
  so a rule sentence opens its paragraph or list item; every
  normative sentence kept its exact wording and home section.
- Three-role approval model (#701): `approval_basis` gains an
  OPTIONAL discriminated `adjudication` member (`kind`: `human` or
  `policy`, a decision mechanism, plus an independent
  `governance_record` boolean) naming what decided a Mission
  instance, distinct from `activation_actor` (who triggered it) and
  `consent_principal` (the accountability root). It is OPTIONAL
  rather than REQUIRED in this revision because the family's
  standing-consent constructors (Template dispatch, Child Delegation,
  Ceiling drawdown) do not yet emit it; a future breaking-change
  window, the same one tracked for `approver`'s removal, MAY promote
  it once they do. A new Role Mapping table ({{role-mapping}}) covers
  direct, relocated human approval, Template dispatch, policy
  drawdown, ceiling drawdown, and AGR-backed approval, with direct
  approval as the degenerate one-human case. `type` and
  `adjudication.kind` get their own unknown-value rule, distinct from
  the Mission Lifecycle state rule. The top-level `approver` member is
  DEPRECATED as a compatibility alias for
  `approval_basis.consent_principal`, normatively equal to it; its
  removal is deferred to the same future breaking-change window.

- References: the agent-identity reference
  draft-klrc-aiagent-auth is replaced by its successor,
  {{I-D.draft-ietf-wimse-aims}}, which names the agent's mission and
  leaves its translation into authorization requirements out of scope
  (Section 10.1) and covers user delegation through the authorization
  code grant (Section 10.4.1).

- References: removed three references the text no longer cites
  (MCP, ISO 4217, and RFC 3986).

- References: draft-zehavi-oauth-rar-metadata is replaced by its
  working-group successor, {{I-D.draft-ietf-oauth-rar-metadata-remediation}},
  which keeps the `insufficient_authorization` error, the
  `authorization_remediation` parameter, and the
  `authorization_details_types_metadata_endpoint` member this document
  cites; the endpoint is no longer described as lacking formal
  standing.

- References: draft-mcguinness-oauth-client-instance-assertion is
  replaced by its two successors, {{I-D.draft-mcguinness-oauth-client-instance-id}} (a client instance's identifier
  carried in its attestation-based client authentication) and
  {{I-D.draft-mcguinness-oauth-client-attesters}} (the client's endorsement of its attesters). The Token Exchange
  example no longer cites the retired `client-instance-jwt` token type.
  The instance-delegate paragraph names the top-level `cnf` as the
  presenter's key, as the Actor Profile requires, instead of `act.cnf`,
  and no longer states that `act.sub` carries the instance identifier or
  that instance evidence alone identifies the delegate ({{I-D.draft-mcguinness-oauth-client-instance-id}},
  Section 5).
  draft-mcguinness-oauth-ai-agent-instance is deprecated and no longer
  cited; the instance-delegate matcher example uses `ai_agent`, the
  actor type the Actor Profile uses, instead of `client_instance`, which
  only that draft defined.

- Approver Authentication Strength composes with OpenID Connect
  ({{approval-authentication}}): a request carrying `openid` asks for an
  ID Token about the authenticated Approver, so when the Approver is not
  the Subject the AS refuses it with `invalid_scope`; and when the
  Approver is not the Subject, whether or not `openid` was requested,
  the Approver's authentication or approval never yields an ID Token,
  UserInfo, or authentication session for the Subject. Self-approval
  keeps its ordinary OpenID Connect behavior (#826).

-00

- Initial individual draft.

# Acknowledgments {#acknowledgments}
{:numbered="false"}

This work builds on the OAuth 2.0 Rich Authorization Requests, Pushed
Authorization Requests, and JWT access token specifications, and is
intended to complement agent-identity work including
{{I-D.draft-ietf-wimse-aims}}.
