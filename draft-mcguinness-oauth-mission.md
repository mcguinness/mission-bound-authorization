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
  I-D.draft-ietf-oauth-rar-metadata-remediation:
  I-D.draft-mcguinness-oauth-actor-profile:
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
  RFC9110:
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
  OpenID.Core:
    title: "OpenID Connect Core 1.0 incorporating errata set 2"
    target: https://openid.net/specs/openid-connect-core-1_0.html
    author:
      - org: OpenID Foundation
    date: 2023

informative:
  I-D.draft-ietf-wimse-arch:
  I-D.draft-ietf-oauth-spiffe-client-auth:
  RFC8126:
  RFC7009:
  RFC8935:
  RFC9493:
  RFC9635:
  RFC8628:
  RFC8792:
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
    target: https://openid.net/specs/oauth-v2-grant-management.html
    author:
      - org: OpenID Foundation
    date: 2023
  AuthZEN.ARAP:
    title: "OpenID AuthZEN Access Request and Approval Profile 1.0"
    target: https://openid.github.io/authzen/authzen-access-request-approval-profile-1_0.html
    author:
      - org: OpenID Foundation
    date: 2026
  I-D.draft-ietf-wimse-aims:
  I-D.draft-hardt-oauth-aauth-protocol:
    title: "AAuth Protocol"
    author:
      -
        ins: D. Hardt
        name: Dick Hardt
    date: 2026-09-25
    seriesinfo:
      Internet-Draft: draft-hardt-oauth-aauth-protocol-11
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
  I-D.draft-mcguinness-mission-capability-binding:
    title: "Mission Capability Binding"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-capability-binding.html
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
  I-D.draft-mcguinness-oauth-mission-device-authorization:
    title: "Mission Device Authorization for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-device-authorization.html
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

OAuth 2.0 has authorization grants and access tokens but no standard
object that binds an approved task, such as one an AI agent performs
on a user's behalf, to the authority approved for it and governs the
tokens later issued under that authority. This document defines that
object for OAuth 2.0: a Mission.

A client submits, through Pushed Authorization Requests, a Mission
Intent describing the task it will perform. The authorization server
derives Rich Authorization Requests authorization details from it,
binds the approved task and that authority to the Approver's consent
through integrity anchors, and records a durable Mission. Every
access token issued under the Mission carries a subset of the approved
authority and a "mission" claim, and every issuance is gated on the
Mission's lifecycle state. Revoking a Mission stops further issuance;
it does not recall tokens already issued, which a resource server
that enforces from the token alone can continue to honor until they
expire.

Optional capabilities represent delegation among agents with the
OAuth Actor Profile and, as specified by a companion, let a single
Mission be honored across trust domains. Runtime enforcement of each
action is a separate, optional layer.

--- middle

# Introduction {#introduction}

This document defines a **Mission**: a durable authorization object
that binds a disclosed task to an explicitly approved Authority Set
and governs the lifecycle of the authority derived from that
approval. The authorization server (AS) issues tokens under a Mission
only while it is `active`, each bounded by the approved Authority
Set, and resource servers enforce the resulting credentials. Revoking
or expiring a Mission stops further issuance and refresh but does
not, by itself, invalidate an already-issued access token, which
remains valid until it expires ({{revocation}}).

Agent-identity work such as {{I-D.draft-ietf-wimse-aims}}
establishes how an AI agent authenticates and how a user delegates
authority to it. The agent is an OAuth 2.0 {{RFC6749}} client
identified by `client_id`, the delegating user is the access token
`sub`, and the agent obtains tokens for the resources its task
requires. That work leaves out of scope:

- how an agent's task (its "mission") is translated into
  authorization;
- how a user's approval of that task is captured as a durable
  artifact; and
- how later token issuance stays bound to what the user approved.

OAuth does not define a task record that links approval of a task to
every grant obtained for it. Without that linkage, withdrawing task
approval need not stop issuance under those grants.

No existing OAuth object fills that role ({{why-a-new-object}}); an
`authorization_details` entry ({{RFC9396}}), for example, expresses
authority but not the task it serves or a lifecycle of its own. A
Mission, held by the AS beside the grant, does. It commits the
disclosed task with its approved authority and has an identifier and
a lifecycle independent of any grant. It can be revoked by that
identifier through an authenticated means, independent of possession
of any token ({{revocation}}), and a token derived from it by Token
Exchange identifies the same Mission ({{grant-binding}}).

A Mission is created and used in a single chain:

1. **Submit.** The client submits a structured **Mission Intent**
   describing the task (goal, target resources, task bounds) instead
   of requesting raw scopes, optionally proposing concrete authority
   alongside it as standard `authorization_details`.
2. **Derive authority.** The AS derives **authorization details**
   ({{RFC9396}}), the **Authority Set**: the concrete authority the
   task needs.
3. **Approve.** At an **approval event**, the approval rendering
   shows the Intent's task, and the Approver consents to the derived
   Authority Set itself, not to the task description alone
   ({{approval-event}}). The AS commits the Mission Intent as
   **`intent_hash`** and the approved Authority Set as
   **`authority_hash`** ({{integrity-anchors}}). It records a durable
   **Mission** whose record associates the disclosed task, the
   approved authority, and the approval basis ({{mission-record}}).
4. **Bind the grant.** The AS binds the OAuth grant the approval
   produces to that Mission, server-side ({{grant-binding}}). Each
   later issuance operation from that grant lineage, such as a
   refresh, is a derivation ({{issuance-gating}}) and resolves to
   exactly this Mission; the client never selects or reassigns it.
   Under a profile, the AS can bind a further grant lineage to the
   same Mission; each lineage resolves to exactly one Mission.
5. **Issue and enforce.** Every derived authority is no broader than
   the approved Authority Set ({{subset}}). Every access token the
   agent obtains under the Mission carries the derived authorization
   details and a **`mission` claim** identifying that Mission (`id`,
   `issuer`). A resource server enforces statelessly from the token.
6. **Stop issuance.** Token issuance and refresh are **gated on
   Mission state**: a Mission that is not `active` yields no further
   derivation ({{issuance-gating}}), including from any grant lineage
   bound to it ({{grant-binding-state}}). Revoking or expiring the
   Mission therefore stops the agent from obtaining further
   authority.

Steps 3 to 6 state the properties this document provides;
{{conformance}} states the requirements that realize them.

A user thus approves the authority for a task once, and that
approval, not a per-request scope grant, bounds and outlives every
token the agent derives. The Mission Record commits the consented
authority once, as `authority_hash`; a party holding the complete
Authority Set can recompute the commitment and compare the result
with `authority_hash` ({{consent-binding}}). Mission Approved-Set
Verification
({{I-D.draft-mcguinness-oauth-mission-approved-set-verification}})
defines how a token that carries only a narrowed subset is checked
against the complete set.

This chain is the first of two enforcement layers, and a deployment
can run it alone: a resource server need not be Mission-aware unless
it receives delegated tokens ({{rs-enforcement}}). A Mission-unaware
resource server that authorizes only from `scope` operates within the
Mission only where the AS establishes that its scope projection and
the resource's independent controls cannot over-grant
({{scope-projection}}). The chain provides task-bound issuance,
auditability, and a revocation gate over future derivation.

The chain does not evaluate individual actions, so token lifetime
and narrow authority bound the exposure between issuance and use.
The second layer, a separately specified runtime layer
({{runtime-boundary}}), adds a per-action check for the action
classes whose consequence needs one.

## Implementation Map {#implementation-map}

The starting path is one client, one authorization server, direct
approval, and a single resource audience, with no runtime profile,
delegated token, or cross-domain projection; {{conformance}} states
the complete roles and optional capabilities. The worked flow
({{first-mission}}) follows one Mission along this path with concrete
times. Each implementer's duties on the starting path, with the
sections that define them:

Mission Client:
: Submits an Intent through PAR ({{submission-via-par}}), optionally
  proposes authority ({{authority-proposal}}), completes the
  authorization-code flow, and reads the granted authority and Mission
  references from the response ({{token-response}},
  {{mission-response-parameters}}). Authorization Server Metadata
  ({{discovery}}) holds the metadata the client reads before it
  submits, and the client's rules for an AS whose Mission support is
  not established and for a credential that is not Mission-bound.

Mission Issuer (AS):
: Its duties on the starting path:

  - validate the submission and derive bounded authority
    ({{submission-processing}}, {{authorization-derivation}});
  - obtain approval, commit the Mission, and bind the grant to it
    ({{direct-approval-steps}}, {{mission-record}}, {{grant-binding}});
  - gate every issuance and refresh on the Mission's state, its
    Authority Set, its expiry, and any emitted `scope` value's
    projection ({{issuance-gating}}); and
  - terminate the Mission on an authorized revocation
    ({{revocation}}).

Mission-aware Resource Server:
: Validates the credential and any sender constraint, enforces the
  carried authority, and applies any configured Mission requirement
  ({{rs-enforcement}}, {{introspected-consumption}}).

This document defines no `authorization_details` type
({{other-types}}). Each Authority Set entry is of a type the AS
supports, such as `mission_resource_access`
({{I-D.draft-mcguinness-oauth-mission-resource-access}}), and a
Mission-aware Resource Server enforces each applicable entry its tokens
carry under that entry's type ({{rs-requirements}}).

The following index names every section an implementer of each
operation needs, by phase, including delegation, which the starting
path excludes; the cited sections govern. Each issuing operation
names the issuance checks ({{issuance-checks}}) and the sections they
cite for it.

Mission creation (client, AS):
: From discovery to the first token response:

  - submission: {{mission-intent}}, {{intent-members}},
    {{submission-via-par}}, {{authority-proposal}},
    {{intent-submission-evidence}}, {{submission-processing}},
    {{commitment-mechanisms}}, {{discovery}};
  - authority: {{authorization-derivation}}, {{derivation-modes}},
    {{consented-authority-set}}, {{subset}}, {{other-types}},
    {{transformation-capabilities}};
  - approval: {{approval-event}}, {{approval-code-protection}},
    {{direct-approval-steps}}, {{approval-preparation}},
    {{approval-commit}}, {{subject-establishment}},
    {{rendering-safeguards}}, {{approval-context-changes}},
    {{authority-sources}}, {{approval-authentication}},
    {{grant-binding-resolution}};
  - Mission Record: {{mission-record}}, {{lifecycle}},
    {{record-identity-members}}, {{record-content-members}},
    {{record-principal-members}}, {{record-provenance-members}},
    {{mission-id}}, {{integrity-anchors}}, {{canonicalization}};
  - code redemption: {{issuance-checks}}, with
    {{mission-response-parameters}}, {{issuance-gating}},
    {{token-claims}}, {{token-response}}, {{refresh-tokens}},
    {{token-authentication-lifetime}}, {{scope-projection}},
    {{mission-claim}}, {{mission-claim-reservation}}, and, for an
    opaque token, {{introspected-consumption}}; and
  - throughout: {{error-mapping}}, {{conformance-roles}},
    {{claiming-conformance}}.

Refresh (client, AS):
: A refresh under a Mission-bound refresh token, narrowing or not:

  - request and grant: {{refresh-tokens}}, {{authority-proposal}},
    {{grant-binding-resolution}}, {{grant-binding-state}};
  - issuance: {{issuance-checks}}, with {{subset}},
    {{transformation-capabilities}}, {{lifecycle}}, {{termination}},
    {{revocation}}, {{mission-response-parameters}},
    {{issuance-gating}}, {{token-claims}}, {{token-response}},
    {{token-authentication-lifetime}}, {{scope-projection}},
    {{mission-claim}}, {{mission-claim-reservation}},
    {{remediation-grains}}, and, for an opaque token,
    {{introspected-consumption}}; and
  - throughout: {{error-mapping}}, {{conformance-roles}}.

Designation and delegated exchange (delegating party, delegate, AS):
: Obtaining a designation and redeeming it:

  - support and selection: {{delegation}}, {{self-exchange}},
    {{discovery}}, {{optional-capabilities}};
  - designation: {{designation}}, {{authority-proposal}},
    {{grant-binding-resolution}}, {{grant-binding-related}},
    {{composite-active}};
  - delegated exchange: {{delegated-exchange}},
    {{grant-binding-state}}, {{rs-mission-unaware}},
    {{delegated-instance-context}}, {{delegation-constraints}},
    {{worked-example-delegated-token}}, {{client-id-rebinding}};
  - issuance, for both: {{issuance-checks}}, with {{subset}},
    {{transformation-capabilities}}, {{lifecycle}},
    {{mission-response-parameters}}, {{issuance-gating}},
    {{token-claims}}, {{token-response}},
    {{token-authentication-lifetime}}, {{scope-projection}},
    {{mission-claim}}, {{mission-claim-reservation}}, and, for an
    opaque token, {{introspected-consumption}}; and
  - throughout: {{error-mapping}}.

Resource-server enforcement of a JWT (RS):
: Validating and enforcing a JWT Mission-bound token:

  - validation: {{rs-enforcement}}, {{token-claims}},
    {{mission-claim}}, {{mission-claim-reservation}},
    {{protected-resource-metadata}};
  - enforcement: {{rs-requirements}}, {{token-response}},
    {{rs-carried-authority}}, {{delegated-instance-context}},
    {{delegation-constraints}};
  - denial: {{rs-denials}}, {{remediation-grains}}, {{error-mapping}},
    {{denial-disclosure}}; and
  - where it introspects to observe Mission state: {{introspection}},
    {{lifecycle}}, {{termination}}, {{composite-active}},
    {{integrity-anchors}}.

Resource-server enforcement by introspection (RS):
: Resolving an opaque Mission-bound token through introspection or
  issuer-local resolution:

  - resolution: {{introspected-consumption}}, {{lifecycle}},
    {{termination}}, {{introspection}},
    {{caller-authorization-and-minimization}}, {{composite-active}},
    {{only-issuer-reports-state}}, {{examples}}, {{integrity-anchors}},
    {{discovery}};
  - enforcement, under the rules for a JWT: {{rs-enforcement}},
    {{rs-requirements}}, {{token-response}}, {{mission-claim}},
    {{rs-carried-authority}}, {{delegated-instance-context}},
    {{delegation-constraints}}, {{protected-resource-metadata}}; and
  - denial: {{rs-denials}}, {{remediation-grains}}, {{error-mapping}},
    {{denial-disclosure}}.

The following table summarizes which surfaces apply, to whom, and
when; the cited sections govern. Ordinary JWT consumption does not
require retrieving the Mission Record or recomputing the complete
approved Authority Set.

| Surface (role) | Applies | Defined in |
| --- | --- | --- |
| Mission Intent via PAR (client, AS) | Mission-creating requests on the authorization-code path; companion-defined back-channel carriage follows its profile | {{submission-via-par}} |
| Direct approval (AS); the Mission Record (AS) | Every direct approval event; the Mission Record at every approval event | {{direct-approval-steps}}, {{mission-record}} |
| Evidence dispatch and refusal (AS) | Implemented by every AS, even one that supports no evidence type; applied to each presented entry | {{intent-submission-evidence}} |
| Authority proposal (client, AS) | Optional for the client; the AS checks one that is submitted | {{authority-proposal}} |
| Grant binding (AS) | Authorization-code lineages and other profile-defined reusable grants, including their refresh-token families | {{grant-binding}} |
| Issuance gating (AS) | Every derivation, refresh and Token Exchange included | {{issuance-gating}} |
| Scope projection (AS) | Every issuance that emits `scope` or whose request names a `scope` value; a `scope`-only target gets a safe projection or a refusal | {{scope-projection}} |
| Sender constraint, primary and refresh tokens (AS) | Recommended for the access token, which may be a bearer token; a public client's refresh token is sender-constrained or rotated | {{token-claims}}, {{refresh-tokens}} |
| Sender constraint, delegation and cross-domain (AS, RS) | The token presented for a designation is sender-constrained, and the designation carries no `cnf`; a delegated token is bound to the delegate's own key; across trust domains, as the cross-domain companion requires | {{designation}}, {{delegated-exchange}}, {{token-claims}} |
| Revocation means (deployment) | An authenticated revocation by `mission_id`, independent of any token | {{revocation}} |
| Enforcement (Mission-aware RS) | Every request the resource server serves | {{rs-enforcement}} |
| Introspection (AS, RS) | Optional; required for opaque tokens served without issuer-local resolution | {{introspection}}, {{introspected-consumption}} |
| Delegation, Cross-Domain (AS, client, RS) | Optional capabilities | {{delegation}}, {{optional-capabilities}} |
| Standing consent (AS) | Only under a companion profile's standing-consent basis | {{standing-consent-bases}} |
{: title="Applicability of this document's surfaces"}

The following table lists the choices this document leaves to a
deployment, who makes each, and, for each party that needs to learn
it, the existing signal, if any, from which that party learns it. A
signal serves only the party entitled to read it: a client treats an
access token as opaque ({{Section 6 of RFC9068}}), so a token's header
and claims are resource-server signals. Where no signal exists, the
table says so, and the party relies on the deployment's documentation
or configuration. The cited sections govern.

| Choice point | Decided by | Who learns it, and how |
| --- | --- | --- |
| Access-token format: JWT or opaque reference token ({{mission-bound-tokens}}) | AS | Resource server: a JWT's `typ` header parameter value `at+jwt` ({{token-claims}}, {{Section 4 of RFC9068}}); no in-band signal marks an opaque token, which it resolves as its deployment arranges ({{introspected-consumption}}). Client: none; it treats every access token as opaque |
| Introspection, and issuer-local resolution of an opaque token ({{introspection}}, {{introspected-consumption}}) | AS | Resource server: the `introspection_endpoint` AS metadata ({{RFC8414}}); for issuer-local resolution, none, since the AS authorizes each reader inside its trusted implementation boundary |
| Sender constraint: bearer, DPoP, or mTLS ({{token-claims}}) | AS, on the client's proof, if any | Resource server: the token's `cnf` claim, or the `cnf` member of an active introspection response ({{rs-enforcement}}, {{introspected-consumption}}). Client: for DPoP, the binding applied to the issued token, from `token_type` `DPoP` in the token response ({{Section 5 of RFC9449}}); for mTLS, the AS's mTLS metadata ({{Section 3.3 of RFC8705}}) states only that the AS supports certificate-bound tokens, and no token-response member says a given token is bound. A resource's DPoP requirement or mTLS support comes from its protected resource metadata ({{RFC9728}}), which also states support, not the binding of a given token. Settled for delegation: a designation is requested with a sender-constrained token, and a delegated token is bound to the delegate's own key ({{designation}}, {{delegated-exchange}}) |
| Authorization-code binding: PKCE `S256` or a DPoP-bound code ({{approval-code-protection}}) | Client, among the methods the AS accepts | AS: the request's `code_challenge` ({{RFC7636}}), or its `dpop_jkt` parameter or DPoP proof ({{Section 10 of RFC9449}}). Client: the `code_challenge_methods_supported` ({{RFC8414}}) and `dpop_signing_alg_values_supported` ({{Section 5.1 of RFC9449}}) AS metadata |
| Refresh-token binding: client authentication, sender constraint, or rotation ({{refresh-tokens}}) | AS | Client: under rotation, a new refresh token in each refresh response ({{Section 6 of RFC6749}}); for a DPoP binding, none beyond its own proof when it obtained the refresh token ({{Section 5 of RFC9449}}) |
| Mission support ({{discovery}}) | AS | Client: the `mission_bound_authorization_supported` AS metadata; otherwise, out of band |
| Supported types and their schemas ({{other-types}}) | AS; each resource server, for the types it accepts | Client: the AS's `authorization_details_types_supported` metadata ({{RFC9396}}) and, where advertised, its types metadata endpoint ({{discovery}}); a resource server's `authorization_details_types_supported` metadata ({{protected-resource-metadata}}) |
| Derivation mode: authority proposal or configured mapping ({{derivation-modes}}) | Client, by proposing or not; deployment, by configuring mappings | Client: no metadata signal; the deployment publishes its mapping space as deployment documentation |
| Transformation capabilities per type: `narrowing`, `delegation`, `projection` ({{transformation-capabilities}}) | AS operator, per type | Client, in order of preference: a `mission_transformation_capabilities` member in the type's entry at the types metadata endpoint, an equivalently shaped member of supported-type documentation, or deployment documentation. Resource server: none needed; it enforces entries as carried ({{delegation-constraints}}). Settled: the first carrier that declares a member governs, and a declared `narrowing` also governs Authority Set derivation |
| Each entry's audience ({{transformation-capabilities}}) | Deployment | AS: a trusted entry-to-audience mapping, such as authenticated configuration or protected resource metadata ({{RFC9728}}). Client: none; it requests an audience with `resource` and reads the granted entries from the token response ({{token-response}}) |
| Scope projection for a target ({{scope-projection}}) | Deployment, per target | AS: the target's protected resource metadata ({{RFC9728}}) or authenticated out-of-band configuration |
| Mission-governed resources ({{authority-proposal}}) | Deployment, or the resource through its metadata | AS and client: the `mission_bound_authorization_required` protected resource metadata ({{protected-resource-metadata}}), which the AS authenticates; a deployment's own classification has no signal, and `false` or omission does not clear it. Resource server: its own configuration ({{rs-requirements}}) |
| Delegation support ({{delegation}}) | AS | Delegating party and delegate: `grant_types_supported` listing the Token Exchange grant type ({{discovery}}); otherwise, out of band or by attempt. Settled: a delegate is identified by its client authentication, an `actor_token` is refused, and a public client is not a delegate ({{delegated-exchange}}) |
| Audiences that process the `act` chain ({{rs-mission-unaware}}) | Deployment | AS: no protocol signal; neither parsing `act` nor `mission_bound_authorization_required` establishes it, and the AS establishes it by deployment means, for example its configuration |
| Designated-client separation ({{designation}}) | Deployment | AS: no protocol signal; the AS establishes by deployment means, for example its configuration, that no resource server accepts the client's identifier as an audience |
| Designation redemption count ({{designation}}) | AS | Delegate: no protocol signal; the AS's policy governs, and deployment documentation may describe it. An attempt reveals only its own outcome, not the permitted count |
| Subject-authentication conveyance ({{rs-denials}}) | Deployment | Resource server: the `acr`, `amr`, and `auth_time` claims ({{token-authentication-lifetime}}), or introspection ({{Section 6 of RFC9470}}); where no Subject authentication applies, they are absent |
| Revocation means ({{revocation}}) | Deployment | A party authorized to revoke: none in this document; a deployment-defined surface, or Mission Status's `revoke` operation |
{: title="Deployment choices and how each party learns them"}

## Applicability {#applicability}

This document targets OAuth deployments where authority serves a
durable, approved task that spans more than one token, request, or
audience: an agent pursuing a multi-step objective on a user's
behalf, or a workflow whose audit must join activity across hops on
a shared task.

This document is not intended for single-request user flows and
short-lived authorizations where the credential's lifetime is the
task's lifetime, ordinary machine-to-machine service credentials
among them; those use OAuth unchanged. The boundary is that lifetime
equality, not the absence of a human: a workload's durable
multi-step task is in scope as a service-owned Mission
({{authority-sources}}).

The direct realization creates each Mission at an approval
interaction on the authorization endpoint.
{{I-D.draft-mcguinness-mission-architecture}} (Section "Mission
Creation Paths") maps the paths where an administrator, or a policy a
human consented to, decides without one.

A Mission is intended to cover one concrete task, not an agent's
whole lifetime. Narrow Missions, each separately approved and
revocable, are preferred over one broad standing Mission that
accumulates authority across unrelated tasks.

This preference has a consent cost: many narrow Missions can create
approval fatigue, and combining unrelated authority into one broad
Mission can make approval difficult to evaluate. A useful boundary
is a task whose purpose, authority, and bounds the Approver can
evaluate together ({{approval-comprehension}}).

Optional companions can reduce repeated approvals through standing
consent ({{standing-consent-bases}}): for example, a template, an
authority ceiling, or a policy that a human approved once governs
later Missions. The template, ceiling, or policy still needs a
meaningful human approval, and no such mechanism removes its
profile's human-approval requirement for high-consequence authority.

The unit of governance is the action, not the content. A Mission
bounds where an agent may act (resources, actions) and how much
(constraints and, where metered, cumulative bounds). It does not
inspect the content that flows within an authorized action: an
approved egress channel carries a status update or an exfiltrated
payload with equal authority. Content-level controls (data loss
prevention, redaction) are complementary; under mediated execution
they fit at the mediating enforcement component
({{runtime-boundary}}).

# Overview {#overview}

## Protocol Flow {#protocol-flow}

Besides the agent (the OAuth client) and the Mission Issuer (the
AS), the flow involves two principals: the Subject, on whose behalf
the Mission is approved, and the Approver, who approves it.
{{conventions-and-terminology}} defines these and the other terms.

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

After token issuance, resource access and lifecycle management proceed
as follows:

(4) The agent calls the resource server with the token. The resource
server enforces the `authorization_details` statelessly and can check
the `mission` claim ({{rs-enforcement}}), with no callback to the AS
required.

(5) A revocation ({{revocation}}), or `expires_at`
passing, moves the Mission
to `terminated`, with reason `revoked` or `expired`, after which the
AS refuses further issuance and refresh. A deployment can also treat
{{RFC7009}} revocation of the refresh token as revoking the Mission
({{revocation}}).

The end-to-end example ({{e2e-example}}) walks this flow with
concrete messages.

## Introductory Example {#first-mission}

In the examples in this document, each service's operation contract
identifies the service's own identifier, such as
`https://erp.example.com`, as the operation target
({{I-D.draft-mcguinness-oauth-mission-resource-access}}). Actions and
constraints determine the permitted operations within that service.

The following example shows a registered client reading invoices
from one ERP resource for Alice, who is both the Subject and the
Approver; the authority source is user-delegated. The AS and ERP
support the `mission_resource_access` type defined by
{{I-D.draft-mcguinness-oauth-mission-resource-access}}. The example
uses a direct approval, a JWT access token, no delegated token, and
no submission evidence (the AS's admission policy requires none).
All times are UTC on the same day.

1. **Submit.** The client pushes a Mission Intent naming
   `https://erp.example.com` and requesting expiry at 13:00, with a
   proposed `authorization_details` entry of type
   `mission_resource_access` for that resource and the action
   `invoices.read`. It follows the PAR `request_uri` into the
   authorization interaction ({{submission-via-par}}).
2. **Approve and commit.** At 12:00 the AS authenticates Alice,
   verifies the authority source and proposed read authority, and
   renders that authority and the effective 13:00 expiry for her
   approval. On approval it atomically creates the active Mission,
   records its commitments, and binds the authorization code to it
   ({{direct-approval-steps}}, {{grant-binding-resolution}}).
3. **Issue.** Still at 12:00, the client redeems the code. The AS
   resolves and checks the Mission and returns a sender-constrained
   ERP token that expires at 12:05, with the read authority and a
   `mission` reference. The response also carries the granted
   authority ({{token-response}}), `mission_id`, and
   `mission_expires_at`; the access token's five-minute lifetime is
   distinct from the Mission's one-hour lifetime
   ({{mission-response-parameters}}).
4. **Use.** The ERP is a Mission-aware Resource Server: it enforces
   the `mission_resource_access` entry itself, work a plain
   {{RFC9068}} resource server does not do ({{conformance}}). It
   validates the token and proof of possession and permits the
   authorized read; the
   token grants no write authority. The resource request involves no
   Mission-state lookup or complete-set retrieval ({{rs-enforcement}}).
5. **Stop further issuance.** At 12:02 an authorized revocation makes
   the Mission non-active. A subsequent refresh, if the AS issued a
   refresh token, is refused with the `invalid_grant` error code
   ({{issuance-gating}}). The already-issued access token can still
   be honored on this stateless path until 12:05; revocation does not
   undo a completed read ({{revocation}}).

An ERP that instead introspects on every request stops honoring the
token on its next request after revocation, through the composite
`active` result ({{composite-active}}).

The later message examples use the end-to-end example's separate Q3
reconciliation Mission ({{e2e-example}}), whose approved authority
includes invoice reads and bounded journal writes. Its identifiers and
timeline differ from this introductory example.

# Conventions and Terminology {#conventions-and-terminology}

{::boilerplate bcp14-tagged}

All JSON shown in this document is non-normative and illustrative; the
member definitions in the surrounding text are authoritative. An
example line too long for the page is folded with the single backslash
strategy of {{RFC8792}}.

## Terminology {#terminology}

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
  direct approval event or, under a standing-consent basis, through the
  earlier standing consent ({{standing-consent-bases}}). Equal to the
  Subject for self-approval; different for administrator or delegated
  approval. Multi-party approval and the provenance of delegated
  approval authority are out of scope ({{multi-party-approval}}).

Mission Issuer (authorization server):
: The OAuth AS that validates a Mission Intent, runs the approval
  event, records the Mission, and derives tokens. It is the Mission's
  `issuer`; this document also calls it the "issuer AS" or the "AS".

Mission Client:
: The client conformance role, defined in {{conformance}}.

Mission-governed client:
: A client that the deployment registers as Mission-governed ("a client
  registered as Mission-governed"); {{authority-proposal}} states the
  rule that registration triggers.

Mission-aware Resource Server:
: The resource server conformance role, defined in {{conformance}}.

Resource AS:
: An authorization server in another trust domain that honors a
  Mission it did not issue, minting its own tokens for its resources;
  it is never the Mission Issuer. The companion Mission Cross-Domain
  Projection profile specifies cross-domain projection
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
  authenticated policy input, not authority. The term names only
  inbound, client-presented material, not the issuer- or
  runtime-produced evidence this document and companion profiles emit
  and record (a consent-evidence artifact, an audit evidence base).

Authority Proposal:
: The `authorization_details` array a client submits alongside a
  Mission Intent, a proposal for Authority Set derivation and not
  authority ({{authority-proposal}}).

Authority Set:
: The set of `authorization_details` entries the AS derives from a
  Mission Intent and the Approver approves
  ({{authorization-derivation}}).

Authority Set derivation:
: Computing the Authority Set from a Mission Intent and any authority
  proposal, in narrowing or configured-mapping mode
  ({{derivation-modes}}).

Derivation:
: One issuance operation the issuer AS performs for a single request
  ({{issuance-gating}}): the initial authorization-code exchange, a
  refresh, a Token Exchange, a cross-domain grant issuance, or the
  redemption of a profile-defined grant, such as the Template
  profile's handoff grant.
  Distinct from Authority Set derivation, which some section titles
  and fixed phrases, such as "derivation policy", also call
  derivation.

Mission:
: The durable authorization object that binds a disclosed task (its
  Mission Intent) to an explicitly approved Authority Set and governs
  the lifecycle of the authority derived from that approval. It is the
  record created at the approval event ({{mission-record}}), immutable
  except for its `state` and `termination` members, identified by a
  Mission Identifier ({{mission-id}}) and, globally, by
  the pair (`issuer`, `id`). A Mission is independent of any OAuth
  grant ({{grant-binding}}). "The approved task" is shorthand for this
  binding: the Approver approves the Authority Set, and the task is
  disclosed and committed beside it.

Mission grant binding (grant binding):
: The AS-controlled, functional mapping from one persistent,
  redeemable grant lineage to exactly one Mission ({{grant-binding}}).
  Distinct from a Derived token's own `mission` claim, which every
  Derived token carries without itself creating a grant binding.

Mission-referenced token:
: A token that carries a Mission reference (for example, a
  `mission_id` or a descriptor a companion profile defines) without
  Mission-derived authority or any gating guarantee. An access token
  of this class does not carry the `mission` claim
  ({{mission-claim-reservation}}).

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

Applicable entry:
: An `authorization_details` entry that applies, under the entry's
  type, to a request to a resource server: where the type defines a
  `resource`, the request's operation target matches it under that type
  ({{token-response}}). {{rs-requirements}} governs an entry whose type
  the resource server does not implement, or whose type-defined
  enforcement it cannot complete.

Delegate:
: A sub-agent, service, or tool, itself an OAuth client authenticated
  as a distinct actor, that obtains a delegated token by Token Exchange
  ({{delegation}}).

Delegating party:
: The holder of a Mission-bound access token that obtains a
  designation for a delegate: the Mission's approved agent, or a
  delegate delegating further ({{designation}}).

Designation:
: The delegating party's authorization, obtained by Token Exchange,
  for one delegate to obtain delegated tokens ({{designation}}).

Delegated exchange (delegated token):
: The Token Exchange in which a delegate redeems a designation naming
  it for a delegated token, whose `act` claim names that delegate as
  the current actor ({{delegated-exchange}}).

Self-exchange (no-actor exchange):
: A Token Exchange with no actor in which an agent presents its own
  Mission-bound access token to obtain a narrowed one; it delegates
  nothing ({{self-exchange}}).

## Principal Model {#principal-model}

This document maps principals onto native OAuth constructs:

- The **Agent** is the OAuth client, referenced by `client_id`; its
  identity and credentialing are out of scope
  ({{I-D.draft-ietf-wimse-aims}}).
- The **Subject** and **Approver** are each an (`iss`, `sub`) pair,
  matching the access token `sub` model of {{RFC9068}}. The Approver
  is the accountable consent principal whose approval created the
  Mission, always equal to `approval_basis.consent_principal`. Under
  a standing-consent basis, the Approver remains the human whose
  consent roots the Mission ({{standing-consent-bases}}).

On a derived token, the `iss` claim is the AS and the `sub` claim is
the AS-local `sub` to which the AS maps the Subject under the
injective mapping of {{subject-establishment}}; adopting the external `sub`
verbatim is the common case. Within the issuing AS's namespace, this
(`iss`, `sub`) pair is the AS-local subject principal, authoritative
for the Subject, and resource servers authorize against it.

The Mission separately records the Subject's home issuer and
identifier as `subject.iss` and `subject.sub`: the external subject
identity, carried as provenance for audit and not on the token. This
document defines no runtime lookup of it.

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
the test compares principals only within one issuer namespace and
never compares the external subject identity with the AS-local
subject principal.

Dynamic delegation (the actors an agent delegates to during
execution) is carried on derived tokens in the `act` chain
({{delegated-exchange}}), not on the Mission Record. This
document uses only (`iss`, `sub`) pairs, not the subject identifier
formats of {{RFC9493}}.

# Mission Intent {#mission-intent}

A Mission Intent is a JSON object describing the task. The client
submits it as the `intent` member of the Submission envelope
({{submission-via-par}}), in place of `scope` or alongside a narrowed
`scope`.

Before the approval event ({{approval-event}}), only the Mission Intent
exists, as untrusted client input ({{submission-via-par}}); after it,
only the Mission is authoritative. A Mission Intent therefore has no
protocol identifier of its own: two submissions of the same Intent
produce two distinct pending requests, and a Mission acquires its
Mission Identifier ({{mission-id}}) only at activation.

The approved Intent carries no authority members. The task, the proposed
authority, and the granted authority are committed separately
({{integrity-anchors}}):

- `intent_hash` commits the approved Intent, which is recorded on the
  Mission;
- `proposal_hash` commits any authority proposal, which the client
  submits separately, on the standard `authorization_details` parameter
  ({{authority-proposal}}); and
- `authority_hash` commits the granted authority, the derived Authority
  Set ({{authorization-derivation}}).

The client writes every Intent member; how it produces them, for
example through a Mission Shaper working from a natural-language
instruction, is out of scope ({{the-mission-the-plan-and-execution}}).
The prose members (`goal`, `task_bounds`) bound authority only through
disclosure: the Approver refuses authority the words do not support
({{authorization-derivation}}).

An AS that makes no use of an optional member still accepts it and
records it with the Intent ({{submission-processing}}). The smallest
Intent carries only the three required members, as in the Submission
envelope example ({{submission-via-par}}). The following summary is
informative; the member definitions after it are authoritative.

## Intent Members {#intent-members}

| Member | Required | What the AS does with it |
| --- | --- | --- |
| `goal` | yes | Records it and renders it to the Approver as inert text; never interprets it |
| `goal_lang` | no | Checks the language tag and uses it when rendering |
| `target_resources` | yes | Bounds the resources a derived entry can name; can key a configured mapping |
| `task_bounds` | no | Records it and renders it to the Approver as inert text; never interprets it |
| `purpose` | no | Records it; can key a configured mapping; in any other decision can only lead to a refusal or stricter treatment |
| `expires_at` | yes | Caps the Mission's effective expiry; refuses a malformed or past value |
{: title="Mission Intent members at a glance"}

The Mission Intent members are:

`goal`:
: REQUIRED. A string. A human-readable statement of the task,
  for rendering to the Approver. It can describe the outcomes that
  show the task is complete; like the rest of the prose, that
  description carries no machine semantics
  ({{authorization-derivation}}). Maximum 4096 characters. Prose
  here persists on the record and can carry personal data about
  third parties ({{third-party-data-subjects}}).

`goal_lang`:
: OPTIONAL. A string. A BCP 47 language tag {{RFC5646}} declaring the
  language of the Intent's human-readable members (`goal`,
  `task_bounds`). It is disclosure metadata for rendering, committed by
  `intent_hash` like every Intent member, and carries no machine
  semantics ({{authorization-derivation}}). At submission acceptance,
  the AS MUST refuse a `goal_lang` that is not a well-formed language
  tag with `invalid_request` ({{i18n}}).

`target_resources`:
: REQUIRED. An array of strings. A client-requested Intent ceiling on
  the task's target resources, each an absolute URI identifying a
  protected resource (an OAuth resource per {{RFC8707}}-style indicators
  or a protected resource per {{RFC9728}}). It bounds which resources a
  derived Authority Set entry may name ({{authorization-derivation}})
  and serves as a configured-mapping lookup key ({{derivation-modes}});
  like `purpose`, the key alone grants no authority. It is not RFC 8707
  `resource` carriage: a client separately requests the audience of a
  given token with the standard `resource` parameter
  ({{token-response}}).

`task_bounds`:
: OPTIONAL. An array of strings. Human-readable bounds on the task
  (for example, "read only invoices from 2026"). They are disclosure
  and audit context, rendered to the Approver beside the derived
  Authority Set ({{direct-approval-steps}}), and carry no machine
  semantics ({{authorization-derivation}}); a machine-enforceable bound
  enters as structure instead.

`purpose`:
: OPTIONAL. A string. A URI identifying the purpose of the task,
  recorded for disclosure and audit. Its semantics are deployment- or
  registry-defined and opaque to this document.

  `purpose` is an opaque lookup key: a configured mapping can key on it
  to select candidate entries, which the Intent, policy, and the
  approval event bound as in any Authority Set derivation
  ({{authorization-derivation}}); the key alone grants no authority. In
  any other decision, `purpose` MAY contribute only to a refusal or to
  stricter treatment: its value, its absence, or a substituted value
  MUST NOT supply, widen, relax, or refresh authority, or replace a
  check that applies independently of it. After approval, the `purpose`
  consulted is the approved Mission's, or a validated projection of it.

`expires_at`:
: REQUIRED. A string. An RFC 3339 {{RFC3339}} date-time: the client's
  requested not-after ceiling for the Mission's lifetime. The submitted
  Intent is recorded verbatim. The granted lifetime is the Mission
  Record's effective `expires_at`, which the AS establishes at Mission
  creation and which is no later than this value
  ({{direct-approval-steps}}, {{mission-record}}).

  At submission acceptance, the AS MUST refuse a malformed or
  already-past value with `invalid_request`. Acceptance does not
  freeze time: Mission creation re-checks the effective expiry
  atomically at the commit ({{direct-approval-steps}}). A request that
  resolves to an already-committed operation is recovery, not a new
  submission, and returns the stored outcome under the applicable
  idempotency rules even when the ceiling has since passed
  ({{mission-response-parameters}}, {{mission-record}}).

The Approver's authentication strength for the approval event is
requested with the standard `acr_values` and `max_age`
authorization-request parameters, not on the Intent
({{approval-authentication}}).

The Mission Intent's top level is closed to the members above and to
those a companion profile the AS implements defines
({{extensibility}}, {{submission-via-par}}).

The following is an example of a Mission Intent:

~~~ json
=============== NOTE: '\' line wrapping per RFC 8792 ===============

{
  "goal": "Reconcile Q3 invoices and post adjustments of at most \
    USD 500 per journal entry.",
  "target_resources": ["https://erp.example.com"],
  "task_bounds": [
    "Read only invoices issued in 2026-Q3.",
    "Post journal entries of at most USD 500 each."
  ],
  "purpose": "urn:example:purpose:reconcile",
  "expires_at": "2026-12-31T23:59:59Z"
}
~~~

## Submission via PAR {#submission-via-par}

On the authorization-code path ({{approval-event}}), a client MUST
submit a Mission Intent through a Pushed Authorization Request
{{RFC9126}} using the `mission_intent` request parameter. The parameter
value is the UTF-8 JSON {{RFC8259}} serialization of the Submission
envelope, form-encoded in the `application/x-www-form-urlencoded` PAR
request body like any other OAuth parameter. The Submission envelope is
a JSON object with exactly these members:

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
- **Carriage through PAR.** On the authorization-code path, the
  AS accepts the Intent in one of two forms:

  1. the form-encoded `mission_intent` parameter of the PAR request
     body; or
  2. a `mission_intent` claim inside a signed Request Object
     ({{RFC9101}}) that is itself pushed through PAR. The claim's
     value is the Submission envelope itself, a JSON object, not its
     serialization; the AS MUST reject with `invalid_request` a claim
     whose value is a string or any other value that is not a JSON
     object.

  The AS MUST reject with `invalid_request` a `mission_intent` presented
  on a front-channel authorization request that does not use a
  PAR-issued `request_uri`. A client MUST NOT send `mission_intent` as a
  plaintext front-channel authorization-request parameter, whether or
  not a Request Object is also present.

  When the pushed request carries a Request Object (a `request`
  parameter value), that object is authoritative: a `mission_intent`
  submitted outside the Request Object in the same push MUST be rejected
  with `invalid_request`, strengthening {{Section 6.3 of RFC9101}},
  under which the AS would only ignore such a value.
- **Alternative back-channel profiles.** A Mission Intent travels on no
  other request unless a companion profile explicitly defines that
  request as a back-channel carriage of the Submission envelope. Such a
  profile carries the envelope and any authority proposal in one request
  that never traverses a user agent, and preserves:

  - this section's envelope and proposal rules;
  - the processing order ({{submission-processing}});
  - Authority Set derivation ({{authorization-derivation}});
  - the approval-event rules for the Mission's approval basis
    ({{approval-event}}, {{standing-consent-instances}}, with a direct
    approval relocated only as {{extensibility}} permits); and
  - the grant binding ({{grant-binding}}).

  Support for a grant type or endpoint never establishes such a carriage
  on its own. The experimental Mission Device Authorization profile
  ({{I-D.draft-mcguinness-oauth-mission-device-authorization}}) defines
  one for a client that cannot complete the authorization-code path, on
  the device authorization grant {{RFC8628}}.
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
  proposal submitted alongside it ({{authority-proposal}}), is untrusted
  client input; trust enters only when the AS validates it and the
  Approver consents to the rendered result. The AS derives and bounds
  authority by its own policy, whatever the client submitted
  ({{authorization-derivation}}).

The following is an example of a Submission envelope carrying a
compact Intent and one evidence entry of an illustrative,
deployment-defined type:

~~~ json
=============== NOTE: '\' line wrapping per RFC 8792 ===============

{
  "intent": {
    "goal": "Reconcile Q3 invoices and post adjustments of at most \
      USD 500 per journal entry.",
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

Policy narrowing is distinct. During Authority Set derivation the AS
MAY omit a syntactically valid entry that policy cannot accept, or
narrow it where the AS has declared `narrowing` for its type
({{authorization-derivation}}, {{transformation-capabilities}}). The granted
`authorization_details` in the token response reflects every
narrowing and omission ({{token-response}}).

When a proposal is present, the AS MUST derive each Authority Set
entry as a subset ({{subset}}) of some proposed entry of the *same
type*: narrowed under that type's own subset rule where the AS has
declared `narrowing` for the type, or carried through unchanged
otherwise ({{transformation-capabilities}}).

`goal` and `task_bounds` then serve as rendering and bounding context
over the proposed authority. Each proposed entry that carries a
`resource` member MUST have it among the Intent's `target_resources`,
compared as {{authorization-derivation}} states; the AS refuses a
request violating this with the `invalid_request` error code.

The carriage rules of {{submission-via-par}} apply to the proposal.
The AS records the array on the Mission exactly as submitted and
commits it by `proposal_hash` ({{integrity-anchors}},
{{mission-record}}), separately from the task (`intent_hash`) and
the approved Authority Set (`authority_hash`), so a narrowed
approved Authority Set can be audited against the proposal that
sought it.

Submitting `authorization_details` without `mission_intent` is an
ordinary {{RFC9396}} request that this document does not govern. Two
AS-side rules keep a governed task from being downgraded to such a
request ({{discovery}} states the client-side rules and
{{downgrade-by-omission}} the threat):

- Where a resource is Mission-governed, its AS MUST NOT issue a token
  for that resource outside a Mission, on any grant type. A resource is
  Mission-governed (a Mission-governed resource) when the deployment
  classifies it so, or when protected resource metadata the AS has
  authenticated ({{RFC9728}}) declares
  `mission_bound_authorization_required` as `true`
  ({{protected-resource-metadata}}). Metadata that omits the member or
  sets it to `false` does not clear a deployment's classification, and
  a less restrictive local classification does not override metadata
  that declares the requirement. This document defines no exception to
  this rule; an exception requires a concrete scope that a separate
  specification defines, and none applies to a resource whose
  metadata declares the requirement.
- If a client registered as Mission-governed sends an authorization
  request, through PAR or at the authorization endpoint, that carries
  `authorization_details` but no `mission_intent`, the AS MUST reject
  the request with the `invalid_request` error code, so the client
  cannot drop the Intent from a request that still carries
  `authorization_details`. The rule applies to that request until it
  completes, including when the AS resumes it after an interaction. A
  request carrying neither is an ordinary request that this rule does
  not reach; the first rule, for a Mission-governed resource, is what
  keeps that resource's tokens inside a Mission.

Under the first rule, a token is issued outside a Mission when the
request has no qualifying Mission binding: no grant bound to a Mission
({{grant-binding}}), or to a companion profile's equivalent binding,
from which the issuance derives under {{mission-claim-reservation}}.
The AS refuses a token request the first rule forbids with the
`invalid_target` error code ({{Section 2 of RFC8707}}) once the
request is otherwise processable. Authentication, syntax, and
grant-validation failures keep their errors and precedence, an invalid
or expired grant keeps its error, and a request under a grant bound to
a Mission that is not `active` keeps the refusal of
{{issuance-gating}}. The rule applies to every audience the token
would carry, including one the AS infers or applies by default when the
request names no `resource`: the AS refuses the request if any of them
is Mission-governed, and does not issue the token for the others. On a
refresh, the AS decides this refusal before it consumes or rotates the
refresh token.

A token request under an existing Mission-bound grant, such as a
narrowing refresh, a self-exchange ({{self-exchange}}) or an exchange
for a delegation designation ({{designation}}), needs no
`mission_intent` under the second rule. This exception opens no
Mission submission carriage, and every other check still applies to
the request: Issuance Gating ({{issuance-gating}}), the subset rule
({{subset}}), the first rule above, and the grant's binding to its
Mission, client and sender.

The following is an example of an authority proposal submitted alongside
the example Intent of {{mission-intent}}. Authority Set derivation,
under a declared `narrowing` capability, narrows `invoices.*` to
`invoices.read`, keeps the proposed Q3
issuance window and write ceiling, which the Intent's task bounds
support, and carries the proposed `delegation` policy through
unchanged (the example Authority Set of {{authorization-derivation}}):

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
  `invalid_request` error code at step 1 of the processing order
  ({{submission-processing}}). The AS MUST refuse an entry whose
  `type` it does not support, and an entry that fails its type's
  validation or verification, with the `invalid_mission_intent_evidence`
  error code ({{oauth-extensions-error-registration}}). A
  submission is accepted only when every presented entry verifies.
- **Policy input, not authority.** A verified entry is not copied into
  the Authority Set and does not stand in for the approval event
  ({{approval-event}}), the sole activation of authority. Verified
  evidence can serve as authenticated input to admission and derivation
  policy; AS policy decides whether the verified claims are acceptable
  for this request.

Supporting an evidence type is optional, but these rules are not: an
AS that supports none still applies them and refuses every presented
entry ({{conformance-roles}}).

Mission Intent Submission Evidence for OAuth 2.0
({{I-D.draft-mcguinness-oauth-mission-submission-evidence}}) specifies
the evidence framework, including required-evidence resolution and the
binding of evidence to one Intent and its presenter.

## Submission Processing Order {#submission-processing}

The AS processes a submission in the following order. Steps 1 to 6
run when the submission arrives; step 7 can run provisionally then
and is complete before the approval rendering
({{derivation-modes}}); step 8 belongs to the approval event, and
step 9 to activation.

1. Parse the Submission envelope, enforce both closed top levels and
   the size bounds ({{submission-via-par}}), and check that each
   `evidence` entry is a JSON object with a `type` member
   ({{intent-submission-evidence}}).
2. Validate the `intent` object against the Mission Intent member
   definitions ({{mission-intent}}).
3. Validate any authority proposal: refuse an entry of a type the AS
   does not support, or one that fails its type's definition or a
   schema advertised for it or established out of band, with
   `invalid_authorization_details`, and a proposed entry that carries a
   `resource` member whose value is not among the Intent's
   `target_resources`, with `invalid_request` ({{authority-proposal}}).
4. Compute the provisional `intent_hash` over the `intent` object
   ({{integrity-anchors}}).
5. Apply any submission checks that configured admission policy or
   adopted profiles require before evidence verification, including
   when no `evidence` member is present. For example, the Submission
   Evidence companion resolves required evidence here and refuses a
   missing required type
   ({{I-D.draft-mcguinness-oauth-mission-submission-evidence}}, Section
   "Required Evidence Is Resolved Before Derivation").
6. Dispatch each presented entry on its `type`, and validate and
   verify it under that type's rules ({{intent-submission-evidence}}).
7. Apply admission policy and derive the Authority Set independently
   ({{authorization-derivation}}), including the `target_resources`
   membership of each entry that carries a `resource` member
   ({{derivation-modes}}) and, where a proposal was submitted, that
   each derived entry is a same-type subset of a proposed entry
   ({{authority-proposal}}).
8. Render the Intent, the Authority Set, and the material verified
   provenance for approval; a change to any of them before the
   decision is re-rendered and approved over the changed context
   ({{approval-event}}).
9. At activation, record the approved `intent`, `intent_hash`, the
   Authority Set, and the verified evidence facts as
   `submission_evidence` ({{mission-record}}).

The AS MUST refuse a submission that fails more than one check with
the error of the earliest failing step in this order. For example:

- a malformed proposal together with a missing required evidence
  type is refused at step 3, with `invalid_authorization_details`;
- a proposed entry outside `target_resources` together with a
  presented evidence entry that fails verification is refused at
  step 3, with `invalid_request`;
- an `intent` object that fails validation together with a malformed
  proposal is refused at step 2, with `invalid_request`; and
- a structurally invalid evidence entry together with a malformed
  proposal is refused at step 1, with `invalid_request`.

The material verified provenance of step 8 is part of the approval
surface. Where a deployment commits the rendered approval surface,
that commitment MUST cover the normalized provenance facts, at least
as a digest of their canonical `submission_evidence` representation
({{mission-record}}). For example, the consent-evidence companion
binds them with a `submission_provenance_hash` inside its committed
disclosure ({{I-D.draft-mcguinness-oauth-mission-consent-evidence}}).

# Mission Authority {#authorization-derivation}

From the Mission Intent, and from the authority proposal where one was
submitted ({{authority-proposal}}), the AS derives the
**Authority Set**: one or more {{RFC9396}} `authorization_details`
entries of an AS-supported type ({{other-types}}).

## Derivation Modes {#derivation-modes}

Authority Set derivation is mechanical: one procedure whose candidate
entries depend on whether an authority proposal was submitted:

- **Narrowing mode** (preferred where the client can author
  `authorization_details`): the client submitted an authority
  proposal ({{authority-proposal}}), and the Authority Set is the
  proposal narrowed to policy. Each derived entry is a same-type
  subset of a proposed entry ({{authority-proposal}}).
- **Configured-mapping mode**: no authority proposal was submitted,
  and a deployment-configured mapping, keyed on the Intent's
  `purpose` or `target_resources`, or on the requested `scope` values
  for a `scope`-only target ({{scope-projection}}), yields the
  candidate entries, which are then narrowed to policy.

  The mapping is a lookup, not synthesis, and no key grants authority
  by itself. Because no `authorization_details` object was submitted,
  the AS refuses an Intent that matches no configured mapping, or whose
  mapped candidates policy narrows to nothing, with `access_denied`
  ({{error-mapping}}). Its `error_description` can say whether no
  mapping matched or policy narrowed the candidates to nothing.

  Either mode is conforming. A deployment publishes its mapping space as
  deployment documentation. Eligibility can be scoped per Subject and
  client, and a mapping keyed on Subject attributes resolves at the
  approval event, where the Subject is established
  ({{direct-approval-steps}}), so a refusal at PAR time is best-effort
  over what is checkable without the Subject.

  Every Mission this mode yields takes its own fresh approval; standing
  consent to a pre-approved ceiling is the separate, experimental
  Mission Template profile
  ({{I-D.draft-mcguinness-oauth-mission-template}}), not this mode.

In either mode, narrowing a candidate entry needs a declared
`narrowing` capability for its type; without one, the entry is
retained unchanged or omitted ({{transformation-capabilities}}).

Authority Set derivation can run provisionally during submission
processing, where the inputs it needs are available
({{submission-processing}}). The
candidate Authority Set is complete before the approval rendering
({{direct-approval-steps}}), and a change that
{{approval-context-changes}} covers is recomputed and approved over the
changed context. The approved Authority Set is fixed when the Mission
Record is created, atomically with the approval decision
({{direct-approval-steps}}), under the derivation policy in force at
the approval event.

In both modes the AS bounds every Authority Set entry by the Mission
Intent: each entry that carries a `resource` member MUST have it among
the Intent's `target_resources` values, by exact string equality. This
membership check applies to the Authority Set, and to a proposal at
submission ({{authority-proposal}}).

A later token issuance is bounded by the subset rule against the
Authority Set ({{subset}}), not by the target list again. A type whose
subset relation admits a narrower `resource` (for
`mission_resource_access`, a descendant of a `prefix` entry) can yield a
token entry that `target_resources` does not name, and a candidate
outside every Authority Set entry fails that rule.

The Mission records the policy version in force as `policy_version`
({{mission-record}}).

Generative Authority Set derivation is not one of this document's
modes. As a local-policy extension, a model's output can be a
recorded input to
the AS's deterministic derivation policy, together with the model's
identifier and version. That input can cause refusal or further
narrow the candidate authority the selected mode and policy otherwise
permit. The AS MUST NOT let it supply or widen authority. Each type's
subset rule ({{subset}}), the Intent bounds, and the prose boundary
below still apply.

A `target_resources` entry the deployment does not recognize is, by
deployment policy, either omitted from the Authority Set or refused with
the `access_denied` error code ({{error-mapping}}).

When an omission or a narrowing leaves the Authority Set short of what
was proposed ({{authority-proposal}}), Authority Set derivation is
partial. The token response states what was granted
({{token-response}}).

## Consented Authority Set {#consented-authority-set}

The derived Authority Set, not the Mission Intent, is the authority the
Approver consents to: the AS renders the Authority Set for approval and
commits it as `authority_hash` ({{direct-approval-steps}}). The Intent's
members describe and bound the task but grant no authority by themselves
({{mission-intent}}): its structured members constrain what the AS can
derive mechanically, its prose members bound through disclosure, and
none widens.

The `goal` and `task_bounds` members are human-readable disclosure and
audit context. The AS MUST derive the same Authority Set, under the same
policy, for two submissions that differ only in `goal`, `goal_lang`, or
`task_bounds`, and MUST NOT gate issuance on those members, whether in
Authority Set derivation, in an adjudicating policy, or through a
model input to either; translating a user's words into structure is
the shaper's job, before admission and outside the trust boundary
({{I-D.draft-mcguinness-mission-shaping}}).

A client-proposed constraint on an individual Authority Set entry enters
through the `authorization_details` proposal: constraints a supported
type's specification defines (for example, the Common Constraints that
{{I-D.draft-mcguinness-oauth-mission-resource-access}} defines for
`mission_resource_access`), and the collision-resistant deployment
extensions the AS understands ({{extensibility}}).

Authority is further bounded by:

- the Intent's structured members (`target_resources`, `expires_at`);
- the configured mapping, a lookup over structured values, not an
  interpretation of prose; and
- local policy and eligibility.

The approval surface renders the prose beside the derived Authority Set
({{direct-approval-steps}}) as the human check that the structure
matches the words, not as a machine enforcement mechanism.

## Derivation Policy and Open-Ended Tasks {#derivation-policy-tasks}

Authority Set derivation is governed by local policy and is not a
portable algorithm:
different authorization servers can derive different Authority Sets from
the same Mission Intent, as they can grant different authority for the
same {{RFC9396}} request or the same scope. Interoperability begins at
the derived Authority Set, whose structure and vocabulary each supported
type defines ({{other-types}}), and at its integrity anchors
({{integrity-anchors}}).

A consumer enforces the derived Authority Set, not the Intent. Audit
establishes what was derived, against `intent_hash` and
`policy_version`, not whether the Authority Set derivation was the
right reading of the task. A deployment whose partners reason about
its Authority Set derivations can
publish a derivation policy identifier and test fixtures that pin
Intent-to-Authority-Set outcomes.

For an open-ended task whose concrete objects cannot be enumerated at
approval (for example, "reconcile this customer's ledger," where the
individual invoices are not yet known), the derived authority is better
bounded by `constraints` that hold as invariants over those objects
than by an exhaustive `resource` enumeration. Such invariants include
the owning customer, the tenant, an amount ceiling, read-only except
named write actions, and a validity window. The runtime layer
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
never contemplated; semantic narrowing is not a property this rule can
provide.

Where the comparison relation cannot decide (an unrecognized member, an
incomparable value), the posture is conservative refusal, as each
consuming rule of this document states. At the token endpoint, where
the comparison cannot establish that a requested `authorization_details`
entry is a subset, the AS MUST refuse the request with the
`invalid_authorization_details` error code, as for an entry that
exceeds the grant ({{error-mapping}}).

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
- narrowing and delegation use the subset and delegation semantics the
  type defines ({{subset}}, {{delegation-constraints}}), under the
  transformation capabilities the AS declares for the type (below); and
- evaluating the entry against a concrete request is the
  responsibility of the resource server, under the entry's type
  ({{rs-requirements}}), or of a composing runtime layer
  ({{runtime-boundary}}), not the AS's.

### Declared Transformation Capabilities {#transformation-capabilities}

The subset rule is fully defined only for a type whose specification
defines it. For every supported type, the AS declares three
independent transformation capabilities; understanding one
establishes none of the others:

- **narrowing:** the AS understands the type's subset relation;
- **delegation:** the AS understands the type's delegation
  semantics; and
- **projection:** the AS establishes a safe scope projection for the
  type ({{scope-projection}}).

The AS MUST NOT narrow, delegate, or project to `scope` an entry of a
type for which it has not declared the corresponding capability; on an
undeclared capability the entry is carried as approved.

The `narrowing` capability also governs Authority Set derivation, and
approval does not waive the subset proof. Without `narrowing` for its
type, the AS retains a valid candidate entry, whether proposed
({{authority-proposal}}) or yielded by a configured mapping
({{derivation-modes}}), unchanged, or omits it where this document
permits omission; it never modifies the entry under a claimed subset
relation. A malformed entry is refused as {{authority-proposal}}
states.

The AS relates each entry to the audiences that consume it through a
trusted entry-to-audience mapping, such as authenticated configuration
or protected resource metadata ({{RFC9728}}). An entry's original
approved audience is the audience or audiences that mapping assigned
the entry when the Mission was approved. An entry's `resource` value is
not by itself an audience ({{token-response}}). The AS MUST retain that
association with the Mission; a later change to the mapping does not
redefine it.

A Mission created from earlier authority, such as a Child Mission
({{I-D.draft-mcguinness-oauth-mission-child-delegation}}), a successor
({{I-D.draft-mcguinness-oauth-mission-expansion}}), or an instance of a
standing consent ({{standing-consent-bases}}), does not reassign the
original approved audience of an entry it inherits: the entry keeps that
of the authority it derives from. Only a fresh approval of the entry, or
a transformation under a declared capability, establishes a different
one. Where the AS cannot establish an entry's original approved
audience, the entry has none; the current mapping does not stand in for
it.

Issuing an entry to an audience other than its original approved
audience, including audience projection to a Resource AS
({{I-D.draft-mcguinness-oauth-mission-cross-domain}}), counts as
narrowing and needs `narrowing`, not `projection`. Without `narrowing`,
the AS MUST NOT issue an entry to any audience other than its original
approved audience, or, except as `scope` under a declared `projection`,
in any form other than exactly as approved, since it cannot prove that a
transformed copy is still a subset of what was approved. Without
`narrowing`, a token for another audience does not carry the entry
({{token-response}}).

A type that declares `delegation` without `narrowing` is delegable only
unchanged: the AS MUST NOT include an entry of such a type in a
delegated token unless it is equal ({{subset}}) to an entry of the
presented delegating token, it keeps that entry's approved audience, and
the type's delegation policy permits the delegate
({{delegation-constraints}}). The reference is the presented token, not
the Mission Authority Set, so equality never restores an entry, or any
part of one, that the presented token omits.

A designation's `aud` names its redeemer ({{designation}}) and
reassigns no entry's original approved audience: for a designation,
the audience rules test the resource audiences associated with the
entries it carries, never the designated client ({{token-response}}).
Its redemption issues an entry only as the rules above permit,
including their `narrowing` condition.

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
machine-readable carrier is optional, and the first declaring carrier
governs. A `mission_transformation_capabilities` value is a JSON
object with three OPTIONAL boolean members, `narrowing`, `delegation`,
and `projection`; an absent member leaves that capability undeclared
by this carrier, falling through to the next carrier in the order
above. For each capability, the first carrier in that order that
declares the member governs, whether it declares `true` or `false`; a
later carrier does not override it. A declared capability permits a
transformation without requiring it, and waives no check this document
requires and no local policy under which the AS refuses one.

### Policy-Language Types {#policy-language-types}

Type-agnosticism lets policy-language profiles compose without this
document defining them: for example, an entry carrying a Cedar policy
set ({{I-D.draft-cecchetti-oauth-rar-cedar}}), or an analogous AuthZEN
policy entry, for an audience that evaluates it, alongside a
general-purpose type such as `mission_resource_access`
({{I-D.draft-mcguinness-oauth-mission-resource-access}}).

The AS derives such an entry from the Mission Intent and bounds it by
the Intent like any other, but does not interpret the carried policy
beyond its type's declared capabilities; the resource server or policy
decision point (PDP) evaluates it at request time.

Because the Cedar profile defines no subset or delegation rule over
policy sets, the AS carries a Cedar entry as approved, so it does not
appear in a delegated token or cross-domain grant. Delegation controls
on other entries in the same Authority Set, such as a
`mission_resource_access` entry, apply to those entries only.

Invoking a Model Context Protocol tool or a function call is modeled
as a `mission_resource_access` entry with no separate type; the
mapping is specified in
{{I-D.draft-mcguinness-oauth-mission-resource-access}}.

# Mission Approval {#approval-event}

An approval event is the atomic transition that creates a Mission.
Every Mission is created at its own approval event, which the record's
`approval_event_id` identifies.

The approval basis (`approval_basis`, {{mission-record}}) and its
adjudication, not the event alone, determine whether a human decides
at that event or an earlier standing consent authorizes the instance:

- A `direct` approval event includes the Approver's contemporaneous
  consent: it is a human approval event.
- Under a standing-consent basis ({{standing-consent-bases}}), the
  instance is decided under an accountable human's earlier approval,
  with no fresh human approval.

## Authorization Code Protection {#approval-code-protection}

The direct realization runs as an OAuth 2.0 {{RFC6749}}
authorization-code flow initiated from the PAR-issued `request_uri`
({{submission-via-par}}). Because the authorization code is the
artifact the Mission grant binds to ({{grant-binding-resolution}})
and it passes through the front channel, the AS MUST bind the code
to the requesting client with PKCE ({{RFC7636}}, `S256` challenge
method) or, equivalently, issue a DPoP-bound authorization code
({{RFC9449}}). Redemption is then verified as
{{Section 4.6 of RFC7636}} or {{Section 10 of RFC9449}} specifies.
This prevents authorization-code injection from yielding the Mission
grant. Issuance at the code's redemption applies the checks of
{{issuance-checks}} as that list states for code redemption.

The AS SHOULD include the `iss` authorization-response parameter
({{RFC9207}}) on the authorization response, so the client can detect
a mix-up attack on the consent-bearing redirect leg ({{RFC9700}}).

## Direct Approval Steps {#direct-approval-steps}

Steps 1 to 3 establish the Approver,
the Subject and the authority source, and check the derived Authority
Set against that source. Step 4 establishes the effective expiry.
Step 5 renders the derived Authority Set for consent, and
{{approval-context-changes}} covers a change before the decision.
Steps 6 and 7 compute the integrity anchors over the approved context
and create the Mission atomically with the decision.

At a direct approval event the AS MUST perform steps 1 to 7, in
order, as one procedure: steps 1 to 5 prepare the approval
({{approval-preparation}}), and steps 6 and 7, which continue the same
procedure, commit the Mission ({{approval-commit}}).

The steps of this section define the `direct` approval basis
(`approval_basis`, {{mission-record}}); a companion profile that
relocates a direct approval keeps them unchanged ({{extensibility}}).

Refusals follow {{error-mapping}}.

### Preparing the Approval {#approval-preparation}

1. **Authenticate the Approver**, subject to the approval-authentication
   floor and any client-requested strength
   ({{approval-authentication}}). The AS MUST NOT take the Approver's
   identity or achieved authentication context from unauthenticated
   client input; the authenticated surface that resolved the approval
   establishes both.
2. **Establish the Subject**: the principal the task is for, recorded as
   the Mission's `subject` and mapped to the `sub` of every derived
   token ({{token-claims}}). The Subject can be a workload or
   organizational principal ({{authority-sources}}), established and
   mapped the same way.
   - **Self-approval.** When the Approver is the Subject, the Subject
     is the authenticated Approver.
   - **Another principal or an external Subject.** The rules of
     {{subject-establishment}} apply at this step.
3. **Establish the authority source**: whose authority the approval
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
4. **Establish the effective Mission expiry**: the requested
   `intent.expires_at` ceiling narrowed by applicable AS policy and
   any ceiling an applicable Mission-creating profile defines. The
   value is bounded as `expires_at` requires ({{mission-record}}) and
   is rechecked at the creation commit (step 7).
5. **Render for consent** the derived Authority Set in human-meaningful
   terms, with the `goal`, `task_bounds`, and the effective
   `expires_at` (and, when it differs, the requested
   `intent.expires_at`, so the Approver sees the narrowing) as
   context:
   - The consent object is the **derived Authority Set**, what the
     agent may do, not the `goal` or Mission Intent: Authority Set
     derivation is local policy, and nothing commits that the derived
     authority reflects the goal the Approver read. An approval
     surface that renders only the `goal` or Mission Intent does not
     conform.
   - The rendering MUST identify the OAuth client that receives the
     authority, the Agent, from client identity information the AS
     trusts, such as its own registration of the client; display text
     the client supplies does not by itself identify it.
   - When the Approver is not the Subject, the rendering MUST
     identify the Subject the authority is granted for.
   - The rendering MUST identify the authority source and, for
     `organizational`, the governed policy it draws on
     (`authority_source.policy`).
   - When the client submitted an authority proposal
     ({{authority-proposal}}), the rendering MUST distinguish the
     entries the client proposed from any narrowing or restructuring
     the AS applied.
   - Mission Capability Binding
     ({{I-D.draft-mcguinness-mission-capability-binding}}) states
     what the rendering presents about the source binding of a
     catalog-sourced action.

### Committing the Mission {#approval-commit}

The same procedure continues from step 5:

6. **Compute the integrity anchors** ({{integrity-anchors}}):
   `authority_hash` over the consented Authority Set, `intent_hash`
   over the approved Mission Intent, and, when an authority proposal
   was submitted ({{authority-proposal}}), `proposal_hash` over the
   submitted `authorization_details` array.
7. **Create the Mission Record** ({{mission-record}}) in the `active`
   state atomically with the approval decision and issuance of the
   authorization code, or, under a back-channel carriage profile
   ({{extensibility}}), with establishment of the Mission grant binding
   and activation of the profile-defined grant for redemption. The
   commit MUST verify atomically that the effective expiry is
   strictly later than the creation instant: acceptance of the
   submission does not freeze time, and where the requested ceiling
   passed while the approval was pending, completion creates no
   Mission. Where a direct approval fails this check, the AS MUST
   refuse the request with `access_denied` ({{error-mapping}}),
   issuing no authorization code or profile-defined grant. A deferred
   or relocated approval flow ({{extensibility}}) inherits this check
   at its own creation commit, with the completion error each flow
   defines.
{: start="6"}

The `authority_hash` is the **authority commitment**: it commits, by
cryptographic digest, exactly the authority the Approver approved.

The Mission Record is what approval leaves behind: the approved
content and its commitments (the approved Mission Intent, the
Authority Set, and the integrity anchors over them); the principals
(the Subject, the approved agent's `client_id`, and the
`approval_basis` naming who consented and how); the authority source;
the issuer's provenance (the policy version and the approval event's
identifier); and the Mission's expiry and lifecycle state.
{{mission-record}} defines each member and when it is present.

## Subject Establishment {#subject-establishment}

These rules apply at step 2 of the direct approval steps
({{direct-approval-steps}}).

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

## Rendering Safeguards {#rendering-safeguards}

The consent rendering is hardened against client text:

- Client-supplied strings (`goal`, `task_bounds`) MUST be rendered as
  inert text and MUST NOT be interpreted as markup.
- The AS SHOULD mitigate Unicode direction-override and
  confusable-character presentation in them.
- The rendering MUST visually distinguish the AS-derived Authority
  Set from client-supplied text and attribute that text to the client,
  identified from client identity information the AS trusts
  ({{approval-preparation}}), so crafted client text cannot pass as
  derived authority or as a statement of the AS.

The rendering presents `goal` and `task_bounds` as recorded, without
truncation: the Intent is recorded verbatim and committed by
`intent_hash` ({{integrity-anchors}}), so a truncated rendering would
show the Approver less than the record holds.

Rendering a bound is not the same as enforcing it: a deployment MUST
NOT present a rendered bound as enforced when no party enforces it.
Which party enforces each bound, and what holds when that party is
absent, follows from Enforcement Requirements ({{rs-requirements}})
and, for a resource server that enforces only `scope`, from Scope
Projection ({{scope-projection}}).
An AS SHOULD make clear to the Approver which rendered bounds its
deployment actually enforces, so consent is not given to a limit that
binds nowhere.

## Changes Before the Decision {#approval-context-changes}

If any of the following changes between approval rendering and the
approval decision, the AS MUST recompute the affected values and the
anchors the Mission records, and MUST NOT create the Mission without
the Approver's consent to the changed context:

- the task or the authority proposal;
- the derived Authority Set;
- the established authority source ({{authority-sources}});
- the effective `expires_at`; or
- a policy input establishing any of them.

Each anchor (`intent_hash`, `authority_hash`, and `proposal_hash` where
a proposal was submitted) is computed over the approved context. Because
the proposal is committed separately, a proposal swapped between
rendering and decision changes `proposal_hash` even where `intent_hash`
is unchanged.

## Approval Comprehension {#approval-comprehension}

The approval event commits the Mission Intent and Authority Set the
AS records as approved. Those commitments establish neither that the
AS rendered them faithfully nor that the Approver understood them
({{consent-binding}}). Step 5 of {{direct-approval-steps}} requires
human-meaningful rendering; comprehension cannot be inferred from an
approval or its integrity anchors.

A short task can legitimately have a large or varied Authority Set:
an erasure request whose proposal or configured lookup
({{authorization-derivation}}) yields dozens of delete entries across
resources. The consent object remains the complete derived Authority
Set. The following non-normative practices can help make it
reviewable:

- **Group** entries by resource and action, keeping visible an entry
  whose constraints, such as its resource range or consumption bound,
  differ materially from the rest of its group.
- **Summarize with drill-down**: cover every resource, action, and
  bound, with each complete entry one interaction away; a summary is a
  view of the set, never a substitute for it.
- **Surface high-risk entries**: make the high-risk authority of
  {{approval-authentication}} prominent in the initial view,
  distinguishing materially different risks and bounds.
- **Split rather than approve** when the set is too large or varied
  for one decision ({{applicability}}).

Mission Consent Evidence
({{I-D.draft-mcguinness-oauth-mission-consent-evidence}}) defines
layered rendering of a committed disclosure, including what its first
layer carries, and lets the Approver ask the basis for an entry before
deciding.

## Authority Sources {#authority-sources}

A Mission draws its authority from one of three sources:

- **user-delegated**: a delegating person's own authority;
- **service-owned**: a workload's own provisioned authority; or
- **organizational**: explicitly governed organizational policy with
  a named accountable owner.

The source names whose authority the approval draws on, recorded
immutably as the Mission's `authority_source`; `approval_basis`
records how drawing on it was activated ({{mission-record}}). The two
compose: any source may activate under the `direct` basis or a
standing-consent basis a companion defines.

Approval activates only authority the source already holds: the AS
establishes the source and verifies the derived Authority Set against
it before approval ({{direct-approval-steps}},
{{standing-consent-instances}}).

The subject-representation discipline is the same in every source:

- The accountable principal is the record's
  `approval_basis.consent_principal` in every source; it is never
  inferred from the token `sub`.
- `sub` carries a delegating person only in the user-delegated
  source. A service-owned or organizational Mission MUST record the
  workload or organizational principal as `subject` and MUST NOT
  record a human principal in its place. The injective mapping of
  {{subject-establishment}} applies unchanged: that principal
  receives its own AS-local `sub`, denotes itself, and impersonates
  nobody. It
  MUST be an authorization subject the AS recognizes as a resource
  owner in its own right (the `sub` model of {{RFC9068}}), not only
  the task's beneficiary.
- The actor model does not vary by source: `client_id` names the
  Agent, and delegates are carried in the `act` chain
  ({{delegation}}).

## Approver Authentication Strength {#approval-authentication}

A deployment MUST publish a statement declaring the minimum
approval-authentication strength (the approval-authentication floor)
it enforces for Missions whose derived Authority Set carries high-risk
authority, and the deployment scope it applies to. High-risk
authority means irreversible, external-commitment, or
privileged-administration actions under the deployment's
classification, or a consumption bound
({{I-D.draft-mcguinness-mission-metering}}). This document requires
no particular serialization.

For the direct flow, a client MAY additionally request an
approval-authentication strength on the authorization request using
the `acr_values` and `max_age` parameters defined in Section 3.1.2.1
of {{OpenID.Core}}. In a Mission approval interaction these
parameters describe the requested authentication of the
**Approver**, not of the token's Subject, who can be a different
principal ({{subject-establishment}}).

Requesting these parameters implies nothing about the authentication
claims of an issued token, which describe the token's Subject, not the
Approver ({{token-authentication-lifetime}}); when the Approver is the
Subject, one authentication event can back both.

The Approver's authentication satisfies `acr_values` when it matches
any one listed value under the deployment's own policy mapping (this
document defines no global ordering of `acr` values); `max_age`
bounds the elapsed time since that authentication.

Approval authentication for a high-risk Mission MUST satisfy both the
published floor and, where the client requested one, the
`acr_values`/`max_age` carriage above; the floor is never relaxed by
a narrower or absent client request.

This document does not require an AS to support OpenID Connect
{{OpenID.Core}}. An authorization request whose `scope` includes
`openid` asks for an ID Token about the End-User the approval
interaction authenticates, who is the Approver. When the Approver is
not the Subject established at step 2 of {{direct-approval-steps}}, the AS
MUST refuse such a request, without creating the Mission, with the
`invalid_scope` error code ({{Section 4.1.2.1 of RFC6749}}). When the
Approver is not the Subject, whether or not `openid` was requested,
the AS MUST NOT issue an ID Token, serve UserInfo, or establish an
authentication session for the Subject solely as a result of the
Approver's authentication or approval.

When the Approver is the Subject, the `openid` scope value and the
`acr_values` and `max_age` parameters keep their {{OpenID.Core}}
meaning, which then describes the same authentication this document
requires. In every approval interaction, the `prompt`, `login_hint`,
and `id_token_hint` parameters concern the Approver.

The authentication actually achieved for the approval event (`acr`,
`amr`, and `auth_time`, in the sense {{RFC9470}} and {{OpenID.Core}}
define them) is approval-time provenance, not requested Intent: this
document never records it as, and an AS MUST NOT read it back from, a
Mission Intent member.

Where a deployment records Consent Evidence, the achieved values
belong in its `authentication_context` member
({{I-D.draft-mcguinness-oauth-mission-consent-evidence}}); this
document defines no Mission Record member for them.

## Single Accountable Approver {#multi-party-approval}

This document records exactly one accountable principal,
`approval_basis.consent_principal`: the principal who approved the
Mission. Two richer patterns are out of scope:

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
({{I-D.draft-mcguinness-oauth-mission-consent-evidence}}).

The `adjudication.governance_record` member ({{mission-record}})
marks an approval such a record backs, and {{role-mapping}} shows how
each scenario assigns the three `approval_basis` roles.

The issuer retains the Approval Governance Record, and this document
defines no surface that discloses it. An artifact that refers to it
does so by its record digest
({{I-D.draft-mcguinness-mission-approval-governance}}, Section
"Conventions and Definitions"). The record binds a governance
evaluation to the Mission's approval event. It does not, by itself,
establish a separate business decision for each subsequent action.

Authenticating approval evidence does not, by itself, establish that
conditions governing later reliance remain satisfied. Whether
subsequent changes to an Approver's role, a delegation, or governing
policy affect an existing Mission depends on the deployment's policy.

# Mission Lifecycle {#lifecycle}

A Mission is in one of two states:

- `active`: the only state in which the AS derives tokens.
- `terminated`: a terminal state; the Mission has ended. Its
  `termination` member ({{termination}}) gives the reason: `revoked`
  when it was revoked ({{revocation}}), or `expired` when its
  `expires_at` passed.

The transitions are:

| From | Event | To | Reason |
|---|---|---|---|
| (none) | approval event | `active` | |
| `active` | revoke | `terminated` | `revoked` |
| `active` | `expires_at` reached | `terminated` | `expired` |
{: title="Mission lifecycle transitions"}

The Mission Lifecycle States registry ({{iana-lifecycle-states}})
holds these states, and the Mission Termination Reasons registry
({{iana-termination-reasons}}) holds the reasons. A companion profile
MAY register an additional state for a lifecycle it introduces (for
example, a paused state); only `active` permits issuance. A companion
profile that defines a further way for a Mission to end registers a
termination reason, not a state.

Wherever a Mission state is reported, including the Mission Record
and the introspection `mission` member, a consumer MUST treat only
the exact value `active` as permitting derivation or continued
reliance, and MUST treat every other value, including one it does
not recognize, as non-active and non-deriving (the
forward-compatibility rule).

For every state-dependent decision this document defines, the AS MUST
treat a Mission as `active` only when its stored state is `active`
and the decision time is strictly before `expires_at`. From
`expires_at`, a Mission whose stored state is still `active` is
`terminated` with reason `expired` for every such decision, whether
or not that transition is persisted, including when persisting it
fails.

Persisting that transition, and emitting any lifecycle event a
state-distribution companion defines, can happen after the decision
that observed the boundary; persisting it never replaces a
termination already recorded.

## Mission Termination {#termination}

A Mission whose `state` is `terminated` carries a `termination`
object, in the Mission Record and wherever its state is reported with
it; a Mission in any other state carries none. Its members are:

`reason`:
: REQUIRED. A string, a value of the Mission Termination Reasons
  registry ({{iana-termination-reasons}}): `revoked` or `expired` in
  this document, or a reason a companion profile registers.

`terminated_at`:
: REQUIRED, except as described below. A
  string. An RFC 3339 {{RFC3339}} date-time: the instant the
  termination took effect. For `expired`, it is the Mission's
  `expires_at`.

A companion profile that registers a reason defines that reason's
further members. A profile that maintains a state version for the
Mission adds the version of the transition that committed the
termination as its audit reference.

The issuer writes `termination` once, atomically with the transition
to `terminated`, and never changes it: an expiry, or any later event,
does not replace the reason or references of a Mission already
terminated.

A termination carries every member its reason requires, except as
follows.

A termination need not carry a member its reason requires when it
was recorded before its reason defined that member, or derived
from such a termination: such a termination exposes only the facts
its record retained and omits a member it has no retained value for,
`terminated_at` included, rather than inventing one. For `expired`,
the retained `terminated_at` is the Mission's `expires_at`; for
another reason, a retained commit time is its `terminated_at` only
where that commit was the termination's effect.

A consumer that receives such a termination, or a `reason` it does
not recognize, still treats the Mission as terminated: it stops work
governed by the Mission, follows no absent reference, and infers no
cause-specific action.

For a transition period, a consumer of a report that still carries
`revoked`, `expired`, `completed`, `superseded`, or `cascaded` as a
Mission's `state` MAY read it as `terminated` with that reason
(`cascaded` as `parent_terminated`) and the facts the report
retained; an emitter never reports those values as a state. That
reading is local: the consumer never re-emits or re-signs it, and it
verifies a signed artifact over its original bytes, which it retains,
before reading it this way.

## Revocation {#revocation}

A Mission is revoked when the AS receives a revocation for it from a
party the deployment's policy authorizes to revoke it, or when that
policy itself terminates the Mission; either way, its termination
reason is `revoked`. The Subject, the Approver, and an administrator
are parties that policy can authorize; none is authorized by its role
alone. A deployment MUST provide an authenticated means, independent
of possession of any token, by which a party its policy authorizes
revokes a Mission by `mission_id` (so a Mission can be stopped even
when no refresh token is held).

When the AS establishes that the principal identified by a Mission's
recorded `subject` ({{record-principal-members}}) has been
deprovisioned, it SHOULD terminate that Mission with termination
reason `revoked`. The rule reaches every Mission not yet terminated,
including one a companion profile has suspended, and identifies the
Subject by its recorded `iss` and `sub`. Temporary disablement, a
source outage, or an unavailable lookup does not by itself establish
deprovisioning. The departure or disablement of an Approver, an
accountable owner, or a client triggers the rule only when that
principal is the recorded Subject; an organizational Mission records
the organizational principal as its Subject ({{authority-sources}}),
so an approving officer's departure does not terminate it under this
rule. A deployment that does not follow this rule documents why; that
exception cannot bypass a continuing dependency the deployment
requires or rewrite the recorded Subject. Termination stops further
issuance ({{issuance-gating}}) but does not itself recall tokens
already issued; an earlier execution cutoff depends on the
deployment's enforcement mechanism.

The wire shape of that operation is out of scope for this document. A
deployment-defined authenticated surface satisfies this requirement;
Mission Status ({{I-D.draft-mcguinness-oauth-mission-status}})
defines an interoperable `revoke` operation.

As {{Section 2.1 of RFC7009}} permits, a deployment's revocation
policy can treat revoking a Mission's refresh token as revoking the
Mission; a deployment that couples token revocation to Mission
revocation documents that behavior.

Token validity and Mission validity are distinct: an already-issued
access token remains valid until it expires ({{issuance-gating}}), so
a token can outlive a transition of its Mission by at most the token
lifetime.

Token introspection ({{introspection}}) is a state-observable overlay
that lets a resource server see Mission state per request and refuse
a revoked Mission's token before the token expires; Mission Status
specifies another, a status surface keyed by `mission_id` with signed
responses. A deployment whose consumers rely on Mission state beyond
a token's lifetime offers one of these, so they read current state
rather than infer it from token validity.

# Mission-Bound Access Tokens {#mission-bound-tokens}

An access token issued under a Mission takes one of two forms:

- a self-contained JWT per {{RFC9068}}, which a resource server can
  enforce from the token alone ({{rs-enforcement}}) and which this
  document's token-carried enforcement assumes; or
- an opaque Mission-bound token, profiled only under the introspected
  consumption mode ({{introspected-consumption}}), where introspection
  or issuer-local resolution carries its claims, with the same
  enforcement obligations.

A deployment whose AS can issue neither deploys a Mission Authority
Server ({{I-D.draft-mcguinness-mission-authority-server}}), which
governs ordinary tokens at the enforcement layer.

{{issuance-checks}} lists the checks an issuance applies on each path.
The next four subsections follow one issuance: resolving the Mission
from the presented grant ({{grant-binding}}), gating the issuance
({{issuance-gating}}), and the token ({{token-claims}}) and its
response ({{token-response}}).

## Issuance Checks {#issuance-checks}

This document defines five issuance paths: code redemption, the token
response that redeems a newly created Mission's authorization code
({{approval-code-protection}}); a refresh ({{refresh-tokens}}); a
designation ({{designation}}); a delegated exchange
({{delegated-exchange}}); and a self-exchange ({{self-exchange}}).
Each is a derivation ({{issuance-gating}}); companion profiles define
further derivations. Each item below names a check, the sections that
state it, and the paths it applies to, with any difference by path. A
path's own section states its further rules, and {{error-mapping}}
gives the error codes.

1. Mission resolution ({{grant-binding-resolution}}): every path, from
   the presented grant: the code, the refresh token, or the
   `subject_token`, which on a delegated exchange is the designation.
2. Client and sender binding: every path, as its own section states
   for the code ({{approval-code-protection}}), the refresh token
   ({{refresh-tokens}}), the token a designation request presents
   ({{designation}}), the delegate ({{delegated-exchange}}), and the
   self-exchanging agent ({{self-exchange}}).
3. Mission state ({{issuance-gating}}, {{lifecycle}}): every path; a
   delegated exchange evaluates each redemption afresh
   ({{delegated-exchange}}).
4. Mission-governed resources ({{authority-proposal}}): every path; a
   refresh, a self-exchange, or a designation request needs no
   `mission_intent`.
5. Subset ({{subset}}): every path, against the Mission Authority Set,
   and also against the presented refresh grant on a refresh
   ({{refresh-tokens}}), the presented token on a designation or a
   self-exchange, and the designation on a delegated exchange; on
   those two delegation exchanges, only as {{delegation-constraints}}
   permits.
6. Declared transformation capabilities
   ({{transformation-capabilities}}): every path that narrows an entry,
   issues it to another audience, delegates it, as a delegated
   exchange does, or projects it to `scope`.
7. Audience ({{token-response}}): every path, by each entry's original
   approved audience ({{transformation-capabilities}}); for a
   designation, the resource audiences of its entries, not the client
   its `aud` names, with designated-client separation
   ({{designation}}); for a delegated token, also an audience that
   processes the `act` chain ({{delegated-exchange}}).
8. Scope projection ({{scope-projection}}): every path that emits
   `scope`, whose request names a `scope` value, or whose target
   consumes only `scope`; on a refresh, with that section's protection
   of the refresh token.
9. Token claims ({{token-claims}}, {{mission-claim}},
   {{mission-claim-reservation}}): every path; the three exchanges keep
   the presented token's `mission` claim. A designation's `aud` names
   the designated client, it carries `may_act` and no `cnf` or `act`
   ({{designation}}), and it creates no key-publication duty by
   itself; a delegated token adds the `act` chain and the delegate's
   own key ({{delegated-exchange}}); a self-exchange adds no `act`
   chain.
10. Lifetime and authentication claims
    ({{token-authentication-lifetime}}): every path, kept short as
    {{issuance-gating}} recommends; a designation also has its own
    expiry ({{designation}}), which does not bound a delegated token
    issued from it.
11. Response members ({{token-response}},
    {{mission-response-parameters}}): every path echoes the granted
    `authorization_details`; {{mission-response-parameters}} requires
    `mission_id` and `mission_expires_at` on code redemption and
    delegated-exchange responses and recommends them on refresh,
    designation, and self-exchange responses.

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
Mission. The AS alone establishes a binding and resolves it from the
grant itself; a client never supplies or negotiates one, and no
client input determines its Mission.

A grant lineage is state the AS can resolve again on a later request,
either:

- the authorization code issued at approval and, where its
  redemption emits one, the refresh-token family that follows it; or
- another profile-defined reusable grant, such as a refresh-token
  family a continuation transport establishes later for the same
  Mission ({{I-D.draft-mcguinness-oauth-mission-continuation}}).

### Establishing and Resolving a Binding {#grant-binding-resolution}

At a direct approval event the AS binds the Mission to the
authorization code it issues, or, under a back-channel carriage
profile, to the grant artifact that profile defines
({{extensibility}}). The binding is server-side, and it resolves the
Mission for operations using that binding; a profile-defined grant can
instead resolve it through its authenticated `mission` reference.

An authorization request that carries no `mission_intent` proposes no
Mission. An AS that answers such a request through consent reuse,
such as with a grant an authentication session holds for the client,
MUST NOT select a grant bound to a Mission: the request would
otherwise acquire an earlier Mission's binding with no submission or
approval of its own. This rule governs grant selection for a new
authorization request. It neither prohibits ordinary consent nor
changes how a derivation resolves an existing binding.

The code itself carries no refresh-token family; only a successful
redemption produces one. A refresh-token family so produced inherits
the code's binding atomically with its issuance, extending the same
Mission grant binding rather than starting a second one.

At each subsequent derivation the AS resolves the Mission from the
grant the client presents:

- the authorization code at the token endpoint;
- the refresh token on refresh;
- the Mission-bound `subject_token` on Token Exchange (a delegate is
  identified by its client authentication, {{delegated-exchange}}); or
- a profile-defined grant, through the authenticated `mission`
  reference it carries, such as the Template profile's handoff grant
  ({{I-D.draft-mcguinness-oauth-mission-template}}).

It then applies the gating of {{issuance-gating}}.

A Mission MAY carry zero or more grant bindings. Beyond any
authorization-code lineage established at approval, a refresh-token
family a continuation transport establishes later (above) is a
further binding, or the Mission's first where it has none, rooted in
the Mission its own `subject_token` resolved to.

The AS MUST resolve a bound grant lineage to the same Mission on
every derivation performed against it: the mapping is fixed for the
lineage's lifetime and is never reassigned to a different Mission.
An AS that finds a lineage resolving to more than one Mission fails
closed on that lineage.

Where a profile-defined operation lets a client present a Mission
Identifier alongside a credential, the identifier is a
non-authoritative cross-check: the AS MUST verify it against the
Mission the credential resolves to and refuse a mismatch with the
`invalid_grant` error code. The `predecessor` parameter of
{{I-D.draft-mcguinness-oauth-mission-expansion}} is an example: it
selects the Mission a successor is created from and does not reassign
an existing binding.

Because the grant, not the identifier, determines the Mission, a
client does not supply `mission_id` to obtain a derivation, and an AS
MUST NOT derive Mission-bound authority from a client-supplied
`mission_id`.

### Grant Bindings and Related Mechanisms {#grant-binding-related}

The grant binding relates to other mechanisms as follows:

- **Token Exchange.** A Token Exchange derivation ({{RFC8693}}) that
  returns only an access token establishes no new grant lineage:
  ordinary in-Mission delegation ({{delegation}}) and self-exchange
  down-scoping ({{self-exchange}}) both work this way, and the issued
  token is a derived token ({{mission-claim}}) whose `mission` claim
  identifies the one Mission its `subject_token` resolved to. Where
  the `subject_token` was issued under a grant lineage, the issued
  token retains that grant provenance, and a later redemption of a
  designation derived from it validates all applicable backing-grant
  state ({{delegated-exchange}}). A Token
  Exchange that instead establishes a redeemable grant
  lineage, such as the continuation profile's
  delegation-family-creating exchange
  ({{I-D.draft-mcguinness-oauth-mission-continuation}}), creates a
  new grant binding, rooted in that same Mission. Three Token
  Exchanges are covered by the two items below instead: cross-domain
  projection and child creation, which return a JWT authorization
  grant, and expansion, which creates a successor. Redeeming the
  Template profile's handoff grant
  ({{I-D.draft-mcguinness-oauth-mission-template}}) issues a derived
  token and creates or extends no grant binding. In the continuation
  profile's Identity Continuation Transport
  ({{I-D.draft-mcguinness-oauth-mission-continuation}}), redeeming a
  root or onward Identity Assertion JWT Authorization Grant (ID-JAG)
  at a Resource AS produces a local derived access token. A Resource
  AS holds a destination-side grant binding only where it separately
  establishes a redeemable grant lineage mapped to the Mission, such
  as a refresh-token family.
- **Cross-domain projection.** A cross-domain projection
  ({{I-D.draft-mcguinness-oauth-mission-cross-domain}}) establishes
  no destination-side grant binding. A Resource AS consumes the
  cross-domain grant, and the local access token it mints there is a
  derived token: it identifies the one originating Mission
  (`mission.id`, `mission.issuer`) but is not backed by a persistent
  local lineage.
- **Child Missions and successors.** A Child Mission
  ({{I-D.draft-mcguinness-oauth-mission-child-delegation}}) and an
  expansion successor
  ({{I-D.draft-mcguinness-oauth-mission-expansion}}) are new
  Missions. Any grant binding or derived token they carry is their
  own under the same rules, not an extension of the origin Mission's
  binding. They relate to their origin only by lineage (the
  child's `parent` member, the successor's `predecessor` member).

A decision-time runtime join, such as the Mission Join of
{{I-D.draft-mcguinness-mission-authority-server}}, in which a policy
decision point joins an ordinary OAuth credential to a Mission per
request, is not a Mission grant binding: it does not make the joined
OAuth grant Mission-bound, and it rests on its own authenticated inputs
and evidence, never on a Mission grant binding.

### Mission State Across Bindings {#grant-binding-state}

Non-active state gates every future derivation across every Mission
grant binding ({{issuance-gating}}). It does not itself revoke an
OAuth grant the same client or subject holds outside any Mission
binding, and it does not recall an access token already issued before
its `exp` absent a runtime state check the token's consumer performs
({{revocation}}, {{introspection}}).

An issuer that needs to cascade a lifecycle operation, or to
enumerate a Mission's bound grant lineages and credentials, maintains
its own issuer-side index from the Mission to each binding; a Mission
Management companion
({{I-D.draft-mcguinness-oauth-mission-management}}) can standardize
that index's wire surface.

When the authorization code expires unredeemed, no derivation is
possible under the Mission regardless of which lifecycle outcome
follows. The deployment either revokes the Mission or lets it expire at
`expires_at`, and applies one choice consistently; both outcomes
terminate it ({{lifecycle}}), so reprocessing the same timeout
changes nothing.

### Mission Identifier and Expiry in Responses {#mission-response-parameters}

This document defines `mission_id` as a token-endpoint response
parameter: a string carrying the Mission Identifier, returned
alongside the issued token. It is an informational reference only:
presenting it authorizes nothing ({{grant-binding-resolution}}), and a
client MUST NOT derive authority from it.

Alongside it, this document defines `mission_expires_at`: the exact
RFC 3339 string recorded as the Mission Record's effective
`expires_at` ({{mission-record}}), the common member of every
Mission-creating success response, whatever surface completes the
creation. `expires_in` describes the access token's lifetime, not the
Mission's, and the effective expiry can be shorter than the requested
`intent.expires_at`.

A client learns both values from these members, not from the access
token, which it treats as opaque ({{Section 6 of RFC9068}}). The AS
returns them as follows:

- The success response that first delivers a newly created Mission's
  identifier or credential MUST carry both. On the authorization-code
  path, the authorization response carrying only the code is not that
  response; the token response redeeming the code is.
- A delegated exchange response ({{delegated-exchange}}) MUST carry
  both, because the delegate did not receive the response that
  created the Mission.
- Any other Mission-bound token response, including a refresh,
  designation ({{designation}}), or self-exchange ({{self-exchange}})
  response, SHOULD carry both.

A creation replay deduplicated under the applicable operation
identifier (`approval_event_id` for direct approval
({{mission-record}}), or the identifier a Mission-creating profile
defines) returns the committed effective value unchanged. On OAuth
token responses `mission_expires_at` is additionally registered as a
token-endpoint response parameter ({{oauth-parameters-registration}}).
It is informational in the same way: presenting it authorizes nothing.

## Issuance Gating {#issuance-gating}

A derivation is one issuance operation the issuer AS performs for a
single request: the initial authorization-code exchange, a refresh, a
Token Exchange, a cross-domain grant issuance
({{I-D.draft-mcguinness-oauth-mission-cross-domain}}), or the
redemption of a profile-defined grant, such as the Template profile's
handoff grant ({{I-D.draft-mcguinness-oauth-mission-template}}). A
companion profile bounds the number of derivations under a Mission
({{I-D.draft-mcguinness-oauth-mission-derivation-limits}}).

A derivation passes these checks, each stated where cited:

1. the Mission resolves from the presented grant
   ({{grant-binding-resolution}});
2. the Mission is `active` ({{lifecycle}}, and below);
3. each emitted entry is a subset of a Mission Authority Set entry
   ({{subset}});
4. any emitted `scope` meets {{scope-projection}}; and
5. each token's `exp` does not exceed the Mission's `expires_at`
   ({{token-authentication-lifetime}}).

Unless the referenced Mission is `active`, the AS MUST refuse a
request to derive a token at the token endpoint: a Token Exchange
({{RFC8693}}) with the `invalid_request` error code
({{Section 2.2.2 of RFC8693}}), and any other grant, refresh
included, with the `invalid_grant` error code. The AS MUST refuse a
derivation request it answers after it has acknowledged a revocation
of the Mission, with the same error code. The AS answers a request
when it makes its final decision to release the result, not when
network delivery of the response completes: a result prepared before
the acknowledgment and released after it is refused. A Token Exchange
takes `invalid_request` because a presented token whose Mission is
not `active` is unacceptable for the exchange, a case
{{Section 2.2.2 of RFC8693}} assigns to that code.

Where a profile of a Token Exchange that the AS implements assigns
its own error code to either refusal, such as a continuation
profile's code for an ended chain, the AS uses that profile's code
instead; the refusal itself, and the `mission_error` member below,
still apply.

The error code alone does not tell a client which gate refused. On a
refusal under this section the AS SHOULD include, alongside `error`,
the `mission_error` token-error-response member
({{oauth-parameters-registration}}) with one
of the values `revoked`, `expired`, or `superseded` (where a companion
defines supersession), the Mission's termination reason
({{termination}}).

These values are termination reasons. A companion profile that
defines another Mission state ({{lifecycle}}), which this section
also refuses, or a further refusal at issuance defines any
`mission_error` value for it, as Mission Status does for a suspended
Mission ({{I-D.draft-mcguinness-oauth-mission-status}}, Section
"Mission Lifecycle Endpoint") and Derivation Limits does for an
exhausted limit
({{I-D.draft-mcguinness-oauth-mission-derivation-limits}}, Section
"Enforcement at Issuance"). A Mission in a state from which it can
return to `active` is never reported with a termination reason.

The `mission_error` member is diagnostic only and optional, whichever
document defines its value: it grants nothing, an unrecognized value
is ignored and is not authoritative about the Mission's state, and it
is returned only to the authenticated client presenting the Mission's
grant.

The `mission_error` values this section names each report a
terminated Mission ({{termination}}): no retry under the same grant
cures the refusal. Further work needs a new approval or, for
`superseded`, the successor Mission
({{I-D.draft-mcguinness-oauth-mission-expansion}}). A new approval is
a fresh approval event, not an automatic consequence of the refusal; a
credential held outside the Mission is no fallback for its task
({{downgrade-by-omission}}); and the refusal gives no assurance that
the refresh token remains usable. This reading is keyed on the value,
not on the error code, because the same refusal covers a Mission in a
non-terminal state that a companion profile registers
({{iana-lifecycle-states}}), whose meaning that profile defines.

Derived tokens SHOULD be short-lived so that a transition to
`terminated` takes effect promptly without per-request
revocation checks. A resource server that does not check Mission state
per request can accept a derived token until its `exp`, so the token's
lifetime is the termination latency there ({{runtime-boundary}}).
Short-lived means within the termination latency the deployment
accepts. This document sets no numerical bound; a deployment profile
can. The cap at the Mission's `expires_at`
({{token-authentication-lifetime}}) does not by itself make a token
short-lived.

## Token Claims {#token-claims}

{{RFC9068}} fixes the JWT's required claims (including `jti`), the `typ`
header parameter value `at+jwt`, and resource server validation
({{Section 2.1 of RFC9068}}, {{Section 2.2 of RFC9068}},
{{Section 4 of RFC9068}}). In addition to what that profile requires, a
derived token:

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
  audience unrelated to that carried authority ({{token-audience}}),
  except that a token the AS issues only for presentation back to
  itself at a Token Exchange, such as a designation ({{designation}}),
  names in `aud` the client that presents it;
- MAY carry an `act` claim when the agent has delegated execution
  ({{delegated-exchange}});
- MAY carry a `scope` claim, subject to {{scope-projection}}; and
- can be sender-constrained, as {{Section 2.2.1 of RFC9700}}
  recommends, via a `cnf` claim {{RFC7800}}: DPoP {{RFC9449}}
  (`cnf.jkt`) or mTLS {{RFC8705}} (`cnf.x5t#S256`).

The primary access token may be a bearer token, preserving
compatibility with bearer-only resource servers while retaining
{{Section 2.2.1 of RFC9700}}'s recommendation; the cost is the
stolen-token exposure ({{token-theft}}).

A delegated token is sender-constrained to the delegate's own key
({{delegated-exchange}}); the cross-domain companion requires
sender-constraint for credentials that cross a trust domain
({{I-D.draft-mcguinness-oauth-mission-cross-domain}}).

An AS that issues Mission-bound JWT access tokens for resource servers
to consume MUST publish its token verification keys (for example, at
its {{RFC8414}} `jwks_uri`, as {{Section 4 of RFC9068}} recommends);
rotation retires a key from signing, never from resolvability while
tokens signed under it remain valid. A token the AS issues only for
presentation back to itself, such as a designation ({{designation}}),
creates no publication duty by itself.

## Audience and Token Response {#token-response}

The AS audience-restricts the token per {{Section 2 of RFC8707}} and
{{Section 3 of RFC9068}}; `aud` names resource server(s), APIs, or
security domains, not necessarily the entries' `resource` values. The
client obtains a single-audience token ({{Section 2.3 of RFC9700}})
with the {{RFC8707}} `resource` parameter, and can narrow it further
with `scope`; the AS narrows the Authority Set under {{subset}} to the
requested resource(s) and sets `aud` accordingly.
{: #token-audience}

A token-endpoint `resource` value outside the Authority Set is an
invalid `resource` value in the sense of {{RFC8707}}.

Three identifiers stay distinct. An entry's `resource`, where its type
defines one, names the protected resource its authority covers, and a
resource server matches each request's operation target against it
under the entry's type (for
`mission_resource_access`,
{{I-D.draft-mcguinness-oauth-mission-resource-access}}). A token
request's `resource` parameter ({{RFC8707}}) selects the audience the
client asks for. The token's `aud` names the recipients that accept
the token, and the AS relates an entry to them through the entry's
original approved audience ({{transformation-capabilities}}).

A token issued for an audience carries only the entries whose original
approved audience includes that audience; an entry approved for another
audience is not carried, unless a declared `narrowing` capability
permits issuing it there. A token whose `aud` names several audiences
is issued only where the same entries are approved for each of them;
where they differ, the AS refuses the request with `invalid_target`, and
the client requests a separate token for each audience. The AS also
refuses with `invalid_target` a request whose audience is approved for
none of the entries the token would carry, and one whose
`authorization_details` ({{Section 6 of RFC9396}}) names an entry not
approved for its audience.

For a designation ({{designation}}), these rules test the resource
audiences associated with the entries it carries, never the designated
client its `aud` names ({{token-claims}}). A designation carries only a
permitted subset of the presented token's entries ({{subset}},
{{delegation-constraints}}), each keeping its original approved
audience ({{transformation-capabilities}}). An entry without an
original approved audience is not carried, and a designation that
would carry no entry is refused with `invalid_target`. The delegated
token issued at its redemption is subject to every rule of this
section unchanged ({{delegated-exchange}}).

The AS returns the granted `authorization_details` in every token
response, including refresh and Token Exchange responses
({{Section 7 of RFC9396}}). Strengthening {{Section 7 of RFC9396}},
the AS MUST NOT omit values from it: the response states exactly the
(possibly narrowed) set assigned to the issued token, and it is the
authoritative statement of what was granted, which the client
compares with its proposal ({{authority-proposal}}). A client MUST NOT
assume authority absent from the granted set. An entry the echo
narrows grants the narrower authority it states, and a client need
not reject a grant narrower than its proposal. The `mission_id` and
`mission_expires_at` response parameters carry the Mission reference
and expiry beside it ({{mission-response-parameters}}).

The following is an example of a refresh request that narrows the
canonical ERP Mission (the worked example of {{mission-record}}) to a
read-only token with the {{RFC8707}} `resource` parameter and the
`authorization_details` parameter ({{Section 6 of RFC9396}}). The ERP
consumes `authorization_details`, so a resource `scope` for it would
be refused ({{scope-projection}}). Extra line breaks are for display
purposes only:

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
({{issuance-gating}}). The following example shows the token response.
It carries no `scope` member because none was requested or granted, and
it echoes the narrowed grant and the `mission_id` reference
({{mission-response-parameters}}). The emitted entry is a subset
({{subset}}) of the Mission's read entry, its `constraints` carried
intact:

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

## Refresh Tokens {#refresh-tokens}

Issuance on a refresh applies the checks of {{issuance-checks}} as
that list states for a refresh.

A Mission-bound refresh token is bound to the client it was issued
to. For a confidential client, client authentication supplies the
binding: on refresh, the AS authenticates the client and verifies
that the refresh token was issued to it ({{Section 6 of RFC6749}}),
so the token need not also be bound to the DPoP proof key
({{Section 5 of RFC9449}}). A public client's refresh token MUST
be sender-constrained or use refresh token rotation
({{Section 2.2.2 of RFC9700}}).

The AS can rotate either client type's refresh token; rotation
detects replay of a consumed refresh token
({{Section 4.14.2 of RFC9700}}) and is not a cryptographic binding.

A refresh request can carry `authorization_details` to narrow the
issued token ({{Section 6 of RFC9396}}). The AS MUST refuse such a
request with the `invalid_authorization_details` error code when a
requested entry exceeds the presented refresh grant or the Mission
Authority Set ({{subset}}), and MUST NOT instead issue a narrower set
than the one requested.

## Authentication Claims and Lifetime {#token-authentication-lifetime}

A derived token's authority comes from the Mission, not from a fresh
authentication. Authentication claims (`acr`, `amr`, `auth_time`) on
a derived access token follow {{Section 2.2.1 of RFC9068}}: they
describe the token's Subject and keep the values of the
authentication event behind the grant, so derivation does not
refresh them. An AS MUST NOT use the authentication of an Approver
who is not the token's Subject as authentication information about
that Subject.

These claims neither establish approval nor expand Mission authority;
the Approver's approval-time authentication remains provenance
({{approval-authentication}}). Where no authentication of the Subject
applies, as when a human approves a Mission for another principal or
for a workload, the claims are absent, and their absence is not an
authentication downgrade.

The `authorization_details` claim is the authoritative expression of
a Mission-bound token's authority; a `scope` claim
({{scope-projection}}) is a compatibility projection that cannot
carry per-entry `constraints`.

A credential the Mission Issuer derives MUST have an `exp` that does
not exceed the Mission's `expires_at`, so that no credential outlives
the approved Mission. The cross-domain companion
({{I-D.draft-mcguinness-oauth-mission-cross-domain}}) specifies how
this bound extends transitively to tokens minted in another trust
domain.

Within that bound, a derived token's lifetime is the AS's policy,
which {{issuance-gating}} recommends keeping short. Token Exchange
does not tightly couple an issued token's lifetime to its
`subject_token`'s ({{Section 2.1 of RFC8693}}): a designation's
expiry ({{designation}}) bounds when it can be redeemed, not the
lifetime of the delegated token issued from it, which can outlive
both the designation and the credential the designation was derived
from. Revoking the grant state backing that credential still refuses
every later redemption ({{delegated-exchange}}).

## Scope Projection {#scope-projection}

This section applies to every issuance that emits `scope` on a
Mission-bound token or whose request names a `scope` value, and to
issuance for a target that consumes only `scope`: such a target
receives a safe projection or a refusal (step 5 below).

For every target audience, the AS MUST establish that the effective
rights the target's enforcement path grants from the projected
`scope`, together with every independently mandatory control on that
path, are a subset of the rights the token's applicable
`authorization_details` grant.

This is a semantic condition, not a structural one. Exactly as it
fails for a relaxed constraint, it fails for a `constraints`-free
entry whose `scope`:

- aggregates a broader action;
- spans more resource instances or paths than the entry;
- carries rights the target's local `scope` interpretation implies;
  or
- arises from the union of several entries.

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
   ({{token-response}}) remains preferred.

Unknown `scope` semantics, unknown resource server enforcement
behavior, or an ambiguous or stale mapping all fail closed under step
5 ({{error-mapping}}). A changed mapping is not by itself stale: the
AS evaluates each issuance, refresh included, against the target's
current trusted mapping, and a mapping is stale only when the AS
cannot establish that it is the current trusted mapping for that
target. This rule applies to every issuance path that can emit
`scope` on a Mission-bound token: initial issuance, refresh, Token
Exchange, and any other derived-token path.

Scope projection does not change OAuth response semantics and does not
make access-token inspection a client requirement.

{{Section 3.3 of RFC6749}} requires the token response to carry `scope`
whenever the granted scope differs from the requested scope, and its
grammar defines no empty scope, so an issuance cannot report an
ungranted requested value by omission. The AS MUST refuse, with
`invalid_scope` ({{error-mapping}}), a request that explicitly names a
`scope` value the issuance cannot grant: a value the target's trusted
mapping names but no carried entry makes safe (step 3), or any `scope`
value the AS associates with a target that consumes
`authorization_details` (step 4).

An unknown, ambiguous, or stale mapping is a step 5 failure and yields
the `invalid_target` error code even when the request also names a
`scope` value; `invalid_scope` applies only under a mapping the AS
trusts.

Where the AS emits a projected `scope`, a requested `scope` narrows
it to the requested values, and the token response reports the
values granted ({{Section 5.1 of RFC6749}}). A Mission-creating
client does not request a resource `scope` for a target that consumes
`authorization_details`; for a `scope`-only target, a requested
`scope` selects among the values the projection can grant. Scope
values with their own semantics, such as `openid` ({{OpenID.Core}}),
are unaffected and combine with `authorization_details` as
{{Section 3.1 of RFC9396}} permits.

For a `scope`-only target, the trusted mapping also relates a
requested `scope` value back to authority, so a deployment's existing
`scope` values can request a Mission in configured-mapping mode
({{derivation-modes}}), combining `scope` with the Mission's
`authorization_details` as {{Section 3.1 of RFC9396}} leaves to the
AS. Each requested value stands for the entries that the type's
specification derives from the mapping (for `mission_resource_access`,
{{I-D.draft-mcguinness-oauth-mission-resource-access}}). The
Authority Set is those entries narrowed to policy, and the token for
that target carries their projection under the steps above. A
requested value the target's trusted mapping does not name cannot be
granted, and is refused with `invalid_scope` ({{error-mapping}}).

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

For example, a payments API at `https://pay.example.com` consumes only
`scope`. Its trusted mapping states that `payments.small` stands for
the `payments.create` action there, and that the API enforces a fixed
500.00 USD ceiling on every operation `payments.small` permits.
Consider this entry for the API:

~~~ json
{ "type": "mission_resource_access",
  "resource": "https://pay.example.com",
  "actions": ["payments.create"],
  "constraints": {
    "max_amount": { "amount": "500.00", "currency": "USD" } } }
~~~

The entry projects to `payments.small`, since the mapping shows that
the target independently enforces its constraint. The same entry with
a `max_amount` of 200.00 USD does not project, since `payments.small`
does not convey the narrower value. With no other carried entry
supplying a safe projection, issuance to the API is refused: under
step 5 with `invalid_target`, or, where the request names
`payments.small`, with `invalid_scope` under the rule for an
explicitly requested value above ({{error-mapping}}). The Mission
Resource Access Profile gives the same pair
({{I-D.draft-mcguinness-oauth-mission-resource-access}}).

The runtime profile's enforcement-scope declarations
({{I-D.draft-mcguinness-mission-runtime}}) can reference the same
mapping for the paths it covers; this rule does not depend on that
profile.

## Mission Claim {#mission-claim}

The `mission` claim is a JSON object:

`id`:
: REQUIRED. A string. The Mission Identifier ({{mission-id}}).

`issuer`:
: REQUIRED. A string. The Mission's `issuer` ({{mission-record}}). A
  credential's `iss` names the party that minted it; `mission.issuer`
  names the party that approved and serves the Mission, and the two
  differ for tokens minted in another trust domain
  ({{I-D.draft-mcguinness-oauth-mission-cross-domain}}).

The `id` and `issuer` members identify the Mission and carry no
authority of their own; the token's own signature authenticates the
pair, and the carried `authorization_details` remains the token's
concrete authority.

`expires_at`:
: OPTIONAL. A string. The Mission's `expires_at`
  ({{mission-record}}), in RFC 3339 {{RFC3339}} date-time form. It
  commits a lifetime bound, not current state: a validator can check
  that the token's `exp` does not exceed it, but that check does not
  establish that the Mission is still `active`, the only state that
  permits reliance ({{lifecycle}}).

A consumer that relies only on the presented token's own validity
needs nothing further: the token's `exp` already bounds it. A profile
that mints a further credential downstream of this one, or that
verifies a Mission's remaining lifetime from retained state rather
than a live token, MUST require `expires_at` and MUST treat its
absence as an error. The token's own `exp` bounds only that one
credential, not every credential the Mission may still yield.

The baseline `mission` claim carries neither `authority_hash` nor
`approval_basis`. Neither is an enforcement input a narrowed-token
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
  "iat": 1793606405,
  "exp": 1793606705,
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

### Claim Reservation {#mission-claim-reservation}

The `mission` claim of an access token, and the `mission` member that
introspection returns for an access token ({{introspection}}), are
reserved for issuance that conforms to a Mission-binding profile. An
AS MUST NOT issue an access token carrying the `mission` claim unless
the token's issuance or derivation conforms to one: this document's
issuance gating ({{issuance-gating}}) and subset rule ({{subset}}) for
a token the Mission's issuer derives, or a companion profile that
defines another issuance or derivation path, including a token that a
Resource AS or a consuming AS issues and a token a holder derives under
an attenuation profile.

A profile that defines such a path MUST identify:

1. the authenticated grant or parent chain that connects the token's
   authority to the Mission;
2. the authority bound the path enforces, and the comparison or
   projection by which it enforces it;
3. where Mission state is checked, by which party, and the freshness or
   lifetime bound within which that check is relied on; and
4. any check a consumer of the token performs.

A `mission` claim means that the token's issuance or derivation
conformed to its profile. It does not mean that the party that minted
the token queried the Mission's current state, and it attests issuance,
not the Mission's state afterward: a later suspension or revocation
does not change what the claim attests ({{lifecycle}},
{{introspection}}). The claim establishes no trust by its presence; a
resource server's issuer authorization and claim validation
({{rs-requirements}}) still apply.

This reservation concerns access tokens and their introspection
representation. An evidence or control artifact that embeds a
`mission` descriptor ({{extension-points}}) is not an access token, and
this section does not change its meaning.

# Resource Server Enforcement {#rs-enforcement}

A resource server enforces a JWT Mission-bound token from the token
alone; no call to the AS is required. It validates the token per
{{Section 4 of RFC9068}}, and any sender-constraint binding (`cnf`)
per {{Section 7.1 of RFC9449}} or {{Section 3 of RFC8705}}, locally,
even when it introspects ({{composite-active}}).

An opaque Mission-bound token is enforced from its active
introspection response or issuer-local resolution instead, under the
same rules ({{introspected-consumption}}).

## Enforcement Requirements {#rs-requirements}

A resource server:

1. MUST treat `authorization_details` as the authoritative expression
   of authority and enforce each applicable entry according to that
   entry's own type specification (for `mission_resource_access`,
   {{I-D.draft-mcguinness-oauth-mission-resource-access}}). Where
   more than one carried entry applies, entries are alternative
   grants of authority, not conjunctive filters, unless the entry's
   type states otherwise.
2. MUST treat as providing no authority any applicable entry whose
   type it does not implement, or whose type-defined enforcement it
   cannot complete (an unrecognized member, an unenforceable
   constraint, or an unrecognized matching mode). It MUST refuse the
   request, with `insufficient_scope` ({{RFC6750}}) or the
   RAR-remediation challenge as {{rs-denials}} states, unless another
   applicable entry that it can fully enforce authorizes the whole
   request on its own, and MUST NOT combine parts of several entries
   to authorize one request. A failure of the token's own validation
   (above) rejects the token whatever its entries carry.
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
6. MUST accept a `mission` claim only from an issuer it explicitly
   trusts to issue Mission-bound authorization for the resource;
   trusting the issuer's ordinary access tokens is not enough. It MUST
   require `mission.issuer` to equal the token's `iss`, unless a
   Mission-binding profile it has adopted ({{mission-claim-reservation}}),
   such as {{I-D.draft-mcguinness-oauth-mission-cross-domain}},
   explicitly establishes the permitted relationship between the two.
   It MUST
   reject a token that fails either check with the `invalid_token`
   error code. For an opaque token, the issuer is the AS whose
   introspection response or issuer-local resolution the resource
   server relies on, and the same checks apply to that response's
   `mission` member ({{introspected-consumption}}).

A resource server can also:

- require that a token carry an `act` chain and record it, while
  authorizing only the token's current actor
  ({{Section 4.1 of RFC8693}});
- log the `mission` claim's `id` and the token's `jti` claim with
  each served request, so its access logs join to Mission evidence;
  or
- where the AS offers it, introspect the token ({{introspection}}) to
  observe Mission state per request.

## Mission-Unaware Resource Servers {#rs-mission-unaware}

Two parties keep a delegated Mission-bound token, one carrying an
`act` claim, from consumers that do not process the `act` chain:

- **The AS, at issuance.** The AS MUST refuse, with `invalid_target`
  ({{error-mapping}}), a request for a delegated Mission-bound token
  whose audience it has not established as a Mission-aware Resource
  Server ({{rs-requirements}}) that also processes the `act` chain,
  authorizing and logging the caller from the chain rather than from
  `client_id` alone. That the audience parses `act` does not
  establish this.
- **The deployment, after issuance.** A deployment MUST NOT route a
  delegated Mission-bound token to a Mission-unaware resource server,
  or to logging or audit infrastructure, that authorizes or logs the
  caller on `client_id` without processing the `act` chain. The AS
  cannot verify where a token travels beyond its audience or which
  pipelines log its use, so that routing and logging remain the
  deployment's.

A Mission-unaware {{RFC9068}} resource server reads `client_id` as
the immediate client, which is accurate for that single token. It
cannot see the delegation lineage in the `act` chain or look up the
originally-approved agent in the Mission Record, so it cannot
recognize the current actor as a delegate, record that lineage, or
join a delegate's action to the Mission's approval in its audit
records.

A resource that requires Mission-bound tokens can advertise that
through the `mission_bound_authorization_required` protected resource
metadata member ({{protected-resource-metadata}}); a resource server
that serves such a resource is, by that requirement, Mission-aware.
That requirement does not by itself establish that the resource
server processes the `act` chain.

A Mission-unaware resource server that authorizes only from `scope`
operates within the Mission only to the extent the AS established a
safe projection for it at issuance ({{scope-projection}}).
Constrained authority that no safe projection carries is enforced
only where a resource server, or a runtime layer, evaluates
`authorization_details`.

## Carried Authority {#rs-carried-authority}

An entry whose type-defined enforcement a resource server cannot
complete fails closed because a type-defined constraint narrows
authority: treating an unenforceable key or member as absent, or
reducing it to disclosure-only, would widen the grant.

The baseline token carries no `authority_hash` ({{mission-claim}}).
Where a deployment discloses it to a resource server (through
introspection's disclosure privilege,
{{caller-authorization-and-minimization}}, or a companion profile
that carries its own copy), it is an audit correlator, not an
enforcement input, and not a cryptographic proof that the carried
entries are a subset of the approved set.

That subset relationship is an assertion by the AS, authenticated by
the token signature. Mission Approved-Set Verification
({{I-D.draft-mcguinness-oauth-mission-approved-set-verification}})
defines an independent check for a resource server that needs more
than that assertion.

## Denial Responses {#rs-denials}

A resource server denial falls into one of four cases, each using the
OAuth challenge for its own failure class ({{error-mapping}} gives
the codes):

1. **Weak or stale Subject authentication.** Where the deployment
   conveys the authentication of the token's Subject, through the
   claims of {{token-authentication-lifetime}} or introspection
   ({{Section 6 of RFC9470}}), and that authentication does not meet
   the resource's requirement, the resource server challenges with
   `insufficient_user_authentication` and the `acr_values` or
   `max_age` parameters ({{Section 3 of RFC9470}}).

   Where no Subject authentication applies, the token carries no such
   claims and the challenge offers no remediation, so the resource
   server does not use it. The Subject's authentication is a distinct
   fact from the Approver's approval-time authentication; a requirement
   on the Approver is an approval floor ({{approval-authentication}}),
   not a resource server challenge.
2. **Sender-constraint or key-binding failure.** The token's proof of
   possession is missing or invalid: the resource server challenges
   with `invalid_token`, in the `DPoP` scheme for a DPoP-bound token
   ({{Section 7.1 of RFC9449}}, with `use_dpop_nonce` per
   {{Section 9 of RFC9449}}) and in the `Bearer` scheme for a
   certificate-bound token ({{Section 3 of RFC8705}}). This is not a
   step-up: no fresh user authentication repairs a missing or wrong
   key.
3. **Insufficient carried authority.** The action is outside the
   token's carried authority: the resource server challenges with
   `insufficient_scope` ({{RFC6750}}), or with the RAR-remediation
   challenge where
   {{I-D.draft-ietf-oauth-rar-metadata-remediation}} is deployed
   ({{remediation-grains}}).
4. **Unenforceable constraint.** An applicable entry carries a
   type-defined member or constraint the resource server cannot
   enforce, and the request fails closed under the same base error as
   case 3.

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
  resource server cannot enforce, and the request fails closed. A
  client MUST NOT treat this value as inviting retry, step-up, or
  fresh approval: none of those makes a resource server enforce a
  constraint it does not implement.

A value the client does not recognize is treated as
`insufficient_authority`. A resource server SHOULD include the
attribute only in a response to a validly signed, audience-correct
token whose holder its deployment permits to learn the distinction
({{denial-disclosure}}).

## Remediation Grains {#remediation-grains}

A denial can carry independent remediation grains: separate
remediation mechanisms, each naming a next step without granting
anything. There are three: the `mission_denial` attribute of the
`WWW-Authenticate` challenge ({{rs-denials}}); the
`insufficient_authorization` error code with the
`authorization_remediation` parameter
({{I-D.draft-ietf-oauth-rar-metadata-remediation}}), which names what
`mission_denial: insufficient_authority` only points at; and the
requestable denial of {{AuthZEN.ARAP}}, profiled by
{{I-D.draft-mcguinness-mission-authzen}}, which routes the same denial
into a governed access request rather than a fresh derivation. Each
grain keeps the wire shape and response status its defining document
gives it.

A client that decodes `authorization_remediation` can request the
carried entries on the standard `authorization_details` parameter of
a refresh request ({{token-response}}), where they derive under
this document's ordinary rules ({{authorization-derivation}}): of an
advertised, schema-valid type ({{discovery}}), narrowed same-type
({{subset}}, {{other-types}}) like any other request. The AS issues
only what both the presented refresh grant ({{Section 6 of RFC9396}})
and the Authority Set contain, and refuses a request beyond either
({{refresh-tokens}}), so a refresh-token family narrower than the
Mission does not obtain the Mission's wider authority.

For entries outside the Authority Set, more authority requires a new
approval, proposed as for a new Mission ({{authority-proposal}}), or
an expansion where that companion is deployed
({{I-D.draft-mcguinness-oauth-mission-expansion}}).
A client holding no refresh grant that covers the entries proposes
them as for a new Mission.

The three grains compose: a deployment can offer any subset, and none
widens authority beyond what {{authorization-derivation}} derives
from the same proposal unremediated.

# Error and Challenge Mapping {#error-mapping}

This document reuses standard OAuth errors and challenges, selected
by parameter ownership and processing stage. The following tables are
the normative statement of the base OAuth error for each failure they
list. Every rule elsewhere in this document that names one of these
codes applies this mapping.

An AS that performs an applicable check early, at PAR, responds with
the same error class the check would yield at the authorization or
token endpoint. {{Section 2.3 of RFC9126}} permits an
authorization-request error at PAR, and returning it there does not
change which row applies.

Where a token request fails more than one check, this document
defines no general precedence among the resulting errors; as under
{{RFC6749}}, which defines none, the AS returns any applicable one.
The orders this document does state still apply: a submission's
processing order ({{submission-processing}}), and the Mission-governed
refusal, which applies only to an otherwise processable request
({{authority-proposal}}). The choice relaxes neither client
authentication nor any rule that limits who receives a detail, such
as `mission_error` ({{issuance-gating}}).

The tables are grouped by surface. The first table holds each
failure whose rule is not confined to the surface of one of the other
three tables (PAR and the authorization endpoint, Token Exchange, or a
protected resource); each failure appears once. Token Exchange is a
token-endpoint operation: a row of the first table that names the
token endpoint or a token request covers an exchange, alongside the
exchange rows of the third table.

| Surface / failing input | Base OAuth error and optional detail |
|---|---|
| PAR, or a companion's token-endpoint submission: a presented evidence entry of an unsupported type, or failing its type's validation or verification ({{intent-submission-evidence}}), or a required evidence type absent | `invalid_mission_intent_evidence` ({{intent-submission-evidence}}). Detail: safe `error_description` |
| Authorization or token request: invalid, unknown, or malformed actual RFC 8707 `resource` parameter, or a token-endpoint `resource` outside the Mission's Authority Set ({{token-response}}) | `invalid_target` ({{Section 2 of RFC8707}}). Detail: safe `error_description` |
| Token request: the requested audience is approved for none of the entries the token would carry, the request's `authorization_details` names an entry not approved for its audience, or the audiences it names are approved for different entries ({{token-response}}) | `invalid_target` ({{Section 2 of RFC8707}}). Detail: safe `error_description` |
| Authorization or token request: the target's scope-projection mapping is unknown, ambiguous, or stale, whether or not the request names a `scope` value, or the target is `scope`-only and no safe projection exists for the applicable entries when the request names no `scope` value ({{scope-projection}}); or the AS has not established a delegated Mission-bound token's audience as a Mission-aware Resource Server that also processes the `act` chain ({{rs-mission-unaware}}) | `invalid_target` ({{Section 2 of RFC8707}}). Detail: safe `error_description` |
| Authorization or token request: an explicitly requested `scope` value the issuance cannot grant under a scope-projection mapping the AS trusts ({{scope-projection}}) | `invalid_scope` ({{Section 4.1.2.1 of RFC6749}}, {{Section 5.2 of RFC6749}}). Detail: safe `error_description` |
| Profile-defined operation that lets a client present a Mission Identifier alongside a credential ({{grant-binding-resolution}}): the identifier does not match the Mission the credential resolves to | `invalid_grant` ({{Section 5.2 of RFC6749}}). Detail: safe `error_description` |
| Token endpoint: the Mission is `terminated` (revoked, expired, superseded, or another termination reason), or in another state that is not `active`, such as one a companion profile defines | `invalid_request` on a Token Exchange ({{Section 2.2.2 of RFC8693}}), `invalid_grant` ({{Section 5.2 of RFC6749}}) on any other grant, or the code a Token Exchange profile assigns ({{issuance-gating}}). Detail: `mission_error` ({{iana}}), or a value the companion profile defines for its state ({{issuance-gating}}) |
| Token endpoint ({{subset}}, {{refresh-tokens}}): the requested RAR subset exceeds the Mission's granted authority, or, on refresh, the presented refresh grant | `invalid_authorization_details` ({{Section 6 of RFC9396}}). Detail: safe `error_description` |
| Token endpoint ({{subset}}): the comparison cannot establish that a requested RAR entry is a subset (an unrecognized member, an incomparable value) | `invalid_authorization_details` ({{Section 6 of RFC9396}}). Detail: safe `error_description` |
{: title="Failures not confined to one surface"}

| Surface / failing input | Base OAuth error and optional detail |
|---|---|
| PAR: malformed Submission envelope or Intent (schema, unknown member, invalid value), including a structurally invalid evidence entry ({{submission-via-par}}, {{intent-submission-evidence}}) | `invalid_request` ({{Section 5.2 of RFC6749}}). Detail: safe `error_description` |
| PAR or authorization: malformed or unsupported actual RAR object (an entry of a submitted `authorization_details` proposal) ({{authority-proposal}}) | `invalid_authorization_details` ({{Section 5 of RFC9396}}). Detail: RAR-defined detail |
| PAR: a proposed entry, valid for its type, whose `resource` is not among the Intent's `target_resources` ({{authority-proposal}}) | `invalid_request` ({{Section 5.2 of RFC6749}}). Detail: safe `error_description` |
| PAR or authorization request from a client registered as Mission-governed: `authorization_details` without `mission_intent` ({{authority-proposal}}) | `invalid_request` ({{Section 4.1.2.1 of RFC6749}}, {{Section 5.2 of RFC6749}}). Detail: safe `error_description` |
| Token request, any grant type: an audience the token would carry, named or inferred, is a Mission-governed resource, and the request has no qualifying Mission binding ({{authority-proposal}}) | `invalid_target` ({{Section 2 of RFC8707}}). Detail: safe `error_description` |
| Authorization request: `scope` includes `openid` and the Approver is not the Subject ({{approval-authentication}}) | `invalid_scope` ({{Section 4.1.2.1 of RFC6749}}). Detail: safe `error_description` |
| Authorization decision ({{direct-approval-steps}}, {{approval-authentication}}, {{derivation-modes}}, {{approval-commit}}): the Approver declines, approval authentication fails the floor or a requested `acr_values` or `max_age`, a well-formed request (including configured-mapping mode) is refused by AS policy, or the commit finds the effective expiry not later than the creation instant | `access_denied` ({{Section 4.1.2.1 of RFC6749}}). Detail: for a configured-mapping refusal, a safe `error_description` can say whether no mapping matched or policy narrowed the candidates to nothing; for an expiry at the commit, a safe `error_description` can say that the requested expiry has passed; otherwise none unless a defined extension applies |
{: title="PAR and authorization endpoint failures"}

| Surface / failing input | Base OAuth error and optional detail |
|---|---|
| Token exchange: a `subject_token` or `actor_token` that is invalid, whose sender constraint is not proven, or that is unacceptable for the exchange | `invalid_request` ({{Section 2.2.2 of RFC8693}}), unless a Token Exchange profile assigns the failure its own code. Detail: safe `error_description` |
| Token exchange: a required DPoP proof that is missing, or a DPoP proof that fails its own validation | `invalid_dpop_proof` ({{Section 5 of RFC9449}}): the failure is not an unproven sender constraint, so the row above does not apply. Detail: safe `error_description` |
| Token exchange: a DPoP proof lacking the current DPoP nonce, where the authorization server requires one | `use_dpop_nonce` with a `DPoP-Nonce` header ({{Section 8 of RFC9449}}), not `invalid_dpop_proof`. Detail: safe `error_description` |
| Token exchange with no actor ({{self-exchange}}): the authenticated client is not the Mission's approved agent | `invalid_request` ({{Section 2.2.2 of RFC8693}}). Detail: safe `error_description` |
| Delegated token exchange ({{delegated-exchange}}): the AS does not authenticate the requesting client by a method it relies on to identify the client, which no public client meets | `invalid_client` ({{Section 5.2 of RFC6749}}). Detail: safe `error_description` |
| Delegated token exchange ({{delegated-exchange}}): the AS has authenticated the requesting client, and the request carries an `actor_token` | `invalid_request` ({{Section 2.2.2 of RFC8693}}). Detail: safe `error_description` |
| Delegated token exchange ({{delegated-exchange}}): the `subject_token` is not a designation this AS issued naming the authenticated requesting client | `invalid_request` ({{Section 2.2.2 of RFC8693}}). Detail: safe `error_description` |
| Designation ({{designation}}): the AS cannot establish that no resource server accepts the named client's identifier as an audience for its access tokens, including an alias it never issues | `invalid_target` ({{Section 2.2.2 of RFC8693}}). Detail: safe `error_description` |
| Delegated token exchange ({{delegation-constraints}}): narrowing leaves no entries for the delegate | `invalid_target` ({{Section 2.2.2 of RFC8693}}). Detail: safe `error_description` |
| Token exchange using {{delegated-instance-context}}: required Client Attestation fails validation | `invalid_client_attestation`. Detail: no instance-identity disclosure |
| Token exchange using {{delegated-instance-context}}: required instance-to-delegate or output-key association cannot be established | `invalid_request` ({{Section 2.2.2 of RFC8693}}). Detail: no instance-identity disclosure |
{: title="Token Exchange failures"}

| Surface / failing input | Base OAuth error and optional detail |
|---|---|
| Protected resource: a token lacking the `mission` claim, where the resource requires it ({{rs-enforcement}}) | `invalid_token` ({{Section 3.1 of RFC6750}}). Detail: none |
| Protected resource: weak or stale authentication of the token's Subject, where the deployment conveys it ({{rs-enforcement}}) | `insufficient_user_authentication` ({{Section 3 of RFC9470}}). Detail: `acr_values` or `max_age` |
| Protected resource: DPoP proof missing, invalid, or mismatched ({{rs-enforcement}}) | `DPoP` `invalid_token` challenge ({{Section 7.1 of RFC9449}}). Detail: none |
| Protected resource: DPoP nonce required, missing, or stale ({{rs-denials}}) | `DPoP` `use_dpop_nonce` challenge ({{Section 9 of RFC9449}}). Detail: fresh nonce |
| Protected resource: certificate-bound token's presented certificate mismatch ({{rs-enforcement}}) | Bearer `invalid_token` challenge ({{Section 3.1 of RFC6750}}, per {{Section 3 of RFC8705}}). Detail: none |
| Protected resource: an opaque Mission-bound token that its introspection response or issuer-local resolution reports inactive ({{introspected-consumption}}) | `invalid_token` ({{Section 3.1 of RFC6750}}), in the `DPoP` scheme for a DPoP-bound token ({{Section 7.1 of RFC9449}}). Detail: none |
| Protected resource: introspection or issuer-local resolution of an opaque Mission-bound token cannot be completed ({{introspected-consumption}}) | No error code reporting the token invalid: HTTP 503 ({{Section 15.6.4 of RFC9110}}), with `Retry-After` where a retry time is meaningful. Detail: none |
| Protected resource: insufficient carried authority, or an unenforceable constraint ({{rs-denials}}) | `insufficient_scope` ({{Section 3.1 of RFC6750}}) or the RAR-remediation challenge ({{remediation-grains}}). Detail: `mission_denial` ({{rs-enforcement}}), minimized |
{: title="Protected resource challenges"}

In these tables, which evidence types are required follows
{{I-D.draft-mcguinness-oauth-mission-submission-evidence}}, and
`invalid_client_attestation` is the error code that
{{Section 5.2 of I-D.draft-mcguinness-oauth-client-instance-id}}
specifies.

# Mission State via Token Introspection {#introspection}

A resource server consults the issuer about a Mission-bound token in
one of three cases, with different obligations:

- **JWT state observation.** A resource server that observes Mission
  state per request introspects the JWT Mission-bound token it holds,
  instead of waiting for the token to expire.
- **Opaque-token consumption.** For an opaque Mission-bound token,
  introspection is the claims carriage: an active response carries
  what the JWT would ({{introspected-consumption}}).
- **Issuer-local resolution.** In place of introspection for an opaque
  Mission-bound token, an AS can serve a qualifying resource server by
  a direct read of the AS's authoritative committed token and grant
  state ({{introspected-consumption}}).

An AS MAY support OAuth 2.0 Token Introspection {{RFC7662}} for
Mission-bound access tokens. When it does, an `active: true` response
for such a token, to a caller authorized to receive Mission data
({{caller-authorization-and-minimization}}), MUST carry, in addition
to the standard members, a `mission` member: a JSON object with the
following members:

- `id` and `issuer`: as in the `mission` claim ({{mission-claim}}).
- `state`: the Mission's current lifecycle state (string). Its value
  space, including a state a deployed companion profile defines, and
  the consumer's forward-compatibility rule are those of
  {{lifecycle}}.
- `termination`: when `state` is `terminated`, the Mission's
  `termination` ({{termination}}) (object).
- `proposal_hash`: when the Mission records an authority proposal,
  the Mission's `proposal_hash` ({{mission-record}}) (string).
- `authority_hash`: the Mission's Authority Set commitment
  ({{mission-record}}) (string).
- `approval_basis`: the Mission's `approval_basis`
  ({{mission-record}}), carrying `type` only.
- `authority_source`: the Mission's `authority_source`
  ({{mission-record}}), carrying `type` and, for `organizational`,
  `policy` with `id` and `version` only, never the policy `digest`.

Only the Mission `issuer` reports `state`, `termination`,
`proposal_hash`, `authority_hash`, `approval_basis`, and
`authority_source` ({{only-issuer-reports-state}}). The last four are
audit and correlation signals, not enforcement inputs
({{rs-enforcement}}); each is disclosed only as
{{caller-authorization-and-minimization}} permits.

For a malformed, unknown, individually expired, or otherwise
unresolvable token, the AS responds per {{RFC7662}} (`active: false`)
with no `mission` member; it does not reveal Mission state for a
token it cannot bind to a Mission. The AS discloses a `mission` member
only for a token it has established was issued on a path that
conforms to {{mission-claim-reservation}}; a token it cannot establish
so is unresolvable in this sense. How the AS establishes this is its
own; a record of its own issuance is one means.

The composite-active rule ({{composite-active}}) and the `mission`
member apply equally when a Mission-bound refresh token is
introspected.

Freshness is per use. Strengthening {{Section 4 of RFC7662}}, which
permits a protected resource to cache the response, this document
defines no caching semantics for the `mission` member: a resource
server that relies on introspection for Mission state treats each
response as an observation for that decision, not as a cacheable
state assertion.

A deployment that needs bounded-staleness caching adopts the Mission
Status companion, whose signed responses carry explicit freshness
({{I-D.draft-mcguinness-oauth-mission-status}}).

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
audience-filtered enforcement projection above, without them.

A `mission` member that a companion profile defines for disclosure
here follows the same member-scoped rule and is not an enforcement
input.

## Composite Active State {#composite-active}

The introspection `active` member reflects the composite
authorization, not the token in isolation. Strengthening
{{Section 4 of RFC7662}}, the AS MUST return `active: true` only when
the access token passes that section's checks (valid signature,
unexpired, and not individually revoked) and the Mission is
`active`. A designation ({{designation}}) authorizes no resource
access: the AS MUST return `active: false` for one, with no `mission`
member.

The AS does not verify the token's sender-constraint (`cnf`) at
introspection; the resource server checks proof of possession when
the token is presented, so `active: true` is not by itself evidence
that the caller holds the bound key.

When the token is otherwise valid but the Mission is `terminated`,
the AS MUST return `active: false` and include `mission.state` and
`mission.termination`, whose `reason` gives the cause, so a resource
server can distinguish a dead Mission from a bad token. A Mission
transition does not by itself revoke the token as an individual
credential; introspection reports the composite authorization as
inactive. An otherwise valid token is one that passes those checks and
that the AS has established was issued on a conforming path
({{introspection}}).

Reporting the `mission` member, `mission.state` included, for an
inactive token deviates from the SHOULD NOT of Sections 2.2 and 4 of
{{RFC7662}} against including additional information about an
inactive token. The caller authorization and minimization rules
({{caller-authorization-and-minimization}}) govern that deviation.

## Issuer-Only Members {#only-issuer-reports-state}

An AS MUST NOT include `mission.state`, `mission.termination`,
`proposal_hash`, `authority_hash`, `approval_basis`, or
`authority_source` in an introspection response unless it holds the
Mission, that is, unless it is the Mission `issuer`. Introspection at
a non-issuer Resource AS, which returns only the claim-shape members,
is specified by the cross-domain companion
({{I-D.draft-mcguinness-oauth-mission-cross-domain}}).

## Introspected Token Consumption {#introspected-consumption}

The RFC 9068 JWT of {{mission-bound-tokens}} is this document's
self-contained carriage. An AS MAY instead issue a Mission-bound
access token as an opaque reference token, under this mode and only
under it; an opaque Mission-bound token outside this mode is not
profiled.

- In this mode, an AS issuing opaque Mission-bound tokens MUST offer
  introspection for them with the members this mode names, unless
  every resource server that consumes them uses issuer-local
  resolution (below).
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
- A resource server consuming an opaque Mission-bound token:
  - MUST resolve it through introspection or issuer-local resolution
    (below) before service;
  - MUST verify `active` is `true`, its own identity in `aud`, and
    the sender-constraint binding `cnf` names; and
  - MUST enforce the response's `authorization_details` under the
    same rules as the token-carried form ({{rs-enforcement}}), the
    fail-closed duties included.
- A resource server whose introspection response for an opaque
  Mission-bound token is `active: false`, or whose issuer-local
  resolution resolves it as inactive, MUST refuse the request with
  the `invalid_token` error code ({{Section 3.1 of RFC6750}}), in the
  `DPoP` scheme for a DPoP-bound token ({{Section 7.1 of RFC9449}}).
- A resource server that cannot obtain a valid introspection response
  or issuer-local resolution for an opaque Mission-bound token MUST
  refuse the request rather than serve it from any cached or
  out-of-band belief about the token's authority. The failure
  establishes nothing about the token: the resource server MUST
  respond with HTTP status code 503 (Service Unavailable)
  ({{Section 15.6.4 of RFC9110}}), adding a `Retry-After` header field
  where a retry time is meaningful, and MUST NOT report the token as
  invalid, such as with the `invalid_token` error code.

The per-use freshness rule of {{introspection}} covers the whole
response in this mode: each response is one observation of the
token's claims and Mission state, not a cacheable authority record.

An AS MAY serve a resource server through issuer-local resolution: a
direct read of the AS's authoritative committed token and grant
state, not a call to an introspection endpoint. {{RFC7662}}
introspection keeps its meaning as a network protocol. A resource
server qualifies only when it is inside the issuer's trusted
implementation boundary and the AS authorizes it to read that state;
common ownership or a shared network does not by itself qualify it.

For each resolution, the AS:

1. MUST resolve the presented token to that token's own
   issuer-qualified issuance or grant record, and establish from that
   record the token's expiry, revocation and grant validity, its
   intended audience, the composite active state
   ({{composite-active}}), and the token's own authority;
2. MUST authorize the resource server and minimize disclosure to it
   as {{caller-authorization-and-minimization}} requires for an
   introspection caller; and
3. MUST yield, when the token is active, only what an active response
   for that token carries in this mode, audience-filtered for that
   resource server and with `act` and `cnf` as that response carries
   them, and never the Mission's Authority Set or other authority the
   token does not carry.

Mission state alone, or a lookup by Mission Identifier, never
establishes a token's validity or authority. An unknown, invalid,
expired or revoked token, or a Mission that is not `active`, resolves
as inactive and yields no authority; missing or unavailable state
yields no valid resolution.

In the resource server duties above, the resolution stands in for the
introspection response, possession proof and fail-closed refusal
included, and each resolution is one per-use observation, not a
cacheable assertion.

## Introspection Response Examples {#examples}

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
  "exp": 1793606705,
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
      "sha-256:hjXlwWBY64-RPs1Z-E_gbyklNcViI5c9jiyMbE4KvFM",
    "proposal_hash":
      "sha-256:p-s-EzdNQTn6RoPHXESkwVtGdk8yL1PxryNyMwroKGo",
    "state": "active"
  }
}
~~~

The following is an example of the response, after the Mission is
revoked, for an unexpired token the AS issued on refresh before the
revocation ({{composite-active}}):

~~~ json
{
  "active": false,
  "mission": {
    "id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
    "issuer": "https://as.example.com",
    "authority_hash":
      "sha-256:hjXlwWBY64-RPs1Z-E_gbyklNcViI5c9jiyMbE4KvFM",
    "state": "terminated",
    "termination": {
      "reason": "revoked",
      "terminated_at": "2026-11-02T08:53:20Z"
    }
  }
}
~~~

# Delegation Within a Mission {#delegation}

Delegation is an optional capability ({{conformance}}). An agent may
delegate execution to downstream actors (a sub-agent, service, or tool
that is itself an OAuth client) within a Mission. Delegation is
represented with the OAuth Actor Profile
{{I-D.draft-mcguinness-oauth-actor-profile}}, which profiles the
`act` (actor) claim of {{Section 4.1 of RFC8693}}.

An intermediary in the agent's own trust domain that presents the
agent's own tokens, such as a gateway holding the agent's
credentials, acts as part of the agent and is not a delegate; acting
as the agent, it can also narrow by self-exchange ({{self-exchange}}),
which does not delegate. An intermediary authenticated as a distinct
actor that obtains a delegated token by Token Exchange is a delegate.

Delegation takes two kinds of Token Exchange, in this order:

1. The delegating party obtains a designation that names the delegate
   ({{designation}}).
2. The delegate redeems that designation for a delegated token
   ({{delegated-exchange}}).

~~~
Delegating party            AS                        Delegate
  | Token Exchange:          |                            |
  | subject_token =          |                            |
  | Mission-bound token,     |                            |
  | audience = delegate ---->|                            |
  |<------ designation ------|                            |
  |---------------------- designation ------------------->|
  |                          |<------ Token Exchange:     |
  |                          |        subject_token =     |
  |                          |        designation         |
  |                          |------- delegated token --->|
~~~

## Designation {#designation}

A designation is the delegating party's authorization for one
delegate to obtain delegated tokens. The holder of a Mission-bound
access token obtains it by Token Exchange ({{RFC8693}}): it presents
that token as the `subject_token`, proves possession of the token's
confirmation key, and names another client's identifier as
`audience`, with `requested_token_type`
`urn:ietf:params:oauth:token-type:access_token`. Only a
sender-constrained token can therefore be designated. The holder is
the Mission's approved agent for a token that carries no `act` claim,
and otherwise the delegate that the AS's accounting records as the
token's outermost actor ({{delegation-constraints}}).

Issuing a designation applies the checks of {{issuance-checks}} as
that list states for a designation.

A designation the AS issues:

- carries a subset ({{subset}}) of the presented token's authority,
  and the same `mission` claim ({{mission-claim}});
- has `aud` equal to the designated client's identifier, and a
  `may_act` claim ({{Section 4.4 of RFC8693}}) whose `sub` is that
  identifier;
- carries no `cnf` and no `act` claim: like an authorization code, it
  is bound to the client that redeems it, which authenticates and
  proves its own key in the delegated exchange ({{delegated-exchange}}),
  and the delegated token's `act` renders the AS's accounting
  ({{delegation-constraints}}); and
- MUST expire shortly after it is issued, and no later than the
  presented token or the Mission's `expires_at`.

A designation names a delegate and adds none. Whether one may be
redeemed more than once within its lifetime is the AS's policy; each
redemption is a delegated exchange of its own ({{delegated-exchange}}).
Its expiry bounds when it can be redeemed, not the lifetime of a
delegated token issued from it ({{token-authentication-lifetime}}).

A designation authorizes no resource access. A designated client's
identifier MUST NOT be an audience that any resource server accepts
for this AS's access tokens, throughout the designation's lifetime.
That includes an alias a resource server accepts but the AS never
issues as an audience. The AS MUST refuse, with `invalid_target`
({{Section 2.2.2 of RFC8693}}), a designation request naming a client
for which it cannot establish that separation. A resource server that
validates a JWT access token's audience ({{Section 4 of RFC9068}})
therefore rejects a designation, and the AS reports one inactive at
introspection ({{composite-active}}).

## Delegated Exchange {#delegated-exchange}

A delegate obtains a delegated token by Token Exchange
({{RFC8693}}), presenting a designation that the delegating party
obtained for it ({{designation}}). Issuance applies the checks of
{{issuance-checks}} as that list states for a delegated exchange. The
AS issues the delegated token subject to all of the following:

- **The exchange is explicit.** The `subject_token` is a designation
  this AS issued naming the authenticated requesting client
  ({{designation}}), with `subject_token_type`
  `urn:ietf:params:oauth:token-type:access_token`, and the
  `requested_token_type` is
  `urn:ietf:params:oauth:token-type:access_token`. The AS MUST refuse
  any other `subject_token` with `invalid_request`
  ({{Section 2.2.2 of RFC8693}}); an access token issued for resource
  access is never sufficient. The delegate is identified by its own
  client authentication, and the AS asserts the actor itself
  ({{delegation-constraints}}).
- **The delegate authenticates.** The AS MUST authenticate the
  requesting client, whether or not the request carries an
  `actor_token`, by a method it relies on to identify the client
  ({{Section 2.3 of RFC6749}}), and MUST refuse a client it does not
  so authenticate with `invalid_client` ({{Section 5.2 of RFC6749}}),
  issuing no token. Once it has so authenticated the client, the AS
  MUST refuse a request that carries an `actor_token` with
  `invalid_request` ({{Section 2.2.2 of RFC8693}}), issuing no token.
  A claimed `client_id`, possession of the designation, or proof of
  an independently chosen key, such as a DPoP key, does not
  authenticate a client. This document does not
  support a public client as a delegate: {{Section 2.3 of RFC6749}}
  lets an AS establish a client authentication method with a public
  client but not rely on it to identify the client. Only an extension
  that defines an explicit binding of a designation to its delegate
  admits one; deployment policy alone does not.
- **Subject is stable.** `sub` remains the Mission's Subject. The
  delegate is an actor, not the Subject.
- **`client_id` keeps its ordinary meaning.** It names the client that
  requested the token ({{token-claims}}); the originally-approved agent
  stays in the Mission Record ({{client-id-rebinding}}).
- **The `act` chain identifies the delegates.** The delegated token
  carries an `act` claim per {{Section 4.1 of RFC8693}} and the Actor
  Profile {{I-D.draft-mcguinness-oauth-actor-profile}}: the outermost
  `act` is the current delegate, and each earlier delegate is nested
  in the previous actor's `act` member. Each actor object carries the
  members that profile defines (for example, `sub`, `iss`, and the
  `sub_profile` actor-type classification, such as `ai_agent`).
- **The audience processes the chain.** The AS issues the delegated
  token only for an audience that meets the issuance rule of
  {{rs-mission-unaware}}, and refuses any other with `invalid_target`.
- **Authority only narrows.** The delegated token's
  `authorization_details` MUST be a subset ({{subset}}) of the
  designation's authority, hence of the delegating token's and of the
  Mission Authority Set.
- **The `mission` claim is unchanged.** The delegated token carries
  the delegating token's `mission` claim ({{mission-claim}})
  unchanged, so every actor in the chain operates under the one
  consented authority.
- **Each delegate is bound to its own key.** The delegated token MUST
  be sender-constrained ({{token-claims}}) to the **delegate's
  own** key: its `cnf` is the delegate's DPoP or mTLS key, not the
  delegating party's, and the delegate proves possession of that key
  in the Token Exchange. Compromise of a delegate's key therefore does
  not enable use of tokens bound to the agent's or another delegate's
  key.
- **Each redemption is gated.** Issuing a delegated token is a
  derivation, refused unless the Mission is `active`
  ({{issuance-gating}}). The AS MUST evaluate every redemption of a
  designation afresh, as a derivation of its own: the credential the
  designation was derived from, and all applicable grant state
  backing that credential, are still valid; the Mission is `active`;
  and the delegation policy ({{delegation-constraints}}) and the
  Mission's current authority admit the result. An earlier redemption
  establishes none of these. Where that credential was issued under a
  grant lineage, the backing grant state includes that lineage, kept
  through any exchange that established no new grant lineage
  ({{grant-binding-related}}). A credential issued under none, as on
  the Template profile's Dispatch path before its delegation family
  exists, has no lineage to validate; that never excuses dropping or
  ignoring a lineage that does exist. The Mission's `active` state
  never substitutes for backing grant state.

The `act` chain nests (`act.act`) for as long as, and only while,
authority continues under the same approved Mission. A new approval
basis, such as a Child Mission
({{I-D.draft-mcguinness-oauth-mission-child-delegation}}) or an
expansion successor ({{I-D.draft-mcguinness-oauth-mission-expansion}}),
begins its own delegation basis and chain, and no organizational,
network, or deployment boundary by itself restarts or extends a
chain.

The chain is attribution, not authority:

- An `act` entry names who acted, for audit.
- The input to the eligibility matching of {{delegation-constraints}}
  is the delegate the AS authenticates and asserts at the exchange,
  not an entry read from the chain.
- An asserted actor identity grants nothing.
- The `authorization_details` subset relations ({{subset}}), not the
  chain, show that authority narrowed.

## Instance Context in Delegated Tokens {#delegated-instance-context}

Where a deployment authenticates client instances
({{I-D.draft-mcguinness-oauth-client-instance-id}}, with attesters a
client endorses under {{I-D.draft-mcguinness-oauth-client-attesters}}),
the delegate named by the outermost `act` can be an actor that an
authenticated instance represents. Instance evidence does not
establish that actor
({{Section 5 of I-D.draft-mcguinness-oauth-client-instance-id}}), so
the AS establishes the delegate's actor identity, and that actor's
trusted association with the instance, separately.

Because a delegated token is sender-constrained to the delegate's own
key ({{delegated-exchange}}), and the Actor Profile makes the
top-level `cnf` the current presenter's key
({{I-D.draft-mcguinness-oauth-actor-profile}}), that `cnf` is a key
the instance possesses.

A deployment MAY convey `client_instance` in delegated tokens under
{{I-D.draft-mcguinness-oauth-client-instance-id}}. This composition
selects the authenticated presenting instance for output context.
The instance specification owns attestation validation,
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

The actor authentication, delegation eligibility, subset, and lifecycle
checks of {{delegated-exchange}} and {{delegation-constraints}}
still authorize the exchange; instance evidence satisfies none of them
by itself. Where deployment policy requires instance attribution, the
AS MUST refuse the exchange if the required instance evidence or its
association with the delegate and output key cannot be established.
{{error-mapping}} gives the error codes for these refusals.

If the exchange issues a refresh token, the grant-continuity rules of
{{Section 5.1 of I-D.draft-mcguinness-oauth-client-instance-id}}
apply alongside {{grant-binding}}; instance continuity alone does not
authorize replacement of the recorded instance or key rebinding.

Consumers establish presenter attribution under Sections 7.3 and 7.5
of {{I-D.draft-mcguinness-oauth-client-instance-id}}. A consumer
requiring attribution rejects unestablished associations under
{{Section 7.6 of I-D.draft-mcguinness-oauth-client-instance-id}}.

This composition does not add provenance to `client_instance`: a
consumer can use the direct-attestation trust configuration only when
the issuer meets that configuration's restriction against upstream
context. An issuer also conveying upstream context needs a separately
specified, authenticated provenance mechanism before its context can
support presenter attribution.

## Self-Exchange Down-Scoping {#self-exchange}

An agent MAY present its own Mission-bound access token as the
`subject_token` of a Token Exchange ({{RFC8693}}) with no actor, to
obtain a narrowed token (for example, a single-audience one). Because
it names no actor, such an exchange does not delegate: it re-scopes
the agent's own authority downward. A designation ({{designation}})
names a delegate, so it is not a self-exchange, and these rules do not
apply to it. An exchange whose `subject_token` is a designation is a
delegated exchange ({{delegated-exchange}}), not a no-actor exchange,
even when it carries no `actor_token`. Issuance applies the checks of
{{issuance-checks}} as that list states for a self-exchange. A
no-actor exchange is subject to the following:

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
({{I-D.draft-mcguinness-oauth-mission-resource-access}}).

Because the policy lives in the entry, `authority_hash` commits it
with the rest of the Authority Set, and it is carried with the entries
wherever they go, including across a cross-domain projection where
that profile's provenance rule keeps it
({{I-D.draft-mcguinness-oauth-mission-cross-domain}}).

**Delegation depth.** The delegation depth of a token is the number
of delegations between the approved agent and the token's current
actor: the agent's own non-delegated token is depth 0, the first
delegate is depth 1, and each further delegate adds 1. The depth
checked against `max_depth` is that of the token being issued,
computed after appending the new outermost actor, not the depth of
the delegating token. A credential projected across a trust domain
carries no `act` chain and enters the target domain at depth 0
({{I-D.draft-mcguinness-oauth-mission-cross-domain}}).

**Depth accounting.** The AS MUST establish delegation depth from
accounting it maintains for the tokens it issues under the Mission
and associates with the credential it validates (for example, recorded
at issuance against the token), not from the nesting of a presented
`act` claim. The `act` chain is attribution
({{delegated-exchange}}): it renders the accounted chain and is not
the source of the count.

Over the exchanges this document defines, the accounting is complete:

- each delegated exchange adds exactly one delegate;
- a designation ({{designation}}) and a self-exchange
  ({{self-exchange}}) add none; and
- a cross-domain projection is the one defined reset.

A profile that issues Mission-bound tokens by another path specifies
how it preserves or reconstructs this accounting and any reset it
defines.

Where the AS cannot establish the depth of the token being issued, no
entry's delegation policy can be evaluated at that depth, so every
entry narrows out under the per-entry rule below and the exchange is
refused as an empty result. A resource server bases no authorization
decision on a prior actor ({{Section 4.1 of RFC8693}}).

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
({{rs-enforcement}}).

## Delegated Token Example {#worked-example-delegated-token}

In this example, the Mission's Authority Set has two entries on the ERP:
`invoices.read`, delegable to `ai_agent` actors through depth 2; and
`journal-entries.write`, which carries no `delegation` member and is
therefore non-delegable. The approved agent `s6BhdRkqt3` designates
sub-agent `tool-runner-7`, an `ai_agent`, which redeems the
designation at depth 1. The read entry
is permitted (depth 1 <= 2, `ai_agent` allowed) and the write entry
narrows out. The following is an example of the decoded delegated
access token:

~~~ json
{
  "iss": "https://as.example.com",
  "sub": "user_3p2q8mN1a0kV7tR",
  "aud": "https://erp.example.com",
  "client_id": "tool-runner-7",
  "iat": 1793607005,
  "exp": 1793607305,
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
  "cnf": { "jkt": "Inaz7NtW9__w8ZNhk-CB7X_Y1G-XSCRAYT4oBffaS_0" },
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

# Standing-Consent Bases {#standing-consent-bases}

A companion profile can generalize approval to a named
standing-consent basis. Under it, a template or policy activates
Mission instances against an accountable human's earlier approval,
with no fresh human approval per instance; each instance is still
created at its own approval event ({{approval-event}}). The companion
profile defines the basis's `approval_basis.type` value
({{record-principal-members}});
{{I-D.draft-mcguinness-mission-architecture}} (Section "Mission
Invariants") lists the standing-consent bases that companion profiles
define. The `type` values form a specification-defined namespace with
no registry ({{namespace-taxonomy}}): each further basis is defined by
the companion profile that introduces it.

For a standing-consent `type`, `activation` takes the shape that its
companion profile defines, and `activation_actor` names a dispatching
or requesting party distinct from the consenting human.

An unrecognized `type` or `adjudication.kind` is handled as
{{record-principal-members}} states for every record consumer.

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
: REQUIRED for every standing-consent `type`. An RFC 3339 date-time:
  the instant the accountable human approved the exact consented root
  that `root_commitment` commits (the template version, the drawdown
  policy version), not the instant this Mission instance was
  activated. The activating issuer MUST verify `approved_at` against
  its retained, authenticated record of that standing consent for
  that exact version; it MUST NOT accept the value as the activating
  request's own uncorroborated assertion.

The `adjudication` member ({{record-principal-members}}), where
present, follows the basis. Where a companion profile defining a
standing-consent `type` populates `adjudication`, `kind` MUST be
`policy`, naming the identity and version of the policy or workflow
that adjudicated the instance. A companion profile MUST NOT flatten a
policy's or an Approval Governance Record's assertion set into a
single principal member.

## Standing-Consent Instances {#standing-consent-instances}

Under a standing-consent basis ({{standing-consent-bases}}), the
standing consent and the instance's adjudication supply the human
decision that a direct approval event makes in
{{direct-approval-steps}}: the Approver's authentication (step 1),
the Approver's authorization for the Subject and the authority source
(steps 2 and 3), and the consent rendering (step 5). The other
creation rules still bind the instance's approval event wherever they
apply:

- the Subject is never taken from unauthenticated client input and
  is mapped injectively (step 2, {{subject-establishment}});
- the authority source and its ceiling ({{authority-sources}});
- the effective expiry and its creation-commit check (steps 4 and 7);
- the integrity anchors (step 6); and
- atomic creation deduplicated on `approval_event_id`
  ({{mission-record}}).

## Activation Policy Commitment {#activation-policy-commitment}

Where a standing-consent basis lets
a separate policy artifact adjudicate activation (a dispatch,
drawdown, or child-creation policy, rather than the consented object
itself), the object the accountable human consented to MUST carry
that policy as an activation policy reference: an object of `id` (a
string), `version` (a string), and `digest`.
The `digest` is an integrity anchor ({{integrity-anchors}}) whose
`typ` is `mission-activation-policy`, whose `iss` is the activating
issuer, and whose `value` is an object of `content_type`, the media
type of the policy snapshot, and `content`, the base64url, no-padding
{{RFC4648}} encoding of the snapshot's exact bytes. Before each
activation, the activating issuer MUST compute `digest` over the exact
snapshot it evaluates, and MUST NOT activate the instance under that
policy when the result differs; the companion profile fixes what
follows, as it does for an activation the policy does not authorize.
The issuer MUST retain each snapshot's bytes and media type for the
audit horizon ({{record-provenance-members}}) of every Mission it activates
under that snapshot, so an auditor can reproduce the digest.
Where no separate policy artifact exists, as when child creation is
adjudicated against the approved delegation entry itself, this rule
does not apply.

## Standing-Consent Recency {#standing-consent-recency}

A deployment can declare a maximum
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

# Mission Record {#mission-record}

A Mission is the durable record created at the approval event; a
Mission Identifier ({{mission-id}}) identifies it. Its members are
immutable after creation, except `state` and the `termination` member
written once when the Mission terminates ({{termination}}).

The record is a logical object: this document constrains its members
and their values and requires no storage form. Where a surface or
profile exchanges or signs the record, the record's JSON form, with
the members this section defines, governs.

Record member names omit the `mission` prefix because the record is
the Mission. Prefixed names, such as the `mission_intent` request
parameter and the `mission_id` response parameter, belong to surfaces
that reference a Mission from outside it.

Member names are spelled out (`issuer`, `expires_at`, `created_at`)
and spelled identically on every surface. The compact JWT names
(`iss`, `exp`, `iat`) describe a signed artifact's own envelope, or
identify a party in an `{iss, sub}` object, not the Mission.

Like the `mission` claim ({{mission-claim}}), the record is open
({{extensibility}}): a companion profile of this document MAY record
additional members set at creation using short names coordinated with
it (for example, a lineage member linking the Mission to a
predecessor or parent); any other extension MUST use
collision-resistant names.

The following subsections define the record's members.

## Identity and Lifecycle Members {#record-identity-members}

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
: REQUIRED. A string. The current lifecycle state: `active` or
  `terminated` in this document, or an additional state defined by a
  companion profile, subject to the forward-compatibility rule of
  {{lifecycle}}.

`termination`:
: CONDITIONAL. An object, present exactly when `state` is
  `terminated`: the reason and instant the Mission terminated
  ({{termination}}).

## Approved Content and Commitments {#record-content-members}

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
    specification selects for recording, nested so type-owned
    facts cannot collide with the common members.

  `submission_evidence` is provenance, not enforcement input, and is
  not carried on the `mission` claim ({{mission-claim}}). Recorded
  facts, such as a verified consent reference, are provenance and
  policy input only; a resource domain validates them under its own
  current policy ({{third-party-data-subjects}}).

  No integrity anchor commits `submission_evidence`: its digests are
  only as trustworthy as the Mission Record that holds them and do not
  independently prove which artifacts were presented at admission. A
  profile whose threat model requires that proof commits normalized
  provenance under its own anchor `typ` ({{integrity-anchors}},
  {{extensibility}}).

## Principals and Approval Basis {#record-principal-members}

`subject`:
: REQUIRED. An object. The Subject, an object with `iss` and `sub`.

`approval_basis`:
: REQUIRED. An object. The approved authorization basis this Mission
  is rooted in, fixed at the approval event and immutable thereafter,
  like `subject`. This document defines the `direct` basis in full; a
  companion profile can define a standing-consent basis
  ({{standing-consent-bases}}). The members below apply to every
  approval basis, with the presence each one states. Three of these
  members answer the questions an approval raises: who consented
  (`consent_principal`), who triggered this instance
  (`activation_actor`), and what mechanism decided it
  (`adjudication`).

  `type`:
  : REQUIRED. A string: `direct`, or a standing-consent value that a
    companion profile defines ({{standing-consent-bases}}).

  An unrecognized `type`, and likewise an unrecognized
  `adjudication.kind` ({{mission-record}}), is preserved unchanged as
  opaque provenance on an otherwise valid record: a consumer MUST NOT
  infer or fabricate the human, policy, or Approval Governance Record
  standing behind it, and MUST refuse only a profile operation that
  itself requires recognized adjudication semantics to proceed (for
  example, evaluating a policy-approval recency ceiling). Unlike an
  unrecognized lifecycle state ({{lifecycle}}), an unrecognized value
  here does not by itself invalidate or deactivate the Mission.

  `consent_principal`:
  : REQUIRED. An object with `iss` and `sub`. The accountable human
    (or human-accountable principal) who consented. MAY equal
    `subject`.

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
  : OPTIONAL. A discriminated object naming the decision *mechanism*
    that adjudicated this instance: distinct from `activation_actor`
    (who triggered it) and `consent_principal` (who is accountable
    for it). Present when a Mission-creating profile or deployment
    chooses to make the mechanism explicit; where absent, the
    mechanism is still fixed by `type` and the construction rules of
    this document or a companion profile (below and
    {{standing-consent-bases}}). Members, where present:

    `kind`:
    : REQUIRED. A string: `human` or `policy`, naming a decision
      mechanism, not a storage location for supporting evidence; a
      companion profile MUST NOT define a `kind` value that names a
      record, an evidence store, or the requesting or dispatching
      party. An unrecognized value is handled under the same rule as
      `approval_basis.type` ({{record-principal-members}}).

    `governance_record`:
    : OPTIONAL. A boolean. `true` when an Approval Governance Record
      is recorded for this approval event
      ({{I-D.draft-mcguinness-mission-approval-governance}}), joined
      by this Mission's own `approval_event_id`. It never changes
      `kind`, which follows the basis (below and
      {{standing-consent-bases}}). Approval Governance
      aligns the record's accountable assertion, where it carries
      one, with that `kind`: a governed decision still names its
      mechanism, and the record supplies the fuller assertion set
      behind it, including any multi-assertion set, never flattened
      into it.

    For `kind: human`: no additional kind-specific members; the
    deciding human is `consent_principal`.

    For `kind: policy`: `policy`, a REQUIRED object with `id` and
    `version` identifying the deciding policy or workflow. It decides
    deterministically over recorded inputs, so re-evaluating that
    `version` over them re-checks the decision. A model's output can
    be one such input, recorded with the model's identifier and
    version: it can refuse an activation or narrow the authority it
    activates, and the AS MUST NOT let it supply or widen authority.
    A model is never itself the deciding policy or workflow.

    Where `adjudication` is present for `direct`, `kind` MUST be
    `human`, with or without `governance_record`: a policy decides
    an instance only under a standing-consent basis
    ({{standing-consent-bases}}).

  `approved_at`:
  : Absent for `direct`, whose approval event carries its own instant
    ({{approval-event}}); a standing-consent basis carries it
    ({{standing-consent-bases}}).

  For `direct`, `activation.approval_event_id` MUST identify a human
  approval event ({{approval-event}}). Approval Governance states how
  a record backing a `direct` approval keeps that human decision as
  its accountable assertion
  ({{I-D.draft-mcguinness-mission-approval-governance}}).

  `approval_basis` is provenance: none of the record's integrity
  anchors, such as `intent_hash`, `authority_hash` or `proposal_hash`,
  covers it
  ({{integrity-anchors}}); a profile that commits the Mission Record
  itself covers it under that profile's own anchor. Two optional
  profiles commit it ({{consent-binding}}). Its disclosure
  through introspection follows
  {{caller-authorization-and-minimization}}. It is not carried on the
  baseline `mission` claim ({{mission-claim}}), and it MUST NOT be
  relied on to grant or widen authority wherever it does appear.

`authority_source`:
: REQUIRED. An object. The source of the authority the approval
  draws on ({{authority-sources}}), established at the approval event
  ({{approval-event}}) and immutable thereafter, like
  `approval_basis`. Members:

  `type`:
  : REQUIRED. A string: `user_delegated`, `service_owned`, or
    `organizational`. An unrecognized value is handled under the same
    rule as an unrecognized `approval_basis.type`
    ({{record-principal-members}}): it is preserved unchanged as opaque
    provenance and does not by itself invalidate or deactivate the
    Mission, and only an operation that itself requires recognized
    source semantics refuses (for example, applying the source's
    authority ceiling or its governed policy). An AS MUST NOT approve a
    Mission whose authority source it does not recognize.

  `policy`:
  : REQUIRED for `organizational`, absent otherwise. An object with
    `id`, `version`, and `digest`: the stable reference to, and
    commitment over, the governed organizational policy the Mission
    draws on. `digest` is a prefixed commitment
    ({{commitment-mechanisms}}) whose exact committed input and
    construction the policy's format specifies: its species and, for
    an envelope anchor, its `typ`, `iss`, and `value`. The party that
    produces the reference computes `digest`; a consumer holding the
    policy can reproduce it, and one that does not compares it as an
    opaque value.

  `authority_source` is provenance like `approval_basis`: recorded
  alongside it, folded into neither `intent_hash` nor
  `authority_hash`, and not carried on access tokens; resource
  servers enforce `authorization_details` and do not consult it.

`client_id`:
: REQUIRED. A string. The Agent (OAuth client) that submitted the
  Mission Intent.

## Provenance and Expiry {#record-provenance-members}

`policy_version`:
: REQUIRED. A string. An opaque audit correlator naming the
  derivation policy version in effect at the approval event; the
  policy itself does not travel.

`approval_event_id`:
: REQUIRED. A string. A unique identifier of the approval event, used
  as the approval idempotency key: a retried or duplicate delivery of
  the same approval decision (a replayed callback, a double-submitted
  consent form, a retried standing-consent activation) MUST NOT create
  a second Mission, and the AS deduplicates on this identifier. The
  identifier names the approval event that creates this Mission
  ({{approval-event}}); under a standing-consent basis
  ({{standing-consent-bases}}), it identifies this instance's creation,
  not the earlier standing approval.

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
plus a declared post-expiry period. A deployment retains a
`terminated` Mission's record for its audit horizon.

## Mission Identifier Format {#mission-id}

A Mission Identifier is an opaque URL-safe ASCII string of
`[A-Za-z0-9_-]` characters, with at least 128 bits of entropy,
carrying no semantic content. The AS MUST NOT reuse a Mission
Identifier. The record and the `mission` claim carry it as `id`; a
surface that references a Mission from outside carries it as
`mission_id`, as in the token-response parameter
({{mission-response-parameters}}).

## Mission Record Example {#worked-example}

The following is an example of a Mission Record:

~~~ json
=============== NOTE: '\' line wrapping per RFC 8792 ===============

{
  "id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
  "issuer": "https://as.example.com",
  "state": "active",
  "intent": {
    "goal": "Reconcile Q3 invoices and post adjustments of at most \
      USD 500 per journal entry.",
    "target_resources": ["https://erp.example.com"],
    "task_bounds": [
      "Read only invoices issued in 2026-Q3.",
      "Post journal entries of at most USD 500 each."
    ],
    "purpose": "urn:example:purpose:reconcile",
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
    "sha-256:hjXlwWBY64-RPs1Z-E_gbyklNcViI5c9jiyMbE4KvFM",
  "intent_hash":
    "sha-256:6T-7s_f-mNW9UpfrrZh3r0HRJmU4My_EsNAf1C1U4r0",
  "proposal_hash":
    "sha-256:p-s-EzdNQTn6RoPHXESkwVtGdk8yL1PxryNyMwroKGo",
  "subject": { "iss": "https://idp.example.com",
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
      "sha-256:hjXlwWBY64-RPs1Z-E_gbyklNcViI5c9jiyMbE4KvFM"
  },
  "authority_source": { "type": "user_delegated" },
  "client_id": "s6BhdRkqt3",
  "policy_version": "deploy-policy:v17",
  "approval_event_id": "ape_8K2nP4qV9rL3tY6sB1z",
  "created_at": "2026-11-02T08:00:00Z",
  "expires_at": "2026-12-31T23:59:59Z"
}
~~~

The following example shows an excerpt, other members omitted, of a
Mission for an agent acting for its own workload principal: `subject`
is the workload principal, `client_id` is the agent, and
`consent_principal` is the administrator who approved it under the
`service_owned` source.

~~~ json
{
  "subject": { "iss": "https://login.example.com",
    "sub": "agt_ledger_reconciler" },
  "client_id": "ledger-reconciler",
  "authority_source": { "type": "service_owned" },
  "approval_basis": {
    "type": "direct",
    "consent_principal": { "iss": "https://login.example.com",
      "sub": "adm_4Hq9Tz" },
    "activation": { "approval_event_id": "ape_2Lw7Kq9Rv4" },
    "activation_actor": { "iss": "https://login.example.com",
      "sub": "adm_4Hq9Tz" },
    "root_commitment":
      "sha-256:R6tY2nD9bM7sX1cF8gH2vJ4kE5pNQl3KvZ4mP5x0wQo"
  }
}
~~~

The first example's anchors are computed over its displayed `intent`,
`proposed_authority` and `authority_set` ({{integrity-anchors}}); the
excerpt's `root_commitment` is illustrative. A companion that extends
this example either reproduces the recorded objects byte-exactly or
states that its example diverges and its anchors differ.

# Integrity and Commitments {#integrity-and-commitments}

This section defines how the anchors the Approver consents to at the
approval event ({{approval-event}}) are constructed, canonicalized,
and bound. The Mission Record ({{mission-record}}) records them, and
the test vectors ({{test-vectors}}) pin the construction
byte-for-byte.

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

   Each anchor sets `typ` and `value` as follows:

   - For `intent_hash`, `typ` is `mission-intent` and `value` is the
     approved Mission Intent object: the Submission envelope's
     `intent` member, not the envelope or its `evidence`
     ({{submission-via-par}}).
   - For `proposal_hash`, `typ` is `mission-proposed-authority` and
     `value` is the submitted `authorization_details` array exactly
     as recorded ({{authority-proposal}}); the anchor is present
     exactly when a proposal was submitted.
   - For `authority_hash`, `typ` is `mission-authority-set` and
     `value` is the Authority Set as a JSON array of entries.
   - For an activation policy reference's `digest`, `typ` is
     `mission-activation-policy` and `value` is the policy snapshot
     object that {{activation-policy-commitment}} defines.

2. Canonicalize the envelope with JCS {{RFC8785}}.
3. Compute SHA-256 {{RFC6234}} over the canonical bytes.
4. Encode as `sha-256:` followed by the base64url, no-padding
   {{RFC4648}} encoding of the digest.

The `typ` field domain-separates the anchors so a digest of one
object cannot be mistaken for another's. The `iss` binding prevents
a committed object from being transplanted across authorization
servers. The `sha-256:` prefix is the algorithm-agility mechanism
({{commitment-mechanisms}}).

The anchors this section lists, and the Authority Set entry
commitment below, bind the AS issuer. The `digest` of an
`authority_source.policy` reference ({{record-principal-members}}) is
not one of them: it uses the issuer the policy's format defines, for a
governed organizational policy its governing authority. That binding
keeps the policy's commitment from being transplanted across policy
authorities, and the same policy commits identically at every AS that
records it.

`intent_hash` and `authority_hash` are independent commitments to
independent objects. That the approved task bounds the derived
authority is a governance assertion, made by derivation policy and
auditable through `policy_version` ({{authorization-derivation}}),
not a cryptographic relation between the anchors: neither anchor
proves anything about the other's object.

The `typ` value space is an extension point ({{extensibility}}):
additional committed objects use this same envelope with a new `typ`
and the canonicalization below.

This document defines no registry of `typ` values; each committing
specification defines its own and relies on the `typ` domain
separation. To keep that domain separation safe without a registry, a
new `typ` value MUST be a collision-resistant name (for example, a
short name prefixed within a namespace the defining profile controls,
following the Collision-Resistant Name guidance of
{{Section 2 of RFC7519}}). `mission-` prefixed values, used by this
document and the profiles that extend it, form a namespace
coordinated through this document's change controller.

This document also defines the **Authority Set entry commitment**, the
envelope above with `typ` `mission-authority-entry`, `iss` the
Mission `issuer`, and `value` a single Authority Set entry object
exactly as recorded ({{test-vectors}}). A companion that cites an
entry by digest (a decision record naming the entry it evaluated,
containment or completion state keyed to an entry) computes it this
way.

Entries whose canonical commitment envelopes are identical produce
the same digest, and within one Mission Record every recorded entry
resolving to the same digest forms one selector equivalence class;
the class is defined by the canonical bytes, not by pre-canonical
source text the record does not preserve.

The commitment is not a globally unique entry identifier: the
envelope binds the issuer, not the Mission, so a protocol that uses
it to select or cite an entry MUST bind it to the Mission `issuer`
and Mission Identifier whose recorded Authority Set is searched,
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
- URI-valued members are compared byte-for-byte, with no
  normalization ({{Section 12 of RFC9396}}), unless a member's own type
  definition
  specifies a normalization. Where a type defines one, as
  `mission_resource_access` does for its `prefix`-match resource
  containment test
  ({{I-D.draft-mcguinness-oauth-mission-resource-access}}), it applies
  to that comparison alone: the default `resource` equality test
  remains an exact match, and anchor computation is always byte-exact
  over the recorded values.

## Commitment Mechanisms {#commitment-mechanisms}

This document's default prefixed construction commits to bytes in
three forms, called species, and a specification defining a prefixed
commitment classifies it as one of them:

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
({{I-D.draft-mcguinness-oauth-mission-resource-access}}).

The security considerations of {{RFC8785}} apply to every JCS
computation.

The algorithm prefix is the agility mechanism. `sha-256` is
mandatory to implement and the only algorithm this document defines.
A new algorithm enters only through a new prefix defined by a
referencing specification, its name drawn from the Named Information
Hash Algorithm Registry ({{RFC6920}}); this document defines no
negotiation.

A verifier MUST reject a digest whose algorithm prefix it does not
recognize, so an algorithm added later cannot be exploited as a
downgrade. These rules bind a prefixed digest of any species when its
defining specification classifies it under this taxonomy and imports
this section normatively; this document so classifies every anchor it
defines.

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

# Extensibility {#extensibility}

Other specifications can extend this document. Extensions build
alongside the stable interface below; they MUST NOT redefine it. The
following remain stable across revisions of this document:

- the `mission` claim members `id` and `issuer` ({{mission-claim}});
- the `authorization_details` carriage and its type-agnostic subset
  discipline ({{other-types}}, {{subset}}); and
- the `act` delegation chain ({{delegated-exchange}}).

## Extension Points {#extension-points}

This document's extension points are:

- **Authority types.** The Authority Set is open to any AS-supported
  `authorization_details` type ({{other-types}}); the Mission
  apparatus (commitment, gating, delegation) is type-agnostic, subject
  to the delegation and projection limits in {{other-types}}. A type's
  specification supplies what the apparatus relies on for its entries:
  - the definition a proposed entry is validated against, alongside
    any schema advertised for the type or established out of band
    ({{submission-processing}});
  - the enforcement semantics a resource server applies to an entry
    ({{rs-requirements}});
  - the subset relation, which the AS applies only where it declares
    `narrowing` for the type; otherwise an entry is carried as approved
    ({{subset}}, {{transformation-capabilities}});
  - the delegation policy, which the AS applies only where it declares
    `delegation`; an entry with no type-defined policy is non-delegable
    ({{delegation-constraints}});
  - when a scope-projection mapping is safe for the type's entries,
    which the AS relies on only where it declares `projection`
    ({{scope-projection}}); and
  - any normalization a comparison of its members uses; without one,
    URI-valued members compare byte for byte ({{canonicalization}}).
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
- **Lifecycle state and termination reason.** The lifecycle state
  space ({{lifecycle}}) is open to additional states that companion
  profiles register in the Mission Lifecycle States registry
  ({{iana-lifecycle-states}}) for lifecycles they introduce. The
  termination reasons ({{termination}}) are likewise open to reasons
  that companion profiles register in the Mission Termination Reasons
  registry ({{iana-termination-reasons}}). Under the
  forward-compatibility rule of {{lifecycle}}, only `active` permits
  issuance.
- **Approval-event sequencing.** The approval-event steps, their
  order, and the atomicity of record creation with the approval decision
  are fixed by {{direct-approval-steps}}; the coupling of that
  decision to authorization-code issuance belongs to the direct flow.
  A companion
  profile MAY relocate the approval event relative to code issuance
  (for example, deferring the decision beyond the authorization
  response), provided the steps and their atomicity hold unchanged
  and no Mission reference exists before the record is `active`; the
  Mission Deferred Approval companion is such a profile
  ({{I-D.draft-mcguinness-oauth-mission-approval}}). A back-channel
  carriage profile ({{submission-via-par}}) MAY instead couple the
  approval decision to establishing the Mission grant binding and
  activating for redemption a grant the profile defines, such as a
  device code issued while the request was pending, provided the steps
  and their atomicity with the approval decision hold unchanged and no
  Mission reference exists before the record is `active`; the Mission
  then binds to that profile-defined reusable grant
  ({{grant-binding-resolution}}).

This document defines no capability-negotiation mechanism or
profile-version field; an extension declares its own identifiers and,
where it needs discovery, its own metadata. {{namespace-taxonomy}}
states the general rule these extension points follow.

## Namespace Taxonomy {#namespace-taxonomy}

This document's extensible namespaces follow one of three postures:

- **Registry-backed.** A namespace whose values determine fail-closed
  behavior and span multiple documents is backed by an IANA registry.
  This document creates the Mission Lifecycle States
  ({{iana-lifecycle-states}}), Mission Termination Reasons
  ({{iana-termination-reasons}}), and Mission Intent Members
  ({{iana-intent-members}}) registries and seeds each with the values
  it defines; every further document that defines a value requests
  that value's registration, carrying any Internet-Draft reference as
  a publication dependency under the registry's policy.
- **Specification-defined.** A namespace with a defined fail-safe for
  unknown values and no registry, such as the `mission` claim members
  ({{mission-claim}}), the Mission Record members ({{mission-record}})
  and the `approval_basis.type` values ({{record-principal-members}}),
  is specification-defined: the defining documents are its value space.
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
  ({{mission-intent}}), Authority Set derivation yielding
  `authorization_details` entries of its supported types
  ({{authorization-derivation}},
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

A client performing a task under a Mission MUST NOT present, for that
task, a credential that is not Mission-bound, such as an ordinary
access token it already holds, unless a deployment-defined,
trusted enforcement path establishes that Mission for the request and
applies the Mission's authority and lifecycle controls to it. Neither
a Mission Identifier the client supplies nor documentation alone
establishes the Mission for a request, and the path confers no
authority beyond the Mission's. The rule does not restrict the
client's workflows unrelated to the Mission
({{downgrade-by-omission}}).

An AS that advertises support for this document MUST include at least
one AS-supported type in its `authorization_details_types_supported`
metadata ({{RFC9396}}): the approved-set commitment a Mission-aware
client relies on. Where `mission_resource_access` is among them, the
Mission Resource Access Profile
({{I-D.draft-mcguinness-oauth-mission-resource-access}}), not
out-of-band documentation, is that type's normative definition.

An AS that advertises `mission_bound_authorization_supported: true`
MUST also publish `pushed_authorization_request_endpoint`
({{RFC9126}}), since the authorization-code path accepts a Mission
Intent only through PAR ({{submission-via-par}}).

An AS that advertises `mission_bound_authorization_supported: true`
SHOULD also advertise `authorization_details_types_metadata_endpoint`
{{I-D.draft-ietf-oauth-rar-metadata-remediation}} where it implements
that endpoint. Implementing that endpoint is optional, and the rules
below bind only an AS that advertises it:

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
  default value is `false`. An AS that has authenticated this metadata
  treats a `true` value as making the resource Mission-governed
  ({{authority-proposal}}); `false` or omission does not clear a
  deployment's classification.

A type-defined `authorization_details` member may define its own
constraint-discovery surface; `mission_resource_access`'s is defined
by the Mission Resource Access Profile
({{I-D.draft-mcguinness-oauth-mission-resource-access}}).

A protected resource can list the `authorization_details` types it
accepts in the `authorization_details_types_supported` parameter
({{Section 2 of RFC9728}}), so a client can propose entries of a
type its target accepts.

# Conformance {#conformance}

The smallest useful conforming deployment is a Mission Issuer that:

- derives in narrowing mode from the client's authority proposal
  ({{authorization-derivation}});
- supports one AS-supported `authorization_details` type and emits
  only that type's specification-defined vocabulary; and
- implements none of the optional capabilities.

A scope-only resource server is served only where the AS established
a safe scope projection for it ({{scope-projection}}). A Mission
Issuer can instead start from configured-mapping mode
({{authorization-derivation}}), which is equally conforming. Neither
starting point is a conformance class, and neither removes a surface:
the Mission Issuer still implements every surface its role lists
({{conformance-roles}}), the evidence dispatch and refusal rules
included even when it supports no evidence type, and the deployment
still provides the authenticated revocation means of {{revocation}}.

## Conformance Roles {#conformance-roles}

An implementation conforms in one of three roles.

A **Mission Issuer** (the authorization server) implements the core
issuance surfaces:

- submission of a Mission Intent, in the Submission envelope, via
  PAR ({{submission-via-par}}), with the Intent Submission Evidence
  dispatch and refusal rules ({{intent-submission-evidence}});
- Authority Set derivation yielding `authorization_details` entries
  of its supported types ({{authorization-derivation}},
  {{other-types}});
- the approval event with its integrity anchors and its recorded
  `approval_basis` and `authority_source` ({{approval-event}},
  {{mission-record}});
- issuance of Mission-bound access tokens carrying the `mission` claim
  ({{mission-bound-tokens}}), as the RFC 9068 JWT or as an opaque
  reference token under the introspected consumption mode
  ({{introspected-consumption}});
- the subset rule ({{subset}}); and
- gating of issuance on Mission state ({{issuance-gating}}).

An AS can conform as a Mission Issuer without supporting any Intent
Submission Evidence type. Such an AS refuses every presented entry
under the dispatch and refusal rules ({{intent-submission-evidence}}):
a structurally invalid entry with the `invalid_request` error code, and
any other entry, as an unsupported type, with the
`invalid_mission_intent_evidence` error code. It need not implement the
evidence framework of
{{I-D.draft-mcguinness-oauth-mission-submission-evidence}} for this
configuration. The companion defines conformance for ASs supporting an
evidence type, whether its evidence is optional or required.

A **Mission-aware Resource Server** implements resource server
enforcement ({{rs-enforcement}}). It enforces a JWT from the token's
own claims, needing no Mission-state store and no call to the AS.
Under the introspected consumption mode, it instead enforces the token
from the token-specific inputs of its active introspection response
or issuer-local resolution ({{introspected-consumption}}).

In either form, it enforces each applicable entry its tokens carry
under that entry's type, which for `mission_resource_access` is work
a plain {{RFC9068}} resource server does not do. Conformance in this
role implies support for no particular type: an entry of a type the
resource server does not implement provides no authority there
({{rs-requirements}}), so interoperable enforcement needs a type that
both the AS and the resource server implement.

A **Mission Client** implements the client surfaces:

- submission of the Mission Intent via PAR on the authorization-code
  path ({{submission-via-par}}), proposing concrete authority, where it
  does, on the `authorization_details` parameter pushed alongside
  `mission_intent` ({{authority-proposal}});
- reading its granted authority from the token-response
  `authorization_details` echo, and assuming none absent from it
  ({{token-response}}); and
- obtaining `mission_id` from the `mission_id` token-response parameter
  ({{mission-response-parameters}}), never from the access token,
  treating it as a reference, not a credential.

## Optional Capabilities {#optional-capabilities}

Beyond these mandatory roles, an implementation can additionally claim
three OPTIONAL capabilities. Each is independent, and an implementation
that supports none of them is still conformant:

- **Delegation** ({{delegation}}): issuing designations
  ({{designation}}) and the derived tokens that carry the `act`
  delegation chain, and consuming those tokens. Only a
  sender-constrained token can be designated, so Delegation requires
  sender-constrained primary tokens.
- **Introspection** ({{introspection}}): reporting Mission state through
  the `mission` token introspection response member. Required where
  the AS issues opaque Mission-bound tokens to a resource server that
  does not use issuer-local resolution ({{introspected-consumption}}).
  Issuer-local resolution does not by itself support a claim of this
  capability.
- **Cross-Domain**: projecting a Mission so it is honored by an
  authorization server in another trust domain. An implementation
  claiming this capability preserves, across the hop:

  1. the Mission reference (`mission.id`, `mission.issuer`) and the
     `authority_hash` the projection carries, intact;
  2. authority that only narrows ({{subset}});
  3. projection performed only by, or under the authorization of, the
     Mission `issuer`, gated on the Mission's `active` state
     ({{lifecycle}}, {{issuance-gating}}); and
  4. projected credential lifetimes capped by the Mission's
     `expires_at` ({{token-authentication-lifetime}}).

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

## Claiming Conformance {#claiming-conformance}

A conforming implementation names the optional capabilities it supports
(for example, "Mission Issuer with Delegation and Cross-Domain"); each
capability's defining section or document states its detailed
requirements.

Emitting the `mission` claim is not, by itself, conformance: the claim
is reserved for conforming issuance ({{mission-claim-reservation}}).
Conformance as a Mission Issuer requires the gates:
authority derived from the approved Intent and committed by the
anchors ({{approval-event}}), issuance bounded by the subset rule
({{subset}}), and derivation gated on Mission state
({{issuance-gating}}). An implementation that carries Mission metadata
without these gates conforms to no role in this document and does not
implement it: in particular, it MUST NOT advertise
`mission_bound_authorization_supported` as `true` ({{discovery}}),
the machine-checkable form of that claim.

The Mission Binding Properties vector of
{{I-D.draft-mcguinness-mission-architecture}} names what these gates
supply as its `credential-mission-bound` property, informatively;
these gates remain authoritative for conformance to this document
regardless.

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
bounds every token derived for it. The Mission records
`authority_hash`, which commits the exact Authority Set the Approver
consented to ({{mission-record}}). The goal rests on the AS deriving
only subsets of that set and signing every token accordingly, and on
the resource server verifying the AS's token signature and enforcing
the carried authority, not on every token carrying the commitment
({{mission-claim}}).

A derived token can carry a narrowed subset, so a resource server
cannot in general recompute `authority_hash` from the token, and the
hash supplies no subset proof. A resource server that does not verify
against the complete set relies on the signed token as the AS's
assertion that the carried authority was correctly projected
({{rs-enforcement}}).

A deployment that needs assurance independent of the token signature
verifies the carried authority against the complete approved set. What
that verification provides depends on when the issuer is compromised.

Retrieving the complete set under the same trust root as the token adds
nothing against an issuer malicious at approval time: that issuer can
approve and commit arbitrary authority, and no containment mechanism
changes that. The same checks do defend against projection
implementation errors, against corruption of the record after an
independently anchored approval commitment, and against post-approval
signing-key compromise where the original commitment is pinned outside
the issuer.

`intent_hash` extends the same protection to the task: it commits the
approved Mission Intent, so an auditor can detect any later alteration
of the recorded task. No anchor substitutes for another.
`authority_hash` is computed over the Authority Set alone
({{integrity-anchors}}), what a resource server enforces and a
cross-domain projection carries, so it can be checked without the
Intent.
`intent_hash` stays tamper-evident audit material even where the
authority is projected without the Intent.

The anchors do not commit the **rendered consent disclosure**: none
binds the locale, disclosure-template version, or material notices the
Approver was shown. A buggy or malicious rendering layer could
therefore show a narrower or different task than the committed
Authority Set without a committed trace.

A deployment whose Missions carry high-risk authority can retain
presentation-level audit evidence from which the disclosure shown can
be reconstructed and audited. Mission Consent Evidence
{{I-D.draft-mcguinness-oauth-mission-consent-evidence}} binds a
`consent_rendering_hash` over a structured consent-disclosure object on
the wire; an AS that does not implement it can record equivalent
evidence out of band. Such a commitment binds the structured disclosure
the AS records, not the presentation itself; it narrows this gap for
audit but does not close it.

The anchors do not commit the approval basis either: who consented,
who activated the Mission, and under which basis ({{mission-record}}).
The record's immutability protects it, and only the AS enforces that.
A deployment that needs the approval basis checkable outside the AS
can register the approval event under Mission Audit Transparency
{{I-D.draft-mcguinness-mission-audit}}, whose registration covers the
record at creation except its `state` and `termination`, or carry the
Approval Context Commitment of
{{I-D.draft-mcguinness-mission-approval-governance}}, whose closed
manifest includes the approval basis, in a signed artifact.

### Downgrade by Omission {#downgrade-by-omission}

A token bearing equivalent `authorization_details` but no `mission`
claim is governed by no Mission state, revocation, or consent
commitment. A resource can be Mission-governed ({{authority-proposal}}),
and a deployment can register a client as Mission-governed. Rules on
three sides address this downgrade:

- **Issuance.** The rules of {{authority-proposal}} keep such a
  resource's tokens inside a Mission on every grant type, client
  credentials included, and refuse such a client's authorization
  request that carries `authorization_details` but omits the Intent.
- **Client.** A client holding a Mission Intent does not fall back to an
  ordinary request where Mission support is not established, and a
  client performing a Mission's task does not present an ordinary
  credential it already holds for that task ({{discovery}}).
- **Enforcement.** A resource server for such a resource rejects a token
  lacking the `mission` claim and can advertise that requirement
  ({{rs-enforcement}}, {{protected-resource-metadata}}).

A held ordinary credential needs no request to the AS, and neither an
AS nor a resource server can generally tell that a request made with
one serves a Mission:

- Classifying a resource as Mission-governed closes this path at that
  resource.
- Mandatory mediation closes it where the client's requests must pass
  through a runtime layer that holds custody of the client's
  credentials ({{I-D.draft-mcguinness-mission-runtime}}).
- A decision-time join of an ordinary credential to the Mission, such
  as the Mission Join of
  {{I-D.draft-mcguinness-mission-authority-server}}, is one realization
  of the enforcement path that {{discovery}} permits.
- An unmediated ordinary workflow at a resource that is not
  Mission-governed remains a residual that only the client's own
  conformance closes.

The integrity of the `mission_bound_authorization_supported`
({{discovery}}) and `mission_bound_authorization_required`
({{protected-resource-metadata}}) metadata rests on the retrieval
protections of {{RFC8414}} and {{RFC9728}}, whose security
considerations apply.

## Agent-Specific Threats {#sec-agent}

### Prompt Injection and Data Exfiltration {#prompt-injection}

This document assumes that an agent reading attacker-influenceable
content can be prompt-injected, and does not try to make the agent
immune. Injection is dangerous when one agent combines access to
private data, exposure to untrusted content, and the ability to
communicate externally; the Mission Security Model
({{I-D.draft-mcguinness-mission-security-model}}) analyzes that
combination and its architectural defenses.

This document constrains the data-access leg: a Mission narrows
authority from everything the agent's standing credentials allow to the
resources the approved task needs, and per-task Missions
({{applicability}}) further limit the effect of a compromise.

Against the untrusted-content leg, authority is fixed at the approval
event, so injected text cannot expand an approved Mission. `purpose`
supplies candidate authority only as a lookup key of the pre-approval
Authority Set derivation whose result the Approver reads and
consents to, and otherwise can only refuse or tighten; `goal` and
`task_bounds` bound it only through that disclosure
({{mission-intent}}, {{authorization-derivation}}).

This document does not constrain the external-communication leg. It
models authority over resources and actions, not how an agent uses
authority it holds:
within an approved Authority Set, an injected agent can read what the
Mission permits and write to a sink the Mission permits.

Constraining exfiltration by a compromised agent is the runtime layer's
role ({{runtime-boundary}}), and even there it is bounded, not closed
({{I-D.draft-mcguinness-mission-runtime}}). Preventing misuse of data
within the authorized scope needs a taint or information-flow layer
this document does not define.

### Authority and Propagated Information {#information-propagation}

Issuance gating bounds escalation by token acquisition
({{issuance-gating}}, {{subset}}): an agent cannot exceed the approved
Authority Set by acquiring additional tokens. The same bound holds for
information: an agent can inherit another agent's knowledge, but not its
authority.

A work product of one Mission (a file, message, memory entry, queue
event, or other durable shared artifact) is input, not authority, to
an agent under another Mission that reads it. The
receiving Mission determines what can be done with the information
under its own Authority Set ({{subset}}); the producing Mission's
authority does not transfer through the artifact by copying,
referencing, embedding, or communicating it.

An agent that needs authority to act on what it read acquires it only
through an authorized derivation or delegation bounded by the Mission
({{delegation}}), not from the artifact.

The threat is emergent authority through coordination: independent
Missions communicating through shared state, so that individually
acceptable actions compose into behavior no single Mission authorized
({{I-D.draft-mcguinness-mission-security-model}}). Mission Work
Products {{I-D.draft-mcguinness-oauth-mission-work-products}}
specifies the mechanism that upholds the invariant across such a
carrier (work-product provenance and a non-transitive
Mission-to-Mission handoff); this document takes no normative
dependency on it.

## Enforcement Boundaries {#sec-enforcement}

### Issuance Scope and Runtime Enforcement {#runtime-boundary}

This document governs Authority Set derivation and the issuance of
authority: it bounds what authority a Mission yields, binds it to the
Approver's consent, and gates every issuance on Mission state. It
does not evaluate individual runtime actions. In particular, it does
not:

- evaluate a request's parameters against the Mission at the point of
  use;
- produce runtime enforcement evidence for each consequential action;
- bind tool or function identities to the Mission; or
- re-evaluate at execution time to close the approval-to-execution
  (time-of-check to time-of-use) gap.

Within a token's lifetime, an active Mission can therefore become
ambient authority for individual consequential actions. Short token
lifetimes and narrow authority bound this exposure but do not
eliminate it.

A runtime layer ({{I-D.draft-mcguinness-mission-runtime}}), out of
scope for this document, evaluates each consequential action against
the Mission, with parameter binding, and records evidence for the
actions it covers. A deployment adds one for an action class that needs
any of the following, which issuance-time bounds alone do not provide:

- per-action evaluation or evidence;
- approval bound to a single action; or
- a bound the receiving resource server cannot enforce.

Where the resource server or a composing runtime layer matches an
operation target against a `prefix` entry, the Resource Boundary
Canonicalization analysis of the Mission Resource Access Profile
({{I-D.draft-mcguinness-oauth-mission-resource-access}}) gives the
single-normalization rule for that match, for a deployment that
supports that type.

Short-lived access tokens are this document's issuance-only
recommendation: with no runtime layer, token lifetime is the
revocation-latency bound at unmodified resource servers. Where a runtime
layer covers the high-consequence classes with an active freshness
source, the point-of-use decision is the revocation cutoff, and
lifetimes can be sized by action class without losing that cutoff
({{I-D.draft-mcguinness-mission-runtime}}).

An extended lifetime is appropriate only for a token whose carried
entries are all on runtime-gated paths. Classes attach to entries
while `exp` attaches to the token, so a single ungated entry takes the
extended lifetime as its revocation latency. Narrowed, single-audience
tokens ({{subset}}) keep gated and ungated authority from sharing one
long-lived token.

### Denial Detail Disclosure {#denial-disclosure}

The `mission_denial` attribute and the {{RFC9470}}
`insufficient_user_authentication` challenge ({{rs-enforcement}}) each
tell a caller which path a denial leads into, and so reveal
authorization shape. An `insufficient_user_authentication` challenge
confirms to the presenting party that the authority exists and only the
Subject's authentication is weak or stale, while
`mission_denial: insufficient_authority` denies that the authority
exists.

Introspection guards the same class of fact behind caller
authorization ({{caller-authorization-and-minimization}}), and
{{rs-enforcement}} limits the attribute to a token holder that the
deployment permits to learn the distinction. Of the two values,
`insufficient_authority` reveals least, and omitting the attribute
reveals nothing.

## Credentials and Delegation {#sec-credentials}

### Token Theft {#token-theft}

Derived tokens are sender-constrained (DPoP {{RFC9449}} or mTLS
{{RFC8705}}) where {{mission-bound-tokens}} and
{{delegated-exchange}} require it. A designation ({{designation}})
carries no confirmation key: like an authorization code issued to a
client that authenticates, it is bound to the client that redeems it,
which authenticates to do so ({{delegated-exchange}}), and it
authorizes no resource access. A stolen designation is therefore
useless without that client's credentials. A stolen token is bounded
by the Authority Set and the Mission lifetime regardless, but
sender-constraint prevents replay by a different party.

### Delegation and Chain Compromise {#delegation-and-chain-compromise}

Delegation ({{delegation}}) widens the set of parties holding
Mission-derived authority. Because authority only narrows down the
chain, a compromised actor can act only within its narrowed
`authorization_details`, for the lifetime of the token it holds. The
following limit this exposure:

- The per-entry delegation constraints (delegability, `max_depth`, and
  `allowed_delegates`, {{delegation-constraints}}) bound it at approval
  time. `max_depth` bounds the length of a delegation chain, not its
  breadth: only `allowed_delegates` bounds fan-out to many distinct
  depth-1 delegates.
- Binding each delegated token to the delegate's own key
  ({{delegated-exchange}}) confines a compromised delegate to its own
  credential.
- Short derived-token lifetimes ({{issuance-gating}}), and marking
  delegable only the entries that need delegation, keep it small.

Audience replay into the exchange is a distinct path: a Mission-bound
token obtained by or issued to one party, presented as a
`subject_token`, could be exchanged for a fresh delegated credential
bound to the presenter. The following gates bound it:

- the exchange is a derivation gated on Mission state;
- the AS applies delegation-authorization policy at every exchange
  ({{delegation-constraints}});
- the result is bound to the authenticated delegate's own key and
  narrowed by the subset rule; and
- a no-actor exchange is accepted only from the Mission's approved
  agent ({{self-exchange}}).

Designation ({{designation}}) closes the remaining gap: a delegated
exchange accepts only a designation naming the authenticated
requesting client, which only the token's holder obtains, by proving
possession of the token's key, so a token obtained from an audience is
refused there.
Sender-constraining the primary token ({{token-claims}})
likewise keeps a stolen token from being designated or
self-exchanged.

### Client Attribution and Delegation Lineage {#client-id-misattribution}

Because this document keeps the ordinary {{RFC9068}} meaning of the
`client_id` claim ({{client-id-rebinding}}), a generic {{RFC9068}}
resource server, or a logging, SIEM, or audit pipeline, that keys
attribution on `client_id` attributes a Mission-derived token,
delegated or not, to the correct requesting client. Such a component
cannot see the delegation lineage in the `act` chain
({{delegated-exchange}}) or the Mission's originally-approved agent,
which is recorded in the Mission Record ({{mission-record}}), not in
`client_id`.

An existing component that authorizes or logs solely from `client_id`
needs review for this gap before it receives delegated Mission-bound
tokens; {{rs-enforcement}} states what a resource server may not infer
or route on `client_id`.

### Signing and Key Rotation {#key-rotation}

The `mission` claim and `authorization_details` are covered by the
AS's signature on the {{RFC9068}} JWT, so their integrity reduces to
the AS's signing key, whose publication and rotation
{{token-claims}} specifies.

Verification for audit outlives validity: keeping a key resolvable for
the audit horizon ({{record-provenance-members}}) of every Mission
whose tokens it
signed lets an auditor verify those tokens later. A companion that
anchors a longer-lived artifact to the same keys (a status assertion, a
Mandate, registered evidence) states its own retention bound.

Revocation for a known or suspected compromise is distinct from routine
retirement: the issuer publishes the compromised key as revoked, or
marks it with a compromise time, rather than only rotating it out.

A compromised issuer signing key voids every guarantee the signature
carries. Holding issuer signing keys in non-exportable, HSM- or
KMS-grade custody with dual-controlled generation reduces that risk.

Segmenting keys by artifact class under distinct `kid` values within
the one `jwks_uri` lets high-value, low-volume signing (long-lived
evidence and portable artifacts) sit under stricter custody than
high-volume token signing. Verification is `kid`-indexed, so this needs
no wire change.

## Composition and Residual Authority {#sec-composition}

### Compromised or Over-Broad Derivation {#compromised-or-over-broad-derivation}

The AS is trusted to derive authority no broader than the Mission
Intent. Both Authority Set derivation modes
({{authorization-derivation}}), a proposal narrowed to policy and a
configured mapping, are mechanical rather than free-form inference.
The recorded `policy_version` makes each Authority Set derivation
auditable by naming the policy it ran under.

### Authority Hash and Mission Identity {#authority-hash-is-not-a-mission-identifier}

`authority_hash` commits the approved Authority Set, not the Mission.
Two Missions that approve byte-identical authority (a successor that
re-approves the same Authority Set, or an unrelated Mission with the
same derived authority) share it while differing in `intent_hash`,
`approval_basis.consent_principal`, and `id`. {{integrity-anchors}}
therefore forbids its use as a Mission Identifier or as a replay or
idempotency key.

A consumer that needs to bind to or correlate a specific Mission uses
the Mission Identifier. A disclosed `authority_hash` is only an audit
correlator ({{rs-carried-authority}}).

### Composition and the Effective Ceiling {#composition-and-the-effective-ceiling}

Delegation depth ({{delegation-constraints}}) resets to 0 at each
cross-domain hop ({{I-D.draft-mcguinness-oauth-mission-cross-domain}})
and, where a deployment runs the child-delegation profile, at each child
generation ({{I-D.draft-mcguinness-oauth-mission-child-delegation}}).

The aggregate surface that a Mission's descendants can reach (the
product of delegation depth, the number of trust domains projected into,
and the number of child generations, each bounded independently) can
therefore exceed what a single approval appears to bound at consent
time. {{I-D.draft-mcguinness-mission-security-model}} analyzes this
composition, including why per-Mission child limits do not add up to a
lifetime total, and the child-delegation profile states how an
approval renders the subtree's figures
({{I-D.draft-mcguinness-oauth-mission-child-delegation}}). Where a
single approval's apparent bound must hold in practice, a deployment
can impose a global cap out of band.

Bounding aggregate consumption (calls, spend, or activity over the life
of a Mission and its descendants) is the metering profile's role
({{I-D.draft-mcguinness-mission-metering}}).

### Authority Materialized Before Containment {#the-containment-materialized-capability-residual}

Under the Mission Containment profile, a contain transition does not
reach authority materialized before it, such as a redeemed
cross-domain grant or a minted attenuation root, which operates for its
own remaining lifetime, as after revocation ({{revocation}}); that
profile states the residual and how short lifetimes bound it
({{I-D.draft-mcguinness-oauth-mission-containment}}, Section "The
Materialized-Capability Residual").

# Privacy Considerations {#privacy-considerations}

The privacy considerations of {{Section 13 of RFC9396}},
{{Section 8 of RFC9126}}, and {{Section 6 of RFC9068}} apply to this
document, as do those of {{Section 5 of RFC7662}} for introspection and
{{Section 6 of RFC8693}} for delegation.

A Mission Identifier is a correlation handle. A deployment limits
exposure by:

- giving stable Mission Identifiers only to parties that enforce,
  audit, or observe that Mission;
- preferring audience-scoped projections of authority where possible;
  and
- minimizing status and introspection disclosures to authorized
  callers ({{caller-authorization-and-minimization}}).

## Mission Identifier Correlation {#mission-identifier-correlation}

This document carries a single canonical Mission Identifier on every
derived token, and cross-domain projection
({{I-D.draft-mcguinness-oauth-mission-cross-domain}}) carries it across
trust domains unchanged. Any party that observes credentials for the
same Mission, whether a resource server, a Resource AS, or an auditor
spanning audiences, can correlate that activity by the Mission
Identifier, and `mission.issuer` further identifies the issuing AS.

That stable anchor lets a resource server, a cross-domain Resource AS,
and an auditor bind credentials and evidence to one approved Mission.
This document does not provide cross-audience unlinkability
({{non-goals}}).

Audience-pairwise (or request-pairwise) Mission references, in which
the issuer projects a distinct opaque identifier per audience and
resolves them server-side, are the fuller mechanism for unlinkability;
they work against the stable anchor, and this document does not define
them. A deployment that carries the canonical Mission Identifier on the
wire accepts this correlation.

## Token Payload Disclosure {#token-payload-disclosure}

The carried `constraints` and a multi-resource Authority Set disclose
the shape of the task and its business bounds (for example, an amount
ceiling) to every holder and every audience of a derived token.
Single-audience tokens, one per resource server, minimize this: each
carries only the entries the consuming resource server needs, as
{{Section 2.3 of RFC9700}} recommends ({{token-response}}).

## Intent Retention and Anchor Disclosure {#intent-retention-and-anchor-disclosure}

The Mission Record's Intent members (`goal`, `task_bounds`) are
personal-data sinks: they carry whatever task description the user
supplied, and their retention and erasure follow {{record-access}}.

The integrity anchors are unsalted commitments: a party holding a
candidate Intent can confirm it against `intent_hash`, and a candidate
proposal against `proposal_hash`. Over low-entropy or guessable content
each anchor is therefore a disclosure channel, and deployments treat it
as one when the Intent itself is sensitive.

## Third-Party Data Subjects {#third-party-data-subjects}

A task can be about a person who holds no Mission role: in a background
check, the employer's agent queries a registrar about a candidate who is
neither Subject nor Approver nor resource owner.

Mission approval records the accountable Approver's authorization of
the undertaking ({{approval-event}}). It is not, by itself, evidence of
such a person's consent to disclosure or of any other legal basis a
disclosure requires. Whether a basis is required, and what satisfies
it, is deployment and legal policy out of scope for this document.

Where the resource domain requires data-subject consent or another
basis, that domain's own lane (the resource server, a gateway, a policy
decision point, or an authorization server acting for the domain)
evaluates it through its own mechanisms, such as claims gathering or a
resource-domain consent artifact. That lane refuses access while
required evidence is absent or invalid, and Mission authority does not
override the refusal.

Mission authority is not the data subject's consent either. A Mission
Record can retain a verified consent reference or facts as
`submission_evidence` ({{mission-record}}); those facts are provenance
and policy input only, which the resource domain validates
independently under its current disclosure policy.

Third-party personal data can enter through any Intent, proposal,
authority, or recorded-evidence member:

- the prose members (`goal`, `task_bounds`) and `purpose`;
- `target_resources` and any explicit member a companion profile defines
  (for example, the metering companion's consumption bounds,
  {{I-D.draft-mcguinness-mission-metering}});
- any type-owned member of a proposed entry, and the derived Authority
  Set entries that reach tokens ({{mission-bound-tokens}}); and
- `submission_evidence` facts, including a consent reference.

Whatever the member, it:

- persists on the Mission Record for its audit horizon
  ({{record-provenance-members}});
- concentrates at the AS with the record ({{record-access}}); and
- if committed, is confirmable through the unsalted anchors by any
  party holding a candidate value
  ({{intent-retention-and-anchor-disclosure}}).

Referencing a third party through resource-scoped or pseudonymous
identifiers, rather than identifying prose, minimizes this exposure.
An opaque identifier is minimization, not anonymity, and personal-data
obligations follow it.

## Mission Record and Evidence Access {#record-access}

The Mission Record concentrates the task, its authority, and its
principals at the AS. Every evidence artifact joins on the Mission
Identifier, so the join is a correlation surface equal to the
identifier itself.

Tokens carry references and authority, not the record: this document
puts no `goal`, `task_bounds`, or other Intent content in a credential.
An Intent Submission Evidence artifact can carry personal data (an
originator identity, a consent reference); PAR keeps it off the front
channel, and the record retains the verified facts selected for
recording under the same access governance as the rest of the
Mission's evidence.

Access to the record and to Mission evidence is policy-governed and
auditable: reading a Mission's evidence is a privileged operation, not
a byproduct of holding a Mission reference. Retention and erasure are
deployment policy, bounded below by the audit horizon
({{record-provenance-members}}).

Where approval-event evidence was registered under the audit
transparency profile ({{I-D.draft-mcguinness-mission-audit}}), its
erasure record and data-subject-request basis are the
transparency-side mechanism. That mechanism records an erasure but
neither performs one nor overrides retention law, and it leaves the
operational Mission Record and its audit-horizon retention floor
untouched.

# Internationalization Considerations {#i18n}

Mission Intent prose (`goal`, `task_bounds`) is human-readable
disclosure. `goal_lang` ({{mission-intent}}) declares the
language of that prose as a BCP 47 language tag {{RFC5646}}, so an
approval surface can render, translate, or route it without guessing the
language.

Three rules apply to the declaration:

- `goal_lang` is a syntactic declaration: the AS checks only its
  well-formedness ({{mission-intent}}), not that the prose is in the
  declared language, so the tag is not a verified property of the text.
- Rendering to the Approver follows the rendering rules of
  {{rendering-safeguards}} unchanged: client prose stays inert text in
  any language and any script, including bidirectional text. Where the
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

- Parameter name: `mission_intent`
- Parameter usage location: authorization request
- Change controller: IETF
- Specification document(s): this document, {{submission-via-par}}

- Parameter name: `mission_id`
- Parameter usage location: token response
- Change controller: IETF
- Specification document(s): this document,
  {{mission-response-parameters}}

- Parameter name: `mission_error`
- Parameter usage location: token response
- Change controller: IETF
- Specification document(s): this document, {{issuance-gating}}

- Parameter name: `mission_expires_at`
- Parameter usage location: token response
- Change controller: IETF
- Specification document(s): this document,
  {{mission-response-parameters}}

PAR {{RFC9126}} carries authorization-request parameters without a
distinct usage location, so the pushed submission of `mission_intent`
needs no separate registration.

The `mission_error` member is carried in the token-endpoint error
response, for which "token response" is the registry's applicable usage
location. It uses the error response's JSON extensibility rather than
defining a new `error` code.

The `mission_denial` attribute uses the extensible auth-param space of
the `WWW-Authenticate` scheme ({{RFC6750}}, {{rs-enforcement}}), for
which no IANA registry exists; no action is required for it.

## OAuth Extensions Error Registration {#oauth-extensions-error-registration}

This document requests registration of the following in the "OAuth
Extensions Error" registry {{RFC6749}}:

- Error name: `invalid_mission_intent_evidence`
- Error usage location: authorization code grant error response,
  token error response
- Related protocol extension: Intent Submission Evidence
  ({{intent-submission-evidence}})
- Change controller: IETF
- Specification document(s): this document,
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

{{adjacent-work}} distinguishes this claim from similarly named claims
and concepts of adjacent work.

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
- a `Terminal` value of `no`, consistent with the transitions
  the registrant's specification defines (a `no` state admits a
  further transition; `terminated` is the one terminal state, and a
  further way for a Mission to end is a termination reason,
  {{iana-termination-reasons}}); and
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
| `terminated` | yes | The Mission has ended; its `termination` gives the reason. | IETF | this document, {{lifecycle}}, {{termination}} |
{: title="Mission Lifecycle States registry: initial contents"}

Each further document that defines a lifecycle state requests that
state's registration in its own IANA considerations. A Designated
Expert MUST reject a further state registered as terminal: a further
way for a Mission to end is a termination reason
({{iana-termination-reasons}}).

## Mission Termination Reasons Registry {#iana-termination-reasons}

IANA is requested to create the "Mission Termination Reasons"
registry. The registration policy is Specification Required
{{RFC8126}}.

A Designated Expert reviews a submission for:

- a `Value` matching `^[a-z][a-z0-9_]*$` not already registered;
- a `Semantics` sentence precise enough to distinguish the reason
  from every registered reason; and
- a `Members` list naming each further `termination` member the
  reason defines ({{termination}}) with its presence (REQUIRED,
  CONDITIONAL, or OPTIONAL).

A reason never makes a Mission available for reliance: every
`terminated` Mission is non-`active`, whatever its reason
({{lifecycle}}).

Each registration records:

- **Value**: the termination reason's string value.
- **Semantics**: one sentence stating how the Mission ended.
- **Members**: the further `termination` members, or "none".
- **Change Controller**: IETF, or the registrant for any other
  registration.
- **Reference**: the specification defining the reason.

This document seeds the registry with the reasons it defines:

| Value | Semantics | Members | Change Controller | Reference |
|---|---|---|---|---|
| `revoked` | An authorized party revoked the Mission, or the deployment's policy terminated it ({{revocation}}). | none | IETF | this document, {{termination}} |
| `expired` | The Mission's `expires_at` passed; `terminated_at` equals it. | none | IETF | this document, {{termination}} |
{: title="Mission Termination Reasons registry: initial contents"}

Each further document that defines a termination reason requests
that reason's registration in its own IANA considerations.

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

This appendix follows one Mission in a single trust domain through
Mission creation, token issuance, resource server enforcement, a
refusal, and revocation. It is illustrative and adds no requirements.
The OAuth steps follow
this document; the identity setup follows
{{I-D.draft-ietf-wimse-aims}}. Identifiers are illustrative; the hash
values are computed over the displayed objects
({{integrity-anchors}}).

The OAuth flow of Stages 1 to 4, and the revocation in Stage 5, use
only this document and the `mission_resource_access` type
({{I-D.draft-mcguinness-oauth-mission-resource-access}}): the
baseline issuance path, with enforcement from the token alone,
bounded by token lifetime. Text marked as a
companion variation shows what an optional companion adds to the same
Mission, and the timeline ({{e2e-timeline}}) lists both.

Scenario: agent `s6BhdRkqt3`, acting for `alice`
(`user_3p2q8mN1a0kV7tR`), reconciles Q3 invoices in the home ERP
under Mission `msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-`.

## Stage 0: Agent Identity (by Reference) {#stage-0-agent-identity-by-reference}

The agent is an OAuth client with a workload identity, for example
one established using WIMSE {{I-D.draft-ietf-wimse-arch}} or SPIFFE
{{I-D.draft-ietf-oauth-spiffe-client-auth}}. `alice` has delegated to
it through an ordinary authorization code flow, per
{{I-D.draft-ietf-wimse-aims}}: the `client_id` claim names the agent,
and the `sub` claim identifies `alice`. This document adds the
Mission layer to that identity; Stage 0 is otherwise unchanged from
that specification.

## Stage 1: Mission Creation {#stage-1-mission-creation}

The following example shows the Submission envelope the agent pushes
through PAR ({{submission-via-par}}), carrying the Mission Intent and
no evidence:

~~~ json
=============== NOTE: '\' line wrapping per RFC 8792 ===============

{
  "intent": {
    "goal": "Reconcile Q3 invoices and post adjustments of at most \
      USD 500 per journal entry.",
    "target_resources": ["https://erp.example.com"],
    "task_bounds": [
      "Read only invoices issued in 2026-Q3.",
      "Post journal entries of at most USD 500 each."
    ],
    "purpose": "urn:example:purpose:reconcile",
    "expires_at": "2026-12-31T23:59:59Z"
  }
}
~~~

In the same push, the agent proposes concrete authority on the
`authorization_details` parameter ({{authority-proposal}}):

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

Both are parameters of one pushed authorization request
({{RFC9126}}), with PKCE ({{RFC7636}}); client authentication is
omitted, and extra line breaks are for display purposes only:

~~~
POST /par HTTP/1.1
Host: as.example.com
Content-Type: application/x-www-form-urlencoded

response_type=code
&client_id=s6BhdRkqt3
&redirect_uri=https%3A%2F%2Fagent.example.com%2Fcb
&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
&code_challenge_method=S256
&mission_intent=%7B%22intent%22%3A%7B%22goal%22%3A%22Reconcile...
&authorization_details=%5B%7B%22type%22%3A%22mission_resource_acc...
~~~

The AS returns a `request_uri`:

~~~
HTTP/1.1 201 Created
Content-Type: application/json
Cache-Control: no-store

{
  "request_uri": "urn:ietf:params:oauth:request_uri:6esc_11ACC5bwc",
  "expires_in": 60
}
~~~

and the agent sends `alice`'s user agent to the authorization
endpoint with it:

~~~
GET /authorize?client_id=s6BhdRkqt3&request_uri=urn%3Aietf%3Aparams
  %3Aoauth%3Arequest_uri%3A6esc_11ACC5bwc HTTP/1.1
Host: as.example.com
~~~

The AS (`as.example.com`) validates both, derives this Authority Set
under a declared `narrowing` capability (each entry a same-type subset
of a proposed entry, {{authority-proposal}},
{{transformation-capabilities}}), and renders it for `alice`'s
consent:

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

`alice` approves at 08:00:00 UTC on 2026-11-02, and the AS records
Mission `msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-` in the `active` state
with `authority_hash`
`sha-256:hjXlwWBY64-RPs1Z-E_gbyklNcViI5c9jiyMbE4KvFM`,
`intent_hash`
`sha-256:6T-7s_f-mNW9UpfrrZh3r0HRJmU4My_EsNAf1C1U4r0`, and
`proposal_hash`
`sha-256:p-s-EzdNQTn6RoPHXESkwVtGdk8yL1PxryNyMwroKGo`.

## Stage 2: Mission-Bound Token Issuance {#stage-2-mission-bound-token-issuance}

At 08:00:05 the agent redeems the authorization code with its PKCE
verifier and a DPoP proof ({{RFC9449}}):

~~~
POST /token HTTP/1.1
Host: as.example.com
Content-Type: application/x-www-form-urlencoded
DPoP: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2Iiwi...

grant_type=authorization_code
&code=SplxlOBeZQQYbYS6WxSbIA
&redirect_uri=https%3A%2F%2Fagent.example.com%2Fcb
&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
~~~

The AS resolves the Mission from the grant
({{grant-binding-resolution}}), checks that it is `active`
({{issuance-gating}}), and issues a Mission-bound access token for the
ERP and a refresh token. The token response carries the granted
`authorization_details` echo ({{token-response}}) and the
`mission_id` and `mission_expires_at` response parameters
({{mission-response-parameters}}):

~~~ json
{
  "access_token": "eyJhbGciOiJFUzI1NiIsInR5cCI6ImF0K2p3dCJ9...",
  "token_type": "DPoP",
  "expires_in": 300,
  "refresh_token": "rt_4mN8qV2xP7sL1tY9zB3k",
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

The following is an example of the decoded access token payload:

~~~ json
{
  "iss": "https://as.example.com",
  "sub": "user_3p2q8mN1a0kV7tR",
  "aud": "https://erp.example.com",
  "client_id": "s6BhdRkqt3",
  "iat": 1793606405,
  "exp": 1793606705,
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

The token's `authorization_details` claim carries the same two entries
as the token response's echo. The token carries everything enforcement
needs: the audience, the sender constraint (the `cnf` claim), the
authority with its constraints, and the `mission` claim naming the
Mission it was derived under. Its 300-second lifetime ends well
before the Mission's `expires_at`. Revoking the Mission stops further
derivation, but this token remains valid until its own `exp`
({{revocation}}).

## Stage 3: Resource Server Enforcement {#stage-3-the-resource-server-enforces}

The agent calls the ERP resource server (`erp.example.com`) with that
token. The resource server:

- validates the JWT and verifies the request's DPoP proof against the
  key identified by the token's `cnf` claim;
- enforces the `authorization_details` entries whose `resource`
  matches the operation target, `https://erp.example.com`,
  permitting `invoices.read` within the Q3 issuance window and
  `journal-entries.write` up to the `max_amount` ceiling of 500.00
  USD ({{rs-enforcement}}); and
- treats the `mission` claim as audit and correlation context, making
  no call to the AS.

With enforcement from the token alone, the consequential
`journal-entries.write` is bounded only by token lifetime and the
carried constraints.

At 08:14:00 the agent refreshes for a write-only token, narrowed to
the `journal-entries.write` entry, as the refresh example in
{{token-response}} narrows to the read entry.

Companion variation (runtime enforcement): where the deployment runs
the runtime profile ({{I-D.draft-mcguinness-mission-runtime}}), the
resource server also obtains a point-of-use permit against current
Mission state from a policy decision point before executing the
write. The AuthZEN profile's worked request
({{I-D.draft-mcguinness-mission-authzen}}) is that check for a 423.50
USD posting at 08:14:03, made with that write-only token.

Companion variation (cross-domain): the end-to-end example of the
Mission Cross-Domain Projection profile
({{I-D.draft-mcguinness-oauth-mission-cross-domain}}) follows a
Mission like this one whose authority also covers a partner ERP in
another trust domain.

## Stage 4: Resource Server Refusal {#stage-4-the-resource-server-refuses}

The agent then asks the ERP to post a 780.00 USD adjustment with the
same write-only token. The amount exceeds the entry's `max_amount` of
500.00 USD, so the ERP refuses it from the token alone as outside the
carried authority ({{rs-enforcement}}). This deployment accepts the
agent learning that more authority needs a new approval or an
expansion ({{denial-disclosure}}), so the challenge carries
`mission_denial`:

~~~
HTTP/1.1 403 Forbidden
WWW-Authenticate: DPoP error="insufficient_scope",
  mission_denial="insufficient_authority"
~~~

A fresh token from the same Mission does not help: every token it
derives is a subset of the same Authority Set ({{subset}}).

## Stage 5: Suspension, Resumption, and Revocation {#stage-5-suspension-resumption-and-revocation}

Suspension and resumption are Mission Status operations, shown in its
companion variation below.

At 08:50:00 the agent refreshes for the read-only token of the
refresh example in {{token-response}}, which expires at 08:55:00.

At 08:53:20 the Mission is revoked, and the AS commits `terminated`
with reason `revoked`. Revocation stops the Mission at the issuer
({{revocation}}). A later refresh is refused with the `mission_error`
diagnostic ({{issuance-gating}}):

~~~
HTTP/1.1 400 Bad Request
Content-Type: application/json
Cache-Control: no-store

{
  "error": "invalid_grant",
  "mission_error": "revoked"
}
~~~

Introspection reports the 08:50:00 token inactive with the Mission's
termination, although the token has not expired ({{examples}},
{{composite-active}}).

Revocation does not recall the token already issued. The ERP,
enforcing from the token alone, can honor the read-only token until
its `exp` at 08:55:00. A resource server that introspects at the
issuer on every request stops honoring it on its next request.

Companion variations:

- **Mission Status** ({{I-D.draft-mcguinness-oauth-mission-status}}).
  The Mission is created at state version 1, suspended at 08:20:00
  and resumed at 08:30:00 (state versions 2 and 3) through the
  profile's lifecycle operations, and the AS derives nothing in
  between ({{lifecycle}}). The revocation at 08:53:20 is the agent's
  own `revoke` operation, with the reason "Quarterly reconcile
  cancelled", under an explicit lifecycle authorization the
  deployment grants it for this Mission; its resource tokens and
  refresh token confer no such authority. The AS commits it as state
  version 4.
- **Mission Signals**
  ({{I-D.draft-mcguinness-oauth-mission-signals}}). A receiver learns
  of the revocation from a Security Event Token.
- **Runtime enforcement** ({{I-D.draft-mcguinness-mission-runtime}}).
  A resource server that obtains a point-of-use permit stops honoring
  the token within that deployment's declared freshness and permit
  bounds, since a permit can rest on a state observation taken before
  the revocation.

## Timeline {#e2e-timeline}

All times are 2026-11-02 UTC. The rows marked with a companion occur
only where that companion is deployed.

| Time | Event | Defined by |
| --- | --- | --- |
| 08:00:00 | `alice` approves; the AS creates the Mission | this document |
| 08:00:05 | The agent redeems the code; the access token expires at 08:05:05 | this document |
| 08:14:00 | The agent refreshes for a write-only token | this document |
| 08:14:03 | A point-of-use permit for a 423.50 USD posting | runtime profile (AuthZEN) |
| 08:20:00, 08:30:00 | The Mission is suspended, then resumed | Mission Status |
| 08:50:00 | The agent refreshes for a read-only token that expires at 08:55:00 | this document |
| 08:53:20 | The Mission is revoked and `terminated`; later refreshes are refused, and introspection reports the read-only token inactive | this document |
| After revocation; delivery time unspecified | A receiver learns of the revocation from a Security Event Token | Mission Signals |
| 08:55:00 | The read-only token expires; a resource server enforcing from the token alone stops honoring it | this document |
{: title="End-to-end example timeline"}

# Design Context and Boundaries {#design-context}

This appendix explains the design choices behind the Mission and
records what this document leaves to other work.

## Relationship to Existing OAuth Objects {#why-a-new-object}

OAuth already has objects near this need, but none is the approved
task:

- A `scope` value or an `authorization_details` entry
  ({{RFC9396}}) expresses authority but neither the task it serves
  nor a lifecycle of its own.
- An access token is a short-lived projection; its `jti` claim
  identifies the token, not the task.
- A refresh token preserves the ability to obtain further tokens but
  commits no bounded, approved authority.
- A consent record proves that an approval event happened; it does
  not govern the resulting work as it continues.

The Mission is the durable object these project from: the approved
task that bounds and outlives them and that every derived token
refers back to. It is not another `authorization_details` type, since
Rich Authorization Requests already express authority; it is the
approved task with a lifecycle, which an Authority Set is derived for
and gated by.

## Relationship to Adjacent Work {#adjacent-work}

A grant, in the sense of FAPI Grant Management {{FAPI.GrantManagement}},
is a durable, queryable, revocable container of consented
authorization data, with no task, integrity commitment, or
derivation gating. A deployment can
surface Mission revocation through a grant-management-style API
({{revocation}}).

This document specifies the issuance and governance layer that
agent-identity work for OAuth leaves unspecified.
{{I-D.draft-ietf-wimse-aims}} names the agent's mission and leaves its
translation into authorization requirements out of scope. This
document specifies that translation and reuses its assignments
unchanged: the agent is the client, and the delegating principal is
the token `sub` ({{principal-model}}). An agent authenticated and
delegated per that document uses these mechanisms to obtain
Mission-bound tokens.

The `mission` claim ({{mission-claim}}) references a Mission, the
authorization object this document defines. It is distinct from
AAuth's `mission_s256` claim ({{I-D.draft-hardt-oauth-aauth-protocol}}),
the SHA-256 digest that identifies an AAuth mission, and from the
agent's mission that {{I-D.draft-ietf-wimse-aims}} names, the purpose
this document translates into authorization. The two claim names do
not collide in the JSON Web Token Claims registry
({{json-web-token-claims-registration}}).

Decision-layer access-request and approval workflows, such as the
OpenID AuthZEN Access Request and Approval Profile {{AuthZEN.ARAP}},
manage approval tasks but do not tie an approval to token issuance.
This document supplies the issuance-bound object such workflows
complete into.

Nearby individual proposals each carry one Mission property without
the others:

- task-linked Rich Authorization Requests with revocation webhooks
  carry a task link;
- intent-digest admission assertions carry an intent commitment; and
- offline capability attenuation
  ({{I-D.draft-niyikiza-oauth-attenuating-agent-tokens}}) carries
  offline narrowing.

None combines the durable approved object, state-gated issuance, and
integrity anchors this document defines.

The Grant Negotiation and Authorization Protocol {{RFC9635}} covers
much of the same design space: a continuable authorization request,
richer client instance identification, and native delegation. Rather
than a new grant protocol, endpoints, and client machinery, this
document uses deployed OAuth 2.0 surfaces: Pushed Authorization
Requests ({{RFC9126}}), Rich Authorization Requests ({{RFC9396}}),
DPoP ({{RFC9449}}), and {{RFC9068}} access tokens. A deployment that
runs PAR, RAR, and sender-constrained tokens adopts the Mission model
without a GNAP grant endpoint or migrating its clients to GNAP.

The Authority Set's subset rule ({{subset}}) follows capability
systems in which a holder narrows what it passes on without
contacting an issuer: macaroons' caveat narrowing, Biscuit's
offline attenuation blocks, UCAN's delegation chains, SPKI/SDSI's
local-name reduction, and object-capability designs generally.

In this document, narrowing applies to a durable,
approval-anchored object that its issuer can revoke for the Mission's
full lifetime, not a bearer credential bounded only by its caveats.
Revoking the Mission therefore still reaches everything derived from
it that has not already left the issuer's reach ({{revocation}}).

## Missions, Plans, and Execution {#the-mission-the-plan-and-execution}

The Mission is the durable, AS-held object that commits the approved
authority and owns the task's lifecycle. Two related things an agent
produces around a task draw on the Mission's authority but carry none
of their own and never enlarge it.

The agent's **plan** (how it decomposes the task, chooses tools, and
delegates to sub-agents) is its own strategy and is out of scope. It
grants nothing: a sub-agent's authority is carried on its delegated
token ({{delegation}}), derived from the Mission and only narrowed
from it ({{subset}}).

The agent's **execution** (the tokens it derives, the calls it makes,
and the decisions taken on them) references the Mission but cannot
expand it. Revoking the Mission stops further derivation
({{issuance-gating}}) but does not undo completed actions. Evaluating
each action against the Mission at the point of use is the runtime
layer's concern ({{runtime-boundary}}).

How a client produces the Intent (for example, a "Mission Shaper"
deriving it from a natural-language instruction) is out of scope.

## Scope and Future Work {#scope-and-future-work}

This document is self-contained: it binds Missions to OAuth 2.0 and
depends normatively only on the specifications listed as its
normative references.

Its reference to the OAuth Actor Profile
({{I-D.draft-mcguinness-oauth-actor-profile}}), for the `act` chain
shape the optional Delegation capability uses, is normative and binds
only a deployment that claims Delegation, so the mandatory
single-domain core does not depend on it.

The companion Mission Cross-Domain Projection profile
{{I-D.draft-mcguinness-oauth-mission-cross-domain}} specifies
cross-domain projection, a single hop that lets an authorization
server in another trust domain honor a Mission, and carries the
identity-chaining and Identity Assertion JWT Authorization Grant
(ID-JAG) dependencies. The Cross-Domain
capability's conformance bar is self-contained in this document
({{conformance}}), so that companion is not a normative dependency.

Optional companion profiles, not required to implement this
document, specify:

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
- an optional Authority Set derivation profile for a vertical that
  wants cross-vendor agreement on what a task authorizes: a registry
  of standard task types mapped to authority templates, so that two
  vendors in that profile derive comparable Authority Sets. This
  document does not standardize the Authority Set derivation
  algorithm ({{authorization-derivation}}).

This document defines no mechanism that pins a Mission to an
approved agent deployment class or version, and reserves no Intent
member for one. Such a pin needs two objects, not one Intent member:
a committed approval-context pin, and presenter-instance
evidence checked at every derivation (for example, using
{{I-D.draft-mcguinness-oauth-client-instance-id}} and
{{I-D.draft-mcguinness-oauth-client-attesters}}). A profile that
defines the pin also defines:

- its request carriage and resolution to an approved deployment
  identifier;
- its Mission Record extension and approval rendering; and
- its fail-closed behavior when the client cannot prove the pin.

This document defines no cumulative consumption bounds (for example,
a budget, call-count, or activity-duration cap). An experimental
companion ({{I-D.draft-mcguinness-mission-metering}}) defines them as
explicit Mission Intent extension members, together with the runtime
metering that enforces them.

## Non-Goals {#non-goals}

The following are out of scope for this document:

- **Semantic / intent verification.** This document does not evaluate
  whether a runtime action serves the Mission's purpose beyond
  matching the approved `authorization_details` and `constraints`;
  per-action evaluation is the runtime layer's role
  ({{runtime-boundary}}). Verifying an agent's declared reasoning
  against the task is a further attestation problem outside both
  layers.
- **Joint outcome and cross-resource effects.** Whether the actions
  taken under a Mission jointly accomplish its task is out of scope,
  as are the ordering, timing, atomicity, and compensation of their
  effects across resource servers. The `mission` claim joins requests
  to an approval for issuance and audit; it does not identify a
  business transaction.
- **Approval-free authorization upgrade.** The Authority Set is
  committed at approval, and this document defines no mid-stream
  widening that bypasses consent. Widening requires a new approval, a
  successor Mission, as specified by Mission Expansion
  {{I-D.draft-mcguinness-oauth-mission-expansion}}.
- **Lifecycle event distribution.** A resource server learns Mission
  state from the token lifetime or optional introspection
  ({{introspection}}); this document defines no push-based
  notification of Mission state changes. Mission Lifecycle Signals
  ({{I-D.draft-mcguinness-oauth-mission-signals}}) specifies a Shared
  Signals and CAEP profile for Mission lifecycle events, delivered as
  Security Event Tokens ({{RFC8935}}).
- **Human-in-the-loop suspension.** The base lifecycle is `active` and
  `terminated` ({{lifecycle}}). Mission Status
  ({{I-D.draft-mcguinness-oauth-mission-status}}) defines a
  `suspended` state with `resume`/`complete` transitions as an
  optional extension. A pending-human-approval state and a
  holding-token pause-and-resume protocol are future lifecycle work.
- **Multi-hop cross-domain projection.** Cross-Domain Projection
  ({{I-D.draft-mcguinness-oauth-mission-cross-domain}}) specifies a
  single projection hop. Mission Cross-Organizational Delegation
  ({{I-D.draft-mcguinness-oauth-mission-cross-org-delegation}})
  profiles recursive delegation across organizations; a destination
  verifies that delegation chain before projecting. Re-projecting a
  Mission from one Resource AS into a further domain is future work.
- **Decentralized agent identity.** Agent identity and credentialing
  are out of scope ({{I-D.draft-ietf-wimse-aims}} and the WIMSE
  architecture, {{I-D.draft-ietf-wimse-arch}}); this document governs
  the approved-task artifact those identities act within, not the
  identities themselves.
- **Cross-audience unlinkability.** A single canonical Mission
  Identifier lets any party holding a token correlate a Mission's
  activity across audiences and resources. `authority_hash` is not
  part of that baseline correlation surface: it stays on the Mission
  Record and the audit and profile surfaces that carry it by
  disclosure privilege ({{mission-claim}},
  {{caller-authorization-and-minimization}}), not on every token by
  default. Pairwise or unlinkable presentation of Mission-bound
  authority works against the identifier and is therefore future work
  ({{mission-identifier-correlation}}).

## Client Identification in Delegated Tokens {#client-id-rebinding}

This document keeps the registered meaning of the `client_id` claim,
stated normatively in {{token-claims}} and enforced in
{{rs-enforcement}}: the OAuth client that requested the token, on
every issued or derived token, a delegated one included. Downstream
delegates are named in the `act` chain ({{delegated-exchange}}), and the
Mission's originally-approved agent remains recorded in the Mission
Record ({{mission-record}}).

The alternative, fixing `client_id` to the approved agent on every
derived token, would lead a generic {{RFC9068}} resource server or
logging pipeline to misattribute a delegate's action to the approved
agent, with no error to surface the mismatch. It would be safe only
where every resource server already processes the `act` chain, and
Mission awareness alone does not establish that
({{rs-mission-unaware}}).

The routing rule of {{rs-enforcement}} does not depend on this
choice. The `mission` claim's presence signals that a token may carry
an `act` chain a consumer needs to process. A Mission-unaware
resource server cannot opt into that processing, so routing a
delegated token to one is forbidden.

# Role Mapping {#role-mapping}

`approval_basis` separates three questions about a Mission's own
creation, which a scenario can assign to different principals:

- who is accountable for it (`consent_principal`);
- who or what triggered it (`activation_actor`); and
- what decided it (`adjudication`).

The companion profiles cited below define the scenarios; the list
shows how each assigns the three roles: its accountability root
(`consent_principal`), activation actor (`activation_actor`), and
adjudication (where a profile or deployment populates it).

Direct approval:
: - Accountability root: The approving human
  - Activation actor: Equal to `consent_principal`: the Approver
    triggers their own approval
  - Adjudication: `kind: human`; the deciding human is
    `consent_principal` itself

Relocated human approval ({{I-D.draft-mcguinness-oauth-mission-approval}}):
: - Accountability root: The human who completes the relocated approval
    event
  - Activation actor: Equal to `consent_principal`, unchanged from the
    direct case: the instance activates at that human's decision, not at
    any earlier submission
  - Adjudication: `kind: human`, as direct

Template dispatch ({{I-D.draft-mcguinness-oauth-mission-template}}):
: - Accountability root: The template's human approver, fixed at
    template creation
  - Activation actor: The Dispatcher that requested the Dispatch,
    distinct from `consent_principal`
  - Adjudication: `kind: policy`, `policy` naming the template's
    `dispatch_policy` `id` and `version` (already carried in the
    dispatched Mission's `template` lineage member), never the
    Template's own `id`/`template_version` nor the Dispatcher

Policy drawdown ({{I-D.draft-mcguinness-oauth-mission-child-delegation}}):
: - Accountability root: The Parent Mission's human Approver
  - Activation actor: The requesting parent Agent, distinct from
    `consent_principal`
  - Adjudication: `kind: policy`, naming the child-creation policy's
    `id`/`version` where the entry carries one, otherwise the Parent
    Mission's approved delegation entry; never the requesting parent
    Agent

Ceiling drawdown ({{I-D.draft-mcguinness-oauth-mission-progressive}}):
: - Accountability root: The Approver who consented the ceiling
  - Activation actor: The requesting client, distinct from
    `consent_principal`
  - Adjudication: `kind: policy`, naming the drawdown policy's
    `policy_id`/`policy_version` carried in `activation`; never the
    requesting client

Governed policy approval ({{I-D.draft-mcguinness-mission-approval-governance}}):
: - Accountability root: The human who approved the exact policy version
    the instance activates under
  - Activation actor: The authenticated client that requested the
    activation, distinct from `consent_principal`
  - Adjudication: `kind: policy`, `policy` naming the deciding policy's
    `id`/`version` (the approved policy itself or the evaluator it
    commits), with `governance_record: true`; never the requesting
    client

AGR-backed direct approval ({{I-D.draft-mcguinness-mission-approval-governance}}):
: - Accountability root: The approving human, whose own `human`
    assertion is the Approval Governance Record's accountable assertion
  - Activation actor: Equal to `consent_principal`, as for direct
    approval
  - Adjudication: `kind: human`, `governance_record: true`; how other
    assertions contribute is Approval Governance's

AGR-backed template or drawdown activation ({{I-D.draft-mcguinness-mission-approval-governance}}):
: - Accountability root: Unchanged from the underlying basis, whose
    `approval_basis` stands in for an accountable assertion
  - Activation actor: Unchanged from the underlying basis
  - Adjudication: `kind: policy`, as the underlying basis assigns it,
    with `governance_record: true`; the full assertion set is never
    collapsed into a single principal

Direct approval is the degenerate case where one human fills every
role. Where a profile or deployment does not populate `adjudication`
({{mission-record}}), the list shows the value it would carry.

# Derivation Policy {#derivation-policy}

This appendix is illustrative and adds no requirements. It
describes an authoring artifact for the contract in
{{authorization-derivation}}, not a standardized policy language or an
alternative subset relation.

## Policy Artifact {#derivation-policy-artifact}

A deployment retains a versioned derivation policy with its ceiling,
configured mappings, and issuance limits. Its inputs include:

- a validated Mission Intent;
- the client's authority proposal in narrowing mode, or configured
  candidates when there is no proposal;
- the applicable authority source ceiling;
- the capability catalog's per-action properties; and
- any recorded model output.

The output is the Authority Set committed by `authority_hash`, and
`policy_version` identifies the policy used.

Reproducing an Authority Set derivation requires the same inputs and
the retained policy and catalog versions, not just the identifier of
a mutable configuration. Replay uses a model's retained output and
never reruns the model. Authority Set derivation is mechanical: a
model may suggest an Intent or a proposal, or contribute a recorded
input that refuses or narrows, but does not make the approval-time
narrowing decision.

## Derivation Policy Properties {#derivation-policy-properties}

The five properties below restate, for a policy author, what
{{authorization-derivation}} and the rules it cites require.

- **Deterministic.** The same Intent, proposal, ceiling, catalog, and
  recorded model output derive the same Authority Set, so
  `policy_version` can serve as an audit correlator
  ({{authorization-derivation}}).
- **Narrowing only.** Every derived entry is a subset of some proposed
  entry of the same type, under that type's own relation
  ({{authority-proposal}}, {{subset}}); in configured-mapping mode the
  configured candidates supply that comparison input. Retaining fewer
  JSON fields is not narrowing: dropping a restriction can grant more.
  Where the relation cannot decide because two bounds are
  incomparable, the result is conservative refusal ({{subset}}). For
  `mission_resource_access`, two amount caps naming different
  currencies have no intersection, with no implicit conversion and no
  "ceiling wins" exception;
  {{I-D.draft-mcguinness-oauth-mission-resource-access}} defines the
  Common Constraints and their intersection rules.
- **Refusal over silent drop.** An entry of an unsupported type, an
  entry that fails its schema, and an entry carrying a constraint the
  engine cannot compare, whether registered or deployment-defined,
  are refused ({{authority-proposal}}, {{subset}}, {{error-mapping}}).
  Authority Set derivation does not repair them by omitting the entry
  or dropping the constraint. An entry the
  engine compares but policy cannot accept differs: it is narrowed,
  under a declared `narrowing` capability
  ({{transformation-capabilities}}), or omitted, and the granted echo
  reflects that ({{authority-proposal}}).
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
  the ordinary direction. Where the ceiling's eligibility defers to the
  issuer's delegation policy (no `allowed_delegates`), a proposed list
  only restricts that policy's decision and never replaces it
  ({{I-D.draft-mcguinness-oauth-mission-resource-access}}).

## Derivation Rule Example {#derivation-rule-example}

The following example uses a catalog whose read actions supply no amount
for a cap to compare against, while a journal write does. The ceiling
separates those actions:

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

Under a declared `narrowing` capability
({{transformation-capabilities}}), the resulting Authority Set
contains the proposed `invoices.read` entry unchanged, and the
proposed `journal-entries.write` entry with `max_amount` narrowed to
`500.00 USD`. The ceiling's unrequested `journal-entries.read` does
not appear. Each proposed entry intersects the same-resource ceiling
entries; an empty action intersection contributes no authority.

Negative fixtures accompany this positive result; none is a special
case that relaxes the type's relation:

- A single mixed read and write proposal carrying the amount cap is
  refused at intake: the read supplies no amount for the cap to
  compare against, and Authority Set derivation does not drop the cap
  from the read fragment.
- A write proposal naming a different currency cannot produce the USD
  intersection shown.
- A proposal carrying a Common Constraint this deployment does not
  compare is refused with the `invalid_authorization_details` error
  code ({{error-mapping}}), not derived with the constraint dropped.

## Fixtures and Authoring Discipline

Versioned Intent and proposal fixtures with expected Authority Sets
make the optional publication in {{authorization-derivation}}
concrete. Reviewing their diffs on every policy change exposes
altered grants before approval.

Fixtures cover normal template and narrowing outcomes, empty
intersections, unknown constraints, incomparable values, and
attempts to introduce delegation. They check each subset against
both the proposal and the ceiling.

A further check runs the shipped configuration through intake,
Authority Set derivation, and a real decision path, since a
configuration that loads does not thereby authorize its intended
workload. Applying the same entry checks at configuration load and at
client intake keeps those two surfaces from disagreeing.

## Ownership and Operational Signals

| Artifact | Owner | Responsibility |
|---|---|---|
| Derivation policy, ceilings, versions and issuance limits | Mission Issuer operator | Outer bounds and reproducible approval-time Authority Set derivation |
| Capability catalog and action properties | Resource owner or service team | Supported operations and the facts their constraints can evaluate |
| Templates and configured mappings | Template author within issuer policy | Candidate authority for supported Intent shapes |
{: title="Ownership and operational signals"}

Templates amortize authoring across Missions and do not bypass the
ceilings. The unmapped-resource rate, template-hit rate, and
rule-exception rate show an operator where its policy authoring
remains incomplete.

# Integrity Anchor Test Vectors {#test-vectors}

These non-normative vectors let an implementation verify its anchor
computation ({{integrity-anchors}}, {{canonicalization}}) byte for
byte. All use the issuer `https://as.example.com`.

Each canonical-bytes block is the exact JCS {{RFC8785}} output: a
single line of UTF-8 with no whitespace outside string values. It is
wrapped here for layout only; removing the line breaks, and adding no
characters, recovers the canonical form.

JCS sorts object member names and preserves array order. In these
vectors, `iss` precedes `typ` precedes `value`; within an entry,
`actions` precedes `constraints` precedes `resource` precedes `type`;
and within `max_amount`, `amount` precedes `currency`.

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
`delegation.allowed_delegates` is an array of matcher objects. JCS
preserves the array's order, so the `sub_profile` matcher stays
before the `sub` matcher.

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
an issued or narrowed token projection.

The entry commitment, over this entry as the envelope `value` with
`typ` `mission-authority-entry`:

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

Canonical bytes of the envelope:

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

<!-- assessed-substrate-digest: 72008afead28043e -->

This appendix is this document's Mapping Assessment of itself against
the kernel and capabilities of the Mission Substrate contract (the
"Mission Substrate Statement" section of
{{I-D.draft-mcguinness-mission-substrate}}). It describes, in the
Statement's form, how the surfaces this document defines realize that
vocabulary.

The assessment is informative and adds no requirement: {{conformance}}
alone defines conformance to this document. This document publishes
no Mission Substrate Statement, makes no substrate-conformance claim,
and takes no requirement from the substrate; each document references
the other informatively.

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
   `expires_at`, the issuer materializing the resulting `terminated`
   transition, reason `expired`, lazily where it chooses; any other
   stored value, recognized or not, is non-active; transitions are authenticated
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

The capability list:

Lifecycle-Gated Authorization:
: Claim: supplied

  Activation: always

  Scope and defining sections: State-gated issuance and every derivation
  gate

  Limitations: Outstanding credentials run to their own `exp`; the
  residual is bounded, not zero

State-Observable:
: Claim: supplied

  Activation: Status, introspection, or Signals companion active

  Scope and defining sections: Those surfaces

  Limitations: Staleness bounded by each surface's declared freshness

Structured Authority:
: Claim: supplied

  Activation: always

  Scope and defining sections: `authorization_details` of AS-supported
  types ({{other-types}}), each type's own specification defining
  semantics (for `mission_resource_access`, the Mission Resource Access
  Profile's Common Constraints,
  {{I-D.draft-mcguinness-oauth-mission-resource-access}})

  Limitations: Semantics exist per supported type, not universally

Monotonic Derivation:
: Claim: supplied

  Activation: always

  Scope and defining sections: The subset rule over covered types at
  every derivation, delegation, and attenuation point

  Limitations: Covered transitions are `attenuate`; a cross-vocabulary
  transition is `decide_anew`, never silent attenuation

Credential-Bound:
: Claim: supplied

  Activation: always

  Scope and defining sections: The `mission` claim on issued tokens

  Limitations: Fact semantics: issuance under the Mission, authority
  derivation, lifecycle-gated issuance; state-as-of only via the
  State-Observable surfaces

Authorized Context Correlation:
: Claim: supplied

  Activation: the Delegation capability active ({{delegation}})

  Scope and defining sections: The Token Exchange join at delegated
  issuance: the AS, as joining authority, joins the Mission and Subject
  carried by the Mission-bound `subject_token` with the delegate
  identity independently established by the delegate's own client
  authentication, binding both to the newly issued credential

  Limitations: The base grant binding at issuance co-establishes its
  facts and is not a join; cross-authority joins are the Mission
  Authority Server's machinery, not this binding's

Independently Verifiable:
: Claim: supplied

  Activation: Mandate, signed Status, or audit companion active

  Scope and defining sections: Anchor recomputation and signed artifacts
  per those profiles

  Limitations: Signature verification never establishes current state

Portable Evidence:
: Claim: supplied

  Activation: Evidence, Mandate, or audit companion active

  Scope and defining sections: Per those profiles

  Limitations: The governance record is otherwise issuer-local
{: #oauth-mission-binding-capabilities newline="true"}

Temporal elements: every issued credential's `exp` is capped by the
record's effective `expires_at`; state observations carry their
surface's declared freshness; the residual after non-active is the
outstanding credential lifetime.
Failure behavior: an unknown lifecycle state is non-active; an
unresolvable reference, a failed anchor verification, and an unknown
`authorization_details` type fail closed; where an entry's activation
condition does not hold, the property is not supplied, and a consumer
cannot rely on it.

This document's three optional capabilities ({{conformance}}) are
surfaces an implementation may or may not offer, each independent of
the others. The capability list above states scoped guarantee
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

-02

- Configured-mapping mode can key on the requested `scope` values for
  a `scope`-only target, through that target's trusted scope-projection
  mapping, which also relates a requested value back to authority
  (Derivation Modes, Scope Projection).
- Editorial, no requirement change: Standing-Consent Bases points to
  the Architecture for the companion-defined bases instead of listing
  them; Grant Bindings and Related Mechanisms, Composition and the
  Effective Ceiling, Authority Materialized Before Containment, and the
  `approval_basis` definition no longer restate what the companions
  specify; the sentence on joining one credential to different Missions
  across requests moves to the Mission Authority Server's Mission
  Join.
- Editorial, no requirement change: Grant Bindings and Related
  Mechanisms places the Template profile's Dispatch Handoff and the
  continuation profile's Identity Continuation Transport, the
  reusable-state case reads as a redeemable grant lineage, the
  derivation resolution list points to profile-defined grants, and a
  derived token's Mission is the one its `subject_token` resolved to,
  with no binding assumed, and Grant Bindings and Related Mechanisms
  and Delegated Exchange keep a token's backing grant provenance where
  its `subject_token` was issued under a grant lineage (#1589, D726).
- Editorial, no requirement change: Grant Bindings and Related
  Mechanisms names the Token Exchanges its later items cover, and the
  Namespace Taxonomy lists the `approval_basis.type` values as
  specification-defined, which Standing-Consent Bases cites.
- Editorial, no requirement change: the `approval_event_id` definition
  names the approval event that creates the Mission and states that,
  under a standing-consent basis, it identifies the instance's
  creation, not the earlier standing approval.
- An access token's `mission` claim, and its introspection `mission`
  member, are reserved for issuance that conforms to a Mission-binding
  profile; a profile that defines another issuance or derivation path
  identifies its grant or chain, authority bound, state check, and
  consumer checks (Claim Reservation). Introspection discloses
  `mission` only for a token issued on a conforming path. A resource
  server's `mission.issuer` check accepts the relationship any
  Mission-binding profile it has adopted establishes, not only a
  cross-domain profile's (Enforcement Requirements).
- A Mission-governed resource, classified by the deployment or by its
  authenticated `mission_bound_authorization_required` metadata, gets
  no token outside a Mission on any grant type; the open-ended policy
  exception is removed, and the refusal is `invalid_target`
  (Authority Proposal).
- A token carries only the entries whose original approved audience
  (the audiences the AS's trusted mapping assigned an entry at
  approval, retained with the Mission and kept by the entries a derived
  Mission inherits) includes its audience, unless a declared
  `narrowing` capability permits issuing an entry there. A token naming
  several audiences is issued only where each is approved for the same
  entries; otherwise, or where the audience is approved for none of the
  entries the token would carry, the request is refused with
  `invalid_target` (Declared Transformation Capabilities, Audience and
  Token Response; #1503, D620, D733).
- A designation's `aud` names its redeemer and reassigns no entry's
  original approved audience: the audience rules test the audiences
  associated with the entries it carries, a permitted subset of the
  presented token's that excludes an entry without an original approved
  audience, and the delegated token issued at its redemption is subject
  to every audience rule (Audience and Token Response, Declared
  Transformation Capabilities; #1717, D845, D859).
- At a delegated exchange the AS authenticates the requesting client by
  a method it relies on to identify the client and refuses any other,
  including every public client, with `invalid_client` and no token; a
  claimed `client_id`, the designation, or an independently chosen key
  does not authenticate it. That client authentication alone identifies
  the delegate: the AS refuses an `actor_token` from an authenticated
  client with `invalid_request`. An exchange presenting a designation
  is a delegated exchange, never a no-actor one (Delegated Exchange,
  Designation, Self-Exchange Down-Scoping, Establishing and Resolving
  a Binding, Error and Challenge Mapping, Token Theft, OAuth Binding
  Mapping Assessment; #1718, D845, D859).
- The key-publication requirement applies to an AS that issues
  Mission-bound JWT access tokens for resource servers to consume, not
  to one issuing only designations; the first capability carrier that
  declares a member governs, `true` or `false`, and a declaration
  waives no check; the declared `narrowing` capability also governs
  Authority Set derivation, where without it a candidate entry is
  retained unchanged or omitted; an undecidable token-endpoint subset
  comparison is refused with `invalid_authorization_details`; and
  short-lived is related to the termination latency a deployment
  accepts, with numerical bounds left to deployment profiles (Token
  Claims, Declared Transformation Capabilities, Authority Proposal,
  Derivation Modes, Subset Rule, Issuance Gating; #1720, D845).
- The AS refuses, with `invalid_target`, a delegated Mission-bound
  token for an audience it has not established as a Mission-aware
  Resource Server that processes the `act` chain; routing and logging
  beyond that audience stay the deployment's (Mission-Unaware Resource
  Servers, Delegated Exchange; #1503, D620).
- Each redemption of a designation validates the originating credential
  and all applicable grant state backing it, which an exchange that
  establishes no new grant lineage keeps; a designation's expiry bounds
  its redemption, not the lifetime of the delegated token issued from
  it (Delegated Exchange, Designation, Authentication Claims and
  Lifetime; #1503, D620).
- Step 1 of the Submission Processing Order applies the size bounds and
  checks each evidence entry's structure, so a structurally invalid
  entry is refused with `invalid_request` before the authority proposal
  is validated, and Conformance Roles names that code for it (Submission
  Processing Order, Intent Submission Evidence, Conformance Roles;
  #1503, #1482, D620).
- The deployment's published approval-authentication floor, and the
  `mission` member of an active introspection response to a caller
  authorized for Mission data, are requirements rather than lowercase
  statements (Approver Authentication Strength, Mission State via Token
  Introspection; #1503, D620).
- A Mission is revoked by a party the deployment's policy authorizes, or
  by that policy itself; the Subject, the Approver, and an administrator
  can be authorized, but none is by role alone (Revocation, Mission
  Lifecycle; #1503, D620).
- Editorial, no requirement change: the Derivation definition, in
  Terminology and Issuance Gating, includes the redemption of a
  profile-defined grant, such as the Template profile's handoff grant;
  a grant binding resolves the Mission for the operations using it,
  and a profile-defined grant can instead resolve it through its
  authenticated `mission` reference (#1631, D751).
- Editorial, no requirement change: the Mission Status variation's
  revocation `reason` describes a revocation, not a completion
  (#1535).
- Editorial, no requirement change: Single Accountable Approver states
  that authenticating approval evidence does not establish that
  conditions governing later reliance remain satisfied, and that the
  effect of later changes to an Approver's role, a delegation, or
  governing policy on an existing Mission is deployment policy (#830).
- When the AS establishes that a Mission's recorded Subject has been
  deprovisioned, it SHOULD terminate the Mission with reason `revoked`;
  temporary disablement, an outage, or another principal's departure
  does not trigger the rule, and termination does not recall issued
  tokens (Revocation; #830).
- A direct approval whose commit finds the effective expiry passed is
  refused with `access_denied`, with no Mission or authorization code
  (Committing the Mission). A token request that fails several checks
  gets any applicable error, subject to the orders this document
  states. A state a companion defines takes that companion's
  `mission_error` value, never a termination reason (Issuance Gating).
  A resource server answers an opaque Mission-bound token resolved as
  inactive with `invalid_token`, and a resolution it cannot complete
  with HTTP 503 and no token error (Introspected Token Consumption).
  Enforcement Requirements refuses an entry it cannot enforce only with
  the codes of the error table, and Mission awareness alone does not
  imply `act` processing (Error and Challenge Mapping, Client
  Identification in Delegated Tokens; #1721, D845).
- `mission_id` and `mission_expires_at` are required on the response
  that first delivers a newly created Mission's identifier or
  credential (on the authorization-code path, the token response, not
  the code-only authorization response) and on a delegated exchange
  response, and recommended on every other Mission-bound token
  response; a client learns them from the response, not from the
  access token. A client assumes no authority absent from the granted
  `authorization_details` and need not reject a narrower grant
  (Mission Identifier and Expiry in Responses, Audience and Token
  Response, Conformance Roles; #1719, D845).
- Editorial, no requirement change: the AS answers a request at its
  final decision to release the result, so a result prepared before an
  acknowledged revocation and released after it is refused (Issuance
  Gating); the Mission Record is a logical object with no required
  storage form; the Authority types extension point lists what a
  type's specification supplies; resource-server conformance implies
  no particular type (Conformance Roles, Authorization Details Types);
  each `mission_error` value is explained to the client (Issuance
  Gating); and Scope Projection gains an example (#1722).
- Editorial, no requirement change: Adjacent Work distinguishes the
  `mission` claim from AAuth's `mission_s256` claim and the WIMSE AIMS
  agent mission; `target_resources`, like `purpose`, grants no
  authority as a configured-mapping key; Terminology defines
  "Mission-governed client"; and Issuance Gating gives the reason a
  Token Exchange refusal uses `invalid_request` (#1532).
- The consent rendering attributes client-supplied text to the client,
  identified from client identity information the AS trusts, and
  presents `goal` and `task_bounds` as recorded, without truncation
  (Rendering Safeguards; #1532, D859).
- Editorial, no requirement change: Terminology defines "applicable
  entry" by the matching rule Audience and Token Response states, and
  adds the delegation terms; Mission State via Token Introspection
  describes a resource server that observes Mission state in plain
  terms; and the Implementation Map gains a table of deployment
  choices, naming for each who decides, which party learns it, and the
  existing signal, if any, it learns from (#1723, #1504, D845).
- Editorial, no requirement change: Mission-Bound Access Tokens opens
  with Issuance Checks, one list of the checks issuance applies, each
  with its home sections and its applicability and exceptions on code
  redemption, refresh, designation, delegated exchange, and
  self-exchange, and each of those paths points to the list; the
  Implementation Map gains an operation index naming the sections each
  operation needs (#1723, D845).
- Editorial, no requirement change: Policy-Language Types drops its
  Cedar example; Remediation Grains names its three grains in one
  paragraph; Grant Bindings and Related Mechanisms leaves the Template
  and Identity Continuation exchange mechanics to their profiles and
  merges the Mission Join paragraphs; Single Accountable Approver
  points to the Approval Governance Record for its mechanics, keeping
  both limitations; Approval Comprehension condenses its practices; and
  the Enforcement Responsibilities table is removed, with Rendering
  Safeguards pointing to Enforcement Requirements and Scope Projection
  (#1793, D919).
- Editorial, no requirement change: Token Claims, Delegated Exchange,
  Intent Submission Evidence, Revocation, Authority Hash and Mission
  Identity, and Authority Materialized Before Containment point to the
  home of a rule they restated, keeping each operation's own condition
  (#1793, D919).

-01

**Breaking wire changes**

- `mission_intent` carries the Mission Intent Submission envelope,
  `intent` plus an optional typed `evidence` array; a bare Intent is
  refused, and unsupported, invalid, or missing required evidence is
  refused with the new `invalid_mission_intent_evidence` error code.
  PAR carries it on the authorization-code path; other grants need a
  companion (#1202). The authority proposal moves from the removed
  Intent member `proposed_authority` to the `authorization_details`
  parameter, committed by the new `proposal_hash`.
- Inside a signed Request Object pushed through PAR, the
  `mission_intent` claim is the Submission envelope as a JSON object,
  not its serialization; any other value is refused with
  `invalid_request` (#1503).
- Intent members, with no aliases (#636, #706, #117): `resources` is
  renamed `target_resources` and `constraints` `task_bounds`;
  `controls` is removed, its `acr` replaced by the `acr_values` and
  `max_age` parameters and its `max_derivations` by Derivation Limits'
  `requested_derivation_limit`. `success_criteria` is removed, and
  earlier Missions keep their recorded Intent. `goal_lang` is new
  (#534). The top level admits only defined members, a Mission Intent
  Members registry assigns short names, and test vectors are
  regenerated.
- The baseline `mission` claim carries `id`, `issuer`, and an optional
  `expires_at`; `authority_hash` leaves the claim, and introspection
  can disclose it (#702). The Mission Record replaces `approver` with
  `approval_basis.consent_principal` (#705) and adds `approval_basis`,
  `authority_source` (#316), `termination`, `proposed_authority`,
  `proposal_hash`, and `submission_evidence`.
- The lifecycle states are `active` and `terminated`; the -00 states
  `revoked` and `expired` become termination reasons, and a consumer
  can read a legacy state that way during a transition (#705). New
  registries hold lifecycle states, any further one non-terminal
  (#170), and termination reasons.
- The token endpoint adds `mission_expires_at`, the effective expiry,
  which can precede the requested `intent.expires_at`, and the
  `mission_error` diagnostic; `mission_id` is recommended.
  Authorization details type metadata can declare
  `mission_transformation_capabilities`, and entry commitments use
  `mission-authority-entry`. Resource server challenges add
  `mission_denial` and use RFC 9470 `insufficient_user_authentication`.
- A Token Exchange refuses an inactive Mission (#1154) and an invalid,
  unproven, or unacceptable subject or actor token (#1178) with
  `invalid_request`, unless its profile assigns a code; other grants
  keep `invalid_grant`, and DPoP proof failures use
  `invalid_dpop_proof` and `use_dpop_nonce`. `access_denied` replaces
  `invalid_authorization_details` where no `authorization_details` was
  submitted; `invalid_target` covers scope-projection and routing
  failures; and `invalid_scope` covers an ungrantable `scope` and an
  `openid` request whose Approver is not the Subject (#826).
- Delegation by designation (#1268): the delegate's `subject_token` is
  a designation, which only the holder of a sender-constrained token
  obtains, by Token Exchange naming the delegate as `audience`.
- Instance context no longer identifies the instance through `act.sub`
  or `act.cnf`: the delegate's actor identity is established
  separately, the top-level `cnf` binds the presenting key, and a
  deployment can convey optional `client_instance` context under
  {{I-D.draft-mcguinness-oauth-client-instance-id}}. The
  instance-delegate matcher example uses the `ai_agent` actor type
  instead of the retired `client_instance` actor type.
{: spacing="compact"}

**Model changes.** Approval separates `consent_principal`,
`activation_actor`, and optional `adjudication` (#701): `direct`
approval is human (#1185), approval activates only authority its
source holds (#316), and standing-consent bases activate instances at
their own approval events (#1078). Derivation is mechanical.
`purpose` selects configured mappings; its other uses, and model
output, only refuse or narrow (#1102). Each grant lineage
binds to one Mission, never through consent reuse (#700, #1259).
Authority is type-agnostic, with scope projection; opaque tokens use
introspection or issuer-local resolution (#1203). Submission
processing checks a proposal before evidence, refuses with the earliest
failing step's error, and completes Authority Set derivation before
the rendering (#1411); the Mission-governed client rule reaches only
authorization requests (#1448); delegation policy crosses a
cross-domain projection where that profile's provenance rule keeps it
(#1374). An unrecognized `authority_source.type` stays opaque
provenance and does not deactivate the Mission, though no Mission is
approved from a source the AS does not recognize, and an
`authority_source.policy` digest follows the construction and issuer
its policy format defines (#1503).

**Moved to companions.** Resource Access (the `mission_resource_access`
type, Common Constraints, tool modeling, and
`mission_constraints_supported`; #637, #645, #698); Intent Submission
Evidence (the verification framework; `evidence` stays); Approved-Set
Verification; Derivation Limits (with `derivations_remaining`);
Metering's Intent members; and Approval Governance's assertion rules.

**Security and privacy.** Delegation hardening and no authority from
an entry a resource server cannot fully enforce (#1258); Approver
authentication kept off derived tokens and out of OpenID Connect
results for another Subject (#826); task credentials that are
Mission-bound or covered by a trusted enforcement path (#1205);
refresh tokens bound per client type (#1204);
issuer-checked Mission resolution (#725); third-party data subjects
(#344); key retention to the audit horizon; a resource server accepts
a `mission` claim only from an issuer it trusts for Mission-bound
authorization, with `mission.issuer` equal to `iss` outside an
adopted cross-domain profile; the approval rendering identifies the
receiving client from information the AS trusts; a refresh request
beyond its grant is refused, never trimmed (#1503); and the approval
basis named as outside the integrity anchors, with the profiles that
commit it (#1518).

**Editorial and structure.** The reading path (#910, #1379);
readability, placement and consolidation passes (#876, #1409, #1447,
#1472, #1479, #1483, #1490, #1501, #1526), with the issuance rules
gathered under Mission-Bound Access Tokens, "Mission Lifecycle and
Gating" retitled "Mission Lifecycle", resource classification named
"Mission-governed resource" (#1503), and one Standing-Consent Bases
section; the error-table detail for a configured-mapping refusal
aligned with Derivation Modes (#1495); subsections, tables and IANA
templates fitted to the text rendering (#1380, #1382, #1401, #1404,
#1410, #1418); canonical-Mission examples (#1176); and the Mapping
Assessment, moved from the substrate (#708).

**References.** The WIMSE AIMS draft, the RAR metadata remediation
draft, and Client Instance ID with Client Attesters replace
draft-klrc-aiagent-auth, draft-zehavi-oauth-rar-metadata, and
draft-mcguinness-oauth-client-instance-assertion; MCP, ISO 4217, RFC
3986, and draft-mcguinness-oauth-ai-agent-instance are removed; RFC
6750, RFC 9700, Client Instance ID, OpenID Connect Core, the RAR
metadata remediation draft and, for Delegation, the OAuth Actor
Profile are normative.

-00

- Initial individual draft.

# Acknowledgments {#acknowledgments}
{:numbered="false"}

This work builds on the OAuth 2.0 Rich Authorization Requests, Pushed
Authorization Requests, and JWT access token specifications, and is
intended to complement agent-identity work including
{{I-D.draft-ietf-wimse-aims}}.
