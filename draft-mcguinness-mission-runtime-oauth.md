---
title: "Mission-Bound Runtime Enforcement: OAuth 2.0 Profile"
abbrev: "Runtime OAuth Profile"
category: std

docname: draft-mcguinness-mission-runtime-oauth-latest
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
 - enforcement
 - pdp
venue:
  github: "mcguinness/mission-bound-authorization"
  latest: "https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-runtime-oauth.html"

author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com

normative:
  RFC6749:
  RFC6750:
  RFC7662:
  RFC9068:
  RFC9700:
  RFC9728:
  I-D.draft-mcguinness-oauth-mission:
    title: "Mission-Bound Authorization for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission.html
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
  I-D.draft-mcguinness-mission-substrate:
    title: "Mission Substrate Requirements"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-substrate.html
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

informative:
  I-D.draft-mcguinness-oauth-mission-issuance-grant:
    title: "Mission Issuance Grant for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-issuance-grant.html
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
  I-D.draft-mcguinness-oauth-mission-status-list:
    title: "Mission Status List for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-status-list.html
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
  I-D.draft-mcguinness-mission-authzen:
    title: "Mission-Bound Runtime Enforcement: AuthZEN Profile"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-authzen.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026

--- abstract

This document profiles Mission-Bound Runtime Enforcement for OAuth 2.0
access tokens. It specifies how validated token claims and token
introspection results supply the runtime decision inputs, how OAuth
mechanisms provide Mission state observations, and how protected
resource metadata conveys runtime classification floors. Enforcement
semantics are defined by Mission-Bound Runtime Enforcement; token
semantics are defined by Mission-Bound Authorization for OAuth 2.0.

--- middle

# Introduction

Mission-Bound Runtime Enforcement {{I-D.draft-mcguinness-mission-runtime}}
(the "runtime core") defines a binding-neutral decision contract: an
established Mission reference, an effective-authority source, an
active predicate and freshness bound, a subject and actor, an action
and resource with normalized parameters, local-policy intersection, an
authenticated permit or deny, an execution boundary, and fail-closed
behavior on anything the deployment does not understand. It names
these as abstract roles and carries no OAuth claim or endpoint
vocabulary. Mission-Bound Authorization for OAuth 2.0
{{I-D.draft-mcguinness-oauth-mission}} (the "issuance profile")
defines the Mission-bound access token: its claims, its issuance and
delegation, and the validation a Resource Server applies to it.

Neither says which validated token values supply which runtime
inputs, which OAuth mechanisms observe Mission state, or how a
protected resource publishes its classification floor. This document
answers those three questions for a deployment whose Mission-bound
credential is an OAuth access token. Three specifications divide the
work:

| Specification | Owns |
|---|---|
| Issuance profile {{I-D.draft-mcguinness-oauth-mission}} | Token claims, issuance, delegation, and baseline Resource Server validation |
| Runtime core {{I-D.draft-mcguinness-mission-runtime}} | Decision inputs, enforcement, freshness requirements, permits, and evidence obligations |
| This document | The mapping between them, OAuth state-source integration, and classification metadata |

This document defines the processing rules that mapping needs and one
protected resource metadata member ({{class-floors}}). It cites the
runtime core's invariants, failure modes, and evidence requirements
and the issuance profile's token validation rather than restating
them.

A decision API is a separate choice. The AuthZEN profile
({{I-D.draft-mcguinness-mission-authzen}}) carries the runtime core's
decision between a PEP and a PDP whatever credential supplied its
inputs, and a deployment using this document does not need it. A
deployment on a different Mission substrate supplies its own
credential profile and uses the runtime core unchanged
({{I-D.draft-mcguinness-mission-substrate}}).

# Status: An Optional Profile {#doc-status}

<!-- family-status: BEGIN (generated from family-manifest.json; exact-matched by scripts/check-family-manifest.mjs) -->
Role: companion. Spec maturity: experimental. Maintenance: active.
Implementation: 5 conformance rows in conformance-manifest.json (2 tested, 1 partial, 2 todo).
Adopt when: The Mission-bound credential is an OAuth access token and the runtime core's abstract roles need their concrete OAuth realization.
Requires: Mission-Bound Runtime Enforcement; Mission Substrate Requirements; Mission-Bound Authorization for OAuth 2.0.
Also requires, conditionally: Mission Resource Access Profile for OAuth 2.0 (when the deployment maps a mission_resource_access authorization_details entry).
<!-- family-status: END -->

# Conventions and Terminology {#conventions-and-definitions}

{::boilerplate bcp14-tagged}

This specification uses the terms "access token", "Authorization
Server", "client", "protected resource", "resource owner", and
"Resource Server" from OAuth 2.0 {{RFC6749}} through the terminology
incorporated by {{I-D.draft-mcguinness-oauth-mission}}. It uses Policy
Enforcement Point (PEP), Policy Decision Point (PDP), established
Mission, decision, Resource policy, consequential action, and the
action-class names as defined by the runtime core
({{I-D.draft-mcguinness-mission-runtime}}).

Validated credential context:
: The values a PEP has established for a presented access token under
  {{token-validation}}: the claims of a validated JWT access token, or
  the members of the introspection response for a presented opaque
  token.

Credential authority:
: The `authorization_details` in the validated credential context.

Current effective authority:
: The Mission's approved Authority Set narrowed by whatever narrowing
  mechanism the deployment runs, as the runtime core's authority input
  defines it; the issuance profile's Status companion names it the
  Effective Authority Set
  ({{I-D.draft-mcguinness-oauth-mission-status}}).

# Establishing Validated Credential Context {#token-validation}

The runtime decision is downstream of ordinary access token
validation. Before using a token's Mission, authority, subject,
client, actor, or confirmation-key values as decision inputs, the PEP
MUST establish that the access token is valid for the protected
resource and request, including its audience and, for a
sender-constrained token, proof of possession of the confirmation key.

The issuance profile defines that validation for both of its token
forms; this document adds no validation step of its own:

- A JWT access token is validated under the issuance profile's
  Resource Server rules, which apply {{RFC9068}} and verify any
  sender-constraint binding ({{I-D.draft-mcguinness-oauth-mission}},
  Section "Resource Server Enforcement").
- An opaque access token is resolved under the issuance profile's
  introspected token consumption mode: introspection before each use,
  an `active` response, the Resource Server's own identity in `aud`,
  and a sender-constraint binding verified locally
  ({{I-D.draft-mcguinness-oauth-mission}}, Section "Introspected Token
  Consumption").

Each value the runtime decision uses is read from the resulting
validated credential context ({{claims-mapping}}).

Introspection freshness is per use under the issuance profile: each
response is an observation for one decision, not a cacheable state
assertion or authority record ({{I-D.draft-mcguinness-oauth-mission}},
Section "Mission State via Token Introspection"). The runtime core's
freshness rules do not relax that; a deployment that needs
bounded-staleness caching uses the Mission Status profile
({{state-sourcing}}).

A PEP MUST NOT ask a PDP to authorize an action from unverified token
claims. If token validation fails, the PEP MUST refuse before runtime
Mission evaluation. When the PEP is an OAuth Resource Server, it uses
the normal OAuth error behavior for the protected resource (for
example, Bearer token errors under {{RFC6750}}); this document defines
no new OAuth error code.

A Mission reference reaches the decision in one of two ways. A
credential-carried reference is the `mission` claim of a validated JWT,
or the `mission` member of the introspection response for an opaque
token. An externally established reference is supplied outside the
token and verified under the runtime core's Mission Binding
Establishment ({{I-D.draft-mcguinness-mission-runtime}}). If the
deployment requires Mission governance for the protected operation and
neither reference is established, the PEP MUST refuse. An external
reference never substitutes for the claim where the protected resource
requires Mission-bound tokens: a resource that advertises
`mission_bound_authorization_required` rejects a token that lacks the
`mission` claim ({{I-D.draft-mcguinness-oauth-mission}}, Section
"Protected Resource Metadata"), whatever reference the deployment could
establish externally.

# Runtime Input Mapping {#claims-mapping}

The runtime core states its decision inputs, permit binding, and
required evidence fields as abstract roles
({{I-D.draft-mcguinness-mission-runtime}}). This section is their
complete, normative realization on this profile. Each value is read
from the validated credential context ({{token-validation}}): a JWT
claim, or the introspection response member of the same name.

| Runtime-core role | OAuth realization |
|---|---|
| Established Mission reference | The `mission` claim's `id` and `issuer` {{I-D.draft-mcguinness-oauth-mission}}, or an externally established reference ({{token-validation}}) |
| Authenticated subject | `sub` |
| Client or immediate-actor identity | `client_id` names the client; when `act` is present, the immediate actor is the current actor in `act` |
| Actor-delegation chain | `act`, when delegation is in effect |
| Sender-constraint confirmation | `cnf`, verified during validation ({{token-validation}}) |
| Token audience or protected-resource reference | The protected resource the PEP guards; validation has established that `aud` names it |
| Authority entry | The credential authority ({{authorization-details-mapping}}) |
| Current effective authority | Established from a Mission state source ({{authorization-details-mapping}}) |
| Token issuer | `iss` |
| Token expiry | `exp` |
| Mission expiry | The `mission` claim's `expires_at` member where present, or a Mission state source that reports the Mission's expiry |

Four pairs in the table are related but distinct inputs:

- `client_id` and `act`. The issuance profile gives `client_id` its
  ordinary meaning, the OAuth client that requested the token, and
  carries delegation in `act` ({{I-D.draft-mcguinness-oauth-mission}},
  Section "Resource Server Enforcement"). When delegation is in
  effect, the PDP MUST evaluate the authenticated `act` claim as part
  of the runtime actor context and refuse a chain that is missing or
  malformed; when an `act` claim is present, the PDP MUST NOT treat
  `client_id` alone as the immediate actor.
- `aud` and the protected resource. Validation establishes that `aud`
  names the protected resource the PEP guards; the decision, the
  permit binding, and the evidence then identify that protected
  resource, the target of the action.
- The credential authority and the current effective authority. The
  action falls within both ({{authorization-details-mapping}}).
- Token expiry and Mission expiry. The PDP MUST refuse if the decision
  context indicates the token is expired (`exp`). Where the validated
  `mission` claim carries the `expires_at` member, the PEP or PDP MAY
  refuse actions past that instant without consulting a state source:
  the value is an immutable commitment and a ceiling only, carrying no
  liveness, so the runtime core's only-`active` rule and freshness
  requirements apply unchanged. Where a Mission state source separately
  reports the Mission `expired`, or exposes the Mission's `expires_at`,
  the PDP MUST refuse on it independent of the token's own `exp`: the
  baseline `mission` claim need not carry `expires_at`, and OAuth token
  introspection {{RFC7662}} does not itself surface it. A profile that
  makes `expires_at` REQUIRED for the credentials it governs, such as
  the Issuance Grant profile
  ({{I-D.draft-mcguinness-oauth-mission-issuance-grant}}), also caps
  `exp` at it under that profile's own rule, never reducing the Mission
  expiry check to `exp` alone.

These realize the runtime core's actor and time inputs
({{I-D.draft-mcguinness-mission-runtime}}); the requirements
themselves, including that no runtime input expands authority beyond
the issued authority, are the runtime core's.

The Mission reference is `id` and `issuer`. `authority_hash` is not
part of the baseline reference; a deployment that needs it as a
commitment proof rather than an audit correlator carries it under the
issuance profile's Local Approved-Set Verification profile
({{I-D.draft-mcguinness-oauth-mission}}). The runtime core's permit
binding and required decision evidence record the roles above; their
serialization is defined by the runtime core and the decision-API
profile in use, for example {{I-D.draft-mcguinness-mission-authzen}}.

# Authority and State Sources {#authority-and-state}

The runtime decision needs two kinds of input that OAuth supplies
separately: the authority an action is checked against, and
observations of Mission state.

## Credential Authority and Current Effective Authority {#authorization-details-mapping}

The runtime core requires that the action be authorized by an
applicable authority entry the Mission-bound credential carries,
evaluated against the Mission's current effective authority, and that
the PDP fail closed on an authority-entry type it does not understand
({{I-D.draft-mcguinness-mission-runtime}}). On this profile those are
two inputs, and the action MUST fall within both:

- the credential authority: the `authorization_details` of the
  validated JWT or, for an opaque token, of its introspection
  response; and
- the current effective authority: the approved Authority Set,
  narrowed by any narrowing mechanism the deployment runs and then
  established from a Mission state source that reports the narrowing
  ({{state-sourcing}}).

A token narrowed below its Mission's approved Authority Set is
evaluated at its own narrower entry. The PDP MUST NOT substitute the
approved Authority Set, or any other record of Mission authority, for
the credential authority.

Each entry is enforced under its type's own specification, as the
issuance profile requires of a Resource Server
({{I-D.draft-mcguinness-oauth-mission}}, Section "Resource Server
Enforcement"). For an entry of type `mission_resource_access`, the
action's `resource` and invoked action or tool identity MUST be within
that entry's `resource` and `actions`, under the subset rule of
{{I-D.draft-mcguinness-oauth-mission-resource-access}}. The PEP asserts
the capability identity (for example, the tool or function name) it
will invoke, and the PDP MUST refuse an identity outside the approved
`actions`. For any other `authorization_details` type, the PDP MUST
evaluate the action under that type's documented runtime semantics, the
runtime core's fail-closed rule governing what it does not understand
or cannot enforce.

# State Sourcing {#state-sourcing}

The runtime core defines an abstract freshness dial running from
credential-lifetime expiry to a queried or event-driven active
source, and requires a deployment to declare its position per action
class ({{I-D.draft-mcguinness-mission-runtime}}). This binding's
concrete instantiations of that dial:

| State source | Capability | Exposure bound | Per-action cost | Depends on | Cannot provide |
|---|---|---|---|---|---|
| Token-lifetime expiry | lifecycle-gated | maximum token lifetime | local clock check | nothing beyond the token | suspend, complete, or any revocation inside the lifetime |
| State-gated refresh | lifecycle-gated | token lifetime (the refresh interval) | none at action time | the issuer at each refresh | anything between refreshes |
| Token introspection ({{RFC7662}}) at the Mission issuer | state-observable | the interval from the lookup to the action it serves | one lookup per use; the issuance profile defines no caching for the `mission` member | issuer availability | reuse of one response across decisions |
| Mission Status operation ({{I-D.draft-mcguinness-oauth-mission-status}}) | state-observable | published staleness bound | one lookup within the bound, cacheable to `fresh_until` | status surface availability | revocation inside the bound |
| Mission Status List ({{I-D.draft-mcguinness-oauth-mission-status-list}}) | state-observable | Status List Token TTL | local bit read | one list fetch per window | terminal-state detail; a non-VALID bit sends the consumer to the authoritative surface |
| Mission Lifecycle Signals ({{I-D.draft-mcguinness-oauth-mission-signals}}) | state-observable | delivery latency within the verified stream | none (event-driven) | stream liveness | the pull floor; a dead stream is stale state |

When the credential issuer also holds the Mission, a PDP on this
binding learns state through token introspection ({{RFC7662}}) at the
issuer per {{I-D.draft-mcguinness-oauth-mission}}. A non-issuer
Resource AS introspecting a local token
({{I-D.draft-mcguinness-oauth-mission-cross-domain}}) cannot report
current Mission state that way; it can establish local token
validity, but not issuer-side Mission freshness.

For the high-consequence classes, the runtime core requires an active
freshness mechanism that reflects a revocation within the staleness
bound ({{I-D.draft-mcguinness-mission-runtime}}); on this binding,
that is token introspection, the Mission Status profile, a Mission
Status List whose Status List Token TTL is within the bound (the
Status List companion's swarm-scale pull floor,
{{I-D.draft-mcguinness-oauth-mission-status-list}}), or Mission
Lifecycle Signals.

Where derivation and refresh of a Mission-bound token are gated on
`active` ({{I-D.draft-mcguinness-oauth-mission}}), token-lifetime
expiry and the refresh cycle each conform to the runtime core's
Credential-lifetime freshness and refresh-gated active source rules,
at the token lifetime as their revocation latency floor.

# Resource-Owner Class Floors {#class-floors}

A resource owner can carry its classification minimums to any PDP
through its protected resource metadata {{RFC9728}}, the OAuth
realization of the runtime core's classification-floor rule
({{I-D.draft-mcguinness-mission-runtime}}):

`mission_action_class_floors`:
: OPTIONAL JSON object. Each member name is an action identifier from
  the resource's `actions` vocabulary
  ({{I-D.draft-mcguinness-oauth-mission}}); an action-family
  identifier, in the issuance profile's action-family form, sets the
  floor for every action in the family. Each value is the minimum
  runtime action class for the mapped action: one of
  `consequential_read`, `consequential_write`, `irreversible_action`,
  `external_commitment`, or `privileged_administration`, naming the
  runtime core's classes.

A PDP with access to the resource's metadata MUST NOT classify a mapped
action below its floor. The member is the interoperable carriage of the
Resource-policy minimum the runtime core's classification floor already
binds; it raises, and never lowers, an action's class. A PDP that does
not recognize a mapped value MUST treat it as naming a high-consequence
class.

For the ERP resource of the runtime core's worked examples:

~~~ json
{
  "resource": "https://erp.example.com",
  "mission_action_class_floors": {
    "journal-entries.read": "consequential_read",
    "journal-entries.write": "irreversible_action"
  }
}
~~~

# Conformance {#conformance}

A deployment conforms to this adapter only where it also conforms to
the runtime core ({{I-D.draft-mcguinness-mission-runtime}}) and the
issuance profile ({{I-D.draft-mcguinness-oauth-mission}}) for the same
enforcement scope. This document adds no separate conformance tier: a
deployment's Enforcement Scope Statement names the runtime core's
requirements, and adopting this adapter is what makes "the Mission-bound
credential is an OAuth access token" a true statement of that scope,
rather than a second scope to separately declare.

# Security Considerations {#security-considerations}

The runtime core's Security Considerations
({{I-D.draft-mcguinness-mission-runtime}}) apply in full, including the
remote decision-channel requirement on a PEP/PDP boundary that is not
co-resident. General OAuth security guidance {{RFC9700}} applies to the
credentials this adapter validates. A PDP that accepts an access token
directly, rather than the minimum credential-derived claims a PEP needs
to convey, MUST treat it as a credential, protect it against
disclosure, and MUST NOT use it outside the declared enforcement scope.

# Privacy Considerations {#privacy-considerations}

This document defines no evidence content of its own; the runtime
core's privacy guidance governs the claims this adapter maps into
decision inputs and evidence records
({{I-D.draft-mcguinness-mission-runtime}}).

# IANA Considerations

## OAuth Protected Resource Metadata Registration

This document registers the following in the "OAuth Protected Resource
Metadata" registry ({{RFC9728}}):

- Metadata Name: `mission_action_class_floors`
- Metadata Description: JSON object mapping a protected resource's
  action identifiers to minimum runtime action classes.
- Change Controller: IETF
- Reference: this document, {{class-floors}}

The Mission-bound token claims this document maps are registered by
{{I-D.draft-mcguinness-oauth-mission}}.

--- back

# Acknowledgments
{:numbered="false"}

This document extracts the OAuth-specific realization of
Mission-Bound Runtime Enforcement so that document can state a
binding-neutral contract. The author thanks reviewers of the runtime
core for pressing on the substrate-neutrality claim until it was true.
