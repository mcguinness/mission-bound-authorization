---
title: "Mission Runtime OAuth Adapter"
abbrev: "Runtime OAuth Adapter"
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
  I-D.draft-mcguinness-mission-authzen:
    title: "Mission-Bound Runtime Enforcement: AuthZEN Profile"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-authzen.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026

--- abstract

Mission-Bound Runtime Enforcement {{I-D.draft-mcguinness-mission-runtime}}
(the "runtime core") specifies a binding-neutral decision contract for
enforcing a Mission-bound credential at the point of use. This document
is the OAuth 2.0 realization of that contract: how a PEP validates a
Mission-bound access token before evaluation, how the runtime core's
abstract subject, actor, sender-constraint, and audience roles map onto
the `sub`, `act`, `cnf`, and `aud` claims and the `mission` claim,
how an `authorization_details` entry realizes the runtime core's
effective-authority-set input (including the `mission_resource_access`
entry type), and how a resource owner carries a runtime classification
floor through OAuth protected-resource metadata. It defines no
enforcement semantics of its own: every invariant, failure mode, and
evidence requirement it mentions is the runtime core's, cited and
mapped, never restated with different force.

--- middle

# Introduction

Mission-Bound Runtime Enforcement {{I-D.draft-mcguinness-mission-runtime}}
(the "runtime core") defines a binding-neutral semantic contract: an
established Mission reference, an effective-authority source, an
active predicate and freshness bound, a subject and actor, an action
and resource with normalized parameters, local-policy intersection, an
authenticated permit or deny, an execution boundary, and fail-closed
behavior on anything the deployment does not understand. It deliberately
carries no OAuth claim or endpoint vocabulary, so a non-OAuth binding
can implement it without importing OAuth semantics.

This document is the OAuth 2.0 adapter: it names the concrete claims
and metadata that satisfy the runtime core's abstract roles for a
deployment whose Mission-bound credential is the OAuth binding's access
token {{I-D.draft-mcguinness-oauth-mission}} (the "issuance profile").
It is normatively dependent on both the runtime core and the issuance
profile, and it adds no enforcement invariant, failure mode, or
evidence requirement beyond what the runtime core already states; where
this document uses a normative keyword, it is realizing a runtime-core
requirement in OAuth terms, not creating a new one.

The adapter's scope is exactly four things:

1. token presentation and validation: how the PEP establishes that an
   OAuth access token is valid before any of its claims become
   decision inputs ({{token-validation}});
2. the claim mapping: which OAuth claims realize the runtime core's
   subject, actor, sender-constraint, audience, and Mission-reference
   roles ({{claims-mapping}});
3. the authorization-details mapping: how an `authorization_details`
   entry, including the `mission_resource_access` type, realizes the
   runtime core's effective-authority-set input
   ({{authorization-details-mapping}}); and
4. protected-resource metadata: how a resource owner carries a runtime
   classification floor to any PDP through OAuth protected-resource
   metadata {{RFC9728}} ({{class-floors}}).

A deployment on a different Mission substrate defines its own adapter
for these four things and uses the runtime core unchanged
({{I-D.draft-mcguinness-mission-substrate}}). A decision-API binding
(for example, the AuthZEN profile, {{I-D.draft-mcguinness-mission-authzen}})
is an orthogonal axis: it wires the runtime core's abstract decision
onto a wire protocol and remains unaware of which credential adapter
supplied the claims it carries.

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

# Token Presentation and Validation {#token-validation}

The runtime decision is downstream of ordinary access token validation.
Before using a token's Mission, authority, subject, client, actor, or
confirmation-key values as decision inputs, the PEP MUST establish that
the access token is valid for the protected resource and request. For
the Mission-bound JWT access tokens defined by the issuance profile,
this means validating the JWT per {{RFC9068}}, verifying the issuer and
audience, checking token expiry, and verifying any sender-constraint
binding (`cnf`) under the proof-of-possession rules of the issuance
profile ({{I-D.draft-mcguinness-oauth-mission}}); this document defines
no proof-of-possession mechanism of its own.

Where the validated token's `mission` claim carries the `expires_at`
member ({{I-D.draft-mcguinness-oauth-mission-issuance-grant}}), the PEP
or PDP MAY refuse actions past that instant without consulting a state
source: the value is an immutable commitment and a ceiling only. It
carries no liveness; the runtime core's only-`active` rule and
freshness requirements apply unchanged
({{I-D.draft-mcguinness-mission-runtime}}).

The underlying OAuth deployment MUST follow the applicable security
best current practice in {{RFC9700}}. In particular, a Resource Server
PEP MUST refuse a token whose audience is not intended for that
Resource Server, and MUST verify the proof-of-possession check for a
sender-constrained token before treating its `cnf` binding as
authenticated.

A PEP MUST NOT ask a PDP to authorize an action from unverified token
claims. If token validation fails, the PEP MUST refuse before runtime
Mission evaluation. If the deployment requires Mission governance for
the protected operation and the token lacks a `mission` claim, the PEP
MUST likewise refuse, unless the deployment establishes the Mission
binding externally, per the runtime core's Mission Binding
Establishment ({{I-D.draft-mcguinness-mission-runtime}}); in that case
the absence of the claim is not a refusal condition, and the join's
verification of the supplied Mission reference applies instead. When
the PEP is an OAuth Resource Server, it uses the normal OAuth error
behavior for the protected resource (for example, Bearer token errors
under {{RFC6750}}); this document defines no new OAuth error code.

The runtime core separately requires that, where the PEP and PDP are
separate components, the decision channel between them is
authenticated and integrity-protected, and that the PDP accepts
credential-derived inputs only from an authorized PEP
({{I-D.draft-mcguinness-mission-runtime}}); that requirement is
binding-neutral and is not restated here.

# Claims Mapping {#claims-mapping}

The runtime core states its decision inputs, permit binding, and
required evidence fields as abstract roles: the established Mission
reference, the authenticated subject, the client or immediate-actor
identity, the actor-delegation chain, the sender-constraint
confirmation, and the token audience or protected-resource reference
({{I-D.draft-mcguinness-mission-runtime}}). This section is the
complete, normative realization of those roles for the OAuth binding:

| Runtime-core role | OAuth realization |
|---|---|
| Established Mission reference | The `mission` claim's baseline `id` and `issuer` {{I-D.draft-mcguinness-oauth-mission}}; `authority_hash` is not on the baseline claim, and where a deployment needs it as a commitment proof rather than an audit correlator, it is carried under the issuance profile's Local Approved-Set Verification profile |
| Authenticated subject | `sub` |
| Client or immediate-actor identity | `client_id` |
| Actor-delegation chain | The `act` claim, evaluated together with the authenticated `client_id` when delegation is in effect |
| Sender-constraint confirmation | `cnf`, verified under the issuance profile's proof-of-possession rules |
| Token audience or protected-resource reference | `aud`, or the protected resource the token was presented to |
| Token issuer | `iss` |
| Token expiry | `exp`; where a profile elevates the `mission` claim's OPTIONAL `expires_at` member to REQUIRED for the credentials it governs (for example, the Issuance Grant profile, {{I-D.draft-mcguinness-oauth-mission-issuance-grant}}), that value additionally caps token expiry under that profile's own rule, never as a silent baseline downgrade to `exp` alone |

When delegation is in effect, the PDP MUST evaluate the authenticated
`act` claim as part of the runtime actor context and refuse a chain
that is missing or malformed; when an `act` claim is present, the PDP
MUST NOT treat `client_id` alone as the immediate actor. These are the
OAuth realization of the runtime core's actor-context input
({{I-D.draft-mcguinness-mission-runtime}}); the requirement itself,
including that a history predicate or any other runtime input MUST NOT
expand authority beyond the issued authority, is the runtime core's.

The runtime core's permit binding and required decision evidence each
bind or record the subject, client/actor identity, and sender-constraint
confirmation as abstract roles; a deployment on this binding records
them as `sub`, `client_id`, the `act` projection, and the `cnf`
confirmation key respectively.

The PDP MUST refuse if the decision context indicates the token is
expired (`exp`). Where a Mission state source separately reports the
Mission `expired`, or exposes the Mission's `expires_at`, the PDP MUST
refuse on it independent of the token's own `exp`: the standard
`mission` claim and OAuth token introspection {{RFC7662}} do not
themselves surface `expires_at`.

# Authorization Details Mapping {#authorization-details-mapping}

The runtime core requires that the action be authorized by an
applicable authority entry, evaluated against the Mission's current
effective authority, and that the PDP fail closed on an authority-entry
type it does not understand ({{I-D.draft-mcguinness-mission-runtime}}).
For this binding, that authority entry is an `authorization_details`
entry carried by, or otherwise available for, the Mission-bound token
(for example, through introspection when the authority is not
represented inline).

For an entry of type `mission_resource_access`, the action's `resource`
and invoked action or tool identity MUST be within that entry's
`resource` and `actions`, under the subset rule of
{{I-D.draft-mcguinness-oauth-mission-resource-access}}. The PEP asserts
the capability identity (for example, the tool or function name) it
will invoke, and the PDP MUST refuse an identity outside the approved
`actions`. For any other `authorization_details` type, the PDP MUST
evaluate the action under that type's documented runtime semantics, the
runtime core's fail-closed rule governing what it does not understand
or cannot enforce.

A deployment on this binding uses OAuth token introspection
{{RFC7662}} or the Mission Status profile
({{I-D.draft-mcguinness-oauth-mission-status}}) as Mission state
sources under the runtime core's freshness discipline
({{I-D.draft-mcguinness-mission-runtime}}); {{state-sourcing}}
catalogs this binding's state sources against that discipline; this
document defines no additional state source of its own.

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
| Token introspection ({{RFC7662}}) | state-observable | published staleness bound | one lookup within the bound, cacheable to `fresh_until` | issuer availability | revocation inside the bound |
| Mission Status operation ({{I-D.draft-mcguinness-oauth-mission-status}}) | state-observable | published staleness bound | one lookup within the bound, cacheable to `fresh_until` | status surface availability | revocation inside the bound |
| Mission Status List ({{I-D.draft-mcguinness-oauth-mission-status}}) | state-observable | Status List Token TTL | local bit read | one list fetch per window | terminal-state detail; a non-VALID bit sends the consumer to the authoritative surface |
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
status profile's swarm-scale pull floor,
{{I-D.draft-mcguinness-oauth-mission-status}}), or Mission Lifecycle
Signals.

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
