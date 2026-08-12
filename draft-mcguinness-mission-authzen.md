---
title: "Mission-Bound Runtime Enforcement: AuthZEN Profile"
abbrev: "Mission AuthZEN"
category: std

docname: draft-mcguinness-mission-authzen-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
keyword:
 - oauth
 - mission
 - authzen
 - pdp
 - enforcement
venue:
  github: "mcguinness/mission-bound-authorization"
  latest: "https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-authzen.html"

author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com

normative:
  RFC3339:
  RFC6234:
  RFC7519:
  RFC8259:
  RFC8785:
  RFC9110:
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
  I-D.draft-mcguinness-mission-runtime-evidence:
    title: "Mission Runtime Evidence"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-runtime-evidence.html
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
  AUTHZEN:
    target: https://openid.net/specs/authorization-api-1_0-final.html
    title: "OpenID AuthZEN Authorization API 1.0"
    author:
      -
        org: OpenID Foundation
    date: 2026
  I-D.draft-zehavi-oauth-rar-metadata:
  ARAP:
    target: https://openid.github.io/authzen/authzen-access-request-approval-profile-1_0.html
    title: "AuthZEN Access Request and Approval Profile - Draft 1"
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  AUTHZEN-OBL:
    target: https://openid.github.io/authzen/authzen-obligations-profile-1_0.html
    title: "AuthZEN Obligations Profile 1.0"
    author:
      -
        org: OpenID AuthZEN Working Group
    date: 2026

informative:
  RFC9457:
  RFC9470:
  I-D.draft-mcguinness-oauth-client-instance-assertion:
  I-D.draft-mcguinness-oauth-ai-agent-instance:
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
  I-D.draft-mcguinness-oauth-mission-progressive:
    title: "Mission Progressive Authorization for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-progressive.html
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
  I-D.draft-mcguinness-mission-harness:
    title: "Mission-Aware Agent Harnesses"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-harness.html
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

--- abstract

Mission-Bound Runtime Enforcement defines a substrate-independent
decision contract: before each consequential action runs, a Policy
Enforcement Point (PEP) obtains a permit from a Policy Decision Point
(PDP) that evaluates the action against the established Mission. This
document is the concrete OpenID AuthZEN binding of that contract. It
maps the contract's decision inputs onto the AuthZEN Authorization API
request, shapes the permit and denial responses, maps decisions and
refusals into the Decision Evidence, Execution Evidence, and Refusal
Record of a binding-neutral evidence companion, binds every runtime
failure condition to a wire-visible identifier, and composes
requestable denials with the AuthZEN Access Request and Approval
Profile. It does not restate the enforcement semantics the runtime
profile owns, the evidence formats the runtime evidence companion
owns, or the capability-source binding the capability-binding
companion owns.

--- middle

# Introduction

Mission-Bound Runtime Enforcement
{{I-D.draft-mcguinness-mission-runtime}} (the "runtime profile")
specifies the runtime enforcement layer for Mission-bound access
tokens issued under Mission-Bound Authorization for OAuth 2.0
{{I-D.draft-mcguinness-oauth-mission}} (the "issuance profile"). The
runtime profile is deliberately substrate-independent: it defines the
decision contract, action classification, PEP placement, parameter
binding and the time-of-check to time-of-use gap, the consumption-bound
failure posture, failure modes, runtime enforcement evidence, and the
runtime
conformance scope, but it states that the decision API wire format is a
deployment choice and defines no binding of its own.

This document is the OpenID AuthZEN binding of that contract: it maps
the runtime profile's abstract decision contract onto the OpenID
AuthZEN Authorization API {{AUTHZEN}} and carries only the
AuthZEN-binding deltas:

- how the runtime profile's materialized policy view is referenced on
  the wire through its `policy_view_id`
  ({{mission-to-policy-materialization}});
- how the runtime profile's decision inputs map onto the AuthZEN
  `subject`/`resource`/`action`/`context` envelope, the worked PDP
  request, and the PDP-side consistency checks ({{pdp-request}});
- batch evaluations over the AuthZEN evaluations endpoint
  ({{batch-evaluations}});
- how the PDP's permit and denial responses are shaped, and the rules
  that keep a permit bound to the PEP, channel, and inputs it was
  issued for ({{pdp-response}});
- how the PDP and PEP emit the Decision Evidence, Execution
  Evidence, and Refusal Record of the runtime evidence companion,
  and which response members this binding echoes into them
  ({{evidence}});
- the runtime denial classification and the complete mapping of the
  runtime profile's failure conditions onto wire-visible identifiers
  ({{runtime-denial-classification}}, {{failure-condition-coverage}});
- how requestable denials can compose with the AuthZEN Access Request
  and Approval Profile {{ARAP}};
- how a deployment adopting Mission Capability Binding carries that
  companion's capability-source context and consumes an already
  established action identity here
  ({{I-D.draft-mcguinness-mission-capability-binding}}).

The AuthZEN wire representation of cumulative consumption metering,
including the settlement exchange and duration-lease renewal, is
defined with the metering semantics themselves in the experimental
metering companion ({{I-D.draft-mcguinness-mission-metering}}).

This document does not restate the enforcement contract. It does not
redefine which actions are consequential, where the PEP MUST sit, the
semantics of parameter binding, the failure
modes, or the runtime conformance scope; those are normatively defined
in {{I-D.draft-mcguinness-mission-runtime}} and are referenced,
not duplicated, here.

AuthZEN continues the Policy Decision Point / Policy Enforcement
Point request-response vocabulary XACML established for externalized
authorization; this binding adopts AuthZEN's JSON/HTTP profile of
that model, not a new one.

The end-to-end flow this binding realizes:

~~~
 Agent        PEP              PDP           Access Request Service
   |           |                |                     |
   |- action ->|                |                     |
   |           | validate token |                     |
   |           |- evaluation -->|                     |
   |           |  request       | decide vs Mission   |
   |           |<- permit ------|                     |
   |           |  (+ context)   |                     |
   |           | execute        |                     |
   |           |- Execution --->|                     |
   |           |  Evidence      | commit / release    |
   |<- result -|                |                     |
   |           |                |                     |
   |           |<- deny --------|                     |
   |           |  (+ access_request)                  |
   |           |- submit access request ------------->|
   |           |<--------------- approval ------------|
   |           |- re-evaluate ->|                     |
~~~

# Conventions and Terminology {#conventions-and-definitions}

{::boilerplate bcp14-tagged}

Two member-presence conventions extend that vocabulary:

CONDITIONAL:
: The member is present when the stated condition holds and absent
  otherwise. The condition accompanies each member so marked.

REQUIRED when known:
: The sender includes the member when it holds the member's value. A
  receiver MUST NOT infer meaning from the member's absence.

This document uses JSON {{RFC8259}} as the data model for all PDP
requests, responses, and evidence objects. JCS canonicalization
{{RFC8785}} applies wherever an integrity hash is computed, under the
canonicalization rules of {{I-D.draft-mcguinness-oauth-mission}}; this
document does not define a second canonicalization.

"SHA-256" refers to {{RFC6234}}. A digest is encoded in the
integrity-anchor encoded form of
{{I-D.draft-mcguinness-oauth-mission}}: `sha-256:` followed by the
base64url, no-padding encoding of the digest.

The terms Policy Enforcement Point (PEP), Policy Decision Point (PDP),
consequential action, Resource policy, decision, Mission state source,
enforcement scope, high-consequence classes, parameter-bound, and the
action-class names (consequential read, consequential write,
irreversible action, external commitment, and privileged
administration) are used as defined in
{{I-D.draft-mcguinness-mission-runtime}}. The Mission claim
(`id`, `issuer`, `authority_hash`), the integrity anchors
(`intent_hash`, `authority_hash`), and `authorization_details`
entries of type `mission_resource_access` are used as defined in
{{I-D.draft-mcguinness-oauth-mission}}.

Additional terms specific to this binding:

Materialized policy view, trusted compiler:
: Defined by the runtime profile
  ({{I-D.draft-mcguinness-mission-runtime}}). This binding carries
  only the wire member `policy_view_id`
  ({{mission-to-policy-materialization}}).

Decision Evidence, Execution Evidence, Refusal Record:
: The records the PDP and PEP emit for a decision, an execution
  outcome, or a pre-decision refusal, defined by the runtime evidence
  companion ({{I-D.draft-mcguinness-mission-runtime-evidence}}).

Executor:
: The component that carries out a permitted action and emits
  Execution Evidence. It is the PEP in the common case, or a distinct
  component where the requesting PEP and the executing component
  differ ({{I-D.draft-mcguinness-mission-runtime-evidence}}).

HTTP message examples follow the AuthZEN specification {{AUTHZEN}} for
the decision request and response, and {{RFC9457}} for problem-details
error bodies where a deployment carries them outside the AuthZEN
envelope.

# Mission Substrate {#mission-substrate}

This binding inherits the substrate requirements of the runtime
profile ({{I-D.draft-mcguinness-mission-runtime}}), whose decision
contract is defined against the Mission model rather than against
OAuth 2.0 mechanics. OAuth enters only through the credential-derived
decision inputs (the token's `sub`, `client_id`, `cnf`,
`authorization_details`, and `mission` claim), which the substrate's
Mission-bound credential supplies. A deployment on another Mission
substrate maps that substrate's credential to the same inputs and uses
this binding unchanged.

# Mission-to-Policy Materialization {#mission-to-policy-materialization}

The PDP evaluates a Mission against an action through a materialized
policy view. The materialized policy view, its trusted-compiler and
reproducibility rules, its bounded-fidelity property, and the
content-addressed `policy_view_id` with its `mission-policy-view`
integrity envelope are defined by the runtime profile
({{I-D.draft-mcguinness-mission-runtime}}). That envelope's
committed payload binds the Mission's `mission_id` and `authority_hash`,
so a consistency check between a decision request and the loaded view is
an equality test on those values ({{pdp-request}}). Nothing in this
binding requires the PDP to be remote: a PDP embedded in or colocated
with its PEP, evaluating against a loaded materialized policy view,
is a conforming deployment, and the decision's network cost is then
paid per freshness window rather than per action.

This binding carries only the wire member. `policy_view_id` appears in
the PDP request and response `context` ({{context-mission}},
{{runtime-denial-classification}}) as the content-addressed correlator
between a permit, its evidence, and the view the PDP evaluated against.
This profile does not pick a concrete policy-language wire form for the
materialized view. Implementations MAY use canonical input bundles the
AuthZEN PDP consumes directly, or an engine-native artifact. Compiling
a Mission into an engine-native policy artifact and standardizing a
policy-view carriage format are out of scope
({{I-D.draft-mcguinness-mission-runtime}}).

# PDP Request {#pdp-request}

The PDP request realizes the runtime profile's abstract decision
contract over the OpenID AuthZEN Authorization API {{AUTHZEN}}. AuthZEN
defines a top-level envelope with `subject`, `resource`, `action`, and
`context` members. This profile binds the Mission-bound decision inputs
into that envelope: action-scoped members are carried in
`action.properties`, resource-scoped members in `resource.properties`,
and evaluation-wide members in `context`, per the AuthZEN request
model. It does not change which inputs MUST be evaluated; those are
defined by the runtime profile.

This binding is used after ordinary access-token validation under
{{I-D.draft-mcguinness-mission-runtime}}: the PEP MUST NOT ask a
PDP to authorize an action from unverified token claims, and the
PEP-PDP channel MUST be integrity-protected and mutually authenticated
as that profile requires.

## AuthZEN envelope binding

| AuthZEN member | Mission-bound binding |
|---|---|
| `subject` | The principal the decision is requested for. |
| `resource` | `type`/`id` carry the fine-grained target object identity the action names (for example, a specific journal entry), for Resource-policy evaluation; `properties` carries resource-scoped members, including `audience` ({{context-audience-freshness}}). It is NOT the identity matched against the approved entry's `resource`; see below. |
| `action` | `name` is the requested action identifier (for example, `journal-entries.write`), which the PDP evaluates against the approved `actions` per {{I-D.draft-mcguinness-oauth-mission}}; `properties` carries action-scoped members ({{parameter-digest}}). |
| `context` | Carries the Mission-bound, evaluation-wide context object defined below. |

The runtime profile requires the PDP to confirm that the action falls
within an approved Authority Set entry by matching the action's
resource and action identity against that entry's `resource` and
`actions` ({{I-D.draft-mcguinness-mission-runtime}}). In this
binding, the approved entry's `resource` (the protected-resource or
audience URI, for example `https://erp.example.com`) is matched against
`resource.properties.audience`, not against the AuthZEN `resource`
object's `type`/`id` identity. The AuthZEN `resource` object's `type`
and `id` carry the finer-grained object identity used only for
Resource-policy evaluation. A PDP MUST perform the entry match against
`resource.properties.audience`; matching it against `resource.type` or
`resource.id` is non-conforming and will diverge across deployments.

The AuthZEN `subject` is the token's authenticated `sub`: the Subject
the Mission's authority is exercised for
({{I-D.draft-mcguinness-oauth-mission}}). It does not change under
delegation. The acting agent's `client_id` and any `act` delegation
chain are carried in `context.actor`, never in `subject`. The PDP binds
the permit to `subject` together with the actor context, and the
confused-deputy check ({{I-D.draft-mcguinness-mission-runtime}})
re-verifies that the action is for the same Subject it was authorized
for.

`subject.type` is `user` unless the deployment profiles another value.
`subject.id` is the token's authenticated `sub`. `subject.properties.iss`
is REQUIRED when known ({{conventions-and-definitions}}), carrying the
issuer that authenticated the Subject, so a `sub` is disambiguated
across issuers; a PEP that cannot establish the Subject's issuer omits
it.

## Mission Decision Context {#context-mission}

The `mission` member identifies the governance record and its current
materialized view. It carries authority identity only: current
Mission state and its freshness are carried separately, in
`context.mission_state_observation` ({{context-audience-freshness}}),
so a change in state never mints a new `policy_view_id`
({{mission-to-policy-materialization}}).

`id`:
: REQUIRED. A string. The Mission's `id`.

`issuer`:
: REQUIRED. A string containing a URI. The Mission's `issuer`.

`authority_hash`:
: REQUIRED. A string. The Authority Set integrity
  anchor, in the integrity-anchor encoded form
  ({{I-D.draft-mcguinness-oauth-mission}}).

`policy_version`:
: REQUIRED when known. A string. The `policy_version` recorded at the
  approval event. It is a Mission-record field
  ({{I-D.draft-mcguinness-oauth-mission}}) and is not carried on the
  `mission` claim or the introspection projection, so a PEP that is not
  co-located with the Mission record may not have it; such a PEP omits
  it and relies on `policy_view_id` for view correlation. A PEP that can
  obtain it (for example, co-located with the issuer) includes it.

`policy_view_id`:
: OPTIONAL. A string. The materialized view identifier
  ({{mission-to-policy-materialization}}). The PDP is authoritative for
  the current view, so a PEP need not supply it; a PEP that has the
  value supplies it and the PDP uses it as a content-addressed
  correlator. When present it is checked as in {{pdp-request}}.

This context anchors the Mission's approved Authority Set through
`authority_hash`. Where a Mission participates in a companion that
overlays evaluated authority on top of the approved set, for example
Mission Containment's Effective Authority Set
({{I-D.draft-mcguinness-oauth-mission-containment}}), the PDP
evaluates the request against that overlaid set, not the approved
set alone, per the runtime profile's Authority decision input
({{I-D.draft-mcguinness-mission-runtime}}). This document defines no
member carrying such an overlay's evaluated state. A companion
profile MAY extend the `mission` context with the member it needs,
by specification, mirroring the denial-reason extension rule
({{runtime-denial-classification}}): an extension member name MUST
be a collision-resistant name or a name coordinated within this
document family, and a PDP that does not recognize an extension
member evaluates the approved Authority Set unchanged. A denial
produced against the overlaid set carries the overlay's own denial
reason, not `out_of_authority`: the Containment profile's
`authority_contained` denies capability the Approver granted and the
issuer later removed, a distinct history from capability never
approved
({{I-D.draft-mcguinness-oauth-mission-containment}}).

## Actor Decision Context {#context-actor}

The `actor` member carries the authenticated actor context when
delegation is in effect, reconstructed from the access token's `act`
claim and the token's authenticated client identity per
{{I-D.draft-mcguinness-oauth-mission}}:

`client_id`:
: REQUIRED when known. A string. The authenticated client identity.

`client_instance_id`:
: OPTIONAL. A string. A deployment-defined client-instance correlator
  when the PEP can establish one.

`act`:
: OPTIONAL. An array of objects. The delegation chain projection,
  ordered root to leaf. For a single actor, the array has one member.

The `actor` member carries the delegation chain only. Provenance beyond
the delegation chain (the tool a request invoked, a named workflow
step, a human approver) MUST NOT be encoded inside the `act` chain;
the PDP evaluates the `act` chain as defined by the runtime profile,
and provenance is recorded in dedicated evidence fields where the
deployment captures it.

Where tokens carry instance identity
({{I-D.draft-mcguinness-oauth-client-instance-assertion}}), the `act`
entry this projection already copies carries the instance identifier
and, under the agent profile
({{I-D.draft-mcguinness-oauth-ai-agent-instance}}), issuer-minted
provenance such as `agent_instance_id` and `agent_model`. Fleet
deployments therefore get which-instance-acted attribution in Decision
Evidence and, through the `evaluation_id` link, in Execution Evidence,
without new members.

## Credential Decision Context {#context-credential}

The `credential` member carries token-derived facts the PEP has already
validated and that the PDP needs to enforce the runtime decision's
time, issuer, and sender-constraint checks:

`issuer`:
: REQUIRED when known. A string containing a URI. The token issuer.

`expires_at`:
: REQUIRED when the token carries an expiry. An RFC 3339 {{RFC3339}}
  timestamp corresponding to the token expiry.

`confirmation`:
: OPTIONAL. An object. A sender-constraint confirmation value or
  digest of that value, included only after the PEP has verified the
  proof-of-possession check for the presented token.

The PEP MUST NOT include unverified credential claims in this member.

## Action Parameters and Parameter Digest {#parameter-digest}

When parameter binding is required for the requested action's class
under {{I-D.draft-mcguinness-mission-runtime}}, the PEP supplies, in
the AuthZEN `action` object's `properties` (`action.properties`), the
following action-scoped members:

`parameters`:
: CONDITIONAL. An object. When present, it MUST be the
  operation-profile-normalized parameter object
  ({{I-D.draft-mcguinness-mission-runtime}}): the same bytes the
  `parameter_digest` is computed over, so the PDP's recomputation
  matches. The shape is action-specific. The PEP MAY omit `parameters`
  and supply only `parameter_digest` where the raw values are sensitive
  ({{I-D.draft-mcguinness-mission-runtime-evidence}}), but only when
  the PDP can still enforce
  the applicable parameter policy from the digest, the supplied
  `parameter_attributes`, or local state. If the PDP needs raw parameter
  values to evaluate an applicable constraint and they are supplied
  through neither `parameters` nor the equivalent privacy-preserving
  `parameter_attributes`, it MUST deny with `parameter_violation`.

`parameter_digest`:
: REQUIRED for parameter-bound classes. A string.
  The `parameter_digest` defined by
  {{I-D.draft-mcguinness-mission-runtime}}. This profile carries
  that value on the wire; it does not define a second digest or
  canonicalization. The executing PEP recomputes and
  reverifies the digest immediately before acting, and the PDP
  recomputes it over any supplied `parameters`, both as that section
  requires.

`idempotency_key`:
: CONDITIONAL. A string, distinct from `parameters` and
  `parameter_digest`. The idempotency key the Operation Profile requires
  for a non-idempotent action in the high-consequence classes
  ({{I-D.draft-mcguinness-mission-runtime}}); it identifies one intended
  execution of the normalized action, so a legitimate re-execution mints
  a new key. REQUIRED where the Operation Profile defines one for the
  action. When the key and the normalized parameters match a prior
  decision whose execution outcome is unresolved or completed within the
  reconciliation window, the PDP MUST deny with `duplicate_suppressed`,
  or route to `approval_required`
  ({{runtime-denial-classification}}).

`parameter_attributes`:
: OPTIONAL. An object. Privacy-preserving attributes derived from the
  action parameters that the PEP supplies for constraint evaluation when
  it withholds raw `parameters`
  ({{I-D.draft-mcguinness-mission-runtime-evidence}}). It is the
  wire carriage of the derived attributes the runtime profile's privacy
  carve-out relies on ({{I-D.draft-mcguinness-mission-runtime}}); each
  member is a deployment-defined attribute the applicable constraints
  evaluate against. A constraint the PDP cannot evaluate from
  `parameter_digest`, `parameter_attributes`, or local state MUST fail
  closed ({{pdp-request}}).

## Audience and Mission State Observation {#context-audience-freshness}

`audience`:
: REQUIRED. A string. Carried at `resource.properties.audience`
  ({{pdp-request}}). The PEP's audience or protected-resource
  identifier.

`mission_state_observation`:
: CONDITIONAL. An object, carried at `context.mission_state_observation`.
  REQUIRED where the deployment's declared state-source placement has
  the PEP supply state; absent where state establishment is placed
  with the PDP, whose obligation the PDP-side consistency checks state
  ({{pdp-request}}). It consolidates the PEP's Mission-state
  observation and its freshness into one snapshot, conveying the
  runtime profile's state and freshness inputs on the wire. The PDP's
  own view is authoritative wherever it can consult a Mission state
  source directly ({{pdp-request}}); this object is the fallback
  carrier for a PEP-supplied observation, never a substitute for a
  state source the PDP can itself consult. Members:

    `state`:
    : REQUIRED. A string. The current Mission lifecycle state the PEP
      established from its Mission state source
      ({{I-D.draft-mcguinness-mission-runtime}}).

    `version`:
    : OPTIONAL. An integer. The Mission's state version as the status
      profile defines it ({{I-D.draft-mcguinness-oauth-mission-status}}),
      populated where the PEP holds it. It lets the PDP compare the
      PEP's observation against the PDP's own tracked
      `mission_state_version` ({{response-context}}) and treat a
      mismatch as staleness; it is never compared against
      `policy_view_id`, which commits to authority only
      ({{mission-to-policy-materialization}}).

    `mode`:
    : REQUIRED. A string. One of `fresh`, `cached`, or `event_driven`
      ({{mission-status-composition}}).

    `freshness_at`:
    : REQUIRED in every mode. An RFC 3339 {{RFC3339}} timestamp. When the
      PEP's view of the Mission state was current.

    `mission_status_issued_at`:
    : REQUIRED for `cached` and `event_driven`, OPTIONAL for `fresh`. An
      RFC 3339 timestamp. When the relied-on Mission state was issued.

    `mission_status_expires_at`:
    : REQUIRED for `cached` and `event_driven`, OPTIONAL for `fresh`. An
      RFC 3339 timestamp. When the relied-on Mission state (or its
      lease) expires.

    `assertion`:
    : OPTIONAL. A string. The signed Mission Status Response
      {{I-D.draft-mcguinness-oauth-mission-status}} the PEP obtained
      `state` and `version` from, when the PEP holds one, so the PDP
      can verify the snapshot instead of trusting an unsigned PEP
      assertion.

The deployment's maximum staleness bound, and the rule that a
consequential action MUST fail closed when the Mission cannot be
established as `active` within that bound, are defined by the runtime
profile ({{I-D.draft-mcguinness-mission-runtime}});
`mission_state_observation` is only their wire representation.

## External-Communication Context {#context-external-communication}

The external-communication predicate is parameter-dependent: whether an
action carries data outside the deployment's trust boundary depends on
the concrete request parameters, not on the action class alone
({{I-D.draft-mcguinness-mission-runtime}}), so the PDP has no class-only
way to recognize one. It is therefore an action-scoped member, carried
at `action.properties.external_communication` alongside the other
action parameter members ({{parameter-digest}}). The PEP, at the last
controllable boundary, computes the predicate from the request
parameters and marks the action:

`external_communication`:
: CONDITIONAL. A boolean. `true` when the PEP determines, from the
  request parameters at the last controllable boundary, that the action
  carries data to a recipient outside the deployment's trust boundary
  ({{I-D.draft-mcguinness-mission-runtime}}). REQUIRED for every action
  in a class for which the deployment declares PDP-enforced taint, so
  the taint requirement has a deterministic PDP-side trigger; OPTIONAL
  otherwise.

## Taint Context {#context-taint}

The OPTIONAL `taint` member carries the harness's untrusted-content
determination ({{I-D.draft-mcguinness-mission-harness}}) for the
requested action, when the deployment routes taint enforcement
through the PDP, as the value of `context.taint`:

~~~ json
{
  "tainted": true,
  "granularity": "parameter",
  "source_class": "web_fetch"
}
~~~

`tainted`:
: REQUIRED when `taint` is present. A boolean. Whether a bound
  parameter of the action derives from tainted content (under
  `granularity` `parameter`) or tainted content has entered the
  governed session (under `granularity` `session`).

`granularity`:
: REQUIRED when `taint` is present. A string, `parameter` or
  `session`: the trigger granularity the harness established.

`source_class`:
: OPTIONAL. A string. The deployment-defined class of the tainting
  source (for example, `web_fetch`, `inbound_message`,
  `third_party_document`), for policy and evidence.

Absence of `taint` means the harness did not route the determination
through the decision request, not that the action is untainted; the
harness's own egress rule then applies. That reading is confined to
harness-enforced deployments. When the deployment's Enforcement Scope
Statement declares PDP-enforced taint for an action class
({{I-D.draft-mcguinness-mission-runtime}}):

- The PDP MUST require `context.taint` on every decision in that class
  whose `action.properties.external_communication` is `true`
  ({{context-external-communication}}) or whose `action_class` is
  `external_commitment`, and MUST deny with `taint_context_missing`
  when it is absent.
- When `taint` is present with `tainted` true on such an action, the
  PDP MUST deny or return `approval_required`
  ({{runtime-denial-classification}}) unless a fresh action-bound
  approval bound to the action's parameters is present in the decision
  context.
- The PDP MUST record the presented taint context in Decision
  Evidence.

## Approval Context {#context-approval}

The OPTIONAL `approval` member is carried at `context.approval` on a
fresh evaluation after an access request is approved. The PEP returns
here exactly the approval object the Access Request Service issued:
ARAP's approval object {{ARAP}} unchanged, with all of ARAP's
members, including its REQUIRED `approved_until`. This profile does
not subset or rename it.

On top of ARAP's own requirements, before treating `context.approval`
as satisfying `approval_required`, the PDP MUST additionally
establish the Mission checks: that the approval binds to the
request's `parameter_digest` (a mismatch means the approval does not
cover these parameters), that its grant time is within the
deployment's maximum approval age
({{I-D.draft-mcguinness-mission-runtime}}), and that `approved_until`
has not passed. An approval failing any of these checks does not
satisfy the denial. The PDP MUST record the presented approval `id`
in Decision Evidence. The approval is an input attribute, never a
bearer grant: the PDP evaluates current policy and current state.

When policy requires an action-bound approval and no valid
`context.approval` satisfies the checks above, the PDP MUST deny with
`approval_required` ({{runtime-denial-classification}}).

## History Context {#context-history}

Which history predicates a decision requires is a policy decision:
the materialized policy view, or the PDP's own policy, names the
predicates it evaluates for the action. The request does not select
them; a requester able to choose which history a decision turns on
could pick predicates favorable to it. This document defines one
predicate type policy MAY name, `action_class_completed`: satisfied
when the PDP's evidence store holds, for the established Mission, at
least one Decision Evidence record with `decision` `permit` and a
named `action_class`, and every such record has a linked Execution
Evidence record ({{I-D.draft-mcguinness-mission-runtime-evidence}})
whose `outcome` is `completed`. An extension predicate type MUST be either a
collision-resistant name or a name coordinated within this document
family, under the same rule as denial reasons
({{runtime-denial-classification}}). A policy-selected predicate
naming `action_class_completed` carries an `action_class`: a runtime
action class name, from the same value space as the Decision Evidence
`action_class` member
({{I-D.draft-mcguinness-mission-runtime-evidence}}). For a migration
Mission whose copy steps are consequential writes, policy names the
delete step's precondition this way:

~~~ json
{
  "predicate": "action_class_completed",
  "action_class": "consequential_write"
}
~~~

The OPTIONAL `mission_history` member carries only what the PEP can
supply in support of the policy-selected predicates, never a
selection of which predicates apply. Members:

`evidence_reference`:
: OPTIONAL. A string. A reference to the evidence or state source the
  PEP consulted, when that source is not the PDP's own evidence
  store, so the PDP can resolve the same history the PEP saw.

`attribute_values`:
: OPTIONAL. An object. Precomputed values for the policy-selected
  predicates, supplied where the deployment permits the PEP to
  compute them directly, mirroring the privacy-preserving carve-out
  for action parameters ({{parameter-digest}}); each member is a
  deployment-defined attribute the applicable predicate evaluates
  against.

The PDP evaluates each policy-selected predicate against its own
evidence store, or, where the deployment's policy permits a
non-default evidence source, against the supplied
`evidence_reference` or `attribute_values`. A caller-supplied
`mission_history` value is never itself evidence of a predicate's
outcome, and carries no result member; the PDP MUST NOT accept a
predicate outcome asserted through any context member.

The PDP MUST refuse the evaluation of a policy-selected predicate it
does not recognize, treating the predicate as not establishable,
consistent with this binding's unknown-value conventions
({{runtime-denial-classification}}). Where deployment or Resource
policy requires a history predicate that is unsatisfied or cannot be
established, the PDP MUST deny with
`history_not_satisfied` ({{runtime-denial-classification}}); the
runtime profile fixes the fail-closed posture and the evidence
store's freshness discipline
({{I-D.draft-mcguinness-mission-runtime}}). The PDP MUST record the
evaluated predicates and their outcomes in Decision Evidence
({{I-D.draft-mcguinness-mission-runtime-evidence}}).

## Worked PDP request

The `policy_view_id` values in this document's examples
(`sha-256:kP3xR9sQ...`) differ from the runtime profile's worked
materialized-view value (`sha-256:fuMqn6Nb...`): this deployment's
view payload includes the engine-evaluable form, so it hashes
differently. Both are valid views of the same Mission.

For the ERP reconciliation Mission:

~~~ http-message
POST /pdp/access/v1/evaluation HTTP/1.1
Host: pdp.example.com
Content-Type: application/json
Authorization: ...

{
  "subject": {
    "type": "user",
    "id": "user_3p2q8mN1a0kV7tR",
    "properties": {
      "iss": "https://idp.example.com"
    }
  },
  "resource": {
    "type": "journal-entry",
    "id": "je_2026Q3_inv_8421",
    "properties": {
      "audience": "https://erp.example.com"
    }
  },
  "action": {
    "name": "journal-entries.write",
    "properties": {
      "parameters": {
        "amount_usd": "423.50",
        "source_invoice_id": "inv_2026Q3_842"
      },
      "parameter_digest":
        "sha-256:WPVi6EnQ7H9Fh-qk9ADxmTg8zruOdVUX1esl-v3TfCI"
    }
  },
  "context": {
    "mission": {
      "id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
      "issuer": "https://as.example.com",
      "authority_hash":
        "sha-256:l3KvZ4mP5x0wQrR6tY2nD9bM7sX1cF8gH2vJ4kE5pNQ",
      "policy_version": "deploy-policy:v17",
      "policy_view_id":
        "sha-256:kP3xR9sQ7nM2vL4tY6bD1eF8jC5wH0pV2nR3kQ4mZ7t"
    },
    "mission_state_observation": {
      "state": "active",
      "mission_status_issued_at": "2026-11-02T08:14:00Z",
      "mission_status_expires_at": "2026-11-02T08:15:00Z",
      "mode": "cached",
      "freshness_at": "2026-11-02T08:14:00Z"
    },
    "actor": {
      "client_id": "s6BhdRkqt3",
      "client_instance_id": "inst_macbook_7f3a",
      "act": [
        {
          "iss": "https://as.example.com",
          "sub": "s6BhdRkqt3"
        }
      ]
    },
    "credential": {
      "issuer": "https://as.example.com",
      "expires_at": "2026-11-02T09:14:00Z"
    }
  }
}
~~~

## PDP-side consistency checks

A PDP that also serves non-Mission AuthZEN traffic MUST NOT downgrade:
for an action within a runtime enforcement scope it mediates, a request
whose `context` lacks the `mission` member ({{context-mission}}) is
malformed under this binding, and the PDP MUST refuse it rather than
evaluate it against non-Mission policy alone. A permit issued to an
in-scope consequential action without Mission evaluation is an
enforcement bypass, not a decision
({{I-D.draft-mcguinness-mission-runtime}}).

In addition to evaluating the decision inputs the runtime profile
requires, the PDP MUST verify that the AuthZEN-carried envelope is
self-consistent:

1. When present, the Mission state conveyed in
   `context.mission_state_observation.state` is exactly `active`; every
   other value, recognized or not, is non-active per the issuance
   profile's forward-compatibility rule
   ({{I-D.draft-mcguinness-oauth-mission}}) and the PDP returns
   `mission_inactive` ({{runtime-denial-classification}}). Where state
   establishment is placed with the PDP and the member is absent
   ({{context-audience-freshness}}), the PDP MUST establish state from
   its own source or deny with `stale_state`. A PDP with direct access
   to a Mission state source MUST prefer its own fresher view over
   `context.mission_state_observation.state`, and MUST return
   `mission_inactive` when its view disagrees with the PEP-supplied
   state. PEP-supplied state is a floor, never a substitute for a state
   source the PDP can itself consult.
2. The `id` and `authority_hash` in `context.mission` equal the
   `mission_id` and `authority_hash` committed in the materialized
   policy view the PDP has loaded for this Mission
   ({{I-D.draft-mcguinness-mission-runtime}}); the PDP returns
   `view_inconsistent` on any inequality.
3. When `context.mission.policy_view_id` is present, it MUST equal
   the loaded view's `policy_view_id`, and the PDP returns
   `view_inconsistent` on inequality.
4. When `context.mission_state_observation.version` is present, the
   PDP compares it against its own tracked `mission_state_version`
   ({{response-context}}), never against `policy_view_id`, which
   commits to authority only ({{mission-to-policy-materialization}}),
   and treats a mismatch as staleness (`stale_state`): one side has
   missed a committed change.
5. A PDP MUST NOT fail a decision solely because the optional
   `policy_view_id` or `policy_version` was omitted; the view the PDP
   loaded is authoritative.
6. When `context.credential.expires_at` is present, it has not passed;
   otherwise the PDP returns `credential_invalid`.
7. The freshness conveyed in `context.mission_state_observation` the
   PEP supplied is within the deployment's staleness bound; otherwise
   the PDP returns `stale_state`, with the freshness-window violation
   in the denial reason.
8. For an action whose class requires parameter binding
   ({{I-D.draft-mcguinness-mission-runtime}}),
   `action.properties.parameter_digest` MUST be present; if it is
   absent the PDP returns `parameter_violation`. When
   `action.properties.parameters` is also present, the PDP-recomputed
   digest MUST match `action.properties.parameter_digest`, otherwise
   `parameter_violation`. When `parameters` is omitted under the
   privacy carve-out ({{parameter-digest}}), the PDP MUST still be able
   to evaluate every applicable parameter constraint from the digest,
   the supplied `action.properties.parameter_attributes`, or local
   state, and returns `parameter_violation` if it cannot. A
   parameter-bound action MUST NOT be permitted without a verified
   `parameter_digest`.
9. A deployment adopting Mission Capability Binding applies that
   companion's source checks and its `capability_drift` extension
   reason ({{I-D.draft-mcguinness-mission-capability-binding}}); this
   binding consumes an already established action identity.

## Clock skew {#clock-skew}

The time comparisons this binding performs (a permit's
mission-execution obligation `expires_at` at the PEP, {{obligations}},
the `context.mission_state_observation` freshness window and
`context.credential.expires_at` at the PDP, and the approval maximum
age, {{context-approval}}) MAY allow
a small leeway to absorb
clock skew between the components. Any leeway MUST NOT exceed the
deployment's maximum clock skew, and the deployment MUST publish that
maximum-skew assumption in its Enforcement Scope Statement
({{I-D.draft-mcguinness-mission-runtime}}). A value outside its window
by more than the published maximum skew MUST fail closed: an expired
permit, a stale freshness window, or an expired credential is refused,
and the leeway never extends a permit lease or freshness lease beyond
its bound plus the published skew.

## Batch evaluations {#batch-evaluations}

The AuthZEN evaluations (boxcar) endpoint MAY be used to submit several
Mission-bound decisions in one request. Batching is a transport
optimization and changes none of the per-item enforcement semantics:
each item is evaluated independently and on the same terms as a single
request.

- Each item yields its own Decision Evidence Object
  ({{I-D.draft-mcguinness-mission-runtime-evidence}}) with its own
  `evidence_id` and `sequence`, assigned in request order.
- Any metered bounds apply per item in request order
  ({{I-D.draft-mcguinness-mission-metering}}).
- Permits are per item, so a boxcar MAY return a mix of permits and
  denials.
- This profile requires `execute_all` semantics: every item MUST be
  evaluated independently, on the same terms as a single request,
  regardless of an earlier item's decision. A PDP MUST reject, as an
  AuthZEN request error rather than a silent downgrade, a request
  whose recognized `options` ask for `deny_on_first_deny`,
  `permit_on_first_permit`, or any other recognized short-circuit or
  fail-fast semantics. An `options` member the PDP does not recognize
  follows AuthZEN's own rules for unrecognized options.

A batch request for two journal-entry writes under the ERP
reconciliation Mission, where the second exceeds the entry's
`max_amount` ceiling of 500.00 USD. The shared `subject` is hoisted
to the request's default members per {{AUTHZEN}}; each item carries its
complete `context`:

~~~ http-message
POST /pdp/access/v1/evaluations HTTP/1.1
Host: pdp.example.com
Content-Type: application/json
Authorization: ...

{
  "subject": {
    "type": "user",
    "id": "user_3p2q8mN1a0kV7tR",
    "properties": {
      "iss": "https://idp.example.com"
    }
  },
  "evaluations": [
    {
      "resource": {
        "type": "journal-entry",
        "id": "je_2026Q3_inv_8421",
        "properties": {
          "audience": "https://erp.example.com"
        }
      },
      "action": {
        "name": "journal-entries.write",
        "properties": {
          "parameters": {
            "amount_usd": "423.50",
            "source_invoice_id": "inv_2026Q3_842"
          },
          "parameter_digest":
            "sha-256:WPVi6EnQ7H9Fh-qk9ADxmTg8zruOdVUX1esl-v3TfCI"
        }
      },
      "context": {
        "mission": {
          "id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
          "issuer": "https://as.example.com",
          "authority_hash":
            "sha-256:l3KvZ4mP5x0wQrR6tY2nD9bM7sX1cF8gH2vJ4kE5pNQ"
        },
        "mission_state_observation": {
          "state": "active",
          "mode": "fresh",
          "freshness_at": "2026-11-02T08:14:00Z"
        },
        "actor": { "client_id": "s6BhdRkqt3" },
        "credential": {
          "issuer": "https://as.example.com",
          "expires_at": "2026-11-02T09:14:00Z"
        }
      }
    },
    {
      "resource": {
        "type": "journal-entry",
        "id": "je_2026Q3_inv_9310",
        "properties": {
          "audience": "https://erp.example.com"
        }
      },
      "action": {
        "name": "journal-entries.write",
        "properties": {
          "parameters": {
            "amount_usd": "780.00",
            "source_invoice_id": "inv_2026Q3_931"
          },
          "parameter_digest":
            "sha-256:mzFwtXAT6_hY0v8_NFHMDJG39HFuWY2fRcOCSFGDyyE"
        }
      },
      "context": {
        "mission": {
          "id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
          "issuer": "https://as.example.com",
          "authority_hash":
            "sha-256:l3KvZ4mP5x0wQrR6tY2nD9bM7sX1cF8gH2vJ4kE5pNQ"
        },
        "mission_state_observation": {
          "state": "active",
          "mode": "fresh",
          "freshness_at": "2026-11-02T08:14:00Z"
        },
        "actor": { "client_id": "s6BhdRkqt3" },
        "credential": {
          "issuer": "https://as.example.com",
          "expires_at": "2026-11-02T09:14:00Z"
        }
      }
    }
  ]
}
~~~

The response returns one decision per item, in request order; the
first is a permit and the second a `parameter_violation` deny, whose
failing `max_amount` key is listed in that item's Decision
Evidence `contributing_constraints`:

~~~ json
{
  "evaluations": [
    {
      "decision": true,
      "context": {
        "evaluation_id": "dec_2FpQ8kV5nR1tX7mB4sJ9eL6wYc",
        "action_class": "irreversible_action",
        "class_source": "deployment",
        "parameter_digest":
          "sha-256:WPVi6EnQ7H9Fh-qk9ADxmTg8zruOdVUX1esl-v3TfCI",
        "policy_view_id":
          "sha-256:kP3xR9sQ7nM2vL4tY6bD1eF8jC5wH0pV2nR3kQ4mZ7t",
        "obligations": [
          {
            "id": "obl_execution",
            "type": "mission-execution",
            "properties": {
              "request_digest":
                "sha-256:WPVi6EnQ7H9Fh-qk9ADxmTg8zruOdVUX1esl-v3TfCI",
              "expires_at": "2026-11-02T08:15:00Z",
              "use_limit": 1,
              "execution_evidence": "required"
            }
          }
        ]
      }
    },
    {
      "decision": false,
      "context": {
        "evaluation_id": "dec_6JwN3xT9rQ4mV8kP1sB5eZ2yLd",
        "reason": "parameter_violation",
        "action_class": "irreversible_action",
        "class_source": "deployment",
        "parameter_digest":
          "sha-256:mzFwtXAT6_hY0v8_NFHMDJG39HFuWY2fRcOCSFGDyyE",
        "policy_view_id":
          "sha-256:kP3xR9sQ7nM2vL4tY6bD1eF8jC5wH0pV2nR3kQ4mZ7t"
      }
    }
  ]
}
~~~

## Timeouts, Retries, and Overload {#transport-behavior}

An evaluation exchange carries metered and single-use consequences,
so its transport behavior is specified, not assumed:

- A PEP MUST bound each evaluation call with a timeout inside the
  action class's staleness budget and treat expiry as
  `pdp_unreachable`
  ({{I-D.draft-mcguinness-mission-runtime-evidence}}): fail closed,
  never a permit.
- A PEP MAY retry an evaluation whose response was lost, carrying
  the same normalized parameters and idempotency key. The runtime
  profile's retransmission rule then returns the prior decision
  where its permit is unexpired and unconsumed
  ({{I-D.draft-mcguinness-mission-runtime}}), and metering MUST NOT
  charge the bound twice for the retried request
  ({{I-D.draft-mcguinness-mission-metering}}).
- A PDP under overload sheds load explicitly with HTTP 429 and
  `Retry-After`. This is transport backpressure, not an authorization
  result: the PEP MUST NOT retry before `Retry-After` elapses, and
  when no decision is obtainable within its policy window it fails
  closed as `pdp_unreachable` under the runtime profile. A successful
  evaluation that denies transiently is expressed with
  `context.next_action: retry` ({{response-context}}), never as an
  HTTP error.
- A PDP MAY publish a maximum batch size and refuse an oversized
  boxcar with HTTP 413; the PEP splits the batch rather than
  dropping items.

# PDP Response {#pdp-response}

The PDP returns its permit or denial in the AuthZEN response
{{AUTHZEN}}: a boolean `decision` and an optional `context` object.
Runtime denials are successful evaluations and are represented as
`decision: false` with the context members below, not as transport
errors. This section defines the response context members, the
obligations lane for mandatory PEP work under a permit, the permit and
denial response shapes, the denial-reason classification with its
complete coverage of the runtime profile's failure conditions, and the
rules that keep a permit bound to the PEP, channel, and inputs it was
issued for.

## Response decision context {#response-context}

This profile defines the following AuthZEN response `context` members:

`evaluation_id`:
: REQUIRED. A string. The correlation identifier for this evaluation,
  ARAP's `evaluation_id` {{ARAP}}. ABNF:
  `1*64( ALPHA / DIGIT / "-" / "_" )`. At least 128 bits of entropy.
  Decision Evidence records this same value as its own `evaluation_id`
  member, alongside the evidence record's distinct `evidence_id`
  ({{I-D.draft-mcguinness-mission-runtime-evidence}}).

`evaluated_at`:
: OPTIONAL. An RFC 3339 {{RFC3339}} timestamp of the evaluation,
  ARAP's `evaluated_at` member {{ARAP}}. RECOMMENDED on a denial that
  carries `access_request` or `next_action`.

`reason`:
: REQUIRED when `decision` is `false`. A string from the set of
  {{runtime-denial-classification}}, including any
  specification-defined extension under that section's extensibility
  rule; a consumer MUST treat an unrecognized value as a deny and MUST
  NOT attach any other semantics to it. A constraint violation uses
  `parameter_violation`; the specific failing `constraints` keys are
  carried in the Decision Evidence `contributing_constraints`, not here.
  `reason` is ARAP's response member ({{ARAP}}); the value set below
  includes ARAP's `approval_required`.

`action_class`:
: REQUIRED. A string. The runtime action class the PDP applied, from
  the value set of {{I-D.draft-mcguinness-mission-runtime-evidence}},
  so the PEP can verify
  it is enforcing that class's permit controls. When the PEP has itself
  established a stricter class for the action, from its deployment
  classification or a resource floor it knows
  ({{I-D.draft-mcguinness-mission-runtime}}), the PEP MUST enforce the
  stricter class's permit controls; for a high-consequence class that
  includes refusing a permit whose mission-execution obligation
  ({{obligations}}) lacks `use_limit: 1`.

`class_source`:
: REQUIRED when `action_class` is present. A string. One of `default`,
  `resource_floor`, or `deployment`
  ({{I-D.draft-mcguinness-mission-runtime-evidence}}).

`parameter_digest`:
: REQUIRED when the request was parameter-bound. A string. The digest
  bound to the decision.

`policy_view_id`:
: REQUIRED. A string. The materialized policy view the PDP evaluated.
  The PDP is authoritative for the view, so it always knows and returns
  this value.

`mission_state_version`:
: OPTIONAL. An integer. The Mission's state version, as the status
  profile defines it ({{I-D.draft-mcguinness-oauth-mission-status}}),
  that the PDP applied to this decision. Present when the PDP tracks
  Mission state version. Distinct from `policy_view_id`, which
  identifies compiled authority only and never commits to state
  ({{mission-to-policy-materialization}}).

`obligations`:
: REQUIRED when `decision` is `true` for a consequential action; MAY
  also accompany a denial. An array of obligation objects
  ({{AUTHZEN-OBL}}). On a permit, the PEP MUST fulfill every obligation
  before releasing the action's effect and MUST treat an unrecognized
  or unfulfillable obligation as an effective deny. On a denial, the
  PEP MUST still deny the action and MUST additionally execute every
  returned obligation; an obligation on a denial confers nothing and
  does not make the denial a permit ({{obligations}}).

`access_request`:
: OPTIONAL. An object. Present on an `out_of_authority` or
  `approval_required` denial when the deployment exposes it as
  requestable under {{ARAP}}. Its members are ARAP's requestable-denial
  context verbatim: the submission `endpoint`, the ARAP-required
  `expires_at`, `evaluation_id`, and the PDP-signed `binding_token`.
  Its presence does not change the `decision: false` result and does
  not grant access.

`next_action`:
: OPTIONAL on a denial. A string: `request`, `retry`, or `none`
  ({{ARAP}}). `request` MUST be accompanied by a fresh
  `context.access_request`. `retry` marks the denial transient: the
  same request is expected to succeed on re-evaluation after a delay.
  `none` marks it terminal for policy and local action alike. ARAP
  defines `next_action` for the denial of a re-evaluation that
  presented an approval; this profile extends it, with identical
  semantics, to any denial.

`retry_after`:
: OPTIONAL, only with `next_action: retry`. An integer: seconds the
  PEP waits before re-evaluating ({{ARAP}}).

No mode leaves the permit window unbounded on the wire. The
mission-execution obligation's `expires_at` property ({{obligations}})
MUST NOT be later than the freshness time or lease of the Mission
state view the decision relied on
({{I-D.draft-mcguinness-mission-runtime}}); in particular, it MUST NOT
be later than a supplied
`context.mission_state_observation.mission_status_expires_at`. In
`fresh` mode with no supplied `mission_status_expires_at`, the PDP
derives the bound from its own state view: the view's freshness time
or lease where the source reports one, otherwise the deployment's
published staleness bound for the action's class.

## Obligations {#obligations}

An obligation is mandatory PEP work under the existing decision,
whichever it is. It confers no authority, has no approver, and
creates no governance state. An obligation MAY accompany a permit or
a denial ({{response-context}}): on a permit the PEP MUST fulfill
each obligation before releasing the action's effect; on a denial the
PEP MUST still deny the action and MUST additionally execute every
returned obligation. Failure to fulfill an obligation, or an
unrecognized obligation type, makes the effective result deny, and
for an already-released action the failure MUST be recorded in
Execution Evidence ({{I-D.draft-mcguinness-mission-runtime-evidence}}).

A PDP supporting this profile advertises `step-up` and
`mission-execution` in its metadata `supported_obligations` array,
and a PEP MAY declare its own `supported_obligations` in the request
context, as the obligations profile defines {{AUTHZEN-OBL}}; the
declaration is advisory. A PDP MUST NOT rely on an obligation the
PEP has not declared or is not required to support: this profile's
conformance floor requires every conforming PEP to support both
`step-up` and `mission-execution` unconditionally ({{conformance}});
for any other obligation type, the PDP relies on it only when the
PEP has declared it.

The PDP MAY attach the {{AUTHZEN-OBL}} step-up obligation
(authentication-context properties such as `acr_value` and
`amr_values`, per that profile) to a permit when Resource policy
requires a stronger authentication context than the actor presents.
The PEP MUST achieve the required context before release; on an OAuth
resource surface it does so through RFC 9470 step-up authentication
{{RFC9470}} at the protected resource. Step-up is not a denial reason
in this profile. The core's `mission_denial` value `step_up_required`
remains the Resource Server's own challenge-surface signal
({{I-D.draft-mcguinness-oauth-mission}}) and composes with, but is
not, this obligation. The requirement is Resource policy, never a
Mission constraint: the issuance profile's `acr` is an approval-time
requirement on the Approver, recorded on the Mission and neither
carried on derived tokens nor evaluated per action, and the issuance
profile defines no per-action `amr` constraint
({{I-D.draft-mcguinness-oauth-mission}}).

This profile defines one composite obligation for permit enforcement,
the mission-execution obligation. Its properties divide into
preconditions, each of which MUST be satisfied or enforced before the
PEP releases the action's effect, and one postcondition, which
completes only once the action's outcome is known:

~~~
{
  "id": "obl_execution",
  "type": "mission-execution",
  "properties": {
    "request_digest": "sha-256:...",
    "expires_at": "2026-11-02T08:15:00Z",
    "use_limit": 1,
    "execution_evidence": "required"
  }
}
~~~

Preconditions: `request_digest` equals the decision's
`parameter_digest` when the request was parameter-bound, and the PEP
MUST enforce the exact request binding; `expires_at` is the permit
lease (bounding rules in {{response-context}}), past which the permit
MUST NOT be used; `use_limit` is an integer consumption bound on
`evaluation_id` (for an action in the high-consequence classes
({{I-D.draft-mcguinness-mission-runtime}}) the PDP MUST set
`use_limit: 1` and the PEP MUST treat a high-consequence permit
lacking it as invalid; absent, the permit carries no PDP-enforced use
limit; this replaces the former `single_use` boolean). The PEP MUST
NOT release the action's effect while any precondition above is
unsatisfied.

Postcondition: `execution_evidence: "required"` obliges the PEP to
emit the Execution Evidence Object
({{I-D.draft-mcguinness-mission-runtime-evidence}}) once, and only
once, the action's outcome exists. If evidence emission fails after an irreversible
effect, the effect stands: nothing retroactively permits or denies
it. The PEP MUST record the emission failure durably and surface it
on its operational alarm path, and the deployment's audit posture
treats the execution as unevidenced. Where the deployment's
transaction assurance depends on that later evidence
({{I-D.draft-mcguinness-mission-runtime}}), the PEP MUST durably
reserve evidence capacity for the execution, an evidence reservation,
before acting, and MUST fail closed when the reservation cannot be
made.

This obligation MUST NOT carry human approval, role or relationship
creation, Mission expansion, a task handle, residual policy, or retry
instructions; `evaluation_id` and evaluation timestamps are decision
facts outside it. Obligation-array ordering is not normative, which is
why these controls travel as one composite obligation rather than as
separately ordered entries.

This profile defines no advice collection. A future `context.advice`
carrying safely-ignorable instructions is reserved; an obligation MUST
NOT be marked optional or downgraded to advice, and execution binding,
permit expiry, use limits, evidence emission, step-up, and mandatory
notification are never advice.

## Permit response shape

When the PDP permits an action, it returns AuthZEN `decision: true` and
the context needed by the PEP to enforce the permit. The
`evaluation_id`, `policy_view_id`, and any `parameter_digest` bind the
response to the Decision Evidence and to the request inputs the PDP
evaluated. `obligations` carries the permit lifetime controls required
by the runtime profile in the mission-execution obligation
({{obligations}}).

~~~ json
{
  "decision": true,
  "context": {
    "evaluation_id": "dec_8K2nP4qV9rL3tY6sB1zN0eF7jB",
    "action_class": "irreversible_action",
    "class_source": "deployment",
    "parameter_digest":
      "sha-256:WPVi6EnQ7H9Fh-qk9ADxmTg8zruOdVUX1esl-v3TfCI",
    "policy_view_id":
      "sha-256:kP3xR9sQ7nM2vL4tY6bD1eF8jC5wH0pV2nR3kQ4mZ7t",
    "obligations": [
      {
        "id": "obl_execution",
        "type": "mission-execution",
        "properties": {
          "request_digest":
            "sha-256:WPVi6EnQ7H9Fh-qk9ADxmTg8zruOdVUX1esl-v3TfCI",
          "expires_at": "2026-11-02T08:15:00Z",
          "use_limit": 1,
          "execution_evidence": "required"
        }
      }
    ]
  }
}
~~~

## Denial response shape {#denial-response}

A runtime denial is returned as `decision: false` with the context
members above:

~~~ json
{
  "decision": false,
  "context": {
    "evaluation_id": "dec_5WcR2mT8xN4qV7kB1sJ6eL9yPd",
    "reason": "stale_state",
    "action_class": "irreversible_action",
    "class_source": "deployment",
    "policy_view_id":
      "sha-256:kP3xR9sQ7nM2vL4tY6bD1eF8jC5wH0pV2nR3kQ4mZ7t"
  }
}
~~~

The same condition, where the PDP marks the denial transient:

~~~ json
{
  "decision": false,
  "context": {
    "evaluation_id": "dec_5WcR2mT8xN4qV7kB1sJ6eL9yPd",
    "reason": "stale_state",
    "action_class": "irreversible_action",
    "class_source": "deployment",
    "policy_view_id":
      "sha-256:kP3xR9sQ7nM2vL4tY6bD1eF8jC5wH0pV2nR3kQ4mZ7t",
    "next_action": "retry",
    "retry_after": 10
  }
}
~~~

A successful evaluation that denies transiently carries `next_action`,
never an HTTP error.

Malformed requests, authentication failures, or PDP processing errors
that prevent evaluation MAY be returned as AuthZEN or transport-level
errors; so is an in-scope request refused for missing Mission context
({{pdp-request}}). A deployment MAY additionally carry {{RFC9457}}
problem details for structured error information when the PDP is
consumed over HTTP outside the AuthZEN envelope.

## Runtime Denial Classification {#runtime-denial-classification}

When the PDP denies a consequential action, the failure condition is
one defined by the runtime profile. This section binds those
conditions to AuthZEN responses and gives the denial-reason identifiers
carried in Decision Evidence:

- `out_of_authority`: the action is not within the Authority Set.
- `approval_required`: deployment or Resource policy requires an
  action-bound approval for this action
  ({{I-D.draft-mcguinness-mission-runtime}}) and a valid fresh
  approval bound to the action's parameters is not present, is older
  than the deployment's maximum approval age, or is bound to a different
  `parameter_digest`. The PEP carries any such approval in
  `context.approval` ({{context-approval}}); this profile does
  not define the approval artifact, which the runtime profile owns.
- `taint_context_missing`: the deployment declares PDP-enforced taint
  for the action's class and the decision request carries no
  `context.taint` ({{context-taint}}).
- `stale_state`: the PEP-supplied freshness is outside the deployment's
  staleness bound (a freshness-window violation). While the condition
  is expected to clear on a fresh read, the PDP SHOULD mark the denial
  transient with `next_action: retry` ({{response-context}}).
- `view_inconsistent`: the request's Mission `id`, `authority_hash`, or
  `policy_view_id` does not equal the committed values in the
  materialized policy view the PDP loaded, so the request and the loaded
  view disagree on which Mission or view is in force. This is a view
  inconsistency, not staleness.
- `mission_inactive`: the Mission state is not `active`.
- `mission_binding_failed`: in externally-established Mission binding
  mode ({{I-D.draft-mcguinness-mission-runtime}}), the PDP could not
  verify the supplied Mission reference against the acting credential
  under the binding's join, so no Mission is established.
- `actor_invalid`: the required `act` chain is missing or malformed, so
  the PDP cannot establish the runtime actor context
  ({{I-D.draft-mcguinness-mission-runtime}}).
- `credential_invalid`: token-derived credential facts supplied by the
  PEP are expired, inconsistent, or otherwise not usable for a runtime
  decision.
- `parameter_violation`: parameters violate a constraint the PDP
  evaluated, the recomputed digest does not match, or a required
  `parameter_digest` is absent for a parameter-bound action.
- `duplicate_suppressed`: the request's `idempotency_key` and normalized
  parameters match a prior decision whose execution outcome is
  unresolved or completed within the reconciliation window, so the PDP
  suppresses a duplicate execution of the same normalized action
  ({{I-D.draft-mcguinness-mission-runtime}}). The PDP MAY instead route
  to `approval_required`. While the condition is expected to clear (an
  unresolved prior outcome), the PDP SHOULD mark the denial transient
  with `next_action: retry` ({{response-context}}).
- `resource_policy`: Resource policy refuses the action independently
  of Mission authority.
- `quota_exceeded`: a metered runtime bound is exhausted. The runtime
  profile fixes the fail-closed posture for consumption bounds
  ({{I-D.draft-mcguinness-mission-runtime}}); the metering semantics
  and settlement exchange are defined by the experimental metering
  companion ({{I-D.draft-mcguinness-mission-metering}}).
- `unsupported_authorization_type`: the action targets an
  `authorization_details` type the PDP does not understand or cannot
  enforce, so it refuses rather than guess the type's semantics
  ({{I-D.draft-mcguinness-mission-runtime}}).
- `constraint_unsupported`: an applicable constraint or consumption
  bound on the entry is unrecognized or unmetered, so the PDP cannot
  enforce it and refuses ({{I-D.draft-mcguinness-mission-runtime}}).
  This is distinct from `parameter_violation`, which is a constraint the
  PDP evaluated and found violated.
- `history_not_satisfied`: a deployment- or Resource-policy-required
  history predicate ({{context-history}}) is not satisfied: the PDP
  established it false, could not establish it, could not consult
  its evidence store within the declared staleness bound, or does
  not recognize the presented `predicate` value. The per-predicate
  outcomes are in Decision Evidence
  ({{I-D.draft-mcguinness-mission-runtime-evidence}}), so the
  unsatisfied and unavailable cases stay distinguishable after the
  fact.

Authentication step-up is not a denial reason under this profile; it
is the step-up obligation on a permit ({{obligations}}). A
Resource-policy refusal not expressible as a permit-plus-obligation is
`resource_policy`.

A terminal policy refusal SHOULD carry `next_action: none`; a denial
the deployment exposes as requestable carries `next_action: request`
with `context.access_request` ({{response-context}}).

This document defines no other denial-reason values. A companion
profile MAY extend the set by specification; an extension value MUST
be either a collision-resistant name (following the Collision-Resistant
Name guidance of {{RFC7519}} Section 4.2) or a name coordinated within
this document family, so values cannot collide. A consumer of a denial
reason, wherever it is carried (the Decision Evidence `denial_reason`,
{{I-D.draft-mcguinness-mission-runtime-evidence}}, or the response
`context.reason`, {{response-context}}), MUST treat an unrecognized value as
a deny and MUST NOT attach any other semantics to it, mirroring the
issuance profile's open lifecycle state space
({{I-D.draft-mcguinness-oauth-mission}}).

## Requestable denials {#requestable-denials}

A deny is terminal for the attempted action: the agent does not proceed
on a denial. A deny need not end the task, however. For an
`out_of_authority` or `approval_required` denial, the PDP MAY
mark the denial **requestable** by including a `context.access_request`
object, composing this binding with the AuthZEN Access Request and
Approval Profile {{ARAP}}. The PEP then submits an ARAP access request
bound to the denied evaluation, an independent approver or policy
adjudicates it (synchronously when policy auto-approves, otherwise
asynchronously through the portable ARAP task handle), and on approval
the PEP re-evaluates against the PDP. This is the demand-driven,
runtime-initiated counterpart to the pre-consented drawdown of the
experimental progressive authorization companion
({{I-D.draft-mcguinness-oauth-mission-progressive}}): the agent starts
narrow and requests the authority it discovers it needs, instead of
holding it up front.

Auto-approval is bounded the same way in-ceiling drawdown is
({{I-D.draft-mcguinness-oauth-mission-progressive}}): a deployment SHOULD
rate-limit and anomaly-check synchronous auto-approval, and MUST NOT
auto-approve a request for an `approval_required` denial in the
irreversible, external-commitment, or privileged-administration classes
without an independent approver, so a compromised agent cannot drive the
request loop to escalate itself unattended.

An ARAP approval is input context, not a bearer grant: the PDP remains
authoritative at enforcement, so the PEP MUST obtain a fresh decision,
and any resulting permit and evidence remain subject to this profile.
The action-bound approval an `approval_required` denial calls for
({{I-D.draft-mcguinness-mission-runtime}}) is exactly such an approval,
and ARAP's `approval.id` or signed `approval.state` is its carrier. An
ARAP completion realizes one of two things. For an in-authority
approval gate (the action is within the Authority Set but policy
requires a fresh approval), the approval attribute alone satisfies the
re-evaluation; no Mission change occurs. For missing authority
(`out_of_authority`, or a subject lacking a role or relationship), the
governance realization MAY be a Mission expansion
({{I-D.draft-mcguinness-oauth-mission-expansion}}), a
policy-adjudicated in-ceiling expansion where the progressive companion
is deployed ({{I-D.draft-mcguinness-oauth-mission-progressive}}), a
role or relationship grant, or another authority-state change; the
fresh evaluation observes that new state. Expansion is one realization,
not ARAP's completion model.

A requestable denial carries `context.access_request` alongside the
denial members. Here deployment policy requires an action-bound
approval for the journal-entry write, no valid fresh approval is
present, and the PDP marks the denial requestable under {{ARAP}}:

~~~ json
{
  "decision": false,
  "context": {
    "evaluation_id": "dec_7YbK4nQ9tR2xV6mL1sP8eJ3wZc",
    "reason": "approval_required",
    "action_class": "irreversible_action",
    "class_source": "deployment",
    "parameter_digest":
      "sha-256:WPVi6EnQ7H9Fh-qk9ADxmTg8zruOdVUX1esl-v3TfCI",
    "policy_view_id":
      "sha-256:kP3xR9sQ7nM2vL4tY6bD1eF8jC5wH0pV2nR3kQ4mZ7t",
    "access_request": {
      "endpoint": "https://requests.example.com/access-requests",
      "expires_at": "2026-11-02T09:14:00Z",
      "evaluation_id": "dec_7YbK4nQ9tR2xV6mL1sP8eJ3wZc",
      "binding_token": "eyJhbGciOiJFUzI1NiIsInR5cCI6InBkcC1kZW5pYWwtYmluZGluZytqd3QifQ.eyJk..."
    }
  }
}
~~~

The `access_request` members are ARAP's requestable-denial context
{{ARAP}} verbatim: the submission `endpoint`, `expires_at`,
`evaluation_id`, and the PDP-signed `binding_token`. Its presence does
not change the `decision: false` result: the PEP refuses the action,
submits the access request, and re-evaluates only after approval.

## Choosing the Lane {#lanes}

Three lanes, and two non-lanes, classify a response by one governing
test: what changes before access can proceed.

Lane 1, obligations and advice:
: PEP work under the existing decision, whichever it is
  ({{obligations}}). An obligation is mandatory and fail-closed: the
  PEP MUST fulfill it or the effective result is deny. Advice
  (reserved, {{obligations}}) is safely-ignorable and fail-open: a
  PEP that does not act on it proceeds unaffected. Neither confers
  authority, has an approver, or creates governance state.

Lane 2, governance (ARAP):
: A governance process creates approval, authority, role, or
  relationship state: `context.access_request` outbound,
  `context.approval` on return, and a portable task handle tracking
  the workflow in between ({{requestable-denials}}).

Lane 3, partial evaluation:
: Residual policy, with no workflow and nothing conferred. Not
  defined by this profile; see the non-goal below.

Not a lane, the RAR remediation grain:
: `insufficient_authorization` and `authorization_remediation` of
  {{I-D.draft-zehavi-oauth-rar-metadata}}, as adopted into the family's
  remediation by the issuance profile
  ({{I-D.draft-mcguinness-oauth-mission}}). It is PAYLOAD, not a lane:
  it DESCRIBES authority that could be requested, MAY travel as
  payload within an ARAP request, and confers nothing by itself. The
  RAR-details grain and the AuthZEN grain are not competing carriers,
  and a deployment MAY expose both on the same denial: the
  RAR-details grain names what authority to propose, carrying
  actionable `authorization_details` the client proposes back on the
  standard `authorization_details` parameter alongside a fresh Intent
  ({{I-D.draft-mcguinness-oauth-mission}}); the AuthZEN grain names
  how the denial is escalated, routing it into a governed access
  request that an independent approver or policy adjudicates before
  the PEP re-evaluates.

Not a lane, transient denial:
: An OUTCOME carrying retry guidance (`next_action: retry`,
  `retry_after`), not a remediation path: nothing is remediated, and
  the condition is expected to clear with time.

Lanes coexist on one response: a requestable denial can carry a
notification obligation under Lane 1's deny-obligation rule
({{obligations}}), and an approval-satisfied permit can carry a
watermarking obligation, without either changing the other's
semantics.

Partial evaluation is a non-goal. This profile returns decisions and
instructions, never executable residual policy. `parameter_attributes`
({{parameter-digest}}), `mission_history` ({{context-history}}),
materialized policy views ({{mission-to-policy-materialization}}), and
embedded PDPs are inputs or deployment shapes, not residual evaluation.
Composition with a future AuthZEN partial-evaluation profile is
reserved, and a PDP MUST NOT return residual policy under this
profile.

## Failure-condition coverage {#failure-condition-coverage}

Every runtime failure condition, whether named in the runtime profile's
failure-mode table or in its other normative requirements
({{I-D.draft-mcguinness-mission-runtime}}), surfaces through exactly
one of four carriers in this binding: a Refusal Record for a PEP
refusal before any PDP decision
({{I-D.draft-mcguinness-mission-runtime-evidence}}), a PDP
denial (`reason` in the decision context, `denial_reason` in Decision
Evidence), a permit obligation ({{obligations}}), or an Execution
Evidence `error` for a failure after a permit
({{I-D.draft-mcguinness-mission-runtime-evidence}}). The table below
is the normative mapping for the conditions it names; extension
identifiers remain
governed by each carrier's extensibility rule.

| Runtime failure condition | Carrier | Identifier |
|---|---|---|
| Token validation fails | Refusal Record | `token_invalid` |
| Required `mission` claim absent | Refusal Record | `mission_claim_missing` |
| PEP-PDP channel authentication or integrity fails | Refusal Record | `channel_failure` |
| PDP unreachable | Refusal Record | `pdp_unreachable` |
| Mission state not establishable at the PEP | Refusal Record | `state_unavailable` |
| Action outside the Authority Set (including an invoked identity outside the approved set with no recorded source binding), or the request would broaden it | PDP denial | `out_of_authority` |
| Resource policy requires a stronger authentication context, satisfiable via step-up | Obligation on permit | step-up obligation ({{AUTHZEN-OBL}}) |
| Resource policy requires a stronger authentication context and refuses outright (not expressible as a permit-plus-obligation) | PDP denial | `resource_policy` |
| Required action-bound approval absent, stale, or parameter-mismatched | PDP denial | `approval_required` |
| Mission state stale (freshness-window violation) | PDP denial | `stale_state` |
| Request Mission `id`, `authority_hash`, or `policy_view_id` inconsistent with the loaded view | PDP denial | `view_inconsistent` |
| Mission not `active`, including a passed `expires_at` | PDP denial | `mission_inactive` |
| External Mission-binding join verification fails | PDP denial | `mission_binding_failed` |
| Required `act` chain missing or malformed | PDP denial | `actor_invalid` |
| Credential facts expired or inconsistent | PDP denial | `credential_invalid` |
| Parameter constraint violated, PDP digest mismatch, or required digest absent | PDP denial | `parameter_violation` |
| Idempotency key and parameters match a prior unresolved or completed decision | PDP denial | `duplicate_suppressed` |
| Resource policy refuses the action | PDP denial | `resource_policy` |
| Consumption bound exhausted | PDP denial | `quota_exceeded` |
| Unsupported `authorization_details` type | PDP denial | `unsupported_authorization_type` |
| Unrecognized or unmetered constraint | PDP denial | `constraint_unsupported` |
| Policy-required history predicate unsatisfied or not establishable | PDP denial | `history_not_satisfied` |
| Effective parameters differ at the executing PEP | Execution Evidence | `parameter_mismatch` |
| Permit validity window passed at execution | Execution Evidence | `permit_expired` |
| Consumed single-use identifier presented again | Execution Evidence | `permit_consumed` |
| Operator or safety control suppressed execution | Execution Evidence | `kill_switch` |

## Permit binding in split topologies {#permit-binding-split}

The requesting component and the executing PEP MUST be the same
enforcement identity, on the same mutually authenticated channel that
requested the permit. A permit is valid only on that channel and
identity, and MUST NOT be relayed to another component as a bearer
grant. Signed Decision Evidence
({{I-D.draft-mcguinness-mission-runtime-evidence}}) MUST
NOT be accepted as authorization to act: it is retrospective evidence
of what the PDP decided, never a live credential a distinct component
presents to execute.

A deployment whose requesting component and executing component
differ is out of scope for this profile. That requester/executor
split is reserved for a future split-execution profile, which would
define a purpose-built execution authorization artifact distinct from
evidence: audience-bound to the executor, short-lived, and one-use.

The single enforcement identity owns the consumed-identifier store and
honors the permit lease (the mission-execution obligation's
`expires_at` and `use_limit`, {{obligations}}) under the runtime
profile's consumed-identifier rules
({{I-D.draft-mcguinness-mission-runtime}}), so a permit cannot be
executed twice or after its lease.

A PEP permit cache MUST key on the permit's bound fields (the Mission
reference and `policy_view_id`, `audience`, `subject`, `client_id`,
actor context, action, resource, the authorizing entry or
`entry_digest`, and `parameter_digest`) and MUST NOT key on freshness
telemetry (`freshness_at`, `mission_status_issued_at`,
`mission_status_expires_at`), whose per-request variation would
otherwise make the cache never hit. A cached permit cannot be reused for
a request that differs in any bound field, and its reuse is bounded in
time by the mission-execution obligation's `expires_at`, not by the
freshness telemetry.

The envelope rule fixes what a permit cache is for. A parameter-bound
class keys on `parameter_digest`, and a high-consequence permit is
single-use, so caching amortizes only repeat-identical,
non-single-use actions: reads and idempotent re-checks. The steady
state for consequential writes is one evaluation per action, and a
deployment sizes PDP capacity and placement to that rate, not to a
cache hit ratio ({{I-D.draft-mcguinness-mission-runtime}}).

## Evaluation identifier propagation {#decision-id-propagation}

The resource request a permit authorizes is commonly served by a
Resource Server that did not see the PDP exchange. The PEP SHOULD
propagate the permit's `evaluation_id` to the resource request in the
`Mission-Decision` request header field ({{iana}}); the field value is
the `evaluation_id`, whose ABNF ({{response-context}}) is
field-value-safe. The field is protected in transit per deployment: at
minimum it rides the TLS channel this binding already requires
({{security-considerations}}), and where the deployment signs resource
requests the signature MUST cover it.

A Resource Server that logs the received `evaluation_id` with the
access it serves closes the decision-to-access join: the Decision
Evidence, the Execution Evidence, and the Resource Server's access log
then share one identifier, so an access is joined to the decision that
permitted it without timestamp correlation. This extends the issuance
profile's recommendation that a Resource Server log the `mission`
claim's `id` and the token `jti` with each decision
({{I-D.draft-mcguinness-oauth-mission}}): the evaluation identifier is
this profile's addition to that correlation set.

The field is a correlation aid, not an authorization. Its presence or
value grants nothing, the Resource Server's token validation and PEP
obligations are unchanged, and a Resource Server MUST NOT treat it as a
permit; the permit-binding rules above govern.

# Runtime Evidence {#evidence}

The PDP and PEP emit the Decision Evidence, Execution Evidence, and
Refusal Records of the runtime evidence companion
{{I-D.draft-mcguinness-mission-runtime-evidence}} (normative
reference) for every decision, execution outcome, and pre-decision
refusal this binding produces. The response's `evaluation_id`
({{response-context}}) is the correlation key; each record carries
its own record identifier (`evidence_id`, `execution_id`, or
`refusal_id`). This binding adds no record members: every Decision
Evidence and Execution Evidence member is defined by the runtime
evidence companion.

This binding's own contribution is the mapping: which decision
request and response members the PDP and PEP echo into a record.
The Decision Evidence `mission`, `subject`, `resource`, `action`,
`audience`, `mission_state_version`, `action_class`, `class_source`,
`credential`, `parameter_digest`, `obligations`, `taint`, and
`mission_history` members are populated from the correspondingly
named members of this binding's PDP request and response
({{pdp-request}}, {{pdp-response}}); the `denial_reason` member
carries the value returned in `context.reason`
({{runtime-denial-classification}}).

The runtime evidence companion's integrity envelope is this binding's
one signing convention for evidence objects: the default envelope
format is `jws-compact`, and the protected `typ` names the record's
own registered media type
({{I-D.draft-mcguinness-mission-runtime-evidence}}).

# Mission Status Composition {#mission-status-composition}

The PDP relies on Mission state to decide. The runtime profile defines
the Mission state source, the maximum staleness bound, and the
fail-closed rule ({{I-D.draft-mcguinness-mission-runtime}}). This
binding conveys that state and its freshness on the wire through the
`context.mission_state_observation` snapshot
({{context-audience-freshness}}), using a `mode` member with one of
three values that describe how the PEP obtained the state:

- `fresh`: the PEP consulted the Mission state source synchronously
  before the action.
- `cached`: the PEP used cached Mission state within the deployment's
  staleness bound.
- `event_driven`: the PEP relies on event-channel invalidation, but the
  cached state remains bounded by the deployment's staleness bound, or
  the lease the state carries, exactly as for `cached`; it is not valid
  indefinitely. A missed or delayed invalidation event does not extend
  validity, and when the bound elapses without a confirming event the
  PEP MUST refresh from a Mission state source rather than continue on
  the cache.

When freshness cannot be established within the bound, the PDP fails
closed for consequential actions as the runtime profile requires; in
this binding that surfaces as a `stale_state` denial
({{runtime-denial-classification}}).

# Conformance {#conformance}

This binding adds AuthZEN-specific obligations on top of the runtime
profile's enforcement contract; an implementation conforms to this
binding only for the resources, action classes, and PDPs in the runtime
enforcement scope it documents
({{I-D.draft-mcguinness-mission-runtime}}).

Each role's obligations are normative in their owning sections; this
checklist cites them without restating their mechanics.

A PEP conforming to this binding MUST:

- carry the Mission and actor decision inputs from validated token
  claims only, matching the approved entry's `resource` against
  `resource.properties.audience` ({{pdp-request}});
- supply `action.properties.parameter_digest` where required
  ({{parameter-digest}}), and, where the deployment adopts Mission
  Capability Binding, `context.capability_source` as that companion
  requires ({{I-D.draft-mcguinness-mission-capability-binding}});
- support both the `step-up` and `mission-execution` obligation types
  unconditionally, whatever it declares in `supported_obligations`
  ({{obligations}});
- fulfill every obligation attached to a permit before releasing the
  action's effect, including the permit lease and use limit carried in
  the mission-execution obligation, and execute every obligation
  attached to a denial while still denying the action ({{obligations}});
- be the same enforcement identity as the requesting component, on the
  same mutually authenticated channel, and never relay a permit or
  treat signed Decision Evidence as authorization to act
  ({{permit-binding-split}});
- key permit caches on the permit's bound fields
  ({{permit-binding-split}}); and
- emit the records of {{I-D.draft-mcguinness-mission-runtime-evidence}}
  for a pre-decision refusal and, for the classes its emission rule
  covers, an execution outcome.

Of these, the mission-execution obligation and execution-outcome
evidence are the machinery of the runtime profile's transaction-assurance
tier ({{I-D.draft-mcguinness-mission-runtime}}): a PEP carries them for
the classes that tier covers.

A PDP conforming to this binding MUST:

- refuse an in-scope consequential request that lacks the Mission
  decision context, and perform the PDP-side consistency checks
  ({{pdp-request}});
- advertise `step-up` and `mission-execution` in its metadata
  `supported_obligations` array, and MUST NOT rely on any other
  obligation type the PEP has not declared support for
  ({{obligations}});
- classify every denial per {{runtime-denial-classification}};
- return the decision context of {{response-context}}, including the
  obligations array on a permit or denial ({{obligations}}); and
- emit the records of {{I-D.draft-mcguinness-mission-runtime-evidence}}
  for every decision.

A deployment whose requesting component and executing component
differ is out of scope for conformance to this profile
({{permit-binding-split}}).

Record producer and consumer conformance, including evidence
signing-key verification and the classification of orphaned Decision
Evidence, is defined by the runtime evidence companion
({{I-D.draft-mcguinness-mission-runtime-evidence}}).

# Security Considerations {#security-considerations}

The runtime profile's Security Considerations
({{I-D.draft-mcguinness-mission-runtime}}) apply in full:
placement and bypass, classification integrity, freshness and
consumption honesty, Resource policy authority, TOCTOU and replay, and
the limits of a compromised PEP or PDP. This section addresses only
threats specific to the AuthZEN binding; threats specific to the
evidence records are the runtime evidence companion's
({{I-D.draft-mcguinness-mission-runtime-evidence}}), and threats
specific to capability-source binding are the capability-binding
companion's ({{I-D.draft-mcguinness-mission-capability-binding}}).

## Unbound-evaluation downgrade

A PDP that serves both Mission-bound and ordinary AuthZEN traffic has
two policy surfaces, and the request selects between them by carrying
`context.mission`. If an in-scope request that lost its Mission
context (a PEP defect, or a path an attacker can influence) were
evaluated against the non-Mission surface, a generic allow rule would
stand in for the Mission evaluation this binding exists to force. The
consistency requirement of {{pdp-request}} refuses such a request
outright; deployments SHOULD additionally alert on in-scope requests
arriving without Mission context, since each one is a PEP defect or a
probe.

## Access Request Service in the trusted base

A deployment that composes with ARAP adds the Access Request Service to
its trusted base: it adjudicates requestable denials and issues the
approvals the PDP consumes as input. A compromised or misconfigured
Access Request Service can auto-approve escalations, so it MUST be
trusted, authenticated, and access-controlled like the PDP, and its
auto-approval is bounded as above.

## Denial oracle

The denial-reason identifiers and any `contributing_constraints` are a
decision oracle: an agent can probe them to map authority it does not
hold. The PEP SHOULD minimize the denial detail it relays to the agent;
a generic refusal suffices to stop the action, and the full reason and
contributing constraints belong in evidence, not in the agent-facing
response. To bound probing through the request loop, deployments SHOULD
rate-limit access requests per Mission and surface request provenance to
Approvers, so a compromised agent driving repeated requestable denials
is visible to the humans adjudicating them.

## Materialized view fidelity

A PDP that evaluates against a materialized view enlarging the
Authority Set's bounds violates the bounded property of
{{mission-to-policy-materialization}}. `authority_hash` is the upper
bound; `policy_view_id` lets the PDP detect that the view it loaded
does not match the Mission the PEP referenced and deny with
`view_inconsistent`.

## Transport

The PDP endpoint MUST be served over TLS 1.2 or later (TLS 1.3
RECOMMENDED). PEP-to-PDP authentication MUST be mutual, satisfying the
integrity and mutual-authentication requirement the runtime profile
places on the PEP-PDP channel
({{I-D.draft-mcguinness-mission-runtime}}). Evidence transport and
storage requirements are the runtime evidence companion's
({{I-D.draft-mcguinness-mission-runtime-evidence}}).

# Privacy Considerations {#privacy-considerations}

The runtime profile's evidence-privacy guidance
({{I-D.draft-mcguinness-mission-runtime}}) applies in full. The
privacy properties of the Decision Evidence, Execution Evidence, and
Refusal Record objects, including their status as PII sinks,
parameter exposure, and actor-chain correlation, are the runtime
evidence companion's ({{I-D.draft-mcguinness-mission-runtime-evidence}});
this binding defines no additional record content and no exemption
from that guidance.

# IANA Considerations {#iana}

This document requests the following IANA actions.

The Decision Evidence, Execution Evidence, and Refusal Record media
types are registered by the runtime evidence companion
({{I-D.draft-mcguinness-mission-runtime-evidence}}), not by this
document.

## AuthZEN Obligation Types Registration

This document requests registration of the `mission-execution`
obligation type in the AuthZEN Obligation Types registry established
by {{AUTHZEN-OBL}}: Type name `mission-execution`; Reference this
document, {{obligations}}; Change controller IETF. The `step-up`
obligation type this profile relies on ({{obligations}}) is
registered by {{AUTHZEN-OBL}} itself and is not re-registered here.

## HTTP Field Name Registration

This document registers the following in the "Hypertext Transfer
Protocol (HTTP) Field Name" registry ({{RFC9110}}):

- Field Name: Mission-Decision
- Status: permanent
- Reference: this document, {{decision-id-propagation}}
- Comments: none

The `context.mission`, `context.mission_state_observation`,
`context.actor`, `context.credential`, `context.taint`, and
`context.approval` members carried inside the AuthZEN request
`context` object ({{pdp-request}}) are AuthZEN extension data and are
not registered in an IETF registry. The `context.capability_source`
member a deployment adopting Mission Capability Binding adds to that
object is likewise AuthZEN extension data, registered by that
companion, not by this document
({{I-D.draft-mcguinness-mission-capability-binding}}).
The `action.properties.parameters`,
`action.properties.parameter_digest`,
`action.properties.idempotency_key`,
`action.properties.parameter_attributes`, and
`action.properties.external_communication` members carried inside the
AuthZEN `action` object, and the `resource.properties.audience` member
carried inside the AuthZEN `resource` object ({{pdp-request}}), are
likewise AuthZEN extension data. The response `context.evaluation_id`,
`context.evaluated_at`, `context.reason`, `context.action_class`,
`context.class_source`, `context.parameter_digest`,
`context.policy_view_id`, `context.mission_state_version`,
`context.obligations`, `context.access_request`,
`context.next_action`, and `context.retry_after` members
({{response-context}}) are likewise AuthZEN extension
data. The Mission-bound token claims this profile consumes are
registered by {{I-D.draft-mcguinness-oauth-mission}}.

--- back

# Acknowledgments
{:numbered="false"}

This document is the AuthZEN binding of Mission-Bound Runtime
Enforcement and builds on the OpenID AuthZEN
Authorization API. The author thanks the OpenID AuthZEN community and
the Mission-Bound Authorization implementer community for feedback.
