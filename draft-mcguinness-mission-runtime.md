---
title: "Mission-Bound Runtime Enforcement"
abbrev: "Mission Runtime"
category: std

docname: draft-mcguinness-mission-runtime-latest
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
  latest: "https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-runtime.html"

author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com

normative:
  RFC3339:
  RFC6749:
  RFC6750:
  RFC6234:
  RFC7662:
  RFC8785:
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
  I-D.draft-mcguinness-mission-substrate:
    title: "Mission Substrate Requirements"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-substrate.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026

informative:
  I-D.draft-rosomakho-oauth-txn-challenge:
  I-D.draft-jiang-oauth-intent-admission:
  I-D.draft-mcguinness-mission-security-model:
    title: "Mission Security Model"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-security-model.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  RFC9470:
  I-D.draft-niyikiza-oauth-attenuating-agent-tokens:
  I-D.draft-mcguinness-oauth-client-instance-assertion:
  I-D.draft-mcguinness-oauth-ai-agent-instance:
  I-D.draft-mcguinness-oauth-actor-receipts:
  I-D.draft-mcguinness-oauth-actor-proofs:
  I-D.draft-mcguinness-mission-audit:
    title: "Mission Audit Transparency"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-audit.html
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
  I-D.draft-mcguinness-mission-mandate:
    title: "Mission Mandate"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-mandate.html
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
  I-D.draft-mcguinness-mission-runtime-evidence:
    title: "Mission Runtime Evidence"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-runtime-evidence.html
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
  I-D.draft-mcguinness-mission-architecture:
    title: "An Architecture for Mission-Bound Authorization"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-architecture.html
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
  I-D.draft-mcguinness-oauth-mission-issuance-grant:
    title: "Mission Issuance Grant for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-issuance-grant.html
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
  I-D.draft-mcguinness-oauth-mission-containment:
    title: "Mission Containment for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-containment.html
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

--- abstract

This document specifies runtime enforcement for Mission-Bound
Authorization: within a declared enforcement scope, no consequential
action executes until a policy enforcement point obtains a permit
from a policy decision point that evaluates the action and its
concrete parameters against the Mission established for the acting
credential. The evaluation checks the Mission's approved authority
and constraints, the actor context from the delegation chain, the
Mission's current state, and the applicable Resource policy. The
companion issuance profile binds issued authority to a durable,
approved Mission but governs issuance and derivation only; without a
point-of-use check, an active Mission becomes ambient authority for
the actions an agent takes within a token's lifetime. This document
is that check. It defines where enforcement sits, how a permit is
bound to concrete parameters to close the time-of-check to
time-of-use gap, the materialized policy view a decision evaluates
against, the fail-closed posture for constraints and consumption
bounds, and the runtime evidence every decision and refusal path
produces. For the high-consequence classes it further defines
action-bound approval, credential custody in the mediating
enforcement point rather than the agent, and two named enforcement
claims with individually verifiable conditions:
agent-compromise-resistant enforcement and trifecta containment.

--- middle

# Introduction

Mission-Bound Authorization for OAuth 2.0
{{I-D.draft-mcguinness-oauth-mission}} (the "issuance profile") makes a
Mission a first-class OAuth artifact: a structured, human-approved,
integrity-bound task whose authority bounds and outlives every token
an agent derives. It is deliberately an issuance-and-derivation
layer: it governs what authority may exist, not what an agent does
with it. Within a token's lifetime the agent exercises the issued
authority freely, so a Mission that is never consulted at the point
of use functions as ambient authority for every consequential action
inside its envelope.

This document is the runtime layer that closes that gap: the
enforcement half of the model, and the profile that makes a
Mission-bound token more than governance metadata. Its substance is
one contract, stated once here and elaborated by the rest of the
document.

## The Runtime Contract {#runtime-contract}

Within a declared enforcement scope, a consequential action executes
only after a Policy Enforcement Point (PEP) at the action's last
controllable boundary obtains, from a Policy Decision Point (PDP), a
permit that evaluates the action and its concrete parameters against
the established Mission: its approved authority and constraints, the
actor context from the delegation chain, its current lifecycle
state, and the applicable Resource policy. The permit is bound to
the parameters the action executes with, and every decision and
refusal path leaves evidence.

Mission-bound tokens bound what authority may exist; the contract
fixes where and how that authority is re-checked before
consequential effects occur. The order is the point: approve the
bounded work, then authorize every consequential action against
that approved boundary. Per-action authorization alone cannot
prevent individually permitted steps from composing into an outcome
no one approved; the approved boundary bounds composition, with the
cumulative bounds and `exclusive` latch of the metering companion
where deployed ({{metering}},
{{I-D.draft-mcguinness-mission-metering}}). The PEP is whatever component can
actually prevent the action: a Resource Server, an MCP server, an
egress proxy, a workflow engine, or the orchestrator itself
({{pep-placement}}). The PDP's placement is a deployment choice
({{decision}}). A deployment whose acting tokens carry no `mission`
claim can still bind each decision to a Mission: the Mission
Substrate ({{mission-substrate}}) admits an externally established
Mission reference ({{mission-binding}}).

## Enforcement Invariants {#enforcement-invariants}

Seven invariants restate the contract as the properties a conforming
deployment maintains. Each is normative in its home section, and the
failure-mode table ({{failure-modes}}) is their operational form.

**Gated at the point of use**:
: No consequential action executes without a prior PDP permit; token
  possession alone never suffices ({{decision}}).

**Enforced at the last controllable boundary**:
: The PEP sits where the action can still be stopped; a check
  further upstream does not survive what happens after it
  ({{pep-placement}}).

**Bound to the bytes**:
: A parameter-bound permit binds the normalized parameters, and the
  executing PEP reverifies them immediately before acting; a changed
  parameter is a refused action ({{parameter-binding}}).

**Fresh or refused**:
: A permit requires the Mission `active` within a published
  staleness bound, and the high-consequence classes require an
  active freshness source, not token-lifetime expiry
  ({{state-freshness}}).

**Fail closed**:
: An unknown or unmetered constraint, an unreachable PDP, Mission
  state that cannot be established within the staleness bound, or an
  unsupported authorization-details type refuses the action
  ({{failure-modes}}).

**Evidenced**:
: Every decision and every refusal path produces an
  integrity-protected record, and a high-consequence action also
  produces execution-outcome evidence ({{evidence}}).

**Never widening**:
: No runtime input expands authority beyond the issued Authority
  Set; a deny is terminal for the attempted action, and widening is
  a governance operation, never a runtime one ({{decision}}).

For the high-consequence classes ({{classification}}) the profile
goes further: action-bound approval re-consents the concrete
parameters ({{action-approval}}), and mediated custody keeps the
credential's sender-constraint key in the enforcing component rather
than the agent ({{custody}}). Those mechanisms compose into the two
named claims of {{named-claims}}, agent-compromise-resistant
enforcement and trifecta containment: the bar a deployment meets
before representing itself as resistant to a compromised or injected
agent, and the High-Assurance Agent level of the Mission Assurance
Levels ({{I-D.draft-mcguinness-mission-architecture}}).

## Invariants, Not a Wire Protocol {#not-a-wire-protocol}

This profile specifies enforcement invariants, not a wire protocol: it
does not standardize a PDP decision API, an enforcement-scope discovery
format, a Mission Status endpoint, or a portable audit receipt. It
defines what a deployment MUST satisfy when it claims runtime Mission
enforcement; the surfaces it deliberately leaves to deployments or
future work are collected in {{deferred}}.

Because the invariants are not a wire format, two conforming deployments
do not thereby interoperate at the PEP-PDP boundary; the interoperable
wire surface is supplied by a separately specified decision API binding
({{authzen}}), the AuthZEN binding being
{{I-D.draft-mcguinness-mission-authzen}}. That a wire format is a
deployment choice does not make it an ad hoc one: the Runtime-Enforced
level of the Mission Assurance Levels
({{I-D.draft-mcguinness-mission-architecture}}) requires a specified
decision-API binding, of which the AuthZEN profile is the one this
family defines; a deployment that uses a different decision API
specifies that binding likewise ({{authzen}}). This document is the
architecture and invariant layer; the binding is the interoperability
layer.

## Relationship to the Issuance Profile {#relationship}

The seam between the two documents is exact. This document delivers
the four things the issuance profile names as out of scope, plus
enforcement of the constraints that profile carries but does not
evaluate:

1. evaluation of a request's parameters against the Mission at the
   point of use ({{decision}}, {{parameter-binding}});
2. per-action runtime enforcement evidence ({{evidence}});
3. binding of the invoked tool or function identity to the Mission's
   approved authority ({{decision}});
4. execution-time re-evaluation that closes the approval-to-execution
   (time-of-check to time-of-use) gap ({{parameter-binding}});

and, additionally, the fail-closed treatment of consumption bounds
({{metering}}).

This document depends normatively on the issuance profile and is not
implementable alone: it consumes the Mission-bound access tokens that
profile defines, or access tokens joined to an externally established
Mission under {{mission-binding}}. It does not place any new
requirement back on the issuance profile; it reads only fields that
profile already defines:

- the `mission` claim (`id`, `issuer`, `authority_hash`);
- the token's `authorization_details`, including entries of type
  `mission_resource_access` (`resource`, `actions`, `constraints`,
  and any `delegation` member) and any other entry type the deployment
  supports under the issuance profile's rules;
- the `act` chain, when delegation is in effect;
- the standard `iss`, `aud`, `sub`, `client_id`, and `exp` claims, when
  present in the token format; and
- any `cnf` sender-constraint binding.

Where this document needs a value the token does not carry (the
current Mission lifecycle state, or a materialized policy-view
version), it obtains it at runtime as described below, never by
requiring the issuance profile to add a field.

The Resource Server enforcement rules in the issuance profile remain
the baseline for every Mission-bound access token. This document adds
an optional runtime conformance profile for deployments that claim
execution-time Mission enforcement; it does not weaken the issuance
profile's stateless token-validation, subset, delegation, or
constraint-enforcement requirements.

# Conventions and Terminology {#conventions-and-terminology}

{::boilerplate bcp14-tagged}

This specification uses the terms "access token", "Authorization
Server", "client", "protected resource", "resource owner", and
"Resource Server" from OAuth 2.0 {{RFC6749}} through the terminology
incorporated by {{I-D.draft-mcguinness-oauth-mission}}. It also uses
the Mission, Mission Intent, Mission Issuer, Authority Set,
Approver, delegation, and `mission` claim terminology from
{{I-D.draft-mcguinness-oauth-mission}}.

Policy Enforcement Point (PEP):
: The component that can prevent a consequential action and that
  obtains and enforces a decision before the action runs. Depending
  on the action this is a Resource Server, an MCP server, an egress
  proxy, a workflow engine, or the orchestrator itself.

Policy Decision Point (PDP):
: The component that evaluates a consequential action against the
  Mission and returns permit or deny. Its placement is a deployment
  choice ({{decision}}).

Resource policy:
: Local policy of the Resource Server or protected resource, including
  object-level authorization, tenant configuration, legal holds,
  service invariants, and risk decisions. Mission authority is an
  upper bound and does not override Resource policy.

Consequential action:
: An action that has external visibility or effect and so MUST be
  evaluated before it runs ({{classification}}).

High-consequence classes:
: The irreversible action, external commitment, and privileged
  administration classes, to which this profile's strictest
  requirements attach ({{classification}}).

Decision:
: A PDP's permit-or-deny result for one action, bound to the inputs
  it evaluated ({{decision}}).

Established Mission:
: The single Mission a decision is evaluated against, established
  from the credential's `mission` claim or externally
  ({{mission-binding}}).

Policy-view version:
: A deployment-opaque identifier the PDP emits for the materialized
  policy and Mission view it evaluated against, so a permit and its
  evidence record tie to a reproducible decision basis. It need not
  reveal policy content; it is a correlator that lets an operator
  determine which materialized policy, Mission state view, and
  constraint interpretation a decision used. It is local to
  the runtime layer and is distinct from the issuance profile's
  `policy_version` Mission-record field
  ({{I-D.draft-mcguinness-oauth-mission}}); this document does not
  interpret it beyond correlation, and defines no portable policy-version
  registry. The materialized policy view and its content-addressed
  `policy_view_id` are defined in {{policy-view}}.

Runtime enforcement evidence:
: The record a consequential action produces for a PDP decision or a
  PEP refusal path ({{evidence}}).

Enforcement scope:
: The set of resources, action classes, execution paths, PEP
  placements, supported authorization details, state sources, and
  evidence mechanisms for which a deployment claims conformance to this
  profile.

Operation Profile:
: The per-operation statement of normalization and binding rules a
  deployment publishes; defined in full in {{parameter-binding}}.

Resource Server runtime profile:
: A deployment's Resource Server-facing conformance statement for this
  profile. It defines which protected resources and operations the
  Resource Server enforces, where the PEP sits, how local Resource
  policy composes with Mission authority, and which Operation Profiles
  apply.

Mission state source:
: A deployment-trusted source from which the PDP establishes the
  Mission lifecycle state or the freshness of that state
  ({{state-freshness}}).

Mission-bound token:
: An access token issued under a Mission per
  {{I-D.draft-mcguinness-oauth-mission}}, carrying
  `authorization_details` and a `mission` claim.

# Mission Substrate {#mission-substrate}

This profile is defined against the Mission model rather than against
OAuth 2.0 mechanics: it is a substrate-neutral consumer, and this
section is its consumption declaration under the rule of Mission
Substrate Requirements ({{I-D.draft-mcguinness-mission-substrate}})
that a substrate-neutral profile declare the kernel functions and
optional capabilities it consumes.

From the contextual-governance kernel it consumes the Mission
identifier and issuer, the kernel's Mission Reference and Controller;
the lifecycle state space with its only-`active`-permits rule, the
kernel's governance gate; the immutable Approved Context, the
approval-time fixity behind every anchor its records cite; and the
Mission's audit horizon, which bounds the ordered governance record.
The kernel requires no particular integrity anchors: `intent_hash`
and `authority_hash` are the OAuth binding's commitment to the
Approved Context, supplied by the issuance profile, not by the
kernel.

It consumes these optional capabilities:

| Capability | Consumption | Scope of consumption |
| --- | --- | --- |
| Structured Authority | required | The decision contract materializes and evaluates the effective Authority Set, with its subset rule and Common Constraints ({{input-authority}}, {{policy-view}}); as the substrate's composition rule warns, a Mission reference alone is not structured authority |
| Lifecycle-Gated Authorization | required | Every Runtime Decision gates on the only-`active`-permits rule ({{decision}}) |
| State-Observable | conditional | An authenticated freshness source with a stated staleness bound, consumed wherever an enforcement scope's published staleness bound is tighter than the credential lifetime ({{state-freshness}}) |
| Monotonic Derivation | conditional | Consumed where delegation, attenuation, or containment narrowing is enforced at action time through effective-set evaluation ({{input-authority}}) |
| Credential-Bound | conditional | Consumed when the binding provides the Mission-bound credential carrying the `mission` claim; a binding that does not provide it supplies an externally established Mission reference instead, under the binding-establishment step of {{mission-binding}} |
| Independently Verifiable | not consumed | Offline verification is the audit profile's concern ({{I-D.draft-mcguinness-mission-audit}}); the runtime evidence companion defines the records and their scoped verification ({{I-D.draft-mcguinness-mission-runtime-evidence}}) |
| Portable Evidence | not consumed | Evidence portability is the audit profile's concern ({{I-D.draft-mcguinness-mission-audit}}); the records themselves are the runtime evidence companion's ({{I-D.draft-mcguinness-mission-runtime-evidence}}) |
{: title="Runtime profile capability consumption"}

The issuance profile {{I-D.draft-mcguinness-oauth-mission}} is this
version's normative substrate: it defines each consumed kernel
function and capability for OAuth 2.0, and every OAuth artifact named
in this document enters through it. A binding that provides the
required capabilities above, and whichever conditional capabilities
the deployment's enforcement scopes require, can host this profile,
given a mapping of this profile's representations onto the binding's
own: the authority representation the decision contract evaluates and
the Approved Context commitment its records cite. Such a binding is
defined by that substrate, not here, and its
Mission Substrate Statement declares what it provides (the AAuth
binding {{I-D.draft-mcguinness-mission-aauth}} is one example). A
binding that does not provide Structured Authority does not host this
profile's decision contract; it composes through its own native
authorization gate and the externally established Mission reference
of {{mission-binding}}. The portability claim is capability-scoped
rather than substrate-wide for the reason the substrate's Capability
Confusion consideration states: every property this profile requires
matches an explicit capability claim and its scope, never the generic
statement that a binding supports Missions.

# The Runtime Model {#runtime-model}

## Enforcement Flow

~~~
 Agent          PEP (action boundary)        PDP
   |                  |                        |
   |- action+params ->|                        |
   |                  | validate token         |
   |                  |- evaluate vs Mission ->|
   |                  |  (authority, params,   |
   |                  |   actor, state)        |
   |                  |<---- permit / deny ----|
   |                  | bind to params;        |
   |                  | write evidence         |
   |<- execute/refuse-|                        |
~~~

The PEP first validates the token as described in {{token-validation}}.
On permit the PEP reverifies the parameter binding, then executes; on
deny it refuses. The inputs the decision evaluates are defined in
{{decision}}.

## Enforcement Scope and Conformance {#runtime-conformance}

This profile is implemented by a runtime deployment, not by an OAuth
Authorization Server alone. Three things conform, at different
granularities: the **runtime deployment** (this section), the
**Resource Server runtime profile** for OAuth-protected resources
({{rs-runtime-profile}}), and the **PEP/PDP decision path** for each
consequential action ({{decision}}). Conformance is not global to a
product, Authorization Server, Resource Server, or PDP: a deployment
conforms to this profile only for the resources, action classes,
execution paths, and authorization-detail types named in its
enforcement scope.

A deployment that claims conformance to this profile MUST publish an
**Enforcement Scope Statement**: the structured, referenceable
declaration of its enforcement scope that auditors, procurement, and
interop tests key on. This statement is what earns the
Runtime-Enforced level of the Mission Assurance Levels, and it feeds
the Mission Deployment Profile, the deployment-level manifest the
architecture defines ({{I-D.draft-mcguinness-mission-architecture}}). It MUST include:

- the protected resources, action classes, and execution paths it
  mediates, and the Mission-establishment mode each enforcement scope
  uses;
- the PEP locations that can prevent those actions, and the unmediated
  paths explicitly excluded from the claim (the harness profile's
  execution-environment scope statement supplies these for a
  harness-run deployment, {{I-D.draft-mcguinness-mission-harness}});
- the credential custody mode for each mediated class (mediated
  custody in the PEP, or agent-held, {{custody}});
- the conformance tier claimed for each mediated action class: the
  core enforcement tier, or the transaction-assurance tier where
  claimed or required (the tier vocabulary below);
- the PDP or PDPs that evaluate Mission-bound decisions;
- the `authorization_details` types, action identifiers, and constraint
  vocabularies it supports;
- any Resource Server runtime profile and Operation Profiles it uses
  ({{rs-runtime-profile}});
- the Mission state source and maximum staleness bound used for each
  action class ({{state-freshness}});
- the PDP-unavailability posture per mediated action class: the
  maximum outage the deployment rides through on unexpired,
  unconsumed permits ({{failure-modes}}), and whether work suppressed
  by fail-closed is queued for resume or dropped;
- the runtime enforcement evidence mechanism and retention window
  ({{evidence}});
- the locations of the deployment-published evidence signing key sets
  (the runtime evidence companion's PDP and PEP key sets,
  {{I-D.draft-mcguinness-mission-runtime-evidence}}, resolve here);
- the reconciliation window for matching execution-outcome evidence to
  decisions, the component responsible for orphaned-evidence and
  sequence-gap detection and for actively reconciling each unresolved
  outcome within the window, and that component's alerting obligation
  ({{evidence}}).

A deployment MUST NOT claim runtime enforcement for a resource, action
class, `authorization_details` type, or execution path outside that
declared scope. A Mission Issuer conforms to the issuance profile; it
does not become a runtime-conforming deployment merely by issuing
Mission-bound tokens. The converse is a stated posture, not a
failure: a resource or class outside the declared scope relies on
issuance gating and token-lifetime freshness ({{state-freshness}}),
and the Enforcement Scope Statement says so. This profile does not
require every resource to evaluate Mission state; it requires the
deployment to say which do.

Within the declared scope the duties tier by action class, and the
tiers have names; the Enforcement Scope Statement names which tier
covers which class.

**Core enforcement tier**:
: What every conforming deployment carries:

  - Mission establishment;
  - per-action evaluation against current Mission state and Resource
    policy;
  - state freshness;
  - permit or deny with a decision identifier and Decision Evidence;
    and
  - parameter binding for the parameter-bound classes.

**Transaction-assurance tier**:
: Claimed per mediated class and required for the high-consequence
  classes:

  - single-use permits and execution leases;
  - Execution Evidence; and
  - outcome reconciliation.

One bound is stated rather than implied: reconciliation detects
divergence between decisions and outcomes; it never manufactures
exactly-once execution, which exists only where the resource itself
supports idempotency, as its Operation Profile records
({{rs-runtime-profile}}).

The enforcement scope is a deployment conformance statement, not an
OAuth Authorization Server metadata extension. This document defines no
discovery mechanism, registry, or wire format for publishing it.
Different deployments can document scope through configuration,
operational policy, resource-server metadata defined elsewhere, or a
contractual profile.

## Action Classification {#classification}

The boundary between consequential and non-consequential actions is
deployment policy, bounded by the classification floor below. This
document defines a default classification a deployment SHOULD adopt,
and a floor it MUST observe.

| Class | Examples | PDP gate | Parameter binding |
|---|---|---|---|
| Non-consequential | internal reasoning, cache reads, planning | not required | n/a |
| Consequential read | reading user data, querying logged APIs | MUST | not required |
| Consequential write | updating records, posting messages | MUST | MUST |
| Irreversible action | sending mail, payment, deletion | MUST | MUST, with TOCTOU reverification and evidence |
| External commitment | signing, accepting terms for the user | MUST | MUST, with TOCTOU reverification and evidence |
| Privileged administration | granting access, changing policy | MUST | MUST, with TOCTOU and evidence |

The table's per-class requirements (the PDP gate and parameter
binding) are requirements for an action **once it is assigned to that
class**. Assigning an action to a class is deployment policy, bounded
by the floor below and by any Resource-policy minimum
({{decision}}): the profile does not require every read to reach a PDP.
A read that is already fully constrained by the token's audience,
resource, and the Resource Server's object-level authorization, and
that does not materially affect the resource set or disclosure risk,
need not be classified a consequential read, and is then not
separately PDP-gated by this profile. A deployment MUST NOT, however,
use classification to evade the floor or a Resource-policy minimum, and
once an action is a consequential write or higher it MUST be gated and
bound as the table requires.

One predicate cuts across the classes. An **external-communication
action** is a consequential action, of any class, whose effect
carries data to a recipient outside the deployment's trust boundary
(sending a message or mail, posting to an external service,
publishing, or any equivalent egress). The term names the egress
property, not a sixth class: an external-communication action keeps
its class and that class's requirements, and rules stated over
"external-communication and external-commitment actions" (the taint
rule, trifecta containment, egress metering) apply to any action
satisfying the predicate or classified `external_commitment`.

The three highest classes are defined by predicates; the table's
examples illustrate them:

Irreversible action:
: the action's effect cannot be reversed by the same authority within
  the deployment's own systems.

External commitment:
: the action creates an obligation or communication binding the
  Subject to a party outside the deployment.

Privileged administration:
: the action changes who holds authority or how authority is
  evaluated.

Classification remains deployment-scoped: each deployment applies the
predicates to its own actions and systems. The predicates make the
resulting classifications comparable across deployments and auditable:
an assignment is justified by whether its predicate holds, not by
resemblance to the examples.

Some operations have no fixed class: a shell, a generic HTTP
client, a code interpreter, any operation whose consequence depends
on its arguments. Such an argument-dependent operation is classified
per invocation, from its normalized parameters, by a classifier the
deployment declares in its Enforcement Scope Statement
({{runtime-conformance}}). An invocation the classifier cannot
affirmatively place MUST be treated as the widest class the
operation can reach, and the floor below applies to the classifier's
assignments as to any other: a class the deployment cannot justify
by its predicate is not a basis to leave the invocation ungated.

**Classification floor.** Four rules bound classification:

1. Actions in the **irreversible**, **external commitment**, and
   **privileged administration** classes MUST be treated as
   consequential and gated.
2. A Mission's `purpose`, or deployment policy, MAY raise an action
   to a stricter class.
3. A Mission's `purpose` or deployment policy MUST NOT lower an
   action below any minimum classification the Resource policy
   ({{decision}}) sets for it, including a floor the resource owner
   publishes in its protected resource metadata ({{class-floors}}).
4. In any case, a Mission's `purpose` or deployment policy MUST NOT
   classify an irreversible, external-commitment, or
   privileged-administration action as non-consequential.

The three classes of the first rule are the **high-consequence
classes**, to which this profile's strictest requirements attach
(action-bound approval ({{action-approval}}), mediated custody
({{custody}}), active-state freshness ({{state-freshness}}), and
execution-outcome evidence ({{evidence}}), each as specified in its
own section). A deployment that leaves such an action ungated does
not enforce this profile for that action's class
({{pep-placement}}).

### Resource-Owner Class Floors {#class-floors}

A resource owner can carry its classification minimums to any PDP
through its protected resource metadata {{RFC9728}}:

`mission_action_class_floors`:
: OPTIONAL JSON object. Each member name is an action identifier from
  the resource's `actions` vocabulary
  ({{I-D.draft-mcguinness-oauth-mission}}); an action-family
  identifier, in the issuance profile's action-family form, sets the
  floor for every action in the family. Each value is the minimum
  runtime action class for the mapped action: one of
  `consequential_read`, `consequential_write`, `irreversible_action`,
  `external_commitment`, or `privileged_administration`, naming the
  classes of this section.

A PDP with access to the resource's metadata MUST NOT classify a
mapped action below its floor. The member is the interoperable
carriage of the Resource-policy minimum the classification floor above
already binds; it raises, and never lowers, an action's class. A PDP
that does not recognize a mapped value MUST treat it as naming a
high-consequence class.

For the ERP resource of the worked examples
({{parameter-digest-example}}):

~~~ json
{
  "resource": "https://erp.example.com",
  "mission_action_class_floors": {
    "journal-entries.read": "consequential_read",
    "journal-entries.write": "irreversible_action"
  }
}
~~~

## Action-Bound Approval {#action-approval}

The Mission's approval event ({{I-D.draft-mcguinness-oauth-mission}})
consents to the task and its authority bound; it does not consent to a
specific action's concrete parameters at the point of use. For the
highest-consequence classes, a deployment can require a second,
**action-bound approval**: a fresh approval bound to the concrete
action and the parameters the PEP is about to permit, distinct from the
Mission's initial approval. A deployment SHOULD reserve action-bound
approval for the actions whose consequence genuinely warrants a human
pause: applied broadly it trains the Approver to rubber-stamp, and a
rubber-stamped approval binds like a considered one (the
consent-fatigue residual of
{{I-D.draft-mcguinness-mission-security-model}}).

An action-bound approval is a governed approval bound to the action:
it is obtained from an independent Approver or
policy authority, never self-issued by the agent or asserted from the
agent's own context, and its rendered disclosure MAY be committed as
Consent Evidence ({{I-D.draft-mcguinness-oauth-mission-consent-evidence}})
bound to the action parameters. It composes with, and does not replace,
{{RFC9470}} step-up authentication, which strengthens the actor's
authentication context rather than approving a specific action.

Four rules govern the approval's enforcement:

1. A PEP MUST refuse an action for which deployment policy or
   Resource policy requires an action-bound approval and a valid
   fresh approval bound to the action's parameters is not present.
2. An action-bound approval MUST carry a maximum age, bounded by a
   value the deployment set publishes, and MAY additionally carry an
   absolute `approved_until` expiry (the AuthZEN binding surfaces ARAP's
   approval expiry there, {{authzen}}). The approval is fresh only before
   the earlier of `approved_at` plus the maximum age and any
   `approved_until`; past that bound the approval is not fresh and the PEP
   MUST refuse.
3. A deployment SHOULD require an action-bound approval for the
   high-consequence classes, where a token-lifetime-wide standing
   authority is least appropriate.
4. Because the approval is bound to the concrete parameters, it MUST
   be reverified under the time-of-check to time-of-use rules of
   {{parameter-binding}}. A parameter change after approval
   invalidates it.

The permit lease does not substitute for the maximum-age bound: a
permit's validity window ({{parameter-binding}}) bounds the permit,
not the age of the approval it relied on.

This profile does not define the wire workflow that obtains the
approval. A decision-API binding MAY route the requiring denial through
a standardized access-request and approval workflow and carry the
resulting approval back as decision input; the AuthZEN binding composes
with the AuthZEN Access Request and Approval Profile for exactly this
({{authzen}}). However obtained, the approval is decision input, not a
bearer grant: the runtime decision of {{decision}} remains
authoritative, and a persisted grant beyond the single action is a
governance state change the fresh decision observes (a Mission
expansion, a role or relationship grant, or another authority
update), never a property of the approval itself.

Two proposed OAuth-native transports are converging on this same
per-action moment, and both compose here rather than compete. The
transaction authorization challenge
({{I-D.draft-rosomakho-oauth-txn-challenge}}) has the protected
resource return a signed challenge that the client presents to the
AS, which obtains approval and issues a token whose
`authorization_details` describe the approved operation; under a
Mission, the approval event is the policy behind that challenge, the
Authority Set bounds what any challenge can be approved into, and
Consent Evidence is its record. The intent admission assertion
({{I-D.draft-jiang-oauth-intent-admission}}) has an admission point
sign a short-lived assertion binding an intent digest, its
originator, an authorized presenter key, and consent evidence, which
the executing endpoint re-verifies; a Mission-governed admission
point evaluates against the Authority Set, and its
consent-by-prior-grant case is exactly a reference to the Mission's
committed anchors. In both compositions the durable record this
family defines is what makes the per-action artifact accountable to
an approved task rather than to policy alone.

## PEP Placement {#pep-placement}

Enforcement only works at the component that can actually stop the
action. A deployment claiming this profile MUST observe these rules:

- The PEP MUST sit at the last controllable boundary before the
  action. A permit checked further upstream does not survive
  parameter changes, retries, or routing that happen after the check.
- A token-issuance decision does not replace execution-time
  authorization. A token-only Resource Server cannot claim runtime
  enforcement; the issuance gate is governance, the runtime gate is
  enforcement.
- A tool-catalog filter does not replace per-call authorization.
  Filtering a tool list by the caller's authority is exposure
  control; every consequential tool call MUST still pass the runtime
  gate.
- An orchestrator's internal check does not replace a Resource
  Server's PEP. Defense in depth is permitted; substitution is not.
- If no PEP can prevent the action for a given class, the deployment
  MUST NOT claim runtime enforcement for that class, and MUST name the
  action classes and execution paths it does mediate.

The boundary varies by action: an OAuth-protected API call is gated at
the Resource Server; a consequential MCP `tools/call` at the MCP
server; a local tool invocation, file write, or payment at the
orchestrator or whatever component drives the call; external egress at
an egress proxy. Where an action can be reached by an unmediated path
(a debug shell, an unsanctioned egress route, a direct connector), the
profile is not enforced for the classes that path reaches.

## Credential Custody and Mediated Execution {#custody}

In an agentic deployment the agent component is itself part of the
attack surface: it may be prompt-injected or compromised. The issuance
and runtime gates do not make the agent trustworthy; they bound what it
can do. A deployment lowers that bound further by not letting the agent
hold the authority whose misuse is unacceptable.

Mission-bound tokens are sender-constrained
({{I-D.draft-mcguinness-oauth-mission}}): whoever holds the
sender-constraint private key the token's `cnf` binds can present the
token. **Mediated execution** is a PEP placement that uses this: for the
action classes a deployment mediates, the sender-constraint private key
is held by the PEP that sits at the last controllable boundary
({{pep-placement}}), not by the agent component. The agent therefore
cannot present the Mission-bound credential directly; to act, it asks
the mediating PEP, which runs the decision of {{decision}} and only then
uses the key. No new token type, credential handle, or wire protocol is
introduced: this is a custody and placement property of the existing
sender-constraint key. The mediating PEP is a co-trusted process in the
agent's own trust domain, not a delegate: the token is unchanged, the
agent remains the principal of record (`client_id` still attributes the
action to the agent), and no `act`-chain entry is added.

~~~
 Agent                Mediating PEP              Resource
   |                  (holds cnf key)               |
   |-- request ------>|                             |
   |                  | run the decision;           |
   |                  | present token with key ---->|
   |                  |<---------- result ----------|
   |<---- result -----|                             |
   |                                                |
   |     X - - - - - - unmediated path absent - - ->|
~~~

For any action class a deployment mediates, the acting credential MUST
be sender-constrained: a bearer token is incompatible with mediated
custody, because a bearer token can be presented by whoever holds it,
including the agent, so the mediating PEP could not be the sole holder
of the authority.

For an action class it mediates, a deployment SHOULD hold the
sender-constraint private key for the Mission-bound credential in the
mediating PEP rather than in the agent component, and SHOULD do so for
the irreversible-action, external-commitment, and
privileged-administration classes. Two
properties follow: a credential exfiltrated from a compromised agent is
unusable without the key; and a compromised agent cannot reach a
mediated action without passing the per-action check, because it never
holds a usable credential for that class. Mediated execution depends on
the agent having no unmediated path to the resource; a Mission-aware
harness establishes that execution environment
({{I-D.draft-mcguinness-mission-harness}}).

Mediated custody's realizable form today is **gateway custody**: a
server-side gateway, an LLM gateway, an MCP gateway, or an egress
proxy, holds the sender-constraint key and the Mission-bound tokens,
and the agent receives no bearer credential at all. That shape is the
claim's home: the custody properties above belong to a deployment
built this way, and a developer laptop with a shell is outside them
by construction, not by configuration.

Where the deployment issues tokens under the client-instance-assertion
profile ({{I-D.draft-mcguinness-oauth-client-instance-assertion}}),
the sender-constraint key is instance-specific: that profile forbids a
key shared across a client's instances. Mediated custody composes with
that rule in either of two shapes. The mediating PEP holds
per-instance keys, taking custody of each instance's key rather than
one shared key; or the mediating PEP is itself the attested instance
that obtained the token, presenting the instance assertion and holding
the instance key. In both shapes that profile's no-shared-key rule and
this section's custody rules are satisfied together.

This narrows, and does not eliminate, the compromised-agent exposure.
The mediating PEP becomes a trusted component whose compromise is
out of scope here ({{security-considerations}}); a compromised agent can
still request mediated actions, which are gated, and can still misuse
any low-consequence authority it legitimately holds directly. The aim is
that the agent is structurally unable to take a high-consequence action
unilaterally, not that the agent is trusted.

The set of action classes a deployment mediates is the load-bearing
parameter here: a deployment that mediates nothing gains nothing from
this section, however it labels itself. A deployment that relies on this
profile to protect against agent compromise therefore MUST include the
high-consequence classes in its mediated set; the protection is only as
broad as that set.

Custody has a lifecycle. A deployment SHOULD prefer per-class
credentials with distinct `cnf` keys over sharing one key across
mediating PEPs, so that compromise of one mediating PEP does not expose
the authority of another. On compromise of a mediating PEP's key, the
deployment revokes the affected tokens and re-derives. A
sender-constraint private key is never published; rotation is
re-derivation with a new `cnf` binding plus revocation or expiry of
the tokens bound to the old key. The Enforcement Scope Statement
SHOULD state the custody replica topology (a shared HSM-held key
versus per-replica keys): replicating one `cnf` key across a PEP
fleet widens the exposure custody exists to shrink.

Mediated execution also places a controllable chokepoint on the
egress path itself: content-level controls this profile does not
define (data-loss prevention, redaction, payload policy) compose
naturally at the mediating PEP, the one component that sees the full
payload after the decision and before presentation.

## Least Exposure {#least-exposure}

A Mission bounds exposure as well as authority. An
agent exceeds the Mission envelope by invoking an action outside the
Authority Set, but also by being exposed to inputs the approved task
does not need: tools, data, memories, prompts, schemas, credentials,
or downstream responses. Authority bounds what execution can do;
exposure bounds what reasoning can see, and unnecessary context is
the raw material of prompt injection and within-scope laundering.

A Mission-aware runtime SHOULD minimize exposure of prompts,
retrieved documents, memory, tool catalogs, schemas, credentials, and
downstream responses to what the active Mission needs. Where mediated
custody is the deployment's declared control for an action class
({{custody}}), credential material and the sender-constraint private
key MUST NOT be exposed to the agent component: exposure reduces
mediation to advice.

Least exposure narrows what injection can read and what within-scope
laundering can draw from; it is not information-flow control, and an
exposure filter, like a tool-catalog filter ({{classification}}),
never replaces per-action authorization.

# Resource Server Runtime Profile {#rs-runtime-profile}

An OAuth Resource Server that claims conformance to this runtime
profile MUST publish or otherwise make available a Resource Server
runtime profile for the protected resources and operations in scope.
The Resource Server runtime profile is a deployment conformance
statement, not an OAuth Authorization Server metadata extension and
not a new access token format. It is the family's enforcement
adapter contract for a resource integration: the artifact two
independent implementations name and version to agree on a
resource's action identifiers, parameter semantics, and enforcement
composition, so the family standardizes the adapter contract rather
than every business action.

The Resource Server runtime profile is a delta over the deployment's
Enforcement Scope Statement ({{runtime-conformance}}): it inherits
the enforcement-scope items and records only what is specific to its
protected operations, restating an inherited item only where its
per-operation value differs. An independently operated Resource
Server MAY instead carry the full statement as a separable annex. It
MUST define:

- the endpoint families, methods, tools, or operation identifiers in
  scope, and the minimum action class for each, including any Resource
  policy floor above the default classification ({{classification}});
- the PEP location that can prevent each operation and any known
  execution path outside the claim, and, when the PEP and PDP are
  separate components, how they authenticate and integrity-protect
  decision requests and responses;
- the Operation Profile for each protected operation or family:
  parameter normalization, default insertion, omitted optional fields,
  set-like array handling, and idempotency-key handling;
- the permit validity window for each action class, and replay controls
  for permit use, including where single-use decision identifiers and
  idempotency keys are recorded and how long consumed identifiers are
  retained;
- how Resource policy is evaluated and composed with Mission authority,
  including local object authorization, tenant configuration, legal
  holds, service invariants, and risk policy;
- the runtime enforcement evidence fields and privacy treatment for
  decision and refusal records; and
- a profile identifier and version, so a change to any of the above
  is detectable and two independent implementations can name the same
  adapter contract.

A Resource Server MUST NOT claim this runtime profile for an operation
unless the operation's consequential effects pass through a PEP that
can refuse the operation after token validation and before execution.
A Resource Server that only validates the access token and checks
static token audience or scope claims does not implement this runtime
profile.

The Resource Server runtime profile MAY be documented in Resource
Server configuration, resource-server metadata defined elsewhere, a
contractual deployment profile, or another deployment-specific
mechanism. This document does not define a discovery document,
registry, or wire format for publishing it.

# Token Presentation and Validation {#token-validation}

The runtime decision is downstream of ordinary access token validation.
Before using a token's Mission, authority, subject, client, actor, or
confirmation-key values as decision inputs, the PEP MUST establish that
the access token is valid for the protected resource and request. For
the Mission-bound JWT access tokens defined by the issuance profile,
this means validating the JWT per {{RFC9068}}, verifying the issuer and
audience, checking token expiry, and verifying any sender-constraint
binding (`cnf`) under the proof-of-possession rules of the issuance
profile ({{I-D.draft-mcguinness-oauth-mission}}); this profile defines
no proof-of-possession mechanism of its own.

Where the validated token's `mission` claim carries the `expires_at`
member ({{I-D.draft-mcguinness-oauth-mission-issuance-grant}}), the
PEP or PDP MAY refuse actions past that instant without consulting a
state source: the value is an immutable commitment and a ceiling
only. It carries no liveness; the only-`active` rule and the
freshness requirements of {{state-freshness}} apply unchanged.

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
binding externally ({{mission-binding}}); in that case the absence of
the claim is not a refusal condition, and the join's verification of
the supplied Mission reference applies instead. When the PEP is an
OAuth Resource Server, it uses the
normal OAuth error behavior for the protected resource (for example,
Bearer token errors under {{RFC6750}}); this profile defines no new
OAuth error code.

Where the PEP and PDP are separate components, the decision request and
response MUST be integrity-protected and the parties MUST authenticate
each other. The PDP MUST accept token-derived inputs only from a PEP
authorized for the declared enforcement scope. A deployment can satisfy
this with a mutually authenticated channel, a signed decision request
and response, or another mechanism with equivalent security properties.
The PEP SHOULD send the PDP the minimum token-derived claims needed for
the decision rather than the presented access token. If a deployment
sends the access token itself to the PDP, the PDP MUST treat it as a
credential, protect it against disclosure, and MUST NOT use it outside
the declared enforcement scope.

# The Runtime Decision {#decision}

Before a consequential action runs, its PEP MUST obtain a permit from
a PDP that evaluates the action against the established Mission
({{mission-binding}}). This is the normative contract. The decision
API wire format is a deployment choice; a binding maps this contract
onto a concrete API ({{authzen}}).

The PEP MUST supply the inputs the PDP needs for the Mission-bound
decision; {{decision-inputs}} defines them.

On a deny, the PEP MUST refuse the action; a deny is terminal for the
attempted action.

A deny need not end the task, however: a decision-API binding MAY
mark a denial requestable and route it through an access-request and
approval workflow ({{action-approval}}, {{authzen}}). An approved
request completes in one of two ways. An in-authority approval gate
is satisfied by the approval attribute alone on the fresh decision;
nothing persists beyond it. Missing authority is realized as a
governance state change the fresh decision observes: a durable
Mission expansion, a role or relationship grant, or another authority
update. This profile defines the runtime decision; it leaves the
request-approval loop, and any realization that persists authority,
to the decision-API binding, the issuance profile's expansion
mechanism, and the deployment's own governance.

A decision separates three response lanes, and a binding maps each
lane to its wire. Obligations and advice are PEP work under the
existing decision: obligations bind (a step-up, a mandated
notification; failing one makes the effective result deny), and
advice, where a binding defines it, is safely ignorable and never
carries a mandatory control. Decision conditions (request binding,
validity bound, use limit) are not work but constraints of the
decision itself, evaluated at every use ({{decision-output}}). Governance rides the
request-approval loop, never the permit: an access request tracked by
a task handle, resolved by an approval or another authority-state
change. Partial evaluation, residual policy the PEP completes
locally, is the third lane; this profile reserves it and defines no
residual form. Two things are not lanes: a description of
requestable authority is payload a request may carry, and a
transient condition is a denial outcome carrying a retry signal,
calling for neither remediation nor a request. The AuthZEN binding
realizes the first two lanes and the transient outcome as
obligations, ARAP composition, and its transient-denial members
({{authzen}}).

The PDP's placement is a deployment choice (co-located with the
Mission's `issuer`, embedded in the Resource Server, a tenant-scoped
service, or a shared service); this document does not mandate one. The
requirement is only that a PEP at each consequential boundary can
reach an applicable PDP.

## Decision Output {#decision-output}

Whatever the wire, a runtime decision presents one abstract output,
and a binding maps each member onto its protocol rather than
inventing parallel semantics:

- an outcome: permit or deny;
- an evaluation identifier and evaluation time, correlating the
  decision with its evidence;
- on a deny, a reason from the binding's failure classification;
- on a permit, decision conditions: declarative constraints on
  relying on the permit (a request binding, a validity bound, a use
  limit), evaluated at every use of the permit; a condition the
  enforcing component does not recognize makes the permit unusable,
  the reliance counterpart of the obligations rule;
- zero or more obligations: mandatory enforcement duties the PEP
  completes under the existing decision, where an unfulfilled or
  unrecognized obligation is an effective deny;
- zero or more advice items, where the binding defines them: safely
  ignorable hints that never carry a mandatory control;
- optionally, an access-request signal marking a denial requestable
  through a governance workflow;
- optionally, a retry signal marking a denial transient, with a wait
  interval; and
- a reserved residual-policy member for a future partial-evaluation
  composition, which this profile does not define.

An approval produced by the governance workflow returns as decision
input on a fresh evaluation ({{action-approval}}), never as output
state. The AuthZEN binding maps this output onto its response
context, the obligations profile, and ARAP ({{authzen}}).

## Decision Inputs {#decision-inputs}

Runtime enforcement MUST evaluate every input below except the last:
History ({{input-history}}) is OPTIONAL, evaluated where the
deployment declares it.

### Authority {#input-authority}

The action MUST be authorized by an applicable
`authorization_details` entry the Mission-bound token carries, or
that is otherwise available to the PEP or PDP for that token under
the issuance profile (for example, through introspection when the
authority is not represented inline).

Where a Mission participates in the Containment profile
({{I-D.draft-mcguinness-oauth-mission-containment}}), this input is
the Mission's current Effective Authority Set, the approved set
minus contained capability, not the approved set the token's
`authorization_details` entry names at face value. The PDP MUST
refuse an action within an entry that is currently contained even
though a token issued before the contain transition still carries
it, established from the same Mission state source and freshness
bound that governs the `active` check ({{state-freshness}}); a
Mission stays `active` while contained, so this check, not the state
check, is what a containment-aware PDP adds. A deployment that does
not deploy the Containment profile evaluates the approved Authority
Set unchanged, as the rest of this section states. The decision-API
binding provides the extension point through which a companion
profile carries which evaluated set the PDP used ({{authzen}}).

For an entry of type `mission_resource_access`, the action's
`resource` and invoked action or tool identity MUST be within that
entry's `resource` and `actions`, under the subset rule of
{{I-D.draft-mcguinness-oauth-mission}}. The PEP asserts the
capability identity (for example, the tool or function name) it will
invoke. The PDP MUST refuse an identity outside the approved
`actions`.

For any other `authorization_details` type, the PDP MUST evaluate
the action under that type's documented runtime semantics and MUST
refuse if it does not understand or cannot enforce those semantics.

The identity of the executing component that serves a capability
(for example, an MCP server instance) is a request-time fact the
decision-API binding MAY carry ({{authzen}}); Resource policy MAY
refuse an executor outside the deployment's trusted set.

A capability sourced from a discovered catalog is additionally
subject to the capability-drift rule of {{capability-drift}}.

### Capability Drift {#capability-drift}

For a capability sourced from a discovered catalog (an MCP tool
catalog, an OpenAPI document, or an equivalent source), where the
validating server recorded a digest of the capability's extracted
definition at derivation, the PDP MUST refuse the action when the
digest of the capability's current extracted definition differs from
the recorded digest (capability drift). The extraction rule per
source format is the capability-binding companion's
({{I-D.draft-mcguinness-mission-capability-binding}}).

A source change that leaves the extracted definition byte-identical
does not by itself refuse. Where the deployment also recorded a
whole-source digest, that digest's stricter semantics apply and any
source change refuses. The recorded digests are part of the derived
authority and are covered by `authority_hash`
({{I-D.draft-mcguinness-oauth-mission}}). Cross-format
canonicalization, signed capability manifests, and cross-catalog
identity remain out of scope ({{deferred}}).

### Resource Policy {#input-resource-policy}

The runtime decision MUST include any applicable Resource policy. A
Mission-bound token and runtime permit are an upper bound on
authority, not a command for the Resource Server to perform the
action. Resource policy MAY be evaluated by the PDP, by the Resource
Server or PEP as a composed local authorization step, or by both.
The action MUST fail closed unless both Mission authority and
Resource policy permit it. Resource policy includes object-level
authorization, tenant configuration, legal holds, service
invariants, and risk policy.

### Parameters {#input-parameters}

Every `constraints` value on the applicable entry MUST be evaluated
against its declared input domain: the concrete action parameters
for parameter constraints, and, where the constraint's definition
declares them, the resource, the subject, Mission state, time,
history, or metered consumption. A constraint the PDP does not
understand, cannot supply the declared inputs for, or cannot enforce
or meter MUST cause refusal; it MUST NOT be ignored or reduced to
disclosure-only treatment.

### Actor {#input-actor}

When delegation is in effect, the PDP MUST evaluate the
authenticated `act` chain as part of the runtime actor context and
refuse a chain that is missing or malformed. When an `act` chain is
present, the PDP MUST NOT treat `client_id` alone as the immediate
actor.

Runtime enforcement consumes the actor context that results from the
issuance profile's delegation checks; it does not recompute the
issuance-time subset validation. The runtime decision MUST NOT
expand authority beyond the issued `authorization_details`. The
issuance profile's delegation constraints are not re-applied here
unless the deployment documents them as runtime Resource policy, but
a deployment MAY apply additional actor-sensitive Resource policy
({{input-resource-policy}}).

Token claims the AS verified under an attested-instance profile,
such as `agent_instance_id` and `agent_model`
({{I-D.draft-mcguinness-oauth-ai-agent-instance}}), are verified
actor context a deployment's Resource policy MAY evaluate; unlike a
self-asserted model or instance label, they are attester-backed
facts.

Where the deployment operates an agent registry, the immediate
actor's registry state (status, revocation, approved deployment
version) is further actor context Resource policy MAY require. A
deployment that declares agent-state evaluation in its Enforcement
Scope Statement treats the registry as a state source under this
profile's freshness discipline: a declared staleness bound, and
refusal when the acting agent or its deployment version is revoked
or the state cannot be established within the bound
({{state-freshness}}). The agent, Mission, and credential lifecycles
gate conjunctively; a valid token never overrides a revoked agent or
a non-active Mission
({{I-D.draft-mcguinness-mission-architecture}}).

### Time {#input-time}

The PDP MUST refuse if the decision context indicates the token is
expired. The issuance profile caps a derived token's `exp` at the
Mission's `expires_at`, so the `exp` check enforces the Mission's
expiry transitively. The standard `mission` claim and introspection
do not surface `expires_at`; where a Mission state source does
expose it (or reports the Mission `expired`), the PDP MUST refuse on
it independent of the token's own `exp`.

The PDP sets the permit's validity window from these inputs. That
the action actually executes within that window is the executing
PEP's reverification, not a decision input ({{parameter-binding}}).

### State {#input-state}

The PDP MUST refuse unless the Mission is `active`
({{state-freshness}}).

### History {#input-history}

The inputs above evaluate the request; this input evaluates where
the undertaking stands. A deployment MAY evaluate policy predicates
over the Mission's prior Decision and Execution Evidence (for
example, a precondition that a named action class completed) as
deployment-local context keyed on the Mission's identity. This is
the sequence-aware half of the context asymmetry the architecture
names ({{I-D.draft-mcguinness-mission-architecture}}): the resource
prices "delete database" the same in isolation and inside an
approved migration whose copy steps completed, and only the layer
where the undertaking's history accumulates can tell the two apart.
The policy side selects: the deployment's policy or materialized
view names the predicates a decision requires, and the requesting
component supplies facts or an evidence reference, never the choice
of predicate.

History is a decision input, never a grant. A history predicate
MUST NOT expand authority beyond the issued
`authorization_details`. Where deployment or Resource policy
requires a history predicate, the PDP MUST fail closed when the
predicate cannot be established or the evidence store cannot be
consulted. A deployment that declares history evaluation in its
Enforcement Scope Statement treats the evidence store as a state
source under this profile's freshness discipline: a declared
staleness bound, and refusal when the required history cannot be
established within the bound ({{state-freshness}}). Cross-PDP
history composes through the deployment's evidence store or
registered transparency records
({{I-D.draft-mcguinness-mission-audit}}) and is otherwise out of
scope. How a decision request names a history predicate, and how
its evaluation is recorded, is the decision-API binding's
({{authzen}}).

## Mission Binding Establishment {#mission-binding}

Every decision evaluates one Mission: the **established Mission**. A
deployment establishes it in one of two modes:

- **Credential-carried.** The acting token's `mission` claim
  identifies the Mission, under the issuance profile's binding
  ({{I-D.draft-mcguinness-oauth-mission}}). The PEP takes the Mission
  reference from the validated token ({{token-validation}}).
- **Externally established.** The token carries no `mission` claim,
  and the PEP supplies a Mission reference from the deployment's
  Mission binding source. The PDP MUST verify that reference against
  the acting credential under a join a binding profile defines; an
  unverified reference MUST NOT establish the Mission. The Mission
  Authority Server profile defines the concrete join for this mode
  ({{I-D.draft-mcguinness-mission-authority-server}}), and the AAuth
  binding's reference propagation supplies the externally carried
  reference for such a join
  ({{I-D.draft-mcguinness-mission-aauth}}).

The mode each enforcement scope uses is part of its Enforcement
Scope Statement ({{runtime-conformance}}). In either mode, the
established Mission is the Mission every input of {{decision-inputs}}
(authority, Resource policy, parameters, actor, time, state) is
evaluated against, and the Mission reference the permit and the
evidence record bind.

## Mission State and Freshness {#state-freshness}

A Mission-aware decision needs the Mission's current state, which a
token alone does not convey. A runtime deployment MUST define the
Mission state source it trusts for each enforcement scope. Examples
include issuer AS token introspection, a local Mission database, an
authenticated status or event feed from the Mission `issuer`, or a
short-lived cross-domain credential
({{I-D.draft-mcguinness-oauth-mission-cross-domain}}) whose lifetime
is the deployment's accepted state lease. The materialized policy
view ({{policy-view}}) is not a state source: it commits the
compiled authority, never the mutable lifecycle state a decision
consults.

The substrate this profile enforces against provides at least a
lifecycle-gated capability (Mission state at the issuer, with reliance
boundable by credential lifetime alone) and MAY additionally provide a
state-observable capability (an authenticated freshness source with a
stated staleness bound). A deployment claiming runtime enforcement for
an action class whose published staleness bound is tighter than the
credential lifetime REQUIRES a state-observable substrate for that
class; the high-consequence classes below always are. A
lifecycle-gated-only substrate supports issuance gating and a
lifetime-bounded action-time posture only: it cannot reflect a
revocation faster than the credential lifetime, so it cannot host a
class whose bound demands that.

- The PDP MUST refuse a consequential action when it cannot establish,
  within the deployment's published staleness bound, that the Mission
  is `active`.
- A state source MUST either report the Mission state with an
  explicit expiry or lease end, or report only an observation time, in
  which case the state remains acceptable only until that observation
  time plus the deployment's published staleness bound for the
  relevant action class. A permit issued from that state view MUST
  expire no later than this state valid-through: the reported expiry
  or lease end, or, absent one, the observation time plus the
  published staleness bound. The observation time alone, without
  adding the staleness bound, is never a permit's expiry.
- When the credential issuer also holds the Mission, the PDP can learn
  state through token introspection ({{RFC7662}}) at the issuer per
  {{I-D.draft-mcguinness-oauth-mission}}. A non-issuer Resource AS
  introspecting a local token
  ({{I-D.draft-mcguinness-oauth-mission-cross-domain}}) cannot report
  current Mission state; it can establish local token validity, but not
  issuer-side Mission freshness.
- This document defines no cross-issuer by-Mission status query.
  Deployments that need tighter freshness than the token or
  cross-domain grant
  ({{I-D.draft-mcguinness-oauth-mission-cross-domain}}) lifetime
  provides use the Mission Status profile
  ({{I-D.draft-mcguinness-oauth-mission-status}}) or Mission Lifecycle
  Signals ({{I-D.draft-mcguinness-oauth-mission-signals}}), or an
  out-of-band trusted status feed.
- The maximum staleness bound per action class and state source is
  declared in the Enforcement Scope Statement
  ({{runtime-conformance}}), together with the revocation latency it
  implies. Publishing the bound without its latency consequence is
  non-conformant. For a PDP-gated class, a Mission's revocation
  takes effect, in the worst case, after the staleness bound plus
  the permit validity window plus the class's execution bound
  ({{parameter-binding}}); the derived token's lifetime is the bound
  only for paths outside PDP gating. This document imposes no
  universal value because the acceptable latency is deployment- and
  consequence-specific; the bound is the number that determines the
  profile's headline revocation property. The per-class budgets
  below are the RECOMMENDED defaults for the value.
- For the high-consequence classes, the state source MUST be an active
  freshness mechanism that can reflect a revocation within the staleness
  bound: token introspection at the issuer ({{RFC7662}}), the Mission Status
  profile ({{I-D.draft-mcguinness-oauth-mission-status}}), a Mission
  Status List whose Status List Token TTL is within the bound (the
  status profile's swarm-scale pull floor,
  {{I-D.draft-mcguinness-oauth-mission-status}}), or Mission
  Lifecycle Signals ({{I-D.draft-mcguinness-oauth-mission-signals}}).
  Token-lifetime expiry alone is not an acceptable state source for
  these classes: it bounds staleness only by the lifetime, so a revoked
  Mission keeps deriving consequence until tokens age out, which is the
  ambient-authority gap this profile exists to close.

For a deployment whose access tokens are short-lived and whose
issuance and refresh are state-gated per the core
({{I-D.draft-mcguinness-oauth-mission}}), the refresh cycle itself is
a conforming active freshness source for any action class whose
published staleness bound the token lifetime meets: the issuance gate
is an active check, and a token that exists is evidence the Mission
was `active` within the lifetime. This source's revocation latency
floor is the token lifetime, so it conforms only for classes whose
bound admits that floor, and the higher-frequency sources (Status,
introspection, Signals) remain the path to tighter bounds.

**Token-lifetime freshness.** Below the high-consequence floor, token
expiry is itself a conforming state source: derivation and refresh
are gated on `active` ({{I-D.draft-mcguinness-oauth-mission}}), so a
token's remaining lifetime bounds the staleness of the authority it
carries, and the published staleness bound for a class relying on it
is the maximum token lifetime. Expiry is a state check performed by
the clock: no status call, no introspection, no change at the
consuming resource. A deployment declares it per class in its
Enforcement Scope Statement like any other source; what it cannot do
is reflect a revocation faster than the lifetime, which is why the
high-consequence classes require an active source.

Together the sources form a single freshness dial, and a deployment
picks a position per action class rather than one posture for the
estate. The comparison, informative:

| State source | Capability | Exposure bound | Per-action cost | Depends on | Cannot provide |
|---|---|---|---|---|---|
| Token-lifetime expiry | lifecycle-gated | maximum token lifetime | local clock check | nothing beyond the token | suspend, complete, or any revocation inside the lifetime |
| State-gated refresh | lifecycle-gated | token lifetime (the refresh interval) | none at action time | the issuer at each refresh | anything between refreshes |
| Mission Status List | state-observable | Status List Token TTL | local bit read | one list fetch per window | terminal-state detail; a non-VALID bit sends the consumer to the authoritative surface |
| Status operation or introspection | state-observable | published staleness bound | one lookup within the bound, cacheable to `fresh_until` | status surface availability | revocation inside the bound |
| Lifecycle Signals | state-observable | delivery latency within the verified stream | none (event-driven) | stream liveness | the pull floor; a dead stream is stale state |

No position on this dial requires a per-request issuer call: the
tightest posture costs one lookup per staleness bound, amortized by
caching, and the loosest costs a clock. The dial is the architecture's
freshness dial made concrete
({{I-D.draft-mcguinness-mission-architecture}}), and the Enforcement
Scope Statement records the chosen position per class.

The following are the RECOMMENDED default freshness postures per
class, adopted absent a documented, consequence-specific analysis:

| Class | Suggested freshness posture |
|---|---|
| Consequential read | Token lifetime or a short state lease; tighter for privacy-sensitive, cross-tenant, or bulk reads |
| Consequential write | A short state lease, typically measured in minutes |
| Irreversible action | Active source required; immediate check or single-use permit, target under 300 s |
| External commitment | Active source required; immediate check or single-use permit, plus an egress PEP for external communication, target under 300 s |
| Privileged administration | Active source required; immediate check, suitable for composition with local step-up, target under 300 s |
| Audit-only | No active freshness required |

A deployment justifies any looser value for a high-consequence class
in its Enforcement Scope Statement.

## Materialized Policy View {#policy-view}

A PDP evaluates a Mission against an action through a **materialized
policy view**: the reproducible, evaluable form of the Mission's
approved authority, produced by the issuing Authorization Server or a
trusted compiler and loaded by the PDP. A **trusted compiler** is a
component the deployment trusts to materialize the Mission's approved
authority faithfully and reproducibly; it is in the deployment's trust
domain and its output is bound by the content-addressed
`policy_view_id` below. The view is substrate-independent runtime
machinery; a decision-API binding carries only its identifier on the
wire ({{authzen}}).

The materialized policy view MUST satisfy three properties:

- Reproducible: identical manifest inputs, including the compiler
  identity, produce a byte-identical manifest, and therefore an
  identical `policy_view_id`, under the canonicalization rules of
  {{I-D.draft-mcguinness-oauth-mission}}.
- Identifiable: the view carries a `policy_view_id`, so PDP cache
  entries are addressable.
- Bounded: materialization is faithful and does not enlarge the
  Authority Set's semantic bounds. A materialized view is an
  evaluation aid, never new authority.

The committed object is a canonical JSON manifest, never the engine
binary itself: JCS canonicalization applies to the manifest, and an
engine-native artifact enters the manifest only by digest, never
directly. `policy_view_id` is the integrity-anchor encoded form
({{I-D.draft-mcguinness-oauth-mission}}) of the SHA-256 {{RFC6234}} of
the JCS {{RFC8785}} canonical bytes of that profile's domain-separated,
issuer-bound integrity-anchor envelope with `typ` `mission-policy-view`:

~~~
SHA-256(JCS({
  "typ":   "mission-policy-view",
  "iss":   <mission.issuer>,
  "value": <materialized view manifest>
}))
~~~

`policy_view_id` is an envelope anchor under the substrate's default
commitment construction, which this document imports normatively
({{I-D.draft-mcguinness-mission-substrate}}).

The committed manifest MUST carry:

- `mission_id` and `authority_hash`: the Mission's identifier and
  Authority Set integrity anchor.
- `policy_version`: the derivation `policy_version` recorded at the
  approval event.
- `compiler`: an object naming the trusted compiler that produced the
  manifest, with `profile` (the compiler's identity) and `version`
  (its version), so a change in compiler identity or version is
  itself a reproducibility input rather than an unaccounted
  difference.
- Either `policy_ir`, the normalized policy intermediate
  representation as JSON, or `artifact`, an object carrying `digest`
  (the integrity-anchor encoded digest of the engine-native artifact)
  and `encoding` (naming the artifact's format), for a deployment
  that compiles to an engine-native form this document does not
  standardize.

The manifest MUST NOT embed Mission lifecycle state: three independent
values govern reliance, and conflating them is the common
implementation error. `policy_view_id` is the content identity of the
compiled authority and the cache key. A `mission_state_version`, where
the deployment serves one ({{I-D.draft-mcguinness-oauth-mission-status}}),
versions the mutable lifecycle state the decision consulted. The state
observation's freshness or lease bounds how long that consultation
stands ({{state-freshness}}). A state transition invalidates reliance
through the version and freshness values without re-identifying the
compiled authority; the manifest acquires a new `policy_view_id` only
when the authority it compiles, or the compiler that compiled it,
changes. A consistency check between a decision request's Mission
reference and the loaded view is therefore an equality test: the
request's Mission `id` and `authority_hash` either equal the committed
values or the view does not apply. Because `policy_view_id` is a
content hash, any change to the manifest yields a new `policy_view_id`,
so equality on `policy_view_id` is the cache identity; it is never the
freshness test. This document defines no second canonicalization and
no policy-language wire form for `policy_ir` or the engine-native
artifact.

## Semantic Evaluators {#semantic-evaluators}

A structurally valid action can still be semantically out of bounds:
every schema check passes while the content betrays the task. A
deployment MAY add a semantic evaluator (a data-loss-prevention
engine, an LLM-based content policy, an embedding-similarity check)
to the decision path. This profile does not standardize the
evaluator; it fixes how one composes:

- **Rubric.** The evaluator judges content against the approved
  task, not a free-floating policy: its rubric is the recorded
  Mission Intent, whose integrity is verifiable against
  `intent_hash`, optionally with the consented Authority Set under
  `authority_hash`. A rubric that cannot be tied to the committed
  record is ordinary deployment policy, not a Mission check.
- **Composition.** The verdict enters the decision as Resource
  policy, carried as deployment-defined context. It can deny, or
  route the action to the existing affordances: an action-bound
  human approval ({{action-approval}}, the decision API binding's
  `approval_required`) or an authentication step-up, which the
  decision API binding carries as an obligation on the permit
  ({{authzen}}). It MUST NOT widen authority and
  MUST NOT substitute for a structural check this profile requires.
- **Evidence.** When a verdict contributes to a decision, the
  decision evidence SHOULD record the evaluator's identity or
  version and its verdict, so a semantic denial is as
  reconstructable as a structural one.
- **Latency.** The evaluator runs inside the invoking action
  class's latency budget ({{runtime-deployment}}); a deployment
  that cannot afford a synchronous evaluation on a class routes the
  class to action-bound approval or narrows its authority instead.

An LLM-based evaluator is itself part of the attack surface: it
reads the same adversarial content it judges, and can be injected
by it. It therefore augments the structural signals (provenance,
composition, enumeration, volume, re-consent) and never replaces
them, and a deployment that relies on one for an action class
states that reliance in its Enforcement Scope Statement.

# Parameter Binding and Time-of-Check to Time-of-Use {#parameter-binding}

Parameter binding is only as consistent as the normalization behind
it, so this profile collects that normalization into a named
**Operation Profile**: the per-operation (or per-operation-family)
statement, part of the Resource Server runtime profile
({{rs-runtime-profile}}), that MUST fix all of the following, so two
implementers of the same operation bind the same bytes:

- the action identifier and how it maps to a `resource`;
- the parameter schema: which parameters exist and their types;
- default insertion and omitted-optional-field rules applied before
  canonicalization;
- set-like array handling and any other canonicalization beyond the
  issuance profile's rules;
- exactly which fields enter the `parameter_digest`;
- digest test vectors for the operation, each carrying the operation
  input before normalization, the exact normalized parameter value,
  the exact JCS UTF-8 serialization (or an unambiguous byte
  representation of it, such as UTF-8 hex), and the resulting
  prefixed digest; at least one vector MUST exercise a normalization
  rule that materially changes the input (default insertion, an
  omitted optional field, set-like array treatment, or another
  operation-specific rule), and at least one conformance case MUST
  present changed parameters that fail the digest match, so
  normalization drift between the PDP and the executing PEP surfaces
  at profile adoption rather than as a fail-closed outage;
- whether a single-use decision identifier is required (versus a
  validity window plus idempotency key);
- whether an execution lease is required; and
- the evidence fields the decision and execution records carry for the
  operation.

The rules below are the normative requirements the Operation Profile
records; a deployment that leaves any of them unstated for a mediated
operation has not specified that operation's binding.

For a schema-bearing capability, a discovered tool that publishes
an input schema, a deployment MAY derive the Operation Profile
mechanically rather than author it: the parameter schema is the
published input schema; no defaults are inserted and omitted
optional fields stay omitted; every field of the raw arguments
object enters the `parameter_digest`; and the single-use,
idempotency, and lease requirements follow from the operation's
class. A derived profile is recorded with the capability's source
digest where the capability-source binding applies
({{I-D.draft-mcguinness-mission-capability-binding}}), so the binding
drifts with the schema that defined it.

## Parameter Digest {#parameter-digest}

A permit for an operation does not authorize arbitrary parameter
values. For consequential writes, irreversible actions, external
commitments, and privileged administration, the PDP MUST bind its
permit to the normalized action parameters through a
`parameter_digest`, and the executing PEP MUST recompute and reverify
that digest immediately before acting
({{execution-reverification}}).

- `parameter_digest` is `sha-256:` followed by the base64url, no
  padding, SHA-256 {{RFC6234}} of the JCS {{RFC8785}} serialization of
  the normalized parameter object. It MUST be computed under the same
  canonicalization rules the issuance profile defines (duplicate
  member rejection, significant array order, byte-for-byte URI
  comparison); this document does not define a second canonicalization.
  It is a canonical-object digest under the substrate's default
  commitment construction, which this document imports normatively
  ({{I-D.draft-mcguinness-mission-substrate}}): the I-JSON
  requirement and the reject-unknown-prefix rule apply to computing
  and verifying it unchanged.
- Every parameter that influences the action's external effect (for
  example, the recipient, destination, amount, or target object) MUST
  enter the `parameter_digest`. A field the deployment excludes MUST be
  shown effect-free in the Operation Profile, which records why that
  field cannot change the action's external effect; a field whose effect
  is not so justified MUST be included.
- The Operation Profile MUST define default insertion, omitted
  optional fields, and set-like array handling before canonicalization.

## Permit Binding {#permit-binding}

Beyond the `parameter_digest`, the permit MUST also bind:

- the Mission reference;
- the token issuer, when available;
- the token audience or protected resource;
- `sub`;
- `client_id`;
- the actor context;
- the sender-constraint confirmation key, when present;
- the action;
- the resource;
- the authorizing `authorization_details` entry, or an entry digest;
- the PDP's policy-view version; and
- a permit lifetime control bounded by the Mission state freshness
  requirement ({{state-freshness}}).

A permit is bound to the full set of authorization-relevant inputs it
was issued for: the authorization binding, which a decision-API
binding realizes as one normalized projection over those inputs,
never as an enumerated subset of fields
({{I-D.draft-mcguinness-mission-authzen}}).

The permit lifetime control is set by action class:

| Action class | Required permit-lifetime control |
|---|---|
| Reversible consequential write | The control MUST be either a single-use decision identifier or a short validity window combined with an idempotency key that prevents repeat execution of the same normalized action |
| Irreversible action, external commitment, or privileged administration | The control MUST be a single-use decision identifier: a validity window alone does not bound how many times such a permit executes |

## Single-Use Identifiers {#single-use-identifiers}

Where a single-use decision identifier is used:

- The enforcing component MUST record consumed identifiers for at
  least the permit lifetime.
- The enforcing component MUST refuse, fail closed, any second
  presentation of a consumed identifier. This is independent of
  consumption metering and applies even when the action carries no
  consumption bound.
- The consumed-identifier store MUST survive an enforcing-component
  restart, or the component MUST fail closed for permits issued
  before the restart.
- A multi-instance PEP MUST share or partition the store so a
  single-use identifier cannot be consumed once per replica.

## Idempotency {#idempotency}

A single-use identifier bounds executions of one permit, not permits
for one action. Enforcement is an atomic state machine over the
(idempotency scope, `idempotency_key`) pair, not a comparison against
retained parameters, with three separated responsibilities: the PDP
prevents concurrent double-permits before an operation completes, the
PEP prevents a consumed permit from executing twice, and the resource
owns the lifecycle and prior result of a completed operation.

- For every non-idempotent operation in the irreversible-action,
  external-commitment, and privileged-administration classes, the
  Operation Profile MUST therefore also define an idempotency key.
- Before issuing a permit for a keyed action, the PDP MUST atomically
  claim the pair (idempotency scope, `idempotency_key`) together with
  the request's operation identity, a canonical projection a
  decision-API binding defines
  ({{I-D.draft-mcguinness-mission-authzen}}). The claim is a single
  linearizable operation: of two concurrent requests presenting the
  same scope and key, exactly one obtains the claim, and the other
  observes it.

**Evaluation retransmission (PDP)**:
: For a re-presentation whose cache key is equal to the prior
  decision's and whose claim matches (same idempotency scope and key,
  same operation identity), while the prior permit is unexpired and
  its `evaluation_id` unconsumed, the PDP SHOULD return the prior
  decision, so a permit response lost in transit does not lock the
  action out for the reconciliation window. This is the only same-key
  path that returns a permit: the PDP claim's purpose is narrowed to
  preventing concurrent double-permits before completion, never to
  replaying a completed result.

**Permit replay prevention (PEP)**:
: Unchanged: the single-use rule of {{single-use-identifiers}} is
  itself atomic. Before releasing the effect of a
  `use_limit`-bearing permit, the enforcement scope MUST atomically
  consume, or atomically reserve and then confirm, the
  `evaluation_id` in a store that is linearizable across every PEP
  replica of the scope. Two replicas MUST NOT both succeed in
  consuming the same identifier; a replica that instead observes an
  already-consumed identifier treats the presentation as consumed,
  not as a fresh single use, a decision-API binding's
  `permit_consumed` classification
  ({{I-D.draft-mcguinness-mission-authzen}}).

**Operation idempotency (Resource Server / Operation Profile)**:
: The resource, not the PDP, owns the key's lifecycle and the prior
  result once an operation completes: for a COMPLETED duplicate the
  resource returns the prior operation result under the Operation
  Profile's rules. A fresh authorization denial is not the vehicle
  for result replay; the claim states below govern only whether a
  new permit issues, never what the resource returns for a completed
  key.

The claim resolves per state, keyed on whether the presented
(idempotency scope, `idempotency_key`) pair matches an existing claim
and whether the request's operation identity equals the one the claim
was made under:

| Claim state | Same key + same operation identity | Same key + different operation identity |
|---|---|---|
| claimed / permit-issued (unconsumed, unexpired) | return the prior decision (retransmission) | `idempotency_conflict`, terminal |
| reserved / outcome unresolved | `duplicate_suppressed`, transient (`next_action: retry`, `retry_after` within the reconciliation window) | `idempotency_conflict`, terminal |
| indeterminate (window closed, outcome undetermined, {{evidence}}) | `duplicate_suppressed`, terminal (`next_action: none`); resolution is operational, never a new permit | `idempotency_conflict`, terminal |
| completed (within window or tombstoned horizon) | `duplicate_suppressed`, terminal (`next_action: none`); the prior result is available from the resource under the Operation Profile | `idempotency_conflict`, terminal |
| failed | deployment policy: retry as a NEW operation requires a new key | `idempotency_conflict`, terminal |
| expired past the declared horizon | outside the guarantee; treated as new. An indeterminate tombstone does not expire into this state ({{evidence}}) | outside the guarantee |
{: title="Idempotency claim state resolution"}

A different operation identity under the same key is always a
conflict, never a new execution: an idempotency key identifies one
intended execution of one normalized request, the same discipline
HTTP's own Idempotency-Key handling applies, restated here in the
family's own terms. A consumed key never yields a second execution:
retransmission returns the prior decision, and a completed operation's
result is replayed by the resource, not re-executed. An intentional
re-execution of the same normalized action is a new operation under a
new idempotency key, never a retry under the consumed one, and an
action-bound approval ({{action-approval}}) authorizes that new
operation as such, never re-execution under the consumed key.

- The idempotency scope is, at minimum, the Mission, the subject and
  the actor, the audience, the action, and the resource; a deployment
  MAY narrow it further and MUST publish the scope in its Enforcement
  Scope Statement. Volatile members MUST NOT be added to the scope.
- For the high-consequence classes the deployment MUST retain a
  durable consumed-key record (a tombstone) for at least its declared
  idempotency horizon, published in the Enforcement Scope Statement.
  Tombstones are enforced, not merely retained: within that horizon a
  claim against a tombstoned key MUST be refused, never treated as a
  fresh claim. Outside those classes a deployment MAY scope the
  guarantee to the reconciliation window ({{evidence}}), and it MUST
  publish which posture applies.

## Execution Reverification {#execution-reverification}

The executing PEP MUST verify the permit's bindings
({{permit-binding}}) and MUST recompute the `parameter_digest`
against the parameters it is about to use. A mismatch MUST cause
refusal: the permit does not authorize the changed parameters.

A permit authorizes initiation. An action still executing when the
permit expires MAY run to completion, unless the action class requires
an execution lease, which the Operation Profile defines; when a lease
is required the executing PEP MUST stop or renew before the lease
expires. For the irreversible-action, external-commitment, and
privileged-administration classes the Operation Profile MUST define
an execution lease or a published maximum execution duration, and
run-to-completion applies only within that bound.

This closes the time-of-check to time-of-use gap and prevents a permit
from being replayed for a different request (the `parameter_digest`
mismatches). For non-idempotent consequential writes, irreversible
actions, external commitments, and privileged administration, the
single-use decision identifier prevents repeat execution under one
permit ({{single-use-identifiers}}), and the required idempotency key
prevents repeat execution of the same normalized action across
separately obtained permits ({{idempotency}}).

## Binding for Consequential Reads {#read-binding}

Consequential reads do not require a parameter digest by default; the
evaluation request still appears in the evidence record, by digest
where the parameters are sensitive ({{evidence}}).

Deployments MUST require parameter binding for consequential reads
when read parameters materially change the effective resource set or
disclosure risk. Independent of that risk judgment, a binding floor
applies: a consequential read whose parameters select a cross-tenant
or cross-audience scope, request a bulk or export-like result, or
choose the returned fields or destination MUST bind those parameters.
A deployment MUST NOT classify such a read as not materially
affecting the resource set. Other examples that materially change the
resource set or disclosure risk include privacy-sensitive filters and
aggregation level. Ordinary reads that do not change the resource set
or disclosure risk can remain unbound.

# Consumption Bounds Fail Closed {#metering}

This document defines no cumulative consumption bounds and no metering
machinery. Cumulative bounds on Mission activity (budget, call counts,
wall-clock duration), and the reserve, commit, lease, settlement, and
distributed-consistency semantics that enforce them, are defined by an
experimental companion ({{I-D.draft-mcguinness-mission-metering}}).

What this document fixes is the failure posture. As with all
constraints, an unmetered or unrecognized consumption bound MUST cause
refusal rather than silent pass-through: when an applicable entry's
`constraints`, or the Mission's `controls`, carries a bound that
expresses cumulative consumption and the deployment does not meter it,
the PDP MUST refuse a consequential action governed by it. A deployment
MUST NOT advertise consumption enforcement it does not perform.

# Failure Modes {#failure-modes}

Enforcement is meaningful only if failure is bounded. A PDP or PEP
MUST behave as follows; in all cases the evidence record
({{evidence}}) MUST be sufficient to reconstruct which path produced a
refusal.

| Condition | Required behavior |
|---|---|
| Token validation fails, including sender-constraint verification | Refuse before runtime Mission evaluation |
| Mission governance is required but the token lacks a `mission` claim | Refuse before runtime Mission evaluation, unless the Mission binding is externally established ({{mission-binding}}) |
| PEP-PDP channel authentication or integrity protection fails | Fail closed |
| Mission state cannot be established within the staleness bound | Fail closed for consequential actions |
| A policy-required history predicate cannot be established, or the evidence store cannot be consulted ({{input-history}}) | Fail closed |
| PDP unreachable | Fail closed for consequential actions; do not proceed on cached permits past the window. An unexpired, unconsumed permit MAY execute during a PDP outage: executing-PEP reverification needs no PDP |
| Mission not `active` | Refuse; work already initiated reconciles under {{evidence}}, never re-executes |
| The Mission's `expires_at` passed, when known from the Mission state source | Refuse |
| Unsupported `authorization_details` type for the action | Refuse |
| Unknown or unmetered constraint on the applicable entry | Refuse |
| Consumption bound would be exceeded | Refuse |
| `parameter_digest` mismatch at the executing PEP | Refuse |
| Re-presentation of a consumed single-use decision identifier | Refuse (fail closed) |
| Required `act` chain missing or malformed | Refuse |
| Invoked capability identity outside the approved `actions` | Refuse |
| Resource policy refuses the action | Refuse |
| Request would broaden the Mission's authority | Refuse (expansion is out of scope) |

# Runtime Enforcement Evidence {#evidence}

Every PDP decision on a consequential action MUST produce a runtime
enforcement evidence record. A PEP refusal for a consequential action,
whether before a PDP decision (for example, token validation failure
or PDP unreachability) or after a PDP permit (for example, a
`parameter_digest` mismatch), MUST likewise produce a runtime
enforcement evidence record with the available fields and the failure
condition. This document fixes the minimum record content and local
integrity requirements; the concrete record schemas, canonical byte
representation, and integrity envelope are defined by Mission Runtime
Evidence ({{I-D.draft-mcguinness-mission-runtime-evidence}}). The
Mission Receipt's portable schema ({{mission-receipt}}) remains out
of scope ({{deferred}}).

A record captures decision inputs, the applicable policy and
authority references, the result, and the failure condition. No
requirement in this section asks for the model's internal reasoning,
and a deployment SHOULD NOT record model chain-of-thought in
enforcement evidence: it is high-sensitivity content with no
verification value the decision inputs do not already carry.

## Required Decision Evidence

A record MUST contain:

- the decision or refusal result and, on refusal, the failure condition
  from {{failure-modes}};
- the request time (RFC 3339 {{RFC3339}}); and
- the `parameter_digest` for parameter-bound classes, or a
  privacy-preserving digest of the evaluation request otherwise.

A record MUST also contain the following fields when they are available
and trusted for the refusal or decision path:

- the Mission reference (`mission.id`, `mission.issuer`) and the
  `authority_hash` (and `intent_hash` when known: it is carried in
  neither the `mission` claim nor introspection, so it is available only
  to a PDP with direct Mission-record access, and most deployments
  record `authority_hash` alone) it operated under;
- the token issuer and audience or protected-resource identifier when
  available;
- the authenticated `sub`, `client_id`, a client-instance identifier
  (a deployment-defined correlator) when present, the sender-constraint
  confirmation key when present, and the `act` chain projection when
  delegation applies;
- the action and resource identifiers (and the asserted capability
  identity when applicable);
- the `authorization_details` type and authorizing entry, or a digest
  of that entry when recording the full entry would disclose excess
  authority or sensitive policy;
- the decision identifier, when the PDP produced one;
- the PDP's policy-view version;
- the identity and role of the emitting enforcement component; and
- OPTIONAL, a `compensates_evaluation_id` member linking a
  compensating action's decision to the original evaluation
  identifier it reverses, so a compensation can be reconciled against
  the action it undoes.

For a token-validation failure, the record MUST NOT describe
unverified token claims as authenticated facts. It MAY include a digest
of the presented token or rejected claim set for correlation and
forensics, subject to the privacy requirements below.

The `authority_hash` and `intent_hash` in a record are the
originating AS's commitments, cited as anchors; the PDP does not
recompute them and is not required to hold the full Authority Set to
record them, consistent with {{I-D.draft-mcguinness-oauth-mission}}.

## Execution-Outcome Evidence

For an action in the high-consequence classes, the executing PEP MUST
also produce, after it acts, an
execution-outcome record keyed to the permit's evaluation identifier,
recording at least success or failure and the effective parameter
digest actually executed, alongside the authorized parameter digest
the permit bound
({{I-D.draft-mcguinness-mission-runtime-evidence}}). This lets a
decision and its execution be reconciled one to one, so a permit that
was obtained but executed more than once, or executed for different
parameters, is detectable after the fact.
The detailed object schema is the Execution Evidence Object, defined
by the runtime evidence companion
({{I-D.draft-mcguinness-mission-runtime-evidence}}).

Reconciliation is bounded in time by the reconciliation window,
orphan-detection component, and alerting obligation the Enforcement
Scope Statement declares ({{runtime-conformance}}): an
execution-outcome record is expected for each decision within the
window, and the named component detects orphaned evidence (a decision
with no matching execution-outcome record within it) and sequence
gaps in a Mission's records ({{record-integrity}}).

An unknown outcome has an owner and a deadline, not only a window:
the declared component MUST actively reconcile each unresolved
outcome before the window closes, querying the resource and matching
evidence, and record the outcome the evidence establishes
(`completed`, `failed`, or `suppressed`,
{{I-D.draft-mcguinness-mission-runtime-evidence}}). Evidence, never
the deadline, determines the result: an outcome the component cannot
establish stays undetermined-outcome, is escalated under the declared
alerting obligation, and is never synthesized into a terminal result.
Reconciliation survives the Mission: once the Mission is non-active,
it MAY record the outcome of work already initiated and MUST NOT
admit a new effect under that Mission (an action already executing
follows the run-to-completion rule of {{execution-reverification}},
unchanged). Consumed and reserved decision identifiers and
idempotency claims persist across Mission lifecycle transitions for
at least the reconciliation window and any declared tombstone horizon
({{idempotency}}): termination does not erase them, so a
post-termination retry resolves against the recorded claim rather
than executing again. An unresolved claim never becomes reusable
through time alone: when the window closes on an undetermined
outcome, the claim converts to a non-reusable indeterminate
tombstone, retained for at least the declared idempotency horizon and
released only by an evidence-recorded operational resolution, never
by expiry into a fresh claim.

## Mission Receipt {#mission-receipt}

A **Mission Receipt** is the portable, tamper-evident projection of a
runtime enforcement evidence record and, for a high-consequence
action, its execution-outcome record: portable evidence of a material
action taken under a Mission, as a Mandate
({{I-D.draft-mcguinness-mission-mandate}}) is portable evidence about
the Mission itself.

A Mission Receipt MUST identify the Mission the action was authorized
under: `mission.id` and `mission.issuer`, or a verifiable Mission
projection such as the cross-domain grant's `mission` claim
({{I-D.draft-mcguinness-oauth-mission-cross-domain}}). It SHOULD bind
the policy decision (the decision identifier and result), the policy
state it was decided under (the PDP's policy-view version and the
Mission's `policy_version`), the
executor (the authenticated actor and any `act` chain), the custody
boundary (whether a mediating PEP held the credential, {{custody}}),
the downstream target (the resource and audience), the outcome, the
timestamps, and, where receipt chaining substitutes for a
transparency feed ({{I-D.draft-mcguinness-mission-audit}}), the
digest of the previous Mission Receipt. The portable schema and
canonical byte representation are deferred ({{deferred}}); the
members above are the minimum a deployment-defined Mission Receipt
binds.

## Record Integrity and Retention {#record-integrity}

The following requirements apply to every record:

- The Resource Server runtime profile MUST define the record's
  concrete serialization and canonicalization before storage and
  integrity protection. JSON records SHOULD use JCS {{RFC8785}} under
  the issuance profile's canonicalization rules.
- It MUST be append-only and integrity-protected; the enforcement
  scope MUST name the mechanism (a hash-linked log, signed segments, a
  transparency anchor, or equivalent). Where a JSON record is
  individually signed, the `evidence_envelope` JWS convention of the
  runtime evidence companion
  ({{I-D.draft-mcguinness-mission-runtime-evidence}}) is the
  suite's one signing convention for evidence objects and SHOULD be
  used, with a `typ` that names the record's own media type, rather
  than a record-specific signing scheme.
- Raw parameters MUST NOT appear in the record; when retained for
  forensics they MUST be in separately access-controlled storage
  referenced by an opaque identifier, with only the
  `parameter_digest` in the record. A deployment SHOULD retain the
  normalized parameters of denied high-consequence attempts in that
  forensic store, so an auditor can reconstruct what was refused, not
  only that a refusal happened.
- Records for one Mission MUST carry a deployment-defined sequence
  indicator, scoped per emitter, so gaps are detectable and one
  emitter's records order without relying on wall-clock time alone.
  This does not by itself reconstruct Mission-wide decision order
  across emitters; that ordering is best-effort, from the
  correlation members and each record's timestamps together
  ({{I-D.draft-mcguinness-mission-runtime-evidence}}).
- The retention window declared in the Enforcement Scope Statement
  MUST be no shorter than the Mission's audit horizon, as defined in
  the Mission Record section of {{I-D.draft-mcguinness-oauth-mission}}.

Digest encoding is uniform across this document family: every digest a
family document defines uses the `sha-256:` prefixed base64url,
no-padding encoding of the issuance profile's integrity-anchor rules
({{I-D.draft-mcguinness-oauth-mission}}). The exceptions are externally
fixed encodings: the COSE hashed payload of the audit companion's
Signed Statements ({{I-D.draft-mcguinness-mission-audit}}) carries the
raw digest bytes the COSE hash-envelope mechanism requires, and the
attenuation substrate's parent-hash form
({{I-D.draft-niyikiza-oauth-attenuating-agent-tokens}}) is unprefixed
base64url. Each exception is identified by its carrying context; the
`sha-256:` prefix appears in neither.

# Named Enforcement Claims {#named-claims}

The strongest properties this profile enables are deployment
properties, not protocol properties: complete PEP placement, a
trusted freshness source, and credential custody are things a
deployment does, not things a token proves. This section defines
them as named claims, each a conjunction of conditions specified
elsewhere in this profile, each individually verifiable, and none
implied by base conformance. A deployment publishes the claims it
makes, and the classes each covers, in its Enforcement Scope
Statement ({{runtime-conformance}}), and demonstrates them with the
negative tests of {{negative-conformance}}. The two claims together
are the High-Assurance Agent bar of the Mission Assurance Levels
({{I-D.draft-mcguinness-mission-architecture}}).

## Agent-Compromise-Resistant Enforcement {#compromise-resistant}

"Protects against agent compromise" is a verifiable claim, not a label.
A deployment claims **agent-compromise-resistant enforcement** only
when, for the high-consequence classes, the four conditions below hold
and the deployment's path scope is declared and audited as this
section then states. Each condition below is MUST under this claim
regardless of its base-profile level; the table at the end of this
section records each condition's base-profile level.

- the sender-constraint private key is held by the mediating PEP, not
  by the agent component, gateway custody being the realizable shape
  ({{custody}}), and is generated in the mediating PEP or its HSM and
  never transferred from the agent;
- each such action requires an action-bound approval
  ({{action-approval}});
- the disclosure rendered to the Approver for an action-bound approval
  is derived from the bound normalized parameters by a component
  isolated from the agent (the approval service or the mediating PEP),
  never composed by the agent, and the rendering SHOULD be committed
  as Consent Evidence, raising the base profile's MAY
  ({{action-approval}}); and
- the Mission state source for those classes is an active freshness
  mechanism, not token-lifetime expiry ({{state-freshness}}).

The fifth term of the claim is the path scope, and it is not a
protocol-verifiable conformance condition; this claim does not present
it as one. That governed work runs with no unmediated path to the
mediated classes, and with no token-endpoint, refresh, or exchange
path by which the agent obtains a fresh usable credential for them
bound to a key it controls, is the deployment audit obligation the
harness profile already names
({{I-D.draft-mcguinness-mission-harness}}). It is declared in the
Enforcement Scope Statement, in the mediated-paths declaration and the
unmediated-path exclusions ({{runtime-conformance}}), with the
declared scope covering fresh-credential paths as well as action
paths, and it is audited organizationally, with the negative tests of
{{negative-conformance}} as its observable check. The claim therefore
reads: the four conditions above, each verifiable, plus the
declared-and-audited path scope. The weakest term of that conjunction
is a self-declared scope statement, and a deployment making this claim
states that plainly rather than implying a stronger term.

A deployment MAY satisfy the action-bound approval condition for a
batch through one approval that binds an enumerated list of parameter
digests, each consumed single-use, so the human pause stays meaningful
at volume rather than degrading into per-action rubber-stamping
({{action-approval}}).

A deployment that leaves any of the four conditions unmet, or whose
Enforcement Scope Statement does not declare the path scope, MUST NOT
claim agent-compromise-resistant enforcement; it may still claim base
runtime conformance. The claim names exactly the set of classes it
covers. This claim additionally requires execution-environment
attestation of the scope statement, the condition
{{trifecta-containment}} states for both High-Assurance Agent
claims.

The guarantee is the conjunction of these conditions, not any one of
them. Mediated custody alone prevents only off-path presentation of
the credential: the agent still initiates every action and supplies
every parameter, and the mediating PEP executes any in-scope action
the agent requests. What bounds a compromised agent is custody
**and** complete PEP placement **and** correct classification acting
together, so the claim is no stronger than the weakest of the three,
and "mediated custody" on its own is not the property.

Each unmet condition loses a specific property; the base-profile
column records the level each condition has outside this claim:

| Condition unmet | Base-profile level | Property lost |
|---|---|---|
| Custody in the mediating PEP | SHOULD ({{custody}}) | Key exfiltration |
| Path scope declared and audited (no unmediated path to the actions or to fresh credentials for them) | Declared in the Enforcement Scope Statement ({{runtime-conformance}}); the audit is this claim's term | Off-path execution or fresh-credential acquisition |
| Action-bound approval | SHOULD ({{action-approval}}) | Unattended high-consequence action |
| Agent-independent approval rendering | Stated only by this claim | Approval decided on agent-composed disclosure |
| Active-state freshness | MUST ({{state-freshness}}) | Revocation lag bounded only by token lifetime |

## Trifecta Containment {#trifecta-containment}

The name is unrelated to Mission Containment
({{I-D.draft-mcguinness-oauth-mission-containment}}), the
issuer-held overlay that removes capability from a Mission's
Authority Set. Trifecta containment names resistance to the
exfiltration trifecta below; Mission Containment names a governance
operation over the Authority Set. Context distinguishes the two, and
a deployment that runs both keeps the terms separate in its
Enforcement Scope Statement.

An agent that holds private-data authority, is exposed to untrusted
content, and can communicate externally combines the three
ingredients of injection-driven exfiltration
({{prompt-injection-exfiltration}}). The profiles gate each
ingredient separately; this claim names the composite. A deployment
claims **trifecta containment** for a Mission's governed work only
when all of the following hold, each MUST under this claim regardless
of its base-profile level:

- **Private-data exposure.** Least exposure ({{least-exposure}}) is
  applied: the context surfaced to the agent is scoped to the active
  Mission, and credential material stays out of the agent for every
  mediated class ({{custody}}).
- **Untrusted content.** A taint policy for untrusted content, as the
  harness profile defines one
  ({{I-D.draft-mcguinness-mission-harness}}), is in force and its
  egress rule is enforced, not advisory: a consequential
  external-communication or external-commitment action whose bound
  parameters derive from tainted content (or, under session-level
  taint, any such action in a tainted session) obtains a fresh
  action-bound approval ({{action-approval}}) or is refused. The
  harness profile's pre-consented egress carve-out applies: a send to
  a destination the Approver concretely named at approval is not
  human-gated on taint grounds alone, and for content-derived
  destinations, those outside the approved set, the full polarity,
  every tainted egress human-gated, remains a condition of this
  claim. Where the decision-API binding carries taint context
  ({{I-D.draft-mcguinness-mission-authzen}}), the PDP enforces the
  rule; otherwise the harness does, and the scope statement says
  which.
- **External communication.** The external-communication and
  external-commitment classes are mediated: no unmediated path, the
  scope statement's egress-channel enumeration covers them
  ({{I-D.draft-mcguinness-mission-harness}}), and the
  sender-constraint keys are held by the mediating PEP ({{custody}}).

The claim is published with the enforcement-scope conformance
statement ({{runtime-conformance}}). It is containment, not immunity:
the limits of {{prompt-injection-exfiltration}} stand, in particular
within-scope laundering, bounded quantitatively where an
egress-volume bound is metered
({{I-D.draft-mcguinness-mission-metering}}), and PEP-placement
completeness.

Both this claim and agent-compromise-resistant enforcement
({{compromise-resistant}}) rest on the execution-environment scope
statement, a self-declared artifact: the wire alone does not let a
relying party distinguish a deployment that built the declared
isolation from one that only published the statement. A deployment
claiming either MUST bind the statement to execution-environment
attestation, presenting Entity Attestation Token evidence under the
AI-agent-instance profile
({{I-D.draft-mcguinness-oauth-ai-agent-instance}}) covering the
isolation properties the statement declares, and MUST NOT represent
the claim as met without it. The requirement is scoped to these two
High-Assurance Agent claims; base runtime conformance does not
require attestation, and a deployment claiming only the base profile
MAY publish its scope statement unattested.

# Negative Conformance Tests {#negative-conformance}

The agent-compromise-resistant claim ({{compromise-resistant}}) rests
on PEP-placement completeness, which is a deployment property no
protocol element proves. A deployment SHOULD demonstrate it with
negative tests: each of the following bypass attempts MUST be refused
or contained by a conforming deployment that makes the relevant
claim, and a deployment SHOULD retain evidence that it ran them.

| Bypass attempt | Required outcome |
|---|---|
| Agent calls a mediated tool directly, around the PEP | Blocked (no unmediated path) |
| Agent presents a cached token after Mission revocation | Blocked within the freshness bound |
| Agent resumes background work after Mission state went stale | Paused or refused on resume re-check |
| Agent delegates to a sub-agent with no explicit delegation | Blocked (no inheritance by session ancestry) |
| Agent alters action parameters after the permit is issued | Blocked by parameter-digest reverification |
| Agent egresses over a secondary channel (DNS, logs, shared store) | Blocked if the channel is in the mediated set; otherwise declared outside the claim |

These are the observable form of the requirements stated normatively
above; a deployment's Enforcement Scope Statement
({{runtime-conformance}}) names which it enforces and which paths it
excludes.

# Deployment Considerations {#runtime-deployment}

Three properties govern how this profile scales.

**Token lifetime trades against the enforcement layer.** The
issuance profile recommends short-lived tokens because, in an
issuance-only deployment, token expiry is the revocation cutoff.
Where this profile's enforcement covers the high-consequence classes
with an active-freshness state source, the PDP is the cutoff for the
actions that matter, and a deployment MAY extend token lifetimes for
issuance-load reasons without silently losing the kill switch; where
issuance gating is the only control, short lifetimes remain the
control and the issuance profile's recommendation stands. The choice
belongs in the Enforcement Scope Statement: what stops a revoked
Mission, at what latency, is a fact that statement already declares
({{runtime-conformance}}).

**The consistency unit is the Mission.** Every strongly consistent
requirement this profile and its companions impose, the atomic
`active` check, single-use decision identifiers, and the consumption
counters and exclusivity latches of the metering companion
({{I-D.draft-mcguinness-mission-metering}}), is scoped to one
Mission. A multi-node PDP therefore shards its state by the Mission
Identifier with no cross-shard coordination; only a
deployment-configured aggregate bound crosses that partition and is
provisioned as its own consistency domain. Fail-closed applies per
action class ({{failure-modes}}): a PDP outage stops consequential
work and nothing else.

**Decision latency is budgeted by class.** The synchronous cost of
this profile is confined to the actions whose consequences warrant
it. Classification ({{classification}}) is the first lever: only
consequential actions need a permit, and only the high-consequence
classes must hold a synchronous gate. For the rest of the governed
surface the common-case decision is local: a PDP embedded in or
colocated with its PEP evaluates against a materialized policy view
({{policy-view}}) whose network cost is paid once per freshness
window, not per action; a permit's validity window covers the
follow-through of one normalized action ({{parameter-binding}}); the
decision API's batch evaluation amortizes fan-out ({{authzen}}); and
metering leases amortize the metered classes
({{I-D.draft-mcguinness-mission-metering}}). Offline attenuation
({{I-D.draft-mcguinness-oauth-mission-attenuation}}) removes the
issuer from sub-agent fan-out entirely; its Experimental status
tracks the maturity of its substrate, not a judgment that localized
offline validation is optional at machine speed. A deployment for
which a synchronous gate on a low-consequence class is too expensive
reclassifies deliberately and records the choice in its Enforcement
Scope Statement, rather than weakening the gate on the classes that
matter.

**Locality ends where the Mission's shared state begins.** The
single-use identifier store and idempotency match
({{parameter-binding}}), the metering counters and exclusivity latch
({{I-D.draft-mcguinness-mission-metering}}), and the per-Mission
evidence sequence ({{I-D.draft-mcguinness-mission-runtime-evidence}}) are
strongly consistent state scoped to one Mission. An embedded PDP
evaluating an action that consults any of them pays the round trip
to the Mission's consistency domain wherever the decision runs, so
the materialized view localizes only the actions that touch none of
them; for the high-consequence classes, whose permits are single-use,
the Mission's domain, not PDP placement, sets the latency floor. A
deployment prices this deliberately: colocate a Mission's domain
with the PEPs that act under it, or accept the hop for the classes
that require it.

# Decision API Binding {#authzen}

The decision contract of {{decision}} is abstract: it fixes the inputs,
the permit, and the invariants, not a wire format. A **decision API
binding** maps that contract onto a concrete PEP-PDP wire protocol. For
deployments using the OpenID AuthZEN Authorization API {{AUTHZEN}}, the
normative binding is the Mission-Bound Runtime Enforcement: AuthZEN
Profile {{I-D.draft-mcguinness-mission-authzen}}, which specifies
how the Mission and actor inputs, the decision and evidence objects, and
the denial classification map onto the AuthZEN request and response.
Other decision APIs may be bound by other specifications. A
deployment that uses a different decision API MUST specify that
binding in the same way.

This document defines no binding of its own. Keeping the binding in a
separate specification preserves substrate-independence: the enforcement
contract, action classification ({{classification}}), PEP placement
({{pep-placement}}), parameter binding ({{parameter-binding}}),
the consumption-bound failure posture ({{metering}}), and runtime
enforcement evidence
({{evidence}}) are the substance, and they do not depend on the decision
wire.

# Out of Scope {#deferred}

The following compose with this profile but are deferred to future
work and are not required to enforce it:

- a standardized enforcement-scope manifest format and discovery
  mechanism;
- cross-format capability-source binding beyond per-capability
  definition-digest drift (signed capability manifests, cross-catalog
  identity);
- the Mission Receipt's portable schema and canonical byte
  representation ({{mission-receipt}}: this profile fixes the term,
  its minimum binding, and the local runtime enforcement evidence
  record). The concrete Decision Evidence, Execution Evidence, and
  Refusal Record object schemas, canonicalization, integrity
  envelope, and media types are, by contrast, no longer deferred:
  they are defined by the runtime evidence companion
  ({{I-D.draft-mcguinness-mission-runtime-evidence}});
- actor provenance beyond the `act` chain and attestation of the
  execution environment: actor-signed hop proofs
  ({{I-D.draft-mcguinness-oauth-actor-proofs}}), issuer-signed hop
  receipts ({{I-D.draft-mcguinness-oauth-actor-receipts}}), and
  attested agent-instance identity
  ({{I-D.draft-mcguinness-oauth-ai-agent-instance}}) specify these,
  and this profile consumes their results as token-derived facts
  where present;
- a purpose registry;
- compilation of the Mission into an engine-native policy artifact
  (Cedar, OpenFGA, or equivalent) and standardization of PDP
  deployment modes;
- offline or partitioned PDP operation (a PDP that decides while
  disconnected from its Mission state source); fail-closed
  ({{failure-modes}}) remains the base rule when state cannot be
  established;
- action-hierarchy and resource-containment subset extensions (this
  profile uses the flat subset rule of
  {{I-D.draft-mcguinness-oauth-mission}});
- evaluation-context binding: an extension letting a high-assurance
  permit commit the resource version, policy-view version, and
  decision time it was evaluated against, hardening the
  target-drift residual of the TOCTOU considerations;
- risk-signal and semantic intent-alignment inputs to the decision,
  which are advisory and deployment-defined ({{inspection-controls}});
  and
- integrity of the result a tool returns as the application relays it to
  the agent's model, and binding an executed action to the model's own
  decision ({{inspection-controls}}).

Structured per-argument attenuation of tool grants
({{I-D.draft-niyikiza-oauth-attenuating-agent-tokens}}) is a related
issuance/delegation-layer primitive, not part of this runtime profile.

# Security Considerations {#security-considerations}

## What This Layer Adds, and Its Limits

Gating every consequential action against the current Mission
prevents an active Mission from acting as ambient authority
({{decision}}, {{parameter-binding}}, {{evidence}}), closing the
approval-to-execution gap the issuance profile leaves open.

It governs actions, not meaning. A request can satisfy every
structural check while its content does harm no schema names: the
approved `send_email` whose body carries what an injection extracted.
The profile's answer is to convert semantic risk into structural
signals rather than ask the PDP to judge content: provenance (the
harness taint context and its default-taint polarity,
{{I-D.draft-mcguinness-mission-harness}}), composition (the
quarantine pattern, {{I-D.draft-mcguinness-mission-architecture}}),
egress-channel enumeration ({{trifecta-containment}}), volume bounds
and exclusivity ({{I-D.draft-mcguinness-mission-metering}}), and
action-bound re-consent for the highest classes
({{action-approval}}). A deployment that additionally runs a content
evaluator (data-loss prevention, an LLM-based content policy)
composes it as Resource policy at the PDP: the verdict enters the
decision as deployment-defined context, only ever narrows, and its
latency belongs to the action class that invokes it
({{semantic-evaluators}}).

It does not make a compromised enforcement component safe. A
compromised PEP can decline to consult the PDP or ignore its decision;
a compromised PDP can return whatever decisions it chooses. Decision
and enforcement evidence make such behavior auditable after the fact;
they do not prevent it in the moment. Signed, externally verifiable
decisions are future work ({{deferred}}).

## Placement and Bypass

The strongest decision logic is void if the PEP is not at the last
controllable boundary, or if an unmediated path can reach the action
({{pep-placement}}). A deployment's claim is only as strong as the set
of execution paths it actually mediates, and that set is the
Enforcement Scope Statement's mediated-paths declaration
({{runtime-conformance}}).

## Prompt Injection and Exfiltration {#prompt-injection-exfiltration}

This profile assumes the agent can be prompt-injected and does not try
to prevent that. It constrains what an injected agent can do by gating
the external-communication leg: external communication is a consequential
action, so every attempt is checked against the Authority Set, bound to
parameters, metered, and (with mediated execution, {{custody}}) made
unreachable to an agent that does not hold the egress credential. This
is the architectural defense, gate the exfiltration against an authority
the injection cannot widen, rather than make the agent injection-proof.
Least exposure ({{least-exposure}}) is the input-side complement: it
shrinks what an injected agent can read and what within-scope
laundering can draw from, without changing the limits below.

Two limits are inherent and a deployment MUST NOT overstate the
guarantee. First, it is exactly as strong as PEP-placement completeness:
every exfiltration channel an agent runtime offers (DNS, logs, error
strings, a write to a store another process reads) is a channel that
must be mediated, and this profile gates the channels routed through a
PEP but cannot prove a deployment enumerated them all (the Achilles'
heel of {{pep-placement}}). Second, this profile provides no
information-flow control: it evaluates each action in isolation against
authority over resources and actions, so a sequence of
individually-authorized steps can compose into an exfiltration no single
check catches (within-scope data laundering), and cumulative
consumption bounds, where metered
({{I-D.draft-mcguinness-mission-metering}}), bound volume, not flow.
Closing that needs a separate taint
or information-flow layer. A coarse session-level mitigation, downgrading
egress authority once untrusted content has entered a session, is
available at the harness layer
({{I-D.draft-mcguinness-mission-harness}}); it raises the bar but
is not information-flow control.

## Relationship to Inspection-Based Controls {#inspection-controls}

Inspection-based runtime defenses for agentic systems share this
profile's premise that the agent application is part of the attack
surface ({{custody}}), and combine deterministic checks over the message
flow with semantic checks over the agent's intent. This profile is the
authority half of that picture; it composes with, but does not replace,
an inspection layer.

Two of this profile's mechanisms are deterministic checks of that kind.
Parameter binding ({{parameter-binding}}) ties a permit to the concrete
parameters the action executes with, so an application cannot alter a
tool call's arguments after the decision. Capability-source binding, in
the capability-binding companion
({{I-D.draft-mcguinness-mission-capability-binding}}), ties an
approved action to the digest of the capability definition it was
derived from, so a swapped or poisoned tool definition fails the
decision. Both refuse the action; neither inspects the agent's
reasoning.

Two adjacent checks are out of scope ({{deferred}}). This profile
evaluates the request path: it does not verify the integrity of the
result a tool returns as the application relays it back to the agent's
model, so an application can still falsify what the model sees; and it
does not by itself establish that an executed action reflects the
model's own decision rather than an application substitution. Mediated
execution ({{custody}}) bounds the second case, since an action outside
the Authority Set is refused however it arose, but it does not bind the
executed action to the model's decision; a deployment that can establish
that correspondence SHOULD. Both sit at the semantic and grounding
boundary the issuance profile names a non-goal
({{I-D.draft-mcguinness-oauth-mission}}).

A semantic intent-alignment signal, for example a judgment that a
requested tool fits the task extracted from the conversation, MAY be
supplied to the PDP as advisory decision input. Such a signal MAY
contribute to a denial; it MUST NOT widen, grant, or refresh authority,
consistent with the inert treatment of `goal` and `purpose` in the
issuance profile ({{I-D.draft-mcguinness-oauth-mission}}). Gating
authority on intent inference is out of scope: verifying an agent's
declared reasoning against the task is an attestation problem outside
both layers, and intent inference is not reliable enough to be
load-bearing for high-consequence authority.

## Classification Integrity

Because "consequential" is partly deployment-defined, the
classification floor of {{classification}} is load-bearing: a
deployment cannot evade enforcement by classifying a high-consequence
action as non-consequential. A `purpose` may raise a class but never lower it
below the resource owner's floor.

## Freshness and Consumption Honesty

A permit is a lease, not a standing grant: stale Mission state MUST
fail closed for consequential actions within the published bound
({{state-freshness}}). A deployment MUST NOT advertise consumption
enforcement it does not perform ({{metering}}); where cumulative
bounds are metered, the exactness and consistency claims of the
metering companion apply ({{I-D.draft-mcguinness-mission-metering}}).

## The History Input

The history input ({{input-history}}) makes prior evidence
load-bearing for later decisions, so it is attacker-adjacent
wherever evidence producers are compromised: a forged record is a
forged precondition, and a suppressed record denies the step that
depends on it. This is the existing evidence-integrity story, not a
new one; the record integrity requirements of {{record-integrity}}
and the transparency mechanisms of the audit companion
({{I-D.draft-mcguinness-mission-audit}}) are the countermeasures,
and a deployment that makes history load-bearing weighs them as
part of the decision path, not only as after-the-fact audit.
Shaping Evidence is never an input to this or any authorization
decision; the shaping profile's existing prohibition stands
unchanged ({{I-D.draft-mcguinness-mission-shaping}}).

## Resource Policy Remains Authoritative

Mission authority is a maximum authority envelope. It does not force a
Resource Server to perform an action, bypass local authorization, or
override object ACLs, tenant configuration, legal holds, service
invariants, or risk policy. A runtime deployment that treats a
Mission-bound permit as sufficient without Resource policy evaluation
can perform actions that the resource owner or service would otherwise
forbid.

## TOCTOU and Replay

Parameter binding ({{parameter-binding}}) ties a permit to specific
normalized parameters and a short window or single use, so a permit
cannot be replayed for a different request or survive a parameter
change between check and use. The executing PEP, not an upstream
component, MUST perform the reverification.

Parameter binding freezes the request, not the target. Between
decision and execution the resource itself can change meaning: a
revised document, a reclassified record, a query that returns a
different set. That residual is outside `parameter_digest`'s reach,
and the mitigations are operational: keep permit validity windows
tight ({{parameter-binding}}), re-evaluate rather than re-present a
permit on retry, and, where the resource exposes a version or
revision identifier, bind it as a parameter so the permit commits
the target state it was decided against. An extension letting a
high-assurance permit commit its evaluation context (resource
version, policy-view version, decision time) is deferred to
implementation demand ({{deferred}}).

## Confused Deputy Across Resources

The permit binding of {{parameter-binding}} ties a decision to the
Mission, the token audience or protected resource, `sub`, `client_id`,
actor context, action, and resource it evaluated. It follows that a PDP
decision for one protected resource, audience, tenant, or operation is
not reusable at another: the executing PEP, which reverifies those
bindings before acting ({{parameter-binding}}), refuses a permit whose
bindings do not match the boundary at which it is presented. A
deployment MUST NOT relax those bindings in a way that would let a
permit cross a resource, audience, tenant, or operation boundary it
was not issued for.

## Decision Channel and Token Disclosure

A separate PDP becomes part of the Resource Server's trusted
authorization path for the operations in its enforcement scope. The
PEP/PDP channel therefore needs mutual authentication, integrity
protection, and authorization for the declared scope
({{token-validation}}). Passing full access tokens to a PDP also
extends credential exposure beyond the Resource Server boundary; a
deployment that does so needs the same credential handling, retention,
and disclosure controls it applies at the Resource Server.

General OAuth security guidance {{RFC9700}} applies to the underlying
credentials.

# Privacy Considerations

Runtime enforcement evidence is intentionally durable and therefore
sensitive. It can reveal a subject's resources, action timing,
delegated actors, and Mission correlation identifier even when raw
action parameters are not stored. Deployments SHOULD minimize recorded
authority entries, store entry and parameter digests where full values
are not needed for audit, restrict access to evidence by role, and
document the retention window declared under {{evidence}}. Access to
Mission evidence is itself a privileged operation a deployment SHOULD
audit, and classifying evidence fields by sensitivity lets access,
export, and retention key on the class; the audit companion's
minimization duties apply across the evidence this layer produces
({{I-D.draft-mcguinness-mission-audit}}). Evidence
shared across resource boundaries can also correlate activity by
`mission.id` and `authority_hash`; deployments that require
unlinkability need an additional privacy design outside this profile.

# IANA Considerations

## OAuth Protected Resource Metadata Registration

This document registers the following in the "OAuth Protected Resource
Metadata" registry ({{RFC9728}}):

- Metadata Name: `mission_action_class_floors`
- Metadata Description: JSON object mapping a protected resource's
  action identifiers to minimum runtime action classes.
- Change Controller: IETF
- Reference: this document, {{class-floors}}

The Mission-bound token claims this
profile consumes are registered by {{I-D.draft-mcguinness-oauth-mission}};
any decision-API wire members are defined by the binding
({{authzen}}, {{I-D.draft-mcguinness-mission-authzen}}).

--- back

# Parameter Digest Worked Example {#parameter-digest-example}

This non-normative example shows an Operation Profile and the
`parameter_digest` it produces ({{parameter-binding}}), so two
implementations can confirm they normalize and digest the same way.

Consider a `journal-entries.write` operation under an ERP
reconciliation Mission (`msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-`) whose
applicable entry carries a `max_amount` ceiling of 500.00 USD. The
Operation Profile fixes the parameter set and normalization: the
members are `amount_usd` and `source_invoice_id`; `amount_usd` is a
decimal string with exactly two fractional digits; no defaults are
inserted and no optional members are omitted; there are no set-like
arrays to order. For a 423.50 USD journal entry, within the ceiling,
the normalized parameter object is:

~~~ json
{
  "amount_usd": "423.50",
  "source_invoice_id": "inv_2026Q3_842"
}
~~~

The `parameter_digest` is `sha-256:` followed by the base64url,
no-padding SHA-256 of the JCS {{RFC8785}} serialization of that object,
under the issuance profile's canonicalization rules (no envelope; the
normalized parameter object is digested directly). The JCS canonical
bytes are a single line with sorted member names and no whitespace:

~~~ text
{"amount_usd":"423.50","source_invoice_id":"inv_2026Q3_842"}
~~~

~~~ text
parameter_digest =
  sha-256:WPVi6EnQ7H9Fh-qk9ADxmTg8zruOdVUX1esl-v3TfCI
~~~

The PDP binds its permit to this value, and the executing PEP recomputes
it over the parameters it is about to use immediately before acting
({{parameter-binding}}); any change to a normalized parameter yields a
different digest and the permit is refused.

# Policy View Worked Example {#policy-view-example}

This non-normative example shows the `policy_view_id` computation of
{{policy-view}} over a materialized-view manifest for the same
Mission. This deployment compiles to an engine-native artifact, so
the manifest carries `artifact` rather than `policy_ir`; a deployment
that serves a state version records it in Decision Evidence and
consumes it through freshness processing instead, never embedding it
in this manifest ({{policy-view}}).

~~~ json
{
  "typ": "mission-policy-view",
  "iss": "https://as.example.com",
  "value": {
    "mission_id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
    "authority_hash":
      "sha-256:l3KvZ4mP5x0wQrR6tY2nD9bM7sX1cF8gH2vJ4kE5pNQ",
    "policy_version": "deploy-policy:v17",
    "compiler": {
      "profile": "https://as.example.com/policy-compiler",
      "version": "1.4.0"
    },
    "artifact": {
      "digest":
        "sha-256:9ZqK3mP7xR2vN4tY6bD1eF8jC5wH0pV2nR3kQ4mZ7tX",
      "encoding": "application/vnd.example.policy-engine+bin"
    }
  }
}
~~~

The JCS canonical bytes are a single line with sorted member names and
no whitespace, shown here wrapped for layout only; remove the layout
line breaks, adding no characters, to recover the canonical form:

~~~ text
{"iss":"https://as.example.com","typ":"mission-policy-view","value":
{"artifact":{"digest":"sha-256:9ZqK3mP7xR2vN4tY6bD1eF8jC5wH0pV2nR3kQ
4mZ7tX","encoding":"application/vnd.example.policy-engine+bin"},"aut
hority_hash":"sha-256:l3KvZ4mP5x0wQrR6tY2nD9bM7sX1cF8gH2vJ4kE5pNQ","
compiler":{"profile":"https://as.example.com/policy-compiler","versi
on":"1.4.0"},"mission_id":"msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-","po
licy_version":"deploy-policy:v17"}}
~~~

~~~ text
policy_view_id = sha-256:kFxuopgt9C4G7S4BhP7ayGhP49wG55HBnq0BzH09UZ8
~~~

Because the identifier is a content hash, any change to the manifest
yields a different `policy_view_id` ({{policy-view}}).

# Runtime Evidence Worked Examples {#evidence-examples}

These non-normative scenarios illustrate the minimum record content of
{{evidence}} for the operation of {{parameter-digest-example}}, in the
concrete record schemas and worked examples the runtime evidence
companion defines
({{I-D.draft-mcguinness-mission-runtime-evidence}}); this document
carries no evidence JSON of its own. In this deployment, the Resource
Server runtime profile classifies `journal-entries.write` as an
irreversible action (a posted entry is corrected only by a
compensating entry), so the permit is single-use and
execution-outcome evidence is required. The policy-view version cites
the view of {{policy-view-example}}.

A permit decision on the 423.50 USD journal entry of
{{parameter-digest-example}}, within the ceiling, for subject
`user_3p2q8mN1a0kV7tR` and client `s6BhdRkqt3` against audience
`https://erp.example.com`: the Decision Evidence record cites the
Mission, the authorizing `mission_resource_access` entry and its
`max_amount` constraint, and the `parameter_digest` of
{{parameter-digest-example}}, correlated by `evaluation_id`
`dec_4NqX7rT2vB9mK5sL8pJ0eW3yZ6cQ`. The companion's own worked example
shows the concrete record
({{I-D.draft-mcguinness-mission-runtime-evidence}}).

The executing PEP then acts and produces the execution-outcome record
keyed to that same `evaluation_id`: outcome `completed`, the
authorized and effective parameter digests equal, the binding-held
case, reconciling the decision and its execution one to one. The
companion's own worked example shows the concrete record
({{I-D.draft-mcguinness-mission-runtime-evidence}}).

A later attempt on the same operation shows a parameter deviation
instead. A distinct permit (`evaluation_id`
`dec_9HtV3wN6xQ1rB8mP5kS2eL7jY4zA`) bound the digest of the same
423.50 entry; between check and use the parameters became 780.00
(normalized object
`{"amount_usd":"780.00","source_invoice_id":"inv_2026Q3_842"}`). The
executing PEP recomputed the digest over the parameters it was about
to use, found it differed from the authorized digest, and suppressed
the release ({{parameter-binding}}): a post-decision suppression is a
final disposition and is recorded as Execution Evidence, never as a
Refusal Record, carrying both the authorized digest and the differing
effective digest it recomputed. The companion's parameter-deviation
worked example shows the concrete record
({{I-D.draft-mcguinness-mission-runtime-evidence}}).

# Acknowledgments
{:numbered="false"}

This document is the runtime companion to Mission-Bound Authorization
for OAuth 2.0 and builds on the OpenID AuthZEN Authorization API and
the OAuth 2.0 Rich Authorization Requests and JWT access token
specifications.
