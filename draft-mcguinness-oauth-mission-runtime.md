---
title: "Mission-Bound Runtime Enforcement for OAuth 2.0"
abbrev: "OAuth Mission Runtime"
category: std

docname: draft-mcguinness-oauth-mission-runtime-latest
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
  github: "mcguinness/draft-mcguinness-oauth-mission"
  latest: "https://mcguinness.github.io/draft-mcguinness-oauth-mission/draft-mcguinness-oauth-mission-runtime.html"

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
  RFC8785:
  RFC9068:
  RFC9700:
  I-D.draft-mcguinness-oauth-mission:
    title: "Mission-Bound Authorization for OAuth 2.0"
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-oauth-mission-latest

informative:
  RFC7662:
  I-D.draft-niyikiza-oauth-attenuating-agent-tokens:
  AUTHZEN:
    target: https://openid.net/specs/authorization-api-1_0-final.html
    title: "OpenID AuthZEN Authorization API 1.0"
    author:
      -
        org: OpenID Foundation
    date: 2025

--- abstract

The Mission-Bound Authorization for OAuth 2.0 profile binds issued
authority to a durable, approved Mission, but it governs issuance and
derivation only: it does not evaluate individual runtime actions, so
an active Mission can become ambient authority for the actions an
agent takes within a token's lifetime. This document specifies the
companion runtime layer for deployments that claim runtime Mission
enforcement. Within a declared enforcement scope, each consequential
action is evaluated, before it executes, against the Mission the
acting credential is bound to: the action and its parameters against
the Mission's approved authority and constraints, the actor context
from the delegation chain, and the Mission against its current state.
It defines where enforcement MUST sit, how a permit is bound to
concrete parameters to close the time-of-check to time-of-use gap, how
carried consumption bounds (budget, call counts, duration) are
metered, and the runtime evidence each consequential action MUST
produce.

--- middle

# Introduction

Mission-Bound Authorization for OAuth 2.0
{{I-D.draft-mcguinness-oauth-mission}} (the "issuance profile") makes a
Mission a first-class OAuth artifact: a structured, human-approved,
integrity-bound task whose authority bounds and outlives every token
an agent derives. But it is deliberately an issuance-and-derivation
layer. As its security considerations state, it does not evaluate
individual runtime actions, so an active Mission still bounds a set of
authority an agent may exercise freely within a token's lifetime, and
preventing that authority from becoming ambient for individual
consequential actions requires a separate runtime enforcement layer.

This document is that layer. It delivers exactly the four things the
issuance profile names as out of scope, plus enforcement of the
constraints that profile carries but does not evaluate:

1. evaluation of a request's parameters against the Mission at the
   point of use ({{decision}}, {{parameter-binding}});
2. per-action runtime enforcement evidence ({{evidence}});
3. binding of the invoked tool or function identity to the Mission's
   approved authority ({{decision}});
4. execution-time re-evaluation that closes the approval-to-execution
   (time-of-check to time-of-use) gap ({{parameter-binding}});

and, additionally, metering of the consumption bounds (budget, call
counts, duration) the issuance profile carries as constraints but
leaves to this layer to enforce ({{metering}}).

The model is a Policy Enforcement Point (PEP) at each consequential
execution boundary that, before the action runs, obtains a decision
from a Policy Decision Point (PDP) evaluating the action against the
Mission. Mission-bound tokens bound what authority may exist; this
profile defines where and how that authority is re-checked before
consequential effects occur.

## Relationship to the issuance profile {#relationship}

This document depends normatively on the issuance profile and is not
implementable alone: it consumes Mission-bound access tokens that
profile defines. It does not place any new requirement back on the
issuance profile; it reads only fields that profile already defines:

- the `mission` claim (`id`, `origin`, `authority_hash`);
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

## Conventions and Terminology {#conventions-and-terminology}

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

Decision:
: A PDP's permit-or-deny result for one action, bound to the inputs
  it evaluated ({{decision}}).

Policy-view version:
: A deployment-opaque identifier the PDP emits for the materialized
  policy and Mission view it evaluated against, so a permit and its
  evidence record tie to a reproducible decision basis. It is local to
  the runtime layer and is distinct from the issuance profile's
  `policy_version` Mission-record field
  ({{I-D.draft-mcguinness-oauth-mission}}); this document does not
  interpret it beyond correlation.

Runtime enforcement evidence:
: The record a consequential action produces for a PDP decision or a
  PEP refusal path ({{evidence}}).

Enforcement scope:
: The set of resources, action classes, execution paths, PEP
  placements, supported authorization details, state sources, and
  evidence mechanisms for which a deployment claims conformance to this
  profile.

Operation profile:
: Deployment documentation that defines operation-specific runtime
  semantics needed for interoperable enforcement within that
  deployment, including parameter normalization rules and duration
  measurement.

Resource Server runtime profile:
: A deployment's Resource Server-facing conformance statement for this
  profile. It defines which protected resources and operations the
  Resource Server enforces, where the PEP sits, how local Resource
  policy composes with Mission authority, and which operation profiles
  apply.

Mission state source:
: A deployment-trusted source from which the PDP establishes the
  Mission lifecycle state or the freshness of that state
  ({{state-freshness}}).

Mission-bound token:
: An access token issued under a Mission per
  {{I-D.draft-mcguinness-oauth-mission}}, carrying
  `authorization_details` and a `mission` claim.

# Runtime model {#runtime-model}

## Enforcement flow

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
deny it refuses. The runtime decision evaluates the action against the
Mission's authority, the entry constraints, the actor chain, the
Mission's current state, and Resource policy, as defined in
{{decision}}.

## Enforcement scope and conformance {#runtime-conformance}

This profile is implemented by a runtime deployment, not by an OAuth
Authorization Server alone. A deployment that claims conformance to
this profile MUST document its enforcement scope, including:

- the protected resources, action classes, and execution paths it
  mediates;
- the PEP locations that can prevent those actions;
- the PDP or PDPs that evaluate Mission-bound decisions;
- the `authorization_details` types, action identifiers, and constraint
  vocabularies it supports;
- any Resource Server runtime profile and operation profiles it uses
  ({{rs-runtime-profile}});
- the Mission state source and maximum staleness bound used for each
  action class ({{state-freshness}});
- the runtime enforcement evidence mechanism and retention window
  ({{evidence}}); and
- any consumption-metering consistency bound it advertises
  ({{metering}}).

A deployment MUST NOT claim runtime enforcement for a resource, action
class, `authorization_details` type, or execution path outside that
declared scope. A Mission Issuer conforms to the issuance profile; it
does not become a runtime-conforming deployment merely by issuing
Mission-bound tokens.

The enforcement scope is a deployment conformance statement, not an
OAuth Authorization Server metadata extension. This document defines no
discovery mechanism, registry, or wire format for publishing it.
Different deployments can document scope through configuration,
operational policy, resource-server metadata defined elsewhere, or a
contractual profile.

## Action classification {#classification}

The boundary between consequential and non-consequential actions is
deployment policy, but a deployment MUST NOT define it so loosely that
nothing is enforced. This document defines a default classification a
deployment SHOULD adopt, and a floor it MUST observe.

| Class | Examples | PDP gate | Parameter binding |
|---|---|---|---|
| Non-consequential | internal reasoning, cache reads, planning | not required | n/a |
| Consequential read | reading user data, querying logged APIs | MUST | not required |
| Consequential write | updating records, posting messages | MUST | MUST |
| Irreversible action | sending mail, payment, deletion | MUST | MUST, with TOCTOU reverification |
| External commitment | signing, accepting terms for the user | MUST | MUST, with TOCTOU reverification and evidence |
| Privileged administration | granting access, changing policy | MUST | MUST, with TOCTOU and evidence |

**Classification floor.** Actions in the **irreversible**, **external
commitment**, and **privileged administration** classes MUST be
treated as consequential and gated. A Mission's `purpose`, or
deployment policy, MAY raise an action to a stricter class; it MUST
NOT lower an action below any minimum classification the Resource
policy ({{decision}}) sets for it, and in any case MUST NOT classify an
irreversible, external-commitment, or privileged-administration action
as non-consequential. A deployment
that leaves such an action ungated does not enforce this profile for
that action's class ({{pep-placement}}).

A deployment policy can require human confirmation, step-up
authentication, or another local signal for privileged administration
or external commitments. This profile does not define such a signal.

Consequential reads do not require parameter binding by default.
However, a deployment MUST bind or digest read parameters when those
parameters materially change the effective resource set or disclosure
risk. Examples include export-like reads, bulk reads, cross-tenant or
cross-account queries, privacy-sensitive filters, field selection that
controls sensitive attributes, destination or delivery parameters, and
aggregation choices that affect re-identification risk.

## PEP placement {#pep-placement}

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

# Resource Server runtime profile {#rs-runtime-profile}

An OAuth Resource Server that claims conformance to this runtime
profile MUST publish or otherwise make available a Resource Server
runtime profile for the protected resources and operations in scope.
The Resource Server runtime profile is a deployment conformance
statement, not an OAuth Authorization Server metadata extension and
not a new access token format.

The Resource Server runtime profile MUST define:

- the protected resources, endpoint families, methods, tools, or
  operation identifiers for which Mission runtime enforcement applies;
- the minimum action class for each protected operation, including any
  Resource policy floor that raises the class above the default
  classification in {{classification}};
- the PEP location that can prevent each protected operation and any
  known execution path that is outside the claim;
- the PDP or PDPs used for Mission-bound runtime decisions, including
  how the PEP and PDP authenticate and integrity-protect decision
  requests and responses when they are separate components;
- the supported `authorization_details` types, action identifiers, and
  constraint vocabularies for those operations;
- the operation profile for each protected operation or operation
  family, including parameter normalization, default insertion,
  omitted optional fields, set-like array handling, idempotency-key
  handling, and duration measurement when duration can be metered;
- the Mission state source, maximum staleness bound, and permit
  lifetime bound used for each action class;
- how Resource policy is evaluated and composed with Mission authority,
  including local object authorization, tenant configuration, legal
  holds, service invariants, and risk policy;
- replay controls for permit use, including where single-use decision
  identifiers and idempotency keys are recorded and how long consumed
  identifiers are retained;
- any consumption-metering topology and consistency bound, including
  reserve, commit, settlement, retry, and reconciliation behavior; and
- the runtime enforcement evidence fields, retention window, and
  privacy treatment for decision and refusal records.

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

# Token presentation and validation {#token-validation}

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

The underlying OAuth deployment MUST follow the applicable security
best current practice in {{RFC9700}}. In particular, a Resource Server
PEP MUST refuse a token whose audience is not intended for that
Resource Server, and MUST verify the proof-of-possession check for a
sender-constrained token before treating its `cnf` binding as
authenticated.

A PEP MUST NOT ask a PDP to authorize an action from unverified token
claims. If token validation fails, or if the deployment requires
Mission governance for the protected operation and the token lacks a
`mission` claim, the PEP MUST refuse before runtime Mission
evaluation. When the PEP is an OAuth Resource Server, it uses the
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

# The decision {#decision}

Before a consequential action runs, its PEP MUST obtain a permit from
a PDP that evaluates the action against the Mission the acting token
is bound to. This is the normative contract. The decision API wire
format is a deployment choice; {{authzen}} gives a non-normative
example binding.

The PEP MUST supply the inputs the PDP needs for the Mission-bound
decision. Runtime enforcement MUST evaluate:

- **Authority.** The action MUST be authorized by an applicable
  `authorization_details` entry in the token. For an entry of type
  `mission_resource_access`, the action's `resource` and invoked action
  or tool identity MUST be within that entry's `resource` and
  `actions`, under the subset rule of
  {{I-D.draft-mcguinness-oauth-mission}}. The PEP asserts the
  capability identity (for example, the tool or function name) it will
  invoke; the PDP MUST refuse an identity outside the approved
  `actions`. For any other `authorization_details` type, the PDP MUST
  evaluate the action under that type's documented runtime semantics
  and MUST refuse if it does not understand or cannot enforce those
  semantics. Richer capability-source binding (source digests,
  cross-format identity) is out of scope ({{deferred}}).
- **Resource policy.** The runtime decision MUST include any
  applicable Resource policy. A Mission-bound token and runtime permit
  are an upper bound on authority, not a command for the Resource
  Server to perform the action. Resource policy MAY be evaluated by
  the PDP, by the Resource Server or PEP as a composed local
  authorization step, or by both. The action MUST fail closed unless
  both Mission authority and Resource policy permit it. Resource
  policy includes object-level authorization, tenant configuration,
  legal holds, service invariants, and risk policy.
- **Parameters.** Every `constraints` value on the applicable entry
  MUST be evaluated against the concrete action parameters. A
  constraint the PDP does not understand or cannot enforce or meter
  MUST cause refusal; it MUST NOT be ignored or reduced to
  disclosure-only treatment.
- **Actor.** When delegation is in effect, the PDP MUST evaluate the
  authenticated `act` chain as part of the runtime actor context and
  refuse a chain that is missing or malformed. The runtime decision
  MUST NOT expand authority beyond the issued `authorization_details`;
  delegation constraints that the issuance profile applies at token
  issuance are not re-applied here unless the deployment documents
  them as runtime Resource policy. When an `act` chain is present, the
  PDP MUST NOT treat `client_id` alone as the immediate actor.
- **Time.** The PDP MUST refuse if the decision context indicates the
  token is expired or the requested action would execute outside the
  permit validity window. The issuance profile caps a derived token's
  `exp` at `mission_expiry`, so the `exp` check enforces the Mission's
  expiry transitively. The standard `mission` claim and introspection
  do not surface `mission_expiry`; where a Mission state source does
  expose it (or reports the Mission `expired`), the PDP MUST refuse on
  it independent of the token's own `exp`.
- **State.** The PDP MUST refuse unless the Mission is `active`
  ({{state-freshness}}).

On a deny, the PEP MUST refuse the action. Authority-expandable
denials and the escalation workflow that turns a deny into a Mission
expansion are out of scope and deferred ({{deferred}}); in this
profile a deny is terminal for the attempted action.

The PDP's placement is a deployment choice (co-located with the
Mission's `origin`, embedded in the Resource Server, a tenant-scoped
service, or a shared service); this document does not mandate one. The
requirement is only that a PEP at each consequential boundary can
reach an applicable PDP.

## Mission state and freshness {#state-freshness}

A Mission-aware decision needs the Mission's current state, which a
token alone does not convey. A runtime deployment MUST define the
Mission state source it trusts for each enforcement scope. Examples
include origin AS token introspection, a local Mission database, an
authenticated status or event feed from the Mission `origin`, a
materialized policy view, or a short-lived cross-domain credential
whose lifetime is the deployment's accepted state lease.

- The PDP MUST refuse a consequential action when it cannot establish,
  within the deployment's published staleness bound, that the Mission
  is `active`.
- A state source MUST either report the Mission state with a freshness
  time, or define a lease interval over which a previously established
  `active` state remains acceptable for the relevant action class.
  A permit issued from that state view MUST expire no later than the
  applicable freshness time or lease interval.
- When the credential issuer also holds the Mission, the PDP can learn
  state through token introspection ({{RFC7662}}) at the issuer per
  {{I-D.draft-mcguinness-oauth-mission}}. A non-origin Resource AS
  introspecting a local token cannot report current Mission state under
  the issuance profile; it can establish local token validity, but not
  origin Mission freshness.
- This document defines no cross-issuer by-Mission status query.
  Deployments that need tighter freshness than the token or
  cross-domain grant lifetime provides need an out-of-band trusted
  status feed or a future standardized Mission Status surface.
- Each enforcement scope MUST publish its maximum staleness bound per
  action class and state source. This document does not impose one
  universal value.

The following non-normative guidance illustrates freshness bounds that
are likely to match the risk of common action classes:

| Class | Suggested freshness posture |
|---|---|
| Consequential read | Token lifetime or a short state lease; tighter for privacy-sensitive, cross-tenant, or bulk reads |
| Consequential write | A short state lease, typically measured in minutes |
| Irreversible action | Immediate check or single-use permit |
| External commitment | Immediate check or single-use permit |
| Privileged administration | Immediate check, suitable for composition with local step-up |

# Parameter binding and time-of-check to time-of-use {#parameter-binding}

A permit for an operation does not authorize arbitrary parameter
values. For consequential writes, irreversible actions, external
commitments, and privileged administration, the PDP MUST bind its
permit to the normalized action parameters through a
`parameter_digest`, and the executing PEP MUST recompute and reverify
that digest immediately before acting.

- `parameter_digest` is `sha-256:` followed by the base64url, no
  padding, SHA-256 {{RFC6234}} of the JCS {{RFC8785}} serialization of
  the normalized parameter object. It MUST be computed under the same
  canonicalization rules the issuance profile defines (duplicate
  member rejection, significant array order, byte-for-byte URI
  comparison); this document does not define a second canonicalization.
- The operation profile MUST define default insertion, omitted
  optional fields, and set-like array handling before canonicalization.
- The permit MUST also bind the Mission reference, token issuer when
  available, token audience or protected resource, `sub`, `client_id`,
  actor context, sender-constraint confirmation key when present,
  action, resource, the authorizing `authorization_details` entry or
  an entry digest, the PDP's policy-view version, and a permit lifetime
  control bounded by the Mission state freshness requirement
  ({{state-freshness}}). For a reversible consequential write, the
  control MUST be either a single-use decision identifier or a short
  validity window combined with an idempotency key that prevents repeat
  execution of the same normalized action. For an irreversible action,
  an external commitment, or privileged administration it MUST be a
  single-use decision identifier: a validity window alone does not
  bound how many times such a permit executes.
- Where a single-use decision identifier is used, the enforcing
  component MUST record consumed identifiers for at least the permit
  lifetime and MUST refuse, fail closed, any second presentation of a
  consumed identifier. This is independent of consumption metering and
  applies even when the action carries no consumption bound.
- The executing PEP MUST verify those bindings and MUST recompute the
  `parameter_digest` against the parameters it is about to use. A
  mismatch MUST cause refusal: the permit does not authorize the
  changed parameters.

This closes the time-of-check to time-of-use gap and prevents a permit
from being replayed for a different request (the `parameter_digest`
mismatches). For non-idempotent consequential writes, irreversible
actions, external commitments, and privileged administration, the
single-use decision identifier or idempotency key also prevents repeat
execution of the same normalized action.
Consequential reads do not require a parameter digest by default; the
evaluation request still appears in the evidence record, by digest
where the parameters are sensitive ({{evidence}}).

Deployments MUST require parameter binding for consequential reads when
read parameters materially change the effective resource set or
disclosure risk. Examples include export-like or bulk reads,
cross-tenant queries, privacy-sensitive filters, selected fields,
destinations, and aggregation level. Ordinary reads that do not change
the resource set or disclosure risk can remain unbound.

# Consumption metering {#metering}

Consumption bounds the Mission carries are enforced here, not at
issuance. The issuance profile ({{I-D.draft-mcguinness-oauth-mission}})
defines three Mission-level consumption bounds in the Mission
`context` that this layer meters:

- `max_budget` (`{ amount, currency }`): the PDP performs an atomic
  reserve-or-charge against the remaining balance for each
  consequential action and MUST refuse when the remaining balance is
  insufficient.
- `max_calls` (`[ { scope, count } ]`): the PDP increments an atomic
  counter for the named `scope` and MUST refuse a call past `count`.
- `max_duration` (an ISO 8601 duration, e.g. `PT8H`; the `duration`
  rule in Appendix A of {{RFC3339}}): the cumulative wall-clock
  duration of consequential activity under the Mission, as the issuance
  profile defines it (distinct from `mission_expiry`). The PDP
  accumulates the duration of consequential activity it reserves,
  commits, or permits and MUST refuse once that total would exceed the
  bound. For an action whose duration is not known before execution,
  the PDP MUST either reserve a bounded maximum duration or issue a
  duration lease that expires unless renewed; the PEP MUST stop the
  action or obtain a new permit before the reservation or lease is
  exhausted. After execution, the PEP MUST report the measured
  duration so the PDP can commit actual use and release any unused
  reservation. The operation profile defines how a single action's
  duration is measured so that PDPs accumulate consistently.

A per-entry `constraints` value that expresses a consumption bound is
metered the same way. When an applicable entry or the Mission's
`context` carries such a bound, the PDP MUST meter use against it and
MUST refuse a consequential action that would exceed it.

The exactness of a consumption bound depends on the decision
topology, and this profile does not overpromise:

- Under a **single serializing PDP** for the Mission, the check and
  decrement can be atomic, and the bound is exact.
- Under **multiple or distributed PDPs** (for example, Resource
  Server-hosted PDPs), an exact global counter is a distributed-counting
  problem. Such a deployment MUST publish the consistency bound it
  operates under (for example, per-PDP sub-budgets, or a bounded
  reconciliation window), and the effective guarantee is that bound,
  not exact-to-the-call enforcement.

A deployment MUST NOT advertise exact consumption enforcement it
cannot meet under its chosen topology. As with all constraints, an
unmetered or unrecognized consumption bound MUST cause refusal rather
than silent pass-through.

For a metered permit, the PDP and PEP MUST define retry and idempotency
behavior. A retry of the same normalized action under the same
idempotency key or single-use decision identifier MUST NOT consume the
bound twice. Reuse of an idempotency key or decision identifier for a
different normalized action MUST cause refusal. For irreversible
actions and external commitments, a deployment MUST define whether
metering is reserved before execution and committed after success, or
committed before execution; it MUST NOT leave the decrement ambiguous.

# Failure modes {#failure-modes}

Enforcement is meaningful only if failure is bounded. A PDP or PEP
MUST behave as follows; in all cases the evidence record
({{evidence}}) MUST be sufficient to reconstruct which path produced a
refusal.

| Condition | Required behavior |
|---|---|
| Token validation fails, including sender-constraint verification | Refuse before runtime Mission evaluation |
| Mission governance is required but the token lacks a `mission` claim | Refuse before runtime Mission evaluation |
| PEP-PDP channel authentication or integrity protection fails | Fail closed |
| Mission state cannot be established within the staleness bound | Fail closed for consequential actions |
| PDP unreachable | Fail closed for consequential actions; do not proceed on cached permits past the window |
| Mission not `active` | Refuse |
| `mission_expiry` passed, when known from the Mission state source | Refuse |
| Unsupported `authorization_details` type for the action | Refuse |
| Unknown or unmetered constraint on the applicable entry | Refuse |
| Consumption bound would be exceeded | Refuse |
| `parameter_digest` mismatch at the executing PEP | Refuse |
| Re-presentation of a consumed single-use decision identifier | Refuse (fail closed) |
| Required `act` chain missing or malformed | Refuse |
| Invoked capability identity outside the approved `actions` | Refuse |
| Resource policy refuses the action | Refuse |
| Request would broaden the Mission's authority | Refuse (expansion is out of scope) |

# Runtime enforcement evidence {#evidence}

Every PDP decision on a consequential action MUST produce a runtime
enforcement evidence record. A PEP refusal for a consequential action,
whether before a PDP decision (for example, token validation failure
or PDP unreachability) or after a PDP permit (for example, a
`parameter_digest` mismatch), MUST likewise produce a runtime
enforcement evidence record with the available fields and the failure
condition. This document fixes the minimum record content and local
integrity requirements. The concrete record schema, any interoperable
canonical byte representation, separate Decision Evidence and
Execution Evidence object schemas, and portable cross-domain receipts
are out of scope ({{deferred}}).

For an irreversible action, an external commitment, or privileged
administration, the executing PEP MUST also produce, after it acts, an
execution-outcome record keyed to the permit's decision identifier,
recording at least success or failure and the `parameter_digest`
actually executed. This lets a decision and its execution be reconciled
one to one, so a permit that was obtained but executed more than once,
or executed for different parameters, is detectable after the fact. The
detailed object schema is deferred ({{deferred}}).

A record MUST contain:

- the decision or refusal result and, on refusal, the failure condition
  from {{failure-modes}};
- the request time (RFC 3339 {{RFC3339}}); and
- the `parameter_digest` for parameter-bound classes, or a
  privacy-preserving digest of the evaluation request otherwise.

A record MUST also contain the following fields when they are available
and trusted for the refusal or decision path:

- the Mission reference (`mission.id`, `mission.origin`) and the
  `authority_hash` (and `intent_hash` when known) it operated under;
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
- the decision identifier, when the PDP produced one; and
- the PDP's policy-view version.

For a token-validation failure, the record MUST NOT describe
unverified token claims as authenticated facts. It MAY include a digest
of the presented token or rejected claim set for correlation and
forensics, subject to the privacy requirements below.

The `authority_hash` and `intent_hash` in a record are the
originating AS's commitments, cited as anchors; the PDP does not
recompute them and is not required to hold the full Authority Set to
record them, consistent with {{I-D.draft-mcguinness-oauth-mission}}.

Requirements on the record:

- The Resource Server runtime profile MUST define the record's
  concrete serialization and canonicalization before storage and
  integrity protection. JSON records SHOULD use JCS {{RFC8785}} under
  the issuance profile's canonicalization rules.
- It MUST be append-only and integrity-protected; the enforcement
  scope MUST name the mechanism (a hash-linked log, signed segments, a
  transparency anchor, or equivalent).
- Raw parameters MUST NOT appear in the record; when retained for
  forensics they MUST be in separately access-controlled storage
  referenced by an opaque identifier, with only the
  `parameter_digest` in the record.
- Records for one Mission MUST carry a deployment-defined sequence
  indicator so decision order can be reconstructed without relying on
  wall-clock time alone.
- The enforcement scope MUST publish a retention window no shorter
  than the Mission's effective audit horizon.

# Example decision API binding: AuthZEN {#authzen}

The decision contract of {{decision}} is abstract. One possible binding
is the OpenID AuthZEN Authorization API {{AUTHZEN}}: the PEP issues an
Access Evaluation request and the PDP returns a decision. This section
is non-normative and does not define an AuthZEN profile.

A deployment using AuthZEN can carry Mission and actor inputs in
AuthZEN's open-ended `context` object:

- `context.mission`: `id`, `origin`, `authority_hash`, and the current
  `state`.
- `context.actor`: `client_id`, client-instance identifier when
  present, and the `act` chain as an array ordered root to leaf.

The AuthZEN `subject` remains the principal the decision is requested
for. On permit, the response carries the policy-view version, a
decision identifier, the `parameter_digest` for parameter-bound
classes, and a short validity window.

This profile's substance is the
enforcement contract, action classification ({{classification}}), PEP
placement ({{pep-placement}}), parameter binding ({{parameter-binding}}),
consumption metering ({{metering}}), and runtime enforcement evidence
({{evidence}}), which is independent of the decision wire. The
`context.mission` and `context.actor` example members above could be
standardized separately as a Mission-bound AuthZEN binding without
changing this contract.

# Out of scope {#deferred}

The following compose with this profile but are deferred to future
work and are not required to enforce it:

- mission expansion and the authority-expandable-denial escalation
  workflow (a deny here is terminal for the attempted action);
- a standardized enforcement-scope manifest format and discovery
  mechanism;
- cross-format capability-source binding (signed capability
  manifests, source-digest drift handling, cross-catalog identity);
- portable, third-party-verifiable decision receipts (this profile
  fixes only the local runtime enforcement evidence record);
- separate Decision Evidence and Execution Evidence object schemas and
  media types;
- actor provenance beyond the `act` chain, attestation of the
  execution environment, and a purpose registry;
- compilation of the Mission into an engine-native policy artifact
  (Cedar, OpenFGA, or equivalent) and standardization of PDP
  deployment modes;
- action-hierarchy and resource-containment subset extensions (this
  profile uses the flat subset rule of
  {{I-D.draft-mcguinness-oauth-mission}}); and
- risk-signal inputs to the decision (deployment-defined).

Structured per-argument attenuation of tool grants
({{I-D.draft-niyikiza-oauth-attenuating-agent-tokens}}) is a related
issuance/delegation-layer primitive, not part of this runtime profile.

# Security Considerations

## What this layer adds, and its limits

Gating every consequential action against the current Mission
prevents an active Mission from acting as ambient authority: authority
is checked at the point of use, parameters are bound to the permit,
consumption is metered, and each decision or refusal path is recorded.
This closes the approval-to-execution gap the issuance profile leaves
open.

It does not make a compromised enforcement component safe. A
compromised PEP can decline to consult the PDP or ignore its decision;
a compromised PDP can return whatever decisions it chooses. Decision
and enforcement evidence make such behavior auditable after the fact;
they do not prevent it in the moment. Signed, externally verifiable
decisions are future work ({{deferred}}).

## Placement and bypass

The strongest decision logic is void if the PEP is not at the last
controllable boundary, or if an unmediated path can reach the action
({{pep-placement}}). A deployment's claim is only as strong as the set
of execution paths it actually mediates; it MUST name that set.

## Classification integrity

Because "consequential" is partly deployment-defined, the
classification floor of {{classification}} is load-bearing: a
deployment cannot evade enforcement by classifying an irreversible,
external-commitment, or privileged-administration action as
non-consequential. A `purpose` may raise a class but never lower it
below the resource owner's floor.

## Freshness and consumption honesty

A permit is a lease, not a standing grant: stale Mission state MUST
fail closed for consequential actions within the published bound
({{state-freshness}}). Consumption bounds are exact only under a
single serializing PDP; a deployment MUST NOT advertise exactness it
cannot meet across distributed decision points ({{metering}}).

## Resource policy remains authoritative

Mission authority is a maximum authority envelope. It does not force a
Resource Server to perform an action, bypass local authorization, or
override object ACLs, tenant configuration, legal holds, service
invariants, or risk policy. A runtime deployment that treats a
Mission-bound permit as sufficient without Resource policy evaluation
can perform actions that the resource owner or service would otherwise
forbid.

## TOCTOU and replay

Parameter binding ({{parameter-binding}}) ties a permit to specific
normalized parameters and a short window or single use, so a permit
cannot be replayed for a different request or survive a parameter
change between check and use. The executing PEP, not an upstream
component, MUST perform the reverification.

## Decision channel and token disclosure

A separate PDP becomes part of the Resource Server's trusted
authorization path for the operations in its enforcement scope. The
PEP/PDP channel therefore needs mutual authentication, integrity
protection, and authorization for the declared scope
({{token-validation}}). Passing full access tokens to a PDP also
extends credential exposure beyond the Resource Server boundary; a
deployment that does so needs the same credential handling, retention,
and disclosure controls it applies at the Resource Server.

## Evidence privacy and correlation

Runtime enforcement evidence is intentionally durable and therefore
sensitive. It can reveal a subject's resources, action timing,
delegated actors, and Mission correlation identifier even when raw
action parameters are not stored. Deployments SHOULD minimize recorded
authority entries, store entry and parameter digests where full values
are not needed for audit, restrict access to evidence by role, and
document the retention window declared under {{evidence}}. Evidence
shared across resource boundaries can also correlate activity by
`mission.id` and `authority_hash`; deployments that require
unlinkability need an additional privacy design outside this profile.

General OAuth security guidance {{RFC9700}} applies to the underlying
credentials.

# IANA Considerations

This document has no IANA actions. The non-normative `context.mission`
and `context.actor` example members of {{authzen}} are not registered
in an IETF registry. The Mission-bound token claims this profile
consumes are registered by {{I-D.draft-mcguinness-oauth-mission}}.

--- back

# Acknowledgments
{:numbered="false"}

This document is the runtime companion to Mission-Bound Authorization
for OAuth 2.0 and builds on the OpenID AuthZEN Authorization API and
the OAuth 2.0 Rich Authorization Requests and JWT access token
specifications.
