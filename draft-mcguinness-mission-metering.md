---
title: "Mission Consumption Metering"
abbrev: "Mission Metering"
category: exp

docname: draft-mcguinness-mission-metering-latest
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
 - metering
 - budget
venue:
  github: "mcguinness/mission-bound-authorization"
  latest: "https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-metering.html"

author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com

normative:
  RFC3339:
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

informative:
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

--- abstract

Mission-Bound Authorization for OAuth 2.0 bounds an agent's authority
by resources, actions, and constraints, and its runtime enforcement
profile evaluates each consequential action at the point of use.
Neither bounds how much of an approved authority a Mission may consume.
This document defines an experimental consumption-metering extension:
four cumulative consumption bounds a Mission Intent may carry
(`max_budget`, `max_calls`, `max_duration`, and `max_egress_volume`),
an exclusivity control (`exclusive`, separation of duty),
the runtime metering
semantics that enforce them (atomic check-and-decrement, reserve and
commit postures, duration leases, and settlement), and the AuthZEN wire
binding for lease renewal and settlement. A consumption bound is
consented at approval and enforced only by a runtime deployment that
implements this profile; a deployment that does not meter a bound must
refuse rather than silently ignore it.

--- middle

# Introduction

Mission-Bound Authorization for OAuth 2.0
{{I-D.draft-mcguinness-oauth-mission}} (the "issuance profile") bounds
what an agent may do; the runtime enforcement profile
({{I-D.draft-mcguinness-mission-runtime}}) enforces each consequential
action at the point of use. A long-running agentic task also needs
bounds on how much: cumulative spend, call volume, and wall-clock
activity. Those are not per-action constraints; they are counters that
deplete across the life of the Mission, and enforcing them is a
metering problem with reserve, commit, retry, and
distributed-consistency concerns of its own.

This document defines that metering layer: the consumption-bounds
vocabulary a Mission Intent carries, the metering semantics a runtime
deployment enforces, and the AuthZEN wire binding
({{I-D.draft-mcguinness-mission-authzen}}) for settlement and
duration-lease renewal.

# Status: An EXPERIMENTAL Extension {#optional-status}

This document is OPTIONAL and **experimental**: adopt it for
evaluation, not as a stable interface. Metering cumulative bounds
exactly under distributed decision points is a distributed-counting
problem, and the reserve, commit, lease, and settlement machinery here
is expected to evolve with implementation experience.

A deployment that does not implement this document carries no
consumption bounds on its Missions and is fully conformant to the
issuance and runtime profiles. The issuance profile's
`max_derivations` is not a consumption bound: it is enforced by the
issuing Authorization Server at each derivation and needs none of this
document ({{I-D.draft-mcguinness-oauth-mission}}).

The consent-integrity rule of {{consent}} is the boundary that makes
this safe to omit: a bound is rendered to an Approver only where it is
actually metered.

# Relationship to the Issuance and Runtime Profiles {#relationship}

This document depends normatively on the issuance profile and the
runtime profile and is not implementable alone. It defines its
consumption bounds as members of the Mission Intent `controls` object,
using the extension seam the issuance profile provides; they are
carried on the Mission and committed by `intent_hash` exactly as any
other Intent member. Metering is performed by the runtime profile's
PDP within a documented enforcement scope; this document adds metering
semantics to the runtime profile's decision contract and changes no
issuance behavior.

# Conventions and Terminology {#conventions}

{::boilerplate bcp14-tagged}

Consumption bound:
: A cumulative bound on Mission activity that depletes as the Mission
  is used, as distinct from a per-action constraint that is evaluated
  independently on each action.

# Mission Substrate {#mission-substrate}

This profile is defined against the Mission model rather than against
OAuth 2.0 mechanics. It consumes these substrate primitives
({{I-D.draft-mcguinness-mission-substrate}}): the Mission Identifier
and issuer, which key every consumption counter; the Authority Set
representation, from which a `call_class` SHOULD be drawn
({{bounds}}); and the integrity-anchor envelope, through which the
bounds are committed by `intent_hash` as Mission Intent `controls`
members. It defines no binding of its own: enforcement composes
through the runtime profile's Mission binding establishment step
({{I-D.draft-mcguinness-mission-runtime}}), and metering adds
counters to the runtime decision.

# Consumption Bounds {#bounds}

A Mission Intent `controls` object
({{I-D.draft-mcguinness-oauth-mission}}) MAY carry these members:

`max_budget`:
: OPTIONAL. An object. A hard cap on cumulative monetary
  spend under the Mission. It carries the same `{amount, currency}`
  shape as the `max_amount` Common Constraint the issuance profile
  seeds, so the per-action cap and this cumulative cap read alike.
  Has the members:

  `amount`:
  : REQUIRED. A string. A decimal number.

  `currency`:
  : REQUIRED. A string. An ISO 4217 currency code.

`max_calls`:
: OPTIONAL. An array of objects. Hard caps on the count of
  consequential call events. Each object has the members:

  `call_class`:
  : REQUIRED. A string. The named call class to meter. A `call_class`
    value SHOULD be drawn from the `actions` identifiers of the
    entry's `mission_resource_access`
    ({{I-D.draft-mcguinness-oauth-mission}}),
    so the metered class maps to evaluated actions; a deployment that
    meters a coarser or cross-entry class defines that class's
    membership, and such a class is deployment-defined and not
    interoperable, like a deployment-defined constraint. (Named
    `call_class` rather than `scope` to avoid collision with the OAuth
    `scope` parameter and claim.)

  `count`:
  : REQUIRED. An integer. 1 or greater.

`max_duration`:
: OPTIONAL. A string. An ISO 8601 duration (for
  example, `PT8H`), matching the `duration` rule in Appendix A of
  {{RFC3339}}, bounding cumulative wall-clock consequential activity
  under the Mission. It is distinct from the Mission's `expires_at`,
  which bounds issuance rather than activity.

`max_egress_volume`:
: OPTIONAL. An object with one or both members `bytes` and
  `messages`, each an integer, 1 or greater: hard caps on cumulative
  egress under the Mission across consequential
  external-communication and external-commitment actions
  ({{I-D.draft-mcguinness-mission-runtime}}), as the total size in
  bytes of those actions' bound payload parameters and the count of
  such actions. It bounds the volume of within-scope laundering; it
  does not detect it.

`exclusive`:
: OPTIONAL. An array of exclusivity groups, each an array of two or
  more selectors. A selector is an object with `resource` (REQUIRED,
  a string) and `actions` (OPTIONAL, an array of strings); it matches
  a consequential action whose resource equals `resource` and, when
  `actions` is present, whose invoked action is within it. Within a
  group, the selectors name authority the Approver consents MUST NOT
  be combined under this Mission ({{exclusivity}}).

The bounds are carried on the Mission and committed by `intent_hash`.
They are not enforced by the Authorization Server at issuance; they are
enforced by the runtime layer at the point of use ({{metering}}).

Example Mission Intent `controls` carrying three of the four bounds
alongside
the issuance profile's members:

~~~ json
{
  "controls": {
    "acr": "urn:example:acr:mfa",
    "max_derivations": 200,
    "max_budget": { "amount": "5000.00", "currency": "USD" },
    "max_calls": [
      { "call_class": "journal-entries.write", "count": 50 }
    ],
    "max_duration": "PT8H"
  }
}
~~~

## Consent Integrity {#consent}

A consumption bound is part of what the Approver consents to. Where a
deployment records Consent Evidence
({{I-D.draft-mcguinness-oauth-mission-consent-evidence}}), the
rendered authority summary MUST include the consumption bounds the
Mission carries.

A deployment MUST NOT render a consumption bound to the Approver as
enforced unless the bound is within a runtime enforcement scope that
meters it under this document. A deployment that accepts the bounds
into the Intent but does not meter them presents an unenforced promise
at the consent surface; a Mission Issuer whose deployment does not
meter a bound SHOULD refuse an Intent that carries it, and MUST NOT
render it as an enforced limit.

# Consumption Metering {#metering}

Consumption bounds are enforced by the runtime profile's PDP
({{I-D.draft-mcguinness-mission-runtime}}), not at issuance:

- `max_budget`: the PDP performs an atomic
  reserve-or-charge against the remaining balance for each
  consequential action and MUST refuse when the remaining balance is
  insufficient.
- `max_calls`: the PDP increments an atomic
  counter for the named `call_class` and MUST refuse a call past `count`.
- `max_egress_volume`: the PDP adds the action's bound payload size
  and increments the action count atomically with the permit and MUST
  refuse an action that would exceed either cap. Payload size is
  measured over the parameter bytes committed by `parameter_digest`
  ({{I-D.draft-mcguinness-mission-runtime}}); the operation profile
  defines the measurement so PDPs accumulate consistently.
- `max_duration`: the PDP
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

A per-entry `constraints` value that expresses a cumulative consumption
bound is metered the same way. When an applicable entry or the
Mission's `controls` carries such a bound, the PDP MUST meter use
against it and MUST refuse a consequential action that would exceed it.
The runtime profile's fail-closed rule stands beneath all of this: an
unmetered or unrecognized consumption bound MUST cause refusal rather
than silent pass-through ({{I-D.draft-mcguinness-mission-runtime}}).

## Exactness and Topology {#topology}

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
cannot meet under its chosen topology. The consistency bound is part of
the runtime enforcement scope the runtime profile requires a deployment
to document ({{I-D.draft-mcguinness-mission-runtime}}).

## Retry, Idempotency, and Reserve/Commit Posture {#retry}

For a metered permit, the PDP and PEP MUST define retry and idempotency
behavior. A retry of the same normalized action under the same
idempotency key or single-use decision identifier MUST NOT consume the
bound twice. Reuse of an idempotency key or decision identifier for a
different normalized action MUST cause refusal. For irreversible
actions and external commitments, a deployment MUST define whether
metering is reserved before execution and committed after success, or
committed before execution; it MUST NOT leave the decrement ambiguous.
A failed attempt releases any reserved consumption per the deployment's
documented reserve/commit posture.

# Exclusivity and Separation of Duty {#exclusivity}

The `exclusive` control ({{bounds}}) is not a consumption bound: it
is a stateful separation-of-duty rule enforced with the same
machinery. Within an exclusivity group, the first permitted
consequential action matching a selector latches the group to that
selector, atomically with the permit; for the Mission's remaining
lifetime the PDP MUST refuse a consequential action matching any
other selector of the same group. The latch is per group and per
Mission, is PDP-side operational state like a consumption counter
({{metering}}), and never unlatches: narrowing by exercise is
monotonic, like every other narrowing in the family.

Exclusivity turns the quarantine deployment pattern
({{I-D.draft-mcguinness-mission-architecture}}) into consented,
enforceable structure: an Approver can approve a Mission that may
read a sensitive store or communicate externally, but never both.
The groups are consented at the approval event, committed by
`intent_hash` with the other `controls` members, and rendered in the
consent disclosure ({{consent}} applies unchanged).

In the AuthZEN binding, a refusal under a latched group is denied
with `exclusivity_latched`, an extension of the runtime denial set
under the AuthZEN profile's coordinated-extension conventions
({{I-D.draft-mcguinness-mission-authzen}}), and recorded as the
`denial_reason` in Decision Evidence. A PDP that cannot establish a
group's latch state fails closed for the actions the group covers,
per the runtime profile's availability posture.

# Aggregate Bounds {#aggregate-bounds}

The bounds of this document are Mission-keyed. A deployment MAY
additionally meter the same bound classes across Missions, keyed by
the Mission's `subject` or by the approved `client_id`, so a fleet
operator can cap what an agent identity or a Subject consumes in
total rather than per task. The counter semantics, reserve/commit
postures, and refusal behavior are unchanged; only the key differs.

An aggregate bound is deployment policy: it is carried on no single
Mission Intent, is committed by no `intent_hash`, and is disclosed
through the deployment's enforcement-scope statement rather than the
approval event. A refusal under an aggregate bound is carried as
`quota_exceeded`, and Decision Evidence records the
deployment-defined aggregate key class.

Aggregate keying crosses the family's per-Mission consistency
domains: a subject-keyed counter is shared by every Mission the
subject holds, so it cannot be sharded by Mission Identifier and is
provisioned as its own consistency domain
({{I-D.draft-mcguinness-mission-runtime}}).

# AuthZEN Binding {#authzen-binding}

Where the runtime deployment uses the AuthZEN binding
({{I-D.draft-mcguinness-mission-authzen}}), this section defines the
wire representation of metering. It defines no new metering semantics
and no new constraint.

When metering a bound would exceed it, the PDP MUST deny with
`quota_exceeded` ({{I-D.draft-mcguinness-mission-authzen}}) instead of
returning a permit, and MUST record `quota_exceeded` as the
`denial_reason` in Decision Evidence. Whether a metered permit is
reserved at decision time and committed on settlement, or committed at
decision time, follows the deployment's documented reserve/commit
posture ({{retry}}); this binding fixes neither. In a batch (boxcar)
evaluation, consumption metering applies per item in request order. The
exactness of the bound is the consistency bound of {{topology}}, not a
property of this wire binding.

## Settlement Exchange {#settlement-exchange}

The metering rules require the PEP to signal actual use so the PDP
commits consumption and releases any reservation. In the AuthZEN
binding, delivery of the Execution Evidence Object
({{I-D.draft-mcguinness-mission-authzen}}) to the PDP is that
commit-or-release signal: on receipt the PDP commits the consumption
the linked action used and releases any reserved excess, keyed to the
Execution Evidence's `decision_id`.

For a duration-metered action the PEP reports the measured duration in
the Execution Evidence `measured_duration` member, and the PDP commits
that duration against `max_duration`. A duration-lease renewal is a new
re-evaluation request that carries the prior permit's `decision_id` in
`context.prior_decision_id`, so the PDP continues the same metered
activity rather than opening a new reservation. This exchange requires
one request member and one evidence member:

`context.prior_decision_id`:
: OPTIONAL. A string. Present on a duration-lease renewal request,
  carrying the `decision_id` of the permit being renewed. Absent on an
  initial request.

`measured_duration` (Execution Evidence):
: REQUIRED for a duration-metered action, otherwise absent. A string
  containing an ISO 8601 duration (the `duration` rule in Appendix A of
  {{RFC3339}}): the PEP's measured duration for the executed action.

A renewal repeats the evaluation-request envelope for the same
activity and adds `context.prior_decision_id`. Here a long-running,
duration-metered ledger reconciliation renews its lease before the
prior permit expires; the action is not parameter-bound, so no
`parameter_digest` is carried:

~~~ json
{
  "subject": {
    "type": "user",
    "id": "user_3p2q8mN1a0kV7tR",
    "properties": {
      "iss": "https://idp.example.com"
    }
  },
  "resource": {
    "type": "ledger",
    "id": "ledger_main"
  },
  "action": { "name": "reconciliation.run" },
  "context": {
    "mission": {
      "id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
      "issuer": "https://as.example.com",
      "authority_hash":
        "sha-256:l3KvZ4mP5x0wQrR6tY2nD9bM7sX1cF8gH2vJ4kE5pNQ",
      "state": "active"
    },
    "actor": { "client_id": "s6BhdRkqt3" },
    "credential": {
      "issuer": "https://as.example.com",
      "expires_at": "2026-11-02T09:14:00Z"
    },
    "audience": "https://erp.example.com",
    "freshness": {
      "mode": "fresh",
      "freshness_at": "2026-11-02T08:44:00Z"
    },
    "prior_decision_id": "dec_0Rt5nB8xW2qK7mJ4vS1pL9eYc"
  }
}
~~~

# Conformance {#conformance}

A runtime deployment that claims this profile MUST:

- meter every consumption bound a governed Mission carries per
  {{metering}}, within its documented runtime enforcement scope
  ({{I-D.draft-mcguinness-mission-runtime}});
- refuse a consequential action that would exceed a bound, and refuse
  on any bound it cannot meter;
- enforce every consented exclusivity group with a latch atomic with
  the permit ({{exclusivity}});
- where aggregate bounds are configured, meter and disclose them per
  {{aggregate-bounds}};
- publish its consistency bound under a multi-PDP topology
  ({{topology}});
- define and document its retry, idempotency, and reserve/commit
  posture ({{retry}}); and
- where the AuthZEN binding is in use, implement the settlement
  exchange of {{settlement-exchange}}.

A Mission Issuer in a deployment claiming this profile MUST carry the
consented bounds on the Mission record committed by `intent_hash`, and
MUST render them at the approval event per {{consent}}.

# Security Considerations {#security-considerations}

Consumption bounds limit the blast radius of a compromised or runaway
agent in a dimension authority narrowing cannot: a Mission whose every
action is individually authorized can still be drained by volume.
Their enforcement, however, is only as good as the metering:

- **Unenforced bounds are consent theater.** A bound rendered at
  approval but not metered anywhere misleads the Approver about the
  Mission's exposure. The consent-integrity rule ({{consent}}) exists
  for this; a deployment that cannot meter MUST NOT render the bound as
  enforced.
- **Distributed undercounting.** Under a multi-PDP topology, an
  attacker who can spread actions across decision points exploits the
  consistency gap. The published consistency bound ({{topology}}) is
  the honest statement of that exposure; per-PDP sub-budgets bound it
  structurally.
- **Settlement honesty.** The PDP commits what the PEP reports.
  Execution Evidence is integrity-protected and signed by the PEP
  ({{I-D.draft-mcguinness-mission-authzen}}); a compromised PEP can
  under-report duration or spend, which is within the runtime profile's
  trusted-base assumptions for PEPs.
- **Lease abandonment.** An agent that stops renewing a duration lease
  and keeps acting is stopped by the PEP, which MUST stop the action or
  obtain a new permit before the lease is exhausted ({{metering}}).

# Privacy Considerations {#privacy-considerations}

Metering state (spend, call counts, activity durations) is a
fine-grained record of Mission activity over time. It SHOULD be
retained under the same access controls and retention windows as
runtime enforcement evidence
({{I-D.draft-mcguinness-mission-runtime}}), and disclosed in decision
responses only as refusals, not as remaining-balance oracles.

# IANA Considerations {#iana}

This document has no IANA actions. `max_budget`, `max_calls`,
`max_duration`, `max_egress_volume`, and `exclusive` are Mission
Intent `controls`
members defined by this
profile under the issuance profile's controls extension seam;
`context.prior_decision_id` and `measured_duration` are AuthZEN
extension data carried per the AuthZEN profile's conventions
({{I-D.draft-mcguinness-mission-authzen}}).

--- back

# Acknowledgments
{:numbered="false"}

This document is part of the Mission-Bound Authorization for OAuth 2.0
work and defines its experimental consumption-metering layer.
