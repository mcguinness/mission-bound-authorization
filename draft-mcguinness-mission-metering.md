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
  I-D.draft-mcguinness-mission-authzen:
    title: "Mission-Bound Runtime Enforcement: AuthZEN Profile"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-authzen.html
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
  I-D.draft-mcguinness-oauth-mission-consent-evidence:
    title: "Mission Consent Evidence for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-consent-evidence.html
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
  RFC7942:
  I-D.draft-mcguinness-oauth-mission-child-delegation:
    title: "Mission Child Delegation for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-child-delegation.html
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
  I-D.draft-mcguinness-mission-orchestration:
    title: "Mission Orchestration and Unwinding"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-orchestration.html
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

This document defines that metering layer:

- the consumption-bounds vocabulary a Mission Intent carries,
- the metering semantics a runtime deployment enforces, and
- the AuthZEN wire binding
  ({{I-D.draft-mcguinness-mission-authzen}}) for settlement and
  duration-lease renewal.

# Status: An Experimental Extension {#optional-status}

This document is optional and experimental: adopt it for
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

## Promotion Criteria {#promotion-criteria}

This section is informative. Promotion moves this accounting model
from optional evaluation toward the architectural baseline for any
Mission carrying a consumption bound, so the bar is exercised
machinery, not elapsed time. Meeting these criteria supplies
implementation and deployment evidence for a deliberate decision,
through the applicable IETF process, about changing this document's
intended status or moving selected mechanisms into a Standards Track
profile; it does not itself change either status, and no criterion,
met or unmet, changes anything automatically. A catalog or inventory
maturity label is distinct from an IETF stream decision and follows
one rather than substituting for one. Implementation listings and
test reports belong in an Implementation Status section per
{{RFC7942}}, removed before RFC publication; this section states the
durable criteria.

Promotion is gated per feature by the applicable rows:

| Gate | Applies to |
| --- | --- |
| Retry, atomicity, settlement, and crash recovery | Every consumption bound |
| Exact or qualified topology behavior | Every claimed topology profile |
| Currency and debit/refund behavior | `max_budget` |
| Call classification and counting point | `max_calls` |
| Measurement, renewal, skew, and stop behavior | `max_duration` |
| Payload dereference and message accounting | `max_egress_volume` |
| Cross-Mission counter consistency | Aggregate bounds |
| Atomic latch and release | `exclusive` |
| Independent interoperation | Each promoted wire profile |
{: title="Promotion gates"}

Each gate passes on named evidence:

**Retry, atomicity, settlement, and crash recovery.** For each
promoted bound class, a reproducible test suite with no skipped
cases demonstrates exactly-once accounting under {{retry}} and
{{settlement-exchange}}: a retry under the same idempotency key or
decision identifier consumes once; a redelivered settlement neither
double-commits nor double-releases; a conflicting redelivery fails
closed; a crash between reserve and commit resumes to a consistent
balance; and every evidence state of {{settlement-states}} is
exercised. This is the decrement-side counterpart of the
exactly-once reservation machinery the family's Mission-creating
surfaces carry for creation.

**Exact or qualified topology behavior.** Each claimed enforcement
profile of {{topology}} is demonstrated against its own guarantee:
the Exact profile never over-consumes under concurrent
near-exhaustion attempts; the Bounded-consistency profile stays
within its published overshoot and staleness bound and reconciles
orphaned reservations on the published cadence, including a
non-idempotent reservation held until affirmative evidence of
non-execution. Only Exact-profile evidence qualifies a bound for
promotion as a baseline hard cap; Bounded-consistency evidence
qualifies only the qualified form, the cap together with its
published bound, rendered per {{consent}}. Artifacts: the
Enforcement Scope Statement naming the profile per counter, and the
reconciliation record.

**Currency and debit/refund behavior** (`max_budget`). Exact decimal
arithmetic with no floating-point accumulation; refusal on a
currency the counter does not carry, or the deployment's documented
conversion rule; debit, refund, and release paths returning exact
amounts.

**Call classification and counting point** (`max_calls`). The
`call_class` mapping of {{bounds}} exercised across implementations,
the same consequential action counted against the same class, and
the counting point proven: the count consumed at decision, the
disposition confirmed at settlement ({{settlement-contract}}).

**Measurement, renewal, skew, and stop behavior** (`max_duration`).
The duration rules of {{metering}} exercised: bounded reservation or
lease for an unknown duration, renewal through
`context.prior_evaluation_id` ahead of expiry by the skew margin,
stop-or-new-permit before exhaustion, the in-flight handling of an
action that cannot be safely stopped, and `measured_duration` commit
with release of the unused reservation.

**Payload dereference and message accounting**
(`max_egress_volume`). The Operation Profile measurement exercised
for both `bytes` and `messages`, including a reference-typed
parameter measured by its dereferenced payload or its action class
excluded from a claimed `bytes` bound ({{metering}}).

**Cross-Mission counter consistency** (aggregate bounds,
{{aggregate-bounds}}). A lineage-keyed budget identifier and its
authoritative shared counter metering a root Mission and its Child
Missions in the counter's own consistency domain: a lineage-wide
`quota_exceeded` refusal from Child Mission consumption, a Child
Mission's released reservation returned to the shared counter, and
no consent surface or Enforcement Scope Statement rendering an
aggregate bound the deployed counter does not back. Artifacts: the
refusal's Decision Evidence carrying a `metering` entry
({{metering-evidence}}) whose `requested`, `remaining`,
`counter_scope`, and `counter_id` prove the accounting invariant
rather than only the asserted refusal.

**Atomic latch and release** (`exclusive`). Concurrent consequential
actions matching different selectors of one group latch exactly one
selector, atomically with the permit; the affirmative-non-execution
release restores the group; refusals carry `exclusivity_latched` in
Decision Evidence; the latch domain is named in the Enforcement
Scope Statement ({{exclusivity}}). This gate also holds the family's
adoption of the `exclusive` control into the issuance profile's core
`controls` vocabulary: that adoption follows the applicable gates of
this section being met, and until then the control is homed here.

**Independent interoperation.** Two distinct results, both required
for each promoted wire profile, aligning with the implementation and
interoperation reporting convention of {{RFC7942}}:

- Operational experience: at least one deployment not operated by
  the implementer.
- Interoperability: an independently implemented PEP and PDP
  exchange the profiled messages, including duplicate delivery and
  failure cases, under the settlement submission contract
  ({{settlement-contract}}).

Across every gate, promotion additionally requires the promoted wire
surface unchanged in name, shape, and semantics across two
consecutive published revisions of this document while the evidence
accumulated: the `controls` members of {{bounds}}, `quota_exceeded`,
`exclusivity_latched`, `context.prior_evaluation_id`,
`measured_duration`, the `metering` evidence member
({{metering-evidence}}), and the settlement submission contract of
{{settlement-contract}}.

Selective promotion means the applicable rows: promoting a
per-Mission bound class does not require the aggregate or
`exclusive` gates, and promoting the `exclusive` control does not
require the bound-class gates; every promotion includes the rows
that apply to each consumption bound it covers, its claimed topology
profiles, and its wire profile.

The criteria are sized to be satisfiable by a reference
implementation, one deployment not operated by its implementer, and
one independently implemented counterpart component; they demand
exercised machinery and stable surfaces, not adoption counts.

<!-- family-status: BEGIN (generated from family-manifest.json; exact-matched by scripts/check-family-manifest.mjs) -->
Maturity: experimental. Maintenance: lab-floor-referenced.
Adopt when: A Mission needs cumulative caps (budget, calls, duration, egress), not just scope.
Requires: Mission-Bound Runtime Enforcement; Mission Runtime Evidence; Mission Substrate Requirements; Mission-Bound Authorization for OAuth 2.0.
Also requires, conditionally: Mission-Bound Runtime Enforcement: AuthZEN Profile (when the AuthZEN binding is the runtime wire); Mission Consent Evidence for OAuth 2.0 (when Consent Evidence is recorded).
<!-- family-status: END -->

# Relationship to the Issuance and Runtime Profiles {#relationship}

This document depends normatively on the issuance profile and the
runtime profile and is not implementable alone. It defines its
consumption bounds as members of the Mission Intent `controls` object,
using the extension seam the issuance profile provides; they are
carried on the Mission and committed by `intent_hash` exactly as any
other Intent member. Metering is performed by the runtime profile's
PDP within a documented enforcement scope; this document adds metering
semantics to the runtime profile's decision contract and changes no
issuance protocol, though it does add consent-surface obligations on
the Mission Issuer ({{consent}}).

# Conventions and Terminology {#conventions}

{::boilerplate bcp14-tagged}

Consumption bound:
: A cumulative bound on Mission activity that depletes as the Mission
  is used, as distinct from a per-action constraint that is evaluated
  independently on each action.

# Mission Substrate {#mission-substrate}

This profile is defined against the Mission model rather than against
OAuth 2.0 mechanics: it is a substrate-neutral consumer, and this
section is its consumption declaration under the rule of Mission
Substrate Requirements ({{I-D.draft-mcguinness-mission-substrate}})
that a substrate-neutral profile declare the kernel functions and
optional capabilities it consumes.

From the contextual-governance kernel it consumes the Mission
Identifier and issuer, the kernel's Mission Reference and Controller,
which key every consumption counter; and the immutable Approved
Context, of which the bounds are part as Mission Intent `controls`
members. The kernel requires no particular integrity anchors:
`intent_hash` is the OAuth binding's commitment to that approved
value, and it commits the bounds like any other Intent member
({{relationship}}).

It consumes these optional capabilities:

| Capability | Consumption | Scope of consumption |
| --- | --- | --- |
| Lifecycle-Gated Authorization | required | Inherited scope: metering is performed by the runtime profile's PDP within a documented enforcement scope ({{relationship}}), so every metered decision is already gated on the only-`active`-permits rule; this document adds counters to that gate and defines no second one |
| Structured Authority | required when a call class or an exclusive selector is drawn from the Authority Set's identifiers | Two consumers. A `call_class` value SHOULD be drawn from the `actions` identifiers of the entry's `mission_resource_access`, so the metered class maps to evaluated actions; a deployment that meters a coarser or cross-entry class defines that class's membership, and such a class is not interoperable ({{bounds}}). The `exclusive` control consumes it even then: its selectors are interpreted in the identifier space of the approved Authority Set entries and compared with each consequential action, `resource` by equality and the invoked action by membership in `actions`, per group and per Mission; selector semantics are owned by this document ({{bounds}}, {{exclusivity}}) |
| State-Observable | not consumed | Mission state is established by the runtime decision this document adds counters to, under that profile's freshness rules, not by this document ({{I-D.draft-mcguinness-mission-runtime}}) |
| Monotonic Derivation | not consumed | A lineage-keyed budget identifier correlates a root Mission and its Child Missions to one shared counter ({{aggregate-bounds}}); lineage counters are correlation, not narrowing, and this document defines no no-broader-than comparison |
| Credential-Bound | not consumed | This document defines no binding of its own: enforcement composes through the runtime profile's Mission binding establishment step ({{I-D.draft-mcguinness-mission-runtime}}) |
| Independently Verifiable | not consumed | This document defines no verification artifact of its own; metered outcomes enter the runtime evidence records and inherit their verification ({{I-D.draft-mcguinness-mission-runtime-evidence}}) |
| Portable Evidence | not consumed | This document defines no evidence artifact of its own; metered refusals and settlement are carried in the runtime evidence records through the coordinated `metering` member ({{metering-evidence}}, {{I-D.draft-mcguinness-mission-runtime-evidence}}) |
{: title="Metering profile capability consumption"}

The portability claim is capability-scoped rather than substrate-wide
for the reason the substrate's Capability Confusion consideration
states: every property this profile requires matches an explicit
capability claim and its scope, never the generic statement that a
binding supports Missions. Hosting under another binding also
requires a representation mapping: the bounds carried inside the
binding's own Approved Context and covered by its own commitment
mechanism, as the OAuth binding carries them in the Mission Intent
and commits them through `intent_hash`.

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
meters it under this document. A Mission Issuer whose deployment does
not meter a bound MUST refuse an Intent that carries it at intake.
Such an Issuer MUST NOT render the bound as an enforced limit. A
deployment that accepts the bounds into the Intent but does not meter
them presents an unenforced promise at the consent surface.

Under a multi-PDP topology ({{topology}}), a consented hard cap the
deployment renders as enforced MUST either:

- be enforced under the Exact enforcement profile, for example as
  per-PDP sub-budgets that sum to the cap; or
- be rendered with the named qualifier of the Bounded-consistency
  enforcement profile the counter operates under ({{topology}}).

Either way the Approver consents to the guarantee the deployment can
meet rather than to a hard number it cannot.

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
  ({{I-D.draft-mcguinness-mission-runtime}}); the Operation Profile
  defines the measurement so PDPs accumulate consistently. For a
  reference-typed parameter, one that carries an attachment identifier
  or URL whose referent egresses while the pointer is what
  `parameter_digest` commits, the Operation Profile MUST measure the
  dereferenced payload size, or the deployment MUST exclude such
  actions from a claimed `bytes` bound. Counting the pointer bytes
  alone understates the egress.
- `max_duration`: the PDP accumulates the duration of consequential
  activity it reserves, commits, or permits, under these rules:

  1. The PDP MUST refuse once the accumulated total would exceed the
     bound.
  2. The PDP MUST accumulate `max_duration` as the sum of per-action
     measured durations, not the union of activity intervals, so
     concurrent actions each count against the bound.
  3. For an action whose duration is not known before execution, the
     PDP MUST either reserve a bounded maximum duration or issue a
     duration lease that expires unless renewed.
  4. The PEP MUST stop the action or obtain a new permit before the
     reservation or lease is exhausted.
  5. Lease boundaries MUST carry a clock-skew margin: the PEP renews
     or stops ahead of expiry by at least the deployment's skew
     bound, so a renewal in flight does not race the expiry it
     extends.
  6. For an action that cannot be safely stopped mid-execution, lease
     exhaustion is handled as an in-flight outcome under the
     orchestration profile's `dispatched_not_committed` or `unknown`
     classes ({{I-D.draft-mcguinness-mission-orchestration}}), not by
     severing the action.
  7. After execution, the PEP MUST report the measured duration so
     the PDP can commit actual use and release any unused
     reservation.

  The Operation Profile defines how a single action's duration is
  measured so that PDPs accumulate consistently.

A per-entry `constraints` value that expresses a cumulative consumption
bound is metered the same way. When an applicable entry or the
Mission's `controls` carries such a bound, the PDP MUST meter use
against it. The PDP MUST refuse a consequential action that would
exceed it. The runtime profile's fail-closed rule stands beneath all
of this: an unmetered or unrecognized consumption bound MUST cause
refusal rather than silent pass-through
({{I-D.draft-mcguinness-mission-runtime}}).

## Exactness and Topology {#topology}

The exactness of a consumption bound depends on the decision
topology, and this profile does not overpromise. A deployment
enforces each counter under one of two named enforcement profiles:

Exact enforcement profile:
: The check and decrement are atomic against the authoritative
  balance: a single serializing PDP for the counter, a shared
  linearizable counter, or per-PDP sub-budgets that are structurally
  exact because they sum to the cap. The bound never over-consumes;
  it is a hard cap.

Bounded-consistency enforcement profile:
: Multiple or distributed PDPs (for example, Resource Server-hosted
  PDPs) share the counter without linearizable coordination, a
  distributed-counting problem. The deployment MUST publish, per
  bound class, the maximum overshoot and staleness it operates under
  (for example, a bounded reconciliation window), and the effective
  guarantee is the cap plus that published bound, not
  exact-to-the-call enforcement. The published qualifier is part of
  the bound's enforced semantic and is rendered per {{consent}}.

A deployment MUST name the enforcement profile per counter in its
Enforcement Scope Statement, and MUST NOT advertise exact consumption
enforcement it cannot meet under its chosen topology. The consistency
bound is part of the runtime enforcement scope the runtime profile
requires a deployment to document
({{I-D.draft-mcguinness-mission-runtime}}).

## Retry, Idempotency, and Reserve/Commit Posture {#retry}

For a metered permit, the PDP and PEP MUST define retry and idempotency
behavior. A retry of the same normalized action under the same
idempotency key or single-use decision identifier MUST NOT consume the
bound twice. Reuse of an idempotency key or decision identifier for a
different normalized action MUST cause refusal. For irreversible
actions and external commitments, a deployment MUST define whether
metering is reserved before execution and committed after success, or
committed before execution. It MUST NOT leave the decrement ambiguous:
a reservation settles on the evidence state ({{settlement-states}}),
never on a generic failure signal. The reserve/commit posture fixes
when consumption is charged; the evidence state fixes how the charge
settles.

# Exclusivity and Separation of Duty {#exclusivity}

The `exclusive` control ({{bounds}}) is not a consumption bound: it
is a stateful separation-of-duty rule enforced with the same
machinery. Within an exclusivity group, the first permitted
consequential action matching a selector latches the group to that
selector, atomically with the permit; for the Mission's remaining
lifetime the PDP MUST refuse a consequential action matching any
other selector of the same group. The latch is per group and per
Mission and is PDP-side operational state like a consumption counter
({{metering}}).

The latch tracks execution, not permit issuance: a permit whose
action is affirmatively not executed never combined the group's
authority, so when Execution Evidence reports that outcome within the
strongly consistent latch domain the PDP releases the latch,
restoring monotonic narrowing rather than breaking it. Absent that
affirmative non-execution the latch does not unlatch: narrowing by
exercise is monotonic, like every other narrowing in the family.

The latch is exempt from the Bounded-consistency enforcement profile
of {{topology}}. A counter degrades gracefully under a per-PDP
sub-budget or a reconciliation window; a separation-of-duty rule violated once is violated
permanently, and two PDPs can latch the same group to opposite
selectors within the window. Therefore:

- An exclusivity group MUST be enforced under the Exact enforcement
  profile of {{topology}}, in a single strongly consistent
  per-Mission latch domain (the runtime profile's
  Mission-sharding guidance makes the Mission the consistency unit,
  {{I-D.draft-mcguinness-mission-runtime}}).
- The Bounded-consistency enforcement profile MUST NOT be applied to
  `exclusive`.
- The deployment MUST name the latch domain in its Enforcement Scope
  Statement.

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
the Mission's `subject`, by the approved `client_id`, or by a
lineage-keyed budget identifier shared by a root Mission and every
Child Mission derived from it, so a fleet operator can cap what an
agent identity, a Subject, or a Mission's whole derivation lineage
consumes in total rather than per task. The counter semantics,
reserve/commit postures, and refusal behavior are unchanged; only the
key differs.

A lineage-keyed budget identifier and its authoritative shared counter
are the only mechanism this document defines for a lineage-wide
aggregate consumption bound: they meter across every Mission a
derivation lineage contains, not within one Mission alone. A Child
Mission's own derivation counter is independent of its parent's and
bounds nothing beyond that Child Mission itself
({{I-D.draft-mcguinness-oauth-mission-child-delegation}}); absent a
deployed lineage-keyed counter, no per-Mission counter, however many
Missions in a lineage carry one, adds up to an aggregate bound on the
lineage.
This document is experimental ({{optional-status}}), so a deployment
running only the stable issuance and runtime profiles has no
lineage-wide aggregate bound in force at all. A deployment MUST NOT
render, in an Enforcement Scope Statement or at any consent surface,
a lineage-wide or subtree aggregate bound as in force unless a
lineage-keyed budget identifier and shared counter meeting this
section's requirements are actually deployed and metered.

An aggregate bound is deployment policy: it is carried on no single
Mission Intent, is committed by no `intent_hash`, and is disclosed
through the deployment's Enforcement Scope Statement rather than the
approval event. A refusal under an aggregate bound is carried as
`quota_exceeded`, and its Decision Evidence `metering` entry records
the aggregate key class in `counter_scope` and the counter in
`counter_id` ({{metering-evidence}}).

Aggregate keying crosses the family's per-Mission consistency
domains: a subject-keyed or lineage-keyed counter is shared by every
Mission the key spans, so it cannot be sharded by Mission Identifier
and is provisioned as its own consistency domain
({{I-D.draft-mcguinness-mission-runtime}}).

# Metering Evidence {#metering-evidence}

A metered decision is auditable only where the evidence exposes the
counter state the decision asserted. This document defines one
coordinated evidence member, `metering`, carried in Decision
Evidence and Execution Evidence under the runtime evidence
companion's extension conventions
({{I-D.draft-mcguinness-mission-runtime-evidence}}).

`metering`:
: An array of one or more entries, one per bound the evaluation
  metered. In a deployment claiming this profile, a Decision
  Evidence record emitted for a metered evaluation, permit or
  refusal, MUST carry it, and an Execution Evidence record MUST
  carry it where the committed quantity is conveyed by `consumed`
  ({{settlement-contract}}). Each entry has the members:

  `bound`:
  : REQUIRED. A string. The metered bound: a `controls` member name
    ({{bounds}}) or the applicable per-entry constraint name
    ({{metering}}).

  `counter_scope`:
  : REQUIRED. A string. The counter's key class: `mission` for the
    Mission-keyed bounds of this document, or `subject`, `client`,
    or `lineage` for an aggregate bound ({{aggregate-bounds}}).

  `counter_id`:
  : REQUIRED. A string. A stable identifier of the counter, the same
    value on every record the counter's decisions and settlements
    produce. It is committed or pseudonymous: a sensitive key (a
    subject or lineage identifier the record does not otherwise
    carry) appears only as a commitment, for example a `sha-256:`
    digest of the deployment's counter key, never raw.

  `requested`:
  : REQUIRED in Decision Evidence, absent otherwise. The quantity
    the evaluation sought to consume, in the bound's native unit
    shape: `{amount, currency}` for `max_budget`, an integer count
    for `max_calls`, an ISO 8601 duration for `max_duration`, and
    an object of `bytes` and `messages` for `max_egress_volume`.

  `reserved`:
  : CONDITIONAL. The same shape. The quantity reserved; REQUIRED in
    the Decision Evidence of a permitted action under a reserving
    posture ({{retry}}).

  `remaining`:
  : REQUIRED in Decision Evidence, absent otherwise. The same shape.
    The counter's remaining quantity after the decision; after a
    refusal, the unchanged remaining quantity the request exceeded.

  `consumed`:
  : CONDITIONAL. The same shape. Execution Evidence only: the actual
    quantity for the PDP to commit, per the bound-class conveyance
    rules of {{settlement-contract}}.

  `settlement_state`:
  : CONDITIONAL. A string. Decision Evidence of a permitted metered
    action only: the decision-time posture, `reserved` or
    `committed` ({{retry}}). The terminal disposition, commit,
    release, hold, or conflict, is applied under
    {{settlement-states}} and joined through `evaluation_id`; it is
    not restated in the immutable record.

The member turns a metered refusal into a checkable claim rather
than an assertion: the refusal's entry shows `requested` exceeding
`remaining` on a named counter, and the counter's accounting history
is the join of the entries sharing its `counter_id`. A lineage-wide
refusal under an aggregate bound reads:

~~~ json
{
  "metering": [
    {
      "bound": "max_budget",
      "counter_scope": "lineage",
      "counter_id":
        "sha-256:t7RnQ2xV9kM4wB1sJ6eL3yP8cA5fH0dZu2gN7bXq4Ss",
      "requested": { "amount": "25.00", "currency": "USD" },
      "remaining": { "amount": "10.00", "currency": "USD" }
    }
  ]
}
~~~

# AuthZEN Binding {#authzen-binding}

Where the runtime deployment uses the AuthZEN binding
({{I-D.draft-mcguinness-mission-authzen}}), this section defines the
wire representation of metering. It defines no new metering semantics
and no new constraint. The requirements of this section and
{{settlement-exchange}} apply only to a deployment that adopts the
AuthZEN binding under that profile's conformance; for every other
deployment the AuthZEN profile remains an informative reference.

When metering a bound would exceed it, the PDP MUST deny with
`quota_exceeded` ({{I-D.draft-mcguinness-mission-authzen}}) instead of
returning a permit. The PDP MUST record `quota_exceeded` as the
`denial_reason` in Decision Evidence.

Whether a metered permit is reserved at decision time and committed on
settlement, or committed at decision time, follows the deployment's
documented reserve/commit posture ({{retry}}); this binding fixes
neither. In a batch (boxcar) evaluation, consumption metering applies
per item in request order. The exactness of the bound is the
consistency bound of {{topology}}, not a property of this wire
binding.

## Settlement Exchange {#settlement-exchange}

The metering rules require the PEP to signal actual use so the PDP
commits consumption and releases any reservation. In the AuthZEN
binding, delivery of the Execution Evidence Object
({{I-D.draft-mcguinness-mission-runtime-evidence}}) to the PDP is
that commit-or-release signal: on receipt the PDP settles the linked
action's consumption per {{settlement-states}}, keyed to the
Execution Evidence's `evaluation_id`.

### Settlement Submission Contract {#settlement-contract}

The settlement transport is the runtime evidence companion's
Execution Evidence delivery contract, profiled rather than a second
channel: exactly one Execution Evidence Object exists per final
disposition of a permit, delivery is at-least-once, and the receiver
deduplicates on `execution_id`
({{I-D.draft-mcguinness-mission-runtime-evidence}}). This profile
adds:

- **Intake and audience.** The deployment MUST name the settlement
  intake, the PDP evidence-submission path or the event or evidence
  API it profiles, in its Enforcement Scope Statement. The intake
  MUST feed the consistency domain that holds the counter
  ({{topology}}, {{aggregate-bounds}}).
- **Authentication.** The intake MUST accept a settlement only as an
  Execution Evidence Object in the evidence companion's integrity
  envelope, verified against the emitter key, scope, and `audience`
  binding claimed in the Enforcement Scope Statement
  ({{I-D.draft-mcguinness-mission-runtime-evidence}}).
- **Acknowledgement.** The intake MUST acknowledge a settlement only
  after the commit or release is durably applied; an unacknowledged
  delivery is retried under the at-least-once contract.
- **Duplicate delivery.** A redelivered record, the same
  `execution_id` with the same settlement-relevant content, MUST be
  acknowledged without applying the settlement again: the commit is
  idempotent on `evaluation_id`, so a redelivered settlement neither
  double-commits the consumption nor double-releases the
  reservation.
- **Conflicting redelivery.** A record naming an `evaluation_id`
  whose settlement is applied but differing in settlement-relevant
  content (`outcome`, `measured_duration`, or a `metering` entry),
  or a second `execution_id` for the same `evaluation_id`, MUST fail
  closed: the applied settlement is unchanged, the conflicting
  record is retained as evidence, and the conflict is surfaced on
  the deployment's audit and alarm path.

The committed quantity is conveyed per bound class:

- `max_calls`: intrinsic. The class counter is consumed at decision
  time, one consequential call per `evaluation_id`; settlement
  confirms the disposition only.
- `max_duration`: the Execution Evidence `measured_duration` member.
- `max_budget`: the Execution Evidence `metering` entry's `consumed`
  member, as `{amount, currency}` ({{metering-evidence}}).
- `max_egress_volume`: the Execution Evidence `metering` entry's
  `consumed` member, as `bytes` and `messages`, measured per the
  Operation Profile rules of {{metering}}, including the
  dereferenced-payload rule.

Where an action class defines no actual measure for a bound, the
Operation Profile MUST state that the reserved quantity commits.

### Settlement by Evidence State {#settlement-states}

A reservation settles on the evidence state, never on a generic
failure signal:

- **Affirmative non-execution** (`outcome` `suppressed`): the action
  was permitted but affirmatively not attempted. The PDP releases
  the reservation and returns the quantity to the counter. Within
  the strongly consistent latch domain this same state releases an
  exclusivity latch ({{exclusivity}}).
- **Completed execution** (`outcome` `completed`): the PDP commits
  the conveyed actual quantity, or the reserved quantity where the
  class defines no actual measure, and releases any reserved excess.
- **Attempted but failed** (`outcome` `failed`): not affirmative
  non-execution, because the attempt may have consumed real
  resources. The Operation Profile MUST define the commit-or-refund
  rule per metered action class; absent a defined rule the
  reservation remains charged and reconciles as an unknown outcome.
- **Unknown outcome** (no evidence within the reservation lease): a
  reservation MUST carry a bounded lease so a crashed or abandoned
  reservation does not consume the budget permanently. On lease
  expiry without settlement the PDP reconciles the reservation
  through the runtime profile's orphaned-evidence process
  ({{I-D.draft-mcguinness-mission-runtime}}). For an idempotent or
  reversible action class, expiry releases the reservation and
  returns the budget; for a non-idempotent action class, expiry
  forces reconciliation or human review rather than release. An
  unsettled reservation remains charged against the bound until it
  is reconciled, and is released only on affirmative evidence of
  non-execution; timeout alone never releases a reservation for a
  non-idempotent action class.
- **Conflicting settlement**: fail closed per
  {{settlement-contract}}. The applied settlement is unchanged; the
  conflict is audited, never adjudicated by the intake.

A containment overlay's contain transition
({{I-D.draft-mcguinness-oauth-mission-containment}}) is not settlement
evidence: an open reservation or duration lease still settles under
the evidence states above, unaffected by contain, and contain narrows
only forward draw, a new reservation or a lease renewal, through the
ordinary permit check against the narrowed Effective Authority Set.

The operational consequence: a lossy evidence channel accumulates
reservations against `max_budget` and `max_calls` until the Mission
starves on `quota_exceeded`, a self-inflicted denial of service. A
deployment SHOULD run orphaned-evidence reconciliation on a published
cadence sized to its evidence-channel loss rate; the reconciliation
window it publishes is how long leaked budget stays leaked.

### Duration-Lease Renewal {#lease-renewal}

For a duration-metered action the PEP reports the measured duration in
the Execution Evidence `measured_duration` member, and the PDP commits
that duration against `max_duration`. A duration-lease renewal is a new
re-evaluation request that carries the prior permit's `evaluation_id`
in `context.prior_evaluation_id`, so the PDP continues the same metered
activity rather than opening a new reservation.

The PDP MUST verify that the renewal's Mission, subject, action, and
audience match the evaluation named by `prior_evaluation_id`. A
deployment sizes lease
intervals to amortize renewals: an interval materially shorter than
the action class's staleness bound adds decision load without
tightening the revocation cutoff. This exchange requires
one request member and one evidence member:

`context.prior_evaluation_id`:
: OPTIONAL. A string. Present on a duration-lease renewal request,
  carrying the `evaluation_id` of the permit being renewed. Absent on
  an initial request.

`measured_duration` (Execution Evidence):
: REQUIRED for a duration-metered action, otherwise absent. A string
  containing an ISO 8601 duration (the `duration` rule in Appendix A of
  {{RFC3339}}): the PEP's measured duration for the executed action.

A renewal repeats the evaluation-request envelope for the same
activity and adds `context.prior_evaluation_id`. Here a long-running,
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
    "prior_evaluation_id": "dec_0Rt5nB8xW2qK7mJ4vS1pL9eYc"
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
- emit the `metering` evidence member on the records
  {{metering-evidence}} requires;
- publish its consistency bound under a multi-PDP topology
  ({{topology}});
- define and document its retry, idempotency, and reserve/commit
  posture ({{retry}}); and
- where the AuthZEN binding is in use, implement the settlement
  exchange of {{settlement-exchange}}.

A Mission Issuer in a deployment claiming this profile MUST carry the
consented bounds on the Mission record committed by `intent_hash`. It
MUST render them at the approval event per {{consent}}.

# Security Considerations {#security-considerations}

Consumption bounds limit the blast radius of a compromised or runaway
agent in a dimension authority narrowing cannot: a Mission whose every
action is individually authorized can still be drained by volume.
Their enforcement, however, is only as good as the metering:

- **Unenforced bounds are consent theater.** A bound rendered at
  approval but not metered anywhere misleads the Approver about the
  Mission's exposure. The consent-integrity rule ({{consent}}) exists
  for this: it forbids a deployment that cannot meter a bound from
  rendering it as enforced.
- **Distributed undercounting.** Under a multi-PDP topology, an
  attacker who can spread actions across decision points exploits the
  consistency gap. The published consistency bound ({{topology}}) is
  the honest statement of that exposure; per-PDP sub-budgets bound it
  structurally.
- **Settlement honesty.** The PDP commits what the PEP reports.
  Execution Evidence is integrity-protected and signed by the PEP
  ({{I-D.draft-mcguinness-mission-runtime-evidence}}); a compromised
  PEP can under-report duration or spend, which is within the runtime
  profile's trusted-base assumptions for PEPs.
- **Lease abandonment.** An agent that stops renewing a duration lease
  and keeps acting is stopped by the PEP, which {{metering}} requires
  to stop the action or obtain a new permit before the lease is
  exhausted.
- **Reservation starvation.** An attacker who opens reservations and
  never settles them can consume a budget with no executed action,
  denying the Mission its remaining authority. The bounded reservation
  lease ({{settlement-exchange}}) caps this: an unsettled reservation is
  reconciled on lease expiry rather than held indefinitely, and the
  idempotent-release path returns the budget.
- **Latch burning.** Because the first matching action latches an
  exclusivity group, an injected agent can try to burn a group by
  driving the side it wants foreclosed, denying the Mission the other
  side. Releasing the latch on affirmative non-execution
  ({{exclusivity}}) keeps an unexecuted attempt from foreclosing the
  group permanently.

# Privacy Considerations {#privacy-considerations}

Metering state (spend, call counts, activity durations) is a
fine-grained record of Mission activity over time. It SHOULD be
retained under the same access controls and retention windows as
runtime enforcement evidence
({{I-D.draft-mcguinness-mission-runtime}}), and disclosed in decision
responses only as refusals, not as remaining-balance oracles. The
`metering` evidence member records `remaining` inside those
access-controlled records ({{metering-evidence}}), never in a
decision response.

The refusal boundary is itself a coarse balance oracle: the point at
which a bound flips from permit to refusal reveals the remaining
margin. A deployment SHOULD bound this probing with the AuthZEN
profile's denial-oracle controls
({{I-D.draft-mcguinness-mission-authzen}}), per-Mission rate-limiting
of access requests and evidence-logging of request provenance, so a
compromised agent mapping a balance by repeated probes is visible to
the humans adjudicating it.

# IANA Considerations {#iana}

This document has no IANA actions. `max_budget`, `max_calls`,
`max_duration`, `max_egress_volume`, and `exclusive` are Mission
Intent `controls`
members defined by this
profile under the issuance profile's controls extension seam;
`context.prior_evaluation_id` is AuthZEN extension data carried per
the AuthZEN profile's conventions
({{I-D.draft-mcguinness-mission-authzen}}); `measured_duration` and
`metering` are coordinated evidence members under the runtime
evidence companion's extension conventions
({{I-D.draft-mcguinness-mission-runtime-evidence}}).

--- back

# Document History {#document-history}

\[\[ To be removed from the final specification ]]

- One informative cross-reference in Settlement by Evidence State
  ({{settlement-states}}): a containment overlay's contain transition
  is not settlement evidence. An open reservation or duration lease
  still settles unchanged under the existing evidence-state rules, and
  contain narrows only forward draw, a new reservation or a lease
  renewal, through the ordinary permit check against the narrowed
  Effective Authority Set. No new settlement state (#670).

# Acknowledgments
{:numbered="false"}

This document is part of the Mission-Bound Authorization work and
defines its experimental consumption-metering layer.
