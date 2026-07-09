---
title: "Mission Orchestration and Unwinding"
abbrev: "Mission Orchestration"
category: exp

docname: draft-mcguinness-mission-orchestration-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
keyword:
 - oauth
 - mission
 - agent
 - orchestration
 - compensation
venue:
  github: "mcguinness/mission-bound-authorization"
  latest: "https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-orchestration.html"

author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com

normative:
  RFC3339:
  RFC7515:
  RFC8259:
  RFC8785:
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
  I-D.draft-mcguinness-oauth-mission-status:
    title: "Mission Status and Lifecycle for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-status.html
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
  I-D.draft-mcguinness-mission-authzen:
    title: "Mission-Bound Runtime Enforcement: AuthZEN Profile"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-authzen.html
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
  I-D.draft-mcguinness-oauth-mission-expansion:
    title: "Mission Expansion for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-expansion.html
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

--- abstract

Mission runtime enforcement can refuse the next consequential action,
but Mission termination can occur while an agent workflow is already in
flight. This document defines an optional orchestration profile for
Mission-governed workflows. It classifies actions by reversibility,
requires an unwind plan before execution, defines behavior when a
Mission is revoked, expired, suspended, completed, or superseded, and
specifies Orchestration Evidence for pause, cancel, compensation, and
human-review decisions. The profile turns Mission termination from a
simple access-control denial into governed handling of execution state,
with compensation authorized only by resource policy or a separate
active Mission, never the terminated Mission.

--- middle

# Introduction

Mission-Bound Authorization for OAuth 2.0
{{I-D.draft-mcguinness-oauth-mission}} (the "issuance profile") gives a
task an approved authority and lifecycle. The runtime profile
{{I-D.draft-mcguinness-mission-runtime}} checks each
consequential action before it executes. These are necessary but not
complete for long-running workflows. A Mission can terminate after some
steps have completed and before others run. Some completed steps can be
compensated. Some cannot. Some in-flight requests can be canceled. Some
must be escalated to a human.

This document defines the orchestration layer that handles those cases.
Before governed execution begins, the orchestrator records an unwind
plan for each consequential step. When Mission state becomes non-active
or cannot be established, the orchestrator stops new governed work and
executes the plan: cancel, compensate, suppress, pause, or hand off to
human review.

The boundary with the harness profile
({{I-D.draft-mcguinness-mission-harness}}) is the question each
answers. The harness answers "may this unit of work continue." This
document answers "how is in-flight state unwound once continuation is
stopped." The runtime profile still gates each action. The checks
compose; none replaces the others ({{relationship}}).

This is a newer, experimental profile and is not required by any
Mission Assurance Level
({{I-D.draft-mcguinness-mission-architecture}}).

# Scope

This document is **experimental**: adopt it for evaluation, not as a
stable interface. Safe unwinding of in-flight agent work is the least
settled layer of the suite, and this profile is expected to change with
implementation experience.

This document defines:

- action reversibility classes ({{reversibility}});
- unwind plans ({{unwind-plan}});
- behavior on Mission state changes ({{state-change-behavior}});
- in-flight request handling ({{in-flight}});
- compensation and human review evidence ({{orchestration-evidence}});
  and
- conformance for a Mission-aware orchestrator ({{conformance}}).

This document does not define a workflow language, a compensation API,
or a replacement for runtime PEP enforcement. Its object shapes (the
unwind plan and the evidence record) bind what a deployment records and
proves, not how an orchestrator is internally structured.

## Orchestration Profile {#orchestration-profile}

A deployment claiming this profile MUST publish or otherwise make
available an orchestration profile for governed workflows. The profile
MUST define:

- workflow classes in scope;
- action-class mapping for workflow steps;
- the source of Mission state used by the orchestrator;
- a staleness bound per action class, calibrated against the runtime
  profile's non-normative freshness table
  ({{I-D.draft-mcguinness-mission-runtime}});
- minimum reversibility class per operation;
- permitted compensation authorities;
- review queues or escalation targets; and
- evidence retention.

The orchestration profile is deployment documentation. It is not an
OAuth Authorization Server metadata extension and does not alter token
format.

# Conventions and Terminology {#conventions}

{::boilerplate bcp14-tagged}

This document uses the terms Mission, Mission state, and consequential
action from {{I-D.draft-mcguinness-oauth-mission}}; and PEP, PDP, and
runtime enforcement evidence from
{{I-D.draft-mcguinness-mission-runtime}}. Where a deployment
uses the AuthZEN profile ({{I-D.draft-mcguinness-mission-authzen}}),
its Decision Evidence and Execution Evidence objects are examples of
the runtime enforcement evidence records this document links.

Orchestrator:
: The component that schedules, sequences, retries, or coordinates
  governed actions in a Mission.

Unwind plan:
: The per-step plan describing what the orchestrator does if Mission
  authority ends or cannot be established before or during that step.

Compensation:
: A deployment-defined action intended to offset or reverse a prior
  action's effect. Compensation is not guaranteed reversal.

Safe point:
: A workflow point at which the orchestrator can stop without starting
  another consequential action and with all prior outcomes recorded.

# Mission Substrate {#mission-substrate}

This profile is defined against the Mission model rather than against
OAuth 2.0 mechanics. It consumes these substrate primitives: the
Mission identifier; the lifecycle state space with its
only-`active`-permits rule; the runtime enforcement evidence its
records link; the integrity-anchor envelope, used for
`unwind_plan_hash`; and the substrate's Mission state, against which
a compensation authority basis resolves ({{compensation-authority}}):
a `separate_mission` basis requires a Mission that is `active` under
the binding in use, and a `resource_policy` basis lies outside Mission
authority entirely. The issuance profile
{{I-D.draft-mcguinness-oauth-mission}} is this version's normative
substrate; another substrate that provides the same primitives can
host this profile unchanged.

# Reversibility Classes {#reversibility}

Each consequential step in a governed workflow MUST be assigned one of
these reversibility classes before execution:

`read_only`:
: The step observes data and has no external side effect. Suppression
  prevents future exposure, but prior disclosure cannot be undone.

`reversible_write`:
: The step changes state and has a known compensation action that can
  restore or materially offset the change.

`irreversible_action`:
: The step cannot be reliably undone once completed.

`external_commitment`:
: The step commits to an external party, sends communication, starts a
  payment, signs, files, orders, or otherwise creates an external
  reliance interest.

`privileged_administration`:
: The step changes policy, access, configuration, or security posture.

`irreversible_action`, `external_commitment`, and
`privileged_administration` are the identically-named action classes of
{{I-D.draft-mcguinness-mission-runtime}} (Section
"Action classification"). A step's reversibility class MUST be at least
the minimum this table maps from the runtime action class the runtime
profile assigns the same operation:

| Runtime action class | Minimum reversibility class |
|---|---|
| Non-consequential | `read_only` |
| Consequential read | `read_only` |
| Consequential write | `reversible_write` |
| Irreversible action | `irreversible_action` |
| External commitment | `external_commitment` |
| Privileged administration | `privileged_administration` |

`read_only` and `reversible_write` are a reversibility refinement this
profile adds that the runtime classification does not separately track.

The class MAY be raised by Resource policy or operation profile. As
with the runtime classification floor
({{I-D.draft-mcguinness-mission-runtime}}), it MUST NOT be lowered
by the orchestrator at runtime to avoid review or compensation
requirements.

## Action-Class Source {#action-class-source}

The orchestrator MUST derive reversibility class from a trusted source:

- Resource Server runtime profile;
- operation profile;
- workflow definition reviewed under deployment policy; or
- Resource policy response.

An agent plan, model output, or tool description MAY suggest a class
but MUST NOT be the sole authority for lowering class. If sources
conflict, the orchestrator MUST use the class that is at least the
minimum the mapping table of {{reversibility}} requires for the
operation's runtime action class.

# Unwind Plan {#unwind-plan}

Before dispatching a consequential step, the orchestrator MUST have an
unwind plan. The plan is deployment documentation committed for audit
({{unwind-plan-integrity}}), not a wire format; the members below are
the information it MUST record, in whatever representation the
deployment commits. The plan has these members:

`step_id`:
: REQUIRED. A string identifying the workflow step.

`mission_id`:
: REQUIRED. The Mission governing the step.

`reversibility`:
: REQUIRED. One of the classes in {{reversibility}}.

`pre_start_behavior`:
: REQUIRED. Behavior when Mission state is non-active before the step
  starts. One of `suppress`, `pause`, `cancel_workflow`, or
  `human_review`.

`in_flight_behavior`:
: REQUIRED. Behavior when Mission state changes while the step is in
  flight. One of `cancel_if_possible`, `wait_then_review`,
  `continue_to_safe_point`, or `human_review`.

`post_completion_behavior`:
: REQUIRED for `reversible_write`, `irreversible_action`,
  `external_commitment`, and `privileged_administration`. One of
  `compensate`, `record_only`, or `human_review`.

`compensation_action`:
: REQUIRED when `post_completion_behavior` is `compensate`. A
  deployment-defined action reference.

`review_queue`:
: REQUIRED when any behavior is `human_review`. A deployment-defined
  queue or escalation target.

`safe_point`:
: OPTIONAL. A deployment-defined workflow point to which
  `continue_to_safe_point` may proceed.

`evidence_policy`:
: OPTIONAL. Deployment-defined instructions for linking runtime
  enforcement evidence ({{I-D.draft-mcguinness-mission-runtime}}),
  Harness Evidence, and Orchestration Evidence. Its members, including
  any retention token such as the
  example's `mission_audit_horizon`, are deployment-defined; the
  retention horizon aligns with the runtime profile's record-retention
  guidance ({{I-D.draft-mcguinness-mission-runtime}}).

The unwind plan does not authorize compensation by itself. A
compensation action that is consequential MUST itself be authorized
under one of the compensation authority bases ({{compensation-authority}}):
resource policy or a separate active Mission, never the terminated
Mission.

## Unwind Plan Integrity {#unwind-plan-integrity}

The `unwind_plan_hash` over the step's unwind plan MUST be committed
at or before the step's dispatch: a hash first recorded after a
trigger proves later alteration, not that the plan existed when the
step was dispatched. The orchestrator MUST commit it in an
Orchestration Evidence record emitted at dispatch
({{orchestration-evidence}}). As an alternative, a deployment MAY
commit it instead as a coordinated member of the step's Decision
Evidence, through the AuthZEN profile's coordinated-extension seam
({{I-D.draft-mcguinness-mission-authzen}}); the step's first
Orchestration Evidence record then repeats the committed value. The
hash is computed with the integrity-anchor envelope of the issuance
profile ({{I-D.draft-mcguinness-oauth-mission}}) under a new `typ`
value `mission-unwind-plan`, where `value` is the unwind plan object.
This lets an auditor verify that the plan a step ran under existed at
dispatch and detect any later alteration.

Every unwind-plan member MUST derive from a trusted source. The
compensation action, review queue, and safe point, like the
reversibility class ({{action-class-source}}), MUST derive from a
reviewed workflow definition or operation profile. Model output MUST
NOT define them.

A model-proposed plan is not excluded; it is unadopted. A deployment
MAY admit one through its review surface, a human review or a
deterministic validation against a reviewed operation profile, which
adopts the proposal into the deployment's committed documentation
before dispatch; the adopted plan is then a reviewed definition, and
the Orchestration Evidence that commits its hash records the
admission. What the rule excludes is model output defining an
unwind-plan member with nothing between proposal and dispatch.

## Worked Unwind Plan {#worked-unwind-plan}

~~~ json
{
  "step_id": "post_journal_entry",
  "mission_id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
  "reversibility": "irreversible_action",
  "pre_start_behavior": "human_review",
  "in_flight_behavior": "wait_then_review",
  "post_completion_behavior": "human_review",
  "review_queue": "finance-control-review",
  "evidence_policy": {
    "link_runtime_evidence": true,
    "retain_for": "mission_audit_horizon"
  }
}
~~~

Its `unwind_plan_hash` is computed with the integrity-anchor envelope
({{unwind-plan-integrity}}): `typ` `mission-unwind-plan`, `iss`
`https://as.example.com`, and this plan as the envelope `value`. The
canonical-bytes block is the exact JCS {{RFC8785}} output, a single
line of UTF-8 with no whitespace, shown wrapped only for layout;
remove the layout line breaks, adding no characters, to recover the
canonical form.

Canonical bytes of the envelope:

~~~ text
{"iss":"https://as.example.com","typ":"mission-unwind-plan","value
":{"evidence_policy":{"link_runtime_evidence":true,"retain_for":"m
ission_audit_horizon"},"in_flight_behavior":"wait_then_review","mi
ssion_id":"msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-","post_completion_
behavior":"human_review","pre_start_behavior":"human_review","reve
rsibility":"irreversible_action","review_queue":"finance-control-r
eview","step_id":"post_journal_entry"}}
~~~

~~~ text
unwind_plan_hash =
  sha-256:jKxM47ygRiTXYVfKjrVE34VZx8nsxg1I9OPPeHnO-_c
~~~

The evidence example of {{orchestration-evidence}} carries this value.

# State-Change Behavior {#state-change-behavior}

When an orchestrator learns that a Mission is no longer `active`, or
cannot establish active state within the deployment's staleness bound,
it MUST:

1. stop dispatching new governed steps for that Mission;
2. suppress or pause queued work;
3. evaluate every in-flight step under {{in-flight}};
4. execute or schedule post-completion behavior for completed steps
   whose unwind plan requires it; and
5. emit Orchestration Evidence under {{orchestration-evidence}}.

The two triggers differ in what they permit. An established
non-active state runs the full sequence. Staleness alone, an active
state that cannot be established within the bound, performs items 1,
2, 3, and 5 and MUST NOT execute post-completion behavior (item 4):
compensation is itself consequential work, and unwinding work nobody
stopped is not fail-closed. Post-completion behavior runs only on an
established non-active state.

The states `revoked` and `expired` ({{I-D.draft-mcguinness-oauth-mission}}),
`suspended` and `completed` ({{I-D.draft-mcguinness-oauth-mission-status}}),
and `superseded` ({{I-D.draft-mcguinness-oauth-mission-expansion}}) are
all non-active. The orchestrator needs none of those companion profiles
to be conformant: per the issuance profile's forward-compatibility rule
it treats any state other than `active` as non-active. A deployment MAY
define different operator handling for each state, but none allows new
governed execution without a fresh authority path. In particular, a
`superseded` Mission's continued work SHOULD proceed under the successor
Mission through a fresh derivation from the successor's grant, not by
rebinding the predecessor's authority; the successor carries its own
Authority Set ({{I-D.draft-mcguinness-oauth-mission-expansion}}).

## Trigger Sources {#trigger-sources}

An orchestrator can learn of Mission state change from:

- Mission Status polling ({{I-D.draft-mcguinness-oauth-mission-status}});
- Mission lifecycle signals
  ({{I-D.draft-mcguinness-oauth-mission-signals}});
- a runtime PDP denial
  ({{I-D.draft-mcguinness-mission-runtime}});
- a harness stop decision
  ({{I-D.draft-mcguinness-mission-harness}});
- operator action; or
- a deployment-specific governance event.

The orchestrator MUST record the trigger source in Orchestration
Evidence. If two trigger sources disagree, the orchestrator MUST use
the safer state until it can reconcile. For example, a signed `revoked`
signal overrides a stale local `active` cache.

# In-Flight Requests {#in-flight}

An in-flight step moves through these outcome classes:

~~~
 not_dispatched --> dispatched_not_committed --> committed
                              |
                              +-------------------> unknown
~~~

For in-flight requests, the orchestrator MUST distinguish:

`not_dispatched`:
: The step has not reached the PEP or external system. The orchestrator
  MUST suppress or pause it.

`dispatched_not_committed`:
: The request was sent, but the deployment can still cancel or prevent
  commit. The orchestrator MUST attempt cancellation when the unwind
  plan says `cancel_if_possible`.

`committed`:
: The action's effect occurred or the deployment cannot prove it did
  not occur. The orchestrator MUST apply post-completion behavior.

`unknown`:
: The orchestrator cannot determine whether the action committed. The
  orchestrator MUST treat the outcome as requiring human review unless
  deployment policy defines a stricter default.

For irreversible actions, external commitments, and privileged
administration, an `unknown` outcome MUST NOT be treated as success or
as harmless suppression.

## Cancellation Attempt {#cancellation}

When the unwind plan requires cancellation, the orchestrator MUST:

1. invoke the deployment-defined cancellation mechanism, if any;
2. record whether cancellation was accepted, rejected, unavailable, or
   unknown;
3. continue to classify the outcome as `unknown` until it has evidence
   that the action did not commit; and
4. emit Orchestration Evidence.

Cancellation acceptance by an upstream queue is not proof that an
external action did not occur.

# Compensation {#compensation}

Compensation is governed work. After a Mission becomes non-active, a
compensation action MUST NOT be performed by presenting that Mission's
authority. It proceeds only under one of the bases of
{{compensation-authority}}: `resource_policy` or `separate_mission`.
If neither applies, the orchestrator MUST escalate to human review.

The compensation record is an Orchestration Evidence record
({{orchestration-evidence}}) with `orchestration_decision` set to
`compensate`. In that case its `authority_basis`, `linked_evidence`,
`compensation_action`, and `compensation_outcome` members are REQUIRED.
Through those members the record links:

- the original Mission (the record's `mission`);
- the original runtime enforcement evidence when available
  (`linked_evidence`);
- the state transition that triggered compensation (`mission_state`
  and `reason`);
- the compensation action (`compensation_action`);
- the authority basis for compensation (`authority_basis`); and
- the outcome (`compensation_outcome`).

## Compensation Authority Basis {#compensation-authority}

Compensation after a non-active transition MUST NOT proceed by
presenting the terminated Mission's authority. The authority basis for
compensation is one of:

`resource_policy`:
: The action is authorized by the resource's or the PDP's own policy,
  independent of Mission-bound authority. The orchestrator presents no
  Mission-bound credential; the resource permits the rollback under its
  own local policy.

`separate_mission`:
: A narrow, pre-provisioned remedial Mission that is `active`
  authorizes the compensation. It is a distinct Mission, not the
  terminated one, and it carries its own Authority Set.

An operator may gate either basis, but operator approval is not itself
an authority basis: it does not create authority a PEP would enforce
over a terminated Mission. If neither basis applies, the orchestrator
MUST NOT compensate and MUST record a `human_review` decision.

## Unwind Ordering and Partial Failure {#unwind-ordering}

When compensation spans dependent steps, the orchestrator MUST run the
compensations in reverse dependency order unless the unwind plan states
another order.

Compensation can complete for some steps and not others. When it does
not complete for every step that required it, the workflow's terminal
state is `compensation_incomplete`. The orchestrator MUST enumerate the
steps whose compensation outcome is unknown or failed in Orchestration
Evidence, so an auditor can see which effects were not offset.

# Human Review {#human-review}

When the orchestrator routes a step to human review (`human_review`),
the review concludes with one of three outcomes:

`approve`:
: The reviewer permits the work to continue.

`reject`:
: The reviewer refuses the work.

`expire`:
: The item reached its parked maximum age without a review decision.

A parked item MUST carry a deployment maximum age. The orchestrator
MUST record the outcome and its authority basis in Orchestration
Evidence.

# Orchestration Evidence {#orchestration-evidence}

An Orchestration Evidence record is a JSON object {{RFC8259}} with these
members:

`event_id`:
: REQUIRED. A unique identifier.

`mission`:
: REQUIRED. The Mission whose orchestration state changed, as the
  nested `mission` object (`id`, `issuer`, and, when known,
  `authority_hash`), the same shape as the `mission` claim of
  {{I-D.draft-mcguinness-oauth-mission}} and the Harness Evidence object
  ({{I-D.draft-mcguinness-mission-harness}}).

`workflow_id`:
: REQUIRED. The workflow or task graph identifier.

`step_id`:
: OPTIONAL. The step affected.

`mission_state`:
: REQUIRED. The state observed.

`state_source`:
: REQUIRED. A value from the shared `state_source` value space defined
  by the Harness profile ({{I-D.draft-mcguinness-mission-harness}}):
  `status`, `signal`, `runtime_decision`, `harness`, `operator`, or a
  deployment-defined source. This profile does not define its own; a
  trigger source from {{trigger-sources}} maps to the corresponding
  value (a harness stop decision to `harness`, an operator action to
  `operator`).

`orchestration_decision`:
: REQUIRED. One of `suppress`, `pause`, `cancel`,
  `continue_to_safe_point`, `compensate`, `human_review`, or
  `record_only`. An unwind plan's
  `pre_start_behavior`/`in_flight_behavior` values map to these: both
  `cancel_workflow` and `cancel_if_possible` record as `cancel`,
  `continue_to_safe_point` carries through unchanged,
  `wait_then_review` and a review queue record as `human_review`, and
  `suppress`/`pause` carry through unchanged.

`reason`:
: REQUIRED. A string naming the condition.

`occurred_at`:
: REQUIRED. An RFC 3339 {{RFC3339}} timestamp.

`linked_evidence`:
: OPTIONAL. An array of runtime enforcement evidence records
  ({{I-D.draft-mcguinness-mission-runtime}}), Harness Evidence,
  or prior Orchestration Evidence identifiers. REQUIRED when
  `orchestration_decision` is `compensate`.

`outcome_state`:
: OPTIONAL. One of `not_dispatched`, `dispatched_not_committed`,
  `committed`, or `unknown`.

`unwind_plan_hash`:
: REQUIRED on the step's dispatch-time record or, where the hash was
  committed through Decision Evidence instead, on the step's first
  Orchestration Evidence record. The integrity anchor over the step's
  unwind plan, committed at or before dispatch
  ({{unwind-plan-integrity}}).

`authority_basis`:
: REQUIRED when `orchestration_decision` is `compensate`; otherwise
  absent. One of `resource_policy` or `separate_mission`
  ({{compensation-authority}}).

`compensation_action`:
: REQUIRED when `orchestration_decision` is `compensate`. The
  deployment-defined compensation action reference.

`compensation_outcome`:
: REQUIRED when `orchestration_decision` is `compensate`. The outcome
  of the compensation action.

`evidence_envelope`:
: OPTIONAL, except REQUIRED when `orchestration_decision` is
  `compensate` and the compensated step's reversibility class is
  `irreversible_action`, `external_commitment`, or
  `privileged_administration`. Compensation in those classes is
  consequential work in its own right; its record does not rest on
  an unsigned self-report by the orchestrator that performed it.
  Integrity protection over the Orchestration Evidence
  object. When present with `format` `jws-compact`, it is a JWS
  {{RFC7515}} Compact Serialization whose payload is the JCS
  {{RFC8785}} canonical bytes of the object with `evidence_envelope`
  removed. When present, it MUST identify the signer: the JWS protected
  header MUST carry `kid`, whose resolution under deployment policy
  identifies the issuer, `alg`, and `typ`, matching the suite's
  evidence-envelope convention
  ({{I-D.draft-mcguinness-mission-runtime}}). This document registers
  no media type; its two local-use type identifiers are
  `mission-orchestration-evidence`, which `typ` carries here, and
  `mission-unwind-plan` ({{unwind-plan-integrity}}).

Example:

~~~ json
{
  "event_id": "orch_4r9SqLm8tY2p",
  "mission": {
    "id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
    "issuer": "https://as.example.com",
    "authority_hash":
      "sha-256:l3KvZ4mP5x0wQrR6tY2nD9bM7sX1cF8gH2vJ4kE5pNQ"
  },
  "workflow_id": "wf_invoice_recon_2026q3",
  "step_id": "post_journal_entry",
  "mission_state": "suspended",
  "state_source": "status",
  "orchestration_decision": "human_review",
  "reason": "external_commitment_dispatched_unknown",
  "outcome_state": "unknown",
  "unwind_plan_hash":
    "sha-256:jKxM47ygRiTXYVfKjrVE34VZx8nsxg1I9OPPeHnO-_c",
  "occurred_at": "2026-11-02T08:16:00Z"
}
~~~

A later record for the same step carries the compensate decision.
Review confirmed that the posting committed before the Mission was
revoked; a pre-provisioned remedial Mission that is `active`
authorizes the reversing entry ({{compensation-authority}}). The
record links the review record above and the original runtime
enforcement evidence, and omits `unwind_plan_hash` because it is not
the step's first record:

~~~ json
{
  "event_id": "orch_9wK2nR5vXq7t",
  "mission": {
    "id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
    "issuer": "https://as.example.com",
    "authority_hash":
      "sha-256:l3KvZ4mP5x0wQrR6tY2nD9bM7sX1cF8gH2vJ4kE5pNQ"
  },
  "workflow_id": "wf_invoice_recon_2026q3",
  "step_id": "post_journal_entry",
  "mission_state": "revoked",
  "state_source": "status",
  "orchestration_decision": "compensate",
  "reason": "committed_step_reversed_after_review",
  "outcome_state": "committed",
  "linked_evidence": [
    "orch_4r9SqLm8tY2p",
    "dec_8K2nP4qV9rL3tY6sB1zN0eF7jB"
  ],
  "authority_basis": "separate_mission",
  "compensation_action": "erp.journal_entry.reverse",
  "compensation_outcome": "completed",
  "occurred_at": "2026-11-02T09:03:00Z"
}
~~~

## Record Integrity and Retention {#evidence-integrity}

Orchestration Evidence records are subject to the record integrity and
retention requirements of the runtime profile
({{I-D.draft-mcguinness-mission-runtime}}), imported here by
reference: append-only integrity protection under a named mechanism, a
per-Mission sequence indicator, no raw parameters in the record, and a
retention window no shorter than the Mission's audit horizon.

## Evidence Ordering {#evidence-ordering}

An orchestrator MUST include a deployment-defined sequence number or
otherwise order evidence records when multiple steps are affected by
the same state transition, matching the runtime profile's per-Mission
sequencing requirement ({{I-D.draft-mcguinness-mission-runtime}}).
Ordering lets an auditor reconstruct whether the orchestrator stopped
before or after a given step committed.

# Relationship to Harness and Runtime Profiles {#relationship}

The two execution profiles share, rather than duplicate, their common
machinery: the `state_source` value space is defined once by the
Harness profile ({{I-D.draft-mcguinness-mission-harness}}) and reused
here ({{orchestration-evidence}}), and the Orchestration Evidence
`mission` descriptor is the same shape as the Harness Evidence
descriptor. A deployment that needs both records emits each at its own
decision point; neither subsumes the other. The runtime profile
{{I-D.draft-mcguinness-mission-runtime}} still governs each
consequential action at the last controllable boundary, whichever
execution profile stops or unwinds the work.

A deployment running both this profile and the harness profile MUST
provide a means for the harness to determine whether a work item is
under an active unwind decision; the mechanism is deployment-defined.
Where harness stop policy and an active unwind decision would produce
different outcomes for the same work item, the stricter outcome
governs.

# Conformance {#conformance}

A conforming Mission-aware orchestrator MUST:

- assign a reversibility class to each consequential step;
- record an unwind plan, and commit its hash, at or before dispatch
  ({{unwind-plan-integrity}});
- stop new governed work when Mission state is non-active or stale;
- classify in-flight steps under {{in-flight}};
- apply post-completion behavior for committed or unknown outcomes;
- emit Orchestration Evidence; and
- document the policy basis for compensation after Mission termination.

A deployment MAY claim this profile for only some workflows, but it
MUST identify workflows and paths outside the claim.

# Security Considerations {#security-considerations}

## Compensation Is Authority-Bearing

Compensation can itself be consequential. A deployment MUST NOT perform
compensation by presenting a terminated Mission's authority. It acts
only under resource policy or a separate active Mission
({{compensation-authority}}). Otherwise termination could become a path
to unauthorized remedial actions.

## Unknown Outcomes

Distributed systems often cannot prove whether an in-flight action
committed. Treating unknown as harmless creates audit gaps. This
profile requires unknown outcomes for high-risk classes to be reviewed
or handled under stricter policy.

## Reversibility Misclassification

An orchestrator can evade review by classifying a step as reversible
when it is not. Resource policy and operation profiles SHOULD define
minimum reversibility classes for protected operations, and
orchestrators MUST NOT lower them.

## Compensation Loops

Compensation actions can fail and trigger further compensation. A
deployment SHOULD cap compensation chains and escalate to human review
when repeated compensation would create additional external effects.

## Race With Runtime Permits

A runtime permit obtained before revocation might still be presented
after the orchestrator learns the Mission is non-active. The
orchestrator MUST stop dispatching such work, and the runtime PEP MUST
still enforce its own permit freshness and Mission-state checks.

# Privacy Considerations {#privacy-considerations}

Orchestration Evidence can expose workflow structure, business
milestones, resource names, and failure conditions. Deployments SHOULD
limit evidence access to audit and operations roles with a need to know
and avoid recording raw user content when identifiers are sufficient.

# IANA Considerations {#iana}

This document makes no IANA request.

--- back

# Acknowledgments
{:numbered="false"}

This document is part of the Mission-Bound Authorization for OAuth 2.0
set and defines how Mission termination affects in-flight workflows.
