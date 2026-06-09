---
title: "Mission-Bound Runtime Enforcement Profile"
abbrev: "Mission Runtime"
category: std

docname: draft-mcguinness-mission-runtime-profile-latest
submissiontype: independent
number:
date:
consensus: true
v: 3
keyword:
 - mission
 - runtime
 - authzen
 - pdp
 - enforcement
venue:
  group: "Independent Submission"
  type: "Independent"
  github: "mcguinness/mission-bound-authorization"
  latest: "https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-runtime-profile.html"

author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com

normative:
  RFC2119:
  RFC8174:
  I-D.draft-mcguinness-mission-framework:
  I-D.draft-mcguinness-mission-expansion:

informative:
  RFC9396:
  RFC9701:
  I-D.draft-mcguinness-mission-oauth-profile:
  I-D.draft-mcguinness-mission-aauth-profile:
  I-D.draft-mcguinness-oauth-actor-profile:
  I-D.draft-mcguinness-oauth-insufficient-claims:

--- abstract

This document profiles the OpenID AuthZEN Authorization API to
enforce Mission-bound authority at runtime. The composition defines
Mission-to-policy materialization, the Resource-Side Enforcement
Contract, PEP placement rules, parameter binding, denial
classification with governed expansion eligibility, the Decision
Evidence Object emitted by the PDP, the Execution Evidence Object
emitted by the PEP or executor, and the runtime `max_invocations`
constraint. Each Mission-bound enforcement claim names a deployment-
published enforcement-scope manifest identifying covered action
classes and execution boundaries.

--- middle

# Introduction

The Mission Framework {{I-D.draft-mcguinness-mission-framework}}
governs credential issuance and derivation. This profile carries
those bounds to the execution boundary. Every consequential action
in a deployment's enforcement-scope manifest is evaluated by a
Policy Decision Point (PDP) against:

- Current Mission state (per Mission Status, from
  {{I-D.draft-mcguinness-mission-framework}}).
- The audience-relevant Authority Set projection.
- Authenticated actor context.
- Resource policy.

The PDP returns a permit, deny, or expandable-denial decision. The
PEP enforces the decision and emits Execution Evidence.

This profile is substrate-independent. OAuth Profile
{{I-D.draft-mcguinness-mission-oauth-profile}} and AAuth Profile
{{I-D.draft-mcguinness-mission-aauth-profile}} adapters supply
substrate-native credential and actor context. The PDP interface
is the OpenID AuthZEN Authorization API 1.0 (a final OpenID
Foundation specification).

## Submission venue

This document is an independent IETF Internet-Draft composing with
the OpenID AuthZEN Authorization API 1.0 specification. AuthZEN
is an OpenID Foundation effort, not an IETF Working Group.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

Terms from {{I-D.draft-mcguinness-mission-framework}} are inherited.
Additional definitions:

**PDP (Policy Decision Point)**:
: Component that evaluates per-action requests and produces a
permit, deny, or expandable-denial decision. Conforms to the
OpenID AuthZEN Authorization API.

**PEP (Policy Enforcement Point)**:
: The in-line component that calls the PDP before allowing a
consequential action and enforces the decision.

**Materialized Policy View**:
: The reproducible evaluable form of the Mission's approved tuple
(Validated Mission Intent, Authority Set, `policy_version`)
produced by the state authority or a trusted compiler.

**Decision Evidence**:
: A durable record emitted by the PDP capturing the inputs and
result of one runtime decision.

**Execution Evidence**:
: A durable record emitted by the PEP or executor capturing whether
the authorized action was attempted, completed, failed, or
suppressed.

**Enforcement-scope manifest**:
: A deployment-published document identifying the action classes,
PEP locations, and execution boundaries covered by a Mission-Bound
Runtime Enforcement conformance claim.

# Profile Structure

This profile is modular:

- **Core**: defines the required PDP contract, PEP placement,
  Decision Evidence, Execution Evidence, parameter binding, and
  denial classification.
- **Optional Modules**: separate per-module specifications adding
  Tool Binding, Decision Receipt, Purpose Registry, Attestation,
  Policy Projection.

Conformance claims name which modules the implementation supports.
The Core profile is the minimum for any Mission-Bound Runtime
Enforcement claim.

# Mission-to-Policy Materialization

The state authority (or a trusted compiler) reproducibly materializes
the approved Mission tuple as an evaluable policy view consumable by
the PDP.

## Inputs

- Validated Mission Intent.
- Authority Set (typed entries).
- `policy_version`.
- Schema versions for each Authority Set entry type.

## Properties

The materialized policy view MUST satisfy:

- **Reproducibility**: same inputs produce byte-identical materialized
  output.
- **Identifiable**: the materialized view carries `policy_view_id`
  and `policy_view_version` so PDP cache entries are addressable.
- **Bounded**: the materialized view does not enlarge the Authority
  Set's semantic bounds. Materialization is faithful.

## Wire form

This profile does not pick a concrete policy-language wire form for
the materialized view. Implementations MAY use:

- Cedar policies (`draft-cecchetti-oauth-rar-cedar`).
- OpenFGA tuples.
- Canonical input bundles consumed by the AuthZEN PDP directly.
- Engine-native artifacts.

The Policy Projection Optional Module (future spec) standardizes a
specific wire form when implementer demand justifies.

# Resource-Side Enforcement Contract (RS-D)

A Resource Server claiming RS-D MUST:

1. Identify every consequential action in its enforcement scope.
2. For each such action, call the PDP before allowing the action.
3. Pass to the PDP the inputs defined in Section 7.
4. Enforce the PDP decision.
5. Emit Execution Evidence after the action's outcome is determined.

A Resource Server claiming RS-D for a named scope but allowing
consequential actions outside that scope to bypass the PDP MUST NOT
claim RS-D for those actions. The enforcement-scope manifest names
covered action classes; uncovered actions are explicitly outside
the claim.

# PEP Placement Rules

The PEP MUST be placed such that:

- Every action in the enforcement scope passes through the PEP.
- The PEP can prevent the action from being executed (not merely
  log it).
- The PEP has access to the authenticated subject, actor context,
  Mission reference, parameters, and Resource policy at decision
  time.

Acceptable placements include:

- In-process middleware in the Resource Server.
- A reverse-proxy interceptor.
- A sidecar enforcement gateway.
- The agent orchestrator's tool-call boundary (for local actions
  not exposed as resources).

PEP placements MUST be documented in the enforcement-scope manifest.

# PDP Request

The PDP request follows the OpenID AuthZEN Authorization API. This
profile adds the following Mission-specific inputs:

- `mission` (object, required): Mission reference and projection.
  Carries `id` or `ref`, `origin`, `authority_hash`,
  `policy_version`, `policy_view_id`.
- `actor` (object, required): authenticated actor context per
  {{I-D.draft-mcguinness-oauth-actor-profile}}.
- `subject` (object, required): authenticated subject identifier.
- `resource` (object, required): the target resource.
- `action` (string, required): the requested action identifier.
- `parameters` (object, conditional): action parameters when
  parameter binding is required.
- `parameter_digest` (string, required when `parameters` is
  present): a digest committing to the parameters at request time.
- `audience` (string, required): the PEP's audience identifier.
- `freshness` (object, required): the Mission Status freshness
  the PEP relies on. Includes `mission_status_issued_at`,
  `mission_status_expires_at`, and the freshness mode (`fresh`,
  `cached`, or `event_driven`).

The PDP MUST verify that the Mission state, `authority_hash`, and
`policy_version` carried by the PEP are consistent with the
materialized policy view. Stale or inconsistent inputs MUST be
treated as denial classification `stale_state`.

# Decision Evidence Object

The PDP emits a Decision Evidence Object for every runtime decision.
The object is a JSON document with:

- `decision_id` (string, required): unique decision identifier.
- `mission_id_or_ref`, `origin`, `authority_hash`, `policy_view_id`:
  Mission projection at decision time.
- `actor`, `subject`, `resource`, `action`, `parameter_digest`,
  `audience`: PDP inputs.
- `decision` (string, required): one of `permit`, `deny`,
  `expandable_deny`.
- `denial_reason` (string, conditional): when `decision` is `deny`
  or `expandable_deny`. Values include `out_of_authority`,
  `aal_insufficient`, `stale_state`, `mission_inactive`,
  `parameter_violation`, `resource_policy`, `quota_exceeded`,
  registered values from the Common Constraints registry.
- `expansion` (object, conditional): when `decision` is
  `expandable_deny`, the eligibility-signaling fields per
  {{I-D.draft-mcguinness-mission-expansion}}: `eligible: true`,
  `access_request_uri`, `ticket`, `requested_authority`.
- `evaluated_at` (RFC 3339 timestamp, required).
- `policy_view_id`, `policy_view_version`.
- `evidence_envelope` (signature or integrity reference): how the
  Decision Evidence is integrity-protected. Profiles bind.

Decision Evidence is durable and integrity-protected. It is the
authoritative record of what the PDP evaluated, NOT proof that the
action occurred.

# Execution Evidence Object

The PEP or executor emits an Execution Evidence Object after the
authorized action's outcome is determined. The object is a JSON
document with:

- `execution_id` (string, required): unique execution identifier.
- `decision_id` (string, required): the Decision Evidence this
  execution is linked to.
- `parameter_digest` (string, required): MUST match the
  `parameter_digest` in the linked Decision Evidence.
- `outcome` (string, required): one of `attempted`, `completed`,
  `failed`, `suppressed`. `suppressed` indicates the action was
  permitted by the PDP but the executor chose not to attempt it
  (e.g., kill-switch, secondary deny).
- `outcome_at` (RFC 3339 timestamp, required).
- `error` (string, conditional): error identifier when `outcome` is
  `failed`.
- `attempted_at`, `completed_at`: timing context.
- `result_summary` (object, optional): minimal action result
  metadata (e.g., affected resource counts).
- `evidence_envelope`: integrity protection.

Decision Evidence and Execution Evidence are **linked but distinct**.
Authorization is not proof that an action occurred; the existence
of a Decision Evidence record without a corresponding Execution
Evidence record indicates the action was not attempted, or that
the executor failed to emit evidence.

## TOCTOU and parameter binding

The `parameter_digest` chain (PEP request → Decision Evidence →
Execution Evidence) closes the time-of-check-to-time-of-use gap.
If the executed action's effective parameters differ from those
the PDP evaluated, the digest mismatch is detectable in audit.

PEP MUST compute `parameter_digest` over the canonical parameter
object using the integrity-anchor hash format from
{{I-D.draft-mcguinness-mission-framework}}.

# Runtime Denial Classification

When the PDP returns a denial, the denial is one of:

- **`out_of_authority`**: the requested action is not within the
  Authority Set. MAY be `expandable_deny` if eligible.
- **`aal_insufficient`**: the actor's AAL does not satisfy an `aal`
  constraint. MAY be satisfied by RFC 9470 step-up authentication
  without expansion.
- **`stale_state`**: the PEP-supplied freshness is stale or
  inconsistent with the materialized policy view.
- **`mission_inactive`**: the Mission state is not `active`.
- **`parameter_violation`**: parameters violate a registered
  constraint.
- **`resource_policy`**: Resource policy refuses the action
  independently of Mission authority.
- **`quota_exceeded`**: a runtime budget (e.g., `max_invocations`)
  has been exhausted.

## Expansion eligibility

The PDP returns `expandable_deny` when:

- The denial is `out_of_authority`, AND
- The Mission Expansion specification's eligibility predicate
  permits expansion for the requested authority delta.

The PEP MUST surface the expansion eligibility to the caller per
{{I-D.draft-mcguinness-mission-expansion}}'s wire binding for the
substrate.

## Insufficient Claims composition

The PDP MAY compose with
{{I-D.draft-mcguinness-oauth-insufficient-claims}} to signal which
authenticated claims would lift an `aal_insufficient` denial.

# `max_invocations` Constraint

This profile defines `max_invocations` as a runtime constraint
distinct from the Framework's `max_derivations` (which is an
issuance constraint).

## Semantics

`max_invocations` is the maximum number of authorized action
invocations permitted under the Mission, evaluated at the
enforcement boundary.

## Authoritative counter

The PEP maintains an authoritative atomic counter per Mission. The
counter is incremented through a reserve-on-permit, finalize-on-
outcome protocol:

1. On PDP `permit`, the PEP reserves one count slot.
2. On Execution Evidence `completed`, the slot is finalized as
   consumed.
3. On Execution Evidence `failed` or `suppressed`, the slot is
   released per the registered constraint semantics
   (default: failed = consumed, suppressed = released).
4. On Execution Evidence missing (timeout), the slot is finalized
   per the registered timeout semantics (default: consumed).

The counter MUST NOT exceed the value declared in the Mission's
`max_invocations` constraint.

## Multi-PEP coordination

When more than one PEP enforces a Mission's `max_invocations` (e.g.,
multiple Resource Servers under one deployment), the deployment
publishes a coordination policy in the enforcement-scope manifest.
Implementations:

- MAY use a centralized counter service.
- MAY use eventually-consistent counters with a per-PEP allocation
  budget.
- MUST NOT allow uncoordinated counters that would together exceed
  the declared maximum.

# Enforcement-Scope Manifest

A deployment publishing a Mission-Bound Runtime Enforcement claim
MUST publish an enforcement-scope manifest identifying:

- **Action classes covered**: the set of action identifiers the
  PEP intercepts.
- **PEP locations**: the components hosting the PEP for each action
  class.
- **Excluded execution boundaries**: action paths or execution
  contexts the deployment cannot intercept (e.g., debug shells,
  unsanctioned egress routes, agent-side tool invocations outside
  the orchestrator).
- **Mission state freshness mode**: `fresh`, `cached`, or
  `event_driven`.
- **Maximum tolerated stale interval**: in seconds.

The manifest is a JSON document published at a well-known URL or
linked from AS metadata.

# Mission Status Composition

The PDP relies on Mission Status to determine current Mission state.
The PEP MUST pass to the PDP the freshness of the Mission Status it
last consulted. The PDP applies the deployment's freshness mode:

- `fresh`: PEP MUST consult Mission Status synchronously before
  every consequential action.
- `cached`: PEP MAY use cached Mission Status within
  `mission_max_stale_seconds`.
- `event_driven`: PEP relies on event-channel invalidation; cached
  state is valid until an event invalidates it.

When freshness fails (cache miss, event-channel lag), the PEP MUST
classify the request as `stale_state` denial unless the deployment
explicitly defines a bounded degraded mode.

# Local-Action Boundary

For consequential actions that are NOT OAuth Resource Server calls
or AAuth resource-token calls (e.g., agent-orchestrator local tool
invocations, file-system writes, process launches), the orchestrator
MUST act as the PEP at the action boundary.

The orchestrator-PEP MUST:

- Identify the local action in its enforcement-scope manifest.
- Call the PDP before the action.
- Emit Decision Evidence and Execution Evidence per Sections 8 and 9.

The enforcement-scope manifest MUST explicitly list local-action
PEP placements and any local actions excluded from enforcement.

# Security Considerations

## Decision Evidence vs Execution Evidence

Decision Evidence is NOT proof an action occurred. Implementations
MUST emit Execution Evidence to record outcomes. Auditors MUST NOT
treat Decision Evidence alone as evidence of action.

## Stale state and TOCTOU

A PDP decision is valid only for the freshness window the PEP
supplied. The PEP MUST NOT execute an authorized action after the
freshness window has elapsed without re-consulting Mission Status.

The `parameter_digest` chain closes the parameter TOCTOU gap.
Implementations MUST verify the digest at execution time.

## PDP compromise

A compromised PDP can return arbitrary decisions. Mission-Bound
Runtime Enforcement assumes a trusted PDP. Deployments mitigate
PDP compromise through key hardware modules for PDP signing keys,
PDP redundancy with majority quorum, and audit-side cross-checks
against Mission Status.

## Authority enlargement at runtime

A PEP that interprets `permit` as authorization beyond the Authority
Set's bounds violates this profile. The Mission's `authority_hash`
is the upper bound; runtime evaluation NEVER enlarges authority.

## `max_invocations` counter correctness

The reserve-on-permit, finalize-on-outcome protocol depends on the
PEP correctly emitting Execution Evidence. A PEP that fails to
emit Execution Evidence leaks reserved slots over time, eventually
denying legitimate requests.

Implementations MUST timeout reserved slots and finalize them per
the registered constraint semantics (default: consumed).

## Bypass surfaces

Action paths outside the enforcement-scope manifest are NOT covered
by the conformance claim. Deployments MUST honestly document
bypass surfaces. A "complete" enforcement claim covering a narrow
manifest is more honest than a broad manifest with unenumerated
bypass surfaces.

# IANA Considerations

## Decision Evidence Object Media Type

This document registers `application/mission-decision-evidence+json`
per RFC 6838.

## Execution Evidence Object Media Type

This document registers `application/mission-execution-evidence+json`
per RFC 6838.

## Mission Common Constraints Registry

This document registers `max_invocations` in the Mission Common
Constraints registry created by
{{I-D.draft-mcguinness-mission-framework}}.

- Name: `max_invocations`
- Type: string (decimal-string integer).
- Specification: this document.
- Authoritative counter: PEP per Section 11.
- Narrowing: derived constraints MAY specify smaller values.

## Mission Capability-Advertisement Metadata

This document registers the following metadata values in the
Mission Capability-Advertisement Metadata registry:

- `mission_optional_modules_supported` values: `tool_binding`,
  `decision_receipt`, `purpose_registry`, `attestation`,
  `policy_projection`. (The modules themselves are separate
  specifications.)
- `mission_freshness_mode_supported`: array of `fresh`, `cached`,
  `event_driven`.
- `mission_enforcement_scope_manifest_uri`: URL of the deployment's
  enforcement-scope manifest.

# Acknowledgments
{:numbered="false"}

The author thanks the OpenID AuthZEN working group and the
Mission-Bound Authorization implementer community for feedback.

--- back
