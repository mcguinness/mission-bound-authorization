---
title: "Mission Child Delegation for OAuth 2.0"
abbrev: "OAuth Mission Child Delegation"
category: std

docname: draft-mcguinness-oauth-mission-child-delegation-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
keyword:
 - oauth
 - mission
 - agent
 - delegation
 - sub-agent
venue:
  github: "mcguinness/draft-mcguinness-oauth-mission"
  latest: "https://mcguinness.github.io/draft-mcguinness-oauth-mission/draft-mcguinness-oauth-mission-child-delegation.html"

author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com

normative:
  RFC3339:
  RFC8259:
  RFC8414:
  RFC9126:
  I-D.draft-mcguinness-oauth-mission:
    title: "Mission-Bound Authorization for OAuth 2.0"
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-oauth-mission-latest
  I-D.draft-mcguinness-oauth-mission-status:
    title: "Mission Status and Lifecycle for OAuth 2.0"
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-oauth-mission-status-latest
  I-D.draft-mcguinness-oauth-mission-expansion:
    title: "Mission Expansion for OAuth 2.0"
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-oauth-mission-expansion-latest

informative:
  RFC8126:
  I-D.draft-mcguinness-oauth-mission-attenuation:
    title: "Mission Offline Attenuation for OAuth 2.0"
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-oauth-mission-attenuation-latest
  I-D.draft-mcguinness-oauth-mission-signals:
    title: "Mission Lifecycle Signals for OAuth 2.0"
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-oauth-mission-signals-latest
  I-D.draft-mcguinness-mission-harness:
    title: "Mission-Aware Agent Harnesses"
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-mission-harness-latest

--- abstract

Mission-Bound Authorization for OAuth 2.0 defines delegated tokens and
the rule that authority narrows down a delegation chain. Agent
harnesses, however, can spawn sub-agents whose work outlives a call
frame or crosses a different execution boundary. This document defines
an OPTIONAL Child Mission Delegation profile. A parent Mission can
authorize a child Mission for a sub-agent, with explicit parent
lineage, strict-subset authority, expiry no later than the parent,
separate child actor identity, fan-out controls, and cascade revocation
when the parent Mission is no longer active. A child Mission is never
created by session ancestry alone.

--- middle

# Introduction

Mission-Bound Authorization for OAuth 2.0
{{I-D.draft-mcguinness-oauth-mission}} (the "issuance profile") supports
delegated Mission-bound tokens. It requires authority to narrow down
the chain and records actor context. That is sufficient for many
service-to-service and token-exchange cases. Agent harnesses introduce
a related but distinct case: a parent agent starts a sub-agent or child
worker with a durable task of its own. The child may have its own
session, queue, tool handles, and runtime identity.

This document defines Child Missions for that case. A Child Mission is
a Mission whose authority is a strict subset of a Parent Mission and
whose lifecycle depends on the parent. It has its own Mission
identifier and actor identity, but it cannot outlive, out-broaden, or
escape the parent. The child is created through an explicit
authorization step, not by inheriting a parent harness session.

# Status: An OPTIONAL Extension {#optional-status}

This document is OPTIONAL. It is a layered extension to the issuance
profile, not a change to it. A deployment that implements
{{I-D.draft-mcguinness-oauth-mission}} and never creates a Child
Mission is fully conformant to that profile and is unaffected by this
document: it accepts no `parent` or `parent_token` parameter, records
no `parent` member, and applies no cascade revocation. The issuance
profile's delegated-token mechanism is complete without Child Missions;
the child machinery defined here is relevant only when a deployment
creates Missions for sub-agents.

A Mission Issuer claims conformance to this document only when it
creates Child Missions ({{conformance}}); otherwise it remains a plain
issuance-profile Mission Issuer. Nothing here places a new requirement
back on the issuance profile.

# Relationship to the Issuance Profile {#issuance-relationship}

This document depends normatively on the issuance profile and is not
implementable alone. It reuses, without restating, that profile's
Mission Intent, submission via PAR, authority derivation, approval
event with its integrity anchors, Mission record, the `mission` claim,
the subset rule, and the lifecycle and issuance gating. It uses
the terms Agent (Client), Subject, Approver, Mission Issuer, Mission
Intent, Authority Set, Mission, and derived token as defined there.

Cascade revocation ({{cascade}}) additionally depends on the Mission
Status and Lifecycle profile
({{I-D.draft-mcguinness-oauth-mission-status}}) and the Mission
Expansion profile ({{I-D.draft-mcguinness-oauth-mission-expansion}})
where a deployment runs them, because those profiles define the
`suspended`, `completed`, and `superseded` parent states the cascade
rules react to. A deployment that runs neither still implements this
profile: under the issuance profile's forward-compatibility rule, the
cascade treats any non-active parent state as a terminal trigger.

A Child Mission is an ordinary Mission under the issuance profile with
two additions: it is created under a parent grant rather than a
first-party approval, and its record and tokens carry the `parent`
member ({{parent-member}}). The child's own `authority_hash` remains
the authority commitment for its tokens; the `parent` member is lineage
and audit data only.

Where this document refers to "the issuance profile" without a section,
it means {{I-D.draft-mcguinness-oauth-mission}} as a whole.

# Scope

This document defines:

- Child Mission creation ({{child-creation}});
- the `parent` lineage member ({{parent-member}});
- strict-subset and expiry rules ({{attenuation}});
- fan-out controls ({{fanout}});
- cascade revocation ({{cascade}});
- child evidence and audit requirements ({{child-evidence}}); and
- conformance for a Child-Mission-capable Mission Issuer
  ({{conformance}}).

This document does not replace ordinary delegated tokens under
{{I-D.draft-mcguinness-oauth-mission}}. A deployment can use delegated
tokens for short-lived delegation and Child Missions for durable
sub-agent work that needs its own lifecycle handle.

# Conventions and Terminology {#conventions}

{::boilerplate bcp14-tagged}

This document uses the terms Mission, Mission Intent, Authority Set,
Mission Issuer, Mission-bound token, and delegation from
{{I-D.draft-mcguinness-oauth-mission}}.

Parent Mission:
: The active Mission from which a Child Mission derives its upper bound
  of authority.

Child Mission:
: A Mission created for a child actor or sub-agent, with authority that
  is a strict subset of its Parent Mission and lifecycle that cascades
  from the parent.

Child actor:
: The agent, workload, sub-agent, or component that receives authority
  under the Child Mission. The child actor is the OAuth client of the
  Child Mission ({{child-creation}}).

Delegation event:
: The Mission Issuer event that creates the Child Mission and records
  the attenuation checks from parent to child.

A Child Mission is a new Mission with its own `mission_id`. It is not an
attenuation child: the Mission Offline Attenuation profile
({{I-D.draft-mcguinness-oauth-mission-attenuation}}) defines a
child as a narrower token minted under one Mission, not a new Mission.

A delegated token is appropriate when the delegate performs work within
the lifetime and operational control of the delegating flow. A Child
Mission is appropriate when the child actor needs a durable Mission
handle of its own: for example, a sub-agent with a queue, background
job, independent harness session, or separate audit lifecycle. A Child
Mission is not a way to widen authority; it is a way to create a
narrower, separately accountable authority record for a child actor.
{:#child-vs-token}

This profile's child delegation is distinct from the in-Mission
delegation the issuance profile already defines. In-Mission delegation
extends a single Mission's `act` chain to additional actors, bounded by
the per-entry `delegation` policy (`allowed_delegates`, `max_depth`) of
{{I-D.draft-mcguinness-oauth-mission}}; no new Mission is created and
authority is exercised under the original Mission. Child delegation, by
contrast, creates a separate Child Mission with its own `mission_id`,
actor, lifecycle, and `act` chain. Where this profile reads the parent
entry's `delegation` policy, it does so to decide whether child creation
is permitted and which `child_actor` is eligible: the presence of a
`children` object in the parent entry's `delegation` member is what
permits child creation for that entry ({{fanout}}), and that object's
`allowed_child_actors` constrains the `child_actor` the parent may name.
The issuance profile's `act` `max_depth` bounds act-chain nesting within
a Mission and is not a child-generation counter; a Child Mission's own
`act` chain restarts at depth 0. Child-generation depth and breadth are
governed instead by the fan-out controls of {{fanout}}.
{:#child-vs-act}

# Child Mission Creation {#child-creation}

A Child Mission is created by submitting a Mission Intent through
Pushed Authorization Requests {{RFC9126}} under the issuance profile,
with child-specific binding to the parent. The request contains:

`mission_intent`:
: REQUIRED. The proposed Child Mission Intent.

`parent`:
: REQUIRED. The `mission_id` of the Parent Mission.

`parent_token`:
: REQUIRED. A refresh token or other Mission-Issuer-accepted grant
  bound to the Parent Mission. The Mission Issuer resolves the Parent
  Mission from this grant. The `parent` parameter is a cross-check and
  audit value; it does not by itself authorize child creation.

`child_actor`:
: REQUIRED. An object identifying the child actor that will hold or
  execute under the Child Mission, using the issuance profile's actor
  vocabulary ({{I-D.draft-mcguinness-oauth-mission}}):

  `sub`:
  : REQUIRED. The child actor's identifier.

  `iss`:
  : OPTIONAL. The issuer of `sub` when it is not the Mission Issuer's
    own namespace.

  `sub_profile`:
  : RECOMMENDED. The actor-type classification (for example,
    `ai_agent`), matched against the parent entry's
    `allowed_child_actors` ({{fanout}}).

The Mission Issuer MUST resolve the parent from `parent_token`, verify
that it matches `parent`, verify that the parent is `active`, and verify
that the applicable parent Authority Set entry's `delegation` member
carries a `children` object ({{fanout}}) that permits child creation for
the requested authority.

The Mission Issuer MUST reject a child creation request presented on a
front channel with `parent_token`. The parent grant is presented only
on the authenticated back channel.

## Child Client Identity {#child-client-identity}

The child actor is the OAuth client of the Child Mission: its
identifier is the `client_id` of the Child Mission record. The child
actor authenticates itself at the token endpoint and redeems its own
grant for the Child Mission's tokens. Child credentials MUST NOT transit
the parent, and the parent MUST NOT hold child tokens. The concrete
conveyance of the child's initial grant reference (for example, an
authorization code or a grant handle) from the creating flow to the
child actor is deployment-defined, subject to those rules.

Where creation is adjudicated by policy with no front channel, the
Mission Issuer completes the authorization without user interaction and
the child actor redeems its grant directly at the token endpoint.

## Cross-Issuer Scope {#cross-issuer}

In this profile the Child Mission's issuer MUST equal `parent.origin`
({{parent-member}}): a Child Mission is created and hosted by the same
Mission Issuer as its parent. Cross-domain child delegation, where the
child is hosted by a different Mission Issuer than the parent, is
deferred work.

## Creation and Revocation Race {#creation-race}

Parent state MUST be re-verified atomically with the Child Mission's
creation commit, or child creation MUST be serialized with parent
lifecycle transitions such that a terminal parent transition
({{cascade}}) either denies every in-flight creation or cascades over
it. A Child Mission MUST NOT commit against a parent that became
non-active after the parent-state check.

## Protocol Flow {#protocol-flow}

~~~
 Parent agent / harness   Mission Issuer (AS)      Child actor
        |                        |                      |
        | 1. PAR: child Mission  | resolve parent       |
        |    Intent + grant ---->| verify active;       |
        |                        | verify children      |
        |<---- request_uri ------|                      |
        |                        |                      |
        | 2. approval or policy->| create child Mission |
        |    adjudication        | record parent member |
        |<-- grant reference ----|                      |
        |                        |                      |
        | 3. convey grant reference (deployment-defined) |
        | ---------------------------------------------->|
        |                        |                      |
        |                        | 4. token request     |
        |                        |    (child auth) <-----|
        |                        | derive child token    |
        |                        | ----- access token -->|
~~~

The approval or policy adjudication in step 2 is deployment-specific.
A deployment MAY require a human approval event for Child Mission
creation or MAY allow policy to approve child creation when the parent
Mission's Authority Set explicitly permits it. In step 3 the parent
conveys only a grant reference, never a child token ({{child-client-identity}});
in step 4 the child actor authenticates itself and redeems its own grant.

## Request Processing {#request-processing}

The Mission Issuer processes child creation in this order:

1. Authenticate the client submitting the PAR request.
2. Resolve the Parent Mission from `parent_token`.
3. Verify the resolved Mission matches `parent`.
4. Verify the Parent Mission is `active`.
5. Verify the parent grant permits the requester to create a child.
6. Verify `child_actor` satisfies the parent entry's `children`
   constraints ({{fanout}}).
7. Derive the child Authority Set and verify strict subset
   ({{strict-subset}}).
8. Apply fan-out controls.
9. Adjudicate approval or policy.
10. Re-verify parent state and create the Child Mission record with
    `parent` atomically ({{creation-race}}).
11. Record Child Evidence.

The child actor then authenticates at the token endpoint and redeems
its own grant for the Child Mission's tokens ({{child-client-identity}}).
Failure at any step MUST prevent child creation.

## Child Creation Denial Reasons {#denial-reasons}

This profile defines these symbolic denial reasons:

`parent_not_active`:
: The Parent Mission is not active.

`parent_mismatch`:
: The caller-supplied `parent` does not match the Mission resolved from
  `parent_token`.

`delegation_not_permitted`:
: The applicable parent Authority Set entry's `delegation` member
  carries no `children` object, so it permits no child creation
  ({{fanout}}).

`child_actor_not_allowed`:
: The child actor does not satisfy the parent entry's
  `allowed_child_actors` ({{fanout}}) or equivalent policy.

`not_strict_subset`:
: The proposed child authority is not a strict subset of parent
  authority ({{strict-subset}}).

`fanout_exceeded`:
: Creating the child would exceed a fan-out control.

`policy_denied`:
: Deployment policy denied child creation.

These symbolic strings appear in error bodies, evidence, and audit,
layered on the OAuth error codes the issuance profile uses:
`parent_not_active` and `parent_mismatch` accompany `invalid_grant`;
`delegation_not_permitted`, `child_actor_not_allowed`,
`not_strict_subset`, and `fanout_exceeded` accompany `invalid_request`;
and `policy_denied` accompanies `access_denied`. In an error response
body the symbolic reason rides in a `mission_denial_reason` member
alongside the OAuth `error` member. A child creation request presented
on the front channel with `parent_token` MUST be rejected with
`invalid_request` ({{child-creation}}).

# The Parent Mission Reference {#parent-member}

A Child Mission carries a `parent` member in its Mission record and in
the `mission` claim of tokens derived under the child:

`parent`:
: REQUIRED for a Child Mission. An object containing:

  `id`:
  : REQUIRED. The Parent Mission identifier.

  `origin`:
  : REQUIRED. The Parent Mission Issuer. The Child Mission's own
    `origin` MUST equal this value ({{cross-issuer}}).

  `authority_hash`:
  : REQUIRED. The Parent Mission authority commitment the child was
    derived under.

  `depth`:
  : REQUIRED. An integer. The child-generation depth of this Child
    Mission: 1 for a child of a root Mission, incremented by one per
    generation. It lets issuers and consumers observe and bound
    generation depth without walking Mission Status.

  `delegation_id`:
  : OPTIONAL. A Mission-Issuer-defined identifier for the child
    delegation event.

  `cascade_mode`:
  : REQUIRED. The cascade mode from {{cascade}}.

  `created_at`:
  : OPTIONAL. The creation time of the Child Mission.

The `parent` member is lineage and audit data. It does not grant
authority. The Child Mission's own `authority_hash` is the authority
commitment for child tokens.

`parent.depth` counts upward from 1 across generations, while the parent
entry's `children.max_child_depth` ({{fanout}}) is a per-entry ceiling
that decrements at each generation, so `parent.depth` never exceeds the
depth the ancestor entries allowed.

Example:

~~~ json
{
  "mission": {
    "id": "msn_child_2Yt7Qv9LqMv4z7sA2bN1k0",
    "origin": "https://as.example.com",
    "authority_hash":
      "sha-256:Td9bM7sX1cF8gH2vJ4kE5pNQl3KvZ4mP5x0wQrR6tY2",
    "parent": {
      "id": "msn_parent_8RfX2Lqv9TqMv4z7sA2bN1k0",
      "origin": "https://as.example.com",
      "authority_hash":
        "sha-256:l3KvZ4mP5x0wQrR6tY2nD9bM7sX1cF8gH2vJ4kE5pNQ",
      "depth": 1,
      "delegation_id": "dlg_7pQ4m",
      "cascade_mode": "immediate",
      "created_at": "2026-11-02T08:14:00Z"
    }
  }
}
~~~

## Mission Record Requirements {#record-requirements}

The Child Mission record MUST contain the `parent` object, the child
actor, the child Authority Set, the child `authority_hash`, the
delegation event identifier, the cascade mode, and the fan-out policy
result. The `parent` value is immutable after creation.

# Attenuation Rules {#attenuation}

A Child Mission MUST be bounded by the Parent Mission:

- every child Authority Set entry MUST be a subset of a parent entry
  under the subset rule of {{I-D.draft-mcguinness-oauth-mission}};
- the child MUST NOT include a resource, action, constraint relaxation,
  or delegation right not present in the parent;
- the child's `mission_expiry` MUST NOT be later than the parent's
  `mission_expiry` (so it transitively caps every child-derived token's
  `exp`, per {{I-D.draft-mcguinness-oauth-mission}});
- the child MUST be created only where the applicable parent entry's
  `delegation` member carries a `children` object ({{fanout}}), and a
  child entry's `delegation` policy MUST NOT be broader than the parent
  entry's: its `max_depth` MUST be no greater and its `allowed_delegates`
  MUST be no wider, per the subset rule of
  {{I-D.draft-mcguinness-oauth-mission}};
- non-delegable parent entries MUST NOT appear in child authority; and
- child authority MUST be bound to the child actor identified in the
  request.

The Mission Issuer MUST compute the Child Mission's `authority_hash`
over the child Authority Set, not over the parent Authority Set. A
Resource Server enforces child tokens exactly as Mission-bound tokens:
the child `authority_hash` is the immediate authority commitment.

Child Mission tokens MUST be sender-constrained to the child actor's
own key, matching the core's delegated-token posture
({{I-D.draft-mcguinness-oauth-mission}}).

## Subset Evaluation {#strict-subset}

In this profile a "strict subset" is the subset rule of
{{I-D.draft-mcguinness-oauth-mission}} applied entry-wise between the
child Authority Set and the parent Authority Set with no relaxation.
"Strict" refers to that no-relaxation requirement, not to inequality:
per-entry equality is permitted, so a child entry MAY equal a parent
entry. Each child entry MUST be a subset of some parent entry under the
core rule, and the `delegation` narrowing of {{attenuation}} applies in
addition. A Mission Issuer MUST NOT assume any relaxation the core rule
does not define (for example resource containment or action-family
narrowing, which the core defers to future work).

If the Mission Issuer cannot prove the child Authority Set is a strict
subset of the parent, it MUST refuse child creation with
`not_strict_subset`.

# Fan-Out Controls {#fanout}

This profile defines the on-switch for child creation as a member of the
core's per-entry `delegation` object. The issuance profile lets a
companion profile define additional `delegation` members that are policy,
not authority, are never broadened downstream, and are carried unchanged
when not understood ({{I-D.draft-mcguinness-oauth-mission}}); this
profile's `children` member is such a member.

`children`:
: OPTIONAL. An object. Its PRESENCE on a parent Authority Set entry's
  `delegation` member is what permits Child Mission creation for that
  entry; an entry whose `delegation` carries no `children` permits no
  child ({{denial-reasons}}). Its members are the fan-out controls, each
  applied per entry, per parent Mission:

  `max_children`:
  : OPTIONAL. A positive integer. The maximum number of concurrently
    non-terminal Child Missions drawing on this entry, per parent
    Mission.

  `allowed_child_actors`:
  : OPTIONAL. An array of matcher objects of the same form as the core's
    `allowed_delegates` ({{I-D.draft-mcguinness-oauth-mission}}),
    constraining which actors or actor classes may receive a Child
    Mission from this entry.

  `max_child_depth`:
  : OPTIONAL. A positive integer, default 1. The maximum
    child-generation depth at which this entry may be included. A Child
    Mission's own entries carry `children` only with `max_child_depth`
    reduced by one, and an entry at depth equal to the limit carries no
    `children`, ending the lineage.

  `child_creation_policy`:
  : OPTIONAL. A policy reference evaluated before each child creation.

Example parent Authority Set entry whose `delegation` carries `children`,
so the entry permits Child Missions to depth 2, at most 5 concurrently,
for `ai_agent` actors:

~~~ json
{
  "type": "mission_resource_access",
  "resource": "https://erp.example.com",
  "actions": ["invoices.read"],
  "delegation": {
    "max_depth": 2,
    "allowed_delegates": [{ "sub_profile": "ai_agent" }],
    "children": {
      "max_children": 5,
      "max_child_depth": 2,
      "allowed_child_actors": [{ "sub_profile": "ai_agent" }]
    }
  }
}
~~~

Depth limits alone do not control breadth: a Parent Mission MAY permit
many Child Missions at the same depth unless `max_children` or
`child_creation_policy` bounds fan-out. A Child-Mission-capable Mission
Issuer MUST enforce every `children` control an entry carries. If an
entry's `children` carries a control the Mission Issuer cannot enforce,
it MUST refuse child creation for that entry.

## Fan-Out Accounting {#fanout-accounting}

The Mission Issuer MUST count non-terminal Child Missions against
`max_children` until the child reaches a terminal state. If cascade is
`bounded_staleness`, the child counts until the cascade window has
closed or the child is otherwise confirmed non-active.

The Mission Issuer MUST serialize child creation against the same
parent entry and fan-out bucket so concurrent requests cannot exceed
the limit.

# Cascade Revocation {#cascade}

A Child Mission depends on the Parent Mission. The cascade trigger is
any Parent Mission transition to a non-active state. This profile
distinguishes terminal triggers from the one reversible trigger:

- Terminal triggers: parent `revoked` or `expired`
  ({{I-D.draft-mcguinness-oauth-mission}}), `completed`
  ({{I-D.draft-mcguinness-oauth-mission-status}}), `superseded`
  ({{I-D.draft-mcguinness-oauth-mission-expansion}}), or `cascaded`
  ({{child-state}}, when the parent is itself a Child Mission that was
  cascade-terminated). On a terminal trigger the Mission Issuer MUST stop
  new derivation under dependent Child Missions and, under `immediate`
  cascade, transition each dependent child to the terminal `cascaded`
  state ({{child-state}}). Cascade is transitive: the children of a
  `cascaded` parent cascade in turn under the same mode, in generation
  order, so a terminal trigger reaches every descendant.
- Reversible trigger: parent `suspended`
  ({{I-D.draft-mcguinness-oauth-mission-status}}). The Mission Issuer
  MUST stop new derivation under dependent Child Missions while the
  parent is suspended, but MUST NOT drive them to a terminal state. When
  the parent is resumed to `active`, dependent children return to their
  pre-suspension state and may derive again. Reporting of a dependent
  child while its parent is suspended is governed by {{child-state}}.

A `superseded` parent does not transfer its Child Missions to the
successor. The successor Mission carries a freshly derived Authority Set
that does not inherit the predecessor's authority by reference
({{I-D.draft-mcguinness-oauth-mission-expansion}}), so a Child Mission
that was a strict subset of the predecessor is not guaranteed to be a
subset of the successor. The Mission Issuer therefore MUST treat
`superseded` as a terminal cascade trigger and MUST NOT silently re-bind
children to the successor. Continuing child work under the successor
requires an explicit new Child Mission creation ({{child-creation}})
under a successor grant, which re-runs strict-subset validation
({{strict-subset}}) against the successor's Authority Set.

The Mission Issuer MUST implement one of these cascade modes and record
it on the Child Mission:

`immediate`:
: On a terminal trigger the Child Mission transitions to the `cascaded`
  state when the parent transition commits. On the reversible trigger
  the child is held non-active while the parent is suspended and
  restored to its prior state on parent resume.

`bounded_staleness`:
: The Child Mission is treated as non-active no later than the cascade
  staleness bound, measured from the consumer's last confirmed-active
  observation of the parent, aligned with the Status profile's freshness
  model ({{I-D.draft-mcguinness-oauth-mission-status}}). That bound is
  the deployment's `mission_max_stale_seconds`
  ({{I-D.draft-mcguinness-oauth-mission-status}}) unless the deployment
  publishes a different bound for child cascade.

`status_required`:
: Consumers MUST check parent state, per reliance decision and within
  the deployment's declared freshness window
  ({{I-D.draft-mcguinness-oauth-mission-status}}), before accepting
  child Mission authority. The Mission Issuer MUST select this mode only
  where every audience of child tokens is known, by registration or
  deployment policy, to implement this profile's parent-state check;
  otherwise the Mission Issuer MUST compensate with short child-token
  lifetimes or introspection-required paths.

The cascade mode MUST NOT allow a Child Mission to continue deriving
new credentials after the parent is known to be non-active.

The cascade behavior by trigger and mode:

| Trigger | Mode | Resulting child state | Who observes |
|---------|------|-----------------------|--------------|
| Terminal (`revoked`, `expired`, `completed`, `superseded`, `cascaded`) | `immediate` | `cascaded` (terminal) | Mission Issuer sets it; consumers read it from Mission Status or a lifecycle event |
| Terminal | `bounded_staleness` | non-active by the staleness bound | Consumer, from its last confirmed-active parent observation |
| Terminal | `status_required` | non-active on the next parent-state check | Consumer, per reliance decision |
| Reversible (`suspended`) | any | reported `suspended`; restored on resume | Origin reports it; consumers read it ({{child-state}}) |

## Child Mission State {#child-state}

A Child Mission has its own state, drawn from the issuance profile's
lifecycle state space ({{I-D.draft-mcguinness-oauth-mission}}). This
profile defines one child-specific terminal state:

`cascaded`:
: A terminal state a Child Mission enters when a terminal cascade
  trigger on its Parent Mission terminates it under `immediate` cascade
  ({{cascade}}). It is distinct from `revoked` (the child itself was not
  revoked) and `expired` (the child's own expiry was not reached), so
  audit can tell a cascade-terminated child from a directly terminated
  one. Following the issuance profile's forward-compatibility rule, a
  consumer treats `cascaded` as non-active, as it treats any state other
  than `active`. Mission Status
  ({{I-D.draft-mcguinness-oauth-mission-status}}) reports it among the
  terminal states, and a Mission lifecycle-change event
  ({{I-D.draft-mcguinness-oauth-mission-signals}}) carries it on the
  cascade transition.

A Child Mission also depends on parent state. For derivation under a
Child Mission, both conditions MUST hold:

- the Child Mission state is `active`; and
- the Parent Mission is active or the cascade mode and freshness rules
  still permit reliance on the prior active state.

If either condition fails, the Mission Issuer MUST refuse derivation.

While a parent is `suspended`, the origin MUST report each dependent
child's state as `suspended` on every state-reporting surface (the
Mission Status operation and token introspection,
{{I-D.draft-mcguinness-oauth-mission-status}}), and MUST restore the
child's own state when the parent resumes to `active`. A child whose own
`mission_expiry` passes during the suspension is `expired`: expiry takes
precedence over the projected `suspended` state.

Mission Status for a Child Mission SHOULD also include a parent
projection for authorized callers, as additional context:

`parent`:
: Object containing parent `id`, `origin`, current parent `state` when
  known, `cascade_mode`, and freshness information.

Consumers that cannot obtain parent state MUST obey the cascade mode:
for `status_required`, they MUST refuse; for `bounded_staleness`, they
MUST refuse after the bound; for `immediate`, they rely on the Mission
Issuer's child state transition.

# Child Evidence {#child-evidence}

The Mission Issuer MUST record a child delegation evidence record with:

- parent Mission identifier, origin, and authority hash;
- child Mission identifier, origin, and authority hash;
- child actor;
- requested and approved child authority;
- attenuation checks performed;
- fan-out counters or policy result;
- cascade mode;
- approval or policy basis; and
- creation time.

This evidence is audit material and does not grant authority.

## Child Evidence Object {#child-evidence-object}

A Child Evidence object is a JSON object {{RFC8259}} with:

`evidence_id`:
: REQUIRED. Unique identifier.

`parent`:
: REQUIRED. Parent Mission reference.

`child`:
: REQUIRED. Child Mission reference.

`child_actor`:
: REQUIRED. Child actor identity.

`attenuation`:
: REQUIRED. Object recording subset checks and result.

`fanout`:
: REQUIRED when fan-out controls apply. Object recording counters and
  policy.

`cascade_mode`:
: REQUIRED. Cascade mode.

`decision`:
: REQUIRED. One of `created` or `denied`.

`denial_reason`:
: REQUIRED when `decision` is `denied`.

`created_at`:
: REQUIRED. RFC 3339 {{RFC3339}} timestamp.

Example:

~~~ json
{
  "evidence_id": "chd_8K2nP4qV",
  "parent": {
    "id": "msn_parent_8RfX2Lqv9TqMv4z7sA2bN1k0",
    "origin": "https://as.example.com",
    "authority_hash":
      "sha-256:l3KvZ4mP5x0wQrR6tY2nD9bM7sX1cF8gH2vJ4kE5pNQ"
  },
  "child": {
    "id": "msn_child_2Yt7Qv9LqMv4z7sA2bN1k0",
    "origin": "https://as.example.com",
    "authority_hash":
      "sha-256:Td9bM7sX1cF8gH2vJ4kE5pNQl3KvZ4mP5x0wQrR6tY2"
  },
  "child_actor": {
    "sub": "subagent-contract-reviewer",
    "sub_profile": "ai_agent"
  },
  "attenuation": {
    "result": "strict_subset"
  },
  "fanout": {
    "active_children": 2,
    "max_children": 5
  },
  "cascade_mode": "immediate",
  "decision": "created",
  "created_at": "2026-11-02T08:14:00Z"
}
~~~

# Relationship to Expansion

Mission Expansion
{{I-D.draft-mcguinness-oauth-mission-expansion}} creates a successor
Mission that replaces a predecessor for a broader task. Child Mission
Delegation creates a dependent Mission for a child actor with narrower
authority. Expansion widens by fresh approval; Child Missions attenuate
within parent authority. The two MUST NOT be conflated.

A Child Mission MAY be expanded, but only within the parent's authority:
a successor Child Mission MUST remain a strict subset of the Parent
Mission's Authority Set ({{strict-subset}}) and keeps the same `parent`.
Expanding a Child Mission beyond its parent requires expanding the parent
first. Re-creation of children after a parent is expanded, and
re-parenting a Child Mission to a different parent, are deferred work.

# Composition with Offline Attenuation {#composition-attenuation}

A Child Mission's tokens MAY serve as attenuation roots under the
Mission Offline Attenuation profile
({{I-D.draft-mcguinness-oauth-mission-attenuation}}). The attenuation
chain's kill switch checks the Child Mission's state, and a parent stop
reaches the chain through cascade ({{cascade}}): when the parent
terminates, the Child Mission becomes non-active and the chain rooted on
its tokens stops at the next state check.

# Relationship to Harnesses

A Mission-aware harness
{{I-D.draft-mcguinness-mission-harness}} MUST NOT treat a
sub-agent handle as authority. When durable sub-agent work requires a
separate authority handle, the harness can request a Child Mission
under this profile.

# Authorization Server Metadata {#discovery}

A Mission Issuer that supports this profile SHOULD advertise it in its
authorization server metadata {{RFC8414}} so a parent agent can
discover child-delegation support before attempting child creation:

`mission_child_delegation_supported`:
: OPTIONAL boolean. When `true`, the Mission Issuer accepts the child
  creation request of {{child-creation}} and enforces the controls of
  this profile. A client MUST NOT infer the fan-out controls
  ({{fanout}}) a deployment enforces from this member alone; an
  unenforceable requested control is refused at creation
  ({{denial-reasons}}).

# Conformance {#conformance}

A conforming Child-Mission-capable Mission Issuer MUST:

- create Child Missions only through explicit authenticated requests;
- resolve the Parent Mission from a parent grant, not from the
  caller-supplied `parent` identifier alone;
- enforce strict-subset authority and expiry;
- enforce delegation and fan-out controls;
- record the `parent` member on child Mission records and tokens;
- implement cascade revocation; and
- record child delegation evidence.

A Resource Server does not need to understand this profile to enforce
child tokens as Mission-bound tokens. A Resource Server MUST NOT apply
lineage-sensitive policy from the `parent` member unless it implements
the semantics of the parent-member ({{parent-member}}) and cascade
({{cascade}}) sections.

# Security Considerations {#security-considerations}

## Authority by Ancestry

The primary threat is implicit authority inheritance: a child actor
acts because it descends from a parent session. This profile requires
explicit child Mission creation and rejects session ancestry as an
authorization basis.

## Fan-Out Amplification

Many child actors at the same depth can amplify authority even when
each child is a subset. Fan-out controls are required so deployments
can bound breadth as well as depth.

## Cascade Failure

If parent revocation does not reach children, child authority can
outlive its source. Cascade modes define how termination propagates and
how consumers bound stale parent state.

## Parent Confusion

An attacker could try to create a child under a parent it does not
control by naming a `parent` identifier. The Mission Issuer resolves
the parent from `parent_token`, not from the identifier, and verifies
the two match.

## Subset Bugs

Subset evaluation is the security core of this profile. Deployments
SHOULD keep subset rules deterministic and auditable, and SHOULD record
the exact parent entries used to justify each child entry.

# Privacy Considerations {#privacy-considerations}

The `parent` member exposes Mission lineage and can correlate child and
parent activity. Deployments SHOULD minimize cross-audience disclosure
of parent lineage when it is not needed for enforcement, and SHOULD
restrict child delegation evidence to authorized audit consumers.

# IANA Considerations {#iana}

This document registers three parameters in the "OAuth Parameters"
registry. For each: Parameter Usage Location authorization request;
Change Controller IETF; Reference this document, {{child-creation}}.

- `parent`
- `parent_token`
- `child_actor`

As with `mission_intent` in the issuance profile, PAR {{RFC9126}}
carries authorization-request parameters without a distinct usage
location, so the pushed submission of these parameters needs no
separate registration. `parent_token` carries a refresh token or other
parent grant and MUST be submitted only through PAR on the
authenticated back channel, never on a front-channel authorization
request ({{child-creation}}).

This document registers one member in the existing "OAuth Authorization
Server Metadata" registry {{RFC8414}}: Change Controller IETF; Reference
this document, {{discovery}}.

- `mission_child_delegation_supported`

Consistent with the issuance profile, which registers the `mission`
claim as an open object with no registry of its members, this document
defines the `parent` member of the `mission` claim
({{parent-member}}) without a separate claim registration: it is a
member defined by this profile, carried inside the already-registered
`mission` claim.

This document defines one closed set of symbolic codes: the child
creation denial reasons ({{denial-reasons}}). Like the issuance
profile's restraint with `mission` members, these are documented in
this specification rather than placed in a new IANA registry: they ride
in the `mission_denial_reason` member of the OAuth error response body
({{denial-reasons}}) and in evidence, inside existing OAuth error
responses rather than on a new wire surface, and the closed set is small
and fully specified here. Should interoperable extension
prove necessary, a future revision can create a "Mission Child
Delegation Denial Reason" registry with a Specification Required
{{RFC8126}} policy; this document does not create it.

--- back

# Acknowledgments
{:numbered="false"}

This document is part of the Mission-Bound Authorization for OAuth 2.0
set and defines explicit child authority for sub-agent work.
