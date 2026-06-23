---
title: "Child Mission Delegation for OAuth 2.0"
abbrev: "OAuth Child Missions"
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
  RFC2119:
  RFC8174:
  RFC3339:
  RFC8259:
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
  I-D.draft-mcguinness-oauth-mission-harness:
    title: "Mission-Aware Agent Harnesses for OAuth 2.0"
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-oauth-mission-harness-latest

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

The issuance profile {{I-D.draft-mcguinness-oauth-mission}} supports
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
the strict-subset rule, and the lifecycle and issuance gating. It uses
the terms Agent (Client), Subject, Approver, Mission Issuer, Mission
Intent, Authority Set, Mission, and derived token as defined there.

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

## Child Mission Versus Delegated Token {#child-vs-token}

A delegated token is appropriate when the delegate performs work within
the lifetime and operational control of the delegating flow. A Child
Mission is appropriate when the child actor needs a durable Mission
handle of its own: for example, a sub-agent with a queue, background
job, independent harness session, or separate audit lifecycle.

A Child Mission is not a way to widen authority. It is a way to create
a narrower, separately accountable authority record for a child actor.

## Child Delegation Versus Act-Chain Delegation {#child-vs-act}

This profile's child delegation is distinct from the in-Mission
delegation the issuance profile already defines. In-Mission delegation
extends a single Mission's `act` chain to additional actors, bounded by
the per-entry `delegation` policy (`allowed_delegates`, `max_depth`) of
{{I-D.draft-mcguinness-oauth-mission}}; no new Mission is created and
authority is exercised under the original Mission. Child delegation, by
contrast, creates a separate Child Mission with its own `mission_id`,
actor, lifecycle, and `act` chain.

Where this profile reuses the parent entry's `delegation` policy, it
does so only to decide whether child creation is permitted and which
`child_actor` is eligible: the parent entry's `delegation` member MUST
explicitly permit child delegation, and `allowed_delegates` constrains
the `child_actor` the parent may name. The issuance profile's `act`
`max_depth` bounds act-chain nesting within a Mission and is not a
child-generation counter; a Child Mission's own `act` chain restarts at
depth 0. Child-generation depth and breadth are governed instead by the
fan-out controls of {{fanout}}.

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
  under the Child Mission.

Delegation event:
: The Mission Issuer event that creates the Child Mission and records
  the attenuation checks from parent to child.

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
  execute under the Child Mission.

The Mission Issuer MUST resolve the parent from `parent_token`, verify
that it matches `parent`, verify that the parent is `active`, and verify
that the parent Authority Set permits child delegation for the requested
authority.

The Mission Issuer MUST reject a child creation request presented on a
front channel with `parent_token`. The parent grant is presented only
on the authenticated back channel.

## Protocol Flow {#protocol-flow}

~~~
 Parent agent / harness        Mission Issuer (AS)
        |                             |
        | 1. PAR: child Mission       | resolve parent
        |    Intent + parent grant -->| verify active;
        |                             | verify delegation
        |<------- request_uri --------|
        |                             |
        | 2. approval or policy ----->| create child Mission
        |    adjudication             | record parent member
        |<---------- code ------------|
        |                             |
        | 3. token request ---------->| derive child token
        |<------ access token --------|
~~~

The approval or policy adjudication in step 2 is deployment-specific.
A deployment MAY require a human approval event for Child Mission
creation or MAY allow policy to approve child creation when the parent
Mission's Authority Set explicitly permits it.

## Request Processing {#request-processing}

The Mission Issuer processes child creation in this order:

1. Authenticate the client submitting the PAR request.
2. Resolve the Parent Mission from `parent_token`.
3. Verify the resolved Mission matches `parent`.
4. Verify the Parent Mission is `active`.
5. Verify the parent grant permits the requester to create a child.
6. Verify `child_actor` satisfies the parent entry's delegation
   constraints.
7. Derive the child Authority Set and verify strict subset.
8. Apply fan-out controls.
9. Adjudicate approval or policy.
10. Create the Child Mission record with `parent`.
11. Record Child Evidence.

Failure at any step MUST prevent child creation.

## Child Creation Denial Reasons {#denial-reasons}

This profile defines these symbolic denial reasons:

`parent_not_active`:
: The Parent Mission is not active.

`parent_mismatch`:
: The caller-supplied `parent` does not match the Mission resolved from
  `parent_token`.

`delegation_not_permitted`:
: The Parent Mission or applicable Authority Set entry does not permit
  child delegation.

`child_actor_not_allowed`:
: The child actor does not satisfy `allowed_delegates` or equivalent
  policy.

`not_strict_subset`:
: The proposed child authority is not a strict subset of parent
  authority.

`fanout_exceeded`:
: Creating the child would exceed a fan-out control.

`policy_denied`:
: Deployment policy denied child creation.

These symbolic strings appear in error bodies, evidence, and audit,
layered on the OAuth error codes the issuance profile uses:
`parent_not_active` and `parent_mismatch` accompany `invalid_grant`;
`delegation_not_permitted`, `child_actor_not_allowed`,
`not_strict_subset`, and `fanout_exceeded` accompany `invalid_request`;
and `policy_denied` accompanies `access_denied`. A child creation
request presented on the front channel with `parent_token` MUST be
rejected with `invalid_request` ({{child-creation}}).

# The `parent` Member {#parent-member}

A Child Mission carries a `parent` member in its Mission record and in
the `mission` claim of tokens derived under the child:

`parent`:
: REQUIRED for a Child Mission. An object containing:

  `id`:
  : REQUIRED. The Parent Mission identifier.

  `origin`:
  : REQUIRED. The Parent Mission Issuer.

  `authority_hash`:
  : REQUIRED. The Parent Mission authority commitment the child was
    derived under.

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

Example:

~~~ json
{
  "mission": {
    "id": "msn_child_2Yt7Qv9LqMv4z7sA2bN1k0",
    "origin": "https://as.example.com",
    "authority_hash":
      "sha-256:Td9bM7sX1cF8gH2vJ4kE5pNQl3KvZ4mP5x0wQrR6tY2n",
    "parent": {
      "id": "msn_parent_8RfX2Lqv9TqMv4z7sA2bN1k0",
      "origin": "https://as.example.com",
      "authority_hash":
        "sha-256:l3KvZ4mP5x0wQrR6tY2nD9bM7sX1cF8gH2vJ4kE",
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
  `delegation` policy permits child delegation ({{child-vs-act}}), and
  any delegation policy on a child entry MUST be strictly narrower than
  the parent entry's;
- non-delegable parent entries MUST NOT appear in child authority; and
- child authority MUST be bound to the child actor identified in the
  request.

The Mission Issuer MUST compute the Child Mission's `authority_hash`
over the child Authority Set, not over the parent Authority Set. A
Resource Server enforces child tokens exactly as Mission-bound tokens:
the child `authority_hash` is the immediate authority commitment.

## Subset Evaluation {#strict-subset}

The child Authority Set subset test is the subset rule of
{{I-D.draft-mcguinness-oauth-mission}}, applied between each child entry
and a parent entry: every child resource equal to or narrower than a
parent resource; every child action a subset of (or deployment-defined
as narrower than) a parent action; every child constraint equal to or
stricter than the corresponding parent constraint; and no parent
constraint removed unless the constrained authority is also removed.
This profile adds one strict requirement specific to child delegation:
a child entry's delegation policy MUST be strictly narrower than the
parent entry's (lower `max_depth`, no broader `allowed_delegates`).

If the Mission Issuer cannot prove the child Authority Set is a subset
of the parent, it MUST refuse child creation with `not_strict_subset`.

# Fan-Out Controls {#fanout}

Depth limits alone do not control breadth. A Parent Mission MAY permit
many Child Missions at the same depth unless policy limits fan-out.

A Child-Mission-capable Mission Issuer MUST support at least one
fan-out control:

`max_child_missions`:
: Maximum number of Child Missions that can be active under a Parent
  Mission or Authority Set entry.

`allowed_child_actors`:
: A constraint on which actors or actor classes may receive Child
  Missions.

`child_creation_policy`:
: A policy reference evaluated before each child creation.

If a parent entry carries a fan-out control the Mission Issuer cannot
enforce, it MUST refuse child creation for that entry.

## Fan-Out Accounting {#fanout-accounting}

The Mission Issuer MUST count active Child Missions against fan-out
limits until the child is non-active. If cascade is
`bounded_staleness`, the child counts until the cascade window has
closed or the child is otherwise confirmed non-active.

The Mission Issuer MUST serialize child creation against the same
parent and fan-out bucket so concurrent requests cannot exceed the
limit.

# Cascade Revocation {#cascade}

A Child Mission depends on the Parent Mission. When the Parent Mission
becomes non-active (`revoked` or `expired`
({{I-D.draft-mcguinness-oauth-mission}}); `suspended` or `completed`
({{I-D.draft-mcguinness-oauth-mission-status}})), the Mission Issuer
MUST prevent new derivation under dependent Child Missions. The
`superseded` state ({{I-D.draft-mcguinness-oauth-mission-expansion}}) is
treated specially: rather than cascade-revoking the children, the
Mission Issuer SHOULD re-bind dependent Child Missions to the successor
Mission, or apply deployment policy, since under expansion the task
continues under the successor.

The Mission Issuer MUST implement one of these cascade modes and record
it on the Child Mission:

`immediate`:
: The Child Mission transitions to a non-active state when the parent
  transition commits.

`bounded_staleness`:
: The Child Mission is treated as non-active no later than the
  deployment's published cascade staleness bound.

`status_required`:
: Consumers MUST check parent state through Mission Status before
  accepting child Mission authority.

The cascade mode MUST NOT allow a Child Mission to continue deriving
new credentials after the parent is known to be non-active.

## Child Mission State {#child-state}

A Child Mission has its own state and also depends on parent state. For
derivation under a Child Mission, both conditions MUST hold:

- the Child Mission state is `active`; and
- the Parent Mission is active or the cascade mode and freshness rules
  still permit reliance on the prior active state.

If either condition fails, the Mission Issuer MUST refuse derivation.

Mission Status for a Child Mission SHOULD include a parent projection
for authorized callers:

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
      "sha-256:l3KvZ4mP5x0wQrR6tY2nD9bM7sX1cF8gH2vJ4kE"
  },
  "child": {
    "id": "msn_child_2Yt7Qv9LqMv4z7sA2bN1k0",
    "origin": "https://as.example.com",
    "authority_hash":
      "sha-256:Td9bM7sX1cF8gH2vJ4kE5pNQl3KvZ4mP5x0wQrR6tY2n"
  },
  "child_actor": {
    "sub": "subagent-contract-reviewer",
    "type": "ai_agent"
  },
  "attenuation": {
    "result": "strict_subset"
  },
  "fanout": {
    "active_children": 2,
    "max_child_missions": 5
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

# Relationship to Harnesses

A Mission-aware harness
{{I-D.draft-mcguinness-oauth-mission-harness}} MUST NOT treat a
sub-agent handle as authority. When durable sub-agent work requires a
separate authority handle, the harness can request a Child Mission
under this profile.

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
child tokens as Mission-bound tokens. A Resource Server that performs
lineage-sensitive policy, however, MUST understand the `parent` member
before relying on it.

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

Consistent with the issuance profile, which registers the `mission`
claim as an open object with no registry of its members, this document
defines the `parent` member of the `mission` claim
({{parent-member}}) without a separate claim registration: it is a
member defined by this profile, carried inside the already-registered
`mission` claim.

This document defines one closed set of symbolic codes: the child
creation denial reasons ({{denial-reasons}}). Like the issuance
profile's restraint with `mission` members, these are documented in
this specification rather than placed in a new IANA registry: they are
conveyed inside existing OAuth error responses and evidence at
deployment-defined locations, not on a new wire surface, and the closed
set is small and fully specified here. Should interoperable extension
prove necessary, a future revision can create a "Mission Child
Delegation Denial Reason" registry with a Specification Required
{{RFC8126}} policy; this document does not create it.

--- back

# Acknowledgments
{:numbered="false"}

This document is part of the Mission-Bound Authorization for OAuth 2.0
set and defines explicit child authority for sub-agent work.
