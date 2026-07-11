---
title: "Mission Child Delegation for OAuth 2.0"
abbrev: "OAuth Mission Child Delegation"
category: std

docname: draft-mcguinness-oauth-mission-child-delegation-latest
submissiontype: IETF
workgroup: Web Authorization Protocol
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
  github: "mcguinness/mission-bound-authorization"
  latest: "https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-child-delegation.html"

author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com

normative:
  RFC3339:
  RFC7523:
  RFC8259:
  RFC8414:
  RFC8785:
  RFC9126:
  I-D.draft-mcguinness-oauth-mission:
    title: "Mission-Bound Authorization for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission.html
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
  I-D.draft-mcguinness-oauth-mission-expansion:
    title: "Mission Expansion for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-expansion.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026

informative:
  RFC8126:
  I-D.draft-mcguinness-oauth-client-instance-assertion:
  I-D.draft-mcguinness-oauth-ai-agent-instance:
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
  I-D.draft-mcguinness-oauth-mission-completion:
    title: "Mission Completion for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-completion.html
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
  I-D.draft-mcguinness-mission-harness:
    title: "Mission-Aware Agent Harnesses"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-harness.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026

--- abstract

Mission-Bound Authorization for OAuth 2.0 defines delegated tokens and
the rule that authority narrows down a delegation chain. Agent
harnesses, however, can spawn sub-agents whose work outlives a call
frame or crosses a different execution boundary. This document defines
an optional Mission Child Delegation profile. A parent Mission can
authorize a Child Mission for a sub-agent, with explicit parent
lineage, strict-subset authority, expiry no later than the parent,
separate child actor identity, fan-out controls, and cascade
termination when the parent Mission ends, with suspend-and-resume
propagation while the parent is suspended. Child creation is permitted
only where a parent entry's delegation policy carries a `children`
object, and child credentials never transit the parent. A Child
Mission is never created by session ancestry alone.

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
The dividing line is survivability: work that can outlive the
delegating flow, because it is queued, scheduled, or retried after
the delegator exits, or that needs its own revocation and audit
lifecycle, requires a Child Mission; work that cannot MAY run on a
delegated token. A harness applies the test at spawn, not by agent
design: the same sub-agent takes a delegated token when invoked
inline and a Child Mission when parked on a queue.
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

  A `child_actor` MAY be identified at instance granularity where the
  deployment authenticates client instances
  ({{I-D.draft-mcguinness-oauth-client-instance-assertion}}; for AI
  agents, {{I-D.draft-mcguinness-oauth-ai-agent-instance}}): `sub`
  carries the instance identifier and `sub_profile` the
  space-separated value list (for example,
  `ai_agent client_instance`). The child client-identity rule
  ({{child-client-identity}}), under which child credentials never
  transit the parent, composes naturally with instance-specific keys.

The Mission Issuer MUST resolve the parent from `parent_token`, verify
that it matches `parent`, verify that the parent is `active`, and verify
that the applicable parent Authority Set entry's `delegation` member
carries a `children` object ({{fanout}}) that permits child creation for
the requested authority.

The Mission Issuer MUST reject a child creation request presented on a
front channel with `parent_token`. The parent grant is presented only
on the authenticated back channel.

Presenting the parent's refresh token as `parent_token` MUST follow
the issuance profile's handling for that token: a sender-constrained
refresh token MUST be presented in conformance with its sender
constraint. Presenting the token for child creation MUST NOT rotate it
and MUST NOT register as a replay in the deployment's refresh-token
replay detection: the token is used here only to bind and resolve the
parent, not to refresh. Because that carve-out would let a stolen
bearer refresh token be presented repeatedly without detection, each
child-creation presentation MUST be recorded and counted toward the
deployment's anomaly detection, and a per-parent rate limit on child
creation requests is a MUST when the presented token is not
sender-constrained.

## Child Client Identity {#child-client-identity}

The child actor is the OAuth client of the Child Mission: its
identifier is the `client_id` of the Child Mission record. The child
actor authenticates itself at the token endpoint and redeems its own
grant for the Child Mission's tokens. Child credentials MUST NOT transit
the parent, and the parent MUST NOT hold child tokens.

The child's initial grant MUST be an audience-bound JWT authorization
grant that the child actor redeems as itself under the {{RFC7523}}
JWT-bearer grant, of the shape the Mission Issuance Grant profile
defines ({{I-D.draft-mcguinness-oauth-mission-issuance-grant}}): on
creating the Child Mission the Mission Issuer mints an assertion that
names the child actor as the authorized redeemer and the Mission
Issuer's token endpoint as the audience, and the child actor presents it
there authenticating with its own client credential. An authorization
code MUST NOT be used to convey the child's grant: a code and its
`request_uri` are redeemable only by the client that pushed the request
({{RFC9126}}), which is the parent, not the child. The child-bound
assertion is redeemable only by the child actor it names, so conveying
it through the parent gives the parent no ability to redeem it. How the
assertion reaches the child actor remains deployment-defined, subject to
the rules above.

Where creation is adjudicated by policy with no front channel, the
Mission Issuer completes the authorization without user interaction,
mints the same child-bound JWT authorization grant, and the child actor
redeems it as itself under the {{RFC7523}} JWT-bearer grant at the token
endpoint.

## Cross-Issuer Scope {#cross-issuer}

In this profile the Child Mission's issuer MUST equal `parent.issuer`
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
4. Verify the Parent Mission is `active` and no ancestor Mission in
   its lineage chain is non-active.
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

## Worked Example {#worked-example}

Under the Q3 reconciliation Mission
`msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-`, the approved agent
`s6BhdRkqt3`, acting for `alice`, spawns a read-only invoice
extraction sub-agent and submits a child Mission Intent through PAR
bound to the parent's grant (illustrative; this Mission's Authority
Set extends the single-domain walkthrough's, its read entry's
`delegation` carrying a `children` object ({{fanout}}), so its
anchors differ from that example's):

~~~ http
POST /par HTTP/1.1
Host: as.example.com
Content-Type: application/x-www-form-urlencoded

mission_intent=%7B...read-only%20Q3%20invoice%20extraction...%7D&
parent=msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-&
parent_token=<refresh%20token%20bound%20to%20the%20parent>&
child_actor=%7B%22sub%22%3A%22subagent-invoice-extractor%22%2C
  %22sub_profile%22%3A%22ai_agent%22%7D&
client_id=s6BhdRkqt3
~~~

The Mission Issuer processes the request per {{request-processing}}
and creates the Child Mission. The sub-agent then authenticates as
`subagent-invoice-extractor` at the token endpoint and redeems its own
grant ({{child-client-identity}}); no child credential transits the
parent. The decoded child access token:

~~~ json
{
  "iss": "https://as.example.com",
  "sub": "user_3p2q8mN1a0kV7tR",
  "aud": "https://erp.example.com",
  "client_id": "subagent-invoice-extractor",
  "iat": 1793607300,
  "exp": 1793607600,
  "jti": "at_5vB8nQ2xT7mK4rW1Zs9c",
  "authorization_details": [
    { "type": "mission_resource_access",
      "resource": "https://erp.example.com",
      "actions": ["invoices.read"],
      "constraints": {
        "resource_issued_after": "2026-07-01T00:00:00Z",
        "resource_issued_before": "2026-09-30T23:59:59Z"
      } }
  ],
  "cnf": { "jkt": "wZ5nT8qL2xV9rB4mC7sD1yF6jH3kP0aG5uE8oS2iN4w" },
  "mission": {
    "id": "msn_9KwP2rT6vX1nL4qY8sB3zC7mF5jD",
    "issuer": "https://as.example.com",
    "authority_hash":
      "sha-256:hQ2vJ4kE5pNQl3KvZ4mP5x0wRr6tY2nD9bM7sX1cF8g",
    "parent": {
      "id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
      "issuer": "https://as.example.com",
      "authority_hash":
        "sha-256:tY2nD9bM7sX1cF8gH2vJ4kE5pNQl3KvZ4mP5x0wQrR6",
      "depth": 1,
      "delegation_id": "dlg_7pQ4m",
      "cascade_mode": "immediate"
    }
  }
}
~~~

`mission.id` is the Child Mission and `mission.authority_hash` commits
the child Authority Set; the `parent` object is lineage, with `depth` 1
for a child of a root Mission. The `cnf` key is the sub-agent's own
({{child-client-identity}}).

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
body the symbolic reason rides in the `mission_denial_reason` member,
the shared adjudication-denial carrier defined and registered by the
expansion profile ({{I-D.draft-mcguinness-oauth-mission-expansion}}),
alongside the OAuth `error` member. A child creation request presented
on the front channel with `parent_token` MUST be rejected with
`invalid_request` ({{child-creation}}).

For example, a child Mission Intent that drops the parent entry's
`resource_issued_before` constraint proposes a relaxation, not a
subset. The
Mission Issuer refuses it ({{strict-subset}}) with:

~~~ json
{
  "error": "invalid_request",
  "mission_denial_reason": "not_strict_subset"
}
~~~

# The Parent Mission Reference {#parent-member}

A Child Mission carries a `parent` member in its Mission record and in
the `mission` claim of tokens derived under the child:

`parent`:
: REQUIRED for a Child Mission. An object containing:

  `id`:
  : REQUIRED. The Parent Mission identifier.

  `issuer`:
  : REQUIRED. The Parent Mission Issuer. The Child Mission's own
    `issuer` MUST equal this value ({{cross-issuer}}).

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
    "id": "msn_9KwP2rT6vX1nL4qY8sB3zC7mF5jD",
    "issuer": "https://as.example.com",
    "authority_hash":
      "sha-256:hQ2vJ4kE5pNQl3KvZ4mP5x0wRr6tY2nD9bM7sX1cF8g",
    "parent": {
      "id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
      "issuer": "https://as.example.com",
      "authority_hash":
        "sha-256:tY2nD9bM7sX1cF8gH2vJ4kE5pNQl3KvZ4mP5x0wQrR6",
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
actor, the child Authority Set, the child `authority_hash`, the child
Mission Intent's `intent_hash` ({{I-D.draft-mcguinness-oauth-mission}}),
the delegation event identifier, the cascade mode, and the fan-out
policy result. The `parent` value is immutable after creation.

The delegation event ({{child-creation}}) is the Child Mission's
approval event. It MUST commit the issuance profile's integrity anchors
({{I-D.draft-mcguinness-oauth-mission}}): `authority_hash` over the
child Authority Set and `intent_hash` over the child Mission Intent, and
it MUST produce the immutable, accountable record the core approval
event produces. A Child Mission is created under a parent grant rather
than a first-party approval ({{issuance-relationship}}), so its human
accountability is inherited from the Parent Mission's own approval.
Where the deployment requires a human approval event for child creation
({{child-creation}}), that event meets the issuance profile's
approval-event requirements in full and its human Approver is the
record's approver. Where creation is adjudicated by policy with no human
interaction ({{child-client-identity}}), the record's approver is the
adjudicating policy (identified by the `child_creation_policy` reference
where the entry carries one, {{fanout}}) together with the Subject and
Approver of the Parent Mission the parent grant resolves to, and the
record MUST mark the approval as policy-adjudicated rather than human.

# Attenuation Rules {#attenuation}

A Child Mission MUST be bounded by the Parent Mission:

- every child Authority Set entry MUST be a subset of a parent entry
  under the subset rule of {{I-D.draft-mcguinness-oauth-mission}};
- the child MUST NOT include a resource, action, constraint relaxation,
  or delegation right not present in the parent;
- the child's `expires_at` MUST NOT be later than the parent's
  `expires_at` (so it transitively caps every child-derived token's
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
does not define: the core's own opt-in hierarchy forms (`prefix`
resource containment and `.*` action families) apply as that rule
defines them, and nothing beyond them applies.

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
    Mission from this entry. Matchers are evaluated under the core's
    `allowed_delegates` matching rules, including the rule that a
    `{ "sub_profile": ... }` matcher is satisfied when its value is
    among the actor's space-separated `sub_profile` values.

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
`max_children` until the child reaches a terminal state.

Where a child entry is a subset of more than one parent entry, the
Mission Issuer MUST select exactly one parent entry as that child
entry's justification and count the child against that entry's
`max_children` alone. The selection MUST be deterministic: the Mission
Issuer selects the first parent entry, in Authority Set order, that the
child entry is a subset of. The recorded justification mapping (the
parent entry each child entry was derived from, {{child-evidence}}) is
the accounting basis: `max_children` is counted per justifying entry,
and the same mapping is what the child evidence records.

The Mission Issuer MUST serialize child creation against the same
parent entry and fan-out bucket so concurrent requests cannot exceed
the limit.

# Cascade Revocation {#cascade}

A Child Mission depends on the Parent Mission. A Mission's dependent
Child Missions are every transitive descendant: its Child Missions,
their children, and every further generation. The cascade trigger is
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

Cascade under this profile is issuer-committed. The Mission Issuer
MUST implement the `immediate` cascade mode and record the mode on the
Child Mission:

`immediate`:
: On a terminal trigger the Child Mission transitions to the `cascaded`
  state when the parent transition commits. On the reversible trigger
  the child is held non-active while the parent is suspended and
  restored to its prior state on parent resume.

Two consumer-verified cascade modes, `bounded_staleness` and
`status_required`, which trade issuer-committed transitions for
consumer-side parent-state checks, are experimental and defined in
{{experimental-cascade}}. A cascade mode MUST NOT allow a Child Mission
to continue deriving
new credentials after the parent is known to be non-active.

A consumer that does not recognize a Child Mission's `cascade_mode`
value MUST verify parent state, within the deployment's declared
freshness window, before each reliance on the child's authority: an
unrecognized mode may place the interim verification obligation on
the consumer.

Cascade modes may differ across one lineage. The Mission Issuer MUST
commit the terminal cascade transition for every dependent Child
Mission regardless of its cascade mode; the mode governs only what
consumers must verify in the interim. An `immediate`-mode descendant
under a consumer-verified parent is therefore never orphaned: its own
transition is committed even where the parent's is consumer-observed.

The cascade behavior by trigger:

| Trigger | Resulting child state | Who observes |
|---------|-----------------------|--------------|
| Terminal (`revoked`, `expired`, `completed`, `superseded`, `cascaded`) | `cascaded` (terminal) | Mission Issuer sets it; consumers read it from Mission Status or a lifecycle event |
| Reversible (`suspended`) | reported `suspended`; restored on resume | Issuer reports it; consumers read it ({{child-state}}) |

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

A Child Mission also depends on ancestor state. For derivation under a
Child Mission, both conditions MUST hold:

- the Child Mission state is `active`; and
- every ancestor Mission in its lineage chain, not only the immediate
  parent, is `active`.

If either condition fails, the Mission Issuer MUST refuse derivation.
A cascade in progress ({{cascade}}) opens no window: a descendant
whose root ancestor is non-active is refused derivation even before
its own cascade transition commits.

Where a deployment also runs the completion profile
({{I-D.draft-mcguinness-oauth-mission-completion}}), discharge
propagates entry-wise: when a parent Authority Set entry is
discharged, the Mission Issuer MUST discharge every child entry
justified by it, so spent authority does not survive in the subtree.
The issuer holds both records, so the propagation needs no consumer
coordination.

While a parent is `suspended`, the issuer MUST report each dependent
child's state as `suspended` on every state-reporting surface (the
Mission Status operation and token introspection,
{{I-D.draft-mcguinness-oauth-mission-status}}), and MUST restore the
child's own state when the parent resumes to `active`. A child whose own
`expires_at` passes during the suspension is `expired`: expiry takes
precedence over the projected `suspended` state.

Projection onset and lift are not silent. Each is a committed
metadata-only change on every affected child for the purposes of the
status profile's state version
({{I-D.draft-mcguinness-oauth-mission-status}}): the child's state
version increments at onset and again at lift, and, where the
deployment runs Lifecycle Signals
({{I-D.draft-mcguinness-oauth-mission-signals}}), a lifecycle-change
event is emitted for each affected child.

Likewise, once a terminal cascade trigger ({{cascade}}) commits at any
ancestor, the issuer MUST report each dependent descendant's state as
`cascaded` on every state-reporting surface (the Mission Status
operation and token introspection,
{{I-D.draft-mcguinness-oauth-mission-status}}) from that commit, ahead
of each descendant's own per-generation transition. The transitive
transitions still commit in generation order ({{cascade}}); this rule
bounds only what a consumer reads, so a consumer keying on a
descendant's own state never reads `active` mid-cascade.

Expiry takes precedence over `cascaded` as it does over the projected
`suspended` state: where a child's own `expires_at` coincides with a
terminal cascade of its parent (for example, a child whose `expires_at`
equals the parent's on parent expiry), the child's own `expired` state
wins and it is reported `expired`, not `cascaded`. This matches the
`cascaded` state, which a child enters only when its own expiry was not
reached.

Mission Status for a Child Mission SHOULD also include a parent
projection for authorized callers, as additional context:

`parent`:
: Object containing parent `id`, `issuer`, current parent `state` when
  known, `cascade_mode`, and freshness information.

Under `immediate` cascade a consumer needs no parent-state check of its
own: it relies on the Mission Issuer's child state transition, read
from the child's own state surfaces. The consumer obligations of the
experimental consumer-verified modes are defined with those modes
({{experimental-cascade}}).

# Child Evidence {#child-evidence}

The Mission Issuer MUST record a child delegation evidence record with:

- parent Mission identifier, issuer, and authority hash;
- child Mission identifier, issuer, and authority hash;
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
    "id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
    "issuer": "https://as.example.com",
    "authority_hash":
      "sha-256:tY2nD9bM7sX1cF8gH2vJ4kE5pNQl3KvZ4mP5x0wQrR6"
  },
  "child": {
    "id": "msn_9KwP2rT6vX1nL4qY8sB3zC7mF5jD",
    "issuer": "https://as.example.com",
    "authority_hash":
      "sha-256:hQ2vJ4kE5pNQl3KvZ4mP5x0wRr6tY2nD9bM7sX1cF8g"
  },
  "child_actor": {
    "sub": "subagent-invoice-extractor",
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

## Canonical Bytes {#child-evidence-canonical}

A Child Evidence object's canonical bytes are its JCS {{RFC8785}}
canonicalization, and its type identifier is
`application/mission-child-evidence+json`, used by local agreement
pending registration. An audit or transparency profile registers the
object by these values.

# Relationship to Expansion

Mission Expansion
{{I-D.draft-mcguinness-oauth-mission-expansion}} creates a successor
Mission that replaces a predecessor for a broader task. Mission Child
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

Cascade reaches derivation at the commit of each transition: once a
terminal trigger commits, no dependent Child Mission derives again.
Outstanding child access tokens run to the earlier of the token's
`exp` and the runtime staleness bound, where the runtime enforcement
layer is deployed. A deployment that needs prompt cascade uses short
child-token lifetimes.

## Parent Confusion

An attacker could try to create a child under a parent it does not
control by naming a `parent` identifier. The Mission Issuer resolves
the parent from `parent_token`, not from the identifier, and verifies
the two match.

## Parent Grant at Rest in PAR

A child creation request carries `parent_token`, a refresh token or
other parent grant, through PAR {{RFC9126}}, so that credential sits at
rest in the PAR store until the pushed request is redeemed or expires. A
deployment MUST protect the PAR store as credential storage: it SHOULD
hold `parent_token` only until its `request_uri` is redeemed or expires
and then delete it, MUST NOT write `parent_token` to request logs,
traces, or audit records in the clear, and MUST redact or hash it
wherever the pushed request is otherwise recorded. Child delegation
evidence ({{child-evidence}}) records the parent Mission by identifier
and authority hash, never the parent grant itself.

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
in the shared `mission_denial_reason` member defined and registered by
the expansion profile
({{I-D.draft-mcguinness-oauth-mission-expansion}}) and in evidence,
inside existing OAuth error responses rather than on a new wire
surface, and the closed set is small and fully specified here. This
document therefore requires no registration for the member. Should
interoperable extension prove necessary, the expansion profile's IANA
considerations anticipate a shared "Mission Denial Reason" registry
with a Specification Required {{RFC8126}} policy; this document does
not create it.

--- back

# Experimental Consumer-Verified Cascade Modes {#experimental-cascade}

This appendix is **experimental**: adopt it for evaluation, not as a
stable interface. It defines two cascade modes that trade the
issuer-committed transition of `immediate` ({{cascade}}) for
consumer-side parent-state checks, for deployments where the Mission
Issuer cannot commit child transitions synchronously with the parent's.
Each shifts a per-reliance obligation onto every consumer of child
tokens, which is why they are not part of the base profile.

`bounded_staleness`:
: The Child Mission is treated as non-active no later than the cascade
  staleness bound, measured from the consumer's last confirmed-active
  observation of the parent, aligned with the Status profile's freshness
  model ({{I-D.draft-mcguinness-oauth-mission-status}}). That bound is
  the deployment's `mission_max_stale_seconds`
  ({{I-D.draft-mcguinness-oauth-mission-status}}) unless the deployment
  publishes a different bound for child cascade. Under this mode a
  non-terminal child counts against `max_children`
  ({{fanout-accounting}}) until the cascade window has closed or the
  child is otherwise confirmed non-active.

`status_required`:
: Consumers MUST check parent state, per reliance decision and within
  the deployment's declared freshness window
  ({{I-D.draft-mcguinness-oauth-mission-status}}), before accepting
  child Mission authority. The Mission Issuer MUST select this mode only
  where every audience of child tokens is known, by registration or
  deployment policy, to implement this profile's parent-state check;
  otherwise the Mission Issuer MUST compensate with short child-token
  lifetimes or introspection-required paths.

The cascade behavior by trigger and mode:

| Trigger | Mode | Resulting child state | Who observes |
|---------|------|-----------------------|--------------|
| Terminal | `bounded_staleness` | non-active by the staleness bound | Consumer, from its last confirmed-active parent observation |
| Terminal | `status_required` | non-active on the next parent-state check | Consumer, per reliance decision |

A consumer that cannot obtain parent state MUST obey the mode: for
`status_required`, it MUST refuse; for `bounded_staleness`, it MUST
refuse after the bound. For derivation under these modes, the Mission
Issuer MAY rely on a prior confirmed-active parent observation within
the mode's freshness rules where it cannot observe the parent
synchronously; a Child Mission MUST NOT derive after the parent is
known to be non-active. The `immediate` rules of {{cascade}} and
{{child-state}} otherwise apply unchanged.

# Acknowledgments
{:numbered="false"}

This document is part of the Mission-Bound Authorization for OAuth 2.0
set and defines explicit child authority for sub-agent work.
