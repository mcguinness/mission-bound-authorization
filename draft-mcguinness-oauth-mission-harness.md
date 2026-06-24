---
title: "Mission-Aware Agent Harnesses for OAuth 2.0"
abbrev: "OAuth Mission Harness"
category: std

docname: draft-mcguinness-oauth-mission-harness-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
keyword:
 - oauth
 - mission
 - agent
 - harness
 - session
venue:
  github: "mcguinness/draft-mcguinness-oauth-mission"
  latest: "https://mcguinness.github.io/draft-mcguinness-oauth-mission/draft-mcguinness-oauth-mission-harness.html"

author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com

normative:
  RFC3339:
  RFC8259:
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
  I-D.draft-mcguinness-oauth-mission-runtime:
    title: "Mission-Bound Runtime Enforcement for OAuth 2.0"
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-oauth-mission-runtime-latest

informative:
  I-D.draft-mcguinness-oauth-mission-signals:
    title: "Mission Lifecycle Signals for OAuth 2.0"
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-oauth-mission-signals-latest
  I-D.draft-mcguinness-oauth-mission-expansion:
    title: "Mission Expansion for OAuth 2.0"
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-oauth-mission-expansion-latest
  I-D.draft-mcguinness-oauth-mission-child-delegation:
    title: "Child Mission Delegation for OAuth 2.0"
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-oauth-mission-child-delegation-latest
  I-D.draft-mcguinness-oauth-mission-orchestration:
    title: "Mission Orchestration and Unwinding for OAuth 2.0"
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-oauth-mission-orchestration-latest

--- abstract

Agent harnesses preserve execution state across restarts, retries,
background jobs, tool-connection reuse, and sub-agent orchestration.
That continuity is not authority. This document defines an OPTIONAL
Mission-aware harness profile for deployments using Mission-Bound
Authorization for OAuth 2.0. It specifies how a harness binds sessions,
task graphs, queues, cached tool connections, and sub-agent handles to
Mission state; when it must re-check Mission status; and how it must
pause, suppress, or terminate work when the Mission is no longer
active. A conforming harness never treats session continuity as proof
that Mission authority continues.

--- middle

# Introduction

Mission-Bound Authorization for OAuth 2.0
{{I-D.draft-mcguinness-oauth-mission}} governs the authority under
which an agent acts. The runtime profile
{{I-D.draft-mcguinness-oauth-mission-runtime}} governs per-action
enforcement. Agent harnesses add a separate layer: they preserve
execution state so work can resume after process restarts, device
handoffs, background scheduling, retries, and sub-agent fan-out.

Harness continuity is useful, but it is not authority. A task graph can
survive after the Mission that justified it is revoked. A cached tool
connection can remain usable after the business condition that
authorized it ends. A child agent can keep running after its parent
Mission is suspended. This profile defines what a harness must do to
avoid treating recoverable runtime state as authorization.

# Scope

This document defines:

- the Mission binding a harness records on sessions and task graph
  nodes ({{mission-binding}});
- resume-time checks ({{resume-checks}});
- queued work and retry behavior ({{queues}});
- cached credential and tool-connection handling ({{cached-access}});
- sub-agent handle requirements ({{subagents}});
- harness evidence ({{harness-evidence}}); and
- conformance for a Mission-aware harness ({{conformance}}).

This document does not define a new OAuth token, a new agent protocol,
or a replacement for Resource Server enforcement. A harness check does
not replace a PEP at the last controllable boundary under
{{I-D.draft-mcguinness-oauth-mission-runtime}}.

## Harness Boundary {#harness-boundary}

This profile applies to harness-managed continuity state, including:

- saved conversation or planning state;
- task graph nodes;
- background jobs;
- retry queues;
- child agent handles;
- tool-connection caches;
- workspace or artifact handles; and
- credential references managed by the harness.

It does not require a harness to inspect application data unrelated to
governed execution. It does require the harness to know when a piece of
continuity state is governed by a Mission and to stop using that state
as an execution basis when the Mission is no longer active.

# Conventions and Terminology {#conventions}

{::boilerplate bcp14-tagged}

This document uses the terms Mission, Mission Issuer, Mission-bound
token, and Mission state from
{{I-D.draft-mcguinness-oauth-mission}} and
{{I-D.draft-mcguinness-oauth-mission-status}}.

Harness:
: The runtime system that preserves and resumes agent execution state,
  including sessions, task graphs, queues, tool handles, and sub-agent
  handles.

Harness session:
: A harness-local continuity record. It is distinct from an IdP
  session, browser session, OAuth authorization session, or access
  token.

Mission binding:
: The Mission reference and status freshness information the harness
  records on a session or task graph node.

Governed work:
: Harness-managed work that can lead to a consequential action under a
  Mission.

# Mission Binding {#mission-binding}

A Mission-aware harness MUST bind every governed session and governed
task graph node to a Mission reference:

`mission_id`:
: REQUIRED. The Mission identifier.

`mission_origin`:
: REQUIRED. The Mission Issuer.

`authority_hash`:
: REQUIRED when known. The Authority Set commitment from the Mission
  claim.

`status_checked_at`:
: REQUIRED when the harness has checked status. An RFC 3339 timestamp.

`status_expires_at`:
: REQUIRED when the harness relies on a status lease. An RFC 3339
  timestamp after which the status MUST NOT be used for continuation.

`state`:
: REQUIRED when known. The last Mission state established by the
  harness.

`state_source`:
: REQUIRED when `state` is present. One of `status`, `signal`,
  `runtime_decision`, `harness`, `operator`, or a deployment-defined
  source: `status` and `signal` name the Mission Status and Lifecycle
  Signals surfaces, `runtime_decision` a runtime enforcement decision,
  `harness` a harness stop decision, and `operator` a human operator
  action. This enumeration is the shared `state_source` value space for
  Mission-aware execution evidence; the orchestration profile
  ({{I-D.draft-mcguinness-oauth-mission-orchestration}}) reuses it
  rather than defining its own.

`enforcement_scope`:
: OPTIONAL. A string or object identifying the runtime enforcement
  scope that applies to this session or node.

`stop_policy`:
: REQUIRED for governed work. The policy the harness applies when the
  Mission is non-active or stale.

The Mission binding grants no authority. It is the pointer that tells
the harness which Mission state it must check before continuing work.

## Binding Inheritance {#binding-inheritance}

When a harness creates a child task graph node, queue item, background
job, or sub-agent handle from governed work, it MUST copy or narrow the
Mission binding. It MUST NOT create an unbound child item that can later
perform governed work without a Mission check.

If a child item is governed by a different Mission, the harness MUST
record the distinct Mission binding and the relationship to the parent
item.

# Resume Checks {#resume-checks}

Before resuming governed work, a Mission-aware harness MUST establish
that the Mission is `active` within the deployment's staleness bound.
Resume includes:

- process restart;
- device or worker handoff;
- background job wake-up;
- retry after failure;
- tool-call continuation after an asynchronous response;
- loading a saved workspace for further action;
- refreshing or reacquiring credentials; and
- dispatching a queued task graph node.

The harness establishes state through one of:

1. a Mission Status operation under
   {{I-D.draft-mcguinness-oauth-mission-status}};
2. a valid event-driven state cache maintained from
   {{I-D.draft-mcguinness-oauth-mission-signals}};
3. a runtime PDP decision under
   {{I-D.draft-mcguinness-oauth-mission-runtime}} that includes a
   current Mission state check for the action about to run; or
4. another deployment-defined state source with equivalent freshness
   semantics.

If the harness cannot establish active state within the bound, it MUST
not resume governed work.

## Resume Algorithm {#resume-algorithm}

Before resuming a governed item, the harness performs:

1. Load the Mission binding.
2. If no Mission binding is present, refuse to resume as governed work
   and emit Harness Evidence with reason `missing_mission_binding`.
3. Establish Mission state through {{resume-checks}}.
4. If state is not `active`, apply stop behavior under {{stop-behavior}}.
5. If state is active but freshness expires before the next
   consequential action can be reached, refresh status or require a
   runtime decision at that action.
6. Resume only the item whose binding was checked. Sibling or child
   items require their own check unless the deployment's status lease
   explicitly covers them.

The harness MUST perform this algorithm even when OAuth credentials in
the session are still valid.

# Event-Driven State Cache {#event-cache}

This section is OPTIONAL. A harness MAY maintain an event-driven
Mission state cache using
{{I-D.draft-mcguinness-oauth-mission-signals}}. The cache entry for a
Mission MUST contain:

- Mission identifier and origin;
- last observed state;
- event identifier or sequence when available;
- event issuance time;
- cache freshness expiry; and
- stream or issuer identity.

The harness MUST ignore events whose issuer, audience, signature, or
ordering cannot be verified under the Signals profile. If expected
events are not received within the deployment's freshness bound, the
harness MUST treat the cache as stale and fall back to status polling
or stop governed continuation.

# Queues and Retries {#queues}

A queued work item under a Mission MUST carry the Mission binding of
{{mission-binding}}. Before dispatching it, the harness MUST run the
resume check of {{resume-checks}}.

Retries do not inherit authority from the prior attempt. A retry MUST
be treated as a new continuation point and MUST re-check Mission state
unless the retry occurs within an unexpired status lease whose use is
allowed for that action class.

When Mission state is not `active`, the harness MUST suppress queued
items for that Mission. It MAY preserve them for audit or operator
review, but MUST NOT dispatch them until a conforming authority path
permits continuation.

## Queue Item Object {#queue-item}

A governed queue item has:

`queue_item_id`:
: REQUIRED. A string.

`mission_binding`:
: REQUIRED. The Mission binding from {{mission-binding}}.

`action_class`:
: REQUIRED when known. The runtime action class.

`not_before`:
: OPTIONAL. An RFC 3339 timestamp.

`expires_at`:
: OPTIONAL. An RFC 3339 timestamp after which the item MUST NOT run.

`retry_of`:
: OPTIONAL. Identifier of the prior attempt.

`idempotency_key`:
: REQUIRED when retrying an action whose runtime profile requires one.

When `expires_at` has passed, the harness MUST suppress the queue item
even if Mission state remains active.

# Cached Credentials and Tool Connections {#cached-access}

A harness often caches OAuth tokens, MCP sessions, API clients, browser
contexts, or connector handles. A Mission-aware harness MUST NOT treat
cached access as evidence that a Mission remains active.

Before using a cached credential or tool connection for governed work,
the harness MUST:

1. verify the cached item is still cryptographically and protocol-valid;
2. verify the Mission is active under {{resume-checks}}; and
3. verify the action still passes runtime enforcement when the action is
   consequential.

When a Mission becomes non-active, the harness MUST mark cached
connections associated with that Mission unusable for new governed
work. If the cache can safely close or revoke them, it SHOULD do so.

## Cache Keys and Cross-Mission Reuse {#cache-keys}

A cached credential, tool connection, or connector handle used for
governed work MUST be keyed by at least:

- Mission identifier and origin;
- audience or protected resource;
- client or actor identity;
- sender-constraint key when applicable; and
- authority hash when known.

The harness MUST NOT reuse a cached connection across Missions unless
the connection carries no authority and every consequential use is
separately authorized under the target Mission. A warm connection to a
tool server is not a permit to call a tool.

# Sub-Agent Handles {#subagents}

Sub-agents and child workers MUST NOT inherit Mission authority merely
because they descend from a parent session. A harness that starts a
sub-agent for governed work MUST bind the sub-agent handle to:

- the parent Mission reference;
- the actor or client identity of the sub-agent;
- the authority or child Mission under which it may act; and
- any delegation or child-Mission constraints that apply.

If the parent Mission becomes non-active, the harness MUST suppress or
terminate child work that depends on it, unless the child has a
separate active Mission whose authority does not depend on the parent.

When a sub-agent needs authority not already delegated to it, the
harness MUST obtain a governed delegation or child Mission. Session
ancestry alone MUST NOT be used as authorization.

## Sub-Agent Stop Propagation {#subagent-stop}

When the harness stops a parent item because its Mission is non-active,
it MUST identify child handles whose authority depends on that Mission.
For each dependent child, it MUST apply one of:

- suppress queued child work;
- request child termination;
- revoke or close child-specific cached connections where supported;
- mark child state as requiring human review; or
- record that the child is governed by an independent active Mission.

The harness MUST emit evidence for each dependent child it leaves
running under an independent Mission.

# Stop Behavior {#stop-behavior}

When a Mission is `revoked`, `expired`, `suspended`, `completed`, or
otherwise non-active under the deployment's lifecycle profile, the
harness MUST stop governed continuation. The stop behavior is one of:

`suppress`:
: Do not dispatch queued or resumable work. Preserve state for audit or
  future review.

`pause`:
: Suspend work pending an authorized lifecycle transition, such as
  `resume`.

`terminate`:
: End the task graph and release associated runtime resources.

`handoff`:
: Escalate to a human or governance workflow without performing further
  governed actions.

The harness MAY choose among these based on deployment policy and
action class, but it MUST NOT continue governed execution while Mission
state is non-active.

## Stop-Behavior Matrix {#stop-matrix}

The harness MUST document a matrix mapping Mission state and action
class to stop behavior. At minimum:

| Mission state | Minimum behavior |
|---|---|
| `revoked` | suppress or terminate |
| `expired` | suppress or terminate |
| `suspended` | pause or suppress |
| `completed` | suppress or terminate |
| `superseded` | suppress and require successor Mission binding |
| unknown or stale | suppress or pause |

The non-core states in this matrix are defined by companion profiles a
deployment may run: `suspended` and `completed` by Mission Status
({{I-D.draft-mcguinness-oauth-mission-status}}), `superseded` by Mission
Expansion ({{I-D.draft-mcguinness-oauth-mission-expansion}}), and
`cascaded` by Child Mission Delegation
({{I-D.draft-mcguinness-oauth-mission-child-delegation}}). The harness
needs none of those profiles to be conformant: per the issuance
profile's forward-compatibility rule, it treats any state other than
`active`, including one it does not recognize, as non-active and stops
governed continuation accordingly. The named rows are the minimum
behavior where a deployment does run the defining profile.

For irreversible actions, external commitments, and privileged
administration, `handoff` or orchestration handling under a deployment
unwind plan SHOULD be used when work may already be in flight.

# Harness Evidence {#harness-evidence}

A Mission-aware harness MUST emit evidence when it suppresses, pauses,
terminates, or resumes governed work due to Mission state. The evidence
record SHOULD contain:

- `event_id`;
- the `mission` object (`id`, `origin`, and, when known,
  `authority_hash`), the same shape as the `mission` claim of
  {{I-D.draft-mcguinness-oauth-mission}};
- `session_id`;
- task graph node or queue item identifier;
- prior and resulting harness state;
- Mission state observed;
- status source and freshness;
- timestamp; and
- actor or sub-agent identifier when applicable.

A Harness Evidence record carries the Mission as the nested `mission`
object, mirroring the `mission` claim; the flat `mission_id` and
`mission_origin` of Mission Binding ({{mission-binding}}) are a binding
key, whereas the evidence record mirrors the claim shape.

Harness Evidence complements runtime enforcement evidence
({{I-D.draft-mcguinness-oauth-mission-runtime}}). It records
execution-continuity decisions, not Resource Server authorization.

## Harness Evidence Object {#harness-evidence-object}

A Harness Evidence object is a JSON object {{RFC8259}} with:

`event_id`:
: REQUIRED. A unique identifier.

`event_type`:
: REQUIRED. One of `resume_allowed`, `resume_suppressed`,
  `queue_suppressed`, `cache_disabled`, `subagent_stopped`,
  `subagent_continued`, or `mission_state_stale`. `event_type`
  categorizes the work item the record is about; the `decision` member
  records the outcome, so the two are orthogonal.

`mission`:
: REQUIRED. Object containing `id`, `origin`, and, when known,
  `authority_hash`.

`session_id`:
: OPTIONAL. Harness session identifier.

`work_item`:
: OPTIONAL. Task graph node, queue item, background job, or child
  handle identifier.

`actor`:
: OPTIONAL. The actor or sub-agent identifier the record concerns, when
  applicable (for example, the child whose work was stopped or
  continued under a `subagent_stopped` or `subagent_continued` event).

`state`:
: REQUIRED. The Mission state observed or `unknown`.

`prior_harness_state`, `resulting_harness_state`:
: OPTIONAL. The harness execution state before and after the recorded
  decision (for example, `running` to `suppressed`).

`state_source`:
: REQUIRED. One of `status`, `signal`, `runtime_decision`, or a
  deployment-defined source, as in {{mission-binding}}.

`freshness`:
: OPTIONAL. Object containing `checked_at` and `expires_at`.

`decision`:
: REQUIRED. One of `continue`, `suppress`, `pause`, `terminate`, or
  `handoff`.

`reason`:
: REQUIRED. String reason.

`occurred_at`:
: REQUIRED. RFC 3339 {{RFC3339}} timestamp.

Example:

~~~ json
{
  "event_id": "hrn_7pQ4mN9s",
  "event_type": "resume_suppressed",
  "mission": {
    "id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
    "origin": "https://as.example.com",
    "authority_hash":
      "sha-256:l3KvZ4mP5x0wQrR6tY2nD9bM7sX1cF8gH2vJ4kE5pNQ"
  },
  "session_id": "sess_agent_42",
  "work_item": "queue_invoice_retry_9",
  "state": "revoked",
  "state_source": "signal",
  "decision": "suppress",
  "reason": "mission_not_active",
  "occurred_at": "2026-11-02T08:16:00Z"
}
~~~

# Conformance {#conformance}

A conforming Mission-aware harness MUST:

- bind governed sessions, queued work, and task graph nodes to Mission
  references;
- check active Mission state before resume, retry dispatch, background
  wake-up, and cached access use;
- suppress governed work when Mission state cannot be established or is
  non-active;
- prevent sub-agent authority by session ancestry;
- emit Harness Evidence for stop and resume decisions; and
- document its staleness bounds and stop behavior.

A harness MUST NOT claim conformance for work it cannot suppress. It
MAY claim conformance for a documented subset of execution paths if it
identifies paths outside the claim.

# Security Considerations {#security-considerations}

## Session Continuity Is Not Authority Continuity

The primary threat is treating recoverable runtime state as proof of
continuing authority. This profile requires a fresh Mission-state
decision at continuation points where harnesses would otherwise resume
automatically.

## Cached Access as Ambient Authority {#sec-cached-access}

Cached credentials and tool connections can bypass visible issuance or
authorization steps. A harness MUST tie cache use to Mission state and
runtime enforcement, or cached access becomes ambient authority.

## Sub-Agent Fan-Out

Implicit sub-agent inheritance can amplify authority. This profile
requires explicit Mission or delegation binding for child handles and
cascade stop behavior when parent authority ends.

## Split-Brain Session State

Multiple workers may resume the same session or queue item. A harness
SHOULD use compare-and-set or equivalent concurrency control so a stop
decision cannot race with a resume decision. When the state is
ambiguous, fail closed and suppress governed work.

## Tool Cache Confusion

Tool connection caches often hide which Mission first authorized a
connection. Cache keys under {{cache-keys}} prevent a connection opened
for one Mission from becoming ambient authority for another.

# Privacy Considerations {#privacy-considerations}

Harness Evidence and Mission bindings can reveal task graphs,
workspace identifiers, tool usage, agent topology, and Mission
relationships. Deployments SHOULD minimize retained harness state,
control access to evidence, and avoid storing raw workspace content in
Harness Evidence unless required for audit.

# IANA Considerations {#iana}

This document makes no IANA request.

--- back

# Acknowledgments
{:numbered="false"}

This document is part of the Mission-Bound Authorization for OAuth 2.0
set and defines how agent harnesses keep runtime continuity separate
from Mission authority.
