---
title: "Mission-Aware Agent Harnesses"
abbrev: "Mission Harness"
category: std

docname: draft-mcguinness-mission-harness-latest
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
  github: "mcguinness/mission-bound-authorization"
  latest: "https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-harness.html"

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
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-oauth-mission-latest
  I-D.draft-mcguinness-oauth-mission-status:
    title: "Mission Status and Lifecycle for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-status.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-oauth-mission-status-latest
  I-D.draft-mcguinness-mission-runtime:
    title: "Mission-Bound Runtime Enforcement"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-runtime.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-mission-runtime-latest

informative:
  I-D.draft-mcguinness-oauth-client-instance-assertion:
  I-D.draft-mcguinness-oauth-ai-agent-instance:
  I-D.draft-mcguinness-oauth-mission-signals:
    title: "Mission Lifecycle Signals for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-signals.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-oauth-mission-signals-latest
  I-D.draft-mcguinness-oauth-mission-expansion:
    title: "Mission Expansion for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-expansion.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-oauth-mission-expansion-latest
  I-D.draft-mcguinness-oauth-mission-child-delegation:
    title: "Mission Child Delegation for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-child-delegation.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-oauth-mission-child-delegation-latest
  I-D.draft-mcguinness-mission-orchestration:
    title: "Mission Orchestration and Unwinding"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-orchestration.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-mission-orchestration-latest

--- abstract

Agent harnesses preserve execution state across restarts, retries,
background jobs, tool-connection reuse, and sub-agent orchestration.
That continuity is not authority. This document defines an optional
Mission-aware harness profile for deployments using Mission-Bound
Authorization, with OAuth 2.0 as this version's normative substrate.
It specifies how a harness binds sessions, task graphs, queues, cached
tool connections, and sub-agent handles to Mission state; when it must
re-check Mission status; and how it must pause, suppress, or terminate
work when the Mission is no longer active. For the action classes a
deployment mediates, the harness also establishes the mediated
execution environment: governed work runs with no path to those
actions that bypasses the enforcement point, and the harness publishes
an execution-environment scope statement. A conforming harness never
treats session continuity as proof that Mission authority continues.

--- middle

# Introduction

Mission-Bound Authorization for OAuth 2.0
{{I-D.draft-mcguinness-oauth-mission}} (the "issuance profile") governs
the authority under which an agent acts. The runtime profile
{{I-D.draft-mcguinness-mission-runtime}} governs per-action
enforcement. Agent harnesses add a separate layer: they preserve
execution state so work can resume after process restarts, device
handoffs, background scheduling, retries, and sub-agent fan-out.

Harness continuity is useful, but it is not authority. A task graph can
survive after the Mission that justified it is revoked. A cached tool
connection can remain usable after the business condition that
authorized it ends. A child agent can keep running after its parent
Mission is suspended. This profile defines what a harness must do to
avoid treating recoverable runtime state as authorization. That is one
of the harness's two duties; the other is establishing the mediated
execution environment, in which work in a mediated action class has no
path that bypasses the enforcement point ({{mediated-egress}}).

# Scope

This document defines:

- the mediated execution environment the harness establishes
  ({{mediated-egress}});
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
{{I-D.draft-mcguinness-mission-runtime}}.

## Harness Boundary {#harness-boundary}

This profile applies to harness-managed continuity state, including:

- saved conversation or planning state;
- task graph nodes;
- background jobs;
- retry queues;
- child agent handles;
- tool-connection caches;
- workspace or artifact handles;
- runtime permits and single-use decision identifiers held by the
  harness ({{I-D.draft-mcguinness-mission-runtime}}); and
- credential references managed by the harness.

It does not require a harness to inspect application data unrelated to
governed execution (defined in {{conventions}}). It does require the
harness to know when a piece of continuity state is governed by a
Mission and to stop using that state as an execution basis when the
Mission is no longer active.

# Conventions and Terminology {#conventions}

{::boilerplate bcp14-tagged}

This document uses the terms Mission, Mission Issuer, and Mission state
from {{I-D.draft-mcguinness-oauth-mission}} and
{{I-D.draft-mcguinness-oauth-mission-status}}; the term Mission-bound
token as defined by the issuance profile
{{I-D.draft-mcguinness-oauth-mission}} and used by the runtime profile
{{I-D.draft-mcguinness-mission-runtime}}; and Policy Enforcement
Point (PEP) and mediated execution from the runtime profile
{{I-D.draft-mcguinness-mission-runtime}}.

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
: Harness-managed work that can invoke an action class or execution
  path in the deployment's declared runtime enforcement scope
  ({{I-D.draft-mcguinness-mission-runtime}}). Whether a work item
  is governed follows from the deployment's documented mapping of work
  items to that scope: a published artifact, not a per-item
  reachability judgment.

# Mission Substrate {#mission-substrate}

This profile is defined against the Mission model rather than against
OAuth 2.0 mechanics. It consumes these substrate primitives: the
Mission identifier; the lifecycle state space with its
only-`active`-permits rule and the deployment's freshness sources; the
Mission-bound credentials the harness holds or mediates, with their
sender-constraint custody, when the binding in use provides them; and
the evidence integrity conventions imported from the runtime profile.
The Mission-bound credential primitive is binding-dependent: under a
binding without Mission-bound credentials, the harness binds governed
work items to the externally established Mission reference of the
runtime profile's Mission binding establishment step
({{I-D.draft-mcguinness-mission-runtime}}), and the custody duties of
{{cached-access}} apply to whatever acting credentials the deployment
uses. The issuance profile
{{I-D.draft-mcguinness-oauth-mission}} is this version's normative
substrate; every OAuth artifact named in this document enters through
it. Another substrate that provides the same primitives can host this
profile unchanged.

# Mission Mediation {#mediated-egress}

The runtime profile's credential custody and mediated execution
({{I-D.draft-mcguinness-mission-runtime}}) hold only if the agent
has no path to a consequential resource that bypasses the Policy
Enforcement Point. Establishing that environment is the harness's
responsibility, and it is the complement to the runtime layer holding
the sender-constraint key: custody is moot if the agent can reach the
resource off-path.

For the action classes a deployment mediates
({{I-D.draft-mcguinness-mission-runtime}}), a Mission-aware
harness MUST run governed consequential work in an execution environment
whose only path to those actions is through the mediating PEP. It MUST
NOT leave an unmediated route to a mediated class, such as a debug
shell, a direct network socket, an unsanctioned egress route, or a
direct connector that does not pass the runtime gate. A harness that
cannot guarantee this for an action class MUST NOT represent work in
that class as runtime-enforced, matching the enforcement-scope rule of
the runtime profile.

The harness MUST publish an execution-environment scope statement. For
each mediated action class it states the isolation mechanism that
confines governed work (for example a container, virtual machine, or
network egress policy) and names the unmediated paths excluded from the
claim. The statement also declares the deployment's taint policy
({{session-taint}}). Verifying that no unmediated path exists is a
deployment audit obligation, not a protocol property: this profile
fixes what the statement declares, not how a deployment proves it.

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
  ({{I-D.draft-mcguinness-mission-orchestration}}) reuses it
  rather than defining its own.

`enforcement_scope`:
: OPTIONAL. A string or object identifying the runtime enforcement
  scope that applies to this session or node.

`stop_policy`:
: REQUIRED for governed work. The policy the harness applies when the
  Mission is non-active or stale: one of the stop-behavior values
  `suppress`, `pause`, `terminate`, or `handoff` ({{stop-behavior}}),
  or a deployment-defined policy.

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
   {{I-D.draft-mcguinness-mission-runtime}} that includes a
   current Mission state check for the action about to run; or
4. another deployment-defined state source with equivalent freshness
   semantics.

If the harness cannot establish active state within the bound, it MUST
NOT resume governed work.

## Resume Algorithm {#resume-algorithm}

The resume check follows one sequence:

~~~
 load binding --> establish Mission state --> active?
                                                |  |
                                          no <--+  +--> yes
                                          |            |
                                     stop behavior   continue
                                          |            |
                                          +---> evidence <---+
~~~

Before resuming a governed item, the harness performs:

1. Load the Mission binding.
2. If no Mission binding is present, refuse to resume as governed work
   and emit Harness Evidence with reason `missing_mission_binding`.
3. Establish Mission state through {{resume-checks}}.
4. If state is not `active`, apply stop behavior under {{stop-behavior}}.
5. Hold this invariant: freshness MUST be valid at the moment each
   consequential action is submitted to the runtime gate. The harness
   does not predict future timing; if freshness is not valid at
   submission, it refreshes status or defers the action to a runtime
   decision.
6. Resume only the item whose binding was checked. Sibling or child
   items require their own check unless the deployment's status lease
   explicitly covers them.

Where the orchestration profile
({{I-D.draft-mcguinness-mission-orchestration}}) is also deployed,
the harness MUST NOT resume a governed item that the orchestrator has
cancelled, or is holding for review, under its in-flight handling, even
when the Mission is `active`. An orchestration unwind decision is not a
Mission-state change, so the resume check above does not catch it; for
items under an active unwind plan the harness defers to the
orchestrator's in-flight decision.

The harness MUST perform this algorithm even when OAuth credentials in
the session are still valid.

## Interaction with the Orchestration Profile {#orchestration-interaction}

A deployment running both this profile and the orchestration profile
({{I-D.draft-mcguinness-mission-orchestration}}) MUST provide a
means for the harness to determine whether a work item is under an
active unwind decision. The mechanism is deployment-defined.

Where harness stop policy and an active unwind decision would produce
different outcomes for the same work item, the stricter outcome
governs. The harness records its decision in Harness Evidence and the
orchestrator records its decision in Orchestration Evidence, and the
two records cross-link through their evidence identifiers.

# Event-Driven State Cache {#event-cache}

This section is OPTIONAL. A harness MAY maintain an event-driven
Mission state cache using
{{I-D.draft-mcguinness-oauth-mission-signals}}. The cache entry for a
Mission MUST contain:

- Mission identifier and issuer;
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

The object below is a RECOMMENDED representation, not a wire format: a
harness MAY represent queued work in any internal structure, provided
the requirements attached to these members hold for the equivalent
information. What is normative is the behavior: the Mission binding,
the resume check before dispatch, and the expiry and retry rules of
this section. A governed queue item carries:

`queue_item_id`:
: REQUIRED. A string.

`mission_binding`:
: REQUIRED. The Mission binding from {{mission-binding}}.

`action_class`:
: REQUIRED when known. The runtime action class.

`not_before`:
: OPTIONAL. An RFC 3339 timestamp.

`expires_at`:
: An RFC 3339 timestamp after which the item MUST NOT run. REQUIRED for
  a high-consequence action class
  ({{I-D.draft-mcguinness-mission-runtime}}) unless the
  deployment sets a maximum queue age for that class; OPTIONAL
  otherwise.

`retry_of`:
: OPTIONAL. Identifier of the prior attempt.

`idempotency_key`:
: REQUIRED when retrying an action whose runtime profile requires one.

When `expires_at` has passed, the harness MUST suppress the queue item
even if Mission state remains active.

A queued item in a high-consequence action class that crossed a
non-active period before dispatch MUST obtain a fresh action-bound
approval ({{I-D.draft-mcguinness-mission-runtime}}) before it
runs. Its earlier place in the queue is not a standing approval across
a Mission non-active interval.

Example: a queued `journal-entries.write` posting under the Q3
invoice-reconciliation Mission, retried once. `expires_at` is present
because the posting is in a high-consequence action class:

~~~ json
{
  "queue_item_id": "queue_journal_post_7",
  "mission_binding": {
    "mission_id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
    "mission_origin": "https://as.example.com",
    "authority_hash":
      "sha-256:l3KvZ4mP5x0wQrR6tY2nD9bM7sX1cF8gH2vJ4kE5pNQ",
    "status_checked_at": "2026-11-01T22:00:00Z",
    "status_expires_at": "2026-11-01T22:05:00Z",
    "state": "active",
    "state_source": "status",
    "stop_policy": "suppress"
  },
  "action_class": "external_commitment",
  "not_before": "2026-11-02T02:00:00Z",
  "expires_at": "2026-11-02T06:00:00Z",
  "retry_of": "queue_journal_post_6",
  "idempotency_key": "idem_jrnl_2026q3_0042"
}
~~~

Before dispatching this item at 02:00, the harness re-runs the resume
check: the binding's status lease expired at 22:05, so the recorded
`active` state is not a basis to continue.

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

On any stop event ({{stop-behavior}}), the harness MUST also mark
unusable any runtime permit and single-use decision identifier
({{I-D.draft-mcguinness-mission-runtime}}) it holds for the
affected Mission. A fresh PDP decision is REQUIRED after any non-active
interval; the harness MUST NOT dispatch a consequential action on a
permit obtained before that interval.

## Cache Keys and Cross-Mission Reuse {#cache-keys}

A cached credential, tool connection, or connector handle used for
governed work MUST be keyed by at least:

- Mission identifier and issuer;
- audience or protected resource;
- client or actor identity;
- sender-constraint key when applicable; and
- authority hash when known.

The harness MUST NOT reuse a cached connection across Missions unless
the connection carries no authority and every consequential use is
separately authorized under the target Mission. A warm connection to a
tool server is not a permit to call a tool.

A workspace or artifact handle bound to a Mission is subject to the
same rules as a cached connection: it MUST be keyed by the Mission
identifier and issuer, and the harness MUST mark it unusable for
governed work on the stop events of this section. A retained workspace
is not a basis to resume governed work under a Mission that is no
longer active.

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

An independent Mission is one whose authority does not derive from the
stopped Mission: it is not a Child Mission of the stopped Mission or of
any of its ancestors. A harness MUST NOT classify a Mission whose
authority cascades from the stopped one as independent, since that child
is itself no longer active.

The harness MUST emit evidence for each dependent child it leaves
running under an independent Mission.

When the harness requests child termination, it MUST record the
termination outcome in Harness Evidence as one of `acknowledged`,
`timed_out`, or `unknown`. Until it has confirmation that the child
stopped, the harness MUST treat the child as still running and fail
closed for any cached access that depends on it, mirroring the
cancellation rule of the orchestration profile
({{I-D.draft-mcguinness-mission-orchestration}}).

Where the deployment authenticates agent instances
({{I-D.draft-mcguinness-oauth-client-instance-assertion}}; for AI
agents, {{I-D.draft-mcguinness-oauth-ai-agent-instance}}), the harness
SHOULD record the instance identifier (`agent_instance_id`, or the
instance `sub`) in its Mission binding ({{mission-binding}}) and in
sub-agent termination evidence, giving stop propagation and its
evidence a which-runtime dimension: which concrete instance was asked
to stop, and which confirmed. Sub-agent chains under the agent
instance profile cannot shed identity, which strengthens the
fail-closed rule above: an unconfirmed stop names the exact instance
the harness treats as still running.

# Harness Execution States {#harness-states}

A governed work item is in one of the following harness execution
states. Harness Evidence types `prior_harness_state` and
`resulting_harness_state` ({{harness-evidence-object}}) against this
enumeration.

| State | Meaning |
|---|---|
| `running` | The item is dispatched and executing under an active Mission. |
| `suppressed` | The item is not dispatched; state is preserved for audit or review. |
| `paused` | The item is suspended pending an authorized lifecycle transition. |
| `terminated` | The item's task graph is ended and its runtime resources released. |
| `handoff` | The item is escalated to a human or governance workflow. |

This enumeration is the evidence vocabulary, not an internal
state-machine requirement: a harness MAY run any internal execution
states, provided each governed item's condition maps onto one of these
values when Harness Evidence is emitted.

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
| `superseded` | suppress; rebinding requires a fresh derivation under the successor Mission |
| `cascaded` | suppress or terminate |
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

## Human-Review Outcomes {#review-outcomes}

When the harness hands off a governed item to human review, the review
concludes with one of three outcomes:

`approve`:
: The reviewer permits the work to continue.

`reject`:
: The reviewer refuses the work.

`expire`:
: The item reached its parked maximum age without a review decision.

A parked item MUST carry a deployment maximum age. The harness MUST
record the outcome, its authority basis, and the reviewer in Harness
Evidence. Resumed work re-enters the resume algorithm
({{resume-algorithm}}): review approval is not itself a Mission-state
check.

# Untrusted Content and Egress {#session-taint}

A prompt-injected agent is constrained at the point of use by the
runtime layer, which gates each action against the Mission
({{I-D.draft-mcguinness-mission-runtime}}). The runtime layer
evaluates each action in isolation; it does not see the session as a
whole. The harness does: it mediates tool input and output and tracks
session and task-graph history against Mission state. That makes the
harness the one layer that can apply a taint rule against the case
where untrusted content drives an agent to exfiltrate within its
authority.

Taint is classed by source. Content from the Subject or the Approver
does not taint; the deployment's **content trust list** extends that
baseline to the sources it vouches for, such as first-party tools, its
own catalogs, and designated corpora. Content from an unlisted source,
or from a source the deployment explicitly marks untrusted (web
fetches, inbound messages, third-party documents), is **tainted**.

The trigger is parameter provenance where the harness can establish
it. Because the harness mediates tool input and output, it SHOULD
track at the data plane which tainted source a value derives from. The
egress rule below then applies when a bound parameter of a
consequential external-communication or external-commitment action
derives from tainted content. Session-level taint remains the
fallback where provenance is unavailable: the harness applies the rule
to every such action in a governed session that tainted content has
entered.

The rule: the harness SHOULD either require a fresh action-bound
approval ({{I-D.draft-mcguinness-mission-runtime}}) or downgrade that
authority (suppress the action), rather than let the agent egress on
the strength of injected content. This is the plan-then-execute
pattern: untrusted content may inform the agent's planning, but it
MUST NOT, on its own, drive an egress the Subject did not direct.

The taint policy MUST be declared in the execution-environment scope
statement ({{mediated-egress}}): the content trust list, the trigger
granularity (parameter provenance, session-level, or both), and the
fallback where provenance is unavailable. The claim is then
inspectable: an auditor reads what taints, what triggers, and what
happens when tracking runs out.

This remains a coarse control, not information-flow control, though
source classing and parameter provenance give it discriminating power:
it gates the egress whose inputs derive from untrusted content and
leaves trusted-provenance egress ungated, instead of gating every
egress in any session any content entered. Data-plane provenance does
not survive model inference, so a value the agent paraphrases rather
than copies can shed its taint, and the control cannot close
within-scope data laundering
({{I-D.draft-mcguinness-oauth-mission}},
{{I-D.draft-mcguinness-mission-runtime}}); it raises the bar by
forcing a human or a fresh approval between untrusted input and
egress. A harness that applies it records the taint source class, the
provenance where established, and the resulting downgrade or approval
in Harness Evidence ({{harness-evidence}}).

# Harness Evidence {#harness-evidence}

A Mission-aware harness MUST emit a Harness Evidence record when it
suppresses, pauses, or terminates governed work due to Mission state,
and when it reverses a stop decision to resume work. It need not emit a
record for every routine continuation. It MAY aggregate or sample
`resume_allowed` records under a documented policy, provided every
stop, and every reversal of a stop, remains individually recorded.

The Harness Evidence Object ({{harness-evidence-object}}) is the
authoritative definition of the record's members. The following is a
non-normative summary of what a record carries:

- `event_id`;
- the `mission` object (`id`, `issuer`, and, when known,
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
({{I-D.draft-mcguinness-mission-runtime}}). It records
execution-continuity decisions, not Resource Server authorization.

Harness Evidence records are subject to the record integrity and
retention requirements of the runtime profile
({{I-D.draft-mcguinness-mission-runtime}}), imported here by
reference: append-only integrity protection under a named mechanism, a
per-Mission sequence indicator, no raw parameters in the record, and a
retention window no shorter than the Mission's audit horizon.

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
: REQUIRED. Object containing `id`, `issuer`, and, when known,
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
  decision, each a value from the harness execution states of
  {{harness-states}} (for example, `running` to `suppressed`).

`state_source`:
: REQUIRED. A value from the single `state_source` enumeration of
  {{mission-binding}}.

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
    "issuer": "https://as.example.com",
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

# Worked Example {#example}

An agent reconciling Q3 invoices under Mission
`msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-` runs as an overnight background
job, so its session outlives `alice`'s attention. Two harness moments
matter.

At 02:00 the job resumes a queued task graph. Before dispatching any
governed work the harness re-reads Mission state ({{resume-checks}}).
`alice` cancelled the Mission at 23:00, so the harness finds it
`revoked`: it does not dispatch, marks cached ERP connections unusable
({{cached-access}}), and emits the suppress evidence shown above. The
session was fully recoverable; the authority that justified it was gone,
and the harness let the Mission, not the session, decide.

Earlier, while still active, the agent fetched a vendor email into its
working context to extract an invoice number. Inbound mail is not on
the deployment's content trust list, so the harness marks the fetched
text tainted and tracks what derives from it ({{session-taint}}). Two
egress attempts follow. The agent posts a journal entry whose amount
and invoice reference derive from ERP records; the ERP connector is a
first-party tool on the trust list, so no bound parameter carries
taint, and the posting proceeds under the ordinary runtime gate. Then
the agent, steered by text in the email, tries to send an external
message whose body derives from that text: the bound parameters carry
tainted provenance, so the harness requires a fresh action-bound
approval before the egress. The runtime layer would gate both calls
against the Mission regardless; the harness adds the rule that
untrusted input cannot, by itself, drive an egress `alice` never
directed.

# Conformance {#conformance}

A conforming Mission-aware harness MUST:

- bind governed sessions, queued work, and task graph nodes to Mission
  references;
- check active Mission state before resume, retry dispatch, background
  wake-up, and cached access use;
- suppress governed work when Mission state cannot be established or is
  non-active;
- run governed consequential work in a mediated execution environment
  for the action classes a deployment mediates, and publish the
  execution-environment scope statement ({{mediated-egress}});
- prevent sub-agent authority by session ancestry;
- emit Harness Evidence for stop and resume decisions; and
- document a staleness bound per action class and its stop behavior.

The runtime profile's non-normative freshness table
({{I-D.draft-mcguinness-mission-runtime}}) is the calibration
reference for these per-action-class bounds.

A harness MUST NOT claim conformance for work it cannot suppress. It
MAY claim conformance for a documented subset of execution paths if it
identifies paths outside the claim.

# Security Considerations {#security-considerations}

## Harness Compromise {#sec-harness-compromise}

The harness is a trusted component. If it is compromised, some
protections survive and others fall.

What survives a harness compromise is the enforcement that does not
run in the harness: Resource-Server-side PEPs still gate each action,
issuance gating still bounds what authority can exist, and Mission
revocation still terminates authority at its source. A compromised
harness cannot manufacture Mission authority the issuer never granted.

What falls is everything the harness alone mediates:
local-tool mediation, session-level suppression, and taint control.
A compromised harness can resume suppressed work, ignore its own stop
decisions, and drive egress that the taint rule was meant to hold.

Because of this split, a deployment that claims the runtime profile's
agent-compromise-resistant enforcement
({{I-D.draft-mcguinness-mission-runtime}}) MUST isolate the
mediating PEP and its sender-constraint key custody from the
agent-facing harness components, by process, host, or service
separation. A harness that both faces the agent and holds the
sender-constraint key defeats mediated custody: its compromise yields
the key.

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
