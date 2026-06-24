<!-- regenerate: off (edited by hand; set to on to let i-d-template regenerate) -->

# Mission-Bound Authorization for OAuth 2.0

This is the working area for a family of individual Internet-Drafts that
add the **Mission**, a durable, approval-backed *governance* object, to
OAuth 2.0. A Mission is not a new way to express authority; it is the
approved task, with a lifecycle, that authority is derived for, bound
to, and gated on.

## The problem

OAuth 2.0 issues access tokens for individual resource requests. It has
no durable, approved artifact that represents the larger task a client
is pursuing on a user's behalf. That gap matters for AI agents: an agent
is typically given a *mission* (book the trip, reconcile the ledger,
triage the inbox) and then takes many actions, across many resources,
over a long time, often spawning sub-agents and surviving restarts. A
bag of independently-issued access tokens cannot express "this is the
task the user approved, here is its boundary, and here is when it ends."

## The mission

This work defines the Mission: a durable object, created by an explicit
approval event, that expresses an approved task and its lifecycle. The
Mission does not itself express authority; that is the job of the
Authority Set. Rich Authorization Requests express authority, a Mission
expresses the approved task it is bound to. A client proposes a
**Mission Intent**; the Authorization Server derives an **Authority
Set** (the concrete resources, actions, and constraints) for it; an
**approval event** commits both as integrity anchors (`intent_hash` and
`authority_hash`); and every derived token carries a `mission` claim
binding it back to that approved task. Token issuance is
gated on Mission state, so revoking or expiring the Mission stops all
further authority for the task at once. Authority can only narrow as it
flows down to derived and delegated tokens; widening requires a fresh
approval.

A small mandatory **core** defines that model. Everything else is an
OPTIONAL companion profile that layers on the core without changing it.

## How the documents fit together

```
        Mission Intent Shaping  (propose a Mission Intent)
                           |
                           |  Pushed Authorization Request (PAR)
                           v
   +===========================================================+
   |  ISSUANCE CORE: Mission-Bound Authorization               |
   |                                                           |
   |  Mission Intent --> Authority Set --> approval event      |
   |  commits intent_hash + authority_hash --> Mission-bound   |
   |  token with the "mission" claim; issuance gated on        |
   |  Mission state (active / revoked / expired)               |
   +===========================================================+
        |                                |
        |  Consent Evidence              |  the agent acts
        |  commits what the              |  with the token
        |  Approver was shown            v
        |                   +=================================+
        |                   |  RUNTIME ENFORCEMENT:           |
        |                   |  Runtime contract + AuthZEN     |
        |                   |  per-action PEP --> PDP check   |
        |                   |  against the Mission            |
        |                   +=================================+
        v
     (audit)

   OPTIONAL companion profiles, layered on the core:

     Lifecycle      Status      query state; revoke/suspend/resume/complete
                    Signals     lifecycle-change events (push or poll)
                    Expansion   widen authority via a new approval

     Sub-agents     Child Mission Delegation   strict-subset child
                    Missions with cascade revocation

     Agent runtime  Harness        session continuity is not authority
                    Orchestration  unwind in-flight work safely
```

One rule keeps this extensible without a central registry: only the
state `active` permits issuance or continued reliance, and a consumer
treats every other state, including one it does not recognize, as
non-active. A state a companion profile adds (such as `suspended`,
`superseded`, or `cascaded`) therefore fails safe for a consumer that
predates it.

## Recommended deployment bundles

The drafts are independently optional, so a conforming issuance
deployment can omit properties many readers assume from "Mission-bound
agents": action-time checks, prompt stop, unwinding, and consent
evidence. These bundles name what to deploy together for a given goal.

| Bundle | Drafts | What you get |
|---|---|---|
| **Baseline issuance** | mission | Approved, integrity-bound Missions; state-gated issuance; a possession-independent kill switch. Audit, not action-time defense. |
| **Enforced agent** | mission + runtime + authzen + status + signals | Per-action enforcement at the point of use, and prompt revocation. The minimum for an agent that takes consequential actions. |
| **Governed agent (recommended for AI agents)** | Enforced agent + consent-evidence + harness + orchestration | Consent-rendering evidence, session-continuity stop, and safe unwinding. Add child-delegation for sub-agents and expansion for mid-task growth. |

Each draft also states its own scoped conformance; the bundles are
guidance, not a new conformance class.

## The documents

Together these drafts form the **Mission-Bound Authorization suite**.
The first is the mandatory core; the rest are OPTIONAL companion
profiles. The companions refer to the core as the **"issuance profile"**
(it governs issuance and derivation), and "Mission-Bound Authorization
for OAuth 2.0" is the title the core shares with the suite it anchors.

### Core

#### Mission-Bound Authorization for OAuth 2.0

The mandatory core, the **issuance profile**. Defines the Mission, the
Mission Intent and Authority Set, the approval event and its
`intent_hash` / `authority_hash` integrity anchors, the `mission` token
claim, the subset rule, and state-gated issuance. Every other document
builds on this one.

* [Editor's Copy](https://mcguinness.github.io/draft-mcguinness-oauth-mission/#go.draft-mcguinness-oauth-mission.html)
* [Datatracker Page](https://datatracker.ietf.org/doc/draft-mcguinness-oauth-mission)
* [Individual Draft](https://datatracker.ietf.org/doc/html/draft-mcguinness-oauth-mission)
* [Compare Editor's Copy to Individual Draft](https://mcguinness.github.io/draft-mcguinness-oauth-mission/#go.draft-mcguinness-oauth-mission.diff)

### Runtime enforcement

#### Mission-Bound Runtime Enforcement for OAuth 2.0

A decision contract for enforcing a Mission-bound token at the point of
use: within a declared enforcement scope, before each consequential
action a Policy Enforcement Point obtains a permit from a Policy
Decision Point that evaluates the action against the Mission. Covers
action classification, where the enforcement point sits, the binding of
a permit to concrete request parameters to close the time-of-check to
time-of-use gap, consumption metering, and fail-closed behavior. For the
high-assurance tier it adds credential custody and mediated execution
(the enforcement point, not the agent, holds the token's
sender-constraint key, so a compromised agent cannot act off-path) and
an action-bound approval for the highest-consequence classes. The
decision-API wire format is a deployment choice, so the contract does
not mandate one.

* [Editor's Copy](https://mcguinness.github.io/draft-mcguinness-oauth-mission/#go.draft-mcguinness-oauth-mission-runtime.html)
* [Datatracker Page](https://datatracker.ietf.org/doc/draft-mcguinness-oauth-mission-runtime)
* [Individual Draft](https://datatracker.ietf.org/doc/html/draft-mcguinness-oauth-mission-runtime)
* [Compare Editor's Copy to Individual Draft](https://mcguinness.github.io/draft-mcguinness-oauth-mission/#go.draft-mcguinness-oauth-mission-runtime.diff)

#### Mission-Bound Runtime Enforcement: AuthZEN Profile

The concrete OpenID AuthZEN binding of the runtime decision contract. It
maps the runtime profile's abstract decision inputs onto the AuthZEN
Authorization API request and response, defines the Decision Evidence
and Execution Evidence objects, and specifies how runtime denials are
carried in an AuthZEN decision. It binds the contract; it does not
restate the enforcement semantics the runtime profile owns.

* [Editor's Copy](https://mcguinness.github.io/draft-mcguinness-oauth-mission/#go.draft-mcguinness-oauth-mission-authzen.html)
* [Datatracker Page](https://datatracker.ietf.org/doc/draft-mcguinness-oauth-mission-authzen)
* [Individual Draft](https://datatracker.ietf.org/doc/html/draft-mcguinness-oauth-mission-authzen)
* [Compare Editor's Copy to Individual Draft](https://mcguinness.github.io/draft-mcguinness-oauth-mission/#go.draft-mcguinness-oauth-mission-authzen.diff)

### Lifecycle

#### Mission Status and Lifecycle for OAuth 2.0

A `mission_id`-keyed status surface with signed responses, plus a
lifecycle endpoint for explicit `revoke`, `suspend`, `resume`, and
`complete` transitions and the `suspended` and `completed` states. It
lets a consumer holding only a `mission_id` ask the origin for current
Mission state, and an authorized party change it.

* [Editor's Copy](https://mcguinness.github.io/draft-mcguinness-oauth-mission/#go.draft-mcguinness-oauth-mission-status.html)
* [Datatracker Page](https://datatracker.ietf.org/doc/draft-mcguinness-oauth-mission-status)
* [Individual Draft](https://datatracker.ietf.org/doc/html/draft-mcguinness-oauth-mission-status)
* [Compare Editor's Copy to Individual Draft](https://mcguinness.github.io/draft-mcguinness-oauth-mission/#go.draft-mcguinness-oauth-mission-status.diff)

#### Mission Lifecycle Signals for OAuth 2.0

A profile of the OpenID Shared Signals Framework: the Mission Issuer
emits a signed Security Event Token on each Mission lifecycle
transition, delivered by push or poll, so a consumer learns of a
revocation, expiry, or other transition promptly without polling. It is
the push complement to the pull-based Status surface.

* [Editor's Copy](https://mcguinness.github.io/draft-mcguinness-oauth-mission/#go.draft-mcguinness-oauth-mission-signals.html)
* [Datatracker Page](https://datatracker.ietf.org/doc/draft-mcguinness-oauth-mission-signals)
* [Individual Draft](https://datatracker.ietf.org/doc/html/draft-mcguinness-oauth-mission-signals)
* [Compare Editor's Copy to Individual Draft](https://mcguinness.github.io/draft-mcguinness-oauth-mission/#go.draft-mcguinness-oauth-mission-signals.diff)

#### Mission Expansion for OAuth 2.0

How to widen a Mission's authority. Because authority can only narrow
within a Mission, widening requires a fresh approval that creates a
successor Mission, which supersedes its predecessor. Expansion is a
governance operation and is deliberately distinct from authentication
step-up.

* [Editor's Copy](https://mcguinness.github.io/draft-mcguinness-oauth-mission/#go.draft-mcguinness-oauth-mission-expansion.html)
* [Datatracker Page](https://datatracker.ietf.org/doc/draft-mcguinness-oauth-mission-expansion)
* [Individual Draft](https://datatracker.ietf.org/doc/html/draft-mcguinness-oauth-mission-expansion)
* [Compare Editor's Copy to Individual Draft](https://mcguinness.github.io/draft-mcguinness-oauth-mission/#go.draft-mcguinness-oauth-mission-expansion.diff)

### Approval-time evidence

#### Mission Intent Shaping for OAuth 2.0

How a client-side "shaper" turns a user's request into a candidate
Mission Intent before it is submitted. The shaper only proposes: its
output is untrusted input until the Authorization Server validates,
narrows, and derives authority from it. OPTIONAL Shaping Evidence
records how the proposal was produced. (Informational.)

* [Editor's Copy](https://mcguinness.github.io/draft-mcguinness-oauth-mission/#go.draft-mcguinness-oauth-mission-shaping.html)
* [Datatracker Page](https://datatracker.ietf.org/doc/draft-mcguinness-oauth-mission-shaping)
* [Individual Draft](https://datatracker.ietf.org/doc/html/draft-mcguinness-oauth-mission-shaping)
* [Compare Editor's Copy to Individual Draft](https://mcguinness.github.io/draft-mcguinness-oauth-mission/#go.draft-mcguinness-oauth-mission-shaping.diff)

#### Mission Consent Evidence for OAuth 2.0

Commits the structured consent disclosure shown to the Approver at the
approval event, through a `consent_rendering_hash` and a signed Consent
Evidence object, so an auditor can reconstruct the recorded approval
surface. It commits what the Authorization Server recorded, not the
pixels presented or the Approver's comprehension.

* [Editor's Copy](https://mcguinness.github.io/draft-mcguinness-oauth-mission/#go.draft-mcguinness-oauth-mission-consent-evidence.html)
* [Datatracker Page](https://datatracker.ietf.org/doc/draft-mcguinness-oauth-mission-consent-evidence)
* [Individual Draft](https://datatracker.ietf.org/doc/html/draft-mcguinness-oauth-mission-consent-evidence)
* [Compare Editor's Copy to Individual Draft](https://mcguinness.github.io/draft-mcguinness-oauth-mission/#go.draft-mcguinness-oauth-mission-consent-evidence.diff)

### Sub-agents

#### Child Mission Delegation for OAuth 2.0

Lets a parent Mission authorize a Child Mission for a sub-agent, with
explicit parent lineage, strict-subset authority, expiry no later than
the parent, fan-out controls, and cascade revocation when the parent is
no longer active. A child is never created by session ancestry alone.

* [Editor's Copy](https://mcguinness.github.io/draft-mcguinness-oauth-mission/#go.draft-mcguinness-oauth-mission-child-delegation.html)
* [Datatracker Page](https://datatracker.ietf.org/doc/draft-mcguinness-oauth-mission-child-delegation)
* [Individual Draft](https://datatracker.ietf.org/doc/html/draft-mcguinness-oauth-mission-child-delegation)
* [Compare Editor's Copy to Individual Draft](https://mcguinness.github.io/draft-mcguinness-oauth-mission/#go.draft-mcguinness-oauth-mission-child-delegation.diff)

### Agent runtime

#### Mission-Aware Agent Harnesses for OAuth 2.0

How an agent harness binds sessions, task graphs, queues, cached tool
connections, and sub-agent handles to Mission state, when it must
re-check status, and how it must pause, suppress, or terminate work when
the Mission is no longer active. It also establishes the mediated
execution environment the runtime profile relies on: for mediated action
classes, governed work runs with no unmediated path to the resource. The
core principle: session continuity is not authority.

* [Editor's Copy](https://mcguinness.github.io/draft-mcguinness-oauth-mission/#go.draft-mcguinness-oauth-mission-harness.html)
* [Datatracker Page](https://datatracker.ietf.org/doc/draft-mcguinness-oauth-mission-harness)
* [Individual Draft](https://datatracker.ietf.org/doc/html/draft-mcguinness-oauth-mission-harness)
* [Compare Editor's Copy to Individual Draft](https://mcguinness.github.io/draft-mcguinness-oauth-mission/#go.draft-mcguinness-oauth-mission-harness.diff)

#### Mission Orchestration and Unwinding for OAuth 2.0

How a multi-step or multi-Mission workflow assigns a reversibility class
to each step, records an unwind plan before dispatch, and unwinds
in-flight work safely when a Mission stops, including compensation after
termination. It governs how workflow state is unwound once continuation
is stopped.

* [Editor's Copy](https://mcguinness.github.io/draft-mcguinness-oauth-mission/#go.draft-mcguinness-oauth-mission-orchestration.html)
* [Datatracker Page](https://datatracker.ietf.org/doc/draft-mcguinness-oauth-mission-orchestration)
* [Individual Draft](https://datatracker.ietf.org/doc/html/draft-mcguinness-oauth-mission-orchestration)
* [Compare Editor's Copy to Individual Draft](https://mcguinness.github.io/draft-mcguinness-oauth-mission/#go.draft-mcguinness-oauth-mission-orchestration.diff)

## Contributing

See the
[guidelines for contributions](https://github.com/mcguinness/draft-mcguinness-oauth-mission/blob/main/CONTRIBUTING.md).

The contributing file also has tips on how to make contributions, if you
don't already know how to do that.

## Command Line Usage

Formatted text and HTML versions of the draft can be built using `make`.

```sh
$ make
```

Command line usage requires that you have the necessary software installed.  See
[the instructions](https://github.com/martinthomson/i-d-template/blob/main/doc/SETUP.md).
