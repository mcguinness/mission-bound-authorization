<!-- regenerate: off (edited by hand; set to on to let i-d-template regenerate) -->

# Mission-Bound Authorization

This is the working area for a family of individual Internet-Drafts
that define the **Mission**: a durable, approval-backed *governance*
object for authorization. A Mission is not a new way to express
authority; it is the approved task, with a lifecycle, that authority is
derived for, bound to, and gated on. The model is substrate-neutral;
**OAuth 2.0 is its flagship binding**, and a standalone binding runs
without touching an existing Authorization Server.

## The problem

OAuth 2.0 issues access tokens for individual resource requests. It has
no durable, approved artifact that represents the larger task a client
is pursuing on a user's behalf. That gap matters for AI agents: an agent
is typically given a *mission* (book the trip, reconcile the ledger,
triage the inbox) and then takes many actions, across many resources,
over a long time, often spawning sub-agents and surviving restarts. A
bag of independently-issued access tokens cannot express "this is the
task the user approved, here is its boundary, and here is when it ends."

## The Mission

This work defines the Mission: a durable object, created by an explicit
approval event, that expresses an approved task and its lifecycle. The
Mission does not itself express authority; that is the job of the
Authority Set. Rich Authorization Requests express authority, a Mission
expresses the approved task it is bound to. A client proposes a
**Mission Intent**; the Mission Issuer derives an **Authority Set** (the
concrete resources, actions, and constraints) for it; and an **approval
event** commits both as integrity anchors (`intent_hash` and
`authority_hash`) and records the Mission.

The Mission Issuer comes in two bindings. In the **OAuth binding**, the
Authorization Server is the Mission Issuer: every derived token carries
a `mission` claim binding it back to the approved task, and token
issuance is gated on Mission state, so revoking or expiring the Mission
stops all further authority at once. In the **standalone binding**, a
Mission Authority Server holds the same object without issuing tokens,
and enforcement joins ordinary tokens to the Mission at the Policy
Decision Point. In both, authority only narrows as it flows down to
derived and delegated credentials; widening requires a fresh approval.

The **core** defines the model and its OAuth 2.0 binding. Everything
else is an OPTIONAL companion profile that layers on without changing
it.

## The architecture

```
 propose      Mission Intent Shaping (client side, untrusted proposal)
                         |
                         v
 approve      Mission Issuer, one of two bindings:
 and record   +--------------------------+  +--------------------------+
              | OAuth AS (issuance core) |  | Mission Authority Server |
              | PAR -> approval event    |  | submit -> async approval |
              | Mission-bound tokens,    |  | no tokens; the PDP joins |
              | issuance gated on state  |  | tokens to the Mission    |
              +--------------------------+  +--------------------------+
                         \                      /
                          v                    v
              THE MISSION: durable record committing intent_hash
              and authority_hash, with a lifecycle state
                         |
 govern       Status (pull)    Signals (push)
              Expansion (widen via a successor)
              Completion (retire authority per entry)
                         |
 enforce      Runtime contract -> AuthZEN binding: a PEP obtains a
 each action  PDP permit before every consequential action
                         |
 run and      Harness (session continuity is not authority)
 wind down    Orchestration (unwind in-flight work safely)

 delegate     Child Delegation (child Missions, cascade revocation)
              Offline Attenuation (narrower tokens minted offline)

 prove        Consent Evidence (what the Approver was shown)
              Mandate (portable, verifiable statement of a Mission)
              Audit (SCITT transparency for all Mission evidence)

 analyze      Security Model (the trusted base, in one view)
```

One rule keeps this extensible without a central registry: only the
state `active` permits issuance or continued reliance, and a consumer
treats every other state, including one it does not recognize, as
non-active. A state a companion profile adds (such as `suspended`,
`superseded`, or `cascaded`) therefore fails safe for a consumer that
predates it.

## How to read this suite

Everyone starts with the core's Introduction, Overview, and
terminology; every companion assumes them. From there, follow the path
that matches your role:

- **Understand the model** (an afternoon): the problem and Mission
  sections above, the core's Introduction and Overview, then the
  Security Model for the trust picture in one view.
- **Implement issuance at an Authorization Server** (identity vendors):
  the core, then Status and Signals (the state surfaces), Consent
  Evidence (approval-surface evidence), Expansion and Completion
  (growing and retiring authority), and Deferred Approval if approvals
  are asynchronous.
- **Deploy agents without changing your AS**: Mission Authority Server,
  then Runtime Enforcement and its AuthZEN binding (mandatory in this
  mode), then the Harness; add Consent Evidence for the Governed
  equivalents.
- **Build enforcement (a PDP or PEP)**: Runtime Enforcement, then the
  AuthZEN binding; read the Harness's custody and mediation sections
  for where keys live.
- **Build an agent harness or orchestrator**: Harness, then
  Orchestration, with Runtime Enforcement for the gate they feed; Child
  Delegation when sub-agents get their own Missions.
- **Audit or review security**: Security Model first, then Consent
  Evidence, Audit Transparency, and Mandate; each profile's own
  Security Considerations remain normative.

## What to deploy

Each draft is optional on its own, but the properties many readers
assume from "Mission-bound agents" (action-time checks, prompt stop,
unwinding, consent evidence) only arrive when several are deployed
together. Most agent deployments therefore want a bundle, not the core
alone. These bundles name what to deploy for a given goal. The short
names in the table are the drafts' nicknames; each maps to a document
described under "The documents" below (mission is the core; the rest
are the companion profiles of the same names).

| Bundle | Drafts | What you get |
|---|---|---|
| **Baseline issuance** | mission | Approved, integrity-bound Missions; state-gated issuance; a possession-independent kill switch (outstanding tokens run to expiry; prompt cutoff needs the Enforced bundle). Audit, not action-time defense. |
| **Enforced agent** | mission + runtime + authzen + a freshness source (status, signals, or origin token introspection) | Per-action enforcement at the point of use, and prompt revocation (pull via status or introspection, push via signals). The minimum for an agent that takes consequential actions. For the high-consequence classes, runtime requires an active freshness source, not token-lifetime expiry. |
| **Governed agent (recommended for AI agents)** | Enforced agent + consent-evidence + harness | Consent-rendering evidence and session-continuity stop. For protection against a compromised agent, claim runtime's named agent-compromise-resistant enforcement (mediated custody, no-unmediated-egress, action-bound approval, all MUST for the high-consequence classes). Add child-delegation for sub-agents and expansion for mid-task growth, and orchestration (experimental) for safe unwinding of in-flight work. |
| **Standalone governance (AS-optional)** | authority-server + runtime + authzen (+ consent-evidence and harness for the Governed equivalents) | Mission governance and per-action enforcement with an unmodified OAuth Authorization Server; the authority server is the freshness source. No Mission-bound tokens and no issuance gating: revoking a Mission stops nothing at the token layer, so enforcement rests entirely on PEP coverage. The on-ramp to the Enforced and Governed bundles. |

There are two ways to deploy the model. The flagship is the OAuth
binding: the Authorization Server implements the issuance profile,
tokens carry the `mission` claim, and issuance is gated on Mission
state. The AS-optional mode runs a standalone Mission Authority Server
instead: Missions are created, approved, and served without any change
to the existing Authorization Server, and enforcement joins ordinary
tokens to Missions at the Policy Decision Point. The Mission Mandate
makes a Mission portable across both: a signed, verifiable statement
of what was approved, checkable by any party without a token exchange.

Mission Intent Shaping is an approval-time, client-side option that
layers onto any bundle; it produces the Mission Intent and is not itself
deployed at the Authorization Server. Mission Deferred Approval is an
approval-time option for deployments whose approvals are asynchronous or
whose reviewers narrow a proposed Mission; it layers onto any bundle.

Each draft also states its own scoped conformance; the bundles are
guidance, not a new conformance class.

In particular, adopting the Governed bundle does not by itself make a
deployment resistant to a compromised agent. That is the runtime
profile's named *agent-compromise-resistant enforcement* claim, which
holds only when all four of its conditions are met for the
high-consequence classes: mediated credential custody, no unmediated
path to those actions, an action-bound approval, and an active-freshness
state source. Mediated custody moves the high-consequence
sender-constraint key out of the agent and into the mediating Policy
Enforcement Point; this *relocates* the credential rather than removing
it, so the mediating PEP becomes a critical trusted component whose own
compromise is out of scope. A deployment that leaves any of the four
conditions unmet, or that cannot place a PEP on every path to a mediated
action, must not represent itself as resistant to agent compromise.

### Maturity

The drafts are not all at the same stage; this is the quickest way to
decide what to build on now.

- **Stable** (normative dependencies are ratified OAuth and finalized
  OpenID specifications): the issuance **core**, **runtime**,
  **authzen**, **status**, and **signals**. Build on these. The core
  confines its three tracked Internet-Draft references (the OAuth Actor
  Profile, identity chaining, and ID-JAG) to its OPTIONAL Delegation and
  Cross-Domain capabilities; the mandatory single-domain core depends
  only on ratified specifications, and identity chaining is approved and
  in the RFC Editor queue. For **authzen**, the stable surface is its
  core AuthZEN decision binding; its Access Request and Approval Profile
  (ARAP) and Model Context Protocol tool-authorization (COAZ)
  integrations and MCP-composition notes are informative and optional.
- **Stable but situational** (adopt when your use case needs them):
  **expansion**, **child-delegation**, **consent-evidence**,
  **harness**, **shaping**, and **audit** (its transparency substrate,
  the SCITT architecture, is ratified as RFC 9943; its remaining tracked
  dependency, the COSE hash envelope, is approved and in the RFC Editor
  queue). For AI agents, consent-evidence and harness are not merely
  situational: they are the Governed bundle's recommended set.
- **Experimental** (adopt for evaluation, not as a stable interface):
  **attenuation** and **approval** depend normatively on Internet-Drafts
  that are not yet ratified (Attenuating Agent Tokens and OAuth Deferred
  Token Response, respectively); **orchestration** and **completion**
  define newer models that are less exercised; **authority-server** and
  **mandate** are the newest documents in the family and not yet
  exercised (the mandate's normative dependencies are all ratified; the
  authority server composes stable profiles, but its PDP join mechanism
  is new). Each names a stable path to prefer where one exists.

In short: the Enforced bundle is built entirely from stable drafts; the
experimental profiles are additive and can wait.

## The documents

Together these drafts form the **Mission-Bound Authorization suite**.
The suite takes its name from the model; the core's title,
"Mission-Bound Authorization for OAuth 2.0", names its flagship
binding. The companions refer to the core as the **"issuance profile"**
(it governs issuance and derivation).

The naming encodes a boundary. Profiles that extend the Authorization
Server's own surfaces (issuance, approval, lifecycle, evidence of
consent) keep "oauth" in their draft names. Profiles that specify
components outside the Authorization Server (runtime enforcement and
its AuthZEN binding, the agent harness, orchestration, intent shaping,
audit transparency, the security model, the standalone authority
server, and the mandate) are named without it: they are defined against
the Mission model's substrate primitives, each names those primitives
in a Mission Substrate section, and the core is that model's OAuth 2.0
binding. Another mission-based protocol that supplies the same
primitives can host them unchanged.

### The model and its bindings

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

#### Mission Authority Server

The AS-optional binding. A Mission Authority Server implements the
Mission Issuer role (intent submission, the approval event, the record,
lifecycle, and state) without being an OAuth Authorization Server and
without deriving tokens. Enforcement joins ordinary OAuth tokens to
Missions at the Policy Decision Point, so a deployment gets Mission
governance with an unmodified AS. No Mission-bound tokens and no
issuance gating; runtime enforcement over every consequential path is
required. The upgrade path is the issuance profile.

* [Editor's Copy](https://mcguinness.github.io/draft-mcguinness-oauth-mission/#go.draft-mcguinness-mission-authority-server.html)
* [Datatracker Page](https://datatracker.ietf.org/doc/draft-mcguinness-mission-authority-server)
* [Individual Draft](https://datatracker.ietf.org/doc/html/draft-mcguinness-mission-authority-server)
* [Compare Editor's Copy to Individual Draft](https://mcguinness.github.io/draft-mcguinness-oauth-mission/#go.draft-mcguinness-mission-authority-server.diff)

### Approval time

#### Mission Intent Shaping

How a client-side "shaper" turns a user's request into a candidate
Mission Intent before it is submitted. The shaper only proposes: its
output is untrusted input until the Mission Issuer validates, narrows,
and derives authority from it. OPTIONAL Shaping Evidence records how
the proposal was produced. (Informational.)

* [Editor's Copy](https://mcguinness.github.io/draft-mcguinness-oauth-mission/#go.draft-mcguinness-mission-shaping.html)
* [Datatracker Page](https://datatracker.ietf.org/doc/draft-mcguinness-mission-shaping)
* [Individual Draft](https://datatracker.ietf.org/doc/html/draft-mcguinness-mission-shaping)
* [Compare Editor's Copy to Individual Draft](https://mcguinness.github.io/draft-mcguinness-oauth-mission/#go.draft-mcguinness-mission-shaping.diff)

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

#### Mission Deferred Approval for OAuth 2.0

Makes the approval event asynchronous and negotiable. Profiles OAuth
Deferred Token Response so a Mission approval can be deferred and
polled, and adds a `revisable` mode: when the Authorization Server can
grant only a narrowed version of the proposed Mission, it signals which
dimensions it refused and invites the client to push a narrowing
revision, continuing the same approval instead of starting over.
Narrowing only.

* [Editor's Copy](https://mcguinness.github.io/draft-mcguinness-oauth-mission/#go.draft-mcguinness-oauth-mission-approval.html)
* [Datatracker Page](https://datatracker.ietf.org/doc/draft-mcguinness-oauth-mission-approval)
* [Individual Draft](https://datatracker.ietf.org/doc/html/draft-mcguinness-oauth-mission-approval)
* [Compare Editor's Copy to Individual Draft](https://mcguinness.github.io/draft-mcguinness-oauth-mission/#go.draft-mcguinness-oauth-mission-approval.diff)

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

#### Mission Completion for OAuth 2.0

The narrowing counterpart of Expansion. Adds `terminal_when`, a
registered Common Constraint that discharges a `mission_resource_access`
entry when its completion condition fires, so the Authorization Server
stops deriving that entry once the task it was granted for is done.
Discharge is monotonic (only retires authority), so it is safe against
an injected agent; it lets a multi-resource Mission complete one entry
at a time; and it is the enforceable counterpart of the inert
`success_criteria`.

* [Editor's Copy](https://mcguinness.github.io/draft-mcguinness-oauth-mission/#go.draft-mcguinness-oauth-mission-completion.html)
* [Datatracker Page](https://datatracker.ietf.org/doc/draft-mcguinness-oauth-mission-completion)
* [Individual Draft](https://datatracker.ietf.org/doc/html/draft-mcguinness-oauth-mission-completion)
* [Compare Editor's Copy to Individual Draft](https://mcguinness.github.io/draft-mcguinness-oauth-mission/#go.draft-mcguinness-oauth-mission-completion.diff)

### Runtime enforcement

#### Mission-Bound Runtime Enforcement

A decision contract for enforcing a Mission-bound token at the point of
use: within a declared enforcement scope, before each consequential
action a Policy Enforcement Point obtains a permit from a Policy
Decision Point that evaluates the action against the Mission. Covers
action classification, where the enforcement point sits, the binding of
a permit to concrete request parameters to close the time-of-check to
time-of-use gap, consumption metering, and fail-closed behavior. For the
high-consequence classes it adds credential custody and mediated
execution (the enforcement point, not the agent, holds the token's
sender-constraint key, so a compromised agent cannot act off-path) and
an action-bound approval for the highest-consequence classes. The
decision-API wire format is a deployment choice, so the contract does
not mandate one.

* [Editor's Copy](https://mcguinness.github.io/draft-mcguinness-oauth-mission/#go.draft-mcguinness-mission-runtime.html)
* [Datatracker Page](https://datatracker.ietf.org/doc/draft-mcguinness-mission-runtime)
* [Individual Draft](https://datatracker.ietf.org/doc/html/draft-mcguinness-mission-runtime)
* [Compare Editor's Copy to Individual Draft](https://mcguinness.github.io/draft-mcguinness-oauth-mission/#go.draft-mcguinness-mission-runtime.diff)

#### Mission-Bound Runtime Enforcement: AuthZEN Profile

The concrete OpenID AuthZEN binding of the runtime decision contract. It
maps the runtime profile's abstract decision inputs onto the AuthZEN
Authorization API request and response, defines the Decision Evidence
and Execution Evidence objects, and specifies how runtime denials are
carried in an AuthZEN decision. It binds the contract; it does not
restate the enforcement semantics the runtime profile owns.

* [Editor's Copy](https://mcguinness.github.io/draft-mcguinness-oauth-mission/#go.draft-mcguinness-mission-authzen.html)
* [Datatracker Page](https://datatracker.ietf.org/doc/draft-mcguinness-mission-authzen)
* [Individual Draft](https://datatracker.ietf.org/doc/html/draft-mcguinness-mission-authzen)
* [Compare Editor's Copy to Individual Draft](https://mcguinness.github.io/draft-mcguinness-oauth-mission/#go.draft-mcguinness-mission-authzen.diff)

### Agent runtime

#### Mission-Aware Agent Harnesses

How an agent harness binds sessions, task graphs, queues, cached tool
connections, and sub-agent handles to Mission state, when it must
re-check status, and how it must pause, suppress, or terminate work when
the Mission is no longer active. It also establishes the mediated
execution environment the runtime profile relies on: for mediated action
classes, governed work runs with no unmediated path to the resource. The
core principle: session continuity is not authority.

* [Editor's Copy](https://mcguinness.github.io/draft-mcguinness-oauth-mission/#go.draft-mcguinness-mission-harness.html)
* [Datatracker Page](https://datatracker.ietf.org/doc/draft-mcguinness-mission-harness)
* [Individual Draft](https://datatracker.ietf.org/doc/html/draft-mcguinness-mission-harness)
* [Compare Editor's Copy to Individual Draft](https://mcguinness.github.io/draft-mcguinness-oauth-mission/#go.draft-mcguinness-mission-harness.diff)

#### Mission Orchestration and Unwinding

How a multi-step or multi-Mission workflow assigns a reversibility class
to each step, records an unwind plan before dispatch, and unwinds
in-flight work safely when a Mission stops, including compensation after
termination. It governs how workflow state is unwound once continuation
is stopped.

* [Editor's Copy](https://mcguinness.github.io/draft-mcguinness-oauth-mission/#go.draft-mcguinness-mission-orchestration.html)
* [Datatracker Page](https://datatracker.ietf.org/doc/draft-mcguinness-mission-orchestration)
* [Individual Draft](https://datatracker.ietf.org/doc/html/draft-mcguinness-mission-orchestration)
* [Compare Editor's Copy to Individual Draft](https://mcguinness.github.io/draft-mcguinness-oauth-mission/#go.draft-mcguinness-mission-orchestration.diff)

### Sub-agents

#### Mission Child Delegation for OAuth 2.0

Lets a parent Mission authorize a Child Mission for a sub-agent, with
explicit parent lineage, strict-subset authority, expiry no later than
the parent, fan-out controls, and cascade revocation when the parent is
no longer active. A child is never created by session ancestry alone.

* [Editor's Copy](https://mcguinness.github.io/draft-mcguinness-oauth-mission/#go.draft-mcguinness-oauth-mission-child-delegation.html)
* [Datatracker Page](https://datatracker.ietf.org/doc/draft-mcguinness-oauth-mission-child-delegation)
* [Individual Draft](https://datatracker.ietf.org/doc/html/draft-mcguinness-oauth-mission-child-delegation)
* [Compare Editor's Copy to Individual Draft](https://mcguinness.github.io/draft-mcguinness-oauth-mission/#go.draft-mcguinness-oauth-mission-child-delegation.diff)

#### Mission Offline Attenuation for OAuth 2.0

Removes the Authorization Server from the sub-agent fan-out hot path.
Profiles Attenuating Agent Tokens so a Mission-bound token holder mints a
narrower child token offline, carrying the same `mission` claim; the
narrowing is verifiable from the carried token chain. The kill switch is
preserved because consumption is gated by the runtime layer re-checking
Mission state, so a revoked Mission stops the whole chain. A capability
for deployments running the runtime enforcement profile, offered
alongside Authorization-Server-mediated delegation.

* [Editor's Copy](https://mcguinness.github.io/draft-mcguinness-oauth-mission/#go.draft-mcguinness-oauth-mission-attenuation.html)
* [Datatracker Page](https://datatracker.ietf.org/doc/draft-mcguinness-oauth-mission-attenuation)
* [Individual Draft](https://datatracker.ietf.org/doc/html/draft-mcguinness-oauth-mission-attenuation)
* [Compare Editor's Copy to Individual Draft](https://mcguinness.github.io/draft-mcguinness-oauth-mission/#go.draft-mcguinness-oauth-mission-attenuation.diff)

### Proof and portability

Three layers of proof, from the approval surface outward: Consent
Evidence commits what the Approver was shown (listed under Approval
time above); the Mandate makes a Mission's committed facts portable and
independently verifiable; Audit Transparency makes all Mission evidence
tamper-evident in an append-only log.

#### Mission Mandate

A signed, portable, independently verifiable statement of a Mission's
committed facts (its identifiers, integrity anchors, Subject, Approver,
and optionally its Authority Set), minted by the Mission Issuer. It is
evidence, not a credential: presenting it authorizes nothing. It lets a
cross-domain verifier, an external rail deriving its own vertical
mandate, or an auditor know what was approved without a token exchange;
current state still comes from Status or Signals. OPTIONAL selective
disclosure via SD-JWT.

* [Editor's Copy](https://mcguinness.github.io/draft-mcguinness-oauth-mission/#go.draft-mcguinness-mission-mandate.html)
* [Datatracker Page](https://datatracker.ietf.org/doc/draft-mcguinness-mission-mandate)
* [Individual Draft](https://datatracker.ietf.org/doc/html/draft-mcguinness-mission-mandate)
* [Compare Editor's Copy to Individual Draft](https://mcguinness.github.io/draft-mcguinness-oauth-mission/#go.draft-mcguinness-mission-mandate.diff)

#### Mission Audit Transparency

Makes the suite's evidence tamper-evident and independently verifiable.
Registers Mission evidence (the approval event, lifecycle transitions,
runtime and consent evidence) into a SCITT Transparency Service as
Signed Statements, with the Mission as the statement subject so a
Mission's records form one append-only feed, and binds the Receipt back
so any party, in any domain, can verify inclusion offline. Statements
commit to evidence by hash, so sensitive task data stays out of the log.
Layers onto any bundle.

* [Editor's Copy](https://mcguinness.github.io/draft-mcguinness-oauth-mission/#go.draft-mcguinness-mission-audit.html)
* [Datatracker Page](https://datatracker.ietf.org/doc/draft-mcguinness-mission-audit)
* [Individual Draft](https://datatracker.ietf.org/doc/html/draft-mcguinness-mission-audit)
* [Compare Editor's Copy to Individual Draft](https://mcguinness.github.io/draft-mcguinness-oauth-mission/#go.draft-mcguinness-mission-audit.diff)

### Security model

#### Mission Security Model

A cross-cutting, Informational consolidation of the suite's trusted base.
Enforcement is spread across components (Authorization Server or Mission
Authority Server, PEP, PDP, harness, consent rendering, and optional
state, access-request, transparency, and event-source services); each
profile states its own security considerations, but this document gives
the single view: what each component must achieve, what it assumes of
the others, and how its compromise degrades the guarantees. It defines
no new mechanism and points to the profiles' normative security
considerations.

* [Editor's Copy](https://mcguinness.github.io/draft-mcguinness-oauth-mission/#go.draft-mcguinness-mission-security-model.html)
* [Datatracker Page](https://datatracker.ietf.org/doc/draft-mcguinness-mission-security-model)
* [Individual Draft](https://datatracker.ietf.org/doc/html/draft-mcguinness-mission-security-model)
* [Compare Editor's Copy to Individual Draft](https://mcguinness.github.io/draft-mcguinness-oauth-mission/#go.draft-mcguinness-mission-security-model.diff)

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
