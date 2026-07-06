<!-- regenerate: off (edited by hand; set to on to let i-d-template regenerate) -->

# Mission-Bound Authorization

This is the working area for a family of individual Internet-Drafts
that define the **Mission**: a durable, approval-backed *governance*
object for authorization. A Mission is not a new way to express
authority; it is the approved task, with a lifecycle, that authority is
derived for, bound to, and gated on. The model is substrate-neutral;
**OAuth 2.0 is its flagship binding**, and a standalone binding runs
without touching an existing Authorization Server.

**Start with the Architecture document and the OAuth core.** Everything
else is optional companion work, and the minimal implementation below
fits on one screen.

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

The Mission Issuer comes in three bindings. In the **OAuth binding**,
the Authorization Server is the Mission Issuer: every derived token
carries a `mission` claim binding it back to the approved task, and
token issuance is gated on Mission state, so revoking or expiring the
Mission stops all further authority at once. In the **standalone
binding**, a Mission Authority Server holds the same object without
issuing tokens, and enforcement joins ordinary tokens to the Mission at
the Policy Decision Point: a peer binding with its own architectural
rationale (governance deliberately decoupled from token issuance, and
one Mission Issuer can govern across many Authorization Servers) that
also serves, operationally, as the adoption bridge for deployments
that cannot yet change their AS. In the **AAuth binding**, the AAuth Person
Server is the Mission Issuer: it gives AAuth's native mission concept
the Mission model's structure, lifecycle, and anchors, and because the
Person Server issues or gates every AAuth auth token, issuance gating
holds there too. In all three, authority only narrows as it flows down
to derived and delegated credentials; widening requires a fresh
approval.

The **core** defines the model and its OAuth 2.0 binding. Everything
else is an OPTIONAL companion profile that layers on without changing
it.

## The architecture

```
 propose      Mission Intent Shaping (client side, untrusted proposal)
                         |
                         v
 approve      Mission Issuer, one of three bindings (the third,
 and record   the AAuth Person Server, hosts AAuth's native
              missions and gates its auth tokens):
              +--------------------------+  +--------------------------+
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

 project      Cross-Domain Projection (one Mission honored in
              another trust domain via the cross-domain grant)

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

The Architecture document (first entry in the catalog below) is the
citable form of this view: components, the substrate interface, the
layers, deployment patterns, and the requirements the family answers.

## How to read this suite

Newcomers start with the Architecture document; implementers start
with the core's Introduction, Overview, and terminology, which every
companion assumes. From there, follow the path that matches your role:

- **Understand the model** (an afternoon): the Architecture document
  (the citable form of this page's structural view), then the core's
  Introduction and Overview, then the Security Model for the trust
  picture in one view.
- **Implement issuance at an Authorization Server** (identity vendors):
  the core, then Status (the state surface; Signals is its experimental
  push complement), Consent
  Evidence (approval-surface evidence), Expansion and Completion
  (growing and retiring authority), Deferred Approval if approvals
  are asynchronous, and Cross-Domain Projection when Missions span
  trust domains.
- **Deploy agents without changing your AS**: Mission Authority Server,
  then Runtime Enforcement and its AuthZEN binding (mandatory in this
  mode), then the Harness; add Consent Evidence for the Governed
  equivalents.
- **Build enforcement (a PDP or PEP)**: Runtime Enforcement, then the
  AuthZEN binding; read runtime's custody section and the Harness's
  mediation section for where keys live.
- **Build an agent harness or orchestrator**: Harness, then
  Orchestration, with Runtime Enforcement for the gate they feed; Child
  Delegation when sub-agents get their own Missions.
- **Audit or review security**: Security Model first, then Consent
  Evidence, Audit Transparency, and Mandate; each profile's own
  Security Considerations remain normative.

## The minimal implementation

The first useful piece is one profile, not the suite. A minimal
conforming deployment of the core implements:

- `mission_intent` submission through Pushed Authorization Requests;
- derivation of the Authority Set, in narrowing mode via
  `proposed_authority`;
- the Mission record with its `intent_hash` and `authority_hash`
  integrity anchors;
- the `mission` claim on issued tokens and the `authorization_details`
  echo in token responses;
- issuance and refresh gated on Mission state, with revocation by
  `mission_id`; and
- optionally, token introspection reporting Mission state.

That is the whole mandatory surface; the core's Conformance section
names it. What the core alone does **not** protect, by design:
already-issued tokens run to expiry (prompt cutoff needs introspection,
Status, or the runtime layer); completed actions are not undone;
off-path execution by a compromised agent is the runtime and harness
profiles' territory; prompt injection is constrained (inert intent
text, fixed authority), not prevented; and information-flow leakage
within approved authority is out of scope. Choose the tier that
matches the risk: the core for low-risk multi-token workflows, the
Enforced bundle for agents that take consequential actions.

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
| **Enforced agent** | mission + runtime + authzen + a freshness source (status or origin token introspection; signals, experimental, adds push) | Per-action enforcement at the point of use, and prompt revocation (pull via status or introspection; the experimental signals profile adds push). The minimum for an agent that takes consequential actions. For the high-consequence classes, runtime requires an active freshness source, not token-lifetime expiry. |
| **Governed agent (recommended for AI agents)** | Enforced agent + consent-evidence + harness | Consent-rendering evidence and session-continuity stop. For protection against a compromised agent, claim runtime's named agent-compromise-resistant enforcement (see the note below the table). Add child-delegation for sub-agents and expansion for mid-task growth, and orchestration (experimental) for safe unwinding of in-flight work. |
| **Standalone governance (AS-optional)** | authority-server (experimental) + runtime + authzen (+ consent-evidence and harness for the Governed equivalents) | Mission governance and per-action enforcement with an unmodified OAuth Authorization Server; the authority server serves the status and lifecycle surfaces itself and is the freshness source. No Mission-bound tokens and no issuance gating: revoking a Mission stops nothing at the token layer, so enforcement rests entirely on PEP coverage. Expansion and sub-agent (Child Mission) creation ride the authority server's own submission surface, with an authenticated-client binding in place of the OAuth wire's token possession. A peer binding chosen for governance-issuance separation, and the adoption bridge toward the Enforced and Governed bundles. |

The model deploys through three bindings. The OAuth binding is the
normative adoption path: the Authorization Server implements the
issuance profile, tokens carry the `mission` claim, and issuance is
gated on Mission state. The standalone binding runs a Mission
Authority Server: a peer binding whose architectural rationale
(governance decoupled from token issuance; one Mission Issuer across
many ASes) can make it the right long-term shape for some
deployments, and which also serves as the adoption bridge where the
AS cannot yet change. The AAuth binding hosts AAuth's native missions
at the Person Server. The Mission Mandate makes a Mission portable
across all of them: a signed, verifiable statement of what was
approved, checkable by any party without a token exchange.

Mission Intent Shaping is an approval-time, client-side option that
layers onto any bundle; it produces the Mission Intent and is not itself
deployed at the Authorization Server. Mission Deferred Approval is an
approval-time option for deployments whose approvals are asynchronous or
whose reviewers narrow a proposed Mission; it layers onto the
OAuth-binding bundles (the Mission Authority Server is natively
asynchronous and does not use it).

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

### The adoption ladder

What to implement, in order. This is deployment advice; dependency
facts are the next subsection.

1. **Adopt first**: read the **architecture**, implement the **core**
   (the minimal implementation above).
2. **Implementation minimum** for agents that act: **status**,
   **runtime**, **authzen** (the Enforced bundle).
3. **Recommended for AI agents**: **consent-evidence** and **harness**
   (the Governed bundle).
4. **Advanced, when the use case arrives**: **expansion**,
   **completion**, **child-delegation**, **cross-domain**,
   **management**, **mandate**, **audit**, **shaping**.
5. **Experimental, adopt for evaluation only**: **signals** (push
   latency optimization over correctly sized status polling),
   **approval** and **approval-revision**, **progressive**,
   **metering**, **attenuation**, **orchestration**,
   **authority-server** (a peer binding and the AS-optional adoption
   bridge; its PDP join is the family's newest mechanism), **aauth**,
   **substrate** (binding requirements for substrates that do not yet
   exist). Each names a stable path to prefer where one exists.

The architecture and security model are Informational companions and
sit outside the ladder.

### Dependency stability

Every normative dependency is a ratified RFC or a finalized OpenID
specification, with these tracked exceptions: the **core** confines
its one Internet-Draft reference (the OAuth Actor Profile) to its
OPTIONAL Delegation capability; **cross-domain** depends on OAuth
identity chaining (approved, in the RFC Editor queue) and ID-JAG (a
working-group document); **audit**'s COSE hash envelope is approved
and in the RFC Editor queue; **approval**, **attenuation**, and
**aauth** track unratified individual drafts (OAuth Deferred Token
Response, Attenuating Agent Tokens, and the AAuth protocol). For
**authzen**, the stable surface is its core AuthZEN decision binding;
its Access Request and Approval Profile (ARAP) and Model Context
Protocol tool-authorization (COAZ) integrations are informative and
optional.

In short: ladder steps 1 through 3 are built entirely on ratified
dependencies; everything experimental is additive and can wait.

### The standardization ask

The ask is not adoption of the suite. It is: adopt the Mission model
and the OAuth issuance profile as the stable substrate for task-bound
delegated authorization. Runtime, lifecycle, evidence, and
cross-domain profiles proceed as companion drafts on their own
timelines.

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
audit transparency, the security model, the architecture, the
standalone authority server, the AAuth binding, the substrate
requirements, and the mandate) are named without it:
they are defined against
the Mission model's substrate primitives, each names those primitives
in a Mission Substrate section, and the core is that model's OAuth 2.0
binding. Another mission-based protocol that supplies the same
primitives can host them unchanged.

### Architecture

#### An Architecture for Mission-Bound Authorization

The single structural view: roles and components, the substrate
interface (the primitives a binding provides and the profiles consume),
the layers, deployment patterns, the requirements the family answers,
and the document map. Informational; it defines no mechanism, and the
profiles remain authoritative. Read this first.

* [Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-architecture.html)
* [Datatracker Page](https://datatracker.ietf.org/doc/draft-mcguinness-mission-architecture)
* [Individual Draft](https://datatracker.ietf.org/doc/html/draft-mcguinness-mission-architecture)
* [Compare Editor's Copy to Individual Draft](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-architecture.diff)

### The core

#### Mission-Bound Authorization for OAuth 2.0

The mandatory core, the **issuance profile**. Defines the Mission, the
Mission Intent and Authority Set, the approval event and its
`intent_hash` / `authority_hash` integrity anchors, the `mission` token
claim, the subset rule, and state-gated issuance. Every other document
builds on this one.

* [Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission.html)
* [Datatracker Page](https://datatracker.ietf.org/doc/draft-mcguinness-oauth-mission)
* [Individual Draft](https://datatracker.ietf.org/doc/html/draft-mcguinness-oauth-mission)
* [Compare Editor's Copy to Individual Draft](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission.diff)

### Approval time

#### Mission Intent Shaping

How a client-side "shaper" turns a user's request into a candidate
Mission Intent before it is submitted. The shaper only proposes: its
output is untrusted input until the Mission Issuer validates, narrows,
and derives authority from it. OPTIONAL Shaping Evidence records how
the proposal was produced. (Informational.)

* [Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-shaping.html)
* [Datatracker Page](https://datatracker.ietf.org/doc/draft-mcguinness-mission-shaping)
* [Individual Draft](https://datatracker.ietf.org/doc/html/draft-mcguinness-mission-shaping)
* [Compare Editor's Copy to Individual Draft](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-shaping.diff)

#### Mission Consent Evidence for OAuth 2.0

Commits the structured consent disclosure shown to the Approver at the
approval event, through a `consent_rendering_hash` and a signed Consent
Evidence object, so an auditor can reconstruct the recorded approval
surface. It commits what the Authorization Server recorded, not the
pixels presented or the Approver's comprehension.

* [Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-consent-evidence.html)
* [Datatracker Page](https://datatracker.ietf.org/doc/draft-mcguinness-oauth-mission-consent-evidence)
* [Individual Draft](https://datatracker.ietf.org/doc/html/draft-mcguinness-oauth-mission-consent-evidence)
* [Compare Editor's Copy to Individual Draft](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-consent-evidence.diff)

#### Mission Deferred Approval for OAuth 2.0

Makes the approval event asynchronous. Profiles OAuth
Deferred Token Response so a Mission approval can be deferred and
polled; the Mission record is created atomically with the asynchronous
decision. A proposal the reviewer will grant only in narrowed form
resolves to a denial, and the client resubmits a narrower Intent.

* [Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-approval.html)
* [Datatracker Page](https://datatracker.ietf.org/doc/draft-mcguinness-oauth-mission-approval)
* [Individual Draft](https://datatracker.ietf.org/doc/html/draft-mcguinness-oauth-mission-approval)
* [Compare Editor's Copy to Individual Draft](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-approval.diff)

#### Mission Approval Revision for OAuth 2.0

Experimental companion to Deferred Approval. Adds a `revisable` mode:
when the Authorization Server can grant only a narrowed version of the
proposed Mission, it signals which dimensions it refused and invites
the client to push a narrowing revision, continuing the same deferred
approval instead of starting over. Narrowing only; deny-and-resubmit
under Deferred Approval alone is the stable path.

* [Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-approval-revision.html)
* [Datatracker Page](https://datatracker.ietf.org/doc/draft-mcguinness-oauth-mission-approval-revision)
* [Individual Draft](https://datatracker.ietf.org/doc/html/draft-mcguinness-oauth-mission-approval-revision)
* [Compare Editor's Copy to Individual Draft](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-approval-revision.diff)

### Lifecycle

#### Mission Status and Lifecycle for OAuth 2.0

A `mission_id`-keyed status surface with signed responses, plus a
lifecycle endpoint for explicit `revoke`, `suspend`, `resume`, and
`complete` transitions and the `suspended` and `completed` states. It
lets a consumer holding only a `mission_id` ask the origin for current
Mission state, and an authorized party change it.

* [Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-status.html)
* [Datatracker Page](https://datatracker.ietf.org/doc/draft-mcguinness-oauth-mission-status)
* [Individual Draft](https://datatracker.ietf.org/doc/html/draft-mcguinness-oauth-mission-status)
* [Compare Editor's Copy to Individual Draft](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-status.diff)

#### Mission Lifecycle Signals for OAuth 2.0

Experimental. A profile of the OpenID Shared Signals Framework: the
Mission Issuer
emits a signed Security Event Token on each Mission lifecycle
transition, delivered by push or poll, so a consumer learns of a
revocation, expiry, or other transition promptly without polling. It is
the push complement to the pull-based Status surface, a latency
optimization for deployments where per-Mission polling does not scale.

* [Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-signals.html)
* [Datatracker Page](https://datatracker.ietf.org/doc/draft-mcguinness-oauth-mission-signals)
* [Individual Draft](https://datatracker.ietf.org/doc/html/draft-mcguinness-oauth-mission-signals)
* [Compare Editor's Copy to Individual Draft](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-signals.diff)

#### Mission Expansion for OAuth 2.0

How to widen a Mission's authority. Because authority can only narrow
within a Mission, widening requires a fresh approval that creates a
successor Mission, which supersedes its predecessor. Expansion is a
governance operation and is deliberately distinct from authentication
step-up.

* [Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-expansion.html)
* [Datatracker Page](https://datatracker.ietf.org/doc/draft-mcguinness-oauth-mission-expansion)
* [Individual Draft](https://datatracker.ietf.org/doc/html/draft-mcguinness-oauth-mission-expansion)
* [Compare Editor's Copy to Individual Draft](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-expansion.diff)

#### Mission Progressive Authorization for OAuth 2.0

Experimental companion to Expansion. At the initial approval the
Approver additionally consents to an authority ceiling and a drawdown
policy; the Mission Issuer may then adjudicate an expansion that stays
within the ceiling by policy instead of a fresh human approval.
High-consequence and cross-domain authority always require the human.
Under Expansion alone, every widening is human-approved.

* [Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-progressive.html)
* [Datatracker Page](https://datatracker.ietf.org/doc/draft-mcguinness-oauth-mission-progressive)
* [Individual Draft](https://datatracker.ietf.org/doc/html/draft-mcguinness-oauth-mission-progressive)
* [Compare Editor's Copy to Individual Draft](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-progressive.diff)

#### Mission Completion for OAuth 2.0

The narrowing counterpart of Expansion. Adds `terminal_when`, a
Common Constraint that discharges a `mission_resource_access`
entry when its completion condition fires, so the Authorization Server
stops deriving that entry once the task it was granted for is done.
Discharge is monotonic (only retires authority), so it is safe against
an injected agent; it lets a multi-resource Mission complete one entry
at a time; and it is the enforceable counterpart of the inert
`success_criteria`.

* [Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-completion.html)
* [Datatracker Page](https://datatracker.ietf.org/doc/draft-mcguinness-oauth-mission-completion)
* [Individual Draft](https://datatracker.ietf.org/doc/html/draft-mcguinness-oauth-mission-completion)
* [Compare Editor's Copy to Individual Draft](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-completion.diff)

#### Mission Management for OAuth 2.0

The fleet-management surface the status profile defers: authenticated
Mission enumeration (by subject, client, state, or expiry window, with
purpose-recorded audit) and bulk lifecycle operations (dry-run first,
then execute against the evaluated set, with a per-Mission outcome
manifest). Operator- and incident-response-facing; each bulk
transition applies the status profile's per-Mission semantics and
emits its per-Mission events. The highest-blast-radius surface in the
family, and documented as such.

* [Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-management.html)
* [Datatracker Page](https://datatracker.ietf.org/doc/draft-mcguinness-oauth-mission-management)
* [Individual Draft](https://datatracker.ietf.org/doc/html/draft-mcguinness-oauth-mission-management)
* [Compare Editor's Copy to Individual Draft](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-management.diff)

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

* [Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-runtime.html)
* [Datatracker Page](https://datatracker.ietf.org/doc/draft-mcguinness-mission-runtime)
* [Individual Draft](https://datatracker.ietf.org/doc/html/draft-mcguinness-mission-runtime)
* [Compare Editor's Copy to Individual Draft](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-runtime.diff)

#### Mission-Bound Runtime Enforcement: AuthZEN Profile

The concrete OpenID AuthZEN binding of the runtime decision contract. It
maps the runtime profile's abstract decision inputs onto the AuthZEN
Authorization API request and response, defines the Decision Evidence
and Execution Evidence objects, and specifies how runtime denials are
carried in an AuthZEN decision. It binds the contract; it does not
restate the enforcement semantics the runtime profile owns.

* [Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-authzen.html)
* [Datatracker Page](https://datatracker.ietf.org/doc/draft-mcguinness-mission-authzen)
* [Individual Draft](https://datatracker.ietf.org/doc/html/draft-mcguinness-mission-authzen)
* [Compare Editor's Copy to Individual Draft](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-authzen.diff)

### Alternate bindings and the substrate

#### Mission Authority Server

A peer binding and the AS-optional adoption bridge. A Mission
Authority Server implements the
Mission Issuer role (intent submission, the approval event, the record,
lifecycle, and state) without being an OAuth Authorization Server and
without deriving tokens. Enforcement joins ordinary OAuth tokens to
Missions at the Policy Decision Point, so a deployment gets Mission
governance with an unmodified AS. No Mission-bound tokens and no
issuance gating; runtime enforcement over every consequential path is
required. Its architectural rationale stands on its own: governance
deliberately decoupled from token issuance, and one Mission Issuer
governing across many Authorization Servers, which can make it the
right long-term shape rather than only a bridge. The upgrade path to
Mission-bound tokens is the issuance profile.

* [Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-authority-server.html)
* [Datatracker Page](https://datatracker.ietf.org/doc/draft-mcguinness-mission-authority-server)
* [Individual Draft](https://datatracker.ietf.org/doc/html/draft-mcguinness-mission-authority-server)
* [Compare Editor's Copy to Individual Draft](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-authority-server.diff)

#### Mission-Bound Authorization for AAuth

The AAuth binding, the first to a non-OAuth substrate. AAuth already
carries a mission reference on every signed request; this binding gives
that native concept the Mission model's structure: the AAuth Person
Server is the Mission Issuer, the mission blob carries the Mission
record and its integrity anchors under AAuth's own `s256` commitment,
the propose/clarify/approve interaction is the (natively asynchronous)
approval event, and the family lifecycle rides AAuth's two wire states
(`active`, `terminated`) with revocation and expiry made normative and
the only-`active` rule governing. Because the Person Server issues or
gates every AAuth auth token, this binding provides true issuance
gating, and the auth token is a Mission-bound credential, so runtime
enforcement composes credential-carried.

* [Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-aauth.html)
* [Datatracker Page](https://datatracker.ietf.org/doc/draft-mcguinness-mission-aauth)
* [Individual Draft](https://datatracker.ietf.org/doc/html/draft-mcguinness-mission-aauth)
* [Compare Editor's Copy to Individual Draft](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-aauth.diff)

#### Mission Substrate Requirements

For authors of new bindings. Consolidates, normatively, what any
further binding of the Mission model must provide (identifier and
origin, the lifecycle state space with the only-`active` rule, the
Authority Set with the subset rule, the integrity anchors, key
material, the audit horizon, approval-event fidelity, and either a
Mission-bound credential or a defined join). Changes nothing for the
three existing bindings, which remain authoritative for themselves;
the core remains the model's definitional home.

* [Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-substrate.html)
* [Datatracker Page](https://datatracker.ietf.org/doc/draft-mcguinness-mission-substrate)
* [Individual Draft](https://datatracker.ietf.org/doc/html/draft-mcguinness-mission-substrate)
* [Compare Editor's Copy to Individual Draft](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-substrate.diff)

#### Mission Consumption Metering

Experimental. Defines the cumulative consumption bounds a Mission
Intent may carry (`max_budget`, `max_calls`, `max_duration`), the
runtime metering that enforces them (atomic check-and-decrement,
reserve/commit postures, duration leases, settlement), and the AuthZEN
wire binding for lease renewal and settlement. Without it, Missions
carry no cumulative bounds; the runtime profile's fail-closed rule
covers any bound a deployment cannot meter.

* [Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-metering.html)
* [Datatracker Page](https://datatracker.ietf.org/doc/draft-mcguinness-mission-metering)
* [Individual Draft](https://datatracker.ietf.org/doc/html/draft-mcguinness-mission-metering)
* [Compare Editor's Copy to Individual Draft](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-metering.diff)

### Agent runtime

#### Mission-Aware Agent Harnesses

How an agent harness binds sessions, task graphs, queues, cached tool
connections, and sub-agent handles to Mission state, when it must
re-check status, and how it must pause, suppress, or terminate work when
the Mission is no longer active. It also establishes the mediated
execution environment the runtime profile relies on: for mediated action
classes, governed work runs with no unmediated path to the resource. The
core principle: session continuity is not authority.

* [Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-harness.html)
* [Datatracker Page](https://datatracker.ietf.org/doc/draft-mcguinness-mission-harness)
* [Individual Draft](https://datatracker.ietf.org/doc/html/draft-mcguinness-mission-harness)
* [Compare Editor's Copy to Individual Draft](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-harness.diff)

#### Mission Orchestration and Unwinding

How a multi-step or multi-Mission workflow assigns a reversibility class
to each step, records an unwind plan before dispatch, and unwinds
in-flight work safely when a Mission stops, including compensation after
termination. It governs how workflow state is unwound once continuation
is stopped.

* [Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-orchestration.html)
* [Datatracker Page](https://datatracker.ietf.org/doc/draft-mcguinness-mission-orchestration)
* [Individual Draft](https://datatracker.ietf.org/doc/html/draft-mcguinness-mission-orchestration)
* [Compare Editor's Copy to Individual Draft](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-orchestration.diff)

### Sub-agents

#### Mission Child Delegation for OAuth 2.0

Lets a parent Mission authorize a Child Mission for a sub-agent, with
explicit parent lineage, strict-subset authority, expiry no later than
the parent, fan-out controls, and cascade revocation when the parent is
no longer active. A child is never created by session ancestry alone.

* [Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-child-delegation.html)
* [Datatracker Page](https://datatracker.ietf.org/doc/draft-mcguinness-oauth-mission-child-delegation)
* [Individual Draft](https://datatracker.ietf.org/doc/html/draft-mcguinness-oauth-mission-child-delegation)
* [Compare Editor's Copy to Individual Draft](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-child-delegation.diff)

#### Mission Offline Attenuation for OAuth 2.0

Removes the Authorization Server from the sub-agent fan-out hot path.
Profiles Attenuating Agent Tokens so a Mission-bound token holder mints a
narrower child token offline, carrying the same `mission` claim; the
narrowing is verifiable from the carried token chain. The kill switch is
preserved because consumption is gated by the runtime layer re-checking
Mission state, so a revoked Mission stops the whole chain. A capability
for deployments running the runtime enforcement profile, offered
alongside Authorization-Server-mediated delegation.

* [Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-attenuation.html)
* [Datatracker Page](https://datatracker.ietf.org/doc/draft-mcguinness-oauth-mission-attenuation)
* [Individual Draft](https://datatracker.ietf.org/doc/html/draft-mcguinness-oauth-mission-attenuation)
* [Compare Editor's Copy to Individual Draft](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-attenuation.diff)

### Cross-domain projection

#### Mission Cross-Domain Projection for OAuth 2.0

Lets a single Mission be honored by Authorization Servers in other
trust domains: the originating Mission Issuer projects audience-scoped
authority through a short-lived, sender-constrained cross-domain grant
(ID-JAG recommended), and the Resource AS mints its own local
Mission-bound tokens from it, preserving the `mission` claim unchanged.
One hop; the single-domain core is complete without it. Extracted from
the core so the mandatory profile carries no cross-domain dependencies.

* [Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-cross-domain.html)
* [Datatracker Page](https://datatracker.ietf.org/doc/draft-mcguinness-oauth-mission-cross-domain)
* [Individual Draft](https://datatracker.ietf.org/doc/html/draft-mcguinness-oauth-mission-cross-domain)
* [Compare Editor's Copy to Individual Draft](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-cross-domain.diff)

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

* [Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-mandate.html)
* [Datatracker Page](https://datatracker.ietf.org/doc/draft-mcguinness-mission-mandate)
* [Individual Draft](https://datatracker.ietf.org/doc/html/draft-mcguinness-mission-mandate)
* [Compare Editor's Copy to Individual Draft](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-mandate.diff)

#### Mission Audit Transparency

Makes the suite's evidence tamper-evident and independently verifiable.
Registers Mission evidence (the approval event, lifecycle transitions,
runtime and consent evidence) into a SCITT Transparency Service as
Signed Statements, with the Mission as the statement subject so a
Mission's records form one append-only feed, and binds the Receipt back
so any party, in any domain, can verify inclusion offline. Statements
commit to evidence by hash, so sensitive task data stays out of the log.
Layers onto any bundle.

* [Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-audit.html)
* [Datatracker Page](https://datatracker.ietf.org/doc/draft-mcguinness-mission-audit)
* [Individual Draft](https://datatracker.ietf.org/doc/html/draft-mcguinness-mission-audit)
* [Compare Editor's Copy to Individual Draft](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-audit.diff)

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

* [Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-security-model.html)
* [Datatracker Page](https://datatracker.ietf.org/doc/draft-mcguinness-mission-security-model)
* [Individual Draft](https://datatracker.ietf.org/doc/html/draft-mcguinness-mission-security-model)
* [Compare Editor's Copy to Individual Draft](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-security-model.diff)

## Contributing

See the
[guidelines for contributions](https://github.com/mcguinness/mission-bound-authorization/blob/main/CONTRIBUTING.md).

The contributing file also has tips on how to make contributions, if you
don't already know how to do that.

## Command Line Usage

Formatted text and HTML versions of the draft can be built using `make`.

```sh
$ make
```

Command line usage requires that you have the necessary software installed.  See
[the instructions](https://github.com/martinthomson/i-d-template/blob/main/doc/SETUP.md).
