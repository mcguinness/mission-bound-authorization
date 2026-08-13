<!-- regenerate: off (edited by hand; set to on to let i-d-template regenerate) -->

# Mission-Bound Authorization

An AI agent is given a *mission* (book the trip, reconcile the ledger,
triage the inbox) and then takes many actions, across many resources,
over a long time, often spawning sub-agents and surviving restarts.
OAuth 2.0 issues access tokens for individual resource requests; a bag
of independently issued tokens cannot express "this is the task the
user approved, here is its boundary, and here is when it ends."

This is the working area for a family of Internet-Drafts that close
that gap with the **Mission**: a durable, approval-backed *governance*
object for authorization. A Mission is not a new way to express
authority; it is the approved task, with a lifecycle, that authority
is derived for, bound to, and gated on. Read as one system, the drafts
define a **delegated-authority layer**: authentication says who is
acting, and entitlement governance says what a principal may hold;
this layer governs the approved task itself, with lifecycle, bounded
authority, per-action enforcement, delegation, evidence, and
management surfaces. Operationally the layer splits the way that
vocabulary implies: the Mission Issuer is the control plane, holding
the approved task and distributing bounded authority, and tokens
with the PEP/PDP boundary are its data plane.

At a glance:

- **37 drafts, deliberately decomposed.** One mandatory core (the
  OAuth 2.0 issuance profile, [on the
  datatracker](https://datatracker.ietf.org/doc/draft-mcguinness-oauth-mission/)),
  three further bindings (one an experimental sketch) and normative
  substrate requirements, optional companion profiles organized by
  verb, and two Informational views (the Architecture and the
  Security Model).
- **Four assurance levels and named claims.** The levels (Baseline
  Issuance, Runtime-Enforced, Governed Agent, and
  High-Assurance Agent) are the adoption ladder: what to deploy, in
  the order deployments build it. What may be claimed is the
  orthogonal set of named assurance claims a deployment lists in its
  Deployment Profile. The first three levels run on ratified
  dependencies and the tracked in-progress ones noted below.
- **Three authorization bindings, an AAuth context binding, and one
  sketch.** The OAuth Authorization Server and standalone Mission
  Authority Server carry the family's portable-authority model. The
  AAuth Person Server supplies the shared approval, reference,
  lifecycle-gate, and audit capabilities in AAuth's own contextual
  governance model. The UMA 2.0 binding remains an experimental
  sketch.

**Start with the
[Architecture](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-architecture.html)
and the [OAuth
core](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission.html).**
Everything else is optional companion work, and the minimal
implementation below fits on one screen. For the story told in prose
rather than protocol, the
**[Mission Handbook](https://notes.karlmcguinness.com/mission-handbook/)**
is the published narrative companion: it motivates the model,
chapter by chapter, for readers who want the why before the wire.

## The Mission

This work defines the Mission: a durable object, created by an explicit
approval event, that expresses an approved task and its lifecycle. The
Mission does not itself express authority. Bindings share an approved
task, stable reference, lifecycle gate, and governance record; their
authority representation is binding-dependent. In the OAuth binding,
Rich Authorization Requests express authority, a client proposes a
**Mission Intent**, the Mission Issuer derives an **Authority Set**, and
an **approval event** commits both as `intent_hash` and
`authority_hash`. AAuth instead keeps the approved natural-language
context at the Person Server and leaves deterministic resource
authorization to scopes, resource tokens, Resource and Access Server
policy, and optionally R3.

The Mission control point has three implemented bindings. In the **OAuth binding**,
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
that cannot yet change their AS. In the **AAuth binding**, the AAuth
Person Server is the controlling authority for the native Mission
Context: AAuth's propose/clarify/approve flow creates an exact-byte
committed blob identified by `{approver, s256}`, with `active` and
`terminated` state and an ordered mission log. The Person Server gates
new authorization only when it is on the path: person-token issuance,
PS-asserted, and federated access. Identity-based and resource-managed
access remain direct resource decisions; a mission travels as
`mission_s256` inside PS-issued person tokens, and a resource must
copy it into the resource tokens it issues. An
experimental fourth binding is sketched for the
**UMA 2.0** Authorization Server: the pushed Mission Intent rides UMA
claims pushing, the resource owner's decision fills UMA's deliberately
unspecified authorization assessment, and every RPT issuance is gated
on Mission state. The OAuth-shaped bindings preserve monotonic
narrowing. AAuth deliberately does not impose a universal cross-hop
subset rule: each chained downstream hop is a fresh resource decision,
with contextual governance applied by the Person Server when it is on
the path.

The **core** defines the model and its OAuth 2.0 binding. Everything
else is an OPTIONAL companion profile that layers on without changing
it.

## The architecture

```
 propose      Mission Intent Shaping (client side, untrusted proposal)
                         |
                         v
 approve      Mission control point, one of four bindings:
 and record   +-------------+ +-------------+ +-------------+ +-------------+
              | OAuth AS    | | Standalone  | | AAuth PS:   | | UMA 2.0 AS  |
              | (core): PAR | | MAS: async  | | native      | | (sketch):   |
              | -> approval | | approvals,  | | missions,   | | tickets +   |
              | tokens      | | no tokens,  | | context +   | | pushed      |
              | gated on    | | PDP joins   | | PS-path     | | Intent, RPT |
              | state       | | to Mission  | | gating      | | state-gated |
              +-------------+ +-------------+ +-------------+ +-------------+
                       \             |             |             /
                        v            v             v            v
              THE MISSION: durable approved context and lifecycle;
              portable authority commitments are binding-dependent
                         |
 govern       Status (pull)    Signals (push)
              Expansion (widen via a successor)
              Completion (retire authority per entry)
              Discovery (bind encountered resources
              within a consented ceiling; experimental)
 contain      Containment (issuer-held monotonic narrowing of a live
              Mission's authority, driven by protected events)
                         |
 enforce      Runtime contract -> AuthZEN binding: a PEP obtains a
 each action  PDP permit before every consequential action
                         |
 run and      Harness (session continuity is not authority)
 wind down    Orchestration (unwind in-flight work safely)

 delegate     Child Delegation (child Missions, cascade revocation)
              Offline Attenuation (narrower tokens minted offline)

 dispatch     Mission Template (consent once to a ceiling, then
              instantiate many Missions from it at machine speed;
              experimental)

 project      Cross-Domain Projection (one Mission honored in
              another trust domain via the cross-domain grant)

 continue     Mission Continuation (authorization continuity over
              ICA, async delegation, and cross-domain transports)

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
citable form of this view: the capability envelope, a Mission's life
end to end, the invariants, components, the substrate interface, the
verbs, deployment patterns, the assurance levels, the Deployment
Profile, and the requirements the family answers.

## How to read this suite

Newcomers start with the Architecture document; implementers start
with the core's Introduction, Overview, and terminology, which every
companion assumes. From there, follow the path that matches your role:

- **Understand the model** (an afternoon): the Architecture document
  (the citable form of this page's structural view), then the core's
  Introduction and Overview, then the Security Model for the trust
  picture in one view.
- **Implement issuance at an Authorization Server** (identity vendors):
  the core, then Status (the state surface, including completion and
  per-entry discharge; Signals is its push complement), Consent
  Evidence (approval-surface evidence), Expansion
  (growing authority), Deferred Approval if approvals
  are asynchronous, Cross-Domain Projection when Missions span
  trust domains, and Discovery (experimental, with Progressive) when
  agents meet resources mid-task: the encounter is adjudicated at
  the issuer.
- **Deploy without changing your AS, or govern an estate**: Mission
  Authority Server, then Runtime Enforcement and its AuthZEN binding
  (mandatory in this mode), then the Harness; add Consent Evidence for
  the Governed Agent level. Its Enterprise Mission Authority Profile
  is the estate operating mode (Join Assertions, instance-bound joins,
  policy-view distribution), with Management for fleet operations.
- **Build enforcement (a PDP or PEP)**: Runtime Enforcement, then the
  AuthZEN binding; read runtime's custody section and the Harness's
  mediation section for where keys live.
- **Build an agent harness or orchestrator**: Harness, then
  Orchestration, with Runtime Enforcement for the gate they feed; Child
  Delegation when sub-agents get their own Missions; Discovery when
  agents work the open world (the harness reports taint and admits
  discovered channels into its egress enumeration).
- **Audit or review security**: Security Model first, then Consent
  Evidence, Audit Transparency, and Mandate; each profile's own
  Security Considerations remain normative.

## The minimal implementation

The first useful piece is one profile, not the suite. A minimal
conforming deployment of the core implements:

- `mission_intent` submission through Pushed Authorization Requests;
- derivation of the Authority Set, in narrowing mode from the standard
  `authorization_details` authority proposal pushed alongside the
  Intent;
- the Mission record with its `intent_hash` and `authority_hash`
  integrity anchors (plus `proposal_hash` where a proposal was
  submitted);
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
within approved authority is out of scope. Choose the level that
matches the risk: Baseline Issuance for low-risk multi-token
workflows, Runtime-Enforced for agents that take consequential
actions.

## What to deploy

Each draft is optional on its own, but the properties many readers
assume from "Mission-bound agents" (action-time checks, prompt stop,
unwinding, consent evidence) only arrive when several are deployed
together. Most agent deployments therefore want a level, not the core
alone. The Mission Assurance Levels name what to deploy for a goal
and what may be claimed; the Architecture document defines them
citably. The short names in the table are the drafts' nicknames; each
maps to a document described under "The documents" below (mission is
the core; the rest are the companion profiles of the same names).

The level is one axis and the authority-bearing binding is another.
An AAuth deployment reports its native Mission Context capabilities
and resource access modes separately; choosing AAuth does not by itself
satisfy the levels' structured-authority or runtime proof obligations.

| Level | Drafts | What you get |
|---|---|---|
| **Baseline Issuance** | mission | Approved, integrity-bound Missions; state-gated issuance where the binding places the Mission authority on the issuance path; a possession-independent kill switch there (outstanding tokens run to expiry; prompt cutoff needs the Runtime-Enforced level). The cutoff is binding-dependent: the standalone MAS has no issuance gate, and AAuth gates PS-asserted and federated access but not direct identity-based or resource-managed decisions. With token lifetimes sized to the declared staleness bound (lifetime-bounded reliance), revocation takes effect within one lifetime on gated paths; what this level lacks is per-action enforcement and parameter binding. OAuth day-one AS prerequisites are PAR, RAR, and JWT access tokens; the standalone MAS and AAuth binding do not inherit them. |
| **Runtime-Enforced** | mission + runtime + authzen + a freshness source (status or issuer token introspection; signals adds push) | Per-action enforcement at the point of use, and prompt revocation. The smallest deployment that makes a Mission-bound token more than governance metadata, and its dependencies are ratified apart from the tracked in-progress ones noted below. For the high-consequence classes, runtime requires an active freshness source, not token-lifetime expiry. |
| **Governed Agent** (recommended for AI agents) | Runtime-Enforced + consent-evidence + harness | Consent-rendering evidence and session-continuity stop. Add child-delegation for sub-agents and expansion for mid-task growth, orchestration (experimental) for safe unwinding of in-flight work, and discovery (experimental, with progressive) for agents that meet resources their approval could not name. |
| **High-Assurance Agent** | Governed Agent + mediated custody, no unmediated path, action-bound approval, active freshness, agent-isolated approval rendering | Resistance to a compromised agent: the runtime profile's named agent-compromise-resistant enforcement and trifecta containment claims (see the note below the table), optionally bound to execution-environment attestation. |

Most estates start, and many legacy resources stay, on
**lifetime-bounded reliance**: short-lived Mission-bound tokens whose
expiry is the state check, with no status or introspection calls at
the resource. The runtime layer is an overlay for the paths whose
consequence warrants it, not a prerequisite for every resource; only
the three high-consequence classes require an active freshness
source.

The model deploys through four bindings, one of them an experimental
sketch. The OAuth binding is the
core's own: the Authorization Server implements the
issuance profile, tokens carry the `mission` claim, and issuance is
gated on Mission state. The standalone binding runs a Mission
Authority Server: a peer binding whose architectural rationale
(governance decoupled from token issuance; one Mission Issuer across
many ASes) can make it the right long-term shape for some
deployments, and which also serves as the adoption bridge where the
AS cannot yet change. The issuance grant profile is its middle path:
estate ASs redeem MAS-minted grants for Mission-bound, state-gated
tokens without taking on the core's approval surfaces. The AAuth binding
hosts AAuth's native Mission Context at the Person Server. It gates
PS-asserted issuance and federated brokering while leaving
identity-based and resource-managed decisions at the resource. Its
native `mission` claim carries `{approver, s256}` as context rather than
the OAuth family claim or a portable Authority Set. The
UMA 2.0 binding (experimental) fills UMA's deliberately unspecified
authorization assessment with the Mission: the pushed Intent rides
claims pushing, `request_submitted` is the native deferred approval,
and every RPT issuance and upgrade is gated on Mission state. The Mission Mandate makes a Mission portable
across the authority-bearing bindings: a signed, verifiable statement
of what was approved, checkable by any party without a token exchange.
It is not a baseline AAuth facility; an AAuth evidence extension would
bind receipts to the native `{approver, s256}` reference instead.

A deployment states what it claims in a **Mission Deployment
Profile**, the architecture's publishable manifest of level, binding,
state sources and staleness bounds, PEP coverage, custody, evidence,
and residual risks. Two deployments that both "support Mission" but
publish different profiles provide different security properties.

Mission Intent Shaping is an approval-time, client-side option for the
OAuth-shaped bindings; it produces the Mission Intent and is not itself
deployed at the Authorization Server. AAuth uses its native mission
proposal instead. Mission Deferred Approval is an
approval-time option for deployments whose approvals are asynchronous or
whose reviewers narrow a proposed Mission; it layers onto the
OAuth-binding levels (the Mission Authority Server, the AAuth
Person Server, and the UMA binding are natively asynchronous and do
not use it).

Each draft also states its own scoped conformance; the levels are
guidance, not a new conformance class.

In particular, adopting the Governed Agent level does not by itself make a
deployment resistant to a compromised agent. That is the runtime
profile's named *agent-compromise-resistant enforcement* claim, which
holds only when all five of its conditions are met for the
high-consequence classes: mediated credential custody, no unmediated
path to those actions, an action-bound approval, an active-freshness
state source, and an approval disclosure rendered by a component
isolated from the agent. Mediated custody moves the high-consequence
sender-constraint key out of the agent and into the mediating Policy
Enforcement Point; this *relocates* the credential rather than removing
it, so the mediating PEP becomes a critical trusted component whose own
compromise is out of scope. A deployment that leaves any of the five
conditions unmet, or that cannot place a PEP on every path to a mediated
action, must not represent itself as resistant to agent compromise.

### Adoption order

What to implement, in order. This is deployment advice; dependency
facts are the next subsection.

1. **Adopt first**: read the **architecture**; then implement the
   **core** (the minimal implementation above) where the AS can
   change, or start at **authority-server** phase 1 (records and
   approvals, no enforcement change) where it cannot. The
   architecture's entry-ramp table maps estate starting conditions
   to the right ramp.
2. **Implementation minimum** for agents that act: **status**,
   **runtime**, **runtime-evidence**, **authzen** (the
   Runtime-Enforced level).
3. **Recommended for AI agents**: **consent-evidence** and **harness**
   (the Governed Agent level).
4. **By binding, where the estate calls for it**: **authority-server**
   (the standalone binding and estate control plane, where the AS
   cannot change or one Mission Issuer governs many systems; its PDP
   join is the family's newest mechanism), **aauth** (where the
   substrate is AAuth), **aauth-management** (native AAuth status,
   permanent termination, expiry, and delegation-tree queries),
   **aauth-expiry** (profiles AAuth's native `expires_at` mission
   lifetime bound; the
   **aauth** binding requires it), **issuance-grant** (the issuance join:
   estate ASs redeem MAS-minted grants for Mission-bound,
   state-gated tokens), **substrate** (for authors of new bindings).
5. **Advanced, when the use case arrives**: **approval** (asynchronous
   approvals), **approval-governance** (authenticated,
   policy-authorized approval provenance for multi-party or
   policy-delegated decisions), **expansion**, **child-delegation**,
   **cross-domain**, **management**, **mandate**, **audit**,
   **capability-binding** (catalog and MCP tool drift detection),
   **shaping**, **signals** (push latency optimization over correctly
   sized status polling).
6. **Experimental, adopt for evaluation only**:
   **approval-revision**, **progressive**, **template** (consent once
   to a ceiling, then dispatch Missions from it at machine speed),
   **metering**, **attenuation**, **orchestration**, **discovery**
   (open-world encounters adjudicated against a pre-consented ceiling
   or by the binding's Controller in context, with the lying-resource
   and tainted-session floors),
   **work-products** (keeps information from carrying the producing
   Mission's authority across a handoff), **containment** (narrows a
   live Mission's effective authority without ending it),
   **mission-continuation** (authorization continuity over ICA /
   async-delegation / cross-domain transports), **uma** (the UMA 2.0
   binding sketch, the first written against the substrate contract).
   Each names a stable path to prefer where one exists.

The architecture and security model are Informational companions and
sit outside the ordering.

### Dependency stability

Outside the family itself, every normative dependency is a ratified
RFC, a finalized OpenID specification, or (for the **uma** sketch) a
final Kantara Initiative Recommendation, with these tracked
exceptions: the **core** has a normative dependency on an
unratified individual draft (OAuth 2.0 RAR Metadata and Error
Remediation): an AS that advertises Mission-bound authorization
support MUST advertise the authorization-details type-metadata
endpoint that draft defines, and its reference to the OAuth Actor
Profile is informative and confined to its OPTIONAL Delegation
capability; **status** depends on the OAuth Status List (a
working-group document); **cross-domain** depends on OAuth
identity chaining (approved, in the RFC Editor queue) and ID-JAG (a
working-group document); **audit**'s COSE hash envelope is approved
and in the RFC Editor queue; **approval**, **attenuation**, **aauth**,
**aauth-expiry**, and **aauth-management** track unratified individual
drafts (OAuth
Deferred Token Response, Attenuating Agent Tokens, and the AAuth
protocol); **authority-server** confines its Internet-Draft
references (client instance assertion and the AI agent instance
profile) to the
Enterprise Mission Authority Profile's instance-bound joins, an
optional hardening above the base conformance floor. For
**authzen**, the decision binding tracks the AuthZEN working group:
the core evaluation API, and normatively the Access Request and
Approval Profile (ARAP) and the Obligations Profile, both
working-group drafts. **capability-binding**'s Model Context Protocol
tool-authorization (COAZ) integration remains informative and
optional.

Family-internal normative dependencies are Internet-Drafts by
construction: the substrate contract anchors the **uma**,
**authority-server**, and **aauth** Statements; **aauth-expiry**
anchors the AAuth binding and its management companion; and the
**core** anchors its OAuth companions. The family manifest tracks
these. The substrate contract publishes before or with any binding
that claims conformance to it.

In short: steps 1 through 3 rest on ratified dependencies and the
tracked in-progress ones noted above; everything experimental is
additive and can wait.

## The standardization ask

The ask is not adoption of the suite. It is: adopt the Mission model
and the OAuth issuance profile as the stable substrate for task-bound
delegated authorization. Runtime, lifecycle, evidence, and
cross-domain profiles proceed as companion drafts on their own
timelines.

## The documents

Together these drafts form the **Mission-Bound Authorization suite**.
The suite takes its name from the model; the core's title,
"Mission-Bound Authorization for OAuth 2.0", names the binding the
core defines. The companions refer to the core as the **"issuance profile"**
(it governs issuance and derivation).

The naming encodes a boundary. Profiles that extend the Authorization
Server's own surfaces (issuance, approval, lifecycle, evidence of
consent) keep "oauth" in their draft names. Profiles that specify
components outside the Authorization Server (runtime enforcement and
its AuthZEN binding, the agent harness, orchestration, intent shaping,
audit transparency, the security model, the architecture, the
standalone authority server, the AAuth binding, the substrate
requirements, consumption metering, open-world discovery, and the
mandate) are named without it:
they are defined against
the Mission model's substrate primitives, each names those primitives
in a Mission Substrate section, and the core is that model's OAuth 2.0
binding. Another mission-based protocol that supplies the same
primitives can host them unchanged.

### Architecture

#### An Architecture for Mission-Bound Authorization

The single structural view: the delegated-authority-layer thesis, the
capability envelope, a Mission's life end to end, the seven
invariants, roles and components, the substrate interface (the
primitives a binding provides and the profiles consume), the verb
spine, deployment patterns, the Mission Assurance Levels, the
Deployment Profile, and the requirements the family answers.
Informational; it defines no mechanism, and the profiles remain
authoritative. Read this first.

[Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-architecture.html)

### The core

#### Mission-Bound Authorization for OAuth 2.0

The mandatory core, the **issuance profile**. Defines the Mission, the
Mission Intent and Authority Set, the approval event and its
`intent_hash` / `authority_hash` integrity anchors, the `mission` token
claim, the subset rule, and state-gated issuance. Every other document
builds on this one.

[Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission.html) · [Datatracker](https://datatracker.ietf.org/doc/draft-mcguinness-oauth-mission) · [Individual Draft](https://datatracker.ietf.org/doc/html/draft-mcguinness-oauth-mission) · [Diff](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission.diff)

### Approval time

#### Mission Intent Shaping

How a client-side "shaper" turns a user's request into a candidate
Mission Intent before it is submitted. The shaper only proposes: its
output is untrusted input until the Mission Issuer validates, narrows,
and derives authority from it. OPTIONAL Shaping Evidence records how
the proposal was produced. (Informational.)

[Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-shaping.html)

#### Mission Consent Evidence for OAuth 2.0

Commits the structured consent disclosure shown to the Approver at the
approval event, through a `consent_rendering_hash` and a signed Consent
Evidence object, so an auditor can reconstruct the recorded approval
surface. A translation floor requires the disclosure to render
authority as natural language rather than serialized structure, and
Disclosure Interrogation lets the Approver ask why an entry is needed
before deciding, answered from recorded shaping and provenance
material. It commits what the Authorization Server recorded, not the
pixels presented or the Approver's comprehension.

[Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-consent-evidence.html)

#### Mission Deferred Approval for OAuth 2.0

Makes the approval event asynchronous. Profiles OAuth
Deferred Token Response so a Mission approval can be deferred and
polled; the Mission record is created atomically with the asynchronous
decision. A proposal the reviewer will grant only in narrowed form
resolves to a denial, and the client resubmits a narrower Intent.

[Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-approval.html)

#### Mission Approval Governance

Extracts approval-authority provenance into the Approval Governance
Record: an issuer-retained, issuer-signed record of who approved,
under which authority, and why the decision satisfied governance.
Assertions are authenticated, event-bound, and policy-authorized
before the evaluation contributes to Mission activation; the
committed record is immutable and never appears on tokens, protocol
messages, or enforcement projections. Required by the Enterprise
Mission Authority Profile under its recording triggers.

[Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-approval-governance.html)

#### Mission Approval Revision for OAuth 2.0

Experimental companion to Deferred Approval. Adds a `revisable` mode:
when the Authorization Server can grant only a narrowed version of the
proposed Mission, it signals which dimensions it refused and invites
the client to push a narrowing revision, continuing the same deferred
approval instead of starting over. Narrowing only; deny-and-resubmit
under Deferred Approval alone is the stable path.

[Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-approval-revision.html)

#### Mission Template for OAuth 2.0

Experimental. An Approver consents once to a task template: a ceiling of
resources, actions, and constraints, plus a dispatch policy and bounds.
Each dispatch then instantiates an ordinary Mission from the template by
policy, at machine speed, with no fresh approval per run. Every instance
is a full Mission, bounded by its own derived Authority Set,
independently gated and revocable, and never exceeding the ceiling.
High-consequence authority classes are never dispatched by policy; they
stay on a fresh human decision.

[Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-template.html)

### Lifecycle

#### Mission Status and Lifecycle for OAuth 2.0

A `mission_id`-keyed status surface with signed responses, plus a
lifecycle endpoint for explicit `revoke`, `suspend`, `resume`, and
`complete` transitions and the `suspended` and `completed` states. It
lets a consumer holding only a `mission_id` ask the issuer for current
Mission state, and an authorized party change it. It also defines
Mission Completion, the narrowing counterpart of Expansion:
`terminal_when`, a Common Constraint that discharges a
`mission_resource_access` entry when its completion condition fires,
monotonic (only retires authority) and so safe against an injected
agent.

[Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-status.html)

#### Mission Lifecycle Signals for OAuth 2.0

A profile of the OpenID Shared Signals Framework: the
Mission Issuer
emits a signed Security Event Token on each Mission lifecycle
transition, delivered by push or poll, so a consumer learns of a
revocation, expiry, or other transition promptly without polling. It is
the push complement to the pull-based Status surface, a latency
optimization for deployments where per-Mission polling does not scale.

[Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-signals.html)

#### Mission Expansion for OAuth 2.0

How to widen a Mission's authority. Because authority can only narrow
within a Mission, widening requires a fresh approval that creates a
successor Mission, which supersedes its predecessor. Expansion is a
governance operation and is deliberately distinct from authentication
step-up.

[Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-expansion.html)

#### Mission Progressive Authorization for OAuth 2.0

Experimental companion to Expansion. At the initial approval the
Approver additionally consents to an authority ceiling and a drawdown
policy; the Mission Issuer may then adjudicate an expansion that stays
within the ceiling by policy instead of a fresh human approval.
High-consequence and cross-domain authority always require the human.
Under Expansion alone, every widening is human-approved.

[Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-progressive.html)

#### Mission Open-World Discovery

Experimental. Makes discovery a governed operation for agents that
meet resources their approval could not name. Defines the Encounter,
resource identity pinning (origin, the RFC 9728 resource-to-AS
metadata chain, self-declaration digests), Discovery Adjudication in
two modes (against a pre-consented ceiling, or contextually by the
binding's Controller as the AAuth Person Server does; bind, route to
a human, or refuse; default-closed in both), and Discovery Evidence
for the transparency log.
Two floors hold regardless of policy: a resource's self-declaration
never classifies its own consequences, and a tainted session never
binds egress-capable authority without a human.

[Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-discovery.html)

#### Mission Management for OAuth 2.0

The fleet-management surface the status profile defers: authenticated
Mission enumeration (by subject, client, state, or expiry window, with
purpose-recorded audit) and bulk lifecycle operations (dry-run first,
then execute against the evaluated set, with a per-Mission outcome
manifest). Operator- and incident-response-facing; each bulk
transition applies the status profile's per-Mission semantics and
emits its per-Mission events. The highest-blast-radius surface in the
family, and documented as such.

[Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-management.html)

#### AAuth Mission Management

The AAuth-native companion promised by the AAuth protocol: authenticated
status, permanent termination, optional immutable expiry, and
delegation-tree queries at the existing Person Server
`mission_endpoint`. Operations use only AAuth's native
`{approver, s256}` mission reference and preserve its two protocol states,
`active` and `terminated`; completion, revocation, expiry, supersession,
and administrative action are separate termination reasons. The Person
Server closes its local decision and issuance paths atomically, attempts
revocation of tracked Auth Tokens by `(iss, jti)`, and reports honestly
where already-issued, opaque, identity-based, or off-path access leaves a
bounded or unknown residual.

[Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-aauth-management.html)

#### AAuth Mission Expiry

Profiles AAuth's `expires_at` mission-blob member: an immutable,
consent-bound lifetime the base protocol enforces on every Person
Server decision path, with lifetime caps on every token carrying
`mission_s256`. This profile adds RFC 3339 date-time precision,
clock-skew documentation duties, and prompt termination at the
deadline. The Mission Context Binding for AAuth requires the member
on every mission.

[Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-aauth-mission-expiry.html)

#### Mission Containment for OAuth 2.0

Optional. Narrows a live Mission without ending it. When a declared
protected event fires (a tainted read, an anomaly signal, a discovery
tainted-session event), the Mission Issuer commits a contain transition:
an issuer-held, versioned overlay removes capability from the Mission's
effective authority while the Mission stays active and the approved
anchors stay immutable. Containment is monotonic and removal-only, and
every derivation (token, child, cross-domain, offline) is gated on the
effective authority. Removed authority returns only through a successor
Mission under the expansion profile, with the predecessor's containment
history disclosed to the Approver.

[Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-containment.html)

### Runtime enforcement

#### Mission-Bound Runtime Enforcement

A decision contract for enforcing a Mission-bound token at the point of
use: within a declared enforcement scope, before each consequential
action a Policy Enforcement Point obtains a permit from a Policy
Decision Point that evaluates the action against the Mission. Covers
action classification, where the enforcement point sits, the binding of
a permit to concrete request parameters to close the time-of-check to
time-of-use gap, the fail-closed posture for consumption bounds, and
fail-closed behavior generally. For the
high-consequence classes it adds credential custody and mediated
execution (the enforcement point, not the agent, holds the token's
sender-constraint key, so a compromised agent cannot act off-path) and
an action-bound approval for the highest-consequence classes. The
decision-API wire format is a deployment choice, so the contract does
not mandate one. Its two named claims, agent-compromise-resistant
enforcement and trifecta containment, set the High-Assurance Agent
bar, and the Mission Receipt makes a single action's evidence
portable.

[Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-runtime.html)

#### Mission Runtime Evidence

The binding-neutral Decision Evidence, Execution Evidence, and
Refusal Record objects a decision-API binding's PDP and PEP emit:
their members, canonicalization, integrity envelope, media types,
and retention. Defined against the runtime profile's abstract
decision output and failure classification, so any decision-API
binding produces the same records; the AuthZEN binding is one such
producer and emits them unchanged. Correlation across records and
wire artifacts of one evaluation is by `evaluation_id`; each record
additionally carries its own record identifier.

[Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-runtime-evidence.html)

#### Mission-Bound Runtime Enforcement: AuthZEN Profile

The concrete OpenID AuthZEN binding of the runtime decision contract. It
maps the runtime profile's abstract decision inputs onto the AuthZEN
Authorization API request and response, emits the Decision Evidence,
Execution Evidence, and Refusal Record of the runtime evidence
companion, and maps every runtime failure condition onto a
wire-visible identifier. It binds the contract; it does not restate
the enforcement semantics the runtime profile owns or the record
formats the runtime evidence companion owns.

[Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-authzen.html)

### Alternate bindings and the substrate

#### Mission Authority Server

A peer binding, the AS-optional deployment mode, and the estate
control plane of the delegated-authority layer. A Mission Authority
Server implements the Mission Issuer role (intent submission, the
approval event, the record, lifecycle, and state) without being an
OAuth Authorization Server and without deriving tokens. Enforcement
joins ordinary OAuth tokens to Missions at the Policy Decision Point,
so a deployment gets Mission governance with an unmodified AS. No
Mission-bound tokens and no issuance gating; runtime enforcement over
every consequential path is required. Above the conformance floor,
the Enterprise Mission Authority Profile is the estate operating
mode: Join Assertions, instance-bound joins, a mapping contract,
policy-view distribution, and documented PEP coverage, with a
deployment topology, connector patterns, and a progressive adoption
path. Where an AS later becomes Mission-aware, the issuance profile
adds Mission-bound tokens for its resources while the MAS continues
to govern the estate.

[Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-authority-server.html)

#### Mission Issuance Grant for OAuth 2.0

The issuance join: the middle integration between the standalone
binding and a natively Mission-aware AS. A short-lived, one-time,
audience-bound assertion minted by the Mission Authority Server for
an active Mission; an estate Authorization Server redeems it at its
token endpoint (RFC 7523 JWT authorization grant) and mints
Mission-bound tokens bounded by the grant's authority subset, capped
at Mission expiry, with refresh gated on Mission state. Restores
Mission-bound credentials and the issuance-gate kill switch without
the AS implementing the core's intake, approval, or derivation
surfaces.

[Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-issuance-grant.html)

#### Mission Context Binding for AAuth

The thin AAuth-native binding. AAuth already defines an immutable
mission blob, exact-byte `s256` commitment, `{approver, s256}` reference,
propose/clarify/approve flow, native `expires_at`, `active` and
`terminated` states, and an ordered mission log. The binding uses those
elements unchanged and defines no new wire members. It treats the
Person Server as the controlling authority for contextual governance,
while scopes, resource tokens, Resource and Access Server policy, and
optionally R3 carry deterministic resource authorization.
`approved_tools` are tool invocations exempt from per-call permission
at the Person Server; they are not remote resource authority. A
mission travels as `mission_s256` in PS-issued person tokens; resources
must copy it into the resource tokens they issue. Active-state
issuance gating is structural in PS-asserted and federated access, and
person-token issuance is itself a PS control point; identity-based and
resource-managed decisions are not Person-Server-gated. Its Mission
Substrate Statement declares the kernel mapping and per-mode
capability claims, including the capabilities it does not supply.

[Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-aauth.html)

#### Mission-Bound Authorization for UMA 2.0

Experimental sketch: the fourth binding, and the first authored
against the Mission Substrate Requirements contract rather than
extracted into it. UMA 2.0 standardized the plumbing of asynchronous,
party-asymmetric authorization (the rotating permission ticket,
`request_submitted`, claims pushing, per-use introspection, and a
continuity token that grants nothing) and deliberately left the
authorization assessment unspecified; this binding fills that
interior with the Mission. The pushed Mission Intent rides claims
pushing at the token endpoint, the resource owner's decision is the
approval event, the lifecycle gates every RPT issuance and upgrade,
the RPT is the Mission-bound credential (token-carried or
introspection-carried via the core's registered `mission` member),
and the PCT is Mission continuity that is never authority. It claims
the contextual-governance kernel plus lifecycle-gated, state-observable,
structured-authority, monotonic-derivation, and credential-bound
capabilities on ratified substrate machinery; independent verification
and portable evidence depend on the selected carriage and companion
profiles. The trades are UMA's thin deployed base and its scope-coarse
authority grain, which leaves runtime enforcement's role unchanged.

[Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-uma.html)

#### Mission Substrate Requirements

For authors of new bindings. Defines a small, normative
contextual-governance kernel: a native Mission reference, identified
Controller, authenticated Actor binding, immutable Approved Context or
verifiable commitment, approval event, active/non-active gate with
bounded reliance, context propagation, and ordered governance record. Stronger properties are
declared separately as lifecycle-gated, state-observable,
structured-authority, monotonic-derivation, credential-bound,
independently-verifiable, and portable-evidence capabilities. Each
binding publishes a Mission Substrate Statement identifying the scope
and limitations of every claim; the kernel does not require OAuth
identifiers, RAR, JWT claims, a universal Authority Set, or common
integrity anchors. The kernel is adoptable outside the family; the
family vocabulary bridge, scoped precedence, and change-ownership
rule live in an appendix.

[Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-substrate.html)

#### Mission Consumption Metering

Experimental. Defines the cumulative consumption bounds a Mission
Intent may carry (`max_budget`, `max_calls`, `max_duration`,
`max_egress_volume`), the `exclusive` control that latches
conflicting action classes apart under a single approval, the
runtime metering that enforces them (atomic check-and-decrement,
reserve/commit postures, duration leases, settlement), and the AuthZEN
wire binding for lease renewal and settlement. Without it, Missions
carry no cumulative bounds; the runtime profile's fail-closed rule
covers any bound a deployment cannot meter.

[Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-metering.html)

### Agent runtime

#### Mission-Aware Agent Harnesses

How an agent harness binds sessions, task graphs, queues, cached tool
connections, and sub-agent handles to Mission state, when it must
re-check status, and how it must pause, suppress, or terminate work when
the Mission is no longer active. It also establishes the mediated
execution environment the runtime profile relies on: for mediated action
classes, governed work runs with no unmediated path to the resource. The
core principle: session continuity is not authority.

[Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-harness.html)

#### Mission Capability Binding

Binds a Mission's approved catalog-sourced entry, an MCP tool, an
OpenAPI operation, or an equivalent capability source, to the
capability source it was derived from: `tool_id`, source, and a
content digest recorded at derivation and verified at decision time.
Defines the per-capability extraction rule that computes the digest,
the `capability_drift` denial reason as a coordinated extension of
the AuthZEN binding's runtime denial classification, and the mapping
onto the OpenID AuthZEN Profile for Model Context Protocol Tool
Authorization (COAZ) for MCP deployments. It rides the AuthZEN
binding's request and consumes an already established action
identity.

[Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-capability-binding.html)

#### Mission Orchestration and Unwinding

How a multi-step or multi-Mission workflow assigns a reversibility class
to each step, records an unwind plan before dispatch, and unwinds
in-flight work safely when a Mission stops, including compensation after
termination. It governs how workflow state is unwound once continuation
is stopped.

[Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-orchestration.html)

### Sub-agents

#### Mission Child Delegation for OAuth 2.0

Lets a parent Mission authorize a Child Mission for a sub-agent, with
explicit parent lineage, strict-subset authority, expiry no later than
the parent, fan-out controls, and cascade revocation when the parent
reaches a terminal state (suspension pauses, not terminates). A child
is never created by session ancestry alone.

[Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-child-delegation.html)

#### Mission Offline Attenuation for OAuth 2.0

Removes the Authorization Server from the sub-agent fan-out hot path.
Profiles Attenuating Agent Tokens so a Mission-bound token holder mints a
narrower child token offline, carrying the same `mission` claim; the
narrowing is verifiable from the carried token chain. The kill switch is
preserved because consumption is gated by the runtime layer re-checking
Mission state, so a revoked Mission stops the whole chain. A capability
for deployments running the runtime enforcement profile, offered
alongside Authorization-Server-mediated delegation.

[Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-attenuation.html)

### Cross-domain projection

#### Mission Cross-Domain Projection for OAuth 2.0

Lets a single Mission be honored by Authorization Servers in other
trust domains: the originating Mission Issuer projects audience-scoped
authority through a short-lived, sender-constrained cross-domain grant
(ID-JAG recommended), and the Resource AS mints its own local
Mission-bound tokens from it, preserving the `mission` claim unchanged.
One hop; the single-domain core is complete without it. Extracted from
the core so the mandatory profile carries no cross-domain dependencies.

[Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-cross-domain.html)

#### Mission Continuation: Authorization Continuity for Mission-Bound Authorization

Profiles authorization continuity: how a Mission's work continues across
hops and over time without re-presenting the original credential and
without widening authority. The Identity Continuation Assertion, async
delegation, and cross-domain projection are the transports; the Mission
binds all of them under one invariant, a continuation handle grants
nothing. Identity continuity re-establishes who is acting; the Mission
remains the record of what work stays authorized.

[Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-continuation.html)

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

[Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-mandate.html)

#### Mission Audit Transparency

Makes the suite's evidence tamper-evident and independently verifiable.
Registers Mission evidence (the approval event, lifecycle transitions,
runtime and consent evidence) into a SCITT Transparency Service as
Signed Statements, with the Mission as the statement subject so a
Mission's records form one append-only feed, and binds the Receipt back
so any party, in any domain, can verify inclusion offline. Statements
commit to evidence by hash, so sensitive task data stays out of the log.
Layers onto any level.

[Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-audit.html)

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

[Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-security-model.html)

#### Mission Work Products

Experimental. Keeps information from carrying authority: an artifact can
cross a boundary with knowledge, but not with the producing Mission's
authority. Defines a policy-free work-product provenance object that
attributes an artifact to the approved work under which it came into
existence, and a non-transitive Mission-to-Mission handoff rule: an
artifact crossing into a receiving Mission is input, and the receiving
Mission re-evaluates any proposed action under its own Authority Set.
One invariant holds throughout: no authority is acquired by information
propagation alone. Provenance records where an artifact came from; it
never says what the reader may do.

[Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-work-products.html)

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

On macOS, building also requires GNU sed on `PATH` (`brew install
gnu-sed`, then prepend `/opt/homebrew/opt/gnu-sed/libexec/gnubin`):
the template's draft-name substitution exceeds BSD sed's per-expression
buffer once a repository carries this many drafts, failing with
`sed: unterminated substitute pattern`. CI uses GNU sed and is
unaffected.

### Family manifest

`family-manifest.json` at the repository root is the machine-readable
inventory of the suite: one entry per `draft-*.md`, with its title,
category, maturity, architectural group (matching "The documents"
below), adoption-order rung, and the other family drafts it
references. It is the single source of truth that README's document
catalog, the Adoption order list, and the architecture's Mission
Document Map are all expected to stay consistent with.

```sh
$ node scripts/check-family-manifest.mjs
```

The check is dependency-free (Node 22+, no `npm install` needed) and
runs in CI on every pull request and push
(`.github/workflows/family-manifest.yml`). It fails on inventory drift
(a draft on disk with no manifest entry, or vice versa), a
front-matter `category` that disagrees with the manifest, a draft not
linked under "The documents" below, a draft missing from the
architecture's Mission Document Map, or a draft with a real
`adoption_rung` missing from the Adoption order list above.
