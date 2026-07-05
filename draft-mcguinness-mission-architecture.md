---
title: "An Architecture for Mission-Bound Authorization"
abbrev: "Mission Architecture"
category: info

docname: draft-mcguinness-mission-architecture-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
keyword:
 - mission
 - agent
 - authorization
 - architecture
venue:
  github: "mcguinness/draft-mcguinness-oauth-mission"
  latest: "https://mcguinness.github.io/draft-mcguinness-oauth-mission/draft-mcguinness-mission-architecture.html"

author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com

informative:
  RFC6749:
  RFC9126:
  RFC9396:
  RFC9943:
  I-D.draft-mcguinness-oauth-mission-cross-domain:
    title: "Mission Cross-Domain Projection for OAuth 2.0"
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-oauth-mission-cross-domain-latest
  I-D.draft-mcguinness-oauth-mission:
    title: "Mission-Bound Authorization for OAuth 2.0"
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-oauth-mission-latest
  I-D.draft-mcguinness-mission-authority-server:
    title: "Mission Authority Server"
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-mission-authority-server-latest
  I-D.draft-mcguinness-mission-aauth:
    title: "Mission-Bound Authorization for AAuth"
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-mission-aauth-latest
  I-D.draft-mcguinness-mission-substrate:
    title: "Mission Substrate Requirements"
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-mission-substrate-latest
  I-D.draft-mcguinness-oauth-mission-management:
    title: "Mission Management for OAuth 2.0"
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-oauth-mission-management-latest
  I-D.draft-mcguinness-mission-shaping:
    title: "Mission Intent Shaping"
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-mission-shaping-latest
  I-D.draft-mcguinness-oauth-mission-consent-evidence:
    title: "Mission Consent Evidence for OAuth 2.0"
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-oauth-mission-consent-evidence-latest
  I-D.draft-mcguinness-oauth-mission-approval:
    title: "Mission Deferred Approval for OAuth 2.0"
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-oauth-mission-approval-latest
  I-D.draft-mcguinness-oauth-mission-status:
    title: "Mission Status and Lifecycle for OAuth 2.0"
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-oauth-mission-status-latest
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
  I-D.draft-mcguinness-oauth-mission-completion:
    title: "Mission Completion for OAuth 2.0"
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-oauth-mission-completion-latest
  I-D.draft-mcguinness-mission-runtime:
    title: "Mission-Bound Runtime Enforcement"
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-mission-runtime-latest
  I-D.draft-mcguinness-mission-authzen:
    title: "Mission-Bound Runtime Enforcement: AuthZEN Profile"
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-mission-authzen-latest
  I-D.draft-mcguinness-mission-harness:
    title: "Mission-Aware Agent Harnesses"
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-mission-harness-latest
  I-D.draft-mcguinness-mission-orchestration:
    title: "Mission Orchestration and Unwinding"
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-mission-orchestration-latest
  I-D.draft-mcguinness-oauth-mission-child-delegation:
    title: "Mission Child Delegation for OAuth 2.0"
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-oauth-mission-child-delegation-latest
  I-D.draft-mcguinness-oauth-mission-attenuation:
    title: "Mission Offline Attenuation for OAuth 2.0"
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-oauth-mission-attenuation-latest
  I-D.draft-mcguinness-mission-mandate:
    title: "Mission Mandate"
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-mission-mandate-latest
  I-D.draft-mcguinness-mission-audit:
    title: "Mission Audit Transparency"
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-mission-audit-latest
  I-D.draft-mcguinness-mission-security-model:
    title: "Mission Security Model"
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-mission-security-model-latest

--- abstract

A Mission is a durable, approval-backed governance object for
authorization: the approved task, with a lifecycle, that authority is
derived for, bound to, and gated on. It is not a new way to express
authority. The Mission model spans a core issuance profile, two further
bindings, and optional companion profiles, and no single
document shows how the pieces fit. This document is that structural
view: the roles and components, the substrate primitives the
companions consume, the layers the profiles form, the deployment
patterns, and the requirements the family answers. It is
Informational: it defines no protocol, object, or requirement, and
every mechanism it names is defined by the profile it points to.

--- middle

# Introduction

A Mission is a durable governance object created by an explicit
approval event: the approved task, with a lifecycle. Authority for
the task is derived for the Mission, bound to it, and gated on its
state. The Mission is not a new way to express authority: Rich
Authorization Requests {{RFC9396}} and kindred mechanisms express
authority, and the Mission is the approved task that authority
serves.

The model is deliberately decomposed: a core profile (the "issuance
profile", {{I-D.draft-mcguinness-oauth-mission}}, here "the core")
defines the object and its OAuth 2.0 {{RFC6749}} binding, a
standalone binding hosts the same object without changing an existing
Authorization Server
({{I-D.draft-mcguinness-mission-authority-server}}), an AAuth binding
gives that protocol's native mission concept the model's structure and
lifecycle ({{I-D.draft-mcguinness-mission-aauth}}), and optional
companions layer approval, lifecycle, enforcement, runtime,
delegation, and proof capabilities on top. The decomposition keeps
each interface small but spreads the structure across many documents
and three bindings; this document is the single structural view.

It defines no protocol, no object, and no requirement. It is a map,
not the territory: every mechanism named points at the profile that
normatively defines it, and where this document and a profile appear
to differ, the profile governs.

# Status: An Informational Architecture {#status}

This document is Informational. It establishes no conformance class
and defines no new mechanism, claim, or wire format. Where it uses
words like "must" or "should," they carry their ordinary English
meaning and describe what a referenced profile establishes, not a
requirement this document places. Terms are the core's; Policy
Enforcement Point (PEP), Policy Decision Point (PDP), and
consequential action are the runtime profile's
({{I-D.draft-mcguinness-mission-runtime}}); Mission Authority Server
(MAS) is defined by
{{I-D.draft-mcguinness-mission-authority-server}}; the AAuth binding
is defined by {{I-D.draft-mcguinness-mission-aauth}}.

Its boundary with the Mission Security Model
({{I-D.draft-mcguinness-mission-security-model}}) is deliberate: this
document describes components, interfaces, and data flows; the
security model describes the trusted base and how each component's
compromise degrades the guarantees. Each profile's own Security
Considerations remain normative over both.

# The Mission {#the-mission}

OAuth 2.0 issues access tokens for individual resource requests; it
has no durable, approved artifact for the larger task a client
pursues on a user's behalf. That matters for AI agents: given a
mission (book the trip, reconcile the ledger), an agent takes many
actions across many resources over a long time, spawning sub-agents
and surviving restarts, and independently issued tokens cannot
express the approved task, its boundary, or its end (the core's
Introduction).

The family separates the task from the authority. The Mission is the
approved task, with a lifecycle; the Authority Set is the concrete
authority (resources, actions, constraints) derived for it. A Mission
is not another `authorization_details` type: it is the durable,
approval-backed object an Authority Set is derived for and gated by
(the core's Why a New Object section).

A client proposes a Mission Intent; the Mission Issuer derives an
Authority Set for it; an approval event commits both and creates the
Mission. The commitment is two integrity anchors, `intent_hash` over
the approved Mission Intent and `authority_hash` over the consented
Authority Set, each computed over a domain-separated, issuer-bound
envelope with fixed canonicalization, so an auditor can reproduce
either digest from the record alone (the core's Mission Approval,
Integrity Anchors, and Canonicalization Rules sections). The record
is immutable except for its state (the Mission Record section).

The core lifecycle states are `active`, `revoked`, and `expired`, and
only `active` permits issuance or continued reliance. Companions add
states (`suspended`, `completed`, `superseded`, `cascaded`), and one
rule keeps
that safe without a registry: a consumer treats every state other
than the exact value `active`, including one it does not recognize,
as non-active, so an unrecognized state fails safe (the core's
Mission Lifecycle and Gating section).

# Mission Roles and Components {#components}

For each component: what it does, what it holds, and which document
specifies it. What its compromise costs is the security model's
subject ({{I-D.draft-mcguinness-mission-security-model}}).

Agent (client):
: Proposes the Mission Intent and executes the task; in the OAuth
  binding it holds derived Mission-bound tokens; outside the trusted
  base and assumed compromisable
  ({{I-D.draft-mcguinness-oauth-mission}}).

Subject:
: The user or system on whose behalf the Mission is approved, an
  (`iss`, `sub`) pair recorded immutably at approval (the core).

Approver:
: The single accountable principal who approves the Mission; equal
  to the Subject for self-approval (the core's Single Accountable
  Approver section).

Mission Issuer:
: Validates the Mission Intent, runs the approval event, records the
  Mission, and owns its state. Three bindings. OAuth Authorization
  Server: every derived token carries the `mission` claim, and
  issuance and refresh are gated on Mission state
  ({{I-D.draft-mcguinness-oauth-mission}}). Mission Authority Server:
  the same record, anchors, and lifecycle without issuing tokens; the
  PDP joins ordinary credentials to the Mission at the point of use
  ({{I-D.draft-mcguinness-mission-authority-server}}). AAuth Person
  Server: the mission blob carries the record under AAuth's `s256`
  commitment, and the Person Server issues or gates every auth token,
  so issuance gating holds ({{I-D.draft-mcguinness-mission-aauth}}).

Resource Server:
: The protected resource. In the OAuth binding it enforces
  statelessly from the token and can check the `mission` claim (the
  core's Resource Server Enforcement section); in the standalone
  binding the token carries no Mission signal, and Mission properties
  reach it only through the enforcement path.

PEP and PDP:
: The PEP sits at the last controllable boundary before an action and
  obtains a permit for each consequential action; under mediated
  custody it, not the agent, holds the sender-constraint key. The PDP
  evaluates the action against the Mission's authority, constraints,
  actor chain, and current state, and fails closed
  ({{I-D.draft-mcguinness-mission-runtime}},
  {{I-D.draft-mcguinness-mission-authzen}}); in the standalone
  binding it also verifies the subject and client join (the MAS's
  Mission Join section).

Agent harness:
: Hosts the agent; binds sessions, task graphs, queues, cached tool
  connections, and sub-agent handles to Mission state; establishes
  the environment with no unmediated path to mediated actions
  ({{I-D.draft-mcguinness-mission-harness}}).

Orchestrator:
: Assigns each workflow step a reversibility class, records an unwind
  plan before dispatch, and compensates in-flight work when a Mission
  stops ({{I-D.draft-mcguinness-mission-orchestration}}).

Transparency Service:
: An append-only SCITT log {{RFC9943}} that registers Mission
  evidence as Signed Statements and issues receipts verifiable
  offline ({{I-D.draft-mcguinness-mission-audit}}).

Verifiers:
: Parties outside the deployment that check Mission facts without a
  token exchange: Mandate verifiers confirm what was approved
  ({{I-D.draft-mcguinness-mission-mandate}}); evidence consumers
  check consent, decision, and execution evidence against the anchors
  and receipts
  ({{I-D.draft-mcguinness-oauth-mission-consent-evidence}},
  {{I-D.draft-mcguinness-mission-authzen}}).

The bindings converge on one object, and enforcement draws on it
regardless of binding:

~~~
      Subject        Approver
          \             |
           \      approval event
            \           |
  +----------------------------------------+
  |             Mission Issuer             |
  | +----------------+ +-----------------+ |
  | | OAuth AS:      | | Standalone MAS: | |
  | | Mission-bound  | | no tokens; the  | |
  | | tokens gated   | | PDP joins       | |
  | | on state       | | credentials     | |
  | +-------+--------+ +--------+--------+ |
  +---------|-------------------|----------+
            v                   v
       the Mission: intent_hash,
    authority_hash, lifecycle state
                  |
                  | state and authority (claim,
                  | introspection, Status, Signals)
                  v
  Agent ------> PEP ----------> PDP
  (harness,      |  <- permit -
  orchestrator)  v
          Resource Server
~~~

# The Mission Substrate {#substrate}

The companion profiles named without "oauth" are defined against the
Mission model's substrate primitives rather than against OAuth
mechanics; each names what it consumes in a Mission Substrate section
of its own. This section consolidates that interface: six primitives,
each with its normative home and its consumers. Every sentence
mirrors a rule the named profile states normatively.

## The Mission Identifier and Origin

An opaque, non-reused `mission_id` with at least 128 bits of entropy
and no semantic content, plus `origin`, the issuer URL of the
approving Mission Issuer; together they name exactly one Mission.
Home: the core's Mission Record and Mission Identifier Format
sections. Consumed by every companion: enforcement decisions,
evidence, harness bindings, the state surfaces, the audit statement
subject, and the Mandate all key on it.

## The Lifecycle State Space

The states of {{the-mission}}, open to companion-defined states, with
the only-`active` rule, fail-safe unrecognized states, and a
freshness source with a stated staleness bound. Home: the state space
and the only-`active` rule are the core's (its Mission Lifecycle and
Gating section); the freshness mechanisms and staleness bounds are
the status and runtime profiles'; Status and Signals add the
observation surfaces. Consumed by the runtime layer (per-class
re-check, fail closed on staleness), the harness (pause, suppress,
terminate), the orchestrator (the unwind trigger), and the Mandate
(state only as of minting).

## The Authority Set Representation

An array of authorization details entries ({{RFC9396}} in the OAuth
binding), each naming a resource, actions, and constraints, governed
by the subset rule (derived or delegated authority is never broader)
and the Common Constraints vocabulary (registered names with fixed
subset and intersection rules). Home: the core's Mission Authority
section, with its Subset Rule and Common Constraints subsections.
Consumed by the runtime layer and AuthZEN binding (evaluation), the
MAS (served to the PDP), Expansion and Completion (growth and
retirement), Child Delegation and Offline Attenuation (narrowing),
Consent Evidence (rendering), and the Mandate (optional carriage).

## The Integrity-Anchor Envelope

A committed object is hashed over an envelope domain-separated by
`typ` and issuer-bound by `iss`, canonicalized by fixed rules, and
encoded with an algorithm prefix a verifier recognizes or rejects;
the `typ` space is an extension point for new committed objects.
Home: the core's Integrity Anchors and Canonicalization Rules
sections, with the extension rule in its Extensibility section.
Consumed by Consent Evidence (`consent_rendering_hash`), Shaping
(Shaping Evidence), the runtime layer and AuthZEN binding
(`mission-policy-view`), Orchestration (`unwind_plan_hash`), the
Mandate (the encoded digest form), and Audit Transparency (the
committed evidence types it registers).

## The Mission-Bound Credential

A credential carrying the `mission` claim (`id`, `origin`,
`authority_hash`) and Mission-derived authorization details, issued
only while the Mission is `active`. Home: the core's Mission-Bound
Access Tokens and The Mission Claim sections.

This is the binding-dependent primitive, and it is exactly where the
bindings split. The OAuth and AAuth bindings provide it (the AAuth
auth token carries the `mission` claim under per-request signature
coverage, {{I-D.draft-mcguinness-mission-aauth}}); the standalone
binding does not: the MAS's Mission Substrate section states that a
MAS provides every other primitive unchanged and provides neither
this credential nor issuance gating
({{I-D.draft-mcguinness-mission-authority-server}}). The seam is the
runtime profile's Mission binding establishment step
({{I-D.draft-mcguinness-mission-runtime}}): the credential carries
the Mission reference where the binding provides one, and a binding
without it supplies an externally established reference, verified
under a join the binding defines, which the MAS profiles as its
Mission Join. Offline Attenuation attenuates this credential and the
token-carriage aspects of delegation ride it, so both require it;
every other companion routes through the binding establishment step,
which is what makes the standalone binding possible.

## The Audit Horizon

The deployment-declared retention window for the Mission record and
its evidence: at least the Mission's lifetime plus a declared
post-terminal period. Home: the core's Mission Record section.
Consumed by Consent Evidence, runtime evidence, and Audit
Transparency for retention; by the MAS for record retention; and by
the security model's retention analysis.

## The Binding Checklist {#binding-checklist}

For a new binding this checklist is now normatively stated by Mission
Substrate Requirements ({{I-D.draft-mcguinness-mission-substrate}});
this section remains the informative summary, and the three existing
bindings remain authoritative for themselves.

Another mission-based protocol hosts the substrate-neutral profiles
unchanged when it provides:

1. a unique, opaque Mission identifier with an authoritative origin;
2. the lifecycle state space with the only-`active` rule, fail-safe
   unrecognized states, and a freshness source with a staleness bound;
3. an Authority Set representation with a subset rule and a shared
   constraint vocabulary;
4. the integrity-anchor envelope and canonicalization for every
   object it commits;
5. an audit horizon over the record and its evidence;
6. published key material: the issuer's signing keys, resolvable by
   the verifiers of its signed artifacts; and
7. optionally, a Mission-bound credential carrying the `mission`
   claim; a substrate that omits it composes as the standalone
   binding does, and the credential-carriage profiles do not apply.

Individual profiles name further inputs in their Mission Substrate
sections: the evidence types and their canonical bytes for audit
transparency, and the intent submission channel for shaping. The
per-profile Mission Substrate sections remain the authoritative
per-consumer statements of this interface; this section consolidates
them and adds nothing.

# Mission Layers {#layers}

The family organizes along a verb spine: each layer answers one
question, sits on one trust boundary, and is owned by named documents.

~~~
 propose      Intent Shaping (client side, untrusted)
                        |
 approve      Mission Issuer: the OAuth AS, Mission
 and record   Authority Server, or AAuth Person Server
              binding (+ Consent Evidence, Deferred
              Approval)
                        |
              the Mission: intent_hash,
              authority_hash, lifecycle state
                        |
 govern       Status (pull), Signals (push),
              Expansion (widen), Completion (retire)
                        |
 enforce      Runtime contract -> AuthZEN binding:
 each action  a PDP permit before every consequential action
                        |
 run and      Harness (continuity is not authority),
 wind down    Orchestration (unwind in-flight work)

 delegate     Child Delegation, Offline Attenuation

 prove        Consent Evidence, Mandate, Audit

 analyze      Security Model (the trusted base)
~~~

## Propose

The question: how does a user's request become a candidate Mission
Intent? The boundary: the client side; output is untrusted until the
Mission Issuer validates and narrows it. Owner: Intent Shaping
({{I-D.draft-mcguinness-mission-shaping}}); the proposal enters via
Pushed Authorization Requests {{RFC9126}} or the MAS submission
endpoint.

## Approve and Record

The question: how does a proposed task become an approved, committed
Mission? The boundary: the Mission Issuer's own; the approval event
is where trust is created. Owners: the three bindings
({{I-D.draft-mcguinness-oauth-mission}},
{{I-D.draft-mcguinness-mission-authority-server}},
{{I-D.draft-mcguinness-mission-aauth}}), Consent Evidence
({{I-D.draft-mcguinness-oauth-mission-consent-evidence}}) committing
the disclosure shown to the Approver, and Deferred Approval
({{I-D.draft-mcguinness-oauth-mission-approval}}), the OAuth
binding's asynchronous path, with an experimental companion adding an
in-review narrowing negotiation; the
standalone and AAuth bindings are natively asynchronous. Where the experimental
progressive authorization companion is used, the initial approval also
consents an authority ceiling for later staged widening
({{I-D.draft-mcguinness-oauth-mission-expansion}}).

## Govern

The question: how do consumers observe Mission state, and how does
authority grow or retire mid-task? The boundary: between the issuer
and every consumer relying on state. Owners: Status, the signed pull
surface with a lifecycle endpoint
({{I-D.draft-mcguinness-oauth-mission-status}}); Signals, the push
complement ({{I-D.draft-mcguinness-oauth-mission-signals}});
Expansion, widening only via an approved successor
({{I-D.draft-mcguinness-oauth-mission-expansion}}); Completion,
per-entry discharge
({{I-D.draft-mcguinness-oauth-mission-completion}}); and Management,
fleet enumeration and bulk lifecycle for operators
({{I-D.draft-mcguinness-oauth-mission-management}}).

## Enforce Each Action

The question: is this specific action, with these parameters,
permitted under this Mission now? The boundary: the last controllable
point between agent and resource. Owners: the runtime profile, the
decision contract with parameter binding, custody, and fail-closed
behavior ({{I-D.draft-mcguinness-mission-runtime}}); its AuthZEN
binding, the concrete decision API and evidence objects
({{I-D.draft-mcguinness-mission-authzen}}).

## Run and Wind Down

The question: how does governed work start, persist, pause, and
unwind when Mission state changes? The boundary: the operator's
execution environment around the agent. Owners: the harness, binding
session continuity to Mission state
({{I-D.draft-mcguinness-mission-harness}}); Orchestration, unwinding
in-flight work through reversibility classes and recorded unwind
plans ({{I-D.draft-mcguinness-mission-orchestration}}).

## Delegate

The question: how does authority reach a sub-agent without widening?
The boundary: between principals acting under one approval. Owners:
Child Delegation, child Missions with lineage, strict-subset
authority, and cascade revocation
({{I-D.draft-mcguinness-oauth-mission-child-delegation}}); Offline
Attenuation, narrower Mission-bound tokens minted off the issuer's
hot path ({{I-D.draft-mcguinness-oauth-mission-attenuation}}).
Offline attenuation requires the runtime enforcement layer: its kill
switch is the runtime state re-check. Both
build on the actor chain of the core's Delegation Within a Mission
section.

## Prove

The question: what can a party outside the deployment verify about
what was approved and done? The boundary: across trust domains and
time; the verifier holds no session with the issuer. Owners: Consent
Evidence ({{I-D.draft-mcguinness-oauth-mission-consent-evidence}});
the Mandate, a signed, portable statement that authorizes nothing
({{I-D.draft-mcguinness-mission-mandate}}); Audit Transparency, the
append-only evidence log ({{I-D.draft-mcguinness-mission-audit}}).

## Analyze

The question: which components must be trusted, and what does each
one's compromise cost? The boundary: the whole system. Owner: the
Mission Security Model
({{I-D.draft-mcguinness-mission-security-model}}).

# Mission Deployment Patterns {#deployment}

The OAuth binding stacks two independent chokepoints. Issuance gating
acts at the token layer: a revoked or expired Mission stops all
further derivation and refresh, and short-lived tokens age out.
Runtime enforcement acts at the action layer: each consequential
action is re-checked against current state at the point of use.
Issuance gating plus runtime enforcement is strictly stronger than
either alone: a gap in PEP coverage is still bounded at the token
layer, and an outstanding token is still stopped at the action layer.

The standalone mode trades the token-layer kill switch for zero
Authorization Server changes. A MAS creates, approves, and serves
Missions while tokens remain ordinary; the PDP joins credentials to
Missions, and the MAS is the freshness source. The cost is
structural: no `mission` claim travels, revoking a Mission stops
nothing at the token layer, and enforcement rests entirely on PEP
coverage, so a token exercised outside that coverage is ungoverned
(the MAS's Limitations section). The upgrade path is the issuance
profile; the record, anchors, and lifecycle carry over unchanged.

In sequence, the standalone mode runs submit, poll, approve, join,
permit:

~~~
 Client               MAS                Approver     PEP/PDP
   |                    |                  |            |
   | 1 submit Intent    |                  |            |
   |------------------->|                  |            |
   | 2 202 pending      |                  |            |
   |<-------------------|                  |            |
   |                    | 3 disclose       |            |
   |                    |----------------->|            |
   |                    | 4 approve        |            |
   |                    |<-----------------|            |
   |                    | Mission active   |            |
   | 5 poll             |                  |            |
   |------------------->|                  |            |
   | 6 approved,        |                  |            |
   |   mission_id       |                  |            |
   |<-------------------|                  |            |
   | 7 action, token,   |                  |            |
   |   Mission ref      |                  |            |
   |--------------------------------------------------->|
   |                    | 8 signed status: |            |
   |                    |   active         |            |
   |                    |<------------------------------|
   |                    |------------------------------>|
   |                    |                  | 9 join;    |
   |                    |                  |   evaluate |
   | 10 permit          |                  |            |
   |<---------------------------------------------------|
~~~

The token in step 7 is an ordinary OAuth token from the unchanged AS;
steps 8 through 10 are the Mission Join and the runtime decision (the
MAS's Mission Join section), and the MAS's staged walkthrough of the
same flow is its end-to-end appendix
({{I-D.draft-mcguinness-mission-authority-server}}).

The bundles progress cumulatively. Baseline issuance is the core
alone: approved, integrity-bound Missions, state-gated issuance, a
possession-independent kill switch; audit, not action-time defense.
The enforced bundle adds the runtime profile, its AuthZEN binding,
and a freshness source: per-action permits and prompt revocation, the
minimum for an agent taking consequential actions. The governed
bundle, recommended for AI agents, adds Consent Evidence and the
harness, growing with Child Delegation, Expansion, and Orchestration
as needed; resistance to a compromised agent comes not from the
bundle but from meeting all four conditions of the runtime profile's
agent-compromise-resistant enforcement. Standalone governance is the
same progression entered through the MAS, with the runtime layer
mandatory from the start. Throughout, every companion is optional;
each profile states its own scoped conformance, and the bundles are
guidance, not a conformance class.

# Mission Requirements {#requirements}

The requirements the family answers, stated implementation-neutrally;
each names its answering documents by short form ({{document-map}}).
They stand on their own: a reader evaluating another design can use
them as a checklist.

## Context and Intent {#req-context}

- **R1**: The task an agent pursues is a durable, structured,
  approved object (oauth-mission; mission-authority-server).
- **R2**: The task and its derived authority are integrity-committed
  at approval, reproducible from the record alone (oauth-mission).
- **R3**: Task proposals are untrusted input: fields the agent can
  influence never derive, widen, or gate authority (oauth-mission;
  mission-shaping).

## Consent and Approval {#req-consent}

- **R4**: The derived authority is disclosed to the Approver before
  it takes effect, and the approval covers it (oauth-mission).
- **R5**: A single accountable Approver is recorded immutably on the
  object (oauth-mission).
- **R6**: What was shown at approval is committed and reconstructible
  by an auditor (oauth-mission-consent-evidence).
- **R7**: Approval can be asynchronous, and any in-review negotiation
  only narrows (oauth-mission-approval; the experimental
  oauth-mission-approval-revision).

## Lifecycle {#req-lifecycle}

- **R8**: Reliance is gated on task state: only `active` permits it,
  and unrecognized states fail safe (oauth-mission).
- **R9**: Revocation is independent of credential possession, and
  state changes propagate by pull or push (oauth-mission;
  oauth-mission-status; oauth-mission-signals).
- **R10**: A task can be suspended and resumed without being
  terminated (oauth-mission-status).
- **R11**: Authority widens only through a fresh approval that
  creates a successor (oauth-mission-expansion).
- **R12**: Authority retires per entry when the work an entry served
  is done (oauth-mission-completion).

## Delegated and Enforced Execution {#req-execution}

- **R13**: Derived and delegated authority only narrows
  (oauth-mission; oauth-mission-attenuation).
- **R14**: Sub-agents receive authority by explicit delegation with
  lineage, fan-out control, and cascade revocation, never by session
  ancestry (oauth-mission-child-delegation).
- **R15**: Each consequential action is checked at the point of use,
  the permit bound to the concrete parameters (mission-runtime;
  mission-authzen).
- **R16**: When a task stops, governed work stops with it and
  in-flight work unwinds safely (mission-harness;
  mission-orchestration).
- **R17**: Task evidence is tamper-evident and verifiable outside the
  deployment (mission-audit; mission-mandate).

# Mission Document Map {#document-map}

One line per document, grouped as the family groups them; the short
form drops the `draft-mcguinness-` prefix. The naming encodes a
boundary: profiles extending the Authorization Server's own surfaces
keep "oauth" in their names; profiles defined against the substrate
of {{substrate}} are named without it. This document is named without
it because the architecture is substrate-neutral by construction.

| Group | Document | Defines |
|---|---|---|
| The model and its bindings | `oauth-mission` | The core issuance profile: the Mission, the approval event and anchors, the `mission` claim, the subset rule, state-gated issuance. |
| | `mission-authority-server` | The standalone Mission Issuer and the PDP join of ordinary credentials to Missions. |
| | `mission-aauth` | The AAuth binding: the Person Server as Mission Issuer, the mission blob as the record under AAuth's `s256` commitment, issuance gating at the token endpoint. |
| | `mission-substrate` | Normative requirements on any further binding of the model; the existing bindings and the core are unchanged by it. |
| Approval time | `mission-shaping` | Client-side shaping of a user's request into a candidate Mission Intent, as untrusted proposal. |
| | `oauth-mission-consent-evidence` | The `consent_rendering_hash` anchor and signed evidence of what the Approver was shown. |
| | `oauth-mission-approval` | Asynchronous approval over the deferred substrate. |
| | `oauth-mission-approval-revision` | Experimental: in-review narrowing revision of a deferred proposal. |
| Lifecycle | `oauth-mission-status` | The signed pull surface and the lifecycle endpoint, with `suspended` and `completed`. |
| | `oauth-mission-signals` | Experimental: a signed event per lifecycle transition, push or poll. |
| | `oauth-mission-expansion` | Widening through an approved successor Mission. |
| | `oauth-mission-progressive` | Experimental: policy-adjudicated expansion within a pre-consented ceiling. |
| | `oauth-mission-management` | Fleet enumeration and bulk lifecycle operations for operators and incident response; dry-run-first, per-Mission semantics. |
| | `oauth-mission-completion` | Per-entry discharge via the `terminal_when` constraint. |
| | `oauth-mission-cross-domain` | Single-hop projection of a Mission to another trust domain via the cross-domain grant ({{I-D.draft-mcguinness-oauth-mission-cross-domain}}). |
| Runtime enforcement | `mission-runtime` | The per-action decision contract: parameter binding, custody, fail-closed behavior. |
| | `mission-authzen` | The concrete decision-API binding and its Decision and Execution Evidence objects. |
| | `mission-metering` | Experimental: cumulative consumption bounds and the metering that enforces them. |
| Agent runtime | `mission-harness` | Binding sessions, queues, and sub-agent handles to Mission state; the mediated environment. |
| | `mission-orchestration` | Reversibility classes, unwind plans, and compensation after a stop. |
| Sub-agents | `oauth-mission-child-delegation` | Child Missions with lineage, strict-subset authority, cascade revocation. |
| | `oauth-mission-attenuation` | Narrower Mission-bound tokens minted offline; the kill switch preserved by runtime re-check. |
| Proof and portability | `mission-mandate` | A signed, portable statement of a Mission's committed facts; evidence, not a credential. |
| | `mission-audit` | Registration of Mission evidence in a SCITT Transparency Service; receipts verifiable offline. |
| Security model | `mission-security-model` | The trusted base in one view: what each component must achieve and what its compromise costs. |

# Security Considerations {#security-considerations}

This document introduces no mechanism and therefore no new security
considerations. The consolidated trusted base and compromise analysis
are the Mission Security Model's
({{I-D.draft-mcguinness-mission-security-model}}), and each profile's
own Security Considerations remain normative.

# IANA Considerations {#iana}

This document makes no IANA request.

--- back

# Acknowledgments
{:numbered="false"}

This document is part of the Mission-Bound Authorization work and
maps the structure that its profiles establish individually.
