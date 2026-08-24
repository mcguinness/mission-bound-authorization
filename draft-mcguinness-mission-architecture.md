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
  github: "mcguinness/mission-bound-authorization"
  latest: "https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-architecture.html"

author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com

informative:
  A2A:
    title: "Agent2Agent (A2A) Protocol Specification, Version 1.0"
    target: https://a2a-protocol.org/v1.0.0/specification/
    author:
      - org: A2A Project
    date: 2026
  I-D.draft-zehavi-oauth-rar-metadata:
  I-D.draft-mcguinness-mission-metering:
    title: "Mission Consumption Metering"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-metering.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  RFC6749:
  RFC9126:
  RFC9396:
  RFC9943:
  RFC8693:
  I-D.draft-mcguinness-oauth-client-instance-assertion:
  I-D.draft-mcguinness-oauth-ai-agent-instance:
  I-D.draft-ietf-oauth-attestation-based-client-auth:
  I-D.draft-ietf-oauth-spiffe-client-auth:
  I-D.draft-mcguinness-oauth-mission-cross-domain:
    title: "Mission Cross-Domain Projection for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-cross-domain.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-oauth-id-continuation-assertion:
    title: "Identity Continuation Assertion for OAuth 2.0 Token Exchange"
    target: https://datatracker.ietf.org/doc/draft-mcguinness-oauth-id-continuation-assertion/
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-zhu-oauth-async-delegation:
  I-D.draft-mcguinness-oauth-mission-continuation:
    title: "Mission Continuation: Authorization Continuity for Mission-Bound Authorization"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-continuation.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-oauth-mission:
    title: "Mission-Bound Authorization for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-oauth-mission-issuance-grant:
    title: "Mission Issuance Grant for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-issuance-grant.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-mission-discovery:
    title: "Mission Open-World Discovery"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-discovery.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-mission-authority-server:
    title: "Mission Authority Server"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-authority-server.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-mission-uma:
    title: "Mission-Bound Authorization for UMA 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-uma.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-mission-gnap:
    title: "Mission-Bound Authorization for GNAP"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-gnap.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-mission-aauth:
    title: "Mission Context Binding for AAuth"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-aauth.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-mission-aauth-management:
    title: "AAuth Mission Management"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-aauth-management.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-aauth-mission-expiry:
    title: "AAuth Mission Expiry"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-aauth-mission-expiry.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-mission-substrate:
    title: "Mission Substrate Requirements"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-substrate.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-oauth-mission-management:
    title: "Mission Management for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-management.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-mission-shaping:
    title: "Mission Intent Shaping"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-shaping.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-oauth-mission-consent-evidence:
    title: "Mission Consent Evidence for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-consent-evidence.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-oauth-mission-approval:
    title: "Mission Deferred Approval for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-approval.html
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
  I-D.draft-mcguinness-oauth-mission-signals:
    title: "Mission Lifecycle Signals for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-signals.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-oauth-mission-progressive:
    title: "Mission Progressive Authorization for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-progressive.html
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
  I-D.draft-mcguinness-oauth-mission-containment:
    title: "Mission Containment for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-containment.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-mission-runtime:
    title: "Mission-Bound Runtime Enforcement"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-runtime.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-oauth-mission-transaction-authorization:
    title: "Mission Transaction Authorization Profile for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-transaction-authorization.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-mission-authzen:
    title: "Mission-Bound Runtime Enforcement: AuthZEN Profile"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-authzen.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-mission-runtime-evidence:
    title: "Mission Runtime Evidence"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-runtime-evidence.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-mission-capability-binding:
    title: "Mission Capability Binding"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-capability-binding.html
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
  I-D.draft-mcguinness-mission-orchestration:
    title: "Mission Orchestration and Unwinding"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-orchestration.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-oauth-mission-child-delegation:
    title: "Mission Child Delegation for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-child-delegation.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-oauth-mission-work-products:
    title: "Mission Work Products"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-work-products.html
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
  I-D.draft-mcguinness-mission-mandate:
    title: "Mission Mandate"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-mandate.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-mission-audit:
    title: "Mission Audit Transparency"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-audit.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-mission-security-model:
    title: "Mission Security Model"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-security-model.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026

--- abstract

A Mission is a durable, approval-backed governance object for
authorization: the approved task, with a lifecycle, that authority is
derived for, bound to, and gated on. It is not a new way to express
authority. Read as one system, the Mission model defines a
delegated-authority layer: authentication says who is acting, and
entitlement governance says what a principal may hold; this layer
governs the approved task itself. It exists because the authority an
Approver consents to is a capability envelope, not a task script, and
the gap between that envelope and what a run actually does is where
agent risk lives; the family's mechanisms exist to narrow that gap.
This document is the structural view: the object and its
invariants, a Mission's life end to end, the roles and substrate, the
verb spine the profiles form, the deployment patterns, the assurance
levels a deployment claims, and the requirements the family answers.
It is Informational: it defines no protocol, object, or requirement,
and every mechanism it names is defined by the profile it points to.

--- middle

# Introduction

A Mission is a durable governance object created by an explicit
approval event: the approved task, with a lifecycle. In the
authority-bearing bindings, authority for the task is derived for the
Mission, bound to it, and gated on its state. In AAuth, the Mission
Context instead governs resource decisions at the PS without becoming
their authority language. The Mission is not a new way to express authority: Rich
Authorization Requests {{RFC9396}} and kindred mechanisms express
authority, and the Mission is the approved task that authority
serves.

The object fills a gap current practice pays for daily: an estate
that cannot size authority to a task compensates with read-only
scoping, a human executing every write, or permanently fenced
pilots, and the Mission is the representation those controls
substitute for.

The model is deliberately decomposed: the OAuth binding (the
"issuance profile" to its OAuth companions,
{{I-D.draft-mcguinness-oauth-mission}})
defines the object and its OAuth 2.0 {{RFC6749}} realization, a
standalone binding hosts the same object without changing an existing
Authorization Server
({{I-D.draft-mcguinness-mission-authority-server}}), an AAuth binding
maps the shared approval, reference, lifecycle-gate, and log capabilities
onto that protocol's native Mission Context without importing the
OAuth Authority Set ({{I-D.draft-mcguinness-mission-aauth}}), and optional
companions layer approval, lifecycle, enforcement, runtime,
delegation, and proof capabilities on top. The decomposition keeps
each interface small but spreads the structure across many documents
and several bindings; this document is the single structural view.

The bindings are peers of one another. OAuth is the family's
first-authored binding, and OAuth 2.0 is the substrate with the most
deployed infrastructure; that is a deployment fact, not a maturity
ranking, and no production Mission deployment is known today on any
binding. Adopting Missions on OAuth requires the changes the OAuth
binding defines. Peer standing implies neither identical
capabilities nor identical adoption cost: AAuth, natively
contextual, adds no new wire members, and each binding's Mission
Substrate Statement declares what it supplies.

Read as one system, the family defines a **delegated-authority
layer** with OAuth 2.0, the standalone Mission Authority Server, and
(as an experimental sketch) UMA 2.0 as authority-bearing bindings.
AAuth composes at the shared Mission Context layer: approval, stable
reference, lifecycle gating where the PS is on path, and governance
history ({{the-mission}}).

It defines no protocol, no object, and no requirement. It is a map,
not the territory: every mechanism named points at the profile that
normatively defines it, and where this document and a profile appear
to differ, the profile governs.

## Map of This Document {#map}

Part order follows a reader's needs: the model first (the Mission
and its life, {{the-mission}}; what the family does not do,
{{non-goals}}), then the verb spine that organizes every mechanism
({{layers}}), the reference shapes deployments take
({{reference-architecture}}), the semantic ground rules
({{invariants}}), the components and identity model
({{components}}), the binding-neutral substrate summary
({{substrate}}) with the derivation boundary behind it
({{derivation-boundary}}), and the deployment layer: patterns and
entry ramps
({{deployment}}), assurance levels and binding properties
({{assurance-levels}}), the Deployment Profile
({{deployment-profile}}), and the prevention-detection and
containment matrices ({{prevention-detection}}). The requirements
the family answers are {{requirements}}; {{document-map}} locates
every document;
DRAFTS.md in the repository is the full catalog.

# Status: An Informational Architecture {#status}

This document is Informational. It establishes no conformance class
and defines no new mechanism, claim, or wire format.

Its boundary with the Mission Security Model
({{I-D.draft-mcguinness-mission-security-model}}) is deliberate: this
document describes components, interfaces, and data flows; the
security model describes the trusted base and how each component's
compromise degrades the guarantees. Each profile's own Security
Considerations remain normative over both.

<!-- family-status: BEGIN (generated from family-manifest.json; exact-matched by scripts/check-family-manifest.mjs) -->
Maturity: informational. Maintenance: active.
Adopt when: Before adopting anything: the Mission model, invariants, and assurance levels the rest cite.
Requires: nothing beyond its listed references.
<!-- family-status: END -->

# Conventions and Terminology {#conventions}

Where this document uses words like "must" or "should," they carry
their ordinary English meaning and describe what a referenced profile
establishes, not a requirement this document places. Mission-model
terms are used as the OAuth binding defines them
({{I-D.draft-mcguinness-oauth-mission}}), the family's first-authored
realization; the substrate contract
({{I-D.draft-mcguinness-mission-substrate}}) carries the
binding-neutral kernel forms. Policy Enforcement
Point (PEP), Policy Decision Point (PDP), and consequential action
are the runtime profile's ({{I-D.draft-mcguinness-mission-runtime}});
Mission Authority Server (MAS) is defined by
{{I-D.draft-mcguinness-mission-authority-server}}; the AAuth binding
is defined by {{I-D.draft-mcguinness-mission-aauth}}.

# The Mission {#the-mission}

OAuth 2.0 standardizes authorization: an access token represents
authorization granted to the client, for a delegating user or for
the client's own behalf, and can serve many requests, and a
deployment may retain durable grant or consent state behind it. What
OAuth does not standardize is an independently addressable,
lifecycle-bearing approved-task object: an artifact whose semantics
persist across tokens, actors, audiences, and evidence.

That matters for AI agents: given a mission (book the trip,
reconcile the ledger), an agent takes many actions across many
resources over a long time, spawning sub-agents and surviving
restarts, and independently issued tokens cannot express the
approved task, its boundary, or its end (the OAuth binding's Introduction).

The family separates the task from the authority, and the
authorization flow separates four objects: the Intent (proposed work, inert until approved), the
Mission (the approved, governed work), the Authority derived for it,
and each Action that uses it, with lifecycle cutting through the
last three. The Mission is the
approved task, with a lifecycle. In the OAuth model, the Authority Set
is the concrete authority (resources, actions, constraints) derived for
it. A Mission is not another `authorization_details` type: it is the
durable, approval-backed object an Authority Set is derived for and
gated by (the OAuth binding's Why a New Object section).

A client proposes a Mission Intent, and MAY propose concrete
authority alongside it; the Mission Issuer derives an
Authority Set; an approval event commits them and creates the
Mission.

In the OAuth binding, the commitment is the integrity anchors:
`intent_hash` over the
approved Mission Intent, `authority_hash` over the consented
Authority Set, and, where the client submitted an authority proposal,
`proposal_hash` over the submitted `authorization_details` array,
each computed over a domain-separated, issuer-bound
envelope with fixed canonicalization, so an auditor can reproduce
each digest from the record alone (the OAuth binding's Mission Approval,
Integrity Anchors, and Canonicalization Rules sections). The record
is immutable except for its state (the Mission Record section).

The Mission lifecycle states are `active`, `revoked`, and `expired`, and
only `active` permits issuance or a new positive governance
decision. A non-active
state stops new derivation at once; authority already issued ends at
the earliest of delivered revocation, a runtime or state-aware
re-check, or the credential's own expiry ({{validity-model}}).

Companions add states (`suspended`, `completed`, `superseded`,
`cascaded`), and one rule keeps that safe without a registry: a
consumer treats every state other than the exact value `active`,
including one it does not recognize, as non-active, so an
unrecognized state fails safe (the OAuth binding's Mission Lifecycle and
Gating section).

AAuth realizes the separation differently. Its exact-byte `s256`
commits the private approved mission blob, and `{approver, s256}` is
the stable reference. The PS applies contextual governance using that
blob and the ordered mission log; scopes, resource tokens, Resource and
Access Server policy, and optionally R3 carry deterministic resource
authorization. AAuth does not add the OAuth Authority Set or its two
anchors, and its native lifecycle remains exactly `active` or
`terminated`.

The Mission model is the beginning of a distinct layer.
Authentication and token issuance answer who is acting and what a
single credential carries; governance of standing entitlements
answers what a principal should hold over time. Neither governs the
approved task a delegate performs on a principal's behalf: its
bounded authority, its lifecycle, the per-action check, and the
evidence that binds back to it.

That is the delegated-authority layer this family defines, composing
with the layers below rather than replacing them, and the Mission
Authority Server ({{I-D.draft-mcguinness-mission-authority-server}})
is its binding-independent control plane across an estate, whichever
party issues a given token. The control-plane vocabulary is exact,
not loose:

- the issuer side holds desired state (the record, its authority,
  its lifecycle and state version), reconciles it (gating, the
  ceiling review, evidence reconciliation), and distributes bounded
  authority (policy views, status, the management surface);
- tokens and the PEP/PDP boundary are the layer's data plane; and
- Status and Signals are the channel between the two.

The plane the layer governs is authority, never operations: how an
agent runs stays with the harness and the orchestrator.

## The Capability Envelope {#capability-envelope}

One tension organizes the whole family. A Mission commits its
authority and intent once, at approval, but an agent's work is
open-ended: the actions a task will take are not known when it is
approved. "Reconcile Q3 invoices" must authorize reading any invoice
and posting any adjustment under the cap, because the specific ones
cannot be enumerated in advance.

So the Authority Set an Approver consents to is a **capability
envelope, not a task specification**, and the gap between that
envelope and what a given run actually does is where agent risk
lives.

The family's mechanisms are levers that narrow that gap:

- constraint-bounding and the subset rule shrink the envelope at
  issuance;
- runtime enforcement checks each action against it at the point of
  use;
- action-bound approval re-consents the highest-consequence actions
  with their concrete parameters;
- progressive authorization trades many increment approvals for one
  bounded ceiling;
- metering caps cumulative consumption; and
- completion retires authority as the task finishes.

No single lever closes the gap; a deployment composes the ones its
risk warrants ({{assurance-levels}}), and the verbs of {{layers}}
organize the levers by the question each answers.

What approval commits is broader than the structured Authority Set
alone: it also commits the rendered intent context (`goal`,
`constraints`, and, where it differs, the requested ceiling), the
effective `expires_at`, and the rendered `controls` bounds
({{I-D.draft-mcguinness-oauth-mission}}). Concrete request values,
current consumption, and action sequencing are decision-time facts,
evaluated later by runtime policy, metering, or action-bound
(transaction) approval; core does not require them to be re-rendered
to the original Approver, though action-bound approval may re-render
exactly that.

The lifecycle control gates new derivation from the envelope; a
credential already materialized under it keeps running to its own
bound ({{kill-switch-composition}}). The two halves compose but do
not substitute: an envelope real at approval time can still admit, at
decision time, an effect the Approver never saw rendered in that
form.

Attribution shares the grain limit: proving which concurrent task
item produced a permitted action needs a verified cross-link no
family carrier supplies today ({{binding-properties}}).

The levers share one strategy: they convert semantic risk into
structural signals. A policy decision point is never asked to judge
whether content is harmful; provenance (the harness taint context),
composition (the quarantine pattern), egress enumeration and volume
bounds, separation of duty, and re-consent turn that question into
facts a decision can gate on. A content evaluator a deployment adds
composes as Resource policy at the decision point and only ever
narrows.

The stance beneath the levers is **survivable incorrectness**: the
agent is probabilistic, so the family never bets on the model being
right and builds so that wrong is survivable, on two arms.

The action arm is this envelope and its levers, wire-backed, with
in-flight work unwinding through recorded reversibility classes
({{I-D.draft-mcguinness-mission-orchestration}}). The input arm is
**least exposure**: everything the agent sees can steer it and
everything it holds can leak, so a Mission budgets disclosure as
well as authority, and mediated custody generalizes from credentials
to context.

The arms differ in maturity, and the difference is stated rather
than blurred: the exposure arm's enforceable edges are the harness
taint rule, egress mediation, and catalog filtering
({{I-D.draft-mcguinness-mission-harness}},
{{I-D.draft-mcguinness-mission-runtime}},
{{I-D.draft-mcguinness-mission-authzen}}), while its interior,
retrieval, memory, and context assembly scoped to the Mission, has
no interoperable form yet and is deployment discipline, declared in
the Deployment Profile ({{deployment-profile}}) rather than claimed.

The envelope meets its hardest case in the open world. The OAuth
model starts with authority client-proposed and enumerated at approval;
an agent that discovers resources at encounter time breaks that premise,
and some authorization mechanisms invert it: the resource declares its
own operations and consequences. Who owns meaning, and how it reaches
derivation, consent, and enforcement, is stated once as the ontology
contract ({{ontology-contract}}).

Where the OAuth discovery profile consumes a self-declaration, the
declaration's digest is committed with the binding evidence: an
additional commitment beside the Mission's integrity anchors,
recording what
the resource claimed to be at the moment authority bound to it. The rest of the
encounter, its routing through drawdown, catalog binding, projection,
or fresh approval, and its identity pinning and floors, is the
discovery companion's contract
({{I-D.draft-mcguinness-mission-discovery}}). AAuth can use R3 for
resource-owned deterministic semantics without placing that declaration
or such an additional commitment in the private mission blob.

## A Mission's Life {#mission-life}

The structure is easiest to see by following one Mission end to end
under the OAuth binding: an operator gives an agent the task
"reconcile Q3 invoices."

1. **Propose.** The client shapes the request into a structured
   Mission Intent, untrusted by construction, and submits it in a
   Pushed Authorization Request {{RFC9126}}, optionally proposing
   concrete authority on the standard `authorization_details`
   parameter alongside it
   ({{I-D.draft-mcguinness-mission-shaping}}; the OAuth binding).
2. **Approve and record.** The Authorization Server derives an
   Authority Set (read invoices, post adjustments under a cap),
   discloses it, and the Approver approves. The approval event
   commits `intent_hash`, `authority_hash`, and, where a proposal was
   submitted, `proposal_hash`, and creates the
   Mission, `active` with an expiry; Consent Evidence commits what
   was shown
   ({{I-D.draft-mcguinness-oauth-mission-consent-evidence}}).
3. **Issue.** Tokens are derived under the subset rule, carry the
   `mission` claim, and derivation and refresh are refused once the
   Mission leaves `active` (the OAuth binding).
4. **Enforce.** Before each consequential action (posting an
   adjustment), the PEP obtains a PDP permit bound to the action's
   concrete parameters and to current Mission state
   ({{I-D.draft-mcguinness-mission-runtime}},
   {{I-D.draft-mcguinness-mission-authzen}}).
5. **Delegate.** A sub-agent that verifies ledger entries receives a
   child Mission with strictly narrower authority and lineage
   ({{I-D.draft-mcguinness-oauth-mission-child-delegation}}).
6. **Govern.** Consumers observe state through Status and Signals;
   growth requires an approved successor
   ({{I-D.draft-mcguinness-oauth-mission-expansion}}), and entries
   retire as their work completes
   ({{I-D.draft-mcguinness-oauth-mission-status}}).
7. **Stop.** Revocation or expiry turns every gate at once: issuance
   refuses, the PDP denies, the harness pauses bound sessions and
   queues, and the orchestrator unwinds in-flight work
   ({{I-D.draft-mcguinness-mission-harness}},
   {{I-D.draft-mcguinness-mission-orchestration}}).
8. **Prove.** The record, anchors, evidence, and receipts let an
   auditor reconstruct what was approved, shown, decided, and done,
   and a Mandate carries the committed facts to parties outside the
   deployment ({{I-D.draft-mcguinness-mission-mandate}},
   {{I-D.draft-mcguinness-mission-audit}}).

The approval-to-permit path in sequence:

~~~
 Approver     Agent              AS          PEP/PDP        RS
    |           |                 |             |            |
    |           | 1 Mission       |             |            |
    |           |   Intent (PAR)  |             |            |
    |           |---------------->|             |            |
    | 2 disclose and approve      |             |            |
    |<--------------------------->|             |            |
    |           |  Mission active:|             |            |
    |           |  intent_hash,   |             |            |
    |           |  authority_hash |             |            |
    |           | 3 Mission-bound |             |            |
    |           |   token         |             |            |
    |           |<----------------|             |            |
    |           | 4 action, token, parameters   |            |
    |           |------------------------------>|            |
    |           |                 | 5 state and |            |
    |           |                 |   authority |            |
    |           |                 |<----------->|            |
    |           |                 |             | 6 permit,  |
    |           |                 |             |   evidence |
    |           | 7 permitted action executes   |----------->|
~~~

Under the standalone binding the same life runs with ordinary tokens
and the Mission Join in place of step 3's claim carriage
({{deployment}}). Under the AAuth binding, the Person Server instead
governs the native Mission Context through propose, clarify, approve,
and the mission log; it does not emulate the AS's Authority Set,
integrity anchors, PDP permits, Child Missions, or portable evidence
({{the-mission}}).

# Non-Goals {#non-goals}

The model's boundary is deliberate. The family does not define:

- **A new authority format, or a new grant protocol.** Rich
  Authorization Requests {{RFC9396}} and kindred mechanisms already
  fill the authority-expression role; the family leaves that to them
  ({{the-mission}}). The same restraint holds against GNAP and the
  capability-system lineage (macaroons, Biscuit, UCAN,
  object-capability narrowing): this family composes with deployed
  grant protocols and attenuation primitives rather than introducing
  a competing one of its own; the OAuth binding states the comparison
  ({{I-D.draft-mcguinness-oauth-mission}}).
- **A policy language.** The PDP evaluates the Mission's Authority
  Set, constraints, and state; how a deployment authors policy beyond
  them is local ({{I-D.draft-mcguinness-mission-runtime}}).
- **Entitlement governance.** What standing access a principal should
  hold over time belongs to existing governance layers; the
  delegated-authority layer composes with them ({{the-mission}}).
- **Agent identity and deployment governance.** Who the agent is, its
  concrete instance, and its approved behavioral version belong to
  the deployment's agent IAM and change governance; the family
  authenticates against and consumes those facts without defining
  them ({{three-objects}}).
- **An agent framework.** The harness constrains the execution
  environment's relationship to Mission state; it does not say how an
  agent plans, reasons, or calls tools
  ({{I-D.draft-mcguinness-mission-harness}}).
- **Semantic derivation.** Whether a derived Authority Set is the
  right reading of the task is committed and auditable, not
  standardized ({{derivation-boundary}}).
- **Agent trustworthiness.** The family bounds what a compromised or
  injected agent can do; it does not make the agent trustworthy
  ({{I-D.draft-mcguinness-mission-security-model}}).

# The Mission Verbs {#layers}

The family organizes along a verb spine: each verb answers one
question, sits on one trust boundary, and is owned by named
documents; the levers of {{capability-envelope}} sort onto this
spine by the question each answers.

~~~
 propose      OAuth Intent Shaping or AAuth native proposal
              (client or agent side, untrusted)
                        |
 approve      Mission control point: the OAuth AS, Mission
 and record   Authority Server, or AAuth Person Server
              contextual-governance binding
              (+ Consent Evidence, Deferred Approval)
                        |
              the Mission: durable approved context and
              lifecycle; authority anchors where defined
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

 project      Cross-Domain Projection (a Mission honored
              in another trust domain)

 continue     Mission Continuation (authorization continuity
              over ICA, async delegation, and cross-domain
              transports)

 prove        Consent Evidence, Mandate, Audit

 analyze      Security Model (the trusted base)
~~~

## Propose

The question: how does a user's request become a candidate approved
task? In OAuth, the boundary is the client side and Intent Shaping
produces an untrusted Mission Intent
({{I-D.draft-mcguinness-mission-shaping}}), entering through Pushed
Authorization Requests {{RFC9126}} or the MAS submission endpoint. In
AAuth, the agent sends the native description and requested tools to
the Person Server's mission endpoint. The AAuth binding defines no
Mission Intent or dependency on the shaping profile.

## Approve and Record

The question: how does a proposed task become an approved, committed
Mission? The boundary is the binding's control point; the approval
event is where trust is created. Owners: the five bindings
({{I-D.draft-mcguinness-oauth-mission}},
{{I-D.draft-mcguinness-mission-authority-server}},
{{I-D.draft-mcguinness-mission-aauth}},
{{I-D.draft-mcguinness-mission-uma}},
{{I-D.draft-mcguinness-mission-gnap}}), Consent Evidence
({{I-D.draft-mcguinness-oauth-mission-consent-evidence}}) committing
the disclosure shown to the Approver, and Deferred Approval
({{I-D.draft-mcguinness-oauth-mission-approval}}), the OAuth
binding's asynchronous path, with an experimental companion adding an
in-review narrowing negotiation; the
standalone and AAuth bindings are natively asynchronous. AAuth's
baseline approval commits its exact mission blob, not the family
Consent Evidence object. Where the experimental
progressive authorization companion is used, the initial approval also
consents an authority ceiling for later staged widening
({{I-D.draft-mcguinness-oauth-mission-progressive}}).

Who holds the deciding side is a spectrum, not a species: the
approval event requires an accountable principal deciding against
committed inputs before any authority exists, and the proposer is
never the approver. A deterministic, versioned policy can approve at
machine speed within a ceiling a human consented to (the OAuth binding's
`policy_drawdown` and `template` authorization bases, {{invariants}}):
policy approves the instance because a human approved the policy or
the template, with `policy_version` keeping that chain re-checkable,
while a model's generated judgment is never the sole authority for
granting or widening: a generated approver reading
attacker-influenced proposals is itself an injection surface. The
high-consequence classes stay on
a fresh human decision, per the progressive profile's prohibited set
({{I-D.draft-mcguinness-oauth-mission-progressive}}).

## Govern

The question: how do consumers observe Mission state, and how does
authority grow or retire mid-task? The boundary: between the issuer
and every consumer relying on state. Owners: Status, the signed pull
surface with a lifecycle endpoint and per-entry completion discharge
({{I-D.draft-mcguinness-oauth-mission-status}}); Signals, the push
complement ({{I-D.draft-mcguinness-oauth-mission-signals}});
Expansion, widening only via an approved successor
({{I-D.draft-mcguinness-oauth-mission-expansion}}); Containment,
event-triggered monotonic narrowing of a live Mission's effective
authority ({{I-D.draft-mcguinness-oauth-mission-containment}});
Management,
fleet enumeration and bulk lifecycle for operators
({{I-D.draft-mcguinness-oauth-mission-management}}); and Discovery,
experimental, binding encountered resources within a pre-consented
ceiling ({{I-D.draft-mcguinness-mission-discovery}}). The AAuth
binding carries this verb natively: its management companion for
status, termination, and delegation-tree queries
({{I-D.draft-mcguinness-mission-aauth-management}}); the approved
lifetime bound is AAuth's own `expires_at`, profiled by the expiry
document ({{I-D.draft-mcguinness-aauth-mission-expiry}}).

## Enforce Each Action

The question: is this specific action, with these parameters,
permitted under this Mission now? The boundary: the last controllable
point between agent and resource. Owners: the runtime profile, the
decision contract with parameter binding, custody, and fail-closed
behavior ({{I-D.draft-mcguinness-mission-runtime}}); its AuthZEN
binding, the concrete decision API
({{I-D.draft-mcguinness-mission-authzen}}); the runtime evidence
companion, the Decision Evidence, Execution Evidence, and Refusal
Record objects ({{I-D.draft-mcguinness-mission-runtime-evidence}}).
Its decision composes conjunctively with the structural plane above:
Effective Authority Set membership, every applicable
cumulative-consumption or stateful operational gate, and a required
action-bound approval are each independently necessary, and none
grants, widens, or restores another
({{I-D.draft-mcguinness-mission-runtime}}, Section "The Runtime
Decision").

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
build on the actor chain of the OAuth binding's Delegation Within a Mission
section. The chooser: the OAuth binding's token-exchange delegation for an
execution hop living and dying with the parent's lifecycle; a Child
Mission when the delegate needs its own lifecycle, approval, or
audit identity; attenuation, experimental, only where offline
minting is the constraint. AAuth delegates natively: a
parent-mediated sub-agent under `parent_agent`, distinct from the
call chain of a service hop, with no Authority Set machinery imported
({{I-D.draft-mcguinness-mission-aauth}}).

## Project

The question: how is one Mission honored in another trust domain? The
boundary: a trust boundary the origin does not control, where the
verifier holds no session with the issuer. Owner: Cross-Domain
Projection, a single-hop grant that carries the Mission's identifier,
issuer, and authority hash into a partner domain unchanged, where a
Resource AS mints a local token bounded by the projected authority
({{I-D.draft-mcguinness-oauth-mission-cross-domain}}). Projection
preserves authority across the boundary rather than narrowing it to a
sub-actor, which is why it is a distinct verb from Delegate;
downstream revocation latency is the local token lifetime.

## Continue

The question: how does a Mission's authorization continue, under the
same approval and constraints, when the acting identity must be
re-established at each hop or after the original credential is gone?
The boundary: the seam between authorization continuity, which the
Mission owns, and identity continuity, which a transport carries.
Owner: Mission Continuation
({{I-D.draft-mcguinness-oauth-mission-continuation}}), the
authorization-continuity profile, which keeps three easily conflated
things apart. Identity continuity, who is acting and how that identity
legitimately continues, rides a transport rather than this profile:
Identity Continuation
({{I-D.draft-mcguinness-oauth-id-continuation-assertion}}) for a
short-lived, sender-constrained hop within a domain; async delegation
({{I-D.draft-zhu-oauth-async-delegation}}) for a long-running,
disconnected task; and the cross-domain grant
({{I-D.draft-mcguinness-oauth-mission-cross-domain}}) across a trust
boundary. Authorization continuity, what work remains authorized under
which constraints on whose approval, is the Mission's: every continued
grant derives a subset of the Mission's Authority Set, is state-gated
at issuance, is bounded by the Mission's expiry, and ends when the
Mission goes terminal. Execution-time evidence records, against the
Mission, what was done at each continued hop. The load-bearing
invariant is that a continuation handle grants nothing: it names an
accepted hop, and every continued grant re-passes the Mission's
`active` gate, so continuity is never authority, the rule the harness
already applies to session continuity
({{I-D.draft-mcguinness-mission-harness}}). Continue is therefore
distinct from Delegate, which narrows authority to a sub-actor, and it
uses the Project verb's cross-domain grant as one transport rather
than replacing it.

## Prove

The question: what can a party outside the deployment verify about
what was approved and done? The boundary: across trust domains and
time; the verifier holds no session with the issuer. Owners: Consent
Evidence ({{I-D.draft-mcguinness-oauth-mission-consent-evidence}});
the Mandate, a signed, portable statement that authorizes nothing
({{I-D.draft-mcguinness-mission-mandate}}); the Mission Receipt,
portable evidence of an action taken under a Mission
({{I-D.draft-mcguinness-mission-runtime}}); Audit Transparency, the
append-only evidence log ({{I-D.draft-mcguinness-mission-audit}}).

## Analyze

The question: which components must be trusted, and what does each
one's compromise cost? The boundary: the whole system. Owner: the
Mission Security Model
({{I-D.draft-mcguinness-mission-security-model}}).

# The Reference Architecture {#reference-architecture}

The family is a menu, but a reader should meet it as a meal. Four
stacks, each containing the previous, are the shapes deployments
actually take, and the second is the reference:

**Protocol core**:
: the OAuth issuance binding alone, the realization these stacks are
  expressed in (chosen for OAuth 2.0's deployed infrastructure): the
  standardizable primitive (approved, anchored, state-gated
  Missions), Mission-substrate conformance ({{requirements}}), no
  per-action control (Baseline Issuance, {{assurance-levels}}). The
  stacks are this OAuth realization throughout; a peer binding
  realizes the levels per its own document, and peer standing does
  not imply identical rungs or capabilities.

**Reference security architecture**:
: core plus runtime enforcement, its AuthZEN binding, runtime
  evidence (the decision and execution objects AuthZEN consumes),
  and a freshness source, Status being the reference choice; the
  substrate contract arrives with them as runtime and AuthZEN's
  normative kernel, by adoption closure, and the family manifest
  records the stack's exact membership (the Runtime-Enforced level,
  {{assurance-levels}}). This is the architecture this document
  means when it says a Mission is enforced, and the one an
  evaluation should picture by default. It presumes an
  authority-bearing binding; under AAuth the analogous per-action
  control is the Person Server's contextual gate on PS-mediated
  paths ({{I-D.draft-mcguinness-mission-aauth}}).

**Recommended agent architecture**:
: the reference architecture plus Consent Evidence and the harness
  (the Governed Agent level): what a deployment running autonomous
  AI agents should build.

**High-assurance architecture**:
: the recommended architecture plus mediated custody, no unmediated
  path, action-bound approval, active freshness, and agent-isolated
  approval rendering (the High-Assurance Agent level).

## The Five Packages {#packages}

Independent of how the drafts are cut for standardization, the
system decomposes into five architecture packages; the document map
({{document-map}}) names every draft, and its groups, not this list,
are the maintained assignment. The packages are the product
architect's view of the same system, and a draft can serve more than
one package:

1. **Mission Control**: the object, approval (including deferred and
   revision), lifecycle, status and signals, expansion, completion,
   management.
2. **Authority Distribution**: the four issuer bindings, the
   issuance grant, cross-domain projection, child delegation,
   offline attenuation.
3. **Runtime Enforcement**: the runtime contract, the AuthZEN
   binding, parameter binding, custody, metering.
4. **Agent Execution Governance**: the harness, orchestration,
   shaping, discovery.
5. **Evidence and Accountability**: consent evidence, the Mandate,
   audit transparency, and the decision and execution evidence the
   runtime package produces.

A product architect deploys packages; a standards reviewer reads
drafts; the two views name the same system.

# Mission Invariants {#invariants}

The following seven invariants define the family's portable-authority
model and are stated normatively by their home documents. They apply to
the OAuth binding and to companions and bindings that explicitly adopt
the corresponding Authority Set capabilities. A change that would break
one in those bindings is a change to that model, not to a profile.

The AAuth binding adopts the context-level invariants: durable approval,
stable attribution, exact-byte integrity, an active-state gate at the
PS, and termination. It does not adopt the OAuth Authority Set, the
OAuth integrity anchors, or universal subset derivation. AAuth resource authority
is decided afresh in the vocabulary and policy of each Resource or
Access Server, with contextual PS governance when the PS is on path.

**Authority serves an approved task**:
: No Mission-bound authority exists except by derivation for a
  Mission, and a Mission is created only when rooted in an approved
  authorization basis that commits `intent_hash` and `authority_hash`
  (the OAuth binding). Fields an agent can influence shape authority only
  through the pre-approval derivation the Approver consents to; once
  the Mission is approved they are inert and never derive, widen, or
  gate authority.

**Only `active` permits**:
: Issuance, refresh, and every new positive governance decision
  require the exact state `active`; every other state, including an
  unrecognized one, fails safe (the OAuth binding's Mission Lifecycle
  and Gating section). A state-aware consumer relies only while it
  observes `active`; a state-unaware consumer retains the bounded
  materialized-credential residual ({{validity-model}}). In AAuth, only PS
  operations and the PS-asserted and federated authorization paths are
  structurally gated; identity-based and resource-managed decisions do
  not pass through the PS. On the gated paths the gate covers requests
  whose resource token carries the validated Mission Reference; a
  stripped reference yields a missionless request, bounded by the
  binding's downgrade rules ({{I-D.draft-mcguinness-mission-aauth}}).

**Authority only narrows**:
: Derived tokens, delegated child Missions, attenuated tokens, and
  cross-domain projections carry subsets; widening exists only as an
  approved successor: a fresh approval
  ({{I-D.draft-mcguinness-oauth-mission-expansion}}), or policy
  drawdown within a ceiling a human pre-consented
  ({{I-D.draft-mcguinness-oauth-mission-progressive}}). The relation
  is typed: it is defined where a structured-authority vocabulary
  defines it (in the OAuth binding, `mission_resource_access` and
  the Common Constraints), and authority carried in a type with no
  defined subset relation is carried as approved, neither narrowed,
  delegated, nor projected; moving authority into expressive
  policy-language entries weakens this guarantee exactly there, a
  trade to make knowingly ({{ontology-contract}};
  {{I-D.draft-mcguinness-mission-security-model}}).

**Revocation is possession-independent**:
: A Mission ends by a state change at its issuer, not by finding and
  destroying credentials; outstanding credentials meet the issuance
  gate, the runtime re-check, or their own expiry, whichever comes
  first ({{validity-model}}; {{I-D.draft-mcguinness-oauth-mission-status}}).

**Attribution is carried, never inferred**:
: Each role in the actor chain travels in its own construct, and the
  evidence layer records them together; no role is derived from
  another ({{actor-chain}}). This invariant scopes the actor chain.
  The credential-to-Mission association is itself a carried fact only
  where a binding carries the `mission` claim; under the standalone
  binding the PDP's join establishes it by inference, bounded by that
  binding's join assurance ({{deployment}}).

**Enforcement fails closed; inert surfaces fail safe**:
: A PDP that cannot establish state or authority within the published
  staleness bound denies, and a consumer that cannot refresh state
  treats its cache as unreliable rather than as permission
  ({{I-D.draft-mcguinness-mission-runtime}}).

**Anchors commit; they do not prove semantics**:
: The integrity anchors prove what was approved and committed, not
  that the derivation was the right reading of the task
  ({{derivation-boundary}}). AAuth's corresponding integrity property is
  the `s256` commitment over exact mission-blob bytes, not the OAuth
  integrity anchors.

Read against "approved" in the first invariant, the OAuth binding fully
defines one authorization basis, `direct`, a human's own approval. It
provides the extension point, an authorization-basis `type` string,
that companion profiles use to define others: `template`, a dispatch
drawing on a ceiling the human consented to once, and
`policy_drawdown`, a child instance a policy adjudicates within a
bound the parent's human already consented to. This is never an
eighth invariant: every value of the basis, defined by the OAuth
binding or by a companion, fixes the same accountable human as
`consent_principal`; they differ only in what activated this instance
and what root that activation traces to (the OAuth binding).

Read as shared capabilities rather than universal wire semantics, the
bindings carry durability, attribution, and termination. Narrowing and
containment require a structured-authority capability and are not
baseline AAuth Mission Context properties.

Read on the artifact plane, the same invariants forbid authority from
riding a work product: crossing into a Mission, it is input the
receiving Mission re-evaluates under its own Authority Set, never a
source of authority itself. This is a reading of the invariants
above, not an eighth invariant, carried through non-transitive
Mission-to-Mission handoff by the Mission Work Products companion
({{I-D.draft-mcguinness-oauth-mission-work-products}}). The OAuth
binding states the rule normatively in its "Authority Does Not
Propagate With Information" section
({{I-D.draft-mcguinness-oauth-mission}}); that section, not this
summary, is the normative text this passage tracks.

Read under composition, the invariants bound one Mission's own
Authority Set, not the aggregate surface a delegation tree, a
cross-domain hop, or a chain of child generations reaches together:
depth resets at each hop and generation independently of its parent,
so the authorized surface a body of work can reach can exceed what
any single approval appears to bound. This is again a reading of the
invariants above, not an eighth invariant; disclosing the composed
bound at the consent surface is the cross-domain and child-delegation
profiles' role, and bounding aggregate consumption is the metering
profile's ({{I-D.draft-mcguinness-oauth-mission-cross-domain}},
{{I-D.draft-mcguinness-oauth-mission-child-delegation}},
{{I-D.draft-mcguinness-mission-metering}}). The OAuth binding states
the same composition property in its "Composition and the Effective
Ceiling" section ({{I-D.draft-mcguinness-oauth-mission}}); that
section, not this summary, is the normative text this passage
tracks.

## The Ontology Contract {#ontology-contract}

The derivation boundary ({{derivation-boundary}}, later in this
document) settles who commits authority; this section
settles who owns what an operation means. The ownership statement is
one sentence: the resource owns the ontology, its operations, its
constraint semantics, and their consequences, while derivation,
consent rendering, and enforcement consume that meaning without
owning it, and no layer invents meaning it does not own. The
consuming contract is equally short: meaning binds at approval, is
enforced at the point of use, and any translation between the
resource's vocabulary and another party's is trusted, verified, or
separately approved, never a place where authority widens
({{approval-fidelity}}). One boundary is shared by agreement: the
resource owns its operation semantics and consequences, while the
family owns the registered cross-resource constraint vocabulary,
which a resource explicitly advertises and adopts before it binds
({{I-D.draft-mcguinness-oauth-mission}}).

Resource-owned meaning reaches the three consuming layers through
five mechanisms, each normative in its own home and composing as one
contract:

Common Constraints:
: The registered constraint vocabulary every conforming party
  evaluates identically, with the `mission_constraints_supported`
  protected-resource metadata member advertising which constraints a
  resource enforces. Home: the issuance profile
  ({{I-D.draft-mcguinness-oauth-mission}}).

Capability-source binding:
: Catalog-sourced capability definitions (an MCP tool, an OpenAPI
  operation) content-digested at derivation and refused on drift at
  decision time, so the meaning authority bound to is the meaning
  enforced. Home: the capability-binding companion
  ({{I-D.draft-mcguinness-mission-capability-binding}}).

Operation Profiles:
: The per-operation statement of normalization and binding rules,
  carrying resource-declared operation semantics such as idempotency,
  reversibility, and lease requirements into parameter binding. Home:
  the runtime profile ({{I-D.draft-mcguinness-mission-runtime}}).

The encounter contract:
: What is submitted, adjudicated, and recorded when an agent meets a
  resource the approval could not enumerate, so meaning that arrives
  late still binds before use. Home: the discovery companion
  ({{I-D.draft-mcguinness-mission-discovery}}).

Resource-Declared Semantics:
: The full inversion: the resource publishes its operations, their
  human meaning, and their consequences. Under the OAuth discovery
  composition, the declaration can be content-addressed by `r3_s256`
  as an additional commitment beside the Mission's integrity anchors; the
  declared operations become candidate vocabulary that derivation
  narrows against. AAuth can instead use R3 as a resource-owned
  deterministic authorization vocabulary while the private mission
  blob remains contextual PS governance. R3 content addressing is not
  a baseline AAuth mission anchor. Home: the discovery and R3
  compositions, informative.

Behind the five mechanisms sits one direction axis, and the
direction is chosen per encounter, not fixed by binding. The family
inherits OAuth's client-proposed default: the client names the
authority it wants and the resource's meaning arrives through
metadata, catalogs, and profiles ({{capability-envelope}}).
Resource-Declared Semantics is the inversion, where the resource
speaks first. Where a structured-authority binding commits that meaning
at approval, it is enforced at use and translation never widens. Under
the OAuth binding the resource-declared direction
runs entirely through seams the family already has: the encounter
contract routes the declaration
({{I-D.draft-mcguinness-mission-discovery}}), narrowing-mode
derivation consumes the declared operations as candidate vocabulary
({{I-D.draft-mcguinness-oauth-mission}}), consent composes the
resource-authored material, and the declaration's digest rides the
derived authority (the progressive companion's
`resource_declaration_digest`,
{{I-D.draft-mcguinness-oauth-mission-progressive}}). In AAuth, R3 can
describe deterministic resource authorization independently of mission
approval; the PS considers the resource request and mission context
without turning the R3 declaration into a Mission Authority Set.
Proposed RAR-type metadata
({{I-D.draft-zehavi-oauth-rar-metadata}}), a resource publishing the
`authorization_details` types and fields it understands, is the
OAuth-native descriptive surface the direction builds on.

Where a deployed semantic-binding mechanism is in force, both
directions close the same loop: the meaning source's digest becomes
part of the derived authority. A catalog-sourced capability pins its
`source_digest`; a resource declaration pins `r3_s256`; in each case
the Authority Set carries the version of the meaning it was derived
under, and the point of use compares against the meaning in force.
An ordinary registered `authorization_details` type can carry stable
semantics with neither digest; the loop is closed by the mechanism a
deployment runs, not by the family universally. Under such a
mechanism, meaning is not consulted at approval and assumed at
enforcement; it is committed at approval and re-verified at use.

The contract's failure mode is already normative in each home: a
consumer that cannot resolve an operation's meaning, a constraint it
cannot evaluate, a drifted capability definition, an unrecognized
declaration, refuses rather than guesses. Meaning, like state, fails
closed.

The contract has a dual, and the two statements carry equal force.
The resource owns what an action means; the Mission owns why it is
happening and where the undertaking stands, and that context exists
nowhere else in the stack. A resource evaluates each request at
perfect local resolution and zero task resolution: it can price
every consequence its ontology names and cannot see the undertaking
the request belongs to. This is the context asymmetry, and a risk
decision composes both sides of it: semantics without purpose prices
every delete the same, and purpose without semantics cannot read the
call.

"Delete database" in isolation is indistinguishable from
catastrophe. "Delete database" inside an approved migration whose
copy steps already completed is a priced, checkable step. That judgment needs the
undertaking's history, and no resource-local view contains it. The
join of Decision and Execution Evidence on the Mission's identity is
where that history is reconstructible after the fact; at decision
time, a task-aware decision point can draw the same history from
trusted prior workflow state or another authoritative source. The runtime profile names the mechanism: sequence-aware
evaluation over the undertaking's history is an optional decision
input, guarded so that history informs a decision and never widens
one ({{I-D.draft-mcguinness-mission-runtime}}).

# Mission Roles and Components {#components}

For each component: what it does, what it holds, and which document
specifies it. What its compromise costs is the security model's
subject ({{I-D.draft-mcguinness-mission-security-model}}).

Agent (client):
: Proposes the Mission Intent and executes the task; in the OAuth
  binding it holds derived Mission-bound tokens; outside the trusted
  base and assumed compromisable
  ({{I-D.draft-mcguinness-oauth-mission}}).

  A deployment may authenticate concrete agent instances under the
  client-instance-assertion profile and its AI-agent profile
  ({{I-D.draft-mcguinness-oauth-client-instance-assertion}},
  {{I-D.draft-mcguinness-oauth-ai-agent-instance}}), which sharpens
  delegation chains, joins, and evidence attribution to instance
  granularity without touching the Mission model.
  Attestation-based client authentication and SPIFFE
  ({{I-D.draft-ietf-oauth-attestation-based-client-auth}},
  {{I-D.draft-ietf-oauth-spiffe-client-auth}}) can supply
  client-instance authentication and workload credentials beneath
  these profiles; they do not define the Mission actor, delegation,
  intent, lifecycle, or evidence semantics defined here.

Subject:
: The user or system on whose behalf the Mission is approved, an
  (`iss`, `sub`) pair recorded immutably at approval (the OAuth binding).
  AAuth keeps the person's relationship and context at the PS and does
  not add this OAuth Subject tuple to the mission blob.

Approver:
: The single accountable principal who approves the Mission; equal
  to the Subject for self-approval (the OAuth binding's Single Accountable
  Approver section). In AAuth, the wire `approver` value names the PS,
  not a portable person identifier; the person reviews and approves
  through that PS.

Mission Issuer:
: Validates the Mission Intent, runs the approval event, records the
  Mission, and owns its state. The authority-bearing bindings host it:

  - OAuth Authorization Server: every derived token carries the
    `mission` claim, and issuance and refresh are gated on Mission
    state ({{I-D.draft-mcguinness-oauth-mission}}).
  - Mission Authority Server: the same record, anchors, and
    lifecycle without issuing tokens; the PDP joins ordinary
    credentials to the Mission at the point of use
    ({{I-D.draft-mcguinness-mission-authority-server}}).
  - UMA 2.0 Authorization Server (experimental sketch): the pushed
    Mission Intent rides UMA claims pushing, the resource owner's
    decision fills UMA's authorization assessment, and RPT issuance
    is gated on state ({{I-D.draft-mcguinness-mission-uma}}).

  The OAuth and standalone authority-bearing bindings also serve
  audience-scoped policy views, the authority-distribution artifact the
  runtime and MAS profiles define
  ({{I-D.draft-mcguinness-mission-runtime}},
  {{I-D.draft-mcguinness-mission-authority-server}}). The AAuth binding
  does not define such a view from the mission blob; deterministic
  resource authorization remains in scopes, resource tokens, Resource
  and Access Server policy, and optionally R3.

AAuth Person Server:
: The controlling authority for the native Mission Context rather than
  an OAuth-style Mission Issuer. The mission blob is committed by
  AAuth's `s256`, and the PS gates PS-asserted issuance and federated
  brokering. It does not gate direct identity-based or resource-managed
  decisions ({{I-D.draft-mcguinness-mission-aauth}}).

Resource Server:
: The protected resource. In the OAuth binding it enforces
  statelessly from the token and can check the `mission` claim (the
  OAuth binding's Resource Server Enforcement section); in the standalone
  binding the token carries no Mission signal, and Mission properties
  reach it only through the enforcement path.

PEP and PDP:
: The PEP sits at the last controllable boundary before an action and
  obtains a permit for each consequential action; under mediated
  custody it, not the agent, holds the sender-constraint key.

  The PDP evaluates the action against the Mission's authority,
  constraints, actor chain, and current state, and fails closed
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

The bindings converge on shared Mission Context capabilities, while
authority carriage and enforcement remain binding-dependent:

~~~
      Subject        Approver
          \             |
           \      approval event
            \           |
  +-------------------------------------------------------------+
  |                    Mission Control Point                    |
  | +------------+ +------------+ +------------+ +------------+ |
  | | OAuth AS:  | | Standalone | | AAuth PS:  | | UMA 2.0 AS | |
  | | Mission-   | | MAS: no    | | Mission    | | (sketch):  | |
  | | bound      | | tokens;    | | Context;   | | pushed     | |
  | | tokens     | | the PDP    | | PS paths   | | Intent;    | |
  | | gated on   | | joins to   | | gated      | | RPTs gated | |
  | | state      | | Mission    | |            | | on state   | |
  | +------------+ +------------+ +------------+ +------------+ |
  +-------|--------------|--------------|--------------|--------+
          v              v              v              v
          durable approved context and lifecycle;
       Authority Set and anchors where the binding defines them
                     |
                     | binding-specific state, context,
                     | and authority surfaces
                     v
     Agent ------> PEP ----------> PDP
     (harness,      |  <- permit -
     orchestrator)  v
             Resource Server
~~~

Grouped as planes rather than parts, the same components form the
delegated-authority layer of {{the-mission}}, with the evidence
surface crossing all of them:

~~~
 control       Mission control point (OAuth AS | MAS | AAuth PS):
               approved context, lifecycle and gating;
               anchors and authority distribution where defined
                    |                       ^
                    | state, authority      | evidence
                    v                       |
 enforcement   PEP and PDP: a permit per consequential
               action, parameter binding, custody
                    |                       ^
                    | mediated actions      | outcomes
                    v                       |
 execution     harness, agent, orchestrator: sessions,
               sub-agents, queues, unwinding

 evidence      Consent Evidence, decision and execution
 (crossing)    evidence, Mission Receipts, the Mandate,
               audit transparency
~~~

## The Actor Chain {#actor-chain}

One material action splits across these roles, and the family keeps
each distinct and attributable rather than collapsing them into one
"agent" identity. The identifiers below are shown in the OAuth
binding's instantiation; each binding carries the same distinctions
in its own vocabulary, AAuth natively with its
`agent` identifier, the Person at the PS, `parent_agent` for a
parent-mediated sub-agent, and the call chain for a service hop
({{I-D.draft-mcguinness-mission-aauth}}):

Principal:
: the Subject, the token `sub` (the OAuth binding).

Accountable approver:
: the Approver, committed at the approval event (the OAuth binding).

Intent generator:
: the shaper, with Shaping Evidence recording what it emitted
  ({{I-D.draft-mcguinness-mission-shaping}}).

Authorizer:
: the Mission Issuer at issuance (the OAuth binding); the PDP per action
  ({{I-D.draft-mcguinness-mission-runtime}}).

Approved agent:
: the OAuth client, `client_id` on every derived token (the OAuth binding).

Executing delegate:
: the outermost `act` actor (the OAuth binding's Delegation section).

Credential holder:
: the mediating PEP under mediated custody
  ({{I-D.draft-mcguinness-mission-runtime}}).

Capability executor:
: the `executor` of the capability source binding
  ({{I-D.draft-mcguinness-mission-capability-binding}}).

Downstream identity:
: the audience-scoped token and the cross-domain local subject
  ({{I-D.draft-mcguinness-oauth-mission-cross-domain}}).

Attribution survives because no role is inferred from another: each
is carried by its own construct, and the evidence layer records them
together, in runtime evidence and the Mission Receipt
({{I-D.draft-mcguinness-mission-runtime}}), Consent Evidence, and
the audit feed.

The chain is actor lineage, not authority lineage. An `act` chain
records who acted through whom; it does not carry what task was
approved, how authority narrowed at each derivation, whether the
task remains `active`, or which parameter constraints bind. Those
travel in the Mission's own constructs: the anchors, the Authority
Set, the lifecycle state, and Child Mission lineage
({{I-D.draft-mcguinness-oauth-mission-child-delegation}}). Reading
an actor chain as authorization provenance is the gap the Mission's
lineage exists to close.

## Three Objects, Three Lifecycles {#three-objects}

Separately from the authorization flow's four objects
({{the-mission}}), a deployment that runs agents under both an agent
identity system and this family governs three independently
lifecycle-bearing objects. Each has its own
owner, lifecycle, and revocation, and the model stays clean only
while none absorbs another's job:

Agent identity (who is acting):
: The logical agent and, where the instance profiles are deployed,
  the concrete instance ({{components}}). Owned by the deployment's
  agent IAM, a registry or directory outside this family, and
  consumed as the `client_id`, the instance assertion, and verified
  instance claims.

Agent Deployment (what is running):
: The approved behavioral version of the agent: its code, model,
  system prompt, tool allowlist, data scope, and runtime
  configuration. Owned by the deployment's change governance; a
  change to any of these is a new Agent Deployment, and which
  changes require re-approving standing Missions is policy that
  governance records.

  A Mission may be pinned to a named Agent Deployment where the
  deployment defines that control. This object is distinct from the
  Mission Deployment Profile ({{deployment-profile}}), which is the
  estate's published claims manifest, not a property of an agent.

Mission (why the authority exists):
: This family's object: the approved task, its lifecycle, and, where
  the binding derives one, its Authority Set.

An agent registry is a complementary dependency, not part of the
Mission system; an A2A AgentCard directory ({{A2A}}) is one example
source. Discovery contents are not authority for workload identity,
authorization, or effective capabilities: a deployment applies local
admission policy and independently verifies the relevant credential,
resource metadata, and capability evidence. Where one
exists, the Mission Issuer and the PDP
consume a small, stable slice of it:

- the agent identifier and its owner,
- current status and revocation state,
- the approved Agent Deployment,
- eligibility bounds (what the registry permits the agent to be
  approved for, a derivation input, never a grant), and
- risk tier.

Registry state is a state source like any other: the consuming
decision point treats it under the runtime profile's freshness
discipline, with a declared staleness bound, failing closed when it
cannot be established ({{I-D.draft-mcguinness-mission-runtime}}).

Authorization composes conjunctively across the three lifecycles: a
decision may depend on agent state, Mission state, and credential
validity, and each gates independently. A valid credential never
overrides a revoked agent or a non-active Mission, and a live agent
under an active Mission still fails on an expired credential.

The assurance levels add binding strength in the same order a
deployment adds it: authority is issued to an authenticated client;
instance assertion pins the concrete instance; sender-constraint
keys pin possession; attested runtimes pin the execution
environment; and an Agent Deployment pin holds the behavioral
version ({{assurance-levels}}).

The division of labor with agent IAM is one sentence: agent identity
preserves who is acting, and the Mission preserves why their
authority exists. The registry and workload identity authenticate an
approved agent instance; the Mission and its derived Authority Set
say what sanctioned work that instance carries; per-hop credentials
narrow; the runtime layer enforces each action and parameter; and
the evidence layer joins what was approved, decided, and done.

## Swarm Execution: Multiplication, Not Delegation {#swarm-execution}

One composition of the three objects recurs often enough to name. A
Mission pinned to an Agent Deployment through the OAuth binding's
`controls.agent_deployment` ({{I-D.draft-mcguinness-oauth-mission}}),
executed concurrently by N attested instances of that Deployment, is
multiplication, not delegation: no `act` hop, no Child Mission, no
attenuation chain, because authority never moves between principals.
Late binding is attestation: an instance joins the work by
authenticating as the pinned Deployment under the instance profiles
({{I-D.draft-mcguinness-oauth-client-instance-assertion}},
{{I-D.draft-mcguinness-oauth-ai-agent-instance}}), not by receiving
a credential from a peer. The invariant is class-grain
authorization, instance-grain attribution: the class, the Agent
Deployment projected as `client_id`, is an authorization subject,
never an attribution subject, and attribution stays per-instance
through the instance substrate, which forbids a sender-constraint
key shared across a client's instances. The OAuth binding's
`controls.max_derivations` is the explicit fan-out ceiling, and
consumption bounds attach at Mission grain, so a swarm shares one
budget ({{I-D.draft-mcguinness-mission-metering}}).

The decision ladder:

- The same principal exercising the same authority concurrently is
  the swarm: more attested instances of the pinned Deployment
  deriving under one Mission, no new construct.
- A different principal acting inline is a delegated token with an
  `act` hop (the OAuth binding's Delegation Within a Mission section).
- A durable sub-agent needing its own lifecycle, approval, or audit
  identity is a Child Mission
  ({{I-D.draft-mcguinness-oauth-mission-child-delegation}}).
- Offline narrowing is attenuation
  ({{I-D.draft-mcguinness-oauth-mission-attenuation}}).

# The Mission Substrate {#substrate}

The binding-neutral contract is Mission Substrate Requirements
({{I-D.draft-mcguinness-mission-substrate}}): a contextual-governance
kernel every binding provides (native reference and controller, actor
binding, approved context, approval event, governance gate, bounded
reliance, context propagation, and an ordered governance record) and
eight optional capabilities each binding claims through its Mission
Substrate Statement (Lifecycle-Gated Authorization, State-Observable,
Structured Authority, Monotonic Derivation, Credential-Bound,
Authorized Context Correlation, Independently Verifiable, and Portable
Evidence).

The bindings declare what they provide, each in its Mission Substrate
Statement. The companion profiles named without "oauth" are defined
against the binding-neutral contract and declare what they consume,
each in a Mission Substrate section of its own; the runtime profile
is the exemplar of that consumption declaration
({{I-D.draft-mcguinness-mission-runtime}}), and the remaining
consumers align progressively. Where a companion consumes a concrete
representation, it is today the OAuth binding's, the realization the
family was first authored against; vocabulary ownership migrates to
the substrate contract by touch
({{I-D.draft-mcguinness-mission-substrate}}).

The remainder of this section documents that instantiation: eight
primitives, each with its normative home and its consumers. Every
sentence mirrors a rule the named profile states normatively. None of
these OAuth-binding representations or stronger semantics is
required verbatim by the binding-neutral kernel, although several
instantiate mandatory kernel functions: the identifier and issuer
realize the Mission Reference and Controller, the lifecycle realizes
the governance gate, token validity participates in bounded reliance,
and the audit horizon participates in the governance record.

## The Primitives, at a Glance {#substrate-primitives}

| Primitive | The OAuth realization | Normative home | Consumed by |
|---|---|---|---|
| Mission Identifier and Issuer | An opaque, non-reused identifier with at least 128 bits of entropy and no semantic content, plus the issuer URL; together they name exactly one Mission. The kernel requires stability, non-reassignment, and unguessability, not this syntax | The OAuth binding: Mission Record, Mission Identifier Format | Every companion: decisions, evidence, harness bindings, the state surfaces, the audit statement subject, the Mandate |
| Lifecycle state space | The states of {{the-mission}}, open to companion-defined states, with the only-`active` rule, fail-safe unrecognized states, and a freshness source with a stated staleness bound | The OAuth binding (state space, only-`active`); the status and runtime profiles (freshness); Status and Signals (observation) | Runtime per-class re-check (fail closed on staleness), harness pause, suppress, and terminate, the orchestrator's unwind trigger, the Mandate (state as of minting) |
| Authority Set representation | Authorization-details entries ({{RFC9396}}), each naming resource, actions, and constraints, under the subset rule (derived or delegated authority is never broader) and the Common Constraints vocabulary (registered names with fixed subset and intersection rules) | The OAuth binding: Mission Authority, Subset Rule, Common Constraints | Runtime and the AuthZEN binding, the MAS, Expansion and Completion, Child Delegation and Offline Attenuation, Consent Evidence, the Mandate |
| Integrity-anchor envelope | A committed object hashed over a `typ`-domain-separated, issuer-bound envelope with fixed canonicalization and an algorithm-prefixed encoding a verifier recognizes or rejects (unknown prefixes refuse; no downgrade); the `typ` space is the extension point | The OAuth binding: Integrity Anchors, Canonicalization Rules, Extensibility | Consent Evidence, Shaping, the runtime layer and AuthZEN binding (`mission-policy-view`), Orchestration, the Mandate, Audit Transparency |
| Issuer key material | Signing keys resolvable from `issuer`; across a rotation each key identifier stays resolvable while artifacts signed under it remain within the audit horizon | The OAuth binding: Signing and Key Rotation | Verifiers of Mission-bound credentials, Consent Evidence, the Mandate, the signed state surfaces, Audit Transparency |
| Audit horizon | The deployment-declared retention window: at least the Mission's lifetime plus a declared post-terminal period | The OAuth binding: Mission Record | Consent and runtime evidence and Audit Transparency (retention), the MAS (record retention), the security model's retention analysis |
{: title="Substrate primitives in their OAuth realization"}

The anchors in the envelope row are **commitment anchors**, not
enforcement proofs ({{derivation-boundary}}): a narrowed-token
Resource Server enforces the authority it receives rather than
reconstructing authority from a hash of a full set it does not hold
({{I-D.draft-mcguinness-mission-security-model}}).

## Token Classes {#token-classes}

"Mission-bound" is a specific claim. This document uses three token
shapes descriptively, so a weak one is not read as the strong one;
the names are defined by the OAuth binding's Terminology, and the
properties the strong class requires are its conformance rule's:

- a **Mission-referenced token** carries a Mission identifier only;
- a **Mission-derived token** carries authority derived from an
  active Mission; and
- a **Mission-bound token** is Mission-derived and additionally
  active-state gated, subset-constrained, and refresh-gated: in the
  contract's vocabulary, a credential covered by the binding's
  Lifecycle-Gated Authorization, Monotonic Derivation, and
  Credential-Bound claims, which the OAuth binding's conformance rule requires
  of the OAuth binding.

Only the third earns the term: a `mission` claim alone is a reference,
not Mission-bound authorization. The family reserves "Mission-bound"
for that class, and a binding earns it through the capability claims
of its Mission Substrate Statement, not by protocol lineage.

## The Mission-Bound Credential

A credential carrying the `mission` claim (`id`, `issuer`,
`authority_hash`) and Mission-derived authorization details, issued
only while the Mission is `active`. Home: the OAuth binding's Mission-Bound
Access Tokens and The Mission Claim sections.

This is the binding-dependent primitive, and it is exactly where the
bindings split. The OAuth binding provides it. The standalone binding
does not: the MAS's Mission Substrate section states that a MAS provides
neither this credential nor issuance gating
({{I-D.draft-mcguinness-mission-authority-server}}). An AAuth auth token
can carry the native `{approver, s256}` mission reference, but it does
not carry the OAuth `authority_hash` or Mission-derived authorization
details and therefore is Mission-referenced, not a Mission-bound
credential in the strong sense defined above
({{I-D.draft-mcguinness-mission-aauth}}).

For profiles that compose with it, the seam is the runtime profile's
Mission binding establishment step
({{I-D.draft-mcguinness-mission-runtime}}): the credential carries
the Mission reference where the binding provides one, and a binding
without it supplies an externally established reference, verified
under a join the binding defines, which the MAS profiles as its
Mission Join.

Offline Attenuation attenuates this credential and the
token-carriage aspects of delegation ride it, so both require it;
the companions that need a credential-to-Mission association (the
runtime layer and the harness) route through the binding
establishment step, which is what makes the standalone binding
possible.

The issuance-grant companion
({{I-D.draft-mcguinness-oauth-mission-issuance-grant}}) composes the
two: the standalone Mission Issuer mints a Mission Issuance Grant
that a consuming Authorization Server redeems for Mission-bound
tokens, providing this primitive compositely.

## Approval Fidelity {#approval-fidelity}

For the portable-authority bindings, the approval event authenticates
the Approver, establishes the Subject, derives and renders the Authority
Set for consent, computes the anchors over the consented set, the
approved Intent, and, where one was submitted, the authority proposal,
and creates the record in `active` atomically with the
decision.

AAuth approval has different fidelity: the native propose, clarify, and
approve interaction authenticates the parties, returns the approved
mission blob and exact-byte `s256` commitment, and creates an `active`
Mission Context. It does not render or commit an OAuth Authority Set.

Home: the OAuth binding's Mission Approval section. Consumed by Consent
Evidence, which binds to this event, and by every downstream
guarantee that assumes the anchors, the gating, and the record.

## The Validity Model {#validity-model}

Five validity horizons govern reliance, each with its own setter,
checker, and consequence; implementations most often err by
conflating them:

Token `exp`:
: set by the credential issuer and checked by every consumer of the
  token. In the OAuth binding it is capped by the Mission's
  `expires_at`. Past it the credential is dead and obtaining a new
  credential re-enters whatever issuance gate the binding and access
  mode provide.

Mission state, and `expires_at` where defined:
: set by the controlling authority and checked at the binding's declared
  control points. In OAuth, the issuance gate, PDP, and state consumers
  enforce it. In AAuth, the PS enforces `active` or `terminated` at PS
  endpoints and on PS-asserted and federated paths; direct
  identity-based and resource-managed decisions have no PS state gate.

`fresh_until`:
: set by the status responder; checked by status consumers. Past it a
  cached state report may not be relied on and is re-fetched.

Permit window:
: set by the PDP; checked by the executing PEP. Past it the permit is
  void and a new decision is required.

Action-approval freshness:
: set by the approval surface; checked by the PDP. Past it an
  action-bound approval no longer authorizes the action it named.

The horizons compose by minimum: reliance at any moment requires
every applicable horizon to be open, and no horizon substitutes for
another.

The horizons also give the deployment its freshness dial, and the
TTL-only end of that dial is a first-class posture, not a fallback. A
deployment that relies on lifetimes alone verifies with local
cryptography and a clock: no state source, no freshness discipline,
no availability coupling, and a worst-case exposure equal to the
lifetime by construction. Where every fresh credential crosses a
Mission-state decision point, this realizes the **lifecycle-gated**
capability with reliance bounded by credential lifetime alone
({{I-D.draft-mcguinness-mission-substrate}}); it is not a property of
every access mode, since AAuth's PS-asserted and federated paths have
that gate while its direct modes do not.

TTL-only is the right choice at action grain, where an artifact lives
seconds to minutes and a revocation landing inside its window has no
observation point that could reach the artifact before its own
expiry does, and for short missions; the family's own short-lived
artifacts (the permit, the cross-domain grant, the Join Assertion)
already sit at this end.

What a lifetime cannot do is
suspend, complete, or kill now, which is the task-grain residue the
Mission's state carries and which the **state-observable** capability
reaches: an authenticated freshness source with a stated staleness
bound, a named substrate capability a binding MAY provide beyond the
kernel's bounded-reliance floor
({{I-D.draft-mcguinness-mission-substrate}}),
and the one runtime enforcement requires
({{I-D.draft-mcguinness-mission-runtime}}).

The two ends are one mechanism seen from opposite sides: a lifetime
relocates the freshness check from the verification path to the
issuance path, so every re-issuance is the policy re-check, which is
the family's gates-new-derivation-only rule in its other reading. A
deployment states where it sits on the dial through its
bounded-revocation claim ({{assurance-claims-axis}}): a TTL-only
posture claims the lifetime as its bound only for paths whose
re-issuance is gated, with no state-observable overlay. The runtime
profile prices each position, source by source, in its state and
freshness section ({{I-D.draft-mcguinness-mission-runtime}}).

## The Binding Checklist {#binding-checklist}

For a new binding this checklist is now normatively stated by Mission
Substrate Requirements ({{I-D.draft-mcguinness-mission-substrate}});
this section remains the informative summary, and the existing
bindings remain authoritative for themselves.

Another mission-based protocol supplies a Mission Context when it maps
the following native capabilities explicitly:

- a stable reference and controlling authority;
- binding to the acting actor;
- immutable approved context, or a verifiable commitment to it;
- an explicit approval event;
- an active-state gate at declared control points;
- a stated reliance bound on every governed decision and artifact;
- context propagation or decision correlation; and
- an ordered governance or audit record.

Structured authority, monotonic derivation, credential carriage,
state observability, independent verification, and portable evidence
are optional facets. A binding composes only the profiles whose required
facets it provides. AAuth supplies the Mission Context capabilities in
its own idiom but not a portable Authority Set or universal subset rule.

The per-profile Mission Substrate sections remain the authoritative
per-consumer statements of this interface.

## Error Surfaces {#error-surfaces}

The OAuth and MAS profiles use three error surfaces, each owned once. OAuth endpoints
return OAuth error codes, owned by the OAuth binding
({{I-D.draft-mcguinness-oauth-mission}}). Lifecycle surfaces,
including management, return the status profile's JSON error body
(`error`, `error_description`, `nonce`)
({{I-D.draft-mcguinness-oauth-mission-status}},
{{I-D.draft-mcguinness-oauth-mission-management}}). MAS-native
surfaces return the MAS error object, which adds `error_reason` and
omits the `nonce` ({{I-D.draft-mcguinness-mission-authority-server}}).
AuthZEN denial reasons are not a fourth surface: they ride the
decision response ({{I-D.draft-mcguinness-mission-authzen}}). Where
the same symbol exists as both an OAuth error code and a wire-body
symbol (`invalid_request`), the envelope it arrives in disambiguates.

The AAuth binding retains AAuth's own error surface.  Its native
management companion returns `application/problem+json`, preserves the
base AAuth `mission_terminated` error on ordinary PS operations, and
makes an absent reference indistinguishable from one the caller is not
authorized to observe
({{I-D.draft-mcguinness-mission-aauth-management}}).

Registration posture is likewise deliberate per artifact class:
OAuth-facing parameters and media types register with IANA, evidence
media types defer registration until cross-domain interoperability
demands it, and each profile states which posture it takes.

# The Authority Derivation Boundary {#derivation-boundary}

Deriving the Authority Set from the Mission Intent is the semantic
heart of the model and the one step the family deliberately does not
standardize. The consequence is a trust boundary worth stating
plainly: interoperability begins at the committed result, not at the
Intent. A Mission Intent has no portable semantics; two conforming
Authorization Servers can derive different Authority Sets from the
same Intent, and audit can establish what was derived (against
`intent_hash` and `policy_version`), never whether it was the right
reading of the task. A deployment whose partners must reason about
its derivations can publish a derivation policy identifier and
test fixtures that pin Intent-to-Authority-Set outcomes, making the local
policy reviewable even though it does not travel. Narrowing
mode ({{I-D.draft-mcguinness-oauth-mission}}) is the checkable path:
where the client supplies candidate authority, derivation is a subset
of it and reproducible, which is the closest the family comes to
portable derivation.

The ceiling the derivation narrows against is itself a composition,
not a single object. The derived Authority Set sits inside every
bound on the task: the issuer's derivation policy, the ceiling of
the Mission's established authority source (a delegating person's
own authority, a workload's provisioned authority, or governed
organizational policy: approval activates authority the source
already holds and grants nothing beyond it, and the Approver needs
authority to activate the source, not personal possession of its
permissions), and, at enforcement time, the resource owner's and
deployment's live policy at the decision point. The
derivation step intersects the first two and commits the result;
the runtime contract re-checks the rest on every action, which is
why a permit is never implied by the Authority Set alone. A
deployment adding further sources (a tenant boundary, an
environment-specific floor) adds them as derivation-policy inputs or
as decision-point policy, never as agent-negotiated widening.

The derivation modes rank by how portable their result is:

| Derivation mode | Portability status |
|---|---|
| Client proposes concrete authority; AS narrows | Interoperable default |
| AS derives from structured Intent fields | Profile-specific |
| AS derives from free text | Local, non-portable unless profiled |
| LLM-assisted derivation | Advisory unless a deterministic policy commits the output |

A deployment seeking interoperable authority uses the first;
free-text and model-assisted derivation are local policy unless a
profile pins them with a published policy identifier, version, and
test fixtures.

# Mission Deployment Patterns {#deployment}

## Binding Security Architectures {#binding-architectures}

The bindings share Mission Context capabilities but are not one security
system: each has its own authority representation, trust assumptions,
cutoff behavior, and failure modes, and a deployment names its
architecture, not only its binding. Three patterns cover the bindings:

- **credential-carried authority**: the credential names the Mission,
  carries derived authority, and issuance is gated (the OAuth AS and
  UMA AS);
- **PDP-joined**: credentials are ordinary and a join establishes
  the association at the decision point (the standalone MAS); and
- **context-carried**: AAuth carries its native `{approver, s256}`
  reference while authority remains in resource scopes and policy.
  The PS gates PS-asserted and federated authorization, while direct
  identity-based and resource-managed decisions bypass the PS.

The differences that decide a design:

| Property | OAuth AS | MAS | AAuth PS | UMA AS (sketch) |
|---|---|---|---|---|
| Credential carries the Mission | yes (`mission` claim) | no | native reference where supported | yes (claim or introspection) |
| Issuance gated on state | yes | no (the issuance grant restores it per consuming AS) | PS-asserted and federated only | yes |
| Runtime PDP required for a kill switch | no (issuance gate exists; runtime tightens) | yes (runtime is the only cutoff) | required for direct modes; PS-path issuance has a bounded cutoff | no (per-use introspection cuts off) |
| Join ambiguity possible | no | yes (bounded by join assurance) | no when the native reference is preserved; it can be ignored in direct modes | no |
| Revocation latency source | token lifetime, status, or runtime | runtime and status only | auth-token lifetime on PS paths; no Mission cutoff on direct paths | next introspection |
| Offline Mission verification | partial (claims verify; state does not) | limited (join assertion) | reference integrity only; blob is private | JWT RPTs partial; opaque RPTs none |

The table is the one-page answer to a question the object-level
framing invites: a MAS deployment does not provide AS-native
semantics because both hold the same Mission, and a reader
comparing deployments compares architectures first.

The OAuth binding stacks two independent chokepoints. Issuance gating
acts at the token layer: a revoked or expired Mission stops all
further derivation and refresh, and short-lived tokens age out.
Runtime enforcement acts at the action layer: each consequential
action is re-checked against current state at the point of use.
Issuance gating plus runtime enforcement is strictly stronger than
either alone: a gap in PEP coverage is still bounded at the token
layer, and an outstanding token is still stopped at the action layer.

The AAuth binding has a narrower structural chokepoint. The Person
Server refuses new PS-asserted issuance or federated brokering for a
terminated Mission Context, bounding those paths by auth-token lifetime.
Identity-based and resource-managed decisions do not cross that
chokepoint. The AAuth binding defines no generic family runtime
composition or independently resource-verifiable Authority Set
({{I-D.draft-mcguinness-mission-aauth}}).

Per-action enforcement is budgeted, not blanket: only consequential
actions are gated, the common-case decision is a local evaluation
against a materialized policy view whose network cost is paid per
freshness window, and only the high-consequence classes are required
by the runtime profile to hold a synchronous gate (the runtime
profile's deployment considerations,
{{I-D.draft-mcguinness-mission-runtime}}).

The composition is an overlay, not a substrate swap: a deployment
mediates the paths where the high-consequence classes live and lets
every other resource ride lifetime-bounded reliance
({{assurance-levels}}), token lifetimes sized to the tolerated
staleness, with no state evaluation at the resource.

The standalone mode trades the token-layer kill switch for zero
Authorization Server changes. A MAS creates, approves, and serves
Missions while tokens remain ordinary; the PDP joins credentials to
Missions, and the MAS is the freshness source.

The cost is structural: no `mission` claim travels, revoking a
Mission stops nothing at the token layer, and enforcement rests
entirely on PEP coverage, so a token exercised outside that coverage
is ungoverned (the MAS's Limitations section). The path to a
token-layer chokepoint is the OAuth binding, where the estate's AS
can change; the record, anchors, and lifecycle carry over unchanged.
That is a move between peer architectures, not an upgrade from a
lesser one: the MAS remains a peer binding, not a staging area (its
own document's framing).

Between the two sits the issuance join
({{I-D.draft-mcguinness-oauth-mission-issuance-grant}}): the MAS
remains the Mission Issuer while estate Authorization Servers redeem
Mission Issuance Grants for Mission-bound, state-gated tokens,
restoring the token-layer chokepoint without moving approval.

## Entry Ramps by Estate {#entry-ramps}

Which chokepoint a deployment builds first is decided by the estate
it already runs, not by preference. The OAuth binding's issuance
ramp assumes
an Authorization Server that supports pushed authorization requests,
rich authorization requests, and JWT access tokens; the standalone
ramp assumes none of that and trades it for PEP coverage. By starting
condition:

| Estate starting condition | Entry ramp | Day-one delta |
|---|---|---|
| AS changeable; PAR, RAR, and JWT access tokens in place | The OAuth binding | AS adds intent intake, derivation, approval, record, and gating; a Mission-creating client changes with it, submitting `mission_intent` through PAR and handling Mission responses and lifecycle refusals; scope-only Resource Servers continue unchanged at scope grain, per-entry constraints reaching them only through a projection or a PEP |
| AS changeable; RAR absent or tokens opaque | MAS first; the OAuth binding once the AS gains the token plane (a peer move, not an upgrade) | A MAS beside the AS; tokens are unchanged, while governance requires approval integration and Mission correlation, and enforcement waits on PEP/PDP coverage with a trustworthy join |
| AS cannot change (shared, third-party, SaaS) | Standalone MAS, phase by phase | Records and approvals first; enforcement arrives with PEP/PDP coverage |
| Many Authorization Servers, one governance point | MAS as estate control plane; issuance join per consuming AS | Each AS adds grant redemption only ({{I-D.draft-mcguinness-oauth-mission-issuance-grant}}) |
| No PEP/PDP over consequential paths | The OAuth binding where the AS allows; runtime layer next | Lifetime-bounded reliance (short tokens, gated refresh); the runtime overlay added later, where the high-consequence classes live |

Every row shares the record, anchors, and lifecycle, so a ramp is an
entry point, not a fork: Missions carry unchanged from any row to the
rows a deployment adopts later.

One ramp cuts across the rows: the **short mission**. A Mission whose
`expires_at` sits minutes out, run in records mode with
lifetime-bounded reliance, is a durable approval record with
TTL-grade operational cost: audit, anchors, and bounded exposure
with no external state-observation surface, the issuer still owning
Mission state and the issuance gate ({{validity-model}}). A deployment
can adopt the family this way first, per task, and add state
surfaces only where missions grow long enough to need suspend,
complete, or kill-now.

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

The quarantine pattern removes a leg of the injection-to-exfiltration
chain instead of gating it: no single Mission ever holds untrusted
input and an egress path at once.

- Work that ingests untrusted content runs under a Mission with no
  external-communication or external-commitment authority.
- Work that communicates externally runs under a separate Mission
  whose inputs are the quarantined product.
- The crossing between them, a human review or a deterministic
  transformation, is recorded as evidence, under the harness taint
  policy ({{I-D.draft-mcguinness-mission-harness}}) and, where
  claimed, the runtime profile's trifecta containment
  ({{I-D.draft-mcguinness-mission-runtime}}).

The quarantine pattern is the deployment-shaped case of a general rule
that holds for every work product one Mission passes to another. A work
product crossing into a receiving Mission is input, not authority: the
receiving Mission re-evaluates any proposed action under its own
Authority Set, and the producing Mission's authority does not transfer
through the artifact by copying, referencing, embedding, or
communicating it. The Mission Work Products companion
({{I-D.draft-mcguinness-oauth-mission-work-products}}) is the normative
home of this rule and defines the provenance object that attributes an
artifact without granting anything. Ingesting a work product is an added
conjunctive gate at the receiving Mission's boundary: it composes with
the three objects' independent gates and does not nest inside them, so
Actor, Agent Deployment, and Mission stay a gating pipeline, not a
containment hierarchy ({{three-objects}}).

Where the separation must hold within one Mission, the metering
profile's exclusivity control
({{I-D.draft-mcguinness-mission-metering}}) latches read-and-egress
apart under a single approval.

The **standing-agent pattern** governs the agent whose work never
ends. The agent stands; the authority cycles: the standing thing is
a charter, a Mission with a consented authority ceiling and drawdown
policy ({{I-D.draft-mcguinness-oauth-mission-progressive}},
experimental), and the working thing is the bounded Mission each
unit of work draws under it, as an in-ceiling successor or a
policy-approved Child Mission
({{I-D.draft-mcguinness-oauth-mission-child-delegation}}), each
expiring and discharging as its unit completes
({{I-D.draft-mcguinness-oauth-mission-status}}).

The progressive profile's prohibited set keeps the high-consequence
classes on a fresh human approval inside the ceiling, and its
Ceiling Review bounds the chain in time with an evidence-rendering
renewal.

Without the progressive profile the same pattern runs as ordinary,
freshly approved unit Missions with deferred approval
({{I-D.draft-mcguinness-oauth-mission-approval}}) absorbing the
volume: the experimental profile changes the unit economics, not the
governance shape.

## Comparison to a Conventional Stack {#standardization-crossovers}

A skeptical reading of this family asks why Rich Authorization
Requests {{RFC9396}}, short-lived tokens, and an AuthZEN PDP holding
policy and session state server-side would not suffice. Steelmanned
first: RAR supplies structured authorization data an Authorization
Server renders into an itemized approval experience; RAR itself
guarantees neither approval fidelity nor a consent UI. A short token
lifetime bounds revocation only when every issuance, refresh, and
exchange path re-evaluates current grant or session state; absent
that discipline a fresh short token keeps issuing against stale
state regardless of lifetime, the dependency the Validity Model
already states ({{validity-model}}). AuthZEN specifies a decision
API, not a global PDP, a durable session store, complete PEP
placement, or a state model; a deployment supplies those properties
in either design.

Inside one administrative domain, a conventional stack (structured
request data, an Authorization Server's consent or grant record,
short credentials, and a stateful PDP) implements durable task
state, fan-out joins, persistent narrowing, and audit locally. Five
places mark where that local composition meets what this family
standardizes:

1. **Durable task semantics across tokens and restarts.** OAuth
   grants, refresh families, or PDP records can outlive a token.
   Mission standardizes an independently addressable,
   lifecycle-bearing approved task with anchors consistently
   interpreted by the Authorization Server, PDP, agents, audiences,
   and evidence producers (the OAuth binding's Why a New Object and
   Relationship to Other Authorization Objects sections,
   {{I-D.draft-mcguinness-oauth-mission}}); it does not make
   persistence newly possible.
2. **Multi-credential, multi-actor join.** A deployment can invent a
   transaction, grant, or workflow identifier shared across
   credentials. Mission gives that join stable approved-task
   semantics, binds it to authority, and carries it through
   delegation and fan-out outside one private PDP schema
   ({{swarm-execution}}).
3. **A second trust domain.** A partner can call the origin PDP,
   share state, or federate policy. The trade is synchronous
   coupling, availability, and disclosure. Cross-Domain Projection
   offers bounded local credentials and common anchors while
   accepting local-token revocation latency (the Project verb). It
   is a portability choice, not the only possible design.
4. **Approval as a first-class record.** A local consent or grant
   database plus versioned decision logs can preserve what was
   approved. Mission's value is a standardized immutable snapshot,
   integrity anchors, and one reference portable evidence can cite
   (the OAuth binding's Why a New Object section,
   {{I-D.draft-mcguinness-oauth-mission}}; the Prove verb).
5. **Persistent narrowing.** A stateful Authorization Server or PDP
   can store reduced entitlements and consult them at issuance.
   Mission standardizes monotonic subset semantics across issuance,
   delegation, attenuation, and cross-domain projections, auditable
   across components ({{invariants}}).

| Requirement | Conventional OAuth+PDP realization | Mission standardization | Illustrative added Mission cost |
|---|---|---|---|
| Durable task semantics | Grants, refresh families, or PDP records outlive the token | An addressable, lifecycle-bearing approved task with anchors consistently interpreted across components | Durable-object and lifecycle storage |
| Multi-credential join | A deployment-invented transaction, grant, or workflow identifier | A stable approved-task reference bound to authority, carried through delegation and fan-out | New claims and endpoints |
| Second trust domain | The partner calls the origin PDP, shares state, or federates policy | Bounded local credentials and common anchors carried by projection | State consistency and distribution; privacy and correlation surface |
| Approval as a record | A consent or grant database plus versioned decision logs | A standardized immutable snapshot with integrity anchors and one portable reference | Evidence operations |
| Persistent narrowing | A stateful Authorization Server or PDP stores reduced entitlements and consults them at issuance | Monotonic subset semantics enforced across issuance, delegation, attenuation, and cross-domain projections | AS or MAS integration; ecosystem adoption |

Past these crossovers, a conventional deployment often accumulates a
durable task record, a stable join key, lifecycle checks, narrowing
rules, and audit correlations. Mission standardizes that recurring
shape across bindings and trust domains; it does not claim local
policy systems cannot implement equivalent outcomes.

## A Worked Composition {#worked-composition}

This non-normative example composes an Action-Enforced deployment
from four providers, none of which is the OAuth binding, to show that
the substrate contract ({{I-D.draft-mcguinness-mission-substrate}})
carries the weight: an AAuth agent acts under a PS-governed Mission
and calls a payment API whose authority vocabulary is owned by the
resource.

Four components publish provider claims:

| Provider | Capability supplied | Scope |
| --- | --- | --- |
| AAuth Person Server | Contextual-governance kernel; Lifecycle-Gated Authorization | PS permission decisions and PS-brokered issuance |
| AAuth Mission Management | State-Observable | The payment PDP, maximum staleness five seconds |
| Payment policy adapter | Structured Authority | Payment API actions and constraints under the payment policy's own versioned vocabulary |
| Payment gateway PEP/PDP | Authorized Context Correlation | The `schedule_payment` and `release_payment` routes |
{: title="Provider claims in the worked composition"}

Action-time enforcement and decision evidence are supplied by the
runtime profile and its evidence companion at the gateway
({{I-D.draft-mcguinness-mission-runtime}}); they consume the
capability claims above as decision inputs. The AAuth rows come from
the binding's own published Mission Substrate Statement: the
lifecycle claim from the base Statement, and the state claim under
its Mission Management activation condition, each with the
Statement's temporal and failure elements
({{I-D.draft-mcguinness-mission-aauth}}). The payment policy
adapter's and the gateway's claims remain the deployment's own,
stated as deployment-local provider claims; nothing here implies
every provider claim becomes binding-owned. The deployment
declaration names the four providers, the two routes, and the
consequence class; no machine-readable declaration format is defined
(the Mission Deployment Profile's schema remains reserved future
work, {{deployment-profile}}), and the declaration is ordinary
deployment documentation.

The deployment runs PS-asserted access. Every resource token the
gateway accepts is PS-issued or PS-brokered and carries the signed
`mission_s256` reference, the protected propagation path;
identity-based and resource-managed access are out of scope here,
because those paths are not PS-gated and may ignore the reference.
The gateway's join validates the carrying artifact's issuer (the
Person Server), its audience (the payment API), the actor binding
(the agent's key, proven on the request), and the request binding,
before joining the PS evidence, the Actor proof, the request, and
the adapter's output; the join is scoped to the two named routes
with a lifetime no longer than the state observation's declared
freshness, and a missing or conflicting input fails closed.

The composition succeeds with these results and limits:

| Requirement | Provider | Result and material limit |
| --- | --- | --- |
| Kernel | AAuth Person Server | Satisfied; native private Mission context and lifecycle |
| Current state | AAuth Mission Management | Satisfied; five-second staleness within the profile's declared maximum |
| Structured authority | Payment policy adapter | Satisfied only inside the payment vocabulary; no cross-resource claim |
| Authorized join | Payment gateway | Satisfied; the gateway validates PS provenance, Actor proof, the request, and the adapter's output before joining them |
| Action-time enforcement | Runtime profile at the gateway | Satisfied for the two named routes; direct payment-API routes are prohibited or declared uncovered |
| Evidence | Evidence companion at the gateway | Satisfied through the decision; approval-to-effect completeness additionally requires execution evidence |
{: title="Composition result"}

Two classifications make the example honest. The payment authority's
fresh decision is `decide_anew` in the substrate's transition
classification, never an attenuation of AAuth authority across
vocabularies; and the AAuth Mission context never becomes a Rich
Authorization Request object. AAuth supplies work continuity, the
payment authority decides permission in its own vocabulary, and the
gateway is the scoped joining and enforcement authority.

The same composition fails when any of the following holds: the
state source is disabled with no equivalent fresh local read; the
adapter publishes descriptive strings rather than machine-evaluable
semantics; the gateway accepts a Mission reference from the agent
without validated provenance (context splicing); the state source's
staleness exceeds the declared maximum; a direct route bypasses the
gateway; the gateway accepts the reference on an identity-based or
resource-managed request; or the payment-vocabulary claim is
generalized to another resource's vocabulary.

# Mission Assurance Levels {#assurance-levels}

Two questions get asked of a Mission deployment: what to deploy for
a goal, and what a relying party can verify. This document answers
them on two different axes. The levels below are **adoption
bundles**: which documents a deployment runs, in the order
deployments build, named so a deployment, a procurement, or a review
can cite one bundle. They are guidance, never a conformance class or
an earned label.

What a deployment proves is the orthogonal claims axis
({{assurance-claims-axis}}): scoped, named claims whose proof
obligations existing profiles fix, listed in the Deployment Profile
beside the residuals each leaves. The claims, never a level name, are
what a relying party compares, because the family's strongest
properties are deployment properties, not protocol properties:
complete PEP placement, a trusted freshness source, and credential
custody are things a deployment does, not things a token proves.

The levels build on one another: a deployment adopts recording and
governing the approved task (Baseline Issuance), then per-action
enforcement (Runtime-Enforced), then agent-governance and
compromise-resistance (Governed and High-Assurance Agent), advancing
to the bundle its risk warrants and stopping there.

The proof obligations noted with each level below are the claims
that become available at that bundle, not properties the level name
asserts.

The levels are one axis; the **binding** is an orthogonal one. The
authority-bearing bindings name their level separately from their
binding. An AAuth deployment instead reports the Mission Context
capabilities and resource access modes it actually uses; selecting the
AAuth binding does not by itself satisfy structured-authority, subset,
portable-evidence, or runtime proof obligations.

The standalone MAS binding is the case that matters most: it
provides the Mission record, lifecycle, and authority but no
Mission-bound credential and no issuance gating, so under it the
kill switch is the runtime layer alone, not the token gate, and a
deployment states that. Binding is not a level.

The AAuth distinction is access-mode dependent: PS-asserted and
federated access have a PS lifecycle gate for new authorization;
identity-based and resource-managed access do not. Its native auth token
is Mission-referenced, not the strong Mission-bound credential defined
by the OAuth binding.

The levels, cumulative:

**Baseline Issuance**:
: the approved, anchored Mission record and its lifecycle: authority
  derived and committed at the approval event with the integrity
  anchors (the OAuth binding).

  Where a structured-authority binding issues Mission-bound
  credentials, issuance is bounded by the subset rule and gated on
  Mission state, which
  grants task-bound, auditable authority and a
  possession-independent kill switch at the issuance gate; it grants
  no per-action control, and outstanding tokens run to their own
  expiry.

  Sized deliberately, that expiry is the level's revocation bound:
  **lifetime-bounded reliance**, access-token lifetimes no longer
  than the deployment's tolerated staleness
  ({{I-D.draft-mcguinness-oauth-mission-status}}), gives a
  quantified cutoff, revocation within one token lifetime, with no
  Resource Server changes and no status traffic; expiry closes the
  temporal bound by the clock alone, observing no revocation,
  suspension, completion, or containment, which is why the lifetime
  must not exceed the tolerated staleness. Revocation latency is a number, not
  a level: what the higher levels add is per-action enforcement,
  parameter binding, and evidence, not a faster clock.

  Under a binding without credential-carried authority (the standalone
  MAS), Baseline
  grants governance and audit; no kill switch of any kind exists
  until a freshness surface (the half-step) and runtime enforcement
  (the next level) arrive, and a deployment states that; the
  issuance join
  ({{I-D.draft-mcguinness-oauth-mission-issuance-grant}}) restores
  gated issuance at each consuming Authorization Server, and
  Baseline with it.

  The nearest AAuth comparison, stated as capabilities rather than a
  level: native approval, exact-byte commitment, active or terminated
  state, and the ordered mission log. The possession-independent
  issuance cutoff applies only to PS-asserted and federated requests
  whose resource token carries the validated Mission Reference; no
  Authority Set or subset proof is implied.

  Proof obligations: the anchored approval and, where credentials
  are issued, the subset rule. A deployment that adds only a
  freshness surface, Mission Status or introspection with a
  published staleness bound
  ({{I-D.draft-mcguinness-oauth-mission-status}}), gains state-aware
  reliance, a revocation cutoff within that bound, without
  per-action enforcement: a half-step into the next level, not a
  level of its own.

  The verification coverage below is profile-owned: each test
  verifies a rule its home profile states normatively, grouped here
  in reading order, never as a conformance class a level confers.
  Coverage is scoped by the capabilities a binding's Mission
  Substrate Statement claims, so a standalone MAS is never asked to
  verify a credential behavior it does not claim; the family's
  conformance manifest carries the profile-owned rows.

  Kernel, every Baseline deployment:

  1. approval creates an active Mission;
  2. an authenticated terminal transition takes effect in the
     Controller's own subsequent decisions; and
  3. the observed residual after a transition does not exceed the
     published reliance bound.

  Credential-Bound, where claimed:

  1. no credential outlives the Mission's effective expiry; and
  2. a credential from another Mission cannot be substituted (the
     reference and its Controller namespace bind together).

  Lifecycle-Gated Authorization, where claimed and limited to the
  operations named in the claim:

  1. an active Mission yields a positive result for a claimed
     operation within policy;
  2. a terminal transition prevents every claimed operation; and
  3. for every lifecycle-gated operation in the claimed scope,
     unavailable, invalid, stale, or unknown state prevents a
     positive result (the forward-compatibility rule: only `active`
     permits reliance, and lost state never fails open).

  For the OAuth binding, the same coverage includes:

  1. refresh while the Mission is active succeeds within policy and
     is refused after a terminal transition; and
  2. a bare client-supplied Mission identifier creates no binding:
     the grant, never the identifier, determines the Mission.

**Runtime-Enforced**:
: adds a PEP/PDP decision on every consequential action, a trusted
  state source with a published staleness bound, parameter binding,
  and runtime evidence ({{I-D.draft-mcguinness-mission-runtime}} and
  its AuthZEN binding). Grants per-action enforcement and revocation
  bounded, for gated classes, by the staleness bound plus the permit
  window plus the class's execution bound, and by token lifetime for
  ungated paths.

  This is the smallest deployment that turns a Mission from governed
  issuance into action-time defense, and every normative dependency
  it needs is a non-experimental family document; it is a
  substantial build, not a wedge, and
  a deployment sizes the effort from the runtime profile's
  conformance section rather than from this level's one-line
  summary.

  Proof obligations: PEP-placement completeness and the declared
  freshness source and bound. Documents: Baseline plus the substrate
  contract (the kernel runtime and AuthZEN consume normatively),
  runtime, its AuthZEN binding, runtime evidence, and a concrete
  freshness source, Status being the reference choice.

**Governed Agent** (recommended for AI agents):
: adds Consent Evidence and the harness, growing with Child Delegation,
  Expansion, Orchestration, and Discovery (experimental, with
  Progressive) as needed. Grants consent-rendering evidence and
  session-continuity discipline. Documents: Runtime-Enforced plus
  consent-evidence and the harness.

**High-Assurance Agent**:
: adds the guarantees that resist a compromised agent. Two named
  claims live at this level, each with proof obligations the runtime
  profile fixes.

  **Agent-compromise-resistant enforcement**: mediated (gateway)
  credential custody, a declared-and-audited path scope,
  action-bound approval for the high-consequence classes, an
  active-freshness state source, and approval disclosures rendered
  by a component isolated from the agent, so a compromised agent
  cannot unilaterally take a high-consequence action for which it
  does not hold a mediated credential.

  **Trifecta containment**: least exposure, the harness taint rule
  enforced as a mandatory requirement of the harness profile, with
  pre-consented egress to Approver-named destinations as its one
  carve-out, and full mediation of the external-communication and
  external-commitment classes with the egress-channel enumeration,
  so an injected agent cannot egress on the strength of untrusted
  content alone.

  These are named high bars, never implied by basic adoption; a
  deployment can bind its Enforcement Scope Statement to
  execution-environment attestation so a claim is technical rather
  than organizational ({{I-D.draft-mcguinness-mission-runtime}},
  {{I-D.draft-mcguinness-mission-harness}}).

Read as an adoption ladder, each level makes a broader class of agent
work defensible to grant. The mapping is informative: the action
classes are the runtime profile's
({{I-D.draft-mcguinness-mission-runtime}}), resource policy remains
authoritative for its own objects, and what a level grants varies
with the binding; the Mission Deployment Profile
({{deployment-profile}}) is where a deployment states its own
`mediated_action_classes` and exclusions.

| Level | What a deployment can defensibly grant |
| --- | --- |
| Baseline Issuance | Consequential reads that are attributable and killable at the issuance gate, outstanding tokens running to their own expiry: the governed pilot |
| Runtime-Enforced | Consequential writes inside approved bounds; reversal and compensation stay the orchestration profile's, where adopted |
| Governed Agent | Unattended operation and delegation, with Consent Evidence binding each approval event |
| High-Assurance Agent | The high-consequence classes ({{I-D.draft-mcguinness-mission-runtime}}), under mediated custody and action-bound approval |

Every level above Baseline Issuance also carries the cross-cutting
obligations its mechanisms imply:

- operation-profile normalization where duration or parameter
  digests are metered ({{I-D.draft-mcguinness-mission-metering}},
  {{I-D.draft-mcguinness-mission-authzen}});
- evidence retention for the audit horizon; and
- a registration schedule where audit transparency is run
  ({{I-D.draft-mcguinness-mission-audit}}).

The evidence levels are accountability, not prevention: they make
what was recorded tamper-evident, not what was perceived true or
what was never recorded present.

## Composed Kill-Switch Reality {#kill-switch-composition}

"Baseline" and "Runtime-Enforced" name two different things that
share spelling. Above, they name a level a deployment adopts. The
containment profile uses the same two words for a property a
consumer obtains per action class
({{I-D.draft-mcguinness-oauth-mission-containment}}, Section
"Containment Properties"). The two are not 1:1: a Runtime-Enforced
deployment can still provide only the Baseline property for a class
its Enforcement Scope Statement leaves lifecycle-gated-only, because
the property requires a state-observable substrate per class, not
per deployment ({{I-D.draft-mcguinness-mission-runtime}}). The table
below names the property in its own column, apart from the rung; a
row can carry a Runtime-Enforced rung and a Baseline property
together without contradiction.

The table composes a deployment that runs the containment profile
with a rung and a binding. A rung and a binding alone confer neither
containment property: containment is an overlay a deployment
separately adopts
({{I-D.draft-mcguinness-oauth-mission-containment}}). "Stops at
commit" names what a contain transition's own state-version commit
reaches immediately ({{I-D.draft-mcguinness-oauth-mission-containment}},
Section "The Contain Transition"); "runs to its own bound" names the
residual the transition does not reach. Every cell is informative
and carries no RFC 2119 language of its own; the cited normative
profile controls wherever a cell and its citation appear to differ.

| Rung | Binding | Property | Stops at commit | Runs to its own bound |
|---|---|---|---|---|
| Baseline Issuance | OAuth binding, structured-authority | Baseline, a new-derivation kill ({{I-D.draft-mcguinness-oauth-mission-containment}}, Section "Containment Properties") | New derivation, delegation, cross-domain projection, and offline attenuation roots minted after the transition ({{I-D.draft-mcguinness-oauth-mission-containment}}, Section "Derivation Gating") | Tokens already issued, to `exp`; a cross-domain projection grant already redeemed and an offline attenuation root already minted before the transition, each to its own lifetime or `del_max_depth` ({{I-D.draft-mcguinness-oauth-mission-containment}}, Section "The Materialized-Capability Residual"); a consequential read under the token-lifetime default, the same bound ({{I-D.draft-mcguinness-mission-runtime}}) |
| Baseline Issuance | Standalone MAS, no credential-carried authority | Neither; the runtime layer is the only cutoff, and it is absent at this rung | Nothing at the resource; the transition commits and is visible on the Mission Status Response and the introspection projection ({{I-D.draft-mcguinness-oauth-mission-containment}}, Section "Visibility") | Every action, to whatever native credential, session, or resource-local bound the resource enforces on its own, if any, until a freshness half-step arrives or the issuance join restores a gate ({{I-D.draft-mcguinness-oauth-mission-issuance-grant}}) |
| Runtime-Enforced | Any binding, a class using a containment-aware state source within its published bound | Runtime-Enforced for that class ({{I-D.draft-mcguinness-oauth-mission-containment}}, Section "Containment Properties"): full Status or introspection carrying `containment_version`, or Signals carrying the overlay change; a fresh derivation narrows what it mints and can shorten the residual, but it checks nothing at action time, so it carries Baseline, not Runtime-Enforced ({{I-D.draft-mcguinness-oauth-mission-containment}}, Section "Containment Properties"); a class checked only against an active-but-not-containment-aware source, gated only by fresh derivation, or left lifecycle-gated-only, gets Baseline only regardless of rung ({{I-D.draft-mcguinness-mission-runtime}}) | The contained capability, denied at the class's next gated action once the source reflects the overlay, within the staleness bound plus the permit window plus the class's execution bound ({{I-D.draft-mcguinness-mission-runtime}}) | Ungated paths, bounded by token lifetime alone |
| Baseline Issuance | MAS as estate control plane, issuance join at each consuming AS | Baseline, from Derivation Gating at the Mission Issuer ({{I-D.draft-mcguinness-oauth-mission-containment}}, Section "Derivation Gating"); the consuming AS's redemption and refresh checks are the issuance profile's ordinary `active` gate, not containment-aware on their own, since a contained Mission stays `active`, unless the consuming AS separately retrieves and applies the containment overlay or current Effective Authority Set ({{I-D.draft-mcguinness-oauth-mission-issuance-grant}}, Section "Redemption") | New grant minting only: the Mission Issuer's Derivation Gating evaluates the Effective Authority Set, so a grant minted after the transition excludes contained authority ({{I-D.draft-mcguinness-oauth-mission-containment}}, Section "Derivation Gating") | An outstanding grant redeems once, to its own maximum lifetime of 300 seconds, at any consuming AS whose redemption check is active-only rather than containment-aware ({{I-D.draft-mcguinness-oauth-mission-issuance-grant}}, Section "Redemption") |

None of this closes the conforming Baseline residual on a path or for
a class no containment-aware action-time gate reaches. For a class a
Runtime-Enforced action-time gate reaches instead, a pre-transition
credential does not run to its own bound at all. The binding
determines the artifact and its cutoff where the residual does
persist: an ungated standalone-MAS path, for instance, runs to
whatever native credential, session, or resource-local bound the
resource enforces on its own, if any, or to none, not to a token
lifetime. What changes row to row is which gate, if any, reaches a
class before its own bound, and how tight that bound is.

## Assurance Claims {#assurance-claims-axis}

The levels are the adoption ladder: what a deployment has built, in
the order deployments build it. What a deployment can prove is an
orthogonal axis, claimed as named **assurance claims**, each with a
proof obligation an existing profile fixes, and listed in the
Deployment Profile ({{deployment-profile}}) rather than implied by a
level:

- **Approved-record integrity**: the anchors reproduce from the
  record alone (the OAuth binding's integrity anchors).
- **Bounded revocation latency**, per path and mechanism, the claim
  naming the paths it covers: for a runtime-gated class, the
  published staleness bound plus the permit window plus the class's
  execution bound ({{I-D.draft-mcguinness-mission-runtime}}); for a
  lifecycle-gated path, the outstanding credential lifetime; an
  ungated path has no bound to claim.
- **Action-time enforcement**: PEP coverage for the Enforcement Scope
  Statement's mediated set, and nothing outside it.
- **Parameter-bound enforcement**: permits bound to concrete
  parameters for the classes claimed.
- **Transaction-grade execution**: the runtime profile's
  transaction-assurance tier machinery (single-use permits, leases,
  outcome reconciliation) for the classes claimed
  ({{I-D.draft-mcguinness-mission-runtime}}).
- **Agent-compromise-resistant enforcement** and **trifecta
  containment**: the two named High-Assurance claims, unchanged
  ({{assurance-levels}}).

Two deployments at the same level under different bindings can hold
different claims; the MAS modes are the worked case
({{I-D.draft-mcguinness-mission-authority-server}}). The claims, not
the level, are what a relying party compares.

## Mission Binding Properties {#binding-properties}

Whether an operation is bound to a Mission is not one question but
three independent ones: who selected and attached the Mission to
this work item (attachment provenance), whether the acting
credential's authority was issued and bounded for the Mission
(credential binding), and whether one authenticated permit covers
these exact operation inputs (action binding). The dimensions are
independent: a native Mission-bound token has strong credential
binding with no harness in sight, a trusted harness attributes work
items precisely while the credential is an ordinary bearer token,
and an action-bound permit can exist over either. No single ladder
orders them, so the family names the properties directly, as a
vector, and a deployment claims the combination each path actually
has.

| Property | Meaning | Minimum proof |
| --- | --- | --- |
| `mission-reference-selected` | A Mission tuple was supplied for routing and selection | The canonical (issuer, mission id) pair; grants nothing and makes no security claim |
| `work-item-bound` | A trusted component bound that tuple to this session, queue, or task item | An authenticated attacher, a tamper-resistant work-item identifier, and stated inheritance and retry rules |
| `credential-correlated` | The presented credential is correlated to the Mission's parties | A mapping join or Mission Join Assertion ({{I-D.draft-mcguinness-mission-authority-server}}), with its stated ceiling |
| `credential-mission-bound` | The credential's authority was issued or derived for the Mission | The six equivalence properties below |
| `presenter-key-bound` | The presenter proves possession of the key the credential is constrained to | Issuance-time key targeting (`cnf` or an equivalent confirmation) plus presentation-time proof of possession |
| `instance-bound` | The concrete acting instance is identified and holds the bound key | `presenter-key-bound` plus the instance requirements below |
| `action-bound` | An authenticated permit authorizes one operation, resource, and input projection | One of the two proof forms below |
{: title="Mission binding properties"}

The properties are claimed per covered Authorization Server,
resource, and action path, never as a product-wide maximum: a mixed
estate claims what each path has, and a weaker path never inherits a
stronger path's claim from the deployment's name. Where policy
requires a property on a path, its absence denies; nothing falls
back silently to a weaker binding.

**Credential-mission-bound** is defined by equivalence, not by one
artifact. For the covered path the credential establishes all of:

1. a trusted issuer authorized to issue for the Mission;
2. the canonical (`mission.issuer`, `mission.id`) pair and the
   recorded `authority_hash`;
3. an issued authority projection no broader than the Mission's
   Authority Set for the target audience;
4. the mapped subject, the requesting `client_id`, and actor or
   delegation context where applicable;
5. bounded lifetime plus active-state issuance and refresh gates; and
6. an auditable derivation link to the Mission authorization: an
   Issuance Grant `jti`
   ({{I-D.draft-mcguinness-oauth-mission-issuance-grant}}), a native
   issuance record ({{I-D.draft-mcguinness-oauth-mission}}), a
   cross-domain projection's provenance
   ({{I-D.draft-mcguinness-oauth-mission-cross-domain}}), or an
   equivalently specified artifact.

Sender constraint is deliberately not among them: issuance-time key
targeting and presentation-time proof are `presenter-key-bound`, a
separate property, so a path that needs possession requires the
composition rather than reading it into the equivalence. That is
also what the mechanisms support: the OAuth binding's tokens SHOULD be
sender-constrained and the generic Issuance Grant's `cnf` is
OPTIONAL, so native issuance, the Mission Issuance Grant, and a
conforming cross-domain exchange satisfy this one property, and
supply `presenter-key-bound` exactly where their confirmation
binding is actually in force. A Mission Join Assertion fails
properties 3, 5, and 6 by design, which is what separates
correlation from issuance.

**Presenter-key-bound** is possession and nothing more: the
credential names a confirmation key at issuance, and the presenter
proves possession at use, with DPoP or mutual TLS. It does not
identify which concrete agent process or workload holds the key.

**Instance-bound** requires all of: an authenticated instance
identifier; a verified binding from that identity to the
confirmation key; current proof of possession; and no key sharing
across instances. End-to-end sender constraint alone establishes
`presenter-key-bound`, never this property.

**Action-bound** requires an authenticated permit binding the
Mission, the action and resource, and the normalized parameters or
complete request projection, under the permit's validity and use
controls, in one of two proof forms:

- **portable permit**: an audience-restricted, presenter- or
  sender-bound artifact, verified where it is presented; the
  transaction token of
  {{I-D.draft-mcguinness-oauth-mission-transaction-authorization}}
  is the family's discharge; or
- **channel-bound permit**: a permit bound to the mutually
  authenticated requesting and executing parties and enforced on
  that same channel, with request cache-key equality, its validity
  window, and the applicable use controls; the runtime permit of the
  AuthZEN binding ({{I-D.draft-mcguinness-mission-authzen}})
  discharges it under exactly those conditions.

A parameter binding alone makes a response neither form, and an
evaluation identifier alone is a correlator, never the property: it
qualifies only where dereferencing it through an authenticated,
audience-bound, freshness- and use-controlled permit store yields
one of the two forms above, complete.

Deployments claim compositions, and a claimed composition requires
every member property:

- **harness-attributed**: `work-item-bound`, under the attacher and
  inheritance rules the harness states
  ({{I-D.draft-mcguinness-mission-harness}});
- **mission-credential-bound**: `credential-mission-bound` plus
  `presenter-key-bound`, end to end; `instance-bound` strengthens
  the claim where an instance identity exists and is verified; and
- **runtime-action-bound**: authoritative Mission establishment plus
  `action-bound`.

A work-item-attribution composition is deliberately absent.
`work-item-bound` and `action-bound` holding together does not prove
the permitted action came from that work item: concurrent items
under one Mission still substitute. The composition becomes
definable only when a verified cross-link exists, the action permit
or its authenticated request context binding the same
tamper-resistant work-item identifier the harness recorded; no
family carrier supplies that today, so a deployment claims the two
properties separately and nothing more.

The mechanism mapping is conservative: a propagated
Mission-Reference is selection only; a mapping join is
`credential-correlated`, with its equivalence-class ambiguity; a
Mission Join Assertion is a stronger, token- and key-specific
`credential-correlated`, still never issuance; a trusted harness
supplies `work-item-bound` where its attacher requirements hold; a
native or issuance-grant-derived token is
`credential-mission-bound`, and `presenter-key-bound` where its
confirmation binding is in force end to end; an authenticated
client-instance assertion with a verified key binding is what makes
a path `instance-bound`; a verified transaction token is the
portable `action-bound` form, and an AuthZEN runtime permit is the
channel-bound form under that binding's conditions.

The property names above are stable identifiers, and a claim is a
per-path declaration, not prose: each claimed property or
composition names the covered issuer, resource, and action-class
paths. The Enforcement Scope Statement carries the per-path
declarations for the enforcement-adjacent properties, and the
Mission Deployment Profile ({{deployment-profile}}) composes them; a
binding's Statement declares what the binding can supply, which is
never itself a deployment claim. An unknown property identifier, an
undeclared path, or an unstated property is not claimed, and a
consumer treats it as not held; nothing downgrades silently.
Schema-level claim identifiers and validation rules remain the
Deployment Profile's own future work.

Binding properties and the assurance claims above compose rather
than repeat: a binding property says whose Mission a path's work and
credentials are bound to; an assurance claim says what the
deployment's enforcement proves. Credential-level and action-level
binding likewise compose rather than substitute.

# The Mission Deployment Profile {#deployment-profile}

The Mission Assurance Levels ({{assurance-levels}}) name what to
deploy, and the assurance claims ({{assurance-claims-axis}}) name
what may be proven; a claim is only checkable if a deployment
states, concretely, what it enforces and what it leaves outside the
boundary. The **Mission Deployment Profile** is that system-level
artifact: the published composition of the per-layer statements
the profiles themselves demand (the runtime profile's Enforcement
Scope Statement, the harness environment statement, the MAS mapping
contract, the Resource Server coverage split, the
transparency-service topology and schedule, and the progressive
profile's bounds and ceiling-review cadence, each where its profile
is run), composed into one object an auditor, a procurement, or a
security review can read. It is one artifact, not a second one: each
fact's owning profile governs its meaning and normative force, and
this document fixes no serialization. A machine-readable manifest
schema, with stable claim identifiers and validation rules, is
deferred family work; until it exists, the shape below is
illustrative and the per-profile statements are the checkable form.

Its distinguishing field is `residual_risks`: the profile is not
credible unless it states, in the same object as its guarantees, what
it does not cover. An illustrative shape, for a deployment that
runs mediated credential custody but makes neither High-Assurance
claim: the agent-compromise-resistant claim requires the runtime
profile's per-condition evidence bindings (EAT profile and claim
identifiers, measurements, appraisal policy, attester identity,
freshness, signed approval configuration, rendering evidence, and a
path-completeness audit), and this shape's generic attestation
reference is declaration input, not that proof. The `key_custody`
entries below are declarations under the same rule: a custody
statement made legible, not a checked assurance grade (the member's
definition below states the open verifier gap):

~~~ json
{
  "profile": "mission-governed-agent-runtime",
  "assurance_claims": [
    "action-time enforcement", "parameter-bound enforcement",
    "bounded revocation latency"
  ],
  "mission_issuer": "https://as.example.com",
  "state_sources": [
    { "type": "status_endpoint", "max_staleness_seconds": 30 }
  ],
  "issuance": {
    "binding": "oauth-core",
    "mission_claim_required": true,
    "refresh_gated_on_active_state": true
  },
  "runtime": {
    "pdp": "authzen",
    "pep_locations": ["tool-gateway", "browser-action-proxy"],
    "mediated_action_classes": [
      "irreversible_action", "external_commitment",
      "privileged_administration"
    ],
    "action_bound_approval_classes": [
      "irreversible_action", "external_commitment",
      "privileged_administration"
    ],
    "unmediated_exclusions": [
      "internal_reasoning", "local_cache_read"
    ]
  },
  "credential_custody": {
    "held_by": "pep",
    "sender_constrained": true,
    "key_generated_in_pep": true,
    "agent_receives_bearer_token": false
  },
  "key_custody": [
    {
      "key_class": "issuer_signing",
      "artifact_classes": ["mission_tokens"],
      "kid_selector": "issuer-token-2026",
      "holder": "hsm_or_kms",
      "exportable": false,
      "generation": "dual_controlled",
      "signing_use_controls": "online_token_signing",
      "compromise_recovery_ref": "https://ops.example.com/procedures/issuer-key-compromise"
    },
    {
      "key_class": "issuer_signing",
      "artifact_classes": ["registered_evidence", "portable_artifacts"],
      "kid_selector": "issuer-evidence-2026",
      "holder": "hsm_or_kms",
      "exportable": false,
      "generation": "dual_controlled",
      "signing_use_controls": "low_volume_high_value_signing",
      "compromise_recovery_ref": "https://ops.example.com/procedures/issuer-key-compromise"
    },
    {
      "key_class": "mediating_pep_custody",
      "artifact_classes": ["sender_constraint_proof"],
      "kid_selector": "pep-dpop-2026",
      "holder": "software",
      "exportable": false,
      "generation": "generated_in_pep",
      "signing_use_controls": "per_session_sender_constraint",
      "compromise_recovery_ref": "https://ops.example.com/procedures/pep-key-rotation",
      "attestation_ref": "https://attest.example.com/pep/2026"
    }
  ],
  "approval_rendering": {
    "rendered_by": "agent-isolated-component"
  },
  "execution_environment": {
    "attestation_ref": "https://attest.example.com/runtime/2026"
  },
  "harness": {
    "subagent_inheritance": "explicit_delegation_only",
    "resume_requires_active_state": true,
    "cached_credentials_revalidated": true,
    "secondary_egress_enumerated": true
  },
  "exposure": {
    "taint_rule": "enforced",
    "egress_channels_enumerated": true,
    "egress_mediated": true
  },
  "standing_charters": {
    "ceiling_review_cadence_days": 90,
    "per_drawdown_bound": "single_entry_delta",
    "drawdown_rate_bound_per_chain_per_hour": 60
  },
  "resource_servers": {
    "authorization_details_enforcing": ["https://erp.example.com"],
    "scope_projection_only": ["https://mail.example.com"],
    "constraint_enforcement_for_scope_only": "runtime_pep"
  },
  "evidence": {
    "decision_evidence": true,
    "execution_evidence": true,
    "retention_days": 365,
    "field_classification": "evidence-schema-v2",
    "evidence_access_audited": true,
    "erasure_policy": "erasure-records",
    "transparency": {
      "service_operator": "third_party",
      "monitor": "sec-ops",
      "registration_time_bound_seconds": 3600
    }
  },
  "residual_risks": [
    "mediated custody is declared, not evidenced: no High-Assurance claim is made",
    "unmediated local reasoning is outside enforcement",
    "revocation latency up to 30 seconds",
    "PEP compromise is not prevented",
    "per-entry constraints reach scope-only resources only via the PEP",
    "long-term memory and provider model context are not Mission-scoped exposure points"
  ]
}
~~~

The `evidence` member carries the deployment's evidence-handling
posture beside its guarantees: the field-classification scheme its
records use, whether access to Mission evidence is itself audited,
and the erasure policy that pairs retention with deletion
accountability ({{I-D.draft-mcguinness-mission-audit}}).

The `key_custody` member declares, as a list keyed by key and
application rather than one row per key class, the custody a
deployment states for each signing key it operates: the key class
(the five classes {{I-D.draft-mcguinness-mission-security-model}}
enumerates: issuer signing, evidence signing, agent
sender-constraint, mediating-PEP custody, attenuation roots), the
artifact classes or `kid` selector the entry covers (core recommends
segmenting issuer signing keys by artifact class under distinct `kid`
values within one `jwks_uri`,
{{I-D.draft-mcguinness-oauth-mission}}), the holder, whether the key
is exportable, its generation and signing-use controls, a reference
to its documented compromise-recovery procedure, and any attestation
or verifier reference for that key. `software` and `hsm_or_kms` are
example holder values, a mechanism family rather than an assurance
grade; this document defines neither as a normative custody-grade
enum and fixes no validation rule for either. `key_custody` makes the
trusted-base key-custody statement
{{I-D.draft-mcguinness-mission-security-model}} already requires
legible in the Deployment Profile; it does not make that statement
checked. Custody assurance stays open until a normative reader or
verifier for this declaration exists.

Two deployments that both "support Mission" but publish different
Deployment Profiles provide different security properties, and the
profile is what makes that difference legible. A deployment lists
its assurance claims ({{assurance-claims-axis}}) here, beside the
residuals each leaves.

# Prevention, Detection, and Residue {#prevention-detection}

Each layer earns a specific property and leaves a specific residue.
Stated as a table so a claim cannot be read as more than it is:

| Mechanism | Prevents | Detects | Does not solve |
|---|---|---|---|
| Core issuance | over-issuance beyond the approved authority; issuance after revocation or expiry | the approved authority (anchored) | action-time misuse within scope |
| Runtime enforcement | an unauthorized action on a mediated path | each PDP/PEP decision (evidence) | actions on an unmediated path |
| Consent Evidence | silent divergence between what was shown and what was committed | the rendered disclosure | whether a human perceived or understood it |
| Audit Transparency | undetectable log tampering or omission (under expected registration) | the evidence timeline | a producer logging a false record |
| Mandate | reliance on unverifiable committed facts | portable Mission facts | authority (it grants none) |

The pattern is uniform: the family commits and checks what a party
was shown, decided, or did; it does not make the human attentive, the
producer honest, or the unmediated path disappear. Those are the
residues the Mission Assurance Levels ({{assurance-levels}}) and the security
model make a deployment state rather than assume, and the exposure
arm ({{capability-envelope}}) carries the same honesty in the other
direction.

## The Containment Matrix {#containment}

Mission termination is one control in a larger containment surface.
Each kill has a different blast radius, and an incident responder
needs the whole matrix:

| Control | Stops | Home |
|---|---|---|
| Capability kill | one capability's new derivation within one Mission, at once at commit; credentials already materialized under it run to their own bound ({{kill-switch-composition}}), and the body of work still runs | the issuer-held containment overlay ({{I-D.draft-mcguinness-oauth-mission-containment}}) |
| Mission kill | one body of work: new derivation at once, and residual credentials at the earliest of revocation, re-check, or their own expiry ({{validity-model}}) | the OAuth binding's revocation; cascades to Child Missions ({{I-D.draft-mcguinness-oauth-mission-child-delegation}}) |
| Agent kill | all work by one agent, across its Missions | the deployment's agent IAM ({{three-objects}}) |
| Agent Deployment kill | every instance running a compromised version | the deployment's change governance ({{three-objects}}) |
| Credential kill | credentials already issued | the binding's substrate, where it supports revocation; otherwise expiry ({{validity-model}}) |
| Workload kill | the running compute itself | the platform |
| Egress kill | the communication path | gateway and network controls |

Mission termination participates in incident response; it does not
replace it. Revoking the Mission stops issuance at once and stops
mediated actions within the staleness bound ({{validity-model}}),
but it terminates no process and closes no network path. The
converse holds too: killing a workload leaves the Mission `active`
and its authority derivable to a replacement instance unless the
Mission is also revoked.

Capability kill claims one of two properties, and which one tracks
the deployment's assurance level
({{I-D.draft-mcguinness-oauth-mission-containment}}): at Baseline
Issuance, a new-derivation kill, gating derivations minted after the
transition and propagating to Child Missions justified by the
contained entry, while a cross-domain grant already redeemed or an
offline attenuation root already minted before the transition keeps
its own bounded lifetime, exactly as the credential-kill row's
residual does; at Runtime-Enforced and above, an action-time kill
that additionally reaches a token issued before the transition,
bounded by the state source's staleness plus the permit and
execution windows.

A deployment's incident runbook names which of these controls exist,
who may pull each, and which capability-kill property its own
assurance level claims.

# Mission Requirements {#requirements}

The requirements the family answers are stated implementation-neutrally;
each names its answering documents by short form ({{document-map}}).
They stand on their own as a checklist, but conformance is capability-
layered rather than measured by resemblance to the OAuth wire model
({{I-D.draft-mcguinness-mission-substrate}}).

A design provides the shared **Mission Context** capabilities when the
first four properties, a compact restatement of the substrate
contract's kernel ({{I-D.draft-mcguinness-mission-substrate}}), hold:

1. **An approved task context**: the task is durable and explicitly
   approved rather than only a session or token.
2. **Stable binding and integrity**: a native reference binds the
   controlling authority, acting actor, and immutable approved context,
   or a verifiable commitment to that context, and propagation or
   correlation rules carry the reference across parties without
   conferring authority.
3. **Lifecycle gate with a reliance bound**: only an active context
   supports new governed decisions at the binding's declared control
   point, and no decision or artifact outlives both its stated bound
   and the transition that ends the context.
4. **Governance history**: decisions and interactions are correlated to
   the stable reference in an ordered audit or governance record.

Two further properties are separately claimable capabilities, not
one bundle: the second requires the first, and a design can hold the
first alone ({{I-D.draft-mcguinness-mission-substrate}}):

5. **Structured Authority**: credentials or decisions carry
   authority that an identified enforcement point can evaluate.
6. **Monotonic Derivation**, available only where Structured
   Authority holds: derived and delegated authority only narrows,
   and widening requires a fresh approval or a drawdown already
   bounded by an approved ceiling.

A design provides **Runtime-Enforced Mission** capabilities when,
over a State-Observable source with a stated staleness bound, two
further properties hold:

7. **Per-action runtime enforcement**: consequential actions are
   checkable against the object at the point of use.
8. **Decision accountability, growing to a joined record**: every
   gated action yields Decision Evidence joined on the object's
   identity. What was shown requires Consent Evidence and what was
   done requires Execution Evidence for the covered classes; with
   those adopted, what was approved, shown, decided, and done is
   reconstructible from the join.

AAuth supplies the first four natively (its `expires_at` member
carries the reliance bound), with its lifecycle gate scoped to PS
endpoints and PS-mediated paths carrying the validated reference. The OAuth binding
supplies both authority capabilities as well. Runtime and portable
evidence remain separately claimed capabilities; the requirements below
unpack the family mechanisms without implying every binding implements
every one.

## Context and Intent {#req-context}

- **R1**: The task an agent pursues is a durable, structured,
  approved object (oauth-mission; mission-authority-server).
- **R2**: The task and its derived authority are integrity-committed
  at approval, reproducible from the record alone (oauth-mission).
- **R3**: Task proposals are untrusted input: fields the agent can
  influence select and narrow what derivation considers, and can
  request gates the issuer enforces, but never grant or widen
  authority by their own assertion (oauth-mission; mission-shaping).

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

- **R8**: New reliance is gated on task state: only `active` permits
  a new governed decision, unrecognized states fail safe, and an
  already-issued artifact ends at its bounded residual
  (oauth-mission).
- **R9**: Revocation is independent of credential possession, and
  state changes propagate by pull or push (oauth-mission;
  oauth-mission-status; oauth-mission-signals).
- **R10**: A task can be suspended and resumed without being
  terminated (oauth-mission-status).
- **R11**: Authority widens only through a fresh approval that
  creates a successor (oauth-mission-expansion).
- **R12**: Authority retires per entry when the work an entry served
  is done (oauth-mission-status).

## Delegated, Projected, and Enforced Execution {#req-execution}

- **R13**: Derived and delegated authority only narrows
  (oauth-mission; oauth-mission-attenuation).
- **R14**: Sub-agents receive authority by explicit delegation with
  lineage, fan-out control, and cascade revocation, never by session
  ancestry (oauth-mission-child-delegation).
- **R15**: Each consequential action is checked at the point of use,
  the permit bound to the concrete parameters (mission-runtime;
  mission-authzen).
- **R16**: When a task stops, governed work stops with it, and
  in-flight work is classified, then suppressed or cancelled where
  possible, compensated where authorized, or escalated; irreversible
  and unknown outcomes remain (mission-harness;
  mission-orchestration).
- **R17**: Task evidence is tamper-evident and verifiable outside the
  deployment (mission-audit; mission-mandate).
- **R18**: Two distinct cross-domain properties, never one: a
  Mission's authority is honorable in another trust domain without
  widening, through the projection grant
  (oauth-mission-cross-domain); and a Mission's committed facts are
  verifiable there without a session with the issuer, granting
  nothing (mission-mandate).
- **R19**: Delegation history follows authorization continuity, never
  organizational topology. A Child Mission, an Expansion successor,
  or any fresh approval starts a new approval basis and actor chain;
  topology alone neither restarts nor extends one. Representation is profile-specific:
  issuer-mediated delegation nests `act`; holder-mediated attenuation
  reconstructs history from per-hop actors; and cross-domain
  projection carries no upstream `act` chain, so any
  destination-domain chain begins locally. Actor identity is
  attribution and policy input; it does not itself grant or prove
  authority (oauth-mission; oauth-mission-child-delegation;
  oauth-mission-expansion; oauth-mission-attenuation;
  oauth-mission-cross-domain).

# Mission Document Map {#document-map}

One row per document, grouped as the family groups them; the short
form drops the `draft-mcguinness-` prefix, and the repository's
DRAFTS.md is the full catalog with maturity and adoption metadata.
The naming encodes a boundary: profiles extending the Authorization
Server's own surfaces keep "oauth" in their names; profiles defined
against the substrate of {{substrate}} are named without it. This
document is named without it because the architecture is
substrate-neutral by construction.

Maturity is a dependency boundary. A Standards-Track profile never
depends normatively on an experimental one: the experimental
profiles extend the stable interface only through its declared
seams, the `controls` extension of the OAuth binding and the
coordinated-extension rules of the evidence objects, and a
Standards-Track document cites them informatively at most. An
experimental profile that stabilizes crosses the boundary by
reclassification, not by a stable document absorbing a dependency.

Within Lifecycle, Status is the OAuth lifecycle suite's root
document, with Signals (the push channel) and Management (the
operator plane) as its satellites; AAuth keeps its native two-state
lifecycle, served by `mission-aauth-management`, with the expiry
bound profiled by `aauth-mission-expiry`.

**Architecture mappings:**

| Document | Role |
|---|---|
| `mission-aam` | Experimental sketch. Cloudflare's Agent Access Model realized on the family: the six AAM components map onto issuance, the PDP, the mediated harness, Containment, Mission Templates, and the evidence join, and the grant review loop is deliberately not adopted. It defines no binding and no new mechanism. |

**The substrate and the bindings:**

| Document | Role |
|---|---|
| `oauth-mission` | The OAuth binding, its OAuth companions' issuance profile: the OAuth realization of the Mission, the approval event and anchors, the `mission` claim, the subset rule, state-gated issuance. |
| `mission-authority-server` | The standalone Mission Issuer and the PDP join of ordinary credentials to Missions. |
| `oauth-mission-issuance-grant` | The issuance join: MAS-minted grants an estate Authorization Server redeems at its token endpoint for Mission-bound, state-gated tokens. |
| `mission-aauth` | The AAuth Mission Context binding: the Person Server as controlling authority, the exact-byte mission blob under AAuth's `s256` commitment, native `{approver, s256}` propagation, and active-state gating on PS endpoints and the PS-asserted and federated paths. It defines no OAuth Authority Set or additional AAuth wire members. |
| `mission-uma` | Experimental sketch. The UMA 2.0 binding: the pushed Mission Intent rides claims pushing, the resource owner's decision fills UMA's authorization assessment, the RPT is the Mission-bound credential, and the PCT is continuity that is never authority; the first binding authored against the substrate contract. |
| `mission-gnap` | Experimental sketch. The GNAP binding: the Mission Intent rides a registered grant request member, interaction or a companion-supplied standing basis is the approval event, grant modification splits into in-Mission drawdown and Approver-routed expansion, and the continuation access token is continuity that is never authority; the second binding authored against the substrate contract. |
| `mission-substrate` | The binding-neutral kernel contract: normative on any further binding, conformed to by the existing bindings through their published Substrate Statements, with vocabulary ownership migrating to it by touch. |

**Approval time:**

| Document | Role |
|---|---|
| `mission-shaping` | Client-side shaping of a user's request into a candidate Mission Intent, as untrusted proposal. |
| `oauth-mission-consent-evidence` | The `consent_rendering_hash` anchor and signed evidence of what the Approver was shown, with the translation floor and Disclosure Interrogation that keep the approval surface readable and questionable. |
| `oauth-mission-approval` | Asynchronous approval over the deferred substrate. |
| `mission-approval-governance` | The Approval Governance Record: authenticated, event-bound, policy-authorized assertions standing behind an approval decision, committed atomically with Mission activation and immutable once signed. |
| `oauth-mission-approval-revision` | Experimental: in-review narrowing revision of a deferred proposal. |
| `oauth-mission-template` | Experimental: one consent to a task template's ceiling; each dispatch instantiates an ordinary Mission from it by policy, at machine speed, bounded by its own derived Authority Set and never exceeding the ceiling. |

**Lifecycle:**

| Document | Role |
|---|---|
| `oauth-mission-status` | The signed pull surface and the lifecycle endpoint, with `suspended` and `completed`, and per-entry discharge via the `terminal_when` constraint. |
| `oauth-mission-signals` | A signed event per lifecycle transition, push or poll. |
| `oauth-mission-expansion` | Widening through an approved successor Mission. |
| `oauth-mission-containment` | Event-triggered, monotonic narrowing of a live Mission's effective authority, with restoration only through an approved successor. |
| `oauth-mission-progressive` | Experimental: policy-adjudicated expansion within a pre-consented ceiling. |
| `mission-discovery` | Experimental: the open-world encounter as a governed operation: identity pinning, ceiling and contextual adjudication with the lying-resource and tainted-session floors, Discovery Evidence. |
| `oauth-mission-management` | Fleet enumeration and bulk lifecycle operations for operators and incident response; dry-run-first, per-Mission semantics. |
| `mission-aauth-management` | AAuth-native status, permanent termination, optional expiry, and delegation-tree queries at the Person Server, keyed only by `{approver, s256}` and preserving AAuth's `active` and `terminated` states. |
| `aauth-mission-expiry` | Profile of AAuth's `expires_at` mission lifetime bound (RFC 3339 precision, skew documentation, prompt termination). The base protocol enforces the bound on every Person Server decision path and caps every token carrying `mission_s256`; the AAuth binding requires the member on every mission. |

**Cross-domain projection and continuity:**

| Document | Role |
|---|---|
| `oauth-mission-cross-domain` | Single-hop projection of a Mission to another trust domain via the cross-domain grant. |
| `oauth-mission-cross-org-delegation` | Recursive cross-organizational delegation as a profile of offline attenuation: the chain is the portable authority proof, each hop names its own actor under the identity-binding rule, and projection turns a verified chain into a local token. |
| `oauth-mission-continuation` | The authorization-continuity profile: a Mission continues its authorization over identity-continuity transports (Identity Continuation, async delegation, cross-domain), state-gated, with the invariant that a continuation handle grants nothing. |
| `oauth-id-continuation-assertion` | A continuation transport: a short-lived token-exchange subject token yielding an ID-JAG for an intra-domain hop, bound to a Mission's authorization by mission-continuation. |

**Runtime enforcement:**

| Document | Role |
|---|---|
| `mission-runtime` | The per-action decision contract: parameter binding, custody, fail-closed behavior. |
| `mission-authzen` | The concrete decision-API binding: the AuthZEN request and response mapping and the denial classification. |
| `mission-runtime-evidence` | The binding-neutral Decision Evidence, Execution Evidence, and Refusal Record objects a decision-API binding's PDP and PEP emit, their integrity envelope, and retention. |
| `mission-metering` | Experimental: cumulative consumption bounds and the metering that enforces them. |
| `oauth-mission-transaction-authorization` | Experimental: the transaction authorization challenge profiled for the cross-domain case, minting a single-use action-bound token after a fresh decision with a governed approval as input. |

**Agent runtime:**

| Document | Role |
|---|---|
| `mission-harness` | Binding sessions, queues, and sub-agent handles to Mission state; the mediated environment. |
| `mission-capability-binding` | Binds an approved catalog-sourced entry (an MCP tool, an OpenAPI operation) to its capability source at derivation and refuses on drift at decision time, with the AuthZEN MCP profile's (COAZ) mapping for MCP deployments. |
| `mission-orchestration` | Experimental: reversibility classes, unwind plans, and compensation after a stop. |

**Sub-agents:**

| Document | Role |
|---|---|
| `oauth-mission-child-delegation` | Child Missions with lineage, strict-subset authority, cascade revocation. |
| `oauth-mission-attenuation` | Experimental: narrower Mission-bound tokens minted offline; the kill switch preserved by runtime re-check. |

**Proof and portability:**

| Document | Role |
|---|---|
| `mission-mandate` | A signed, portable statement of a Mission's committed facts; evidence, not a credential. |
| `mission-audit` | Registration of Mission evidence in a SCITT Transparency Service; receipts verifiable offline. |

**Security model:**

| Document | Role |
|---|---|
| `oauth-mission-work-products` | Experimental: work-product provenance, attribution and not authority, and the non-transitive Mission-to-Mission handoff rule; a work product crossing into a Mission is input, re-evaluated under the receiver's Authority Set. |
| `mission-security-model` | The trusted base in one view: what each component must achieve and what its compromise costs. |

# Security Considerations {#security-considerations}

This document defines no wire mechanism; each profile's own Security
Considerations remain normative, and the consolidated trusted base
and compromise analysis are the Mission Security Model's
({{I-D.draft-mcguinness-mission-security-model}}). What this
document does introduce is composition, and the risks that emerge
only at composition are its security subject matter:

- stale state and materialized authority: an already-issued
  credential, redeemed grant, or minted attenuation root stays
  usable to its artifact-specific bound only where no timely
  state-aware or action-time gate reaches it; where one does,
  reliance ends at that earlier gate ({{validity-model}},
  {{kill-switch-composition}});
- unmediated paths: enforcement claims hold only inside the declared
  PEP boundary, and the Enforcement Scope Statement's exclusions are
  where a compromised agent goes first;
- semantic-derivation trust: the derivation boundary
  ({{derivation-boundary}}) concentrates meaning-to-authority
  translation at the issuer, and the anchors commit its output, not
  its correctness;
- component compromise: issuer, PDP, PEP, state source, and evidence
  producer each void a different guarantee when compromised, and the
  security model prices each;
- context splicing and join ambiguity: independently valid identity,
  credential, and Mission facts compose into an unauthorized whole
  wherever they are combined without an authorized joining
  authority, verified inputs, an association policy, and conflict
  handling ({{I-D.draft-mcguinness-mission-substrate}});
- false but correctly signed evidence: signatures make records
  tamper-evident, never true; and
- correlation: the Mission Identifier, actor chain, and evidence
  joins that make audit possible are the same joins that correlate
  activity across audiences ({{privacy-considerations}}).

# Privacy Considerations {#privacy-considerations}

The privacy properties of the Mission record and the Mission Intent
are the OAuth binding's ({{I-D.draft-mcguinness-oauth-mission}}) and each
adopted profile's; this document describes them and adds no data
element of its own. The OAuth binding's Privacy Considerations
cover Mission
Identifier correlation, token payload disclosure, and Intent
retention, with the audit profile's erasure record as the
transparency-side mechanism
({{I-D.draft-mcguinness-mission-audit}}). The status profile's
anti-oracle property bounds what its status surfaces disclose
({{I-D.draft-mcguinness-oauth-mission-status}}).

Read across profiles rather than per document, the dataflow
concentrates in three places: the record and its evidence at the
issuer (task prose, principals, authority, provenance); the decision
and execution evidence joined on the Mission Identifier at the
runtime and audit layers; and the correlation surface that
identifier creates wherever it travels (tokens, status responses,
evidence, receipts, the Mandate). Minimization therefore has one
shape everywhere: audience-scope what each party receives, prefer
audience-scoped references over content (a stable reference reused
across audiences is itself a correlation surface), and let the
record's access governance, not possession of a reference, decide
who reads the concentrated view.

The AAuth binding's privacy posture is its own
({{I-D.draft-mcguinness-mission-aauth}}): the private mission blob
never leaves the agent and the Person Server, the stable
`{approver, s256}` reference is a correlation handle across every
resource that sees it, and the mission log concentrates a detailed
activity history at the Person Server, with the binding's
minimization and retention duties applying there.

# IANA Considerations {#iana}

This document makes no IANA request.

--- back

# Document History {#document-history}

\[\[ To be removed from the final specification ]]

- Editorial density pass on this Informational document: the
  aggregate-ceiling and artifact-plane (non-transitive work-product)
  composition readings under {{invariants}} tightened to a summary
  sentence plus citation each, with their "not this summary, is the
  normative text this passage tracks" deferral kept; several
  over-long paragraphs in {{capability-envelope}}, {{validity-model}},
  {{assurance-levels}}, and {{containment}} split for one idea per
  paragraph and front-loaded openers. No normative content, anchor,
  or table row changed.

# Acknowledgments
{:numbered="false"}

This document is part of the Mission-Bound Authorization work and
maps the structure that its profiles establish individually.
