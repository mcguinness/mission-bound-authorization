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
  I-D.draft-ietf-oauth-rar-metadata-remediation:
  RFC9728:
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
  I-D.draft-mcguinness-oauth-client-instance-id:
  I-D.draft-mcguinness-oauth-client-attesters:
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
  I-D.draft-zhu-oauth-async-delegation:
  I-D.draft-mcguinness-oauth-mission-continuation:
    title: "Mission Continuation for OAuth 2.0"
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
  I-D.draft-mcguinness-oauth-mission-approved-set-verification:
    title: "Mission Approved-Set Verification for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-approved-set-verification.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-oauth-mission-resource-access:
    title: "Mission Resource Access Profile for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-resource-access.html
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
    title: "Mission-Bound Authorization for User-Managed Access (UMA) 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-uma.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-mission-gnap:
    title: "Mission-Bound Authorization for the Grant Negotiation and Authorization Protocol (GNAP)"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-gnap.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-hardt-oauth-aauth-protocol:
    title: "AAuth Protocol"
    author:
      -
        ins: D. Hardt
        name: Dick Hardt
    date: 2026-09-25
    seriesinfo:
      Internet-Draft: draft-hardt-oauth-aauth-protocol-11
  I-D.draft-hardt-aauth-r3:
    title: "AAuth Rich Resource Requests (R3)"
    author:
      -
        ins: D. Hardt
        name: Dick Hardt
    date: 2026-09-28
    seriesinfo:
      Internet-Draft: draft-hardt-aauth-r3-00
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
  I-D.draft-mcguinness-oauth-mission-status-list:
    title: "Mission Status List for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-status-list.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-oauth-mission-discharge:
    title: "Mission Entry Discharge for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-discharge.html
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
    title: "Mission Work Products for OAuth 2.0"
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
  I-D.draft-mcguinness-oauth-mission-derivation-limits:
    title: "Mission Derivation Limits for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-derivation-limits.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-oauth-mission-submission-evidence:
    title: "Mission Intent Submission Evidence for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-submission-evidence.html
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
authority. It exists because the authority an Approver consents to is
a capability envelope, not a task script, and the gap between that
envelope and what a run actually does is where agent risk lives; the
family's mechanisms exist to narrow that gap. Read as one system, the
Mission model defines a delegated-authority layer: authentication says
who is acting, and entitlement governance says what a principal may
hold; this layer governs the approved task itself. This document is
the structural view: the object and its invariants, a Mission's life
end to end, the roles and substrate, the verb spine the profiles
form, the deployment patterns, the assurance levels a deployment
claims, and the requirements the family answers. It is Informational:
it defines no protocol, object, or requirement, and every mechanism
it names is defined by the profile it points to.

--- middle

# Introduction

A Mission is a durable governance object created by an explicit
approval event: the approved task, with a lifecycle. The Mission is
not a new way to express authority: Rich Authorization Requests
{{RFC9396}} and kindred mechanisms express authority, and the Mission
is the approved task that authority serves. In the authority-bearing
bindings, authority for the task is derived for the Mission, bound to
it, and gated on its state.

The object fills a gap that deployments pay for daily. An estate that
cannot size authority to a task compensates with read-only scoping, a
human executing every write, or permanently fenced pilots; the Mission
is the representation those controls substitute for.

What the family standardizes is agreement across components.
Independently implemented components, under a declared binding and the
deployment's declared mappings, preserve the same approved task
context, narrowing rules, lifecycle meaning, and provenance. Inside one
administrative domain a conventional stack implements much of this
locally ({{standardization-crossovers}}); each deployment still
configures its bindings, mappings, and the trust between components.

The model is decomposed into bindings and optional companions. The
bindings are these:

- The OAuth binding (the "issuance profile" to its OAuth companions,
  {{I-D.draft-mcguinness-oauth-mission}}) defines the object and its
  OAuth 2.0 {{RFC6749}} realization.
- A standalone binding hosts the same object without changing an
  existing Authorization Server
  ({{I-D.draft-mcguinness-mission-authority-server}}).
- An AAuth binding ({{I-D.draft-mcguinness-mission-aauth}}) maps the
  shared approval, reference, lifecycle-gate, and log capabilities onto
  the native Mission Context of AAuth
  ({{I-D.draft-hardt-oauth-aauth-protocol}}) without importing the OAuth
  Authority Set. There, the Mission Context instead governs resource
  decisions at the Person Server (PS) without becoming their authority
  language.
- UMA 2.0 and GNAP bindings exist as experimental sketches
  ({{components}}).

The bindings are peers: each attaches to its own protocol as an
equally adoptable unit and declares what it supplies. What peer
standing implies, and how the bindings differ, is stated once with the
binding architectures ({{binding-architectures}}).

Optional companions layer approval, lifecycle, enforcement, runtime,
delegation, and proof capabilities on top. The decomposition keeps
each interface small but spreads the structure across many documents
and several bindings; this document is the single structural view.

This document is Informational. It defines no protocol, mechanism,
requirement, conformance class, or wire format. It does define
descriptive vocabulary that other documents cite: the assurance levels
and claims ({{assurance-levels}}) and the binding properties
({{binding-properties}}), whose `credential-mission-bound` property
defines what earns the Mission-bound token class ({{token-classes}}).
Material marked illustrative (the worked composition, the Deployment
Profile shapes, and the verification scenarios) shows one way to apply
the model and fixes nothing. Every other passage summarizes rules owned
by the documents it cites; where a summary and its owning profile appear
to differ, the profile governs.

This document describes components, interfaces, and data flows; the
Mission Security Model
({{I-D.draft-mcguinness-mission-security-model}}) describes the
trusted base and how each component's compromise degrades the
guarantees. Each profile's own Security Considerations remain
normative over both.

## Map of This Document {#map}

The body reads in four parts, followed by appendices:

- **The model** comes first: a Mission's life end to end
  ({{mission-life}}); the Mission ({{the-mission}}), with its approval
  and lifecycle ({{approval-and-lifecycle}}), authority path
  ({{mission-authority-path}}), delegated-authority layer
  ({{delegated-authority-layer}}), capability envelope
  ({{capability-envelope}}), and survivable incorrectness
  ({{survivable-incorrectness}}); what the family does not do
  ({{non-goals}}); the roles ({{components}}); the verb spine that
  organizes every mechanism ({{layers}}); the invariants
  ({{invariants}}); and who owns meaning and who commits authority
  ({{meaning-and-derivation}}).
- **The substrate and the bindings** follow ({{substrate}}): the
  binding-neutral kernel, the validity model ({{validity-model}}),
  and how the bindings differ ({{binding-architectures}}).
- **Assurance** ({{assurance-levels}}) covers what a deployment
  adopts ({{assurance-level-definitions}}), what it can prove
  ({{assurance-claims-axis}}), how its paths are bound
  ({{binding-properties}}), and what a kill reaches ({{containment}},
  {{kill-switch-composition}}).
- **Deployment** ({{deployment}}) covers entry ramps
  ({{entry-ramps}}), patterns, and the Deployment Profile
  ({{deployment-profile}}).
- **The appendices** hold the requirements the family answers
  ({{requirements}}), a comparison with a conventional stack
  ({{standardization-crossovers}}), a worked composition
  ({{worked-composition}}), the error surfaces ({{error-surfaces}}),
  illustrative verification guidance ({{verification-guidance}}), the
  Deployment Profile shapes ({{deployment-profile-examples}}), and the
  document map ({{document-map}}). DRAFTS.md in the repository is the
  full catalog.

Readers with one goal can start on a shorter path:

- New to Missions: {{mission-life}}, {{the-mission}}, and {{layers}}.
- Choosing what to deploy: {{assurance-levels}} and {{deployment}}.
- Writing or assessing a binding: {{substrate}}, {{binding-properties}},
  and {{requirements}}.
- Reviewing security: {{invariants}}, {{containment}}, and
  {{security-considerations}}.

# Conventions and Terminology {#conventions}

Where this document uses words like "must" or "should," they carry
their ordinary English meaning and describe what a referenced profile
establishes, not a requirement this document places.

Other documents define these terms:

- Binding-neutral Mission terms (the Mission Context, the Mission
  Reference and Controller, the approved context, the approval event,
  the governance gate, bounded reliance, and the named substrate
  capabilities): the substrate contract
  ({{I-D.draft-mcguinness-mission-substrate}}).
- The transition classification, including `decide_anew`: the
  substrate contract ({{I-D.draft-mcguinness-mission-substrate}}).
- Terms of the OAuth realization (Mission Intent, Authority Set,
  integrity anchors, and Mission Issuer): the OAuth binding
  ({{I-D.draft-mcguinness-oauth-mission}}).
- Policy Enforcement Point (PEP), Policy Decision Point (PDP),
  consequential action, the high-consequence classes, and the
  Enforcement Scope Statement: the runtime profile
  ({{I-D.draft-mcguinness-mission-runtime}}).
- Effective Authority Set: the status profile
  ({{I-D.draft-mcguinness-oauth-mission-status}}).
- Mission Authority Server (MAS):
  {{I-D.draft-mcguinness-mission-authority-server}}.
- The AAuth binding: {{I-D.draft-mcguinness-mission-aauth}}.

A passage that uses the OAuth realization's terms describes that
realization or a binding that adopts it. No binding is the default
reading of a passage that does not name one.

# A Mission's Life {#mission-life}

Under the OAuth binding, an operator gives an agent the task
"reconcile Q3 invoices," and one Mission carries it end to end:

1. **Propose.** The client shapes the request into a structured
   Mission Intent, untrusted by construction, and submits it in a
   Pushed Authorization Request {{RFC9126}}, optionally proposing
   concrete authority on the standard `authorization_details`
   parameter ({{I-D.draft-mcguinness-mission-shaping}}; the OAuth
   binding).
2. **Approve and record.** The Authorization Server derives and
   discloses an Authority Set (read invoices, post adjustments under
   a cap), and the Approver approves. The approval event creates the
   Mission, `active` with an expiry, and commits `intent_hash`,
   `authority_hash`, and, where a proposal was submitted,
   `proposal_hash`; Consent Evidence commits what was shown
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
   ({{I-D.draft-mcguinness-oauth-mission-discharge}}).
7. **Stop.** Revocation or expiry turns every gate: issuance refuses
   at once, the PDP denies within its state source's staleness bound,
   the harness pauses bound sessions and queues, and the orchestrator
   unwinds in-flight work
   ({{I-D.draft-mcguinness-mission-harness}},
   {{I-D.draft-mcguinness-mission-orchestration}}); a token no
   state-aware gate reaches runs to its own expiry
   ({{validity-model}}). Mediated actions under a permit already issued
   stop within the staleness bound plus the permit window and the
   class's execution bound ({{I-D.draft-mcguinness-mission-runtime}}).
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

Under the standalone binding the same life runs with ordinary tokens and
the Mission Join in place of step 3's claim carriage; there, revocation
stops nothing at the token layer, and runtime enforcement is the only
cutoff ({{binding-architectures}}). In sequence, the standalone mode
runs submit, approve, poll, join, permit:

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

Under the AAuth binding, the Person Server instead governs the native
Mission Context through propose, clarify, approve, and the mission log;
it does not emulate the AS's Authority Set, integrity anchors, PDP
permits, Child Missions, or portable evidence
({{binding-architectures}}, {{assurance-levels}}).

# The Mission {#the-mission}

OAuth 2.0 standardizes authorization. An access token represents
authorization granted to the client, for a delegating user or on the
client's own behalf, and can serve many requests; a deployment may
retain durable grant or consent state behind it. What OAuth does not
standardize is an independently addressable, lifecycle-bearing
approved-task object: an artifact whose semantics persist across
tokens, actors, audiences, and evidence.

That gap matters for AI agents. Given a mission (book the trip,
reconcile the ledger), an agent takes many actions across many
resources over a long time, spawning sub-agents and surviving
restarts. Independently issued tokens cannot express the approved
task, its boundary, or its end (the OAuth binding's Introduction).

The family separates the task from the authority. The authorization
flow separates four objects:

- the Intent: proposed work, inert until approved;
- the Mission: the approved, governed work;
- the Authority derived for it; and
- each Action that uses it.

Lifecycle cuts through the last three. In the OAuth model, the
Authority Set is the concrete authority (resources, actions,
constraints) derived for the Mission.

## Approval and Lifecycle {#approval-and-lifecycle}

In every binding, an explicit approval event creates the Mission and
commits its approved context, or a verifiable commitment to it, and
the Mission's Controller then owns its state. In the OAuth binding, a
client proposes a Mission Intent, and may propose concrete authority
alongside it; the Mission Issuer derives an Authority Set; and the
approval event commits both.

In the OAuth binding, the commitment is the integrity anchors:

- `intent_hash` over the approved Mission Intent;
- `authority_hash` over the consented Authority Set; and
- where the client submitted an authority proposal, `proposal_hash`
  over the submitted `authorization_details` array.

Each anchor is computed over a domain-separated, issuer-bound envelope
with fixed canonicalization, so an auditor can reproduce each digest
from the record alone (the OAuth binding's Mission Approval, Integrity
Anchors, and Canonicalization Rules sections). The record is immutable
except for its state (the Mission Record section).

In the OAuth binding the lifecycle states are `active`, `revoked`,
and `expired`, and only `active` permits issuance or a new positive
governance decision. A non-active state stops further derivation and
refresh at once. A credential already issued ends at the earliest of an
applicable revocation, a state-aware or runtime check that reaches it,
or its own expiry ({{validity-model}}).

Companions add states (`suspended`, `completed`, `superseded`,
`cascaded`). One rule keeps these additions safe without a registry: a
consumer treats every state other than the exact value `active`,
including one it does not recognize, as non-active, so an unrecognized
state fails safe (the OAuth binding's Mission Lifecycle and Gating
section).

AAuth has its own counterparts to the OAuth commitment and lifecycle.
Its exact-byte `s256` commits the private approved mission blob. The
approving PS and `s256` are the Mission Reference, AAuth's mission
identity (Section 8.2.1 of {{I-D.draft-hardt-oauth-aauth-protocol}}).
On the wire the reference is the `mission_s256` claim or parameter.
The blob carries no member naming the PS: a person token names it by
`iss`, a resource or auth token by `ps`, and a request by its
destination.

In AAuth, the PS applies contextual governance using that blob and the
ordered mission log; scopes, resource tokens, Resource and Access
Server policy, and optionally AAuth Rich Resource Requests
(R3, {{I-D.draft-hardt-aauth-r3}}) carry deterministic resource
authorization. AAuth does not add the OAuth Authority Set or its two
anchors, and its native lifecycle remains exactly `active` or
`terminated`.

## The Authority Path {#mission-authority-path}

In OAuth's names, authority moves along one path from the approval
event to an action, and no stage holds more than the stage before it:

~~~
 approval basis
       |
       | adjudication
       v
 approval event
       |
       v
 Approved Authority Set (anchored, immutable)
       |
       | containment, discharge: subtract only
       v
 Effective Authority Set --child creation--> new approval event
       |               |                     for a Child Mission
       | derivation:   |
       | subset rule   | current set
       v               |
 derived credential    |
       |               |
       v               v
 runtime decision, where deployed
 (with action parameters and lifecycle state)
       |
       v
 action
~~~
{: #authority-path title="The authority path, in OAuth's names"}

{{authority-transitions}} places each mechanism on this path.

The lifecycle gate sits beside the path, not on it: only `active`
permits issuance, refresh, and a new positive governance decision, and
`resume` reopens a suspended Mission's gate without changing either set
({{I-D.draft-mcguinness-oauth-mission-status}}). Widening and
restoration never happen in place; a new approval event creates a
successor ({{I-D.draft-mcguinness-oauth-mission-expansion}}).

The runtime decision takes the current Effective Authority Set as its
own input, so narrowing applied after issuance binds there
({{I-D.draft-mcguinness-mission-runtime}}). Where no runtime decision
is deployed, a resource relies on the credential alone, and the
materialized-credential residual remains ({{validity-model}}).

## The Delegated-Authority Layer {#delegated-authority-layer}

This family defines a delegated-authority layer. It governs the
approved task a delegate performs on a principal's behalf: its
bounded authority, its lifecycle, the per-action check, and the
evidence that binds back to it. Authentication and token issuance
answer who is acting and what a single credential carries; governance
of standing entitlements answers what a principal should hold over
time. Neither governs that task. This layer composes with the layers
below rather than replacing them.

The Mission Authority Server
({{I-D.draft-mcguinness-mission-authority-server}}) is the layer's
binding-independent control plane across an estate, whichever party
issues a given token. Within the layer:

- the issuer side holds desired state (the record, its authority,
  its lifecycle and state version), reconciles it (gating, the
  ceiling review, evidence reconciliation), and distributes bounded
  authority (policy views, status, the management surface);
- tokens and the PEP/PDP boundary are the layer's data plane; and
- Status and Signals are the channel between the two.

The plane the layer governs is authority, never operations: how an
agent runs stays with the harness and the orchestrator.

Grouped as planes, the roles of {{components}} form this layer, with
the evidence surface crossing all of them:

~~~
 control       Mission control point (OAuth AS | MAS | AAuth PS |
               UMA AS | GNAP AS):
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

## The Capability Envelope {#capability-envelope}

A Mission commits its authority and intent once, at approval, but an
agent's work is open-ended: the actions a task will take are not known
when it is approved. "Reconcile Q3 invoices" must authorize reading
any invoice and posting any adjustment under the cap, because the
specific ones cannot be enumerated in advance.

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

In the OAuth binding, what approval commits is broader than the
structured Authority Set alone ({{I-D.draft-mcguinness-oauth-mission}});
it also commits:

- the rendered intent context (`goal`, `task_bounds`, and, where it
  differs, the requested ceiling);
- the effective `expires_at`; and
- the rendered `derivation_limit` and any metering bound
  ({{I-D.draft-mcguinness-oauth-mission-derivation-limits}},
  {{I-D.draft-mcguinness-mission-metering}}).

Concrete request values, current consumption, and action sequencing
are decision-time facts, evaluated later by runtime policy, metering,
or action-bound (transaction) approval. The OAuth binding does not
require them to be re-rendered to the original Approver, though
action-bound approval may re-render exactly that.

The lifecycle control gates new derivation from the envelope; a
credential already materialized under it keeps running to its own bound
unless an action-time gate reaches it first ({{validity-model}},
{{kill-switch-composition}}). Approval-time commitment and decision-time
checks compose but do not substitute: an envelope real at approval time
can still admit, at decision time, an effect the Approver never saw
rendered in that form.

Attribution has the same limit at task-item grain: proving which
concurrent task item produced a permitted action needs a verified
cross-link that no family carrier supplies ({{binding-properties}}).

## Survivable Incorrectness {#survivable-incorrectness}

The levers share one strategy: they convert semantic risk into
structural signals. A policy decision point is never asked to judge
whether content is harmful. Provenance (the harness taint context),
composition (the quarantine pattern), egress enumeration and volume
bounds, separation of duty, and re-consent turn that question into
facts a decision can gate on. A content evaluator a deployment adds
composes as Resource policy at the decision point and only ever
narrows.

The stance beneath the levers is **survivable incorrectness**: the
agent is probabilistic, so the family never bets on the model being
right and builds so that wrong is survivable, on two arms:

- The action arm is the capability envelope ({{capability-envelope}})
  and its levers, wire-backed, with in-flight work unwinding through
  recorded reversibility classes
  ({{I-D.draft-mcguinness-mission-orchestration}}).
- The input arm is **least exposure**: everything the agent sees can
  steer it and everything it holds can leak, so a Mission budgets
  disclosure as well as authority, and mediated custody generalizes
  from credentials to context.

The arms differ in maturity. The input arm's enforceable edges are
the harness taint rule, egress mediation, and catalog filtering
({{I-D.draft-mcguinness-mission-harness}},
{{I-D.draft-mcguinness-mission-runtime}},
{{I-D.draft-mcguinness-mission-authzen}}). Its interior (retrieval,
memory, and context assembly scoped to the Mission) has no
interoperable form and is deployment discipline, declared in the
Deployment Profile ({{deployment-profile}}) rather than claimed.

A bound makes an error survivable only along the dimension it meters.
A per-action cap, a cumulative budget, and a recipient list each bound
their own quantity; an incorrect run inside every bound can still cause
harm none of them measures, so staying within the authorized envelope
does not by itself make the harm tolerable. A deployment states which
harms its bounds cover and lists the rest as residuals
({{deployment-profile}}).

# Non-Goals {#non-goals}

The family does not define:

- **A new grant protocol.** Rich Authorization Requests {{RFC9396}} and
  kindred mechanisms already fill the authority-expression role, and the
  family leaves the grant exchange to them. It defines its own
  cross-resource `authorization_details` type only where {{RFC9396}}
  leaves type semantics to the type, in the OAuth binding's Mission
  Resource Access Profile
  ({{I-D.draft-mcguinness-oauth-mission-resource-access}}). The same
  restraint applies to GNAP and the capability-system lineage
  (macaroons, Biscuit, UCAN, object-capability narrowing): the family
  composes with deployed grant protocols and attenuation primitives
  rather than adding a competing one. The OAuth binding states the
  comparison ({{I-D.draft-mcguinness-oauth-mission}}).
- **A policy language.** The PDP evaluates the Mission's Authority Set,
  constraints, and state; how a deployment authors policy beyond them is
  local ({{I-D.draft-mcguinness-mission-runtime}}).
- **Entitlement governance.** What standing access a principal should
  hold over time belongs to existing governance layers; the
  delegated-authority layer composes with them
  ({{delegated-authority-layer}}).
- **Agent identity and deployment governance.** Who the agent is, its
  concrete instance, and its approved behavioral version belong to the
  deployment's agent IAM and change governance; the family authenticates
  against and consumes those facts without defining them
  ({{three-objects}}).
- **An agent framework.** The harness constrains the execution
  environment's relationship to Mission state; it does not say how an
  agent plans, reasons, or calls tools
  ({{I-D.draft-mcguinness-mission-harness}}).
- **Semantic derivation.** Whether a derived Authority Set is the right
  reading of the task is committed and auditable, not standardized
  ({{derivation-boundary}}).
- **Agent trustworthiness.** The family bounds what a compromised or
  injected agent can do; it does not make the agent trustworthy
  ({{I-D.draft-mcguinness-mission-security-model}}).

# Mission Roles and Components {#components}

The parties and components below take part in a Mission, and the
figure after them sets the bindings side by side. What each
component's compromise costs is the security model's subject
({{I-D.draft-mcguinness-mission-security-model}}).

Agent (client):
: Proposes the Mission Intent and executes the task. In the OAuth
  binding it holds derived Mission-bound tokens. It sits outside the
  trusted base and is assumed compromisable
  ({{I-D.draft-mcguinness-oauth-mission}}).

Subject:
: The user or system on whose behalf the Mission is approved, an
  (`iss`, `sub`) pair recorded immutably at approval (the OAuth
  binding). AAuth keeps the person's relationship and context at the
  PS and does not add this OAuth Subject tuple to the mission blob.

Approver:
: The single accountable principal who approves the Mission; equal
  to the Subject for self-approval (the OAuth binding's Single
  Accountable Approver section). In AAuth the approver is always the
  PS, not a portable person identifier, and the blob carries no member
  naming it; the person reviews and approves through that PS.

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
  - GNAP authorization server (experimental sketch): the Mission
    Intent rides the grant request as a registered member, the
    interaction or a standing basis is the approval event, and access
    token issuance and rotation are gated on state
    ({{I-D.draft-mcguinness-mission-gnap}}).

  The OAuth and standalone authority-bearing bindings also serve
  audience-scoped policy views, the authority-distribution artifact the
  runtime and MAS profiles define
  ({{I-D.draft-mcguinness-mission-runtime}},
  {{I-D.draft-mcguinness-mission-authority-server}}). The AAuth binding
  defines no such view from the mission blob; its deterministic
  resource authorization remains in scopes, resource tokens, Resource
  and Access Server policy, and optionally R3.

AAuth Person Server:
: The controlling authority for the native Mission Context rather than
  an OAuth-style Mission Issuer; AAuth's `s256` commits the mission
  blob. The PS gates three of AAuth's resource access modes, the
  **PS-gated modes** (person identity, PS authorization, and federated
  authorization). In person identity it gates person-token issuance
  but does not decide at the resource; PS authorization is
  three-party, and federated authorization four-party. It does not
  gate agent identity or resource-managed access (Section 4.2 of
  {{I-D.draft-hardt-oauth-aauth-protocol}},
  {{I-D.draft-mcguinness-mission-aauth}}).

Resource Server:
: The protected resource. In the OAuth binding it enforces
  statelessly from the token and can check the `mission` claim (the
  OAuth binding's Resource Server Enforcement section). In the
  standalone binding the token carries no Mission signal, and Mission
  properties reach it only through the enforcement path.

PEP and PDP:
: The PEP sits at the last controllable boundary before an action and
  obtains a permit for each consequential action. Under mediated
  custody it, not the agent, holds the sender-constraint key.

  The PDP evaluates the action against the Mission's authority,
  constraints, actor chain, and current state, and fails closed
  ({{I-D.draft-mcguinness-mission-runtime}},
  {{I-D.draft-mcguinness-mission-authzen}}). In the standalone
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
  +---------------------------------------------------------------+
  |                     Mission Control Point                     |
  | +-----------+-----------+-----------+-----------+-----------+ |
  | | OAuth AS: | Standalone| AAuth PS: | UMA 2.0 AS| GNAP AS   | |
  | | Mission-  | MAS: no   | Mission   | (sketch): | (sketch): | |
  | | bound     | tokens;   | Context;  | pushed    | Intent in | |
  | | tokens    | the PDP   | PS paths  | Intent;   | request;  | |
  | | gated on  | joins to  | gated     | RPTs gated| tokens    | |
  | | state     | Mission   |           | on state  | gated     | |
  | +-----------+-----------+-----------+-----------+-----------+ |
  +-------|-----------|-----------|-----------|-----------|-------+
          v           v           v           v           v
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

## The Actor Chain {#actor-chain}

One material action splits across the roles below. The family keeps
each distinct and attributable rather than collapsing them into one
"agent" identity. Each binding carries the same distinctions in its
own vocabulary; AAuth does so natively with its `agent` identifier,
the Person at the PS, `parent_agent` for a parent-mediated sub-agent,
and the call chain for a service hop
({{I-D.draft-mcguinness-mission-aauth}}). The entries below show the
OAuth binding's instantiation:

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
: the client the Mission Record records at approval (the OAuth
  binding).

Requesting client:
: `client_id` on each issued or derived token, naming the client that
  requested it, never the approved agent (the OAuth binding).

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
approved, how authority narrowed at each derivation, whether the task
remains `active`, or which parameter constraints bind. Those travel in
the Mission's own constructs: the anchors, the Authority Set, the
lifecycle state, and Child Mission lineage
({{I-D.draft-mcguinness-oauth-mission-child-delegation}}). Reading an
actor chain as authorization provenance is the gap the Mission's lineage
exists to close.

## Agent Identity, Agent Deployment, and Mission {#three-objects}

A deployment that runs agents under both an agent identity system and
this family governs three independently lifecycle-bearing objects,
separate from the authorization flow's four objects ({{the-mission}}).
Each has its own owner, lifecycle, and revocation, and the model stays
clean only while none absorbs another's job:

Agent identity (who is acting):
: The logical agent and, where client instance identification is
  deployed, the concrete instance. Owned by the deployment's agent
  IAM, a registry or directory outside this family, and consumed, in
  the OAuth binding, as the `client_id`, the client-instance
  attestation, and validated Instance Context.

  A deployment may authenticate concrete agent instances with client
  instance identification, which extends attestation-based client
  authentication
  ({{I-D.draft-ietf-oauth-attestation-based-client-auth}}), and endorse
  its attesters in client metadata
  ({{I-D.draft-mcguinness-oauth-client-instance-id}},
  {{I-D.draft-mcguinness-oauth-client-attesters}}). Doing so sharpens
  joins and evidence attribution to instance granularity without
  touching the Mission model. Instance evidence alone identifies no
  actor or delegate ({{I-D.draft-mcguinness-oauth-client-instance-id}},
  Section 5). SPIFFE workload credentials
  ({{I-D.draft-ietf-oauth-spiffe-client-auth}}) on their own convey no
  instance identity under that profile
  ({{I-D.draft-mcguinness-oauth-client-instance-id}}, Section 8.2).
  None of these mechanisms defines the Mission actor, delegation,
  intent, lifecycle, or evidence semantics defined here.

Agent Deployment (what is running):
: The approved behavioral version of the agent: its code, model,
  system prompt, tool allowlist, data scope, and runtime
  configuration. Owned by the deployment's change governance. A
  change to any of these is a new Agent Deployment; which changes
  require re-approving standing Missions is policy that governance
  records.

  A Mission may be pinned to a named Agent Deployment where a
  companion Agent Deployment Binding profile realizes that pin;
  {{I-D.draft-mcguinness-oauth-mission}} names the profile and its
  required properties but defines none of its wire mechanics itself.
  An Agent Deployment is distinct from the Mission Deployment Profile
  ({{deployment-profile}}), the estate's published claims manifest,
  not a property of an agent.

Mission (why the authority exists):
: This family's object: the approved task, its lifecycle, and, where
  the binding derives one, its Authority Set.

An agent registry is a complementary dependency, not part of the
Mission system; an A2A AgentCard directory ({{A2A}}) is one example
source. Where one exists, the Mission Issuer and the PDP consume a
small, stable slice of it:

- the agent identifier and its owner,
- current status and revocation state,
- the approved Agent Deployment,
- eligibility bounds (what the registry permits the agent to be
  approved for, a derivation input, never a grant), and
- risk tier.

Discovery contents are not authority for workload identity,
authorization, or effective capabilities: a deployment applies local
admission policy and independently verifies the relevant credential,
resource metadata, and capability evidence.

Registry state is a state source like any other: the consuming
decision point treats it under the runtime profile's freshness
discipline, with a declared staleness bound, failing closed when it
cannot be established ({{I-D.draft-mcguinness-mission-runtime}}).

Authorization composes conjunctively across these lifecycles and the
credential's own: a decision may depend on agent state, Mission state,
and credential validity, and each gates independently. A valid
credential never overrides a revoked agent or a non-active Mission, and
a live agent under an active Mission still fails on an expired
credential.

Binding strength accumulates as a deployment adds it:

- authority is issued to an authenticated client;
- sender-constraint keys pin possession;
- client-instance attestation over an instance-unique key pins the
  concrete instance;
- attested runtimes pin the execution environment; and
- an Agent Deployment pin holds the behavioral version.

The key and instance steps are the `presenter-key-bound` and
`instance-bound` binding properties ({{binding-properties}}); none of
these steps is an assurance level.

In the division of labor with agent IAM, agent identity preserves who
is acting, and the Mission preserves why their authority exists:

- the registry and workload identity authenticate an approved agent
  instance;
- the Mission and, where the binding derives one, its Authority Set
  say what sanctioned work that instance carries;
- per-hop credentials narrow;
- the runtime layer enforces each action and parameter; and
- the evidence layer joins what was approved, decided, and done.

# The Mission Verbs {#layers}

The family organizes along a verb spine. Each verb answers one
question, sits on one trust boundary, and is owned by named
documents; the levers of {{capability-envelope}} sort onto the spine
by the question each answers.

~~~
 propose      OAuth Intent Shaping or AAuth native proposal
              (client or agent side, untrusted)
                        |
 approve      Mission control point: the OAuth AS, Mission
 and record   Authority Server, AAuth Person Server
              contextual-governance binding, UMA AS, or
              GNAP AS (+ Consent Evidence, Deferred Approval)
                        |
              the Mission: durable approved context and
              lifecycle; authority anchors where defined
                        |
 govern       Status (pull), Signals (push),
              Expansion (widen), Discharge (retire)
                        |
 enforce      Runtime contract -> AuthZEN profile:
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

The family manifest records each verb's owning documents. The
Packages column gives the product architect's view: the five
architecture packages a deployment builds, independent of how the
drafts are cut for standardization:

- Mission Control;
- Authority Distribution, including the four Mission Issuer bindings
  (OAuth, the MAS, UMA, and GNAP);
- Runtime Enforcement;
- Agent Execution Governance; and
- Evidence and Accountability.

A document can serve more than one package, and the document map
({{document-map}}) names every draft.

| Verb | Owning documents | Packages |
| --- | --- | --- |
| propose | `mission-shaping`, `oauth-mission-submission-evidence`, `oauth-mission-request-provenance` | Agent Execution Governance |
| approve and record | `oauth-mission`, `mission-authority-server`, `mission-aauth`, `mission-uma`, `mission-gnap`, `mission-substrate`, `oauth-mission-resource-access`, `oauth-mission-issuance-grant`, `oauth-mission-consent-evidence`, `oauth-mission-approval`, `oauth-mission-approval-revision`, `oauth-mission-template`, `mission-approval-governance` | Mission Control; Authority Distribution; Evidence and Accountability |
| govern | `oauth-mission-status`, `oauth-mission-status-list`, `oauth-mission-signals`, `oauth-mission-management`, `oauth-mission-discharge`, `oauth-mission-expansion`, `oauth-mission-progressive`, `oauth-mission-containment`, `oauth-mission-derivation-limits`, `mission-control-plane`, `mission-discovery`, `mission-metering`, `mission-aauth-management`, `aauth-mission-expiry` | Mission Control; Runtime Enforcement (metering); Agent Execution Governance (discovery) |
| enforce each action | `mission-runtime`, `mission-runtime-oauth`, `mission-authzen`, `mission-runtime-evidence`, `mission-capability-binding`, `oauth-mission-transaction-authorization` | Runtime Enforcement; Evidence and Accountability |
| run and wind down | `mission-harness`, `mission-orchestration` | Agent Execution Governance |
| delegate | `oauth-mission-child-delegation`, `oauth-mission-attenuation`, `oauth-mission-cross-org-delegation` | Authority Distribution |
| project | `oauth-mission-cross-domain`, `oauth-mission-cross-org-delegation` | Authority Distribution |
| continue | `oauth-mission-continuation` | Authority Distribution |
| prove | `oauth-mission-consent-evidence`, `oauth-mission-approved-set-verification`, `oauth-mission-work-products`, `mission-runtime-evidence`, `mission-mandate`, `mission-audit`, `mission-evidence-envelope` | Evidence and Accountability |
| analyze | `mission-security-model`, `mission-aam`, this document | all five |
{: #packages title="The verb spine: owning documents and packages"}

The same mechanisms, placed on the authority path
({{authority-path}}) by the transition each acts on:

| Mechanism | What it changes | Home |
| --- | --- | --- |
| Direct approval | a proposal to an approval event (`direct` basis) | `oauth-mission` |
| Template dispatch | a template ceiling to an approval event (`template` basis) | `oauth-mission-template` |
| Expansion | a freshly adjudicated successor Authority Set, for widening or restoration | `oauth-mission-expansion` |
| Progressive authorization | an Expansion successor adjudicated by policy within a pre-consented ceiling (`ceiling_drawdown` basis) | `oauth-mission-progressive` |
| Containment | narrows the Effective Authority Set; restored only through an Expansion successor | `oauth-mission-containment` |
| Discharge | narrows the Effective Authority Set; the entry is spent | `oauth-mission-discharge` |
| Suspend and resume | closes and reopens the lifecycle gate; neither set changes | `oauth-mission-status` |
| Revoke, complete, expire | closes the lifecycle gate terminally | `oauth-mission`, `oauth-mission-status` |
| Issuance and refresh | the Effective Authority Set to a derived credential | `oauth-mission` |
| Issuance grant | an Effective subset handed to a consuming AS | `oauth-mission-issuance-grant` |
| Derivation limits | bounds how many derivations the Effective Authority Set yields | `oauth-mission-derivation-limits` |
| Attenuation | a derived credential to a narrower one, offline | `oauth-mission-attenuation` |
| Child delegation | a new Child Mission approval event bounded by the parent's Effective Authority Set (`direct` or `policy_drawdown` basis) | `oauth-mission-child-delegation` |
| Cross-domain projection | a derived subset honored as a destination-local credential | `oauth-mission-cross-domain` |
| Runtime decision | credential authority, the current Effective Authority Set, and state to a per-action decision | `mission-runtime`, `mission-authzen` |
| Deferred approval, approval revision, approval governance | how an approval event is reached; no transition of their own | `oauth-mission-approval`, `oauth-mission-approval-revision`, `mission-approval-governance` |
| Evidence, continuation, work products | record or carry a transition; move no authority | `oauth-mission-consent-evidence`, `mission-runtime-evidence`, `mission-audit`, `oauth-mission-continuation`, `oauth-mission-work-products` |
{: #authority-transitions title="The transition each mechanism acts on"}

## Propose

Question:
: How does a user's request become a candidate approved task?

Boundary:
: The client side, in OAuth.

Owners:
: * Intent Shaping, which produces an untrusted Mission Intent
    ({{I-D.draft-mcguinness-mission-shaping}}); and
  * the submission-evidence framework, under which any Intent
    Submission Evidence is processed
    ({{I-D.draft-mcguinness-oauth-mission-submission-evidence}}).

In OAuth, the Intent enters through Pushed Authorization Requests
{{RFC9126}} or the MAS submission endpoint. In AAuth, the agent sends
the native description and requested tools to the Person Server's
mission endpoint. The AAuth binding defines no Mission Intent or
dependency on the shaping profile.

## Approve and Record

Question:
: How does a proposed task become an approved, committed Mission?

Boundary:
: The binding's control point; the approval event is where trust is
  created.

Owners:
: * the five bindings ({{I-D.draft-mcguinness-oauth-mission}},
    {{I-D.draft-mcguinness-mission-authority-server}},
    {{I-D.draft-mcguinness-mission-aauth}},
    {{I-D.draft-mcguinness-mission-uma}},
    {{I-D.draft-mcguinness-mission-gnap}});
  * Consent Evidence, committing the disclosure shown to the Approver
    ({{I-D.draft-mcguinness-oauth-mission-consent-evidence}}); and
  * Deferred Approval
    ({{I-D.draft-mcguinness-oauth-mission-approval}}), the OAuth
    binding's asynchronous path, with an experimental companion adding
    an in-review narrowing negotiation.

The standalone and AAuth bindings are natively asynchronous. AAuth's
baseline approval commits its exact mission blob, not the family
Consent Evidence object. Where the experimental progressive
authorization companion is used, the initial approval also consents an
authority ceiling for later staged widening
({{I-D.draft-mcguinness-oauth-mission-progressive}}).

Who holds the deciding side is a spectrum, not a species. The approval
event requires an accountable principal deciding against committed
inputs before any authority exists, and the proposer is never the
approver.

A deterministic, versioned policy can approve at machine speed within
a ceiling a human consented to (the `template`, `policy_drawdown`, and
`ceiling_drawdown` authorization bases that companion profiles define
on the OAuth binding's extension point; see Authorization bases in
{{invariants}}). Policy
approves the instance because a human approved the policy or the
template; `policy_version` keeps that chain re-checkable. Derivation
fixes the authority, the adjudicator (a human or such a policy)
decides activation, and a human is accountable.

A model's judgment, over risk signals or enterprise context, enters
adjudication only as a recorded input to the policy: it can refuse or
narrow, never grant or widen. Neither the policy nor a model input to
it gates on the Intent's prose members, which stay the human
Approver's check ({{I-D.draft-mcguinness-oauth-mission}}). A generated
approver reading attacker-influenced proposals is itself an injection
surface. The high-consequence classes stay on a fresh human decision,
per the progressive profile's prohibited set
({{I-D.draft-mcguinness-oauth-mission-progressive}}).

## Govern

Question:
: How do consumers observe Mission state, and how does authority grow
  or retire mid-task?

Boundary:
: Between the issuer and every consumer relying on state.

Owners:
: * Status, the signed pull surface with a lifecycle endpoint
    ({{I-D.draft-mcguinness-oauth-mission-status}}), extended by the
    Status List companion for fleet-scale reliance
    ({{I-D.draft-mcguinness-oauth-mission-status-list}}) and by the
    Entry Discharge companion for per-entry completion discharge
    ({{I-D.draft-mcguinness-oauth-mission-discharge}});
  * Signals, the push complement
    ({{I-D.draft-mcguinness-oauth-mission-signals}});
  * Expansion, widening only via an approved successor
    ({{I-D.draft-mcguinness-oauth-mission-expansion}});
  * Containment, event-triggered monotonic narrowing of a live
    Mission's effective authority
    ({{I-D.draft-mcguinness-oauth-mission-containment}});
  * Management, fleet enumeration and bulk lifecycle for operators
    ({{I-D.draft-mcguinness-oauth-mission-management}}); and
  * Discovery, experimental, binding encountered resources within a
    pre-consented ceiling ({{I-D.draft-mcguinness-mission-discovery}}).

The AAuth binding carries this verb natively through its management
companion for status, termination, and delegation-tree queries
({{I-D.draft-mcguinness-mission-aauth-management}}). Its native approved
lifetime bound is AAuth's own `expires_at`, profiled by the expiry
document ({{I-D.draft-mcguinness-aauth-mission-expiry}}).

## Enforce Each Action

Question:
: Is this specific action, with these parameters, permitted under this
  Mission now?

Boundary:
: The last controllable point between agent and resource.

Owners:
: * the runtime profile, the decision contract with parameter binding,
    custody, and fail-closed behavior
    ({{I-D.draft-mcguinness-mission-runtime}});
  * its AuthZEN profile, the concrete decision API
    ({{I-D.draft-mcguinness-mission-authzen}}); and
  * the runtime evidence companion, the Decision Evidence, Execution
    Evidence, and Refusal Record objects
    ({{I-D.draft-mcguinness-mission-runtime-evidence}}).

The runtime decision composes conjunctively with the other gates. Each
of the following is independently necessary, and none grants, widens,
or restores another ({{I-D.draft-mcguinness-mission-runtime}},
Section "The Runtime Decision"):

- Effective Authority Set membership;
- every applicable cumulative-consumption or stateful operational
  gate; and
- a required action-bound approval.

## Run and Wind Down

Question:
: How does governed work start, persist, pause, and unwind when Mission
  state changes?

Boundary:
: The operator's execution environment around the agent.

Owners:
: * the harness, binding session continuity to Mission state
    ({{I-D.draft-mcguinness-mission-harness}}); and
  * Orchestration, unwinding in-flight work through reversibility
    classes and recorded unwind plans
    ({{I-D.draft-mcguinness-mission-orchestration}}).

## Delegate

Question:
: How does authority reach a sub-agent without widening?

Boundary:
: Between principals acting under one approval.

Owners:
: * Child Delegation, child Missions with lineage, strict-subset
    authority, and cascade revocation
    ({{I-D.draft-mcguinness-oauth-mission-child-delegation}}); and
  * Offline Attenuation, narrower Mission-bound tokens minted off the
    issuer's hot path
    ({{I-D.draft-mcguinness-oauth-mission-attenuation}}).

Both build on the actor chain of the OAuth binding's Delegation Within
a Mission section. Offline attenuation requires the runtime
enforcement layer: its kill switch is the runtime state re-check.

The chooser:

- the OAuth binding's token-exchange delegation ({{RFC8693}}), for an
  execution hop that lives and dies with the parent's lifecycle;
- a Child Mission, when the delegate needs its own lifecycle,
  approval, or audit identity; and
- offline attenuation, experimental, only where offline minting is the
  constraint.

The same principal exercising the same authority concurrently is not
delegation but swarm execution ({{swarm-execution}}).

AAuth delegates natively: a parent-mediated sub-agent under
`parent_agent`, distinct from the call chain of a service hop, with
no Authority Set machinery imported
({{I-D.draft-mcguinness-mission-aauth}}).

## Swarm Execution: Multiplication, Not Delegation {#swarm-execution}

Swarm execution composes the three lifecycle-bearing objects
({{three-objects}}): one Mission, executed concurrently by N instances
acting under the same authorized agent identity. Where the deployment
implements the Mission's Agent Deployment pin, every instance also
satisfies it. It is multiplication, not delegation: no `act` hop, no
Child Mission, no attenuation chain, because authority never moves
between principals.

The Agent Deployment pin is a named architectural pattern, not a wire
member the OAuth binding defines. That document reserves no Intent
member for it and points to a dedicated Agent Deployment Binding
profile, which a deployment wanting the pin implements
({{I-D.draft-mcguinness-oauth-mission}}). An agent identity and an
Agent Deployment are distinct objects ({{three-objects}}): a profile
may map a Deployment version to a distinct client registration, but
this document neither requires nor implies that mapping.

The invariant is shared-identity authorization with per-instance
attribution. Authorization attaches to the shared agent identity, and
that shared identity does not distinguish individual instances. For
deployments using OAuth client authentication and the client-instance
profile, including applicable MAS joined paths, late binding is
attestation: an instance joins the work by authenticating as the shared
client with its own Client Attestation
({{I-D.draft-mcguinness-oauth-client-instance-id}}), not by receiving a
credential from a peer. Attribution then stays per-instance through
verified Instance Context, which attributes a presentation to an
instance only under a sender-constraint key unique to it
({{I-D.draft-mcguinness-oauth-client-instance-id}}, Section 7.3). These
mechanisms realize per-instance attribution; they do not themselves
define the Deployment-version pin.

The derivation limits profile's `derivation_limit`
({{I-D.draft-mcguinness-oauth-mission-derivation-limits}}) is not a
fan-out or concurrency ceiling. It counts issuance events, not
instances: a single instance refreshing N times consumes it exactly
as N instances deriving once each would. What bounds a
swarm's aggregate consumption is the metering profile's Mission-grain
budget: consumption bounds attach to the Mission, not to any one
instance, so a swarm of instances shares one budget
({{I-D.draft-mcguinness-mission-metering}}).

Swarm execution comes before the Delegate verb's chooser: more
instances under the same authorized agent identity deriving under one
Mission, with no new construct. A different principal acting inline,
a durable sub-agent, and offline narrowing take the chooser's options.

## Project

Question:
: How is one Mission honored in another trust domain?

Boundary:
: A trust boundary the origin does not control, where the verifier
  holds no session with the issuer.

Owner:
: Cross-Domain Projection, a single-hop grant that carries the
  Mission's identifier, issuer, and authority hash into a partner
  domain unchanged, where a Resource AS mints a local token bounded by
  the projected authority
  ({{I-D.draft-mcguinness-oauth-mission-cross-domain}}).

Projection preserves authority across the boundary rather than narrowing
it to a sub-actor, which makes it a distinct verb from Delegate.
Downstream revocation latency is the local token lifetime.

## Continue

Question:
: How does a Mission's authorization continue, under the same approval
  and constraints, when the acting identity must be re-established at
  each hop or after the original credential is gone?

Boundary:
: The seam between authorization continuity and identity continuity.

Owner:
: Mission Continuation
  ({{I-D.draft-mcguinness-oauth-mission-continuation}}), the
  authorization-continuity profile.

The profile keeps three easily conflated things apart:

- Identity continuity (who is acting, and how that identity
  legitimately continues) rides a transport, not this profile:
  Identity Continuation
  ({{I-D.draft-mcguinness-oauth-id-continuation-assertion}}) for
  short-lived, sender-constrained hops among Resource Authorization
  Servers that trust a common identity provider; async delegation
  ({{I-D.draft-zhu-oauth-async-delegation}}) for a long-running,
  disconnected task; and the cross-domain grant
  ({{I-D.draft-mcguinness-oauth-mission-cross-domain}}) across a trust
  boundary.
- Authorization continuity (what work remains authorized, under which
  constraints, on whose approval) is the Mission's. Every continued
  grant derives a subset of the Mission's Authority Set, is
  state-gated at issuance, and is bounded by the Mission's expiry.
  When the Mission goes terminal, new continued grants end; authority
  already issued under a continued grant runs to its own bound unless
  a state-aware gate reaches it first.
- Execution-time evidence records, against the Mission, what was done
  at each continued hop.

A continuation handle grants nothing: it names an accepted hop, and
every continued grant re-passes the Mission's `active` gate.
Continuity is never authority, the rule the harness applies
to session continuity ({{I-D.draft-mcguinness-mission-harness}}).

Continue differs from Delegate, which narrows authority to a sub-actor.
Continue uses the Project verb's cross-domain grant as one transport
rather than replacing it.

## Prove

Question:
: What can a party outside the deployment verify about what was
  approved and done?

Boundary:
: Across trust domains and time; the verifier holds no session with
  the issuer.

Owners:
: * Consent Evidence
    ({{I-D.draft-mcguinness-oauth-mission-consent-evidence}});
  * the Mandate, a signed, portable statement that authorizes nothing
    ({{I-D.draft-mcguinness-mission-mandate}});
  * the Mission Receipt, portable evidence of an action taken under a
    Mission ({{I-D.draft-mcguinness-mission-runtime}}); and
  * Audit Transparency, the append-only evidence log
    ({{I-D.draft-mcguinness-mission-audit}}).

## Analyze

Question:
: Which components must be trusted, and what does each one's
  compromise cost?

Boundary:
: The whole system.

Owner:
: The Mission Security Model
  ({{I-D.draft-mcguinness-mission-security-model}}).

# Mission Invariants {#invariants}

Seven invariants define the family's portable-authority model; their
home documents state them normatively. They apply to the OAuth binding
and to companions and bindings that explicitly adopt the corresponding
Authority Set capabilities. A change that would break one in those
bindings is a change to that model, not to a profile.

The AAuth binding adopts the context-level invariants: durable approval,
stable attribution, exact-byte integrity, an active-state gate at the
PS, and termination. It does not adopt the OAuth Authority Set, the
OAuth integrity anchors, or universal subset derivation. AAuth resource
authority is decided afresh in the vocabulary and policy of each
Resource or Access Server, with contextual PS governance when the PS is
on path.

Read as shared capabilities rather than universal wire semantics, all
the bindings carry durability, attribution, and termination; narrowing
and containment require a structured-authority capability, so they are
not baseline AAuth Mission Context properties.

**Authority serves an approved task**:
: No Mission-bound authority exists except by derivation for a
  Mission, and a Mission is created only when rooted in an approved
  authorization basis that commits `intent_hash` and `authority_hash`
  (the OAuth binding). Fields an agent can influence shape authority
  only through the pre-approval derivation the Approver consents to.
  Once the Mission is approved, those fields are inert and never
  derive, widen, or gate authority.

**Only `active` permits**:
: Issuance, refresh, and every new positive governance decision require
  the exact state `active`; every other state, including an unrecognized
  one, fails safe (the OAuth binding's Mission Lifecycle and Gating
  section). A state-aware consumer relies only while it observes
  `active`; a state-unaware consumer retains the bounded
  materialized-credential residual ({{validity-model}}). In AAuth, only
  PS operations are structurally gated; agent identity and
  resource-managed access do not pass through the PS. In person
  identity access, the gate is person-token issuance (Section 7.1 of
  {{I-D.draft-hardt-oauth-aauth-protocol}}). In PS authorization and
  federated authorization access, the gate covers auth-token issuance
  and federated brokering for requests whose resource token carries
  the validated Mission Reference; a stripped or mismatched reference
  fails the request, which is never evaluated as missionless
  ({{I-D.draft-mcguinness-mission-aauth}}).

**Authority only narrows**:
: Derived tokens, delegated child Missions, attenuated tokens, and
  cross-domain projections carry subsets ({{authority-path}}). Widening
  exists only as an approved successor: a fresh approval
  ({{I-D.draft-mcguinness-oauth-mission-expansion}}), or policy drawdown
  within a ceiling a human pre-consented
  ({{I-D.draft-mcguinness-oauth-mission-progressive}}). Within a live
  Mission, issuer-held narrowing such as containment or discharge only
  subtracts: each mechanism feeds a single Effective Authority Set,
  every derivation reads it, and none restores authority
  ({{I-D.draft-mcguinness-oauth-mission-status}}). The subset relation
  is typed: a type's specification defines its own subset relation,
  and an issuer narrows, delegates, or projects an entry only under a
  capability it declares for that type (for example, on the OAuth
  binding, `mission_resource_access` and its Common Constraints,
  {{I-D.draft-mcguinness-oauth-mission-resource-access}}). Without that
  capability the entry is carried exactly as approved. Moving
  authority into expressive policy-language entries weakens this
  guarantee exactly there, a trade to make knowingly
  ({{I-D.draft-mcguinness-mission-security-model}}).

**Revocation is possession-independent**:
: A Mission ends by a state change at its issuer, not by finding and
  destroying credentials. Where the binding gates issuance, further
  derivation and refresh stop at once; an outstanding credential ends
  at the earliest of an applicable revocation, a state-aware or runtime
  check that reaches it, or its own expiry ({{validity-model}};
  {{I-D.draft-mcguinness-oauth-mission-status}}).

**Attribution is carried, never inferred**:
: Each role in the actor chain travels in its own construct, and the
  evidence layer records them together; no role is derived from
  another ({{actor-chain}}).
  The credential-to-Mission association is itself a carried fact only
  where a binding carries the `mission` claim; under the standalone
  binding the PDP's join establishes it by inference, bounded by that
  binding's join assurance ({{binding-architectures}}).

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

Three readings follow from the invariants without adding to them:

Authorization bases:
: "Approved" in the first invariant has more than one basis. The OAuth
  binding fully defines one, `direct`, a human's own approval. It also
  provides the extension point, an authorization-basis `type` string,
  that companion profiles use to define others:

  - `template`: a dispatch drawing on a ceiling the human consented
    to once.
  - `policy_drawdown`: a child instance a policy adjudicates within a
    bound the parent's human already consented to.
  - `ceiling_drawdown`: a successor a policy adjudicates within an
    authority ceiling the Approver consented to at the initial
    approval.

  Every basis fixes the same accountable human as `consent_principal`;
  the bases differ only in what activated this instance and what root
  that activation traces to (the OAuth binding).

Work products:
: Authority never rides a work product. Crossing into a Mission, a
  work product is input the receiving Mission re-evaluates under its
  own Authority Set, never a source of authority itself. The Mission
  Work Products companion carries the rule through non-transitive
  Mission-to-Mission handoff
  ({{I-D.draft-mcguinness-oauth-mission-work-products}}), and the
  OAuth binding states it in its "Authority Does Not Propagate With
  Information" section ({{I-D.draft-mcguinness-oauth-mission}}).

Composition:
: An approval bounds the authority each derivation under the Mission
  carries; it does not bound the aggregate effect of a body of work.
  The invariants bound one Mission's own Authority Set, not the surface
  a delegation tree, a cross-domain hop, or a chain of child
  generations reaches together.

  The per-Mission figures differ in kind and do not multiply into a
  lifetime total:

  - In the child-delegation profile, `max_children` limits
    concurrently non-terminal children, so a completed child frees its
    slot.
  - `max_child_depth` limits generations.
  - Each Child Mission's derivation cap is its own, independent of its
    parent's.

  Delegation depth also resets at each cross-domain hop and child
  generation. Disclosing what these figures bound at the consent
  surface is the cross-domain and child-delegation profiles' role. An
  aggregate bound holds only where a deployment enforces one (the
  metering profile's lineage budget) and is never rendered as in force
  otherwise ({{I-D.draft-mcguinness-oauth-mission-cross-domain}},
  {{I-D.draft-mcguinness-oauth-mission-child-delegation}},
  {{I-D.draft-mcguinness-mission-metering}}). The OAuth binding
  states the same property in its "Composition and the Effective
  Ceiling" section ({{I-D.draft-mcguinness-oauth-mission}}).

# Meaning and Derivation {#meaning-and-derivation}

Three questions sit between a proposed task and enforced authority:

- who owns what an operation means ({{ontology-contract}});
- who commits the authority derived from the task
  ({{derivation-boundary}}); and
- what the approval event fixes ({{approval-fidelity}}).

## The Ontology Contract {#ontology-contract}

The capability envelope ({{capability-envelope}}) meets its hardest case
in the open world. The OAuth model starts with authority the client
proposes and the approval enumerates. An agent that discovers resources
at encounter time breaks that premise, and some authorization mechanisms
invert it: the resource declares its own operations and consequences.

The derivation boundary ({{derivation-boundary}}) settles who commits
authority; this section settles who owns what an operation means. The
resource owns the ontology, its operations, its constraint semantics,
and their consequences. Derivation, consent rendering, and enforcement
consume that meaning without owning it, and no layer invents meaning it
does not own. One boundary is shared by agreement: the resource owns its
operation semantics and consequences, while the family owns the
registered cross-resource constraint vocabulary, which a resource
explicitly advertises and adopts before it binds
({{I-D.draft-mcguinness-oauth-mission-resource-access}}).

The consuming contract: meaning binds at approval and is enforced at
the point of use. Any translation between the resource's vocabulary
and another party's is trusted, verified, or separately approved, never
a place where authority widens.

Resource-owned meaning reaches the three consuming layers through five
mechanisms, each defined in its own home and composing as one contract:

Common Constraints:
: The registered constraint vocabulary every conforming party evaluates
  identically, with the `mission_constraints_supported`
  protected-resource metadata member advertising which constraints a
  resource enforces. Home: the OAuth binding's Mission Resource Access
  Profile ({{I-D.draft-mcguinness-oauth-mission-resource-access}}).

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
  late still binds before use. It covers the encounter's routing
  (through drawdown, catalog binding, projection, or fresh approval),
  identity pinning, and floors. Home: the discovery companion
  ({{I-D.draft-mcguinness-mission-discovery}}).

Resource-Declared Semantics:
: The full inversion: the resource publishes its operations, their human
  meaning, and their consequences. Under the OAuth discovery
  composition, the declaration can be content-addressed by `r3_s256` as
  an additional commitment beside the Mission's integrity anchors,
  recording what the resource claimed to be when authority bound to
  it. In that composition, the declared operations become candidate
  vocabulary that derivation narrows against. AAuth can instead use R3
  as a resource-owned deterministic authorization vocabulary while the
  private mission blob remains contextual PS governance. R3 content
  addressing is not a baseline AAuth mission anchor. Home: the discovery
  and R3 compositions, informative.

Behind the five mechanisms sits one direction axis, chosen per
encounter, not fixed by binding. The family inherits OAuth's
client-proposed default: the client names the authority it wants, and
the resource's meaning arrives through metadata, catalogs, and profiles.
Resource-Declared Semantics is the inversion, where the resource speaks
first. Where a structured-authority binding commits that meaning at
approval, it is enforced at use and translation never widens.

Under the OAuth binding, the resource-declared direction runs entirely
through existing family seams:

- the encounter contract routes the declaration
  ({{I-D.draft-mcguinness-mission-discovery}});
- narrowing-mode derivation consumes the declared operations as
  candidate vocabulary ({{I-D.draft-mcguinness-oauth-mission}});
- consent composes the resource-authored material; and
- the declaration's digest rides the derived authority (the
  progressive companion's `resource_declaration_digest`,
  {{I-D.draft-mcguinness-oauth-mission-progressive}}).

The OAuth-native descriptive surfaces the resource-declared direction
builds on are an authorization server's RAR type metadata, the schema
and documentation of each type it supports
({{I-D.draft-ietf-oauth-rar-metadata-remediation}}), and a protected
resource's `authorization_details_types_supported` ({{RFC9728}}).

In AAuth, R3 can describe deterministic resource authorization
independently of mission approval; the PS considers the resource request
and mission context without turning the R3 declaration into a Mission
Authority Set.

Where a deployed semantic-binding mechanism is in force, both directions
close the same loop: the meaning source's digest becomes part of the
derived authority. A catalog-sourced capability pins its
`source_digest`, and a resource declaration pins `r3_s256`. In each
case the Authority Set carries the version of the meaning it was
derived under, and the point of use compares against the meaning in
force. Under such a mechanism, meaning is not consulted at approval and
assumed at enforcement; it is committed at approval and re-verified at
use. An ordinary registered `authorization_details` type can carry
stable semantics with neither digest; the loop is closed by the
mechanism a deployment runs, not by the family universally.

Meaning, like state, fails closed. Each home states the contract's
failure mode: a consumer facing an operation meaning it cannot resolve,
a constraint it cannot evaluate, a drifted capability definition, or an
unrecognized declaration refuses rather than guesses.

The contract has a dual of equal force. The resource owns what an action
means; the Mission owns why it is happening and where the undertaking
stands, and carries that context in one form that independently
implemented components on the path share. A resource that does not
itself run the undertaking
evaluates each request at perfect local resolution and zero task
resolution: it can price every consequence its ontology names but
cannot see the undertaking the request belongs to. A risk decision
composes both sides of this context asymmetry. Semantics without
purpose prices every delete the same; purpose without semantics cannot
read the call.

"Delete database" in isolation is indistinguishable from catastrophe.
"Delete database" inside an approved migration whose copy of that same
database, at the revision being deleted, already completed is a priced,
checkable step. That judgment needs the undertaking's history bound to
the object and its revision, which a resource-local view holds only
where the resource itself runs the workflow. After
the fact, that history is reconstructible from the join of Decision and
Execution Evidence on the Mission's identity. At decision time, a
task-aware decision point can draw the same history from trusted prior
workflow state or another authoritative source. The runtime profile
names the mechanisms: sequence-aware evaluation over the undertaking's
history is an optional decision input, guarded so that history informs a
decision and never widens one, and Evaluation-Context Binding commits
the revision a decision relied on
({{I-D.draft-mcguinness-mission-runtime}}).

## The Authority Derivation Boundary {#derivation-boundary}

In the authority-bearing bindings, the Approver consents to the
Authority Set the Mission Issuer renders and commits, not to the
Mission Intent. All of these bindings derive under the OAuth
binding's rules ({{I-D.draft-mcguinness-oauth-mission}}, Section
"Mission Authority").

Derivation is mechanical: the Mission Issuer narrows a submitted
authority proposal to policy, or looks up candidate entries in a
configured mapping keyed on structured Intent members and narrows
those. The prose members (`goal`, `task_bounds`, `success_criteria`)
never change what is derived; they bound authority through disclosure,
since the Approver refuses authority the words do not support.
Translating a user's words into structure is the shaper's job, before
admission and outside the trust boundary
({{I-D.draft-mcguinness-mission-shaping}}).

Derivation policy stays local: what the Mission Issuer narrows to, and
what its mappings contain. The consequence is a trust boundary:
interoperability begins at the committed result, not at the Intent. A
Mission Intent has no portable semantics; two conforming Mission
Issuers can derive different Authority Sets from the same submission.
Audit can establish what was derived (against `intent_hash` and
`policy_version`), never whether it was the right reading of the task.

Narrowing mode is the interoperable path: each derived entry is a
subset of a proposed entry, so the client can check that the result
stays within its proposal. Reproducing which subset was derived takes
the retained derivation policy and its inputs. A deployment whose partners
must reason about its derivations can publish a derivation policy
identifier and test fixtures that pin Intent-to-Authority-Set
outcomes, making the local policy reviewable even though it does not
travel. The OAuth binding's informative Derivation Policy appendix
({{I-D.draft-mcguinness-oauth-mission}}) illustrates that policy
artifact: a worked narrowing rule, fixtures, and ownership.

The ceiling the derivation narrows against is a composition, not a
single object. The derived Authority Set sits inside every bound on the
task:

- the issuer's derivation policy;
- the ceiling of the Mission's established authority source; and
- at enforcement time, the resource owner's and deployment's live
  policy at the decision point.

The derivation step intersects the first two and commits the result.
The runtime contract re-checks the rest on every action, which is why a
permit is never implied by the Authority Set alone. A deployment adding
further sources (a tenant boundary, an environment-specific floor) adds
them as derivation-policy inputs or as decision-point policy, never as
agent-negotiated widening.

The established authority source is a delegating person's own authority,
a workload's provisioned authority, or governed organizational policy.
Approval activates authority the source already holds and grants nothing
beyond it. The Approver needs authority to activate the source, not
personal possession of its permissions.

The derivation modes rank by how portable their result is:

| Derivation mode | Portability status |
|---|---|
| Client proposes concrete authority; Mission Issuer narrows it to policy | Interoperable default |
| Configured mapping keyed on structured Intent members | Conforming; the mapping is deployment-specific |
| Model-assisted derivation over the structured inputs | Local-policy extension: the model's output is a recorded input that can refuse or narrow, never supply or widen |
| Derivation from the prose members | Not a mode: prose is disclosure, shaped before admission |
{: title="Derivation modes by portability"}

A deployment seeking interoperable authority uses narrowing; a
model-assisted extension stays local policy unless a profile pins it
with a published policy identifier, version, and test fixtures.

## Approval Fidelity {#approval-fidelity}

For the portable-authority bindings, the approval event authenticates
the Approver, establishes the Subject, derives and renders the Authority
Set for consent, and computes the anchors over the consented set, the
approved Intent, and, where one was submitted, the authority proposal.
That approval event creates the record in `active` atomically with the
decision.

AAuth approval has different fidelity: the native propose, clarify, and
approve interaction authenticates the parties, returns the approved
mission blob and exact-byte `s256` commitment, and creates an `active`
Mission Context. It does not render or commit an OAuth Authority Set.

Home: the OAuth binding's Mission Approval section. Consumed by Consent
Evidence, which binds to this event, and by every downstream guarantee
that assumes the anchors, the gating, and the record.

# The Mission Substrate {#substrate}

The binding-neutral contract is Mission Substrate Requirements
({{I-D.draft-mcguinness-mission-substrate}}), which states the checklist
below normatively for any further binding. Its contextual-governance
kernel is what every binding provides. A mission-based protocol
supplies a Mission Context when it maps these native capabilities
explicitly:

- a stable reference and controlling authority;
- binding to the acting actor;
- immutable approved context, or a verifiable commitment to it;
- an explicit approval event;
- an active-state gate at declared control points;
- a stated reliance bound on every governed decision and artifact;
- context propagation or decision correlation; and
- an ordered governance or audit record.
{: #binding-checklist}

Each binding declares what it supplies, in a Mission Substrate
Statement or, for the OAuth binding, an informative Mapping Assessment.
Beyond the kernel, a binding that publishes a Statement claims through
it any of eight optional capabilities (Lifecycle-Gated Authorization,
State-Observable, Structured Authority, Monotonic Derivation,
Credential-Bound, Authorized Context Correlation, Independently
Verifiable, and Portable Evidence), and composes only the profiles
whose required capabilities it provides. The OAuth binding publishes no
Statement; its Mapping Assessment maps it to the same capabilities
({{I-D.draft-mcguinness-oauth-mission}}).

The companion profiles named without "oauth" are defined against the
binding-neutral contract, and most declare what they consume in a
Mission Substrate section of their own. The runtime profile's
declaration is the exemplar ({{I-D.draft-mcguinness-mission-runtime}}),
and the other consumers align with it to varying degrees. Where a
companion consumes a concrete representation, it is the OAuth
binding's, the realization the family was first authored against;
vocabulary ownership migrates to the substrate contract by touch
({{I-D.draft-mcguinness-mission-substrate}}).

The OAuth binding instantiates the substrate through eight primitives,
each with a normative home and consumers: six in the table below, the
Mission-Bound Credential ({{mission-bound-credential}}), and the
approval event, whose fidelity is described in {{approval-fidelity}}.
The binding-neutral kernel requires none of these OAuth-binding
representations or stronger semantics verbatim, though several
instantiate mandatory kernel functions:

- the identifier and issuer realize the Mission Reference and
  Controller;
- the lifecycle realizes the governance gate;
- token validity participates in bounded reliance; and
- the audit horizon participates in the governance record.

## The Primitives, at a Glance {#substrate-primitives}

| Primitive | The OAuth realization | Normative home | Consumed by |
|---|---|---|---|
| Mission Identifier and Issuer | An opaque, non-reused identifier with at least 128 bits of entropy and no semantic content, plus the issuer URL; together they name exactly one Mission. The kernel requires stability, non-reassignment, and unguessability, not this syntax | The OAuth binding: Mission Record, Mission Identifier Format | Every companion: decisions, evidence, harness bindings, the state surfaces, the audit statement subject, the Mandate |
| Lifecycle state space | The states of {{approval-and-lifecycle}}, open to companion-defined states, with the only-`active` rule, fail-safe unrecognized states, and a freshness source with a stated staleness bound | The OAuth binding (state space, only-`active`); the status and runtime profiles (freshness); Status and Signals (observation) | Runtime per-class re-check (fail closed on staleness), harness pause, suppress, and terminate, the orchestrator's unwind trigger, the Mandate (state as of minting) |
| Authority Set representation | Authorization-details entries ({{RFC9396}}), each naming resource, actions, and constraints, under the subset rule (derived or delegated authority is never broader) and, for `mission_resource_access`, the Common Constraints vocabulary (registered names with fixed subset and intersection rules) | The OAuth binding: Mission Authority, Subset Rule; the Mission Resource Access Profile: Common Constraints | Runtime and the AuthZEN profile, the MAS, Expansion and Discharge, Child Delegation and Offline Attenuation, Consent Evidence, the Mandate |
| Integrity-anchor envelope | A committed object hashed over a `typ`-domain-separated, issuer-bound envelope with fixed canonicalization and an algorithm-prefixed encoding a verifier recognizes or rejects (unknown prefixes refuse; no downgrade); the `typ` space is the extension point | The OAuth binding: Integrity Anchors, Canonicalization Rules, Extensibility | Consent Evidence, Shaping, the runtime layer and AuthZEN profile (`mission-policy-view`), Orchestration, the Mandate, Audit Transparency |
| Issuer key material | Signing keys resolvable from `issuer`; across a rotation each key identifier stays resolvable while artifacts signed under it remain within the audit horizon | The OAuth binding: Signing and Key Rotation | Verifiers of Mission-bound credentials, Consent Evidence, the Mandate, the signed state surfaces, Audit Transparency |
| Audit horizon | The deployment-declared retention window: at least the Mission's lifetime plus a declared post-terminal period | The OAuth binding: Mission Record | Consent and runtime evidence and Audit Transparency (retention), the MAS (record retention), the security model's retention analysis |
{: title="Substrate primitives in their OAuth realization"}

The anchors in the envelope row are **commitment anchors**, not
enforcement proofs ({{derivation-boundary}}). A Resource Server holding
a narrowed token enforces the authority it receives rather than
reconstructing authority from a hash of a full set it does not hold
({{I-D.draft-mcguinness-mission-security-model}}). A Resource Server
or policy decision point that needs an independent check retrieves
the complete approved set, recomputes its anchor, and checks the
carried authority as a subset of it under Mission Approved-Set
Verification
({{I-D.draft-mcguinness-oauth-mission-approved-set-verification}}).

## Token Classes {#token-classes}

"Mission-bound" is a specific claim. The OAuth binding's Terminology
names three token shapes so that a weak one is not read as the strong
one:

- a **Mission-referenced token** carries a Mission identifier only;
- a **Mission-derived token** carries authority derived from an
  active Mission; and
- a **Mission-bound token** is Mission-derived and additionally
  active-state gated, subset-constrained, and refresh-gated: in the
  contract's vocabulary, a credential covered by the binding's
  Lifecycle-Gated Authorization, Monotonic Derivation, and
  Credential-Bound claims.

Only the third earns the term: a `mission` claim alone is a reference,
not Mission-bound authorization. The family defines "Mission-bound" by
the `credential-mission-bound` equivalence of the binding properties
({{binding-properties}}): six conditions, each mapped to what
discharges it, earned only where all hold together. The OAuth binding
discharges the equivalence through its own conformance rule.

## The Mission-Bound Credential {#mission-bound-credential}

The Mission-Bound Credential is a credential carrying the `mission`
claim (`id`, `issuer`) and Mission-derived authorization details,
issued only while the Mission is `active`. Its home is the OAuth
binding's Mission-Bound Access Tokens and The Mission Claim sections.
The claim's `id` and `issuer` are the Mission-identity condition; a
token-carried Authority Set commitment is never required for it, per
condition 2 of `credential-mission-bound` ({{binding-properties}}).

The credential is the binding-dependent primitive, and the bindings
split on it:

- the OAuth binding provides it;
- the standalone binding does not: per the MAS's Mission Substrate
  section, a MAS provides neither this credential nor issuance gating
  ({{I-D.draft-mcguinness-mission-authority-server}}); and
- an AAuth auth token can carry the native Mission Reference
  (`mission_s256`) but does not carry Mission-derived authorization
  details, so it is Mission-referenced, not a Mission-bound credential
  ({{I-D.draft-mcguinness-mission-aauth}}).

For profiles that compose with the credential, the seam is Mission
binding establishment ({{I-D.draft-mcguinness-mission-runtime}}, Section
"Mission Binding Establishment"). It has two modes. Credential-carried:
the acting credential carries the Mission reference, where the binding
provides one. Externally established: the PEP supplies a reference that
the PDP verifies against the acting credential under a join the binding
defines, which the MAS profiles as its Mission Join; an unverified
reference establishes no Mission.

Offline Attenuation attenuates this credential, and the token-carriage
aspects of delegation ride it, so both require it. The companions that
need a credential-to-Mission association (the runtime layer and the
harness) route through Mission binding establishment, which is what
makes the standalone binding possible.

The issuance-grant companion
({{I-D.draft-mcguinness-oauth-mission-issuance-grant}}) provides this
primitive by composing the OAuth and standalone bindings: the
standalone Mission Issuer mints a Mission Issuance Grant that a
consuming Authorization Server redeems for Mission-bound tokens.

## The Validity Model {#validity-model}

Five validity horizons govern reliance, each with its own setter,
checker, and consequence; implementations most often err by conflating
them:

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
  endpoints and on the PS-gated modes; agent identity and
  resource-managed access have no PS state gate.

`fresh_until`:
: set by the status responder; checked by status consumers. Past it a
  cached state report may not be relied on and is re-fetched.

Permit window:
: set by the PDP; checked by the executing PEP. Past it the permit is
  void and a new decision is required.

Action-approval freshness:
: set by the approval surface; checked by the PDP. Past it an
  action-bound approval no longer authorizes the action it named.

The horizons compose by minimum: reliance at any moment requires every
applicable horizon to be open, and no horizon substitutes for another.

The minimum applies to horizons enforced together on one use, not to
sequential reminting. An exchange that mints a new artifact without a
fresh state check relies on the observation behind the artifact it
consumed, so the residual sums: the consumed artifact's remaining
redemption time with its clock-skew leeway, plus the new artifact's
lifetime, plus that of each further unchecked exchange, capped by the
expiry ceilings that already apply. A grant redeemed at a consuming
Authorization Server without a Mission-state integration is the
family's case ({{I-D.draft-mcguinness-oauth-mission-issuance-grant}}).

The horizons also give the deployment its freshness dial, whose
TTL-only end is a first-class posture, not a fallback. A deployment
that relies on lifetimes alone verifies with local cryptography and a
clock: no state source, no freshness discipline, no availability
coupling, and a worst-case exposure equal to the lifetime by
construction. Where every fresh credential crosses a Mission-state
decision point, this posture realizes the **lifecycle-gated** capability
with reliance bounded by credential lifetime alone
({{I-D.draft-mcguinness-mission-substrate}}). That holds only for access
modes with such a gate: AAuth's PS-gated modes have it, while agent
identity and resource-managed access do not.

TTL-only is appropriate where the artifact's lifetime meets the
tolerated exposure bound and no required state check would shorten that
exposure. That is the case for short missions, and at action grain: an
artifact there lives seconds to minutes, and a revocation landing
inside its window has no observation point that could reach the
artifact before its own expiry does. The family's short-lived artifacts
(the permit, the cross-domain grant, the Join Assertion) sit at this
end.

A lifetime cannot suspend, complete, or kill at once. The Mission's
state carries that task-grain residue, and the **state-observable**
capability (an authenticated freshness source with a stated staleness
bound) reaches it. State-observable is a named substrate capability a
binding may provide beyond the kernel's bounded-reliance floor
({{I-D.draft-mcguinness-mission-substrate}}), and it is the one runtime
enforcement requires ({{I-D.draft-mcguinness-mission-runtime}}).

The two ends are one mechanism seen from opposite sides. A lifetime
relocates the freshness check from the verification path to the
issuance path, so every re-issuance is the policy re-check: the family's
gates-new-derivation-only rule in its other reading. A deployment states
where it sits on the dial through its bounded-revocation claim
({{assurance-claims-axis}}): a TTL-only posture claims the lifetime as
its bound only for paths whose re-issuance is gated, with no
state-observable overlay. The runtime profile prices each position,
source by source, in its state and freshness section
({{I-D.draft-mcguinness-mission-runtime}}).

## Binding Security Architectures {#binding-architectures}

The authority-bearing bindings are OAuth 2.0, the standalone Mission
Authority Server, and (as experimental sketches) UMA 2.0 and GNAP. AAuth
composes at the shared Mission Context layer: approval, stable
reference, lifecycle gating where the PS is on path, and governance
history ({{approval-and-lifecycle}}).

Peer standing among the bindings is a deployment-topology claim, not a
data-model-independence claim: each attaches to its own protocol as an
equally adoptable unit and declares what it supplies ({{substrate}}).
OAuth is the family's first-authored binding, built on widely deployed
OAuth infrastructure, a deployment fact and not a maturity ranking. The
Mission Authority Server
({{I-D.draft-mcguinness-mission-authority-server}}) is a normative
standalone-controller protocol binding over the OAuth Mission data
model: a peer deployment topology, but not an independent substrate
model, since it normatively imports the OAuth Mission record and
issuance profile. AAuth demonstrates model independence: it maps the
shared kernel onto its own protocol's native Mission Context without
importing the OAuth Authority Set
({{I-D.draft-mcguinness-mission-aauth}}). Peer standing implies neither
identical capabilities nor identical adoption cost: adopting Missions
on OAuth requires the changes the OAuth binding defines, while AAuth,
natively contextual, adds no new wire members.

The bindings share Mission Context capabilities but are not one security
system. Each has its own authority representation, trust assumptions,
cutoff behavior, and failure modes, and a deployment names its
architecture, not only its binding. Three patterns cover the bindings:

- **credential-carried authority**: the credential names the Mission,
  carries derived authority, and issuance is gated (the OAuth AS,
  UMA AS, and GNAP AS);
- **PDP-joined**: credentials are ordinary and a join establishes
  the association at the decision point (the standalone MAS); and
- **context-carried**: AAuth carries its native Mission Reference
  (`mission_s256`) while authority remains in resource scopes and
  policy. The PS-gated modes ({{components}}) pass through the PS,
  while agent identity and resource-managed access bypass it.

The differences that decide a design:

| Property | OAuth AS | MAS | AAuth PS | UMA AS (sketch) | GNAP AS (sketch) |
|---|---|---|---|---|---|
| Credential carries the Mission | yes (`mission` claim) | no | native reference where supported | yes (claim or introspection) | yes (protected `mission` claim or introspection assertion) |
| Issuance gated on state | yes | no (the issuance grant restores it per consuming AS) | person identity, PS authorization, and federated authorization only | yes | yes (issuance, grant modification, and rotation) |
| Runtime PDP required for a kill switch | no (issuance gate exists; runtime tightens) | yes (runtime is the only cutoff) | none from the binding for agent identity and resource-managed access; PS-path issuance has a bounded cutoff | no (per-use introspection cuts off) | no (issuance gate exists; per-use introspection cuts off where deployed) |
| Join ambiguity possible | no | yes (bounded by join assurance) | no when the native reference is preserved; it can be ignored in agent identity and resource-managed access | no | no (native binding; no cross-authority join) |
| Revocation latency source | token lifetime, status, or runtime | runtime and status only | auth-token lifetime on PS paths; no Mission cutoff on agent identity and resource-managed paths | next introspection | token lifetime, or the declared introspection cache bound |
| Offline Mission verification | partial (claims verify; state does not) | limited (join assertion) | reference integrity only; blob is private | JWT RPTs partial; opaque RPTs none | partial with a structured token or signed Mission Status |
{: title="How the binding architectures differ"}

A MAS deployment that holds the same Mission as an AS deployment does
not thereby provide AS-native semantics, so a comparison of deployments
compares their architectures first.

One Mission can govern authority issued by several authorization
servers. Its Controller need not issue each credential, and each server
may know the same participant by its own client identifier. The owning
Mission Issuer records how those identifiers relate: the MAS in its
mapping contract, and each issuance grant's `client_id` as the
consuming AS knows it
({{I-D.draft-mcguinness-mission-authority-server}},
{{I-D.draft-mcguinness-oauth-mission-issuance-grant}}). Identifier
equality is therefore neither required nor sufficient for participant
continuity. The kernel requires no `client_id` and no subset relation
across administrative or protocol boundaries
({{I-D.draft-mcguinness-mission-substrate}}), and a `client_id` shared
by several workloads is a join residual the MAS states.

The OAuth binding stacks two independent chokepoints. Issuance gating
acts at the token layer: a revoked or expired Mission stops all further
derivation and refresh, and short-lived tokens age out. Runtime
enforcement acts at the action layer: each consequential action is
re-checked against current state at the point of use. Issuance gating
plus runtime enforcement is strictly stronger than either alone: a gap
in PEP coverage is still bounded at the token layer, and an outstanding
token is still stopped at the action layer on mediated paths.

The AAuth binding has a narrower structural chokepoint. The Person
Server refuses new person-token issuance, PS authorization, or
federated brokering for a terminated Mission Context, bounding those
paths by token lifetime. Agent identity and resource-managed access do
not cross that chokepoint. AAuth supplies the Mission Context
capabilities in its own idiom but not a portable Authority Set or
universal subset rule. The AAuth binding defines no generic family
runtime composition or independently resource-verifiable Authority Set
({{I-D.draft-mcguinness-mission-aauth}}).

Per-action enforcement is budgeted, not blanket:

- only consequential actions are gated;
- the common-case decision is a local evaluation against a
  materialized policy view whose network cost is paid per freshness
  window; and
- the runtime profile requires a synchronous gate only for the
  high-consequence classes (the runtime profile's deployment
  considerations, {{I-D.draft-mcguinness-mission-runtime}}).

Runtime enforcement composes as an overlay, not a substrate swap: a
deployment mediates the paths where the high-consequence classes live
and lets every other resource ride lifetime-bounded reliance
({{assurance-level-definitions}}), with token lifetimes sized to the
tolerated staleness and no state evaluation at the resource.

The standalone mode trades the token-layer kill switch for zero
Authorization Server changes. A MAS creates, approves, and serves
Missions while tokens remain ordinary; the PDP joins credentials to
Missions, and the MAS is the freshness source. The cost is structural:

- no `mission` claim travels;
- revoking a Mission stops nothing at the token layer; and
- enforcement rests entirely on PEP coverage, so a token exercised
  outside that coverage is ungoverned (the MAS's Limitations section).

The path to a token-layer chokepoint is the OAuth binding, where the
estate's AS can change; the record, anchors, and lifecycle carry over
unchanged. That is a move between peer architectures, not an upgrade
from a lesser one: the MAS remains a peer binding, not a staging area
(its own document's framing).

Between those two architectures sits the issuance join
({{I-D.draft-mcguinness-oauth-mission-issuance-grant}}): the MAS remains
the Mission Issuer while estate Authorization Servers redeem Mission
Issuance Grants for Mission-bound, state-gated tokens, restoring the
token-layer chokepoint without moving approval.

# Mission Assurance Levels {#assurance-levels}

This document uses six frames for what a deployment does and what
it can show. Each answers a different question, and none substitutes
for another:

| Frame | Question it answers | Where |
| --- | --- | --- |
| Verbs | What happens to a Mission and its authority | {{layers}} |
| Assurance levels | Which capabilities a deployment adopts, in the order deployments build them | {{assurance-level-definitions}} |
| Assurance claims | What a relying party can verify | {{assurance-claims-axis}} |
| Binding properties | Which relationships a path establishes: attachment provenance, credential binding (with presenter key and instance), and action binding | {{binding-properties}} |
| Containment properties | What a capability kill reaches, per action class and state source | {{containment}}, {{kill-switch-composition}} |
| Deployment Profile | Where a deployment declares all of the above | {{deployment-profile}} |
{: title="Assurance frames"}

The levels are **adoption bundles**: named sets of the documents a
deployment runs, so a deployment, a procurement, or a review can cite
one bundle. They are guidance, never a conformance class, an earned
label, or a ladder a deployment must climb. A deployment adopts the
bundle its risk warrants and stops there.

The levels build on one another in the order deployments build:
recording and governing the approved task (Baseline Issuance), then
per-action enforcement (Runtime-Enforced), then agent governance and
compromise resistance (Governed Agent and High-Assurance Agent).

A level does not determine any action class's containment property.
The proof obligations noted with a level are the claims that
become available at that bundle, not properties the level name
asserts. A relying party compares claims, not levels
({{assurance-claims-axis}}), because the family's strongest
properties are deployment properties, not protocol properties:
complete PEP placement, a trusted freshness source, and credential
custody are things a deployment does, not things a token proves.

The binding is an orthogonal axis, not a level: the authority-bearing
bindings name their level separately from their binding. The
standalone MAS provides the Mission record, lifecycle, and authority
but no Mission-bound credential and no issuance gating. Under the
standalone MAS, the kill switch is the runtime layer alone, not the
token gate, and a deployment states that.

An AAuth deployment reports the Mission Context capabilities and
resource access modes it uses instead of a level. Selecting the AAuth
binding does not by itself satisfy structured-authority, subset,
portable-evidence, or runtime proof obligations. The AAuth binding's
lifecycle gate covers the PS-gated modes but not agent identity or
resource-managed access, and the binding's native auth token is
Mission-referenced, not Mission-bound ({{token-classes}}).

## The Four Levels {#assurance-level-definitions}

Each level includes the one before it:

**Baseline Issuance**:
: the approved, anchored Mission record and its lifecycle: authority
  derived and committed at the approval event with the integrity
  anchors (the OAuth binding).

  **Credential-issuing bindings**: where a structured-authority binding
  issues Mission-bound credentials, issuance is bounded by the subset
  rule and gated on Mission state. That gated issuance grants
  task-bound, auditable authority and a possession-independent kill
  switch at the issuance gate. It grants no per-action control, and
  outstanding tokens run to their own expiry.

  Sized deliberately, that expiry is the level's revocation bound.
  **Lifetime-bounded reliance**, access-token lifetimes no longer than
  the deployment's tolerated staleness
  ({{I-D.draft-mcguinness-oauth-mission-status}}), gives a quantified
  cutoff: revocation within one token lifetime on every path whose
  minting checks current Mission state, with no Resource Server
  changes and no status traffic. Expiry closes the temporal
  bound by the clock alone and observes no revocation, suspension,
  completion, or containment, so the lifetime must not exceed the
  tolerated staleness. Revocation latency is a number, not a level:
  the higher levels add per-action enforcement, parameter binding,
  and evidence, not a faster clock.

  **Standalone MAS**: under a binding without credential-carried
  authority, Baseline grants governance and audit. No kill switch of
  any kind exists under such a binding until a freshness surface and
  runtime enforcement (the next level) arrive, and a deployment states
  that. The issuance join
  ({{I-D.draft-mcguinness-oauth-mission-issuance-grant}}) restores
  gated issuance at each consuming Authorization Server, and Baseline
  with it. At a consuming Authorization Server that checks no Mission
  state at redemption, the bound is the grant's remaining redemption
  time plus the issued token's lifetime ({{validity-model}}).

  **AAuth**: the nearest comparison, stated as capabilities rather
  than a level, is native approval, exact-byte commitment, active or
  terminated state, and the ordered mission log. The
  possession-independent issuance cutoff applies only to person-token
  issuance and to PS authorization and federated requests whose
  resource token carries the validated Mission Reference. No Authority
  Set or subset proof is implied.

  **Proof obligations**: the anchored approval and, where credentials
  are issued, the subset rule.

  Where the binding gates issuance, a deployment that adds only a
  freshness surface (Mission Status or introspection with a published
  staleness bound, {{I-D.draft-mcguinness-oauth-mission-status}})
  gains state-aware reliance: a revocation cutoff within that bound,
  without per-action enforcement. That is a half-step into the next
  level, not a level of its own.

  **Verification**: illustrative scenarios for this level, each traced
  to the rule its home document states, are in
  {{verification-guidance}}.

**Runtime-Enforced**:
: adds a PEP/PDP decision on every consequential action, a trusted
  state source with a published staleness bound, parameter binding,
  and runtime evidence ({{I-D.draft-mcguinness-mission-runtime}} and
  its AuthZEN profile).

  **Grants**: per-action enforcement and bounded revocation (for
  gated classes, within the staleness bound plus the permit window
  plus the class's execution bound; for paths no runtime gate
  reaches, within token lifetime where issuance is gated).

  Runtime-Enforced is the smallest deployment that turns a Mission
  from governed issuance into action-time defense. Every normative
  dependency it needs is a family document intended for the Standards
  Track. It is a substantial build, not a wedge: a deployment sizes
  the effort from the runtime profile's conformance section rather
  than from this level's one-line summary.

  **Proof obligations**: PEP-placement completeness and the declared
  freshness source and bound.

  **Documents**: Baseline plus the substrate contract (the kernel that
  runtime and AuthZEN consume normatively), runtime, its AuthZEN
  profile, runtime evidence, and a concrete freshness source (Status
  is the reference choice).

**Governed Agent** (recommended for AI agents):
: adds Consent Evidence and the harness, growing with Child
  Delegation, Expansion, Orchestration, and Discovery (experimental,
  with Progressive) as needed.

  **Grants**: consent-rendering evidence and session-continuity
  discipline.

  **Documents**: Runtime-Enforced plus consent-evidence and the
  harness.

**High-Assurance Agent**:
: adds the guarantees that resist a compromised agent. Two named
  claims live at this level, each with proof obligations the runtime
  profile fixes.

  **Agent-compromise-resistant enforcement**: mediated (gateway)
  credential custody, a declared-and-audited path scope,
  action-bound approval for the high-consequence classes, an
  active-freshness state source, and approval disclosures rendered
  by a component isolated from the agent. With these, a compromised
  agent cannot unilaterally take a high-consequence action for which
  it does not hold a mediated credential.

  **Trifecta containment**: least exposure, the harness taint rule
  enforced as a mandatory requirement of the harness profile, with
  pre-consented egress to Approver-named destinations as its one
  carve-out; and full mediation of the external-communication and
  external-commitment classes with the egress-channel enumeration.
  With both halves, an injected agent cannot egress on the strength of
  untrusted content alone.

  Both claims are named high bars, never implied by basic adoption.
  Each requires execution-environment attestation of the Enforcement
  Scope Statement, with the evidence bindings the runtime profile
  fixes, so the claim is technical rather than organizational; base
  runtime conformance requires no attestation
  ({{I-D.draft-mcguinness-mission-runtime}},
  {{I-D.draft-mcguinness-mission-harness}}).

Read in adoption order, each level makes a broader class of agent
work defensible to grant.

| Level | What a deployment can defensibly grant |
| --- | --- |
| Baseline Issuance | Consequential reads and writes outside the high-consequence classes whose bounds the receiving Resource Server enforces, attributable and killable at the issuance gate, outstanding tokens running to their own expiry or the next introspection |
| Runtime-Enforced | Consequential actions that need a per-action decision: parameter-bound writes and bounds finer than the receiving Resource Server enforces; reversal and compensation stay the orchestration profile's, where adopted |
| Governed Agent | Unattended operation and delegation, with Consent Evidence binding each approval event |
| High-Assurance Agent | The high-consequence classes ({{I-D.draft-mcguinness-mission-runtime}}), under mediated custody and action-bound approval |
{: title="What each level makes defensible to grant"}

The mapping is informative: the action classes are the runtime
profile's ({{I-D.draft-mcguinness-mission-runtime}}), resource policy
remains authoritative for its own objects, and what a level grants
varies with the binding. A deployment states its own
`mediated_action_classes` and exclusions in the Mission Deployment
Profile ({{deployment-profile}}).

Every level above Baseline Issuance also carries the cross-cutting
obligations its mechanisms imply:

- operation-profile normalization where duration or parameter
  digests are metered ({{I-D.draft-mcguinness-mission-metering}},
  {{I-D.draft-mcguinness-mission-authzen}});
- evidence retention for the audit horizon; and
- a registration schedule where audit transparency is run
  ({{I-D.draft-mcguinness-mission-audit}}).

The evidence mechanisms are accountability, not prevention: they make
what was recorded tamper-evident, not what was perceived true or
what was never recorded present.

## The Reference Architecture {#reference-architecture}

The four levels are also the four reference stacks deployments take,
each containing the previous. The stacks are expressed in the OAuth
realization. A peer binding realizes the levels per its own document,
and peer standing does not imply identical levels or capabilities. The
family manifest records each stack's exact membership.

- **Protocol core** (Baseline Issuance): the OAuth binding alone, the
  standardizable primitive of approved, anchored, state-gated
  Missions, meeting the Mission Context requirements ({{requirements}}).
- **Reference security architecture** (Runtime-Enforced): the
  protocol core plus runtime enforcement, its AuthZEN profile,
  runtime evidence (the decision and execution objects AuthZEN
  consumes), and a freshness source (Status is the reference choice).
  Adoption closure brings in the substrate contract, the normative
  kernel of runtime and AuthZEN.
- **Recommended agent architecture** (Governed Agent): what a
  deployment running autonomous AI agents should build.
- **High-assurance architecture** (High-Assurance Agent): the
  recommended agent architecture plus mediated custody, no unmediated
  path, action-bound approval, active freshness, and agent-isolated
  approval rendering.

When this document says a Mission is enforced, it means the reference
security architecture, and an evaluation should picture it by
default. That architecture presumes an authority-bearing binding.
Under AAuth, the analogous per-action control is the Person Server's
contextual gate on PS-mediated paths
({{I-D.draft-mcguinness-mission-aauth}}).

## Assurance Claims {#assurance-claims-axis}

What a deployment can prove is an axis orthogonal to the levels:
named **assurance claims**, each with a proof obligation an existing
profile fixes, listed in the Deployment Profile
({{deployment-profile}}) rather than implied by a level:

- **Approved-record integrity**: the committed Intent, authority
  proposal, and Authority Set reproduce from the retained record alone
  (the OAuth binding's integrity anchors). The claim covers neither the
  record's provenance members nor an issuer that substitutes a record
  and its anchors together; defending against post-approval
  substitution takes an independently pinned anchor
  ({{I-D.draft-mcguinness-oauth-mission-approved-set-verification}}).
- **Bounded revocation latency**, per path and mechanism, naming the
  paths it covers: for a runtime-gated class, the published staleness
  bound plus the permit window plus the class's execution bound
  ({{I-D.draft-mcguinness-mission-runtime}}); for a lifecycle-gated
  path, the outstanding credential lifetime; for a path that remints
  without a fresh state check, the summed residual of
  {{validity-model}}; an ungated path has no bound to claim.
- **Action-time enforcement**: PEP coverage for the Enforcement Scope
  Statement's mediated set, and nothing outside it.
- **Parameter-bound enforcement**: permits bound to concrete
  parameters for the classes claimed.
- **Transaction-grade execution**: the runtime profile's
  transaction-assurance tier machinery (single-use permits, leases,
  outcome reconciliation) for the classes claimed
  ({{I-D.draft-mcguinness-mission-runtime}}).
- **Agent-compromise-resistant enforcement** and **trifecta
  containment**: the two named High-Assurance claims, as defined in
  {{assurance-level-definitions}}.

Two deployments at the same level under different bindings can hold
different claims; the MAS modes are the worked case
({{I-D.draft-mcguinness-mission-authority-server}}). A relying party
compares the claims, not the level.

## Mission Binding Properties {#binding-properties}

Whether an operation is bound to a Mission is not one question but
three:

- attachment provenance: who selected and attached the Mission to
  this work item?
- credential binding: was the acting credential's authority issued
  and bounded for the Mission?
- action binding: does one authenticated permit cover these exact
  operation inputs?

The three dimensions are independent. A native Mission-bound token has
strong credential binding with no harness in sight; a trusted harness
attributes work items precisely while the credential is an ordinary
bearer token; an action-bound permit can exist over either. No single
ladder orders them, so the family names the properties directly, as a
vector, and a deployment claims the combination each path has.

As an index of related properties, the table's entries relate to the
three dimensions as follows: `mission-reference-selected` and
`work-item-bound` to attachment provenance; `credential-correlated`,
`credential-mission-bound`, `presenter-key-bound`, and `instance-bound`
to credential binding; and `action-bound` to action binding. The index
establishes no property for any mechanism; the mechanism mapping below
states what each mechanism establishes.

| Property | Meaning | Minimum proof |
| --- | --- | --- |
| `mission-reference-selected` | A Mission tuple was supplied for routing and selection | The canonical (issuer, mission id) pair; grants nothing and makes no security claim |
| `work-item-bound` | A trusted component bound that tuple to this session, queue, or task item | An authenticated attacher, a tamper-resistant work-item identifier, and stated inheritance and retry rules |
| `credential-correlated` | The presented credential is correlated to the Mission's parties | A mapping join or Mission Join Assertion, with its stated ceiling |
| `credential-mission-bound` | The credential's authority was issued or derived for the Mission | The six conditions below |
| `presenter-key-bound` | The presenter proves possession of the key the credential is constrained to | Issuance-time key targeting (`cnf` or an equivalent confirmation) plus presentation-time proof of possession |
| `instance-bound` | The concrete acting instance is identified and holds the bound key | `presenter-key-bound` plus the instance requirements below |
| `action-bound` | An authenticated permit authorizes one operation, resource, and input projection | One of the two proof forms below |
{: title="Mission binding properties"}

The mapping join and the Mission Join Assertion are the MAS's
({{I-D.draft-mcguinness-mission-authority-server}}).

The properties are claimed per covered Authorization Server,
resource, and action path, never as a product-wide maximum. A mixed
estate claims what each path has, and a weaker path never inherits a
stronger path's claim from the deployment's name. Where policy
requires a property on a path, its absence denies; nothing falls
back silently to a weaker binding.

**Credential-mission-bound** is defined by equivalence, not by one
artifact. It is the family's authoritative definition of what earns
the term "Mission-bound", and it backs the Mission-bound token class
({{token-classes}}). For the covered path, the credential establishes
all of these conditions:

1. a trusted issuer authorized to issue for the Mission;
2. the canonical (`mission.issuer`, `mission.id`) pair identifying
   the Mission: the baseline Mission reference, and an identity
   condition only, never a token-carried Authority Set commitment;
3. an issued authority projection no broader than the Mission's
   Authority Set for the target audience;
4. the mapped subject, the requesting `client_id`, and actor or
   delegation context where applicable;
5. bounded lifetime plus active-state issuance and refresh gates; and
6. an auditable derivation link from the credential to the Mission's
   recorded Authority Set: the OAuth binding's Mission Record
   ({{I-D.draft-mcguinness-oauth-mission}}), an Issuance Grant `jti`
   ({{I-D.draft-mcguinness-oauth-mission-issuance-grant}}), a
   cross-domain projection's provenance
   ({{I-D.draft-mcguinness-oauth-mission-cross-domain}}), or an
   equivalently specified artifact. A token-carried Authority Set
   commitment, where a binding supplies one, strengthens this
   condition's local verifiability. It is never itself the
   Mission-identity requirement of condition 2, and its absence does
   not fail this condition where the issuer-retained record is
   otherwise reachable.

A binding earns the property by one of two routes, never by protocol
lineage. Either route must establish all six conditions for the
covered path:

- **Substrate route.** A binding that claims substrate conformance
  supplies its full Mission Substrate Statement
  ({{I-D.draft-mcguinness-mission-substrate}}, Section "Mission
  Substrate Statement"): its kernel mappings (among them the Mission
  Reference, the Controller, the Actor handle and identifier mappings,
  and the reliance bound) and its capability claims, together with the
  deployment's applicable issuer trust configuration and the validated
  credential's own evidence.
- **Binding route.** A binding that claims no substrate conformance
  establishes the conditions through its own specification and
  conformance requirements.

No fixed split assigns some conditions to the Statement and others to
the credential, and a capability label alone never establishes a
whole condition. Monotonic Derivation bears on condition 3, and
Lifecycle-Gated Authorization on condition 5's active-state gate, but
each condition also rests on the mappings, trust, and credential
evidence it depends on. The Substrate's Credential-Bound capability
can select correlation-only fact semantics
({{I-D.draft-mcguinness-mission-substrate}}), which by itself
evidences neither the derivation-link condition (6) nor the
authority-projection condition (3). A Credential-Bound claim alone,
whatever semantics it selects, never by itself evidences
`credential-mission-bound`: conditions 1 and 4 also rest on the
deployment's issuer trust configuration and the credential's own
subject, `client_id`, and actor claims, which no capability row
supplies.

The OAuth binding claims no substrate conformance and publishes no
Statement, so it takes the binding route: its own Conformance gates
establish the conditions, independent of the substrate contract
({{I-D.draft-mcguinness-oauth-mission}}). Its informative Mapping
Assessment explains that mapping and is not a conformance result;
OAuth conformance stays governed by the OAuth binding. The OAuth
binding's evidence for each condition:

| Condition | OAuth binding evidence |
| --- | --- |
| 1 | The Mission Issuer role and the applicable issuer trust |
| 2 | The validated `mission.issuer` and `mission.id` |
| 3 | The subset rule |
| 4 | The recorded parties and their required binding into issued credentials |
| 5 | Token lifetime bounds and the active-state issuance and refresh gates |
| 6 | The Mission Record, retained for the audit horizon, and the credential's derivation link to it |
{: title="How the OAuth binding establishes credential-mission-bound"}

Sender constraint is not among the six conditions. Issuance-time key
targeting and presentation-time proof are `presenter-key-bound`, a
separate property, so a path that needs possession requires the
composition rather than reading possession into the equivalence. The
mechanisms match: the OAuth binding recommends sender-constrained
tokens, and the generic Issuance Grant leaves `cnf` optional. Native
issuance, the Mission Issuance Grant, and a conforming cross-domain
exchange therefore satisfy the equivalence, and supply
`presenter-key-bound` exactly where their confirmation binding is in
force.

A verified Mission Join Assertion
({{I-D.draft-mcguinness-mission-authority-server}}) establishes
token-specific `credential-correlated`. For conditions 1, 2, and 4, it
authenticates the Mission reference and attests the party join, but
trusting the MAS's correlation does not establish that the acting
token's issuer issued its authority for that Mission. Conditions 3, 5,
and 6 stay unsatisfied by design; that gap is what separates correlation
from issuance. The assertion alone establishes neither possession nor
instance identity. On the joined path, `presenter-key-bound` comes from
the acting credential and its validated presentation: the MAS mints an
assertion only for a token with a `cnf` key, and the PEP reports that
key only after verifying the request's proof of possession, or the
certificate only after authenticating it on the request's mutual-TLS
connection.

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
  AuthZEN profile ({{I-D.draft-mcguinness-mission-authzen}})
  discharges it under exactly those conditions.

A parameter binding alone makes a response neither form. An
evaluation identifier alone is a correlator, never the property; it
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
- **runtime-action-bound**: Mission binding establishment
  ({{I-D.draft-mcguinness-mission-runtime}}, Section "Mission Binding
  Establishment") plus `action-bound`.

The family defines no work-item-attribution composition. Holding
`work-item-bound` and `action-bound` together does not prove the
permitted action came from that work item: concurrent items under
one Mission still substitute. The composition becomes definable only
when a verified cross-link exists: the action permit, or its
authenticated request context, binds the same tamper-resistant
work-item identifier the harness recorded. No family carrier
supplies that cross-link, so a deployment claims the two properties
separately and nothing more.

The mechanism mapping is conservative:

| Mechanism | Binding property it establishes |
| --- | --- |
| Propagated Mission-Reference | Selection only |
| Mapping join | `credential-correlated`, with its equivalence-class ambiguity |
| Mission Join Assertion | Token-specific `credential-correlated`, never issuance; `presenter-key-bound` comes from the acting credential's validated presentation, not from the assertion |
| Trusted harness | `work-item-bound`, where its attacher requirements hold |
| Native or issuance-grant-derived token | `credential-mission-bound`, and `presenter-key-bound` where its confirmation binding is in force end to end |
| Instance Context | what makes the path `instance-bound`, where its association with the presenter is established over an instance-unique confirmation key and, for context preserved from an input token, authenticated provenance ({{I-D.draft-mcguinness-oauth-client-instance-id}}, Sections 7.3 and 7.5) |
| Verified transaction token | The portable `action-bound` form |
| AuthZEN runtime permit | The channel-bound `action-bound` form, under that binding's conditions |
{: title="Mission binding mechanisms"}

The property names above are stable identifiers. A claim is a
per-path declaration, not prose: each claimed property or
composition names the covered issuer, resource, and action-class
paths. The Enforcement Scope Statement carries the per-path
declarations for the enforcement-adjacent properties, and the
Mission Deployment Profile ({{deployment-profile}}) composes them. A
binding's Statement declares what the binding can supply, which is
never itself a deployment claim. An unknown property identifier, an
undeclared path, or an unstated property is not claimed, and a
consumer treats it as not held; nothing downgrades silently.
Schema-level claim identifiers and validation rules remain the
Deployment Profile's own future work.

Binding properties and the assurance claims above compose rather
than repeat. A binding property says what a path establishes, from
the Mission a work item is attached to, through the credential,
presenter key, and instance, to the authorized action. An assurance
claim says what the deployment's enforcement proves. Credential-level
and action-level binding likewise compose rather than substitute.

## The Containment Matrix {#containment}

Mission termination is one control in a larger containment surface.
Each kill has a different blast radius, and an incident responder
needs the whole matrix:

| Control | Stops | Home |
|---|---|---|
| Capability kill | one capability within one Mission and the Child Missions it justifies: new derivation at once at commit; credentials already materialized under it run to their own bound unless a containment-aware action-time gate reaches them first ({{kill-switch-composition}}); the body of work still runs | the issuer-held containment overlay |
| Mission kill | one body of work: further derivation and refresh at once, and residual credentials at the earliest of an applicable revocation, a state-aware or runtime check that reaches them, or their own expiry ({{validity-model}}) | the OAuth binding's revocation; cascades to Child Missions |
| Agent kill | all work by one agent, across its Missions | the deployment's agent IAM ({{three-objects}}) |
| Agent Deployment kill | every instance running a compromised version | the deployment's change governance ({{three-objects}}) |
| Credential kill | credentials already issued | the binding's substrate, where it supports revocation; otherwise expiry ({{validity-model}}) |
| Workload kill | the running compute itself | the platform |
| Egress kill | the communication path | gateway and network controls |
{: title="The containment matrix"}

The issuer-held containment overlay is defined by
{{I-D.draft-mcguinness-oauth-mission-containment}}, and cascade
revocation to Child Missions by
{{I-D.draft-mcguinness-oauth-mission-child-delegation}}.

Mission termination participates in incident response; it does not
replace it. Revoking the Mission:

- stops issuance at once where the binding gates it;
- stops mediated actions within the staleness bound plus the permit
  window and the class's execution bound ({{validity-model}},
  {{assurance-claims-axis}}); and
- terminates no process and closes no network path.

The converse holds too: killing a workload leaves the Mission
`active` and its authority derivable to a replacement instance
unless the Mission is also revoked.

Capability kill provides, per action class and consumer, one of two
containment properties (named like, but distinct from, the levels of the
same name; {{kill-switch-composition}}) or neither, never by the
deployment's assurance level
({{I-D.draft-mcguinness-oauth-mission-containment}}, Section
"Containment Properties"):

- the Baseline property, a new-derivation kill that also propagates
  to Child Missions justified by the contained entry; and
- the Runtime-Enforced property, an action-time kill that also
  reaches a token issued before the transition.

A standalone MAS path with no runtime gate gets neither.
{{kill-switch-composition}} composes the properties by level and
binding, with what each leaves running.

A deployment's incident runbook names which of these controls exist,
who may pull each, and, per action class, which capability-kill
property its consumers obtain.

## Composed Kill-Switch Reality {#kill-switch-composition}

The words "Baseline" and "Runtime-Enforced" each have two meanings.
In {{assurance-level-definitions}}, they name a level a deployment
adopts. The containment profile
uses the same words for a property a consumer obtains per action
class ({{I-D.draft-mcguinness-oauth-mission-containment}},
Section "Containment Properties"). Level and property are not 1:1. A
Runtime-Enforced deployment can still provide only the Baseline
property for a class its Enforcement Scope Statement leaves
lifecycle-gated-only, because the property requires a
state-observable substrate per class, not per deployment
({{I-D.draft-mcguinness-mission-runtime}}). A row can therefore carry
a Runtime-Enforced level and a Baseline property together without
contradiction.

Each row below assumes a deployment that runs the containment profile,
at the row's level and under its binding. A level and a binding alone
confer neither containment property: containment is an overlay a
deployment adopts separately
({{I-D.draft-mcguinness-oauth-mission-containment}}). In the table,
"Stops at commit" is what a contain transition's own state-version
commit reaches immediately
({{I-D.draft-mcguinness-oauth-mission-containment}}, Section "The
Contain Transition"), and "Runs to its own bound" is the residual the
transition does not reach. In the cells, a quoted name is a section of
the containment profile
({{I-D.draft-mcguinness-oauth-mission-containment}}), or of the issuance
grant ({{I-D.draft-mcguinness-oauth-mission-issuance-grant}}) where the
cell says so; "runtime profile" is
{{I-D.draft-mcguinness-mission-runtime}}.

| Level | Binding | Property | Stops at commit | Runs to its own bound |
|---|---|---|---|---|
| Baseline Issuance | OAuth binding, structured-authority | Baseline, a new-derivation kill ("Containment Properties") | New derivation, delegation, and cross-domain projection minted after the transition ("Derivation Gating") | Tokens already issued, to `exp`, and a consequential read under the token-lifetime default, the same bound (runtime profile); pre-transition projection grants (note 1) |
| Baseline Issuance | Standalone MAS, no credential-carried authority | Neither; the runtime layer is the only cutoff, and it is absent at this level | Nothing at the resource; the transition commits and is visible on the Mission Status Response and the introspection projection ("Visibility") | Every action, to the resource's own bound, if any (note 2) |
| Runtime-Enforced | Any binding, a class using a containment-aware state source within its published bound (note 3) | Runtime-Enforced for that class ("Containment Properties"); Baseline only for the classes in note 4 | The contained capability, denied at the class's next gated action once the source reflects the overlay, within the staleness bound plus the permit window plus the class's execution bound (runtime profile) | Paths no action-time gate reaches: token lifetime where issuance is gated, otherwise no bound |
| Baseline Issuance | MAS as estate control plane, issuance join at each consuming AS | Baseline, from Derivation Gating at the Mission Issuer ("Derivation Gating") and, at a consuming AS with a Mission-state integration, from projecting each redemption and refresh through the Effective Authority Set (note 5) | New grant minting: the Mission Issuer's Derivation Gating evaluates the Effective Authority Set, so a grant minted after the transition excludes contained authority ("Derivation Gating"); and, at a consuming AS with a Mission-state integration, each redemption and refresh once its state source reflects the transition (issuance grant, "Effective Authority Set Projection") | An outstanding grant redeems once, within its 300-second lifetime, at a consuming AS without a Mission-state integration, which checks no Mission state at redemption and issues no refresh tokens; tokens already issued run to their own `exp` (issuance grant, "Redemption") |
| Runtime-Enforced | OAuth binding with offline attenuation, a consumer whose check is active-state only (note 6) | Baseline ("Containment Properties"): a contained Mission stays `active` | New attenuation roots, which exclude contained authority ("Derivation Gating") | Roots minted before the transition, to their own lifetime (note 6) |
{: title="What a capability kill stops, and what runs to its own bound"}

Notes:

1. Under the OAuth binding at Baseline Issuance, a cross-domain
   projection grant already redeemed before the transition runs to its
   own lifetime ({{I-D.draft-mcguinness-oauth-mission-containment}},
   Section "The Materialized-Capability Residual"). Offline attenuation
   is not accepted at this level (note 6).
2. Under the standalone MAS at Baseline Issuance, every action runs to
   whatever native credential, session, or resource-local bound the
   resource enforces on its own, if any. It does so until runtime
   enforcement over a freshness source arrives or the issuance join
   restores a gate
   ({{I-D.draft-mcguinness-oauth-mission-issuance-grant}}).
3. Under any binding, a containment-aware state source is full Status or
   introspection carrying `containment_version`, or Signals carrying the
   overlay change.
4. Under any binding, where a class is checked only against an
   active-but-not-containment-aware source, left lifecycle-gated-only,
   or gated only by fresh derivation, it gets the Baseline property
   only, regardless of level ({{I-D.draft-mcguinness-mission-runtime}}).
   A fresh derivation narrows what it mints and can shorten the
   residual, but it checks nothing at action time, so it carries the
   Baseline property, not the Runtime-Enforced one
   ({{I-D.draft-mcguinness-oauth-mission-containment}}, Section
   "Containment Properties").
5. Under the MAS as estate control plane, a consuming AS either has a
   Mission-state integration or has none
   ({{I-D.draft-mcguinness-oauth-mission-issuance-grant}}, Section
   "Effective Authority Set Projection"). One that has it projects
   every redemption and refresh through the Mission's current
   Effective Authority Set, so its issuance excludes contained
   authority within its published staleness bound. A lifecycle-state
   check alone, under which a contained Mission still reads `active`,
   is not such an integration. One that has none checks no Mission
   state at redemption, issues no refresh tokens, and relies on the
   Mission Issuer's minting gate, so a grant minted before the
   transition can still redeem within its 300-second lifetime, and the
   token it yields then runs to its own `exp`: the residual is the two
   summed ({{validity-model}}).
6. Under the OAuth binding with offline attenuation, a consumer accepts
   a chain only under runtime enforcement, with a fresh active-state
   check on every presentation regardless of action class
   ({{I-D.draft-mcguinness-oauth-mission-attenuation}}, Section "The
   Kill Switch Requires Runtime Enforcement"), so no Baseline-only,
   lifetime-only path accepts one. Revoking the Mission fails that
   check, so acceptance of every chain stops within the deployment's
   declared freshness bound. Containing an entry leaves the Mission
   `active`, so the same check does not stop a root minted before the
   transition from supporting the contained capability: the root keeps
   minting narrower children for its own lifetime, and its
   `del_max_depth` limits how deep they go, not how long they live
   ({{I-D.draft-mcguinness-oauth-mission-containment}}, Section "The
   Materialized-Capability Residual"). Claiming the Runtime-Enforced
   property for attenuated chains needs a containment-aware action-time
   check (note 3).

None of this closes the conforming Baseline residual on a path or for
a class no containment-aware action-time gate reaches. For a class a
Runtime-Enforced action-time gate reaches instead, a pre-transition
credential does not run to its own bound at all. Where the residual
does persist, the binding determines the artifact and its cutoff: an
ungated standalone-MAS path, for instance, runs to the resource's own
bound, if any (note 2), or to none, not to a token lifetime. What
changes row to row is which gate, if any, reaches a class before its
own bound, and how tight that bound is.

## Prevention, Detection, and Residue {#prevention-detection}

Each layer earns a specific property and leaves a specific residue:

| Mechanism | Prevents | Detects | Does not solve |
|---|---|---|---|
| Core issuance | over-issuance beyond the approved authority; issuance after revocation or expiry | the approved authority (anchored) | action-time misuse within scope |
| Runtime enforcement | an unauthorized action on a mediated path | each PDP/PEP decision (evidence) | actions on an unmediated path |
| Consent Evidence | silent divergence between what was shown and what was committed | the rendered disclosure | whether a human perceived or understood it |
| Audit Transparency | undetectable log tampering or omission (under expected registration) | the evidence timeline | a producer logging a false record |
| Mandate | reliance on unverifiable committed facts | portable Mission facts | authority (it grants none) |
{: title="What each layer prevents, detects, and leaves"}

In each layer, the family commits and checks what a party was shown,
decided, or did. It does not make the human attentive, the producer
honest, or the unmediated path disappear. Those are the residues the
Mission Assurance Levels ({{assurance-levels}}) and the security
model make a deployment state rather than assume. The input arm
({{survivable-incorrectness}}) carries the same honesty in the other
direction.

# Mission Deployment Patterns {#deployment}

A deployment enters the family from the estate it already runs
({{entry-ramps}}). It can stop at issuance alone ({{issuance-only}}),
adopt Missions one short task at a time ({{short-mission}}), and
compose named patterns for untrusted input ({{quarantine-pattern}})
and for work that never ends ({{standing-agent}}). The Deployment
Profile states what it built ({{deployment-profile}}).

## Entry Ramps by Estate {#entry-ramps}

The estate a deployment already runs, not preference, decides which
chokepoint it builds first. The OAuth binding's issuance ramp assumes
an Authorization Server that supports pushed authorization requests,
rich authorization requests, and JWT access tokens. The standalone
ramp assumes none of that and trades it for PEP coverage. By starting
condition:

| Estate starting condition | Entry ramp | Day-one delta |
|---|---|---|
| AS changeable; PAR, RAR, and JWT access tokens in place | The OAuth binding | AS adds intent intake, derivation, approval, record, and gating; a Mission-creating client changes with it, submitting `mission_intent` through PAR and handling Mission responses and lifecycle refusals; scope-only Resource Servers continue unchanged at scope grain, per-entry constraints reaching them only through a projection or a PEP |
| AS changeable; RAR absent or tokens opaque | MAS first; the OAuth binding once the AS gains the token plane (a peer move, not an upgrade) | A MAS beside the AS; tokens are unchanged, while governance requires approval integration and Mission correlation, and enforcement waits on PEP/PDP coverage with a trustworthy join |
| AS cannot change (shared, third-party, SaaS) | Standalone MAS, phase by phase | Records and approvals first; enforcement arrives with PEP/PDP coverage |
| Many Authorization Servers, one governance point | MAS as estate control plane; issuance join per consuming AS | Each AS adds grant redemption only |
| No PEP/PDP over consequential paths | The OAuth binding where the AS allows; the runtime layer where a class needs it | Lifetime-bounded reliance (short tokens, gated refresh); the runtime overlay added later, where the high-consequence classes live |
{: title="Entry ramps by estate"}

Grant redemption and the issuance join are defined by
{{I-D.draft-mcguinness-oauth-mission-issuance-grant}}. Every row shares
the record, anchors, and lifecycle, so a ramp is an entry point, not a
fork: Missions carry unchanged from any row to the rows a deployment
adopts later.

## The Issuance-Only Deployment {#issuance-only}

The entry-ramp table's last row is a deployment in its own right, the
**issuance-only deployment**: the Authorization Server and the
Mission-creating client change, and Resource Servers need not be
Mission-aware. A delegated token reaches only a Mission-aware Resource
Server, so a delegate calling any other resource runs under a Child
Mission where child creation is authorized
({{I-D.draft-mcguinness-oauth-mission-child-delegation}}).

The OAuth binding's invariants carry the deployment:

- every derived token is a subset of the Authority Set;
- no audience receives a grant it would over-grant on; and
- no credential outlives the Mission's expiry.

The deployment sizes token lifetime to its tolerated staleness. Where
the Authorization Server offers introspection, a Resource Server that
introspects per request stops honoring a token at its next request
once the Mission leaves `active`, with no Mission-specific code
({{I-D.draft-mcguinness-oauth-mission}}).

The deployment claims approved-record integrity and bounded revocation
latency ({{assurance-claims-axis}}); {{deployment-profile-examples}}
shows its Deployment Profile. The runtime layer
({{I-D.draft-mcguinness-mission-runtime}}) joins for the
high-consequence classes and for an action class that needs:

- per-action evaluation or evidence;
- approval bound to a single action; or
- a bound the receiving Resource Server cannot enforce.

## The Short Mission {#short-mission}

One ramp cuts across the rows: the **short mission**, a Mission whose
`expires_at` sits minutes out, run in records mode with
lifetime-bounded reliance. It is a durable approval record with
TTL-grade operational cost: audit, anchors, and bounded exposure with
no external state-observation surface. The issuer still owns Mission
state and the issuance gate ({{validity-model}}). A deployment can
adopt the family this way first, per task, and add state surfaces
only where missions grow long enough to need suspend, complete, or
kill-now.

## The Quarantine Pattern {#quarantine-pattern}

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

Where untrusted input and egress must stay separate within one
Mission, the metering profile's exclusivity control
({{I-D.draft-mcguinness-mission-metering}}) latches read-and-egress
apart under a single approval.

The pattern applies the invariants' work-products reading
({{invariants}}) to deployment: a work product is input, not
authority, and the producing Mission's authority does not transfer
through the artifact by copying, referencing, embedding, or
communicating it. The Mission Work Products companion
({{I-D.draft-mcguinness-oauth-mission-work-products}}) defines the
provenance object that attributes an artifact without granting
anything.

Ingesting a work product adds a conjunctive gate at the receiving
Mission's boundary. That gate composes with the three objects'
independent gates and does not nest inside them, so Agent identity,
Agent Deployment, and Mission stay a gating pipeline, not a
containment hierarchy ({{three-objects}}).

## The Standing-Agent Pattern {#standing-agent}

The **standing-agent pattern** governs the agent whose work never
ends. The agent stands; the authority cycles. The standing thing is a
charter: a Mission with a consented authority ceiling and drawdown
policy ({{I-D.draft-mcguinness-oauth-mission-progressive}},
experimental). The working thing is the bounded Mission each unit of
work draws under the charter, as an in-ceiling successor or a
policy-approved Child Mission
({{I-D.draft-mcguinness-oauth-mission-child-delegation}}). Each unit
Mission expires and discharges as its unit completes
({{I-D.draft-mcguinness-oauth-mission-status}},
{{I-D.draft-mcguinness-oauth-mission-discharge}}).

The progressive profile's prohibited set keeps the high-consequence
classes on a fresh human approval inside the ceiling. Its Ceiling
Review bounds the chain in time with an evidence-rendering renewal.

Without the progressive profile, the same pattern runs as ordinary,
freshly approved unit Missions with deferred approval
({{I-D.draft-mcguinness-oauth-mission-approval}}) absorbing the
volume: the experimental profile changes the unit economics, not the
governance shape.

## The Mission Deployment Profile {#deployment-profile}

The Mission Assurance Levels ({{assurance-levels}}) name what to
deploy, and the assurance claims ({{assurance-claims-axis}}) name
what may be proven. A claim is only checkable if a deployment states,
concretely, what it enforces and what it leaves outside the boundary.

The **Mission Deployment Profile** is that statement as a system-level
artifact: the published composition of the per-layer statements the
profiles demand, in one object an auditor, a procurement, or a
security review can read. It includes each statement where its
profile is run:

- the runtime profile's Enforcement Scope Statement;
- the harness environment statement;
- the MAS mapping contract;
- the Resource Server coverage split;
- the transparency-service topology and schedule; and
- the progressive profile's bounds and ceiling-review cadence.

The profile composes existing statements rather than restating them:
each fact's owning profile governs its meaning and normative force,
and this document fixes no serialization. A machine-readable manifest
schema, with stable claim identifiers and validation rules, is
deferred family work. Until it exists, the shapes in
{{deployment-profile-examples}} are illustrative, and the per-profile
statements are the checkable form.

Its distinguishing field is `residual_risks`: the profile is not
credible unless it states, in the same object as its guarantees, what
it does not cover.

The `evidence` member carries the deployment's evidence-handling
posture beside its guarantees: the field-classification scheme its
records use, whether access to Mission evidence is itself audited,
and the erasure policy that pairs retention with deletion
accountability ({{I-D.draft-mcguinness-mission-audit}}).

The `key_custody` member declares the custody a deployment states for
each signing key it operates, as a list keyed by key and application
rather than one row per key class. Each entry states:

- its key class, one of the five classes
  {{I-D.draft-mcguinness-mission-security-model}} enumerates: issuer
  signing, evidence signing, agent sender-constraint, mediating-PEP
  custody, attenuation roots;
- the artifact classes or `kid` selector it covers (the OAuth binding
  recommends segmenting issuer signing keys by artifact class under
  distinct `kid` values within one `jwks_uri`,
  {{I-D.draft-mcguinness-oauth-mission}});
- the holder, and whether the key is exportable;
- its generation and signing-use controls;
- a reference to its documented compromise-recovery procedure; and
- any attestation or verifier reference for that key.

`software` and `hsm_or_kms` are example holder values naming a
mechanism family, not an assurance grade. This document defines
neither as a normative custody-grade enum and fixes no validation
rule for either. `key_custody` makes the trusted-base key-custody
statement that {{I-D.draft-mcguinness-mission-security-model}} already
requires legible in the Deployment Profile; it does not make that
statement checked. Custody assurance stays open until a normative
reader or verifier for this declaration exists.

Two deployments that both "support Mission" but publish different
Deployment Profiles provide different security properties; the
profile makes that difference legible.

# Security Considerations {#security-considerations}

This document defines no wire mechanism. Each profile's own Security
Considerations remain normative, and the consolidated trusted base
and compromise analysis are the Mission Security Model's
({{I-D.draft-mcguinness-mission-security-model}}). This document
introduces composition, and its security subject matter is the risks
that emerge only at composition:

- stale state and materialized authority: an already-issued credential,
  redeemed grant, or minted attenuation root stays usable to its
  artifact-specific bound only where no timely state-aware or
  action-time gate reaches it. For a contained capability, it stays
  usable to that bound only where, in addition, no containment-aware
  gate reaches it ({{kill-switch-composition}}). Where any such gate
  does reach it, reliance ends at that earlier gate
  ({{validity-model}}, {{kill-switch-composition}});
- unmediated paths: enforcement claims hold only inside the declared PEP
  boundary, and the Enforcement Scope Statement's exclusions are where a
  compromised agent goes first;
- semantic-derivation trust: the derivation boundary
  ({{derivation-boundary}}) concentrates meaning-to-authority
  translation at the issuer, and the anchors commit its output, not its
  correctness;
- component compromise: issuer, PDP, PEP, state source, and evidence
  producer each void a different guarantee when compromised, and the
  security model prices each;
- context splicing and join ambiguity: independently valid identity,
  credential, and Mission facts compose into an unauthorized whole
  wherever they are combined without an authorized joining authority,
  verified inputs, an association policy, and conflict handling
  ({{I-D.draft-mcguinness-mission-substrate}});
- false but correctly signed evidence: signatures make records
  tamper-evident, never true; and
- correlation: the Mission Identifier, actor chain, and evidence joins
  that make audit possible are the same joins that correlate activity
  across audiences ({{privacy-considerations}}).

# Privacy Considerations {#privacy-considerations}

The privacy properties of the Mission record and the Mission Intent are
the OAuth binding's ({{I-D.draft-mcguinness-oauth-mission}}), for it and
for the bindings that import its record, and each adopted profile's; the
AAuth binding's are its own, below. This document describes them and
adds no data element of its own.

The OAuth binding's Privacy Considerations cover Mission Identifier
correlation, token payload disclosure, and Intent retention, with the
audit profile's erasure record as the transparency-side mechanism
({{I-D.draft-mcguinness-mission-audit}}). The status profile's
anti-oracle property bounds what its status surfaces disclose
({{I-D.draft-mcguinness-oauth-mission-status}}).

Read across profiles, the dataflow concentrates in three places:

- the record and its evidence at the issuer (task prose, principals,
  authority, provenance);
- the decision and execution evidence joined on the Mission Identifier
  at the runtime and audit layers; and
- the correlation surface that identifier creates wherever it travels
  (tokens, status responses, evidence, receipts, the Mandate).

Minimization has one shape everywhere:

- audience-scope what each party receives;
- prefer audience-scoped references over content (a stable reference
  reused across audiences is itself a correlation surface); and
- let the record's access governance, not possession of a reference,
  decide who reads the concentrated view.

In the AAuth binding ({{I-D.draft-mcguinness-mission-aauth}}), the
private mission blob never leaves the agent and the Person Server, and
the stable Mission Reference (`mission_s256` with the approving PS) is
a correlation handle across every resource that sees it. The mission
log concentrates a detailed activity history at the Person Server,
where the binding's minimization and retention duties apply.

# IANA Considerations {#iana}

This document makes no IANA request.

--- back

# Mission Requirements {#requirements}

The requirements the family answers are stated implementation-neutrally;
each names its answering documents by short form ({{document-map}}).
They stand on their own as a checklist, but conformance is
capability-layered rather than measured by resemblance to the OAuth
wire model ({{I-D.draft-mcguinness-mission-substrate}}).

The first four properties are a compact restatement of the substrate
contract's kernel ({{I-D.draft-mcguinness-mission-substrate}}). A
design provides the shared **Mission Context** capabilities when they
hold:

1. **An approved task context**: the task is durable and explicitly
   approved rather than only a session or token.
2. **Stable binding and integrity**: a native reference binds the
   controlling authority, acting actor, and immutable approved context,
   or a verifiable commitment to that context. Propagation or
   correlation rules carry the reference across parties without
   conferring authority.
3. **Lifecycle gate with a reliance bound**: only an active context
   supports new governed decisions at the binding's declared control
   point, and no decision or artifact outlives both its stated bound
   and the transition that ends the context.
4. **Governance history**: decisions and interactions are correlated to
   the stable reference in an ordered audit or governance record.

Two further properties are separately claimable capabilities, not one
bundle. The second requires the first, and a design can hold the
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
   done requires Execution Evidence for the covered classes. With
   those adopted, what was approved, shown, decided, and done is
   reconstructible from the join.

AAuth supplies the first four natively (its `expires_at` member
carries the reliance bound), with its lifecycle gate scoped to PS
endpoints and PS-mediated paths carrying the validated reference.
The OAuth binding supplies both authority capabilities as well.
Runtime and portable evidence remain separately claimed capabilities.
The requirements below unpack the family mechanisms without implying
every binding implements every one.

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

- **R8**: New reliance is gated on task state: only `active` permits a
  new governed decision, unrecognized states fail safe, and an
  already-issued artifact ends at its bounded residual (oauth-mission).
- **R9**: Revocation is independent of credential possession, and state
  changes propagate by pull or push (oauth-mission;
  oauth-mission-status; oauth-mission-signals).
- **R10**: A task can be suspended and resumed without being terminated
  (oauth-mission-status).
- **R11**: Authority widens only through an approved successor: a fresh
  approval, or policy drawdown within a ceiling a human pre-consented
  (oauth-mission-expansion; oauth-mission-progressive).
- **R12**: Authority retires per entry when the work an entry served is
  done (oauth-mission-discharge).

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
  topology alone neither restarts nor extends one. Representation is
  profile-specific. Issuer-mediated delegation nests `act`, and
  holder-mediated attenuation reconstructs history from per-hop
  actors. Cross-domain projection carries no upstream `act` chain, so
  any destination-domain chain begins locally. Actor identity is
  attribution and policy input; it does not itself grant or prove
  authority (oauth-mission; oauth-mission-child-delegation;
  oauth-mission-expansion; oauth-mission-attenuation;
  oauth-mission-cross-domain).

# Comparison to a Conventional Stack {#standardization-crossovers}

A skeptic of this family asks why Rich Authorization Requests
{{RFC9396}}, short-lived tokens, and an AuthZEN PDP holding policy and
session state server-side would not suffice.

- RAR supplies structured authorization data an Authorization Server
  renders into an itemized approval experience. RAR itself guarantees
  neither approval fidelity nor a consent UI.
- A short token lifetime bounds revocation only when every issuance,
  refresh, and exchange path re-evaluates current grant or session
  state. Absent that discipline, a fresh short token keeps issuing
  against stale state regardless of lifetime ({{validity-model}}).
- AuthZEN specifies a decision API, not a global PDP, a durable
  session store, complete PEP placement, or a state model. A
  deployment supplies those properties in either design.

Inside one administrative domain, a conventional stack (structured
request data, an Authorization Server's consent or grant record,
short credentials, and a stateful PDP) implements durable task
state, fan-out joins, persistent narrowing, and audit locally. Five
places mark where that local composition meets what this family
standardizes:

| Requirement | Conventional OAuth+PDP realization | Mission standardization | Illustrative added Mission cost |
|---|---|---|---|
| Durable task semantics across tokens and restarts | OAuth grants, refresh families, or PDP records outlive the token | An independently addressable, lifecycle-bearing approved task with anchors consistently interpreted by the Authorization Server, PDP, agents, audiences, and evidence producers; it does not make persistence newly possible (the OAuth binding's Why a New Object and Relationship to Other Authorization Objects sections) | Durable-object and lifecycle storage |
| Multi-credential, multi-actor join | A deployment-invented transaction, grant, or workflow identifier shared across credentials | Stable approved-task semantics for that join, bound to authority and carried through delegation and fan-out outside one private PDP schema ({{swarm-execution}}) | New claims and endpoints |
| A second trust domain | The partner calls the origin PDP, shares state, or federates policy, trading synchronous coupling, availability, and disclosure | Bounded local credentials and common anchors carried by Cross-Domain Projection, accepting local-token revocation latency (the Project verb): a portability choice, not the only possible design | State consistency and distribution; privacy and correlation surface |
| Approval as a first-class record | A local consent or grant database plus versioned decision logs | A standardized immutable snapshot, integrity anchors, and one reference portable evidence can cite (the OAuth binding's Why a New Object section; the Prove verb) | Evidence operations |
| Persistent narrowing | A stateful Authorization Server or PDP stores reduced entitlements and consults them at issuance | Monotonic subset semantics across issuance, delegation, attenuation, and cross-domain projections, auditable across components ({{invariants}}) | AS or MAS integration; ecosystem adoption |
{: title="Where a conventional stack meets Mission standardization"}

The OAuth binding's sections named in the table are in
{{I-D.draft-mcguinness-oauth-mission}}. Past these crossovers, a
conventional deployment often accumulates a durable task record, a
stable join key, lifecycle checks, narrowing rules, and audit
correlations. Mission standardizes that recurring shape across bindings
and trust domains; it does not claim local policy systems cannot
implement equivalent outcomes.

# A Worked Composition {#worked-composition}

This non-normative example shows that the substrate contract
({{I-D.draft-mcguinness-mission-substrate}}) carries the weight. It
composes a deployment that enforces at action time from four
providers, none of which is the OAuth binding. An AAuth agent acts
under a PS-governed Mission and calls a payment API whose authority
vocabulary the resource owns.

Four components publish provider claims:

| Provider | Capability supplied | Scope |
| --- | --- | --- |
| AAuth Person Server | Contextual-governance kernel; Lifecycle-Gated Authorization | PS permission decisions and PS-brokered issuance |
| AAuth Mission Management | State-Observable | The payment PDP, maximum staleness five seconds |
| Payment policy adapter | Structured Authority | Payment API actions and constraints under the payment policy's own versioned vocabulary |
| Payment gateway PEP/PDP | Authorized Context Correlation | The `schedule_payment` and `release_payment` routes |
{: title="Provider claims in the worked composition"}

The runtime profile and its evidence companion supply action-time
enforcement and decision evidence at the gateway
({{I-D.draft-mcguinness-mission-runtime}}); they consume the
capability claims above as decision inputs.

The AAuth rows come from the binding's own published Mission
Substrate Statement: the lifecycle claim from the base Statement, and
the state claim under its Mission Management activation condition,
each with the Statement's temporal and failure elements
({{I-D.draft-mcguinness-mission-aauth}}). The payment policy
adapter's and the gateway's claims remain deployment-local provider
claims; nothing here implies every provider claim becomes
binding-owned.

The deployment declaration names the four providers, the two routes,
and the consequence class. It is ordinary deployment documentation;
no machine-readable declaration format is defined, and the Mission
Deployment Profile's schema remains reserved future work
({{deployment-profile}}).

The deployment runs PS authorization (three-party) access; agent
identity, person identity, resource-managed, and federated access are
out of scope here. Every auth token the gateway accepts is PS-issued
and carries the signed `mission_s256` reference copied from the
resource token, the protected propagation path.

Before joining the PS evidence, the Actor proof, the request, and the
adapter's output, the gateway's join validates:

- the carrying artifact's issuer (the Person Server);
- the artifact's audience (the payment API);
- the actor binding (the agent's key, proven on the request); and
- the request binding.

The join is scoped to the two named routes, with a lifetime no longer
than the state observation's declared freshness. A missing or
conflicting input fails closed.

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

AAuth supplies work continuity, the payment authority decides
permission in its own vocabulary, and the gateway is the scoped
joining and enforcement authority. The payment authority's fresh
decision is `decide_anew` in the substrate's transition
classification, never an attenuation of AAuth authority across
vocabularies. The AAuth Mission context never becomes a Rich
Authorization Request object.

The same composition fails when:

- the state source is disabled with no equivalent fresh local read;
- the state source's staleness exceeds the declared maximum;
- the adapter publishes descriptive strings rather than
  machine-evaluable semantics;
- the payment-vocabulary claim is generalized to another resource's
  vocabulary;
- a direct route bypasses the gateway;
- the gateway accepts a Mission reference from the agent without
  validated provenance (context splicing); or
- the gateway accepts the reference on an agent identity or
  resource-managed request.

# Error Surfaces {#error-surfaces}

The OAuth and MAS profiles use three error surfaces, each owned once:

- OAuth endpoints return OAuth error codes, owned by the OAuth binding
  ({{I-D.draft-mcguinness-oauth-mission}}).
- Lifecycle surfaces, including management, return the status
  profile's JSON error body (`error`, `error_description`, `nonce`)
  ({{I-D.draft-mcguinness-oauth-mission-status}},
  {{I-D.draft-mcguinness-oauth-mission-management}}).
- MAS-native surfaces return the MAS error object, which adds
  `error_reason` and omits the `nonce`
  ({{I-D.draft-mcguinness-mission-authority-server}}).

AuthZEN denial reasons are not a fourth surface: they ride the
decision response ({{I-D.draft-mcguinness-mission-authzen}}). Where
the same symbol exists as both an OAuth error code and a wire-body
symbol (`invalid_request`), the envelope it arrives in disambiguates.

The AAuth binding retains AAuth's own error surface. Its native
management companion returns `application/problem+json`, preserves the
base AAuth `mission_terminated` error on ordinary PS operations, and
makes an absent reference indistinguishable from one the caller is not
authorized to observe
({{I-D.draft-mcguinness-mission-aauth-management}}).

Registration posture differs per artifact class: OAuth-facing
parameters and media types register with IANA, and evidence media
types defer registration until cross-domain interoperability demands
it. Each profile states which posture it takes.

# Illustrative Verification Guidance {#verification-guidance}

These scenarios illustrate how a Baseline Issuance deployment can be
checked. Each checks a rule its home document states normatively; this
document owns none of them and confers no conformance class.

Coverage is scoped by the capabilities a binding's Mission Substrate
Statement claims, so a standalone MAS is never asked to verify a
credential behavior it does not claim. The OAuth binding, which
publishes no Statement, is covered through its own Conformance gates.
The family's conformance manifest carries the profile-owned rows.

Kernel, every Baseline deployment (the substrate contract's approval
event, governance gate, and bounded reliance,
{{I-D.draft-mcguinness-mission-substrate}}):

1. approval creates an active Mission;
2. an authenticated terminal transition takes effect in the
   Controller's own subsequent decisions; and
3. the observed residual after a transition does not exceed the
   published reliance bound.

Expiry ceiling, where the binding imposes one (the OAuth binding's
Mission-Bound Access Tokens section,
{{I-D.draft-mcguinness-oauth-mission}}; the UMA and GNAP bindings,
{{I-D.draft-mcguinness-mission-uma}},
{{I-D.draft-mcguinness-mission-gnap}}; for AAuth, the expiry profile,
{{I-D.draft-mcguinness-aauth-mission-expiry}}; and for the standalone
MAS, the issuance grant's Lifetime rule,
{{I-D.draft-mcguinness-oauth-mission-issuance-grant}}):

1. no credential outlives the Mission's effective expiry.

Credential-Bound, where claimed (the substrate contract's
Credential-Bound capability):

1. a credential from another Mission cannot be substituted (the
   reference and its Controller namespace bind together).

Lifecycle-Gated Authorization, where claimed and limited to the
operations named in the claim (the substrate contract's
Lifecycle-Gated Authorization capability):

1. an active Mission yields a positive result for a claimed
   operation within policy;
2. a terminal transition prevents every claimed operation; and
3. for every lifecycle-gated operation in the claimed scope,
   unavailable, invalid, stale, or unknown state prevents a
   positive result (the forward-compatibility rule: only `active`
   permits reliance, and lost state never fails open).

For the OAuth binding, the same coverage includes (the OAuth
binding's Mission Lifecycle and Gating and grant-binding rules,
{{I-D.draft-mcguinness-oauth-mission}}):

1. refresh while the Mission is active succeeds within policy and
   is refused after a terminal transition; and
2. a bare client-supplied Mission identifier creates no binding:
   the grant, never the identifier, determines the Mission.

# Deployment Profile Example Shapes {#deployment-profile-examples}

These shapes are illustrative. This document fixes no serialization,
and each fact's owning profile governs its meaning
({{deployment-profile}}).

The first shape is for a deployment that runs mediated credential
custody but makes neither High-Assurance claim. In this shape:

- Its generic attestation reference is declaration input, not the
  proof the agent-compromise-resistant claim requires: the runtime
  profile's per-condition evidence bindings (EAT profile and claim
  identifiers, measurements, appraisal policy, attester identity,
  freshness, signed approval configuration, rendering evidence, and a
  path-completeness audit).
- Its `key_custody` entries are declarations under the same rule: a
  custody statement made legible, not a checked assurance grade (the
  member's definition in {{deployment-profile}} states the open
  verifier gap).
- Its revocation residuals follow the runtime profile's arithmetic:
  for a mediated class, the state valid-through (30 seconds, which
  also caps each permit) plus the class's execution bound; for any
  other path, the access-token lifetime.

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
    "refresh_gated_on_active_state": true,
    "max_access_token_lifetime_seconds": 300
  },
  "runtime": {
    "pdp": "authzen",
    "pep_locations": ["tool-gateway", "browser-action-proxy"],
    "execution_bound_seconds": 30,
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
    "mediated classes: revocation stops new effect within 60 seconds",
    "other paths: revocation within the 300-second token lifetime",
    "PEP compromise is not prevented",
    "per-entry constraints reach scope-only resources only via the PEP",
    "long-term memory and provider model context are not Mission-scoped exposure points"
  ]
}
~~~

An issuance-only deployment ({{issuance-only}}) publishes a smaller
shape, with:

- no `runtime`, `credential_custody`, or `harness` member;
- its token lifetime stated as the revocation bound where a Resource
  Server does not introspect; and
- residuals that name the per-action check it does not run.

~~~ json
{
  "profile": "mission-issuance-only",
  "assurance_claims": [
    "approved-record integrity", "bounded revocation latency"
  ],
  "mission_issuer": "https://as.example.com",
  "state_sources": [
    { "type": "introspection", "max_staleness_seconds": 0 }
  ],
  "issuance": {
    "binding": "oauth-core",
    "refresh_gated_on_active_state": true,
    "max_access_token_lifetime_seconds": 300
  },
  "resource_servers": {
    "authorization_details_enforcing": ["https://erp.example.com"],
    "scope_projection_only": ["https://mail.example.com"],
    "constraint_enforcement_for_scope_only": "refuse_issuance"
  },
  "residual_risks": [
    "no per-action check within a token lifetime",
    "revocation up to 300 seconds where no introspection",
    "scope-only constraints not projectable are refused",
    "delegated tokens reach Mission-aware resources only"
  ]
}
~~~

# Mission Document Map {#document-map}

One row per document, grouped as the family groups them; the short
form drops the `draft-mcguinness-` prefix, and the repository's
DRAFTS.md is the full catalog with maturity and adoption metadata.
The naming encodes a boundary: profiles extending the Authorization
Server's own surfaces keep "oauth" in their names; profiles defined
against the substrate of {{substrate}} are named without it. This
document is named without it because the architecture is
substrate-neutral.

Maturity is a dependency boundary. A Standards-Track profile never
depends normatively on an experimental one, and a Standards-Track
document cites an experimental profile informatively at most. The
experimental profiles extend the stable interface only through its
declared seams: the Mission Intent extension seam of the OAuth
binding (a named, companion-defined top-level member) and the
coordinated-extension rules of the evidence objects. An experimental
profile that stabilizes crosses the boundary by reclassification, not
by a stable document absorbing a dependency.

Within Lifecycle, Status is the OAuth lifecycle suite's root
document, with Signals (the push channel) and Management (the
operator plane) as its satellites; AAuth keeps its native two-state
lifecycle, served by `mission-aauth-management`, with the expiry
bound profiled by `aauth-mission-expiry`.

**Architecture mappings:**

| Document | Role |
|---|---|
| `mission-aam` | Experimental sketch. Cloudflare's Agent Access Model mapped onto the family; defines no binding or mechanism. |

**The substrate and the bindings:**

| Document | Role |
|---|---|
| `oauth-mission` | The OAuth binding: approval, anchors, the `mission` claim, the subset rule, and state-gated issuance. |
| `oauth-mission-resource-access` | The `mission_resource_access` type: matching, Common Constraints, delegation policy, and subset algebra. |
| `mission-authority-server` | The standalone Mission Issuer and the PDP join of ordinary credentials to Missions. |
| `oauth-mission-issuance-grant` | The issuance join: MAS-minted grants an Authorization Server redeems for Mission-bound, state-gated tokens. |
| `mission-aauth` | The AAuth binding: Person Server control, the `s256`-committed mission blob, and PS-path gating. |
| `mission-uma` | Experimental sketch. The UMA 2.0 binding: Intent by claims pushing, the RPT as Mission-bound credential. |
| `mission-gnap` | Experimental sketch. The GNAP binding: Intent in the grant request; drawdown or expansion on modification. |
| `mission-substrate` | The binding-neutral kernel contract, normative on any further binding; bindings other than OAuth publish Statements. |

**Approval time:**

| Document | Role |
|---|---|
| `mission-shaping` | Client-side shaping of a user's request into a candidate Mission Intent, as untrusted proposal. |
| `oauth-mission-submission-evidence` | The Intent Submission Evidence framework: entry convention, binding, and verification bounds; defines no types. |
| `oauth-mission-request-provenance` | Optional evidence type: a trusted intake's signed record of who originated the request behind an Intent, with a secret-keyed request digest. |
| `oauth-mission-consent-evidence` | The `consent_rendering_hash` anchor and signed evidence of what the Approver was shown. |
| `oauth-mission-approval` | Asynchronous approval over the deferred substrate. |
| `mission-approval-governance` | The Approval Governance Record: authenticated assertions behind an approval, committed atomically with activation. |
| `oauth-mission-approval-revision` | Experimental: in-review narrowing revision of a deferred proposal. |
| `oauth-mission-template` | Experimental: one consent to a template's ceiling; each dispatch is an ordinary, policy-instantiated Mission. |

**Lifecycle:**

| Document | Role |
|---|---|
| `oauth-mission-status` | The signed pull surface and lifecycle endpoint, with `suspended` and `completed`. |
| `oauth-mission-status-list` | A signed, compressed Status List read locally per action instead of per-Mission status reads. |
| `oauth-mission-discharge` | Per-entry discharge via `terminal_when`, an extension operation on the Status lifecycle endpoint. |
| `oauth-mission-signals` | A signed event per lifecycle transition, push or poll. |
| `mission-control-plane` | Experimental: issuer consistency, durable transition publication, rollback resistance, and the availability boundary. |
| `oauth-mission-expansion` | Widening through an approved successor Mission. |
| `oauth-mission-containment` | Event-triggered monotonic narrowing of a live Mission's effective authority; restoration only by successor. |
| `oauth-mission-derivation-limits` | An issuer-enforced cap on derivations under one Mission, refused at issuance once reached. |
| `oauth-mission-progressive` | Experimental: policy-adjudicated expansion within a pre-consented ceiling. |
| `mission-discovery` | Experimental: the open-world encounter as a governed operation, with identity pinning and adjudication floors. |
| `oauth-mission-management` | Fleet enumeration and bulk lifecycle operations for operators; dry-run-first, per-Mission semantics. |
| `mission-aauth-management` | AAuth-native status, termination, optional expiry, and delegation-tree queries at the Person Server. |
| `aauth-mission-expiry` | Profile of AAuth's `expires_at` lifetime bound: precision, skew documentation, prompt termination. |

**Cross-domain projection and continuity:**

| Document | Role |
|---|---|
| `oauth-mission-cross-domain` | Single-hop projection of a Mission to another trust domain via the cross-domain grant. |
| `oauth-mission-cross-org-delegation` | Recursive cross-organizational delegation as offline attenuation; projection turns a verified chain into a local token. |
| `oauth-mission-continuation` | Authorization continuity over identity-continuity transports, state-gated; a continuation handle grants nothing. |
| `oauth-id-continuation-assertion` | A continuation transport: a short-lived subject token yielding an ID-JAG for one hop. |

**Runtime enforcement:**

| Document | Role |
|---|---|
| `mission-runtime` | The per-action decision contract: parameter binding, custody, fail-closed behavior; binding-neutral. |
| `mission-runtime-oauth` | The OAuth 2.0 realization of the runtime contract: token validation and claim and authority mappings. |
| `mission-authzen` | The AuthZEN profile: the decision-API request and response mapping and the denial classification. |
| `mission-runtime-evidence` | Decision Evidence, Execution Evidence, and Refusal Records: their integrity envelope and retention. |
| `mission-metering` | Experimental: cumulative consumption bounds and the metering that enforces them. |
| `oauth-mission-transaction-authorization` | Experimental: a single-use action-bound token minted after a fresh cross-domain decision. |

**Agent runtime:**

| Document | Role |
|---|---|
| `mission-harness` | Binding sessions, queues, and sub-agent handles to Mission state; the mediated environment. |
| `mission-capability-binding` | Binds a catalog-sourced entry (an MCP tool or OpenAPI operation) to its source; refuses drift. |
| `mission-orchestration` | Experimental: reversibility classes, unwind plans, and compensation after a stop. |

**Sub-agents:**

| Document | Role |
|---|---|
| `oauth-mission-child-delegation` | Child Missions with lineage, strict-subset authority, cascade revocation. |
| `oauth-mission-attenuation` | Experimental: narrower Mission-bound tokens minted offline; the kill switch preserved by runtime re-check. |

**Proof and portability:**

| Document | Role |
|---|---|
| `oauth-mission-approved-set-verification` | An independent check that carried authority is a subset of the complete approved Authority Set. |
| `mission-mandate` | A signed, portable statement of a Mission's committed facts; evidence, not a credential. |
| `mission-audit` | Registration of Mission evidence in a SCITT Transparency Service; receipts verifiable offline. |
| `mission-evidence-envelope` | Experimental: a binding-neutral evidence envelope and payload-type registry for future evidence kinds. |

**Security model:**

| Document | Role |
|---|---|
| `oauth-mission-work-products` | Experimental: work-product provenance and non-transitive handoff; a work product is input, not authority. |
| `mission-security-model` | The trusted base in one view: what each component must achieve and what its compromise costs. |

# Document History {#document-history}

\[\[ To be removed from the final specification ]]

- Corrections from the fourth outside review, with no change to any
  profile's requirements. The Validity Model sums the residual across
  an exchange that mints without a fresh state check, and The Four
  Levels, Assurance Claims, Composed Kill-Switch Reality, and
  Appendix F's first shape state revocation figures from that
  arithmetic. The Actor Chain separates the approved agent, recorded
  at approval, from the requesting `client_id`. Both High-Assurance
  claims require attestation. The Ontology Contract describes task
  context as shared across components; the Derivation Boundary calls
  narrowing checkable, not reproducible; Survivable Incorrectness
  separates a bounded dimension from tolerable harm; and the
  Introduction states the standardization thesis.

- Four clarifications from #953, with no change to any profile's
  requirements. Mission Binding Properties states two routes to
  `credential-mission-bound` (a substrate Statement with its kernel
  mappings, issuer trust, and credential evidence, or a binding's own
  conformance requirements), each establishing all six conditions,
  and lists the OAuth binding's evidence for every condition; the
  Mission Join Assertion's properties are stated from the MAS
  definition; Swarm Execution describes instances under the same
  authorized agent identity, keeps the Agent Deployment pin distinct
  from `client_id`, and labels the client-attestation text by
  mechanism; and the runtime seam is named Mission binding
  establishment throughout.

- The Approved-record integrity claim names what the anchors cover
  (the committed Intent, authority proposal, and Authority Set) and
  states that provenance members and an issuer substituting a record
  with its anchors are outside it.

- What ends an already-issued credential is worded the same way in
  Approval and Lifecycle, the possession-independent revocation
  invariant, and the containment matrix: an applicable revocation, a
  state-aware or runtime check that reaches it, or its own expiry.
  Issuance gating stops only further derivation and refresh; it does
  not end an existing credential. Step 7 of A Mission's Life keeps its
  PDP clause and adds when mediated actions under an earlier permit
  stop. No change to any profile's requirements.

- The Mission Substrate no longer claims that every companion named
  without "oauth" has a Mission Substrate section of its own.

- A readability pass, with no change to any profile's requirements.
  The Mission and Mission Assurance Levels gain subsections (Approval
  and Lifecycle, The Authority Path, The Delegated-Authority Layer, The
  Four Levels); each verb section leads with its question, boundary,
  and owners; the Map of This Document lists the parts and adds reading
  paths; the access modes the AAuth Person Server gates are named the
  PS-gated modes; untitled tables get captions, and long citations
  leave table cells so the tables fit the text format; and inline
  enumerations across the document become lists. RFC 8693 is cited
  where the delegation chooser names token exchange, two stale uses of
  "Completion" name the Entry Discharge companion, and the assurance
  levels are called levels throughout, never rungs.

- The derivation-modes table follows the OAuth binding: a model's
  output in derivation is a recorded input that can refuse or narrow,
  never supply or widen, with no change to any profile's
  requirements.

- The authority path, with no change to any profile's requirements.
  The Mission adds a figure from approval basis to action, with the
  lifecycle gate beside the path, child creation as a new approval
  event, and the current Effective Authority Set as a separate runtime
  input; the Mission Verbs adds a table placing each mechanism on the
  transition it acts on; and Binding Security Architectures states
  that one Mission can span authorization servers whose client
  identifiers differ, related through the owning Mission Issuer's
  recorded mappings.

- The RAR metadata citation names the working-group successor
  draft-ietf-oauth-rar-metadata-remediation and separates an
  authorization server's type metadata from a protected resource's
  RFC 9728 `authorization_details_types_supported`.

- Approve and Record names the three approval roles (derivation,
  adjudication, accountability) and summarizes the OAuth binding's
  rule that a model's judgment enters adjudication only as a recorded
  input to a deterministic policy, an input that can refuse or narrow
  and never grant or widen; the prose members stay the human
  Approver's check.

- Composition states the per-Mission bound model once, with no change
  to any profile's requirements: an approval bounds the authority each
  derivation carries; concurrent children, generations, and
  per-Mission derivations do not multiply into a lifetime total; and
  an aggregate bound holds only where a deployment enforces one.

- Derivation and narrowing, with no change to any profile's
  requirements. The derivation boundary states the derivation
  procedure the authority-bearing bindings share (narrowing or a
  configured mapping, with prose members as disclosure) and that only
  derivation policy stays local; Authority only narrows covers the
  Effective Authority Set and the per-type transformation
  capabilities.

- The issuance-join row of the composed kill-switch table and its note
  follow the Mission Issuance Grant's two consuming-AS modes: with a
  Mission-state integration, redemption and refresh are projected
  through the Effective Authority Set; without one, nothing is checked
  at redemption and no refresh tokens are issued. The earlier
  "active-only" redemption check no longer exists there.
- AAuth alignment, with no change to any profile's requirements. The
  AAuth and R3 references cite the published revisions -11 and -00;
  the Mission Reference is the approving PS and `s256`; the access
  modes carry AAuth's names; and the gateway walkthrough names the
  issuers of the auth tokens it accepts.

- Density, with no change to any profile's requirements. Long
  paragraphs are split to one idea each and long sentences shortened;
  Continue lists the three continuities and keeps the residual for
  authority already issued under a continued grant; the binding
  properties' mechanism mapping is a table; the kill-switch
  composition table has short cells with numbered notes; and
  meta-commentary about the document is removed. OAuth-specific
  statements the pass found unlabeled now say so.

- Reading order and section ownership, with no change to any
  profile's requirements. A Mission's Life leads the model; Meaning
  and Derivation gathers the ontology contract, the derivation
  boundary, and approval fidelity; the binding comparison, now with
  GNAP, sits with the substrate; Assurance opens with a table of the
  frames it uses and folds the reference stacks into the levels; and
  each deployment pattern has its own subsection. Requirements, the
  conventional-stack comparison, the worked composition, error
  surfaces, illustrative verification guidance, the Deployment
  Profile shapes, and the trimmed document map are appendices. The
  verb spine carries an overlay of owning documents and packages.
  Repeated explanations have one home, and a repetition that
  qualifies a guarantee keeps a short local summary. The model is
  stated binding-neutrally, with each realization labeled, and the
  Runtime-Enforced bundle's dependencies are described by intended
  category, not maturity.

- Editorial corrections, with no change to any profile's
  requirements. The capability-kill property is stated per action
  class and consumer rather than per assurance level, matching the
  composition section and the containment profile. The four Mission
  Issuer bindings are named, and GNAP joins the Mission Issuer roles,
  the control-point peer row, and the credential-carried pattern. The
  worked composition names no level. The AAuth protocol and R3 are
  cited, and AAuth terms are expanded on first use. Terms owned
  elsewhere point to their owners. "Mission-bound" names one
  definition. Keywords describing other documents' rules are
  lowercased, and temporal phrasing is removed. The agent-identity
  section is retitled, the binding-property summary covers the whole
  vector, and the AuthZEN companion is called the AuthZEN profile.
  The Stop step of A Mission's Life separates what ends at once from
  what ends within a staleness bound or at a token's own expiry.

- The issuance-only deployment is named under Entry Ramps by Estate
  with its invariants, introspection cutoff, claims, and runtime
  triggers; the adoption-ladder table grants Baseline Issuance the
  reads and writes whose bounds the receiving Resource Server
  enforces; and the Deployment Profile gains an issuance-only example
  shape.

- Client-instance references follow their successors:
  draft-mcguinness-oauth-client-instance-assertion is replaced by
  {I-D.draft-mcguinness-oauth-client-instance-id} and
  {{I-D.draft-mcguinness-oauth-client-attesters}}, and the
  deprecated draft-mcguinness-oauth-ai-agent-instance is no longer
  cited. Instance identity is
  a client-instance attestation and validated Instance Context,
  attribution needs an instance-unique key, and instance evidence
  identifies no actor. No requirement changed.

- Linked the OAuth binding's informative derivation-policy appendix
  from the authority derivation boundary (#309).

- Added the optional Control-Plane Consistency companion to the document
  map (#250).

- Controls taxonomy retirement (#636): the swarm-execution discussion
  no longer claims `derivation_limit` (renamed from `max_derivations`)
  is a fan-out or concurrency ceiling; it counts issuance events, not
  instances, and one instance refreshing repeatedly exhausts it exactly
  as N instances deriving once each would. The Agent Deployment pin is
  now described as a named architectural pattern with no wire member
  the OAuth binding currently defines, pointing to a forward-referenced
  Agent Deployment Binding profile instead of the retired
  `controls.agent_deployment`. References to the OAuth binding's
  retired `controls` extension seam updated to the Mission Intent's
  own (open, named-member) extension seam.

- PR #717 review fix: precised the "Mission-bound" definition text
  ({{token-classes}} and {{binding-properties}}) so it no longer
  requires a Mission Substrate Statement of a binding that
  deliberately publishes none. A binding that claims substrate
  conformance evidences `credential-mission-bound` through its own
  Statement; the OAuth binding, which claims no substrate conformance
  and publishes no Statement, is instead assessed through its own
  informative Mapping Assessment and discharges the definition
  directly through its own Conformance gates. No normative content
  changed.

- Reworded the blanket "the bindings are peers of one another"
  sentence in the Introduction to name two independent axes, deployment
  topology and data-model independence, and to classify the Mission
  Authority Server as a normative standalone-controller protocol
  binding over the OAuth Mission data model: a peer deployment
  topology, but not an independent substrate model (#704).
  Cross-referenced the three
  previously uncross-referenced accounts of what earns "Mission-bound"
  ({{token-classes}} and {{binding-properties}}, and the OAuth
  binding's Conformance gates): {{binding-properties}}'s
  `credential-mission-bound` equivalence is now the stated definition,
  a binding's Mission Substrate Statement is how it evidences the
  properties, and the OAuth binding's gates are its discharge of the
  definition (#663). No normative content, anchor, or table row
  changed.

- Cross-referenced the three previously separate accounts of what
  earns the "Mission-bound" term: {{token-classes}} now names the
  Mission Binding Properties vector's `credential-mission-bound`
  property ({{binding-properties}}) as the definition. Its six
  conditions are each mapped to the Statement capability or OAuth
  binding surface that discharges it, condition 2 (Mission identity)
  no longer names a token-carried `authority_hash`, aligning with
  the ruled minimal-claim direction of #702, and condition 6
  (the auditable derivation link) names the OAuth binding's retained
  Mission Record explicitly rather than asserting an unspecified
  discharge (#663).

- Non-goal reworded (#637): "a new authority format, or a new grant
  protocol" narrowed to "a new grant protocol," naming the OAuth
  binding's Mission Resource Access Profile as the family's one
  cross-resource `authorization_details` type, since RFC 9396 leaves
  type semantics to the type and the family now defines one. Document
  Map gains the profile's row under "The substrate and the bindings."

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
