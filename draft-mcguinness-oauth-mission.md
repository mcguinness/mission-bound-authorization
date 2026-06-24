---
title: "Mission-Bound Authorization for OAuth 2.0"
abbrev: "OAuth Mission"
category: std

docname: draft-mcguinness-oauth-mission-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
keyword:
 - oauth
 - mission
 - agent
 - authorization
 - rar
 - par
venue:
  github: "mcguinness/draft-mcguinness-oauth-mission"
  latest: "https://mcguinness.github.io/draft-mcguinness-oauth-mission/draft-mcguinness-oauth-mission.html"

author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com

normative:
  RFC3339:
  RFC6234:
  RFC6749:
  RFC7636:
  RFC7523:
  RFC7800:
  RFC8259:
  RFC8693:
  RFC8785:
  RFC8705:
  RFC8707:
  RFC9068:
  RFC9126:
  RFC9396:
  RFC9449:
  RFC7662:
  RFC8414:
  RFC7519:
  RFC9728:
  I-D.draft-ietf-oauth-identity-assertion-authz-grant:
  I-D.draft-ietf-oauth-identity-chaining:
  I-D.draft-mcguinness-oauth-actor-profile:

informative:
  RFC8126:
  RFC6750:
  RFC7009:
  RFC8935:
  RFC9493:
  RFC9700:
  I-D.draft-klrc-aiagent-auth:
  I-D.draft-ietf-oauth-transaction-tokens:
  I-D.draft-niyikiza-oauth-attenuating-agent-tokens:
  I-D.draft-cecchetti-oauth-rar-cedar:
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
  I-D.draft-mcguinness-oauth-mission-runtime:
    title: "Mission-Bound Runtime Enforcement for OAuth 2.0"
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-oauth-mission-runtime-latest
  I-D.draft-mcguinness-oauth-mission-expansion:
    title: "Mission Expansion for OAuth 2.0"
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-oauth-mission-expansion-latest
  I-D.draft-mcguinness-oauth-mission-consent-evidence:
    title: "Mission Consent Evidence for OAuth 2.0"
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-oauth-mission-consent-evidence-latest

--- abstract

An AI agent is typically given a mission: a task to pursue on a
user's behalf. OAuth 2.0 issues access tokens for individual
resource requests, but it has no durable, approved artifact that
ties those tokens to the one task a user actually authorized. As a
result, an agent's authority is a collection of independently
obtained tokens with no shared, auditable boundary, and a user's
approval is disconnected from what the agent later does.

This document defines a Mission: a structured, human-approved,
integrity-bound authorization artifact for OAuth 2.0. A client submits
a Mission Intent through Pushed Authorization Requests; the
Authorization Server derives Rich Authorization Requests authorization
details from it, binds them to the Approver's consent through an
integrity anchor, and records a durable Mission. Every access token
derived under the Mission carries that authority and a "mission"
claim, and issuance is gated on the Mission's lifecycle state.
Delegation among agents is carried with the OAuth Actor Profile, and
an optional cross-domain grant of the OAuth identity chaining
architecture lets a single Mission cross trust domains and be honored
by more than one Authorization Server, preserving the Mission's
consent commitment throughout. This is the issuance and governance
"mission layer" left unspecified by agent-identity work for OAuth;
runtime enforcement of each action is a separate, optional layer.

--- middle

# Introduction

Agent-identity work such as {{I-D.draft-klrc-aiagent-auth}}
establishes how an AI agent authenticates and how a user delegates
authority to it: the agent is an OAuth 2.0 {{RFC6749}} client
identified by `client_id`, the delegating user is the access token
`sub`, and the
agent obtains tokens for the resources its task requires. That work
deliberately leaves three things out of scope: how an agent's task
(its "mission") is translated into authorization, how a user's
approval of that task is captured as a durable artifact, and how
later token issuance stays bound to what the user approved.

Without that layer the gap is invisible to every individual OAuth
component. Each token is individually valid and each request
individually in scope, yet nothing checks whether the task the user
approved is still the one being pursued. A token issued for a task
remains usable after the user's approval has lapsed or been withdrawn,
because no OAuth object ties the token's validity to the task's
authorization: the credential stays secure while the work it
authorizes has quietly become unauthorized.

This document specifies that missing layer. It defines a
**Mission**: a structured, human-approved, integrity-bound OAuth
authorization artifact. The contribution is a single chain:

1. The client submits a structured **Mission Intent** describing the
   task (goal, target resources, constraints) instead of requesting
   raw scopes.
2. The Authorization Server (AS) derives **authorization details**
   ({{RFC9396}}) from the Intent: the concrete authority the task
   needs.
3. At an **approval event**, the Approver consents to that
   authority, and the AS commits it as an **`authority_hash`** and
   records a durable **Mission**.
4. Every access token the agent obtains under the Mission carries the
   derived authorization details and a **`mission` claim** bearing
   the `authority_hash`. A Resource Server enforces statelessly from
   the token.
5. Token issuance and refresh are **gated on Mission state**, so
   revoking or expiring the Mission stops the agent from obtaining
   further authority.

The result is that a user approves a task once, and that approval,
not a per-request scope grant, bounds and outlives every token the
agent derives. Each token carries an `authority_hash` audit anchor back
to the consented authority; a holder of the full Authority Set can
verify it, and a holder of only a narrowed subset (a downstream or
cross-domain party) treats it as an audit anchor it cannot recompute
({{consent-binding}}).

## Why a New Object

OAuth already has objects near this need, but none is the approved
task. A `scope` value or an `authorization_details` entry
({{RFC9396}}) expresses authority but neither the task it serves nor a
lifecycle of its own. An access token is a short-lived projection; its
`jti` identifies the token, not the task. A refresh token preserves
the ability to obtain further tokens but commits no bounded, approved
authority. A consent record proves that an approval event happened; it
does not govern the resulting work as it continues. The Mission is the
durable object these project from: the approved task that bounds and
outlives them, and that every derived token refers back to.

Put plainly: Rich Authorization Requests express authority; a Mission
expresses an approved task with a lifecycle. The Mission is a separate
object because that approved-task lifecycle, not a new way to express
authority, is what OAuth lacks. A Mission is therefore not another
`authorization_details` type; it is the durable, approval-backed object
an Authority Set is derived for and gated by.

## The Mission, the Plan, and Execution

The Mission is the durable, AS-held object that commits the approved
authority and owns the task's lifecycle. Two related things an agent
produces around a task are deliberately not the Mission and carry no
authority of their own.

The agent's **plan**, how it decomposes the task, chooses tools, and
delegates to sub-agents, is the agent's own strategy and is out of
scope for this document. It grants nothing: authority a sub-agent
exercises is carried by the `act` chain ({{delegation}}), derived from
the Mission and only ever narrowed from it ({{subset}}), never created
by the plan.

The agent's **execution**, the tokens it derives, the calls it makes,
and the decisions taken on them, references the Mission but cannot
expand it. Revoking the Mission stops further derivation
({{lifecycle}}); it does not undo actions already completed.
Evaluating each action against the Mission at the point of use is the
runtime layer's concern ({{runtime-boundary}}), not this document's.

The invariant across all three: the plan and the execution draw on the
Mission's authority; neither enlarges it.

## Relationship to Agent-Identity Specifications

This document is complementary to {{I-D.draft-klrc-aiagent-auth}}
and reuses its model: the agent is the OAuth client
(`client_id`); the delegating user or system is the token `sub`.
This document does not define agent identity, credentialing, or
posture; it defines the approved-task artifact those identities act
within. An agent authenticated and delegated per that specification
uses the mechanisms here to obtain Mission-bound tokens.

## Applicability

This profile targets OAuth deployments where authority serves a
durable, user-approved task that spans more than one token, request,
or audience: an agent pursuing a multi-step objective on a user's
behalf, or a workflow whose audit must join activity across hops on a
shared task. It is not intended for, and adds cost without benefit to,
single-request user flows, machine-to-machine service credentials, or
short-lived authorizations where the credential's lifetime is the
task's lifetime; those use OAuth unchanged.

A Mission SHOULD be scoped to a concrete task, not to an agent's whole
lifetime. A deployment SHOULD prefer narrow, per-task Missions, each
separately approved and revocable, over a single broad standing Mission
that accumulates authority across unrelated tasks. The durable object is
the approved task: keeping it task-scoped is what makes its authority
and audit meaningful and bounds the blast radius on compromise to one
task. An agent pursuing many tasks holds many Missions, not one broad
one.

## Scope and Future Work

This document is a self-contained, minimum-viable profile: it binds
Missions to OAuth 2.0 and is implementable on its own, depending only
on the OAuth and JOSE specifications it cites. A single cross-domain
hop is supported as an optional binding ({{cross-domain}}); the
single-domain core is implementable without it.

Two normative dependencies are on in-progress individual drafts, so
this document cannot advance ahead of them: the OAuth Actor Profile
({{I-D.draft-mcguinness-oauth-actor-profile}}) for the `act` chain, and
the identity-chaining and ID-JAG drafts
({{I-D.draft-ietf-oauth-identity-chaining}},
{{I-D.draft-ietf-oauth-identity-assertion-authz-grant}}) for
cross-domain projection. Both are confined to OPTIONAL capabilities
(Delegation and Cross-Domain), so the mandatory single-domain core does
not depend on them.

Separate from this document, and not required to implement it, are
several capabilities now specified as OPTIONAL companion profiles: an
additional integrity anchor over a structured consent disclosure
(`consent_rendering_hash`, {{consent-binding}}) is defined by Mission
Consent Evidence {{I-D.draft-mcguinness-oauth-mission-consent-evidence}};
mission expansion is defined by Mission Expansion
{{I-D.draft-mcguinness-oauth-mission-expansion}}; and a cross-domain
status or event-distribution mechanism for tighter revocation is defined
by Mission Status {{I-D.draft-mcguinness-oauth-mission-status}} and
Mission Lifecycle Signals {{I-D.draft-mcguinness-oauth-mission-signals}}.
A deployment implements this document without any of them. Remaining
future work, not yet specified, includes a substrate-neutral
generalization of the Mission model across non-OAuth authorization
substrates, the normative carriage of Mission context in Transaction
Tokens (shown only illustratively in the end-to-end example appendix),
and, for a community that wants cross-vendor agreement on what a task
authorizes within a vertical, an OPTIONAL derivation profile: a registry
of standard task types mapped to authority templates, so that two
vendors in that profile derive comparable Authority Sets. This document
deliberately does not standardize the derivation algorithm itself
({{authorization-derivation}}); a vertical profile is the appropriate
vehicle where portable derivation is genuinely needed.

## Non-Goals

The following are deliberately out of scope. Each is a recurring
question for agent authorization; naming it here records that it was
considered and where it belongs, not that it was overlooked.

- **Semantic / intent verification.** This profile binds a token to an
  approved authority and task; it does not evaluate whether a given
  runtime action serves the Mission's purpose beyond matching the
  approved `authorization_details` and `constraints`. Per-action
  evaluation is the runtime layer's role ({{runtime-boundary}}).
  Verifying an agent's declared reasoning against the task is a further
  attestation problem outside both layers.
- **Approval-free authorization upgrade.** The Authority Set is
  committed at approval; this profile defines no mid-stream widening
  that bypasses consent. Widening requires a new approval, a successor
  Mission, as specified by Mission Expansion
  {{I-D.draft-mcguinness-oauth-mission-expansion}}. That approval MAY be
  given by policy rather than by a human when the original approval
  pre-consented to an authority ceiling and a drawdown policy
  (progressive authorization,
  {{I-D.draft-mcguinness-oauth-mission-expansion}}); a widening that no
  consent, human or pre-given, authorizes remains out of scope.
- **Lifecycle event distribution.** A Resource Server learns Mission
  state from the token lifetime or optional introspection
  ({{introspection}}); this profile defines no push-based notification
  of Mission state changes. A Shared Signals ({{RFC8935}}) / CAEP
  profile for Mission lifecycle events is specified separately by the
  Mission Lifecycle Signals profile
  ({{I-D.draft-mcguinness-oauth-mission-signals}}), not here.
- **Human-in-the-loop suspension.** The base lifecycle here is
  `active`, `revoked`, `expired` ({{lifecycle}}). A `suspended` state
  with `resume`/`complete` transitions is defined as an OPTIONAL
  extension by the Mission Status and Lifecycle profile
  ({{I-D.draft-mcguinness-oauth-mission-status}}); a
  pending-human-approval state and a holding-token pause-and-resume
  protocol remain future lifecycle work.
- **Multi-hop cross-domain provenance.** A single cross-domain hop is
  supported ({{cross-domain}}); chaining a Mission across more than one
  trust-domain boundary, and the verifiable provenance that would
  require, are future work.
- **Decentralized agent identity.** Agent identity and credentialing
  are out of scope ({{I-D.draft-klrc-aiagent-auth}}, and workload
  identity efforts such as WIMSE); this profile governs the
  approved-task artifact those identities act within, not the
  identities themselves.

## Conventions and Terminology

{::boilerplate bcp14-tagged}

All JSON shown in this document is non-normative and illustrative; the
member definitions in the surrounding text are authoritative.

Agent (Client):
: The OAuth client acting on a user's behalf, identified by
  `client_id`. Agent identity is established per
  {{I-D.draft-klrc-aiagent-auth}} or ordinary OAuth client
  authentication.

Subject:
: The user or system on whose behalf the Mission is approved,
  identified by an (`iss`, `sub`) pair and carried in derived tokens'
  `sub` claim.

Approver:
: The single accountable principal who approves the Mission at the
  approval event. Equal to the Subject for self-approval; different
  for administrator or delegated approval. This document records one
  accountable Approver; multi-party approval and the provenance of
  delegated approval authority are deferred ({{multi-party-approval}}).

Mission Issuer (Authorization Server):
: The OAuth AS that validates a Mission Intent, runs the approval
  event, records the Mission, and derives tokens. It is the Mission's
  `origin`. "Mission Issuer", "originating AS", and "AS" are used
  interchangeably in this document.

Resource AS:
: An Authorization Server in another trust domain that honors a
  Mission it did not issue, minting its own tokens for its resources
  from a cross-domain grant ({{cross-domain}}), for which the Identity
  Assertion Authorization Grant (ID-JAG) is the recommended profile.
  A Resource AS is never the Mission Issuer. Relevant only to
  deployments using the optional cross-domain binding.

Mission Intent:
: The structured description of the task the client submits
  ({{mission-intent}}).

Authority Set:
: The set of `authorization_details` entries the AS derives from a
  Mission Intent and the Approver approves
  ({{authorization-derivation}}).

Mission:
: The durable, immutable record created at the approval event
  ({{mission-record}}), identified by a `mission_id`.

Derived token:
: An access token issued under a Mission, carrying its Mission-derived
  authority (the full Authority Set or a narrowed subset) as
  `authorization_details` and a `mission` claim
  ({{mission-bound-tokens}}).

# Conformance {#conformance}

An implementation conforms in one of two roles.

A **Mission Issuer** (the Authorization Server) implements the core
issuance surfaces:

- submission of a Mission Intent via PAR ({{mission-intent}});
- derivation of `mission_resource_access` authorization details
  ({{authorization-derivation}});
- the approval event with its integrity anchors ({{approval-event}});
- issuance of Mission-bound access tokens carrying the `mission` claim
  ({{mission-bound-tokens}});
- the subset rule ({{subset}}); and
- gating of issuance on Mission state ({{lifecycle}}).

A **Mission-aware Resource Server** implements Resource Server
enforcement ({{rs-enforcement}}).

Beyond these mandatory roles, this profile defines three OPTIONAL
capabilities that an implementation MAY additionally claim. Each is
independent, and an implementation that supports none of them is still
conformant:

- **Delegation** ({{delegation}}): issuing and consuming derived tokens
  that carry the `act` delegation chain.
- **Introspection** ({{introspection}}): reporting Mission state through
  the `mission` token introspection response member.
- **Cross-Domain** ({{cross-domain}}): issuing or honoring the
  cross-domain grant so a Mission spans more than one AS.

A conforming implementation names the optional capabilities it supports
(for example, "Mission Issuer with Delegation and Cross-Domain"); each
capability's own section states its detailed requirements.

The `mission_bound_authorization_supported` metadata ({{discovery}})
advertises Mission Issuer support only. It makes no assertion about any
Resource Server, which does not advertise through Authorization Server
metadata. The OPTIONAL capabilities are discovered first through
existing OAuth metadata ({{RFC8414}}): `introspection_endpoint` for
introspection, and `grant_types_supported` containing
`urn:ietf:params:oauth:grant-type:token-exchange` for delegation and
cross-domain grant issuance. Absent such a signal, a capability is
discovered out of band or by attempt: a Token Exchange, an ID-JAG
issuance, or an introspection request fails if the issuer does not
support it.

# Overview

## Principal Model

This document carries principals natively to OAuth:

- The **Agent** is the OAuth client, referenced by `client_id`. Agent
  identity and credentialing are out of scope (see
  {{I-D.draft-klrc-aiagent-auth}}).
- The **Subject** and **Approver** are each an (`iss`,
  `sub`) pair, matching the access token `sub` model of {{RFC9068}}.

On a derived token the `sub` claim is the Subject's `sub` and the
token `iss` is the AS; within the issuing AS's namespace this
(`iss`, `sub`) pair is authoritative for the Subject, and Resource
Servers authorize against it. The Subject's home issuer is recorded
on the Mission as `subject.iss` for audit and is not carried on the
token; this document defines no runtime lookup of it (there is no
by-Mission status endpoint). Across trust domains, the ID-JAG conveys
Subject identity to the Resource AS through its own subject-resolution
claims ({{cross-domain}}), not through a Mission lookup.

Principals are recorded at the approval event and are immutable. Two
principals are equal when their `iss` and `sub` are byte-equal.
Dynamic delegation (the actors an agent delegates to during
execution) is carried on derived tokens via the `act` chain
({{delegation}}), not on the immutable Mission record. Richer subject
identifier formats (for example, the formats of {{RFC9493}}) MAY be
layered in future versions and are not required here.

## Protocol Flow

~~~
 Agent (client)                       Mission Issuer (AS)
      |                                     |
      | 1. PAR: mission_intent ------------>| derive authority
      |<----------- request_uri ------------| (authz_details)
      |                                     |
      | 2. authorization request ---------->| principal consents
      |                                     |   -> authority_hash
      |<-------------- code ----------------| -> Mission active
      |                                     |   (bound to the grant)
      |                                     |
      | 3. token request ------------------>| gate: active?
      |<----------- access token -----------| + authz_details
      |                                     |   + mission claim
      v
~~~

The flow then leaves the AS: (4) the agent calls the Resource Server
with the token; the RS enforces the `authorization_details`
statelessly and MAY check the `mission` claim, with no callback to the
AS required. (5) A management revoke or `mission_expiry` moves the
Mission to `revoked` or `expired`, after which the AS refuses further
issuance and refresh; a deployment MAY additionally compose RFC 7009
{{RFC7009}} refresh-token revocation ({{revocation}}).

# Mission Intent {#mission-intent}

A Mission Intent is the proposal; the Mission is the approval; the
integrity anchors commit the moment of transition. Before the approval
event ({{approval-event}}) only the Intent exists, as untrusted client
input ({{submission-via-par}}); after it, only the Mission is
authoritative. A Mission Intent therefore has no protocol identifier
of its own: two submissions of the same Intent produce two distinct
pending requests, and a Mission acquires its `mission_id`
({{mission-record}}) only at activation. The approved Intent is
recorded on the Mission and committed by `intent_hash`
({{integrity-anchors}}); it describes the task but commits no
authority, which is committed separately by `authority_hash` over the
derived Authority Set ({{authorization-derivation}}).

A Mission Intent is a JSON object describing the task. The client
submits it instead of, or alongside a narrowed, `scope`. It has the
following members:

`goal`:
: REQUIRED. A string. A human-readable statement of the task,
  for rendering to the Approver. Maximum 4096 characters.

`resources`:
: REQUIRED. An array of strings. The target resources the
  task needs, each an absolute URI identifying a protected resource
  (an OAuth resource per {{RFC8707}}-style indicators or a Protected
  Resource per {{RFC9728}}).

`constraints`:
: OPTIONAL. An array of strings. Human-readable bounds on
  the task (for example, "read only invoices from 2026"). These
  inform derivation and consent rendering.

`success_criteria`:
: OPTIONAL. An array of strings. Human-readable
  observable outcomes that indicate the task is complete. These are
  disclosure and audit material only: they are rendered to the
  Approver and committed by `intent_hash` ({{integrity-anchors}}),
  but carry no machine semantics and MUST NOT be used to derive,
  widen, or gate authority.

`purpose`:
: OPTIONAL. A string. A URI identifying the purpose of the
  task, recorded for disclosure and audit. Its semantics are
  deployment- or registry-defined and opaque to this document; like
  `success_criteria` it MUST NOT be used to derive, widen, or gate
  authority. A deployment MAY consult it for out-of-band policy or
  logging that does not affect the authority derived here.

`mission_expiry`:
: REQUIRED. A string. An RFC 3339 {{RFC3339}}
  date-time after which the Mission MUST NOT derive tokens.

`context`:
: OPTIONAL. An object of machine-actionable bounds. This
  document defines the members below; others MAY be added by
  deployments:

  `acr`:
  : OPTIONAL. A string. The minimum authentication context
    class the Approver MUST satisfy at the approval event.

  `max_derivations`:
  : OPTIONAL. A positive integer. A positive (1 or greater)
    bound on the number of derivations the origin AS performs under the
    Mission, enforced per {{lifecycle}}. A value of 0 is invalid (it
    would forbid even the initial issuance); to stop a Mission, revoke
    it ({{revocation}}). An AS MUST reject `max_derivations` below 1
    with `invalid_request`. This is an origin-AS
    derivation cap, not an end-to-end credential cap: it does not
    count local tokens a Resource AS mints from an ID-JAG, which the
    origin cannot observe ({{lifecycle}}).

  `max_budget`:
  : OPTIONAL. An object. A hard cap on cumulative monetary
    spend under the Mission. Has the members:

    `amount`:
    : REQUIRED. A string. A decimal number.

    `currency`:
    : REQUIRED. A string. An ISO 4217 currency code.

  `max_calls`:
  : OPTIONAL. An array of objects. Hard caps on the count of
    consequential call events. Each object has the members:

    `call_class`:
    : REQUIRED. A string. The named call class to meter. A `call_class`
      value SHOULD be drawn from the `actions` identifiers of the
      entry's `mission_resource_access` ({{authorization-derivation}}),
      so the metered class maps to evaluated actions; a deployment that
      meters a coarser or cross-entry class defines that class's
      membership, and such a class is deployment-defined and not
      interoperable, like a deployment-defined constraint. (Named
      `call_class` rather than `scope` to avoid collision with the OAuth
      `scope` parameter and claim.)

    `count`:
    : REQUIRED. An integer. 1 or greater.

  `max_duration`:
  : OPTIONAL. A string. An ISO 8601 duration (for
    example, `PT8H`), matching the `duration` rule in Appendix A of
    {{RFC3339}}, bounding cumulative wall-clock consequential activity
    under the Mission. It is distinct from `mission_expiry`, which
    bounds issuance rather than activity.

  `max_budget`, `max_calls`, and `max_duration` are **consumption
  bounds**: a deployment names them here so issuance and the runtime
  layer share one vocabulary. They are carried on the Mission and
  committed by `intent_hash`, but, unlike `max_derivations`, they are
  not enforced by the AS at issuance. They are enforced at the point of
  use by the runtime layer ({{runtime-boundary}}); absent that layer
  they are not enforced.

Example Mission Intent:

~~~ json
{
  "goal": "Reconcile Q3 invoices and post adjustments under $500.",
  "resources": ["https://erp.example.com"],
  "constraints": [
    "Read only invoices issued in 2026-Q3.",
    "Post journal entries under $500."
  ],
  "success_criteria": [
    "All Q3 invoices reconciled.",
    "Each posted adjustment references a source invoice."
  ],
  "purpose": "urn:example:purpose:reconcile",
  "mission_expiry": "2026-12-31T23:59:59Z",
  "context": {
    "acr": "urn:example:acr:mfa",
    "max_derivations": 200,
    "max_budget": { "amount": "5000.00", "currency": "USD" },
    "max_calls": [
      { "call_class": "journal-entries.write", "count": 50 }
    ],
    "max_duration": "PT8H"
  }
}
~~~

## Submission via PAR {#submission-via-par}

A client MUST submit a Mission Intent through a Pushed Authorization
Request {{RFC9126}} using the `mission_intent` request parameter. The
parameter value is the UTF-8 JSON {{RFC8259}} serialization of the
Mission Intent object, carried as an ordinary OAuth request-parameter
value (form-encoded in the `application/x-www-form-urlencoded` PAR
request body, like other OAuth parameters). The AS returns a
`request_uri` as usual, which the client uses to start authorization.
An AS that cannot parse `mission_intent` as a JSON object, or that
parses it but finds it structurally invalid against this document's
member definitions, MUST refuse the request with `invalid_request`.

A different case is an Intent that is well-formed but from which the AS
cannot derive a valid Authority Set (for example, an unsupported
resource, action, or authorization details type, or a policy that bars
the requested authority). In that case the AS SHOULD refuse with
`invalid_authorization_details` ({{RFC9396}}), even though the client
did not submit `authorization_details` directly. This lets a client
distinguish a syntax error from an authority-derivation failure.

The Intent MUST arrive through PAR: an AS MUST reject a `mission_intent`
presented directly on a front-channel authorization request, rather
than through a PAR-issued `request_uri`, with `invalid_request`. PAR
keeps the integrity-sensitive Intent off the untrusted front channel.
Because `mission_intent` is untrusted client input that the AS records
and hashes, a deployment SHOULD also bound its total size and the
lengths of its arrays, refusing an Intent that exceeds those limits
with `invalid_request`.

A client MUST NOT submit `authorization_details` directly together
with `mission_intent`; the AS derives authorization details from the
Intent ({{authorization-derivation}}). A request carrying both MUST
be refused with `invalid_request`. A client MAY submit `scope` and
`resource` ({{RFC8707}}) values; the AS treats them as a requested
subset and MUST NOT grant authority beyond what the Mission Intent
yields.

For a Mission request, the parameters pushed via PAR are authoritative.
The AS MUST ignore any `mission_intent`, `authorization_details`,
`scope`, or `resource` presented on the front-channel authorization
request that redeems the `request_uri`. The AS MUST NOT let such a
front-channel value widen the authority derived from the pushed Intent.

A Mission Intent is untrusted client input. Trust enters only when the
AS validates it and the Approver consents to the rendered result. The
AS MUST treat the submitted Intent as a proposal, never as authority.
The AS MUST derive authority and bound it by policy regardless of what
the client submitted. How a client produces the Mission Intent (for
example, a "Mission Shaper" that derives it from a natural-language
instruction) is out of scope for this document.

# Mission Authority {#authorization-derivation}

From the Mission Intent, the AS derives the **Authority Set**: one or
more {{RFC9396}} `authorization_details` entries of type
`mission_resource_access` ({{type-registration}}). The AS MUST:

- Produce, for each `resources` entry the deployment recognizes, a
  `mission_resource_access` entry whose `resource` is that URI and
  whose `actions` are derived from the Intent's `goal`, `constraints`,
  and deployment policy.
- Bound every derived entry by the Mission Intent. The AS MUST NOT
  derive authority not supported by the Intent.
- Record the policy version used for derivation as the Mission's
  `policy_version`.

The derived Authority Set, not the Mission Intent, is the authority the
Approver consents to: the AS renders the Authority Set for approval and
commits it as `authority_hash` ({{approval-event}}). The Intent's
`goal`, `constraints`, and other members describe and bound the task
but grant no authority by themselves ({{mission-intent}}); they
constrain what the AS MAY derive, never widen it.

Derivation is governed by local policy and is not a portable algorithm:
different Authorization Servers MAY derive different Authority Sets from
the same Mission Intent, exactly as different deployments grant
different authority for the same {{RFC9396}} request or the same scope.
That locality is intended, not a gap. It is the resource-owning AS's
policy, and it is not a value a foreign party should reproduce. What
this profile makes interoperable is therefore not the derivation step
but its result: the derived Authority Set's structure and vocabulary
({{authorization-derivation}}, {{common-constraints}}) and its
integrity anchors ({{integrity-anchors}}), which a consumer in any
domain interprets, enforces, and audits identically. A consumer enforces
the derived Authority Set, never the Intent.

Two rules keep local derivation accountable rather than opaque. First,
derivation MUST be reproducible: the same Mission Intent and the same
`policy_version` MUST yield the same Authority Set at a given AS, so a
derivation can be re-checked and a divergence detected. Second, an AS
SHOULD make the policy a `policy_version` identifies inspectable to
relying parties and auditors that must evaluate how it derives authority.
Local policy is thus versioned and reviewable, which is what a
cross-domain trust decision actually needs, even though the policy
itself does not travel.

Where cross-vendor interoperability matters, an AS SHOULD derive the
Authority Set by narrowing a client-proposed set of
`authorization_details` to policy, rather than generating one from free
text. Narrowing is governed by the subset rule ({{subset}}), which is
interoperable, so the result is verifiable and enforceable in any domain
even though the policy decision of what to narrow to stays local; the
Intent's `goal` and `constraints` then serve as the human-readable
consent-rendering layer over that proposed authority. Generating
authority from free text alone is permitted but is the least portable
and most semantically fraught option, and SHOULD be reserved for
deployments that do not need cross-vendor agreement.

For an open-ended task whose concrete objects cannot be enumerated at
approval (for example, "reconcile this customer's ledger," where the
individual invoices are not yet known), the AS SHOULD bound the derived
authority primarily by `constraints` that hold as invariants over those
objects (the owning customer, the tenant, an amount ceiling, read-only
except named write actions, a validity window) rather than by an
exhaustive `resource` enumeration. The runtime layer
({{runtime-boundary}}) checks each concrete object against the
constraint at the point of use. Constraint-bounding lets a Mission cover
an open-ended task with tight authority even though the specific objects
are unknown at approval, and avoids the over-broad enumeration a
deployment would otherwise need to anticipate them.

A `mission_resource_access` entry is a {{RFC9396}}
`authorization_details` object with these members:

`type`:
: REQUIRED. A string. `mission_resource_access`.

`resource`:
: REQUIRED. A string. The single protected resource the
  entry applies to, an absolute URI identifying an OAuth protected
  resource ({{RFC8707}}) or a Protected Resource ({{RFC9728}}). It is
  the same kind of identifier as the {{RFC8707}} `resource` value. The
  AS derives the token `aud` from the `resource` values of the carried
  entries as described in {{mission-bound-tokens}}; the `aud` identifies
  the Resource Server(s) and need not be byte-equal to a `resource` (it
  is typically coarser). It is carried here as a type-specific member of
  each
  `mission_resource_access` entry, which {{RFC9396}} permits; carrying
  it per entry (rather than once for the request, as the {{RFC8707}}
  `resource` request parameter does) lets one token scope distinct
  authority to distinct resources. Per {{RFC9396}}, the `resource`
  request parameter does not affect how the AS processes
  `authorization_details`, and this member is distinct from the
  {{RFC9396}} common `locations` field.

`actions`:
: REQUIRED. An array of strings. Permitted action
  identifiers, each matching `[A-Za-z0-9_.:-]+`. Like an OAuth scope, an
  action identifier carries meaning only at the `resource` that defines
  it; a consumer enforces only the actions it recognizes for that
  resource and honors no others, so an action a consumer does not
  understand is fail-closed by construction (the action is simply not
  within the authority it can enforce). An AS SHOULD draw action
  identifiers from a namespace the serving resource documents, so the
  set is interpretable cross-vendor rather than ad hoc.

`constraints`:
: OPTIONAL. An object. Machine-actionable per-resource
  bounds (for example, `max_amount_usd`). A member name registered as a
  Common Constraint ({{common-constraints}}) has shared semantics
  across deployments; any other name is deployment-defined.

  - Because a `constraints` member narrows authority, a Resource Server
    that cannot enforce one MUST fail closed ({{rs-enforcement}}).
  - To avoid that failure mode, the AS SHOULD emit for a given
    `resource` only `constraints` keys that the Resource Server serving
    it is known (by registration or deployment policy) to understand
    and enforce.

`delegation`:
: OPTIONAL. An object. The delegation policy for this
  entry ({{delegation-constraints}}). When absent, this entry's
  authority is non-delegable: it MUST NOT appear in a delegated
  token. When present, it has these members:

  `max_depth`:
  : REQUIRED. An integer. The maximum delegation depth at
    which this entry's authority may be exercised
    ({{delegation-constraints}}).

  `allowed_delegates`:
  : OPTIONAL. An array of objects. The permitted
    delegates, each a `may_act`-style matcher
    ({{delegation-constraints}}): `{ "sub": "<client_id>" }` for a
    specific delegate, or `{ "sub_profile": "<actor-type>" }` for an
    actor-type class. When absent, any actor is permitted (subject to
    `max_depth`).

Example Authority Set (the read entry is delegable to depth 2; the
write entry carries no `delegation` and so is non-delegable, because
`delegation` is per entry):

~~~ json
[
  { "type": "mission_resource_access",
    "resource": "https://erp.example.com",
    "actions": ["invoices.read"],
    "delegation": {
      "max_depth": 2,
      "allowed_delegates": [{ "sub_profile": "ai_agent" }]
    } },
  { "type": "mission_resource_access",
    "resource": "https://erp.example.com",
    "actions": ["journal-entries.write"],
    "constraints": { "max_amount_usd": 500 } }
]
~~~

## Subset Rule {#subset}

When the AS narrows the Authority Set for a derived token, a derived
`mission_resource_access` entry A is a subset of a Mission entry B
when:

1. A.`resource` equals B.`resource`.
2. A.`actions` is a subset of B.`actions`.
3. For every key K in **B**.`constraints`, K MUST also be present in
   A.`constraints`, and A's value MUST be no broader than B's under
   K's subset rule: the registered rule when K is a Common Constraint
   ({{common-constraints}}), the deployment-defined comparison
   otherwise. A key present in B but absent from A is treated as the
   broadest possible value and therefore fails this test. In short,
   constraints MUST NOT be dropped, only added or tightened.

The AS MUST refuse to derive an entry that is not a subset of some
Mission Authority Set entry.

This comparison is deliberately flat: `resource` matches by exact
equality and `actions` by array membership. It does not yet define
resource containment (a path-prefix or hierarchical resource) or action
families (an `invoices.*` hierarchy). Real hierarchical resources are
expected to need both, so an extension defining hierarchical resource
and action subset semantics is known near-term work; until then a
deployment expresses hierarchy through explicit entries or constraints,
and the runtime layer enforces it ({{runtime-boundary}}).

The `delegation` member is policy, not authority, and is not part of
this comparison ({{delegation-constraints}}). A derived entry's
`delegation`, when present, MUST NOT be broader than the parent entry's:
its `max_depth` MUST be no greater and its `allowed_delegates` MUST be
no wider. A derived entry MUST NOT introduce `delegation` where the
parent entry has none.

## Common Constraints {#common-constraints}

A `constraints` member name ({{authorization-derivation}}) is either a
registered **Common Constraint** or a deployment-defined key. Common
Constraints give independently developed deployments one vocabulary
they interpret, narrow, and compare identically; the "Mission Common
Constraints" registry ({{iana-common-constraints}}) is the extension
point.

A registered Common Constraint defines:

- **Value syntax**: the JSON {{RFC8259}} value type and any additional
  rules.
- **Subset rule**: how a candidate value is judged no broader than a
  reference value, used by the subset comparison of {{subset}}.
- **Intersection rule**: how two values for the same key combine; the
  result MUST be no broader than either operand.

A `constraints` member whose name is registered is interpreted per the
registry. A member whose name is not registered remains
deployment-defined and is interpreted only within the issuing
deployment; a consumer that does not recognize it MUST fail closed
({{rs-enforcement}}).

This document registers the initial Common Constraints:

- `max_amount_usd` (number): a per-action ceiling, in US dollars, on a
  monetary amount. Subset: no broader when less than or equal to the
  reference value. Intersection: the minimum of the two values.
- `issued_after` (string, an RFC 3339 {{RFC3339}} date-time): the
  action applies only to resources issued at or after this instant.
  Subset: no broader when greater than or equal to the reference.
  Intersection: the later instant.
- `issued_before` (string, an RFC 3339 {{RFC3339}} date-time): the
  action applies only to resources issued at or before this instant.
  Subset: no broader when less than or equal to the reference.
  Intersection: the earlier instant.

## Other Authorization Details Types {#other-types}

`mission_resource_access` is the only type this document defines, but
the Authority Set MAY include other AS-supported {{RFC9396}}
`authorization_details` types when an audience consumes them. ("Supported"
here means the AS recognizes and documents the type, as advertised by
`authorization_details_types_supported` ({{discovery}}); RFC 9396
establishes no IANA registry of type identifiers.) The Mission apparatus
is type-agnostic toward such entries:

- they are committed by `authority_hash` and gated on Mission state
  exactly as `mission_resource_access` entries are;
- narrowing and delegation use the subset semantics the type defines
  ({{subset}}, {{delegation-constraints}}). A type whose subset and
  delegation semantics the AS does not understand MUST NOT be
  delegated, audience-projected to a Resource AS, or narrowed: the AS
  cannot prove a transformed copy is still a subset of what was
  approved. Such an entry MAY be issued only to its original approved
  audience, carried exactly as approved, and MUST NOT appear in a
  delegated or cross-domain (ID-JAG) token;
- evaluating the entry against a concrete request is the runtime
  layer's responsibility ({{runtime-boundary}}), not the AS's.

This lets policy-language profiles compose without this document
defining them: for example, an entry carrying a Cedar policy set
({{I-D.draft-cecchetti-oauth-rar-cedar}}), or an analogous AuthZEN
policy entry, for an audience that evaluates it. The AS derives such
an entry from the Mission Intent and bounds it by the Intent like any
other, but treats the carried policy largely opaquely; the Resource
Server or Policy Decision Point (PDP) evaluates it at request time.

Example (non-normative): an Authority Set with a Cedar policy entry
for a finance audience that consumes Cedar, alongside a
`mission_resource_access` entry for a calendar audience that does not.
The Cedar `policySet` is abbreviated:

~~~ json
[
  {
    "type": "account_information",
    "rarFormat": "cedar",
    "policySet": "permit(principal, action, resource) when {...};"
  },
  {
    "type": "mission_resource_access",
    "resource": "https://calendar.example.com",
    "actions": ["events.read"],
    "constraints": { "window_days": 30 }
  }
]
~~~

Both entries are committed by the one `authority_hash` and bound to
the Mission. The Cedar entry is evaluated by the finance audience's
PDP; the `mission_resource_access` entry is enforced as in
{{mission-bound-tokens}}. Because the Cedar profile defines no subset
rule over policy sets, the AS carries the Cedar entry as approved
rather than narrowing it; the per-entry `delegation` controls still
bound who may delegate it and how far.

## Modeling Tools and Function Calls {#tools}

This section is non-normative guidance. A "tool" an agent invokes,
such as a Model Context Protocol (MCP) tool or a function call, is
modeled as a `mission_resource_access` entry. No separate entry type
is needed, and the rules above (derivation, subset, delegation,
`authority_hash`) apply unchanged.

The mapping is:

- `resource` is the tool provider. For an MCP tool it is the MCP
  server's URL. The MCP authorization model makes the server an OAuth
  2.0 resource server, so this is the resource identifier a token is
  audience-bound to.
- `actions` are the tool names the task needs at that provider.
  Authorizing a tool is authorizing its name as an action, which
  lines up with MCP filtering its tool list by the caller's granted
  authority and routing each tool call for authorization.
- `constraints` carry machine-actionable bounds on a tool's
  arguments, for example an amount ceiling or a recipient domain.
  Like all `constraints`, they are committed by `authority_hash` and
  carried to the point of use, but they are evaluated against the
  concrete call arguments by a runtime enforcement layer, not at
  issuance ({{runtime-boundary}}).

For example, a Mission authorized to read invoices and post small
adjustments through a finance MCP server, and to send messages
through a messaging MCP server, derives:

~~~ json
[
  { "type": "mission_resource_access",
    "resource": "https://finance.example.com/mcp",
    "actions": ["query_invoices", "post_adjustment"],
    "constraints": { "max_amount_usd": 500 } },
  { "type": "mission_resource_access",
    "resource": "https://mail.example.com/mcp",
    "actions": ["send_message"],
    "constraints": { "recipient_domain": "example.com" } }
]
~~~

Delegation to a sub-agent works unchanged: add a `delegation` member
to a tool entry ({{delegation-constraints}}). For example, an entry a
sub-agent of type `ai_agent` may invoke at depth 1, narrowed to the
read tool only:

~~~ json
{ "type": "mission_resource_access",
  "resource": "https://finance.example.com/mcp",
  "actions": ["query_invoices"],
  "delegation": {
    "max_depth": 1,
    "allowed_delegates": [{ "sub_profile": "ai_agent" }]
  } }
~~~

What this profile does not provide for tools is a typed, attenuable
per-argument constraint grammar: narrowing one tool's argument schema
against another (for example, `amount` in a `range`, `recipient` in a
`one_of` set) as the grant is derived or delegated. Argument bounds
here are the same flat, carried `constraints` used for any resource,
evaluated at runtime. Structured per-argument attenuation
({{I-D.draft-niyikiza-oauth-attenuating-agent-tokens}}, with object
capability systems such as UCAN as prior art) is a richer primitive
deferred to future work; it would extend the delegation and subset
model of this document ({{delegation-constraints}}, {{subset}})
rather than introduce a new entry type.

# Mission Approval {#approval-event}

The approval event is the atomic transition at which the Approver
consents and the AS creates the Mission. It runs as an OAuth 2.0
{{RFC6749}} authorization-code flow initiated from the PAR-issued
`request_uri` ({{submission-via-par}}). Because the authorization code
is the artifact the Mission grant binds to ({{grant-binding}}) and it
travels the front channel, the AS MUST bind the code to the requesting
client with PKCE ({{RFC7636}}, `S256` challenge method) or,
equivalently, issue a DPoP-bound authorization code ({{RFC9449}}). The
AS MUST reject a code redemption whose PKCE verifier or DPoP key does
not match the binding established for the request. This prevents
authorization-code injection from yielding the Mission grant.

At the approval event the AS MUST, in order:

1. Authenticate the Approver. If the Mission Intent's
   `context.acr` is present, the authentication MUST satisfy it.
2. Establish the Subject: the principal the task is for, recorded as
   the Mission's `subject` and set as the `sub` of every derived token
   ({{mission-bound-tokens}}). When the Approver is the Subject
   (self-approval), this is the authenticated Approver. When the
   Approver is a different principal (for example, an administrator or
   manager approving on a user's behalf), the AS MUST itself establish
   the Subject's (`iss`, `sub`), and MUST authorize the Approver to
   approve for that Subject under local policy. The AS MUST NOT take the
   Subject from unauthenticated client input. This document defines no
   wire parameter for the Subject; how the AS establishes it
   (administrative selection, a directory, an authenticated reference)
   is a deployment matter.
3. Render for consent the derived Authority Set, the `goal` and
   `constraints`, the `mission_expiry`, and any `context` bounds
   (notably `max_derivations`), so the Approver sees the temporal and
   issuance limits, not only the authority. When the Approver is not
   the Subject, the rendering MUST identify the Subject the authority
   is granted for.
4. Compute the integrity anchors ({{integrity-anchors}}):
   `authority_hash` over the consented Authority Set and
   `intent_hash` over the approved Mission Intent.
5. Create the Mission record ({{mission-record}}) in the `active`
   state, atomically with issuance of the authorization code.

Rendering a bound is not the same as enforcing it, and a deployment MUST
NOT let the rendering imply otherwise. The approved resources and
actions are enforced by any Resource Server that honors the token. A
per-entry `constraint`, however, binds only where a Resource Server
understands and enforces its key ({{rs-enforcement}}); the consumption
bounds `max_budget`, `max_calls`, and `max_duration` bind only under the
runtime layer ({{runtime-boundary}}); and `max_derivations` is an
origin-AS cap that does not bound a Resource AS's local-token minting in
another domain ({{cross-domain}}). In a deployment without runtime
enforcement, and for any constraint no Resource Server enforces, these
bounds are advisory: rendered, consented, and committed, but enforced
nowhere. An AS SHOULD make clear to the Approver which rendered bounds
its deployment actually enforces, so consent is not given to a limit
that binds nowhere.

The `authority_hash` is the **authority commitment**: it binds, by
cryptographic digest, exactly the authority the Approver approved. It
commits the approved authority, not the way that authority was
rendered to the Approver; this profile commits no separate consent
disclosure object (see {{consent-binding}}). If the derived Authority
Set changes between rendering and consent, the AS MUST recompute and
MUST refuse to activate unless the principal approves the changed
set. Every token derived under the
Mission carries this value ({{mission-bound-tokens}}), so a party
holding the full Authority Set can verify a token's authority against
what was approved. A party holding only a narrowed subset cannot
recompute it and treats it as an audit anchor (see {{consent-binding}}
and {{cross-domain}}).

The `intent_hash` commits the **approved Mission Intent**: the
task the Approver consented to, as recorded on the Mission. It makes
the recorded task tamper-evident: an auditor can verify the Mission's
`mission_intent` against `intent_hash` and detect any later
alteration. `intent_hash` commits the task; `authority_hash`
commits the authority derived from it.

## Binding the Mission to the Grant {#grant-binding}

At the approval event the AS binds the Mission to the authorization
grant it issues: the authorization code, and the refresh token
issued from it. The binding is server-side and is what "the
referenced Mission" in {{lifecycle}} refers to: at each subsequent
derivation the AS resolves the Mission from the grant the client
presents: the authorization code at the token endpoint (the initial
exchange uses `grant_type=authorization_code`), the refresh
token on refresh, or the Mission-bound `subject_token` on Token
Exchange (the `actor_token` identifies the delegate, {{delegation}}).
It then applies the gating of {{lifecycle}}. A client does
not supply `mission_id` to obtain a derivation; an AS MUST NOT derive
Mission-bound authority from a client-supplied `mission_id`, because
the grant, not the identifier, determines the Mission.

The interoperable surface for `mission_id` is the `mission` claim's
`id` on each issued token ({{mission-claim}}); a client reads it from
there. A deployment MAY additionally surface `mission_id` in the token
response as a deployment-local convenience for correlation and
display, but this document defines no interoperable token-response
parameter for it. Either way `mission_id` is a reference, not a
credential: presenting it authorizes nothing ({{lifecycle}}).

## Single Accountable Approver {#multi-party-approval}

This document records exactly one `approver`: the
accountable principal who approved the Mission. Two richer patterns
are deliberately out of scope and deferred:

- **Multi-party approval** (M-of-N or dual control), where more than
  one principal must approve. The number of approvers is orthogonal
  to the consent commitment: however many principals approve the same
  rendered Authority Set, the `authority_hash`, and every token
  derived from it, is identical. Multi-party approval raises the
  assurance of *how* approval was obtained; it does not change the
  artifacts this document produces. A deployment requiring dual
  control today can obtain the additional approvals out of band and
  record one accountable Approver under the same `authority_hash`;
  this document simply does not natively represent the co-approvers.
- **Approval-authority provenance** (the standing policy or delegation
  an administrator or headless approval traces back to). This is
  governance state about who stands behind a delegated approval, not
  part of binding tokens to approved authority, and is left to a
  governance layer.

## Integrity Anchors {#integrity-anchors}

Both anchors are computed the same way over a domain-separated,
issuer-bound envelope:

1. Construct the envelope, where `typ` selects the committed object
   and `value` is that object:

   ~~~
   {
     "typ": "<mission-intent | mission-authority-set>",
     "iss": "<the AS issuer URL>",
     "value": <the committed object>
   }
   ~~~

   For `intent_hash`, `typ` is `mission-intent` and `value` is the
   approved Mission Intent object. For `authority_hash`, `typ` is
   `mission-authority-set` and `value` is the Authority Set as a JSON
   array of entries.

2. Canonicalize the envelope with JCS {{RFC8785}}.
3. Compute SHA-256 {{RFC6234}} over the canonical bytes.
4. Encode as `sha-256:` followed by the base64url, no-padding,
   encoding of the digest.

The `typ` field domain-separates the two anchors so a digest of one
object can never be mistaken for the other. The `iss` binding
prevents a committed object from being transplanted across
Authorization Servers.

The `typ` value space is an extension point ({{extensibility}}):
additional committed objects use this same envelope with a new `typ`
and the canonicalization below. This document defines no registry of
`typ` values; each committing specification defines its own and relies
on the `typ` domain separation. To keep that domain separation safe
without a registry, a new `typ` value MUST be a collision-resistant name
(for example, a short name prefixed within a namespace the defining
profile controls, following the Collision-Resistant Name guidance of
{{RFC7519}} Section 4.2). The `mission-` prefixed values defined across
this Mission-Bound Authorization profile set share an author-coordinated
namespace for this reason.

SHA-256 is the only digest algorithm this document defines; the
`sha-256:` prefix identifies it. Algorithm agility is future work.

A verifier MUST reject an integrity anchor whose algorithm prefix it
does not recognize. A verifier MUST NOT treat an unrecognized prefix as
`sha-256`. This ensures that adding an algorithm later cannot be
exploited as a downgrade.

## Canonicalization Rules {#canonicalization}

JCS {{RFC8785}} alone does not make two implementations agree on
every byte. The following rules close the remaining gaps; they apply
to computing an anchor and to comparing committed values:

- The committed `value` is exactly the object the AS recorded on the
  Mission: the approved `mission_intent` for `intent_hash`, the
  `authority_set` for `authority_hash`. An auditor reproduces a
  digest from the record alone.
- The AS MUST reject an input object containing duplicate JSON member
  names before canonicalization; such input is invalid.
- JCS does not reorder array elements, and this document defines no
  element sorting, so array order is significant. The AS MUST emit
  each array in a fixed, reproducible order; that order is part of
  the canonical form.
- URI-valued members are compared byte-for-byte unless a member's
  definition specifies a normalization. This document defines none,
  so `resource` and every other URI MUST match exactly (this governs
  the `resource` equality test of {{subset}}).

# Mission Record {#mission-record}

A Mission is the durable record created at the approval event. Its
members are immutable after creation except for its `state`, and it is
identified by a `mission_id`. Operational issuance bookkeeping, such as
the derivation count gated under {{lifecycle}}, is AS-side state about
the Mission, not a member of the immutable record. Like the `mission`
claim ({{mission-claim}}), the record is open ({{extensibility}}): a
companion profile MAY record additional, collision-resistantly named
members set at creation (for example, a lineage member linking the
Mission to a predecessor or parent). The members below are the ones this
profile defines:

`mission_id`:
: REQUIRED. A string. The canonical Mission identifier
  ({{mission-id}}).

`origin`:
: REQUIRED. A string. The issuer URL of the Mission Issuer
  that approved the Mission. Equals the `iss` of tokens that AS
  derives; for cross-domain tokens it remains the originating AS even
  though the issuing `iss` differs ({{cross-domain}}).

`state`:
: REQUIRED. A string. The current lifecycle state: `active`, `revoked`,
  or `expired` in this profile, or an additional state defined by a
  companion profile, subject to the forward-compatibility rule of
  {{lifecycle}}.

`mission_intent`:
: REQUIRED. An object. The approved Mission Intent.

`authority_set`:
: REQUIRED. An array. The consented Authority Set.

`authority_hash`:
: REQUIRED. A string. The consent commitment over
  the Authority Set ({{integrity-anchors}}).

`intent_hash`:
: REQUIRED. A string. The integrity commitment over
  the approved Mission Intent ({{integrity-anchors}}), making the
  recorded task tamper-evident.

`subject`:
: REQUIRED. An object. The Subject, an object with `iss` and
  `sub`.

`approver`:
: REQUIRED. An object. The Approver,
  an object with `iss` and `sub`. MAY equal `subject`.

`client_id`:
: REQUIRED. A string. The Agent (OAuth client) that
  submitted the Mission Intent.

`policy_version`:
: REQUIRED. A string. The derivation policy version
  in effect at the approval event.

`approval_event_id`:
: REQUIRED. A string. A unique identifier of the
  approval event, used as the approval idempotency key.

`created_at`:
: REQUIRED. A string. RFC 3339 timestamp of creation.

`mission_expiry`:
: REQUIRED. A string. Mirrors
  `mission_intent.mission_expiry`.

## `mission_id` Format {#mission-id}

`mission_id` is an opaque URL-safe ASCII string of `[A-Za-z0-9_-]`
characters, at least 128 bits of entropy, carrying no semantic
content. It MUST NOT be reused.

## Worked Example

~~~ json
{
  "mission_id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
  "origin": "https://as.example.com",
  "state": "active",
  "mission_intent": { "goal": "Reconcile Q3 invoices ...",
    "resources": ["https://erp.example.com"],
    "mission_expiry": "2026-12-31T23:59:59Z" },
  "authority_set": [
    { "type": "mission_resource_access",
      "resource": "https://erp.example.com",
      "actions": ["invoices.read"],
      "delegation": {
        "max_depth": 2,
        "allowed_delegates": [{ "sub_profile": "ai_agent" }]
      } },
    { "type": "mission_resource_access",
      "resource": "https://erp.example.com",
      "actions": ["journal-entries.write"],
      "constraints": { "max_amount_usd": 500 } }
  ],
  "authority_hash":
    "sha-256:l3KvZ4mP5x0wQrR6tY2nD9bM7sX1cF8gH2vJ4kE5pNQ",
  "intent_hash":
    "sha-256:wQ7p4LHnX9Md0LqJ6sZJ8b8mZ3rN2xT5pV4lE6sQqYY",
  "subject": { "iss": "https://idp.example.com",
    "sub": "user_3p2q8mN1a0kV7tR" },
  "approver": { "iss": "https://idp.example.com",
    "sub": "user_3p2q8mN1a0kV7tR" },
  "client_id": "s6BhdRkqt3",
  "policy_version": "deploy-policy:v17",
  "approval_event_id": "ape_8K2nP4qV9rL3tY6sB1z",
  "created_at": "2026-10-15T14:32:11Z",
  "mission_expiry": "2026-12-31T23:59:59Z"
}
~~~

# Mission-Bound Access Tokens {#mission-bound-tokens}

Access tokens issued under a Mission are JWTs per {{RFC9068}}, which
fixes the required claims (including `jti`) and the `at+jwt` JOSE
header `typ` ({{RFC9068}} Sections 2.1 and 2.2); a Resource Server
MUST verify the `typ` per {{RFC9068}}. In addition to what that
profile requires, a derived token:

- carries the token's Mission-derived authority as
  `authorization_details` ({{RFC9396}}); this MAY be the full Authority
  Set or a narrowed subset ({{subset}});
- carries a `mission` claim ({{mission-claim}});
- sets `sub` to the Mission's Subject `sub` and `client_id` to the
  Mission's `client_id`;
- MUST set `aud` to identify the Resource Server(s) authorized to
  consume the carried `authorization_details`, and MUST NOT include an
  audience unrelated to that carried authority (see below);
- MAY carry an `act` claim when the agent has delegated execution
  ({{delegation}});
- MAY carry a `scope` claim, subject to the rule below;
- SHOULD be sender-constrained, via a `cnf` claim {{RFC7800}}:
  DPoP {{RFC9449}} (`cnf.jkt`) or mTLS {{RFC8705}} (`cnf.x5t#S256`).

The AS MUST NOT include `authorization_details` exceeding the
Mission's Authority Set. On any issuance that narrows authority (for
example, a single-audience token), each emitted entry MUST be a
subset of a Mission Authority Set entry under {{subset}}.

The `aud` SHOULD be derived from the resource indicators
({{RFC8707}}), Protected Resource metadata ({{RFC9728}}), or the
deployment's resource-to-RS mapping. It identifies the Resource
Server(s) and need not be byte-equal to the `resource` values of the
`authorization_details` entries: an `aud` typically names an RS, API,
or security domain, while RAR entries may name resources, accounts,
tools, or locations beneath it. Bounding `aud` to the consuming
Resource Server(s) prevents a confused-deputy or token-redirection
attack: a multi-resource Authority Set otherwise yields a token an
unrelated Resource Server would accept even though it was obtained to
act elsewhere. A deployment SHOULD prefer per-RS (single-audience)
tokens, narrowed under {{subset}}. A client requests such a token at
the token endpoint with the {{RFC8707}} `resource` parameter (and MAY
further narrow with `scope`); the AS narrows the Authority Set under
{{subset}} to the requested resource(s) and sets `aud` to the
corresponding Resource Server(s). This is the within-domain
counterpart of the audience-scoping the Mission Issuer applies when
projecting authority to a Resource AS ({{audience-scope}}).

Sender-constraining is SHOULD for this primary token, aligned with
{{RFC9700}}. It is stronger (MUST) for three derived credentials that
face higher replay exposure: delegated tokens, which a less-trusted
delegate holds ({{delegation}}); cross-domain grants, which cross a
trust boundary ({{cross-domain-grant}}); and the Resource AS local
tokens minted from them ({{validation-at-resource-as}}). A deployment
SHOULD sender-constrain the primary token as well where its threat
model warrants.

The token-endpoint response conveys the granted authority to the
client. Because the client submits `mission_intent` rather than
`authorization_details`, the access token is otherwise the only place
the granted authority appears, and a client is not expected to parse
the access token for authority. The AS therefore MUST return the granted
`authorization_details` in the token-endpoint response, per
{{RFC9396}} Section 7, reflecting exactly the (possibly narrowed) set
assigned to the issued token. (A client does read the `mission` claim's
`id` from the token to learn its `mission_id`, per {{grant-binding}};
"not expected to parse for authority" refers only to the
`authorization_details`, which the response echoes.) The same applies to refresh and Token
Exchange responses.

Mission-bound refresh tokens MUST be sender-constrained or use refresh
token rotation, especially for a public client, since Mission-state
gating bounds a stolen refresh token's usefulness over time but not
while the Mission is still `active`. This requirement matches the
refresh-token guidance of {{RFC9700}} Section 2.2.2.

The authentication context of the approval event (`context.acr`,
{{mission-intent}}) describes the Approver at approval time and is
recorded on the Mission, not on derived tokens; a derived token's
authority comes from the Mission, not from a fresh authentication, so
this document requires no `acr` or `auth_time` claim on it. An AS MAY
include `acr` and `auth_time` per {{RFC9068}} to convey the approval
context, but a consumer MUST NOT treat their absence as an
authentication downgrade.

`authorization_details` is the authoritative expression of a
Mission-bound token's authority. Any `scope` the token carries MUST be
derived from, and no broader than, the Authority Set. Specifically:

- every scope value MUST correspond to authority already present in
  `authorization_details`; and
- a scope value MUST NOT convey authority, or relaxation of a
  constraint, that the Authority Set does not grant.

Because `scope` is a coarse string list, it cannot carry the per-entry
`constraints`; it is a compatibility projection, never the
authoritative form of the Mission's authority. The AS MUST NOT issue a
Mission-bound token whose `scope` exceeds the Authority Set.

A credential the Mission Issuer derives (an access token or a
cross-domain grant) MUST have an `exp` that does not exceed the
Mission's `mission_expiry`, so no credential outlives the approved
Mission, not only that none is issued after expiry. A Resource AS does
not hold `mission_expiry`; it MUST instead cap a local token's `exp`
at the `exp` of the cross-domain grant it was minted from
({{cross-domain}}). Because that grant is itself bounded by
`mission_expiry`, the local token is bounded transitively.

## The `mission` Claim {#mission-claim}

The `mission` claim is a JSON object:

`id`:
: REQUIRED. A string. The Mission's `mission_id`.

`origin`:
: REQUIRED. A string. The AS issuer URL.

`authority_hash`:
: REQUIRED. A string. The Mission's
  `authority_hash`, binding the token to the consented authority.

The `mission` claim is an open object ({{extensibility}}): additional
members MAY appear alongside the three above. This document defines no
registry of `mission` members; an extension member MUST use a
collision-resistant name (for example, a name in a namespace the
extension controls, per the Collision-Resistant Name guidance of
{{RFC7519}} Section 4.2) and is defined by the profile that introduces
it. A consumer MUST ignore members it does not understand and MUST NOT
use any additional member to grant or widen authority; the three
members above remain authoritative.

Example decoded token payload:

~~~ json
{
  "iss": "https://as.example.com",
  "sub": "user_3p2q8mN1a0kV7tR",
  "aud": "https://erp.example.com",
  "client_id": "s6BhdRkqt3",
  "iat": 1797840000,
  "exp": 1797840300,
  "jti": "at_9Kp2vN7sR1tY8mZ3qX5b",
  "authorization_details": [
    { "type": "mission_resource_access",
      "resource": "https://erp.example.com",
      "actions": ["invoices.read"],
      "delegation": {
        "max_depth": 2,
        "allowed_delegates": [{ "sub_profile": "ai_agent" }]
      } },
    { "type": "mission_resource_access",
      "resource": "https://erp.example.com",
      "actions": ["journal-entries.write"],
      "constraints": { "max_amount_usd": 500 } }
  ],
  "cnf": { "jkt": "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I" },
  "mission": {
    "id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
    "origin": "https://as.example.com",
    "authority_hash":
      "sha-256:l3KvZ4mP5x0wQrR6tY2nD9bM7sX1cF8gH2vJ4kE5pNQ"
  }
}
~~~

## Resource Server Enforcement {#rs-enforcement}

A Resource Server enforces from the token alone; no call to the AS is
required. A Resource Server:

- MUST validate the JWT per {{RFC9068}} and verify any
  sender-constraint binding (`cnf`).
- MUST treat `authorization_details` as the authoritative expression
  of authority and enforce the entries whose `resource` it serves,
  permitting only the listed `actions` subject to `constraints`.
- MUST fail closed on any `constraints` key it does not understand, or
  understands but cannot enforce, in an entry whose `resource` it
  serves: it MUST refuse the request (for example, a `403` with
  `insufficient_scope` {{RFC6750}}, or the deployment's usual
  insufficient-authority error) rather than grant access while ignoring
  the key. A `constraints` member narrows authority, so treating an
  unenforceable key as absent would silently widen the grant; an RS
  MUST NOT reduce a constraint to disclosure-only.
- MUST NOT, when a token also carries `scope`, grant on the basis of a
  scope value any access broader than the corresponding
  `authorization_details` entry permits; in particular, `scope` MUST
  NOT be used to bypass a constraint carried only in
  `authorization_details`.
- MUST NOT treat `client_id` as the identity of the acting party on a
  delegated token. This profile keeps `client_id` equal to the
  Mission's approved agent on every derived token ({{delegation}}); the
  immediate actor is the outermost `act`. An RS that authorizes or logs
  the caller MUST process the `act` chain to identify the acting party,
  or it will attribute a delegate's action to the approved agent.
- This `act`-processing requirement binds a Mission-aware RS. Because a
  Mission-unaware {{RFC9068}} RS reads `client_id` as the immediate
  client and would misattribute, a deployment SHOULD NOT route
  delegated tokens to an RS that authorizes or logs on `client_id`
  without processing `act`.
- MAY, for a Mission-governed resource, be configured to require the
  `mission` claim, and MUST then reject a token that lacks it with
  `invalid_token`. This prevents downgrade by omission: where the same
  AS also issues ordinary tokens, a token bearing equivalent
  `authorization_details` but no `mission` claim is governed by no
  Mission state, revocation, or consent commitment, and MUST NOT be
  accepted where Mission governance is required.
- MAY treat the `mission` claim as audit and correlation context.
- MAY, if it independently holds the Authority Set, recompute
  `authority_hash` ({{integrity-anchors}}) and compare it to the
  `mission` claim to detect a token whose authority does not match
  the approved Mission.
- MAY, where the AS offers it, introspect the token ({{introspection}})
  to observe the Mission's current state per request rather than
  relying on the token lifetime to bound revocation latency. An RS that
  introspects MUST still verify the token's sender-constraint (`cnf`)
  locally and MUST NOT treat an `active: true` result as proof the
  caller holds the bound key; the AS does not check possession at
  introspection ({{introspection}}).

A Mission-unaware Resource Server that authorizes only from `scope`
still operates within the Mission at the coarse scope level, because
the AS derived and bounded that scope by the Authority Set
({{mission-bound-tokens}}); but it does not enforce the per-entry
`constraints`, which `scope` cannot carry. A deployment that relies on
those constraints MUST route the protected operation through a
Resource Server that enforces `authorization_details` (or the runtime
layer that evaluates them).

# Mission Lifecycle and Gating {#lifecycle}

A Mission is in one of three states:

- `active`: tokens MAY be derived. The only state from which issuance
  proceeds.
- `revoked`: terminated by the Subject, Approver, or
  policy. Terminal.
- `expired`: `mission_expiry` has passed. Terminal.

The transitions are:

| From | Event | To |
|---|---|---|
| (none) | approval event | `active` |
| `active` | revoke | `revoked` |
| `active` | `mission_expiry` reached | `expired` |

These three states are the mandatory core of the Mission lifecycle
state space. This profile owns that state space; an OPTIONAL companion
profile MAY define an additional state for a lifecycle it introduces
(for example, a paused or a superseded state), but only `active` ever
permits issuance. To keep the state space extensible without a registry,
a consumer MUST apply this forward-compatibility rule wherever a Mission
state is reported, including the Mission record, the `mission` claim,
and the introspection response: only the exact value `active` permits
derivation or continued reliance, and every other value, including a
value the consumer does not recognize, MUST be treated as non-active and
non-deriving. A consumer MUST NOT fail open on an unrecognized state.
This makes a state added by a companion profile fail safe for a consumer
that predates it.

## Issuance Gating

The AS MUST refuse to derive a token, at the token endpoint, on
refresh, and on Token Exchange ({{RFC8693}}), unless the
referenced Mission is `active`. Issuance against a `revoked` or
`expired` Mission MUST fail with `invalid_grant`. Because derivation
is gated on Mission state, revoking or expiring a Mission stops all
further authority for the task, including refresh.

When the Mission Intent sets `context.max_derivations`, the AS MUST
maintain a per-Mission count of **derivations** and MUST refuse with
`invalid_grant` any derivation that would exceed the bound. A
derivation is one issuance operation the origin AS performs for a
single request: the initial authorization-code exchange, a refresh, a
Token Exchange, or an ID-JAG issuance ({{cross-domain}}). Each counts
as exactly one, regardless of how many artifacts it emits: a code
exchange that returns both an access token and a refresh token is one
derivation, and a refresh that rotates both is one. The exact rules:

- A derivation that fails, including one refused for exceeding the
  bound, MUST NOT be counted.
- The check and increment MUST be atomic with issuance, so concurrent
  derivations cannot collectively exceed the bound.
- The count covers only derivations the origin AS performs. Tokens a
  Resource AS mints from an ID-JAG ({{cross-domain}}) are NOT counted
  by the origin (the origin cannot observe them); the ID-JAG issuance
  that authorized them was counted once, and the Resource AS bounds
  its own local issuance by its policy.

The AS maintains this count as internal bookkeeping; it is operational
state, not part of the immutable Mission record.

Derived tokens SHOULD be short-lived so that a transition to
`revoked` or `expired` takes effect promptly without per-request
revocation checks.

## Revocation {#revocation}

A Mission is revoked when the AS receives an authorized revocation
for it. A deployment MUST provide an authenticated means for the
Subject, the Approver, or an administrator to revoke a Mission by
`mission_id`, independent of possession of any token (so a Mission
can be stopped even when no refresh token is held).

This document does not define the wire shape of that operation.
Revocation is a management-plane action by a party in the AS's own
trust domain, not a cross-party protocol exchange, and the lifecycle
gate that makes it effective ({{lifecycle}}, {{introspection}})
already rides on existing endpoints, so no standardized endpoint is
required for interoperability. A standardized Mission management API,
and the richer `suspend`/`complete` operations, are deferred to future
work.

A deployment MAY additionally treat {{RFC7009}} revocation of a
Mission's refresh token as revoking the Mission. A deployment MUST NOT
couple routine token revocation to Mission revocation unless it
documents that behavior. Already-issued access tokens remain valid
until they expire; a deployment requiring lower cutoff latency SHOULD
use short token lifetimes.

The stateless baseline needs no status surface: a token is a
self-contained authorization and verification is stateless. A
deployment MAY additionally offer token introspection
({{introspection}}) so a Resource Server can observe Mission state
per request and cut off a revoked Mission without waiting out the
token lifetime. A canonical Mission Status surface (keyed by
`mission_id`) and signed status responses are specified separately as
an OPTIONAL companion profile by Mission Status
{{I-D.draft-mcguinness-oauth-mission-status}}; this document does not
require them.

# Mission State via Token Introspection {#introspection}

This section is OPTIONAL. The stateless baseline
({{mission-bound-tokens}}) needs no introspection; an AS that does not
offer it, and a Resource Server that does not use it, are unaffected.
It lets a Mission-state-aware Resource Server observe a Mission's
current state per request instead of waiting out a token's lifetime.
Because it can report Mission state for a token whose Mission is no
longer `active`, this section deviates from the {{RFC7662}} default of
omitting response members for an inactive token; that additional
disclosure is governed by the caller-authorization and minimization
rules below ({{caller-authorization-and-minimization}}).

An AS MAY support OAuth 2.0 Token Introspection {{RFC7662}} for
Mission-bound access tokens. When it does, the response for such a
token carries, in addition to the standard members, a `mission` member
in one of two shapes, depending on whether the responding AS holds the
Mission:

- From the Mission `origin`: `id`, `origin`, and `authority_hash` (as
  in the `mission` claim, {{mission-claim}}) plus the current lifecycle
  `state` (string). The core states are `active`, `revoked`, and
  `expired` ({{lifecycle}}); a deployment that runs a companion profile
  defining an additional state reports that state here, and a consumer
  applies the forward-compatibility rule of {{lifecycle}} (only `active`
  permits reliance; any other value, recognized or not, is non-active).
- From a non-origin Resource AS (which holds a local token it minted
  from a cross-domain grant, not the Mission): the claim-shape members
  only. Such an AS MUST omit `state`, since it cannot report current
  Mission state ({{only-origin-reports-state}}).

The AS includes the `mission` member only when it has authenticated the
caller, the caller is authorized for the token
({{caller-authorization-and-minimization}}), and the presented token
resolves to a Mission. For a malformed, unknown, expired-as-issued, or
otherwise unresolvable token, the AS responds per {{RFC7662}}
(`active: false`) with no `mission` member; it does not reveal Mission
state for a token it cannot bind to a Mission. The case below
(`active: false` with `mission.state`) applies only to a token that is
itself valid but whose Mission is no longer `active`.

## Caller Authorization and Minimization {#caller-authorization-and-minimization}

The introspection endpoint is protected per {{RFC7662}}. The AS:

- MUST authenticate the calling party.
- MUST return Mission data only to a caller authorized to receive
  it, in particular a Resource Server that is an audience of the
  token.
- MUST audience-filter the response, returning the
  `authorization_details` entries and Mission data relevant to the
  caller's audience and not disclosing entries addressed to other
  audiences ({{audience-scope}}).

Because this profile returns the `mission` member and `mission.state`
even when `active` is `false` (diverging from the {{RFC7662}} default
of omitting members for inactive tokens), the AS MUST apply this same
authorization and minimization to that data and MUST NOT reveal
Mission detail to an unauthorized introspection caller.

## Composite `active`

The introspection `active` member reflects the composite
authorization, not the token in isolation. The AS MUST return
`active: true` only when the access token is itself valid (valid
signature, unexpired, and not individually revoked) AND the Mission
is `active`. The AS does not verify the token's sender-constraint
(`cnf`) at introspection: proof of possession is checked by the
Resource Server when the token is presented, not by the AS over an
introspection call, so `active: true` is not by itself evidence the
caller holds the bound key.

When the token is otherwise valid but the Mission is `revoked` or
`expired`, the AS MUST return `active: false` and include
`mission.state` giving the reason, so a Resource Server can
distinguish a dead Mission from a bad token. (This extends the
{{RFC7662}} default of omitting members when `active` is `false`.) A
Mission transition does not by itself revoke the token as an
individual credential; introspection reports the composite
authorization as inactive.

## Only the Origin Reports Mission State {#only-origin-reports-state}

An AS MUST NOT include `mission.state` in an introspection response
unless it holds the Mission, that is, unless it is the Mission
`origin`. A Resource AS introspecting a local token it minted from an
ID-JAG ({{cross-domain}}) knows the Mission state only as of ID-JAG
validation and has no query to the origin keyed by `mission_id` (this
document defines none); it MUST omit `mission.state` rather than
report a stale value as current. `authority_hash`, when included, is
the origin reporting its own commitment, not the introspecting party
recomputing a subset ({{consent-binding}}).

This is token introspection: it answers "is this token's
authorization still good," keyed by the token presented. The
canonical Mission Status surface (keyed by `mission_id`) remains out of scope
({{revocation}}).

## Example

A Mission-bound token whose Mission has been revoked, introspected at
the origin AS:

~~~ json
{
  "active": false,
  "mission": {
    "id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
    "origin": "https://as.example.com",
    "authority_hash":
      "sha-256:l3KvZ4mP5x0wQrR6tY2nD9bM7sX1cF8gH2vJ4kE5pNQ",
    "state": "revoked"
  }
}
~~~

While the Mission is `active`, the response is the standard
{{RFC7662}} body (`active: true`, `sub`, `client_id`, `aud`, `exp`,
`authorization_details`, ...) plus the `mission` member carrying
`state: active`.

# Delegation Within a Mission {#delegation}

This section is OPTIONAL. A deployment whose agents never delegate, and
a Resource Server that sees no delegated tokens, are unaffected.

An agent may delegate execution to downstream actors (a sub-agent,
service, or tool that is itself an OAuth client) within a Mission.
Delegation is represented with the OAuth Actor Profile
{{I-D.draft-mcguinness-oauth-actor-profile}}, which profiles the
RFC 8693 {{RFC8693}} `act` (actor) claim.

A delegate obtains a delegated token by Token Exchange
({{RFC8693}}). The AS issues the delegated token subject to all of
the following:

- **The exchange is explicit.** The delegating Mission-bound access
  token is the `subject_token`, with `subject_token_type` of
  `urn:ietf:params:oauth:token-type:access_token`. The delegate is
  identified by an `actor_token` (with its `actor_token_type`) or by
  its own client authentication, and the AS asserts the actor itself
  ({{delegation-constraints}}); a `requested_token_type` of
  `urn:ietf:params:oauth:token-type:access_token` is used. The
  response carries the matching `issued_token_type` and a `token_type`
  for the issued access token, per {{RFC8693}} Section 2.2.1.
- **Subject is stable.** `sub` remains the Mission's Subject. The
  delegate is an actor, not the subject.
- **The approved agent stays `client_id`.** This profile keeps
  `client_id` equal to the Mission's approved agent on every derived
  token ({{mission-bound-tokens}}), so the approved party is
  verifiable everywhere. Downstream delegates are carried in the
  `act` chain, not in `client_id`. This is a deliberate choice over
  the {{RFC9068}} reading in which `client_id` is the immediate
  client; here the immediate delegate is the outermost `act`.
- **The `act` chain identifies the delegates.** The delegated token
  carries an `act` claim per the Actor Profile
  {{I-D.draft-mcguinness-oauth-actor-profile}}: the outermost `act` is
  the immediate delegate, with prior delegates nested inward, back
  toward the approved agent. Each actor object
  carries the members that profile defines (`sub`, `iss`, and the
  RECOMMENDED `sub_profile` actor-type classification, e.g.
  `ai_agent`). This document does not re-specify the `act` structure.
- **Authority only narrows.** The delegated token's
  `authorization_details` MUST be a subset ({{subset}}) of the
  delegating token's authority, hence of the Mission Authority Set.
  Delegation MUST NOT add authority.
- **The Mission binding rides unchanged.** The delegated token
  carries the same `mission` claim ({{mission-claim}}), its
  `id`, `origin`, and `authority_hash`, so every actor in
  the chain operates under the one consented authority.
- **Each delegate is bound to its own key.** The delegated token MUST
  be sender-constrained ({{mission-bound-tokens}}) to the **delegate's
  own** key: its `cnf` is the delegate's DPoP or mTLS key, not the
  delegating party's. The delegate proves possession of that key in
  the Token Exchange. A compromised delegate key therefore cannot be
  replayed as the agent or as another actor in the chain, and each
  actor's credential is independently revocable by key.
- **Each delegation is gated.** Issuing a delegated token is a
  derivation event; the AS MUST refuse it unless the Mission is
  `active` ({{lifecycle}}).

## Delegation Constraints {#delegation-constraints}

What may be delegated, how far, and to whom is governed per
Authority Set entry by the entry's optional `delegation` member
({{authorization-derivation}}). Because the policy lives in the
entry, it is committed by `authority_hash` with the rest of the
Authority Set and travels with the audience-scoped entries across the
cross-domain hop ({{cross-domain}}), needing no separate mechanism.

**Delegation depth.** The delegation depth of a token is the number
of actors in its `act` chain (the nesting depth of the `act` claim),
counted from the approved agent: the agent's own non-delegated token
is depth 0, the first delegate is depth 1, and each further delegate
adds 1. The depth checked against `max_depth` is that of the token
being issued, computed after appending the new outermost actor, not
the depth of the delegating token. A cross-domain grant carries no
`act` chain ({{cross-domain-grant}}) and so enters the target domain
at depth 0; a Resource AS that then issues delegated tokens of its own
counts from there ({{validation-at-resource-as}}).

**Per-entry enforcement.** When the AS issues a token to a delegate
(the actor that becomes the outermost `act`) at delegation depth
`d`, it includes a Mission Authority Set entry in the delegated
token's `authorization_details` only if all of the following hold:

1. the entry carries a `delegation` member (otherwise it is
   non-delegable, which is the default);
2. `d` is less than or equal to the entry's `delegation.max_depth`;
   and
3. the delegate is permitted by `delegation.allowed_delegates`, or
   that member is absent.

An entry failing any of these narrows out of the delegated token,
consistent with the subset rule ({{subset}}). The `delegation`
member is policy, not authority, and is not part of the subset
comparison; surviving entries are carried with their `delegation`
member intact so the next hop is evaluated the same way.

**Matching `allowed_delegates`.** Each entry is a matcher object
modeled on the RFC 8693 `may_act` actor object ({{RFC8693}} Section
4.4): where `may_act` names a single party eligible to act on a token,
`allowed_delegates` is a per-Authority-Set-entry *list* of such
matchers, generalized to actor-type classes. A `{ "sub": ... }`
matcher permits a specific delegate by client identifier; a
`{ "sub_profile": ... }` matcher permits any actor of that type (for
example, `ai_agent`). A deployment can thus permit a specific client,
a class of actors, or both, and a delegate is permitted if it matches
any entry. The AS MUST authenticate the delegate at the Token Exchange
and assert the actor's `sub` and `sub_profile` itself. A self-asserted
`sub_profile` MUST NOT satisfy a matcher; otherwise a client could
claim any actor type to bypass the constraint.

A `{ "sub": ... }` matcher is a client identifier in the issuing AS's
namespace and is not portable across a trust domain. When a Resource
AS evaluates a conveyed entry ({{cross-domain}}), it MUST fail closed,
narrowing the entry out, for any `sub` matcher it cannot resolve
against the delegate it authenticated in its own namespace. Portable
cross-domain matching SHOULD therefore use a `sub_profile` matcher, an
actor-type class rather than a domain-relative identifier.

**Empty result.** If narrowing leaves no entries for the delegate,
the AS MUST refuse with `invalid_grant` rather than issue a token
with empty authority.

**The Resource Server enforces none of this.** Delegation
constraints are applied by the AS at issuance; a Resource Server sees
only the already-narrowed `authorization_details` and enforces those
as usual ({{mission-bound-tokens}}).

## Worked Example: Delegated Token

Suppose the Mission's Authority Set has two entries on the ERP:
`invoices.read`, delegable to `ai_agent` actors through depth 2; and
`journal-entries.write`, which carries no `delegation` member and is
therefore non-delegable. The approved agent `s6BhdRkqt3` delegates to
sub-agent `tool-runner-7`, an `ai_agent`, at depth 1. The read entry
is permitted (depth 1 <= 2, `ai_agent` allowed) and the write entry
narrows out. The decoded delegated access token:

~~~ json
{
  "iss": "https://as.example.com",
  "sub": "user_3p2q8mN1a0kV7tR",
  "aud": "https://erp.example.com",
  "client_id": "s6BhdRkqt3",
  "iat": 1797840600,
  "exp": 1797840900,
  "jti": "at_3qX5bN7sR1tY8mZ9Kp2v",
  "authorization_details": [
    { "type": "mission_resource_access",
      "resource": "https://erp.example.com",
      "actions": ["invoices.read"],
      "delegation": {
        "max_depth": 2,
        "allowed_delegates": [{ "sub_profile": "ai_agent" }]
      } }
  ],
  "act": {
    "sub": "tool-runner-7",
    "iss": "https://as.example.com",
    "sub_profile": "ai_agent"
  },
  "cnf": { "jkt": "qVx7y2N0p4Lq9Md3sZJ8b8mZ3rN2xT5pV4lE6sQqYY" },
  "mission": {
    "id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
    "origin": "https://as.example.com",
    "authority_hash":
      "sha-256:l3KvZ4mP5x0wQrR6tY2nD9bM7sX1cF8gH2vJ4kE5pNQ"
  }
}
~~~

`sub` is still the user and `client_id` is still the approved agent;
`tool-runner-7` appears only as the actor. The `cnf` is
`tool-runner-7`'s own key, not the agent's, so this token cannot be
replayed as the agent. The non-delegable write entry was dropped; the
read entry survives, carrying its `delegation` member so a further hop
can be evaluated: a depth-3 delegate, or a non-`ai_agent` one, would
narrow it out too. The `mission` claim is unchanged.

# Cross-Domain Missions {#cross-domain}

This section is OPTIONAL. The single-domain core is complete without
it; a deployment whose Missions never leave their issuing AS is
unaffected.

A Mission is approved and held by one Mission Issuer (its `origin`).
This section lets a single Mission be honored by Authorization
Servers in other trust domains, so a Mission can span more than one
AS, using the cross-domain authorization grant of the OAuth identity
chaining architecture {{I-D.draft-ietf-oauth-identity-chaining}}: the
origin AS issues, through an {{RFC8693}} token exchange, a short-lived
JWT authorization grant audienced to the target Authorization Server,
which the client redeems there with the {{RFC7523}} JWT-bearer grant.

This document calls that artifact the **cross-domain grant** and
attaches Mission context to it ({{cross-domain-grant}}). The Identity
Assertion Authorization Grant (ID-JAG)
{{I-D.draft-ietf-oauth-identity-assertion-authz-grant}} is the
RECOMMENDED profile of the cross-domain grant, and every example in
this document uses it; another identity-chaining JWT authorization
grant profile that meets the requirements of {{cross-domain-grant}}
MAY be used instead. Where a requirement elsewhere in this document
names the ID-JAG, it is illustrating with the recommended profile and
applies equally to any conforming cross-domain grant.

This entire section is OPTIONAL. An AS that issues no cross-domain
grant, and a deployment confined to a single trust domain, ignore it;
the rest of this document is fully implementable without it.

This section is a thin Mission-bound profile of the cross-domain
grant, not merely `mission`-claim carriage: beyond attaching and
validating Mission context, it imposes two security requirements on the
grant for Mission-bound use, proof-of-possession and single use
({{cross-domain-grant}}, {{validation-at-resource-as}}). The grant's
own format, signing, and token-exchange envelope remain defined by the
cross-domain grant profile (ID-JAG in the recommended case) and its
underlying {{RFC8693}} and {{RFC7523}}; this document does not redefine
them. The two added requirements are a floor: the cross-domain grant is
the highest-authority credential crossing a trust boundary, and its
profile does not by itself guarantee them.

In this model there is exactly one Mission Issuer per Mission (the
`origin`) and one or more **Resource ASes** in other domains that
mint their own tokens for their resources. A Resource AS is never the
Mission Issuer and MUST NOT create or alter a Mission.

## Audience-Scoped Authority {#audience-scope}

When projecting authority toward a Resource AS, the Mission Issuer
includes only the Authority Set entries whose `resource` that
Resource AS is authoritative for, under the deployment's
resource-to-AS mapping. Entries for other Resource ASes MUST NOT be
disclosed.

## Issuing the Cross-Domain Grant {#cross-domain-grant}

Issuing a cross-domain grant is a derivation event and is gated like
any other ({{lifecycle}}). A Mission-bound cross-domain grant:

- MUST be a JWT authorization grant issued and signed by the Mission
  `origin`, redeemable at the target Resource AS through the
  {{RFC7523}} JWT-bearer grant;
- MUST be audienced to the target Resource AS, and MUST NOT have a
  lifetime exceeding 300 seconds (a short lifetime bounds cross-domain
  revocation latency; see {{cross-domain-revocation}});
- MUST be sender-constrained ({{RFC7800}}) to the presenting client by
  the proof-of-possession mechanism the cross-domain grant profile
  defines (for the ID-JAG profile, as that specification defines). This
  document does not define a new PoP mechanism; the originating AS and
  the Resource AS MUST use the mechanism of the profile in use, so that
  binding and verification interoperate;
- MUST carry a `jti` for one-time use, so the bound party cannot
  replay it within its lifetime ({{validation-at-resource-as}},
  {{RFC7523}} Section 3);
- MUST carry the `mission` claim ({{mission-claim}}) with `id`,
  `origin`, and `authority_hash` unchanged from the Mission, and the
  audience-scoped `authorization_details` ({{audience-scope}}); and
- MUST convey the Mission's Subject in the form the identity chaining
  architecture defines, so the Resource AS can resolve it locally
  ({{validation-at-resource-as}}).

The ID-JAG profile meets these requirements and is RECOMMENDED; in it
the artifact is the ID-JAG and the issuance request carries a
`requested_token_type` of `urn:ietf:params:oauth:token-type:id-jag`.

The client obtains the grant with an {{RFC8693}} token exchange. The
`subject_token` MUST be the Mission's refresh token, with
`subject_token_type` of
`urn:ietf:params:oauth:token-type:refresh_token`, and the `audience`
identifies the target Resource AS. This refresh-token mode is what
binds the request to a Mission: the AS resolves the Mission from the
presented grant per {{grant-binding}}, exactly as on any other
refresh, and the grant therefore projects the agent's full Mission
authority (audience-scoped), never a narrowed delegate's.

This profile intentionally fixes the refresh-token subject mode to
remove any ambiguity about which Mission authority a cross-domain grant
projects: the refresh token resolves to exactly one Mission and its
full authority, whereas an access token or delegated token could carry
a narrowed or actor-specific subset. The cost is that this optional
cross-domain binding is unavailable to a deployment that issues no
refresh token; such a deployment uses the single-domain core, which
needs no refresh token.

The AS MUST reject an access token or a delegated token presented as
`subject_token` for cross-domain issuance. The AS MUST NOT resolve the
Mission from a client-supplied `mission_id`, nor from an identity
assertion that carries no Mission binding.

Before issuing, the AS MUST verify the Mission is `active` (failing
otherwise with `invalid_grant`) and that the target Resource AS is
authorized for the requested resources under the Mission's Authority
Set (failing otherwise with `invalid_target`, {{RFC8693}}). The token-exchange
response carries `issued_token_type` of
`urn:ietf:params:oauth:token-type:id-jag` (for the RECOMMENDED
profile) and `token_type` of `N_A`, per {{RFC8693}} Section 2.2.1.

This profile defines only the refresh-token `subject_token` mode above.
Other Mission-bound subject-token modes, such as an access-token
subject mode (which would have to bound the projected authority by the
presenting token rather than by the full Mission Authority Set), are
left to future profiles. Excluding the access-token subject mode here
is a deliberate choice for this minimum-viable profile: it avoids
propagating a narrowed or delegated authority across a trust boundary,
where it could be re-widened. A deployment that does not issue the
agent a Mission refresh token therefore cannot use this OPTIONAL
cross-domain hop as defined here.

A delegate, rather than the agent, crossing a trust domain directly
and carrying its own narrowed authority into another domain is out of
scope for this document and deferred to future work. Cross-domain
issuance here always projects the agent's Mission authority; delegation
within the target domain is performed by the Resource AS
({{validation-at-resource-as}}). A sub-agent that must act in a
different trust domain under its own narrowed authority is therefore not
covered by a single hop; distributed multi-agent work across domains
composes only through the agent's projected authority or through
separate Missions per domain. A delegate-carries-its-own-authority mode
is future work.

Two roles must not be conflated. The grant the client presents to
*obtain* the cross-domain grant (the Mission's refresh token) is the
input to the exchange and selects the Mission; the Mission-bound
access token plays no part here. The identity the issued grant conveys
*to* the Resource AS is the Mission's Subject, which the AS populates
from the Mission's recorded `subject` and which the Resource AS
resolves locally per the identity chaining rules (this document
defines no cross-domain subject mapping, {{validation-at-resource-as}}).

Sender-constraining is REQUIRED for the cross-domain grant, stronger
than the RECOMMENDED level for the primary access token
({{mission-bound-tokens}}): it is the highest-authority credential in
the chain and the only one that crosses a trust boundary, and the
underlying grant provides no replay backstop of its own.

## Validation at the Resource AS {#validation-at-resource-as}

A Resource AS consuming a Mission-bound cross-domain grant:

- MUST establish issuer trust in the originating AS by local policy
  or issuer metadata before accepting any Mission reference. It MUST
  NOT trust a `mission.origin` merely because it appears inside a
  signed assertion.
- MUST validate the grant's signature and expiry, and verify its
  `aud` is the Resource AS's own identifier, rejecting a grant
  minted for a different Resource AS.
- MUST verify the grant's sender-constraint by the proof-of-possession
  mechanism the cross-domain grant profile defines (for the ID-JAG
  profile, as that specification defines), and MUST reject with
  `invalid_grant` a cross-domain grant that is not sender-constrained
  or whose proof-of-possession does not verify. A bearer grant MUST
  NOT be accepted: it is the highest-authority credential crossing the
  trust boundary, so accepting one unbound would let any party that
  captured it mint a local token.
  - Because this document defines no cross-domain status query,
    freshness is the Resource AS's only check that the Mission was
    active at issuance; the short grant lifetime bounds the staleness.
- MUST reject a replayed cross-domain grant: it MUST track the grant's
  `jti` for the grant's validity window and refuse a second
  presentation with `invalid_grant` ({{RFC7523}} Section 3), so a grant
  cannot be replayed even by the party it is bound to.
- When issuing local access tokens for its resources, the Resource AS
  uses the subject-resolution rules of the underlying cross-domain
  grant and identity chaining specifications. The local token preserves
  the `mission` claim (`id`, `origin`, and `authority_hash`) unchanged
  from the cross-domain grant. The issuing `iss` is the Resource AS;
  `mission.origin` remains the originating AS. Such a local token:
  - has an `exp` that MUST NOT exceed the grant's `exp`
    ({{mission-bound-tokens}}), which bounds it transitively by
    `mission_expiry`;
  - MUST be sender-constrained ({{RFC7800}}), like the grant it derives
    from, and MUST NOT be issued as a bearer token; and
  - if it preserves the origin `client_id`, does so only as an audit
    reference, not a local identity: that value is in the originating
    AS's namespace, and a partner Resource Server MUST NOT resolve or
    authorize on it as a local client, for the same portability reason
    that applies to a `sub` matcher in `allowed_delegates`
    ({{delegation-constraints}}).
- MUST bound the issued `authorization_details` by what the
  cross-domain grant conveyed, and MUST apply its own local
  authorization policy in addition: honoring a Mission does not
  obligate it to authorize any particular request. Because the
  conveyed entries were derived under the originating AS's local policy,
  the Resource AS does not re-derive them; it interprets and enforces
  them by their structure and vocabulary. It MUST fail closed on a
  conveyed `actions` identifier or `constraints` key it does not
  recognize for the resource in question, exactly as a Resource Server
  does ({{rs-enforcement}}), so authority it cannot interpret is never
  honored across the trust boundary rather than enforced by guess.
- MUST, when it issues delegated tokens of its own, enforce each
  entry's `delegation` policy as in {{delegation-constraints}}; the
  policy travels on the conveyed entries. The cross-domain grant
  carries no `act` chain ({{cross-domain-grant}}), so the Resource
  AS's own delegation depth begins at 0.

This document does not define cross-domain subject mapping. A Resource
AS consuming a Mission-bound cross-domain grant resolves the subject
of any local token according to the cross-domain grant profile in use
(the Identity Assertion Authorization Grant profile in the recommended
case), the OAuth identity chaining architecture, and its local trust
and account-linking policy. This document only requires that the
Mission binding (`mission.id`, `mission.origin`, and `authority_hash`)
and the audience-scoped `authorization_details` remain bounded as
described here.

Downstream, `authority_hash` is an immutable audit and correlation
anchor to the originating AS's consent commitment. A Resource AS and
its Resource Servers hold only the audience-scoped subset, never the
full Authority Set, so they cannot recompute `authority_hash`
({{integrity-anchors}}); its integrity rests on the signature chain
(the originating AS signs the ID-JAG; the Resource AS validates
issuer trust and signs its local token). It is verifiable only
against the originating AS, which this document does not require to
be exposed.

# Extensibility {#extensibility}

This profile is a base layer that other agent-authorization work is
expected to extend. Extensions add alongside the stable interface
below; they MUST NOT redefine it. An extension MAY rely on these
remaining stable across revisions of this profile:

- the `mission` claim members `id`, `origin`, and `authority_hash`
  ({{mission-claim}});
- the `mission_resource_access` authorization details shape
  ({{authorization-derivation}}); and
- the `act` delegation chain ({{delegation}}).

The profile offers three extension points, each a declared seam rather
than new machinery:

- **Authority types.** The Authority Set is open to other AS-supported
  `authorization_details` types ({{other-types}}); the Mission
  apparatus (commitment, gating, delegation) is type-agnostic toward
  them, subject to the delegation and projection limits in
  {{other-types}}.
- **Integrity anchors.** Additional committed objects use the same
  domain-separated, issuer-bound envelope with a new `typ`
  ({{integrity-anchors}}). A consent-disclosure commitment, an
  instruction-text attestation, or a delegation receipt can be
  committed this way without changing this profile. A profile that
  commits an evidence or disclosure object MUST commit it with this
  envelope and a collision-resistant `typ`, not by hashing the bare
  object, so the domain separation and issuer binding hold uniformly. A
  `mission` descriptor embedded in such an object uses the `mission`
  claim shape ({{mission-claim}}), optionally extended with
  collision-resistantly named members (for example, an `intent_hash`
  for audit), and is never authority-bearing on its own.
- **The `mission` claim.** It is an open object ({{mission-claim}}):
  additional, collision-resistantly named members ride the mission
  binding (for example, a runtime decision reference, a delegation
  receipt, or an attestation reference), and consumers ignore unknown
  members and never derive authority from them.
- **Lifecycle state.** The lifecycle state space ({{lifecycle}}) is open
  to additional states defined by companion profiles for lifecycles they
  introduce. The forward-compatibility rule in {{lifecycle}} keeps this
  safe without a registry: only `active` permits issuance, and a consumer
  treats every other state, recognized or not, as non-active.

This document defines no extension registry, capability-negotiation
mechanism, or profile-version field; an extension declares its own
identifiers and, where it needs discovery, its own metadata. The
extensibility of the `typ` value space, the `mission` claim, and the
lifecycle state space rests on collision-resistant naming and the
fail-safe rules above rather than on central registration.

# Authorization Server Metadata {#discovery}

An AS MAY advertise support for this specification in its
authorization server metadata {{RFC8414}}:

`mission_bound_authorization_supported`:
: OPTIONAL boolean. When `true`, the AS supports the core Mission
  Issuer surfaces of this profile ({{conformance}}): the
  `mission_intent` authorization request parameter through PAR
  ({{mission-intent}}), derivation of `mission_resource_access`
  authorization details ({{authorization-derivation}}), Mission-bound
  access tokens ({{mission-bound-tokens}}), and the `mission` JWT claim
  ({{mission-claim}}). It asserts Mission Issuer support only; it makes
  no claim about any Resource Server, nor about the OPTIONAL
  capabilities (delegation, introspection, cross-domain Missions),
  which are discovered out of band or by attempt ({{conformance}}).

An AS that advertises this profile SHOULD also include
`mission_resource_access` in its `authorization_details_types_supported`
metadata ({{RFC9396}}), so that RFC 9396-aware clients
discover the authorization details type through the standard mechanism.
A client MAY use the RFC 9396 client metadata `authorization_details_types`
at registration to declare the types it understands.

Discovery is OPTIONAL: a deployment MAY arrange Mission-bound
authorization out of band, and this member only lets an AS advertise
it. When the member is absent or `false`, a client MUST NOT infer
that the AS supports this specification.

# Security Considerations

## Consent Binding {#consent-binding}

The security goal of this document is that a user's approval of a
task bounds every token derived for it. The `authority_hash` is the
mechanism: it commits the exact Authority Set the Approver
consented to, and every derived token carries it in the `mission`
claim. An AS MUST compute `authority_hash` over the same Authority
Set it rendered for consent, and MUST re-render and re-consent if that
set changes ({{approval-event}}). `authority_hash` commits the full
Authority Set, while a derived token may carry a narrowed subset, so a
Resource Server cannot in general recompute it from the token alone. A
Resource Server that independently holds the full Authority Set MUST
reject a token whose set does not match `authority_hash`; otherwise
`authority_hash` serves as a whole-Mission audit and correlation anchor
({{cross-domain}}) and the Resource Server enforces the token's
`authorization_details` directly ({{mission-bound-tokens}}).

`intent_hash` extends the same protection to the task itself: it
commits the approved Mission Intent, so an auditor can detect any
later alteration of the recorded task, independently of the authority
derived from it. The two anchors are domain-separated
({{integrity-anchors}}); neither is a substitute for the other.

The task and the authority are committed separately, rather than folded
into one hash over the whole Mission, because they are distinct objects
with distinct uses. `authority_hash` commits what a Resource Server
enforces and what a cross-domain projection carries, so it MUST be
verifiable from a token that conveys only the authority, without the
Intent. `intent_hash` commits the task as audit material, tamper-evident
even where the authority is projected without the Intent travelling with
it. One combined hash could not serve both a token that carries
authority alone and an auditor that holds the task alone.

Neither anchor proves the Approver understood the rendered task, nor
that the AS rendered it faithfully; they commit what the AS
recorded, and make post-hoc tampering of those records detectable.

This profile commits the task (`intent_hash`) and the authority
(`authority_hash`) the Approver consented to, but deliberately does
not commit the **rendered consent disclosure** itself: the locale,
disclosure-template version, and material notices the Approver was
shown are not bound by any anchor here. Because of this gap, a buggy or
malicious rendering layer could mislead the Approver, showing a
narrower or different task than the Authority Set actually committed,
without leaving any committed trace. A deployment whose Missions carry
high-risk authority SHOULD therefore record presentation-level audit
evidence: for example, a hash over the exact consent disclosure
rendered to the Approver, retained so the disclosure shown can be
reconstructed and audited after the fact. Binding this on the wire (a
`consent_rendering_hash` over a structured consent-disclosure object)
is specified as an OPTIONAL companion profile by Mission Consent
Evidence {{I-D.draft-mcguinness-oauth-mission-consent-evidence}}; an AS
that does not implement it MAY record equivalent evidence out of band.
As that profile makes explicit, such a commitment binds the structured
disclosure the AS records, not the pixels actually presented; it
narrows this gap for audit but does not close it.

## Mission Drift

Because issuance is gated on Mission state and bounded by the
Authority Set, an agent cannot escalate beyond the approved task by
acquiring additional tokens: every derived token is a subset of the
approved authority ({{subset}}), and no token can be derived once the
Mission is `revoked` or `expired`. Deployments SHOULD keep derived
token lifetimes short so state transitions take effect promptly.

## Issuance Scope, Not Runtime Enforcement {#runtime-boundary}

This profile governs the issuance and derivation of authority: it
bounds what authority a Mission yields, binds it to the Approver's
consent, and gates derivation on Mission state. It does not evaluate
individual runtime actions. In particular, it does not:

- evaluate a request's parameters against the Mission at the point of
  use;
- produce runtime enforcement evidence for each consequential action;
- bind tool or function identities to the Mission; or
- re-evaluate at execution time to close the
  approval-to-execution (time-of-check to time-of-use) gap.

Mission governance is necessary but not sufficient. An active Mission
still bounds a set of authority an agent may exercise freely within a
token's lifetime, so an active Mission can become ambient authority
for individual consequential actions. Preventing that requires a
runtime enforcement layer that evaluates each consequential action
against the Mission and records evidence; such a layer composes with
this profile and is out of scope here. Short token lifetimes and
narrow authority bound, but do not eliminate, this exposure.

## Token Theft

Derived tokens are sender-constrained (DPoP {{RFC9449}} or mTLS
{{RFC8705}}) at the levels set in {{mission-bound-tokens}},
{{cross-domain-grant}}, and {{validation-at-resource-as}}: SHOULD for
the primary access token, MUST for delegated tokens, cross-domain
grants, and Resource AS local tokens. A stolen token is bounded by the
Authority Set and the Mission lifetime regardless, but
sender-constraint prevents replay by a different party.

## Delegation and Chain Compromise

Delegation ({{delegation}}) widens the set of parties holding
Mission-derived authority. Because authority only narrows down the
chain, a compromised actor can act only within the authority it was
delegated, for the lifetime of the token it holds: the exposure of
any actor is bounded by its narrowed `authorization_details` times
its token lifetime. The per-entry delegation constraints
({{delegation-constraints}}) bound this exposure at approval time:
non-delegable entries never reach a delegate at all, `max_depth`
caps how far an entry can propagate, and `allowed_delegates`
restricts who may receive it. Note that `max_depth` bounds the
*length* of a delegation chain, not its *breadth*: fan-out to many
distinct depth-1 delegates is bounded only by `allowed_delegates`, so
a deployment that needs to limit breadth MUST constrain
`allowed_delegates` (and MAY use `max_derivations` to cap total
derivations). Because each delegated token is bound
to the delegate's own key ({{delegation}}), a compromised delegate is
confined to its own narrowed credential: it cannot replay as the
agent or another actor, and its credential can be revoked by key
without revoking the rest of the chain. Deployments SHOULD keep
delegated token lifetimes short and SHOULD make only the entries that
need delegation delegable.

## Cross-Domain Revocation Latency {#cross-domain-revocation}

Single-domain revocation is prompt: the AS that issued a token also
honors its revocation ({{revocation}}). The cross-domain case
({{cross-domain}}) is strictly weaker. When a Mission is revoked at
the originating AS, that AS can stop issuing new ID-JAGs, but it
cannot revoke a token a Resource AS has already minted in another
domain: that token remains valid until its own expiry. Cross-domain
revocation latency is therefore the downstream token lifetime. For
this reason, Resource ASes MUST issue short-lived local tokens for
Mission-bound interactions; the originating AS bounds ID-JAG lifetimes
by the 300-second cap of {{cross-domain}}, so a revoked Mission cannot
continue to seed new downstream tokens for long.
The introspection of {{introspection}} closes the revocation gap only
single-domain: it requires the introspecting AS to hold the Mission,
and a Resource AS has no query to the origin keyed by `mission_id`, so short
downstream lifetimes remain the only cross-domain control. Deployments
needing tighter cross-domain revocation can add the status or
event-distribution mechanisms specified separately by Mission Status
{{I-D.draft-mcguinness-oauth-mission-status}} and Mission Lifecycle
Signals {{I-D.draft-mcguinness-oauth-mission-signals}}, which this
document does not require.

## Signing and Key Rotation

The `mission` claim and `authorization_details` are carried inside
the {{RFC9068}} JWT and are covered by the AS's token signature; their
integrity reduces to the AS's signing key. An AS MUST publish its
verification keys (for example, via {{RFC8414}} `jwks_uri`) and
SHOULD retain the verification key for each key identifier it has
signed under long enough to verify tokens issued before a rotation.

## Compromised or Over-Broad Derivation

The AS is trusted to derive authority no broader than the Mission
Intent. Deployments SHOULD constrain derivation with explicit
resource and action mappings rather than free-form inference, and
SHOULD record `policy_version` so a derivation can be audited and
reproduced. General OAuth security guidance {{RFC9700}} applies.

## Authority Hash Is Not a Mission Identifier

`authority_hash` commits the approved Authority Set, not the Mission.
Two distinct Missions that approve byte-identical authority carry the
same `authority_hash`: a successor Mission that re-approves the same
Authority Set, or an unrelated Mission with the same derived authority,
differs in its `intent_hash`, `approver`, and `mission_id` while
sharing the `authority_hash`. It is therefore not globally unique to a
Mission and MUST NOT be used as a Mission identifier or as a replay or
idempotency key for a Mission. The canonical `mission_id` identifies
the Mission; `authority_hash` identifies the authority the Mission
approved. A consumer that needs to bind to or correlate a specific
Mission uses `mission_id`, and `intent_hash` and `approver` distinguish
Missions that share an Authority Set.

# Privacy Considerations

## Mission Identifier Correlation

This document carries a single canonical `mission_id` on every
derived token and ID-JAG. Any party that observes credentials for the
same Mission, whether a Resource Server, a Resource AS, or an auditor
spanning audiences, can correlate that activity by `mission_id`, and
`mission.origin` further identifies the issuing AS. This profile does
not provide cross-audience unlinkability. Audience-pairwise (or
request-pairwise) Mission references, in which the origin projects a
distinct opaque identifier per audience and resolves them
server-side, are the fuller mechanism for that and are deferred to
future work. A deployment that carries the canonical `mission_id` on
the wire SHOULD document this correlation property.

# IANA Considerations

## OAuth Parameters Registration

This document registers the following in the "OAuth Parameters"
registry:

- Name: `mission_intent`
- Parameter Usage Location: authorization request
- Change Controller: IETF
- Reference: this document, {{mission-intent}}

PAR {{RFC9126}} carries authorization-request parameters without a
distinct usage location, so the pushed submission of `mission_intent`
needs no separate registration.

## Authorization Details Type `mission_resource_access` {#type-registration}

`mission_resource_access` is an `authorization_details` type per
{{RFC9396}} Section 2, defined by this document in
{{authorization-derivation}}. RFC 9396 does not establish an IANA
registry of authorization details types (type identifiers are
interpreted by the Authorization Server), so this document creates no
registry entry for it and requires no IANA action here. If a registry
of authorization details types is established in the future, this type
SHOULD be registered in it.

## JSON Web Token Claims Registration

This document registers the following in the "JSON Web Token Claims"
registry:

- Claim Name: `mission`
- Claim Description: Reference to the Mission a token was derived
  under, with the consent-commitment `authority_hash`. An open object;
  additional members may be present and are ignored if unknown.
- Change Controller: IETF
- Specification Document(s): this document, {{mission-claim}}

## OAuth Token Introspection Response Registration

This document registers the following in the "OAuth Token
Introspection Response" registry ({{RFC7662}}):

- Name: `mission`
- Description: The Mission a token was derived under. Same object shape
  as the `mission` JWT claim ({{mission-claim}}); a response from the
  Mission origin additionally carries a `state` member giving the
  current lifecycle state ({{introspection}}).
- Change Controller: IETF
- Reference: this document, {{introspection}}

## OAuth Authorization Server Metadata Registration

This document registers the following in the "OAuth Authorization
Server Metadata" registry ({{RFC8414}}):

- Metadata Name: `mission_bound_authorization_supported`
- Metadata Description: Boolean indicating that the Authorization
  Server supports the Mission Issuer core surfaces of this document.
- Change Controller: IETF
- Reference: this document, {{discovery}}

## Mission Common Constraints Registry {#iana-common-constraints}

IANA is requested to create the "Mission Common Constraints" registry.
The registration policy is Specification Required {{RFC8126}}. Each
entry has:

- Name: the `constraints` member name, matching `^[A-Za-z0-9_.:-]+$`.
- Value syntax: the JSON {{RFC8259}} value type and any rules.
- Subset rule: the narrowing semantics ({{common-constraints}}).
- Intersection rule: how two values combine.
- Change Controller.
- Reference.

The registry is seeded with the constraints defined in
{{common-constraints}}; for each, Change Controller IETF and Reference
this document:

- `max_amount_usd`
- `issued_after`
- `issued_before`

--- back

# End-to-End Example (Non-Normative)

This appendix walks one Mission from an agent, through a cross-domain
hop, and into an internal microservice call chain. It is illustrative
and adds no normative requirements. The OAuth pieces use the rules in
this document; the identity setup is by reference to
{{I-D.draft-klrc-aiagent-auth}}; and the final intra-domain hop shows
one deployment-local way to carry Mission context in a Transaction
Token {{I-D.draft-ietf-oauth-transaction-tokens}}. Identifiers and
hash values are illustrative and are not computed from the displayed
JSON.

The chain crosses boundaries in two distinct ways, and seeing why is
the point of the example:

- The **Identity Assertion Authorization Grant (ID-JAG)** crosses
  *between* trust domains: from the home domain (`as.example.com`)
  to the partner domain (`ras.partner.example.com`).
- **Transaction Tokens** propagate *within* the partner trust domain:
  from the partner's Resource Server through its internal services.

The Mission is the durable anchor across both: `mission.id`,
`mission.origin`, and `authority_hash` ride unchanged through every
hop. OAuth authority is audience-scoped by the Mission Issuer and
Resource AS; deployment-local transaction context then narrows the
operation for internal services. In this baseline walkthrough no hop
calls back to `mission.origin` for state; each enforces from the
credential it holds. (The optional Status and Signals layers add
origin-fed state where a deployment wants it, as noted below.)

This walkthrough is the baseline issuance path: stateless enforcement
bounded only by token lifetime. The OPTIONAL companion profiles layer on
it, and the stages note where: Stage 4 gains a runtime point-of-use
check, and Stage 3 gains prompt cross-domain revocation from Status or
Signals.

Scenario: agent `s6BhdRkqt3`, acting for `alice`
(`user_3p2q8mN1a0kV7tR`), reconciles Q3 invoices in a partner ERP
under Mission `msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-`.

## Stage 0: Agent Identity (by Reference)

The agent is an OAuth client with a workload identity (for example a
WIMSE or SPIFFE identity), and `alice` has delegated to it through an
ordinary authorization-code flow, per
{{I-D.draft-klrc-aiagent-auth}}: `client_id` is the agent and the
token `sub` is `alice`. This document adds the Mission layer on top of
that identity; Stage 0 is otherwise unchanged from that specification.

## Stage 1: Mission Creation at the Home AS

The agent submits this Mission Intent through PAR ({{mission-intent}}):

~~~ json
{
  "goal": "Reconcile Q3 invoices in the partner ERP.",
  "resources": ["https://erp.partner.example.com"],
  "constraints": [
    "Read only invoices issued in 2026-Q3.",
    "Post journal entries under $500."
  ],
  "success_criteria": [
    "All Q3 invoices reconciled.",
    "Each posted adjustment references a source invoice."
  ],
  "purpose": "urn:example:purpose:reconcile",
  "mission_expiry": "2026-12-31T23:59:59Z",
  "context": {
    "acr": "urn:example:acr:mfa",
    "max_derivations": 200,
    "max_budget": { "amount": "5000.00", "currency": "USD" },
    "max_calls": [
      { "call_class": "journal-entries.write", "count": 50 }
    ],
    "max_duration": "PT8H"
  }
}
~~~

The home AS (`as.example.com`) validates it, derives this Authority
Set, and renders it for `alice`'s consent:

~~~ json
[
  { "type": "mission_resource_access",
    "resource": "https://erp.partner.example.com",
    "actions": ["invoices.read"],
    "delegation": {
      "max_depth": 1,
      "allowed_delegates": [{ "sub_profile": "ai_agent" }]
    } },
  { "type": "mission_resource_access",
    "resource": "https://erp.partner.example.com",
    "actions": ["journal-entries.write"],
    "constraints": { "max_amount_usd": 500 } }
]
~~~

After approval, the home AS records Mission
`msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-` in the `active` state with
`authority_hash`
`sha-256:l3KvZ4mP5x0wQrR6tY2nD9bM7sX1cF8gH2vJ4kE5pNQ` and
`intent_hash`
`sha-256:wQ7p4LHnX9Md0LqJ6sZJ8b8mZ3rN2xT5pV4lE6sQqYY`. The ERP is in
the partner trust domain, so the agent's next step is a cross-domain
projection rather than a home-domain access token.

## Stage 2: Cross-Domain Projection via ID-JAG (Between Domains)

The agent needs the partner ERP, behind the Resource AS
`ras.partner.example.com`. It presents its Mission refresh token as
the `subject_token` of a token exchange requesting an ID-JAG
({{cross-domain}}); the home AS resolves the Mission from that grant,
gates on Mission `active`, and mints a Mission-bound ID-JAG audienced
to that Resource AS, carrying the `mission` claim and the
audience-scoped authority for the ERP:

~~~ json
{
  "iss": "https://as.example.com",
  "aud": "https://ras.partner.example.com",
  "sub": "user_3p2q8mN1a0kV7tR",
  "client_id": "s6BhdRkqt3",
  "iat": 1797840000,
  "exp": 1797840300,
  "cnf": { "jkt": "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I" },
  "authorization_details": [
    { "type": "mission_resource_access",
      "resource": "https://erp.partner.example.com",
      "actions": ["invoices.read"],
      "delegation": {
        "max_depth": 1,
        "allowed_delegates": [{ "sub_profile": "ai_agent" }]
      } },
    { "type": "mission_resource_access",
      "resource": "https://erp.partner.example.com",
      "actions": ["journal-entries.write"],
      "constraints": { "max_amount_usd": 500 } }
  ],
  "mission": {
    "id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
    "origin": "https://as.example.com",
    "authority_hash":
      "sha-256:l3KvZ4mP5x0wQrR6tY2nD9bM7sX1cF8gH2vJ4kE5pNQ"
  }
}
~~~

The ID-JAG is short-lived (300 s) and sender-constrained to the
agent. Its `exp` does not exceed `mission_expiry`
({{mission-bound-tokens}}).

## Stage 3: The Resource AS Issues a Local Access Token

`ras.partner.example.com` validates the ID-JAG ({{cross-domain}}): it
establishes issuer trust in `as.example.com`, verifies the signature,
checks that `aud` is itself, checks the expiry, and verifies the
sender-constraint proof. It then issues its own access token for the
ERP, preserving the `mission` claim unchanged and capping `exp` at the
ID-JAG's `exp`:

~~~ json
{
  "iss": "https://ras.partner.example.com",
  "aud": "https://erp.partner.example.com",
  "sub": "partner-user_7Kp4QnZ2vR9s",
  "client_id": "s6BhdRkqt3",
  "iat": 1797840030,
  "exp": 1797840290,
  "jti": "at_7Kp4QnZ2vR9sT1mX8b3N",
  "cnf": { "jkt": "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I" },
  "authorization_details": [
    { "type": "mission_resource_access",
      "resource": "https://erp.partner.example.com",
      "actions": ["invoices.read"],
      "delegation": {
        "max_depth": 1,
        "allowed_delegates": [{ "sub_profile": "ai_agent" }]
      } },
    { "type": "mission_resource_access",
      "resource": "https://erp.partner.example.com",
      "actions": ["journal-entries.write"],
      "constraints": { "max_amount_usd": 500 } }
  ],
  "mission": {
    "id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
    "origin": "https://as.example.com",
    "authority_hash":
      "sha-256:l3KvZ4mP5x0wQrR6tY2nD9bM7sX1cF8gH2vJ4kE5pNQ"
  }
}
~~~

The issuing `iss` is now the Resource AS, but `mission.origin` remains
the home AS. The token's `exp` (1797840290) is below the ID-JAG's
(1797840300) and far below `mission_expiry`. The Resource AS-local
`sub` is illustrative; its value is determined by the
subject-resolution rules of the ID-JAG and identity chaining profiles,
not by this document.

Revoking the Mission now stops new ID-JAGs, but the local token the
Resource AS minted stays usable until its `exp` (260 seconds), bounded
by the 300-second ID-JAG cap ({{cross-domain-revocation}}). Tighter
cross-domain revocation is opt-in, and the two companions do different
things: a Mission Status freshness lease shortens how long the partner
relies on stale state by forcing a pull or per-request re-check, while a
Mission Lifecycle Signal notifies the partner on a Mission transition so
it can react without polling.

The Resource AS holds only this audience's subset and cannot recompute
`authority_hash`. To show its local token did not widen beyond the
ID-JAG, it SHOULD record, per minted token, both sides of the
derivation: the consumed ID-JAG's `jti` and conveyed
`authorization_details`, and the local token's own identifier or digest
(`jti`), `iss`, `aud`, `iat`, `exp`, and issued `authorization_details`.
An auditor can then identify the exact local token, tie it to the grant
it was minted from, and check its authority is a subset of that grant.

## Stage 4: The Resource Server Enforces

The agent calls the ERP Resource Server (`erp.partner.example.com`)
with that token. The Resource Server validates the JWT and the `cnf`
binding and enforces the `authorization_details` whose `resource` it
serves, permitting `invoices.read` and `journal-entries.write` up to
`max_amount_usd: 500` ({{mission-bound-tokens}}). It treats the
`mission` claim as an audit anchor; holding only this audience's
subset of the Authority Set, it does not recompute `authority_hash`.

This is stateless enforcement from the token alone.
`journal-entries.write` is a consequential write, so where the partner
deploys the runtime profile
({{I-D.draft-mcguinness-oauth-mission-runtime}}) it also obtains a
point-of-use PDP permit against current Mission state before executing.
The baseline bounds the write only by token lifetime and
`max_amount_usd`.

## Stage 5: Internal Call Context via Transaction Tokens

To serve the request, the ERP Resource Server calls internal services
inside the partner trust domain. Here it calls a ledger service for one
invoice. The Resource Server is the entry edge of that domain: after
it has validated the Mission-bound access token, it obtains a
short-lived Transaction Token for the internal call.

The following shows one illustrative way the Mission context could
ride in that Transaction Token. This is not a Mission-derived OAuth
access token, and this document does not define the Transaction Token
claim names or issuance rules. The important point is that the local
context can keep the Mission anchor while narrowing the internal
operation:

~~~ json
{
  "iss": "https://txn.partner.example.com",
  "aud": "https://ledger.partner.example.com",
  "sub": "partner-user_7Kp4QnZ2vR9s",
  "tid": "txn_5kQ9pX2vN7sR1tY8mZ3",
  "iat": 1797840060,
  "exp": 1797840120,
  "txn_authorization": {
    "source_resource": "https://erp.partner.example.com",
    "source_actions": ["invoices.read"],
    "internal_operation": "ledger.lookup_invoice",
    "constraints": { "invoice_id": "inv_2026Q3_1042" }
  },
  "mission": {
    "id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
    "origin": "https://as.example.com",
    "authority_hash":
      "sha-256:l3KvZ4mP5x0wQrR6tY2nD9bM7sX1cF8gH2vJ4kE5pNQ"
  }
}
~~~

The Transaction Token is intra-domain and the shortest-lived
credential in the chain (60 s). The holder has changed: the Resource
Server's workload, not the agent, possesses it. The local context has
narrowed again, to one ledger lookup for one invoice, while the
`mission` anchor is unchanged.

## Stage 6: The Internal Service Enforces

The ledger service receives the Transaction Token, validates it under
partner-domain policy, reads the Mission context and local transaction
authorization, and enforces them for the internal operation. Like
every consumer downstream of the home AS, it treats `authority_hash`
as an audit and correlation anchor it cannot recompute, and it makes
no call to `mission.origin`.

## What Rode Through, and What Narrowed

| Hop (mechanism) | Mission anchor | Authority or context | Expiry |
|---|---|---|---|
| ID-JAG (between domains) | unchanged | ERP: read + write | 1797840300 |
| Resource AS token | unchanged | ERP: read + write | 1797840290 |
| Txn Token (within domain) | unchanged | one ledger lookup | 1797840120 |

The Mission anchor (`id`, `origin`, `authority_hash`) is constant end
to end. OAuth authority is preserved or narrowed at the cross-domain
boundary, and local transaction context narrows the internal operation
inside the partner domain. The lifetime shrinks at every hop and never
exceeds `mission_expiry`. The ID-JAG carried identity *between* trust
domains; the Transaction Token carried context *within* one. The
Mission bound both.

# Acknowledgments
{:numbered="false"}

This work builds on the OAuth 2.0 Rich Authorization Requests, Pushed
Authorization Requests, and JWT access token specifications, and is
intended to complement agent-identity work including
{{I-D.draft-klrc-aiagent-auth}}.
