---
title: "Mission Child Delegation for OAuth 2.0"
abbrev: "OAuth Mission Child Delegation"
category: std

docname: draft-mcguinness-oauth-mission-child-delegation-latest
submissiontype: IETF
workgroup: Web Authorization Protocol
number:
date:
consensus: true
v: 3
keyword:
 - oauth
 - mission
 - agent
 - delegation
 - sub-agent
venue:
  github: "mcguinness/mission-bound-authorization"
  latest: "https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-child-delegation.html"

author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com

normative:
  RFC3339:
  RFC6755:
  RFC6838:
  RFC7523:
  RFC8259:
  RFC8414:
  RFC8693:
  RFC9396:
  RFC8705:
  RFC8785:
  RFC9126:
  RFC9449:
  I-D.draft-mcguinness-oauth-mission:
    title: "Mission-Bound Authorization for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission.html
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
  I-D.draft-mcguinness-oauth-mission-discharge:
    title: "Mission Completion and Entry Discharge for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-discharge.html
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

informative:
  RFC8126:
  I-D.draft-gerber-oauth-deferred-token-response:
  I-D.draft-mcguinness-oauth-client-instance-assertion:
  I-D.draft-mcguinness-oauth-ai-agent-instance:
  I-D.draft-mcguinness-mission-authority-server:
    title: "Mission Authority Server"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-authority-server.html
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
  I-D.draft-mcguinness-oauth-mission-containment:
    title: "Mission Containment for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-containment.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-oauth-mission-continuation:
    title: "Mission Continuation: Authorization Continuity for Mission-Bound Authorization"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-continuation.html
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
  I-D.draft-mcguinness-oauth-mission-attenuation:
    title: "Mission Offline Attenuation for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-attenuation.html
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
  I-D.draft-mcguinness-mission-harness:
    title: "Mission-Aware Agent Harnesses"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-harness.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-mission-architecture:
    title: "An Architecture for Mission-Bound Authorization"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-architecture.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-mission-metering:
    title: "Mission Consumption Metering"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-metering.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026

--- abstract

Mission-Bound Authorization for OAuth 2.0 defines delegated tokens and
the rule that authority narrows down a delegation chain. Agent
harnesses, however, can spawn sub-agents whose work outlives a call
frame or crosses a different execution boundary. This document defines
an optional Mission Child Delegation profile. A parent Mission can
authorize a Child Mission for a sub-agent, with explicit parent
lineage, strict-subset authority, expiry no later than the parent,
separate child actor identity, fan-out controls, and cascade
termination when the parent Mission ends, with suspend-and-resume
propagation while the parent is suspended. Child creation is permitted
only where a parent entry's delegation policy carries a `children`
object, and child credentials never transit the parent. A Child
Mission is never created by session ancestry alone.

--- middle

# Introduction

Mission-Bound Authorization for OAuth 2.0
{{I-D.draft-mcguinness-oauth-mission}} (the "issuance profile") supports
delegated Mission-bound tokens. It requires authority to narrow down
the chain and records actor context. That is sufficient for many
service-to-service and token-exchange cases.

Agent harnesses introduce
a related but distinct case: a parent agent starts a sub-agent or child
worker with a durable task of its own. The child may have its own
session, queue, tool handles, and runtime identity.

This document defines Child Missions for that case. A Child Mission is
a Mission whose authority is a strict subset of a Parent Mission and
whose lifecycle depends on the parent. It has its own Mission
identifier and actor identity, but it cannot outlive, out-broaden, or
escape the parent. The child is created through an explicit
authorization step, not by inheriting a parent harness session.

# Status: An Optional Extension {#optional-status}

This document is optional. It is a layered extension to the issuance
profile, not a change to it. A deployment that implements
{{I-D.draft-mcguinness-oauth-mission}} and never creates a Child
Mission is fully conformant to that profile and is unaffected by this
document: it accepts no child-creation token exchange, records
no `parent` member, and applies no cascade revocation. The issuance
profile's delegated-token mechanism is complete without Child Missions;
the child machinery defined here is relevant only when a deployment
creates Missions for sub-agents.

A Mission Issuer claims conformance to this document only when it
creates Child Missions ({{conformance}}); otherwise it remains a plain
issuance-profile Mission Issuer. Nothing here places a new requirement
back on the issuance profile.

<!-- family-status: BEGIN (generated from family-manifest.json; exact-matched by scripts/check-family-manifest.mjs) -->
Role: companion. Spec maturity: experimental. Maintenance: active.
Implementation: 14 conformance rows in conformance-manifest.json (14 todo).
Adopt when: A sub-agent needs its own Mission outliving a call frame, with cascade termination.
Requires: Mission-Bound Authorization for OAuth 2.0.
Also requires, conditionally: Mission Expansion for OAuth 2.0 and Mission Status and Lifecycle for OAuth 2.0 (when cascade revocation reacts to parent lifecycle states); Mission Completion and Entry Discharge for OAuth 2.0 (when the deployment also runs the Entry Discharge companion).
<!-- family-status: END -->

# Relationship to the Issuance Profile {#issuance-relationship}

This document depends normatively on the issuance profile and is not
implementable alone. It reuses, without restating, that profile's
Mission Intent, submission via PAR, authority derivation, approval
event with its integrity anchors, Mission record, the `mission` claim,
the subset rule, and the lifecycle and issuance gating. It uses
the terms Agent (Client), Subject, Approver, Mission Issuer, Mission
Intent, Authority Set, Mission, and derived token as defined there.

Cascade revocation ({{cascade}}) additionally depends on the Mission
Status and Lifecycle profile
({{I-D.draft-mcguinness-oauth-mission-status}}) and the Mission
Expansion profile ({{I-D.draft-mcguinness-oauth-mission-expansion}})
where a deployment runs them, because those profiles define the
`suspended`, `completed`, and `superseded` parent states the cascade
rules react to. A deployment that runs neither still implements this
profile: under the issuance profile's forward-compatibility rule, the
cascade treats any non-active parent state as a terminal trigger.

Containment propagation ({{child-state}}) additionally depends on the
Mission Containment profile
({{I-D.draft-mcguinness-oauth-mission-containment}}) where a deployment
runs it, because that profile defines the containment overlay and the
contained-capability concept the propagation rule reacts to. A
deployment that does not run Containment holds no overlay to propagate
and is unaffected by that rule.

A Child Mission is an ordinary Mission under the issuance profile with
two additions: it is created under a parent grant rather than a
first-party approval, and its record and tokens carry the `parent`
member ({{parent-member}}). The child's own `authority_hash` remains
the authority commitment on its record, on the same baseline terms as
any Mission's ({{I-D.draft-mcguinness-oauth-mission}}); the `parent`
member is lineage and audit data only.

Where this document refers to "the issuance profile" without a section,
it means {{I-D.draft-mcguinness-oauth-mission}} as a whole.

## Relationship to Delegated Tokens {#child-vs-token}

A Child Mission is a new Mission with its own `mission_id`. It is not
an attenuation child: the Mission Offline Attenuation profile
({{I-D.draft-mcguinness-oauth-mission-attenuation}}) defines a child
as a narrower token minted under one Mission, not a new Mission.

Neither construct is the first question when the need is only more
concurrent capacity. The same principal running more attested
instances of the same pinned Agent Deployment (a named architectural
pattern the issuance profile points to a forward-referenced Agent
Deployment Binding profile for, not a wire member it currently
defines itself) under the same Mission is
multiplication, not delegation: each instance derives under the
Mission directly, with no `act` hop and no Child Mission. The
architecture names this swarm execution and states the full decision
ladder ({{I-D.draft-mcguinness-mission-architecture}}); the choice
below begins where a different principal or a separate lifecycle
enters.

A delegated token is appropriate when the delegate performs work
within the lifetime and operational control of the delegating flow. A
Child Mission is appropriate when the child actor needs a durable
Mission handle of its own: for example, a sub-agent with a queue,
background job, independent harness session, or separate audit
lifecycle. A Child Mission is not a way to widen authority; it is a
way to create a narrower, separately accountable authority record for
a child actor.

The dividing line is survivability: work that can outlive the
delegating flow, because it is queued, scheduled, or retried after
the delegator exits, or that needs its own revocation and audit
lifecycle, requires a Child Mission; work that cannot MAY run on a
delegated token. A harness applies the test at spawn, not by agent
design: the same sub-agent takes a delegated token when invoked
inline and a Child Mission when parked on a queue.

## Relationship to In-Mission Delegation {#child-vs-act}

This profile's child delegation is distinct from the in-Mission
delegation the issuance profile already defines. In-Mission delegation
extends a single Mission's `act` chain to additional actors, bounded by
the per-entry `delegation` policy (`allowed_delegates`, `max_depth`) of
{{I-D.draft-mcguinness-oauth-mission}}; no new Mission is created and
authority is exercised under the original Mission. Child delegation, by
contrast, creates a separate Child Mission with its own `mission_id`,
actor, lifecycle, and `act` chain.

Where this profile reads the parent entry's `delegation` policy, it
does so to decide whether child creation is permitted and which
`child_actor` is eligible: the presence of a `children` object in the
parent entry's `delegation` member is what permits child creation for
that entry ({{fanout}}), and that object's `allowed_child_actors`
constrains the `child_actor` the parent may name.

The issuance profile's `act` `max_depth` bounds act-chain nesting
within a Mission and is not a child-generation counter; a Child
Mission's own `act` chain restarts at depth 0. Child-generation depth
and breadth are governed instead by the fan-out controls of
{{fanout}}.

# Scope

This document defines:

- Child Mission creation ({{child-creation}});
- the `parent` lineage member ({{parent-member}});
- strict-subset and expiry rules ({{attenuation}});
- fan-out controls ({{fanout}});
- cascade revocation ({{cascade}});
- child evidence and audit requirements ({{child-evidence}}); and
- conformance for a Child-Mission-capable Mission Issuer
  ({{conformance}}).

This document does not replace ordinary delegated tokens under
{{I-D.draft-mcguinness-oauth-mission}}. A deployment can use delegated
tokens for short-lived delegation and Child Missions for durable
sub-agent work that needs its own lifecycle handle.

# Conventions and Terminology {#conventions}

{::boilerplate bcp14-tagged}

This document uses the terms Mission, Mission Intent, Authority Set,
Mission Issuer, Mission-bound token, and delegation from
{{I-D.draft-mcguinness-oauth-mission}}, and Effective Authority Set
from {{I-D.draft-mcguinness-oauth-mission-status}}.

Parent Mission:
: The active Mission from which a Child Mission derives its upper bound
  of authority.

Child Mission:
: A Mission created for a child actor or sub-agent, with authority that
  is a strict subset of its Parent Mission and lifecycle that cascades
  from the parent.

Child actor:
: The agent, workload, sub-agent, or component that receives authority
  under the Child Mission. The child actor is the OAuth client of the
  Child Mission ({{child-creation}}).

Delegation event:
: The Mission Issuer event that creates the Child Mission and records
  the attenuation checks from parent to child.

The design comparison between Child Missions, delegated tokens, and
in-Mission delegation is in {{child-vs-token}} and {{child-vs-act}}.

# Child Mission Creation {#child-creation}

To create a Child Mission, the requester MUST prove possession of the
Parent Mission's authority through a sender-constrained proof, and a
reusable bearer refresh credential MUST NOT be the carrier of that
proof. This is the abstract requirement child creation rests on, stated
once and independent of any wire binding.

On the OAuth wire this document binds that requirement to an {{RFC8693}}
token exchange at the token endpoint, under this profile's
child-creation grant type ({{grant-type}}): the parent's own
sender-constrained Mission-bound access token is the `subject_token`,
and possession is proven against that token's confirmation key
({{request-processing}}). The Mission Authority Server profile
({{I-D.draft-mcguinness-mission-authority-server}}) binds the same
abstract requirement to an authenticated-client submission on its
token-less surface; the two are peer bindings of one requirement.

The child-creation token exchange carries:

`grant_type`:
: REQUIRED. `urn:ietf:params:oauth:grant-type:token-exchange`, the
  {{RFC8693}} token-exchange grant type ({{grant-type}}).

`requested_token_type`:
: REQUIRED. `urn:ietf:params:oauth:token-type:jwt`. This value selects
  child creation: the Mission Issuer returns the child-bound JWT
  authorization grant ({{child-client-identity}}). Expansion, the peer
  operation on the same grant, is selected by the access-token type
  ({{I-D.draft-mcguinness-oauth-mission-expansion}}).

`subject_token`:
: REQUIRED. The Parent Mission's sender-constrained Mission-bound access
  token. The Mission Issuer resolves the Parent Mission from this token
  ({{request-processing}}); this token, not any identifier, selects the
  parent authoritatively.

`subject_token_type`:
: REQUIRED. `urn:ietf:params:oauth:token-type:access_token`. The Mission
  Issuer MUST reject any other value with `invalid_request`. A refresh
  token MUST NOT be accepted as the `subject_token` for child creation:
  the possession proof is a sender-constrained access token, never a
  reusable bearer refresh credential.

`actor_token`:
: OPTIONAL. A token identifying the acting parent agent, per
  {{RFC8693}}. Where it is absent, the request's client authentication
  identifies the acting agent. This document carries the acting-agent
  identity; it does not restructure any act chain. A Child Mission is a
  new work-continuity unit whose own `act` chain restarts at the child
  actor ({{child-vs-act}}).

`actor_token_type`:
: REQUIRED when `actor_token` is present, per {{RFC8693}}.

`mission_intent`:
: REQUIRED. The Mission Intent Submission envelope
  ({{I-D.draft-mcguinness-oauth-mission}}) whose `intent` is the
  proposed Child Mission Intent; its OPTIONAL `evidence` array
  carries Intent Submission Evidence under that profile's dispatch,
  refusal, and never-authority rules.

`authorization_details`:
: OPTIONAL. The child's authority proposal: the standard {{RFC9396}}
  parameter carried on the same token request, itself ordinary
  {{RFC9396}} token-request usage. This parameter is this exchange's
  proposal carriage, replacing the issuance profile's PAR-only
  carriage rule; that profile's validation, derivation, recording,
  and hashing semantics apply unchanged
  ({{I-D.draft-mcguinness-oauth-mission}}). It is a proposal, never
  authority: the child Authority Set is derived and bounded by policy
  and by the strict-subset rule regardless of what was proposed. A
  Child Mission created from an exchange carrying one records
  `proposed_authority` and `proposal_hash`.

`child_actor`:
: REQUIRED. An object identifying the child actor that will hold or
  execute under the Child Mission, using the issuance profile's actor
  vocabulary ({{I-D.draft-mcguinness-oauth-mission}}):

  `sub`:
  : REQUIRED. The child actor's identifier.

  `iss`:
  : OPTIONAL. The issuer of `sub` when it is not the Mission Issuer's
    own namespace.

  `sub_profile`:
  : RECOMMENDED. The actor-type classification (for example,
    `ai_agent`), matched against the parent entry's
    `allowed_child_actors` ({{fanout}}).

  A `child_actor` MAY be identified at instance granularity where the
  deployment authenticates client instances
  ({{I-D.draft-mcguinness-oauth-client-instance-assertion}}; for AI
  agents, {{I-D.draft-mcguinness-oauth-ai-agent-instance}}): `sub`
  carries the instance identifier and `sub_profile` the
  space-separated value list (for example,
  `ai_agent client_instance`). The child client-identity rule
  ({{child-client-identity}}), under which child credentials never
  transit the parent, composes naturally with instance-specific keys.

`parent`:
: OPTIONAL. A string. The `mission_id` of the Parent Mission, a
  non-authoritative cross-check and audit value only. The Mission Issuer
  resolves and selects the parent from `subject_token`
  ({{request-processing}}); when `parent` is present it MUST verify it
  names that same resolved Mission and refuse a mismatch with
  `invalid_grant`. `parent` does not by itself authorize child creation.

`creation_request_id`:
: REQUIRED. The creation idempotency identifier the expansion profile
  defines for the family's Mission-creating token exchanges
  ({{I-D.draft-mcguinness-oauth-mission-expansion}}): an ASCII string
  of at most 255 octets identifying this one child-creation operation
  across every completion mode ({{creation-idempotency}}). The
  Mission Issuer MUST refuse an exchange missing it with
  `invalid_request`.

The parent redeems this token exchange at the token endpoint under the
child-creation grant type ({{grant-type}}). The presence of
`child_actor` marks the exchange as a child creation; an exchange
carrying both `child_actor` and the expansion profile's `predecessor`
cross-check ({{I-D.draft-mcguinness-oauth-mission-expansion}}) MUST be
refused with `invalid_request`, since the operations do not combine.

The Mission Issuer MUST resolve the parent from `subject_token`, verify
that the presenter controls the token's own confirmation key ({{RFC9449}}
DPoP proof `jkt`, or {{RFC8705}} mTLS `x5t#S256`) and, for a DPoP proof,
that the proof `jti` is single-use per {{RFC9449}}, verify that any
`parent` cross-check names the resolved Mission, verify that the parent
is `active`, and verify that the applicable parent Authority Set entry's
`delegation` member carries a `children` object ({{fanout}}) that
permits child creation for the requested authority
({{request-processing}}). Possession is proven against the token's own
confirmation, a sender-constrained proof; it is not read from any
Mission-record field. A `subject_token` that is not sender-constrained
cannot carry this proof, so the Mission Issuer MUST refuse it with
`invalid_request`.

The possession proof is presented only on the token endpoint's
authenticated back channel and MUST NOT appear on any front channel.

The Mission Issuer MUST record each child-creation presentation and
count it toward the deployment's anomaly detection, and the
per-parent fan-out ({{fanout}}) and rate limits apply unconditionally.
Because the `subject_token` is a short-lived, sender-constrained access
token rather than a reusable refresh credential, presenting it for
child creation carries no refresh rotation or replay-detection
interaction: it is consumed only to resolve and bind the parent.

## Child Client Identity {#child-client-identity}

The child actor is the OAuth client of the Child Mission: its
identifier is the `client_id` of the Child Mission record. The child
actor authenticates itself at the token endpoint and redeems its own
grant for the Child Mission's tokens. Child credentials MUST NOT transit
the parent, and the parent MUST NOT hold child tokens.

The child's initial grant MUST be an audience-bound JWT authorization
grant that the child actor redeems as itself under the {{RFC7523}}
JWT-bearer grant, of the shape the Mission Issuance Grant profile
defines ({{I-D.draft-mcguinness-oauth-mission-issuance-grant}}): on
creating the Child Mission the Mission Issuer mints an assertion that
names the child actor as the authorized redeemer and the Mission
Issuer's token endpoint as the audience, and the child actor presents it
there authenticating with its own client credential.

An authorization code MUST NOT be used to convey the child's grant: an
authorization code is redeemable by the client that obtained it, which
is the parent, not the child. The child-bound assertion is redeemable
only by the child actor it names, so conveying it through the parent
gives the parent no ability to redeem it. How the assertion reaches the
child actor remains deployment-defined, subject to the rules above.

Where creation is adjudicated by policy as a subset derivation, the
child-creation token exchange completes synchronously ({{completion}}),
the Mission Issuer mints the child-bound JWT authorization grant with no
user interaction, and the child actor redeems it as itself under the
{{RFC7523}} JWT-bearer grant at the token endpoint.

## Cross-Issuer Scope {#cross-issuer}

In this profile the Child Mission's issuer MUST equal `parent.issuer`
({{parent-member}}): a Child Mission is created and hosted by the same
Mission Issuer as its parent. Cross-domain child delegation, where the
child is hosted by a different Mission Issuer than the parent, is
deferred work.

## Creation and Revocation Race {#creation-race}

Parent state MUST be re-verified atomically with the Child Mission's
creation commit, or child creation MUST be serialized with parent
lifecycle transitions such that a terminal parent transition
({{cascade}}) either denies every in-flight creation or cascades over
it. A Child Mission MUST NOT commit against a parent that became
non-active after the parent-state check.

Where creation is deferred or interactive ({{completion}}), the same
rule governs the deferred window between the request and the creation
commit:

- The parent's Mission state MUST be re-verified at the creation commit,
  not only at request time. A parent terminated or contained during the
  window MUST fail the commit, preserving the cascade the parent's
  terminal state effects ({{cascade}}): a deferred approval MUST NOT
  become a bypass of it.
- Expiry of the `subject_token` during the window MUST NOT gate the
  commit. The parent binding and the possession proof are evaluated and
  recorded at request time ({{request-processing}}); the short-lived
  `subject_token` expiring while approval is pending does not invalidate
  the pending exchange. The re-verification above is of the parent's
  Mission state, not of the expired token.

## Completion {#completion}

The child-creation token exchange completes in one of three modes,
the family's shared completion pattern for Mission-creating
exchanges. Child creation keeps the synchronous mode that Mission
Expansion does not define: an expansion always widens and always
takes fresh consent, so it completes only deferred or interactively
({{I-D.draft-mcguinness-oauth-mission-expansion}}), while a Child
Mission is always a creation and a strict subset of its parent, so a
policy-permitted synchronous completion is unambiguous
({{strict-subset}}). The deferred token
response is a completion mode, not a replacement:

Synchronous:
: When child creation is a subset derivation of already-approved
  authority that a deployment permits by policy, the Mission Issuer
  completes the exchange in its response, returning the child grant
  reference ({{grant-type}}). This is the common case: a Child Mission
  is a strict subset of its parent ({{strict-subset}}).

Deferred:
: When a deployment requires a fresh approval for child creation and
  approval is asynchronous, the Mission Issuer returns the deferred
  token response of the family's Mission Deferred Approval substrate
  ({{I-D.draft-gerber-oauth-deferred-token-response}}, profiled for
  Missions by {{I-D.draft-mcguinness-oauth-mission-approval}}):
  `authorization_pending` with a polling `interval`. The Approver acts
  asynchronously; the requester polls; the poll resolves to the child
  grant reference on approval, or to `access_denied` or `expired_token`.
  This document references that substrate and does not redefine it.

Interactive:
: When a deployment requires an interactive fresh approval, the Mission
  Issuer runs the deployment's existing front-channel approval event,
  the issuance profile's own approval ceremony via a Pushed
  Authorization Request {{RFC9126}}
  ({{I-D.draft-mcguinness-oauth-mission}}), after which the child grant
  reference is returned.

The child grant reference conveyed at completion is the child-bound JWT
authorization grant of {{child-client-identity}}, never a child token.

## Protocol Flow {#protocol-flow}

~~~
 Parent agent / harness   Mission Issuer (AS)      Child actor
        |                        |                      |
        | 1. token exchange ---->| resolve parent from  |
        |    subject_token =     | subject_token; verify|
        |    parent's Mission-   | possession (cnf);    |
        |    bound access token; | verify active;       |
        |    child_actor         | verify children      |
        |                        |                      |
        | 2. complete (sync,     | create child Mission |
        |    deferred, or        | record parent member |
        |<-- grant reference ----| interactive)         |
        |                        |                      |
        | 3. convey grant reference (deployment-defined) |
        | ---------------------------------------------->|
        |                        |                      |
        |                        | 4. token request     |
        |                        |    (child auth) <-----|
        |                        | derive child token    |
        |                        | ----- access token -->|
~~~

The completion in step 2 is deployment-specific ({{completion}}). A
deployment MAY require a fresh approval event for Child Mission
creation, completing via the deferred token response or the interactive
approval, or MAY allow policy to approve child creation synchronously
when the parent Mission's Authority Set explicitly permits it. Step 1
is the parent's child-creation token exchange at the token endpoint,
under the grant type of {{grant-type}}. In step 3 the parent conveys
only a grant reference, never a child token ({{child-client-identity}});
in step 4 the child actor authenticates itself and redeems its own
grant.

## Grant Type {#grant-type}

This profile binds child creation to the token endpoint through the
{{RFC8693}} token-exchange grant type, adding no new grant type and no
new endpoint. The parent presents the child-creation token exchange
({{child-creation}}) at the token endpoint under:

`grant_type`:
: REQUIRED. `urn:ietf:params:oauth:grant-type:token-exchange`.

`requested_token_type`:
: REQUIRED. `urn:ietf:params:oauth:token-type:jwt`, which selects child
  creation. Expansion is the peer operation on the same grant, selected
  by the access-token type
  ({{I-D.draft-mcguinness-oauth-mission-expansion}}).

The exchange follows {{RFC8693}}, carrying `subject_token`,
`subject_token_type`, `child_actor`, `mission_intent`,
`creation_request_id`, and the optional `parent` cross-check of
{{child-creation}}. The parent proves possession
of the Parent Mission by controlling the `subject_token`'s confirmation
key ({{request-processing}}); the Mission Issuer resolves and
authorizes the parent from that possession, not from client
registration alone. This is the single gated child-creation decision
this profile permits per exchange: where the possession proof is a DPoP
proof, its `jti` is single-use per {{RFC9449}}, so a captured exchange
cannot be replayed to derive a second Child Mission. A lost response
is the complementary fault: a retried exchange recovers the committed
child under the creation idempotency of {{creation-idempotency}},
never a second one.

On success the Mission Issuer responds with the {{RFC8693}} token
response shape:

`access_token`:
: REQUIRED. The child-bound JWT authorization grant of
  {{child-client-identity}}: the {{RFC7523}} assertion the child actor
  redeems next. The issued artifact travels in this member, per
  {{RFC8693}}.

`issued_token_type`:
: REQUIRED. `urn:ietf:params:oauth:token-type:jwt`.

`token_type`:
: REQUIRED. `N_A`, per {{RFC8693}} Section 2.2.1: bearer semantics do
  not apply to this artifact.

`mission_id`:
: REQUIRED. The Child Mission identifier.

`mission_expires_at`:
: REQUIRED. The Child Mission's effective `expires_at`, the issuance
  profile's common Mission-creating response member
  ({{I-D.draft-mcguinness-oauth-mission}}).

`parent`:
: REQUIRED. The `parent` member of {{parent-member}}.

A token response carries no `grant_type`; none appears here. The
`access_token` is not usable by its redeemer: only the child actor
named in the assertion can redeem it, under the {{RFC7523}} JWT-bearer
grant of {{child-client-identity}}. The parent receives it only to
convey to the child actor, never to use as its own access token,
consistent with the rule that child credentials never transit the
parent ({{child-client-identity}}).

## Request Processing {#request-processing}

The Mission Issuer MUST process a child-creation token exchange in this
order, refusing on the first failure:

1. Parse the exchange, require `subject_token` with
   `subject_token_type` =
   `urn:ietf:params:oauth:token-type:access_token`, rejecting a
   refresh token, and require `creation_request_id`
   ({{child-creation}}).
2. Resolve the Parent Mission from `subject_token`.
3. Verify possession: the presenter controls the `subject_token`'s own
   confirmation key ({{RFC9449}} DPoP proof `jkt`, or {{RFC8705}} mTLS
   `x5t#S256`), and, for a DPoP proof, the proof `jti` is single-use.
4. Verify the acting agent (`actor_token`, or the request's client
   authentication) is authorized to create a child under this parent,
   and verify that any `parent` cross-check names the resolved Mission.
5. Look up the `(client, creation_request_id)` reservation and, where
   one exists, recover the recorded operation instead of proceeding
   ({{creation-idempotency}}). Per the expansion profile's lookup
   order, the lookup follows client authentication and possession
   verification and precedes the parent-state gate of step 6.
6. Verify the Parent Mission is `active` and no ancestor Mission in its
   lineage chain is non-active.
7. Verify the applicable parent Authority Set entry's `delegation`
   carries a `children` object permitting child creation, and that
   `child_actor` satisfies its constraints ({{fanout}}).
8. Derive the child Authority Set, verify strict subset
   ({{strict-subset}}), and apply fan-out controls.
9. Determine subset derivation versus fresh approval and complete per
   {{completion}}: synchronous, deferred, or interactive.
10. At the creation commit, re-verify parent state ({{creation-race}}),
    create the Child Mission record with `parent` and the completed
    `(client, creation_request_id)` reservation atomically
    ({{creation-idempotency}}), and record Child Evidence.

On any failure the Mission Issuer MUST refuse with `invalid_request`,
`invalid_grant`, or `invalid_token` as appropriate, and MUST NOT create
a child. The child actor then authenticates at the token endpoint and
redeems its own grant for the Child Mission's tokens
({{child-client-identity}}).

## Creation Idempotency {#creation-idempotency}

The `creation_request_id` semantics are the expansion profile's,
defined once for the family's Mission-creating token exchanges and
not redefined here
({{I-D.draft-mcguinness-oauth-mission-expansion}}): the operation
fingerprint and its extension rule, the durable reservation and its
uniqueness constraint, recovery as delivery, the revalidation and
lookup-order rules, and tombstone retention against the published
retry horizon. This section states what is specific to child
creation.

In the fingerprint object, `op` is `child-creation`; `source` is the
Parent Mission's `mission_id` resolved from `subject_token`
({{request-processing}}); `child_actor` is the parsed `child_actor`
object; and `cross_check` is the supplied `parent` value, when
present. The remaining members are as the expansion profile defines
them. Two child creations differing only in `child_actor` are
different operations: presenting the same `creation_request_id` for
both is refused with `invalid_request`.

Recovery is delivery, never a second child. A revalidated repetition
of the same `(client, creation_request_id)`:

- returns the same deferral or interactive continuation while
  completion is pending, scoped to the authenticated client;
- returns the original child-bound JWT authorization grant while it
  remains valid;
- re-mints the child-bound grant for the same Child Mission when the
  original has expired (the assertion is deliberately short-lived,
  {{I-D.draft-mcguinness-oauth-mission-issuance-grant}}), provided
  the Child Mission remains `active` under the conditions of
  {{child-state}} and the requester re-establishes the recorded
  authorization context. Re-minting is a delivery event with
  ordinary issuance accounting; it MUST NOT create a second Child
  Mission, count a second time against `max_children`
  ({{fanout-accounting}}), or record a second Child Evidence object
  ({{child-evidence}}).

## Worked Example {#worked-example}

Under the Q3 reconciliation Mission
`msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-`, the approved agent
`s6BhdRkqt3`, acting for `alice`, spawns a read-only invoice
extraction sub-agent and presents a child-creation token exchange whose
`subject_token` is the parent's Mission-bound access token, proving
possession with a DPoP proof over the token's confirmation key
(illustrative; this Mission's Authority Set extends the single-domain
walkthrough's, its read entry's `delegation` carrying a `children`
object ({{fanout}}), so its anchors differ from that example's):

~~~ http
POST /token HTTP/1.1
Host: as.example.com
Content-Type: application/x-www-form-urlencoded
DPoP: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2Iiwi...

grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange&
requested_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Ajwt&
subject_token=<parent%20Mission-bound%20access%20token>&
subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3A
  access_token&
mission_intent=%7B%22intent%22%3A
  %7B...read-only%20Q3%20invoice%20extraction...%7D%7D&
parent=msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-&
child_actor=%7B%22sub%22%3A%22subagent-invoice-extractor%22%2C
  %22sub_profile%22%3A%22ai_agent%22%7D&
client_id=s6BhdRkqt3
~~~

The Mission Issuer resolves the parent from `subject_token`, verifies
the presenter controls the token's confirmation key, processes the
request per {{request-processing}}, and, as this child is a strict
subset of the parent, completes synchronously ({{completion}}) and
creates the Child Mission. The sub-agent then authenticates as
`subagent-invoice-extractor` at the token endpoint and redeems its own
grant ({{child-client-identity}}); no child credential transits the
parent. The decoded child access token:

~~~ json
{
  "iss": "https://as.example.com",
  "sub": "user_3p2q8mN1a0kV7tR",
  "aud": "https://erp.example.com",
  "client_id": "subagent-invoice-extractor",
  "iat": 1793607300,
  "exp": 1793607600,
  "jti": "at_5vB8nQ2xT7mK4rW1Zs9c",
  "authorization_details": [
    { "type": "mission_resource_access",
      "resource": "https://erp.example.com",
      "actions": ["invoices.read"],
      "constraints": {
        "resource_issued_after": "2026-07-01T00:00:00Z",
        "resource_issued_before": "2026-09-30T23:59:59Z"
      } }
  ],
  "cnf": { "jkt": "wZ5nT8qL2xV9rB4mC7sD1yF6jH3kP0aG5uE8oS2iN4w" },
  "mission": {
    "id": "msn_9KwP2rT6vX1nL4qY8sB3zC7mF5jD",
    "issuer": "https://as.example.com",
    "parent": {
      "id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
      "issuer": "https://as.example.com",
      "authority_hash":
        "sha-256:tY2nD9bM7sX1cF8gH2vJ4kE5pNQl3KvZ4mP5x0wQrR6",
      "depth": 1,
      "delegation_id": "dlg_7pQ4m",
      "cascade_mode": "immediate"
    }
  }
}
~~~

`mission.id` is the Child Mission, on the issuance profile's baseline
`{id, issuer}` claim ({{I-D.draft-mcguinness-oauth-mission}}); the
child's own `authority_hash`, which commits its Authority Set, is
recorded on its Mission record and is not carried on the claim by
default. The `parent` object is lineage, this profile's own member,
with `depth` 1 for a child of a root Mission. The `cnf` key is the
sub-agent's own ({{child-client-identity}}).

## Child Creation Denial Reasons {#denial-reasons}

This profile defines these symbolic denial reasons:

`parent_not_active`:
: The Parent Mission is not active.

`parent_mismatch`:
: The caller-supplied `parent` cross-check does not match the Mission
  resolved from `subject_token`.

`delegation_not_permitted`:
: The applicable parent Authority Set entry's `delegation` member
  carries no `children` object, so it permits no child creation
  ({{fanout}}).

`child_actor_not_allowed`:
: The child actor does not satisfy the parent entry's
  `allowed_child_actors` ({{fanout}}) or equivalent policy.

`not_strict_subset`:
: The proposed child authority is not a strict subset of parent
  authority ({{strict-subset}}).

`fanout_exceeded`:
: Creating the child would exceed a fan-out control.

`policy_denied`:
: Deployment policy denied child creation.

These symbolic strings appear in error bodies, evidence, and audit,
layered on the OAuth error codes the issuance profile uses:
`parent_not_active` and `parent_mismatch` accompany `invalid_grant`;
`delegation_not_permitted`, `child_actor_not_allowed`,
`not_strict_subset`, and `fanout_exceeded` accompany `invalid_request`;
and `policy_denied` accompanies `access_denied`. In an error response
body the symbolic reason rides, alongside the OAuth `error` member, in
the `mission_denial_reason` member, the shared adjudication-denial
carrier defined and registered by the expansion profile
({{I-D.draft-mcguinness-oauth-mission-expansion}}); this document
requests these seven reasons' registration in that profile's Mission
Denial Reasons registry ({{iana-registrations}}). On a deferred
completion ({{completion}}) a denial surfaces as the deferred
substrate's `access_denied` resolution. The possession proof is
presented only on the token endpoint's authenticated back channel and
MUST NOT appear on any front channel ({{child-creation}}).

For example, a child Mission Intent that drops the parent entry's
`resource_issued_before` constraint proposes a relaxation, not a
subset. The
Mission Issuer refuses it ({{strict-subset}}) with:

~~~ json
{
  "error": "invalid_request",
  "mission_denial_reason": "not_strict_subset"
}
~~~

# The Parent Mission Reference {#parent-member}

A Child Mission carries a `parent` member in its Mission record and in
the `mission` claim of tokens derived under the child:

`parent`:
: REQUIRED for a Child Mission. An object containing:

  `id`:
  : REQUIRED. The Parent Mission identifier.

  `issuer`:
  : REQUIRED. The Parent Mission Issuer. The Child Mission's own
    `issuer` MUST equal this value ({{cross-issuer}}).

  `authority_hash`:
  : REQUIRED. The Parent Mission authority commitment the child was
    derived under.

  `depth`:
  : REQUIRED. An integer. The child-generation depth of this Child
    Mission: 1 for a child of a root Mission, incremented by one per
    generation. It lets issuers and consumers observe and bound
    generation depth without walking Mission Status.

  `delegation_id`:
  : OPTIONAL. A Mission-Issuer-defined identifier for the child
    delegation event.

  `cascade_mode`:
  : REQUIRED. The cascade mode from {{cascade}}.

  `created_at`:
  : OPTIONAL. The creation time of the Child Mission.

The `parent` member is lineage and audit data. It does not grant
authority. The Child Mission's own `authority_hash` is the authority
commitment for the child, on its record.

`parent.depth` counts upward from 1 across generations, while the parent
entry's `children.max_child_depth` ({{fanout}}) is a per-entry ceiling
that decrements at each generation, so `parent.depth` never exceeds the
depth the ancestor entries allowed.

Example:

~~~ json
{
  "mission": {
    "id": "msn_9KwP2rT6vX1nL4qY8sB3zC7mF5jD",
    "issuer": "https://as.example.com",
    "parent": {
      "id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
      "issuer": "https://as.example.com",
      "authority_hash":
        "sha-256:tY2nD9bM7sX1cF8gH2vJ4kE5pNQl3KvZ4mP5x0wQrR6",
      "depth": 1,
      "delegation_id": "dlg_7pQ4m",
      "cascade_mode": "immediate",
      "created_at": "2026-11-02T08:14:00Z"
    }
  }
}
~~~

## Mission Record Requirements {#record-requirements}

The Child Mission record MUST contain:

- the `parent` object;
- the child actor;
- the child Authority Set;
- the child `authority_hash`;
- the child Mission Intent's `intent_hash`
  ({{I-D.draft-mcguinness-oauth-mission}});
- where the child-creation exchange carried an authority proposal,
  the recorded `proposed_authority` and its `proposal_hash`;
- the delegation event identifier;
- the cascade mode; and
- the fan-out policy result.

The `parent` value is immutable after creation.

The delegation event ({{child-creation}}) is the Child Mission's
approval event. It MUST commit the issuance profile's integrity anchors
({{I-D.draft-mcguinness-oauth-mission}}): `authority_hash` over the
child Authority Set, `intent_hash` over the child Mission Intent, and,
where the exchange carried an authority proposal, `proposal_hash` over
it, and
it MUST produce record the issuance profile's approval.

A Child Mission is created under a parent grant rather than a
first-party approval ({{issuance-relationship}}), so its human
accountability is inherited from the Parent Mission's own approval.
The Child Mission's `approval_basis` (the issuance profile's Mission
Record member, {{I-D.draft-mcguinness-oauth-mission}}) records how.

Where the deployment requires a human approval event for child
creation ({{child-creation}}), that event meets the issuance
profile's approval-event requirements in full, its human Approver is
the record's `approver`, and `approval_basis.type` is `direct`:

- `consent_principal` is that Approver;
- `activation` is `{ approval_event_id }`;
- `activation_actor` equals `consent_principal`; and
- `root_commitment` is the child's own `authority_hash`, exactly as
  for an ordinary Mission.

Where creation is adjudicated by policy with no human interaction
({{child-client-identity}}), `approval_basis.type` is
`policy_drawdown`:

- `consent_principal` is the Parent Mission's own
  `approver`, the accountable human standing behind the delegation that
  permits child creation ({{fanout}});
- `activation_actor` is the
  requesting parent agent, the Parent Mission's `client_id`, distinct
  from `consent_principal`; and
- `root_commitment` is the entry's
  `child_creation_policy` reference where the entry carries one,
  otherwise the Parent Mission's own `authority_hash`, which commits
  the authorizing delegation entry.

Either way `root_commitment` MUST
reference a committed value: the anti-laundering guarantee that a
`policy_drawdown` basis always traces to something the human's
approval actually committed.

Where the entry carries a
`child_creation_policy`, `activation` carries that policy's `id` and
`version` and this creation's own delegation event identifier (above)
as `activation_event_id`. Where it does not, the drawdown is against
the parent's approved delegation entry itself, not a separate policy
artifact: `activation` omits `policy_id` and carries only the
delegation event identifier as `activation_event_id`. The record's
`approver` is `consent_principal`: the Parent Mission's human
Approver, never the policy and never the requesting agent.

`approved_at` (the issuance profile's standing-consent requirement)
is the human approval instant of the consented root that
`root_commitment` commits, and it follows the root. Both forms above
were consented at the Parent Mission's approval event, since an
entry-carried `child_creation_policy` reference rides the committed
entry that approval covered, so `approved_at` is that approval
event's instant, read from the retained Parent record, never from
the child-creation request. Where a deployment separately versions
and re-approves the referenced policy's content as a standing
consent of its own, `approved_at` is that policy version's
human-approval instant, verified from the deployment's retained
governance record.

# Attenuation Rules {#attenuation}

A Child Mission MUST be bounded by the Parent Mission:

- every child Authority Set entry MUST be a subset of a parent entry
  under the subset rule of {{I-D.draft-mcguinness-oauth-mission}};
- the child MUST NOT include a resource, action, constraint relaxation,
  or delegation right not present in the parent;
- the child's effective `expires_at` MUST NOT be later than the child
  submission's `intent.expires_at`, the requested ceiling of the
  issuance profile's requested-versus-effective rule, nor later than
  the parent's `expires_at` (so it transitively caps every
  child-derived token's `exp`, per
  {{I-D.draft-mcguinness-oauth-mission}}); an auditor verifies those
  two inequalities and that any further shortening is justified by
  recorded policy, never by matching a recomputed minimum, since the
  issuance profile permits additional shortening under applicable AS
  policy; child creation inherits the issuance profile's atomic
  creation-time check, so a requested ceiling that passes while the
  creation is pending completes as this profile's creation failure,
  never as a Child Mission;
- the child MUST be created only where the applicable parent entry's
  `delegation` member carries a `children` object ({{fanout}});
- a child entry's `delegation` policy MUST NOT be broader than the
  parent entry's, per the subset rule of
  {{I-D.draft-mcguinness-oauth-mission}}:
  - its `max_depth` MUST be no greater; and
  - its `allowed_delegates` MUST be no wider;
- non-delegable parent entries MUST NOT appear in child authority; and
- child authority MUST be bound to the child actor identified in the
  request.

The Mission Issuer MUST compute the Child Mission's `authority_hash`
over the child Authority Set, not over the parent Authority Set. A
Resource Server enforces child tokens exactly as Mission-bound tokens:
the child `authority_hash` is the immediate authority commitment.

Child Mission tokens MUST be sender-constrained to the child actor's
own key, matching the issuance profile's delegated-token posture
({{I-D.draft-mcguinness-oauth-mission}}).

## Subset Evaluation {#strict-subset}

In this profile a "strict subset" is the subset rule of
{{I-D.draft-mcguinness-oauth-mission}} applied entry-wise between the
child Authority Set and the parent Authority Set with no relaxation.
"Strict" refers to that no-relaxation requirement, not to inequality:
per-entry equality is permitted, so a child entry MAY equal a parent
entry. Each child entry MUST be a subset of some parent entry under the
issuance profile's rule, and the `delegation` narrowing of {{attenuation}} applies in
addition. A Mission Issuer MUST NOT assume any relaxation the issuance profile's rule
does not define: the issuance profile's own opt-in hierarchy forms (`prefix`
resource containment and `.*` action families) apply as that rule
defines them, and nothing beyond them applies.

If the Mission Issuer cannot prove the child Authority Set is a strict
subset of the parent, it MUST refuse child creation with
`not_strict_subset`.

## Derivation Budget Is Not Inherited {#derivation-budget}

A Child Mission's effective `derivation_limit`
({{I-D.draft-mcguinness-oauth-mission}}) is established from its own
Mission Intent's `requested_derivation_limit`, clamped by the
deployment's own policy ceiling for the Child Mission, at child
creation, and is independent of the parent's: the
attenuation rules above bound a child's authority, expiry, and
delegation policy against the parent, but not its derivation count.
`derivation_limit` is a per-Mission local issuance counter. A Mission
Issuer and a deployment MUST NOT treat it, at any single Mission, as
an aggregate, concurrency, spend, or subtree bound.

A Parent Mission's
own `derivation_limit` caps derivation at the parent alone; it does not
bound how many derivations the child subtree performs in aggregate,
and a deep or wide subtree can derive far more than the parent's own
cap suggests. Where an approval interface displays `derivation_limit`,
or any per-Mission derivation control, as a limit on child creation,
that interface MUST disclose the composed bound reachable through the
subtree alongside it, so the Approver sees the real reachable surface
rather than one Mission's local counter alone.

Bounding the aggregate
across a subtree is the role of consumption metering, not this
profile's attenuation rules
({{I-D.draft-mcguinness-mission-metering}}). This warning is about the
child-subtree axis specifically; the continuation profile separately
counts derivations within a single Mission's own continued grants,
where a delegated refresh-token family's successive refreshes are one
derivation, not one per refresh
({{I-D.draft-mcguinness-oauth-mission-continuation}}, Section
"Authorization Continuity and the Mission").

# Fan-Out Controls {#fanout}

This profile defines the on-switch for child creation as a member of the
issuance profile's per-entry `delegation` object. The issuance profile lets a
companion profile define additional `delegation` members that are policy,
not authority, are never broadened downstream, and are carried unchanged
when not understood ({{I-D.draft-mcguinness-oauth-mission}}); this
profile's `children` member is such a member.

`children`:
: OPTIONAL. An object. Its PRESENCE on a parent Authority Set entry's
  `delegation` member is what permits Child Mission creation for that
  entry; an entry whose `delegation` carries no `children` permits no
  child ({{denial-reasons}}). Its members are the fan-out controls, each
  applied per entry, per parent Mission:

  `max_children`:
  : OPTIONAL. A positive integer. The maximum number of concurrently
    non-terminal Child Missions drawing on this entry, per parent
    Mission.

  `allowed_child_actors`:
  : OPTIONAL. An array of matcher objects of the same form as the issuance profile's
    `allowed_delegates` ({{I-D.draft-mcguinness-oauth-mission}}),
    constraining which actors or actor classes may receive a Child
    Mission from this entry. Matchers are evaluated under the issuance profile's
    `allowed_delegates` matching rules, including the rule that a
    `{ "sub_profile": ... }` matcher is satisfied when its value is
    among the actor's space-separated `sub_profile` values.

  `max_child_depth`:
  : OPTIONAL. A positive integer, default 1. The maximum
    child-generation depth at which this entry may be included. A Child
    Mission's own entries carry `children` only with `max_child_depth`
    reduced by one, and an entry at depth equal to the limit carries no
    `children`, ending the lineage.

  `child_creation_policy`:
  : OPTIONAL. A policy reference evaluated before each child creation.

Example parent Authority Set entry whose `delegation` carries `children`,
so the entry permits Child Missions to depth 2, at most 5 concurrently,
for `ai_agent` actors:

~~~ json
{
  "type": "mission_resource_access",
  "resource": "https://erp.example.com",
  "actions": ["invoices.read"],
  "delegation": {
    "max_depth": 2,
    "allowed_delegates": [{ "sub_profile": "ai_agent" }],
    "children": {
      "max_children": 5,
      "max_child_depth": 2,
      "allowed_child_actors": [{ "sub_profile": "ai_agent" }]
    }
  }
}
~~~

Depth limits alone do not control breadth: a Parent Mission MAY permit
many Child Missions at the same depth unless `max_children` or
`child_creation_policy` bounds fan-out. A Child-Mission-capable Mission
Issuer MUST enforce every `children` control an entry carries. If an
entry's `children` carries a control the Mission Issuer cannot enforce,
it MUST refuse child creation for that entry.

## Fan-Out Accounting {#fanout-accounting}

The Mission Issuer MUST count non-terminal Child Missions against
`max_children` until the child reaches a terminal state.

Where a child entry is a subset of more than one parent entry, the
Mission Issuer MUST select exactly one parent entry as that child
entry's justification and count the child against that entry's
`max_children` alone. The selection MUST be deterministic: the Mission
Issuer selects the first parent entry, in Authority Set order, that the
child entry is a subset of. The recorded justification mapping (the
parent entry each child entry was derived from, {{child-evidence}}) is
the accounting basis: `max_children` is counted per justifying entry,
and the same mapping is what the child evidence records.

The Mission Issuer MUST serialize child creation against the same
parent entry and fan-out bucket so concurrent requests cannot exceed
the limit.

# Cascade Revocation {#cascade}

A Child Mission depends on the Parent Mission. A Mission's dependent
Child Missions are every transitive descendant: its Child Missions,
their children, and every further generation. The cascade trigger is
any Parent Mission transition to a non-active state. This profile
distinguishes terminal triggers from the one reversible trigger.

Terminal triggers:
: Parent `revoked` or `expired`
  ({{I-D.draft-mcguinness-oauth-mission}}), `completed`
  ({{I-D.draft-mcguinness-oauth-mission-status}}), `superseded`
  ({{I-D.draft-mcguinness-oauth-mission-expansion}}), or `cascaded`
  ({{child-state}}, when the parent is itself a Child Mission that was
  cascade-terminated).

  On a terminal trigger the Mission Issuer MUST stop new derivation
  under dependent Child Missions and, under `immediate` cascade, MUST
  transition each dependent child to the terminal `cascaded` state
  ({{child-state}}).

  Cascade is transitive: the children of a `cascaded` parent cascade
  in turn under the same mode, in generation order, so a terminal
  trigger reaches every descendant.

Reversible trigger:
: Parent `suspended` ({{I-D.draft-mcguinness-oauth-mission-status}}).

  While the parent is suspended the Mission Issuer MUST stop new
  derivation under dependent Child Missions, but MUST NOT drive them
  to a terminal state. When the parent is resumed to `active`,
  dependent children return to their pre-suspension state and may
  derive again. Reporting of a dependent child while its parent is
  suspended is governed by {{child-state}}.

A `superseded` parent does not transfer its Child Missions to the
successor. The Mission Issuer MUST treat `superseded` as a terminal
cascade trigger and MUST NOT silently re-bind children to the
successor.

The reason is how successor authority is derived: the successor
Mission carries a freshly derived Authority Set that does not inherit
the predecessor's authority by reference
({{I-D.draft-mcguinness-oauth-mission-expansion}}), so a Child Mission
that was a strict subset of the predecessor is not guaranteed to be a
subset of the successor.

Continuing child work under the successor requires an explicit new
Child Mission creation ({{child-creation}}) under a successor grant,
which re-runs strict-subset validation ({{strict-subset}}) against the
successor's Authority Set.

Without explicitly approved carryover ({{carryover}}), there is no
batched record-continuity path from fan-out to widening: a
deployment that creates several Child Missions under a predecessor and
later expands that predecessor pays for it by tearing down every
non-terminal descendant and re-creating each one still needed under
the successor. That cost is deliberate.

A Child Mission's authority
must always trace to a committed approval it was actually checked
against: `parent.authority_hash` commits to the exact predecessor
Authority Set the strict-subset check ran against
({{parent-member}}), and a successor's freshly derived Authority Set
is not that commitment. The expansion profile's child-cascade consent
notice is where this cost can be surfaced to the Approver, at the same
consent event that approves the successor
({{I-D.draft-mcguinness-oauth-mission-expansion}}, Section "The
deferred window").

Cascade under this profile is issuer-committed. The Mission Issuer
MUST implement the `immediate` cascade mode and record the mode on the
Child Mission:

`immediate`:
: On a terminal trigger the Child Mission transitions to the `cascaded`
  state when the parent transition commits. On the reversible trigger
  the child is held non-active while the parent is suspended and
  restored to its prior state on parent resume.

Two consumer-verified cascade modes, `bounded_staleness` and
`status_required`, which trade issuer-committed transitions for
consumer-side parent-state checks, are experimental and defined in
{{experimental-cascade}}. A cascade mode MUST NOT allow a Child Mission
to continue deriving
new credentials after the parent is known to be non-active.

A consumer that does not recognize a Child Mission's `cascade_mode`
value MUST verify parent state, within the deployment's declared
freshness window, before each reliance on the child's authority: an
unrecognized mode may place the interim verification obligation on
the consumer.

Cascade modes may differ across one lineage. The Mission Issuer MUST
commit the terminal cascade transition for every dependent Child
Mission regardless of its cascade mode; the mode governs only what
consumers must verify in the interim.

An `immediate`-mode descendant under a consumer-verified parent is
therefore never orphaned: its own transition is committed even where
the parent's is consumer-observed.

The cascade behavior by trigger:

| Trigger | Resulting child state | Who observes |
|---------|-----------------------|--------------|
| Terminal (`revoked`, `expired`, `completed`, `superseded`, `cascaded`) | `cascaded` (terminal) | Mission Issuer sets it; consumers read it from Mission Status or a lifecycle event |
| Reversible (`suspended`) | reported `suspended`; restored on resume | Issuer reports it; consumers read it ({{child-state}}) |

## Child Mission State {#child-state}

A Child Mission has its own state, drawn from the issuance profile's
lifecycle state space ({{I-D.draft-mcguinness-oauth-mission}}). This
profile defines one child-specific terminal state:

`cascaded`:
: A terminal state a Child Mission enters when a terminal cascade
  trigger on its Parent Mission terminates it under `immediate` cascade
  ({{cascade}}). It is distinct from `revoked` (the child itself was not
  revoked) and `expired` (the child's own expiry was not reached), so
  audit can tell a cascade-terminated child from a directly terminated
  one.

  Following the issuance profile's forward-compatibility rule, a
  consumer treats `cascaded` as non-active, as it treats any state other
  than `active`. Mission Status
  ({{I-D.draft-mcguinness-oauth-mission-status}}) reports it among the
  terminal states, and a Mission lifecycle-change event
  ({{I-D.draft-mcguinness-oauth-mission-signals}}) carries it on the
  cascade transition.

A Child Mission also depends on ancestor state. For derivation under a
Child Mission, both conditions MUST hold:

- the Child Mission state is `active`; and
- every ancestor Mission in its lineage chain, not only the immediate
  parent, is `active`.

If either condition fails, the Mission Issuer MUST refuse derivation.
A cascade in progress ({{cascade}}) opens no window: a descendant
whose root ancestor is non-active is refused derivation even before
its own cascade transition commits.

Where a deployment also runs the Entry Discharge companion's
completion machinery ({{I-D.draft-mcguinness-oauth-mission-discharge}}),
discharge propagates entry-wise: when a parent Authority Set
entry is discharged, the Mission Issuer MUST discharge every child
entry justified by it, so spent authority does not survive in the
subtree.

Where a deployment also runs the Mission Containment profile
({{I-D.draft-mcguinness-oauth-mission-containment}}), containment
propagates entry-wise too: when a parent Authority Set entry is
contained, the Mission Issuer MUST propagate the containment to every
child entry justified by it, so a Child Mission does not keep deriving
contained authority while the parent stays `active`. A containment
transition on the parent does not itself change any child's lifecycle
state; it narrows the child's own Effective Authority Set exactly as
it narrows the parent's.

The issuer holds both records in either case, so the propagation needs
no consumer coordination.

While a parent is `suspended`, the issuer MUST report each dependent
child's state as `suspended` on every state-reporting surface (the
Mission Status operation and token introspection,
{{I-D.draft-mcguinness-oauth-mission-status}}), and MUST restore the
child's own state when the parent resumes to `active`.

A child whose own `expires_at` passes during the suspension is
`expired`: expiry takes precedence over the projected `suspended`
state.

Projection onset and lift are not silent. Each is a committed
metadata-only change on every affected child for the purposes of the
status profile's state version
({{I-D.draft-mcguinness-oauth-mission-status}}): the child's state
version increments at onset and again at lift, and, where the
deployment runs Lifecycle Signals
({{I-D.draft-mcguinness-oauth-mission-signals}}), a lifecycle-change
event is emitted for each affected child.

Likewise, once a terminal cascade trigger ({{cascade}}) commits at any
ancestor, the issuer MUST report each dependent descendant's state as
`cascaded` on every state-reporting surface (the Mission Status
operation and token introspection,
{{I-D.draft-mcguinness-oauth-mission-status}}) from that commit, ahead
of each descendant's own per-generation transition.

The transitive transitions still commit in generation order
({{cascade}}); this rule bounds only what a consumer reads, so a
consumer keying on a descendant's own state never reads `active`
mid-cascade.

Expiry takes precedence over `cascaded` as it does over the projected
`suspended` state: where a child's own `expires_at` coincides with a
terminal cascade of its parent (for example, a child whose `expires_at`
equals the parent's on parent expiry), the child's own `expired` state
wins and it is reported `expired`, not `cascaded`. This matches the
`cascaded` state, which a child enters only when its own expiry was not
reached.

Mission Status for a Child Mission SHOULD also include a parent
projection for authorized callers, as additional context:

`parent`:
: Object containing parent `id`, `issuer`, current parent `state` when
  known, `cascade_mode`, and freshness information.

Under `immediate` cascade a consumer needs no parent-state check of its
own: it relies on the Mission Issuer's child state transition, read
from the child's own state surfaces. The consumer obligations of the
experimental consumer-verified modes are defined with those modes
({{experimental-cascade}}).

# Child Mission Carryover {#carryover}

Child Mission Carryover is OPTIONAL. It batches explicitly approved creation
of replacement records during expansion; it never preserves an old record by
re-parenting it. The rules below apply to a Mission Issuer implementing this
capability. Ordinary cascade remains the default when it is not selected.

Carryover requires a child-specific direct approval for each replacement.
A policy-adjudicated progressive drawdown MUST NOT perform carryover.

## The Approved Manifest {#carryover-manifest}

The Mission Issuer MUST render and commit the exact Carryover Manifest,
including its exclusion policy and replacement approval facts, at the
expansion approval event.

A manifest is a JSON object with a `format_version` of 1, predecessor and
proposed successor references, the successor proposal's Intent and
authority commitments, `exclusion_policy`, and `entries`. References
include `issuer` and Mission identifier. Proposed identifiers are
reserved during preparation; reservation creates no authority. Entries
are ordered by old `created_at`, then old Mission identifier (byte order),
independently of the generation order used for derivation. Each entry names:

- `child_id`, `issuer`, `created_at`, `child_actor`, and current state and
  version;
- `authority_hash`, `intent_hash`, `effective_authority_hash`,
  `containment_version`, and the exact `parent` reference and `depth`;
- `derivation_limit`, `derivation_count`, `expires_at`, and every mutable
  discharge, fan-out, meter, or latch input used to decide or transfer
  eligibility (or authenticated commitments to those inputs);
- `outcome`, either `carry` or `cascade`, and a `reason` for `cascade`; and
- for `carry`, `replacement_id` and the proposed replacement's Intent
  commitment, approved-authority commitment, actor, parent reference,
  `authority_source`, expiry, derivation budget, and deterministic
  child-specific approval event identifier.

The manifest includes every non-terminal descendant at rendering. It retains
the complete proposed Intent and authority alongside their commitments, or
enough committed inputs and a versioned deterministic derivation to reproduce
them exactly. A reference to an uncommitted mutable policy is insufficient.
If the replacement inherits the successor's `authority_source` rather than the
old child's, that change is explicitly rendered and committed.

The `manifest_hash` uses the issuance profile's default commitment
construction over the JCS {{RFC8785}} canonical manifest, including
`exclusion_policy`. The issuer retains
the manifest with its authenticated approval; the hash alone authenticates no
approval. Each child-specific event identifier is derived from the committed
expansion approval event identifier and qualified old-child identity using
JCS and the same namespaced commitment construction, and is stable on retry.

The exclusion policy is either all-or-nothing (any change requires a fresh
render/approval), or disclosed-exclusions (only the stated change classes can
exclude rows, with dependent-descendant exclusion and unrendered-child cascade
explicitly disclosed). Neither mode silently adds a replacement or changes
a rendered cascade into carry.

## Completion Snapshot Check {#carryover-cas}

The Mission Issuer MUST compare-and-set every mutable eligibility and
transfer input committed in the manifest within the completion transaction,
not merely compare lifecycle version or `authority_hash`.

This includes effective authority/discharge state, derivation counters,
fan-out occupancy, and any external meter/latch state. A derivation counter
can change without a lifecycle-version increment; that still invalidates the
snapshot. Where the issuer cannot atomically protect an external transfer,
the affected child is ineligible, with that reason disclosed before approval.

A changed or missing input requires re-rendering, or exclusion strictly under
the committed policy. Excluding a prospective replacement parent excludes
every dependent descendant: no replacement attaches to a missing parent.
New descendants absent from the manifest are never carried; under
disclosed-exclusions they cascade and appear in the completion evidence.
Already-terminal old children retain their terminal state and are recorded as
excluded, never transitioned again to `cascaded`. Each final outcome is recorded
against its rendered row, not inferred from set equality over the subtree.

## Generation-by-Generation Eligibility {#carryover-generations}

The Mission Issuer MUST re-derive and validate each carried child in
generation order against its prospective parent's Effective Authority Set,
using all ordinary strict-subset, actor, and children-control checks.

A direct child's parent is the successor; a deeper child's parent is its
new replacement parent, never the root successor. Justification is recomputed
by {{fanout-accounting}} against the new parent. Survival of the old justifying
entry is not required: the successor may reorder, split, or combine entries.
The old mapping is evidence, not stable entry identity.

## No State, Authority, Expiry, or Budget Reset {#carryover-no-reset}

The Mission Issuer MUST use the old child's current Effective Authority Set
as the replacement's authority ceiling and MUST NOT restore containment or
discharge removed by that effective-set calculation.

Only an effectively `active` child is eligible. A `suspended` child is
excluded, not resumed by carryover. The replacement's approved set is the
rechecked effective set, with no overlay reset that restores removed
authority.

The replacement's `expires_at` MUST NOT exceed either the old child's
`expires_at` or its new parent's effective `expires_at`.

A successor's separately approved expiry extension does not extend the old
child's horizon. Any other policy shortening remains applicable.

The Mission Issuer MUST preserve the old child's `derivation_limit` and
`derivation_count` and atomically preserve every remaining operational budget
or make the child ineligible.

This is a carryover-specific exception to starting a new child with a fresh
derivation counter ({{derivation-budget}}): the replacement continues the old
child's remaining budget, despite receiving a new record identifier.
Metering and exclusivity require defined, atomic transfer or shared-state
binding; changing the key to `replacement_id` is not a transfer. Fan-out is
recounted against new justifying entries in the same serialization domain,
including concurrently non-terminal occupants and all carried generations.
Repeated expansion/carryover cannot replenish any of these budgets.

## Fresh Records and Direct Approval {#carryover-records}

The Mission Issuer MUST create a new record for each replacement, with
`approval_basis.type` `direct` and a child-specific approval event, and MUST
NOT modify the old child's `parent` or immutable approval anchors.

The expansion Approver is the `consent_principal` and ordinary `direct`
`activation_actor` for each replacement; activation carries its
deterministic `approval_event_id` and `root_commitment` is its own
`authority_hash`. The issuer re-runs the ordinary source-activation and
source-ceiling checks for the
rendered replacement `authority_source`. There is no `expansion_carryover`
standing-consent basis.

The replacement records `related_to` as correlation with the qualified old
child, under expansion's existing correlation semantics. The old child gains
`carried_to`, a string containing the replacement Mission identifier under
the same issuer, only when its `cascaded` transition and replacement commit.
`carried_to` is immutable thereafter, absent for excluded children, and grants
nothing. Neither pointer selects authority or rebinds a credential.

## Atomic Records, Recoverable Delivery {#carryover-commit}

The Mission Issuer MUST commit successor activation, predecessor
supersession, every replacement record, the required old-child cascades,
the final old-to-new map, and durable publication/recovery work atomically.

No partial successor, surviving replacement, or cascade is left by a failed
transaction. Constructing replacements before cascades inside the transaction
does not promise a remote observation order. External publication is performed
after commit and is recoverable and idempotent; it is never performed inside
the record transaction.

The Mission Issuer MUST provide idempotent retrieval of the committed
replacement result through the child-creation completion surface to the
authenticated and authorized child actor.

The deterministic event identifier is a correlation/idempotency key, never
a bearer credential. Retrieval repeats no approval, creates no duplicate
replacement, and still enforces current authorization and lifecycle checks
on any newly issued credential. An interrupted delivery can resume from the
durably retained result.

A token for the terminated child MUST NOT be treated as a credential of its
replacement.

Existing tokens retain their original identity and ordinary expiry and
state-reliance rules; new derivation under the old child stops. Replacement
authority requires a credential issued for the new record. Without a separate
readiness/acknowledgment protocol, carryover preserves record continuity and
removes repeated approval ceremonies, but does not guarantee uninterrupted
worker execution.

## Carryover Evidence and Observation {#carryover-evidence}

The Mission Issuer MUST retain authenticated Carryover Evidence containing
the `manifest_hash`, predecessor and successor references, and the complete
final map of old child identities to carried or excluded outcomes.

For a carried row the map includes `replacement_id` and its child-specific
`approval_event_id`; for an excluded row it includes `reason` and observed
terminal state or committed cascade. Unrendered descendants are listed
explicitly. The map, not `related_to`, is the normative record of replacement.

A replacement's ordinary Child Evidence object is extended with
`creation_mode` set to `carryover`, `carried_from` (a qualified old-child
reference), `manifest_hash`, and `carryover_evidence` (an authenticated
reference to the retained batch map). Its existing `parent`, `child`,
`attenuation`, `fanout`, and `decision` members remain required; a batch
map does not replace ordinary Child Evidence or become authority.

When Status or Signals is deployed, the issuer MUST carry the committed
`carried_to` correlation on the old child's `cascaded` observation as defined
by those profiles.

A consumer MUST NOT infer absence of a replacement from receiving a cascade
before the replacement's creation event.

Signals may duplicate or reorder deliveries. Consumers pair by the
authenticated issuer-qualified identifiers, retain unresolved pairs, and
resynchronize through authorized Status/completion/evidence retrieval. The
durable map makes recovery possible even if creation was never delivered to
that consumer. Correlation does not override ordinary state, authority, or
credential verification. No cross-Mission version ordering is implied.

## Acceptance Cases {#carryover-acceptance}

A carryover implementation exercises at least: a carried leaf; an ineligible
leaf; contained/discharged authority not restored; suspended child excluded;
grandchild under its replacement parent; dependent exclusion; new fan-out
limits; predecessor expiry extension not inherited; changed state and missing
record at completion; derivation consumption and discharge after rendering;
unrendered new descendants; already-terminal child exclusion; two successive
carryovers with non-increasing budgets; authenticated idempotent recovery;
a forced mid-batch rollback; crash after commit before publication; and
out-of-order creation/cascade signals.

# Child Evidence {#child-evidence}

The Mission Issuer MUST record a child delegation evidence record with:

- parent Mission identifier, issuer, and authority hash;
- child Mission identifier, issuer, and authority hash;
- child actor;
- requested and approved child authority;
- attenuation checks performed;
- fan-out counters or policy result;
- cascade mode;
- approval or policy basis; and
- creation time.

This evidence is audit material and does not grant authority.

## Child Evidence Object {#child-evidence-object}

A Child Evidence object is a JSON object {{RFC8259}} with:

`evidence_id`:
: REQUIRED. Unique identifier.

`parent`:
: REQUIRED. Parent Mission reference.

`child`:
: REQUIRED. Child Mission reference.

`child_actor`:
: REQUIRED. Child actor identity.

`attenuation`:
: REQUIRED. Object recording subset checks and result.

`fanout`:
: REQUIRED when fan-out controls apply. Object recording counters and
  policy.

`cascade_mode`:
: REQUIRED. Cascade mode.

`decision`:
: REQUIRED. One of `created` or `denied`.

`denial_reason`:
: REQUIRED when `decision` is `denied`.

`created_at`:
: REQUIRED. RFC 3339 {{RFC3339}} timestamp.

Example:

~~~ json
{
  "evidence_id": "chd_8K2nP4qV",
  "parent": {
    "id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
    "issuer": "https://as.example.com",
    "authority_hash":
      "sha-256:tY2nD9bM7sX1cF8gH2vJ4kE5pNQl3KvZ4mP5x0wQrR6"
  },
  "child": {
    "id": "msn_9KwP2rT6vX1nL4qY8sB3zC7mF5jD",
    "issuer": "https://as.example.com",
    "authority_hash":
      "sha-256:hQ2vJ4kE5pNQl3KvZ4mP5x0wRr6tY2nD9bM7sX1cF8g"
  },
  "child_actor": {
    "sub": "subagent-invoice-extractor",
    "sub_profile": "ai_agent"
  },
  "attenuation": {
    "result": "strict_subset"
  },
  "fanout": {
    "active_children": 2,
    "max_children": 5
  },
  "cascade_mode": "immediate",
  "decision": "created",
  "created_at": "2026-11-02T08:14:00Z"
}
~~~

## Canonical Bytes {#child-evidence-canonical}

A Child Evidence object's canonical bytes are its JCS {{RFC8785}}
canonicalization, and its type identifier is
`application/mission-child-evidence+json`, registered by this document
({{iana}}).

# Relationship to Expansion

Mission Expansion
{{I-D.draft-mcguinness-oauth-mission-expansion}} creates a successor
Mission that replaces a predecessor for a broader task. Mission Child
Delegation creates a dependent Mission for a child actor with narrower
authority. Expansion widens by fresh approval; Child Missions attenuate
within parent authority. The two operations are distinct.

A Child Mission MAY be expanded, but only within the parent's authority:
a successor Child Mission MUST remain a strict subset of the Parent
Mission's Authority Set ({{strict-subset}}) and keeps the same `parent`.
Expanding a Child Mission beyond its parent requires expanding the parent
first. Explicitly approved batched re-creation after a parent expands is
defined by {{carryover}}; re-parenting an existing record remains forbidden.

# Composition with Offline Attenuation {#composition-attenuation}

A Child Mission's tokens MAY serve as attenuation roots under the
Mission Offline Attenuation profile
({{I-D.draft-mcguinness-oauth-mission-attenuation}}). The attenuation
chain's kill switch checks the Child Mission's state, and a parent stop
reaches the chain through cascade ({{cascade}}): when the parent
terminates, the Child Mission becomes non-active and the chain rooted on
its tokens stops at the next state check.

# Relationship to Harnesses

A Mission-aware harness
{{I-D.draft-mcguinness-mission-harness}} MUST NOT treat a
sub-agent handle as authority. When durable sub-agent work requires a
separate authority handle, the harness can request a Child Mission
under this profile.

# Authorization Server Metadata {#discovery}

A Mission Issuer that supports this profile SHOULD advertise it in its
authorization server metadata {{RFC8414}} so a parent agent can
discover child-delegation support before attempting child creation:

`mission_child_delegation_supported`:
: OPTIONAL boolean. When `true`, the Mission Issuer accepts the child
  creation request of {{child-creation}} and enforces the controls of
  this profile. A client MUST NOT infer the fan-out controls
  ({{fanout}}) a deployment enforces from this member alone; an
  unenforceable requested control is refused at creation
  ({{denial-reasons}}).

# Conformance {#conformance}

A conforming Child-Mission-capable Mission Issuer MUST:

- create Child Missions only through the child-creation token exchange
  ({{child-creation}}), accepting the parent's Mission-bound access
  token as `subject_token` with `subject_token_type` of `access_token`
  and rejecting a refresh token;
- resolve the Parent Mission from `subject_token` and prove possession
  against that token's own confirmation key, not from the
  caller-supplied `parent` identifier alone
  ({{request-processing}});
- require `creation_request_id` on every child-creation exchange and
  recover a repeated one per {{creation-idempotency}}, never creating
  a second child;
- enforce strict-subset authority and expiry;
- enforce delegation and fan-out controls;
- record the `parent` member on child Mission records and tokens;
- record the Child Mission's `approval_basis` ({{record-requirements}}):
  `direct` for a human-approved child, `policy_drawdown` for one
  policy adjudicates, with `consent_principal` always the Parent
  Mission's human `approver`;
- implement cascade revocation; and
- record child delegation evidence.

A Resource Server does not need to understand this profile to enforce
child tokens as Mission-bound tokens. A Resource Server MUST NOT apply
lineage-sensitive policy from the `parent` member unless it implements
the semantics of the parent-member ({{parent-member}}) and cascade
({{cascade}}) sections.

# Security Considerations {#security-considerations}

## Authority by Ancestry

The primary threat is implicit authority inheritance: a child actor
acts because it descends from a parent session. This profile requires
explicit child Mission creation and rejects session ancestry as an
authorization basis.

## Fan-Out Amplification

Many child actors at the same depth can amplify authority even when
each child is a subset. Fan-out controls are required so deployments
can bound breadth as well as depth.

## Cascade Failure

If parent revocation does not reach children, child authority can
outlive its source. Cascade modes define how termination propagates and
how consumers bound stale parent state.

Cascade reaches derivation at the commit of each transition: once a
terminal trigger commits, no dependent Child Mission derives again.
Outstanding child access tokens run to the earlier of the token's
`exp` and the runtime staleness bound, where the runtime enforcement
layer is deployed. A deployment that needs prompt cascade uses short
child-token lifetimes.

## Parent Confusion

An attacker could try to create a child under a parent it does not
control by naming a `parent` identifier. The Mission Issuer resolves
the parent from `subject_token`, not from the identifier, proves
possession against the token's own confirmation key, and verifies any
`parent` cross-check names the resolved Mission
({{request-processing}}).

## Possession Proof and the Eliminated Parent-Grant-at-Rest Concern

Earlier revisions of this profile carried the parent grant as a
`parent_token` refresh token pushed through PAR {{RFC9126}}, so a
reusable bearer credential sat at rest in the PAR store until the
pushed request was redeemed or expired. The child-creation token
exchange eliminates that concern by construction: the possession proof
is the parent's short-lived, sender-constrained Mission-bound access
token presented directly at the token endpoint as `subject_token`
({{child-creation}}), never a reusable refresh credential and never
held at rest awaiting redemption. A refresh token MUST NOT be accepted
as `subject_token`.

- A captured `subject_token`, without its DPoP key or mTLS certificate,
  cannot carry the possession proof.
- The DPoP proof `jti` is single-use per {{RFC9449}}, so a captured
  exchange cannot be replayed ({{request-processing}}).
- Where a deployment records the exchange for audit, it MUST NOT write
  `subject_token` or the DPoP proof to logs, traces, or audit records
  in the clear, and MUST redact or hash them wherever the request is
  otherwise recorded. Child delegation evidence ({{child-evidence}})
  records the parent by identifier and authority hash, never the
  credential itself.

## Subset Bugs

Subset evaluation is the security core of this profile. Deployments
SHOULD keep subset rules deterministic and auditable, and SHOULD record
the exact parent entries used to justify each child entry.

# Privacy Considerations {#privacy-considerations}

The `parent` member exposes Mission lineage and can correlate child and
parent activity. Deployments SHOULD minimize cross-audience disclosure
of parent lineage when it is not needed for enforcement, and SHOULD
restrict child delegation evidence to authorized audit consumers.

# IANA Considerations {#iana}

This document registers two parameters in the "OAuth Parameters"
registry. For each: Parameter Usage Location token request; Change
Controller IETF; Reference this document, {{child-creation}}.

- `parent`
- `child_actor`

The child-creation token exchange carries the already-registered
`mission_intent` request parameter and the already-registered
{{RFC8693}} token-exchange parameters `subject_token`,
`subject_token_type`, `requested_token_type`, `actor_token`, and
`actor_token_type`; none of these needs registration by this document.
This document removes the earlier revision's registration request for a
`parent_token` parameter: the parent is resolved from `subject_token`,
so no dedicated parent-token parameter exists. The `parent` and `child_actor`
parameters are presented only on the token endpoint's authenticated
back channel, never on a front-channel authorization request
({{child-creation}}).

The `creation_request_id` parameter this profile requires on the
child-creation exchange ({{creation-idempotency}}) is defined and
registered by the expansion profile
({{I-D.draft-mcguinness-oauth-mission-expansion}}); this document
adds no registration for it.

This document registers one member in the existing "OAuth Authorization
Server Metadata" registry {{RFC8414}}: Change Controller IETF; Reference
this document, {{discovery}}.

- `mission_child_delegation_supported`

Consistent with the issuance profile, which registers the `mission`
claim as an open object with no registry of its members, this document
defines the `parent` member of the `mission` claim
({{parent-member}}) without a separate claim registration: it is a
member defined by this profile, carried inside the already-registered
`mission` claim.

This document defines one closed set of symbolic codes: the child
creation denial reasons ({{denial-reasons}}). They ride the shared
`mission_denial_reason` member the expansion profile defines and
registers ({{I-D.draft-mcguinness-oauth-mission-expansion}}). This
document establishes no registry of its own; it requests these
registrations in the registries its siblings establish
({{iana-registrations}}).

## Registry Registrations {#iana-registrations}

This document requests registration of its seven denial reasons in
the expansion profile's Mission Denial Reasons registry, one row per
reason of {{denial-reasons}}, each with its semantics as defined
there, Change Controller IETF, and Reference this document,
{{denial-reasons}}.

It requests registration of one state in the issuance profile's
Mission Lifecycle States registry
({{I-D.draft-mcguinness-oauth-mission}}):

| Value | Terminal | Semantics | Change Controller | Reference |
|---|---|---|---|---|
| `cascaded` | yes | A terminal state a Child Mission enters when a terminal cascade trigger on its Parent Mission terminates it under `immediate` cascade. | IETF | this document, {{child-state}} |

## Media Type Registration

This document registers one media type per {{RFC6838}}.

### Child Evidence Media Type

- Type name: application
- Subtype name: mission-child-evidence+json
- Required parameters: none
- Optional parameters: none
- Encoding considerations: binary; JSON encoded in UTF-8
- Security considerations: see {{security-considerations}}
- Interoperability considerations: see this document
- Published specification: this document
- Applications that use this media type: Mission child delegation
  deployments
- Fragment identifier considerations: same as for `application/json`
- Additional information:
  - Deprecated alias names for this type: none
  - Magic number(s): none
  - File extension(s): `.json`
  - Macintosh file type code(s): TEXT
- Person & email address to contact for further information:
  Karl McGuinness <public@karlmcguinness.com>
- Intended usage: COMMON
- Restrictions on usage: none
- Author: IETF
- Change controller: IETF

Child creation uses the already-registered {{RFC8693}}
`urn:ietf:params:oauth:grant-type:token-exchange` grant type, selected
by the `requested_token_type` value `urn:ietf:params:oauth:token-type:jwt`
({{grant-type}}); this document requests no new grant-type registration.
An earlier revision requested registration of a dedicated
`urn:ietf:params:oauth:grant-type:mission-child-creation` grant type;
this document removes that request, folding child creation into the
token-exchange grant the rest of the Mission family already uses.

--- back

# Experimental Consumer-Verified Cascade Modes {#experimental-cascade}

This appendix is **experimental**: adopt it for evaluation, not as a
stable interface. It is not part of this profile's conformance
surface, so its rules are stated in lowercase rather than as BCP 14
keywords. It defines two cascade modes that trade the
issuer-committed transition of `immediate` ({{cascade}}) for
consumer-side parent-state checks, for deployments where the Mission
Issuer cannot commit child transitions synchronously with the parent's.
Each shifts a per-reliance obligation onto every consumer of child
tokens, which is why they are not part of the base profile.

`bounded_staleness`:
: The Child Mission is treated as non-active no later than the cascade
  staleness bound, measured from the consumer's last confirmed-active
  observation of the parent, aligned with the Status profile's freshness
  model ({{I-D.draft-mcguinness-oauth-mission-status}}). That bound is
  the deployment's `mission_max_stale_seconds`
  ({{I-D.draft-mcguinness-oauth-mission-status}}) unless the deployment
  publishes a different bound for child cascade. Under this mode a
  non-terminal child counts against `max_children`
  ({{fanout-accounting}}) until the cascade window has closed or the
  child is otherwise confirmed non-active.

`status_required`:
: Consumers must check parent state, per reliance decision and within
  the deployment's declared freshness window
  ({{I-D.draft-mcguinness-oauth-mission-status}}), before accepting
  child Mission authority. The Mission Issuer must select this mode only
  where every audience of child tokens is known, by registration or
  deployment policy, to implement this profile's parent-state check;
  otherwise the Mission Issuer must compensate with short child-token
  lifetimes or introspection-required paths.

The cascade behavior by trigger and mode:

| Trigger | Mode | Resulting child state | Who observes |
|---------|------|-----------------------|--------------|
| Terminal | `bounded_staleness` | non-active by the staleness bound | Consumer, from its last confirmed-active parent observation |
| Terminal | `status_required` | non-active on the next parent-state check | Consumer, per reliance decision |

A consumer that cannot obtain parent state must obey the mode:

- under `status_required`, it must refuse; and
- under `bounded_staleness`, it must refuse after the bound.

For derivation under these modes, the Mission Issuer may rely on a
prior confirmed-active parent observation within the mode's freshness
rules where it cannot observe the parent synchronously; a Child
Mission must not derive after the parent is known to be non-active.
The `immediate` rules of {{cascade}} and {{child-state}} otherwise
apply unchanged.

# Document History {#document-history}

\[\[ To be removed from the final specification ]]

- Added the capability-gated Child Mission Carryover foundation, including
  full snapshot and budget checks, committed exclusion semantics, fresh
  direct approvals, and durable observation and recovery. Carryover
  preserves record continuity, not worker continuity (#576).

# Acknowledgments
{:numbered="false"}

This document is part of the Mission-Bound Authorization for OAuth 2.0
set and defines explicit child authority for sub-agent work.
