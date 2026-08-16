---
title: "Mission Transaction Authorization Profile for OAuth 2.0"
abbrev: "OAuth Mission Transaction Authorization"
category: exp

docname: draft-mcguinness-oauth-mission-transaction-authorization-latest
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
 - authorization
 - transaction
 - approval
venue:
  github: "mcguinness/mission-bound-authorization"
  latest: "https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-transaction-authorization.html"

author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com

normative:
  RFC6838:
  RFC7515:
  RFC7519:
  RFC7800:
  RFC8693:
  RFC8725:
  RFC9396:
  RFC9449:
  I-D.draft-rosomakho-oauth-txn-challenge:
  I-D.draft-mcguinness-oauth-mission:
    title: "Mission-Bound Authorization for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission.html
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
  I-D.draft-mcguinness-mission-metering:
    title: "Mission Metering"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-metering.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-oauth-mission-status:
    title: "Mission Status for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-status.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-oauth-mission-cross-domain:
    title: "Mission Cross-Domain Projection for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-cross-domain.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026

informative:
  RFC9470:
  I-D.draft-mcguinness-oauth-mission-cross-org-delegation:
    title: "Mission Cross-Organizational Delegation for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-cross-org-delegation.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-mission-approval-governance:
    title: "Mission Approval Governance"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-approval-governance.html
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
  I-D.draft-mcguinness-mission-audit:
    title: "Mission Audit"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-audit.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026

--- abstract

Some delegated actions must stay subject to execution-time human
authorization even after a Mission is approved: the authorization is
bound to the concrete action, its parameters, the resource, the
on-behalf-of principal, and the authorized presenter, and the result
is usable at most once.  This document is a thin profile of the OAuth
transaction authorization challenge for Mission-bound authorization.
It runs the upstream challenge, endpoint, and polling unchanged and
adds only the Mission-specific delta: the challenge and token bind the
Mission, the approval is decision input to a fresh authorization
decision rather than a bearer grant, the transaction token is
restricted to its one recorded transaction, and enforcement happens at
the point of use.  Cross-organizational delegation is projected to a
locally consumable Mission-bound token first; this profile then runs
over that single local credential.

--- middle

# Introduction

The Mission approval event ({{I-D.draft-mcguinness-oauth-mission}})
consents to a task and its authority bound; it does not consent to a
specific action's concrete parameters at the point of use.  Mission
Runtime defines the policy model for a fresh, action-bound approval,
its concrete-parameter binding, its maximum age, and its
time-of-check-to-time-of-use reverification, and states that the
approval is decision input, never a bearer grant
({{I-D.draft-mcguinness-mission-runtime}}, Section "Action-Bound
Approval").  What Runtime leaves open is the portable wire workflow
that obtains the approval and delivers an enforceable result.

The OAuth transaction authorization challenge
({{I-D.draft-rosomakho-oauth-txn-challenge}}) already defines that
workflow: a capability header, a challenge, a transaction
authorization endpoint, a pending handle, polling, and a token
response.  This document does not restate or fork that protocol.  It
is a thin delta that runs the upstream protocol unchanged and adds
four Mission-specific things: the challenge and token bind the
Mission; the approval is input to a fresh authorization decision; the
transaction token is restricted to its one recorded transaction and
cannot be refreshed, exchanged, or reused; and enforcement is at the
point of use.

# Status: An Experimental Extension {#status}

This profile is experimental and profiles an unratified individual
draft ({{I-D.draft-rosomakho-oauth-txn-challenge}}).  Where this
document names an upstream artifact (a header, parameter, endpoint,
claim, or error), the upstream definition governs and this document
adds only Mission constraints.  Should an upstream change establish
profile-specific challenge types or parameters, this profile follows
the upstream registry rather than inventing a parallel one.  Upstream
engagement, including the implementation-derived `parameter_digest`
feedback, is tracked separately; this document consumes that work.

# Conventions and Terminology

{::boilerplate bcp14-tagged}

This document uses the Mission family's terms from the issuance
profile ({{I-D.draft-mcguinness-oauth-mission}}) and the runtime
profile ({{I-D.draft-mcguinness-mission-runtime}}).

Transaction Authorization Server (TAS):
: the OAuth Authorization Server in the functional role of the
  upstream transaction authorization endpoint
  ({{I-D.draft-rosomakho-oauth-txn-challenge}}), even where it is
  deployed separately from the Mission Issuer.  It validates the
  challenge, the presented Mission-bound token, the presenter, and a
  governed approval, runs a fresh authorization decision, and issues
  the transaction token.  The resource trusts its key and policy role
  through pre-established metadata, never a request claim.

Transaction token:
: the sender-constrained, audience-restricted, single-use access
  token the TAS issues on a permit ({{token}}).

# Applicability and Composition {#applicability}

This profile is invoked when any of the following requires
action-bound approval for a Mission-bound request: the matched
Authority Set entry carries `constraints.requires_action_approval:
true`; destination resource policy requires approval for the action or
risk class; or a current local entitlement or governance rule
requires it.  A delegated child MUST preserve
`requires_action_approval: true` under the Common Constraints subset
rule ({{I-D.draft-mcguinness-oauth-mission}}); `false` is equivalent
to omission and cannot override a `true` ancestor, and this profile
defines no second approval constraint.  Step-up authentication
({{RFC9470}}) is a different lane: it strengthens the actor's
authentication context and does not approve the transaction.

The credential this profile operates on is a single **local
Mission-bound token**: an access token whose `mission` claim, `sub`,
`client_id`, and `act` are established in the resource's own domain.
Cross-organizational delegation is out of band to this profile:
a delegation chain is verified and projected to a local Mission-bound
token through the cross-domain projection exchange first
({{I-D.draft-mcguinness-oauth-mission-cross-org-delegation}},
{{I-D.draft-mcguinness-oauth-mission-cross-domain}}), and this profile
then runs over that one local credential.  A TAS is not a
chain-verifying endpoint: the projection has already established the
local `sub`, `client_id`, `act`, audience, and origin-principal
mapping, and the upstream chain survives in the projection's
derivation evidence
({{I-D.draft-mcguinness-mission-runtime-evidence}}), not in the
transaction request.

# The Upstream Protocol, Unchanged {#upstream}

This profile runs the upstream protocol
({{I-D.draft-rosomakho-oauth-txn-challenge}}) without modification:

- a client advertises support with the `Accept-Txn-Challenge` request
  header;
- a protected resource that needs transaction authorization responds
  with the `transaction_authorization_required` challenge in
  `WWW-Authenticate`, carrying the signed challenge in the
  `transaction_challenge` parameter;
- the client presents the challenge to the
  `transaction_authorization_endpoint` advertised in Authorization
  Server metadata;
- the endpoint returns a `transaction_authorization_id` pending
  handle when authorization is not immediate, which the client polls;
  and
- the upstream error responses apply unchanged.

The TAS is the OAuth Authorization Server in the endpoint's
functional role ({{applicability}}).  This document adds the Mission
constraints in the sections below; it does not restate the upstream
message flow.

# Resource Challenge {#challenge}

The challenge is the upstream challenge JWT with `typ`
`txn-authz-challenge+jwt` and the mandatory upstream `reason`.  A
Mission deployment additionally binds:

- `txn`, the resource-scoped transaction identifier (upstream);
- exactly one operation-scoped `authorization_details` entry
  ({{RFC9396}}), or one compound-action detail whose registered
  semantics make it atomic;
- `parameter_digest`, computed exactly as Mission Runtime specifies
  ({{I-D.draft-mcguinness-mission-runtime}});
- `operation_profile`, an object with `id` and `version` pinning the
  Operation Profile under which `parameter_digest` was computed, so a
  profile update while approval is pending cannot silently change
  normalization ({{parameters}});
- `mission`, copied by value from the verified local Mission-bound
  token, including the origin principal `subject` where the
  cross-organizational principal profile applies
  ({{I-D.draft-mcguinness-oauth-mission-cross-domain}}); and
- `cnf`, the presenter key the resulting token binds to ({{RFC7800}}).

The resource MUST derive these from the request and the verified
local token and MUST NOT accept client-supplied replacements.  The
challenge `exp` is short: it bounds initial admission and challenge
replay, not the approval workflow ({{lifetimes}}).

## Parameter Transport {#parameters}

The TAS recomputes `parameter_digest` and decides over concrete
inputs.  Raw values are conveyed by one composed mechanism, not an ad
hoc side channel: either every approval-relevant value is expressed
in the registered `authorization_details` entry, or the resource
profiles the upstream `reason_uri` as a resource-controlled retrieval
reference whose authenticated response is bound to the challenge
`iss`, `txn`, the challenge `jti`, and `parameter_digest`.  Operation
Profile resolution is deterministic and versioned: the TAS resolves
the exact `operation_profile.id` and `version` from the challenge and
recomputes the digest under that version.  No generic attributes bag
is defined.

# Redemption and Approval {#redemption}

The client presents the challenge, the local Mission-bound token, and
proof of possession of the challenge `cnf` key to the transaction
authorization endpoint.  The TAS MUST, in order:

1. authenticate the client and verify possession of the challenge
   `cnf` key;
2. resolve the challenge issuer to a registered resource and validate
   its `typ`, signature, audience, time, and `jti` replay state
   (upstream);
3. validate the local Mission-bound token: Mission state, authority,
   audience, expiry, and proof of possession;
4. require value equality between the challenge `mission` and the
   token's Mission invariants, by value of the profiled members, not
   byte comparison of a serialization;
5. establish that the requested `authorization_details` is within the
   token's authority and applies to the challenge issuer and
   resource;
6. enforce `requires_action_approval` and destination policy;
7. obtain or resolve a governed approval from an acceptable
   independent Approver or policy authority, through ARAP and the
   Approval Governance record
   ({{I-D.draft-mcguinness-mission-authzen}},
   {{I-D.draft-mcguinness-mission-approval-governance}}), bound to
   `txn`, the operation identity, `parameter_digest`, the resource,
   the Mission, the origin principal, and the presenter key;
8. verify approval status, scope, grant time, maximum age, and
   `approved_until`; and
9. run a fresh authorization decision
   ({{I-D.draft-mcguinness-mission-runtime}}) using the verified
   approval as context together with current Mission state, principal
   entitlement, resource policy, and the concrete parameter inputs.

Any denial ends the flow.  Approval completion alone MUST NOT trigger
token issuance and MUST NOT bypass step 9.  The set of acceptable
Transaction Authorization Servers, challenge issuers, and approval
authorities is deployment or federation policy, never taken from an
untrusted request claim.

## Lifetimes and the Pending Workflow {#lifetimes}

Three lifetimes are distinct:

- the challenge `exp` bounds initial admission and replay of the
  challenge;
- the `transaction_authorization_id` pending handle expiry bounds the
  asynchronous approval workflow, and MAY be longer than the
  challenge `exp`; and
- the transaction token `exp` is bounded by the fresh revalidation
  inputs of step 9 and the pending-handle expiry, NOT by the
  already-consumed challenge `exp`.

One accepted challenge maps to exactly one pending workflow: a retry
of the same accepted challenge returns the existing
`transaction_authorization_id`, never a second approval task.  On
completion, the TAS performs a fresh revalidation of Mission state,
credential validity, authority, approval freshness, principal
entitlement, resource policy, and presenter binding before issuing;
a poll before completion returns the upstream pending status.

# Transaction Token {#token}

On a permit, the TAS issues a JWT access token whose `typ` is
`mission-txn-token+jwt` (REQUIRED), an explicit type whose registered
semantics are "Mission transaction authorization, sender-constrained,
single audience, single use".  The token response carries
`token_type` `DPoP` (or the deployment's sender-constraining
mechanism); a refresh token MUST NOT be issued.  The token contains
only:

- standard `iss`, `iat`, `exp`, and `jti`;
- `sub`: the destination-local principal established by the projected
  local Mission-bound token, never the approver or the approval
  workflow;
- `client_id`: the client authenticated at the transaction endpoint;
- `act`: REQUIRED whenever actor context was present on the local
  token, carried per the local projection rule
  ({{I-D.draft-mcguinness-oauth-mission-cross-domain}}); the approver
  and approval workflow are never `sub`, `client_id`, or `act`;
- `aud`: a single string, exactly the verified challenge issuer;
- `txn`, copied from the verified challenge;
- the exact permitted `authorization_details`, never wider than the
  challenge or the current decision;
- `parameter_digest`, copied only after recomputation and
  verification;
- `mission`, value-invariant from the verified local token including
  `subject` where the principal profile applies; and
- `cnf`, exactly the challenge-bound presenter key ({{RFC7800}}).

The token MUST NOT carry a generic `approval` object, a `single_use`
boolean, raw rendered approval text or action parameters, roles or
relationships conferred by an approval workflow, or embedded evidence
objects; single use is semantic to the token `typ`.  The token
additionally MUST NOT be refreshed, exchanged or delegated
({{RFC8693}} inputs refuse it), used as a cross-organizational
delegation root, or accepted as an ordinary Mission-bound token, and
it is usable only for its recorded `txn`.  A conforming resource
rejects a `mission-txn-token+jwt` presented on any path other than
the one recorded transaction, and rejects an ordinary Mission-bound
token presented as a transaction token.

The token `exp` is no later than the earliest of the approval
freshness or `approved_until`, the local credential expiry, the
Mission expiry, the pending-handle expiry, and the deployment
maximum.

# Offline Verification and Execution {#verification}

The protected resource verifies locally, without calling the TAS on
the request path:

1. the exact token `typ` `mission-txn-token+jwt`, a trusted issuer
   and signature, the intended single-string `aud`, `iat` and `exp`,
   and the token class;
2. proof of possession of the `cnf` key by the current presenter
   ({{RFC9449}});
3. equality of `txn`, the Mission invariants (by value), the
   operation `authorization_details`, and the recomputed
   `parameter_digest` with the pending operation;
4. origin-principal, local-subject, and actor consistency under the
   principal profile
   ({{I-D.draft-mcguinness-oauth-mission-cross-domain}});
5. current local policy, principal entitlement, and any required
   Mission-state observation, each within its declared freshness
   bound; the Mission-state source is the Status surface
   ({{I-D.draft-mcguinness-oauth-mission-status}}), keeping runtime
   state observation the targeted overlay it is elsewhere in the
   family; and
6. atomic first use for the resource transaction ({{atomicity}}).

## At-Most-Once and Identifier Roles {#atomicity}

Four identifiers play distinct roles:

- the challenge `jti` detects replay of the challenge (upstream, at
  the TAS);
- the `transaction_authorization_id` is the pending-workflow and
  issuance idempotency key: TAS issuance is idempotent per accepted
  challenge and workflow, so repeated polls return the same
  authorization result rather than minting a second token;
- `txn` is the resource-scoped transaction and the resource's
  **consumption key**: the resource consumes at most once per `txn`,
  so two validly signed tokens carrying different `jti` for the same
  `txn` still execute at most once; and
- the token `jti` additionally detects exact replay of one issued
  token; the runtime idempotency identity
  ({{I-D.draft-mcguinness-mission-runtime}}) links a retried attempt
  to the same effect.

The resource's consumption record for `txn` is the metering profile's
Exact enforcement profile
({{I-D.draft-mcguinness-mission-metering}}, Section "Exactness and
Topology"): the first-use check and record are linearizable across
every replica capable of executing the same operation, committed
before the irreversible effect or atomically with it where the
operation store supports that transaction.  If the consumption store
is unavailable, enforcement fails closed.  A retry after an ambiguous
response uses the Operation Profile's idempotency key to retrieve or
complete the same result; it never consumes a second time.  A
genuinely new attempt requires a new challenge, approval decision,
token, and idempotency key.

# Evidence and Audit {#evidence}

Each lifecycle event is recorded by its own profile, correlated by
identifiers rather than embedded in the token:

- the action-approval workflow and its provenance are ARAP and the
  Approval Governance record
  ({{I-D.draft-mcguinness-mission-authzen}},
  {{I-D.draft-mcguinness-mission-approval-governance}});
- the fresh PDP decision and its reference to the approval is
  Decision Evidence
  ({{I-D.draft-mcguinness-mission-runtime-evidence}});
- the single execution or refusal is Execution Evidence; and
- Mission Consent Evidence
  ({{I-D.draft-mcguinness-oauth-mission-consent-evidence}}) is
  evidence of the original Mission approval event only, not of the
  transaction approval, whose lifecycle is the runtime action-approval
  mechanism above.

Correlation uses the Mission reference, `txn`, the challenge `jti`,
the `transaction_authorization_id`, the transaction-token `jti`,
`parameter_digest`, and the runtime idempotency identity.  Records do
not ride in the token; where durable independent proof is required
the audit profile registers or receipts them
({{I-D.draft-mcguinness-mission-audit}}).  The TAS MUST be able to
show that its fresh decision relied on a valid approval, but a
relying party's authorization decision rests on the trusted typed
token plus its own current checks.

# Failure Semantics {#failures}

- No or expired action approval: deny; the workflow MAY return or
  request another approval.
- Approval granted but current policy or entitlement denies: deny;
  approval is not a bypass.
- Parameter, resource, Mission, principal, presenter, or audience
  mismatch: terminal refusal for that token or challenge.
- Stale or unavailable required state: fail closed; retry only per
  the declared state-recovery policy.
- Consumed `txn`: return the prior idempotent result where the
  Operation Profile allows it, otherwise `duplicate_suppressed`;
  never execute again, including for a second token bearing the same
  `txn`.
- Challenge or token with an unknown `typ` or authorization-details
  semantics: reject, never best-effort parse.

# Conformance {#conformance}

An implementation conforms as a **protected resource** (challenge
issuer and offline verifier, {{challenge}}, {{verification}}), as a
**Transaction Authorization Server** ({{redemption}}, {{token}}), or
both.  Positive and negative vectors cover, at minimum:

- the upstream endpoint, capability header, challenge, pending
  handle, and polling run unchanged;
- a valid challenge, asynchronous approval that completes after the
  challenge `exp`, fresh revalidation, and one execution;
- delegated `requires_action_approval` preservation and an attempted
  removal;
- step-up presented without transaction approval;
- a valid approval for a changed amount, recipient, resource, action,
  Mission, origin principal, actor, audience, or presenter key;
- approval complete but the Authority Set, local entitlement, or
  resource policy denies;
- a missing or changed `parameter_digest`, a different
  canonicalization, and an Operation Profile version change while
  approval is pending;
- challenge replay, token replay on one replica, simultaneous replay
  across replicas, and **two validly signed tokens with different
  `jti` for the same `txn` executing at most once**;
- duplicate TAS issuance suppressed per accepted challenge and
  workflow (repeated polls return the same result);
- identity projection: `sub` is the mapped local principal, the
  approver never becomes `sub`/`client_id`/`act`, `aud` is the single
  challenge issuer, `cnf` is the challenge key;
- the token refused when refreshed, exchanged, offered as a
  cross-organizational root, or presented as an ordinary Mission
  token;
- an ambiguous first execution followed by an idempotent retry;
- an untrusted challenge issuer, TAS, or approval authority; and
- evidence correlation from challenge and decision through exactly one
  execution or a terminal refusal.

# Security Considerations

The runtime profile's security considerations apply in full.  This
profile adds the transaction surface.

- **Approval is not authority.**  A permit is issued only after the
  fresh decision of {{redemption}} step 9; a completed approval alone
  never yields a token.  A relying party trusts the typed token and
  its own current checks, not a reconstructed approval workflow.
- **At most once versus availability.**  The consumption record is
  keyed by the resource-scoped `txn` under the Exact enforcement
  profile, so two tokens for one `txn` cannot both execute.  Under
  partition, fail-closed sacrifices availability; a local cache
  cannot support the at-most-once property, and this profile makes no
  such claim without a shared atomic consumption domain.
- **Trust anchors are pre-established.**  The accepted challenge
  issuers, Transaction Authorization Servers, and approval
  authorities come from federation metadata; a token or challenge
  never selects its own trust authority.
- **Token containment.**  The transaction token cannot be refreshed,
  exchanged, delegated, made a cross-organizational root, or accepted
  as an ordinary Mission token, and is usable only for its recorded
  `txn`; these restrictions keep a single-action authority from
  becoming standing authority.
- **JWT best practices.**  Every JWT this profile handles follows
  {{RFC8725}}: explicit typing, algorithm allow-lists, and no
  unverified pass-through.

# Privacy Considerations

`parameter_digest` keeps sensitive action inputs out of the token and
challenge; raw values travel only through the composed transport of
{{parameters}} when a decision genuinely needs them.  The transaction
token carries no approver identity or rendered approval text;
approver detail lives on the evidence plane under its disclosure
rules ({{I-D.draft-mcguinness-mission-runtime-evidence}}).  Where the
origin-principal profile applies, its correlation and minimization
rules govern the `mission.subject` the challenge and token carry
({{I-D.draft-mcguinness-oauth-mission-cross-domain}}).

# IANA Considerations {#iana}

## Media Type Registration

This document requests registration of the following media type in
the "Media Types" registry, per {{RFC6838}}.  The transaction
challenge type (`txn-authz-challenge+jwt`) is registered by the
upstream draft ({{I-D.draft-rosomakho-oauth-txn-challenge}}) and is
not re-registered here.

- Type name: application
- Subtype name: mission-txn-token+jwt
- Required parameters: N/A
- Optional parameters: N/A
- Encoding considerations: 8bit; the token is a JWT
  ({{RFC7519}}), a series of base64url-encoded values separated by
  period characters
- Security considerations: see {{iana}} and the Security
  Considerations of this document
- Interoperability considerations: N/A
- Published specification: this document
- Applications that use this media type: Mission-aware protected
  resources and Transaction Authorization Servers
- Fragment identifier considerations: N/A
- Additional information: N/A
- Person and email address to contact for further information:
  Karl McGuinness (public@karlmcguinness.com)
- Intended usage: COMMON
- Restrictions on usage: none
- Author: Karl McGuinness
- Change controller: IESG

--- back

# Acknowledgments
{:numbered="false"}

This profile builds on the transaction authorization challenge and on
the action-bound approval model of Mission Runtime.
