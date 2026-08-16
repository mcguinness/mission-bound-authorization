---
title: "Mission Transaction Authorization Profile for OAuth 2.0"
abbrev: "Mission Transaction Authorization"
category: exp

docname: draft-mcguinness-mission-transaction-authorization-latest
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
  latest: "https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-transaction-authorization.html"

author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com

normative:
  RFC7515:
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

informative:
  RFC9470:
  I-D.draft-mcguinness-oauth-mission-consent-evidence:
    title: "Mission Consent Evidence for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-consent-evidence.html
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
  I-D.draft-mcguinness-oauth-mission-cross-org-delegation:
    title: "Mission Cross-Organizational Delegation for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-cross-org-delegation.html
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
bound to the concrete action, parameters, resource, on-behalf-of
principal, and authorized presenter, the designation survives
delegation, enforcement works without a live callback to the approval
authority, and the result is usable at most once.  This document
profiles the OAuth transaction authorization challenge for
Mission-bound authorization: a protected resource signs a challenge
for one normalized operation, a trusted Transaction Authorization
Server validates the challenge, the Mission or delegation authority,
the presenter, and a governed approval, performs a fresh
authorization decision with the approval as input, and only then
issues a sender-constrained, audience-restricted, single-use
transaction access token the resource verifies locally.  The approval
is not authority; the token is authority because a trusted server
issued it after a fresh decision bounded by the Mission and the
approved operation.

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
Approval").  What Runtime deliberately leaves open is the portable
wire workflow that obtains the approval and delivers an enforceable
result across a trust boundary.

This document fills that gap for the cross-domain case by profiling
the transaction authorization challenge
({{I-D.draft-rosomakho-oauth-txn-challenge}}).  It keeps the model
small: `requires_action_approval` stays the only Authority Set
designation, the transaction token carries no generic approval or
evidence bag, single use is semantic to the token type, and Consent,
Decision, and Execution Evidence stay on the evidence and audit
planes, correlated by identifiers rather than embedded in every
request.

# Status: An Experimental Extension {#status}

This profile is experimental and profiles an unratified individual
draft ({{I-D.draft-rosomakho-oauth-txn-challenge}}).  Upstream
engagement with that draft, including the implementation-derived
`parameter_digest` feedback, is tracked separately; this document
consumes that work rather than duplicating it.

# Conventions and Terminology

{::boilerplate bcp14-tagged}

This document uses the Mission family's terms from the issuance
profile ({{I-D.draft-mcguinness-oauth-mission}}) and the runtime
profile ({{I-D.draft-mcguinness-mission-runtime}}).

Transaction Authorization Server (TAS):
: the trusted server that validates a transaction challenge, the
  Mission or delegation authority, the presenter, and a governed
  approval, performs a fresh authorization decision, and issues the
  transaction token.  It MAY be operated by the origin or the
  destination domain; the resource trusts its key and policy role
  through pre-established federation metadata, never a request claim.

Transaction token:
: the sender-constrained, audience-restricted, single-use access
  token the TAS issues on a permit ({{token}}).

# Applicability {#applicability}

This profile is invoked when any of the following requires
action-bound approval for a Mission-bound request:

- the matched Authority Set entry carries
  `constraints.requires_action_approval: true`;
- destination resource policy requires approval for the action or
  risk class; or
- a current local entitlement or governance rule requires it.

A delegated child MUST preserve `requires_action_approval: true`
under the Common Constraints subset rule
({{I-D.draft-mcguinness-oauth-mission}}); `false` remains equivalent
to omission and cannot override a `true` ancestor, and this profile
defines no second approval constraint.  Step-up authentication
({{RFC9470}}) is not a substitute: it strengthens the actor's
authentication context and does not approve the transaction.  A
durable role or relationship grant produced by an approval workflow
is current governance state the PDP re-evaluates, not an approval
token.

# Resource Challenge {#challenge}

After receiving an ordinary Mission-bound request, the PEP normalizes
the operation under its Operation Profile and computes the runtime
`parameter_digest` ({{I-D.draft-mcguinness-mission-runtime}}).  If
approval is required and no valid transaction token is present, the
resource returns a signed transaction challenge: a JWT with an
explicit `typ` profiled for Mission transaction authorization,
carrying:

- standard `iss` (the protected resource), `aud` (the selected TAS),
  `iat`, `exp`, and `jti`;
- `txn`, the resource-scoped transaction identifier;
- exactly one operation-scoped `authorization_details` entry, or one
  compound-action detail whose registered semantics make it atomic;
- `parameter_digest`, computed exactly as Mission Runtime specifies;
- `mission`, copied from the verified credential or chain, including
  the invariant origin principal `subject` where the
  cross-organizational principal profile applies
  ({{I-D.draft-mcguinness-oauth-mission-cross-domain}}); and
- `cnf`, identifying the presenter key the resulting token binds to.

The resource MUST derive these values from the request and the
verified credential and MUST NOT accept client-supplied
replacements.  Raw action parameters SHOULD stay outside the
challenge when the TAS can authorize from the digest and
privacy-preserving attributes; where raw values are needed to render
or decide, they travel through an authenticated confidential channel
and are recomputed against the digest.  The challenge `exp` MUST be
short and no later than the presented credential or chain, the
Mission expiry, and the resource-declared challenge ceiling.

# Challenge Redemption and Approval {#redemption}

The client presents to the TAS: the signed challenge, the current
Mission-bound token or cross-organizational delegation chain
({{I-D.draft-mcguinness-oauth-mission-cross-org-delegation}}), proof
of possession of the challenge `cnf` key, and any separately
authenticated attributes policy requires.  The TAS MUST, in order:

1. authenticate the client or presenter and verify possession of the
   challenge-bound key;
2. resolve the challenge issuer to a registered resource and validate
   its exact `typ`, signature, audience, time, and `jti` replay
   state;
3. validate the Mission-bound token or the complete delegation chain,
   including Mission state, origin principal, actor lineage,
   authority subset, audience, depth, expiry, and proof of
   possession;
4. require exact equality between the challenge `mission` and the
   verified credential or chain Mission invariants, by value of the
   profiled members, not byte comparison of a serialization;
5. establish that the requested `authorization_details` is within the
   verified delegated authority and applies to the challenge issuer
   and resource;
6. enforce `requires_action_approval` and destination policy;
7. obtain or resolve a governed approval from an acceptable
   independent Approver or policy authority, bound to `txn`, the
   operation identity, `parameter_digest`, the resource, the Mission,
   the origin principal, and the presenter key;
8. verify approval status, scope, grant time, maximum age, and
   `approved_until`; and
9. run a fresh authorization decision
   ({{I-D.draft-mcguinness-mission-runtime}}) using the verified
   approval as context together with current Mission state, principal
   entitlement, resource policy, and the concrete parameter inputs.

Any denial ends the flow.  Approval completion alone MUST NOT trigger
token issuance and MUST NOT bypass step 9.  The set of acceptable
Transaction Authorization Servers, resource challenge issuers, and
approval authorities is deployment or federation policy, never taken
from an untrusted request claim.

# Transaction Token {#token}

On a permit, the TAS issues a JWT access token with an explicit `typ`
whose registered semantics are "Mission transaction authorization,
sender-constrained, single audience, single use".  It contains only:

- standard `iss`, `sub`, `aud`, `iat`, `exp`, and `jti`;
- ordinary `client_id` and `act` identity semantics where applicable
  ({{I-D.draft-mcguinness-oauth-mission}});
- `txn`, copied from the verified challenge;
- the exact permitted `authorization_details`, never wider than the
  challenge, the delegation chain, or the current decision;
- `parameter_digest`, copied only after recomputation and
  verification;
- the `mission` claim, value-invariant from the verified credential
  including `subject` where the principal profile applies; and
- `cnf`, bound to the verified presenter key.

The token MUST NOT carry a generic `approval` object, a `single_use`
boolean, raw rendered approval text or action parameters, roles or
relationships conferred by an approval workflow, or evidence objects
whose lifecycle and disclosure rules belong to the evidence and audit
profiles.  Single use is semantic to the token `typ`, not a carried
flag.

The token `exp` is no later than the earliest of the challenge
expiry, the approval freshness or `approved_until`, the current
credential or delegation-chain expiry, the Mission expiry, and the
deployment maximum.  A short token lifetime limits stale-policy and
theft exposure but does not replace the point-of-use state checks the
deployment's runtime claim requires.

# Offline Verification and Execution {#verification}

The protected resource verifies locally, without calling the TAS on
the request path:

1. the exact token `typ`, a trusted issuer and signature, the
   intended `aud`, `iat` and `exp`, and the token class;
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
6. atomic first use of `(iss, jti)` in the consumption domain.

The consumption domain is the metering profile's Exact enforcement
profile ({{I-D.draft-mcguinness-mission-metering}}, Section
"Exactness and Topology"): the first-use check and record are
linearizable across every replica capable of executing the same
operation, committed before the irreversible effect or atomically
with it where the operation store supports that transaction.  If the
consumption store is unavailable, enforcement fails closed for this
profile.

`txn` identifies the resource transaction; `jti` identifies the
issued authorization; the replay key is `(iss, jti)`.  A retry after
an ambiguous response uses the Operation Profile's idempotency key to
retrieve or complete the same result; it never consumes the token to
create a second effect.  A genuinely new attempt requires a new
challenge, approval decision, token, and idempotency key.

# Evidence and Audit {#evidence}

The approval service or TAS records the governed approval state and,
where configured, Consent Evidence
({{I-D.draft-mcguinness-oauth-mission-consent-evidence}}).  The PDP
emits Decision Evidence and the executor emits Execution Evidence
under the runtime evidence profile
({{I-D.draft-mcguinness-mission-runtime-evidence}}).  They correlate
using the Mission reference, `txn`, the transaction-token `jti`,
`parameter_digest`, and the idempotency identity.

Those records do not ride in the transaction token.  Where durable
independent proof is required, the audit profile registers or
receipts the relevant evidence
({{I-D.draft-mcguinness-mission-audit}}).  The enforcement token
stays small and privacy-minimized; the evidence plane retains the
richer account.  The TAS MUST be able to show that its fresh decision
relied on a valid approval, but a relying party's authorization
decision rests on the trusted typed token plus current local checks,
not on parsing an evidence blob.

# Failure Semantics {#failures}

- No or expired action approval: deny; the workflow MAY return or
  request another approval.
- Approval granted but current policy or entitlement denies: deny;
  approval is not a bypass.
- Parameter, resource, Mission, principal, presenter, or audience
  mismatch: terminal refusal for that token or challenge.
- Stale or unavailable required state: fail closed; retry only per
  the declared state-recovery policy.
- Consumed token: return the prior idempotent result where the
  Operation Profile allows it, otherwise `duplicate_suppressed`;
  never execute again.
- Challenge or token with an unknown `typ` or authorization-details
  semantics: reject, never best-effort parse.

# Conformance {#conformance}

An implementation conforms as a **protected resource** (challenge
issuer and offline verifier, {{challenge}}, {{verification}}), as a
**Transaction Authorization Server** ({{redemption}}, {{token}}), or
both.  Positive and negative vectors cover, at minimum: a valid
cross-domain challenge, approval, fresh decision, and one execution;
delegated `requires_action_approval` preservation and an attempted
removal; step-up presented without transaction approval; a valid
approval for a changed amount, recipient, resource, action, Mission,
origin principal, actor, audience, or presenter key; approval
complete but the Authority Set, local entitlement, or resource policy
denies; a missing or changed `parameter_digest` and a different
canonicalization; challenge replay, token replay on one replica, and
simultaneous replay across replicas; an ambiguous first execution
followed by an idempotent retry; an expired challenge, approval,
Mission, delegation leaf, or token; an untrusted resource challenge
issuer, TAS, or approval authority; an arbitrary signed JWT or an
ordinary Mission token presented as a transaction token; the absence
of raw parameters and approval detail from the token; and evidence
correlation from challenge and decision through exactly one execution
or a terminal refusal.

# Security Considerations

The runtime profile's security considerations apply in full.  This
profile adds the transaction surface.

- **Approval is not authority.**  A permit is issued only after the
  fresh decision of {{redemption}} step 9; a completed approval alone
  never yields a token.  A relying party trusts the typed token and
  its own current checks, not a reconstructed approval workflow.
- **At most once versus availability.**  The Exact-profile
  consumption domain is linearizable across every replica that can
  execute the operation.  Under partition, fail-closed sacrifices
  availability; a merely local cache cannot support the at-most-once
  property, and this profile makes no at-most-once claim without a
  shared atomic consumption domain.
- **Trust anchors are pre-established.**  The accepted challenge
  issuers, Transaction Authorization Servers, and approval
  authorities come from federation metadata.  A token or challenge
  never selects its own trust authority.
- **Short lifetimes.**  Short challenge and token windows reduce
  stale-state and theft exposure at the cost of more expiries and
  retries; deployments publish the ceilings and instrument expirations
  rather than hide the tradeoff.
- **JWT best practices.**  Every JWT this profile handles follows
  {{RFC8725}}: explicit typing, algorithm allow-lists, and no
  unverified pass-through.

# Privacy Considerations

`parameter_digest` keeps sensitive action inputs out of the token and
challenge; raw values travel only over an authenticated confidential
channel when a decision genuinely needs them.  The transaction token
carries no approver identity or rendered approval text; approver
detail lives on the evidence plane under its disclosure rules
({{I-D.draft-mcguinness-mission-runtime-evidence}}).  Where the
origin-principal profile applies, its correlation and minimization
rules govern the `mission.subject` the challenge and token carry
({{I-D.draft-mcguinness-oauth-mission-cross-domain}}).

# IANA Considerations {#iana}

## Media Type Registrations

This document requests registration of two media types in the "Media
Types" registry.

For the transaction challenge, `application/mission-txn-challenge+jwt`:
Type name: application; Subtype name: mission-txn-challenge+jwt;
Required parameters: N/A; Optional parameters: N/A; Encoding
considerations: binary (JWT); Security considerations: see this
document; Published specification: this document; Applications that
use this media type: Mission-aware protected resources and
Transaction Authorization Servers; Change controller: IESG.

For the transaction token, `application/mission-txn-token+jwt`: Type
name: application; Subtype name: mission-txn-token+jwt; Required
parameters: N/A; Optional parameters: N/A; Encoding considerations:
binary (JWT); Security considerations: see this document; Published
specification: this document; Applications that use this media type:
Mission-aware protected resources and Transaction Authorization
Servers; Change controller: IESG.

--- back

# Acknowledgments
{:numbered="false"}

This profile builds on the transaction authorization challenge and on
the action-bound approval model of Mission Runtime.
