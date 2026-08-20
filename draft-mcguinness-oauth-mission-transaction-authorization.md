---
title: "Mission Transaction Authorization Profile for OAuth 2.0"
abbrev: "OAuth Mission Transaction Authorization"
category: exp

docname: draft-mcguinness-oauth-mission-transaction-authorization-latest
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
 - transaction
 - approval
venue:
  github: "mcguinness/mission-bound-authorization"
  latest: "https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-txn-authorization.html"

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
  RFC8705:
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
  I-D.draft-mcguinness-mission-substrate:
    title: "Mission Substrate Requirements"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-substrate.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026

informative:
  RFC9068:
  RFC9470:
  I-D.draft-reece-wimse-cross-org-delegation:
  I-D.draft-mcguinness-oauth-actor-profile:
  I-D.draft-hardt-aauth-r3:
    title: "AAuth Rich Resource Requests (R3)"
    target: https://dickhardt.github.io/AAuth/draft-hardt-aauth-r3.html
    author:
      -
        ins: D. Hardt
        name: Dick Hardt
    date: 2026
  I-D.draft-mcguinness-mission-aauth:
    title: "Mission Context Binding for AAuth"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-aauth.html
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
  ARAP:
    target: https://openid.github.io/authzen/authzen-access-request-approval-profile-1_0.html
    title: "AuthZEN Access Request and Approval Profile - Draft 1"
    author:
      -
        org: OpenID Foundation
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
  I-D.draft-mcguinness-mission-runtime-evidence:
    title: "Mission Runtime Evidence"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-runtime-evidence.html
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
  I-D.draft-mcguinness-mission-metering:
    title: "Mission Consumption Metering"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-metering.html
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
  I-D.draft-mcguinness-oauth-mission-continuation:
    title: "Mission Continuation: Authorization Continuity for Mission-Bound Authorization"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-continuation.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026

--- abstract

A delegated agent's Mission may require that a specific action, with
its concrete parameters, be authorized fresh at the point of use,
across an organizational boundary, without a live callback on the
execution path. This document defines a Mission Transaction
Authorization profile of the OAuth transaction authorization
challenge {{I-D.draft-rosomakho-oauth-txn-challenge}}. It keeps that
protocol's wire contract whole and adds only the Mission layer: the
profiled challenge claims, `subject_token` credential carriage,
Mission and authority validation, approval as decision input, the
fresh decision, and the transaction-token profile.

--- middle

# Introduction

An agent's Mission can carry actions whose consequence warrants more
than the Mission's own approval and more than a stronger
authentication context. Cross-organizational delegation sharpens the
requirement: {{I-D.draft-reece-wimse-cross-org-delegation}} describes
delegated work that must remain subject to execution-time human
authorization, bound to the concrete action, parameters, resource,
on-behalf-of principal, and authorized presenter, surviving
delegation, and usable at most once, without a live call back to the
approval authority on the execution path.

The Mission family already supplies the policy model: the Common
Constraint `requires_action_approval`
({{I-D.draft-mcguinness-oauth-mission}}) designates an action as
requiring a fresh approval and is monotonic under the subset rule, and
Mission Runtime's action-bound approval
({{I-D.draft-mcguinness-mission-runtime}}) defines concrete-parameter
binding, a maximum age, a fresh decision, and atomic consumption. What
neither defines is the portable wire workflow that carries an
approval across a trust boundary to a resource that must enforce
locally. This document supplies that workflow as a profile of the
OAuth transaction authorization challenge
{{I-D.draft-rosomakho-oauth-txn-challenge}}. The profile keeps that
protocol's challenge type, request and response parameters,
capability signal, endpoint, and asynchronous polling whole; it adds
the Mission-profiled challenge claims, the credential carried to the
transaction endpoint, Mission and authority validation, approval as
decision input, the fresh decision, and the transaction-token
profile.

The approval is not authority. The transaction token is authority
because a trusted issuer minted it after a fresh decision bounded by
the Mission and the approved operation.

This profile is the strict-delta consumer of the upstream protocol;
engagement with that protocol's own evolution proceeds through the
family's coordination process, outside this document.

# Status: An Optional Extension {#optional-status}

This document is optional. A deployment that satisfies action-bound
approval by another means, a synchronous local decision, a bespoke
callback, or no cross-organizational case at all, is fully conformant
to the issuance profile and the runtime profile and is unaffected by
this document. It places no new requirement on either.

A deployment claims this profile only when it carries action-bound
approval across a trust boundary through the transaction challenge
and token defined here. The Mission, its Authority Set, the subset
rule, and `requires_action_approval` are unchanged; this document
governs only the portable wire result that a resource and a
Transaction Authorization Server exchange to satisfy an action-bound
approval requirement.

This profile tracks an in-progress substrate. It depends normatively
on the OAuth transaction authorization challenge
({{I-D.draft-rosomakho-oauth-txn-challenge}}), an early Internet-Draft
that is not ratified and whose details may change, so this profile is
not yet a stable interface and will track the substrate as it
evolves. It reuses, without restating, the upstream challenge type,
parameters, endpoint, and polling states, and the Mission's own
`mission` claim, `requires_action_approval`, `parameter_digest`, and
`act` delegation chain exactly as those documents define them.
Action-bound approval within a single trust domain, which needs only
the runtime profile, is the stable path; deploy this profile for
evaluation rather than as a stable interface. This document is
Experimental for that reason, tracking its substrate and crossing to
the stable tier by reclassification when the substrate does.

# Conventions and Terminology {#conventions}

{::boilerplate bcp14-tagged}

This document uses Mission, Authority Set, Approver, Mission Issuer,
`mission_resource_access`, and the subset rule as the issuance profile
defines them ({{I-D.draft-mcguinness-oauth-mission}}); action-bound
approval, the Operation Profile, `parameter_digest`, and Mission state
freshness as the runtime profile defines them
({{I-D.draft-mcguinness-mission-runtime}}); the envelope anchor,
canonical-object digest, and raw-octet digest species of the default
commitment construction as the substrate defines them
({{I-D.draft-mcguinness-mission-substrate}}); and the transaction
authorization challenge, its claims, its endpoint, and its pending and
polling states as the OAuth transaction authorization challenge
defines them ({{I-D.draft-rosomakho-oauth-txn-challenge}}).

Transaction Authorization Server (TAS):
: The OAuth Authorization Server acting in the role
  {{I-D.draft-rosomakho-oauth-txn-challenge}} defines for the
  transaction authorization endpoint: it validates the challenge,
  applies the Mission validation and fresh-decision rules of this
  profile, and mints the transaction token. A TAS instance MAY be the
  Mission Issuer itself or an Authorization Server deployed separately
  from it; this profile does not require either arrangement.

Challenge-Issuing Resource:
: The protected resource of
  {{I-D.draft-rosomakho-oauth-txn-challenge}} in this profile: it
  normalizes the requested operation, computes its `parameter_digest`,
  and signs the transaction challenge with the Mission-profiled claims
  of {{resource-challenge}}.

Presenting Client:
: The client of {{I-D.draft-rosomakho-oauth-txn-challenge}} in this
  profile: it holds the challenge's confirmation key, obtains the
  transaction token from the TAS, and presents the token to the
  Challenge-Issuing Resource for execution.

Transaction challenge:
: The `transaction_challenge` of
  {{I-D.draft-rosomakho-oauth-txn-challenge}}, typed
  `txn-authz-challenge+jwt`, profiled by {{resource-challenge}} with
  the Mission-profiled claims.

Transaction token:
: The sender-constrained, single-audience, single-use JWT the TAS
  mints of {{transaction-token}}, typed `application/mission-txn-token+jwt`.

# Applicability {#applicability}

This profile is invoked when any of these requires action-bound
approval for a normalized operation:

- the matched Authority Set entry carries
  `constraints.requires_action_approval: true`;
- destination resource policy requires approval for the action or
  risk class; or
- a current local entitlement or governance rule requires it.

A delegated child MUST preserve `requires_action_approval: true`
under the Common Constraints subset rule of
{{I-D.draft-mcguinness-oauth-mission}}. `false` remains equivalent to
omitting the member and cannot override a `true` ancestor. This
profile defines no second approval constraint: `requires_action_approval`
stays the only Authority Set designation this profile reads.

Step-up authentication is not a substitute. A step-up obligation
({{RFC9470}}) proves a stronger authentication context; it does not
approve the transaction, and a Transaction Authorization Server MUST
NOT treat a step-up context alone as satisfying an action-bound
approval requirement. A durable role or relationship grant produced
by a governance decision is also not an approval token: it becomes
current governance state, and the fresh decision of
{{challenge-redemption}} re-evaluates it like any other current
policy input rather than consuming it as the approval itself.

# Resource Challenge {#resource-challenge}

After receiving an ordinary Mission-bound request for an action that
falls under {{applicability}}, the Challenge-Issuing Resource
normalizes the operation under its Operation Profile and computes the
runtime `parameter_digest` ({{I-D.draft-mcguinness-mission-runtime}}).
When no valid transaction token is presented, the resource signals and
returns a transaction authorization challenge exactly as the upstream
protocol defines: the client's `Accept-Txn-Challenge` header gates the
signal, the `transaction_authorization_required` error and
`transaction_challenge` parameter carry the challenge, and the
challenge is a JWT with protected header `typ`
`txn-authz-challenge+jwt`
({{I-D.draft-rosomakho-oauth-txn-challenge}} Sections 4.1, 4.2, and
4.2.1). This document does not restate that mechanism.

The challenge's REQUIRED claims `iss`, `aud`, `iat`, `exp`, `jti`,
`txn`, `authorization_details`, and `reason`, and its OPTIONAL `act`
and `reason_uri`, are exactly as
{{I-D.draft-rosomakho-oauth-txn-challenge}} Section 4.2.2 defines
them. `authorization_details` carries exactly one operation-scoped
`mission_resource_access` entry ({{I-D.draft-mcguinness-oauth-mission}})
or one compound-action detail whose registered semantics make the
operation atomic. The Operation Profile a TAS and the resource apply
resolves deterministically from the challenge's `iss` and that entry's
`type` member ({{RFC9396}}): a resource versions its Operation Profile
by versioning `type`, and a TAS MUST retain and recognize a superseded
Operation Profile version for as long as a pending workflow still
references it.

This profile adds the following REQUIRED challenge claims:

`mission`:
: REQUIRED. Copied from the verified Mission-bound access token,
  unchanged, including the invariant origin principal
  (`mission.subject`) where the Origin Principal profile applies
  ({{I-D.draft-mcguinness-oauth-mission-cross-domain}}).

`parameter_digest`:
: REQUIRED. Computed exactly as the runtime profile specifies
  ({{I-D.draft-mcguinness-mission-runtime}}); this document defines no
  second canonicalization.

`cnf`:
: REQUIRED. The presenter key {{RFC7800}} to which the resulting
  transaction token must be bound.

The resource MUST derive `mission`, `parameter_digest`, and `cnf` from
the request and the verified Mission-bound access token, and MUST NOT
accept a client-supplied replacement for any of them.

Raw action parameters SHOULD remain outside the challenge when the TAS
can decide from `parameter_digest` plus privacy-preserving attributes.
Where a decision needs the normalized operation itself, this profile's
one resource-controlled retrieval mechanism is the upstream
`reason_uri` claim: dereferencing it, over a channel authenticated to
the Challenge-Issuing Resource, returns the normalized operation bound
to `txn`, the challenge `jti`, and `parameter_digest`; the party
relying on the retrieved operation MUST recompute `parameter_digest`
against it before relying on it. This document defines no second,
unspecified attribute channel.

# Challenge Redemption and Approval {#challenge-redemption}

The Presenting Client submits the challenge to the
`transaction_authorization_endpoint` exactly as
{{I-D.draft-rosomakho-oauth-txn-challenge}} Section 5.1 defines:
`client_id` where required, and the signed `transaction_challenge`.
This profile adds two REQUIRED parameters that carry the Mission-bound
access token as an assertion, under {{RFC8693}} Sections 2.1 and 3:

`subject_token`:
: REQUIRED. The Mission-bound access token.

`subject_token_type`:
: REQUIRED. `urn:ietf:params:oauth:token-type:access_token`.

The request also carries proof of possession of the challenge's `cnf`
key, using DPoP {{RFC9449}} or mTLS {{RFC8705}}, the same mechanism
{{transaction-token}} binds the resulting token to. A holder-mediated
cross-organizational delegation Chain is not an acceptable
`subject_token` for this version of the profile; presenting one at the
transaction endpoint returns once this profile defines its own
`subject_token_type` and presentation binding for the Chain
Presentation the cross-organizational delegation profile serializes
({{I-D.draft-mcguinness-oauth-mission-cross-org-delegation}}).

The TAS authenticates the Presenting Client and validates the
challenge exactly as
{{I-D.draft-rosomakho-oauth-txn-challenge}} Sections 5.1 and 4.6
require. This profile adds, in order:

1. validating `subject_token`'s audience against the challenge's `iss`
   and its `cnf` against the proof of possession presented on this
   request, establishing that the presented Mission-bound access token
   was issued for the challenged resource and is held by the party
   presenting the challenge;
2. requiring exact equality between the challenge's `mission` and
   `subject_token`'s `mission` invariants;
3. establishing that the challenge's `authorization_details` is within
   `subject_token`'s Authority Set under the subset rule
   ({{I-D.draft-mcguinness-oauth-mission}}) and applies to the
   challenge's `iss` and resource;
4. enforcing `requires_action_approval` and destination resource
   policy;
5. obtaining or resolving a governed approval from an acceptable
   independent Approver or policy authority, bound to `txn`, the
   operation identity, `parameter_digest`, the resource, the Mission,
   the destination-local subject and, where the Origin Principal
   profile applies
   ({{I-D.draft-mcguinness-oauth-mission-cross-domain}}), the
   issuer-qualified origin principal, and the presenter key;
6. verifying the approval's status, scope, grant time, maximum age,
   and `approved_until`; and
7. running a fresh authorization decision using the verified approval
   as context together with current Mission state, `subject_token`
   validity, client and key binding, resource policy, and the concrete
   parameter inputs or attributes; the decision consumes the
   destination-local subject and, where present, the issuer-qualified
   origin principal as distinct inputs and revalidates their current
   mapping and entitlement.

Any denial ends the flow. Completion of step 6 alone MUST NOT trigger
token issuance and MUST NOT bypass step 7.

An approval obtained under step 5 SHOULD carry the shape of an
AuthZEN Access Request and Approval Profile approval object
({{ARAP}}); steps 6 and 7 mirror the checks the AuthZEN binding
applies to that object when it is presented as decision input, never
as a bearer bypass ({{I-D.draft-mcguinness-mission-authzen}}). Where
an Approval Governance Record backs the decision, that record is the
authoritative provenance of who approved and under what authority
({{I-D.draft-mcguinness-mission-approval-governance}}); this document
neither restates nor requires it.

## Subject Establishment {#subject-establishment}

The destination-local subject the flow binds, from the approval of
step 5 through the token of {{transaction-token}}, is established at
admission and revalidated at completion:

1. verify `subject_token` and establish its issuer-qualified
   identity, the pair of its `iss` and its `sub`;
2. establish the destination-local subject from that identity under
   the configured namespace policy of {{subject-namespaces}};
3. where the Origin Principal profile applies
   ({{I-D.draft-mcguinness-oauth-mission-cross-domain}}), co-resolve
   that subject with `mission.subject` under the profile's
   destination mapping rule; a conflict between them MUST be refused;
4. persist, on the pending workflow, the issuer-qualified source
   identity, the pinned destination-local subject, the origin
   principal where present, and the identity and version of the
   namespace policy that produced the pinned subject;
5. at completion, resolve the current namespace policy against the
   persisted source identity again and require it to produce the
   pinned subject; a policy that no longer exists, no longer accepts
   the identity, or produces any other value MUST be refused; and
6. only then run the fresh decision of step 7 and mint the token.

### Subject Namespaces {#subject-namespaces}

A TAS MAY restrict which `subject_token` issuers and subject
namespaces it accepts. Whether an accepted issuer shares this
Authorization Server's subject namespace is configured trust policy,
never inferred from request data. For a same-namespace issuer the
verified `sub` is the destination-local subject, unchanged. For every
accepted foreign namespace the TAS MUST apply an injective,
issuer-qualified mapping from the pair (`iss`, `sub`) into its own
namespace and use the mapped value. A missing, ambiguous, stale, or
disabled mapping MUST be refused rather than guessed.

## Two-Phase Expiry {#two-phase-expiry}

The challenge's `exp` bounds initial admission only: the Presenting
Client MUST submit before it expires, and a late challenge is refused
into a new workflow, never revived into an existing one. On
acceptance, the pending workflow, identified by the upstream
`transaction_authorization_id` (correlated to the ARAP task handle
where ARAP backs the approval,
{{I-D.draft-mcguinness-mission-authzen}}), carries its own
deployment-declared lifetime: the upstream `expires_in` of
{{I-D.draft-rosomakho-oauth-txn-challenge}} Section 5.2. Steps 6 and 7
of {{challenge-redemption}} revalidate current Mission state,
`subject_token` validity, approval freshness, client and key binding,
entitlement, and policy, fresh at the moment they run; the
transaction token's `exp` is bounded by those inputs and the pending
workflow's remaining lifetime, never by the already-consumed
challenge `exp` ({{transaction-token}}).

Repeated initial submission of the same `(challenge issuer, challenge
jti, client, cnf)` MUST return the existing pending workflow or fail
deterministically; it MUST NOT create a second workflow for the same
admitted challenge.

The set of acceptable Transaction Authorization Servers,
Challenge-Issuing Resources, and approval authorities is deployment
and federation policy, never taken from an untrusted request claim.
Key discovery rides the upstream metadata
({{I-D.draft-rosomakho-oauth-txn-challenge}}): a Challenge-Issuing
Resource publishes its challenge-signing keys at
`txn_challenge_jwks_uri` with
`txn_challenge_signing_alg_values_supported`, and the TAS resolves a
challenge issuer's keys there and nowhere else; a client discovers
the TAS through `transaction_authorization_endpoint` in Authorization
Server metadata. A TAS MAY
be the Mission Issuer itself or an Authorization Server deployed
separately from it; a resource trusts a TAS's token-signing key and
policy role through pre-established federation metadata, not through
anything the request asserts about itself.

# Transaction Token {#transaction-token}

On permit, the Transaction Authorization Server issues a JWT with
protected header `typ` `mission-txn-token+jwt` ({{iana}}). This is its own
JWT access-token profile with the complete validation semantics below;
it does not conform to {{RFC9068}}, and a Resource Server that
recognizes only `at+jwt` correctly rejects it as unknown. A deployment
wanting RFC 9068 interoperability instead relies on the upstream `txn`
claim carried by an ordinary JWT access token
({{I-D.draft-rosomakho-oauth-txn-challenge}} Section 6); that is not
this profile's shape. Its claims:

`iss`, `iat`, `exp`, `jti`:
: REQUIRED, standard JWT claims {{RFC7519}}.

`aud`:
: REQUIRED. A singleton, exactly the verified challenge's `iss`.
  Never a list and never any other value.

`sub`:
: REQUIRED. The destination-local subject, derived from the verified
  issuer-qualified identity of the presented `subject_token` under
  the establishment and revalidation rules of
  {{subject-establishment}} and the namespace contract of
  {{subject-namespaces}}: the pinned subject those rules produced at
  admission and reconfirmed at completion, never a value derived a
  second way at minting time. Where the Origin Principal profile
  applies ({{I-D.draft-mcguinness-oauth-mission-cross-domain}}), the
  issuer-qualified origin principal travels in `mission.subject`,
  alongside the local subject and never in place of it. Never the
  Approver.

`client_id`:
: REQUIRED. The client authenticated at the transaction endpoint
  ({{RFC8693}} Section 4.3). The upstream client and the executing
  agent MAY be different parties; this claim identifies the former.

`act`:
: REQUIRED whenever requester or actor context existed on
  `subject_token` or the challenge; otherwise absent. Present under
  the same conditions and structure as the issuance profile's `act`
  chain ({{I-D.draft-mcguinness-oauth-mission}}, Section "Delegation
  Within a Mission"; the OAuth Actor Profile
  {{I-D.draft-mcguinness-oauth-actor-profile}} remains the structural
  reference). The chain is attribution, never authority: it names
  who acted, for audit and as policy input, and grants nothing by
  itself. Actor proofs and receipts, where a deployment carries them,
  stay off this token; they ride `subject_token` or the delegation
  context the TAS verified at redemption ({{challenge-redemption}}),
  never the transaction token itself.

`txn`:
: REQUIRED. Copied unchanged from the verified challenge.

`authorization_details`:
: REQUIRED. The exact permitted entry, never wider than the
  challenge, `subject_token`'s Authority Set, or the fresh decision of
  {{challenge-redemption}}.

`parameter_digest`:
: REQUIRED. Copied only after recomputation and verification against
  the challenge's value.

`mission`:
: REQUIRED. The Mission claim's profiled members, value-equal to the
  verified challenge's `mission`. The transaction token is a freshly
  signed JWT; this is value equality of the profiled members, not
  byte preservation of a carried artifact.

`cnf`:
: REQUIRED. Bound to the verified presenter key, DPoP {{RFC9449}}
  (`cnf.jkt`) or mTLS {{RFC8705}} (`cnf.x5t#S256`), equal to the
  challenge's `cnf` and the proof verified at redemption.

The token MUST NOT carry a generic `approval` object, a `single_use`
boolean, raw rendered approval text or action parameters, roles or
relationships conferred by an approval workflow, or evidence objects
whose lifecycle and disclosure rules belong to the evidence and audit
profiles. It MUST NOT carry a refresh token, a delegation grant, or
token-exchange input, and MUST NOT be accepted as a general
Mission-bound access token for any purpose beyond the challenged
operation.

The token's `exp` MUST be no later than the earliest of: approval
freshness or `approved_until`; `subject_token`'s own validity; Mission
expiry; the pending workflow's remaining lifetime
({{two-phase-expiry}}); and deployment maximum. It is never bounded by
the already-consumed challenge `exp`. A short token lifetime limits
stale-policy and revocation exposure but does not replace the
point-of-use state checks {{offline-verification}} requires.

# Offline Verification and Execution {#offline-verification}

The Challenge-Issuing Resource verifies the transaction token locally,
without calling the Transaction Authorization Server on the request
path:

1. exact token `typ`, trusted issuer and signature, intended `aud`,
   `iat` and `exp`, and token class;
2. `cnf` proof by the current presenter;
3. equality of `txn`, the `mission` invariants, the operation
   `authorization_details`, and the recomputed `parameter_digest`
   with the pending operation;
4. origin principal, local subject, and actor consistency under the
   principal profile in effect
   ({{I-D.draft-mcguinness-oauth-mission-cross-domain}});
5. current local policy, principal entitlement, and that the
   challenged operation remains within the Mission's current
   Effective Authority Set, observed through a full audience-scoped
   Mission Status Response, containment- and discharge-aware issuer
   token introspection, or an equivalent authenticated, versioned
   authority source that reflects every relevant `authority_changed`
   update, each within its declared freshness bounds; the Status
   List MAY serve as a lifecycle prefilter only and MUST NOT alone
   satisfy this step, since its two-bit reliance state does not
   observe containment or discharge
   ({{I-D.draft-mcguinness-oauth-mission-status}},
   {{I-D.draft-mcguinness-oauth-mission-signals}},
   {{I-D.draft-mcguinness-mission-runtime}}); and
6. atomic first use of the resource-scoped `txn` in the consumption
   domain; a second, distinct token `jti` presented for an
   already-consumed `txn` is the same replay and MUST be refused,
   never executed as a new attempt.

The Effective Authority Set belongs to the Mission and is evaluated
at the point of use, not carried by the token: an `active` Mission
observed before containment or discharge narrowed the set does not
satisfy step 5. The transaction token transports a bounded,
action-bound approval and never substitutes for the Mission's current
authority, applicable Resource policy, or consumption state.

Consumption of `txn` MUST be linearizable across every replica capable
of executing the same operation, meeting the metering companion's
Exact enforcement profile
({{I-D.draft-mcguinness-mission-metering}}): the record commits before
the irreversible effect, or atomically with it where the operation
store supports that transaction. If the consumption store is
unavailable, the resource MUST fail closed for this profile.

`txn` identifies the resource transaction and is the atomic
consumption key; challenge `jti` identifies one admission into a
workflow; `transaction_authorization_id` (or the ARAP task handle
backing it) identifies one pending workflow; token `jti` identifies
one issuance from that workflow, not the one execution; and the
Operation Profile's idempotency key identifies one effect. At most one
authorization result exists per accepted workflow: repeated polling
after a decision returns the same token or result stably, and a TAS
MUST NOT mint a second token, under a different `jti`, for a `txn`
whose workflow already produced one. An ambiguous retry looks up the
prior result along this chain, from `txn` and token `jti` to the
workflow to the idempotency key, and the resource returns
`duplicate_suppressed` as the runtime profile defines it
({{I-D.draft-mcguinness-mission-runtime}}) rather than executing
again. A genuinely new attempt requires a new challenge, a new
workflow, a new token, and a new idempotency key.

# Evidence and Audit {#evidence-audit}

This document defines no evidence object of its own. The approval
service or TAS records Approval Governance and, where configured,
Consent Evidence state
({{I-D.draft-mcguinness-mission-approval-governance}},
{{I-D.draft-mcguinness-oauth-mission-consent-evidence}}); the fresh
decision and the executing resource emit Decision Evidence and
Execution Evidence under the runtime evidence profile
({{I-D.draft-mcguinness-mission-runtime-evidence}}), which a Mission
Receipt may summarize ({{I-D.draft-mcguinness-mission-runtime}}); and
where durable independent proof is required, the audit profile
registers the relevant evidence
({{I-D.draft-mcguinness-mission-audit}}). These records correlate by
the Mission reference, `txn`, the transaction token's `jti`,
`parameter_digest`, and idempotency identity. None of them ride in the
transaction token.

The Transaction Authorization Server MUST be able to show that its
fresh decision relied on a valid approval. A resource's own
authorization decision rests on the trusted, typed transaction token
plus the current local checks of {{offline-verification}}, never on
parsing an arbitrary evidence blob presented at the request.

This profile defines no Continuation Transport and no continuity
guarantee of its own
({{I-D.draft-mcguinness-oauth-mission-continuation}}). Its token is a
bounded, single-use authorization artifact. The token carries `txn`,
its own `jti`, and `parameter_digest`; those correlate the runtime
evidence profile's execution-time evidence to this hop
({{I-D.draft-mcguinness-mission-runtime-evidence}}). The Operation
Profile's idempotency identity correlates the effect and is not
carried by the token.

# Failure Semantics {#failure-semantics}

The pending and polling states and errors of
{{I-D.draft-rosomakho-oauth-txn-challenge}} Section 5.3
(`authorization_pending`, `slow_down`, `access_denied`,
`expired_token`) apply unchanged; this document defines no second
error vocabulary for that surface. Initial validation only admits a
workflow: only the fresh decision at {{challenge-redemption}}
completion is final, and an admitted workflow MUST still refuse there
when a fresh input no longer holds.

No or expired action approval:
: Deny. The workflow MAY return or request another approval.

Approval granted but current policy or entitlement denies:
: Deny. The approval is not a bypass of step 7 of
  {{challenge-redemption}}.

Parameter, resource, Mission, principal, presenter, or audience
mismatch:
: Terminal refusal for that token or challenge.

Stale or unavailable required state:
: Fail closed. Retry only according to the declared state-recovery
  policy.

Consumed token:
: Return the prior idempotent result via the relationship map of
  {{offline-verification}} when the Operation Profile allows it;
  otherwise `duplicate_suppressed`
  ({{I-D.draft-mcguinness-mission-runtime}}). Never execute again.

A challenge or token with an unknown `typ` or unrecognized
`authorization_details` semantics:
: MUST be rejected outright, never parsed on a best-effort basis.

# Security Considerations {#security-considerations}

The security considerations of the issuance profile
{{I-D.draft-mcguinness-oauth-mission}} and the runtime profile
{{I-D.draft-mcguinness-mission-runtime}} apply.

Challenge and credential substitution:
: A challenge is scoped to one resource, one operation, and one
  presenter key. {{challenge-redemption}}'s step 1 (`subject_token`
  audience and `cnf`), step 2 (exact `mission` equality), and step 3
  (authority subset) together close the case of a challenge issued
  for one resource being redeemed for another's benefit, or a
  Mission-bound access token issued for a different resource or held
  by a different party being accepted as this profile's credential; a
  TAS that skips any of the three can be induced to authorize an
  operation the verified authority never covered.

Approval replay across operations:
: An approval is bound to `txn`, the operation identity, and
  `parameter_digest`. A TAS that treats a completed approval as
  standing authority for a different transaction, rather than
  re-running step 7 fresh for each redemption, reintroduces the
  bearer-grant failure mode this profile exists to close.

Transaction Authorization Server compromise, and pending-workflow exposure:
: The TAS is the component every resource on the deployment trusts to
  have run a genuine fresh decision. Its compromise mints tokens for
  operations no human or policy authority approved, and a long-lived
  pending workflow widens the window in which `subject_token`, its
  key, or the approval authority can be compromised before that
  decision runs. Deployments SHOULD isolate the TAS's signing key and
  decision logic from the agent's own execution environment, matching
  the runtime profile's mediated-custody posture, SHOULD bound the
  pending workflow's declared lifetime ({{two-phase-expiry}}) to what
  genuine approval latency requires, and SHOULD bound token lifetime
  tightly enough that a detected compromise's blast radius is the
  outstanding token population, not the Mission's full remaining
  lifetime.

Consumption-store availability, and the fail-closed posture generally:
: The at-most-once property this profile claims exists only while the
  consumption store meets the Exact enforcement profile of
  {{I-D.draft-mcguinness-mission-metering}}; a deployment that
  degrades to a merely local cache during partition no longer has
  that property and MUST NOT claim it. Every failure path of
  {{failure-semantics}} resolves to denial, refusal, or a fail-closed
  state, never silent pass-through; an implementation that treats an
  unrecognized `typ`, an unverifiable approval, or an unreachable
  consumption store as permission is nonconformant.

# Privacy Considerations {#privacy-considerations}

Raw action parameters and approval detail stay off the transaction
token by design: the token carries `parameter_digest`, not the
parameters, and no `approval` object. A Transaction Authorization
Server that needs more than the digest to decide or render obtains
raw values through the `reason_uri` retrieval of
{{resource-challenge}}, never by widening the token.

Digest-plus-attributes authorization lets a TAS decide without
learning more than the deployment chooses to disclose over that
channel; a deployment SHOULD weigh what attributes it discloses to
the TAS against what the decision genuinely requires. Presenting
`subject_token` discloses to the TAS that the Presenting Client holds
Mission-bound authority at the challenged resource; the TAS already
is a party the deployment trusts with the fresh decision, so this is
not a disclosure beyond what {{challenge-redemption}} already requires
it to evaluate.

`txn` and the transaction token's `jti` are a correlation surface: any
party observing both a challenge and its redeemed token can link one
resource transaction to one TAS decision. This is the profile's
intended accountability property, not an incidental leak, but a
deployment SHOULD scope `txn` values to the minimum lifetime and
audience that {{resource-challenge}} and {{offline-verification}}
require.

# IANA Considerations {#iana}

## Media Type Registration

IANA is requested to register one media type per {{RFC6838}}. Its
JOSE protected `typ` is the registered media type with the
`application/` prefix omitted where JWS permits the shortened form; an
HTTP `Content-Type` carries the full media type. This document
registers no new claim, parameter, or metadata member: `txn`,
`mission`, `cnf`, `parameter_digest`, `subject_token`, and
`authorization_details` are each defined by the document that owns
them and are reused here unchanged. This document does not register a
second challenge media type; the challenge keeps the upstream `typ`
`txn-authz-challenge+jwt` unchanged.

### application/mission-txn-token+jwt

- Type name: application
- Subtype name: mission-txn-token+jwt
- Required parameters: none
- Optional parameters: none
- Encoding considerations: 8bit; JWS Compact Serialization
  {{RFC7515}}
- Security considerations: see {{security-considerations}}
- Interoperability considerations: see this document
- Published specification: this document
- Applications that use this media type: Mission-Bound Authorization
  Challenge-Issuing Resources, Transaction Authorization Servers, and
  Presenting Clients
- Fragment identifier considerations: not applicable
- Additional information:
  - Deprecated alias names for this type: none
  - Magic number(s): none
  - File extension(s): none
  - Macintosh file type code(s): none
- Person & email address to contact for further information:
  Karl McGuinness <public@karlmcguinness.com>
- Intended usage: COMMON
- Restrictions on usage: none
- Author: IETF
- Change controller: IETF

The transaction token's registered semantics are sender-constrained,
single-audience, and single-use. A Resource Server that recognizes
`typ` `mission-txn-token+jwt` enforces exactly those properties regardless
of any member on the token; this document defines no `single_use`
member anywhere, because single use is semantic to the type itself.

# Mission Substrate {#mission-substrate}

This document is defined against the Mission model rather than
against OAuth 2.0 mechanics: it is a substrate-neutral consumer, and
this section is its consumption declaration under the rule of Mission
Substrate Requirements ({{I-D.draft-mcguinness-mission-substrate}})
that a substrate-neutral profile declare the kernel functions and
optional capabilities it consumes.

From the contextual-governance kernel it consumes the Mission
identifier and issuer, the kernel's Mission Reference and Controller
carried in the `mission` claim, and the active and non-active gate the
fresh decision of {{challenge-redemption}} observes.

Its declaration against the optional capabilities:

| Capability | Consumption | Scope of consumption |
| --- | --- | --- |
| Lifecycle-Gated Authorization | required | A transaction token is minted only from a Mission the TAS observed `active`; this document adds no second gate to the issuance profile's ({{I-D.draft-mcguinness-oauth-mission}}) |
| Structured Authority | consumed | The challenge and token's `authorization_details` entry is evaluated against the verified Authority Set under the subset rule ({{challenge-redemption}} step 3) |
| State-Observable | consumed | Offline verification observes current Mission state within its declared freshness bound ({{offline-verification}}); establishing that state is the runtime and Status profiles' concern |
| Monotonic Derivation | not consumed | A transaction token narrows nothing durable: it is a bounded, single-use permit, not a Mission, Child Mission, or successor |
| Credential-Bound | required and produced | `subject_token` MUST already be sender-constrained by `cnf`, and the minted transaction token is itself a `cnf`-bound artifact ({{transaction-token}}); this profile both requires and produces the capability |
| Authorized Context Correlation | not consumed | The Presenting Client authenticates directly with its own `cnf` proof; no issuer-established correlation joins a separate credential to the Mission here |
| Independently Verifiable | produced | Offline verification of {{offline-verification}} independently verifies the transaction permit, the transaction binding, the carried authority, and the presenter binding, all as of issuance; it is explicitly not independent verification of Mission approval history or current Mission state |
| Portable Evidence | not consumed | This document defines no evidence artifact of its own; the evidence plane of {{evidence-audit}} carries the durable account |
{: title="Transaction authorization capability consumption"}

Beyond the kernel, this profile also consumes companion capabilities
outside the substrate contract: the metering companion's Exact
enforcement profile for atomic `txn` consumption and the Mission
Status surface for freshness-bounded state observation (both
{{offline-verification}}), and, conditionally, the cross-domain Origin
Principal profile for the invariant origin principal
({{resource-challenge}}). All three are consumed, none produced.

These consumed capabilities join conjunctively, at the runtime
decision, with the Mission's current Effective Authority Set and any
applicable cumulative-consumption or stateful operational gate
({{I-D.draft-mcguinness-mission-runtime}}, Section "The Runtime
Decision"): the fresh, action-bound permit this profile mints is one
more independent gate, never a substitute for the others.

The carrier-side dual of this declaration, what a protocol binding
must provide for another substrate to host this profile's flow, is
{{carrier-binding-floor}}.

# Carrier Binding Floor {#carrier-binding-floor}

The wire mechanics of this document are one discharge of a
carrier-neutral flow: {{mission-substrate}} declares what this profile
consumes from the Mission kernel, and this section declares what the
flow itself requires, in three layers. {{transaction-invariants}}
states the invariants that make the flow safe on any substrate.
{{carrier-requirements}} states the slots a protocol binding MUST
provide to carry them. {{oauth-discharge}} names this document's own
discharge of each slot. A binding that cannot provide a slot does not
host this profile: absence is fail-closed, and there is no partial
hosting.

## Transaction Invariants {#transaction-invariants}

Four roles participate: the Challenging Resource, which owns the
operation and its state; the Transaction Authority, which admits the
workflow and mints the result; the Presenter, which holds the
committed key; and the Approver, whose governed decision is input to
the Transaction Authority's own. The invariants bind commitments, not
member names:

1. Every commitment the challenge carries, to the operation, to the
   concrete parameters, to the Mission context, and to the presenter
   key, is derived by the Challenging Resource from its own
   authoritative state; a caller-supplied replacement for any of them
   is never accepted.
2. Admission and completion are distinct: challenge expiry bounds
   admission alone, the pending workflow has its own declared
   lifetime, and completion runs a fresh authorization decision to
   which the approval is input and never a bypass. A step-up
   authentication context and durable governance state never issue
   alone.
3. At most one result exists per transaction instance, across every
   workflow that references it, and repeated polls return that result
   stably.
4. The result is single-use by class, sender-constrained to the
   committed key, audience-restricted to the Challenging Resource,
   carries no approval object, no evidence, and no raw parameters,
   and is never acceptable as a general credential of the substrate.
5. Immediately before execution, the Challenging Resource
   re-establishes, within declared freshness bounds, current Mission
   lifecycle state, current authority, current entitlement, and its
   own policy, and consumes the transaction instance atomically,
   linearizably across every replica capable of executing the
   operation, failing closed when either the state source or the
   consumption store is unavailable. A result minted before a
   termination or a narrowing never executes after it.
6. The result's subject is the destination-local subject; the
   issuer-qualified origin principal travels alongside it, never in
   place of it; actor context is attribution, never authority.
7. Refusals are typed, and pending, denied, and expired workflow
   states are distinguishable, so a refused caller can re-plan
   without receiving a map of the environment.

## Carrier Requirements {#carrier-requirements}

A protocol binding provides one slot for each requirement below. Each
slot is named by function; the binding supplies the substrate-native
carrier.

Challenge carrier:
: A resource-authenticated artifact for the commitments of
  {{transaction-invariants}}, whose signing keys a verifier resolves
  from the issuer's published metadata and nowhere else; one issuer's
  key never verifies another issuer's challenge.

Operation identity:
: A versioned operation identifier scoped to the Challenging
  Resource, validated as a complete entry and yielding a typed
  operation; a human-readable member is never authorization input; a
  superseded version resolves only for workflows admitted under it.

Parameter commitment:
: The runtime profile's `parameter_digest`
  ({{I-D.draft-mcguinness-mission-runtime}}), adopted into the
  binding's native commitment, or a verifiable equivalence to it. A
  binding never defines a second canonicalization.

Workflow handle:
: A transaction-instance identifier with its own lifetime, distinct
  from any content address, under which repeated initial submission
  of one (challenge issuer, challenge identifier, client, presenter
  key) returns the existing workflow or fails deterministically.

Result class:
: An artifact class every verifier can distinguish from each of the
  substrate's general credential classes, carrying the single-use
  semantics of invariant 4 on the class itself, never on a member.

Possession:
: Proof of the committed presenter key at redemption and at
  execution, with the execution proof bound to the presented artifact
  itself, not only to the key.

Current-state source:
: An authoritative source for the execution-time checks of invariant
  5, with a declared freshness bound, available to the Challenging
  Resource unconditionally on the execution path.

Failure vocabulary:
: A mapping of pending, denied, and expired workflow states onto the
  substrate's native vocabulary; the binding defines no second
  vocabulary.

## OAuth Discharge {#oauth-discharge}

| Requirement | This document |
| --- | --- |
| Challenge carrier | The signed challenge of {{resource-challenge}}, keys via `txn_challenge_jwks_uri` |
| Operation identity | The `authorization_details` entry `type` and Operation Profile rules of {{resource-challenge}} |
| Parameter commitment | `parameter_digest`, carried and verified per {{resource-challenge}} and {{offline-verification}} |
| Workflow handle | `transaction_authorization_id` and the admission rules of {{two-phase-expiry}} |
| Result class | `mission-txn-token+jwt` per {{transaction-token}} |
| Possession | `cnf` under DPoP or mutual TLS, including `ath`, per {{challenge-redemption}} and {{offline-verification}} |
| Current-state source | Offline verification step 5 of {{offline-verification}}: the Mission Status surface, the Status List, or issuer introspection within declared freshness bounds |
| Failure vocabulary | The upstream vocabulary applied unchanged per {{failure-semantics}} |
{: title="OAuth discharge of the carrier requirements"}

The Mission Context Binding for AAuth
({{I-D.draft-mcguinness-mission-aauth}}) records, informatively, the
native and missing status of each requirement against AAuth and R3
({{I-D.draft-hardt-aauth-r3}}); it does not claim the capability.

# Conformance {#conformance}

A **Transaction Authorization Server**:

- authenticates the Presenting Client and validates the challenge as
  {{I-D.draft-rosomakho-oauth-txn-challenge}} requires, then completes
  every added step of {{challenge-redemption}} in order and refuses on
  any failure;
- MUST NOT let completion of the approval step alone trigger token
  issuance or bypass the fresh decision;
- mints the transaction token only with the claims and MUST NOT list
  of {{transaction-token}}; and
- publishes its signing keys and accepted challenge issuers as
  deployment and federation metadata, resolving each challenge
  issuer's keys through its published `txn_challenge_jwks_uri` and
  never accepting either from the request.

A **Challenge-Issuing Resource**:

- derives the Mission-profiled challenge claims from the request and
  the verified credential, never from a client-supplied value
  ({{resource-challenge}});
- verifies the transaction token locally under
  {{offline-verification}} without a request-path call to the TAS;
  and
- consumes `txn` atomically and linearizably across every replica,
  failing closed when the consumption store is unavailable.

A **Presenting Client**:

- proves possession of the challenge's and token's confirmation key
  at redemption and at execution; and
- treats the transaction token, not the approval, as authority: it
  does not construct or assert an approval object of its own.

Positive and negative conformance vectors exist for: a valid
challenge, `subject_token` presentation, approval, fresh decision, and
one execution; delegated constraint preservation and an attempted
removal of `requires_action_approval`; step-up presented without
transaction approval; an approval valid for a changed amount,
recipient, resource, action, Mission, destination-local subject,
origin principal, actor, audience, or presenter key; an approval
complete but Authority Set, entitlement, or resource policy denying;
a missing or changed `parameter_digest` and a different
canonicalization; a pending
workflow that outlives its challenge and is later approved; repeated
initial submission of the same challenge returning one workflow;
challenge replay, single-replica token replay, and two distinct token
`jti` values presented for one `txn`; an ambiguous first execution
followed by an idempotent retry; an expired challenge, pending
workflow, `subject_token`, or transaction token; a `subject_token`
valid for a different resource audience or an unmatched `cnf`; an
untrusted resource, TAS, or approval authority; an arbitrary signed
JWT or an ordinary Mission token presented as a transaction token; a
privacy projection showing raw parameters and approval detail absent
from the token; and evidence correlation from challenge and decision
through exactly one execution or terminal refusal.

# Acknowledgments
{:numbered="false"}

This document is part of the Mission-Bound Authorization work and
profiles the OAuth transaction authorization challenge for
cross-organizational, execution-time approval.
