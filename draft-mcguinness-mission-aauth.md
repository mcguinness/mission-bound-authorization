---
title: "Mission Context Binding for AAuth"
abbrev: "Mission AAuth"
category: std

docname: draft-mcguinness-mission-aauth-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
keyword:
 - mission
 - agent
 - authorization
 - aauth
 - person server
 - governance
venue:
  github: "mcguinness/mission-bound-authorization"
  latest: "https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-aauth.html"

author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com

normative:
  I-D.draft-hardt-oauth-aauth-protocol:
    title: "AAuth Protocol"
    target: https://dickhardt.github.io/AAuth/draft-hardt-oauth-aauth-protocol.html
    author:
      -
        ins: D. Hardt
        name: Dick Hardt
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
  I-D.draft-mcguinness-oauth-mission-transaction-authorization:
    title: "Mission Transaction Authorization Profile for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-transaction-authorization.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-hardt-aauth-r3:
    title: "AAuth Rich Resource Requests (R3)"
    target: https://dickhardt.github.io/AAuth/draft-hardt-aauth-r3.html
    author:
      -
        ins: D. Hardt
        name: Dick Hardt
    date: 2026
  I-D.draft-mcguinness-aauth-mission-expiry:
    title: "AAuth Mission Expiry"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-aauth-mission-expiry.html
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

--- abstract

AAuth defines missions as optional, immutable authorization contexts
for agent governance at a Person Server.  A mission is approved through
AAuth's native propose, clarify, and approve interaction, is identified
by the native `approver` and `s256` reference, and accumulates an
ordered mission log.  This document describes how those native
facilities realize a Mission Context binding without adding a second
mission identifier, a portable authority language, or new AAuth wire
members.

This binding preserves AAuth's separation between contextual governance
at the Person Server and deterministic resource authorization through
scopes, resource tokens, resource and Access Server policy, and
optionally R3.  It also identifies where active-state issuance gating is
structural and where a mission reference is only advisory context.

--- middle

# Introduction

The AAuth protocol {{I-D.draft-hardt-oauth-aauth-protocol}} gives agents
independent cryptographic identities and supports five resource access
modes: identity-based, resource-managed, person-identity, Person Server
(PS)-asserted, and federated.  Agent governance is orthogonal to those
modes.

AAuth already defines the protocol elements needed for a durable Mission
Context:

- the agent proposes a natural-language mission to its PS;
- the PS and person can clarify and refine the proposal before approval;
- the approved mission blob is immutable and identified by the native
  pair of `approver` and `s256`;
- the agent names the mission when it requests a person token from its
  PS, and the PS stamps the mission into the person token, from where
  the resource and the PS copy it into every resource and auth token
  issued under it;
- the PS evaluates requests using the approved context and the ordered
  mission log; and
- a mission is either `active` or permanently `terminated`.

This document is a thin binding over those facilities.  AAuth's own
`expires_at` mission-blob member carries the expiry this binding
requires on every mission ({{lifecycle}}); this document defines no new
AAuth endpoint, header field, token claim, mission-blob member, or
lifecycle state at all.  It makes AAuth missions' security and
composition properties explicit and keeps an OAuth-specific authority
model from being imposed on them.

## Contextual Governance, Not Portable Authority

AAuth missions are not a machine-evaluable policy language.  The PS has
the approved mission description, the person's context, the agent's
justifications, prior decisions and actions, and a channel to the person
for clarification.  It uses that context to govern whether the agent's
next action is appropriate.

Deterministic authorization is separate.  A resource describes and
enforces its permissions through scopes, resource tokens, its own policy,
and, in federated deployments, Access Server policy.  An AAuth deployment
can additionally use R3 {{I-D.draft-hardt-aauth-r3}} for structured,
resource-owned authorization semantics.

Consequently, this binding does not define an Authority Set, translate
mission tools into authorization details, or require one resource's
authorization to be a subset of another's.  Each resource decision is
made in that resource's vocabulary and at its own policy decision point.
The PS applies the further contextual governance constraint when it is
on the authorization path.

## Scope

This document specifies:

- how an AAuth mission is identified and bound to an agent;
- which AAuth approval and lifecycle events form the Mission Context;
- how a PS applies the active-state gate to its own endpoints and to
  authorizations that it brokers;
- how the native mission reference propagates without exposing the
  mission blob; and
- the resulting security, privacy, audit, and compromise properties.

This document does not specify general-purpose mission management,
administrative termination, delegation-tree queries, portable evidence,
or deterministic cross-resource permission semantics.  Those are
possible AAuth companion specifications rather than requirements of this
binding.

# Status: An Optional Profile {#doc-status}

<!-- family-status: BEGIN (generated from family-manifest.json; exact-matched by scripts/check-family-manifest.mjs) -->
Role: adapter-binding. Spec maturity: experimental. Maintenance: frozen-until-upstream-release.
Implementation: not yet in the conformance ledger (conformance-manifest.json).
Adopt when: The substrate is AAuth: Mission context on its native propose/approve flow.
Requires: Mission Substrate Requirements.
<!-- family-status: END -->

# Conventions and Terminology {#conventions-and-terminology}

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL
NOT**, **SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **NOT RECOMMENDED**,
**MAY**, and **OPTIONAL** in this document are to be interpreted as
described in BCP 14 when, and only when, they appear in all capitals as
shown here.

This binding tracks the AAuth editor's copy as revised by its
person-token change (the -11 revision in preparation).

This document uses the AAuth terms *agent identifier*, *Person Server*,
*mission blob*, *mission reference*, *resource token*, *auth token*,
*approved tools*, *mission log*, *person token*, and the `mission_s256`
claim as defined by {{I-D.draft-hardt-oauth-aauth-protocol}}.

For this binding:

Mission Context:
: The immutable approved mission blob, its native mission reference, its
  current active or terminated state, and the ordered mission log used
  by the PS when governing an agent's work.

Controlling authority:
: The PS identified by the mission reference's `approver` value.  The PS
  performs approval, stores the mission context, evaluates governed
  requests, and controls the mission's active state.

Context propagation:
: Carrying the native mission reference across an AAuth interaction.  It
  does not by itself grant resource authority or prove that the receiving
  party evaluated the mission contents.

Issuance gating:
: Refusing to issue or broker a fresh credential when the referenced
  mission is not active.

# AAuth Mission Context Model

## Capability Model {#capability-model}

An AAuth mission, as this binding profiles it with AAuth Mission
Expiry, supplies every element of the contextual-governance kernel of
{{I-D.draft-mcguinness-mission-substrate}}; base AAuth alone supplies
all but the reliance bound.  The element-by-element mapping and the
formal capability claims are this binding's Mission Substrate
Statement ({{mission-substrate}}).  In AAuth's own terms:

Stable native reference:
: The pair `{approver, s256}` remains this binding's Mission Reference,
  with `s256` compared within the approver's namespace.  On the wire it
  travels as the flat `mission_s256` claim, with that namespace carried
  by the person token's `iss` and the resource token's `ps`.  No
  additional `mission_id` is needed or defined.

Controlling authority:
: `approver` identifies the PS responsible for approval and governance.
  It is not replaced by a separate Mission issuer field.

Agent binding:
: The approved mission blob contains the AAuth agent identifier in its
  `agent` member.  The PS MUST ensure that requests using the reference
  are made by that agent, except where AAuth expressly defines a
  parent-mediated or call-chaining relationship.

Immutable approved context:
: `s256` commits to the exact decoded bytes of the base64url `mission`
  member.  The blob is stored by the agent and PS rather than
  distributed to resources.

Explicit approval:
: The AAuth propose, clarify, and approve interaction produces the
  approved blob and reference.

Lifecycle gate:
: Only an `active` mission can support new governed requests.  A
  `terminated` mission is permanently non-active.

Bounded reliance:
: AAuth enforces `expires_at` on every PS decision path and caps every
  token carrying `mission_s256` to it ({{lifecycle}}); the PS still
  establishes `active` at decision time.

Context propagation:
: The signed `mission_s256` claim, carried by person, resource, and
  auth tokens, carries only the reference.  Support varies by resource
  access mode as described in {{access-modes}}.

Ordered governance record:
: The PS maintains the mission log and evaluates new governed requests
  in the context of that history.

Structured Authority, Monotonic Derivation, Independently Verifiable,
and Portable Evidence are not baseline properties of this binding;
{{mission-substrate}} records the formal claims.  A companion protocol
can supply one or more of those capabilities without changing the
meaning of the AAuth mission blob.

## Native Reference and Exact-Byte Commitment {#reference}

The mission reference is exactly the AAuth pair:

~~~ json
{
  "approver": "https://ps.example",
  "s256": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
}
~~~

The PS's approval envelope carries `s256` alongside a `mission` member
that is the base64url encoding, without padding, of the exact bytes it
persists as the mission blob.  The agent decodes `mission` to recover
those bytes.  AAuth makes verifying `s256` against the decoded bytes a
SHOULD before first use; a Mission Context Agent MUST verify it before
any governed use, and MUST preserve the decoded bytes exactly.  Parsing
and reserializing the JSON can change the bytes and therefore MUST NOT
be used to reproduce the committed blob.

The reference simultaneously provides stable identification and an
integrity commitment.  This binding does not add `intent_hash`,
`authority_hash`, `proposal_hash`, or a second semantic projection.  Such parallel
commitments would create ambiguity about which object was approved and
would require implementations to keep multiple canonicalizations in
lockstep.

The reference does not authenticate itself when copied outside a
protected AAuth message.  It gains protocol integrity from the AAuth
message signature or signed token that carries it.  Implementations MUST
apply all AAuth signature, issuer, audience, proof-of-possession, and
request-context checks before relying on a received reference.

## Mission Blob {#blob}

The approved mission blob uses the members defined by AAuth, including
`approver`, `agent`, `approved_at`, and `description`, and optionally
`approved_tools` and `approved_resources`.  The blob carries AAuth's
`expires_at` member, which this binding requires on every mission
({{lifecycle}}).  This binding itself defines no additional members.
AAuth states that these member lists are a floor, not a closed set; a
reader MUST ignore a member it does not recognize.

The blob's `agent` value is an AAuth agent identifier.  It MUST NOT be
described or processed as an OAuth `client_id`.  The two identifiers have
different namespaces, discovery mechanisms, and key-binding properties.

The approved `description` expresses human intent and governance
context.  It is not a deterministic access-control policy.  The PS or
person can refine, constrain, or expand the proposed description during
review; the approved blob returned by the PS is the authoritative result.

### Approved Tools

`approved_tools` identifies agent tool invocations that do not require
a per-call decision at the PS permission endpoint.  Examples include a
tool call, a file write, or sending a message; a tool can invoke
remote infrastructure, so the exemption is from the per-call
permission request, not a locality claim.  The PS still uses the
mission context and mission log for governance: `approved_tools` is
structured PS-governance input, not portable resource authority.

An approved tool is not, by that fact alone, authority at a remote
resource.  This binding therefore does not map an approved tool name or
description to a resource identifier, scope, authorization detail, or
R3 operation.  Remote resource access follows AAuth's resource access
protocol and the resource's own authorization semantics.

# Protocol Binding

## Roles {#roles}

The AAuth roles map to the Mission Context model as follows:

| AAuth role | Mission Context responsibility |
|---|---|
| Agent | Proposes work, verifies and stores the approved blob, names the mission at person-token issuance, supplies justifications, and records actions as AAuth requires. |
| Person Server | Acts as controlling authority, conducts approval and clarification, stores state and the mission log, and governs requests on PS endpoints. |
| Person | Reviews, clarifies, approves, and accepts completion through the PS. |
| Resource | Defines and enforces its resource authorization; when mission-aware, preserves the native reference as AAuth specifies. |
| Access Server | Evaluates resource policy and issues auth tokens in federated access; it does not evaluate the private mission blob. |

No AAuth party becomes an OAuth client, Authorization Server, or Resource
Server merely by implementing this binding.

## Proposal, Clarification, and Approval {#approval}

The agent creates the Mission Context by sending an AAuth mission
proposal to the PS `mission_endpoint`.  The proposal contains the
natural-language description and can contain requested tools as defined
by AAuth.

The PS MAY defer the response while the person or another appropriate
decision-maker reviews the proposal.  AAuth clarification messages can
ask the agent for missing context or negotiate changes.  The agent MUST
NOT treat the proposal, a pending response, or a clarification exchange
as approval.

Approval occurs only when the PS returns the approval envelope: `s256`
and the approved mission blob as the base64url-encoded `mission`
member.  Before using the context, the agent MUST:

1. verify the AAuth response according to the base protocol;
2. decode `mission` and compute SHA-256 over the exact decoded bytes;
3. verify that the result equals the envelope's `s256` value;
4. verify that the blob's `approver` and `agent` members identify the
   approving PS and requesting agent; and
5. store the exact decoded bytes and native reference.

A failed check invalidates the approval response.  The agent MUST NOT
operate under the resulting reference.

## Governed Requests and Mission Log {#mission-log}

For every PS request seeking a positive governance decision under a
mission reference, the PS MUST verify that:

- it is the identified `approver`;
- the `s256` identifies a mission blob it approved;
- the authenticated agent is entitled to act in the referenced context;
  and
- the mission is `active`.

If any of these checks cannot be completed, including establishing the
mission's current state, the PS MUST fail closed and reject the
request.

Authenticated status, termination, denial, cleanup, and audit
operations defined by this binding's companions are not positive
governance decisions; they answer on a non-active mission as their
specifications define.

The PS then evaluates the request using the approved description, the
request's justification and other inputs, applicable person or
organization policy, and relevant prior entries in the mission log.  A
valid reference means that the context is identified and intact; it does
not require the PS to approve the request.

The PS MUST maintain the mission log as an ordered record of the AAuth
interactions defined to belong to the mission, including token requests,
permission decisions, audit records, interaction requests, and
clarification chats.  Log records SHOULD preserve sufficient correlation
data to associate each decision with its authenticated request and any
issued token without recording raw credentials.

The PS MUST protect the mission log's integrity, MUST restrict read
access to the person, the PS itself, and parties authorized under its
administrative policy, and MUST retain the log for a declared period
that extends beyond termination.

The mission log is complete only for PS-observed operations.
`approved_tools` activity the agent performs without a per-call PS
decision, and any other agent-side action, enters the log only as
agent-reported audit records; the PS MUST distinguish agent-reported
entries from PS-observed ones and MUST NOT represent the former as
the latter.  A counter or hash chain alone does not prove
completeness for activity that can occur without consuming it; a
deployment needing stronger completeness for local activity requires
a non-bypassable observation point.

The approved blob is immutable.  New facts, decisions, and actions are
appended to the log; they do not mutate or replace the committed blob.

## Deterministic Resource Authorization

A mission approval does not pre-authorize a portable set of remote
resource operations.  Deterministic resource authorization continues to
use the AAuth mechanisms appropriate to the access mode:

- the resource's identity-based policy;
- the resource-managed authorization result;
- scopes in resource and auth tokens;
- resource policy in PS-asserted access;
- Access Server policy in federated access; and
- optionally, resource-owned R3 vocabularies and requests.

The PS's governance decision is an additional contextual decision where
the PS is on the path.  It neither replaces the resource's deterministic
authorization nor proves that every resource independently enforces the
mission description.

No general subset relation is defined between successive or downstream
resource scopes.  In a call chain, a downstream resource can require an
operation that has no equivalent in the upstream resource's vocabulary.
The PS evaluates each governed hop against the mission context, while
each Resource or Access Server applies its own policy.

## Resource Access Modes {#access-modes}

Mission governance and resource access mode are independent.  The
security effect of a mission therefore depends on whether the PS is on
the authorization path.

| Resource access mode | Mission Context behavior |
|---|---|
| Identity-based | The resource authorizes the signed agent identity directly.  A mission reference can be sent to a mission-aware resource, but the PS does not gate that resource decision and the resource can ignore the reference. |
| Resource-managed | The resource manages authorization directly.  A mission reference can provide context, but the PS does not gate the resource's issuance or decision and the resource can ignore the reference. |
| Person-identity | The resource authorizes on the PS-issued person token's identity alone.  Person-token issuance is the PS's control point: mission-scoped via `mission_s256`, capped at one hour and by the mission's `expires_at`; the resource's own decision is not PS-gated. |
| PS-asserted | The resource token is presented to the PS, which evaluates the active Mission Context before it issues an auth token.  PS issuance gating is structural for a request whose resource token carries the mission's `mission_s256` claim ({{ref-propagation}}).  The resource still applies its own resource policy. |
| Federated | The PS evaluates the active Mission Context before it federates the request to the resource's Access Server and before returning the resulting auth token.  PS broker gating is structural under the same condition; the Access Server independently applies resource policy. |

In every mode, the PS MUST apply the active-state gate to its own
permission, audit, interaction, mission, and token operations when they
reference a mission, as required by AAuth, except that an
authenticated status or termination operation defined by a companion
returns terminal state instead.  In identity-based and
resource-managed access, that PS-local gate does not stop an agent from
making requests directly to a resource.  Deployments MUST NOT claim PS
issuance gating for those direct resource decisions.

A resource MUST NOT omit `mission_s256` from a resource token it issues
when the person token it verified carried one; AAuth makes a missing
claim a protocol violation rather than permitted ignorance.  An
implementation MUST NOT infer that a resource evaluated mission context
merely because a token carried the claim.  Even a mission-aware Resource
or Access Server receives only the reference and MUST NOT dereference it
to obtain the private mission blob.

## Transaction Authorization {#transaction-authorization}

This binding does not claim the transaction authorization capability.
The Carrier Binding Floor of
{{I-D.draft-mcguinness-oauth-mission-transaction-authorization}} names
the slots a binding must provide to host action-bound transaction
authorization, and several have no native home in AAuth or R3 today.
Consistent with this document's rule that it adds no new AAuth wire
members, it defines no extensions to close them.

| Requirement | Native today | Missing home |
| --- | --- | --- |
| Challenge carrier | The AAuth-Requirement challenge with a signed resource token | Members committing to the concrete parameters, the mission reference, and the presenter key |
| Operation identity | R3 vocabulary definitions, content-addressed | Definition versioning and supersession |
| Parameter commitment | The content-addressed R3 per-call document | A defined parameter-commitment member |
| Workflow handle | None: `r3_s256` is a content address, and intentionally identical calls share it | A transaction-instance identifier with its own lifetime and admission idempotency |
| Result class | None: the per-call result is an ordinary `aa-auth+jwt` | A class every verifier can distinguish, with single use semantic to the class |
| At most one result | R3 single-uses one issued token | An issuance guard giving one admitted transaction at most one result |
| Possession | AAuth proof of possession | An execution proof bound to the presented artifact itself |
| Current-state source | Conditional: the management status operation where deployed ({{I-D.draft-mcguinness-mission-aauth-management}}) | An unconditional source on the execution path |
| Failure vocabulary | Proposal pending, denied, and expired states | None |
| Fresh decision | PS adjudication under the lifecycle gate ({{lifecycle}}) | None |
{: title="Transaction authorization requirements: native and missing"}

A deployment could claim the capability only after the missing homes
exist upstream and this binding additionally claims State-Observable
unconditionally on the execution path (today conditional), and either
Structured Authority or an equivalent resource-owned evaluation of the
operation commitment (today not supported).  Until then the execution
gate and the authority evaluation the transaction invariants require
have no source in this binding, and hosting the flow is unsupported.

## Reference Propagation {#ref-propagation}

An agent operating in a Mission Context names the mission when it
requests a person token from its PS, and the PS stamps `mission_s256`
into the issued person token.  A resource that verifies that person
token MUST copy `mission_s256` into the resource token it issues.  When
an auth token is issued in the mission context, it carries the same
flat `mission_s256` claim, copied onward from the resource token.

This binding adds no member alongside that claim.  The namespace once
carried by `approver` is carried by the person token's `iss` and
the resource token's `ps`.  Receivers MUST NOT require `mission_id`,
`issuer`, `policy_version`, `intent_hash`, `authority_hash`,
`proposal_hash`, or embedded
authorization details for conformance to this binding.

Each copying party MUST preserve `mission_s256` exactly.  A PS receiving
a resource token with a mission reference MUST verify that `ps`
identifies itself before using local mission state.  Token verifiers
MUST perform the AAuth issuer, audience, agent, key, and
request-binding checks in addition to comparing the reference.

The presence of a reference establishes correlation, not authorization.
Authorization still depends on the issuer's decision, the token's scopes
and other claims, proof of possession, resource policy, and, where the PS
is on path, the PS's current contextual governance decision.

AAuth no longer treats a stripped mission as permitted downgrade: a
resource MUST NOT omit `mission_s256` from a resource token when the
person token it verified carried one, and a PS MUST resolve the
resource token's identified person token by `person_token_jti` and
reject any mismatch or omission against that person token's
`mission_s256`.  That base rule is what makes stripping detectable;
comparing claims by agent and resource alone cannot, because an agent
running concurrent missions holds more than one person token for the
same resource, and only the named person token resolves to one.

This binding keeps two further local rules on top of it.  An agent operating
under a mission MUST verify that a returned resource token carries the
exact `mission_s256`, and MUST NOT continue that authorization under
the mission when it is absent or different.  A PS whose policy places
an agent under mission governance MUST reject a missionless token
request from that agent.  The Lifecycle-Gated Authorization and
Credential-Bound claims of {{mission-substrate}} cover only requests
whose resource token carries the protected `mission_s256` claim.

## Lifecycle {#lifecycle}

An AAuth Mission Context has exactly the two native states:

active:
: The agent can submit governed requests under the mission.  Each request
  remains subject to a fresh PS decision and any resource policy.

terminated:
: The mission is permanently ended.  The PS MUST reject governed
  requests that reference it with AAuth's `mission_terminated` error,
  and the agent MUST stop acting under it.  An authenticated status
  or termination operation defined by a companion returns terminal
  state instead ({{mission-log}}).

Completion follows AAuth's interaction flow: the agent proposes
completion with a summary, the PS presents it to the person, and the
mission terminates only if the person accepts.  Other termination causes
and administrative mechanisms are left to AAuth mission-management work.
A deployment can record a termination reason in its private log without
creating another protocol state.

Every mission approved under this binding MUST carry AAuth's
`expires_at` member, and the PS MUST enforce it on every decision path
as AAuth requires.  When a proposal omits an expiry, the PS MUST set
one at approval under deployment policy, and that policy SHOULD prefer
the shortest expiry consistent with the mission's purpose.

Expiry transitions the mission to `terminated`; it adds no third
state, and no token carrying `mission_s256` outlives the mission's
approved `expires_at`.  AAuth distinguishes an expiry-caused termination with a
`termination_reason` of `expired`, surfaced where a management
companion exposes it, rather than with a separate error status.  An
early completion, revocation, or administrative termination prevents
new governed issuance; an outstanding token remains usable until
revocation or its own expiry, inside that approved bound.

There is no suspended state in this binding.  A short wait uses AAuth's
deferred-response mechanism.  A long or materially changed pause is
handled by terminating the old mission and approving a new, appropriately
scoped mission while retaining the old log for audit.

Termination prevents new governed issuance and PS operations.  It does
not retroactively erase a previously issued credential or guarantee that
all independently authorizing resources learn the state immediately.
Short token lifetimes bound this residual window in PS-asserted and
federated modes.  A resource needing stronger termination latency
requires an additional revocation or event mechanism.

# Conformance

An implementation conforms as an **AAuth Mission Context Agent** if it:

- implements AAuth mission proposal and approval;
- verifies and preserves the exact approved blob bytes;
- uses only the native `{approver, s256}` reference;
- names the mission at person-token issuance and verifies that a
  returned resource token carries the exact `mission_s256`;
- stops using a mission after `mission_terminated`;
- initiates no new governed work at or after the mission's
  `expires_at`; and
- does not treat mission approval or `approved_tools` as remote resource
  authority.

An implementation conforms as an **AAuth Mission Context Person Server**
if it:

- implements AAuth proposal, clarification, approval, and completion;
- binds the approved blob to the authenticated agent identifier;
- maintains the native active or terminated state and ordered mission
  log;
- applies the active-state gate to every governed PS operation that
  references a mission, while an authenticated status or termination
  surface defined by a companion returns terminal state instead;
- approves no mission without AAuth's `expires_at` member and enforces
  it on every decision path as AAuth requires;
- evaluates resource-token requests in mission context when it issues or
  brokers auth tokens; and
- does not expose the private mission blob to Resources or Access Servers.

An implementation conforms as a **mission-aware Resource or Access
Server** if it preserves and validates the native reference as required
by AAuth and does not claim to have evaluated the private mission
description.  Support by a Resource or Access Server is not required for
agent-and-PS conformance.

This document intentionally makes no "full" or "partial" provision
claim.  Conformance states which capabilities are present; it does not
rank AAuth by similarity to an OAuth authorization model.

# Security Considerations

The security considerations of AAuth apply.  This section highlights
properties specific to treating an AAuth mission as a Mission Context.

## Reference Substitution and Blob Integrity

An attacker can attempt to replace either `approver` or `s256`, attach a
valid reference to a different agent, or present uncommitted JSON as the
approved blob.  The decoded-bytes digest check, signed person-token carriage of
`mission_s256`, signed resource and auth tokens, agent-token
verification, and proof-of-possession binding are all necessary
defenses.

The agent MUST reject an approval response when the digest of the
decoded `mission` bytes differs from `s256`.  The PS MUST resolve a
reference only in its own approved-mission store and MUST verify the
authenticated agent's right to use it.  Resources and Access Servers
MUST NOT fetch a blob from an attacker-selected `approver` URL; AAuth
forbids dereferencing the reference.

## Confused-Deputy and Audience Checks

A reference is not a bearer capability.  Accepting it without verifying
the surrounding AAuth request or token can let an attacker borrow another
mission's context or cause a decision to be logged against the wrong
mission.  Parties MUST perform all AAuth audience, issuer, signing-key,
agent, confirmation-key, and request-context checks before associating a
request with a Mission Context.

In federated access, the PS and Access Server retain distinct policy
roles.  The PS MUST validate the resource token and govern the request
before federation.  The Access Server MUST validate its inputs and apply
resource policy; it cannot assume that a valid mission reference defines
the requested resource authority.

## Agent Compromise

Compromise of an agent and its signing key enables the attacker to make
requests that appear to come from that agent while its tokens and
missions remain usable.  Mission governance can reduce the effect where
the PS sees the request: the PS can compare justifications and behavior
with the approved context and log, request clarification, or deny new
issuance.  It does not make the compromised agent trustworthy.

In identity-based or resource-managed access, the attacker can contact a
resource without passing through the PS.  Mission termination alone
cannot stop such access.  Agent-token revocation, key rotation, resource
policy, resource-managed credential invalidation, and incident response
remain necessary.

PSes SHOULD support anomaly detection over the mission log, minimize
credential lifetimes, and make termination available to the person and
authorized administrators through applicable AAuth mechanisms.

## Person Server Compromise

The PS is the controlling authority and holds the private mission blob,
the person relationship, and the PS-observed governance log.  A compromised
PS can approve false missions, misrepresent state, disclose sensitive
context, issue PS-asserted auth tokens, or broker requests to Access
Servers.  AAuth signature verification does not protect against a
malicious legitimate PS signing key.

Deployments SHOULD protect PS signing keys and mission stores with
appropriate isolation, access control, backup, monitoring, and recovery
procedures.  Log integrity controls SHOULD make deletion, reordering, or
alteration detectable.  Separating administrative access from online
token-issuance privileges reduces the compromise blast radius.

## Log Integrity and Availability

The mission log is an input to future governance decisions and an audit
record.  Missing, reordered, or injected entries can change a PS decision
or hide misuse.  The PS SHOULD assign stable ordering information,
authenticate the source of entries, retain decision outcomes and relevant
token identifiers, and make retention behavior clear to the person.

The log can also be used for denial of service.  PSes SHOULD bound entry
size, clarification rounds, request rates, and retention while preserving
the records needed for active governance and incident investigation.
Availability loss at the PS prevents new PS-asserted and federated
authorizations; it does not necessarily stop identity-based or
resource-managed access.

## Prompt Injection and Untrusted Text

Mission descriptions, tool descriptions, justifications, clarification
messages, and audit content are untrusted input.  A PS that presents them
to a person or an AI decision-maker MUST sanitize rendered Markdown and
SHOULD clearly separate agent-supplied content from trusted policy and
system instructions.

An AI-assisted decision-maker MUST NOT treat text in a mission or log as
authority to alter verification rules, reveal secrets, bypass policy, or
invoke tools.  Deterministic checks on tokens, signatures, identities,
scopes, and state remain outside the natural-language decision context.

# Privacy Considerations

The exact mission blob can contain sensitive intent, planned actions,
tool use, organizational context, and person interactions.  AAuth's
reference-only design keeps the blob between the agent and PS.  Resources
and Access Servers receive the opaque `{approver, s256}` reference and
MUST NOT dereference it.

The stable reference is nevertheless a correlation handle.  Reusing it
across resources reveals that requests belong to the same mission and
reveals the PS hostname.  Agents SHOULD attach a Mission Context only
when its governance and correlation benefits justify that disclosure.
Resources, Access Servers, and logs SHOULD retain the reference only as
long as needed for authorization, security, dispute resolution, or legal
obligations.

The mission log centralizes a detailed history at the PS.  PS operators
SHOULD minimize recorded personal data, separate token identifiers from
raw token material, define retention and deletion policies, protect log
access, and give the person meaningful visibility into the retained
history.  Termination does not itself require erasure because the log can
be needed for audit and incident response.

Pairwise subject identifiers and other AAuth privacy mechanisms remain
applicable.  This binding does not replace them with the agent identifier
or mission reference.  Where the deployment uses pairwise or directed
person identifiers, the PS MUST maintain the mapping from each directed
identifier to the mission's person, so accountability and the person's
visibility into the retained history survive the pairwise boundary.

# Operational Considerations

PS-asserted and federated deployments SHOULD use short-lived auth tokens
so that a terminated mission stops supporting fresh authorization within
a bounded period.  Operators SHOULD document that bound and distinguish
it from immediate revocation.

Agents SHOULD retain the exact mission blob and log enough local
correlation data to diagnose mismatched references, but SHOULD NOT copy
the private blob into resource requests, telemetry, exception messages,
or general application logs.

Implementations SHOULD expose the native mission state and completion
flow consistently with AAuth.  Additional administrative APIs, event
delivery, signed evidence, or R3 decision bindings require separately
specified capabilities and trust relationships; their absence does not
change conformance to this binding.

# Mission Substrate Statement {#mission-substrate}

This section is this binding's Mission Substrate Statement and
declares conformance to {{I-D.draft-mcguinness-mission-substrate}}.
It applies to this revision of the binding in every resource access
mode of {{access-modes}}; mode-specific limits appear in the
capability table.

The contextual-governance kernel maps as follows:

1. **Mission Reference**: the native pair `{approver, s256}` remains
   this binding's Mission Reference.  `approver` is the uniqueness
   namespace, `s256` is compared as the exact unpadded base64url digest
   of the approved bytes, a changed blob is a different mission, a
   reference is never reassigned, retention follows the mission log's
   declared period, and the reference is unguessable to parties that do
   not hold the private blob.  On the wire it travels as the flat
   `mission_s256` claim, with that namespace carried by the person
   token's `iss` and the resource token's `ps` ({{reference}},
   {{mission-log}}).
2. **Controller**: the PS identified by `approver` controls approval,
   governance state, and the mission log ({{roles}}).  Consumers
   establish its identity and keys from AAuth's published PS metadata
   and key set ({{I-D.draft-hardt-oauth-aauth-protocol}}).
3. **Actor binding**: the blob's `agent` member names the AAuth agent
   identifier, authenticated by its agent token and HTTP message
   signatures; parent-mediated and call-chaining relationships are
   the only delegations, and the identifier maps to no OAuth
   `client_id` ({{blob}}, {{roles}}).
4. **Approved Context**: the private approved mission blob, delivered
   as the approval envelope's base64url `mission` member and immutable
   under the exact-byte `s256` commitment over its decoded bytes; it is
   never disclosed to Resources or Access Servers.  Both governance
   parties retain the decoded blob, satisfying the kernel's
   maintained-value branch; `s256` is verification material for
   holders, and algorithm migration follows AAuth ({{blob}},
   {{reference}}).
5. **Approval ceremony**: the AAuth propose, clarify, and approve
   interaction creates the approved blob and the `active` mission
   atomically ({{approval}}).
6. **Governance gate**: only `active` permits governed PS processing;
   `terminated` is permanent, and an unrecognized state is not
   active.  Person-accepted completion and the mission's `expires_at`
   are the base transitions; administrative termination is supplied
   by AAuth Mission Management where deployed ({{lifecycle}}).
7. **Reliance bound**: every mission carries AAuth's native
   `expires_at` member, enforced on every PS decision path
   ({{lifecycle}}); PS decisions establish `active` at decision time,
   no token carrying `mission_s256` exceeds the mission's `expires_at`,
   and the residual after a transition is bounded by outstanding token
   lifetime.  AAuth Mission Expiry
   {{I-D.draft-mcguinness-aauth-mission-expiry}} profiles the member
   this binding relies on.
8. **Context propagation**: the signed `mission_s256` claim, carried
   by person, resource, and auth tokens, carries governance context;
   the blob itself never propagates; coverage varies by access mode
   ({{ref-propagation}}, {{access-modes}}).
9. **Governance record**: the PS mission log is the ordered
   governance record, scoped to PS-observed operations with
   agent-reported local activity distinguished, and with the
   coverage, ordering, integrity, access, and retention requirements
   of {{mission-log}}.

The Statement's capability table follows, one row per capability;
every supplied row states its activation conditions, and its temporal
and failure elements in its cells or by express inheritance of the
Bounded Reliance floor ({{I-D.draft-mcguinness-mission-substrate}}):

| Capability | Claim | Activation | Scope and defining sections | Limitations |
| --- | --- | --- | --- | --- |
| Lifecycle-Gated Authorization | supplied | always | Mission approval and other positive governance decisions at the mission endpoint, permission decisions, and auth-token issuance the PS performs or brokers for requests carrying the person-token-issued `mission_s256` claim; decisions fail closed when current state cannot be established ({{lifecycle}}, {{access-modes}}, {{mission-log}}) | Independently issued resource credentials and missionless token requests are outside the claim ({{ref-propagation}}); the post-transition residual is bounded by auth-token lifetime and `expires_at` |
| State-Observable | supplied | the AAuth Mission Management status operation active ({{I-D.draft-mcguinness-mission-aauth-management}}) | Authenticated per-role callers, the `active` and `terminated` vocabulary, responses stamped `observed_at` with a declared `fresh_until` reliance bound, failing closed on failed, unrecognized, or stale responses, absent and unauthorized references indistinguishable | The base binding exposes no consumer-facing state source; token acceptance is not observation |
| Structured Authority | not supplied | -- | -- | The mission description is private prose and `approved_tools` is PS-governance input; scopes or a resource-owned policy language can supply structure inside its own boundary |
| Monotonic Derivation | not supplied | -- | -- | No cross-boundary subset relation is defined; a resource policy language can define monotonicity within its own vocabulary |
| Credential-Bound | supplied | PS-asserted or federated access mode, for requests whose resource token carries and validates the signed `mission_s256` claim ({{access-modes}}, {{ref-propagation}}) | PS-issued or PS-brokered artifacts carry the claim, a binding established at issuance rather than by an external join; fact semantics: PS issuance or brokering under the mission | Identity-based and resource-managed modes convey no mission binding; federated artifacts are AS-issued under the PS's brokering |
| Authorized Context Correlation | not supplied | -- | -- | The PS co-establishes the mission, person, agent, and token where it is on the path; no authoritative join of independently established facts is defined |
| Independently Verifiable | not supplied | -- | -- | `s256` proves byte identity to parties holding the blob; it does not prove record properties or current state to third parties |
| Portable Evidence | not supplied | -- | -- | The mission log is PS-local; signed receipts or checkpoints would be an extension |
{: title="AAuth Mission substrate capabilities"}

Each supplied row's temporal elements inherit the binding's own
bounds unless stated: decisions establish current state at the PS at
decision time, artifact lifetime is the auth-token lifetime capped by
`expires_at`, and the residual after the mission becomes non-active
is the outstanding auth-token lifetime. Failure behavior is uniformly
fail-closed: a request whose resource token is missing the
`mission_s256` claim its mode requires, carries one that fails
validation, or mismatches the named mission is processed as
missionless at best and never as mission-bound; a failed,
unrecognized, or stale Management status response, or an unavailable
status surface, refuses the state-dependent decision; unknown input
never degrades to a weaker mode silently.

# IANA Considerations

This document requests no IANA actions.  It uses only protocol elements
defined by {{I-D.draft-hardt-oauth-aauth-protocol}} and defines no new
header field, structured-field parameter, JWT claim, token member,
metadata member, error code, capability value, or registry value.

--- back

# Acknowledgments

The author thanks the AAuth community for defining a mission model in
which contextual governance, deterministic resource authorization, and
incremental deployment remain distinct concerns.
