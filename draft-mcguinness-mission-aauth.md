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
    author:
      -
        ins: D. Hardt
        name: Dick Hardt
    date: 2026-09-25
    seriesinfo:
      Internet-Draft: draft-hardt-oauth-aauth-protocol-11
  I-D.draft-mcguinness-mission-substrate:
    title: "Mission Substrate Requirements"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-substrate.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026

informative:
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
  I-D.draft-hardt-aauth-r3:
    title: "AAuth Rich Resource Requests (R3)"
    author:
      -
        ins: D. Hardt
        name: Dick Hardt
    date: 2026-09-28
    seriesinfo:
      Internet-Draft: draft-hardt-aauth-r3-00
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
  I-D.draft-hardt-aauth-supervision:
    title: "AAuth Supervision"
    target: https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-aauth-supervision.md
    author:
      -
        ins: D. Hardt
        name: Dick Hardt
    date: 2026-10-03
    refcontent: "Work in Progress, editor's copy at commit 70d67375, not submitted as an Internet-Draft"

--- abstract

AAuth defines missions as optional, immutable authorization contexts
for agent governance at a Person Server.  A mission is approved through
AAuth's native propose, clarify, and approve interaction, is identified
by the native pair of the approving Person Server and `s256`, and
accumulates an ordered mission log.  This document describes how those
native facilities realize a Mission Context binding without adding a
second mission identifier, a portable authority language, or new AAuth
wire members.

This binding preserves AAuth's separation between contextual governance
at the Person Server and deterministic resource authorization through
scopes, resource tokens, resource and Access Server policy, and
optionally R3.  It also identifies where active-state issuance gating is
structural and where a mission reference is only advisory context.

--- middle

# Introduction

The AAuth protocol {{I-D.draft-hardt-oauth-aauth-protocol}} gives agents
independent cryptographic identities and supports five resource access
modes: agent identity, resource-managed (two-party), person identity,
Person Server (PS) authorization (three-party), and federated
authorization (four-party) (Section 4.2 of
{{I-D.draft-hardt-oauth-aauth-protocol}}).  Agent governance is
orthogonal to those modes.

AAuth already defines the protocol elements needed for a durable Mission
Context:

- the agent proposes a natural-language mission to its PS;
- the PS and person can clarify and refine the proposal before approval;
- the approved mission blob is immutable and identified by the native
  pair of the approving PS and `s256`;
- the agent names the mission when it requests a person token from its
  PS, and the PS stamps the mission into the person token, from where
  the resource copies it into each resource token and the auth token's
  issuer, the PS or an Access Server (AS), copies it into each auth
  token issued under it;
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

This binding is written against draft-hardt-oauth-aauth-protocol-11
and draft-hardt-aauth-r3-00.

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

## Scope {#scope}

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

# Conventions and Terminology {#conventions-and-terminology}

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL
NOT**, **SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **NOT RECOMMENDED**,
**MAY**, and **OPTIONAL** in this document are to be interpreted as
described in BCP 14 when, and only when, they appear in all capitals as
shown here.

This document uses the AAuth terms *agent identifier*, *Person Server*,
*mission blob*, *mission identifier* (Section 8.2.1 of
{{I-D.draft-hardt-oauth-aauth-protocol}}), *resource token*,
*auth token*, *mission log*, *person token*, the `approved_tools`
member, and the `mission_s256` claim as defined by
{{I-D.draft-hardt-oauth-aauth-protocol}}.  This binding's Mission
Reference is defined in {{reference}}.

For this binding:

Mission Context:
: The immutable approved mission blob, its native mission reference, its
  current active or terminated state, and the ordered mission log used
  by the PS when governing an agent's work.

Controlling authority:
: The approving PS of the Mission Reference ({{reference}}).  The PS
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
: The pair of the approving PS and `s256` is this binding's Mission
  Reference ({{reference}}), with `s256` compared within the approving
  PS's namespace.  No additional `mission_id` is needed or defined.

Controlling authority:
: The approving PS is responsible for approval and governance.  No
  separate Mission issuer field names it.

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
: AAuth enforces `expires_at` on every PS decision path and caps the
  person tokens and auth tokens the PS issues at it ({{lifecycle}}); the
  PS still establishes `active` at decision time, including when it
  acts on a resource token, whose lifetime is independent of
  `expires_at`.

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

The pair of the approving PS and `s256` is this binding's Mission
Reference: AAuth's mission identity (Section 8.2.1 of
{{I-D.draft-hardt-oauth-aauth-protocol}}).  The approving PS is named
by the `iss` of a person token, the `ps` claim of a resource or auth
token, or the PS a request is made to; the blob carries no member
naming it.  On the wire the reference is the `mission_s256` claim or
parameter.

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

`mission_s256` commits to the original approved blob and to nothing
accepted after it.  An accepted `update` changes neither the blob nor
`mission_s256`, but from its acceptance the mission's meaning is the
blob plus its accepted updates (Section 8.4 of
{{I-D.draft-hardt-oauth-aauth-protocol}}).  This binding therefore
treats each accepted update as the approval of a new immutable version
of the Approved Context ({{I-D.draft-mcguinness-mission-substrate}}):
the blob plus the accepted updates through that one, in acceptance
order.  A version is identified by the Mission Reference together with
its position in the accepted-update sequence, the original blob being
position zero; the update's own `s256` is verification material for
the entry at that position, not a unique identifier.  A pending or
rejected update is part of no version.  Work that the original
description no longer describes uses a successor mission, and the old
mission terminates as `superseded`.

The reference does not authenticate itself when copied outside a
protected AAuth message.  It gains protocol integrity from the AAuth
message signature or signed token that carries it.  Implementations MUST
apply all AAuth signature, issuer, audience, proof-of-possession, and
request-context checks before relying on a received reference.

The reference is an integrity commitment, not a secret.  It is a
deterministic digest of the blob bytes, so a party that can predict
the blob's content can confirm a guess; the digest's length says
nothing about the entropy of its input.  This binding confines the
reference instead: every PS surface keyed by it authenticates the
caller and does not disclose whether a mission exists.  The mission
endpoint does so natively (Section 8.7 of
{{I-D.draft-hardt-oauth-aauth-protocol}}), the management control plane
by its anti-oracle rules
({{I-D.draft-mcguinness-mission-aauth-management}}), and the auth token
endpoint because a resource token's reference is checked against the
agent's own presented token before any state check (Section 6.7.2 of
{{I-D.draft-hardt-oauth-aauth-protocol}}).  AAuth's mission status
error carries no ownership condition (Section 8.8 of
{{I-D.draft-hardt-oauth-aauth-protocol}}), so at a PS endpoint that
takes a `mission_s256` parameter, a PS MUST establish that the mission
belongs to the requesting agent before reporting its state.  For an
absent mission and a mission belonging to another agent, the PS MUST
return the same status, error, body, and header set, with observably
equivalent timing.

Possession of the reference, or a correct guess, conveys no authority
over status, logs, or management.  A deployment that claims stronger
unpredictability documents its added entropy construction and its
retention consequences; this binding defines no member for it.

## Mission Blob {#blob}

The approved mission blob uses the members defined by AAuth, including
`agent`, `approved_at`, and `description`, and optionally
`approved_tools` and `approved_resources` (Section 8.2 of
{{I-D.draft-hardt-oauth-aauth-protocol}}).  The blob carries AAuth's
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
| Person | Reviews, clarifies, and approves through the PS when the Person is the Supervisor or a supervision server asks, and accepts completion through the PS. |
| Supervisor | Performs supervision (Section 4.3 of {{I-D.draft-hardt-oauth-aauth-protocol}}): the Person by default, or the deciding supervision server the PS consults for the agent ({{I-D.draft-hardt-aauth-supervision}}). |
| Resource | Defines and enforces its resource authorization; copies `mission_s256` unchanged from the presented token into each resource token it issues, as AAuth requires. |
| Access Server | Evaluates resource policy and issues auth tokens in federated access; it does not evaluate the private mission blob. |

An agent's deciding supervision server is the one supervision server
the PS consults for that agent, as configured at the PS; an agent
without one is supervised by the person (Section 6 of
{{I-D.draft-hardt-aauth-supervision}}).  For supervision decisions
within this binding's scope ({{scope}}), a PS with a deciding
supervision server for the agent obtains that server's decision.  The
PS retains responsibility for verification, enforcement, issuance, and
recording.  Management authorization and revocation are unchanged;
AAuth Supervision excludes both from supervision (Section 1.3 of
{{I-D.draft-hardt-aauth-supervision}}).  A supervision server's `allow`
of a completion does not by itself terminate the mission: the mission
terminates with reason `completed` only when the person accepts
({{lifecycle}}).

No AAuth party becomes an OAuth client, authorization server, or resource
server merely by implementing this binding.

## Proposal, Clarification, and Approval {#approval}

The agent creates the Mission Context by sending an AAuth mission
proposal to the PS `mission_endpoint`.  The proposal contains the
natural-language description and can contain requested tools as defined
by AAuth.

The PS MAY defer the response while the Supervisor ({{roles}}), by
default the person, reviews the proposal.  AAuth clarification messages
can ask the agent for missing context or negotiate changes.  The agent
MUST NOT treat the proposal, a pending response, or a clarification
exchange as approval.

Approval occurs only when the PS returns the approval envelope: `s256`
and the approved mission blob as the base64url-encoded `mission`
member.  Before using the context, the agent MUST:

1. verify the AAuth response according to the base protocol;
2. decode `mission` and compute SHA-256 over the exact decoded bytes;
3. verify that the result equals the envelope's `s256` value;
4. verify that the blob's `agent` member identifies the requesting
   agent, and record as the approving PS the PS whose
   `mission_endpoint` received the proposal; and
5. store the exact decoded bytes and native reference.

A failed check invalidates the approval response.  The agent MUST NOT
operate under the resulting reference.

## Governed Requests and Mission Log {#mission-log}

For every PS request seeking a positive governance decision under a
mission reference, the PS MUST verify that:

- it is the PS the reference names;
- the `s256` identifies a mission blob it approved;
- the authenticated agent is entitled to act in the referenced context;
  and
- the mission is `active`.

If any of these checks cannot be completed, including establishing the
mission's current state, the PS MUST fail closed and reject the
request.

Authenticated status, termination, denial, cleanup, and control-plane
audit operations defined by this binding's companions are not positive
governance decisions; they answer on a non-active mission as their
specifications define.

The PS then evaluates the request using the approved description, the
request's justification and other inputs, applicable person or
organization policy, and relevant prior entries in the mission log.  A
valid reference means that the context is identified and intact; it does
not require the PS to approve the request.

The PS MUST maintain the mission log as an ordered record of the AAuth
interactions defined to belong to the mission, including token requests,
accepted updates, permission decisions, audit records, interaction
requests, clarification chats, and the supervision decisions made
(Section 8.3 of {{I-D.draft-hardt-oauth-aauth-protocol}}).  Log records
SHOULD preserve sufficient correlation data to associate each decision
with its authenticated request and any issued token without recording
raw credentials.

For each supervision decision, the PS records the actual decider: the
person acting directly, the deciding supervision server identified by
its `issuer`, or the person answering after the server's `ask` or while
the server is unavailable.  For an exchange with a supervision server,
the log entry is the exchange itself under the PS-minted `sdi`, with
any signatures preserved, and the person's later answer is recorded
under the same `sdi` (Sections 7.3 and 9.4 of
{{I-D.draft-hardt-aauth-supervision}}).  An unsigned response rests on
the PS's own record; a response signed under the server's published
`jwks_uri` is independently verifiable.  A deployment that claims to
prove what its supervision server decided requires a server that
signs.

The PS MUST protect the mission log's integrity, MUST restrict read
access to the person, the PS itself, the deciding supervision server
for the mission's agent ({{roles}}), and parties authorized under its
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
An accepted `update` at the mission's own URL is one such entry,
digested by its own `s256`; it changes neither the blob nor
`mission_s256` (Section 8.4 of
{{I-D.draft-hardt-oauth-aauth-protocol}}).

## Deterministic Resource Authorization

A mission approval does not pre-authorize a portable set of remote
resource operations.  Deterministic resource authorization continues to
use the AAuth mechanisms appropriate to the access mode:

- the resource's own policy in agent identity access;
- the resource-managed authorization result;
- scopes in resource and auth tokens;
- resource policy in PS authorization access;
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
| Agent identity | The resource authorizes the signed agent identity directly.  No AAuth carrier conveys `mission_s256` in this mode (Section 4.5 of {{I-D.draft-hardt-oauth-aauth-protocol}}), and the PS does not gate the resource decision. |
| Resource-managed (two-party) | The resource manages authorization directly.  No AAuth carrier conveys `mission_s256` in this mode, and the PS does not gate the resource's issuance or decision. |
| Person identity | The resource authorizes on the PS-issued person token's identity alone.  Person-token issuance is the PS's control point: mission-scoped via `mission_s256`, capped at one hour and by the mission's `expires_at`; the resource's own decision is not PS-gated. |
| PS authorization (three-party) | The resource token is presented to the PS, which evaluates the active Mission Context before it issues an auth token.  PS issuance gating is structural for a request whose resource token carries the mission's `mission_s256` claim ({{ref-propagation}}).  The resource still applies its own resource policy. |
| Federated authorization (four-party) | The PS evaluates the active Mission Context before it federates the request to the resource's Access Server and before returning the resulting auth token.  PS broker gating is structural under the same condition; the Access Server independently applies resource policy. |

In every mode, the PS MUST apply the active-state gate to its own
permission, audit, interaction, mission, and token operations when they
reference a mission, as required by AAuth, except that an
authenticated status or termination operation defined by a companion
returns terminal state instead.  In agent identity and
resource-managed access, that PS-local gate does not stop an agent from
making requests directly to a resource.  Deployments MUST NOT claim PS
issuance gating for those direct resource decisions.

A resource MUST NOT omit `mission_s256` from a resource token it issues
when the presented token it verified carried one; AAuth makes a missing
claim a protocol violation rather than permitted ignorance
(Section 6.7.1 of {{I-D.draft-hardt-oauth-aauth-protocol}}).  An
implementation MUST NOT infer that a resource evaluated mission context
merely because a token carried the claim.  Even a mission-aware Resource
or Access Server receives only the reference and MUST NOT dereference it
to obtain the private mission blob.

## Transaction Authorization {#transaction-authorization}

This binding does not claim the transaction authorization capability.
The Carrier Binding Floor of
{{I-D.draft-mcguinness-oauth-mission-transaction-authorization}} names
the slots a binding must provide to host action-bound transaction
authorization.  R3 supplies per-call authorization in its own terms
({{I-D.draft-hardt-aauth-r3}}); the gap is to the family's stronger
transaction profile.  The table classifies each slot as supplied, supplied conditionally,
unproven equivalence, or absent, and names the signed native field and
verifier step that supply it.  Its section numbers refer to
{{I-D.draft-hardt-oauth-aauth-protocol}}, or to
{{I-D.draft-hardt-aauth-r3}} where marked R3; the management status
operation is that of {{I-D.draft-mcguinness-mission-aauth-management}}.
Consistent with this document's rule that it adds no new AAuth wire
members, it defines no extensions to close a gap.

| Requirement | Native carrier and verifier step | Status | Gap |
| --- | --- | --- | --- |
| Challenge carrier | The resource token, signed by the resource and verified against its published keys (6.7.2), commits to the operation and parameters through `r3_uri` and `r3_s256` (R3 7.3), to the Mission through `mission_s256`, and to the presenter key through `agent_jkt` (6.7.1) | Supplied; the Mission commitment when the presented token carries one | The parameter commitment, in its own row |
| Operation identity | The R3 document, identified by `r3_s256` over its served bytes, names the operation in the resource's vocabulary (R3 7.2) | Supplied for identity; absent for supersession | A superseded definition that resolves only for workflows admitted under it |
| Parameter commitment | The proposal's `parameters`, committed by `r3_s256`; under `401` the resource compares the retried call to them structurally, and under `202` it executes the held call (R3 10.1, R3 10.2) | Unproven equivalence | A verifiable equivalence to `parameter_digest` (below) |
| Workflow handle | Under `202`, the pending URL; once the call completes, its record and result are keyed by the auth token's `jti` and retained at least until that token's `exp` (6.5.1) | Supplied conditionally (`202` only) | A declared lifetime for the pending workflow; a handle under `401`; admission idempotency on either path |
| Result class | The per-call result is an ordinary `aa-auth+jwt` with the members of any R3 auth token (R3 9); only the referenced proposal and the resource's state show that it is per-call | Absent | A class every verifier can distinguish, with single use semantic to the class |
| At most one result | One invocation per per-call auth token, with a repeated presentation answered from the retained result (R3 10.2, 6.5.1) | Supplied per token | An issuance guard: issuers need not keep replay state for resource tokens (6.7.1, 11.3.4.2), so one proposal can yield more than one per-call auth token; the resource's consumption of the proposal bounds execution, not issuance |
| Possession | The per-call auth token travels in `Signature-Key`, a covered component, on the `401` retry and the `202` poll alike, and its `cnf.jwk` must equal the request-signing key; the PS checks `agent_jkt` at redemption (11.3.3.1, 9.4.3.2, 6.7.2) | Supplied | None |
| Current-state source | The PS checks mission state when it acts on the resource token (6.7.2); at the resource, the management status operation where deployed | Supplied conditionally | An unconditional source on the execution path |
| Failure vocabulary | Proposal pending; the `denied`, `abandoned`, `expired`, and `revoked` polling errors (11.9.4); and an expired presented token when a per-call approval outlives it (R3 10.2) | Supplied | None |
| Fresh decision | PS adjudication under the lifecycle gate ({{lifecycle}}) | Supplied | None |
{: title="Transaction authorization requirements: native carriers and status"}

Where a supervision server ({{roles}}) makes the fresh decision, it
receives the resource token, which commits to the proposal through
`r3_uri` and `r3_s256`, but not the proposal itself (Section 11.2 of
{{I-D.draft-hardt-aauth-supervision}}).

The R3 parameter commitment is not shown to be equivalent to
`parameter_digest` ({{I-D.draft-mcguinness-mission-runtime}}).  R3
commits to the parameters exactly as the resource serialized them in
the proposal, and under `401` compares the retried call to them by
JSON value equality or by the digest of a presented value.
`parameter_digest` is a digest of a normalized parameter object: an
Operation Profile fixes default insertion, omitted optional fields, and
set-like arrays, and every parameter that influences the action's
external effect enters it.  The two coincide for one resource
operation only when the resource's proposal carries every
effect-bearing parameter in that normalized form, which neither R3 nor
this binding requires.  Under `202` the held call itself is executed,
so no parameter can be substituted, but no digest exists for another
verifier to recompute.  This binding defines no second
canonicalization to close the gap.

R3 also lets a resource seek approval to release a result it has
already computed, rather than approval to execute (Section 10.4 of
{{I-D.draft-hardt-aauth-r3}}).  That approval gates disclosure, not
execution.  The floor's invariants concern pre-execution approval, so a
release-gated call is outside this mapping, and approving release is
never treated as approving execution.

The slots without a native home are operation supersession, parameter
equivalence, a declared pending-workflow lifetime, the `401` workflow
handle and admission idempotency, a distinguishable result class, an
issuance guard giving one result per transaction instance, and an
unconditional current-state source.  A
deployment could claim the capability only after those exist upstream
and this binding additionally claims State-Observable unconditionally
on the execution path (it is claimed conditionally), and either
Structured Authority or an equivalent resource-owned evaluation of the
operation commitment (not supplied).  Until then the execution gate and
the authority evaluation the transaction invariants require have no
source in this binding, and hosting the flow is unsupported.

## Reference Propagation {#ref-propagation}

An agent operating in a Mission Context names the mission when it
requests a person token from its PS, and the PS stamps `mission_s256`
into the issued person token (Section 7.1 of
{{I-D.draft-hardt-oauth-aauth-protocol}}).  A resource that verifies a
presented token (a person token or an auth token) carrying
`mission_s256` MUST copy it into the resource token it issues, which
names that presented token in `presented_jti` (Section 6.7.1 of
{{I-D.draft-hardt-oauth-aauth-protocol}}).  When an auth token is
issued in the mission context, its issuer (the PS, or the AS in
four-party access) copies the same flat `mission_s256` claim onward
from the resource token (Section 9.4.1 of
{{I-D.draft-hardt-oauth-aauth-protocol}}).

A resource that calls a downstream resource for its caller acts as an
intermediary: an agent with its own agent identifier and key (Section
10.1.1.1 of {{I-D.draft-hardt-oauth-aauth-protocol}}).  It requests a
person token for the downstream resource, presenting the token its
caller presented as `upstream_token`.  When that upstream token carries
`mission_s256`, the PS evaluates the request against that mission and
copies `mission_s256` into the person token it issues; the
intermediary does not send `mission_s256` of its own (Sections 7.1 and
10.1.1 of {{I-D.draft-hardt-oauth-aauth-protocol}}).  A chained hop is
therefore PS-governed derivation under the same Mission, not a child
mission: the Mission's `agent` stays the root actor, the intermediary
is a separate actor ({{mission-substrate}}), and the hop's supervision
decision follows {{roles}}.

This binding adds no member alongside that claim.  The approving PS
that scopes it is named as {{reference}} describes.  Receivers MUST NOT
require `mission_id`,
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

AAuth does not treat a stripped mission as permitted downgrade: a
resource MUST NOT omit `mission_s256` from a resource token when the
presented token it verified carried one, and a PS MUST verify the
`presented_token` the agent forwards against the resource token, its
`jti` against `presented_jti` and its `mission_s256` against the
resource token's, and reject any mismatch or omission (Sections 6.7.2
and 7.2.1 of {{I-D.draft-hardt-oauth-aauth-protocol}}).  In four-party
access the AS performs the same verification (Section 9.1.1 of
{{I-D.draft-hardt-oauth-aauth-protocol}}).  That base rule is what
makes stripping detectable; comparing claims by agent and resource
alone cannot, because an agent running concurrent missions holds more
than one person token for the same resource, and only the named
presented token identifies one.  The check uses no retained record on
the request path; the PS's record of the person tokens it issues
serves revocation (Section 7.1 of
{{I-D.draft-hardt-oauth-aauth-protocol}}).

This binding keeps further local rules on top of it.  An agent
operating under a mission MUST verify that a returned resource token
carries the exact `mission_s256`, and MUST NOT continue that
authorization under the mission when it is absent or different.  A PS
whose policy places an agent under mission governance MUST reject a
missionless token request from that agent.

AAuth lists an AS-issued auth token's `mission_s256` among its optional
claims, and the PS's delivery checks do not include it (Sections 9.4.1
and 9.1.3 of {{I-D.draft-hardt-oauth-aauth-protocol}}).  In four-party
access, before returning an AS-issued auth token to the agent, a PS
MUST verify that the token carries the resource token's `mission_s256`
exactly whenever the resource token carried one.  A token that fails
this check fails the PS's delivery verification, and the PS answers
`as_unreachable` (Section 9.1.3 of
{{I-D.draft-hardt-oauth-aauth-protocol}}).

A request's Mission association is required when that policy applies
or when the request derives from a presented token or upstream token
that carries `mission_s256`.  A required association that is missing,
malformed, invalid, unresolvable, or mismatched fails the request under
AAuth's own rules, in AAuth's order of checks:

- a malformed `mission_s256` in a person token request receives
  `invalid_request`, and one naming a mission that does not exist or
  belongs to another agent is rejected (Section 7.1 of
  {{I-D.draft-hardt-oauth-aauth-protocol}});
- a presented token that fails verification receives
  `invalid_presented_token`, or `expired_presented_token` when only its
  `exp` fails, which is how a Mission-bound token fails once
  `expires_at` passes (Sections 6.7.2 and 7.1.2 of
  {{I-D.draft-hardt-oauth-aauth-protocol}});
- a resource token that omits or mismatches its presented token's
  `mission_s256` receives `invalid_resource_token` (Section 6.7.2 of
  {{I-D.draft-hardt-oauth-aauth-protocol}}); and
- a request that reaches the mission-state check under a mission that
  is no longer active receives `mission_terminated` (Section 8.8 of
  {{I-D.draft-hardt-oauth-aauth-protocol}}).

The PS, or the AS in four-party access, MUST NOT evaluate a failed
request as missionless authorization, and the agent MUST NOT retry it
without the reference.

Intentionally missionless authorization is a separate path, admitted by
explicit deployment policy from the outset for requests with no
required or inherited Mission association.  It is never a fallback
after Mission validation fails.  It is outside the Lifecycle-Gated
Authorization and Credential-Bound claims.  Each claim's scope and
activation conditions are stated in {{mission-substrate}}.

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

Completion uses the `completion` action at
`{mission_endpoint}/{mission_s256}`: the agent proposes completion with
a summary, the PS presents it to the person, and the mission terminates
with reason `completed` only if the person accepts (Section 8.5 of
{{I-D.draft-hardt-oauth-aauth-protocol}}).  The PS records why a
mission terminated alongside the mission, from AAuth's open reason set
of `completed`, `revoked`, `expired`, `superseded`, and
`administrative`; a reason is never a protocol state (Section 8.6 of
{{I-D.draft-hardt-oauth-aauth-protocol}}).  A mission reaches
`terminated` by accepted completion, by its `expires_at`, by PS
revocation of the mission (Section 11.12.4 of
{{I-D.draft-hardt-oauth-aauth-protocol}}), or by a control-plane
operation at the `mission_control_endpoint`, which AAuth Mission
Management {{I-D.draft-mcguinness-mission-aauth-management}} defines.

An accepted `update` can narrow or broaden the work under the same
reference ({{reference}}).  The PS MUST NOT accept an update that
broadens the work without the Supervisor's acceptance.  The Supervisor
is the Person unless a deciding supervision server is configured for
the agent ({{roles}}).  Under a deciding supervision server, the
server's `allow` accepts the update and its `ask` requires the
person's response (Section 10.3 of
{{I-D.draft-hardt-aauth-supervision}}); the PS does not classify
broadening itself to decide whether to consult the server, so a
configured server can authorize broadening without a fresh human
decision.  The Supervisor's acceptance is the approval of the new
version ({{reference}}).

Every mission approved under this binding MUST carry AAuth's
`expires_at` member, and the PS MUST enforce it on every decision path
as AAuth requires.  A proposal can request an expiry under AAuth
Mission Expiry {{I-D.draft-mcguinness-aauth-mission-expiry}}; when it
requests none, the PS MUST set one at approval under deployment policy,
and that policy SHOULD prefer the shortest expiry consistent with the
mission's purpose.

Expiry transitions the mission to `terminated`; it adds no third
state.  The PS caps the person tokens and auth tokens it issues at
`expires_at` (Sections 7.1.2 and 9.4.1 of
{{I-D.draft-hardt-oauth-aauth-protocol}}), and the presented token
carries that bound to an AS (Section 9.1.1 of
{{I-D.draft-hardt-oauth-aauth-protocol}}).  A resource token is a
short-lived request artifact whose lifetime is independent of
`expires_at`; the PS verifies that the mission is active and unexpired
whenever it acts on one (Sections 6.7.1 and 6.7.2 of
{{I-D.draft-hardt-oauth-aauth-protocol}}).  AAuth distinguishes an
expiry-caused termination with a `termination_reason` of `expired` in
the `mission_terminated` error (Section 8.8 of
{{I-D.draft-hardt-oauth-aauth-protocol}}), rather than with a separate
error status.  An early completion, revocation, or administrative
termination prevents new governed issuance; an outstanding person
token or auth token remains usable until revocation or its own expiry,
inside that bound.

There is no suspended state in this binding.  A short wait uses AAuth's
deferred-response mechanism.  A long or materially changed pause is
handled by terminating the old mission and approving a new, appropriately
scoped mission while retaining the old log for audit.

Termination prevents new governed issuance and PS operations.  It does
not retroactively erase a previously issued credential or guarantee that
all independently authorizing resources learn the state immediately.
In the modes that present a person token, short token lifetimes bound
this residual window: a party that no revocation reaches is bounded
by token lifetime alone, at most one hour for a person token or an auth
token (Section 11.12.5 of {{I-D.draft-hardt-oauth-aauth-protocol}}).
AAuth token revocation shortens the window where the token's recipient
supports it (Section 11.12 of {{I-D.draft-hardt-oauth-aauth-protocol}});
a resource needing stronger termination latency requires an additional
event mechanism.

# Conformance

An implementation conforms as an **AAuth Mission Context Agent** if it:

- implements AAuth mission proposal and approval;
- verifies and preserves the exact approved blob bytes;
- uses only the native reference of the approving PS and `s256`;
- names the mission at person-token issuance and verifies that a
  returned resource token carries the exact `mission_s256`;
- stops using a mission after `mission_terminated`;
- initiates no new governed work at or after the mission's
  `expires_at`; and
- does not treat mission approval or `approved_tools` as remote resource
  authority.

An implementation conforms as an **AAuth Mission Context Person Server**
if it:

- implements AAuth proposal, clarification, approval, update, and
  completion;
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

AAuth requires a resource to copy `mission_s256` from the presented
token into its resource token, and an Access Server to verify the
presented token against the resource token (Sections 6.7.1 and 9.1.1
of {{I-D.draft-hardt-oauth-aauth-protocol}}).  An implementation
conforms as a **mission-aware Resource or Access Server** if it does so
and does not claim to have evaluated the private mission description.
Support by a Resource or Access Server is not required for
agent-and-PS conformance.

This document intentionally makes no "full" or "partial" provision
claim.  Conformance states which capabilities are present; it does not
rank AAuth by similarity to an OAuth authorization model.

# Security Considerations

The security considerations of AAuth apply.  This section highlights
properties specific to treating an AAuth mission as a Mission Context.

## Reference Substitution and Blob Integrity

An attacker can attempt to substitute the approving PS or `s256`, attach
a valid reference to a different agent, or present uncommitted JSON as
the approved blob.  The decoded-bytes digest check, signed person-token
carriage of `mission_s256`, signed resource and auth tokens, the
`presented_jti` binding of each resource token to one presented token
whose `mission_s256` it matches exactly (Section 6.7.2 of
{{I-D.draft-hardt-oauth-aauth-protocol}}), agent-token verification,
and proof-of-possession binding are all necessary defenses.

The agent MUST reject an approval response when the digest of the
decoded `mission` bytes differs from `s256`.  The PS MUST resolve a
reference only in its own approved-mission store and MUST verify the
authenticated agent's right to use it.  Resources and Access Servers
MUST NOT fetch a blob from a location derived from the reference, such
as one under the approving PS's identifier.

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

In agent identity or resource-managed access, the attacker can contact a
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
context, issue auth tokens in PS authorization access, or broker
requests to Access Servers.  AAuth signature verification does not
protect against a malicious legitimate PS signing key.

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
Availability loss at the PS prevents new person tokens and new PS
authorization and federated authorization grants; it does not
necessarily stop agent identity or resource-managed access, or person
identity access on a person token already issued, which lives at most
one hour (Section 7.1.1 of {{I-D.draft-hardt-oauth-aauth-protocol}}).

## Prompt Injection and Untrusted Text

Mission descriptions, tool descriptions, justifications, clarification
messages, and audit content are untrusted input.  A PS that presents them
to a person or an AI decision-maker MUST sanitize rendered Markdown and
SHOULD clearly separate agent-supplied content from trusted policy and
system instructions.  On a consent surface, AAuth also requires the PS
to distinguish resource-asserted from agent-asserted content and to
attribute the latter to the agent (Section 7.4 of
{{I-D.draft-hardt-oauth-aauth-protocol}}).

An AI-assisted decision-maker MUST NOT treat text in a mission or log as
authority to alter verification rules, reveal secrets, bypass policy, or
invoke tools.  Deterministic checks on tokens, signatures, identities,
scopes, and state remain outside the natural-language decision context.

# Privacy Considerations

The exact mission blob can contain sensitive intent, planned actions,
tool use, organizational context, and person interactions.  AAuth's
reference-only design keeps the blob between the agent and PS.  Resources
and Access Servers receive only the reference, which is `s256` and the
PS that approved it (Section 14.3 of
{{I-D.draft-hardt-oauth-aauth-protocol}}), and MUST NOT dereference it.

The stable reference is nevertheless a correlation handle.  Reusing it
across resources reveals that requests belong to the same mission and
reveals the PS hostname.  Because it is a deterministic digest, a
party that can predict a blob's content can also test a guess against
an observed reference; the PS's confinement of the reference and its
data minimization hold whether or not the reference stays secret
({{reference}}).  Agents SHOULD attach a Mission Context only when its
governance and correlation benefits justify that disclosure.
Once attached, the reference also travels where the agent does not
choose: when a resource acting as an agent obtains a person token for
a downstream resource, the PS copies `mission_s256` from the upstream
token into it (Section 7.1 of {{I-D.draft-hardt-oauth-aauth-protocol}}).
Resources, Access Servers, and logs SHOULD retain the reference only as
long as needed for authorization, security, dispute resolution, or legal
obligations.

The mission log centralizes a detailed history at the PS.  PS operators
SHOULD minimize recorded personal data, separate token identifiers from
raw token material, define retention and deletion policies, protect log
access, and give the person meaningful visibility into the retained
history.  Termination does not itself require erasure because the log can
be needed for audit and incident response.  A deciding supervision
server receives mission text, justifications, audit records, and
clarification transcripts for the agents routed to it, and a newly
routed server receives the active state the PS replays to it (Sections
14 and 17.1 of {{I-D.draft-hardt-aauth-supervision}}); the routing
configured at the PS determines that disclosure.

Pairwise subject identifiers and other AAuth privacy mechanisms remain
applicable.  This binding does not replace them with the agent identifier
or mission reference.  Where the deployment uses pairwise or directed
person identifiers, the PS MUST maintain the mapping from each directed
identifier to the mission's person, so accountability and the person's
visibility into the retained history survive the pairwise boundary.

# Operational Considerations

PS authorization and federated authorization deployments SHOULD use
short-lived auth tokens so that a terminated mission stops supporting
fresh authorization within
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

1. **Mission Reference**: the native pair of the approving PS and
   `s256` is this binding's Mission Reference.  The PS is the uniqueness
   namespace, `s256` is compared as the exact unpadded base64url digest
   of the approved bytes, a changed blob is a different mission, a
   reference is never reassigned, retention follows the mission log's
   declared period, and the reference, a content digest rather than a
   secret, meets the unguessability requirement by namespace
   confinement ({{reference}}).  On the wire it travels as the flat
   `mission_s256` claim or parameter, with the PS named as
   {{reference}} describes ({{mission-log}}).
2. **Controller**: the approving PS controls approval,
   governance state, and the mission log ({{roles}}).  Consumers
   establish its identity and keys from AAuth's published PS metadata
   and key set ({{I-D.draft-hardt-oauth-aauth-protocol}}).
3. **Actor binding**: the blob's `agent` member names the root actor,
   the AAuth agent identifier authenticated by its agent token and
   HTTP message signatures; parent-mediated and call-chaining
   relationships are the only delegations, and the identifier maps to
   no OAuth `client_id` ({{blob}}, {{roles}}).  The holder of a chained
   person token is the intermediary, a separate actor whose agent
   identity the PS establishes from the intermediary's authenticated
   agent token and its own records; the token's `cnf` binds the key,
   not the identity ({{ref-propagation}}).
4. **Approved Context**: the private approved mission blob, delivered
   as the approval envelope's base64url `mission` member and immutable
   under the exact-byte `s256` commitment over its decoded bytes, and
   each later version an accepted update approves: the blob plus the
   accepted updates through it, immutable and identified by the
   Mission Reference and its position in the accepted-update sequence,
   by the kernel's new-version route ({{reference}}, {{lifecycle}}).
   None of it is disclosed to Resources or Access Servers.  Both governance
   parties retain the decoded blob, satisfying the kernel's
   maintained-value branch; `s256` is verification material for
   holders, and AAuth fixes its algorithm at SHA-256 with no migration
   path (Section 8.2 of {{I-D.draft-hardt-oauth-aauth-protocol}};
   {{blob}}, {{reference}}).
5. **Approval ceremony**: the AAuth propose, clarify, and approve
   interaction creates the approved blob and the `active` mission
   atomically ({{approval}}).
6. **Governance gate**: only `active` permits governed PS processing;
   `terminated` is permanent, and an unrecognized state is not
   active.  Person-accepted completion, the mission's `expires_at`, and
   PS revocation of the mission are the base transitions; control-plane
   termination at the `mission_control_endpoint` is supplied by AAuth
   Mission Management where deployed ({{lifecycle}}).
7. **Reliance bound**: every mission carries AAuth's native
   `expires_at` member, enforced on every PS decision path
   ({{lifecycle}}); PS decisions establish `active` at decision time,
   including on a resource token, whose lifetime is independent of
   `expires_at`; no person token or auth token carrying `mission_s256`
   exceeds the mission's `expires_at`; and the residual after a
   transition is bounded by outstanding token lifetime.  AAuth Mission
   Expiry {{I-D.draft-mcguinness-aauth-mission-expiry}} profiles the
   member this binding relies on.
8. **Context propagation**: the signed `mission_s256` claim, carried
   by person, resource, and auth tokens, carries governance context,
   including on a person token the PS issues to an intermediary on an
   upstream token, where the PS copies the claim and the intermediary
   never supplies it; the blob itself never propagates; coverage varies
   by access mode ({{ref-propagation}}, {{access-modes}}).
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
| Lifecycle-Gated Authorization | supplied | always | Mission approval and other positive governance decisions at the mission endpoint, permission decisions, person-token issuance under a named or upstream-inherited mission, and auth-token issuance the PS performs or brokers for requests carrying the person-token-issued `mission_s256` claim; decisions fail closed when current state cannot be established ({{lifecycle}}, {{access-modes}}, {{mission-log}}) | Independently issued resource credentials and intentionally missionless requests, admitted by policy with no required or inherited association, are outside the claim; a failed required association is rejected, never treated as missionless ({{ref-propagation}}); the post-transition residual is bounded by person-token and auth-token lifetime and `expires_at` |
| State-Observable | supplied | the AAuth Mission Management status operation active ({{I-D.draft-mcguinness-mission-aauth-management}}) | Authenticated per-role callers, the `active` and `terminated` vocabulary, responses stamped `observed_at` with a declared `fresh_until` reliance bound, failing closed on failed, unrecognized, or stale responses, absent and unauthorized references indistinguishable | The base binding exposes no consumer-facing state source; token acceptance is not observation |
| Structured Authority | not supplied | -- | -- | The mission description is private prose and `approved_tools` is PS-governance input; scopes or a resource-owned policy language can supply structure inside its own boundary |
| Monotonic Derivation | not supplied | -- | -- | No cross-boundary subset relation is defined; a resource policy language can define monotonicity within its own vocabulary; an accepted update can broaden the work under the same reference with the Supervisor's acceptance ({{lifecycle}}), so the binding offers no containment guarantee |
| Credential-Bound | supplied | PS authorization or federated authorization access mode, for requests whose resource token carries and validates the signed `mission_s256` claim ({{access-modes}}, {{ref-propagation}}) | PS-issued or PS-brokered artifacts carry the claim, a binding established at issuance rather than by an external join; fact semantics: PS issuance or brokering under the mission | Agent identity and resource-managed modes convey no mission binding; federated authorization artifacts are AS-issued under the PS's brokering, and the PS's delivery check rejects one that omits or alters the claim ({{ref-propagation}}) |
| Authorized Context Correlation | not supplied | -- | -- | The PS co-establishes the mission, person, agent, and token where it is on the path; no authoritative join of independently established facts is defined |
| Independently Verifiable | not supplied | -- | -- | `s256` proves byte identity to parties holding the blob; it does not prove record properties or current state to third parties |
| Portable Evidence | not supplied | -- | -- | The mission log is PS-local; signed receipts or checkpoints would be an extension |
{: title="AAuth Mission substrate capabilities"}

Each supplied row's temporal elements inherit the binding's own
bounds unless stated: decisions establish current state at the PS at
decision time, artifact lifetime is the auth-token lifetime capped by
`expires_at`, and the residual after the mission becomes non-active
is the outstanding person-token and auth-token lifetime. Failure
behavior is fail-closed. A request whose required Mission association
is missing, malformed, invalid, unresolvable, or mismatched is rejected
under AAuth's own failure rules and is never evaluated or retried as
missionless authorization ({{ref-propagation}}). A failed,
unrecognized, or stale Management status response, or an unavailable
status surface, refuses the decision that depends on that state, and
unknown input never silently selects a weaker mode. Intentionally
missionless authorization is a separate path admitted by deployment
policy from the outset, outside the Lifecycle-Gated Authorization and
Credential-Bound claims; it is not a fallback after Mission validation
fails.

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

# Document History {#document-history}

\[\[ To be removed from the final specification ]]

- An accepted update approves a new immutable version of the Approved
  Context, identified by the Mission Reference and its position in the
  accepted-update sequence; `mission_s256` commits to the original
  blob only, and a pending or rejected update is part of no version.
  The PS must not accept a broadening update without the Supervisor's
  acceptance; under a deciding supervision server, its `allow` accepts
  and its `ask` requires the person, so a configured server can
  authorize broadening without a fresh human decision. The Statement
  names the versions and disclaims any containment guarantee (#965).

- Maps AAuth's Supervisor role and defines an agent's deciding
  supervision server. A PS with one obtains that server's decision for
  supervision decisions and keeps verification, enforcement, issuance,
  and recording; management authorization and revocation are
  unchanged, and a supervision server's `allow` of a completion does
  not by itself terminate the mission, which still needs the person's
  acceptance. The mission log records the actual decider and, for a
  supervision-server exchange, the `sdi` and the exchange with any
  signatures; the deciding server is a log reader; a supervision server
  does not see the R3 proposal. AAuth Supervision is cited
  informatively, pinned at dickhardt/AAuth commit 70d67375 (#967).
